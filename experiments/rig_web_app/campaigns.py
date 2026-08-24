"""Read-only discovery of externally managed engineering campaigns."""

from __future__ import annotations

import hashlib
import heapq
import math
import os
import re
import shutil
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from ura.strict_json import strict_json_loads


_CAMPAIGN_SCHEMA = "ura-engineering-campaign/1"
_ROUTE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ARTIFACT_LINKS_SCHEMA = "ura-engineering-campaign-artifact-links/1"
_ARTIFACT_LINKS_FILE = "artifact-links.json"
_ARTIFACT_LINK_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()-]{0,79}\Z")
_ARTIFACT_LINK_KINDS = frozenset({"directory", "file"})
_MAX_ARTIFACT_LINKS = 16
_MAX_ARTIFACT_LINK_PATH = 2048
_MAX_CAMPAIGNS = 20
_MAX_DIRECTORY_ENTRIES = 500
_MAX_MARKER_BYTES = 64 * 1024
_MAX_EVENT_LOG_BYTES = 512 * 1024
_MAX_MODEL_EXECUTION_COUNT = 1_000_000
_MAX_FRAMEWORK_SESSION_ENTRIES = 256
_FRAMEWORK_SESSION_START_SLOP_SECONDS = 300
_FRAMEWORK_SESSION_LAUNCH_GRACE_SECONDS = 30
_FRAMEWORK_RUNTIME_LOCK_ID = re.compile(r"[0-9a-f]{64}\Z")
_NAMED_SESSION_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_NAMED_SESSION_PROBE_TIMEOUT_SECONDS = 2
_NAMED_SESSION_CACHE_TTL_SECONDS = 5
_NAMED_SESSION_ERROR_CACHE_TTL_SECONDS = 1
_MAX_NAMED_SESSION_CACHE_ENTRIES = 256
_MAX_CONCURRENT_SESSION_PROBES = _MAX_CAMPAIGNS
_PHASE_TASKS = {"bootstrap", "stage2"}
_TASK_SUCCEEDED = {"passed", "complete", "completed", "success", "succeeded"}
_TASK_SKIPPED = {"skipped"}
_TASK_ACTIVE = {"running", "active", "in_progress"}
_CAMPAIGN_SUCCEEDED = {
    "passed",
    "complete",
    "passed_with_optional_failures",
    "complete_with_optional_failures",
}


def _timestamp(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        return result if math.isfinite(result) else None
    except (OSError, OverflowError, ValueError):
        return None


def _bounded_file(path: Path, limit: int) -> tuple[bytes | None, str | None]:
    """Read at most ``limit`` bytes from one regular, non-symlink file."""

    try:
        if path.is_symlink():
            return None, "symlink rejected"
        with path.open("rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None, "not a regular file"
            data = handle.read(limit + 1)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"unreadable ({exc.__class__.__name__})"
    if len(data) > limit:
        return None, f"larger than {limit // 1024} KiB"
    return data, None


def _bounded_single_link_json(path: Path, limit: int) -> dict[str, Any] | None:
    """Read one immutable small JSON object through a stable file snapshot."""

    descriptor: int | None = None
    try:
        if path.is_symlink():
            return None
        named_before = path.lstat()
        if (
            not stat.S_ISREG(named_before.st_mode)
            or named_before.st_nlink != 1
            or not 0 < named_before.st_size <= limit
        ):
            return None
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        identity = lambda item: (  # noqa: E731 - compact stat identity
            item.st_mode,
            item.st_dev,
            item.st_ino,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
        )
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(
            named_before
        ):
            return None
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        named_after = path.lstat()
        if identity(opened) != identity(after) or identity(after) != identity(
            named_after
        ):
            return None
        value = strict_json_loads(b"".join(chunks).decode("utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return value if isinstance(value, dict) else None


@dataclass(frozen=True)
class _NamedSessionSpec:
    directory: Path
    launcher: str
    socket: str
    session: str
    grace_until: float
    owner_label: str


_NAMED_SESSION_CACHE_LOCK = threading.Lock()
_NAMED_SESSION_CACHE: dict[
    _NamedSessionSpec,
    tuple[float, bool | None],
] = {}


def _clear_named_session_liveness_cache() -> None:
    """Clear the bounded process cache (used by deterministic regressions)."""

    with _NAMED_SESSION_CACHE_LOCK:
        _NAMED_SESSION_CACHE.clear()


def _exact_marker_session(
    directory: Path,
    marker: dict[str, Any],
    *,
    started_at: float,
    owner_label: str,
) -> _NamedSessionSpec | None:
    socket = marker.get("tmux_socket")
    session = marker.get("tmux_session")
    if socket is None and session is None:
        return None
    if (
        not isinstance(socket, str)
        or not isinstance(session, str)
        or _NAMED_SESSION_TOKEN.fullmatch(socket) is None
        or _NAMED_SESSION_TOKEN.fullmatch(session) is None
    ):
        return None
    return _NamedSessionSpec(
        directory=directory,
        launcher="tmux",
        socket=socket,
        session=session,
        grace_until=started_at + _FRAMEWORK_SESSION_LAUNCH_GRACE_SECONDS,
        owner_label=owner_label,
    )


def _framework_named_session_spec(
    directory: Path,
    marker: dict[str, Any],
    *,
    started_at: float,
) -> _NamedSessionSpec | None:
    """Resolve one exact framework session, preferring marker authority."""

    lock_id = marker.get("runtime_lock_id")
    target_call_cap = marker.get("target_call_cap")
    if (
        marker.get("evidence_class") != "framework_runtime_setup"
        or not isinstance(lock_id, str)
        or not _FRAMEWORK_RUNTIME_LOCK_ID.fullmatch(lock_id)
        or directory.name != f"framework-runtime-{lock_id[:12]}"
        or marker.get("campaign_id") != directory.name
        or marker.get("model_tasks") != []
        or not isinstance(target_call_cap, int)
        or isinstance(target_call_cap, bool)
        or target_call_cap != 0
    ):
        return None

    explicit = _exact_marker_session(
        directory,
        marker,
        started_at=started_at,
        owner_label="framework installer",
    )
    if explicit is not None:
        return explicit

    sessions_path = directory / "sessions"
    try:
        if sessions_path.is_symlink():
            return None
        sessions = sessions_path.resolve(strict=True)
        if sessions.parent != directory or not stat.S_ISDIR(sessions.lstat().st_mode):
            return None
        pattern = re.compile(
            rf"ura-framework-(?:install|resume|verify)-{lock_id[:8]}-"
            r"(?:all|[0-9a-f]{8})-[0-9a-f]{10}\.log\Z"
        )
        session_logs: list[tuple[int, float, Path]] = []
        for index, candidate in enumerate(sessions.iterdir()):
            if index >= _MAX_FRAMEWORK_SESSION_ENTRIES:
                return None
            if not pattern.fullmatch(candidate.name):
                continue
            metadata = candidate.lstat()
            if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                return None
            session_logs.append((metadata.st_mtime_ns, metadata.st_mtime, candidate))
    except OSError:
        return None
    if not session_logs:
        return None

    latest_ns = max(item[0] for item in session_logs)
    latest = [item for item in session_logs if item[0] == latest_ns]
    if len(latest) != 1:
        return None
    _mtime_ns, log_mtime, log = latest[0]
    if log_mtime < started_at - _FRAMEWORK_SESSION_START_SLOP_SECONDS:
        return None

    session = log.name.removesuffix(".log")
    home = sessions / f"{session}.home"
    try:
        if home.is_symlink():
            return None
        resolved_home = home.resolve(strict=True)
        if resolved_home.parent != sessions or not stat.S_ISDIR(resolved_home.lstat().st_mode):
            return None
    except OSError:
        return None

    exit_bytes, exit_error = _bounded_file(sessions / f"{session}.exit", 16)
    if exit_error is not None:
        return None
    if exit_bytes is not None:
        try:
            exit_code = int(exit_bytes.strip().decode("ascii"))
        except (UnicodeError, ValueError):
            return None
        if 0 <= exit_code <= 255:
            # A terminal exit marker is stronger than an operating-system
            # probe. Preserve it as an already-dead exact specification.
            return _NamedSessionSpec(
                directory=directory,
                launcher="terminal",
                socket="",
                session=session,
                grace_until=0.0,
                owner_label="framework installer",
            )
        return None
    socket = f"ura-fw-{hashlib.sha256(session.encode('ascii')).hexdigest()[:16]}"
    return _NamedSessionSpec(
        directory=directory,
        launcher="auto",
        socket=socket,
        session=session,
        grace_until=max(started_at, log_mtime) + _FRAMEWORK_SESSION_LAUNCH_GRACE_SECONDS,
        owner_label="framework installer",
    )


def _campaign_named_session_spec(
    directory: Path,
    marker: dict[str, Any],
    *,
    started_at: float,
) -> _NamedSessionSpec | None:
    evidence_class = marker.get("evidence_class")
    if evidence_class == "framework_runtime_setup":
        return _framework_named_session_spec(
            directory,
            marker,
            started_at=started_at,
        )
    if marker.get("campaign_id") == directory.name:
        return _exact_marker_session(
            directory,
            marker,
            started_at=started_at,
            owner_label="engineering campaign",
        )
    return None


def _probe_one_named_session(
    spec: _NamedSessionSpec,
    *,
    tmux: str | None,
    screen: str | None,
) -> bool | None:
    if spec.launcher == "terminal":
        return False
    environment = {
        "HOME": str(spec.directory),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
    }
    if spec.launcher == "tmux" or (spec.launcher == "auto" and tmux is not None):
        if tmux is None:
            return None
        argv = [tmux, "-L", spec.socket, "has-session", "-t", spec.session]
        try:
            completed = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=_NAMED_SESSION_PROBE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return (
            completed.returncode == 0
            if completed.returncode in {0, 1}
            else None
        )
    if screen is None:
        return None
    try:
        completed = subprocess.run(
            [screen, "-ls", spec.session],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=environment,
            timeout=_NAMED_SESSION_PROBE_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if re.search(
        rf"(?m)^\s*\d+\.{re.escape(spec.session)}\s+"
        r"\((?:Attached|Detached|Multi(?:,\s*attached)?)\)\s*$",
        completed.stdout,
    ):
        return True
    return False if completed.returncode in {0, 1} else None


def _named_session_liveness(
    specs: list[_NamedSessionSpec],
) -> dict[_NamedSessionSpec, bool | None]:
    """Probe unique sessions concurrently and cache a bounded short snapshot."""

    unique = list(dict.fromkeys(specs))
    if not unique:
        return {}
    now = time.monotonic()
    wall_now = time.time()
    results: dict[_NamedSessionSpec, bool | None] = {}
    pending: list[_NamedSessionSpec] = []
    with _NAMED_SESSION_CACHE_LOCK:
        for spec in unique:
            if wall_now < spec.grace_until:
                results[spec] = None
                continue
            cached = _NAMED_SESSION_CACHE.get(spec)
            if cached is not None and now - cached[0] <= (
                _NAMED_SESSION_CACHE_TTL_SECONDS
                if cached[1] is not None
                else _NAMED_SESSION_ERROR_CACHE_TTL_SECONDS
            ):
                results[spec] = cached[1]
            else:
                pending.append(spec)
    if not pending:
        return results

    tmux = shutil.which("tmux", path=os.defpath)
    screen = shutil.which("screen", path=os.defpath) if tmux is None else None
    workers = min(_MAX_CONCURRENT_SESSION_PROBES, len(pending))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ura-session-probe") as pool:
        future_specs = {
            pool.submit(
                _probe_one_named_session,
                spec,
                tmux=tmux,
                screen=screen,
            ): spec
            for spec in pending
        }
        for future in as_completed(future_specs):
            spec = future_specs[future]
            try:
                results[spec] = future.result()
            except Exception:  # noqa: BLE001 - liveness stays unknown on a worker fault
                results[spec] = None

    observed_at = time.monotonic()
    with _NAMED_SESSION_CACHE_LOCK:
        for spec in pending:
            _NAMED_SESSION_CACHE[spec] = (observed_at, results.get(spec))
        if len(_NAMED_SESSION_CACHE) > _MAX_NAMED_SESSION_CACHE_ENTRIES:
            oldest = sorted(
                _NAMED_SESSION_CACHE,
                key=lambda item: _NAMED_SESSION_CACHE[item][0],
            )
            for spec in oldest[
                : len(_NAMED_SESSION_CACHE) - _MAX_NAMED_SESSION_CACHE_ENTRIES
            ]:
                del _NAMED_SESSION_CACHE[spec]
    return results


def _events(path: Path, *, required: bool = False) -> tuple[list[dict[str, Any]], str | None]:
    """Read a bounded task-event log, ignoring an incomplete final line."""

    data, error = _bounded_file(path, _MAX_EVENT_LOG_BYTES)
    if data is None:
        return [], error or ("missing task log" if required else None)
    if not data and required:
        return [], "empty task log"
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return [], "invalid UTF-8"
    lines = text.splitlines()
    if data and not data.endswith(b"\n"):
        lines = lines[:-1]
    parsed: list[dict[str, Any]] = []
    malformed = False
    for line in lines:
        try:
            value = strict_json_loads(line)
        except (ValueError, TypeError, RecursionError):
            malformed = True
            continue
        if isinstance(value, dict):
            parsed.append(value)
        else:
            malformed = True
    return parsed, "malformed JSON event" if malformed else None


def _phase_state(
    events: list[dict[str, Any]],
    phase: str,
) -> tuple[str | None, float | None, dict[str, Any] | None]:
    starts = [
        ((_timestamp(row.get("at")) or 0.0, index), row)
        for index, row in enumerate(events)
        if row.get("event") == "campaign_start" and row.get("task") == phase
    ]
    if not starts:
        return None, None, None
    latest_start = max(item[0] for item in starts)
    terminals = [
        ((_timestamp(row.get("at")) or 0.0, index), row)
        for index, row in enumerate(events)
        if row.get("event") in {"campaign_end", "campaign_stop"}
        and row.get("task") == phase
        and ((_timestamp(row.get("at")) or 0.0), index) >= latest_start
    ]
    if not terminals:
        return "running", None, None
    (ended_at, _index), terminal = max(terminals, key=lambda item: item[0])
    status = str(terminal.get("status") or "failed").strip().lower()[:32]
    if terminal.get("event") == "campaign_end" and status in _CAMPAIGN_SUCCEEDED:
        return "complete", ended_at, terminal
    return "failed", ended_at, terminal


def _planned_tasks(marker: dict[str, Any]) -> tuple[str, ...] | None:
    """Return a strict, unique declared plan, or ``None`` when unknown.

    A campaign without ``planned_tasks`` has no knowable pending count. A
    malformed optional declaration is treated the same way instead of
    guessing from observed events or launcher implementation details.
    """

    raw = marker.get("planned_tasks")
    if not isinstance(raw, list):
        return None
    tasks: list[str] = []
    seen: set[str] = set()
    for value in raw:
        if not isinstance(value, str):
            return None
        task = value.strip()
        if not task or len(task) > 256 or task in _PHASE_TASKS:
            return None
        if task in seen:
            return None
        seen.add(task)
        tasks.append(task)
    return tuple(tasks)


def _declared_model_tasks(
    marker: dict[str, Any],
    planned_tasks: tuple[str, ...] | None,
) -> tuple[tuple[str, ...] | None, str]:
    """Return a strict declared model-task subset and a fail-closed error."""

    raw = marker.get("model_tasks")
    if raw is None:
        return None, ""
    if not isinstance(raw, list):
        return None, "model_tasks must be a list"
    if planned_tasks is None:
        return None, "model_tasks requires a valid planned_tasks declaration"
    planned = set(planned_tasks)
    tasks: list[str] = []
    seen: set[str] = set()
    for value in raw:
        if not isinstance(value, str):
            return None, "model_tasks contains a non-string value"
        task = value.strip()
        if not task or len(task) > 256:
            return None, "model_tasks contains an invalid task name"
        if task not in planned:
            return None, f"model task {task!r} is not in planned_tasks"
        if task in seen:
            return None, f"model task {task!r} is duplicated"
        seen.add(task)
        tasks.append(task)
    return tuple(tasks), ""


def _compact_status_tag(
    state: str,
    display_state: str,
    *,
    failed_tasks: int,
    skipped_tasks: int,
    pending_tasks: int | None,
    unplanned_tasks: int,
) -> str:
    """Return a short lifecycle tag without overstating partial campaigns."""

    raw = display_state.strip().lower()
    if state == "complete":
        return (
            "partial"
            if failed_tasks or skipped_tasks or pending_tasks or unplanned_tasks
            else "passed"
        )
    if state == "running":
        return "running"
    if state in {"orphaned", "unknown"}:
        return state
    if raw in {"blocked", "cancelled", "canceled", "stopped"}:
        return "stopped" if raw in {"cancelled", "canceled", "stopped"} else raw
    return "failed"


@dataclass(frozen=True)
class EngineeringCampaign:
    """Filesystem-backed status for a campaign not owned by this console."""

    route_id: str
    campaign_id: str
    directory: Path
    state: str
    display_state: str
    status_tag: str
    state_detail: str
    started_at: float
    ended_at: float | None
    progress: str
    completed_tasks: int
    succeeded_tasks: int
    failed_tasks: int
    skipped_tasks: int
    active_tasks: tuple[str, ...]
    download_tasks: tuple[str, ...]
    pending_tasks: int | None
    unplanned_tasks: tuple[str, ...]
    task_outcomes: tuple[tuple[str, str, str], ...]
    model_tasks: tuple[str, ...] | None
    model_declaration_error: str
    model_succeeded_tasks: int | None
    model_failed_tasks: int | None
    model_skipped_tasks: int | None
    model_active_tasks: int | None
    model_pending_tasks: int | None
    model_attempted_calls: int | None
    model_successful_generations: int | None
    model_execution_covered_tasks: int | None
    model_execution_error: str
    last_detail: str
    release_commit: str
    evidence_class: str
    thesis_empirical_evidence: bool
    hosted_calls_allowed: bool
    target_call_cap: int | None
    reserved_calls: int
    hard_stop_hours: float | None
    named_session_liveness_verified: bool
    logs: tuple[tuple[str, str, Path], ...]
    artifact_links: tuple[tuple[str, str], ...] = ()
    artifact_link_error: str = ""

    def runtime_seconds(self) -> float:
        return max(0.0, (self.ended_at or time.time()) - self.started_at)


def _engineering_artifact_links(
    directory: Path,
    *,
    marker_campaign_id: object,
) -> tuple[tuple[tuple[str, str], ...], str]:
    """Load one generic, bounded set of retained engineering-artifact links."""

    descriptor_path = directory / _ARTIFACT_LINKS_FILE
    descriptor_present = descriptor_path.exists() or descriptor_path.is_symlink()
    if not descriptor_present:
        return (), ""
    value = _bounded_single_link_json(descriptor_path, _MAX_MARKER_BYTES)
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "campaign_id", "links"}
        or value.get("schema") != _ARTIFACT_LINKS_SCHEMA
        or value.get("campaign_id") != directory.name
        or value.get("campaign_id") != marker_campaign_id
    ):
        return (), "Engineering artifact-link descriptor is invalid."
    raw_links = value.get("links")
    if (
        not isinstance(raw_links, list)
        or not raw_links
        or len(raw_links) > _MAX_ARTIFACT_LINKS
    ):
        return (), "Engineering artifact-link descriptor is invalid."

    try:
        results = directory.parent.parent.resolve(strict=True)
    except OSError:
        return (), "Engineering artifact-link descriptor is invalid."

    links: list[tuple[str, str]] = [
        (
            "Link descriptor",
            f"engineering/{directory.name}/{_ARTIFACT_LINKS_FILE}",
        )
    ]
    labels: set[str] = set()
    paths: set[str] = set()
    for raw in raw_links:
        if not isinstance(raw, dict) or set(raw) != {
            "label",
            "path",
            "kind",
            "required",
        }:
            return (), "Engineering artifact-link descriptor is invalid."
        label = raw.get("label")
        path_value = raw.get("path")
        kind = raw.get("kind")
        required = raw.get("required")
        if (
            not isinstance(label, str)
            or _ARTIFACT_LINK_LABEL.fullmatch(label) is None
            or label in labels
            or not isinstance(path_value, str)
            or not path_value
            or len(path_value) > _MAX_ARTIFACT_LINK_PATH
            or not path_value.isprintable()
            or "\\" in path_value
            or not isinstance(kind, str)
            or kind not in _ARTIFACT_LINK_KINDS
            or type(required) is not bool
        ):
            return (), "Engineering artifact-link descriptor is invalid."
        relative = PurePosixPath(path_value)
        if (
            not relative.parts
            or relative.is_absolute()
            or relative.as_posix() != path_value
            or any(part in {"", ".", ".."} or ":" in part for part in relative.parts)
            or path_value in paths
        ):
            return (), "Engineering artifact-link descriptor is invalid."
        labels.add(label)
        paths.add(path_value)
        current = results
        target_missing = False
        for index, part in enumerate(relative.parts):
            current /= part
            try:
                metadata = current.lstat()
                is_alias = stat.S_ISLNK(metadata.st_mode) or current.is_junction()
            except FileNotFoundError:
                target_missing = True
                break
            except (OSError, ValueError, RuntimeError):
                return (), "Engineering artifact-link descriptor is invalid."
            if is_alias:
                return (), "Engineering artifact-link descriptor is invalid."
            try:
                resolved = current.resolve(strict=True)
            except (OSError, ValueError, RuntimeError):
                return (), "Engineering artifact-link descriptor is invalid."
            is_target = index == len(relative.parts) - 1
            if (
                resolved != current
                or results not in resolved.parents
                or (not is_target and not stat.S_ISDIR(metadata.st_mode))
            ):
                return (), "Engineering artifact-link descriptor is invalid."
        if target_missing:
            if required:
                return (), "Engineering artifact-link descriptor is invalid."
            continue
        if (kind == "directory" and not stat.S_ISDIR(metadata.st_mode)) or (
            kind == "file" and not stat.S_ISREG(metadata.st_mode)
        ):
            return (), "Engineering artifact-link descriptor is invalid."
        links.append((label, path_value))
    return tuple(links), ""


def _load_campaign(
    directory: Path,
    *,
    named_session_liveness: dict[_NamedSessionSpec, bool | None] | None = None,
) -> EngineeringCampaign | None:
    marker_path = directory / "ENGINEERING_ONLY.json"
    marker_bytes, marker_error = _bounded_file(marker_path, _MAX_MARKER_BYTES)
    if marker_bytes is None or marker_error is not None:
        return None
    try:
        marker = strict_json_loads(marker_bytes.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None
    if not isinstance(marker, dict) or marker.get("schema") != _CAMPAIGN_SCHEMA:
        return None
    # This index is deliberately limited to explicitly non-empirical
    # engineering work. It never imports a campaign into the research ledger.
    if marker.get("thesis_empirical_evidence") is not False:
        return None
    hosted_calls_allowed = marker.get("hosted_calls_allowed")
    if not isinstance(hosted_calls_allowed, bool):
        return None

    bootstrap_path = directory / "task-log.jsonl"
    stage2_path = directory / "stage2-task-log.jsonl"
    bootstrap, bootstrap_error = _events(bootstrap_path, required=True)
    stage2, stage2_error = _events(stage2_path)
    all_events = sorted(
        bootstrap + stage2,
        key=lambda row: _timestamp(row.get("at")) or 0.0,
    )

    stage2_state, stage2_end, stage2_terminal = _phase_state(stage2, "stage2")
    bootstrap_state, bootstrap_end, bootstrap_terminal = _phase_state(bootstrap, "bootstrap")
    state = stage2_state or bootstrap_state or "unknown"
    ended_at = stage2_end if stage2_state is not None else bootstrap_end
    terminal = stage2_terminal if stage2_state is not None else bootstrap_terminal
    display_state = state
    state_detail = ""
    if terminal is not None:
        display_state = str(terminal.get("status") or state).strip().lower()[:32] or state
        state_detail = str(terminal.get("detail") or "").strip()[:1000]
    activity_error = bootstrap_error or stage2_error
    if activity_error:
        state = "unknown"
        display_state = "unknown"
        state_detail = ""
        ended_at = None

    started_at = _timestamp(marker.get("started_at"))
    if started_at is None:
        try:
            started_at = marker_path.stat().st_mtime
        except OSError:
            started_at = 0.0
    hard_stop_value = marker.get("hard_stop_hours")
    if (
        isinstance(hard_stop_value, (int, float))
        and not isinstance(hard_stop_value, bool)
        and math.isfinite(float(hard_stop_value))
        and float(hard_stop_value) > 0
    ):
        hard_stop_hours = float(hard_stop_value)
    else:
        hard_stop_hours = None
    session_spec = _campaign_named_session_spec(
        directory,
        marker,
        started_at=started_at,
    )
    session_observed: bool | None = None
    marker_declares_named_session = (
        marker.get("tmux_socket") is not None
        or marker.get("tmux_session") is not None
    )
    if state == "running" and (
        marker_declares_named_session or session_spec is not None
    ):
        if session_spec is None:
            state = "unknown"
            display_state = "unknown"
            state_detail = (
                "engineering campaign declares an invalid named-session identity; "
                "the retained task log has no terminal event"
            )
        else:
            session_observed = (
                _named_session_liveness([session_spec]).get(session_spec)
                if named_session_liveness is None
                else named_session_liveness.get(session_spec)
            )
            if session_observed is False:
                state = "orphaned"
                display_state = "orphaned"
                state_detail = (
                    f"{session_spec.owner_label} named session is no longer live; "
                    "the retained task log has no terminal event"
                )
            elif session_observed is None:
                state = "unknown"
                display_state = "unknown"
                state_detail = (
                    f"{session_spec.owner_label} named-session liveness is unavailable; "
                    "the retained task log has no terminal event"
                )
    if (
        state == "running"
        and hard_stop_hours is not None
        and time.time() > started_at + hard_stop_hours * 3600
    ):
        if session_observed is True and session_spec is not None:
            state_detail = (
                f"declared hard stop exceeded while the exact "
                f"{session_spec.owner_label} named session remains live"
            )
        else:
            state = "orphaned"
            display_state = "orphaned"
            state_detail = (
                "declared hard stop exceeded and exact named-session liveness "
                "is unavailable; the retained task log has no terminal event"
            )

    task_states: dict[str, str] = {}
    task_kinds: dict[str, str] = {}
    for row in all_events:
        event = row.get("event")
        raw_task = row.get("task")
        if not isinstance(raw_task, str):
            continue
        task = raw_task.strip()[:256]
        if not task or task in _PHASE_TASKS:
            continue
        if event == "task_start":
            task_states[task] = "running"
            # Activity is an explicit event contract. A task name containing
            # "download" is deliberately insufficient evidence.
            if row.get("task_kind") == "model_download":
                task_kinds[task] = "model_download"
            else:
                task_kinds.pop(task, None)
        elif event in {"task_end", "task_skip"}:
            status = str(row.get("status") or "failed").strip().lower()[:32]
            task_states[task] = status
            task_kinds.pop(task, None)
    interrupted_tasks: tuple[str, ...] = ()
    if state in {"complete", "failed", "orphaned"}:
        interrupted_tasks = tuple(
            task for task, status in task_states.items() if status in _TASK_ACTIVE
        )
        for task in interrupted_tasks:
            task_states[task] = "interrupted"
    succeeded_tasks = sum(status in _TASK_SUCCEEDED for status in task_states.values())
    skipped_tasks = sum(status in _TASK_SKIPPED for status in task_states.values())
    failed_tasks = sum(
        status not in _TASK_SUCCEEDED | _TASK_SKIPPED | _TASK_ACTIVE
        for status in task_states.values()
    )
    active_tasks = tuple(task for task, status in task_states.items() if status in _TASK_ACTIVE)
    download_tasks = tuple(
        task for task in active_tasks if task_kinds.get(task) == "model_download"
    )
    completed_tasks = succeeded_tasks + failed_tasks + skipped_tasks
    planned_tasks = _planned_tasks(marker)
    pending_tasks = (
        sum(task not in task_states for task in planned_tasks)
        if planned_tasks is not None and not activity_error
        else None
    )

    model_tasks, model_declaration_error = _declared_model_tasks(marker, planned_tasks)
    model_task_set = set(model_tasks or ())
    planned_task_set = set(planned_tasks or ())
    task_order = list(planned_tasks or ())
    task_order_seen = set(task_order)
    task_order.extend(task for task in task_states if task not in task_order_seen)
    task_outcomes = tuple(
        (
            task,
            task_states.get(task, "pending"),
            "unplanned"
            if planned_tasks is not None and task not in planned_task_set
            else "unclassified"
            if model_tasks is None
            else "model"
            if task in model_task_set
            else "support",
        )
        for task in task_order
    )
    unplanned_tasks = (
        tuple(task for task in task_states if task not in planned_task_set)
        if planned_tasks is not None
        else ()
    )
    if model_tasks is None:
        model_succeeded_tasks = None
        model_failed_tasks = None
        model_skipped_tasks = None
        model_active_tasks = None
        model_pending_tasks = None
    else:
        model_states = {task: task_states.get(task, "pending") for task in model_tasks}
        model_succeeded_tasks = sum(
            status in _TASK_SUCCEEDED for status in model_states.values()
        )
        model_skipped_tasks = sum(status in _TASK_SKIPPED for status in model_states.values())
        model_active_tasks = sum(status in _TASK_ACTIVE for status in model_states.values())
        model_pending_tasks = sum(status == "pending" for status in model_states.values())
        model_failed_tasks = sum(
            status not in _TASK_SUCCEEDED | _TASK_SKIPPED | _TASK_ACTIVE | {"pending"}
            for status in model_states.values()
        )

    model_execution_path = directory / "model-execution.jsonl"
    model_execution_events, model_execution_error = _events(model_execution_path)
    execution_by_task: dict[str, tuple[int, int]] = {}
    model_execution_present = (
        model_execution_path.is_file() and not model_execution_path.is_symlink()
    )
    if model_execution_present:
        if model_tasks is None:
            model_execution_error = model_execution_error or (
                "model execution log requires a valid model_tasks declaration"
            )
        for row in model_execution_events:
            if row.get("event") != "model_execution":
                model_execution_error = model_execution_error or "unsupported model execution event"
                continue
            task = row.get("task")
            attempted = row.get("attempted_calls")
            successful = row.get("successful_generations")
            if (
                not isinstance(task, str)
                or not task.strip()
                or len(task.strip()) > 256
                or isinstance(attempted, bool)
                or not isinstance(attempted, int)
                or isinstance(successful, bool)
                or not isinstance(successful, int)
                or attempted < 0
                or successful < 0
                or successful > attempted
                or attempted > _MAX_MODEL_EXECUTION_COUNT
            ):
                model_execution_error = model_execution_error or "invalid model execution event"
                continue
            normalized_task = task.strip()
            if normalized_task in execution_by_task:
                model_execution_error = model_execution_error or (
                    "model execution report duplicates a task"
                )
                continue
            if model_tasks is None or normalized_task not in model_task_set:
                model_execution_error = model_execution_error or (
                    "model execution event references an undeclared model task"
                )
                continue
            task_status = task_states.get(normalized_task)
            if (
                (task_status is None or task_status in _TASK_SKIPPED)
                and (attempted != 0 or successful != 0)
            ):
                model_execution_error = model_execution_error or (
                    "positive model execution contradicts a pending or skipped task"
                )
                continue
            execution_by_task[normalized_task] = (attempted, successful)
        if not execution_by_task and model_execution_error is None:
            model_execution_error = "empty model execution log"
        if model_tasks is not None and state != "running":
            missing_model_tasks = model_task_set - set(execution_by_task)
            if missing_model_tasks:
                model_execution_error = model_execution_error or (
                    "terminal model execution report omits declared model task(s): "
                    + ", ".join(sorted(missing_model_tasks))
                )
    if execution_by_task and model_execution_error is None:
        model_attempted_calls = sum(value[0] for value in execution_by_task.values())
        model_successful_generations = sum(value[1] for value in execution_by_task.values())
        if model_attempted_calls > _MAX_MODEL_EXECUTION_COUNT:
            model_execution_error = "model execution totals exceed the supported limit"
            model_attempted_calls = None
            model_successful_generations = None
    else:
        model_attempted_calls = None
        model_successful_generations = None
    model_execution_covered_tasks = (
        len(execution_by_task)
        if model_execution_present and model_execution_error is None
        else None
    )

    status_tag = _compact_status_tag(
        state,
        display_state,
        failed_tasks=failed_tasks,
        skipped_tasks=skipped_tasks,
        pending_tasks=pending_tasks,
        unplanned_tasks=len(unplanned_tasks),
    )

    reserved_calls = 0
    call_events, call_error = _events(directory / "local-call-ledger.jsonl")
    for row in call_events:
        try:
            reserved_calls = max(reserved_calls, int(row.get("cumulative_reserved_max_calls", 0)))
        except (TypeError, ValueError):
            pass
    target_call_value = marker.get("target_call_cap")
    if (
        isinstance(target_call_value, int)
        and not isinstance(target_call_value, bool)
        and target_call_value > 0
    ):
        target_call_cap = target_call_value
    else:
        target_call_cap = None

    if activity_error:
        parts = [f"activity status unavailable: {activity_error}"]
    else:
        parts = [
            f"task processes: {succeeded_tasks} succeeded; {failed_tasks} failed; "
            f"{skipped_tasks} skipped; {len(active_tasks)} active",
            (f"pending: {pending_tasks}" if pending_tasks is not None else "pending: not declared"),
        ]
        if active_tasks and state == "running":
            parts.append("active task: " + ", ".join(active_tasks))
        if download_tasks and state == "running":
            parts.append("model download in progress: " + ", ".join(download_tasks))
        if interrupted_tasks:
            parts.append(f"{len(interrupted_tasks)} interrupted without a terminal task event")
        if unplanned_tasks:
            parts.append("unplanned task event(s): " + ", ".join(unplanned_tasks))
        if terminal is not None:
            terminal_summary = f"campaign terminal: {display_state}"
            if state_detail:
                terminal_summary += f" - {state_detail}"
            parts.append(terminal_summary)
    if model_declaration_error:
        parts.append(f"model tasks unavailable: {model_declaration_error}")
    elif model_tasks is None:
        parts.append("model tasks: not declared")
    else:
        parts.append(
            f"model tasks: {model_succeeded_tasks} succeeded; "
            f"{model_failed_tasks} failed; {model_skipped_tasks} skipped; "
            f"{model_active_tasks} active; pending: {model_pending_tasks}"
        )
    if model_execution_error:
        parts.append(f"model execution report invalid: {model_execution_error}")
    elif model_attempted_calls is None:
        parts.append("model execution: not reported")
    else:
        parts.append(
            f"model execution report: {model_successful_generations} successful generation(s) "
            f"from {model_attempted_calls} attempt(s); coverage "
            f"{model_execution_covered_tasks}/{len(model_tasks or ())} model tasks"
        )
    if target_call_cap is not None:
        calls = "unknown" if call_error else str(reserved_calls)
        parts.append(
            f"call budget reserved: {calls}/{target_call_cap} "
            "(not execution evidence)"
        )

    last_detail = ""
    if all_events:
        last = all_events[-1]
        last_detail = str(last.get("detail") or "")[:1000]

    logs = tuple(
        (key, label, path)
        for key, label, path in (
            ("bootstrap", "Bootstrap activity", bootstrap_path),
            ("stage2", "Stage 2 activity", stage2_path),
            ("failures", "Stage 2 failures", directory / "stage2-failures.jsonl"),
            ("calls", "Local call ledger", directory / "local-call-ledger.jsonl"),
            ("model", "Model execution report", model_execution_path),
        )
        if not path.is_symlink() and path.is_file()
    )
    marker_campaign_id = marker.get("campaign_id")
    campaign_id = str(marker_campaign_id or directory.name)
    artifact_links, artifact_link_error = _engineering_artifact_links(
        directory,
        marker_campaign_id=marker_campaign_id,
    )
    return EngineeringCampaign(
        route_id=directory.name,
        campaign_id=campaign_id,
        directory=directory,
        state=state,
        display_state=display_state,
        status_tag=status_tag,
        state_detail=state_detail,
        started_at=started_at,
        ended_at=ended_at,
        progress="; ".join(parts),
        completed_tasks=completed_tasks,
        succeeded_tasks=succeeded_tasks,
        failed_tasks=failed_tasks,
        skipped_tasks=skipped_tasks,
        active_tasks=active_tasks,
        download_tasks=download_tasks,
        pending_tasks=pending_tasks,
        unplanned_tasks=unplanned_tasks,
        task_outcomes=task_outcomes,
        model_tasks=model_tasks,
        model_declaration_error=model_declaration_error,
        model_succeeded_tasks=model_succeeded_tasks,
        model_failed_tasks=model_failed_tasks,
        model_skipped_tasks=model_skipped_tasks,
        model_active_tasks=model_active_tasks,
        model_pending_tasks=model_pending_tasks,
        model_attempted_calls=model_attempted_calls,
        model_successful_generations=model_successful_generations,
        model_execution_covered_tasks=model_execution_covered_tasks,
        model_execution_error=model_execution_error or "",
        last_detail=last_detail,
        release_commit=str(marker.get("release_commit") or ""),
        evidence_class=str(marker.get("evidence_class") or "engineering"),
        thesis_empirical_evidence=False,
        hosted_calls_allowed=hosted_calls_allowed,
        target_call_cap=target_call_cap,
        reserved_calls=reserved_calls,
        hard_stop_hours=hard_stop_hours,
        named_session_liveness_verified=session_observed is True,
        logs=logs,
        artifact_links=artifact_links,
        artifact_link_error=artifact_link_error,
    )


def _engineering_root(results_root: Path) -> Path | None:
    engineering = results_root / "engineering"
    try:
        results = results_root.resolve(strict=True)
        if engineering.is_symlink():
            return None
        root = engineering.resolve(strict=True)
        if root.parent != results:
            return None
    except OSError:
        return None
    return root


def load_engineering_campaign(
    results_root: Path,
    route_id: str,
) -> EngineeringCampaign | None:
    """Load one named campaign directly for its detail/log route."""

    root = _engineering_root(results_root)
    if root is None or not _ROUTE_ID.fullmatch(route_id):
        return None
    candidate = root / route_id
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        if resolved.parent != root or not stat.S_ISDIR(resolved.lstat().st_mode):
            return None
    except OSError:
        return None
    return _load_campaign(resolved)


def _running_campaign_session_spec(directory: Path) -> _NamedSessionSpec | None:
    """Return the exact session identity for one nonterminal controller.

    This is the deliberately small discovery pass used before the recent-row
    cap is applied. Every file read remains bounded, and only controller
    classes with an exact named-session contract can cross that cap.
    """

    marker_bytes, marker_error = _bounded_file(
        directory / "ENGINEERING_ONLY.json",
        _MAX_MARKER_BYTES,
    )
    if marker_bytes is None or marker_error is not None:
        return None
    try:
        marker = strict_json_loads(marker_bytes.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None
    if (
        not isinstance(marker, dict)
        or marker.get("schema") != _CAMPAIGN_SCHEMA
        or marker.get("thesis_empirical_evidence") is not False
    ):
        return None
    bootstrap, bootstrap_error = _events(
        directory / "task-log.jsonl",
        required=True,
    )
    stage2, stage2_error = _events(directory / "stage2-task-log.jsonl")
    stage2_state, _stage2_end, _stage2_terminal = _phase_state(stage2, "stage2")
    bootstrap_state, _bootstrap_end, _bootstrap_terminal = _phase_state(
        bootstrap,
        "bootstrap",
    )
    if (
        bootstrap_error
        or stage2_error
        or (stage2_state or bootstrap_state or "unknown") != "running"
    ):
        return None
    started_at = _timestamp(marker.get("started_at"))
    if started_at is None:
        try:
            started_at = (directory / "ENGINEERING_ONLY.json").stat().st_mtime
        except OSError:
            started_at = 0.0
    return _campaign_named_session_spec(
        directory,
        marker,
        started_at=started_at,
    )


def scan_engineering_campaigns(
    results_root: Path,
    *,
    started_from: float | None = None,
    started_to: float | None = None,
) -> tuple[list[EngineeringCampaign], str]:
    """Load a bounded campaign index and return any omission notice.

    Jobs passes its inclusive date window so marker start times are filtered
    before the 20-row display cap. An unwindowed scan also reconciles every
    exact-session nonterminal controller in the bounded directory scan, so a
    genuinely live controller cannot disappear behind newer terminal history.
    """

    if (started_from is None) != (started_to is None):
        raise ValueError("campaign date window requires both bounds")
    if started_from is not None and (
        isinstance(started_from, bool)
        or isinstance(started_to, bool)
        or not isinstance(started_from, (int, float))
        or not isinstance(started_to, (int, float))
        or not math.isfinite(float(started_from))
        or not math.isfinite(float(started_to))
        or float(started_from) > float(started_to)
    ):
        raise ValueError("invalid campaign date window")

    root = _engineering_root(results_root)
    if root is None:
        return [], ""
    candidates: list[tuple[float, int, Path]] = []
    truncated = False
    try:
        for index, candidate in enumerate(root.iterdir()):
            if index >= _MAX_DIRECTORY_ENTRIES:
                truncated = True
                break
            if candidate.is_symlink() or not _ROUTE_ID.fullmatch(candidate.name):
                continue
            try:
                metadata = candidate.lstat()
            except OSError:
                continue
            if stat.S_ISDIR(metadata.st_mode):
                started_at = float(metadata.st_mtime)
                if started_from is not None:
                    marker_bytes, marker_error = _bounded_file(
                        candidate / "ENGINEERING_ONLY.json",
                        _MAX_MARKER_BYTES,
                    )
                    if marker_bytes is None or marker_error is not None:
                        continue
                    try:
                        marker = strict_json_loads(marker_bytes.decode("utf-8"))
                    except (UnicodeError, ValueError, TypeError, RecursionError):
                        continue
                    if (
                        not isinstance(marker, dict)
                        or marker.get("schema") != _CAMPAIGN_SCHEMA
                        or marker.get("thesis_empirical_evidence") is not False
                    ):
                        continue
                    marker_started = _timestamp(marker.get("started_at"))
                    if marker_started is not None:
                        started_at = marker_started
                    if not float(started_from) <= started_at <= float(started_to):
                        continue
                candidates.append((started_at, metadata.st_mtime_ns, candidate))
    except OSError:
        return [], "External campaign directory could not be scanned."

    newest = heapq.nlargest(
        _MAX_CAMPAIGNS,
        candidates,
        key=(
            (lambda item: (item[0], item[1]))
            if started_from is not None
            else (lambda item: item[1])
        ),
    )
    resolved_candidates: list[Path] = []
    seen_resolved: set[Path] = set()
    for _started, _mtime, candidate in newest:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in seen_resolved:
            continue
        seen_resolved.add(resolved)
        resolved_candidates.append(resolved)

    specs_by_directory: dict[Path, _NamedSessionSpec] = {}
    for resolved in resolved_candidates:
        spec = _running_campaign_session_spec(resolved)
        if spec is not None:
            specs_by_directory[resolved] = spec

    # A date-window scan is a bounded history query. The separate unwindowed
    # scan used by Jobs is responsible for the live override. Inspect at most
    # _MAX_DIRECTORY_ENTRIES here, then let the exact tmux/screen probes (each
    # separately timeout-bounded) decide which older controllers are live.
    older_session_directories: list[Path] = []
    if started_from is None:
        for _started, _mtime, candidate in candidates:
            try:
                if candidate.is_symlink():
                    continue
                resolved = candidate.resolve(strict=True)
                if (
                    resolved.parent != root
                    or resolved in seen_resolved
                    or not stat.S_ISDIR(resolved.lstat().st_mode)
                ):
                    continue
            except OSError:
                continue
            spec = _running_campaign_session_spec(resolved)
            if spec is None:
                continue
            seen_resolved.add(resolved)
            specs_by_directory[resolved] = spec
            older_session_directories.append(resolved)
    session_liveness = _named_session_liveness(list(specs_by_directory.values()))

    live_older_directories = [
        resolved
        for resolved in older_session_directories
        if session_liveness.get(specs_by_directory[resolved]) is True
    ]
    resolved_candidates.extend(live_older_directories)

    campaigns = []
    for resolved in resolved_candidates:
        campaign = _load_campaign(
            resolved,
            named_session_liveness=session_liveness,
        )
        if campaign is not None:
            campaigns.append(campaign)
    notices = []
    omitted = max(0, len(candidates) - len(newest) - len(live_older_directories))
    if omitted:
        notices.append(
            f"Showing the {_MAX_CAMPAIGNS} newest retained engineering campaigns"
            f"{' in the selected date range' if started_from is not None else ''}; "
            f"{omitted} additional scanned director"
            f"{'y was' if omitted == 1 else 'ies were'} omitted."
            + (
                " Exact-session live controllers outside the recent cap remain included."
                if started_from is None
                else ""
            )
        )
    if truncated:
        notices.append(
            f"The external campaign scan stopped after {_MAX_DIRECTORY_ENTRIES} directory "
            "entries; later entries were not inspected."
        )
    return (
        sorted(campaigns, key=lambda item: item.started_at, reverse=True),
        " ".join(notices),
    )


def discover_engineering_campaigns(results_root: Path) -> list[EngineeringCampaign]:
    """Compatibility helper returning the bounded recent-campaign list."""

    campaigns, _notice = scan_engineering_campaigns(results_root)
    return campaigns
