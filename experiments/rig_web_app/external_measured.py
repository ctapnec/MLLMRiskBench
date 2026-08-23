"""Create-only operational registration for externally launched measured jobs.

The campaign controllers own these processes.  Rig Web reads the registrations
to make the exact jobs and their explicitly owned Runner output roots visible,
but it never imports them into the console database or acquires process
ownership.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from ura.strict_json import strict_json_loads

from .artifacts import assert_durable_job_state_path_free, run_kind
from .campaigns import _NamedSessionSpec, _named_session_liveness


REGISTRY_DIRECTORY = "external-measured-jobs"
REGISTRATION_SCHEMA = "ura-external-measured-job/1"
TERMINAL_SCHEMA = "ura-external-measured-job-terminal/1"

_REGISTRATION_FILE = "registration.json"
_TERMINAL_FILE = "terminal.json"
_SAFE_JOB_ID = re.compile(r"external-[A-Za-z0-9][A-Za-z0-9._-]{0,118}\Z")
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_REGISTRATIONS = 2_000
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_TERMINAL_BYTES = 16 * 1024
_MAX_ARGV_ITEMS = 2_048
_MAX_ARG_BYTES = 32_768
_MAX_ARGV_BYTES = 256 * 1024
_MAX_RUNNING_SESSION_PROBES = 20
_MAX_SCAN_CACHE_ENTRIES = 32
_SCAN_CACHE_TTL_SECONDS = 1.0
_START_SESSION_GRACE_SECONDS = 30
_MAX_SUPPORTED_EPOCH = 32_503_680_000.0  # 3000-01-01 00:00:00 UTC
_SECRET_OPTION_COMPONENTS = frozenset(
    {
        "auth",
        "authorization",
        "credential",
        "credentials",
        "key",
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
    }
)
_COMPACT_SECRET_OPTION_NAMES = frozenset(
    {
        "accesstoken",
        "apikey",
        "authtoken",
        "bearertoken",
        "clientsecret",
        "credential",
        "credentials",
        "privatekey",
        "refreshtoken",
    }
)
_LIVENESS_UNAVAILABLE_DETAIL = (
    "Exact named-session liveness is unavailable; running state is not asserted."
)
_LIVENESS_UNPROBED_DETAIL = (
    "Exact named-session liveness was not probed because the bounded scan limit was "
    "reached; running state is not asserted."
)
_LIVENESS_STOPPED_DETAIL = "The exact registered named session is not running."


@dataclass(frozen=True)
class ExternalMeasuredJob:
    """One validated externally owned measured Runner registration."""

    job_id: str
    command: str
    run_kind: str
    argv: tuple[str, ...]
    argv_sha256: str
    out_dir: Path
    artifact_relative: str
    expected_commit: str
    framework_lock_id: str
    gate5_sha256: str
    tmux_socket: str
    tmux_session: str
    started_at: float
    ended_at: float | None
    state: str
    state_detail: str
    exit_code: int | None
    registration_dir: Path

    def runtime_seconds(self) -> float:
        end = self.ended_at if self.ended_at is not None else time.time()
        return max(0.0, end - self.started_at)


_SCAN_CACHE_LOCK = threading.RLock()
_SCAN_CACHE: dict[
    tuple[Path, bool, float | None, float | None],
    tuple[float, tuple[ExternalMeasuredJob, ...], str],
] = {}


def _strict_epoch(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        epoch = math.nan
    else:
        try:
            epoch = float(value)
        except OverflowError:
            epoch = math.inf
    if not math.isfinite(epoch) or not 0 <= epoch <= _MAX_SUPPORTED_EPOCH:
        raise ValueError(
            f"{label} must be an epoch in the supported UTC datetime range "
            "1970-01-01 through 3000-01-01"
        )
    try:
        datetime.fromtimestamp(epoch, timezone.utc)
    except (OSError, OverflowError, ValueError) as exc:
        raise ValueError(f"{label} is not renderable as a supported UTC datetime") from exc
    return epoch


def _clear_external_measured_scan_cache() -> None:
    """Clear the short operational scan snapshot (primarily for deterministic tests)."""

    with _SCAN_CACHE_LOCK:
        _SCAN_CACHE.clear()


def _invalidate_external_measured_scan_cache(results_root: Path) -> None:
    try:
        resolved = Path(results_root).resolve(strict=True)
    except OSError:
        return
    with _SCAN_CACHE_LOCK:
        for key in tuple(_SCAN_CACHE):
            if key[0] == resolved:
                del _SCAN_CACHE[key]


def _cached_external_measured_scan(
    key: tuple[Path, bool, float | None, float | None],
) -> tuple[list[ExternalMeasuredJob], str] | None:
    now = time.monotonic()
    with _SCAN_CACHE_LOCK:
        cached = _SCAN_CACHE.get(key)
        if cached is None:
            return None
        if now - cached[0] > _SCAN_CACHE_TTL_SECONDS:
            del _SCAN_CACHE[key]
            return None
        return list(cached[1]), cached[2]


def _cache_external_measured_scan(
    key: tuple[Path, bool, float | None, float | None],
    jobs: list[ExternalMeasuredJob],
    notice: str,
) -> None:
    with _SCAN_CACHE_LOCK:
        _SCAN_CACHE[key] = (time.monotonic(), tuple(jobs), notice)
        if len(_SCAN_CACHE) > _MAX_SCAN_CACHE_ENTRIES:
            oldest = sorted(_SCAN_CACHE, key=lambda item: _SCAN_CACHE[item][0])
            for stale in oldest[: len(_SCAN_CACHE) - _MAX_SCAN_CACHE_ENTRIES]:
                del _SCAN_CACHE[stale]


def _secret_bearing_option(argument: str) -> bool:
    """Recognize secret option names without substring-matching legitimate flags."""

    if not argument.startswith("-"):
        return False
    option_name = argument.split("=", 1)[0].lstrip("-")
    if not option_name:
        return False
    components = tuple(
        component
        for component in re.split(r"[-_.]+", option_name.casefold())
        if component
    )
    if any(component in _SECRET_OPTION_COMPONENTS for component in components):
        return True
    compact = "".join(components)
    return compact in _COMPACT_SECRET_OPTION_NAMES


def _canonical_argv_bytes(argv: Sequence[str]) -> bytes:
    return json.dumps(
        list(argv),
        ensure_ascii=False,
        sort_keys=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _validated_argv(argv: Sequence[str]) -> tuple[tuple[str, ...], str]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        raise ValueError("sanitized argv must be a sequence of strings")
    if not 1 <= len(argv) <= _MAX_ARGV_ITEMS:
        raise ValueError("sanitized argv item count is outside the safe bound")
    retained: list[str] = []
    for item in argv:
        if not isinstance(item, str):
            raise ValueError("sanitized argv must contain only strings")
        encoded = item.encode("utf-8")
        if (
            not item
            or len(encoded) > _MAX_ARG_BYTES
            or "\x00" in item
            or any(ord(character) < 0x20 for character in item)
        ):
            raise ValueError("sanitized argv contains an unsafe argument")
        retained.append(item)
    if any(_secret_bearing_option(part) for part in retained):
        raise ValueError("sanitized argv contains a secret-bearing option")
    material = _canonical_argv_bytes(retained)
    if len(material) > _MAX_ARGV_BYTES:
        raise ValueError("sanitized argv exceeds the safe byte bound")
    assert_durable_job_state_path_free(retained, None)
    return tuple(retained), hashlib.sha256(material).hexdigest()


def _resolved_results_root(results_root: Path) -> Path:
    supplied = Path(results_root)
    try:
        # Rig Web is intentionally launched with the repository's configured
        # ``runs`` symlink.  Resolve that trusted configuration boundary once;
        # every registry/output child is then constrained below the canonical
        # target and is independently prohibited from being a symlink.
        resolved = supplied.resolve(strict=True)
        if not stat.S_ISDIR(resolved.lstat().st_mode):
            raise ValueError("results root is not a directory")
    except OSError as exc:
        raise ValueError("results root is unavailable") from exc
    return resolved


def _registry_root(results_root: Path, *, create: bool) -> Path | None:
    results = _resolved_results_root(results_root)
    candidate = results / REGISTRY_DIRECTORY
    if create:
        try:
            candidate.mkdir(mode=0o750, exist_ok=True)
        except OSError as exc:
            raise ValueError("external measured registry cannot be created") from exc
    try:
        if candidate.is_symlink():
            return None
        root = candidate.resolve(strict=True)
        if root.parent != results or not stat.S_ISDIR(root.lstat().st_mode):
            return None
    except OSError:
        return None
    return root


def _resolved_runner_output(results_root: Path, out_dir: Path) -> tuple[Path, str]:
    results = _resolved_results_root(results_root)
    runner = results / "thesis" / "runner"
    supplied = Path(out_dir)
    if not supplied.is_absolute():
        raise ValueError("external measured out_dir must be absolute")
    try:
        if supplied.is_symlink():
            raise ValueError("external measured out_dir must not be a symlink")
        resolved = supplied.resolve(strict=True)
        if not stat.S_ISDIR(resolved.lstat().st_mode):
            raise ValueError("external measured out_dir is not a directory")
        runner_resolved = runner.resolve(strict=True)
        if not stat.S_ISDIR(runner_resolved.lstat().st_mode):
            raise ValueError("Runner output root is not a directory")
        relative = resolved.relative_to(runner_resolved)
        if not relative.parts:
            raise ValueError("external measured out_dir must be below the Runner root")
    except OSError as exc:
        raise ValueError("external measured out_dir is unavailable") from exc
    except ValueError as exc:
        if str(exc).startswith("external measured") or str(exc).startswith("Runner"):
            raise
        raise ValueError("external measured out_dir escapes results_root/thesis/runner") from exc
    return resolved, resolved.relative_to(results).as_posix()


def _validate_identity(
    *,
    job_id: str,
    command: str,
    declared_kind: str,
    argv: Sequence[str],
    out_dir: Path,
    results_root: Path,
    expected_commit: str,
    framework_lock_id: str,
    gate5_sha256: str,
    tmux_socket: str,
    tmux_session: str,
) -> tuple[tuple[str, ...], str, Path, str]:
    if not isinstance(job_id, str) or _SAFE_JOB_ID.fullmatch(job_id) is None:
        raise ValueError("external measured job_id is unsafe")
    if command != "run_matrix" or declared_kind != "measured":
        raise ValueError("external registration supports measured run_matrix only")
    retained_argv, argv_sha256 = _validated_argv(argv)
    if run_kind(command, list(retained_argv)) != declared_kind:
        raise ValueError("sanitized argv does not describe a measured run")
    positions = [index for index, part in enumerate(retained_argv) if part == "--out"]
    if len(positions) != 1 or positions[0] + 1 >= len(retained_argv):
        raise ValueError("sanitized argv must contain one exact --out value")
    resolved_out, artifact_relative = _resolved_runner_output(results_root, out_dir)
    argv_out = Path(retained_argv[positions[0] + 1])
    if not argv_out.is_absolute():
        raise ValueError("sanitized argv --out must be absolute")
    try:
        if argv_out.resolve(strict=True) != resolved_out:
            raise ValueError("sanitized argv --out differs from registered out_dir")
    except OSError as exc:
        raise ValueError("sanitized argv --out is unavailable") from exc
    if _HEX40.fullmatch(expected_commit) is None:
        raise ValueError("expected commit must be lowercase 40-hex")
    if _HEX64.fullmatch(framework_lock_id) is None:
        raise ValueError("framework lock id must be lowercase 64-hex")
    if _HEX64.fullmatch(gate5_sha256) is None:
        raise ValueError("Gate 5 digest must be lowercase 64-hex")
    if _SAFE_TOKEN.fullmatch(tmux_socket) is None:
        raise ValueError("tmux socket is unsafe")
    if _SAFE_TOKEN.fullmatch(tmux_session) is None:
        raise ValueError("tmux session is unsafe")
    return retained_argv, argv_sha256, resolved_out, artifact_relative


def _write_create_only(path: Path, document: dict[str, Any]) -> Path:
    raw = (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    temporary: Path | None = None
    descriptor: int | None = None
    for _attempt in range(32):
        candidate = path.parent / (
            f".{path.name}.{os.getpid()}.{secrets.token_hex(12)}.tmp"
        )
        try:
            descriptor = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        except FileExistsError:
            continue
        temporary = candidate
        break
    if temporary is None or descriptor is None:
        raise OSError("could not allocate a private registration publication file")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        _publish_create_only(temporary, path)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        _fsync_directory(path.parent)
        return path
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        _fsync_directory(path.parent)


def _publish_create_only(temporary: Path, final: Path) -> None:
    """Atomically publish a complete private file without replacing a final path."""

    if os.name == "nt":
        # Windows rename is atomic and raises FileExistsError when final exists.
        os.rename(temporary, final)
        return

    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is not None:
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,  # AT_FDCWD
            os.fsencode(temporary),
            -100,
            os.fsencode(final),
            1,  # RENAME_NOREPLACE
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, os.strerror(error), str(final))
        unsupported = {errno.EINVAL, errno.ENOSYS}
        if hasattr(errno, "ENOTSUP"):
            unsupported.add(errno.ENOTSUP)
        if error not in unsupported:
            raise OSError(error, os.strerror(error), str(final))

    # Portable no-replace fallback.  The final link always names the already
    # fsynced complete inode; the caller immediately removes the private link.
    os.link(temporary, final, follow_symlinks=False)


def _fsync_directory(directory: Path) -> None:
    """Persist same-directory publication/cleanup where directory fsync exists."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def register_external_measured_start(
    results_root: Path,
    *,
    job_id: str,
    command: str,
    run_kind_name: str,
    sanitized_argv: Sequence[str],
    out_dir: Path,
    expected_commit: str,
    framework_lock_id: str,
    gate5_sha256: str,
    tmux_socket: str,
    tmux_session: str,
    started_at: float | None = None,
) -> Path:
    """Create one immutable external measured start registration."""

    timestamp = _strict_epoch(
        time.time() if started_at is None else started_at,
        "started_at",
    )
    argv, argv_sha256, resolved_out, _artifact_relative = _validate_identity(
        job_id=job_id,
        command=command,
        declared_kind=run_kind_name,
        argv=sanitized_argv,
        out_dir=out_dir,
        results_root=results_root,
        expected_commit=expected_commit,
        framework_lock_id=framework_lock_id,
        gate5_sha256=gate5_sha256,
        tmux_socket=tmux_socket,
        tmux_session=tmux_session,
    )
    root = _registry_root(results_root, create=True)
    if root is None:
        raise ValueError("external measured registry is unsafe")
    registration_dir = root / job_id
    registration_dir.mkdir(mode=0o750, exist_ok=False)
    try:
        path = _write_create_only(
            registration_dir / _REGISTRATION_FILE,
            {
                "schema": REGISTRATION_SCHEMA,
                "event": "start",
                "job_id": job_id,
                "command": command,
                "run_kind": run_kind_name,
                "sanitized_argv": list(argv),
                "argv_sha256": argv_sha256,
                "out_dir": str(resolved_out),
                "expected_commit": expected_commit,
                "framework_lock_id": framework_lock_id,
                "gate5_sha256": gate5_sha256,
                "tmux": {
                    "launcher": "tmux",
                    "socket": tmux_socket,
                    "session": tmux_session,
                },
                "started_at": timestamp,
                "registration_authority": "operational_only",
                "thesis_empirical_evidence": False,
            },
        )
        _invalidate_external_measured_scan_cache(root.parent)
        return path
    except Exception:
        # Only the exact directory created above is considered, and rmdir is
        # intentionally successful only when no partial registration evidence
        # exists.  A non-empty or replaced path is preserved for inspection.
        try:
            if (
                not registration_dir.is_symlink()
                and registration_dir.resolve(strict=True).parent == root
            ):
                registration_dir.rmdir()
        except OSError:
            pass
        raise


def register_external_measured_terminal(
    results_root: Path,
    *,
    job_id: str,
    exit_code: int,
    ended_at: float | None = None,
) -> Path:
    """Create the sole immutable terminal event for a registered job."""

    if not isinstance(job_id, str) or _SAFE_JOB_ID.fullmatch(job_id) is None:
        raise ValueError("external measured job_id is unsafe")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise ValueError("terminal exit_code must be an integer from 0 through 255")
    timestamp = _strict_epoch(
        time.time() if ended_at is None else ended_at,
        "ended_at",
    )
    existing = load_external_measured_job(results_root, job_id, probe_session=False)
    if existing is None:
        raise ValueError("external measured start registration is unavailable or invalid")
    if timestamp < existing.started_at:
        raise ValueError("terminal event precedes its start event")
    path = _write_create_only(
        existing.registration_dir / _TERMINAL_FILE,
        {
            "schema": TERMINAL_SCHEMA,
            "event": "terminal",
            "job_id": job_id,
            "ended_at": timestamp,
            "state": "complete" if exit_code == 0 else "failed",
            "exit_code": exit_code,
        },
    )
    _invalidate_external_measured_scan_cache(existing.registration_dir.parent.parent)
    return path


def _bounded_regular_json(path: Path, byte_limit: int) -> dict[str, Any] | None:
    descriptor: int | None = None
    try:
        if path.is_symlink():
            return None
        path_before = path.lstat()
        if not stat.S_ISREG(path_before.st_mode) or path_before.st_size > byte_limit:
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > byte_limit
            or before.st_nlink != 1
            or path_before.st_nlink != 1
            or before.st_dev != path_before.st_dev
            or before.st_ino != path_before.st_ino
        ):
            return None
        chunks: list[bytes] = []
        remaining = byte_limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = path.lstat()
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_mtime_ns != after.st_mtime_ns
            or len(raw) != after.st_size
            or len(raw) > byte_limit
            or path_after.st_dev != after.st_dev
            or path_after.st_ino != after.st_ino
            or after.st_nlink != 1
            or path_after.st_nlink != 1
            or not stat.S_ISREG(path_after.st_mode)
        ):
            return None
        value = strict_json_loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return value if isinstance(value, dict) else None


def _load_registration(
    results_root: Path,
    registration_dir: Path,
) -> ExternalMeasuredJob | None:
    registration = _bounded_regular_json(
        registration_dir / _REGISTRATION_FILE,
        _MAX_REGISTRATION_BYTES,
    )
    if registration is None or set(registration) != {
        "schema",
        "event",
        "job_id",
        "command",
        "run_kind",
        "sanitized_argv",
        "argv_sha256",
        "out_dir",
        "expected_commit",
        "framework_lock_id",
        "gate5_sha256",
        "tmux",
        "started_at",
        "registration_authority",
        "thesis_empirical_evidence",
    }:
        return None
    tmux = registration.get("tmux")
    if not isinstance(tmux, dict) or set(tmux) != {"launcher", "socket", "session"}:
        return None
    if (
        registration.get("schema") != REGISTRATION_SCHEMA
        or registration.get("event") != "start"
        or registration.get("job_id") != registration_dir.name
        or registration.get("registration_authority") != "operational_only"
        or registration.get("thesis_empirical_evidence") is not False
        or tmux.get("launcher") != "tmux"
    ):
        return None
    try:
        argv, argv_sha256, out_dir, artifact_relative = _validate_identity(
            job_id=registration["job_id"],
            command=registration["command"],
            declared_kind=registration["run_kind"],
            argv=registration["sanitized_argv"],
            out_dir=Path(registration["out_dir"]),
            results_root=results_root,
            expected_commit=registration["expected_commit"],
            framework_lock_id=registration["framework_lock_id"],
            gate5_sha256=registration["gate5_sha256"],
            tmux_socket=tmux["socket"],
            tmux_session=tmux["session"],
        )
        started_at = _strict_epoch(registration["started_at"], "started_at")
    except (KeyError, TypeError, ValueError):
        return None
    if registration.get("argv_sha256") != argv_sha256:
        return None

    terminal_path = registration_dir / _TERMINAL_FILE
    terminal = _bounded_regular_json(terminal_path, _MAX_TERMINAL_BYTES)
    if terminal is None:
        try:
            terminal_exists = terminal_path.exists() or terminal_path.is_symlink()
        except OSError:
            terminal_exists = True
        if terminal_exists:
            return None
        ended_at = None
        exit_code = None
        state = "running"
    else:
        if set(terminal) != {
            "schema",
            "event",
            "job_id",
            "ended_at",
            "state",
            "exit_code",
        }:
            return None
        try:
            ended_at = _strict_epoch(terminal["ended_at"], "ended_at")
        except (KeyError, ValueError):
            return None
        exit_code = terminal.get("exit_code")
        if (
            terminal.get("schema") != TERMINAL_SCHEMA
            or terminal.get("event") != "terminal"
            or terminal.get("job_id") != registration_dir.name
            or isinstance(exit_code, bool)
            or not isinstance(exit_code, int)
            or not 0 <= exit_code <= 255
            or terminal.get("state") != ("complete" if exit_code == 0 else "failed")
            or ended_at < started_at
        ):
            return None
        state = str(terminal["state"])

    return ExternalMeasuredJob(
        job_id=registration_dir.name,
        command="run_matrix",
        run_kind="measured",
        argv=argv,
        argv_sha256=argv_sha256,
        out_dir=out_dir,
        artifact_relative=artifact_relative,
        expected_commit=registration["expected_commit"],
        framework_lock_id=registration["framework_lock_id"],
        gate5_sha256=registration["gate5_sha256"],
        tmux_socket=tmux["socket"],
        tmux_session=tmux["session"],
        started_at=started_at,
        ended_at=ended_at,
        state=state,
        state_detail="",
        exit_code=exit_code,
        registration_dir=registration_dir,
    )


def _external_session_spec(job: ExternalMeasuredJob) -> _NamedSessionSpec:
    return _NamedSessionSpec(
        directory=job.registration_dir,
        launcher="tmux",
        socket=job.tmux_socket,
        session=job.tmux_session,
        grace_until=job.started_at + _START_SESSION_GRACE_SECONDS,
        owner_label="external measured controller",
    )


def _apply_external_session_liveness(
    jobs: list[ExternalMeasuredJob],
    *,
    probe_limit: int,
) -> tuple[list[ExternalMeasuredJob], int]:
    running = sorted(
        (
            (job, _external_session_spec(job))
            for job in jobs
            if job.state == "running"
        ),
        key=lambda item: (item[0].started_at, item[0].job_id),
        reverse=True,
    )
    selected = running[:probe_limit]
    observed = _named_session_liveness([spec for _job, spec in selected])
    by_job_id: dict[str, ExternalMeasuredJob] = {}
    for job, spec in selected:
        live = observed.get(spec)
        if live is True:
            by_job_id[job.job_id] = replace(job, state_detail="")
        elif live is False:
            by_job_id[job.job_id] = replace(
                job,
                state="orphaned",
                state_detail=_LIVENESS_STOPPED_DETAIL,
            )
        else:
            by_job_id[job.job_id] = replace(
                job,
                state="unknown",
                state_detail=_LIVENESS_UNAVAILABLE_DETAIL,
            )
    for job, _spec in running[probe_limit:]:
        by_job_id[job.job_id] = replace(
            job,
            state="unknown",
            state_detail=_LIVENESS_UNPROBED_DETAIL,
        )
    return [by_job_id.get(job.job_id, job) for job in jobs], max(
        0, len(running) - probe_limit
    )


def load_external_measured_job(
    results_root: Path,
    job_id: str,
    *,
    probe_session: bool = True,
) -> ExternalMeasuredJob | None:
    """Load one safe fixed-child registration without recursive discovery."""

    if not isinstance(job_id, str) or _SAFE_JOB_ID.fullmatch(job_id) is None:
        return None
    try:
        root = _registry_root(results_root, create=False)
    except ValueError:
        return None
    if root is None:
        return None
    candidate = root / job_id
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        if resolved.parent != root or not stat.S_ISDIR(resolved.lstat().st_mode):
            return None
    except OSError:
        return None
    job = _load_registration(results_root, resolved)
    if job is None or not probe_session:
        return job
    observed, _unprobed = _apply_external_session_liveness([job], probe_limit=1)
    return observed[0]


def scan_external_measured_jobs(
    results_root: Path,
    *,
    started_from: float | None = None,
    started_to: float | None = None,
    probe_session: bool = True,
) -> tuple[list[ExternalMeasuredJob], str]:
    """Scan only direct registered children, with explicit entry/file bounds."""

    if (started_from is None) != (started_to is None):
        raise ValueError("external measured date window requires both bounds")
    if started_from is not None:
        lower = _strict_epoch(started_from, "started_from")
        upper = _strict_epoch(started_to, "started_to")
        if lower > upper:
            raise ValueError("external measured date window is reversed")
    else:
        lower = upper = 0.0
    try:
        resolved_results = _resolved_results_root(results_root)
    except ValueError:
        return [], "External measured registry is unavailable."
    cache_key = (
        resolved_results,
        probe_session,
        lower if started_from is not None else None,
        upper if started_to is not None else None,
    )
    cached = _cached_external_measured_scan(cache_key)
    if cached is not None:
        return cached
    root = _registry_root(resolved_results, create=False)
    if root is None:
        empty: list[ExternalMeasuredJob] = []
        _cache_external_measured_scan(cache_key, empty, "")
        return empty, ""
    jobs: list[ExternalMeasuredJob] = []
    truncated = False
    try:
        for index, candidate in enumerate(root.iterdir()):
            if index >= _MAX_REGISTRATIONS:
                truncated = True
                break
            if candidate.is_symlink() or _SAFE_JOB_ID.fullmatch(candidate.name) is None:
                continue
            try:
                resolved = candidate.resolve(strict=True)
                if resolved.parent != root or not stat.S_ISDIR(resolved.lstat().st_mode):
                    continue
            except OSError:
                continue
            job = _load_registration(resolved_results, resolved)
            if job is None:
                continue
            if started_from is not None and not lower <= job.started_at <= upper:
                continue
            jobs.append(job)
    except OSError:
        return [], "External measured registry could not be scanned."
    notices = []
    if truncated:
        notices.append(
            f"External measured registry scan stopped after {_MAX_REGISTRATIONS} entries."
        )
    if probe_session:
        jobs, unprobed = _apply_external_session_liveness(
            jobs,
            probe_limit=_MAX_RUNNING_SESSION_PROBES,
        )
        if unprobed:
            notices.append(
                "External measured named-session liveness probing was limited to "
                f"the {_MAX_RUNNING_SESSION_PROBES} newest running registrations; "
                f"{unprobed} additional running registration"
                f"{'s were' if unprobed != 1 else ' was'} not probed and "
                "are shown as unknown."
            )
    sorted_jobs = sorted(
        jobs,
        key=lambda item: (item.started_at, item.job_id),
        reverse=True,
    )
    notice = " ".join(notices)
    _cache_external_measured_scan(cache_key, sorted_jobs, notice)
    return sorted_jobs, notice


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create-only externally owned measured-job registration"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    start = subparsers.add_parser("start")
    start.add_argument("--results-root", type=Path, required=True)
    start.add_argument("--job-id", required=True)
    start.add_argument("--command", default="run_matrix")
    start.add_argument("--run-kind", default="measured")
    start.add_argument("--out-dir", type=Path, required=True)
    start.add_argument("--expected-commit", required=True)
    start.add_argument("--framework-lock-id", required=True)
    start.add_argument("--gate5-sha256", required=True)
    start.add_argument("--tmux-socket", required=True)
    start.add_argument("--tmux-session", required=True)
    start.add_argument("--started-at", type=float)
    start.add_argument("--argv", nargs=argparse.REMAINDER, required=True)
    terminal = subparsers.add_parser("terminal")
    terminal.add_argument("--results-root", type=Path, required=True)
    terminal.add_argument("--job-id", required=True)
    terminal.add_argument("--exit-code", type=int, required=True)
    terminal.add_argument("--ended-at", type=float)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "start":
        path = register_external_measured_start(
            args.results_root,
            job_id=args.job_id,
            command=args.command,
            run_kind_name=args.run_kind,
            sanitized_argv=args.argv,
            out_dir=args.out_dir,
            expected_commit=args.expected_commit,
            framework_lock_id=args.framework_lock_id,
            gate5_sha256=args.gate5_sha256,
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            started_at=args.started_at,
        )
    else:
        path = register_external_measured_terminal(
            args.results_root,
            job_id=args.job_id,
            exit_code=args.exit_code,
            ended_at=args.ended_at,
        )
    print(path)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
