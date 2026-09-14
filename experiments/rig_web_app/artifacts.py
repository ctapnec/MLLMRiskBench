"""Artifact inventory, process records, and recorded-usage extraction."""

from __future__ import annotations

import hashlib
import html
import math
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from ura.model_identity import canonical_provider_name
from ura.strict_json import strict_json_loads
from ura.validation_cache import ValidationCache

from .catalog import _INVENTORY_MAX_ENTRIES, _INVENTORY_MAX_DEPTH


_PIPELINE_STAGES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Revision receipt", (".project-revision.json",)),
    ("Source receipts", ("source-conformance.json",)),
    ("Envelopes", (".request-envelope.json",)),
    ("Attestations", (".live-attestation.json",)),
    ("Canaries", (".lane-canary.json", ".canary.json")),
    ("Grids", (".grid.json",)),
    ("Level-1/2", ()),  # filled from level1/level2/suite counts below
)
_ANALYSIS_MARKERS = ("level1", "level2", "suite-evidence")


_STAGE_PATHS_SHOWN = 20


@dataclass
class StageInventory:
    """Presence-only tally for one pipeline stage."""

    count: int = 0
    superseded: int = 0
    paths: list[str] = field(default_factory=list)


def artifact_inventory(root: Path) -> tuple[dict[str, StageInventory], bool]:
    """Count retained artifact files by kind under the results root.

    Bounded, presence-only walk: at most ``_INVENTORY_MAX_ENTRIES`` directory
    entries and ``_INVENTORY_MAX_DEPTH`` levels are visited, lazily, so one
    pathological flat directory cannot stall the dashboard.  Files below a
    ``superseded`` directory are tallied separately (archived, not current).
    Returns the stages plus a truncation flag (counts are a lower bound when
    True).  Counting a file says nothing about its validity.
    """

    stages: dict[str, StageInventory] = {label: StageInventory() for label, _ in _PIPELINE_STAGES}
    seen = 0
    root = root.resolve()

    def record(label: str, entry: Path) -> None:
        stage = stages[label]
        try:
            relative = entry.relative_to(root).as_posix()
        except ValueError:
            relative = entry.name
        if "superseded" in relative.split("/"):
            stage.superseded += 1
        else:
            stage.count += 1
        if len(stage.paths) < _STAGE_PATHS_SHOWN:
            stage.paths.append(relative)

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            for entry in directory.iterdir():
                seen += 1
                if seen > _INVENTORY_MAX_ENTRIES:
                    return stages, True
                if entry.is_dir():
                    if depth + 1 <= _INVENTORY_MAX_DEPTH:
                        stack.append((entry, depth + 1))
                    continue
                name = entry.name.lower()
                for label, suffixes in _PIPELINE_STAGES:
                    if any(name.endswith(suffix) for suffix in suffixes):
                        record(label, entry)
                if name.endswith((".json", ".csv")) and any(
                    marker in name for marker in _ANALYSIS_MARKERS
                ):
                    record("Level-1/2", entry)
        except OSError:
            continue
    return stages, False


def _pipeline_svg(stages: Mapping[str, StageInventory]) -> str:
    node_w, node_h, gap, top = 128, 58, 24, 12
    total_w = len(_PIPELINE_STAGES) * node_w + (len(_PIPELINE_STAGES) - 1) * gap
    parts = [
        f"<svg class='pipeline' viewBox='0 0 {total_w} {node_h + 2 * top}' "
        "role='img' aria-label='campaign pipeline'>",
        "<defs><marker id='arrowhead' markerWidth='7' markerHeight='7' "
        "refX='6' refY='3.5' orient='auto'><path d='M0 0L7 3.5L0 7z'/>"
        "</marker></defs>",
    ]
    for index, (label, _suffixes) in enumerate(_PIPELINE_STAGES):
        x = index * (node_w + gap)
        stage = stages.get(label, StageInventory())
        cls = "node present" if stage.count else "node"
        if stage.count:
            count_text = f"{stage.count} file{'s' if stage.count != 1 else ''}"
        else:
            count_text = "none yet"
        extra = (
            f"<text class='count sub' x='{x + node_w / 2}' y='{top + 51}' "
            f"text-anchor='middle'>+{stage.superseded} archived</text>"
            if stage.superseded
            else ""
        )
        node = (
            f"<g class='{cls}'>"
            f"<rect x='{x}' y='{top}' width='{node_w}' height='{node_h}' "
            "rx='10'/>"
            f"<text x='{x + node_w / 2}' y='{top + 23}' "
            f"text-anchor='middle'>{html.escape(label)}</text>"
            f"<text class='count' x='{x + node_w / 2}' y='{top + 40}' "
            f"text-anchor='middle'>{html.escape(count_text)}</text>" + extra + "</g>"
        )
        # A stage node links to the directory holding its files, preferring a
        # current (non-archived) path so the click lands on live artifacts;
        # presence there never implies validity.
        if stage.paths:
            current = [p for p in stage.paths if "superseded" not in p.split("/")]
            first = (current or stage.paths)[0]
            directory = first.rsplit("/", 1)[0] if "/" in first else ""
            node = (
                f"<a href='/artifacts?path={quote(directory)}' "
                f"aria-label='browse {html.escape(label)} artifacts'>" + node + "</a>"
            )
        parts.append(node)
        if index < len(_PIPELINE_STAGES) - 1:
            start = x + node_w
            parts.append(
                f"<path class='arrow' d='M{start + 3} {top + node_h / 2} "
                f"L{start + gap - 4} {top + node_h / 2}'/>"
            )
    parts.append("</svg>")
    return "<div class='scroll'>" + "".join(parts) + "</div>"


@dataclass
class Job:
    job_id: str
    command: str
    argv: list[str]
    directory: Path
    process: subprocess.Popen | None = None
    stdout_handle: Any = None
    stderr_handle: Any = None
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None
    #: Durable builder/form parameters this job was composed from. Explicit
    #: workstation checkpoint paths are projected to content identities before
    #: this object is created, so restore/UI state never needs the locator.
    builder_params: dict[str, str] | None = None
    #: The pinned project revision exported when the job started.
    pin: str = ""
    #: Short failure context (stderr tail) persisted for a failed job.
    failure: str | None = None
    #: Explicit active-work classification. Presentation code may surface it
    #: only while ``state() == "running"``; a command/name is never inferred.
    activity: str | None = None
    #: A Windows Job Object handle the process is assigned to, used by explicit
    #: Stop as the reliable whole-tree kill fallback. None on POSIX / when
    #: unavailable; closing it alone never terminates a running experiment.
    job_handle: Any = None
    #: Set when a stop could NOT be confirmed to have terminated the tree, so
    #: the UI surfaces an explicit stop failure rather than a false success.
    stop_error: str | None = None
    #: Last-known state for a job restored from the database whose live
    #: process handle is gone (a prior console session started it).
    restored_state: str | None = None
    restored_exit: int | None = None
    #: Set only AFTER the terminal state committed to the database.
    run_recorded: bool = False

    def state(self) -> str:
        if self.process is None:
            return self.restored_state or "unknown"
        code = self.exit_code()
        if getattr(self.process, "interrupted", False):
            return "stopped" if (self.directory / "stop-request.json").exists() else "interrupted"
        if code is None:
            return "running"
        if self.ended_at is None:
            self.ended_at = time.time()
        return "complete" if code == 0 else "failed"

    def exit_code(self) -> int | None:
        if self.process is None:
            return self.restored_exit
        code = self.process.poll()
        from .job_runtime import read_state
        record = getattr(self.process, "terminal", None) or read_state(self.directory)
        if record and record.get("supervisor", {}).get("pid") == getattr(self.process, "pid", None):
            if record["state"] in {"complete", "failed"}:
                self.process.terminal = record
                return int(record["exit_code"])
            if code is not None:
                self.process.interrupted = True
        return None if getattr(self.process, "interrupted", False) else code

    def runtime_seconds(self) -> float:
        end = self.ended_at if self.ended_at is not None else time.time()
        return max(0.0, end - self.started_at)


def assert_durable_job_state_path_free(
    argv: list[str],
    builder_params: Mapping[str, str] | None,
) -> None:
    """Reject any explicit vLLM checkpoint locator in retained job state.

    Runtime argv may need an operator-local path long enough for vLLM to open
    a checkpoint.  Durable argv, builder keys, and builder values must carry
    only the checkpoint's content identity.  Keep this validator neutral so
    lifecycle can run the exact same persistence boundary *before* Popen and
    SQLite can retain a redundant fail-closed check for alternate callers.
    """

    from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

    retained_strings = [str(value) for value in argv]
    if builder_params:
        retained_strings.extend(str(key) for key in builder_params)
        retained_strings.extend(str(value) for value in builder_params.values())
    for retained in retained_strings:
        # Model lists are comma-delimited.  Iterate every marker in each token
        # too, so a safe first identity cannot hide a later path-bearing one.
        for token in retained.split(","):
            lowered = token.casefold()
            offset = 0
            while True:
                marker = lowered.find("vllm:", offset)
                if marker < 0:
                    break
                model = token[marker + len("vllm:") :].strip()
                if _is_explicit_local_path(model):
                    raise ValueError(
                        "refusing to persist an explicit local checkpoint path"
                    )
                offset = marker + len("vllm:")


#: Map a job's command + argv to a campaign-run kind for the registry.
def run_kind(command: str, argv: list[str]) -> str | None:
    if command not in {"run_matrix", "rig_check"}:
        return None
    if command == "rig_check":
        return "preflight"
    # No-call modes take precedence over any lane-shape flag that may also be
    # present in a composed or restored argv.
    if "--model-acquisition-plan-only" in argv:
        return "acquisition_plan"
    if "--preflight-only" in argv:
        return "preflight"
    if "--dry-run" in argv:
        return "dry_run"
    if "--attestation-probe" in argv:
        return "attestation_probe"
    if "--diagnostic-canary" in argv:
        return "diagnostic_canary"
    return "measured"


def _argv_out_dir(argv: list[str]) -> str:
    for flag in ("--out", "--output"):
        if flag in argv:
            index = argv.index(flag)
            if index + 1 < len(argv):
                return argv[index + 1]
    return ""


# -- Windows whole-tree kill via a Job Object -------------------------------
#
# Windows has no process groups that kill a tree; ``taskkill /T`` walks the
# live tree but can fail.  A plain Job Object gives explicit Stop a reliable
# ``TerminateJobObject`` fallback while still allowing a running experiment to
# remain detached when the console closes.  KILL_ON_JOB_CLOSE is deliberately
# not enabled: closing the console must not silently kill a paid run and leave
# its database row falsely marked ``running``.


def _win_managed_job() -> Any:
    """Create a Windows Job Object handle for explicit whole-tree stop."""

    if os.name != "nt":
        return None
    try:
        import ctypes  # noqa: PLC0415 - Windows-only
        from ctypes import wintypes  # noqa: PLC0415 - Windows-only

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None

        return handle
    except Exception:  # noqa: BLE001 - any ctypes fault -> no job object
        return None


def _win_assign_job(handle: Any, process: subprocess.Popen) -> bool:
    """Assign a running process (and its future children) to the job."""

    if handle is None or os.name != "nt" or process is None:
        return False
    try:
        import ctypes  # noqa: PLC0415 - Windows-only

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        return bool(kernel32.AssignProcessToJobObject(handle, int(process._handle)))
    except Exception:  # noqa: BLE001
        return False


def _win_close_handle(handle: Any) -> None:
    if handle is None or os.name != "nt":
        return
    try:
        import ctypes  # noqa: PLC0415 - Windows-only

        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
    except Exception:  # noqa: BLE001
        pass


def _win_terminate_job(handle: Any) -> bool:
    """Terminate every process assigned to a Windows Job Object."""

    if handle is None or os.name != "nt":
        return False
    try:
        import ctypes  # noqa: PLC0415 - Windows-only

        return bool(ctypes.WinDLL("kernel32", use_last_error=True).TerminateJobObject(handle, 1))
    except Exception:  # noqa: BLE001
        return False


# -- recorded token usage and calculated cost -------------------------------
#
# Never an estimate: every number below is read from retained run artifacts,
# entered through their completion markers so checkpoints, superseded partial
# snapshots, and orphaned cell files are never counted.  Monetary cost is
# calculated only from an operator-edited effective-dated pricing table; a
# missing token count or missing price renders as N/A, never as zero.

#: Billing categories recorded per (provider, model).  Semantics follow each
#: provider's own usage fields verbatim (no overlap adjustment is invented):
#: ``input``/``output`` are the provider-reported token counts
#: (``raw.provider_usage`` detail preferred over the normalized ``tokens``
#: map), ``cache_read``/``cache_write`` and ``reasoning`` appear only when the
#: provider reported them.
_TOKEN_CATEGORIES = ("input", "output", "cache_read", "cache_write", "reasoning")
#: Categories that carry their own price.  ``reasoning`` is deliberately absent:
#: providers bill thinking/reasoning tokens as part of ``output`` (the adapters
#: enforce reasoning <= output), so charging it again would double-bill.  It is
#: displayed for transparency but never priced.
_BILLED_CATEGORIES = ("input", "output", "cache_read", "cache_write")
_UNBILLED_PROVIDERS = {"vllm", "ollama", "mock", "local"}
_MARKER_SUFFIX = ".complete.json"

# Derived console indexes must not treat retained engineering harnesses as
# research runs.  Those trees deliberately contain copied fixtures, temporary
# pytest workspaces, and smoke-test artifacts that may themselves look like
# valid Runner outputs.  They remain browsable as raw engineering evidence,
# but recursive scientific/usage discovery stops at these boundaries.
_DERIVED_SCAN_EXCLUDED_DIRS = frozenset(
    {
        "engineering",
        "external-measured-jobs",
        "external-measured-jobs-v2",
        "external-analysis-jobs",
        "verification",
        "verifications",
        ".pytest_cache",
        "__pycache__",
    }
)


def derived_scan_directory_excluded(path: Path) -> bool:
    """Whether a recursive derived-index scan must not enter ``path``.

    This is intentionally based on retained evidence boundaries, not a broad
    substring match: a workstation's own temporary parent may legitimately
    contain the configured results root.  Symlinked directories are also
    excluded so an artifact tree cannot redirect a bounded scan elsewhere.
    """

    if path.is_symlink():
        return True
    name = path.name.casefold()
    if name in _DERIVED_SCAN_EXCLUDED_DIRS or name.startswith("pytest-"):
        return True
    marker = path / "ENGINEERING_ONLY.json"
    try:
        return marker.is_file() and not marker.is_symlink()
    except (OSError, RuntimeError):
        return True


def derived_index_path_quarantined(value: str) -> bool:
    """Reject a stale derived row whose recorded locator crosses engineering.

    SQLite may contain rows written by an older broad recursive reindex.  The
    read boundary therefore mirrors discovery until the next reindex replaces
    those rows.  Only path *segments* are inspected; words such as
    ``engineering-study`` do not match.
    """

    parts = tuple(
        part.casefold()
        for part in value.replace("\\", "/").split("/")
        if part
    )
    return any(
        part in _DERIVED_SCAN_EXCLUDED_DIRS or part.startswith("pytest-")
        for part in parts
    )


def explicit_engineering_boundary(path: Path) -> bool:
    """Whether ``path`` is at/below an explicit engineering-only marker."""

    for directory in (path, *path.parents):
        marker = directory / "ENGINEERING_ONLY.json"
        try:
            if marker.is_file() and not marker.is_symlink():
                return True
        except (OSError, RuntimeError):
            return True
    return False


def derived_path_quarantined(path: Path, results_root: Path) -> bool:
    """Scientific-index boundary for one exact canonical path.

    Relative segment exclusions apply only inside ``results_root`` so a
    workstation parent called ``pytest-*`` or ``engineering`` cannot taint an
    exact external run.  An explicit ``ENGINEERING_ONLY.json`` boundary applies
    everywhere, including ordinary-name directories inside the results tree.
    """

    if explicit_engineering_boundary(path):
        return True
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(results_root.resolve(strict=True)).as_posix()
    except ValueError:
        return False
    except (OSError, RuntimeError):
        return True
    return derived_index_path_quarantined(relative)


def _canonical_excluded_roots(values: tuple[Path, ...]) -> tuple[Path, ...]:
    roots: set[Path] = set()
    for value in values:
        try:
            resolved = value.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved.is_dir():
            roots.add(resolved)
    return tuple(roots)


def _under_excluded_root(path: Path, roots: tuple[Path, ...]) -> bool:
    if not roots:
        return False
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return True
    for root in roots:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        return True
    return False


def _tokens_by_category(tokens: Any, provider_usage: Any) -> dict[str, int]:
    """Normalize one call's recorded token counts into billing categories.

    Categories are made non-overlapping so no token is billed twice:
    ``input`` is the billable-at-input-rate count with any separately-billed
    cache reads removed (Anthropic's ``input_tokens`` already excludes cache;
    Fable exposes the net figure as ``uncached_input``; OpenAI's
    ``input_tokens`` is cache-inclusive, so the reported cache read is
    subtracted). ``cache_read``/``cache_write`` are the separately-priced
    cache components. ``reasoning`` is recorded for transparency only - every
    provider here bills thinking/reasoning tokens *as* output tokens (the
    adapters enforce ``reasoning <= output``), so ``compute_costs`` treats it
    as a subset of ``output`` and never charges it a second time.  Local
    adapters record prompt/completion and are not billed at all.
    """

    out: dict[str, int] = {}
    tk = tokens if isinstance(tokens, Mapping) else {}
    pu = provider_usage if isinstance(provider_usage, Mapping) else {}

    def valid_count(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 0

    def put(category: str, value: Any) -> None:
        if valid_count(value):
            out[category] = value

    put("output", pu.get("output_tokens"))
    if "output" not in out:
        put("output", tk.get("output", tk.get("completion")))
    put("cache_read", pu.get("cache_read_input_tokens"))
    put("cache_write", pu.get("cache_creation_input_tokens"))
    details_in = pu.get("input_tokens_details")
    if isinstance(details_in, Mapping):
        put("cache_read", details_in.get("cached_tokens"))
        put("cache_write", details_in.get("cache_write_tokens"))
    if "cache_read" not in out:
        put("cache_read", tk.get("cached_input"))
    if "cache_write" not in out:
        put("cache_write", tk.get("cache_write_input"))
    details_out = pu.get("output_tokens_details")
    if isinstance(details_out, Mapping):
        put("reasoning", details_out.get("thinking_tokens", details_out.get("reasoning_tokens")))
    if "reasoning" not in out:
        put("reasoning", tk.get("reasoning"))
    # Input last, so the cache reads it must exclude are already known. Prefer
    # an explicitly net figure (Fable's uncached_input); otherwise a provider
    # input_tokens is only ever written by the cache-inclusive OpenAI adapter
    # here, so net out the reported cache read.  A normalized tokens map (the
    # judge trail) reports ``input`` INCLUSIVE of its ``cached_input``, so net
    # that out too - the judge example {input: 100000, cached_input: 80000}
    # must be 20,000 ordinary input plus 80,000 cache-read, not 180,000 billed.
    if valid_count(tk.get("uncached_input")):
        put("input", tk["uncached_input"])
    elif valid_count(pu.get("input_tokens")):
        cached = out.get("cache_read", 0)
        if cached <= pu["input_tokens"]:
            put("input", pu["input_tokens"] - cached)
    elif valid_count(tk.get("input")):
        cached = tk.get("cached_input")
        gross = tk["input"]
        if valid_count(cached):
            if cached <= gross:
                put("input", gross - cached)
        else:
            put("input", gross)
    else:
        put("input", tk.get("prompt"))
    return out


def _token_usage_complete(categories: Mapping[str, int]) -> bool:
    """True only when a call records both mandatory billing directions."""

    return "input" in categories and "output" in categories


def _response_identity(record: Mapping[str, Any]) -> tuple[str, str]:
    """(provider, model) for one responses.jsonl record."""

    raw = record.get("raw")
    raw = raw if isinstance(raw, Mapping) else {}
    target = str(record.get("target", "") or "")
    provider = raw.get("provider") or raw.get("provider_name")
    if not isinstance(provider, str) or not provider:
        provider = target.split(":", 1)[0] if ":" in target else (target or "unknown")
    model = None
    for key in ("resolved_model", "provider_resolved_model", "provider_model", "model"):
        candidate = raw.get(key)
        if isinstance(candidate, str) and candidate:
            model = candidate
            break
    return canonical_provider_name(str(provider)), str(model or target or "unknown")


def _marker_artifact_path(
    marker_path: Path,
    descriptor: Any,
    *,
    verify_sha: bool = False,
) -> Path:
    """Resolve and byte-check one completion-marker artifact descriptor."""

    if not isinstance(descriptor, Mapping):
        raise ValueError("completion marker artifact descriptor missing")
    name = str(descriptor.get("file", ""))
    if not name or "/" in name or "\\" in name:
        raise ValueError(f"artifact descriptor names a non-bare file {name!r}")
    path = marker_path.parent / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"artifact {name!r} is missing or not a regular file")
    size = path.stat().st_size
    if size != descriptor.get("bytes"):
        raise ValueError(f"artifact {name!r} byte size changed since completion")
    if verify_sha:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != descriptor.get("sha256"):
            raise ValueError(f"artifact {name!r} digest changed since completion")
    return path


def iter_completed_markers(
    root: Path,
    *,
    max_entries: int = _INVENTORY_MAX_ENTRIES,
    excluded_roots: tuple[Path, ...] = (),
) -> tuple[list[tuple[Path, dict[str, Any]]], dict[str, int]]:
    """Completion markers under root plus honest skip accounting.

    Only ``*.complete.json`` markers with ``status: complete`` and
    ``format_version: 2`` and no sibling ``<stem>.error.json`` are returned;
    everything else (orphan cell files, checkpoints, errored cells) is
    excluded and counted so truncation is never silent.  ``excluded_roots``
    are exact descendant outputs owned by other retained Jobs.
    """

    markers: list[tuple[Path, dict[str, Any]]] = []
    canonical_exclusions = _canonical_excluded_roots(excluded_roots)
    stats = {
        "markers": 0,
        "skipped_error": 0,
        "skipped_invalid": 0,
        "orphan_responses": 0,
        "truncated": 0,
    }
    seen = 0
    completed_stems: set[str] = set()
    response_files: list[tuple[Path, str]] = []
    stack: list[Path] = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                stats["truncated"] = 1
                break
            if entry.is_dir():
                if not derived_scan_directory_excluded(
                    entry
                ) and not _under_excluded_root(entry, canonical_exclusions):
                    stack.append(entry)
                continue
            name = entry.name
            if name.endswith(".responses.jsonl") and not name.endswith(
                ".responses.checkpoint.jsonl"
            ):
                response_files.append((entry, name[: -len(".responses.jsonl")]))
                continue
            if not name.endswith(_MARKER_SUFFIX):
                continue
            stem = name[: -len(_MARKER_SUFFIX)]
            if (directory / f"{stem}.error.json").exists():
                stats["skipped_error"] += 1
                continue
            try:
                doc = strict_json_loads(entry.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                stats["skipped_invalid"] += 1
                continue
            if (
                not isinstance(doc, dict)
                or doc.get("status") != "complete"
                or doc.get("format_version") != 2
                or not isinstance(doc.get("artifacts"), dict)
            ):
                stats["skipped_invalid"] += 1
                continue
            markers.append((entry, doc))
            completed_stems.add(str(entry.parent / stem))
        if seen > max_entries:
            break
    stats["markers"] = len(markers)
    stats["orphan_responses"] = sum(
        1 for path, stem in response_files if str(path.parent / stem) not in completed_stems
    )
    return markers, stats


def usage_rows_from_marker(
    marker_path: Path,
    doc: Mapping[str, Any],
    *,
    verify_sha: bool = False,
) -> list[dict[str, Any]]:
    """Recorded per-(role, provider, model, category) usage for one cell.

    Target usage comes from the completion-bound responses artifact
    (``Response.tokens`` plus ``raw.provider_usage`` detail); judge usage from
    the completion-bound trails artifact (``raw.judge_call.tokens``, every
    cascade stage, provider-refusal rows excluded because no judge call was
    made).  A record whose token block is absent is tallied under the
    ``missing_tokens`` category so it renders as N/A, never as zero.
    """

    marker_sha = hashlib.sha256(marker_path.read_bytes()).hexdigest()
    run_id = str(doc.get("run_id", ""))
    out_dir = str(marker_path.parent)
    usage_date = _marker_usage_date(marker_path, doc)
    artifacts = doc["artifacts"]
    tallies: dict[tuple[str, str, str, str], int] = {}

    def add(role: str, provider: str, model: str, category: str, amount: int) -> None:
        provider = canonical_provider_name(provider)
        key = (role, provider, model, category)
        tallies[key] = tallies.get(key, 0) + amount

    responses_path = _marker_artifact_path(
        marker_path, artifacts.get("responses"), verify_sha=verify_sha
    )
    n_lines = 0
    with responses_path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            n_lines += 1
            try:
                record = strict_json_loads(line)
            except (ValueError, RecursionError) as exc:
                raise ValueError(
                    f"invalid responses usage JSON at {responses_path}:{n_lines}: {exc}"
                ) from exc
            if not isinstance(record, Mapping):
                raise ValueError(
                    f"non-object responses usage row at {responses_path}:{n_lines}"
                )
            provider, model = _response_identity(record)
            raw = record.get("raw")
            raw = raw if isinstance(raw, Mapping) else {}
            categories = _tokens_by_category(record.get("tokens"), raw.get("provider_usage"))
            add("target", provider, model, "calls", 1)
            if not _token_usage_complete(categories):
                add("target", provider, model, "missing_tokens", 1)
            for category, amount in categories.items():
                add("target", provider, model, category, amount)
    expected = artifacts["responses"].get("records")
    if isinstance(expected, int) and expected != n_lines:
        raise ValueError(
            f"responses artifact record count changed since completion ({n_lines} != {expected})"
        )
    trails_path = _marker_artifact_path(marker_path, artifacts.get("trails"), verify_sha=verify_sha)
    with trails_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = strict_json_loads(line)
            except (ValueError, RecursionError) as exc:
                raise ValueError(
                    f"invalid trails usage JSON at {trails_path}:{line_number}: {exc}"
                ) from exc
            if not isinstance(record, Mapping):
                raise ValueError(
                    f"non-object trails usage row at {trails_path}:{line_number}"
                )
            raw = record.get("raw")
            raw = raw if isinstance(raw, Mapping) else {}
            judge_call = raw.get("judge_call")
            if not isinstance(judge_call, Mapping):
                continue  # stage made no judge call
            if judge_call.get("sampling_control") == "not_queried_provider_refusal":
                continue  # provider refused; no call was made or billed
            provider = canonical_provider_name(
                str(judge_call.get("provider") or "unknown")
            )
            model = str(
                judge_call.get("provider_resolved_model") or raw.get("judge_model") or "unknown"
            )
            categories = _tokens_by_category(judge_call.get("tokens"), None)
            add("judge", provider, model, "calls", 1)
            if not _token_usage_complete(categories):
                add("judge", provider, model, "missing_tokens", 1)
            for category, amount in categories.items():
                add("judge", provider, model, category, amount)
    now = time.time()
    return [
        {
            "marker_sha": marker_sha,
            "role": role,
            "provider": provider,
            "model": model,
            "category": category,
            "amount": amount,
            "run_id": run_id,
            "out_dir": out_dir,
            "usage_date": usage_date,
            "recorded_at": now,
        }
        for (role, provider, model, category), amount in sorted(tallies.items())
    ]


def _marker_usage_date(marker_path: Path, doc: Mapping[str, Any]) -> str:
    """The run's completion date (YYYY-MM-DD) from completion-bound evidence.

    Prefers the marker's own ``completed_at`` timestamp; falls back to the
    completion marker file's mtime (the marker is written at completion).  This
    is provenance time, NOT scan time - reindexing an old run today reprices it
    at its own date, never today's rate.
    """

    timestamp: float | None = None
    stamp = doc.get("completed_at")
    if isinstance(stamp, (int, float)) and not isinstance(stamp, bool) and math.isfinite(stamp):
        timestamp = float(stamp)
    if timestamp is None:
        try:
            timestamp = marker_path.stat().st_mtime
        except OSError:
            return ""
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(timestamp))
    except (OSError, ValueError, OverflowError):
        return ""


def _judge_row_usage(record: Mapping[str, Any]) -> tuple[str, str, dict[str, int]] | None:
    """(provider, model, categories) for one trail record's judge call, or None
    when the stage made no billable judge call."""

    raw = record.get("raw")
    raw = raw if isinstance(raw, Mapping) else {}
    judge_call = raw.get("judge_call")
    if not isinstance(judge_call, Mapping):
        return None
    if judge_call.get("sampling_control") == "not_queried_provider_refusal":
        return None
    provider = canonical_provider_name(
        str(judge_call.get("provider") or "unknown")
    )
    model = str(judge_call.get("provider_resolved_model") or raw.get("judge_model") or "unknown")
    return provider, model, _tokens_by_category(judge_call.get("tokens"), None)


def failed_cell_usage_rows(
    root: Path,
    *,
    max_entries: int = _INVENTORY_MAX_ENTRIES,
    excluded_roots: tuple[Path, ...] = (),
) -> list[dict[str, Any]]:
    """Observable paid target/judge work in FAILED cells (operational only).

    A failed cell (a ``<stem>.error.json``) leaves durable partial
    ``responses``/``trails`` for the calls that DID happen before the failure.
    That work cost real money, so it is accounted for operational spend under
    the distinct ``target_failed``/``judge_failed`` roles - kept out of every
    scientific result (those read only completion markers) but never erased.
    A failed provider call's bounded ``call_audit.logical_call_count`` is
    surfaced as reserved-call exposure (N/A tokens).  ``completed_attempts`` is
    deliberately not used: an experiment attempt is not a provider-call count.
    Descendant outputs in ``excluded_roots`` belong to other Jobs.
    """

    rows: list[dict[str, Any]] = []
    canonical_exclusions = _canonical_excluded_roots(excluded_roots)
    seen = 0
    stack: list[Path] = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries:
                return rows
            if entry.is_dir():
                if not derived_scan_directory_excluded(
                    entry
                ) and not _under_excluded_root(entry, canonical_exclusions):
                    stack.append(entry)
                continue
            if not entry.name.endswith(".error.json"):
                continue
            stem = entry.name[: -len(".error.json")]
            try:
                err = strict_json_loads(entry.read_text(encoding="utf-8"))
                err_sha = hashlib.sha256(entry.read_bytes()).hexdigest()
            except (OSError, ValueError):
                continue
            if not isinstance(err, dict) or err.get("status") != "error":
                continue
            try:
                usage_date = time.strftime("%Y-%m-%d", time.gmtime(entry.stat().st_mtime))
            except OSError:
                usage_date = ""
            tallies: dict[tuple[str, str, str, str], int] = {}

            def add(
                role: str,
                provider: str,
                model: str,
                category: str,
                amount: int,
                *,
                _t: dict = tallies,
            ) -> None:
                provider = canonical_provider_name(provider)
                key = (role, provider, model, category)
                _t[key] = _t.get(key, 0) + amount

            responses = directory / f"{stem}.responses.jsonl"
            if responses.is_file():
                try:
                    for line in responses.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        try:
                            record = strict_json_loads(line)
                        except ValueError:
                            continue
                        if not isinstance(record, Mapping):
                            continue
                        provider, model = _response_identity(record)
                        raw = record.get("raw")
                        raw = raw if isinstance(raw, Mapping) else {}
                        cats = _tokens_by_category(record.get("tokens"), raw.get("provider_usage"))
                        add("target_failed", provider, model, "calls", 1)
                        if not _token_usage_complete(cats):
                            add("target_failed", provider, model, "missing_tokens", 1)
                        for category, amount in cats.items():
                            add("target_failed", provider, model, category, amount)
                except OSError:
                    pass
            trails = directory / f"{stem}.trails.jsonl"
            if trails.is_file():
                try:
                    for line in trails.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        try:
                            record = strict_json_loads(line)
                        except ValueError:
                            continue
                        if not isinstance(record, Mapping):
                            continue
                        judged = _judge_row_usage(record)
                        if judged is None:
                            continue
                        provider, model, cats = judged
                        add("judge_failed", provider, model, "calls", 1)
                        if not _token_usage_complete(cats):
                            add("judge_failed", provider, model, "missing_tokens", 1)
                        for category, amount in cats.items():
                            add("judge_failed", provider, model, category, amount)
                except OSError:
                    pass
            # The failed in-flight call has no Response/trail token block, but
            # ExternalCallFailure retains a bounded per-call audit.  This is an
            # exact call exposure, unlike completed_attempts (a different unit).
            audit = err.get("call_audit")
            audit = audit if isinstance(audit, Mapping) else {}
            logical_calls = audit.get("logical_call_count")
            if (
                isinstance(logical_calls, int)
                and not isinstance(logical_calls, bool)
                and logical_calls > 0
            ):
                provider = canonical_provider_name(
                    str(audit.get("provider") or "unknown")
                )
                model = str(
                    audit.get("resolved_model")
                    or err.get("target")
                    or err.get("model_spec")
                    or "unknown"
                )
                add("reserved", provider, model, "calls", logical_calls)
                add("reserved", provider, model, "missing_tokens", logical_calls)
            now = time.time()
            rows.extend(
                {
                    "marker_sha": err_sha,
                    "role": role,
                    "provider": provider,
                    "model": model,
                    "category": category,
                    "amount": amount,
                    "run_id": str(err.get("run_id", "")),
                    "out_dir": str(directory),
                    "usage_date": usage_date,
                    "recorded_at": now,
                }
                for (role, provider, model, category), amount in sorted(tallies.items())
            )
    return rows


_USAGE_CACHE = ValidationCache(entries=32)


def collect_usage(
    root: Path, *, verify_sha: bool = False, excluded_roots: tuple[Path, ...] = (),
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Reuse unchanged output accounting; explicit full checks bypass the cache."""
    if verify_sha:
        return _collect_usage(root, verify_sha=True, excluded_roots=excluded_roots)
    key = (str(root.absolute()), tuple(str(path.absolute()) for path in excluded_roots))
    return _USAGE_CACHE.get(key, lambda: _collect_usage(root, excluded_roots=excluded_roots), trees=(root,))


def _collect_usage(
    root: Path,
    *,
    verify_sha: bool = False,
    excluded_roots: tuple[Path, ...] = (),
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """All recorded usage rows under root, with honest skip accounting.

    Completion-marker-bound rows (scientific + operational) plus failed-cell
    rows (operational spend only, distinct ``*_failed``/``reserved`` roles).
    Exact descendant outputs in ``excluded_roots`` are not attributed to this
    root's Job.
    """

    markers, stats = iter_completed_markers(
        root,
        excluded_roots=excluded_roots,
    )
    rows: list[dict[str, Any]] = []
    stats["unreadable_artifacts"] = 0
    for marker_path, doc in markers:
        try:
            rows.extend(usage_rows_from_marker(marker_path, doc, verify_sha=verify_sha))
        except (OSError, ValueError):
            stats["unreadable_artifacts"] += 1
    failed = failed_cell_usage_rows(root, excluded_roots=excluded_roots)
    stats["failed_cells"] = len({row["marker_sha"] for row in failed})
    rows.extend(failed)
    return rows, stats
