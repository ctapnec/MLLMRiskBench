"""Read-only discovery of externally managed engineering campaigns."""

from __future__ import annotations

import json
import heapq
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


_CAMPAIGN_SCHEMA = "ura-engineering-campaign/1"
_ROUTE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_CAMPAIGNS = 20
_MAX_DIRECTORY_ENTRIES = 500
_MAX_MARKER_BYTES = 64 * 1024
_MAX_EVENT_LOG_BYTES = 512 * 1024


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
            value = json.loads(line)
        except (ValueError, TypeError, RecursionError):
            malformed = True
            continue
        if isinstance(value, dict):
            parsed.append(value)
        else:
            malformed = True
    return parsed, "malformed JSON event" if malformed else None


def _phase_state(events: list[dict[str, Any]], phase: str) -> tuple[str | None, float | None]:
    starts = [
        (_timestamp(row.get("at")) or 0.0, row)
        for row in events
        if row.get("event") == "campaign_start" and row.get("task") == phase
    ]
    if not starts:
        return None, None
    latest_start = max(item[0] for item in starts)
    terminals = [
        (_timestamp(row.get("at")) or 0.0, row)
        for row in events
        if row.get("event") in {"campaign_end", "campaign_stop"}
        and row.get("task") == phase
        and (_timestamp(row.get("at")) or 0.0) >= latest_start
    ]
    if not terminals:
        return "running", None
    ended_at, terminal = max(terminals, key=lambda item: item[0])
    status = str(terminal.get("status") or "failed").lower()
    if terminal.get("event") == "campaign_end" and status in {"passed", "complete"}:
        return "complete", ended_at
    return "failed", ended_at


@dataclass(frozen=True)
class EngineeringCampaign:
    """Filesystem-backed status for a campaign not owned by this console."""

    route_id: str
    campaign_id: str
    directory: Path
    state: str
    started_at: float
    ended_at: float | None
    progress: str
    completed_tasks: int
    failed_tasks: int
    active_tasks: tuple[str, ...]
    last_detail: str
    release_commit: str
    evidence_class: str
    thesis_empirical_evidence: bool
    hosted_calls_allowed: bool
    target_call_cap: int | None
    reserved_calls: int
    hard_stop_hours: float | None
    logs: tuple[tuple[str, str, Path], ...]

    def runtime_seconds(self) -> float:
        return max(0.0, (self.ended_at or time.time()) - self.started_at)


def _load_campaign(directory: Path) -> EngineeringCampaign | None:
    marker_path = directory / "ENGINEERING_ONLY.json"
    marker_bytes, marker_error = _bounded_file(marker_path, _MAX_MARKER_BYTES)
    if marker_bytes is None or marker_error is not None:
        return None
    try:
        marker = json.loads(marker_bytes.decode("utf-8"))
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

    stage2_state, stage2_end = _phase_state(stage2, "stage2")
    bootstrap_state, bootstrap_end = _phase_state(bootstrap, "bootstrap")
    state = stage2_state or bootstrap_state or "unknown"
    ended_at = stage2_end if stage2_state is not None else bootstrap_end
    activity_error = bootstrap_error or stage2_error
    if activity_error:
        state = "unknown"
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
    if (
        state == "running"
        and hard_stop_hours is not None
        and time.time() > started_at + hard_stop_hours * 3600
    ):
        state = "orphaned"

    task_states: dict[str, str] = {}
    for row in all_events:
        event = row.get("event")
        task = str(row.get("task") or "")[:256]
        if not task or task in {"bootstrap", "stage2"}:
            continue
        if event == "task_start":
            task_states[task] = "running"
        elif event == "task_end":
            status = str(row.get("status") or "failed").lower()[:32]
            task_states[task] = status
    active_tasks = tuple(task for task, status in task_states.items() if status == "running")
    completed_tasks = sum(status != "running" for status in task_states.values())
    failed_tasks = sum(
        status not in {"running", "passed", "complete"}
        for status in task_states.values()
    )
    if state != "running":
        active_tasks = ()

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
        parts = [f"{completed_tasks} task{'s' if completed_tasks != 1 else ''} finished"]
        if failed_tasks:
            parts.append(f"{failed_tasks} failed")
        if active_tasks:
            parts.append("last recorded active: " + ", ".join(active_tasks))
    if target_call_cap is not None:
        calls = "unknown" if call_error else str(reserved_calls)
        parts.append(f"local calls reserved: {calls}/{target_call_cap}")

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
        )
        if not path.is_symlink() and path.is_file()
    )
    return EngineeringCampaign(
        route_id=directory.name,
        campaign_id=str(marker.get("campaign_id") or directory.name),
        directory=directory,
        state=state,
        started_at=started_at,
        ended_at=ended_at,
        progress="; ".join(parts),
        completed_tasks=completed_tasks,
        failed_tasks=failed_tasks,
        active_tasks=active_tasks,
        last_detail=last_detail,
        release_commit=str(marker.get("release_commit") or ""),
        evidence_class=str(marker.get("evidence_class") or "engineering"),
        thesis_empirical_evidence=False,
        hosted_calls_allowed=hosted_calls_allowed,
        target_call_cap=target_call_cap,
        reserved_calls=reserved_calls,
        hard_stop_hours=hard_stop_hours,
        logs=logs,
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


def scan_engineering_campaigns(
    results_root: Path,
) -> tuple[list[EngineeringCampaign], str]:
    """Load a bounded recent-campaign index and return any omission notice."""

    root = _engineering_root(results_root)
    if root is None:
        return [], ""
    candidates: list[tuple[int, Path]] = []
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
                candidates.append((metadata.st_mtime_ns, candidate))
    except OSError:
        return [], "External campaign directory could not be scanned."

    newest = heapq.nlargest(_MAX_CAMPAIGNS, candidates, key=lambda item: item[0])
    campaigns = []
    seen_resolved: set[Path] = set()
    for _mtime, candidate in newest:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved in seen_resolved:
            continue
        seen_resolved.add(resolved)
        campaign = load_engineering_campaign(results_root, candidate.name)
        if campaign is not None:
            campaigns.append(campaign)
    notices = []
    omitted = max(0, len(candidates) - len(newest))
    if omitted:
        notices.append(
            f"Showing the {_MAX_CAMPAIGNS} most recently created retained engineering "
            f"campaigns; {omitted} additional scanned director"
            f"{'y was' if omitted == 1 else 'ies were'} omitted."
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
