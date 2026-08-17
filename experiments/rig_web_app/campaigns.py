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
_MAX_MODEL_EXECUTION_COUNT = 1_000_000
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
        return "reported running"
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
    if (
        state == "running"
        and hard_stop_hours is not None
        and time.time() > started_at + hard_stop_hours * 3600
    ):
        state = "orphaned"
        display_state = "orphaned"

    task_states: dict[str, str] = {}
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
        elif event in {"task_end", "task_skip"}:
            status = str(row.get("status") or "failed").strip().lower()[:32]
            task_states[task] = status
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
    return EngineeringCampaign(
        route_id=directory.name,
        campaign_id=str(marker.get("campaign_id") or directory.name),
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
