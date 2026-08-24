"""Explicit Jobs/Stats registration for tmux-owned campaign controllers.

The rig console discovers external engineering work only through its retained
``ura-engineering-campaign/1`` marker and task-event contract. These helpers let
the versioned local-campaign controllers emit that contract without giving the
console process ownership of their tmux sessions.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Sequence


_CAMPAIGN_SCHEMA = "ura-engineering-campaign/1"
_ROUTE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TASK = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_EVIDENCE_CLASS = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_NAMED_SESSION_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TERMINAL_EVENTS = {"campaign_end", "campaign_stop"}
_TASK_EVENTS = {"task_start", "task_end", "task_skip"}
_CONTROLLER_TASK = "controller"
_FileIdentity = tuple[int, int]


class ConsoleEventError(ValueError):
    """A controller attempted to emit an unsafe or inconsistent event."""


def _canonical_line(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _utc_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not isinstance(value, str) or not value:
        raise ConsoleEventError("event timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConsoleEventError("event timestamp is not ISO-8601") from exc
    if parsed.tzinfo is None or not math.isfinite(parsed.timestamp()):
        raise ConsoleEventError("event timestamp must include a finite timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _regular_directory(path: Path, label: str) -> Path:
    if path.is_symlink():
        raise ConsoleEventError(f"{label} must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise ConsoleEventError(f"{label} is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConsoleEventError(f"{label} is not a directory")
    return resolved


def _control_root(work_root: Path, control_root: Path) -> Path:
    work = _regular_directory(work_root, "work root")
    runs = _regular_directory(work / "runs", "runs root")
    engineering = _regular_directory(runs / "engineering", "engineering root")
    root = _regular_directory(control_root, "control root")
    if engineering.parent != runs or root.parent != engineering:
        raise ConsoleEventError("control root is not a direct engineering campaign")
    if not _ROUTE_ID.fullmatch(root.name):
        raise ConsoleEventError("control root name is not a safe route")
    return root


def _identity(metadata: os.stat_result) -> _FileIdentity:
    return metadata.st_dev, metadata.st_ino


def _require_single_link(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise ConsoleEventError(f"{label} is not a regular file")
    if metadata.st_nlink != 1:
        raise ConsoleEventError(f"{label} must have exactly one hard link")


def _remove_created_file(path: Path, identity: _FileIdentity, label: str) -> None:
    """Remove only the exact create-only file produced by this invocation."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ConsoleEventError(f"{label} recovery could not inspect its output") from exc
    if not stat.S_ISREG(metadata.st_mode) or _identity(metadata) != identity:
        raise ConsoleEventError(f"{label} recovery refused a replaced output")
    try:
        path.unlink()
    except OSError as exc:
        raise ConsoleEventError(f"{label} recovery could not remove its output") from exc


def _write_create_only(path: Path, payload: bytes) -> _FileIdentity:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise ConsoleEventError(f"create-only output already exists or is unsafe: {path}") from exc
    identity: _FileIdentity | None = None
    try:
        metadata = os.fstat(descriptor)
        identity = _identity(metadata)
        _require_single_link(metadata, "create-only output")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        final_metadata = os.fstat(descriptor)
        _require_single_link(final_metadata, "create-only output")
        if _identity(final_metadata) != identity:
            raise ConsoleEventError("create-only output identity changed while writing")
    except BaseException as exc:
        os.close(descriptor)
        if identity is not None:
            try:
                _remove_created_file(path, identity, "create-only output")
            except ConsoleEventError as recovery_exc:
                raise recovery_exc from exc
        raise
    os.close(descriptor)
    return identity


def _read_marker(path: Path) -> object:
    if path.is_symlink():
        raise ConsoleEventError("campaign marker must not be a symlink")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ConsoleEventError("campaign marker is unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        _require_single_link(metadata, "campaign marker")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            payload = handle.read()
            _require_single_link(os.fstat(handle.fileno()), "campaign marker")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ConsoleEventError("campaign marker is unreadable") from exc


def _append(path: Path, payload: bytes) -> None:
    if path.is_symlink():
        raise ConsoleEventError("task log must not be a symlink")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise ConsoleEventError("task log is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        _require_single_link(metadata, "task log")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view) :]
        os.fsync(descriptor)
        _require_single_link(os.fstat(descriptor), "task log")
    finally:
        os.close(descriptor)


def start_campaign(
    *,
    work_root: Path,
    control_root: Path,
    campaign_id: str,
    release_commit: str,
    evidence_class: str,
    hard_stop_hours: int,
    planned_tasks: Sequence[str],
    tmux_socket: str,
    tmux_session: str,
    at: str | None = None,
    initial_running_tasks: Sequence[str] = (),
) -> None:
    root = _control_root(work_root, control_root)
    if campaign_id != root.name or not _ROUTE_ID.fullmatch(campaign_id):
        raise ConsoleEventError("campaign ID must equal the control-root route")
    if not _HEX40.fullmatch(release_commit):
        raise ConsoleEventError("release commit must be 40 lowercase hex characters")
    if not _EVIDENCE_CLASS.fullmatch(evidence_class):
        raise ConsoleEventError("invalid evidence class")
    if isinstance(hard_stop_hours, bool) or not 1 <= hard_stop_hours <= 24 * 365:
        raise ConsoleEventError("hard stop must be between 1 and 8760 hours")
    if (
        not isinstance(tmux_socket, str)
        or not isinstance(tmux_session, str)
        or _NAMED_SESSION_TOKEN.fullmatch(tmux_socket) is None
        or _NAMED_SESSION_TOKEN.fullmatch(tmux_session) is None
    ):
        raise ConsoleEventError("tmux socket and session must be safe named-session tokens")
    tasks = tuple(planned_tasks)
    if (
        not tasks
        or len(tasks) != len(set(tasks))
        or any(not _TASK.fullmatch(task) or task in {"bootstrap", "stage2"} for task in tasks)
    ):
        raise ConsoleEventError("planned tasks must be non-empty, safe, and unique")
    running_tasks = tuple(initial_running_tasks)
    if (
        len(running_tasks) != len(set(running_tasks))
        or any(task not in tasks for task in running_tasks)
    ):
        raise ConsoleEventError("initial running tasks must be unique planned tasks")
    timestamp = _utc_timestamp(at)
    marker = {
        "schema": _CAMPAIGN_SCHEMA,
        "campaign_id": campaign_id,
        "release_commit": release_commit,
        "evidence_class": evidence_class,
        "thesis_empirical_evidence": False,
        "hosted_calls_allowed": False,
        "hard_stop_hours": hard_stop_hours,
        "started_at": timestamp,
        "planned_tasks": list(tasks),
        "tmux_socket": tmux_socket,
        "tmux_session": tmux_session,
    }
    # Publish the marker last. The console ignores an event log without its
    # marker, whereas publishing a marker before its required log would expose
    # a transient, false "unknown" campaign.
    task_log = root / "task-log.jsonl"
    initial_events = [
        {
            "at": timestamp,
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
            "detail": "local_campaign_controller",
        },
        *(
            {
                "at": timestamp,
                "event": "task_start",
                "task": task,
                "status": "running",
                "detail": "child_controller_started",
            }
            for task in running_tasks
        ),
    ]
    task_log_identity = _write_create_only(
        task_log,
        b"".join(_canonical_line(event) for event in initial_events),
    )
    try:
        _write_create_only(root / "ENGINEERING_ONLY.json", _canonical_line(marker))
    except BaseException as exc:
        try:
            _remove_created_file(task_log, task_log_identity, "campaign registration")
        except ConsoleEventError as recovery_exc:
            raise recovery_exc from exc
        raise


def _append_events(
    *,
    work_root: Path,
    control_root: Path,
    events: Sequence[tuple[str, str, str, str]],
    at: str | None = None,
) -> None:
    root = _control_root(work_root, control_root)
    rows = tuple(events)
    if not rows:
        raise ConsoleEventError("at least one campaign event is required")
    allowed_statuses = {
        "task_start": {"running"},
        "task_end": {"passed", "failed"},
        "task_skip": {"skipped"},
        "campaign_end": {"passed", "failed", "blocked"},
        "campaign_stop": {"stopped"},
    }
    marker = _read_marker(root / "ENGINEERING_ONLY.json")
    if (
        not isinstance(marker, dict)
        or marker.get("schema") != _CAMPAIGN_SCHEMA
        or marker.get("campaign_id") != root.name
        or marker.get("thesis_empirical_evidence") is not False
        or marker.get("hosted_calls_allowed") is not False
    ):
        raise ConsoleEventError("campaign marker does not own this control root")
    planned_tasks = marker.get("planned_tasks")
    timestamp = _utc_timestamp(at)
    payload = bytearray()
    for event, task, status, detail in rows:
        if event not in _TASK_EVENTS | _TERMINAL_EVENTS:
            raise ConsoleEventError("unsupported campaign event")
        if not _TASK.fullmatch(task):
            raise ConsoleEventError("invalid event task")
        if event in _TERMINAL_EVENTS and task != "bootstrap":
            raise ConsoleEventError("campaign terminal must target bootstrap")
        if event in _TASK_EVENTS and task in {"bootstrap", "stage2"}:
            raise ConsoleEventError("task event uses a reserved phase name")
        normalized_status = status.strip().lower()
        if not _TASK.fullmatch(normalized_status):
            raise ConsoleEventError("invalid event status")
        if normalized_status not in allowed_statuses[event]:
            raise ConsoleEventError("event status does not match its lifecycle event")
        if not isinstance(detail, str) or len(detail) > 1000:
            raise ConsoleEventError("event detail exceeds 1000 characters")
        if (
            event in _TASK_EVENTS
            and (
                not isinstance(planned_tasks, list)
                or task not in planned_tasks
                or any(not isinstance(item, str) for item in planned_tasks)
            )
        ):
            raise ConsoleEventError("task event is not in the declared campaign plan")
        payload.extend(
            _canonical_line(
                {
                    "at": timestamp,
                    "event": event,
                    "task": task,
                    "status": normalized_status,
                    "detail": detail,
                }
            )
        )
    _append(
        root / "task-log.jsonl",
        bytes(payload),
    )


def append_event(
    *,
    work_root: Path,
    control_root: Path,
    event: str,
    task: str,
    status: str,
    detail: str,
    at: str | None = None,
) -> None:
    _append_events(
        work_root=work_root,
        control_root=control_root,
        events=((event, task, status, detail),),
        at=at,
    )


def start_child_controller(
    *,
    work_root: Path,
    control_root: Path,
    campaign_id: str,
    release_commit: str,
    evidence_class: str,
    hard_stop_hours: int,
    tmux_socket: str,
    tmux_session: str,
    at: str | None = None,
) -> None:
    """Register an independently launched child under the normal Jobs contract."""

    start_campaign(
        work_root=work_root,
        control_root=control_root,
        campaign_id=campaign_id,
        release_commit=release_commit,
        evidence_class=evidence_class,
        hard_stop_hours=hard_stop_hours,
        planned_tasks=(_CONTROLLER_TASK,),
        tmux_socket=tmux_socket,
        tmux_session=tmux_session,
        at=at,
        initial_running_tasks=(_CONTROLLER_TASK,),
    )


def finish_child_controller(
    *,
    work_root: Path,
    control_root: Path,
    exit_code: int,
    at: str | None = None,
) -> None:
    """Publish task and campaign terminals for a registered child controller."""

    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or not 0 <= exit_code <= 255:
        raise ConsoleEventError("controller exit code must be between 0 and 255")
    status = "passed" if exit_code == 0 else "failed"
    detail = f"child_controller_exit_{exit_code}"
    _append_events(
        work_root=work_root,
        control_root=control_root,
        events=(
            ("task_end", _CONTROLLER_TASK, status, detail),
            ("campaign_end", "bootstrap", status, detail),
        ),
        at=at,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    start = subparsers.add_parser("start")
    start.add_argument("--work-root", type=Path, required=True)
    start.add_argument("--control-root", type=Path, required=True)
    start.add_argument("--campaign-id", required=True)
    start.add_argument("--release-commit", required=True)
    start.add_argument("--evidence-class", required=True)
    start.add_argument("--hard-stop-hours", type=int, required=True)
    start.add_argument("--planned-task", action="append", default=[], required=True)
    start.add_argument("--tmux-socket", required=True)
    start.add_argument("--tmux-session", required=True)
    start.add_argument("--at")
    child_start = subparsers.add_parser("child-start")
    child_start.add_argument("--work-root", type=Path, required=True)
    child_start.add_argument("--control-root", type=Path, required=True)
    child_start.add_argument("--campaign-id", required=True)
    child_start.add_argument("--release-commit", required=True)
    child_start.add_argument("--evidence-class", required=True)
    child_start.add_argument("--hard-stop-hours", type=int, required=True)
    child_start.add_argument("--tmux-socket", required=True)
    child_start.add_argument("--tmux-session", required=True)
    child_start.add_argument("--at")
    child_finish = subparsers.add_parser("child-finish")
    child_finish.add_argument("--work-root", type=Path, required=True)
    child_finish.add_argument("--control-root", type=Path, required=True)
    child_finish.add_argument("--exit-code", type=int, required=True)
    child_finish.add_argument("--at")
    event = subparsers.add_parser("event")
    event.add_argument("--work-root", type=Path, required=True)
    event.add_argument("--control-root", type=Path, required=True)
    event.add_argument("--event", choices=sorted(_TASK_EVENTS | _TERMINAL_EVENTS), required=True)
    event.add_argument("--task", required=True)
    event.add_argument("--status", required=True)
    event.add_argument("--detail", default="")
    event.add_argument("--at")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "start":
        start_campaign(
            work_root=args.work_root,
            control_root=args.control_root,
            campaign_id=args.campaign_id,
            release_commit=args.release_commit,
            evidence_class=args.evidence_class,
            hard_stop_hours=args.hard_stop_hours,
            planned_tasks=args.planned_task,
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            at=args.at,
        )
    elif args.action == "child-start":
        start_child_controller(
            work_root=args.work_root,
            control_root=args.control_root,
            campaign_id=args.campaign_id,
            release_commit=args.release_commit,
            evidence_class=args.evidence_class,
            hard_stop_hours=args.hard_stop_hours,
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            at=args.at,
        )
    elif args.action == "child-finish":
        finish_child_controller(
            work_root=args.work_root,
            control_root=args.control_root,
            exit_code=args.exit_code,
            at=args.at,
        )
    else:
        append_event(
            work_root=args.work_root,
            control_root=args.control_root,
            event=args.event,
            task=args.task,
            status=args.status,
            detail=args.detail,
            at=args.at,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
