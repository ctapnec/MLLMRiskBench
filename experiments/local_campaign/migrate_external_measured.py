"""Migrate immutable local-campaign measured-job registrations to v2.

The deployed pre-v2 controllers use a Gate-5-specific field.  This task-owned
adapter copies those operational identities into Rig Web's generic v2 registry
without modifying or deleting the original records.
"""

from __future__ import annotations

import argparse
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ura.strict_json import strict_json_loads

from experiments.rig_web_app.external_measured import (
    REGISTRY_DIRECTORY as V2_DIRECTORY,
    ExternalMeasuredJob,
    _strict_epoch,
    _validate_identity,
    load_external_measured_job,
    register_external_measured_start,
    register_external_measured_terminal,
)


_V1_DIRECTORY = "external-measured-jobs"
_V1_SCHEMA = "ura-external-measured-job/1"
_TERMINAL_SCHEMA = "ura-external-measured-job-terminal/1"
_MAX_JOBS = 2_000
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_TERMINAL_BYTES = 16 * 1024
_REGISTRATION_FIELDS = {
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
}
_TERMINAL_FIELDS = {
    "schema",
    "event",
    "job_id",
    "ended_at",
    "state",
    "exit_code",
}


@dataclass(frozen=True)
class _V1Start:
    job_id: str
    command: str
    run_kind: str
    argv: tuple[str, ...]
    argv_sha256: str
    out_dir: Path
    expected_commit: str
    framework_lock_id: str
    admission_sha256: str
    tmux_socket: str
    tmux_session: str
    started_at: float


@dataclass(frozen=True)
class _MigrationRecord:
    start: _V1Start
    terminal: tuple[float, int] | None


def _regular_json(path: Path, *, maximum: int) -> dict[str, Any] | None:
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink():
        raise ValueError(f"symlinked v1 registration file: {path}")
    with path.open("rb") as handle:
        before = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError(f"invalid v1 registration file: {path}")
        payload = handle.read(maximum + 1)
        after = os.fstat(handle.fileno())
    named = path.lstat()
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    if (
        len(payload) != before.st_size
        or identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or identity != (named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns)
        or named.st_nlink != 1
    ):
        raise ValueError(f"v1 registration file changed during read: {path}")
    document = strict_json_loads(payload.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"v1 registration is not an object: {path}")
    return document


def _v1_root(results: Path) -> Path | None:
    candidate = results / _V1_DIRECTORY
    if not candidate.exists() and not candidate.is_symlink():
        return None
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
    if (
        candidate.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != candidate
        or resolved.parent != results
    ):
        raise ValueError("invalid v1 external measured registry")
    return resolved


def _terminal(
    document: Mapping[str, Any] | None,
    job_id: str,
    *,
    started_at: float,
) -> tuple[float, int] | None:
    if document is None:
        return None
    exit_code = document.get("exit_code")
    try:
        ended_at = _strict_epoch(document.get("ended_at"), "ended_at")
    except ValueError as exc:
        raise ValueError(f"invalid v1 terminal registration: {job_id}") from exc
    if (
        set(document) != _TERMINAL_FIELDS
        or document.get("schema") != _TERMINAL_SCHEMA
        or document.get("event") != "terminal"
        or document.get("job_id") != job_id
        or isinstance(exit_code, bool)
        or not isinstance(exit_code, int)
        or not 0 <= exit_code <= 255
        or document.get("state") != ("complete" if exit_code == 0 else "failed")
        or ended_at < started_at
    ):
        raise ValueError(f"invalid v1 terminal registration: {job_id}")
    return ended_at, exit_code


def _registration(
    document: Mapping[str, Any],
    job_id: str,
    *,
    results_root: Path,
) -> _V1Start:
    tmux = document.get("tmux")
    if (
        set(document) != _REGISTRATION_FIELDS
        or document.get("schema") != _V1_SCHEMA
        or document.get("event") != "start"
        or document.get("job_id") != job_id
        or document.get("command") != "run_matrix"
        or document.get("run_kind") != "measured"
        or document.get("registration_authority") != "operational_only"
        or document.get("thesis_empirical_evidence") is not False
        or not isinstance(tmux, dict)
        or set(tmux) != {"launcher", "socket", "session"}
        or tmux.get("launcher") != "tmux"
    ):
        raise ValueError(f"invalid v1 start registration: {job_id}")
    out_dir = document.get("out_dir")
    if not isinstance(out_dir, str):
        raise ValueError(f"invalid v1 start registration: {job_id}")
    try:
        argv, argv_sha256, resolved_out, _artifact_relative = _validate_identity(
            job_id=job_id,
            command=document.get("command"),
            declared_kind=document.get("run_kind"),
            argv=document.get("sanitized_argv"),
            out_dir=Path(out_dir),
            results_root=results_root,
            expected_commit=document.get("expected_commit"),
            framework_lock_id=document.get("framework_lock_id"),
            admission_sha256=document.get("gate5_sha256"),
            tmux_socket=tmux.get("socket"),
            tmux_session=tmux.get("session"),
        )
        started_at = _strict_epoch(document.get("started_at"), "started_at")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid v1 start registration: {job_id}") from exc
    if document.get("argv_sha256") != argv_sha256:
        raise ValueError(f"invalid v1 start registration: {job_id}")
    return _V1Start(
        job_id=job_id,
        command="run_matrix",
        run_kind="measured",
        argv=argv,
        argv_sha256=argv_sha256,
        out_dir=resolved_out,
        expected_commit=document["expected_commit"],
        framework_lock_id=document["framework_lock_id"],
        admission_sha256=document["gate5_sha256"],
        tmux_socket=tmux["socket"],
        tmux_session=tmux["session"],
        started_at=started_at,
    )


def _start_matches(
    existing: ExternalMeasuredJob,
    start: _V1Start,
) -> bool:
    return (
        existing.job_id == start.job_id
        and existing.command == start.command
        and existing.run_kind == start.run_kind
        and existing.argv == start.argv
        and existing.argv_sha256 == start.argv_sha256
        and existing.out_dir == start.out_dir
        and existing.expected_commit == start.expected_commit
        and existing.framework_lock_id == start.framework_lock_id
        and existing.admission_sha256 == start.admission_sha256
        and existing.tmux_socket == start.tmux_socket
        and existing.tmux_session == start.tmux_session
        and existing.started_at == start.started_at
    )


def _terminal_matches(
    existing: ExternalMeasuredJob,
    terminal: tuple[float, int] | None,
) -> bool:
    if terminal is None:
        return existing.ended_at is None and existing.exit_code is None
    return existing.ended_at == terminal[0] and existing.exit_code == terminal[1]


def _v2_root(results: Path) -> Path | None:
    candidate = results / V2_DIRECTORY
    if not candidate.exists() and not candidate.is_symlink():
        return None
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
    if (
        candidate.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != candidate
        or resolved.parent != results
    ):
        raise ValueError("invalid v2 external measured registry")
    return resolved


def _destination_exists(root: Path | None, job_id: str) -> bool:
    if root is None:
        return False
    candidate = root / job_id
    return candidate.exists() or candidate.is_symlink()


def migrate_external_measured_v1(results_root: Path) -> tuple[int, int]:
    """Copy every exact v1 record into the generic v2 registry."""

    results = Path(results_root).resolve(strict=True)
    root = _v1_root(results)
    if root is None:
        return 0, 0
    candidates = sorted(root.iterdir(), key=lambda path: path.name)
    if len(candidates) > _MAX_JOBS:
        raise ValueError("v1 external measured registry exceeds bounded migration cap")
    records: list[_MigrationRecord] = []
    for candidate in candidates:
        metadata = candidate.lstat()
        directory = candidate.resolve(strict=True)
        if (
            candidate.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or directory != candidate
            or directory.parent != root
        ):
            raise ValueError(f"invalid v1 job directory: {candidate}")
        raw = _regular_json(
            directory / "registration.json",
            maximum=_MAX_REGISTRATION_BYTES,
        )
        if raw is None:
            raise ValueError(f"missing v1 start registration: {candidate.name}")
        start = _registration(raw, candidate.name, results_root=results)
        terminal = _terminal(
            _regular_json(
                directory / "terminal.json",
                maximum=_MAX_TERMINAL_BYTES,
            ),
            candidate.name,
            started_at=start.started_at,
        )
        records.append(_MigrationRecord(start=start, terminal=terminal))

    # Validate the complete source batch and every destination before any
    # create-only publication. A known-bad later row therefore cannot leave a
    # migrated prefix, and a differing start is never terminalized.
    v2_root = _v2_root(results)
    initially_existing: dict[str, bool] = {}
    for record in records:
        current = load_external_measured_job(
            results,
            record.start.job_id,
            probe_session=False,
        )
        exists = _destination_exists(v2_root, record.start.job_id)
        if current is None:
            if exists:
                raise ValueError(
                    f"invalid v2 migration collision: {record.start.job_id}"
                )
            initially_existing[record.start.job_id] = False
            continue
        if not _start_matches(current, record.start):
            raise ValueError(f"v2 migration collision differs: {record.start.job_id}")
        if current.ended_at is not None and not _terminal_matches(
            current,
            record.terminal,
        ):
            raise ValueError(f"v2 migration collision differs: {record.start.job_id}")
        if record.terminal is None and not _terminal_matches(current, None):
            raise ValueError(f"v2 migration collision differs: {record.start.job_id}")
        initially_existing[record.start.job_id] = True

    migrated = 0
    existing_count = 0
    for record in records:
        start = record.start
        current = load_external_measured_job(
            results,
            start.job_id,
            probe_session=False,
        )
        if not initially_existing[start.job_id]:
            if current is not None:
                raise ValueError(f"v2 migration destination changed: {start.job_id}")
            register_external_measured_start(
                results,
                job_id=start.job_id,
                command=start.command,
                run_kind_name=start.run_kind,
                sanitized_argv=start.argv,
                out_dir=start.out_dir,
                expected_commit=start.expected_commit,
                framework_lock_id=start.framework_lock_id,
                admission_sha256=start.admission_sha256,
                tmux_socket=start.tmux_socket,
                tmux_session=start.tmux_session,
                started_at=start.started_at,
            )
            if record.terminal is not None:
                register_external_measured_terminal(
                    results,
                    job_id=start.job_id,
                    exit_code=record.terminal[1],
                    ended_at=record.terminal[0],
                )
            migrated += 1
            continue
        if current is None or not _start_matches(current, start):
            raise ValueError(f"v2 migration destination changed: {start.job_id}")
        if record.terminal is not None and current.ended_at is None:
            register_external_measured_terminal(
                results,
                job_id=start.job_id,
                exit_code=record.terminal[1],
                ended_at=record.terminal[0],
            )
            current = load_external_measured_job(
                results,
                start.job_id,
                probe_session=False,
            )
        if (
            current is None
            or not _start_matches(current, start)
            or not _terminal_matches(current, record.terminal)
        ):
            raise ValueError(f"v2 migration collision differs: {start.job_id}")
        existing_count += 1
    return migrated, existing_count


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Migrate local-campaign external measured jobs from v1 to v2"
    )
    parser.add_argument("--results-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    migrated, existing = migrate_external_measured_v1(args.results_root)
    print(f"migrated={migrated} existing={existing}")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
