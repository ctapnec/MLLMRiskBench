"""Operational registrations for externally produced analysis reports.

Rig Web uses this generic, create-only boundary to render exact Level-1,
Level-2, and campaign-terminal reports produced outside the console. A
registration conveys display ownership only. It cannot grant thesis-evidence
authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from ura.strict_json import strict_json_loads

from .external_measured import _write_create_only
from .reports import _validate_report_document


REGISTRY_DIRECTORY = "external-analysis-jobs"
REGISTRATION_SCHEMA = "ura-external-analysis-registration/1"

_REGISTRATION_FILE = "registration.json"
_SAFE_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_REPORT_BYTES = 64 * 1024 * 1024
_MAX_REPORTS = 128
_MAX_LABEL = 256
_FIELDS = {
    "schema",
    "job_id",
    "authority",
    "thesis_empirical_evidence",
    "work_label",
    "completion_status",
    "explicit_limitations",
    "analysis_root",
    "reports",
}
_REPORT_FIELDS = {"path", "sha256", "bytes", "kind", "display_name"}


@dataclass(frozen=True)
class ExternalAnalysisReportSpec:
    """One report supplied to the generic registration publisher."""

    path: Path
    kind: str
    display_name: str


@dataclass(frozen=True)
class ExternalAnalysisReport:
    """One exact report accepted from a generic registration."""

    path: Path
    artifact_relative: str
    display_name: str
    kind: str
    sha256: str
    bytes: int


@dataclass(frozen=True)
class ExternalAnalysisRegistration:
    """Validated operational registration for one external analysis job."""

    job_id: str
    analysis_root: Path
    artifact_relative: str
    work_label: str
    completion_status: str
    explicit_limitations: tuple[tuple[str, str], ...]
    reports: tuple[ExternalAnalysisReport, ...]


def _regular_bytes(path: Path, *, maximum: int) -> bytes:
    if path.is_symlink():
        raise ValueError("symlinked external analysis file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > maximum
        ):
            raise ValueError("invalid external analysis file")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            if not block:
                raise ValueError("short external analysis file")
            chunks.append(block)
            remaining -= len(block)
        after = os.fstat(fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("external analysis file changed during read")
        payload = b"".join(chunks)
    finally:
        os.close(fd)
    named = path.lstat()
    identity = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
    )
    if identity != (
        named.st_dev,
        named.st_ino,
        named.st_mode,
        named.st_nlink,
        named.st_size,
        named.st_mtime_ns,
    ):
        raise ValueError("external analysis file name changed during read")
    return payload


def _relative_path(value: object, *, label: str) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value:
        raise ValueError(f"invalid {label}")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ValueError(f"invalid {label}")
    return relative


def _beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return path != root
    except ValueError:
        return False


def _resolved_relative(
    results_root: Path,
    value: object,
    *,
    label: str,
) -> tuple[Path, str]:
    relative = _relative_path(value, label=label)
    candidate = results_root / Path(*relative.parts)
    path = candidate.resolve(strict=True)
    if path != candidate or not _beneath(path, results_root):
        raise ValueError(f"{label} escapes results root")
    return path, relative.as_posix()


def _label(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_LABEL
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"invalid external analysis {field}")
    return value


def _limitations(value: object, status: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > 128:
        raise ValueError("invalid external analysis limitations")
    rows = []
    for name, detail in value.items():
        rows.append(
            (
                _label(name, field="limitation name"),
                _label(detail, field="limitation detail"),
            )
        )
    if (status == "complete") != (not rows):
        raise ValueError("external analysis status and limitations differ")
    return tuple(sorted(rows))


def _validated_report(
    results_root: Path,
    analysis_root: Path,
    raw: Mapping[str, object],
) -> ExternalAnalysisReport:
    if set(raw) != _REPORT_FIELDS:
        raise ValueError("external analysis report fields differ")
    kind = raw.get("kind")
    if kind not in {"level1", "level2", "terminal_inventory"}:
        raise ValueError("unsupported external analysis report kind")
    path, relative = _resolved_relative(
        results_root,
        raw.get("path"),
        label="external analysis report path",
    )
    if not _beneath(path, analysis_root):
        raise ValueError("external analysis report escapes its analysis root")
    payload = _regular_bytes(path, maximum=_MAX_REPORT_BYTES)
    if (
        raw.get("bytes") != len(payload)
        or _HEX64.fullmatch(str(raw.get("sha256"))) is None
        or raw.get("sha256") != hashlib.sha256(payload).hexdigest()
    ):
        raise ValueError("external analysis report identity differs")
    try:
        document = strict_json_loads(payload.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("external analysis report is not strict JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("external analysis report is not an object")
    _validate_report_document(str(kind), document)
    return ExternalAnalysisReport(
        path=path,
        artifact_relative=relative,
        display_name=_label(raw.get("display_name"), field="report display name"),
        kind=str(kind),
        sha256=str(raw["sha256"]),
        bytes=len(payload),
    )


def load_external_analysis_report(
    report: ExternalAnalysisReport,
) -> dict[str, object] | None:
    """Revalidate one registered report immediately before rendering it."""

    try:
        payload = _regular_bytes(report.path, maximum=_MAX_REPORT_BYTES)
        if len(payload) != report.bytes or hashlib.sha256(payload).hexdigest() != report.sha256:
            return None
        document = strict_json_loads(payload.decode("utf-8"))
        if not isinstance(document, dict):
            return None
        _validate_report_document(report.kind, document)
        return document
    except (OSError, TypeError, UnicodeError, ValueError, RecursionError):
        return None


def _registry_root(results_root: Path, *, create: bool) -> Path:
    candidate = results_root / REGISTRY_DIRECTORY
    if create:
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            pass
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
    if (
        candidate.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != candidate
        or resolved.parent != results_root
    ):
        raise ValueError("invalid external analysis registry")
    return resolved


def _job_directory(registry_root: Path, job_id: str, *, create: bool) -> Path:
    if _SAFE_JOB_ID.fullmatch(job_id) is None:
        raise ValueError("invalid external analysis job id")
    candidate = registry_root / job_id
    if create:
        candidate.mkdir(mode=0o700)
    metadata = candidate.lstat()
    resolved = candidate.resolve(strict=True)
    if (
        candidate.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or resolved != candidate
        or resolved.parent != registry_root
    ):
        raise ValueError("invalid external analysis job directory")
    return resolved


def load_external_analysis_registration(
    results_root: Path,
    job_id: str,
) -> ExternalAnalysisRegistration | None:
    """Load one exact generic registration, or fail closed with ``None``."""

    try:
        results = Path(results_root).resolve(strict=True)
        registry = _registry_root(results, create=False)
        job_directory = _job_directory(registry, job_id, create=False)
        registration_path = job_directory / _REGISTRATION_FILE
        payload = _regular_bytes(
            registration_path,
            maximum=_MAX_REGISTRATION_BYTES,
        )
        document = strict_json_loads(payload.decode("utf-8"))
        if (
            not isinstance(document, dict)
            or set(document) != _FIELDS
            or document.get("schema") != REGISTRATION_SCHEMA
            or document.get("job_id") != job_id
            or document.get("authority") != "external_operational_non_thesis"
            or document.get("thesis_empirical_evidence") is not False
        ):
            return None
        work_label = _label(document.get("work_label"), field="work label")
        status = document.get("completion_status")
        if status not in {"complete", "complete_with_explicit_limitations"}:
            return None
        limitations = _limitations(document.get("explicit_limitations"), str(status))
        analysis_root, analysis_relative = _resolved_relative(
            results,
            document.get("analysis_root"),
            label="external analysis root",
        )
        if not analysis_root.is_dir():
            return None
        raw_reports = document.get("reports")
        if (
            not isinstance(raw_reports, list)
            or not 1 <= len(raw_reports) <= _MAX_REPORTS
            or any(not isinstance(report, Mapping) for report in raw_reports)
        ):
            return None
        reports = tuple(_validated_report(results, analysis_root, report) for report in raw_reports)
        if (
            len({report.path for report in reports}) != len(reports)
            or sum(report.kind == "terminal_inventory" for report in reports) > 1
        ):
            return None
        return ExternalAnalysisRegistration(
            job_id=job_id,
            analysis_root=analysis_root,
            artifact_relative=analysis_relative,
            work_label=work_label,
            completion_status=str(status),
            explicit_limitations=limitations,
            reports=reports,
        )
    except (OSError, TypeError, ValueError, RecursionError):
        return None


def publish_external_analysis_registration(
    results_root: Path,
    *,
    job_id: str,
    analysis_root: Path,
    work_label: str,
    completion_status: str,
    explicit_limitations: Mapping[str, str],
    reports: Sequence[ExternalAnalysisReportSpec],
) -> Path:
    """Create one generic registration after validating every report byte."""

    results = Path(results_root).resolve(strict=True)
    analysis = Path(analysis_root).resolve(strict=True)
    if not analysis.is_dir() or not _beneath(analysis, results):
        raise ValueError("external analysis root is outside results root")
    if completion_status not in {"complete", "complete_with_explicit_limitations"}:
        raise ValueError("invalid external analysis completion status")
    normalized_limitations = _limitations(explicit_limitations, completion_status)
    normalized_label = _label(work_label, field="work label")
    if not 1 <= len(reports) <= _MAX_REPORTS:
        raise ValueError("invalid external analysis report count")
    rows = []
    seen: set[Path] = set()
    terminal_inventory_seen = False
    for report in reports:
        path = Path(report.path).resolve(strict=True)
        if (
            path in seen
            or (report.kind == "terminal_inventory" and terminal_inventory_seen)
            or not _beneath(path, analysis)
        ):
            raise ValueError("external analysis report ownership differs")
        seen.add(path)
        terminal_inventory_seen = (
            terminal_inventory_seen or report.kind == "terminal_inventory"
        )
        payload = _regular_bytes(path, maximum=_MAX_REPORT_BYTES)
        relative = path.relative_to(results).as_posix()
        row: dict[str, object] = {
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
            "kind": report.kind,
            "display_name": report.display_name,
        }
        _validated_report(results, analysis, row)
        rows.append(row)
    registration = {
        "schema": REGISTRATION_SCHEMA,
        "job_id": job_id,
        "authority": "external_operational_non_thesis",
        "thesis_empirical_evidence": False,
        "work_label": normalized_label,
        "completion_status": completion_status,
        "explicit_limitations": dict(normalized_limitations),
        "analysis_root": analysis.relative_to(results).as_posix(),
        "reports": rows,
    }
    payload = (
        json.dumps(
            registration,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_REGISTRATION_BYTES:
        raise ValueError("external analysis registration is too large")
    registry = _registry_root(results, create=True)
    job_directory = _job_directory(registry, job_id, create=True)
    path = job_directory / _REGISTRATION_FILE
    try:
        return _write_create_only(path, registration)
    except Exception:
        # Retry is safe after an interrupted private-file publication. Remove
        # only the exact directory created for this attempt, and only when it
        # is still empty. Any foreign or partial evidence remains untouched.
        try:
            if (
                not job_directory.is_symlink()
                and job_directory.resolve(strict=True).parent == registry
            ):
                job_directory.rmdir()
        except OSError:
            pass
        raise
