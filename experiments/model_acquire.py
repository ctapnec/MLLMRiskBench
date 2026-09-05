#!/usr/bin/env python3
"""Explicit, bounded acquisition of immutable Hugging Face model snapshots.

This controller is intentionally separate from measured/preflight execution.
It first obtains the complete sibling manifest for an exact commit, imports
already cached files without claiming a download, and only marks the job as
``model_download`` while a missing file is being fetched.  The resulting
managed snapshot contains regular files (never shared-cache symlinks) and is
published with a content-addressed completion receipt.

The Web console invokes this as a controller-only command.  Its activity side
channel is authenticated and job-bound; stdout is never interpreted as state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

# make ``import ura`` work when run as a script from the repository root
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))

from ura.model_acquisition import (  # noqa: E402
    HUGGINGFACE_ENDPOINT,
    MAX_SNAPSHOT_BYTES,
    ModelAcquisitionError,
    build_receipt,
    build_upstream_manifest,
    load_plan,
    seal_snapshot,
    strict_json_bytes,
    validate_plan,
    validate_repo_filename,
    validate_repo_id,
    validate_revision,
    validate_upstream_manifest,
    write_document_create_only,
)
from ura.model_acquisition import (  # noqa: E402
    _checked_direct_child_directory as _core_checked_direct_child_directory,
)
from ura.model_acquisition import (  # noqa: E402
    _read_contained_regular_file as _core_read_contained_regular_file,
)


_MAX_DEADLINE_SECONDS = 7 * 24 * 60 * 60
_ACTIVITY_TOKEN_ENV = "URA_MODEL_ACQUISITION_ACTIVITY_TOKEN"
_ACTIVITY_SCHEMA = "ura-job-activity-event/1"
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class AcquisitionBackend(Protocol):
    def fetch_manifest(
        self,
        repo_id: str,
        revision: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> dict[str, Any]: ...

    def cached_file(self, repo_id: str, revision: str, filename: str) -> Path | None: ...

    def download_file(
        self,
        repo_id: str,
        revision: str,
        filename: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> Path: ...


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    receipt_path: Path
    receipt_sha256: str
    receipt_id: str
    downloaded_bytes: int


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _remaining(deadline: float, monotonic: Callable[[], float]) -> float:
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("model acquisition exceeded its hard deadline")
    return remaining


def _check_cancelled(cancelled: Callable[[], bool]) -> None:
    if cancelled():
        raise InterruptedError("model acquisition was cancelled")


def _prepare_absolute_directory(value: Path | str, *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or _is_link_or_junction(path):
        raise ModelAcquisitionError(
            f"{label} must be a non-link, non-junction absolute directory"
        )
    try:
        path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError(f"{label} cannot be prepared") from exc
    if not resolved.is_dir():
        raise ModelAcquisitionError(f"{label} is not a directory")
    return resolved


def _is_link_or_junction(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_junction()
    except OSError as exc:
        raise ModelAcquisitionError("filesystem link status cannot be inspected") from exc


def _filesystem_identity(info: os.stat_result) -> tuple[int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode)


def _safe_relative_filename(value: str) -> PurePosixPath:
    return PurePosixPath(validate_repo_filename(value))


def _remove_quarantined_tree(
    path: Path,
    *,
    store: Path,
    expected_identity: tuple[int, int, int],
) -> None:
    """Delete one identity-bound tree without traversing links or junctions."""

    try:
        info = path.lstat()
        if (
            path.parent != store
            or _filesystem_identity(info) != expected_identity
            or _is_link_or_junction(path)
            or not stat.S_ISDIR(info.st_mode)
            or path.resolve(strict=True) != path
        ):
            raise ModelAcquisitionError(
                "refusing to traverse a changed acquisition staging directory"
            )
        entries = list(path.iterdir())
        if _filesystem_identity(path.lstat()) != expected_identity:
            raise ModelAcquisitionError(
                "acquisition staging directory changed during cleanup"
            )
        for entry in entries:
            child_info = entry.lstat()
            if _is_link_or_junction(entry) or stat.S_ISLNK(child_info.st_mode):
                # Removing the directory entry itself never traverses its target.
                if stat.S_ISDIR(child_info.st_mode) or entry.is_junction():
                    os.rmdir(entry)
                else:
                    entry.unlink()
                continue
            if stat.S_ISREG(child_info.st_mode):
                if child_info.st_nlink != 1:
                    raise ModelAcquisitionError(
                        "refusing to clean a multiply-linked staging file"
                    )
                descriptor = os.open(
                    entry,
                    os.O_RDONLY
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    opened = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or opened.st_nlink != 1
                        or _filesystem_identity(opened)
                        != _filesystem_identity(child_info)
                    ):
                        raise ModelAcquisitionError(
                            "staging file changed before cleanup"
                        )
                finally:
                    os.close(descriptor)
                entry.unlink()
                continue
            if stat.S_ISDIR(child_info.st_mode):
                isolated = path / (
                    ".cleanup-child-" + secrets.token_hex(16)
                )
                os.rename(entry, isolated)
                moved = isolated.lstat()
                if (
                    _filesystem_identity(moved) != _filesystem_identity(child_info)
                    or _is_link_or_junction(isolated)
                ):
                    raise ModelAcquisitionError(
                        "staging child changed while being isolated"
                    )
                _remove_quarantined_tree(
                    isolated,
                    store=path,
                    expected_identity=_filesystem_identity(moved),
                )
                continue
            raise ModelAcquisitionError(
                "refusing to clean a special staging filesystem entry"
            )
        if _filesystem_identity(path.lstat()) != expected_identity:
            raise ModelAcquisitionError(
                "acquisition staging directory changed before removal"
            )
        os.rmdir(path)
    except OSError as exc:
        raise ModelAcquisitionError("model acquisition staging cleanup failed") from exc


def _safe_remove_partial(
    path: Path,
    *,
    store: Path,
    expected_identity: tuple[int, int, int],
) -> None:
    """Quarantine and remove only this command's exact staging directory."""

    try:
        if path.parent != store or not re.fullmatch(
            r"\.hf-[0-9a-f]{32}\.[0-9a-f]{32}\.partial", path.name
        ):
            raise ModelAcquisitionError("refusing to clean an unrecognized staging path")
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if (
            _filesystem_identity(info) != expected_identity
            or _is_link_or_junction(path)
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise ModelAcquisitionError(
                "refusing to clean a replaced acquisition staging path"
            )
        quarantine = store / (
            ".cleanup-" + path.name.removeprefix(".") + "." + secrets.token_hex(16)
        )
        os.rename(path, quarantine)
        moved = quarantine.lstat()
        if (
            _filesystem_identity(moved) != expected_identity
            or _is_link_or_junction(quarantine)
        ):
            raise ModelAcquisitionError(
                "acquisition staging identity changed while being quarantined"
            )
        _remove_quarantined_tree(
            quarantine,
            store=store,
            expected_identity=expected_identity,
        )
    except OSError as exc:
        raise ModelAcquisitionError("model acquisition staging cleanup failed") from exc


class _ResourceLock:
    """Process-lifetime lock, optionally waiting within the acquisition deadline."""

    def __init__(
        self, path: Path, *, deadline: float | None = None,
        cancelled: Callable[[], bool] = lambda: False,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep, shared: bool = False,
    ):
        self.path = path
        self.stream = None
        self.deadline = deadline
        self.cancelled = cancelled
        self.monotonic = monotonic
        self.sleep = sleep
        self.shared = shared

    def __enter__(self) -> "_ResourceLock":
        descriptor: int | None = None
        try:
            parent = self.path.parent.resolve(strict=True)
            if self.path.parent != parent or _is_link_or_junction(parent):
                raise ModelAcquisitionError("resource lock parent is unsafe")
            before: os.stat_result | None
            try:
                before = self.path.lstat()
            except FileNotFoundError:
                before = None
            if before is not None and (
                _is_link_or_junction(self.path)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
            ):
                raise ModelAcquisitionError("resource lock path is unsafe")
            descriptor = os.open(
                self.path,
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            opened = os.fstat(descriptor)
            after = self.path.lstat()
            if (
                _is_link_or_junction(self.path)
                or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or _filesystem_identity(opened) != _filesystem_identity(after)
                or (before is not None and _filesystem_identity(before)
                    != _filesystem_identity(opened))
                or self.path.resolve(strict=True) != self.path
            ):
                raise ModelAcquisitionError("resource lock changed while opening")
            self.stream = os.fdopen(descriptor, "r+b", closefd=True)
            descriptor = None
            self.stream.seek(0)
            if self.stream.read(1) != b"L":
                self.stream.seek(0)
                self.stream.write(b"L")
                self.stream.flush()
            self.stream.seek(0)
            while True:
                if self.deadline is not None:
                    _check_cancelled(self.cancelled)
                    _remaining(self.deadline, self.monotonic)
                try:
                    if os.name == "nt":
                        import msvcrt

                        mode = msvcrt.LK_NBRLCK if self.shared else msvcrt.LK_NBLCK
                        msvcrt.locking(self.stream.fileno(), mode, 1)
                    else:
                        import fcntl

                        mode = fcntl.LOCK_SH if self.shared else fcntl.LOCK_EX
                        fcntl.flock(self.stream.fileno(), mode | fcntl.LOCK_NB)
                    break
                except OSError as exc:
                    if self.deadline is None or exc.errno not in {errno.EACCES, errno.EAGAIN}:
                        raise
                    _check_cancelled(self.cancelled)
                    self.sleep(min(0.25, _remaining(self.deadline, self.monotonic)))
            # A waiting process must not proceed with a renamed/replaced lock.
            if (self.path.resolve(strict=True) != self.path
                    or _filesystem_identity(self.path.lstat()) != _filesystem_identity(opened)
                    or os.fstat(self.stream.fileno()).st_nlink != 1):
                raise ModelAcquisitionError("resource lock changed while waiting")
        except BaseException as exc:
            if descriptor is not None:
                os.close(descriptor)
            if self.stream is not None:
                self.stream.close()
                self.stream = None
            if isinstance(exc, (TimeoutError, InterruptedError, ModelAcquisitionError)):
                raise
            if isinstance(exc, (OSError, ImportError)):
                raise ModelAcquisitionError("another acquisition owns this resource") from exc
            raise
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        del exc_type, exc, traceback
        if self.stream is None:
            return
        try:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        finally:
            self.stream.close()
            self.stream = None


class ActivityReporter:
    """Write authenticated job-bound activity transitions atomically."""

    def __init__(self, *, path: Path | str, job_id: str, token: str):
        if not isinstance(job_id, str) or _JOB_ID.fullmatch(job_id) is None:
            raise ModelAcquisitionError("activity job id is invalid")
        if not isinstance(token, str) or _SHA256.fullmatch(token) is None:
            raise ModelAcquisitionError("activity token must be 64 lowercase hex characters")
        target = Path(path)
        if not target.is_absolute() or target.is_symlink():
            raise ModelAcquisitionError("activity event path must be absolute and non-symlink")
        parent = target.parent.resolve(strict=True)
        if not parent.is_dir() or target.parent != parent:
            raise ModelAcquisitionError("activity event parent must be one resolved directory")
        self.path = target
        self.job_id = job_id
        self.key = bytes.fromhex(token)
        self.sequence = 0

    def __call__(self, active: bool) -> None:
        self.sequence += 1
        body: dict[str, Any] = {
            "activity": "model_download" if active else None,
            "at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "download_observed": True,
            "job_id": self.job_id,
            "schema": _ACTIVITY_SCHEMA,
            "sequence": self.sequence,
            "state": "start" if active else "end",
        }
        event = dict(body)
        event["hmac_sha256"] = hmac.new(
            self.key, _canonical_bytes(body), hashlib.sha256
        ).hexdigest()
        raw = _canonical_bytes(event) + b"\n"
        temporary = self.path.parent / f".{self.path.name}.{os.getpid()}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = None
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            raise ModelAcquisitionError("activity transition cannot be published") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)


def validate_activity_event(
    value: object,
    *,
    job_id: str,
    token: str,
    minimum_sequence: int,
) -> dict[str, Any]:
    """Validate one event before the lifecycle changes a displayed activity."""

    if not isinstance(value, dict) or set(value) != {
        "activity",
        "at",
        "download_observed",
        "hmac_sha256",
        "job_id",
        "schema",
        "sequence",
        "state",
    }:
        raise ModelAcquisitionError("activity event fields are invalid")
    if value.get("schema") != _ACTIVITY_SCHEMA or value.get("job_id") != job_id:
        raise ModelAcquisitionError("activity event is bound to another job")
    sequence = value.get("sequence")
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence <= minimum_sequence
        or sequence > 2**31 - 1
    ):
        raise ModelAcquisitionError("activity event sequence is stale")
    state = value.get("state")
    activity = value.get("activity")
    if (
        value.get("download_observed") is not True
        or (state, activity) not in {("start", "model_download"), ("end", None)}
    ):
        raise ModelAcquisitionError("activity event transition is invalid")
    timestamp = value.get("at")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z") or len(timestamp) > 40:
        raise ModelAcquisitionError("activity event timestamp is invalid")
    try:
        parsed_timestamp = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelAcquisitionError("activity event timestamp is invalid") from exc
    if parsed_timestamp.utcoffset() != dt.timedelta(0):
        raise ModelAcquisitionError("activity event timestamp is not UTC")
    received = value.get("hmac_sha256")
    if not isinstance(received, str) or _SHA256.fullmatch(received) is None:
        raise ModelAcquisitionError("activity event authentication is invalid")
    if not isinstance(token, str) or _SHA256.fullmatch(token) is None:
        raise ModelAcquisitionError("activity token is invalid")
    body = {key: child for key, child in value.items() if key != "hmac_sha256"}
    expected = hmac.new(bytes.fromhex(token), _canonical_bytes(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(received, expected):
        raise ModelAcquisitionError("activity event authentication failed")
    return dict(value)


def _copy_cached_file(
    source: Path | str,
    destination: Path,
    *,
    expected_size: int,
    deadline: float,
    cancelled: Callable[[], bool],
    monotonic: Callable[[], float],
    disk_usage: Callable[[Path], Any],
    store: Path,
    min_free_bytes: int,
) -> None:
    try:
        resolved_source = Path(source).resolve(strict=True)
        source_info = resolved_source.stat()
    except OSError as exc:
        raise ModelAcquisitionError("cached Hub file cannot be inspected") from exc
    if not stat.S_ISREG(source_info.st_mode) or source_info.st_size != expected_size:
        raise ModelAcquisitionError("cached Hub file size does not match upstream metadata")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with resolved_source.open("rb") as source_stream, os.fdopen(
            descriptor, "wb", closefd=True
        ) as destination_stream:
            descriptor = None
            copied = 0
            while chunk := source_stream.read(8 * 1024 * 1024):
                _check_cancelled(cancelled)
                _remaining(deadline, monotonic)
                if disk_usage(store).free < min_free_bytes + len(chunk):
                    raise ModelAcquisitionError("disk headroom fell below the required reserve")
                destination_stream.write(chunk)
                copied += len(chunk)
                if copied > expected_size:
                    raise ModelAcquisitionError("cached Hub file exceeds upstream size")
            if copied != expected_size:
                raise ModelAcquisitionError("cached Hub file ended before upstream size")
            destination_stream.flush()
            os.fsync(destination_stream.fileno())
    except OSError as exc:
        raise ModelAcquisitionError("cached Hub file cannot be copied") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_managed_manifest(
    store: Path,
    resource: Mapping[str, Any],
    *,
    cancelled: Callable[[], bool],
) -> tuple[dict[str, Any], Path]:
    resource_root, resource_identity = _core_checked_direct_child_directory(
        store,
        str(resource["resource_id"]),
        label=f"managed resource {resource['resource_id']}",
    )
    snapshot, snapshot_identity = _core_checked_direct_child_directory(
        resource_root,
        "snapshot",
        label=f"managed snapshot {resource['resource_id']}",
    )
    try:
        entries = list(resource_root.iterdir())
    except OSError as exc:
        raise ModelAcquisitionError("managed resource cannot be inspected") from exc
    manifests = [
        entry
        for entry in entries
        if re.fullmatch(r"hf-manifest-[0-9a-f]{32}\.upstream-manifest\.json", entry.name)
    ]
    if len(manifests) != 1:
        raise ModelAcquisitionError("managed resource has no unique completion manifest")
    manifest_path = manifests[0]
    try:
        raw = _core_read_contained_regular_file(
            manifest_path,
            parent=resource_root,
            label="managed upstream manifest",
        )
        manifest = validate_upstream_manifest(strict_json_bytes(raw))
    except OSError as exc:
        raise ModelAcquisitionError("managed upstream manifest cannot be read") from exc
    if (
        manifest["repo_id"] != resource["repo_id"]
        or manifest["revision"] != resource["revision"]
        or manifest["file_policy"] != resource["file_policy"]
    ):
        raise ModelAcquisitionError("managed resource belongs to another plan resource")
    # A cache hit is claimed only after the same complete-content proof used by
    # receipt admission. Re-resolve both directories after hashing to close
    # junction/rename swaps before the controller skips network acquisition.
    seal_snapshot(
        snapshot,
        upstream_manifest=manifest,
        cancelled=cancelled,
    )
    resource_after, resource_identity_after = _core_checked_direct_child_directory(
        store,
        str(resource["resource_id"]),
        label=f"managed resource {resource['resource_id']}",
    )
    snapshot_after, snapshot_identity_after = _core_checked_direct_child_directory(
        resource_after,
        "snapshot",
        label=f"managed snapshot {resource['resource_id']}",
    )
    if (
        resource_after != resource_root
        or snapshot_after != snapshot
        or resource_identity_after != resource_identity
        or snapshot_identity_after != snapshot_identity
    ):
        raise ModelAcquisitionError("managed resource changed during cache-hit proof")
    return manifest, snapshot


def acquire(
    plan: Mapping[str, Any],
    *,
    store: Path | str,
    receipts_dir: Path | str,
    max_download_bytes: int,
    min_free_bytes: int,
    deadline_seconds: float,
    backend: AcquisitionBackend,
    activity: Callable[[bool], None] | None = None,
    cancelled: Callable[[], bool] = lambda: False,
    monotonic: Callable[[], float] = time.monotonic,
    disk_usage: Callable[[Path], Any] = shutil.disk_usage,
) -> AcquisitionResult:
    """Acquire all missing plan resources and publish one exact receipt."""

    canonical = validate_plan(dict(plan))
    if (
        isinstance(max_download_bytes, bool)
        or not 0 <= max_download_bytes <= MAX_SNAPSHOT_BYTES
    ):
        raise ModelAcquisitionError("max-download-bytes is invalid")
    if isinstance(min_free_bytes, bool) or not 0 <= min_free_bytes <= MAX_SNAPSHOT_BYTES:
        raise ModelAcquisitionError("min-free-bytes is invalid")
    if not 1 <= float(deadline_seconds) <= _MAX_DEADLINE_SECONDS:
        raise ModelAcquisitionError("deadline-seconds is outside the supported range")
    checked_store = _prepare_absolute_directory(store, label="managed model store")
    checked_receipts = _prepare_absolute_directory(
        receipts_dir, label="model acquisition receipt directory"
    )
    deadline = monotonic() + float(deadline_seconds)
    downloaded_bytes = 0
    snapshots: dict[str, Path] = {}
    manifests: dict[str, dict[str, Any]] = {}

    for resource in canonical["resources"]:
        _check_cancelled(cancelled)
        _remaining(deadline, monotonic)
        resource_id = resource["resource_id"]
        final_root = checked_store / resource_id
        lock_path = checked_store / f".{resource_id}.lock"
        # Published snapshots are read-only and undergo the same complete seal
        # proof below. Share their read lease with other cache-hit verification
        # and runtime construction; missing-resource imports remain exclusive.
        published = os.path.lexists(final_root)
        with _ResourceLock(lock_path, deadline=deadline, cancelled=cancelled,
                           monotonic=monotonic, shared=published):
            try:
                final_root.lstat()
            except FileNotFoundError:
                final_exists = False
            else:
                final_exists = True
            if published and not final_exists:
                raise ModelAcquisitionError("managed resource disappeared while waiting")
            if final_exists:
                manifest, snapshot = _load_managed_manifest(
                    checked_store,
                    resource,
                    cancelled=cancelled,
                )
                manifests[resource_id] = manifest
                snapshots[resource_id] = snapshot
                continue

            manifest = validate_upstream_manifest(
                backend.fetch_manifest(
                    resource["repo_id"],
                    resource["revision"],
                    deadline=deadline,
                    cancelled=cancelled,
                )
            )
            _remaining(deadline, monotonic)
            if (
                manifest["repo_id"] != resource["repo_id"]
                or manifest["revision"] != resource["revision"]
            ):
                raise ModelAcquisitionError("Hub metadata resolved a different resource")
            nonce = os.urandom(16).hex()
            partial = checked_store / f".{resource_id}.{nonce}.partial"
            snapshot = partial / "snapshot"
            partial_identity: tuple[int, int, int] | None = None
            try:
                snapshot.mkdir(parents=True)
                partial_info = partial.lstat()
                if (
                    _is_link_or_junction(partial)
                    or not stat.S_ISDIR(partial_info.st_mode)
                    or partial.resolve(strict=True) != partial
                ):
                    raise ModelAcquisitionError(
                        "model acquisition staging directory is unsafe"
                    )
                partial_identity = _filesystem_identity(partial_info)
                sources: dict[str, Path] = {}
                missing: list[dict[str, Any]] = []
                for file_row in manifest["files"]:
                    _check_cancelled(cancelled)
                    _remaining(deadline, monotonic)
                    cached = backend.cached_file(
                        resource["repo_id"], resource["revision"], file_row["path"]
                    )
                    if cached is None:
                        missing.append(file_row)
                    else:
                        sources[file_row["path"]] = Path(cached)
                missing_bytes = sum(file_row["size"] for file_row in missing)
                if downloaded_bytes + missing_bytes > max_download_bytes:
                    raise ModelAcquisitionError("missing model bytes exceed max-download-bytes")
                # All model bytes are copied into the self-contained store.
                # Only missing files additionally occupy transport-cache space.
                required_free = min_free_bytes + manifest["total_bytes"] + missing_bytes
                if disk_usage(checked_store).free < required_free:
                    raise ModelAcquisitionError(
                        "insufficient disk space plus required headroom"
                    )

                download_active = False
                try:
                    if missing:
                        if activity is not None:
                            activity(True)
                        download_active = True
                    for file_row in missing:
                        _check_cancelled(cancelled)
                        _remaining(deadline, monotonic)
                        source = backend.download_file(
                            resource["repo_id"],
                            resource["revision"],
                            file_row["path"],
                            deadline=deadline,
                            cancelled=cancelled,
                        )
                        _remaining(deadline, monotonic)
                        sources[file_row["path"]] = Path(source)
                        downloaded_bytes += file_row["size"]
                finally:
                    if download_active and activity is not None:
                        activity(False)

                for file_row in manifest["files"]:
                    relative = _safe_relative_filename(file_row["path"])
                    destination = snapshot.joinpath(*relative.parts)
                    _copy_cached_file(
                        sources[file_row["path"]],
                        destination,
                        expected_size=file_row["size"],
                        deadline=deadline,
                        cancelled=cancelled,
                        monotonic=monotonic,
                        disk_usage=disk_usage,
                        store=checked_store,
                        min_free_bytes=min_free_bytes,
                    )
                # Promotion is completion, not merely the end of transport.
                # Prove the complete official sibling set and every Git/LFS
                # content identity while the tree is still disposable.
                seal_snapshot(
                    snapshot,
                    upstream_manifest=manifest,
                    cancelled=cancelled,
                )
                write_document_create_only(
                    partial.resolve(),
                    manifest,
                    identifier=manifest["manifest_id"],
                    suffix="upstream-manifest.json",
                )
                if final_root.exists() or final_root.is_symlink():
                    raise ModelAcquisitionError("managed resource appeared during promotion")
                os.rename(partial, final_root)
            except BaseException:
                if partial_identity is not None:
                    _safe_remove_partial(
                        partial,
                        store=checked_store,
                        expected_identity=partial_identity,
                    )
                raise
            manifests[resource_id] = manifest
            snapshots[resource_id] = final_root / "snapshot"

    _check_cancelled(cancelled)
    _remaining(deadline, monotonic)
    receipt = build_receipt(
        canonical,
        snapshots=snapshots,
        manifests=manifests,
        cancelled=cancelled,
    )
    receipt_path, receipt_digest = write_document_create_only(
        checked_receipts,
        receipt,
        identifier=receipt["receipt_id"],
        suffix="receipt.json",
    )
    return AcquisitionResult(
        receipt_path=receipt_path,
        receipt_sha256=receipt_digest,
        receipt_id=receipt["receipt_id"],
        downloaded_bytes=downloaded_bytes,
    )


def _safe_worker_environment() -> dict[str, str]:
    """Pass runtime essentials, Hub tokens and the bounded transport policy."""

    allowed = {
        "HF_TOKEN",
        "HF_HUB_DISABLE_XET",
        "HUGGING_FACE_HUB_TOKEN",
        "LANG",
        "LC_ALL",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "WINDIR",
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed
        and isinstance(value, str)
        and len(value) <= 8192
        and "\0" not in value
    }
    environment.update(
        {
            "HF_HUB_DISABLE_PROGRESS_BARS": "1",
            "HF_HUB_DISABLE_TELEMETRY": "1",
            "HF_HUB_DOWNLOAD_TIMEOUT": "60",
            "HF_HUB_ETAG_TIMEOUT": "30",
            "PYTHONUNBUFFERED": "1",
        }
    )
    environment.pop("HF_ENDPOINT", None)
    environment.pop("PYTHONPATH", None)
    return environment


def _terminate_worker(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


class HuggingFaceBackend:
    """Official-endpoint backend with network calls isolated in child processes."""

    def __init__(self, *, transport_cache: Path | str):
        self.transport_cache = _prepare_absolute_directory(
            transport_cache, label="Hugging Face transport cache"
        )

    def _worker(
        self,
        arguments: list[str],
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> None:
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), *arguments],
            cwd=str(_REPO_ROOT),
            env=_safe_worker_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        try:
            while process.poll() is None:
                if cancelled():
                    raise InterruptedError("model acquisition was cancelled")
                if time.monotonic() >= deadline:
                    raise TimeoutError("model acquisition exceeded its hard deadline")
                time.sleep(0.05)
            if process.returncode != 0:
                raise ModelAcquisitionError("Hugging Face acquisition worker failed")
        except BaseException:
            _terminate_worker(process)
            raise

    def fetch_manifest(
        self,
        repo_id: str,
        revision: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> dict[str, Any]:
        output = self.transport_cache / f".manifest-{os.urandom(16).hex()}.json"
        try:
            self._worker(
                [
                    "--worker-manifest",
                    "--repo-id",
                    validate_repo_id(repo_id),
                    "--revision",
                    validate_revision(revision),
                    "--worker-output",
                    str(output),
                ],
                deadline=deadline,
                cancelled=cancelled,
            )
            try:
                raw = _core_read_contained_regular_file(
                    output,
                    parent=self.transport_cache,
                    label="worker manifest output",
                )
                return validate_upstream_manifest(strict_json_bytes(raw))
            except OSError as exc:
                raise ModelAcquisitionError("worker manifest output cannot be read") from exc
        finally:
            output.unlink(missing_ok=True)

    def cached_file(self, repo_id: str, revision: str, filename: str) -> Path | None:
        try:
            from huggingface_hub import hf_hub_download
            from huggingface_hub.errors import LocalEntryNotFoundError
        except ImportError as exc:
            raise ModelAcquisitionError("huggingface_hub is required for model acquisition") from exc
        try:
            value = hf_hub_download(
                repo_id=validate_repo_id(repo_id),
                revision=validate_revision(revision),
                filename=_safe_relative_filename(filename).as_posix(),
                cache_dir=str(self.transport_cache),
                endpoint=HUGGINGFACE_ENDPOINT,
                local_files_only=True,
            )
        except LocalEntryNotFoundError:
            return None
        except Exception as exc:
            raise ModelAcquisitionError("local Hugging Face cache lookup failed") from exc
        return Path(value)

    def download_file(
        self,
        repo_id: str,
        revision: str,
        filename: str,
        *,
        deadline: float,
        cancelled: Callable[[], bool],
    ) -> Path:
        self._worker(
            [
                "--worker-download",
                "--repo-id",
                validate_repo_id(repo_id),
                "--revision",
                validate_revision(revision),
                "--filename",
                _safe_relative_filename(filename).as_posix(),
                "--transport-cache",
                str(self.transport_cache),
            ],
            deadline=deadline,
            cancelled=cancelled,
        )
        cached = self.cached_file(repo_id, revision, filename)
        if cached is None:
            raise ModelAcquisitionError("download worker returned without the requested file")
        return cached


def _worker_token() -> str | None:
    return os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN") or None


def _worker_manifest(args: argparse.Namespace) -> int:
    try:
        from huggingface_hub import HfApi

        repository = validate_repo_id(args.repo_id)
        revision = validate_revision(args.revision)
        info = HfApi(endpoint=HUGGINGFACE_ENDPOINT, token=_worker_token()).model_info(
            repository,
            revision=revision,
            files_metadata=True,
            timeout=30,
        )
        if getattr(info, "sha", None) != revision:
            raise ModelAcquisitionError("Hub metadata did not resolve the requested commit")
        files = []
        for sibling in getattr(info, "siblings", ()):
            lfs = getattr(sibling, "lfs", None)
            files.append(
                {
                    "blob_id": getattr(sibling, "blob_id", None),
                    "lfs_sha256": getattr(lfs, "sha256", None) if lfs is not None else None,
                    "path": getattr(sibling, "rfilename", None),
                    "size": getattr(sibling, "size", None),
                }
            )
        manifest = build_upstream_manifest(repository, revision, files)
        output = Path(args.worker_output)
        if not output.is_absolute() or output.exists() or output.is_symlink():
            raise ModelAcquisitionError("worker output path is invalid")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(_canonical_bytes(manifest) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return 0
    except Exception:
        return 1


def _worker_download(args: argparse.Namespace) -> int:
    try:
        from huggingface_hub import hf_hub_download

        cache = _prepare_absolute_directory(args.transport_cache, label="transport cache")
        hf_hub_download(
            repo_id=validate_repo_id(args.repo_id),
            revision=validate_revision(args.revision),
            filename=_safe_relative_filename(args.filename).as_posix(),
            cache_dir=str(cache),
            endpoint=HUGGINGFACE_ENDPOINT,
            token=_worker_token(),
            force_download=False,
            local_files_only=False,
            resume_download=True,
        )
        return 0
    except Exception:
        return 1


class _SignalCancellation:
    def __init__(self) -> None:
        self.cancelled = False

    def install(self) -> None:
        def request_cancel(signum, frame) -> None:  # noqa: ANN001
            del signum, frame
            self.cancelled = True

        signal.signal(signal.SIGINT, request_cancel)
        signal.signal(signal.SIGTERM, request_cancel)

    def __call__(self) -> bool:
        return self.cancelled


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan")
    parser.add_argument("--plan-sha256")
    parser.add_argument("--store")
    parser.add_argument("--receipts-dir")
    parser.add_argument("--transport-cache")
    parser.add_argument("--max-download-bytes", type=int)
    parser.add_argument("--min-free-bytes", type=int)
    parser.add_argument("--deadline-seconds", type=float)
    parser.add_argument("--activity-event")
    parser.add_argument("--activity-job-id")
    parser.add_argument("--worker-manifest", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-download", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--repo-id", help=argparse.SUPPRESS)
    parser.add_argument("--revision", help=argparse.SUPPRESS)
    parser.add_argument("--filename", help=argparse.SUPPRESS)
    parser.add_argument("--worker-output", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.worker_manifest:
        return _worker_manifest(args)
    if args.worker_download:
        return _worker_download(args)
    required = {
        "--deadline-seconds": args.deadline_seconds,
        "--max-download-bytes": args.max_download_bytes,
        "--min-free-bytes": args.min_free_bytes,
        "--plan": args.plan,
        "--plan-sha256": args.plan_sha256,
        "--receipts-dir": args.receipts_dir,
        "--store": args.store,
    }
    missing = [flag for flag, value in required.items() if value is None]
    if missing:
        raise SystemExit("missing required arguments: " + ", ".join(sorted(missing)))
    event_values = (args.activity_event, args.activity_job_id)
    if any(value is not None for value in event_values) and not all(
        value is not None for value in event_values
    ):
        raise SystemExit("--activity-event and --activity-job-id must be paired")
    reporter = None
    if args.activity_event is not None:
        token = os.environ.get(_ACTIVITY_TOKEN_ENV, "")
        reporter = ActivityReporter(
            path=args.activity_event,
            job_id=args.activity_job_id,
            token=token,
        )
    cancellation = _SignalCancellation()
    cancellation.install()
    try:
        plan = load_plan(args.plan, expected_sha256=args.plan_sha256)
        checked_store = _prepare_absolute_directory(
            args.store, label="managed model store"
        )
        transport_value = args.transport_cache or str(checked_store / ".transport-cache")
        checked_transport = _prepare_absolute_directory(
            transport_value, label="Hugging Face transport cache"
        )
        if (
            checked_transport.parent != checked_store
            or checked_transport.stat().st_dev != checked_store.stat().st_dev
        ):
            raise ModelAcquisitionError(
                "transport cache must be one direct child on the managed-store filesystem"
            )
        result = acquire(
            plan,
            store=checked_store,
            receipts_dir=args.receipts_dir,
            max_download_bytes=args.max_download_bytes,
            min_free_bytes=args.min_free_bytes,
            deadline_seconds=args.deadline_seconds,
            backend=HuggingFaceBackend(transport_cache=checked_transport),
            activity=reporter,
            cancelled=cancellation,
        )
    except (InterruptedError, ModelAcquisitionError, TimeoutError, ValueError) as exc:
        print(f"model acquisition failed: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "downloaded_bytes": result.downloaded_bytes,
                "receipt_id": result.receipt_id,
                "receipt_sha256": result.receipt_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
