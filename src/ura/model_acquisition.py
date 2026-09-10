"""Fail-closed planning and completion seals for Hugging Face model assets.

The benchmark must never let a measured run turn model construction into an
implicit network operation.  This module deliberately contains no eager
``huggingface_hub`` import.  It describes the exact immutable resources a run
will need, proves cache hits with a local-only resolver, and seals the bytes
that were found.  A separate, explicit acquisition command is the only caller
allowed to populate a missing resource.

Absolute cache paths are launch inputs, not durable scientific identity.  The
durable identity is the repository, immutable commit, roles, plan binding, and
content tree SHA-256 recorded below.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any


PLAN_SCHEMA = "ura-model-acquisition-plan/1"
RECEIPT_SCHEMA = "ura-model-acquisition-receipt/1"
UPSTREAM_MANIFEST_SCHEMA = "ura-hf-upstream-manifest/1"
HUGGINGFACE_ENDPOINT = "https://huggingface.co"
FULL_REPOSITORY_POLICY = "complete_repository_snapshot"

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_RESOURCES = 64
MAX_BINDINGS = 64
MAX_SNAPSHOT_FILES = 500_000
MAX_SNAPSHOT_BYTES = 4 * 1024**4

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMMUTABLE_REVISION = re.compile(r"[0-9a-f]{40,64}")
_BINDING_KEY = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_REPO_COMPONENT = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,94}[A-Za-z0-9])?")
_RESOURCE_ID = re.compile(r"hf-[0-9a-f]{32}")
_PLAN_ID = re.compile(r"acquisition-plan-[0-9a-f]{32}")
_RECEIPT_ID = re.compile(r"acquisition-receipt-[0-9a-f]{32}")
_MANIFEST_ID = re.compile(r"hf-manifest-[0-9a-f]{32}")

RESOURCE_ROLES = frozenset(
    {
        "defense_guardrail",
        "guardrail_judge",
        "llm_judge",
        "nanogcg_surrogate",
        "vllm_target",
    }
)
STORAGE_KINDS = frozenset({"managed_store"})


class ModelAcquisitionError(ValueError):
    """One acquisition plan, receipt, or local snapshot is not trustworthy."""


class CacheMissError(ModelAcquisitionError):
    """A required immutable snapshot is not available without network I/O."""


@dataclass(frozen=True, slots=True)
class HubRequirement:
    """One caller's need for an immutable Hub repository snapshot."""

    role: str
    repo_id: str
    revision: str


@dataclass(frozen=True, slots=True)
class SnapshotSeal:
    """Content evidence for one resolved local snapshot."""

    tree_sha256: str
    inventory_sha256: str
    file_count: int
    total_bytes: int


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256_bytes(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ModelAcquisitionError(f"duplicate JSON key {key!r}")
        output[key] = value
    return output


def _reject_constant(value: str) -> None:
    raise ModelAcquisitionError(f"non-finite JSON value {value!r}")


def _check_json_depth(value: object, *, maximum: int = 32) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > maximum:
            raise ModelAcquisitionError("acquisition JSON nesting exceeds the limit")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def strict_json_bytes(raw: bytes) -> object:
    """Parse one bounded UTF-8 JSON document without duplicate/NaN ambiguity."""

    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_DOCUMENT_BYTES:
        raise ModelAcquisitionError("acquisition JSON has an invalid byte size")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ModelAcquisitionError("acquisition JSON is invalid") from exc
    _check_json_depth(value)
    return value


def _validated_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ModelAcquisitionError(f"{label} must be 64 lowercase hex characters")
    return value


def validate_repo_id(value: object) -> str:
    """Validate a model repository identifier, never a local/URL path."""

    if not isinstance(value, str) or value != value.strip() or len(value) > 192:
        raise ModelAcquisitionError("Hub repo_id must be a bounded canonical string")
    if (
        value.count("/") != 1
        or "\\" in value
        or ":" in value
        or ".." in value
        or "--" in value
        or value.endswith(".git")
    ):
        raise ModelAcquisitionError("Hub repo_id must be namespace/name, not a path or URL")
    namespace, name = value.split("/", 1)
    if _REPO_COMPONENT.fullmatch(namespace) is None or _REPO_COMPONENT.fullmatch(name) is None:
        raise ModelAcquisitionError("Hub repo_id contains invalid characters")
    return value


def validate_revision(value: object) -> str:
    """Require a full immutable commit, not a branch, tag, or short SHA."""

    if not isinstance(value, str):
        raise ModelAcquisitionError("Hub revision must be an immutable commit")
    normalized = value.strip().lower()
    if value != normalized or _IMMUTABLE_REVISION.fullmatch(normalized) is None:
        raise ModelAcquisitionError("Hub revision must be 40-64 lowercase hex characters")
    return normalized


def _resource_id(repo_id: str, revision: str) -> str:
    digest = hashlib.sha256(f"{repo_id}\0{revision}".encode("utf-8")).hexdigest()
    return "hf-" + digest[:32]


def hub_requirement(role: object, repo_id: object, revision: object) -> HubRequirement:
    if not isinstance(role, str) or role not in RESOURCE_ROLES:
        raise ModelAcquisitionError(f"unsupported Hub resource role {role!r}")
    return HubRequirement(
        role=role,
        repo_id=validate_repo_id(repo_id),
        revision=validate_revision(revision),
    )


def vllm_requirement(
    model_spec: object,
    revision: object,
    *,
    role: str,
    explicit_local_path: bool = False,
) -> HubRequirement | None:
    """Project one vLLM target/judge selection into a Hub requirement.

    The caller already owns the authoritative local-path classification.  A
    local checkpoint is content-digest-bound elsewhere and must not be turned
    into a Hub lookup here.
    """

    if role not in {"vllm_target", "llm_judge"}:
        raise ModelAcquisitionError("vLLM resources may only be target or judge roles")
    if explicit_local_path:
        return None
    if not isinstance(model_spec, str) or not model_spec.startswith("vllm:"):
        raise ModelAcquisitionError("vLLM model spec must start with 'vllm:'")
    return hub_requirement(role, model_spec.split(":", 1)[1], revision)


def guardrail_requirement(
    model_id: object,
    revision: object,
    *,
    defense: bool,
) -> HubRequirement:
    return hub_requirement(
        "defense_guardrail" if defense else "guardrail_judge",
        model_id,
        revision,
    )


def nanogcg_requirement(config: Mapping[str, Any]) -> HubRequirement | None:
    """Return the NanoGCG surrogate requirement, or none for a sealed suffix."""

    suffix = config.get("suffix")
    if suffix is not None:
        if not isinstance(suffix, str) or not suffix:
            raise ModelAcquisitionError("NanoGCG suffix must be a non-empty string")
        return None
    return hub_requirement(
        "nanogcg_surrogate",
        config.get("model_id", "meta-llama/Llama-3.1-8B-Instruct"),
        config.get("model_revision"),
    )


def build_plan(
    requirements: Iterable[HubRequirement],
    *,
    bindings: Mapping[str, str],
) -> dict[str, Any]:
    """Build a canonical prospective plan, merging roles for one snapshot."""

    if not isinstance(bindings, Mapping) or not 1 <= len(bindings) <= MAX_BINDINGS:
        raise ModelAcquisitionError("acquisition plan needs bounded immutable bindings")
    normalized_bindings: dict[str, str] = {}
    for key, value in bindings.items():
        if not isinstance(key, str) or _BINDING_KEY.fullmatch(key) is None:
            raise ModelAcquisitionError("acquisition binding key is invalid")
        normalized_bindings[key] = _validated_sha256(value, label=f"binding {key!r}")

    merged: dict[tuple[str, str], set[str]] = {}
    count = 0
    for raw in requirements:
        count += 1
        if count > MAX_RESOURCES * len(RESOURCE_ROLES):
            raise ModelAcquisitionError("too many acquisition requirements")
        if not isinstance(raw, HubRequirement):
            raise ModelAcquisitionError("acquisition requirements must be HubRequirement values")
        requirement = hub_requirement(raw.role, raw.repo_id, raw.revision)
        merged.setdefault((requirement.repo_id, requirement.revision), set()).add(
            requirement.role
        )
    if not merged:
        raise ModelAcquisitionError("an acquisition plan must contain at least one Hub resource")
    if len(merged) > MAX_RESOURCES:
        raise ModelAcquisitionError("too many distinct acquisition resources")

    resources = [
        {
            "file_policy": FULL_REPOSITORY_POLICY,
            "repo_id": repo_id,
            "resource_id": _resource_id(repo_id, revision),
            "revision": revision,
            "roles": sorted(roles),
        }
        for (repo_id, revision), roles in sorted(merged.items())
    ]
    body: dict[str, Any] = {
        "bindings": dict(sorted(normalized_bindings.items())),
        "resources": resources,
        "schema": PLAN_SCHEMA,
    }
    body["plan_id"] = "acquisition-plan-" + _sha256_bytes(body)[:32]
    return body


def validate_plan(value: object) -> dict[str, Any]:
    """Validate and return the canonical representation of one plan."""

    if not isinstance(value, dict) or set(value) != {
        "bindings",
        "plan_id",
        "resources",
        "schema",
    }:
        raise ModelAcquisitionError("acquisition plan has unknown or missing fields")
    if value.get("schema") != PLAN_SCHEMA:
        raise ModelAcquisitionError("unsupported acquisition plan schema")
    resources = value.get("resources")
    bindings = value.get("bindings")
    if not isinstance(resources, list) or not isinstance(bindings, dict):
        raise ModelAcquisitionError("acquisition plan resources/bindings are invalid")
    requirements: list[HubRequirement] = []
    previous_key: tuple[str, str] | None = None
    for resource in resources:
        if not isinstance(resource, dict) or set(resource) != {
            "file_policy",
            "repo_id",
            "resource_id",
            "revision",
            "roles",
        }:
            raise ModelAcquisitionError("acquisition resource has unknown or missing fields")
        repo_id = validate_repo_id(resource.get("repo_id"))
        revision = validate_revision(resource.get("revision"))
        if resource.get("file_policy") != FULL_REPOSITORY_POLICY:
            raise ModelAcquisitionError("acquisition file policy must fetch the full repository")
        if resource.get("resource_id") != _resource_id(repo_id, revision):
            raise ModelAcquisitionError("acquisition resource_id does not match repo/revision")
        roles = resource.get("roles")
        if (
            not isinstance(roles, list)
            or not roles
            or roles != sorted(set(roles))
            or any(not isinstance(role, str) or role not in RESOURCE_ROLES for role in roles)
        ):
            raise ModelAcquisitionError("acquisition resource roles are invalid")
        key = (repo_id, revision)
        if previous_key is not None and key <= previous_key:
            raise ModelAcquisitionError("acquisition resources are not uniquely sorted")
        previous_key = key
        requirements.extend(hub_requirement(role, repo_id, revision) for role in roles)
    canonical = build_plan(requirements, bindings=bindings)
    plan_id = value.get("plan_id")
    if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
        raise ModelAcquisitionError("acquisition plan_id is invalid")
    if canonical != value:
        raise ModelAcquisitionError("acquisition plan is not canonical or its ID is stale")
    return canonical


def plan_sha256(plan: Mapping[str, Any]) -> str:
    return _sha256_bytes(validate_plan(dict(plan)))


_WINDOWS_RESERVED_COMPONENTS = frozenset({
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
})
_PORTABLE_FORBIDDEN_FILENAME_CHARACTERS = frozenset('<>:"\\|?*')


def validate_repo_filename(value: object) -> str:
    """Validate one repository path before any destination filesystem access."""

    if not isinstance(value, str) or value != value.strip() or not value or len(value) > 1024:
        raise ModelAcquisitionError("upstream repository filename is invalid")
    if "\\" in value or "\0" in value or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ModelAcquisitionError("upstream repository filename is invalid")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or len(parsed.parts) > 32 or any(
        part in {"", ".", ".."} for part in parsed.parts
    ):
        raise ModelAcquisitionError("upstream repository filename is not safely relative")
    for component in parsed.parts:
        if (
            len(component) > 255
            or component.endswith((" ", "."))
            or unicodedata.normalize("NFC", component) != component
            or any(
                character in _PORTABLE_FORBIDDEN_FILENAME_CHARACTERS
                for character in component
            )
            or component.split(".", 1)[0].casefold()
            in _WINDOWS_RESERVED_COMPONENTS
        ):
            raise ModelAcquisitionError(
                "upstream repository filename is not portable across filesystems"
            )
    return parsed.as_posix()


_validated_repo_filename = validate_repo_filename


def build_upstream_manifest(
    repo_id: object,
    revision: object,
    files: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Canonicalize the exact sibling metadata returned for one commit.

    The metadata request happens only inside the explicit acquisition job and
    must resolve the requested immutable commit exactly.  Every sibling is
    included; weight-format filtering is intentionally forbidden.
    """

    repository = validate_repo_id(repo_id)
    commit = validate_revision(revision)
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    seen_portable: set[str] = set()
    total_bytes = 0
    for raw in files:
        if (
            not isinstance(raw, Mapping)
            or not set(raw).issubset({"blob_id", "lfs_sha256", "path", "size"})
            or not {"path", "size"}.issubset(raw)
        ):
            raise ModelAcquisitionError("upstream sibling metadata has invalid fields")
        path = _validated_repo_filename(raw.get("path"))
        if path in seen:
            raise ModelAcquisitionError("upstream sibling metadata contains duplicate paths")
        seen.add(path)
        portable_identity = unicodedata.normalize("NFC", path).casefold()
        if portable_identity in seen_portable:
            raise ModelAcquisitionError(
                "upstream sibling metadata contains a portable path collision"
            )
        seen_portable.add(portable_identity)
        size = raw.get("size")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= MAX_SNAPSHOT_BYTES
            or total_bytes + size > MAX_SNAPSHOT_BYTES
        ):
            raise ModelAcquisitionError("upstream sibling size exceeds the acquisition bound")
        total_bytes += size
        blob_id = raw.get("blob_id")
        if blob_id is not None and (
            not isinstance(blob_id, str)
            or re.fullmatch(r"[0-9a-f]{40}", blob_id.lower()) is None
            or blob_id != blob_id.lower()
        ):
            raise ModelAcquisitionError("upstream sibling blob identity is invalid")
        lfs_sha256 = raw.get("lfs_sha256")
        if lfs_sha256 is not None:
            _validated_sha256(lfs_sha256, label="upstream LFS SHA-256")
        if blob_id is None and lfs_sha256 is None:
            raise ModelAcquisitionError("upstream sibling lacks a content identity")
        normalized.append(
            {
                "blob_id": blob_id,
                "lfs_sha256": lfs_sha256,
                "path": path,
                "size": size,
            }
        )
        if len(normalized) > MAX_SNAPSHOT_FILES:
            raise ModelAcquisitionError("upstream sibling count exceeds the acquisition bound")
    if not normalized:
        raise ModelAcquisitionError("upstream repository contains no files")
    body: dict[str, Any] = {
        "endpoint": HUGGINGFACE_ENDPOINT,
        "file_policy": FULL_REPOSITORY_POLICY,
        "files": sorted(normalized, key=lambda row: row["path"]),
        "repo_id": repository,
        "revision": commit,
        "schema": UPSTREAM_MANIFEST_SCHEMA,
        "total_bytes": total_bytes,
    }
    body["manifest_id"] = "hf-manifest-" + _sha256_bytes(body)[:32]
    return body


def validate_upstream_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "endpoint",
        "file_policy",
        "files",
        "manifest_id",
        "repo_id",
        "revision",
        "schema",
        "total_bytes",
    }:
        raise ModelAcquisitionError("upstream manifest has unknown or missing fields")
    if (
        value.get("schema") != UPSTREAM_MANIFEST_SCHEMA
        or value.get("endpoint") != HUGGINGFACE_ENDPOINT
        or value.get("file_policy") != FULL_REPOSITORY_POLICY
    ):
        raise ModelAcquisitionError("upstream manifest policy is invalid")
    files = value.get("files")
    if not isinstance(files, list):
        raise ModelAcquisitionError("upstream manifest files are invalid")
    canonical = build_upstream_manifest(
        value.get("repo_id"),
        value.get("revision"),
        files,
    )
    if canonical.get("total_bytes") != value.get("total_bytes"):
        raise ModelAcquisitionError("upstream manifest byte total is stale")
    manifest_id = value.get("manifest_id")
    if (
        not isinstance(manifest_id, str)
        or _MANIFEST_ID.fullmatch(manifest_id) is None
        or canonical != value
    ):
        raise ModelAcquisitionError("upstream manifest is non-canonical or its ID is stale")
    return canonical


def upstream_manifest_sha256(manifest: Mapping[str, Any]) -> str:
    return _sha256_bytes(validate_upstream_manifest(dict(manifest)))


def load_document(
    path: Path | str,
    *,
    expected_sha256: str,
    kind: str,
) -> dict[str, Any]:
    """Read one exact regular file and validate its caller-bound byte digest."""

    expected = _validated_sha256(expected_sha256, label=f"expected {kind} SHA-256")
    source = Path(path)
    raw = _read_contained_regular_file(
        source,
        parent=source.parent,
        label=f"{kind} file",
    )
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ModelAcquisitionError(f"{kind} file does not match its exact SHA-256")
    parsed = strict_json_bytes(raw)
    if not isinstance(parsed, dict):
        raise ModelAcquisitionError(f"{kind} document must be an object")
    return parsed


def load_plan(path: Path | str, *, expected_sha256: str) -> dict[str, Any]:
    return validate_plan(
        load_document(path, expected_sha256=expected_sha256, kind="acquisition plan")
    )


def _is_link_or_junction(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_junction()
    except OSError as exc:
        raise ModelAcquisitionError("filesystem link status cannot be inspected") from exc


def _filesystem_identity(info: os.stat_result) -> tuple[int, int, int]:
    # Windows may update birth/change-time metadata merely when a file handle
    # is opened. Device + file index/inode + type remain the stable identity.
    return (info.st_dev, info.st_ino, info.st_mode)


def _checked_snapshot_root(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ModelAcquisitionError("resolved snapshot must be an absolute path")
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError("resolved snapshot cannot be inspected") from exc
    if _is_link_or_junction(path) or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(
        info.st_mode
    ):
        raise ModelAcquisitionError(
            "resolved snapshot must be a non-link, non-junction directory"
        )
    return resolved


def _checked_direct_child_directory(
    parent: Path,
    child_name: str,
    *,
    label: str,
) -> tuple[Path, tuple[int, int, int]]:
    candidate = parent / child_name
    if candidate.parent != parent:
        raise ModelAcquisitionError(f"{label} is not a direct child of its store")
    try:
        info = candidate.lstat()
        if (
            _is_link_or_junction(candidate)
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise ModelAcquisitionError(
                f"{label} must be a non-link, non-junction directory"
            )
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError(f"{label} cannot be inspected") from exc
    if resolved != candidate or resolved.parent != parent:
        raise ModelAcquisitionError(f"{label} resolves outside its direct store parent")
    return resolved, _filesystem_identity(info)


def _read_contained_regular_file(
    path: Path,
    *,
    parent: Path,
    label: str,
) -> bytes:
    if path.parent != parent:
        raise ModelAcquisitionError(f"{label} is not a direct child")
    descriptor: int | None = None
    try:
        info = path.lstat()
        if (
            _is_link_or_junction(path)
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or not 0 < info.st_size <= MAX_DOCUMENT_BYTES
        ):
            raise ModelAcquisitionError(f"{label} must be one contained regular file")
        resolved = path.resolve(strict=True)
        if resolved != path or resolved.parent != parent:
            raise ModelAcquisitionError(f"{label} resolves outside its resource directory")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(resolved, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != info.st_size
            or _filesystem_identity(opened) != _filesystem_identity(info)
        ):
            raise ModelAcquisitionError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(MAX_DOCUMENT_BYTES + 1)
            after = os.fstat(stream.fileno())
            if (
                _filesystem_identity(after) != _filesystem_identity(opened)
                or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
            ):
                raise ModelAcquisitionError(f"{label} changed while it was read")
        if len(raw) != info.st_size:
            raise ModelAcquisitionError(f"{label} byte size changed while it was read")
        return raw
    except OSError as exc:
        raise ModelAcquisitionError(f"{label} cannot be read") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def seal_snapshot(
    root: Path | str,
    *,
    max_files: int = MAX_SNAPSHOT_FILES,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
    cancelled: Callable[[], bool] | None = None,
    full_content: bool = True,
    upstream_manifest: Mapping[str, Any] | None = None,
) -> SnapshotSeal:
    """Hash one bounded snapshot tree and build a fast stat inventory.

    The managed store must be self-contained.  Every entry is therefore a
    regular file; shared-cache symlinks must be copied/dereferenced before this
    function is called. Directory links and every special file fail closed.
    ``full_content=False`` is only for repeated receipt verification: callers
    must compare the returned inventory to a prior full-content seal and must
    never treat its ``tree_sha256`` as a content digest.
    """

    if isinstance(max_files, bool) or not 1 <= max_files <= MAX_SNAPSHOT_FILES:
        raise ModelAcquisitionError("snapshot max_files is invalid")
    if isinstance(max_bytes, bool) or not 1 <= max_bytes <= MAX_SNAPSHOT_BYTES:
        raise ModelAcquisitionError("snapshot max_bytes is invalid")
    manifest = (
        validate_upstream_manifest(dict(upstream_manifest))
        if upstream_manifest is not None
        else None
    )
    if manifest is not None and not full_content:
        raise ModelAcquisitionError("upstream manifest verification requires content hashing")
    expected_files = (
        {row["path"]: row for row in manifest["files"]} if manifest is not None else None
    )
    checked_root = _checked_snapshot_root(root)
    digest = hashlib.sha256(b"ura-hf-snapshot-tree-v1\0")
    inventory = hashlib.sha256(b"ura-hf-snapshot-inventory-v1\0")
    file_count = 0
    total_bytes = 0
    stack = [checked_root]
    rows: list[tuple[str, Path]] = []
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise ModelAcquisitionError("snapshot tree cannot be enumerated") from exc
        for entry in entries:
            if cancelled is not None and cancelled():
                raise InterruptedError("snapshot sealing was cancelled")
            path = Path(entry.path)
            try:
                if _is_link_or_junction(path):
                    raise ModelAcquisitionError(
                        "snapshot contains a filesystem link or junction"
                    )
                if entry.is_dir(follow_symlinks=False):
                    stack.append(path)
                    continue
                if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    raise ModelAcquisitionError("snapshot contains a special filesystem entry")
            except OSError as exc:
                raise ModelAcquisitionError("snapshot entry cannot be inspected") from exc
            relative = path.relative_to(checked_root).as_posix()
            if not relative or "\0" in relative:
                raise ModelAcquisitionError("snapshot contains an invalid relative path")
            rows.append((relative, path))
            if len(rows) > max_files:
                raise ModelAcquisitionError("snapshot file count exceeds its bound")

    if expected_files is not None and {relative for relative, _path in rows} != set(
        expected_files
    ):
        raise ModelAcquisitionError("snapshot paths do not match the complete upstream manifest")

    for relative, path in sorted(rows):
        if cancelled is not None and cancelled():
            raise InterruptedError("snapshot sealing was cancelled")
        try:
            target = path.resolve(strict=True)
            target_info = target.stat()
        except OSError as exc:
            raise ModelAcquisitionError("snapshot file cannot be inspected") from exc
        if not target.is_relative_to(checked_root):
            raise ModelAcquisitionError("snapshot file resolves outside the managed store")
        if not stat.S_ISREG(target_info.st_mode) or target_info.st_nlink != 1:
            raise ModelAcquisitionError("snapshot link does not resolve to a regular file")
        size = target_info.st_size
        if size < 0 or total_bytes + size > max_bytes:
            raise ModelAcquisitionError("snapshot bytes exceed their bound")
        expected_file = expected_files.get(relative) if expected_files is not None else None
        if expected_file is not None and size != expected_file["size"]:
            raise ModelAcquisitionError("snapshot file size does not match upstream metadata")
        total_bytes += size
        file_count += 1
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        inventory.update(relative.encode("utf-8"))
        inventory.update(b"\0")
        inventory.update(b"regular")
        inventory.update(b"\0")
        inventory.update(str(size).encode("ascii"))
        inventory.update(b"\0")
        inventory.update(str(target_info.st_mtime_ns).encode("ascii"))
        inventory.update(b"\0")
        if full_content:
            lfs_digest = hashlib.sha256() if expected_file and expected_file["lfs_sha256"] else None
            git_digest = None
            if expected_file and expected_file["lfs_sha256"] is None:
                git_digest = hashlib.sha1()  # noqa: S324 - Git blob identity is SHA-1 by protocol
                git_digest.update(f"blob {size}\0".encode("ascii"))
            descriptor: int | None = None
            try:
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(target, flags)
                opened_info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(opened_info.st_mode)
                    or opened_info.st_nlink != 1
                    or opened_info.st_size != target_info.st_size
                    or opened_info.st_mtime_ns != target_info.st_mtime_ns
                    or (
                        target_info.st_ino
                        and opened_info.st_ino
                        and opened_info.st_ino != target_info.st_ino
                    )
                    or (
                        target_info.st_dev
                        and opened_info.st_dev
                        and opened_info.st_dev != target_info.st_dev
                    )
                ):
                    raise ModelAcquisitionError("snapshot file changed while it was opened")
                with os.fdopen(descriptor, "rb", closefd=True) as stream:
                    descriptor = None
                    while chunk := stream.read(8 * 1024 * 1024):
                        if cancelled is not None and cancelled():
                            raise InterruptedError("snapshot sealing was cancelled")
                        digest.update(chunk)
                        if lfs_digest is not None:
                            lfs_digest.update(chunk)
                        if git_digest is not None:
                            git_digest.update(chunk)
                    after_info = os.fstat(stream.fileno())
                    if (
                        after_info.st_size != opened_info.st_size
                        or after_info.st_mtime_ns != opened_info.st_mtime_ns
                        or (
                            opened_info.st_ino
                            and after_info.st_ino
                            and after_info.st_ino != opened_info.st_ino
                        )
                    ):
                        raise ModelAcquisitionError(
                            "snapshot file changed while it was being hashed"
                        )
            except OSError as exc:
                raise ModelAcquisitionError("snapshot file cannot be read") from exc
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if lfs_digest is not None and lfs_digest.hexdigest() != expected_file["lfs_sha256"]:
                raise ModelAcquisitionError("snapshot LFS content does not match upstream metadata")
            if git_digest is not None and git_digest.hexdigest() != expected_file["blob_id"]:
                raise ModelAcquisitionError("snapshot Git blob does not match upstream metadata")
        digest.update(b"\0")
    if file_count == 0:
        raise ModelAcquisitionError("snapshot contains no files")
    return SnapshotSeal(
        tree_sha256=digest.hexdigest(),
        inventory_sha256=inventory.hexdigest(),
        file_count=file_count,
        total_bytes=total_bytes,
    )


def _utc_timestamp(value: dt.datetime | None = None) -> str:
    current = value or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ModelAcquisitionError("completion time must be timezone-aware")
    return current.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def retain_snapshot_verification(
    root: Path | str, evidence: SnapshotSeal, *, upstream_manifest: Mapping[str, Any]
) -> None:
    """Retain a verified content identity for inexpensive reuse of installed bytes."""
    snapshot = _checked_snapshot_root(root)
    manifest = validate_upstream_manifest(dict(upstream_manifest))
    if not isinstance(evidence, SnapshotSeal):
        raise ModelAcquisitionError("saved verification must be a snapshot seal")
    for key in ("tree_sha256", "inventory_sha256"):
        _validated_sha256(getattr(evidence, key), label="saved " + key)
    if (evidence.file_count != len(manifest["files"])
            or evidence.total_bytes != manifest["total_bytes"]):
        raise ModelAcquisitionError("saved verification does not match the complete manifest")
    value = {"schema": "ura-installed-model-verification/1",
        "manifest_sha256": upstream_manifest_sha256(manifest),
        "seal": {key: getattr(evidence, key) for key in
                 ("tree_sha256", "inventory_sha256", "file_count", "total_bytes")}}
    raw = _canonical_bytes(value)
    path = snapshot.parent / "snapshot-verification.json"
    if path.exists():
        if _read_contained_regular_file(path, parent=snapshot.parent, label="saved model verification") == raw:
            return
    temporary = snapshot.parent / (".snapshot-verification-" + secrets.token_hex(8) + ".tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def reuse_snapshot_verification(
    root: Path | str, *, upstream_manifest: Mapping[str, Any],
    cancelled: Callable[[], bool] | None = None,
) -> SnapshotSeal:
    """Check saved identity and current metadata; do not claim a fresh byte hash."""
    snapshot = _checked_snapshot_root(root)
    manifest = validate_upstream_manifest(dict(upstream_manifest))
    try:
        raw = _read_contained_regular_file(snapshot.parent / "snapshot-verification.json",
            parent=snapshot.parent, label="saved model verification")
    except ModelAcquisitionError as exc:
        raise ModelAcquisitionError(
            "installed model has no saved verification; reuse its acquisition receipt "
            "or opt in to --verify-model-sha256 once") from exc
    value = strict_json_bytes(raw)
    if (not isinstance(value, dict) or set(value) != {"schema", "manifest_sha256", "seal"}
            or value["schema"] != "ura-installed-model-verification/1"
            or value["manifest_sha256"] != upstream_manifest_sha256(manifest)):
        raise ModelAcquisitionError("saved model verification manifest differs")
    seal = value["seal"]
    if not isinstance(seal, dict) or set(seal) != {"tree_sha256", "inventory_sha256", "file_count", "total_bytes"}:
        raise ModelAcquisitionError("saved model verification fields differ")
    for key in ("tree_sha256", "inventory_sha256"):
        _validated_sha256(seal[key], label="saved " + key)
    current = seal_snapshot(snapshot, full_content=False, cancelled=cancelled)
    if (any(getattr(current, key) != seal[key] for key in ("inventory_sha256", "file_count", "total_bytes"))
            or current.file_count != len(manifest["files"]) or current.total_bytes != manifest["total_bytes"]):
        raise ModelAcquisitionError("installed model metadata changed since verification")
    return SnapshotSeal(**seal)


def build_receipt(
    plan: Mapping[str, Any],
    *,
    snapshots: Mapping[str, Path | str],
    manifests: Mapping[str, Mapping[str, Any]],
    completed_at: dt.datetime | None = None,
    max_files: int = MAX_SNAPSHOT_FILES,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
    cancelled: Callable[[], bool] | None = None,
    verified_snapshots: Mapping[str, SnapshotSeal] | None = None,
) -> dict[str, Any]:
    """Record acquired content identities, reusing supplied verified snapshots."""

    canonical = validate_plan(dict(plan))
    expected_ids = {resource["resource_id"] for resource in canonical["resources"]}
    if set(snapshots) != expected_ids or set(manifests) != expected_ids:
        raise ModelAcquisitionError("receipt snapshots/manifests must match the plan exactly")
    sealed: list[dict[str, Any]] = []
    for resource in canonical["resources"]:
        resource_id = resource["resource_id"]
        manifest = validate_upstream_manifest(dict(manifests[resource_id]))
        if (
            manifest["repo_id"] != resource["repo_id"]
            or manifest["revision"] != resource["revision"]
            or manifest["file_policy"] != resource["file_policy"]
        ):
            raise ModelAcquisitionError("upstream manifest does not match the plan resource")
        if verified_snapshots is None:
            evidence = seal_snapshot(
                snapshots[resource_id], max_files=max_files, max_bytes=max_bytes,
                cancelled=cancelled, upstream_manifest=manifest,
            )
        else:
            evidence = verified_snapshots.get(resource_id)
            if not isinstance(evidence, SnapshotSeal):
                raise ModelAcquisitionError("verified snapshot is missing")
            current = seal_snapshot(
                snapshots[resource_id], full_content=False, max_files=max_files,
                max_bytes=max_bytes, cancelled=cancelled,
            )
            if any(getattr(current, key) != getattr(evidence, key) for key in
                   ("inventory_sha256", "file_count", "total_bytes")):
                raise ModelAcquisitionError("snapshot metadata changed before receipt publication")
            _validated_sha256(evidence.tree_sha256, label="verified tree SHA-256")
        if (
            evidence.file_count != len(manifest["files"])
            or evidence.total_bytes != manifest["total_bytes"]
        ):
            raise ModelAcquisitionError(
                "downloaded snapshot does not contain the complete upstream manifest"
            )
        sealed.append(
            {
                "file_count": evidence.file_count,
                "inventory_sha256": evidence.inventory_sha256,
                "repo_id": resource["repo_id"],
                "resource_id": resource_id,
                "revision": resource["revision"],
                "roles": resource["roles"],
                "storage": "managed_store",
                "total_bytes": evidence.total_bytes,
                "tree_sha256": evidence.tree_sha256,
                "upstream_manifest_id": manifest["manifest_id"],
                "upstream_manifest_sha256": upstream_manifest_sha256(manifest),
            }
        )
    body: dict[str, Any] = {
        "completed_at": _utc_timestamp(completed_at),
        "plan_id": canonical["plan_id"],
        "plan_sha256": plan_sha256(canonical),
        "resources": sealed,
        "schema": RECEIPT_SCHEMA,
    }
    body["receipt_id"] = "acquisition-receipt-" + _sha256_bytes(body)[:32]
    return body


def validate_receipt(
    value: object,
    *,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate receipt structure and immutable plan/resource binding."""

    canonical_plan = validate_plan(dict(plan))
    if not isinstance(value, dict) or set(value) != {
        "completed_at",
        "plan_id",
        "plan_sha256",
        "receipt_id",
        "resources",
        "schema",
    }:
        raise ModelAcquisitionError("acquisition receipt has unknown or missing fields")
    if value.get("schema") != RECEIPT_SCHEMA:
        raise ModelAcquisitionError("unsupported acquisition receipt schema")
    if value.get("plan_id") != canonical_plan["plan_id"]:
        raise ModelAcquisitionError("acquisition receipt is bound to another plan")
    if value.get("plan_sha256") != plan_sha256(canonical_plan):
        raise ModelAcquisitionError("acquisition receipt plan digest is stale")
    timestamp = value.get("completed_at")
    if not isinstance(timestamp, str) or not timestamp.endswith("Z") or len(timestamp) > 40:
        raise ModelAcquisitionError("acquisition completion timestamp is invalid")
    try:
        parsed_timestamp = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ModelAcquisitionError("acquisition completion timestamp is invalid") from exc
    if parsed_timestamp.utcoffset() != dt.timedelta(0):
        raise ModelAcquisitionError("acquisition completion timestamp is not UTC")
    resources = value.get("resources")
    if not isinstance(resources, list) or len(resources) != len(canonical_plan["resources"]):
        raise ModelAcquisitionError("acquisition receipt resources do not match the plan")
    normalized_resources: list[dict[str, Any]] = []
    for expected, resource in zip(canonical_plan["resources"], resources, strict=True):
        if not isinstance(resource, dict) or set(resource) != {
            "file_count",
            "inventory_sha256",
            "repo_id",
            "resource_id",
            "revision",
            "roles",
            "storage",
            "total_bytes",
            "tree_sha256",
            "upstream_manifest_id",
            "upstream_manifest_sha256",
        }:
            raise ModelAcquisitionError("receipt resource has unknown or missing fields")
        for field in ("repo_id", "resource_id", "revision", "roles"):
            if resource.get(field) != expected[field]:
                raise ModelAcquisitionError("receipt resource identity does not match the plan")
        if resource.get("storage") not in STORAGE_KINDS:
            raise ModelAcquisitionError("receipt storage kind is invalid")
        _validated_sha256(resource.get("tree_sha256"), label="snapshot tree SHA-256")
        _validated_sha256(
            resource.get("inventory_sha256"), label="snapshot inventory SHA-256"
        )
        _validated_sha256(
            resource.get("upstream_manifest_sha256"),
            label="upstream manifest SHA-256",
        )
        manifest_id = resource.get("upstream_manifest_id")
        if not isinstance(manifest_id, str) or _MANIFEST_ID.fullmatch(manifest_id) is None:
            raise ModelAcquisitionError("receipt upstream manifest ID is invalid")
        file_count = resource.get("file_count")
        total_bytes = resource.get("total_bytes")
        if (
            isinstance(file_count, bool)
            or not isinstance(file_count, int)
            or not 1 <= file_count <= MAX_SNAPSHOT_FILES
            or isinstance(total_bytes, bool)
            or not isinstance(total_bytes, int)
            or not 0 <= total_bytes <= MAX_SNAPSHOT_BYTES
        ):
            raise ModelAcquisitionError("receipt snapshot bounds are invalid")
        normalized_resources.append(dict(resource))
    body = {
        "completed_at": timestamp,
        "plan_id": canonical_plan["plan_id"],
        "plan_sha256": plan_sha256(canonical_plan),
        "resources": normalized_resources,
        "schema": RECEIPT_SCHEMA,
    }
    expected_receipt_id = "acquisition-receipt-" + _sha256_bytes(body)[:32]
    receipt_id = value.get("receipt_id")
    if (
        not isinstance(receipt_id, str)
        or _RECEIPT_ID.fullmatch(receipt_id) is None
        or receipt_id != expected_receipt_id
    ):
        raise ModelAcquisitionError("acquisition receipt ID is invalid or stale")
    body["receipt_id"] = receipt_id
    return body


def load_receipt(
    path: Path | str,
    *,
    expected_sha256: str,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    return validate_receipt(
        load_document(path, expected_sha256=expected_sha256, kind="acquisition receipt"),
        plan=plan,
    )


def verify_receipt_snapshots(
    plan: Mapping[str, Any],
    receipt: Mapping[str, Any],
    *,
    managed_store: Path | str,
    max_files: int = MAX_SNAPSHOT_FILES,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
    cancelled: Callable[[], bool] | None = None,
    verify_sha256: bool = False,
) -> dict[str, Path]:
    """Resolve every receipted snapshot from the managed offline store.

    Normal reuse checks the installed file inventory against the retained
    receipt without rereading weights. Full content verification is opt-in.
    Inventory checking does not claim to detect same-size modifications whose
    timestamps have also been restored.
    """

    canonical_plan = validate_plan(dict(plan))
    if type(verify_sha256) is not bool:
        raise ModelAcquisitionError("model SHA verification option must be boolean")
    canonical_receipt = validate_receipt(dict(receipt), plan=canonical_plan)
    store = _checked_snapshot_root(managed_store)
    resolved: dict[str, Path] = {}
    for resource in canonical_receipt["resources"]:
        resource_id = resource["resource_id"]
        resource_candidate = store / resource_id
        if not resource_candidate.exists() and not _is_link_or_junction(resource_candidate):
            raise CacheMissError(f"receipted snapshot {resource_id} is absent from cache")
        resource_root, resource_identity = _checked_direct_child_directory(
            store,
            resource_id,
            label=f"managed resource {resource_id}",
        )
        path, snapshot_identity = _checked_direct_child_directory(
            resource_root,
            "snapshot",
            label=f"managed snapshot {resource_id}",
        )
        manifest_path = resource_root / (
            resource["upstream_manifest_id"] + ".upstream-manifest.json"
        )
        manifest_raw = _read_contained_regular_file(
            manifest_path,
            parent=resource_root,
            label=f"managed upstream manifest {resource_id}",
        )
        manifest_value = strict_json_bytes(manifest_raw)
        manifest = validate_upstream_manifest(manifest_value)
        if (
            manifest["repo_id"] != resource["repo_id"]
            or manifest["revision"] != resource["revision"]
            or manifest["manifest_id"] != resource["upstream_manifest_id"]
            or upstream_manifest_sha256(manifest)
            != resource["upstream_manifest_sha256"]
        ):
            raise ModelAcquisitionError(
                f"receipted snapshot {resource_id} manifest changed after acquisition"
            )
        evidence = seal_snapshot(
            path,
            max_files=max_files,
            max_bytes=max_bytes,
            cancelled=cancelled,
            full_content=verify_sha256,
        )
        resource_after, resource_identity_after = _checked_direct_child_directory(
            store,
            resource_id,
            label=f"managed resource {resource_id}",
        )
        snapshot_after, snapshot_identity_after = _checked_direct_child_directory(
            resource_after,
            "snapshot",
            label=f"managed snapshot {resource_id}",
        )
        if (
            resource_after != resource_root
            or snapshot_after != path
            or resource_identity_after != resource_identity
            or snapshot_identity_after != snapshot_identity
        ):
            raise ModelAcquisitionError(
                f"receipted snapshot {resource_id} changed directory identity during verification"
            )
        manifest_after = _read_contained_regular_file(
            resource_after
            / (resource["upstream_manifest_id"] + ".upstream-manifest.json"),
            parent=resource_after,
            label=f"managed upstream manifest {resource_id}",
        )
        if manifest_after != manifest_raw:
            raise ModelAcquisitionError(
                f"receipted snapshot {resource_id} manifest changed during verification"
            )
        if (
            evidence.inventory_sha256 != resource["inventory_sha256"]
            or evidence.file_count != resource["file_count"]
            or evidence.total_bytes != resource["total_bytes"]
            or (verify_sha256 and evidence.tree_sha256 != resource["tree_sha256"])
        ):
            raise ModelAcquisitionError(
                f"receipted snapshot {resource_id} changed after acquisition"
            )
        resolved[resource_id] = path
    return resolved


def retain_receipt_verification(
    plan: Mapping[str, Any], receipt: Mapping[str, Any], *, managed_store: Path | str,
) -> None:
    """Migrate a retained acquisition receipt to the installed-model cache.

    Existing content hashes remain historical evidence. Current file metadata
    must still match; this operation neither downloads nor hashes model bytes.
    """
    canonical = validate_receipt(dict(receipt), plan=plan)
    resolved = verify_receipt_snapshots(plan, canonical, managed_store=managed_store)
    for resource in canonical["resources"]:
        snapshot = resolved[resource["resource_id"]]
        manifest = strict_json_bytes(_read_contained_regular_file(
            snapshot.parent / (resource["upstream_manifest_id"] + ".upstream-manifest.json"),
            parent=snapshot.parent, label="managed upstream manifest",
        ))
        evidence = SnapshotSeal(**{key: resource[key] for key in
            ("tree_sha256", "inventory_sha256", "file_count", "total_bytes")})
        retain_snapshot_verification(snapshot, evidence, upstream_manifest=manifest)


def write_document_create_only(
    directory: Path | str,
    document: Mapping[str, Any],
    *,
    identifier: str,
    suffix: str,
) -> tuple[Path, str]:
    """Publish canonical JSON exactly once under its content-derived ID."""

    if (
        not isinstance(identifier, str)
        or not (
            _PLAN_ID.fullmatch(identifier)
            or _RECEIPT_ID.fullmatch(identifier)
            or _MANIFEST_ID.fullmatch(identifier)
        )
    ):
        raise ModelAcquisitionError("document identifier is invalid")
    if not isinstance(suffix, str) or re.fullmatch(r"[a-z0-9.-]{1,48}", suffix) is None:
        raise ModelAcquisitionError("document suffix is invalid")
    root = Path(directory)
    if not root.is_absolute() or _is_link_or_junction(root):
        raise ModelAcquisitionError(
            "document directory must be a non-link, non-junction absolute path"
        )
    try:
        root.mkdir(parents=True, exist_ok=True)
        checked_root = root.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError("document directory cannot be prepared") from exc
    root_info = root.lstat()
    if (
        checked_root != root
        or _is_link_or_junction(root)
        or not stat.S_ISDIR(root_info.st_mode)
    ):
        raise ModelAcquisitionError("document directory is not one resolved directory")
    raw = _canonical_bytes(document) + b"\n"
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise ModelAcquisitionError("document exceeds its byte bound")
    target = checked_root / f"{identifier}.{suffix}"
    temporary = checked_root / f".{identifier}.{secrets.token_hex(12)}.tmp"
    descriptor: int | None = None
    temporary_exists = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        temporary_exists = True
        opened = os.fstat(descriptor)
        named = temporary.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _filesystem_identity(opened) != _filesystem_identity(named)
            or _is_link_or_junction(temporary)
        ):
            raise ModelAcquisitionError("temporary completion document is unsafe")
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-link publication is create-only.  Unlike replace(), it cannot
        # silently overwrite a receipt another concurrent job just published.
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError:
            existing = _read_contained_regular_file(
                target,
                parent=checked_root,
                label="existing completion document",
            )
            if existing != raw:
                raise ModelAcquisitionError(
                    "content-addressed document path already differs"
                )
        else:
            temporary.unlink()
            temporary_exists = False
            existing = _read_contained_regular_file(
                target,
                parent=checked_root,
                label="published completion document",
            )
            if existing != raw:
                raise ModelAcquisitionError("published completion document differs")
        return target, hashlib.sha256(raw).hexdigest()
    except OSError as exc:
        raise ModelAcquisitionError("completion document cannot be published") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            if temporary_exists:
                temporary.unlink(missing_ok=True)
        except OSError:
            pass


__all__ = [
    "CacheMissError",
    "HubRequirement",
    "MAX_SNAPSHOT_BYTES",
    "MAX_SNAPSHOT_FILES",
    "ModelAcquisitionError",
    "PLAN_SCHEMA",
    "RECEIPT_SCHEMA",
    "UPSTREAM_MANIFEST_SCHEMA",
    "SnapshotSeal",
    "build_plan",
    "build_receipt",
    "build_upstream_manifest",
    "guardrail_requirement",
    "hub_requirement",
    "load_plan",
    "load_receipt",
    "nanogcg_requirement",
    "plan_sha256",
    "seal_snapshot",
    "strict_json_bytes",
    "upstream_manifest_sha256",
    "validate_plan",
    "validate_receipt",
    "validate_repo_filename",
    "validate_repo_id",
    "validate_revision",
    "validate_upstream_manifest",
    "verify_receipt_snapshots",
    "vllm_requirement",
    "write_document_create_only",
]
