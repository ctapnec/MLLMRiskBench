"""Typed boundary for result-producing external engines.

Some upstream systems are complete evaluators rather than prompt generators.  A
URA ``BaseAttacker`` cannot faithfully wrap such a system: replaying its prompts
through ``Runner`` would make a second target call, discard the upstream response
and judge, and silently change the estimand.  These models retain the native run
as a source-specific artifact family instead.

The original files remain authoritative.  Every imported run records resolved
paths, byte counts and SHA-256 digests, while each case records a digest and a
locator into those files.  ``common_metric_eligible`` and
``runner_replay_eligible`` are hard-coded false so a downstream consumer cannot
mistake source-native classifications, agent-task checks, or audit dimensions
for URA's common ASR/FRR labels.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ._engine_common import ExternalEngineOutputError


NATIVE_RUN_SCHEMA = "ura-native-engine-run/1"
DEFAULT_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_RUN_ARTIFACT_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_RUN_ARTIFACT_FILES = 256
DEFAULT_MAX_JSON_NODES = 2_000_000
DEFAULT_MAX_JSON_DEPTH = 64


class NativeArtifactFile(BaseModel):
    """Integrity descriptor for one authoritative upstream artifact."""

    model_config = ConfigDict(extra="forbid")

    role: str
    path: str
    sha256: str
    bytes: int = Field(ge=1)
    records: int = Field(ge=1)

    @field_validator("sha256")
    @classmethod
    def _full_sha256(cls, value: str) -> str:
        digest = value.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("native artifact digest must be a full SHA-256")
        return digest


class NativeEngineCase(BaseModel):
    """One source-native evaluation case without a fabricated common label."""

    model_config = ConfigDict(extra="forbid")

    id: str
    source_run_id: str
    target_model: str
    attack_method: str
    original_input: Any
    adversarial_input: str | None = None
    target_outputs: list[str] = Field(default_factory=list)
    native_outcome: str
    native_scores: dict[str, int | float] = Field(default_factory=dict)
    native_details: dict[str, Any] = Field(default_factory=dict)
    source_artifact_role: str
    source_record: str
    source_record_sha256: str

    @field_validator(
        "id",
        "source_run_id",
        "target_model",
        "attack_method",
        "native_outcome",
        "source_artifact_role",
        "source_record",
    )
    @classmethod
    def _nonblank_identifiers(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("native case identifiers must not be blank")
        return value

    @field_validator("source_record_sha256")
    @classmethod
    def _record_sha256(cls, value: str) -> str:
        digest = value.lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("native record digest must be a full SHA-256")
        return digest


class NativeEngineRun(BaseModel):
    """Normalized envelope around a complete source-native evaluator run."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())

    integration_schema: Literal["ura-native-engine-run/1"] = NATIVE_RUN_SCHEMA
    engine: Literal[
        "fuzzyai",
        "petri",
        "asb",
        "agentdojo",
        "autodan_turbo",
        "giskard_v2_scan",
        "giskard_v2_raget",
        "easyjailbreak",
        "garak",
        "promptfoo",
    ]
    integration_mode: Literal["native_artifact_import"] = "native_artifact_import"
    native_schema: str
    native_run_id: str
    upstream_repository: str
    upstream_version: str | None = None
    upstream_revision: str | None = None
    source_artifacts: list[NativeArtifactFile]
    target_models: list[str]
    model_roles: dict[str, str] = Field(default_factory=dict)
    cases: list[NativeEngineCase]
    native_aggregates: dict[str, Any] = Field(default_factory=dict)
    import_accounting: dict[str, int | float] = Field(default_factory=dict)
    measurement_semantics: str
    common_metric_eligible: Literal[False] = False
    runner_replay_eligible: Literal[False] = False

    @model_validator(mode="after")
    def _complete_native_run(self) -> "NativeEngineRun":
        if not self.native_schema.strip():
            raise ValueError("native_schema must not be blank")
        if not self.native_run_id.strip():
            raise ValueError("native_run_id must not be blank")
        if not self.source_artifacts:
            raise ValueError("a native run requires source artifacts")
        if len(self.source_artifacts) > DEFAULT_MAX_RUN_ARTIFACT_FILES:
            raise ValueError(
                "native run exceeds the source-artifact file-count limit"
            )
        if sum(artifact.bytes for artifact in self.source_artifacts) > (
            DEFAULT_MAX_RUN_ARTIFACT_BYTES
        ):
            raise ValueError(
                "native run exceeds the aggregate source-artifact byte limit"
            )
        if not self.target_models or any(
            not model.strip() for model in self.target_models
        ):
            raise ValueError("a native run requires nonblank target model identities")
        if not self.cases:
            raise ValueError("a native run requires at least one case")
        if not self.measurement_semantics.strip():
            raise ValueError("measurement_semantics must not be blank")
        return self


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON data deterministically for per-record lineage digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def strict_json_loads(text: str) -> Any:
    """Parse bounded-complexity JSON and reject duplicate/non-finite values."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON numeric constant {value!r}")

    def object_without_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key {key!r}")
            value[key] = item
        return value

    value = json.loads(
        text,
        parse_constant=reject_constant,
        object_pairs_hook=object_without_duplicates,
    )
    nodes = 0
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > DEFAULT_MAX_JSON_NODES:
            raise ValueError(
                f"JSON artifact exceeds {DEFAULT_MAX_JSON_NODES} value nodes"
            )
        if depth > DEFAULT_MAX_JSON_DEPTH:
            raise ValueError(
                f"JSON artifact nesting exceeds {DEFAULT_MAX_JSON_DEPTH}"
            )
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("JSON artifact contains a non-finite number")
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _resolved_without_symlinks(path: Path) -> tuple[Path, os.stat_result]:
    """Resolve an existing artifact while rejecting symlinked path components."""

    candidate = Path(path).expanduser().absolute()
    current = Path(candidate.anchor)
    try:
        for part in candidate.parts[1:]:
            current /= part
            if current.is_symlink():
                raise ExternalEngineOutputError(
                    f"native artifact path contains a symbolic link: {current}"
                )
        resolved = candidate.resolve(strict=True)
        observed = os.stat(resolved, follow_symlinks=False)
    except ExternalEngineOutputError:
        raise
    except OSError as exc:
        raise ExternalEngineOutputError(
            f"native artifact cannot be resolved: {path}"
        ) from exc
    if not stat.S_ISREG(observed.st_mode):
        raise ExternalEngineOutputError(
            f"native artifact is not a regular file: {resolved}"
        )
    return resolved, observed


def _read_stable_artifact(
    path: Path,
    *,
    max_bytes: int,
    collect: bool,
) -> tuple[Path, bytes | None, str, int]:
    """Read/hash one descriptor and reject symlinks, growth, or replacement."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    resolved, path_stat = _resolved_without_symlinks(path)
    if path_stat.st_size < 1:
        raise ExternalEngineOutputError(f"native artifact is empty: {resolved}")
    if path_stat.st_size > max_bytes:
        raise ExternalEngineOutputError(
            f"native artifact exceeds the {max_bytes}-byte import limit: {resolved}"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = hashlib.sha256()
    chunks: list[bytes] | None = [] if collect else None
    total = 0
    try:
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ExternalEngineOutputError(
                    f"native artifact is not a regular file: {resolved}"
                )
            if (
                before.st_dev != path_stat.st_dev
                or before.st_ino != path_stat.st_ino
                or before.st_size != path_stat.st_size
            ):
                raise ExternalEngineOutputError(
                    f"native artifact changed before it could be read: {resolved}"
                )
            while True:
                chunk = handle.read(min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ExternalEngineOutputError(
                        f"native artifact exceeds the {max_bytes}-byte import limit: "
                        f"{resolved}"
                    )
                digest.update(chunk)
                if chunks is not None:
                    chunks.append(chunk)
            after = os.fstat(handle.fileno())
        current = os.stat(resolved, follow_symlinks=False)
    except ExternalEngineOutputError:
        raise
    except OSError as exc:
        raise ExternalEngineOutputError(
            f"native artifact could not be read safely: {resolved}"
        ) from exc

    identity = (before.st_dev, before.st_ino)
    stable = (
        identity == (after.st_dev, after.st_ino)
        == (current.st_dev, current.st_ino)
        and before.st_size == after.st_size == current.st_size == total
        and before.st_mtime_ns == after.st_mtime_ns == current.st_mtime_ns
    )
    if not stable:
        raise ExternalEngineOutputError(
            f"native artifact changed while it was being read: {resolved}"
        )
    return (
        resolved,
        b"".join(chunks) if chunks is not None else None,
        digest.hexdigest(),
        total,
    )


def describe_artifact(
    path: Path,
    *,
    role: str,
    records: int,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> NativeArtifactFile:
    """Bound and stream-hash an already-validated, non-empty artifact."""

    resolved, _, digest, size = _read_stable_artifact(
        path, max_bytes=max_bytes, collect=False
    )
    return NativeArtifactFile(
        role=role,
        path=str(resolved),
        sha256=digest,
        bytes=size,
        records=records,
    )


def read_utf8_artifact(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> tuple[Path, bytes, str]:
    """Read one bounded UTF-8 artifact and reject empty/oversized input."""

    resolved, data, _, _ = _read_stable_artifact(
        path, max_bytes=max_bytes, collect=True
    )
    assert data is not None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExternalEngineOutputError(
            f"native artifact is not valid UTF-8: {resolved}"
        ) from exc
    return resolved, data, text


def read_binary_artifact(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> tuple[Path, bytes]:
    """Read a bounded opaque artifact without interpreting or executing it.

    This is primarily for native engines that persist Python pickles alongside
    auditable JSON exports.  Importers may hash and retain those files as lineage,
    but must never deserialize untrusted pickle content.
    """

    resolved, data, _, _ = _read_stable_artifact(
        path, max_bytes=max_bytes, collect=True
    )
    assert data is not None
    return resolved, data


def require_expected_sha256(data: bytes, expected: str | None, *, role: str) -> str:
    """Return the content digest and optionally enforce a pre-registered value."""

    digest = hashlib.sha256(data).hexdigest()
    if expected is not None:
        normalized = expected.lower()
        if len(normalized) != 64 or any(
            char not in "0123456789abcdef" for char in normalized
        ):
            raise ValueError(f"expected {role} SHA-256 must contain 64 hex characters")
        if digest != normalized:
            raise ExternalEngineOutputError(
                f"{role} SHA-256 mismatch: expected {normalized}, observed {digest}"
            )
    return digest


__all__ = [
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "DEFAULT_MAX_RUN_ARTIFACT_BYTES",
    "DEFAULT_MAX_RUN_ARTIFACT_FILES",
    "NATIVE_RUN_SCHEMA",
    "NativeArtifactFile",
    "NativeEngineCase",
    "NativeEngineRun",
    "canonical_json_bytes",
    "describe_artifact",
    "json_sha256",
    "read_binary_artifact",
    "read_utf8_artifact",
    "require_expected_sha256",
    "strict_json_loads",
]
