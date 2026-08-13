"""Compact, fail-closed receipts for acquired benchmark source arms.

The operator receipt contains only facts that cannot be reconstructed from a
converted corpus: upstream identity, the exact consumed input, raw-record
accounting, an access/license decision, and a bounded semantic review.  Rich
converted, cluster, policy, metric, and media inventories remain runtime
observations; duplicating them in a second operator-maintained schema would
create drift without adding evidence.

Passing this contract establishes acquisition/conversion traceability only.  It
is not legal advice, benchmark validation, evaluator validation, or a result.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .converters._common import canonical_converted_corpus_sha256
from .data_models import DataPoint, MediaRef


SOURCE_CONFORMANCE_SCHEMA = "ura-source-conformance/1"
CLUSTER_RULE = "source_cluster_id_else_datapoint_id/v1"
_HEX = frozenset("0123456789abcdef")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def canonical_json_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _nonblank(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be a non-blank, unpadded string")
    return value


def _sha256(value: str, field: str) -> str:
    value = _nonblank(value, field).lower()
    if len(value) != 64 or any(char not in _HEX for char in value):
        raise ValueError(f"{field} must be a full SHA-256 digest")
    return value


def _timestamp(value: str, field: str) -> str:
    value = _nonblank(value, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value


def _https_uri(value: str, field: str) -> str:
    value = _nonblank(value, field)
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.netloc or parsed.username
        or parsed.password or parsed.query or parsed.fragment
    ):
        raise ValueError(
            f"{field} must be a credential-, query-, and fragment-free HTTPS URI"
        )
    return value


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ConsumedInput(_StrictModel):
    """Exact regular file consumed, or the directory that the converter opens.

    A directory is not recursively rehashed here: large media trees can be
    hundreds of GB.  Its converted rows and every admitted media digest are
    instead re-derived and bound by :func:`observed_arm_conformance`.
    """

    kind: Literal["file", "directory"]
    sha256: str | None = None
    bytes: int | None = Field(default=None, ge=1)

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str | None) -> str | None:
        return None if value is None else _sha256(value, "consumed_input.sha256")

    @model_validator(mode="after")
    def _shape(self) -> "ConsumedInput":
        if self.kind == "file" and (self.sha256 is None or self.bytes is None):
            raise ValueError("file consumed_input requires sha256 and bytes")
        if self.kind == "directory" and (
            self.sha256 is not None or self.bytes is not None
        ):
            raise ValueError(
                "directory consumed_input is bound by converted/runtime evidence"
            )
        return self


class Component(_StrictModel):
    role: str
    path_env: str
    sha256: str
    bytes: int = Field(ge=1)

    @field_validator("role")
    @classmethod
    def _role(cls, value: str) -> str:
        return _nonblank(value, "component.role")

    @field_validator("path_env")
    @classmethod
    def _env(cls, value: str) -> str:
        value = _nonblank(value, "component.path_env")
        if _ENV_NAME.fullmatch(value) is None:
            raise ValueError("component.path_env must name an environment variable")
        return value

    @field_validator("sha256")
    @classmethod
    def _digest(cls, value: str) -> str:
        return _sha256(value, "component.sha256")


class OperatorDecision(_StrictModel):
    decision: Literal["approved", "rejected", "pending"]
    access_status: Literal["granted", "not_required", "denied", "pending"]
    license_identifier_or_notice: str
    reviewer: str
    reviewed_at: str
    evidence_sha256: str
    notes: str

    @field_validator("license_identifier_or_notice", "reviewer", "notes")
    @classmethod
    def _text(cls, value: str, info) -> str:
        return _nonblank(value, f"operator_decision.{info.field_name}")

    @field_validator("reviewed_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _timestamp(value, "operator_decision.reviewed_at")

    @field_validator("evidence_sha256")
    @classmethod
    def _evidence(cls, value: str) -> str:
        return _sha256(value, "operator_decision.evidence_sha256")


class RawRecordAccounting(_StrictModel):
    discovered: int = Field(ge=0)
    accepted: int = Field(ge=0)
    excluded_by_design: int = Field(ge=0)
    rejected_invalid: int = Field(ge=0)
    reasons: dict[str, int]

    @model_validator(mode="after")
    def _reconcile(self) -> "RawRecordAccounting":
        if self.discovered != (
            self.accepted + self.excluded_by_design + self.rejected_invalid
        ):
            raise ValueError("raw-record accounting does not reconcile")
        if any(
            not isinstance(reason, str) or not reason.strip() or count < 0
            for reason, count in self.reasons.items()
        ):
            raise ValueError("raw-record reasons require nonblank keys/nonnegative counts")
        if sum(self.reasons.values()) != (
            self.excluded_by_design + self.rejected_invalid
        ):
            raise ValueError("raw-record reason counts do not reconcile")
        return self


class SemanticReview(_StrictModel):
    status: Literal["passed", "failed", "pending"]
    reviewer: str
    reviewed_at: str
    selection_rule: str
    reviewed_cluster_ids: list[str]
    reviewed_converted_corpus_sha256: str
    notes: str

    @field_validator("reviewer", "selection_rule", "notes")
    @classmethod
    def _text(cls, value: str, info) -> str:
        return _nonblank(value, f"semantic_review.{info.field_name}")

    @field_validator("reviewed_at")
    @classmethod
    def _time(cls, value: str) -> str:
        return _timestamp(value, "semantic_review.reviewed_at")

    @field_validator("reviewed_converted_corpus_sha256")
    @classmethod
    def _digest(cls, value: str, info) -> str:
        return _sha256(value, f"semantic_review.{info.field_name}")

    @model_validator(mode="after")
    def _passing(self) -> "SemanticReview":
        if any(
            not isinstance(item, str) or not item.strip() or item != item.strip()
            for item in self.reviewed_cluster_ids
        ):
            raise ValueError("semantic review cluster ids must be nonblank/unpadded")
        if len(self.reviewed_cluster_ids) != len(set(self.reviewed_cluster_ids)):
            raise ValueError("semantic review cluster ids must be unique")
        if self.status == "passed" and not self.reviewed_cluster_ids:
            raise ValueError("passed semantic review requires reviewed clusters")
        return self


class ArmReceipt(_StrictModel):
    arm_id: str
    converter: str
    path_env: str
    source_label: str | None = None
    split: str | None = None
    disposition: Literal["admitted", "blocked", "not_selected"]
    reason: str
    upstream_uri: str | None = None
    requested_revision: str | None = None
    observed_revision: str | None = None
    consumed_input: ConsumedInput | None = None
    components: list[Component] = Field(default_factory=list)
    operator_decision: OperatorDecision | None = None
    raw_records: RawRecordAccounting | None = None
    semantic_review: SemanticReview | None = None

    @field_validator("arm_id", "converter", "path_env", "reason")
    @classmethod
    def _labels(cls, value: str, info) -> str:
        value = _nonblank(value, f"arm.{info.field_name}")
        if info.field_name == "path_env" and _ENV_NAME.fullmatch(value) is None:
            raise ValueError("arm.path_env must name an environment variable")
        return value

    @field_validator("source_label", "split")
    @classmethod
    def _optional_text(cls, value: str | None, info) -> str | None:
        return None if value is None else _nonblank(value, f"arm.{info.field_name}")

    @field_validator("upstream_uri")
    @classmethod
    def _uri(cls, value: str | None) -> str | None:
        return None if value is None else _https_uri(value, "arm.upstream_uri")

    @field_validator("requested_revision", "observed_revision")
    @classmethod
    def _revision(cls, value: str | None, info) -> str | None:
        if value is None:
            return None
        value = _nonblank(value, f"arm.{info.field_name}").lower()
        if len(value) < 7 or len(value) > 128 or any(char.isspace() for char in value):
            raise ValueError(f"arm.{info.field_name} is not a bounded revision")
        return value

    @model_validator(mode="after")
    def _admission(self) -> "ArmReceipt":
        evidence = (
            self.upstream_uri, self.requested_revision, self.observed_revision,
            self.consumed_input, self.operator_decision, self.raw_records,
            self.semantic_review,
        )
        if self.disposition == "admitted":
            if any(item is None for item in evidence):
                raise ValueError(f"admitted arm {self.arm_id!r} lacks receipt evidence")
            if self.requested_revision != self.observed_revision:
                raise ValueError("admitted arm requested/observed revisions differ")
            if self.operator_decision.decision != "approved":
                raise ValueError("admitted arm requires approved operator decision")
            if self.operator_decision.access_status not in {
                "granted", "not_required"
            }:
                raise ValueError("admitted arm requires granted/not-required access")
            if self.raw_records.accepted <= 0:
                raise ValueError("admitted arm requires accepted raw records")
            if self.semantic_review.status != "passed":
                raise ValueError("admitted arm requires passed semantic review")
            if self.consumed_input.kind == "directory" and not self.components:
                raise ValueError(
                    "directory-backed admitted arm requires a declared exact-file "
                    "release component"
                )
        elif any(item is not None for item in evidence) or self.components:
            raise ValueError(
                "blocked/not-selected arms retain only disposition and reason"
            )
        envs = [component.path_env for component in self.components]
        if len(envs) != len(set(envs)):
            raise ValueError(f"arm {self.arm_id!r} repeats a component path_env")
        return self


class SourceConformanceManifest(_StrictModel):
    schema_name: Literal["ura-source-conformance/1"] = Field(alias="schema")
    claim_scope: Literal["acquisition_and_conversion_traceability_only"]
    arms: list[ArmReceipt]

    @model_validator(mode="after")
    def _arms(self) -> "SourceConformanceManifest":
        arm_ids = [arm.arm_id for arm in self.arms]
        if not arm_ids or len(arm_ids) != len(set(arm_ids)):
            raise ValueError("source receipt requires unique arms")
        return self


#: Placeholder marker written by the receipt scaffold for every operator
#: judgment field.  A receipt is rejected while any of them survives, so a
#: scaffold can never be renamed into an admissible receipt without the
#: operator actually supplying each judgment.
SCAFFOLD_SENTINEL = "OPERATOR_TODO"


def validate_source_conformance_manifest(value: object) -> dict[str, Any]:
    normalized = SourceConformanceManifest.model_validate(value).model_dump(
        mode="json", by_alias=True
    )
    serialized = json.dumps(normalized, ensure_ascii=False).lower()
    if SCAFFOLD_SENTINEL.lower() in serialized:
        raise ValueError(
            "source receipt retains scaffold placeholder text "
            f"({SCAFFOLD_SENTINEL}); complete every operator judgment field "
            "before validation"
        )
    return normalized


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file_from_env(path_env: str) -> Path:
    configured = os.environ.get(path_env)
    if configured is None or not configured.strip():
        raise ValueError(f"receipt requires nonblank environment {path_env}")
    unresolved = Path(configured).expanduser()
    if unresolved.is_symlink():
        raise ValueError(f"receipt input {path_env} must not be a symlink")
    path = unresolved.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"receipt component {path_env} is not a regular file")
    return path


def _verify_component(component: Mapping[str, Any]) -> None:
    path = _regular_file_from_env(str(component["path_env"]))
    if path.stat().st_size != component["bytes"]:
        raise ValueError(f"receipt component {component['path_env']} byte mismatch")
    if _sha256_file(path) != component["sha256"]:
        raise ValueError(f"receipt component {component['path_env']} hash mismatch")


def _verify_consumed_input(arm: Mapping[str, Any]) -> dict[str, object]:
    path_env = str(arm["path_env"])
    configured = os.environ.get(path_env)
    if configured is None or not configured.strip():
        raise ValueError(f"receipt requires nonblank environment {path_env}")
    unresolved = Path(configured).expanduser()
    if unresolved.is_symlink():
        raise ValueError(f"receipt input {path_env} must not be a symlink")
    path = unresolved.resolve(strict=True)
    declared = arm["consumed_input"]
    if declared["kind"] == "file":
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"receipt input {path_env} is not the declared file")
        size = path.stat().st_size
        digest = _sha256_file(path)
        if size != declared["bytes"] or digest != declared["sha256"]:
            raise ValueError(f"receipt consumed input {path_env} changed")
        return {"kind": "file", "sha256": digest, "bytes": size}
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"receipt input {path_env} is not the declared directory")
    return {"kind": "directory", "runtime_binding": "converted_corpus_and_media"}


def verify_manifest_components(
    manifest: Mapping[str, Any], *, selected_arms: Sequence[str] | None = None,
) -> list[str]:
    normalized = validate_source_conformance_manifest(manifest)
    arms_by_id = {arm["arm_id"]: arm for arm in normalized["arms"]}
    chosen = sorted(arms_by_id) if selected_arms is None else sorted(selected_arms)
    missing = sorted(set(chosen) - set(arms_by_id))
    if missing:
        raise ValueError(f"source receipt omits selected arms: {missing}")
    verified: list[str] = []
    for arm_id in chosen:
        arm = arms_by_id[arm_id]
        if arm["disposition"] != "admitted":
            continue
        _verify_consumed_input(arm)
        for component in arm["components"]:
            _verify_component(component)
        verified.append(arm_id)
    return verified


def _cluster_key(datapoint: DataPoint) -> tuple[str, bool]:
    cluster = datapoint.meta.get("source_cluster_id")
    if isinstance(cluster, str) and cluster.strip():
        return cluster, True
    return datapoint.id, False


def _media_payload_bytes(ref: MediaRef) -> tuple[int, str | None]:
    if ref.path:
        unresolved = Path(ref.path)
        if unresolved.is_symlink():
            return 0, "symlink_media"
        try:
            path = unresolved.resolve(strict=True)
        except OSError:
            return 0, "missing_media"
        if not path.is_file() or path.is_symlink():
            return 0, "non_regular_media"
        size = path.stat().st_size
        # Converter admission already read, typed, bounded, and hashed these
        # bytes. Re-reading a 245k-item audio release merely to duplicate that
        # work would be an expensive second provenance system. Runner admission
        # rehashes every selected physical item immediately before execution.
        if (
            ref.sha256 is None
            or len(ref.sha256) != 64
            or any(char not in _HEX for char in ref.sha256.lower())
        ):
            return size, "missing_media_content_address"
        return size, None
    if ref.uri and ref.uri.startswith("data:") and ";base64," in ref.uri:
        try:
            payload = base64.b64decode(ref.uri.split(",", 1)[1], validate=True)
        except (ValueError, TypeError):
            return 0, "invalid_data_uri"
        digest = hashlib.sha256(payload).hexdigest()
        if ref.sha256 is not None and digest != ref.sha256.lower():
            return len(payload), "media_sha256_mismatch"
        return len(payload), None
    return 0, "unverifiable_media_uri"


def observed_arm_conformance(datapoints: Sequence[DataPoint]) -> dict[str, Any]:
    """Derive compact runtime evidence from the complete converted corpus."""

    rows = list(datapoints)
    if not rows:
        raise ValueError("source receipt cannot observe an empty corpus")
    cluster_sizes: Counter[str] = Counter()
    explicit = 0
    policy_rows: list[object] = []
    metric_rows: list[object] = []
    policy_counts: Counter[str] = Counter()
    required_metric_counts: Counter[str] = Counter()
    common_eligible = 0
    media_rows: list[object] = []
    media_failures: list[str] = []
    media_bytes: defaultdict[str, int] = defaultdict(int)
    media_refs: Counter[str] = Counter()
    seen_content: set[tuple[str, str]] = set()
    for datapoint in rows:
        cluster, is_explicit = _cluster_key(datapoint)
        cluster_sizes[cluster] += 1
        explicit += int(is_explicit)
        if datapoint.source_policy is None:
            policy_rows.append([datapoint.id, None])
            policy_counts["none"] += 1
        else:
            policy = datapoint.source_policy
            policy_counts[
                f"{policy.policy_id}|{policy.version}|{policy.sha256}|"
                f"{policy.intended_metric or ''}"
            ] += 1
            policy_rows.append([
                datapoint.id, policy.policy_id, policy.version, policy.sha256,
                policy.intended_metric,
            ])
        metric_rows.append([
            datapoint.id,
            datapoint.meta.get("common_metrics_eligible", True) is True,
            datapoint.meta.get("required_metric"),
        ])
        common_eligible += int(
            datapoint.meta.get("common_metrics_eligible", True) is True
        )
        required = datapoint.meta.get("required_metric")
        if isinstance(required, str) and required.strip():
            required_metric_counts[required] += 1
        refs = [*datapoint.media]
        for turn in datapoint.dialog_history:
            refs.extend(turn.media)
        seen_refs: set[tuple[str, str, str | None]] = set()
        for ref in refs:
            digest = (ref.sha256 or "").lower()
            ref_identity = (ref.modality, digest, ref.mime)
            if ref_identity in seen_refs:
                continue
            seen_refs.add(ref_identity)
            size, failure = _media_payload_bytes(ref)
            media_rows.append([datapoint.id, ref.modality, digest, ref.mime, size])
            media_refs[ref.modality] += 1
            identity = (ref.modality, digest)
            if digest and identity not in seen_content:
                media_bytes[ref.modality] += size
                seen_content.add(identity)
            if failure:
                media_failures.append(f"{datapoint.id}:{ref.modality}:{failure}")
    if media_failures:
        media_result = "failed"
    elif media_rows:
        media_result = "passed"
    else:
        media_result = "not_applicable"
    return {
        "converted_corpus_sha256": canonical_converted_corpus_sha256(rows),
        "emitted_datapoints": len(rows),
        "clusters": {
            "rule": CLUSTER_RULE,
            "unique": len(cluster_sizes),
            "explicit_rows": explicit,
            "fallback_rows": len(rows) - explicit,
            "max_size": max(cluster_sizes.values()),
        },
        "policies": {
            "counts": dict(sorted(policy_counts.items())),
            "inventory_sha256": canonical_json_sha256(sorted(policy_rows)),
        },
        "metrics": {
            "common_eligible": common_eligible,
            "common_ineligible": len(rows) - common_eligible,
            "required_metric_counts": dict(sorted(required_metric_counts.items())),
            "inventory_sha256": canonical_json_sha256(sorted(metric_rows)),
        },
        "media": {
            "result": media_result,
            "verification_basis": (
                "converter_content_address_plus_selected_runner_rehash"
            ),
            "inventory_sha256": canonical_json_sha256(sorted(media_rows)),
            "refs": dict(sorted(media_refs.items())),
            "unique_bytes": dict(sorted(media_bytes.items())),
            "failures": sorted(media_failures),
        },
    }


def selected_source_conformance_sha256(
    manifest: Mapping[str, Any], selected_arms: Sequence[str],
) -> str:
    normalized = validate_source_conformance_manifest(manifest)
    arms_by_id = {arm["arm_id"]: arm for arm in normalized["arms"]}
    missing = sorted(set(selected_arms) - set(arms_by_id))
    if missing:
        raise ValueError(f"source receipt omits selected arms: {missing}")
    payload = {
        "schema": normalized["schema"],
        "claim_scope": normalized["claim_scope"],
        "arms": [arms_by_id[arm] for arm in sorted(selected_arms)],
    }
    return canonical_json_sha256(payload)


def validate_selected_source_conformance(
    manifest: Mapping[str, Any], *,
    selected_source_instances: Mapping[str, Mapping[str, object]],
    full_observations: Mapping[str, Mapping[str, object]],
    sampling_audits: Mapping[str, Mapping[str, object]],
    source_config_selected_sha256: str,
    verify_components: bool = True,
) -> dict[str, Any]:
    """Bind selected receipts to complete converted evidence before target calls."""

    normalized = validate_source_conformance_manifest(manifest)
    selected = sorted(selected_source_instances)
    if set(selected) != set(full_observations) or set(selected) != set(sampling_audits):
        raise ValueError("source receipt selected-arm inputs do not align")
    expected_config = _sha256(
        source_config_selected_sha256, "source_config_selected_sha256"
    )
    arms_by_id = {arm["arm_id"]: arm for arm in normalized["arms"]}
    missing = sorted(set(selected) - set(arms_by_id))
    if missing:
        raise ValueError(f"source receipt omits selected arms: {missing}")
    if verify_components:
        verify_manifest_components(normalized, selected_arms=selected)
    observed: dict[str, Mapping[str, object]] = {}
    for arm_id in selected:
        arm = arms_by_id[arm_id]
        instance = selected_source_instances[arm_id]
        if arm["disposition"] != "admitted":
            raise ValueError(
                f"selected source arm {arm_id!r} is {arm['disposition']}, not admitted"
            )
        for field in ("converter", "path_env", "source_label", "split"):
            if arm.get(field) != instance.get(field):
                raise ValueError(f"source receipt arm {arm_id!r} {field} mismatch")
        observation = dict(full_observations[arm_id])
        audit = sampling_audits[arm_id]
        full_digest = audit.get("full_converted_corpus_sha256")
        if observation.get("converted_corpus_sha256") != full_digest:
            raise ValueError(f"source receipt arm {arm_id!r} full audit mismatch")
        if observation["emitted_datapoints"] != audit.get("total_records"):
            raise ValueError(f"source receipt arm {arm_id!r} full count mismatch")
        if observation["clusters"]["unique"] != audit.get("total_clusters"):
            raise ValueError(f"source receipt arm {arm_id!r} cluster count mismatch")
        if observation["media"]["result"] == "failed":
            raise ValueError(f"source receipt arm {arm_id!r} media conformance failed")
        if (
            arm["semantic_review"]["reviewed_converted_corpus_sha256"]
            != full_digest
        ):
            raise ValueError(
                f"source receipt arm {arm_id!r} semantic review is stale"
            )
        unknown_reviewed = sorted(
            set(arm["semantic_review"]["reviewed_cluster_ids"])
            - set(audit.get("total_cluster_ids", []))
        )
        if unknown_reviewed:
            raise ValueError(
                f"source receipt arm {arm_id!r} semantic review references "
                f"unknown clusters: {unknown_reviewed[:5]}"
            )
        observed[arm_id] = observation
    return {
        "schema": SOURCE_CONFORMANCE_SCHEMA,
        "selected_arms": selected,
        "normalized_selected_sha256": selected_source_conformance_sha256(
            normalized, selected
        ),
        "source_config_selected_sha256": expected_config,
        "observed_full_corpus_sha256": canonical_json_sha256(observed),
    }


__all__ = [
    "CLUSTER_RULE",
    "SOURCE_CONFORMANCE_SCHEMA",
    "SourceConformanceManifest",
    "canonical_json_sha256",
    "observed_arm_conformance",
    "selected_source_conformance_sha256",
    "validate_selected_source_conformance",
    "validate_source_conformance_manifest",
    "verify_manifest_components",
]
