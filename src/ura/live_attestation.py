"""Strict live target-route and physical-transport attestation receipts.

An attestation is a prerequisite receipt derived from an already completed,
integrity-validated bounded probe.  It establishes only that one exact target
route returned the recorded identity after receiving one exact byte-backed
input-modality combination at a recorded time.  It is not a safety score,
benchmark result, evaluator validation, human label, or proof that a mutable
provider route will remain unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .modality_coverage import canonical_modality_combination


LIVE_ATTESTATION_SCHEMA = "ura-live-attestation/1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"live-attestation-[0-9a-f]{24}")
_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_RECORD_FIELDS = frozenset({
    "record_id",
    "execution_scope_id",
    "requested_target_spec",
    "resolved_target",
    "route_kind",
    "route_config_sha256",
    "exact_input_modalities",
    "realized_target_identity",
    "observed_at_utc",
    "probe",
})
_TOP_FIELDS = frozenset({
    "schema",
    "status",
    "purpose",
    "records",
    "limitations",
    "attestation_id",
})
_PROBE_FIELDS = frozenset({
    "evidence_kind",
    "grid_id",
    "run_id",
    "grid_artifact",
    "completion_artifact",
    "realized_identities_sha256",
    "attempt_media_hashes_sha256",
    "harness_source_sha256",
    "driver_source_sha256",
})
_DESCRIPTOR_FIELDS = frozenset({"file", "sha256", "bytes"})
_REALIZED_FIELDS = frozenset({
    "target",
    "provider",
    "resolved_model",
    "system_fingerprint",
    "model_revision",
    "model_digest",
})
_STABLE_REALIZED_FIELDS = (
    "provider",
    "resolved_model",
    "model_revision",
    "model_digest",
)


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def route_config_sha256(
    *,
    route_kind: str,
    requested_target_spec: str,
    resolved_target: str,
    route_config: Mapping[str, Any] | None,
) -> str:
    """Hash the secret-free target constructor contract used by a route.

    ``resolved_target`` is the unwrapped base-target identity.  Keeping the
    defense wrapper outside this projection allows one successful transport
    probe to support defended and undefended experiments that use the same
    exact underlying route.
    """

    if route_kind not in {"hosted_api", "local_runtime"}:
        raise ValueError("live-attestation route kind is invalid")
    requested = _nonblank(requested_target_spec, "requested target spec")
    resolved = _nonblank(resolved_target, "resolved target")
    if route_config is not None and not isinstance(route_config, Mapping):
        raise ValueError("live-attestation route config must be an object or null")
    return canonical_json_sha256({
        "route_kind": route_kind,
        "requested_target_spec": requested,
        "resolved_target": resolved,
        "route_config": dict(route_config) if route_config is not None else None,
    })


def route_config_from_grid_request(
    request: Mapping[str, Any],
    *,
    route_kind: str,
    requested_target_spec: str,
    resolved_target: str,
) -> dict[str, Any] | None:
    """Select the exact secret-free route config persisted by ``run_matrix``.

    Hosted API configs are keyed by the requested provider/model spec.  Local
    configs are deliberately keyed by the path-safe, immutable base target
    identity persisted after construction.  Keeping that distinction here
    prevents receipt production and later analysis from silently hashing
    ``null`` for a local vLLM/Ollama route.
    """

    if not isinstance(request, Mapping):
        raise ValueError("live-attestation grid request must be an object")
    if route_kind == "hosted_api":
        field = "api_configs"
        key = _nonblank(requested_target_spec, "requested target spec")
        required = False
    elif route_kind == "local_runtime":
        field = "local_configs"
        key = _nonblank(resolved_target, "resolved target")
        required = True
    else:
        raise ValueError("live-attestation route kind is invalid")
    configs = request.get(field, {} if route_kind == "hosted_api" else None)
    if not isinstance(configs, Mapping):
        raise ValueError(f"grid request {field} must be an object")
    value = configs.get(key)
    if value is None:
        if required:
            raise ValueError(
                "local live attestation lacks the selected base-route config"
            )
        return None
    if not isinstance(value, Mapping):
        raise ValueError("selected live-attestation route config must be an object")
    return dict(value)


def _nonblank(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be a non-blank unpadded string")
    return value


def validate_execution_scope_id(value: object) -> str:
    """Validate one non-secret operator-defined account/runtime scope label."""

    scope = _nonblank(value, "execution_scope_id")
    if _SCOPE.fullmatch(scope) is None:
        raise ValueError("execution_scope_id has invalid characters")
    return scope


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _timestamp(value: object, label: str) -> datetime:
    text = _nonblank(value, label)
    if not text.endswith("Z"):
        raise ValueError(f"{label} must be UTC RFC3339 ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is not a valid UTC RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must use UTC")
    return parsed


def _descriptor(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _DESCRIPTOR_FIELDS:
        raise ValueError(f"{label} must contain file, sha256, and bytes")
    filename = _nonblank(value.get("file"), f"{label}.file")
    if Path(filename).name != filename:
        raise ValueError(f"{label}.file must be a basename")
    digest = _sha256(value.get("sha256"), f"{label}.sha256")
    byte_count = value.get("bytes")
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count <= 0:
        raise ValueError(f"{label}.bytes must be a positive integer")
    return {"file": filename, "sha256": digest, "bytes": byte_count}


def stable_realized_target_identity(value: Mapping[str, Any]) -> dict[str, str]:
    """Project a realized target snapshot to fields safe for admission matching.

    Wrapper/display target names and system fingerprints remain receipt
    provenance but are deliberately excluded from the response equality check:
    a defended target wraps the same base route, and providers may rotate a
    fingerprint without changing that route.  The requested/base route itself
    is independently bound by ``route_config_sha256``.  A provider-returned
    resolved model, revision, or digest does participate in equality.
    """

    return {
        field: str(value[field])
        for field in _STABLE_REALIZED_FIELDS
        if value.get(field) is not None
    }


def realized_identity_matches(
    expected: Mapping[str, Any], observed: Mapping[str, Any]
) -> bool:
    expected_stable = stable_realized_target_identity(expected)
    observed_stable = stable_realized_target_identity(observed)
    return all(observed_stable.get(key) == value for key, value in expected_stable.items())


def _record_id(record: Mapping[str, Any]) -> str:
    material = {
        key: record[key]
        for key in sorted(_RECORD_FIELDS - {"record_id"})
    }
    return "live-attestation-record-" + canonical_json_sha256(material)[:24]


def validate_live_attestation_manifest(value: object) -> dict[str, Any]:
    """Validate one strict, content-addressed transport-attestation manifest."""

    if not isinstance(value, dict) or set(value) != _TOP_FIELDS:
        raise ValueError("live attestation has an invalid top-level field inventory")
    if value.get("schema") != LIVE_ATTESTATION_SCHEMA:
        raise ValueError("unsupported live-attestation schema")
    if value.get("status") != "complete":
        raise ValueError("live attestation must declare status=complete")
    if value.get("purpose") != "target_route_and_byte_backed_transport_only":
        raise ValueError("live attestation has an invalid purpose")
    limitations = value.get("limitations")
    required_limitations = {
        "safety_validity_established": False,
        "evaluator_validity_established": False,
        "benchmark_result_established": False,
        "human_validity_established": False,
        "future_route_availability_guaranteed": False,
    }
    if limitations != required_limitations:
        raise ValueError("live attestation must retain every non-validity limitation")
    records = value.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("live attestation requires at least one record")
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for index, raw in enumerate(records):
        label = f"live attestation record {index}"
        if not isinstance(raw, dict) or set(raw) != _RECORD_FIELDS:
            raise ValueError(f"{label} has an invalid field inventory")
        try:
            scope = validate_execution_scope_id(raw.get("execution_scope_id"))
        except ValueError as exc:
            raise ValueError(f"{label}.execution_scope_id is invalid") from exc
        requested = _nonblank(raw.get("requested_target_spec"), f"{label}.requested_target_spec")
        resolved = _nonblank(raw.get("resolved_target"), f"{label}.resolved_target")
        route_kind = raw.get("route_kind")
        if route_kind not in {"hosted_api", "local_runtime"}:
            raise ValueError(f"{label}.route_kind is invalid")
        route_digest = _sha256(raw.get("route_config_sha256"), f"{label}.route_config_sha256")
        modalities_raw = raw.get("exact_input_modalities")
        if not isinstance(modalities_raw, list):
            raise ValueError(f"{label}.exact_input_modalities must be a list")
        try:
            modalities = list(canonical_modality_combination(modalities_raw))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} has invalid exact input modalities") from exc
        if modalities != modalities_raw:
            raise ValueError(f"{label}.exact_input_modalities is not canonical")
        realized = raw.get("realized_target_identity")
        if (
            not isinstance(realized, dict)
            or not realized
            or set(realized) - _REALIZED_FIELDS
            or any(not isinstance(item, str) or not item.strip() for item in realized.values())
        ):
            raise ValueError(f"{label}.realized_target_identity is invalid")
        if realized.get("target") != resolved:
            raise ValueError(f"{label} resolved/realized target mismatch")
        if not isinstance(realized.get("resolved_model"), str):
            raise ValueError(f"{label} lacks a provider/runtime resolved_model")
        if route_kind == "hosted_api" and not isinstance(realized.get("provider"), str):
            raise ValueError(f"{label} hosted identity lacks provider")
        if route_kind == "local_runtime" and not (
            isinstance(realized.get("model_revision"), str)
            or isinstance(realized.get("model_digest"), str)
        ):
            raise ValueError(f"{label} local identity lacks revision or digest")
        observed_at = _nonblank(raw.get("observed_at_utc"), f"{label}.observed_at_utc")
        _timestamp(observed_at, f"{label}.observed_at_utc")
        probe = raw.get("probe")
        if not isinstance(probe, dict) or set(probe) != _PROBE_FIELDS:
            raise ValueError(f"{label}.probe has an invalid field inventory")
        if probe.get("evidence_kind") not in {
            "synthetic_live_transport_probe",
            "real_source_live_transport_probe",
        }:
            raise ValueError(f"{label}.probe evidence_kind is invalid")
        _nonblank(probe.get("grid_id"), f"{label}.probe.grid_id")
        _nonblank(probe.get("run_id"), f"{label}.probe.run_id")
        _descriptor(probe.get("grid_artifact"), f"{label}.probe.grid_artifact")
        _descriptor(
            probe.get("completion_artifact"), f"{label}.probe.completion_artifact"
        )
        _sha256(
            probe.get("realized_identities_sha256"),
            f"{label}.probe.realized_identities_sha256",
        )
        _sha256(
            probe.get("attempt_media_hashes_sha256"),
            f"{label}.probe.attempt_media_hashes_sha256",
        )
        _sha256(
            probe.get("harness_source_sha256"),
            f"{label}.probe.harness_source_sha256",
        )
        _sha256(
            probe.get("driver_source_sha256"),
            f"{label}.probe.driver_source_sha256",
        )
        expected_record_id = _record_id(raw)
        if raw.get("record_id") != expected_record_id:
            raise ValueError(f"{label} record_id/content mismatch")
        key = (scope, requested, tuple(modalities))
        if key in seen:
            raise ValueError("duplicate live-attestation scope/target/modality record")
        seen.add(key)
        normalized.append({
            **raw,
            "execution_scope_id": scope,
            "requested_target_spec": requested,
            "resolved_target": resolved,
            "route_config_sha256": route_digest,
            "exact_input_modalities": modalities,
            "realized_target_identity": dict(sorted(realized.items())),
        })
    normalized.sort(key=lambda row: row["record_id"])
    if normalized != records:
        raise ValueError("live-attestation records must be sorted by record_id")
    body = {
        key: value[key]
        for key in sorted(_TOP_FIELDS - {"attestation_id"})
    }
    expected_id = "live-attestation-" + canonical_json_sha256(body)[:24]
    if value.get("attestation_id") != expected_id or _ID.fullmatch(expected_id) is None:
        raise ValueError("live attestation ID/content mismatch")
    return value


def build_live_attestation_manifest(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Build and validate a canonical receipt from already verified probe rows."""

    prepared: list[dict[str, Any]] = []
    for raw in records:
        item = dict(raw)
        item["record_id"] = _record_id(item)
        prepared.append(item)
    prepared.sort(key=lambda row: row["record_id"])
    body: dict[str, Any] = {
        "schema": LIVE_ATTESTATION_SCHEMA,
        "status": "complete",
        "purpose": "target_route_and_byte_backed_transport_only",
        "records": prepared,
        "limitations": {
            "safety_validity_established": False,
            "evaluator_validity_established": False,
            "benchmark_result_established": False,
            "human_validity_established": False,
            "future_route_availability_guaranteed": False,
        },
    }
    body["attestation_id"] = "live-attestation-" + canonical_json_sha256(body)[:24]
    return validate_live_attestation_manifest(body)


def load_live_attestation_file(
    path_value: str | Path,
    expected_sha256: str,
    *,
    max_bytes: int = 4 * 1024 * 1024,
) -> tuple[dict[str, Any], dict[str, object]]:
    """Load exact approved bytes without following a symlink."""

    expected = _sha256(expected_sha256.lower(), "live-attestation expected sha256")
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError("live-attestation input must not be a symlink")
    path = unresolved.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("live-attestation input must be a regular file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError("live-attestation input is empty or exceeds the size limit")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ValueError("live-attestation input changed while being read")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected:
        raise ValueError("live-attestation byte digest mismatch")
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        duplicates = sorted(key for key, count in Counter(key for key, _ in pairs).items()
                            if count > 1)
        if duplicates:
            raise ValueError(
                "duplicate JSON object keys are forbidden: " + ", ".join(duplicates)
            )
        return dict(pairs)

    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {token!r} is forbidden")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("live-attestation input is malformed JSON") from exc
    manifest = validate_live_attestation_manifest(value)
    return manifest, {"file": path.name, "sha256": digest, "bytes": size}


def required_attestation_keys(
    *,
    execution_scope_id: str,
    requested_target_specs: Iterable[str],
    eligibility_items: Iterable[Mapping[str, Any]],
) -> set[tuple[str, str, tuple[str, ...]]]:
    """Return exact transport prerequisites for compatible planning strata."""

    requested = set(requested_target_specs)
    return {
        (
            execution_scope_id,
            str(item["requested_target_spec"]),
            tuple(str(value) for value in item["exact_modality_combination"]),
        )
        for item in eligibility_items
        if item.get("requested_target_spec") in requested
        and item.get("status") == "compatible_if_isolated"
    }


def validate_required_live_attestations(
    manifests: Sequence[Mapping[str, Any]],
    *,
    required_keys: set[tuple[str, str, tuple[str, ...]]],
    resolved_targets: Mapping[str, str],
    route_config_sha256: Mapping[str, str],
    route_kind: Mapping[str, str],
    current_harness_source_sha256: str,
    current_driver_source_sha256: str,
    reference_time: datetime,
    max_age_hours: float,
) -> dict[tuple[str, str, tuple[str, ...]], dict[str, Any]]:
    """Match every exact prerequisite and reject stale or ambiguous receipts."""

    if reference_time.tzinfo is None:
        raise ValueError("live-attestation reference time must be timezone-aware")
    harness_digest = _sha256(
        current_harness_source_sha256,
        "current harness source sha256",
    )
    driver_digest = _sha256(
        current_driver_source_sha256,
        "current experiment driver source sha256",
    )
    if not isinstance(max_age_hours, (int, float)) or isinstance(max_age_hours, bool):
        raise ValueError("live-attestation max age must be numeric")
    if not 0 < float(max_age_hours) <= 24 * 365:
        raise ValueError("live-attestation max age must be in (0, 8760] hours")
    index: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for manifest in manifests:
        validate_live_attestation_manifest(manifest)
        for record in manifest["records"]:
            key = (
                record["execution_scope_id"],
                record["requested_target_spec"],
                tuple(record["exact_input_modalities"]),
            )
            if key not in required_keys:
                continue
            if key in index:
                raise ValueError(f"duplicate required live attestation for {key!r}")
            requested = key[1]
            if record["resolved_target"] != resolved_targets.get(requested):
                raise ValueError(f"live attestation resolved target mismatch for {requested}")
            if record["route_config_sha256"] != route_config_sha256.get(requested):
                raise ValueError(f"live attestation route/config mismatch for {requested}")
            if record["route_kind"] != route_kind.get(requested):
                raise ValueError(f"live attestation route kind mismatch for {requested}")
            if record["probe"]["harness_source_sha256"] != harness_digest:
                raise ValueError(
                    f"live attestation harness source mismatch for {requested}"
                )
            if record["probe"]["driver_source_sha256"] != driver_digest:
                raise ValueError(
                    f"live attestation experiment driver mismatch for {requested}"
                )
            observed = _timestamp(record["observed_at_utc"], "observed_at_utc")
            age_hours = (reference_time.astimezone(timezone.utc) - observed).total_seconds() / 3600
            if age_hours < 0:
                raise ValueError(f"live attestation is future-dated for {requested}")
            if age_hours > float(max_age_hours):
                raise ValueError(f"live attestation is stale for {requested}")
            index[key] = record
    missing = sorted(required_keys - set(index))
    if missing:
        raise ValueError(f"missing exact live-attestation prerequisites: {missing!r}")
    identities_by_target: dict[tuple[str, str], dict[str, str]] = {}
    for key, record in index.items():
        target_key = (key[0], key[1])
        identity = stable_realized_target_identity(
            record["realized_target_identity"]
        )
        prior = identities_by_target.setdefault(target_key, identity)
        if prior != identity:
            raise ValueError(
                "one target has conflicting stable identities across required "
                f"modality attestations: {target_key!r}"
            )
    return index


__all__ = [
    "LIVE_ATTESTATION_SCHEMA",
    "build_live_attestation_manifest",
    "canonical_json_sha256",
    "load_live_attestation_file",
    "realized_identity_matches",
    "required_attestation_keys",
    "route_config_from_grid_request",
    "route_config_sha256",
    "stable_realized_target_identity",
    "validate_execution_scope_id",
    "validate_live_attestation_manifest",
    "validate_required_live_attestations",
]
