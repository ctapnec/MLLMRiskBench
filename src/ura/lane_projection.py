"""Strict prospective lane projections produced before generation calls.

The artifact records the already-computed conservative logical-call exposure
for one exact, successfully admitted experiment request.  It deliberately does
not estimate tokens, money, elapsed time, throughput, or output storage: those
quantities require a measured canary and remain ``CANNOT-VERIFY``.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .eligibility import canonical_json_sha256, validate_eligibility_plan


LANE_PROJECTION_SCHEMA = "ura-lane-projection/1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"lane-projection-[0-9a-f]{24}")
_TOP_FIELDS = frozenset({
    "schema",
    "status",
    "purpose",
    "projection_id",
    "eligibility_binding",
    "selection",
    "call_projection",
    "unavailable_estimates",
    "limitations",
})
_ELIGIBILITY_FIELDS = frozenset({
    "plan_id", "request_id", "artifact", "experiment_conditions",
})
_DESCRIPTOR_FIELDS = frozenset({"file", "sha256", "bytes", "records"})
_SELECTION_FIELDS = frozenset({"arms", "totals"})
_ARM_FIELDS = frozenset({
    "logical_source_arm",
    "converter",
    "selected_converted_corpus_sha256",
    "selected_datapoint_ids_sha256",
    "total_records",
    "selected_records",
    "total_clusters",
    "selected_clusters",
    "selected_cluster_ids_sha256",
    "sample_seed",
    "limit",
    "source_policy_cluster_counts",
    "selected_input_media",
})
_MEDIA_FIELDS = frozenset({
    "status",
    "verification_basis",
    "inventory_sha256",
    "refs_by_modality",
    "unique_bytes_by_modality",
    "total_unique_bytes",
})
_TOTAL_FIELDS = frozenset({
    "logical_source_arms",
    "selected_records",
    "selected_clusters",
    "source_policy_clusters",
    "arm_summed_unique_input_media_bytes",
})
_CALL_FIELDS = frozenset({
    "semantics",
    "trajectories",
    "target_calls",
    "judge_calls",
    "local_guardrail_evaluations",
    "http_attempts",
    "by_attacker",
})
_CALL_COUNT_FIELDS = (
    "trajectories",
    "target_calls",
    "judge_calls",
    "local_guardrail_evaluations",
    "http_attempts",
)
_UNAVAILABLE_REASONS = {
    "token_usage": "requires_measured_canary_usage",
    "monetary_price_or_cost": "requires_measured_usage_and_applicable_provider_terms",
    "runtime_or_throughput": "requires_measured_canary_timing",
    "expected_output_storage": "requires_measured_canary_artifact_bytes",
}
_LIMITATIONS = {
    "production_boundary": (
        "after_successful_whole_request_preflight_before_first_generation_call"
    ),
    "provider_or_model_generation_invoked_by_projection": False,
    "measured_canary_established": False,
    "operator_approved_caps_established": False,
    "scientific_result_established": False,
}


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return value


def _strict_object(
    value: object, fields: frozenset[str], label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} has an invalid field inventory")
    return value


def _validate_descriptor(value: object) -> dict[str, Any]:
    descriptor = _strict_object(value, _DESCRIPTOR_FIELDS, "eligibility descriptor")
    filename = descriptor.get("file")
    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
    ):
        raise ValueError("eligibility descriptor file must be a basename")
    _sha256(descriptor.get("sha256"), "eligibility descriptor sha256")
    for field in ("bytes", "records"):
        if _nonnegative_int(descriptor.get(field), f"eligibility descriptor {field}") <= 0:
            raise ValueError(f"eligibility descriptor {field} must be positive")
    return descriptor


def _validate_condition(value: object) -> dict[str, Any]:
    condition = _strict_object(
        value, frozenset({"condition_id", "values"}), "experiment conditions"
    )
    values = condition.get("values")
    if not isinstance(values, dict):
        raise ValueError("experiment condition values must be an object")
    expected = "condition-" + canonical_json_sha256(values)[:24]
    if condition.get("condition_id") != expected:
        raise ValueError("experiment condition ID/content mismatch")
    return condition


def _validate_call_projection(value: object) -> dict[str, Any]:
    projection = _strict_object(value, _CALL_FIELDS, "call projection")
    if projection.get("semantics") != "conservative_complete_grid_upper_bound_v1":
        raise ValueError("call projection has unsupported semantics")
    by_attacker = projection.get("by_attacker")
    if not isinstance(by_attacker, dict) or not by_attacker:
        raise ValueError("call projection requires a non-empty attacker inventory")
    totals = {field: _nonnegative_int(projection.get(field), field)
              for field in _CALL_COUNT_FIELDS}
    sums: Counter[str] = Counter()
    for attacker, raw in by_attacker.items():
        if not isinstance(attacker, str) or not attacker.strip() or attacker != attacker.strip():
            raise ValueError("call projection attacker names must be non-blank/unpadded")
        item = _strict_object(
            raw, frozenset(_CALL_COUNT_FIELDS), f"call projection attacker {attacker!r}"
        )
        for field in _CALL_COUNT_FIELDS:
            sums[field] += _nonnegative_int(item.get(field), f"{attacker}.{field}")
    if any(sums[field] != totals[field] for field in _CALL_COUNT_FIELDS):
        raise ValueError("call projection attacker counts do not reconcile")
    return projection


def _validate_media(value: object, label: str) -> dict[str, Any]:
    media = _strict_object(value, _MEDIA_FIELDS, label)
    status = media.get("status")
    if status not in {"available", "not_applicable"}:
        raise ValueError(f"{label}.status is invalid")
    basis = media.get("verification_basis")
    if not isinstance(basis, str) or not basis.strip():
        raise ValueError(f"{label}.verification_basis must be non-blank")
    _sha256(media.get("inventory_sha256"), f"{label}.inventory_sha256")
    refs = media.get("refs_by_modality")
    unique_bytes = media.get("unique_bytes_by_modality")
    if not isinstance(refs, dict) or not isinstance(unique_bytes, dict):
        raise ValueError(f"{label} modality inventories must be objects")
    allowed_modalities = {"image", "audio", "video"}
    if set(refs) - allowed_modalities or set(unique_bytes) - allowed_modalities:
        raise ValueError(f"{label} contains an invalid physical modality")
    for key, count in refs.items():
        if _nonnegative_int(count, f"{label}.refs_by_modality.{key}") <= 0:
            raise ValueError(f"{label} media reference counts must be positive")
    for key, count in unique_bytes.items():
        if _nonnegative_int(count, f"{label}.unique_bytes_by_modality.{key}") <= 0:
            raise ValueError(f"{label} unique byte counts must be positive")
    total = _nonnegative_int(media.get("total_unique_bytes"), f"{label}.total_unique_bytes")
    if total != sum(unique_bytes.values()):
        raise ValueError(f"{label} unique byte counts do not reconcile")
    if status == "not_applicable":
        if refs or unique_bytes or total:
            raise ValueError(f"{label} not-applicable inventory must be empty")
        if basis != "no_physical_media_selected":
            raise ValueError(f"{label} has an invalid not-applicable basis")
        if media["inventory_sha256"] != canonical_json_sha256([]):
            raise ValueError(f"{label} empty inventory digest is invalid")
    else:
        if not refs or not unique_bytes or total <= 0:
            raise ValueError(f"{label} available inventory requires physical bytes")
        if set(unique_bytes) - set(refs):
            raise ValueError(f"{label} byte modalities lack reference counts")
        if basis != "converter_content_address_plus_selected_runner_rehash":
            raise ValueError(f"{label} has an invalid byte-verification basis")
    return media


def validate_lane_projection(value: object) -> dict[str, Any]:
    """Validate one self-contained ``ura-lane-projection/1`` artifact."""

    artifact = _strict_object(value, _TOP_FIELDS, "lane projection")
    if artifact.get("schema") != LANE_PROJECTION_SCHEMA:
        raise ValueError("unsupported lane-projection schema")
    if artifact.get("status") != "complete":
        raise ValueError("lane projection must declare status=complete")
    if artifact.get("purpose") != "prospective_no_call_exposure_projection":
        raise ValueError("lane projection has an invalid purpose")

    binding = _strict_object(
        artifact.get("eligibility_binding"),
        _ELIGIBILITY_FIELDS,
        "lane projection eligibility binding",
    )
    for field, pattern in (
        ("plan_id", r"eligibility-[0-9a-f]{24}"),
        ("request_id", r"eligibility-request-[0-9a-f]{24}"),
    ):
        if not isinstance(binding.get(field), str) or re.fullmatch(
            pattern, binding[field]
        ) is None:
            raise ValueError(f"lane projection eligibility {field} is invalid")
    _validate_descriptor(binding.get("artifact"))
    _validate_condition(binding.get("experiment_conditions"))

    selection = _strict_object(
        artifact.get("selection"), _SELECTION_FIELDS, "lane projection selection"
    )
    arms = selection.get("arms")
    if not isinstance(arms, list) or not arms:
        raise ValueError("lane projection requires selected source arms")
    arm_ids: list[str] = []
    sums: Counter[str] = Counter()
    for index, raw in enumerate(arms):
        arm = _strict_object(raw, _ARM_FIELDS, f"lane projection arm {index}")
        arm_id = arm.get("logical_source_arm")
        converter = arm.get("converter")
        if not isinstance(arm_id, str) or not arm_id.strip() or arm_id != arm_id.strip():
            raise ValueError("lane projection arm ID must be non-blank/unpadded")
        if not isinstance(converter, str) or not converter.strip():
            raise ValueError("lane projection converter must be non-blank")
        arm_ids.append(arm_id)
        for field in (
            "selected_converted_corpus_sha256",
            "selected_datapoint_ids_sha256",
            "selected_cluster_ids_sha256",
        ):
            _sha256(arm.get(field), f"lane projection arm {arm_id} {field}")
        integers = {
            field: _nonnegative_int(arm.get(field), f"lane projection arm {arm_id} {field}")
            for field in (
                "total_records", "selected_records", "total_clusters",
                "selected_clusters", "limit",
            )
        }
        _integer(arm.get("sample_seed"), f"lane projection arm {arm_id} sample_seed")
        if integers["selected_records"] > integers["total_records"]:
            raise ValueError("lane projection selected records exceed total records")
        if integers["selected_clusters"] > integers["total_clusters"]:
            raise ValueError("lane projection selected clusters exceed total clusters")
        policy_counts = arm.get("source_policy_cluster_counts")
        if not isinstance(policy_counts, dict) or not policy_counts:
            raise ValueError("lane projection arm requires source-policy cluster counts")
        for policy, count in policy_counts.items():
            if not isinstance(policy, str) or not policy:
                raise ValueError("lane projection source-policy key is invalid")
            _nonnegative_int(count, f"lane projection source-policy count {policy}")
        if sum(policy_counts.values()) != integers["selected_clusters"]:
            raise ValueError("source-policy cluster counts do not reconcile")
        media = _validate_media(
            arm.get("selected_input_media"),
            f"lane projection arm {arm_id} selected input media",
        )
        sums["selected_records"] += integers["selected_records"]
        sums["selected_clusters"] += integers["selected_clusters"]
        sums["source_policy_clusters"] += sum(policy_counts.values())
        sums["arm_summed_unique_input_media_bytes"] += media["total_unique_bytes"]
    if arm_ids != sorted(set(arm_ids)):
        raise ValueError("lane projection arms must be unique and sorted")
    totals = _strict_object(
        selection.get("totals"), _TOTAL_FIELDS, "lane projection selection totals"
    )
    expected_totals = {
        "logical_source_arms": len(arms),
        **{field: sums[field] for field in (
            "selected_records", "selected_clusters", "source_policy_clusters",
            "arm_summed_unique_input_media_bytes",
        )},
    }
    if totals != expected_totals:
        raise ValueError("lane projection selection totals do not reconcile")

    _validate_call_projection(artifact.get("call_projection"))
    unavailable = artifact.get("unavailable_estimates")
    if not isinstance(unavailable, dict) or set(unavailable) != set(_UNAVAILABLE_REASONS):
        raise ValueError("lane projection unavailable-estimate inventory is invalid")
    for field, reason in _UNAVAILABLE_REASONS.items():
        expected = {"status": "CANNOT-VERIFY", "value": None, "reason": reason}
        if unavailable.get(field) != expected:
            raise ValueError(f"lane projection {field} must remain CANNOT-VERIFY")
    if artifact.get("limitations") != _LIMITATIONS:
        raise ValueError("lane projection limitations are incomplete or invalid")

    body = {key: item for key, item in artifact.items() if key != "projection_id"}
    expected_id = "lane-projection-" + canonical_json_sha256(body)[:24]
    if artifact.get("projection_id") != expected_id or _ID.fullmatch(expected_id) is None:
        raise ValueError("lane projection ID/content mismatch")
    return artifact


def validate_lane_projection_binding(
    value: object,
    *,
    eligibility_plan: Mapping[str, Any],
    eligibility_artifact: Mapping[str, Any],
) -> dict[str, Any]:
    """Require a projection to name one exact eligibility artifact/condition."""

    projection = validate_lane_projection(value)
    plan = validate_eligibility_plan(dict(eligibility_plan))
    expected = {
        "plan_id": plan["plan_id"],
        "request_id": plan["request_id"],
        "artifact": dict(eligibility_artifact),
        "experiment_conditions": plan["bindings"].get("experiment_conditions"),
    }
    _validate_descriptor(expected["artifact"])
    _validate_condition(expected["experiment_conditions"])
    if projection["eligibility_binding"] != expected:
        raise ValueError("lane projection does not bind the exact eligibility condition")
    return projection


def build_lane_projection(
    *,
    eligibility_plan: Mapping[str, Any],
    eligibility_artifact: Mapping[str, Any],
    sampling_audits: Mapping[str, Mapping[str, Any]],
    source_policy_cluster_counts: Mapping[str, Mapping[str, int]],
    selected_media_inventories: Mapping[str, Mapping[str, Any]],
    call_projection: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one deterministic projection from an admitted exact request."""

    plan = validate_eligibility_plan(dict(eligibility_plan))
    if (
        plan["execution"]["whole_request_preflight_complete"] is not True
        or plan["execution"]["request_status"] != "whole_request_compatible"
    ):
        raise ValueError("lane projection requires successful whole-request preflight")
    condition = plan["bindings"].get("experiment_conditions")
    _validate_condition(condition)
    selected_corpora = plan["bindings"].get("selected_corpora")
    if not isinstance(selected_corpora, dict):
        raise ValueError("eligibility plan lacks selected-corpus bindings")
    selected_arms = set(sampling_audits)
    if (
        selected_arms != set(source_policy_cluster_counts)
        or selected_arms != set(selected_media_inventories)
        or selected_arms != set(selected_corpora)
        or selected_arms != set(plan["request"]["logical_source_arms"])
    ):
        raise ValueError("lane projection source-arm inventories do not match")

    arms: list[dict[str, Any]] = []
    for arm_id in sorted(selected_arms):
        audit = sampling_audits[arm_id]
        binding = selected_corpora[arm_id]
        selected_ids = audit.get("selected_ids")
        cluster_ids = audit.get("selected_cluster_ids")
        if not isinstance(selected_ids, list) or not isinstance(cluster_ids, list):
            raise ValueError(f"sampling audit {arm_id!r} lacks selected identities")
        if binding.get("selected_records") != len(selected_ids):
            raise ValueError(f"sampling/eligibility record count mismatch for {arm_id!r}")
        if binding.get("selected_datapoint_ids_sha256") != canonical_json_sha256(
            sorted(selected_ids)
        ):
            raise ValueError(f"sampling/eligibility datapoint binding mismatch for {arm_id!r}")
        media_raw = selected_media_inventories[arm_id]
        if media_raw.get("result") not in {"passed", "not_applicable"}:
            raise ValueError(f"selected media inventory failed for {arm_id!r}")
        refs = dict(media_raw.get("refs", {}))
        unique_bytes = dict(media_raw.get("unique_bytes", {}))
        media = {
            "status": "available" if refs else "not_applicable",
            "verification_basis": (
                str(media_raw.get("verification_basis"))
                if refs else "no_physical_media_selected"
            ),
            "inventory_sha256": media_raw.get("inventory_sha256"),
            "refs_by_modality": refs,
            "unique_bytes_by_modality": unique_bytes,
            "total_unique_bytes": sum(unique_bytes.values()),
        }
        arms.append({
            "logical_source_arm": arm_id,
            "converter": audit.get("converter"),
            "selected_converted_corpus_sha256": binding.get(
                "selected_converted_corpus_sha256"
            ),
            "selected_datapoint_ids_sha256": binding.get(
                "selected_datapoint_ids_sha256"
            ),
            "total_records": audit.get("total_records"),
            "selected_records": audit.get("selected_records"),
            "total_clusters": audit.get("total_clusters"),
            "selected_clusters": audit.get("selected_clusters"),
            "selected_cluster_ids_sha256": canonical_json_sha256(sorted(cluster_ids)),
            "sample_seed": audit.get("sample_seed"),
            "limit": audit.get("limit"),
            "source_policy_cluster_counts": dict(
                source_policy_cluster_counts[arm_id]
            ),
            "selected_input_media": media,
        })
    totals = {
        "logical_source_arms": len(arms),
        "selected_records": sum(item["selected_records"] for item in arms),
        "selected_clusters": sum(item["selected_clusters"] for item in arms),
        "source_policy_clusters": sum(
            sum(item["source_policy_cluster_counts"].values()) for item in arms
        ),
        "arm_summed_unique_input_media_bytes": sum(
            item["selected_input_media"]["total_unique_bytes"] for item in arms
        ),
    }
    body: dict[str, Any] = {
        "schema": LANE_PROJECTION_SCHEMA,
        "status": "complete",
        "purpose": "prospective_no_call_exposure_projection",
        "eligibility_binding": {
            "plan_id": plan["plan_id"],
            "request_id": plan["request_id"],
            "artifact": dict(eligibility_artifact),
            "experiment_conditions": condition,
        },
        "selection": {"arms": arms, "totals": totals},
        "call_projection": dict(call_projection),
        "unavailable_estimates": {
            field: {"status": "CANNOT-VERIFY", "value": None, "reason": reason}
            for field, reason in _UNAVAILABLE_REASONS.items()
        },
        "limitations": dict(_LIMITATIONS),
    }
    body["projection_id"] = (
        "lane-projection-" + canonical_json_sha256(body)[:24]
    )
    return validate_lane_projection_binding(
        body,
        eligibility_plan=plan,
        eligibility_artifact=eligibility_artifact,
    )


def lane_projection_bytes(value: Mapping[str, Any]) -> bytes:
    """Return the stable on-disk representation after strict validation."""

    artifact = validate_lane_projection(dict(value))
    return (
        json.dumps(
            artifact,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        ) + "\n"
    ).encode("utf-8")


def write_lane_projection(directory: Path, value: Mapping[str, Any]) -> Path:
    """Retain a projection under its content identity without overwriting."""

    payload = lane_projection_bytes(value)
    artifact = validate_lane_projection(dict(value))
    path = directory / f"{artifact['projection_id']}.lane-projection.json"
    directory.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
            raise ValueError(f"content-addressed lane-projection collision: {path}")
        return path
    with path.open("xb") as handle:
        handle.write(payload)
    return path


def load_lane_projection_file(
    path_value: str | Path,
    expected_sha256: str,
    *,
    max_bytes: int = 4 * 1024 * 1024,
) -> tuple[dict[str, Any], dict[str, object]]:
    """Load exact projection bytes with strict JSON and content validation."""

    expected = _sha256(expected_sha256.lower(), "lane projection expected sha256")
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError("lane projection input must not be a symlink")
    path = unresolved.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("lane projection input must be a regular file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError("lane projection input is empty or exceeds the size limit")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ValueError("lane projection input changed while being read")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected:
        raise ValueError("lane projection byte digest mismatch")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        duplicates = sorted(
            key for key, count in Counter(key for key, _ in pairs).items()
            if count > 1
        )
        if duplicates:
            raise ValueError(
                "duplicate JSON object keys are forbidden: " + ", ".join(duplicates)
            )
        return dict(pairs)

    try:
        raw = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number {token!r} is forbidden")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("lane projection input is malformed JSON") from exc
    projection = validate_lane_projection(raw)
    expected_name = f"{projection['projection_id']}.lane-projection.json"
    if path.name != expected_name:
        raise ValueError("lane projection filename/content identity mismatch")
    return projection, {"file": path.name, "sha256": digest, "bytes": size}


__all__ = [
    "LANE_PROJECTION_SCHEMA",
    "build_lane_projection",
    "lane_projection_bytes",
    "load_lane_projection_file",
    "validate_lane_projection",
    "validate_lane_projection_binding",
    "write_lane_projection",
]
