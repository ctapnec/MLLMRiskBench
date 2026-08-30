"""Join planning, execution, and decision evidence without pooling their units.

The Level-1 artifact is an accounting surface, not a safety score.  A prospective
``ura-request-envelope/4`` fixes whole-arm request units before source loading;
after selected corpora materialize, ``ura-eligibility-plan/3`` names their exact
planning strata.  Bound early failures remain request-unit evidence only because
their modality/source strata cannot be reconstructed honestly.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from experiments.figure_results import (  # noqa: E402
    _GridReference,
    _inside,
    _integer,
    _nonblank,
    _read_object,
    _reject_duplicate_realized_target_arms,
    _sha256_file,
    _string_list,
    _validate_cell,
)
from experiments.suite_summary import (  # noqa: E402
    _final_model_nonresponse,
    _load_eligibility_plan,
)
from ura.data_models import Attempt  # noqa: E402
from ura.adapters._engine_runtime import (  # noqa: E402
    validate_engine_runtime_selection_identity_descriptor,
)
from ura.eligibility import (  # noqa: E402
    ELIGIBILITY_SCHEMA,
    LEGACY_ELIGIBILITY_SCHEMA,
    canonical_json_sha256,
    lifecycle_stratum_id,
    planning_stratum_sha256,
    validate_eligibility_plan,
)
from ura.approximate_metrics import (  # noqa: E402
    validate_approximate_abstention_judgment,
    validate_approximate_completion_bindings,
    validate_approximate_judgment,
)
from ura.live_attestation import (  # noqa: E402
    load_live_attestation_file,
    realized_identity_matches,
    required_attestation_keys,
    route_config_from_grid_request,
    route_config_sha256,
    stable_realized_target_identity,
    validate_required_live_attestations,
)
from ura.model_acquisition_runtime import (  # noqa: E402
    model_acquisition_execution_descriptor,
    model_acquisition_shared_role_projection,
    validate_model_acquisition_execution_descriptor,
    validate_model_acquisition_grid_binding,
    validate_model_acquisition_role_projection,
    validate_model_acquisition_role_projection_binding,
)
from ura.project_revision import validate_project_revision_binding  # noqa: E402
from ura.request_envelope import (  # noqa: E402
    load_request_envelope_file,
    load_request_error_file,
    validate_request_envelope,
    validate_request_envelope_descriptor,
    validate_request_error,
)


LEVEL1_SCHEMA = "ura-level1-evidence/3"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CONDITION_ID = re.compile(r"condition-[0-9a-f]{24}")
_LIVE_ATTESTATION_ID = re.compile(r"live-attestation-[0-9a-f]{24}")
_EXECUTION_SCOPE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_COMPLETE = frozenset({"complete", "complete_existing"})
_STRUCTURAL_NA = frozenset({
    "transport_blocked",
    "requires_source_native_runtime_or_evaluator",
    "requires_substantive_automated_evaluator_or_reference",
    "attack_mode_incompatible",
})
_MAX_ERROR_BYTES = 8 * 1024 * 1024
_CONDITION_FIELDS = frozenset({
    "execution_purpose",
    "project_revision",
    "defense",
    "defense_guard",
    "judges",
    "judge_model",
    "guardrail_model",
    "guardrail_revision",
    "guardrail_device",
    "defense_guardrail_model",
    "defense_guardrail_revision",
    "defense_guardrail_device",
    "seeds",
    "sample_seed",
    "limit",
    "max_queries",
    "max_turns",
    "call_caps",
    "group_keys",
    "quantization",
    "dtype",
    "dry_run",
    "hosted_judge_data_transfer_acknowledged",
    "selected_config_identities",
    "engine_runtimes",
    "model_acquisition",
    "live_attestation",
})
_CONDITION_FIELDS_WITH_SAMPLING_POLICY = frozenset({
    *_CONDITION_FIELDS,
    "sampling_policy",
})
_CSV_FIELDS = (
    "lifecycle_stratum_id",
    "request_id",
    "plan_id",
    "condition_id",
    "requested_target_spec",
    "resolved_target",
    "logical_source_arm",
    "source",
    "exact_modality_combination",
    "execution_mode",
    "metric_mode",
    "semantic_family",
    "expected_behavior",
    "attacker",
    "defense",
    "evidence_kind",
    "planning_status",
    "planning_disposition",
    "scientifically_compatible",
    "execution_eligible",
    "structural_not_applicable",
    "failed_gates",
    "attestation_status",
    "grid_id",
    "grid_locator",
    "execution_evidence_locator",
    "run_id",
    "execution_unit_started",
    "completed",
    "completed_judgment_records",
    "decided_judgment_records",
    "abstained_judgment_records",
    "missing_response_judgment_records",
    "analysis_inclusion_status",
    "included_records",
    "missing",
    "final_disposition",
)


def _strict_json_sha256(value: object) -> str:
    return canonical_json_sha256(value)


def _pretty_json_records(path: Path) -> int:
    """Mirror ``run_matrix._record_count`` for pretty-printed JSON evidence."""

    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _selected_identity(value: object, *, label: str) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be null or an artifact object")
    digest = value.get("normalized_selected_sha256")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError(f"{label} lacks normalized selected SHA-256")
    return {"normalized_selected_sha256": digest}


def _bound_artifact_identity(value: object, *, label: str) -> dict[str, object] | None:
    """Identity of an artifact that is bound whole rather than selected from.

    A reusable registry may hold entries for other lanes, so only the normalized
    selected subset may define execution identity there. A source-conformance
    receipt is not like that: it is bound in its entirety, so its byte identity
    IS its execution identity, and that is what the Runner records for it.
    Demanding the registry shape here rejected every grid that actually bound a
    receipt, which is every real campaign run; it passed unnoticed because a run
    with no receipt bound records null and is accepted.
    """

    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be null or an artifact object")
    digest = value.get("sha256")
    size = value.get("bytes")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError(f"{label} lacks an exact SHA-256")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError(f"{label} lacks an exact byte length")
    # Same keys the Runner hashes for this field, so the recomputed grid
    # identity matches the one in the filename.
    return {"bytes": size, "sha256": digest}


def _identity_validator(field: str):  # noqa: ANN202 - returns one of two callables
    """The identity shape each selected-config field is recorded in."""

    return _bound_artifact_identity if field == "source_conformance" else _selected_identity


def _engine_runtime_selection_identity(
    value: object,
    *,
    label: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        return validate_engine_runtime_selection_identity_descriptor(value)
    except ValueError as exc:
        raise ValueError(f"{label} is invalid: {exc}") from exc


def _live_attestation_projection(value: object) -> dict[str, Any] | None:
    """Validate the exact receipt projection bound into a run condition."""

    if value is None:
        return None
    fields = {"mode", "execution_scope_id", "max_age_hours", "artifacts"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("live-attestation condition has an invalid field inventory")
    mode = value.get("mode")
    if mode not in {"probe", "measured", "not_required"}:
        raise ValueError("live-attestation mode is invalid")
    scope = value.get("execution_scope_id")
    max_age = value.get("max_age_hours")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("live-attestation artifacts must be a list")
    if mode == "not_required":
        if scope is not None or max_age is not None or artifacts:
            raise ValueError(
                "not-required live-attestation condition must be empty"
            )
    else:
        if (
            not isinstance(scope, str)
            or scope != scope.strip()
            or _EXECUTION_SCOPE_ID.fullmatch(scope) is None
        ):
            raise ValueError("live-attestation execution_scope_id is invalid")
        if mode == "measured":
            if (
                isinstance(max_age, bool)
                or not isinstance(max_age, (int, float))
                or not 0 < float(max_age) <= 24 * 365
            ):
                raise ValueError("live-attestation max_age_hours is invalid")
        elif max_age is not None or artifacts:
            raise ValueError(
                "probe live-attestation condition cannot consume artifacts or age"
            )
    normalized: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "file", "sha256", "bytes", "attestation_id",
        }:
            raise ValueError("live-attestation artifact descriptor is incomplete")
        filename = artifact.get("file")
        digest = artifact.get("sha256")
        byte_count = artifact.get("bytes")
        attestation_id = artifact.get("attestation_id")
        if (
            not isinstance(filename, str)
            or not filename
            or Path(filename).name != filename
        ):
            raise ValueError("live-attestation artifact filename is unsafe")
        if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
            raise ValueError("live-attestation artifact SHA-256 is invalid")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count <= 0
        ):
            raise ValueError("live-attestation artifact byte count is invalid")
        if (
            not isinstance(attestation_id, str)
            or _LIVE_ATTESTATION_ID.fullmatch(attestation_id) is None
        ):
            raise ValueError("live-attestation artifact ID is invalid")
        normalized.append(dict(artifact))
    canonical = sorted(
        normalized,
        key=lambda item: (
            item["attestation_id"], item["sha256"], item["file"], item["bytes"]
        ),
    )
    if normalized != canonical or len({
        (item["attestation_id"], item["sha256"], item["bytes"])
        for item in normalized
    }) != len(normalized):
        raise ValueError(
            "live-attestation artifact descriptors must be unique and canonical"
        )
    return {
        "mode": mode,
        "execution_scope_id": scope,
        "max_age_hours": max_age,
        "artifacts": normalized,
    }


def _condition_values(value: object) -> dict[str, Any]:
    """Validate the compact experiment-condition projection used by Level 1."""

    expected_fields = (
        _CONDITION_FIELDS_WITH_SAMPLING_POLICY
        if isinstance(value, dict) and "sampling_policy" in value
        else _CONDITION_FIELDS
    )
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ValueError("eligibility experiment-condition fields are incomplete")
    if "sampling_policy" in value:
        from ura.sampling import effective_sampling_policy  # noqa: PLC0415

        effective_sampling_policy(value["sampling_policy"])
    if value["execution_purpose"] not in {
        "diagnostic_dry_run",
        "preflight_only",
        "attestation_probe",
        "diagnostic_canary",
        "measured_run",
    }:
        raise ValueError("experiment condition execution_purpose is invalid")
    for field in ("defense", "defense_guard", "dtype"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise ValueError(f"experiment condition {field} must be nonblank")
    if not isinstance(value["quantization"], str):
        raise ValueError("experiment condition quantization must be a string")
    for field in (
        "judge_model",
        "guardrail_model",
        "guardrail_revision",
        "guardrail_device",
        "defense_guardrail_model",
        "defense_guardrail_revision",
        "defense_guardrail_device",
    ):
        item = value[field]
        if item is not None and (not isinstance(item, str) or not item.strip()):
            raise ValueError(f"experiment condition {field} must be null or nonblank")
    for field in ("judges", "seeds", "group_keys"):
        items = value[field]
        if not isinstance(items, list) or not items or len(set(items)) != len(items):
            raise ValueError(f"experiment condition {field} must be a non-empty unique list")
    if any(not isinstance(item, str) or not item.strip() for item in value["judges"]):
        raise ValueError("experiment condition judges must contain nonblank strings")
    if any(
        not isinstance(item, int) or isinstance(item, bool) for item in value["seeds"]
    ):
        raise ValueError("experiment condition seeds must contain integers")
    if any(not isinstance(item, str) or not item.strip() for item in value["group_keys"]):
        raise ValueError("experiment condition group_keys must contain nonblank strings")
    for field in ("sample_seed", "limit", "max_queries", "max_turns"):
        item = value[field]
        if not isinstance(item, int) or isinstance(item, bool):
            raise ValueError(f"experiment condition {field} must be an integer")
    if value["limit"] < 0 or value["max_queries"] <= 0 or value["max_turns"] <= 0:
        raise ValueError("experiment condition limit/horizon is out of range")
    call_caps = value["call_caps"]
    expected_caps = {"target", "judge", "http_attempts", "deadline_seconds"}
    if not isinstance(call_caps, dict) or set(call_caps) != expected_caps:
        raise ValueError("experiment condition call_caps is incomplete")
    for field, item in call_caps.items():
        if item is not None and (
            not isinstance(item, int) or isinstance(item, bool) or item <= 0
        ):
            raise ValueError(f"experiment condition call cap {field} is invalid")
    if not isinstance(value["dry_run"], bool) or not isinstance(
        value["hosted_judge_data_transfer_acknowledged"], bool
    ):
        raise ValueError(
            "experiment condition dry_run/data-transfer acknowledgement "
            "must be boolean"
        )
    if value["dry_run"] and value["execution_purpose"] not in {
        "diagnostic_dry_run", "diagnostic_canary"
    }:
        raise ValueError("experiment condition execution purpose/dry-run mismatch")
    if not value["dry_run"] and value["execution_purpose"] == "diagnostic_dry_run":
        raise ValueError("experiment condition execution purpose/dry-run mismatch")
    selected = value["selected_config_identities"]
    expected_selected = {
        "source_config",
        "source_conformance",
        "attacker_config",
        "engine_runtime_config",
        "api_config",
        "local_config",
    }
    if not isinstance(selected, dict) or set(selected) != expected_selected:
        raise ValueError("experiment condition selected-config identities are incomplete")
    for field in sorted(expected_selected):
        _identity_validator(field)(selected[field], label=f"selected {field}")
    _engine_runtime_selection_identity(
        value["engine_runtimes"], label="experiment condition engine runtimes"
    )
    acquisition = validate_model_acquisition_role_projection(
        value["model_acquisition"]
    )
    if acquisition["scope"] != "shared":
        raise ValueError("experiment condition acquisition projection is not shared")
    validate_project_revision_binding(
        value["project_revision"], allow_not_required=value["dry_run"]
    )
    _live_attestation_projection(value["live_attestation"])
    return value


def _legacy_condition_values(value: object) -> dict[str, Any]:
    """Normalize the exact runtime-free eligibility-v2 projection."""

    legacy_fields = _CONDITION_FIELDS - {"engine_runtimes"}
    if not isinstance(value, dict) or set(value) != legacy_fields:
        raise ValueError(
            "legacy eligibility experiment-condition fields are incomplete"
        )
    selected = value.get("selected_config_identities")
    legacy_selected_fields = {
        "source_config",
        "source_conformance",
        "attacker_config",
        "api_config",
        "local_config",
    }
    if not isinstance(selected, dict) or set(selected) != legacy_selected_fields:
        raise ValueError(
            "legacy eligibility selected-config identities are incomplete"
        )
    normalized = dict(value)
    normalized["selected_config_identities"] = {
        **selected,
        "engine_runtime_config": None,
    }
    normalized["engine_runtimes"] = None
    return _condition_values(normalized)


def _condition_from_plan(plan: dict[str, Any]) -> dict[str, Any]:
    bindings = plan["bindings"]
    raw = bindings.get("experiment_conditions")
    if not isinstance(raw, dict) or set(raw) != {"condition_id", "values"}:
        raise ValueError(
            f"eligibility plan {plan['plan_id']} lacks exact experiment conditions"
        )
    raw_values = raw["values"]
    if plan["schema"] == LEGACY_ELIGIBILITY_SCHEMA:
        values = _legacy_condition_values(raw_values)
    else:
        values = _condition_values(raw_values)
    condition_id = raw["condition_id"]
    if (
        not isinstance(condition_id, str)
        or _CONDITION_ID.fullmatch(condition_id) is None
        or condition_id != "condition-" + _strict_json_sha256(raw_values)[:24]
    ):
        raise ValueError("eligibility experiment condition ID/content mismatch")
    if values["dry_run"] is not plan["request"]["dry_run"]:
        raise ValueError("eligibility request/condition dry-run mismatch")
    project_revision = validate_project_revision_binding(
        bindings.get("project_revision"),
        allow_not_required=values["dry_run"] is True,
    )
    if project_revision != values["project_revision"]:
        raise ValueError("eligibility project-revision condition mismatch")
    selected = bindings.get("selected_config_identities")
    if plan["schema"] == LEGACY_ELIGIBILITY_SCHEMA:
        if "engine_runtimes" in bindings:
            raise ValueError(
                "legacy eligibility binding unexpectedly contains engine runtimes"
            )
        selected = _legacy_condition_values({
            **raw_values,
            "selected_config_identities": selected,
        })["selected_config_identities"]
    if not isinstance(selected, dict) or selected != values[
        "selected_config_identities"
    ]:
        raise ValueError("eligibility selected-config condition mismatch")
    if _engine_runtime_selection_identity(
        bindings.get("engine_runtimes"), label="eligibility engine runtimes"
    ) != _engine_runtime_selection_identity(
        values["engine_runtimes"], label="experiment condition engine runtimes"
    ):
        raise ValueError("eligibility engine-runtime condition mismatch")
    full_acquisition = validate_model_acquisition_execution_descriptor(
        bindings.get("model_acquisition")
    )
    try:
        validate_model_acquisition_role_projection_binding(
            values["model_acquisition"],
            full_acquisition,
        )
    except ValueError as exc:
        raise ValueError("eligibility model-acquisition condition mismatch") from exc
    validate_request_envelope_descriptor(bindings.get("request_envelope"))
    for field in (
        "source_instances_sha256",
        "attacker_configs_sha256",
        "api_configs_sha256",
        "local_configs_sha256",
    ):
        digest = bindings.get(field)
        if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
            raise ValueError(f"eligibility binding {field} is not SHA-256")
    return {"condition_id": condition_id, "values": values}


def _grid_condition(
    request: Mapping[str, Any], *, eligibility_schema: str = ELIGIBILITY_SCHEMA
) -> dict[str, Any]:
    judges = request.get("judges")
    if not isinstance(judges, list):
        raise ValueError("grid request judges must be a list")
    budget = request.get("global_call_budget")
    if not isinstance(budget, dict):
        raise ValueError("grid request lacks the global call-budget condition")
    legacy = eligibility_schema == LEGACY_ELIGIBILITY_SCHEMA
    if legacy and (
        "engine_runtime_config_artifact" in request
        or "engine_runtimes" in request
    ):
        raise ValueError(
            "legacy runtime-free grid unexpectedly contains engine runtime fields"
        )
    selected = {
        "source_config": _selected_identity(
            request.get("source_config_artifact"), label="source config"
        ),
        "source_conformance": _bound_artifact_identity(
            request.get("source_conformance_artifact"), label="source conformance"
        ),
        "attacker_config": _selected_identity(
            request.get("attacker_config_artifact"), label="attacker config"
        ),
        "engine_runtime_config": _selected_identity(
            request.get("engine_runtime_config_artifact"),
            label="engine runtime config",
        ),
        "api_config": _selected_identity(
            request.get("api_config_artifact"), label="API config"
        ),
        "local_config": _selected_identity(
            request.get("local_config_artifact"), label="local config"
        ),
    }
    values = {
        "execution_purpose": request.get("execution_purpose"),
        "project_revision": validate_project_revision_binding(
            request.get("project_revision")
        ),
        "defense": request.get("defense"),
        "defense_guard": request.get("defense_guard"),
        "judges": judges,
        "judge_model": request.get("judge_model") if "llm" in judges else None,
        "guardrail_model": request.get("guardrail_model"),
        "guardrail_revision": request.get("guardrail_revision"),
        "guardrail_device": request.get("guardrail_device"),
        "defense_guardrail_model": request.get("defense_guardrail_model"),
        "defense_guardrail_revision": request.get("defense_guardrail_revision"),
        "defense_guardrail_device": request.get("defense_guardrail_device"),
        "seeds": request.get("seeds"),
        "sample_seed": request.get("sample_seed"),
        "limit": request.get("limit"),
        "max_queries": request.get("max_queries"),
        "max_turns": request.get("max_turns"),
        "call_caps": {
            "target": budget.get("max_target_calls"),
            "judge": budget.get("max_judge_calls"),
            "http_attempts": budget.get("max_http_attempts"),
            "deadline_seconds": budget.get(
                "call_start_deadline_seconds_from_first_invocation"
            ),
        },
        "group_keys": request.get("group_keys"),
        "quantization": request.get("quantization"),
        "dtype": request.get("dtype"),
        "dry_run": request.get("dry_run"),
        "hosted_judge_data_transfer_acknowledged": request.get(
            "hosted_judge_data_transfer_acknowledged"
        ),
        "selected_config_identities": selected,
        "engine_runtimes": _engine_runtime_selection_identity(
            request.get("engine_runtimes"), label="grid engine runtimes"
        ),
        "model_acquisition": model_acquisition_shared_role_projection(
            request.get("model_acquisition_execution")
        ),
        "live_attestation": _live_attestation_projection(
            request.get("live_attestation")
        ),
    }
    if "sampling_policy" in request:
        values["sampling_policy"] = request["sampling_policy"]
    if legacy:
        legacy_values = dict(values)
        legacy_selected = dict(selected)
        del legacy_selected["engine_runtime_config"]
        legacy_values["selected_config_identities"] = legacy_selected
        del legacy_values["engine_runtimes"]
        condition_id = "condition-" + _strict_json_sha256(legacy_values)[:24]
    else:
        condition_id = "condition-" + _strict_json_sha256(values)[:24]
    return {
        "condition_id": condition_id,
        "values": values,
    }


def _validate_grid_plan_bindings(
    request: Mapping[str, Any], plan: Mapping[str, Any]
) -> None:
    bindings = plan["bindings"]
    if validate_request_envelope_descriptor(
        request.get("request_envelope")
    ) != validate_request_envelope_descriptor(bindings.get("request_envelope")):
        raise ValueError("grid/eligibility request-envelope binding mismatch")
    if request.get("driver_source") != bindings.get("driver_source"):
        raise ValueError("grid/eligibility driver-source binding mismatch")
    project_revision = validate_project_revision_binding(
        request.get("project_revision")
    )
    if project_revision != validate_project_revision_binding(
        bindings.get("project_revision")
    ):
        raise ValueError("grid/eligibility project-revision binding mismatch")
    if validate_model_acquisition_execution_descriptor(
        request.get("model_acquisition_execution")
    ) != validate_model_acquisition_execution_descriptor(
        bindings.get("model_acquisition")
    ):
        raise ValueError("grid/eligibility model-acquisition binding mismatch")
    if _engine_runtime_selection_identity(
        request.get("engine_runtimes"), label="grid engine runtimes"
    ) != _engine_runtime_selection_identity(
        bindings.get("engine_runtimes"), label="eligibility engine runtimes"
    ):
        raise ValueError("grid/eligibility engine-runtime binding mismatch")
    harness_source = request.get("harness_source")
    driver_source = request.get("driver_source")
    if (
        not isinstance(harness_source, dict)
        or project_revision["harness_source_sha256"]
        != harness_source.get("sha256")
    ):
        raise ValueError("grid/project-revision harness-source mismatch")
    if (
        not isinstance(driver_source, dict)
        or project_revision["driver_source_sha256"]
        != driver_source.get("sha256")
    ):
        raise ValueError("grid/project-revision driver-source mismatch")
    for request_field, binding_field in (
        ("source_instances", "source_instances_sha256"),
        ("attacker_configs", "attacker_configs_sha256"),
        ("api_configs", "api_configs_sha256"),
        ("local_configs", "local_configs_sha256"),
    ):
        if _strict_json_sha256(request.get(request_field)) != bindings.get(
            binding_field
        ):
            raise ValueError(
                f"grid/eligibility {request_field.replace('_', '-')} binding mismatch"
            )


def _evidence_artifact(path: Path, *, root: Path) -> dict[str, Any]:
    return {
        "locator": str(path.relative_to(root)),
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _plan_artifact(path: Path) -> tuple[dict[str, Any], str, str, int, int]:
    plan, digest, locator = _load_eligibility_plan(path)
    validate_eligibility_plan(plan)
    condition = _condition_from_plan(plan)
    del condition
    return plan, digest, locator, path.stat().st_size, _pretty_json_records(path)


def _request_envelope_artifact(path: Path) -> dict[str, Any]:
    envelope, descriptor = load_request_envelope_file(path)
    return {"envelope": envelope, "descriptor": descriptor}


def _load_live_attestation_artifact(
    path: Path, expected_sha256: str
) -> dict[str, Any]:
    manifest, descriptor = load_live_attestation_file(path, expected_sha256)
    return {
        "manifest": manifest,
        "descriptor": {
            **descriptor,
            "attestation_id": manifest["attestation_id"],
        },
    }


def _utc_timestamp(value: object, *, label: str) -> datetime:
    text = _nonblank(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is not an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must be timezone-aware UTC")
    return parsed


def _bind_live_attestations(
    grids_by_plan: Mapping[str, dict[str, Any]],
    plans: Mapping[str, tuple[dict[str, Any], str, str, int, int]],
    artifacts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Validate grid-bound receipts and attach exact prerequisite references."""

    # The producer retains a content-addressed copy under a new basename.  The
    # semantic receipt identity is therefore its typed ID plus exact bytes, not
    # the packaging locator used by either command.
    supplied: dict[tuple[object, ...], dict[str, Any]] = {}
    seen_ids: dict[str, tuple[object, ...]] = {}
    for artifact in artifacts:
        descriptor = artifact["descriptor"]
        key = (
            descriptor["sha256"],
            descriptor["bytes"],
            descriptor["attestation_id"],
        )
        if key in supplied:
            raise ValueError("duplicate --live-attestation input")
        prior = seen_ids.setdefault(descriptor["attestation_id"], key)
        if prior != key:
            raise ValueError("one live-attestation ID has multiple byte descriptors")
        supplied[key] = artifact

    used: set[tuple[object, ...]] = set()
    matched_record_ids: set[str] = set()
    realized_measured_grids = 0
    for plan_id, grid in grids_by_plan.items():
        plan = plans[plan_id][0]
        request = grid["request"]
        projection = _live_attestation_projection(request.get("live_attestation"))
        attestation_probe = request.get("attestation_probe")
        if not isinstance(attestation_probe, bool):
            raise ValueError("grid request lacks boolean attestation_probe")
        if request.get("dry_run") is True:
            if (
                attestation_probe
                or projection is None
                or projection["mode"] != "not_required"
            ):
                raise ValueError("diagnostic dry-run grid cannot bind live attestations")
            grid["live_attestations"] = {}
            continue
        if projection is None:
            raise ValueError("measured grid lacks typed live-attestation prerequisites")
        if projection["mode"] == "probe":
            if not attestation_probe:
                raise ValueError("live-attestation probe mode lacks probe declaration")
            raise ValueError(
                "attestation probe grids are diagnostic prerequisite evidence, "
                "not Level-1 measured-result inputs"
            )
        if projection["mode"] != "measured":
            raise ValueError("non-probe live grid must use measured attestation mode")
        if attestation_probe:
            raise ValueError("measured grid cannot declare attestation_probe=true")
        realized_measured_grids += 1

        selected_artifacts: list[dict[str, Any]] = []
        for descriptor in projection["artifacts"]:
            key = (
                descriptor["sha256"],
                descriptor["bytes"],
                descriptor["attestation_id"],
            )
            artifact = supplied.get(key)
            if artifact is None:
                raise ValueError(
                    "grid-bound live-attestation artifact was not supplied exactly"
                )
            used.add(key)
            selected_artifacts.append(artifact)

        scope = projection["execution_scope_id"]
        required = required_attestation_keys(
            execution_scope_id=scope,
            requested_target_specs=plan["request"]["requested_target_specs"],
            eligibility_items=plan["items"],
        )
        planned_resolved_targets: dict[str, str] = {}
        for item in plan["items"]:
            if item["status"] != "compatible_if_isolated":
                continue
            requested = item["requested_target_spec"]
            resolved = item["resolved_target"]
            if not isinstance(resolved, str) or not resolved:
                raise ValueError("attestation-required planning row lacks resolved target")
            prior = planned_resolved_targets.setdefault(requested, resolved)
            if prior != resolved:
                raise ValueError("one requested target has multiple resolved identities")

        resolved_targets: dict[str, str] = {}
        route_config: dict[str, str] = {}
        route_kinds: dict[str, str] = {}
        for artifact in selected_artifacts:
            for record in artifact["manifest"]["records"]:
                key = (
                    record["execution_scope_id"],
                    record["requested_target_spec"],
                    tuple(record["exact_input_modalities"]),
                )
                if key not in required:
                    continue
                requested = record["requested_target_spec"]
                planned_resolved = planned_resolved_targets[requested]
                attested_resolved = record["resolved_target"]
                if planned_resolved not in {
                    attested_resolved,
                    f"{attested_resolved}+guard",
                }:
                    raise ValueError(
                        "live attestation does not resolve the planned base target"
                    )
                previous_resolved = resolved_targets.setdefault(
                    requested, attested_resolved
                )
                if previous_resolved != attested_resolved:
                    raise ValueError(
                        "required live attestations disagree on resolved target"
                    )
                expected_route_kind = (
                    "local_runtime"
                    if requested.startswith(("vllm:", "ollama:"))
                    else "hosted_api"
                )
                if record["route_kind"] != expected_route_kind:
                    raise ValueError(
                        "live attestation route kind differs from requested target"
                    )
                selected_route_config = route_config_from_grid_request(
                    request,
                    route_kind=expected_route_kind,
                    requested_target_spec=requested,
                    resolved_target=attested_resolved,
                )
                previous_config = route_config.setdefault(
                    requested,
                    route_config_sha256(
                        route_kind=expected_route_kind,
                        requested_target_spec=requested,
                        resolved_target=attested_resolved,
                        route_config=selected_route_config,
                    ),
                )
                previous_kind = route_kinds.setdefault(
                    requested, expected_route_kind
                )
                if (
                    previous_config != record["route_config_sha256"]
                    or previous_kind != record["route_kind"]
                ):
                    raise ValueError(
                        "required live attestations disagree on target route identity"
                    )
        target_conditions = request.get("target_execution_conditions")
        if not isinstance(target_conditions, dict):
            raise ValueError(
                "measured grid lacks target execution-condition identities"
            )
        matched = validate_required_live_attestations(
            [artifact["manifest"] for artifact in selected_artifacts],
            required_keys=required,
            resolved_targets=resolved_targets,
            route_config_sha256=route_config,
            route_kind=route_kinds,
            target_condition_sha256=target_conditions,
            current_harness_source_sha256=_nonblank(
                request.get("harness_source", {}).get("sha256")
                if isinstance(request.get("harness_source"), dict)
                else None,
                "measured grid harness source sha256",
            ),
            current_driver_source_sha256=_nonblank(
                request.get("driver_source", {}).get("sha256")
                if isinstance(request.get("driver_source"), dict)
                else None,
                "measured grid experiment driver source sha256",
            ),
            current_project_revision=validate_project_revision_binding(
                request.get("project_revision"), allow_not_required=False
            ),
            reference_time=_utc_timestamp(
                grid.get("started_at"), label="measured grid started_at"
            ),
            max_age_hours=projection["max_age_hours"],
        )
        expected_identity_by_target: dict[str, dict[str, Any]] = {}
        for key, record in matched.items():
            expected_identity_by_target.setdefault(
                key[1], record["realized_target_identity"]
            )
        for cell in grid["cells"].values():
            if cell["status"] not in _COMPLETE:
                continue
            validated = cell["validated_cell"]
            run = validated["manifest"]["config"]["run"]
            requested = run.get("requested_model_spec") or run.get("model_spec")
            if requested not in expected_identity_by_target:
                # Current manifests persist the resolved model_spec; recover the
                # requested key through the exact plan mapping.
                matches = [
                    key
                    for key, resolved in planned_resolved_targets.items()
                    if resolved == run.get("model_spec")
                ]
                if len(matches) != 1:
                    raise ValueError(
                        "completed cell cannot be mapped to one attested target"
                    )
                requested = matches[0]
            observed_identity = validated["realized_identities"]["target"][
                "snapshot"
            ]
            # An input-defense-only cell made no target call and therefore has
            # no provider/runtime identity to compare. When one was observed,
            # it must still match the admission receipt independently here.
            if stable_realized_target_identity(observed_identity) and not (
                realized_identity_matches(
                    expected_identity_by_target[requested], observed_identity
                )
            ):
                raise ValueError(
                    "completed cell realized target identity differs from its "
                    "live attestation"
                )
        references: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
        for key, record in matched.items():
            owners = [
                artifact
                for artifact in selected_artifacts
                if any(
                    candidate["record_id"] == record["record_id"]
                    for candidate in artifact["manifest"]["records"]
                )
            ]
            if len(owners) != 1:
                raise ValueError("attested record does not have exactly one artifact owner")
            owner = owners[0]
            matched_record_ids.add(record["record_id"])
            references[key] = {
                "attestation_id": owner["manifest"]["attestation_id"],
                "record_id": record["record_id"],
                "artifact": {
                    "attestation_id": owner["descriptor"]["attestation_id"],
                    "sha256": owner["descriptor"]["sha256"],
                    "bytes": owner["descriptor"]["bytes"],
                    "supplied_file": owner["descriptor"]["file"],
                    "retained_grid_file": next(
                        descriptor["file"]
                        for descriptor in projection["artifacts"]
                        if (
                            descriptor["attestation_id"],
                            descriptor["sha256"],
                            descriptor["bytes"],
                        ) == (
                            owner["descriptor"]["attestation_id"],
                            owner["descriptor"]["sha256"],
                            owner["descriptor"]["bytes"],
                        )
                    ),
                },
                "observed_at_utc": record["observed_at_utc"],
                "evidence_kind": record["probe"]["evidence_kind"],
                "probe_grid_id": record["probe"]["grid_id"],
                "probe_run_id": record["probe"]["run_id"],
            }
        grid["live_attestations"] = references

    unused = set(supplied) - used
    if realized_measured_grids and unused:
        raise ValueError("supplied live-attestation artifact is outside the grid cohort")
    if not artifacts:
        return None
    descriptors = sorted(
        (dict(artifact["descriptor"]) for artifact in artifacts),
        key=lambda item: (item["attestation_id"], item["sha256"], item["file"]),
    )
    return {
        "status": (
            "validated"
            if realized_measured_grids
            else "not_evaluated_no_realized_measured_grid"
        ),
        "artifacts": descriptors,
        "artifact_count": len(descriptors),
        "matched_record_count": len(matched_record_ids),
        "scope": "target_route_and_byte_backed_transport_only",
    }


def _artifact_path(
    root: Path, parent: Path, descriptor: object, *, label: str
) -> Path:
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "file",
        "sha256",
        "bytes",
        "records",
    }:
        raise ValueError(f"{label} lacks an exact artifact descriptor")
    filename = descriptor.get("file")
    if not isinstance(filename, str) or Path(filename).name != filename:
        raise ValueError(f"unsafe {label} artifact name")
    candidate = parent / filename
    if candidate.is_symlink():
        raise ValueError(f"{label} artifact must not be a symlink: {candidate}")
    path = _inside(root, candidate)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} artifact is not a regular file: {path}")
    digest = descriptor.get("sha256")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError(f"{label} artifact has invalid SHA-256")
    if descriptor.get("bytes") != path.stat().st_size:
        raise ValueError(f"{label} artifact byte-count mismatch")
    if digest != _sha256_file(path):
        raise ValueError(f"{label} artifact digest mismatch")
    if descriptor.get("records") != _pretty_json_records(path):
        raise ValueError(f"{label} artifact record-count mismatch")
    return path


def _grid_id(grid: dict[str, Any], *, legacy_runtime_free: bool = False) -> str:
    request = grid["request"]
    identity = dict(request)
    config_fields = [
        "source_config_artifact",
        "source_conformance_artifact",
        "attacker_config_artifact",
        "api_config_artifact",
        "local_config_artifact",
    ]
    if legacy_runtime_free:
        if (
            "engine_runtime_config_artifact" in request
            or "engine_runtimes" in request
        ):
            raise ValueError(
                "legacy runtime-free grid unexpectedly contains engine runtime fields"
            )
    else:
        config_fields.insert(3, "engine_runtime_config_artifact")
    for field in config_fields:
        # Dispatch per field, exactly as the Runner does when it derives this
        # identity. A bound receipt is hashed by its byte identity; the reusable
        # registries are hashed by their normalized selected subset. The stored
        # artifact carries both digests, so reading the wrong one raised no
        # error at all: it silently produced a different grid identity than the
        # one in the filename, and every real run failed the match.
        identity[field] = _identity_validator(
            field.removesuffix("_artifact")
        )(request.get(field), label=field.replace("_", " "))
    identity["model_acquisition"] = (
        validate_model_acquisition_execution_descriptor(
            request.get("model_acquisition_execution")
        )
    )
    return "grid-" + _strict_json_sha256(identity)[:24]


def _validate_grid_model_acquisition(
    request: Mapping[str, Any],
    *,
    evidence_root: Path,
) -> dict[str, Any]:
    """Validate Level-1's full event evidence and grid-wide stable roster."""

    full = model_acquisition_execution_descriptor(
        request.get("model_acquisition"),
        evidence_root=evidence_root,
    )
    stable = validate_model_acquisition_execution_descriptor(
        request.get("model_acquisition_execution")
    )
    validate_model_acquisition_grid_binding(stable, request)
    if full != stable:
        raise ValueError("grid model-acquisition execution identity is stale")
    return stable


def _plan_descriptor_matches(
    descriptor: object,
    artifact: tuple[dict[str, Any], str, str, int, int],
) -> bool:
    plan, digest, locator, byte_count, records = artifact
    return descriptor == {
        "plan_id": plan["plan_id"],
        "file": locator,
        "sha256": digest,
        "bytes": byte_count,
        "records": records,
        "counts": plan["counts"],
    }


def _error_record(path: Path, *, root: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_ERROR_BYTES:
        raise ValueError(f"invalid request-level error artifact: {path}")
    value = _read_object(path)
    if value.get("status") != "error":
        raise ValueError(f"error artifact does not declare status=error: {path}")
    if value.get("schema") == "ura-request-error/1":
        error = load_request_error_file(path)
        return {
            "locator": str(path.relative_to(root)),
            "sha256": _sha256_file(path),
            "bytes": path.stat().st_size,
            "phase": error["failure"]["phase"],
            "scope": "bound_pre_materialization_request_error",
            "request_error": error,
        }
    phase = _nonblank(value.get("phase"), f"error phase in {path}")
    return {
        "locator": str(path.relative_to(root)),
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
        "phase": phase,
        "scope": "unstratified_request_or_preflight_error_not_bound_to_a_grid_cell",
    }


def _load_results(
    roots: Iterable[Path],
    plans: Mapping[str, tuple[dict[str, Any], str, str, int, int]],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    resolved_roots = [root.resolve(strict=True) for root in roots]
    if len(set(resolved_roots)) != len(resolved_roots):
        raise ValueError("duplicate --results root")
    for index, first in enumerate(resolved_roots):
        if not first.is_dir():
            raise ValueError(f"results root is not a directory: {first}")
        for second in resolved_roots[index + 1 :]:
            if first in second.parents or second in first.parents:
                raise ValueError("nested --results roots would double-count artifacts")

    grids_by_plan: dict[str, dict[str, Any]] = {}
    seen_grid_ids: set[str] = set()
    request_errors: list[dict[str, Any]] = []
    for root in resolved_roots:
        locks = sorted([*root.rglob("*.grid.lock"), *root.rglob("*.cell.lock")])
        if locks:
            raise ValueError(f"results cohort is still locked/running: {locks[0]}")
        referenced_markers: set[Path] = set()
        referenced_errors: set[Path] = set()
        for grid_path in sorted(root.rglob("*.grid.json")):
            grid = _read_object(grid_path)
            grid_id = _nonblank(grid.get("grid_id"), f"grid_id in {grid_path}")
            request = grid.get("request")
            if not isinstance(request, dict):
                raise ValueError(f"grid lacks request: {grid_path}")
            if request.get("execution_purpose") == "diagnostic_canary":
                raise ValueError(
                    f"diagnostic canary is not Level-1 measured evidence: {grid_path}"
                )
            try:
                _validate_grid_model_acquisition(
                    request,
                    evidence_root=grid_path.parent.resolve(),
                )
            except ValueError as exc:
                raise ValueError(
                    f"grid model-acquisition evidence is invalid: "
                    f"{grid_path}: {exc}"
                ) from exc
            descriptor = request.get("eligibility_plan")
            if not isinstance(descriptor, dict):
                raise ValueError(f"grid lacks eligibility descriptor: {grid_path}")
            plan_id = descriptor.get("plan_id")
            if not isinstance(plan_id, str) or plan_id not in plans:
                raise ValueError(f"grid eligibility plan was not supplied: {grid_path}")
            if plan_id in grids_by_plan:
                raise ValueError(f"more than one grid binds eligibility plan {plan_id}")
            plan_artifact = plans[plan_id]
            plan = plan_artifact[0]
            if grid_id != _grid_id(
                grid,
                legacy_runtime_free=plan["schema"] == LEGACY_ELIGIBILITY_SCHEMA,
            ) or grid_path.name != f"{grid_id}.grid.json":
                raise ValueError(f"grid ID/content/filename mismatch: {grid_path}")
            if grid_id in seen_grid_ids:
                raise ValueError(f"duplicate grid identity: {grid_id}")
            seen_grid_ids.add(grid_id)
            if not _plan_descriptor_matches(descriptor, plan_artifact):
                raise ValueError(f"grid/eligibility artifact descriptor mismatch: {grid_path}")
            if _grid_condition(
                request, eligibility_schema=plan["schema"]
            ) != _condition_from_plan(plan):
                raise ValueError(f"grid/eligibility experiment-condition mismatch: {grid_path}")
            _validate_grid_plan_bindings(request, plan)

            models = _string_list(request.get("models"), f"models in {grid_path}")
            corpora = _string_list(request.get("corpora"), f"corpora in {grid_path}")
            attackers = _string_list(
                request.get("attackers"), f"attackers in {grid_path}"
            )
            requested_to_resolved: dict[str, str] = {}
            for item in plan["items"]:
                requested_target = item["requested_target_spec"]
                resolved_target = item["resolved_target"]
                if not isinstance(resolved_target, str) or not resolved_target:
                    raise ValueError(
                        "grid-bound eligibility item lacks a resolved target"
                    )
                previous = requested_to_resolved.setdefault(
                    requested_target, resolved_target
                )
                if previous != resolved_target:
                    raise ValueError(
                        "eligibility request maps one target spec to multiple "
                        "resolved targets"
                    )
            resolved_models = [
                requested_to_resolved[requested_target]
                for requested_target in plan["request"]["requested_target_specs"]
            ]
            if (
                models != resolved_models
                or sorted(corpora) != plan["request"]["logical_source_arms"]
                or attackers != plan["request"]["selected_attackers"]
            ):
                raise ValueError(f"grid/eligibility requested axes mismatch: {grid_path}")
            expected = {
                (model, corpus, attacker)
                for model in models
                for corpus in corpora
                for attacker in attackers
            }
            statuses = grid.get("cells")
            requested = len(expected)
            if (
                not isinstance(statuses, list)
                or len(statuses) != requested
                or _integer(grid.get("requested_cells"), "requested_cells") != requested
                or _integer(grid.get("accounted_cells"), "accounted_cells") != requested
            ):
                raise ValueError(f"grid requested-cell accounting mismatch: {grid_path}")
            observed: set[tuple[str, str, str]] = set()
            cells: dict[tuple[str, str, str], dict[str, Any]] = {}
            error_cells = 0
            for raw_status in statuses:
                if not isinstance(raw_status, dict):
                    raise ValueError(f"grid contains a non-object cell: {grid_path}")
                key = (
                    _nonblank(raw_status.get("model_spec"), "cell model_spec"),
                    _nonblank(raw_status.get("corpus"), "cell corpus"),
                    _nonblank(raw_status.get("attacker"), "cell attacker"),
                )
                if key in observed:
                    raise ValueError(f"grid contains duplicate cell {key!r}: {grid_path}")
                observed.add(key)
                status = raw_status.get("status")
                if status in _COMPLETE:
                    if raw_status.get("execution_started") not in (None, True):
                        raise ValueError("completed grid cell cannot say execution_started=false")
                    marker_name = _nonblank(
                        raw_status.get("completion_marker"), "completion marker"
                    )
                    if Path(marker_name).name != marker_name:
                        raise ValueError("unsafe completion-marker name")
                    marker_candidate = grid_path.parent / marker_name
                    if marker_candidate.is_symlink():
                        raise ValueError(
                            f"completion marker must not be a symlink: {marker_candidate}"
                        )
                    marker_path = _inside(root, marker_candidate)
                    if marker_path in referenced_markers:
                        raise ValueError("completion marker referenced more than once")
                    referenced_markers.add(marker_path)
                    ref = _GridReference(
                        grid_id,
                        grid_path,
                        request,
                        raw_status,
                        plan,
                        grid.get("engine_runtime_close"),
                    )
                    cell = _validate_cell(
                        marker_path,
                        [ref],
                        allow_diagnostic_dry_run=request.get("dry_run") is True,
                    )
                    cells[key] = {
                        "status": status,
                        "execution_started": True,
                        "run_id": cell["run_id"],
                        "marker": str(marker_path.relative_to(root)),
                        "evidence_artifact": _evidence_artifact(
                            marker_path, root=root
                        ),
                        "validated_cell": cell,
                    }
                elif status == "error":
                    error_cells += 1
                    started = raw_status.get("execution_started")
                    if not isinstance(started, bool):
                        raise ValueError("error grid cell lacks execution_started boolean")
                    phase = _nonblank(raw_status.get("phase"), "error grid-cell phase")
                    error_path = _artifact_path(
                        root,
                        grid_path.parent,
                        raw_status.get("error_artifact"),
                        label="cell error",
                    )
                    referenced_errors.add(error_path)
                    error_value = _read_object(error_path)
                    expected_error_identity = {
                        "status": "error",
                        "grid_id": grid_id,
                        "model_spec": key[0],
                        "corpus": key[1],
                        "attacker": key[2],
                        "run_id": raw_status.get("run_id"),
                        "phase": phase,
                        "execution_started": started,
                    }
                    for field, expected_value in expected_error_identity.items():
                        if error_value.get(field) != expected_value:
                            raise ValueError(f"grid/error {field} identity mismatch")
                    if started and (
                        not isinstance(expected_error_identity["run_id"], str)
                        or not expected_error_identity["run_id"]
                    ):
                        raise ValueError("started grid/error lacks a run identity")
                    cells[key] = {
                        "status": "error",
                        "execution_started": started,
                        "run_id": raw_status.get("run_id"),
                        "error": str(error_path.relative_to(root)),
                        "evidence_artifact": _evidence_artifact(
                            error_path, root=root
                        ),
                    }
                else:
                    raise ValueError(f"unsupported grid cell status {status!r}")
            if observed != expected:
                raise ValueError(f"grid Cartesian inventory mismatch: {grid_path}")
            n_errors = _integer(grid.get("n_errors"), f"n_errors in {grid_path}")
            modality_result = grid.get("modality_coverage_result")
            if not isinstance(modality_result, dict):
                raise ValueError(f"grid lacks modality coverage result: {grid_path}")
            if modality_result.get("status") == "failed":
                modality_errors = 1
            elif modality_result.get("schema") in {
                "ura-modality-coverage-result/1",
                "ura-modality-coverage-result/2",
            }:
                modality_errors = 0
            else:
                raise ValueError(f"invalid modality coverage result: {grid_path}")
            expected_errors = error_cells + modality_errors
            if n_errors != expected_errors:
                raise ValueError(f"grid error accounting does not reconcile: {grid_path}")
            if grid.get("status") == "complete":
                if n_errors != 0:
                    raise ValueError(f"complete grid retains errors: {grid_path}")
            elif grid.get("status") == "partial":
                if n_errors < 1:
                    raise ValueError(f"partial grid error accounting mismatch: {grid_path}")
            else:
                raise ValueError(f"final Level-1 inventory rejects running grid: {grid_path}")
            grids_by_plan[plan_id] = {
                "grid_id": grid_id,
                "grid_status": grid["status"],
                "started_at": grid.get("started_at"),
                "grid_locator": str(grid_path.relative_to(root)),
                "grid_artifact": _evidence_artifact(grid_path, root=root),
                "root": str(root),
                "request": request,
                "cells": cells,
                "n_errors": n_errors,
            }

        marker_candidates = set(root.rglob("*.complete.json"))
        symlink_markers = [path for path in marker_candidates if path.is_symlink()]
        if symlink_markers:
            raise ValueError(f"completion marker must not be a symlink: {symlink_markers[0]}")
        discovered_markers = {path.resolve() for path in marker_candidates}
        if discovered_markers != referenced_markers:
            raise ValueError(
                "grid/completion-marker inventory mismatch: "
                f"orphaned={sorted(map(str, discovered_markers - referenced_markers))!r}, "
                f"missing={sorted(map(str, referenced_markers - discovered_markers))!r}"
            )
        for error_path in sorted(root.rglob("*.error.json")):
            if error_path.is_symlink():
                raise ValueError(f"error artifact must not be a symlink: {error_path}")
            resolved = error_path.resolve(strict=True)
            if resolved not in referenced_errors:
                request_errors.append(_error_record(resolved, root=root))
    _reject_duplicate_realized_target_arms([
        cell["validated_cell"]
        for grid in grids_by_plan.values()
        for cell in grid["cells"].values()
        if isinstance(cell, dict) and "validated_cell" in cell
    ])
    request_errors.sort(key=lambda item: (item["locator"], item["sha256"]))
    return grids_by_plan, request_errors


def _policy_identity(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("judgment source policy is not an object")
    projected = {
        "policy_id": value.get("policy_id"),
        "version": value.get("version"),
        "sha256": value.get("sha256"),
    }
    if any(not isinstance(item, str) or not item for item in projected.values()):
        raise ValueError("judgment source policy identity is incomplete")
    return projected  # type: ignore[return-value]


def _match_item(
    items: list[dict[str, Any]], attempt_raw: dict[str, Any], judgment: dict[str, Any]
) -> dict[str, Any]:
    attempt = Attempt.model_validate(attempt_raw, strict=True)
    raw = judgment.get("raw")
    if not isinstance(raw, dict):
        raise ValueError("completed judgment lacks raw provenance")
    planning_fields = (
        "planning_source",
        "planning_exact_modality_combination",
        "planning_expected_behavior",
        "planning_common_metrics_eligible",
        "planning_required_metric",
        "planning_source_policy",
        "planning_stratum_sha256",
    )
    for field in planning_fields:
        if raw.get(field) != attempt.params.get(field):
            raise ValueError(
                f"Attempt/Judgment planning identity mismatch for {field}"
            )
    exact = attempt.params.get("planning_exact_modality_combination")
    if (
        not isinstance(exact, list)
        or not exact
        or any(not isinstance(value, str) for value in exact)
    ):
        raise ValueError("completed judgment lacks planning modality identity")
    token = attempt.params.get("planning_stratum_sha256")
    if not isinstance(token, str) or _HEX64.fullmatch(token) is None:
        raise ValueError(
            "completed Attempt lacks its exact planning-stratum identity "
            "(planning_stratum_sha256); regenerate the cell with the current "
            "Runner instead of loading pre-2.11 artifacts"
        )
    # The legacy fields below are coarser than the planner's grouping key, so
    # they cross-check the matched stratum but never select it: two strata may
    # differ only in declared modalities or execution mode.
    candidates = [
        item for item in items if planning_stratum_sha256(item) == token
    ]
    if len(candidates) != 1:
        raise ValueError(
            "completed judgment cannot be attributed to exactly one planning "
            f"stratum; attempt={judgment.get('attempt_id')!r}, matches={len(candidates)}"
        )
    item = candidates[0]
    if (
        item["source"] != attempt.params.get("planning_source")
        or item["exact_modality_combination"] != exact
        or item["expected_behavior"]
        != attempt.params.get("planning_expected_behavior")
        or item["common_metrics_eligible"]
        is not attempt.params.get("planning_common_metrics_eligible")
        or item["required_metric"]
        != attempt.params.get("planning_required_metric")
        or item["source_policy"]
        != _policy_identity(attempt.params.get("planning_source_policy"))
    ):
        raise ValueError(
            "planning-stratum token matched an item whose visible planning "
            f"identity contradicts the Attempt; attempt={judgment.get('attempt_id')!r}"
        )
    return item


def _decision_state(judgment: dict[str, Any]) -> str:
    """Return authoritative/common or source-native decision state only.

    Supplementary approximate decisions deliberately do not affect this state;
    callers that need proxy coverage use ``_approximate_decision_state``.
    """

    raw = judgment["raw"]
    if raw.get("policy_evaluable_turn") is not True:
        return "non_evaluable"
    if raw.get("common_metrics_eligible") is False:
        source = raw.get("source_evaluation")
        return "decided" if isinstance(source, dict) and source.get("valid") is True else "abstained"
    decided = (
        judgment.get("label") != "not_applicable"
        and raw.get("cascade_confident") is True
        and raw.get("parsed") is not False
    )
    return "decided" if decided else "abstained"


def _approximate_decision_state(
    judgment: dict[str, Any],
    *,
    response: Mapping[str, Any] | None = None,
    supplementary_policy: Mapping[str, Any] | None = None,
) -> str | None:
    """Return supplementary proxy state, without relabeling source evidence."""

    raw = judgment["raw"]
    approximate = raw.get("approximate_security_decision")
    if approximate is None:
        if raw.get("approximate_decision_status") == "abstained":
            if response is None or supplementary_policy is None:
                raise ValueError(
                    "approximate abstention validation requires its Response and "
                    "manifest policy"
                )
            validate_approximate_abstention_judgment(
                judgment,
                response=response,
                supplementary_policy=supplementary_policy,
            )
            return "abstained"
        return None
    if (
        raw.get("policy_evaluable_turn") is not True
        or raw.get("common_metrics_eligible") is not False
    ):
        raise ValueError(
            "approximate security decision must belong to a policy-evaluable, "
            "common-metric-ineligible judgment"
        )
    if response is None or supplementary_policy is None:
        raise ValueError(
            "approximate decision validation requires its Response and manifest policy"
        )
    validate_approximate_judgment(
        judgment,
        response=response,
        supplementary_policy=supplementary_policy,
    )
    decided = (
        judgment.get("label") != "not_applicable"
        and raw.get("cascade_confident") is True
        and raw.get("parsed") is not False
    )
    return "decided" if decided else "abstained"


def _validate_proxy_completion_bindings(cell: Mapping[str, Any]) -> None:
    """Require Level-1 proxy rows to match completion-hashed typed stages."""

    manifest = cell.get("manifest")
    config = manifest.get("config") if isinstance(manifest, Mapping) else None
    validate_approximate_completion_bindings(
        judgments=cell.get("judgments", []),
        responses=cell.get("responses"),
        supplementary_policy=(
            config.get("supplementary_metric_policy")
            if isinstance(config, Mapping)
            else None
        ),
        trails=cell.get("trails", []),
    )


def _item_support(
    items: list[dict[str, Any]],
    cell: dict[str, Any],
    selected_corpus_binding: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    support: dict[str, dict[str, Any]] = {
        item["cell_id"]: {
            "completed_judgment_records": 0,
            "evaluable_judgment_records": 0,
            "decided_judgment_records": 0,
            "abstained_judgment_records": 0,
            "missing_response_judgment_records": 0,
            "non_evaluable_judgment_records": 0,
            "approximate_proxy_evaluable_judgment_records": 0,
            "approximate_proxy_decided_judgment_records": 0,
            "approximate_proxy_abstained_judgment_records": 0,
            "observed_datapoint_ids": set(),
        }
        for item in items
    }
    validated = cell["validated_cell"]
    run_config = validated["manifest"].get("config", {}).get("run")
    if not isinstance(run_config, dict):
        raise ValueError("completed cell lacks run configuration")
    audit = run_config.get("sampling_audit")
    if not isinstance(audit, dict):
        raise ValueError("completed cell lacks sampling audit")
    for field in (
        "converter",
        "full_converted_corpus_sha256",
        "selected_converted_corpus_sha256",
        "selected_records",
        "sample_seed",
        "limit",
    ):
        if audit.get(field) != selected_corpus_binding.get(field):
            raise ValueError(f"completed cell/eligibility sampling {field} mismatch")
    if ("sampling_policy" in audit) != (
        "sampling_policy" in selected_corpus_binding
    ) or audit.get("sampling_policy") != selected_corpus_binding.get(
        "sampling_policy"
    ):
        raise ValueError("completed cell/eligibility sampling policy mismatch")
    if (
        ("sampling_policy" in run_config) != ("sampling_policy" in audit)
        or run_config.get("sampling_policy") != audit.get("sampling_policy")
    ):
        raise ValueError("completed cell run/sampling-audit policy mismatch")
    selected_ids = audit.get("selected_ids")
    if (
        not isinstance(selected_ids, list)
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or canonical_json_sha256(sorted(selected_ids))
        != selected_corpus_binding.get("selected_datapoint_ids_sha256")
    ):
        raise ValueError("completed cell/eligibility selected-ID audit mismatch")
    attempts = validated["attempts"]
    responses = validated.get("responses")
    if not isinstance(responses, dict):
        raise ValueError("completed cell lacks validated Responses")
    supplementary_policy = validated["manifest"].get("config", {}).get(
        "supplementary_metric_policy"
    )
    _validate_proxy_completion_bindings(validated)
    for judgment in validated["judgments"]:
        attempt_id = judgment.get("attempt_id")
        attempt = attempts.get(attempt_id)
        if not isinstance(attempt, dict):
            raise ValueError("completed judgment lacks its validated Attempt")
        item = _match_item(items, attempt, judgment)
        record = support[item["cell_id"]]
        record["completed_judgment_records"] += 1
        record["observed_datapoint_ids"].add(attempt.get("datapoint_id"))
        state = _decision_state(judgment)
        record[f"{state}_judgment_records"] += 1
        if _final_model_nonresponse(judgment):
            record["missing_response_judgment_records"] += 1
        if state != "non_evaluable":
            record["evaluable_judgment_records"] += 1
        approximate_state = _approximate_decision_state(
            judgment,
            response=responses.get(attempt_id),
            supplementary_policy=supplementary_policy,
        )
        if approximate_state is not None:
            record["approximate_proxy_evaluable_judgment_records"] += 1
            record[
                f"approximate_proxy_{approximate_state}_judgment_records"
            ] += 1
    for item in items:
        record = support[item["cell_id"]]
        if item["status"] != "compatible_if_isolated":
            if record["completed_judgment_records"]:
                raise ValueError("structurally blocked planning stratum has completed evidence")
            continue
        if len(record["observed_datapoint_ids"]) != item["selected_datapoint_count"]:
            raise ValueError(
                "completed cell does not cover an exact planning stratum's selected "
                f"datapoints: {item['cell_id']}"
            )
        observed_ids = sorted(record["observed_datapoint_ids"])
        if canonical_json_sha256(observed_ids) != item[
            "selected_datapoint_ids_sha256"
        ]:
            raise ValueError(
                "completed cell covers the wrong planning-stratum datapoint IDs: "
                f"{item['cell_id']}"
            )
        record["observed_datapoint_ids"] = observed_ids
    return support


def _validate_envelope_plan_binding(
    envelope: Mapping[str, Any], descriptor: Mapping[str, Any], plan: Mapping[str, Any]
) -> None:
    if plan["bindings"].get("request_envelope") != dict(descriptor):
        raise ValueError("eligibility plan/request-envelope descriptor mismatch")
    request = envelope["request"]
    planned = plan["request"]
    if request["requested_target_keys"] != planned["requested_target_specs"]:
        raise ValueError("eligibility plan/request-envelope target inventory mismatch")
    if sorted(request["logical_source_arms"]) != planned["logical_source_arms"]:
        raise ValueError("eligibility plan/request-envelope source-arm inventory mismatch")
    if request["selected_attackers"] != planned["selected_attackers"]:
        raise ValueError("eligibility plan/request-envelope attacker inventory mismatch")
    if request["dry_run"] is not planned["dry_run"]:
        raise ValueError("eligibility plan/request-envelope dry-run mismatch")
    bindings = envelope["bindings"]
    if bindings["project_revision"] != plan["bindings"].get("project_revision"):
        raise ValueError("eligibility plan/request-envelope project revision mismatch")
    if bindings["driver_source"] != plan["bindings"].get("driver_source"):
        raise ValueError("eligibility plan/request-envelope driver source mismatch")
    condition = _condition_from_plan(dict(plan))["values"]
    if ("sampling_policy" in request) != ("sampling_policy" in condition):
        raise ValueError(
            "eligibility condition/request-envelope sampling policy presence mismatch"
        )
    projected = {
        field: request[field]
        for field in (
            "execution_purpose", "judges", "judge_model", "seeds", "sample_seed",
            "limit", "max_queries", "max_turns", "defense", "defense_guard",
            "group_keys", "quantization", "dtype", "dry_run", "call_caps",
        )
    }
    if "sampling_policy" in request:
        projected["sampling_policy"] = request["sampling_policy"]
    if any(condition[field] != value for field, value in projected.items()):
        raise ValueError("eligibility condition/request-envelope scalar mismatch")


def _request_error_applies(error: Mapping[str, Any], unit: Mapping[str, Any]) -> bool:
    scope = error["scope"]
    level = scope["level"]
    if level == "whole_request":
        return True
    if level == "requested_target":
        return scope["requested_target_key"] == unit["requested_target_key"]
    if level == "logical_source_arm":
        return scope["logical_source_arm"] == unit["logical_source_arm"]
    return all(
        scope[field] == unit[field]
        for field in ("requested_target_key", "logical_source_arm", "attacker")
    )


def _bind_request_lifecycle(
    request_envelopes: list[dict[str, Any]] | None,
    plans: Mapping[str, tuple[dict[str, Any], str, str, int, int]],
    request_level_errors: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    if request_envelopes is None:
        return [], [], {
            "status": "not_supplied",
            "counts": None,
            "reason": "no ura-request-envelope/2 or /3 artifacts were supplied",
        }
    envelopes: dict[str, dict[str, Any]] = {}
    descriptors: dict[str, dict[str, Any]] = {}
    for artifact in request_envelopes:
        envelope = artifact.get("envelope")
        descriptor = artifact.get("descriptor")
        if not isinstance(envelope, dict) or not isinstance(descriptor, dict):
            raise ValueError("invalid request-envelope input artifact")
        envelope = validate_request_envelope(envelope)
        descriptor = validate_request_envelope_descriptor(descriptor)
        envelope_id = envelope.get("envelope_id")
        if envelope_id != descriptor["envelope_id"] or envelope_id in envelopes:
            raise ValueError("duplicate or mismatched request-envelope input")
        envelopes[envelope_id] = envelope
        descriptors[envelope_id] = descriptor

    plan_by_envelope: dict[str, dict[str, Any]] = {}
    for plan, _digest, _locator, _bytes, _records in plans.values():
        descriptor = validate_request_envelope_descriptor(
            plan["bindings"].get("request_envelope")
        )
        envelope_id = descriptor["envelope_id"]
        envelope = envelopes.get(envelope_id)
        if envelope is None or descriptor != descriptors[envelope_id]:
            raise ValueError("eligibility plan references an unsupplied request envelope")
        if envelope_id in plan_by_envelope:
            raise ValueError("one request envelope is bound to multiple eligibility plans")
        _validate_envelope_plan_binding(envelope, descriptor, plan)
        plan_by_envelope[envelope_id] = plan

    errors_by_envelope: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in request_level_errors:
        error = record.get("request_error")
        if error is None:
            continue
        descriptor = error["request_envelope"]
        envelope_id = descriptor["envelope_id"]
        envelope = envelopes.get(envelope_id)
        if envelope is None or descriptor != descriptors[envelope_id]:
            raise ValueError("request error references an unsupplied request envelope")
        # Revalidate membership against the supplied prospective universe.
        validate_request_error(dict(error), envelope=envelope)
        errors_by_envelope[envelope_id].append(record)
    for envelope_id, errors in errors_by_envelope.items():
        if len(errors) != 1:
            raise ValueError("one request envelope has multiple early-failure artifacts")
        if envelope_id in plan_by_envelope:
            raise ValueError("request envelope has both materialized plan and early error")

    envelope_rows: list[dict[str, Any]] = []
    unit_rows: list[dict[str, Any]] = []
    for envelope_id in sorted(envelopes):
        envelope = envelopes[envelope_id]
        plan = plan_by_envelope.get(envelope_id)
        errors = errors_by_envelope.get(envelope_id, [])
        error_record = errors[0] if errors else None
        envelope_rows.append({
            "envelope_id": envelope_id,
            "artifact": descriptors[envelope_id],
            "execution_purpose": envelope["request"]["execution_purpose"],
            "dry_run": envelope["request"]["dry_run"],
            "requested_execution_units": len(envelope["execution_units"]),
            "plan_id": plan["plan_id"] if plan else None,
            "request_id": plan["request_id"] if plan else None,
            "early_error": (
                {
                    key: error_record[key]
                    for key in ("locator", "sha256", "bytes", "phase")
                }
                if error_record
                else None
            ),
            "materialization_status": (
                "materialized_to_eligibility"
                if plan
                else "blocked_before_materialization"
                if error_record
                else "missing_after_request_envelope"
            ),
        })
        plan_units = {
            (
                unit["requested_target_spec"], unit["logical_source_arm"],
                unit["attacker"],
            ): unit
            for unit in (plan["execution"]["units"] if plan else [])
        }
        for unit in envelope["execution_units"]:
            key = (
                unit["requested_target_key"], unit["logical_source_arm"],
                unit["attacker"],
            )
            planned_unit = plan_units.get(key)
            applies = bool(
                error_record
                and _request_error_applies(error_record["request_error"], unit)
            )
            if plan is not None and planned_unit is None:
                raise ValueError("eligibility plan omits a prospective execution unit")
            unit_rows.append({
                **unit,
                "envelope_id": envelope_id,
                "execution_purpose": envelope["request"]["execution_purpose"],
                "dry_run": envelope["request"]["dry_run"],
                "plan_id": plan["plan_id"] if plan else None,
                "request_id": plan["request_id"] if plan else None,
                "eligibility_execution_unit_id": (
                    planned_unit["execution_unit_id"] if planned_unit else None
                ),
                "materialized": planned_unit is not None,
                "bound_early_error": applies,
                "attempted": False if applies else None,
                "final_disposition": (
                    "materialized_to_eligibility"
                    if planned_unit
                    else "blocked_before_materialization"
                    if applies
                    else "unmaterialized_missing_evidence"
                ),
            })
    unit_rows.sort(key=lambda item: (item["envelope_id"], item["request_unit_id"]))
    counts = {
        "unit": "prospective_whole_arm_request_unit",
        "requested": len(unit_rows),
        "materialized": sum(row["materialized"] for row in unit_rows),
        "blocked_before_materialization": sum(
            row["bound_early_error"] for row in unit_rows
        ),
        "missing": sum(
            row["final_disposition"] == "unmaterialized_missing_evidence"
            for row in unit_rows
        ),
        "attempted": None,
    }
    if counts["requested"] != (
        counts["materialized"] + counts["blocked_before_materialization"]
        + counts["missing"]
    ):
        raise ValueError("prospective request-unit counts do not reconcile")
    return envelope_rows, unit_rows, {
        "status": "validated",
        "counts": counts,
        "limitations": {
            "source_or_modality_strata_fabricated": False,
            "execution_or_provider_call_inferred": False,
            "empirical_validity_established": False,
        },
    }


def build_level1_evidence(
    plan_artifacts: list[tuple[dict[str, Any], str, str, int, int]],
    grids_by_plan: Mapping[str, dict[str, Any]],
    request_level_errors: list[dict[str, Any]],
    live_attestation_availability: Mapping[str, Any] | None = None,
    request_envelopes: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one deterministic, unit-qualified lifecycle inventory."""

    _reject_duplicate_realized_target_arms([
        cell["validated_cell"]
        for grid in grids_by_plan.values()
        for cell in grid.get("cells", {}).values()
        if isinstance(cell, dict) and "validated_cell" in cell
    ])

    if not plan_artifacts and not request_envelopes:
        raise ValueError(
            "Level-1 evidence requires an eligibility plan or request envelope"
        )
    dry_run_modes = {
        artifact[0]["request"]["dry_run"] for artifact in plan_artifacts
    }
    if request_envelopes:
        dry_run_modes.update(
            artifact["envelope"]["request"]["dry_run"]
            for artifact in request_envelopes
        )
    if len(dry_run_modes) != 1:
        raise ValueError(
            "one Level-1 artifact must not mix diagnostic dry-run and measured requests"
        )
    diagnostic_dry_run = next(iter(dry_run_modes))
    evidence_kind = "diagnostic_dry_run" if diagnostic_dry_run else "measured_run"
    expected_purpose = "diagnostic_dry_run" if diagnostic_dry_run else "measured_run"
    observed_purposes = {
        artifact[0]["bindings"]["experiment_conditions"]["values"][
            "execution_purpose"
        ]
        for artifact in plan_artifacts
    }
    if request_envelopes:
        observed_purposes.update(
            artifact["envelope"]["request"]["execution_purpose"]
            for artifact in request_envelopes
        )
    if observed_purposes != {expected_purpose}:
        raise ValueError(
            "Level-1 accepts only diagnostic_dry_run or measured_run request "
            "cohorts; probes, preflights, and canaries are excluded"
        )
    revision_identities = {
        canonical_json_sha256(
            artifact[0]["bindings"]["project_revision"]
        )
        for artifact in plan_artifacts
    }
    if request_envelopes:
        revision_identities.update(
            canonical_json_sha256(
                artifact["envelope"]["bindings"]["project_revision"]
            )
            for artifact in request_envelopes
        )
    if len(revision_identities) != 1:
        raise ValueError("one Level-1 cohort must use one project revision binding")
    live_attestation_status = (
        live_attestation_availability.get("status")
        if live_attestation_availability is not None
        else None
    )
    if live_attestation_status not in {
        None,
        "validated",
        "not_evaluated_no_realized_measured_grid",
    }:
        raise ValueError("Level-1 live-attestation availability status is invalid")
    live_attestation_evaluated = live_attestation_status == "validated"
    supplied_attestation_identities = {
        (
            descriptor.get("attestation_id"),
            descriptor.get("sha256"),
            descriptor.get("bytes"),
        )
        for descriptor in (
            live_attestation_availability.get("artifacts", [])
            if live_attestation_availability is not None
            else []
        )
        if isinstance(descriptor, dict)
    }
    plans: dict[str, tuple[dict[str, Any], str, str, int, int]] = {}
    seen_requests: set[str] = set()
    seen_lifecycle: set[str] = set()
    for artifact in plan_artifacts:
        plan = artifact[0]
        validate_eligibility_plan(plan)
        _condition_from_plan(plan)
        if plan["plan_id"] in plans or plan["request_id"] in seen_requests:
            raise ValueError("duplicate eligibility plan/request identity")
        plans[plan["plan_id"]] = artifact
        seen_requests.add(plan["request_id"])
        for item in plan["items"]:
            lifecycle_id = lifecycle_stratum_id(plan["request_id"], item["cell_id"])
            if lifecycle_id in seen_lifecycle:
                raise ValueError("duplicate Level-1 lifecycle stratum")
            seen_lifecycle.add(lifecycle_id)
    orphan_grids = set(grids_by_plan) - set(plans)
    if orphan_grids:
        raise ValueError(f"grids reference unsupplied plans: {sorted(orphan_grids)!r}")
    request_envelope_rows, prospective_unit_rows, request_availability = (
        _bind_request_lifecycle(request_envelopes, plans, request_level_errors)
    )

    rows: list[dict[str, Any]] = []
    unit_rows: list[dict[str, Any]] = []
    request_rows: list[dict[str, Any]] = []
    for plan_id in sorted(plans):
        plan, digest, locator, byte_count, _records = plans[plan_id]
        condition = _condition_from_plan(plan)
        grid = grids_by_plan.get(plan_id)
        request_rows.append({
            "plan_id": plan_id,
            "request_id": plan["request_id"],
            "condition_id": condition["condition_id"],
            "condition": condition["values"],
            "evidence_kind": evidence_kind,
            "eligibility_artifact": {
                "locator": locator,
                "sha256": digest,
                "bytes": byte_count,
            },
            "bindings": plan["bindings"],
            "grid_id": grid["grid_id"] if grid else None,
            "grid_status": grid["grid_status"] if grid else "not_supplied",
            "grid_artifact": grid["grid_artifact"] if grid else None,
            "live_attestation": (
                _live_attestation_projection(grid["request"].get("live_attestation"))
                if grid
                else condition["values"]["live_attestation"]
            ),
        })
        items_by_unit: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in plan["items"]:
            items_by_unit[item["execution_unit_id"]].append(item)
        units = {unit["execution_unit_id"]: unit for unit in plan["execution"]["units"]}
        for unit_id in sorted(items_by_unit):
            items = items_by_unit[unit_id]
            unit = units[unit_id]
            resolved_targets = {item["resolved_target"] for item in items}
            if len(resolved_targets) != 1:
                raise ValueError(
                    "execution unit does not bind exactly one resolved target"
                )
            resolved_target = next(iter(resolved_targets))
            if grid is not None and (
                not isinstance(resolved_target, str) or not resolved_target
            ):
                raise ValueError(
                    "grid-bound execution unit lacks a resolved target"
                )
            key = (
                resolved_target,
                unit["logical_source_arm"],
                unit["attacker"],
            )
            grid_cell = grid["cells"].get(key) if grid is not None else None
            support = (
                _item_support(
                    items,
                    grid_cell,
                    plan["bindings"]["selected_corpora"][
                        unit["logical_source_arm"]
                    ],
                )
                if grid_cell is not None and grid_cell["status"] in _COMPLETE
                else {}
            )
            item_attestations: dict[str, tuple[str, dict[str, Any] | None]] = {}
            projection = (
                _live_attestation_projection(
                    grid["request"].get("live_attestation")
                )
                if grid is not None
                else condition["values"]["live_attestation"]
            )
            projected_receipts_supplied = bool(
                projection is not None
                and projection["artifacts"]
                and {
                    (
                        descriptor["attestation_id"],
                        descriptor["sha256"],
                        descriptor["bytes"],
                    )
                    for descriptor in projection["artifacts"]
                }.issubset(supplied_attestation_identities)
            )
            for item in items:
                if item["status"] != "compatible_if_isolated":
                    item_attestations[item["cell_id"]] = ("not_required", None)
                elif projection is not None and projection["mode"] == "not_required":
                    item_attestations[item["cell_id"]] = ("not_required", None)
                elif grid is None:
                    item_attestations[item["cell_id"]] = (
                        "not_evaluated"
                        if projected_receipts_supplied
                        else "not_supplied",
                        None,
                    )
                else:
                    if (
                        not live_attestation_evaluated
                        or projection is None
                        or projection["mode"] != "measured"
                    ):
                        raise ValueError(
                            "measured planning stratum lacks an attestation binding"
                        )
                    key = (
                        projection["execution_scope_id"],
                        item["requested_target_spec"],
                        tuple(item["exact_modality_combination"]),
                    )
                    reference = grid.get("live_attestations", {}).get(key)
                    if not isinstance(reference, dict):
                        raise ValueError(
                            "measured planning stratum lacks its exact live attestation"
                        )
                    item_attestations[item["cell_id"]] = (
                        "attested", reference
                    )
            unit_structural = all(
                item["status"] == "N/A" and item["disposition"] in _STRUCTURAL_NA
                for item in items
            )
            unit_eligible = (
                unit["status"] == "whole_arm_compatible"
                and plan["execution"]["request_status"] == "whole_request_compatible"
            )
            unit_attempted = bool(
                grid_cell is not None and grid_cell["execution_started"] is True
            )
            unit_completed = bool(
                grid_cell is not None and grid_cell["status"] in _COMPLETE
            )
            compatible_attestations = [
                item_attestations[item["cell_id"]]
                for item in items
                if item["status"] == "compatible_if_isolated"
            ]
            if not compatible_attestations:
                unit_attestation_status = "not_required"
            else:
                unit_statuses = {
                    status for status, _reference in compatible_attestations
                }
                if len(unit_statuses) != 1:
                    raise ValueError(
                        "execution unit has inconsistent live-attestation statuses"
                    )
                unit_attestation_status = next(iter(unit_statuses))
            unit_attestation_references = sorted(
                {
                    canonical_json_sha256(reference): json.dumps(
                        reference,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    for status, reference in compatible_attestations
                    if status == "attested" and reference is not None
                }.values()
            )
            if unit_structural:
                unit_final = "not_applicable_structural"
            elif grid_cell is None:
                unit_final = "missing_not_attempted" if unit_eligible else "blocked_preflight"
            elif grid_cell["status"] == "error":
                unit_final = (
                    "error_after_execution_start"
                    if grid_cell["execution_started"]
                    else "error_before_execution"
                )
            elif grid and grid["grid_status"] != "complete":
                unit_final = "completed_cell_but_grid_failed"
            else:
                unit_final = "completed"
            unit_rows.append({
                "lifecycle_execution_unit_id": "lifecycle-unit-" + _strict_json_sha256({
                    "request_id": plan["request_id"], "execution_unit_id": unit_id,
                })[:24],
                "request_id": plan["request_id"],
                "plan_id": plan_id,
                "condition_id": condition["condition_id"],
                **unit,
                "resolved_target": resolved_target,
                "evidence_kind": evidence_kind,
                "scientifically_compatible_strata": sum(
                    item["status"] == "compatible_if_isolated" for item in items
                ),
                "structural_not_applicable_strata": sum(
                    item["status"] == "N/A"
                    and item["disposition"] in _STRUCTURAL_NA
                    for item in items
                ),
                "execution_eligible": unit_eligible,
                "attestation_status": unit_attestation_status,
                "attestation_references": [
                    json.loads(value) for value in unit_attestation_references
                ],
                "grid_id": grid["grid_id"] if grid else None,
                "grid_artifact": grid["grid_artifact"] if grid else None,
                "run_id": grid_cell.get("run_id") if grid_cell else None,
                "execution_evidence_artifact": (
                    grid_cell.get("evidence_artifact") if grid_cell else None
                ),
                "execution_started": unit_attempted,
                "attempted": unit_attempted,
                "completed": unit_completed,
                "missing": unit_eligible and grid_cell is None,
                "final_disposition": unit_final,
            })

            for item in items:
                structural = (
                    item["status"] == "N/A"
                    and item["disposition"] in _STRUCTURAL_NA
                )
                scientific = item["status"] == "compatible_if_isolated"
                execution_eligible = scientific and unit_eligible
                completed = bool(
                    grid_cell is not None
                    and grid_cell["status"] in _COMPLETE
                    and support.get(item["cell_id"], {}).get(
                        "completed_judgment_records", 0
                    ) > 0
                )
                execution_unit_started = bool(
                    grid_cell and grid_cell["execution_started"]
                )
                if structural:
                    final = "not_applicable_structural"
                elif item["status"] == "N/A":
                    final = "blocked_preflight_or_invalid_declaration"
                elif unit["status"] != "whole_arm_compatible":
                    final = "compatible_stratum_blocked_by_sibling"
                elif grid_cell is None:
                    final = (
                        "missing_not_attempted"
                        if execution_eligible
                        else "blocked_request_preflight"
                    )
                elif grid_cell["status"] == "error":
                    final = (
                        "execution_unit_error_after_start_stratum_attempt_unknown"
                        if execution_unit_started
                        else "execution_unit_error_before_start"
                    )
                elif grid and grid["grid_status"] != "complete":
                    final = "completed_stratum_but_grid_failed"
                elif completed:
                    final = "completed"
                else:  # pragma: no cover - exact coverage validation rejects this
                    final = "missing_completed_stratum_evidence"
                item_counts = support.get(item["cell_id"], {})
                attestation_status, attestation_reference = item_attestations[
                    item["cell_id"]
                ]
                rows.append({
                    "lifecycle_stratum_id": lifecycle_stratum_id(
                        plan["request_id"], item["cell_id"]
                    ),
                    "request_id": plan["request_id"],
                    "plan_id": plan_id,
                    "condition_id": condition["condition_id"],
                    "requested_target_spec": item["requested_target_spec"],
                    "resolved_target": item["resolved_target"],
                    "logical_source_arm": item["logical_source_arm"],
                    "source": item["source"],
                    "exact_modality_combination": item[
                        "exact_modality_combination"
                    ],
                    "execution_mode": item["execution_mode"],
                    "metric_mode": item["metric_mode"],
                    "semantic_family": item["semantic_family"],
                    "expected_behavior": item["expected_behavior"],
                    "source_policy": item["source_policy"],
                    "attacker": item["attacker"],
                    "defense": condition["values"]["defense"],
                    "evidence_kind": evidence_kind,
                    "planning_status": item["status"],
                    "planning_disposition": item["disposition"],
                    "scientifically_compatible": scientific,
                    "execution_eligible": execution_eligible,
                    "structural_not_applicable": structural,
                    "failed_gates": item["failed_gates"],
                    "selected_datapoint_count": item["selected_datapoint_count"],
                    "selected_datapoint_ids_sha256": item[
                        "selected_datapoint_ids_sha256"
                    ],
                    "attestation_status": attestation_status,
                    "attestation_reference": attestation_reference,
                    "grid_id": grid["grid_id"] if grid else None,
                    "grid_locator": (
                        grid["grid_artifact"]["locator"] if grid else None
                    ),
                    "run_id": grid_cell.get("run_id") if grid_cell else None,
                    "execution_evidence_artifact": (
                        grid_cell.get("evidence_artifact") if grid_cell else None
                    ),
                    "execution_evidence_locator": (
                        grid_cell.get("evidence_artifact", {}).get("locator")
                        if grid_cell
                        else None
                    ),
                    # A whole Runner cell can start and fail before every source
                    # stratum is reached.  Do not project that unit milestone into
                    # a false stratum-level attempted claim.
                    "execution_unit_started": execution_unit_started,
                    "completed": completed,
                    "completed_judgment_records": item_counts.get(
                        "completed_judgment_records", 0
                    ),
                    "evaluable_judgment_records": item_counts.get(
                        "evaluable_judgment_records", 0
                    ),
                    "decided_judgment_records": item_counts.get(
                        "decided_judgment_records", 0
                    ),
                    "abstained_judgment_records": item_counts.get(
                        "abstained_judgment_records", 0
                    ),
                    "missing_response_judgment_records": item_counts.get(
                        "missing_response_judgment_records", 0
                    ),
                    "non_evaluable_judgment_records": item_counts.get(
                        "non_evaluable_judgment_records", 0
                    ),
                    "approximate_proxy_evaluable_judgment_records": item_counts.get(
                        "approximate_proxy_evaluable_judgment_records", 0
                    ),
                    "approximate_proxy_decided_judgment_records": item_counts.get(
                        "approximate_proxy_decided_judgment_records", 0
                    ),
                    "approximate_proxy_abstained_judgment_records": item_counts.get(
                        "approximate_proxy_abstained_judgment_records", 0
                    ),
                    "analysis_inclusion_status": "not_supplied",
                    "included_records": None,
                    "missing": execution_eligible and grid_cell is None,
                    "final_disposition": final,
                })

    rows.sort(key=lambda item: item["lifecycle_stratum_id"])
    unit_rows.sort(key=lambda item: item["lifecycle_execution_unit_id"])
    request_rows.sort(key=lambda item: item["request_id"])
    planning_counts = {
        "unit": "planning_stratum",
        "requested": len(rows),
        "scientifically_compatible": sum(
            row["scientifically_compatible"] for row in rows
        ),
        "execution_eligible": sum(row["execution_eligible"] for row in rows),
        "structural_not_applicable": sum(
            row["structural_not_applicable"] for row in rows
        ),
        "blocked_or_unresolved": sum(
            not row["execution_eligible"] and not row["structural_not_applicable"]
            for row in rows
        ),
        "completed": sum(row["completed"] for row in rows),
        "with_decided_support": sum(
            row["decided_judgment_records"] > 0 for row in rows
        ),
        "with_abstained_support": sum(
            row["abstained_judgment_records"] > 0 for row in rows
        ),
        "with_missing_response_support": sum(
            row["missing_response_judgment_records"] > 0 for row in rows
        ),
        "missing": sum(row["missing"] for row in rows),
        "associated_execution_unit_error": sum(
            row["final_disposition"].startswith("execution_unit_error_")
            for row in rows
        ),
        "attempted": None,
        "attested": (
            sum(row["attestation_status"] == "attested" for row in rows)
            if live_attestation_evaluated
            else None
        ),
        "included": None,
    }
    execution_counts = {
        "unit": "whole_arm_execution_unit",
        "requested": len(unit_rows),
        "execution_eligible": sum(row["execution_eligible"] for row in unit_rows),
        "attempted": sum(row["attempted"] for row in unit_rows),
        "completed": sum(row["completed"] for row in unit_rows),
        "missing": sum(row["missing"] for row in unit_rows),
        "error": sum(
            row["final_disposition"].startswith("error_") for row in unit_rows
        ),
        "structural_not_applicable": sum(
            row["final_disposition"] == "not_applicable_structural"
            for row in unit_rows
        ),
        "attested": (
            sum(
                row["attestation_status"] == "attested"
                for row in unit_rows
            )
            if live_attestation_evaluated
            else None
        ),
    }
    judgment_counts = {
        "unit": "judgment_record",
        "completed": sum(row["completed_judgment_records"] for row in rows),
        "evaluable": sum(row["evaluable_judgment_records"] for row in rows),
        "decided": sum(row["decided_judgment_records"] for row in rows),
        "abstained": sum(row["abstained_judgment_records"] for row in rows),
        "missing_responses": sum(
            row["missing_response_judgment_records"] for row in rows
        ),
        "non_evaluable": sum(
            row["non_evaluable_judgment_records"] for row in rows
        ),
        "included": None,
    }
    if judgment_counts["completed"] != (
        judgment_counts["decided"]
        + judgment_counts["abstained"]
        + judgment_counts["non_evaluable"]
    ):
        raise ValueError("Level-1 judgment decision counts do not reconcile")
    if judgment_counts["missing_responses"] > judgment_counts["abstained"]:
        raise ValueError("Level-1 missing-response counts do not reconcile")
    approximate_proxy_counts = {
        "unit": "supplementary_approximate_judgment_record",
        "evaluable": sum(
            row["approximate_proxy_evaluable_judgment_records"] for row in rows
        ),
        "decided": sum(
            row["approximate_proxy_decided_judgment_records"] for row in rows
        ),
        "abstained": sum(
            row["approximate_proxy_abstained_judgment_records"] for row in rows
        ),
        "included": None,
    }
    if approximate_proxy_counts["evaluable"] != (
        approximate_proxy_counts["decided"]
        + approximate_proxy_counts["abstained"]
    ):
        raise ValueError("Level-1 approximate proxy decision counts do not reconcile")
    body: dict[str, Any] = {
        "schema_version": LEVEL1_SCHEMA,
        "status": "validated_unit_qualified_lifecycle_inventory",
        "scope": {
            "fixed_universe": (
                "prospective whole-arm request units from supplied "
                "ura-request-envelope/2 or /3 artifacts, plus exact materialized "
                "planning "
                "strata from supplied ura-eligibility-plan/3 artifacts "
                "(or exact runtime-free legacy /2 artifacts)"
            ),
            "pre_materialization_failures": (
                "bound to prospective request units only; exact source/modality "
                "strata are CANNOT-VERIFY and are not fabricated"
            ),
            "universal_safety_score_defined": False,
            "evidence_kind": evidence_kind,
            "contains_diagnostic_dry_run": diagnostic_dry_run,
            "empirical_validity_established": False,
        },
        "availability": {
            "prospective_request": request_availability,
            "live_attestation": {
                **(
                    {
                        "status": "not_supplied",
                        "counts": None,
                        "reason": (
                            "no typed live-attestation artifacts were supplied"
                        ),
                    }
                    if live_attestation_availability is None
                    else {
                        **dict(live_attestation_availability),
                        "counts": (
                            {
                                "unit": "typed_transport_prerequisite",
                                "planning_strata_attested": planning_counts[
                                    "attested"
                                ],
                                "execution_units_attested": execution_counts[
                                    "attested"
                                ],
                                "artifacts": live_attestation_availability[
                                    "artifact_count"
                                ],
                                "matched_records": live_attestation_availability[
                                    "matched_record_count"
                                ],
                            }
                            if live_attestation_evaluated
                            else None
                        ),
                        **(
                            {}
                            if live_attestation_evaluated
                            else {
                                "reason": (
                                    "receipts were supplied, but no realized measured "
                                    "grid provides a historical started_at binding"
                                )
                            }
                        ),
                        "limitations": {
                            "safety_validity_established": False,
                            "evaluator_validity_established": False,
                            "benchmark_result_established": False,
                            "human_validity_established": False,
                            "future_route_availability_guaranteed": False,
                        },
                    }
                )
            },
            "analysis_inclusion": {
                "status": "not_supplied",
                "counts": None,
                "reason": "no analysis-inclusion evidence is defined in this wave",
            },
            "planning_stratum_attempts": {
                "status": "not_derivable_from_error_units",
                "counts": None,
                "reason": (
                    "whole execution-unit start does not identify which source "
                    "strata were attempted before an error"
                ),
            },
        },
        "counts": {
            "prospective_request_units": request_availability.get("counts"),
            "planning_strata": planning_counts,
            "execution_units": execution_counts,
            "judgment_records": judgment_counts,
            "approximate_proxy_judgment_records": approximate_proxy_counts,
            "request_level_errors": {
                "unit": "request_error_artifact",
                "observed": len(request_level_errors),
                "bound_pre_materialization": sum(
                    record.get("scope") == "bound_pre_materialization_request_error"
                    for record in request_level_errors
                ),
                "unstratified": sum(
                    record.get("scope")
                    != "bound_pre_materialization_request_error"
                    for record in request_level_errors
                ),
            },
        },
        "requests": request_rows,
        "request_envelopes": request_envelope_rows,
        "prospective_request_units": prospective_unit_rows,
        "planning_strata": rows,
        "execution_units": unit_rows,
        "request_level_errors": request_level_errors,
    }
    body["evidence_id"] = "level1-" + _strict_json_sha256(body)[:24]
    return body


def _csv_value(value: object) -> object:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        handle = path.open("x", encoding="utf-8", newline="")
        created = True
        with handle:
            writer = csv.DictWriter(
                handle, fieldnames=_CSV_FIELDS, extrasaction="ignore"
            )
            writer.writeheader()
            for row in rows:
                writer.writerow({
                    field: _csv_value(row.get(field)) for field in _CSV_FIELDS
                })
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise


def _discover_request_envelopes(
    plan_paths: list[Path],
    plan_artifacts: list[tuple[dict[str, Any], str, str, int, int]],
    result_roots: list[Path],
) -> list[dict[str, Any]]:
    """Find auto-generated envelopes beside supplied plans/results."""

    candidates: set[Path] = set()
    for plan_path, artifact in zip(plan_paths, plan_artifacts):
        descriptor = validate_request_envelope_descriptor(
            artifact[0]["bindings"].get("request_envelope")
        )
        candidates.add(plan_path.resolve(strict=True).parent / descriptor["file"])
    for root in result_roots:
        resolved = root.resolve(strict=True)
        candidates.update(resolved.rglob("request-envelope-*.request-envelope.json"))
    artifacts = [_request_envelope_artifact(path) for path in sorted(candidates)]
    if len({item["descriptor"]["envelope_id"] for item in artifacts}) != len(
        artifacts
    ):
        raise ValueError("duplicate request-envelope identity in Level-1 inputs")
    return artifacts


def _write_json_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        handle = path.open("x", encoding="utf-8", newline="\n")
        created = True
        with handle:
            json.dump(
                value,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                indent=2,
                allow_nan=False,
            )
            handle.write("\n")
    except Exception:
        if created:
            path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Join planning eligibility, grid lifecycle, and decision support "
            "without pooling their units"
        )
    )
    parser.add_argument(
        "--eligibility",
        type=Path,
        action="append",
        default=[],
        help=(
            "validated ura-eligibility-plan/3 JSON (or exact runtime-free legacy "
            "/2); repeat per request condition"
        ),
    )
    parser.add_argument(
        "--results",
        type=Path,
        action="append",
        default=[],
        help="run_matrix results root containing final complete/partial grids",
    )
    parser.add_argument(
        "--live-attestation",
        type=Path,
        action="append",
        default=[],
        help=(
            "typed ura-live-attestation/2 JSON; repeat and pair positionally "
            "with --live-attestation-sha256"
        ),
    )
    parser.add_argument(
        "--live-attestation-sha256",
        action="append",
        default=[],
        help="approved byte SHA-256 paired with one --live-attestation input",
    )
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-csv", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out_json.resolve() == args.out_csv.resolve():
        parser.error("Level-1 JSON and CSV outputs must be different paths")
    if args.out_json.exists() or args.out_csv.exists():
        parser.error("Level-1 outputs are create-only and must not already exist")
    if len(args.live_attestation) != len(args.live_attestation_sha256):
        parser.error(
            "--live-attestation and --live-attestation-sha256 must be paired"
        )
    try:
        artifacts = [_plan_artifact(path) for path in args.eligibility]
        envelope_artifacts = _discover_request_envelopes(
            args.eligibility, artifacts, args.results
        )
        plan_index = {artifact[0]["plan_id"]: artifact for artifact in artifacts}
        if len(plan_index) != len(artifacts):
            raise ValueError("duplicate eligibility plan input")
        grids, request_errors = _load_results(args.results, plan_index)
        live_artifacts = [
            _load_live_attestation_artifact(path, digest)
            for path, digest in zip(
                args.live_attestation, args.live_attestation_sha256
            )
        ]
        live_availability = _bind_live_attestations(
            grids, plan_index, live_artifacts
        )
        report = build_level1_evidence(
            artifacts,
            grids,
            request_errors,
            live_availability,
            envelope_artifacts,
        )
        created_outputs: list[Path] = []
        try:
            _write_json_new(args.out_json, report)
            created_outputs.append(args.out_json)
            write_csv(args.out_csv, report["planning_strata"])
            created_outputs.append(args.out_csv)
        except Exception:
            for path in created_outputs:
                path.unlink(missing_ok=True)
            raise
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"Level-1 evidence failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "written",
        "evidence_id": report["evidence_id"],
        "json": str(args.out_json.resolve()),
        "csv": str(args.out_csv.resolve()),
        "prospective_request_units": report["counts"][
            "prospective_request_units"
        ]["requested"],
        "planning_strata": report["counts"]["planning_strata"]["requested"],
        "execution_units": report["counts"]["execution_units"]["requested"],
        "attestation_status": report["availability"]["live_attestation"]["status"],
        "analysis_inclusion_status": report["availability"]["analysis_inclusion"][
            "status"
        ],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
