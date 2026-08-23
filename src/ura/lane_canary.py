"""Content-addressed summaries of one strictly validated diagnostic canary.

The summary is operational evidence only.  It records what one bounded run
actually exercised; it never authorizes a larger campaign and never turns a
synthetic or live diagnostic into empirical benchmark evidence.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any, Mapping

from .eligibility import canonical_json_sha256
from .project_revision import validate_project_revision_binding


LANE_CANARY_SCHEMA = "ura-lane-canary/1"
_CANARY_ID = re.compile(r"lane-canary-[0-9a-f]{24}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TOP_FIELDS = frozenset({
    "schema", "status", "purpose", "canary_id", "evidence_class",
    "bindings", "condition", "workload", "artifact_storage",
    "latency_observations", "call_accounting", "decision_support",
    "role_reachability", "limitations",
})
_LIMITATIONS = {
    "campaign_authorized": False,
    "empirical_benchmark_evidence": False,
    "human_validity_established": False,
    "throughput_extrapolation_permitted": False,
    "storage_extrapolation_permitted": False,
    "model_ranking_permitted": False,
    "future_provider_latency": "CANNOT-VERIFY",
    "token_usage_completeness": "CANNOT-VERIFY",
    "monetary_price_or_cost": "CANNOT-VERIFY",
    "interpretation": (
        "one-cluster diagnostic reachability and observed resource evidence only"
    ),
}
_BINDING_FIELDS = frozenset({
    "grid_id", "grid_artifact", "run_id", "completion_artifact",
    "eligibility_plan_id", "eligibility_request_id", "eligibility_condition_id",
    "eligibility_artifact", "lane_projection_id", "lane_projection_artifact",
})
_DESCRIPTOR_FIELDS = frozenset({"file", "sha256", "bytes", "records"})
_CONDITION_FIELDS = frozenset({
    "execution_purpose", "dry_run", "requested_model_spec", "resolved_target",
    "logical_source_arm", "attacker", "defense", "judges", "seeds",
    "realized_identities", "source_identity",
})
_WORKLOAD_FIELDS = frozenset({
    "selected_clusters", "selected_cluster_ids", "selected_cluster_ids_sha256",
    "selected_rows", "selected_row_ids", "selected_row_ids_sha256",
    "completed_attempts", "completed_responses", "completed_judgments",
    "completed_trail_records",
})
_STORAGE_FIELDS = frozenset({
    "core_by_role", "core_artifact_bytes", "supporting_artifact_bytes",
    "network_payload_bytes",
})
_LATENCY_FIELDS = frozenset({
    "grid_observation_window", "target", "model_judge", "end_to_end_throughput",
})
_LATENCY_SUMMARY_FIELDS = frozenset({
    "observations", "observed_records", "missing_record_ids", "sum_ms",
    "minimum_ms", "maximum_ms",
})
_WINDOW_FIELDS = frozenset({
    "started_at", "finished_at", "self_reported_wall_clock_seconds", "basis",
    "precision", "runtime_or_throughput_established", "throughput_derived",
})
_CALL_FIELDS = frozenset({
    "semantics", "reserved", "observed_transport_attempts",
    "reserved_minus_reported_transport_attempts",
})
_RESERVED_FIELDS = frozenset({
    "target_logical_calls", "judge_model_calls", "http_attempt_exposure",
})
_OBSERVED_TRANSPORT_FIELDS = frozenset({
    "target_reported_total", "judge_reported_total", "reported_total",
    "target_unreported_record_ids", "judge_unreported_record_ids",
    "reporting_complete",
})
_DECISION_FIELDS = frozenset({
    "completed", "evaluable", "decided", "abstained", "non_evaluable",
    "decision_coverage",
})
_ROLE_FIELDS = frozenset({
    "semantics", "execution_roles", "stages", "all_configured_stages_represented",
})
_SOURCE_IDENTITY_FIELDS = frozenset({
    "dataset_hashes", "harness_source", "driver_source",
    "source_conformance_artifact", "project_revision",
})
_ATTACKER_ROLE_FIELDS = frozenset({"identity", "status", "observed_records"})
_TARGET_ROLE_FIELDS = frozenset({
    "identity", "status", "observed_records", "input_defense_block_records",
})
_DEFENSE_ROLE_FIELDS = frozenset({
    "identity", "status", "configured_stages", "observed_stage_records",
    "passed_records", "blocked_records",
})
_SOURCE_EVALUATOR_ROLE_FIELDS = frozenset({
    "status", "required_records", "observed_records", "valid_records",
})


def _strict_object(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} has an invalid field inventory")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _nonblank(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{label} must be a non-blank, unpadded string")
    return value


def _descriptor(value: object, label: str) -> dict[str, Any]:
    item = _strict_object(value, _DESCRIPTOR_FIELDS, label)
    filename = _nonblank(item.get("file"), f"{label}.file")
    if Path(filename).name != filename:
        raise ValueError(f"{label}.file must be a basename")
    digest = item.get("sha256")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError(f"{label}.sha256 must be lowercase SHA-256")
    _integer(item.get("bytes"), f"{label}.bytes", minimum=1)
    _integer(item.get("records"), f"{label}.records", minimum=1)
    return item


def _sorted_unique_strings(value: object, label: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    output = [_nonblank(item, f"{label} item") for item in value]
    if output != sorted(set(output)) or (nonempty and not output):
        raise ValueError(f"{label} must be sorted, unique, and appropriately non-empty")
    return output


def _finite_latency(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise ValueError(f"{label} must be finite and non-negative")
    return float(value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_descriptor(path: Path, *, records: int = 1) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"expected regular non-symlink artifact: {path}")
    return {
        "file": path.name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
        "records": records,
    }


def _decision_state(judgment: Mapping[str, Any]) -> str:
    raw = judgment.get("raw")
    if not isinstance(raw, dict):
        raise ValueError("judgment lacks raw decision provenance")
    if raw.get("policy_evaluable_turn") is not True:
        return "non_evaluable"
    if raw.get("common_metrics_eligible") is False:
        source = raw.get("source_evaluation")
        return (
            "decided"
            if isinstance(source, dict) and source.get("valid") is True
            else "abstained"
        )
    return (
        "decided"
        if judgment.get("label") != "not_applicable"
        and raw.get("cascade_confident") is True
        and raw.get("parsed") is not False
        else "abstained"
    )


def _source_evaluator_role(
    judgments: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Report substantive source-evaluator execution, not diagnostics.

    Runner deliberately persists an ``implemented: false`` source-evaluation
    object when a corpus declares a source metric whose evaluator is absent.
    That diagnostic proves why the native metric was not emitted; it does not
    mean that the missing evaluator ran.
    """

    required_rows = [
        row
        for row in judgments
        if isinstance(row.get("raw"), dict)
        and row["raw"].get("common_metrics_eligible") is False
        and row["raw"].get("policy_evaluable_turn") is True
    ]
    required = len(required_rows)
    observed = sum(
        isinstance(row["raw"].get("source_evaluation"), dict)
        and row["raw"]["source_evaluation"].get("implemented") is True
        for row in required_rows
    )
    valid = sum(
        isinstance(row["raw"].get("source_evaluation"), dict)
        and row["raw"]["source_evaluation"].get("implemented") is True
        and row["raw"]["source_evaluation"].get("valid") is True
        for row in required_rows
    )
    return {
        "status": (
            "not_applicable"
            if required == 0
            else "exercised" if observed else "not_exercised"
        ),
        "required_records": required,
        "observed_records": observed,
        "valid_records": valid,
    }


def _latency_summary(observations: list[dict[str, Any]], missing: list[str]) -> dict[str, Any]:
    values = [_finite_latency(row["latency_ms"], "latency observation") for row in observations]
    return {
        "observations": observations,
        "observed_records": len(values),
        "missing_record_ids": sorted(missing),
        "sum_ms": sum(values) if values else None,
        "minimum_ms": min(values) if values else None,
        "maximum_ms": max(values) if values else None,
    }


def _transport_count(raw: object, label: str) -> tuple[int | None, bool]:
    if not isinstance(raw, dict) or "transport_attempt_count" not in raw:
        return None, False
    return _integer(raw["transport_attempt_count"], label), True


def _stage_was_queried(row: Mapping[str, Any], judge: str) -> bool:
    """Distinguish Guard invocation from an actual model inference."""

    if row.get("stage_queried") is False:
        return False
    if judge == "guardrail":
        return row.get("guardrail_queried") is True
    return True


def _validate_latency_summary(
    value: object, label: str, *, model_judge: bool,
) -> dict[str, Any]:
    summary = _strict_object(value, _LATENCY_SUMMARY_FIELDS, label)
    observations = summary.get("observations")
    if not isinstance(observations, list):
        raise ValueError(f"{label}.observations must be a list")
    values: list[float] = []
    record_ids: list[str] = []
    for index, observation in enumerate(observations):
        expected_fields = (
            {"attempt_id", "stage", "judge", "latency_ms"}
            if model_judge else {"attempt_id", "latency_ms"}
        )
        if not isinstance(observation, dict) or set(observation) != expected_fields:
            raise ValueError(f"{label} observation {index} is invalid")
        attempt_id = _nonblank(
            observation.get("attempt_id"), f"{label} observation attempt_id"
        )
        values.append(_finite_latency(
            observation.get("latency_ms"), f"{label} observation latency_ms"
        ))
        record_ids.append(attempt_id if not model_judge else (
            f"{attempt_id}:{_integer(observation.get('stage'), f'{label} stage')}:"
            f"{_nonblank(observation.get('judge'), f'{label} judge')}"
        ))
    if len(record_ids) != len(set(record_ids)):
        raise ValueError(f"{label} contains duplicate observation identities")
    missing = _sorted_unique_strings(
        summary.get("missing_record_ids"), f"{label}.missing_record_ids"
    )
    if set(record_ids) & set(missing):
        raise ValueError(f"{label} records cannot be both observed and missing")
    if _integer(summary.get("observed_records"), f"{label}.observed_records") != len(values):
        raise ValueError(f"{label} observed-record count does not reconcile")
    expected = {
        "sum_ms": sum(values) if values else None,
        "minimum_ms": min(values) if values else None,
        "maximum_ms": max(values) if values else None,
    }
    for field, expected_value in expected.items():
        if summary.get(field) != expected_value:
            raise ValueError(f"{label}.{field} does not reconcile")
    return summary


def _observation_window(grid: Mapping[str, Any]) -> dict[str, Any]:
    started = grid.get("started_at")
    finished = grid.get("finished_at")
    if not isinstance(started, str) or not isinstance(finished, str):
        raise ValueError("completed canary grid lacks start/finish timestamps")
    try:
        start_time = datetime.fromisoformat(started)
        finish_time = datetime.fromisoformat(finished)
    except ValueError as exc:
        raise ValueError("canary grid has invalid ISO timestamps") from exc
    if start_time.tzinfo is None or finish_time.tzinfo is None:
        raise ValueError("canary grid timestamps must be timezone-aware")
    if start_time.utcoffset() != timezone.utc.utcoffset(start_time) or (
        finish_time.utcoffset() != timezone.utc.utcoffset(finish_time)
    ):
        raise ValueError("canary grid timestamps must be UTC")
    seconds = (finish_time - start_time).total_seconds()
    if seconds < 0:
        raise ValueError("canary grid finish precedes its start")
    return {
        "started_at": started,
        "finished_at": finished,
        "self_reported_wall_clock_seconds": seconds,
        "basis": (
            "driver_self_reported_grid_timestamps_bound_by_this_summary_but_"
            "not_monotonic_or_completion_marker_hashed"
        ),
        "precision": "whole_seconds_including_preflight_and_artifact_finalization",
        "runtime_or_throughput_established": False,
        "throughput_derived": False,
    }


def build_lane_canary_summary(
    *,
    cell: Mapping[str, Any],
    grid: Mapping[str, Any],
    grid_descriptor: Mapping[str, Any],
    eligibility_plan: Mapping[str, Any],
    eligibility_descriptor: Mapping[str, Any],
    lane_projection: Mapping[str, Any],
    lane_projection_descriptor: Mapping[str, Any],
    completion_descriptor: Mapping[str, Any],
    completion_marker: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a deterministic summary from inputs already validated by strict loaders."""

    request = grid.get("request")
    manifest = cell.get("manifest")
    if not isinstance(request, dict) or not isinstance(manifest, dict):
        raise ValueError("canary grid/cell structure is incomplete")
    run = (manifest.get("config") or {}).get("run")
    if (
        request.get("execution_purpose") != "diagnostic_canary"
        or not isinstance(run, dict)
        or run.get("execution_purpose") != "diagnostic_canary"
    ):
        raise ValueError("lane canary summary requires typed diagnostic_canary evidence")
    dry_run = request.get("dry_run")
    if not isinstance(dry_run, bool) or run.get("dry_run") is not dry_run:
        raise ValueError("grid/manifest diagnostic dry-run state mismatch")
    evidence_class = "synthetic_offline" if dry_run else "live_diagnostic"

    audit = run.get("sampling_audit")
    if not isinstance(audit, dict) or audit.get("selected_clusters") != 1:
        raise ValueError("lane canary must retain exactly one selected source cluster")
    selected_ids = audit.get("selected_ids")
    cluster_ids = audit.get("selected_cluster_ids")
    if (
        not isinstance(selected_ids, list)
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or len(set(selected_ids)) != len(selected_ids)
        or not isinstance(cluster_ids, list)
        or len(cluster_ids) != 1
        or not isinstance(cluster_ids[0], str)
        or not cluster_ids[0]
        or audit.get("selected_records") != len(selected_ids)
    ):
        raise ValueError("lane canary sampling identities/counts are invalid")

    attempts = cell.get("attempts")
    responses = cell.get("responses")
    judgments = cell.get("judgments")
    trails = cell.get("trails")
    if not all(isinstance(item, (dict, list)) for item in (attempts, responses, judgments, trails)):
        raise ValueError("validated canary cell lacks core records")
    if not isinstance(attempts, dict) or not isinstance(responses, dict):
        raise ValueError("validated canary cell indexes are invalid")
    if not isinstance(judgments, list) or not isinstance(trails, list):
        raise ValueError("validated canary decision records are invalid")

    marker_artifacts = completion_marker.get("artifacts")
    if not isinstance(marker_artifacts, dict):
        raise ValueError("completion marker lacks artifact descriptors")
    core_by_role = {key: dict(marker_artifacts[key]) for key in sorted(marker_artifacts)}
    core_bytes = sum(_integer(item.get("bytes"), f"artifact {role} bytes")
                     for role, item in core_by_role.items())

    target_latency: list[dict[str, Any]] = []
    target_latency_missing: list[str] = []
    target_reported_attempts = 0
    target_unreported: list[str] = []
    for attempt_id, response in sorted(responses.items()):
        latency = response.get("latency_ms")
        if latency is None:
            target_latency_missing.append(attempt_id)
        else:
            target_latency.append({"attempt_id": attempt_id, "latency_ms": latency})
        count, reported = _transport_count(
            response.get("raw"), f"target transport count for {attempt_id}"
        )
        if reported:
            target_reported_attempts += int(count or 0)
        else:
            target_unreported.append(attempt_id)

    judge_latency: list[dict[str, Any]] = []
    judge_latency_missing: list[str] = []
    judge_reported_attempts = 0
    judge_unreported: list[str] = []
    stage_counts: dict[tuple[int, str, str], Counter[str]] = {}
    for row in trails:
        attempt_id = str(row.get("attempt_id"))
        stage = _integer(row.get("stage"), f"trail stage for {attempt_id}")
        judge = row.get("judge")
        role = row.get("cascade_role")
        if not isinstance(judge, str) or role not in {"authoritative", "shadow"}:
            raise ValueError("trail stage lacks judge/role identity")
        queried = _stage_was_queried(row, judge)
        counts = stage_counts.setdefault((stage, judge, role), Counter())
        counts["records"] += 1
        counts["queried" if queried else "not_queried"] += 1
        call = row.get("judge_call")
        record_id = f"{attempt_id}:{stage}:{judge}"
        if not queried or not isinstance(call, dict):
            # Local rules/guardrails have no provider-call latency or transport.
            continue
        latency = call.get("latency_ms")
        if latency is None:
            judge_latency_missing.append(record_id)
        else:
            judge_latency.append({
                "attempt_id": attempt_id,
                "stage": stage,
                "judge": judge,
                "latency_ms": latency,
            })
        count, reported = _transport_count(call, f"judge transport count for {record_id}")
        if reported:
            judge_reported_attempts += int(count or 0)
        else:
            judge_unreported.append(record_id)

    decision_counts = Counter(_decision_state(row) for row in judgments)
    evaluable = decision_counts["decided"] + decision_counts["abstained"]
    role_rows = [
        {
            "stage": stage,
            "judge": judge,
            "role": role,
            "trail_records": counts["records"],
            "queried_records": counts["queried"],
            "not_queried_records": counts["not_queried"],
            "reached": counts["queried"] > 0,
        }
        for (stage, judge, role), counts in sorted(stage_counts.items())
    ]
    defense_name = run.get("defense")
    configured_defense_stages = (
        [] if defense_name == "none"
        else ["input", "output"] if defense_name == "both"
        else [defense_name]
    )
    observed_defense_stages: Counter[str] = Counter()
    blocked_defense_records = 0
    passed_defense_records = 0
    for response in responses.values():
        raw = response.get("raw")
        if not isinstance(raw, dict):
            continue
        stages = raw.get("defense_stages_evaluated")
        if not isinstance(stages, list):
            continue
        for stage in stages:
            if stage in {"input", "output"}:
                observed_defense_stages[stage] += 1
        blocked_defense_records += int(raw.get("defense") == "blocked")
        passed_defense_records += int(raw.get("defense") == "passed")
    source_evaluator_role = _source_evaluator_role(judgments)
    target_observed = sum(
        not (
            isinstance(response.get("raw"), dict)
            and response["raw"].get("defense") == "blocked"
            and response["raw"].get("stage") == "input"
            and response["raw"].get("base_target_queried") is not True
        )
        for response in responses.values()
    )
    execution_roles = {
        "attacker": {
            "identity": run.get("attacker"),
            "status": "exercised" if attempts else "not_exercised",
            "observed_records": len(attempts),
        },
        "target": {
            "identity": cell.get("model"),
            "status": "exercised" if target_observed else "not_exercised",
            "observed_records": target_observed,
            "input_defense_block_records": len(responses) - target_observed,
        },
        "defense": {
            "identity": defense_name,
            "status": (
                "not_applicable"
                if defense_name == "none"
                else "exercised"
                if set(configured_defense_stages).issubset(observed_defense_stages)
                else "partially_exercised"
                if observed_defense_stages
                else "not_exercised"
            ),
            "configured_stages": configured_defense_stages,
            "observed_stage_records": dict(sorted(observed_defense_stages.items())),
            "passed_records": passed_defense_records,
            "blocked_records": blocked_defense_records,
        },
        "source_evaluator": source_evaluator_role,
    }

    budget = grid.get("call_budget_snapshot")
    if not isinstance(budget, dict):
        raise ValueError("canary grid lacks final call-budget snapshot")
    reserved = {
        "target_logical_calls": _integer(budget.get("target_calls"), "target calls"),
        "judge_model_calls": _integer(budget.get("judge_calls"), "judge calls"),
        "http_attempt_exposure": _integer(budget.get("http_attempts"), "HTTP exposure"),
    }
    reported_total = target_reported_attempts + judge_reported_attempts
    transport_complete = not target_unreported and not judge_unreported

    conditions = eligibility_plan.get("bindings", {}).get("experiment_conditions")
    condition_id = conditions.get("condition_id") if isinstance(conditions, dict) else None
    source_identity = {
        "dataset_hashes": manifest.get("dataset_hashes"),
        "harness_source": (manifest.get("config") or {}).get("harness_source"),
        "driver_source": run.get("driver_source"),
        "source_conformance_artifact": run.get("source_conformance_artifact"),
        "project_revision": run.get("project_revision"),
    }
    project_revision = validate_project_revision_binding(
        source_identity["project_revision"], allow_not_required=dry_run
    )
    eligibility_project_revision = validate_project_revision_binding(
        eligibility_plan.get("bindings", {}).get("project_revision"),
        allow_not_required=dry_run,
    )
    if project_revision != eligibility_project_revision:
        raise ValueError("canary execution/eligibility project-revision mismatch")
    if project_revision["harness_source_sha256"] != (
        source_identity["harness_source"] or {}
    ).get("sha256"):
        raise ValueError("canary project-revision/harness-source mismatch")
    if project_revision["driver_source_sha256"] != (
        source_identity["driver_source"] or {}
    ).get("sha256"):
        raise ValueError("canary project-revision/driver-source mismatch")
    body: dict[str, Any] = {
        "schema": LANE_CANARY_SCHEMA,
        "status": "complete",
        "purpose": "bounded_diagnostic_canary_summary",
        "evidence_class": evidence_class,
        "bindings": {
            "grid_id": grid.get("grid_id"),
            "grid_artifact": dict(grid_descriptor),
            "run_id": cell.get("run_id"),
            "completion_artifact": dict(completion_descriptor),
            "eligibility_plan_id": eligibility_plan.get("plan_id"),
            "eligibility_request_id": eligibility_plan.get("request_id"),
            "eligibility_condition_id": condition_id,
            "eligibility_artifact": dict(eligibility_descriptor),
            "lane_projection_id": lane_projection.get("projection_id"),
            "lane_projection_artifact": dict(lane_projection_descriptor),
        },
        "condition": {
            "execution_purpose": "diagnostic_canary",
            "dry_run": dry_run,
            "requested_model_spec": run.get("model_spec"),
            "resolved_target": cell.get("model"),
            "logical_source_arm": run.get("corpus"),
            "attacker": run.get("attacker"),
            "defense": run.get("defense"),
            "judges": manifest.get("judges"),
            "seeds": manifest.get("seeds"),
            "realized_identities": cell.get("realized_identities"),
            "source_identity": source_identity,
        },
        "workload": {
            "selected_clusters": 1,
            "selected_cluster_ids": sorted(cluster_ids),
            "selected_cluster_ids_sha256": canonical_json_sha256(sorted(cluster_ids)),
            "selected_rows": len(selected_ids),
            "selected_row_ids": sorted(selected_ids),
            "selected_row_ids_sha256": canonical_json_sha256(sorted(selected_ids)),
            "completed_attempts": len(attempts),
            "completed_responses": len(responses),
            "completed_judgments": len(judgments),
            "completed_trail_records": len(trails),
        },
        "artifact_storage": {
            "core_by_role": core_by_role,
            "core_artifact_bytes": core_bytes,
            "supporting_artifact_bytes": sum(
                _integer(item.get("bytes"), "supporting artifact bytes")
                for item in (
                    grid_descriptor, completion_descriptor,
                    eligibility_descriptor, lane_projection_descriptor,
                )
            ),
            "network_payload_bytes": "CANNOT-VERIFY",
        },
        "latency_observations": {
            "grid_observation_window": _observation_window(grid),
            "target": _latency_summary(target_latency, target_latency_missing),
            "model_judge": _latency_summary(judge_latency, judge_latency_missing),
            "end_to_end_throughput": "CANNOT-VERIFY",
        },
        "call_accounting": {
            "semantics": budget.get("accounting_semantics"),
            "reserved": reserved,
            "observed_transport_attempts": {
                "target_reported_total": target_reported_attempts,
                "judge_reported_total": judge_reported_attempts,
                "reported_total": reported_total,
                "target_unreported_record_ids": sorted(target_unreported),
                "judge_unreported_record_ids": sorted(judge_unreported),
                "reporting_complete": transport_complete,
            },
            "reserved_minus_reported_transport_attempts": (
                reserved["http_attempt_exposure"] - reported_total
                if transport_complete else "CANNOT-VERIFY"
            ),
        },
        "decision_support": {
            "completed": len(judgments),
            "evaluable": evaluable,
            "decided": decision_counts["decided"],
            "abstained": decision_counts["abstained"],
            "non_evaluable": decision_counts["non_evaluable"],
            "decision_coverage": (
                decision_counts["decided"] / evaluable if evaluable else None
            ),
        },
        "role_reachability": {
            "semantics": "actual_execution_and_queried_cascade_roles_v1",
            "execution_roles": execution_roles,
            "stages": role_rows,
            "all_configured_stages_represented": {
                row.get("judge") for row in trails
            } == set(manifest.get("judges") or []),
        },
        "limitations": dict(_LIMITATIONS),
    }
    body["canary_id"] = "lane-canary-" + canonical_json_sha256(body)[:24]
    return validate_lane_canary_summary(body)


def validate_lane_canary_summary(value: object) -> dict[str, Any]:
    """Fail closed on field drift, inconsistent support, or changed content ID."""

    artifact = _strict_object(value, _TOP_FIELDS, "lane canary summary")
    if artifact.get("schema") != LANE_CANARY_SCHEMA:
        raise ValueError("unsupported lane-canary schema")
    if artifact.get("status") != "complete" or artifact.get("purpose") != (
        "bounded_diagnostic_canary_summary"
    ):
        raise ValueError("lane canary status/purpose is invalid")
    if artifact.get("evidence_class") not in {"synthetic_offline", "live_diagnostic"}:
        raise ValueError("lane canary evidence class is invalid")
    if artifact.get("limitations") != _LIMITATIONS:
        raise ValueError("lane canary limitations are incomplete")

    bindings = _strict_object(artifact.get("bindings"), _BINDING_FIELDS, "bindings")
    for field, pattern in (
        ("grid_id", r"grid-[0-9a-f]{24}"),
        ("run_id", r"run-[0-9a-f]{24}"),
        ("eligibility_plan_id", r"eligibility-[0-9a-f]{24}"),
        ("eligibility_request_id", r"eligibility-request-[0-9a-f]{24}"),
        ("eligibility_condition_id", r"condition-[0-9a-f]{24}"),
        ("lane_projection_id", r"lane-projection-[0-9a-f]{24}"),
    ):
        item = bindings.get(field)
        if not isinstance(item, str) or re.fullmatch(pattern, item) is None:
            raise ValueError(f"lane canary binding {field} is invalid")
    descriptors = [
        _descriptor(bindings.get(field), f"bindings.{field}")
        for field in (
            "grid_artifact", "completion_artifact", "eligibility_artifact",
            "lane_projection_artifact",
        )
    ]

    condition = _strict_object(
        artifact.get("condition"), _CONDITION_FIELDS, "lane canary condition"
    )
    if condition.get("execution_purpose") != "diagnostic_canary":
        raise ValueError("lane canary condition execution purpose is invalid")
    if not isinstance(condition.get("dry_run"), bool):
        raise ValueError("lane canary condition dry_run must be boolean")
    expected_class = "synthetic_offline" if condition["dry_run"] else "live_diagnostic"
    if artifact["evidence_class"] != expected_class:
        raise ValueError("lane canary evidence class/dry-run state mismatch")
    for field in (
        "requested_model_spec", "resolved_target", "logical_source_arm", "attacker",
        "defense",
    ):
        _nonblank(condition.get(field), f"lane canary condition {field}")
    judges_raw = condition.get("judges")
    if not isinstance(judges_raw, list) or not judges_raw:
        raise ValueError("lane canary condition judges must be a non-empty list")
    judges = [
        _nonblank(judge, "lane canary condition judge") for judge in judges_raw
    ]
    if len(judges) != len(set(judges)):
        raise ValueError("lane canary condition judges must be unique")
    seeds = condition.get("seeds")
    if (
        not isinstance(seeds, list)
        or not seeds
        or any(isinstance(seed, bool) or not isinstance(seed, int) for seed in seeds)
        or len(seeds) != len(set(seeds))
    ):
        raise ValueError("lane canary condition seeds must be unique integers")
    if not isinstance(condition.get("realized_identities"), dict):
        raise ValueError("lane canary condition realized identities must be an object")
    source_identity = _strict_object(
        condition.get("source_identity"), _SOURCE_IDENTITY_FIELDS,
        "lane canary condition source identity",
    )
    project_revision = validate_project_revision_binding(
        source_identity.get("project_revision"),
        allow_not_required=condition["dry_run"],
    )
    harness_source = source_identity.get("harness_source")
    driver_source = source_identity.get("driver_source")
    if (
        not isinstance(harness_source, dict)
        or project_revision["harness_source_sha256"]
        != harness_source.get("sha256")
    ):
        raise ValueError("lane canary project-revision/harness-source mismatch")
    if (
        not isinstance(driver_source, dict)
        or project_revision["driver_source_sha256"]
        != driver_source.get("sha256")
    ):
        raise ValueError("lane canary project-revision/driver-source mismatch")

    workload = _strict_object(
        artifact.get("workload"), _WORKLOAD_FIELDS, "lane canary workload"
    )
    if _integer(workload.get("selected_clusters"), "selected clusters") != 1:
        raise ValueError("lane canary must describe exactly one selected cluster")
    cluster_ids = _sorted_unique_strings(
        workload.get("selected_cluster_ids"), "selected cluster IDs", nonempty=True
    )
    row_ids = _sorted_unique_strings(
        workload.get("selected_row_ids"), "selected row IDs", nonempty=True
    )
    if len(cluster_ids) != 1:
        raise ValueError("lane canary must bind exactly one selected cluster ID")
    for field, items in (
        ("selected_cluster_ids_sha256", cluster_ids),
        ("selected_row_ids_sha256", row_ids),
    ):
        if workload.get(field) != canonical_json_sha256(items):
            raise ValueError(f"lane canary workload {field} mismatch")
    if _integer(workload.get("selected_rows"), "selected rows", minimum=1) != len(row_ids):
        raise ValueError("lane canary selected-row count does not reconcile")
    completed_attempts = _integer(
        workload.get("completed_attempts"), "completed attempts", minimum=1
    )
    completed_responses = _integer(
        workload.get("completed_responses"), "completed responses", minimum=1
    )
    completed_judgments = _integer(
        workload.get("completed_judgments"), "completed judgments", minimum=1
    )
    if len({completed_attempts, completed_responses, completed_judgments}) != 1:
        raise ValueError("lane canary attempt/response/judgment counts do not reconcile")
    _integer(workload.get("completed_trail_records"), "completed trail records", minimum=1)

    storage = _strict_object(
        artifact.get("artifact_storage"), _STORAGE_FIELDS, "lane canary storage"
    )
    core = storage.get("core_by_role")
    required_roles = {"attempts", "judgments", "manifest", "responses", "results", "trails"}
    if not isinstance(core, dict) or set(core) != required_roles:
        raise ValueError("lane canary core-artifact inventory is invalid")
    core_descriptors = [
        _descriptor(item, f"core artifact {role}") for role, item in sorted(core.items())
    ]
    expected_core_records = {
        "attempts": completed_attempts,
        "judgments": completed_judgments,
        "manifest": 1,
        "responses": completed_responses,
        "trails": _integer(
            workload.get("completed_trail_records"), "completed trail records"
        ),
    }
    for role, count in expected_core_records.items():
        if core[role].get("records") != count:
            raise ValueError(f"lane canary core {role} record count mismatch")
    _integer(core["results"].get("records"), "core results records", minimum=1)
    if _integer(storage.get("core_artifact_bytes"), "core artifact bytes") != sum(
        item["bytes"] for item in core_descriptors
    ):
        raise ValueError("lane canary core-artifact bytes do not reconcile")
    if _integer(storage.get("supporting_artifact_bytes"), "supporting artifact bytes") != sum(
        item["bytes"] for item in descriptors
    ):
        raise ValueError("lane canary supporting-artifact bytes do not reconcile")
    if storage.get("network_payload_bytes") != "CANNOT-VERIFY":
        raise ValueError("lane canary must not invent network payload bytes")

    latency = _strict_object(
        artifact.get("latency_observations"), _LATENCY_FIELDS, "latency observations"
    )
    window = _strict_object(
        latency.get("grid_observation_window"), _WINDOW_FIELDS,
        "self-reported grid wall-clock window",
    )
    for field in ("started_at", "finished_at"):
        parsed = datetime.fromisoformat(
            _nonblank(window.get(field), f"grid wall-clock {field}")
        )
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("grid wall-clock timestamps must be UTC")
    start_time = datetime.fromisoformat(window["started_at"])
    finish_time = datetime.fromisoformat(window["finished_at"])
    seconds = (finish_time - start_time).total_seconds()
    if seconds < 0 or window.get("self_reported_wall_clock_seconds") != seconds:
        raise ValueError("self-reported grid wall-clock window does not reconcile")
    if (
        window.get("runtime_or_throughput_established") is not False
        or window.get("throughput_derived") is not False
        or "self_reported" not in _nonblank(window.get("basis"), "wall-clock basis")
        or "whole_seconds" not in _nonblank(window.get("precision"), "wall-clock precision")
    ):
        raise ValueError("grid wall-clock limitations are incomplete")
    _validate_latency_summary(
        latency.get("target"), "target latency", model_judge=False
    )
    _validate_latency_summary(
        latency.get("model_judge"), "model-judge latency", model_judge=True
    )
    if latency.get("end_to_end_throughput") != "CANNOT-VERIFY":
        raise ValueError("lane canary must not extrapolate throughput")

    calls = _strict_object(
        artifact.get("call_accounting"), _CALL_FIELDS, "lane canary call accounting"
    )
    if calls.get("semantics") != "durable_pre_call_logical_reservation_v1":
        raise ValueError("lane canary call-accounting semantics are invalid")
    reserved = _strict_object(calls.get("reserved"), _RESERVED_FIELDS, "reserved calls")
    for field in _RESERVED_FIELDS:
        _integer(reserved.get(field), f"reserved {field}")
    observed = _strict_object(
        calls.get("observed_transport_attempts"), _OBSERVED_TRANSPORT_FIELDS,
        "observed transport attempts",
    )
    target_reported = _integer(observed.get("target_reported_total"), "target attempts")
    judge_reported = _integer(observed.get("judge_reported_total"), "judge attempts")
    if _integer(observed.get("reported_total"), "reported attempts") != (
        target_reported + judge_reported
    ):
        raise ValueError("reported transport-attempt counts do not reconcile")
    target_missing = _sorted_unique_strings(
        observed.get("target_unreported_record_ids"), "unreported target records"
    )
    judge_missing = _sorted_unique_strings(
        observed.get("judge_unreported_record_ids"), "unreported judge records"
    )
    complete = not target_missing and not judge_missing
    if observed.get("reporting_complete") is not complete:
        raise ValueError("transport-attempt reporting-completeness mismatch")
    expected_difference: int | str = (
        reserved["http_attempt_exposure"] - observed["reported_total"]
        if complete else "CANNOT-VERIFY"
    )
    if calls.get("reserved_minus_reported_transport_attempts") != expected_difference:
        raise ValueError("reserved/reported transport difference does not reconcile")
    if complete and observed["reported_total"] > reserved["http_attempt_exposure"]:
        raise ValueError("reported transport attempts exceed reserved exposure")

    support = _strict_object(
        artifact.get("decision_support"), _DECISION_FIELDS, "decision support"
    )
    completed = _integer(support.get("completed"), "completed decisions")
    decided = _integer(support.get("decided"), "decided decisions")
    abstained = _integer(support.get("abstained"), "abstained decisions")
    non_evaluable = _integer(support.get("non_evaluable"), "non-evaluable decisions")
    evaluable = _integer(support.get("evaluable"), "evaluable decisions")
    if completed != decided + abstained + non_evaluable or evaluable != decided + abstained:
        raise ValueError("lane canary decision counts do not reconcile")
    expected_coverage = decided / evaluable if evaluable else None
    if support.get("decision_coverage") != expected_coverage:
        raise ValueError("lane canary decision coverage does not reconcile")
    if completed != completed_judgments:
        raise ValueError("lane canary workload/decision counts do not reconcile")

    roles = _strict_object(
        artifact.get("role_reachability"), _ROLE_FIELDS, "role reachability"
    )
    if roles.get("semantics") != "actual_execution_and_queried_cascade_roles_v1":
        raise ValueError("role-reachability semantics are invalid")
    if not isinstance(roles.get("all_configured_stages_represented"), bool):
        raise ValueError("configured-stage coverage must be boolean")
    execution_roles = roles.get("execution_roles")
    if not isinstance(execution_roles, dict) or set(execution_roles) != {
        "attacker", "target", "defense", "source_evaluator"
    }:
        raise ValueError("execution-role inventory is invalid")
    attacker_role = _strict_object(
        execution_roles["attacker"], _ATTACKER_ROLE_FIELDS, "attacker role"
    )
    if (
        attacker_role.get("identity") != condition["attacker"]
        or attacker_role.get("status") != "exercised"
        or attacker_role.get("observed_records") != completed_attempts
    ):
        raise ValueError("attacker reachability does not reconcile")
    target_role = _strict_object(
        execution_roles["target"], _TARGET_ROLE_FIELDS, "target role"
    )
    target_observed = _integer(target_role.get("observed_records"), "target records")
    target_blocks = _integer(
        target_role.get("input_defense_block_records"), "input-defense blocks"
    )
    if (
        target_role.get("identity") != condition["resolved_target"]
        or target_observed + target_blocks != completed_responses
        or target_role.get("status") != (
            "exercised" if target_observed else "not_exercised"
        )
    ):
        raise ValueError("target reachability does not reconcile")
    defense_role = _strict_object(
        execution_roles["defense"], _DEFENSE_ROLE_FIELDS, "defense role"
    )
    expected_defense_stages = (
        [] if condition["defense"] == "none"
        else ["input", "output"] if condition["defense"] == "both"
        else [condition["defense"]]
    )
    observed_stages = defense_role.get("observed_stage_records")
    if not isinstance(observed_stages, dict) or set(observed_stages) - {"input", "output"}:
        raise ValueError("defense stage-record inventory is invalid")
    for stage, count in observed_stages.items():
        _integer(count, f"defense {stage} records", minimum=1)
    passed = _integer(defense_role.get("passed_records"), "passed defense records")
    blocked = _integer(defense_role.get("blocked_records"), "blocked defense records")
    if passed + blocked > completed_responses:
        raise ValueError("defense outcome records exceed completed responses")
    expected_defense_status = (
        "not_applicable" if not expected_defense_stages
        else "exercised" if set(expected_defense_stages).issubset(observed_stages)
        else "partially_exercised" if observed_stages else "not_exercised"
    )
    if (
        defense_role.get("identity") != condition["defense"]
        or defense_role.get("configured_stages") != expected_defense_stages
        or defense_role.get("status") != expected_defense_status
        or (not expected_defense_stages and (observed_stages or passed or blocked))
        or (
            bool(expected_defense_stages)
            and passed + blocked != completed_responses
        )
        or (
            "input" in expected_defense_stages
            and observed_stages.get("input") != completed_responses
        )
        or (
            "output" in expected_defense_stages
            and observed_stages.get("output") != completed_responses - target_blocks
        )
    ):
        raise ValueError("defense reachability does not reconcile")
    source_role = _strict_object(
        execution_roles["source_evaluator"], _SOURCE_EVALUATOR_ROLE_FIELDS,
        "source-evaluator role",
    )
    required_source = _integer(
        source_role.get("required_records"), "source-evaluator required records"
    )
    observed_source = _integer(
        source_role.get("observed_records"), "source-evaluator observed records"
    )
    valid_source = _integer(
        source_role.get("valid_records"), "source-evaluator valid records"
    )
    expected_source_status = (
        "not_applicable" if required_source == 0
        else "exercised" if observed_source else "not_exercised"
    )
    if (
        required_source > completed_judgments
        or valid_source > observed_source
        or observed_source > required_source
        or source_role.get("status") != expected_source_status
    ):
        raise ValueError("source-evaluator reachability does not reconcile")
    stages = roles.get("stages")
    if not isinstance(stages, list):
        raise ValueError("cascade role stages must be a list")
    observed_judges: set[str] = set()
    for index, stage in enumerate(stages):
        expected_fields = {
            "stage", "judge", "role", "trail_records", "queried_records",
            "not_queried_records", "reached",
        }
        if not isinstance(stage, dict) or set(stage) != expected_fields:
            raise ValueError(f"cascade stage {index} has an invalid field inventory")
        _integer(stage.get("stage"), f"cascade stage {index}")
        judge = _nonblank(stage.get("judge"), f"cascade judge {index}")
        observed_judges.add(judge)
        if stage.get("role") not in {"authoritative", "shadow"}:
            raise ValueError(f"cascade stage {index} has invalid role")
        records = _integer(stage.get("trail_records"), f"cascade trail records {index}")
        queried = _integer(stage.get("queried_records"), f"cascade queried records {index}")
        not_queried = _integer(
            stage.get("not_queried_records"), f"cascade non-queried records {index}"
        )
        if records != queried + not_queried or stage.get("reached") != (queried > 0):
            raise ValueError(f"cascade stage {index} counts do not reconcile")
    if roles["all_configured_stages_represented"] is not (observed_judges == set(judges)):
        raise ValueError("configured-stage coverage does not reconcile")

    body = {key: item for key, item in artifact.items() if key != "canary_id"}
    expected_id = "lane-canary-" + canonical_json_sha256(body)[:24]
    if artifact.get("canary_id") != expected_id or _CANARY_ID.fullmatch(expected_id) is None:
        raise ValueError("lane canary ID/content mismatch")
    return artifact


def lane_canary_bytes(value: Mapping[str, Any]) -> bytes:
    artifact = validate_lane_canary_summary(dict(value))
    return (json.dumps(
        artifact, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False,
    ) + "\n").encode("utf-8")


def write_lane_canary(directory: Path, value: Mapping[str, Any]) -> Path:
    """Create the immutable summary, accepting an identical existing copy."""

    payload = lane_canary_bytes(value)
    artifact = validate_lane_canary_summary(dict(value))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{artifact['canary_id']}.lane-canary.json"
    if path.exists():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != payload:
            raise FileExistsError(f"lane-canary artifact collision: {path}")
        return path
    temporary = path.with_name(f".{path.name}.pending-{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists():
            raise FileExistsError(f"lane-canary artifact appeared concurrently: {path}")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


__all__ = [
    "LANE_CANARY_SCHEMA", "artifact_descriptor", "build_lane_canary_summary",
    "lane_canary_bytes", "validate_lane_canary_summary", "write_lane_canary",
]
