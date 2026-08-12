"""Join planning, execution, and decision evidence without pooling their units.

The Level-1 artifact is an accounting surface, not a safety score.  Its fixed
planning-stratum universe begins only after selected corpora have materialized
and ``ura-eligibility-plan/1`` can name their exact strata.  Earlier acquisition
or conversion failures are retained separately as request-level errors because
their modality/source strata cannot be reconstructed honestly.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from experiments.figure_results import (  # noqa: E402
    _GridReference,
    _inside,
    _integer,
    _nonblank,
    _read_object,
    _sha256_file,
    _string_list,
    _validate_cell,
)
from experiments.suite_summary import _load_eligibility_plan  # noqa: E402
from ura.data_models import Attempt  # noqa: E402
from ura.eligibility import (  # noqa: E402
    canonical_json_sha256,
    lifecycle_stratum_id,
    validate_eligibility_plan,
)


LEVEL1_SCHEMA = "ura-level1-evidence/1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CONDITION_ID = re.compile(r"condition-[0-9a-f]{24}")
_COMPLETE = frozenset({"complete", "complete_existing"})
_STRUCTURAL_NA = frozenset({
    "transport_blocked",
    "requires_source_native_runtime_or_evaluator",
    "requires_substantive_automated_evaluator_or_reference",
    "attack_mode_incompatible",
})
_MAX_ERROR_BYTES = 8 * 1024 * 1024
_CONDITION_FIELDS = frozenset({
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
    "selected_config_identities",
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


def _condition_values(value: object) -> dict[str, Any]:
    """Validate the compact experiment-condition projection used by Level 1."""

    if not isinstance(value, dict) or set(value) != _CONDITION_FIELDS:
        raise ValueError("eligibility experiment-condition fields are incomplete")
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
    if not isinstance(value["dry_run"], bool):
        raise ValueError("experiment condition dry_run must be boolean")
    selected = value["selected_config_identities"]
    expected_selected = {
        "source_config",
        "source_conformance",
        "attacker_config",
        "api_config",
        "local_config",
    }
    if not isinstance(selected, dict) or set(selected) != expected_selected:
        raise ValueError("experiment condition selected-config identities are incomplete")
    for field in sorted(expected_selected):
        _selected_identity(selected[field], label=f"selected {field}")
    return value


def _condition_from_plan(plan: dict[str, Any]) -> dict[str, Any]:
    bindings = plan["bindings"]
    raw = bindings.get("experiment_conditions")
    if not isinstance(raw, dict) or set(raw) != {"condition_id", "values"}:
        raise ValueError(
            f"eligibility plan {plan['plan_id']} lacks exact experiment conditions"
        )
    values = _condition_values(raw["values"])
    condition_id = raw["condition_id"]
    if (
        not isinstance(condition_id, str)
        or _CONDITION_ID.fullmatch(condition_id) is None
        or condition_id != "condition-" + _strict_json_sha256(values)[:24]
    ):
        raise ValueError("eligibility experiment condition ID/content mismatch")
    if values["dry_run"] is not plan["request"]["dry_run"]:
        raise ValueError("eligibility request/condition dry-run mismatch")
    selected = bindings.get("selected_config_identities")
    if not isinstance(selected, dict) or selected != values[
        "selected_config_identities"
    ]:
        raise ValueError("eligibility selected-config condition mismatch")
    for field in (
        "source_instances_sha256",
        "attacker_configs_sha256",
        "api_configs_sha256",
        "local_configs_sha256",
    ):
        digest = bindings.get(field)
        if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
            raise ValueError(f"eligibility binding {field} is not SHA-256")
    return raw


def _grid_condition(request: Mapping[str, Any]) -> dict[str, Any]:
    judges = request.get("judges")
    if not isinstance(judges, list):
        raise ValueError("grid request judges must be a list")
    budget = request.get("global_call_budget")
    if not isinstance(budget, dict):
        raise ValueError("grid request lacks the global call-budget condition")
    selected = {
        "source_config": _selected_identity(
            request.get("source_config_artifact"), label="source config"
        ),
        "source_conformance": _selected_identity(
            request.get("source_conformance_artifact"), label="source conformance"
        ),
        "attacker_config": _selected_identity(
            request.get("attacker_config_artifact"), label="attacker config"
        ),
        "api_config": _selected_identity(
            request.get("api_config_artifact"), label="API config"
        ),
        "local_config": _selected_identity(
            request.get("local_config_artifact"), label="local config"
        ),
    }
    values = {
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
        "selected_config_identities": selected,
    }
    return {
        "condition_id": "condition-" + _strict_json_sha256(values)[:24],
        "values": values,
    }


def _validate_grid_plan_bindings(
    request: Mapping[str, Any], plan: Mapping[str, Any]
) -> None:
    bindings = plan["bindings"]
    if request.get("driver_source") != bindings.get("driver_source"):
        raise ValueError("grid/eligibility driver-source binding mismatch")
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


def _grid_id(grid: dict[str, Any]) -> str:
    request = grid["request"]
    identity = dict(request)
    for field in (
        "source_config_artifact",
        "source_conformance_artifact",
        "attacker_config_artifact",
        "api_config_artifact",
        "local_config_artifact",
    ):
        identity[field] = _selected_identity(
            request.get(field), label=field.replace("_", " ")
        )
    return "grid-" + _strict_json_sha256(identity)[:24]


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
            if grid_id != _grid_id(grid) or grid_path.name != f"{grid_id}.grid.json":
                raise ValueError(f"grid ID/content/filename mismatch: {grid_path}")
            if grid_id in seen_grid_ids:
                raise ValueError(f"duplicate grid identity: {grid_id}")
            seen_grid_ids.add(grid_id)
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
            if not _plan_descriptor_matches(descriptor, plan_artifact):
                raise ValueError(f"grid/eligibility artifact descriptor mismatch: {grid_path}")
            if _grid_condition(request) != _condition_from_plan(plan):
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
                    ref = _GridReference(grid_id, grid_path, request, raw_status)
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
            elif modality_result.get("schema") == "ura-modality-coverage-result/1":
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
    candidates = [
        item
        for item in items
        if item["source"] == attempt.params.get("planning_source")
        and item["exact_modality_combination"] == exact
        and item["expected_behavior"]
        == attempt.params.get("planning_expected_behavior")
        and item["common_metrics_eligible"]
        is attempt.params.get("planning_common_metrics_eligible")
        and item["required_metric"]
        == attempt.params.get("planning_required_metric")
        and item["source_policy"]
        == _policy_identity(attempt.params.get("planning_source_policy"))
    ]
    if len(candidates) != 1:
        raise ValueError(
            "completed judgment cannot be attributed to exactly one planning "
            f"stratum; attempt={judgment.get('attempt_id')!r}, matches={len(candidates)}"
        )
    return candidates[0]


def _decision_state(judgment: dict[str, Any]) -> str:
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
            "non_evaluable_judgment_records": 0,
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
    selected_ids = audit.get("selected_ids")
    if (
        not isinstance(selected_ids, list)
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or canonical_json_sha256(sorted(selected_ids))
        != selected_corpus_binding.get("selected_datapoint_ids_sha256")
    ):
        raise ValueError("completed cell/eligibility selected-ID audit mismatch")
    attempts = validated["attempts"]
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
        if state != "non_evaluable":
            record["evaluable_judgment_records"] += 1
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


def build_level1_evidence(
    plan_artifacts: list[tuple[dict[str, Any], str, str, int, int]],
    grids_by_plan: Mapping[str, dict[str, Any]],
    request_level_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build one deterministic, unit-qualified lifecycle inventory."""

    if not plan_artifacts:
        raise ValueError("Level-1 evidence requires at least one eligibility plan")
    dry_run_modes = {
        artifact[0]["request"]["dry_run"] for artifact in plan_artifacts
    }
    if len(dry_run_modes) != 1:
        raise ValueError(
            "one Level-1 artifact must not mix diagnostic dry-run and measured requests"
        )
    diagnostic_dry_run = next(iter(dry_run_modes))
    evidence_kind = "diagnostic_dry_run" if diagnostic_dry_run else "measured_run"
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
                "attestation_status": "not_supplied",
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
                    "attestation_status": "not_supplied",
                    "attestation_reference": None,
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
                    "non_evaluable_judgment_records": item_counts.get(
                        "non_evaluable_judgment_records", 0
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
        "missing": sum(row["missing"] for row in rows),
        "associated_execution_unit_error": sum(
            row["final_disposition"].startswith("execution_unit_error_")
            for row in rows
        ),
        "attempted": None,
        "attested": None,
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
        "attested": None,
    }
    judgment_counts = {
        "unit": "judgment_record",
        "completed": sum(row["completed_judgment_records"] for row in rows),
        "evaluable": sum(row["evaluable_judgment_records"] for row in rows),
        "decided": sum(row["decided_judgment_records"] for row in rows),
        "abstained": sum(row["abstained_judgment_records"] for row in rows),
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
    body: dict[str, Any] = {
        "schema_version": LEVEL1_SCHEMA,
        "status": "validated_unit_qualified_lifecycle_inventory",
        "scope": {
            "fixed_universe": (
                "materialized requested planning strata from supplied "
                "ura-eligibility-plan/1 artifacts"
            ),
            "pre_materialization_failures": (
                "retained as request-level errors; exact source/modality strata "
                "are CANNOT-VERIFY and are not fabricated"
            ),
            "universal_safety_score_defined": False,
            "evidence_kind": evidence_kind,
            "contains_diagnostic_dry_run": diagnostic_dry_run,
            "empirical_validity_established": False,
        },
        "availability": {
            "live_attestation": {
                "status": "not_supplied",
                "counts": None,
                "reason": "RUN-006 typed attestation binding is not implemented",
            },
            "analysis_inclusion": {
                "status": "not_supplied",
                "counts": None,
                "reason": (
                    "no explicit downstream analysis-selection artifact was supplied"
                ),
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
            "planning_strata": planning_counts,
            "execution_units": execution_counts,
            "judgment_records": judgment_counts,
            "request_level_errors": {
                "unit": "unstratified_request_error_artifact",
                "observed": len(request_level_errors),
            },
        },
        "requests": request_rows,
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
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field)) for field in _CSV_FIELDS})


def _write_json_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(
            value,
            handle,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        handle.write("\n")


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
        required=True,
        help="validated ura-eligibility-plan/1 JSON; repeat per request condition",
    )
    parser.add_argument(
        "--results",
        type=Path,
        action="append",
        default=[],
        help="run_matrix results root containing final complete/partial grids",
    )
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-csv", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out_json.resolve() == args.out_csv.resolve():
        parser.error("--out-json and --out-csv must be different paths")
    try:
        artifacts = [_plan_artifact(path) for path in args.eligibility]
        plan_index = {artifact[0]["plan_id"]: artifact for artifact in artifacts}
        if len(plan_index) != len(artifacts):
            raise ValueError("duplicate eligibility plan input")
        grids, request_errors = _load_results(args.results, plan_index)
        report = build_level1_evidence(artifacts, grids, request_errors)
        _write_json_new(args.out_json, report)
        try:
            write_csv(args.out_csv, report["planning_strata"])
        except Exception:
            args.out_json.unlink(missing_ok=True)
            raise
    except (KeyError, OSError, TypeError, ValueError) as exc:
        print(f"Level-1 evidence failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "written",
        "evidence_id": report["evidence_id"],
        "json": str(args.out_json.resolve()),
        "csv": str(args.out_csv.resolve()),
        "planning_strata": report["counts"]["planning_strata"]["requested"],
        "execution_units": report["counts"]["execution_units"]["requested"],
        "attestation_status": "not_supplied",
        "analysis_inclusion_status": "not_supplied",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
