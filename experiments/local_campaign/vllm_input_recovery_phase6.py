"""Recover only the unfinished GPTGeoChat suffix after a context rejection.

The retained Runner 2.25 prefix remains immutable. This controller verifies that
prefix against the exact failed seven-unit campaign, excludes it with Runner's
content-bound recovery selector, and executes only the never-completed suffix
under Runner 2.26. Context-limit rejections become typed input-compatibility
missing responses; model-output failures retain the independent retry policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _descriptor,
    _stable_file,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    COMPLETED_LANES,
    PREFIX_SCHEMA,
    UNIT_LAYOUT,
    Unit,
    _create_json,
    _framework_lock_id,
    _gate5_manifest_sha256,
    _historical_specs,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _sha256_json,
    _utc_now,
    _validate_descriptor,
    validate_historical_completion,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-vllm-input-recovery-phase6/1"
FAILED_SCHEMA = "ura-vllm-stability-phase6/1"
FAILED_COMMIT = "bd2faf4e98febfdda01e99bdd6042673f7564bc8"
FAILED_UNIT = "vllm-stability-gptgeochat-qwen3-vl"
SOURCE_LANE = "gptgeochat-qwen3-vl"
CORPUS = "gptgeochat_release"
SELECTED_RECORDS = 2020
COMPLETED_PREFIX_RECORDS = 375
RECOVERY_RECORDS = SELECTED_RECORDS - COMPLETED_PREFIX_RECORDS
RECOVERY_UNIT = "vllm-input-recovery-gptgeochat-qwen3-vl-suffix"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
RESULT_FIELDS = {
    "status",
    "unit_id",
    "source_lane",
    "corpus",
    "selected_records",
    "target_answer_retries",
    "target_call_cap",
    "target_attempts",
    "successful_target_generations",
    "missing_responses",
    "result_root",
    "state",
    "level1",
}
STATE_FIELDS = {
    "schema",
    "unit_id",
    "source_lane",
    "corpus",
    "selected_records",
    "target_answer_retries",
    "target_call_cap",
    "attestation",
    "projection",
    "result_root",
    "runner_argv",
}


def _canonical_root(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{label} is not an absolute path")
    path = Path(value)
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical existing path")
    return path


def _one_file(root: Path, pattern: str, *, label: str) -> Path:
    matches = sorted(root.glob(pattern))
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError(f"{label} requires exactly one {pattern}")
    return matches[0]


def _one_full_checkpoint(root: Path) -> Path:
    matches = [
        path
        for path in sorted(root.glob(f"{CORPUS}--*.checkpoint.jsonl"))
        if not path.name.endswith(".responses.checkpoint.jsonl")
    ]
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError("failed GPTGeoChat requires exactly one full checkpoint")
    return matches[0]


def _jsonl_rows(path: Path, *, label: str) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    for raw in _stable_file(path, label=label).splitlines():
        if not raw:
            continue
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{label} contains a non-object row")
        rows.append(value)
    return rows


def validate_failed_completion(
    path: Path,
    expected_sha256: str,
) -> tuple[dict[str, Any], Path]:
    """Require the exact one-failure seven-unit terminal before recovery."""

    resolved = path.resolve(strict=True)
    payload = _stable_file(resolved, label="failed vLLM stability completion")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("failed vLLM stability completion digest changed")
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("failed vLLM stability completion is not one object")
    expected_fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "historical_completion",
        "historical_completed_lanes_excluded",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "model_stability_accounting",
        "no_completed_rows_repeated",
        "cross_output_policy_pooling_permitted",
        "paid_provider_calls",
    }
    expected_order = [row[0] for row in UNIT_LAYOUT]
    if (
        set(value) != expected_fields
        or value.get("schema") != FAILED_SCHEMA
        or value.get("status") != "complete_with_failures"
        or value.get("controller_exit_code") != 1
        or value.get("expected_commit") != FAILED_COMMIT
        or value.get("runner_code_version") != "ura-runner/2.25"
        or value.get("target_answer_retries") != 1
        or value.get("historical_completed_lanes_excluded")
        != sorted(COMPLETED_LANES)
        or value.get("unit_order") != expected_order
        or value.get("model_stability_accounting")
        != "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        or value.get("no_completed_rows_repeated") is not True
        or value.get("cross_output_policy_pooling_permitted") is not False
        or value.get("paid_provider_calls") != 0
    ):
        raise ValueError("failed vLLM stability completion contract changed")
    historical_path = _validate_descriptor(
        value.get("historical_completion"),
        label="failed campaign historical completion",
    )
    historical = _load_json(
        historical_path,
        label="failed campaign historical completion",
    )
    validate_historical_completion(historical)

    failures = value.get("unit_failures")
    results = value.get("unit_results")
    if not isinstance(failures, dict) or set(failures) != {FAILED_UNIT}:
        raise ValueError("failed campaign does not contain exactly the GPTGeoChat failure")
    failure = failures[FAILED_UNIT]
    if (
        not isinstance(failure, dict)
        or set(failure)
        != {
            "status",
            "unit_id",
            "source_lane",
            "corpus",
            "stage",
            "error_type",
            "error",
            "target_answer_retries",
        }
        or failure.get("status") != "failed"
        or failure.get("unit_id") != FAILED_UNIT
        or failure.get("source_lane") != SOURCE_LANE
        or failure.get("corpus") is not None
        or failure.get("stage") != "gate5_or_measured"
        or failure.get("target_answer_retries") != 1
    ):
        raise ValueError("GPTGeoChat failed-unit record changed")
    expected_results = {row[0]: row[3] for row in UNIT_LAYOUT if row[0] != FAILED_UNIT}
    if not isinstance(results, dict) or set(results) != set(expected_results):
        raise ValueError("failed campaign completed-unit inventory changed")
    attempted = successful = missing = 0
    for unit_id, selected in expected_results.items():
        result = results[unit_id]
        if (
            not isinstance(result, dict)
            or result.get("status") != "complete"
            or result.get("unit_id") != unit_id
            or result.get("selected_records") != selected
            or result.get("target_answer_retries") != 1
            or result.get("target_call_cap") != selected * 2
            or result.get("target_attempts") != selected
        ):
            raise ValueError(f"failed campaign completed unit {unit_id!r} changed")
        unit_successful = result.get("successful_target_generations")
        unit_missing = result.get("missing_responses")
        if (
            isinstance(unit_successful, bool)
            or not isinstance(unit_successful, int)
            or unit_successful < 0
            or isinstance(unit_missing, bool)
            or not isinstance(unit_missing, int)
            or unit_missing < 0
            or unit_successful + unit_missing != selected
        ):
            raise ValueError(f"failed campaign unit {unit_id!r} accounting changed")
        _validate_descriptor(result.get("state"), label=f"{unit_id} state")
        _validate_descriptor(result.get("level1"), label=f"{unit_id} Level 1")
        _canonical_root(result.get("result_root"), label=f"{unit_id} result root")
        attempted += selected
        successful += unit_successful
        missing += unit_missing
    if value.get("target_execution") != {
        "target_attempts": attempted,
        "successful_target_generations": successful,
        "missing_responses": missing,
    }:
        raise ValueError("failed campaign target-execution accounting changed")
    control_root = resolved.parent
    if (
        control_root.is_symlink()
        or control_root.resolve(strict=True) != control_root
        or control_root.parent.name != "engineering"
    ):
        raise ValueError("failed campaign control root is not canonical")
    return value, control_root


def build_recovery_prefix(
    failed_root: Path,
) -> tuple[dict[str, Any], Path]:
    """Bind the exact 375 durable rows and return the never-completed suffix."""

    state_path = failed_root / "units" / FAILED_UNIT / "state.json"
    state = _load_json(state_path, label="failed GPTGeoChat unit state")
    if (
        state.get("schema") != "ura-vllm-stability-phase6-unit-state/1"
        or state.get("unit_id") != FAILED_UNIT
        or state.get("source_lane") != SOURCE_LANE
        or state.get("corpus") is not None
        or state.get("selected_records") != SELECTED_RECORDS
        or state.get("target_answer_retries") != 1
        or state.get("target_call_cap") != SELECTED_RECORDS * 2
    ):
        raise ValueError("failed GPTGeoChat unit state changed")
    result_root = _canonical_root(
        state.get("result_root"),
        label="failed GPTGeoChat result root",
    )
    manifest_path = _one_file(
        result_root,
        f"{CORPUS}--*.manifest.json",
        label="failed GPTGeoChat manifest",
    )
    attempts_path = _one_file(
        result_root,
        f"{CORPUS}--*.attempts.jsonl",
        label="failed GPTGeoChat attempts",
    )
    response_checkpoint = _one_file(
        result_root,
        f"{CORPUS}--*.responses.checkpoint.jsonl",
        label="failed GPTGeoChat response checkpoint",
    )
    full_checkpoint = _one_full_checkpoint(result_root)
    manifest = _load_json(manifest_path, label="failed GPTGeoChat manifest")
    config = manifest.get("config")
    run = config.get("run") if isinstance(config, dict) else None
    audit = run.get("sampling_audit") if isinstance(run, dict) else None
    selected_ids = audit.get("selected_ids") if isinstance(audit, dict) else None
    if (
        not isinstance(selected_ids, list)
        or len(selected_ids) != SELECTED_RECORDS
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or len(set(selected_ids)) != SELECTED_RECORDS
    ):
        raise ValueError("failed GPTGeoChat selected identity inventory changed")
    attempt_rows = _jsonl_rows(attempts_path, label="failed GPTGeoChat attempts")
    completed_ids = [row.get("datapoint_id") for row in attempt_rows]
    if (
        len(completed_ids) != COMPLETED_PREFIX_RECORDS
        or any(not isinstance(item, str) or not item for item in completed_ids)
        or len(set(completed_ids)) != COMPLETED_PREFIX_RECORDS
        or completed_ids != selected_ids[:COMPLETED_PREFIX_RECORDS]
        or len(_jsonl_rows(response_checkpoint, label="GPTGeoChat responses"))
        != COMPLETED_PREFIX_RECORDS
        or len(_jsonl_rows(full_checkpoint, label="GPTGeoChat checkpoints"))
        != COMPLETED_PREFIX_RECORDS
    ):
        raise ValueError("failed GPTGeoChat durable rows are not the exact prefix")
    remaining_ids = selected_ids[COMPLETED_PREFIX_RECORDS:]
    return {
        "schema": PREFIX_SCHEMA,
        "corpus": CORPUS,
        "completed_prefix_count": COMPLETED_PREFIX_RECORDS,
        "selected_datapoint_ids_sha256": _sha256_json(selected_ids),
        "completed_prefix_ids_sha256": _sha256_json(completed_ids),
        "remaining_datapoint_ids_sha256": _sha256_json(remaining_ids),
    }, result_root


def _validate_metric_result(
    result: object,
    *,
    logical_lane: str,
    physical_unit: str,
    source_lane: str,
    corpus: str | None,
    selected_records: int,
    runner_root: Path,
    control_root: Path,
    state_schema: str,
    completion: Mapping[str, object],
) -> dict[str, Any]:
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
        raise ValueError(f"{physical_unit} metric result contract changed")
    successful = result.get("successful_target_generations")
    missing = result.get("missing_responses")
    if (
        result.get("status") != "complete"
        or result.get("unit_id") != physical_unit
        or result.get("source_lane") != source_lane
        or result.get("corpus") != corpus
        or result.get("selected_records") != selected_records
        or result.get("target_answer_retries") != 1
        or result.get("target_call_cap") != selected_records * 2
        or result.get("target_attempts") != selected_records
        or isinstance(successful, bool)
        or not isinstance(successful, int)
        or successful < 0
        or isinstance(missing, bool)
        or not isinstance(missing, int)
        or missing < 0
        or successful + missing != selected_records
    ):
        raise ValueError(f"{physical_unit} metric accounting changed")

    result_root = Path(str(result.get("result_root", "")))
    expected_root = runner_root / physical_unit / control_root.name
    if (
        not result_root.is_absolute()
        or result_root.is_symlink()
        or result_root.resolve(strict=True) != expected_root
    ):
        raise ValueError(f"{physical_unit} metric result root changed")
    state_path = _validate_descriptor(
        result.get("state"), label=f"{physical_unit} state"
    )
    level1_path = _validate_descriptor(
        result.get("level1"), label=f"{physical_unit} Level 1 evidence"
    )
    expected_unit_root = control_root / "units" / physical_unit
    if (
        state_path != expected_unit_root / "state.json"
        or level1_path != expected_unit_root / "level1.json"
    ):
        raise ValueError(f"{physical_unit} controller artifact placement changed")

    grids = sorted(result_root.glob("*.grid.json"))
    envelopes = sorted(result_root.glob("*.request-envelope.json"))
    eligibility = sorted(result_root.glob("eligibility-*.eligibility.json"))
    markers = sorted(result_root.glob("*.complete.json"))
    if (
        len(grids) != 1
        or len(envelopes) != 1
        or len(eligibility) != 1
        or not markers
    ):
        raise ValueError(f"{physical_unit} completed Runner artifacts changed")

    state = _load_json(state_path, label=f"{physical_unit} state")
    argv = state.get("runner_argv")
    if (
        set(state) != STATE_FIELDS
        or state.get("schema") != state_schema
        or state.get("unit_id") != physical_unit
        or state.get("source_lane") != source_lane
        or state.get("corpus") != corpus
        or state.get("selected_records") != selected_records
        or state.get("target_answer_retries") != 1
        or state.get("target_call_cap") != selected_records * 2
        or state.get("result_root") != str(result_root)
        or not isinstance(argv, list)
        or any(not isinstance(item, str) for item in argv)
        or _option(argv, "--target-answer-retries") != "1"
    ):
        raise ValueError(f"{physical_unit} measured state changed")
    revision = _option(argv, "--project-revision-sha256")
    source = _option(argv, "--source-conformance-sha256")
    if HEX64.fullmatch(revision) is None or HEX64.fullmatch(source) is None:
        raise ValueError(f"{physical_unit} project/source stratum changed")
    evidence = {
        "completion": dict(completion),
        "physical_unit_id": physical_unit,
        "logical_lane_id": logical_lane,
        "grid": _descriptor(grids[0], label=f"{physical_unit} measured grid"),
        "request_envelope": _descriptor(
            envelopes[0], label=f"{physical_unit} request envelope"
        ),
        "eligibility_plan": _descriptor(
            eligibility[0], label=f"{physical_unit} eligibility plan"
        ),
        "completion_markers": [
            _descriptor(marker, label=f"{physical_unit} completion marker")
            for marker in markers
        ],
        "state": dict(result["state"]),
        "level1": dict(result["level1"]),
    }
    return {
        "revision": revision,
        "source": source,
        "root": str(result_root),
        "evidence": evidence,
        "grid": evidence["grid"],
        "eligibility_plan": evidence["eligibility_plan"],
        "completion_markers": evidence["completion_markers"],
        "successful": successful,
        "missing": missing,
    }


def validate_phase7_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the failed Runner 2.25 campaign plus its Runner 2.26 suffix."""

    recovery_completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    recovery_completion = _load_json(
        recovery_completion_path,
        label="vLLM input-recovery completion",
    )
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "failed_completion",
        "recovery_selection",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "input_compatibility_accounting",
        "model_stability_accounting",
        "no_completed_rows_repeated",
        "cross_runner_or_input_policy_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(recovery_completion) != fields
        or recovery_completion.get("schema") != SCHEMA
        or recovery_completion.get("status") != "complete"
        or recovery_completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(recovery_completion.get("expected_commit", "")))
        is None
        or recovery_completion.get("runner_code_version") != "ura-runner/2.26"
        or recovery_completion.get("target_answer_retries") != 1
        or recovery_completion.get("unit_order") != [RECOVERY_UNIT]
        or recovery_completion.get("unit_failures") != {}
        or recovery_completion.get("input_compatibility_accounting")
        != "typed_missing_response_without_retry_or_policy_judge"
        or recovery_completion.get("model_stability_accounting")
        != "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        or recovery_completion.get("no_completed_rows_repeated") is not True
        or recovery_completion.get(
            "cross_runner_or_input_policy_pooling_permitted"
        )
        is not False
        or recovery_completion.get("paid_provider_calls") != 0
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            str(recovery_completion.get("completed_at_utc", "")),
        )
        is None
    ):
        raise ValueError("vLLM input-recovery completion contract changed")

    failed_path = _validate_descriptor(
        recovery_completion.get("failed_completion"),
        label="vLLM failed stability completion",
    )
    failed_descriptor = dict(recovery_completion["failed_completion"])
    failed, failed_root = validate_failed_completion(
        failed_path,
        str(failed_descriptor["sha256"]),
    )
    expected_prefix, failed_prefix_root = build_recovery_prefix(failed_root)
    recovery_selection_path = _validate_descriptor(
        recovery_completion.get("recovery_selection"),
        label="GPTGeoChat recovery selection",
    )
    recovery_control_root = recovery_completion_path.parent
    if (
        recovery_control_root.is_symlink()
        or recovery_control_root.resolve(strict=True) != recovery_control_root
        or recovery_control_root.parent.name != "engineering"
        or recovery_selection_path
        != recovery_control_root / "inputs/gptgeochat-completed-prefix.json"
        or _load_json(recovery_selection_path, label="GPTGeoChat recovery selection")
        != expected_prefix
    ):
        raise ValueError("GPTGeoChat recovery selection changed")

    failed_results = failed.get("unit_results")
    recovery_results = recovery_completion.get("unit_results")
    if (
        not isinstance(failed_results, dict)
        or not isinstance(recovery_results, dict)
        or set(recovery_results) != {RECOVERY_UNIT}
    ):
        raise ValueError("vLLM recovery metric result inventory changed")

    failed_completion_descriptor = _descriptor(
        failed_path, label="vLLM failed stability completion"
    )
    recovery_descriptor = _descriptor(
        recovery_completion_path, label="vLLM input-recovery completion"
    )
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility_plans: list[dict[str, object]] = []
    metric_completion_markers: list[dict[str, object]] = []
    revision_strata: dict[str, list[str]] = {}
    revision_by_lane: dict[str, str] = {}
    sources: set[str] = set()
    total_successful = 0
    total_missing = 0

    for unit_id, source_lane, corpus, selected_records in UNIT_LAYOUT:
        if unit_id == FAILED_UNIT:
            continue
        validated = _validate_metric_result(
            failed_results.get(unit_id),
            logical_lane=unit_id,
            physical_unit=unit_id,
            source_lane=source_lane,
            corpus=corpus,
            selected_records=selected_records,
            runner_root=runner_root,
            control_root=failed_root,
            state_schema="ura-vllm-stability-phase6-unit-state/1",
            completion=failed_completion_descriptor,
        )
        revision = str(validated["revision"])
        revision_strata.setdefault(revision, []).append(unit_id)
        revision_by_lane[unit_id] = revision
        sources.add(str(validated["source"]))
        metric_roots[unit_id] = str(validated["root"])
        metric_evidence[unit_id] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_eligibility_plans.append(dict(validated["eligibility_plan"]))
        metric_completion_markers.extend(validated["completion_markers"])
        total_successful += int(validated["successful"])
        total_missing += int(validated["missing"])

    recovery_validated = _validate_metric_result(
        recovery_results.get(RECOVERY_UNIT),
        logical_lane=FAILED_UNIT,
        physical_unit=RECOVERY_UNIT,
        source_lane=SOURCE_LANE,
        corpus=CORPUS,
        selected_records=RECOVERY_RECORDS,
        runner_root=runner_root,
        control_root=recovery_control_root,
        state_schema="ura-vllm-input-recovery-phase6-unit-state/1",
        completion=recovery_descriptor,
    )
    recovery_revision = str(recovery_validated["revision"])
    recovery_source = str(recovery_validated["source"])
    recovery_state_path = _validate_descriptor(
        recovery_results[RECOVERY_UNIT]["state"],
        label="GPTGeoChat recovery state",
    )
    recovery_argv = _load_json(
        recovery_state_path, label="GPTGeoChat recovery state"
    )["runner_argv"]
    if (
        _option(recovery_argv, "--recovery-completed-prefix")
        != str(recovery_selection_path)
        or _option(recovery_argv, "--recovery-completed-prefix-sha256")
        != str(recovery_completion["recovery_selection"]["sha256"])
    ):
        raise ValueError("GPTGeoChat recovery argv selection changed")
    if recovery_revision in revision_strata or len(revision_strata) != 1:
        raise ValueError("vLLM failed and recovery revisions are not separate")
    revision_strata[recovery_revision] = [FAILED_UNIT]
    revision_by_lane[FAILED_UNIT] = recovery_revision
    sources.add(recovery_source)
    metric_roots[FAILED_UNIT] = str(recovery_validated["root"])
    metric_evidence[FAILED_UNIT] = dict(recovery_validated["evidence"])
    metric_grids.append(dict(recovery_validated["grid"]))
    metric_eligibility_plans.append(dict(recovery_validated["eligibility_plan"]))
    metric_completion_markers.extend(recovery_validated["completion_markers"])
    total_successful += int(recovery_validated["successful"])
    total_missing += int(recovery_validated["missing"])

    target_execution = recovery_completion.get("target_execution")
    if (
        target_execution
        != {
            "target_attempts": RECOVERY_RECORDS,
            "successful_target_generations": recovery_validated["successful"],
            "missing_responses": recovery_validated["missing"],
        }
        or len(sources) != 1
    ):
        raise ValueError("vLLM input-recovery aggregate accounting changed")
    logical_order = [row[0] for row in UNIT_LAYOUT]
    metric_target_attempts = sum(
        row[3] for row in UNIT_LAYOUT if row[0] != FAILED_UNIT
    ) + RECOVERY_RECORDS
    if total_successful + total_missing != metric_target_attempts:
        raise ValueError("vLLM Phase 7 metric coverage changed")
    return {
        "completion": failed_completion_descriptor,
        "input_recovery_completion": recovery_descriptor,
        "runner_code_version": "ura-runner/2.25+ura-runner/2.26",
        "output_policy_stratum": (
            "runner_225_completed_units_plus_runner_226_input_recovery"
        ),
        "unit_order": logical_order,
        "terminal_states": {lane: "measured_complete" for lane in logical_order},
        "lifecycle_transitions": {
            FAILED_UNIT: [
                "runner_225_failed_after_375_durable_rows",
                "runner_226_missing_only_suffix_complete",
            ]
        },
        "failed_prefix_lifecycle": {
            "physical_unit_id": FAILED_UNIT,
            "durable_rows": COMPLETED_PREFIX_RECORDS,
            "result_root": str(failed_prefix_root),
            "included_in_metric_evidence": False,
            "pooling_with_recovery_permitted": False,
        },
        "metric_lane_order": logical_order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility_plans,
        "metric_completion_markers": metric_completion_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": revision_by_lane,
        "project_revision_receipt_sha256": next(iter(revision_strata)),
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": {
            "target_attempts": metric_target_attempts,
            "successful_target_generations": total_successful,
            "missing_responses": total_missing,
        },
        "cross_output_policy_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if CODE_VERSION != "ura-runner/2.26":
        raise ValueError("GPTGeoChat input recovery requires Runner 2.26")
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh GPTGeoChat recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("control root must be a direct engineering campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    failed, failed_root = validate_failed_completion(
        args.failed_completion,
        args.failed_completion_sha256,
    )
    prefix, old_result_root = build_recovery_prefix(failed_root)
    historical_path = _validate_descriptor(
        failed["historical_completion"],
        label="recovery historical completion",
    )
    historical = _load_json(historical_path, label="recovery historical completion")
    specs = _historical_specs(historical)
    unit = Unit(
        RECOVERY_UNIT,
        SOURCE_LANE,
        CORPUS,
        specs[SOURCE_LANE],
        RECOVERY_RECORDS,
        prefix,
    )

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    prefix_path = control_root / "inputs/gptgeochat-completed-prefix.json"
    _create_json(prefix_path, prefix)
    prefix_sha = hashlib.sha256(prefix_path.read_bytes()).hexdigest()
    launch = {
        "schema": "ura-vllm-input-recovery-phase6-launch/1",
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "failed_completion": _descriptor(
            args.failed_completion,
            label="failed vLLM stability completion",
        ),
        "retained_prefix_result_root": str(old_result_root),
        "recovery_selection": _descriptor(
            prefix_path,
            label="GPTGeoChat recovery prefix",
        ),
        "unit_order": [RECOVERY_UNIT],
        "no_completed_rows_repeated": True,
        "cross_runner_or_input_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_vllm_input_recovery",
        hard_stop_hours=168,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    try:
        results[RECOVERY_UNIT] = _run_unit(
            unit,
            python=python,
            work_root=work_root,
            control_root=control_root,
            project_revision=project_revision,
            project_revision_sha256=args.project_revision_sha256,
            scope=args.execution_scope_id,
            recovery_path=prefix_path,
            recovery_sha256=prefix_sha,
            expected_commit=args.expected_commit,
            framework_lock_id=_framework_lock_id(),
            admission_sha256=_gate5_manifest_sha256(unit.spec),
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            state_schema="ura-vllm-input-recovery-phase6-unit-state/1",
        )
    except (
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        failures[RECOVERY_UNIT] = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc)[:4000],
        }
    result = results.get(RECOVERY_UNIT, {})
    attempted = int(result.get("target_attempts", 0))
    successful = int(result.get("successful_target_generations", 0))
    missing = int(result.get("missing_responses", 0))
    status = "complete" if not failures else "complete_with_failures"
    completion = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "failed_completion": launch["failed_completion"],
        "recovery_selection": launch["recovery_selection"],
        "unit_order": [RECOVERY_UNIT],
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "input_compatibility_accounting": (
            "typed_missing_response_without_retry_or_policy_judge"
        ),
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_runner_or_input_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "completion.json", completion)
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{completion['controller_exit_code']}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=attempted,
        successful_target_generations=successful,
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=int(completion["controller_exit_code"]),
    )
    return int(completion["controller_exit_code"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--project-revision", type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--failed-completion", type=Path, required=True)
    parser.add_argument("--failed-completion-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", required=True)
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    if HEX64.fullmatch(args.failed_completion_sha256) is None:
        raise ValueError("failed completion SHA-256 is invalid")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
