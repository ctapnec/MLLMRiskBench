"""Continue only the never-executed DeepSeek failed-output recovery unit.

The first six-unit recovery completed five units, then rejected DeepSeek-R1
during live attestation because that reasoning model was incorrectly bound with
``think=false``. This controller validates and retains those five completed
unit results, changes no selector, and executes only the 1,674-row DeepSeek
unit with the corrected explicit thinking policy.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_BY_SPEC,
    CURRENT_OLLAMA_NUM_CTX,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _descriptor,
    _stable_file,
)
from experiments.local_campaign.failed_output_recovery_phase6 import (
    DEEPSEEK_UNIT,
    EXPECTED_RECOVERY_COUNTS,
    EXPECTED_RECOVERY_ROWS,
    EXPECTED_UNIT_ORDER,
    HEX40,
    HEX64,
    LAUNCH_SCHEMA as PRIOR_LAUNCH_SCHEMA,
    ORIGINAL_UNIT_ORDER,
    SCHEMA as PRIOR_SCHEMA,
    SNAPSHOT_SCHEMA as PRIOR_SNAPSHOT_SCHEMA,
    UNIT_STATE_SCHEMA,
    _durable_outcomes,
    _prepare_units,
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _validate_descriptor,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-failed-output-recovery-phase6/3"
LAUNCH_SCHEMA = "ura-failed-output-recovery-continuation-phase6-launch/2"
SNAPSHOT_SCHEMA = "ura-failed-output-recovery-continuation-input-snapshot/1"
DEEPSEEK_CONTINUATION_NUM_PREDICT = 2_048
DEEPSEEK_PHYSICAL_UNIT = EXPECTED_UNIT_ORDER[4]
RETAINED_UNIT_ORDER = EXPECTED_UNIT_ORDER[:4] + EXPECTED_UNIT_ORDER[5:]
CONTINUATION_UNIT_ORDER = (DEEPSEEK_PHYSICAL_UNIT,)
PRIOR_TARGET_EXECUTION = {
    "target_attempts": 2_139,
    "successful_target_generations": 2_083,
    "missing_responses": 56,
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_control_root(path: Path, *, label: str) -> Path:
    root = path.parent
    if (
        root.is_symlink()
        or root.resolve(strict=True) != root
        or root.parent.name != "engineering"
    ):
        raise ValueError(f"{label} control root is not canonical")
    return root


def _validate_prior_completion(
    completion_path: Path,
    *,
    completion_sha256: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Path]:
    resolved = completion_path.resolve(strict=True)
    if completion_sha256 is not None:
        if HEX64.fullmatch(completion_sha256) is None or hashlib.sha256(
            _stable_file(resolved, label="prior failed-output completion")
        ).hexdigest() != completion_sha256:
            raise ValueError("prior failed-output completion digest changed")
    completion = _load_json(resolved, label="prior failed-output completion")
    expected_fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "launch",
        "input_snapshot",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "successful_rows_repeated",
        "input_incompatible_rows_retried",
        "cross_revision_pooling_permitted",
        "paid_provider_calls",
    }
    results = completion.get("unit_results")
    failures = completion.get("unit_failures")
    if (
        set(completion) != expected_fields
        or completion.get("schema") != PRIOR_SCHEMA
        or completion.get("status") != "complete_with_failures"
        or completion.get("controller_exit_code") != 1
        or completion.get("runner_code_version") != "ura-runner/2.27"
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_order") != list(EXPECTED_UNIT_ORDER)
        or not isinstance(results, dict)
        or set(results) != set(RETAINED_UNIT_ORDER)
        or not isinstance(failures, dict)
        or set(failures) != {DEEPSEEK_PHYSICAL_UNIT}
        or completion.get("target_execution") != PRIOR_TARGET_EXECUTION
        or completion.get("successful_rows_repeated") != 0
        or completion.get("input_incompatible_rows_retried") != 0
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("prior failed-output terminal partition changed")
    failure = failures[DEEPSEEK_PHYSICAL_UNIT]
    if (
        not isinstance(failure, dict)
        or failure.get("unit_id") != DEEPSEEK_PHYSICAL_UNIT
        or failure.get("original_unit_id") != DEEPSEEK_UNIT
        or failure.get("status") != "failed"
    ):
        raise ValueError("prior DeepSeek failure identity changed")

    control_root = _canonical_control_root(
        resolved, label="prior failed-output recovery"
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="prior failed-output launch"
    )
    snapshot_path = _validate_descriptor(
        completion.get("input_snapshot"), label="prior failed-output snapshot"
    )
    launch = _load_json(launch_path, label="prior failed-output launch")
    snapshot = _load_json(snapshot_path, label="prior failed-output snapshot")
    if (
        launch_path != control_root / "launch.json"
        or snapshot_path != control_root / "input-snapshot.json"
        or launch.get("schema") != PRIOR_LAUNCH_SCHEMA
        or launch.get("runner_code_version") != "ura-runner/2.27"
        or launch.get("target_answer_retries") != 1
        or launch.get("unit_order") != list(EXPECTED_UNIT_ORDER)
        or launch.get("recovery_records") != EXPECTED_RECOVERY_ROWS
        or snapshot.get("schema") != PRIOR_SNAPSHOT_SCHEMA
        or snapshot.get("recovery_records") != EXPECTED_RECOVERY_ROWS
        or not isinstance(snapshot.get("units"), dict)
        or set(snapshot["units"]) != set(EXPECTED_UNIT_ORDER)
    ):
        raise ValueError("prior failed-output launch or snapshot changed")
    return completion, launch, snapshot, control_root


def _revision_map(
    validated: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, list[str]], dict[str, str]]:
    strata: dict[str, list[str]] = {}
    by_lane: dict[str, str] = {}
    if set(validated) - set(EXPECTED_UNIT_ORDER):
        raise ValueError("failed-output metric revision inventory changed")
    for lane in EXPECTED_UNIT_ORDER:
        if lane not in validated:
            continue
        revision = str(validated[lane]["revision"])
        strata.setdefault(revision, []).append(lane)
        by_lane[lane] = revision
    return strata, by_lane


def _partial_durable_counts(
    *,
    work_root: Path,
    control_root: Path,
) -> tuple[int, int, int]:
    """Count checkpointed logical rows when Runner exits before Level 1."""

    state_path = control_root / "units" / DEEPSEEK_PHYSICAL_UNIT / "state.json"
    if not state_path.exists():
        return 0, 0, 0
    state = _load_json(state_path, label="partial DeepSeek unit state")
    expected_root = (
        work_root
        / "runs/thesis/runner"
        / DEEPSEEK_PHYSICAL_UNIT
        / control_root.name
    )
    result_root = Path(str(state.get("result_root", "")))
    if (
        state.get("schema") != UNIT_STATE_SCHEMA
        or state.get("unit_id") != DEEPSEEK_PHYSICAL_UNIT
        or state.get("selected_records") != EXPECTED_RECOVERY_COUNTS[4]
        or state.get("target_answer_retries") != 1
        or not result_root.is_absolute()
        or result_root.is_symlink()
        or result_root.resolve(strict=True) != expected_root.resolve(strict=True)
    ):
        raise ValueError("partial DeepSeek unit state changed")
    attempts, outcomes, _attempt_files, _response_files = _durable_outcomes(
        result_root
    )
    allowed = {
        "usable_first_response",
        "recovered_after_retry",
        "failed_output",
        "input_incompatible",
    }
    if any(status not in allowed for status in outcomes.values()):
        raise ValueError("partial DeepSeek outcome has an unsupported terminal status")
    attempted = len(attempts)
    if attempted > EXPECTED_RECOVERY_COUNTS[4]:
        raise ValueError("partial DeepSeek outcome count exceeds its selection")
    missing = sum(
        status in {"failed_output", "input_incompatible"}
        for status in outcomes.values()
    )
    return attempted, attempted - missing, missing


def _create_deepseek_generation_condition(
    *,
    control_root: Path,
) -> dict[str, object]:
    """Bind the separately calibrated DeepSeek completion allowance."""

    model = CURRENT_OLLAMA_BY_SPEC[
        "ollama:deepseek-r1:32b-qwen-distill-q4_K_M"
    ]
    if model.label != "deepseek-r1-distill-32b" or model.think is not True:
        raise ValueError("DeepSeek continuation model condition changed")
    config_path = control_root / "configs" / f"{model.label}.json"
    _create_json(
        config_path,
        {
            model.spec: {
                "digest": model.digest,
                "modalities": list(model.modalities),
                "num_ctx": CURRENT_OLLAMA_NUM_CTX,
                "num_predict": DEEPSEEK_CONTINUATION_NUM_PREDICT,
                "think": True,
            }
        },
    )
    config = _descriptor(config_path, label="DeepSeek continuation local config")
    return {
        "local_config": config,
        "num_ctx": CURRENT_OLLAMA_NUM_CTX,
        "num_predict": DEEPSEEK_CONTINUATION_NUM_PREDICT,
        "think": True,
    }


def _validate_partial_phase7_completion(
    resolved: Path, *, runner_root: Path, completion: Mapping[str, Any]
) -> dict[str, Any]:
    """Read the retained /2 interruption without promoting its partial grid."""

    control_root = _canonical_control_root(resolved, label="partial recovery")
    prior_path = _validate_descriptor(
        completion.get("prior_completion"), label="prior failed-output completion"
    )
    prior, _prior_launch, prior_snapshot, prior_root = _validate_prior_completion(
        prior_path
    )
    if (
        set(completion) != set(prior) | {
            "prior_completion", "retained_unit_order", "continuation_unit_order"
        }
        or completion.get("schema") != "ura-failed-output-recovery-phase6/2"
        or completion.get("status") != "complete_with_failures"
        or completion.get("controller_exit_code") != 1
        or completion.get("expected_commit")
        != "50175d37e1ab28cc10722eb08d765debac3d0eaa"
        or completion.get("retained_unit_order") != list(RETAINED_UNIT_ORDER)
        or completion.get("continuation_unit_order") != list(CONTINUATION_UNIT_ORDER)
        or any(completion.get(key) != prior[key] for key in (
            "runner_code_version", "target_answer_retries", "unit_order",
            "unit_results", "target_execution", "successful_rows_repeated",
            "input_incompatible_rows_retried", "cross_revision_pooling_permitted",
            "paid_provider_calls",
        ))
        or set(completion.get("unit_failures", {})) != {DEEPSEEK_PHYSICAL_UNIT}
    ):
        raise ValueError("partial failed-output completion contract changed")
    unit_root = control_root / "units" / DEEPSEEK_PHYSICAL_UNIT
    expected_failure = {
        "unit_id": DEEPSEEK_PHYSICAL_UNIT, "original_unit_id": DEEPSEEK_UNIT,
        "status": "failed", "error_type": "RuntimeError",
        "error": f"Runner exited 143; see {unit_root / 'measured.run.log'}",
    }
    if completion["unit_failures"][DEEPSEEK_PHYSICAL_UNIT] != expected_failure:
        raise ValueError("partial DeepSeek failure identity changed")
    launch_path = _validate_descriptor(completion["launch"], label="partial launch")
    snapshot_path = _validate_descriptor(
        completion["input_snapshot"], label="partial snapshot"
    )
    launch = _load_json(launch_path, label="partial launch")
    snapshot = _load_json(snapshot_path, label="partial snapshot")
    if (
        launch_path != control_root / "launch.json"
        or snapshot_path != control_root / "input-snapshot.json"
        or launch.get("schema")
        != "ura-failed-output-recovery-continuation-phase6-launch/1"
        or launch.get("expected_commit") != completion["expected_commit"]
        or launch.get("runner_code_version") != "ura-runner/2.27"
        or launch.get("target_answer_retries") != 1
        or launch.get("unit_order") != list(CONTINUATION_UNIT_ORDER)
        or launch.get("prior_completion") != completion["prior_completion"]
        or launch.get("input_snapshot") != completion["input_snapshot"]
        or launch.get("recovery_records") != EXPECTED_RECOVERY_COUNTS[4]
        or launch.get("successful_rows_repeated") != 0
        or launch.get("paid_provider_calls") != 0
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or snapshot.get("recovery_records") != EXPECTED_RECOVERY_COUNTS[4]
        or snapshot.get("successful_rows_repeated") != 0
        or snapshot.get("input_incompatible_rows_retried") != 0
        or snapshot.get("units") != {
            DEEPSEEK_PHYSICAL_UNIT: prior_snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
        }
    ):
        raise ValueError("partial failed-output launch or selection changed")
    revision_path = _validate_descriptor(
        launch.get("project_revision"), label="partial project revision"
    )
    revision = _load_json(revision_path, label="partial project revision")
    repository = revision.get("repository", {})
    if (
        revision.get("schema") != "ura-project-revision/1"
        or revision.get("status") != "complete"
        or repository.get("clean") is not True
        or repository.get("expected_commit") != completion["expected_commit"]
        or repository.get("observed_commit") != completion["expected_commit"]
    ):
        raise ValueError("partial failed-output project identity changed")
    prior_descriptor = _descriptor(prior_path, label="prior completion")
    validated = {
        lane: _validate_metric_result(
            prior["unit_results"][lane], physical_unit=lane,
            original_unit=original, selected_records=count,
            runner_root=runner_root, control_root=prior_root,
            completion=prior_descriptor,
        )
        for lane, original, count in zip(
            EXPECTED_UNIT_ORDER, ORIGINAL_UNIT_ORDER, EXPECTED_RECOVERY_COUNTS,
            strict=True,
        ) if lane in RETAINED_UNIT_ORDER
    }
    successful = sum(item["successful"] for item in validated.values())
    missing = sum(item["missing"] for item in validated.values())
    sources = {item["source"] for item in validated.values()}
    if (
        len(sources) != 1
        or {"target_attempts": successful + missing,
            "successful_target_generations": successful, "missing_responses": missing}
        != completion["target_execution"]
    ):
        raise ValueError("partial failed-output retained accounting changed")
    state_path = unit_root / "state.json"
    state = _load_json(state_path, label="partial DeepSeek state")
    state_argv = state.get("runner_argv")
    source = next(iter(sources))
    revision_sha = launch["project_revision"]["sha256"]
    if (
        not isinstance(state_argv, list)
        or any(not isinstance(item, str) for item in state_argv)
        or _option(state_argv, "--project-revision-sha256") != revision_sha
        or _option(state_argv, "--source-conformance-sha256") != source
        or _option(state_argv, "--target-answer-retries") != "1"
    ):
        raise ValueError("partial DeepSeek state stratum changed")
    attempted, partial_success, partial_missing = _partial_durable_counts(
        work_root=runner_root.parents[2], control_root=control_root
    )
    result_root = Path(state["result_root"])
    partial_evidence = {
        "state": _descriptor(state_path, label="partial DeepSeek state"),
        "launch": dict(completion["launch"]),
        "input_snapshot": dict(completion["input_snapshot"]),
        "project_revision": dict(launch["project_revision"]),
        "runner_files": [_descriptor(path, label="partial Runner file")
                         for path in sorted(result_root.rglob("*")) if path.is_file()],
        "failure": dict(expected_failure),
    }
    strata, revisions = _revision_map(validated)
    metric_roots = {lane: item["root"] for lane, item in validated.items()}
    metric_evidence = {lane: item["evidence"] for lane, item in validated.items()}
    return {
        "completion": _descriptor(resolved, label="partial recovery completion"),
        "runner_code_version": "ura-runner/2.27",
        "output_policy_stratum": "runner_227_failed_output_recovery",
        "unit_order": list(EXPECTED_UNIT_ORDER),
        "original_unit_order": list(ORIGINAL_UNIT_ORDER),
        "terminal_states": {lane: "partial" if lane == DEEPSEEK_PHYSICAL_UNIT
                            else "measured_complete" for lane in EXPECTED_UNIT_ORDER},
        "metric_lane_order": list(RETAINED_UNIT_ORDER),
        "metric_roots": metric_roots, "metric_evidence": metric_evidence,
        "lifecycle_roots": {**metric_roots, DEEPSEEK_PHYSICAL_UNIT: str(result_root)},
        "lifecycle_evidence": {**metric_evidence, DEEPSEEK_PHYSICAL_UNIT: partial_evidence},
        "lifecycle_project_revision_receipt_sha256": {
            **revisions, DEEPSEEK_PHYSICAL_UNIT: revision_sha
        },
        "metric_grids": [item["grid"] for item in validated.values()],
        "metric_eligibility_plans": [item["eligibility_plan"] for item in validated.values()],
        "metric_completion_markers": [marker for item in validated.values()
                                      for marker in item["completion_markers"]],
        "revision_strata": strata,
        "metric_project_revision_receipt_sha256": revisions,
        "project_revision_receipt_sha256": revision_sha,
        "source_conformance_sha256": source,
        "source_target_execution": dict(completion["target_execution"]),
        "target_execution": {
            "target_attempts": successful + missing + attempted,
            "successful_target_generations": successful + partial_success,
            "missing_responses": missing + partial_missing,
        },
        "successful_rows_repeated": 0, "input_incompatible_rows_retried": 0,
        "cross_revision_pooling_permitted": False,
    }


def validate_phase7_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the combined five-retained plus one-continuation result."""

    resolved = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    completion = _load_json(resolved, label="continued failed-output completion")
    if completion.get("schema") == "ura-failed-output-recovery-phase6/2":
        return _validate_partial_phase7_completion(
            resolved, runner_root=runner_root, completion=completion
        )
    expected_fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "generation_condition",
        "prior_completion",
        "launch",
        "input_snapshot",
        "unit_order",
        "retained_unit_order",
        "continuation_unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "successful_rows_repeated",
        "input_incompatible_rows_retried",
        "cross_revision_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(completion) != expected_fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != "ura-runner/2.27"
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_order") != list(EXPECTED_UNIT_ORDER)
        or completion.get("retained_unit_order") != list(RETAINED_UNIT_ORDER)
        or completion.get("continuation_unit_order")
        != list(CONTINUATION_UNIT_ORDER)
        or completion.get("unit_failures") != {}
        or completion.get("successful_rows_repeated") != 0
        or completion.get("input_incompatible_rows_retried") != 0
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("continued failed-output completion contract changed")
    control_root = _canonical_control_root(
        resolved, label="continued failed-output recovery"
    )
    prior_path = _validate_descriptor(
        completion.get("prior_completion"), label="prior failed-output completion"
    )
    prior, _prior_launch, prior_snapshot, prior_root = _validate_prior_completion(
        prior_path
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="failed-output continuation launch"
    )
    snapshot_path = _validate_descriptor(
        completion.get("input_snapshot"),
        label="failed-output continuation snapshot",
    )
    launch = _load_json(launch_path, label="failed-output continuation launch")
    snapshot = _load_json(
        snapshot_path, label="failed-output continuation snapshot"
    )
    condition = completion.get("generation_condition")
    if not isinstance(condition, dict) or set(condition) != {
        "local_config",
        "num_ctx",
        "num_predict",
        "think",
    }:
        raise ValueError("DeepSeek continuation generation condition changed")
    config_path = _validate_descriptor(
        condition["local_config"], label="DeepSeek continuation local config"
    )
    model = CURRENT_OLLAMA_BY_SPEC[
        "ollama:deepseek-r1:32b-qwen-distill-q4_K_M"
    ]
    expected_config = {
        model.spec: {
            "digest": model.digest,
            "modalities": list(model.modalities),
            "num_ctx": CURRENT_OLLAMA_NUM_CTX,
            "num_predict": DEEPSEEK_CONTINUATION_NUM_PREDICT,
            "think": True,
        }
    }
    if (
        condition.get("num_ctx") != CURRENT_OLLAMA_NUM_CTX
        or condition.get("num_predict") != DEEPSEEK_CONTINUATION_NUM_PREDICT
        or condition.get("think") is not True
        or config_path
        != control_root / "configs" / f"{model.label}.json"
        or _load_json(config_path, label="DeepSeek continuation local config")
        != expected_config
    ):
        raise ValueError("DeepSeek continuation local config changed")
    if (
        launch_path != control_root / "launch.json"
        or snapshot_path != control_root / "input-snapshot.json"
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("runner_code_version") != "ura-runner/2.27"
        or launch.get("target_answer_retries") != 1
        or launch.get("generation_condition") != condition
        or launch.get("prior_completion") != completion["prior_completion"]
        or launch.get("unit_order") != list(CONTINUATION_UNIT_ORDER)
        or launch.get("recovery_records") != EXPECTED_RECOVERY_COUNTS[4]
        or launch.get("successful_rows_repeated") != 0
        or launch.get("paid_provider_calls") != 0
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or snapshot.get("recovery_records") != EXPECTED_RECOVERY_COUNTS[4]
        or snapshot.get("successful_rows_repeated") != 0
        or set(snapshot.get("units", {})) != {DEEPSEEK_PHYSICAL_UNIT}
        or snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
        != prior_snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
    ):
        raise ValueError("failed-output continuation launch or snapshot changed")

    results = completion.get("unit_results")
    prior_results = prior["unit_results"]
    if (
        not isinstance(results, dict)
        or set(results) != set(EXPECTED_UNIT_ORDER)
        or any(results[lane] != prior_results[lane] for lane in RETAINED_UNIT_ORDER)
    ):
        raise ValueError("retained failed-output results changed")
    completion_descriptor = _descriptor(
        resolved, label="continued failed-output completion"
    )
    prior_descriptor = _descriptor(prior_path, label="prior failed-output completion")
    validated: dict[str, dict[str, Any]] = {}
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility_plans: list[dict[str, object]] = []
    metric_completion_markers: list[dict[str, object]] = []
    successful = 0
    missing = 0
    sources: set[str] = set()
    for physical, original, selected in zip(
        EXPECTED_UNIT_ORDER,
        ORIGINAL_UNIT_ORDER,
        EXPECTED_RECOVERY_COUNTS,
        strict=True,
    ):
        source_snapshot = (
            snapshot["units"][physical]
            if physical == DEEPSEEK_PHYSICAL_UNIT
            else prior_snapshot["units"][physical]
        )
        summary = (
            source_snapshot.get("summary")
            if isinstance(source_snapshot, dict)
            else None
        )
        if (
            not isinstance(source_snapshot, dict)
            or source_snapshot.get("original_unit_id") != original
            or not isinstance(summary, dict)
            or summary.get("recovery_records") != selected
        ):
            raise ValueError(f"{physical} combined input snapshot changed")
        item = _validate_metric_result(
            results[physical],
            physical_unit=physical,
            original_unit=original,
            selected_records=selected,
            runner_root=runner_root,
            control_root=(
                control_root if physical == DEEPSEEK_PHYSICAL_UNIT else prior_root
            ),
            completion=(
                completion_descriptor
                if physical == DEEPSEEK_PHYSICAL_UNIT
                else prior_descriptor
            ),
        )
        validated[physical] = item
        sources.add(str(item["source"]))
        metric_roots[physical] = str(item["root"])
        metric_evidence[physical] = dict(item["evidence"])
        metric_grids.append(dict(item["grid"]))
        metric_eligibility_plans.append(dict(item["eligibility_plan"]))
        metric_completion_markers.extend(item["completion_markers"])
        successful += int(item["successful"])
        missing += int(item["missing"])
    deepseek_state_path = _validate_descriptor(
        results[DEEPSEEK_PHYSICAL_UNIT]["state"],
        label="DeepSeek continuation state",
    )
    deepseek_state = _load_json(
        deepseek_state_path, label="DeepSeek continuation state"
    )
    deepseek_argv = deepseek_state.get("runner_argv")
    if (
        not isinstance(deepseek_argv, list)
        or any(not isinstance(item, str) for item in deepseek_argv)
        or _option(deepseek_argv, "--local-config") != str(config_path)
        or _option(deepseek_argv, "--local-config-sha256")
        != condition["local_config"]["sha256"]
    ):
        raise ValueError("DeepSeek continuation state lost its generation condition")
    target_execution = completion.get("target_execution")
    if (
        target_execution
        != {
            "target_attempts": EXPECTED_RECOVERY_ROWS,
            "successful_target_generations": successful,
            "missing_responses": missing,
        }
        or successful + missing != EXPECTED_RECOVERY_ROWS
        or len(sources) != 1
    ):
        raise ValueError("continued failed-output aggregate accounting changed")
    revision_strata, revision_by_lane = _revision_map(validated)
    return {
        "completion": completion_descriptor,
        "runner_code_version": "ura-runner/2.27",
        "output_policy_stratum": "runner_227_failed_output_recovery",
        "unit_order": list(EXPECTED_UNIT_ORDER),
        "original_unit_order": list(ORIGINAL_UNIT_ORDER),
        "terminal_states": {
            unit: "measured_complete" for unit in EXPECTED_UNIT_ORDER
        },
        "metric_lane_order": list(EXPECTED_UNIT_ORDER),
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility_plans,
        "metric_completion_markers": metric_completion_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": revision_by_lane,
        "project_revision_receipt_sha256": revision_by_lane[
            DEEPSEEK_PHYSICAL_UNIT
        ],
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": dict(target_execution),
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
        "cross_revision_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if CODE_VERSION != "ura-runner/2.27":
        raise ValueError("failed-output continuation requires Runner 2.27")
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh failed-output continuation root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("failed-output continuation root must be one direct campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    prior_path = args.prior_completion.resolve(strict=True)
    prior, _prior_launch, prior_snapshot, _prior_root = _validate_prior_completion(
        prior_path, completion_sha256=args.prior_completion_sha256
    )

    control_root.mkdir(mode=0o700)
    for name in ("units", "inputs", "configs"):
        (control_root / name).mkdir(mode=0o700)
    generation_condition = _create_deepseek_generation_condition(
        control_root=control_root
    )
    prepared = _prepare_units(
        args,
        work_root=work_root,
        control_root=control_root,
        only_original_units=(DEEPSEEK_UNIT,),
    )
    if (
        len(prepared) != 1
        or prepared[0][0].unit_id != DEEPSEEK_PHYSICAL_UNIT
        or prepared[0][0].selected_records != EXPECTED_RECOVERY_COUNTS[4]
        or prepared[0][5] != DEEPSEEK_UNIT
        or {
            "original_unit_id": prepared[0][5],
            **prepared[0][3],
        }
        != prior_snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
    ):
        raise ValueError("DeepSeek-only continuation selection changed")
    unit, selector, selector_sha, source_snapshot, hub_required, original = prepared[0]
    local = _option(unit.spec["base_argv"], "--local")
    model = CURRENT_OLLAMA_BY_SPEC.get(local)
    if (
        model is None
        or model.label != "deepseek-r1-distill-32b"
        or model.think is not True
        or _option(unit.spec["base_argv"], "--local-config")
        != generation_condition["local_config"]["path"]
        or _option(unit.spec["base_argv"], "--local-config-sha256")
        != generation_condition["local_config"]["sha256"]
    ):
        raise ValueError("DeepSeek continuation thinking policy changed")

    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "created_at_utc": _utc_now(),
        "units": {
            DEEPSEEK_PHYSICAL_UNIT: {
                "original_unit_id": original,
                **source_snapshot,
            }
        },
        "recovery_records": EXPECTED_RECOVERY_COUNTS[4],
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
    }
    snapshot_path = control_root / "input-snapshot.json"
    _create_json(snapshot_path, snapshot)
    prior_descriptor = _descriptor(
        prior_path, label="prior failed-output completion"
    )
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "generation_condition": generation_condition,
        "prior_completion": prior_descriptor,
        "project_revision": _descriptor(
            project_revision, label="continuation project revision"
        ),
        "input_snapshot": _descriptor(
            snapshot_path, label="continuation input snapshot"
        ),
        "unit_order": list(CONTINUATION_UNIT_ORDER),
        "recovery_records": EXPECTED_RECOVERY_COUNTS[4],
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
    }
    launch_path = control_root / "launch.json"
    _create_json(launch_path, launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_failed_output_recovery_continuation",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    result: dict[str, Any] | None = None
    failure: dict[str, Any] | None = None
    try:
        measured = _run_unit(
            unit,
            python=python,
            work_root=work_root,
            control_root=control_root,
            project_revision=project_revision,
            project_revision_sha256=args.project_revision_sha256,
            scope=args.execution_scope_id,
            recovery_path=selector,
            recovery_sha256=selector_sha,
            expected_commit=args.expected_commit,
            framework_lock_id=_framework_lock_id(),
            admission_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            state_schema=UNIT_STATE_SCHEMA,
            hub_acquisition_required=hub_required,
        )
        result = {**measured, "original_unit_id": original}
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        failure = {
            "status": "failed",
            "unit_id": DEEPSEEK_PHYSICAL_UNIT,
            "original_unit_id": DEEPSEEK_UNIT,
            "error_type": type(exc).__name__,
            "error": str(exc)[:4000],
        }

    results = dict(prior["unit_results"])
    failures: dict[str, Any] = {}
    continuation_attempts = 0
    continuation_successful = 0
    continuation_missing = 0
    if result is not None:
        results[DEEPSEEK_PHYSICAL_UNIT] = result
        continuation_attempts = int(result["target_attempts"])
        continuation_successful = int(result["successful_target_generations"])
        continuation_missing = int(result["missing_responses"])
    else:
        failures[DEEPSEEK_PHYSICAL_UNIT] = failure
        try:
            (
                continuation_attempts,
                continuation_successful,
                continuation_missing,
            ) = _partial_durable_counts(
                work_root=work_root,
                control_root=control_root,
            )
        except (OSError, TypeError, ValueError) as accounting_exc:
            if failure is not None:
                failure["durable_accounting_error_type"] = type(
                    accounting_exc
                ).__name__
                failure["durable_accounting_error"] = str(accounting_exc)[:4000]
    completion = {
        "schema": SCHEMA,
        "status": "complete" if not failures else "complete_with_failures",
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "generation_condition": generation_condition,
        "prior_completion": prior_descriptor,
        "launch": _descriptor(launch_path, label="failed-output continuation launch"),
        "input_snapshot": _descriptor(
            snapshot_path, label="failed-output continuation snapshot"
        ),
        "unit_order": list(EXPECTED_UNIT_ORDER),
        "retained_unit_order": list(RETAINED_UNIT_ORDER),
        "continuation_unit_order": list(CONTINUATION_UNIT_ORDER),
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": PRIOR_TARGET_EXECUTION["target_attempts"]
            + continuation_attempts,
            "successful_target_generations": PRIOR_TARGET_EXECUTION[
                "successful_target_generations"
            ]
            + continuation_successful,
            "missing_responses": PRIOR_TARGET_EXECUTION["missing_responses"]
            + continuation_missing,
        },
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
        "cross_revision_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    completion_path = control_root / "completion.json"
    _create_json(completion_path, completion)
    exit_code = int(completion["controller_exit_code"])
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{exit_code}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=continuation_attempts,
        successful_target_generations=continuation_successful,
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=exit_code,
    )
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-completion", type=Path, required=True)
    parser.add_argument("--prior-completion-sha256", required=True)
    parser.add_argument("--ollama-base-completion", type=Path, required=True)
    parser.add_argument("--ollama-base-completion-sha256", required=True)
    parser.add_argument("--ollama-interrupted-root", type=Path, required=True)
    parser.add_argument("--vllm-failed-completion", type=Path, required=True)
    parser.add_argument("--vllm-failed-completion-sha256", required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--project-revision", type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", default="default")
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"failed-output continuation failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
