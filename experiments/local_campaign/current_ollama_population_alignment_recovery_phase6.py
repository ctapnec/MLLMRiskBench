"""Continue only never-started Ollama population-alignment units.

The base completion and every successful unit remain immutable. This controller
accepts the exact failed partition, the interrupted failed-output continuation,
and the terminal hardware-fit correction that completes its DeepSeek selection.
It then runs only the four R-Judge and two GPTGeoChat units that never started.
No completed or DeepSeek row is scheduled again.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
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
from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_BY_SPEC,
    PROSPECTIVE_OLLAMA_NUM_CTX,
)
from experiments.local_campaign.current_ollama_population_alignment_phase6 import (
    ALIGNMENT_LANES,
    EXPECTED_EXTENSION_ROWS,
    RUNNER_CODE_VERSION as BASE_RUNNER_CODE_VERSION,
    SCHEMA as BASE_SCHEMA,
    _validate_prefix_complete,
    build_alignment_units,
    hub_acquisition_required,
    validate_completion as validate_base_completion,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _replace_option,
    _run_unit,
    _validate_descriptor,
)
from experiments.local_model_profiles import apply_profile
from ura.request_envelope import load_request_envelope_file
from ura.runner import CODE_VERSION


SCHEMA = "ura-current-ollama-population-alignment-recovery-phase6/5"
LAUNCH_SCHEMA = (
    "ura-current-ollama-population-alignment-recovery-phase6-launch/5"
)
UNIT_STATE_SCHEMA = (
    "ura-current-ollama-population-alignment-recovery-phase6-unit-state/5"
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FAILED_OUTPUT_COVERED_LANE = (
    "ollama-deepseek-r1-distill-32b-text-primary-100-extension"
)
CONTINUATION_LANES = tuple(
    lane
    for lane in ALIGNMENT_LANES
    if lane.startswith(("rjudge-ollama-", "gptgeochat-ollama-"))
)
EXPECTED_CONTINUATION_ROWS = 2_350
EXPECTED_DEEPSEEK_COVERAGE = {
    "selected_records": 3_854,
    "prior_eligible_records": 1_909,
    "durable_outcomes": 888,
    "failed_output_records": 653,
    "input_incompatible_records": 0,
    "never_attempted_records": 1_021,
    "recovery_records": 1_674,
    "completed_records_excluded": 2_180,
}
EXPECTED_HARDWARE_DEEPSEEK_COVERAGE = {
    "selected_records": 3_854,
    "prior_eligible_records": 1_674,
    "durable_outcomes": 785,
    "failed_output_records": 14,
    "length_ended_records": 28,
    "never_attempted_records": 889,
    "recovery_records": 931,
    "completed_records_excluded": 2_923,
    "outcome_counts": {
        "failed_output": 14,
        "recovered_after_retry": 15,
        "usable_first_response": 756,
    },
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_inputs(
    completion_path: Path,
    *,
    runner_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[Any]]:
    snapshot = validate_base_completion(
        completion_path,
        runner_root=runner_root,
        allow_incomplete=True,
    )
    completion = _load_json(
        completion_path, label="failed Ollama population-alignment completion"
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="failed Ollama alignment launch"
    )
    launch = _load_json(launch_path, label="failed Ollama alignment launch")
    gate5_path = _validate_descriptor(
        launch.get("gate5"), label="retained Ollama Gate 5"
    )
    stability_path = _validate_descriptor(
        launch.get("stability_completion"),
        label="retained Ollama stability completion",
    )
    gate5, _stability = _validate_prefix_complete(
        gate5_path=gate5_path,
        stability_path=stability_path,
        runner_root=runner_root,
    )
    units = list(build_alignment_units(gate5))
    if [item.unit.unit_id for item in units] != list(ALIGNMENT_LANES):
        raise ValueError("Ollama population-alignment recovery unit order changed")
    return snapshot, completion, launch, units


def _selected_failed_lanes(
    snapshot: Mapping[str, Any], *, covered_lanes: Sequence[str] = ()
) -> list[str]:
    terminal = snapshot.get("terminal_states")
    if not isinstance(terminal, dict):
        raise ValueError("failed alignment terminal states changed")
    failed = [lane for lane in ALIGNMENT_LANES if terminal.get(lane) == "failed"]
    covered = list(covered_lanes)
    if len(set(covered)) != len(covered) or any(lane not in failed for lane in covered):
        raise ValueError("covered alignment-recovery lane inventory changed")
    selected = [lane for lane in failed if lane not in set(covered)]
    if not selected:
        raise ValueError("Ollama population-alignment recovery is unnecessary")
    return selected


def _failed_output_coverage(
    completion_path: Path,
    completion_sha256: str,
    hardware_fit_completion_path: Path,
    hardware_fit_completion_sha256: str,
    *,
    runner_root: Path,
) -> tuple[
    dict[str, Any],
    dict[str, object],
    dict[str, object],
    dict[str, int],
]:
    """Validate the interrupted recovery and its exact hardware-fit successor."""

    if HEX64.fullmatch(completion_sha256) is None:
        raise ValueError("failed-output recovery digest is malformed")
    resolved = completion_path.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(resolved, label="failed-output recovery completion")
    ).hexdigest() != completion_sha256:
        raise ValueError("failed-output recovery completion digest changed")

    # Imported lazily because failed_output_recovery_phase6 imports _base_inputs
    # from this module while deriving its immutable selectors.
    from experiments.local_campaign.failed_output_recovery_continuation_phase6 import (
        CONTINUATION_UNIT_ORDER,
        DEEPSEEK_PHYSICAL_UNIT,
        EXPECTED_RECOVERY_COUNTS,
        EXPECTED_UNIT_ORDER,
        ORIGINAL_UNIT_ORDER,
        RETAINED_UNIT_ORDER,
        _canonical_control_root,
        _validate_prior_completion,
    )
    from experiments.local_campaign.failed_output_recovery_phase6 import (
        DEEPSEEK_UNIT,
        _validate_metric_result as _validate_failed_output_metric_result,
    )
    from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
        validate_completion as validate_hardware_fit_completion,
    )

    completion = _load_json(resolved, label="interrupted failed-output completion")
    expected_fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
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
    failures = completion.get("unit_failures")
    control_root = _canonical_control_root(
        resolved, label="interrupted failed-output recovery"
    )
    expected_error = (
        "Runner exited 143; see "
        f"{control_root}/units/{DEEPSEEK_PHYSICAL_UNIT}/measured.run.log"
    )
    expected_failure = {
        "status": "failed",
        "unit_id": DEEPSEEK_PHYSICAL_UNIT,
        "original_unit_id": DEEPSEEK_UNIT,
        "error_type": "RuntimeError",
        "error": expected_error,
    }
    if (
        set(completion) != expected_fields
        or completion.get("schema") != "ura-failed-output-recovery-phase6/2"
        or completion.get("status") != "complete_with_failures"
        or completion.get("controller_exit_code") != 1
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != "ura-runner/2.27"
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_order") != list(EXPECTED_UNIT_ORDER)
        or completion.get("retained_unit_order") != list(RETAINED_UNIT_ORDER)
        or completion.get("continuation_unit_order")
        != list(CONTINUATION_UNIT_ORDER)
        or failures != {DEEPSEEK_PHYSICAL_UNIT: expected_failure}
        or completion.get("target_execution")
        != {
            "target_attempts": 2_139,
            "successful_target_generations": 2_083,
            "missing_responses": 56,
        }
        or completion.get("successful_rows_repeated") != 0
        or completion.get("input_incompatible_rows_retried") != 0
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("interrupted failed-output completion contract changed")

    prior_path = _validate_descriptor(
        completion.get("prior_completion"), label="prior failed-output completion"
    )
    prior, _prior_launch, prior_snapshot, prior_root = _validate_prior_completion(
        prior_path
    )
    prior_descriptor = _descriptor(
        prior_path, label="prior failed-output completion"
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="interrupted failed-output launch"
    )
    snapshot_path = _validate_descriptor(
        completion.get("input_snapshot"),
        label="interrupted failed-output snapshot",
    )
    launch = _load_json(launch_path, label="interrupted failed-output launch")
    snapshot = _load_json(
        snapshot_path, label="interrupted failed-output snapshot"
    )
    if (
        launch_path != control_root / "launch.json"
        or snapshot_path != control_root / "input-snapshot.json"
        or launch.get("schema")
        != "ura-failed-output-recovery-continuation-phase6-launch/1"
        or launch.get("runner_code_version") != "ura-runner/2.27"
        or launch.get("target_answer_retries") != 1
        or launch.get("prior_completion") != completion["prior_completion"]
        or launch.get("input_snapshot") != completion["input_snapshot"]
        or launch.get("unit_order") != list(CONTINUATION_UNIT_ORDER)
        or launch.get("recovery_records") != EXPECTED_RECOVERY_COUNTS[4]
        or launch.get("successful_rows_repeated") != 0
        or launch.get("paid_provider_calls") != 0
        or snapshot.get("schema")
        != "ura-failed-output-recovery-continuation-input-snapshot/1"
        or snapshot.get("recovery_records") != EXPECTED_RECOVERY_COUNTS[4]
        or snapshot.get("successful_rows_repeated") != 0
        or set(snapshot.get("units", {})) != {DEEPSEEK_PHYSICAL_UNIT}
        or snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
        != prior_snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
    ):
        raise ValueError("interrupted failed-output launch or snapshot changed")

    results = completion.get("unit_results")
    if (
        DEEPSEEK_UNIT != FAILED_OUTPUT_COVERED_LANE
        or ORIGINAL_UNIT_ORDER[4] != FAILED_OUTPUT_COVERED_LANE
        or EXPECTED_RECOVERY_COUNTS[4] != 1_674
        or not isinstance(results, dict)
        or set(results) != set(RETAINED_UNIT_ORDER)
        or any(results[unit_id] != prior["unit_results"][unit_id] for unit_id in RETAINED_UNIT_ORDER)
    ):
        raise ValueError("failed-output DeepSeek recovery identity changed")
    deepseek_snapshot = snapshot.get("units", {}).get(DEEPSEEK_PHYSICAL_UNIT)
    summary = (
        deepseek_snapshot.get("summary")
        if isinstance(deepseek_snapshot, dict)
        else None
    )
    if (
        not isinstance(summary, dict)
        or any(summary.get(key) != value for key, value in EXPECTED_DEEPSEEK_COVERAGE.items())
    ):
        raise ValueError("failed-output DeepSeek population coverage changed")

    retained_alignment = list(EXPECTED_UNIT_ORDER[:4])
    retained_successful = 0
    retained_missing = 0
    for physical in RETAINED_UNIT_ORDER:
        index = list(EXPECTED_UNIT_ORDER).index(physical)
        validated = _validate_failed_output_metric_result(
            results[physical],
            physical_unit=physical,
            original_unit=ORIGINAL_UNIT_ORDER[index],
            selected_records=EXPECTED_RECOVERY_COUNTS[index],
            runner_root=runner_root,
            control_root=prior_root,
            completion=prior_descriptor,
        )
        if physical in retained_alignment:
            retained_successful += int(validated["successful"])
            retained_missing += int(validated["missing"])
    if retained_successful != 2_083 or retained_missing != 36:
        raise ValueError("retained alignment recovery accounting changed")

    if HEX64.fullmatch(hardware_fit_completion_sha256) is None:
        raise ValueError("hardware-fit completion digest is malformed")
    hardware_path = hardware_fit_completion_path.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(hardware_path, label="hardware-fit completion")
    ).hexdigest() != hardware_fit_completion_sha256:
        raise ValueError("hardware-fit completion digest changed")
    hardware = validate_hardware_fit_completion(
        hardware_path, runner_root=runner_root
    )
    hardware_descriptor = _descriptor(
        hardware_path, label="hardware-fit completion"
    )
    hardware_document = _load_json(
        hardware_path, label="hardware-fit completion"
    )
    hardware_inventory_path = _validate_descriptor(
        hardware_document.get("inventory"), label="hardware-fit inventory"
    )
    hardware_inventory = _load_json(
        hardware_inventory_path, label="hardware-fit inventory"
    )
    hardware_units = hardware_inventory.get("units")
    hardware_order = hardware.get("unit_order")
    if (
        hardware_document.get("status") != "complete"
        or hardware_document.get("unit_failures") != {}
        or not isinstance(hardware_units, list)
        or len(hardware_units) != 25
        or not isinstance(hardware_order, list)
        or len(hardware_order) != 25
        or any(
            hardware.get("terminal_states", {}).get(unit_id)
            != "measured_complete"
            for unit_id in hardware_order
        )
    ):
        raise ValueError("hardware-fit completion is not fully successful")
    hardware_deepseek = hardware_units[0]
    hardware_deepseek_id = hardware_order[0]
    hardware_summary = (
        hardware_deepseek.get("summary")
        if isinstance(hardware_deepseek, dict)
        else None
    )
    hardware_result = hardware_document.get("unit_results", {}).get(
        hardware_deepseek_id
    )
    if (
        not isinstance(hardware_deepseek, dict)
        or hardware_deepseek.get("source_unit_id") != DEEPSEEK_PHYSICAL_UNIT
        or hardware_deepseek.get("source_lane") != FAILED_OUTPUT_COVERED_LANE
        or hardware_deepseek.get("local_spec")
        != "ollama:deepseek-r1:32b-qwen-distill-q4_K_M"
        or hardware_summary != EXPECTED_HARDWARE_DEEPSEEK_COVERAGE
        or not isinstance(hardware_result, dict)
        or hardware_result.get("target_attempts") != 931
    ):
        raise ValueError("hardware-fit DeepSeek coverage changed")
    hardware_successful = int(hardware_result["successful_target_generations"])
    hardware_missing = int(hardware_result["missing_responses"])
    if hardware_successful + hardware_missing != 931:
        raise ValueError("hardware-fit DeepSeek accounting changed")

    partial_successful = 771
    retained_partial_successful = 743
    alignment_successful = (
        retained_successful + retained_partial_successful + hardware_successful
    )
    alignment_missing = retained_missing + hardware_missing
    if alignment_successful + alignment_missing != 3_793:
        raise ValueError("combined alignment recovery coverage changed")
    coverage = {
        **EXPECTED_DEEPSEEK_COVERAGE,
        "prior_usable_records": 235,
        "base_failed_rows_replaced": 2_119,
        "alignment_recovery_rows": 3_793,
        "alignment_recovery_physical_attempts": 3_835,
        "alignment_recovery_successful_target_generations": alignment_successful,
        "alignment_recovery_missing_responses": alignment_missing,
        "partial_deepseek_successful_target_generations": partial_successful,
        "partial_deepseek_missing_responses": 14,
        "retained_partial_deepseek_successful_target_generations": (
            retained_partial_successful
        ),
        "hardware_fit_deepseek_successful_target_generations": hardware_successful,
        "hardware_fit_deepseek_missing_responses": hardware_missing,
        "hardware_fit_replayed_partial_rows": 42,
    }
    return (
        {
            "completion": _descriptor(
                resolved, label="interrupted failed-output completion"
            ),
            "hardware_fit_completion": hardware_descriptor,
            "project_revision_receipt_sha256": hardware[
                "metric_project_revision_receipt_sha256"
            ][hardware_deepseek_id],
        },
        _descriptor(resolved, label="interrupted failed-output completion"),
        hardware_descriptor,
        coverage,
    )


def _configured_unit(
    item: Any, *, control_root: Path, profile_registry: Path
) -> Any:
    """Bind thinking, hardware-fit context and the approved output profile."""

    base = list(item.unit.spec["base_argv"])
    local = _option(base, "--local")
    model = CURRENT_OLLAMA_BY_SPEC.get(local)
    if model is None:
        raise ValueError(f"{item.unit.unit_id}: current Ollama identity changed")
    config_path = control_root / "configs" / f"{model.label}.json"
    if not config_path.exists():
        unprofiled: dict[str, object] = {
            "digest": model.digest,
            "modalities": list(model.modalities),
            "num_ctx": PROSPECTIVE_OLLAMA_NUM_CTX,
            "think": model.think,
        }
        model_config, profile = apply_profile(
            model.spec, unprofiled, path=profile_registry
        )
        if profile is None:
            raise ValueError(
                f"{item.unit.unit_id}: current Ollama target has no readiness profile"
            )
        _create_json(
            config_path,
            {model.spec: model_config},
        )
    config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()
    base = _replace_option(base, "--local-config", str(config_path))
    base = _replace_option(base, "--local-config-sha256", config_sha)
    spec = {**item.unit.spec, "base_argv": base}
    return replace(item, unit=replace(item.unit, spec=spec))


def _combined_target_execution(
    *,
    base_execution: Mapping[str, object],
    coverage: Mapping[str, int],
    continuation_successful: int,
    continuation_missing: int,
) -> dict[str, int]:
    if base_execution != {
        "target_attempts": 7_341,
        "successful_target_generations": 5_222,
        "missing_responses": 2_119,
    }:
        raise ValueError("base population-alignment failed-output partition changed")
    final_successful = (
        5_222
        + continuation_successful
        + coverage["prior_usable_records"]
        + coverage["alignment_recovery_successful_target_generations"]
    )
    final_missing = (
        continuation_missing + coverage["alignment_recovery_missing_responses"]
    )
    actual_successful = (
        5_222
        + coverage["prior_usable_records"]
        + coverage["alignment_recovery_successful_target_generations"]
        + continuation_successful
        + coverage["partial_deepseek_successful_target_generations"]
        - coverage["retained_partial_deepseek_successful_target_generations"]
    )
    actual_missing = (
        2_119
        + 653
        + coverage["alignment_recovery_missing_responses"]
        + continuation_missing
        + coverage["partial_deepseek_missing_responses"]
    )
    if (
        coverage.get("hardware_fit_replayed_partial_rows") != 42
        or actual_successful + actual_missing != 14_414
        or final_successful + final_missing != EXPECTED_EXTENSION_ROWS
    ):
        raise ValueError("combined population-alignment row count changed")
    return {
        "target_attempts": 14_414,
        "successful_target_generations": actual_successful,
        "missing_responses": actual_missing,
        "unique_population_rows": EXPECTED_EXTENSION_ROWS,
        "retained_population_successful_target_generations": final_successful,
        "retained_population_missing_responses": final_missing,
        "replayed_failed_output_rows": 2_772,
        "replayed_partial_recovery_rows": 42,
        "never_attempted_rows_completed": 1_021,
        "alignment_never_started_rows_completed": EXPECTED_CONTINUATION_ROWS,
    }


def run(args: argparse.Namespace) -> int:
    if CODE_VERSION != "ura-runner/2.30":
        raise ValueError("Ollama alignment continuation requires Runner 2.30")
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = work_root / "runs/thesis/runner"
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh Ollama alignment-recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("alignment-recovery root must be one direct campaign")
    base_completion = args.base_completion.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(base_completion, label="failed alignment completion")
    ).hexdigest() != args.base_completion_sha256:
        raise ValueError("failed alignment completion digest changed")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    profile_source = args.profile_registry.resolve(strict=True)
    profile_bytes = _stable_file(
        profile_source, label="local-model profile registry"
    )
    snapshot, _base, _base_launch, units = _base_inputs(
        base_completion,
        runner_root=runner_root,
    )
    (
        _failed_output,
        failed_output_descriptor,
        hardware_fit_descriptor,
        _coverage,
    ) = _failed_output_coverage(
        args.failed_output_recovery_completion,
        args.failed_output_recovery_completion_sha256,
        args.hardware_fit_completion,
        args.hardware_fit_completion_sha256,
        runner_root=runner_root,
    )
    selected = _selected_failed_lanes(
        snapshot, covered_lanes=(FAILED_OUTPUT_COVERED_LANE,)
    )
    if selected != list(CONTINUATION_LANES):
        raise ValueError("Ollama population-alignment continuation selection changed")
    source_by_lane = {
        item.unit.unit_id: item
        for item in units
        if item.unit.unit_id in selected
    }
    if (
        list(source_by_lane) != selected
        or sum(source_by_lane[lane].unit.selected_records for lane in selected)
        != EXPECTED_CONTINUATION_ROWS
    ):
        raise ValueError("Ollama alignment continuation row count changed")

    control_root.mkdir(mode=0o700)
    for name in ("units", "configs", "inputs"):
        (control_root / name).mkdir(mode=0o700)
    profile_snapshot = control_root / "inputs/local-model-profiles.json"
    with profile_snapshot.open("xb") as handle:
        handle.write(profile_bytes)
    by_lane = {
        lane: _configured_unit(
            source_by_lane[lane],
            control_root=control_root,
            profile_registry=profile_snapshot,
        )
        for lane in selected
    }
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "base_completion": _descriptor(
            base_completion, label="failed alignment completion"
        ),
        "failed_output_recovery_completion": failed_output_descriptor,
        "hardware_fit_completion": hardware_fit_descriptor,
        "project_revision": _descriptor(
            project_revision, label="recovery project revision"
        ),
        "profile_registry": _descriptor(
            profile_snapshot, label="local-model profile registry"
        ),
        "unit_order": selected,
        "extension_rows": EXPECTED_CONTINUATION_ROWS,
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    launch_path = control_root / "launch.json"
    _create_json(launch_path, launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_ollama_population_alignment_recovery",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for lane in selected:
        item = by_lane[lane]
        selector = base_completion.parent / "inputs" / f"{lane}.completed-selection.json"
        selector = selector.resolve(strict=True)
        selector_sha = hashlib.sha256(
            _stable_file(selector, label=f"{lane} recovery selection")
        ).hexdigest()
        try:
            results[lane] = _run_unit(
                item.unit,
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
                admission_sha256=args.base_completion_sha256,
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
                state_schema=UNIT_STATE_SCHEMA,
                hub_acquisition_required=hub_acquisition_required(item.unit),
            )
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            failures[lane] = {
                "status": "failed",
                "unit_id": lane,
                "stage": "recovery_gate5_or_measured",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
                "target_answer_retries": 1,
            }
    attempts = sum(int(row["target_attempts"]) for row in results.values())
    successful = sum(
        int(row["successful_target_generations"]) for row in results.values()
    )
    missing = sum(int(row["missing_responses"]) for row in results.values())
    status = "complete" if not failures else "complete_with_failures"
    completion = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "base_completion": _descriptor(
            base_completion, label="failed alignment completion"
        ),
        "failed_output_recovery_completion": failed_output_descriptor,
        "hardware_fit_completion": hardware_fit_descriptor,
        "launch": _descriptor(launch_path, label="alignment recovery launch"),
        "unit_order": selected,
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempts,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "no_completed_rows_repeated": True,
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
        target_attempts=attempts,
        successful_target_generations=successful,
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=exit_code,
    )
    return exit_code


def validate_recovery_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    control_root = completion_path.parent
    completion = _load_json(
        completion_path, label="Ollama population-alignment recovery completion"
    )
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "base_completion",
        "failed_output_recovery_completion",
        "hardware_fit_completion",
        "launch",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "no_completed_rows_repeated",
        "cross_revision_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != "ura-runner/2.30"
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_failures") != {}
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("Ollama population-alignment recovery completion changed")
    base_path = _validate_descriptor(
        completion.get("base_completion"), label="failed alignment completion"
    )
    failed_output_path = _validate_descriptor(
        completion.get("failed_output_recovery_completion"),
        label="failed-output recovery completion",
    )
    hardware_fit_path = _validate_descriptor(
        completion.get("hardware_fit_completion"),
        label="hardware-fit completion",
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="alignment recovery launch"
    )
    if launch_path != control_root / "launch.json":
        raise ValueError("alignment recovery launch placement changed")
    base_snapshot, _base, _base_launch, units = _base_inputs(
        base_path,
        runner_root=runner_root,
    )
    (
        failed_output,
        failed_output_descriptor,
        hardware_fit_descriptor,
        coverage,
    ) = _failed_output_coverage(
        failed_output_path,
        hashlib.sha256(failed_output_path.read_bytes()).hexdigest(),
        hardware_fit_path,
        hashlib.sha256(hardware_fit_path.read_bytes()).hexdigest(),
        runner_root=runner_root,
    )
    selected = _selected_failed_lanes(
        base_snapshot, covered_lanes=(FAILED_OUTPUT_COVERED_LANE,)
    )
    if (
        selected != list(CONTINUATION_LANES)
        or completion.get("failed_output_recovery_completion")
        != failed_output_descriptor
        or completion.get("hardware_fit_completion") != hardware_fit_descriptor
    ):
        raise ValueError("alignment continuation prerequisite changed")
    if completion.get("unit_order") != selected:
        raise ValueError("alignment recovery selection changed")
    results = completion.get("unit_results")
    if not isinstance(results, dict) or set(results) != set(selected):
        raise ValueError("alignment recovery result inventory changed")
    launch = _load_json(launch_path, label="alignment recovery launch")
    launch_fields = {
        "schema",
        "started_at_utc",
        "expected_commit",
        "runner_code_version",
        "execution_scope_id",
        "target_answer_retries",
        "base_completion",
        "failed_output_recovery_completion",
        "hardware_fit_completion",
        "project_revision",
        "profile_registry",
        "unit_order",
        "extension_rows",
        "no_completed_rows_repeated",
        "paid_provider_calls",
    }
    if (
        set(launch) != launch_fields
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("expected_commit") != completion["expected_commit"]
        or launch.get("runner_code_version") != "ura-runner/2.30"
        or launch.get("target_answer_retries") != 1
        or launch.get("base_completion") != completion["base_completion"]
        or launch.get("failed_output_recovery_completion")
        != completion["failed_output_recovery_completion"]
        or launch.get("hardware_fit_completion")
        != completion["hardware_fit_completion"]
        or launch.get("unit_order") != selected
        or launch.get("extension_rows") != EXPECTED_CONTINUATION_ROWS
        or launch.get("no_completed_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
    ):
        raise ValueError("alignment recovery launch changed")
    _validate_descriptor(
        launch.get("project_revision"), label="recovery project revision"
    )
    profile_registry = _validate_descriptor(
        launch.get("profile_registry"), label="local-model profile registry"
    )
    if profile_registry != control_root / "inputs/local-model-profiles.json":
        raise ValueError("alignment recovery profile-registry placement changed")

    by_lane = {item.unit.unit_id: item for item in units}
    recovered_roots: dict[str, str] = {}
    recovered_evidence: dict[str, dict[str, object]] = {}
    recovered_grids: dict[str, dict[str, object]] = {}
    recovered_eligibility: dict[str, dict[str, object]] = {}
    recovered_markers: dict[str, list[dict[str, object]]] = {}
    recovery_revisions: dict[str, list[str]] = {}
    sources: set[str] = set()
    successful = 0
    missing = 0
    recovery_descriptor = _descriptor(
        completion_path, label="alignment recovery completion"
    )
    for lane in selected:
        item = by_lane[lane]
        selector = base_path.parent / "inputs" / f"{lane}.completed-selection.json"
        selector = selector.resolve(strict=True)
        selector_sha = hashlib.sha256(selector.read_bytes()).hexdigest()
        validated = _validate_metric_result(
            results[lane],
            logical_lane=lane,
            physical_unit=lane,
            source_lane=lane,
            corpus=None,
            selected_records=item.unit.selected_records,
            runner_root=runner_root,
            control_root=control_root,
            state_schema=UNIT_STATE_SCHEMA,
            completion=recovery_descriptor,
        )
        state_path = _validate_descriptor(
            results[lane]["state"], label=f"{lane} recovered state"
        )
        state = _load_json(state_path, label=f"{lane} recovered state")
        argv = state["runner_argv"]
        local = _option(argv, "--local")
        model = CURRENT_OLLAMA_BY_SPEC.get(local)
        config_path = Path(_option(argv, "--local-config")).resolve(strict=True)
        config_sha = _option(argv, "--local-config-sha256")
        config = _load_json(config_path, label=f"{lane} local configuration")
        expected_config = None
        if model is not None:
            unprofiled: dict[str, object] = {
                "digest": model.digest,
                "modalities": list(model.modalities),
                "num_ctx": PROSPECTIVE_OLLAMA_NUM_CTX,
                "think": model.think,
            }
            expected_model_config, profile = apply_profile(
                model.spec, unprofiled, path=profile_registry
            )
            if profile is None:
                raise ValueError(f"{lane}: readiness profile is missing")
            expected_config = {model.spec: expected_model_config}
        if (
            _option(argv, "--limit") != "100"
            or _option(argv, "--sample-seed") != "0"
            or _option(argv, "--target-answer-retries") != "1"
            or _option(argv, "--recovery-completed-prefix") != str(selector)
            or _option(argv, "--recovery-completed-prefix-sha256")
            != selector_sha
            or model is None
            or config_path != control_root / "configs" / f"{model.label}.json"
            or hashlib.sha256(config_path.read_bytes()).hexdigest() != config_sha
            or config != expected_config
        ):
            raise ValueError(f"{lane}: recovered population argv changed")
        if (
            item.unit.spec["metric_mode"] != "static"
            and any(flag.startswith("--model-acquisition-") for flag in argv)
        ):
            raise ValueError(f"{lane}: local-only lane gained Hub acquisition")
        envelopes = sorted(Path(validated["root"]).glob("*.request-envelope.json"))
        if len(envelopes) != 1:
            raise ValueError(f"{lane}: recovered request-envelope inventory changed")
        envelope, _descriptor_value = load_request_envelope_file(envelopes[0])
        request = envelope["request"]
        if (
            envelope.get("schema") != "ura-request-envelope/6"
            or request.get("target_answer_retries") != 1
            or request.get("limit") != 100
            or request.get("recovery_selection", {}).get("schema")
            != "ura-recovery-completed-selection/1"
        ):
            raise ValueError(f"{lane}: recovered request binding changed")
        revision = str(validated["revision"])
        recovery_revisions.setdefault(revision, []).append(lane)
        sources.add(str(validated["source"]))
        recovered_roots[lane] = str(validated["root"])
        recovered_evidence[lane] = dict(validated["evidence"])
        recovered_grids[lane] = dict(validated["grid"])
        recovered_eligibility[lane] = dict(validated["eligibility_plan"])
        recovered_markers[lane] = list(validated["completion_markers"])
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    expected_recovery = sum(by_lane[lane].unit.selected_records for lane in selected)
    target_execution = completion.get("target_execution")
    if (
        target_execution
        != {
            "target_attempts": expected_recovery,
            "successful_target_generations": successful,
            "missing_responses": missing,
        }
        or successful + missing != expected_recovery
        or sources != {base_snapshot["source_conformance_sha256"]}
    ):
        raise ValueError("alignment recovery accounting changed")

    result = copy.deepcopy(base_snapshot)
    result["completion"] = recovery_descriptor
    result["runner_code_version"] = "mixed"
    result["runner_code_versions"] = {
        "base_completed_units": BASE_RUNNER_CODE_VERSION,
        "continuation_units": "ura-runner/2.30",
        "interrupted_failed_output_recovery_units": "ura-runner/2.27",
        "hardware_fit_recovery_units": "ura-runner/2.29",
    }
    result["terminal_states"] = {
        lane: "measured_complete" for lane in ALIGNMENT_LANES
    }
    metric_lanes = [lane for lane in ALIGNMENT_LANES if lane != FAILED_OUTPUT_COVERED_LANE]
    result["metric_lane_order"] = metric_lanes
    result["metric_roots"].update(recovered_roots)
    result["metric_evidence"].update(recovered_evidence)
    result["lifecycle_evidence"] = copy.deepcopy(result["metric_evidence"])
    result["lifecycle_evidence"][FAILED_OUTPUT_COVERED_LANE] = {
        "metric_disposition": "split_runner_strata_no_pooling",
        "failed_output_recovery_completion": failed_output_descriptor,
        "hardware_fit_completion": hardware_fit_descriptor,
        "population_coverage": dict(coverage),
    }
    result["metric_grids"] = [
        (
            recovered_grids[lane]
            if lane in recovered_grids
            else next(
                item
                for item in base_snapshot["metric_grids"]
                if item["path"].startswith(base_snapshot["metric_roots"][lane] + "/")
            )
        )
        for lane in metric_lanes
    ]
    result["metric_eligibility_plans"] = [
        (
            recovered_eligibility[lane]
            if lane in recovered_eligibility
            else next(
                item
                for item in base_snapshot["metric_eligibility_plans"]
                if item["path"].startswith(base_snapshot["metric_roots"][lane] + "/")
            )
        )
        for lane in metric_lanes
    ]
    result["metric_completion_markers"] = [
        marker
        for lane in metric_lanes
        for marker in (
            recovered_markers[lane]
            if lane in recovered_markers
            else [
                item
                for item in base_snapshot["metric_completion_markers"]
                if item["path"].startswith(base_snapshot["metric_roots"][lane] + "/")
            ]
        )
    ]
    revision_strata = copy.deepcopy(base_snapshot["revision_strata"])
    for revision, lanes in recovery_revisions.items():
        revision_strata.setdefault(revision, []).extend(lanes)
    result["revision_strata"] = revision_strata
    result["project_revision_receipt_sha256"] = next(iter(recovery_revisions))
    result["metric_project_revision_receipt_sha256"] = {
        lane: revision
        for revision, lanes in revision_strata.items()
        for lane in lanes
    }
    result["lifecycle_project_revision_receipt_sha256"] = {
        **result["metric_project_revision_receipt_sha256"],
        FAILED_OUTPUT_COVERED_LANE: failed_output[
            "project_revision_receipt_sha256"
        ],
    }
    result["target_execution"] = _combined_target_execution(
        base_execution=base_snapshot["target_execution"],
        coverage=coverage,
        continuation_successful=successful,
        continuation_missing=missing,
    )
    result["population_segments"] = {
        FAILED_OUTPUT_COVERED_LANE: {
            "status": "population_complete_across_disjoint_runner_strata",
            "extension_records": 1_909,
            "runner_226_retained_usable_records": 235,
            "runner_227_interrupted_recovery_retained_records": 743,
            "runner_229_hardware_fit_recovery_records": 931,
            "security_metric_pooling_permitted": False,
            "failed_output_recovery_completion": failed_output_descriptor,
            "hardware_fit_completion": hardware_fit_descriptor,
        }
    }
    result["no_completed_rows_repeated"] = True
    result["cross_revision_pooling_permitted"] = False
    return result


def validate_phase7_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    value = _load_json(completion_path, label="Phase 7 alignment completion")
    if value.get("schema") == BASE_SCHEMA:
        return validate_base_completion(completion_path, runner_root=runner_root)
    if value.get("schema") == SCHEMA:
        return validate_recovery_completion(completion_path, runner_root=runner_root)
    raise ValueError("unsupported Ollama population-alignment completion schema")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-completion", type=Path, required=True)
    parser.add_argument("--base-completion-sha256", required=True)
    parser.add_argument(
        "--failed-output-recovery-completion", type=Path, required=True
    )
    parser.add_argument(
        "--failed-output-recovery-completion-sha256", required=True
    )
    parser.add_argument("--hardware-fit-completion", type=Path, required=True)
    parser.add_argument("--hardware-fit-completion-sha256", required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--project-revision", type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--profile-registry", type=Path, required=True)
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
        print(f"Ollama alignment recovery failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
