"""Finish the failed current-Ollama stability cohort without duplicate calls.

Five Ministral image units are inherited unchanged.  Four fully executed Gemma
text units are finalized from their durable responses with zero target or judge
calls.  Only the five Gemma image units that stopped before measured execution
are launched under the corrected attestation probe policy.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments.finalize_recovered_trails import (
    SCHEMA as FINALIZATION_SCHEMA,
    finalize as finalize_recovered_trails,
)
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_phase6 import _level1_counts
from experiments.local_campaign.current_ollama_stability_phase6 import (
    RUNNER_CODE_VERSION,
    UNIT_STATE_SCHEMA,
    _input_json,
    build_units,
    validate_failed_recovery,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit,
    _create_json,
    _descriptor,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _validate_descriptor,
)


SCHEMA = "ura-current-ollama-stability-continuation-phase6/1"
LAUNCH_SCHEMA = "ura-current-ollama-stability-continuation-phase6-launch/1"
CONTINUATION_STATE_SCHEMA = (
    "ura-current-ollama-stability-continuation-phase6-unit-state/1"
)
TEXT_FINALIZATION_UNITS = (
    "ollama-stability-gemma4-text-airbench-suffix",
    "ollama-stability-gemma4-text-xstest-full",
    "ollama-stability-gemma4-text-simplesafetytests-full",
    "ollama-stability-gemma4-text-decodingtrust-stereotype",
)
NEW_IMAGE_UNITS = (
    "ollama-stability-gemma4-image-mllmguard-privacy-suffix",
    "ollama-stability-gemma4-image-mllmguard-bias",
    "ollama-stability-gemma4-image-mllmguard-toxicity",
    "ollama-stability-gemma4-image-mllmguard-legality",
    "ollama-stability-gemma4-image-holisafe-full",
)
INHERITED_UNITS = (
    "ollama-stability-ministral3-image-mllmguard-privacy-suffix",
    "ollama-stability-ministral3-image-mllmguard-bias",
    "ollama-stability-ministral3-image-mllmguard-toxicity",
    "ollama-stability-ministral3-image-mllmguard-legality",
    "ollama-stability-ministral3-image-holisafe-full",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log_contains(path: Path, text: str) -> bool:
    return (
        path.is_file()
        and not path.is_symlink()
        and 0 < path.stat().st_size <= 16 * 1024 * 1024
        and text in path.read_text(encoding="utf-8", errors="strict")
    )


def _failed_inputs(
    completion_path: Path,
    completion_sha256: str,
    *,
    runner_root: Path,
) -> tuple[dict[str, Any], Path, list[Unit], dict[str, int]]:
    if HEX64.fullmatch(completion_sha256) is None:
        raise ValueError("failed stability completion SHA-256 is invalid")
    completion_path = completion_path.resolve(strict=True)
    if hashlib.sha256(completion_path.read_bytes()).hexdigest() != completion_sha256:
        raise ValueError("failed stability completion digest changed")
    failed = _load_json(completion_path, label="failed current Ollama stability")
    failed_root = completion_path.parent
    if (
        failed.get("schema") != "ura-current-ollama-stability-phase6/1"
        or failed.get("status") != "complete_with_failures"
        or failed.get("controller_exit_code") != 1
        or failed.get("runner_code_version") != RUNNER_CODE_VERSION
        or failed.get("no_completed_rows_repeated") is not True
        or failed.get("paid_provider_calls") != 0
        or (failed_root / ".exit").read_text(encoding="ascii") != "1\n"
    ):
        raise ValueError("failed current Ollama stability terminal changed")
    launch_path = _validate_descriptor(
        failed.get("launch"), label="failed current Ollama stability launch"
    )
    if launch_path != failed_root / "launch.json":
        raise ValueError("failed stability launch placement changed")
    launch = _load_json(launch_path, label="failed stability launch")
    gate5_path = _validate_descriptor(launch.get("gate5"), label="Gate 5")
    base_path = _validate_descriptor(
        launch.get("base_completion"), label="base current Ollama completion"
    )
    recovery_path = _validate_descriptor(
        launch.get("failed_recovery_completion"), label="failed old recovery"
    )
    historical = validate_failed_recovery(
        gate5_path=gate5_path,
        base_completion=base_path,
        recovery_completion=recovery_path,
        runner_root=runner_root,
    )
    units, durable = build_units(
        gate5=historical["gate5"], base=historical["base"]
    )
    order = tuple(unit.unit_id for unit in units)
    expected = TEXT_FINALIZATION_UNITS + NEW_IMAGE_UNITS + INHERITED_UNITS
    results = failed.get("unit_results")
    failures = failed.get("unit_failures")
    if (
        order != expected
        or failed.get("unit_order") != list(expected)
        or not isinstance(results, dict)
        or set(results) != set(INHERITED_UNITS)
        or not isinstance(failures, dict)
        or set(failures) != set(TEXT_FINALIZATION_UNITS + NEW_IMAGE_UNITS)
    ):
        raise ValueError("failed stability terminal unit partition changed")
    for unit_id in TEXT_FINALIZATION_UNITS:
        if not _log_contains(
            failed_root / "units" / unit_id / "measured.run.log",
            "model_stability_status differs from its retained stage projection",
        ):
            raise ValueError(f"{unit_id}: failed for an unrelated reason")
    for unit_id in NEW_IMAGE_UNITS:
        if not _log_contains(
            failed_root / "units" / unit_id / "probe.derive.log",
            "lacks a provider/runtime resolved_model",
        ):
            raise ValueError(f"{unit_id}: pre-measured failure changed")
    return failed, failed_root, units, durable


def _finalize_text_unit(
    unit: Unit,
    *,
    python: Path,
    work_root: Path,
    control_root: Path,
    failed_root: Path,
    project_revision: Path,
    project_revision_sha256: str,
) -> tuple[dict[str, Any], dict[str, object]]:
    unit_root = control_root / "units" / unit.unit_id
    unit_root.mkdir(parents=True, mode=0o700)
    old_state_path = failed_root / "units" / unit.unit_id / "state.json"
    old_state = _load_json(old_state_path, label=f"{unit.unit_id} failed state")
    if (
        old_state.get("schema") != UNIT_STATE_SCHEMA
        or old_state.get("unit_id") != unit.unit_id
        or old_state.get("selected_records") != unit.selected_records
        or old_state.get("target_answer_retries") != 1
    ):
        raise ValueError(f"{unit.unit_id}: failed measured state changed")
    source_root = Path(str(old_state.get("result_root", ""))).resolve(strict=True)
    result_root = work_root / "runs/thesis/runner" / unit.unit_id / control_root.name
    result_root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    finalization = finalize_recovered_trails(
        source_root=source_root,
        out_root=result_root,
        finalizer_project_revision=project_revision,
        finalizer_project_revision_sha256=project_revision_sha256,
    )
    state = {
        **old_state,
        "schema": CONTINUATION_STATE_SCHEMA,
        "result_root": str(result_root),
    }
    _create_json(unit_root / "state.json", state)
    attempted, successful, missing = _level1_counts(
        python=python,
        lane_root=unit_root,
        state=state,
        timeout=3600,
    )
    if attempted != unit.selected_records:
        raise ValueError(f"{unit.unit_id}: finalized population changed")
    result = {
        "status": "complete",
        "unit_id": unit.unit_id,
        "source_lane": unit.source_lane,
        "corpus": unit.corpus,
        "selected_records": unit.selected_records,
        "target_answer_retries": 1,
        "target_call_cap": unit.selected_records * 2,
        "target_attempts": attempted,
        "successful_target_generations": successful,
        "missing_responses": missing,
        "result_root": str(result_root),
        "state": _descriptor(unit_root / "state.json", label="finalized state"),
        "level1": _descriptor(unit_root / "level1.json", label="finalized Level 1"),
    }
    return result, dict(finalization["receipt"])


def _validate_completion_value(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    completion_path = completion_path.resolve(strict=True)
    control_root = completion_path.parent
    completion = _load_json(completion_path, label="stability continuation")
    fields = {
        "schema", "status", "controller_exit_code", "completed_at_utc",
        "expected_commit", "runner_code_version", "target_answer_retries",
        "launch", "failed_completion", "unit_order", "unit_results",
        "unit_failures", "inherited_units", "finalized_units",
        "new_execution_units", "finalizations", "historical_durable_rows",
        "selected_rows", "continuation_selected_attempts", "target_execution",
        "model_stability_accounting", "no_completed_rows_repeated",
        "cross_output_policy_pooling_permitted", "paid_provider_calls",
    }
    if (
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or completion.get("runner_code_version") != RUNNER_CODE_VERSION
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_failures") != {}
        or completion.get("inherited_units") != list(INHERITED_UNITS)
        or completion.get("finalized_units") != list(TEXT_FINALIZATION_UNITS)
        or completion.get("new_execution_units") != list(NEW_IMAGE_UNITS)
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("cross_output_policy_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("stability continuation contract changed")
    failed_path = _validate_descriptor(
        completion.get("failed_completion"), label="failed stability completion"
    )
    failed_sha = str(completion["failed_completion"]["sha256"])
    failed, failed_root, units, durable = _failed_inputs(
        failed_path, failed_sha, runner_root=runner_root
    )
    expected_order = [unit.unit_id for unit in units]
    if (
        completion.get("unit_order") != expected_order
        or completion.get("historical_durable_rows") != durable
        or completion.get("selected_rows") != sum(unit.selected_records for unit in units)
        or completion.get("continuation_selected_attempts")
        != sum(unit.selected_records for unit in units if unit.unit_id in NEW_IMAGE_UNITS)
    ):
        raise ValueError("stability continuation population changed")
    results = completion.get("unit_results")
    if not isinstance(results, dict) or list(results) != expected_order:
        raise ValueError("stability continuation result order changed")
    finalizations = completion.get("finalizations")
    if (
        not isinstance(finalizations, dict)
        or set(finalizations) != set(TEXT_FINALIZATION_UNITS)
    ):
        raise ValueError("stability continuation finalization inventory changed")

    failed_descriptor = _descriptor(failed_path, label="failed stability completion")
    continuation_descriptor = _descriptor(
        completion_path, label="stability continuation completion"
    )
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_plans: list[dict[str, object]] = []
    metric_markers: list[dict[str, object]] = []
    revision_strata: dict[str, list[str]] = {}
    revision_by_lane: dict[str, str] = {}
    sources: set[str] = set()
    successful = missing = 0
    for unit in units:
        unit_id = unit.unit_id
        if unit_id in INHERITED_UNITS:
            owning_root = failed_root
            state_schema = UNIT_STATE_SCHEMA
            evidence_completion = failed_descriptor
        else:
            owning_root = control_root
            state_schema = CONTINUATION_STATE_SCHEMA
            evidence_completion = continuation_descriptor
        validated = _validate_metric_result(
            results[unit_id],
            logical_lane=unit_id,
            physical_unit=unit_id,
            source_lane=unit.source_lane,
            corpus=unit.corpus,
            selected_records=unit.selected_records,
            runner_root=runner_root,
            control_root=owning_root,
            state_schema=state_schema,
            completion=evidence_completion,
        )
        if unit_id in TEXT_FINALIZATION_UNITS:
            receipt_path = _validate_descriptor(
                finalizations[unit_id], label=f"{unit_id} finalization"
            )
            receipt = _load_json(receipt_path, label=f"{unit_id} finalization")
            if (
                receipt.get("schema") != FINALIZATION_SCHEMA
                or receipt.get("status") != "complete"
                or receipt.get("target_calls") != 0
                or receipt.get("judge_calls") != 0
                or receipt.get("attempts") != unit.selected_records
                or receipt.get("output_root") != validated["root"]
            ):
                raise ValueError(f"{unit_id}: finalization receipt changed")
            validated["evidence"]["post_execution_finalization"] = dict(
                finalizations[unit_id]
            )
        revision = str(validated["revision"])
        revision_strata.setdefault(revision, []).append(unit_id)
        revision_by_lane[unit_id] = revision
        sources.add(str(validated["source"]))
        metric_roots[unit_id] = str(validated["root"])
        metric_evidence[unit_id] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_plans.append(dict(validated["eligibility_plan"]))
        metric_markers.extend(validated["completion_markers"])
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    total = sum(unit.selected_records for unit in units)
    if (
        completion.get("target_execution")
        != {
            "target_attempts": total,
            "successful_target_generations": successful,
            "missing_responses": missing,
        }
        or successful + missing != total
        or len(sources) != 1
    ):
        raise ValueError("stability continuation target accounting changed")
    return {
        "completion": continuation_descriptor,
        "runner_code_version": RUNNER_CODE_VERSION,
        "output_policy_stratum": (
            "provider_neutral_retry_1_with_zero_call_trail_finalization"
        ),
        "unit_order": expected_order,
        "terminal_states": {unit_id: "measured_complete" for unit_id in expected_order},
        "metric_lane_order": expected_order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_plans,
        "metric_completion_markers": metric_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": revision_by_lane,
        "project_revision_receipt_sha256": next(iter(revision_strata)),
        "source_conformance_sha256": next(iter(sources)),
        "historical_durable_rows": durable,
        "target_execution": dict(completion["target_execution"]),
        "cross_output_policy_pooling_permitted": False,
    }


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    return _validate_completion_value(completion_path, runner_root=runner_root)


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh stability continuation root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("stability continuation must be one direct campaign root")
    project_revision = args.project_revision.resolve(strict=True)
    _input_json(
        project_revision,
        args.project_revision_sha256,
        label="continuation project revision",
    )
    failed, failed_root, units, durable = _failed_inputs(
        args.failed_stability_completion,
        args.failed_stability_completion_sha256,
        runner_root=work_root / "runs/thesis/runner",
    )
    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    failed_launch = _load_json(
        failed_root / "launch.json", label="failed stability launch"
    )
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "failed_completion": _descriptor(
            args.failed_stability_completion, label="failed stability completion"
        ),
        "gate5": dict(failed_launch["gate5"]),
        "base_completion": dict(failed_launch["base_completion"]),
        "failed_recovery_completion": dict(
            failed_launch["failed_recovery_completion"]
        ),
        "inherited_units": list(INHERITED_UNITS),
        "finalized_units": list(TEXT_FINALIZATION_UNITS),
        "new_execution_units": list(NEW_IMAGE_UNITS),
        "unit_order": [unit.unit_id for unit in units],
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_current_ollama_stability_continuation",
        hard_stop_hours=168,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    old_results = failed["unit_results"]
    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    finalizations: dict[str, object] = {}
    gate5_sha = str(failed_launch["gate5"]["sha256"])
    for unit in units:
        unit_id = unit.unit_id
        try:
            if unit_id in INHERITED_UNITS:
                results[unit_id] = old_results[unit_id]
                continue
            if unit_id in TEXT_FINALIZATION_UNITS:
                result, receipt = _finalize_text_unit(
                    unit,
                    python=python,
                    work_root=work_root,
                    control_root=control_root,
                    failed_root=failed_root,
                    project_revision=project_revision,
                    project_revision_sha256=args.project_revision_sha256,
                )
                results[unit_id] = result
                finalizations[unit_id] = receipt
                continue
            recovery_path = None
            recovery_sha = None
            if unit.recovery is not None:
                recovery_path = control_root / "inputs" / f"{unit_id}.completed-prefix.json"
                _create_json(recovery_path, unit.recovery)
                recovery_sha = hashlib.sha256(recovery_path.read_bytes()).hexdigest()
            results[unit_id] = _run_unit(
                unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=project_revision,
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=recovery_path,
                recovery_sha256=recovery_sha,
                expected_commit=args.expected_commit,
                framework_lock_id=_framework_lock_id(),
                admission_sha256=gate5_sha,
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
                state_schema=CONTINUATION_STATE_SCHEMA,
            )
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            failures[unit_id] = {
                "status": "failed",
                "unit_id": unit_id,
                "source_lane": unit.source_lane,
                "corpus": unit.corpus,
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
            }
    attempted = sum(int(row["target_attempts"]) for row in results.values())
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
        "runner_code_version": RUNNER_CODE_VERSION,
        "target_answer_retries": 1,
        "launch": _descriptor(control_root / "launch.json", label="continuation launch"),
        "failed_completion": launch["failed_completion"],
        "unit_order": [unit.unit_id for unit in units],
        "unit_results": results,
        "unit_failures": failures,
        "inherited_units": list(INHERITED_UNITS),
        "finalized_units": list(TEXT_FINALIZATION_UNITS),
        "new_execution_units": list(NEW_IMAGE_UNITS),
        "finalizations": finalizations,
        "historical_durable_rows": durable,
        "selected_rows": sum(unit.selected_records for unit in units),
        "continuation_selected_attempts": sum(
            unit.selected_records for unit in units if unit.unit_id in NEW_IMAGE_UNITS
        ),
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_output_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "completion.json", completion)
    exit_code = int(completion["controller_exit_code"])
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{exit_code}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=attempted,
        successful_target_generations=successful,
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=exit_code,
    )
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--failed-stability-completion", type=Path, required=True)
    parser.add_argument("--failed-stability-completion-sha256", required=True)
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
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
