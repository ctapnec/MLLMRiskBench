"""Resume only Ollama stability units stopped by the zero-record canary bug."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any, Sequence

from experiments.finalize_recovered_trails import SCHEMA as FINALIZATION_SCHEMA
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_stability_continuation_phase6 import (
    CONTINUATION_STATE_SCHEMA,
    INHERITED_UNITS,
    NEW_IMAGE_UNITS,
    TEXT_FINALIZATION_UNITS,
    _failed_inputs,
)
from experiments.local_campaign.current_ollama_stability_phase6 import (
    RUNNER_CODE_VERSION,
    UNIT_STATE_SCHEMA,
    _input_json,
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
    _project_python,
    _run_unit,
    _validate_descriptor,
)


SCHEMA = "ura-current-ollama-stability-canary-recovery-phase6/1"
LAUNCH_SCHEMA = "ura-current-ollama-stability-canary-recovery-phase6-launch/1"
RECOVERY_STATE_SCHEMA = (
    "ura-current-ollama-stability-canary-recovery-phase6-unit-state/1"
)
PARTIAL_SCHEMA = "ura-current-ollama-stability-continuation-phase6/1"
CANARY_ERROR = "core result record/byte counts do not reconcile"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stable_input(
    path: Path, digest: str, *, label: str
) -> tuple[Path, dict[str, Any]]:
    if HEX64.fullmatch(digest) is None:
        raise ValueError(f"{label} SHA-256 is invalid")
    path = path.resolve(strict=True)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError(f"{label} digest changed")
    return path, _load_json(path, label=label)


def validate_partial_completion(
    completion_path: Path,
    completion_sha256: str,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Accept only the exact continuation failure caused after Runner canaries."""

    completion_path, completion = _stable_input(
        completion_path,
        completion_sha256,
        label="partial stability continuation",
    )
    root = completion_path.parent
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
        or completion.get("schema") != PARTIAL_SCHEMA
        or completion.get("status") != "complete_with_failures"
        or completion.get("controller_exit_code") != 1
        or completion.get("runner_code_version") != RUNNER_CODE_VERSION
        or completion.get("target_answer_retries") != 1
        or completion.get("inherited_units") != list(INHERITED_UNITS)
        or completion.get("finalized_units") != list(TEXT_FINALIZATION_UNITS)
        or completion.get("new_execution_units") != list(NEW_IMAGE_UNITS)
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("cross_output_policy_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("partial stability continuation contract changed")
    launch_path = _validate_descriptor(
        completion.get("launch"), label="partial continuation launch"
    )
    if launch_path != root / "launch.json":
        raise ValueError("partial continuation launch placement changed")
    failed_path = _validate_descriptor(
        completion.get("failed_completion"), label="failed stability completion"
    )
    failed_sha = str(completion["failed_completion"]["sha256"])
    failed, failed_root, units, durable = _failed_inputs(
        failed_path,
        failed_sha,
        runner_root=runner_root,
    )
    del failed
    order = [unit.unit_id for unit in units]
    results = completion.get("unit_results")
    failures = completion.get("unit_failures")
    if (
        completion.get("unit_order") != order
        or completion.get("historical_durable_rows") != durable
        or completion.get("selected_rows")
        != sum(unit.selected_records for unit in units)
        or not isinstance(results, dict)
        or not isinstance(failures, dict)
        or not failures
        or set(results) | set(failures) != set(order)
        or set(results) & set(failures)
        or not set(failures) <= set(NEW_IMAGE_UNITS)
        or not set(TEXT_FINALIZATION_UNITS + INHERITED_UNITS) <= set(results)
    ):
        raise ValueError("partial stability continuation partition changed")
    finalizations = completion.get("finalizations")
    if not isinstance(finalizations, dict) or set(finalizations) != set(
        TEXT_FINALIZATION_UNITS
    ):
        raise ValueError("partial finalization inventory changed")
    unit_by_id = {unit.unit_id: unit for unit in units}
    for unit_id, failure in failures.items():
        unit_root = root / "units" / unit_id
        canary_root = unit_root / "canary"
        eligibility = sorted(canary_root.glob("eligibility-*.eligibility.json"))
        canary_log = unit_root / "canary.validate.log"
        if (
            not isinstance(failure, dict)
            or failure.get("status") != "failed"
            or failure.get("unit_id") != unit_id
            or unit_by_id[unit_id].unit_id != unit_id
            or canary_root.is_symlink()
            or len(eligibility) != 1
            or not canary_log.is_file()
            or CANARY_ERROR not in canary_log.read_text(
                encoding="utf-8", errors="strict"
            )
            or (unit_root / "state.json").exists()
            or (unit_root / "preflight").exists()
            or (unit_root / "measured-acquisition").exists()
        ):
            raise ValueError(f"{unit_id}: canary-only failure changed")
    failed_descriptor = _descriptor(
        failed_path, label="failed stability completion"
    )
    partial_descriptor = _descriptor(
        completion_path, label="partial stability continuation"
    )
    for unit_id, result in results.items():
        unit = unit_by_id[unit_id]
        if unit_id in INHERITED_UNITS:
            owning_root = failed_root
            state_schema = UNIT_STATE_SCHEMA
            evidence_completion = failed_descriptor
        else:
            owning_root = root
            state_schema = CONTINUATION_STATE_SCHEMA
            evidence_completion = partial_descriptor
        validated = _validate_metric_result(
            result,
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
            receipt = _load_json(
                receipt_path, label=f"{unit_id} finalization"
            )
            if (
                receipt.get("schema") != FINALIZATION_SCHEMA
                or receipt.get("status") != "complete"
                or receipt.get("target_calls") != 0
                or receipt.get("judge_calls") != 0
                or receipt.get("attempts") != unit.selected_records
                or receipt.get("output_root") != validated["root"]
            ):
                raise ValueError(f"{unit_id}: finalization receipt changed")
    attempted = sum(int(row["target_attempts"]) for row in results.values())
    successful = sum(
        int(row["successful_target_generations"]) for row in results.values()
    )
    missing = sum(int(row["missing_responses"]) for row in results.values())
    if completion.get("target_execution") != {
        "target_attempts": attempted,
        "successful_target_generations": successful,
        "missing_responses": missing,
    }:
        raise ValueError("partial stability accounting changed")
    return {
        "completion": completion,
        "path": completion_path,
        "root": root,
        "failed_root": failed_root,
        "units": units,
        "durable": durable,
        "results": results,
        "failures": failures,
        "finalizations": finalizations,
    }


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    completion_path = completion_path.resolve(strict=True)
    root = completion_path.parent
    completion = _load_json(completion_path, label="canary recovery completion")
    fields = {
        "schema", "status", "controller_exit_code", "completed_at_utc",
        "expected_commit", "runner_code_version", "target_answer_retries",
        "launch", "partial_completion", "failed_completion", "unit_order",
        "unit_results", "unit_failures", "inherited_units", "recovered_units",
        "revalidated_canaries", "finalizations", "historical_durable_rows",
        "selected_rows", "recovery_selected_attempts", "target_execution",
        "model_stability_accounting", "no_completed_rows_repeated",
        "diagnostic_canary_target_calls_repeated",
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
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("diagnostic_canary_target_calls_repeated") != 0
        or completion.get("cross_output_policy_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("canary recovery completion contract changed")
    launch_path = _validate_descriptor(
        completion.get("launch"), label="canary recovery launch"
    )
    if launch_path != root / "launch.json":
        raise ValueError("canary recovery launch placement changed")
    launch = _load_json(launch_path, label="canary recovery launch")
    partial_path = _validate_descriptor(
        completion.get("partial_completion"), label="partial continuation"
    )
    partial = validate_partial_completion(
        partial_path,
        str(completion["partial_completion"]["sha256"]),
        runner_root=runner_root,
    )
    units: list[Unit] = partial["units"]
    order = [unit.unit_id for unit in units]
    recovered = list(partial["failures"])
    inherited = [unit_id for unit_id in order if unit_id not in set(recovered)]
    results = completion.get("unit_results")
    if (
        set(launch)
        != {
            "schema", "started_at_utc", "expected_commit",
            "execution_scope_id", "target_answer_retries",
            "partial_completion", "recovered_units", "inherited_units",
            "no_completed_rows_repeated",
            "diagnostic_canary_target_calls_repeated", "paid_provider_calls",
        }
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("expected_commit") != completion.get("expected_commit")
        or launch.get("target_answer_retries") != 1
        or launch.get("partial_completion") != completion.get("partial_completion")
        or launch.get("recovered_units") != recovered
        or launch.get("inherited_units") != inherited
        or launch.get("no_completed_rows_repeated") is not True
        or launch.get("diagnostic_canary_target_calls_repeated") != 0
        or launch.get("paid_provider_calls") != 0
        or completion.get("unit_order") != order
        or completion.get("recovered_units") != recovered
        or completion.get("inherited_units") != inherited
        or completion.get("historical_durable_rows") != partial["durable"]
        or completion.get("selected_rows")
        != sum(unit.selected_records for unit in units)
        or completion.get("recovery_selected_attempts")
        != sum(unit.selected_records for unit in units if unit.unit_id in recovered)
        or completion.get("finalizations") != partial["finalizations"]
        or completion.get("failed_completion")
        != partial["completion"]["failed_completion"]
        or not isinstance(results, dict)
        or list(results) != order
    ):
        raise ValueError("canary recovery population changed")
    canaries = completion.get("revalidated_canaries")
    if not isinstance(canaries, dict) or list(canaries) != recovered:
        raise ValueError("revalidated canary inventory changed")
    for unit_id in recovered:
        path = _validate_descriptor(
            canaries[unit_id], label=f"{unit_id} revalidated canary"
        )
        expected_parent = root / "units" / unit_id / "reused-canary-summary"
        if (
            path.parent != expected_parent
            or path.suffixes[-2:] != [".lane-canary", ".json"]
        ):
            raise ValueError(f"{unit_id}: revalidated canary placement changed")

    failed_descriptor = _descriptor(
        _validate_descriptor(
            completion.get("failed_completion"), label="failed stability completion"
        ),
        label="failed stability completion",
    )
    partial_descriptor = _descriptor(partial_path, label="partial continuation")
    recovery_descriptor = _descriptor(
        completion_path, label="canary recovery completion"
    )
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    grids: list[dict[str, object]] = []
    plans: list[dict[str, object]] = []
    markers: list[dict[str, object]] = []
    revision_strata: dict[str, list[str]] = {}
    revision_by_lane: dict[str, str] = {}
    sources: set[str] = set()
    successful = missing = 0
    recovered_set = set(recovered)
    for unit in units:
        unit_id = unit.unit_id
        if unit_id in recovered_set:
            owning_root = root
            state_schema = RECOVERY_STATE_SCHEMA
            evidence_completion = recovery_descriptor
        elif unit_id in INHERITED_UNITS:
            owning_root = partial["failed_root"]
            state_schema = UNIT_STATE_SCHEMA
            evidence_completion = failed_descriptor
        else:
            owning_root = partial["root"]
            state_schema = CONTINUATION_STATE_SCHEMA
            evidence_completion = partial_descriptor
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
        revision = str(validated["revision"])
        revision_strata.setdefault(revision, []).append(unit_id)
        revision_by_lane[unit_id] = revision
        sources.add(str(validated["source"]))
        metric_roots[unit_id] = str(validated["root"])
        metric_evidence[unit_id] = dict(validated["evidence"])
        grids.append(dict(validated["grid"]))
        plans.append(dict(validated["eligibility_plan"]))
        markers.extend(validated["completion_markers"])
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
        raise ValueError("canary recovery target accounting changed")
    return {
        "completion": recovery_descriptor,
        "runner_code_version": RUNNER_CODE_VERSION,
        "output_policy_stratum": (
            "provider_neutral_retry_1_with_zero_call_trail_finalization"
        ),
        "unit_order": order,
        "terminal_states": {unit_id: "measured_complete" for unit_id in order},
        "metric_lane_order": order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": grids,
        "metric_eligibility_plans": plans,
        "metric_completion_markers": markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": revision_by_lane,
        "project_revision_receipt_sha256": next(iter(revision_strata)),
        "source_conformance_sha256": next(iter(sources)),
        "historical_durable_rows": partial["durable"],
        "target_execution": dict(completion["target_execution"]),
        "cross_output_policy_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh canary recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("canary recovery must be one direct campaign root")
    project_revision = args.project_revision.resolve(strict=True)
    _input_json(
        args.project_revision,
        args.project_revision_sha256,
        label="canary recovery project revision",
    )
    partial = validate_partial_completion(
        args.partial_completion,
        args.partial_completion_sha256,
        runner_root=work_root / "runs/thesis/runner",
    )
    units: list[Unit] = partial["units"]
    recovered = list(partial["failures"])
    recovered_set = set(recovered)
    inherited = [unit.unit_id for unit in units if unit.unit_id not in recovered_set]
    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "partial_completion": _descriptor(
            partial["path"], label="partial continuation"
        ),
        "recovered_units": recovered,
        "inherited_units": inherited,
        "no_completed_rows_repeated": True,
        "diagnostic_canary_target_calls_repeated": 0,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_current_ollama_canary_recovery",
        hard_stop_hours=168,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    failed_launch = _load_json(
        partial["failed_root"] / "launch.json", label="failed stability launch"
    )
    gate5_sha = str(failed_launch["gate5"]["sha256"])
    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    revalidated_canaries: dict[str, object] = {}
    for unit in units:
        unit_id = unit.unit_id
        if unit_id not in recovered_set:
            results[unit_id] = partial["results"][unit_id]
            continue
        try:
            recovery_path = None
            recovery_sha = None
            if unit.recovery is not None:
                recovery_path = (
                    control_root / "inputs" / f"{unit_id}.completed-prefix.json"
                )
                _create_json(recovery_path, unit.recovery)
                recovery_sha = hashlib.sha256(recovery_path.read_bytes()).hexdigest()
            result = _run_unit(
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
                state_schema=RECOVERY_STATE_SCHEMA,
                validated_canary_root=partial["root"] / "units" / unit_id / "canary",
            )
            summary_root = control_root / "units" / unit_id / "reused-canary-summary"
            summaries = sorted(summary_root.glob("*.lane-canary.json"))
            if len(summaries) != 1:
                raise ValueError(f"{unit_id}: revalidated canary summary changed")
            revalidated_canaries[unit_id] = _descriptor(
                summaries[0], label=f"{unit_id} revalidated canary"
            )
            results[unit_id] = result
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
        "launch": _descriptor(control_root / "launch.json", label="recovery launch"),
        "partial_completion": launch["partial_completion"],
        "failed_completion": partial["completion"]["failed_completion"],
        "unit_order": [unit.unit_id for unit in units],
        "unit_results": results,
        "unit_failures": failures,
        "inherited_units": inherited,
        "recovered_units": recovered,
        "revalidated_canaries": revalidated_canaries,
        "finalizations": partial["finalizations"],
        "historical_durable_rows": partial["durable"],
        "selected_rows": sum(unit.selected_records for unit in units),
        "recovery_selected_attempts": sum(
            unit.selected_records for unit in units if unit.unit_id in recovered_set
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
        "diagnostic_canary_target_calls_repeated": 0,
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
    parser.add_argument("--partial-completion", type=Path, required=True)
    parser.add_argument("--partial-completion-sha256", required=True)
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
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
