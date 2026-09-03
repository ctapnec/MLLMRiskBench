"""Recover the one hardware-fit unit blocked by an undersized canary cap.

The predecessor's 24 completed units remain immutable. This controller runs
only the three unattempted GPTGeoChat rows and publishes one superseding
completion whose metric evidence points to the original and repair roots.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any

from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import _descriptor, _stable_file
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    EXPECTED_TOTAL_ROWS,
    _unit_order,
    _validate_phase7_completion as _validate_repairable_predecessor,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    load_inventory,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit,
    _create_json,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _replace_option,
    _run_unit,
    _utc_now,
    _validate_descriptor,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-local-hardware-fit-failed-unit-recovery-phase6/1"
LAUNCH_SCHEMA = "ura-local-hardware-fit-failed-unit-recovery-launch/1"
AMENDMENT_SCHEMA = "ura-gate5-local-hardware-fit-failed-unit-recovery/1"
STATE_SCHEMA = "ura-local-hardware-fit-failed-unit-recovery-state/1"
FAILED_UNIT_INDEX = 21
FAILED_SELECTED_RECORDS = 3
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _configure_unit(
    item: Mapping[str, Any],
    *,
    unit_id: str,
    control_root: Path,
) -> tuple[Unit, Path, str, Path, str]:
    selector = item.get("recovery_selection")
    config = item.get("hardware_fit_local_config")
    base = item.get("base_argv")
    summary = item.get("summary")
    corpora = selector.get("corpora") if isinstance(selector, Mapping) else None
    if (
        not isinstance(selector, Mapping)
        or selector.get("schema") != "ura-recovery-completed-selection/1"
        or not isinstance(corpora, Mapping)
        or not corpora
        or not isinstance(config, Mapping)
        or not isinstance(base, list)
        or any(not isinstance(value, str) for value in base)
        or not isinstance(summary, Mapping)
        or summary.get("recovery_records") != FAILED_SELECTED_RECORDS
    ):
        raise ValueError("failed hardware-fit unit input changed")
    selector_path = control_root / "inputs" / f"{unit_id}.json"
    config_path = control_root / "configs" / f"{unit_id}.json"
    _create_json(selector_path, dict(selector))
    _create_json(config_path, dict(config))
    selector_sha = hashlib.sha256(selector_path.read_bytes()).hexdigest()
    config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()
    corrected = _replace_option(base, "--local-config", str(config_path))
    corrected = _replace_option(corrected, "--local-config-sha256", config_sha)
    corrected = _replace_option(corrected, "--corpora", ",".join(corpora))
    corpus = next(iter(corpora)) if len(corpora) == 1 else None
    unit = Unit(
        unit_id=unit_id,
        source_lane=str(item["source_lane"]),
        corpus=corpus,
        spec={"base_argv": corrected, "modality": item["modality"]},
        selected_records=FAILED_SELECTED_RECORDS,
        recovery=selector,
    )
    return unit, selector_path, selector_sha, config_path, config_sha


def _validate_predecessor(
    path: Path,
    sha256: str,
    *,
    runner_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    resolved = path.resolve(strict=True)
    payload = _stable_file(resolved, label="failed hardware-fit completion")
    if hashlib.sha256(payload).hexdigest() != sha256:
        raise ValueError("failed hardware-fit completion digest changed")
    value = _load_json(resolved, label="failed hardware-fit completion")
    inventory_path = _validate_descriptor(
        value.get("inventory"), label="hardware-fit inventory"
    )
    inventory = load_inventory(
        inventory_path, str(value["inventory"].get("sha256", ""))
    )
    order = _unit_order(inventory)
    failed_unit = order[FAILED_UNIT_INDEX - 1]
    validated = _validate_repairable_predecessor(
        resolved,
        runner_root=runner_root,
        allow_failed_unit=failed_unit,
    )
    return value, validated, inventory, failed_unit


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    resolved = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    control_root = resolved.parent
    value = _load_json(resolved, label="hardware-fit failed-unit recovery")
    fields = {
        "schema", "status", "controller_exit_code", "completed_at_utc",
        "expected_commit", "runner_code_version", "target_answer_retries",
        "prior_completion", "inventory", "gate5_amendment", "unit_order",
        "retained_unit_order", "recovered_unit", "unit_results",
        "unit_failures", "target_execution", "planned_unique_rows",
        "successful_rows_repeated", "historical_rows_mutated",
        "cross_condition_pooling_permitted", "paid_provider_calls",
    }
    if (
        set(value) != fields
        or value.get("schema") != SCHEMA
        or value.get("status") != "complete"
        or value.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(value.get("expected_commit", ""))) is None
        or value.get("runner_code_version") != CODE_VERSION
        or value.get("target_answer_retries") != 1
        or value.get("unit_failures") != {}
        or value.get("planned_unique_rows") != EXPECTED_TOTAL_ROWS
        or value.get("successful_rows_repeated") != 0
        or value.get("historical_rows_mutated") is not False
        or value.get("cross_condition_pooling_permitted") is not False
        or value.get("paid_provider_calls") != 0
    ):
        raise ValueError("hardware-fit failed-unit recovery contract changed")
    prior_path = _validate_descriptor(
        value.get("prior_completion"), label="failed hardware-fit completion"
    )
    prior_sha = str(value["prior_completion"].get("sha256", ""))
    prior, retained, inventory, unit_id = _validate_predecessor(
        prior_path,
        prior_sha,
        runner_root=runner_root.resolve(strict=True),
    )
    order = retained["unit_order"]
    if (
        value.get("inventory") != prior.get("inventory")
        or value.get("unit_order") != order
        or value.get("retained_unit_order")
        != [candidate for candidate in order if candidate != unit_id]
        or value.get("recovered_unit") != unit_id
    ):
        raise ValueError("hardware-fit failed-unit recovery partition changed")
    amendment_path = _validate_descriptor(
        value.get("gate5_amendment"), label="failed-unit Gate 5 amendment"
    )
    expected_amendment = {
        "schema": AMENDMENT_SCHEMA,
        "approved_scope": "exact_pre_runner_canary_cap_failure_only",
        "prior_completion": dict(value["prior_completion"]),
        "inventory": dict(value["inventory"]),
        "recovered_unit": unit_id,
        "selected_records": FAILED_SELECTED_RECORDS,
        "target_answer_retries": 1,
        "measured_max_total_target_calls": FAILED_SELECTED_RECORDS * 2,
        "diagnostic_canary_cap_source": "full_retained_selection",
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
    }
    if (
        amendment_path != control_root / "gate5-failed-unit-amendment.json"
        or _load_json(amendment_path, label="failed-unit Gate 5 amendment")
        != expected_amendment
    ):
        raise ValueError("failed-unit Gate 5 amendment changed")
    results = value.get("unit_results")
    prior_results = prior.get("unit_results")
    if (
        not isinstance(results, dict)
        or list(results) != order
        or not isinstance(prior_results, dict)
        or any(
            results[candidate] != prior_results[candidate]
            for candidate in order
            if candidate != unit_id
        )
    ):
        raise ValueError("hardware-fit inherited result identity changed")
    item = inventory["units"][FAILED_UNIT_INDEX - 1]
    selector_path = control_root / "inputs" / f"{unit_id}.json"
    config_path = control_root / "configs" / f"{unit_id}.json"
    if (
        _load_json(selector_path, label="failed-unit recovery selector")
        != item["recovery_selection"]
        or _load_json(config_path, label="failed-unit hardware config")
        != item["hardware_fit_local_config"]
    ):
        raise ValueError("failed-unit recovery input changed")
    completion_descriptor = _descriptor(resolved, label="recovery completion")
    corpora = item["recovery_selection"]["corpora"]
    validated = _validate_metric_result(
        results[unit_id],
        logical_lane=unit_id,
        physical_unit=unit_id,
        source_lane=str(item["source_lane"]),
        corpus=next(iter(corpora)) if len(corpora) == 1 else None,
        selected_records=FAILED_SELECTED_RECORDS,
        runner_root=runner_root,
        control_root=control_root,
        state_schema=STATE_SCHEMA,
        completion=completion_descriptor,
    )
    state_path = _validate_descriptor(results[unit_id]["state"], label="recovery state")
    state = _load_json(state_path, label="recovery state")
    argv = state.get("runner_argv")
    if (
        not isinstance(argv, list)
        or _option(argv, "--recovery-completed-prefix") != str(selector_path)
        or _option(argv, "--recovery-completed-prefix-sha256")
        != hashlib.sha256(selector_path.read_bytes()).hexdigest()
        or _option(argv, "--local-config") != str(config_path)
        or _option(argv, "--local-config-sha256")
        != hashlib.sha256(config_path.read_bytes()).hexdigest()
    ):
        raise ValueError("failed-unit measured binding changed")
    accounting = {
        "target_attempts": int(retained["target_execution"]["target_attempts"])
        + FAILED_SELECTED_RECORDS,
        "successful_target_generations": int(
            retained["target_execution"]["successful_target_generations"]
        ) + int(validated["successful"]),
        "missing_responses": int(retained["target_execution"]["missing_responses"])
        + int(validated["missing"]),
    }
    if (
        value.get("target_execution") != accounting
        or retained["source_conformance_sha256"] != str(validated["source"])
    ):
        raise ValueError("hardware-fit failed-unit recovery accounting changed")

    metric_roots = {**retained["metric_roots"], unit_id: str(validated["root"])}
    metric_evidence = {
        **retained["metric_evidence"], unit_id: dict(validated["evidence"])
    }
    metric_order = list(order)
    metric_roots = {candidate: metric_roots[candidate] for candidate in metric_order}
    metric_evidence = {
        candidate: metric_evidence[candidate] for candidate in metric_order
    }
    revisions = {
        **retained["metric_project_revision_receipt_sha256"],
        unit_id: str(validated["revision"]),
    }
    revision_strata: dict[str, list[str]] = {}
    for candidate in metric_order:
        revision_strata.setdefault(revisions[candidate], []).append(candidate)
    lifecycle_roots = {**retained["lifecycle_roots"], unit_id: str(validated["root"])}
    lifecycle_evidence = {
        **retained["lifecycle_evidence"], unit_id: dict(validated["evidence"])
    }
    return {
        "completion": completion_descriptor,
        "inventory": dict(value["inventory"]),
        "runner_code_version": CODE_VERSION,
        "output_policy_stratum": "hardware_fit_context_and_maximum_available_output",
        "unit_order": order,
        "terminal_states": {candidate: "measured_complete" for candidate in order},
        "lifecycle_roots": {
            candidate: lifecycle_roots[candidate] for candidate in order
        },
        "lifecycle_evidence": {
            candidate: lifecycle_evidence[candidate] for candidate in order
        },
        "lifecycle_revision_strata": revision_strata,
        "lifecycle_project_revision_receipt_sha256": revisions,
        "metric_lane_order": metric_order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": [metric_evidence[candidate]["grid"] for candidate in metric_order],
        "metric_eligibility_plans": [
            metric_evidence[candidate]["eligibility_plan"] for candidate in metric_order
        ],
        "metric_completion_markers": [
            marker
            for candidate in metric_order
            for marker in metric_evidence[candidate]["completion_markers"]
        ],
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": revisions,
        "source_conformance_sha256": str(validated["source"]),
        "target_execution": accounting,
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "successful_rows_repeated": 0,
        "cross_condition_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = (work_root / "runs/thesis/runner").resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh failed-unit recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("failed-unit recovery root must be one direct campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    prior, retained, inventory, unit_id = _validate_predecessor(
        args.prior_completion,
        args.prior_completion_sha256,
        runner_root=runner_root,
    )
    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    (control_root / "configs").mkdir(mode=0o700)
    unit, selector_path, selector_sha, _config_path, _config_sha = _configure_unit(
        inventory["units"][FAILED_UNIT_INDEX - 1],
        unit_id=unit_id,
        control_root=control_root,
    )
    prior_descriptor = _descriptor(
        args.prior_completion.resolve(strict=True), label="failed hardware-fit completion"
    )
    amendment = {
        "schema": AMENDMENT_SCHEMA,
        "approved_scope": "exact_pre_runner_canary_cap_failure_only",
        "prior_completion": prior_descriptor,
        "inventory": dict(prior["inventory"]),
        "recovered_unit": unit_id,
        "selected_records": FAILED_SELECTED_RECORDS,
        "target_answer_retries": 1,
        "measured_max_total_target_calls": FAILED_SELECTED_RECORDS * 2,
        "diagnostic_canary_cap_source": "full_retained_selection",
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
    }
    amendment_path = control_root / "gate5-failed-unit-amendment.json"
    _create_json(amendment_path, amendment)
    amendment_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    order = retained["unit_order"]
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "prior_completion": prior_descriptor,
        "inventory": dict(prior["inventory"]),
        "gate5_amendment": _descriptor(amendment_path, label="Gate 5 amendment"),
        "unit_order": order,
        "recovered_unit": unit_id,
        "selected_records": FAILED_SELECTED_RECORDS,
        "target_answer_retries": 1,
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_hardware_fit_failed_unit_recovery",
        hard_stop_hours=24,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    results = dict(prior["unit_results"])
    failures: dict[str, Any] = {}
    repaired: dict[str, Any] | None = None
    try:
        repaired = _run_unit(
            unit,
            python=python,
            work_root=work_root,
            control_root=control_root,
            project_revision=project_revision,
            project_revision_sha256=args.project_revision_sha256,
            scope=args.execution_scope_id,
            recovery_path=selector_path,
            recovery_sha256=selector_sha,
            expected_commit=args.expected_commit,
            framework_lock_id=_framework_lock_id(),
            admission_sha256=amendment_sha,
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            state_schema=STATE_SCHEMA,
        )
        results[unit_id] = repaired
    except (
        KeyError, OSError, RuntimeError, subprocess.SubprocessError, TypeError, ValueError
    ) as exc:
        failures[unit_id] = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc)[:4000],
        }
    results = {candidate: results[candidate] for candidate in order if candidate in results}
    successful = int(retained["target_execution"]["successful_target_generations"])
    missing = int(retained["target_execution"]["missing_responses"])
    attempted = int(retained["target_execution"]["target_attempts"])
    if repaired is not None:
        attempted += int(repaired["target_attempts"])
        successful += int(repaired["successful_target_generations"])
        missing += int(repaired["missing_responses"])
    completion = {
        "schema": SCHEMA,
        "status": "complete" if not failures else "complete_with_failures",
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "prior_completion": prior_descriptor,
        "inventory": dict(prior["inventory"]),
        "gate5_amendment": launch["gate5_amendment"],
        "unit_order": order,
        "retained_unit_order": [candidate for candidate in order if candidate != unit_id],
        "recovered_unit": unit_id,
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "successful_rows_repeated": 0,
        "historical_rows_mutated": False,
        "cross_condition_pooling_permitted": False,
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
        target_attempts=0 if repaired is None else int(repaired["target_attempts"]),
        successful_target_generations=(
            0 if repaired is None else int(repaired["successful_target_generations"])
        ),
    )
    finish_child_controller(work_root=work_root, control_root=control_root, exit_code=exit_code)
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-completion", type=Path, required=True)
    parser.add_argument("--prior-completion-sha256", required=True)
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
    except Exception as exc:  # noqa: BLE001 - terminal controller boundary
        print(f"hardware-fit failed-unit recovery failed: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
