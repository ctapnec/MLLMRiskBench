"""Continue the bounded-output tail after vLLM retained CUDA allocations.

The predecessor durably completed two units and ten rows of its third unit.
Its remaining cells failed before target calls because vLLM retained model
weights after the documented in-process shutdown.  This controller preserves
those 76 durable rows, extends the completed-ID selector for the partial unit,
and executes only the remaining 94 rows under the current project revision.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from experiments import run_matrix
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import _descriptor, _stable_file
from experiments.local_campaign.current_ollama_phase6 import _counts_from_level1
from experiments.local_campaign.failed_output_recovery_phase6 import (
    _durable_outcomes,
    _selected_rows,
)
from experiments.local_campaign.local_bounded_output_continuation_phase6 import (
    STATE_SCHEMA as PRIOR_STATE_SCHEMA,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    _unit_order,
    extend_completed_selector,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    configure_units,
    load_inventory,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import RESULT_FIELDS
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _sha256_json,
    _utc_now,
    _validate_descriptor,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-local-bounded-output-cuda-recovery-phase6/1"
LAUNCH_SCHEMA = "ura-local-bounded-output-cuda-recovery-phase6-launch/1"
SNAPSHOT_SCHEMA = "ura-local-bounded-output-cuda-interruption/1"
STATE_SCHEMA = "ura-local-bounded-output-cuda-recovery-phase6-unit-state/1"
AMENDMENT_SCHEMA = "ura-gate5-local-bounded-output-cuda-recovery/1"
PRIOR_LAUNCH_SCHEMA = "ura-local-bounded-output-continuation-phase6-launch/2"
FIRST_UNIT_INDEX = 21
PARTIAL_UNIT_INDEX = 23
EXPECTED_UNIT_COUNT = 25
EXPECTED_TAIL_ROWS = 170
EXPECTED_DURABLE_ROWS = 76
EXPECTED_PARTIAL_ROWS = 10
EXPECTED_RECOVERY_ROWS = 94
EXPECTED_TOTAL_ROWS = 4_463
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_campaign(path: Path, *, label: str) -> Path:
    root = path.resolve(strict=True)
    if root.is_symlink() or root.parent.name != "engineering":
        raise ValueError(f"{label} is not one canonical engineering campaign")
    return root


def _completed_result(
    *, unit_id: str, item: Mapping[str, Any], prior_root: Path
) -> dict[str, Any]:
    state_path = prior_root / "units" / unit_id / "state.json"
    level1_path = prior_root / "units" / unit_id / "level1.json"
    state = _load_json(state_path, label=f"{unit_id} retained state")
    selected = int(item["summary"]["recovery_records"])
    attempted, successful, missing = _counts_from_level1(
        _load_json(level1_path, label=f"{unit_id} retained Level 1")
    )
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
        or state.get("source_lane") != item.get("source_lane")
        or state.get("selected_records") != selected
        or attempted != selected
    ):
        raise ValueError(f"{unit_id} retained completion changed")
    result = {
        "status": "complete",
        "unit_id": unit_id,
        "source_lane": item["source_lane"],
        "corpus": state.get("corpus"),
        "selected_records": selected,
        "target_answer_retries": 1,
        "target_call_cap": selected * 2,
        "target_attempts": attempted,
        "successful_target_generations": successful,
        "missing_responses": missing,
        "result_root": state["result_root"],
        "state": _descriptor(state_path, label=f"{unit_id} retained state"),
        "level1": _descriptor(level1_path, label=f"{unit_id} retained Level 1"),
    }
    if set(result) != RESULT_FIELDS:
        raise AssertionError("retained result field inventory changed")
    return result


def _partial_partition(
    *, item: Mapping[str, Any], unit_id: str, prior_root: Path, runner_root: Path
) -> tuple[dict[str, Any], dict[str, Any], int, int]:
    state_path = prior_root / "units" / unit_id / "state.json"
    state = _load_json(state_path, label="CUDA-interrupted unit state")
    argv = state.get("runner_argv")
    selected = int(item["summary"]["recovery_records"])
    result_root = Path(str(state.get("result_root", ""))).resolve(strict=True)
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
        or state.get("selected_records") != selected
        or not isinstance(argv, list)
        or any(not isinstance(value, str) for value in argv)
        or result_root != runner_root / unit_id / prior_root.name
        or (prior_root / "units" / unit_id / "level1.json").exists()
    ):
        raise ValueError("CUDA-interrupted unit boundary changed")

    attempts, outcomes, attempt_files, response_files = _durable_outcomes(result_root)
    durable_ids = list(attempts.values())
    if (
        len(durable_ids) != EXPECTED_PARTIAL_ROWS
        or len(durable_ids) != len(set(durable_ids))
        or set(outcomes) != set(durable_ids)
        or any(
            status
            not in {
                "usable_first_response",
                "recovered_after_retry",
                "failed_output",
                "input_incompatible",
            }
            for status in outcomes.values()
        )
    ):
        raise ValueError("CUDA-interrupted durable-row partition changed")

    selected_rows, audits = _selected_rows(argv)
    old_selector, _binding = run_matrix.load_recovery_completed_prefix(
        _option(argv, "--recovery-completed-prefix"),
        _option(argv, "--recovery-completed-prefix-sha256"),
    )
    if old_selector is None:
        raise ValueError("CUDA-interrupted unit lost its completed selector")
    selected_ids: dict[str, list[str]] = {}
    eligible_ids: list[str] = []
    for corpus, rows in selected_rows.items():
        selected_ids[corpus] = [row.id for row in rows]
        eligible, _audit = run_matrix.apply_recovery_completed_prefix(
            corpus, rows, audits[corpus], old_selector
        )
        eligible_ids.extend(row.id for row in eligible)
    if durable_ids != eligible_ids[:EXPECTED_PARTIAL_ROWS]:
        raise ValueError("durable rows are not the exact eligible prefix")
    selector, remaining = extend_completed_selector(
        selector=item["recovery_selection"],
        selected_ids=selected_ids,
        newly_completed_ids=durable_ids,
    )
    if remaining != selected - EXPECTED_PARTIAL_ROWS:
        raise ValueError("CUDA recovery remaining-row count changed")
    missing = sum(
        status in {"failed_output", "input_incompatible"}
        for status in outcomes.values()
    )
    evidence = {
        "unit_id": unit_id,
        "state": _descriptor(state_path, label="CUDA-interrupted unit state"),
        "result_root": str(result_root),
        "attempt_files": [
            _descriptor(path, label="CUDA-interrupted attempts")
            for path in attempt_files
        ],
        "response_files": [
            _descriptor(path, label="CUDA-interrupted responses")
            for path in response_files
        ],
        "durable_rows": EXPECTED_PARTIAL_ROWS,
        "successful_target_generations": EXPECTED_PARTIAL_ROWS - missing,
        "missing_responses": missing,
        "durable_datapoint_ids_sha256": _sha256_json(durable_ids),
        "metric_grid_complete": False,
    }
    return selector, evidence, EXPECTED_PARTIAL_ROWS - missing, missing


def inspect_interrupted_campaign(
    *, prior_root: Path, inventory: Mapping[str, Any], runner_root: Path
) -> dict[str, Any]:
    units = inventory.get("units")
    order = _unit_order(inventory)
    if (
        not isinstance(units, list)
        or len(order) != EXPECTED_UNIT_COUNT
        or (prior_root / "completion.json").exists()
        or (prior_root / "interruption.json").exists()
        or (prior_root / ".exit").exists()
    ):
        raise ValueError("interrupted bounded-output campaign shape changed")
    launch_path = prior_root / "launch.json"
    launch = _load_json(launch_path, label="interrupted bounded-output launch")
    tail_order = order[FIRST_UNIT_INDEX - 1 :]
    if (
        launch.get("schema") != PRIOR_LAUNCH_SCHEMA
        or launch.get("runner_code_version") != CODE_VERSION
        or launch.get("unit_order") != tail_order
        or launch.get("selected_records") != EXPECTED_TAIL_ROWS
        or launch.get("target_answer_retries") != 1
        or launch.get("no_valid_rows_repeated") is not True
    ):
        raise ValueError("interrupted bounded-output launch changed")

    retained: dict[str, dict[str, Any]] = {}
    for index in range(FIRST_UNIT_INDEX - 1, PARTIAL_UNIT_INDEX - 1):
        unit_id = order[index]
        retained[unit_id] = _completed_result(
            unit_id=unit_id, item=units[index], prior_root=prior_root
        )
    partial_id = order[PARTIAL_UNIT_INDEX - 1]
    selector, partial, partial_successful, partial_missing = _partial_partition(
        item=units[PARTIAL_UNIT_INDEX - 1],
        unit_id=partial_id,
        prior_root=prior_root,
        runner_root=runner_root,
    )
    for index in range(PARTIAL_UNIT_INDEX, EXPECTED_UNIT_COUNT):
        unit_id = order[index]
        if (
            (prior_root / "units" / unit_id / "state.json").exists()
            or (runner_root / unit_id / prior_root.name).exists()
        ):
            raise ValueError(f"{unit_id} is not an unstarted retained unit")

    continuation_items: list[dict[str, Any]] = []
    for index in range(PARTIAL_UNIT_INDEX - 1, EXPECTED_UNIT_COUNT):
        copied = dict(units[index])
        copied["summary"] = dict(copied["summary"])
        if index == PARTIAL_UNIT_INDEX - 1:
            copied["recovery_selection"] = selector
            copied["summary"]["recovery_records"] -= EXPECTED_PARTIAL_ROWS
        continuation_items.append(copied)
    remaining = sum(
        int(item["summary"]["recovery_records"])
        for item in continuation_items
    )
    retained_attempts = sum(int(value["target_attempts"]) for value in retained.values())
    retained_successful = sum(
        int(value["successful_target_generations"]) for value in retained.values()
    )
    retained_missing = sum(int(value["missing_responses"]) for value in retained.values())
    if retained_attempts + EXPECTED_PARTIAL_ROWS != EXPECTED_DURABLE_ROWS:
        raise ValueError("interrupted durable-row total changed")
    if remaining != EXPECTED_RECOVERY_ROWS:
        raise ValueError("CUDA recovery selection changed")
    return {
        "launch": _descriptor(launch_path, label="interrupted bounded-output launch"),
        "order": order,
        "tail_order": tail_order,
        "retained_results": retained,
        "partial": partial,
        "continuation_inventory": {"units": continuation_items},
        "retained_accounting": {
            "target_attempts": retained_attempts + EXPECTED_PARTIAL_ROWS,
            "successful_target_generations": retained_successful + partial_successful,
            "missing_responses": retained_missing + partial_missing,
        },
    }


def _terminalize_prior(
    *, prior_root: Path, work_root: Path, durable_rows: int, successful_rows: int
) -> dict[str, Any]:
    marker_path = prior_root / "interruption.json"
    marker = {
        "schema": "ura-local-bounded-output-cuda-interrupted/1",
        "status": "interrupted",
        "reason": "vllm_inprocess_cuda_allocation_retained_between_cells",
        "exit_code": 125,
        "interrupted_at_utc": _utc_now(),
        "durable_rows": durable_rows,
        "successful_rows_repeated": 0,
    }
    _create_json(marker_path, marker)
    with (prior_root / ".exit").open("xb") as handle:
        handle.write(b"125\n")
    publish_target_execution(
        work_root=work_root,
        control_root=prior_root,
        target_attempts=durable_rows,
        successful_target_generations=successful_rows,
    )
    finish_child_controller(work_root=work_root, control_root=prior_root, exit_code=125)
    return _descriptor(marker_path, label="CUDA interruption marker")


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = (work_root / "runs/thesis/runner").resolve(strict=True)
    prior_root = _canonical_campaign(args.prior_root, label="prior root")
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh CUDA recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("CUDA recovery root must be one direct engineering campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    inventory_path = args.inventory.resolve(strict=True)
    inventory = load_inventory(inventory_path, args.inventory_sha256)
    inspected = inspect_interrupted_campaign(
        prior_root=prior_root, inventory=inventory, runner_root=runner_root
    )

    control_root.mkdir(mode=0o700)
    for name in ("units", "inputs", "configs"):
        (control_root / name).mkdir(mode=0o700)
    configured = configure_units(
        inspected["continuation_inventory"],
        control_root=control_root,
        start_index=PARTIAL_UNIT_INDEX,
    )
    continuation_order = [unit.unit_id for unit, _path, _sha in configured]
    if continuation_order != inspected["order"][PARTIAL_UNIT_INDEX - 1 :]:
        raise ValueError("CUDA recovery unit order changed")
    prior_descriptor = _descriptor(prior_root / "launch.json", label="prior launch")
    amendment = {
        "schema": AMENDMENT_SCHEMA,
        "approved_scope": "exact_rows_unfinished_after_vllm_cuda_retention",
        "prior_launch": prior_descriptor,
        "inventory": _descriptor(inventory_path, label="hardware-fit inventory"),
        "selected_records": EXPECTED_RECOVERY_ROWS,
        "target_answer_retries": 1,
        "max_total_target_calls": EXPECTED_RECOVERY_ROWS * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
    }
    amendment_path = control_root / "gate5-cuda-recovery-amendment.json"
    _create_json(amendment_path, amendment)
    amendment_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    prior_marker = _terminalize_prior(
        prior_root=prior_root,
        work_root=work_root,
        durable_rows=EXPECTED_DURABLE_ROWS,
        successful_rows=int(
            inspected["retained_accounting"]["successful_target_generations"]
        ),
    )
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "created_at_utc": _utc_now(),
        "prior_root": str(prior_root),
        "prior_launch": inspected["launch"],
        "prior_marker": prior_marker,
        "retained_results": inspected["retained_results"],
        "partial": inspected["partial"],
        "retained_accounting": inspected["retained_accounting"],
    }
    snapshot_path = control_root / "prior-interruption.json"
    _create_json(snapshot_path, snapshot)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "project_revision": _descriptor(project_revision, label="project revision"),
        "inventory": _descriptor(inventory_path, label="hardware-fit inventory"),
        "prior_interruption": _descriptor(snapshot_path, label="prior interruption"),
        "gate5_amendment": _descriptor(amendment_path, label="Gate 5 amendment"),
        "unit_order": continuation_order,
        "selected_records": EXPECTED_RECOVERY_ROWS,
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
        evidence_class="measured_local_bounded_output_cuda_recovery",
        hard_stop_hours=48,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    attempts = successful = missing = 0
    for unit, selector_path, selector_sha in configured:
        prior_canary = prior_root / "units" / unit.unit_id / "canary"
        try:
            result = _run_unit(
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
                validated_canary_root=(prior_canary if prior_canary.is_dir() else None),
            )
            results[unit.unit_id] = result
            attempts += int(result["target_attempts"])
            successful += int(result["successful_target_generations"])
            missing += int(result["missing_responses"])
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            failures[unit.unit_id] = {
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
            }
    retained = inspected["retained_accounting"]
    completion = {
        "schema": SCHEMA,
        "status": "complete" if not failures else "complete_with_failures",
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "prior_interruption": launch["prior_interruption"],
        "inventory": launch["inventory"],
        "gate5_amendment": launch["gate5_amendment"],
        "unit_order": continuation_order,
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": int(retained["target_attempts"]) + attempts,
            "successful_target_generations": int(
                retained["successful_target_generations"]
            ) + successful,
            "missing_responses": int(retained["missing_responses"]) + missing,
        },
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "tail_planned_unique_rows": EXPECTED_TAIL_ROWS,
        "recovery_selected_records": EXPECTED_RECOVERY_ROWS,
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
        target_attempts=attempts,
        successful_target_generations=successful,
    )
    finish_child_controller(
        work_root=work_root, control_root=control_root, exit_code=exit_code
    )
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-sha256", required=True)
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
    if HEX64.fullmatch(args.inventory_sha256) is None:
        raise ValueError("inventory SHA-256 is invalid")
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    try:
        return run(args)
    except Exception as exc:  # noqa: BLE001 - terminal controller boundary
        print(f"CUDA recovery failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
