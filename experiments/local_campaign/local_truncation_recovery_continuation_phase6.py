"""Continue an interrupted local hardware-fit campaign without repeated rows.

The retained campaign completed two units and durably checkpointed part of its
third unit before an Ollama response-body deadline defect stopped progress.
This controller validates that exact partition, terminalizes the interrupted
controller, extends the third unit's completed-ID selector, and runs only rows
that have never reached a durable terminal response.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import hashlib
from pathlib import Path
import re
import subprocess
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
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    LAUNCH_SCHEMA as PRIOR_LAUNCH_SCHEMA,
    STATE_SCHEMA as PRIOR_STATE_SCHEMA,
    configure_units,
    load_inventory,
    _safe_unit_id,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    RESULT_FIELDS,
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _external_job_id,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _sha256_json,
    _utc_now,
    _validate_descriptor,
)
from experiments.rig_web_app.external_measured import (
    register_external_measured_terminal,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-local-truncation-recovery-phase6-continuation/1"
LAUNCH_SCHEMA = "ura-local-truncation-recovery-phase6-continuation-launch/1"
SNAPSHOT_SCHEMA = "ura-local-truncation-recovery-interruption/1"
AMENDMENT_SCHEMA = "ura-gate5-local-hardware-fit-continuation/1"
STATE_SCHEMA = "ura-local-truncation-recovery-phase6-unit-state/3"
RETAINED_COMPLETE_COUNT = 2
PARTIAL_UNIT_INDEX = 3
EXPECTED_PARTIAL_ROWS = 424
EXPECTED_TOTAL_ROWS = 4_463
EXPECTED_RETAINED_ROWS = 1_749
EXPECTED_CONTINUATION_ROWS = EXPECTED_TOTAL_ROWS - EXPECTED_RETAINED_ROWS
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_control_root(path: Path, *, label: str) -> Path:
    root = path.resolve(strict=True)
    if root.is_symlink() or root.parent.name != "engineering":
        raise ValueError(f"{label} is not one canonical engineering campaign")
    return root


def _unit_order(inventory: Mapping[str, Any]) -> list[str]:
    units = inventory.get("units")
    if not isinstance(units, list):
        raise ValueError("hardware-fit inventory units changed")
    return [_safe_unit_id(index, item) for index, item in enumerate(units, 1)]


def _completed_result(
    *,
    unit_id: str,
    item: Mapping[str, Any],
    control_root: Path,
) -> dict[str, Any]:
    selected = int(item["summary"]["recovery_records"])
    state_path = control_root / "units" / unit_id / "state.json"
    level1_path = control_root / "units" / unit_id / "level1.json"
    state = _load_json(state_path, label=f"{unit_id} retained state")
    attempted, successful, missing = _counts_from_level1(
        _load_json(level1_path, label=f"{unit_id} retained Level 1")
    )
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
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


def extend_completed_selector(
    *,
    selector: Mapping[str, Any],
    selected_ids: Mapping[str, Sequence[str]],
    newly_completed_ids: Sequence[str],
) -> tuple[dict[str, Any], int]:
    """Add durable IDs to a completed selector and return remaining row count."""

    corpora = selector.get("corpora")
    if (
        selector.get("schema") != "ura-recovery-completed-selection/1"
        or not isinstance(corpora, dict)
        or set(corpora) != set(selected_ids)
        or len(newly_completed_ids) != len(set(newly_completed_ids))
    ):
        raise ValueError("interrupted recovery selector identity changed")
    pending = set(newly_completed_ids)
    rebuilt: dict[str, dict[str, Any]] = {}
    remaining_total = 0
    for corpus, ordered_value in selected_ids.items():
        ordered = list(ordered_value)
        entry = corpora.get(corpus)
        if not isinstance(entry, dict):
            raise ValueError(f"{corpus}: interrupted selector entry changed")
        prior = entry.get("completed_datapoint_ids")
        if (
            not isinstance(prior, list)
            or any(not isinstance(item, str) or not item for item in prior)
            or len(prior) != len(set(prior))
            or entry.get("selected_datapoint_ids_sha256") != _sha256_json(ordered)
            or entry.get("completed_datapoint_ids_sha256") != _sha256_json(prior)
        ):
            raise ValueError(f"{corpus}: interrupted completed selector changed")
        additions = [item for item in ordered if item in pending]
        pending.difference_update(additions)
        completed = sorted(set(prior) | set(additions))
        if not set(completed).issubset(ordered):
            raise ValueError(f"{corpus}: continuation selector leaves the selection")
        if len(completed) == len(ordered):
            continue
        remaining = [item for item in ordered if item not in set(completed)]
        rebuilt[corpus] = {
            "completed_record_count": len(completed),
            "selected_datapoint_ids_sha256": _sha256_json(ordered),
            "completed_datapoint_ids": completed,
            "completed_datapoint_ids_sha256": _sha256_json(completed),
            "remaining_datapoint_ids_sha256": _sha256_json(remaining),
        }
        remaining_total += len(remaining)
    if pending:
        raise ValueError("durable interrupted rows are absent from the selection")
    if not rebuilt or remaining_total < 1:
        raise ValueError("interrupted continuation contains no unfinished row")
    return {
        "schema": "ura-recovery-completed-selection/1",
        "corpora": rebuilt,
    }, remaining_total


def _partial_partition(
    *,
    item: Mapping[str, Any],
    unit_id: str,
    prior_root: Path,
    runner_root: Path,
    expected_rows: int,
) -> tuple[dict[str, Any], dict[str, Any], int, int]:
    state_path = prior_root / "units" / unit_id / "state.json"
    state = _load_json(state_path, label=f"{unit_id} interrupted state")
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
        or state.get("selected_records") != int(item["summary"]["recovery_records"])
        or (prior_root / "units" / unit_id / "level1.json").exists()
    ):
        raise ValueError("interrupted partial-unit state changed")
    argv = state.get("runner_argv")
    if not isinstance(argv, list) or any(not isinstance(value, str) for value in argv):
        raise ValueError("interrupted partial-unit argv changed")
    result_root = Path(str(state.get("result_root", ""))).resolve(strict=True)
    if result_root != runner_root / unit_id / prior_root.name:
        raise ValueError("interrupted partial result root changed")
    attempts, outcomes, attempt_files, response_files = _durable_outcomes(result_root)
    durable_ids = list(attempts.values())
    allowed = {
        "usable_first_response",
        "recovered_after_retry",
        "failed_output",
        "input_incompatible",
    }
    if (
        len(durable_ids) != expected_rows
        or len(durable_ids) != len(set(durable_ids))
        or set(outcomes) != set(durable_ids)
        or any(status not in allowed for status in outcomes.values())
    ):
        raise ValueError("interrupted durable-row partition changed")

    selected_rows, audits = _selected_rows(argv)
    old_selector, _binding = run_matrix.load_recovery_completed_prefix(
        _option(argv, "--recovery-completed-prefix"),
        _option(argv, "--recovery-completed-prefix-sha256"),
    )
    if old_selector is None:
        raise ValueError("interrupted partial unit lost its recovery selector")
    eligible_ids: list[str] = []
    selected_ids: dict[str, list[str]] = {}
    for corpus, rows in selected_rows.items():
        selected_ids[corpus] = [row.id for row in rows]
        eligible, _audit = run_matrix.apply_recovery_completed_prefix(
            corpus, rows, audits[corpus], old_selector
        )
        eligible_ids.extend(row.id for row in eligible)
    if durable_ids != eligible_ids[:expected_rows]:
        raise ValueError("interrupted rows are not the exact eligible prefix")
    selector, remaining = extend_completed_selector(
        selector=item["recovery_selection"],
        selected_ids=selected_ids,
        newly_completed_ids=durable_ids,
    )
    expected_remaining = int(item["summary"]["recovery_records"]) - expected_rows
    if remaining != expected_remaining:
        raise ValueError("interrupted continuation row count changed")
    missing = sum(status in {"failed_output", "input_incompatible"} for status in outcomes.values())
    evidence = {
        "unit_id": unit_id,
        "state": _descriptor(state_path, label="interrupted partial state"),
        "result_root": str(result_root),
        "attempt_files": [
            _descriptor(path, label="interrupted partial attempts") for path in attempt_files
        ],
        "response_files": [
            _descriptor(path, label="interrupted partial responses") for path in response_files
        ],
        "durable_rows": expected_rows,
        "successful_target_generations": expected_rows - missing,
        "missing_responses": missing,
        "durable_datapoint_ids_sha256": _sha256_json(durable_ids),
        "metric_grid_complete": False,
    }
    return selector, evidence, expected_rows - missing, missing


def inspect_interrupted_campaign(
    *,
    prior_root: Path,
    inventory: Mapping[str, Any],
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the two-complete, one-partial, remaining-unstarted partition."""

    units = inventory["units"]
    order = _unit_order(inventory)
    if (
        len(order) != 25
        or sum(int(item["summary"]["recovery_records"]) for item in units) != EXPECTED_TOTAL_ROWS
    ):
        raise ValueError("interrupted hardware-fit inventory changed")
    if (prior_root / "completion.json").exists() or (prior_root / ".exit").exists():
        raise ValueError("prior hardware-fit campaign is already terminal")
    launch_path = prior_root / "launch.json"
    launch = _load_json(launch_path, label="interrupted hardware-fit launch")
    inventory_descriptor = launch.get("inventory")
    if (
        launch.get("schema") != PRIOR_LAUNCH_SCHEMA
        or launch.get("runner_code_version") != CODE_VERSION
        or launch.get("unit_order") != order
        or launch.get("selected_records") != EXPECTED_TOTAL_ROWS
        or launch.get("target_answer_retries") != 1
        or launch.get("no_completed_rows_repeated") is not True
        or not isinstance(inventory_descriptor, dict)
    ):
        raise ValueError("interrupted hardware-fit launch changed")

    for index, (unit_id, item) in enumerate(zip(order, units, strict=True)):
        selector_path = prior_root / "inputs" / f"{unit_id}.json"
        config_path = prior_root / "configs" / f"{unit_id}.json"
        if (
            _load_json(selector_path, label=f"{unit_id} retained selector")
            != item["recovery_selection"]
            or _load_json(config_path, label=f"{unit_id} retained config")
            != item["hardware_fit_local_config"]
        ):
            raise ValueError(f"{unit_id} retained input changed")
        if index < PARTIAL_UNIT_INDEX:
            state = _load_json(
                prior_root / "units" / unit_id / "state.json",
                label=f"{unit_id} retained measured state",
            )
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
                raise ValueError(f"{unit_id} retained measured binding changed")

    retained: dict[str, dict[str, Any]] = {}
    for index in range(RETAINED_COMPLETE_COUNT):
        unit_id = order[index]
        retained[unit_id] = _completed_result(
            unit_id=unit_id,
            item=units[index],
            control_root=prior_root,
        )
    partial_id = order[PARTIAL_UNIT_INDEX - 1]
    selector, partial, partial_successful, partial_missing = _partial_partition(
        item=units[PARTIAL_UNIT_INDEX - 1],
        unit_id=partial_id,
        prior_root=prior_root,
        runner_root=runner_root,
        expected_rows=EXPECTED_PARTIAL_ROWS,
    )
    for index in range(PARTIAL_UNIT_INDEX, len(order)):
        unit_id = order[index]
        state = prior_root / "units" / unit_id / "state.json"
        result = runner_root / unit_id / prior_root.name
        if state.exists() or result.exists():
            raise ValueError(f"{unit_id} is not an unstarted retained unit")

    continuation_items: list[dict[str, Any]] = []
    for index in range(PARTIAL_UNIT_INDEX - 1, len(units)):
        copied = dict(units[index])
        copied["summary"] = dict(copied["summary"])
        if index == PARTIAL_UNIT_INDEX - 1:
            copied["recovery_selection"] = selector
            copied["summary"]["recovery_records"] -= EXPECTED_PARTIAL_ROWS
        continuation_items.append(copied)
    retained_attempts = sum(int(result["target_attempts"]) for result in retained.values())
    retained_successful = sum(
        int(result["successful_target_generations"]) for result in retained.values()
    )
    retained_missing = sum(int(result["missing_responses"]) for result in retained.values())
    return {
        "launch": _descriptor(launch_path, label="interrupted hardware-fit launch"),
        "retained_results": retained,
        "partial": partial,
        "continuation_inventory": {"units": continuation_items},
        "retained_accounting": {
            "target_attempts": retained_attempts + EXPECTED_PARTIAL_ROWS,
            "successful_target_generations": retained_successful + partial_successful,
            "missing_responses": retained_missing + partial_missing,
        },
        "order": order,
    }


def _validate_phase7_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    resolved = completion_path.resolve(strict=True)
    control_root = resolved.parent
    completion = _load_json(resolved, label="continued hardware-fit completion")
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "prior_interruption",
        "inventory",
        "gate5_amendment",
        "unit_order",
        "retained_unit_order",
        "continuation_unit_order",
        "unit_results",
        "unit_failures",
        "partial_lifecycle",
        "target_execution",
        "planned_unique_rows",
        "successful_rows_repeated",
        "cross_condition_pooling_permitted",
        "historical_rows_mutated",
        "paid_provider_calls",
    }
    if (
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != CODE_VERSION
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_failures") != {}
        or completion.get("planned_unique_rows") != EXPECTED_TOTAL_ROWS
        or completion.get("successful_rows_repeated") != 0
        or completion.get("cross_condition_pooling_permitted") is not False
        or completion.get("historical_rows_mutated") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("continued hardware-fit completion contract changed")

    snapshot_path = _validate_descriptor(
        completion.get("prior_interruption"), label="hardware-fit interruption"
    )
    snapshot = _load_json(snapshot_path, label="hardware-fit interruption")
    inventory_path = _validate_descriptor(
        completion.get("inventory"), label="hardware-fit inventory"
    )
    inventory = load_inventory(inventory_path, str(completion["inventory"].get("sha256", "")))
    order = _unit_order(inventory)
    retained_order = order[:RETAINED_COMPLETE_COUNT]
    continuation_order = order[PARTIAL_UNIT_INDEX - 1 :]
    prior_root = Path(str(snapshot.get("prior_control_root", ""))).resolve(strict=True)
    inspect_terminalized_campaign(
        prior_root=prior_root,
        inventory=inventory,
        runner_root=runner_root.resolve(strict=True),
        snapshot=snapshot,
    )
    if (
        completion.get("unit_order") != order
        or completion.get("retained_unit_order") != retained_order
        or completion.get("continuation_unit_order") != continuation_order
        or snapshot_path != control_root / "prior-interruption.json"
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or snapshot.get("order") != order
        or completion.get("partial_lifecycle") != snapshot.get("partial")
        or not isinstance(snapshot.get("continuation_inputs"), dict)
        or set(snapshot["continuation_inputs"]) != set(continuation_order)
    ):
        raise ValueError("continued hardware-fit partition changed")
    partial = snapshot["partial"]
    if not isinstance(partial, dict):
        raise ValueError("interrupted partial evidence changed")
    for field in ("state",):
        _validate_descriptor(partial.get(field), label=f"partial {field}")
    for field in ("attempt_files", "response_files"):
        descriptors = partial.get(field)
        if not isinstance(descriptors, list) or not descriptors:
            raise ValueError(f"interrupted partial {field} changed")
        for descriptor in descriptors:
            _validate_descriptor(descriptor, label=f"partial {field}")

    results = completion.get("unit_results")
    if not isinstance(results, dict) or set(results) != set(order):
        raise ValueError("continued hardware-fit result inventory changed")
    completion_descriptor = _descriptor(resolved, label="continued hardware-fit completion")
    snapshot_descriptor = _descriptor(snapshot_path, label="hardware-fit interruption")
    terminal_states: dict[str, str] = {}
    lifecycle_roots: dict[str, str] = {}
    lifecycle_evidence: dict[str, dict[str, object]] = {}
    lifecycle_revisions: dict[str, str] = {}
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility: list[dict[str, object]] = []
    metric_markers: list[dict[str, object]] = []
    metric_revisions: dict[str, str] = {}
    sources: set[str] = set()
    successful = int(snapshot["retained_accounting"]["successful_target_generations"])
    missing = int(snapshot["retained_accounting"]["missing_responses"])

    for index, (unit_id, item) in enumerate(zip(order, inventory["units"], strict=True)):
        if index < RETAINED_COMPLETE_COUNT:
            selected = int(item["summary"]["recovery_records"])
            physical_root = prior_root
            state_schema = PRIOR_STATE_SCHEMA
            evidence_completion = snapshot_descriptor
        else:
            selected = int(item["summary"]["recovery_records"])
            if index == PARTIAL_UNIT_INDEX - 1:
                selected -= EXPECTED_PARTIAL_ROWS
            physical_root = control_root
            state_schema = STATE_SCHEMA
            evidence_completion = completion_descriptor
        recovery_corpora = item["recovery_selection"]["corpora"]
        corpus = next(iter(recovery_corpora)) if len(recovery_corpora) == 1 else None
        validated = _validate_metric_result(
            results[unit_id],
            logical_lane=unit_id,
            physical_unit=unit_id,
            source_lane=str(item["source_lane"]),
            corpus=corpus,
            selected_records=selected,
            runner_root=runner_root,
            control_root=physical_root,
            state_schema=state_schema,
            completion=evidence_completion,
        )
        if index >= RETAINED_COMPLETE_COUNT:
            inputs = snapshot["continuation_inputs"][unit_id]
            if not isinstance(inputs, dict) or set(inputs) != {
                "selector",
                "config",
                "selected_records",
            }:
                raise ValueError(f"{unit_id} continuation input contract changed")
            selector_path = _validate_descriptor(
                inputs["selector"], label=f"{unit_id} continuation selector"
            )
            config_path = _validate_descriptor(
                inputs["config"], label=f"{unit_id} continuation config"
            )
            state_path = _validate_descriptor(
                results[unit_id]["state"], label=f"{unit_id} continuation state"
            )
            state = _load_json(state_path, label=f"{unit_id} continuation state")
            argv = state.get("runner_argv")
            if (
                inputs["selected_records"] != selected
                or not isinstance(argv, list)
                or _option(argv, "--recovery-completed-prefix") != str(selector_path)
                or _option(argv, "--recovery-completed-prefix-sha256")
                != inputs["selector"]["sha256"]
                or _option(argv, "--local-config") != str(config_path)
                or _option(argv, "--local-config-sha256") != inputs["config"]["sha256"]
            ):
                raise ValueError(f"{unit_id} continuation binding changed")
        terminal_states[unit_id] = "measured_complete"
        lifecycle_roots[unit_id] = str(validated["root"])
        evidence = dict(validated["evidence"])
        if index == PARTIAL_UNIT_INDEX - 1:
            evidence["interrupted_durable_prefix"] = dict(snapshot["partial"])
        lifecycle_evidence[unit_id] = evidence
        lifecycle_revisions[unit_id] = str(validated["revision"])
        metric_roots[unit_id] = str(validated["root"])
        metric_evidence[unit_id] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_eligibility.append(dict(validated["eligibility_plan"]))
        metric_markers.extend(validated["completion_markers"])
        metric_revisions[unit_id] = str(validated["revision"])
        sources.add(str(validated["source"]))
        if index >= RETAINED_COMPLETE_COUNT:
            successful += int(validated["successful"])
            missing += int(validated["missing"])
    accounting = {
        "target_attempts": EXPECTED_TOTAL_ROWS,
        "successful_target_generations": successful,
        "missing_responses": missing,
    }
    if completion.get("target_execution") != accounting or len(sources) != 1:
        raise ValueError("continued hardware-fit accounting changed")
    revision_strata: dict[str, list[str]] = {}
    lifecycle_strata: dict[str, list[str]] = {}
    for unit_id in order:
        revision_strata.setdefault(metric_revisions[unit_id], []).append(unit_id)
        lifecycle_strata.setdefault(lifecycle_revisions[unit_id], []).append(unit_id)
    return {
        "completion": completion_descriptor,
        "inventory": dict(completion["inventory"]),
        "runner_code_version": CODE_VERSION,
        "output_policy_stratum": "hardware_fit_context_and_maximum_available_output",
        "unit_order": order,
        "terminal_states": terminal_states,
        "lifecycle_roots": lifecycle_roots,
        "lifecycle_evidence": lifecycle_evidence,
        "lifecycle_revision_strata": lifecycle_strata,
        "lifecycle_project_revision_receipt_sha256": lifecycle_revisions,
        "metric_lane_order": order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility,
        "metric_completion_markers": metric_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": metric_revisions,
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": accounting,
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "successful_rows_repeated": 0,
        "cross_condition_pooling_permitted": False,
    }


def inspect_terminalized_campaign(
    *,
    prior_root: Path,
    inventory: Mapping[str, Any],
    runner_root: Path,
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    """Recheck the retained root after its explicit interruption marker exists."""

    marker_path = prior_root / "interruption.json"
    exit_path = prior_root / ".exit"
    marker = _load_json(marker_path, label="hardware-fit interruption marker")
    if (
        marker.get("schema") != "ura-local-hardware-fit-interrupted/1"
        or marker.get("exit_code") != 125
        or marker.get("durable_rows") != EXPECTED_RETAINED_ROWS
        or marker.get("successful_rows_repeated") != 0
        or _stable_file(exit_path, label="hardware-fit interrupted exit") != b"125\n"
        or snapshot.get("marker") != _descriptor(marker_path, label="interruption marker")
    ):
        raise ValueError("hardware-fit interruption marker changed")
    if (prior_root / "completion.json").exists():
        raise ValueError("interrupted hardware-fit root gained a completion")
    return {"marker": marker, "order": _unit_order(inventory)}


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = (work_root / "runs/thesis/runner").resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh hardware-fit continuation root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("hardware-fit continuation root must be one direct campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if (
        hashlib.sha256(_stable_file(project_revision, label="project revision")).hexdigest()
        != args.project_revision_sha256
    ):
        raise ValueError("project revision digest changed")
    inventory_path = args.inventory.resolve(strict=True)
    inventory = load_inventory(inventory_path, args.inventory_sha256)
    prior_root = _canonical_control_root(
        args.prior_control_root, label="interrupted hardware-fit root"
    )
    if Path(f"/proc/{args.interrupted_controller_pid}").exists():
        raise ValueError("interrupted controller process is still alive")
    inspected = inspect_interrupted_campaign(
        prior_root=prior_root,
        inventory=inventory,
        runner_root=runner_root,
    )

    control_root.mkdir(mode=0o700)
    for name in ("units", "inputs", "configs"):
        (control_root / name).mkdir(mode=0o700)
    marker = {
        "schema": "ura-local-hardware-fit-interrupted/1",
        "status": "interrupted",
        "reason": "ollama_response_body_deadline_not_enforced",
        "exit_code": 125,
        "interrupted_at_utc": _utc_now(),
        "durable_rows": EXPECTED_RETAINED_ROWS,
        "successful_rows_repeated": 0,
    }
    marker_path = prior_root / "interruption.json"
    _create_json(marker_path, marker)
    with (prior_root / ".exit").open("xb") as handle:
        handle.write(b"125\n")
    register_external_measured_terminal(
        work_root / "runs",
        job_id=_external_job_id(prior_root, inspected["order"][2]),
        exit_code=125,
    )
    publish_target_execution(
        work_root=work_root,
        control_root=prior_root,
        target_attempts=EXPECTED_RETAINED_ROWS,
        successful_target_generations=int(
            inspected["retained_accounting"]["successful_target_generations"]
        ),
    )
    finish_child_controller(work_root=work_root, control_root=prior_root, exit_code=125)

    configured = configure_units(inspected["continuation_inventory"], control_root=control_root)
    continuation_order = [unit.unit_id for unit, _path, _sha in configured]
    expected_continuation = inspected["order"][PARTIAL_UNIT_INDEX - 1 :]
    remaining_rows = sum(unit.selected_records for unit, _path, _sha in configured)
    if (
        continuation_order != expected_continuation
        or remaining_rows != EXPECTED_CONTINUATION_ROWS
    ):
        raise ValueError("hardware-fit continuation inventory changed")
    continuation_inputs = {}
    for unit, selector_path, _selector_sha in configured:
        config_path = Path(_option(unit.spec["base_argv"], "--local-config"))
        continuation_inputs[unit.unit_id] = {
            "selector": _descriptor(selector_path, label=f"{unit.unit_id} continuation selector"),
            "config": _descriptor(config_path, label=f"{unit.unit_id} continuation config"),
            "selected_records": unit.selected_records,
        }
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "created_at_utc": _utc_now(),
        "prior_control_root": str(prior_root),
        "prior_launch": inspected["launch"],
        "marker": _descriptor(marker_path, label="interruption marker"),
        "order": inspected["order"],
        "retained_results": inspected["retained_results"],
        "partial": inspected["partial"],
        "retained_accounting": inspected["retained_accounting"],
        "continuation_inputs": continuation_inputs,
        "successful_rows_repeated": 0,
    }
    snapshot_path = control_root / "prior-interruption.json"
    _create_json(snapshot_path, snapshot)
    amendment = {
        "schema": AMENDMENT_SCHEMA,
        "approved_scope": "never_completed_rows_after_bound_interruption",
        "inventory": _descriptor(inventory_path, label="hardware-fit inventory"),
        "prior_interruption": _descriptor(snapshot_path, label="hardware-fit interruption"),
        "selected_records": remaining_rows,
        "retained_durable_rows": EXPECTED_RETAINED_ROWS,
        "target_answer_retries": 1,
        "max_total_target_calls": remaining_rows * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "per_unit_deadline_seconds": 86_400,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
    }
    amendment_path = control_root / "gate5-continuation-amendment.json"
    _create_json(amendment_path, amendment)
    amendment_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "project_revision": _descriptor(project_revision, label="continuation project revision"),
        "inventory": amendment["inventory"],
        "prior_interruption": amendment["prior_interruption"],
        "gate5_amendment": _descriptor(amendment_path, label="continuation Gate 5 amendment"),
        "unit_order": continuation_order,
        "selected_records": remaining_rows,
        "target_answer_retries": 1,
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
        evidence_class="measured_local_hardware_fit_continuation",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results = dict(inspected["retained_results"])
    failures: dict[str, Any] = {}
    continuation_attempts = continuation_successful = continuation_missing = 0
    for unit, selector_path, selector_sha in configured:
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
            )
            results[unit.unit_id] = result
            continuation_attempts += int(result["target_attempts"])
            continuation_successful += int(result["successful_target_generations"])
            continuation_missing += int(result["missing_responses"])
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
        "unit_order": inspected["order"],
        "retained_unit_order": inspected["order"][:RETAINED_COMPLETE_COUNT],
        "continuation_unit_order": continuation_order,
        "unit_results": results,
        "unit_failures": failures,
        "partial_lifecycle": inspected["partial"],
        "target_execution": {
            "target_attempts": int(retained["target_attempts"]) + continuation_attempts,
            "successful_target_generations": int(retained["successful_target_generations"])
            + continuation_successful,
            "missing_responses": int(retained["missing_responses"]) + continuation_missing,
        },
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "successful_rows_repeated": 0,
        "cross_condition_pooling_permitted": False,
        "historical_rows_mutated": False,
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
    finish_child_controller(work_root=work_root, control_root=control_root, exit_code=exit_code)
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-control-root", type=Path, required=True)
    parser.add_argument("--interrupted-controller-pid", type=int, required=True)
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
    if args.interrupted_controller_pid < 2:
        raise ValueError("interrupted controller PID is invalid")
    if HEX64.fullmatch(args.inventory_sha256) is None:
        raise ValueError("inventory SHA-256 is invalid")
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    return run(args)


def validate_phase7_completion(completion_path: Path, *, runner_root: Path) -> dict[str, Any]:
    return _validate_phase7_completion(completion_path, runner_root=runner_root)


if __name__ == "__main__":
    raise SystemExit(main())
