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
    EXPECTED_USABLE as BOUNDED_RETAINED_USABLE,
    PARTIAL_INDEX as BOUNDED_PARTIAL_INDEX,
    SNAPSHOT_SCHEMA as BOUNDED_SNAPSHOT_SCHEMA,
    STATE_SCHEMA as PRIOR_STATE_SCHEMA,
    _expand_compact_retained_result,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    SNAPSHOT_SCHEMA as RETAINED_SNAPSHOT_SCHEMA,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    STATE_SCHEMA as MIDDLE_STATE_SCHEMA,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    _unit_order,
    extend_completed_selector,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    STATE_SCHEMA as BASE_STATE_SCHEMA,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    configure_units,
    load_inventory,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    RESULT_FIELDS,
    _validate_metric_result,
)
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
    selected = int(state.get("selected_records", 0))
    attempted, successful, missing = _counts_from_level1(
        _load_json(level1_path, label=f"{unit_id} retained Level 1")
    )
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
        or state.get("source_lane") != item.get("source_lane")
        or selected < 1
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


def _validate_pre_state_root(path: Path) -> list[dict[str, Any]] | None:
    """Accept only acquisition-copied evidence before measured state existed."""

    if not path.exists() and not path.is_symlink():
        return None
    root = path.resolve(strict=True)
    if path.is_symlink() or not root.is_dir():
        raise ValueError("pre-state result root is not one canonical directory")
    files = sorted(root.iterdir())
    patterns = (
        "live-attestation-*.json",
        "project-revision-*.project-revision.json",
        "request-envelope-*.request-envelope.json",
        "source-conformance-*.json",
    )
    expected: list[Path] = []
    for pattern in patterns:
        matches = sorted(root.glob(pattern))
        if len(matches) != 1:
            raise ValueError("pre-state result evidence shape changed")
        expected.extend(matches)
    if files != sorted(expected) or any(
        candidate.is_symlink() or not candidate.is_file() for candidate in files
    ):
        raise ValueError("pre-state result contains measured or ambiguous artifacts")
    return [
        _descriptor(candidate, label="pre-state result evidence")
        for candidate in files
    ]


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
    pre_state_units: dict[str, list[dict[str, Any]]] = {}
    for index in range(PARTIAL_UNIT_INDEX, EXPECTED_UNIT_COUNT):
        unit_id = order[index]
        if (prior_root / "units" / unit_id / "state.json").exists():
            raise ValueError(f"{unit_id} is not an unstarted retained unit")
        pre_state = _validate_pre_state_root(runner_root / unit_id / prior_root.name)
        if pre_state is not None:
            pre_state_units[unit_id] = pre_state

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
        "pre_state_units": pre_state_units,
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


def _validate_prior_terminal(prior_root: Path) -> dict[str, Any]:
    marker_path = prior_root / "interruption.json"
    marker = _load_json(marker_path, label="CUDA-interrupted predecessor marker")
    if (
        set(marker)
        != {
            "schema",
            "status",
            "reason",
            "exit_code",
            "interrupted_at_utc",
            "durable_rows",
            "successful_rows_repeated",
        }
        or marker.get("schema") != "ura-local-bounded-output-cuda-interrupted/1"
        or marker.get("status") != "interrupted"
        or marker.get("reason")
        != "vllm_inprocess_cuda_allocation_retained_between_cells"
        or marker.get("exit_code") != 125
        or marker.get("durable_rows") != EXPECTED_DURABLE_ROWS
        or marker.get("successful_rows_repeated") != 0
        or _stable_file(prior_root / ".exit", label="CUDA-interrupted exit")
        != b"125\n"
        or (prior_root / "completion.json").exists()
    ):
        raise ValueError("CUDA-interrupted predecessor terminal changed")
    return _descriptor(marker_path, label="CUDA-interrupted predecessor marker")


def validate_completion(completion_path: Path, *, runner_root: Path) -> dict[str, Any]:
    """Validate the complete 25-unit population without pooling split revisions."""

    resolved = completion_path.resolve(strict=True)
    control_root = resolved.parent
    runner_root = runner_root.resolve(strict=True)
    completion = _load_json(resolved, label="CUDA recovery completion")
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
        "unit_results",
        "unit_failures",
        "target_execution",
        "planned_unique_rows",
        "tail_planned_unique_rows",
        "recovery_selected_records",
        "successful_rows_repeated",
        "historical_rows_mutated",
        "cross_condition_pooling_permitted",
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
        or completion.get("tail_planned_unique_rows") != EXPECTED_TAIL_ROWS
        or completion.get("recovery_selected_records") != EXPECTED_RECOVERY_ROWS
        or completion.get("successful_rows_repeated") != 0
        or completion.get("historical_rows_mutated") is not False
        or completion.get("cross_condition_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("CUDA recovery completion contract changed")

    completion_descriptor = _descriptor(resolved, label="CUDA recovery completion")
    launch_path = control_root / "launch.json"
    launch = _load_json(launch_path, label="CUDA recovery launch")
    launch_fields = {
        "schema",
        "started_at_utc",
        "expected_commit",
        "runner_code_version",
        "execution_scope_id",
        "project_revision",
        "inventory",
        "prior_interruption",
        "gate5_amendment",
        "unit_order",
        "selected_records",
        "target_answer_retries",
        "no_completed_rows_repeated",
        "paid_provider_calls",
    }
    if (
        set(launch) != launch_fields
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("expected_commit") != completion.get("expected_commit")
        or launch.get("runner_code_version") != CODE_VERSION
        or launch.get("inventory") != completion.get("inventory")
        or launch.get("prior_interruption") != completion.get("prior_interruption")
        or launch.get("gate5_amendment") != completion.get("gate5_amendment")
        or launch.get("unit_order") != completion.get("unit_order")
        or launch.get("selected_records") != EXPECTED_RECOVERY_ROWS
        or launch.get("target_answer_retries") != 1
        or launch.get("no_completed_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
    ):
        raise ValueError("CUDA recovery launch contract changed")

    inventory_path = _validate_descriptor(
        completion["inventory"], label="CUDA recovery inventory"
    )
    inventory = load_inventory(
        inventory_path, str(completion["inventory"].get("sha256", ""))
    )
    order = _unit_order(inventory)
    recovery_order = order[PARTIAL_UNIT_INDEX - 1 :]
    results = completion.get("unit_results")
    if (
        len(order) != EXPECTED_UNIT_COUNT
        or completion.get("unit_order") != recovery_order
        or not isinstance(results, dict)
        or set(results) != set(recovery_order)
    ):
        raise ValueError("CUDA recovery inventory changed")

    amendment_path = _validate_descriptor(
        completion["gate5_amendment"], label="CUDA recovery Gate 5 amendment"
    )
    amendment = _load_json(amendment_path, label="CUDA recovery Gate 5 amendment")
    if (
        amendment_path != control_root / "gate5-cuda-recovery-amendment.json"
        or amendment.get("schema") != AMENDMENT_SCHEMA
        or amendment.get("approved_scope")
        != "exact_rows_unfinished_after_vllm_cuda_retention"
        or amendment.get("inventory") != completion.get("inventory")
        or amendment.get("selected_records") != EXPECTED_RECOVERY_ROWS
        or amendment.get("target_answer_retries") != 1
        or amendment.get("max_total_target_calls") != EXPECTED_RECOVERY_ROWS * 2
        or amendment.get("max_total_judge_calls") != 0
        or amendment.get("max_total_http_attempts") != 0
        or amendment.get("successful_rows_repeated") != 0
        or amendment.get("paid_provider_calls") != 0
    ):
        raise ValueError("CUDA recovery Gate 5 amendment changed")

    snapshot_path = _validate_descriptor(
        completion["prior_interruption"], label="CUDA predecessor snapshot"
    )
    snapshot = _load_json(snapshot_path, label="CUDA predecessor snapshot")
    if (
        snapshot_path != control_root / "prior-interruption.json"
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or set(snapshot)
        != {
            "schema",
            "created_at_utc",
            "prior_root",
            "prior_launch",
            "prior_marker",
            "retained_results",
            "partial",
            "pre_state_units",
            "retained_accounting",
        }
    ):
        raise ValueError("CUDA predecessor snapshot changed")
    prior_root = Path(str(snapshot.get("prior_root", ""))).resolve(strict=True)
    if snapshot.get("prior_marker") != _validate_prior_terminal(prior_root):
        raise ValueError("CUDA predecessor terminal descriptor changed")
    prior_launch_path = _validate_descriptor(
        snapshot["prior_launch"], label="bounded-output predecessor launch"
    )
    if prior_launch_path != prior_root / "launch.json":
        raise ValueError("bounded-output predecessor launch placement changed")
    prior_launch = _load_json(prior_launch_path, label="bounded-output predecessor launch")
    if prior_launch.get("schema") != PRIOR_LAUNCH_SCHEMA:
        raise ValueError("bounded-output predecessor launch changed")
    if amendment.get("prior_launch") != _descriptor(
        prior_launch_path, label="bounded-output predecessor launch"
    ):
        raise ValueError("CUDA amendment predecessor binding changed")

    prior_snapshot_path = _validate_descriptor(
        prior_launch["prior_interruption"], label="bounded-output predecessor snapshot"
    )
    prior_snapshot = _load_json(
        prior_snapshot_path, label="bounded-output predecessor snapshot"
    )
    if prior_snapshot.get("schema") != BOUNDED_SNAPSHOT_SCHEMA:
        raise ValueError("bounded-output predecessor snapshot schema changed")
    middle_root = Path(str(prior_snapshot.get("prior_root", ""))).resolve(strict=True)
    middle_results = prior_snapshot.get("retained_results")
    middle_launch_path = _validate_descriptor(
        prior_snapshot["prior_launch"], label="middle predecessor launch"
    )
    if middle_launch_path != middle_root / "launch.json":
        raise ValueError("middle predecessor launch placement changed")
    middle_launch = _load_json(middle_launch_path, label="middle predecessor launch")
    retained_snapshot_path = _validate_descriptor(
        middle_launch["prior_interruption"], label="base retained snapshot"
    )
    retained_snapshot = _load_json(retained_snapshot_path, label="base retained snapshot")
    base_results = retained_snapshot.get("retained_results")
    if (
        retained_snapshot.get("schema") != RETAINED_SNAPSHOT_SCHEMA
        or retained_snapshot.get("order") != order
        or not isinstance(base_results, dict)
        or set(base_results) != set(order[:2])
        or not isinstance(middle_results, dict)
        or set(middle_results) != set(order[2:20])
        or not isinstance(snapshot.get("retained_results"), dict)
        or set(snapshot["retained_results"]) != set(order[20:22])
    ):
        raise ValueError("CUDA recovery retained result partition changed")
    base_root = Path(
        str(retained_snapshot.get("prior_control_root", ""))
    ).resolve(strict=True)

    expected_partial_selector, expected_partial, _partial_successful, _partial_missing = (
        _partial_partition(
            item=inventory["units"][PARTIAL_UNIT_INDEX - 1],
            unit_id=order[PARTIAL_UNIT_INDEX - 1],
            prior_root=prior_root,
            runner_root=runner_root,
        )
    )
    if snapshot.get("partial") != expected_partial:
        raise ValueError("CUDA-interrupted durable partition changed")
    expected_continuation = []
    for index in range(PARTIAL_UNIT_INDEX - 1, EXPECTED_UNIT_COUNT):
        item = dict(inventory["units"][index])
        item["summary"] = dict(item["summary"])
        if index == PARTIAL_UNIT_INDEX - 1:
            item["recovery_selection"] = expected_partial_selector
            item["summary"]["recovery_records"] -= EXPECTED_PARTIAL_ROWS
        expected_continuation.append(item)
    if sum(
        int(item["summary"]["recovery_records"]) for item in expected_continuation
    ) != EXPECTED_RECOVERY_ROWS:
        raise ValueError("CUDA recovery selection accounting changed")

    expected_pre_state: dict[str, list[dict[str, Any]]] = {}
    for unit_id in order[PARTIAL_UNIT_INDEX:]:
        expected = _validate_pre_state_root(runner_root / unit_id / prior_root.name)
        if expected is not None:
            expected_pre_state[unit_id] = expected
    if snapshot.get("pre_state_units") != expected_pre_state:
        raise ValueError("CUDA pre-state evidence changed")

    terminal_states: dict[str, str] = {}
    lifecycle_roots: dict[str, str] = {}
    lifecycle_evidence: dict[str, dict[str, object]] = {}
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility: list[dict[str, object]] = []
    metric_markers: list[dict[str, object]] = []
    metric_revisions: dict[str, str] = {}
    sources: set[str] = set()
    successful = missing = selected_total = 0
    for index, (unit_id, item) in enumerate(zip(order, inventory["units"], strict=True)):
        if index < 2:
            result = base_results[unit_id]
            physical_root = base_root
            state_schema = BASE_STATE_SCHEMA
            evidence_completion = _descriptor(
                retained_snapshot_path, label="base retained snapshot"
            )
        elif index < 20:
            retained_corpora = item["recovery_selection"]["corpora"]
            retained_corpus = (
                next(iter(retained_corpora)) if len(retained_corpora) == 1 else None
            )
            result = _expand_compact_retained_result(
                middle_results[unit_id],
                unit_id=unit_id,
                source_lane=str(item["source_lane"]),
                corpus=retained_corpus,
                selected_records=int(item["summary"]["recovery_records"]),
            )
            physical_root = middle_root
            state_schema = MIDDLE_STATE_SCHEMA
            evidence_completion = _descriptor(
                prior_snapshot_path, label="middle retained snapshot"
            )
        elif index < PARTIAL_UNIT_INDEX - 1:
            result = snapshot["retained_results"][unit_id]
            physical_root = prior_root
            state_schema = PRIOR_STATE_SCHEMA
            evidence_completion = _descriptor(
                snapshot_path, label="CUDA predecessor snapshot"
            )
        else:
            result = results[unit_id]
            physical_root = control_root
            state_schema = STATE_SCHEMA
            evidence_completion = completion_descriptor

        selected = int(item["summary"]["recovery_records"])
        if index == BOUNDED_PARTIAL_INDEX - 1:
            selected -= BOUNDED_RETAINED_USABLE
        if index == PARTIAL_UNIT_INDEX - 1:
            selected -= EXPECTED_PARTIAL_ROWS
        corpora = item["recovery_selection"]["corpora"]
        corpus = next(iter(corpora)) if len(corpora) == 1 else None
        validated = _validate_metric_result(
            result,
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
        terminal_states[unit_id] = "measured_complete"
        lifecycle_roots[unit_id] = str(validated["root"])
        evidence = dict(validated["evidence"])
        if index == BOUNDED_PARTIAL_INDEX - 1:
            evidence["interrupted_usable_row"] = dict(prior_snapshot["partial"])
        if index == PARTIAL_UNIT_INDEX - 1:
            evidence["interrupted_cuda_rows"] = dict(snapshot["partial"])
        lifecycle_evidence[unit_id] = evidence
        metric_roots[unit_id] = str(validated["root"])
        metric_evidence[unit_id] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_eligibility.append(dict(validated["eligibility_plan"]))
        metric_markers.extend(validated["completion_markers"])
        metric_revisions[unit_id] = str(validated["revision"])
        sources.add(str(validated["source"]))
        selected_total += selected
        successful += int(validated["successful"])
        missing += int(validated["missing"])

    cuda_partial = snapshot["partial"]
    retained_results = snapshot["retained_results"]
    expected_retained_accounting = {
        "target_attempts": sum(
            int(retained_results[unit]["target_attempts"]) for unit in order[20:22]
        )
        + EXPECTED_PARTIAL_ROWS,
        "successful_target_generations": sum(
            int(retained_results[unit]["successful_target_generations"])
            for unit in order[20:22]
        )
        + int(cuda_partial["successful_target_generations"]),
        "missing_responses": sum(
            int(retained_results[unit]["missing_responses"]) for unit in order[20:22]
        )
        + int(cuda_partial["missing_responses"]),
    }
    selected_total += BOUNDED_RETAINED_USABLE + EXPECTED_PARTIAL_ROWS
    successful += BOUNDED_RETAINED_USABLE + int(
        cuda_partial["successful_target_generations"]
    )
    missing += int(cuda_partial["missing_responses"])
    if (
        selected_total != EXPECTED_TOTAL_ROWS
        or successful + missing != EXPECTED_TOTAL_ROWS
        or len(sources) != 1
        or snapshot.get("retained_accounting") != expected_retained_accounting
        or completion.get("target_execution")
        != {
            "target_attempts": EXPECTED_TAIL_ROWS,
            "successful_target_generations": int(
                snapshot["retained_accounting"]["successful_target_generations"]
            )
            + sum(int(results[unit]["successful_target_generations"]) for unit in recovery_order),
            "missing_responses": int(snapshot["retained_accounting"]["missing_responses"])
            + sum(int(results[unit]["missing_responses"]) for unit in recovery_order),
        }
    ):
        raise ValueError("CUDA recovery final population accounting changed")

    revision_strata: dict[str, list[str]] = {}
    for lane, revision in metric_revisions.items():
        revision_strata.setdefault(revision, []).append(lane)
    old_partial_id = order[BOUNDED_PARTIAL_INDEX - 1]
    cuda_partial_id = order[PARTIAL_UNIT_INDEX - 1]
    return {
        "completion": completion_descriptor,
        "inventory": dict(completion["inventory"]),
        "runner_code_version": "mixed",
        "output_policy_stratum": "mixed_retained_and_profiled_response_allowance",
        "unit_order": order,
        "terminal_states": terminal_states,
        "lifecycle_roots": lifecycle_roots,
        "lifecycle_evidence": lifecycle_evidence,
        "lifecycle_revision_strata": dict(revision_strata),
        "lifecycle_project_revision_receipt_sha256": dict(metric_revisions),
        "metric_lane_order": list(order),
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility,
        "metric_completion_markers": metric_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": metric_revisions,
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": {
            "target_attempts": EXPECTED_TOTAL_ROWS,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "population_segments": {
            old_partial_id: {
                "profiled_rows": int(
                    inventory["units"][BOUNDED_PARTIAL_INDEX - 1]["summary"][
                        "recovery_records"
                    ]
                )
                - BOUNDED_RETAINED_USABLE,
                "retained_usable_rows": BOUNDED_RETAINED_USABLE,
                "security_metric_pooling_permitted": False,
            },
            cuda_partial_id: {
                "current_revision_profiled_rows": int(
                    inventory["units"][PARTIAL_UNIT_INDEX - 1]["summary"][
                        "recovery_records"
                    ]
                )
                - EXPECTED_PARTIAL_ROWS,
                "retained_predecessor_rows": EXPECTED_PARTIAL_ROWS,
                "retained_predecessor_successful_rows": int(
                    cuda_partial["successful_target_generations"]
                ),
                "retained_predecessor_missing_rows": int(
                    cuda_partial["missing_responses"]
                ),
                "security_metric_pooling_permitted": False,
            },
        },
        "successful_rows_repeated": 0,
        "cross_condition_pooling_permitted": False,
    }


def validate_alignment_prerequisite(
    completion_path: Path, *, runner_root: Path
) -> dict[str, Any]:
    """Expose the retained DeepSeek unit after validating the full successor."""

    view = validate_completion(completion_path, runner_root=runner_root)
    inventory_descriptor = view["inventory"]
    inventory_path = _validate_descriptor(
        inventory_descriptor, label="CUDA recovery inventory"
    )
    inventory = load_inventory(
        inventory_path, str(inventory_descriptor.get("sha256", ""))
    )
    order = list(view["unit_order"])
    completion = _load_json(completion_path, label="CUDA recovery completion")
    snapshot_path = _validate_descriptor(
        completion["prior_interruption"], label="CUDA predecessor snapshot"
    )
    snapshot = _load_json(snapshot_path, label="CUDA predecessor snapshot")
    prior_launch_path = _validate_descriptor(
        snapshot["prior_launch"], label="bounded-output predecessor launch"
    )
    prior_launch = _load_json(prior_launch_path, label="bounded-output predecessor launch")
    prior_snapshot_path = _validate_descriptor(
        prior_launch["prior_interruption"], label="bounded-output predecessor snapshot"
    )
    prior_snapshot = _load_json(
        prior_snapshot_path, label="bounded-output predecessor snapshot"
    )
    middle_launch_path = _validate_descriptor(
        prior_snapshot["prior_launch"], label="middle predecessor launch"
    )
    middle_launch = _load_json(middle_launch_path, label="middle predecessor launch")
    retained_snapshot_path = _validate_descriptor(
        middle_launch["prior_interruption"], label="base retained snapshot"
    )
    retained_snapshot = _load_json(retained_snapshot_path, label="base retained snapshot")
    deepseek_id = order[0]
    deepseek_result = retained_snapshot["retained_results"][deepseek_id]
    return {
        "completion": dict(view["completion"]),
        "deepseek_id": deepseek_id,
        "deepseek_result": deepseek_result,
        "deepseek_revision": view["metric_project_revision_receipt_sha256"][
            deepseek_id
        ],
        "inventory": inventory,
        "unit_order": order,
    }


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
        "pre_state_units": inspected["pre_state_units"],
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
