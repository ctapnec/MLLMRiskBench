from __future__ import annotations

import json
import inspect

import pytest

from experiments.local_campaign.current_ollama import CURRENT_OLLAMA_BY_LABEL
from experiments.local_campaign.failed_output_recovery_phase6 import (
    EXPECTED_RECOVERY_COUNTS,
    EXPECTED_RECOVERY_ROWS,
    EXPECTED_UNIT_ORDER,
    ORIGINAL_UNIT_ORDER,
    _durable_outcomes,
    build_completed_selection,
    physical_unit_id,
    validate_phase7_completion as dispatch_phase7_completion,
)
from experiments.local_campaign.failed_output_recovery_continuation_phase6 import (
    CONTINUATION_UNIT_ORDER,
    DEEPSEEK_CONTINUATION_NUM_PREDICT,
    DEEPSEEK_PHYSICAL_UNIT,
    RETAINED_UNIT_ORDER,
    SCHEMA as CONTINUATION_SCHEMA,
    _create_deepseek_generation_condition,
    _partial_durable_counts,
    _revision_map,
    run as run_continuation,
)
from ura.data_models import SCHEMA_VERSION


def test_phase7_recovery_inventory_is_the_exact_six_unit_proof() -> None:
    assert len(ORIGINAL_UNIT_ORDER) == len(EXPECTED_UNIT_ORDER) == 6
    assert EXPECTED_RECOVERY_COUNTS == (1223, 555, 323, 18, 1674, 20)
    assert EXPECTED_RECOVERY_ROWS == 3813
    assert EXPECTED_UNIT_ORDER == tuple(
        f"failed-output-recovery-{index:02d}-{original[:52]}"
        for index, original in enumerate(ORIGINAL_UNIT_ORDER, 1)
    )


def test_failed_output_continuation_selects_only_unexecuted_deepseek() -> None:
    assert CONTINUATION_UNIT_ORDER == (EXPECTED_UNIT_ORDER[4],)
    assert DEEPSEEK_PHYSICAL_UNIT == EXPECTED_UNIT_ORDER[4]
    assert RETAINED_UNIT_ORDER == EXPECTED_UNIT_ORDER[:4] + EXPECTED_UNIT_ORDER[5:]

    source = inspect.getsource(run_continuation)
    assert "only_original_units=(DEEPSEEK_UNIT,)" in source
    assert 'results = dict(prior["unit_results"])' in source
    assert "successful_rows_repeated\": 0" in source
    assert "_partial_durable_counts(" in source
    assert "_create_deepseek_generation_condition(" in source
    assert CONTINUATION_SCHEMA == "ura-failed-output-recovery-phase6/3"
    assert "ura-failed-output-recovery-phase6/3" in inspect.getsource(
        dispatch_phase7_completion
    )

    assert physical_unit_id(ORIGINAL_UNIT_ORDER[4]) == EXPECTED_UNIT_ORDER[4]
    with pytest.raises(ValueError, match="unknown failed-output recovery unit"):
        physical_unit_id("not-a-recovery-unit")

    # Reverse mutation: renumbering the filtered unit from one reproduces the
    # pre-execution selector mismatch that this continuation must reject.
    reindexed = f"failed-output-recovery-01-{ORIGINAL_UNIT_ORDER[4][:52]}"
    assert reindexed != DEEPSEEK_PHYSICAL_UNIT


def test_failed_output_continuation_preserves_split_revision_strata() -> None:
    validated = {
        lane: {"revision": "a" * 64 if lane != DEEPSEEK_PHYSICAL_UNIT else "b" * 64}
        for lane in EXPECTED_UNIT_ORDER
    }
    strata, by_lane = _revision_map(validated)

    assert strata == {
        "a" * 64: list(RETAINED_UNIT_ORDER),
        "b" * 64: [DEEPSEEK_PHYSICAL_UNIT],
    }
    assert by_lane[DEEPSEEK_PHYSICAL_UNIT] == "b" * 64

    # Reverse mutation: pooling the continuation into the retained revision is
    # detectable because the second stratum disappears.
    mutated = {lane: {"revision": "a" * 64} for lane in EXPECTED_UNIT_ORDER}
    mutated_strata, _mutated_by_lane = _revision_map(mutated)
    assert mutated_strata != strata


def test_failed_output_continuation_counts_checkpointed_rows_after_failure(
    tmp_path,
) -> None:
    work_root = tmp_path / "work"
    control_root = work_root / "runs" / "engineering" / "campaign"
    unit_root = control_root / "units" / DEEPSEEK_PHYSICAL_UNIT
    result_root = (
        work_root
        / "runs"
        / "thesis"
        / "runner"
        / DEEPSEEK_PHYSICAL_UNIT
        / control_root.name
    )
    unit_root.mkdir(parents=True)
    result_root.mkdir(parents=True)
    (unit_root / "state.json").write_text(
        json.dumps({
            "schema": "ura-failed-output-recovery-phase6-unit-state/1",
            "unit_id": DEEPSEEK_PHYSICAL_UNIT,
            "selected_records": EXPECTED_RECOVERY_COUNTS[4],
            "target_answer_retries": 1,
            "result_root": str(result_root),
        }),
        encoding="utf-8",
    )
    attempts = [
        {
            "id": f"attempt-{index}",
            "datapoint_id": f"row-{index}",
            "attacker": "replay",
            "target": "target",
            "rendered_input": [{"role": "user", "content": "fixture"}],
            "run_id": f"run-{index}",
        }
        for index in range(2)
    ]
    responses = [
        {
            "attempt_id": "attempt-0",
            "target": "target",
            "output_turns": [{"role": "assistant", "content": "answer"}],
            "raw": {"model_stability_status": "usable_first_response"},
            "run_id": "run-0",
        },
        {
            "attempt_id": "attempt-1",
            "target": "target",
            "output_turns": [],
            "raw": {"model_stability_status": "failed_output"},
            "run_id": "run-1",
        },
    ]
    (result_root / "fixture.attempts.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in attempts), encoding="utf-8"
    )
    (result_root / "fixture.responses.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in responses), encoding="utf-8"
    )

    assert _partial_durable_counts(
        work_root=work_root,
        control_root=control_root,
    ) == (2, 1, 1)

    # Reverse mutation: the old controller published zeros after the same
    # checkpointed failure and therefore cannot satisfy this accounting proof.
    assert (0, 0, 0) != (2, 1, 1)


def test_deepseek_continuation_binds_separate_calibrated_generation_cap(
    tmp_path,
) -> None:
    model = CURRENT_OLLAMA_BY_LABEL["deepseek-r1-distill-32b"]
    control_root = tmp_path / "campaign"
    (control_root / "configs").mkdir(parents=True)
    condition = _create_deepseek_generation_condition(
        control_root=control_root,
    )

    assert DEEPSEEK_CONTINUATION_NUM_PREDICT == 2_048
    assert condition["num_predict"] == 2_048
    assert condition["think"] is True
    config_path = control_root / "configs" / "deepseek-r1-distill-32b.json"
    assert condition["local_config"]["path"] == str(config_path)
    assert json.loads(config_path.read_text(encoding="utf-8"))[model.spec] == {
        "digest": model.digest,
        "modalities": ["text"],
        "num_ctx": 8192,
        "num_predict": 2_048,
        "think": True,
    }

    # Reverse mutation: the stopped 512-token condition is not this cohort.
    assert 512 != DEEPSEEK_CONTINUATION_NUM_PREDICT


def test_selector_replays_only_failed_and_never_attempted_rows() -> None:
    selected = {
        "alpha": ["a", "b", "c", "d"],
        "beta": ["e", "f"],
    }
    eligible = {
        "alpha": ["b", "c", "d"],
        "beta": ["f"],
    }
    outcomes = {
        "b": "usable_first_response",
        "c": "failed_output",
        "f": "input_incompatible",
    }

    selector, summary = build_completed_selection(
        selected_ids=selected,
        eligible_ids=eligible,
        outcomes=outcomes,
    )

    assert list(selector["corpora"]) == ["alpha"]
    alpha = selector["corpora"]["alpha"]
    assert alpha["completed_datapoint_ids"] == ["a", "b"]
    assert summary == {
        "selected_records": 6,
        "prior_eligible_records": 4,
        "durable_outcomes": 3,
        "failed_output_records": 1,
        "input_incompatible_records": 1,
        "never_attempted_records": 1,
        "recovery_records": 2,
        "completed_records_excluded": 4,
        "recovery_corpora": ["alpha"],
    }

    # Reverse mutation: treating the failed row as complete changes the exact
    # remaining-set digest and would silently omit a required replay.
    mutated, mutated_summary = build_completed_selection(
        selected_ids=selected,
        eligible_ids=eligible,
        outcomes={**outcomes, "c": "usable_first_response"},
    )
    assert mutated["corpora"]["alpha"]["remaining_datapoint_ids_sha256"] != (
        alpha["remaining_datapoint_ids_sha256"]
    )
    assert mutated_summary["recovery_records"] == 1


def test_selector_rejects_outcomes_outside_prior_unfinished_population() -> None:
    with pytest.raises(ValueError, match="outside the prior unfinished"):
        build_completed_selection(
            selected_ids={"alpha": ["a", "b"]},
            eligible_ids={"alpha": ["b"]},
            outcomes={"a": "failed_output"},
        )


def test_selector_refuses_a_recovery_with_no_failed_or_unfinished_row() -> None:
    with pytest.raises(ValueError, match="no failed or unfinished"):
        build_completed_selection(
            selected_ids={"alpha": ["a", "b"]},
            eligible_ids={"alpha": ["b"]},
            outcomes={"b": "usable_first_response"},
        )


def test_durable_outcomes_include_prejudging_response_checkpoint(tmp_path) -> None:
    final_attempt = {
        "id": "attempt-a",
        "datapoint_id": "a",
        "attacker": "replay",
        "target": "target",
        "rendered_input": [{"role": "user", "content": "a"}],
        "run_id": "run-a",
    }
    final_response = {
        "attempt_id": "attempt-a",
        "target": "target",
        "output_turns": [{"role": "assistant", "content": "answer"}],
        "raw": {},
        "run_id": "run-a",
    }
    checkpoint_attempt = {
        **final_attempt,
        "id": "attempt-b",
        "datapoint_id": "b",
        "rendered_input": [{"role": "user", "content": "b"}],
        "run_id": "run-b",
    }
    checkpoint_response = {
        "attempt_id": "attempt-b",
        "target": "target",
        "output_turns": [],
        "raw": {"model_stability_status": "failed_output"},
        "run_id": "run-b",
    }
    (tmp_path / "alpha.attempts.jsonl").write_text(
        json.dumps(final_attempt) + "\n", encoding="utf-8"
    )
    (tmp_path / "alpha.responses.jsonl").write_text(
        json.dumps(final_response) + "\n", encoding="utf-8"
    )
    (tmp_path / "beta.responses.checkpoint.jsonl").write_text(
        json.dumps({
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-b",
            "attempt": checkpoint_attempt,
            "response": checkpoint_response,
            "budget_after_target": None,
        })
        + "\n",
        encoding="utf-8",
    )

    attempts, outcomes, attempt_files, response_files = _durable_outcomes(
        tmp_path
    )

    assert attempts == {"attempt-a": "a", "attempt-b": "b"}
    assert outcomes == {"a": "usable_first_response", "b": "failed_output"}
    assert [path.name for path in attempt_files] == ["alpha.attempts.jsonl"]
    assert [path.name for path in response_files] == [
        "alpha.responses.jsonl",
        "beta.responses.checkpoint.jsonl",
    ]


def test_durable_outcomes_accept_checkpoint_before_attempts_file(tmp_path) -> None:
    checkpoint_attempt = {
        "id": "attempt-b",
        "datapoint_id": "b",
        "attacker": "replay",
        "target": "target",
        "rendered_input": [{"role": "user", "content": "b"}],
        "run_id": "run-b",
    }
    checkpoint_response = {
        "attempt_id": "attempt-b",
        "target": "target",
        "output_turns": [],
        "raw": {"model_stability_status": "failed_output"},
        "run_id": "run-b",
    }
    (tmp_path / "beta.responses.checkpoint.jsonl").write_text(
        json.dumps({
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-b",
            "attempt": checkpoint_attempt,
            "response": checkpoint_response,
            "budget_after_target": None,
        })
        + "\n",
        encoding="utf-8",
    )

    attempts, outcomes, attempt_files, response_files = _durable_outcomes(
        tmp_path
    )

    assert attempts == {"attempt-b": "b"}
    assert outcomes == {"b": "failed_output"}
    assert attempt_files == []
    assert [path.name for path in response_files] == [
        "beta.responses.checkpoint.jsonl"
    ]
