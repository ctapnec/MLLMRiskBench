from __future__ import annotations

import json

import pytest

from experiments.local_campaign.failed_output_recovery_phase6 import (
    _durable_outcomes,
    build_completed_selection,
)
from ura.data_models import SCHEMA_VERSION


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
