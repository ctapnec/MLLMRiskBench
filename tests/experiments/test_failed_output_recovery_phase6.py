from __future__ import annotations

import pytest

from experiments.local_campaign.failed_output_recovery_phase6 import (
    build_completed_selection,
)


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
