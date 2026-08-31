from __future__ import annotations

import pytest

from experiments.finalize_recovered_trails import (
    repair_recovered_judgments,
    repair_recovered_trail_rows,
)
from ura.data_models import DialogTurn, Judgment, Response


def _response() -> Response:
    return Response(
        attempt_id="attempt-1",
        target="fixture-target",
        output_turns=[DialogTurn(role="assistant", content="usable")],
        run_id="run-fixture",
        raw={
            "model_stability_status": "recovered_after_retry",
            "model_stability_category": "empty_output",
            "model_stability_error_type": "TargetAnswerError",
            "model_stability_retry_count": 1,
            "judge_stage_bindings": [
                {
                    "stage": 0,
                    "judge": "rules",
                    "model_stability_status": None,
                    "model_stability_category": None,
                    "model_stability_error_type": None,
                    "model_stability_retry_count": None,
                }
            ],
        },
    )


def _judgment() -> Judgment:
    return Judgment(
        attempt_id="attempt-1",
        judge="rules",
        label="safe",
        score=0.0,
        run_id="run-fixture",
        raw={
            "model_stability_status": "recovered_after_retry",
            "model_stability_category": "empty_output",
            "model_stability_error_type": "TargetAnswerError",
            "model_stability_retry_count": 1,
        },
    )


def test_recovered_trail_finalizer_repairs_only_response_bound_fields() -> None:
    row = {
        "attempt_id": "attempt-1",
        "stage": 0,
        "judge": "rules",
        "model_stability_status": None,
        "model_stability_category": None,
        "model_stability_error_type": None,
        "model_stability_retry_count": None,
        "unrelated": "retained",
    }
    judgments, judgment_count = repair_recovered_judgments(
        {"attempt-1": _response()}, {"attempt-1": _judgment()}
    )
    repaired, count = repair_recovered_trail_rows(
        [row], {"attempt-1": _response()}, judgments
    )

    assert judgment_count == count == 1
    assert repaired[0]["model_stability_status"] == "recovered_after_retry"
    assert repaired[0]["model_stability_category"] == "empty_output"
    assert repaired[0]["model_stability_error_type"] == "TargetAnswerError"
    assert repaired[0]["model_stability_retry_count"] == 1
    assert repaired[0]["unrelated"] == "retained"
    assert row["model_stability_status"] is None
    binding = judgments["attempt-1"].raw["judge_stage_bindings"][0]
    assert binding["model_stability_status"] == "recovered_after_retry"
    assert binding["model_stability_retry_count"] == 1


def test_recovered_trail_finalizer_rejects_conflicting_retained_status() -> None:
    row = {
        "attempt_id": "attempt-1",
        "model_stability_status": "failed_output",
    }
    with pytest.raises(ValueError, match="conflicting model_stability_status"):
        judgments, _count = repair_recovered_judgments(
            {"attempt-1": _response()}, {"attempt-1": _judgment()}
        )
        repair_recovered_trail_rows(
            [row], {"attempt-1": _response()}, judgments
        )
