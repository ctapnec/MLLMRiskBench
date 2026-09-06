"""Retain malformed classifier evidence without inventing a scored result."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import run_matrix
from ura.judges.base import JudgeCascade, JudgeCascadeDecisionError
from ura.judges.guardrail import GuardrailJudge
from ura.runner import ExternalCallFailure, Runner


class MalformedGuard(GuardrailJudge):
    def _ensure_loaded(self):
        pass

    def _run_guard(self, conversation):
        # The decoded output actually observed on the retained MMSafety row.
        return "assistantsafe"


def test_matrix_retains_failed_guard_trail_but_no_authoritative_judgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A dry fixture must not inherit the production checkout receipt.
    monkeypatch.delenv("URA_PROJECT_REVISION_MANIFEST", raising=False)
    monkeypatch.delenv("URA_PROJECT_REVISION_SHA256", raising=False)
    guard = MalformedGuard(revision="b" * 40)
    monkeypatch.setattr(
        run_matrix, "build_judges", lambda *_args, **_kwargs: JudgeCascade([guard]),
    )
    result = run_matrix.main([
        "--dry-run", "--attackers", "replay", "--judges", "guardrail",
        "--guardrail-revision", "b" * 40,
        "--corpora", "synth", "--limit", "1", "--seeds", "0",
        "--max-queries", "1", "--max-turns", "1", "--out", str(tmp_path),
    ])
    assert result == 1
    errors = [json.loads(path.read_text()) for path in tmp_path.glob("*.error.json")]
    error = next(item for item in errors if item.get("exception_type") == "ExternalCallFailure")
    retained = error["judge_decision_failure"]
    assert retained["authoritative_verdict"] is False
    assert len(retained["trail"]) == 1
    stage = retained["trail"][0]
    assert stage["judge"] == "guardrail"
    assert stage["raw"]["output"] == "assistantsafe"
    assert stage["raw"]["parsed"] is False
    assert stage["raw"]["confidence"] == 0.0
    assert stage["raw"]["cascade_confident"] is False
    assert stage["raw"]["cascade_role"] == "shadow"
    responses = Runner.load_response_checkpoint(next(tmp_path.glob("*.responses.checkpoint.jsonl")))
    assert set(responses) == {stage["attempt_id"]}
    assert not list(tmp_path.glob("*.complete.json"))
    assert error["completed_attempts"] == 0


@pytest.mark.parametrize("phase", ["target_call", "judge_call"])
def test_unrelated_errors_do_not_invent_failed_judge_trails(phase: str) -> None:
    cause = RuntimeError("unrelated failure")
    cause.trail = ["untrusted arbitrary attribute"]
    error = ExternalCallFailure(phase, cause)
    error.__cause__ = cause
    assert run_matrix._failed_judge_decision(error) == {}


def test_target_failure_cannot_export_a_judge_decision_trail() -> None:
    cause = JudgeCascadeDecisionError([])
    error = ExternalCallFailure("target_call", cause)
    error.__cause__ = cause
    assert run_matrix._failed_judge_decision(error) == {}
