"""Malformed paid judge output is retained without fabricated labels or retries."""
from __future__ import annotations

import copy
import json

import pytest

from experiments import retained_response_judge_execute as subject
from test_retained_response_judge_execute import FakeHaiku, _prepared
from ura.judges.llm import LLMJudge, LLMJudgeOutputError


class MalformedHaiku(FakeHaiku):
    def generate(self, *args, **kwargs):
        response = super().generate(*args, **kwargs)
        if self.calls == 1:
            response.output_turns[0].content = "I cannot supply a rubric verdict."
        return response


def _arguments(prepared):
    return {key: prepared[key] for key in ("plan_path", "runner_view", "source_receipt", "api_config", "pricing_config", "out")}


def _review(plan, index=0):
    return {"circuit": {"error_type": "LLMJudgeOutputError", "plan_id": plan["plan_id"],
                        "selection_index": index, "retained_row_sha256": plan["selected"][index]["retained_row_sha256"]},
            "physical_attempts": 1, "provider_response_id": "msg_retained_error",
            "sources": [{"file": "circuit.json", "sha256": "a" * 64, "bytes": 100}]}


def test_parse_error_preserves_actual_paid_reply_and_usage(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    row = prepared["plan"]["selected"][0]
    point, response = subject._judge_inputs(row, "prompt", "answer")
    target = MalformedHaiku()
    with pytest.raises(LLMJudgeOutputError) as caught:
        LLMJudge(target).judge(point, response)
    assert caught.value.verdict.tokens == {"input": 100, "output": 12, "total": 112}
    assert caught.value.verdict.output_turns[0].content == "I cannot supply a rubric verdict."
    assert target.calls == 1


def test_opt_in_retains_invalid_verdict_and_resumes_without_repeating_calls(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    target = MalformedHaiku()
    args = _arguments(prepared)
    completion = subject.execute(**args, judge_factory=lambda *_: target, retain_invalid_verdicts=True)
    value = json.loads(completion.read_bytes())
    assert value["invalid_verdicts"] == 1 and value["unknown_usage_judgments"] == 0
    assert value["judge_calls"] == target.calls == 2
    assert value["actual_cost_microusd"] == 320
    artifact = json.loads(subject._judgment_path(prepared["out"], 0, prepared["plan"]["selected"][0]).read_bytes())
    assert artifact["judgment"]["label"] == "not_applicable" and artifact["judgment"]["raw"]["parsed"] is False
    assert artifact["invalid_verdict"]["verdict"]["tokens"]["output"] == 12
    assert subject.execute(**args, judge_factory=lambda *_: target, retain_invalid_verdicts=True) == completion
    assert target.calls == 2
    with pytest.raises(ValueError, match="policy differs"):
        subject.execute(**args, judge_factory=lambda *_: target)


def test_default_still_stops_for_investigation(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    target = MalformedHaiku()
    with pytest.raises(RuntimeError, match="circuit opened"):
        subject.execute(**_arguments(prepared), judge_factory=lambda *_: target)
    assert target.calls == 1


def test_empty_reply_still_stops_even_when_invalid_verdict_retention_enabled(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    target = FakeHaiku()
    generate = target.generate
    def empty(*args, **kwargs):
        response = generate(*args, **kwargs)
        response.output_turns = []
        return response
    target.generate = empty
    with pytest.raises(RuntimeError, match="circuit opened"):
        subject.execute(**_arguments(prepared), judge_factory=lambda *_: target, retain_invalid_verdicts=True)
    assert target.calls == 1


def test_unknown_historical_usage_stays_null_and_reserved(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    plan, row = prepared["plan"], prepared["plan"]["selected"][0]
    artifact = subject.invalid_verdict_artifact(plan=plan, index=0, row=row, verdict=None, reviewed_failure=_review(plan))
    subject._validate_artifact(artifact, plan=plan, index=0, row=row)
    assert artifact["cost_microusd"] is None
    assert subject._artifact_usage(artifact) == (0, 0, 0)  # Known-only subtotal, not free usage.
    settled = []
    class Budget:
        def settle(self, *args):
            settled.append(args)
    subject._settle_shared_artifact(Budget(), {row["retained_row_sha256"]: {"call_id": "judge-original"}}, row, artifact)
    assert settled == [("judge-original", 1, None)]


@pytest.mark.parametrize("damage", ["label", "usage_zero", "attempt", "evidence", "plan", "index"])
def test_invalid_verdict_cannot_invent_label_usage_or_unrelated_failure(tmp_path, monkeypatch, damage):
    prepared = _prepared(tmp_path, monkeypatch)
    plan, row = prepared["plan"], prepared["plan"]["selected"][0]
    artifact = subject.invalid_verdict_artifact(plan=plan, index=0, row=row, verdict=None, reviewed_failure=_review(plan))
    artifact = copy.deepcopy(artifact)
    if damage == "label":
        artifact["judgment"]["label"] = "safe"
    elif damage == "usage_zero":
        artifact["cost_microusd"] = 0
    elif damage == "attempt":
        artifact["invalid_verdict"]["reviewed_failure"]["physical_attempts"] = 2
    elif damage == "evidence":
        artifact["invalid_verdict"]["reviewed_failure"]["sources"] = []
    else:
        artifact["invalid_verdict"]["reviewed_failure"]["circuit"]["plan_id" if damage == "plan" else "selection_index"] = "wrong"
    with pytest.raises(ValueError):
        subject._validate_artifact(artifact, plan=plan, index=0, row=row)


def test_valid_verdict_cannot_be_suppressed_as_invalid(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    plan = prepared["plan"]
    with pytest.raises(ValueError, match="valid rubric"):
        subject.invalid_verdict_artifact(plan=plan, index=0, row=plan["selected"][0], verdict=FakeHaiku().generate([]))
