from __future__ import annotations

import copy
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_retained_execute as subject, run_matrix
from experiments.hosted_attempt_budget import create_budget, AttemptBudget
from test_retained_input_replay import _fixture, _RecordingMock
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker, retained_dialog
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.runner import Runner, retained_execution_admission, current_retained_execution_admission
from ura.targets.api import OpenAITarget


def _setup(tmp_path, *, adaptive=True, outputs=None, tight=False):
    points, _original, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=adaptive)
    ids = [entry["origin"]["selection"]["input_identity_sha256"] for entry in value["entries"]]
    attacker = ReplayAttacker(**config, retained_input_ids=ids)
    target = OpenAITarget("gpt-5.5", max_tokens=128, max_retries=3, temperature=None)
    calls = []
    outputs = iter(outputs or ["I cannot help with that."] * len(ids))

    def create(**request):
        calls.append(copy.deepcopy(request))
        text = next(outputs)
        if isinstance(text, BaseException):
            raise text
        return SimpleNamespace(id="mock-response", model="gpt-5.5", system_fingerprint="mock-fp",
            choices=[SimpleNamespace(index=0, finish_reason="stop",
                                     message=SimpleNamespace(content=text, refusal=None))],
            usage=SimpleNamespace(prompt_tokens=7, completion_tokens=5, total_tokens=12))

    target._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    program = {"target": target.name, "provider": "openai", "max_output_tokens": 128}
    requests = {key: {"call_id": key, "request_sha256": subject._sha(target.build_request(
        retained_dialog(entry["rendered_input"]), seed=0)), "input_tokens": 32,
        "max_output_tokens": 128, "bound_microusd": 10000}
        for key, entry in zip(ids, value["entries"])}
    descriptor = create_budget(tmp_path / "money", provider_budgets_microusd={
        "anthropic": 90000000, "openai": 12500 * len(ids) if tight else 40000000},
        planned_calls=[{"call_id": key, "provider": "openai", "pool": "target", "bound_microusd": 10000}
                       for key in ids])
    budget = AttemptBudget(tmp_path / "money", descriptor["sha256"])
    admission = subject._Admission(program=program, job={"purpose": "measured_run", "input_ids": ids, "argv": []},
                                    budget=budget, attacker=attacker, requests=requests,
                                    prices={"input": "2", "output": "6"})
    return points, attacker, target, calls, admission


def _runner(attacker, target, admission):
    with retained_execution_admission(admission):
        return Runner(attacker, target, JudgeCascade([RuleJudge()]), AttackBudget(max_queries=2, max_turns=2),
                      [0], target_answer_retries=0, execution_stage="responses")


def test_target_money_settles_after_checkpoint_and_resume_never_reissues(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    checkpoint = tmp_path / "responses.jsonl"
    states = []

    def retain(record):
        states.append(admission.budget.snapshot()["pools"]["openai:target"]["unresolved_attempts"])
        Runner.append_checkpoint(checkpoint, record)

    first = _runner(attacker, target, admission)
    first.run(points, on_response=retain)
    assert len(calls) == 2 and states == [1, 1]
    assert admission.budget.snapshot()["pools"]["openai:target"]["settled_cost_microusd"] == 88
    second = _runner(attacker, target, admission)
    second.run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == len(second.responses) == 2
    assert current_retained_execution_admission() is None


def test_paid_empty_response_is_durable_then_opens_global_circuit_before_next_input(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=["", "must never run"])
    checkpoint = tmp_path / "responses.jsonl"
    with pytest.raises(RuntimeError, match="durable response"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(calls) == len(records) == 1
    assert (admission.budget.root / "paid-circuit.json").is_file()
    assert next(iter(records.values()))["response"]["raw"]["model_stability_status"] == "failed_output"
    assert admission.budget.snapshot()["pools"]["openai:target"]["unknown_usage_attempts"] == 1


def test_paid_target_cannot_call_without_response_checkpoint(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    with pytest.raises(ValueError, match="durable response checkpoint"):
        _runner(attacker, target, admission).run(points)
    assert calls == []


def test_request_change_fails_before_reservation_and_sdk(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    target.temperature = 0.5
    with pytest.raises(ValueError, match="request changed"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    assert calls == []
    assert admission.budget.snapshot()["pools"]["openai:target"]["unresolved_attempts"] == 0


class _HTTP500(Exception):
    status_code = 500


def test_status_retry_reserves_each_physical_attempt_and_holds_unknown_charge(tmp_path, monkeypatch):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, adaptive=False,
                                                       outputs=[_HTTP500("mock"), "usable"])
    _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2 and state["unknown_usage_attempts"] == 1
    assert state["reserved_exposure_microusd"] == 10000 and state["settled_cost_microusd"] == 44


def test_retry_cannot_spend_remaining_selected_first_calls(tmp_path, monkeypatch):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, tight=True,
                                                       outputs=[_HTTP500("mock"), "must never run"])
    with pytest.raises(Exception, match="retry cannot consume"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 1 and state["unstarted_first_commitments_microusd"] == 10000
    assert state["unknown_usage_attempts"] == 1


@pytest.mark.parametrize("surface,provider", [("anthropic-fable", "anthropic"),
    ("openai-responses", "openai"), ("kimi", "kimi"), ("moonshot", "kimi")])
def test_billing_provider_preserves_configured_surface_aliases(surface, provider):
    assert subject._billing_provider(surface) == provider


def test_partition_does_not_change_original_artifact_or_rerun_pilot(tmp_path):
    points, _original, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=True)
    before = Path(config["replay_artifact"]).read_bytes()
    ids = [row["origin"]["selection"]["input_identity_sha256"] for row in value["entries"]]
    generated = []
    for identity in ids:
        attacker = ReplayAttacker(**config, retained_input_ids=[identity])
        runner = Runner(attacker, _RecordingMock(), JudgeCascade([RuleJudge()]), AttackBudget(max_queries=1, max_turns=1),
                        [0], target_answer_retries=0)
        runner.run(points)
        generated += [attempt.params["retained_origin"]["selection"]["input_identity_sha256"] for attempt in runner.attempts]
    assert generated == ids and len(set(generated)) == len(ids)
    assert Path(config["replay_artifact"]).read_bytes() == before
    for invalid in ([ids[0], ids[0]], list(reversed(ids)), ["not-selected"]):
        with pytest.raises(ValueError, match="partition"):
            ReplayAttacker(**config, retained_input_ids=invalid)


def test_nonprefix_retained_pilot_is_one_original_cluster_not_extra_sample(tmp_path, monkeypatch):
    points, _audit = run_matrix.load_corpus_with_audit("synth", 0, 0, exclude_tool_conditioned=True)
    chosen = next(point for point in reversed(points) if point.modalities == ["text"] and point.expected_behavior == "refuse")
    _points, _cell, _plan, _bindings, value, config = _fixture(tmp_path, points=[chosen], corpus="synth")
    attacker = ReplayAttacker(**config, retained_input_ids=[value["entries"][0]["origin"]["selection"]["input_identity_sha256"]])
    sampled, audit = run_matrix.load_retained_replay_corpus("synth", 1, 0, attacker=attacker,
        sampling_policy=None, source_instance=run_matrix._default_source_instance("synth"))
    assert sampled == [chosen] and audit["selected_clusters"] == audit["limit"] == 1
    assert audit["pre_retained_loading_limit"] == 0
    assert audit["selection_method"] == "content_bound_retained_input_replay_v1"
    assert audit["selected_indices"] != [0]
    calls = _RecordingMock()
    runner = Runner(attacker, calls, JudgeCascade([RuleJudge()]), AttackBudget(max_queries=1, max_turns=1),
                    [0], target_answer_retries=0)
    runner.run(sampled)
    assert len(calls._dialogs) == 1 and runner.attempts[0].datapoint_id == chosen.id


def test_fully_bound_program_still_cannot_skip_final_campaign_admission(tmp_path):
    with pytest.raises(ValueError, match="complete local-source program admission"):
        subject._validated_jobs({}, None)
