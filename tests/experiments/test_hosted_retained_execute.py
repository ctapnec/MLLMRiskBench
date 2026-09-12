from __future__ import annotations

import copy
import hashlib
import json
import os
from contextlib import nullcontext
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
from ura.runner import Runner, retained_execution_admission, current_retained_execution_admission, validate_response_refusal_state
from ura.data_models import DialogTurn, Response
from ura.targets.api import OpenAITarget


def _setup(tmp_path, *, adaptive=True, outputs=None, tight=False, continuous=False):
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
    program = {"target": target.name, "provider": "openai", "max_output_tokens": 128,
               "sources": {"pricing": {"sha256": "b" * 64}}}
    requests = {key: {"call_id": key, "request_sha256": subject._sha(target.build_request(
        retained_dialog(entry["rendered_input"]), seed=0)), "input_tokens": 32,
        "max_output_tokens": 128, "bound_microusd": 10000}
        for key, entry in zip(ids, value["entries"])}
    descriptor = create_budget(tmp_path / "money", provider_budgets_microusd={
        "anthropic": 90000000, "openai": 12550 if continuous else 12500 * len(ids) if tight else 40000000},
        planned_calls=[{"call_id": key, "provider": "openai", "pool": "target", "bound_microusd": 10000}
                       for key in ids], reservation_policy='per_attempt' if continuous else 'first_attempts_upfront')
    budget = AttemptBudget(tmp_path / "money", descriptor["sha256"])
    admission = subject._Admission(program=program, job={"purpose": "measured_run", "input_ids": ids, "argv": []},
                                    budget=budget, attacker=attacker, requests=requests,
                                    prices={"input": "2", "output": "6"})
    return points, attacker, target, calls, admission


def _runner(attacker, target, admission):
    with retained_execution_admission(admission):
        return Runner(attacker, target, JudgeCascade([RuleJudge()]), AttackBudget(max_queries=2, max_turns=2),
                      [0], target_answer_retries=0, execution_stage="responses")


def test_registered_count_uses_funded_starts_and_final_or_checkpointed_responses(tmp_path, monkeypatch):
    points, attacker, target, _calls, admission = _setup(tmp_path)
    records = []
    runner = _runner(attacker, target, admission)
    runner.run(points, on_response=records.append)
    final_root = tmp_path / "final"
    checkpoint_root = tmp_path / "checkpoint"
    final_root.mkdir()
    checkpoint_root.mkdir()
    (final_root / "one.responses.jsonl").write_text(
        json.dumps(records[0]["response"]) + "\n"
    )
    missing = copy.deepcopy(records[1])
    missing["response"]["output_turns"] = []
    missing["response"]["raw"]["model_stability_status"] = "failed_output"
    Runner.append_checkpoint(
        checkpoint_root / "two.responses.checkpoint.jsonl", missing
    )
    program = {
        "target": target.name,
        "requests": admission.requests,
        "jobs": [
            {"argv": ["--out", str(final_root)]},
            {"argv": ["--out", str(checkpoint_root)]},
        ],
    }
    original_load = admission.budget._load
    reads = []
    def observed_load():
        reads.append(True)
        return original_load()
    monkeypatch.setattr(admission.budget, "_load", observed_load)
    assert subject._retained_execution_counts(program, admission.budget) == (2, 1)
    assert len(reads) == 1, "Reporting must not reload the monetary ledger per input"
    reads.clear()
    assert subject._retained_execution_counts(program, admission.budget, include_saved=True) == (2, 1, 2)
    assert len(reads) == 1, "Saved-output accounting must use the same single ledger snapshot"


@pytest.mark.parametrize("final_prefix", [0, 1])
def test_registered_count_keeps_paid_checkpoint_beside_incomplete_final(tmp_path, final_prefix):
    points, attacker, target, _calls, admission = _setup(tmp_path)
    records = []
    _runner(attacker, target, admission).run(points, on_response=records.append)
    output = tmp_path / "partial"
    output.mkdir()
    (output / "cell.responses.jsonl").write_text("".join(
        json.dumps(row["response"]) + "\n" for row in records[:final_prefix]
    ))
    for row in records:
        Runner.append_checkpoint(output / "cell.responses.checkpoint.jsonl", row)
    program = {
        "target": target.name, "requests": admission.requests,
        "jobs": [{"argv": ["--out", str(output)]}],
    }
    assert subject._retained_execution_counts(program, admission.budget) == (2, 2)


@pytest.mark.parametrize("code,expected", [("cyber_policy", 2), ("bio_policy", 2), ("invalid_parameter", 1)])
def test_registered_count_recognizes_only_explicit_legacy_policy_codes(tmp_path, code, expected):
    points, attacker, target, calls, admission = _setup(tmp_path)
    records = []
    _runner(attacker, target, admission).run(points, on_response=records.append)
    saved = records[1]["response"]
    saved["output_turns"] = []
    saved["raw"].update(model_stability_status="failed_output", model_stability_category="transport_failure",
        call_audit=dict(provider="openai", operation="generate", status_code=400, provider_error_code=code))
    output = tmp_path / "legacy"
    output.mkdir()
    path = output / "cell.responses.jsonl"
    path.write_text("".join(json.dumps(row["response"])+"\n" for row in records))
    original = path.read_bytes()
    program = {"target": target.name, "requests": admission.requests,
        "jobs": [{"argv": ["--out", str(output)]}]}
    assert subject._retained_execution_counts(program, admission.budget, include_saved=True) == (2, expected, 2)
    assert path.read_bytes() == original and len(calls) == 2


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


def test_continuous_capacity_waits_for_inflight_settlement_before_http(tmp_path, monkeypatch):
    points, attacker, target, calls, admission = _setup(tmp_path, continuous=True)
    keys = list(admission.requests)
    # Another worker temporarily holds the whole pool for a different input.
    admission.budget.reserve(keys[1], 1, provider='openai')
    waits = []
    def settle_other(_delay):
        assert not calls
        waits.append(True)
        admission.budget.settle(keys[1], 1, 1)
    monkeypatch.setattr(subject.time, 'sleep', settle_other)
    records = []
    with pytest.raises(Exception, match='transport continuation|response checkpoint|circuit|target_call'):
        # The first request succeeds after the other reservation settles. The
        # second input belongs to that other worker and cannot be repeated.
        _runner(attacker, target, admission).run(points, on_response=records.append)
    assert waits == [True] and len(calls) == 1 and len(records) == 1
    assert admission.budget.reserved_attempt_count(keys[0]) == 1


def test_continuous_capacity_shortage_does_not_open_global_paid_stop(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path, continuous=True)
    keys = list(admission.requests)
    admission.budget.reserve(keys[1], 1, provider='openai')
    admission.budget.settle(keys[1], 1, None)
    with pytest.raises(Exception, match='available provider pool capacity'):
        _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    assert calls == []
    assert not (admission.budget.root / 'paid-circuit.json').exists()
    assert admission.budget.reserved_attempt_count(keys[0]) == 0


def test_missing_cache_split_uses_reported_token_bound_without_answer_retry(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(cache_read="0.2", cache_write=None)
    assert admission.program["sources"]["pricing"]["sha256"] == "b" * 64
    checkpoint = tmp_path / "bounded.responses.checkpoint.jsonl"
    _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    pool = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2
    assert pool["settled_cost_microusd"] == 0
    assert pool["unknown_usage_attempts"] == pool["bounded_usage_attempts"] == 2
    assert pool["reserved_exposure_microusd"] == 88
    _runner(attacker, target, admission).run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 2


@pytest.mark.parametrize("provider,write_rate", [("anthropic", None), ("openai", "3")])
def test_cache_bound_does_not_assume_inclusive_anthropic_or_free_priced_writes(tmp_path, provider, write_rate):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(cache_read="0.2", cache_write=write_rate)
    admission.program["sources"] = {"pricing": {"sha256": "b" * 64}}
    if provider == "anthropic":
        # Exercise the checkpoint hook only: its native input counter is not
        # interchangeable with OpenAI's cache-inclusive prompt total.
        admission.program.pop("sources")
        records = []
        original = _runner(attacker, target, admission)
        original.run(points, on_response=records.append)
        admission.program["provider"] = provider
        admission.program["sources"] = {"pricing": {"sha256": "b" * 64}}
        for record in records:
            from ura.data_models import Attempt
            admission.response_checkpointed(None, Attempt.model_validate(record["attempt"]),
                                            Response.model_validate(record["response"]))
    else:
        checkpoint = tmp_path / "unpriced.responses.checkpoint.jsonl"
        _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    pool = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2 and pool["settled_cost_microusd"] == 0
    assert pool["bounded_usage_attempts"] == 0 and pool["reserved_exposure_microusd"] == 20000


@pytest.mark.parametrize("reserved,written,input_rate,expected", [("2.5", 5, "2", 96), ("2", 5, "2", 20000),
    (None, 5, "2", 20000), ("2.5", 8, "2", 20000), ("0.25", 5, 0.2, 64)])
def test_openai_reported_writes_use_only_funded_cache_ceiling(tmp_path, monkeypatch, reserved, written, input_rate, expected):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(input=input_rate, cache_read="0.2", cache_write=None)
    if reserved is not None:
        admission.prices["reservation_input"] = reserved
    generate = target.generate

    def with_writes(dialog, *, seed=None):
        response = generate(dialog, seed=seed)
        response.tokens.update(cached_input=0, cache_write_input=written)
        return response

    monkeypatch.setattr(target, "generate", with_writes)
    checkpoint = tmp_path / "writes.responses.checkpoint.jsonl"
    _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    pool = admission.budget.snapshot()["pools"]["openai:target"]
    assert pool["settled_cost_microusd"] == 0
    assert pool["unknown_usage_attempts"] == 2
    assert pool["bounded_usage_attempts"] == (0 if expected == 20000 else 2)
    assert pool["reserved_exposure_microusd"] == expected
    _runner(attacker, target, admission).run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 2


def test_precalculated_aggregate_usage_preserves_answer_and_unknown_bill_above_forecast(tmp_path, monkeypatch):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.budget.use_precalculated_spending()
    admission.prices.update(cache_read="0.2", cache_write=None, reservation_input="2.5")
    generate = target.generate

    def aggregate_usage(dialog, *, seed=None):
        response = generate(dialog, seed=seed)
        # Actual Sol Pro usage shape: aggregate input exceeds counted prompt;
        # positive cache writes lack an exact tariff in the retained price file.
        response.tokens.update(input=20565, output=6199, total=26764, cached_input=8353, cache_write_input=1808)
        return response

    monkeypatch.setattr(target, "generate", aggregate_usage)
    checkpoint = tmp_path / "aggregate.responses.checkpoint.jsonl"
    _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    pool = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2
    assert pool["tracked_spend_microusd"] == 2 * 88607
    assert pool["settled_cost_microusd"] == 0
    assert pool["unknown_usage_attempts"] == pool["bounded_usage_attempts"] == 2
    assert not (admission.budget.root / "paid-circuit.json").exists()
    ledger = (admission.budget.root / "ledger.json").read_bytes()
    _runner(attacker, target, admission).run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 2
    assert (admission.budget.root / "ledger.json").read_bytes() == ledger


def test_typed_provider_refusal_is_funded_observed_outcome_not_paid_stop(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    create = target._client.chat.completions.create

    def refuse(**request):
        result = create(**request)
        result.choices[0].message.content = None
        result.choices[0].message.refusal = "I cannot assist with that request."
        return result

    target._client.chat.completions.create = refuse
    checkpoint = tmp_path / "refusals.responses.checkpoint.jsonl"
    runner = _runner(attacker, target, admission)
    runner.run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    assert len(calls) == len(admission.requests)
    assert all(r.raw["provider_refusal"] is True and r.output_turns == [] for r in runner.responses)
    assert not (admission.budget.root / "paid-circuit.json").exists()
    program = {"target": target.name, "requests": admission.requests,
               "jobs": [{"argv": ["--out", str(tmp_path)]}]}
    assert subject._retained_execution_counts(program, admission.budget) == (len(admission.requests), len(admission.requests))
    before = len(calls)
    _runner(attacker, target, admission).run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == before


@pytest.mark.parametrize("policy_code", ["cyber_policy", "bio_policy"])
def test_policy_http_400_retains_unknown_charge_and_continues_next_input(tmp_path, policy_code):
    import httpx
    import openai
    denied = openai.BadRequestError('policy rejection', response=httpx.Response(400,
        request=httpx.Request('POST', 'https://example.test')),
        body={'code': policy_code, 'type': 'invalid_request_error'})
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=[denied, 'I cannot help with that.'])
    runner = _runner(attacker, target, admission)
    from ura.targets.api import canonical_https_endpoint_identity
    # Match actual measured lanes, not an unattested diagnostic fixture.
    runner.expected_target_identity = {"provider": "openai", "resolved_model": target.model,
        "endpoint_identity": canonical_https_endpoint_identity(target.base_url)}
    checkpoint = tmp_path / 'policy.responses.checkpoint.jsonl'
    runner.run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    assert len(calls) == len(runner.responses) == 2
    assert runner.responses[0].raw['provider_refusal_category'] == f'openai_http400_{policy_code}'
    assert runner.responses[0].output_turns == [] and runner.responses[0].tokens is None
    assert runner.responses[1].output_turns[0].content == 'I cannot help with that.'
    assert not (admission.budget.root / 'paid-circuit.json').exists()
    ledger = json.loads((admission.budget.root / 'ledger.json').read_text())
    first = admission.job['input_ids'][0]
    assert ledger['attempts'][first]['1'] == {'actual_cost_microusd': None, 'state': 'unknown'}
    from ura.runner import validate_planned_realized_identities, realized_identity_summary
    summary = realized_identity_summary(runner.responses, [])
    validate_planned_realized_identities({'expected_target_identity':runner.expected_target_identity}, {}, runner.responses, [], summary)
    resumed = _runner(attacker, target, admission)
    resumed.expected_target_identity = runner.expected_target_identity
    resumed.run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 2
    assert resumed.responses[0].raw['resolved_model'] is None


@pytest.mark.parametrize('change', ['endpoint', 'provider', 'model', 'code', 'category', 'generation', 'output', 'usage'])
def test_policy_http_400_does_not_hide_actual_identity_or_outcome_conflicts(tmp_path, change):
    import httpx
    import openai
    from ura.runner import validate_planned_realized_identities
    from ura.targets.api import canonical_https_endpoint_identity
    denied = openai.BadRequestError('policy rejection', response=httpx.Response(400,
        request=httpx.Request('POST', 'https://example.test')),
        body={'code': 'cyber_policy', 'type': 'invalid_request_error'})
    points, attacker, target, _calls, admission = _setup(tmp_path, outputs=[denied, 'I cannot help with that.'])
    runner = _runner(attacker, target, admission)
    records = []
    runner.run(points, on_response=records.append)
    response = runner.responses[0].model_copy(deep=True)
    expected = {'provider':'openai', 'resolved_model':target.model,
                'endpoint_identity':canonical_https_endpoint_identity(target.base_url)}
    if change == 'endpoint':
        response.raw['endpoint_identity'] = canonical_https_endpoint_identity('https://different.example/v1')
    elif change == 'provider':
        response.raw['provider'] = 'kimi'
    elif change == 'model':
        response.raw['resolved_model'] = 'wrong-model'
    elif change == 'code':
        response.raw['call_audit']['provider_error_code'] = 'invalid_parameter'
    elif change == 'category':
        response.raw['provider_refusal_category'] = 'unrecognized'
    elif change == 'generation':
        response.raw['provider_generation_observed'] = True
    elif change == 'output':
        response.output_turns = [DialogTurn(role='assistant', content='ordinary answer')]
    else:
        response.tokens = {'input':1, 'output':1}
    runner.expected_target_identity = expected
    with pytest.raises((ValueError, RuntimeError)):
        runner._validate_attested_target_identity(response)
    with pytest.raises(ValueError):
        validate_planned_realized_identities({'expected_target_identity':expected}, {}, [response], [], {'judges':[]})


def test_malformed_refusal_cannot_be_counted_as_an_observed_outcome(tmp_path):
    points, attacker, target, _calls, admission = _setup(tmp_path)
    records = []
    _runner(attacker, target, admission).run(points, on_response=records.append)
    row = copy.deepcopy(records[0]["response"])
    row["raw"].update(provider_refusal=True, provider_refusal_category="openai_refusal")
    # A refusal cannot simultaneously contain ordinary generated text.
    (tmp_path / "contradictory.responses.jsonl").write_text(json.dumps(row) + "\n")
    program = {"target": target.name, "requests": admission.requests,
               "jobs": [{"argv": ["--out", str(tmp_path)]}]}
    with pytest.raises(ValueError, match="exactly one"):
        subject._retained_execution_counts(program, admission.budget)


@pytest.mark.parametrize("cached,write_rate,expected_cost", [(0, None, 88), (2, None, 82), (0, "3", None)])
def test_read_only_cache_tariff_does_not_require_unpriced_write_counter(tmp_path, monkeypatch, cached, write_rate, expected_cost):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(cache_read="0.5", cache_write=write_rate)
    generate = target.generate
    def with_cache_usage(dialog, *, seed=None):
        response = generate(dialog, seed=seed)
        response.tokens["cached_input"] = cached
        assert "cache_write_input" not in response.tokens
        return response
    monkeypatch.setattr(target, "generate", with_cache_usage)
    checkpoint = tmp_path / "responses.jsonl"
    _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2
    if expected_cost is None:
        assert state["unknown_usage_attempts"] == 2
    else:
        assert state["unknown_usage_attempts"] == 0
        assert state["settled_cost_microusd"] == expected_cost
    _runner(attacker, target, admission).run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 2


@pytest.mark.parametrize("read_rate,write_rate,cached,written,expected_cost", [
    ("0.5", None, 0, 0, 88),
    ("0.5", None, 2, 0, 82),
    (None, "3", 0, 1, 90),
    (None, "3", 1, 0, None),
    ("0.5", None, 0, 1, None),
])
def test_zero_cache_usage_needs_no_rate_and_resume_never_rebills(
    tmp_path, monkeypatch, read_rate, write_rate, cached, written, expected_cost,
):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(cache_read=read_rate, cache_write=write_rate)
    generate = target.generate

    def with_cache_usage(dialog, *, seed=None):
        response = generate(dialog, seed=seed)
        response.tokens.update(cached_input=cached, cache_write_input=written)
        return response

    monkeypatch.setattr(target, "generate", with_cache_usage)
    checkpoint = tmp_path / "responses.jsonl"
    _runner(attacker, target, admission).run(
        points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row),
    )
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert state["unresolved_attempts"] == 0
    if expected_cost is None:
        assert state["unknown_usage_attempts"] == 2
        assert state["reserved_exposure_microusd"] == 20000
    else:
        assert state["unknown_usage_attempts"] == 0
        assert state["settled_cost_microusd"] == expected_cost
    resumed = _runner(attacker, target, admission)
    resumed.run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == len(resumed.responses) == 2


def test_peak_funded_route_does_not_release_an_assumed_off_peak_discount(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.prices.update(reservation_input="4", reservation_output="12",
                            settlement_input="4", settlement_output="12")
    _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2
    assert state["settled_cost_microusd"] == 176


def test_credit_exhaustion_preserves_checkpoint_and_unknown_charge_without_retry(tmp_path):
    failure = RuntimeError("private provider error")
    failure.status_code = 429
    failure.body = {"error": {"code": "credit_balance_exhausted", "type": "insufficient_quota"}}
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=[failure, "must not run"])
    checkpoint = tmp_path / "responses.jsonl"
    with pytest.raises(RuntimeError, match="durable response"):
        _runner(attacker, target, admission).run(
            points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row),
        )
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(records) == len(calls) == 1
    response = next(iter(records.values()))["response"]
    assert response["raw"]["call_audit"]["provider_funding_status"] == "credit_balance_exhausted"
    assert response["raw"]["transport_retry_status"] == "not_retryable"
    assert response["tokens"] is None and response["output_turns"] == []
    assert admission.budget.provider_funding_stops()[0]["category"] == "provider_funding_unavailable"
    assert not (admission.budget.root / "paid-circuit.json").exists()
    assert admission.budget.snapshot()["pools"]["openai:target"]["unknown_usage_attempts"] == 1


def test_paid_empty_response_is_durable_then_pauses_only_its_target(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=["", "must never run"])
    checkpoint = tmp_path / "responses.jsonl"
    with pytest.raises(RuntimeError, match="durable response"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(calls) == len(records) == 1
    assert not (admission.budget.root / "paid-circuit.json").exists()
    pause = subject.target_pause(admission.budget, target.name)
    assert pause["category"] == "missing_target_output"
    assert subject.target_pause(admission.budget, "openai:another-model") is None
    assert next(iter(records.values()))["response"]["raw"]["model_stability_status"] == "failed_output"
    assert admission.budget.snapshot()["pools"]["openai:target"]["unknown_usage_attempts"] == 1

    # A new worker on the same target stops before the SDK, without poisoning
    # the shared budget. Another target's unused slot remains available.
    entry = list(admission.entries.values())[1]
    attempt = SimpleNamespace(params={"retained_origin": entry["origin"]},
                              rendered_input=retained_dialog(entry["rendered_input"]), seed=0)
    with pytest.raises(subject.TargetRoutePaused, match="target awaits review"):
        with admission.attempt(SimpleNamespace(target=target), attempt):
            target.generate(attempt.rendered_input, seed=0)
    assert len(calls) == 1
    assert not (admission.budget.root / "paid-circuit.json").exists()
    admission.budget.reserve(list(admission.requests.values())[1]["call_id"], 1, provider="openai")


@pytest.mark.parametrize("purpose", ["attestation_probe", "diagnostic_canary", "measured_run"])
def test_usable_truncated_response_never_opens_paid_circuit(tmp_path, purpose):
    points, attacker, target, calls, admission = _setup(tmp_path)
    admission.job["purpose"] = purpose
    create = target._client.chat.completions.create

    def truncated(**request):
        result = create(**request)
        result.choices[0].finish_reason = "length"
        return result

    target._client.chat.completions.create = truncated
    records = []
    _runner(attacker, target, admission).run(points, on_response=records.append)
    assert len(records) == len(calls) == 2
    assert all(row["response"]["raw"]["output_truncated"] is True for row in records)
    assert not (admission.budget.root / "paid-circuit.json").exists()


@pytest.mark.parametrize("execution_stage", ["all", "judgments"])
def test_restored_missing_paid_output_can_finish_judging_without_reopening_target_calls(tmp_path, execution_stage):
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=["", "must never run"])
    checkpoint = tmp_path / "responses.jsonl"
    with pytest.raises(RuntimeError, match="durable response"):
        _runner(attacker, target, admission).run(
            points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    records = Runner.load_response_checkpoint(checkpoint)
    before = (admission.budget.root / "ledger.json").read_bytes()
    pause_path = subject.target_pause_path(admission.budget, target.name)
    pause = pause_path.read_bytes()
    # Restore just the retained attempt; no new answer or judge classification
    # is appropriate for an empty output. The original paid stop stays in force.
    first = next(iter(records.values()))
    from ura.data_models import Attempt
    attempt = Attempt.model_validate(first["attempt"])
    response = Response.model_validate(first["response"])
    resumed = _runner(attacker, target, admission)
    resumed.execution_stage = execution_stage
    resumed.stop_on_failed_output = True
    restored = resumed._execute_or_restore(points[0], attempt, response.run_id, None, None,
                                          response_record=first)
    assert restored == response
    assert len(calls) == 1
    assert pause_path.read_bytes() == pause
    assert (admission.budget.root / "ledger.json").read_bytes() == before


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


class _HTTP400(Exception):
    status_code = 400


@pytest.mark.parametrize("failure,expected_state,physical", [
    (ConnectionError("disconnected"), "exhausted", 4),
    (_HTTP500("unavailable"), "exhausted", 4),
    (_HTTP400("request rejected"), "not_retryable", 1),
])
def test_terminal_transport_failure_does_not_claim_a_pending_retry(tmp_path, monkeypatch, failure, expected_state, physical):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, outputs=[failure] * 4)
    checkpoint = tmp_path / "responses.jsonl"
    with pytest.raises(RuntimeError, match="durable response"):
        _runner(attacker, target, admission).run(
            points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row),
        )
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(records) == 1
    response = next(iter(records.values()))["response"]
    assert response["raw"]["transport_retry_status"] == expected_state
    assert response["raw"]["model_stability_category"] == "transport_failure"
    assert response["output_turns"] == [] and response["tokens"] is None
    assert subject.target_pause(admission.budget, target.name)["category"] == "terminal_transport_failure"
    assert not (admission.budget.root / "paid-circuit.json").exists()
    assert len(calls) == physical
    assert admission.budget.snapshot()["pools"]["openai:target"]["unknown_usage_attempts"] == physical
    assert admission.budget.snapshot()["pools"]["openai:target"]["unstarted_first_commitments_microusd"] == 10000
    retained = Response.model_validate(response)
    validate_response_refusal_state(retained)
    for bad_raw in (
        {**retained.raw, "transport_retry_status": "complete"},
        {**retained.raw, "model_stability_category": "empty_final_output"},
    ):
        with pytest.raises(ValueError, match="transport retry state"):
            validate_response_refusal_state(retained.model_copy(update={"raw": bad_raw}))


@pytest.mark.parametrize("retryable,ordinal,retries,expected", [
    (True, 1, 3, "pending"),
    (True, 4, 3, "exhausted"),
    (False, 1, 3, "not_retryable"),
    (None, 1, 3, "needs_review"),
])
def test_transport_retry_state_uses_lifetime_ordinal_not_current_invocation_length(retryable, ordinal, retries, expected):
    from types import SimpleNamespace
    from ura.runner import _transport_failure_retry_state

    error = SimpleNamespace(call_audit={"transport_retryable": retryable}, transport_attempts=[{"attempt": ordinal}])
    assert _transport_failure_retry_state(error, SimpleNamespace(max_retries=retries)) == expected


@pytest.mark.parametrize("failure", [_HTTP500("mock"), ConnectionError("disconnected")])
def test_status_retry_reserves_each_physical_attempt_and_holds_unknown_charge(tmp_path, monkeypatch, failure):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, adaptive=False,
                                                       outputs=[failure, "usable"])
    _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    state = admission.budget.snapshot()["pools"]["openai:target"]
    assert len(calls) == 2 and state["unknown_usage_attempts"] == 1
    assert state["reserved_exposure_microusd"] == 10000 and state["settled_cost_microusd"] == 44


@pytest.mark.parametrize("failure", [_HTTP500("mock"), ConnectionError("disconnected")])
def test_retry_cannot_spend_remaining_selected_first_calls(tmp_path, monkeypatch, failure):
    monkeypatch.setattr("ura.targets.api.time.sleep", lambda seconds: None)
    points, attacker, target, calls, admission = _setup(tmp_path, tight=True,
                                                       outputs=[failure, "must never run"])
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
                    [0], target_answer_retries=0, execution_stage="responses")
    runner.run(sampled)
    assert len(calls._dialogs) == 1 and runner.attempts[0].datapoint_id == chosen.id


def test_funded_distinct_partition_does_not_regenerate_collapsed_source_rows(tmp_path, monkeypatch):
    points, attacker, _target, calls, admission = _setup(tmp_path, adaptive=False)
    sibling = points[0].model_copy(update={"id": "collapsed-source-alias"})
    monkeypatch.setattr(run_matrix, "load_corpus_with_audit", lambda *a, **kw: (
        [*points, sibling], {"selected_indices": [0, 1], "selected_records": 2}))
    kwargs = dict(attacker=attacker, sampling_policy=None, source_instance={})
    with pytest.raises(ValueError, match="whole original source clusters"):
        run_matrix.load_retained_replay_corpus("retained-corpus", 1, 0, **kwargs)
    # An ordinary monetary admission alone must not waive the raw-source check.
    with retained_execution_admission(admission), pytest.raises(ValueError, match="whole original source clusters"):
        run_matrix.load_retained_replay_corpus("retained-corpus", 1, 0, **kwargs)
    subject._bind_funded_cluster_population([admission])
    with retained_execution_admission(admission):
        selected, audit = run_matrix.load_retained_replay_corpus("retained-corpus", 1, 0, **kwargs)
    assert selected == points and not calls
    assert audit["cluster_coverage_basis"] == "validated_distinct_funded_population"
    assert audit["funded_population_input_count"] == audit["selected_funded_input_count"] == 1


def test_funded_partition_cannot_split_one_unpaid_cluster_into_probe_and_measured(tmp_path):
    _points, _attacker, _target, calls, whole = _setup(tmp_path, adaptive=True)
    parts = []
    for key in whole.entries:
        part = copy.copy(whole)
        part.entries = {key: whole.entries[key]}
        parts.append(part)
    subject._bind_funded_cluster_population(parts)
    for part in parts:
        with pytest.raises(ValueError, match="whole unpaid source clusters"):
            part.validate_funded_cluster_partition("retained-corpus")
    assert not calls


def test_scoped_cli_uses_exact_nonprefix_inputs_and_seals_one_mock_response(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("URA_"):
            monkeypatch.delenv(key)
    points, _audit = run_matrix.load_corpus_with_audit("synth", 0, 0)
    chosen = next(point for point in reversed(points) if point.modalities == ["text"] and point.expected_behavior == "refuse")
    _points, _cell, _plan, _bindings, value, config = _fixture(tmp_path, points=[chosen], corpus="synth")
    config["retained_input_ids"] = [value["entries"][0]["origin"]["selection"]["input_identity_sha256"]]
    config_path = tmp_path / "attacker.json"
    config_path.write_text(json.dumps({"replay": config}))
    calls = []

    class RecordingTarget(_RecordingMock):
        def generate(self, dialog, *, seed=None):
            calls.append(dialog)
            response = super().generate(dialog, seed=seed)
            return response.model_copy(update={"output_turns": [DialogTurn(role="assistant", content="I cannot assist with that request.")]})

    # This fixture bypasses monetary admission only for the existing mock CLI;
    # production admission rejects --dry-run and tests actual SDK funding above.
    admission = SimpleNamespace(validate_cli=lambda argv, args: None,
                                validate_runner=lambda runner: None,
                                attempt=lambda runner, attempt: nullcontext(),
                                response_checkpointed=lambda runner, attempt, response, **kwargs: None)
    monkeypatch.setattr(run_matrix, "build_target", lambda spec, **kwargs: RecordingTarget())
    out = tmp_path / "mock-run"
    with retained_execution_admission(admission):
        result = run_matrix.main(["--dry-run", "--corpora", "synth", "--limit", "1", "--judges", "rules",
            "--attackers", "replay", "--target-answer-retries", "0", "--attacker-config", str(config_path),
            "--attacker-config-sha256", hashlib.sha256(config_path.read_bytes()).hexdigest(), "--out", str(out)])
    assert result == 0 and len(calls) == 1
    manifests = [json.loads(path.read_text()) for path in out.glob("*.manifest.json")]
    audit = manifests[0]["config"]["run"]["sampling_audit"]
    assert audit["selected_ids"] == [chosen.id] and audit["selected_clusters"] == 1
    assert list(out.glob("*.complete.json"))


def test_fully_bound_program_still_cannot_skip_final_campaign_admission(tmp_path):
    with pytest.raises(ValueError, match="complete local-source program admission"):
        subject._validated_jobs({}, None)


def _program(
    tmp_path,
    monkeypatch,
    *,
    target_spec="openai:gpt-5.5",
    judge_rates=(1, 5),
    extra_points=0,
    source_capture=None,
    scoring_probes=False,
    reservation_policy="first_attempts_upfront",
):
    from test_hosted_campaign_budget import _api_config, _pricing, _budgets
    from experiments import hosted_campaign_budget as money, hosted_retained_inputs as materializer
    from experiments.hosted_request_tokens import count_request
    points, cell, _old_plan, _old_bindings, _value, _config = _fixture(tmp_path, adaptive=True)
    if scoring_probes:
        # Preparation needs a scoring-capable pilot AND measured population.
        # The default fixture deliberately contains one Crescendo setup turn;
        # here use two direct, independently evaluable source clusters instead.
        from ura.converters._common import canonical_converted_corpus_sha256
        second = points[0].model_copy(update={"id": "independent-input",
            "payload_text": "A different retained source question",
            "meta": {**points[0].meta, "source_cluster_id": "independent-cluster"}})
        points.append(second)
        cell["manifest"]["dataset_hashes"]["corpus"] = canonical_converted_corpus_sha256(points)
        for index, attempt in enumerate(cell["attempts"].values()):
            point = points[index]
            attempt["attacker"] = "replay"
            attempt["datapoint_id"] = point.id
            attempt["rendered_input"] = [attempt["rendered_input"][0],
                {"role": "user", "content": point.payload_text, "media": []}]
            attempt["params"].update(policy_evaluable_turn=True,
                turn_expected_behavior=point.expected_behavior, policy_challenge_index=0,
                source_cluster_id=point.meta["source_cluster_id"])
        cell["artifacts"]["attempts"].write_text("\n".join(json.dumps(row) for row in cell["attempts"].values()) + "\n")
    if extra_points:
        from ura.converters._common import canonical_converted_corpus_sha256
        for number in range(extra_points):
            point = points[0].model_copy(update={"id": f"extra-{number}",
                "payload_text": f"Additional source question {number}",
                "meta": {**points[0].meta, "source_cluster_id": f"extra-cluster-{number}"}})
            points.append(point)
            attempt = copy.deepcopy(cell["attempts"]["original-0"])
            attempt.update(id=f"extra-{number}", datapoint_id=point.id)
            attempt["params"]["source_cluster_id"] = point.meta["source_cluster_id"]
            attempt["rendered_input"][-1]["content"] = point.payload_text
            cell["attempts"][attempt["id"]] = attempt
            cell["responses"][attempt["id"]] = {"output_turns": []}
            cell["judgments"].append({"attempt_id": attempt["id"],
                                     "raw": copy.deepcopy(cell["judgments"][0]["raw"])})
        cell["manifest"]["dataset_hashes"]["corpus"] = canonical_converted_corpus_sha256(points)
        cell["artifacts"]["attempts"].write_text("\n".join(json.dumps(row) for row in cell["attempts"].values()) + "\n")
    if source_capture is not None:
        source_capture.update(points=points, cell=cell)
    billing_provider = subject._billing_provider(target_spec.split(":", 1)[0])
    api = _api_config()
    api[target_spec]["temperature"] = None

    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

    pricing = _pricing()
    pricing["providers"]["anthropic"]["models"][money.JUDGE_MODEL]["rates"][0][
        "per_million_tokens"
    ].update(input=judge_rates[0], output=judge_rates[1])
    sources = {"api_config": save("api.json", api), "pricing": save("prices.json", pricing),
               "budgets": save("budgets.json", _budgets()), "media_index": save("media.json", {})}
    def portable(raw):
        return {"file": Path(raw["path"]).name, "sha256": raw["sha256"], "bytes": raw["bytes"]}
    budget_projection = money.build_projection(api_config=api, pricing=pricing, budgets=_budgets(),
        descriptors={"api_config": portable(sources["api_config"]), "pricing_config": portable(sources["pricing"]),
                     "budgets": portable(sources["budgets"])}, pricing_as_of="2026-09-03",
                     reservation_policy=reservation_policy)
    sources["budget_projection"] = save("projection.json", budget_projection)
    inventory = save("historical-inventory.json", {"fixture": "not a real complete local campaign"})
    monkeypatch.setattr(subject, "_validated_local_cells", lambda program: ([cell], inventory))
    bindings = {"budget": budget_projection, "budget_descriptor": portable(sources["budget_projection"]),
                "api_config": api, "api_descriptor": portable(sources["api_config"]),
                "media_index": {}, "local_inventory_descriptor": portable(inventory)}
    plan = materializer.build_plan(candidates=materializer.candidates_from_cells([cell]), target=target_spec, call_cap=2, **bindings)
    value = materializer.materialize_replay(plan, cells=[cell], source_corpora={cell["run_id"]: points},
                                            corpus="retained-corpus", **bindings)
    replay = save("real-shaped-replay.json", value)
    normalized, _api_artifact = run_matrix._load_api_config(
        sources["api_config"]["path"], [target_spec], sources["api_config"]["sha256"],
    )
    target = run_matrix.build_target(target_spec, api_config=normalized.get(target_spec))
    requests, jobs, slots = {}, [], []
    for index, entry in enumerate(value["entries"]):
        key = entry["origin"]["selection"]["input_identity_sha256"]
        call_id = "target-" + subject._sha({"target": target_spec, "input_id": key})
        request = target.build_request(retained_dialog(entry["rendered_input"]), seed=0)
        count = count_request(target, request, allow_network=False)
        requests[key] = {"call_id": call_id, "request_sha256": subject._sha(request), "token_count": count,
                         "input_tokens": count["input_tokens"], "max_output_tokens": 8192, "bound_microusd": 500000}
        requests[key]["judge_call_ids"] = {cohort: "judge-" + cohort + "-" + subject._sha({"target": target_spec, "input_id": key})
                                           for cohort in ("local", "hosted")}
        slots.append({"call_id": call_id, "provider": billing_provider, "pool": "target", "bound_microusd": 500000})
        judge_bound = int(
            money.JUDGE_MAX_INPUT_TOKENS * judge_rates[0]
            + money.JUDGE_MAX_OUTPUT_TOKENS * judge_rates[1]
        )
        slots += [{"call_id": value, "provider": "anthropic", "pool": "judge", "bound_microusd": judge_bound}
                  for value in requests[key]["judge_call_ids"].values()]
        config = save(f"attacker{index}.json", {"replay": {"replay_artifact": replay["path"],
            "replay_artifact_sha256": replay["sha256"], "retained_input_ids": [key]}})
        argv = ["--api", target_spec, "--api-config", sources["api_config"]["path"],
                "--api-config-sha256", sources["api_config"]["sha256"], "--corpora", "retained-corpus",
                "--attackers", "replay", "--judges", "rules,guardrail", "--seeds", "0", "--sample-seed", "0",
                "--target-answer-retries", "0", "--max-total-target-calls", "1", "--max-total-judge-calls", "1",
                "--max-total-http-attempts", "4", "--max-queries", "1", "--max-turns", "1",
                "--attacker-config", config["path"], "--attacker-config-sha256", config["sha256"],
                "--out", str(tmp_path / f"job{index}"), "--limit", "1" if index == 0 else "0"]
        if index == 0:
            argv.append("--diagnostic-canary")
        jobs.append({"name": f"job{index}", "input_ids": [key], "purpose": "diagnostic_canary" if index == 0 else "measured_run",
                     "argv": argv})
    descriptor = create_budget(tmp_path / "program-money", provider_budgets_microusd={
        "anthropic": 90000000, "openai": 40000000, "kimi": 15000000, "deepseek": 10000000}, planned_calls=slots)
    program = {"schema": subject.SCHEMA, "budget_plan_sha256": descriptor["sha256"], "sources": sources,
               "target": target_spec, "provider": billing_provider, "max_output_tokens": 8192,
               "pricing_as_of": "2026-09-03", "jobs": jobs, "requests": requests,
               "token_count_policy": subject.TOKEN_COUNT_POLICY,
               "replaced_descriptive_prerequisite": "authority.requires_exact_provider_token_counts",
               "predecessor_selection": {"schema": plan["schema"], "plan_id": plan["plan_id"], "sha256": subject._sha(plan)}}
    return program, AttemptBudget(tmp_path / "program-money", descriptor["sha256"])


def test_program_rebuilds_exact_selection_and_fixed_disjoint_pilot_before_any_client(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch)
    monkeypatch.setattr(OpenAITarget, "_get_client", lambda self: pytest.fail("program validation cannot construct SDK"))
    jobs = subject._validated_jobs(program, budget)
    assert len(jobs) == 2
    assert set(jobs[0].entries).isdisjoint(jobs[1].entries)
    assert budget.snapshot()["pools"]["openai:target"]["unstarted_first_commitments_microusd"] == 1000000


def test_program_applies_peak_funded_deepseek_rates_to_settlement(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch, target_spec="deepseek:deepseek-v4-pro")
    jobs = subject._validated_jobs(program, budget)
    assert jobs[0].prices["reservation_input"] == "1.32"
    assert jobs[0].prices["reservation_output"] == "3.96"
    assert jobs[0].prices["settlement_input"] == "1.32"
    assert jobs[0].prices["settlement_output"] == "3.96"


def test_program_derives_judge_slot_floor_from_bound_projection_rates(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch, judge_rates=(0.5, 2))
    jobs = subject._validated_jobs(program, budget)
    assert len(jobs) == 2
    judge_slots = [
        budget.call(call_id)
        for request in program["requests"].values()
        for call_id in request["judge_call_ids"].values()
    ]
    assert {slot["bound_microusd"] for slot in judge_slots} == {7168}


def test_registered_execution_publishes_one_hosted_tmux_job(tmp_path, monkeypatch):
    program, budget = _program(tmp_path, monkeypatch)
    program_path = tmp_path / "hosted-program.json"
    program_path.write_text(json.dumps(program))
    program_sha = hashlib.sha256(program_path.read_bytes()).hexdigest()
    work = tmp_path / "work"
    (work / "runs" / "engineering").mkdir(parents=True)
    control = work / "runs" / "engineering" / "hosted-gpt55"
    project = tmp_path / "project"
    project.mkdir()
    outputs = [Path(job["argv"][job["argv"].index("--out") + 1]) for job in program["jobs"]]
    monkeypatch.setattr(subject, "_validated_checkout", lambda root, commit: project)
    validations = []
    validate = subject._validated_local_cells
    monkeypatch.setattr(subject, "_validated_local_cells",
                        lambda value: validations.append(value) or validate(value))
    calls = []
    monkeypatch.setattr(run_matrix, "main", lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(subject, "_retained_execution_counts", lambda value, money: (2, 2))

    observed = subject.execute_registered(
        program_path=program_path,
        program_sha256=program_sha,
        budget_root=budget.root,
        budget_plan_sha256=budget.expected_plan_sha256,
        project_root=project,
        expected_commit="a" * 40,
        work_root=work,
        control_root=control,
        tmux_socket="ura-hosted-gpt55",
        tmux_session="hosted-gpt55",
    )
    assert observed == outputs
    assert len(validations) == 1
    assert calls == [job["argv"] for job in program["jobs"]]
    marker = json.loads((control / "ENGINEERING_ONLY.json").read_text())
    assert marker["hosted_calls_allowed"] is True
    assert marker["target_call_cap"] == 2
    report = json.loads((control / "model-execution.jsonl").read_text())
    assert report["attempted_calls"] == report["successful_generations"] == 2
    events = [json.loads(line) for line in (control / "task-log.jsonl").read_text().splitlines()]
    assert events[-2]["status"] == events[-1]["status"] == "passed"


def test_registered_execution_rejects_incomplete_local_source_before_job_or_client(
    tmp_path, monkeypatch,
):
    program, budget = _program(tmp_path, monkeypatch)
    program_path = tmp_path / "hosted-program.json"
    program_path.write_text(json.dumps(program))
    work = tmp_path / "work"
    (work / "runs" / "engineering").mkdir(parents=True)
    control = work / "runs" / "engineering" / "hosted-blocked"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setattr(subject, "_validated_checkout", lambda root, commit: project)
    monkeypatch.setattr(
        subject,
        "_validated_jobs",
        lambda value, money: (_ for _ in ()).throw(ValueError("RR incomplete")),
    )
    monkeypatch.setattr(subject, "execute", lambda **kwargs: pytest.fail("paid executor reached"))
    with pytest.raises(ValueError, match="RR incomplete"):
        subject.execute_registered(
            program_path=program_path,
            program_sha256=hashlib.sha256(program_path.read_bytes()).hexdigest(),
            budget_root=budget.root,
            budget_plan_sha256=budget.expected_plan_sha256,
            project_root=project,
            expected_commit="a" * 40,
            work_root=work,
            control_root=control,
            tmux_socket="ura-hosted-blocked",
            tmux_session="hosted-blocked",
        )
    assert not control.exists()


@pytest.mark.parametrize("mutation", ["repeat_pilot", "skip_input", "changed_request", "changed_count", "answer_retry",
                                     "unfinished_local", "invented_judge", "wrong_predecessor", "measured_first"])
def test_program_rejects_changed_selection_count_retry_or_unfinished_local(tmp_path, monkeypatch, mutation):
    program, budget = _program(tmp_path, monkeypatch)
    if mutation == "repeat_pilot":
        program["jobs"][1] = copy.deepcopy(program["jobs"][0])
    elif mutation == "skip_input":
        program["jobs"].pop()
    elif mutation == "changed_request":
        next(iter(program["requests"].values()))["request_sha256"] = "0" * 64
    elif mutation == "changed_count":
        next(iter(program["requests"].values()))["token_count"]["input_tokens"] += 1
    elif mutation == "answer_retry":
        argv = program["jobs"][0]["argv"]
        argv[argv.index("--target-answer-retries") + 1] = "1"
    elif mutation == "invented_judge":
        next(iter(program["requests"].values()))["judge_call_ids"]["hosted"] = "invented-output-hash"
    elif mutation == "wrong_predecessor":
        program["predecessor_selection"]["sha256"] = "a" * 64
    elif mutation == "measured_first":
        program["jobs"].reverse()
    else:
        monkeypatch.setattr(subject, "_validated_local_cells", lambda program: (_ for _ in ()).throw(ValueError("RR incomplete")))
        monkeypatch.setattr(run_matrix, "build_target", lambda *args, **kwargs: pytest.fail("unfinished local source reached target factory"))
    with pytest.raises(ValueError):
        subject._validated_jobs(program, budget)


def _matched_funding(tmp_path, monkeypatch):
    from experiments import retained_response_judge as retained
    from experiments import retained_response_judge_execute as judging
    from experiments import retained_response_judge_pair as pairs
    from test_retained_input_replay import _matching_view, _runner
    from test_retained_response_judge_execute import JUDGE, _prepared
    from ura.runner import _portable_attempt_dump

    source_root = tmp_path / "original"
    source_root.mkdir()
    points, original, _plan, _bindings, value, config = _fixture(source_root, adaptive=True)
    prepared = _prepared(tmp_path, monkeypatch)
    api = json.loads(prepared["api_config"].read_bytes())
    api[JUDGE]["max_tokens"] = 512
    prepared["api_config"].write_bytes(judging._canonical(api))
    api_sha = hashlib.sha256(prepared["api_config"].read_bytes()).hexdigest()
    programs, slots, admissions, hosted_cells = [], [], {}, []

    class NamedMock(_RecordingMock):
        def generate(self, dialog, *, seed=None):
            return super().generate(dialog, seed=seed).model_copy(update={"target": self.name})

    for spec in ("openai:gpt-5.5", "openai:gpt-5.6-terra", "anthropic:claude-haiku-4-5"):
        mock = NamedMock()
        mock.name = spec
        runner = _runner(config, target=mock)
        runner.run(points, run_config={"attacker": "replay", "corpus": "retained-corpus",
                                      "project_revision": {"sha256": "c" * 64}})
        hosted_cells.append({"source_identity_validated": True, "run_id": runner.last_manifest.run_id,
            "model": spec, "manifest": runner.last_manifest.model_dump(mode="json"),
            "attempts": {a.id: _portable_attempt_dump(a) for a in runner.attempts}})
        entries, requests = {}, {}
        for entry in value["entries"]:
            key = entry["origin"]["selection"]["input_identity_sha256"]
            ids = {cohort: "judge-" + cohort + "-" + subject._sha({"target": spec, "input_id": key})
                   for cohort in ("local", "hosted")}
            entries[key] = entry
            requests[key] = {"judge_call_ids": ids}
            slots += [{"call_id": call_id, "provider": "anthropic", "pool": "judge", "bound_microusd": 14848}
                      for call_id in ids.values()]
        admissions[spec] = [SimpleNamespace(entries=entries, requests=requests)]
        programs.append({"target": spec})
    hosted_view = tmp_path / "hosted"
    hosted_view.mkdir()
    local_view = _matching_view(original)
    views = [_matching_view(cell) for cell in hosted_cells]
    hosted = (hosted_cells, {k: v for view in views for k, v in view[1].items()},
              {k: v for view in views for k, v in view[2].items()},
              {"policy_evaluable_samples": 3, "common_ineligible_evaluable_rows_excluded": 0})
    # Only the absent final campaign seal/read-only artifact boundary is
    # synthetic. Actual Runner Attempts, origin checks and paired join execute.
    monkeypatch.setattr(subject, "_validated_local_cells", lambda program: ([original], {}))
    monkeypatch.setattr(subject, "_validated_jobs", lambda program, budget, **kwargs: admissions[program["target"]])
    monkeypatch.setattr(retained, "_read_view", lambda path: hosted if path == hosted_view else local_view)
    (local_rows, local_audit), (hosted_rows, hosted_audit), _ = retained.load_pair_candidate_views(prepared["runner_view"], hosted_view)
    condition = prepared["plan"]["judge_condition"]
    pricing = {key: condition[key] for key in (
        "pricing_config_sha256", "pricing_as_of", "pricing_effective_date", "pricing_currency",
        "input_microusd_per_token", "output_microusd_per_token")}
    plan = pairs.build_pair_plan(local_rows, hosted_rows, local_population_audit=local_audit,
        hosted_population_audit=hosted_audit, source_descriptor=prepared["plan"]["source"],
        judge_model=JUDGE, api_config_sha256=api_sha, pricing_condition=pricing, limit=3, share_local_judgments=True)
    prepared["plan_path"].write_bytes(judging._canonical(plan))
    descriptor = create_budget(tmp_path / "funded-pairs", provider_budgets_microusd={"anthropic": 90000000}, planned_calls=slots)
    budget = AttemptBudget(tmp_path / "funded-pairs", descriptor["sha256"])
    kwargs = {key: prepared[key] for key in ("plan_path", "source_receipt", "api_config")}
    kwargs.update(programs=programs, budget=budget, plan_sha256=hashlib.sha256(prepared["plan_path"].read_bytes()).hexdigest(),
                  local_runner_view=prepared["runner_view"], hosted_runner_view=hosted_view)
    return prepared, plan, admissions, kwargs


def test_actual_retained_pair_outputs_bind_four_unique_slots_and_resume_once(tmp_path, monkeypatch):
    from experiments import retained_response_judge_pair_execute as paired
    from test_retained_judge_shared_budget import HookHaiku
    from experiments import retained_response_judge_execute as judging
    prepared, plan, _admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    requests = subject.build_matched_judge_requests(**kwargs)
    assert len(plan["pairs"]) == 3 and len(plan["selected"]) == len(requests) == 4
    assert sum(value["call_id"].startswith("judge-local-") for value in requests.values()) == 1
    assert len({value["call_id"] for value in requests.values()}) == 4
    assert subject.build_matched_judge_requests(**kwargs) == requests
    condition = plan["judge_condition"]
    config, _ = judging._load_api_config(prepared["api_config"], judge_model=condition["model"],
                                        expected_sha256=condition["api_config_sha256"])
    fake = HookHaiku(config)
    execute_kwargs = {key: prepared[key] for key in ("plan_path", "source_receipt", "api_config", "pricing_config", "out")}
    execute_kwargs.update(local_runner_view=kwargs["local_runner_view"], hosted_runner_view=kwargs["hosted_runner_view"],
                          shared_budget=kwargs["budget"], shared_requests=requests, judge_factory=lambda *_: fake)
    result = paired.execute(**execute_kwargs)
    assert fake.calls == fake.http_calls == 4
    assert paired.execute(**execute_kwargs) == result and fake.http_calls == 4
    pool = kwargs["budget"].snapshot()["pools"]["anthropic:judge"]
    assert pool["settled_attempts"] == 4
    assert pool["unstarted_first_commitments_microusd"] == 8 * 14848


def test_matched_judging_validates_each_distinct_local_history_once(tmp_path, monkeypatch):
    _prepared, _plan, _admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(subject, "_validated_local_cells",
                        lambda program: calls.append(program.get("runner_view")) or ([], {}))
    subject.build_matched_judge_requests(**kwargs)
    assert calls == [None]
    calls.clear()
    kwargs["programs"][-1]["runner_view"] = "different-retained-input-view"
    subject.build_matched_judge_requests(**kwargs)
    assert calls == [None, "different-retained-input-view"]


@pytest.mark.parametrize("mutation", ["changed_origin", "missing_program", "duplicate_program", "underfunded_request"])
def test_matched_slot_binding_rejects_unfunded_or_changed_actual_input(tmp_path, monkeypatch, mutation):
    prepared, plan, admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    if mutation == "missing_program":
        kwargs["programs"].pop()
    elif mutation == "duplicate_program":
        kwargs["programs"].append(kwargs["programs"][0])
    elif mutation == "changed_origin":
        for admission in admissions[kwargs["programs"][0]["target"]]:
            admission.entries = copy.deepcopy(admission.entries)
            for entry in admission.entries.values():
                entry["origin"]["original_attempt"]["strategy"] = "different funded source"
    else:
        from experiments import retained_response_judge_execute as judging
        actual = judging.build_shared_request_receipts
        def oversized(*args, **named):
            receipts = actual(*args, **named)
            next(iter(receipts.values()))["input_tokens_estimate"] = 1000000
            return receipts
        monkeypatch.setattr(judging, "build_shared_request_receipts", oversized)
    with pytest.raises(ValueError, match="funded"):
        subject.build_matched_judge_requests(**kwargs)


def test_matched_funding_keeps_checkpoint_carried_input_judge_slots(tmp_path, monkeypatch):
    _prepared, plan, admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    program = kwargs['programs'][0]
    original = admissions[program['target']][0]
    program['requests'] = copy.deepcopy(original.requests)
    carried = {key: {'attempt': {'params': {'retained_origin': copy.deepcopy(entry['origin'])}}}
               for key, entry in original.entries.items()}
    # The source reader and monetary/source bindings below are real fixture
    # artifacts. Only selection admission is represented as an already-verified
    # native prefix rather than a job that would regenerate those answers.
    admissions[program['target']] = []
    monkeypatch.setattr(subject, '_reviewed_completed_responses',
                        lambda candidate, budget: carried if candidate is program else {})
    receipts = subject.build_matched_judge_requests(**kwargs)
    assert len(plan['selected']) == len(receipts) == 4
    assert len({row['call_id'] for row in receipts.values()}) == 4


def test_matched_slot_binding_revalidates_actual_source_artifacts_before_mapping(tmp_path, monkeypatch):
    _prepared, _plan, _admissions, kwargs = _matched_funding(tmp_path, monkeypatch)
    (tmp_path / "original" / "source.attempts.jsonl").write_text("changed original artifact\n")
    with pytest.raises(ValueError, match="source artifact bytes differ"):
        subject.build_matched_judge_requests(**kwargs)
