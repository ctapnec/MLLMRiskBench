"""Cross-controller retries retain the original paid attempt and its charge."""
from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace

import pytest

from experiments import hosted_retained_execute as subject
from experiments.hosted_attempt_budget import BudgetError
from test_hosted_retained_execute import _runner, _setup
from ura.runner import Runner
from ura.targets import api


def _failed_prefix(tmp_path, monkeypatch, *, tight=False):
    points, attacker, target, calls, original = _setup(
        tmp_path, outputs=[ConnectionError("interrupted"), "A retained retry answer", "Second answer"],
        tight=tight,
    )
    checkpoint = tmp_path / "original.responses.checkpoint.jsonl"
    # Reproduce the old installed behavior: one network exception was terminal.
    with monkeypatch.context() as patch:
        patch.setattr(api, "_retryable_transport_error", lambda exc, **kwargs: False)
        with pytest.raises(RuntimeError, match="durable response"):
            _runner(attacker, target, original).run(
                points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row),
            )
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(records) == len(calls) == 1
    attempt_id, record = next(iter(records.items()))
    key = record["attempt"]["params"]["retained_origin"]["selection"]["input_identity_sha256"]
    subject.target_pause_path(original.budget, target.name).rename(tmp_path / "reviewed-stop.json")
    raw = checkpoint.read_bytes()
    recovery = {
        "checkpoint": {"path": str(checkpoint), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)},
        "attempt_id": attempt_id, "prior_attempts": 1,
        "request_sha256": original.requests[key]["request_sha256"],
    }
    program = {**original.program, "schema": subject.TRANSPORT_RECOVERY_SCHEMA,
               "requests": original.requests, "transport_recoveries": {key: recovery}}
    return points, attacker, target, calls, original, program, key, raw


def _admission(original, attacker, program):
    return subject._Admission(
        program=program, job=original.job, budget=original.budget, attacker=attacker,
        requests=original.requests, prices=original.prices,
    )


def test_transport_resume_continues_ordinal_preserves_charge_and_does_not_repeat_answer(tmp_path, monkeypatch):
    points, attacker, target, calls, original, program, key, prior_bytes = _failed_prefix(tmp_path, monkeypatch)
    admission = _admission(original, attacker, program)
    checkpoint = tmp_path / "recovered.responses.checkpoint.jsonl"
    recovered = _runner(attacker, target, admission)
    recovered.run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    assert len(calls) == 3 and calls[0] == calls[1]
    first = recovered.responses[0]
    assert first.raw["transport_attempt_count"] == 1
    assert first.raw["transport_attempts"][0]["attempt"] == 2
    assert first.raw.get("model_stability_retry_count", 0) == 0
    assert original.budget.reserved_attempt_count(original.requests[key]["call_id"]) == 2
    pool = original.budget.snapshot()["pools"]["openai:target"]
    assert pool["unknown_usage_attempts"] == 1 and pool["reserved_exposure_microusd"] == 10000
    assert pool["settled_attempts"] == 2
    assert (tmp_path / "original.responses.checkpoint.jsonl").read_bytes() == prior_bytes
    _runner(attacker, target, _admission(original, attacker, program)).run(
        points, response_records=Runner.load_response_checkpoint(checkpoint),
    )
    assert len(calls) == 3


@pytest.mark.parametrize("mutation", ["request", "digest", "exhausted", "legacy", "unfunded"])
def test_transport_resume_rejects_changed_scope_before_any_new_call(tmp_path, monkeypatch, mutation):
    _points, attacker, _target, calls, original, program, key, _raw = _failed_prefix(tmp_path, monkeypatch)
    recovery = program["transport_recoveries"][key]
    if mutation == "request":
        recovery["request_sha256"] = "0" * 64
    elif mutation == "digest":
        recovery["checkpoint"]["sha256"] = "0" * 64
    elif mutation == "exhausted":
        recovery["prior_attempts"] = 4
    elif mutation == "legacy":
        program["schema"] = subject.COUNTED_INPUT_SCHEMA
    else:
        program["transport_recoveries"]["not-selected"] = recovery
    with pytest.raises(ValueError, match="transport recovery"):
        _admission(original, attacker, program)
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["answer", "tokens", "empty_answer", "http400", "unknown_exception", "provider"])
def test_transport_resume_is_not_an_answer_or_parser_retry(tmp_path, monkeypatch, mutation):
    _points, attacker, _target, calls, original, program, key, _raw = _failed_prefix(tmp_path, monkeypatch)
    recovery = program["transport_recoveries"][key]
    path = tmp_path / "different.responses.checkpoint.jsonl"
    record = copy.deepcopy(next(iter(Runner.load_response_checkpoint(
        tmp_path / "original.responses.checkpoint.jsonl",
    ).values())))
    response = record["response"]
    if mutation == "answer":
        response["output_turns"] = [{"role": "assistant", "content": "Already paid answer"}]
    elif mutation == "tokens":
        response["tokens"] = {"input": 7, "output": 0}
    elif mutation == "empty_answer":
        response["raw"]["model_stability_category"] = "empty_final_output"
        response["raw"].pop("transport_retry_status", None)
    elif mutation == "http400":
        response["raw"]["call_audit"]["status_code"] = 400
    elif mutation == "unknown_exception":
        response["raw"]["call_audit"]["error_type"] = "ValueError"
    else:
        response["raw"]["call_audit"]["provider"] = "anthropic"
    path.write_text(json.dumps(record) + "\n")
    raw = path.read_bytes()
    recovery["checkpoint"] = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    with pytest.raises(ValueError):
        _admission(original, attacker, program)
    assert len(calls) == 1


def test_transport_resume_cannot_spend_another_inputs_first_attempt(tmp_path, monkeypatch):
    points, attacker, target, calls, original, program, _key, _raw = _failed_prefix(tmp_path, monkeypatch, tight=True)
    admission = _admission(original, attacker, program)
    with pytest.raises((BudgetError, RuntimeError), match="retry cannot consume"):
        _runner(attacker, target, admission).run(points, on_response=lambda row: None)
    assert len(calls) == 1
    assert original.budget.snapshot()["pools"]["openai:target"]["unstarted_first_commitments_microusd"] == 10000


@pytest.mark.parametrize("provider", ["openai", "openai-responses", "anthropic", "anthropic-fable", "kimi", "deepseek", "google"])
def test_every_provider_shares_the_remaining_physical_attempt_limit(monkeypatch, provider):
    monkeypatch.setattr(api.time, "sleep", lambda seconds: None)
    calls, reservations = [], []

    def failing(**request):
        calls.append(request)
        raise ConnectionError("network interrupted")

    with api.provider_attempt_admission(lambda p, r, n: reservations.append((p, n)), attempts_used=1):
        with pytest.raises(api.ProviderTransportError) as caught:
            api._call_with_retry(failing, {"model": "fixture"}, provider=provider, max_retries=3)
    assert len(calls) == 3
    assert reservations == [(provider, n) for n in (2, 3, 4)]
    assert [row["attempt"] for row in caught.value.transport_attempts] == [2, 3, 4]
    assert caught.value.call_audit["transport_attempt_count"] == 3
    # Context reset: an unrelated input still has its original first attempt.
    _result, audit = api._call_with_retry(lambda **r: SimpleNamespace(), {}, provider=provider, max_retries=0)
    assert audit[0]["attempt"] == 1


def test_exhausted_transport_prefix_never_invokes_the_sdk():
    with api.provider_attempt_admission(lambda p, r, n: pytest.fail("reservation"), attempts_used=4):
        with pytest.raises(ValueError, match="exhausted"):
            api._call_with_retry(lambda **r: pytest.fail("SDK"), {}, provider="openai", max_retries=3)
