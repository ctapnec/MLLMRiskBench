"""Hosted concurrency must respect provider backoff and serialize GPU scoring."""
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
from threading import Event
from types import SimpleNamespace
import os

import pytest

from ura import hosted_scheduling as scheduling
from ura.targets import api


def test_responses_only_defers_before_any_judge_slot_and_restores_scope(monkeypatch):
    from ura import runner

    acquired = []
    monkeypatch.setattr(runner, "current_retained_execution_admission", lambda: object())
    slot = SimpleNamespace(acquire=lambda: acquired.append(True))
    token = scheduling._SCORING_SLOT.set(slot)
    try:
        with scheduling.hosted_responses_only():
            with pytest.raises(scheduling.HostedJudgingDeferred):
                scheduling.acquire_hosted_local_scoring_slot()
            assert acquired == []
        scheduling.acquire_hosted_local_scoring_slot()
        assert acquired == [True]
    finally:
        scheduling._SCORING_SLOT.reset(token)


def test_responses_only_cannot_silently_defer_an_unrelated_local_job():
    with scheduling.hosted_responses_only():
        with pytest.raises(RuntimeError, match="retained execution admission"):
            scheduling.acquire_hosted_local_scoring_slot()


@pytest.mark.parametrize("header", ["13", "0.75", "Thu, 10 Sep 2026 12:00:13 GMT"])
def test_retry_after_is_respected_before_next_paid_attempt(monkeypatch, header):
    monkeypatch.setattr(api.time, "time", lambda: 1789041600)
    sleeps, events = [], []
    error = RuntimeError("rate limited")
    error.status_code = 429
    error.response = SimpleNamespace(headers={"retry-after": header})

    def call():
        events.append("call")
        if events.count("call") == 1:
            raise error
        return "ok"

    def sleep(seconds):
        sleeps.append(seconds)
        events.append("sleep")

    monkeypatch.setattr(api.time, "sleep", sleep)
    with api.provider_attempt_admission(lambda *_: events.append("reserve")):
        result, _ = api._call_with_retry(call, {}, provider="openai", max_retries=3)
    assert result == "ok"
    assert sleeps == [0.75 if header == "0.75" else 13.0]
    assert events == ["reserve", "call", "sleep", "reserve", "call"]


@pytest.mark.parametrize("header", [None, "bad", "NaN", "-3", "Infinity"])
def test_malformed_retry_after_uses_jittered_backoff(monkeypatch, header):
    monkeypatch.setattr(api.random, "uniform", lambda *_: 0.25)
    error = RuntimeError()
    error.headers = {"Retry-After": header}
    assert api._transport_retry_delay(error, 3) == 2.25


def test_past_http_date_uses_backoff(monkeypatch):
    monkeypatch.setattr(api.time, "time", lambda: 1789041600)
    monkeypatch.setattr(api.random, "uniform", lambda *_: 0.25)
    error = RuntimeError()
    error.headers = {"Retry-After": formatdate(1789041500, usegmt=True)}
    assert api._transport_retry_delay(error, 1) == 0.75


@pytest.mark.parametrize("header", [None, "15", "900"])
def test_google_retry_info_waits_before_next_funded_attempt(monkeypatch, header):
    errors = pytest.importorskip("google.genai.errors")
    error = errors.ClientError(429, {"error": {
        "code": 429, "status": "RESOURCE_EXHAUSTED", "message": "daily request quota",
        "details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": "781s"}],
    }})
    error.response = SimpleNamespace(headers={} if header is None else {"retry-after": header})
    events = []

    def call(**request):
        assert request == {"model": "same-model", "contents": "same-input"}
        events.append("call")
        if events.count("call") == 1:
            raise error
        return "answer"

    monkeypatch.setattr(api.time, "sleep", lambda seconds: events.append(seconds))
    with api.provider_attempt_admission(lambda *_: events.append("reserve")):
        result, audit = api._call_with_retry(call, {"model": "same-model", "contents": "same-input"},
                                           provider="google", max_retries=3)
    assert result == "answer" and len(audit) == 2
    assert events == ["reserve", "call", 900.0 if header == "900" else 781.0, "reserve", "call"]


@pytest.mark.parametrize("duration,expected", [("1.125s", 1.125), ("0s", 0.5),
                                               ("-3s", 0.75), ("NaNs", 0.75), ("2e3s", 0.75),
                                               (None, 0.75)])
def test_google_retry_info_duration_validation(monkeypatch, duration, expected):
    errors = pytest.importorskip("google.genai.errors")
    error = errors.ClientError(429, {"error": {
        "details": [{"@type": "type.googleapis.com/google.rpc.RetryInfo", "retryDelay": duration}],
    }})
    monkeypatch.setattr(api.random, "uniform", lambda *_: 0.25)
    assert api._transport_retry_delay(error, 1) == expected


@pytest.mark.skipif(os.name != "posix", reason="rig GPU scheduler uses POSIX flock")
def test_scoring_slot_is_lazy_exclusive_and_released_after_exception(tmp_path):
    path = tmp_path / "gpu-0.lock"
    first, entered, release, second = Event(), Event(), Event(), Event()

    def owner():
        with pytest.raises(RuntimeError, match="test cleanup"):
            with scheduling.hosted_local_scoring_slot(path):
                assert not path.exists()
                scheduling.acquire_hosted_local_scoring_slot()
                first.set()
                assert release.wait(5)
                raise RuntimeError("test cleanup")

    def contender():
        assert first.wait(5)
        with scheduling.hosted_local_scoring_slot(path):
            entered.set()
            scheduling.acquire_hosted_local_scoring_slot()
            second.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(owner), pool.submit(contender)
        assert entered.wait(5)
        try:
            assert not second.wait(0.15)
        finally:
            release.set()
        a.result(timeout=5)
        b.result(timeout=5)
    assert second.is_set()
    assert scheduling._SCORING_SLOT.get() is None


def test_unconfigured_local_execution_does_not_acquire_gpu_slot():
    assert scheduling._SCORING_SLOT.get() is None
    scheduling.acquire_hosted_local_scoring_slot()
