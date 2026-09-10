"""Hosted concurrency must respect provider backoff and serialize GPU scoring."""
from concurrent.futures import ThreadPoolExecutor
from email.utils import formatdate
from threading import Event
from types import SimpleNamespace
import os

import pytest

from ura import hosted_scheduling as scheduling
from ura.targets import api


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
