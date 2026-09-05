"""No-network proofs for controller-owned physical HTTP reservations."""

import pytest

from ura.targets import api


class HttpFailure(RuntimeError):
    status_code = 500


def test_each_retry_is_admitted_before_its_sdk_call(monkeypatch):
    monkeypatch.setattr(api.time, "sleep", lambda _: None)
    events = []
    request = {"model": "example", "max_tokens": 512, "messages": []}

    def reserve(provider, observed, attempt):
        assert provider == "example-provider"
        assert observed is request
        events.append(("reserve", attempt))

    def call(**kwargs):
        assert kwargs == request
        number = 1 + sum(kind == "call" for kind, _ in events)
        events.append(("call", number))
        if number < 4:
            raise HttpFailure()
        return "complete"

    with api.provider_attempt_admission(reserve):
        result, audit = api._call_with_retry(
            call, request, provider="example-provider", max_retries=3
        )
    assert result == "complete"
    assert events == [item for n in range(1, 5) for item in (("reserve", n), ("call", n))]
    assert [item["outcome"] for item in audit] == ["error"] * 3 + ["success"]


@pytest.mark.parametrize("denied_attempt", [1, 2, 4])
def test_reservation_denial_is_not_an_http_retry(monkeypatch, denied_attempt):
    monkeypatch.setattr(api.time, "sleep", lambda _: None)
    admitted = []
    calls = []

    # Even a status-bearing reservation exception is not an SDK failure and
    # must not be retried. No attempt is spent after the denial.
    class BudgetDenied(HttpFailure):
        pass

    def reserve(provider, request, attempt):
        admitted.append(attempt)
        if attempt == denied_attempt:
            raise BudgetDenied("no funds reserved")

    def call(**kwargs):
        calls.append(kwargs)
        raise HttpFailure()

    with api.provider_attempt_admission(reserve), pytest.raises(BudgetDenied):
        api._call_with_retry(call, {}, provider="example", max_retries=3)
    assert len(calls) == denied_attempt - 1
    assert admitted == list(range(1, denied_attempt + 1))


def test_nested_admission_restores_scope_after_exception():
    events = []

    def run():
        return api._call_with_retry(lambda: "ok", {}, provider="example", max_retries=0)

    with api.provider_attempt_admission(lambda *args: events.append("outer")):
        run()
        with pytest.raises(RuntimeError, match="scope interrupted"):
            with api.provider_attempt_admission(lambda *args: events.append("inner")):
                run()
                raise RuntimeError("scope interrupted")
        run()
    run()
    assert events == ["outer", "inner", "outer"]


def test_invalid_admission_does_not_open_scope():
    with pytest.raises(TypeError, match="must be callable"):
        with api.provider_attempt_admission(None):
            pytest.fail("invalid scope entered")


def test_unscoped_transport_preserves_error_audit(monkeypatch):
    monkeypatch.setattr(api.time, "sleep", lambda _: None)

    def fail():
        raise HttpFailure()

    with pytest.raises(api.ProviderTransportError) as caught:
        api._call_with_retry(fail, {}, provider="example", max_retries=3)
    assert len(caught.value.transport_attempts) == 4
    assert all(item["status_code"] == 500 for item in caught.value.transport_attempts)
