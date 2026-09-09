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


@pytest.mark.parametrize("nested", [False, True])
def test_sdk_policy_error_keeps_machine_cause_without_retry_or_payload(nested):
    import httpx
    import openai
    from ura.runner import _safe_call_audit

    body = {"code": "cyber_policy", "type": "invalid_request_error",
            "message": "private request text", "param": "private field"}
    if nested:
        body = {"error": body}
    error = openai.BadRequestError(
        "private request text",
        response=httpx.Response(400, request=httpx.Request("POST", "https://example.test")),
        body=body,
    )
    calls = []

    def fail():
        calls.append(1)
        raise error

    with pytest.raises(api.ProviderTransportError) as caught:
        api._call_with_retry(fail, {}, provider="openai", max_retries=3)
    assert len(calls) == 1
    audit = _safe_call_audit(caught.value.call_audit)
    assert audit["provider_error_code"] == "cyber_policy"
    assert audit["provider_error_type"] == "invalid_request_error"
    assert audit["transport_retryable"] is False
    assert audit["status_code"] == 400
    assert "private" not in repr(audit) + repr(caught.value.transport_attempts)


@pytest.mark.parametrize("value", ["sk-secret", "Bearer-secret", "request text", "x" * 101, {"message": "private"}])
def test_provider_error_metadata_omits_non_machine_fields(value):
    error = RuntimeError("private")
    error.body = {"code": value, "type": value, "message": "private"}
    assert api._transport_error_metadata(error) == {}
