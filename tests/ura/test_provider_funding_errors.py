"""Funding failures stop without consuming the transient HTTP retry allowance."""

import json

import pytest

from ura.targets import api


class HTTPFailure(Exception):
    def __init__(self, status, error):
        self.status_code = status
        self.body = {"error": error}


@pytest.mark.parametrize("provider,status,error,reason", [
    ("openai", 429, {"code": "credit_balance_exhausted", "type": "insufficient_quota"}, "credit_balance_exhausted"),
    ("openai-responses", 429, {"code": "project_spend_limit_exceeded"}, "spend_limit_reached"),
    ("openai", 429, {"code": "organization_spend_limit_exceeded"}, "spend_limit_reached"),
    ("openai", 429, {"code": "organization_usage_limit_exceeded"}, "usage_limit_reached"),
    ("openai", 429, {"type": "insufficient_quota"}, "funding_or_quota_unavailable"),
    ("deepseek", 402, {}, "credit_balance_exhausted"),
    ("kimi", 429, {"type": "exceeded_current_quota_error"}, "funding_or_account_unavailable"),
    ("anthropic", 400, {"type": "invalid_request_error", "message": "Your credit balance is too low to access the API."}, "credit_balance_exhausted"),
    ("google", 429, {"message": "Your prepayment credits are depleted."}, "credit_balance_exhausted"),
])
def test_funding_failure_is_one_attempt_with_machine_reason(monkeypatch, provider, status, error, reason):
    attempts = []
    sleeps = []
    monkeypatch.setattr(api.time, "sleep", sleeps.append)

    def fail(**request):
        attempts.append(request)
        raise HTTPFailure(status, {**error, "request_echo": "private prompt sk-test-secret"})

    with pytest.raises(api.ProviderTransportError) as caught:
        api._call_with_retry(fail, {"model": "test"}, provider=provider, max_retries=3)
    assert len(attempts) == 1
    assert sleeps == []
    assert caught.value.call_audit["provider_funding_status"] == reason
    assert caught.value.call_audit["transport_retryable"] is False
    assert "private prompt" not in json.dumps(caught.value.call_audit)
    assert "sk-test-secret" not in json.dumps(caught.value.transport_attempts)


@pytest.mark.parametrize("provider,status,error", [
    ("openai", 429, {"code": "slow_down", "type": "rate_limit_error"}),
    ("openai", 429, {"code": "rate_limit_exceeded"}),
    ("kimi", 429, {"type": "rate_limit_reached_error"}),
    ("kimi", 429, {"type": "engine_overloaded_error"}),
    ("google", 429, {"status": "RESOURCE_EXHAUSTED", "message": "Spend rate limit exceeded; retry in 30s"}),
    ("deepseek", 503, {}),
])
def test_transient_limits_still_retry(monkeypatch, provider, status, error):
    attempts = []
    monkeypatch.setattr(api.time, "sleep", lambda delay: None)

    def call(**request):
        attempts.append(request)
        if len(attempts) == 1:
            raise HTTPFailure(status, error)
        return "answer"

    answer, audit = api._call_with_retry(call, {}, provider=provider, max_retries=3)
    assert answer == "answer" and len(attempts) == 2
    assert "provider_funding_status" not in audit[0]


def test_policy_and_parameter_errors_are_not_budget_exhaustion():
    for body in [{"code": "cyber_policy"}, {"type": "invalid_request_error", "message": "Invalid model parameter"}]:
        assert api._provider_funding_status(HTTPFailure(400, body), "openai") is None
    assert api._provider_funding_status(HTTPFailure(400, {
        "type": "invalid_request_error", "message": "Invalid input contains: your credit balance is too low"
    }), "anthropic") is None


def test_real_google_sdk_status_and_error_body():
    errors = pytest.importorskip("google.genai.errors")
    transient = errors.ClientError(429, {"error": {
        "code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Please retry after 30 seconds."
    }})
    exhausted = errors.ClientError(429, {"error": {
        "code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Your prepayment credits are depleted."
    }})
    assert api._transport_status_code(transient) == 429
    assert api._retryable_transport_error(transient, provider="google") is True
    assert api._provider_funding_status(exhausted, "google") == "credit_balance_exhausted"
    assert api._retryable_transport_error(exhausted, provider="google") is False
