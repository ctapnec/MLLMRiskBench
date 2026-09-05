"""Full real-adapter request previews; count services are mocked, never generation."""
import copy
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.hosted_request_tokens import (
    TokenCountUnavailable, count_request, request_sha256, validate_receipt,
)
from ura.data_models import DialogTurn
from ura.targets.api import OpenAICompatibleTarget


_PREVIEWS = runpy.run_path(str(Path(__file__).parents[1] / "ura" / "test_provider_request_preview.py"))
KINDS, _dialog, _target = (_PREVIEWS[key] for key in ("KINDS", "_dialog", "_target"))


def _client(target, monkeypatch, result=None, error=None):
    observed = []

    def count(**payload):
        observed.append(copy.deepcopy(payload))
        if error:
            raise error
        return result if result is not None else SimpleNamespace(object="response.input_tokens", input_tokens=731)

    def post(path, *, cast_to, body):
        assert path == "/tokenizers/estimate-token-count" and cast_to is dict
        observed.append(copy.deepcopy(body))
        return result if result is not None else {"data": {"total_tokens": 731}}

    options = []
    client = SimpleNamespace(messages=SimpleNamespace(count_tokens=count),
                             responses=SimpleNamespace(input_tokens=SimpleNamespace(count=count)), post=post)
    client.with_options = lambda **kwargs: (options.append(kwargs), client)[1]
    monkeypatch.setattr(target, "_get_client", lambda: client)
    return observed, options


@pytest.mark.parametrize("kind", KINDS)
def test_full_request_count_preserves_history_images_and_selected_model(kind, tmp_path, monkeypatch):
    target = _target(kind, tmp_path)
    request = target.build_request(_dialog(tmp_path), seed=0)
    original = copy.deepcopy(request)
    observed, options = _client(target, monkeypatch)
    receipt = count_request(target, request, allow_network=True)
    assert request == original and len(observed) == 1
    assert receipt["request_sha256"] == request_sha256(original)
    assert receipt["count_request_sha256"] == request_sha256(observed[0])
    assert receipt["requested_model"] == target.model and receipt["requested_spec"] == target.requested_spec
    assert receipt["input_tokens"] == 731
    assert receipt["method"] == ("provider_exact" if kind == "sol" else "provider_estimate")
    assert options == [{"max_retries": 0, "timeout": 30.0}]
    assert "max_tokens" not in observed[0] and "max_output_tokens" not in observed[0]
    encoded = str(observed[0])
    for text in ("Preserve every instruction.", "Earlier question.", "Earlier answer.",
                 "Now inspect this image.", "iVBORw0KGgo"):
        assert text in encoded
    if kind == "fable":
        assert observed[0]["thinking"] == request["thinking"]
        assert observed[0]["output_config"] == request["output_config"]
    if kind == "sol":
        assert observed[0]["reasoning"] == request["reasoning"]
    if kind == "astra":
        assert receipt["method_id"] == "openai_responses_projection_of_chat_v1"
        assert "input_image" in encoded and "image_url" in encoded
    before = copy.deepcopy(observed)
    assert validate_receipt(target, request, receipt) == receipt
    assert observed == before  # Resume cannot recount or generate.


@pytest.mark.parametrize("kind", KINDS)
def test_offline_text_estimate_never_constructs_client_and_media_requires_counter(kind, tmp_path, monkeypatch):
    target = _target(kind, tmp_path)

    def forbidden():
        pytest.fail("offline estimate constructed a client")

    monkeypatch.setattr(target, "_get_client", forbidden)
    request = target.build_request([DialogTurn(role="user", content="A complete question.")])
    receipt = count_request(target, request)
    assert receipt["method"] == "local_estimate" and receipt["count_http_attempts"] == 0
    assert receipt["count_fee_status"] == "no_network"
    assert validate_receipt(target, request, receipt) == receipt
    with pytest.raises(TokenCountUnavailable, match="physical media"):
        count_request(target, target.build_request(_dialog(tmp_path)))


@pytest.mark.parametrize("bad", [None, True, -1, 1.5, "731"])
def test_bad_counter_result_refuses_without_generation_or_fallback(bad, tmp_path, monkeypatch):
    target = _target("haiku", tmp_path)
    observed, _ = _client(target, monkeypatch, result={"input_tokens": bad})
    with pytest.raises(ValueError, match="nonnegative integer"):
        count_request(target, target.build_request(_dialog(tmp_path)), allow_network=True)
    assert len(observed) == 1


def test_counter_failure_is_not_retried_or_replaced_with_byte_count(tmp_path, monkeypatch):
    target = _target("sol", tmp_path)
    observed, _ = _client(target, monkeypatch, error=TimeoutError("counter unavailable"))
    with pytest.raises(TimeoutError):
        count_request(target, target.build_request(_dialog(tmp_path)), allow_network=True)
    assert len(observed) == 1


def test_network_opt_in_is_not_a_truthy_configuration_string(tmp_path, monkeypatch):
    target = _target("haiku", tmp_path)
    observed, _ = _client(target, monkeypatch)
    with pytest.raises(ValueError, match="explicit boolean"):
        count_request(target, target.build_request(_dialog(tmp_path)), allow_network="false")
    assert observed == []


def test_receipt_rejects_changed_model_body_and_false_exactness(tmp_path, monkeypatch):
    target = _target("astra", tmp_path)
    request = target.build_request(_dialog(tmp_path))
    _client(target, monkeypatch)
    receipt = count_request(target, request, allow_network=True)
    for modified in (dict(receipt, method="provider_exact"), dict(receipt, requested_model="other"),
                     dict(receipt, request_sha256="0" * 64), dict(receipt, input_tokens=True)):
        with pytest.raises(ValueError):
            validate_receipt(target, request, modified)
    with pytest.raises(ValueError):
        validate_receipt(target, dict(request, max_completion_tokens=17), receipt)
    with pytest.raises(ValueError):
        count_request(target, dict(request, model="other"))


def test_unknown_input_field_and_chat_content_are_not_silently_dropped(tmp_path, monkeypatch):
    target = _target("astra", tmp_path)
    request = target.build_request(_dialog(tmp_path))
    observed, _ = _client(target, monkeypatch)
    with pytest.raises(TokenCountUnavailable):
        count_request(target, dict(request, new_input_field="must not vanish"), allow_network=True)
    request["messages"][-1]["content"].append({"type": "unknown", "data": "must not vanish"})
    with pytest.raises(TokenCountUnavailable):
        count_request(target, request, allow_network=True)
    assert not observed


def test_deepseek_offline_estimate_does_not_use_an_openai_counter(tmp_path, monkeypatch):
    target = OpenAICompatibleTarget("deepseek-v4-pro", "https://api.deepseek.com", "DEEPSEEK_API_KEY",
                                    provider="deepseek", modality_support=("text",))
    monkeypatch.setattr(target, "_get_client", lambda: pytest.fail("wrong provider counter"))
    request = target.build_request([DialogTurn(role="user", content="A complete question.")])
    receipt = count_request(target, request, allow_network=True)
    assert receipt["method"] == "local_estimate" and receipt["count_http_attempts"] == 0
    assert validate_receipt(target, request, receipt) == receipt


@pytest.mark.parametrize("kind", KINDS)
def test_installed_sdk_serializes_only_count_endpoint(kind, tmp_path, monkeypatch):
    httpx = pytest.importorskip("httpx")
    openai = pytest.importorskip("openai")
    anthropic = pytest.importorskip("anthropic")
    target = _target(kind, tmp_path)
    expected_path = ("/v1/messages/count_tokens" if kind in {"haiku", "fable"} else
                     "/v1/tokenizers/estimate-token-count" if kind == "kimi" else
                     "/v1/responses/input_tokens")
    delivered = []

    def handle(request):
        assert request.method == "POST" and request.url.path == expected_path
        delivered.append(json.loads(request.content))
        result = ({"data": {"total_tokens": 731}} if kind == "kimi" else
                  {"input_tokens": 731, "object": "response.input_tokens"})
        return httpx.Response(200, json=result, request=request)

    transport = httpx.Client(transport=httpx.MockTransport(handle))
    if kind in {"haiku", "fable"}:
        client = anthropic.Anthropic(api_key="not-a-real-key", base_url="https://api.anthropic.com",
                                     max_retries=0, http_client=transport)
    else:
        base = "https://api.moonshot.ai/v1" if kind == "kimi" else "https://api.openai.com/v1"
        client = openai.OpenAI(api_key="not-a-real-key", base_url=base, max_retries=0, http_client=transport)
    monkeypatch.setattr(target, "_get_client", lambda: client)
    try:
        receipt = count_request(target, target.build_request(_dialog(tmp_path)), allow_network=True)
    finally:
        client.close()
    assert receipt["input_tokens"] == 731 and len(delivered) == 1
    assert receipt["count_request_sha256"] == request_sha256(delivered[0])
