"""Google uses the same rendered request for counting, funding and generation."""
import copy
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_campaign_budget as projection, hosted_request_tokens as tokens
from experiments.hosted_retained_execute import _validate_input_budget, COUNTED_INPUT_SCHEMA, COUNTED_INPUT_POLICY
from ura.targets.api import GeminiTarget, provider_attempt_admission


FIXTURES = runpy.run_path(str(Path(__file__).parents[1] / "ura/test_provider_request_preview.py"))
BUDGET = runpy.run_path(str(Path(__file__).with_name("test_hosted_campaign_budget.py")))


def test_gemini_preview_is_the_exact_admitted_generation_request(tmp_path, monkeypatch):
    target = GeminiTarget("gemini-3.8-flash", media_roots=[tmp_path], max_tokens=4096,
                          temperature=None, supports_seed=True)
    dialog = FIXTURES["_dialog"](tmp_path)
    body = target.build_request(dialog, seed=0)
    assert target._client is None
    serialized = json.dumps(body)
    assert body["config"] == {"max_output_tokens": 4096, "system_instruction": "Preserve every instruction.", "seed": 0}
    for text in ["Earlier question.", "Earlier answer.", "Now inspect this image.", "iVBORw0KGgo"]:
        assert text in serialized
    from google.genai import types
    blob = types.Blob(**body["contents"][-1]["parts"][-1]["inline_data"])
    assert blob.data == (tmp_path / "pixel.png").read_bytes()
    seen = []

    class Observed(BaseException):
        pass

    def generate(**request):
        seen.append(request)
        raise Observed()

    admitted = []
    monkeypatch.setattr(target, "_get_client", lambda: SimpleNamespace(models=SimpleNamespace(generate_content=generate)))
    with provider_attempt_admission(lambda provider, request, number: admitted.append((provider, request, number))):
        with pytest.raises(Observed):
            target.generate(dialog, seed=0)
    assert seen == [body]
    assert admitted == [("google", body, 1)]


def test_gemini_count_preserves_system_history_image_and_configuration(tmp_path, monkeypatch):
    target = GeminiTarget("gemini-3.1-pro-preview", media_roots=[tmp_path], max_tokens=4096)
    body = target.build_request(FIXTURES["_dialog"](tmp_path))
    delivered = []

    def request(method, path, payload, options):
        delivered.append(copy.deepcopy(payload))
        assert method == "post" and path == "models/gemini-3.1-pro-preview:countTokens"
        assert options.timeout == 30000 and options.retry_options.attempts == 1
        return SimpleNamespace(body='{"totalTokens":731}')

    monkeypatch.setattr(target, "_get_client", lambda: SimpleNamespace(_api_client=SimpleNamespace(request=request)))
    receipt = tokens.count_request(target, body, allow_network=True)
    generated = delivered[0]["generateContentRequest"]
    assert generated["systemInstruction"] == {"parts": [{"text": "Preserve every instruction."}]}
    assert generated["generationConfig"] == {"maxOutputTokens": 4096, "temperature": 0.0}
    assert generated["contents"][-1]["parts"][-1]["inlineData"]["mimeType"] == "image/png"
    assert receipt["input_tokens"] == 731 and receipt["method"] == "provider_exact"
    assert tokens.validate_receipt(target, body, receipt) == receipt
    assert len(delivered) == 1
    with pytest.raises(tokens.TokenCountUnavailable, match="physical media"):
        tokens.count_request(target, body)
    body["config"]["unrecognized_instruction"] = "must not be dropped"
    with pytest.raises(tokens.TokenCountUnavailable, match="configuration"):
        tokens.count_request(target, body, allow_network=True)


def google_projection():
    api = {"google:gemini-3.8-flash": {"modalities": ["text", "image"], "max_tokens": 4096}}
    prices = BUDGET["_pricing"]()
    prices["providers"]["google"] = {"models": {"gemini-3.8-flash": {"rates": [{
        "currency": "USD", "effective_date": "2026-09-03", "per_million_tokens": {"input": .75, "output": 3.75}}]}}}
    budgets = {"providers": [{"match": "google", "prepaid": "$24.47"}, {"match": "anthropic", "prepaid": "$20"}]}
    route = {"label": "Flash", "spec": "google:gemini-3.8-flash", "provider": "google",
             "model": "gemini-3.8-flash", "call_cap": 100, "max_output_tokens": 4096}
    return dict(api_config=api, pricing=prices, budgets=budgets, descriptors={}, pricing_as_of="2026-09-03",
                route_configuration=[route])


def test_configured_projection_funds_google_and_haiku_without_fake_haiku_target():
    kwargs = google_projection()
    value = projection.build_projection(**kwargs)
    assert value["schema"] == projection.CONFIGURED_SCHEMA
    assert value["route_configuration"] == kwargs["route_configuration"]
    assert value["totals"]["target_paid_call_cap"] == 100
    assert value["judge"]["paid_call_cap"] == 200
    assert {p["provider"] for p in value["providers"]} == {"google", "anthropic"}
    assert next(p for p in value["providers"] if p["provider"] == "anthropic")["target_maximum_cost_microusd"] == 0
    assert value["status"] == "budget_fit"


@pytest.mark.parametrize("change", [{"call_cap": True}, {"spec": "google:wrong-model"}, {"unknown": 1}, {"max_output_tokens": 0}])
def test_configured_route_rejects_invalid_identity_and_limits(change):
    kwargs = google_projection()
    kwargs["route_configuration"][0].update(change)
    with pytest.raises(ValueError):
        projection.build_projection(**kwargs)


def test_counted_request_cannot_cross_its_pricing_tier():
    program = {"schema": COUNTED_INPUT_SCHEMA, "input_budget_policy": COUNTED_INPUT_POLICY,
               "requests": {"one": {"input_tokens": 200001, "bound_microusd": 1}}}
    route = {"maximum_priced_input_tokens": 200000, "maximum_cost_microusd": 100}
    with pytest.raises(ValueError, match="pricing tier"):
        _validate_input_budget(program, route)
