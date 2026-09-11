"""Paid reply parsing must not erase the evidence needed to diagnose a failure."""
from types import SimpleNamespace

import pytest

from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import DataPoint, DialogTurn
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.runner import Runner, _safe_failed_provider_reply
from ura.targets.api import AnthropicOutputError, AnthropicTarget


def _fixture(*, stop_reason="end_turn", redacted=False):
    types = pytest.importorskip("anthropic.types")
    block = ({"type": "redacted_thinking", "data": "opaque"} if redacted else
             {"type": "thinking", "thinking": "late", "signature": "signature"})
    response = types.Message(id="msg-fixture", type="message", role="assistant",
        model="claude-opus-5", stop_reason=stop_reason, stop_sequence=None,
        content=[{"type": "text", "text": "Partial visible reply"}, block],
        usage=types.Usage(input_tokens=7, output_tokens=3,
                          cache_read_input_tokens=2, cache_creation_input_tokens=4))
    target = AnthropicTarget("claude-opus-5", adaptive_thinking=True, temperature=None)
    calls = []
    def create(**request):
        calls.append(request)
        return response
    target._client = SimpleNamespace(messages=SimpleNamespace(create=create))
    return target, response, calls


@pytest.mark.parametrize("redacted", [False, True])
def test_partial_refusal_is_classified_before_continuation_order(redacted):
    target, _response, calls = _fixture(stop_reason="refusal", redacted=redacted)
    result = target.generate([DialogTurn(role="user", content="fixture")])
    assert len(calls) == 1
    assert result.raw["provider_refusal"] is True and result.output_turns == []
    assert result.tokens == {"input": 13, "output": 3, "total": 16,
                             "cached_input": 2, "cache_write_input": 4}
    assert result.raw["discarded_partial_thinking_blocks"] == 1
    assert result.raw["discarded_partial_text_blocks"] == 1


def test_unhandled_order_retains_reply_and_actual_http_count():
    target, response, calls = _fixture()
    with pytest.raises(AnthropicOutputError, match="thinking after visible text") as caught:
        target.generate([DialogTurn(role="user", content="fixture")])
    assert len(calls) == 1
    exc = caught.value
    assert exc.retained_provider_response["content"] == response.model_dump(mode="json")["content"]
    assert exc.retained_provider_response["stop_reason"] == "end_turn"
    assert "messages" not in exc.retained_provider_response
    assert exc.call_audit["transport_attempt_count"] == 1
    assert exc.call_audit["reported_input_tokens"] == 13
    assert exc.call_audit["reported_total_tokens"] == 16


def test_runner_retains_failed_sdk_reply_without_promoting_it(tmp_path):
    target, _response, calls = _fixture()
    runner = Runner(ReplayAttacker(), target, JudgeCascade([RuleJudge()]),
                    AttackBudget(max_queries=1, max_turns=1), [0],
                    target_answer_retries=0, execution_stage="responses")
    point = DataPoint(id="fixture", source="fixture", modalities=["text"],
                      payload_text="Explain the color blue.", risk_category="jailbreak",
                      expected_behavior="safe_answer")
    checkpoint = tmp_path / "responses.jsonl"
    runner.run([point], on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    rows = list(Runner.load_response_checkpoint(checkpoint).values())
    assert len(calls) == len(rows) == 1
    result = rows[0]["response"]
    assert result["output_turns"] == []
    assert result["raw"]["model_stability_status"] == "failed_output"
    assert result["tokens"] == {"input": 13, "output": 3, "total": 16}
    assert result["raw"]["transport_attempt_count"] == 1
    native = result["raw"]["model_stability_failures"][0]["provider_response"]
    assert native["id"] == "msg-fixture" and native["stop_reason"] == "end_turn"
    assert [block["type"] for block in native["content"]] == ["text", "thinking"]


@pytest.mark.parametrize("value,status", [
    ({"content": object()}, "non_json_provider_reply"),
    ({"text": "x" * (2 * 1024 * 1024)}, "provider_reply_exceeds_2_mib"),
])
def test_diagnostic_payload_is_bounded_without_hiding_retention_failure(value, status):
    assert _safe_failed_provider_reply(value)["retention_status"] == status
