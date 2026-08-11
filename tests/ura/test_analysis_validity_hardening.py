from __future__ import annotations

import pytest
from pydantic import ValidationError

from ura.data_models import DialogTurn, EvalResult, ProviderContinuationState
from ura.metrics import judge_scores


def test_provider_continuation_state_round_trips_exact_openai_items() -> None:
    items = [
        {"type": "reasoning", "id": "rs_1", "encrypted_content": "opaque"},
        {
            "type": "message", "id": "msg_1", "role": "assistant",
            "content": [{"type": "output_text", "text": "answer"}],
        },
    ]
    turn = DialogTurn(
        role="assistant", content="answer",
        provider_state=ProviderContinuationState(
            provider="openai", api_surface="responses", items=items,
        ),
    )
    restored = DialogTurn.model_validate(turn.model_dump(mode="json"), strict=True)
    assert restored.provider_state is not None
    assert restored.provider_state.items == items


@pytest.mark.parametrize("item", [
    {"type": "function_call", "name": "tool"},
    {"type": "message", "role": "user", "content": []},
    {"type": "reasoning", "api_key": "secret"},
])
def test_provider_continuation_state_rejects_unsupported_or_secret_items(item: dict) -> None:
    with pytest.raises(ValidationError):
        ProviderContinuationState(
            provider="openai", api_surface="responses", items=[item],
        )


def test_mmsafety_official_metric_requires_real_official_evaluator() -> None:
    with pytest.raises(ValidationError, match="official evaluator"):
        EvalResult(
            id="m", metric="mmsafety_official_attack_rate", value=0.5, n=2,
            provenance={"source_evaluation": {"official_evaluator_executed": False}},
        )


def test_judge_scores_reports_binary_specificity() -> None:
    scores = judge_scores(
        ["violation", "safe", "violation", "safe"],
        ["violation", "safe", "safe", "safe"],
    )
    assert scores["specificity"] == pytest.approx(2 / 3)
