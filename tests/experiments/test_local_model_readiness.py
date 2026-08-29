from __future__ import annotations

import random

import pytest

from experiments.local_model_readiness import (
    READINESS_SEED,
    SCHEMA,
    TEXT_BANK,
    TEXT_MIN_CORRECT,
    TEXT_SAMPLE_SIZE,
    VISION_MIN_CORRECT,
    VISION_SAMPLE_SIZE,
    _run_text,
    readiness_policy,
    validate_readiness,
)
from ura.data_models import DialogTurn, Response


class AnsweringTarget:
    def __init__(self) -> None:
        selected = random.Random(READINESS_SEED).sample(TEXT_BANK, TEXT_SAMPLE_SIZE)
        answers = {
            "sum-7-5": "12",
            "product-9-3": "27",
            "difference-18-11": "7",
            "capital-france": "Paris",
            "freezing-water": "0",
            "opposite-north": "south",
            "sort-integers": "2,5,8",
            "uppercase-thesis": "THESIS",
            "earth-satellite": "moon",
            "days-week": "7",
            "mix-red-blue": "purple",
            "cat-spanish": "gato",
            "binary-six": "110",
            "even-sequence": "8",
            "water-formula": "H2O",
            "earth-orbit": "true",
            "alphabet-first": "A",
            "minutes-hour": "60",
            "plural-mouse": "mice",
            "square-five": "25",
        }
        self.answers = {prompt: answers[question_id] for question_id, prompt, _ in selected}

    def generate(self, dialog: list[DialogTurn], *, seed: int | None = None) -> Response:
        prompt = dialog[0].content or ""
        answer = self.answers[prompt]
        return Response(
            attempt_id=f"readiness-{seed}",
            target="mock-local",
            output_turns=[DialogTurn(role="assistant", content=answer)],
            latency_ms=1.0,
            tokens={"prompt": 1, "completion": 1, "total": 2},
            raw={"backend": "mock"},
        )


def readiness_receipt(*, text_correct: int = 5, vision: bool = True) -> dict[str, object]:
    return {
        "modalities": ["text", "image"] if vision else ["text"],
        "policy": readiness_policy(),
        "readiness_id": "a" * 64,
        "requested_spec": "vllm:example/model",
        "schema": SCHEMA,
        "status": "verified",
        "text": {
            "correct": text_correct,
            "minimum_correct": TEXT_MIN_CORRECT,
            "nonresponses": 0,
            "observations": [{} for _ in range(TEXT_SAMPLE_SIZE)],
            "passed": True,
            "sample_seed": READINESS_SEED,
            "sample_size": TEXT_SAMPLE_SIZE,
        },
        "vision": (
            {
                "correct": VISION_MIN_CORRECT,
                "minimum_correct": VISION_MIN_CORRECT,
                "nonresponses": 0,
                "observations": [{} for _ in range(VISION_SAMPLE_SIZE)],
                "passed": True,
                "sample_seed": READINESS_SEED,
                "sample_size": VISION_SAMPLE_SIZE,
            }
            if vision
            else None
        ),
    }


def test_benign_text_readiness_uses_ten_seeded_questions() -> None:
    assert READINESS_SEED == 20260829
    assert TEXT_SAMPLE_SIZE == 10
    assert TEXT_MIN_CORRECT == 5
    result = _run_text(AnsweringTarget())
    assert result["passed"] is True
    assert result["correct"] == 10
    assert result["nonresponses"] == 0


def test_readiness_validator_requires_text_and_image_thresholds() -> None:
    validate_readiness(readiness_receipt(), expected_spec="vllm:example/model")
    with pytest.raises(ValueError, match="text readiness"):
        validate_readiness(readiness_receipt(text_correct=4))
    failed_vision = readiness_receipt()
    assert isinstance(failed_vision["vision"], dict)
    failed_vision["vision"]["nonresponses"] = 1
    with pytest.raises(ValueError, match="vision readiness"):
        validate_readiness(failed_vision)


def test_local_campaign_controllers_require_readiness_receipts() -> None:
    from pathlib import Path

    templates = Path("experiments/local_campaign/templates")
    for name in ("phase5_ollama_workflow.sh.in", "phase6_native_diagnostics.sh.in"):
        source = (templates / name).read_text(encoding="utf-8")
        assert "URA_LOCAL_MODEL_READINESS_ROOT" in source
        assert "-m experiments.local_model_readiness" in source
        assert "--expected-spec" in source
