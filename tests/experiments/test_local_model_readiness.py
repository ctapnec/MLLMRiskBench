from __future__ import annotations

import hashlib
import json
import random

import pytest

from experiments.local_model_readiness import (
    COLORS,
    LEGACY_SCHEMA,
    PROFILE_DEFAULT_GENERATION_TOKENS,
    PROFILE_MAXIMUM_GENERATION_TOKENS,
    PROFILE_REQUEST_DEADLINE_SECONDS,
    READINESS_SEED,
    SCHEMA,
    TEXT_BANK,
    TEXT_MIN_CORRECT,
    TEXT_SAMPLE_SIZE,
    VISION_MIN_CORRECT,
    VISION_SAMPLE_SIZE,
    _run_text,
    _run_vision,
    _run_condition,
    legacy_readiness_policy,
    readiness_policy,
    validate_readiness,
)
from experiments.local_model_profiles import apply_profile, load_profiles, update_registry
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


class PartiallyAnsweringTarget(AnsweringTarget):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def generate(self, dialog: list[DialogTurn], *, seed: int | None = None) -> Response:
        self.calls += 1
        if self.calls <= 5:
            return super().generate(dialog, seed=seed)
        return Response(
            attempt_id=f"readiness-{seed}",
            target="mock-local",
            output_turns=[DialogTurn(role="assistant", content="")],
            latency_ms=1.0,
            tokens={"prompt": 1, "completion": 0, "total": 1},
            raw={"backend": "mock"},
        )


class PartiallySeeingTarget:
    def __init__(self) -> None:
        pairs = [(left, right) for left in COLORS for right in COLORS if left != right]
        selected = random.Random(READINESS_SEED).sample(pairs, VISION_SAMPLE_SIZE)
        self.answers = [f"LEFT={left};RIGHT={right}" for left, right in selected]
        self.calls = 0

    def generate(self, _dialog: list[DialogTurn], *, seed: int | None = None) -> Response:
        answer = self.answers[self.calls] if self.calls < 2 else ""
        self.calls += 1
        return Response(
            attempt_id=f"readiness-{seed}",
            target="mock-local",
            output_turns=[DialogTurn(role="assistant", content=answer)],
            latency_ms=1.0,
            tokens={
                "prompt": 1,
                "completion": int(bool(answer)),
                "total": 1 + int(bool(answer)),
            },
            raw={"backend": "mock"},
        )


class SlowReportedTarget(AnsweringTarget):
    def generate(self, dialog: list[DialogTurn], *, seed: int | None = None) -> Response:
        response = super().generate(dialog, seed=seed)
        return response.model_copy(update={"latency_ms": 120_001.0})


def readiness_receipt(*, text_correct: int = 5, vision: bool = True) -> dict[str, object]:
    text = {
        "correct": text_correct,
        "minimum_correct": TEXT_MIN_CORRECT,
        "nonresponses": 0,
        "observations": [{} for _ in range(TEXT_SAMPLE_SIZE)],
        "passed": text_correct >= TEXT_MIN_CORRECT,
        "sample_seed": READINESS_SEED,
        "sample_size": TEXT_SAMPLE_SIZE,
    }
    image = (
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
    )
    conditions = [
        {
            "deadline_failures": 0,
            "generation_tokens": tokens,
            "passed": text["passed"] and (image is None or image["passed"]),
            "text": text,
            "vision": image,
        }
        for tokens in (
            PROFILE_DEFAULT_GENERATION_TOKENS,
            PROFILE_MAXIMUM_GENERATION_TOKENS,
        )
    ]
    return {
        "execution_profile": {
            "conditions": conditions,
            "per_request_deadline_seconds": PROFILE_REQUEST_DEADLINE_SECONDS,
            "selected_generation_tokens": PROFILE_MAXIMUM_GENERATION_TOKENS,
            "selection_basis": "highest_passing_condition",
        },
        "modalities": ["text", "image"] if vision else ["text"],
        "policy": readiness_policy(),
        "readiness_id": "a" * 64,
        "requested_spec": "vllm:example/model",
        "schema": SCHEMA,
        "status": "verified",
        "text": text,
        "vision": image,
    }


def test_benign_text_readiness_uses_ten_seeded_questions() -> None:
    assert READINESS_SEED == 20260829
    assert TEXT_SAMPLE_SIZE == 10
    assert TEXT_MIN_CORRECT == 5
    result = _run_text(AnsweringTarget())
    assert result["passed"] is True
    assert result["correct"] == 10
    assert result["nonresponses"] == 0

    partial = _run_text(PartiallyAnsweringTarget())
    assert partial["passed"] is True
    assert partial["correct"] == 5
    assert partial["nonresponses"] == 5


def test_readiness_validator_requires_text_and_image_thresholds() -> None:
    assert VISION_MIN_CORRECT == 2
    validate_readiness(readiness_receipt(), expected_spec="vllm:example/model")
    pass_with_nonresponses = readiness_receipt()
    pass_with_nonresponses["text"]["nonresponses"] = 5
    for condition in pass_with_nonresponses["execution_profile"]["conditions"]:
        condition["text"]["nonresponses"] = 5
    assert isinstance(pass_with_nonresponses["vision"], dict)
    pass_with_nonresponses["vision"]["nonresponses"] = 3
    for condition in pass_with_nonresponses["execution_profile"]["conditions"]:
        condition["vision"]["nonresponses"] = 3
    validate_readiness(pass_with_nonresponses)
    with pytest.raises(ValueError, match="text readiness"):
        validate_readiness(readiness_receipt(text_correct=4))
    below_vision_threshold = readiness_receipt()
    assert isinstance(below_vision_threshold["vision"], dict)
    below_vision_threshold["vision"]["correct"] = 1
    below_vision_threshold["vision"]["passed"] = False
    for condition in below_vision_threshold["execution_profile"]["conditions"]:
        condition["vision"]["correct"] = 1
        condition["vision"]["passed"] = False
        condition["passed"] = False
    with pytest.raises(ValueError, match="vision readiness"):
        validate_readiness(below_vision_threshold)

    vision = _run_vision(PartiallySeeingTarget())
    assert vision["passed"] is True
    assert vision["correct"] == 2
    assert vision["nonresponses"] == 3


def test_readiness_approves_highest_passing_profiled_condition() -> None:
    value = readiness_receipt(vision=False)
    assert validate_readiness(value)["execution_profile"][
        "selected_generation_tokens"
    ] == 25000
    value["execution_profile"]["conditions"].pop()
    with pytest.raises(ValueError, match="execution profile"):
        validate_readiness(value)


def test_readiness_never_approves_a_condition_with_a_120_second_request() -> None:
    result = _run_condition(
        SlowReportedTarget(),
        spec="vllm:example/model",
        modalities=["text"],
        generation_tokens=PROFILE_MAXIMUM_GENERATION_TOKENS,
    )

    assert result["text"]["correct"] == TEXT_SAMPLE_SIZE
    assert result["deadline_failures"] == TEXT_SAMPLE_SIZE
    assert result["passed"] is False


def test_retained_schema_one_readiness_receipts_remain_valid() -> None:
    value = readiness_receipt(vision=False)
    value.pop("execution_profile")
    value["schema"] = LEGACY_SCHEMA
    value["policy"] = legacy_readiness_policy()
    assert validate_readiness(value)["schema"] == LEGACY_SCHEMA

    value["execution_profile"] = {}
    with pytest.raises(ValueError, match="legacy local-model readiness"):
        validate_readiness(value)


def test_readiness_profile_registry_is_identity_bound_and_reused(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    receipt = readiness_receipt(vision=False)
    receipt_path = tmp_path / "model.readiness.json"
    raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    receipt_path.write_bytes(raw)
    registry = tmp_path / "profiles.json"
    config = {
        "revision": "b" * 40,
        "modalities": ["text"],
        "max_model_len": -1,
    }
    update_registry(
        spec="vllm:example/model",
        local_config=config,
        readiness_path=receipt_path,
        readiness_sha256=hashlib.sha256(raw).hexdigest(),
        readiness=receipt,
        path=registry,
    )
    monkeypatch.setenv("URA_LOCAL_MODEL_PROFILE_REGISTRY", str(registry))
    assert load_profiles()["vllm:example/model"]["generation_tokens"] == 25000
    profiled, evidence = apply_profile("vllm:example/model", config)
    assert profiled["max_tokens"] == 25000
    assert profiled["timeout"] == PROFILE_REQUEST_DEADLINE_SECONDS
    assert evidence is not None

    overridden, _evidence = apply_profile(
        "vllm:example/model", {**config, "max_tokens": 8192, "timeout": 90}
    )
    assert overridden["max_tokens"] == 25000
    assert overridden["timeout"] == PROFILE_REQUEST_DEADLINE_SECONDS

    changed = {**config, "revision": "c" * 40}
    with pytest.raises(ValueError, match="identity differs"):
        apply_profile("vllm:example/model", changed)

    with pytest.raises(ValueError, match="only to local"):
        apply_profile("openai-responses:example", {})


def test_local_campaign_controllers_require_readiness_receipts() -> None:
    from pathlib import Path

    templates = Path("experiments/local_campaign/templates")
    for name in ("phase5_ollama_workflow.sh.in", "phase6_native_diagnostics.sh.in"):
        source = (templates / name).read_text(encoding="utf-8")
        assert "URA_LOCAL_MODEL_READINESS_ROOT" in source
        assert "-m experiments.local_model_readiness" in source
        assert "--expected-spec" in source
