from __future__ import annotations

import hashlib
import json
import random

import pytest

from experiments.local_model_readiness import (
    BOUNDED_SCHEMA,
    COLORS,
    LEGACY_SCHEMA,
    PROFILE_DEFAULT_GENERATION_TOKENS,
    PROFILE_GENERATION_TOKEN_CANDIDATES,
    PROFILE_MAXIMUM_GENERATION_TOKENS,
    PROFILE_REQUEST_DEADLINE_SECONDS,
    READINESS_SEED,
    SCHEMA,
    TEXT_BANK,
    TEXT_MIN_CORRECT,
    TEXT_SAMPLE_SIZE,
    VISION_MIN_CORRECT,
    VISION_SAMPLE_SIZE,
    _configure_readiness_condition,
    _profile_generation_conditions,
    _run_text,
    _run_vision,
    _run_condition,
    bounded_readiness_policy,
    legacy_readiness_policy,
    readiness_policy,
    validate_readiness,
)
from experiments.local_model_profiles import (
    LEGACY_SCHEMA as LEGACY_PROFILE_SCHEMA,
    SCHEMA as PROFILE_SCHEMA,
    apply_profile,
    load_profiles,
    update_registry,
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


class GenerationStressTarget(AnsweringTarget):
    def __init__(self, *, fail_at: int | None = None) -> None:
        super().__init__()
        self.max_tokens = PROFILE_DEFAULT_GENERATION_TOKENS
        self.fail_at = fail_at
        self.closed = 0
        self.poisoned = False

    def close(self) -> None:
        self.closed += 1
        self.poisoned = False

    def generate(self, dialog: list[DialogTurn], *, seed: int | None = None) -> Response:
        if self.poisoned:
            raise AssertionError("a timed-out request remained queued")
        prompt = dialog[0].content or ""
        if "generation-throughput calibration" not in prompt:
            return super().generate(dialog, seed=seed)
        latency_ms = (
            120_001.0
            if self.fail_at is not None and self.max_tokens >= self.fail_at
            else 1.0
        )
        self.poisoned = latency_ms >= 120_000.0
        return Response(
            attempt_id=f"readiness-{seed}",
            target="mock-local",
            output_turns=[DialogTurn(role="assistant", content="alpha beta")],
            latency_ms=latency_ms,
            tokens={
                "prompt": 1,
                "completion": self.max_tokens,
                "total": self.max_tokens + 1,
            },
            raw={"backend": "mock", "finish_reason": "length"},
        )


def _stress_result(generation_tokens: int) -> dict[str, object]:
    minimum = (generation_tokens * 95 + 99) // 100
    return {
        "characters": 10,
        "deadline_passed": True,
        "effective_generation": {},
        "latency_ms": 1.0,
        "minimum_completion_tokens": minimum,
        "outcome": "generated_text",
        "passed": True,
        "preview": "alpha beta",
        "reached_generation_cap": True,
        "requested_generation_tokens": generation_tokens,
        "termination_reason": "length",
        "thinking_output_observed": False,
        "tokens": {
            "prompt": 1,
            "completion": generation_tokens,
            "total": generation_tokens + 1,
        },
    }


def readiness_receipt(
    *,
    text_correct: int = 5,
    vision: bool = True,
    spec: str = "vllm:example/model",
    think: bool | str = False,
) -> dict[str, object]:
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
    tokens = PROFILE_GENERATION_TOKEN_CANDIDATES[0]
    conditions = [{
        "deadline_failures": 0,
        "generation_tokens": tokens,
        "passed": True,
        "stress_text": _stress_result(tokens),
        "stress_vision": _stress_result(tokens) if vision else None,
    }]
    local_execution = (
        {"max_model_len": -1}
        if spec.startswith("vllm:")
        else {"num_ctx": "fit", "think": think}
    )
    return {
        "execution_profile": {
            "conditions": conditions,
            "local_execution": local_execution,
            "per_request_deadline_seconds": PROFILE_REQUEST_DEADLINE_SECONDS,
            "selected_generation_tokens": PROFILE_MAXIMUM_GENERATION_TOKENS,
            "selection_basis": "first_descending_stress_pass",
        },
        "modalities": ["text", "image"] if vision else ["text"],
        "policy": readiness_policy(),
        "readiness_id": "a" * 64,
        "requested_spec": spec,
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
    assert isinstance(pass_with_nonresponses["vision"], dict)
    pass_with_nonresponses["vision"]["nonresponses"] = 3
    validate_readiness(pass_with_nonresponses)
    with pytest.raises(ValueError, match="text readiness"):
        validate_readiness(readiness_receipt(text_correct=4))
    below_vision_threshold = readiness_receipt()
    assert isinstance(below_vision_threshold["vision"], dict)
    below_vision_threshold["vision"]["correct"] = 1
    below_vision_threshold["vision"]["passed"] = False
    with pytest.raises(ValueError, match="vision readiness"):
        validate_readiness(below_vision_threshold)

    vision = _run_vision(PartiallySeeingTarget())
    assert vision["passed"] is True
    assert vision["correct"] == 2
    assert vision["nonresponses"] == 3


def test_readiness_approves_first_descending_passing_condition() -> None:
    value = readiness_receipt(vision=False)
    assert validate_readiness(value)["execution_profile"][
        "selected_generation_tokens"
    ] == 25000
    value["execution_profile"]["conditions"].pop()
    with pytest.raises(ValueError, match="execution profile"):
        validate_readiness(value)


def test_generation_profile_lowers_cap_at_first_120_second_failure() -> None:
    target = GenerationStressTarget(fail_at=4_096)
    conditions, selected = _profile_generation_conditions(
        target,
        spec="vllm:example/model",
        modalities=["text"],
    )

    assert selected == 2_048
    assert [row["generation_tokens"] for row in conditions] == [
        25_000,
        16_384,
        8_192,
        4_096,
        2_048,
    ]
    assert [row["passed"] for row in conditions] == [False, False, False, False, True]
    assert conditions[0]["deadline_failures"] == 1
    assert target.closed == 4


def test_generation_profile_resets_between_timed_out_text_and_image() -> None:
    target = GenerationStressTarget(fail_at=4_096)

    conditions, selected = _profile_generation_conditions(
        target,
        spec="vllm:example/model",
        modalities=["text", "image"],
    )

    assert selected == 2_048
    assert len(conditions) == 5
    assert target.closed == 8


def test_generation_profile_rejects_early_stop_before_requested_cap() -> None:
    target = GenerationStressTarget()
    original_generate = target.generate

    def early_stop(dialog, *, seed=None):
        response = original_generate(dialog, seed=seed)
        if "generation-throughput calibration" not in (dialog[0].content or ""):
            return response
        return response.model_copy(
            update={
                "raw": {"backend": "mock", "finish_reason": "stop"},
                "tokens": {"prompt": 1, "completion": 8, "total": 9},
            }
        )

    target.generate = early_stop
    conditions, selected = _profile_generation_conditions(
        target,
        spec="ollama:example:model",
        modalities=["text"],
    )

    assert selected is None
    assert len(conditions) == len(PROFILE_GENERATION_TOKEN_CANDIDATES)
    assert all(condition["passed"] is False for condition in conditions)


def test_thinking_only_stress_calibrates_without_replacing_answer_survey() -> None:
    value = readiness_receipt(
        vision=False,
        spec="ollama:example:model",
        think=True,
    )
    stress = value["execution_profile"]["conditions"][0]["stress_text"]
    stress["characters"] = 0
    stress["outcome"] = "model_nonresponse"
    stress["preview"] = ""
    stress["thinking_output_observed"] = True

    assert validate_readiness(value)["status"] == "verified"


def test_current_readiness_rejects_non_prefix_or_post_failure_conditions() -> None:
    value = readiness_receipt(vision=False)
    value["execution_profile"]["conditions"][0]["generation_tokens"] = 16_384
    with pytest.raises(ValueError, match="conditions"):
        validate_readiness(value)

    value = readiness_receipt(vision=False)
    passing = value["execution_profile"]["conditions"][0]
    failed = {
        **passing,
        "generation_tokens": 25_000,
        "stress_text": _stress_result(25_000),
    }
    failed["stress_text"]["termination_reason"] = "stop"
    failed["stress_text"]["tokens"]["completion"] = 1
    failed["stress_text"]["reached_generation_cap"] = False
    failed["stress_text"]["passed"] = False
    failed["passed"] = False
    passing = {
        **passing,
        "generation_tokens": 16_384,
        "stress_text": _stress_result(16_384),
    }
    extra = {
        **passing,
        "generation_tokens": 8_192,
        "stress_text": _stress_result(8_192),
    }
    value["execution_profile"]["conditions"] = [failed, passing, extra]
    value["execution_profile"]["selected_generation_tokens"] = 16_384
    with pytest.raises(ValueError, match="condition status"):
        validate_readiness(value)


def test_readiness_condition_forces_fit_context_and_preserves_thinking() -> None:
    vllm_config = {"max_model_len": 12_288, "max_tokens": 512}
    assert _configure_readiness_condition("vllm:example/model", vllm_config) == {
        "max_model_len": -1
    }
    assert vllm_config == {
        "max_model_len": -1,
        "max_tokens": 25_000,
        "timeout": 120.0,
    }

    ollama_config = {"num_ctx": 8_192, "num_predict": 512, "think": "low"}
    assert _configure_readiness_condition("ollama:example:model", ollama_config) == {
        "num_ctx": "fit",
        "think": "low",
    }
    assert ollama_config == {
        "num_ctx": "fit",
        "num_predict": 25_000,
        "think": "low",
        "timeout": 120.0,
    }


def test_retained_schema_two_readiness_receipts_remain_valid() -> None:
    value = readiness_receipt(vision=False)
    text = value["text"]
    conditions = [
        {
            "deadline_failures": 0,
            "generation_tokens": tokens,
            "passed": True,
            "text": text,
            "vision": None,
        }
        for tokens in (
            PROFILE_DEFAULT_GENERATION_TOKENS,
            PROFILE_MAXIMUM_GENERATION_TOKENS,
        )
    ]
    value["schema"] = BOUNDED_SCHEMA
    value["policy"] = bounded_readiness_policy()
    value["execution_profile"] = {
        "conditions": conditions,
        "per_request_deadline_seconds": PROFILE_REQUEST_DEADLINE_SECONDS,
        "selected_generation_tokens": PROFILE_MAXIMUM_GENERATION_TOKENS,
        "selection_basis": "highest_passing_condition",
    }

    assert validate_readiness(value)["schema"] == BOUNDED_SCHEMA


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
    assert json.loads(registry.read_text(encoding="ascii"))["schema"] == PROFILE_SCHEMA
    monkeypatch.setenv("URA_LOCAL_MODEL_PROFILE_REGISTRY", str(registry))
    assert load_profiles()["vllm:example/model"]["generation_tokens"] == 25000
    profiled, evidence = apply_profile("vllm:example/model", config)
    assert profiled["max_tokens"] == 25000
    assert profiled["timeout"] == PROFILE_REQUEST_DEADLINE_SECONDS
    assert evidence is not None

    overridden, _evidence = apply_profile(
        "vllm:example/model",
        {**config, "max_model_len": 2_048, "max_tokens": 8192, "timeout": 90},
    )
    assert overridden["max_tokens"] == 25000
    assert overridden["max_model_len"] == -1
    assert overridden["timeout"] == PROFILE_REQUEST_DEADLINE_SECONDS

    ollama_receipt = readiness_receipt(
        vision=False,
        spec="ollama:example:model",
        think=True,
    )
    ollama_path = tmp_path / "ollama.readiness.json"
    ollama_raw = (
        json.dumps(ollama_receipt, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    ollama_path.write_bytes(ollama_raw)
    ollama_config = {
        "digest": "d" * 64,
        "modalities": ["text"],
        "num_ctx": 8_192,
        "think": False,
    }
    update_registry(
        spec="ollama:example:model",
        local_config=ollama_config,
        readiness_path=ollama_path,
        readiness_sha256=hashlib.sha256(ollama_raw).hexdigest(),
        readiness=ollama_receipt,
        path=registry,
    )
    profiled_ollama, _ = apply_profile(
        "ollama:example:model",
        ollama_config,
        path=registry,
    )
    assert profiled_ollama["num_ctx"] == "fit"
    assert profiled_ollama["num_predict"] == 25_000
    assert profiled_ollama["think"] is True

    changed = {**config, "revision": "c" * 40}
    with pytest.raises(ValueError, match="identity differs"):
        apply_profile("vllm:example/model", changed)

    with pytest.raises(ValueError, match="only to local"):
        apply_profile("openai-responses:example", {})


def test_legacy_profile_registry_cannot_configure_new_local_inference(
    tmp_path,
) -> None:
    registry = tmp_path / "legacy-profiles.json"
    registry.write_text(
        json.dumps(
            {
                "schema": LEGACY_PROFILE_SCHEMA,
                "models": {
                    "vllm:example/model": {
                        "generation_tokens": 25_000,
                        "identity": {"revision": "b" * 40},
                        "modalities": ["text"],
                        "readiness": {
                            "path": "/historical/readiness.json",
                            "sha256": "c" * 64,
                            "readiness_id": "d" * 64,
                        },
                        "request_timeout_seconds": 120,
                    }
                },
            }
        ),
        encoding="ascii",
    )

    assert load_profiles(path=registry) == {}


def test_local_campaign_controllers_require_readiness_receipts() -> None:
    from pathlib import Path

    templates = Path("experiments/local_campaign/templates")
    for name in ("phase5_ollama_workflow.sh.in", "phase6_native_diagnostics.sh.in"):
        source = (templates / name).read_text(encoding="utf-8")
        assert "URA_LOCAL_MODEL_READINESS_ROOT" in source
        assert "-m experiments.local_model_readiness" in source
        assert "--expected-spec" in source
