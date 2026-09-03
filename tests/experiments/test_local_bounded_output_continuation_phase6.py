from __future__ import annotations

import inspect

import pytest

from experiments.local_campaign.local_bounded_output_continuation_phase6 import (
    SCHEMA,
    bounded_local_config,
    validate_alignment_prerequisite,
    validate_completion,
)
from ura.targets.local import (
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    MAX_VLLM_GENERATION_TOKENS,
)


def test_bounded_vllm_recovery_keeps_hardware_fit_context() -> None:
    assert SCHEMA.endswith("/2")
    spec = "vllm:example/model"
    result = bounded_local_config(
        {
            spec: {
                "revision": "a" * 40,
                "modalities": ["text", "image"],
                "max_model_len": -1,
            }
        },
        spec=spec,
        generation_tokens=MAX_VLLM_GENERATION_TOKENS,
        timeout=DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    )

    assert result[spec]["max_model_len"] == -1
    assert result[spec]["max_tokens"] == MAX_VLLM_GENERATION_TOKENS
    assert result[spec]["timeout"] == DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS


def test_bounded_ollama_recovery_keeps_hardware_fit_context() -> None:
    spec = "ollama:example:latest"
    result = bounded_local_config(
        {
            spec: {
                "digest": "b" * 64,
                "modalities": ["text"],
                "num_ctx": "fit",
                "num_predict": -1,
            }
        },
        spec=spec,
        generation_tokens=MAX_VLLM_GENERATION_TOKENS,
        timeout=DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    )

    assert result[spec]["num_ctx"] == "fit"
    assert result[spec]["num_predict"] == MAX_VLLM_GENERATION_TOKENS
    assert result[spec]["timeout"] == DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("spec", "config"),
    (
        ("vllm:example/model", {"max_model_len": 8192}),
        ("ollama:example:latest", {"num_ctx": 8192}),
    ),
)
def test_bounded_recovery_refuses_non_hardware_fit_context(
    spec: str, config: dict[str, object]
) -> None:
    with pytest.raises(ValueError, match="lost hardware-fit context"):
        bounded_local_config(
            {spec: config},
            spec=spec,
            generation_tokens=MAX_VLLM_GENERATION_TOKENS,
            timeout=DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
        )


def test_bounded_recovery_validators_follow_the_named_prior_launch_descriptor() -> None:
    alignment_source = inspect.getsource(validate_alignment_prerequisite)
    completion_source = inspect.getsource(validate_completion)

    assert 'snapshot.get("prior_launch")' in alignment_source
    assert 'snapshot.get("launch")' not in alignment_source
    assert 'snapshot["prior_launch"]' in completion_source
    assert 'snapshot["launch"]' not in completion_source
