from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from experiments.local_campaign.local_bounded_output_continuation_phase6 import (
    SCHEMA,
    _validate_invalid_result_root,
    bounded_local_config,
    profiled_bounded_local_config,
    validate_alignment_prerequisite,
    validate_completion,
)
from ura.targets.local import (
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    MAX_VLLM_GENERATION_TOKENS,
)


def test_bounded_vllm_recovery_keeps_hardware_fit_context() -> None:
    assert SCHEMA.endswith("/3")
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


def test_profiled_bounded_recovery_reuses_the_approved_vllm_topology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec = "vllm:example/model"

    def profile(selected_spec, config, *, path):
        assert selected_spec == spec
        assert path == tmp_path / "profiles.json"
        return (
            {
                **config,
                "gpu_memory_utilization": 0.85,
                "max_model_len": -1,
                "max_tokens": 4_096,
                "tensor_parallel_size": 2,
                "timeout": 120.0,
            },
            {"generation_tokens": 4_096},
        )

    monkeypatch.setattr(
        "experiments.local_campaign.local_bounded_output_continuation_phase6.apply_profile",
        profile,
    )
    result, evidence = profiled_bounded_local_config(
        {
            spec: {
                "gpu_memory_utilization": 0.9,
                "max_model_len": -1,
                "max_tokens": 25_000,
                "tensor_parallel_size": 1,
                "timeout": 120.0,
            }
        },
        spec=spec,
        profile_registry=tmp_path / "profiles.json",
    )

    assert evidence == {"generation_tokens": 4_096}
    assert result[spec]["tensor_parallel_size"] == 2
    assert result[spec]["gpu_memory_utilization"] == 0.85


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


def test_invalid_output_condition_requires_zero_durable_measured_rows(tmp_path: Path) -> None:
    root = tmp_path / "result"
    root.mkdir()
    for suffix in ("attempts", "responses", "trails"):
        (root / f"run.{suffix}.jsonl").write_bytes(b"")
    # The real first-call failure creates the judgment stream but reaches no
    # result-export stage, so run.jsonl is empty and run.results.jsonl absent.
    (root / "run.jsonl").write_bytes(b"")
    (root / "run.manifest.json").write_text(
        json.dumps(
            {
                "code_version": "ura-runner/2.30",
                "config": {
                    "components": {
                        "target": {
                            "max_model_len": -1,
                            "max_tokens": 25_000,
                            "timeout": 120.0,
                        }
                    }
                },
                "n_datapoints": 3,
                "n_attempts": 0,
            }
        ),
        encoding="utf-8",
    )
    (root / "run.error.json").write_text(
        json.dumps(
            {
                "call_budget_snapshot": {
                    "http_attempts": 0,
                    "judge_calls": 0,
                    "max_target_calls": 6,
                    "target_calls": 1,
                },
                "completed_attempts": 0,
                "exception_type": "ExternalCallFailure",
                "execution_started": True,
                "message": (
                    "target_call failed: generation exceeded the configured hard "
                    "120s deadline"
                ),
                "status": "error",
            }
        ),
        encoding="utf-8",
    )

    evidence = _validate_invalid_result_root(root)

    assert evidence["measured_target_attempts"] == 1
    assert evidence["durable_measured_rows"] == 0

    (root / "run.responses.jsonl").write_text('{"response":"must not be rerun"}\n')
    with pytest.raises(ValueError, match="durable row"):
        _validate_invalid_result_root(root)
