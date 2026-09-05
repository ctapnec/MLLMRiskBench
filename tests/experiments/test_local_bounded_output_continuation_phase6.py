from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from experiments.local_campaign import local_bounded_output_cuda_recovery_phase6
from experiments.local_campaign.local_bounded_output_continuation_phase6 import (
    SCHEMA,
    _expand_compact_retained_result,
    _validate_invalid_result_root,
    bounded_local_config,
    profiled_bounded_local_config,
    validate_alignment_prerequisite,
    validate_completion,
)
from experiments.local_campaign.local_bounded_output_cuda_recovery_phase6 import (
    EXPECTED_DURABLE_ROWS as CUDA_DURABLE_ROWS,
    EXPECTED_RECOVERY_ROWS as CUDA_RECOVERY_ROWS,
    EXPECTED_TAIL_ROWS as CUDA_TAIL_ROWS,
    _completed_result as cuda_completed_result,
    _partial_partition as cuda_partial_partition,
    _validate_pre_state_root,
    inspect_interrupted_campaign as inspect_cuda_interruption,
    run as run_cuda_recovery,
    validate_alignment_prerequisite as validate_cuda_alignment_prerequisite,
    validate_completion as validate_cuda_completion,
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


def test_cuda_recovery_selects_only_the_unfinished_tail_and_reuses_canaries() -> None:
    assert CUDA_DURABLE_ROWS == 76
    assert CUDA_RECOVERY_ROWS == 94
    assert CUDA_DURABLE_ROWS + CUDA_RECOVERY_ROWS == CUDA_TAIL_ROWS == 170

    inspection = inspect.getsource(inspect_cuda_interruption)
    completed = inspect.getsource(cuda_completed_result)
    partition = inspect.getsource(cuda_partial_partition)
    execution = inspect.getsource(run_cuda_recovery)
    assert 'selected = int(state.get("selected_records", 0))' in completed
    assert "_partial_partition(" in inspection
    assert "extend_completed_selector(" in partition
    assert "durable_ids != eligible_ids[:EXPECTED_PARTIAL_ROWS]" in partition
    assert 'validated_canary_root=(prior_canary if prior_canary.is_dir() else None)' in execution
    assert '"successful_rows_repeated": 0' in execution


def test_compact_retained_result_expands_the_real_schema_2_shape() -> None:
    compact = {
        "attempted": 611,
        "level1": {"path": "/sealed/level1.json", "sha256": "a" * 64, "bytes": 1},
        "missing": 0,
        "result_root": "/sealed/result",
        "selected_records": 611,
        "state": {"path": "/sealed/state.json", "sha256": "b" * 64, "bytes": 1},
        "successful": 611,
    }

    expanded = _expand_compact_retained_result(
        compact,
        unit_id="local-hardware-fit-003",
        source_lane="local-ollama-ministral-text-primary-100",
        corpus=None,
        selected_records=611,
    )

    assert expanded["status"] == "complete"
    assert expanded["target_answer_retries"] == 1
    assert expanded["target_call_cap"] == 1_222
    assert expanded["target_attempts"] == 611
    assert expanded["successful_target_generations"] == 611
    assert expanded["missing_responses"] == 0
    assert expanded["state"] is compact["state"]
    assert expanded["level1"] is compact["level1"]


@pytest.mark.parametrize(
    "mutation",
    (
        {"extra": True},
        {"attempted": 610},
        {"successful": 610},
        {"missing": True},
        {"selected_records": 610},
    ),
)
def test_compact_retained_result_rejects_contract_and_accounting_mutations(
    mutation: dict[str, object],
) -> None:
    compact: dict[str, object] = {
        "attempted": 611,
        "level1": {"path": "/sealed/level1.json", "sha256": "a" * 64, "bytes": 1},
        "missing": 0,
        "result_root": "/sealed/result",
        "selected_records": 611,
        "state": {"path": "/sealed/state.json", "sha256": "b" * 64, "bytes": 1},
        "successful": 611,
    }
    compact.update(mutation)

    with pytest.raises(ValueError, match="compact retained result"):
        _expand_compact_retained_result(
            compact,
            unit_id="local-hardware-fit-003",
            source_lane="local-ollama-ministral-text-primary-100",
            corpus=None,
            selected_records=611,
        )


def test_cuda_completion_expands_compact_middle_stratum_before_validation() -> None:
    validation = inspect.getsource(validate_cuda_completion)

    assert "_expand_compact_retained_result(" in validation
    assert "middle_results[unit_id]" in validation
    assert "retained_selected -= EARLY_PARTIAL_ROWS" in validation
    assert 'evidence["interrupted_durable_prefix"]' in validation
    assert '"retained_predecessor_rows": EARLY_PARTIAL_ROWS' in validation


def test_cuda_recovery_accepts_only_exact_pre_state_evidence(tmp_path: Path) -> None:
    root = tmp_path / "result"
    root.mkdir()
    for name in (
        "live-attestation-a.json",
        "project-revision-a.project-revision.json",
        "request-envelope-a.request-envelope.json",
        "source-conformance-a.json",
    ):
        (root / name).write_text("{}\n", encoding="utf-8")

    assert len(_validate_pre_state_root(root) or []) == 4

    (root / "run.manifest.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="measured or ambiguous"):
        _validate_pre_state_root(root)


def test_phase7_dispatches_cuda_recovery_without_pooling_retained_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completion = tmp_path / "completion.json"
    completion.write_text(
        json.dumps({"schema": "ura-local-bounded-output-cuda-recovery-phase6/1"}),
        encoding="utf-8",
    )
    expected = {"validated": True}
    observed: dict[str, Path] = {}

    def validate(path: Path, *, runner_root: Path) -> dict[str, bool]:
        observed["completion"] = path
        observed["runner_root"] = runner_root
        return expected

    monkeypatch.setattr(
        local_bounded_output_cuda_recovery_phase6,
        "validate_completion",
        validate,
    )
    assert validate_completion(completion, runner_root=tmp_path) is expected
    assert observed == {"completion": completion, "runner_root": tmp_path}

    dispatch = inspect.getsource(validate_completion)
    validation = inspect.getsource(validate_cuda_completion)

    assert 'candidate.get("schema") == "ura-local-bounded-output-cuda-recovery-phase6/1"' in dispatch
    assert "validate_cuda_recovery_completion(" in dispatch
    assert 'evidence["interrupted_cuda_rows"]' in validation
    assert '"retained_predecessor_rows": EXPECTED_PARTIAL_ROWS' in validation
    assert '"security_metric_pooling_permitted": False' in validation
    assert '"successful_rows_repeated": 0' in validation


def test_alignment_prerequisite_dispatches_cuda_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completion = tmp_path / "completion.json"
    completion.write_text(
        json.dumps({"schema": "ura-local-bounded-output-cuda-recovery-phase6/1"}),
        encoding="utf-8",
    )
    expected = {"deepseek_result": {"target_attempts": 931}}
    observed: dict[str, Path] = {}

    def validate(path: Path, *, runner_root: Path) -> dict[str, object]:
        observed["completion"] = path
        observed["runner_root"] = runner_root
        return expected

    monkeypatch.setattr(
        local_bounded_output_cuda_recovery_phase6,
        "validate_alignment_prerequisite",
        validate,
    )
    assert validate_alignment_prerequisite(completion, runner_root=tmp_path) is expected
    assert observed == {"completion": completion, "runner_root": tmp_path}

    dispatch = inspect.getsource(validate_alignment_prerequisite)
    validation = inspect.getsource(validate_cuda_alignment_prerequisite)
    assert "validate_cuda_alignment_prerequisite(" in dispatch
    assert 'deepseek_result = retained_snapshot["retained_results"][deepseek_id]' in validation
