"""Local vLLM identity is decided by an explicit path signal, not cwd existence.

A bare Hugging Face hub id must be treated as a remote checkpoint (requiring an
immutable revision) even when a same-named directory shadows it in the current
working directory; only an explicit path is a local checkpoint.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from ura.runner import _component_config
from ura.targets.local import (
    OllamaTarget,
    VLLMTarget,
    _is_explicit_local_path,
    _tree_sha256,
)


def test_is_explicit_local_path():
    assert _is_explicit_local_path("./ckpt")
    assert _is_explicit_local_path("../ckpt")
    assert _is_explicit_local_path("~/ckpt")
    assert _is_explicit_local_path(str(Path("/abs/ckpt")))
    assert not _is_explicit_local_path("Qwen/Qwen3-VL-8B-Instruct")
    assert not _is_explicit_local_path("meta-llama/Llama-3-8B")
    assert not _is_explicit_local_path("")


def test_hub_id_not_local_even_if_cwd_dir_shadows_it(tmp_path, monkeypatch):
    shadow = tmp_path / "Qwen" / "Qwen3-VL-8B-Instruct"
    shadow.mkdir(parents=True)
    (shadow / "config.json").write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    target = VLLMTarget("Qwen/Qwen3-VL-8B-Instruct", modality_support=("text",))
    with pytest.raises(ValueError, match="immutable"):
        target.validate_research_identity()


def test_explicit_local_path_requires_matching_digest(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    (ckpt / "weights.bin").write_bytes(b"abc")
    digest = _tree_sha256(ckpt.resolve())
    target = VLLMTarget(
        str(ckpt), modality_support=("text",), model_digest=digest
    )
    target.validate_research_identity()
    persisted = json.dumps(_component_config(target), sort_keys=True)
    assert target.name == f"vllm:local-checkpoint@sha256:{digest}"
    assert target.model == "local-checkpoint"
    assert str(ckpt.resolve()) not in persisted
    assert run_matrix._persisted_model_spec(
        f"vllm:{ckpt}", {"digest": digest}
    ) == target.name
    wrong = VLLMTarget(str(ckpt), modality_support=("text",), model_digest="0" * 64)
    with pytest.raises(ValueError, match="digest does not match"):
        wrong.validate_research_identity()


def test_local_alias_identity_is_separate_from_execution_condition() -> None:
    digest = "a" * 64
    ollama_a = OllamaTarget("alias-a", model_digest=digest)
    ollama_b = OllamaTarget("alias-b", model_digest=digest)
    assert run_matrix._precall_model_identity(ollama_a) == (
        run_matrix._precall_model_identity(ollama_b)
    )
    assert run_matrix._target_execution_condition_identity(ollama_a) == (
        run_matrix._target_execution_condition_identity(ollama_b)
    )

    revision = "b" * 40
    bf16 = VLLMTarget(
        "org/model", revision=revision, quantization=None, dtype="bfloat16",
        modality_support=("text",),
    )
    fp8 = VLLMTarget(
        "org/model", revision=revision, quantization="fp8", dtype="auto",
        modality_support=("text",),
    )
    assert run_matrix._precall_model_identity(bf16) == (
        run_matrix._precall_model_identity(fp8)
    )
    assert run_matrix._target_execution_condition_identity(bf16) != (
        run_matrix._target_execution_condition_identity(fp8)
    )


def test_local_config_artifact_uses_a_logical_filename(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.mkdir()
    (ckpt / "weights.bin").write_bytes(b"abc")
    digest = _tree_sha256(ckpt.resolve())
    spec = f"vllm:{ckpt.resolve()}"
    config = tmp_path / "local-targets.json"
    config.write_text(json.dumps({spec: {
        "digest": digest, "modalities": ["text"], "tensor_parallel_size": 1,
    }}), encoding="utf-8")

    loaded, artifact = run_matrix._load_local_config(str(config), [spec])

    assert loaded[spec]["digest"] == digest
    assert loaded[spec]["tensor_parallel_size"] == 1
    assert artifact is not None
    assert set(artifact) == {
        "file", "sha256", "bytes", "normalized_selected_sha256",
    }
    assert artifact["file"] == config.name
    assert str(config.resolve()) not in json.dumps(artifact)
    target = run_matrix.build_target(spec, local_identity=loaded[spec])
    assert target.tensor_parallel_size == 1


def test_selected_local_config_identity_is_path_independent(tmp_path):
    specs = []
    configs = []
    for name in ("private-a", "private-b"):
        checkpoint = tmp_path / name / "checkpoint"
        checkpoint.mkdir(parents=True)
        (checkpoint / "weights.bin").write_bytes(b"same checkpoint bytes")
        digest = _tree_sha256(checkpoint.resolve())
        spec = f"vllm:{checkpoint.resolve()}"
        config = tmp_path / f"{name}.json"
        config.write_text(json.dumps({spec: {
            "digest": digest,
            "modalities": ["text"],
            "tensor_parallel_size": 1,
        }}), encoding="utf-8")
        specs.append(spec)
        configs.append(config)

    artifacts = [
        run_matrix._load_local_config(
            str(config),
            [spec],
            hardware={
                "available": False,
                "source": "fixture",
                "gpu_count": 0,
                "aggregate_vram_gib": 0.0,
                "max_gpu_vram_gib": 0.0,
                "gpus": [],
            },
        )[1]
        for spec, config in zip(specs, configs, strict=True)
    ]
    assert artifacts[0] is not None and artifacts[1] is not None
    assert (
        artifacts[0]["normalized_selected_sha256"]
        == artifacts[1]["normalized_selected_sha256"]
    )
    assert artifacts[0]["sha256"] != artifacts[1]["sha256"]


def test_private_generated_local_config_is_consumed_and_unlinked(
    tmp_path, monkeypatch,
):
    checkpoint = (tmp_path / "private-checkpoint").resolve()
    spec = f"vllm:{checkpoint}"
    document = {spec: {
        "digest": "a" * 64,
        "modalities": ["text"],
        "tensor_parallel_size": 1,
        "gpu_memory_utilization": 0.9,
        "parameter_count_b": 1,
        "quantization": "none",
    }}
    raw = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    private = tmp_path / ".private-local-configs"
    private.mkdir()
    config = private / f"selected-{digest[:24]}-0123456789abcdef.json"
    config.write_bytes(raw)
    monkeypatch.setenv("URA_PRIVATE_TRANSIENT_LOCAL_CONFIG", str(config.resolve()))

    loaded, artifact = run_matrix._load_local_config(
        str(config),
        [spec],
        hardware={
            "available": False,
            "source": "fixture",
            "gpu_count": 0,
            "aggregate_vram_gib": 0.0,
            "max_gpu_vram_gib": 0.0,
            "gpus": [],
        },
        expected_sha256=digest,
    )

    assert loaded[spec]["digest"] == "a" * 64
    assert artifact == {
        "file": config.name,
        "sha256": digest,
        "bytes": len(raw),
        "normalized_selected_sha256": artifact["normalized_selected_sha256"],
    }
    assert not config.exists()
    assert "URA_PRIVATE_TRANSIENT_LOCAL_CONFIG" not in os.environ


def test_run_matrix_rejects_multiple_local_models_per_process(tmp_path):
    with pytest.raises(SystemExit):
        run_matrix.main([
            "--local", "vllm:one/model,vllm:two/model",
            "--attackers", "replay",
            "--judges", "rules",
            "--corpora", "synth",
            "--out", str(tmp_path / "out"),
        ])


def test_local_target_setup_error_does_not_persist_checkpoint_path(
    tmp_path, project_revision_args,
):
    missing = (tmp_path / "private-workstation" / "missing-ckpt").resolve()
    spec = f"vllm:{missing}"
    digest = "0" * 64
    config = tmp_path / "local-targets.json"
    config.write_text(json.dumps({spec: {
        "digest": digest, "modalities": ["text"], "tensor_parallel_size": 1,
    }}), encoding="utf-8")
    out = tmp_path / "artifacts"

    result = run_matrix.main([
        "--preflight-only",
        *project_revision_args,
        "--local", spec,
        "--local-config", str(config),
        "--attackers", "replay",
        "--judges", "rules",
        "--corpora", "synth",
        "--limit", "1",
        "--out", str(out),
    ])

    assert result == 1
    error = json.loads(next(out.glob("*.error.json")).read_text(encoding="utf-8"))
    serialized_values = "\n".join(str(value) for value in error.values())
    assert str(missing) not in serialized_values
    assert error["model_spec"] == f"vllm:local-checkpoint@sha256:{digest}"


def test_prebuilt_local_judge_target_is_reused_by_the_cascade():
    sentinel = object()
    cascade = run_matrix.build_judges(
        ["llm"], "vllm:./private/judge", judge_target=sentinel
    )
    assert len(cascade.stages) == 1
    assert cascade.stages[0].judge_target is sentinel


def test_run_matrix_rejects_local_target_and_local_judge_double_engine(
    tmp_path, project_revision_args,
):
    with pytest.raises(SystemExit):
        run_matrix.main([
            "--preflight-only",
            *project_revision_args,
            "--local", "vllm:org/Target-7B",
            "--judge-model", "vllm:org/Judge-7B",
            "--attackers", "replay",
            "--judges", "rules,llm",
            "--corpora", "synth",
            "--out", str(tmp_path / "double-engine"),
        ])


@pytest.mark.parametrize("valid_config", [False, True])
def test_local_judge_path_never_enters_retained_request_or_error_artifacts(
    tmp_path, project_revision_args, valid_config,
):
    missing = (tmp_path / "private-workstation" / "judge-ckpt").resolve()
    spec = f"vllm:{missing}"
    digest = "0" * 64
    config = tmp_path / "judge-local-targets.json"
    config.write_text(json.dumps({spec: {
        "digest": digest,
        "modalities": ["text"] if valid_config else [],
        "tensor_parallel_size": 1,
    }}), encoding="utf-8")
    out = tmp_path / ("valid" if valid_config else "invalid")

    result = run_matrix.main([
        "--preflight-only",
        *project_revision_args,
        "--api", "mock", "--target-answer-retries", "0",
        "--judge-model", spec,
        "--local-config", str(config),
        "--attackers", "replay",
        "--judges", "rules,llm",
        "--corpora", "synth",
        "--limit", "1",
        "--out", str(out),
    ])

    assert result == 1

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, child in value.items():
                yield str(key)
                yield from strings(child)
        elif isinstance(value, list):
            for child in value:
                yield from strings(child)

    retained_strings = []
    for artifact in out.rglob("*.json"):
        retained_strings.extend(strings(json.loads(artifact.read_text(encoding="utf-8"))))
    assert retained_strings
    assert all(str(missing) not in value for value in retained_strings)
    assert all(spec not in value for value in retained_strings)
