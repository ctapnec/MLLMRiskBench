"""Local vLLM identity is decided by an explicit path signal, not cwd existence.

A bare Hugging Face hub id must be treated as a remote checkpoint (requiring an
immutable revision) even when a same-named directory shadows it in the current
working directory; only an explicit path is a local checkpoint.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from ura.runner import _component_config
from ura.targets.local import VLLMTarget, _is_explicit_local_path, _tree_sha256


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


def test_run_matrix_rejects_multiple_local_models_per_process(tmp_path):
    with pytest.raises(SystemExit):
        run_matrix.main([
            "--local", "vllm:one/model,vllm:two/model",
            "--attackers", "replay",
            "--judges", "rules",
            "--corpora", "synth",
            "--out", str(tmp_path / "out"),
        ])


def test_local_target_setup_error_does_not_persist_checkpoint_path(tmp_path):
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
