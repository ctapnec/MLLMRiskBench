"""Local vLLM identity is decided by an explicit path signal, not cwd existence.

A bare Hugging Face hub id must be treated as a remote checkpoint (requiring an
immutable revision) even when a same-named directory shadows it in the current
working directory; only an explicit path is a local checkpoint.
"""
from __future__ import annotations

from pathlib import Path

import pytest

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
    VLLMTarget(str(ckpt), modality_support=("text",), model_digest=digest).validate_research_identity()
    wrong = VLLMTarget(str(ckpt), modality_support=("text",), model_digest="0" * 64)
    with pytest.raises(ValueError, match="digest does not match"):
        wrong.validate_research_identity()
