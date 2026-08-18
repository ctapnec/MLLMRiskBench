from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import ura.adapters.nanogcg as nanogcg_module
from ura.adapters.base import AttackBudget
from ura.adapters.nanogcg import NanoGCGAttacker
from ura.converters.synth import synth_corpus
from ura.judges.guardrail import GuardrailJudge
from ura.model_acquisition import ModelAcquisitionError
from ura.targets.local import VLLMTarget, _tree_sha256


class _RejectAfterConstruction:
    """Exercise each consumer's cleanup callback like a failed post-hash."""

    def __init__(self, snapshot: Path) -> None:
        self.snapshot = snapshot.resolve()
        self.constructor_calls = 0

    def construct(self, _requirement, constructor, *, cleanup=None):
        self.constructor_calls += 1
        loaded = constructor(self.snapshot)
        assert cleanup is not None
        cleanup(loaded)
        raise ModelAcquisitionError("fixture post-verification mismatch")


def test_explicit_local_vllm_mutation_cleans_engine_and_exposes_no_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "checkpoint").resolve()
    snapshot.mkdir()
    weights = snapshot / "weights.bin"
    weights.write_bytes(b"sealed")
    digest = _tree_sha256(snapshot)
    events: list[str] = []

    class Engine:
        def __init__(self, **kwargs):
            assert kwargs["model"] == str(snapshot)
            assert kwargs["tokenizer"] == str(snapshot)
            assert os.environ["HF_HUB_OFFLINE"] == "1"
            weights.write_bytes(b"drift!")

        def shutdown(self) -> None:
            events.append("shutdown")

        def chat(self, *_args):
            events.append("inference")
            return []

    monkeypatch.setitem(
        sys.modules,
        "vllm",
        SimpleNamespace(LLM=Engine),
    )
    target = VLLMTarget(
        str(snapshot),
        model_digest=digest,
        modality_support=("text",),
    )
    with pytest.raises(ValueError, match="changed during engine construction"):
        target.preflight_base()
    assert events == ["shutdown"]
    assert target._llm is None


def test_vllm_postverify_failure_shutdowns_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    events: list[str] = []

    class Engine:
        def __init__(self, **kwargs):
            assert kwargs["model"] == str(snapshot)
            assert kwargs["tokenizer"] == str(snapshot)

        def shutdown(self) -> None:
            events.append("shutdown")

    monkeypatch.setitem(sys.modules, "vllm", SimpleNamespace(LLM=Engine))
    runtime = _RejectAfterConstruction(snapshot)
    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text",),
        model_runtime=runtime,
    )
    with pytest.raises(ModelAcquisitionError, match="post-verification"):
        target.preflight_base()
    assert runtime.constructor_calls == 1
    assert events == ["shutdown"]
    assert target._llm is None


def test_guardrail_postverify_failure_releases_every_loaded_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    events: list[str] = []

    class Tokenizer:
        def close(self) -> None:
            events.append("tokenizer-close")
            raise RuntimeError("cleanup continues")

    class Model:
        def to(self, device: str):
            events.append(f"model-to-{device}")
            return self

        def eval(self) -> None:
            events.append("model-eval")

        def close(self) -> None:
            events.append("model-close")

    class TokenizerLoader:
        @staticmethod
        def from_pretrained(path: str, **kwargs):
            assert path == str(snapshot)
            assert kwargs["local_files_only"] is True
            return Tokenizer()

    class ModelLoader:
        @staticmethod
        def from_pretrained(path: str, **kwargs):
            assert path == str(snapshot)
            assert kwargs["local_files_only"] is True
            return Model()

    fake_cuda = SimpleNamespace(
        is_available=lambda: True,
        empty_cache=lambda: events.append("cuda-empty"),
    )
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(cuda=fake_cuda))
    monkeypatch.setitem(
        sys.modules,
        "transformers",
        SimpleNamespace(
            AutoModelForCausalLM=ModelLoader,
            AutoTokenizer=TokenizerLoader,
        ),
    )
    runtime = _RejectAfterConstruction(snapshot)
    guard = GuardrailJudge(
        revision="b" * 40,
        device="cuda:0",
        model_runtime=runtime,
    )
    with pytest.raises(ModelAcquisitionError, match="post-verification"):
        guard.preflight()
    assert events == [
        "model-to-cuda:0",
        "model-eval",
        "tokenizer-close",
        "model-close",
        "model-to-cpu",
        "cuda-empty",
    ]
    assert guard._model is None and guard._tokenizer is None


def test_nanogcg_postverify_failure_releases_objects_without_optimization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    events: list[str] = []
    revision = "c" * 40

    class Model:
        config = SimpleNamespace(_commit_hash=revision)

        def to(self, device: str):
            events.append(f"model-to-{device}")
            return self

        def eval(self) -> None:
            events.append("model-eval")

        def close(self) -> None:
            events.append("model-close")

    class Tokenizer:
        init_kwargs = {"_commit_hash": revision}

        def close(self) -> None:
            events.append("tokenizer-close")

    fake_transformers = SimpleNamespace(
        AutoModelForCausalLM=SimpleNamespace(
            from_pretrained=lambda *_args, **_kwargs: Model()
        ),
        AutoTokenizer=SimpleNamespace(
            from_pretrained=lambda *_args, **_kwargs: Tokenizer()
        ),
    )
    fake_torch = SimpleNamespace(
        float16="float16",
        cuda=SimpleNamespace(
            is_available=lambda: True,
            empty_cache=lambda: events.append("cuda-empty"),
        ),
    )
    fake_nanogcg = SimpleNamespace(
        __version__="fixture",
        run=lambda *_args: events.append("optimization"),
    )
    modules = {
        "nanogcg": fake_nanogcg,
        "torch": fake_torch,
        "transformers": fake_transformers,
    }
    monkeypatch.setattr(
        nanogcg_module,
        "_require",
        lambda module, *_args: modules[module],
    )
    runtime = _RejectAfterConstruction(snapshot)
    attacker = NanoGCGAttacker(
        model_id="Org/Surrogate",
        model_revision=revision,
        model_runtime=runtime,
    )
    with pytest.raises(ModelAcquisitionError, match="post-verification"):
        list(
            attacker.generate(
                synth_corpus(1)[0],
                AttackBudget(max_queries=1, max_turns=1, seed=0),
            )
        )
    assert "optimization" not in events
    assert events == [
        "model-to-cuda",
        "model-eval",
        "tokenizer-close",
        "model-close",
        "model-to-cpu",
        "cuda-empty",
    ]
    assert attacker._model is None and attacker._tokenizer is None
