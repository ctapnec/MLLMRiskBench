from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import ura.adapters.nanogcg as nanogcg_module
from ura.adapters._engine_common import ExternalEngineOutputError
from ura.adapters.base import AttackBudget
from ura.adapters.nanogcg import NanoGCGAttacker
from ura.data_models import DataPoint, RiskCategory


def _datapoint() -> DataPoint:
    return DataPoint(
        id="nanogcg-dp",
        source="unit",
        modalities=["text"],
        payload_text="harmful request",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _budget() -> AttackBudget:
    return AttackBudget(max_queries=1, max_turns=1, seed=17)


def test_precomputed_suffix_is_explicit_replay_not_white_box() -> None:
    attempt = list(
        NanoGCGAttacker(
            suffix=" adversarial suffix",
            suffix_source="artifact:sha256:abc",
            model_revision="0123456789abcdef",
        ).generate(_datapoint(), _budget())
    )[0]

    assert attempt.params["attack_semantics"] == "precomputed_suffix_replay"
    assert attempt.params["suffix_source"] == "artifact:sha256:abc"
    assert attempt.params["losses"] == []
    assert attempt.strategy.startswith("gcg:precomputed_suffix_replay:")


def test_optimization_requires_pinned_surrogate_revision() -> None:
    with pytest.raises(ValueError, match="immutable model_revision"):
        list(NanoGCGAttacker().generate(_datapoint(), _budget()))


def test_optimization_preserves_resolved_model_and_full_trace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commit = "0123456789abcdef0123456789abcdef01234567"
    snapshot = tmp_path / "managed-snapshot"
    snapshot.mkdir()

    class FakeRuntime:
        def construct(self, requirement, constructor, *, cleanup=None):
            del cleanup
            assert requirement.repo_id == "surrogate/model"
            assert requirement.revision == commit
            assert requirement.role == "nanogcg_surrogate"
            assert os.environ["HF_HUB_OFFLINE"] == "1"
            assert os.environ["TRANSFORMERS_OFFLINE"] == "1"
            return constructor(snapshot.resolve())

        @staticmethod
        def private_execution(_role, callback):
            return callback()

    class FakeModel:
        config = SimpleNamespace(_commit_hash=commit)

        def to(self, device: str):
            assert device == "cuda"
            return self

        def eval(self) -> None:
            return None

    class FakeModelLoader:
        @staticmethod
        def from_pretrained(model_id: str, **kwargs):
            assert model_id == str(snapshot.resolve())
            assert kwargs["local_files_only"] is True
            assert "revision" not in kwargs
            return FakeModel()

    class FakeTokenizerLoader:
        @staticmethod
        def from_pretrained(model_id: str, **kwargs):
            assert model_id == str(snapshot.resolve())
            assert kwargs["local_files_only"] is True
            assert "revision" not in kwargs
            return SimpleNamespace(init_kwargs={"_commit_hash": commit})

    fake_transformers = SimpleNamespace(
        AutoModelForCausalLM=FakeModelLoader,
        AutoTokenizer=FakeTokenizerLoader,
    )
    fake_torch = SimpleNamespace(
        float16="float16",
        cuda=SimpleNamespace(is_available=lambda: True),
    )
    fake_nanogcg = SimpleNamespace(
        __version__="0.test",
        GCGConfig=lambda **kwargs: kwargs,
        run=lambda *_args: SimpleNamespace(
            best_string="suffix-b",
            best_loss=0.25,
            losses=[0.5, 0.25],
            strings=["suffix-a", "suffix-b"],
        ),
    )
    modules = {
        "nanogcg": fake_nanogcg,
        "transformers": fake_transformers,
        "torch": fake_torch,
    }
    monkeypatch.setattr(
        nanogcg_module, "_require", lambda module, *_args: modules[module]
    )
    for name in (
        "HF_DATASETS_OFFLINE",
        "HF_HUB_DISABLE_TELEMETRY",
        "HF_HUB_OFFLINE",
        "TRANSFORMERS_OFFLINE",
    ):
        monkeypatch.delenv(name, raising=False)

    attempt = list(
        NanoGCGAttacker(
            model_id="surrogate/model",
            model_revision=commit,
                num_steps=2,
                search_width=4,
                topk=2,
                model_runtime=FakeRuntime(),
            ).generate(_datapoint(), _budget())
    )[0]

    assert attempt.params["attack_semantics"] == "surrogate_transfer"
    assert attempt.params["resolved_surrogate_revision"] == commit
    assert attempt.params["nanogcg_version"] == "0.test"
    assert attempt.params["best_loss"] == 0.25
    assert attempt.params["losses"] == [0.5, 0.25]
    assert attempt.params["optimization_strings"] == ["suffix-a", "suffix-b"]


def test_malformed_optimization_trace_fails_closed() -> None:
    with pytest.raises(ExternalEngineOutputError, match="different lengths"):
        NanoGCGAttacker._validate_result(
            SimpleNamespace(
                best_string="suffix",
                best_loss=0.5,
                losses=[0.5],
                strings=["suffix", "extra"],
            )
        )
