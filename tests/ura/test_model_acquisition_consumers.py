from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ura.adapters.nanogcg import LIVE_NANOGCG_DISABLED_MESSAGE, NanoGCGAttacker
from ura.judges.guardrail import GuardrailJudge
from ura.model_acquisition import ModelAcquisitionError
from ura.model_acquisition_runtime import (
    ManagedModelLoadError,
    private_model_execution,
)
from ura.runner import _component_config
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
    capsys: pytest.CaptureFixture[str],
) -> None:
    snapshot = (tmp_path / "checkpoint").resolve()
    snapshot.mkdir()
    weights = snapshot / "weights.bin"
    weights.write_bytes(b"sealed")
    digest = _tree_sha256(snapshot)
    events: list[str] = []

    class EngineCore:
        def shutdown(self) -> None:
            events.append("shutdown")
            print(f"shutdown-snapshot:{snapshot}")

    class InprocClient:
        def __init__(self) -> None:
            self.engine_core = EngineCore()

        def shutdown(self) -> None:
            self.engine_core.shutdown()

    class Engine:
        def __init__(self, **kwargs):
            assert kwargs["model"] == str(snapshot)
            assert kwargs["tokenizer"] == str(snapshot)
            assert os.environ["HF_HUB_OFFLINE"] == "1"
            weights.write_bytes(b"drift!")
            self.llm_engine = SimpleNamespace(engine_core=InprocClient())

        def __del__(self) -> None:
            print(f"rejected-engine-finalizer:{snapshot}")

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
    output = capsys.readouterr().out
    assert events == ["shutdown"]
    assert str(snapshot) not in output
    assert output.count("[managed-model-private]") >= 2
    assert target._llm is None


def test_vllm_postverify_failure_shutdowns_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    events: list[str] = []

    class EngineCore:
        def shutdown(self) -> None:
            events.append("shutdown")

    class InprocClient:
        def __init__(self) -> None:
            self.engine_core = EngineCore()

        def shutdown(self) -> None:
            self.engine_core.shutdown()

    class Engine:
        def __init__(self, **kwargs):
            assert kwargs["model"] == str(snapshot)
            assert kwargs["tokenizer"] == str(snapshot)
            self.llm_engine = SimpleNamespace(engine_core=InprocClient())

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


def test_vllm_construction_forces_in_process_mode_restores_env_and_keeps_tp2(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    events: list[object] = []

    class Runtime:
        def construct(self, _requirement, constructor, *, cleanup=None):
            assert cleanup is not None
            return constructor(snapshot)

        @staticmethod
        def private_execution(_role, callback):
            return callback()

    class EngineCore:
        def shutdown(self) -> None:
            events.append("engine-core-shutdown")

    class InprocClient:
        def __init__(self) -> None:
            self.engine_core = EngineCore()

        def shutdown(self) -> None:
            self.engine_core.shutdown()

    class LLM:
        def __init__(self, **kwargs: object) -> None:
            events.append(
                (
                    "construct",
                    os.environ.get("VLLM_ENABLE_V1_MULTIPROCESSING"),
                    kwargs["tensor_parallel_size"],
                )
            )
            self.llm_engine = SimpleNamespace(engine_core=InprocClient())

    monkeypatch.setitem(sys.modules, "vllm", SimpleNamespace(LLM=LLM))
    monkeypatch.setenv("VLLM_ENABLE_V1_MULTIPROCESSING", "1")
    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text", "image"),
        tensor_parallel_size=2,
        model_runtime=Runtime(),
    )

    target.preflight_base()

    assert events == [("construct", "0", 2)]
    assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "1"
    assert _component_config(target)["engine_core_execution_mode"] == "in_process"
    target.close()
    assert events[-1] == "engine-core-shutdown"


def test_vllm_construction_rejects_sync_mp_client_and_restores_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    events: list[str] = []

    class Runtime:
        def construct(self, _requirement, constructor, *, cleanup=None):
            assert cleanup is not None
            return constructor(snapshot)

        @staticmethod
        def private_execution(_role, callback):
            return callback()

    class SyncMPClient:
        output_queue_thread = object()
        engine_core = SimpleNamespace(shutdown=lambda: None)

        def shutdown(self) -> None:
            events.append("sync-mp-shutdown")

    class LLM:
        def __init__(self, **_kwargs: object) -> None:
            assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "0"
            self.llm_engine = SimpleNamespace(engine_core=SyncMPClient())

    monkeypatch.setitem(sys.modules, "vllm", SimpleNamespace(LLM=LLM))
    monkeypatch.delenv("VLLM_ENABLE_V1_MULTIPROCESSING", raising=False)
    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text", "image"),
        model_runtime=Runtime(),
    )

    with pytest.raises(RuntimeError, match="execution-mode admission"):
        target.preflight_base()

    assert events == ["sync-mp-shutdown"]
    assert "VLLM_ENABLE_V1_MULTIPROCESSING" not in os.environ
    assert target._llm is None


def test_vllm_rejects_configured_multiprocess_engine_core_mode() -> None:
    with pytest.raises(ValueError, match="supports only.*in_process"):
        VLLMTarget(
            "Org/Target",
            revision="a" * 40,
            modality_support=("text",),
            engine_core_execution_mode="multiprocess",
        )


def test_vllm_cached_engine_is_readmitted_before_reuse() -> None:
    class SyncMPClient:
        output_queue_thread = object()
        engine_core = SimpleNamespace(shutdown=lambda: None)

        @staticmethod
        def shutdown() -> None:
            pass

    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text",),
        model_runtime=object(),
    )
    target._llm = SimpleNamespace(
        llm_engine=SimpleNamespace(engine_core=SyncMPClient())
    )

    with pytest.raises(RuntimeError, match="required in-process EngineCore"):
        target._engine()

    target._llm = None


def test_vllm_close_reaches_v027_engine_core_and_is_idempotent() -> None:
    events: list[str] = []

    class Runtime:
        def private_execution(self, role, callback):
            events.append(f"private:{role}")
            return callback()

    class Core:
        def shutdown(self) -> None:
            events.append("engine-core-shutdown")

    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text",),
        model_runtime=Runtime(),
    )
    target._llm = SimpleNamespace(
        llm_engine=SimpleNamespace(engine_core=Core())
    )

    target.close()
    target.close()

    assert events == ["private:vllm_target", "engine-core-shutdown"]
    assert target._llm is None


def test_vllm_close_does_not_manually_join_or_destroy_third_party_zmq() -> None:
    events: list[str] = []

    class Runtime:
        def private_execution(self, role, callback):
            events.append(f"private:{role}")
            return callback()

    class OutputThread:
        def join(self, *, timeout: float) -> None:
            del timeout
            raise AssertionError("adapter must not join vLLM-owned threads")

        def is_alive(self) -> bool:
            raise AssertionError("adapter must not inspect vLLM-owned threads")

    class Context:
        def destroy(self, *, linger: int) -> None:
            del linger
            raise AssertionError("adapter must not destroy vLLM-owned contexts")

    class InprocClient:
        output_queue_thread = OutputThread()
        ctx = Context()

        def shutdown(self) -> None:
            events.append("official-inproc-shutdown")

    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text", "image"),
        model_runtime=Runtime(),
    )
    target._llm = SimpleNamespace(
        llm_engine=SimpleNamespace(engine_core=InprocClient())
    )

    target.close()

    assert events == ["private:vllm_target", "official-inproc-shutdown"]
    assert target._llm is None


def test_vllm_close_collects_destructor_inside_private_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_locator = (tmp_path / "operator-private" / "vllm-snapshot").resolve()

    class Runtime:
        def private_execution(self, role, callback):
            return private_model_execution(
                callback,
                role=role,
                private_values=(private_locator,),
            )

    class Engine:
        def shutdown(self) -> None:
            pass

        def __del__(self) -> None:
            print(f"engine-finalizer:{private_locator}")

    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text",),
        model_runtime=Runtime(),
    )
    target._llm = Engine()

    target.close()

    output = capsys.readouterr().out
    assert str(private_locator) not in output
    assert "engine-finalizer:[managed-model-private]" in output


def test_vllm_close_failure_drops_traceback_refs_inside_private_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_locator = (tmp_path / "operator-private" / "failed-vllm").resolve()

    class Runtime:
        def private_execution(self, role, callback):
            return private_model_execution(
                callback,
                role=role,
                private_values=(private_locator,),
            )

    class Engine:
        def shutdown(self) -> None:
            raise RuntimeError(f"third-party-shutdown-detail:{private_locator}")

        def __del__(self) -> None:
            print(f"failed-engine-finalizer:{private_locator}")

    target = VLLMTarget(
        "Org/Target",
        revision="a" * 40,
        modality_support=("text",),
        model_runtime=Runtime(),
    )
    target._llm = Engine()

    with pytest.raises(ManagedModelLoadError) as caught:
        target.close()

    output = capsys.readouterr().out
    assert str(private_locator) not in output
    assert "failed-engine-finalizer:[managed-model-private]" in output
    assert str(private_locator) not in str(caught.value)
    assert "third-party-shutdown-detail" not in str(caught.value)
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


def test_guardrail_close_releases_loaded_state_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class Runtime:
        def private_execution(self, role, callback):
            events.append(f"private:{role}")
            return callback()

    class Tokenizer:
        def close(self) -> None:
            events.append("tokenizer-close")

    class Model:
        def close(self) -> None:
            events.append("model-close")

        def to(self, device: str):
            events.append(f"model-to-{device}")
            return self

    fake_cuda = SimpleNamespace(
        is_available=lambda: True,
        empty_cache=lambda: events.append("cuda-empty"),
    )
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(cuda=fake_cuda))
    guard = GuardrailJudge(
        revision="b" * 40,
        device="cuda:1",
        model_runtime=Runtime(),
    )
    guard._tokenizer = Tokenizer()
    guard._model = Model()

    guard.close()
    guard.close()

    assert events == [
        "private:guardrail_judge",
        "tokenizer-close",
        "model-close",
        "model-to-cpu",
        "cuda-empty",
    ]
    assert guard._model is None and guard._tokenizer is None


def test_guardrail_close_collects_destructors_inside_private_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_locator = (tmp_path / "operator-private" / "guard-snapshot").resolve()

    class Runtime:
        def private_execution(self, role, callback):
            return private_model_execution(
                callback,
                role=role,
                private_values=(private_locator,),
            )

    class LeakyObject:
        def __init__(self, kind: str) -> None:
            self.kind = kind

        def __del__(self) -> None:
            print(f"{self.kind}-finalizer:{private_locator}")

    fake_cuda = SimpleNamespace(
        is_available=lambda: False,
        empty_cache=lambda: pytest.fail("CUDA cache must not be reached"),
    )
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(cuda=fake_cuda))
    guard = GuardrailJudge(
        revision="b" * 40,
        model_runtime=Runtime(),
    )
    guard._tokenizer = LeakyObject("tokenizer")
    guard._model = LeakyObject("model")

    guard.close()

    output = capsys.readouterr().out
    assert str(private_locator) not in output
    assert "tokenizer-finalizer:[managed-model-private]" in output
    assert "model-finalizer:[managed-model-private]" in output


def test_guardrail_close_contains_exceptional_lookup_and_finalizer_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_locator = (tmp_path / "operator-private" / "failed-guard").resolve()

    class Runtime:
        def private_execution(self, role, callback):
            return private_model_execution(
                callback,
                role=role,
                private_values=(private_locator,),
            )

    class ExceptionalObject:
        def __init__(self, kind: str) -> None:
            self.kind = kind

        def __getattribute__(self, name: str):
            if name in {"close", "to"}:
                raise RuntimeError(
                    f"third-party-lookup-detail:{private_locator}"
                )
            return object.__getattribute__(self, name)

        def __del__(self) -> None:
            print(f"{self.kind}-exceptional-finalizer:{private_locator}")

    fake_cuda = SimpleNamespace(
        is_available=lambda: False,
        empty_cache=lambda: pytest.fail("CUDA cache must not be reached"),
    )
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(cuda=fake_cuda))
    guard = GuardrailJudge(
        revision="b" * 40,
        model_runtime=Runtime(),
    )
    guard._tokenizer = ExceptionalObject("tokenizer")
    guard._model = ExceptionalObject("model")

    guard.close()

    output = capsys.readouterr().out
    assert str(private_locator) not in output
    assert "third-party-lookup-detail" not in output
    assert "tokenizer-exceptional-finalizer:[managed-model-private]" in output
    assert "model-exceptional-finalizer:[managed-model-private]" in output


def test_nanogcg_live_fails_before_snapshot_or_framework_construction() -> None:
    runtime = SimpleNamespace(construct=lambda *_args, **_kwargs: pytest.fail(
        "managed snapshot construction must not run before Stage 2 admission"
    ))
    with pytest.raises(RuntimeError, match=LIVE_NANOGCG_DISABLED_MESSAGE):
        NanoGCGAttacker(
            model_id="Org/Surrogate",
            model_revision="c" * 40,
            model_runtime=runtime,
        )
