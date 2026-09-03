from __future__ import annotations

import builtins
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import run_matrix
from experiments.rig_web import RigWebApp
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.converters.synth import synth_corpus
from ura.data_models import Attempt, DialogTurn
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.model_acquisition_runtime import private_model_execution
from ura.runner import CODE_VERSION, Runner, _component_config
from ura.targets.base import TargetInputError
from ura.targets.local import (
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_OLLAMA_NUM_CTX,
    DEFAULT_OLLAMA_NUM_PREDICT,
    DEFAULT_VLLM_GENERATION_TOKENS,
    DEFAULT_VLLM_MAX_MODEL_LEN,
    MAX_VLLM_MODEL_LEN,
    LocalTargetAnswerError,
    OllamaTarget,
    VLLMTarget,
)


SPEC = "vllm:Qwen/Qwen3-VL-8B-Instruct"
REVISION = "6" * 40


def test_current_runner_version_includes_local_context_contract() -> None:
    assert CODE_VERSION == "ura-runner/2.31"
    assert DEFAULT_VLLM_GENERATION_TOKENS == 4096
    assert DEFAULT_VLLM_MAX_MODEL_LEN == -1
    assert DEFAULT_OLLAMA_NUM_CTX == "fit"
    assert DEFAULT_OLLAMA_NUM_PREDICT == 4096


def test_vllm_omitted_generation_cap_uses_finite_local_default(
    tmp_path: Path,
) -> None:
    config = _config(include_context_cap=False)
    config.pop("max_tokens")
    path = _write_config(tmp_path, config)

    loaded, _artifact = run_matrix._load_local_config(str(path), [SPEC])
    assert loaded[SPEC]["max_tokens"] == 4096
    target = run_matrix.build_target(SPEC, local_identity=loaded[SPEC])
    assert target.max_tokens == 4096
    assert target.timeout == DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS
    direct_identity = dict(loaded[SPEC])
    direct_target = run_matrix.build_target(SPEC, local_identity=direct_identity)
    assert direct_target.max_tokens == 4096
    assert VLLMTarget("fixture", revision=REVISION).max_tokens == 4096


def test_live_runner_requires_an_approved_local_execution_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "URA_LOCAL_MODEL_PROFILE_REGISTRY", str(tmp_path / "missing-profiles.json")
    )
    path = _write_config(tmp_path, _config())

    with pytest.raises(ValueError, match="no approved readiness profile"):
        run_matrix._load_local_config(
            str(path), [SPEC], require_execution_profiles=True
        )


def _rig_hardware() -> dict[str, object]:
    return {
        "available": True,
        "source": "test",
        "gpu_count": 2,
        "aggregate_vram_gib": 47.98,
        "max_gpu_vram_gib": 23.99,
        "gpus": [
            {
                "index": index,
                "compute_capability": "8.9",
                "memory_total_mib": 24564,
                "vram_gib": 23.99,
            }
            for index in range(2)
        ],
    }


def _config(*, include_context_cap: bool = True) -> dict[str, object]:
    config: dict[str, object] = {
        "revision": REVISION,
        "modalities": ["text", "image"],
        "tensor_parallel_size": 1,
        "gpu_memory_utilization": 0.90,
        "max_tokens": 4096,
    }
    if include_context_cap:
        config["max_model_len"] = 12288
    return config


def _write_config(
    tmp_path: Path, config: dict[str, object]
) -> Path:
    path = tmp_path / "local-targets.json"
    path.write_text(json.dumps({SPEC: config}), encoding="utf-8")
    return path


def _write_execution_profile(
    repo: Path,
    *,
    spec: str,
    config: dict[str, object],
    generation_tokens: int = 4096,
) -> None:
    identity_key = "revision" if "revision" in config else "digest"
    evidence = repo / "profile-readiness.json"
    evidence.write_text("{}\n", encoding="utf-8")
    registry = {
        "schema": "ura-local-model-execution-profiles/2",
        "models": {
            spec: {
                "generation_tokens": generation_tokens,
                "identity": {
                    identity_key: str(config[identity_key]).lower(),
                },
                "modalities": list(config["modalities"]),
                "readiness": {
                    "path": str(evidence.resolve()),
                    "sha256": "a" * 64,
                    "readiness_id": "b" * 64,
                },
                "request_timeout_seconds": 120.0,
            }
        },
    }
    (repo / "experiments" / "local-model-profiles.json").write_text(
        json.dumps(registry), encoding="utf-8"
    )


def test_qwen_context_cap_survives_loader_target_and_portable_identity(
    tmp_path: Path,
) -> None:
    path = _write_config(tmp_path, _config())

    loaded, artifact = run_matrix._load_local_config(
        str(path), [SPEC], hardware=_rig_hardware()
    )
    target = run_matrix.build_target(SPEC, local_identity=loaded[SPEC])
    target_config = _component_config(target)

    assert artifact is not None
    assert loaded[SPEC]["max_model_len"] == 12288
    assert loaded[SPEC]["max_tokens"] == 4096
    assert target.max_model_len == 12288
    assert target.max_tokens == 4096
    assert target.engine_core_execution_mode == "in_process"
    assert target_config["max_model_len"] == 12288
    assert target_config["max_tokens"] == 4096
    assert target_config["engine_core_execution_mode"] == "in_process"
    assert str(path.resolve()) not in json.dumps(target_config, sort_keys=True)


def test_absent_context_cap_binds_vllm_hardware_fit_behavior_and_identity(
    tmp_path: Path,
) -> None:
    path = _write_config(tmp_path, _config(include_context_cap=False))

    loaded, _artifact = run_matrix._load_local_config(
        str(path), [SPEC], hardware=_rig_hardware()
    )
    target = run_matrix.build_target(SPEC, local_identity=loaded[SPEC])
    target_config = _component_config(target)

    assert loaded[SPEC]["max_model_len"] == -1
    assert target.max_model_len == -1
    assert target_config["max_model_len"] == -1

    capped = VLLMTarget(
        SPEC.split(":", 1)[1],
        revision=REVISION,
        modality_support=("text", "image"),
        tensor_parallel_size=1,
        gpu_memory_utilization=0.90,
        max_tokens=4096,
        max_model_len=15360,
    )
    capped_config = _component_config(capped)
    assert capped_config == {**target_config, "max_model_len": 15360}

    def manifest_for(local_target: VLLMTarget):
        return Runner(
            ReplayAttacker(),
            local_target,
            JudgeCascade([RuleJudge()]),
            AttackBudget(max_queries=1, max_turns=1, seed=0),
            [0],
        ).plan_manifest(synth_corpus(1))

    fit_manifest = manifest_for(target)
    capped_manifest = manifest_for(capped)
    assert fit_manifest.run_id != capped_manifest.run_id
    assert fit_manifest.config["components"]["target"]["max_model_len"] == -1
    assert capped_manifest.config["components"]["target"]["max_model_len"] == 15360


@pytest.mark.parametrize(
    "invalid",
    [None, False, True, 0, -2, 1.5, "15360", MAX_VLLM_MODEL_LEN + 1],
)
def test_local_config_rejects_invalid_context_caps_before_target_construction(
    tmp_path: Path, invalid: object
) -> None:
    config = _config()
    config["max_model_len"] = invalid
    path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="max_model_len must be -1"):
        run_matrix._load_local_config(
            str(path), [SPEC], hardware=_rig_hardware()
        )


def test_local_config_rejects_non_string_modalities_without_crashing(
    tmp_path: Path,
) -> None:
    config = _config()
    config["modalities"] = [{}]
    path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="unique declared text"):
        run_matrix._load_local_config(
            str(path), [SPEC], hardware=_rig_hardware()
        )


def test_local_config_canonicalizes_uppercase_identity_hex(tmp_path: Path) -> None:
    config = _config()
    config["revision"] = "A" * 40
    path = _write_config(tmp_path, config)

    loaded, _artifact = run_matrix._load_local_config(
        str(path), [SPEC], hardware=_rig_hardware()
    )
    assert loaded[SPEC]["revision"] == "a" * 40


def test_context_cap_is_not_a_generation_limit_alias(tmp_path: Path) -> None:
    config = _config()
    config["max_tokens"] = 15361
    path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="max_tokens must not exceed max_model_len"):
        run_matrix._load_local_config(
            str(path), [SPEC], hardware=_rig_hardware()
        )
    with pytest.raises(ValueError, match="max_tokens must not exceed max_model_len"):
        VLLMTarget(
            SPEC.split(":", 1)[1],
            revision=REVISION,
            modality_support=("text", "image"),
            max_tokens=15361,
            max_model_len=15360,
        )


def test_vllm_engine_receives_explicit_or_hardware_fit_context_policy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    engine_kwargs: list[dict[str, object]] = []
    sampling_kwargs: list[dict[str, object]] = []
    snapshot = tmp_path / "managed-snapshot"
    snapshot.mkdir()

    class FakeRuntime:
        def construct(self, requirement, constructor, *, cleanup=None):
            del cleanup
            assert requirement.role == "vllm_target"
            assert os.environ["HF_HUB_OFFLINE"] == "1"
            assert os.environ["TRANSFORMERS_OFFLINE"] == "1"
            return constructor(snapshot.resolve())

        @staticmethod
        def private_execution(_role, callback):
            return callback()

    class FakeLLM:
        def __init__(self, **kwargs: object) -> None:
            assert os.environ["HF_HUB_OFFLINE"] == "1"
            assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "0"
            assert kwargs["model"] == str(snapshot.resolve())
            assert kwargs["tokenizer"] == str(snapshot.resolve())
            assert "revision" not in kwargs
            assert "tokenizer_revision" not in kwargs
            engine_kwargs.append(kwargs)
            requested = kwargs.get("max_model_len")
            resolved = 65_536 if requested == -1 else requested
            self.llm_engine = SimpleNamespace(
                engine_core=InprocClient(),
                model_config=SimpleNamespace(max_model_len=resolved),
            )

        def chat(self, _messages: object, _sampling: object) -> list[object]:
            completion = SimpleNamespace(
                text="bounded response",
                finish_reason="stop",
                stop_reason=None,
                token_ids=[2, 3],
            )
            return [SimpleNamespace(outputs=[completion], prompt_token_ids=[1])]

    class EngineCore:
        def shutdown(self) -> None:
            pass

    class InprocClient:
        def __init__(self) -> None:
            self.engine_core = EngineCore()

        def shutdown(self) -> None:
            self.engine_core.shutdown()

    class FakeSamplingParams:
        def __init__(self, **kwargs: object) -> None:
            sampling_kwargs.append(kwargs)

    monkeypatch.setitem(
        sys.modules,
        "vllm",
        SimpleNamespace(LLM=FakeLLM, SamplingParams=FakeSamplingParams),
    )
    real_import = builtins.__import__

    def offline_import(
        name: str,
        globals_: object = None,
        locals_: object = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ):
        if name == "vllm":
            assert os.environ["HF_HUB_OFFLINE"] == "1"
            assert os.environ["TRANSFORMERS_OFFLINE"] == "1"
            if "SamplingParams" not in fromlist:
                assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "0"
        return real_import(name, globals_, locals_, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", offline_import)
    for name in (
        "HF_DATASETS_OFFLINE",
        "HF_HUB_DISABLE_TELEMETRY",
        "HF_HUB_OFFLINE",
        "TRANSFORMERS_OFFLINE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VLLM_ENABLE_V1_MULTIPROCESSING", "operator-value")
    capped = VLLMTarget(
        SPEC.split(":", 1)[1],
        revision=REVISION,
        modality_support=("text", "image"),
        max_tokens=4096,
        max_model_len=15360,
        model_runtime=FakeRuntime(),
    )
    response = capped.generate([DialogTurn(role="user", content="probe")], seed=7)
    repeated = capped.generate([DialogTurn(role="user", content="probe")], seed=7)
    assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "operator-value"

    assert engine_kwargs[0]["max_model_len"] == 15360
    assert "max_tokens" not in engine_kwargs[0]
    assert sampling_kwargs[0]["max_tokens"] == 4096
    assert "max_model_len" not in sampling_kwargs[0]
    assert "stop" not in sampling_kwargs[0]
    assert "stop_token_ids" not in sampling_kwargs[0]
    assert "ignore_eos" not in sampling_kwargs[0]
    assert response.raw["max_model_len"] == 15360
    assert response.raw["requested_max_model_len"] == 15360
    assert response.raw["engine_core_execution_mode"] == "in_process"
    assert response.raw["generation"]["max_tokens"] == 4096
    assert response.attempt_id == repeated.attempt_id
    assert response.attempt_id.strip()

    runner = Runner(
        ReplayAttacker(),
        capped,
        JudgeCascade([RuleJudge()]),
        AttackBudget(max_queries=1, max_turns=1, seed=7),
        [7],
    )
    attempt = Attempt(
        id="canonical-attempt-id",
        datapoint_id="fixture-datapoint",
        attacker="replay",
        target=capped.name,
        rendered_input=[DialogTurn(role="user", content="probe")],
        seed=7,
        params={
            "attack_fingerprint": "attack-fixture",
            "transfer_key": "transfer-fixture",
            "transferable": True,
        },
    )
    linked = runner._respond(attempt, run_id="run-fixture")
    assert linked.attempt_id == attempt.id
    assert linked.run_id == "run-fixture"

    hardware_fit = VLLMTarget(
        SPEC.split(":", 1)[1],
        revision=REVISION,
        modality_support=("text",),
        model_runtime=FakeRuntime(),
    )
    fit_response = hardware_fit.generate(
        [DialogTurn(role="user", content="probe")]
    )
    assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "operator-value"
    assert engine_kwargs[1]["max_model_len"] == -1
    assert sampling_kwargs[-1]["max_tokens"] == 4096
    assert fit_response.raw["generation"]["max_tokens"] == 4096
    assert fit_response.raw["requested_max_model_len"] == -1
    assert fit_response.raw["max_model_len"] == 65_536
    assert fit_response.raw["max_model_len_policy"] == "hardware_fit"


def test_vllm_length_capped_nonempty_completion_is_retained() -> None:
    completion = SimpleNamespace(
        text="ear Bez " * 256,
        finish_reason="length",
        stop_reason=None,
        token_ids=[644, 22627] * 256,
    )
    outputs = [SimpleNamespace(outputs=[completion], prompt_token_ids=[1, 2, 3])]

    text, tokens, finish_reason, stop_reason = VLLMTarget._extract(outputs)

    assert text == completion.text
    assert tokens == {"prompt": 3, "completion": 512, "total": 515}
    assert finish_reason == "length"
    assert stop_reason is None


def test_vllm_successful_empty_completion_is_typed_model_nonresponse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeRuntime:
        @staticmethod
        def private_execution(_role: str, callback):
            return callback()

    class FakeSamplingParams:
        def __init__(self, **_kwargs: object) -> None:
            pass

    class EmptyLLM:
        @staticmethod
        def chat(_messages: object, _sampling: object) -> list[object]:
            completion = SimpleNamespace(
                text="",
                finish_reason="stop",
                stop_reason=None,
                token_ids=[],
            )
            return [SimpleNamespace(outputs=[completion], prompt_token_ids=[1, 2])]

    monkeypatch.setitem(
        sys.modules,
        "vllm",
        SimpleNamespace(SamplingParams=FakeSamplingParams),
    )
    target = VLLMTarget(
        SPEC.split(":", 1)[1],
        revision=REVISION,
        modality_support=("text",),
        model_runtime=FakeRuntime(),
    )
    monkeypatch.setattr(target, "_engine", lambda: EmptyLLM())

    response = target.generate([DialogTurn(role="user", content="probe")], seed=7)

    assert response.output_turns == []
    assert response.tokens == {"prompt": 2, "completion": 0, "total": 2}
    assert response.raw["backend"] == "vllm"
    assert response.raw["finish_reason"] == "stop"
    assert response.raw["empty_completion_observed"] is True


def test_vllm_context_rejection_survives_sealed_execution_as_typed_input(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private = tmp_path / "private-model-snapshot"

    class VLLMValidationError(ValueError):
        pass

    class FakeRuntime:
        @staticmethod
        def private_execution(role: str, callback):
            return private_model_execution(
                callback,
                role=role,
                private_values=(private,),
            )

    class FakeSamplingParams:
        def __init__(self, **_kwargs: object) -> None:
            pass

    class RejectingLLM:
        @staticmethod
        def chat(_messages: object, _sampling: object) -> list[object]:
            raise VLLMValidationError(
                "The decoder prompt (length 12290) is longer than the maximum "
                f"model length of 12288; private={private}"
            )

    monkeypatch.setitem(
        sys.modules,
        "vllm",
        SimpleNamespace(SamplingParams=FakeSamplingParams),
    )
    target = VLLMTarget(
        SPEC.split(":", 1)[1],
        revision=REVISION,
        modality_support=("text", "image"),
        max_model_len=12288,
        model_runtime=FakeRuntime(),
    )
    monkeypatch.setattr(target, "_engine", lambda: RejectingLLM())

    with pytest.raises(TargetInputError) as caught:
        target.generate([DialogTurn(role="user", content="probe")], seed=7)

    assert caught.value.category == "context_limit_exceeded"
    assert str(caught.value) == (
        "vLLM prompt length 12290 exceeds admitted context limit 12288"
    )
    assert str(private) not in str(caught.value)


def test_ollama_uses_the_same_nonblank_deterministic_attempt_placeholder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    target = OllamaTarget("fixture:latest", model_digest=digest, num_ctx=8192)
    monkeypatch.setattr(
        target, "_verify_daemon_identity", lambda *, deadline=None: digest
    )
    monkeypatch.setattr(
        target, "_verify_loaded_identity", lambda _model, *, deadline: digest
    )
    prestates = iter(("empty", "selected"))
    monkeypatch.setattr(
        target,
        "_verify_pre_generation_residency",
        lambda *, deadline: next(prestates),
    )
    monkeypatch.setattr(
        target,
        "_chat",
        lambda _messages, *, seed=None, deadline=None: {
            "model": "fixture:latest",
            "message": {"role": "assistant", "content": "local response"},
            "done": True,
            "done_reason": "length",
            "prompt_eval_count": 3,
            "eval_count": 2,
        },
    )
    dialog = [DialogTurn(role="user", content="probe")]

    first = target.generate(dialog, seed=7)
    second = target.generate(dialog, seed=7)

    def release(*, deadline: float) -> str:
        del deadline
        target._residency_owned = False
        return "unload"

    monkeypatch.setattr(target, "_release_owned_residency", release)
    target.close()

    assert first.attempt_id == second.attempt_id
    assert first.attempt_id.strip()
    assert first.output_turns[0].content == "local response"
    assert first.raw["done_reason"] == "length"


def test_ollama_retains_successful_empty_completion_as_typed_nonresponse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    target = OllamaTarget("fixture:latest", model_digest=digest, num_ctx=8192)
    monkeypatch.setattr(
        target, "_verify_daemon_identity", lambda *, deadline=None: digest
    )
    monkeypatch.setattr(
        target, "_verify_loaded_identity", lambda *_args, deadline=None: digest
    )
    monkeypatch.setattr(
        target, "_verify_pre_generation_residency", lambda *, deadline: "empty"
    )
    monkeypatch.setattr(
        target,
        "_chat",
        lambda _messages, *, seed=None, deadline=None: {
            "model": "fixture:latest",
            "message": {"role": "assistant", "content": ""},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 3,
            "eval_count": 0,
        },
    )

    response = target.generate([DialogTurn(role="user", content="probe")], seed=7)

    def release(*, deadline: float) -> str:
        del deadline
        target._residency_owned = False
        return "unload"

    monkeypatch.setattr(target, "_release_owned_residency", release)
    target.close()
    assert response.output_turns == []
    assert response.raw["empty_completion_observed"] is True
    assert response.raw["done_reason"] == "stop"


def test_ollama_disabled_thinking_rejects_daemon_policy_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    target = OllamaTarget(
        "fixture:latest", model_digest=digest, num_ctx=8192, think=False
    )
    monkeypatch.setattr(
        target, "_verify_daemon_identity", lambda *, deadline=None: digest
    )
    monkeypatch.setattr(
        target, "_verify_pre_generation_residency", lambda *, deadline: "empty"
    )
    monkeypatch.setattr(
        target,
        "_chat",
        lambda _messages, *, seed=None, deadline=None: {
            "model": "fixture:latest",
            "message": {
                "role": "assistant",
                "content": "",
                "thinking": "unexpected separate reasoning",
            },
            "done": True,
            "done_reason": "length",
        },
    )

    def release(*, deadline: float) -> str:
        del deadline
        target._residency_owned = False
        return "unload"

    monkeypatch.setattr(target, "_release_owned_residency", release)
    with pytest.raises(LocalTargetAnswerError) as caught:
        target.generate([DialogTurn(role="user", content="probe")], seed=7)

    assert caught.value.category == "thinking_control_mismatch"
    assert target._residency_owned is False


def test_ollama_config_forbids_vllm_context_cap(tmp_path: Path) -> None:
    spec = "ollama:fixture:latest"
    path = tmp_path / "ollama.json"
    path.write_text(
        json.dumps({spec: {
            "digest": "a" * 64,
            "modalities": ["text"],
            "max_model_len": 15360,
        }}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="forbids vLLM fields"):
        run_matrix._load_local_config(str(path), [spec])
    with pytest.raises(ValueError, match="vLLM-only option.*max_model_len"):
        OllamaTarget(
            "fixture:latest",
            model_digest="a" * 64,
            max_model_len=15360,
        )

    legitimate = OllamaTarget(
        "fixture:latest",
        model_digest="a" * 64,
        num_ctx=8192,
    )
    assert legitimate._sampling_options()["num_ctx"] == 8192


def test_ollama_local_config_binds_context_and_output_caps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "ollama:fixture:latest"
    from experiments.rig_web_app.ollama_service import OllamaService  # noqa: PLC0415

    monkeypatch.setattr(
        OllamaService,
        "roster",
        lambda _self, _entries, *, force=False: {
            "available": True,
            "models": [{
                "spec": spec,
                "digest": "a" * 64,
                "modalities": ["text"],
            }],
            "excluded": [],
            "issues": [],
        },
    )
    path = tmp_path / "ollama-caps.json"
    path.write_text(
        json.dumps({spec: {
            "digest": "a" * 64,
            "modalities": ["text"],
            "num_ctx": 8192,
            "num_predict": 768,
            "think": "low",
        }}),
        encoding="utf-8",
    )

    loaded, _artifact = run_matrix._load_local_config(str(path), [spec])
    assert loaded[spec]["num_ctx"] == 8192
    assert loaded[spec]["num_predict"] == 768
    assert loaded[spec]["think"] == "low"
    target = run_matrix.build_target(spec, local_identity=loaded[spec])
    assert target._sampling_options() == {
        "temperature": 0.0,
        "num_ctx": 8192,
        "num_predict": 768,
    }
    assert target.think == "low"

    default_path = tmp_path / "ollama-default-caps.json"
    default_path.write_text(
        json.dumps({spec: {"digest": "a" * 64, "modalities": ["text"]}}),
        encoding="utf-8",
    )
    defaults, _artifact = run_matrix._load_local_config(str(default_path), [spec])
    assert defaults[spec]["num_ctx"] == "fit"
    assert defaults[spec]["num_predict"] == DEFAULT_OLLAMA_NUM_PREDICT
    assert defaults[spec]["think"] is False
    default_target = run_matrix.build_target(spec, local_identity=defaults[spec])
    assert default_target.num_ctx == "fit"
    assert "num_ctx" not in default_target._sampling_options()
    assert default_target._sampling_options()["num_predict"] == 4096


def test_ollama_native_max_context_is_resolved_once_from_pinned_model_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = OllamaTarget(
        "fixture:latest",
        model_digest="a" * 64,
        num_ctx="max",
    )
    requests: list[str] = []

    def bounded(request, *, purpose: str, deadline: float):
        del deadline
        requests.append(request.full_url)
        assert purpose == "model context metadata"
        return {
            "model_info": {
                "general.architecture": "fixture",
                "fixture.context_length": 131_072,
            }
        }

    monkeypatch.setattr(target, "_bounded_json_request", bounded)

    assert target._resolve_num_ctx(deadline=1.0) == 131_072
    assert target._resolve_num_ctx(deadline=1.0) == 131_072
    assert requests == ["http://127.0.0.1:11434/api/show"]
    assert target._sampling_options() == {
        "temperature": 0.0,
        "num_ctx": 131_072,
        "num_predict": 4096,
    }


def test_ollama_hardware_fit_probes_down_to_largest_fully_gpu_resident_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = OllamaTarget("fixture:latest", model_digest="a" * 64)
    probes: list[int] = []
    unloads: list[int] = []

    def resolve_native(*, deadline: float) -> int:
        del deadline
        assert target.num_ctx == "max"
        return 131_072

    def preload(candidate: int, *, deadline: float) -> dict[str, int]:
        del deadline
        probes.append(candidate)
        target._residency_owned = True
        size = 55_000 if candidate == 131_072 else 38_000
        size_vram = 30_000 if candidate == 131_072 else size
        return {
            "size": size,
            "size_vram": size_vram,
            "context_length": candidate,
        }

    def unload(*, deadline: float) -> str:
        del deadline
        unloads.append(probes[-1])
        target._residency_owned = False
        return "unload"

    monkeypatch.setattr(target, "_resolve_num_ctx", resolve_native)
    monkeypatch.setattr(target, "_preload_context_candidate", preload)
    monkeypatch.setattr(target, "_release_owned_residency", unload)

    assert target._resolve_hardware_fit_context(deadline=1.0) == 65_536
    assert probes == [131_072, 65_536]
    assert unloads == [131_072]
    assert target._resolved_num_ctx == 65_536
    assert target._sampling_options()["num_ctx"] == 65_536
    assert target._hardware_fit_attempts == [
        {
            "context_length": 131_072,
            "size": 55_000,
            "size_vram": 30_000,
            "fully_gpu_resident": False,
        },
        {
            "context_length": 65_536,
            "size": 38_000,
            "size_vram": 38_000,
            "fully_gpu_resident": True,
        },
    ]


def test_ollama_hardware_fit_revalidates_cached_context_after_unload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = OllamaTarget("fixture:latest", model_digest="a" * 64)
    target._resolved_num_ctx = 65_536
    target._hardware_fit_attempts = [{
        "context_length": 131_072,
        "size": 55_000,
        "size_vram": 30_000,
        "fully_gpu_resident": False,
    }]
    calls: list[int] = []

    def preload(candidate: int, *, deadline: float) -> dict[str, int]:
        del deadline
        calls.append(candidate)
        target._residency_owned = True
        return {
            "size": 38_000,
            "size_vram": 38_000,
            "context_length": candidate,
        }

    monkeypatch.setattr(target, "_preload_context_candidate", preload)

    assert target._ensure_hardware_fit_context(
        residency_prestate="empty", deadline=1.0
    ) == 65_536
    assert calls == [65_536]
    assert target._hardware_fit_attempts == [{
        "context_length": 65_536,
        "size": 38_000,
        "size_vram": 38_000,
        "fully_gpu_resident": True,
    }]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("num_ctx", True, "num_ctx must be 'fit', 'max', or an integer"),
        ("num_ctx", 0, "num_ctx must be 'fit', 'max', or an integer"),
        ("num_ctx", "default", "num_ctx must be 'fit', 'max', or an integer"),
        ("num_predict", -2, "num_predict must be -1 or an integer"),
        ("num_predict", 0, "num_predict must be -1 or an integer"),
        ("think", "extreme", "think must be boolean"),
        ("timeout", 0, "timeout must be numeric"),
    ),
)
def test_ollama_local_config_rejects_invalid_execution_caps(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    spec = "ollama:fixture:latest"
    path = tmp_path / f"invalid-{field}.json"
    path.write_text(
        json.dumps({spec: {
            "digest": "a" * 64,
            "modalities": ["text"],
            field: value,
        }}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=message):
        run_matrix._load_local_config(str(path), [spec])


def test_rig_web_preserves_and_displays_curated_context_cap(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "local-targets.example.json").write_text(
        json.dumps({SPEC: _config()}), encoding="utf-8"
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8"
    )
    _write_execution_profile(repo, spec=SPEC, config=_config())
    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_rig_hardware(),
    )
    try:
        selected_path = app._materialize_selected_local_config([SPEC])
        selected = json.loads(selected_path.read_text(encoding="utf-8"))[SPEC]
        page = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()

    assert selected["max_model_len"] == 12288
    assert selected["max_tokens"] == 4096
    assert "context cap 12,288 tokens" in page


def test_rig_web_preserves_and_displays_ollama_execution_caps(
    tmp_path: Path,
) -> None:
    spec = "ollama:fixture:latest"
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    config = {
        "digest": "a" * 64,
        "modalities": ["text"],
        "num_ctx": 4096,
        "num_predict": 256,
    }
    (rig / "local-targets.example.json").write_text(
        json.dumps({spec: config}),
        encoding="utf-8",
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8"
    )
    _write_execution_profile(repo, spec=spec, config=config)
    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_rig_hardware(),
    )
    try:
        selected_path = app._materialize_selected_local_config([spec])
        selected = json.loads(selected_path.read_text(encoding="utf-8"))[spec]
        page = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()

    assert selected["num_ctx"] == 4096
    assert selected["num_predict"] == 4096
    assert selected["timeout"] == 120.0
    assert "context cap 4,096 tokens / output cap 4,096 tokens" in page


def test_rig_web_rejects_invalid_curated_context_cap(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    invalid = _config()
    invalid["max_model_len"] = True
    (rig / "local-targets.example.json").write_text(
        json.dumps({SPEC: invalid}), encoding="utf-8"
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8"
    )
    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_rig_hardware(),
    )
    params = {
        "mode": "measured",
        "local": SPEC,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
    }
    try:
        errors = app._validate_builder(params)
        with pytest.raises(ValueError, match="max_model_len"):
            app._materialize_selected_local_config([SPEC])
    finally:
        app.close()

    assert "max_model_len must be -1" in errors["models"]


def test_rig_web_rejects_ollama_vllm_context_cap_before_render_or_strip(
    tmp_path: Path,
) -> None:
    spec = "ollama:fixture:latest"
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "local-targets.example.json").write_text(
        json.dumps({spec: {
            "digest": "a" * 64,
            "modalities": ["text"],
            "max_model_len": 15360,
        }}),
        encoding="utf-8",
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8"
    )
    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_rig_hardware(),
    )
    params = {
        "mode": "measured",
        "local": spec,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
    }
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        errors = app._validate_builder(params)
        with pytest.raises(ValueError, match="Ollama config forbids vLLM fields"):
            app._materialize_selected_local_config([spec])
    finally:
        app.close()

    marker = f"data-model='{spec}'"
    at = page.index(marker)
    input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
    assert "disabled" in input_tag
    assert "invalid local config" in page
    assert "max_model_len" in page
    assert "context cap 15,360 tokens" not in page
    assert "Ollama config forbids vLLM fields" in errors["models"]


@pytest.mark.parametrize("invalid_max_tokens", [False, 0, 25_001])
def test_rig_web_matches_cli_generation_limit_validation(
    tmp_path: Path, invalid_max_tokens: object
) -> None:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    invalid = _config()
    invalid["max_tokens"] = invalid_max_tokens
    (rig / "local-targets.example.json").write_text(
        json.dumps({SPEC: invalid}), encoding="utf-8"
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8"
    )
    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=repo,
        gpu_hardware=_rig_hardware(),
    )
    params = {
        "mode": "measured",
        "local": SPEC,
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
    }
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        errors = app._validate_builder(params)
        with pytest.raises(ValueError, match="max_tokens must be an integer"):
            app._materialize_selected_local_config([SPEC])
    finally:
        app.close()

    marker = f"data-model='{SPEC}'"
    at = page.index(marker)
    input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
    assert "disabled" in input_tag
    assert "invalid local config" in page
    assert "max_tokens must be an integer" in errors["models"]
    with pytest.raises(ValueError, match="max_tokens must be an integer"):
        run_matrix._load_local_config(
            str(rig / "local-targets.example.json"),
            [SPEC],
            hardware=_rig_hardware(),
        )
    with pytest.raises(ValueError, match="max_tokens must be an integer"):
        VLLMTarget(
            SPEC.split(":", 1)[1],
            revision=REVISION,
            modality_support=("text", "image"),
            max_tokens=invalid_max_tokens,  # type: ignore[arg-type]
        )
