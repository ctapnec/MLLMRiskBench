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
from ura.runner import CODE_VERSION, Runner, _component_config
from ura.targets.local import (
    DEFAULT_OLLAMA_NUM_CTX,
    DEFAULT_OLLAMA_NUM_PREDICT,
    MAX_VLLM_MODEL_LEN,
    OllamaTarget,
    VLLMTarget,
)


SPEC = "vllm:Qwen/Qwen3-VL-8B-Instruct"
REVISION = "6" * 40


def test_local_context_contract_bumps_runner_version() -> None:
    assert CODE_VERSION == "ura-runner/2.24"


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


def test_absent_context_cap_keeps_native_vllm_behavior_and_identity(
    tmp_path: Path,
) -> None:
    path = _write_config(tmp_path, _config(include_context_cap=False))

    loaded, _artifact = run_matrix._load_local_config(
        str(path), [SPEC], hardware=_rig_hardware()
    )
    target = run_matrix.build_target(SPEC, local_identity=loaded[SPEC])
    target_config = _component_config(target)

    assert "max_model_len" not in loaded[SPEC]
    assert target.max_model_len is None
    assert "max_model_len" not in target_config

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

    native_manifest = manifest_for(target)
    capped_manifest = manifest_for(capped)
    assert native_manifest.run_id != capped_manifest.run_id
    assert "max_model_len" not in native_manifest.config["components"]["target"]
    assert capped_manifest.config["components"]["target"]["max_model_len"] == 15360


@pytest.mark.parametrize(
    "invalid",
    [None, False, True, 0, -1, 1.5, "15360", MAX_VLLM_MODEL_LEN + 1],
)
def test_local_config_rejects_invalid_context_caps_before_target_construction(
    tmp_path: Path, invalid: object
) -> None:
    config = _config()
    config["max_model_len"] = invalid
    path = _write_config(tmp_path, config)

    with pytest.raises(ValueError, match="max_model_len must be an integer"):
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


def test_vllm_engine_receives_only_explicit_context_cap(
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
            self.llm_engine = SimpleNamespace(engine_core=InprocClient())

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

    native = VLLMTarget(
        SPEC.split(":", 1)[1],
        revision=REVISION,
        modality_support=("text",),
        model_runtime=FakeRuntime(),
    )
    native_response = native.generate([DialogTurn(role="user", content="probe")])
    assert os.environ["VLLM_ENABLE_V1_MULTIPROCESSING"] == "operator-value"
    assert "max_model_len" not in engine_kwargs[1]
    assert "max_model_len" not in native_response.raw


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


def test_ollama_uses_the_same_nonblank_deterministic_attempt_placeholder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    target = OllamaTarget("fixture:latest", model_digest=digest)
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
    target = OllamaTarget("fixture:latest", model_digest=digest)
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
        }}),
        encoding="utf-8",
    )

    loaded, _artifact = run_matrix._load_local_config(str(path), [spec])
    assert loaded[spec]["num_ctx"] == 8192
    assert loaded[spec]["num_predict"] == 768
    target = run_matrix.build_target(spec, local_identity=loaded[spec])
    assert target._sampling_options() == {
        "temperature": 0.0,
        "num_ctx": 8192,
        "num_predict": 768,
    }

    default_path = tmp_path / "ollama-default-caps.json"
    default_path.write_text(
        json.dumps({spec: {"digest": "a" * 64, "modalities": ["text"]}}),
        encoding="utf-8",
    )
    defaults, _artifact = run_matrix._load_local_config(str(default_path), [spec])
    assert defaults[spec]["num_ctx"] == DEFAULT_OLLAMA_NUM_CTX
    assert defaults[spec]["num_predict"] == DEFAULT_OLLAMA_NUM_PREDICT


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("num_ctx", True, "num_ctx must be an integer"),
        ("num_ctx", 0, "num_ctx must be an integer"),
        ("num_predict", 0, "num_predict must be an integer"),
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
    (rig / "local-targets.example.json").write_text(
        json.dumps({spec: {
            "digest": "a" * 64,
            "modalities": ["text"],
            "num_ctx": 4096,
            "num_predict": 256,
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
    try:
        selected_path = app._materialize_selected_local_config([spec])
        selected = json.loads(selected_path.read_text(encoding="utf-8"))[spec]
        page = app.handle("GET", "/build")[2].decode("utf-8")
    finally:
        app.close()

    assert selected["num_ctx"] == 4096
    assert selected["num_predict"] == 256
    assert "context cap 4,096 tokens / output cap 256 tokens" in page


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

    assert "max_model_len must be an integer" in errors["models"]


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
