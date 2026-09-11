"""Regression coverage for explicit hosted-model execution conditions."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import run_matrix
from ura.data_models import DialogTurn
from ura.targets.api import (
    AnthropicTarget,
    GeminiTarget,
    OpenAICompatibleTarget,
    OpenAITarget,
    build_api_target,
    normalize_api_target_config,
)


def _write_config(path: Path, spec: str, value: dict[str, object]) -> Path:
    path.write_text(json.dumps({spec: value}), encoding="utf-8")
    return path


@pytest.mark.parametrize('model', ['deepseek-v4-pro', 'deepseek-v4-flash'])
@pytest.mark.parametrize('limit', [32768, 393216])
def test_deepseek_explicit_output_uses_documented_model_ceiling(tmp_path, model, limit):
    spec = 'deepseek:' + model
    config = {'modalities': ['text'], 'max_tokens': limit, 'temperature': None}
    path = _write_config(tmp_path / 'api.json', spec, config)
    normalized, _ = _load_config(path, [spec])
    target = build_api_target(spec, config=normalized[spec])
    assert target.build_request([DialogTurn(role='user', content='Hello')], seed=0)['max_tokens'] == limit
    with pytest.raises(ValueError, match='393216'):
        normalize_api_target_config(spec, {**config, 'max_tokens': 393217})
    assert normalize_api_target_config(spec, {**config, 'max_tokens': 4096})['max_tokens'] == 4096


def _load_config(
    path: Path, specs: list[str]
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    return run_matrix._load_api_config(
        str(path), specs, hashlib.sha256(path.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize('provider', ['openai', 'anthropic', 'google', 'kimi', 'deepseek'])
@pytest.mark.parametrize('limit', [32768, 65536])
def test_generic_api_output_has_no_invented_shared_ceiling(tmp_path, provider, limit):
    spec = provider + ':account-visible-output-model'
    config = {'modalities': ['text'], 'max_tokens': limit, 'temperature': None}
    path = _write_config(tmp_path / 'api.json', spec, config)
    normalized, _ = _load_config(path, [spec])
    target = build_api_target(spec, config=normalized[spec])
    assert target.max_tokens == limit
    request = target.build_request([DialogTurn(role='user', content='Hello')], seed=0)
    actual = request['config']['max_output_tokens'] if provider == 'google' else request['max_tokens']
    assert actual == limit
    assert normalize_api_target_config(spec, {**config, 'max_tokens': 4096})['max_tokens'] == 4096


@pytest.mark.parametrize('limit', [True, False, None, 0, -1, 32768.0, '32768'])
def test_generic_api_output_still_requires_positive_integer(limit):
    with pytest.raises(ValueError, match='positive integer'):
        normalize_api_target_config('openai:account-visible-output-model', {
            'modalities': ['text'], 'max_tokens': limit, 'temperature': None,
        })


@pytest.mark.parametrize('spec', ['deepseek:deepseek-v4-pro', 'openai:account-visible-output-model'])
def test_builder_preserves_explicit_large_api_output_allowance(tmp_path, spec):
    from experiments.rig_web import RigWebApp

    repo = tmp_path / 'repo'
    (repo / 'experiments').mkdir(parents=True)
    _write_config(repo / 'experiments/api-targets.json', spec, {
        'modalities': ['text'], 'max_tokens': 32768, 'temperature': None,
    })
    app = RigWebApp(repo_root=repo, results_root=tmp_path / 'runs',
        state_dir=tmp_path / 'state', gpu_hardware={}, system_hardware={})
    try:
        snapshot, _, _, configs = app._selected_api_config_snapshot({'api': spec, 'mode': 'measured'})
        assert configs[spec]['max_tokens'] == 32768
        assert snapshot['routes'][0]['config']['max_tokens'] == 32768
    finally:
        app.close()


def test_api_config_is_exact_normalized_and_constructs_declared_target(
    tmp_path: Path,
) -> None:
    spec = "qwen:qwen3.7-max-2026-06-08"
    path = _write_config(tmp_path / "api.json", spec, {
        "modalities": ["text", "image"],
        "base_url": "https://example.invalid/compatible/v1/",
        "max_tokens": 4096,
        "temperature": None,
    })

    loaded, artifact = _load_config(path, [spec])

    assert loaded == {spec: {
        "modalities": ["text", "image"],
        "base_url": "https://example.invalid/compatible/v1",
        "max_tokens": 4096,
        "temperature": None,
    }}
    assert artifact is not None
    assert artifact["file"] == path.name
    assert len(str(artifact["sha256"])) == 64
    assert artifact["normalized_selected_sha256"] == run_matrix._sha256_json(
        loaded
    )
    target = run_matrix.build_target(spec, api_config=loaded[spec])
    assert isinstance(target, OpenAICompatibleTarget)
    assert target.base_url == "https://example.invalid/compatible/v1"
    assert target.modality_support == ("text", "image")
    assert target.max_tokens == 4096
    assert target.temperature is None


def test_generic_measured_api_requires_exact_config_but_fixed_targets_do_not(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="require --api-config"):
        run_matrix._load_api_config("", ["openai:account-visible-model"])

    assert run_matrix._load_api_config("", ["claude-fable-5"]) == ({}, None)
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="missing selected generic"):
        _load_config(empty, ["openai:account-visible-model"])


def test_api_config_can_be_a_reusable_roster_superset(tmp_path: Path) -> None:
    selected = "openai:selected-model"
    config = {
        selected: {
            "modalities": ["text"], "max_tokens": 2048, "temperature": 0.0,
        },
        "google:other-lane": {
            "modalities": ["text", "image"],
            "max_tokens": 2048,
            "temperature": None,
        },
    }
    path = tmp_path / "roster.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    loaded, artifact = _load_config(path, [selected])

    assert set(loaded) == {selected}
    selected_identity = run_matrix._selected_config_artifact_identity(artifact)
    config["google:other-lane"]["max_tokens"] = 4096
    path.write_text(json.dumps(config), encoding="utf-8")
    loaded_after_unused_edit, artifact_after_unused_edit = (
        _load_config(path, [selected])
    )
    assert loaded_after_unused_edit == loaded
    assert run_matrix._selected_config_artifact_identity(
        artifact_after_unused_edit
    ) == selected_identity
    assert artifact_after_unused_edit["sha256"] != artifact["sha256"]

    config[selected]["max_tokens"] = 4096
    path.write_text(json.dumps(config), encoding="utf-8")
    _, artifact_after_selected_edit = _load_config(path, [selected])
    assert run_matrix._selected_config_artifact_identity(
        artifact_after_selected_edit
    ) != selected_identity


def test_private_api_config_digest_mismatch_unlinks_before_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "glm:tampered-private"
    directory = tmp_path / ".private-api-configs"
    directory.mkdir()
    path = directory / ("selected-api-" + "a" * 24 + "-" + "b" * 16 + ".json")
    first = {spec: {
        "modalities": ["text"], "max_tokens": 64, "temperature": 0.0,
        "base_url": "https://first.example/v1",
    }}
    path.write_text(json.dumps(first), encoding="utf-8")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_text(
        json.dumps({spec: {**first[spec], "max_tokens": 128}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("URA_PRIVATE_TRANSIENT_API_CONFIG", str(path))

    with pytest.raises(ValueError, match="does not match the read config bytes"):
        run_matrix._load_api_config(str(path), [spec], expected)
    assert not path.exists()


def test_private_local_config_digest_mismatch_unlinks_before_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "vllm:org/private-tamper"
    directory = tmp_path / ".private-local-configs"
    directory.mkdir()
    path = directory / ("selected-" + "a" * 24 + "-" + "b" * 16 + ".json")
    first = {spec: {
        "revision": "a" * 40,
        "modalities": ["text"],
        "tensor_parallel_size": 1,
    }}
    path.write_text(json.dumps(first), encoding="utf-8")
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_text(
        json.dumps({spec: {**first[spec], "revision": "b" * 40}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("URA_PRIVATE_TRANSIENT_LOCAL_CONFIG", str(path))

    with pytest.raises(ValueError, match="does not match the read config bytes"):
        run_matrix._load_local_config(
            str(path), [spec], expected_sha256=expected
        )
    assert not path.exists()


def test_selected_configs_reject_duplicate_json_keys_at_every_depth(
    tmp_path: Path,
) -> None:
    api_spec = "glm:duplicate-config"
    api_path = tmp_path / "duplicate-api.json"
    api_path.write_text(
        '{"glm:duplicate-config":{"modalities":["text"],'
        '"max_tokens":64,"max_tokens":128,"temperature":0.0,'
        '"base_url":"https://example.invalid/v1"}}',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON object key 'max_tokens'"):
        _load_config(api_path, [api_spec])

    local_spec = "vllm:org/duplicate-config"
    local_path = tmp_path / "duplicate-local.json"
    local_path.write_text(
        '{"vllm:org/duplicate-config":{"revision":"' + "a" * 40
        + '","modalities":["text"]},'
        '"vllm:org/duplicate-config":{"revision":"' + "b" * 40
        + '","modalities":["text"]}}',
        encoding="utf-8",
    )
    with pytest.raises(
        ValueError,
        match="duplicate JSON object key 'vllm:org/duplicate-config'",
    ):
        run_matrix._load_local_config(str(local_path), [local_spec])

    retained = tmp_path / "retained.json"
    retained.write_text('{"binding":"first","binding":"second"}', encoding="utf-8")
    digest = hashlib.sha256(retained.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="invalid --fixture JSON: duplicate JSON"):
        run_matrix._read_content_addressed_json(
            str(retained), digest, flag_name="--fixture", max_bytes=4096
        )


@pytest.mark.parametrize(
    ("spec", "config", "message"),
    [
        (
            "openai:fixture",
            {
                "modalities": ["text"],
                "base_url": "https://example.invalid/v1",
                "max_tokens": 100,
                "temperature": 0.0,
            },
            "only for compatible providers",
        ),
        (
            "qwen:fixture",
            {
                "modalities": ["text"],
                "base_url": "https://user:secret@example.invalid/v1",
                "max_tokens": 100,
                "temperature": 0.0,
            },
            "credential-free .*HTTPS",
        ),
        (
            "deepseek:fixture",
            {
                "modalities": ["text", "audio"],
                "max_tokens": 100,
                "temperature": 0.0,
            },
            "cannot serialize",
        ),
    ],
)
def test_api_config_rejects_unpersistable_or_unserializable_claims(
    tmp_path: Path,
    spec: str,
    config: dict[str, object],
    message: str,
) -> None:
    path = _write_config(tmp_path / "bad.json", spec, config)
    with pytest.raises(ValueError, match=message):
        _load_config(path, [spec])


def test_known_text_only_model_cannot_be_declared_image_capable() -> None:
    with pytest.raises(ValueError, match="overstates.*modalities"):
        normalize_api_target_config(
            "deepseek:deepseek-v4-pro",
            {
                "modalities": ["text", "image"],
                "max_tokens": 4096,
                "temperature": None,
            },
        )


def test_nullable_temperature_is_omitted_from_generic_provider_requests() -> None:
    dialog = [DialogTurn(role="user", content="request")]

    anthropic_request: dict[str, object] = {}
    anthropic = AnthropicTarget("claude-generic", temperature=None)
    anthropic._client = SimpleNamespace(messages=SimpleNamespace(
        create=lambda **kwargs: (
            anthropic_request.update(kwargs)
            or SimpleNamespace(
                id="msg-1",
                type="message",
                role="assistant",
                model="claude-generic-20260801",
                stop_reason="end_turn",
                stop_sequence=None,
                content=[SimpleNamespace(type="text", text="complete")],
                usage=SimpleNamespace(input_tokens=1, output_tokens=1),
            )
        )
    ))
    anthropic_response = anthropic.generate(dialog)
    assert "temperature" not in anthropic_request
    assert anthropic_response.raw["generation"]["temperature"] == "omitted"

    openai_request: dict[str, object] = {}
    openai = OpenAITarget("gpt-generic", temperature=None)
    openai._client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=lambda **kwargs: (
            openai_request.update(kwargs)
            or SimpleNamespace(
                id="chat-1",
                model="gpt-generic-20260801",
                system_fingerprint="fp-1",
                choices=[SimpleNamespace(
                    index=0,
                    finish_reason="stop",
                    message=SimpleNamespace(
                        role="assistant", content="complete", refusal=None
                    ),
                )],
                usage=SimpleNamespace(
                    prompt_tokens=1, completion_tokens=1, total_tokens=2
                ),
            )
        ))
    ))
    openai_response = openai.generate(dialog)
    assert "temperature" not in openai_request
    assert openai_response.raw["generation"]["temperature"] == "omitted"

    gemini_request: dict[str, object] = {}
    gemini = GeminiTarget("gemini-generic", temperature=None)
    gemini._client = SimpleNamespace(models=SimpleNamespace(
        generate_content=lambda **kwargs: (
            gemini_request.update(kwargs)
            or SimpleNamespace(
                response_id="gemini-1",
                model_version="gemini-generic-20260801",
                prompt_feedback=SimpleNamespace(
                    block_reason=None, block_reason_message=None
                ),
                candidates=[SimpleNamespace(
                    finish_reason="STOP",
                    finish_message=None,
                    safety_ratings=[],
                    content=SimpleNamespace(
                        role="model", parts=[SimpleNamespace(text="complete")]
                    ),
                )],
                usage_metadata=SimpleNamespace(
                    prompt_token_count=1,
                    candidates_token_count=1,
                    total_token_count=2,
                ),
            )
        )
    ))
    gemini_response = gemini.generate(dialog)
    assert "temperature" not in gemini_request["config"]
    assert gemini_response.raw["generation"]["temperature"] == "omitted"


def test_direct_builder_applies_declared_capabilities_to_unknown_exact_id() -> None:
    target = build_api_target("google:gemini-account-preview", config={
        "modalities": ["text", "image", "audio", "video"],
        "max_tokens": 2048,
        "temperature": 0.0,
    })

    assert isinstance(target, GeminiTarget)
    assert target.modality_support == ("text", "image", "audio", "video")
    assert target.modality_combinations == (
        ("text",),
        ("text", "image"),
        ("text", "audio"),
        ("text", "video"),
    )


def test_gemini_serializes_declared_audio_and_video_bytes() -> None:
    target = build_api_target("google:gemini-account-preview", config={
        "modalities": ["text", "image", "audio", "video"],
        "max_tokens": 2048,
        "temperature": None,
    })
    audio = b"RIFF\x04\x00\x00\x00WAVE"
    video = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42"

    def ref(modality: str, mime: str, payload: bytes):
        return {
            "modality": modality,
            "mime": mime,
            "uri": (
                f"data:{mime};base64," + base64.b64encode(payload).decode("ascii")
            ),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    _system, contents = target._to_contents([DialogTurn.model_validate({
        "role": "user",
        "content": "Inspect both inputs.",
        "media": [
            ref("audio", "audio/wav", audio),
            ref("video", "video/mp4", video),
        ],
    })])

    parts = contents[0]["parts"]
    assert parts[1]["inline_data"] == {
        "mime_type": "audio/wav", "data": audio,
    }
    assert parts[2]["inline_data"] == {
        "mime_type": "video/mp4", "data": video,
    }


def test_llm_judge_uses_the_same_explicit_api_condition() -> None:
    spec = "qwen:account-visible-judge"
    config = {
        "modalities": ["text"],
        "base_url": "https://example.invalid/compatible/v1",
        "max_tokens": 3072,
        "temperature": None,
    }

    cascade = run_matrix.build_judges(
        ["rules", "llm"],
        spec,
        judge_api_config=config,
    )

    judge_target = cascade.stages[1].judge_target
    assert isinstance(judge_target, OpenAICompatibleTarget)
    assert judge_target.name == spec
    assert judge_target.max_tokens == 3072
    assert judge_target.temperature is None
    assert judge_target.base_url == "https://example.invalid/compatible/v1"


@pytest.mark.parametrize("model", ["claude-opus-5", "claude-sonnet-5"])
@pytest.mark.parametrize("thinking", ["", "summary"])
def test_claude_5_config_preserves_adaptive_thinking_across_turns(
    model: str, thinking: str,
) -> None:
    spec = f"anthropic:{model}"
    target = build_api_target(spec, config={
        "modalities": ["text", "image"],
        "max_tokens": 4096,
        "temperature": None,
        "thinking": "adaptive",
        "effort": "medium",
    })
    assert isinstance(target, AnthropicTarget)
    request: dict[str, object] = {}
    target._client = SimpleNamespace(messages=SimpleNamespace(
        create=lambda **kwargs: (
            request.update(kwargs)
            or SimpleNamespace(
                id="msg-opus",
                type="message",
                role="assistant",
                model=model,
                stop_reason="end_turn",
                stop_sequence=None,
                content=[
                    SimpleNamespace(
                        type="thinking", thinking=thinking, signature="signed"
                    ),
                    SimpleNamespace(type="text", text="visible"),
                ],
                usage=SimpleNamespace(input_tokens=2, output_tokens=3),
            )
        )
    ))

    response = target.generate([DialogTurn(role="user", content="request")])

    assert request["thinking"] == {"type": "adaptive"}
    assert request["output_config"] == {"effort": "medium"}
    assert "temperature" not in request
    assert response.output_turns[0].provider_thinking == [{
        "type": "thinking", "thinking": thinking, "signature": "signed",
    }]
    _system, continuation = target._to_messages([
        response.output_turns[0], DialogTurn(role="user", content="follow up")
    ])
    assert continuation[0]["content"][0]["signature"] == "signed"
    assert continuation[0]["content"][0]["thinking"] == thinking


def test_claude_5_config_requires_explicit_adaptive_condition() -> None:
    with pytest.raises(ValueError, match="requires thinking='adaptive'"):
        build_api_target("anthropic:claude-sonnet-5", config={
            "modalities": ["text", "image"],
            "max_tokens": 4096,
            "temperature": None,
        })
