"""Exact offline previews use the same body builders as paid generation."""

import base64
import hashlib
import json
from types import SimpleNamespace

import pytest

from ura.data_models import DialogTurn, MediaRef
from ura.targets import api


KINDS = ("haiku", "fable", "astra", "sol", "kimi")


def _target(kind, root):
    roots = [root]
    if kind == "haiku":
        return api.AnthropicTarget("claude-haiku-4-5-20251001", max_tokens=2048, media_roots=roots)
    if kind == "fable":
        return api.AnthropicFableTarget("claude-fable-5-1",
                                        requested_spec=api.AnthropicFableTarget.FABLE_51_SPEC,
                                        media_roots=roots)
    if kind == "astra":
        return api.OpenAITarget("gpt-6-astra", max_tokens=8192, media_roots=roots)
    if kind == "sol":
        return api.OpenAIResponsesTarget(requested_spec=api.OpenAIResponsesTarget.OUTPUT_8192_SPEC,
                                         media_roots=roots)
    return api.OpenAICompatibleTarget("kimi-k3", "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY",
                                      provider="kimi", max_tokens=8192, media_roots=roots,
                                      modality_support=("text", "image"), reasoning_effort="low")


def _dialog(root):
    data = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
    path = root / "pixel.png"
    path.write_bytes(data)
    media = MediaRef(modality="image", path=str(path), mime="image/png",
                     sha256=hashlib.sha256(data).hexdigest())
    return [DialogTurn(role="system", content="Preserve every instruction."),
            DialogTurn(role="user", content="Earlier question."),
            DialogTurn(role="assistant", content="Earlier answer."),
            DialogTurn(role="user", content="Now inspect this image.", media=[media])]


@pytest.mark.parametrize("kind", KINDS)
def test_preview_preserves_full_body_without_client_or_key(kind, tmp_path, monkeypatch):
    target = _target(kind, tmp_path)
    dialog = _dialog(tmp_path)
    before = [turn.model_dump(mode="json") for turn in dialog]

    def forbidden(*args, **kwargs):
        pytest.fail("preview constructed a client or imported an SDK")

    monkeypatch.setattr(target, "_get_client", forbidden)
    monkeypatch.setattr(api, "_require", forbidden)
    body = target.build_request(dialog, seed=0)
    assert target._client is None
    assert [turn.model_dump(mode="json") for turn in dialog] == before
    encoded = json.dumps(body)
    for text in ("Preserve every instruction.", "Earlier question.",
                 "Earlier answer.", "Now inspect this image."):
        assert text in encoded
    assert "iVBORw0KGgo" in encoded
    assert body["model"] == target.model
    token_key = "max_output_tokens" if kind == "sol" else (
        "max_completion_tokens" if kind == "astra" else "max_tokens")
    assert body[token_key] == target.max_tokens
    if kind == "fable":
        assert body["thinking"] == {"type": "adaptive"}
        assert body["output_config"] == {"effort": "high"}
        assert "temperature" not in body
    if kind == "sol":
        assert body["reasoning"] == {"mode": "pro", "effort": "medium", "context": "all_turns"}
        assert body["store"] is False
        assert body["truncation"] == "disabled"
    if kind == "kimi":
        assert body["reasoning_effort"] == "low"
        assert "seed" not in body


@pytest.mark.parametrize("kind", KINDS)
def test_generate_uses_exact_preview_builder_body(kind, tmp_path, monkeypatch):
    target = _target(kind, tmp_path)
    dialog = _dialog(tmp_path)
    expected = target.build_request(dialog, seed=0)
    expected["preview_test_marker"] = "same-builder"
    previews, delivered = [], []

    class CallObserved(BaseException):
        pass

    def build(observed, *, seed=None):
        assert observed is dialog and seed == 0
        previews.append(True)
        return expected

    def create(**body):
        delivered.append(body)
        raise CallObserved()

    endpoint = SimpleNamespace(create=create)
    client = SimpleNamespace(messages=endpoint, responses=endpoint,
                             chat=SimpleNamespace(completions=endpoint))
    monkeypatch.setattr(target, "build_request", build)
    monkeypatch.setattr(target, "_get_client", lambda: client)
    with pytest.raises(CallObserved):
        target.generate(dialog, seed=0)
    assert previews == [True]
    assert delivered == [expected]
