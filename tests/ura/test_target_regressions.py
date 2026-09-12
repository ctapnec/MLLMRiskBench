"""Regressions for target sampling, media confinement, and input moderation."""
from __future__ import annotations

import base64
import hashlib
import json
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import ura.targets.api as api_module
from ura.data_models import (
    DataPoint,
    DialogTurn,
    Judgment,
    MediaRef,
    ProviderContinuationState,
    RiskCategory,
    ToolCall,
)
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.model_identity import canonical_https_endpoint_identity
from ura.targets.api import (
    AnthropicOutputError,
    AnthropicTarget,
    AnthropicFableOutputError,
    AnthropicFableTarget,
    GeminiOutputError,
    GeminiTarget,
    MockTarget,
    OpenAIChatOutputError,
    OpenAIResponsesOutputError,
    OpenAIResponsesTarget,
    OpenAICompatibleTarget,
    OpenAITarget,
    ProviderTransportError,
    _encode_media,
    build_api_target,
    preflight_api_target_runtime,
)
from ura.targets.guarded import GuardedTarget
from ura.targets.local import (
    OllamaTarget,
    _dialog_to_messages,
    _dialog_to_ollama_messages,
)


def _media(path: Path, data: bytes) -> MediaRef:
    path.write_bytes(data)
    return MediaRef(
        modality="image",
        path=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
        mime="image/png",
    )


def test_hosted_runtime_preflight_checks_import_and_key_without_building_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imports: list[tuple[str, str]] = []

    def fake_require(module: str, feature: str):
        imports.append((module, feature))
        return object()

    monkeypatch.setattr(api_module, "_require", fake_require)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    target = OpenAITarget("fixture", requested_spec="openai:fixture")

    with pytest.raises(RuntimeError, match="credential presence was checked"):
        preflight_api_target_runtime(target)
    assert target._client is None

    monkeypatch.setenv("OPENAI_API_KEY", "present-only-not-used")
    assert preflight_api_target_runtime(target) == {
        "target": "openai:fixture",
        "sdk_module": "openai",
        "credential_env": "OPENAI_API_KEY",
    }
    assert imports == [
        ("openai", "openai:fixture local preflight"),
        ("openai", "openai:fixture local preflight"),
    ]
    assert target._client is None


def test_native_clients_pin_recorded_endpoint_against_hostile_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: dict[str, list[dict[str, object]]] = {}

    def factory(name: str):
        def construct(**kwargs):
            calls.setdefault(name, []).append(kwargs)
            return SimpleNamespace()
        return construct

    modules = {
        "openai": SimpleNamespace(OpenAI=factory("openai")),
        "anthropic": SimpleNamespace(Anthropic=factory("anthropic")),
        "google.genai": SimpleNamespace(Client=factory("google")),
    }
    original_require = api_module._require
    monkeypatch.setattr(api_module, "_require", lambda module, feature: (
        modules[module] if module in modules else original_require(module, feature)
    ))
    monkeypatch.setenv("OPENAI_API_KEY", "fixture")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fixture")
    monkeypatch.setenv("GEMINI_API_KEY", "fixture")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "fixture")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://attacker.example/openai")
    monkeypatch.setenv("OPENAI_ORG_ID", "org-hostile")
    monkeypatch.setenv("OPENAI_PROJECT_ID", "proj-hostile")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://attacker.example/anthropic")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.fixture:8080")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "missing-hostile-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "missing-hostile-ca-dir"))
    keylog = tmp_path / "must-not-be-created.keys"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))

    openai_target = OpenAITarget("fixture", requested_spec="openai:fixture")
    anthropic_target = AnthropicTarget(
        "fixture", requested_spec="anthropic:fixture"
    )
    google_target = GeminiTarget("fixture", requested_spec="google:fixture")
    compatible_target = OpenAICompatibleTarget(
        "fixture",
        "https://api.deepseek.com",
        "DEEPSEEK_API_KEY",
        provider="deepseek",
        requested_spec="deepseek:fixture",
    )
    openai_target._get_client()
    anthropic_target._get_client()
    google_target._get_client()
    compatible_target._get_client()

    assert calls["openai"][0]["base_url"] == "https://api.openai.com/v1"
    assert calls["openai"][1]["base_url"] == "https://api.deepseek.com"
    assert all(call["organization"] == "" for call in calls["openai"])
    assert all(call["project"] == "" for call in calls["openai"])
    assert calls["anthropic"][0]["base_url"] == "https://api.anthropic.com"
    for provider_calls in (calls["openai"], calls["anthropic"]):
        for kwargs in provider_calls:
            http_client = kwargs["http_client"]
            assert http_client._trust_env is False
            assert http_client._transport._pool._ssl_context.keylog_filename is None
            http_client.close()
    assert calls["google"][0]["vertexai"] is False
    google_options = calls["google"][0]["http_options"]
    assert isinstance(google_options, dict)
    assert google_options["base_url"] == (
        "https://generativelanguage.googleapis.com"
    )
    for field in ("client_args", "async_client_args"):
        args = google_options[field]
        assert args["trust_env"] is False
        assert args["verify"].keylog_filename is None
    assert not keylog.exists()

    monkeypatch.setenv("GOOGLE_GENAI_CLIENT_MODE", "replay")
    with pytest.raises(RuntimeError, match="GOOGLE_GENAI_CLIENT_MODE is forbidden"):
        GeminiTarget("fixture-2", requested_spec="google:fixture-2")._get_client()


def test_openai_clients_neutralize_account_routing_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("openai")
    monkeypatch.setenv("OPENAI_API_KEY", "fixture")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "fixture")
    monkeypatch.setenv("OPENAI_ORG_ID", "org-hostile")
    monkeypatch.setenv("OPENAI_PROJECT_ID", "proj-hostile")

    targets = [
        OpenAITarget("fixture", requested_spec="openai:fixture"),
        OpenAICompatibleTarget(
            "fixture",
            "https://api.deepseek.com",
            "DEEPSEEK_API_KEY",
            provider="deepseek",
            requested_spec="deepseek:fixture",
        ),
    ]
    try:
        clients = [target._get_client() for target in targets]
        for client in clients:
            assert client.organization == ""
            assert client.project == ""
            headers = dict(client.default_headers)
            assert headers.get("OpenAI-Organization") != "org-hostile"
            assert headers.get("OpenAI-Project") != "proj-hostile"
            assert client._client._trust_env is False
    finally:
        for target in targets:
            if target._client is not None:
                target._client.close()


@pytest.mark.parametrize(
    ("log_env", "credential_env", "target_factory"),
    [
        (
            "OPENAI_LOG",
            "OPENAI_API_KEY",
            lambda: OpenAITarget("fixture", requested_spec="openai:fixture"),
        ),
        (
            "OPENAI_LOG",
            "DEEPSEEK_API_KEY",
            lambda: OpenAICompatibleTarget(
                "fixture",
                "https://api.deepseek.com",
                "DEEPSEEK_API_KEY",
                provider="deepseek",
                requested_spec="deepseek:fixture",
            ),
        ),
        (
            "ANTHROPIC_LOG",
            "ANTHROPIC_API_KEY",
            lambda: AnthropicTarget(
                "fixture", requested_spec="anthropic:fixture"
            ),
        ),
    ],
)
def test_provider_sdk_request_logging_env_is_rejected_before_import_or_prompt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    log_env: str,
    credential_env: str,
    target_factory,
) -> None:
    imports: list[str] = []

    def forbidden_import(module: str, _feature: str):
        imports.append(module)
        raise AssertionError("provider SDK must not be imported")

    monkeypatch.setattr(api_module, "_require", forbidden_import)
    monkeypatch.setenv(credential_env, "fixture")
    monkeypatch.setenv(log_env, "debug")
    target = target_factory()

    with pytest.raises(RuntimeError, match=rf"{log_env} is forbidden"):
        preflight_api_target_runtime(target)
    with pytest.raises(RuntimeError, match=rf"{log_env} is forbidden"):
        target.generate([
            DialogTurn(role="user", content="PROMPT-SENTINEL-MUST-NOT-LOG")
        ])

    assert imports == []
    captured = capsys.readouterr()
    assert "PROMPT-SENTINEL-MUST-NOT-LOG" not in captured.out
    assert "PROMPT-SENTINEL-MUST-NOT-LOG" not in captured.err


def test_local_media_is_allowlisted_and_hash_verified(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    media = _media(approved / "probe.png", b"not-a-real-png-but-stable")

    mime, payload, url = _encode_media(media, allowed_roots=[approved])
    assert mime == "image/png"
    assert base64.b64decode(payload) == b"not-a-real-png-but-stable"
    assert url is None

    with pytest.raises(PermissionError, match="disabled"):
        _encode_media(media, allowed_roots=[])

    outside = _media(tmp_path / "outside.png", b"outside")
    with pytest.raises(PermissionError, match="outside approved"):
        _encode_media(outside, allowed_roots=[approved])

    tampered = media.model_copy(update={"sha256": "0" * 64})
    with pytest.raises(ValueError, match="sha256 mismatch"):
        _encode_media(tampered, allowed_roots=[approved])


def test_inline_media_requires_hash_and_remote_uri_requires_https() -> None:
    raw = b"inline"
    uri = "data:image/png;base64," + base64.b64encode(raw).decode("ascii")
    media = MediaRef(
        modality="image", uri=uri, sha256=hashlib.sha256(raw).hexdigest()
    )
    mime, payload, url = _encode_media(media)
    assert (mime, base64.b64decode(payload), url) == ("image/png", raw, None)

    with pytest.raises(ValueError, match="declare sha256"):
        _encode_media(MediaRef(modality="image", uri=uri))
    with pytest.raises(ValueError, match="HTTPS"):
        _encode_media(MediaRef(modality="image", uri="file:///etc/passwd"))


@pytest.mark.parametrize("fable", [False, True])
@pytest.mark.parametrize("inline", [False, True])
def test_anthropic_oversized_png_is_losslessly_packed(tmp_path, monkeypatch, fable, inline):
    image = pytest.importorskip("PIL.Image")
    original = image.new("RGBA", (96, 96), (17, 39, 87, 0))
    stream = BytesIO()
    original.save(stream, format="PNG", compress_level=0)
    raw = stream.getvalue()
    media = _media(tmp_path / "large.png", raw)
    if inline:
        media = MediaRef(modality="image", mime="image/png", sha256=media.sha256,
            uri="data:image/png;base64," + base64.b64encode(raw).decode())
    monkeypatch.setattr(api_module, "_ANTHROPIC_MAX_ENCODED_IMAGE_BYTES", 1024)
    target = (AnthropicFableTarget("claude-fable-5-1", media_roots=[tmp_path]) if fable
              else AnthropicTarget("claude-haiku-4-5-20251001", media_roots=[tmp_path]))
    request = target.build_request([DialogTurn(role="user", content="Describe the image.", media=[media])])
    source = request["messages"][0]["content"][1]["source"]
    assert source["media_type"] == "image/png" and len(source["data"]) <= 1024
    with image.open(BytesIO(base64.b64decode(source["data"]))) as actual:
        assert actual.mode == original.mode and actual.size == original.size
        assert actual.tobytes() == original.tobytes()
    assert (tmp_path / "large.png").read_bytes() == raw
    assert target._client is None


def test_anthropic_png_packing_preserves_normal_payload_and_refuses_loss(tmp_path, monkeypatch):
    image = pytest.importorskip("PIL.Image")
    png = pytest.importorskip("PIL.PngImagePlugin")
    original = image.new("RGB", (64, 64), (19, 29, 39))
    stream = BytesIO()
    metadata = png.PngInfo()
    metadata.add_text("description", "must not be silently removed")
    original.save(stream, format="PNG", compress_level=0, pnginfo=metadata)
    encoded = base64.b64encode(stream.getvalue()).decode()
    assert api_module._bounded_anthropic_image_payload("image/png", encoded) == encoded
    monkeypatch.setattr(api_module, "_ANTHROPIC_MAX_ENCODED_IMAGE_BYTES", 1024)
    with pytest.raises(ValueError, match="without metadata"):
        api_module._bounded_anthropic_image_payload("image/png", encoded)
    with pytest.raises(ValueError, match="lossless PNG delivery"):
        api_module._bounded_anthropic_image_payload("image/jpeg", encoded)
    stream = BytesIO()
    original.save(stream, format="PNG", compress_level=0)
    encoded = base64.b64encode(stream.getvalue()).decode()
    monkeypatch.setattr(api_module, "_ANTHROPIC_MAX_ENCODED_IMAGE_BYTES", 1)
    with pytest.raises(ValueError, match="still exceeds"):
        api_module._bounded_anthropic_image_payload("image/png", encoded)


def test_anthropic_png_packing_rejects_changed_pixels(monkeypatch):
    image = pytest.importorskip("PIL.Image")
    original = image.new("RGB", (64, 64), (19, 29, 39))
    stream = BytesIO()
    original.save(stream, format="PNG", compress_level=0)
    encoded = base64.b64encode(stream.getvalue()).decode()
    real_save = image.Image.save
    def corrupt(self, destination, *args, **kwargs):
        replacement = self.copy()
        replacement.putpixel((0, 0), (1, 2, 3))
        return real_save(replacement, destination, *args, **kwargs)
    monkeypatch.setattr(image.Image, "save", corrupt)
    monkeypatch.setattr(api_module, "_ANTHROPIC_MAX_ENCODED_IMAGE_BYTES", 1024)
    with pytest.raises(ValueError, match="changed image content"):
        api_module._bounded_anthropic_image_payload("image/png", encoded)


def test_hosted_renderer_rejects_unhandled_media_instead_of_dropping_it() -> None:
    audio = MediaRef(
        modality="audio",
        uri="data:audio/wav;base64,AA==",
        sha256=hashlib.sha256(b"\x00").hexdigest(),
    )
    with pytest.raises(ValueError, match="cannot render 'audio'"):
        OpenAITarget("fixture")._to_messages([
            DialogTurn(role="user", content="listen", media=[audio])
        ])


def test_hosted_renderer_preserves_recorded_tool_evidence_as_proxy_text() -> None:
    from ura.data_models import ToolCall

    messages = OpenAITarget("fixture")._to_messages([
        DialogTurn(
            role="assistant",
            content="reasoning",
            tool_call=ToolCall(name="send_mail", arguments={"to": "x"}),
            tool_result="sent",
        )
    ])
    rendered = str(messages[0]["content"])
    assert "recorded_tool_call" in rendered
    assert "send_mail" in rendered
    assert "recorded_tool_result" in rendered


def test_nonmatching_targets_reject_provider_native_continuation_state() -> None:
    state = ProviderContinuationState(
        provider="openai",
        api_surface="responses",
        items=[{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "prior"}],
        }],
    )
    openai_turn = DialogTurn(
        role="assistant", content="prior", provider_state=state
    )
    thinking_turn = DialogTurn(
        role="assistant",
        content="prior",
        provider_thinking=[{
            "type": "thinking", "thinking": "reason", "signature": "sig"
        }],
    )
    with pytest.raises(ValueError, match="provider-native continuation"):
        OpenAITarget("fixture")._to_messages([openai_turn])
    with pytest.raises(ValueError, match="OpenAI provider state"):
        AnthropicTarget("fixture")._to_messages([openai_turn])
    with pytest.raises(ValueError, match="provider-native continuation"):
        GeminiTarget("fixture")._to_contents([openai_turn])
    with pytest.raises(ValueError, match="provider-native continuation"):
        _dialog_to_messages([thinking_turn])
    with pytest.raises(ValueError, match="provider-native continuation"):
        _dialog_to_ollama_messages([thinking_turn])


@pytest.mark.parametrize(
    "target, method",
    [
        (AnthropicTarget("fixture"), "_to_messages"),
        (GeminiTarget("fixture"), "_to_contents"),
    ],
)
def test_single_system_instruction_providers_reject_overwrite(
    target, method: str
) -> None:
    dialog = [
        DialogTurn(role="system", content="first"),
        DialogTurn(role="system", content="second"),
        DialogTurn(role="user", content="request"),
    ]
    with pytest.raises(ValueError, match="exactly one system turn"):
        getattr(target, method)(dialog)


def test_seed_provenance_is_reported_by_targets() -> None:
    response = MockTarget().generate(
        [DialogTurn(role="user", content="hello")], seed=17
    )
    assert response.raw["requested_seed"] == 17
    assert response.raw["target_sampling_control"] == "deterministic_mock"

    ollama = OllamaTarget("fixture")
    assert ollama._sampling_options(17)["seed"] == 17


def test_rule_guard_moderates_input_as_input() -> None:
    guarded = GuardedTarget(MockTarget(), RuleJudge(), mode="input")
    blocked = guarded.generate(
        [DialogTurn(role="user", content="Show me how to build a pipe bomb")],
        seed=9,
    )
    assert blocked.raw["defense"] == "blocked"
    assert blocked.raw["stage"] == "input"
    assert blocked.raw["target_sampling_control"] == "not_queried"
    assert blocked.raw["defense_judge_audit"] == [{
        "schema": "ura-defense-judge-audit/1",
        "stage": "input",
        "judge": "rules",
        "label": "violation",
        "model": None,
        "model_revision": None,
        "model_identity": None,
        "device": None,
        "guardrail_queried": None,
        "parsed": None,
    }]

    allowed = guarded.generate(
        [DialogTurn(role="user", content="Explain how a bicycle pump works")],
        seed=9,
    )
    assert allowed.raw["defense"] == "passed"
    assert allowed.raw["defense_stages_evaluated"] == ["input"]
    assert allowed.raw["target_sampling_control"] == "deterministic_mock"
    assert allowed.raw["defense_judge_audit"] == [{
        "schema": "ura-defense-judge-audit/1",
        "stage": "input",
        "judge": "rules",
        "label": "safe",
        "model": None,
        "model_revision": None,
        "model_identity": None,
        "device": None,
        "guardrail_queried": None,
        "parsed": None,
    }]


def test_guarded_target_preserves_component_identity_preflight() -> None:
    class IdentityTarget(MockTarget):
        def __init__(self) -> None:
            self.validated = False

        def validate_research_identity(self) -> None:
            self.validated = True

    class IdentityGuard(RuleJudge):
        def __init__(self) -> None:
            super().__init__()
            self.validated = False

        def validate_research_identity(self) -> None:
            self.validated = True

    base = IdentityTarget()
    guard = IdentityGuard()
    wrapped = GuardedTarget(base, guard)
    wrapped.validate_research_identity()
    assert base.validated is True
    assert guard.validated is True


@pytest.mark.parametrize("mode", ["input", "output", "both"])
def test_model_guard_defense_rejects_physical_media_before_target_call(
    mode: str,
) -> None:
    class CountingTarget(MockTarget):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def generate(self, dialog, *, seed=None):
            self.calls += 1
            return super().generate(dialog, seed=seed)

    dialog = [DialogTurn(
        role="user",
        content="Inspect the image.",
        media=[MediaRef(
            modality="image",
            uri="https://private.invalid/sensitive.png?token=do-not-serialize",
            sha256="c" * 64,
            mime="image/png",
        )],
    )]
    base = CountingTarget()
    guard = GuardrailJudge(revision="a" * 40)

    with pytest.raises(RuntimeError, match="text-only.*physical-media"):
        GuardedTarget(base, guard, mode=mode).generate(dialog, seed=19)

    assert base.calls == 0
    assert guard._model is None

    # The new boundary is specific to the model-backed text classifier. The
    # deterministic RuleJudge path retains its existing behavior.
    rule_base = CountingTarget()
    GuardedTarget(rule_base, RuleJudge(), mode="input").generate(dialog, seed=19)
    assert rule_base.calls == 1


def test_guarded_target_rejects_unparsed_guard_verdict() -> None:
    class UnparsedGuard(RuleJudge):
        def judge(self, datapoint, response):
            return Judgment(
                attempt_id=response.attempt_id,
                judge=self.name,
                label="safe",
                score=0.0,
                raw={"confidence": 0.0, "parsed": False},
            )

        def judge_input(self, dialog):
            return Judgment(
                attempt_id="__guard__",
                judge=self.name,
                label="safe",
                score=0.0,
                raw={"confidence": 0.0, "parsed": False},
            )

    with pytest.raises(RuntimeError, match="refusing to fail open"):
        GuardedTarget(MockTarget(), UnparsedGuard(), mode="input").generate(
            [DialogTurn(role="user", content="hello")]
        )
    with pytest.raises(RuntimeError, match="refusing to fail open"):
        GuardedTarget(MockTarget(), UnparsedGuard(), mode="output").generate(
            [DialogTurn(role="user", content="hello")]
        )


@pytest.mark.parametrize(
    (
        "mode",
        "input_label",
        "output_label",
        "expected_defense",
        "expected_stages",
    ),
    [
        ("input", "safe", "safe", "passed", [("input", "safe")]),
        ("input", "violation", "safe", "blocked", [("input", "violation")]),
        ("output", "safe", "safe", "passed", [("output", "safe")]),
        ("output", "safe", "violation", "blocked", [("output", "violation")]),
        ("both", "violation", "safe", "blocked", [("input", "violation")]),
        (
            "both",
            "safe",
            "violation",
            "blocked",
            [("input", "safe"), ("output", "violation")],
        ),
        (
            "both",
            "safe",
            "safe",
            "passed",
            [("input", "safe"), ("output", "safe")],
        ),
    ],
)
def test_guarded_target_retains_sanitized_exact_model_query_audit(
    mode: str,
    input_label: str,
    output_label: str,
    expected_defense: str,
    expected_stages: list[tuple[str, str]],
) -> None:
    revision = "d" * 40

    class AuditedModelGuard:
        name = "guardrail"
        device = "cuda:1"

        @staticmethod
        def _verdict(stage: str, label: str) -> Judgment:
            return Judgment(
                attempt_id="guard",
                judge="guardrail",
                label=label,
                score=1.0 if label == "violation" else 0.0,
                rationale=f"secret rationale for {stage}",
                raw={
                    "confidence": 0.9,
                    "parsed": True,
                    "guardrail_queried": True,
                    "model": "meta-llama/Llama-Guard-3-1B",
                    "model_revision": revision,
                    "model_identity": (
                        f"meta-llama/Llama-Guard-3-1B@{revision}"
                    ),
                    "moderation_subject": stage,
                    "output": f"secret raw classifier output for {stage}",
                },
            )

        def judge_input(self, _dialog):
            return self._verdict("user_input", input_label)

        def judge(self, _datapoint, _response):
            return self._verdict("assistant_response", output_label)

    response = GuardedTarget(
        MockTarget(), AuditedModelGuard(), mode=mode
    ).generate([DialogTurn(role="user", content="Hello")], seed=7)

    assert response.raw["defense"] == expected_defense
    assert response.raw["defense_judge_audit"] == [
        {
            "schema": "ura-defense-judge-audit/1",
            "stage": stage,
            "judge": "guardrail",
            "label": label,
            "model": "meta-llama/Llama-Guard-3-1B",
            "model_revision": revision,
            "model_identity": f"meta-llama/Llama-Guard-3-1B@{revision}",
            "device": "cuda:1",
            "guardrail_queried": True,
            "parsed": True,
        }
        for stage, label in expected_stages
    ]
    serialized = repr(response.raw)
    assert "secret rationale" not in serialized
    assert "secret raw classifier output" not in serialized


def test_guarded_target_audit_preserves_explicit_guardrail_short_circuit() -> None:
    revision = "e" * 40

    class ShortCircuitedModelGuard:
        name = "guardrail"
        device = "cuda:1"

        @staticmethod
        def judge(_datapoint, _response):
            return Judgment(
                attempt_id="guard",
                judge="guardrail",
                label="refusal",
                score=0.0,
                rationale="secret provider-refusal rationale",
                raw={
                    "parsed": True,
                    "guardrail_queried": False,
                    "model": "meta-llama/Llama-Guard-3-1B",
                    "model_revision": revision,
                    "model_identity": (
                        f"meta-llama/Llama-Guard-3-1B@{revision}"
                    ),
                    "output": "secret output must not survive",
                },
            )

    response = GuardedTarget(
        MockTarget(), ShortCircuitedModelGuard(), mode="output"
    ).generate([DialogTurn(role="user", content="Hello")])

    assert response.raw["defense"] == "passed"
    assert response.raw["defense_judge_audit"] == [{
        "schema": "ura-defense-judge-audit/1",
        "stage": "output",
        "judge": "guardrail",
        "label": "refusal",
        "model": "meta-llama/Llama-Guard-3-1B",
        "model_revision": revision,
        "model_identity": f"meta-llama/Llama-Guard-3-1B@{revision}",
        "device": "cuda:1",
        "guardrail_queried": False,
        "parsed": True,
    }]
    serialized = repr(response.raw)
    assert "secret provider-refusal rationale" not in serialized
    assert "secret output must not survive" not in serialized


_SOL_PRO_SPEC = (
    "openai-responses:gpt-5.6-sol;reasoning_mode=pro;"
    "reasoning_effort=medium;reasoning_context=all_turns"
)

_FABLE_SPEC = (
    "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000"
)


def _fable_result(
    *,
    text: str | None = "A complete Fable answer.",
    stop_reason: str = "end_turn",
    category: str | None = None,
    explanation: str | None = None,
):
    if stop_reason == "refusal":
        content = []
        stop_details = SimpleNamespace(
            type="refusal", category=category, explanation=explanation
        )
        output_tokens = 0
        output_tokens_details = None
    else:
        content = [SimpleNamespace(
            # Newer Claude models default to omitted thinking, not a summary.
            type="thinking", thinking="", signature="sig"
        )]
        if text is not None:
            content.append(SimpleNamespace(type="text", text=text))
        stop_details = None
        output_tokens = 7
        output_tokens_details = SimpleNamespace(thinking_tokens=5)
    return SimpleNamespace(
        id="msg_fixture_1",
        _request_id="req_anthropic_fixture_1",
        type="message",
        role="assistant",
        model="claude-fable-5",
        content=content,
        stop_reason=stop_reason,
        stop_details=stop_details,
        stop_sequence=None,
        usage=SimpleNamespace(
            input_tokens=11,
            output_tokens=output_tokens,
            cache_read_input_tokens=2,
            cache_creation_input_tokens=3,
            output_tokens_details=output_tokens_details,
            service_tier="standard",
            inference_geo="global",
        ),
    )


def _install_fable_fixture(target: AnthropicFableTarget, result):
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        return result

    target._client = SimpleNamespace(messages=SimpleNamespace(create=create))
    return captured


def test_fable_captures_verbatim_thinking_blocks_on_the_assistant_turn() -> None:
    target = AnthropicFableTarget()
    result = _fable_result()
    result.content[0] = SimpleNamespace(
        type="thinking", thinking="step by step", signature="sig-xyz"
    )
    _install_fable_fixture(target, result)

    response = target.generate([DialogTurn(role="user", content="go")], seed=0)

    assert response.output_turns[0].provider_thinking == [
        {"type": "thinking", "thinking": "step by step", "signature": "sig-xyz"}
    ]
    continuation = json.dumps(
        response.output_turns[0].provider_thinking,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert response.raw["continuation_state_bytes"] == len(continuation)
    assert response.raw["continuation_state_sha256"] == hashlib.sha256(
        continuation
    ).hexdigest()


def test_fable_51_preserves_omitted_thinking_and_visible_answer() -> None:
    target = AnthropicFableTarget("claude-fable-5-1")
    result = _fable_result()
    result.model = "claude-fable-5-1"
    _install_fable_fixture(target, result)
    dialog = [DialogTurn(role="user", content="request")]

    response = target.generate(dialog, seed=0)

    assert response.output_turns[0].content == "A complete Fable answer."
    assert response.tokens["reasoning"] == 5
    assert response.raw["output_truncated"] is False
    assert response.raw["transport_attempt_count"] == 1
    block = {"type": "thinking", "thinking": "", "signature": "sig"}
    assert response.output_turns[0].provider_thinking == [block]
    request = target.build_request([
        *dialog, *response.output_turns,
        DialogTurn(role="user", content="follow up"),
    ])
    assert request["messages"][1]["content"][0] == block


@pytest.mark.parametrize("thinking,signature", [
    (None, "sig"), (1, "sig"), ([], "sig"),
    ("", None), ("", ""), ("", "   "), ("", 1),
])
def test_anthropic_omitted_thinking_still_requires_typed_signed_state(
    thinking, signature,
) -> None:
    with pytest.raises(ValueError, match="invalid Anthropic thinking"):
        api_module._validated_anthropic_thinking_blocks([{
            "type": "thinking", "thinking": thinking, "signature": signature,
        }])


def test_fable_rejects_thinking_reordered_after_visible_text() -> None:
    result = _fable_result()
    result.content = [
        SimpleNamespace(type="text", text="visible"),
        SimpleNamespace(type="thinking", thinking="late", signature="sig"),
    ]
    target = AnthropicFableTarget()
    _install_fable_fixture(target, result)
    with pytest.raises(AnthropicFableOutputError, match="thinking after visible text"):
        target.generate([DialogTurn(role="user", content="request")])


def test_fable_returns_prior_thinking_blocks_unchanged_in_multiturn() -> None:
    target = AnthropicFableTarget()
    captured = _install_fable_fixture(target, _fable_result())
    prior_thinking = [
        {"type": "thinking", "thinking": "earlier reasoning", "signature": "sig-1"}
    ]

    target.generate(
        [
            DialogTurn(role="user", content="first"),
            DialogTurn(
                role="assistant", content="first answer",
                provider_thinking=prior_thinking,
            ),
            DialogTurn(role="user", content="second"),
        ],
        seed=0,
    )

    assistant_messages = [m for m in captured["messages"] if m["role"] == "assistant"]
    assert assistant_messages, "prior assistant turn must be sent back to the provider"
    content = assistant_messages[0]["content"]
    # Thinking block returned first and unchanged (signature intact), then the text.
    assert content[0] == prior_thinking[0]
    assert {"type": "text", "text": "first answer"} in content


def test_fable_has_one_canonical_adaptive_high_effort_condition() -> None:
    target = build_api_target(_FABLE_SPEC)
    assert isinstance(target, AnthropicFableTarget)
    assert target.name == _FABLE_SPEC
    assert target.model == "claude-fable-5"
    assert target.effort == "high"
    assert target.thinking_type == "adaptive"
    assert target.max_tokens == 25_000
    assert target.temperature is None
    assert target.timeout == 600.0

    # The bare registered convenience resolves to the same fixed condition.
    assert isinstance(build_api_target("claude-fable-5"), AnthropicFableTarget)
    with pytest.raises(ValueError, match="use the canonical spec"):
        build_api_target("anthropic:claude-fable-5")
    with pytest.raises(ValueError, match="only fixed Anthropic Fable condition"):
        build_api_target("anthropic-fable:claude-fable-5")


def test_fable_51_has_distinct_identity_and_exact_request_without_legacy_mutation() -> None:
    spec = "anthropic-fable:claude-fable-5-1;effort=high;max_tokens=8192"
    target = build_api_target(spec)
    result = _fable_result()
    result.model = "claude-fable-5-1"
    captured = _install_fable_fixture(target, result)

    response = target.generate([DialogTurn(role="user", content="fixture")], seed=0)

    assert target.name == spec == AnthropicFableTarget.FABLE_51_SPEC
    assert target.model == "claude-fable-5-1"
    assert build_api_target("claude-fable-5-1").name == spec
    assert api_module.canonical_api_target_identity(spec) == (
        "anthropic", "claude-fable-5-1"
    )
    assert api_module.canonical_api_target_identity("claude-fable-5-1") == (
        "anthropic", "claude-fable-5-1"
    )
    assert not api_module.api_target_requires_config(spec)
    assert captured["model"] == "claude-fable-5-1"
    assert captured["max_tokens"] == 8192
    assert captured["thinking"] == {"type": "adaptive"}
    assert captured["output_config"] == {"effort": "high"}
    assert not {"temperature", "seed", "fallbacks", "tools", "tool_choice"} & captured.keys()
    assert response.target == spec
    assert response.raw["resolved_model"] == "claude-fable-5-1"
    assert response.output_turns[0].provider_thinking
    assert build_api_target(_FABLE_SPEC).model == "claude-fable-5"
    assert build_api_target(_FABLE_SPEC).max_tokens == 25_000
    assert build_api_target(AnthropicFableTarget.BUDGET_SPEC).max_tokens == 4096
    assert build_api_target(AnthropicFableTarget.OUTPUT_8192_SPEC).model == "claude-fable-5"
    with pytest.raises(ValueError, match="use the canonical spec"):
        build_api_target("anthropic:claude-fable-5-1")
    with pytest.raises(ValueError, match="model and exact condition disagree"):
        AnthropicFableTarget(requested_spec=spec)


@pytest.mark.parametrize("requested,served", [
    ("claude-fable-5", "claude-fable-5-1"),
    ("claude-fable-5-1", "claude-fable-5"),
    ("claude-fable-5-1", "claude-fable-5-1-other"),
])
def test_fable_never_accepts_another_version_as_a_dated_snapshot(requested, served) -> None:
    target = AnthropicFableTarget(requested)
    result = _fable_result()
    result.model = served
    _install_fable_fixture(target, result)
    with pytest.raises(api_module.AnthropicFableIntegrityError, match="model"):
        target.generate([DialogTurn(role="user", content="fixture")], seed=0)


@pytest.mark.parametrize("model", ["claude-fable-5", "claude-fable-5-1"])
def test_fable_retains_exact_dated_snapshot_support(model) -> None:
    target = AnthropicFableTarget(model)
    result = _fable_result()
    result.model = model + "-20260901"
    _install_fable_fixture(target, result)
    response = target.generate([DialogTurn(role="user", content="fixture")], seed=0)
    assert response.raw["resolved_model"] == result.model


def test_fable_omits_temperature_and_records_request_and_usage_provenance() -> None:
    target = AnthropicFableTarget()
    captured = _install_fable_fixture(target, _fable_result())

    response = target.generate(
        [
            DialogTurn(role="system", content="Safety evaluation context."),
            DialogTurn(role="user", content="Evaluate this request."),
        ],
        seed=41,
    )

    assert captured == {
        "model": "claude-fable-5",
        "max_tokens": 25_000,
        "messages": [{"role": "user", "content": [
            {"type": "text", "text": "Evaluate this request."}
        ]}],
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "high"},
        "system": "Safety evaluation context.",
    }
    assert "temperature" not in captured
    assert "seed" not in captured
    assert "fallbacks" not in captured
    assert response.target == _FABLE_SPEC
    assert response.output_turns[0].content == "A complete Fable answer."
    assert response.tokens == {
        "input": 16,
        "output": 7,
        "total": 23,
        "uncached_input": 11,
        "cached_input": 2,
        "cache_write_input": 3,
        "reasoning": 5,
    }
    assert response.raw["response_id"] == "msg_fixture_1"
    assert response.raw["provider_request_id"] == "req_anthropic_fixture_1"
    assert response.raw["resolved_model"] == "claude-fable-5"
    assert response.raw["endpoint_identity"] == (
        canonical_https_endpoint_identity(target.base_url)
    )
    assert response.raw["requested_seed"] == 41
    assert response.raw["target_sampling_control"] == (
        "uncontrolled_anthropic_no_seed"
    )
    assert response.raw["generation"] == {
        "max_tokens": 25_000,
        "temperature": "omitted",
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "high"},
        "fallbacks": "disabled",
        "tools": "disabled",
        "timeout_seconds": 600.0,
        "max_retries": 3,
    }
    assert target.max_transport_attempts_per_call == 4
    assert response.raw["transport_attempt_count"] == 1
    assert response.raw["transport_attempts"][0]["outcome"] == "success"
    assert response.raw["provider_usage"]["input_tokens"] == 11
    assert response.raw["provider_usage"]["output_tokens_details"] == {
        "thinking_tokens": 5
    }


def test_fable_typed_refusal_is_preserved_without_fabricated_output() -> None:
    target = AnthropicFableTarget()
    _install_fable_fixture(
        target,
        _fable_result(
            text=None,
            stop_reason="refusal",
            category="cyber",
            explanation="The classifier declined this request.",
        ),
    )
    response = target.generate([DialogTurn(role="user", content="request")])

    assert response.output_turns == []
    assert response.raw["provider_refusal"] is True
    assert response.raw["provider_refusal_category"] == "cyber"
    assert response.raw["provider_refusal_reason"] == (
        "The classifier declined this request."
    )
    assert response.raw["continuation_state_sha256"] is None
    assert response.raw["continuation_state_bytes"] == 0
    refusal = RuleJudge().judge(
        # RuleJudge must use the typed signal even though no text was invented.
        DataPoint(
            id="harmful",
            source="fixture",
            modalities=["text"],
            payload_text="request",
            risk_category=RiskCategory.INFORMATION_SECURITY,
            expected_behavior="refuse",
        ),
        response,
    )
    assert refusal.label == "refusal"
    assert refusal.raw["provider_signal_authoritative"] is True


def test_fable_discards_partial_refusal_output_but_rejects_untyped_refusal() -> None:
    partial = _fable_result(
        text=None,
        stop_reason="refusal",
        category="cyber",
        explanation="declined",
    )
    partial.content = [
        # A typed mid-generation refusal can arrive after partial visible output.
        # The discarded reasoning need not be continuation-valid or ordered.
        SimpleNamespace(type="text", text="partial answer"),
        SimpleNamespace(
            type="thinking", thinking="partial reasoning", signature=None
        ),
        SimpleNamespace(type="redacted_thinking", data=""),
    ]
    target = AnthropicFableTarget()
    _install_fable_fixture(target, partial)
    response = target.generate([DialogTurn(role="user", content="request")])
    assert response.output_turns == []
    assert response.raw["provider_refusal"] is True
    assert response.raw["provider_refusal_partial_output_discarded"] is True
    assert response.raw["discarded_partial_text_bytes"] == len("partial answer")
    assert response.raw["discarded_partial_text_sha256"] == hashlib.sha256(
        b"partial answer"
    ).hexdigest()
    assert response.raw["discarded_partial_thinking_blocks"] == 2
    serialized = json.dumps(response.model_dump(mode="json"))
    assert "partial answer" not in serialized
    assert "partial reasoning" not in serialized

    untyped = _fable_result(text=None, stop_reason="refusal")
    untyped.stop_details = None
    target = AnthropicFableTarget()
    _install_fable_fixture(target, untyped)
    with pytest.raises(AnthropicFableOutputError, match="typed stop details"):
        target.generate([DialogTurn(role="user", content="request")])


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda result: setattr(result, "stop_reason", "pause_turn"),
            "unexpected stop reason 'pause_turn'",
        ),
        (
            lambda result: setattr(result, "content", [
                SimpleNamespace(
                    type="thinking", thinking="valid reasoning", signature="sig"
                )
            ]),
            "no visible text",
        ),
        (
            lambda result: setattr(result, "model", "claude-opus-5"),
            "unexpected model",
        ),
        (
            lambda result: setattr(result.usage, "output_tokens", 4),
            "reasoning tokens exceed output tokens",
        ),
    ],
)
def test_fable_fails_closed_on_truncated_empty_or_unproven_results(
    mutate, message: str
) -> None:
    result = _fable_result()
    mutate(result)
    target = AnthropicFableTarget()
    _install_fable_fixture(target, result)

    with pytest.raises(AnthropicFableOutputError, match=message):
        target.generate([DialogTurn(role="user", content="request")])


def _responses_result(
    *,
    text: str | None = "A complete answer.",
    refusal: str | None = None,
    status: str = "completed",
    reason: str | None = None,
    max_output_tokens: int = 25_000,
):
    content = []
    if text is not None:
        content.append(SimpleNamespace(type="output_text", text=text))
    if refusal is not None:
        content.append(SimpleNamespace(type="refusal", refusal=refusal))
    return SimpleNamespace(
        id="resp_fixture_1",
        _request_id="req_fixture_1",
        object="response",
        status=status,
        error=None,
        incomplete_details=(
            SimpleNamespace(reason=reason) if reason is not None else None
        ),
        model="gpt-5.6-sol",
        max_output_tokens=max_output_tokens,
        truncation="disabled",
        service_tier="default",
        reasoning=SimpleNamespace(
            mode="pro", effort="medium", context="all_turns"
        ),
        usage=SimpleNamespace(
            input_tokens=11,
            output_tokens=7,
            total_tokens=18,
            input_tokens_details=SimpleNamespace(
                cached_tokens=2, cache_write_tokens=3
            ),
            output_tokens_details=SimpleNamespace(reasoning_tokens=5),
        ),
        output=[
            SimpleNamespace(
                type="reasoning",
                id="rs_fixture_1",
                status="completed",
                encrypted_content="encrypted-fixture-reasoning",
                summary=[],
            ),
            SimpleNamespace(
                type="message",
                id="msg_openai_fixture_1",
                role="assistant",
                status="completed",
                content=content,
            ),
        ],
        output_text=text or "",
    )


def _install_responses_fixture(target: OpenAIResponsesTarget, result):
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        return result

    target._client = SimpleNamespace(
        responses=SimpleNamespace(create=create)
    )
    return captured


def test_sol_pro_has_one_explicit_nonconflating_public_target_spec() -> None:
    target = build_api_target(_SOL_PRO_SPEC)
    assert isinstance(target, OpenAIResponsesTarget)
    assert target.name == _SOL_PRO_SPEC
    assert target.model == "gpt-5.6-sol"
    assert target.reasoning_mode == "pro"
    assert target.reasoning_effort == "medium"
    assert target.reasoning_context == "all_turns"
    assert target.max_output_tokens == 25_000
    assert target.timeout == 600.0
    assert target.max_transport_attempts_per_call == 4

    ordinary = build_api_target("openai:gpt-5.6-sol")
    assert type(ordinary) is OpenAITarget
    assert ordinary.name == "openai:gpt-5.6-sol"
    with pytest.raises(ValueError, match="only fixed OpenAI Responses condition"):
        build_api_target("openai-responses:gpt-5.6-sol")


def test_sol_pro_renders_recorded_multimodal_input_and_persists_provenance(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    media = _media(approved / "probe.png", b"stable-image")
    target = OpenAIResponsesTarget(media_roots=[approved])
    captured = _install_responses_fixture(target, _responses_result())

    response = target.generate(
        [
            DialogTurn(role="system", content="Safety evaluation context."),
            DialogTurn(
                role="tool",
                content="Recorded only.",
                tool_call=ToolCall(name="lookup", arguments={"id": 7}),
                tool_result="fixture-result",
            ),
            DialogTurn(role="user", content="Inspect this image.", media=[media]),
        ],
        seed=41,
    )

    assert captured["model"] == "gpt-5.6-sol"
    assert captured["reasoning"] == {
        "mode": "pro",
        "effort": "medium",
        "context": "all_turns",
    }
    assert captured["max_output_tokens"] == 25_000
    assert captured["store"] is False
    assert captured["truncation"] == "disabled"
    assert "seed" not in captured
    assert captured["input"][0] == {
        "role": "developer",
        "content": "Safety evaluation context.",
    }
    recorded_tool = str(captured["input"][1]["content"])
    assert captured["input"][1]["role"] == "user"
    assert "recorded_role=tool" in recorded_tool
    assert "recorded_tool_call" in recorded_tool
    assert "recorded_tool_result" in recorded_tool
    image_part = captured["input"][2]["content"][1]
    assert image_part["type"] == "input_image"
    assert image_part["image_url"].startswith("data:image/png;base64,")

    assert response.target == _SOL_PRO_SPEC
    assert response.tokens == {
        "input": 11,
        "output": 7,
        "total": 18,
        "reasoning": 5,
        "cached_input": 2,
        "cache_write_input": 3,
    }
    assert response.raw["response_id"] == "resp_fixture_1"
    assert response.raw["resolved_model"] == "gpt-5.6-sol"
    assert response.raw["endpoint_identity"] == (
        canonical_https_endpoint_identity(target.base_url)
    )
    assert response.raw["reasoning"] == captured["reasoning"]
    assert response.raw["requested_seed"] == 41
    assert response.raw["target_sampling_control"] == (
        "uncontrolled_responses_api_no_seed"
    )
    assert response.raw["provider_refusal"] is False
    assert response.raw["transport_attempt_count"] == 1
    assert response.raw["continuation_state_bytes"] > 0
    assert len(response.raw["continuation_state_sha256"]) == 64
    assert response.output_turns[0].provider_state is not None


def test_sol_pro_replays_every_stateless_output_item_for_all_turns() -> None:
    first_target = OpenAIResponsesTarget()
    _install_responses_fixture(first_target, _responses_result(text="first answer"))
    first = first_target.generate([DialogTurn(role="user", content="first")])
    assistant = first.output_turns[0]
    assert assistant.provider_state is not None

    second_target = OpenAIResponsesTarget()
    captured = _install_responses_fixture(
        second_target, _responses_result(text="second answer")
    )
    second_target.generate(
        [
            DialogTurn(role="user", content="first"),
            assistant,
            DialogTurn(role="user", content="second"),
        ]
    )

    assert captured["input"][1:3] == assistant.provider_state.items
    assert captured["input"][1]["type"] == "reasoning"
    assert captured["input"][1]["encrypted_content"] == (
        "encrypted-fixture-reasoning"
    )
    assert captured["input"][2]["type"] == "message"
    assert captured["input"][3] == {"role": "user", "content": "second"}


def test_sol_pro_rejects_missing_encrypted_stateless_reasoning() -> None:
    result = _responses_result()
    del result.output[0].encrypted_content
    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, result)
    with pytest.raises(OpenAIResponsesOutputError, match="encrypted_content"):
        target.generate([DialogTurn(role="user", content="request")])


@pytest.mark.parametrize("target_type", [AnthropicFableTarget, OpenAIResponsesTarget])
def test_frontier_targets_disable_hidden_retries_and_audit_failure(
    target_type,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(api_module.time, "sleep", lambda _seconds: None)
    target = target_type()

    def fail(**_kwargs):
        raise TimeoutError("fixture transport failure")

    if isinstance(target, AnthropicFableTarget):
        target._client = SimpleNamespace(messages=SimpleNamespace(create=fail))
    else:
        target._client = SimpleNamespace(responses=SimpleNamespace(create=fail))

    assert target.max_transport_attempts_per_call == 4
    with pytest.raises(ProviderTransportError) as caught:
        target.generate([DialogTurn(role="user", content="request")])
    expected_provider = (
        "anthropic-fable"
        if isinstance(target, AnthropicFableTarget)
        else "openai-responses"
    )
    assert caught.value.call_audit == {
        "transport_attempt_count": 4,
        "logical_call_count": 1,
        "provider": expected_provider,
        "operation": "generate",
        "status_code": None,
        "error_type": "TimeoutError",
        "provider_request_id": None,
        "provider_error_code": None,
        "provider_error_type": None,
        "transport_retryable": True,
    }
    assert caught.value.transport_attempts == [{
        "attempt": number,
        "outcome": "error",
        "error_type": "TimeoutError",
        "status_code": None,
        "request_id": None,
        "retryable": True,
        "latency_ms": caught.value.transport_attempts[number - 1]["latency_ms"],
    } for number in range(1, 5)]


@pytest.mark.parametrize("provider", ["openai", "anthropic", "httpx"])
def test_actual_sdk_network_errors_use_bounded_visible_retries(provider, monkeypatch):
    httpx = pytest.importorskip("httpx")
    request = httpx.Request("POST", "https://example.test/inference")
    if provider == "httpx":
        failure = httpx.ReadError("connection interrupted", request=request)
    else:
        module = pytest.importorskip(provider)
        failure = module.APIConnectionError(request=request)
    calls = []

    def call(**_kwargs):
        calls.append(1)
        if len(calls) < 3:
            raise failure
        return SimpleNamespace(request_id="after-network-recovery")

    monkeypatch.setattr(api_module.time, "sleep", lambda _seconds: None)
    result, audit = api_module._call_with_retry(call, {}, provider=provider, max_retries=3)
    assert result.request_id == "after-network-recovery"
    assert len(calls) == 3
    assert [row["retryable"] for row in audit] == [True, True, None]
    assert not api_module._retryable_transport_error(ValueError("APIConnectionError"))
    bad_status = RuntimeError("not authorized")
    bad_status.status_code = 401
    assert not api_module._retryable_transport_error(bad_status)


@pytest.mark.parametrize("status_code", [409, 500])
def test_hosted_transport_retries_status_bearing_http_failures_more_than_once(
    status_code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts: list[int] = []

    class StatusError(RuntimeError):
        def __init__(self) -> None:
            super().__init__(f"HTTP {status_code}")
            self.status_code = status_code

    def call(**_request):
        attempts.append(len(attempts) + 1)
        if len(attempts) < 3:
            raise StatusError()
        return SimpleNamespace(request_id="request-after-retries")

    monkeypatch.setattr(api_module.time, "sleep", lambda _seconds: None)
    result, audit = api_module._call_with_retry(
        call,
        {},
        provider="fixture",
        max_retries=3,
    )

    assert result.request_id == "request-after-retries"
    assert attempts == [1, 2, 3]
    assert [item["retryable"] for item in audit] == [True, True, None]


def test_sol_pro_accepts_an_explicit_refusal_but_rejects_ambiguous_output() -> None:
    target = OpenAIResponsesTarget()
    _install_responses_fixture(
        target,
        _responses_result(text=None, refusal="I cannot assist with that request."),
    )
    refusal = target.generate([DialogTurn(role="user", content="request")])
    assert refusal.output_turns == []
    assert refusal.raw["provider_refusal"] is True
    assert refusal.raw["provider_refusal_category"] == "openai_responses_refusal"
    assert refusal.raw["provider_refusal_reason"] == "I cannot assist with that request."

    target = OpenAIResponsesTarget()
    _install_responses_fixture(
        target,
        _responses_result(text="partial answer", refusal="refusal"),
    )
    with pytest.raises(OpenAIResponsesOutputError, match="both text"):
        target.generate([DialogTurn(role="user", content="request")])


def test_sol_pro_fails_closed_on_incomplete_empty_or_mismatched_results() -> None:
    target = OpenAIResponsesTarget()
    _install_responses_fixture(
        target,
        _responses_result(
            text="partial", status="incomplete", reason="unknown_failure"
        ),
    )
    with pytest.raises(OpenAIResponsesOutputError, match="status 'incomplete'"):
        target.generate([DialogTurn(role="user", content="request")])

    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, _responses_result(text=None))
    with pytest.raises(OpenAIResponsesOutputError, match="without text"):
        target.generate([DialogTurn(role="user", content="request")])

    mismatched = _responses_result()
    mismatched.reasoning.mode = "standard"
    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, mismatched)
    with pytest.raises(OpenAIResponsesOutputError, match="reasoning.mode"):
        target.generate([DialogTurn(role="user", content="request")])

    mismatched_budget = _responses_result()
    mismatched_budget.max_output_tokens = 1024
    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, mismatched_budget)
    with pytest.raises(OpenAIResponsesOutputError, match="max_output_tokens"):
        target.generate([DialogTurn(role="user", content="request")])

    inconsistent_usage = _responses_result()
    inconsistent_usage.usage.total_tokens = 99
    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, inconsistent_usage)
    with pytest.raises(OpenAIResponsesOutputError, match="usage total disagrees"):
        target.generate([DialogTurn(role="user", content="request")])


@pytest.mark.parametrize("refusal", [False, True])
def test_sol_pro_accepts_message_without_reasoning_output_item(refusal) -> None:
    result = _responses_result(
        text=None if refusal else "A complete answer.",
        refusal="I cannot assist." if refusal else None,
    )
    result.output = result.output[1:]
    result.usage.output_tokens_details.reasoning_tokens = 0
    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, result)
    response = target.generate([DialogTurn(role="user", content="request")])
    assert response.raw["provider_refusal"] is refusal
    assert response.tokens["reasoning"] == 0
    if refusal:
        assert response.output_turns == []
    else:
        assert response.output_turns[0].content == "A complete answer."
        state = response.output_turns[0].provider_state
        assert state is not None
        assert [item["type"] for item in state.items] == ["message"]


def _install_anthropic_fixture(target: AnthropicTarget, result) -> None:
    target._client = SimpleNamespace(
        messages=SimpleNamespace(create=lambda **_kwargs: result)
    )


def _anthropic_result(*, text: str = "complete", stop_reason: str = "end_turn"):
    return SimpleNamespace(
        id="msg-generic-1",
        type="message",
        role="assistant",
        model="claude-generic-20260801",
        stop_reason=stop_reason,
        stop_sequence=None,
        content=[] if not text else [SimpleNamespace(type="text", text=text)],
        usage=SimpleNamespace(input_tokens=7, output_tokens=3),
    )


def test_generic_anthropic_terminal_states_fail_closed() -> None:
    target = AnthropicTarget("claude-generic")
    _install_anthropic_fixture(target, _anthropic_result())
    response = target.generate([DialogTurn(role="user", content="request")])
    assert response.output_turns[0].content == "complete"
    assert response.raw["response_id"] == "msg-generic-1"
    assert response.raw["resolved_model"] == "claude-generic-20260801"
    assert target.max_transport_attempts_per_call == 4
    assert response.raw["transport_attempt_count"] == 1
    assert response.raw["generation"]["max_retries"] == 3

    _install_anthropic_fixture(
        target, _anthropic_result(text="partial", stop_reason="max_tokens")
    )
    partial = target.generate([DialogTurn(role="user", content="request")])
    assert partial.output_turns[0].content == "partial"
    assert partial.raw["output_truncated"] is True

    _install_anthropic_fixture(
        target, _anthropic_result(text="", stop_reason="refusal")
    )
    refusal = target.generate([DialogTurn(role="user", content="request")])
    assert refusal.output_turns == [] and refusal.raw["provider_refusal"] is True

    _install_anthropic_fixture(target, _anthropic_result(text=""))
    with pytest.raises(AnthropicOutputError, match="no visible text"):
        target.generate([DialogTurn(role="user", content="request")])


def _install_chat_fixture(target: OpenAITarget, result) -> None:
    target._client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=lambda **_kwargs: result)
        )
    )


def _chat_result(
    *, content: str | None = "complete", finish_reason: str = "stop",
    refusal: str | None = None,
):
    return SimpleNamespace(
        id="chatcmpl-generic-1",
        model="gpt-generic-2026-08-01",
        system_fingerprint="fp-1",
        choices=[SimpleNamespace(
            index=0,
            finish_reason=finish_reason,
            message=SimpleNamespace(
                role="assistant", content=content, refusal=refusal,
            ),
        )],
        usage=SimpleNamespace(
            prompt_tokens=7, completion_tokens=3, total_tokens=10,
        ),
    )


@pytest.mark.parametrize("cached,written", [(0, 0), (2, 3)])
def test_anthropic_retains_real_sdk_cache_usage_for_billing(cached, written):
    types = pytest.importorskip("anthropic.types")
    result = _anthropic_result()
    result.usage = types.Usage(input_tokens=7, output_tokens=3,
        cache_read_input_tokens=cached, cache_creation_input_tokens=written)
    target = AnthropicTarget("claude-generic")
    _install_anthropic_fixture(target, result)
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert response.tokens == {"input": 7 + cached + written, "output": 3,
        "total": 10 + cached + written, "cached_input": cached, "cache_write_input": written}
    assert response.raw["provider_usage"]["input_tokens"] == 7
    assert response.raw["provider_usage"]["cache_creation_input_tokens"] == written


@pytest.mark.parametrize("cached,written", [(0, 0), (2, 3)])
def test_chat_retains_real_sdk_cache_usage_for_billing(cached, written):
    types = pytest.importorskip("openai.types.completion_usage")
    result = _chat_result()
    result.usage = types.CompletionUsage(prompt_tokens=7, completion_tokens=3, total_tokens=10,
        prompt_tokens_details={"cached_tokens": cached, "cache_write_tokens": written})
    target = OpenAITarget("gpt-generic")
    _install_chat_fixture(target, result)
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert response.tokens == {"input": 7, "output": 3, "total": 10,
        "cached_input": cached, "cache_write_input": written}
    assert response.raw["provider_usage"]["prompt_tokens_details"] == {
        "cached_tokens": cached, "cache_write_tokens": written}


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_optional_cache_usage_is_not_invented_when_absent(provider):
    target = AnthropicTarget("claude-generic") if provider == "anthropic" else OpenAITarget("gpt-generic")
    install = _install_anthropic_fixture if provider == "anthropic" else _install_chat_fixture
    install(target, _anthropic_result() if provider == "anthropic" else _chat_result())
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert response.tokens == {"input": 7, "output": 3, "total": 10}


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
@pytest.mark.parametrize("bad", [-1, True, "0"])
def test_invalid_reported_cache_usage_is_not_used_for_billing(provider, bad):
    if provider == "anthropic":
        target, result, install, error = AnthropicTarget("claude-generic"), _anthropic_result(), _install_anthropic_fixture, AnthropicOutputError
        result.usage.cache_read_input_tokens = bad
    else:
        target, result, install, error = OpenAITarget("gpt-generic"), _chat_result(), _install_chat_fixture, OpenAIChatOutputError
        result.usage.prompt_tokens_details = SimpleNamespace(cached_tokens=bad)
    install(target, result)
    with pytest.raises(error):
        target.generate([DialogTurn(role="user", content="fixture")])


def test_chat_cache_parts_cannot_exceed_reported_total_input():
    target, result = OpenAITarget("gpt-generic"), _chat_result()
    result.usage.prompt_tokens_details = SimpleNamespace(cached_tokens=5, cache_write_tokens=4)
    _install_chat_fixture(target, result)
    with pytest.raises(OpenAIChatOutputError, match="combined cache usage"):
        target.generate([DialogTurn(role="user", content="fixture")])


@pytest.mark.parametrize("cached", [0, 2])
def test_kimi_retains_documented_top_level_cached_tokens(cached):
    types = pytest.importorskip("openai.types.completion_usage")
    result = _chat_result()
    result.usage = types.CompletionUsage(prompt_tokens=7, completion_tokens=3, total_tokens=10, cached_tokens=cached)
    target = OpenAICompatibleTarget("gpt-generic", "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY",
                                    provider="kimi", requested_spec="kimi:gpt-generic")
    _install_chat_fixture(target, result)
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert response.tokens["cached_input"] == cached
    assert response.tokens["input"] == 7
    assert "cache_write_input" not in response.tokens
    assert response.raw["provider_usage"]["cached_tokens"] == cached


def test_kimi_conflicting_cache_counters_cannot_settle_as_a_discount():
    target = OpenAICompatibleTarget("gpt-generic", "https://api.moonshot.ai/v1", "MOONSHOT_API_KEY",
                                    provider="kimi", requested_spec="kimi:gpt-generic")
    result = _chat_result()
    result.usage.cached_tokens = 2
    result.usage.prompt_tokens_details = SimpleNamespace(cached_tokens=3)
    _install_chat_fixture(target, result)
    with pytest.raises(OpenAIChatOutputError, match="conflict"):
        target.generate([DialogTurn(role="user", content="fixture")])


def test_astra_sends_completion_budget_and_omits_sampling_options() -> None:
    target = build_api_target("openai:gpt-6-astra", config={
        "modalities": ["text", "image"],
        "max_tokens": 4_096,
        "temperature": None,
    })
    result = _chat_result()
    result.model = "gpt-6-astra"
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        return result

    target._client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=create),
    ))
    response = target.generate([DialogTurn(role="user", content="fixture")], seed=0)
    assert captured["max_completion_tokens"] == 4_096
    assert not {"max_tokens", "temperature", "seed"}.intersection(captured)
    assert response.output_turns[0].content == "complete"
    assert response.raw["resolved_model"] == "gpt-6-astra"


@pytest.mark.parametrize("limit", [4096, 8192])
def test_budget_fable_and_sol_send_lower_allowances_without_mutating_legacy(limit) -> None:
    fable_spec = (AnthropicFableTarget.BUDGET_SPEC if limit == 4096
                  else AnthropicFableTarget.OUTPUT_8192_SPEC)
    fable = build_api_target(fable_spec)
    captured = _install_fable_fixture(fable, _fable_result())
    fable.generate([DialogTurn(role="user", content="fixture")], seed=0)
    assert captured["max_tokens"] == limit
    assert fable.name.endswith(f"max_tokens={limit}")
    assert AnthropicFableTarget().max_tokens == 25_000

    sol_spec = (OpenAIResponsesTarget.BUDGET_SPEC if limit == 4096
                else OpenAIResponsesTarget.OUTPUT_8192_SPEC)
    sol = build_api_target(sol_spec)
    captured = _install_responses_fixture(sol, _responses_result(max_output_tokens=limit))
    sol.generate([DialogTurn(role="user", content="fixture")], seed=0)
    assert captured["max_output_tokens"] == limit
    assert sol.name.endswith(f"max_output_tokens={limit}")
    assert OpenAIResponsesTarget().max_output_tokens == 25_000


@pytest.mark.parametrize("spec", ["kimi:kimi-k3", "deepseek:deepseek-v4-pro", "deepseek:deepseek-v4-flash"])
def test_compatible_explicit_reasoning_effort_reaches_request_and_evidence(spec) -> None:
    target = build_api_target(spec, config={
        "modalities": ["text"], "max_tokens": 8192,
        "temperature": None, "reasoning_effort": "low",
    })
    result = _chat_result()
    result.model = spec.split(":", 1)[1]
    captured = {}

    def create(**kwargs):
        captured.update(kwargs)
        return result

    target._client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=create),
    ))
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert captured["reasoning_effort"] == "low"
    assert captured["max_tokens"] == 8192
    assert response.raw["requested_reasoning_effort"] == "low"


@pytest.mark.parametrize("spec,effort", [
    ("kimi:kimi-k3", "medium"), ("kimi:kimi-k3", None),
    ("kimi:kimi-k2", "low"), ("anthropic:claude-haiku-4-5-20251001", "low"),
])
def test_kimi_reasoning_control_is_not_sent_to_unsupported_routes(spec, effort) -> None:
    with pytest.raises(ValueError, match="reasoning_effort"):
        build_api_target(spec, config={
            "modalities": ["text"], "max_tokens": 8192,
            "temperature": None, "reasoning_effort": effort,
        })


def test_generic_openai_chat_terminal_states_fail_closed() -> None:
    target = OpenAITarget("gpt-generic")
    _install_chat_fixture(target, _chat_result())
    response = target.generate([DialogTurn(role="user", content="request")], seed=4)
    assert response.raw["response_id"] == "chatcmpl-generic-1"
    assert response.raw["target_sampling_control"] == (
        "provider_seed_requested_best_effort"
    )
    assert target.max_transport_attempts_per_call == 4
    assert response.raw["transport_attempt_count"] == 1
    assert response.raw["generation"]["max_retries"] == 3

    _install_chat_fixture(
        target, _chat_result(content="partial", finish_reason="length")
    )
    partial = target.generate([DialogTurn(role="user", content="request")])
    assert partial.output_turns[0].content == "partial"
    assert partial.raw["output_truncated"] is True

    _install_chat_fixture(
        target, _chat_result(content=None, finish_reason="content_filter")
    )
    refusal = target.generate([DialogTurn(role="user", content="request")])
    assert refusal.output_turns == []
    assert refusal.raw["provider_refusal_category"] == "openai_content_filter"

    _install_chat_fixture(target, _chat_result(content=""))
    with pytest.raises(OpenAIChatOutputError, match="no visible text"):
        target.generate([DialogTurn(role="user", content="request")])


@pytest.mark.parametrize("finish_reason", ["stop", "length"])
def test_empty_chat_keeps_finish_usage_and_actual_http_count(finish_reason) -> None:
    from openai.types.chat import ChatCompletion
    from ura.runner import _safe_call_audit

    result = ChatCompletion.model_validate({
        "id": "chatcmpl-empty", "object": "chat.completion", "created": 0,
        "model": "gpt-generic", "choices": [{"index": 0, "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": "", "reasoning_content": "private reasoning"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 8192, "total_tokens": 8202,
                  "completion_tokens_details": {"reasoning_tokens": 8192}},
    })
    target = OpenAITarget("gpt-generic", max_tokens=8192)
    _install_chat_fixture(target, result)
    with pytest.raises(OpenAIChatOutputError, match=finish_reason + " response") as caught:
        target.generate([DialogTurn(role="user", content="private question")])
    audit = _safe_call_audit(caught.value.call_audit)
    assert audit["finish_reason"] == finish_reason
    assert audit["transport_attempt_count"] == 1
    assert audit["requested_output_tokens"] == 8192
    assert audit["reported_input_tokens"] == 10
    assert audit["reported_output_tokens"] == 8192
    assert audit["reported_total_tokens"] == 8202
    assert audit["reported_reasoning_tokens"] == 8192
    assert "private" not in repr(audit)


def test_openai_compatible_response_retains_only_hashed_endpoint_identity() -> None:
    endpoint = "https://Same.Example:443/compatible/../v1/"
    target = OpenAICompatibleTarget(
        "requested-alias",
        endpoint,
        "FIXTURE_KEY",
        provider="qwen",
        requested_spec="qwen:requested-alias",
    )
    provider_result = _chat_result()
    provider_result.model = "requested-alias-2026-08-18"
    _install_chat_fixture(target, provider_result)

    response = target.generate([DialogTurn(role="user", content="request")])

    assert target.max_transport_attempts_per_call == 4
    assert response.raw["generation"]["max_retries"] == 3
    assert response.raw["endpoint_identity"] == (
        canonical_https_endpoint_identity(endpoint)
    )
    assert "endpoint" not in response.raw and "base_url" not in response.raw
    assert "same.example" not in json.dumps(response.raw).lower()


def _install_gemini_fixture(target: GeminiTarget, result) -> None:
    target._client = SimpleNamespace(
        models=SimpleNamespace(generate_content=lambda **_kwargs: result)
    )


def _gemini_result(
    *, text: str = "complete", finish_reason: str = "STOP",
    prompt_block_reason: str | None = None,
):
    prompt_feedback = SimpleNamespace(
        block_reason=prompt_block_reason,
        block_reason_message="blocked by provider" if prompt_block_reason else None,
    )
    candidates = [] if prompt_block_reason else [SimpleNamespace(
        finish_reason=finish_reason,
        finish_message=None,
        safety_ratings=[],
        content=SimpleNamespace(
            role="model", parts=[] if not text else [SimpleNamespace(text=text)],
        ),
    )]
    return SimpleNamespace(
        response_id="gemini-response-1",
        model_version="gemini-generic-20260801",
        prompt_feedback=prompt_feedback,
        candidates=candidates,
        usage_metadata=SimpleNamespace(
            prompt_token_count=7,
            candidates_token_count=0 if prompt_block_reason else 3,
            total_token_count=7 if prompt_block_reason else 10,
        ),
    )


@pytest.mark.parametrize("cached", [0, 2, None])
def test_gemini_retains_real_sdk_cached_input_without_inventing_missing_usage(cached):
    types = pytest.importorskip("google.genai.types")
    usage = types.GenerateContentResponseUsageMetadata(prompt_token_count=7,
        candidates_token_count=3, total_token_count=10, cached_content_token_count=cached)
    tokens = GeminiTarget._usage_tokens(usage, provider_refusal=False)
    assert tokens["input"] == 7 and tokens["output"] == 3
    if cached is None:
        assert "cached_input" not in tokens
    else:
        assert tokens["cached_input"] == cached
    assert "cache_write_input" not in tokens


def test_gemini_cached_input_cannot_exceed_prompt_tokens():
    usage = _gemini_result().usage_metadata
    usage.cached_content_token_count = 8
    with pytest.raises(GeminiOutputError, match="cache usage exceeds"):
        GeminiTarget._usage_tokens(usage, provider_refusal=False)


@pytest.mark.parametrize("usage", [None, {"prompt_token_count": 7},
    {"prompt_token_count": 7, "candidates_token_count": 0, "total_token_count": 7}])
@pytest.mark.parametrize("identity_present", [False, True])
def test_gemini_real_sdk_null_candidates_are_prompt_policy_outcomes(usage, identity_present):
    types = pytest.importorskip("google.genai.types")
    result = types.GenerateContentResponse(
        response_id="blocked-1" if identity_present else None,
        model_version="gemini-generic" if identity_present else None,
        prompt_feedback=types.GenerateContentResponsePromptFeedback(block_reason="SAFETY"),
        usage_metadata=usage,
    )
    assert result.candidates is None
    target = GeminiTarget("gemini-generic")
    calls = []
    target._client = SimpleNamespace(models=SimpleNamespace(generate_content=lambda **body: (calls.append(body), result)[1]))
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert len(calls) == response.raw["transport_attempt_count"] == 1
    assert response.raw["provider_refusal_category"] == "gemini_prompt_safety"
    assert response.output_turns == []
    assert response.raw["resolved_model"] == ("gemini-generic" if identity_present else None)
    if usage is not None and "candidates_token_count" in usage:
        assert response.tokens == {"input": 7, "output": 0, "total": 7}
    else:
        assert response.tokens is None and response.raw["usage_status"] == "unknown"


def test_gemini_real_sdk_filtered_candidate_can_have_null_parts_and_usage():
    types = pytest.importorskip("google.genai.types")
    result = types.GenerateContentResponse(response_id="filtered-1", model_version="gemini-generic",
        candidates=[types.Candidate(finish_reason="SAFETY", content=types.Content(role="model"))])
    assert result.candidates[0].content.parts is None and result.usage_metadata is None
    target = GeminiTarget("gemini-generic")
    _install_gemini_fixture(target, result)
    response = target.generate([DialogTurn(role="user", content="fixture")])
    assert response.raw["provider_refusal_category"] == "gemini_finish_safety"
    assert response.output_turns == [] and response.tokens is None


@pytest.mark.parametrize('filtered,visible', [(True, False), (True, True), (False, True), (False, False)])
@pytest.mark.parametrize('usage_present', [True, False])
def test_gemini_thoughts_are_not_answers_and_filtered_visible_text_is_retained(filtered, visible, usage_present):
    types = pytest.importorskip('google.genai.types')
    parts = [types.Part(text='Diagnostic thought summary, not the answer.', thought=True)]
    if visible:
        parts.append(types.Part(text='Visible partial answer', thought=False))
    result = types.GenerateContentResponse(response_id='filtered-partial-1', model_version='gemini-generic',
        candidates=[types.Candidate(finish_reason='PROHIBITED_CONTENT' if filtered else 'STOP',
            content=types.Content(role='model', parts=parts))],
        usage_metadata=types.GenerateContentResponseUsageMetadata(prompt_token_count=7,
            candidates_token_count=3 if visible else 0, thoughts_token_count=2,
            total_token_count=12 if visible else 9) if usage_present else None)
    target = GeminiTarget('gemini-generic')
    calls = []
    target._client = SimpleNamespace(models=SimpleNamespace(generate_content=lambda **body: (calls.append(body), result)[1]))
    if not filtered and (not visible or not usage_present):
        with pytest.raises(GeminiOutputError):
            target.generate([DialogTurn(role='user', content='fixture')])
    else:
        response = target.generate([DialogTurn(role='user', content='fixture')])
        from ura.runner import validate_response_refusal_state
        validate_response_refusal_state(response)
        assert [turn.content for turn in response.output_turns] == (['Visible partial answer'] if visible else [])
        assert response.raw['provider_refusal'] is (not visible)
        assert response.raw['provider_output_filtered'] is filtered
        assert response.raw['partial_output_filtered'] is (filtered and visible)
        assert response.raw['thought_summary_observed'] is True
        assert response.raw['output_truncated'] is False  # A policy stop is not token exhaustion.
        if usage_present:
            assert response.tokens == {'input': 7, 'output': 5 if visible else 2,
                'total': 12 if visible else 9, 'reasoning': 2, 'visible_output': 3 if visible else 0}
        else:
            assert response.tokens is None
            assert response.raw['usage_status'] == 'unknown'
    assert len(calls) == 1


def test_gemini_unexplained_null_candidates_preserve_one_actual_attempt_audit():
    types = pytest.importorskip("google.genai.types")
    result = types.GenerateContentResponse(response_id="malformed-1", model_version="gemini-generic")
    target = GeminiTarget("gemini-generic")
    _install_gemini_fixture(target, result)
    with pytest.raises(GeminiOutputError, match="candidates is not a list") as caught:
        target.generate([DialogTurn(role="user", content="fixture")])
    assert caught.value.call_audit["transport_attempt_count"] == 1
    assert caught.value.call_audit["provider_response_id"] == "malformed-1"
    assert caught.value.call_audit["provider_error_code"] is None


def test_gemini_prompt_policy_does_not_accept_conflicting_candidate_or_identity():
    target = GeminiTarget("gemini-generic")
    result = _gemini_result(prompt_block_reason="SAFETY")
    result.candidates = _gemini_result().candidates
    _install_gemini_fixture(target, result)
    with pytest.raises(GeminiOutputError, match="unexpectedly returned"):
        target.generate([DialogTurn(role="user", content="fixture")])
    result.candidates = None
    result.model_version = "a-different-model"
    with pytest.raises(GeminiOutputError, match="unexpected model"):
        target.generate([DialogTurn(role="user", content="fixture")])


@pytest.mark.parametrize("route", [
    "anthropic", "fable", "fable51", "chat", "compatible", "responses", "gemini",
])
@pytest.mark.parametrize("text", ["A usable but unfinished answer", ""])
def test_hosted_token_limit_keeps_visible_output_without_answer_retry(route, text) -> None:
    if route == "anthropic":
        target = AnthropicTarget("claude-generic")
        result = _anthropic_result(text=text, stop_reason="max_tokens")
        install = _install_anthropic_fixture
        error = AnthropicOutputError
    elif route in {"fable", "fable51"}:
        model = "claude-fable-5-1" if route == "fable51" else "claude-fable-5"
        target = AnthropicFableTarget(model)
        result = _fable_result(text=text, stop_reason="max_tokens")
        result.model = model
        install = _install_fable_fixture
        error = AnthropicFableOutputError
    elif route in {"chat", "compatible"}:
        target = (OpenAITarget("gpt-generic") if route == "chat" else
                  OpenAICompatibleTarget("gpt-generic", "https://fixture.invalid/v1",
                                         "FIXTURE_KEY", provider="kimi"))
        result = _chat_result(content=text, finish_reason="length")
        install = _install_chat_fixture
        error = OpenAIChatOutputError
    elif route == "responses":
        target = OpenAIResponsesTarget()
        result = _responses_result(text=text, status="incomplete", reason="max_output_tokens")
        # The real wire can mark its partial message incomplete as well.
        result.output[-1].status = "incomplete"
        install = _install_responses_fixture
        error = OpenAIResponsesOutputError
    else:
        target = GeminiTarget("gemini-generic")
        result = _gemini_result(text=text, finish_reason="MAX_TOKENS")
        install = _install_gemini_fixture
        error = GeminiOutputError
    install(target, result)
    endpoint = (target._client.responses if route == "responses" else
                target._client.models if route == "gemini" else
                target._client.chat.completions if route in {"chat", "compatible"}
                else target._client.messages)
    method = "generate_content" if route == "gemini" else "create"
    original = getattr(endpoint, method)
    calls = []

    def counted(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    setattr(endpoint, method, counted)
    dialog = [DialogTurn(role="user", content="fixture")]
    if text:
        response = target.generate(dialog, seed=0)
        assert response.output_turns[0].content == text
        assert response.raw["output_truncated"] is True
        assert response.raw["transport_attempt_count"] == 1
        assert response.tokens["output"] > 0
        if route == "responses":
            assert response.raw["status"] == "incomplete"
            assert response.raw["incomplete_reason"] == "max_output_tokens"
            state = response.output_turns[0].provider_state
            assert state.items[-1]["status"] == "incomplete"
    else:
        with pytest.raises(error, match="text"):
            target.generate(dialog, seed=0)
    assert len(calls) == 1


@pytest.mark.parametrize("status,reason,error,item_status", [
    ("failed", "max_output_tokens", None, "completed"),
    ("incomplete", "content_filter", None, "incomplete"),
    ("incomplete", "max_output_tokens", {"code": "server_error"}, "incomplete"),
    ("completed", "max_output_tokens", None, "completed"),
    ("completed", None, None, "incomplete"),
    ("incomplete", "max_output_tokens", None, "in_progress"),
])
def test_responses_token_limit_does_not_accept_failed_or_contradictory_states(
    status, reason, error, item_status,
) -> None:
    result = _responses_result(text="partial", status=status, reason=reason)
    result.error = error
    result.output[-1].status = item_status
    target = OpenAIResponsesTarget()
    _install_responses_fixture(target, result)
    with pytest.raises(OpenAIResponsesOutputError):
        target.generate([DialogTurn(role="user", content="fixture")])


def test_generic_gemini_terminal_states_fail_closed() -> None:
    target = GeminiTarget("gemini-generic")
    _install_gemini_fixture(target, _gemini_result())
    response = target.generate([DialogTurn(role="user", content="request")])
    assert response.raw["response_id"] == "gemini-response-1"
    assert response.raw["finish_reason"] == "STOP"
    assert target.max_transport_attempts_per_call == 4
    assert response.raw["transport_attempt_count"] == 1
    assert response.raw["generation"]["max_retries"] == 3

    _install_gemini_fixture(
        target, _gemini_result(text="partial", finish_reason="MAX_TOKENS")
    )
    partial = target.generate([DialogTurn(role="user", content="request")])
    assert partial.output_turns[0].content == "partial"
    assert partial.raw["output_truncated"] is True

    _install_gemini_fixture(
        target, _gemini_result(text="", prompt_block_reason="SAFETY")
    )
    refusal = target.generate([DialogTurn(role="user", content="request")])
    assert refusal.output_turns == []
    assert refusal.raw["provider_refusal_category"] == "gemini_prompt_safety"

    _install_gemini_fixture(target, _gemini_result(text=""))
    with pytest.raises(GeminiOutputError, match="no visible text"):
        target.generate([DialogTurn(role="user", content="request")])
