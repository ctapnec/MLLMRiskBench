"""Hosted-API and offline-mock targets (thesis III.2.2).

Concrete :class:`~ura.targets.base.BaseTarget` implementations:

* :class:`MockTarget` - a dependency-free, deterministic model used by the test
  suite and offline demos. It refuses on a keyword heuristic and complies
  benignly otherwise, so pure-python attacker/judge paths can run end-to-end.
* :class:`AnthropicTarget`, :class:`OpenAITarget`, :class:`GeminiTarget` - thin
  gateways over the hosted SDKs. Each lazily imports its SDK, reads its API key
  from the environment, converts :class:`~ura.data_models.DialogTurn` histories
  (including image :class:`~ura.data_models.MediaRef`) into the provider format,
  calls the API, and maps the reply back onto :class:`~ura.data_models.Response`.

Only pydantic + the standard library are imported at module load time; every
provider SDK is imported inside the method that needs it.
"""
from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Optional

from ..data_models import DialogTurn, MediaRef, Response
from .base import REGISTRY, BaseTarget

# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

# Coarse keyword heuristic driving MockTarget's refusals. Deliberately blunt:
# the point is a *deterministic* stand-in, not a real safety classifier.
_HARMFUL_MARKERS: tuple[str, ...] = (
    "bomb", "explosive", "weapon", "kill", "murder", "poison", "malware",
    "ransomware", "exploit", "sql injection", "phishing", "ddos", "botnet",
    "meth", "cocaine", "heroin", "fentanyl", "synthesize", "bioweapon",
    "nerve agent", "anthrax", "self-harm", "suicide", "child", "csem",
    "hotwire", "counterfeit", "launder", "untraceable", "steal", "hack",
    "credit card", "ssn", "how to make a", "step-by-step", "jailbreak",
    "ignore previous", "disregard your", "pretend you are",
)

_REFUSAL_TEXT = (
    "I can't help with that. The request appears to involve harmful, dangerous, "
    "or unsafe activity, so I won't provide instructions or assistance."
)


def _last_user_text(dialog: list[DialogTurn]) -> str:
    """Return the concatenated text of the most recent user turn (may be empty)."""
    for turn in reversed(dialog):
        if turn.role == "user":
            return turn.content or ""
    # Fall back to the last turn with any content.
    for turn in reversed(dialog):
        if turn.content:
            return turn.content
    return ""


def _looks_harmful(text: str) -> bool:
    """True when ``text`` trips the coarse harmful-content heuristic."""
    low = text.lower()
    return any(marker in low for marker in _HARMFUL_MARKERS)


def _dialog_fingerprint(dialog: list[DialogTurn]) -> str:
    """Deterministic short id derived from the rendered dialog.

    ``BaseTarget.generate`` receives a dialog rather than an Attempt, so the
    target cannot know the originating ``attempt_id``. We emit a stable
    content-hash placeholder; the runner overwrites it with the real id when it
    links the Response back to its Attempt.
    """
    h = hashlib.sha256()
    for turn in dialog:
        h.update(turn.role.encode())
        h.update(b"\x1f")
        h.update((turn.content or "").encode())
        h.update(b"\x1e")
    return h.hexdigest()[:16]


def _approx_tokens(text: str) -> int:
    """Cheap whitespace-based token estimate for the offline mock."""
    return max(1, len(text.split()))


def _require(module: str, feature: str):
    """Import ``module`` lazily or raise a uniform, actionable error."""
    import importlib

    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - exercised only without SDK
        pkg = {
            "anthropic": "anthropic",
            "openai": "openai",
            "google.generativeai": "google-generativeai",
        }.get(module, module)
        raise RuntimeError(
            f"{pkg} is required for {feature}; pip install {pkg}"
        ) from exc


def _encode_media(media: MediaRef) -> tuple[str, str, Optional[str]]:
    """Return ``(mime, base64_data_or_empty, url_or_none)`` for an image ref.

    Prefers a local ``path`` (embedded as base64) and otherwise passes the
    remote ``uri`` through untouched so providers that accept URLs can fetch it.
    """
    mime = media.mime or (
        mimetypes.guess_type(media.path or media.uri or "")[0] or "image/png"
    )
    if media.path:
        data = base64.b64encode(Path(media.path).read_bytes()).decode("ascii")
        return mime, data, None
    if media.uri:
        return mime, "", media.uri
    raise ValueError("MediaRef has neither path nor uri to encode")


# --------------------------------------------------------------------------- #
# Offline deterministic mock
# --------------------------------------------------------------------------- #

class MockTarget(BaseTarget):
    """Deterministic, dependency-free target for tests and offline demos.

    Refuses when the last user turn trips :func:`_looks_harmful`, otherwise
    returns a short benign completion. Multimodal-aware only in that it accepts
    image turns without failing.
    """

    name = "mock"
    modality_support = ("text", "image")

    def __init__(self, model: str = "mock") -> None:
        self.model = model

    def generate(self, dialog: list[DialogTurn]) -> Response:
        start = time.perf_counter()
        prompt = _last_user_text(dialog)

        if not prompt.strip():
            reply = "Hello! How can I help you today?"
        elif _looks_harmful(prompt):
            reply = _REFUSAL_TEXT
        else:
            reply = (
                "Sure - here is a straightforward, safe answer to your request: "
                f"{prompt.strip()[:160]}"
            )

        latency_ms = (time.perf_counter() - start) * 1000.0
        prompt_tokens = sum(_approx_tokens(t.content or "") for t in dialog)
        completion_tokens = _approx_tokens(reply)

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.model,
            output_turns=[DialogTurn(role="assistant", content=reply)],
            latency_ms=latency_ms,
            tokens={
                "input": prompt_tokens,
                "output": completion_tokens,
                "total": prompt_tokens + completion_tokens,
            },
            raw={"mock": True, "refused": reply == _REFUSAL_TEXT},
        )


# --------------------------------------------------------------------------- #
# Hosted-API targets
# --------------------------------------------------------------------------- #

class AnthropicTarget(BaseTarget):
    """Anthropic Messages API gateway (SDK imported lazily)."""

    name = "anthropic"
    modality_support = ("text", "image")

    def __init__(self, model: str, max_tokens: int = 1024) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        if self._client is None:
            anthropic = _require("anthropic", "AnthropicTarget")
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY is required for AnthropicTarget; "
                    "set it in the environment"
                )
            self._client = anthropic.Anthropic(api_key=key)
        return self._client

    def _to_messages(
        self, dialog: list[DialogTurn]
    ) -> tuple[Optional[str], list[dict[str, Any]]]:
        """Split ``dialog`` into an Anthropic system string and message blocks."""
        system: Optional[str] = None
        messages: list[dict[str, Any]] = []
        for turn in dialog:
            if turn.role == "system":
                system = turn.content
                continue
            role = "assistant" if turn.role == "assistant" else "user"
            blocks: list[dict[str, Any]] = []
            if turn.content:
                blocks.append({"type": "text", "text": turn.content})
            for media in turn.media:
                if media.modality != "image":
                    continue
                mime, data, url = _encode_media(media)
                if url:
                    blocks.append(
                        {"type": "image", "source": {"type": "url", "url": url}}
                    )
                else:
                    blocks.append(
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime,
                                "data": data,
                            },
                        }
                    )
            if turn.tool_result and not turn.content:
                blocks.append({"type": "text", "text": turn.tool_result})
            messages.append({"role": role, "content": blocks or (turn.content or "")})
        return system, messages

    def generate(self, dialog: list[DialogTurn]) -> Response:
        client = self._get_client()
        system, messages = self._to_messages(dialog)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        start = time.perf_counter()
        resp = client.messages.create(**kwargs)  # provider-specific call
        latency_ms = (time.perf_counter() - start) * 1000.0

        text = "".join(
            block.text for block in resp.content if getattr(block, "type", "") == "text"
        )
        usage = getattr(resp, "usage", None)
        tokens = None
        if usage is not None:
            tokens = {
                "input": getattr(usage, "input_tokens", 0),
                "output": getattr(usage, "output_tokens", 0),
            }
            tokens["total"] = tokens["input"] + tokens["output"]

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.model,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={"id": getattr(resp, "id", None), "model": self.model},
        )


class OpenAITarget(BaseTarget):
    """OpenAI Chat Completions gateway (SDK imported lazily)."""

    name = "openai"
    modality_support = ("text", "image")

    def __init__(self, model: str, max_tokens: int = 1024) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client = None

    def _get_client(self):
        if self._client is None:
            openai = _require("openai", "OpenAITarget")
            key = os.environ.get("OPENAI_API_KEY")
            if not key:
                raise RuntimeError(
                    "OPENAI_API_KEY is required for OpenAITarget; "
                    "set it in the environment"
                )
            self._client = openai.OpenAI(api_key=key)
        return self._client

    def _to_messages(self, dialog: list[DialogTurn]) -> list[dict[str, Any]]:
        """Render ``dialog`` as OpenAI chat messages with mixed-content parts."""
        messages: list[dict[str, Any]] = []
        for turn in dialog:
            role = turn.role if turn.role in ("system", "user", "assistant") else "user"
            parts: list[dict[str, Any]] = []
            if turn.content:
                parts.append({"type": "text", "text": turn.content})
            for media in turn.media:
                if media.modality != "image":
                    continue
                mime, data, url = _encode_media(media)
                image_url = url or f"data:{mime};base64,{data}"
                parts.append({"type": "image_url", "image_url": {"url": image_url}})
            if turn.tool_result and not turn.content:
                parts.append({"type": "text", "text": turn.tool_result})
            # Plain-text turns keep a bare string for maximal compatibility.
            content: Any = parts if len(parts) != 1 or parts[0]["type"] != "text" else parts[0]["text"]
            messages.append({"role": role, "content": content})
        return messages

    def generate(self, dialog: list[DialogTurn]) -> Response:
        client = self._get_client()
        messages = self._to_messages(dialog)

        # GPT-5 / o-series reasoning models require max_completion_tokens
        token_key = ("max_completion_tokens"
                     if self.model.startswith(("gpt-5", "o1", "o3", "o4")) else "max_tokens")
        start = time.perf_counter()
        resp = client.chat.completions.create(  # provider-specific call
            model=self.model,
            messages=messages,
            **{token_key: self.max_tokens},
        )
        latency_ms = (time.perf_counter() - start) * 1000.0

        text = resp.choices[0].message.content or ""
        usage = getattr(resp, "usage", None)
        tokens = None
        if usage is not None:
            tokens = {
                "input": getattr(usage, "prompt_tokens", 0),
                "output": getattr(usage, "completion_tokens", 0),
                "total": getattr(usage, "total_tokens", 0),
            }

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.model,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={"id": getattr(resp, "id", None), "model": self.model},
        )


class OpenAICompatibleTarget(OpenAITarget):
    """An OpenAI-compatible Chat Completions endpoint at a different base URL and
    API key. Covers DeepSeek, Moonshot/Kimi, Zhipu/GLM, Alibaba Qwen (DashScope),
    and ByteDance Doubao (Volcano Ark). The message/image handling and response
    mapping are inherited from OpenAITarget; only the client wiring changes."""

    def __init__(self, model: str, base_url: str, key_env: str, max_tokens: int = 1024) -> None:
        super().__init__(model, max_tokens=max_tokens)
        self.base_url = base_url
        self.key_env = key_env
        self.name = model

    def _get_client(self):
        if self._client is None:
            openai = _require("openai", f"{self.name} (OpenAI-compatible)")
            key = os.environ.get(self.key_env)
            if not key:
                raise RuntimeError(
                    f"{self.key_env} is required for {self.name}; set it in the environment")
            self._client = openai.OpenAI(api_key=key, base_url=self.base_url)
        return self._client


class GeminiTarget(BaseTarget):
    """Google Gemini gateway via ``google-generativeai`` (imported lazily)."""

    name = "gemini"
    modality_support = ("text", "image")

    def __init__(self, model: str) -> None:
        self.model = model
        self._genai = None

    def _get_sdk(self):
        if self._genai is None:
            genai = _require("google.generativeai", "GeminiTarget")
            key = os.environ.get("GOOGLE_API_KEY")
            if not key:
                raise RuntimeError(
                    "GOOGLE_API_KEY is required for GeminiTarget; "
                    "set it in the environment"
                )
            genai.configure(api_key=key)
            self._genai = genai
        return self._genai

    def _to_contents(
        self, dialog: list[DialogTurn]
    ) -> tuple[Optional[str], list[dict[str, Any]]]:
        """Return ``(system_instruction, contents)`` in Gemini's schema."""
        system: Optional[str] = None
        contents: list[dict[str, Any]] = []
        for turn in dialog:
            if turn.role == "system":
                system = turn.content
                continue
            role = "model" if turn.role == "assistant" else "user"
            parts: list[Any] = []
            if turn.content:
                parts.append({"text": turn.content})
            for media in turn.media:
                if media.modality != "image":
                    continue
                mime, data, url = _encode_media(media)
                if data:
                    parts.append(
                        {"inline_data": {"mime_type": mime, "data": data}}
                    )
                elif url:
                    parts.append({"file_data": {"mime_type": mime, "file_uri": url}})
            if turn.tool_result and not turn.content:
                parts.append({"text": turn.tool_result})
            contents.append({"role": role, "parts": parts})
        return system, contents

    def generate(self, dialog: list[DialogTurn]) -> Response:
        genai = self._get_sdk()
        system, contents = self._to_contents(dialog)
        model = genai.GenerativeModel(self.model, system_instruction=system)

        start = time.perf_counter()
        resp = model.generate_content(contents)  # provider-specific call
        latency_ms = (time.perf_counter() - start) * 1000.0

        text = getattr(resp, "text", "") or ""
        usage = getattr(resp, "usage_metadata", None)
        tokens = None
        if usage is not None:
            tokens = {
                "input": getattr(usage, "prompt_token_count", 0),
                "output": getattr(usage, "candidates_token_count", 0),
                "total": getattr(usage, "total_token_count", 0),
            }

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.model,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={"model": self.model},
        )


# --------------------------------------------------------------------------- #
# Registry wiring
# --------------------------------------------------------------------------- #

REGISTRY.register("mock", MockTarget, provider="mock", modality="text+image")

# Current frontier model ids (August 2026). Model names churn fast, so this list
# is only a convenience: you can always pass ANY id as "<provider>:<model>" (see
# build_api_target), so the registry never has to be edited when a new checkpoint
# ships. Do NOT add legacy ids here.
_ANTHROPIC_DEFAULTS = (
    "claude-opus-5",                 # top Opus tier
    "claude-sonnet-5",               # balanced
    "claude-fable-5",                # generally-available Mythos-class (exceeds Opus 4.8)
    "claude-haiku-4-5-20251001",     # cheap/fast (good judge model)
    "claude-mythos-5",               # Mythos-class, safeguards lifted (approved orgs only)
)
_OPENAI_DEFAULTS = (
    "gpt-5.6",                       # GPT-5.6 flagship (Sol)
    "gpt-5.6-luna",                  # GPT-5.6 cost-efficient (Luna) - good judge model
    "gpt-5.5",                       # previous frontier, still available
)
_GEMINI_DEFAULTS = (
    "gemini-3.1-pro",                # flagship reasoning/multimodal
    "gemini-3.6-flash",             # fast/cheap
)

for _mid in _ANTHROPIC_DEFAULTS:
    REGISTRY.register(
        _mid, (lambda m=_mid: AnthropicTarget(m)), provider="anthropic", hosted=True
    )
for _mid in _OPENAI_DEFAULTS:
    REGISTRY.register(
        _mid, (lambda m=_mid: OpenAITarget(m)), provider="openai", hosted=True
    )
for _mid in _GEMINI_DEFAULTS:
    REGISTRY.register(
        _mid, (lambda m=_mid: GeminiTarget(m)), provider="google", hosted=True
    )

# OpenAI-compatible providers (base_url + key env). The open-weight frontier
# flagships (DeepSeek V4, GLM-5.x, Kimi K3) are huge MoEs, so their APIs are the
# practical way to test them; smaller variants also run locally via vLLM (below).
_COMPAT: dict[str, tuple[str, str]] = {
    "deepseek": ("https://api.deepseek.com", "DEEPSEEK_API_KEY"),
    "glm": ("https://open.bigmodel.cn/api/paas/v4", "ZHIPU_API_KEY"),
    "zhipu": ("https://open.bigmodel.cn/api/paas/v4", "ZHIPU_API_KEY"),
    "kimi": ("https://api.moonshot.cn/v1", "MOONSHOT_API_KEY"),
    "moonshot": ("https://api.moonshot.cn/v1", "MOONSHOT_API_KEY"),
    "qwen": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "DASHSCOPE_API_KEY"),
    "dashscope": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "DASHSCOPE_API_KEY"),
    "alibaba": ("https://dashscope.aliyuncs.com/compatible-mode/v1", "DASHSCOPE_API_KEY"),
    "doubao": ("https://ark.cn-beijing.volces.com/api/v3", "ARK_API_KEY"),
    "bytedance": ("https://ark.cn-beijing.volces.com/api/v3", "ARK_API_KEY"),
}

# Representative current (2026) ids per lab. Verify the exact id/endpoint for your
# account; anything not listed still works via "<provider>:<model>".
_COMPAT_DEFAULTS = {
    "deepseek": ("deepseek-chat", "deepseek-reasoner"),   # DeepSeek V4 Pro / reasoner
    "glm": ("glm-5.2", "glm-4.6"),                         # Zhipu / z.ai (MIT, open weights)
    "kimi": ("kimi-k3", "kimi-k2.6"),                      # Moonshot (open weights)
    "qwen": ("qwen-max", "qwen-plus"),                     # Alibaba (Qwen3.6-Max via qwen-max)
    "doubao": ("doubao-pro", "doubao-vision-pro"),         # ByteDance (use your endpoint id)
}
for _prov, _ids in _COMPAT_DEFAULTS.items():
    _url, _key = _COMPAT[_prov]
    for _mid in _ids:
        REGISTRY.register(
            _mid, (lambda m=_mid, u=_url, k=_key: OpenAICompatibleTarget(m, u, k)),
            provider=_prov, hosted=True)

_PROVIDERS = {
    "anthropic": AnthropicTarget, "claude": AnthropicTarget,
    "openai": OpenAITarget, "gpt": OpenAITarget,
    "google": GeminiTarget, "gemini": GeminiTarget,
}


def build_api_target(spec: str) -> BaseTarget:
    """Build a hosted target from ``"<provider>:<model>"`` or a bare registered id.

    Native providers: anthropic/claude, openai/gpt, google/gemini. OpenAI-compatible
    providers: deepseek, glm/zhipu, kimi/moonshot, qwen/dashscope/alibaba,
    doubao/bytedance. Examples: ``"deepseek:deepseek-chat"``, ``"qwen:qwen-max"``,
    ``"kimi:kimi-k3"``, or a bare registered id like ``"claude-fable-5"``.
    """
    if ":" in spec:
        provider, model = spec.split(":", 1)
        provider = provider.lower()
        if provider in _PROVIDERS:
            return _PROVIDERS[provider](model)
        if provider in _COMPAT:
            url, key = _COMPAT[provider]
            return OpenAICompatibleTarget(model, url, key)
        raise KeyError(f"unknown API provider '{provider}' in '{spec}'")
    return REGISTRY.create(spec)


__all__ = [
    "MockTarget",
    "AnthropicTarget",
    "OpenAITarget",
    "OpenAICompatibleTarget",
    "GeminiTarget",
    "build_api_target",
]
