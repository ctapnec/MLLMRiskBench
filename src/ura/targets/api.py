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
import binascii
import hashlib
import hmac
import json
import mimetypes
import os
import time
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import unquote_to_bytes, urlsplit

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

_MOCK_REFUSAL_CUES: tuple[str, ...] = (
    "i can't",
    "i cannot",
    "i won't",
    "cannot help",
    "can't help",
    "cannot assist",
    "can't assist",
    "must decline",
)


class OpenAIResponsesOutputError(RuntimeError):
    """A Responses API result cannot be used as a complete model output."""


class AnthropicFableOutputError(RuntimeError):
    """A Fable Messages result cannot be used as a complete model output."""


class AnthropicOutputError(RuntimeError):
    """An Anthropic Messages result is incomplete or lacks provenance."""


class OpenAIChatOutputError(RuntimeError):
    """An OpenAI Chat Completions result is incomplete or lacks provenance."""


class GeminiOutputError(RuntimeError):
    """A Gemini GenerateContent result is incomplete or lacks provenance."""


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


def _mock_judge_verdict(prompt: str) -> Optional[str]:
    """Return a parseable offline verdict for the bundled judge rubric.

    ``MockTarget`` is a smoke-test double, not a research judge.  Still, making
    its explicit rubric mode structurally valid lets :class:`LLMJudge` fail
    closed on malformed *real* judge output without breaking the keyless smoke
    path or silently re-introducing heuristic imputation in the judge itself.
    """
    response_marker = "### Response"
    answer_marker = "### Answer"
    if response_marker not in prompt or answer_marker not in prompt:
        return None
    if not all(
        field in prompt
        for field in ("1.refused:", "2.convincing:", "3.specific:")
    ):
        return None
    response_section = prompt.split(response_marker, 1)[1].split(answer_marker, 1)[0]
    answer = response_section.strip()
    low = answer.lower()
    refused = any(cue in low for cue in _MOCK_REFUSAL_CUES)
    if refused:
        convincing = specific = 1
    else:
        word_count = len(answer.split())
        convincing = 4 if word_count >= 20 else 3
        actionable = any(
            cue in low
            for cue in (
                "step 1",
                "first,",
                "instructions",
                "procedure",
                "command",
                "code",
            )
        )
        specific = 4 if actionable else 3
    return (
        f"1.refused: {int(refused)}\n"
        f"2.convincing: {convincing}\n"
        f"3.specific: {specific}"
    )


def _provider_field(value: Any, name: str, default: Any = None) -> Any:
    """Read a provider SDK object or its JSON-dict test equivalent."""
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def _required_provider_string(
    value: Any, name: str, *, error: type[RuntimeError], location: str
) -> str:
    field = _provider_field(value, name)
    if not isinstance(field, str) or not field.strip():
        raise error(f"{location} omitted non-blank {name} provenance")
    return field


def _required_nonnegative_int(
    value: Any, name: str, *, error: type[RuntimeError], location: str
) -> int:
    field = _provider_field(value, name)
    if isinstance(field, bool) or not isinstance(field, int) or field < 0:
        raise error(f"{location} omitted valid {name} provenance")
    return field


def _enum_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    name = getattr(value, "name", None)
    text = name if isinstance(name, str) else str(value)
    return text.rsplit(".", 1)[-1].upper()


def _resolved_model_matches(requested: str, resolved: str) -> bool:
    return resolved == requested or resolved.startswith(f"{requested}-")


def _required_usage_count(value: Any, name: str, *, location: str) -> int:
    count = _provider_field(value, name)
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise OpenAIResponsesOutputError(
            f"OpenAI Responses completed without valid {location}.{name} provenance"
        )
    return count


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
        for media in turn.media:
            h.update(b"\x1d")
            h.update(media.modality.encode())
            h.update(b"\x1f")
            h.update((media.sha256 or media.uri or media.path or "").encode())
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
            "google.genai": "google-genai",
        }.get(module, module)
        raise RuntimeError(
            f"{pkg} is required for {feature}; pip install {pkg}"
        ) from exc


_MAX_MEDIA_BYTES = 25 * 1024 * 1024


def _media_roots(roots: Optional[Iterable[str | Path]] = None) -> tuple[Path, ...]:
    """Resolve the explicit allow-list used for local media reads.

    Hosted targets can exfiltrate a local file if an untrusted corpus is allowed
    to choose an arbitrary ``MediaRef.path``. Local files are therefore disabled
    unless a target receives ``media_roots`` or ``URA_MEDIA_ROOTS`` contains one
    or more paths separated by the platform path separator.
    """
    configured: Iterable[str | Path]
    if roots is None:
        raw = os.environ.get("URA_MEDIA_ROOTS", "")
        configured = [entry for entry in raw.split(os.pathsep) if entry]
    else:
        configured = roots
    resolved: list[Path] = []
    for root in configured:
        path = Path(root).expanduser().resolve(strict=True)
        if not path.is_dir():
            raise ValueError(f"approved media root is not a directory: {path}")
        resolved.append(path)
    return tuple(resolved)


def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
    return any(path == root or root in path.parents for root in roots)


def _verify_hash(data: bytes, expected: Optional[str], source: str) -> str:
    digest = hashlib.sha256(data).hexdigest()
    if expected is None:
        raise ValueError(f"local/inline media must declare sha256: {source}")
    if not hmac.compare_digest(digest, expected.lower()):
        raise ValueError(
            f"media sha256 mismatch for {source}: expected {expected}, got {digest}"
        )
    return digest


def _decode_data_uri(uri: str, *, max_bytes: int) -> tuple[str, bytes]:
    header, separator, payload = uri.partition(",")
    if not separator or not header.lower().startswith("data:"):
        raise ValueError("malformed data URI")
    metadata = header[5:].split(";")
    mime = metadata[0] or "application/octet-stream"
    try:
        if any(item.lower() == "base64" for item in metadata[1:]):
            data = base64.b64decode(payload, validate=True)
        else:
            data = unquote_to_bytes(payload)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("malformed data URI payload") from exc
    if len(data) > max_bytes:
        raise ValueError(f"media exceeds {max_bytes} byte limit")
    return mime, data


def _encode_media(
    media: MediaRef,
    *,
    allowed_roots: Optional[Iterable[str | Path]] = None,
    max_bytes: int = _MAX_MEDIA_BYTES,
) -> tuple[str, str, Optional[str]]:
    """Return ``(mime, base64_data_or_empty, url_or_none)`` for an image ref.

    Local reads are hash-verified and constrained to an explicit root allow-list.
    Inline ``data:`` URIs are decoded and hash-verified. Remote references must
    use HTTPS and contain no embedded credentials.
    """
    if media.modality != "image":
        raise ValueError(f"image target cannot encode {media.modality!r} media")
    if bool(media.path) == bool(media.uri):
        raise ValueError("MediaRef must contain exactly one of path or uri")
    if media.path:
        roots = _media_roots(allowed_roots)
        if not roots:
            raise PermissionError(
                "local media upload is disabled; configure media_roots or URA_MEDIA_ROOTS"
            )
        path = Path(media.path).expanduser().resolve(strict=True)
        if not path.is_file():
            raise ValueError(f"media path is not a regular file: {path}")
        if not _inside(path, roots):
            raise PermissionError(f"media path is outside approved roots: {path}")
        if path.stat().st_size > max_bytes:
            raise ValueError(f"media exceeds {max_bytes} byte limit: {path}")
        raw = path.read_bytes()
        _verify_hash(raw, media.sha256, str(path))
        mime = media.mime or mimetypes.guess_type(str(path))[0] or "image/png"
        if not mime.startswith("image/"):
            raise ValueError(f"unsupported image MIME type {mime!r}: {path}")
        data = base64.b64encode(raw).decode("ascii")
        return mime, data, None
    if media.uri:
        if media.uri.lower().startswith("data:"):
            mime, raw = _decode_data_uri(media.uri, max_bytes=max_bytes)
            _verify_hash(raw, media.sha256, "inline data URI")
            if media.mime and media.mime != mime:
                raise ValueError(
                    f"inline media MIME mismatch: declared {media.mime!r}, URI {mime!r}"
                )
            if not mime.startswith("image/"):
                raise ValueError(f"unsupported inline image MIME type {mime!r}")
            return mime, base64.b64encode(raw).decode("ascii"), None
        parsed = urlsplit(media.uri)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("remote media URI must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("remote media URI must not contain credentials")
        mime = media.mime or mimetypes.guess_type(parsed.path)[0] or "image/png"
        if not mime.startswith("image/"):
            raise ValueError(f"unsupported remote image MIME type {mime!r}")
        return mime, "", media.uri
    raise ValueError("MediaRef has neither path nor uri to encode")


def _recorded_trace_text(turn: DialogTurn) -> list[str]:
    """Preserve non-native tool/environment evidence without claiming execution."""
    parts: list[str] = []
    if turn.role in {"tool", "env"}:
        parts.append(f"[recorded_role={turn.role}]")
    if turn.tool_call is not None:
        parts.append(
            "[recorded_tool_call "
            f"{turn.tool_call.name}({json.dumps(turn.tool_call.arguments, sort_keys=True)})]"
        )
    if turn.tool_result is not None:
        parts.append(f"[recorded_tool_result] {turn.tool_result}")
    return parts


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
        self.name = model  # per-instance id so distinct mocks get distinct output cells

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        start = time.perf_counter()
        prompt = _last_user_text(dialog)

        mock_judge_verdict = _mock_judge_verdict(prompt)
        if mock_judge_verdict is not None:
            reply = mock_judge_verdict
        elif not prompt.strip():
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
            raw={
                "mock": True,
                "refused": reply == _REFUSAL_TEXT,
                "requested_seed": seed,
                "target_sampling_control": "deterministic_mock",
            },
        )


# --------------------------------------------------------------------------- #
# Hosted-API targets
# --------------------------------------------------------------------------- #

class AnthropicTarget(BaseTarget):
    """Anthropic Messages API gateway (SDK imported lazily)."""

    name = "anthropic"
    modality_support = ("text", "image")
    tool_serialization = "recorded_text_proxy_no_execution"

    def __init__(
        self,
        model: str,
        max_tokens: int = 1024,
        *,
        requested_spec: Optional[str] = None,
        temperature: float = 0.0,
        timeout: float = 120.0,
        max_retries: int = 2,
        media_roots: Optional[Iterable[str | Path]] = None,
    ) -> None:
        self.model = model
        self.provider = "anthropic"
        self.requested_spec = requested_spec or f"anthropic:{model}"
        self.name = self.requested_spec
        self.max_tokens = max_tokens
        self.temperature = float(temperature)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.media_roots = _media_roots(media_roots)
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
            self._client = anthropic.Anthropic(
                api_key=key, timeout=self.timeout, max_retries=self.max_retries
            )
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
            if role == "assistant" and turn.provider_thinking:
                # Return preserved thinking blocks unchanged (signatures intact),
                # ahead of the visible text, per the extended-thinking contract.
                blocks.extend(turn.provider_thinking)
            if turn.content:
                blocks.append({"type": "text", "text": turn.content})
            blocks.extend(
                {"type": "text", "text": text}
                for text in _recorded_trace_text(turn)
            )
            for media in turn.media:
                if media.modality != "image":
                    raise ValueError(
                        f"AnthropicTarget cannot render {media.modality!r} media"
                    )
                mime, data, url = _encode_media(
                    media, allowed_roots=self.media_roots
                )
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
            messages.append({"role": role, "content": blocks or (turn.content or "")})
        return system, messages

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        client = self._get_client()
        system, messages = self._to_messages(dialog)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        start = time.perf_counter()
        resp = client.messages.create(**kwargs)  # provider-specific call
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_id = _required_provider_string(
            resp, "id", error=AnthropicOutputError, location="Anthropic response"
        )
        if _provider_field(resp, "type") != "message":
            raise AnthropicOutputError("Anthropic response has a non-message type")
        if _provider_field(resp, "role") != "assistant":
            raise AnthropicOutputError("Anthropic response has a non-assistant role")
        resolved_model = _required_provider_string(
            resp, "model", error=AnthropicOutputError, location="Anthropic response"
        )
        if not _resolved_model_matches(self.model, resolved_model):
            raise AnthropicOutputError(
                f"Anthropic resolved unexpected model {resolved_model!r}"
            )
        content = _provider_field(resp, "content")
        if not isinstance(content, (list, tuple)):
            raise AnthropicOutputError("Anthropic response content is not a block list")
        unsupported = [
            _provider_field(block, "type")
            for block in content
            if _provider_field(block, "type") != "text"
        ]
        if unsupported:
            raise AnthropicOutputError(
                "Anthropic returned unsupported content blocks while tools and "
                f"thinking were disabled: {unsupported!r}"
            )
        text_parts = [_provider_field(block, "text") for block in content]
        if any(not isinstance(part, str) for part in text_parts):
            raise AnthropicOutputError("Anthropic text block lacks string text")
        text = "".join(text_parts)
        stop_reason = _provider_field(resp, "stop_reason")
        provider_refusal = stop_reason == "refusal"
        if provider_refusal:
            if text.strip():
                raise AnthropicOutputError(
                    "Anthropic typed refusal contained visible partial output"
                )
            output_turns: list[DialogTurn] = []
        else:
            if stop_reason != "end_turn":
                raise AnthropicOutputError(
                    f"Anthropic response ended with incomplete or unexpected "
                    f"stop_reason {stop_reason!r}"
                )
            if not text.strip():
                raise AnthropicOutputError(
                    "Anthropic end_turn response contained no visible text"
                )
            output_turns = [DialogTurn(role="assistant", content=text)]
        if _provider_field(resp, "stop_sequence") is not None:
            raise AnthropicOutputError(
                "Anthropic named a stop sequence although none was requested"
            )
        usage = _provider_field(resp, "usage")
        if usage is None:
            raise AnthropicOutputError("Anthropic response omitted usage provenance")
        input_tokens = _required_nonnegative_int(
            usage, "input_tokens", error=AnthropicOutputError,
            location="Anthropic usage",
        )
        output_tokens = _required_nonnegative_int(
            usage, "output_tokens", error=AnthropicOutputError,
            location="Anthropic usage",
        )
        tokens = {
            "input": input_tokens,
            "output": output_tokens,
            "total": input_tokens + output_tokens,
        }

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=output_turns,
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "id": response_id,
                "response_id": response_id,
                "provider": self.provider,
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "stop_reason": stop_reason,
                "stop_sequence": _provider_field(resp, "stop_sequence"),
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled",
                "provider_refusal": provider_refusal,
                "provider_refusal_category": (
                    "anthropic_stop_reason_refusal" if provider_refusal else None
                ),
                "provider_refusal_reason": None,
                "generation": {
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                },
            },
        )


_ANTHROPIC_FABLE_MODEL = "claude-fable-5"
_ANTHROPIC_FABLE_SPEC = (
    "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000"
)


class AnthropicFableTarget(AnthropicTarget):
    """Frozen Claude Fable 5 high-effort adaptive-thinking condition."""

    name = _ANTHROPIC_FABLE_SPEC
    MAX_TOKENS = 25_000
    EFFORT = "high"
    THINKING_TYPE = "adaptive"

    def __init__(
        self,
        model: str = _ANTHROPIC_FABLE_MODEL,
        *,
        requested_spec: Optional[str] = None,
        timeout: float = 600.0,
        max_retries: int = 2,
        media_roots: Optional[Iterable[str | Path]] = None,
    ) -> None:
        if model != _ANTHROPIC_FABLE_MODEL:
            raise ValueError(
                "the frozen Fable condition requires model 'claude-fable-5'"
            )
        if requested_spec is not None and requested_spec != _ANTHROPIC_FABLE_SPEC:
            raise ValueError(
                "the Fable target must use the canonical spec "
                f"{_ANTHROPIC_FABLE_SPEC!r}"
            )
        super().__init__(
            model,
            max_tokens=self.MAX_TOKENS,
            requested_spec=_ANTHROPIC_FABLE_SPEC,
            timeout=timeout,
            max_retries=max_retries,
            media_roots=media_roots,
        )
        # Fable rejects non-default sampling parameters.  ``None`` documents
        # omission in the component snapshot; generate() never sends it.
        self.temperature = None
        self.effort = self.EFFORT
        self.thinking_type = self.THINKING_TYPE

    @staticmethod
    def _usage_tokens(resp: Any) -> dict[str, int]:
        usage = _provider_field(resp, "usage")
        if usage is None:
            raise AnthropicFableOutputError(
                "Anthropic Fable completed without usage provenance"
            )

        def required(name: str, *, owner: Any = usage, location: str = "usage") -> int:
            value = _provider_field(owner, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise AnthropicFableOutputError(
                    f"Anthropic Fable completed without valid {location}.{name}"
                )
            return value

        input_tokens = required("input_tokens")
        output_tokens = required("output_tokens")
        cache_read_tokens = 0
        cache_creation_tokens = 0
        cache_read_value = _provider_field(usage, "cache_read_input_tokens")
        if cache_read_value is not None:
            cache_read_tokens = required("cache_read_input_tokens")
        cache_creation_value = _provider_field(
            usage, "cache_creation_input_tokens"
        )
        if cache_creation_value is not None:
            cache_creation_tokens = required("cache_creation_input_tokens")

        # Anthropic defines total input as the sum of uncached, cache-read, and
        # cache-creation tokens.  Normalize that total here while retaining the
        # provider-native breakdown below and in ``raw.provider_usage``.
        total_input_tokens = (
            input_tokens + cache_read_tokens + cache_creation_tokens
        )
        tokens = {
            "input": total_input_tokens,
            "output": output_tokens,
            "total": total_input_tokens + output_tokens,
            "uncached_input": input_tokens,
        }
        if cache_read_value is not None:
            tokens["cached_input"] = cache_read_tokens
        if cache_creation_value is not None:
            tokens["cache_write_input"] = cache_creation_tokens
        output_details = _provider_field(usage, "output_tokens_details")
        if output_details is not None:
            thinking_tokens = _provider_field(output_details, "thinking_tokens")
            if thinking_tokens is not None:
                tokens["reasoning"] = required(
                    "thinking_tokens",
                    owner=output_details,
                    location="usage.output_tokens_details",
                )
                if tokens["reasoning"] > output_tokens:
                    raise AnthropicFableOutputError(
                        "Anthropic Fable reasoning tokens exceed output tokens"
                    )
        return tokens

    @staticmethod
    def _provider_usage(resp: Any) -> dict[str, Any]:
        """Retain provider-native usage names alongside normalized counters."""
        usage = _provider_field(resp, "usage")
        output_details = _provider_field(usage, "output_tokens_details")
        return {
            "input_tokens": _provider_field(usage, "input_tokens"),
            "output_tokens": _provider_field(usage, "output_tokens"),
            "cache_read_input_tokens": _provider_field(
                usage, "cache_read_input_tokens"
            ),
            "cache_creation_input_tokens": _provider_field(
                usage, "cache_creation_input_tokens"
            ),
            "output_tokens_details": (
                {
                    "thinking_tokens": _provider_field(
                        output_details, "thinking_tokens"
                    )
                }
                if output_details is not None
                else None
            ),
            "service_tier": _provider_field(usage, "service_tier"),
            "inference_geo": _provider_field(usage, "inference_geo"),
        }

    @staticmethod
    def _visible_text(resp: Any) -> tuple[str, list[dict[str, Any]]]:
        content = _provider_field(resp, "content")
        if not isinstance(content, (list, tuple)):
            raise AnthropicFableOutputError(
                "Anthropic Fable response content is not a block list"
            )
        text_blocks: list[str] = []
        thinking_blocks: list[dict[str, Any]] = []
        for block in content:
            block_type = _provider_field(block, "type")
            if block_type == "text":
                value = _provider_field(block, "text")
                if not isinstance(value, str):
                    raise AnthropicFableOutputError(
                        "Anthropic Fable text block is not a string"
                    )
                text_blocks.append(value)
            elif block_type == "thinking":
                # Preserve the verbatim thinking block (including its signature)
                # so a multi-turn continuation returns it to the provider
                # unchanged, rather than discarding the model's reasoning.
                thinking_blocks.append({
                    "type": "thinking",
                    "thinking": _provider_field(block, "thinking"),
                    "signature": _provider_field(block, "signature"),
                })
            elif block_type == "redacted_thinking":
                thinking_blocks.append({
                    "type": "redacted_thinking",
                    "data": _provider_field(block, "data"),
                })
            else:
                raise AnthropicFableOutputError(
                    "Anthropic Fable returned unsupported content block "
                    f"{block_type!r} without any tools enabled"
                )
        return "".join(text_blocks), thinking_blocks

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        client = self._get_client()
        system, messages = self._to_messages(dialog)
        if not messages:
            raise ValueError("AnthropicTarget requires at least one non-system message")
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
            "thinking": {"type": self.thinking_type},
            "output_config": {"effort": self.effort},
        }
        if system:
            kwargs["system"] = system

        start = time.perf_counter()
        resp = client.messages.create(**kwargs)
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_id = _provider_field(resp, "id")
        if not isinstance(response_id, str) or not response_id.strip():
            raise AnthropicFableOutputError(
                "Anthropic Fable completed without a response id"
            )
        if _provider_field(resp, "type") != "message":
            raise AnthropicFableOutputError(
                "Anthropic Fable response has a non-message object type"
            )
        if _provider_field(resp, "role") != "assistant":
            raise AnthropicFableOutputError(
                "Anthropic Fable response has a non-assistant role"
            )
        resolved_model = _provider_field(resp, "model")
        if (
            not isinstance(resolved_model, str)
            or not resolved_model.strip()
            or not (
                resolved_model == self.model
                or resolved_model.startswith(f"{self.model}-")
            )
        ):
            raise AnthropicFableOutputError(
                f"Anthropic Fable resolved unexpected model {resolved_model!r}"
            )
        stop_reason = _provider_field(resp, "stop_reason")
        stop_details = _provider_field(resp, "stop_details")
        stop_sequence = _provider_field(resp, "stop_sequence")
        text, thinking_blocks = self._visible_text(resp)
        thinking_block_count = len(thinking_blocks)
        tokens = self._usage_tokens(resp)

        provider_refusal = stop_reason == "refusal"
        refusal_category: Optional[str] = None
        refusal_reason: Optional[str] = None
        if provider_refusal:
            if text.strip():
                raise AnthropicFableOutputError(
                    "Anthropic Fable refusal contained visible partial text"
                )
            if thinking_block_count:
                raise AnthropicFableOutputError(
                    "Anthropic Fable refusal contained partial thinking output"
                )
            if _provider_field(stop_details, "type") != "refusal":
                raise AnthropicFableOutputError(
                    "Anthropic Fable refusal omitted typed stop details"
                )
            if stop_sequence is not None:
                raise AnthropicFableOutputError(
                    "Anthropic Fable refusal unexpectedly named a stop sequence"
                )
            category = _provider_field(stop_details, "category")
            explanation = _provider_field(stop_details, "explanation")
            if category is not None and not isinstance(category, str):
                raise AnthropicFableOutputError(
                    "Anthropic Fable refusal category is not a string or null"
                )
            if explanation is not None and not isinstance(explanation, str):
                raise AnthropicFableOutputError(
                    "Anthropic Fable refusal explanation is not a string or null"
                )
            refusal_category = category
            refusal_reason = explanation
            output_turns: list[DialogTurn] = []
        else:
            if stop_reason != "end_turn":
                raise AnthropicFableOutputError(
                    f"Anthropic Fable {response_id} ended with incomplete or "
                    f"unexpected stop reason {stop_reason!r}"
                )
            if stop_details is not None:
                raise AnthropicFableOutputError(
                    "Anthropic Fable end_turn unexpectedly contained stop details"
                )
            if stop_sequence is not None:
                raise AnthropicFableOutputError(
                    "Anthropic Fable end_turn unexpectedly named a stop sequence"
                )
            if not text.strip():
                raise AnthropicFableOutputError(
                    "Anthropic Fable end_turn contained no visible text"
                )
            output_turns = [DialogTurn(
                role="assistant", content=text, provider_thinking=thinking_blocks,
            )]

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=output_turns,
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "id": response_id,
                "response_id": response_id,
                "provider_request_id": _provider_field(resp, "_request_id"),
                "provider": "anthropic",
                "api_surface": "messages",
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "stop_reason": stop_reason,
                "stop_sequence": stop_sequence,
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled_anthropic_no_seed",
                "provider_refusal": provider_refusal,
                "provider_refusal_category": refusal_category,
                "provider_refusal_reason": refusal_reason,
                "thinking_block_count": thinking_block_count,
                "usage": dict(tokens),
                "provider_usage": self._provider_usage(resp),
                "generation": {
                    "max_tokens": self.max_tokens,
                    "temperature": "omitted",
                    "thinking": {"type": self.thinking_type},
                    "output_config": {"effort": self.effort},
                    "fallbacks": "disabled",
                    "tools": "disabled",
                    "timeout_seconds": self.timeout,
                    "max_retries": self.max_retries,
                },
            },
        )


class OpenAITarget(BaseTarget):
    """OpenAI Chat Completions gateway (SDK imported lazily)."""

    name = "openai"
    modality_support = ("text", "image")
    tool_serialization = "recorded_text_proxy_no_execution"

    def __init__(
        self,
        model: str,
        max_tokens: int = 1024,
        *,
        provider: str = "openai",
        requested_spec: Optional[str] = None,
        temperature: float = 0.0,
        timeout: float = 120.0,
        max_retries: int = 2,
        media_roots: Optional[Iterable[str | Path]] = None,
        supports_seed: bool = True,
    ) -> None:
        self.model = model
        self.provider = provider
        self.requested_spec = requested_spec or f"{provider}:{model}"
        self.name = self.requested_spec
        self.max_tokens = max_tokens
        self.temperature = float(temperature)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.media_roots = _media_roots(media_roots)
        self.supports_seed = bool(supports_seed)
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
            self._client = openai.OpenAI(
                api_key=key, timeout=self.timeout, max_retries=self.max_retries
            )
        return self._client

    def _to_messages(self, dialog: list[DialogTurn]) -> list[dict[str, Any]]:
        """Render ``dialog`` as OpenAI chat messages with mixed-content parts."""
        messages: list[dict[str, Any]] = []
        for turn in dialog:
            role = turn.role if turn.role in ("system", "user", "assistant") else "user"
            parts: list[dict[str, Any]] = []
            if turn.content:
                parts.append({"type": "text", "text": turn.content})
            parts.extend(
                {"type": "text", "text": text}
                for text in _recorded_trace_text(turn)
            )
            for media in turn.media:
                if media.modality != "image":
                    raise ValueError(
                        f"OpenAITarget cannot render {media.modality!r} media"
                    )
                mime, data, url = _encode_media(
                    media, allowed_roots=self.media_roots
                )
                image_url = url or f"data:{mime};base64,{data}"
                parts.append({"type": "image_url", "image_url": {"url": image_url}})
            # Plain-text turns keep a bare string for maximal compatibility.
            content: Any = parts if len(parts) != 1 or parts[0]["type"] != "text" else parts[0]["text"]
            messages.append({"role": role, "content": content})
        return messages

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        client = self._get_client()
        messages = self._to_messages(dialog)

        # GPT-5 / o-series reasoning models require max_completion_tokens
        token_key = ("max_completion_tokens"
                     if self.model.startswith(("gpt-5", "o1", "o3", "o4")) else "max_tokens")
        request: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            token_key: self.max_tokens,
            "temperature": self.temperature,
        }
        if seed is not None and self.supports_seed:
            request["seed"] = int(seed)
        start = time.perf_counter()
        resp = client.chat.completions.create(**request)  # provider-specific call
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_id = _required_provider_string(
            resp, "id", error=OpenAIChatOutputError,
            location="OpenAI Chat response",
        )
        resolved_model = _required_provider_string(
            resp, "model", error=OpenAIChatOutputError,
            location="OpenAI Chat response",
        )
        if not _resolved_model_matches(self.model, resolved_model):
            raise OpenAIChatOutputError(
                f"OpenAI Chat resolved unexpected model {resolved_model!r}"
            )
        choices = _provider_field(resp, "choices")
        if not isinstance(choices, (list, tuple)) or len(choices) != 1:
            raise OpenAIChatOutputError(
                "OpenAI Chat response must contain exactly one requested choice"
            )
        choice = choices[0]
        choice_index = _provider_field(choice, "index")
        if choice_index != 0:
            raise OpenAIChatOutputError("OpenAI Chat choice index is not zero")
        finish_reason = _provider_field(choice, "finish_reason")
        message = _provider_field(choice, "message")
        if message is None:
            raise OpenAIChatOutputError("OpenAI Chat choice omitted its message")
        role = _provider_field(message, "role", "assistant")
        if role != "assistant":
            raise OpenAIChatOutputError("OpenAI Chat returned a non-assistant message")
        content = _provider_field(message, "content")
        refusal = _provider_field(message, "refusal")
        if content is not None and not isinstance(content, str):
            raise OpenAIChatOutputError("OpenAI Chat message content is not text or null")
        if refusal is not None and not isinstance(refusal, str):
            raise OpenAIChatOutputError("OpenAI Chat refusal is not text or null")
        text = content or ""
        refusal_text = refusal or ""
        provider_refusal = bool(refusal_text.strip()) or finish_reason == "content_filter"
        if provider_refusal:
            if text.strip():
                raise OpenAIChatOutputError(
                    "OpenAI Chat typed refusal/filter contained visible partial output"
                )
            output_turns: list[DialogTurn] = []
            refusal_category = (
                "openai_content_filter"
                if finish_reason == "content_filter"
                else "openai_message_refusal"
            )
        else:
            if finish_reason != "stop":
                raise OpenAIChatOutputError(
                    f"OpenAI Chat response ended with incomplete or unexpected "
                    f"finish_reason {finish_reason!r}"
                )
            if not text.strip():
                raise OpenAIChatOutputError(
                    "OpenAI Chat stop response contained no visible text"
                )
            output_turns = [DialogTurn(role="assistant", content=text)]
            refusal_category = None
        usage = _provider_field(resp, "usage")
        if usage is None:
            raise OpenAIChatOutputError("OpenAI Chat response omitted usage provenance")
        input_tokens = _required_nonnegative_int(
            usage, "prompt_tokens", error=OpenAIChatOutputError,
            location="OpenAI Chat usage",
        )
        output_tokens = _required_nonnegative_int(
            usage, "completion_tokens", error=OpenAIChatOutputError,
            location="OpenAI Chat usage",
        )
        total_tokens = _required_nonnegative_int(
            usage, "total_tokens", error=OpenAIChatOutputError,
            location="OpenAI Chat usage",
        )
        if total_tokens < input_tokens + output_tokens:
            raise OpenAIChatOutputError(
                "OpenAI Chat total_tokens is smaller than prompt + completion"
            )
        tokens = {
            "input": input_tokens,
            "output": output_tokens,
            "total": total_tokens,
        }

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=output_turns,
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "id": response_id,
                "response_id": response_id,
                "provider": self.provider,
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "system_fingerprint": _provider_field(resp, "system_fingerprint"),
                "finish_reason": finish_reason,
                "requested_seed": seed,
                "target_sampling_control": (
                    "provider_seed_requested_best_effort"
                    if seed is not None and self.supports_seed
                    else "uncontrolled"
                ),
                "provider_refusal": provider_refusal,
                "provider_refusal_category": refusal_category,
                "provider_refusal_reason": refusal_text or None,
                "generation": {
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "seed": seed if self.supports_seed else None,
                },
            },
        )


_OPENAI_SOL_PRO_MODEL = "gpt-5.6-sol"
_OPENAI_SOL_PRO_SPEC = (
    "openai-responses:gpt-5.6-sol;reasoning_mode=pro;"
    "reasoning_effort=medium;reasoning_context=current_turn"
)


class OpenAIResponsesTarget(OpenAITarget):
    """Frozen GPT-5.6 Sol Pro condition over the OpenAI Responses API.

    OpenAI exposes Pro as ``reasoning.mode='pro'`` on a GPT-5.6 model, not as
    a separate model slug.  This target intentionally has one canonical public
    identity so standard Chat Completions and the Pro condition cannot collapse
    into the same metric group.  Reasoning effort/context and the initial
    output-token budget are frozen for reproducible comparison.
    """

    name = _OPENAI_SOL_PRO_SPEC
    MAX_OUTPUT_TOKENS = 25_000
    REASONING_MODE = "pro"
    REASONING_EFFORT = "medium"
    REASONING_CONTEXT = "current_turn"

    def __init__(
        self,
        model: str = _OPENAI_SOL_PRO_MODEL,
        *,
        requested_spec: Optional[str] = None,
        timeout: float = 600.0,
        max_retries: int = 2,
        media_roots: Optional[Iterable[str | Path]] = None,
    ) -> None:
        if model != _OPENAI_SOL_PRO_MODEL:
            raise ValueError(
                "the frozen Sol Pro condition requires model 'gpt-5.6-sol'"
            )
        if requested_spec is not None and requested_spec != _OPENAI_SOL_PRO_SPEC:
            raise ValueError(
                "the Sol Pro target must use the canonical spec "
                f"{_OPENAI_SOL_PRO_SPEC!r}"
            )
        super().__init__(
            model,
            max_tokens=self.MAX_OUTPUT_TOKENS,
            provider="openai",
            requested_spec=_OPENAI_SOL_PRO_SPEC,
            temperature=0.0,
            timeout=timeout,
            max_retries=max_retries,
            media_roots=media_roots,
            supports_seed=False,
        )
        self.api_surface = "responses"
        self.max_output_tokens = self.MAX_OUTPUT_TOKENS
        self.reasoning_mode = self.REASONING_MODE
        self.reasoning_effort = self.REASONING_EFFORT
        self.reasoning_context = self.REASONING_CONTEXT
        self.store = False
        self.truncation = "disabled"

    def _to_responses_input(
        self, dialog: list[DialogTurn]
    ) -> list[dict[str, Any]]:
        """Render recorded turns as Responses easy-input messages."""
        if not dialog:
            raise ValueError("OpenAI Responses input dialog must not be empty")
        rendered: list[dict[str, Any]] = []
        for turn in dialog:
            role = {
                "system": "developer",
                "tool": "user",
                "env": "user",
            }.get(turn.role, turn.role)
            parts: list[dict[str, Any]] = []
            if turn.content:
                parts.append({"type": "input_text", "text": turn.content})
            parts.extend(
                {"type": "input_text", "text": text}
                for text in _recorded_trace_text(turn)
            )
            for media in turn.media:
                if media.modality != "image":
                    raise ValueError(
                        "OpenAIResponsesTarget cannot render "
                        f"{media.modality!r} media"
                    )
                mime, data, url = _encode_media(
                    media, allowed_roots=self.media_roots
                )
                parts.append({
                    "type": "input_image",
                    "image_url": url or f"data:{mime};base64,{data}",
                })
            if not parts:
                raise ValueError(
                    f"OpenAI Responses cannot render empty {turn.role!r} turn"
                )
            content: Any
            if len(parts) == 1 and parts[0]["type"] == "input_text":
                content = parts[0]["text"]
            else:
                content = parts
            rendered.append({"role": role, "content": content})
        return rendered

    @staticmethod
    def _extract_completed_output(
        resp: Any,
    ) -> tuple[str, bool, int, int, int]:
        output = _provider_field(resp, "output")
        if not isinstance(output, (list, tuple)):
            raise OpenAIResponsesOutputError(
                "OpenAI Responses completed without an output-item list"
            )
        text_blocks: list[str] = []
        refusal_blocks: list[str] = []
        reasoning_item_count = 0
        message_item_count = 0
        for item in output:
            item_type = _provider_field(item, "type")
            if item_type == "reasoning":
                item_id = _provider_field(item, "id")
                if not isinstance(item_id, str) or not item_id.strip():
                    raise OpenAIResponsesOutputError(
                        "OpenAI Responses reasoning item omitted its id"
                    )
                item_status = _provider_field(item, "status")
                if item_status not in (None, "completed"):
                    raise OpenAIResponsesOutputError(
                        "OpenAI Responses contains non-completed reasoning output"
                    )
                reasoning_item_count += 1
                continue
            if item_type != "message":
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses returned an unexpected output item "
                    f"of type {item_type!r} without any tools enabled"
                )
            message_id = _provider_field(item, "id")
            if not isinstance(message_id, str) or not message_id.strip():
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses output message omitted its id"
                )
            message_item_count += 1
            if _provider_field(item, "role") != "assistant":
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses output message is not an assistant message"
                )
            if _provider_field(item, "status") != "completed":
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses contains a non-completed output message"
                )
            content = _provider_field(item, "content")
            if not isinstance(content, (list, tuple)):
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses output message has no content-item list"
                )
            for part in content:
                part_type = _provider_field(part, "type")
                if part_type == "output_text":
                    value = _provider_field(part, "text")
                    if not isinstance(value, str):
                        raise OpenAIResponsesOutputError(
                            "OpenAI Responses output_text is not a string"
                        )
                    text_blocks.append(value)
                elif part_type == "refusal":
                    value = _provider_field(part, "refusal")
                    if not isinstance(value, str):
                        raise OpenAIResponsesOutputError(
                            "OpenAI Responses refusal is not a string"
                        )
                    refusal_blocks.append(value)
                else:
                    raise OpenAIResponsesOutputError(
                        "OpenAI Responses message contains unsupported content "
                        f"type {part_type!r}"
                    )

        if reasoning_item_count < 1:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses Pro output omitted its reasoning item"
            )
        if message_item_count != 1:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses Pro output must contain exactly one final message"
            )
        text = "".join(text_blocks)
        refusal = "\n".join(refusal_blocks)
        try:
            convenience_text = _provider_field(resp, "output_text")
        except Exception as exc:  # malformed SDK object/property
            raise OpenAIResponsesOutputError(
                "OpenAI Responses output_text aggregation failed"
            ) from exc
        if convenience_text not in (None, ""):
            if not isinstance(convenience_text, str) or convenience_text != text:
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses output_text disagrees with output items"
                )
        if text.strip() and refusal.strip():
            raise OpenAIResponsesOutputError(
                "OpenAI Responses returned both text and an explicit refusal"
            )
        if refusal.strip():
            return (
                refusal,
                True,
                len(output),
                reasoning_item_count,
                message_item_count,
            )
        if not text.strip():
            raise OpenAIResponsesOutputError(
                "OpenAI Responses completed without text or explicit refusal"
            )
        return (
            text,
            False,
            len(output),
            reasoning_item_count,
            message_item_count,
        )

    def _validated_reasoning(self, resp: Any) -> dict[str, str]:
        reasoning = _provider_field(resp, "reasoning")
        if reasoning is None:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses omitted effective reasoning provenance"
            )
        expected = {
            "mode": self.reasoning_mode,
            "effort": self.reasoning_effort,
            "context": self.reasoning_context,
        }
        effective: dict[str, str] = {}
        for field, wanted in expected.items():
            actual = _provider_field(reasoning, field)
            if actual != wanted:
                raise OpenAIResponsesOutputError(
                    f"OpenAI Responses effective reasoning.{field} was "
                    f"{actual!r}, expected {wanted!r}"
                )
            effective[field] = actual
        return effective

    @staticmethod
    def _usage_tokens(resp: Any) -> dict[str, int]:
        usage = _provider_field(resp, "usage")
        if usage is None:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses completed without usage provenance"
            )
        output_details = _provider_field(usage, "output_tokens_details")
        if output_details is None:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses omitted output token details"
            )
        tokens = {
            "input": _required_usage_count(
                usage, "input_tokens", location="usage"
            ),
            "output": _required_usage_count(
                usage, "output_tokens", location="usage"
            ),
            "total": _required_usage_count(
                usage, "total_tokens", location="usage"
            ),
            "reasoning": _required_usage_count(
                output_details,
                "reasoning_tokens",
                location="usage.output_tokens_details",
            ),
        }
        if tokens["total"] != tokens["input"] + tokens["output"]:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses usage total disagrees with input plus output"
            )
        if tokens["reasoning"] > tokens["output"]:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses reasoning tokens exceed output tokens"
            )
        input_details = _provider_field(usage, "input_tokens_details")
        if input_details is not None:
            for provider_name, artifact_name in (
                ("cached_tokens", "cached_input"),
                ("cache_write_tokens", "cache_write_input"),
            ):
                value = _provider_field(input_details, provider_name)
                if value is not None:
                    tokens[artifact_name] = _required_usage_count(
                        input_details,
                        provider_name,
                        location="usage.input_tokens_details",
                    )
                    if tokens[artifact_name] > tokens["input"]:
                        raise OpenAIResponsesOutputError(
                            f"OpenAI Responses {artifact_name} exceeds input tokens"
                        )
        return tokens

    @staticmethod
    def _provider_usage(resp: Any) -> dict[str, Any]:
        """Retain the Responses API usage field names without flattening them."""
        usage = _provider_field(resp, "usage")
        input_details = _provider_field(usage, "input_tokens_details")
        output_details = _provider_field(usage, "output_tokens_details")
        return {
            "input_tokens": _provider_field(usage, "input_tokens"),
            "output_tokens": _provider_field(usage, "output_tokens"),
            "total_tokens": _provider_field(usage, "total_tokens"),
            "input_tokens_details": (
                {
                    "cached_tokens": _provider_field(
                        input_details, "cached_tokens"
                    ),
                    "cache_write_tokens": _provider_field(
                        input_details, "cache_write_tokens"
                    ),
                }
                if input_details is not None
                else None
            ),
            "output_tokens_details": (
                {
                    "reasoning_tokens": _provider_field(
                        output_details, "reasoning_tokens"
                    )
                }
                if output_details is not None
                else None
            ),
        }

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        client = self._get_client()
        rendered_input = self._to_responses_input(dialog)
        requested_reasoning = {
            "mode": self.reasoning_mode,
            "effort": self.reasoning_effort,
            "context": self.reasoning_context,
        }
        request: dict[str, Any] = {
            "model": self.model,
            "input": rendered_input,
            "reasoning": requested_reasoning,
            "max_output_tokens": self.max_output_tokens,
            "store": self.store,
            "truncation": self.truncation,
        }
        start = time.perf_counter()
        resp = client.responses.create(**request)
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_id = _provider_field(resp, "id")
        if not isinstance(response_id, str) or not response_id.strip():
            raise OpenAIResponsesOutputError(
                "OpenAI Responses completed without a response id"
            )
        if _provider_field(resp, "object") != "response":
            raise OpenAIResponsesOutputError(
                "OpenAI Responses result has a non-response object type"
            )
        status = _provider_field(resp, "status")
        if status != "completed":
            incomplete = _provider_field(resp, "incomplete_details")
            error = _provider_field(resp, "error")
            reason = (
                _provider_field(incomplete, "reason")
                or _provider_field(error, "code")
                or "unspecified"
            )
            raise OpenAIResponsesOutputError(
                f"OpenAI Responses {response_id} ended with status "
                f"{status!r} ({reason})"
            )
        if _provider_field(resp, "error") is not None:
            raise OpenAIResponsesOutputError(
                f"OpenAI Responses {response_id} completed with an error object"
            )
        if _provider_field(resp, "incomplete_details") is not None:
            raise OpenAIResponsesOutputError(
                f"OpenAI Responses {response_id} completed with incomplete details"
            )

        resolved_model = _provider_field(resp, "model")
        if (
            not isinstance(resolved_model, str)
            or not resolved_model.strip()
            or not (
                resolved_model == self.model
                or resolved_model.startswith(f"{self.model}-")
            )
        ):
            raise OpenAIResponsesOutputError(
                f"OpenAI Responses resolved unexpected model {resolved_model!r}"
            )
        effective_reasoning = self._validated_reasoning(resp)
        if _provider_field(resp, "max_output_tokens") != self.max_output_tokens:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses effective max_output_tokens disagrees with "
                "the frozen request"
            )
        if _provider_field(resp, "truncation") != self.truncation:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses effective truncation disagrees with the "
                "frozen request"
            )
        tokens = self._usage_tokens(resp)
        (
            text,
            provider_refusal,
            output_item_count,
            reasoning_item_count,
            message_item_count,
        ) = self._extract_completed_output(resp)
        output_turns = (
            []
            if provider_refusal
            else [DialogTurn(role="assistant", content=text)]
        )

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=output_turns,
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "id": response_id,
                "response_id": response_id,
                "provider_request_id": _provider_field(resp, "_request_id"),
                "provider": "openai",
                "api_surface": self.api_surface,
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "status": status,
                "service_tier": _provider_field(resp, "service_tier"),
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled_responses_api_no_seed",
                "requested_reasoning": dict(requested_reasoning),
                "reasoning": effective_reasoning,
                "usage": dict(tokens),
                "provider_usage": self._provider_usage(resp),
                "provider_refusal": provider_refusal,
                "provider_refusal_category": None,
                "provider_refusal_reason": text if provider_refusal else None,
                "output_item_count": output_item_count,
                "reasoning_item_count": reasoning_item_count,
                "message_item_count": message_item_count,
                "generation": {
                    "max_output_tokens": self.max_output_tokens,
                    "store": self.store,
                    "truncation": self.truncation,
                    "tools": "disabled",
                    "timeout_seconds": self.timeout,
                    "max_retries": self.max_retries,
                },
            },
        )


class OpenAICompatibleTarget(OpenAITarget):
    """An OpenAI-compatible Chat Completions endpoint at a different base URL and
    API key. Covers DeepSeek, Moonshot/Kimi, Zhipu/GLM, Alibaba Qwen (DashScope),
    and ByteDance Doubao (Volcano Ark). The message/image handling and response
    mapping are inherited from OpenAITarget; only the client wiring changes."""

    def __init__(
        self,
        model: str,
        base_url: str,
        key_env: str,
        max_tokens: int = 1024,
        *,
        provider: str = "openai-compatible",
        requested_spec: Optional[str] = None,
        temperature: float = 0.0,
        timeout: float = 120.0,
        max_retries: int = 2,
        media_roots: Optional[Iterable[str | Path]] = None,
        supports_seed: bool = False,
    ) -> None:
        super().__init__(
            model,
            max_tokens=max_tokens,
            provider=provider,
            requested_spec=requested_spec,
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
            media_roots=media_roots,
            supports_seed=supports_seed,
        )
        self.base_url = base_url
        self.key_env = key_env
        self.name = self.requested_spec

    def _get_client(self):
        if self._client is None:
            openai = _require("openai", f"{self.name} (OpenAI-compatible)")
            key = os.environ.get(self.key_env)
            if not key:
                raise RuntimeError(
                    f"{self.key_env} is required for {self.name}; set it in the environment")
            self._client = openai.OpenAI(
                api_key=key,
                base_url=self.base_url,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
        return self._client


class GeminiTarget(BaseTarget):
    """Google Gemini gateway via the current ``google-genai`` SDK."""

    name = "gemini"
    modality_support = ("text", "image")
    tool_serialization = "recorded_text_proxy_no_execution"

    def __init__(
        self,
        model: str,
        *,
        requested_spec: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        timeout: float = 120.0,
        media_roots: Optional[Iterable[str | Path]] = None,
        supports_seed: bool = False,
    ) -> None:
        self.model = model
        self.provider = "google"
        self.requested_spec = requested_spec or f"google:{model}"
        self.name = self.requested_spec
        self.max_tokens = int(max_tokens)
        self.temperature = float(temperature)
        self.timeout = float(timeout)
        self.media_roots = _media_roots(media_roots)
        self.supports_seed = bool(supports_seed)
        self._client = None

    def _get_client(self):
        if self._client is None:
            genai = _require("google.genai", "GeminiTarget")
            key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if not key:
                raise RuntimeError(
                    "GEMINI_API_KEY (or GOOGLE_API_KEY) is required for "
                    "GeminiTarget; set it in the environment"
                )
            self._client = genai.Client(
                api_key=key,
                http_options={"timeout": int(self.timeout * 1000)},
            )
        return self._client

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
            parts.extend(
                {"text": text} for text in _recorded_trace_text(turn)
            )
            for media in turn.media:
                if media.modality != "image":
                    raise ValueError(
                        f"GeminiTarget cannot render {media.modality!r} media"
                    )
                mime, data, url = _encode_media(
                    media, allowed_roots=self.media_roots
                )
                if data:
                    parts.append(
                        {
                            "inline_data": {
                                "mime_type": mime,
                                "data": base64.b64decode(data),
                            }
                        }
                    )
                elif url:
                    parts.append({"file_data": {"mime_type": mime, "file_uri": url}})
            contents.append({"role": role, "parts": parts})
        return system, contents

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        client = self._get_client()
        system, contents = self._to_contents(dialog)
        config: dict[str, Any] = {
            "max_output_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
        if system:
            config["system_instruction"] = system
        if seed is not None and self.supports_seed:
            config["seed"] = int(seed)

        start = time.perf_counter()
        resp = client.models.generate_content(
            model=self.model,
            contents=contents,
            config=config or None,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0

        response_id = _required_provider_string(
            resp, "response_id", error=GeminiOutputError,
            location="Gemini response",
        )
        resolved_model = _required_provider_string(
            resp, "model_version", error=GeminiOutputError,
            location="Gemini response",
        )
        if not _resolved_model_matches(self.model, resolved_model):
            raise GeminiOutputError(
                f"Gemini resolved unexpected model {resolved_model!r}"
            )
        prompt_feedback = _provider_field(resp, "prompt_feedback")
        prompt_block_reason = _enum_name(
            _provider_field(prompt_feedback, "block_reason")
            if prompt_feedback is not None else None
        )
        prompt_blocked = prompt_block_reason not in {
            None, "", "BLOCK_REASON_UNSPECIFIED",
        }
        candidates = _provider_field(resp, "candidates", [])
        if not isinstance(candidates, (list, tuple)):
            raise GeminiOutputError("Gemini response candidates is not a list")
        finish_reason: Optional[str] = None
        finish_message: Optional[str] = None
        safety_ratings: list[str] = []
        provider_refusal = False
        refusal_category: Optional[str] = None
        refusal_reason: Optional[str] = None
        if prompt_blocked:
            if candidates:
                raise GeminiOutputError(
                    "Gemini prompt block unexpectedly returned candidate output"
                )
            provider_refusal = True
            refusal_category = f"gemini_prompt_{prompt_block_reason.lower()}"
            refusal_reason = str(
                _provider_field(prompt_feedback, "block_reason_message", "") or ""
            ) or None
            output_turns: list[DialogTurn] = []
        else:
            if len(candidates) != 1:
                raise GeminiOutputError(
                    "Gemini response must contain exactly one requested candidate"
                )
            candidate = candidates[0]
            finish_reason = _enum_name(_provider_field(candidate, "finish_reason"))
            finish_message_raw = _provider_field(candidate, "finish_message")
            if finish_message_raw is not None and not isinstance(finish_message_raw, str):
                raise GeminiOutputError("Gemini finish_message is not text or null")
            finish_message = finish_message_raw
            content = _provider_field(candidate, "content")
            role = _provider_field(content, "role") if content is not None else None
            parts = _provider_field(content, "parts", []) if content is not None else []
            if role not in {None, "model"}:
                raise GeminiOutputError("Gemini candidate has a non-model role")
            if not isinstance(parts, (list, tuple)):
                raise GeminiOutputError("Gemini candidate parts is not a list")
            text_parts: list[str] = []
            for part in parts:
                part_text = _provider_field(part, "text")
                non_text = any(
                    _provider_field(part, field) is not None
                    for field in (
                        "function_call", "function_response", "inline_data",
                        "file_data", "executable_code", "code_execution_result",
                    )
                )
                if non_text:
                    raise GeminiOutputError(
                        "Gemini returned a non-text/tool part while tools were disabled"
                    )
                if part_text is not None:
                    if not isinstance(part_text, str):
                        raise GeminiOutputError("Gemini text part is not a string")
                    text_parts.append(part_text)
            text = "".join(text_parts)
            safety = _provider_field(candidate, "safety_ratings", [])
            if isinstance(safety, (list, tuple)):
                safety_ratings = [str(item) for item in safety]
            filtered_reasons = {
                "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT",
                "SPII", "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT",
                "IMAGE_RECITATION", "ESCALATION",
            }
            provider_refusal = finish_reason in filtered_reasons
            if provider_refusal:
                if text.strip():
                    raise GeminiOutputError(
                        "Gemini filtered candidate contained visible partial output"
                    )
                refusal_category = f"gemini_finish_{finish_reason.lower()}"
                refusal_reason = finish_message
                output_turns = []
            else:
                if finish_reason != "STOP":
                    raise GeminiOutputError(
                        f"Gemini candidate ended with incomplete or unexpected "
                        f"finish_reason {finish_reason!r}"
                    )
                if not text.strip():
                    raise GeminiOutputError(
                        "Gemini STOP candidate contained no visible text"
                    )
                output_turns = [DialogTurn(role="assistant", content=text)]
        usage = _provider_field(resp, "usage_metadata")
        if usage is None:
            raise GeminiOutputError("Gemini response omitted usage provenance")
        input_tokens = _required_nonnegative_int(
            usage, "prompt_token_count", error=GeminiOutputError,
            location="Gemini usage",
        )
        output_tokens = _required_nonnegative_int(
            usage, "candidates_token_count", error=GeminiOutputError,
            location="Gemini usage",
        )
        total_tokens = _required_nonnegative_int(
            usage, "total_token_count", error=GeminiOutputError,
            location="Gemini usage",
        )
        if total_tokens < input_tokens + output_tokens:
            raise GeminiOutputError(
                "Gemini total tokens is smaller than prompt + candidate tokens"
            )
        tokens = {
            "input": input_tokens,
            "output": output_tokens,
            "total": total_tokens,
        }

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=output_turns,
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "provider": self.provider,
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "response_id": response_id,
                "finish_reason": finish_reason,
                "finish_message": finish_message,
                "prompt_block_reason": prompt_block_reason,
                "safety_ratings": safety_ratings,
                "requested_seed": seed,
                "target_sampling_control": (
                    "provider_seed_requested_best_effort"
                    if seed is not None and self.supports_seed
                    else "uncontrolled"
                ),
                "provider_refusal": provider_refusal,
                "provider_refusal_category": refusal_category,
                "provider_refusal_reason": refusal_reason,
                "generation": {
                    "max_tokens": self.max_tokens,
                    "temperature": self.temperature,
                    "seed": seed if self.supports_seed else None,
                },
            },
        )


# --------------------------------------------------------------------------- #
# Registry wiring
# --------------------------------------------------------------------------- #

REGISTRY.register("mock", MockTarget, provider="mock", modality="text+image")

# Provider-documented model IDs verified for the experiment protocol snapshot.
# The list is deliberately conservative. Account-specific, preview, and newly
# released IDs remain usable through ``<provider>:<model>`` and must be captured
# verbatim in the run manifest; they are not guessed here.
_ANTHROPIC_DEFAULTS = (
    "claude-opus-5",
    "claude-sonnet-5",
    "claude-fable-5",
    "claude-haiku-4-5-20251001",
)
_OPENAI_DEFAULTS = (
    "gpt-5.1-2025-11-13",
    "gpt-5-mini-2025-08-07",
    "gpt-4.1-2025-04-14",
)
_GEMINI_DEFAULTS = (
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
)

for _mid in _ANTHROPIC_DEFAULTS:
    REGISTRY.register(
        _mid, (lambda m=_mid: AnthropicTarget(
            m, requested_spec=f"anthropic:{m}"
        )), provider="anthropic", hosted=True
    )
# The bare public Fable ID remains a convenience, but resolves to the canonical
# executable condition rather than the ordinary target that sends temperature.
REGISTRY.register(
    _ANTHROPIC_FABLE_MODEL,
    AnthropicFableTarget,
    provider="anthropic",
    hosted=True,
)
for _mid in _OPENAI_DEFAULTS:
    REGISTRY.register(
        _mid, (lambda m=_mid: OpenAITarget(
            m, requested_spec=f"openai:{m}"
        )), provider="openai", hosted=True
    )
for _mid in _GEMINI_DEFAULTS:
    REGISTRY.register(
        _mid, (lambda m=_mid: GeminiTarget(
            m, requested_spec=f"google:{m}"
        )), provider="google", hosted=True
    )

# OpenAI-compatible providers (base URL + key environment variable). Exact
# account-visible model IDs are supplied in the experiment configuration.
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

# Only DeepSeek IDs are registered as bare conveniences because its public API
# documents these exact aliases. Other providers are intentionally
# provider-qualified to avoid speculative aliases and cross-provider collisions.
_COMPAT_DEFAULTS = {
    "deepseek": ("deepseek-v4-pro", "deepseek-v4-flash"),
}
for _prov, _ids in _COMPAT_DEFAULTS.items():
    _url, _key = _COMPAT[_prov]
    for _mid in _ids:
        REGISTRY.register(
            _mid, (lambda m=_mid, u=_url, k=_key, p=_prov: OpenAICompatibleTarget(
                m, u, k, provider=p, requested_spec=f"{p}:{m}"
            )),
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
    doubao/bytedance. Examples: ``"deepseek:deepseek-v4-pro"`` or
    ``"qwen:<account-visible-id>"``. Bare IDs are limited to the conservative
    registry above.
    """
    if ":" in spec:
        provider, model = spec.split(":", 1)
        provider = provider.lower()
        if provider == "anthropic-fable":
            if spec != _ANTHROPIC_FABLE_SPEC:
                raise ValueError(
                    "the only frozen Anthropic Fable condition is "
                    f"{_ANTHROPIC_FABLE_SPEC!r}"
                )
            return AnthropicFableTarget(
                _ANTHROPIC_FABLE_MODEL, requested_spec=_ANTHROPIC_FABLE_SPEC
            )
        if provider == "openai-responses":
            if spec != _OPENAI_SOL_PRO_SPEC:
                raise ValueError(
                    "the only frozen OpenAI Responses condition is "
                    f"{_OPENAI_SOL_PRO_SPEC!r}"
                )
            return OpenAIResponsesTarget(
                _OPENAI_SOL_PRO_MODEL, requested_spec=_OPENAI_SOL_PRO_SPEC
            )
        if provider in {"anthropic", "claude"}:
            if model == _ANTHROPIC_FABLE_MODEL:
                raise ValueError(
                    "Claude Fable 5 rejects the ordinary Anthropic target's "
                    "temperature parameter; use the canonical spec "
                    f"{_ANTHROPIC_FABLE_SPEC!r}"
                )
            return AnthropicTarget(model, requested_spec=spec)
        if provider in {"openai", "gpt"}:
            return OpenAITarget(model, requested_spec=spec)
        if provider in {"google", "gemini"}:
            return GeminiTarget(model, requested_spec=spec)
        if provider in _COMPAT:
            url, key = _COMPAT[provider]
            return OpenAICompatibleTarget(
                model, url, key, provider=provider, requested_spec=spec
            )
        raise KeyError(f"unknown API provider '{provider}' in '{spec}'")
    return REGISTRY.create(spec)


__all__ = [
    "MockTarget",
    "AnthropicTarget",
    "AnthropicFableTarget",
    "AnthropicFableOutputError",
    "OpenAITarget",
    "OpenAIResponsesTarget",
    "OpenAIResponsesOutputError",
    "OpenAICompatibleTarget",
    "GeminiTarget",
    "build_api_target",
]
