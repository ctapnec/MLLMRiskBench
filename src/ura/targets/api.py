"""Hosted-API and offline-mock targets (thesis III.2.2).

Concrete :class:`~ura.targets.base.BaseTarget` implementations:

* :class:`MockTarget` - a dependency-free, deterministic model used by the test
  suite and offline demos. It refuses on a keyword heuristic and complies
  benignly otherwise, so pure-python attacker/judge paths can run end-to-end.
* :class:`AnthropicTarget`, :class:`OpenAITarget`, :class:`GeminiTarget` - thin
  gateways over the hosted SDKs. Each lazily imports its SDK, reads its API key
  from the environment, converts :class:`~ura.data_models.DialogTurn` histories
  (including supported physical :class:`~ura.data_models.MediaRef` inputs) into
  the provider format,
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
import re
import math
import mimetypes
import os
import ssl
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Optional
from urllib.parse import unquote_to_bytes, urlsplit

from ..data_models import (
    DialogTurn,
    MediaRef,
    ProviderContinuationState,
    Response,
)
from ..model_identity import (
    canonical_https_endpoint,
    canonical_https_endpoint_identity,
    canonical_provider_name,
)
from .base import REGISTRY, BaseTarget, TargetAnswerError, TargetIntegrityError

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

_NATIVE_PROVIDER_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com/v1",
    "google": "https://generativelanguage.googleapis.com",
}

_SDK_REQUEST_LOG_ENV = {
    "openai": "OPENAI_LOG",
    "anthropic": "ANTHROPIC_LOG",
}
DEFAULT_HOSTED_HTTP_ERROR_RETRIES = 3
_RETRYABLE_HTTP_STATUS_CODES = frozenset({408, 409, 425, 429})

_AttemptAdmission = Callable[[str, Mapping[str, Any], int], None]
_PROVIDER_ATTEMPT_ADMISSION: ContextVar[Optional[_AttemptAdmission]] = ContextVar(
    "ura_provider_attempt_admission", default=None
)
_PROVIDER_ATTEMPTS_USED: ContextVar[int] = ContextVar("ura_provider_attempts_used", default=0)


@contextmanager
def provider_attempt_admission(
    reserve: _AttemptAdmission, *, attempts_used: int = 0,
) -> Iterator[None]:
    """Scope a controller's durable reservation to each physical HTTP attempt.

    The callback receives provider, final request and one-based attempt number.
    It must not mutate the request. It runs before SDK invocation, including
    each retry; its exceptions stop execution without becoming retryable SDK
    errors. The owning controller supplies pricing, durable accounting and
    settlement. This hook alone is not a dollar budget or paid admission.
    Each executing thread must enter its own scope. A reviewed transport
    continuation supplies its already-used physical attempts; these consume
    the same retry allowance and are not counted as new SDK calls.
    """
    if not callable(reserve):
        raise TypeError("provider attempt admission must be callable")
    if type(attempts_used) is not int or attempts_used < 0:
        raise ValueError("used provider attempts must be a nonnegative integer")
    token = _PROVIDER_ATTEMPT_ADMISSION.set(reserve)
    used_token = _PROVIDER_ATTEMPTS_USED.set(attempts_used)
    try:
        yield
    finally:
        _PROVIDER_ATTEMPTS_USED.reset(used_token)
        _PROVIDER_ATTEMPT_ADMISSION.reset(token)


def _reject_sdk_request_logging(module: str) -> None:
    """Fail before SDK import when request-body debug logging is enabled.

    Provider SDK debug loggers can emit the complete prompt/message payload to
    stderr, which Rig Web retains as a job artifact.  The measured transport
    contract therefore admits no process-environment override for those
    loggers; operator diagnostics must use the harness' redacted call audit.
    """

    env_name = _SDK_REQUEST_LOG_ENV.get(module)
    if env_name is not None and os.environ.get(env_name, "").strip():
        raise RuntimeError(
            f"{env_name} is forbidden because provider SDK request logging may "
            "disclose prompts in durable job logs"
        )


def _sealed_ssl_context(feature: str) -> ssl.SSLContext:
    """Build a CA-verified TLS context independent of process TLS env vars."""

    certifi = _require("certifi", feature)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(certifi.where()))
    # Constructing SSLContext directly (rather than create_default_context)
    # prevents SSLKEYLOGFILE from silently enabling TLS secret logging.
    context.keylog_filename = None
    return context


def _sealed_http_client(feature: str):
    """Return an SDK-compatible sync client with environment routing disabled."""

    httpx = _require("httpx", feature)
    return httpx.Client(
        trust_env=False,
        verify=_sealed_ssl_context(feature),
    )


# Capabilities below describe what this adapter actually serializes, capped by
# the named model's documented inputs. Unknown/account-private IDs default to
# text rather than inheriting a provider-wide vision claim. This keeps a broad
# roster honest: an image/video cell is admitted only for an exact attested ID.
def canonical_api_target_identity(spec: str) -> tuple[str, str]:
    """Resolve a hosted request spelling to its executed provider/model pair.

    This is deliberately side-effect free: Builder admission can compare bare
    registry conveniences, provider aliases, and fixed Fable/Sol routes without
    constructing a client or changing the requested route retained in evidence.
    The cases mirror :func:`build_api_target` and use registry provider metadata
    for every supported bare id.
    """

    requested = spec.strip()
    if not requested:
        raise ValueError("API target identity requires a non-blank spec")
    if requested in _ANTHROPIC_FABLE_MODELS:
        return "anthropic", requested
    if requested in _ANTHROPIC_FABLE_OUTPUT_SPECS:
        return "anthropic", requested.split(":", 1)[1].split(";", 1)[0]
    if requested in _OPENAI_SOL_OUTPUT_SPECS:
        return "openai", _OPENAI_SOL_PRO_MODEL
    if ":" in requested:
        provider, model = requested.split(":", 1)
        provider = provider.strip().lower()
        model = model.strip()
        if not provider or not model:
            raise ValueError(
                "provider-qualified targets require non-blank provider/model"
            )
        if provider == "anthropic-fable":
            raise ValueError("unknown fixed Anthropic Fable target condition")
        if provider == "openai-responses":
            raise ValueError("unknown fixed OpenAI Responses target condition")
        return canonical_provider_name(provider), model
    if requested == "mock":
        return "runtime-name", requested
    provider = REGISTRY.meta(requested).get("provider")
    if not isinstance(provider, str) or not provider.strip():
        raise KeyError(f"unknown bare API target {requested!r}")
    return canonical_provider_name(provider), requested


_MODEL_ADAPTER_MODALITIES: dict[tuple[str, str], tuple[str, ...]] = {
    ("anthropic", "claude-opus-5"): ("text", "image"),
    ("anthropic", "claude-sonnet-5"): ("text", "image"),
    ("anthropic", "claude-fable-5"): ("text", "image"),
    ("anthropic", "claude-fable-5-1"): ("text", "image"),
    ("anthropic", "claude-haiku-4-5-20251001"): ("text", "image"),
    ("openai", "gpt-5.6-sol"): ("text", "image"),
    ("openai", "gpt-6-astra"): ("text", "image"),
    ("openai", "gpt-5.6-terra"): ("text", "image"),
    ("openai", "gpt-5.6-luna"): ("text", "image"),
    ("openai", "gpt-5.1-2025-11-13"): ("text", "image"),
    ("openai", "gpt-5-mini-2025-08-07"): ("text", "image"),
    ("openai", "gpt-4.1-2025-04-14"): ("text", "image"),
    # Gemini supports richer inputs and this adapter now emits all three
    # physical-media part types. Keep aliases explicit so preview drift cannot
    # silently change the experiment.
    ("google", "gemini-3.1-pro-preview"): ("text", "image", "audio", "video"),
    ("google", "gemini-3.8-flash"): ("text", "image", "audio", "video"),
    ("google", "gemini-3.6-flash"): ("text", "image", "audio", "video"),
    ("google", "gemini-3.5-flash"): ("text", "image", "audio", "video"),
    ("google", "gemini-3.5-flash-lite"): ("text", "image", "audio", "video"),
    ("deepseek", "deepseek-v4-pro"): ("text",),
    ("deepseek", "deepseek-v4-flash"): ("text",),
    ("glm", "glm-5.2"): ("text",),
    ("glm", "glm-5.1"): ("text",),
    ("kimi", "kimi-k3"): ("text", "image"),
    ("qwen", "qwen3.7-max-2026-06-08"): ("text", "image"),
    ("qwen", "qwen3.7-plus"): ("text", "image"),
}


def _adapter_modalities(provider: str, model: str) -> tuple[str, ...]:
    canonical = canonical_provider_name(provider)
    return _MODEL_ADAPTER_MODALITIES.get((canonical, model), ("text",))


def _validated_modalities(value: Iterable[str]) -> tuple[str, ...]:
    modalities = tuple(value)
    allowed = {"text", "image", "audio", "video"}
    if (
        not modalities
        or modalities[0] != "text"
        or set(modalities) - allowed
        or len(set(modalities)) != len(modalities)
    ):
        raise ValueError("target modalities require unique text[/image/audio/video]")
    return modalities


def _provider_serialized_modalities(provider: str) -> frozenset[str]:
    """Return physical inputs that the selected provider adapter can encode."""

    canonical = canonical_provider_name(provider)
    if canonical == "google":
        return frozenset({"text", "image", "audio", "video"})
    return frozenset({"text", "image"})


def _validated_provider_modalities(
    provider: str, value: Iterable[str]
) -> tuple[str, ...]:
    modalities = _validated_modalities(value)
    unsupported = set(modalities) - _provider_serialized_modalities(provider)
    if unsupported:
        raise ValueError(
            f"{provider} adapter cannot serialize declared modalities: "
            + ",".join(sorted(unsupported))
        )
    return modalities


class OpenAIResponsesOutputError(TargetAnswerError):
    """A Responses API result cannot be used as a complete model output."""


class AnthropicFableOutputError(TargetAnswerError):
    """A Fable Messages result cannot be used as a complete model output."""


class AnthropicOutputError(TargetAnswerError):
    """An Anthropic Messages result is incomplete or lacks provenance."""


class OpenAIChatOutputError(TargetAnswerError):
    """An OpenAI Chat Completions result is incomplete or lacks provenance."""


class GeminiOutputError(TargetAnswerError):
    """A Gemini GenerateContent result is incomplete or lacks provenance."""


class OpenAIResponsesIntegrityError(
    TargetIntegrityError, OpenAIResponsesOutputError,
):
    """A Responses result contradicts fixed request or model identity."""


class AnthropicFableIntegrityError(
    TargetIntegrityError, AnthropicFableOutputError,
):
    """A Fable result contradicts the admitted model identity."""


class AnthropicIntegrityError(TargetIntegrityError, AnthropicOutputError):
    """An Anthropic result contradicts the admitted model identity."""


class OpenAIChatIntegrityError(TargetIntegrityError, OpenAIChatOutputError):
    """A Chat Completions result contradicts the admitted model identity."""


class GeminiIntegrityError(TargetIntegrityError, GeminiOutputError):
    """A Gemini result contradicts the admitted model identity."""


class ProviderTransportError(TargetAnswerError):
    """A hosted request exhausted its explicit, auditable retry policy."""

    def __init__(
        self,
        message: str,
        *,
        provider: str,
        transport_attempts: list[dict[str, Any]],
    ) -> None:
        super().__init__(message, category="transport_failure")
        self.transport_attempts = list(transport_attempts)
        last = self.transport_attempts[-1] if self.transport_attempts else {}
        # Runner persists this deliberately small summary in error artifacts.
        # The detailed attempt list remains available on the immediate cause
        # without placing request payloads or credentials in the exception.
        self.call_audit = {
            "transport_attempt_count": len(self.transport_attempts),
            "logical_call_count": 1,
            "provider": provider,
            "operation": "generate",
            "status_code": last.get("status_code"),
            "error_type": last.get("error_type"),
            "provider_request_id": last.get("request_id"),
            "provider_error_code": last.get("provider_error_code"),
            "provider_error_type": last.get("provider_error_type"),
            "transport_retryable": last.get("retryable"),
        }
        if last.get("provider_funding_status"):
            self.call_audit["provider_funding_status"] = last["provider_funding_status"]


def _transport_status_code(exc: BaseException) -> int | None:
    value = getattr(exc, "status_code", None)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    # google-genai exposes HTTP status as APIError.code, not status_code.
    if type(exc).__module__.startswith("google.genai.errors"):
        value = getattr(exc, "code", None)
        if type(value) is int and 100 <= value <= 599:
            return value
    response = getattr(exc, "response", None)
    value = getattr(response, "status_code", None)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _transport_request_id(value: Any) -> str | None:
    for name in ("request_id", "_request_id"):
        request_id = getattr(value, name, None)
        if isinstance(request_id, str) and request_id.strip():
            return request_id.strip()
    return None


def _transport_error_body(exc: BaseException) -> Mapping[str, Any]:
    body = getattr(exc, "body", None)
    if body is None and type(exc).__module__.startswith("google.genai.errors"):
        body = getattr(exc, "details", None)
    if not isinstance(body, Mapping):
        return {}
    error = body.get("error", body)
    return error if isinstance(error, Mapping) else {}


def _transport_error_metadata(exc: BaseException) -> dict[str, str]:
    """Keep SDK machine codes, never provider messages or echoed requests."""
    error = _transport_error_body(exc)
    result = {}
    for key in ("code", "type"):
        value = error.get(key)
        if (isinstance(value, str)
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,99}", value)
                and not value.lower().startswith(("sk-", "bearer"))):
            result["provider_error_" + key] = value
    return result


def _provider_funding_status(exc: BaseException, provider: str) -> str | None:
    """Classify explicit billing failures without mistaking rate limits for credit loss."""
    status = _transport_status_code(exc)
    error = _transport_error_body(exc)
    code, kind = error.get("code"), error.get("type")
    if provider in {"openai", "openai-responses"} and status == 429:
        reasons = {
            "credit_balance_exhausted": "credit_balance_exhausted",
            "organization_spend_limit_exceeded": "spend_limit_reached",
            "project_spend_limit_exceeded": "spend_limit_reached",
            "organization_usage_limit_exceeded": "usage_limit_reached",
            "insufficient_quota": "funding_or_quota_unavailable",
        }
        if isinstance(code, str) and code in reasons:
            return reasons[code]
        if kind == "insufficient_quota":
            return "funding_or_quota_unavailable"
    if provider == "deepseek" and status == 402:
        return "credit_balance_exhausted"
    if provider in {"kimi", "moonshot"} and status == 429 and kind == "exceeded_current_quota_error":
        return "funding_or_account_unavailable"
    message = error.get("message")
    message = message.strip().lower() if isinstance(message, str) else ""
    if (provider in {"anthropic", "anthropic-fable"} and status == 400
            and kind == "invalid_request_error" and message.startswith("your credit balance is too low")):
        return "credit_balance_exhausted"
    if (provider == "google" and status == 429
            and message.startswith("your prepayment credits are depleted")):
        return "credit_balance_exhausted"
    return None


def _retryable_transport_error(exc: BaseException, *, provider: str = "") -> bool:
    if _provider_funding_status(exc, provider) is not None:
        return False
    status = _transport_status_code(exc)
    if status is not None:
        return status in _RETRYABLE_HTTP_STATUS_CODES or 500 <= status <= 599
    if isinstance(exc, (ConnectionError, TimeoutError)):
        return True
    # Keep provider SDKs optional. Recognize their actual typed network-error
    # ancestry, not exception text or arbitrary SDK/programming errors.
    network_types = {
        "openai": {"APIConnectionError", "APITimeoutError"},
        "anthropic": {"APIConnectionError", "APITimeoutError"},
        "httpx": {"NetworkError", "TimeoutException", "RemoteProtocolError"},
        "requests": {"ConnectionError", "Timeout"},
    }
    return any(
        cls.__name__ in network_types.get(cls.__module__.split(".", 1)[0], set())
        for cls in type(exc).__mro__
    )


def _call_with_retry(
    call: Any,
    request: dict[str, Any],
    *,
    provider: str,
    max_retries: int,
) -> tuple[Any, list[dict[str, Any]]]:
    """Run one provider call with bounded, secret-free attempt provenance."""
    audit: list[dict[str, Any]] = []
    attempts_used = _PROVIDER_ATTEMPTS_USED.get()
    if attempts_used > max_retries:
        raise ValueError("provider transport retry allowance is exhausted")
    for attempt_number in range(attempts_used + 1, max_retries + 2):
        admission = _PROVIDER_ATTEMPT_ADMISSION.get()
        if admission is not None:
            admission(provider, request, attempt_number)
        started = time.perf_counter()
        try:
            result = call(**request)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            retryable = _retryable_transport_error(exc, provider=provider)
            funding_status = _provider_funding_status(exc, provider)
            audit.append({
                "attempt": attempt_number,
                "outcome": "error",
                "error_type": type(exc).__name__,
                "status_code": _transport_status_code(exc),
                "request_id": _transport_request_id(exc),
                "retryable": retryable,
                **_transport_error_metadata(exc),
                **({"provider_funding_status": funding_status} if funding_status else {}),
                "latency_ms": elapsed_ms,
            })
            if not retryable or attempt_number > max_retries:
                raise ProviderTransportError(
                    f"{provider} transport failed after {attempt_number} attempt(s): "
                    f"{type(exc).__name__}",
                    provider=provider,
                    transport_attempts=audit,
                ) from exc
            time.sleep(0.5 * (2 ** (attempt_number - 1)))
            continue
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        audit.append({
            "attempt": attempt_number,
            "outcome": "success",
            "error_type": None,
            "status_code": None,
            "request_id": _transport_request_id(result),
            "retryable": None,
            "latency_ms": elapsed_ms,
        })
        return result, audit
    raise AssertionError("unreachable provider retry loop")


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
#: Video releases legitimately exceed the image/audio bound; mirrors the
#: converter-side DEFAULT_MAX_VIDEO_ASSET_BYTES. Provider-side request limits
#: still apply downstream and fail per item, visibly.
_MAX_VIDEO_MEDIA_BYTES = 64 * 1024 * 1024
_MEDIA_ROOT_ALIAS_PREFIX = "@media-root/"


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


def _resolve_local_media_path(
    value: str, roots: tuple[Path, ...]
) -> tuple[Path, int]:
    """Resolve an absolute input or portable ``@media-root/<n>/...`` alias."""
    if value.startswith(_MEDIA_ROOT_ALIAS_PREFIX):
        suffix = value[len(_MEDIA_ROOT_ALIAS_PREFIX):]
        index_text, separator, relative_text = suffix.partition("/")
        if (
            not separator
            or not index_text.isdigit()
            or not relative_text
            or int(index_text) >= len(roots)
        ):
            raise ValueError("invalid logical media-root alias")
        relative = PurePosixPath(relative_text)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("logical media-root alias escapes its approved root")
        root_index = int(index_text)
        root = roots[root_index]
        path = root.joinpath(*relative.parts).resolve(strict=True)
        if path != root and root not in path.parents:
            raise PermissionError("logical media-root alias escapes approved root")
        return path, root_index

    path = Path(value).expanduser().resolve(strict=True)
    matches = [
        (index, root) for index, root in enumerate(roots)
        if path == root or root in path.parents
    ]
    if not matches:
        raise PermissionError(f"media path is outside approved roots: {path}")
    # Prefer the narrowest containing root; retain its configured index in the
    # alias so rebinding does not depend on an absolute workstation path.
    root_index, _ = max(matches, key=lambda item: len(item[1].parts))
    return path, root_index


def _logical_media_root_alias(
    path: Path, root_index: int, roots: tuple[Path, ...]
) -> str:
    relative = path.relative_to(roots[root_index]).as_posix()
    if not relative or relative == ".":
        raise ValueError("media reference must name a file below its approved root")
    return f"{_MEDIA_ROOT_ALIAS_PREFIX}{root_index}/{relative}"


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
    max_bytes: Optional[int] = None,
) -> tuple[str, str, Optional[str]]:
    """Return ``(mime, base64_data_or_empty, url_or_none)`` for physical media.

    Local reads are hash-verified and constrained to an explicit root allow-list.
    Inline ``data:`` URIs are decoded and hash-verified. Remote references must
    use HTTPS and contain no embedded credentials.
    """
    if media.modality not in {"image", "audio", "video"}:
        raise ValueError(f"target cannot encode {media.modality!r} media")
    if max_bytes is None:
        max_bytes = (
            _MAX_VIDEO_MEDIA_BYTES
            if media.modality == "video"
            else _MAX_MEDIA_BYTES
        )
    mime_prefix = f"{media.modality}/"
    default_mime = {
        "image": "image/png",
        "audio": "audio/wav",
        "video": "video/mp4",
    }[media.modality]
    if bool(media.path) == bool(media.uri):
        raise ValueError("MediaRef must contain exactly one of path or uri")
    if media.path:
        roots = _media_roots(allowed_roots)
        if not roots:
            raise PermissionError(
                "local media upload is disabled; configure media_roots or URA_MEDIA_ROOTS"
            )
        path, _root_index = _resolve_local_media_path(media.path, roots)
        if not path.is_file():
            raise ValueError(f"media path is not a regular file: {path}")
        if path.stat().st_size > max_bytes:
            raise ValueError(f"media exceeds {max_bytes} byte limit: {path}")
        raw = path.read_bytes()
        _verify_hash(raw, media.sha256, str(path))
        mime = media.mime or mimetypes.guess_type(str(path))[0] or default_mime
        if not mime.startswith(mime_prefix):
            raise ValueError(
                f"unsupported {media.modality} MIME type {mime!r}: {path}"
            )
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
            if not mime.startswith(mime_prefix):
                raise ValueError(
                    f"unsupported inline {media.modality} MIME type {mime!r}"
                )
            return mime, base64.b64encode(raw).decode("ascii"), None
        parsed = urlsplit(media.uri)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise ValueError("remote media URI must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("remote media URI must not contain credentials")
        mime = media.mime or mimetypes.guess_type(parsed.path)[0] or default_mime
        if not mime.startswith(mime_prefix):
            raise ValueError(
                f"unsupported remote {media.modality} MIME type {mime!r}"
            )
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


def _validated_anthropic_thinking_blocks(
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate the exact provider-native continuation projection for Fable."""
    validated: list[dict[str, Any]] = []
    for block in blocks:
        block_type = block.get("type")
        if block_type == "thinking":
            # Omitted thinking is a valid empty string. The opaque signature
            # still carries the provider's continuation state and is required.
            if (
                set(block) != {"type", "thinking", "signature"}
                or not isinstance(block.get("thinking"), str)
                or not isinstance(block.get("signature"), str)
                or not block["signature"].strip()
            ):
                raise ValueError("invalid Anthropic thinking continuation block")
        elif block_type == "redacted_thinking":
            if (
                set(block) != {"type", "data"}
                or not isinstance(block.get("data"), str)
                or not str(block["data"]).strip()
            ):
                raise ValueError("invalid Anthropic redacted-thinking block")
        else:
            raise ValueError(
                f"unsupported Anthropic thinking continuation type {block_type!r}"
            )
        validated.append(dict(block))
    encoded = json.dumps(
        validated, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > 2 * 1024 * 1024:
        raise ValueError("Anthropic thinking continuation exceeds 2 MiB")
    return validated


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
    evidence_class = "synthetic"
    # The offline mock is the universal stand-in for bounded dry-run and
    # source-conformance observations, so it accepts every physical modality
    # (it reads only the last user text and never processes the media bytes).
    modality_support = ("text", "image", "audio", "video")

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
    accepts_provider_thinking = False

    def __init__(
        self,
        model: str,
        max_tokens: int = 1024,
        *,
        requested_spec: Optional[str] = None,
        temperature: float | None = 0.0,
        timeout: float = 120.0,
        max_retries: int = DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        media_roots: Optional[Iterable[str | Path]] = None,
        modality_support: Optional[Iterable[str]] = None,
        adaptive_thinking: bool = False,
        effort: str | None = None,
    ) -> None:
        self.model = model
        self.provider = "anthropic"
        self.base_url = _NATIVE_PROVIDER_ENDPOINTS["anthropic"]
        self.requested_spec = requested_spec or f"anthropic:{model}"
        self.name = self.requested_spec
        self.max_tokens = max_tokens
        self.temperature = None if temperature is None else float(temperature)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        # SDK retries are opaque to the harness budget and provenance. Disable
        # them and perform any configured retries through `_call_with_retry`.
        self.sdk_max_retries = 0
        self.max_transport_attempts_per_call = self.max_retries + 1
        self.media_roots = _media_roots(media_roots)
        self.modality_support = _validated_provider_modalities(
            "anthropic",
            modality_support or _adapter_modalities("anthropic", model)
        )
        self.modality_combinations = tuple(
            [("text",)]
            + [
                ("text", modality)
                for modality in ("image", "audio", "video")
                if modality in self.modality_support
            ]
        )
        self.accepts_provider_thinking = bool(adaptive_thinking)
        self.adaptive_thinking = bool(adaptive_thinking)
        if effort is not None and effort not in {
            "low", "medium", "high", "xhigh", "max"
        }:
            raise ValueError("Anthropic effort must be low/medium/high/xhigh/max")
        if effort is not None and not self.adaptive_thinking:
            raise ValueError("Anthropic effort requires adaptive thinking")
        if self.adaptive_thinking and self.temperature is not None:
            raise ValueError("Anthropic adaptive thinking requires omitted temperature")
        self.effort = effort
        self._client = None

    def _get_client(self):
        if self._client is None:
            _reject_sdk_request_logging("anthropic")
            anthropic = _require("anthropic", "AnthropicTarget")
            key = os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise RuntimeError(
                    "ANTHROPIC_API_KEY is required for AnthropicTarget; "
                    "set it in the environment"
                )
            self._client = anthropic.Anthropic(
                api_key=key,
                base_url=self.base_url,
                http_client=_sealed_http_client("AnthropicTarget transport"),
                timeout=self.timeout,
                max_retries=self.sdk_max_retries,
            )
        return self._client

    def _to_messages(
        self, dialog: list[DialogTurn]
    ) -> tuple[Optional[str], list[dict[str, Any]]]:
        """Split ``dialog`` into an Anthropic system string and message blocks."""
        system: Optional[str] = None
        messages: list[dict[str, Any]] = []
        for turn in dialog:
            if turn.provider_state is not None:
                raise ValueError(
                    "Anthropic Messages cannot consume OpenAI provider state"
                )
            if turn.provider_thinking and not self.accepts_provider_thinking:
                raise ValueError(
                    "generic Anthropic target cannot consume provider thinking; "
                    "use the matching Fable target"
                )
            if turn.role == "system":
                if system is not None:
                    raise ValueError(
                        "Anthropic Messages accepts exactly one system turn"
                    )
                if (
                    not (turn.content or "").strip()
                    or turn.media
                    or turn.tool_call is not None
                    or turn.tool_result is not None
                    or turn.provider_thinking
                ):
                    raise ValueError(
                        "Anthropic system turn must be non-empty plain text"
                    )
                system = turn.content
                continue
            role = "assistant" if turn.role == "assistant" else "user"
            blocks: list[dict[str, Any]] = []
            if role == "assistant" and turn.provider_thinking:
                # Return preserved thinking blocks unchanged (signatures intact),
                # ahead of the visible text, per the extended-thinking contract.
                blocks.extend(
                    _validated_anthropic_thinking_blocks(turn.provider_thinking)
                )
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
                if "image" not in self.modality_support:
                    raise ValueError(
                        f"Anthropic model {self.model!r} is not attested for image input"
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
        if not messages:
            raise ValueError("AnthropicTarget requires at least one non-system message")
        return system, messages

    def build_request(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Build the exact generation request without a client or network call."""
        system, messages = self._to_messages(dialog)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
        }
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        if self.adaptive_thinking:
            kwargs["thinking"] = {"type": "adaptive"}
            kwargs["output_config"] = {"effort": self.effort or "high"}
        if system:
            kwargs["system"] = system
        return kwargs

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        kwargs = self.build_request(dialog, seed=seed)
        client = self._get_client()
        start = time.perf_counter()
        resp, transport_attempts = _call_with_retry(
            client.messages.create,
            kwargs,
            provider=self.provider,
            max_retries=self.max_retries,
        )
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
            raise AnthropicIntegrityError(
                f"Anthropic resolved unexpected model {resolved_model!r}"
            )
        content = _provider_field(resp, "content")
        if not isinstance(content, (list, tuple)):
            raise AnthropicOutputError("Anthropic response content is not a block list")
        text_parts: list[str] = []
        thinking_blocks: list[dict[str, Any]] = []
        saw_text = False
        for block in content:
            block_type = _provider_field(block, "type")
            if block_type == "text":
                part = _provider_field(block, "text")
                if not isinstance(part, str):
                    raise AnthropicOutputError(
                        "Anthropic text block lacks string text"
                    )
                saw_text = True
                text_parts.append(part)
                continue
            if not self.adaptive_thinking or block_type not in {
                "thinking", "redacted_thinking"
            }:
                raise AnthropicOutputError(
                    "Anthropic returned unsupported content block "
                    f"{block_type!r} for this execution condition"
                )
            if saw_text:
                raise AnthropicOutputError(
                    "Anthropic returned thinking after visible text"
                )
            if block_type == "thinking":
                thinking_blocks.append({
                    "type": "thinking",
                    "thinking": _provider_field(block, "thinking"),
                    "signature": _provider_field(block, "signature"),
                })
            else:
                thinking_blocks.append({
                    "type": "redacted_thinking",
                    "data": _provider_field(block, "data"),
                })
        if thinking_blocks:
            try:
                thinking_blocks = _validated_anthropic_thinking_blocks(
                    thinking_blocks
                )
            except ValueError as exc:
                raise AnthropicOutputError(str(exc)) from exc
        text = "".join(text_parts)
        stop_reason = _provider_field(resp, "stop_reason")
        provider_refusal = stop_reason == "refusal"
        if provider_refusal:
            # Anthropic documents typed refusals both before and during a
            # generation. Partial text/thinking is not a model answer and must
            # be discarded rather than turning the refusal into a failed cell.
            output_turns: list[DialogTurn] = []
        else:
            if stop_reason not in {"end_turn", "max_tokens"}:
                raise AnthropicOutputError(
                    f"Anthropic response ended with incomplete or unexpected "
                    f"stop_reason {stop_reason!r}"
                )
            if not text.strip():
                raise AnthropicOutputError(
                    "Anthropic end_turn response contained no visible text"
                )
            output_turns = [DialogTurn(
                role="assistant",
                content=text,
                provider_thinking=thinking_blocks,
            )]
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
                "endpoint_identity": (
                    canonical_https_endpoint_identity(self.base_url)
                    if isinstance(getattr(self, "base_url", None), str)
                    else None
                ),
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "stop_reason": stop_reason,
                "output_truncated": stop_reason == "max_tokens",
                "stop_sequence": _provider_field(resp, "stop_sequence"),
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled",
                "provider_refusal": provider_refusal,
                "provider_refusal_category": (
                    "anthropic_stop_reason_refusal" if provider_refusal else None
                ),
                "provider_refusal_reason": None,
                "discarded_partial_text_blocks": (
                    len(text_parts) if provider_refusal else 0
                ),
                "discarded_partial_thinking_blocks": (
                    len(thinking_blocks) if provider_refusal else 0
                ),
                "transport_attempt_count": len(transport_attempts),
                "transport_attempts": transport_attempts,
                "generation": {
                    "temperature": (
                        self.temperature
                        if self.temperature is not None
                        else "omitted"
                    ),
                    "max_tokens": self.max_tokens,
                    "max_retries": self.max_retries,
                    "thinking": (
                        "adaptive" if self.adaptive_thinking else "disabled"
                    ),
                    "effort": self.effort,
                },
            },
        )


_ANTHROPIC_FABLE_MODEL = "claude-fable-5"
_ANTHROPIC_FABLE_51_MODEL = "claude-fable-5-1"
_ANTHROPIC_FABLE_MODELS = frozenset({_ANTHROPIC_FABLE_MODEL, _ANTHROPIC_FABLE_51_MODEL})
_ANTHROPIC_FABLE_SPEC = (
    "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000"
)
_ANTHROPIC_FABLE_BUDGET_SPEC = (
    "anthropic-fable:claude-fable-5;effort=high;max_tokens=4096"
)
_ANTHROPIC_FABLE_8192_SPEC = (
    "anthropic-fable:claude-fable-5;effort=high;max_tokens=8192"
)
_ANTHROPIC_FABLE_51_SPEC = (
    "anthropic-fable:claude-fable-5-1;effort=high;max_tokens=8192"
)
_ANTHROPIC_FABLE_OUTPUT_SPECS = {
    _ANTHROPIC_FABLE_SPEC: 25_000,
    _ANTHROPIC_FABLE_BUDGET_SPEC: 4_096,
    _ANTHROPIC_FABLE_8192_SPEC: 8_192,
    _ANTHROPIC_FABLE_51_SPEC: 8_192,
}


class AnthropicFableTarget(AnthropicTarget):
    """Exact Claude Fable 5/5.1 high-effort adaptive-thinking conditions."""

    name = _ANTHROPIC_FABLE_SPEC
    MAX_TOKENS = 25_000
    BUDGET_SPEC = _ANTHROPIC_FABLE_BUDGET_SPEC
    BUDGET_MAX_TOKENS = 4_096
    OUTPUT_8192_SPEC = _ANTHROPIC_FABLE_8192_SPEC
    FABLE_51_SPEC = _ANTHROPIC_FABLE_51_SPEC
    EFFORT = "high"
    THINKING_TYPE = "adaptive"
    accepts_provider_thinking = True

    def __init__(
        self,
        model: str = _ANTHROPIC_FABLE_MODEL,
        *,
        requested_spec: Optional[str] = None,
        timeout: float = 600.0,
        max_retries: int = DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        media_roots: Optional[Iterable[str | Path]] = None,
    ) -> None:
        if model not in _ANTHROPIC_FABLE_MODELS:
            raise ValueError(
                "the fixed Fable condition requires an exact supported Fable model"
            )
        selected_spec = requested_spec or (
            _ANTHROPIC_FABLE_SPEC if model == _ANTHROPIC_FABLE_MODEL
            else _ANTHROPIC_FABLE_51_SPEC
        )
        if requested_spec is not None and requested_spec not in _ANTHROPIC_FABLE_OUTPUT_SPECS:
            raise ValueError(
                "the Fable target must use the canonical spec "
                f"{_ANTHROPIC_FABLE_SPEC!r}"
            )
        if selected_spec.split(":", 1)[1].split(";", 1)[0] != model:
            raise ValueError("the Fable model and exact condition disagree")
        super().__init__(
            model,
            max_tokens=_ANTHROPIC_FABLE_OUTPUT_SPECS[selected_spec],
            requested_spec=selected_spec,
            timeout=timeout,
            max_retries=max_retries,
            media_roots=media_roots,
        )
        # Fable rejects non-default sampling parameters.  ``None`` documents
        # omission in the component snapshot; generate() never sends it.
        self.temperature = None
        self.accepts_provider_thinking = True
        self.effort = self.EFFORT
        self.thinking_type = self.THINKING_TYPE
        self.sdk_max_retries = 0

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
    def _visible_text(
        resp: Any, *, continuation_required: bool = True
    ) -> tuple[str, list[dict[str, Any]]]:
        content = _provider_field(resp, "content")
        if not isinstance(content, (list, tuple)):
            raise AnthropicFableOutputError(
                "Anthropic Fable response content is not a block list"
            )
        text_blocks: list[str] = []
        thinking_blocks: list[dict[str, Any]] = []
        saw_text = False
        for block in content:
            block_type = _provider_field(block, "type")
            if block_type == "text":
                value = _provider_field(block, "text")
                if not isinstance(value, str):
                    raise AnthropicFableOutputError(
                        "Anthropic Fable text block is not a string"
                    )
                saw_text = True
                text_blocks.append(value)
            elif block_type == "thinking":
                if saw_text and continuation_required:
                    raise AnthropicFableOutputError(
                        "Anthropic Fable returned thinking after visible text"
                    )
                # Preserve the verbatim thinking block (including its signature)
                # so a multi-turn continuation returns it to the provider
                # unchanged, rather than discarding the model's reasoning.
                thinking_blocks.append({
                    "type": "thinking",
                    "thinking": _provider_field(block, "thinking"),
                    "signature": _provider_field(block, "signature"),
                })
            elif block_type == "redacted_thinking":
                if saw_text and continuation_required:
                    raise AnthropicFableOutputError(
                        "Anthropic Fable returned redacted thinking after visible text"
                    )
                thinking_blocks.append({
                    "type": "redacted_thinking",
                    "data": _provider_field(block, "data"),
                })
            else:
                raise AnthropicFableOutputError(
                    "Anthropic Fable returned unsupported content block "
                    f"{block_type!r} without any tools enabled"
                )
        if continuation_required:
            try:
                thinking_blocks = _validated_anthropic_thinking_blocks(
                    thinking_blocks
                )
            except ValueError as exc:
                raise AnthropicFableOutputError(str(exc)) from exc
        else:
            # Typed mid-generation refusals discard partial output.  Do not
            # impose continuation-only signature/nonblank requirements on data
            # that will never be returned to the provider, but still bound the
            # parsed provider material before counting it.
            try:
                encoded = json.dumps(
                    {"text": text_blocks, "thinking": thinking_blocks},
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise AnthropicFableOutputError(
                    "Anthropic Fable partial refusal output is not bounded JSON"
                ) from exc
            if len(encoded) > 2 * 1024 * 1024:
                raise AnthropicFableOutputError(
                    "Anthropic Fable partial refusal output exceeds 2 MiB"
                )
        return "".join(text_blocks), thinking_blocks

    def build_request(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Preview the fixed Fable request without constructing its SDK client."""
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
        return kwargs

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        kwargs = self.build_request(dialog, seed=seed)
        client = self._get_client()
        start = time.perf_counter()
        resp, transport_attempts = _call_with_retry(
            client.messages.create,
            kwargs,
            provider="anthropic-fable",
            max_retries=self.max_retries,
        )
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
                or re.fullmatch(re.escape(self.model) + r"-\d{8}", resolved_model)
            )
        ):
            raise AnthropicFableIntegrityError(
                f"Anthropic Fable resolved unexpected model {resolved_model!r}"
            )
        stop_reason = _provider_field(resp, "stop_reason")
        stop_details = _provider_field(resp, "stop_details")
        stop_sequence = _provider_field(resp, "stop_sequence")
        text, thinking_blocks = self._visible_text(
            resp, continuation_required=stop_reason != "refusal"
        )
        thinking_block_count = len(thinking_blocks)
        tokens = self._usage_tokens(resp)

        provider_refusal = stop_reason == "refusal"
        refusal_category: Optional[str] = None
        refusal_reason: Optional[str] = None
        discarded_partial_text_sha256: Optional[str] = None
        discarded_partial_text_bytes = 0
        discarded_partial_thinking_blocks = 0
        if provider_refusal:
            # A Fable classifier may refuse either before generation or while a
            # response is already in flight. Anthropic requires clients to
            # discard partial output and handle both cases as typed refusals.
            if text:
                encoded_partial = text.encode("utf-8")
                discarded_partial_text_sha256 = hashlib.sha256(
                    encoded_partial
                ).hexdigest()
                discarded_partial_text_bytes = len(encoded_partial)
            discarded_partial_thinking_blocks = thinking_block_count
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
            if stop_reason not in {"end_turn", "max_tokens"}:
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
        continuation_json = (
            None
            if provider_refusal
            else json.dumps(
                thinking_blocks,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
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
                "provider": "anthropic",
                "endpoint_identity": canonical_https_endpoint_identity(
                    self.base_url
                ),
                "api_surface": "messages",
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "stop_reason": stop_reason,
                "output_truncated": stop_reason == "max_tokens",
                "stop_sequence": stop_sequence,
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled_anthropic_no_seed",
                "provider_refusal": provider_refusal,
                "provider_refusal_category": refusal_category,
                "provider_refusal_reason": refusal_reason,
                "provider_refusal_partial_output_discarded": bool(
                    discarded_partial_text_bytes
                    or discarded_partial_thinking_blocks
                ),
                "discarded_partial_text_sha256": discarded_partial_text_sha256,
                "discarded_partial_text_bytes": discarded_partial_text_bytes,
                "discarded_partial_thinking_blocks": (
                    discarded_partial_thinking_blocks
                ),
                "thinking_block_count": thinking_block_count,
                "continuation_state_sha256": (
                    hashlib.sha256(continuation_json).hexdigest()
                    if continuation_json is not None else None
                ),
                "continuation_state_bytes": (
                    len(continuation_json) if continuation_json is not None else 0
                ),
                "transport_attempt_count": len(transport_attempts),
                "transport_attempts": transport_attempts,
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
        temperature: float | None = 0.0,
        timeout: float = 120.0,
        max_retries: int = DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        media_roots: Optional[Iterable[str | Path]] = None,
        supports_seed: bool = True,
        modality_support: Optional[Iterable[str]] = None,
        reasoning_effort: str | None = None,
    ) -> None:
        if reasoning_effort is not None and (
            (canonical_provider_name(provider), model) not in {
                ("kimi", "kimi-k3"), ("deepseek", "deepseek-v4-pro"), ("deepseek", "deepseek-v4-flash")}
            or reasoning_effort not in {"low", "high", "max"}
        ):
            raise ValueError("reasoning_effort supports Kimi K3 and DeepSeek V4 low/high/max only")
        self.reasoning_effort = reasoning_effort
        self.model = model
        self.provider = provider
        if canonical_provider_name(provider) == "openai":
            self.base_url = _NATIVE_PROVIDER_ENDPOINTS["openai"]
        self.requested_spec = requested_spec or f"{provider}:{model}"
        self.name = self.requested_spec
        self.max_tokens = max_tokens
        self.temperature = None if temperature is None else float(temperature)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        # Keep the SDK at one HTTP attempt; the wrapper below owns retries and
        # records each one for the global billable-attempt ceiling.
        self.sdk_max_retries = 0
        self.max_transport_attempts_per_call = self.max_retries + 1
        self.media_roots = _media_roots(media_roots)
        self.supports_seed = bool(supports_seed) and model != "gpt-6-astra"
        self.modality_support = _validated_provider_modalities(
            provider,
            modality_support or _adapter_modalities(provider, model)
        )
        self.modality_combinations = tuple(
            [("text",)]
            + [
                ("text", modality)
                for modality in ("image", "audio", "video")
                if modality in self.modality_support
            ]
        )
        self._client = None

    def _get_client(self):
        if self._client is None:
            _reject_sdk_request_logging("openai")
            openai = _require("openai", "OpenAITarget")
            key = os.environ.get("OPENAI_API_KEY")
            if not key:
                raise RuntimeError(
                    "OPENAI_API_KEY is required for OpenAITarget; "
                    "set it in the environment"
                )
            self._client = openai.OpenAI(
                api_key=key,
                # Empty explicit values prevent the SDK from inheriting
                # OPENAI_ORG_ID / OPENAI_PROJECT_ID.  Inheriting either can
                # select an unreviewed billing project on native routes and
                # leak OpenAI account identifiers to compatible providers.
                organization="",
                project="",
                base_url=self.base_url,
                http_client=_sealed_http_client("OpenAITarget transport"),
                timeout=self.timeout,
                max_retries=self.sdk_max_retries,
            )
        return self._client

    def _to_messages(self, dialog: list[DialogTurn]) -> list[dict[str, Any]]:
        """Render ``dialog`` as OpenAI chat messages with mixed-content parts."""
        messages: list[dict[str, Any]] = []
        for turn in dialog:
            if turn.provider_state is not None or turn.provider_thinking:
                raise ValueError(
                    "OpenAI Chat cannot consume provider-native continuation "
                    "state from another API surface"
                )
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
                if "image" not in self.modality_support:
                    raise ValueError(
                        f"model {self.model!r} is not attested for image input"
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

    def build_request(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Preview complete Chat/compatible input, including media and history."""
        messages = self._to_messages(dialog)

        # GPT-5/6 and o-series reasoning models require max_completion_tokens.
        token_key = ("max_completion_tokens"
                     if self.model.startswith(("gpt-5", "gpt-6", "o1", "o3", "o4")) else "max_tokens")
        request: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            token_key: self.max_tokens,
        }
        if self.reasoning_effort is not None:
            request["reasoning_effort"] = self.reasoning_effort
        if self.temperature is not None:
            request["temperature"] = self.temperature
        if seed is not None and self.supports_seed:
            request["seed"] = int(seed)
        return request

    def _policy_rejection(
        self, error: ProviderTransportError, dialog: list[DialogTurn],
        *, seed: int | None, started: float,
    ) -> Response:
        """Retain an explicit native policy denial without inventing a completion."""
        audit = error.call_audit
        if (canonical_provider_name(self.provider) != "openai"
            or audit.get("status_code") != 400
            or audit.get("provider_error_code") != "cyber_policy"):
            raise error
        return Response(
            attempt_id=_dialog_fingerprint(dialog), target=self.name,
            output_turns=[], tokens=None,
            latency_ms=(time.perf_counter() - started) * 1000.0,
            raw={
                "provider": "openai",
                "endpoint_identity": canonical_https_endpoint_identity(self.base_url),
                "requested_spec": self.requested_spec, "requested_model": self.model,
                "resolved_model": None, "target_identity_observed": False,
                "requested_seed": seed, "target_sampling_control": "not_observed_provider_policy_rejection",
                "provider_refusal": True, "provider_refusal_category": "openai_http400_cyber_policy",
                "provider_refusal_reason": "cyber_policy", "provider_request_id": audit.get("provider_request_id"),
                "provider_policy_rejection": True, "provider_generation_observed": False,
                "output_truncated": False, "call_audit": dict(audit),
                "transport_attempt_count": len(error.transport_attempts),
                "transport_attempts": error.transport_attempts,
                "generation": {"max_tokens": self.max_tokens, "max_retries": self.max_retries},
            },
        )

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        request = self.build_request(dialog, seed=seed)
        client = self._get_client()
        start = time.perf_counter()
        try:
            resp, transport_attempts = _call_with_retry(
                client.chat.completions.create, request,
                provider=self.provider, max_retries=self.max_retries,
            )
        except ProviderTransportError as exc:
            return self._policy_rejection(exc, dialog, seed=seed, started=start)
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
            raise OpenAIChatIntegrityError(
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
            if finish_reason not in {"stop", "length"}:
                raise OpenAIChatOutputError(
                    f"OpenAI Chat response ended with incomplete or unexpected "
                    f"finish_reason {finish_reason!r}"
                )
            if not text.strip():
                error = OpenAIChatOutputError(
                    f"OpenAI Chat {finish_reason} response contained no visible text"
                )
                error.call_audit = {
                    "provider": self.provider, "operation": "generate",
                    "logical_call_count": 1,
                    "transport_attempt_count": len(transport_attempts),
                    "provider_response_id": response_id, "resolved_model": resolved_model,
                    "finish_reason": finish_reason, "requested_output_tokens": self.max_tokens,
                }
                usage = _provider_field(resp, "usage")
                for source, destination in (
                    ("prompt_tokens", "reported_input_tokens"),
                    ("completion_tokens", "reported_output_tokens"),
                    ("total_tokens", "reported_total_tokens"),
                ):
                    value = _provider_field(usage, source)
                    if type(value) is int and value >= 0:
                        error.call_audit[destination] = value
                details = _provider_field(usage, "completion_tokens_details")
                reasoning = _provider_field(details, "reasoning_tokens")
                if type(reasoning) is int and reasoning >= 0:
                    error.call_audit["reported_reasoning_tokens"] = reasoning
                raise error
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
                "endpoint_identity": (
                    canonical_https_endpoint_identity(self.base_url)
                    if isinstance(getattr(self, "base_url", None), str)
                    else None
                ),
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "system_fingerprint": _provider_field(resp, "system_fingerprint"),
                **({"requested_reasoning_effort": self.reasoning_effort}
                   if self.reasoning_effort is not None else {}),
                "finish_reason": finish_reason,
                "output_truncated": finish_reason == "length",
                "requested_seed": seed,
                "target_sampling_control": (
                    "provider_seed_requested_best_effort"
                    if seed is not None and self.supports_seed
                    else "uncontrolled"
                ),
                "provider_refusal": provider_refusal,
                "provider_refusal_category": refusal_category,
                "provider_refusal_reason": refusal_text or None,
                "transport_attempt_count": len(transport_attempts),
                "transport_attempts": transport_attempts,
                "generation": {
                    "max_tokens": self.max_tokens,
                    "temperature": (
                        self.temperature
                        if self.temperature is not None
                        else "omitted"
                    ),
                    "seed": seed if self.supports_seed else None,
                    "max_retries": self.max_retries,
                },
            },
        )


_OPENAI_SOL_PRO_MODEL = "gpt-5.6-sol"
_OPENAI_SOL_PRO_SPEC = (
    "openai-responses:gpt-5.6-sol;reasoning_mode=pro;"
    "reasoning_effort=medium;reasoning_context=all_turns"
)
_OPENAI_SOL_BUDGET_SPEC = _OPENAI_SOL_PRO_SPEC + ";max_output_tokens=4096"
_OPENAI_SOL_8192_SPEC = _OPENAI_SOL_PRO_SPEC + ";max_output_tokens=8192"
_OPENAI_SOL_OUTPUT_SPECS = {
    _OPENAI_SOL_PRO_SPEC: 25_000,
    _OPENAI_SOL_BUDGET_SPEC: 4_096,
    _OPENAI_SOL_8192_SPEC: 8_192,
}


class OpenAIResponsesTarget(OpenAITarget):
    """Fixed GPT-5.6 Sol Pro condition over the OpenAI Responses API.

    OpenAI exposes Pro as ``reasoning.mode='pro'`` on a GPT-5.6 model, not as
    a separate model slug.  This target intentionally has one canonical public
    identity so standard Chat Completions and the Pro condition cannot collapse
    into the same metric group.  Reasoning effort/context and the initial
    output-token budget are explicit for reproducible comparison.
    """

    name = _OPENAI_SOL_PRO_SPEC
    MAX_OUTPUT_TOKENS = 25_000
    BUDGET_SPEC = _OPENAI_SOL_BUDGET_SPEC
    BUDGET_MAX_OUTPUT_TOKENS = 4_096
    OUTPUT_8192_SPEC = _OPENAI_SOL_8192_SPEC
    REASONING_MODE = "pro"
    REASONING_EFFORT = "medium"
    REASONING_CONTEXT = "all_turns"

    def __init__(
        self,
        model: str = _OPENAI_SOL_PRO_MODEL,
        *,
        requested_spec: Optional[str] = None,
        timeout: float = 600.0,
        max_retries: int = DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        media_roots: Optional[Iterable[str | Path]] = None,
    ) -> None:
        if model != _OPENAI_SOL_PRO_MODEL:
            raise ValueError(
                "the fixed Sol Pro condition requires model 'gpt-5.6-sol'"
            )
        if requested_spec is not None and requested_spec not in _OPENAI_SOL_OUTPUT_SPECS:
            raise ValueError(
                "the Sol Pro target must use the canonical spec "
                f"{_OPENAI_SOL_PRO_SPEC!r}"
            )
        super().__init__(
            model,
            max_tokens=_OPENAI_SOL_OUTPUT_SPECS[requested_spec or self.name],
            provider="openai",
            requested_spec=requested_spec or _OPENAI_SOL_PRO_SPEC,
            temperature=0.0,
            timeout=timeout,
            max_retries=max_retries,
            media_roots=media_roots,
            supports_seed=False,
        )
        self.api_surface = "responses"
        self.max_output_tokens = self.max_tokens
        self.reasoning_mode = self.REASONING_MODE
        self.reasoning_effort = self.REASONING_EFFORT
        self.reasoning_context = self.REASONING_CONTEXT
        self.store = False
        self.truncation = "disabled"
        self.sdk_max_retries = 0

    def _to_responses_input(
        self, dialog: list[DialogTurn]
    ) -> list[dict[str, Any]]:
        """Render messages and exact stateless Responses continuation items."""
        if not dialog:
            raise ValueError("OpenAI Responses input dialog must not be empty")
        rendered: list[dict[str, Any]] = []
        for turn in dialog:
            if turn.provider_thinking:
                raise ValueError(
                    "OpenAI Responses cannot consume Anthropic provider thinking"
                )
            if turn.provider_state is not None:
                state = turn.provider_state
                if state.provider != "openai" or state.api_surface != "responses":
                    raise ValueError(
                        "OpenAI Responses received incompatible provider state"
                    )
                if turn.media or turn.tool_call is not None or turn.tool_result:
                    raise ValueError(
                        "OpenAI Responses continuation turns cannot mix provider "
                        "state with media or recorded tool fields"
                    )
                messages = [
                    item for item in state.items if item.get("type") == "message"
                ]
                if len(messages) != 1:
                    raise ValueError(
                        "OpenAI Responses continuation state must contain exactly "
                        "one assistant message"
                    )
                visible = "".join(
                    part.get("text", "")
                    for part in messages[0].get("content", [])
                    if isinstance(part, dict) and part.get("type") == "output_text"
                )
                if visible != (turn.content or ""):
                    raise ValueError(
                        "OpenAI Responses continuation message disagrees with the "
                        "recorded assistant text"
                    )
                # ``model_dump``/validation has already reduced this to bounded
                # JSON.  Round-trip it to avoid handing mutable artifact objects
                # to the provider SDK.
                rendered.extend(json.loads(json.dumps(state.items)))
                continue
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
    def _json_output_item(value: Any) -> dict[str, Any]:
        """Convert one SDK output item to an exact JSON object."""

        def convert(node: Any) -> Any:
            if node is None or isinstance(node, (str, int, float, bool)):
                return node
            if isinstance(node, dict):
                return {str(key): convert(child) for key, child in node.items()}
            if isinstance(node, (list, tuple)):
                return [convert(child) for child in node]
            dump = getattr(node, "model_dump", None)
            if callable(dump):
                try:
                    return convert(dump(mode="json"))
                except TypeError:
                    return convert(dump())
            values = getattr(node, "__dict__", None)
            if isinstance(values, dict):
                return {
                    str(key): convert(child)
                    for key, child in values.items()
                    if not str(key).startswith("_")
                }
            raise OpenAIResponsesOutputError(
                "OpenAI Responses output item is not JSON serializable"
            )

        converted = convert(value)
        if not isinstance(converted, dict):
            raise OpenAIResponsesOutputError(
                "OpenAI Responses output item did not serialize to an object"
            )
        return converted

    def _continuation_state(self, resp: Any) -> ProviderContinuationState:
        """Validate and retain every output item needed by ``all_turns``."""
        output = _provider_field(resp, "output")
        if not isinstance(output, (list, tuple)):
            raise OpenAIResponsesOutputError(
                "OpenAI Responses completed without continuation output items"
            )
        items = [self._json_output_item(item) for item in output]
        for item in items:
            if item.get("type") != "reasoning":
                continue
            encrypted = item.get("encrypted_content")
            if not isinstance(encrypted, str) or not encrypted.strip():
                raise OpenAIResponsesOutputError(
                    "OpenAI Responses stateless all_turns reasoning omitted "
                    "encrypted_content"
                )
        try:
            return ProviderContinuationState(
                provider="openai", api_surface="responses", items=items
            )
        except ValueError as exc:
            raise OpenAIResponsesOutputError(
                "OpenAI Responses returned invalid continuation state"
            ) from exc

    @staticmethod
    def _extract_completed_output(
        resp: Any,
        *,
        token_limited: bool = False,
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
                if item_status not in (None, "completed") and not (
                    token_limited and item_status == "incomplete"
                ):
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
            if _provider_field(item, "status") != "completed" and not (
                token_limited and _provider_field(item, "status") == "incomplete"
            ):
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

        # Reasoning settings do not guarantee a reasoning output item. Keep
        # every item supplied, but accept a valid message/refusal without one.
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
                raise OpenAIResponsesIntegrityError(
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

    def build_request(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Preview the fixed Responses body without a generation or SDK client."""
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
        return request

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        request = self.build_request(dialog, seed=seed)
        requested_reasoning = request["reasoning"]
        client = self._get_client()
        start = time.perf_counter()
        try:
            resp, transport_attempts = _call_with_retry(
                client.responses.create, request,
                provider="openai-responses", max_retries=self.max_retries,
            )
        except ProviderTransportError as exc:
            return self._policy_rejection(exc, dialog, seed=seed, started=start)
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
        incomplete = _provider_field(resp, "incomplete_details")
        incomplete_reason = _provider_field(incomplete, "reason")
        token_limited = status == "incomplete" and incomplete_reason == "max_output_tokens"
        if status != "completed" and not token_limited:
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
        if incomplete is not None and not token_limited:
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
            raise OpenAIResponsesIntegrityError(
                f"OpenAI Responses resolved unexpected model {resolved_model!r}"
            )
        effective_reasoning = self._validated_reasoning(resp)
        if _provider_field(resp, "max_output_tokens") != self.max_output_tokens:
            raise OpenAIResponsesIntegrityError(
                "OpenAI Responses effective max_output_tokens disagrees with "
                "the fixed request"
            )
        if _provider_field(resp, "truncation") != self.truncation:
            raise OpenAIResponsesIntegrityError(
                "OpenAI Responses effective truncation disagrees with the "
                "fixed request"
            )
        tokens = self._usage_tokens(resp)
        (
            text,
            provider_refusal,
            output_item_count,
            reasoning_item_count,
            message_item_count,
        ) = self._extract_completed_output(resp, token_limited=token_limited)
        continuation_state = (
            None if provider_refusal else self._continuation_state(resp)
        )
        output_turns = [] if provider_refusal else [
            DialogTurn(
                role="assistant",
                content=text,
                provider_state=continuation_state,
            )
        ]
        continuation_json = (
            None
            if continuation_state is None
            else json.dumps(
                continuation_state.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
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
                "endpoint_identity": canonical_https_endpoint_identity(
                    self.base_url
                ),
                "api_surface": self.api_surface,
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "status": status,
                "incomplete_reason": incomplete_reason,
                "output_truncated": token_limited,
                "service_tier": _provider_field(resp, "service_tier"),
                "requested_seed": seed,
                "target_sampling_control": "uncontrolled_responses_api_no_seed",
                "requested_reasoning": dict(requested_reasoning),
                "reasoning": effective_reasoning,
                "usage": dict(tokens),
                "provider_usage": self._provider_usage(resp),
                "provider_refusal": provider_refusal,
                "provider_refusal_category": (
                    "openai_responses_refusal" if provider_refusal else None
                ),
                "provider_refusal_reason": text if provider_refusal else None,
                "output_item_count": output_item_count,
                "reasoning_item_count": reasoning_item_count,
                "message_item_count": message_item_count,
                "continuation_state_sha256": (
                    hashlib.sha256(continuation_json).hexdigest()
                    if continuation_json is not None
                    else None
                ),
                "continuation_state_bytes": (
                    len(continuation_json) if continuation_json is not None else 0
                ),
                "transport_attempt_count": len(transport_attempts),
                "transport_attempts": transport_attempts,
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
        temperature: float | None = 0.0,
        timeout: float = 120.0,
        max_retries: int = DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        media_roots: Optional[Iterable[str | Path]] = None,
        supports_seed: bool = False,
        modality_support: Optional[Iterable[str]] = None,
        reasoning_effort: str | None = None,
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
            reasoning_effort=reasoning_effort,
            modality_support=(
                modality_support or _adapter_modalities(provider, model)
            ),
        )
        self.base_url = base_url
        self.key_env = key_env
        self.name = self.requested_spec

    def _get_client(self):
        if self._client is None:
            _reject_sdk_request_logging("openai")
            openai = _require("openai", f"{self.name} (OpenAI-compatible)")
            key = os.environ.get(self.key_env)
            if not key:
                raise RuntimeError(
                    f"{self.key_env} is required for {self.name}; set it in the environment")
            self._client = openai.OpenAI(
                api_key=key,
                organization="",
                project="",
                base_url=self.base_url,
                http_client=_sealed_http_client(
                    f"{self.name} compatible transport"
                ),
                timeout=self.timeout,
                max_retries=self.sdk_max_retries,
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
        temperature: float | None = 0.0,
        timeout: float = 120.0,
        max_retries: int = DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        media_roots: Optional[Iterable[str | Path]] = None,
        supports_seed: bool = False,
        modality_support: Optional[Iterable[str]] = None,
        thinking_level: str | None = None,
    ) -> None:
        self.model = model
        self.provider = "google"
        self.base_url = _NATIVE_PROVIDER_ENDPOINTS["google"]
        self.requested_spec = requested_spec or f"google:{model}"
        self.name = self.requested_spec
        self.max_tokens = int(max_tokens)
        self.temperature = None if temperature is None else float(temperature)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self.max_transport_attempts_per_call = self.max_retries + 1
        self.media_roots = _media_roots(media_roots)
        self.supports_seed = bool(supports_seed)
        if thinking_level is not None and (
            not model.startswith("gemini-3") or thinking_level not in {"minimal", "low", "medium", "high"}
            or ("pro" in model and thinking_level == "minimal")
        ):
            raise ValueError("Gemini thinking_level is not supported for this model")
        self.thinking_level = thinking_level
        self.modality_support = _validated_provider_modalities(
            "google",
            modality_support or _adapter_modalities("google", model)
        )
        self.modality_combinations = tuple(
            [("text",)]
            + [
                ("text", modality)
                for modality in ("image", "audio", "video")
                if modality in self.modality_support
            ]
        )
        self._client = None

    def _get_client(self):
        if self._client is None:
            genai = _require("google.genai", "GeminiTarget")
            if os.environ.get("GOOGLE_GENAI_CLIENT_MODE", "").strip():
                raise RuntimeError(
                    "GOOGLE_GENAI_CLIENT_MODE is forbidden; Gemini transport "
                    "mode is fixed by the harness"
                )
            key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
            if not key:
                raise RuntimeError(
                    "GEMINI_API_KEY (or GOOGLE_API_KEY) is required for "
                    "GeminiTarget; set it in the environment"
                )
            self._client = genai.Client(
                vertexai=False,
                api_key=key,
                http_options={
                    "base_url": self.base_url,
                    "timeout": int(self.timeout * 1000),
                    "client_args": {
                        "trust_env": False,
                        "verify": _sealed_ssl_context(
                            "GeminiTarget sync transport"
                        ),
                    },
                    "async_client_args": {
                        "trust_env": False,
                        "verify": _sealed_ssl_context(
                            "GeminiTarget async transport"
                        ),
                    },
                    # One SDK attempt. The harness wrapper performs and records
                    # any requested retry itself.
                    "retry_options": {"attempts": 1},
                },
            )
        return self._client

    def _to_contents(
        self, dialog: list[DialogTurn]
    ) -> tuple[Optional[str], list[dict[str, Any]]]:
        """Return ``(system_instruction, contents)`` in Gemini's schema."""
        system: Optional[str] = None
        contents: list[dict[str, Any]] = []
        for turn in dialog:
            if turn.provider_state is not None or turn.provider_thinking:
                raise ValueError(
                    "Gemini cannot consume provider-native continuation state "
                    "from another API surface"
                )
            if turn.role == "system":
                if system is not None:
                    raise ValueError("Gemini accepts exactly one system turn")
                if (
                    not (turn.content or "").strip()
                    or turn.media
                    or turn.tool_call is not None
                    or turn.tool_result is not None
                ):
                    raise ValueError("Gemini system turn must be non-empty plain text")
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
                if media.modality not in {"image", "audio", "video"}:
                    raise ValueError(
                        f"GeminiTarget cannot render {media.modality!r} media"
                    )
                if media.modality not in self.modality_support:
                    raise ValueError(
                        f"Gemini model {self.model!r} is not attested for "
                        f"{media.modality!r} input"
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
        if not contents:
            raise ValueError("GeminiTarget requires at least one non-system message")
        return system, contents

    def build_request(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Return the JSON-compatible body shared by counting and generation."""
        system, contents = self._to_contents(dialog)
        for content in contents:
            for part in content["parts"]:
                if "inline_data" in part:
                    blob = part["inline_data"]
                    blob["data"] = base64.b64encode(blob["data"]).decode("ascii")
        config: dict[str, Any] = {
            "max_output_tokens": self.max_tokens,
        }
        if self.thinking_level is not None:
            config["thinking_config"] = {"thinking_level": self.thinking_level.upper()}
        if self.temperature is not None:
            config["temperature"] = self.temperature
        if system:
            config["system_instruction"] = system
        if seed is not None and self.supports_seed:
            config["seed"] = int(seed)
        return {"model": self.model, "contents": contents, "config": config}

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        client = self._get_client()
        request = self.build_request(dialog, seed=seed)

        start = time.perf_counter()
        resp, transport_attempts = _call_with_retry(
            client.models.generate_content,
            request,
            provider=self.provider,
            max_retries=self.max_retries,
        )
        latency_ms = (time.perf_counter() - start) * 1000.0

        try:
            return self._normalize_response(resp, dialog, seed=seed, latency_ms=latency_ms,
                                            transport_attempts=transport_attempts)
        except GeminiOutputError as exc:
            candidates = _provider_field(resp, "candidates")
            candidate = candidates[0] if isinstance(candidates, (list, tuple)) and candidates else None
            feedback = _provider_field(resp, "prompt_feedback")
            exc.call_audit = {
                "provider": self.provider, "operation": "generate", "logical_call_count": 1,
                "transport_attempt_count": len(transport_attempts),
                "provider_response_id": _provider_field(resp, "response_id"),
                "resolved_model": _provider_field(resp, "model_version"),
                "provider_error_code": _enum_name(_provider_field(feedback, "block_reason")),
                "finish_reason": _enum_name(_provider_field(candidate, "finish_reason")),
                "requested_output_tokens": self.max_tokens,
                "error_type": type(exc).__name__,
            }
            raise

    def _normalize_response(self, resp: Any, dialog: list[DialogTurn], *, seed: int | None, latency_ms: float,
                            transport_attempts: list[dict[str, Any]]) -> Response:
        prompt_feedback = _provider_field(resp, "prompt_feedback")
        prompt_block_reason = _enum_name(
            _provider_field(prompt_feedback, "block_reason")
            if prompt_feedback is not None else None
        )
        prompt_blocked = prompt_block_reason not in {
            None, "", "BLOCK_REASON_UNSPECIFIED",
        }
        identities = {}
        for key in ("response_id", "model_version"):
            value = _provider_field(resp, key)
            if value is None and prompt_blocked:
                identities[key] = None
            else:
                identities[key] = _required_provider_string(resp, key, error=GeminiOutputError,
                                                           location="Gemini response")
        response_id, resolved_model = identities["response_id"], identities["model_version"]
        if resolved_model is not None and not _resolved_model_matches(self.model, resolved_model):
            raise GeminiIntegrityError(f"Gemini resolved unexpected model {resolved_model!r}")
        candidates = _provider_field(resp, "candidates", [])
        if candidates is None and prompt_blocked:
            candidates = []
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
            filtered_reasons = {
                "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT",
                "SPII", "IMAGE_SAFETY", "IMAGE_PROHIBITED_CONTENT",
                "IMAGE_RECITATION", "ESCALATION", "MODEL_ARMOR",
            }
            finish_message_raw = _provider_field(candidate, "finish_message")
            if finish_message_raw is not None and not isinstance(finish_message_raw, str):
                raise GeminiOutputError("Gemini finish_message is not text or null")
            finish_message = finish_message_raw
            content = _provider_field(candidate, "content")
            role = _provider_field(content, "role") if content is not None else None
            parts = _provider_field(content, "parts", []) if content is not None else []
            if parts is None and finish_reason in filtered_reasons:
                parts = []
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
                if finish_reason not in {"STOP", "MAX_TOKENS"}:
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
        tokens = self._usage_tokens(usage, provider_refusal=provider_refusal)

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=output_turns,
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "provider": self.provider,
                "endpoint_identity": canonical_https_endpoint_identity(self.base_url),
                "requested_spec": self.requested_spec,
                "requested_model": self.model,
                "resolved_model": resolved_model,
                "response_id": response_id,
                "finish_reason": finish_reason,
                "output_truncated": finish_reason == "MAX_TOKENS",
                "finish_message": finish_message,
                "prompt_block_reason": prompt_block_reason,
                **({"requested_thinking_level": self.thinking_level} if self.thinking_level is not None else {}),
                "safety_ratings": safety_ratings,
                "requested_seed": seed,
                "target_sampling_control": "provider_seed_requested_best_effort" if seed is not None and self.supports_seed else "uncontrolled",
                "provider_refusal": provider_refusal,
                "provider_refusal_category": refusal_category,
                "provider_refusal_reason": refusal_reason,
                "usage_status": "reported" if tokens is not None else "unknown",
                "transport_attempt_count": len(transport_attempts),
                "transport_attempts": transport_attempts,
                "generation": {"max_tokens": self.max_tokens,
                    "temperature": self.temperature if self.temperature is not None else "omitted",
                    "seed": seed if self.supports_seed else None, "max_retries": self.max_retries},
            },
        )

    @staticmethod
    def _usage_tokens(usage: Any, *, provider_refusal: bool) -> dict[str, int] | None:
        # Blocked responses may omit usage fields. Unknown billing is not zero.
        if provider_refusal:
            for field in ("prompt_token_count", "candidates_token_count", "total_token_count", "thoughts_token_count"):
                if _provider_field(usage, field) is not None:
                    _required_nonnegative_int(usage, field, error=GeminiOutputError, location="Gemini usage")
        if provider_refusal and any(_provider_field(usage, field) is None for field in
                ("prompt_token_count", "candidates_token_count", "total_token_count")):
            return None
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
        candidate_tokens = output_tokens
        thoughts = _provider_field(usage, "thoughts_token_count")
        if thoughts is not None:
            output_tokens += _required_nonnegative_int(
                usage, "thoughts_token_count", error=GeminiOutputError,
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
        return {
            "input": input_tokens,
            "output": output_tokens,
            "total": total_tokens,
            **({"reasoning": thoughts, "visible_output": candidate_tokens} if thoughts is not None else {}),
        }

# --------------------------------------------------------------------------- #
# Registry wiring
# --------------------------------------------------------------------------- #

REGISTRY.register(
    "mock", MockTarget, provider="mock", modality="text+image+audio+video"
)

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
REGISTRY.register(
    _ANTHROPIC_FABLE_51_MODEL,
    lambda: AnthropicFableTarget(_ANTHROPIC_FABLE_51_MODEL),
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
    "kimi": ("https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
    "moonshot": ("https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
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

_COMPAT_ENDPOINT_ENV = {
    "deepseek": "URA_DEEPSEEK_BASE_URL",
    "glm": "URA_GLM_BASE_URL",
    "zhipu": "URA_GLM_BASE_URL",
    "kimi": "URA_KIMI_BASE_URL",
    "moonshot": "URA_KIMI_BASE_URL",
    "qwen": "URA_QWEN_BASE_URL",
    "dashscope": "URA_QWEN_BASE_URL",
    "alibaba": "URA_QWEN_BASE_URL",
    "doubao": "URA_DOUBAO_BASE_URL",
    "bytedance": "URA_DOUBAO_BASE_URL",
}


def _validated_https_base_url(value: str, *, source: str) -> str:
    """Validate one non-secret provider endpoint for safe manifest persistence."""

    try:
        return canonical_https_endpoint(value)
    except ValueError as exc:
        raise ValueError(
            f"{source} must be a credential-free canonical HTTPS base URL"
        ) from exc


def _compat_endpoint(provider: str, default: str) -> str:
    """Resolve a region/account endpoint without accepting credential-bearing URLs."""

    configured = os.environ.get(_COMPAT_ENDPOINT_ENV[provider], "").strip()
    return _validated_https_base_url(
        configured or default,
        source=_COMPAT_ENDPOINT_ENV[provider],
    )


def api_target_endpoint_identity(
    spec: str,
    config: dict[str, object] | None = None,
) -> str | None:
    """Resolve a non-disclosing compatible-API endpoint identity."""

    requested = spec.strip()
    if ":" in requested:
        provider = requested.split(":", 1)[0].strip().lower()
    else:
        provider = next(
            (
                candidate
                for candidate, models in _COMPAT_DEFAULTS.items()
                if requested in models
            ),
            "",
        )
    try:
        canonical_provider, _model = canonical_api_target_identity(requested)
    except (KeyError, ValueError):
        canonical_provider = canonical_provider_name(provider)
    native_endpoint = _NATIVE_PROVIDER_ENDPOINTS.get(canonical_provider)
    if native_endpoint is not None:
        return canonical_https_endpoint_identity(native_endpoint)
    if provider not in _COMPAT:
        return None
    configured = (config or {}).get("base_url")
    if configured is not None:
        if not isinstance(configured, str):
            raise ValueError("API target base_url must be a string")
        return canonical_https_endpoint_identity(
            _validated_https_base_url(
                configured,
                source=f"API config {requested!r} base_url",
            )
        )
    default, _key = _COMPAT[provider]
    return canonical_https_endpoint_identity(_compat_endpoint(provider, default))


def api_target_requires_config(spec: str) -> bool:
    """Whether a measured target needs an explicit exact-spec API condition."""

    if spec in {*_ANTHROPIC_FABLE_MODELS, *_ANTHROPIC_FABLE_OUTPUT_SPECS,
                *_OPENAI_SOL_OUTPUT_SPECS}:
        return False
    if ":" in spec:
        return True
    registered_generic = {
        *_ANTHROPIC_DEFAULTS,
        *_OPENAI_DEFAULTS,
        *_GEMINI_DEFAULTS,
        *(
            model
            for models in _COMPAT_DEFAULTS.values()
            for model in models
        ),
    }
    return spec in registered_generic


def normalize_api_target_config(
    spec: str, config: dict[str, object]
) -> dict[str, object]:
    """Validate and canonicalize one measured generic API target condition.

    Credentials are deliberately absent. The returned object is safe to persist
    verbatim in the grid request and is also the exact constructor input.
    """

    if not api_target_requires_config(spec):
        raise ValueError(f"API target {spec!r} uses inherent config or is unregistered")
    allowed = {
        "modalities", "base_url", "max_tokens", "temperature",
        "thinking", "effort", "reasoning_effort", "thinking_level",
    }
    if set(config) - allowed:
        raise ValueError(f"API config {spec!r} contains unsupported execution fields")
    missing = {"modalities", "max_tokens", "temperature"} - set(config)
    if missing:
        raise ValueError(
            f"API config {spec!r} is missing: " + ", ".join(sorted(missing))
        )

    if ":" in spec:
        provider, _model = spec.split(":", 1)
        provider = provider.lower().strip()
    elif spec in _ANTHROPIC_DEFAULTS:
        provider = "anthropic"
    elif spec in _OPENAI_DEFAULTS:
        provider = "openai"
    elif spec in _GEMINI_DEFAULTS:
        provider = "google"
    else:
        provider = next(
            name for name, models in _COMPAT_DEFAULTS.items() if spec in models
        )
    canonical_provider = canonical_provider_name(provider)
    known_native = {"anthropic", "openai", "google"}
    if canonical_provider not in known_native and provider not in _COMPAT:
        raise ValueError(f"unknown API provider {provider!r} in {spec!r}")

    raw_modalities = config["modalities"]
    if not isinstance(raw_modalities, list) or any(
        not isinstance(item, str) for item in raw_modalities
    ):
        raise ValueError(
            f"API config {spec!r} modalities must be a JSON string list"
        )
    modalities = _validated_provider_modalities(provider, raw_modalities)
    selected_model = spec.split(":", 1)[-1] if ":" in spec else spec
    thinking_level = config.get("thinking_level")
    if "thinking_level" in config and (
        canonical_provider != "google" or not selected_model.startswith("gemini-3")
        or not isinstance(thinking_level, str) or thinking_level not in {"minimal", "low", "medium", "high"}
        or ("pro" in selected_model and thinking_level == "minimal")
    ):
        raise ValueError(f"API config {spec!r} thinking_level is unsupported")
    reasoning_effort = config.get("reasoning_effort")
    if "reasoning_effort" in config and (
        (canonical_provider, selected_model) not in {
            ("kimi", "kimi-k3"), ("deepseek", "deepseek-v4-pro"), ("deepseek", "deepseek-v4-flash")}
        or not isinstance(reasoning_effort, str)
        or reasoning_effort not in {"low", "high", "max"}
    ):
        raise ValueError(f"API config {spec!r} reasoning_effort supports Kimi K3 and DeepSeek V4 low/high/max only")
    documented_modalities = _MODEL_ADAPTER_MODALITIES.get(
        (canonical_provider, selected_model)
    )
    if documented_modalities is not None:
        overstated = set(modalities) - set(documented_modalities)
        if overstated:
            raise ValueError(
                f"API config {spec!r} overstates the implemented/documented model "
                "modalities: " + ",".join(sorted(overstated))
            )

    max_tokens = config["max_tokens"]
    if (
        isinstance(max_tokens, bool)
        or not isinstance(max_tokens, int)
        or not 1 <= max_tokens <= 25_000
    ):
        raise ValueError(
            f"API config {spec!r} max_tokens must be an integer in 1..25000"
        )
    temperature = config["temperature"]
    if temperature is not None and (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not math.isfinite(float(temperature))
        or not 0.0 <= float(temperature) <= 2.0
    ):
        raise ValueError(
            f"API config {spec!r} temperature must be null or finite in [0, 2]"
        )
    thinking = config.get("thinking")
    effort = config.get("effort")
    if thinking is not None and thinking != "adaptive":
        raise ValueError(
            f"API config {spec!r} thinking must be omitted or 'adaptive'"
        )
    if effort is not None and effort not in {
        "low", "medium", "high", "xhigh", "max"
    }:
        raise ValueError(
            f"API config {spec!r} effort must be low/medium/high/xhigh/max"
        )
    if (thinking is not None or effort is not None) and canonical_provider != "anthropic":
        raise ValueError(
            f"API config {spec!r} thinking/effort are Anthropic-only"
        )
    adaptive_default_models = {"claude-opus-5", "claude-sonnet-5"}
    if selected_model in adaptive_default_models:
        if thinking != "adaptive" or effort is None or temperature is not None:
            raise ValueError(
                f"API config {spec!r} requires thinking='adaptive', explicit "
                "effort, and temperature=null"
            )
    elif thinking is not None or effort is not None:
        raise ValueError(
            f"API config {spec!r} does not have an implemented adaptive-thinking "
            "contract"
        )

    normalized: dict[str, object] = {
        "modalities": list(modalities),
        "max_tokens": max_tokens,
        "temperature": None if temperature is None else float(temperature),
    }
    if thinking is not None:
        normalized["thinking"] = thinking
        normalized["effort"] = effort
    if reasoning_effort is not None:
        normalized["reasoning_effort"] = reasoning_effort
    if thinking_level is not None:
        normalized["thinking_level"] = thinking_level
    configured_url = config.get("base_url")
    if provider in _COMPAT:
        default_url, _key = _COMPAT[provider]
        if configured_url is not None and not isinstance(configured_url, str):
            raise ValueError(f"API config {spec!r} base_url must be a string")
        normalized["base_url"] = (
            _validated_https_base_url(
                configured_url,
                source=f"API config {spec!r} base_url",
            )
            if isinstance(configured_url, str)
            else _compat_endpoint(provider, default_url)
        )
    elif configured_url is not None:
        raise ValueError(
            f"API config {spec!r} base_url is allowed only for compatible providers"
        )
    return normalized


def preflight_api_target_runtime(target: BaseTarget) -> dict[str, str] | None:
    """Verify local hosted-client readiness without constructing a client.

    This deliberately stops at importing the selected SDK and confirming that
    one of its credential environment variables is non-blank.  It performs no
    network request, so it cannot establish account access or model visibility.
    Offline/test targets return ``None`` because they have no hosted runtime.
    """
    requirement: tuple[str, tuple[str, ...]] | None
    if isinstance(target, OpenAICompatibleTarget):
        requirement = ("openai", (target.key_env,))
    elif isinstance(target, OpenAITarget):
        requirement = ("openai", ("OPENAI_API_KEY",))
    elif isinstance(target, AnthropicTarget):
        requirement = ("anthropic", ("ANTHROPIC_API_KEY",))
    elif isinstance(target, GeminiTarget):
        requirement = ("google.genai", ("GEMINI_API_KEY", "GOOGLE_API_KEY"))
    else:
        return None

    module, credential_envs = requirement
    _reject_sdk_request_logging(module)
    _require(module, f"{target.name} local preflight")
    present_env = next(
        (name for name in credential_envs if os.environ.get(name, "").strip()),
        None,
    )
    if present_env is None:
        rendered = " or ".join(credential_envs)
        raise RuntimeError(
            f"local hosted preflight requires non-blank {rendered}; "
            "credential presence was checked without contacting the provider"
        )
    return {
        "target": target.name,
        "sdk_module": module,
        "credential_env": present_env,
    }


def build_api_target(
    spec: str, *, config: dict[str, object] | None = None
) -> BaseTarget:
    """Build a hosted target from ``"<provider>:<model>"`` or a bare registered id.

    Native providers: anthropic/claude, openai/gpt, google/gemini. OpenAI-compatible
    providers: deepseek, glm/zhipu, kimi/moonshot, qwen/dashscope/alibaba,
    doubao/bytedance. Examples: ``"deepseek:deepseek-v4-pro"`` or
    ``"qwen:<account-visible-id>"``. Bare IDs are limited to the conservative
    registry above.
    """
    normalized = (
        normalize_api_target_config(spec, config) if config is not None else None
    )
    constructor_kwargs: dict[str, Any] = {}
    if normalized is not None:
        constructor_kwargs = {
            "max_tokens": normalized["max_tokens"],
            "temperature": normalized["temperature"],
            "modality_support": normalized["modalities"],
        }
        if normalized.get("reasoning_effort") is not None:
            constructor_kwargs["reasoning_effort"] = normalized["reasoning_effort"]
        if normalized.get("thinking_level") is not None:
            constructor_kwargs["thinking_level"] = normalized["thinking_level"]

    if ":" in spec:
        provider, model = spec.split(":", 1)
        provider = provider.lower()
        if provider == "anthropic-fable":
            if spec not in _ANTHROPIC_FABLE_OUTPUT_SPECS:
                raise ValueError(
                    "the only fixed Anthropic Fable condition is "
                    f"{_ANTHROPIC_FABLE_SPEC!r}"
                )
            return AnthropicFableTarget(
                model.split(";", 1)[0], requested_spec=spec
            )
        if provider == "openai-responses":
            if spec not in _OPENAI_SOL_OUTPUT_SPECS:
                raise ValueError(
                    "the only fixed OpenAI Responses condition is "
                    f"{_OPENAI_SOL_PRO_SPEC!r}"
                )
            return OpenAIResponsesTarget(
                _OPENAI_SOL_PRO_MODEL, requested_spec=spec
            )
        if provider in {"anthropic", "claude"}:
            if model in _ANTHROPIC_FABLE_MODELS:
                raise ValueError(
                    "Claude Fable rejects the ordinary Anthropic target's "
                    "temperature parameter; use the canonical spec "
                    f"{_ANTHROPIC_FABLE_SPEC!r}"
                )
            return AnthropicTarget(
                model,
                requested_spec=spec,
                adaptive_thinking=(
                    normalized is not None
                    and normalized.get("thinking") == "adaptive"
                ),
                effort=(str(normalized["effort"]) if normalized is not None
                        and normalized.get("effort") is not None else None),
                **constructor_kwargs,
            )
        if provider in {"openai", "gpt"}:
            return OpenAITarget(model, requested_spec=spec, **constructor_kwargs)
        if provider in {"google", "gemini"}:
            return GeminiTarget(model, requested_spec=spec, **constructor_kwargs)
        if provider in _COMPAT:
            url, key = _COMPAT[provider]
            return OpenAICompatibleTarget(
                model,
                str(normalized["base_url"]) if normalized else _compat_endpoint(
                    provider, url
                ),
                key,
                provider=provider,
                requested_spec=spec,
                **constructor_kwargs,
            )
        raise KeyError(f"unknown API provider '{provider}' in '{spec}'")
    if normalized is not None:
        if spec in _ANTHROPIC_DEFAULTS:
            return AnthropicTarget(
                spec,
                requested_spec=f"anthropic:{spec}",
                adaptive_thinking=(normalized.get("thinking") == "adaptive"),
                effort=(str(normalized["effort"])
                        if normalized.get("effort") is not None else None),
                **constructor_kwargs,
            )
        if spec in _OPENAI_DEFAULTS:
            return OpenAITarget(
                spec, requested_spec=f"openai:{spec}", **constructor_kwargs
            )
        if spec in _GEMINI_DEFAULTS:
            return GeminiTarget(
                spec, requested_spec=f"google:{spec}", **constructor_kwargs
            )
        for provider, models in _COMPAT_DEFAULTS.items():
            if spec in models:
                _url, key = _COMPAT[provider]
                return OpenAICompatibleTarget(
                    spec,
                    str(normalized["base_url"]),
                    key,
                    provider=provider,
                    requested_spec=f"{provider}:{spec}",
                    **constructor_kwargs,
                )
    return REGISTRY.create(spec)


__all__ = [
    "DEFAULT_HOSTED_HTTP_ERROR_RETRIES",
    "provider_attempt_admission",
    "MockTarget",
    "AnthropicTarget",
    "AnthropicFableTarget",
    "AnthropicFableOutputError",
    "OpenAITarget",
    "OpenAIResponsesTarget",
    "OpenAIResponsesOutputError",
    "ProviderTransportError",
    "OpenAICompatibleTarget",
    "GeminiTarget",
    "api_target_endpoint_identity",
    "api_target_requires_config",
    "canonical_api_target_identity",
    "canonical_provider_name",
    "normalize_api_target_config",
    "preflight_api_target_runtime",
    "build_api_target",
]
