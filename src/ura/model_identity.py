"""Side-effect-free strong model-identity projections shared across layers."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping
from urllib.parse import quote, unquote_to_bytes, urlsplit

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMMUTABLE_REVISION = re.compile(r"[0-9a-f]{40,64}")
_ENDPOINT_IDENTITY = re.compile(r"https-base-url-sha256:([0-9a-f]{64})")
_PROVIDER_ALIASES = {
    "claude": "anthropic",
    "gpt": "openai",
    "gemini": "google",
    "zhipu": "glm",
    "moonshot": "kimi",
    "dashscope": "qwen",
    "alibaba": "qwen",
    "bytedance": "doubao",
}


def canonical_provider_name(provider: str) -> str:
    """Return the execution-equivalent provider family for identity checks."""

    normalized = provider.strip().lower()
    return _PROVIDER_ALIASES.get(normalized, normalized)


def canonical_https_endpoint(value: str) -> str:
    """Return a credential-free canonical HTTPS endpoint authority/path."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("endpoint must be a non-blank HTTPS URL")
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("endpoint must be a credential-free HTTPS base URL")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("endpoint has an invalid port") from exc
    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("endpoint has an invalid hostname") from exc
    if not hostname:
        raise ValueError("endpoint has an invalid hostname")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None and port != 443:
        authority += f":{port}"
    try:
        decoded_path = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("endpoint path must be valid UTF-8") from exc
    if "\\" in decoded_path or any(ord(character) < 32 for character in decoded_path):
        raise ValueError("endpoint path contains forbidden characters")
    segments: list[str] = []
    for segment in decoded_path.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    path = "/" + "/".join(segments) if segments else ""
    return "https://" + authority + quote(
        path,
        safe="/:@-._~!$&'()*+,;=",
    )


def canonical_https_endpoint_identity(value: str) -> str:
    """Hash a canonical HTTPS base URL for durable, non-disclosing identity."""

    canonical = canonical_https_endpoint(value)
    return "https-base-url-sha256:" + hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


def validate_https_endpoint_identity(value: str) -> str:
    """Validate one typed durable HTTPS endpoint identity."""

    if not isinstance(value, str):
        raise ValueError("endpoint identity must be a string")
    normalized = value.strip().lower()
    if _ENDPOINT_IDENTITY.fullmatch(normalized) is None:
        raise ValueError(
            "endpoint identity must be https-base-url-sha256:<64 lowercase hex>"
        )
    return normalized


def strong_realized_model_identity_keys(
    value: Mapping[str, Any],
) -> set[tuple[str, ...]]:
    """Return independent strong keys that prove two snapshots use one model."""

    keys: set[tuple[str, ...]] = set()
    resolved_model = value.get("resolved_model")
    endpoint_identity = value.get("endpoint_identity")
    if (
        isinstance(endpoint_identity, str)
        and endpoint_identity.strip()
        and isinstance(resolved_model, str)
        and resolved_model.strip()
    ):
        keys.add((
            "endpoint-model",
            validate_https_endpoint_identity(endpoint_identity),
            resolved_model.strip(),
        ))
    else:
        # A compatible endpoint is an independently operated execution route.
        # Once that route is known, provider/model is only display provenance:
        # retaining it as a second equality key would collapse two intentionally
        # distinct services that happen to expose the same served-model label.
        provider = value.get("provider")
        if (
            isinstance(provider, str)
            and provider.strip()
            and isinstance(resolved_model, str)
            and resolved_model.strip()
        ):
            keys.add((
                "provider-model",
                canonical_provider_name(provider),
                resolved_model.strip(),
            ))
    digest = value.get("model_digest")
    if isinstance(digest, str) and _SHA256.fullmatch(digest.strip().lower()):
        keys.add(("sha256", digest.strip().lower()))
    revision = value.get("model_revision")
    if (
        isinstance(revision, str)
        and _IMMUTABLE_REVISION.fullmatch(revision.strip().lower())
        and isinstance(resolved_model, str)
        and resolved_model.strip()
    ):
        keys.add((
            "model-revision",
            resolved_model.strip(),
            revision.strip().lower(),
        ))
    return keys


__all__ = [
    "canonical_https_endpoint",
    "canonical_https_endpoint_identity",
    "canonical_provider_name",
    "strong_realized_model_identity_keys",
    "validate_https_endpoint_identity",
]
