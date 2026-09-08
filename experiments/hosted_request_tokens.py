"""Full-request token evidence, separate from monetary and campaign admission.

Counters never generate an answer. Network access is opt-in; text-only offline
results are explicitly estimates. In particular, a Responses projection is
not an exact count of OpenAI Chat serialization. No request setting is changed.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ura.targets.api import (
    AnthropicTarget, OpenAICompatibleTarget, OpenAIResponsesTarget, OpenAITarget,
)


_ANTHROPIC_INPUT = frozenset({"model", "messages", "system", "tools", "tool_choice",
                             "thinking", "output_config", "cache_control"})
_RESPONSES_INPUT = frozenset({"model", "input", "instructions", "conversation",
                            "previous_response_id", "reasoning", "text", "tools",
                            "tool_choice", "parallel_tool_calls", "personality", "truncation"})
_GENERATION_ONLY = frozenset({"max_tokens", "max_completion_tokens", "max_output_tokens",
                            "temperature", "top_p", "seed", "store", "service_tier"})
_LOCAL_METHOD = "canonical_request_utf8_bytes_plus_256_v1"
_RECEIPT_FIELDS = frozenset({"request_sha256", "count_request_sha256", "provider",
                            "requested_spec", "requested_model", "input_tokens", "method",
                            "method_id", "count_http_attempts", "count_fee_status"})


class TokenCountUnavailable(ValueError):
    """No declared counting method covers this request without dropping input."""


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")


def request_sha256(request: Mapping) -> str:
    return hashlib.sha256(_canonical(request)).hexdigest()


def _has_media(value):
    if isinstance(value, dict):
        if value.get("type") in {"image", "image_url", "input_image", "input_audio", "input_file",
                                "document", "video", "file"}:
            return True
        return any(_has_media(item) for item in value.values())
    return isinstance(value, list) and any(_has_media(item) for item in value)


def _checked_request(target, request):
    if not isinstance(request, Mapping) or request.get("model") != target.model:
        raise ValueError("token count request differs from the exact target model")
    if not isinstance(target, (AnthropicTarget, OpenAITarget)):
        raise TokenCountUnavailable("this target has no hosted request-count method")
    return json.loads(_canonical(dict(request)))


def _pick(request, included, omitted):
    if set(request) - included - omitted:
        raise TokenCountUnavailable("count method does not cover all request fields")
    return {key: value for key, value in request.items() if key in included}


def _chat_projection(request):
    """Project the current Chat renderer's messages for an explicitly estimated count."""
    selected = _pick(request, {"model", "messages", "reasoning_effort"}, _GENERATION_ONLY)
    result = {"model": selected["model"], "input": []}
    messages = selected.get("messages")
    if not isinstance(messages, list):
        raise TokenCountUnavailable("Chat counting needs the complete message list")
    for message in messages:
        if (not isinstance(message, dict) or set(message) != {"role", "content"}
                or message["role"] not in {"system", "developer", "user", "assistant"}):
            raise TokenCountUnavailable("Chat count projection cannot drop message fields")
        content = message["content"]
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and set(block) == {"type", "text"} and block["type"] == "text":
                    parts.append({"type": "input_text", "text": block["text"]})
                elif isinstance(block, dict) and set(block) == {"type", "image_url"} and block["type"] == "image_url":
                    image = block["image_url"]
                    if not isinstance(image, dict) or not {"url"} <= set(image) <= {"url", "detail"}:
                        raise TokenCountUnavailable("Chat count projection cannot drop image fields")
                    parts.append({"type": "input_image", "image_url": image["url"],
                                  **({"detail": image["detail"]} if "detail" in image else {})})
                else:
                    raise TokenCountUnavailable("Chat count projection cannot drop content blocks")
            content = parts
        elif not isinstance(content, str):
            raise TokenCountUnavailable("Chat count projection needs text or supported blocks")
        result["input"].append({"role": message["role"], "content": content})
    if "reasoning_effort" in selected:
        result["reasoning"] = {"effort": selected["reasoning_effort"]}
    return result


def _count_plan(target, request, *, network):
    if not network:
        if _has_media(request):
            raise TokenCountUnavailable("offline byte estimates cannot count physical media")
        return "local_estimate", _LOCAL_METHOD, request, "no_network"
    if isinstance(target, AnthropicTarget):
        return ("provider_estimate", "anthropic_messages_count_tokens_v1",
                _pick(request, _ANTHROPIC_INPUT, _GENERATION_ONLY), "free_documented")
    if isinstance(target, OpenAIResponsesTarget):
        return ("provider_exact", "openai_responses_input_tokens_v1",
                _pick(request, _RESPONSES_INPUT, _GENERATION_ONLY), "unspecified")
    if isinstance(target, OpenAICompatibleTarget):
        if target.provider in {"kimi", "moonshot"}:
            return ("provider_estimate", "kimi_estimate_token_count_v1",
                    _pick(request, {"model", "messages"}, _GENERATION_ONLY | {"reasoning_effort"}),
                    "unspecified")
        return _count_plan(target, request, network=False)
    return ("provider_estimate", "openai_responses_projection_of_chat_v1",
            _chat_projection(request), "unspecified")


def _field(value, name):
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)


def count_request(target, request: Mapping, *, allow_network: bool = False) -> dict:
    """Count one complete request after the controller's campaign admission.

    Default: no client, key, download or network. Explicit network counting uses
    the target's existing sealed transport, zero SDK retries and a 30s timeout.
    Count failures propagate: they never cause generation or silent fallback.
    Receipts contain hashes/counts, not prompts, media payloads or credentials.
    """
    if type(allow_network) is not bool:
        raise ValueError("allow_network must be an explicit boolean")
    body = _checked_request(target, request)
    method, method_id, counted, fee = _count_plan(target, body, network=allow_network)
    receipt = {"request_sha256": request_sha256(body), "count_request_sha256": request_sha256(counted),
               "provider": target.provider, "requested_spec": target.requested_spec,
               "requested_model": target.model, "method": method, "method_id": method_id,
               "count_http_attempts": 0 if method == "local_estimate" else 1, "count_fee_status": fee}
    if method == "local_estimate":
        tokens = len(_canonical(counted)) + 256
    else:
        client = target._get_client().with_options(max_retries=0, timeout=min(30.0, target.timeout))
        if method_id == "anthropic_messages_count_tokens_v1":
            response = client.messages.count_tokens(**counted)
            tokens = _field(response, "input_tokens")
        elif method_id == "kimi_estimate_token_count_v1":
            response = client.post("/tokenizers/estimate-token-count", cast_to=dict[str, Any], body=counted)
            if _field(response, "error") is not None:
                raise ValueError("Kimi token counter returned an error")
            tokens = _field(_field(response, "data"), "total_tokens")
        else:
            response = client.responses.input_tokens.count(**counted)
            if _field(response, "object") != "response.input_tokens":
                raise ValueError("Responses token counter returned a different object")
            tokens = _field(response, "input_tokens")
    if type(tokens) is not int or tokens < 0:
        raise ValueError("provider token count is not a nonnegative integer")
    receipt["input_tokens"] = tokens
    return receipt


def validate_receipt(target, request: Mapping, receipt: Mapping) -> dict:
    """Recheck retained count identity without repeating its network request."""
    if not isinstance(receipt, Mapping) or set(receipt) != _RECEIPT_FIELDS:
        raise ValueError("retained token-count fields differ")
    body = _checked_request(target, request)
    method, method_id, counted, fee = _count_plan(target, body, network=receipt["method"] != "local_estimate")
    expected = {"request_sha256": request_sha256(body), "count_request_sha256": request_sha256(counted),
                "provider": target.provider, "requested_spec": target.requested_spec,
                "requested_model": target.model, "method": method, "method_id": method_id,
                "count_http_attempts": 0 if method == "local_estimate" else 1, "count_fee_status": fee}
    if any(receipt[key] != value for key, value in expected.items()):
        raise ValueError("retained token-count request, model or counting method changed")
    tokens = receipt["input_tokens"]
    if type(tokens) is not int or tokens < 0:
        raise ValueError("retained token count is not a nonnegative integer")
    if method == "local_estimate" and tokens != len(_canonical(counted)) + 256:
        raise ValueError("retained local token estimate changed")
    return dict(receipt)


def cached_count_request(target, request: Mapping, *, cache_root: Path,
                         allow_network: bool = False) -> dict:
    """Persist each completed counter result; resume validates without recounting."""
    from experiments.retained_response_judge_execute import _exclusive_lock, _read_regular, _write_new

    if type(allow_network) is not bool:
        raise ValueError("allow_network must be an explicit boolean")
    root = Path(cache_root)
    if (not root.is_absolute() or root.is_symlink()
        or root.resolve(strict=True) != root or not root.is_dir()):
        raise ValueError("token-count cache must be one canonical existing directory")
    body = _checked_request(target, request)
    method, method_id, _counted, _fee = _count_plan(target, body, network=allow_network)
    key = request_sha256({"request": body, "target": target.requested_spec,
                          "provider": target.provider, "base_url": str(target.base_url),
                          "method": method, "method_id": method_id})
    path = root / f"{key}.json"
    with _exclusive_lock(root):
        if path.exists() or path.is_symlink():
            receipt, _descriptor = _read_regular(path, label="retained token count", max_bytes=65536)
            checked = validate_receipt(target, body, receipt)
            if checked["method"] != method or checked["method_id"] != method_id:
                raise ValueError("cached token-count method differs from the requested policy")
            return checked
        receipt = count_request(target, body, allow_network=allow_network)
        _write_new(path, receipt)
        return receipt
