"""Local open-weight targets: vLLM and Ollama backends (thesis III.2.2).

These wrap self-hosted inference so open-weight models can be evaluated on the
same footing as hosted APIs. Heavy vLLM dependencies are imported lazily inside
the call path. Ollama uses a dependency-free, size-bounded HTTP transport against
``localhost:11434``; avoiding the convenience SDK is intentional because its
eager response decoding cannot enforce the harness's byte ceiling.

Factories are registered in the shared ``REGISTRY`` under ``"vllm"`` and
``"ollama"`` so the orchestrator can address either backend by id.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterable, Optional

from ..data_models import DialogTurn, Response
from .base import REGISTRY, BaseTarget

_ROLE_MAP = {
    "system": "system",
    "user": "user",
    "assistant": "assistant",
    "tool": "tool",
    "env": "user",  # environment observations surface as user-side context
}

_IMMUTABLE_REVISION = re.compile(r"[0-9a-f]{40,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_OLLAMA_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_OLLAMA_JSON_NODES = 250_000
_MAX_OLLAMA_JSON_DEPTH = 64


def _strict_bounded_json_bytes(data: bytes) -> Any:
    """Decode one standards-conforming, structurally bounded JSON value."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON object key {key!r}")
            value[key] = child
        return value

    def parse_float(number: str) -> float:
        value = float(number)
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value

    value = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=object_pairs,
        parse_float=parse_float,
        parse_constant=lambda constant: (_ for _ in ()).throw(
            ValueError(f"invalid JSON constant {constant}")
        ),
    )
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_OLLAMA_JSON_NODES:
            raise ValueError("JSON node count exceeds the configured limit")
        if depth > _MAX_OLLAMA_JSON_DEPTH:
            raise ValueError("JSON nesting exceeds the configured limit")
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)
    return value


def _is_explicit_local_path(model: str) -> bool:
    """True only when the model spec is an explicit filesystem path.

    A bare Hugging Face hub id such as ``Qwen/Qwen3-VL-8B-Instruct`` is never
    treated as a local checkpoint even if a same-named directory happens to exist
    in the current working directory. A local checkpoint must be given as an
    absolute path or with an explicit ``~``, ``./`` or ``../`` prefix, so
    local-vs-remote identity does not depend on the process's working directory.
    """
    spec = model.strip()
    if not spec:
        return False
    # POSIX-absolute ("/..."), Windows drive-relative/UNC ("\\..."), and the
    # explicit relative prefixes are path signals on any platform; a hub id such
    # as "org/model" matches none of them. is_absolute() additionally catches a
    # Windows drive-absolute path ("C:\\...").
    if spec.startswith(("~", "./", "../", ".\\", "..\\", "/", "\\")):
        return True
    return Path(spec).is_absolute()


class LocalTargetOutputError(RuntimeError):
    """A local backend returned incomplete output or unverifiable provenance."""


def _tree_sha256(path: Path) -> str:
    if path.is_symlink():
        raise ValueError("local model identity cannot be verified through a symlink")
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    if not path.is_dir():
        raise ValueError("local model path must be a regular file or directory")
    all_items = sorted(path.rglob("*"))
    if any(item.is_symlink() for item in all_items):
        raise ValueError("local model tree must not contain symlinks")
    files = [item for item in all_items if item.is_file()]
    if not files:
        raise ValueError("local model directory is empty")
    for item in files:
        file_digest = hashlib.sha256()
        size = 0
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                file_digest.update(chunk)
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest.hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _dialog_to_messages(
    dialog: list[DialogTurn], *, multimodal: bool = False,
    media_roots: Optional[Iterable[str | Path]] = None,
) -> list[dict[str, Any]]:
    """Flatten a URA dialog into OpenAI/vLLM-style chat messages.

    Text content and tool results are inlined as text so that text-only local
    backends still receive the full context of a turn. When ``multimodal`` is set
    (the target declares image support, e.g. a vision-language model served by
    vLLM), any image :class:`~ura.data_models.MediaRef` on a turn is forwarded as
    an OpenAI-style ``image_url`` content part (a ``data:`` base64 URI, or the
    remote URL) - the format ``vllm.LLM.chat`` accepts for VLMs. Turns without
    images keep a bare string so text-only models are unaffected.
    """
    messages: list[dict[str, Any]] = []
    for turn in dialog:
        if turn.provider_state is not None or turn.provider_thinking:
            raise ValueError(
                "local vLLM target cannot consume provider-native continuation state"
            )
        role = _ROLE_MAP.get(turn.role, "user")
        parts: list[str] = []
        if turn.content:
            parts.append(turn.content)
        if turn.tool_call is not None:
            parts.append(
                f"[tool_call {turn.tool_call.name}"
                f"({json.dumps(turn.tool_call.arguments)})]"
            )
        if turn.tool_result is not None:
            parts.append(f"[tool_result] {turn.tool_result}")
        text = "\n".join(parts)

        if turn.media and not multimodal:
            raise ValueError("text-only local target cannot render physical media")
        unsupported = [m.modality for m in turn.media if m.modality != "image"]
        if unsupported:
            raise ValueError(
                "local multimodal renderer cannot encode media modalities: "
                + ",".join(sorted(set(unsupported)))
            )
        images = list(turn.media) if multimodal else []
        if not images:
            messages.append({"role": role, "content": text})
            continue

        # lazy import keeps this module stdlib-only until an image is actually sent
        from .api import _encode_media

        content: list[dict[str, Any]] = []
        if text:
            content.append({"type": "text", "text": text})
        for media in images:
            mime, data, url = _encode_media(media, allowed_roots=media_roots)
            image_url = url or f"data:{mime};base64,{data}"
            content.append({"type": "image_url", "image_url": {"url": image_url}})
        messages.append({"role": role, "content": content})
    return messages


def _dialog_to_ollama_messages(
    dialog: list[DialogTurn],
    *,
    multimodal: bool = False,
    media_roots: Optional[Iterable[str | Path]] = None,
) -> list[dict[str, Any]]:
    """Render Ollama ``/api/chat`` messages with bounded base64 images."""

    messages: list[dict[str, Any]] = []
    for turn in dialog:
        if turn.provider_state is not None or turn.provider_thinking:
            raise ValueError(
                "Ollama target cannot consume provider-native continuation state"
            )
        role = _ROLE_MAP.get(turn.role, "user")
        parts: list[str] = []
        if turn.content:
            parts.append(turn.content)
        if turn.tool_call is not None:
            parts.append(
                f"[tool_call {turn.tool_call.name}"
                f"({json.dumps(turn.tool_call.arguments)})]"
            )
        if turn.tool_result is not None:
            parts.append(f"[tool_result] {turn.tool_result}")
        message: dict[str, Any] = {"role": role, "content": "\n".join(parts)}
        if turn.media and not multimodal:
            raise ValueError("text-only Ollama target cannot render physical media")
        unsupported = [media.modality for media in turn.media if media.modality != "image"]
        if unsupported:
            raise ValueError(
                "Ollama target cannot encode media modalities: "
                + ",".join(sorted(set(unsupported)))
            )
        if turn.media:
            from .api import _encode_media

            images: list[str] = []
            for media in turn.media:
                _mime, encoded, remote_url = _encode_media(
                    media, allowed_roots=media_roots
                )
                if remote_url is not None:
                    raise ValueError(
                        "Ollama image input requires content-addressed local or "
                        "inline bytes; remote image URLs are not admitted"
                    )
                images.append(encoded)
            message["images"] = images
        messages.append(message)
    return messages


class VLLMTarget(BaseTarget):
    """A model served by the in-process vLLM engine (thesis III.2.2).

    Tuned for the 2x RTX 4090 rig by defaulting to ``tensor_parallel_size=2``.
    The :class:`vllm.LLM` engine is heavyweight, so it is constructed lazily on
    the first :meth:`generate` call and cached for the lifetime of the target.
    """

    name = "vllm"
    modality_support: tuple[str, ...] = ("text",)

    def __init__(
        self,
        model: str,
        *,
        revision: Optional[str] = None,
        model_digest: Optional[str] = None,
        tensor_parallel_size: int = 2,
        quantization: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        dtype: str = "auto",
        gpu_memory_utilization: float = 0.90,
        modality_support: Optional[tuple[str, ...]] = None,
        media_roots: Optional[Iterable[str | Path]] = None,
        **engine_kwargs: Any,
    ) -> None:
        self.revision = revision.lower() if isinstance(revision, str) else revision
        self.model_digest = (
            model_digest.lower() if isinstance(model_digest, str) else model_digest
        )
        self._runtime_model = model
        self.model = "local-checkpoint" if _is_explicit_local_path(model) else model
        if self.revision is not None and self.model_digest is not None:
            raise ValueError("VLLMTarget accepts revision or model_digest, not both")
        identity = self.revision or (
            f"sha256:{self.model_digest}" if self.model_digest else "unresolved"
        )
        # The runtime path is private process state. Persisted target/response
        # identities bind the checkpoint bytes without leaking a workstation path.
        self.name = f"vllm:{self.model}@{identity}"
        # A vision-language model declares ("text", "image") so image datapoints
        # are forwarded. A text-only target remains ("text",); scored image cells
        # are rejected rather than flattened or relabelled as text-only.
        self.capabilities_declared = modality_support is not None
        self.modality_support = tuple(modality_support or ("text",))
        self.modality_combinations = tuple(
            [("text",)]
            + (
                [("text", "image")]
                if "image" in self.modality_support
                else []
            )
        )
        from .api import _media_roots
        self.media_roots = _media_roots(media_roots)
        self.tensor_parallel_size = tensor_parallel_size
        self.quantization = quantization
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.dtype = dtype
        self.gpu_memory_utilization = gpu_memory_utilization
        self.engine_kwargs = engine_kwargs
        self._llm: Any = None
        self._identity_verified = False

    def validate_research_identity(self) -> None:
        if self._identity_verified:
            return
        if not self.capabilities_declared:
            raise ValueError(
                "VLLMTarget measured runs require an explicit modality_support "
                "declaration; model-name guessing is not evidence"
            )
        allowed = {"text", "image"}
        if (
            not self.modality_support
            or "text" not in self.modality_support
            or set(self.modality_support) - allowed
            or len(set(self.modality_support)) != len(self.modality_support)
        ):
            raise ValueError(
                "VLLMTarget modality_support must be a unique text[/image] declaration"
            )
        # Local vs remote (hub) identity is decided by an explicit path signal, not
        # by cwd-relative existence, so a bare hub id can never be silently treated
        # as a local checkpoint that shadows a same-named working-directory folder.
        if _is_explicit_local_path(self._runtime_model):
            local_path = Path(self._runtime_model).expanduser()
            if not isinstance(self.model_digest, str) or not _SHA256.fullmatch(
                self.model_digest
            ):
                raise ValueError(
                    "local vLLM checkpoints require an explicit 64-hex model_digest"
                )
            if local_path.is_symlink():
                raise ValueError("local vLLM checkpoint path must not be a symlink")
            resolved = local_path.resolve(strict=True)
            if _tree_sha256(resolved) != self.model_digest:
                raise ValueError("local vLLM checkpoint digest does not match bytes")
        elif not isinstance(self.revision, str) or not _IMMUTABLE_REVISION.fullmatch(
            self.revision
        ):
            raise ValueError(
                "remote (hub) vLLM checkpoints require an immutable 40-64 hex revision"
            )
        self._identity_verified = True

    def _engine(self) -> Any:
        """Lazily build and cache the vLLM engine."""
        self.validate_research_identity()
        if self._llm is None:
            try:
                from vllm import LLM  # type: ignore
            except ImportError as exc:  # pragma: no cover - offline path
                raise RuntimeError(
                    "vllm is required for VLLMTarget; pip install vllm"
                ) from exc
            identity_kwargs: dict[str, Any] = {}
            if self.revision is not None:
                identity_kwargs["revision"] = self.revision
                # Pin the tokenizer/chat-template to the SAME immutable revision
                # so it cannot drift independently of the model weights.
                identity_kwargs["tokenizer_revision"] = self.revision
            self._llm = LLM(
                model=self._runtime_model,
                tensor_parallel_size=self.tensor_parallel_size,
                quantization=self.quantization,
                dtype=self.dtype,
                gpu_memory_utilization=self.gpu_memory_utilization,
                **identity_kwargs,
                **self.engine_kwargs,
            )
        return self._llm

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        try:
            from vllm import SamplingParams  # type: ignore
        except ImportError as exc:  # pragma: no cover - offline path
            raise RuntimeError(
                "vllm is required for VLLMTarget; pip install vllm"
            ) from exc

        llm = self._engine()
        messages = _dialog_to_messages(
            dialog,
            multimodal="image" in self.modality_support,
            media_roots=self.media_roots,
        )
        sampling_kwargs: dict[str, Any] = dict(
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        if seed is not None:
            sampling_kwargs["seed"] = int(seed)
        sampling = SamplingParams(**sampling_kwargs)

        t0 = time.perf_counter()
        outputs = llm.chat(messages, sampling)  # type: ignore[attr-defined]
        latency_ms = (time.perf_counter() - t0) * 1000.0

        text, tokens, finish_reason, stop_reason = self._extract(outputs)
        return Response(
            attempt_id="",
            target=self.name,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "backend": "vllm",
                "model": self.model,
                "resolved_model": self.model,
                "model_revision": self.revision,
                "model_digest": self.model_digest,
                "finish_reason": finish_reason,
                "stop_reason": stop_reason,
                "requested_seed": seed,
                "target_sampling_control": (
                    "local_seed" if seed is not None else "uncontrolled"
                ),
                "generation": {
                    "seed": seed,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                },
            },
        )

    @staticmethod
    def _extract(
        outputs: Any,
    ) -> tuple[str, dict[str, int], str, Optional[str]]:
        """Pull generated text + token counts from a vLLM ``RequestOutput``.

        Isolated so the online API surface is easy to adjust in one place.
        """
        if not isinstance(outputs, (list, tuple)) or len(outputs) != 1:
            raise LocalTargetOutputError(
                "vLLM must return exactly one RequestOutput for one chat request"
            )
        first = outputs[0]
        completions = getattr(first, "outputs", None)
        if not isinstance(completions, (list, tuple)) or len(completions) != 1:
            raise LocalTargetOutputError("vLLM returned zero or multiple completions")
        completion = completions[0]
        text = getattr(completion, "text", "") or ""
        if not text.strip():
            raise LocalTargetOutputError("vLLM returned an empty completion")
        finish_reason = getattr(completion, "finish_reason", None)
        if finish_reason != "stop":
            raise LocalTargetOutputError(
                f"vLLM completion is truncated or incomplete: {finish_reason!r}"
            )
        stop_reason_raw = getattr(completion, "stop_reason", None)
        stop_reason = str(stop_reason_raw) if stop_reason_raw is not None else None
        prompt_ids = getattr(first, "prompt_token_ids", None)
        completion_ids = getattr(completion, "token_ids", None)
        if prompt_ids is None or completion_ids is None:
            raise LocalTargetOutputError("vLLM omitted prompt/completion token provenance")
        prompt_n = len(prompt_ids)
        completion_n = len(completion_ids)
        tokens = {
            "prompt": prompt_n,
            "completion": completion_n,
            "total": prompt_n + completion_n,
        }
        return text, tokens, finish_reason, stop_reason


class OllamaTarget(BaseTarget):
    """A model served by a local Ollama daemon (thesis III.2.2).

    Uses a dependency-free HTTP call against the daemon's ``/api/chat`` endpoint
    via ``urllib`` so both model-inventory and completion bodies are bounded
    before JSON decoding, regardless of whether the optional SDK is installed.
    """

    name = "ollama"
    modality_support: tuple[str, ...] = ("text",)

    def __init__(
        self,
        model: str,
        *,
        model_digest: Optional[str] = None,
        host: str = "http://localhost:11434",
        temperature: float = 0.0,
        num_predict: int = 512,
        timeout: float = 300.0,
        modality_support: tuple[str, ...] = ("text",),
        media_roots: Optional[Iterable[str | Path]] = None,
        **options: Any,
    ) -> None:
        self.model = model
        self.model_digest = (
            model_digest.lower() if isinstance(model_digest, str) else model_digest
        )
        identity = f"sha256:{self.model_digest}" if self.model_digest else "unresolved"
        self.name = f"ollama:{model}@{identity}"
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout = timeout
        self.modality_support = tuple(modality_support)
        self.modality_combinations = tuple(
            [("text",)]
            + ([("text", "image")] if "image" in self.modality_support else [])
        )
        from .api import _media_roots

        self.media_roots = _media_roots(media_roots)
        self.options = options

    def validate_research_identity(self) -> None:
        if not isinstance(self.model_digest, str) or not _SHA256.fullmatch(
            self.model_digest
        ):
            raise ValueError(
                "OllamaTarget measured runs require an explicit 64-hex model_digest"
            )
        if (
            not self.modality_support
            or "text" not in self.modality_support
            or set(self.modality_support) - {"text", "image"}
            or len(set(self.modality_support)) != len(self.modality_support)
        ):
            raise ValueError(
                "OllamaTarget modality_support must be a unique text[/image] declaration"
            )

    @staticmethod
    def _normalized_digest(value: object) -> Optional[str]:
        if not isinstance(value, str):
            return None
        normalized = value.lower().removeprefix("sha256:")
        return normalized if _SHA256.fullmatch(normalized) else None

    def _verify_daemon_identity(self) -> str:
        self.validate_research_identity()
        request = urllib.request.Request(f"{self.host}/api/tags", method="GET")
        inventory = self._bounded_json_request(
            request, purpose="model inventory"
        )
        if not isinstance(inventory, dict) or not isinstance(inventory.get("models"), list):
            raise LocalTargetOutputError("Ollama returned an invalid model inventory")
        matches = [
            item for item in inventory["models"]
            if isinstance(item, dict)
            and (item.get("model") == self.model or item.get("name") == self.model)
        ]
        if len(matches) != 1:
            raise LocalTargetOutputError(
                f"Ollama inventory did not resolve exactly one {self.model!r} model"
            )
        resolved = self._normalized_digest(matches[0].get("digest"))
        if resolved != self.model_digest:
            raise LocalTargetOutputError(
                "Ollama daemon model digest does not match declared model_digest"
            )
        return resolved

    def _sampling_options(self, seed: int | None = None) -> dict[str, Any]:
        opts: dict[str, Any] = {
            "temperature": self.temperature,
            "num_predict": self.num_predict,
        }
        opts.update(self.options)
        if seed is not None:
            opts["seed"] = int(seed)
        return opts

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        verified_digest = self._verify_daemon_identity()
        messages = _dialog_to_ollama_messages(
            dialog,
            multimodal="image" in self.modality_support,
            media_roots=self.media_roots,
        )
        t0 = time.perf_counter()
        data = self._chat(messages, seed=seed)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        if not isinstance(data, dict):
            raise LocalTargetOutputError("Ollama response is not an object")
        if data.get("error"):
            raise LocalTargetOutputError(f"Ollama returned an error: {data['error']}")
        if data.get("done") is not True:
            raise LocalTargetOutputError("Ollama response did not declare done=true")
        done_reason = data.get("done_reason")
        if done_reason != "stop":
            raise LocalTargetOutputError(
                f"Ollama response is truncated or incomplete: {done_reason!r}"
            )
        resolved_model = data.get("model")
        if not isinstance(resolved_model, str) or resolved_model != self.model:
            raise LocalTargetOutputError(
                f"Ollama returned unexpected model identity {resolved_model!r}"
            )
        message = data.get("message")
        if not isinstance(message, dict):
            raise LocalTargetOutputError("Ollama response omitted its message object")
        if message.get("role", "assistant") != "assistant":
            raise LocalTargetOutputError("Ollama returned a non-assistant message")
        text = message.get("content")
        if not isinstance(text, str) or not text.strip():
            raise LocalTargetOutputError("Ollama returned an empty completion")
        tokens = self._token_counts(data)
        return Response(
            attempt_id="",
            target=self.name,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "backend": "ollama",
                "model": self.model,
                "resolved_model": resolved_model,
                "model_digest": self.model_digest,
                "verified_model_digest": verified_digest,
                "model_identity_verified": True,
                "done": True,
                "done_reason": done_reason,
                "requested_seed": seed,
                "target_sampling_control": (
                    "local_seed" if seed is not None else "uncontrolled"
                ),
                "generation": {
                    "seed": seed,
                    "temperature": self.temperature,
                    "num_predict": self.num_predict,
                },
            },
        )

    def _chat(
        self, messages: list[dict[str, Any]], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Send a timeout- and byte-bounded chat request."""
        return self._chat_http(messages, seed=seed)

    def _chat_http(
        self, messages: list[dict[str, Any]], *, seed: int | None = None
    ) -> dict[str, Any]:
        """Dependency-free fallback against Ollama's REST API."""
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "options": self._sampling_options(seed),
                "stream": False,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        value = self._bounded_json_request(req, purpose="chat response")
        if not isinstance(value, dict):
            raise LocalTargetOutputError("Ollama HTTP response is not a JSON object")
        return value

    def _bounded_json_request(
        self, request: urllib.request.Request, *, purpose: str
    ) -> Any:
        """Read one Ollama JSON body with a hard pre-parse byte ceiling."""

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except (TypeError, ValueError) as exc:
                        raise LocalTargetOutputError(
                            f"Ollama {purpose} has invalid Content-Length"
                        ) from exc
                    if declared_size < 0 or declared_size > _MAX_OLLAMA_RESPONSE_BYTES:
                        raise LocalTargetOutputError(
                            f"Ollama {purpose} exceeds the 4 MiB limit"
                        )
                body = response.read(_MAX_OLLAMA_RESPONSE_BYTES + 1)
        except LocalTargetOutputError:
            raise
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            raise RuntimeError(
                f"could not obtain Ollama {purpose} from {self.host} within "
                f"the configured {self.timeout:g}s timeout"
            ) from exc
        if len(body) > _MAX_OLLAMA_RESPONSE_BYTES:
            raise LocalTargetOutputError(
                f"Ollama {purpose} exceeds the 4 MiB limit"
            )
        try:
            return _strict_bounded_json_bytes(body)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise LocalTargetOutputError(
                f"Ollama {purpose} is not bounded standards-conforming JSON"
            ) from exc

    @staticmethod
    def _token_counts(data: dict[str, Any]) -> dict[str, int]:
        prompt_n = data.get("prompt_eval_count")
        completion_n = data.get("eval_count")
        if (
            isinstance(prompt_n, bool)
            or not isinstance(prompt_n, int)
            or prompt_n < 0
            or isinstance(completion_n, bool)
            or not isinstance(completion_n, int)
            or completion_n < 0
        ):
            raise LocalTargetOutputError(
                "Ollama omitted valid prompt/completion token provenance"
            )
        return {
            "prompt": prompt_n,
            "completion": completion_n,
            "total": prompt_n + completion_n,
        }


def make_vllm_target(model: str, **kwargs: Any) -> "VLLMTarget":
    """Factory helper for :class:`VLLMTarget` (used by the registry)."""
    return VLLMTarget(model, **kwargs)


def make_ollama_target(model: str, **kwargs: Any) -> "OllamaTarget":
    """Factory helper for :class:`OllamaTarget` (used by the registry)."""
    return OllamaTarget(model, **kwargs)


# Register generic factories. Concrete model ids can be registered by callers
# via ``REGISTRY.register(id, lambda: make_vllm_target("org/model", ...))``.
REGISTRY.register(
    "vllm",
    lambda: make_vllm_target("Qwen/Qwen3-VL-8B-Instruct"),
    backend="vllm",
    tensor_parallel_size=2,
)
REGISTRY.register(
    "ollama",
    lambda: make_ollama_target("llama3.3"),
    backend="ollama",
)

# Gray Swan Cygnet circuit-breaker (RR) open weights - the built-in-defense contrast
# of RQ3 (thesis II.6.1 / V.1.2 / V.2.3). Registered as first-class targets so the exact
# HF ids resolve without the vllm: prefix; the LLaVA variant is vision-capable.
REGISTRY.register(
    "GraySwanAI/Llama-3-8B-Instruct-RR",
    lambda: make_vllm_target("GraySwanAI/Llama-3-8B-Instruct-RR"),
    backend="vllm",
    tensor_parallel_size=2,
)
REGISTRY.register(
    "GraySwanAI/llava-v1.6-mistral-7b-hf-RR",
    lambda: make_vllm_target(
        "GraySwanAI/llava-v1.6-mistral-7b-hf-RR", modality_support=("text", "image")
    ),
    backend="vllm",
    tensor_parallel_size=2,
)


__all__ = [
    "VLLMTarget",
    "OllamaTarget",
    "make_vllm_target",
    "make_ollama_target",
]
