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

import base64
import gc
import hashlib
import json
import math
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Literal, Optional

from ..data_models import DialogTurn, Response
from ..ollama_security import (
    DEFAULT_OLLAMA_URL,
    NoRedirect,
    OllamaProcessLock,
    canonicalize_ollama_url,
    open_with_deadline,
    read_bounded_response,
    remaining_seconds,
)
from .base import (
    REGISTRY,
    BaseTarget,
    TargetAnswerError,
    TargetInputError,
    TargetIntegrityError,
)

_ROLE_MAP = {
    "system": "system",
    "user": "user",
    "assistant": "assistant",
    "tool": "tool",
    "env": "user",  # environment observations surface as user-side context
}

# Exact retained LLaVA-Mistral base/RR tokenizer templates. Both use [INST]
# without a system-role token; they differ only in assistant whitespace. This
# is a renderer capability, not a guess based on a model's name or config ID.
_LEGACY_MISTRAL_INST_TEMPLATES = frozenset({
    "18f104df66d35dcc5eae04e8831dd58a9b9191f82d54147199fe6bc6c8e5bc4c",
    "26a59556925c987317ce5291811ba3b7f32ec4c647c400c6cc7e3a9993007ba7",
})

_IMMUTABLE_REVISION = re.compile(r"[0-9a-f]{40,64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_OLLAMA_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_OLLAMA_REQUEST_BYTES = 32 * 1024 * 1024
_MAX_OLLAMA_JSON_NODES = 250_000
_MAX_OLLAMA_JSON_DEPTH = 64
_MAX_OLLAMA_MODELS = 512
_OLLAMA_TAG = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    r"(?::[A-Za-z0-9][A-Za-z0-9._-]*)?\Z"
)
MAX_VLLM_MODEL_LEN = 1_000_000
MAX_VLLM_GENERATION_TOKENS = 25_000
DEFAULT_LOCAL_GENERATION_TOKENS = 4_096
DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS = 120.0
DEFAULT_VLLM_GENERATION_TOKENS = DEFAULT_LOCAL_GENERATION_TOKENS
# vLLM 0.27's -1 sentinel derives the model-native ceiling and then reduces it
# to the largest KV-cache allocation that fits the GPUs available at engine
# construction. It is distinct from an omitted value, which requests the
# native ceiling even when that cannot fit.
DEFAULT_VLLM_MAX_MODEL_LEN = -1
# ``fit`` is the default hardware-fit policy. OllamaTarget starts from the
# pinned model's native context, performs load-only residency probes, and
# halves the candidate until /api/ps proves that the complete runtime is GPU
# resident. ``max`` remains an explicit native-maximum condition for retained
# historical work.
DEFAULT_OLLAMA_NUM_CTX: Literal["fit"] = "fit"
MAX_OLLAMA_NUM_CTX = 1_000_000
MAX_OLLAMA_NUM_PREDICT = 25_000
MIN_OLLAMA_HARDWARE_FIT_CONTEXT = 4_096
# Direct target construction uses a finite profiling baseline. Runner and Rig
# Web reject local generative campaigns until an identity-bound readiness
# profile replaces this value.
DEFAULT_OLLAMA_NUM_PREDICT = DEFAULT_LOCAL_GENERATION_TOKENS
VLLM_IN_PROCESS_EXECUTION_MODE = "in_process"
_VLLM_MULTIPROCESSING_ENV = "VLLM_ENABLE_V1_MULTIPROCESSING"
_VLLM_ENVIRONMENT_LOCK = threading.RLock()
_VLLM_CONTEXT_LIMIT_ERROR = re.compile(
    r"(?:decoder )?prompt \(length (?P<length>[0-9]+)\) is longer than the "
    r"maximum model length of (?P<limit>[0-9]+)",
    re.IGNORECASE,
)


def validate_local_request_timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 1.0 <= float(value) <= 3_600.0
    ):
        raise ValueError("timeout must be numeric in [1, 3600] seconds")
    return float(value)


@contextmanager
def _vllm_generation_deadline(seconds: float) -> Iterator[None]:
    """Bound one synchronous vLLM request on POSIX main-thread execution."""

    if (
        os.name != "posix"
        or threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "setitimer")
    ):
        yield
        return

    def expired(_signum: int, _frame: object) -> None:
        raise LocalTargetAnswerError(
            f"vLLM generation exceeded the configured hard {seconds:g}s deadline",
            category="generation_timeout",
        )

    previous_handler = signal.getsignal(signal.SIGALRM)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 0.0)
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer != (0.0, 0.0):
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS = frozenset({
    "revision",
    "tensor_parallel_size",
    "gpu_memory_utilization",
    "max_tokens",
    "max_model_len",
    "parameter_count_b",
    "multi_gpu_compatible",
    "quantization",
    "allow_unknown_fit",
})
VLLM_FORBIDDEN_LOCAL_CONFIG_FIELDS = frozenset({"num_ctx", "num_predict", "think", "context_ceiling"})
_OLLAMA_RESERVED_CONSTRUCTOR_OPTIONS = (
    OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS
    | {"digest", "modalities", "multi_gpu_support_basis", "dtype"}
)


@contextmanager
def _vllm_in_process_environment() -> Iterator[None]:
    """Select vLLM's in-process EngineCore only while importing/building it.

    vLLM reads this process-global setting while importing and constructing
    ``LLM``. The harness admits only one local target per process, but the lock
    also makes nested or concurrent adapter construction restore the operator's
    prior environment deterministically.
    """

    with _VLLM_ENVIRONMENT_LOCK:
        previous = os.environ.get(_VLLM_MULTIPROCESSING_ENV)
        os.environ[_VLLM_MULTIPROCESSING_ENV] = "0"
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop(_VLLM_MULTIPROCESSING_ENV, None)
            else:
                os.environ[_VLLM_MULTIPROCESSING_ENV] = previous


def canonical_local_model_identity(
    model: object,
    *,
    revision: object = None,
    model_digest: object = None,
) -> tuple[str, ...] | None:
    """Return the strongest immutable local-model identity available.

    A byte digest intentionally outranks a daemon tag or checkpoint locator, so
    two Ollama aliases (or two explicit-path aliases) cannot masquerade as two
    scientific target models. Hub revisions remain qualified by the exact model
    id because a commit-like revision is not globally unique across repositories.
    """

    if isinstance(model_digest, str):
        digest = model_digest.strip().lower()
        if _SHA256.fullmatch(digest):
            return "sha256", digest
    if isinstance(model, str) and isinstance(revision, str):
        normalized_model = model.strip()
        normalized_revision = revision.strip().lower()
        if normalized_model and _IMMUTABLE_REVISION.fullmatch(normalized_revision):
            return "model-revision", normalized_model, normalized_revision
    return None


def validate_vllm_max_model_len(value: object) -> int:
    """Return vLLM's hardware-fit sentinel or one bounded context limit.

    ``max_model_len`` controls engine/KV-cache allocation, not generation
    length.  The upper bound admits current long-context checkpoints while
    preventing a malformed local registry from requesting an unbounded engine
    allocation.
    """

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or (value != -1 and not 1 <= value <= MAX_VLLM_MODEL_LEN)
    ):
        raise ValueError(
            "max_model_len must be -1 (hardware-fit) or an integer in "
            f"1..{MAX_VLLM_MODEL_LEN}"
        )
    return value


def validate_vllm_max_tokens(value: object) -> int:
    """Return one bounded vLLM generation limit or reject it."""

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_VLLM_GENERATION_TOKENS
    ):
        raise ValueError(
            "max_tokens must be an integer in "
            f"1..{MAX_VLLM_GENERATION_TOKENS}"
        )
    return value


def validate_ollama_num_ctx(value: object) -> int | Literal["fit", "max"]:
    """Return an Ollama context policy sentinel or one finite allocation."""

    if value in {"fit", "max"}:
        return value

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_OLLAMA_NUM_CTX
    ):
        raise ValueError(
            "num_ctx must be 'fit', 'max', or an integer in "
            f"1..{MAX_OLLAMA_NUM_CTX}"
        )
    return value


def validate_ollama_context_ceiling(value: object) -> int:
    """Bound hardware-fit allocation without permitting CPU spill."""
    if type(value) is not int or not 1 <= value <= MAX_OLLAMA_NUM_CTX:
        raise ValueError(f"context_ceiling must be an integer in 1..{MAX_OLLAMA_NUM_CTX}")
    return value


def validate_ollama_num_predict(value: object) -> int:
    """Return Ollama's maximum sentinel or one bounded finite limit."""

    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or (value != -1 and not 1 <= value <= MAX_OLLAMA_NUM_PREDICT)
    ):
        raise ValueError(
            "num_predict must be -1 or an integer in "
            f"1..{MAX_OLLAMA_NUM_PREDICT}"
        )
    return value


def validate_ollama_think(value: object) -> bool | str:
    """Return one explicit Ollama thinking policy or reject it."""

    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value in {"low", "medium", "high"}:
        return value
    raise ValueError("think must be boolean or one of low, medium, high")


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


class LocalTargetAnswerError(LocalTargetOutputError, TargetAnswerError):
    """One local inference call produced no usable answer."""


class LocalTargetInputError(LocalTargetOutputError, TargetInputError):
    """One local input was rejected before model generation could begin."""


def _vllm_context_limit_failure(exc: Exception) -> tuple[int, int] | None:
    """Return only safe numeric context facts for one exact vLLM rejection."""

    if type(exc).__name__ != "VLLMValidationError":
        return None
    matched = _VLLM_CONTEXT_LIMIT_ERROR.search(str(exc))
    if matched is None:
        return None
    length = int(matched.group("length"))
    limit = int(matched.group("limit"))
    if limit < 1 or length <= limit:
        return None
    return length, limit


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


def _vllm_chat_template_messages(
    messages: list[dict[str, Any]], llm: Any,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Encode a leading instruction in the two known system-less templates.

    Retained DialogTurns remain unchanged. The system text becomes the prefix
    of the first [INST] instruction, not a fabricated turn or claimed native
    system-role channel. Other templates and invalid role sequences retain
    their native handling. Content, whitespace and image order are preserved.
    """
    native = {"policy": "native"}
    if (len(messages) < 2 or messages[0]["role"] != "system"
            or messages[1]["role"] != "user"):
        return messages, native
    get_tokenizer = getattr(llm, "get_tokenizer", None)
    if not callable(get_tokenizer):
        return messages, native
    template = getattr(get_tokenizer(), "chat_template", None)
    if not isinstance(template, str):
        return messages, native
    digest = hashlib.sha256(template.encode("utf-8")).hexdigest()
    if digest not in _LEGACY_MISTRAL_INST_TEMPLATES:
        return messages, native
    system = messages[0]["content"]
    user = messages[1]["content"]
    if not isinstance(system, str):
        return messages, native
    prefix = system + "\n\n"
    if isinstance(user, str):
        content: Any = prefix + user
    elif isinstance(user, list):
        content = list(user)
        if content and content[0].get("type") == "text":
            content[0] = {**content[0], "text": prefix + content[0]["text"]}
        else:
            content.insert(0, {"type": "text", "text": prefix})
    else:
        return messages, native
    rendered = [{**messages[1], "content": content}, *messages[2:]]
    return rendered, {"policy": "leading_system_in_mistral_inst_v1",
                      "template_sha256": digest}


def _ollama_image_payload(mime: str, encoded: str) -> tuple[str, dict[str, Any] | None]:
    """Use lossless PNG for WebP, which some Ollama engines cannot decode."""
    if mime != "image/webp":
        return encoded, None
    image = _require("PIL.Image", "Ollama WebP image delivery")
    original = base64.b64decode(encoded, validate=True)
    try:
        with image.open(BytesIO(original)) as decoded:
            if decoded.format != "WEBP" or getattr(decoded, "n_frames", 1) != 1:
                raise LocalTargetInputError("Ollama WebP delivery requires one still image")
            decoded.load()
            if decoded.mode not in {"RGB", "RGBA"}:
                raise LocalTargetInputError("Ollama WebP delivery cannot preserve this pixel mode")
            buffer = BytesIO()
            decoded.save(buffer, format="PNG")
            delivered = buffer.getvalue()
            trace = dict(source_mime=mime, delivered_mime="image/png", source_bytes=len(original),
                delivered_bytes=len(delivered), width=decoded.width, height=decoded.height,
                pixel_mode=decoded.mode, delivered_sha256=hashlib.sha256(delivered).hexdigest(),
                resized=False, decoded_pixels_preserved=True)
    except (OSError, ValueError) as exc:
        raise LocalTargetInputError("Ollama could not decode the retained WebP image") from exc
    return base64.b64encode(delivered).decode("ascii"), trace


def _dialog_to_ollama_messages(
    dialog: list[DialogTurn],
    *,
    multimodal: bool = False,
    media_roots: Optional[Iterable[str | Path]] = None,
    image_transport: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Render Ollama ``/api/chat`` messages with bounded base64 images."""

    messages: list[dict[str, Any]] = []
    for turn_index, turn in enumerate(dialog):
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
            for media_index, media in enumerate(turn.media):
                _mime, encoded, remote_url = _encode_media(
                    media, allowed_roots=media_roots
                )
                if remote_url is not None:
                    raise ValueError(
                        "Ollama image input requires content-addressed local or "
                        "inline bytes; remote image URLs are not admitted"
                    )
                encoded, trace = _ollama_image_payload(_mime, encoded)
                if trace is not None and image_transport is not None:
                    image_transport.append(dict(trace, turn_index=turn_index, media_index=media_index,
                        source_sha256=media.sha256))
                images.append(encoded)
            message["images"] = images
        messages.append(message)
    return messages


class VLLMTarget(BaseTarget):
    """A model served by the in-process vLLM engine (thesis III.2.2).

    The :class:`vllm.LLM` engine is heavyweight, so it is constructed lazily and
    cached for the lifetime of the target. Measured orchestration supplies an
    explicit one- or two-GPU tensor-parallel condition and admits only one local
    target per process. The EngineCore client itself is always ``InprocClient``;
    tensor-parallel workers remain an independent vLLM executor concern.
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
        max_tokens: Optional[int] = DEFAULT_VLLM_GENERATION_TOKENS,
        max_model_len: Optional[int] = DEFAULT_VLLM_MAX_MODEL_LEN,
        timeout: float = DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
        temperature: float = 0.0,
        dtype: str = "auto",
        gpu_memory_utilization: float = 0.90,
        modality_support: Optional[tuple[str, ...]] = None,
        media_roots: Optional[Iterable[str | Path]] = None,
        model_runtime: Any = None,
        managed_model_role: str = "vllm_target",
        engine_core_execution_mode: str = VLLM_IN_PROCESS_EXECUTION_MODE,
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
        self.max_tokens = (
            None if max_tokens is None else validate_vllm_max_tokens(max_tokens)
        )
        self.max_model_len = (
            None
            if max_model_len is None
            else validate_vllm_max_model_len(max_model_len)
        )
        self.timeout = validate_local_request_timeout(timeout)
        if (
            self.max_model_len is not None
            and self.max_model_len > 0
            and self.max_tokens is not None
            and self.max_tokens > self.max_model_len
        ):
            raise ValueError("max_tokens must not exceed max_model_len")
        self.temperature = temperature
        self.dtype = dtype
        self.gpu_memory_utilization = gpu_memory_utilization
        if engine_core_execution_mode != VLLM_IN_PROCESS_EXECUTION_MODE:
            raise ValueError(
                "VLLMTarget supports only the fail-closed in_process EngineCore mode"
            )
        # Public so Runner's component config binds every run to the selected
        # vLLM process topology before the first model call.
        self.engine_core_execution_mode = engine_core_execution_mode
        self.engine_kwargs = engine_kwargs
        if managed_model_role not in {"vllm_target", "llm_judge"}:
            raise ValueError("VLLMTarget managed model role is invalid")
        # The managed snapshot locator lives only inside this private runtime
        # object. Component serialization excludes underscore attributes, so
        # neither it nor a workstation path can enter durable evidence.
        self._model_runtime = model_runtime
        self._managed_model_role = managed_model_role
        self._llm: Any = None
        self._resolved_max_model_len: Optional[int] = None
        self._identity_verified = False

    @staticmethod
    def _verify_engine_core_execution_mode(engine: Any) -> None:
        """Fail closed unless vLLM realized its synchronous in-process client.

        In vLLM 0.27, ``LLM.llm_engine.engine_core`` is ``InprocClient`` only
        when V1 EngineCore multiprocessing is disabled. ``SyncMPClient`` owns a
        ZeroMQ output thread whose teardown can abort the Runner after otherwise
        successful image generation, so absence of an error during construction
        is not sufficient admission evidence.
        """

        try:
            llm_engine = getattr(engine, "llm_engine")
            core_client = getattr(llm_engine, "engine_core")
            client_type = type(core_client).__name__
            has_output_thread = hasattr(core_client, "output_queue_thread")
            in_process_core = getattr(core_client, "engine_core")
            shutdown = getattr(core_client, "shutdown", None)
        except Exception:
            raise RuntimeError(
                "vLLM did not expose a verifiable in-process EngineCore client"
            ) from None
        if (
            client_type != "InprocClient"
            or has_output_thread
            or in_process_core is None
            or not callable(shutdown)
        ):
            raise RuntimeError(
                "vLLM did not realize the required in-process EngineCore client"
            ) from None

    @staticmethod
    def _shutdown_engine(engine: Any) -> None:
        """Invoke the owning vLLM shutdown hook exactly once.

        vLLM 0.27's offline ``LLM`` facade does not expose ``shutdown``. Its
        owning client is ``LLM.llm_engine.engine_core``. Accepted engines use
        ``InprocClient``, whose official ``shutdown`` hook releases EngineCore
        without a SyncMPClient output thread or a Runner-owned ZeroMQ context.
        Do not reach into third-party thread or context internals during cleanup.
        Older vLLM releases expose the hook on the facade, engine, or model
        executor, so retain those bounded compatibility fallbacks.
        """

        candidates: list[Any] = [engine]
        llm_engine: Any = None
        nested: Any = None
        lookup_failed = False
        try:
            llm_engine = getattr(engine, "llm_engine", None)
        except Exception:
            lookup_failed = True
        if llm_engine is not None:
            candidates.append(llm_engine)
            for attribute in ("engine_core", "model_executor"):
                try:
                    nested = getattr(llm_engine, attribute, None)
                except Exception:
                    lookup_failed = True
                    continue
                if nested is not None:
                    candidates.append(nested)
        saw_hook = False
        hook_failed = False
        candidate: Any = None
        method: Any = None
        for candidate in candidates:
            for method_name in ("shutdown", "close"):
                try:
                    method = getattr(candidate, method_name, None)
                except Exception:
                    lookup_failed = True
                    continue
                if not callable(method):
                    continue
                saw_hook = True
                try:
                    method()
                except Exception:  # try the next version-specific hook
                    hook_failed = True
                    continue
                return
        # Do not retain a candidate, bound method, or third-party exception in
        # the traceback that crosses the private execution boundary.
        candidates.clear()
        candidate = None
        method = None
        llm_engine = None
        nested = None
        engine = None
        if hook_failed or lookup_failed:
            raise RuntimeError("vLLM engine shutdown failed") from None
        if not saw_hook:
            raise RuntimeError("vLLM engine exposes no supported shutdown hook") from None

    def close(self) -> None:
        """Synchronously release the admitted in-process vLLM engine.

        Detach first so repeated cleanup and error paths are idempotent. The
        shutdown itself stays inside the managed-model private-output boundary;
        neither loader locators nor third-party exception text can enter matrix
        diagnostics.
        """

        engine_holder = [self._llm]
        self._llm = None
        if engine_holder[0] is None:
            return

        def shutdown_and_release() -> None:
            shutdown_failed = False
            try:
                self._shutdown_engine(engine_holder[0])
            except Exception as exc:
                shutdown_failed = True
                # Tracebacks retain frame locals, including engine candidates.
                # Strip the complete exception graph before releasing the last
                # engine reference so its finalizer runs inside redaction.
                pending: list[BaseException] = [exc]
                seen: set[int] = set()
                while pending:
                    current = pending.pop()
                    if id(current) in seen:
                        continue
                    seen.add(id(current))
                    for linked in (current.__cause__, current.__context__):
                        if linked is not None:
                            pending.append(linked)
                    current.__traceback__ = None
                    current.__cause__ = None
                    current.__context__ = None
                pending.clear()
                seen.clear()
                current = None
                linked = None
            finally:
                # The engine object's destructor/finalizer is third-party code.
                # Drop its last lifecycle-owned reference and collect it while
                # stdout, stderr, logs, and errors are still path-redacted.
                engine_holder.clear()
                gc.collect()
                # Engine shutdown releases live tensors, but PyTorch's caching
                # allocator can otherwise retain the freed blocks in this
                # process. A readiness deadline is followed by a lower-cap
                # engine construction, so release that cache before returning.
                torch = sys.modules.get("torch")
                cuda = getattr(torch, "cuda", None) if torch is not None else None
                empty_cache = getattr(cuda, "empty_cache", None)
                if callable(empty_cache):
                    empty_cache()
            if shutdown_failed:
                raise RuntimeError("vLLM engine shutdown failed") from None

        if self._model_runtime is not None:
            self._model_runtime.private_execution(
                self._managed_model_role,
                shutdown_and_release,
            )
        else:
            from ..model_acquisition_runtime import private_model_execution

            private_model_execution(
                shutdown_and_release,
                role=self._managed_model_role,
                private_values=(Path(self._runtime_model).expanduser(),),
            )

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
            if not resolved.is_dir():
                raise ValueError(
                    "local vLLM checkpoint must be a sealed snapshot directory"
                )
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
        if self._llm is not None:
            self._verify_engine_core_execution_mode(self._llm)
            return self._llm

        from ..model_acquisition_runtime import (
            ensure_interpreter_scripts_on_path,
            hf_offline_environment_overrides,
            private_model_execution,
        )

        # vLLM/Transformers may cache Hub policy during import. Explicit local
        # exceptions are offline too; their tokenizer comes from the same seal.
        os.environ.update(hf_offline_environment_overrides())
        # The sampler JIT-builds a FlashInfer kernel on first use and shells out
        # to ninja, which ships beside this interpreter but is not on PATH when
        # the interpreter is invoked by absolute path.
        ensure_interpreter_scripts_on_path()
        if self.revision is not None and self._model_runtime is None:
            raise RuntimeError(
                "Hub vLLM engines require an admitted managed-model runtime; "
                "implicit Hugging Face downloads are disabled"
            )

        # vLLM 0.27 reads this setting both while importing its engine modules
        # and while LLMEngine selects its EngineCore client. Keep the override
        # active through construction, then restore the exact operator value.
        with _vllm_in_process_environment():
            try:
                from vllm import LLM  # type: ignore
            except ImportError as exc:  # pragma: no cover - offline path
                raise RuntimeError(
                    "vllm is required for VLLMTarget; pip install vllm"
                ) from exc
            context_kwargs: dict[str, Any] = {}
            if self.max_model_len is not None:
                context_kwargs["max_model_len"] = self.max_model_len
            common_kwargs: dict[str, Any] = {
                "tensor_parallel_size": self.tensor_parallel_size,
                "quantization": self.quantization,
                "dtype": self.dtype,
                "gpu_memory_utilization": self.gpu_memory_utilization,
                **context_kwargs,
                **self.engine_kwargs,
            }

            def cleanup(engine: Any) -> None:
                try:
                    self._shutdown_engine(engine)
                except Exception:
                    # A post-construction integrity failure is authoritative.
                    # ManagedModelRuntime also drops the rejected object and
                    # collects cycles after this best-effort shutdown.
                    pass

            def construct_checked(**kwargs: Any) -> Any:
                loaded_holder = [LLM(**kwargs)]
                try:
                    self._verify_engine_core_execution_mode(loaded_holder[0])
                except Exception:
                    try:
                        cleanup(loaded_holder[0])
                    finally:
                        loaded_holder.clear()
                        gc.collect()
                    raise RuntimeError(
                        "vLLM engine failed in-process execution-mode admission"
                    ) from None
                return loaded_holder.pop()

            if self.revision is None:
                # Explicit operator-local checkpoints are already sealed by
                # their tree digest and never consult Hugging Face. Re-hash on
                # both sides of construction: the earlier identity validation
                # is not a lease over an operator-mutable directory.
                checkpoint = Path(self._runtime_model).expanduser()
                if checkpoint.is_symlink():
                    raise ValueError("local vLLM checkpoint path must not be a symlink")
                resolved = checkpoint.resolve(strict=True)
                if _tree_sha256(resolved) != self.model_digest:
                    raise ValueError(
                        "local vLLM checkpoint digest changed before engine construction"
                    )
                loaded = private_model_execution(
                    lambda: construct_checked(
                        model=str(resolved),
                        tokenizer=str(resolved),
                        **common_kwargs,
                    ),
                    role=self._managed_model_role,
                    private_values=(resolved,),
                )
                try:
                    if (
                        checkpoint.is_symlink()
                        or checkpoint.resolve(strict=True) != resolved
                        or _tree_sha256(resolved) != self.model_digest
                    ):
                        raise ValueError(
                            "local vLLM checkpoint digest changed during engine "
                            "construction"
                        )
                except Exception:
                    loaded_holder = [loaded]
                    loaded = None

                    def discard() -> None:
                        try:
                            cleanup(loaded_holder[0])
                        finally:
                            loaded_holder.clear()
                            gc.collect()

                    private_model_execution(
                        discard,
                        role=self._managed_model_role,
                        private_values=(resolved,),
                    )
                    raise
                self._llm = loaded
            else:
                from ..model_acquisition import vllm_requirement
                from ..model_acquisition_runtime import (
                    vllm_managed_snapshot_kwargs,
                )

                requirement = vllm_requirement(
                    f"vllm:{self.model}",
                    self.revision,
                    role=self._managed_model_role,
                )

                def construct(snapshot: Path) -> Any:
                    return construct_checked(
                        **vllm_managed_snapshot_kwargs(snapshot),
                        **common_kwargs,
                    )

                self._llm = self._model_runtime.construct(
                    requirement,
                    construct,
                    cleanup=cleanup,
                )
        model_config = getattr(
            getattr(self._llm, "llm_engine", None), "model_config", None
        )
        resolved_max_model_len = getattr(model_config, "max_model_len", None)
        if (
            isinstance(resolved_max_model_len, bool)
            or not isinstance(resolved_max_model_len, int)
            or not 1 <= resolved_max_model_len <= MAX_VLLM_MODEL_LEN
        ):
            raise RuntimeError("vLLM did not expose its resolved context allocation")
        self._resolved_max_model_len = resolved_max_model_len
        return self._llm

    def preflight_base(self) -> None:
        """Load the engine before any separate Torch guard initializes CUDA."""

        self._engine()

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        # Engine admission establishes offline policy before any vLLM import.
        llm = self._engine()
        try:
            from vllm import SamplingParams  # type: ignore
        except ImportError as exc:  # pragma: no cover - offline path
            raise RuntimeError(
                "vllm is required for VLLMTarget; pip install vllm"
            ) from exc

        messages = _dialog_to_messages(
            dialog,
            multimodal="image" in self.modality_support,
            media_roots=self.media_roots,
        )
        messages, template_rendering = _vllm_chat_template_messages(messages, llm)
        sampling_kwargs: dict[str, Any] = dict(
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        if seed is not None:
            sampling_kwargs["seed"] = int(seed)
        sampling = SamplingParams(**sampling_kwargs)

        def chat_once() -> Any:
            try:
                return llm.chat(messages, sampling)  # type: ignore[attr-defined]
            except Exception as exc:
                context_failure = _vllm_context_limit_failure(exc)
                if context_failure is None:
                    raise
                return {"vllm_context_limit_failure": context_failure}

        t0 = time.perf_counter()
        with _vllm_generation_deadline(self.timeout):
            if self._model_runtime is not None:
                outputs = self._model_runtime.private_execution(
                    self._managed_model_role,
                    chat_once,
                )
            else:
                from ..model_acquisition_runtime import private_model_execution

                outputs = private_model_execution(
                    chat_once,
                    role=self._managed_model_role,
                    private_values=(Path(self._runtime_model).expanduser(),),
                )
        latency_ms = (time.perf_counter() - t0) * 1000.0

        if (
            isinstance(outputs, dict)
            and set(outputs) == {"vllm_context_limit_failure"}
            and isinstance(outputs["vllm_context_limit_failure"], tuple)
            and len(outputs["vllm_context_limit_failure"]) == 2
        ):
            length, limit = outputs["vllm_context_limit_failure"]
            raise LocalTargetInputError(
                f"vLLM prompt length {length} exceeds admitted context limit {limit}",
                category="context_limit_exceeded",
            )

        text, tokens, finish_reason, stop_reason = self._extract(outputs)
        empty_completion_observed = not bool(text.strip())
        from .api import _dialog_fingerprint

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=(
                []
                if empty_completion_observed
                else [DialogTurn(role="assistant", content=text)]
            ),
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "backend": "vllm",
                "model": self.model,
                "resolved_model": self.model,
                "model_revision": self.revision,
                "model_digest": self.model_digest,
                "quantization": self.quantization or "none",
                "engine_core_execution_mode": self.engine_core_execution_mode,
                "chat_template_rendering": template_rendering,
                "max_model_len_policy": (
                    "hardware_fit" if self.max_model_len == -1 else "explicit"
                ),
                "requested_max_model_len": self.max_model_len,
                "max_model_len": self._resolved_max_model_len,
                "finish_reason": finish_reason,
                "output_truncated": finish_reason == "length",
                "stop_reason": stop_reason,
                "empty_completion_observed": empty_completion_observed,
                "requested_seed": seed,
                "target_sampling_control": (
                    "local_seed" if seed is not None else "uncontrolled"
                ),
                "generation": {
                    "seed": seed,
                    "temperature": self.temperature,
                    "max_tokens": self.max_tokens,
                    "max_model_len": self._resolved_max_model_len,
                    "timeout_seconds": self.timeout,
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
            raise LocalTargetAnswerError(
                "vLLM must return exactly one RequestOutput for one chat request"
            )
        first = outputs[0]
        completions = getattr(first, "outputs", None)
        if not isinstance(completions, (list, tuple)) or len(completions) != 1:
            raise LocalTargetAnswerError("vLLM returned zero or multiple completions")
        completion = completions[0]
        text = getattr(completion, "text", None)
        if not isinstance(text, str):
            raise LocalTargetAnswerError("vLLM returned a non-text completion")
        finish_reason = getattr(completion, "finish_reason", None)
        if finish_reason not in {"stop", "length"}:
            raise LocalTargetAnswerError(
                f"vLLM completion ended with an unsupported reason: {finish_reason!r}"
            )
        stop_reason_raw = getattr(completion, "stop_reason", None)
        stop_reason = str(stop_reason_raw) if stop_reason_raw is not None else None
        prompt_ids = getattr(first, "prompt_token_ids", None)
        completion_ids = getattr(completion, "token_ids", None)
        if prompt_ids is None or completion_ids is None:
            raise LocalTargetAnswerError(
                "vLLM omitted prompt/completion token provenance"
            )
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
        host: str = DEFAULT_OLLAMA_URL,
        temperature: float = 0.0,
        num_ctx: int | Literal["fit", "max"] = DEFAULT_OLLAMA_NUM_CTX,
        context_ceiling: int | None = None,
        num_predict: int = DEFAULT_OLLAMA_NUM_PREDICT,
        think: bool | str = False,
        timeout: float = DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
        modality_support: tuple[str, ...] = ("text",),
        media_roots: Optional[Iterable[str | Path]] = None,
        **options: Any,
    ) -> None:
        if (
            not isinstance(model, str)
            or len(model.strip()) > 256
            or _OLLAMA_TAG.fullmatch(model.strip()) is None
        ):
            raise ValueError("OllamaTarget model must be a bounded exact tag")
        timeout = validate_local_request_timeout(timeout)
        self.model = model.strip()
        self.model_digest = (
            model_digest.lower() if isinstance(model_digest, str) else model_digest
        )
        identity = f"sha256:{self.model_digest}" if self.model_digest else "unresolved"
        self.name = f"ollama:{model}@{identity}"
        self.host = canonicalize_ollama_url(host)
        self.temperature = temperature
        self.num_ctx = validate_ollama_num_ctx(num_ctx)
        self.context_ceiling = (
            validate_ollama_context_ceiling(context_ceiling)
            if context_ceiling is not None else None
        )
        if self.context_ceiling is not None and self.num_ctx != "fit":
            raise ValueError("context_ceiling requires num_ctx='fit'")
        self._resolved_num_ctx: int | None = None
        self._hardware_fit_attempts: list[dict[str, int | bool]] = []
        self.num_predict = validate_ollama_num_predict(num_predict)
        self.think = validate_ollama_think(think)
        self.timeout = timeout
        self._monotonic: Callable[[], float] = time.monotonic
        self._sleep: Callable[[float], None] = time.sleep
        self._residency_owned = False
        self._transaction_lock = threading.Lock()
        self._lifetime_lease: OllamaProcessLock | None = None
        self._open_request = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
        ).open
        self.modality_support = tuple(modality_support)
        if "image" in self.modality_support:
            self.image_transport = "webp_to_lossless_png"
        self.modality_combinations = tuple(
            [("text",)]
            + ([("text", "image")] if "image" in self.modality_support else [])
        )
        from .api import _media_roots

        self.media_roots = _media_roots(media_roots)
        forbidden_options = sorted(
            set(options) & _OLLAMA_RESERVED_CONSTRUCTOR_OPTIONS
        )
        if forbidden_options:
            raise ValueError(
                "OllamaTarget does not accept reserved/vLLM-only option(s): "
                + ", ".join(forbidden_options)
            )
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

    def _acquire_transaction_lock(self, *, deadline: float) -> None:
        remaining = remaining_seconds(
            deadline,
            self._monotonic,
            label="Ollama in-process transaction lock acquisition",
        )
        if not self._transaction_lock.acquire(timeout=remaining):
            raise TimeoutError(
                "Ollama in-process transaction lock acquisition exceeded its "
                "hard wall-clock deadline"
            )

    def _acquire_lifetime_leases(self, *, deadline: float) -> None:
        """Exclude another inference owner and every endpoint mutation.

        The inference namespace is also the admission gate automatically taken
        by every exclusive endpoint mutation. Status and roster readers use
        only the endpoint namespace, so they remain available during a run.
        """

        if self._lifetime_lease is not None:
            return
        lifetime_lease = OllamaProcessLock(
            base_url=self.host,
            exclusive=True,
            deadline=deadline,
            namespace="inference",
            monotonic=self._monotonic,
            sleep=self._sleep,
        )
        lifetime_lease.__enter__()
        self._lifetime_lease = lifetime_lease

    def _release_lifetime_leases(self) -> None:
        lifetime_lease = self._lifetime_lease
        self._lifetime_lease = None
        if lifetime_lease is not None:
            lifetime_lease.__exit__(None, None, None)

    @staticmethod
    def _normalized_digest(value: object) -> Optional[str]:
        if not isinstance(value, str):
            return None
        normalized = value.lower().removeprefix("sha256:")
        return normalized if _SHA256.fullmatch(normalized) else None

    def _verified_inventory_digest(
        self,
        inventory: object,
        *,
        model: str,
        purpose: str,
    ) -> str:
        """Require one exact, internally consistent model/digest inventory row."""

        if not isinstance(inventory, dict):
            raise LocalTargetOutputError(f"Ollama returned an invalid {purpose}")
        rows = inventory.get("models")
        if not isinstance(rows, list) or len(rows) > _MAX_OLLAMA_MODELS:
            raise LocalTargetOutputError(f"Ollama returned an invalid {purpose}")
        matches: list[str] = []
        for index, item in enumerate(rows):
            if not isinstance(item, dict):
                raise LocalTargetOutputError(
                    f"Ollama {purpose} row {index} is not an object"
                )
            name = item.get("name")
            row_model = item.get("model")
            if (
                not isinstance(name, str)
                or not isinstance(row_model, str)
                or len(name) > 256
                or len(row_model) > 256
                or _OLLAMA_TAG.fullmatch(name) is None
                or _OLLAMA_TAG.fullmatch(row_model) is None
                or name != row_model
            ):
                raise LocalTargetOutputError(
                    f"Ollama {purpose} row {index} has ambiguous model identity"
                )
            digest = self._normalized_digest(item.get("digest"))
            if digest is None:
                raise LocalTargetOutputError(
                    f"Ollama {purpose} row {index} has an invalid digest"
                )
            if name == model:
                matches.append(digest)
        if len(matches) != 1:
            raise LocalTargetOutputError(
                f"Ollama {purpose} did not resolve exactly one {model!r} model"
            )
        if matches[0] != self.model_digest:
            raise LocalTargetOutputError(
                f"Ollama {purpose} digest does not match declared model_digest"
            )
        return matches[0]

    def _verify_daemon_identity(self, *, deadline: float | None = None) -> str:
        self.validate_research_identity()
        deadline = deadline or (self._monotonic() + self.timeout)
        request = urllib.request.Request(f"{self.host}/api/tags", method="GET")
        inventory = self._bounded_json_request(
            request,
            purpose="model inventory",
            deadline=deadline,
        )
        return self._verified_inventory_digest(
            inventory,
            model=self.model,
            purpose="model inventory",
        )

    def _resolve_num_ctx(self, *, deadline: float) -> int:
        """Resolve an explicit or native-maximum request context."""

        if self._resolved_num_ctx is not None:
            return self._resolved_num_ctx
        if isinstance(self.num_ctx, int):
            self._resolved_num_ctx = self.num_ctx
            return self._resolved_num_ctx
        if self.num_ctx == "fit":
            raise LocalTargetOutputError(
                "Ollama hardware-fit context requires the measured residency lifecycle"
            )
        payload = json.dumps({"model": self.model}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/show",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        document = self._bounded_json_request(
            request,
            purpose="model context metadata",
            deadline=deadline,
        )
        model_info = (
            document.get("model_info") if isinstance(document, dict) else None
        )
        if not isinstance(model_info, dict) or len(model_info) > 4096:
            raise LocalTargetOutputError(
                "Ollama /api/show lacks bounded model_info for native context"
            )
        architecture = model_info.get("general.architecture")
        if (
            not isinstance(architecture, str)
            or not architecture
            or len(architecture) > 128
            or re.fullmatch(r"[A-Za-z0-9_.-]+", architecture) is None
        ):
            raise LocalTargetOutputError(
                "Ollama /api/show lacks a valid general.architecture"
            )
        key = f"{architecture}.context_length"
        value = model_info.get(key)
        try:
            resolved = validate_ollama_num_ctx(value)
        except ValueError as exc:
            raise LocalTargetOutputError(
                f"Ollama /api/show lacks a valid {key} native context length"
            ) from exc
        if not isinstance(resolved, int):
            raise LocalTargetOutputError(
                f"Ollama /api/show lacks a finite {key} native context length"
            )
        self._resolved_num_ctx = resolved
        return resolved

    def _loaded_runtime_profile(self, *, deadline: float) -> dict[str, int]:
        """Return bounded loaded-runtime bytes and context for the selected model."""

        inventory = self._loaded_inventory(deadline=deadline)
        rows = inventory.get("models") if isinstance(inventory, dict) else None
        if not isinstance(rows, list) or len(rows) != 1:
            raise LocalTargetOutputError(
                "Ollama hardware-fit probe did not resolve one loaded model"
            )
        self._verified_inventory_digest(
            inventory,
            model=self.model,
            purpose="hardware-fit loaded-model inventory",
        )
        row = rows[0]
        profile: dict[str, int] = {}
        for field in ("size", "size_vram", "context_length"):
            value = row.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value <= 0
                or value > 2**63 - 1
            ):
                raise LocalTargetOutputError(
                    f"Ollama hardware-fit inventory has invalid {field}"
                )
            profile[field] = value
        return profile

    def _preload_context_candidate(
        self, candidate: int, *, deadline: float
    ) -> dict[str, int]:
        """Load one context allocation without generating a model answer."""

        payload = json.dumps(
            {
                "keep_alive": -1,
                "model": self.model,
                "options": {"num_ctx": candidate},
                "stream": False,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        self._residency_owned = True
        try:
            value = self._bounded_json_request(
                request,
                purpose="hardware-fit preload",
                deadline=deadline,
            )
            if (
                not isinstance(value, dict)
                or value.get("done") is not True
                or value.get("error")
            ):
                raise LocalTargetOutputError(
                    "Ollama hardware-fit preload did not complete cleanly"
                )
            resolved_model = value.get("model")
            if resolved_model is not None and resolved_model != self.model:
                raise TargetIntegrityError(
                    "Ollama hardware-fit preload returned an unexpected model"
                )
            profile = self._loaded_runtime_profile(deadline=deadline)
            if profile["context_length"] != candidate:
                raise LocalTargetOutputError(
                    "Ollama hardware-fit preload changed the requested context"
                )
            return profile
        except Exception:
            cleanup_deadline = self._monotonic() + self.timeout
            try:
                self._release_owned_residency(deadline=cleanup_deadline)
            except Exception as cleanup:
                raise cleanup
            raise

    def _resolve_hardware_fit_context(self, *, deadline: float) -> int:
        """Choose the largest tested native fraction that is fully GPU resident."""

        original_policy = self.num_ctx
        self.num_ctx = "max"
        try:
            candidate = self._resolve_num_ctx(deadline=deadline)
        finally:
            self.num_ctx = original_policy
            self._resolved_num_ctx = None
        if self.context_ceiling is not None:
            candidate = min(candidate, self.context_ceiling)
        minimum = min(candidate, MIN_OLLAMA_HARDWARE_FIT_CONTEXT)
        while candidate >= minimum:
            profile = self._preload_context_candidate(candidate, deadline=deadline)
            fully_gpu_resident = profile["size_vram"] >= profile["size"]
            self._hardware_fit_attempts.append(
                {
                    "context_length": candidate,
                    "size": profile["size"],
                    "size_vram": profile["size_vram"],
                    "fully_gpu_resident": fully_gpu_resident,
                }
            )
            if fully_gpu_resident:
                self._resolved_num_ctx = candidate
                return candidate
            self._release_owned_residency(deadline=deadline)
            if candidate == minimum:
                break
            candidate = max(
                minimum,
                (candidate // 2 // 1024) * 1024,
            )
        raise LocalTargetOutputError(
            "Ollama model cannot remain fully GPU resident at the minimum "
            f"{minimum}-token context"
        )

    def _ensure_hardware_fit_context(
        self, *, residency_prestate: str, deadline: float
    ) -> int:
        """Prove a GPU-only allocation before each new residency cycle."""

        if residency_prestate == "selected":
            if self._resolved_num_ctx is None:
                raise LocalTargetOutputError(
                    "Ollama hardware-fit residency lacks a resolved context"
                )
            profile = self._loaded_runtime_profile(deadline=deadline)
            if (
                profile["context_length"] != self._resolved_num_ctx
                or profile["size_vram"] < profile["size"]
            ):
                raise LocalTargetOutputError(
                    "Ollama hardware-fit residency changed before generation"
                )
            return self._resolved_num_ctx
        if residency_prestate != "empty":
            raise LocalTargetOutputError(
                "Ollama hardware-fit assessment requires empty or selected residency"
            )

        if self._resolved_num_ctx is not None:
            cached = self._resolved_num_ctx
            self._hardware_fit_attempts = []
            profile = self._preload_context_candidate(cached, deadline=deadline)
            fully_gpu_resident = profile["size_vram"] >= profile["size"]
            self._hardware_fit_attempts.append(
                {
                    "context_length": cached,
                    "size": profile["size"],
                    "size_vram": profile["size_vram"],
                    "fully_gpu_resident": fully_gpu_resident,
                }
            )
            if fully_gpu_resident:
                return cached
            self._release_owned_residency(deadline=deadline)
            self._resolved_num_ctx = None

        self._hardware_fit_attempts = []
        return self._resolve_hardware_fit_context(deadline=deadline)

    def _loaded_inventory(self, *, deadline: float) -> object:
        request = urllib.request.Request(f"{self.host}/api/ps", method="GET")
        return self._bounded_json_request(
            request,
            purpose="loaded-model inventory",
            deadline=deadline,
        )

    def _verify_empty_loaded_inventory(self, *, deadline: float) -> None:
        inventory = self._loaded_inventory(deadline=deadline)
        if not isinstance(inventory, dict):
            raise LocalTargetOutputError(
                "Ollama returned an invalid loaded-model inventory"
            )
        rows = inventory.get("models")
        if not isinstance(rows, list) or len(rows) > _MAX_OLLAMA_MODELS:
            raise LocalTargetOutputError(
                "Ollama returned an invalid loaded-model inventory"
            )
        if rows:
            raise LocalTargetOutputError(
                "Ollama measured generation requires an empty loaded-model inventory"
            )

    def _wait_for_empty_loaded_inventory(self, *, deadline: float) -> None:
        """Wait for an acknowledged asynchronous unload to leave no residency."""

        while True:
            inventory = self._loaded_inventory(deadline=deadline)
            rows = inventory.get("models") if isinstance(inventory, dict) else None
            if not isinstance(rows, list) or len(rows) > _MAX_OLLAMA_MODELS:
                raise LocalTargetOutputError(
                    "Ollama returned an invalid loaded-model inventory"
                )
            if not rows:
                return
            if len(rows) != 1:
                raise LocalTargetOutputError(
                    "Ollama unload observed an unexpected co-resident model"
                )
            self._verified_inventory_digest(
                inventory,
                model=self.model,
                purpose="loaded-model inventory during unload",
            )
            remaining = remaining_seconds(
                deadline,
                self._monotonic,
                label="Ollama model residency cleanup",
            )
            self._sleep(min(0.05, remaining))

    def _verify_pre_generation_residency(self, *, deadline: float) -> str:
        inventory = self._loaded_inventory(deadline=deadline)
        if not isinstance(inventory, dict):
            raise LocalTargetOutputError(
                "Ollama returned an invalid loaded-model inventory"
            )
        rows = inventory.get("models")
        if not isinstance(rows, list) or len(rows) > _MAX_OLLAMA_MODELS:
            raise LocalTargetOutputError(
                "Ollama returned an invalid loaded-model inventory"
            )
        if not rows:
            return "empty"
        if len(rows) != 1:
            raise LocalTargetOutputError(
                "Ollama measured generation requires empty residency or exactly "
                "the selected model"
            )
        self._verified_inventory_digest(
            inventory,
            model=self.model,
            purpose="loaded-model inventory",
        )
        if not self._residency_owned:
            raise LocalTargetOutputError(
                "Ollama selected model was preloaded outside this target lifecycle"
            )
        return "selected"

    def _verify_loaded_identity(self, model: str, *, deadline: float) -> str:
        inventory = self._loaded_inventory(deadline=deadline)
        rows = inventory.get("models") if isinstance(inventory, dict) else None
        if not isinstance(rows, list) or len(rows) != 1:
            raise LocalTargetOutputError(
                "Ollama loaded-model inventory did not resolve exactly one "
                "exclusively loaded model"
            )
        return self._verified_inventory_digest(
            inventory,
            model=model,
            purpose="loaded-model inventory",
        )

    def _unload_model(self, *, deadline: float) -> str:
        payload = json.dumps(
            {
                "keep_alive": 0,
                "model": self.model,
                "stream": False,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        value = self._bounded_json_request(
            request,
            purpose="model unload response",
            deadline=deadline,
        )
        if not isinstance(value, dict) or value.get("done") is not True:
            raise LocalTargetOutputError(
                "Ollama model unload did not declare done=true"
            )
        if value.get("error"):
            raise LocalTargetOutputError(
                f"Ollama model unload returned an error: {value['error']}"
            )
        resolved_model = value.get("model")
        if resolved_model is not None and resolved_model != self.model:
            raise LocalTargetOutputError(
                f"Ollama model unload returned unexpected identity {resolved_model!r}"
            )
        done_reason = value.get("done_reason")
        if done_reason != "unload":
            raise LocalTargetOutputError(
                "Ollama model unload did not declare done_reason='unload'"
            )
        return done_reason

    def _verify_owned_residency_before_unload(self, *, deadline: float) -> str:
        """Return empty/selected without mutating drifted or foreign state."""

        self._verify_daemon_identity(deadline=deadline)
        inventory = self._loaded_inventory(deadline=deadline)
        if not isinstance(inventory, dict):
            raise LocalTargetOutputError(
                "Ollama returned an invalid loaded-model inventory before unload"
            )
        rows = inventory.get("models")
        if not isinstance(rows, list) or len(rows) > _MAX_OLLAMA_MODELS:
            raise LocalTargetOutputError(
                "Ollama returned an invalid loaded-model inventory before unload"
            )
        if not rows:
            return "empty"
        if len(rows) != 1:
            raise LocalTargetOutputError(
                "Ollama cleanup refused unexpected co-resident models before unload"
            )
        self._verified_inventory_digest(
            inventory,
            model=self.model,
            purpose="loaded-model inventory before unload",
        )
        return "selected"

    def _release_owned_residency(self, *, deadline: float) -> str:
        prestate = self._verify_owned_residency_before_unload(deadline=deadline)
        if prestate == "empty":
            self._residency_owned = False
            return "already-empty"
        done_reason = self._unload_model(deadline=deadline)
        self._wait_for_empty_loaded_inventory(deadline=deadline)
        self._residency_owned = False
        return done_reason

    def prepare_isolated_probe(self) -> str:
        """Clear only verified stale self-residency between readiness children."""

        deadline = self._monotonic() + self.timeout
        acquired = False
        try:
            self._acquire_transaction_lock(deadline=deadline)
            acquired = True
            self._acquire_lifetime_leases(deadline=deadline)
            self._verify_daemon_identity(deadline=deadline)
            inventory = self._loaded_inventory(deadline=deadline)
            rows = inventory.get("models") if isinstance(inventory, dict) else None
            if not isinstance(rows, list) or len(rows) > _MAX_OLLAMA_MODELS:
                raise LocalTargetOutputError(
                    "Ollama returned an invalid loaded-model inventory before "
                    "isolated readiness probe"
                )
            if not rows:
                return "already-empty"
            if len(rows) != 1:
                raise LocalTargetOutputError(
                    "isolated readiness cleanup refuses co-resident models"
                )
            self._verified_inventory_digest(
                inventory,
                model=self.model,
                purpose="loaded-model inventory before isolated readiness probe",
            )
            done_reason = self._unload_model(deadline=deadline)
            self._wait_for_empty_loaded_inventory(deadline=deadline)
            return done_reason
        except TimeoutError as exc:
            raise LocalTargetOutputError(str(exc)) from exc
        finally:
            self._release_lifetime_leases()
            if acquired:
                self._transaction_lock.release()

    def close(self) -> None:
        """Release model residency retained for this Runner process.

        Runner tracks every constructed target and invokes ``close`` in its
        unconditional process teardown. Keeping the selected model resident
        between calls avoids reloading it for every corpus row. The lifetime
        inference/mutation gate admits read-only status while preventing
        another target or daemon mutation until verified cleanup.
        """

        deadline = self._monotonic() + self.timeout
        acquired = False
        try:
            self._acquire_transaction_lock(deadline=deadline)
            acquired = True
            if self._residency_owned:
                if self._lifetime_lease is None:
                    raise RuntimeError(
                        "Ollama residency ownership lacks its lifetime lease"
                    )
                self._release_owned_residency(deadline=deadline)
        except TimeoutError as exc:
            raise LocalTargetOutputError(str(exc)) from exc
        finally:
            try:
                if not self._residency_owned:
                    self._release_lifetime_leases()
            finally:
                if acquired:
                    self._transaction_lock.release()

    def _sampling_options(self, seed: int | None = None) -> dict[str, Any]:
        opts: dict[str, Any] = {
            "temperature": self.temperature,
            "num_predict": self.num_predict,
        }
        if isinstance(self.num_ctx, int):
            opts["num_ctx"] = self.num_ctx
        elif self._resolved_num_ctx is not None:
            opts["num_ctx"] = self._resolved_num_ctx
        opts.update(self.options)
        if seed is not None:
            opts["seed"] = int(seed)
        return opts

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        self.validate_research_identity()
        deadline = self._monotonic() + self.timeout
        acquired = False
        try:
            self._acquire_transaction_lock(deadline=deadline)
            acquired = True
            self._acquire_lifetime_leases(deadline=deadline)
            pre_digest = self._verify_daemon_identity(deadline=deadline)
            residency_prestate = self._verify_pre_generation_residency(
                deadline=deadline
            )
            if self.num_ctx == "fit":
                resolved_num_ctx = self._ensure_hardware_fit_context(
                    residency_prestate=residency_prestate,
                    deadline=deadline,
                )
            else:
                resolved_num_ctx = self._resolve_num_ctx(deadline=deadline)
            image_transport: list[dict[str, Any]] = []
            messages = _dialog_to_ollama_messages(
                dialog,
                multimodal="image" in self.modality_support,
                media_roots=self.media_roots,
                image_transport=image_transport,
            )
            # Once the chat is submitted the daemon may own residency even
            # if the response later fails validation. Mark it before the
            # request so Runner's outer teardown can retry a failed cleanup.
            self._residency_owned = True
            try:
                t0 = time.perf_counter()
                data = self._chat(messages, seed=seed, deadline=deadline)
                latency_ms = (time.perf_counter() - t0) * 1000.0

                if not isinstance(data, dict):
                    raise LocalTargetAnswerError(
                        "Ollama response is not an object"
                    )
                if data.get("error"):
                    raise LocalTargetAnswerError(
                        f"Ollama returned an error: {data['error']}"
                    )
                if data.get("done") is not True:
                    raise LocalTargetAnswerError(
                        "Ollama response did not declare done=true"
                    )
                done_reason = data.get("done_reason")
                if done_reason not in {"stop", "length"}:
                    raise LocalTargetAnswerError(
                        "Ollama response ended with an unsupported reason: "
                        f"{done_reason!r}"
                    )
                resolved_model = data.get("model")
                if (
                    not isinstance(resolved_model, str)
                    or resolved_model != self.model
                ):
                    raise TargetIntegrityError(
                        "Ollama returned unexpected model identity "
                        f"{resolved_model!r}"
                    )
                message = data.get("message")
                if not isinstance(message, dict):
                    raise LocalTargetAnswerError(
                        "Ollama response omitted its message object"
                    )
                if message.get("role", "assistant") != "assistant":
                    raise LocalTargetAnswerError(
                        "Ollama returned a non-assistant message"
                    )
                text = message.get("content")
                if not isinstance(text, str):
                    raise LocalTargetAnswerError(
                        "Ollama returned a non-text completion"
                    )
                thinking = message.get("thinking", "")
                if not isinstance(thinking, str):
                    raise LocalTargetAnswerError(
                        "Ollama returned a non-text thinking field"
                    )
                thinking_observed = bool(thinking.strip())
                if self.think is False and thinking_observed:
                    raise LocalTargetAnswerError(
                        "Ollama returned thinking output when think=false",
                        category="thinking_control_mismatch",
                    )
                empty_completion_observed = not bool(text.strip())
                tokens = self._token_counts(data)
                post_digest = self._verify_daemon_identity(deadline=deadline)
                loaded_digest = self._verify_loaded_identity(
                    resolved_model,
                    deadline=deadline,
                )
                loaded_runtime_profile: dict[str, int] = {}
                if self.num_ctx == "fit":
                    loaded_runtime_profile = self._loaded_runtime_profile(
                        deadline=deadline
                    )
                    if (
                        loaded_runtime_profile["context_length"] != resolved_num_ctx
                        or loaded_runtime_profile["size_vram"]
                        < loaded_runtime_profile["size"]
                    ):
                        raise LocalTargetOutputError(
                            "Ollama hardware-fit residency changed during generation"
                        )
            except Exception as primary:
                cleanup_deadline = self._monotonic() + self.timeout
                try:
                    self._release_owned_residency(deadline=cleanup_deadline)
                except Exception as cleanup:
                    if hasattr(cleanup, "add_note"):
                        cleanup.add_note(
                            "cleanup followed an Ollama generation failure: "
                            f"{type(primary).__name__}"
                        )
                    raise cleanup from primary
                raise
        except TimeoutError as exc:
            raise LocalTargetOutputError(str(exc)) from exc
        finally:
            try:
                if not self._residency_owned:
                    self._release_lifetime_leases()
            finally:
                if acquired:
                    self._transaction_lock.release()
        from .api import _dialog_fingerprint

        return Response(
            attempt_id=_dialog_fingerprint(dialog),
            target=self.name,
            output_turns=(
                []
                if empty_completion_observed
                else [DialogTurn(role="assistant", content=text)]
            ),
            latency_ms=latency_ms,
            tokens=tokens,
            raw={
                "backend": "ollama",
                "model": self.model,
                "resolved_model": resolved_model,
                "model_digest": self.model_digest,
                "verified_model_digest": pre_digest,
                "post_verified_model_digest": post_digest,
                "loaded_verified_model_digest": loaded_digest,
                "model_identity_verified": True,
                "model_identity_transaction": "pre-tags/chat/post-tags/post-ps",
                "model_residency_transaction": (
                    f"{residency_prestate}-pre/exact-selected-post/"
                    "process-cleanup-registered"
                ),
                "done": True,
                "done_reason": done_reason,
                "output_truncated": done_reason == "length",
                "empty_completion_observed": empty_completion_observed,
                "requested_seed": seed,
                "target_sampling_control": (
                    "local_seed" if seed is not None else "uncontrolled"
                ),
                "generation": {
                    "seed": seed,
                    "temperature": self.temperature,
                    "num_ctx_policy": self.num_ctx,
                    **({"context_ceiling": self.context_ceiling}
                       if self.context_ceiling is not None else {}),
                    "num_ctx": resolved_num_ctx,
                    "num_predict": self.num_predict,
                    "think": self.think,
                    "timeout_seconds": self.timeout,
                },
                "hardware_fit_attempts": list(self._hardware_fit_attempts),
                "loaded_runtime": loaded_runtime_profile,
                "thinking_output_observed": thinking_observed,
                **({"image_transport": {"policy": self.image_transport, "transforms": image_transport}}
                   if "image" in self.modality_support else {}),
            },
        )

    def _chat(
        self,
        messages: list[dict[str, Any]],
        *,
        seed: int | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        """Send a timeout- and byte-bounded chat request."""
        return self._chat_http(messages, seed=seed, deadline=deadline)

    def _chat_http(
        self,
        messages: list[dict[str, Any]],
        *,
        seed: int | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        """Dependency-free fallback against Ollama's REST API."""
        deadline = deadline or (self._monotonic() + self.timeout)
        if self.num_ctx == "max" and self._resolved_num_ctx is None:
            self._resolve_num_ctx(deadline=deadline)
        if self.num_ctx == "fit" and self._resolved_num_ctx is None:
            raise LocalTargetOutputError(
                "Ollama hardware-fit chat requires a completed residency assessment"
            )
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "options": self._sampling_options(seed),
                "think": self.think,
                "stream": False,
            }
        ).encode("utf-8")
        if len(payload) > _MAX_OLLAMA_REQUEST_BYTES:
            raise ValueError("Ollama chat request exceeds the 32 MiB limit")
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            value = self._bounded_json_request(
                req,
                purpose="chat response",
                deadline=deadline,
            )
        except (LocalTargetOutputError, RuntimeError) as exc:
            raise LocalTargetAnswerError(
                str(exc), category="transport_failure"
            ) from exc
        if not isinstance(value, dict):
            raise LocalTargetAnswerError(
                "Ollama HTTP response is not a JSON object"
            )
        return value

    def _bounded_json_request(
        self,
        request: urllib.request.Request,
        *,
        purpose: str,
        deadline: float,
    ) -> Any:
        """Read strict JSON through the fixed opener under one hard deadline."""

        try:
            timeout = min(
                self.timeout,
                remaining_seconds(
                    deadline,
                    self._monotonic,
                    label=f"Ollama {purpose}",
                ),
            )
            response = open_with_deadline(
                self._open_request,
                request,
                deadline=deadline,
                monotonic=self._monotonic,
                maximum_timeout=timeout,
                label=f"Ollama {purpose}",
            )
            with response:
                body = read_bounded_response(
                    response,
                    maximum=_MAX_OLLAMA_RESPONSE_BYTES,
                    deadline=deadline,
                    monotonic=self._monotonic,
                    label=f"Ollama {purpose}",
                )
        except LocalTargetOutputError:
            raise
        except urllib.error.HTTPError as exc:
            # An immediate daemon rejection is not evidence that generation ran
            # until its deadline. Keep the status and a bounded native reason.
            detail = ""
            try:
                with exc:
                    body = read_bounded_response(
                        exc, maximum=4096, deadline=deadline,
                        monotonic=self._monotonic, label=f"Ollama {purpose} error",
                    )
                document = _strict_bounded_json_bytes(body)
                if isinstance(document, dict) and isinstance(document.get("error"), str):
                    detail = ": " + " ".join(document["error"].split())[:512]
            except (OSError, ValueError, RecursionError):
                pass  # The HTTP status remains known even without a readable body.
            raise RuntimeError(
                f"Ollama {purpose} returned HTTP {exc.code}{detail}"
            ) from exc
        except ValueError as exc:
            if "byte limit" in str(exc):
                raise LocalTargetOutputError(
                    f"Ollama {purpose} exceeds the 4 MiB limit"
                ) from exc
            raise LocalTargetOutputError(str(exc)) from exc
        except (TimeoutError, urllib.error.URLError, OSError) as exc:
            cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if not isinstance(cause, TimeoutError):
                errno = getattr(cause, "errno", None)
                detail = f" (errno {errno})" if isinstance(errno, int) else ""
                raise RuntimeError(
                    f"could not obtain Ollama {purpose} from {self.host}: "
                    f"{type(cause).__name__}{detail}"
                ) from exc
            raise RuntimeError(
                f"could not obtain Ollama {purpose} from {self.host} within "
                f"the configured hard {self.timeout:g}s deadline"
            ) from exc
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
            raise LocalTargetAnswerError(
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
    "DEFAULT_OLLAMA_NUM_CTX",
    "DEFAULT_OLLAMA_NUM_PREDICT",
    "DEFAULT_LOCAL_GENERATION_TOKENS",
    "DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS",
    "DEFAULT_VLLM_GENERATION_TOKENS",
    "DEFAULT_VLLM_MAX_MODEL_LEN",
    "MAX_OLLAMA_NUM_CTX",
    "MAX_OLLAMA_NUM_PREDICT",
    "MAX_VLLM_GENERATION_TOKENS",
    "MAX_VLLM_MODEL_LEN",
    "MIN_OLLAMA_HARDWARE_FIT_CONTEXT",
    "OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS",
    "VLLM_FORBIDDEN_LOCAL_CONFIG_FIELDS",
    "VLLMTarget",
    "OllamaTarget",
    "canonical_local_model_identity",
    "make_vllm_target",
    "make_ollama_target",
    "validate_ollama_num_ctx",
    "validate_ollama_num_predict",
    "validate_ollama_think",
    "validate_vllm_max_model_len",
    "validate_vllm_max_tokens",
]
