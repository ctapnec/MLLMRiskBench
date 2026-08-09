"""Local open-weight targets: vLLM and Ollama backends (thesis III.2.2).

These wrap self-hosted inference so open-weight models can be evaluated on the
same footing as hosted APIs. Heavy dependencies (``vllm``, ``ollama``) are
imported lazily inside the call path, so this module imports cleanly on a box
with only pydantic + the stdlib. The Ollama target additionally ships a
dependency-free HTTP fallback against ``localhost:11434`` using ``urllib``.

Factories are registered in the shared ``REGISTRY`` under ``"vllm"`` and
``"ollama"`` so the orchestrator can address either backend by id.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from ..data_models import DialogTurn, Response
from .base import REGISTRY, BaseTarget

_ROLE_MAP = {
    "system": "system",
    "user": "user",
    "assistant": "assistant",
    "tool": "tool",
    "env": "user",  # environment observations surface as user-side context
}


def _dialog_to_messages(
    dialog: list[DialogTurn], *, multimodal: bool = False
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

        images = [m for m in turn.media if m.modality == "image"] if multimodal else []
        if not images:
            messages.append({"role": role, "content": text})
            continue

        # lazy import keeps this module stdlib-only until an image is actually sent
        from .api import _encode_media

        content: list[dict[str, Any]] = []
        if text:
            content.append({"type": "text", "text": text})
        for media in images:
            mime, data, url = _encode_media(media)
            image_url = url or f"data:{mime};base64,{data}"
            content.append({"type": "image_url", "image_url": {"url": image_url}})
        messages.append({"role": role, "content": content})
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
        tensor_parallel_size: int = 2,
        quantization: Optional[str] = None,
        max_tokens: int = 512,
        temperature: float = 0.0,
        dtype: str = "auto",
        gpu_memory_utilization: float = 0.90,
        modality_support: tuple[str, ...] = ("text",),
        **engine_kwargs: Any,
    ) -> None:
        self.model = model
        self.name = model  # per-model id so each vLLM model writes its own result cell
        # A vision-language model (e.g. Qwen3-VL) declares ("text", "image") so image
        # datapoints are forwarded; a text-only local model stays ("text",) and image
        # corpora are run text-only (documented; excluded from m-ASR in the protocol).
        self.modality_support = tuple(modality_support)
        self.tensor_parallel_size = tensor_parallel_size
        self.quantization = quantization
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.dtype = dtype
        self.gpu_memory_utilization = gpu_memory_utilization
        self.engine_kwargs = engine_kwargs
        self._llm: Any = None

    def _engine(self) -> Any:
        """Lazily build and cache the vLLM engine."""
        if self._llm is None:
            try:
                from vllm import LLM  # type: ignore
            except ImportError as exc:  # pragma: no cover - offline path
                raise RuntimeError(
                    "vllm is required for VLLMTarget; pip install vllm"
                ) from exc
            self._llm = LLM(
                model=self.model,
                tensor_parallel_size=self.tensor_parallel_size,
                quantization=self.quantization,
                dtype=self.dtype,
                gpu_memory_utilization=self.gpu_memory_utilization,
                **self.engine_kwargs,
            )
        return self._llm

    def generate(self, dialog: list[DialogTurn]) -> Response:
        try:
            from vllm import SamplingParams  # type: ignore
        except ImportError as exc:  # pragma: no cover - offline path
            raise RuntimeError(
                "vllm is required for VLLMTarget; pip install vllm"
            ) from exc

        llm = self._engine()
        messages = _dialog_to_messages(
            dialog, multimodal="image" in self.modality_support
        )
        sampling = SamplingParams(
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        t0 = time.perf_counter()
        outputs = llm.chat(messages, sampling)  # type: ignore[attr-defined]
        latency_ms = (time.perf_counter() - t0) * 1000.0

        text, tokens = self._extract(outputs)
        return Response(
            attempt_id="",
            target=self.model,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={"backend": "vllm", "model": self.model},
        )

    @staticmethod
    def _extract(outputs: Any) -> tuple[str, Optional[dict[str, int]]]:
        """Pull generated text + token counts from a vLLM ``RequestOutput``.

        Isolated so the online API surface is easy to adjust in one place.
        """
        if not outputs:
            return "", None
        first = outputs[0]
        completion = first.outputs[0]
        text = getattr(completion, "text", "") or ""
        tokens: Optional[dict[str, int]] = None
        prompt_ids = getattr(first, "prompt_token_ids", None)
        completion_ids = getattr(completion, "token_ids", None)
        if prompt_ids is not None or completion_ids is not None:
            prompt_n = len(prompt_ids) if prompt_ids is not None else 0
            completion_n = len(completion_ids) if completion_ids is not None else 0
            tokens = {
                "prompt": prompt_n,
                "completion": completion_n,
                "total": prompt_n + completion_n,
            }
        return text, tokens


class OllamaTarget(BaseTarget):
    """A model served by a local Ollama daemon (thesis III.2.2).

    Uses the ``ollama`` Python client when installed; otherwise falls back to a
    dependency-free HTTP call against the daemon's ``/api/chat`` endpoint via
    ``urllib``, so the common case works with only the stdlib.
    """

    name = "ollama"
    modality_support: tuple[str, ...] = ("text",)

    def __init__(
        self,
        model: str,
        *,
        host: str = "http://localhost:11434",
        temperature: float = 0.0,
        num_predict: int = 512,
        timeout: float = 300.0,
        **options: Any,
    ) -> None:
        self.model = model
        self.name = model  # per-model id so each Ollama model writes its own result cell
        self.host = host.rstrip("/")
        self.temperature = temperature
        self.num_predict = num_predict
        self.timeout = timeout
        self.options = options

    def _sampling_options(self) -> dict[str, Any]:
        opts: dict[str, Any] = {
            "temperature": self.temperature,
            "num_predict": self.num_predict,
        }
        opts.update(self.options)
        return opts

    def generate(self, dialog: list[DialogTurn]) -> Response:
        messages = _dialog_to_messages(dialog)
        t0 = time.perf_counter()
        data = self._chat(messages)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        text = (data.get("message") or {}).get("content", "") or ""
        tokens = self._token_counts(data)
        return Response(
            attempt_id="",
            target=self.model,
            output_turns=[DialogTurn(role="assistant", content=text)],
            latency_ms=latency_ms,
            tokens=tokens,
            raw={"backend": "ollama", "model": self.model},
        )

    def _chat(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Send a chat request via the ollama client, or HTTP fallback."""
        try:
            import ollama  # type: ignore
        except ImportError:
            return self._chat_http(messages)

        client = ollama.Client(host=self.host)
        result = client.chat(
            model=self.model,
            messages=messages,
            options=self._sampling_options(),
            stream=False,
        )
        # Newer clients return a pydantic-like object; normalize to a dict.
        if hasattr(result, "model_dump"):
            return result.model_dump()  # type: ignore[no-any-return]
        return dict(result)

    def _chat_http(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        """Dependency-free fallback against Ollama's REST API."""
        payload = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "options": self._sampling_options(),
                "stream": False,
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:  # pragma: no cover - network path
            raise RuntimeError(
                f"could not reach Ollama daemon at {self.host}; "
                "start it with `ollama serve` or install the ollama client"
            ) from exc
        return json.loads(body)

    @staticmethod
    def _token_counts(data: dict[str, Any]) -> Optional[dict[str, int]]:
        prompt_n = data.get("prompt_eval_count")
        completion_n = data.get("eval_count")
        if prompt_n is None and completion_n is None:
            return None
        prompt_n = int(prompt_n or 0)
        completion_n = int(completion_n or 0)
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
    lambda: make_vllm_target("meta-llama/Llama-3.1-8B-Instruct"),
    backend="vllm",
    tensor_parallel_size=2,
)
REGISTRY.register(
    "ollama",
    lambda: make_ollama_target("llama3.1"),
    backend="ollama",
)


__all__ = [
    "VLLMTarget",
    "OllamaTarget",
    "make_vllm_target",
    "make_ollama_target",
]
