"""Target gateway interface (thesis III.2.2).

A single abstraction over hosted APIs (Anthropic/OpenAI/Google) and local
open-weight backends (vLLM/Ollama). Concrete targets are registered so the
orchestrator can address any model by id.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..data_models import DialogTurn, Response


class BaseTarget(ABC):
    """A model under test.

    ``seed`` is a request for deterministic sampling, not a guarantee. Concrete
    targets must state the effective control in
    ``Response.raw["target_sampling_control"]``; hosted providers that cannot
    honour a seed report ``"uncontrolled"``. This prevents the runner from
    inferring reproducibility merely because a method accepted the argument.
    """

    name: str = "base"
    modality_support: tuple[str, ...] = ("text",)

    @abstractmethod
    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        ...  # pragma: no cover - interface


class TargetRegistry:
    """Maps model ids to target factories (records size/quant/VRAM for local models)."""

    def __init__(self) -> None:
        self._factories: dict[str, callable] = {}
        self._meta: dict[str, dict] = {}

    def register(self, model_id: str, factory, **meta) -> None:
        self._factories[model_id] = factory
        self._meta[model_id] = meta

    def create(self, model_id: str) -> BaseTarget:
        if model_id not in self._factories:
            raise KeyError(f"unknown target '{model_id}'")
        return self._factories[model_id]()

    def meta(self, model_id: str) -> dict:
        return self._meta.get(model_id, {})

    def ids(self) -> list[str]:
        return sorted(self._factories)


REGISTRY = TargetRegistry()

__all__ = ["BaseTarget", "TargetRegistry", "REGISTRY"]
