"""Target gateway interface (thesis III.2.2).

A single abstraction over hosted APIs (Anthropic/OpenAI/Google) and local
open-weight backends (vLLM/Ollama). Concrete targets are registered so the
orchestrator can address any model by id.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..data_models import DialogTurn, Response


class TargetAnswerError(RuntimeError):
    """One target call produced no usable model answer.

    The Runner retains this as a typed model-stability observation and continues
    the admitted evaluation population.  Identity, seal, configuration and
    budget failures must use a different exception type and remain terminal.
    """

    def __init__(self, message: str, *, category: str = "unusable_output") -> None:
        super().__init__(message)
        self.category = category


class TargetIntegrityError(RuntimeError):
    """A target violated admitted identity or fixed execution provenance."""


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
    # Research evidence produced by this target. Real provider/local targets use
    # the measured default; deterministic fixtures must opt into ``synthetic``.
    # Runner treats a response-level mock marker as an additional fail-safe, so
    # a caller cannot upgrade mock evidence merely by overriding this attribute.
    evidence_class: str = "measured"

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

__all__ = [
    "BaseTarget",
    "TargetAnswerError",
    "TargetIntegrityError",
    "TargetRegistry",
    "REGISTRY",
]
