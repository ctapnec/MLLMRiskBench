"""Microsoft PyRIT engine adapter (thesis II.4.1, III.2.2)."""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt, _require


class PyRITAttacker(BaseAttacker):
    """Wrap Microsoft PyRIT prompt-conversion / orchestration.

    Uses PyRIT's ``PromptConverter`` chain to mutate the seed payload into
    concrete attack prompts. Orchestrator-driven online scoring is out of scope
    for a single generate() call; we materialise deterministic converter output.
    """

    name = "pyrit"

    def __init__(self, converters: list[str] | None = None) -> None:
        # Names of pyrit.prompt_converter classes to apply in order.
        self.converters = converters or ["Base64Converter"]

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        prompt = self._render(self._seed(datapoint))
        yield _attempt(
            datapoint,
            self.name,
            strategy="+".join(self.converters),
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={"converters": self.converters},
        )

    @staticmethod
    def _seed(datapoint: DataPoint) -> str:
        return datapoint.payload_text or datapoint.payload_code or ""

    def _render(self, seed: str) -> str:
        """Apply the configured PyRIT converter chain (lazy import)."""
        mod = _require("pyrit.prompt_converter", "PyRITAttacker")
        text = seed
        for name in self.converters:
            converter_cls = getattr(mod, name)
            result = converter_cls().convert_sync(prompt=text, input_type="text")
            text = getattr(result, "output_text", str(result))
        return text
