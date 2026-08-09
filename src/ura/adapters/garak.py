"""NVIDIA Garak engine adapter (thesis II.4.1, III.2.2)."""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt, _require


class GarakAttacker(BaseAttacker):
    """Wrap NVIDIA Garak probes as seed-prompt generators.

    Garak probes expose a ``prompts`` list; each becomes one Attempt. We only
    read the probe's static prompts (no live target harnessing here).
    """

    name = "garak"

    def __init__(self, probe: str = "dan.Dan_11_0") -> None:
        self.probe = probe

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        prompts = self._probe_prompts()[: max(1, budget.max_queries)]
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy=self.probe,
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={"probe": self.probe},
            )

    def _probe_prompts(self) -> list[str]:
        """Instantiate the Garak probe and pull its static prompts (lazy)."""
        garak = _require("garak._plugins", "GarakAttacker")
        probe = garak.load_plugin(f"probes.{self.probe}")
        return [str(p) for p in getattr(probe, "prompts", [])] or [""]
