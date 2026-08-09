"""Confident-AI DeepTeam engine adapter (thesis II.4.1, III.2.2)."""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt, _require


class DeepTeamAttacker(BaseAttacker):
    """Wrap Confident-AI DeepTeam attack enhancements.

    DeepTeam exposes single-turn attack transforms (e.g. ``PromptInjection``,
    ``Roleplay``). We apply one transform to the seed to produce an Attempt.
    """

    name = "deepteam"

    def __init__(self, attack: str = "PromptInjection") -> None:
        self.attack = attack

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompt = self._enhance(seed)
        yield _attempt(
            datapoint,
            self.name,
            strategy=self.attack,
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={"attack": self.attack},
        )

    def _enhance(self, seed: str) -> str:
        """Apply a DeepTeam attack transform to the seed (lazy import)."""
        mod = _require("deepteam.attacks.single_turn", "DeepTeamAttacker")
        attack_cls = getattr(mod, self.attack)
        return attack_cls().enhance(seed)
