"""GuardedTarget - a defense wrapper for the E4 ablation (thesis V.1.7, RQ3).

Wraps any :class:`~ura.targets.base.BaseTarget` behind a guardrail judge so that
unsafe **inputs** are blocked before the model is queried and/or unsafe
**outputs** are suppressed after. Running the same matrix with and without the
wrapper measures both the attack-success reduction and the over-refusal cost of a
deployed guardrail - externally reconstructing the safety layer that the
Fable/Mythos split represents internally (II.6.1).

Pure-python when the guard is a :class:`~ura.judges.rules.RuleJudge`; with a
:class:`GuardrailJudge` it inherits that judge's lazy dependency.
"""
from __future__ import annotations

from typing import Literal

from ..data_models import DataPoint, DialogTurn, Response, RiskCategory
from ..judges.base import BaseJudge
from .base import BaseTarget

_BLOCK_TEXT = (
    "I can't help with that. A safety guardrail flagged this request as "
    "potentially harmful, so it was blocked before completion."
)

# A generic datapoint for the guard: the guardrail classifies content, not the
# datapoint's declared category, so a placeholder is sufficient.
_GUARD_DP = DataPoint(
    id="__guard__", source="guard", modalities=["text"],
    risk_category=RiskCategory.JAILBREAK, expected_behavior="refuse",
)


class GuardedTarget(BaseTarget):
    """A base target defended by a guardrail judge on input and/or output."""

    def __init__(
        self,
        base: BaseTarget,
        guard: BaseJudge,
        mode: Literal["input", "output", "both"] = "input",
    ) -> None:
        self.base = base
        self.guard = guard
        self.mode = mode
        self.name = f"{base.name}+guard"
        self.modality_support = base.modality_support

    def _blocked(self, target: str, stage: str) -> Response:
        return Response(
            attempt_id="__guard__",
            target=self.name,
            output_turns=[DialogTurn(role="assistant", content=_BLOCK_TEXT)],
            raw={"defense": "blocked", "stage": stage, "base_target": target},
        )

    def generate(self, dialog: list[DialogTurn]) -> Response:
        # 1) input screening: judge the incoming user turn(s)
        if self.mode in ("input", "both"):
            probe = Response(
                attempt_id="__guard__", target=self.base.name,
                output_turns=[t for t in dialog if t.role == "user"][-1:] or dialog[-1:],
            )
            if self.guard.judge(_GUARD_DP, probe).label == "violation":
                return self._blocked(self.base.name, "input")

        # 2) query the wrapped target; attribute the result to the guarded config
        response = self.base.generate(dialog).model_copy(update={"target": self.name})

        # 3) output screening: judge the model's reply
        if self.mode in ("output", "both"):
            if self.guard.judge(_GUARD_DP, response).label == "violation":
                blocked = self._blocked(self.base.name, "output")
                blocked.raw["suppressed_output"] = True
                return blocked
        return response


__all__ = ["GuardedTarget"]
