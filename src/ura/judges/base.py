"""Judge interface and the cheapest-first cascade (thesis III.2.2, II.5.2).

The cascade answers Chapter II's LLM-as-judge validity critique: cheap
deterministic rules run first, then a guardrail classifier, then an LLM judge
only for the uncertain remainder, with a human-audit sink for calibration.
Each stage emits a Judgment; agreement between stages is a reported metric.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..data_models import DataPoint, Judgment, Response


class BaseJudge(ABC):
    """Score a Response against a DataPoint's expected behavior."""

    name: str = "base"
    #: confidence below which the cascade escalates to the next stage
    escalate_below: float = 0.0

    @abstractmethod
    def judge(self, datapoint: DataPoint, response: Response) -> Judgment:
        ...  # pragma: no cover - interface

    def confident(self, judgment: Judgment) -> bool:
        """Whether this stage is confident enough to stop the cascade."""
        conf = float(judgment.raw.get("confidence", 1.0))
        return conf >= self.escalate_below


class JudgeCascade:
    """Run judges cheapest-first; stop at the first confident verdict.

    Records every stage's Judgment (for Cohen's-kappa agreement) and returns the
    final decision plus the full per-stage trail.
    """

    def __init__(self, stages: list[BaseJudge], human_sink: Optional[BaseJudge] = None) -> None:
        if not stages:
            raise ValueError("JudgeCascade needs at least one stage")
        self.stages = stages
        self.human_sink = human_sink

    def judge(self, datapoint: DataPoint, response: Response) -> tuple[Judgment, list[Judgment]]:
        trail: list[Judgment] = []
        decision: Optional[Judgment] = None
        for stage in self.stages:
            j = stage.judge(datapoint, response)
            trail.append(j)
            if decision is None and stage.confident(j):
                decision = j
        # fall back to the last (most expensive) stage if nothing was confident
        final = decision or trail[-1]
        return final, trail


__all__ = ["BaseJudge", "JudgeCascade"]
