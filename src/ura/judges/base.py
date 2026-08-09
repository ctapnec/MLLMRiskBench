"""Judge interface and the cheapest-first cascade (thesis III.2.2, II.5.2).

The cascade answers Chapter II's LLM-as-judge validity critique: cheap
deterministic rules run first, then a guardrail classifier, then an LLM judge.
By default every stage is scored so inter-judge agreement (Cohen's kappa) can be
computed over the full per-stage trail, and ``escalate_below`` selects which
stage's verdict is authoritative (set it above 0 for a cost-saving early-exit
where later stages run only for low-confidence items). The ``human_sink`` is a
RESERVED calibration hook: human adjudication is applied out-of-band on the
stratified audit sample of V.1.5 (yielding judge-vs-human precision/recall/F1 via
:func:`ura.metrics.judge_scores`), not as an automatic fourth cascade stage.
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
        # Reserved calibration hook (out-of-band human audit on a stratified sample,
        # V.1.5); not invoked inside judge(), which scores only the automated stages.
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
