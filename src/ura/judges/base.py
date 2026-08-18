"""Judge interface and the cheapest-first cascade (thesis III.2.2, II.5.2).

The cascade answers Chapter II's LLM-as-judge validity critique: cheap
deterministic rules run first, then a guardrail classifier, then an LLM judge.
Every stage is shadow-scored so inter-judge agreement (Cohen's kappa) can be
computed over the full per-stage trail, and ``escalate_below`` selects which
stage's verdict is authoritative. The ``human_sink`` is a
RESERVED calibration hook: human adjudication is applied out-of-band on the
stratified audit sample of V.1.5 (yielding judge-vs-human precision/recall/F1 via
:func:`ura.metrics.judge_scores`), not as an automatic fourth cascade stage.
"""
from __future__ import annotations

import math
from abc import ABC, abstractmethod
from typing import Optional

from ..data_models import DataPoint, Judgment, Response


class BaseJudge(ABC):
    """Score a Response against a DataPoint's expected behavior."""

    name: str = "base"
    #: confidence below which the cascade escalates to the next stage
    escalate_below: float = 0.0
    # True only when the stage can incorporate
    # DataPoint.meta["judge_reference_text"] into its scoring input. Runtime
    # provenance still has to report that the context was actually consumed.
    source_reference_context_capable: bool = False

    @abstractmethod
    def judge(self, datapoint: DataPoint, response: Response) -> Judgment:
        ...  # pragma: no cover - interface

    def confident(self, judgment: Judgment) -> bool:
        """Whether this stage is confident enough to stop the cascade."""
        value = judgment.raw.get("confidence")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0.0 <= float(value) <= 1.0
        ):
            raise ValueError(
                f"judge {self.name!r} must emit finite confidence in [0,1]"
            )
        conf = float(value)
        return conf >= self.escalate_below


class JudgeCascadeDecisionError(RuntimeError):
    """No automated stage produced a confidence-qualified decision.

    A low-confidence placeholder is an abstention, not a binary safety label.
    Callers must fail the scored cell (and may analyse the retained stage
    outputs separately) instead of silently promoting the last placeholder.
    """

    def __init__(self, trail: list[Judgment]) -> None:
        super().__init__(
            "judge cascade produced no confidence-qualified authoritative verdict"
        )
        self.trail = trail


class JudgeCascade:
    """Run every judge for a shadow trail; use the first confident verdict.

    Later stages always run so their labels remain available for agreement and
    calibration.  They are *shadow scores*: the authoritative final judgment is
    the first stage whose confidence clears its threshold.  If no stage is
    confident, the cascade raises :class:`JudgeCascadeDecisionError`; it never
    turns an abstention into a binary label. Graded StrongREJECT is a separate
    construct: Runner extracts it only from the shadow stage that emitted the
    explicit StrongREJECT rubric fields, never from an arbitrary authoritative
    rule/guardrail score.
    """

    def __init__(self, stages: list[BaseJudge], human_sink: Optional[BaseJudge] = None) -> None:
        if not stages:
            raise ValueError("JudgeCascade needs at least one stage")
        names = [stage.name for stage in stages]
        if any(not isinstance(name, str) or not name.strip() for name in names):
            raise ValueError("JudgeCascade stage names must be non-blank strings")
        if len(set(names)) != len(names):
            raise ValueError("JudgeCascade stage names must be unique")
        for stage in stages:
            threshold = stage.escalate_below
            if (
                isinstance(threshold, bool)
                or not isinstance(threshold, (int, float))
                or not math.isfinite(float(threshold))
                or not 0.0 <= float(threshold) <= 1.0
            ):
                raise ValueError(
                    f"judge {stage.name!r} escalate_below must be in [0,1]"
                )
        self.stages = stages
        # Reserved calibration hook (out-of-band human audit on a stratified sample,
        # V.1.5); not invoked inside judge(), which scores only the automated stages.
        self.human_sink = human_sink

    def judge(self, datapoint: DataPoint, response: Response) -> tuple[Judgment, list[Judgment]]:
        raw_trail: list[Judgment] = []
        confidence: list[bool] = []
        authority_index: Optional[int] = None
        for index, stage in enumerate(self.stages):
            j = stage.judge(datapoint, response)
            if j.attempt_id != response.attempt_id:
                raise ValueError(
                    f"judge {stage.name!r} linked its verdict to "
                    f"{j.attempt_id!r}; expected {response.attempt_id!r}"
                )
            if j.judge != stage.name:
                raise ValueError(
                    f"judge stage {stage.name!r} emitted identity {j.judge!r}"
                )
            if not math.isfinite(float(j.score)):
                raise ValueError(f"judge {stage.name!r} emitted a non-finite score")
            raw_trail.append(j)
            is_confident = stage.confident(j)
            confidence.append(is_confident)
            if authority_index is None and is_confident:
                authority_index = index
        trail: list[Judgment] = []
        for index, judgment in enumerate(raw_trail):
            authoritative = index == authority_index
            role = "authoritative" if authoritative else "shadow"
            trail.append(judgment.model_copy(update={
                "raw": {
                    **judgment.raw,
                    "stage_queried": True,
                    "policy_evaluation_status": "evaluated",
                    "cascade_stage": index,
                    "cascade_confident": confidence[index],
                    "cascade_role": role,
                    "cascade_policy": "first_confident_with_full_shadow_trail",
                }
            }))
        if authority_index is None:
            raise JudgeCascadeDecisionError(trail)
        final = trail[authority_index]
        return final, trail


__all__ = ["BaseJudge", "JudgeCascade", "JudgeCascadeDecisionError"]
