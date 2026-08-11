"""GuardedTarget - a defense wrapper for the E4 ablation (thesis V.1.7, RQ3).

Wraps any :class:`~ura.targets.base.BaseTarget` behind a guardrail judge so that
unsafe **inputs** are blocked before the model is queried and/or unsafe
**outputs** are suppressed after. Running the same matrix with and without the
wrapper measures both the attack-success reduction and the over-refusal cost of a
deployed guardrail. This is a within-target defense ablation and is analytically
separate from cross-provider model comparisons (II.6.1).

Pure-python when the guard is a :class:`~ura.judges.rules.RuleJudge`; with a
:class:`GuardrailJudge` it inherits that judge's lazy dependency.
"""
from __future__ import annotations

from typing import Literal

from ..data_models import DataPoint, DialogTurn, Judgment, Response, RiskCategory
from ..judges.base import BaseJudge
from ..judges.guardrail import GuardrailJudge
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
        if hasattr(base, "modality_combinations"):
            # Preserve the adapter's tested combination contract. Re-inferring
            # it from a flat capability list could either lose an explicitly
            # supported cross-media combination or claim one the base adapter
            # never implemented.
            self.modality_combinations = getattr(base, "modality_combinations")
        if hasattr(base, "max_transport_attempts_per_call"):
            self.max_transport_attempts_per_call = getattr(
                base, "max_transport_attempts_per_call"
            )
        if hasattr(base, "media_roots"):
            self.media_roots = getattr(base, "media_roots")

    def validate_research_identity(self) -> None:
        """Preserve the wrapped target/guard identity gates in measured runs."""
        for component in (self.base, self.guard):
            validator = getattr(component, "validate_research_identity", None)
            if callable(validator):
                validator()

    def preflight_base(self) -> None:
        """Preload only the wrapped target; guard loading is ordered separately."""

        preflight = getattr(self.base, "preflight_base", None)
        if callable(preflight):
            preflight()

    def _blocked(
        self, target: str, stage: str, *, seed: int | None = None
    ) -> Response:
        return Response(
            attempt_id="__guard__",
            target=self.name,
            output_turns=[DialogTurn(role="assistant", content=_BLOCK_TEXT)],
            raw={
                "defense": "blocked",
                "stage": stage,
                "base_target": target,
                "requested_seed": seed,
                "target_sampling_control": "not_queried",
            },
        )

    @staticmethod
    def _require_valid_guard_verdict(verdict: Judgment) -> None:
        """Stop a scored cell when a model guard says its output was unparsed.

        A rule guard may intentionally emit a low-confidence safe result to mean
        that no blocking rule matched.  An explicit ``parsed=False`` signal is
        different: the model output was not understood.  Letting the placeholder
        safe label pass would make the defense fail open.
        """
        if verdict.raw.get("parsed") is False:
            raise RuntimeError(
                "defense guard returned an unparsed verdict; refusing to fail open"
            )

    def generate(
        self, dialog: list[DialogTurn], *, seed: int | None = None
    ) -> Response:
        # Llama Guard 3 is a text classifier. A hash sentinel is useful when it
        # participates as a non-multimodal judge, but it cannot defend a request
        # whose safety semantics are carried by physical media. Reject the cell
        # before either the guard model or the wrapped target can be queried.
        if isinstance(self.guard, GuardrailJudge) and any(
            turn.media for turn in dialog
        ):
            raise RuntimeError(
                "GuardrailJudge defense is text-only and cannot screen a "
                "physical-media dialog; refusing before target execution"
            )

        # 1) input screening: judge the incoming user turn(s)
        if self.mode in ("input", "both"):
            judge_input = getattr(self.guard, "judge_input", None)
            if callable(judge_input):
                verdict = judge_input(dialog)
            else:
                # Compatibility path for custom legacy guards. The provenance
                # explicitly records that a response-oriented API was used.
                input_turns = [t for t in dialog if t.role in ("user", "env")]
                probe = Response(
                    attempt_id="__guard__",
                    target=self.base.name,
                    output_turns=[
                        DialogTurn(role="assistant", content=t.content, media=t.media)
                        for t in (input_turns[-1:] or dialog[-1:])
                    ],
                    raw={"moderation_subject": "user_input", "compatibility_mode": True},
                )
                verdict = self.guard.judge(_GUARD_DP, probe)
            self._require_valid_guard_verdict(verdict)
            if verdict.label == "violation":
                return self._blocked(self.base.name, "input", seed=seed)

        # 2) query the wrapped target; attribute the result to the guarded config
        response = self.base.generate(dialog, seed=seed).model_copy(
            update={"target": self.name}
        )

        # 3) output screening: judge the model's reply
        if self.mode in ("output", "both"):
            verdict = self.guard.judge(_GUARD_DP, response)
            self._require_valid_guard_verdict(verdict)
            if verdict.label == "violation":
                blocked = self._blocked(self.base.name, "output", seed=seed)
                # The base target was queried and billed even though the guard
                # suppresses its text. Preserve its sanitized identity,
                # generation and transport audit so durable accounting and
                # modality-execution evidence do not mistake this for an input
                # block. The unsafe output turns themselves remain discarded.
                return blocked.model_copy(update={
                    "latency_ms": response.latency_ms,
                    "tokens": response.tokens,
                    "raw": {
                        **response.raw,
                        **blocked.raw,
                        "target_sampling_control": response.raw.get(
                            "target_sampling_control",
                            response.raw.get("sampling_control"),
                        ),
                        "base_target_queried": True,
                        "suppressed_output": True,
                    },
                })
        return response


__all__ = ["GuardedTarget"]
