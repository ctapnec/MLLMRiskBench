"""Replay attacker - static-corpus adapter (thesis III.2.2).

The simplest attacker: it does not synthesize or escalate anything. It renders a
DataPoint verbatim into exactly one Attempt so that a pre-authored corpus (e.g.
converted R-Judge / MM-SafetyBench probes) can be replayed against any target.

If the DataPoint already carries a ``dialog_history`` it is used as-is; otherwise
a single ``user`` turn is assembled from ``payload_text`` / ``payload_code`` /
``media``. Fully deterministic, pure Python, no third-party dependencies.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint, DialogTurn
from .base import AttackBudget, BaseAttacker


class ReplayAttacker(BaseAttacker):
    """Turn a DataPoint into exactly one Attempt, replaying it verbatim."""

    name: str = "replay"

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        """Yield a single deterministic Attempt for ``datapoint``.

        The rendered input is the DataPoint's ``dialog_history`` when present,
        otherwise a lone ``user`` turn built from its payload fields and media.
        """
        rendered = self._render(datapoint)
        yield Attempt(
            # seed is part of the id so multi-seed runs do not collide in the
            # transfer matrix / kappa trails (which key on attempt_id); the id stays
            # model-independent, so the same (datapoint, seed) still matches across models.
            id=f"{datapoint.id}::replay::s{budget.seed}",
            datapoint_id=datapoint.id,
            attacker=self.name,
            strategy="replay",
            turn_index=0,
            rendered_input=rendered,
            seed=budget.seed,
            params={"max_queries": budget.max_queries, "max_turns": budget.max_turns},
        )

    @staticmethod
    def _render(datapoint: DataPoint) -> list[DialogTurn]:
        """Build the dialog to send: existing history, or one synthesized turn."""
        if datapoint.dialog_history:
            # Replay the authored conversation unchanged.
            return list(datapoint.dialog_history)

        # Assemble a single user turn from the payload fields.
        parts: list[str] = []
        if datapoint.payload_text:
            parts.append(datapoint.payload_text)
        if datapoint.payload_code:
            parts.append(datapoint.payload_code)
        content = "\n\n".join(parts) if parts else None

        return [
            DialogTurn(
                role="user",
                content=content,
                media=list(datapoint.media),
            )
        ]


__all__ = ["ReplayAttacker"]
