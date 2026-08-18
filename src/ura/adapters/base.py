"""Attacker and converter interfaces (thesis III.2.2).

Converters normalize a source corpus into DataPoints; Runner-compatible
attackers turn a DataPoint into one or more concrete Attempts.  External
integrations that own their target or evaluator instead expose strict native
artifact boundaries and deliberately reject this prompt-generation contract.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..attacker_input_contract import (
    AttackerInputContract,
    AttackerInputContractError,
)
from ..data_models import Attempt, DataPoint, Response


@dataclass(frozen=True)
class AttackBudget:
    """Bounds per-attempt resources so engines are compared fairly."""

    max_queries: int = 1
    max_turns: int = 1
    seed: int = 0

    def __post_init__(self) -> None:
        if self.max_queries < 1:
            raise ValueError("AttackBudget.max_queries must be at least 1")
        if self.max_turns < 1:
            raise ValueError("AttackBudget.max_turns must be at least 1")


class AttackSession(ABC):
    """Response-conditioned conversation owned by a stateful attacker.

    ``next_attempt`` is called first with ``None`` and thereafter with the
    target response to the previously returned attempt.  It must return
    ``None`` once the attack is complete.  Query and turn limits remain the
    runner's responsibility, so every attacker is capped consistently.
    """

    @abstractmethod
    def next_attempt(self, previous_response: Response | None) -> Attempt | None:
        ...  # pragma: no cover - interface


class BaseConverter(ABC):
    """Normalize a source framework's corpus into unified DataPoints."""

    name: str = "base"
    schema_version: str = "1.0"

    @abstractmethod
    def parse(self, path: Path) -> list[DataPoint]:  # pragma: no cover - interface
        ...


class BaseAttacker(ABC):
    """Produce concrete Attempts from a DataPoint."""

    name: str = "base"

    @abstractmethod
    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        ...  # pragma: no cover - interface

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        """Declare every possible target-input shape before execution.

        Runner-compatible adapters override this fail-closed boundary.  Native
        integrations retain their own end-to-end artifact contract and are
        already rejected from common Runner execution.
        """

        raise AttackerInputContractError(
            f"attacker {self.name!r} has no prospective target-input contract"
        )

    def validate_measured_run(self, corpus: Iterable[DataPoint] = ()) -> None:
        """Fail before a measured grid when generation has an unsafe side effect.

        Ordinary attackers need no admission step.  Adapters whose prompt
        generation can itself call an external/source model override this hook
        and require an immutable precomputed artifact instead.
        """
        return None

    def start_session(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackSession | None:
        """Return a native response-conditioned session, when supported.

        The default keeps existing corpus/replay and external-engine adapters
        backward compatible.  The runner falls back to :meth:`generate` when
        this method returns ``None``.
        """
        return None

    def generate_batch(
        self, datapoints: Iterable[DataPoint], budget: AttackBudget
    ) -> list[Attempt]:
        out: list[Attempt] = []
        for dp in datapoints:
            out.extend(self.generate(dp, budget))
        return out


__all__ = [
    "AttackBudget",
    "AttackSession",
    "BaseConverter",
    "BaseAttacker",
]
