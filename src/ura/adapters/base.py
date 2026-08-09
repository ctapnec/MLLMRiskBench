"""Attacker and converter interfaces (thesis III.2.2).

Converters normalize a source corpus into DataPoints; attackers turn a DataPoint
into one or more concrete Attempts, either by replaying a static corpus or by
driving an external engine (PyRIT, Garak, DeepTeam, Promptfoo, Petri).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..data_models import Attempt, DataPoint


@dataclass(frozen=True)
class AttackBudget:
    """Bounds per-attempt resources so engines are compared fairly."""

    max_queries: int = 1
    max_turns: int = 1
    seed: int = 0


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

    def generate_batch(
        self, datapoints: Iterable[DataPoint], budget: AttackBudget
    ) -> list[Attempt]:
        out: list[Attempt] = []
        for dp in datapoints:
            out.extend(self.generate(dp, budget))
        return out


__all__ = ["AttackBudget", "BaseConverter", "BaseAttacker"]
