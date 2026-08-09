"""Attacker aggregator + factory (thesis III.2.2).

Each external red-team engine has its own module - pyrit, garak, deepteam,
promptfoo - and the pure-python replay / crescendo adapters live beside them.
This module re-exports the engine classes and provides :func:`get_attacker`,
which resolves any attacker by name. Every engine dependency is imported lazily
inside its own module, so importing this file needs only pydantic + stdlib.
"""
from __future__ import annotations

from .base import BaseAttacker
from .deepteam import DeepTeamAttacker
from .garak import GarakAttacker
from .promptfoo import PromptfooAttacker
from .pyrit import PyRITAttacker


def get_attacker(name: str) -> BaseAttacker:
    """Resolve an attacker adapter by name.

    Handles the pure-python ``replay`` / ``crescendo`` adapters (imported lazily
    from sibling modules) and the four engine wrappers.
    """
    key = name.strip().lower()
    if key == "replay":
        from .replay import ReplayAttacker

        return ReplayAttacker()
    if key == "crescendo":
        from .crescendo import CrescendoAttacker

        return CrescendoAttacker()
    engines: dict[str, type[BaseAttacker]] = {
        "pyrit": PyRITAttacker,
        "garak": GarakAttacker,
        "deepteam": DeepTeamAttacker,
        "promptfoo": PromptfooAttacker,
    }
    if key in engines:
        return engines[key]()
    raise ValueError(
        f"unknown attacker {name!r}; "
        f"choose from replay, crescendo, {', '.join(engines)}"
    )


__all__ = [
    "PyRITAttacker",
    "GarakAttacker",
    "DeepTeamAttacker",
    "PromptfooAttacker",
    "get_attacker",
]
