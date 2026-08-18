"""Attacker aggregator + factory (thesis III.2.2).

Each external red-team engine has its own module - pyrit, garak, deepteam,
promptfoo, t3mp3st, petri, fuzzyai, nanogcg, autodan, agentdojo, giskard,
easyjailbreak, h4rm3l, spikee, ideator, purplellama, asb, harmbench - and the
pure-python replay / crescendo adapters live beside them. This module re-exports
the engine classes and provides :func:`get_attacker`,
which resolves any attacker by name. Every engine dependency is imported lazily
inside its own module, so importing this file needs only pydantic + stdlib.
"""
from __future__ import annotations

from .agentdojo import AgentDojoAttacker
from ._engine_runtime import (
    RUNTIME_REQUIRED_ATTACKERS,
    require_admitted_engine_runtime,
)
from .asb import ASBAttacker
from .autodan import AutoDANTurboAttacker
from .base import BaseAttacker
from .deepteam import DeepTeamAttacker
from .easyjailbreak import EasyJailbreakAttacker
from .fuzzyai import FuzzyAIAttacker
from .garak import GarakAttacker
from .giskard import GiskardAttacker
from .h4rm3l import H4rm3lAttacker
from .harmbench import HarmBenchAttacker
from .ideator import IDEATORAttacker
from .nanogcg import NanoGCGAttacker
from .petri import PetriAttacker
from .promptfoo import PromptfooAttacker
from .purplellama import PurpleLlamaAttacker
from .pyrit import PyRITAttacker
from .spikee import SpikeeAttacker
from .t3mp3st import T3MP3STAttacker


#: The canonical, ordered list of every registered attacker name - the single
#: source of truth ``get_attacker`` resolves against and the console builder
#: derives its attacker inventory from (so the two never drift).  ``replay`` and
#: ``crescendo`` are the pure-python adapters; the rest are external engines.
ATTACKER_NAMES: tuple[str, ...] = (
    "replay", "crescendo",
    "pyrit", "garak", "deepteam", "promptfoo", "t3mp3st", "petri", "fuzzyai",
    "nanogcg", "autodan", "agentdojo", "giskard", "easyjailbreak", "h4rm3l",
    "spikee", "ideator", "purplellama", "asb", "harmbench",
)

_ENGINE_TYPES: dict[str, type[BaseAttacker]] = {
    "pyrit": PyRITAttacker,
    "garak": GarakAttacker,
    "deepteam": DeepTeamAttacker,
    "promptfoo": PromptfooAttacker,
    "t3mp3st": T3MP3STAttacker,
    "petri": PetriAttacker,
    "fuzzyai": FuzzyAIAttacker,
    "nanogcg": NanoGCGAttacker,
    "autodan": AutoDANTurboAttacker,
    "agentdojo": AgentDojoAttacker,
    "giskard": GiskardAttacker,
    "easyjailbreak": EasyJailbreakAttacker,
    "h4rm3l": H4rm3lAttacker,
    "spikee": SpikeeAttacker,
    "ideator": IDEATORAttacker,
    "purplellama": PurpleLlamaAttacker,
    "asb": ASBAttacker,
    "harmbench": HarmBenchAttacker,
}


def attacker_runner_replay_eligible(name: str) -> bool:
    """Return static Runner eligibility without constructing an adapter."""

    key = name.strip().lower()
    if key in {"replay", "crescendo"}:
        return True
    try:
        attacker_type = _ENGINE_TYPES[key]
    except KeyError as exc:
        raise ValueError(f"unknown attacker {name!r}") from exc
    return bool(getattr(attacker_type, "runner_replay_eligible", True))


def get_attacker(name: str, **config: object) -> BaseAttacker:
    """Resolve an attacker adapter by name.

    Handles the pure-python ``replay`` / ``crescendo`` adapters (imported lazily
    from sibling modules) and every registered external-engine integration.
    """
    key = name.strip().lower()
    if key == "replay":
        from .replay import ReplayAttacker

        return ReplayAttacker(**config)
    if key == "crescendo":
        from .crescendo import CrescendoAttacker

        return CrescendoAttacker(**config)
    if key in _ENGINE_TYPES:
        if key in RUNTIME_REQUIRED_ATTACKERS:
            require_admitted_engine_runtime(config.get("engine_runtime"), key)
        return _ENGINE_TYPES[key](**config)
    raise ValueError(
        f"unknown attacker {name!r}; "
        f"choose from replay, crescendo, {', '.join(_ENGINE_TYPES)}"
    )


__all__ = [
    "ATTACKER_NAMES",
    "PyRITAttacker",
    "GarakAttacker",
    "DeepTeamAttacker",
    "PromptfooAttacker",
    "T3MP3STAttacker",
    "PetriAttacker",
    "FuzzyAIAttacker",
    "NanoGCGAttacker",
    "AutoDANTurboAttacker",
    "AgentDojoAttacker",
    "GiskardAttacker",
    "EasyJailbreakAttacker",
    "H4rm3lAttacker",
    "SpikeeAttacker",
    "IDEATORAttacker",
    "PurpleLlamaAttacker",
    "ASBAttacker",
    "HarmBenchAttacker",
    "attacker_runner_replay_eligible",
    "get_attacker",
]
