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
    engines: dict[str, type[BaseAttacker]] = {
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
    if key in engines:
        return engines[key](**config)
    raise ValueError(
        f"unknown attacker {name!r}; "
        f"choose from replay, crescendo, {', '.join(engines)}"
    )


__all__ = [
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
    "get_attacker",
]
