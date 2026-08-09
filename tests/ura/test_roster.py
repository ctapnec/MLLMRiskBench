"""Roster tests: the full attacker + converter registries resolve, guard offline,
and are robust to a missing corpus path. Locks the expanded engine/framework set
against silent regressions (an engine dropped from get_attacker, a converter that
crashes on a missing file, a wrapped engine that imports a heavy dep at module load).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ura.adapters.base import AttackBudget
from ura.adapters.engines import get_attacker
from ura.converters import get_converter, synth_corpus
from ura.converters import _CONVERTERS

# The wrapped engines require a third-party library or CLI; offline they must raise
# a clear error at generate() time, never import their dep at module load.
WRAPPED_ENGINES = ["pyrit", "garak", "deepteam", "promptfoo", "t3mp3st",
                   "petri", "fuzzyai", "nanogcg", "autodan", "agentdojo", "giskard"]
NATIVE_ATTACKERS = ["replay", "crescendo"]

EXPECTED_CONVERTERS = {
    "rjudge", "mmsafety", "jailbreakv", "gptgeochat", "agentharm", "strongreject",
    "bipia", "harmbench", "vlsbench", "mossbench", "siuo",
    "advbench", "jailbreakbench", "figstep", "cyberseceval", "injecagent", "mllmguard",
}


def test_attacker_roster_resolves():
    for name in NATIVE_ATTACKERS + WRAPPED_ENGINES:
        assert get_attacker(name) is not None
    # every wrapped engine reports its own name
    for name in WRAPPED_ENGINES:
        assert get_attacker(name).name == name


@pytest.mark.parametrize("name", WRAPPED_ENGINES)
def test_wrapped_engine_guarded_offline(name: str):
    """With no third-party lib/CLI installed, generate() raises a clear error
    (import-clean module, cost paid only at the edge)."""
    attacker = get_attacker(name)
    dp = synth_corpus(1)[0]
    with pytest.raises(Exception):  # RuntimeError in practice; never a bare ImportError at import
        list(attacker.generate(dp, AttackBudget(max_queries=2)))


def test_converter_roster_resolves_and_is_missing_path_safe():
    assert set(_CONVERTERS) == EXPECTED_CONVERTERS
    for name in EXPECTED_CONVERTERS:
        conv = get_converter(name)
        assert conv.name == name
        # a missing corpus path returns [] rather than raising (dependency-tolerant)
        assert conv.parse(Path(f"does-not-exist-{name}.json")) == []
        assert conv.parse(Path(f"does-not-exist-{name}.csv")) == []
