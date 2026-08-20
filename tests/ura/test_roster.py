"""Roster tests: the full attacker + converter registries resolve, guard offline,
and fail closed on a missing corpus path. Locks the expanded engine/framework set
against silent regressions (an engine dropped from get_attacker, a converter that
crashes on a missing file, a wrapped engine that imports a heavy dep at module load).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from ura.adapters.base import AttackBudget
from ura.adapters._engine_runtime import RUNTIME_REQUIRED_ATTACKERS
from ura.adapters.engines import get_attacker
from ura.converters import CorpusNotFoundError, get_converter, synth_corpus
from ura.converters import _CONVERTERS

# The wrapped engines require a third-party library or CLI; offline they must raise
# a clear error at generate() time, never import their dep at module load.
WRAPPED_ENGINES = ["pyrit", "garak", "deepteam", "promptfoo", "t3mp3st",
                   "petri", "fuzzyai", "nanogcg", "autodan", "agentdojo", "giskard",
                   "easyjailbreak", "h4rm3l", "spikee", "ideator", "purplellama",
                   "asb", "harmbench"]
NATIVE_ATTACKERS = ["replay", "crescendo"]

class _RosterRuntime:
    """Minimal admitted handle for constructor-only registry coverage."""

    admitted = True

    def __init__(self, engine: str) -> None:
        self.engine = engine

    def execute(self, *_args: object, **_kwargs: object) -> object:
        raise RuntimeError("roster fixture never executes an isolated runtime")

    def public_descriptor(self) -> dict[str, str]:
        return {"schema": "test-engine-runtime/1", "engine": self.engine}


def _roster_attacker(name: str):  # noqa: ANN202
    config: dict[str, object] = {}
    if name in RUNTIME_REQUIRED_ATTACKERS:
        config["engine_runtime"] = _RosterRuntime(name)
    elif name == "nanogcg":
        config.update(
            suffix=" !precomputed-test-suffix!",
            suffix_source="unit-test fixture",
        )
    return get_attacker(name, **config)


EXPECTED_CONVERTERS = {
    "rjudge", "mmsafety", "jailbreakv", "gptgeochat", "agentharm", "strongreject",
    "bipia", "harmbench", "vlsbench", "mossbench", "siuo",
    "advbench", "jailbreakbench", "figstep", "cyberseceval", "injecagent", "mllmguard",
    "jalmbench", "videosafetybench", "saladbench",
}


def test_attacker_roster_resolves():
    for name in NATIVE_ATTACKERS + WRAPPED_ENGINES:
        assert _roster_attacker(name) is not None
    # every wrapped engine reports its own name
    for name in WRAPPED_ENGINES:
        assert _roster_attacker(name).name == name


@pytest.mark.parametrize("name", WRAPPED_ENGINES)
def test_wrapped_engine_guarded_offline(name: str):
    """With no third-party lib/CLI installed, generate() raises a clear error
    (import-clean module, cost paid only at the edge)."""
    if name in RUNTIME_REQUIRED_ATTACKERS:
        with pytest.raises(RuntimeError, match="explicit virtual environment"):
            get_attacker(name)
        return
    if name == "nanogcg":
        with pytest.raises(RuntimeError, match="live nanoGCG optimization is disabled"):
            get_attacker(name)
        return
    attacker = _roster_attacker(name)
    dp = synth_corpus(1)[0]
    with pytest.raises(Exception):  # RuntimeError in practice; never a bare ImportError at import
        list(attacker.generate(dp, AttackBudget(max_queries=2)))


def test_converter_roster_resolves_and_fails_closed_on_missing_path():
    assert set(_CONVERTERS) == EXPECTED_CONVERTERS
    for name in EXPECTED_CONVERTERS:
        conv = get_converter(name)
        assert conv.name == name
        # Missing data is a measurement failure, not an empty benchmark cell.
        with pytest.raises(CorpusNotFoundError):
            conv.parse(Path(f"does-not-exist-{name}.json"))
        with pytest.raises(CorpusNotFoundError):
            conv.parse(Path(f"does-not-exist-{name}.csv"))
