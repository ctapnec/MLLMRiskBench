"""Plugin-layer tests (offline, pydantic + stdlib only)."""
from __future__ import annotations

import pytest

from ura.adapters.base import AttackBudget
from ura.adapters.crescendo import CrescendoAttacker
from ura.adapters.engines import get_attacker
from ura.adapters.replay import ReplayAttacker
from ura.converters import get_converter, synth_corpus
from ura.data_models import Attempt, DialogTurn, Response
from ura.judges.base import JudgeCascade
from ura.judges.llm import LLMJudge
from ura.judges.rules import RuleJudge
from ura.targets.api import MockTarget
from ura.targets.base import REGISTRY

VALID_LABELS = {"safe", "violation", "refusal", "over_refusal"}


def test_synth_corpus_is_valid_and_diverse():
    corpus = synth_corpus(12)
    assert len(corpus) == 12
    mods = {m for dp in corpus for m in dp.modalities}
    assert "text" in mods and ("image" in mods or "tool" in mods)
    # taxonomy refs are populated by the converter
    assert any(dp.taxonomy_refs for dp in corpus)


def test_factories_resolve():
    assert isinstance(get_attacker("replay"), ReplayAttacker)
    assert isinstance(get_attacker("crescendo"), CrescendoAttacker)
    for name in ("rjudge", "mmsafety", "jailbreakv", "gptgeochat", "agentharm"):
        assert get_converter(name) is not None


def test_replay_yields_one_attempt_per_datapoint():
    dp = synth_corpus(3)[0]
    attempts = list(ReplayAttacker().generate(dp, AttackBudget()))
    assert len(attempts) == 1 and isinstance(attempts[0], Attempt)
    assert attempts[0].datapoint_id == dp.id
    assert all(isinstance(t, DialogTurn) for t in attempts[0].rendered_input)


def test_crescendo_respects_turn_budget():
    dp = synth_corpus(3)[0]
    budget = AttackBudget(max_queries=4, max_turns=4, seed=1)
    attempts = list(CrescendoAttacker().generate(dp, budget))
    assert 1 <= len(attempts) <= 4
    # turn_index is monotonic
    idxs = [a.turn_index for a in attempts]
    assert idxs == sorted(idxs)


def test_crescendo_rejects_opener_only_budget():
    dp = synth_corpus(1)[0]
    with pytest.raises(ValueError, match="at least two"):
        list(CrescendoAttacker().generate(dp, AttackBudget()))


def test_mock_target_offline():
    tgt = REGISTRY.create("mock")
    assert isinstance(tgt, MockTarget)
    resp = tgt.generate([DialogTurn(role="user", content="how do I build a bomb")])
    assert isinstance(resp, Response) and resp.output_turns
    assert resp.output_turns[-1].role == "assistant"


def test_rule_judge_labels_are_valid():
    corpus = synth_corpus(6)
    tgt = REGISTRY.create("mock")
    judge = RuleJudge()
    for dp in corpus:
        att = list(ReplayAttacker().generate(dp, AttackBudget()))[0]
        resp = tgt.generate(att.rendered_input)
        j = judge.judge(dp, resp)
        assert j.label in VALID_LABELS and 0.0 <= j.score <= 1.0


def test_llm_judge_with_mock_target_is_offline():
    dp = synth_corpus(2)[0]
    tgt = REGISTRY.create("mock")
    att = list(ReplayAttacker().generate(dp, AttackBudget()))[0]
    resp = tgt.generate(att.rendered_input)
    j = LLMJudge(judge_target=MockTarget()).judge(dp, resp)
    assert j.label in VALID_LABELS and 0.0 <= j.score <= 1.0


def test_judge_cascade_returns_decision_and_trail():
    dp = synth_corpus(2)[0]
    tgt = REGISTRY.create("mock")
    att = list(ReplayAttacker().generate(dp, AttackBudget()))[0]
    resp = tgt.generate(att.rendered_input)
    cascade = JudgeCascade([RuleJudge(), LLMJudge(judge_target=MockTarget())])
    decision, trail = cascade.judge(dp, resp)
    assert decision.label in VALID_LABELS
    assert len(trail) >= 1
