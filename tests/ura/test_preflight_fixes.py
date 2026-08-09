"""Regression tests for the pre-run harness fixes (rig-readiness pass).

Each test pins one blocking issue caught before the 2x RTX 4090 run:
per-model cell naming, seed-distinct attempt ids, per-category kappa trails, and
the multi-turn robustness metrics.
"""
from __future__ import annotations

import json
from pathlib import Path

from ura.adapters.base import AttackBudget
from ura.adapters.crescendo import CrescendoAttacker
from ura.adapters.replay import ReplayAttacker
from ura.converters import synth_corpus
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.runner import Runner
from ura.targets.api import AnthropicTarget, GeminiTarget, MockTarget, OpenAITarget


def test_api_targets_use_per_model_name():
    # Construction must not need an SDK/key; only generate() does. The name is the
    # MODEL id (not the provider), so two models of one provider get distinct cells.
    assert AnthropicTarget("claude-opus-5").name == "claude-opus-5"
    assert OpenAITarget("gpt-5.6").name == "gpt-5.6"
    assert GeminiTarget("gemini-3.1-pro").name == "gemini-3.1-pro"
    assert AnthropicTarget("claude-opus-5").name != AnthropicTarget("claude-fable-5").name


def test_attempt_ids_include_seed():
    dp = synth_corpus(1)[0]
    r0 = next(iter(ReplayAttacker().generate(dp, AttackBudget(seed=0)))).id
    r1 = next(iter(ReplayAttacker().generate(dp, AttackBudget(seed=1)))).id
    assert r0.endswith("::s0") and r1.endswith("::s1") and r0 != r1

    c0 = [a.id for a in CrescendoAttacker().generate(dp, AttackBudget(seed=0, max_turns=3))]
    c1 = [a.id for a in CrescendoAttacker().generate(dp, AttackBudget(seed=1, max_turns=3))]
    # different seeds must not share any id (else transfer/kappa silently halve the data)
    assert set(c0).isdisjoint(c1)


def test_trails_carry_risk_category(tmp_path: Path):
    corpus = synth_corpus(8)
    runner = Runner(ReplayAttacker(), MockTarget(), JudgeCascade([RuleJudge()]),
                    AttackBudget(), seeds=[0])
    runner.run(corpus, started_at="t")
    p = tmp_path / "cell.trails.jsonl"
    runner.save_trails(p)
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    assert rows and all("risk_category" in r and "modality" in r for r in rows)
    assert {r["risk_category"] for r in rows} - {"unknown"}  # real categories present


def test_aggregate_emits_multiturn_robustness():
    corpus = synth_corpus(8)
    runner = Runner(CrescendoAttacker(), MockTarget(), JudgeCascade([RuleJudge()]),
                    AttackBudget(max_turns=4), seeds=[0])
    judgments, _ = runner.run(corpus, started_at="t")
    metrics = {r.metric for r in runner.aggregate(judgments, group_keys=["model"])}
    assert "robust_refusal_rate" in metrics  # V.2.4 / RQ4 is now producible
