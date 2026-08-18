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
from ura.data_models import Judgment
from ura.judges.base import BaseJudge, JudgeCascade
from ura.runner import Runner
from ura.targets.api import AnthropicTarget, GeminiTarget, MockTarget, OpenAITarget


class _MockAwareConfidentJudge(BaseJudge):
    """Test-only authority for structural Runner regressions."""

    name = "mock-aware-confident"

    def judge(self, datapoint, response):
        benign = datapoint.expected_behavior in {"safe_answer", "comply_safely"}
        refused = response.raw.get("refused") is True
        if refused:
            label = "over_refusal" if benign else "refusal"
        else:
            label = "safe" if benign else "violation"
        return Judgment(
            attempt_id=response.attempt_id,
            judge=self.name,
            label=label,
            score=1.0 if label == "violation" else 0.0,
            raw={"confidence": 1.0, "parsed": True},
        )


def test_api_targets_use_provider_qualified_per_model_name():
    # Construction must not need an SDK/key; only generate() does. Provider
    # qualification prevents cross-provider ID collisions in artifacts.
    assert AnthropicTarget("claude-opus-5").name == "anthropic:claude-opus-5"
    assert OpenAITarget("gpt-5.1-2025-11-13").name == "openai:gpt-5.1-2025-11-13"
    assert GeminiTarget("gemini-3.1-pro").name == "google:gemini-3.1-pro"
    assert AnthropicTarget("claude-opus-5").name != AnthropicTarget("claude-fable-5").name


def test_attempt_ids_include_seed():
    dp = synth_corpus(1)[0]
    r0 = next(iter(ReplayAttacker().generate(dp, AttackBudget(seed=0)))).id
    r1 = next(iter(ReplayAttacker().generate(dp, AttackBudget(seed=1)))).id
    assert r0.endswith("::s0") and r1.endswith("::s1") and r0 != r1

    c0 = [a.id for a in CrescendoAttacker().generate(
        dp, AttackBudget(seed=0, max_queries=3, max_turns=3)
    )]
    c1 = [a.id for a in CrescendoAttacker().generate(
        dp, AttackBudget(seed=1, max_queries=3, max_turns=3)
    )]
    # different seeds must not share any id (else transfer/kappa silently halve the data)
    assert set(c0).isdisjoint(c1)


def test_trails_carry_risk_category(tmp_path: Path):
    corpus = [row for row in synth_corpus(8) if "tool" not in row.modalities]
    runner = Runner(ReplayAttacker(), MockTarget(), JudgeCascade([_MockAwareConfidentJudge()]),
                    AttackBudget(), seeds=[0])
    runner.run(corpus, started_at="t")
    p = tmp_path / "cell.trails.jsonl"
    runner.save_trails(p)
    rows = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    assert rows and all("risk_category" in r and "modality" in r for r in rows)
    assert {r["risk_category"] for r in rows} - {"unknown"}  # real categories present


def test_aggregate_emits_multiturn_robustness():
    corpus = [row for row in synth_corpus(8) if "tool" not in row.modalities]
    runner = Runner(CrescendoAttacker(), MockTarget(), JudgeCascade([_MockAwareConfidentJudge()]),
                    AttackBudget(max_queries=4, max_turns=4), seeds=[0])
    judgments, _ = runner.run(corpus, started_at="t")
    metrics = {
        result.metric
        for result in runner.aggregate(
            judgments, group_keys=["model", "effective_modality"]
        )
    }
    assert "robust_refusal_rate" in metrics  # V.2.4 / RQ4 is now producible
