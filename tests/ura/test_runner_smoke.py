"""End-to-end offline smoke test: corpus -> attacker -> MockTarget -> judge -> metrics -> report."""
from __future__ import annotations

import json
from pathlib import Path

from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.converters import synth_corpus
from ura.data_models import EvalResult, RunManifest
from ura.judges.base import JudgeCascade
from ura.judges.llm import LLMJudge
from ura.judges.rules import RuleJudge
from ura.report import risk_card
from ura.runner import Runner
from ura.targets.api import MockTarget
from ura.targets.base import REGISTRY


def _runner():
    target = REGISTRY.create("mock")
    cascade = JudgeCascade([RuleJudge(), LLMJudge(judge_target=MockTarget())])
    return Runner(
        attacker=ReplayAttacker(),
        target=target,
        judge_cascade=cascade,
        budget=AttackBudget(max_turns=1, seed=0),
        seeds=[0],
    )


def test_end_to_end_run_and_report(tmp_path: Path):
    corpus = synth_corpus(12)
    runner = _runner()

    judgments, manifest = runner.run(corpus, started_at="2026-08-09T00:00:00Z")
    assert judgments, "run produced no judgments"
    assert all(0.0 <= j.score <= 1.0 for j in judgments)
    assert isinstance(manifest, RunManifest)
    assert manifest.run_id and "mock" in manifest.models
    assert manifest.adapters and manifest.judges

    # aggregation into EvalResults with CIs
    results = runner.aggregate(judgments, group_keys=["risk"])
    assert results and all(isinstance(r, EvalResult) for r in results)
    asr = [r for r in results if r.metric.upper() == "ASR"]
    assert asr, "no ASR metric produced"
    for r in asr:
        assert 0.0 <= r.value <= 1.0
        if r.ci_low is not None and r.ci_high is not None:
            assert r.ci_low <= r.value <= r.ci_high

    # persistence: JSONL always
    out = tmp_path / "results.jsonl"
    runner.save_results(judgments, out)
    assert out.exists()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(judgments)
    json.loads(lines[0])  # valid JSON

    # reporting
    card = risk_card(results, "mock")
    assert isinstance(card, str) and "mock" in card and len(card) > 50


def test_run_is_deterministic():
    corpus = synth_corpus(8)
    j1, _ = _runner().run(corpus, started_at="t")
    j2, _ = _runner().run(corpus, started_at="t")
    assert [(j.attempt_id, j.label) for j in j1] == [(j.attempt_id, j.label) for j in j2]
