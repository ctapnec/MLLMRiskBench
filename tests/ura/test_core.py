"""Unit tests for the URA-Bench stable core (schema, metrics, taxonomy).

Runs offline with only pydantic + stdlib. Plugin/integration tests live in
test_plugins.py and test_runner_smoke.py.
"""
from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from ura.data_models import (
    DataPoint, DialogTurn, EvalResult, Judgment, MediaRef,
    RiskCategory, RunManifest, SCHEMA_VERSION,
)
from ura import metrics
from ura import taxonomy


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

def test_datapoint_minimal_valid():
    dp = DataPoint(id="d1", source="unit", modalities=["text"],
                   risk_category=RiskCategory.JAILBREAK, expected_behavior="refuse")
    assert dp.schema_version == SCHEMA_VERSION
    assert dp.turns == 1 and dp.is_agentic is False


def test_datapoint_rejects_empty_modalities():
    with pytest.raises(ValidationError):
        DataPoint(id="d", source="u", modalities=[],
                  risk_category=RiskCategory.TOXICITY, expected_behavior="refuse")


def test_mediaref_rejects_text_modality():
    with pytest.raises(ValidationError):
        MediaRef(modality="text", uri="http://x/y.png")
    with pytest.raises(ValidationError, match="physical image, audio, or video"):
        MediaRef(modality="tool", uri="data:application/json;base64,e30=")
    with pytest.raises(ValidationError, match="physical image, audio, or video"):
        MediaRef(modality="multi", uri="data:application/octet-stream;base64,AA==")
    ok = MediaRef(modality="image", path="a.png", sha256="deadbeef")
    assert ok.modality == "image"


def test_judgment_score_bounds():
    Judgment(attempt_id="a", judge="rules", label="violation", score=1.0)
    with pytest.raises(ValidationError):
        Judgment(attempt_id="a", judge="rules", label="violation", score=1.5)


def test_multiturn_agentic_datapoint_roundtrips():
    dp = DataPoint(
        id="a1", source="agentharm", modalities=["text", "tool"], is_agentic=True, turns=2,
        dialog_history=[
            DialogTurn(role="user", content="do X"),
            DialogTurn(role="assistant", content="calling tool",
                       tool_call={"name": "shell", "arguments": {"cmd": "ls"}}),
        ],
        risk_category=RiskCategory.AGENTIC_MISUSE, expected_behavior="refuse",
    )
    restored = DataPoint.model_validate_json(dp.model_dump_json())
    assert restored.is_agentic and restored.dialog_history[1].tool_call.name == "shell"


# --------------------------------------------------------------------------- #
# Taxonomy
# --------------------------------------------------------------------------- #

def test_every_category_maps_to_some_standard():
    # Every non-umbrella category carries at least one conservative category-level
    # standard reference; umbrella categories (e.g. CATASTROPHIC) attach the
    # specific hazard per DataPoint instead, so their category default is empty.
    for cat in RiskCategory:
        if cat in taxonomy.UMBRELLA_CATEGORIES:
            assert not taxonomy.refs_for(cat), f"{cat} umbrella must not force a hazard"
            continue
        assert taxonomy.refs_for(cat), f"{cat} has no category-level standard reference"


def test_refs_for_privacy():
    refs = taxonomy.refs_for(RiskCategory.PRIVACY)
    assert "OWASP_LLM:LLM02" in refs and "MLCOMMONS:Privacy" in refs


def test_agentic_defaults_do_not_overclaim_goal_hijack_or_tool_misuse():
    refs = taxonomy.refs_for(RiskCategory.AGENTIC_MISUSE)
    assert "OWASP_ASI:ASI01" not in refs
    assert "OWASP_ASI:ASI02" not in refs
    assert "NIST_GENAI:Human-AI Configuration" in refs


def test_eu_systemic_risks_present():
    assert "loss of control" in taxonomy.EU_AI_ACT_SYSTEMIC_RISKS


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def _judgments(labels):
    return [
        Judgment(
            attempt_id=str(i),
            judge="j",
            label=lbl,
            score=0.8,
            raw={
                "policy_evaluable_turn": True,
                "policy_challenge_index": i,
                "policy_challenge_horizon": len(labels),
                "turn_expected_behavior": "refuse",
            },
        )
        for i, lbl in enumerate(labels)
    ]


def test_asr_and_dsr_complement():
    js = _judgments(["violation", "safe", "safe", "violation"])
    assert metrics.attack_success_rate(js) == 0.5
    assert metrics.defense_success_rate(js) == 0.5


def test_over_refusal_rate():
    js = _judgments(["over_refusal", "safe", "over_refusal", "refusal"])
    assert metrics.over_refusal_rate(js) == 0.5
    assert metrics.refusal_rate(js) == 0.25


def test_cohen_kappa_perfect_and_chance():
    assert metrics.cohen_kappa(["a", "b", "a"], ["a", "b", "a"]) == 1.0
    k = metrics.cohen_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"])
    assert -1.0 <= k <= 1.0 and abs(k) < 1e-9  # exactly chance


def test_bootstrap_ci_is_deterministic_and_brackets_mean():
    vals = [0.0, 1.0, 1.0, 0.0, 1.0]
    lo1, hi1 = metrics.bootstrap_ci(vals, seed=7)
    lo2, hi2 = metrics.bootstrap_ci(vals, seed=7)
    assert (lo1, hi1) == (lo2, hi2)           # reproducible
    assert lo1 <= (sum(vals) / len(vals)) <= hi1


def test_robust_refusal_and_turns_to_break():
    esc = {
        "c1": _judgments(["safe", "violation"]),      # broke at turn 2
        "c2": _judgments(["refusal"]),                # fully resisted
        "c3": _judgments(["safe", "safe"]),           # fully resisted
    }
    assert metrics.robust_refusal_rate(esc) == pytest.approx(2 / 3)
    assert metrics.turns_to_break(esc["c1"]) == 2
    assert metrics.turns_to_break(esc["c2"]) is None
    assert metrics.median_turns_to_break(esc) == 2.0


def test_transferability():
    src = {"a1", "a2", "a3"}
    tgt = {
        "a1": Judgment(attempt_id="a1", judge="j", label="violation", score=0.9),
        "a2": Judgment(attempt_id="a2", judge="j", label="safe", score=0.1),
        "a3": Judgment(attempt_id="a3", judge="j", label="violation", score=0.9),
    }
    assert metrics.transferability(src, tgt) == pytest.approx(2 / 3)


def test_eval_result_and_manifest_construct():
    r = EvalResult(id="r1", metric="ASR", value=0.42, ci_low=0.3, ci_high=0.55, n=100,
                   group_by={"model": "mock", "risk": "jailbreak"})
    assert 0 <= r.value <= 1 and r.ci_low <= r.value <= r.ci_high
    m = RunManifest(run_id="run-1", code_version="1.0", seeds=[0, 1], models=["mock"])
    assert m.schema_version == SCHEMA_VERSION and math.isclose(len(m.seeds), 2)
