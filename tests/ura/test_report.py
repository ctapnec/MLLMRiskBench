"""Risk-card scoping and estimand-rendering regressions (report.py).

Pins that a shared results list is attributed by explicit model scope (untagged
results are not silently spread across every model), and that each safety
estimand is rendered under its own metric name with static and live estimands
kept separate, rather than collapsed to a single first-substring "attack success".
"""
from __future__ import annotations

from ura.data_models import EvalResult
from ura.report import risk_card


def _r(metric, value, *, model=None, risk="jailbreak", **prov):
    group_by = {"risk": risk}
    if model is not None:
        group_by["model"] = model
    return EvalResult(id=f"{metric}:{model}:{risk}", metric=metric, value=value,
                      n=100, group_by=group_by, provenance=prov)


def test_tagged_results_scoped_per_model():
    results = [_r("ASR", 0.10, model="A"), _r("ASR", 0.90, model="B")]
    card_a = risk_card(results, "A")
    card_b = risk_card(results, "B")
    assert "0.100" in card_a and "0.900" not in card_a
    assert "0.900" in card_b and "0.100" not in card_b


def test_untagged_not_attributed_to_every_model():
    # With a model-tagged set present, an untagged result is ambiguous and excluded.
    results = [_r("ASR", 0.10, model="A"), _r("ASR", 0.50, model=None)]
    card_a = risk_card(results, "A")
    assert "0.100" in card_a and "0.500" not in card_a
    # A model with no matching tagged result gets an empty card, not the untagged value.
    card_b = risk_card(results, "B")
    assert "0.500" not in card_b
    assert "No evaluation results" in card_b


def test_untagged_only_set_is_single_model():
    results = [_r("ASR", 0.10, model=None)]
    card = risk_card(results, "solo-model")
    assert "0.100" in card


def test_synthetic_smoke_results_are_marked_not_authoritative():
    # A synthetic (MockTarget/mock-judge) run must be visibly distinguished from a
    # measured one, both per-metric and with a run-level banner.
    card = risk_card([_r("ASR", 0.10, model="A", evidence_class="synthetic")], "A")
    assert "synthetic (offline smoke, not measured)" in card
    assert "synthetic offline-smoke results" in card
    assert "authoritative/source-native" not in card


def test_measured_results_stay_authoritative_source_native():
    card = risk_card([_r("ASR", 0.10, model="A", evidence_class="measured")], "A")
    assert "authoritative/source-native" in card
    assert "synthetic (offline smoke" not in card


def test_static_and_live_estimands_rendered_distinctly():
    results = [
        _r("ASR", 0.10, model="A", population="harmful_static"),
        _r("conversation_ASR", 0.40, model="A", population="harmful_response_conditioned"),
        _r("over_refusal_rate", 0.05, model="A"),
    ]
    card = risk_card(results, "A")
    assert "Safety (static, single-turn)" in card and "ASR `0.100`" in card
    assert "Safety (live, multi-turn)" in card and "conversation_ASR `0.400`" in card
    assert "Utility (over-refusal)" in card
    # The old collapse to a single generic "attack success" label is gone.
    assert "attack success" not in card
