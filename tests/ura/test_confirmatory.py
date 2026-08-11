"""Confirmatory analysis primitives (thesis V.1.7)."""
from __future__ import annotations

import pytest

from ura.data_models import Judgment
from ura.metrics import (
    cohen_kappa_ci,
    holm_bonferroni,
    kaplan_meier_curve,
    paired_cluster_permutation_test,
    paired_effect_manski_bounds,
    power_for_paired_difference,
    power_gate,
    required_clusters_for_power,
    restricted_mean_turns_to_break,
    rmtb_with_ci,
)


def _esc(*labels: str) -> list[Judgment]:
    return [
        Judgment(
            attempt_id=f"a{i}", judge="rules", label=lbl,
            score=1.0 if lbl == "violation" else 0.0,
        )
        for i, lbl in enumerate(labels)
    ]


def test_permutation_test_reproducible_and_bounds_pvalue():
    strong = paired_cluster_permutation_test([0.4] * 12, n_permutations=2000, seed=1)
    assert strong["p_value"] < 0.01
    null = paired_cluster_permutation_test(
        [0.5, -0.5, 0.4, -0.4], n_permutations=2000, seed=1
    )
    assert null["p_value"] > 0.2
    assert paired_cluster_permutation_test(
        [0.4] * 12, n_permutations=2000, seed=1
    ) == strong
    with pytest.raises(ValueError):
        paired_cluster_permutation_test([])
    with pytest.raises(ValueError):
        paired_cluster_permutation_test([float("nan")])


def test_holm_bonferroni_stepdown():
    adj = holm_bonferroni({"a": 0.01, "b": 0.04, "c": 0.03}, alpha=0.05)
    assert adj["a"]["p_holm"] == pytest.approx(0.03)
    assert adj["c"]["p_holm"] == pytest.approx(0.06)
    assert adj["b"]["p_holm"] == pytest.approx(0.06)
    assert adj["a"]["reject"] is True
    assert adj["c"]["reject"] is False


def test_two_sided_power_includes_both_tails_and_is_monotone():
    # both tails: for a tiny effect two-sided power slightly exceeds the one-sided
    # lower tail alone and stays >= alpha.
    p_two = power_for_paired_difference(0.001, 1.0, 10, alpha=0.05, two_sided=True)
    assert p_two >= 0.05 - 1e-9
    assert required_clusters_for_power(0.05, 0.5) > required_clusters_for_power(0.10, 0.5)
    assert 0.0 <= power_for_paired_difference(0.1, 0.5, 50) <= 1.0


def test_power_gate_uses_supplied_pilot_sd():
    n_req = required_clusters_for_power(0.1, 0.5)
    assert power_gate(0.1, 0.5, n_req)["adequately_powered"] is True
    assert power_gate(0.1, 0.5, 3)["adequately_powered"] is False


def test_paired_effect_manski_bounds_bracket_matched_estimate():
    b = paired_effect_manski_bounds(
        matched_diffs=[0.5, -0.5],        # matched mean effect 0
        left_only_values=[1.0],           # left observed, right missing
        right_only_values=[0.0],          # right observed, left missing
        n_invalid=1,                      # both sides unusable
    )
    assert b["n_total"] == 5
    assert b["lower_bound"] == pytest.approx(-0.2)
    assert b["upper_bound"] == pytest.approx(0.6)
    assert b["lower_bound"] <= 0.0 <= b["upper_bound"]


def test_kaplan_meier_curve_and_rmtb_with_cluster_ci():
    curve = kaplan_meier_curve([(1, True), (2, True), (3, False)])
    assert curve[0] == (1, pytest.approx(2 / 3))
    assert curve[1] == (2, pytest.approx(1 / 3))
    escalations = {
        "c1": _esc("violation"),
        "c2": _esc("refusal", "violation"),
        "c3": _esc("refusal", "refusal", "refusal"),
    }
    clusters = {"c1": "d1", "c2": "d2", "c3": "d3"}
    assert restricted_mean_turns_to_break(escalations, 3) == pytest.approx(2.0)
    point, lo, hi = rmtb_with_ci(escalations, clusters, 3, n_resamples=500, seed=0)
    assert point == pytest.approx(2.0)
    assert lo <= point <= hi


def test_cohen_kappa_ci_perfect_agreement_and_empty():
    labels = ["violation", "refusal", "violation", "refusal"]
    result = cohen_kappa_ci(labels, labels, n_resamples=500, seed=0)
    assert result is not None
    kappa, lo, hi = result
    assert kappa == pytest.approx(1.0)
    assert lo <= 1.0 <= hi + 1e-9
    assert cohen_kappa_ci([], []) is None
