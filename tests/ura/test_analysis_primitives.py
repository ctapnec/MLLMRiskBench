"""Paired, survival, and agreement analysis primitives."""
from __future__ import annotations

import pytest

from ura.data_models import Judgment
from ura.metrics import (
    cohen_kappa_ci,
    equal_cluster_bootstrap_ci,
    equal_cluster_mean,
    holm_bonferroni,
    kaplan_meier_curve,
    paired_cluster_permutation_test,
    paired_effect_manski_bounds,
    restricted_mean_turns_to_break,
    rmtb_with_ci,
)


def _esc(*labels: str, horizon: int | None = None) -> list[Judgment]:
    challenge_horizon = len(labels) if horizon is None else horizon
    return [
        Judgment(
            attempt_id=f"a{i}", judge="rules", label=label,
            score=1.0 if label == "violation" else 0.0,
            raw={
                "policy_evaluable_turn": True,
                "policy_challenge_index": i,
                "policy_challenge_horizon": challenge_horizon,
                "turn_expected_behavior": "refuse",
            },
        )
        for i, label in enumerate(labels)
    ]


def test_equal_cluster_mean_and_bootstrap_reweight_unequal_clusters() -> None:
    # Attempt-weighted mean would be 3/5 = 0.6; equal source-cluster weighting is
    # (3/4 + 0/1) / 2 = 0.375, giving the singleton cluster equal weight.
    values = [1.0, 1.0, 1.0, 0.0, 0.0]
    clusters = ["cA", "cA", "cA", "cA", "cB"]
    assert equal_cluster_mean(values, clusters) == pytest.approx(0.375)

    # Equal-size clusters coincide with the attempt-weighted mean.
    assert equal_cluster_mean([1.0, 0.0, 1.0, 0.0], ["a", "a", "b", "b"]) == (
        pytest.approx(0.5)
    )

    lo, hi = equal_cluster_bootstrap_ci(values, clusters, seed=0)
    assert 0.0 <= lo <= 0.375 <= hi <= 1.0

    with pytest.raises(ValueError):
        equal_cluster_mean([], [])


def test_permutation_test_reproducible_and_bounds_pvalue() -> None:
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


def test_holm_bonferroni_stepdown() -> None:
    adjusted = holm_bonferroni(
        {"a": 0.01, "b": 0.04, "c": 0.03}, alpha=0.05
    )
    assert adjusted["a"]["p_holm"] == pytest.approx(0.03)
    assert adjusted["c"]["p_holm"] == pytest.approx(0.06)
    assert adjusted["b"]["p_holm"] == pytest.approx(0.06)
    assert adjusted["a"]["reject"] is True
    assert adjusted["c"]["reject"] is False


def test_paired_effect_manski_bounds_bracket_matched_estimate() -> None:
    bounds = paired_effect_manski_bounds(
        matched_diffs=[0.5, -0.5],
        left_only_values=[1.0],
        right_only_values=[0.0],
        n_invalid=1,
    )
    assert bounds["n_total"] == 5
    assert bounds["lower_bound"] == pytest.approx(-0.2)
    assert bounds["upper_bound"] == pytest.approx(0.6)
    assert bounds["lower_bound"] <= 0.0 <= bounds["upper_bound"]


def test_kaplan_meier_curve_and_rmtb_with_cluster_ci() -> None:
    curve = kaplan_meier_curve([(1, True), (2, True), (3, False)])
    assert curve[0] == (1, pytest.approx(2 / 3))
    assert curve[1] == (2, pytest.approx(1 / 3))
    escalations = {
        "c1": _esc("violation", horizon=3),
        "c2": _esc("refusal", "violation", horizon=3),
        "c3": _esc("refusal", "refusal", "refusal", horizon=3),
    }
    clusters = {"c1": "d1", "c2": "d2", "c3": "d3"}
    assert restricted_mean_turns_to_break(escalations, 3) == pytest.approx(2.0)
    point, lo, hi = rmtb_with_ci(
        escalations, clusters, 3, n_resamples=500, seed=0
    )
    assert point == pytest.approx(2.0)
    assert lo <= point <= hi


def test_cohen_kappa_ci_perfect_agreement_and_empty() -> None:
    labels = ["violation", "refusal", "violation", "refusal"]
    result = cohen_kappa_ci(labels, labels, n_resamples=500, seed=0)
    assert result is not None
    kappa, lo, hi = result
    assert kappa == pytest.approx(1.0)
    assert lo <= 1.0 <= hi + 1e-9
    assert cohen_kappa_ci([], []) is None
