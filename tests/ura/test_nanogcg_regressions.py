from __future__ import annotations

import pytest

from ura.adapters.base import AttackBudget
from ura.adapters.nanogcg import (
    LIVE_NANOGCG_DISABLED_MESSAGE,
    NanoGCGAttacker,
    PRECOMPUTED_SURROGATE_UNSPECIFIED,
)
from ura.data_models import DataPoint, RiskCategory


def _datapoint() -> DataPoint:
    return DataPoint(
        id="nanogcg-dp",
        source="unit",
        modalities=["text"],
        payload_text="harmful request",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _budget() -> AttackBudget:
    return AttackBudget(max_queries=1, max_turns=1, seed=17)


def test_precomputed_suffix_is_explicit_replay_and_framework_not_invoked() -> None:
    attacker = NanoGCGAttacker(
        suffix=" adversarial suffix",
        suffix_source="artifact:sha256:abc",
        model_revision="0123456789abcdef",
    )
    attempt = list(attacker.generate(_datapoint(), _budget()))[0]
    assert attempt.params["attack_semantics"] == "precomputed_suffix_replay"
    assert attempt.params["suffix_source"] == "artifact:sha256:abc"
    assert attempt.params["losses"] == []
    assert attempt.params["framework_execution"] == "not_invoked"
    assert attempt.params["engine_runtime"] is None
    assert attacker.preflight()["framework_execution"] == "not_invoked"
    assert attempt.params["surrogate_model_id"] == PRECOMPUTED_SURROGATE_UNSPECIFIED
    assert attempt.params["resolved_surrogate_revision"] is None
    assert attempt.strategy.startswith("gcg:precomputed_suffix_replay:")


@pytest.mark.parametrize(
    "metadata",
    [
        {"captured_surrogate_id": "Org/Model"},
        {"captured_surrogate_revision": "0" * 40},
    ],
)
def test_captured_surrogate_identity_is_an_exact_pair(metadata: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="must be supplied together"):
        NanoGCGAttacker(suffix=" replay", **metadata)


@pytest.mark.parametrize(
    "metadata",
    [
        {"captured_source_id": "source:1"},
        {"captured_target": "non-default target"},
    ],
)
def test_captured_source_and_target_are_an_exact_pair(metadata: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="must be supplied together"):
        NanoGCGAttacker(suffix=" replay", **metadata)


def test_captured_suffix_rejects_a_different_source_row() -> None:
    attacker = NanoGCGAttacker(
        suffix=" replay",
        captured_source_id="source:1",
        captured_target="non-default target",
    )
    with pytest.raises(RuntimeError, match="source differs"):
        list(attacker.generate(_datapoint(), _budget()))


def test_live_optimization_is_unconditionally_disabled_before_runtime_use() -> None:
    class ForbiddenRuntime:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(f"managed runtime must not be touched: {name}")

    with pytest.raises(RuntimeError, match="disabled inside Runner") as raised:
        NanoGCGAttacker(
            model_revision="0" * 40,
            model_runtime=ForbiddenRuntime(),
        )
    assert str(raised.value) == LIVE_NANOGCG_DISABLED_MESSAGE


def test_precomputed_replay_rejects_model_runtime() -> None:
    with pytest.raises(ValueError, match="does not accept a model runtime"):
        NanoGCGAttacker(suffix=" replay", model_runtime=object())
