"""Exact-contract regressions for standalone transformation engines."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import ura.adapters.deepteam as deepteam_module
import ura.adapters.pyrit as pyrit_module
from ura.adapters._engine_common import ExternalEngineOutputError
from ura.adapters.base import AttackBudget
from ura.adapters.deepteam import DeepTeamAttacker
from ura.adapters.pyrit import PyRITAttacker
from ura.data_models import DataPoint, RiskCategory


def _datapoint(text: str = "harmful objective") -> DataPoint:
    return DataPoint(
        id="transform:1",
        source="unit",
        modalities=["text"],
        payload_text=text,
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _budget() -> AttackBudget:
    return AttackBudget(max_queries=1, max_turns=1, seed=7)


class _Result:
    def __init__(self, output_text: str, output_type: str = "text") -> None:
        self.output_text = output_text
        self.output_type = output_type


class _PyRITBase64:
    async def convert_async(self, *, prompt: str, input_type: str) -> _Result:
        assert input_type == "text"
        return _Result("encoded::" + prompt)


def test_pyrit_uses_pinned_async_converter_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pyrit_module, "_installed_pyrit_version", lambda: "0.14.0")
    monkeypatch.setattr(
        pyrit_module,
        "_require",
        lambda *_args, **_kwargs: SimpleNamespace(Base64Converter=_PyRITBase64),
    )

    attempt = list(PyRITAttacker().generate(_datapoint(), _budget()))[0]
    assert attempt.rendered_input[-1].content == "encoded::harmful objective"
    assert attempt.params["pyrit_version"] == "0.14.0"
    assert attempt.params["full_pyrit_scenario_executed"] is False
    assert attempt.params["source_model_conditioned"] is False


@pytest.mark.parametrize("failure", ["version", "identity", "modality"])
def test_pyrit_fails_closed_on_drift_or_non_treatment(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    observed_version = "0.13.0" if failure == "version" else "0.14.0"
    monkeypatch.setattr(
        pyrit_module, "_installed_pyrit_version", lambda: observed_version
    )

    class Converter:
        async def convert_async(self, *, prompt: str, input_type: str) -> _Result:
            if failure == "identity":
                return _Result(prompt)
            return _Result("bytes", "image_path")

    monkeypatch.setattr(
        pyrit_module,
        "_require",
        lambda *_args, **_kwargs: SimpleNamespace(Base64Converter=Converter),
    )
    with pytest.raises(ExternalEngineOutputError):
        list(PyRITAttacker().generate(_datapoint(), _budget()))


def test_pyrit_rejects_dynamic_or_duplicate_converter_names() -> None:
    with pytest.raises(ValueError, match="audited deterministic registry"):
        PyRITAttacker(converters=["LLMGenericTextConverter"])
    with pytest.raises(ValueError, match="duplicates"):
        PyRITAttacker(converters=["ROT13Converter", "ROT13Converter"])


class _DeepTeamBase64:
    def enhance(self, attack: str) -> str:
        return "deepteam::" + attack


def test_deepteam_uses_pinned_deterministic_enhancement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        deepteam_module, "_installed_deepteam_version", lambda: "1.0.7"
    )
    monkeypatch.setattr(
        deepteam_module,
        "_require",
        lambda *_args, **_kwargs: SimpleNamespace(Base64=_DeepTeamBase64),
    )
    attempt = list(DeepTeamAttacker().generate(_datapoint(), _budget()))[0]
    assert attempt.rendered_input[-1].content == "deepteam::harmful objective"
    assert attempt.params["deepteam_version"] == "1.0.7"
    assert attempt.params["full_deepteam_red_team_executed"] is False
    assert attempt.params["deepteam_native_metric_executed"] is False


def test_deepteam_rejects_llm_conditioned_attack_in_runner() -> None:
    with pytest.raises(ValueError, match="deterministic standalone"):
        DeepTeamAttacker(attack="PromptInjection")


@pytest.mark.parametrize("failure", ["version", "identity", "blank"])
def test_deepteam_fails_closed_on_drift_or_non_treatment(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    observed_version = "1.0.6" if failure == "version" else "1.0.7"
    monkeypatch.setattr(
        deepteam_module, "_installed_deepteam_version", lambda: observed_version
    )

    class Attack:
        def enhance(self, seed: str) -> str:
            if failure == "identity":
                return seed
            return "   "

    monkeypatch.setattr(
        deepteam_module,
        "_require",
        lambda *_args, **_kwargs: SimpleNamespace(Base64=Attack),
    )
    with pytest.raises(ExternalEngineOutputError):
        list(DeepTeamAttacker().generate(_datapoint(), _budget()))
