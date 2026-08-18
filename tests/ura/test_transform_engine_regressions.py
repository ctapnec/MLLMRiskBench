"""Exact bridge-contract regressions for standalone transformation engines."""

from __future__ import annotations

import pytest

from ura.adapters._engine_common import ExternalEngineOutputError
from ura.adapters._engine_runtime import EngineExecution
from ura.adapters.base import AttackBudget
from ura.adapters.deepteam import DeepTeamAttacker
from ura.adapters.pyrit import PyRITAttacker
from ura.data_models import DataPoint, DialogTurn, RiskCategory


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


class _Runtime:
    admitted = True

    def __init__(self, engine: str, result: object) -> None:
        self.engine = engine
        self.result = result
        self.calls: list[tuple[str, object]] = []

    def public_descriptor(self) -> dict:
        return {"schema": "test-runtime/1", "status": "verified"}

    def execute(self, operation: str, payload: object, **_kwargs: object) -> EngineExecution:
        self.calls.append((operation, payload))
        return EngineExecution(
            result=self.result,
            artifacts={},
            request_sha256="a" * 64,
            runtime=self.public_descriptor(),
        )


def test_pyrit_uses_fixed_isolated_converter_operation() -> None:
    runtime = _Runtime("pyrit", {"text": "encoded::harmful objective"})
    attempt = list(
        PyRITAttacker(engine_runtime=runtime).generate(_datapoint(), _budget())
    )[0]
    assert runtime.calls == [(
        "pyrit.convert",
        {"converters": ["Base64Converter"], "seed": "harmful objective"},
    )]
    assert attempt.rendered_input[-1].content == "encoded::harmful objective"
    assert attempt.params["pyrit_version"] == "0.14.0"
    assert attempt.params["full_pyrit_scenario_executed"] is False
    assert attempt.params["engine_request_sha256"] == "a" * 64


def test_transformed_attack_replaces_source_request_instead_of_appending_it() -> None:
    point = _datapoint()
    point.dialog_history = [
        DialogTurn(role="system", content="Retain this conditioning."),
        DialogTurn(role="user", content="harmful objective"),
    ]
    runtime = _Runtime("pyrit", {"text": "encoded::harmful objective"})
    attempt = list(
        PyRITAttacker(engine_runtime=runtime).generate(point, _budget())
    )[0]
    assert [turn.role for turn in attempt.rendered_input] == ["system", "user"]
    assert attempt.rendered_input[0].content == "Retain this conditioning."
    assert attempt.rendered_input[-1].content == "encoded::harmful objective"
    assert all(turn.content != "harmful objective" for turn in attempt.rendered_input)


@pytest.mark.parametrize("result", [
    {"text": "harmful objective"},
    {"text": 123},
    {"unexpected": "value"},
])
def test_pyrit_fails_closed_on_invalid_bridge_result(result: object) -> None:
    with pytest.raises(ExternalEngineOutputError):
        list(
            PyRITAttacker(engine_runtime=_Runtime("pyrit", result)).generate(
                _datapoint(), _budget()
            )
        )


def test_pyrit_requires_an_admitted_explicit_runtime_at_execution() -> None:
    with pytest.raises(RuntimeError, match="explicit virtual environment"):
        list(PyRITAttacker().generate(_datapoint(), _budget()))


def test_pyrit_rejects_dynamic_or_duplicate_converter_names() -> None:
    with pytest.raises(ValueError, match="audited deterministic registry"):
        PyRITAttacker(converters=["LLMGenericTextConverter"])
    with pytest.raises(ValueError, match="duplicates"):
        PyRITAttacker(converters=["ROT13Converter", "ROT13Converter"])


def test_deepteam_uses_fixed_isolated_enhancement_operation() -> None:
    runtime = _Runtime("deepteam", {"text": "deepteam::harmful objective"})
    attempt = list(
        DeepTeamAttacker(engine_runtime=runtime).generate(_datapoint(), _budget())
    )[0]
    assert runtime.calls == [(
        "deepteam.enhance",
        {"attack": "Base64", "seed": "harmful objective"},
    )]
    assert attempt.rendered_input[-1].content == "deepteam::harmful objective"
    assert attempt.params["deepteam_version"] == "1.0.7"
    assert attempt.params["full_deepteam_red_team_executed"] is False
    assert attempt.params["deepteam_native_metric_executed"] is False


def test_deepteam_rejects_llm_conditioned_attack_in_runner() -> None:
    with pytest.raises(ValueError, match="deterministic standalone"):
        DeepTeamAttacker(attack="PromptInjection")


@pytest.mark.parametrize("result", [
    {"text": "harmful objective"},
    {"text": "   "},
    {"unexpected": "value"},
])
def test_deepteam_fails_closed_on_invalid_bridge_result(result: object) -> None:
    with pytest.raises(ExternalEngineOutputError):
        list(
            DeepTeamAttacker(
                engine_runtime=_Runtime("deepteam", result)
            ).generate(_datapoint(), _budget())
        )
