"""Microsoft PyRIT 0.14 deterministic prompt-converter integration.

PyRIT is a full red-team framework, but it also documents a smaller standalone
``PromptConverter.convert_async`` boundary.  URA supports only an exact registry
of deterministic text-to-text converters through ``BaseAttacker``.  PyRIT
scenarios, targets, memory and scorers are not claimed to have run.

Primary contract: https://github.com/microsoft/PyRIT/tree/v0.14.0/pyrit/prompt_converter
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint
from ._engine_common import ExternalEngineOutputError, _attempt
from ._engine_runtime import (
    EngineExecution,
    require_admitted_engine_runtime,
)
from .base import AttackBudget, BaseAttacker


PYRIT_VERSION = "0.14.0"
PYRIT_REPOSITORY = "https://github.com/microsoft/PyRIT"
PYRIT_CONVERTERS = {
    "AtbashConverter",
    "Base64Converter",
    "ROT13Converter",
}


class PyRITAttacker(BaseAttacker):
    """Apply a pinned deterministic PyRIT converter chain to one frozen seed."""

    name = "pyrit"
    supported_integration_mode = "deterministic_converter_transfer"

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        return text_only_transfer_contract(self.name, datapoint, budget)

    def __init__(
        self,
        converters: list[str] | None = None,
        *,
        upstream_version: str = PYRIT_VERSION,
        engine_runtime: object = None,
    ) -> None:
        selected = converters or ["Base64Converter"]
        if not selected or any(name not in PYRIT_CONVERTERS for name in selected):
            raise ValueError(
                "PyRIT converters must use the audited deterministic registry: "
                + ", ".join(sorted(PYRIT_CONVERTERS))
            )
        if len(set(selected)) != len(selected):
            raise ValueError("PyRIT converter chain must not contain duplicates")
        if upstream_version != PYRIT_VERSION:
            raise ValueError(f"PyRIT must be pinned to {PYRIT_VERSION}")
        self.converters = selected
        self.upstream_version = upstream_version
        self._engine_runtime = engine_runtime

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        if not seed.strip():
            raise ExternalEngineOutputError("PyRIT converter seed must not be blank")
        prompt, execution = self._render(seed)
        yield _attempt(
            datapoint,
            self.name,
            strategy="+".join(self.converters),
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={
                "converters": self.converters,
                "pyrit_version": self.upstream_version,
                "upstream_repository": PYRIT_REPOSITORY,
                "mode": "deterministic_converter_transfer",
                "full_pyrit_scenario_executed": False,
                "pyrit_target_executed": False,
                "pyrit_scorer_executed": False,
                "source_model_conditioned": False,
                "input_sha256": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
                "output_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "engine_request_sha256": execution.request_sha256,
                "engine_runtime": dict(execution.runtime),
            },
        )

    def _render(self, seed: str) -> tuple[str, EngineExecution]:
        runtime = require_admitted_engine_runtime(self._engine_runtime, self.name)
        execution = runtime.execute(
            "pyrit.convert",
            {"converters": list(self.converters), "seed": seed},
        )
        if not isinstance(execution, EngineExecution):
            raise ExternalEngineOutputError("PyRIT bridge returned no execution receipt")
        result = execution.result
        if not isinstance(result, dict) or set(result) != {"text"}:
            raise ExternalEngineOutputError("PyRIT bridge result fields are invalid")
        text = result.get("text")
        if not isinstance(text, str) or not text.strip() or text == seed:
            raise ExternalEngineOutputError("PyRIT bridge returned an invalid prompt")
        if execution.artifacts:
            raise ExternalEngineOutputError("PyRIT bridge returned unexpected artifacts")
        return text, execution


__all__ = [
    "PYRIT_CONVERTERS",
    "PYRIT_REPOSITORY",
    "PYRIT_VERSION",
    "PyRITAttacker",
]
