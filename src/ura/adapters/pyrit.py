"""Microsoft PyRIT 0.14 deterministic prompt-converter integration.

PyRIT is a full red-team framework, but it also documents a smaller standalone
``PromptConverter.convert_async`` boundary.  URA supports only an exact registry
of deterministic text-to-text converters through ``BaseAttacker``.  PyRIT
scenarios, targets, memory and scorers are not claimed to have run.

Primary contract: https://github.com/microsoft/PyRIT/tree/v0.14.0/pyrit/prompt_converter
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Iterable
from importlib import metadata
from typing import Any

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint
from ._engine_common import ExternalEngineOutputError, _attempt, _require
from .base import AttackBudget, BaseAttacker


PYRIT_VERSION = "0.14.0"
PYRIT_REPOSITORY = "https://github.com/microsoft/PyRIT"
PYRIT_CONVERTERS = {
    "AtbashConverter",
    "Base64Converter",
    "ROT13Converter",
}


def _installed_pyrit_version() -> str:
    try:
        return metadata.version("pyrit")
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            f"PyRIT is required; install the audited pin `pyrit=={PYRIT_VERSION}`"
        ) from exc


def _run_converter(converter: Any, prompt: str) -> Any:
    """Call PyRIT's actual async converter API from the synchronous Runner path."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(converter.convert_async(prompt=prompt, input_type="text"))
    raise RuntimeError(
        "PyRIT converter replay requires a synchronous execution context; "
        "do not nest Runner.generate inside a running event loop"
    )


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

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        if not seed.strip():
            raise ExternalEngineOutputError("PyRIT converter seed must not be blank")
        prompt = self._render(seed)
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
            },
        )

    def _render(self, seed: str) -> str:
        observed_version = _installed_pyrit_version()
        if observed_version != self.upstream_version:
            raise ExternalEngineOutputError(
                "PyRIT package version mismatch: "
                f"expected {self.upstream_version}, observed {observed_version}"
            )
        module = _require(
            "pyrit.prompt_converter",
            "PyRITAttacker",
            f"pyrit=={self.upstream_version}",
        )
        text = seed
        for name in self.converters:
            converter_cls = getattr(module, name, None)
            if not isinstance(converter_cls, type):
                raise ExternalEngineOutputError(
                    f"PyRIT {self.upstream_version} does not export {name}"
                )
            converter = converter_cls()
            result = _run_converter(converter, text)
            output = getattr(result, "output_text", None)
            output_type = getattr(result, "output_type", None)
            if not isinstance(output, str) or not output.strip():
                raise ExternalEngineOutputError(
                    f"PyRIT converter {name} returned no nonblank text"
                )
            if output_type != "text":
                raise ExternalEngineOutputError(
                    f"PyRIT converter {name} returned output_type={output_type!r}, not text"
                )
            if output == text:
                raise ExternalEngineOutputError(
                    f"PyRIT converter {name} left the input unchanged"
                )
            text = output
        return text


__all__ = [
    "PYRIT_CONVERTERS",
    "PYRIT_REPOSITORY",
    "PYRIT_VERSION",
    "PyRITAttacker",
]
