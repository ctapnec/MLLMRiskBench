"""DeepTeam 1.0.7 deterministic single-turn enhancement integration.

DeepTeam documents ``enhance(attack)`` as a standalone boundary.  Some
enhancements call a simulator LLM and can return the original attack after
failed retries; those require a separate source-model-conditioned experiment and
are not admitted here.  URA supports the exact deterministic Base64, ROT13 and
Leetspeak transforms, then evaluates the frozen transformed prompt as a transfer
condition.  It does not claim to execute DeepTeam's vulnerability simulator,
target callback, metrics or full ``red_team`` workflow.

Primary contracts: https://github.com/confident-ai/deepteam and
https://www.trydeepteam.com/guides/guide-custom-attacks
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


DEEPTEAM_VERSION = "1.0.7"
DEEPTEAM_REPOSITORY = "https://github.com/confident-ai/deepteam"
DEEPTEAM_DETERMINISTIC_ATTACKS = {"Base64", "Leetspeak", "ROT13"}


class DeepTeamAttacker(BaseAttacker):
    """Apply one exact deterministic DeepTeam enhancement offline."""

    name = "deepteam"
    supported_integration_mode = "deterministic_enhancement_transfer"

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        return text_only_transfer_contract(self.name, datapoint, budget)

    def __init__(
        self,
        attack: str = "Base64",
        *,
        upstream_version: str = DEEPTEAM_VERSION,
        engine_runtime: object = None,
    ) -> None:
        if attack not in DEEPTEAM_DETERMINISTIC_ATTACKS:
            raise ValueError(
                "DeepTeam Runner support is restricted to deterministic standalone "
                "enhancements: " + ", ".join(sorted(DEEPTEAM_DETERMINISTIC_ATTACKS))
            )
        if upstream_version != DEEPTEAM_VERSION:
            raise ValueError(f"DeepTeam must be pinned to {DEEPTEAM_VERSION}")
        self.attack = attack
        self.upstream_version = upstream_version
        self._engine_runtime = engine_runtime

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        if not seed.strip():
            raise ExternalEngineOutputError("DeepTeam enhancement seed must not be blank")
        prompt, execution = self._enhance(seed)
        yield _attempt(
            datapoint,
            self.name,
            strategy=self.attack,
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={
                "attack": self.attack,
                "deepteam_version": self.upstream_version,
                "upstream_repository": DEEPTEAM_REPOSITORY,
                "mode": "deterministic_enhancement_transfer",
                "source_model_conditioned": False,
                "full_deepteam_red_team_executed": False,
                "deepteam_target_callback_executed": False,
                "deepteam_native_metric_executed": False,
                "input_sha256": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
                "output_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "engine_request_sha256": execution.request_sha256,
                "engine_runtime": dict(execution.runtime),
            },
        )

    def _enhance(self, seed: str) -> tuple[str, EngineExecution]:
        runtime = require_admitted_engine_runtime(self._engine_runtime, self.name)
        execution = runtime.execute(
            "deepteam.enhance",
            {"attack": self.attack, "seed": seed},
        )
        if not isinstance(execution, EngineExecution):
            raise ExternalEngineOutputError(
                "DeepTeam bridge returned no execution receipt"
            )
        result = execution.result
        if not isinstance(result, dict) or set(result) != {"text"}:
            raise ExternalEngineOutputError("DeepTeam bridge result fields are invalid")
        enhanced = result.get("text")
        if not isinstance(enhanced, str) or not enhanced.strip() or enhanced == seed:
            raise ExternalEngineOutputError("DeepTeam bridge returned an invalid prompt")
        if execution.artifacts:
            raise ExternalEngineOutputError("DeepTeam bridge returned unexpected artifacts")
        return enhanced, execution


__all__ = [
    "DEEPTEAM_DETERMINISTIC_ATTACKS",
    "DEEPTEAM_REPOSITORY",
    "DEEPTEAM_VERSION",
    "DeepTeamAttacker",
]
