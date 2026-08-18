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
from importlib import metadata

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint
from ._engine_common import ExternalEngineOutputError, _attempt, _require
from .base import AttackBudget, BaseAttacker


DEEPTEAM_VERSION = "1.0.7"
DEEPTEAM_REPOSITORY = "https://github.com/confident-ai/deepteam"
DEEPTEAM_DETERMINISTIC_ATTACKS = {"Base64", "Leetspeak", "ROT13"}


def _installed_deepteam_version() -> str:
    try:
        return metadata.version("deepteam")
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError(
            "DeepTeam is required; install the audited pin "
            f"`deepteam=={DEEPTEAM_VERSION}`"
        ) from exc


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

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        if not seed.strip():
            raise ExternalEngineOutputError("DeepTeam enhancement seed must not be blank")
        prompt = self._enhance(seed)
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
            },
        )

    def _enhance(self, seed: str) -> str:
        observed_version = _installed_deepteam_version()
        if observed_version != self.upstream_version:
            raise ExternalEngineOutputError(
                "DeepTeam package version mismatch: "
                f"expected {self.upstream_version}, observed {observed_version}"
            )
        module = _require(
            "deepteam.attacks.single_turn",
            "DeepTeamAttacker",
            f"deepteam=={self.upstream_version}",
        )
        attack_cls = getattr(module, self.attack, None)
        if not isinstance(attack_cls, type):
            raise ExternalEngineOutputError(
                f"DeepTeam {self.upstream_version} does not export {self.attack}"
            )
        enhanced = attack_cls().enhance(seed)
        if not isinstance(enhanced, str) or not enhanced.strip():
            raise ExternalEngineOutputError(
                f"DeepTeam {self.attack} returned no nonblank enhanced prompt"
            )
        if enhanced == seed:
            raise ExternalEngineOutputError(
                f"DeepTeam {self.attack} left the input unchanged"
            )
        return enhanced


__all__ = [
    "DEEPTEAM_DETERMINISTIC_ATTACKS",
    "DEEPTEAM_REPOSITORY",
    "DEEPTEAM_VERSION",
    "DeepTeamAttacker",
]
