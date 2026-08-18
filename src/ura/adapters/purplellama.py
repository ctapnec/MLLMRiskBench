"""Source-bound PurpleLlama/CyberSecEval identity adapter.

Meta's official PurpleLlama repository provides the CyberSecEval datasets and a
native benchmark runner.  This adapter does one narrower, auditable job: it
replays a DataPoint already normalized by ``CyberSecEvalConverter`` under the
``purplellama`` adapter identity.  It accepts no unrelated corpus row, generates
no new attack, calls no source model, and does not claim to run the official
response/judge/stat pipeline.

The authored dialog is copied without changing its roles, text, tool fields, or
per-turn media.  Every top-level MediaRef must already be represented in that
dialog, which prevents a malformed conversion from dropping a visual prompt
while still appearing as a PurpleLlama attempt.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable

from ..attacker_input_contract import (
    AttackerInputContract,
    identity_replay_contract,
)
from ..data_models import Attempt, DataPoint, MediaRef
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
)
from .base import AttackBudget, BaseAttacker


def _media_key(media: MediaRef) -> str:
    return json.dumps(
        media.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


class PurpleLlamaAttacker(BaseAttacker):
    """Replay only source-authentic CyberSecEval inputs under their native name."""

    name = "purplellama"

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        if datapoint.source != "cyberseceval":
            raise ExternalEngineConformanceError(
                "PurpleLlama input planning accepts only CyberSecEval DataPoints"
            )
        return identity_replay_contract(self.name, datapoint, budget)

    def generate(
        self,
        datapoint: DataPoint,
        budget: AttackBudget,
    ) -> Iterable[Attempt]:
        if datapoint.source != "cyberseceval":
            raise ExternalEngineConformanceError(
                "PurpleLlama identity replay accepts only "
                "DataPoint.source=='cyberseceval'; arbitrary rows would destroy "
                "source identity"
            )
        if not datapoint.dialog_history:
            raise ExternalEngineOutputError(
                "CyberSecEval DataPoint has no authored dialog to preserve"
            )

        rendered = [turn.model_copy(deep=True) for turn in datapoint.dialog_history]
        original_dump = [
            turn.model_dump(mode="json") for turn in datapoint.dialog_history
        ]
        if [turn.model_dump(mode="json") for turn in rendered] != original_dump:
            raise ExternalEngineOutputError(
                "PurpleLlama identity copy changed the authored CyberSecEval dialog"
            )

        dialog_media = Counter(
            _media_key(media) for turn in datapoint.dialog_history for media in turn.media
        )
        top_level_media = Counter(_media_key(media) for media in datapoint.media)
        missing = top_level_media - dialog_media
        if missing:
            raise ExternalEngineOutputError(
                "CyberSecEval DataPoint contains top-level MediaRefs that are absent "
                "from its authored dialog; refusing lossy PurpleLlama replay"
            )

        dataset = datapoint.meta.get("dataset")
        yield Attempt(
            id=f"{datapoint.id}::purplellama::s{budget.seed}",
            datapoint_id=datapoint.id,
            attacker=self.name,
            strategy="cyberseceval-source-identity",
            turn_index=0,
            rendered_input=rendered,
            seed=budget.seed,
            params={
                "source_bound": True,
                "source": "cyberseceval",
                "source_dataset": dataset,
                "identity_replay": True,
                "attack_generated": False,
                "source_model_conditioned": False,
                "native_purplellama_runner_executed": False,
                "native_response_judge_stat_pipeline_executed": False,
                "dialog_preserved_verbatim": True,
                "dialog_turns": len(rendered),
                "dialog_media_refs": sum(
                    len(turn.media) for turn in datapoint.dialog_history
                ),
                "top_level_media_refs": len(datapoint.media),
                "max_queries": budget.max_queries,
                "max_turns": budget.max_turns,
                "citation": datapoint.meta.get("citation", "cyberseceval3-2024"),
            },
        )


__all__ = ["PurpleLlamaAttacker"]
