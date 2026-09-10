"""Replay attacker - static-corpus adapter (thesis III.2.2).

The simplest attacker: it does not synthesize or escalate anything. It renders a
DataPoint verbatim into exactly one Attempt so that a pre-authored corpus (e.g.
converted R-Judge / MM-SafetyBench probes) can be replayed against any target.

If the DataPoint already carries a ``dialog_history`` it is used as-is; otherwise
a single ``user`` turn is assembled from ``payload_text`` / ``payload_code`` /
``media``. Fully deterministic, pure Python, no third-party dependencies.
"""
from __future__ import annotations

from collections.abc import Iterable
import copy
import hashlib
import json
from pathlib import Path

from ..attacker_input_contract import (
    AttackerInputContract,
    identity_replay_contract,
    retained_replay_contract,
)
from ..converters._common import canonical_converted_corpus_sha256
from ..data_models import Attempt, DataPoint, DialogTurn, MediaRef, ToolCall
from ..strict_json import strict_json_loads
from ._native_artifacts import read_utf8_artifact
from .base import AttackBudget, BaseAttacker


RETAINED_REPLAY_SCHEMA = "ura-retained-input-replay/1"
DISTINCT_RETAINED_REPLAY_SCHEMA = "ura-retained-input-replay/2"
COHORT_RETAINED_REPLAY_SCHEMA = "ura-retained-input-replay/3"


def retained_sha256(value: object) -> str:
    return hashlib.sha256((json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False) + "\n").encode()).hexdigest()


def retained_dialog(turns: list[dict]) -> list[DialogTurn]:
    """Reject unknown fields instead of silently dropping retained dialogue data."""
    if not isinstance(turns, list) or not turns:
        raise ValueError("retained replay requires an exact nonempty dialogue")
    for turn in turns:
        if not isinstance(turn, dict) or set(turn) - DialogTurn.model_fields.keys():
            raise ValueError("retained dialogue contains unsupported turn fields")
        for media in turn.get("media") or []:
            if not isinstance(media, dict) or set(media) - MediaRef.model_fields.keys():
                raise ValueError("retained dialogue contains unsupported media fields")
        tool = turn.get("tool_call")
        if tool is not None and (not isinstance(tool, dict) or set(tool) - ToolCall.model_fields.keys()):
            raise ValueError("retained dialogue contains unsupported tool fields")
    return [DialogTurn.model_validate(turn) for turn in turns]


def retained_dialog_sha256(turns: list[DialogTurn]) -> str:
    """Locator-independent delivery identity; roles, history and media order stay bound."""
    value = [turn.model_dump(mode="json") for turn in turns]
    for turn in value:
        for media in turn["media"]:
            if media.get("path"):
                digest = media.get("sha256")
                if not isinstance(digest, str) or len(digest) != 64:
                    raise ValueError("retained replay media lacks its content digest")
                media["path"] = "sha256:" + digest
    return retained_sha256(value)


def validate_retained_origin(origin: dict, dialog: list[DialogTurn]) -> bool:
    """Check an explicit transport replay's identity, never claim native attack execution."""
    if not isinstance(origin, dict) or set(origin) != {
        "selection", "original_attempt", "source_membership", "source_datapoint_sha256",
        "delivered_input_sha256", "plan_id", "plan_sha256",
    }:
        raise ValueError("retained replay origin fields differ")
    selected, original, source = (origin[key] for key in
                                  ("selection", "original_attempt", "source_membership"))
    identity = {key: value for key, value in selected.items()
                if key not in {"input_identity_sha256", "local_sources", "media_bindings"}}
    if (retained_sha256(identity) != selected["input_identity_sha256"]
        or retained_sha256(original) != source["attempt_sha256"]
        or retained_sha256(original["params"]) != source["attempt_params_sha256"]
        or source not in selected["local_sources"]
        or original["id"] != source["attempt_id"]
        or original["run_id"] != source["run_id"]
        or original["target"] != source["local_model"]
        or original["attacker"] != selected["framework"]
        or original["datapoint_id"] != selected["datapoint_id"]
        or original["seed"] != selected["requested_seed"]
        or original["turn_index"] != selected["turn_index"]
        or retained_sha256(original["rendered_input"]) != selected["rendered_input_sha256"]):
        raise ValueError("retained replay original Attempt identity differs")
    original_dialog = retained_dialog(original["rendered_input"])
    if (retained_dialog_sha256(original_dialog) != origin["delivered_input_sha256"]
        or retained_dialog_sha256(dialog) != origin["delivered_input_sha256"]):
        raise ValueError("retained replay delivered dialogue differs from its original input")
    evaluable = original["params"].get("policy_evaluable_turn")
    expected = original["params"].get("turn_expected_behavior")
    if (type(evaluable) is not bool
        or expected != (selected["expected_behavior"] if evaluable else "comply_safely")):
        raise ValueError("retained replay lacks exact original policy-evaluation scope")
    return evaluable


class ReplayAttacker(BaseAttacker):
    """Turn a DataPoint into exactly one Attempt, replaying it verbatim."""

    name: str = "replay"

    def __init__(self, *, replay_artifact: str | None = None,
                 replay_artifact_sha256: str | None = None,
                 retained_input_ids: list[str] | None = None) -> None:
        self._retained = None
        self._selected_entries = None
        if replay_artifact is None:
            if replay_artifact_sha256 is not None or retained_input_ids is not None:
                raise ValueError("retained replay digest/selection requires an artifact")
            return
        _path, raw, _text = read_utf8_artifact(Path(replay_artifact), max_bytes=64 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != replay_artifact_sha256:
            raise ValueError("retained replay artifact bytes differ")
        value = strict_json_loads(raw, max_nodes=4_000_000)
        if (not isinstance(value, dict) or set(value) != {
            "schema", "status", "corpus", "plan", "entries", "replay_id",
        } or value["schema"] not in {RETAINED_REPLAY_SCHEMA, DISTINCT_RETAINED_REPLAY_SCHEMA, COHORT_RETAINED_REPLAY_SCHEMA}
            or value["status"] != "no_call_materialized"
            or not isinstance(value["entries"], list) or not value["entries"]
            or value["replay_id"] != "retained-replay-" + retained_sha256({
                key: item for key, item in value.items() if key != "replay_id"})[:24]):
            raise ValueError("retained replay materialization contract differs")
        plan = value["plan"]
        plan_schema = {COHORT_RETAINED_REPLAY_SCHEMA: "ura-hosted-retained-input-plan/3",
                       DISTINCT_RETAINED_REPLAY_SCHEMA: "ura-hosted-retained-input-plan/2",
                       RETAINED_REPLAY_SCHEMA: "ura-hosted-retained-input-plan/1"}[value["schema"]]
        if (plan.get("schema") != plan_schema
            or plan.get("status") != "no_call_selection_only"
            or plan["authority"]["paid_execution_authorized"] is not False
            or plan["plan_id"] != "hosted-inputs-" + retained_sha256({
                key: item for key, item in plan.items() if key != "plan_id"})[:24]):
            raise ValueError("retained replay input selection plan differs")
        selected_entries = {entry["input_identity_sha256"]: entry for entry in plan["selected"]
                            if entry["corpus"] == value["corpus"]}
        if len(selected_entries) != len(value["entries"]):
            raise ValueError("retained replay input selection population differs")
        seen = set()
        for entry in value["entries"]:
            if set(entry) != {"origin", "rendered_input"}:
                raise ValueError("retained replay entry fields differ")
            origin = entry["origin"]
            validate_retained_origin(origin, retained_dialog(entry["rendered_input"]))
            selected = origin["selection"]
            identity = selected["input_identity_sha256"]
            if (identity in seen or selected != selected_entries.get(identity)
                or origin["plan_id"] != plan["plan_id"]
                or origin["plan_sha256"] != retained_sha256(plan)):
                raise ValueError("retained replay has duplicate inputs or mixed corpora")
            seen.add(identity)
        self._retained = value
        self._selected_entries = value["entries"]
        if retained_input_ids is not None:
            if (not isinstance(retained_input_ids, list) or not retained_input_ids
                or any(not isinstance(key, str) for key in retained_input_ids)
                or len(set(retained_input_ids)) != len(retained_input_ids)):
                raise ValueError("retained replay partition needs unique selected input IDs")
            selected = [entry for entry in value["entries"]
                        if entry["origin"]["selection"]["input_identity_sha256"] in retained_input_ids]
            if [entry["origin"]["selection"]["input_identity_sha256"] for entry in selected] != retained_input_ids:
                raise ValueError("retained replay partition differs from original selected input order")
            self._selected_entries = selected
            self.retained_input_ids = list(retained_input_ids)
        self.replay_artifact_sha256 = replay_artifact_sha256
        self.retained_replay_id = value["replay_id"]

    def retained_entries(self, datapoint: DataPoint, budget: AttackBudget) -> list[dict]:
        if self._retained is None:
            return []
        entries = [entry for entry in self._selected_entries
                   if entry["origin"]["selection"]["datapoint_id"] == datapoint.id]
        if not entries or len(entries) > min(budget.max_queries, budget.max_turns):
            raise ValueError("retained replay selection must fit exactly inside the attack budget")
        digest = canonical_converted_corpus_sha256([datapoint])
        for entry in entries:
            origin = entry["origin"]
            if (origin["source_datapoint_sha256"] != digest
                or origin["selection"]["requested_seed"] != budget.seed):
                raise ValueError("retained replay source DataPoint or seed differs")
        return entries

    def validate_measured_run(self, corpus: Iterable[DataPoint] = ()) -> None:
        if self._retained is not None:
            ids = [dp.id for dp in corpus]
            expected = {entry["origin"]["selection"]["datapoint_id"]
                        for entry in self._selected_entries}
            if len(ids) != len(set(ids)) or set(ids) != expected:
                raise ValueError("retained replay corpus does not match the exact selected inputs")

    def select_corpus(self, name: str, corpus: list[DataPoint]) -> list[DataPoint]:
        if self._retained is None or self._retained["corpus"] != name:
            raise ValueError("retained replay source arm differs")
        expected = {entry["origin"]["selection"]["datapoint_id"]
                    for entry in self._selected_entries}
        selected = [point for point in corpus if point.id in expected]
        self.validate_measured_run(selected)
        for point in selected:
            self.retained_entries(point, AttackBudget(max_queries=len(self._selected_entries),
                                                       max_turns=len(self._selected_entries), seed=0))
        return selected

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        if self._retained is not None:
            return retained_replay_contract(self.name, datapoint, budget,
                                            entries=self.retained_entries(datapoint, budget))
        return identity_replay_contract(self.name, datapoint, budget)

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        """Yield a single deterministic Attempt for ``datapoint``.

        The rendered input is the DataPoint's ``dialog_history`` when present,
        otherwise a lone ``user`` turn built from its payload fields and media.
        """
        if self._retained is not None:
            for index, entry in enumerate(self.retained_entries(datapoint, budget)):
                origin = copy.deepcopy(entry["origin"])
                identity = origin["selection"]["input_identity_sha256"]
                yield Attempt(id=f"{datapoint.id}::retained-replay::{identity}",
                              datapoint_id=datapoint.id, attacker=self.name,
                              strategy="retained_input_replay", turn_index=index,
                              rendered_input=retained_dialog(entry["rendered_input"]),
                              seed=budget.seed, params={"retained_origin": origin,
                                                       "replayed_transcript": True})
            return
        rendered = self._render(datapoint)
        yield Attempt(
            # seed is part of the id so multi-seed runs do not collide in the
            # transfer matrix / kappa trails (which key on attempt_id); the id stays
            # model-independent, so the same (datapoint, seed) still matches across models.
            id=f"{datapoint.id}::replay::s{budget.seed}",
            datapoint_id=datapoint.id,
            attacker=self.name,
            strategy="replay",
            turn_index=0,
            rendered_input=rendered,
            seed=budget.seed,
            params={"max_queries": budget.max_queries, "max_turns": budget.max_turns},
        )

    @staticmethod
    def _render(datapoint: DataPoint) -> list[DialogTurn]:
        """Build the dialog to send: existing history, or one synthesized turn."""
        if datapoint.dialog_history:
            # Replay the authored conversation unchanged.
            return list(datapoint.dialog_history)

        # Assemble a single user turn from the payload fields.
        parts: list[str] = []
        if datapoint.payload_text:
            parts.append(datapoint.payload_text)
        if datapoint.payload_code:
            parts.append(datapoint.payload_code)
        content = "\n\n".join(parts) if parts else None

        return [
            DialogTurn(
                role="user",
                content=content,
                media=list(datapoint.media),
            )
        ]


__all__ = ["ReplayAttacker"]
