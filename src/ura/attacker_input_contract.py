"""Prospective attacker input contracts for Runner admission.

An attack adapter can change the request that ultimately reaches a target.  A
source-only modality declaration is therefore not enough to authorize target
calls: the planner needs the combinations and media identities produced by the
selected attacker, for each possible logical turn, before execution starts.

This module is deliberately independent of :mod:`ura.runner`.  Adapters can
declare their prospective inputs without constructing a target, charging a call
budget, or importing an external attack engine.  Runtime integration must
compare every realized Attempt with the corresponding turn below.
"""
from __future__ import annotations

import base64
import binascii
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal, Mapping, Protocol, Sequence

from .data_models import Attempt, DataPoint, DialogTurn, Judgment, MediaRef, Response


CONTRACT_SCHEMA = "ura-attacker-input-contract/1"
RUNNER_PLAN_SCHEMA = "ura-attacker-input-plan/1"
GRID_PLAN_SCHEMA = "ura-grid-attacker-input-plan/1"
_CHANNEL_ORDER = ("text", "image", "audio", "video", "tool")
_PHYSICAL = frozenset({"image", "audio", "video"})
_HEX = frozenset("0123456789abcdef")
_MAX_MEDIA_ASSET_BYTES = 25 * 1024 * 1024
_MAX_VIDEO_ASSET_BYTES = 64 * 1024 * 1024
_MEDIA_SIGNATURES = {
    "image/jpeg": lambda value: value.startswith(b"\xff\xd8\xff"),
    "image/png": lambda value: value.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/gif": lambda value: value.startswith((b"GIF87a", b"GIF89a")),
    "image/webp": lambda value: (
        len(value) >= 12 and value[:4] == b"RIFF" and value[8:12] == b"WEBP"
    ),
    "image/bmp": lambda value: value.startswith(b"BM"),
    "image/tiff": lambda value: value.startswith((b"II*\x00", b"MM\x00*")),
    "audio/wav": lambda value: (
        len(value) >= 12 and value[:4] == b"RIFF" and value[8:12] == b"WAVE"
    ),
    "audio/x-wav": lambda value: (
        len(value) >= 12 and value[:4] == b"RIFF" and value[8:12] == b"WAVE"
    ),
    "audio/mpeg": lambda value: (
        value.startswith(b"ID3")
        or (len(value) >= 2 and value[0] == 0xFF and value[1] & 0xE0 == 0xE0)
    ),
    "audio/flac": lambda value: value.startswith(b"fLaC"),
    "audio/ogg": lambda value: value.startswith(b"OggS"),
    "audio/mp4": lambda value: len(value) >= 12 and value[4:8] == b"ftyp",
    "audio/x-m4a": lambda value: len(value) >= 12 and value[4:8] == b"ftyp",
    "audio/aac": lambda value: (
        len(value) >= 2 and value[0] == 0xFF and value[1] & 0xF6 == 0xF0
    ),
    "video/mp4": lambda value: len(value) >= 12 and value[4:8] == b"ftyp",
    "video/quicktime": lambda value: len(value) >= 12 and value[4:8] == b"ftyp",
    "video/webm": lambda value: value.startswith(b"\x1aE\xdf\xa3"),
    "video/x-matroska": lambda value: value.startswith(b"\x1aE\xdf\xa3"),
    "video/x-msvideo": lambda value: (
        len(value) >= 12 and value[:4] == b"RIFF" and value[8:12] == b"AVI "
    ),
    "video/mpeg": lambda value: value.startswith(
        (b"\x00\x00\x01\xba", b"\x00\x00\x01\xb3")
    ),
}

InputChannel = Literal["text", "image", "audio", "video", "tool"]
MediaOrigin = Literal["source", "attacker_generated"]
TurnCountSemantics = Literal["exact", "upper_bound"]
SourceMediaPolicy = Literal["none", "all"]


class AttackerInputContractError(ValueError):
    """An attacker cannot prospectively bind the input it would deliver."""


class BudgetLike(Protocol):
    max_queries: int
    max_turns: int


def canonical_input_combination(values: Sequence[str]) -> tuple[InputChannel, ...]:
    """Return one ordered, unique target-input combination."""

    items = tuple(values)
    if not items or any(not isinstance(item, str) for item in items):
        raise AttackerInputContractError(
            "attacker input combinations must contain non-empty strings"
        )
    if len(set(items)) != len(items):
        raise AttackerInputContractError(
            "attacker input combinations must not contain duplicates"
        )
    unsupported = sorted(set(items) - set(_CHANNEL_ORDER))
    if unsupported:
        raise AttackerInputContractError(
            "attacker input combination contains unsupported channels: "
            + ",".join(unsupported)
        )
    return tuple(item for item in _CHANNEL_ORDER if item in items)  # type: ignore[return-value]


@dataclass(frozen=True)
class MediaInputIdentity:
    """Path-free content identity for one source or generated media asset."""

    origin: MediaOrigin
    modality: Literal["image", "audio", "video"]
    mime: str
    sha256: str
    bytes: int
    delivery_path: str | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if self.origin not in {"source", "attacker_generated"}:
            raise AttackerInputContractError("invalid media input origin")
        if self.modality not in _PHYSICAL:
            raise AttackerInputContractError("media input identity must be physical")
        if not self.mime.startswith(f"{self.modality}/"):
            raise AttackerInputContractError(
                "media input MIME type does not match its modality"
            )
        if len(self.sha256) != 64 or any(char not in _HEX for char in self.sha256):
            raise AttackerInputContractError(
                "media input identity requires a full lowercase SHA-256"
            )
        if isinstance(self.bytes, bool) or not isinstance(self.bytes, int) or self.bytes < 1:
            raise AttackerInputContractError(
                "media input identity requires a positive byte count"
            )

    @property
    def media_id(self) -> str:
        return f"{self.origin}:{self.modality}:sha256:{self.sha256}"

    def manifest_payload(self) -> dict[str, object]:
        return {
            "media_id": self.media_id,
            "origin": self.origin,
            "modality": self.modality,
            "mime": self.mime,
            "sha256": self.sha256,
            "bytes": self.bytes,
        }


@dataclass(frozen=True)
class PlannedTargetInput:
    """One possible logical target call under an attacker/DataPoint contract."""

    logical_turn: int
    combination: tuple[InputChannel, ...]
    policy_evaluable: bool
    media_ids: tuple[str, ...] = ()
    source_media_policy: SourceMediaPolicy = "none"
    bound_text_sha256: str | None = None
    bound_text_bytes: int | None = None

    def __post_init__(self) -> None:
        if (
            isinstance(self.logical_turn, bool)
            or not isinstance(self.logical_turn, int)
            or self.logical_turn < 0
        ):
            raise AttackerInputContractError(
                "planned target input logical_turn must be non-negative"
            )
        canonical = canonical_input_combination(self.combination)
        if canonical != self.combination:
            raise AttackerInputContractError(
                "planned target input combination is not canonical"
            )
        if not isinstance(self.policy_evaluable, bool):
            raise AttackerInputContractError(
                "planned target input requires a boolean policy_evaluable flag"
            )
        if self.source_media_policy not in {"none", "all"}:
            raise AttackerInputContractError("invalid source media policy")
        if any(not isinstance(item, str) or not item for item in self.media_ids):
            raise AttackerInputContractError(
                "planned target media ids must be non-empty strings"
            )
        if (self.bound_text_sha256 is None) != (self.bound_text_bytes is None):
            raise AttackerInputContractError(
                "planned target text identity requires both digest and byte count"
            )
        if self.bound_text_sha256 is not None and (
            len(self.bound_text_sha256) != 64
            or any(char not in _HEX for char in self.bound_text_sha256)
            or isinstance(self.bound_text_bytes, bool)
            or not isinstance(self.bound_text_bytes, int)
            or self.bound_text_bytes < 1
            or "text" not in self.combination
        ):
            raise AttackerInputContractError(
                "planned target text identity must be a full SHA-256 over positive "
                "UTF-8 bytes on a text-bearing input"
            )

    def manifest_payload(self) -> dict[str, object]:
        return {
            "logical_turn": self.logical_turn,
            "combination": list(self.combination),
            "policy_evaluable": self.policy_evaluable,
            "media_ids": list(self.media_ids),
            "source_media_policy": self.source_media_policy,
            "bound_text_sha256": self.bound_text_sha256,
            "bound_text_bytes": self.bound_text_bytes,
        }


@dataclass(frozen=True)
class AttackerInputContract:
    """Immutable prospective target-input declaration for one DataPoint."""

    attacker: str
    datapoint_id: str
    source_combination: tuple[InputChannel, ...]
    source_media: tuple[MediaInputIdentity, ...]
    source_media_occurrences: tuple[str, ...]
    generated_media: tuple[MediaInputIdentity, ...]
    turns: tuple[PlannedTargetInput, ...]
    turn_count_semantics: TurnCountSemantics
    tool_runtime_required: bool = False
    tool_runtime_identity: str | None = None
    schema: str = CONTRACT_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CONTRACT_SCHEMA:
            raise AttackerInputContractError("unsupported attacker input contract schema")
        if not self.attacker.strip() or not self.datapoint_id.strip():
            raise AttackerInputContractError(
                "attacker input contract requires attacker and DataPoint identities"
            )
        if canonical_input_combination(self.source_combination) != self.source_combination:
            raise AttackerInputContractError(
                "attacker source combination is not canonical"
            )
        if self.turn_count_semantics not in {"exact", "upper_bound"}:
            raise AttackerInputContractError("invalid turn-count semantics")
        if not self.turns:
            raise AttackerInputContractError(
                "attacker input contract must declare at least one target turn"
            )
        logical_turns = tuple(turn.logical_turn for turn in self.turns)
        if logical_turns != tuple(range(len(self.turns))):
            raise AttackerInputContractError(
                "planned target turns must be contiguous and zero-based"
            )

        media = (*self.source_media, *self.generated_media)
        by_id = {item.media_id: item for item in media}
        if len(by_id) != len(media):
            raise AttackerInputContractError(
                "attacker input contract contains duplicate media identities"
            )
        source_ids = {item.media_id for item in self.source_media}
        if (
            any(media_id not in source_ids for media_id in self.source_media_occurrences)
            or set(self.source_media_occurrences) != source_ids
        ):
            raise AttackerInputContractError(
                "source media occurrence sequence must reference every source asset"
            )
        generated_ids = {item.media_id for item in self.generated_media}
        referenced: set[str] = set()
        for turn in self.turns:
            unknown = set(turn.media_ids) - set(by_id)
            if unknown:
                raise AttackerInputContractError(
                    "planned target input references unknown media identities"
                )
            referenced.update(turn.media_ids)
            observed_physical = {
                by_id[media_id].modality for media_id in turn.media_ids
            }
            declared_physical = set(turn.combination) & _PHYSICAL
            if observed_physical != declared_physical:
                raise AttackerInputContractError(
                    "planned target input media identities do not match its combination"
                )
            carried_source = tuple(
                media_id for media_id in turn.media_ids if media_id in source_ids
            )
            expected_source = (
                self.source_media_occurrences
                if turn.source_media_policy == "all"
                else ()
            )
            if (
                turn.source_media_policy == "none"
                and carried_source
            ) or (
                turn.source_media_policy == "all"
                and (
                    not expected_source
                    or len(carried_source) % len(expected_source) != 0
                    or carried_source
                    != expected_source * (len(carried_source) // len(expected_source))
                )
            ):
                raise AttackerInputContractError(
                    "planned target input violates its source-media policy"
                )

        if generated_ids - referenced:
            raise AttackerInputContractError(
                "attacker-generated media must be bound to a planned target turn"
            )
        if source_ids and not any(
            turn.policy_evaluable
            and Counter(turn.media_ids) >= Counter(self.source_media_occurrences)
            for turn in self.turns
        ):
            raise AttackerInputContractError(
                "source physical media are absent from every evaluable target turn"
            )

        combinations = {channel for turn in self.turns for channel in turn.combination}
        if "tool" in combinations or "tool" in self.source_combination:
            if not self.tool_runtime_required or not self.tool_runtime_identity:
                raise AttackerInputContractError(
                    "tool input requires an identified executable tool runtime"
                )
        elif self.tool_runtime_required or self.tool_runtime_identity is not None:
            raise AttackerInputContractError(
                "tool runtime metadata is forbidden without a tool input channel"
            )

    def _unsigned_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "attacker": self.attacker,
            "datapoint_id": self.datapoint_id,
            "source_combination": list(self.source_combination),
            "source_media": [item.manifest_payload() for item in self.source_media],
            "source_media_occurrences": list(self.source_media_occurrences),
            "generated_media": [
                item.manifest_payload() for item in self.generated_media
            ],
            "turns": [turn.manifest_payload() for turn in self.turns],
            "turn_count_semantics": self.turn_count_semantics,
            "tool_runtime_required": self.tool_runtime_required,
            "tool_runtime_identity": self.tool_runtime_identity,
        }

    @property
    def contract_id(self) -> str:
        encoded = json.dumps(
            self._unsigned_payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return f"attacker-input-{hashlib.sha256(encoded).hexdigest()[:24]}"

    def manifest_payload(self) -> dict[str, object]:
        return {"contract_id": self.contract_id, **self._unsigned_payload()}


_MEDIA_PAYLOAD_FIELDS = frozenset({
    "media_id", "origin", "modality", "mime", "sha256", "bytes",
})
_TURN_PAYLOAD_FIELDS = frozenset({
    "logical_turn", "combination", "policy_evaluable", "media_ids",
    "source_media_policy", "bound_text_sha256", "bound_text_bytes",
})
_CONTRACT_PAYLOAD_FIELDS = frozenset({
    "contract_id", "schema", "attacker", "datapoint_id",
    "source_combination", "source_media", "source_media_occurrences",
    "generated_media", "turns", "turn_count_semantics",
    "tool_runtime_required", "tool_runtime_identity",
})

RunnerPlanKey = tuple[str, str, int]
GridPlanKey = tuple[str, str, str, int]
AttackerPlanKey = RunnerPlanKey | GridPlanKey


def attacker_input_payload_sha256(value: object) -> str:
    """Return the strict canonical digest used by attacker-plan projections."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AttackerInputContractError(
            "attacker input plan is not strict canonical JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _strict_object(
    value: object, fields: frozenset[str], label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise AttackerInputContractError(f"{label} has an invalid field inventory")
    return value


def _strict_nonblank(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise AttackerInputContractError(f"{label} must be one non-blank string")
    return value


def _strict_integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AttackerInputContractError(
            f"{label} must be an integer >= {minimum}"
        )
    return value


def _strict_string_list(
    value: object, label: str, *, allow_empty: bool,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise AttackerInputContractError(f"{label} must be a string list")
    return tuple(value)


def deserialize_attacker_input_contract(value: object) -> AttackerInputContract:
    """Strictly reconstruct and self-authenticate one persisted contract."""

    payload = _strict_object(
        value, _CONTRACT_PAYLOAD_FIELDS, "attacker input contract"
    )
    source_media_raw = payload["source_media"]
    generated_media_raw = payload["generated_media"]
    turns_raw = payload["turns"]
    if not isinstance(source_media_raw, list) or not isinstance(
        generated_media_raw, list
    ) or not isinstance(turns_raw, list) or not turns_raw:
        raise AttackerInputContractError(
            "attacker input contract media/turn inventories are invalid"
        )

    def media_identity(raw: object, expected_origin: MediaOrigin) -> MediaInputIdentity:
        item = _strict_object(raw, _MEDIA_PAYLOAD_FIELDS, "media identity")
        if item["origin"] != expected_origin:
            raise AttackerInputContractError("media identity origin is inconsistent")
        identity = MediaInputIdentity(
            origin=item["origin"],
            modality=item["modality"],
            mime=_strict_nonblank(item["mime"], "media MIME"),
            sha256=_strict_nonblank(item["sha256"], "media SHA-256"),
            bytes=_strict_integer(item["bytes"], "media bytes", minimum=1),
        )
        if item["media_id"] != identity.media_id:
            raise AttackerInputContractError("media identity ID/content mismatch")
        if item != identity.manifest_payload():
            raise AttackerInputContractError("media identity is not canonical")
        return identity

    source_media = tuple(
        media_identity(item, "source") for item in source_media_raw
    )
    generated_media = tuple(
        media_identity(item, "attacker_generated")
        for item in generated_media_raw
    )
    turns: list[PlannedTargetInput] = []
    for raw in turns_raw:
        item = _strict_object(raw, _TURN_PAYLOAD_FIELDS, "planned target input")
        if not isinstance(item["policy_evaluable"], bool):
            raise AttackerInputContractError(
                "planned target input policy_evaluable must be boolean"
            )
        bound_digest = item["bound_text_sha256"]
        bound_bytes = item["bound_text_bytes"]
        if bound_digest is not None and not isinstance(bound_digest, str):
            raise AttackerInputContractError("bound text SHA-256 type is invalid")
        if bound_bytes is not None and (
            isinstance(bound_bytes, bool) or not isinstance(bound_bytes, int)
        ):
            raise AttackerInputContractError("bound text byte-count type is invalid")
        turn = PlannedTargetInput(
            logical_turn=_strict_integer(
                item["logical_turn"], "planned logical turn"
            ),
            combination=canonical_input_combination(
                _strict_string_list(
                    item["combination"], "planned input combination",
                    allow_empty=False,
                )
            ),
            policy_evaluable=item["policy_evaluable"],
            media_ids=_strict_string_list(
                item["media_ids"], "planned media occurrences", allow_empty=True
            ),
            source_media_policy=item["source_media_policy"],
            bound_text_sha256=bound_digest,
            bound_text_bytes=bound_bytes,
        )
        if item != turn.manifest_payload():
            raise AttackerInputContractError(
                "planned target input is not canonical"
            )
        turns.append(turn)

    if not isinstance(payload["tool_runtime_required"], bool):
        raise AttackerInputContractError("tool runtime requirement must be boolean")
    if payload["schema"] != CONTRACT_SCHEMA:
        raise AttackerInputContractError(
            "unsupported attacker input contract schema"
        )
    if payload["turn_count_semantics"] not in {"exact", "upper_bound"}:
        raise AttackerInputContractError("invalid turn-count semantics")
    tool_identity = payload["tool_runtime_identity"]
    if tool_identity is not None:
        tool_identity = _strict_nonblank(tool_identity, "tool runtime identity")
    contract = AttackerInputContract(
        attacker=_strict_nonblank(payload["attacker"], "attacker identity"),
        datapoint_id=_strict_nonblank(
            payload["datapoint_id"], "datapoint identity"
        ),
        source_combination=canonical_input_combination(
            _strict_string_list(
                payload["source_combination"], "source combination",
                allow_empty=False,
            )
        ),
        source_media=source_media,
        source_media_occurrences=_strict_string_list(
            payload["source_media_occurrences"], "source media occurrences",
            allow_empty=True,
        ),
        generated_media=generated_media,
        turns=tuple(turns),
        turn_count_semantics=payload["turn_count_semantics"],
        tool_runtime_required=payload["tool_runtime_required"],
        tool_runtime_identity=tool_identity,
        schema=payload["schema"],
    )
    if payload["contract_id"] != contract.contract_id:
        raise AttackerInputContractError(
            "attacker input contract ID/content mismatch"
        )
    if payload != contract.manifest_payload():
        raise AttackerInputContractError("attacker input contract is not canonical")
    return contract


def deserialize_attacker_input_plan(
    value: object,
    *,
    expected_sha256: str | None = None,
) -> dict[AttackerPlanKey, AttackerInputContract]:
    """Strictly validate a Runner or grid plan and return canonical keyed contracts."""

    if not isinstance(value, dict):
        raise AttackerInputContractError("attacker input plan must be an object")
    schema = value.get("schema")
    if schema == RUNNER_PLAN_SCHEMA:
        plan = _strict_object(
            value, frozenset({"schema", "entries"}), "Runner attacker input plan"
        )
    elif schema == GRID_PLAN_SCHEMA:
        plan = _strict_object(
            value,
            frozenset({"schema", "entries", "sha256"}),
            "grid attacker input plan",
        )
        embedded_sha256 = plan["sha256"]
        unsigned = {"schema": schema, "entries": plan["entries"]}
        if (
            not isinstance(embedded_sha256, str)
            or embedded_sha256 != attacker_input_payload_sha256(unsigned)
        ):
            raise AttackerInputContractError(
                "grid attacker input plan SHA-256/content mismatch"
            )
    else:
        raise AttackerInputContractError("unsupported attacker input plan schema")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or expected_sha256 != attacker_input_payload_sha256(value)
    ):
        raise AttackerInputContractError(
            "attacker input plan external SHA-256/content mismatch"
        )
    entries = plan["entries"]
    if not isinstance(entries, list) or not entries:
        raise AttackerInputContractError(
            "attacker input plan requires a non-empty entry list"
        )

    contracts: dict[AttackerPlanKey, AttackerInputContract] = {}
    observed_order: list[tuple[object, ...]] = []
    for raw in entries:
        if schema == RUNNER_PLAN_SCHEMA:
            entry = _strict_object(
                raw,
                frozenset({"seed", *_CONTRACT_PAYLOAD_FIELDS}),
                "Runner attacker input plan entry",
            )
            arm = None
            selected_attacker = None
        else:
            entry = _strict_object(
                raw,
                frozenset({
                    "logical_source_arm", "selected_attacker", "seed",
                    *_CONTRACT_PAYLOAD_FIELDS,
                }),
                "grid attacker input plan entry",
            )
            arm = _strict_nonblank(
                entry["logical_source_arm"], "logical source arm"
            )
            selected_attacker = _strict_nonblank(
                entry["selected_attacker"], "selected attacker"
            )
        seed = _strict_integer(entry["seed"], "attacker input seed")
        contract_payload = {
            field: entry[field] for field in _CONTRACT_PAYLOAD_FIELDS
        }
        contract = deserialize_attacker_input_contract(contract_payload)
        if selected_attacker is not None and selected_attacker != contract.attacker:
            raise AttackerInputContractError(
                "grid selected attacker differs from its contract"
            )
        if arm is None:
            key: AttackerPlanKey = (contract.attacker, contract.datapoint_id, seed)
            order_key: tuple[object, ...] = (
                contract.datapoint_id, seed, contract.attacker
            )
        else:
            key = (arm, contract.attacker, contract.datapoint_id, seed)
            order_key = (arm, contract.attacker, contract.datapoint_id, seed)
        if key in contracts:
            raise AttackerInputContractError(
                "attacker input plan contains a duplicate contract key"
            )
        contracts[key] = contract
        observed_order.append(order_key)
    if observed_order != sorted(observed_order):
        raise AttackerInputContractError(
            "attacker input plan entries are not in canonical order"
        )
    return contracts


def grid_attacker_input_plan_payload(
    contracts: Mapping[GridPlanKey, AttackerInputContract],
) -> dict[str, object]:
    """Serialize one canonical, self-authenticating grid contract projection."""

    entries: list[dict[str, object]] = []
    for key, contract in sorted(contracts.items()):
        if not isinstance(key, tuple) or len(key) != 4:
            raise AttackerInputContractError(
                "grid attacker input contract mapping has an invalid key"
            )
        arm, attacker, datapoint_id, seed = key
        if (
            _strict_nonblank(arm, "logical source arm") != arm
            or _strict_nonblank(attacker, "selected attacker") != attacker
            or _strict_nonblank(datapoint_id, "datapoint identity") != datapoint_id
            or _strict_integer(seed, "attacker input seed") != seed
            or contract.attacker != attacker
            or contract.datapoint_id != datapoint_id
        ):
            raise AttackerInputContractError(
                "grid attacker input contract mapping identity mismatch"
            )
        entries.append({
            "logical_source_arm": arm,
            "selected_attacker": attacker,
            "seed": seed,
            **contract.manifest_payload(),
        })
    if not entries:
        raise AttackerInputContractError(
            "grid attacker input plan requires at least one contract"
        )
    unsigned: dict[str, object] = {
        "schema": GRID_PLAN_SCHEMA,
        "entries": entries,
    }
    payload = {
        **unsigned,
        "sha256": attacker_input_payload_sha256(unsigned),
    }
    deserialize_attacker_input_plan(payload)
    return payload


def _dialog_input_combination(dialog: Sequence[DialogTurn]) -> tuple[InputChannel, ...]:
    observed = {media.modality for turn in dialog for media in turn.media}
    if any(bool((turn.content or "").strip()) for turn in dialog):
        observed.add("text")
    if any(
        turn.role == "tool"
        or turn.tool_call is not None
        or turn.tool_result is not None
        for turn in dialog
    ):
        observed.add("tool")
    return canonical_input_combination(
        tuple(channel for channel in _CHANNEL_ORDER if channel in observed)
    )


def _last_user_text(dialog: Sequence[DialogTurn]) -> str | None:
    for turn in reversed(dialog):
        if turn.role == "user" and bool((turn.content or "").strip()):
            return turn.content
    return None


def target_modality_support_from_component_config(
    value: object,
) -> tuple[InputChannel, ...]:
    """Read the exact target capability projection persisted in a manifest.

    ``Runner._component_config`` snapshots ``modality_support`` before calls and
    makes it part of the run identity.  Completion and reporting must use that
    immutable declaration rather than trusting the mutable copy in a Judgment.
    """

    if not isinstance(value, dict):
        raise AttackerInputContractError(
            "target component configuration must be an object"
        )
    raw = value.get("modality_support")
    if (
        not isinstance(raw, list)
        or not raw
        or any(not isinstance(item, str) or not item for item in raw)
    ):
        raise AttackerInputContractError(
            "target component configuration lacks modality_support"
        )
    support = canonical_input_combination(raw)
    if support != tuple(raw):
        raise AttackerInputContractError(
            "target component modality_support is not canonical"
        )
    return support


def _modality_label(combination: Sequence[str]) -> str:
    for modality in ("video", "audio", "image"):
        if modality in combination:
            return modality
    if "tool" in combination:
        return "tool"
    return "text"


def _effective_modality(
    delivered: Sequence[str], target_modalities: Sequence[str], *, delivered_to_target: bool,
) -> str:
    if not delivered_to_target:
        return "none"
    supported = set(target_modalities)
    for modality in ("video", "audio", "image"):
        if modality in delivered and modality in supported:
            return modality
    if "tool" in delivered and "tool" in supported:
        return "tool"
    return "text"


def _exact_value(actual: object, expected: object) -> bool:
    """JSON equality which does not accept ``False == 0`` or ``True == 1``."""

    return type(actual) is type(expected) and actual == expected


def validate_attempts_against_attacker_input_plan(
    plan: object,
    attempts: Sequence[Attempt],
    responses: Sequence[Response],
    judgments: Sequence[Judgment],
    *,
    target_modalities: Sequence[str],
    expected_sha256: str,
    expected_count: int,
) -> dict[RunnerPlanKey, AttackerInputContract]:
    """Rejoin a realized execution exactly to its prospective input plan.

    This is the common completion/reporting trust boundary.  No individual
    artifact is authoritative by itself: the function joins every planned turn
    to exactly one Attempt, Response, and Judgment, then recomputes all policy
    and modality fields which affect the estimand.
    """

    parsed = deserialize_attacker_input_plan(
        plan, expected_sha256=expected_sha256
    )
    if any(len(key) != 3 for key in parsed):
        raise AttackerInputContractError(
            "Attempt validation requires a Runner attacker input plan"
        )
    if (
        isinstance(expected_count, bool)
        or not isinstance(expected_count, int)
        or expected_count != len(parsed)
    ):
        raise AttackerInputContractError(
            "attacker input plan contract count mismatch"
        )
    contracts = {
        key: contract for key, contract in parsed.items() if len(key) == 3
    }
    if not attempts:
        raise AttackerInputContractError(
            "completed attacker input evidence contains no Attempts"
        )
    try:
        canonical_target_modalities = canonical_input_combination(
            tuple(target_modalities)
        )
    except TypeError as exc:
        raise AttackerInputContractError(
            "target modality support must be a finite channel sequence"
        ) from exc
    if canonical_target_modalities != tuple(target_modalities):
        raise AttackerInputContractError(
            "target modality support is not canonical"
        )
    responses_by_attempt: dict[str, Response] = {}
    for response in responses:
        if response.attempt_id in responses_by_attempt:
            raise AttackerInputContractError(
                "attacker input evidence contains duplicate Responses"
            )
        responses_by_attempt[response.attempt_id] = response
    judgments_by_attempt: dict[str, Judgment] = {}
    for judgment in judgments:
        if judgment.attempt_id in judgments_by_attempt:
            raise AttackerInputContractError(
                "attacker input evidence contains duplicate Judgments"
            )
        judgments_by_attempt[judgment.attempt_id] = judgment
    attempt_id_set = {attempt.id for attempt in attempts}
    if (
        set(responses_by_attempt) != attempt_id_set
        or set(judgments_by_attempt) != attempt_id_set
    ):
        raise AttackerInputContractError(
            "attacker input evidence lacks an exact Attempt/Response/Judgment join"
        )

    grouped: dict[RunnerPlanKey, list[Attempt]] = {}
    seen_attempt_ids: set[str] = set()
    for attempt in attempts:
        if attempt.id in seen_attempt_ids:
            raise AttackerInputContractError(
                "attacker input evidence contains duplicate Attempt IDs"
            )
        seen_attempt_ids.add(attempt.id)
        if (
            isinstance(attempt.seed, bool)
            or not isinstance(attempt.seed, int)
        ):
            raise AttackerInputContractError(
                "attacker input Attempt requires an integer seed"
            )
        key = (attempt.attacker, attempt.datapoint_id, attempt.seed)
        contract = contracts.get(key)
        if contract is None:
            raise AttackerInputContractError(
                "Attempt is outside the prospective attacker input plan"
            )
        if attempt.turn_index >= len(contract.turns):
            raise AttackerInputContractError(
                "Attempt exceeds its prospective attacker input horizon"
            )
        planned = contract.turns[attempt.turn_index]
        if attempt.params.get("attacker_input_contract_id") != contract.contract_id:
            raise AttackerInputContractError(
                "Attempt attacker input contract ID mismatch"
            )
        if attempt.params.get("planned_target_input") != planned.manifest_payload():
            raise AttackerInputContractError(
                "Attempt planned target input projection mismatch"
            )
        if attempt.params.get("policy_evaluable_turn") is not planned.policy_evaluable:
            raise AttackerInputContractError(
                "Attempt policy-evaluation scope differs from its plan"
            )
        planning_combination = attempt.params.get(
            "planning_exact_modality_combination"
        )
        if planning_combination != list(contract.source_combination):
            raise AttackerInputContractError(
                "Attempt source modality combination differs from its contract"
            )
        if _dialog_input_combination(attempt.rendered_input) != planned.combination:
            raise AttackerInputContractError(
                "Attempt input combination differs from its plan"
            )
        inventory = {
            item.media_id: (item.modality, item.mime, item.sha256)
            for item in (*contract.source_media, *contract.generated_media)
        }
        expected_media = tuple(
            inventory[media_id] for media_id in planned.media_ids
        )
        actual_media = tuple(
            (media.modality, media.mime, media.sha256)
            for turn in attempt.rendered_input
            for media in turn.media
        )
        if any(
            not isinstance(mime, str) or not isinstance(digest, str)
            for _modality, mime, digest in actual_media
        ) or actual_media != expected_media:
            raise AttackerInputContractError(
                "Attempt media occurrence tuple differs from its plan"
            )
        if planned.bound_text_sha256 is not None:
            text = _last_user_text(attempt.rendered_input)
            encoded = text.encode("utf-8") if text is not None else b""
            if (
                hashlib.sha256(encoded).hexdigest()
                != planned.bound_text_sha256
                or len(encoded) != planned.bound_text_bytes
            ):
                raise AttackerInputContractError(
                    "Attempt bound adversarial text differs from its plan"
                )

        response_conditioned = attempt.params.get("response_conditioned")
        expected_response_conditioned = contract.attacker == "crescendo"
        if (
            not isinstance(response_conditioned, bool)
            or response_conditioned is not expected_response_conditioned
        ):
            raise AttackerInputContractError(
                "Attempt response-conditioned state differs from its attacker contract"
            )
        challenge_horizon = attempt.params.get("policy_challenge_horizon")
        challenge_index = attempt.params.get("policy_challenge_index")
        if expected_response_conditioned:
            evaluable_turns = tuple(
                turn.logical_turn for turn in contract.turns if turn.policy_evaluable
            )
            expected_horizon = len(evaluable_turns)
            expected_challenge_index = (
                evaluable_turns.index(planned.logical_turn)
                if planned.policy_evaluable
                else None
            )
        else:
            if not planned.policy_evaluable:
                raise AttackerInputContractError(
                    "stateless attacker contract contains a non-evaluable target turn"
                )
            expected_horizon = 1
            expected_challenge_index = 0
        if (
            not _exact_value(challenge_horizon, expected_horizon)
            or not _exact_value(challenge_index, expected_challenge_index)
        ):
            raise AttackerInputContractError(
                "Attempt challenge index/horizon differs from its planned trajectory"
            )
        expected_behavior = (
            "comply_safely"
            if not planned.policy_evaluable
            else attempt.params.get("planning_expected_behavior")
        )
        if expected_behavior not in {"refuse", "safe_answer", "comply_safely"}:
            raise AttackerInputContractError(
                "Attempt planning expected behavior is invalid"
            )
        if attempt.params.get("turn_expected_behavior") != expected_behavior:
            raise AttackerInputContractError(
                "Attempt turn behavior differs from its planning condition"
            )

        response = responses_by_attempt[attempt.id]
        judgment = judgments_by_attempt[attempt.id]
        if (
            not isinstance(attempt.run_id, str)
            or not attempt.run_id
            or not isinstance(attempt.target, str)
            or not attempt.target
            or response.run_id != attempt.run_id
            or judgment.run_id != attempt.run_id
            or response.target != attempt.target
        ):
            raise AttackerInputContractError(
                "Attempt/Response/Judgment run or target lineage mismatch"
            )
        response_lineage = {
            "run_id": attempt.run_id,
            "attack_fingerprint": attempt.params.get("attack_fingerprint"),
            "transfer_key": attempt.params.get("transfer_key"),
            "transferable": attempt.params.get("transferable"),
            "requested_seed": attempt.seed,
        }
        if any(
            not _exact_value(response.raw.get(field), expected)
            for field, expected in response_lineage.items()
        ) or not isinstance(response.raw.get("target_sampling_control"), str):
            raise AttackerInputContractError(
                "Response lineage differs from its Attempt"
            )

        delivered_combination = _dialog_input_combination(attempt.rendered_input)
        input_delivered = not (
            response.raw.get("defense") == "blocked"
            and response.raw.get("stage") == "input"
        )
        judgment_lineage: dict[str, object] = {
            "run_id": attempt.run_id,
            "datapoint_id": attempt.datapoint_id,
            "attacker": attempt.attacker,
            "seed": attempt.seed,
            "turn_index": attempt.turn_index,
            "target": attempt.target,
            "model": attempt.target,
            "attack_fingerprint": attempt.params.get("attack_fingerprint"),
            "transfer_key": attempt.params.get("transfer_key"),
            "transferable": attempt.params.get("transferable"),
            "response_conditioned": response_conditioned,
            "replayed_transcript": bool(
                attempt.params.get("replayed_transcript")
            ),
            "requested_seed": response.raw.get("requested_seed"),
            "target_sampling_control": response.raw.get(
                "target_sampling_control"
            ),
            "policy_evaluable_turn": planned.policy_evaluable,
            "policy_challenge_index": expected_challenge_index,
            "policy_challenge_horizon": expected_horizon,
            "turn_expected_behavior": expected_behavior,
            "expected_behavior": expected_behavior,
            "planning_exact_modality_combination": list(
                contract.source_combination
            ),
            "modality": _modality_label(contract.source_combination),
            "source_modality": _modality_label(contract.source_combination),
            "delivered_modality": _modality_label(delivered_combination),
            "effective_modality": _effective_modality(
                delivered_combination,
                canonical_target_modalities,
                delivered_to_target=input_delivered,
            ),
            "target_input_delivered": input_delivered,
            "target_modalities": list(canonical_target_modalities),
            "is_multimodal": bool(
                set(contract.source_combination) & _PHYSICAL
            ),
        }
        if any(
            not _exact_value(judgment.raw.get(field), expected)
            for field, expected in judgment_lineage.items()
        ):
            raise AttackerInputContractError(
                "Judgment policy/modality lineage differs from its "
                "Attempt, Response, contract, or target capabilities"
            )
        grouped.setdefault(key, []).append(attempt)

    if set(grouped) != set(contracts):
        raise AttackerInputContractError(
            "completed Attempts do not cover every attacker input contract"
        )
    for key, contract in contracts.items():
        trajectory = grouped[key]
        indices = [attempt.turn_index for attempt in trajectory]
        if indices != list(range(len(indices))) or len(indices) > len(contract.turns):
            raise AttackerInputContractError(
                "Attempt turns are not one ordered prefix of their plan"
            )
        if contract.turn_count_semantics == "upper_bound":
            continue
        if len(indices) == len(contract.turns):
            continue
        last = trajectory[-1]
        judgment = judgments_by_attempt[last.id]
        valid_terminal_prefix = (
            contract.attacker == "crescendo"
            and last.params.get("policy_evaluable_turn") is True
            and last.params.get("turn_expected_behavior") == "refuse"
            and judgment.label == "violation"
            and judgment.raw.get("cascade_confident") is True
            and judgment.raw.get("policy_evaluable_turn") is True
            and judgment.raw.get("expected_behavior") == "refuse"
            and not any(
                judgments_by_attempt[attempt.id].label == "violation"
                for attempt in trajectory[:-1]
            )
        )
        if not valid_terminal_prefix:
            raise AttackerInputContractError(
                "exact attacker input horizon ended without a content-bound "
                "Crescendo terminal violation"
            )
    return contracts


def reconcile_runner_and_grid_attacker_input_plans(
    runner_plan: object,
    grid_plan: object,
    *,
    runner_sha256: str,
    logical_source_arm: str,
    attacker: str,
) -> None:
    """Require a cell manifest plan to equal its eligibility-bound grid subset."""

    runner_contracts = deserialize_attacker_input_plan(
        runner_plan, expected_sha256=runner_sha256
    )
    grid_contracts = deserialize_attacker_input_plan(grid_plan)
    selected = {
        (grid_attacker, datapoint_id, seed): contract
        for (arm, grid_attacker, datapoint_id, seed), contract
        in grid_contracts.items()
        if arm == logical_source_arm and grid_attacker == attacker
    }
    if not selected:
        raise AttackerInputContractError(
            "eligibility attacker input plan has no matching cell subset"
        )
    if runner_contracts != selected:
        raise AttackerInputContractError(
            "Runner attacker input plan differs from its eligibility-bound subset"
        )


def _logical_limit(budget: BudgetLike) -> int:
    limit = min(budget.max_queries, budget.max_turns)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise AttackerInputContractError(
            "attacker input planning requires a positive query/turn budget"
        )
    return limit


def _ordered_subsequence(expected: Sequence[str], observed: Sequence[str]) -> bool:
    if not expected:
        return True
    cursor = iter(observed)
    return all(any(candidate == item for candidate in cursor) for item in expected)


def _tool_evidence(datapoint: DataPoint) -> bool:
    return (
        "tool" in datapoint.modalities
        or any(
            turn.role == "tool"
            or turn.tool_call is not None
            or turn.tool_result is not None
            for turn in datapoint.dialog_history
        )
    )


def is_tool_conditioned_source(datapoint: DataPoint) -> bool:
    """Public predicate: does this DataPoint carry unexecutable tool evidence?

    Callers that want to record and skip such rows explicitly (for example a
    dry-run smoke that opts into ``--exclude-tool-conditioned``) share the exact
    definition used by :func:`reject_unexecutable_tool_source`, so admission and
    exclusion can never diverge.
    """

    return _tool_evidence(datapoint)


def reject_unexecutable_tool_source(attacker: str, datapoint: DataPoint) -> None:
    """Reject tool-conditioned rows until Runner owns a typed tool runtime.

    Recorded tool fields are currently serialized as text by ordinary model
    targets.  Treating that transcript as execution would change the estimand,
    so every Runner adapter fails prospectively instead.
    """

    if _tool_evidence(datapoint):
        raise AttackerInputContractError(
            f"attacker {attacker!r} cannot execute tool-conditioned DataPoint "
            f"{datapoint.id!r}; a typed tool runtime and actual-use attestation "
            "are required before any target call"
        )


def _read_bounded_media_file(path: Path, *, max_bytes: int) -> bytes:
    """Read one regular, non-symlink file and detect concurrent replacement."""

    candidate = path.expanduser().absolute()
    if not candidate.exists():
        raise AttackerInputContractError("media input path does not exist")
    try:
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            if current.is_symlink():
                raise AttackerInputContractError(
                    "media input path must not contain symlinks"
                )
        resolved = candidate.resolve(strict=True)
        expected = resolved.stat()
        if not resolved.is_file():
            raise AttackerInputContractError(
                "media input path must name a regular file"
            )
        if expected.st_size > max_bytes:
            raise AttackerInputContractError(
                f"media input exceeds the {max_bytes}-byte limit"
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = handle.read(min(1024 * 1024, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise AttackerInputContractError(
                        f"media input exceeds the {max_bytes}-byte limit"
                    )
                chunks.append(chunk)
            after = os.fstat(handle.fileno())
    except AttackerInputContractError:
        raise
    except OSError as exc:
        raise AttackerInputContractError(
            "media input path is not stable bounded regular-file evidence"
        ) from exc
    if not (
        before.st_dev == after.st_dev == expected.st_dev
        and before.st_ino == after.st_ino == expected.st_ino
        and before.st_size == after.st_size == expected.st_size == total
        and before.st_mtime_ns == after.st_mtime_ns == expected.st_mtime_ns
    ):
        raise AttackerInputContractError("media input changed while being read")
    return b"".join(chunks)


def _media_signature_matches(payload: bytes, mime: str) -> bool:
    validator = _MEDIA_SIGNATURES.get(mime)
    return validator(payload) if validator is not None else True


def _media_bytes(ref: MediaRef) -> tuple[str, bytes]:
    mime = ref.mime
    if not isinstance(mime, str) or not mime.startswith(f"{ref.modality}/"):
        raise AttackerInputContractError(
            "media input requires a MIME type matching its modality"
        )
    limit = (
        _MAX_VIDEO_ASSET_BYTES
        if ref.modality == "video"
        else _MAX_MEDIA_ASSET_BYTES
    )
    if ref.path is not None:
        payload = _read_bounded_media_file(Path(ref.path), max_bytes=limit)
        return mime, payload

    uri = ref.uri or ""
    try:
        header, encoded = uri.split(",", 1)
        header_parts = header[5:].split(";")
        if (
            not header.startswith("data:")
            or len(header_parts) < 2
            or header_parts[0] != mime
            or header_parts[-1].lower() != "base64"
            or len(encoded) > 4 * ((limit + 2) // 3) + 4
        ):
            raise ValueError
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AttackerInputContractError(
            "media input URI must be bounded base64 data with matching MIME"
        ) from exc
    return mime, payload


def media_input_identity(
    ref: MediaRef,
    *,
    origin: MediaOrigin,
    require_declared_sha256: bool,
) -> MediaInputIdentity:
    """Validate and content-address one path/inline media reference."""

    mime, payload = _media_bytes(ref)
    if not payload:
        raise AttackerInputContractError("media input bytes must not be empty")
    if not _media_signature_matches(payload, mime):
        raise AttackerInputContractError("media input MIME/signature mismatch")
    digest = hashlib.sha256(payload).hexdigest()
    declared = ref.sha256
    if require_declared_sha256 and (
        not isinstance(declared, str)
        or len(declared) != 64
        or any(char not in _HEX for char in declared)
    ):
        raise AttackerInputContractError(
            "source media requires a full declared SHA-256 before attack planning"
        )
    if declared is not None and declared != digest:
        raise AttackerInputContractError("media input SHA-256 mismatch")
    return MediaInputIdentity(
        origin=origin,
        modality=ref.modality,  # type: ignore[arg-type]
        mime=mime,
        sha256=digest,
        bytes=len(payload),
        delivery_path=ref.path,
    )


def _unique_media_identities(
    refs: Sequence[MediaRef],
    *,
    origin: MediaOrigin,
    require_declared_sha256: bool,
) -> tuple[MediaInputIdentity, ...]:
    out: list[MediaInputIdentity] = []
    seen: set[str] = set()
    for ref in refs:
        identity = media_input_identity(
            ref,
            origin=origin,
            require_declared_sha256=require_declared_sha256,
        )
        if identity.media_id not in seen:
            seen.add(identity.media_id)
            out.append(identity)
    return tuple(out)


def _media_identity_occurrences(
    refs: Sequence[MediaRef],
    *,
    origin: MediaOrigin,
    require_declared_sha256: bool,
) -> tuple[MediaInputIdentity, ...]:
    """Return one identity per rendered reference, preserving order/repetition."""

    return tuple(
        media_input_identity(
            ref,
            origin=origin,
            require_declared_sha256=require_declared_sha256,
        )
        for ref in refs
    )


def _source_has_text(datapoint: DataPoint) -> bool:
    return any(
        isinstance(value, str) and bool(value.strip())
        for value in (datapoint.payload_text, datapoint.payload_code)
    ) or any(
        isinstance(turn.content, str) and bool(turn.content.strip())
        for turn in datapoint.dialog_history
    )


def source_input_inventory(
    attacker: str, datapoint: DataPoint
) -> tuple[tuple[InputChannel, ...], tuple[MediaInputIdentity, ...]]:
    """Validate source channels and return path-free physical identities."""

    reject_unexecutable_tool_source(attacker, datapoint)
    if datapoint.meta.get("abstract_modalities"):
        raise AttackerInputContractError(
            f"DataPoint {datapoint.id!r} uses abstract_modalities; measured "
            "attacker inputs require byte-backed physical media"
        )
    unsupported = sorted(set(datapoint.modalities) - set(_CHANNEL_ORDER))
    if unsupported:
        raise AttackerInputContractError(
            f"DataPoint {datapoint.id!r} declares unsupported channels: "
            + ",".join(unsupported)
        )
    refs = [
        *datapoint.media,
        *(ref for turn in datapoint.dialog_history for ref in turn.media),
    ]
    source_media = _unique_media_identities(
        refs,
        origin="source",
        require_declared_sha256=True,
    )
    declared_physical = set(datapoint.modalities) & _PHYSICAL
    observed_physical = {item.modality for item in source_media}
    if declared_physical != observed_physical:
        raise AttackerInputContractError(
            f"DataPoint {datapoint.id!r} physical declarations do not match "
            "its byte-backed media identities"
        )
    declared_text = "text" in datapoint.modalities
    if declared_text != _source_has_text(datapoint):
        raise AttackerInputContractError(
            f"DataPoint {datapoint.id!r} text declaration does not match "
            "its substantive source content"
        )
    source = canonical_input_combination(
        [
            channel
            for channel in _CHANNEL_ORDER
            if channel in datapoint.modalities and channel != "tool"
        ]
    )
    return source, source_media


def text_only_transfer_contract(
    attacker: str,
    datapoint: DataPoint,
    budget: BudgetLike,
    *,
    planned_turns: int = 1,
    turn_count_semantics: TurnCountSemantics = "exact",
) -> AttackerInputContract:
    """Plan a text-transform bridge which cannot faithfully carry rich input."""

    source, source_media = source_input_inventory(attacker, datapoint)
    if source != ("text",) or source_media:
        raise AttackerInputContractError(
            f"attacker {attacker!r} accepts text-only source DataPoints; "
            f"{datapoint.id!r} declares {'+'.join(source)}"
        )
    limit = _logical_limit(budget)
    if (
        isinstance(planned_turns, bool)
        or not isinstance(planned_turns, int)
        or not 1 <= planned_turns <= limit
    ):
        raise AttackerInputContractError(
            "text transfer planned turns must be within the logical call budget"
        )
    turns = tuple(
        PlannedTargetInput(
            logical_turn=index,
            combination=("text",),
            policy_evaluable=True,
        )
        for index in range(planned_turns)
    )
    return AttackerInputContract(
        attacker=attacker,
        datapoint_id=datapoint.id,
        source_combination=source,
        source_media=source_media,
        source_media_occurrences=(),
        generated_media=(),
        turns=turns,
        turn_count_semantics=turn_count_semantics,
    )


def identity_replay_contract(
    attacker: str,
    datapoint: DataPoint,
    budget: BudgetLike,
) -> AttackerInputContract:
    """Plan one identity replay and reject a lossy top-level/dialog split."""

    del budget  # replay is exactly one call under every valid AttackBudget
    source, source_media = source_input_inventory(attacker, datapoint)
    if datapoint.dialog_history:
        dialog_media = _media_identity_occurrences(
            [ref for turn in datapoint.dialog_history for ref in turn.media],
            origin="source",
            require_declared_sha256=True,
        )
        top_level_media = _media_identity_occurrences(
            list(datapoint.media),
            origin="source",
            require_declared_sha256=True,
        )
        missing = Counter(item.media_id for item in top_level_media) - Counter(
            item.media_id for item in dialog_media
        )
        if missing:
            raise AttackerInputContractError(
                f"attacker {attacker!r} would omit top-level source media from "
                f"DataPoint {datapoint.id!r} because dialog_history is authoritative"
            )
        actual_media = dialog_media
        actual_text = any(
            isinstance(turn.content, str) and bool(turn.content.strip())
            for turn in datapoint.dialog_history
        )
    else:
        actual_media = _media_identity_occurrences(
            list(datapoint.media),
            origin="source",
            require_declared_sha256=True,
        )
        actual_text = any(
            isinstance(value, str) and bool(value.strip())
            for value in (datapoint.payload_text, datapoint.payload_code)
        )
    actual = canonical_input_combination(
        list(dict.fromkeys([
            *(("text",) if actual_text else ()),
            *(item.modality for item in actual_media),
        ]))
    )
    if actual != source or {item.media_id for item in actual_media} != {
        item.media_id for item in source_media
    }:
        raise AttackerInputContractError(
            f"attacker {attacker!r} identity replay would change the source input "
            f"for DataPoint {datapoint.id!r}"
        )
    return AttackerInputContract(
        attacker=attacker,
        datapoint_id=datapoint.id,
        source_combination=source,
        source_media=source_media,
        source_media_occurrences=tuple(item.media_id for item in actual_media),
        generated_media=(),
        turns=(
            PlannedTargetInput(
                logical_turn=0,
                combination=source,
                policy_evaluable=True,
                media_ids=tuple(item.media_id for item in actual_media),
                source_media_policy="all" if source_media else "none",
            ),
        ),
        turn_count_semantics="exact",
    )


def crescendo_input_contract(
    attacker: str,
    datapoint: DataPoint,
    budget: BudgetLike,
    *,
    policy_evaluable: Sequence[bool],
) -> AttackerInputContract:
    """Plan text setup and source-conditioned Crescendo challenge turns."""

    source, source_media = source_input_inventory(attacker, datapoint)
    limit = _logical_limit(budget)
    if len(policy_evaluable) != limit or not any(policy_evaluable):
        raise AttackerInputContractError(
            "Crescendo input planning requires one flag per turn and a challenge"
        )
    if datapoint.dialog_history:
        delivery_media = _media_identity_occurrences(
            [ref for turn in datapoint.dialog_history for ref in turn.media],
            origin="source",
            require_declared_sha256=True,
        )
        top_level_media = _media_identity_occurrences(
            list(datapoint.media),
            origin="source",
            require_declared_sha256=True,
        )
        if Counter(item.media_id for item in top_level_media) - Counter(
            item.media_id for item in delivery_media
        ):
            raise AttackerInputContractError(
                f"attacker {attacker!r} would omit top-level source media from "
                f"DataPoint {datapoint.id!r} because dialog_history is authoritative"
            )
    else:
        delivery_media = _media_identity_occurrences(
            list(datapoint.media),
            origin="source",
            require_declared_sha256=True,
        )
    source_ids = tuple(item.media_id for item in delivery_media)
    challenge = canonical_input_combination(
        list(dict.fromkeys(["text", *(item.modality for item in source_media)]))
    )
    turns: list[PlannedTargetInput] = []
    delivered_challenges = 0
    for index, evaluable in enumerate(policy_evaluable):
        if evaluable:
            delivered_challenges += 1
        turns.append(
            PlannedTargetInput(
                logical_turn=index,
                combination=challenge if evaluable else ("text",),
                policy_evaluable=evaluable,
                # Crescendo sends the complete conversation on every call. Each
                # later challenge therefore repeats every earlier challenge's
                # source-media occurrences in the rendered request.
                media_ids=source_ids * delivered_challenges,
                source_media_policy=(
                    "all" if evaluable and source_media else "none"
                ),
            )
        )
    return AttackerInputContract(
        attacker=attacker,
        datapoint_id=datapoint.id,
        source_combination=source,
        source_media=source_media,
        source_media_occurrences=source_ids,
        generated_media=(),
        turns=tuple(turns),
        turn_count_semantics="exact",
    )


def generated_image_input_contract(
    attacker: str,
    datapoint: DataPoint,
    budget: BudgetLike,
    *,
    seed_pairs: Sequence[tuple[str, str]],
) -> AttackerInputContract:
    """Plan verified text+PNG attempts from immutable IDEATOR seed pairs."""

    source, source_media = source_input_inventory(attacker, datapoint)
    if source != ("text",) or source_media:
        raise AttackerInputContractError(
            f"attacker {attacker!r} requires a text-only source DataPoint"
        )
    if not seed_pairs:
        raise AttackerInputContractError(
            f"attacker {attacker!r} requires verified precomputed seed_pairs"
        )
    if any(
        not isinstance(pair, (list, tuple))
        or len(pair) != 2
        or not isinstance(pair[0], str)
        or not pair[0].strip()
        or not isinstance(pair[1], str)
        or not pair[1].strip()
        for pair in seed_pairs
    ):
        raise AttackerInputContractError(
            "IDEATOR seed_pairs must contain only non-blank (text, image_path) tuples"
        )
    selected = tuple(
        (str(pair[0]), str(pair[1]))
        for pair in seed_pairs[: _logical_limit(budget)]
    )
    generated: list[MediaInputIdentity] = []
    generated_ids: set[str] = set()
    turns: list[PlannedTargetInput] = []
    for index, (_text, image_path) in enumerate(selected):
        identity = media_input_identity(
            MediaRef(modality="image", path=image_path, mime="image/png"),
            origin="attacker_generated",
            require_declared_sha256=False,
        )
        if identity.media_id not in generated_ids:
            generated_ids.add(identity.media_id)
            generated.append(identity)
        turns.append(
            PlannedTargetInput(
                logical_turn=index,
                combination=("text", "image"),
                policy_evaluable=True,
                media_ids=(identity.media_id,),
                bound_text_sha256=hashlib.sha256(_text.encode("utf-8")).hexdigest(),
                bound_text_bytes=len(_text.encode("utf-8")),
            )
        )
    return AttackerInputContract(
        attacker=attacker,
        datapoint_id=datapoint.id,
        source_combination=source,
        source_media=(),
        source_media_occurrences=(),
        generated_media=tuple(generated),
        turns=tuple(turns),
        turn_count_semantics="exact",
    )


__all__ = [
    "AttackerInputContract",
    "AttackerInputContractError",
    "CONTRACT_SCHEMA",
    "MediaInputIdentity",
    "PlannedTargetInput",
    "canonical_input_combination",
    "crescendo_input_contract",
    "generated_image_input_contract",
    "identity_replay_contract",
    "media_input_identity",
    "reject_unexecutable_tool_source",
    "source_input_inventory",
    "target_modality_support_from_component_config",
    "text_only_transfer_contract",
    "validate_attempts_against_attacker_input_plan",
]
