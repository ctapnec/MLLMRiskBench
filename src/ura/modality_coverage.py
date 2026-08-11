"""Capability-driven physical-modality coverage planning and verification.

Flat ``modality_support`` declarations say which media encoders an adapter can
actually invoke.  They do not prove that every cross-media combination works,
so this module infers only text and text+one-physical-medium combinations unless
the target explicitly declares ``modality_combinations``.  Unsupported or
unavailable combinations are recorded; available-but-unselected and planned-
but-unexecuted combinations fail closed.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
from typing import Iterable, Literal, Mapping, Sequence

from .converters._common import (
    DEFAULT_MAX_MEDIA_ASSET_BYTES,
    ConverterError,
    _read_bounded_bytes,
    media_signature_matches,
)
from .converters.release_specs import KNOWN_CORPUS_MODALITY_COMBINATIONS
from .data_models import DataPoint, MediaRef
from .targets.base import BaseTarget


_ORDER = ("text", "image", "audio", "video")
_PHYSICAL = frozenset({"image", "audio", "video"})
_ALLOWED = frozenset(_ORDER)


class ModalityCoverageError(ValueError):
    """A declared target capability would be silently absent from a run."""


def canonical_modality_combination(values: Iterable[str]) -> tuple[str, ...]:
    """Return a unique, deterministic physical-input signature."""

    items = tuple(values)
    if not items or any(not isinstance(item, str) for item in items):
        raise ModalityCoverageError("modality combinations must be non-empty strings")
    if len(set(items)) != len(items):
        raise ModalityCoverageError("modality combinations must not contain duplicates")
    unsupported = sorted(set(items) - _ALLOWED)
    if unsupported:
        raise ModalityCoverageError(
            "physical modality coverage cannot infer abstract/unsupported values: "
            + ",".join(unsupported)
        )
    return tuple(item for item in _ORDER if item in items)


def datapoint_modality_combination(datapoint: DataPoint) -> tuple[str, ...]:
    """Physical combination backed by admitted media bytes in a datapoint."""

    declared_physical = set(datapoint.modalities).intersection(_PHYSICAL)
    refs = [
        *datapoint.media,
        *(
            ref
            for turn in datapoint.dialog_history
            for ref in turn.media
        ),
    ]
    observed_physical: set[str] = set()
    validated_sources: set[
        tuple[str, str | None, str | None, str | None, str | None]
    ] = set()
    for ref in refs:
        if ref.modality not in _PHYSICAL:
            raise ModalityCoverageError(
                f"datapoint {datapoint.id!r} contains a non-physical MediaRef"
            )
        observed_physical.add(ref.modality)
        source_key = (ref.modality, ref.path, ref.uri, ref.sha256, ref.mime)
        if source_key not in validated_sources:
            _validate_byte_backed_ref(datapoint.id, ref)
            validated_sources.add(source_key)
    if declared_physical != observed_physical:
        raise ModalityCoverageError(
            f"datapoint {datapoint.id!r} physical modality declaration does not "
            f"match byte-backed MediaRefs: declared={sorted(declared_physical)}, "
            f"observed={sorted(observed_physical)}"
        )

    return canonical_modality_combination(
        item for item in datapoint.modalities if item in _ALLOWED
    )


def _validate_byte_backed_ref(datapoint_id: str, ref: MediaRef) -> None:
    digest = ref.sha256
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ModalityCoverageError(
            f"datapoint {datapoint_id!r} physical MediaRef lacks a full SHA-256"
        )
    if (
        not isinstance(ref.mime, str)
        or not ref.mime.startswith(f"{ref.modality}/")
    ):
        raise ModalityCoverageError(
            f"datapoint {datapoint_id!r} physical MediaRef lacks a matching MIME type"
        )
    if ref.path is not None:
        try:
            _, payload = _read_bounded_bytes(
                Path(ref.path), max_bytes=DEFAULT_MAX_MEDIA_ASSET_BYTES
            )
        except ConverterError as exc:
            raise ModalityCoverageError(
                f"datapoint {datapoint_id!r} physical MediaRef path cannot be "
                "admitted as stable bounded bytes"
            ) from exc
    else:
        uri = ref.uri or ""
        try:
            header, encoded = uri.split(",", 1)
            header_parts = header[5:].split(";")
            if (
                not header.startswith("data:")
                or len(header_parts) < 2
                or header_parts[0] != ref.mime
                or header_parts[-1].lower() != "base64"
                or len(encoded) > (4 * ((DEFAULT_MAX_MEDIA_ASSET_BYTES + 2) // 3) + 4)
            ):
                raise ValueError
            payload = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ModalityCoverageError(
                f"datapoint {datapoint_id!r} physical MediaRef is not bounded base64 data"
            ) from exc
    if not payload or len(payload) > DEFAULT_MAX_MEDIA_ASSET_BYTES:
        raise ModalityCoverageError(
            f"datapoint {datapoint_id!r} physical MediaRef bytes are empty or oversized"
        )
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ModalityCoverageError(
            f"datapoint {datapoint_id!r} physical MediaRef SHA-256 mismatch"
        )
    if not media_signature_matches(payload, ref.mime):
        raise ModalityCoverageError(
            f"datapoint {datapoint_id!r} physical MediaRef MIME/signature mismatch"
        )


def declared_target_combinations(target: BaseTarget) -> tuple[tuple[str, ...], ...]:
    """Validate explicit combinations or conservatively derive independent ones."""

    support = canonical_modality_combination(
        getattr(target, "modality_support", ("text",))
    )
    explicit = getattr(target, "modality_combinations", None)
    if explicit is None:
        # A flat declaration proves individual encoders, not arbitrary Cartesian
        # products.  Never claim image+audio or image+video without an explicit
        # adapter contract and test.
        combinations: list[tuple[str, ...]] = []
        if "text" in support:
            combinations.append(("text",))
        combinations.extend(
            canonical_modality_combination(
                ("text", modality) if "text" in support else (modality,)
            )
            for modality in _ORDER
            if modality in _PHYSICAL and modality in support
        )
    else:
        if isinstance(explicit, (str, bytes)):
            raise ModalityCoverageError(
                "target modality_combinations must be a sequence of combinations"
            )
        combinations = [
            canonical_modality_combination(combination)
            for combination in explicit
        ]
        if not combinations:
            raise ModalityCoverageError("target modality_combinations cannot be empty")

    if len(set(combinations)) != len(combinations):
        raise ModalityCoverageError("target modality_combinations must be unique")
    for combination in combinations:
        if not set(combination).issubset(support):
            raise ModalityCoverageError(
                f"target combination {combination!r} exceeds modality_support {support!r}"
            )
    covered = set().union(*(set(combination) for combination in combinations))
    omitted = sorted((set(support) & _PHYSICAL) - covered)
    if omitted:
        raise ModalityCoverageError(
            "target physical support is absent from modality_combinations: "
            + ",".join(omitted)
        )
    return tuple(combinations)


CoverageStatus = Literal[
    "planned", "unavailable", "available_but_unselected", "executed"
]


@dataclass(frozen=True)
class ModalityCoverageItem:
    target: str
    combination: tuple[str, ...]
    status: CoverageStatus
    selected_corpora: tuple[str, ...]
    eligible_datapoint_ids: tuple[str, ...]
    known_eligible_corpora: tuple[str, ...]
    justification: str | None = None


@dataclass(frozen=True)
class ModalityCoveragePlan:
    schema: str
    enforcement: Literal["strict", "diagnostic"]
    items: tuple[ModalityCoverageItem, ...]

    def manifest_payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "enforcement": self.enforcement,
            "items": [asdict(item) for item in self.items],
        }


def plan_modality_coverage(
    targets: Sequence[BaseTarget],
    corpora: Mapping[str, Sequence[DataPoint]],
    *,
    enforce_available: bool = True,
) -> ModalityCoveragePlan:
    """Plan every actually supported combination for selected multimodal targets.

    A target is considered multimodal only when its adapter declares at least one
    physical modality.  Known released data that was not selected is an error;
    genuinely unavailable combinations are retained with an explicit reason.
    """

    points_by_combination: dict[tuple[str, ...], list[tuple[str, DataPoint]]] = {}
    datapoint_owners: dict[str, str] = {}
    for corpus_name, points in corpora.items():
        if not isinstance(corpus_name, str) or not corpus_name.strip():
            raise ModalityCoverageError("corpus names must be non-blank strings")
        for datapoint in points:
            previous_owner = datapoint_owners.get(datapoint.id)
            if previous_owner is not None:
                raise ModalityCoverageError(
                    f"duplicate datapoint id {datapoint.id!r} across selected "
                    f"corpora/rows ({previous_owner!r}, {corpus_name!r})"
                )
            datapoint_owners[datapoint.id] = corpus_name
            combination = datapoint_modality_combination(datapoint)
            points_by_combination.setdefault(combination, []).append(
                (corpus_name, datapoint)
            )

    items: list[ModalityCoverageItem] = []
    target_names: set[str] = set()
    for target in targets:
        target_name = str(getattr(target, "name", "")).strip()
        if not target_name:
            raise ModalityCoverageError("coverage target has no non-blank name")
        if target_name in target_names:
            raise ModalityCoverageError(f"duplicate coverage target {target_name!r}")
        target_names.add(target_name)
        support = set(getattr(target, "modality_support", ("text",)))
        if not support.intersection(_PHYSICAL):
            continue

        for combination in declared_target_combinations(target):
            selected = points_by_combination.get(combination, [])
            selected_corpora = tuple(sorted({name for name, _ in selected}))
            ids = tuple(sorted({point.id for _, point in selected}))
            known = tuple(KNOWN_CORPUS_MODALITY_COMBINATIONS.get(combination, ()))
            if ids:
                status: CoverageStatus = "planned"
                justification = None
            elif known:
                status = "available_but_unselected"
                justification = (
                    "released compatible data exists but no selected, converted "
                    "datapoint exercises this combination"
                )
            else:
                status = "unavailable"
                justification = (
                    "no maintained released corpus is registered for this exact "
                    "adapter-supported combination"
                )
            items.append(ModalityCoverageItem(
                target=target_name,
                combination=combination,
                status=status,
                selected_corpora=selected_corpora,
                eligible_datapoint_ids=ids,
                known_eligible_corpora=known,
                justification=justification,
            ))

    plan = ModalityCoveragePlan(
        schema="ura-modality-coverage-plan/1",
        enforcement="strict" if enforce_available else "diagnostic",
        items=tuple(items),
    )
    missing = [
        item for item in plan.items if item.status == "available_but_unselected"
    ]
    if missing and enforce_available:
        detail = "; ".join(
            f"{item.target}:{'+'.join(item.combination)} "
            f"(eligible corpora: {','.join(item.known_eligible_corpora)})"
            for item in missing
        )
        raise ModalityCoverageError(
            "multimodal capability coverage would be silently incomplete: " + detail
        )
    return plan


def verify_executed_modality_coverage(
    plan: ModalityCoveragePlan,
    executed_evidence: Mapping[
        str, Iterable[tuple[str, tuple[str, ...]]]
    ],
) -> ModalityCoveragePlan:
    """Require exact delivered-combination evidence for every planned item.

    An eligible datapoint id alone is insufficient: a response-conditioned
    setup turn can share that id while omitting its physical payload.  Evidence
    therefore binds the id to the combination actually sent to the base target.
    """

    executed = {
        target: {
            (
                str(datapoint_id),
                canonical_modality_combination(combination),
            )
            for datapoint_id, combination in evidence
        }
        for target, evidence in executed_evidence.items()
    }
    updated: list[ModalityCoverageItem] = []
    missing: list[ModalityCoverageItem] = []
    for item in plan.items:
        if item.status != "planned":
            updated.append(item)
            continue
        observed = executed.get(item.target, set())
        if any(
            datapoint_id in item.eligible_datapoint_ids
            and combination == item.combination
            for datapoint_id, combination in observed
        ):
            updated.append(ModalityCoverageItem(
                **{**asdict(item), "status": "executed"}
            ))
        else:
            missing.append(item)
            updated.append(item)
    if missing:
        detail = "; ".join(
            f"{item.target}:{'+'.join(item.combination)}" for item in missing
        )
        raise ModalityCoverageError(
            "planned multimodal capabilities received no real executed probe: " + detail
        )
    return ModalityCoveragePlan(
        schema="ura-modality-coverage-result/1",
        enforcement=plan.enforcement,
        items=tuple(updated),
    )


__all__ = [
    "ModalityCoverageError",
    "ModalityCoverageItem",
    "ModalityCoveragePlan",
    "canonical_modality_combination",
    "datapoint_modality_combination",
    "declared_target_combinations",
    "plan_modality_coverage",
    "verify_executed_modality_coverage",
]
