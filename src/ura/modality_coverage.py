"""Capability-driven physical-modality coverage planning and verification.

Flat ``modality_support`` declarations say which media encoders an adapter can
actually invoke.  They do not prove that every cross-media combination works,
so this module infers only text and text+one-physical-medium combinations unless
the target explicitly declares ``modality_combinations``.  Unsupported or
unavailable combinations are recorded; available-but-unselected and planned-
but-unexecuted combinations fail closed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable, Literal, Mapping, Sequence

from .converters.release_specs import KNOWN_CORPUS_MODALITY_COMBINATIONS
from .data_models import DataPoint
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
    """Physical combination really delivered by a converted datapoint."""

    return canonical_modality_combination(
        item for item in datapoint.modalities if item in _ALLOWED
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
    for corpus_name, points in corpora.items():
        if not isinstance(corpus_name, str) or not corpus_name.strip():
            raise ModalityCoverageError("corpus names must be non-blank strings")
        for datapoint in points:
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
    executed_datapoint_ids: Mapping[str, Iterable[str]],
) -> ModalityCoveragePlan:
    """Require at least one real executed probe for every planned combination."""

    executed = {
        target: {str(datapoint_id) for datapoint_id in ids}
        for target, ids in executed_datapoint_ids.items()
    }
    updated: list[ModalityCoverageItem] = []
    missing: list[ModalityCoverageItem] = []
    for item in plan.items:
        if item.status != "planned":
            updated.append(item)
            continue
        observed = executed.get(item.target, set())
        if observed.intersection(item.eligible_datapoint_ids):
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
