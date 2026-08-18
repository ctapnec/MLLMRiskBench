"""Durable model/source/modality admission accounting.

The execution planner deliberately keeps incompatible cells out of scored
denominators.  This module makes those exclusions durable instead of relying on
an exception message or an operator-maintained table.  It does not invent a
Cartesian benchmark: one row is emitted only for each actually selected source
stratum and attacker, crossed with every requested target specification.
Because Runner executes whole logical arms, a gate-clean stratum is only
``compatible_if_isolated``; execution-unit and whole-request status separately
state whether the selected request can actually pass preflight.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .attacker_input_contract import (
    AttackerInputContract,
    AttackerInputContractError,
    deserialize_attacker_input_plan,
    grid_attacker_input_plan_payload,
)
from .data_models import DataPoint
from .modality_coverage import (
    canonical_modality_combination,
    datapoint_modality_combination,
    declared_target_combinations,
)
from .source_metrics import source_evaluator_implemented


ELIGIBILITY_SCHEMA = "ura-eligibility-plan/2"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MODALITY_ORDER = ("text", "image", "audio", "video", "tool")
_PHYSICAL = frozenset({"image", "audio", "video"})
_CELL_IDENTITY_FIELDS = (
    "requested_target_spec",
    "logical_source_arm",
    "source",
    "exact_modality_combination",
    "execution_mode",
    "metric_mode",
    "expected_behavior",
    "source_policy",
    "attacker",
    "declared_modalities",
    "exact_modality",
    "common_metrics_eligible",
    "semantic_family",
    "required_metric",
    "source_metric_runtime",
    "source_evaluator_implemented",
    "source_metric_attackers",
    "automated_grading_mode",
    "automated_metric_scope",
    "source_reference_available",
    "resolved_target",
    "selected_datapoint_count",
    "selected_datapoint_ids_sha256",
    "source_exact_modality_combination",
    "target_call_modality_combinations",
    "evaluable_modality_combinations",
    "attacker_input_contract_bindings",
    "attacker_input_contract_bindings_sha256",
    "generated_media_inventory",
    "generated_media_inventory_sha256",
    "tool_runtime_required",
)
_ATTACKER_CONTRACT_FIELDS = {
    "source_exact_modality_combination",
    "target_call_modality_combinations",
    "evaluable_modality_combinations",
    "attacker_input_contract_bindings",
    "attacker_input_contract_bindings_sha256",
    "generated_media_inventory",
    "generated_media_inventory_sha256",
    "tool_runtime_required",
}
_CELL_CONTRACT_BINDING_FIELDS = frozenset({
    "datapoint_id", "seed", "contract_id", "planned_turns",
    "turn_count_semantics",
})
_STRATUM_IDENTITY_FIELDS = tuple(
    field for field in _CELL_IDENTITY_FIELDS
    if field not in {
        "requested_target_spec", "attacker", "resolved_target",
        *_ATTACKER_CONTRACT_FIELDS,
    }
)
_ITEM_FIELDS = frozenset({
    *_CELL_IDENTITY_FIELDS,
    "cell_id",
    "resolved_target",
    "effective_modality",
    "source_evaluator_implemented",
    "selected_datapoint_count",
    "selected_datapoint_ids_sha256",
    "status",
    "disposition",
    "failed_gates",
    "execution_unit_id",
    "execution_unit_status",
})


def canonical_json_sha256(value: object) -> str:
    """SHA-256 of strict canonical JSON used by eligibility identities."""

    material = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def eligibility_plan_id(value_without_plan_id: Mapping[str, Any]) -> str:
    """Content identity for a complete eligibility plan payload."""

    return f"eligibility-{canonical_json_sha256(value_without_plan_id)[:24]}"


def _request_id(request: Mapping[str, Any], bindings: Mapping[str, Any]) -> str:
    identity = {"request": dict(request), "bindings": dict(bindings)}
    return f"eligibility-request-{canonical_json_sha256(identity)[:24]}"


def _project_identity(
    value: Mapping[str, Any], fields: Sequence[str]
) -> dict[str, Any]:
    return {field: value.get(field) for field in fields}


def _cell_id(value: Mapping[str, Any]) -> str:
    identity = _project_identity(value, _CELL_IDENTITY_FIELDS)
    return f"eligibility-cell-{canonical_json_sha256(identity)[:24]}"


def lifecycle_stratum_id(request_id: str, cell_id: str) -> str:
    """Identity for one planning stratum under one exact request condition.

    A bare ``cell_id`` deliberately excludes run-wide conditions.  The Level-1
    inventory therefore uses this composite identity so the same source
    stratum can legitimately appear under two defenses or judge/runtime
    configurations without being pooled.
    """

    if re.fullmatch(r"eligibility-request-[0-9a-f]{24}", request_id) is None:
        raise ValueError("invalid eligibility request_id")
    if re.fullmatch(r"eligibility-cell-[0-9a-f]{24}", cell_id) is None:
        raise ValueError("invalid eligibility cell_id")
    identity = {"request_id": request_id, "cell_id": cell_id}
    return f"lifecycle-stratum-{canonical_json_sha256(identity)[:24]}"


def _stratum_token(value: Mapping[str, Any]) -> str:
    return canonical_json_sha256(_project_identity(value, _STRATUM_IDENTITY_FIELDS))


def _stratum_id(value: Mapping[str, Any]) -> str:
    return f"eligibility-stratum-{_stratum_token(value)[:24]}"


def _execution_unit_identity(value: Mapping[str, Any]) -> dict[str, str]:
    return {
        "requested_target_spec": str(value["requested_target_spec"]),
        "logical_source_arm": str(value["logical_source_arm"]),
        "attacker": str(value["attacker"]),
    }


def _execution_unit_id(value: Mapping[str, Any]) -> str:
    return (
        "eligibility-unit-"
        + canonical_json_sha256(_execution_unit_identity(value))[:24]
    )


def _richest_modality(combination: Sequence[str]) -> str:
    for modality in ("video", "audio", "image", "text"):
        if modality in combination:
            return modality
    raise ValueError("exact physical modality combination is empty")


def _declared_modalities(datapoint: DataPoint) -> tuple[str, ...]:
    present = set(datapoint.modalities)
    return tuple(item for item in _MODALITY_ORDER if item in present)


def _source_policy_identity(datapoint: DataPoint) -> dict[str, str] | None:
    policy = datapoint.source_policy
    if policy is None:
        return None
    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "sha256": policy.sha256,
    }


def _normalized_optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _normalized_attacker_constraint(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
        or len(set(value)) != len(value)
    ):
        return ()
    return tuple(sorted(item.strip().lower() for item in value))


def _metric_descriptor(datapoint: DataPoint) -> dict[str, Any]:
    common = datapoint.meta.get("common_metrics_eligible", True)
    required = _normalized_optional_text(datapoint.meta.get("required_metric"))
    runtime = _normalized_optional_text(datapoint.meta.get("source_metric_runtime"))
    if common is True:
        if datapoint.expected_behavior == "refuse":
            metric_mode = "common_harmful_response_proxy"
            family = "unsafe_response_rate"
        else:
            metric_mode = "common_benign_over_refusal_proxy"
            family = "benign_refusal_rate"
        implemented: bool | None = True
    elif common is False:
        metric_mode = "source_specific_evaluator"
        family = required or "source_specific_unspecified"
        implemented = bool(
            required and source_evaluator_implemented(datapoint.source, required)
        )
    else:
        metric_mode = "invalid_common_metric_declaration"
        family = "coverage_conformance"
        implemented = False
    physical = bool(set(datapoint.modalities).intersection(_PHYSICAL))
    reference = _normalized_optional_text(datapoint.meta.get("judge_reference_text"))
    endpoint_scope = datapoint.meta.get("automated_metric_scope", "media_conditioned")
    if common is True and physical:
        if endpoint_scope == "response_only":
            grading_mode = "response_only_text_judge_proxy"
        elif endpoint_scope == "media_conditioned" and reference is not None:
            grading_mode = "text_judges_with_source_reference_proxy"
        else:
            grading_mode = "unavailable"
    elif common is True:
        grading_mode = "text_judges_over_text_response"
    elif implemented:
        grading_mode = "source_specific_response_parser"
    else:
        grading_mode = "unavailable"
    return {
        "common_metrics_eligible": common,
        "metric_mode": metric_mode,
        "semantic_family": family,
        "required_metric": required,
        "source_metric_runtime": runtime,
        "source_evaluator_implemented": implemented,
        "source_metric_attackers": _normalized_attacker_constraint(
            datapoint.meta.get("source_metric_attackers")
        ),
        "automated_grading_mode": grading_mode,
        "automated_metric_scope": endpoint_scope if physical else None,
        "source_reference_available": reference is not None,
    }


#: Datapoint-level fields that define one planning stratum.  The planner groups
#: selected rows by exactly this projection (plus the arm label), so the Runner
#: stamp and Level-1 attribution must use the same field set: any coarser key
#: can match two strata that differ only in, e.g., declared modalities or
#: execution mode.
PLANNING_STRATUM_FIELDS = (
    "source",
    "declared_modalities",
    "exact_modality_combination",
    "exact_modality",
    "execution_mode",
    "expected_behavior",
    "source_policy",
    "common_metrics_eligible",
    "metric_mode",
    "semantic_family",
    "required_metric",
    "source_metric_runtime",
    "source_evaluator_implemented",
    "source_metric_attackers",
    "automated_grading_mode",
    "automated_metric_scope",
    "source_reference_available",
)


def datapoint_planning_stratum(
    datapoint: DataPoint, *, validate_media_bytes: bool = True
) -> dict[str, Any]:
    """Datapoint-level planning-stratum descriptor shared with the Runner.

    The planner keeps ``validate_media_bytes`` on so byte-backed media
    admission stays a planning gate.  The Runner stamps the same descriptor
    onto attempts after media were already admitted and aliased for delivery,
    where the original corpus paths need not resolve; both paths produce the
    identical declared combination value.
    """

    if validate_media_bytes:
        exact = datapoint_modality_combination(datapoint)
    else:
        exact = canonical_modality_combination(
            item
            for item in datapoint.modalities
            if item in _MODALITY_ORDER and item != "tool"
        )
    return {
        "source": datapoint.source,
        "declared_modalities": list(_declared_modalities(datapoint)),
        "exact_modality_combination": list(exact),
        "exact_modality": _richest_modality(exact),
        "execution_mode": _normalized_optional_text(
            datapoint.meta.get("execution_mode")
        ) or "harness_response_evaluation",
        "expected_behavior": datapoint.expected_behavior,
        "source_policy": _source_policy_identity(datapoint),
        **_metric_descriptor(datapoint),
    }


def planning_stratum_sha256(value: Mapping[str, Any]) -> str:
    """Content identity of a planning stratum's datapoint-level descriptor."""

    return canonical_json_sha256(_project_identity(value, PLANNING_STRATUM_FIELDS))


def _source_strata(
    logical_source_arm: str, rows: Sequence[DataPoint]
) -> list[tuple[dict[str, Any], list[DataPoint]]]:
    grouped: dict[str, tuple[dict[str, Any], list[DataPoint]]] = {}
    for datapoint in rows:
        descriptor: dict[str, Any] = {
            "logical_source_arm": logical_source_arm,
            **datapoint_planning_stratum(datapoint),
        }
        key = json.dumps(descriptor, sort_keys=True, separators=(",", ":"))
        grouped.setdefault(key, (descriptor, []))[1].append(datapoint)
    return [grouped[key] for key in sorted(grouped)]


def build_eligibility_plan(
    *,
    requested_targets: Sequence[str],
    targets: Mapping[str, object],
    corpora: Mapping[str, Sequence[DataPoint]],
    attackers: Sequence[str],
    attacker_input_contracts: Mapping[
        tuple[str, str, str, int], AttackerInputContract
    ],
    target_failures: Mapping[str, Mapping[str, str]] | None = None,
    global_failures: Sequence[Mapping[str, str]] = (),
    bindings: Mapping[str, Any] | None = None,
    dry_run: bool = False,
    approximate_common_metrics: bool = False,
    whole_request_preflight_complete: bool = False,
) -> dict[str, Any]:
    """Build the explicit requested-target x selected-source eligibility ledger.

    ``targets`` is keyed by the persisted requested target spec.  A requested
    spec absent from it must have a ``target_failures`` entry and is retained as
    N/A for every selected source stratum.  Physical media are byte-validated by
    :func:`datapoint_modality_combination`; malformed evidence remains a hard
    planning error rather than an N/A compatibility decision.
    """

    requested = list(requested_targets)
    selected_attackers = [item.strip().lower() for item in attackers]
    if (
        not requested
        or any(not isinstance(item, str) or not item.strip() for item in requested)
        or len(set(requested)) != len(requested)
    ):
        raise ValueError("eligibility plan requires unique non-blank target specs")
    if (
        not corpora
        or any(not isinstance(arm, str) or not arm.strip() for arm in corpora)
        or any(not rows for rows in corpora.values())
    ):
        raise ValueError("eligibility plan requires non-empty logical source arms")
    if (
        not selected_attackers
        or any(not item for item in selected_attackers)
        or len(set(selected_attackers)) != len(selected_attackers)
    ):
        raise ValueError("eligibility plan requires unique non-blank attackers")
    expected_contract_prefixes = {
        (arm, attacker, datapoint.id)
        for arm, rows in corpora.items()
        for attacker in selected_attackers
        for datapoint in rows
    }
    observed_contract_prefixes = {
        (arm, attacker, datapoint_id)
        for arm, attacker, datapoint_id, _seed in attacker_input_contracts
    }
    if expected_contract_prefixes != observed_contract_prefixes:
        raise ValueError(
            "attacker input contracts do not cover the selected "
            "source/attacker/datapoint universe"
        )
    seeds_by_prefix: dict[tuple[str, str, str], set[int]] = defaultdict(set)
    for key, contract in attacker_input_contracts.items():
        if (
            not isinstance(key, tuple)
            or len(key) != 4
            or not isinstance(key[3], int)
            or isinstance(key[3], bool)
            or key[3] < 0
            or contract.attacker != key[1]
            or contract.datapoint_id != key[2]
        ):
            raise ValueError("attacker input contract mapping has an invalid identity")
        seeds_by_prefix[key[:3]].add(key[3])
    seed_sets = {tuple(sorted(value)) for value in seeds_by_prefix.values()}
    if len(seed_sets) != 1 or not seed_sets:
        raise ValueError(
            "attacker input contracts must cover one consistent non-empty seed set"
        )
    contract_seeds = next(iter(seed_sets))

    unknown_targets = set(targets) - set(requested)
    unknown_failures = set(target_failures or {}) - set(requested)
    if unknown_targets or unknown_failures:
        raise ValueError("eligibility plan target maps contain unrequested specs")

    failures = dict(target_failures or {})
    normalized_global_failures: list[dict[str, str]] = []
    for failure in global_failures:
        gate = failure.get("gate")
        reason = failure.get("reason")
        if (
            not isinstance(gate, str)
            or not gate.strip()
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise ValueError("global eligibility failures require gate and reason")
        normalized_global_failures.append({
            "gate": gate.strip(), "reason": reason.strip()[:2000]
        })
    declared_by_target: dict[str, set[tuple[str, ...]]] = {}
    resolved_by_target: dict[str, str | None] = {}
    capability_errors: dict[str, str] = {}
    for spec in requested:
        target = targets.get(spec)
        if target is None:
            if spec not in failures:
                raise ValueError(f"requested target {spec!r} has no target or failure")
            resolved_by_target[spec] = None
            continue
        resolved = str(getattr(target, "name", "")).strip()
        if not resolved:
            capability_errors[spec] = "target has no non-blank runtime identity"
            resolved_by_target[spec] = None
            continue
        resolved_by_target[spec] = resolved
        try:
            declared_by_target[spec] = set(declared_target_combinations(target))
        except (TypeError, ValueError) as exc:
            capability_errors[spec] = str(exc)

    resolved_owners: dict[str, list[str]] = defaultdict(list)
    for spec, resolved in resolved_by_target.items():
        if resolved is not None:
            resolved_owners[resolved].append(spec)
    for resolved, owners in resolved_owners.items():
        if len(owners) > 1:
            for spec in owners:
                capability_errors[spec] = (
                    f"resolved target identity {resolved!r} is shared by requested "
                    f"specs {sorted(owners)!r}"
                )

    strata: list[tuple[dict[str, Any], list[DataPoint]]] = []
    for arm in sorted(corpora):
        strata.extend(_source_strata(arm, corpora[arm]))

    items: list[dict[str, Any]] = []
    for spec in requested:
        for descriptor, rows in strata:
            exact = tuple(descriptor["exact_modality_combination"])
            for attacker in selected_attackers:
                arm = str(descriptor["logical_source_arm"])
                contracts = [
                    attacker_input_contracts[(arm, attacker, datapoint.id, seed)]
                    for datapoint in sorted(rows, key=lambda item: item.id)
                    for seed in contract_seeds
                ]
                if any(contract.source_combination != exact for contract in contracts):
                    raise ValueError(
                        "attacker input contract source combination differs from "
                        "the eligibility source stratum"
                    )
                target_combinations = sorted({
                    turn.combination
                    for contract in contracts
                    for turn in contract.turns
                })
                evaluable_combinations = sorted({
                    turn.combination
                    for contract in contracts
                    for turn in contract.turns
                    if turn.policy_evaluable
                })
                if not evaluable_combinations:
                    raise ValueError(
                        "attacker input contract has no policy-evaluable target input"
                    )
                contract_bindings = [
                    {
                        "datapoint_id": contract.datapoint_id,
                        "seed": seed,
                        "contract_id": contract.contract_id,
                        "planned_turns": len(contract.turns),
                        "turn_count_semantics": contract.turn_count_semantics,
                    }
                    for datapoint in sorted(rows, key=lambda item: item.id)
                    for seed in contract_seeds
                    for contract in [
                        attacker_input_contracts[(arm, attacker, datapoint.id, seed)]
                    ]
                ]
                generated_by_id = {
                    media.media_id: media.manifest_payload()
                    for contract in contracts
                    for media in contract.generated_media
                }
                generated_inventory = [
                    generated_by_id[key] for key in sorted(generated_by_id)
                ]
                failed_gates: list[dict[str, str]] = [
                    dict(failure) for failure in normalized_global_failures
                ]
                if spec in failures:
                    failure = failures[spec]
                    failed_gates.append({
                        "gate": str(failure.get("gate") or "target_setup"),
                        "reason": str(
                            failure.get("reason")
                            or "target construction/preflight did not complete"
                        )[:2000],
                    })
                elif spec in capability_errors:
                    failed_gates.append({
                        "gate": "target_capability_declaration",
                        "reason": capability_errors[spec][:2000],
                    })
                elif missing_combinations := sorted(
                    set(target_combinations) - declared_by_target.get(spec, set())
                ):
                    failed_gates.append({
                        "gate": "target_transport",
                        "reason": (
                            "target does not declare planned attacker input "
                            "combination(s) "
                            + ",".join("+".join(item) for item in missing_combinations)
                        ),
                    })

                common = descriptor["common_metrics_eligible"]
                required = descriptor["required_metric"]
                if common is not True and common is not False:
                    failed_gates.append({
                        "gate": "metric_declaration",
                        "reason": "common_metrics_eligible is not boolean",
                    })
                elif common is False and not required:
                    failed_gates.append({
                        "gate": "metric_declaration",
                        "reason": (
                            "common-metric-ineligible source stratum lacks a "
                            "required_metric"
                        ),
                    })
                elif (
                    common is False
                    and descriptor["source_evaluator_implemented"] is not True
                    and not approximate_common_metrics
                ):
                    reason = "exact source/required_metric evaluator is not implemented"
                    if descriptor["source_metric_runtime"]:
                        reason += (
                            "; required runtime: "
                            + descriptor["source_metric_runtime"]
                        )
                    failed_gates.append({
                        "gate": "source_evaluator",
                        "reason": reason[:2000],
                    })
                elif (
                    (common is True or (common is False and approximate_common_metrics))
                    and descriptor["automated_metric_scope"] not in {
                    None, "media_conditioned", "response_only"
                    }
                ):
                    failed_gates.append({
                        "gate": "automated_common_evaluator",
                        "reason": (
                            "physical common-metric stratum has invalid "
                            "automated_metric_scope"
                        ),
                    })
                elif (
                    (common is True or (common is False and approximate_common_metrics))
                    and descriptor["automated_metric_scope"] == "media_conditioned"
                    and descriptor["source_reference_available"] is not True
                ):
                    failed_gates.append({
                        "gate": "automated_common_evaluator",
                        "reason": (
                            "media-conditioned common metric lacks non-blank "
                            "source judge_reference_text"
                        ),
                    })

                allowed = descriptor["source_metric_attackers"]
                if allowed == ():
                    failed_gates.append({
                        "gate": "attack_mode_declaration",
                        "reason": "source_metric_attackers is malformed",
                    })
                elif allowed is not None and attacker not in allowed:
                    failed_gates.append({
                        "gate": "attack_mode",
                        "reason": (
                            f"source metric permits {','.join(allowed)}, not {attacker}"
                        ),
                    })

                if failed_gates:
                    status = "N/A"
                    gate_names = {gate["gate"] for gate in failed_gates}
                    if spec in failures or "target_setup" in gate_names or any(
                        name.startswith("target_") and name != "target_transport"
                        for name in gate_names
                    ):
                        disposition = "target_setup_or_capability_blocked"
                    elif normalized_global_failures:
                        disposition = "execution_preflight_blocked"
                    elif "target_transport" in gate_names:
                        disposition = "transport_blocked"
                    elif "source_evaluator" in gate_names:
                        disposition = "requires_source_native_runtime_or_evaluator"
                    elif "automated_common_evaluator" in gate_names:
                        disposition = (
                            "requires_substantive_automated_evaluator_or_reference"
                        )
                    elif "attack_mode" in gate_names:
                        disposition = "attack_mode_incompatible"
                    else:
                        disposition = "invalid_metric_or_attack_declaration"
                    effective: str | None = None
                else:
                    # This is a stratum-level compatibility claim only. Runner
                    # executes a complete logical arm for one target/attacker,
                    # so a compatible row is not independently runnable when a
                    # sibling stratum in that execution unit is blocked.
                    status = "compatible_if_isolated"
                    disposition = (
                        "compatible_common_proxy_if_isolated"
                        if common is True
                        else "compatible_source_plus_approximate_proxy_if_isolated"
                        if descriptor["source_evaluator_implemented"] is True
                        and approximate_common_metrics
                        else "compatible_approximate_proxy_if_isolated"
                        if approximate_common_metrics
                        else "compatible_source_specific_evaluator_if_isolated"
                    )
                    effective = _richest_modality(
                        tuple({
                            modality
                            for combination in evaluable_combinations
                            for modality in combination
                            if modality != "tool"
                        })
                    )

                ids = sorted(datapoint.id for datapoint in rows)
                identity = {
                    "requested_target_spec": spec,
                    "logical_source_arm": descriptor["logical_source_arm"],
                    "source": descriptor["source"],
                    "exact_modality_combination": descriptor[
                        "exact_modality_combination"
                    ],
                    "execution_mode": descriptor["execution_mode"],
                    "metric_mode": descriptor["metric_mode"],
                    "expected_behavior": descriptor["expected_behavior"],
                    "source_policy": descriptor["source_policy"],
                    "attacker": attacker,
                    "declared_modalities": descriptor["declared_modalities"],
                    "exact_modality": descriptor["exact_modality"],
                    "common_metrics_eligible": common,
                    "semantic_family": descriptor["semantic_family"],
                    "required_metric": required,
                    "source_metric_runtime": descriptor["source_metric_runtime"],
                    "source_evaluator_implemented": descriptor[
                        "source_evaluator_implemented"
                    ],
                    "source_metric_attackers": (
                        list(allowed) if allowed is not None else None
                    ),
                    "automated_grading_mode": descriptor[
                        "automated_grading_mode"
                    ],
                    "automated_metric_scope": descriptor[
                        "automated_metric_scope"
                    ],
                    "source_reference_available": descriptor[
                        "source_reference_available"
                    ],
                    "resolved_target": resolved_by_target.get(spec),
                    "selected_datapoint_count": len(rows),
                    "selected_datapoint_ids_sha256": canonical_json_sha256(ids),
                    "source_exact_modality_combination": list(exact),
                    "target_call_modality_combinations": [
                        list(item) for item in target_combinations
                    ],
                    "evaluable_modality_combinations": [
                        list(item) for item in evaluable_combinations
                    ],
                    "attacker_input_contract_bindings": contract_bindings,
                    "attacker_input_contract_bindings_sha256": canonical_json_sha256(
                        contract_bindings
                    ),
                    "generated_media_inventory": generated_inventory,
                    "generated_media_inventory_sha256": canonical_json_sha256(
                        generated_inventory
                    ),
                    "tool_runtime_required": any(
                        contract.tool_runtime_required for contract in contracts
                    ),
                }
                items.append({
                    "cell_id": _cell_id(identity),
                    **identity,
                    "effective_modality": effective,
                    "status": status,
                    "disposition": disposition,
                    "failed_gates": failed_gates,
                    "execution_unit_id": _execution_unit_id(identity),
                    "execution_unit_status": "pending_unit_accounting",
                })

    execution_units: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        execution_units[item["execution_unit_id"]].append(item)
    unit_records: list[dict[str, Any]] = []
    for unit_id in sorted(execution_units):
        unit_items = execution_units[unit_id]
        blocking_ids = sorted(
            item["cell_id"] for item in unit_items if item["status"] == "N/A"
        )
        unit_status = (
            "blocked_by_incompatible_stratum"
            if blocking_ids
            else "whole_arm_compatible"
        )
        for item in unit_items:
            item["execution_unit_status"] = unit_status
            if item["status"] == "compatible_if_isolated" and blocking_ids:
                item["disposition"] = (
                    "compatible_if_isolated_but_whole_arm_blocked"
                )
        unit_records.append({
            "execution_unit_id": unit_id,
            **_execution_unit_identity(unit_items[0]),
            "status": unit_status,
            "blocking_cell_ids": blocking_ids,
        })

    items.sort(key=lambda item: (
        item["requested_target_spec"],
        item["logical_source_arm"],
        item["source"],
        tuple(item["exact_modality_combination"]),
        item["execution_mode"],
        item["metric_mode"],
        item["expected_behavior"],
        json.dumps(item["source_policy"], sort_keys=True),
        item["attacker"],
    ))
    dispositions = Counter(str(item["disposition"]) for item in items)
    statuses = Counter(str(item["status"]) for item in items)
    blocked_units = sum(
        unit["status"] == "blocked_by_incompatible_stratum"
        for unit in unit_records
    )
    if normalized_global_failures:
        request_execution_status = "blocked_before_execution"
    elif not whole_request_preflight_complete:
        request_execution_status = "pending_whole_request_preflight"
    elif blocked_units:
        request_execution_status = "not_fully_executable"
    else:
        request_execution_status = "whole_request_compatible"
    stratum_inventory: list[dict[str, Any]] = []
    seen_strata: set[str] = set()
    for item in items:
        stratum_id = _stratum_id(item)
        if stratum_id in seen_strata:
            continue
        seen_strata.add(stratum_id)
        stratum_inventory.append({
            "stratum_id": stratum_id,
            **_project_identity(item, _STRATUM_IDENTITY_FIELDS),
        })
    stratum_inventory.sort(key=lambda item: item["stratum_id"])
    request = {
        "requested_target_specs": requested,
        "logical_source_arms": sorted(corpora),
        "selected_attackers": selected_attackers,
        "source_strata": stratum_inventory,
        "dry_run": bool(dry_run),
    }
    binding_payload = dict(bindings or {})
    canonical_attacker_plan = grid_attacker_input_plan_payload(
        attacker_input_contracts
    )
    supplied_attacker_plan = binding_payload.get("attacker_input_plan")
    if supplied_attacker_plan is not None:
        try:
            supplied_contracts = deserialize_attacker_input_plan(
                supplied_attacker_plan
            )
        except AttackerInputContractError as exc:
            raise ValueError(
                "eligibility attacker input plan binding is invalid"
            ) from exc
        if supplied_contracts != dict(attacker_input_contracts):
            raise ValueError(
                "eligibility attacker input plan differs from planned contracts"
            )
    binding_payload["attacker_input_plan"] = canonical_attacker_plan
    if approximate_common_metrics:
        binding_payload["supplementary_metric_policy"] = {
            "approximate_common_metrics": True,
            "authority": "supplementary_non_authoritative",
            "metric_prefix": "approximate_",
        }
    payload: dict[str, Any] = {
        "schema": ELIGIBILITY_SCHEMA,
        "status": "complete",
        "request_id": _request_id(request, binding_payload),
        "request": request,
        "bindings": binding_payload,
        "execution": {
            "executor_unit": (
                "requested_target_spec_x_logical_source_arm_x_attacker_"
                "whole_logical_arm"
            ),
            "request_status": request_execution_status,
            "whole_request_preflight_complete": bool(
                whole_request_preflight_complete
            ),
            "global_failed_gates": normalized_global_failures,
            "units_total": len(unit_records),
            "units_compatible": len(unit_records) - blocked_units,
            "units_blocked": blocked_units,
            "units": unit_records,
        },
        "counts": {
            "cells_total": len(items),
            "compatible_if_isolated": statuses.get("compatible_if_isolated", 0),
            "not_applicable": statuses.get("N/A", 0),
            "by_disposition": dict(sorted(dispositions.items())),
        },
        "items": items,
    }
    payload["plan_id"] = eligibility_plan_id(payload)
    validate_eligibility_plan(payload)
    return payload


def validate_eligibility_plan(value: object) -> dict[str, Any]:
    """Fail-closed validation for a loaded ``ura-eligibility-plan/2`` value."""

    if not isinstance(value, dict):
        raise ValueError("eligibility artifact must be a JSON object")
    required = {
        "schema", "plan_id", "request_id", "status", "request", "bindings",
        "execution", "counts", "items",
    }
    if set(value) != required:
        missing = sorted(required - set(value))
        unknown = sorted(set(value) - required)
        raise ValueError(
            f"eligibility artifact fields mismatch; missing={missing}, unknown={unknown}"
        )
    if value["schema"] != ELIGIBILITY_SCHEMA or value["status"] != "complete":
        raise ValueError("unsupported or incomplete eligibility artifact")
    body = {key: item for key, item in value.items() if key != "plan_id"}
    expected_plan_id = eligibility_plan_id(body)
    if value["plan_id"] != expected_plan_id:
        raise ValueError("eligibility artifact plan_id/content mismatch")
    request = value["request"]
    if not isinstance(request, dict) or set(request) != {
        "requested_target_specs", "logical_source_arms", "selected_attackers",
        "source_strata", "dry_run",
    }:
        raise ValueError("eligibility artifact has an invalid request inventory")
    for field in ("requested_target_specs", "logical_source_arms", "selected_attackers"):
        entries = request[field]
        if (
            not isinstance(entries, list)
            or not entries
            or any(not isinstance(item, str) or not item for item in entries)
            or len(set(entries)) != len(entries)
        ):
            raise ValueError(f"eligibility request {field} must be unique strings")
    if not isinstance(request["dry_run"], bool) or not isinstance(value["bindings"], dict):
        raise ValueError("eligibility request/bindings types are invalid")
    expected_request_id = _request_id(request, value["bindings"])
    if value["request_id"] != expected_request_id:
        raise ValueError("eligibility artifact request_id/content mismatch")
    try:
        attacker_plan = deserialize_attacker_input_plan(
            value["bindings"].get("attacker_input_plan")
        )
    except AttackerInputContractError as exc:
        raise ValueError(
            "eligibility attacker input plan binding is invalid"
        ) from exc
    if any(len(key) != 4 for key in attacker_plan):
        raise ValueError("eligibility requires a grid attacker input plan")
    grid_arms = {key[0] for key in attacker_plan}
    grid_attackers = {key[1] for key in attacker_plan}
    if (
        grid_arms != set(request["logical_source_arms"])
        or grid_attackers != set(request["selected_attackers"])
    ):
        raise ValueError(
            "eligibility attacker input plan differs from requested arms/attackers"
        )

    requested_strata = request["source_strata"]
    if not isinstance(requested_strata, list) or not requested_strata:
        raise ValueError("eligibility request requires a source-stratum inventory")
    stratum_fields = {"stratum_id", *_STRATUM_IDENTITY_FIELDS}
    strata_by_id: dict[str, dict[str, Any]] = {}
    arms_with_strata: set[str] = set()
    for stratum in requested_strata:
        if not isinstance(stratum, dict) or set(stratum) != stratum_fields:
            raise ValueError("eligibility request contains an invalid source stratum")
        stratum_id = stratum.get("stratum_id")
        if stratum_id != _stratum_id(stratum):
            raise ValueError("eligibility source stratum identity mismatch")
        if stratum_id in strata_by_id:
            raise ValueError(f"duplicate eligibility source stratum: {stratum_id}")
        arm = stratum.get("logical_source_arm")
        if arm not in request["logical_source_arms"]:
            raise ValueError("eligibility source stratum is outside requested arms")
        arms_with_strata.add(arm)
        strata_by_id[stratum_id] = stratum
    if arms_with_strata != set(request["logical_source_arms"]):
        raise ValueError("eligibility source strata omit a logical source arm")

    items = value["items"]
    if not isinstance(items, list) or not items:
        raise ValueError("eligibility artifact must contain at least one cell")
    seen_ids: set[str] = set()
    observed_cross_product: set[tuple[str, str, str]] = set()
    status_counts: Counter[str] = Counter()
    disposition_counts: Counter[str] = Counter()
    items_by_unit: dict[str, list[dict[str, Any]]] = defaultdict(list)
    consumed_contract_cells: set[tuple[str, tuple[str, str, str, int]]] = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != _ITEM_FIELDS:
            raise ValueError("eligibility item has an invalid field inventory")
        cell_id = item.get("cell_id")
        if cell_id != _cell_id(item):
            raise ValueError("eligibility cell_id/content mismatch")
        if cell_id in seen_ids:
            raise ValueError(f"duplicate eligibility cell_id: {cell_id}")
        seen_ids.add(cell_id)
        target = item.get("requested_target_spec")
        arm = item.get("logical_source_arm")
        attacker = item.get("attacker")
        if target not in request["requested_target_specs"] or arm not in request[
            "logical_source_arms"
        ] or attacker not in request["selected_attackers"]:
            raise ValueError("eligibility cell is outside the requested inventory")
        stratum_id = _stratum_id(item)
        requested_stratum = strata_by_id.get(stratum_id)
        if requested_stratum is None or _project_identity(
            item, _STRATUM_IDENTITY_FIELDS
        ) != _project_identity(requested_stratum, _STRATUM_IDENTITY_FIELDS):
            raise ValueError("eligibility cell is outside requested source strata")
        cross_key = (target, stratum_id, attacker)
        if cross_key in observed_cross_product:
            raise ValueError("duplicate eligibility target/stratum/attacker cell")
        observed_cross_product.add(cross_key)
        combination = item.get("exact_modality_combination")
        if not isinstance(combination, list) or not combination:
            raise ValueError("eligibility cell lacks exact modality combination")
        try:
            canonical = list(canonical_modality_combination(combination))
        except ValueError as exc:
            raise ValueError("eligibility exact modality combination is invalid") from exc
        if canonical != combination or item.get("exact_modality") != _richest_modality(
            combination
        ):
            raise ValueError("eligibility exact modality is inconsistent")
        if item.get("source_exact_modality_combination") != combination:
            raise ValueError("eligibility source modality projection is inconsistent")
        target_combinations = item.get("target_call_modality_combinations")
        evaluable_combinations = item.get("evaluable_modality_combinations")
        if (
            not isinstance(target_combinations, list)
            or not target_combinations
            or not isinstance(evaluable_combinations, list)
            or not evaluable_combinations
        ):
            raise ValueError("eligibility cell lacks attacker target combinations")
        try:
            canonical_target = sorted(
                list(canonical_modality_combination(entry))
                for entry in target_combinations
            )
            canonical_evaluable = sorted(
                list(canonical_modality_combination(entry))
                for entry in evaluable_combinations
            )
        except ValueError as exc:
            raise ValueError(
                "eligibility attacker target combination is invalid"
            ) from exc
        if (
            canonical_target != target_combinations
            or canonical_evaluable != evaluable_combinations
            or any(entry not in target_combinations for entry in evaluable_combinations)
        ):
            raise ValueError("eligibility attacker target combinations are inconsistent")
        bindings = item.get("attacker_input_contract_bindings")
        binding_digest = item.get("attacker_input_contract_bindings_sha256")
        if (
            not isinstance(bindings, list)
            or not bindings
            or any(
                not isinstance(binding, dict)
                or set(binding) != _CELL_CONTRACT_BINDING_FIELDS
                or not isinstance(binding["datapoint_id"], str)
                or not binding["datapoint_id"]
                or isinstance(binding["seed"], bool)
                or not isinstance(binding["seed"], int)
                or binding["seed"] < 0
                or re.fullmatch(
                    r"attacker-input-[0-9a-f]{24}", binding["contract_id"]
                ) is None
                or isinstance(binding["planned_turns"], bool)
                or not isinstance(binding["planned_turns"], int)
                or binding["planned_turns"] < 1
                or binding["turn_count_semantics"] not in {
                    "exact", "upper_bound"
                }
                for binding in bindings
            )
            or binding_digest != canonical_json_sha256(bindings)
        ):
            raise ValueError("eligibility attacker input contract binding is invalid")
        binding_keys = [
            (arm, attacker, binding["datapoint_id"], binding["seed"])
            for binding in bindings
        ]
        if binding_keys != sorted(binding_keys) or len(set(binding_keys)) != len(
            binding_keys
        ):
            raise ValueError(
                "eligibility attacker input contract bindings are not canonical"
            )
        try:
            contracts = [attacker_plan[key] for key in binding_keys]
        except KeyError as exc:
            raise ValueError(
                "eligibility cell references a contract outside its bound plan"
            ) from exc
        expected_bindings = [
            {
                "datapoint_id": contract.datapoint_id,
                "seed": key[3],
                "contract_id": contract.contract_id,
                "planned_turns": len(contract.turns),
                "turn_count_semantics": contract.turn_count_semantics,
            }
            for key, contract in zip(binding_keys, contracts, strict=True)
        ]
        if bindings != expected_bindings:
            raise ValueError(
                "eligibility cell contract bindings differ from the full plan"
            )
        if any(
            list(contract.source_combination) != combination
            for contract in contracts
        ):
            raise ValueError(
                "eligibility cell source combination differs from its contracts"
            )
        expected_target_combinations = [list(entry) for entry in sorted({
            turn.combination
            for contract in contracts
            for turn in contract.turns
        })]
        expected_evaluable_combinations = [list(entry) for entry in sorted({
            turn.combination
            for contract in contracts
            for turn in contract.turns
            if turn.policy_evaluable
        })]
        if (
            target_combinations != expected_target_combinations
            or evaluable_combinations != expected_evaluable_combinations
        ):
            raise ValueError(
                "eligibility cell target combinations differ from its contracts"
            )
        datapoint_ids = sorted({key[2] for key in binding_keys})
        if (
            item.get("selected_datapoint_count") != len(datapoint_ids)
            or item.get("selected_datapoint_ids_sha256")
            != canonical_json_sha256(datapoint_ids)
        ):
            raise ValueError(
                "eligibility cell datapoint accounting differs from its contracts"
            )
        expected_generated_by_id: dict[str, dict[str, object]] = {}
        for contract in contracts:
            for media in contract.generated_media:
                payload = media.manifest_payload()
                previous = expected_generated_by_id.setdefault(
                    media.media_id, payload
                )
                if previous != payload:
                    raise ValueError(
                        "eligibility contracts conflict on generated media identity"
                    )
        expected_generated = [
            expected_generated_by_id[media_id]
            for media_id in sorted(expected_generated_by_id)
        ]
        generated = item.get("generated_media_inventory")
        if (
            not isinstance(generated, list)
            or generated != expected_generated
            or item.get("generated_media_inventory_sha256")
            != canonical_json_sha256(generated)
            or item.get("tool_runtime_required")
            != any(contract.tool_runtime_required for contract in contracts)
        ):
            raise ValueError("eligibility generated media inventory is invalid")
        for key in binding_keys:
            consumed_key = (target, key)
            if consumed_key in consumed_contract_cells:
                raise ValueError(
                    "eligibility contract appears in multiple source strata"
                )
            consumed_contract_cells.add(consumed_key)
        declared = item.get("declared_modalities")
        if (
            not isinstance(declared, list)
            or declared != [entry for entry in _MODALITY_ORDER if entry in declared]
            or any(entry not in _MODALITY_ORDER for entry in declared)
            or not set(combination).issubset(declared)
        ):
            raise ValueError("eligibility declared modalities are invalid")
        status = item.get("status")
        gates = item.get("failed_gates")
        if status not in {"compatible_if_isolated", "N/A"} or not isinstance(gates, list):
            raise ValueError("eligibility cell has invalid status/gates")
        if (status == "compatible_if_isolated") != (not gates):
            raise ValueError("eligibility status and failed gates disagree")
        expected_effective = _richest_modality(tuple({
            modality
            for entry in evaluable_combinations
            for modality in entry
        }))
        if (
            status == "compatible_if_isolated"
            and item.get("effective_modality") != expected_effective
        ):
            raise ValueError(
                "compatible eligibility cell must preserve attacker-delivered modality"
            )
        if status == "N/A" and item.get("effective_modality") is not None:
            raise ValueError("N/A eligibility cell must not claim effective delivery")
        for gate in gates:
            if (
                not isinstance(gate, dict)
                or set(gate) != {"gate", "reason"}
                or not isinstance(gate["gate"], str)
                or not gate["gate"]
                or not isinstance(gate["reason"], str)
                or not gate["reason"]
            ):
                raise ValueError("eligibility failed-gate entries are invalid")
        digest = item.get("selected_datapoint_ids_sha256")
        count = item.get("selected_datapoint_count")
        if (
            not isinstance(digest, str)
            or _HEX64.fullmatch(digest) is None
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count <= 0
        ):
            raise ValueError("eligibility datapoint accounting is invalid")
        disposition = item.get("disposition")
        if not isinstance(disposition, str) or not disposition:
            raise ValueError("eligibility cell lacks a disposition")
        unit_id = item.get("execution_unit_id")
        if unit_id != _execution_unit_id(item):
            raise ValueError("eligibility execution-unit identity mismatch")
        items_by_unit[unit_id].append(item)
        status_counts[status] += 1
        disposition_counts[disposition] += 1

    expected_cross_product = {
        (target, stratum_id, attacker)
        for target in request["requested_target_specs"]
        for stratum_id in strata_by_id
        for attacker in request["selected_attackers"]
    }
    if observed_cross_product != expected_cross_product:
        raise ValueError(
            "eligibility artifact does not cover the requested "
            "target/source-stratum/attacker cross-product"
        )
    expected_contract_cells = {
        (target, key)
        for target in request["requested_target_specs"]
        for key in attacker_plan
    }
    if consumed_contract_cells != expected_contract_cells:
        raise ValueError(
            "eligibility cells do not fully and exactly cover the attacker input plan"
        )

    execution = value["execution"]
    execution_fields = {
        "executor_unit", "request_status", "whole_request_preflight_complete",
        "global_failed_gates", "units_total", "units_compatible",
        "units_blocked", "units",
    }
    if not isinstance(execution, dict) or set(execution) != execution_fields:
        raise ValueError("eligibility artifact has invalid execution accounting")
    if execution["executor_unit"] != (
        "requested_target_spec_x_logical_source_arm_x_attacker_whole_logical_arm"
    ) or not isinstance(execution["whole_request_preflight_complete"], bool):
        raise ValueError("eligibility artifact has invalid executor semantics")
    global_gates = execution["global_failed_gates"]
    if not isinstance(global_gates, list):
        raise ValueError("eligibility global failed gates must be a list")
    for gate in global_gates:
        if (
            not isinstance(gate, dict)
            or set(gate) != {"gate", "reason"}
            or not isinstance(gate["gate"], str)
            or not gate["gate"]
            or not isinstance(gate["reason"], str)
            or not gate["reason"]
        ):
            raise ValueError("eligibility global failed-gate entry is invalid")
    if global_gates and any(
        any(gate not in item["failed_gates"] for gate in global_gates)
        for item in items
    ):
        raise ValueError("eligibility cells omit a global failed gate")

    units = execution["units"]
    if not isinstance(units, list):
        raise ValueError("eligibility execution units must be a list")
    expected_unit_keys = {
        (target, arm, attacker)
        for target in request["requested_target_specs"]
        for arm in request["logical_source_arms"]
        for attacker in request["selected_attackers"]
    }
    observed_unit_keys: set[tuple[str, str, str]] = set()
    blocked_units = 0
    for unit in units:
        if not isinstance(unit, dict) or set(unit) != {
            "execution_unit_id", "requested_target_spec", "logical_source_arm",
            "attacker", "status", "blocking_cell_ids",
        }:
            raise ValueError("eligibility execution unit has invalid fields")
        unit_id = unit["execution_unit_id"]
        if unit_id != _execution_unit_id(unit) or unit_id not in items_by_unit:
            raise ValueError("eligibility execution unit identity mismatch")
        unit_key = (
            unit["requested_target_spec"], unit["logical_source_arm"],
            unit["attacker"],
        )
        if unit_key in observed_unit_keys:
            raise ValueError("duplicate eligibility execution unit")
        observed_unit_keys.add(unit_key)
        expected_blockers = sorted(
            item["cell_id"] for item in items_by_unit[unit_id]
            if item["status"] == "N/A"
        )
        expected_unit_status = (
            "blocked_by_incompatible_stratum"
            if expected_blockers
            else "whole_arm_compatible"
        )
        if (
            unit["blocking_cell_ids"] != expected_blockers
            or unit["status"] != expected_unit_status
            or any(
                item["execution_unit_status"] != expected_unit_status
                for item in items_by_unit[unit_id]
            )
        ):
            raise ValueError("eligibility execution-unit accounting is inconsistent")
        blocked_units += int(bool(expected_blockers))
    if observed_unit_keys != expected_unit_keys:
        raise ValueError("eligibility artifact omits a whole execution unit")
    expected_request_status = (
        "blocked_before_execution"
        if global_gates
        else "pending_whole_request_preflight"
        if not execution["whole_request_preflight_complete"]
        else "not_fully_executable"
        if blocked_units
        else "whole_request_compatible"
    )
    if execution["request_status"] != expected_request_status:
        raise ValueError("eligibility whole-request status is inconsistent")
    if execution["whole_request_preflight_complete"] and blocked_units:
        raise ValueError("completed whole-request preflight cannot retain blocked units")
    if {
        "units_total": execution["units_total"],
        "units_compatible": execution["units_compatible"],
        "units_blocked": execution["units_blocked"],
    } != {
        "units_total": len(units),
        "units_compatible": len(units) - blocked_units,
        "units_blocked": blocked_units,
    }:
        raise ValueError("eligibility execution-unit counts do not reconcile")

    counts = value["counts"]
    expected_counts = {
        "cells_total": len(items),
        "compatible_if_isolated": status_counts.get("compatible_if_isolated", 0),
        "not_applicable": status_counts.get("N/A", 0),
        "by_disposition": dict(sorted(disposition_counts.items())),
    }
    if counts != expected_counts:
        raise ValueError("eligibility artifact counts do not reconcile with cells")
    return value


def summarize_eligibility_plans(
    plans: Sequence[tuple[dict[str, Any], str, str]]
) -> dict[str, Any]:
    """Return a non-pooling inventory for validated eligibility artifacts."""

    seen: set[str] = set()
    seen_requests: dict[str, str] = {}
    seen_lifecycle_strata: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    dispositions: Counter[str] = Counter()
    for plan, artifact_sha256, locator in plans:
        validate_eligibility_plan(plan)
        plan_id = str(plan["plan_id"])
        if plan_id in seen:
            raise ValueError(f"duplicate eligibility plan_id: {plan_id}")
        seen.add(plan_id)
        request_id = str(plan["request_id"])
        if request_id in seen_requests:
            raise ValueError(
                "overlapping eligibility plans share request binding "
                f"{request_id}: {seen_requests[request_id]!r}, {locator!r}"
            )
        seen_requests[request_id] = locator
        for item in plan["items"]:
            cell_id = str(item["cell_id"])
            lifecycle_id = lifecycle_stratum_id(request_id, cell_id)
            if lifecycle_id in seen_lifecycle_strata:
                raise ValueError(
                    "overlapping eligibility plans share lifecycle stratum "
                    f"{lifecycle_id}: "
                    f"{seen_lifecycle_strata[lifecycle_id]!r}, {locator!r}"
                )
            seen_lifecycle_strata[lifecycle_id] = locator
        counts = plan["counts"]
        totals["cells_total"] += counts["cells_total"]
        totals["compatible_if_isolated"] += counts["compatible_if_isolated"]
        totals["not_applicable"] += counts["not_applicable"]
        dispositions.update(counts["by_disposition"])
        records.append({
            "plan_id": plan_id,
            "request_id": request_id,
            "canonical_locator": locator,
            "canonical_sha256": artifact_sha256,
            "request": plan["request"],
            "bindings": plan["bindings"],
            "counts": counts,
        })
    records.sort(key=lambda item: item["plan_id"])
    return {
        "n_plans": len(records),
        "cells_total": totals["cells_total"],
        "compatible_if_isolated": totals["compatible_if_isolated"],
        "not_applicable": totals["not_applicable"],
        "by_disposition": dict(sorted(dispositions.items())),
        "plans": records,
        "interpretation": (
            "stratum compatibility and whole-request N/A accounting only; "
            "compatible_if_isolated is not an independently runnable cell or "
            "execution evidence"
        ),
    }


__all__ = [
    "ELIGIBILITY_SCHEMA",
    "build_eligibility_plan",
    "canonical_json_sha256",
    "eligibility_plan_id",
    "lifecycle_stratum_id",
    "summarize_eligibility_plans",
    "validate_eligibility_plan",
]
