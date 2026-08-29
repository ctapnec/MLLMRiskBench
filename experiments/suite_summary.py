"""Build a broad-roster evidence inventory without a universal safety score.

Runner cells are admitted through the same content-addressed completed-grid
validator used by measured figures.  Source-native evaluator envelopes are
admitted through :mod:`experiments.native_import`.  The output keeps every
rate in its exact benchmark/policy/modality/model condition and retains native
aggregates on their original, per-run scales.
Optional eligibility inputs are integrity-checked planning inventories. Their
``compatible_if_isolated`` strata are not renamed as runnable execution cells,
and overlapping request/cell identities are rejected rather than double-counted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from experiments.figure_results import (  # noqa: E402
    _load_cells,
    _reject_duplicate_realized_target_arms,
)
from experiments.native_import import load_native_run  # noqa: E402
from ura.approximate_metrics import (  # noqa: E402
    ApproximateSecurityDecision,
    aggregate_approximate_provenance,
    validate_approximate_abstention_judgment,
    validate_approximate_completion_bindings,
    validate_approximate_judgment,
    validate_approximate_metric_provenance,
)
from ura.adapters._native_artifacts import NativeEngineRun  # noqa: E402
from ura.data_models import Judgment  # noqa: E402
from ura.eligibility import (  # noqa: E402
    summarize_eligibility_plans,
    validate_eligibility_plan,
)


SUITE_SCHEMA = "ura-suite-evidence/1"
_MAX_SOURCE_CONFIG_BYTES = 1024 * 1024
_MAX_ELIGIBILITY_BYTES = 16 * 1024 * 1024
_GUARD_ABSTENTION_REASON = (
    "guardrail_safe_cannot_adjudicate_benign_over_refusal"
)
_EXPECTED_NATIVE_PROJECTS = frozenset({
    "agentdojo",
    "asb",
    "autodan_turbo",
    "easyjailbreak",
    "fuzzyai",
    "garak",
    "giskard",
    "petri",
    "promptfoo",
})
def _expected_converter_families() -> frozenset[str]:
    """The converter families the project actually ships.

    This was a hand-maintained list, and it drifted: it held nineteen names
    while the registry had grown to twenty-five, so the six newest families
    (airbench, decodingtrust, holisafe, saladbench, simplesafetytests, xstest)
    could never be reported missing, and every campaign published a stale
    nineteen-name expected set that contradicted the documented twenty-five.
    Deriving it from the registry that defines the families removes the second
    place a family has to be listed, so the same drift cannot recur.
    """

    from ura.converters import _CONVERTERS  # noqa: PLC0415 - avoids an import cycle

    return frozenset(_CONVERTERS)

_NATIVE_FAMILIES: dict[str, list[str]] = {
    "agentdojo": ["attack_or_injection_goal_success", "task_utility"],
    "asb": ["attack_or_injection_goal_success", "task_utility"],
    "autodan_turbo": ["adaptive_compromise", "graded_risk"],
    "easyjailbreak": ["attack_or_injection_goal_success"],
    "fuzzyai": ["detector_findings"],
    "garak": ["detector_findings"],
    "giskard_v2_raget": ["task_utility"],
    "giskard_v2_scan": ["detector_findings"],
    "petri": ["graded_risk"],
    "promptfoo": ["attack_or_injection_goal_success"],
}


def _metric_family(metric: str) -> str:
    approximate = metric.startswith("approximate_")
    if approximate:
        metric = metric.removeprefix("approximate_")
    if metric in {"ASR", "refusal_rate"}:
        family = "unsafe_response_rate"
    elif metric == "ISR":
        # Runner ISR is the harmful-response rate restricted to rows carrying
        # an indirect-injection risk tag.  It does not observe whether an
        # injected goal executed, so it must not inherit a source-native goal-
        # success interpretation.
        family = "unsafe_response_rate"
    elif metric in {"over_refusal_rate", "conversation_over_refusal_rate"}:
        family = "benign_refusal_rate"
    elif metric in {
        "conversation_ASR",
        "robust_refusal_rate",
        "median_turns_to_break",
        "restricted_mean_turns_to_break",
        "kaplan_meier_survival",
    } or metric.startswith("survival_"):
        family = "adaptive_compromise"
    elif metric in {"strongreject", "conversation_strongreject_max"}:
        family = "graded_risk"
    elif metric == "source_metric_implementation_coverage":
        family = "coverage_conformance"
    elif metric.startswith(("rjudge_", "gptgeochat_")):
        family = "classification_quality"
    else:
        family = "source_specific_or_specialized"
    return f"approximate_{family}" if approximate else family


def _policy(raw: dict[str, Any]) -> dict[str, Any]:
    source_policy = raw.get("source_policy")
    digest = source_policy.get("sha256") if isinstance(source_policy, dict) else None
    return {
        "policy_id": str(raw.get("source_policy_id", "unversioned")),
        "version": str(raw.get("source_policy_version", "unversioned")),
        "sha256": digest,
    }


def _execution_mode(raw: dict[str, Any]) -> str:
    if bool(raw.get("response_conditioned")) and not bool(raw.get("replayed_transcript")):
        return "live_response_conditioned"
    return "static_or_exact_replay"


def _stratum_identity(cell: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    raw = row["raw"]
    run = cell["manifest"]["config"]["run"]
    source_evaluation = raw.get("source_evaluation")
    return {
        # A run ID binds the target, judge cascade, source instance, sampling,
        # budgets and code identities.  Omitting it would silently pool rows
        # from independently configured grids that merely share display labels.
        "run_id": cell["run_id"],
        "model_spec": run["model_spec"],
        "resolved_model": cell["model"],
        "corpus_arm": run["corpus"],
        "source": raw["source"],
        "source_policy": _policy(raw),
        "declared_modality": raw["modality"],
        "effective_modality": raw["effective_modality"],
        "risk_category": raw["risk_category"],
        "attacker": run["attacker"],
        "defense": run["defense"],
        "execution_mode": _execution_mode(raw),
        "expected_behavior": raw["expected_behavior"],
        "common_metrics_eligible": raw["common_metrics_eligible"],
        "source_metric_family": (
            source_evaluation.get("family")
            if isinstance(source_evaluation, dict)
            else None
        ),
    }


def _measurement_families(identity: dict[str, Any], rows: list[dict[str, Any]]) -> list[str]:
    if not identity["common_metrics_eligible"]:
        families = [
            "classification_quality"
            if identity["source_metric_family"] is not None
            else "coverage_conformance"
        ]
        proxy = [
            validate_approximate_judgment(row)[1]
            for row in rows
            if row["raw"].get("approximate_security_decision") is not None
        ]
        proxy_attempted = bool(proxy) or any(
            row["raw"].get("approximate_decision_status") == "abstained"
            for row in rows
        )
        if proxy_attempted:
            families.append(
                "approximate_adaptive_compromise"
                if identity["execution_mode"] == "live_response_conditioned"
                else "approximate_unsafe_response_rate"
                if identity["expected_behavior"] == "refuse"
                else "approximate_benign_refusal_rate"
            )
            if any(
                row["raw"].get("strongreject_evaluated") is True for row in rows
            ):
                families.append("approximate_graded_risk")
        return sorted(set(families))
    if identity["execution_mode"] == "live_response_conditioned":
        families = ["adaptive_compromise"]
    elif identity["expected_behavior"] == "refuse":
        families = ["unsafe_response_rate"]
    else:
        families = ["benign_refusal_rate"]
    # A harmful-response proxy is not an injection-goal-success evaluator merely
    # because the source carries a prompt-injection risk tag. Goal execution and
    # task utility belong to a source-native scorer/importer.
    if any(row["raw"].get("strongreject_evaluated") is True for row in rows):
        families.append("graded_risk")
    return sorted(set(families))


def _final_guard_abstention(row: dict[str, Any]) -> bool:
    raw = row.get("raw")
    return (
        isinstance(raw, dict)
        and row.get("judge") == "guardrail"
        and row.get("label") == "not_applicable"
        and row.get("score") == 0.0
        and isinstance(raw.get("confidence"), (int, float))
        and not isinstance(raw.get("confidence"), bool)
        and float(raw["confidence"]) == 0.0
        and raw.get("expected_behavior")
        in {"safe_answer", "comply_safely"}
        and raw.get("parsed") is True
        and raw.get("unsafe") is False
        and raw.get("guardrail_queried") is True
        and raw.get("over_refusal_expressible") is False
        and raw.get("automated_decision_status") == "abstained"
        and raw.get("abstention_reason") == _GUARD_ABSTENTION_REASON
        and raw.get("cascade_role") == "authoritative"
        and raw.get("cascade_confident") is True
    )


def _final_model_nonresponse(row: dict[str, Any]) -> bool:
    raw = row.get("raw")
    return (
        isinstance(raw, dict)
        and row.get("label") == "not_applicable"
        and row.get("score") == 0.0
        and raw.get("policy_evaluable_turn") is True
        and raw.get("common_metrics_eligible") is True
        and raw.get("stage_queried") is False
        and raw.get("policy_evaluation_status") == "model_nonresponse"
        and isinstance(raw.get("confidence"), (int, float))
        and not isinstance(raw.get("confidence"), bool)
        and float(raw["confidence"]) == 1.0
        and raw.get("parsed") is None
        and raw.get("cascade_role") == "authoritative"
        and raw.get("cascade_confident") is True
        and raw.get("metric_authority") is None
        and raw.get("required_metric") is None
    )


def _response_index(values: Any) -> dict[str, Any]:
    if isinstance(values, dict):
        return dict(values)
    if isinstance(values, list):
        return {
            str(row.get("attempt_id")): row
            for row in values
            if isinstance(row, dict) and isinstance(row.get("attempt_id"), str)
        }
    return {}


def _is_non_evaluable_setup(row: dict[str, Any]) -> bool:
    """Validate and identify one unqueried live-conversation setup row."""

    raw = row.get("raw")
    if not isinstance(raw, dict) or raw.get("policy_evaluable_turn") is not False:
        return False
    if (
        row.get("label") != "not_applicable"
        or row.get("score") != 0.0
        or raw.get("policy_challenge_index") is not None
        or raw.get("turn_expected_behavior") != "comply_safely"
        or raw.get("common_metrics_eligible") is not False
        or raw.get("stage_queried") is not False
        or raw.get("policy_evaluation_status") != "not_evaluable"
        or raw.get("cascade_role") != "authoritative"
        or raw.get("cascade_confident") is not True
    ):
        raise ValueError("runner stratum carries an invalid non-evaluable setup row")
    return True


def _descriptive_endpoint(
    identity: dict[str, Any], rows: list[dict[str, Any]], *,
    responses: Any = None,
    supplementary_policy: Any = None,
) -> dict[str, Any] | None:
    """Return an exact-stratum static rate, never a cross-stratum estimate."""

    approximate = False
    decisions: list[ApproximateSecurityDecision] = []
    decision_rows: list[dict[str, Any]] = []
    abstained_rows: list[dict[str, Any]] = []
    rows = [row for row in rows if not _is_non_evaluable_setup(row)]
    if not identity["common_metrics_eligible"]:
        response_by_attempt = _response_index(responses)
        for row in rows:
            raw = row["raw"]
            response = response_by_attempt.get(row.get("attempt_id"))
            if raw.get("approximate_security_decision") is not None:
                _judgment, decision = validate_approximate_judgment(
                    row,
                    response=response,
                    supplementary_policy=supplementary_policy,
                )
                decisions.append(decision)
                decision_rows.append(row)
            elif raw.get("approximate_decision_status") == "abstained":
                if response is None:
                    raise ValueError(
                        "approximate abstention lacks its authoritative Response"
                    )
                validate_approximate_abstention_judgment(
                    row,
                    response=response,
                    supplementary_policy=supplementary_policy,
                )
                abstained_rows.append(row)
        if not decision_rows and not abstained_rows:
            return None
        approximate = True
    else:
        for row in rows:
            if row.get("label") == "not_applicable":
                if not (
                    _final_guard_abstention(row)
                    or _final_model_nonresponse(row)
                ):
                    raise ValueError(
                        "runner stratum carries an invalid authoritative N/A"
                    )
                abstained_rows.append(row)
            else:
                decision_rows.append(row)
    completed = len(decision_rows) + len(abstained_rows)
    missing_responses = sum(_final_model_nonresponse(row) for row in abstained_rows)
    support = {
        "judgments_completed": completed,
        "judgments_evaluable": completed,
        "judgments_decided": len(decision_rows),
        "judgments_abstained": len(abstained_rows),
        "decision_coverage": len(decision_rows) / completed if completed else None,
    }
    if missing_responses:
        support["judgments_missing_responses"] = missing_responses
    if identity["execution_mode"] == "live_response_conditioned":
        endpoint = (
            "conversation_ASR"
            if identity["expected_behavior"] == "refuse"
            else "conversation_over_refusal_rate"
        )
        endpoint_row = {
            "endpoint": f"approximate_{endpoint}" if approximate else endpoint,
            "value": None,
            "reason": "turn rows require trajectory-level aggregation; use aggregate_results",
            "decision_support": support,
        }
        if approximate:
            endpoint_row["metric_authority"] = "supplementary_non_authoritative"
        return endpoint_row
    if identity["expected_behavior"] == "refuse":
        endpoint = "ASR"
        positive = "violation"
    else:
        endpoint = "over_refusal_rate"
        positive = "over_refusal"
    if not decision_rows:
        endpoint_row = {
            "endpoint": f"approximate_{endpoint}" if approximate else endpoint,
            "value": None,
            "reason": "no_decided_judgments",
            "decision_support": support,
        }
        if approximate:
            endpoint_row["metric_authority"] = "supplementary_non_authoritative"
        return endpoint_row
    cluster_events: dict[str, list[float]] = defaultdict(list)
    for row in decision_rows:
        raw = row["raw"]
        cluster_id = str(raw.get("source_cluster_id") or raw["datapoint_id"])
        cluster_events[cluster_id].append(float(row["label"] == positive))
    cluster_means = [
        sum(events) / len(events) for events in cluster_events.values()
    ]
    endpoint_row = {
        "endpoint": f"approximate_{endpoint}" if approximate else endpoint,
        "n_event_records": sum(row["label"] == positive for row in decision_rows),
        "n_records": len(decision_rows),
        "n_source_clusters": len(cluster_means),
        "value": sum(cluster_means) / len(cluster_means),
        "weighting": "equal_source_prompt_intent_cluster",
        "uncertainty": None,
        "decision_support": support,
        "qualification": (
            "descriptive exact-stratum equal-cluster rate; no cross-stratum pooling"
        ),
    }
    if approximate:
        evidence_classes = {item.selected_evidence_class for item in decisions}
        if len(evidence_classes) != 1:
            raise ValueError(
                "runner stratum mixes selected-stage approximate evidence class"
            )
        evidence_class = next(iter(evidence_classes))
        endpoint_row.update({
            "metric_authority": "supplementary_non_authoritative",
            "warning_tag": (
                "warning_synthetic_approximate"
                if evidence_class == "synthetic"
                else "warning_approximate"
            ),
            "evidence_class": evidence_class,
            "reliability_score": min(
                item.reliability.score for item in decisions
            ),
            "reliability_kind": (
                "uncalibrated_heuristic_indicator_not_probability"
            ),
        })
    return endpoint_row


def _metric_proxy_rows(
    rows: list[dict[str, Any]], group_by: dict[str, Any]
) -> list[Judgment]:
    """Select the exact completed judgments behind one aggregate bucket."""

    selected: list[Judgment] = []
    for value in rows:
        judgment = Judgment.model_validate(value, strict=True)
        if all(
            str(
                judgment.raw[key]
                if key in judgment.raw and judgment.raw[key] is not None
                else getattr(judgment, key, "unknown")
            )
            == expected
            for key, expected in group_by.items()
        ):
            selected.append(judgment)
    return selected


def _validate_proxy_cell_bindings(cell: dict[str, Any]) -> None:
    validate_approximate_completion_bindings(
        judgments=cell["judgments"],
        responses=cell.get("responses"),
        supplementary_policy=cell["manifest"].get("config", {}).get(
            "supplementary_metric_policy"
        ),
        trails=cell.get("trails", []),
    )


def summarize_runner_cells(cells: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[
        str, tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]
    ] = {}
    aggregate_results: list[dict[str, Any]] = []
    seen_run_ids: set[str] = set()

    for cell in cells:
        if cell["run_id"] in seen_run_ids:
            raise ValueError(f"duplicate completed runner run_id: {cell['run_id']}")
        seen_run_ids.add(cell["run_id"])
        _validate_proxy_cell_bindings(cell)
        run = cell["manifest"]["config"]["run"]
        sources: set[str] = set()
        policies: dict[str, dict[str, Any]] = {}
        modalities: set[str] = set()
        for row in cell["judgments"]:
            identity = _stratum_identity(cell, row)
            token = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            grouped.setdefault(token, (identity, [], cell))[1].append(row)
            sources.add(identity["source"])
            policy = identity["source_policy"]
            policies[json.dumps(policy, sort_keys=True)] = policy
            modalities.add(identity["effective_modality"])

        scope = {
            "sources": sorted(sources),
            "source_policies": [policies[key] for key in sorted(policies)],
            "effective_modalities": sorted(modalities),
        }
        for result in cell["aggregate_results"]:
            provenance = result["provenance"]
            metric = result["metric"]
            approximate_value = provenance.get("approximate_security")
            if isinstance(metric, str) and metric.startswith("approximate_"):
                approximate = validate_approximate_metric_provenance(
                    metric, approximate_value
                )
                if (
                    isinstance(result.get("n"), bool)
                    or not isinstance(result.get("n"), int)
                    or result["n"] != approximate.n_result_units
                ):
                    raise ValueError(
                        "suite approximate aggregate n does not match its typed "
                        "metric-specific result-unit count"
                    )
                group_by = result.get("group_by")
                if not isinstance(group_by, dict):
                    raise ValueError(
                        "approximate aggregate lacks exact grouping provenance"
                    )
                recomputed = aggregate_approximate_provenance(
                    _metric_proxy_rows(cell["judgments"], group_by),
                    metric=metric.removeprefix("approximate_"),
                    responses=cell.get("responses"),
                    supplementary_policy=cell["manifest"].get(
                        "config", {}
                    ).get("supplementary_metric_policy"),
                )
                if approximate.model_dump(mode="json") != recomputed:
                    raise ValueError(
                        "suite approximate aggregate does not match its exact "
                        "metric-specific completed proxy decisions"
                    )
            elif approximate_value is not None:
                raise ValueError(
                    "source/common aggregate carries approximate provenance"
                )
            else:
                approximate = None
            aggregate_row = {
                "run_id": cell["run_id"],
                "model_spec": run["model_spec"],
                "resolved_model": cell["model"],
                "corpus_arm": run["corpus"],
                "attacker": run["attacker"],
                "defense": run["defense"],
                "metric": metric,
                "semantic_family": _metric_family(result["metric"]),
                "value": result["value"],
                "ci_low": result.get("ci_low"),
                "ci_high": result.get("ci_high"),
                "n": result["n"],
                "group_by": result["group_by"],
                "provenance": provenance,
                "scope_inventory": scope,
                "cross_cell_pooling_permitted": False,
            }
            if approximate is not None:
                aggregate_row.update({
                    "metric_authority": "supplementary_non_authoritative",
                    "warning_tag": approximate.warning_tag,
                    "reliability_score": approximate.reliability_score,
                    "reliability_kind": approximate.reliability_kind,
                })
            aggregate_results.append(aggregate_row)

    strata: list[dict[str, Any]] = []
    for token in sorted(grouped):
        identity, rows, cell = grouped[token]
        cluster_ids = {
            str(row["raw"].get("source_cluster_id") or row["raw"]["datapoint_id"])
            for row in rows
        }
        approximate_rows = [
            row
            for row in rows
            if row["raw"].get("approximate_security_decision") is not None
        ]
        if approximate_rows:
            for row in approximate_rows:
                validate_approximate_judgment(row)
        approximate_abstention_rows = [
            row
            for row in rows
            if row["raw"].get("approximate_decision_status") == "abstained"
        ]
        source_or_common_label_counts = (
            dict(sorted(Counter(row["label"] for row in rows).items()))
            if identity["common_metrics_eligible"]
            else {"not_applicable": len(rows)}
        )
        strata.append({
            **identity,
            "measurement_families": _measurement_families(identity, rows),
            "n_completed_records": len(rows),
            "n_source_clusters": len(cluster_ids),
            "label_counts": source_or_common_label_counts,
            "n_strongreject_graded": (
                sum(
                    row["raw"].get("strongreject_evaluated") is True
                    for row in rows
                )
                if identity["common_metrics_eligible"]
                else 0
            ),
            "approximate_proxy_label_counts": dict(sorted(Counter(
                row["label"] for row in approximate_rows
            ).items())),
            "n_approximate_proxy_abstained": len(approximate_abstention_rows),
            "n_approximate_strongreject_graded": sum(
                row["raw"].get("strongreject_evaluated") is True
                for row in approximate_rows
            ),
            "descriptive_common_endpoint": _descriptive_endpoint(
                identity,
                rows,
                responses=cell.get("responses"),
                supplementary_policy=cell["manifest"].get("config", {}).get(
                    "supplementary_metric_policy"
                ),
            ),
        })

    aggregate_results.sort(key=lambda item: (
        item["model_spec"], item["corpus_arm"], item["attacker"], item["metric"],
        json.dumps(item["group_by"], sort_keys=True),
    ))
    return {
        "n_completed_cells": len(cells),
        "n_completed_records": sum(len(cell["judgments"]) for cell in cells),
        "strata": strata,
        "aggregate_results": aggregate_results,
    }


def _score_field_coverage(cases: Iterable[Any]) -> dict[str, int]:
    coverage: Counter[str] = Counter()
    for case in cases:
        coverage.update(case.native_scores)
    return dict(sorted(coverage.items()))


def summarize_native_runs(
    native_runs: list[tuple[NativeEngineRun, str, str]],
) -> dict[str, Any]:
    seen: set[tuple[str, str]] = set()
    runs: list[dict[str, Any]] = []
    for run, digest, locator in native_runs:
        identity = (run.engine, run.native_run_id)
        if identity in seen:
            raise ValueError(f"duplicate native run identity: {identity!r}")
        seen.add(identity)
        per_target: dict[str, list[Any]] = defaultdict(list)
        for case in run.cases:
            per_target[case.target_model].append(case)
        target_strata = []
        for target in sorted(per_target):
            cases = per_target[target]
            target_strata.append({
                "target_model": target,
                "source": run.engine,
                "native_contract": {
                    "native_schema": run.native_schema,
                    "upstream_version": run.upstream_version,
                    "upstream_revision": run.upstream_revision,
                },
                "modality": "source_native_unspecified",
                "semantic_families": _NATIVE_FAMILIES[run.engine],
                "n_cases": len(cases),
                "native_outcome_counts": dict(sorted(
                    Counter(case.native_outcome for case in cases).items()
                )),
                "native_score_field_coverage": _score_field_coverage(cases),
                "common_metric_eligible": False,
            })
        runs.append({
            "engine": run.engine,
            "native_run_id": run.native_run_id,
            "canonical_locator": locator,
            "canonical_sha256": digest,
            "measurement_semantics": run.measurement_semantics,
            "target_strata": target_strata,
            "native_aggregates": run.native_aggregates,
            "import_accounting": run.import_accounting,
            "native_scale_pooling_permitted": False,
        })
    runs.sort(key=lambda item: (item["engine"], item["native_run_id"]))
    return {"n_native_runs": len(runs), "runs": runs}


def build_suite_summary(
    cells: list[dict[str, Any]],
    native_runs: list[tuple[NativeEngineRun, str, str]],
    *,
    eligibility_plans: list[tuple[dict[str, Any], str, str]] | None = None,
    expected_source_arms: dict[str, str] | None = None,
    source_inventory_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _reject_duplicate_realized_target_arms(cells)
    eligibility_inputs = eligibility_plans or []
    if not cells and not native_runs and not eligibility_inputs:
        raise ValueError(
            "suite summary requires runner cells, native runs, and/or eligibility plans"
        )
    runner = summarize_runner_cells(cells)
    native = summarize_native_runs(native_runs)
    eligibility = summarize_eligibility_plans(eligibility_inputs)
    observed_source_arms = {
        str(cell["manifest"]["config"]["run"]["corpus"])
        for cell in cells
    }
    expected_arms = set(expected_source_arms or {})
    configured_converter_families = set((expected_source_arms or {}).values())
    observed_native_projects = {
        "giskard" if run.engine.startswith("giskard_v2_") else run.engine
        for run, _, _ in native_runs
    }
    source_inventory_supplied = expected_source_arms is not None
    missing_source_arms = sorted(expected_arms - observed_source_arms)
    missing_native_projects = sorted(
        _EXPECTED_NATIVE_PROJECTS - observed_native_projects
    )
    missing_converter_families = sorted(
        _expected_converter_families() - configured_converter_families
    )
    presence_complete = bool(source_inventory_supplied) and not (
        missing_source_arms or missing_native_projects or missing_converter_families
    )
    return {
        "schema_version": SUITE_SCHEMA,
        "status": "validated_available_evidence_inventory",
        "pooling_policy": {
            "universal_safety_score_defined": False,
            "common_rates": (
                "kept in exact model/source/policy/modality/attacker/defense strata"
            ),
            "native_results": "kept by native run and original scale",
            "heterogeneous_rate_pooling": False,
        },
        "source_native_presence": {
            "all_expected_entries_observed": presence_complete,
            "program_complete_claimed": False,
            "full_model_lane_coverage_claimed": False,
            "scope": (
                "presence against the supplied source registry plus the nine "
                "expected native projects; not model-by-source lane completeness"
            ),
            "source_inventory_supplied": source_inventory_supplied,
            "source_inventory_artifact": source_inventory_artifact,
            "expected_source_arms": sorted(expected_arms),
            "observed_source_arms": sorted(observed_source_arms),
            "missing_source_arms": missing_source_arms,
            "unexpected_source_arms": sorted(observed_source_arms - expected_arms)
            if source_inventory_supplied
            else [],
            "expected_converter_families": sorted(_expected_converter_families()),
            "configured_converter_families": sorted(configured_converter_families),
            "missing_converter_families": missing_converter_families,
            "expected_native_projects": sorted(_EXPECTED_NATIVE_PROJECTS),
            "observed_native_projects": sorted(observed_native_projects),
            "missing_native_projects": missing_native_projects,
            "interpretation": (
                "missing entries are visible gaps; record each as not run, failed, "
                "or scientifically unavailable with a reason rather than silently "
                "omitting it"
            ),
        },
        "runner": runner,
        "native": native,
        "eligibility": eligibility,
    }


def _load_source_inventory(path_value: Path) -> tuple[dict[str, str], dict[str, Any]]:
    """Load the checked source-arm registry for coverage accounting only."""

    if path_value.is_symlink():
        raise ValueError("--source-config must not be a symlink")
    path = path_value.resolve(strict=True)
    stat = path.stat()
    if not path.is_file() or stat.st_size > _MAX_SOURCE_CONFIG_BYTES:
        raise ValueError("--source-config must be a regular <=1 MiB JSON file")
    data = path.read_bytes()
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in --source-config: {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid --source-config JSON: {exc}") from exc
    if not isinstance(value, dict) or not value:
        raise ValueError("--source-config must be a non-empty object keyed by arm id")
    inventory: dict[str, str] = {}
    for arm_id, raw in value.items():
        if (
            not isinstance(arm_id, str)
            or not arm_id.strip()
            or arm_id != arm_id.strip()
            or "," in arm_id
        ):
            raise ValueError("source-config arm IDs must be non-blank and unpadded")
        if not isinstance(raw, dict):
            raise ValueError(f"source-config arm {arm_id!r} must be an object")
        converter = raw.get("converter")
        if not isinstance(converter, str) or not converter.strip():
            raise ValueError(f"source-config arm {arm_id!r} lacks converter")
        inventory[arm_id] = converter.strip().lower()
    return inventory, {
        "file": path.name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _load_eligibility_plan(
    path_value: Path,
) -> tuple[dict[str, Any], str, str]:
    """Load one bounded, non-symlink, content-self-verifying plan artifact."""

    if path_value.is_symlink():
        raise ValueError("--eligibility must not be a symlink")
    path = path_value.resolve(strict=True)
    stat = path.stat()
    if (
        not path.is_file()
        or path.is_symlink()
        or stat.st_size <= 0
        or stat.st_size > _MAX_ELIGIBILITY_BYTES
    ):
        raise ValueError("--eligibility must be a regular non-empty <=16 MiB JSON file")
    data = path.read_bytes()
    if len(data) != stat.st_size:
        raise ValueError("--eligibility changed while being read")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in --eligibility: {key!r}")
            result[key] = item
        return result

    def reject_constant(item: str) -> None:
        raise ValueError(f"non-finite JSON number in --eligibility: {item!r}")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid --eligibility JSON: {exc}") from exc
    plan = validate_eligibility_plan(value)
    return plan, hashlib.sha256(data).hexdigest(), path.name


def _write_new(path: Path, value: dict[str, Any]) -> None:
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Summarize completion-validated broad-roster evidence without pooling"
    )
    parser.add_argument(
        "--results", type=Path, action="append", default=[],
        help="completed run_matrix results root; repeat for independent grids",
    )
    parser.add_argument(
        "--native", type=Path, action="append", default=[],
        help="canonical NativeEngineRun JSON; repeat for native runs",
    )
    parser.add_argument(
        "--eligibility", type=Path, action="append", default=[],
        help=(
            "validated run_matrix/rig_check eligibility JSON; repeat for "
            "independent requested grids"
        ),
    )
    parser.add_argument(
        "--source-config",
        type=Path,
        help=(
            "complete source-instance registry used to report observed and missing "
            "program arms"
        ),
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.results and not args.native and not args.eligibility:
        parser.error("provide at least one --results, --native, or --eligibility input")

    try:
        cells: list[dict[str, Any]] = []
        for root in args.results:
            resolved = root.resolve(strict=True)
            cells.extend(_load_cells(resolved))
        native_runs = []
        for path in args.native:
            run, digest = load_native_run(path)
            native_runs.append((run, digest, path.name))
        eligibility_plans = [
            _load_eligibility_plan(path) for path in args.eligibility
        ]
        source_inventory = None
        source_inventory_artifact = None
        if args.source_config is not None:
            source_inventory, source_inventory_artifact = _load_source_inventory(
                args.source_config
            )
        summary = build_suite_summary(
            cells,
            native_runs,
            eligibility_plans=eligibility_plans,
            expected_source_arms=source_inventory,
            source_inventory_artifact=source_inventory_artifact,
        )
        _write_new(args.out, summary)
    except (OSError, TypeError, ValueError) as exc:
        print(f"suite summary failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "written",
        "output": str(args.out.resolve()),
        "n_completed_cells": summary["runner"]["n_completed_cells"],
        "n_native_runs": summary["native"]["n_native_runs"],
        "n_eligibility_plans": summary["eligibility"]["n_plans"],
        "n_not_applicable_cells": summary["eligibility"]["not_applicable"],
        "source_native_presence_complete": summary["source_native_presence"][
            "all_expected_entries_observed"
        ],
        "universal_safety_score_defined": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
