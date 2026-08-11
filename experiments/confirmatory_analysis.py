"""Execute a content-bound, complete-family confirmatory analysis plan.

The plan is frozen before the main run.  Each contrast carries its own SESOI,
disjoint-pilot variance artifact, required unique-cluster count and exact set of
hypotheses.  Missing cells remain members of their multiplicity family instead
of silently reducing the Holm denominator.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src"))

from experiments.analysis_integrity import (  # noqa: E402
    analysis_source_identity,
    human_analysis_cell_id,
    parse_source_policy_token,
    read_bound_json,
)
from experiments.paired_compare import compare, compare_adaptivity  # noqa: E402
from ura.metrics import (  # noqa: E402
    holm_bonferroni_complete_family,
    power_gate,
    required_clusters_for_power,
    required_clusters_for_proportion_precision,
)

PLAN_SCHEMA = "ura-confirmatory-plan/1.0"
RESULT_SCHEMA = "ura-confirmatory-analysis/1.0"


def _nonblank(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-blank string")
    return value


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0):
        raise ValueError(f"{label} must be finite" + (" and positive" if positive else ""))
    return result


def _path(base: Path, value: Any, label: str) -> Path:
    rendered = _nonblank(value, label)
    path = Path(rendered)
    return path if path.is_absolute() else (base / path).resolve()


def _pilot(plan_dir: Path, contrast: dict[str, Any]) -> tuple[dict[str, Any], float]:
    pilot = contrast.get("pilot")
    if not isinstance(pilot, dict):
        raise ValueError(f"contrast {contrast.get('contrast_id')!r} lacks pilot object")
    expected = _nonblank(pilot.get("sha256"), "pilot.sha256").lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("pilot.sha256 must be a lowercase SHA-256 digest")
    artifact = _path(plan_dir, pilot.get("artifact"), "pilot.artifact")
    payload = read_bound_json(artifact, expected_sha256=expected)
    if payload.get("schema_version") != "ura-disjoint-pilot/1.0":
        raise ValueError(f"pilot {artifact} has unsupported schema_version")
    if payload.get("disjoint_from_main") is not True:
        raise ValueError(f"pilot {artifact} does not assert disjoint_from_main=true")
    run_ids = payload.get("source_run_ids")
    if not isinstance(run_ids, list) or not run_ids or any(
        not isinstance(value, str) or not value for value in run_ids
    ):
        raise ValueError(f"pilot {artifact} lacks source_run_ids")
    sd = _number(payload.get("cluster_sd"), "pilot.cluster_sd", positive=True)
    n = payload.get("n_unique_clusters")
    if not isinstance(n, int) or isinstance(n, bool) or n < 2:
        raise ValueError(f"pilot {artifact} requires at least two unique clusters")
    return payload, sd


def _human_design(
    plan: dict[str, Any], *, plan_dir: Path, alpha: float,
    plan_artifact: dict[str, Any],
) -> dict[str, Any]:
    human_plan = plan.get("human_audit")
    if not isinstance(human_plan, dict):
        raise ValueError("plan requires a frozen human_audit design")
    prevalence_mode = human_plan.get("event_prevalence_mode")
    pilot: dict[str, Any] | None = None
    cluster_ids: list[str] = []
    pilot_run_ids: list[str] = []
    if prevalence_mode == "conservative_max_binomial_variance":
        prevalence = 0.5
        prevalence_provenance = "conservative_max_binomial_variance"
    else:
        if prevalence_mode not in {None, "representative_disjoint_pilot"}:
            raise ValueError("human_audit.event_prevalence_mode is unsupported")
        pilot_ref = human_plan.get("pilot")
        if not isinstance(pilot_ref, dict):
            raise ValueError("representative human_audit design requires a pilot artifact")
        pilot_path = _path(
            plan_dir, pilot_ref.get("artifact"), "human_audit.pilot.artifact"
        )
        pilot = read_bound_json(
            pilot_path,
            expected_sha256=_nonblank(
                pilot_ref.get("sha256"), "human_audit.pilot.sha256"
            ),
        )
        cluster_ids = pilot.get("cluster_ids")
        if (
            pilot.get("schema_version") != "ura-disjoint-pilot/1.0"
            or pilot.get("disjoint_from_main") is not True
            or not isinstance(pilot.get("source_run_ids"), list)
            or not pilot["source_run_ids"]
            or not isinstance(cluster_ids, list)
            or len(cluster_ids) != pilot.get("n_unique_clusters")
            or len(set(cluster_ids)) != len(cluster_ids)
        ):
            raise ValueError(
                "human-audit pilot must be disjoint, run-identified, and cluster-identified"
            )
        pilot_run_ids = pilot["source_run_ids"]
        prevalence = _number(
            pilot.get("event_prevalence"), "human pilot event_prevalence"
        )
        prevalence_provenance = "representative_disjoint_pilot"
    half_width = _number(
        human_plan.get("precision_half_width"),
        "human_audit.precision_half_width", positive=True,
    )
    required = required_clusters_for_proportion_precision(
        prevalence, half_width, alpha=alpha,
    )
    if human_plan.get("required_unique_clusters") != required:
        raise ValueError(
            "human_audit.required_unique_clusters does not equal the frozen "
            f"pilot calculation: {required}"
        )
    minimum_raters = human_plan.get("minimum_independent_raters")
    if (
        not isinstance(minimum_raters, int) or isinstance(minimum_raters, bool)
        or minimum_raters < 2
    ):
        raise ValueError("human_audit.minimum_independent_raters must be an integer >=2")
    return {
        "required_unique_clusters": required,
        "precision_half_width": half_width,
        "pilot_event_prevalence": prevalence,
        "event_prevalence_provenance": prevalence_provenance,
        "minimum_independent_raters": minimum_raters,
        "pilot_artifact": pilot["_artifact_identity"] if pilot is not None else None,
        "pilot_source_run_ids": pilot_run_ids,
        "pilot_cluster_ids": cluster_ids,
        "confirmatory_plan_artifact": plan_artifact,
    }


def load_human_audit_design(
    path: Path, *, expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a frozen plan and return its pre-main human-audit design."""
    path = path.resolve()
    plan = read_bound_json(path, expected_sha256=expected_sha256)
    artifact = plan.pop("_artifact_identity")
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise ValueError(f"plan must use {PLAN_SCHEMA}")
    alpha = _number(plan.get("alpha"), "alpha", positive=True)
    if alpha >= 1:
        raise ValueError("alpha must be below one")
    return _human_design(
        plan, plan_dir=path.parent, alpha=alpha, plan_artifact=artifact,
    )


def _contrast(
    plan_dir: Path, contrast: dict[str, Any], *, alpha: float,
    target_power: float, bootstrap: int, permutations: int, seed: int,
) -> tuple[dict[str, Any], dict[str, float | None]]:
    contrast_id = _nonblank(contrast.get("contrast_id"), "contrast_id")
    contrast_type = contrast.get("type")
    if contrast_type not in {"model", "defense", "adaptivity"}:
        raise ValueError(f"contrast {contrast_id!r} has invalid type")
    results = _path(plan_dir, contrast.get("results"), f"{contrast_id}.results")
    corpora = contrast.get("corpora")
    if not isinstance(corpora, list) or not corpora or any(
        not isinstance(value, str) or not value for value in corpora
    ) or len(set(corpora)) != len(corpora):
        raise ValueError(f"contrast {contrast_id!r} requires unique corpora")
    common = dict(
        results=results, corpus=None, n_resamples=bootstrap, seed=seed,
        n_permutations=permutations,
        assume_exchangeable=contrast.get("assume_exchangeable") is True,
        smallest_effect=None, pilot_cluster_sd=None,
        target_power=target_power, alpha=alpha,
    )
    if contrast_type == "adaptivity":
        left = contrast.get("left")
        right = contrast.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise ValueError(f"contrast {contrast_id!r} lacks left/right selectors")
        if left.get("model_spec") != right.get("model_spec") or left.get("defense") != right.get("defense"):
            raise ValueError("adaptivity selectors must share model_spec and defense")
        report = compare_adaptivity(
            **common, model=_nonblank(left.get("model_spec"), "left.model_spec"),
            defense=_nonblank(left.get("defense"), "left.defense"),
            left_attacker=_nonblank(left.get("attacker"), "left.attacker"),
            right_attacker=_nonblank(right.get("attacker"), "right.attacker"),
        )
    else:
        left = contrast.get("left")
        right = contrast.get("right")
        if not isinstance(left, dict) or not isinstance(right, dict):
            raise ValueError(f"contrast {contrast_id!r} lacks left/right selectors")
        report = compare(
            **common,
            left_model=_nonblank(left.get("model_spec"), "left.model_spec"),
            right_model=_nonblank(right.get("model_spec"), "right.model_spec"),
            left_defense=_nonblank(left.get("defense"), "left.defense"),
            right_defense=_nonblank(right.get("defense"), "right.defense"),
            attacker=_nonblank(left.get("attacker"), "left.attacker"),
        )
        if right.get("attacker") != left.get("attacker"):
            raise ValueError("model/defense contrast selectors must share attacker")
    observed_corpora = set(report["facets"]) | set(report.get("unavailable_facets", {}))
    if observed_corpora != set(corpora):
        raise ValueError(
            f"contrast {contrast_id!r} corpus inventory differs from frozen plan: "
            f"observed={sorted(observed_corpora)!r}, planned={sorted(corpora)!r}"
        )
    hypotheses = contrast.get("hypotheses")
    if not isinstance(hypotheses, list) or not hypotheses or any(
        not isinstance(value, str) or not value for value in hypotheses
    ) or len(set(hypotheses)) != len(hypotheses):
        raise ValueError(f"contrast {contrast_id!r} requires frozen unique hypotheses")
    hypothesis_designs = contrast.get("hypothesis_designs")
    if not isinstance(hypothesis_designs, dict) or set(hypothesis_designs) != set(hypotheses):
        raise ValueError(
            f"contrast {contrast_id!r} requires one frozen pilot/SESOI design per "
            "hypothesis (no global SD reuse)"
        )

    def resolve_metric(local_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        parts = local_id.split("::")
        if len(parts) not in {2, 3, 5}:
            raise ValueError(
                f"hypothesis {local_id!r} must be '<corpus>::<metric>' (only "
                "for a single-policy facet), '<corpus>::<metric>::<policy-token>', "
                "or '<corpus>::<metric>::<policy-token>::<risk>::<modality>'"
            )
        facet = report["facets"].get(parts[0])
        if facet is None:
            return None, None
        if len(parts) == 2:
            policies = facet.get("source_policy_facets") or []
            if len(policies) != 1:
                raise ValueError(
                    f"hypothesis {local_id!r} would pool {len(policies)} source policies"
                )
            metric_result = facet.get("metrics", {}).get(parts[1])
        elif len(parts) == 3:
            metric_result = facet.get("policy_metrics", {}).get(
                f"{parts[2]}::{parts[1]}"
            )
        else:
            metric_result = facet.get("category_metrics", {}).get(
                f"{parts[2]}::{parts[3]}::{parts[4]}"
            )
        if metric_result is None:
            raise ValueError(f"hypothesis {local_id!r} names an unsupported metric")
        return facet, metric_result

    pvalues: dict[str, float | None] = {}
    frozen_design_records: dict[str, Any] = {}
    planned_powered = True
    for local_id in hypotheses:
        parts = local_id.split("::")
        corpus, metric_name = parts[:2]
        facet, metric_result = resolve_metric(local_id)
        value: float | None = None
        design = hypothesis_designs[local_id]
        if not isinstance(design, dict):
            raise ValueError(f"hypothesis design {local_id!r} must be an object")
        sesoi = _number(
            design.get("smallest_effect"), f"{local_id}.smallest_effect", positive=True
        )
        pilot, pilot_sd = _pilot(plan_dir, design)
        required = required_clusters_for_power(
            sesoi, pilot_sd, alpha=alpha, target_power=target_power,
        )
        if design.get("required_unique_clusters") != required:
            raise ValueError(
                f"hypothesis {local_id!r} required_unique_clusters="
                f"{design.get('required_unique_clusters')!r}, recomputed={required}"
            )
        pilot_clusters = pilot.get("cluster_ids")
        if (
            not isinstance(pilot_clusters, list)
            or len(pilot_clusters) != pilot.get("n_unique_clusters")
            or len(set(pilot_clusters)) != len(pilot_clusters)
        ):
            raise ValueError(f"pilot for {local_id!r} lacks unique cluster_ids")
        if metric_name in {"ASR", "conversation_ASR"}:
            expected_metric = "ASR"
        elif metric_name in {"FRR", "over_refusal_rate", "conversation_over_refusal_rate"}:
            expected_metric = "FRR"
        else:
            raise ValueError(f"hypothesis {local_id!r} uses an unsupported endpoint")
        if pilot.get("metric") != expected_metric or pilot.get("corpus") != corpus:
            raise ValueError(
                f"pilot for {local_id!r} does not match its corpus/metric"
            )
        if len(parts) in {3, 5}:
            expected_policy_id, expected_policy_version = parse_source_policy_token(
                parts[2]
            )
        elif metric_result is not None:
            expected_policy_id = metric_result.get("source_policy_id")
            expected_policy_version = metric_result.get("source_policy_version")
        else:
            raise ValueError(
                f"unavailable hypothesis {local_id!r} must name its source policy"
            )
        if metric_result is not None and (
            metric_result.get("source_policy_id") != expected_policy_id
            or metric_result.get("source_policy_version") != expected_policy_version
        ):
            raise ValueError(f"hypothesis {local_id!r} source-policy token mismatches data")
        if (
            pilot.get("source_policy_id") != expected_policy_id
            or pilot.get("source_policy_version") != expected_policy_version
        ):
            raise ValueError(f"pilot for {local_id!r} does not match source policy")
        expected_risk = parts[3] if len(parts) == 5 else None
        expected_modality = parts[4] if len(parts) == 5 else None
        if (
            pilot.get("risk_category") != expected_risk
            or pilot.get("modality") != expected_modality
        ):
            raise ValueError(
                f"pilot for {local_id!r} does not match its risk/modality endpoint"
            )
        if pilot.get("selectors") != {"left": left, "right": right}:
            raise ValueError(f"pilot selectors do not match contrast {contrast_id!r}")
        main_runs: set[str] = set()
        main_clusters: set[str] = set()
        partition_check: dict[str, Any] = {"status": "not_applicable_unpartitioned_fixture"}
        power: dict[str, Any]
        if facet is not None and metric_result is not None:
            main_runs = {facet["left"]["run_id"], facet["right"]["run_id"]}
            main_clusters = set(
                (metric_result.get("pairing_audit") or {}).get(
                    "matched_prompt_intent_cluster_ids", []
                )
            )
            if main_runs & set(pilot["source_run_ids"]):
                raise ValueError(f"pilot/main run overlap for hypothesis {local_id!r}")
            if main_clusters & set(pilot_clusters):
                raise ValueError(f"pilot/main cluster overlap for hypothesis {local_id!r}")
            main_bindings = [
                facet[side].get("partition_plan") for side in ("left", "right")
            ]
            bound_main = [
                value for value in main_bindings
                if isinstance(value, dict) and value.get("status") == "bound"
            ]
            if bound_main:
                if (
                    len(bound_main) != 2 or bound_main[0] != bound_main[1]
                    or bound_main[0].get("partition_role") != "main"
                ):
                    raise ValueError("main contrast arms have inconsistent partition binding")
                pilot_partition = pilot.get("partition_plan")
                if (
                    not isinstance(pilot_partition, dict)
                    or pilot_partition.get("status") != "bound"
                    or pilot_partition.get("partition_role") != "pilot"
                    or (pilot_partition.get("artifact") or {}).get("sha256")
                    != (bound_main[0].get("artifact") or {}).get("sha256")
                ):
                    raise ValueError(
                        f"pilot for {local_id!r} is not bound to the main partition plan"
                    )
                main_assignments = [
                    facet[side].get("partition_assignment")
                    for side in ("left", "right")
                ]
                if (
                    not all(isinstance(value, dict) for value in main_assignments)
                    or main_assignments[0] != main_assignments[1]
                    or main_assignments[0].get("partition_role") != "main"
                    or not main_clusters <= set(
                        main_assignments[0].get("cluster_ids") or []
                    )
                ):
                    raise ValueError("main endpoint clusters escape the frozen main partition")
                partition_check = {
                    "status": "verified_content_addressed_disjoint_partition",
                    "partition_plan_sha256": (
                        bound_main[0].get("artifact") or {}
                    ).get("sha256"),
                    "pilot_role": "pilot",
                    "main_role": "main",
                }
            elif isinstance(pilot.get("partition_plan"), dict):
                raise ValueError(
                    f"pilot for {local_id!r} is partition-bound but main results are not"
                )
            power = power_gate(
                sesoi, pilot_sd, int(metric_result.get("n_clusters") or 0),
                alpha=alpha, target_power=target_power,
            )
            metric_result["preregistered_power_gate"] = power
            candidate = (metric_result.get("permutation_test") or {}).get("p_value")
            if isinstance(candidate, (int, float)):
                value = float(candidate)
        else:
            power = {
                "adequately_powered": False,
                "reason": "planned hypothesis unavailable in completed main artifacts",
            }
        powered = (
            metric_result is not None
            and metric_result.get("status") == "estimated"
            and power.get("adequately_powered") is True
        )
        planned_powered = planned_powered and powered
        frozen_design_records[local_id] = {
            "smallest_effect": sesoi,
            "pilot": pilot["_artifact_identity"],
            "pilot_source_run_ids": pilot["source_run_ids"],
            "pilot_cluster_sd": pilot_sd,
            "required_unique_clusters": required,
            "main_unique_clusters": (
                metric_result.get("n_clusters") if metric_result is not None else 0
            ),
            "pilot_main_run_disjoint": not bool(main_runs & set(pilot["source_run_ids"])),
            "pilot_main_cluster_disjoint": not bool(main_clusters & set(pilot_clusters)),
            "partition_disjointness": partition_check,
            "power_gate": power,
        }
        pvalues[f"{contrast_id}::{local_id}"] = value
    report["preregistered"] = {
        "contrast_id": contrast_id,
        "contrast_type": contrast_type,
        "hypotheses": hypotheses,
        "hypothesis_designs": frozen_design_records,
        "all_planned_metrics_adequately_powered": planned_powered,
    }
    return report, pvalues


def _validated_human_audit(
    path: Path, *, expected_sha256: str, plan_artifact: dict[str, Any],
    design: dict[str, Any], alpha: float,
    required_sensitivity: list[dict[str, str]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    human = read_bound_json(path, expected_sha256=expected_sha256)
    identity = human.pop("_artifact_identity")
    if human.get("schema_version") != "ura-human-audit/1.0":
        raise ValueError("final human audit has an unsupported schema_version")
    if human.get("publishable_real_run") is not True:
        raise ValueError("final human audit is not publishable")
    binding = human.get("confirmatory_plan_artifact")
    if not isinstance(binding, dict) or binding.get("sha256") != plan_artifact["sha256"]:
        raise ValueError("human audit is not bound to this confirmatory plan")
    frozen = human.get("frozen_human_audit_design")
    expected_frozen = {
        "required_unique_clusters": design["required_unique_clusters"],
        "minimum_independent_raters": design["minimum_independent_raters"],
    }
    if frozen != expected_frozen:
        raise ValueError("human audit does not match the frozen cluster/rater design")
    audit = human.get("audit") or {}
    if audit.get("sampled_unique_prompt_intent_clusters") != design["required_unique_clusters"]:
        raise ValueError("human audit does not cover the frozen unique-cluster count")
    if len(human.get("raters") or []) < design["minimum_independent_raters"]:
        raise ValueError("human audit lacks the frozen number of independent raters")
    sensitivity = human.get("primary_effect_sensitivity")
    uncertainty = sensitivity.get("uncertainty") if isinstance(sensitivity, dict) else None
    if (
        not isinstance(uncertainty, dict)
        or uncertainty.get("alpha") != alpha
        or not isinstance(uncertainty.get("n_resamples"), int)
        or uncertainty["n_resamples"] < 1
        or not isinstance(uncertainty.get("seed"), int)
    ):
        raise ValueError("human primary-effect sensitivity lacks frozen bootstrap uncertainty")
    human_rates = (sensitivity.get("model_endpoint_rates") or {}).get(
        "human_consensus", {}
    )
    if not human_rates or any(
        not isinstance(model.get("bootstrap_ci"), dict)
        for models in human_rates.values() for model in models.values()
    ):
        raise ValueError("human-consensus endpoint rates lack cluster-bootstrap CIs")
    paired = sensitivity.get("paired_model_effects")
    if not isinstance(paired, dict) or not paired or any(
        not isinstance(record.get("human_consensus_effect_bootstrap_ci"), dict)
        or not isinstance(
            record.get("human_minus_automated_effect_bootstrap_ci"), dict
        )
        for record in paired.values()
    ):
        raise ValueError("human primary paired-effect sensitivity lacks bootstrap CIs")
    for requirement in required_sensitivity:
        cell_id = requirement["analysis_cell_id"]
        left = requirement["left_model"]
        right = requirement["right_model"]
        cell_rates = human_rates.get(cell_id)
        if (
            not isinstance(cell_rates, dict)
            or any(
                not isinstance((cell_rates.get(model) or {}).get("bootstrap_ci"), dict)
                for model in (left, right)
            )
        ):
            raise ValueError(
                f"human sensitivity does not cover planned model cell {cell_id!r}"
            )
        pair_key = f"{cell_id}::{left}|{right}"
        pair = paired.get(pair_key)
        if (
            not isinstance(pair, dict)
            or not isinstance(pair.get("human_consensus_effect_bootstrap_ci"), dict)
            or not isinstance(
                pair.get("human_minus_automated_effect_bootstrap_ci"), dict
            )
        ):
            raise ValueError(
                f"human sensitivity lacks planned paired effect {pair_key!r}"
            )
    return human, identity


def execute_plan(
    path: Path, *, preliminary: bool = False,
    human_audit_path: Path | None = None,
    human_audit_sha256: str | None = None,
) -> dict[str, Any]:
    path = path.resolve()
    plan = read_bound_json(path)
    artifact_identity = plan.pop("_artifact_identity")
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise ValueError(f"plan must use {PLAN_SCHEMA}")
    plan_id = _nonblank(plan.get("plan_id"), "plan_id")
    evaluation_policy = plan.get("evaluation_policy")
    if not isinstance(evaluation_policy, dict) or set(evaluation_policy) != {
        "policy_id", "version", "sha256",
    }:
        raise ValueError(
            "plan.evaluation_policy must contain exactly policy_id, version, sha256"
        )
    for field in ("policy_id", "version"):
        _nonblank(evaluation_policy.get(field), f"evaluation_policy.{field}")
    policy_digest = _nonblank(
        evaluation_policy.get("sha256"), "evaluation_policy.sha256"
    ).lower()
    if len(policy_digest) != 64 or any(c not in "0123456789abcdef" for c in policy_digest):
        raise ValueError("evaluation_policy.sha256 must be a lowercase SHA-256")
    alpha = _number(plan.get("alpha"), "alpha", positive=True)
    if alpha >= 1:
        raise ValueError("alpha must be below one")
    target_power = _number(plan.get("target_power"), "target_power", positive=True)
    if target_power >= 1:
        raise ValueError("target_power must be below one")
    human_design = _human_design(
        plan, plan_dir=path.parent, alpha=alpha, plan_artifact=artifact_identity,
    )
    bootstrap = plan.get("bootstrap_resamples")
    permutations = plan.get("permutations")
    seed = plan.get("seed")
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (
        bootstrap, permutations, seed,
    )) or bootstrap < 1 or permutations < 1:
        raise ValueError("bootstrap_resamples/permutations must be positive ints; seed int")
    families = plan.get("families")
    if not isinstance(families, list) or not families:
        raise ValueError("plan requires at least one multiplicity family")
    reports: dict[str, dict[str, Any]] = {}
    family_results: dict[str, dict[str, Any]] = {}
    seen_contrasts: set[str] = set()
    for family in families:
        if not isinstance(family, dict):
            raise ValueError("family entries must be objects")
        family_id = _nonblank(family.get("family_id"), "family_id")
        contrasts = family.get("contrasts")
        frozen = family.get("hypotheses")
        if not isinstance(contrasts, list) or not contrasts:
            raise ValueError(f"family {family_id!r} lacks contrasts")
        if not isinstance(frozen, list) or not frozen or len(set(frozen)) != len(frozen):
            raise ValueError(f"family {family_id!r} lacks unique frozen hypotheses")
        pvalues: dict[str, float | None] = {}
        for contrast in contrasts:
            if not isinstance(contrast, dict):
                raise ValueError("contrast entries must be objects")
            contrast_id = _nonblank(contrast.get("contrast_id"), "contrast_id")
            if contrast_id in seen_contrasts:
                raise ValueError(f"duplicate contrast_id {contrast_id!r}")
            seen_contrasts.add(contrast_id)
            report, contrast_p = _contrast(
                path.parent, contrast, alpha=alpha, target_power=target_power,
                bootstrap=bootstrap, permutations=permutations, seed=seed,
            )
            reports[contrast_id] = report
            pvalues.update(contrast_p)
        if set(frozen) != set(pvalues):
            raise ValueError(
                f"family {family_id!r} complete hypothesis inventory mismatch: "
                f"planned_only={sorted(set(frozen)-set(pvalues))!r}, "
                f"derived_only={sorted(set(pvalues)-set(frozen))!r}"
            )
        family_results[family_id] = {
            "method": "holm_bonferroni_complete_frozen_family",
            "alpha": alpha,
            "hypotheses": holm_bonferroni_complete_family(pvalues, alpha=alpha),
            "family_size": len(frozen),
            "frozen_hypothesis_order": frozen,
        }
    all_reports_publishable = all(
        all(
            isinstance(facet.get("publishability_checks"), dict)
            and all(
                value is True for key, value in facet["publishability_checks"].items()
                if key != "adequately_powered"
            )
            for facet in report["facets"].values()
        )
        and report.get("preregistered", {}).get("all_planned_metrics_adequately_powered") is True
        and not report.get("unavailable_facets")
        for report in reports.values()
    )
    all_hypotheses_available = all(
        hypothesis["status"] == "estimated"
        for family in family_results.values()
        for hypothesis in family["hypotheses"].values()
    )
    main_run_ids: set[str] = set()
    main_cluster_ids: set[str] = set()
    for report in reports.values():
        for facet in report["facets"].values():
            main_run_ids.update({facet["left"]["run_id"], facet["right"]["run_id"]})
            for collection in (facet.get("metrics", {}), facet.get("category_metrics", {})):
                for metric in collection.values():
                    main_cluster_ids.update(
                        (metric.get("pairing_audit") or {}).get(
                            "matched_prompt_intent_cluster_ids", []
                        )
                    )
    human_run_overlap = main_run_ids & set(human_design["pilot_source_run_ids"])
    human_cluster_overlap = main_cluster_ids & set(human_design["pilot_cluster_ids"])
    if human_run_overlap or human_cluster_overlap:
        raise ValueError(
            "human-audit pilot overlaps main experiment: "
            f"runs={sorted(human_run_overlap)!r}, clusters={sorted(human_cluster_overlap)!r}"
        )
    human_design["pilot_main_run_disjoint"] = True
    human_design["pilot_main_cluster_disjoint"] = True
    required_human_sensitivity: list[dict[str, str]] = []
    for report in reports.values():
        preregistered = report.get("preregistered") or {}
        if preregistered.get("contrast_type") != "model":
            continue
        for local_id in preregistered.get("hypotheses") or []:
            parts = local_id.split("::")
            facet = report.get("facets", {}).get(parts[0])
            if not isinstance(facet, dict):
                continue
            if len(parts) == 2:
                metric = (facet.get("metrics") or {}).get(parts[1])
            elif len(parts) == 3:
                metric = (facet.get("policy_metrics") or {}).get(
                    f"{parts[2]}::{parts[1]}"
                )
            else:
                metric = (facet.get("category_metrics") or {}).get(
                    f"{parts[2]}::{parts[3]}::{parts[4]}"
                )
            if not isinstance(metric, dict):
                continue
            policy_id = metric.get("source_policy_id")
            policy_version = metric.get("source_policy_version")
            if not isinstance(policy_id, str) or not isinstance(policy_version, str):
                raise ValueError(f"planned human endpoint {local_id!r} lacks source policy")
            required_human_sensitivity.append({
                "hypothesis": local_id,
                "analysis_cell_id": human_analysis_cell_id(
                    metric["source"], policy_id, policy_version,
                    metric.get("risk_category"), metric.get("modality"),
                    metric["metric_alias"],
                ),
                "left_model": facet["left"]["resolved_target"],
                "right_model": facet["right"]["resolved_target"],
            })
    if preliminary:
        if human_audit_path is not None or human_audit_sha256 is not None:
            raise ValueError("preliminary mode cannot bind a human-audit artifact")
        human_audit_identity = None
        human_audit_bound = False
    else:
        if human_audit_path is None or human_audit_sha256 is None:
            raise ValueError(
                "final analysis requires --human-audit and --human-audit-sha256"
            )
        _, human_audit_identity = _validated_human_audit(
            human_audit_path.resolve(), expected_sha256=human_audit_sha256,
            plan_artifact=artifact_identity, design=human_design, alpha=alpha,
            required_sensitivity=required_human_sensitivity,
        )
        human_audit_bound = True
    statistical_publishable = all_reports_publishable and all_hypotheses_available
    return {
        "schema_version": RESULT_SCHEMA,
        "plan_id": plan_id,
        "evaluation_policy": evaluation_policy,
        "plan_artifact": artifact_identity,
        "analysis_source": analysis_source_identity([
            Path(__file__), _REPO_ROOT / "experiments" / "paired_compare.py",
            _REPO_ROOT / "experiments" / "analysis_integrity.py",
            _REPO_ROOT / "src" / "ura" / "metrics.py",
        ]),
        "alpha": alpha,
        "target_power": target_power,
        "analysis_stage": "preliminary" if preliminary else "final_human_bound",
        "human_audit_plan": human_design,
        "human_audit_artifact": human_audit_identity,
        "required_human_sensitivity": required_human_sensitivity,
        "publishable_real_run": statistical_publishable and human_audit_bound,
        "publishability_checks": {
            "all_contrasts_publishable": all_reports_publishable,
            "complete_families_estimable": all_hypotheses_available,
            "plan_and_pilots_content_addressed": True,
            "publishable_human_audit_bound": human_audit_bound,
        },
        "families": family_results,
        "contrasts": reports,
        "unexplained_exclusions": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute an immutable, pilot-powered confirmatory plan"
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--preliminary", action="store_true",
        help="write a non-publishable statistical analysis before human audit",
    )
    parser.add_argument("--human-audit", type=Path)
    parser.add_argument("--human-audit-sha256")
    args = parser.parse_args(argv)
    try:
        result = execute_plan(
            args.plan, preliminary=args.preliminary,
            human_audit_path=args.human_audit,
            human_audit_sha256=args.human_audit_sha256,
        )
    except ValueError as exc:
        print(f"confirmatory analysis validation failed: {exc}", file=sys.stderr)
        return 1
    output = args.output or args.plan.with_name("confirmatory_analysis.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {output}: {len(result['contrasts'])} contrast(s), "
        f"publishable={result['publishable_real_run']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
