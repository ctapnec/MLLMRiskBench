"""Execute a content-bound, complete-family confirmatory analysis plan.

The plan is frozen before the main run.  Each contrast carries its own SESOI,
disjoint-pilot variance artifact, required unique-cluster count and exact set of
hypotheses.  Missing cells remain members of their multiplicity family instead
of silently reducing the Holm denominator.
"""
from __future__ import annotations

import argparse
import hashlib
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
    human_analysis_arm_id,
    human_analysis_cell_id,
    parse_source_policy_token,
    read_bound_json,
    validate_analysis_source_identity,
)
from experiments.paired_compare import compare, compare_adaptivity  # noqa: E402
from experiments.pilot_analysis import (  # noqa: E402
    REQUIRED_PILOT_CHECKS,
    paired_analysis_design,
)
from ura.metrics import (  # noqa: E402
    holm_bonferroni_complete_family,
    power_gate,
    required_clusters_for_power,
    required_clusters_for_proportion_precision,
)

PLAN_SCHEMA = "ura-confirmatory-plan/1.0"
RESULT_SCHEMA = "ura-confirmatory-analysis/1.0"
EVALUATION_POLICY_SCHEMA = "ura-evaluation-policy/1.0"
_MAX_EVALUATION_POLICY_BYTES = 64 * 1024
_PILOT_ANALYSIS_SOURCES = {
    "experiments/analysis_integrity.py",
    "experiments/paired_compare.py",
    "experiments/pilot_analysis.py",
    "src/ura/metrics.py",
}
_HUMAN_ANALYSIS_SOURCES = {
    "experiments/human_audit.py",
    "experiments/transfer_matrix.py",
    "src/ura/metrics.py",
}


def _validate_exact_analysis_sources(
    identity: Any, expected: set[str], *, label: str,
) -> dict[str, Any]:
    observed = validate_analysis_source_identity(identity)
    paths = {record["path"] for record in observed["files"]}
    if paths != expected:
        raise ValueError(
            f"{label} analysis-source inventory differs from {sorted(expected)!r}"
        )
    return observed


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


def _evaluation_policy(
    value: Any,
) -> tuple[dict[str, str], dict[str, Any], dict[str, Any]]:
    """Resolve and verify the small, repository-relative interpretation policy."""
    required = {"artifact", "bytes", "policy_id", "version", "sha256"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(
            "plan.evaluation_policy must contain exactly artifact, bytes, "
            "policy_id, version, sha256"
        )
    policy_id = _nonblank(value.get("policy_id"), "evaluation_policy.policy_id")
    version = _nonblank(value.get("version"), "evaluation_policy.version")
    expected_digest = _nonblank(
        value.get("sha256"), "evaluation_policy.sha256"
    )
    if (
        expected_digest != expected_digest.lower()
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        raise ValueError("evaluation_policy.sha256 must be a lowercase SHA-256")
    expected_bytes = value.get("bytes")
    if (
        not isinstance(expected_bytes, int)
        or isinstance(expected_bytes, bool)
        or not 0 < expected_bytes <= _MAX_EVALUATION_POLICY_BYTES
    ):
        raise ValueError(
            "evaluation_policy.bytes must be an integer between 1 and "
            f"{_MAX_EVALUATION_POLICY_BYTES}"
        )

    locator = _nonblank(value.get("artifact"), "evaluation_policy.artifact")
    logical = Path(locator)
    if (
        "\\" in locator
        or logical.is_absolute()
        or logical.drive
        or logical.as_posix() != locator
        or any(part in {"", ".", ".."} for part in logical.parts)
    ):
        raise ValueError(
            "evaluation_policy.artifact must be a canonical repository-relative path"
        )
    unresolved = _REPO_ROOT.joinpath(*logical.parts)
    current = _REPO_ROOT
    for part in logical.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("evaluation_policy.artifact must not traverse a symlink")
    resolved = unresolved.resolve()
    try:
        canonical = resolved.relative_to(_REPO_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError("evaluation_policy.artifact escapes the repository") from exc
    if canonical != locator:
        raise ValueError(
            "evaluation_policy.artifact must be a canonical repository-relative path"
        )
    if not resolved.is_file() or resolved.stat().st_size != expected_bytes:
        raise ValueError(
            "evaluation_policy artifact byte length differs from the frozen plan"
        )

    payload = read_bound_json(resolved, expected_sha256=expected_digest)
    raw_identity = payload.pop("_artifact_identity")
    if raw_identity.get("bytes") != expected_bytes:
        raise ValueError(
            "evaluation_policy artifact byte length differs from the frozen plan"
        )
    if payload.get("schema_version") != EVALUATION_POLICY_SCHEMA:
        raise ValueError(
            f"evaluation_policy artifact must use {EVALUATION_POLICY_SCHEMA}"
        )
    if payload.get("policy_id") != policy_id or payload.get("version") != version:
        raise ValueError(
            "evaluation_policy artifact policy_id/version differ from the frozen plan"
        )
    content_sha256 = hashlib.sha256(json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    identity = {
        "path": locator,
        "bytes": expected_bytes,
        "sha256": expected_digest,
        "content_sha256": content_sha256,
    }
    declared = {
        "policy_id": policy_id,
        "version": version,
        "sha256": expected_digest,
    }
    return declared, identity, payload


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
    cluster_ids = payload.get("cluster_ids")
    if (
        not isinstance(cluster_ids, list)
        or len(cluster_ids) != n
        or any(not isinstance(value, str) or not value for value in cluster_ids)
        or len(set(cluster_ids)) != n
    ):
        raise ValueError(f"pilot {artifact} lacks its exact unique-cluster inventory")
    expected_population_digest = hashlib.sha256(json.dumps(
        sorted(cluster_ids), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    if payload.get("cluster_population_sha256") != expected_population_digest:
        raise ValueError(f"pilot {artifact} has an invalid cluster-population digest")
    admissibility = payload.get("admissibility")
    if (
        not isinstance(admissibility, dict)
        or admissibility.get("status") != "eligible_real_complete_exclusion_free_pilot"
        or admissibility.get("mock_free") is not True
        or not isinstance(admissibility.get("checks"), dict)
        or set(admissibility["checks"]) != REQUIRED_PILOT_CHECKS
        or any(value is not True for value in admissibility["checks"].values())
        or not isinstance(admissibility.get("endpoint_pairing_exclusions"), dict)
        or any(
            admissibility["endpoint_pairing_exclusions"].get(field) != 0
            for field in (
                "left_only_units", "right_only_units",
                "static_input_mismatch_units", "unexplained_exclusions",
            )
        )
    ):
        raise ValueError(
            f"pilot {artifact} is not an admissible real, complete, exclusion-free pilot"
        )
    analysis_design = payload.get("analysis_design")
    if not isinstance(analysis_design, dict):
        raise ValueError(f"pilot {artifact} lacks its normalized analysis design")
    expected_design_digest = hashlib.sha256(json.dumps(
        analysis_design, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    if payload.get("analysis_design_sha256") != expected_design_digest:
        raise ValueError(f"pilot {artifact} has an invalid analysis-design digest")
    _validate_exact_analysis_sources(
        payload.get("analysis_source"), _PILOT_ANALYSIS_SOURCES, label="pilot"
    )
    return payload, sd


def _human_sensitivity_requirements(
    plan: dict[str, Any], *, plan_dir: Path,
) -> list[dict[str, Any]]:
    """Normalize every planned endpoint into pre-labelling arm coverage."""
    families = plan.get("families")
    if not isinstance(families, list) or not families:
        raise ValueError("plan requires families before human-audit preparation")
    requirements: list[dict[str, Any]] = []
    seen_contrasts: set[str] = set()
    for family in families:
        if not isinstance(family, dict) or not isinstance(family.get("contrasts"), list):
            raise ValueError("human-audit planning found an invalid contrast family")
        for contrast in family["contrasts"]:
            if not isinstance(contrast, dict):
                raise ValueError("human-audit planning found a malformed contrast")
            if contrast.get("type") not in {"model", "defense", "adaptivity"}:
                continue
            contrast_id = _nonblank(contrast.get("contrast_id"), "contrast_id")
            if contrast_id in seen_contrasts:
                raise ValueError(f"duplicate contrast_id {contrast_id!r}")
            seen_contrasts.add(contrast_id)
            left, right = contrast.get("left"), contrast.get("right")
            hypotheses = contrast.get("hypotheses")
            designs = contrast.get("hypothesis_designs")
            if (
                not isinstance(left, dict)
                or not isinstance(right, dict)
                or not isinstance(hypotheses, list)
                or not hypotheses
                or any(not isinstance(value, str) or not value for value in hypotheses)
                or not isinstance(designs, dict)
                or set(designs) != set(hypotheses)
            ):
                raise ValueError(f"contrast {contrast_id!r} is incomplete")
            for local_id in hypotheses:
                parts = local_id.split("::")
                if len(parts) not in {2, 3, 5}:
                    raise ValueError(f"invalid model hypothesis {local_id!r}")
                metric_name = parts[1]
                if metric_name in {"ASR", "conversation_ASR"}:
                    endpoint, expected = "ASR", "refuse"
                elif metric_name in {
                    "FRR", "over_refusal_rate", "conversation_over_refusal_rate",
                }:
                    endpoint, expected = "FRR", "benign"
                else:
                    raise ValueError(f"unsupported human endpoint {local_id!r}")
                if len(parts) in {3, 5}:
                    policy_id, policy_version = parse_source_policy_token(parts[2])
                else:
                    pilot, _ = _pilot(plan_dir, designs[local_id])
                    policy_id = _nonblank(
                        pilot.get("source_policy_id"), "pilot.source_policy_id"
                    )
                    policy_version = _nonblank(
                        pilot.get("source_policy_version"),
                        "pilot.source_policy_version",
                    )
                risk = parts[3] if len(parts) == 5 else None
                modality = parts[4] if len(parts) == 5 else None
                for side, selector in (("left", left), ("right", right)):
                    requirement_id = f"{contrast_id}::{local_id}::{side}"
                    requirements.append({
                        "requirement_id": requirement_id,
                        "hypothesis": f"{contrast_id}::{local_id}",
                        "side": side,
                        "corpus": parts[0],
                        "model_spec": _nonblank(
                            selector.get("model_spec"), f"{side}.model_spec"
                        ),
                        "defense": _nonblank(
                            selector.get("defense"), f"{side}.defense"
                        ),
                        "attacker": _nonblank(
                            selector.get("attacker"), f"{side}.attacker"
                        ),
                        "source_policy_id": policy_id,
                        "source_policy_version": policy_version,
                        "risk_category": risk,
                        "modality": modality,
                        "metric": endpoint,
                        "expected_population": expected,
                    })
    identifiers = [item["requirement_id"] for item in requirements]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("human sensitivity requirements contain duplicate identities")
    return sorted(requirements, key=lambda item: item["requirement_id"])


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
        expected_population_digest = hashlib.sha256(json.dumps(
            sorted(cluster_ids), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        if pilot.get("cluster_population_sha256") != expected_population_digest:
            raise ValueError("human-audit pilot has an invalid cluster-population digest")
        _validate_exact_analysis_sources(
            pilot.get("analysis_source"), _PILOT_ANALYSIS_SOURCES,
            label="human-audit pilot",
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
    sensitivity_requirements = _human_sensitivity_requirements(
        plan, plan_dir=plan_dir,
    )
    population_cells = {
        (
            item["corpus"], item["source_policy_id"],
            item["source_policy_version"], item.get("risk_category"),
            item.get("modality"), item["metric"], item["expected_population"],
        )
        for item in sensitivity_requirements
    }
    if not population_cells or required < 2 * len(population_cells):
        raise ValueError(
            "human-audit precision design cannot provide at least two clusters "
            "to every required population cell"
        )
    balanced_support_floor = max(2, required // len(population_cells))
    validity_gate = human_plan.get("validity_gate")
    if not isinstance(validity_gate, dict) or set(validity_gate) != {
        "minimum_shared_clusters_per_required_cell",
        "minimum_endpoint_agreement",
        "minimum_inter_rater_endpoint_agreement",
    }:
        raise ValueError(
            "human_audit.validity_gate must freeze balanced shared-cluster "
            "support, automated-consensus agreement, and inter-rater agreement"
        )
    minimum_shared = validity_gate.get(
        "minimum_shared_clusters_per_required_cell"
    )
    minimum_agreement = validity_gate.get("minimum_endpoint_agreement")
    minimum_inter_rater_agreement = validity_gate.get(
        "minimum_inter_rater_endpoint_agreement"
    )
    if (
        not isinstance(minimum_shared, int) or isinstance(minimum_shared, bool)
        or minimum_shared < balanced_support_floor or minimum_shared > required
    ):
        raise ValueError(
            "human_audit validity support must be an integer between the "
            f"balanced population-cell floor ({balanced_support_floor}) and "
            "required_unique_clusters"
        )
    if (
        not isinstance(minimum_agreement, (int, float))
        or isinstance(minimum_agreement, bool)
        or not 0 < float(minimum_agreement) <= 1
    ):
        raise ValueError(
            "human_audit minimum_endpoint_agreement must lie in (0,1]"
        )
    if (
        not isinstance(minimum_inter_rater_agreement, (int, float))
        or isinstance(minimum_inter_rater_agreement, bool)
        or not 0 < float(minimum_inter_rater_agreement) <= 1
    ):
        raise ValueError(
            "human_audit minimum_inter_rater_endpoint_agreement must lie in (0,1]"
        )
    return {
        "required_unique_clusters": required,
        "precision_half_width": half_width,
        "pilot_event_prevalence": prevalence,
        "event_prevalence_provenance": prevalence_provenance,
        "minimum_independent_raters": minimum_raters,
        "validity_gate": {
            "minimum_shared_clusters_per_required_cell": minimum_shared,
            "minimum_endpoint_agreement": float(minimum_agreement),
            "minimum_inter_rater_endpoint_agreement": float(
                minimum_inter_rater_agreement
            ),
            "minimum_required_cell_support_floor": balanced_support_floor,
            "n_required_population_cells": len(population_cells),
        },
        "pilot_artifact": pilot["_artifact_identity"] if pilot is not None else None,
        "pilot_source_run_ids": pilot_run_ids,
        "pilot_cluster_ids": cluster_ids,
        "confirmatory_plan_artifact": plan_artifact,
        "sensitivity_requirements": sensitivity_requirements,
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
    family_size: int,
) -> tuple[dict[str, Any], dict[str, float | None]]:
    contrast_id = _nonblank(contrast.get("contrast_id"), "contrast_id")
    contrast_type = contrast.get("type")
    if contrast_type not in {"model", "defense", "adaptivity"}:
        raise ValueError(f"contrast {contrast_id!r} has invalid type")
    if contrast.get("assume_exchangeable") is not True:
        raise ValueError(
            f"confirmatory contrast {contrast_id!r} must explicitly assert paired "
            "sign-flip exchangeability; otherwise it is descriptive only"
        )
    per_hypothesis_alpha = alpha / family_size
    if 1 / (permutations + 1) > per_hypothesis_alpha:
        minimum = math.ceil(1 / per_hypothesis_alpha - 1)
        raise ValueError(
            f"contrast {contrast_id!r} requires at least {minimum} permutations "
            f"to resolve the first Holm threshold {per_hypothesis_alpha}"
        )
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
    hypothesis_endpoint_roles: dict[str, str] = {}
    planned_powered = True
    for local_id in hypotheses:
        parts = local_id.split("::")
        corpus, metric_name = parts[:2]
        facet, metric_result = resolve_metric(local_id)
        value: float | None = None
        design = hypothesis_designs[local_id]
        if not isinstance(design, dict):
            raise ValueError(f"hypothesis design {local_id!r} must be an object")
        endpoint_role = design.get("endpoint_role")
        if endpoint_role not in {"primary", "secondary"}:
            raise ValueError(
                f"hypothesis design {local_id!r} requires endpoint_role=primary|secondary"
            )
        if facet is not None:
            inventories = [
                (facet.get(side) or {}).get("source_metric_inventory") or []
                for side in ("left", "right")
            ]
            if any(not isinstance(inventory, list) for inventory in inventories):
                raise ValueError(f"hypothesis {local_id!r} has invalid source metrics")
            proxy_source_metrics = {
                "mmsafety_official_attack_rate", "mossbench_refusal_rate",
            }
            is_secondary_proxy = any(
                isinstance(entry, dict)
                and entry.get("required_metric") in proxy_source_metrics
                for inventory in inventories for entry in inventory
            )
            if is_secondary_proxy and endpoint_role != "secondary":
                raise ValueError(
                    f"hypothesis {local_id!r} is a common URA proxy for a benchmark "
                    "with a distinct official evaluator and cannot be labelled primary"
                )
        sesoi = _number(
            design.get("smallest_effect"), f"{local_id}.smallest_effect", positive=True
        )
        if sesoi > 1:
            raise ValueError(
                f"{local_id}.smallest_effect must not exceed one for a rate difference"
            )
        pilot, pilot_sd = _pilot(plan_dir, design)
        required = required_clusters_for_power(
            sesoi, pilot_sd, alpha=alpha, target_power=target_power,
            family_size=family_size,
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
            main_analysis_design = paired_analysis_design(facet)
            if pilot.get("analysis_design") != main_analysis_design:
                raise ValueError(
                    f"pilot analysis design does not match main contrast {contrast_id!r}"
                )
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
                alpha=alpha, target_power=target_power, family_size=family_size,
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
            "endpoint_role": endpoint_role,
            "smallest_effect": sesoi,
            "pilot": pilot["_artifact_identity"],
            "pilot_source_run_ids": pilot["source_run_ids"],
            "pilot_cluster_sd": pilot_sd,
            "pilot_main_analysis_design_sha256": pilot["analysis_design_sha256"],
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
        hypothesis_endpoint_roles[f"{contrast_id}::{local_id}"] = endpoint_role
    report["preregistered"] = {
        "contrast_id": contrast_id,
        "contrast_type": contrast_type,
        "hypotheses": hypotheses,
        "hypothesis_designs": frozen_design_records,
        "hypothesis_endpoint_roles": hypothesis_endpoint_roles,
        "all_planned_metrics_adequately_powered": planned_powered,
    }
    return report, pvalues


def _validated_human_audit(
    path: Path, *, expected_sha256: str, plan_artifact: dict[str, Any],
    design: dict[str, Any], alpha: float, bootstrap_resamples: int, seed: int,
    required_sensitivity: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    human = read_bound_json(path, expected_sha256=expected_sha256)
    identity = human.pop("_artifact_identity")
    if human.get("schema_version") != "ura-human-audit/1.0":
        raise ValueError("final human audit has an unsupported schema_version")
    if human.get("publishable_real_run") is not True:
        raise ValueError("final human audit is not publishable")
    _validate_exact_analysis_sources(
        human.get("analysis_source"), _HUMAN_ANALYSIS_SOURCES,
        label="human audit",
    )
    binding = human.get("confirmatory_plan_artifact")
    if not isinstance(binding, dict) or binding.get("sha256") != plan_artifact["sha256"]:
        raise ValueError("human audit is not bound to this confirmatory plan")
    frozen = human.get("frozen_human_audit_design")
    expected_frozen = {
        "required_unique_clusters": design["required_unique_clusters"],
        "minimum_independent_raters": design["minimum_independent_raters"],
        "minimum_shared_clusters_per_required_cell": design["validity_gate"][
            "minimum_shared_clusters_per_required_cell"
        ],
        "minimum_endpoint_agreement": design["validity_gate"][
            "minimum_endpoint_agreement"
        ],
        "minimum_inter_rater_endpoint_agreement": design["validity_gate"][
            "minimum_inter_rater_endpoint_agreement"
        ],
        "minimum_required_cell_support_floor": design["validity_gate"][
            "minimum_required_cell_support_floor"
        ],
        "n_required_population_cells": design["validity_gate"][
            "n_required_population_cells"
        ],
    }
    if frozen != expected_frozen:
        raise ValueError("human audit does not match the frozen cluster/rater design")
    audit = human.get("audit") or {}
    if audit.get("sampled_unique_prompt_intent_clusters") != design["required_unique_clusters"]:
        raise ValueError("human audit does not cover the frozen unique-cluster count")
    if len(human.get("raters") or []) < design["minimum_independent_raters"]:
        raise ValueError("human audit lacks the frozen number of independent raters")
    labels_artifact = human.get("completed_labels_artifact")
    if (
        not isinstance(labels_artifact, dict)
        or set(labels_artifact) != {"file", "bytes", "sha256"}
        or not isinstance(labels_artifact.get("file"), str)
        or not labels_artifact["file"].strip()
        or isinstance(labels_artifact.get("bytes"), bool)
        or not isinstance(labels_artifact.get("bytes"), int)
        or labels_artifact["bytes"] <= 0
        or not isinstance(labels_artifact.get("sha256"), str)
        or len(labels_artifact["sha256"]) != 64
        or labels_artifact["sha256"] != labels_artifact["sha256"].lower()
        or any(character not in "0123456789abcdef" for character in labels_artifact["sha256"])
    ):
        raise ValueError("human audit lacks its content-addressed completed labels CSV")
    sensitivity = human.get("primary_effect_sensitivity")
    uncertainty = sensitivity.get("uncertainty") if isinstance(sensitivity, dict) else None
    if (
        not isinstance(uncertainty, dict)
        or uncertainty.get("alpha") != alpha
        or uncertainty.get("n_resamples") != bootstrap_resamples
        or uncertainty.get("seed") != seed
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
    validity_gate = human.get("human_validity_gate")
    expected_gate = design["validity_gate"]
    gate_cells = validity_gate.get("cells") if isinstance(validity_gate, dict) else None
    expected_requirement_ids = {
        requirement["requirement_id"]
        for requirement in design["sensitivity_requirements"]
    }
    if (
        not isinstance(validity_gate, dict)
        or validity_gate.get("status") != "passed"
        or validity_gate.get("all_required_arm_cells_passed") is not True
        or validity_gate.get("minimum_shared_clusters_per_required_cell")
        != expected_gate["minimum_shared_clusters_per_required_cell"]
        or validity_gate.get("minimum_endpoint_agreement")
        != expected_gate["minimum_endpoint_agreement"]
        or validity_gate.get("minimum_inter_rater_endpoint_agreement")
        != expected_gate["minimum_inter_rater_endpoint_agreement"]
        or validity_gate.get("minimum_required_cell_support_floor")
        != expected_gate["minimum_required_cell_support_floor"]
        or validity_gate.get("n_required_population_cells")
        != expected_gate["n_required_population_cells"]
        or validity_gate.get("full_rater_coverage") is not True
        or validity_gate.get("all_inter_rater_pairs_passed") is not True
        or not isinstance(gate_cells, dict)
        or set(gate_cells) != expected_requirement_ids
    ):
        raise ValueError("human audit does not pass the frozen validity gate")
    rate_sensitivity = sensitivity.get("human_minus_automated_endpoint_rates") or {}
    arm_metadata = sensitivity.get("analysis_arm_metadata") or {}
    cell_metadata = sensitivity.get("analysis_cell_metadata") or {}
    for requirement in design["sensitivity_requirements"]:
        requirement_id = requirement["requirement_id"]
        matching_cells = [
            cell_id for cell_id, metadata in cell_metadata.items()
            if metadata.get("source_policy_id") == requirement["source_policy_id"]
            and metadata.get("source_policy_version")
            == requirement["source_policy_version"]
            and metadata.get("risk_category") == requirement.get("risk_category")
            and metadata.get("modality") == requirement.get("modality")
            and metadata.get("metric") == requirement["metric"]
        ]
        if len(matching_cells) != 1:
            raise ValueError(
                f"human validity requirement {requirement_id!r} does not bind "
                "one realized analysis cell"
            )
        cell_id = matching_cells[0]
        matching_arms = [
            arm_id for arm_id, metadata in arm_metadata.items()
            if metadata.get("model_spec") == requirement["model_spec"]
            and metadata.get("defense") == requirement["defense"]
            and metadata.get("attacker") == requirement["attacker"]
        ]
        if len(matching_arms) != 1:
            raise ValueError(
                f"human validity requirement {requirement_id!r} does not bind "
                "one realized arm"
            )
        arm_id = matching_arms[0]
        observed = (rate_sensitivity.get(cell_id) or {}).get(arm_id) or {}
        recorded = gate_cells[requirement_id]
        n_shared = observed.get("n_shared_unique_clusters")
        agreement = observed.get("endpoint_event_agreement")
        if (
            recorded.get("analysis_cell_id") != cell_id
            or recorded.get("analysis_arm_id") != arm_id
            or recorded.get("n_shared_unique_clusters") != n_shared
            or recorded.get("endpoint_event_agreement") != agreement
            or not isinstance(n_shared, int)
            or n_shared < expected_gate["minimum_shared_clusters_per_required_cell"]
            or not isinstance(agreement, (int, float))
            or isinstance(agreement, bool)
            or float(agreement) < expected_gate["minimum_endpoint_agreement"]
            or recorded.get("passed") is not True
        ):
            raise ValueError(
                f"human validity requirement {requirement_id!r} failed or drifted"
            )
    for requirement in required_sensitivity:
        cell_id = requirement["analysis_cell_id"]
        left = requirement["analysis_left_arm"]
        right = requirement["analysis_right_arm"]
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
    evaluation_policy, evaluation_policy_artifact, evaluation_policy_content = (
        _evaluation_policy(plan.get("evaluation_policy"))
    )
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
    seen_families: set[str] = set()
    for family in families:
        if not isinstance(family, dict):
            raise ValueError("family entries must be objects")
        family_id = _nonblank(family.get("family_id"), "family_id")
        if family_id in seen_families:
            raise ValueError(f"duplicate family_id {family_id!r}")
        seen_families.add(family_id)
        family_endpoint_role = family.get("endpoint_role")
        if family_endpoint_role not in {"primary", "secondary"}:
            raise ValueError(
                f"family {family_id!r} requires endpoint_role=primary|secondary"
            )
        contrasts = family.get("contrasts")
        frozen = family.get("hypotheses")
        if not isinstance(contrasts, list) or not contrasts:
            raise ValueError(f"family {family_id!r} lacks contrasts")
        if (
            not isinstance(frozen, list)
            or not frozen
            or any(not isinstance(value, str) or not value for value in frozen)
            or len(set(frozen)) != len(frozen)
        ):
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
                family_size=len(frozen),
            )
            reports[contrast_id] = report
            pvalues.update(contrast_p)
            roles = (report.get("preregistered") or {}).get(
                "hypothesis_endpoint_roles", {}
            )
            if any(role != family_endpoint_role for role in roles.values()):
                raise ValueError(
                    f"family {family_id!r} mixes or mislabels endpoint roles"
                )
        if set(frozen) != set(pvalues):
            raise ValueError(
                f"family {family_id!r} complete hypothesis inventory mismatch: "
                f"planned_only={sorted(set(frozen)-set(pvalues))!r}, "
                f"derived_only={sorted(set(pvalues)-set(frozen))!r}"
            )
        family_results[family_id] = {
            "method": "holm_bonferroni_complete_frozen_family",
            "alpha": alpha,
            "endpoint_role": family_endpoint_role,
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
    required_human_sensitivity: list[dict[str, Any]] = []
    for report in reports.values():
        preregistered = report.get("preregistered") or {}
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
            planned_left = human_analysis_arm_id(
                facet["left"]["model_spec"], facet["left"]["resolved_target"],
                facet["left"]["defense"], facet["left"]["attacker"],
            )
            planned_right = human_analysis_arm_id(
                facet["right"]["model_spec"], facet["right"]["resolved_target"],
                facet["right"]["defense"], facet["right"]["attacker"],
            )
            analysis_left, analysis_right = sorted((planned_left, planned_right))
            required_human_sensitivity.append({
                "hypothesis": local_id,
                "analysis_cell_id": human_analysis_cell_id(
                    metric["source"], policy_id, policy_version,
                    metric.get("risk_category"), metric.get("modality"),
                    metric["metric_alias"],
                ),
                "planned_left_arm": planned_left,
                "planned_right_arm": planned_right,
                "analysis_left_arm": analysis_left,
                "analysis_right_arm": analysis_right,
                "analysis_to_planned_effect_multiplier": (
                    1 if (analysis_left, analysis_right) == (planned_left, planned_right)
                    else -1
                ),
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
            bootstrap_resamples=bootstrap, seed=seed,
            required_sensitivity=required_human_sensitivity,
        )
        human_audit_bound = True
    statistical_publishable = all_reports_publishable and all_hypotheses_available
    return {
        "schema_version": RESULT_SCHEMA,
        "plan_id": plan_id,
        "evaluation_policy": evaluation_policy,
        "evaluation_policy_artifact": evaluation_policy_artifact,
        "evaluation_policy_content": evaluation_policy_content,
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
            "evaluation_policy_content_addressed": True,
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
