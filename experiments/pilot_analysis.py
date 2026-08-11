"""Generate a bounded disjoint-pilot artifact from completed pilot runs.

This command performs no target or judge calls. It reduces paired outcomes to
one mean per source prompt/intent cluster, estimates the sample SD of cluster
differences, and records the event prevalence used to plan the human audit.
The confirmatory driver later proves that pilot run and cluster identities do
not overlap the main analysis.
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
    source_policy_token,
)
from experiments.paired_compare import compare, compare_adaptivity  # noqa: E402

PILOT_SCHEMA = "ura-disjoint-pilot/1.0"


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def generate_pilot(
    results: Path, *, left_model: str, right_model: str,
    left_defense: str = "none", right_defense: str = "none",
    left_attacker: str = "replay", right_attacker: str | None = None,
    corpus: str, metric: str = "ASR", prevalence_source: str = "pooled",
    risk_category: str | None = None, modality: str | None = None,
    source_policy_id: str | None = None,
    source_policy_version: str | None = None,
) -> dict[str, Any]:
    if metric not in {"ASR", "FRR"}:
        raise ValueError("pilot metric must be ASR or FRR")
    if prevalence_source not in {"left", "right", "pooled", "conservative"}:
        raise ValueError("prevalence_source must be left, right, pooled, or conservative")
    if (risk_category is None) != (modality is None):
        raise ValueError("--risk-category and --modality must be supplied together")
    if (source_policy_id is None) != (source_policy_version is None):
        raise ValueError(
            "--source-policy-id and --source-policy-version must be supplied together"
        )
    if risk_category is not None and metric != "ASR":
        raise ValueError("category pilots currently support the harmful ASR endpoint only")
    if right_attacker is not None:
        if left_model != right_model or left_defense != right_defense:
            raise ValueError("adaptivity pilot requires the same model and defense")
        report = compare_adaptivity(
            results, model=left_model, defense=left_defense,
            left_attacker=left_attacker, right_attacker=right_attacker,
            corpus=corpus, n_resamples=1,
        )
    else:
        report = compare(
            results, left_model=left_model, right_model=right_model,
            left_defense=left_defense, right_defense=right_defense,
            attacker=left_attacker, corpus=corpus, n_resamples=1,
        )
    facet = report["facets"][corpus]
    candidate = None
    policy_token = (
        source_policy_token(source_policy_id, source_policy_version)
        if source_policy_id is not None and source_policy_version is not None
        else None
    )
    if risk_category is not None:
        if policy_token is None:
            raise ValueError("category pilots require an exact source policy id/version")
        candidate = facet["category_metrics"].get(
            f"{policy_token}::{risk_category}::{modality}"
        )
    elif policy_token is not None:
        matches = [
            value for name, value in facet["policy_metrics"].items()
            if name.startswith(f"{policy_token}::")
            and value.get("metric_alias") == metric
        ]
        if len(matches) != 1:
            raise ValueError("exact policy endpoint is missing or ambiguous")
        candidate = matches[0]
    else:
        if len(facet.get("source_policy_facets") or []) != 1:
            raise ValueError(
                "pilot endpoint spans multiple source policies; select one exact policy"
            )
        for name, value in facet["metrics"].items():
            if metric == "ASR" and name in {"ASR", "conversation_ASR"}:
                candidate = value
            if metric == "FRR" and name in {
                "over_refusal_rate", "conversation_over_refusal_rate",
            }:
                candidate = value
    if not isinstance(candidate, dict) or candidate.get("status") != "estimated":
        raise ValueError(f"pilot {metric} is not estimable in corpus {corpus!r}")
    sd = candidate.get("cluster_difference_sd")
    summaries = candidate.get("cluster_summaries")
    if (
        not isinstance(sd, (int, float)) or isinstance(sd, bool)
        or not math.isfinite(float(sd)) or float(sd) <= 0
        or not isinstance(summaries, list) or len(summaries) < 2
    ):
        raise ValueError(
            "pilot has fewer than two clusters or zero/undefined cluster-difference "
            "variance; enlarge the disjoint pilot"
        )
    cluster_ids = [str(item["source_cluster_id"]) for item in summaries]
    if len(set(cluster_ids)) != len(cluster_ids):
        raise ValueError("pilot cluster summaries contain duplicate identities")
    left_prevalence = sum(float(item["left_mean"]) for item in summaries) / len(summaries)
    right_prevalence = sum(float(item["right_mean"]) for item in summaries) / len(summaries)
    prevalence = {
        "left": left_prevalence,
        "right": right_prevalence,
        "pooled": (left_prevalence + right_prevalence) / 2,
        "conservative": 0.5,
    }[prevalence_source]
    source_run_ids = sorted({facet["left"]["run_id"], facet["right"]["run_id"]})
    partition_bindings = [facet[side].get("partition_plan") for side in ("left", "right")]
    bound_partitions = [
        value for value in partition_bindings
        if isinstance(value, dict) and value.get("status") == "bound"
    ]
    if bound_partitions:
        if len(bound_partitions) != 2 or bound_partitions[0] != bound_partitions[1]:
            raise ValueError("pilot arms do not share one content-addressed partition plan")
        partition_plan = bound_partitions[0]
        if partition_plan.get("partition_role") != "pilot":
            raise ValueError("pilot runs must use partition_role='pilot'")
        assignments = [facet[side].get("partition_assignment") for side in ("left", "right")]
        if (
            not all(isinstance(value, dict) for value in assignments)
            or assignments[0] != assignments[1]
            or assignments[0].get("partition_role") != "pilot"
            or not set(cluster_ids) <= set(assignments[0].get("cluster_ids") or [])
        ):
            raise ValueError("pilot endpoint clusters are outside its frozen pilot partition")
        partition_assignment = assignments[0]
    else:
        partition_plan = None
        partition_assignment = None
    return {
        "schema_version": PILOT_SCHEMA,
        "disjoint_from_main": True,
        "disjointness_status": "declared_now_verified_against_main_by_confirmatory_driver",
        "source_run_ids": source_run_ids,
        "cluster_ids": sorted(cluster_ids),
        "cluster_population_sha256": _sha256_json(sorted(cluster_ids)),
        "n_unique_clusters": len(cluster_ids),
        "cluster_unit": "source_cluster_id (fallback datapoint_id)",
        "cluster_sd": float(sd),
        "event_prevalence": prevalence,
        "event_prevalence_source": prevalence_source,
        "event_prevalence_provenance": (
            "conservative_max_binomial_variance"
            if prevalence_source == "conservative"
            else "observed_disjoint_pilot_cluster_prevalence"
        ),
        "left_event_prevalence": left_prevalence,
        "right_event_prevalence": right_prevalence,
        "metric": metric,
        "corpus": corpus,
        "risk_category": risk_category,
        "modality": modality,
        "source_policy_id": source_policy_id,
        "source_policy_version": source_policy_version,
        "selectors": {
            "left": {
                "model_spec": left_model, "defense": left_defense,
                "attacker": left_attacker,
            },
            "right": {
                "model_spec": right_model, "defense": right_defense,
                "attacker": right_attacker or left_attacker,
            },
        },
        "paired_analysis_source": report["analysis_source"],
        "partition_plan": partition_plan,
        "partition_assignment": partition_assignment,
        "analysis_source": analysis_source_identity([
            Path(__file__), _REPO_ROOT / "experiments" / "paired_compare.py",
            _REPO_ROOT / "experiments" / "analysis_integrity.py",
            _REPO_ROOT / "src" / "ura" / "metrics.py",
        ]),
        "artifact_root": str(Path(results).resolve()),
        "no_new_target_or_judge_calls": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a content-bound disjoint-pilot variance artifact"
    )
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--left-model", required=True)
    parser.add_argument("--right-model", required=True)
    parser.add_argument("--left-defense", default="none")
    parser.add_argument("--right-defense", default="none")
    parser.add_argument("--left-attacker", default="replay")
    parser.add_argument(
        "--right-attacker", default=None,
        help="set for a replay-vs-adaptive pilot (usually crescendo)",
    )
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--metric", choices=["ASR", "FRR"], default="ASR")
    parser.add_argument("--risk-category")
    parser.add_argument("--modality")
    parser.add_argument("--source-policy-id")
    parser.add_argument("--source-policy-version")
    parser.add_argument(
        "--prevalence-source", choices=["left", "right", "pooled", "conservative"],
        default="conservative",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        artifact = generate_pilot(
            args.results, left_model=args.left_model, right_model=args.right_model,
            left_defense=args.left_defense, right_defense=args.right_defense,
            left_attacker=args.left_attacker, right_attacker=args.right_attacker,
            corpus=args.corpus, metric=args.metric,
            prevalence_source=args.prevalence_source,
            risk_category=args.risk_category, modality=args.modality,
            source_policy_id=args.source_policy_id,
            source_policy_version=args.source_policy_version,
        )
    except ValueError as exc:
        print(f"pilot analysis validation failed: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(
        f"wrote {args.output}: clusters={artifact['n_unique_clusters']}, "
        f"cluster_sd={artifact['cluster_sd']:.6g}, sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
