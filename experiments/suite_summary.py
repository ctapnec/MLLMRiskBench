"""Build a broad-roster evidence inventory without a universal safety score.

Runner cells are admitted through the same content-addressed completed-grid
validator used by measured figures.  Source-native evaluator envelopes are
admitted through :mod:`experiments.native_import`.  The output keeps every
rate in its exact benchmark/policy/modality/model condition and retains native
aggregates on their original, per-run scales.
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

from experiments.figure_results import _load_cells  # noqa: E402
from experiments.native_import import load_native_run  # noqa: E402
from ura.adapters._native_artifacts import NativeEngineRun  # noqa: E402


SUITE_SCHEMA = "ura-suite-evidence/1"
_MAX_SOURCE_CONFIG_BYTES = 1024 * 1024
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
_EXPECTED_CONVERTER_FAMILIES = frozenset({
    "advbench",
    "agentharm",
    "bipia",
    "cyberseceval",
    "figstep",
    "gptgeochat",
    "harmbench",
    "injecagent",
    "jailbreakbench",
    "jailbreakv",
    "jalmbench",
    "mllmguard",
    "mmsafety",
    "mossbench",
    "rjudge",
    "siuo",
    "strongreject",
    "videosafetybench",
    "vlsbench",
})

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
    if metric in {"ASR", "refusal_rate"}:
        return "unsafe_response_rate"
    if metric == "ISR":
        # Runner ISR is the harmful-response rate restricted to rows carrying
        # an indirect-injection risk tag.  It does not observe whether an
        # injected goal executed, so it must not inherit a source-native goal-
        # success interpretation.
        return "unsafe_response_rate"
    if metric in {"over_refusal_rate", "conversation_over_refusal_rate"}:
        return "benign_refusal_rate"
    if metric in {
        "conversation_ASR",
        "robust_refusal_rate",
        "median_turns_to_break",
        "restricted_mean_turns_to_break",
        "kaplan_meier_survival",
    } or metric.startswith("survival_"):
        return "adaptive_compromise"
    if metric in {"strongreject", "conversation_strongreject_max"}:
        return "graded_risk"
    if metric == "source_metric_implementation_coverage":
        return "coverage_conformance"
    if metric.startswith(("rjudge_", "gptgeochat_")):
        return "classification_quality"
    return "source_specific_or_specialized"


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
        return [
            "classification_quality"
            if identity["source_metric_family"] is not None
            else "coverage_conformance"
        ]
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


def _descriptive_endpoint(
    identity: dict[str, Any], rows: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Return an exact-stratum static rate, never a cross-stratum estimate."""

    if not identity["common_metrics_eligible"]:
        return None
    if identity["execution_mode"] == "live_response_conditioned":
        endpoint = (
            "conversation_ASR"
            if identity["expected_behavior"] == "refuse"
            else "conversation_over_refusal_rate"
        )
        return {
            "endpoint": endpoint,
            "value": None,
            "reason": "turn rows require trajectory-level aggregation; use aggregate_results",
        }
    if identity["expected_behavior"] == "refuse":
        endpoint = "ASR"
        positive = "violation"
    else:
        endpoint = "over_refusal_rate"
        positive = "over_refusal"
    cluster_events: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        raw = row["raw"]
        cluster_id = str(raw.get("source_cluster_id") or raw["datapoint_id"])
        cluster_events[cluster_id].append(float(row["label"] == positive))
    cluster_means = [
        sum(events) / len(events) for events in cluster_events.values()
    ]
    return {
        "endpoint": endpoint,
        "n_event_records": sum(row["label"] == positive for row in rows),
        "n_records": len(rows),
        "n_source_clusters": len(cluster_means),
        "value": sum(cluster_means) / len(cluster_means),
        "weighting": "equal_source_prompt_intent_cluster",
        "uncertainty": None,
        "qualification": (
            "descriptive exact-stratum equal-cluster rate; no cross-stratum pooling"
        ),
    }


def summarize_runner_cells(cells: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    aggregate_results: list[dict[str, Any]] = []
    seen_run_ids: set[str] = set()

    for cell in cells:
        if cell["run_id"] in seen_run_ids:
            raise ValueError(f"duplicate completed runner run_id: {cell['run_id']}")
        seen_run_ids.add(cell["run_id"])
        run = cell["manifest"]["config"]["run"]
        sources: set[str] = set()
        policies: dict[str, dict[str, Any]] = {}
        modalities: set[str] = set()
        for row in cell["judgments"]:
            identity = _stratum_identity(cell, row)
            token = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            grouped.setdefault(token, (identity, []))[1].append(row)
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
            aggregate_results.append({
                "run_id": cell["run_id"],
                "model_spec": run["model_spec"],
                "resolved_model": cell["model"],
                "corpus_arm": run["corpus"],
                "attacker": run["attacker"],
                "defense": run["defense"],
                "metric": result["metric"],
                "semantic_family": _metric_family(result["metric"]),
                "value": result["value"],
                "ci_low": result.get("ci_low"),
                "ci_high": result.get("ci_high"),
                "n": result["n"],
                "group_by": result["group_by"],
                "provenance": result["provenance"],
                "scope_inventory": scope,
                "cross_cell_pooling_permitted": False,
            })

    strata: list[dict[str, Any]] = []
    for token in sorted(grouped):
        identity, rows = grouped[token]
        cluster_ids = {
            str(row["raw"].get("source_cluster_id") or row["raw"]["datapoint_id"])
            for row in rows
        }
        strata.append({
            **identity,
            "measurement_families": _measurement_families(identity, rows),
            "n_completed_records": len(rows),
            "n_source_clusters": len(cluster_ids),
            "label_counts": dict(sorted(Counter(row["label"] for row in rows).items())),
            "n_strongreject_graded": sum(
                row["raw"].get("strongreject_evaluated") is True for row in rows
            ),
            "descriptive_common_endpoint": _descriptive_endpoint(identity, rows),
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
    expected_source_arms: dict[str, str] | None = None,
    source_inventory_artifact: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not cells and not native_runs:
        raise ValueError("suite summary requires runner cells and/or native runs")
    runner = summarize_runner_cells(cells)
    native = summarize_native_runs(native_runs)
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
        _EXPECTED_CONVERTER_FAMILIES - configured_converter_families
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
            "expected_converter_families": sorted(_EXPECTED_CONVERTER_FAMILIES),
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
        "--source-config",
        type=Path,
        help=(
            "complete source-instance registry used to report observed and missing "
            "program arms"
        ),
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.results and not args.native:
        parser.error("provide at least one --results or --native input")

    try:
        cells: list[dict[str, Any]] = []
        for root in args.results:
            resolved = root.resolve(strict=True)
            cells.extend(_load_cells(resolved))
        native_runs = []
        for path in args.native:
            run, digest = load_native_run(path)
            native_runs.append((run, digest, path.name))
        source_inventory = None
        source_inventory_artifact = None
        if args.source_config is not None:
            source_inventory, source_inventory_artifact = _load_source_inventory(
                args.source_config
            )
        summary = build_suite_summary(
            cells,
            native_runs,
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
        "source_native_presence_complete": summary["source_native_presence"][
            "all_expected_entries_observed"
        ],
        "universal_safety_score_defined": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
