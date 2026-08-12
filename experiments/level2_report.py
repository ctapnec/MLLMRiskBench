"""Export deterministic Level-2 compatible-family tables without pooling.

Completed measured runner cells are admitted only through the content-addressed
completed-grid validator shared with measured figures, so diagnostic dry runs,
diagnostic canaries, and attestation probes are rejected before any row is
built.  Every exported estimate keeps its complete compatibility key (run,
served target, source arm, source policy identity, modality, population,
attacker, defense, ordered judge identity, budget/sampling condition); rows are
never merged across distinct keys.  Source-native evidence stays in a separate
table on its original scales, and judgment-record decision coverage accompanies
every judge-derived estimate.  The export is descriptive only: it defines no
universal safety score, ranks no models, and establishes no empirical validity
by itself.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from experiments.figure_results import _load_cells  # noqa: E402
from experiments.level1_evidence import _decision_state  # noqa: E402
from experiments.native_import import load_native_run  # noqa: E402
from experiments.suite_summary import (  # noqa: E402
    _metric_family,
    summarize_native_runs,
)
from ura.eligibility import canonical_json_sha256  # noqa: E402


LEVEL2_SCHEMA = "ura-level2-report/1"

#: The safe default aggregation identity emitted by ``Runner.aggregate``.  A
#: coarser or renamed grouping cannot be exported because its buckets would not
#: pin the compatibility key.
_REQUIRED_GROUP_KEYS = frozenset({
    "model",
    "source",
    "risk",
    "effective_modality",
    "expected_behavior",
    "attacker",
    "source_policy_id",
    "source_policy_version",
})

#: Explicit adverse-direction declaration per known common metric.  Unlisted
#: source-specific metrics keep their source-defined polarity and scale.
_METRIC_POLARITY = {
    "ASR": "higher_adverse",
    "ISR": "higher_adverse",
    "conversation_ASR": "higher_adverse",
    "over_refusal_rate": "higher_adverse",
    "conversation_over_refusal_rate": "higher_adverse",
    "strongreject": "higher_adverse",
    "conversation_strongreject_max": "higher_adverse",
    "refusal_rate": "higher_favorable",
    "robust_refusal_rate": "higher_favorable",
    "median_turns_to_break": "higher_favorable",
    "restricted_mean_turns_to_break": "higher_favorable",
    "kaplan_meier_survival": "higher_favorable",
    "source_metric_implementation_coverage": "higher_favorable",
}

_CSV_FIELDS = (
    "run_id",
    "corpus_arm",
    "model_spec",
    "resolved_model",
    "source",
    "risk_category",
    "effective_modality",
    "expected_behavior",
    "attacker",
    "defense",
    "defense_guardrail_revision",
    "ordered_judges",
    "judge_model",
    "seeds",
    "sample_seed",
    "limit",
    "source_policy_id",
    "source_policy_version",
    "source_policy_sha256",
    "semantic_family",
    "metric",
    "endpoint_status",
    "polarity",
    "value",
    "ci_low",
    "ci_high",
    "ci_method",
    "n_records",
    "n_clusters",
    "cluster_unit",
    "population",
    "horizon_turns",
    "execution_modes",
    "judgments_completed",
    "judgments_evaluable",
    "judgments_decided",
    "judgments_abstained",
    "judgments_non_evaluable",
    "cross_stratum_pooling_permitted",
)


def _polarity(metric: str) -> str:
    if metric.startswith("survival_"):
        return "higher_favorable"
    return _METRIC_POLARITY.get(metric, "source_defined")


def _bucket_key(values: Mapping[str, Any]) -> str:
    projected = {key: values[key] for key in sorted(_REQUIRED_GROUP_KEYS)}
    return json.dumps(projected, sort_keys=True, separators=(",", ":"))


def _judgment_bucket(cell: dict[str, Any], raw: Mapping[str, Any]) -> str:
    return _bucket_key({
        "model": cell["model"],
        "source": raw["source"],
        "risk": raw["risk_category"],
        "effective_modality": raw["effective_modality"],
        # Planning identity keeps adaptive setup turns in the stratum that
        # produced the conversation instead of a phantom comply bucket.
        "expected_behavior": raw["planning_expected_behavior"],
        "attacker": raw["attacker"],
        "source_policy_id": str(raw.get("source_policy_id", "unversioned")),
        "source_policy_version": str(
            raw.get("source_policy_version", "unversioned")
        ),
    })


def _coverage_by_bucket(cell: dict[str, Any]) -> dict[str, dict[str, Any]]:
    coverage: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "judgments_completed": 0,
        "judgments_evaluable": 0,
        "judgments_decided": 0,
        "judgments_abstained": 0,
        "judgments_non_evaluable": 0,
        "execution_modes": set(),
        "policy_sha256": set(),
        "official_source_evaluator": set(),
    })
    for judgment in cell["judgments"]:
        raw = judgment.get("raw")
        if not isinstance(raw, dict):
            raise ValueError("completed judgment lacks raw provenance")
        record = coverage[_judgment_bucket(cell, raw)]
        record["judgments_completed"] += 1
        state = _decision_state(judgment)
        record[f"judgments_{state}"] += 1
        if state != "non_evaluable":
            record["judgments_evaluable"] += 1
        record["execution_modes"].add(
            str(raw.get("execution_mode") or "harness_response_evaluation")
        )
        policy = raw.get("source_policy")
        if isinstance(policy, dict) and policy.get("sha256"):
            record["policy_sha256"].add(str(policy["sha256"]))
        source_evaluation = raw.get("source_evaluation")
        if isinstance(source_evaluation, dict):
            record["official_source_evaluator"].add(
                source_evaluation.get("official_evaluator_executed") is True
            )
    return coverage


def _endpoint_status(family: str, coverage: Mapping[str, Any]) -> str:
    if family == "classification_quality":
        official = coverage["official_source_evaluator"]
        return (
            "official_source_evaluator"
            if official == {True}
            else "source_specific_evaluator"
        )
    if family == "coverage_conformance":
        return "coverage_accounting"
    return "common_proxy"


def _estimate_rows(cell: dict[str, Any]) -> list[dict[str, Any]]:
    run = cell["manifest"]["config"]["run"]
    manifest = cell["manifest"]
    coverage = _coverage_by_bucket(cell)
    rows: list[dict[str, Any]] = []
    for result in cell["aggregate_results"]:
        group_by = result.get("group_by")
        if not isinstance(group_by, dict):
            raise ValueError(
                f"aggregate result lacks its grouping identity: {cell['run_id']}"
            )
        if set(group_by) != _REQUIRED_GROUP_KEYS:
            raise ValueError(
                "level-2 export requires the safe default aggregation "
                f"grouping; got {sorted(group_by)} in {cell['run_id']}"
            )
        bucket = _bucket_key(group_by)
        bucket_coverage = coverage.get(bucket)
        if bucket_coverage is None:
            raise ValueError(
                "aggregate bucket has no completed judgment support: "
                f"{bucket} in {cell['run_id']}"
            )
        policy_digests = bucket_coverage["policy_sha256"]
        if len(policy_digests) > 1:
            raise ValueError(
                f"aggregate bucket mixes source-policy digests: {bucket}"
            )
        provenance = result.get("provenance")
        if not isinstance(provenance, dict):
            raise ValueError(
                f"aggregate result lacks provenance: {cell['run_id']}"
            )
        metric = str(result["metric"])
        family = _metric_family(metric)
        rows.append({
            "run_id": cell["run_id"],
            "corpus_arm": run["corpus"],
            "model_spec": run["model_spec"],
            "resolved_model": cell["model"],
            "source": group_by["source"],
            "risk_category": group_by["risk"],
            "effective_modality": group_by["effective_modality"],
            "expected_behavior": group_by["expected_behavior"],
            "attacker": group_by["attacker"],
            "defense": run["defense"],
            "defense_guardrail_revision": run.get("defense_guardrail_revision"),
            "ordered_judges": list(manifest["judges"]),
            "judge_model": run.get("judge_model"),
            "seeds": list(manifest["seeds"]),
            "sample_seed": run.get("sample_seed"),
            "limit": run.get("limit"),
            "source_policy_id": group_by["source_policy_id"],
            "source_policy_version": group_by["source_policy_version"],
            "source_policy_sha256": (
                next(iter(policy_digests)) if policy_digests else None
            ),
            "semantic_family": family,
            "metric": metric,
            "endpoint_status": _endpoint_status(family, bucket_coverage),
            "polarity": _polarity(metric),
            "value": result["value"],
            "ci_low": result.get("ci_low"),
            "ci_high": result.get("ci_high"),
            "ci_method": provenance.get("ci_method"),
            "n_records": result["n"],
            "n_clusters": provenance.get("n_clusters"),
            "cluster_unit": provenance.get("cluster_unit"),
            "population": provenance.get("population"),
            "horizon_turns": provenance.get("horizon_turns"),
            "execution_modes": sorted(bucket_coverage["execution_modes"]),
            "judgments_completed": bucket_coverage["judgments_completed"],
            "judgments_evaluable": bucket_coverage["judgments_evaluable"],
            "judgments_decided": bucket_coverage["judgments_decided"],
            "judgments_abstained": bucket_coverage["judgments_abstained"],
            "judgments_non_evaluable": bucket_coverage[
                "judgments_non_evaluable"
            ],
            "cross_stratum_pooling_permitted": False,
        })
    return rows


def build_level2_report(
    cells: list[dict[str, Any]],
    native_runs: list[tuple[Any, str, str]],
) -> dict[str, Any]:
    if not cells and not native_runs:
        raise ValueError("level-2 report requires runner cells and/or native runs")
    seen_run_ids: set[str] = set()
    estimates: list[dict[str, Any]] = []
    cell_bindings: list[dict[str, Any]] = []
    for cell in cells:
        if cell["run_id"] in seen_run_ids:
            raise ValueError(
                f"duplicate completed runner run_id: {cell['run_id']}"
            )
        seen_run_ids.add(cell["run_id"])
        estimates.extend(_estimate_rows(cell))
        run = cell["manifest"]["config"]["run"]
        cell_bindings.append({
            "run_id": cell["run_id"],
            "corpus_arm": run["corpus"],
            "attacker": run["attacker"],
            "model_spec": run["model_spec"],
            "code_version": cell["manifest"]["code_version"],
            "schema_version": cell["manifest"]["schema_version"],
            "project_revision": run.get("project_revision"),
            "request_envelope": run.get("request_envelope"),
        })
    estimates.sort(key=lambda row: (
        row["semantic_family"], row["source"], row["metric"],
        row["model_spec"], row["attacker"], row["defense"], row["run_id"],
        json.dumps(
            {key: row[key] for key in (
                "risk_category", "effective_modality", "expected_behavior",
                "source_policy_id", "source_policy_version",
            )},
            sort_keys=True,
        ),
    ))
    cell_bindings.sort(key=lambda item: item["run_id"])
    body = {
        "schema_version": LEVEL2_SCHEMA,
        "status": "deterministic_compatible_stratum_export",
        "pooling_policy": {
            "universal_safety_score_defined": False,
            "cross_stratum_pooling_permitted": False,
            "native_scale_pooling_permitted": False,
            "row_identity": (
                "one exported estimate per exact run/served-target/source/"
                "policy/modality/population/attacker/defense/judge/budget "
                "stratum and metric; distinct keys are never merged"
            ),
        },
        "empirical_validity_established": False,
        "validity_note": (
            "descriptive export of completion-validated measured artifacts; "
            "scientific validity requires the separate Chapter V evidence "
            "chain (conformance, attestation, human audit)"
        ),
        "inputs": {
            "n_completed_cells": len(cells),
            "cells": cell_bindings,
        },
        "common": {
            "n_estimate_rows": len(estimates),
            "estimates": estimates,
        },
        "native": summarize_native_runs(native_runs),
    }
    body["report_id"] = f"level2-{canonical_json_sha256(body)[:24]}"
    return body


def _csv_text(estimates: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer, fieldnames=list(_CSV_FIELDS), lineterminator="\n"
    )
    writer.writeheader()
    for row in estimates:
        record: dict[str, Any] = {}
        for field in _CSV_FIELDS:
            value = row[field]
            if isinstance(value, list):
                record[field] = "|".join(str(item) for item in value)
            elif value is None:
                record[field] = ""
            else:
                record[field] = value
        writer.writerow(record)
    return buffer.getvalue()


def _markdown_text(report: dict[str, Any]) -> str:
    lines = [
        "# Level-2 compatible-family tables",
        "",
        f"Report `{report['report_id']}` "
        f"({report['inputs']['n_completed_cells']} completion-validated "
        "measured cells). Every row is one exact compatibility stratum and "
        "metric; rows are never comparable across strata, no universal safety "
        "score is defined, and no model ranking is implied. "
        "This export does not establish empirical validity by itself.",
        "",
    ]
    by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in report["common"]["estimates"]:
        by_family[row["semantic_family"]].append(row)
    for family in sorted(by_family):
        lines.append(f"## {family}")
        lines.append("")
        lines.append(
            "| source | metric | status | polarity | model | attacker | "
            "defense | modality | population | value | 95% CI | n | clusters "
            "| decided/abstained |"
        )
        lines.append("|" + "---|" * 14)
        for row in by_family[family]:
            interval = (
                f"[{row['ci_low']}, {row['ci_high']}]"
                if row["ci_low"] is not None
                else "-"
            )
            lines.append(
                f"| {row['source']} | {row['metric']} | "
                f"{row['endpoint_status']} | {row['polarity']} | "
                f"{row['model_spec']} | {row['attacker']} | {row['defense']} "
                f"| {row['effective_modality']} | {row['population']} | "
                f"{row['value']} | {interval} | {row['n_records']} | "
                f"{row['n_clusters']} | "
                f"{row['judgments_decided']}/{row['judgments_abstained']} |"
            )
        lines.append("")
    native = report["native"]
    lines.append("## Source-native evidence (original scales; never pooled)")
    lines.append("")
    if native["n_native_runs"] == 0:
        lines.append("No source-native runs were supplied.")
    else:
        lines.append(
            "| engine | native run | target | n cases | native outcomes |"
        )
        lines.append("|" + "---|" * 5)
        for run in native["runs"]:
            for stratum in run["target_strata"]:
                outcomes = json.dumps(
                    stratum["native_outcome_counts"], sort_keys=True
                )
                lines.append(
                    f"| {run['engine']} | {run['native_run_id']} | "
                    f"{stratum['target_model']} | {stratum['n_cases']} | "
                    f"`{outcomes}` |"
                )
    lines.append("")
    return "\n".join(lines)


def _write_new_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Export deterministic Level-2 compatible-family JSON/CSV/Markdown "
            "tables from completion-validated measured artifacts"
        )
    )
    parser.add_argument(
        "--results", type=Path, action="append", default=[],
        help="completed measured run_matrix results root; repeatable",
    )
    parser.add_argument(
        "--native", type=Path, action="append", default=[],
        help="canonical NativeEngineRun JSON envelope; repeatable",
    )
    parser.add_argument("--out-json", type=Path, required=True)
    parser.add_argument("--out-csv", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.results and not args.native:
        parser.error("provide at least one --results or --native input")
    written: list[Path] = []
    try:
        cells: list[dict[str, Any]] = []
        for root in args.results:
            cells.extend(_load_cells(root.resolve(strict=True)))
        native_runs = []
        for path in args.native:
            run, digest = load_native_run(path)
            native_runs.append((run, digest, path.name))
        report = build_level2_report(cells, native_runs)
        json_text = json.dumps(
            report, ensure_ascii=False, indent=2, sort_keys=True,
            allow_nan=False,
        ) + "\n"
        csv_text = _csv_text(report["common"]["estimates"])
        markdown_text = _markdown_text(report)
        for path, text in (
            (args.out_json, json_text),
            (args.out_csv, csv_text),
            (args.out_md, markdown_text),
        ):
            _write_new_text(path, text)
            written.append(path)
    except (OSError, TypeError, ValueError, KeyError) as exc:
        for path in written:
            path.unlink(missing_ok=True)
        print(f"level-2 report failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "status": "written",
        "report_id": report["report_id"],
        "json": str(args.out_json.resolve()),
        "csv": str(args.out_csv.resolve()),
        "md": str(args.out_md.resolve()),
        "n_estimate_rows": report["common"]["n_estimate_rows"],
        "n_native_runs": report["native"]["n_native_runs"],
        "universal_safety_score_defined": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
