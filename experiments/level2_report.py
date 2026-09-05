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

from experiments.figure_results import (  # noqa: E402
    _load_cells,
    _reject_duplicate_realized_target_arms,
)
from experiments.level1_evidence import (  # noqa: E402
    _approximate_decision_state,
    _decision_state,
)
from experiments.native_import import load_native_run  # noqa: E402
from experiments.suite_summary import (  # noqa: E402
    _metric_family,
    summarize_native_runs,
)
from ura.eligibility import canonical_json_sha256  # noqa: E402
from ura.approximate_metrics import (  # noqa: E402
    aggregate_approximate_provenance,
    validate_approximate_completion_bindings,
    validate_approximate_metric_provenance,
)
from ura.data_models import Judgment  # noqa: E402


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
    "metric_authority",
    "warning_tag",
    "evidence_class",
    "reliability_score",
    "reliability_kind",
    "approximate_provenance",
    "approximate_model_query_count",
    "approximate_source_reference_use_count",
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
    "group_refinements",
    "execution_modes",
    "judgments_completed",
    "judgments_evaluable",
    "judgments_decided",
    "judgments_abstained",
    "judgments_missing_responses",
    "judgments_non_evaluable",
    "cross_stratum_pooling_permitted",
)
_CSV_FIELDS_WITH_SAMPLING_POLICY = (
    *_CSV_FIELDS[:_CSV_FIELDS.index("source_policy_id")],
    "sampling_policy",
    *_CSV_FIELDS[_CSV_FIELDS.index("source_policy_id"):],
)


def _polarity(metric: str) -> str:
    if metric.startswith("approximate_"):
        metric = metric.removeprefix("approximate_")
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
        "source_judgments_completed": 0,
        "source_judgments_evaluable": 0,
        "source_judgments_decided": 0,
        "source_judgments_abstained": 0,
        "source_judgments_missing_responses": 0,
        "source_judgments_non_evaluable": 0,
        "approximate_judgments_completed": 0,
        "approximate_judgments_evaluable": 0,
        "approximate_judgments_decided": 0,
        "approximate_judgments_abstained": 0,
        "execution_modes": set(),
        "policy_sha256": set(),
        "official_source_evaluator": set(),
    })
    responses = cell.get("responses")
    responses = responses if isinstance(responses, dict) else {}
    supplementary_policy = cell["manifest"].get("config", {}).get(
        "supplementary_metric_policy"
    )
    for judgment in cell["judgments"]:
        raw = judgment.get("raw")
        if not isinstance(raw, dict):
            raise ValueError("completed judgment lacks raw provenance")
        record = coverage[_judgment_bucket(cell, raw)]
        record["source_judgments_completed"] += 1
        state = _decision_state(judgment)
        record[f"source_judgments_{state}"] += 1
        if raw.get("policy_evaluation_status") == "model_nonresponse":
            record["source_judgments_missing_responses"] += 1
        if state != "non_evaluable":
            record["source_judgments_evaluable"] += 1
        approximate_state = _approximate_decision_state(
            judgment,
            response=responses.get(judgment.get("attempt_id")),
            supplementary_policy=supplementary_policy,
        )
        if approximate_state is not None:
            record["approximate_judgments_completed"] += 1
            record["approximate_judgments_evaluable"] += 1
            record[f"approximate_judgments_{approximate_state}"] += 1
        planning_execution_mode = raw.get("planning_execution_mode")
        if not isinstance(planning_execution_mode, str) or not planning_execution_mode:
            raise ValueError(
                "completed judgment lacks planning_execution_mode; regenerate "
                "the cell with the current Runner instead of loading older "
                "artifacts"
            )
        record["execution_modes"].add(planning_execution_mode)
        policy = raw.get("source_policy")
        if isinstance(policy, dict) and policy.get("sha256"):
            record["policy_sha256"].add(str(policy["sha256"]))
        source_evaluation = raw.get("source_evaluation")
        if isinstance(source_evaluation, dict):
            record["official_source_evaluator"].add(
                source_evaluation.get("official_evaluator_executed") is True
            )
    return coverage


def _validate_proxy_trail_bindings(cell: dict[str, Any]) -> None:
    """Bind every proxy decision to the completion-hashed trail projection."""

    validate_approximate_completion_bindings(
        judgments=cell["judgments"],
        responses=cell.get("responses"),
        supplementary_policy=cell["manifest"].get("config", {}).get(
            "supplementary_metric_policy"
        ),
        trails=cell.get("trails", []),
    )


def _metric_proxy_rows(
    cell: dict[str, Any], group_by: Mapping[str, Any]
) -> list[Judgment]:
    rows: list[Judgment] = []
    for value in cell["judgments"]:
        judgment = Judgment.model_validate(value, strict=True)
        if all(
            str(
                judgment.raw[key]
                if key in judgment.raw and judgment.raw[key] is not None
                else getattr(judgment, key, "unknown")
            ) == expected
            for key, expected in group_by.items()
        ):
            rows.append(judgment)
    return rows


def _endpoint_status(
    family: str, coverage: Mapping[str, Any], provenance: Mapping[str, Any]
) -> str:
    if isinstance(provenance.get("approximate_security"), dict):
        return "approximate_common_proxy"
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
    _validate_proxy_trail_bindings(cell)
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
        if not _REQUIRED_GROUP_KEYS.issubset(group_by):
            raise ValueError(
                "level-2 export requires the safe default aggregation "
                f"grouping; got {sorted(group_by)} in {cell['run_id']}"
            )
        refinements = {
            key: group_by[key]
            for key in sorted(set(group_by) - _REQUIRED_GROUP_KEYS)
        }
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
        approximate = provenance.get("approximate_security")
        if metric.startswith("approximate_"):
            if approximate is None:
                raise ValueError(
                    f"approximate result lacks strict proxy provenance: {metric}"
                )
            approximate = validate_approximate_metric_provenance(
                metric, approximate
            ).model_dump(mode="json")
            if (
                isinstance(result.get("n"), bool)
                or not isinstance(result.get("n"), int)
                or result["n"] != approximate["n_result_units"]
            ):
                raise ValueError(
                    "approximate aggregate n does not match its typed "
                    "metric-specific result-unit count"
                )
            metric_rows = _metric_proxy_rows(cell, group_by)
            recomputed = aggregate_approximate_provenance(
                metric_rows,
                metric=metric.removeprefix("approximate_"),
                responses=cell.get("responses"),
                supplementary_policy=cell["manifest"].get("config", {}).get(
                    "supplementary_metric_policy"
                ),
            )
            if recomputed != approximate:
                raise ValueError(
                    "approximate aggregate provenance does not match its exact "
                    "metric-specific completed proxy decisions"
                )
        elif approximate is not None:
            raise ValueError(
                f"source/common result carries approximate provenance: {metric}"
            )
        coverage_prefix = "approximate" if approximate is not None else "source"
        selected_coverage = (
            {
                "judgments_completed": bucket_coverage[
                    "approximate_judgments_completed"
                ],
                "judgments_evaluable": bucket_coverage[
                    "approximate_judgments_evaluable"
                ],
                "judgments_decided": bucket_coverage[
                    "approximate_judgments_decided"
                ],
                "judgments_abstained": bucket_coverage[
                    "approximate_judgments_abstained"
                ],
                "judgments_missing_responses": 0,
                "judgments_non_evaluable": 0,
                "official_source_evaluator": bucket_coverage[
                    "official_source_evaluator"
                ],
            }
            if approximate is not None
            else {
                "judgments_completed": bucket_coverage[
                    "source_judgments_completed"
                ],
                "judgments_evaluable": bucket_coverage[
                    "source_judgments_evaluable"
                ],
                "judgments_decided": bucket_coverage[
                    "source_judgments_decided"
                ],
                "judgments_abstained": bucket_coverage[
                    "source_judgments_abstained"
                ],
                "judgments_missing_responses": bucket_coverage[
                    "source_judgments_missing_responses"
                ],
                "judgments_non_evaluable": bucket_coverage[
                    "source_judgments_non_evaluable"
                ],
                "official_source_evaluator": bucket_coverage[
                    "official_source_evaluator"
                ],
            }
        )
        if selected_coverage["judgments_completed"] == 0:
            raise ValueError(
                f"aggregate result has no {coverage_prefix} decision coverage: {metric}"
            )
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
            **(
                {"sampling_policy": run["sampling_policy"]}
                if "sampling_policy" in run
                else {}
            ),
            "source_policy_id": group_by["source_policy_id"],
            "source_policy_version": group_by["source_policy_version"],
            "source_policy_sha256": (
                next(iter(policy_digests)) if policy_digests else None
            ),
            "semantic_family": family,
            "metric": metric,
            "endpoint_status": _endpoint_status(
                family, selected_coverage, provenance
            ),
            "metric_authority": (
                "supplementary_non_authoritative"
                if approximate is not None
                else "authoritative_or_source_native"
            ),
            "warning_tag": (
                approximate.get("warning_tag") if approximate is not None else None
            ),
            "evidence_class": (
                approximate.get("evidence_class") if approximate is not None else None
            ),
            "reliability_score": (
                approximate.get("reliability_score")
                if approximate is not None else None
            ),
            "reliability_kind": (
                approximate.get("reliability_kind")
                if approximate is not None else None
            ),
            "approximate_provenance": approximate,
            "approximate_model_query_count": (
                approximate["n_model_queried_decisions"]
                if approximate is not None else None
            ),
            "approximate_source_reference_use_count": (
                approximate["n_source_reference_context_used"]
                if approximate is not None else None
            ),
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
            "group_refinements": (
                json.dumps(refinements, sort_keys=True, separators=(",", ":"))
                if refinements else ""
            ),
            "execution_modes": sorted(bucket_coverage["execution_modes"]),
            "judgments_completed": selected_coverage["judgments_completed"],
            "judgments_evaluable": selected_coverage["judgments_evaluable"],
            "judgments_decided": selected_coverage["judgments_decided"],
            "judgments_abstained": selected_coverage["judgments_abstained"],
            "judgments_missing_responses": selected_coverage[
                "judgments_missing_responses"
            ],
            "judgments_non_evaluable": selected_coverage[
                "judgments_non_evaluable"
            ],
            "cross_stratum_pooling_permitted": False,
        })
    return rows


def build_level2_report(
    cells: list[dict[str, Any]],
    native_runs: list[tuple[Any, str, str]],
) -> dict[str, Any]:
    _reject_duplicate_realized_target_arms(cells)
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
        row["metric"], row["group_refinements"],
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
    fields = (
        _CSV_FIELDS_WITH_SAMPLING_POLICY
        if any("sampling_policy" in row for row in estimates)
        else _CSV_FIELDS
    )
    writer = csv.DictWriter(
        buffer, fieldnames=list(fields), lineterminator="\n"
    )
    writer.writeheader()
    for row in estimates:
        record: dict[str, Any] = {}
        for field in fields:
            value = row.get(field) if field == "sampling_policy" else row[field]
            if isinstance(value, list):
                record[field] = "|".join(str(item) for item in value)
            elif isinstance(value, dict):
                record[field] = json.dumps(
                    value, sort_keys=True, separators=(",", ":")
                )
            elif value is None:
                record[field] = ""
            else:
                record[field] = value
        writer.writerow(record)
    return buffer.getvalue()


def _md_cell(value: Any) -> str:
    """Escape a value for a GFM pipe-table cell."""

    escaped = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return escaped.replace("\n", " ")


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
    if any(
        row["metric_authority"] == "supplementary_non_authoritative"
        for row in report["common"]["estimates"]
    ):
        lines.extend([
            "> ⚠ Approximate rows are supplementary response proxies, not "
            "authoritative or source-native results. Synthetic rows are plumbing "
            "evidence only; reliability is an uncalibrated heuristic, not a "
            "probability or accuracy estimate.",
            "",
        ])
    for family in sorted(by_family):
        lines.append(f"## {family}")
        lines.append("")
        lines.append(
            "| source | metric | status | authority | warning | evidence | reliability | "
            "polarity | model | attacker | defense | modality | population | value | 95% CI | n | clusters "
            "| decided/abstained |"
        )
        lines.append("|" + "---|" * 18)
        for row in by_family[family]:
            interval = (
                f"[{row['ci_low']}, {row['ci_high']}]"
                if row["ci_low"] is not None
                else "-"
            )
            reliability = (
                f"{row['reliability_score']} heuristic (not probability)"
                if row["reliability_score"] is not None
                else "-"
            )
            lines.append(
                f"| {_md_cell(row['source'])} | {_md_cell(row['metric'])} | "
                f"{_md_cell(row['endpoint_status'])} | "
                f"{_md_cell(row['metric_authority'])} | "
                f"{_md_cell(row['warning_tag'] or '-')} | "
                f"{_md_cell(row['evidence_class'] or '-')} | "
                f"{_md_cell(reliability)} | "
                f"{_md_cell(row['polarity'])} | "
                f"{_md_cell(row['model_spec'])} | {_md_cell(row['attacker'])} "
                f"| {_md_cell(row['defense'])} "
                f"| {_md_cell(row['effective_modality'])} | "
                f"{_md_cell(row['population'])} | "
                f"{_md_cell(row['value'])} | {_md_cell(interval)} | "
                f"{row['n_records']} | "
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
                    f"| {_md_cell(run['engine'])} | "
                    f"{_md_cell(run['native_run_id'])} | "
                    f"{_md_cell(stratum['target_model'])} | "
                    f"{stratum['n_cases']} | "
                    f"`{_md_cell(outcomes)}` |"
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
    parser.add_argument(
        "--historical-code-repository", type=Path,
        help="validate retained revision strata through their exact trusted Git source",
    )
    parser.add_argument("--out-csv", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.results and not args.native:
        parser.error("provide at least one --results or --native input")
    written: list[Path] = []
    try:
        cells: list[dict[str, Any]] = []
        for root in args.results:
            if args.historical_code_repository is None:
                cells.extend(_load_cells(root.resolve(strict=True)))
            else:
                from experiments.retained_artifact_reader import load_cells

                cells.extend(load_cells(
                    root.resolve(strict=True), code_repository=args.historical_code_repository,
                ))
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
