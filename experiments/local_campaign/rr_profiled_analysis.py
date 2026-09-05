"""Publish the completed RR supplement through existing Level-1/2 and Stats tools.

The frozen 144-condition historical analysis remains separate. This module
does not generate responses, judge outputs, or pool RR with its base model.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from experiments import level1_evidence, level2_report
from experiments.local_campaign.current_ollama_gate5 import _descriptor
from experiments.local_campaign.rr_profiled_phase6 import (
    CONTINUATION_SCHEMA, LAYOUT, SCHEMA, STATE_SCHEMA, terminal_chain,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import _validate_metric_result
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json, _load_json, _option, _validate_descriptor,
)
from experiments.rig_web_app.external_analysis import (
    ExternalAnalysisReportSpec, publish_external_analysis_registration,
)


def validated_units(completion_path: Path, *, runner_root: Path):
    path = completion_path.resolve(strict=True)
    root = path.parent
    if root.is_symlink() or root.parent.name != "engineering":
        raise ValueError("RR completion root is not a campaign directory")
    value = _load_json(path, label="RR completion")
    expected_order = [lane for lane, _count in LAYOUT]
    if (
        value.get("schema") != SCHEMA or value.get("status") != "complete"
        or value.get("controller_exit_code") != 0 or value.get("unit_failures") != {}
        or value.get("unit_order") != expected_order
        or set(value.get("unit_results", {})) != set(expected_order)
        or value.get("planned_unique_rows") != 7606
        or value.get("target_answer_retries") != 1
        or value.get("successful_rows_repeated") != 0
        or value.get("paid_provider_calls") != 0
        or value.get("cross_condition_pooling_permitted") is not False
    ):
        raise ValueError("RR analysis requires all four complete planned units")
    launch_path = _validate_descriptor(value.get("launch"), label="RR launch")
    launch = _load_json(launch_path, label="RR launch")
    if launch_path != root / "launch.json" or any(
        value.get(key) != item for key, item in launch.items() if key != "status"
    ):
        raise ValueError("RR completion changed its original launch")
    for evidence in launch["units"].values():
        for field in ("source_specification", "local_config"):
            _validate_descriptor(evidence[field], label=f"RR {field}")
    descriptor = _descriptor(path, label="RR completion")
    validated = {}
    for lane, count in LAYOUT:
        item = _validate_metric_result(
            value["unit_results"][lane], logical_lane=lane, physical_unit=lane,
            source_lane=lane, corpus=None, selected_records=count,
            runner_root=runner_root, control_root=root, state_schema=STATE_SCHEMA,
            completion=descriptor,
        )
        state = _load_json(Path(value["unit_results"][lane]["state"]["path"]), label="RR state")
        config = launch["units"][lane]["local_config"]
        if (
            _option(state["runner_argv"], "--local-config") != config["path"]
            or _option(state["runner_argv"], "--local-config-sha256") != config["sha256"]
            or item["revision"] != value["project_revision"]["sha256"]
        ):
            raise ValueError("RR state lost its profiled execution condition")
        validated[lane] = item
    counts = {
        "target_attempts": 7606,
        "successful_target_generations": sum(item["successful"] for item in validated.values()),
        "missing_responses": sum(item["missing"] for item in validated.values()),
    }
    if counts != value.get("target_execution") or len({item["source"] for item in validated.values()}) != 1:
        raise ValueError("RR completion accounting or source stratum changed")
    return value, validated


def validated_continuation(completion_path: Path, *, runner_root: Path):
    """Require exact full coverage, but report metrics only for completed grids."""
    chain, _selected, outcomes, snapshots, segments = terminal_chain(
        completion_path, runner_root=runner_root,
    )
    counts_by_lane = {lane: len(outcomes[lane]) for lane, _count in LAYOUT}
    if counts_by_lane != dict(LAYOUT):
        raise ValueError("RR continuation analysis requires all 7,606 planned responses")
    validated = {}
    for segment in segments:
        generation, lane = segment["generation"], segment["lane"]
        item = _validate_metric_result(
            segment["result"], logical_lane=lane, physical_unit=lane,
            source_lane=lane, corpus=None, selected_records=segment["selected_records"],
            runner_root=runner_root, control_root=generation["root"], state_schema=STATE_SCHEMA,
            completion=_descriptor(generation["path"], label="RR segment completion"),
        )
        if item["revision"] != generation["value"]["project_revision"]["sha256"]:
            raise ValueError("RR metric segment changed its execution revision")
        validated[f"{generation['root'].name}/{lane}"] = item
    if not validated or len({item["source"] for item in validated.values()}) != 1:
        raise ValueError("RR continuation has no completed metric grid or changed its source stratum")
    successful = sum(status in {"usable_first_response", "recovered_after_retry"}
                     for lane in outcomes.values() for status in lane.values())
    coverage = {
        "schema": "ura-profiled-rr-continuation-coverage/1",
        "planned_responses": 7606, "retained_responses": sum(counts_by_lane.values()),
        "responses_by_lane": counts_by_lane, "successful_rows_repeated": 0,
        "completed_grid_responses": sum(item["selected_records"] for item in segments),
        "interrupted_grid_responses": 7606 - sum(item["selected_records"] for item in segments),
        "interrupted_grids_promoted": False, "retained_chain": snapshots,
        "judge_coverage_requires_retained_postfactum_analysis": any(
            generation["value"]["unit_failures"] for generation in chain),
    }
    value = {**chain[-1]["value"], "target_execution": {
        "target_attempts": 7606, "successful_target_generations": successful,
        "missing_responses": 7606 - successful,
    }}
    return value, validated, coverage


def export_level1_strata(units, *, output: Path, project: Path, continuation: bool):
    """Each Level-1 export has one exact retained execution revision."""
    groups = {}
    for item in units.values():
        groups.setdefault(item["revision"], []).append(item)
    if not continuation and len(groups) != 1:
        raise ValueError("original RR analysis changed its execution revision stratum")
    reports = {}
    for revision, items in sorted(groups.items()):
        stem = f"level1-{revision}" if continuation else "level1"
        path = output / f"{stem}.json"
        argv = ["--out-json", str(path), "--out-csv", str(output / f"{stem}.csv"),
                "--historical-code-repository", str(project)]
        for item in items:
            argv.extend(("--results", item["root"], "--eligibility", item["eligibility_plan"]["path"]))
        if level1_evidence.main(argv):
            raise ValueError("RR revision-specific Level-1 export failed; nothing published to Stats")
        reports[revision] = _descriptor(path, label="RR revision-specific Level 1")
    return reports


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--completion", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    work = args.work_root.resolve(strict=True)
    source = _load_json(args.completion.resolve(strict=True), label="RR completion")
    coverage = None
    if source.get("schema") == CONTINUATION_SCHEMA:
        value, units, coverage = validated_continuation(
            args.completion, runner_root=work / "runs/thesis/runner",
        )
    else:
        value, units = validated_units(args.completion, runner_root=work / "runs/thesis/runner")
    output = args.out
    if output.exists() or not output.is_absolute() or not output.is_relative_to(work / "runs"):
        raise ValueError("RR analysis requires a fresh results directory")
    output.mkdir(parents=True, mode=0o700)
    if coverage is not None:
        _create_json(output / "continuation-coverage.json", coverage)
    level1_reports = export_level1_strata(
        units, output=output, project=args.project_root.resolve(strict=True), continuation=coverage is not None,
    )
    level2 = ["--out-json", str(output / "level2.json"), "--out-csv", str(output / "level2.csv"),
              "--out-md", str(output / "level2.md"),
              "--historical-code-repository", str(args.project_root.resolve(strict=True))]
    for item in units.values():
        level2.extend(("--results", item["root"]))
    if level2_report.main(level2):
        raise ValueError("RR Level-1/2 analysis failed; nothing published to Stats")
    _create_json(output / "completion.json", {
        "schema": "ura-profiled-rr-analysis/2" if coverage else "ura-profiled-rr-analysis/1",
        "status": "complete",
        "source_completion": _descriptor(args.completion.resolve(strict=True), label="RR completion"),
        "target_execution": value["target_execution"],
        **({"level1_by_execution_revision": level1_reports} if coverage
           else {"level1": next(iter(level1_reports.values()))}),
        "level2": _descriptor(output / "level2.json", label="RR Level 2"),
        "historical_144_conditions_replaced": False, "base_rr_pooling_permitted": False,
        "paired_defense_estimate": "requires_separate_matching_condition_analysis",
        **({"continuation_coverage": _descriptor(output / "continuation-coverage.json", label="RR coverage"),
             "interrupted_grid_responses": coverage["interrupted_grid_responses"],
             "judge_coverage_requires_retained_postfactum_analysis":
                 coverage["judge_coverage_requires_retained_postfactum_analysis"]} if coverage else {}),
    })
    publish_external_analysis_registration(
        work / "runs", job_id=args.completion.parent.name, analysis_root=output,
        work_label="GraySwan RR - current-profile supplement",
        completion_status="complete_with_explicit_limitations",
        explicit_limitations={"comparison_scope": "RR-only cohort; a base/RR estimate requires matching input and serving conditions.",
                             **({"checkpoint_coverage":
                                 f"{coverage['interrupted_grid_responses']} interrupted-grid responses are retained, not promoted; "
                                 "their judged evidence requires retained post-factum analysis."} if coverage else {})},
        reports=[*(ExternalAnalysisReportSpec(Path(item["path"]), "level1", f"RR input coverage - {revision[:12]}")
                   for revision, item in level1_reports.items()),
                 ExternalAnalysisReportSpec(output / "level2.json", "level2", "RR outcomes, stability and token conditions")],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
