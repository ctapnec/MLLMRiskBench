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
from experiments.local_campaign.rr_profiled_phase6 import LAYOUT, SCHEMA, STATE_SCHEMA
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--completion", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    work = args.work_root.resolve(strict=True)
    value, units = validated_units(args.completion, runner_root=work / "runs/thesis/runner")
    output = args.out
    if output.exists() or not output.is_absolute() or not output.is_relative_to(work / "runs"):
        raise ValueError("RR analysis requires a fresh results directory")
    output.mkdir(parents=True, mode=0o700)
    level1 = ["--out-json", str(output / "level1.json"), "--out-csv", str(output / "level1.csv")]
    level2 = ["--out-json", str(output / "level2.json"), "--out-csv", str(output / "level2.csv"),
              "--out-md", str(output / "level2.md"),
              "--historical-code-repository", str(args.project_root.resolve(strict=True))]
    for item in units.values():
        level1.extend(("--results", item["root"], "--eligibility", item["eligibility_plan"]["path"]))
        level2.extend(("--results", item["root"]))
    if level1_evidence.main(level1) or level2_report.main(level2):
        raise ValueError("RR Level-1/2 analysis failed; nothing published to Stats")
    _create_json(output / "completion.json", {
        "schema": "ura-profiled-rr-analysis/1", "status": "complete",
        "source_completion": _descriptor(args.completion.resolve(strict=True), label="RR completion"),
        "target_execution": value["target_execution"],
        "level1": _descriptor(output / "level1.json", label="RR Level 1"),
        "level2": _descriptor(output / "level2.json", label="RR Level 2"),
        "historical_144_conditions_replaced": False, "base_rr_pooling_permitted": False,
        "paired_defense_estimate": "requires_separate_matching_condition_analysis",
    })
    publish_external_analysis_registration(
        work / "runs", job_id=args.completion.parent.name, analysis_root=output,
        work_label="GraySwan RR - current-profile supplement",
        completion_status="complete_with_explicit_limitations",
        explicit_limitations={"comparison_scope": "RR-only cohort; a base/RR estimate requires matching input and serving conditions."},
        reports=[ExternalAnalysisReportSpec(output / "level1.json", "level1", "RR input coverage"),
                 ExternalAnalysisReportSpec(output / "level2.json", "level2", "RR outcomes, stability and token conditions")],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
