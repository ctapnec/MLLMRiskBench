"""Validate the RR parallel supplement without promoting its interrupted prefix.

The historical 144-condition analysis is not replaced. New worker segments must
be complete grids; old closed cells have an explicitly narrower evidence scope.
No target or judge is constructed by this analysis handoff.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Sequence

from experiments import retained_artifact_reader as retained
from experiments.hosted_retained_inputs import candidates_from_cells
from experiments.level2_report import build_level2_report
from experiments.local_campaign import rr_parallel_campaign as campaign
from experiments.local_campaign.rr_profiled_analysis import export_level1_strata
from experiments.local_campaign.vllm_input_recovery_phase6 import _validate_metric_result
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit, _create_json, _load_json, _option, _sha256_json, _validate_descriptor,
)
from experiments.rig_web_app.external_analysis import (
    ExternalAnalysisReportSpec, publish_external_analysis_registration,
)

SCHEMA = "ura-rr-parallel-analysis/1"
PREFIX_SCOPE = "source_validated_closed_cell_in_interrupted_grid"

# Every semantic check below is the ORIGINAL source function. The caller-bound
# reference describes membership in the original request, not an invented grid
# status. In particular, neither the source grid nor its missing cell inventory
# is rewritten or reported complete.
_PREFIX_WORKER = r'''
import hashlib, json, sys
from pathlib import Path
from experiments import level1_evidence as source
from experiments.figure_results import _GridReference, _validate_cell
from ura.runner import _harness_source_identity

request = json.load(sys.stdin)
harness = _harness_source_identity()["sha256"]
driver = hashlib.sha256(Path("experiments/run_matrix.py").read_bytes()).hexdigest()
cells = []
for group in request["groups"]:
    grid_path = Path(group["grid"])
    grid = source._read_object(grid_path)
    original = grid["request"]
    revision = original["project_revision"]
    if (revision["expected_commit"] != request["commit"]
        or revision["observed_commit"] != request["commit"]
        or revision["head_tree"] != request["tree"]
        or revision["harness_source_sha256"] != harness
        or revision["driver_source_sha256"] != driver):
        raise ValueError("RR prefix source differs from its exact validator checkout")
    artifact = source._plan_artifact(Path(group["eligibility"]))
    plan = artifact[0]
    if (not source._plan_descriptor_matches(original["eligibility_plan"], artifact)
        or source._grid_id(grid) != grid["grid_id"]
        or grid_path.name != grid["grid_id"] + ".grid.json"
        or source._grid_condition(original) != source._condition_from_plan(plan)):
        raise ValueError("RR prefix grid/eligibility identity changed")
    source._validate_grid_plan_bindings(original, plan)
    source._validate_grid_model_acquisition(original, evidence_root=grid_path.parent)
    for name in group["markers"]:
        marker = Path(name)
        value = source._read_object(marker)
        manifest_name = value["artifacts"]["manifest"]["file"]
        if Path(manifest_name).name != manifest_name:
            raise ValueError("RR prefix manifest locator is unsafe")
        manifest = source._read_object(marker.parent / manifest_name)
        run = manifest["config"]["run"]
        membership = {"run_id": value["run_id"], **{key: run[key] for key in ("corpus", "model_spec", "attacker")}}
        if (run["corpus"] not in original["corpora"]
            or run["model_spec"] not in original["models"]
            or run["attacker"] not in original["attackers"]
            or run["grid_id"] != grid["grid_id"]):
            raise ValueError("RR prefix cell is outside its original request")
        ref = _GridReference(grid["grid_id"], grid_path, original, membership, plan, grid.get("engine_runtime_close"))
        cells.append(_validate_cell(marker, [ref]))
def json_default(item):
    if isinstance(item, Path):
        return str(item)
    raise TypeError(type(item).__name__)
print(json.dumps({"validator_commit": request["commit"], "cells": cells},
                 default=json_default, allow_nan=False))
'''


def _descriptor(path: Path, label: str = "RR analysis artifact") -> dict:
    return campaign.prior._descriptor(path, label=label)


def _same_launch(completion: dict, launch: dict) -> None:
    if any(completion.get(key) != value for key, value in launch.items() if key != "status"):
        raise ValueError("RR completion changed its bound launch")


def _source_prefix_cells(snapshot: dict, *, project: Path) -> list[dict]:
    """Read only descriptor-bound closed cells, with the original source checks."""
    launch_path = _validate_descriptor(snapshot["launch"], label="RR prefix launch")
    original = _load_json(launch_path, label="RR prefix launch")
    receipt_path = _validate_descriptor(original["project_revision"], label="RR prefix revision")
    receipt = _load_json(receipt_path, label="RR prefix revision")["repository"]
    commit, tree = receipt["expected_commit"], receipt["head_tree"]
    if receipt["observed_commit"] != commit or commit != original["expected_commit"]:
        raise ValueError("RR prefix receipt source changed")
    trusted_head = retained._git(project, "rev-parse", "HEAD")
    retained._git(project, "merge-base", "--is-ancestor", commit, trusted_head)
    if retained._git(project, "rev-parse", f"{commit}^{{tree}}") != tree:
        raise ValueError("RR prefix source tree changed")
    groups = []
    for lane, item in snapshot["lanes"].items():
        files = [_validate_descriptor(value, label="RR prefix raw file") for value in item["raw_files"]]
        markers = [path for path in files if path.name.endswith(".complete.json")]
        if not markers:
            continue
        root = Path(item["result_root"])
        grids = [path for path in files if path.name.endswith(".grid.json")]
        plans = [path for path in files if path.name.endswith(".eligibility.json")]
        if (len(grids) != 1 or len(plans) != 1
                or any(path.parent != root for path in [*markers, *grids, *plans])):
            raise ValueError("RR prefix marker has no exact original grid and eligibility")
        groups.append({"source_lane": lane, "grid": str(grids[0]),
                       "eligibility": str(plans[0]), "markers": [str(path) for path in markers]})
    if not groups:
        return []
    with tempfile.TemporaryDirectory(prefix="ura-rr-prefix-reader-") as scratch:
        worktree = Path(scratch).resolve() / "source"
        installed = False
        try:
            retained._git(project, "worktree", "add", "--quiet", "--detach", str(worktree), commit)
            installed = True
            env = dict(os.environ)
            env.update(PYTHONPATH=str(worktree / "src"), PYTHONDONTWRITEBYTECODE="1")
            for key in list(env):
                if key.endswith(("_API_KEY", "_TOKEN")):
                    env.pop(key)
            result = subprocess.run([sys.executable, "-c", _PREFIX_WORKER], cwd=worktree, env=env,
                                    input=json.dumps({"groups": groups, "commit": commit, "tree": tree}),
                                    capture_output=True, text=True, encoding="utf-8", timeout=600, check=False)
            if result.returncode:
                raise ValueError("RR prefix exact-source validator failed: " + result.stderr[-4000:])
            value = retained._decode_validator_ipc(result.stdout)
            if value.get("validator_commit") != commit or len(value.get("cells", [])) != sum(len(g["markers"]) for g in groups):
                raise ValueError("RR prefix validator changed its closed-cell inventory")
            cells = value["cells"]
            allowed = {name for group in groups for name in group["markers"]}
            if {cell["complete_path"] for cell in cells} != allowed:
                raise ValueError("RR prefix validator returned an unbound marker")
            for cell in cells:
                retained._restore_cell_paths(cell)
                cell["integrity_mode"] = PREFIX_SCOPE
                cell["grid_audit"] = {"mode": PREFIX_SCOPE, "parent_grid_promoted": False,
                                      "completion_marker": str(cell["complete_path"])}
            return cells
        finally:
            if installed:
                retained._git(project, "worktree", "remove", "--force", str(worktree))


def validated_prefix(snapshot: dict, *, runner_root: Path, project: Path) -> tuple[list[dict], dict]:
    if snapshot != campaign.inspect_prefix(snapshot["observation"], runner_root=runner_root):
        raise ValueError("RR interrupted prefix changed after its stopped snapshot")
    cells = _source_prefix_cells(snapshot, project=project)
    judged = {lane: set() for lane in snapshot["lanes"]}
    for cell in cells:
        run = cell["manifest"]["config"]["run"]
        matching = [lane for lane, item in snapshot["lanes"].items()
                    if Path(item["result_root"]) == cell["complete_path"].parent]
        if len(matching) != 1 or cell.get("source_identity_validated") is not True:
            raise ValueError("RR prefix cell lost its exact lane/source identity")
        lane = matching[0]
        ids = {attempt["datapoint_id"] for attempt in cell["attempts"].values()}
        allowed = set(snapshot["selected_ids"][lane].get(run["corpus"], []))
        if (not ids <= allowed or not ids <= set(snapshot["lanes"][lane]["outcomes"])
                or ids & judged[lane] or len(ids) != len(cell["responses"])):
            raise ValueError("RR prefix closed-cell identities are duplicated or outside its retained input set")
        judged[lane].update(ids)
    pending = {}
    for lane, item in snapshot["lanes"].items():
        if judged[lane] != set(item["retained_judgment_ids"]):
            raise ValueError("RR prefix retained judgment inventory failed exact-source validation")
        pending[lane] = sorted(set(item["outcomes"]) - judged[lane])
    return cells, {"retained_responses": snapshot["retained_response_count"],
                   "source_validated_judgments": sum(map(len, judged.values())),
                   "post_factum_judging_required_ids": pending,
                   "judging_complete": not any(pending.values()), "new_judge_calls": 0,
                   "evidence_scope": PREFIX_SCOPE, "old_grid_promoted": False}


def validate(completion_path: Path, *, work: Path, project: Path) -> tuple[dict, dict, list[dict], list[dict]]:
    path = completion_path.resolve(strict=True)
    root = path.parent
    if root.parent != work / "runs/engineering":
        raise ValueError("RR parallel completion is outside the campaign directory")
    value = _load_json(path, label="RR parallel completion")
    launch_path = _validate_descriptor(value["launch"], label="RR parallel launch")
    launch = _load_json(launch_path, label="RR parallel launch")
    if (launch_path != root / "launch.json" or value.get("schema") != campaign.SCHEMA
            or value.get("status") != "responses_complete_pending_prefix_validation"
            or value.get("worker_exit_codes") != {"0": 0, "1": 0}
            or set(value.get("worker_completions", {})) != {"0", "1"}
            or launch.get("original_population") != 7606 or launch.get("max_tokens") != 4096
            or launch.get("tensor_parallel_size") != 1 or launch.get("target_answer_retries") != 1
            or launch.get("old_grid_promoted") is not False
            or launch.get("cross_condition_pooling_permitted") is not False
            or launch.get("work_root") != str(work)):
        raise ValueError("RR parallel analysis requires both complete 4096-token TP1 workers")
    _same_launch(value, launch)
    units = [Unit(**item) for item in launch["units"]]
    if launch["queues"] != campaign.balanced_queues(units):
        raise ValueError("RR parallel analysis queue assignment changed")
    snapshot_path = _validate_descriptor(launch["interruption"], label="RR interrupted prefix")
    snapshot = _load_json(snapshot_path, label="RR interrupted prefix")
    prefix_cells, prefix = validated_prefix(snapshot, runner_root=work / "runs/thesis/runner", project=project)
    measured_coverage = campaign.coverage(launch)
    if (not measured_coverage["complete"] or measured_coverage["expected_inputs"] != 7606
            or measured_coverage != value.get("coverage")):
        raise ValueError("RR parallel analysis requires the exact 7,606-input disjoint union")
    revision_path = _validate_descriptor(launch["project_revision"], label="RR parallel revision")
    revision = _load_json(revision_path, label="RR parallel revision")["repository"]
    if any(revision.get(key) != launch["expected_commit"] for key in ("expected_commit", "observed_commit")):
        raise ValueError("RR parallel analysis source receipt changed")
    by_id = {unit.unit_id: unit for unit in units}
    validated, cells = {}, []
    source_strata = set()
    for gpu in ("0", "1"):
        worker_root = root.with_name(root.name + f"-gpu{gpu}")
        worker_path = _validate_descriptor(value["worker_completions"][gpu], label="RR worker completion")
        worker = _load_json(worker_path, label="RR worker completion")
        worker_launch_path = _validate_descriptor(worker["launch"], label="RR worker launch")
        worker_launch = _load_json(worker_launch_path, label="RR worker launch")
        if (launch["workers"][gpu] != str(worker_root) or worker_path != worker_root / "completion.json"
                or worker_launch_path != worker_root / "launch.json"
                or worker_launch != {"schema": campaign.SCHEMA, "parent": value["launch"],
                                     "physical_gpu": gpu, "unit_order": launch["queues"][gpu]}
                or worker.get("schema") != campaign.SCHEMA or worker.get("status") != "complete"
                or worker.get("physical_gpu") != gpu or worker.get("failures") != {}
                or set(worker.get("results", {})) != set(launch["queues"][gpu])):
            raise ValueError("RR worker terminal or original GPU assignment changed")
        worker_cells = []
        for unit_id in launch["queues"][gpu]:
            unit = by_id[unit_id]
            item = _validate_metric_result(
                worker["results"][unit_id], logical_lane=unit.source_lane, physical_unit=unit_id,
                source_lane=unit.source_lane, corpus=unit.corpus, selected_records=unit.selected_records,
                runner_root=work / "runs/thesis/runner", control_root=worker_root,
                state_schema=campaign.STATE_SCHEMA, completion=value["worker_completions"][gpu])
            if item["revision"] != launch["project_revision"]["sha256"]:
                raise ValueError("RR segment execution revision changed")
            state = _load_json(Path(item["evidence"]["state"]["path"]), label="RR segment state")
            if (_option(state["runner_argv"], "--guardrail-device") != "cuda:0"
                    or _option(state["runner_argv"], "--local-config-sha256") != _option(unit.spec["base_argv"], "--local-config-sha256")):
                raise ValueError("RR segment lost its one-GPU profile or scoring assignment")
            grid = _load_json(Path(item["grid"]["path"]), label="RR segment grid")
            if grid.get("status") != "complete":
                raise ValueError("RR segment requires a terminal complete grid, not response coverage alone")
            current = retained.load_cells(Path(item["root"]), code_repository=project)
            expected = set(snapshot["selected_ids"][unit.source_lane][unit.corpus]) - set(snapshot["lanes"][unit.source_lane]["outcomes"])
            ids = [row["datapoint_id"] for cell in current for row in cell["attempts"].values()]
            if (len(ids) != unit.selected_records or len(set(ids)) != len(ids) or set(ids) != expected
                    or any(cell["manifest"]["config"]["run"]["corpus"] != unit.corpus for cell in current)):
                raise ValueError("RR segment completed cells do not match the exact remaining input set")
            source_strata.add(item["source"])
            validated[unit_id] = {**item, "physical_gpu": gpu, "source_lane": unit.source_lane, "corpus": unit.corpus}
            worker_cells.extend(current)
        if (worker.get("target_attempts") != sum(len(cell["responses"]) for cell in worker_cells)
                or worker.get("successful_generations") != sum(validated[key]["successful"] for key in launch["queues"][gpu])):
            raise ValueError("RR worker terminal response accounting changed")
        cells.extend(worker_cells)
    if len(source_strata) != 1 or len({cell["run_id"] for cell in [*prefix_cells, *cells]}) != len(prefix_cells) + len(cells):
        raise ValueError("RR supplement has duplicate cells or mixed source conformance")
    handoff = {"schema": SCHEMA, "status": "complete" if prefix["judging_complete"] else "complete_with_pending_prefix_judging",
               "source_completion": _descriptor(path), "interruption": launch["interruption"],
               "coverage": measured_coverage, "prefix": prefix,
               "completed_grid_roots": [item["root"] for item in validated.values()],
               "source_validated_prefix_markers": [_descriptor(cell["complete_path"]) for cell in prefix_cells],
               "historical_144_conditions_replaced": False, "old_grid_promoted": False,
               "cross_condition_pooling_permitted": False, "target_calls": 0, "judge_calls": 0}
    return handoff, validated, cells, prefix_cells


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("completion", "work-root", "project-root", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args(argv)
    work, project = args.work_root.resolve(strict=True), args.project_root.resolve(strict=True)
    handoff, units, cells, prefix_cells = validate(args.completion, work=work, project=project)
    output = args.out
    if not output.is_absolute() or output.exists() or not output.is_relative_to(work / "runs"):
        raise ValueError("RR parallel analysis needs a fresh output directory")
    output.mkdir(parents=True, mode=0o700)
    level1 = export_level1_strata(units, output=output, project=project, continuation=True)
    reports = [ExternalAnalysisReportSpec(Path(item["path"]), "level1", f"RR parallel input coverage - {revision[:12]}")
               for revision, item in level1.items()]
    level2 = {}
    for label, population in (("completed-segments", cells), ("closed-prefix-cells", prefix_cells)):
        if not population:
            continue
        path = output / f"level2-{label}.json"
        _create_json(path, build_level2_report(population, []))
        level2[label] = _descriptor(path)
        reports.append(ExternalAnalysisReportSpec(path, "level2", f"RR outcomes - {label}"))
    # Reuses the exact Attempt/media selector. This is an input inventory, not a
    # funded judge plan, a provider request, or authority to repeat any old call.
    inputs = candidates_from_cells([*cells, *prefix_cells])
    input_path = output / "retained-inputs.json"
    _create_json(input_path, {"schema": "ura-rr-parallel-retained-inputs/1", "inputs": inputs,
                             "input_count": len(inputs), "inputs_sha256": _sha256_json(inputs),
                             "source_completion": handoff["source_completion"], "paid_calls_authorized": False})
    _create_json(output / "completion.json", {**handoff, "level1_by_execution_revision": level1,
                                              "level2_by_evidence_scope": level2,
                                              "retained_inputs": _descriptor(input_path)})
    pending = sum(map(len, handoff["prefix"]["post_factum_judging_required_ids"].values()))
    publish_external_analysis_registration(
        work / "runs", job_id=args.completion.parent.name, analysis_root=output,
        work_label="GraySwan RR - two-GPU supplement", completion_status="complete_with_explicit_limitations",
        explicit_limitations={"prefix_scope": "Old closed cells are independently source-validated; their interrupted parent grid is not promoted.",
                              "prefix_judging": f"{pending} retained prefix responses still need post-factum judging; no old judgment is rerun automatically.",
                              "comparison_scope": "Historical 144 conditions and execution revisions remain separate; a paired contrast requires exact matching."},
        reports=reports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
