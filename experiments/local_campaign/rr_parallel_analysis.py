"""Validate the RR parallel supplement without promoting its interrupted prefix.

The historical 144-condition analysis is not replaced. New worker segments must
be complete grids; old closed cells have an explicitly narrower evidence scope.
No target or judge is constructed by this analysis handoff.
"""
from __future__ import annotations

import argparse
import inspect
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
from experiments.local_campaign.console_events import finish_child_controller, start_child_controller
from experiments.local_campaign.rr_profiled_analysis import export_level1_strata
from experiments.local_campaign.vllm_input_recovery_phase6 import _validate_metric_result
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit, _create_json, _load_json, _option, _sha256_json, _validate_descriptor,
)
from experiments.rig_web_app.external_analysis import (
    ExternalAnalysisReportSpec, publish_external_analysis_registration,
)
from ura.project_revision import load_project_revision_file, project_revision_binding

SCHEMA = "ura-rr-parallel-analysis/1"
PREFIX_SCOPE = "source_validated_closed_cell_in_interrupted_grid"

_COVERAGE_WORKER = r'''
import hashlib, json, sys
from pathlib import Path
from experiments.local_campaign.rr_parallel_campaign import coverage
from ura.runner import _harness_source_identity

request = json.load(sys.stdin)
revision = request["revision"]
if (revision["harness_source_sha256"] != _harness_source_identity()["sha256"]
    or revision["driver_source_sha256"] != hashlib.sha256(Path("experiments/run_matrix.py").read_bytes()).hexdigest()):
    raise ValueError("RR reported coverage source differs from its original checkout")
print(json.dumps({"validator_commit": request["commit"], "coverage": coverage(request["launch"])}))
'''

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
result = {"validator_commit": request["commit"], "cells": cells}
if request.get("joined"):
    from experiments import human_audit
    exec(request["media_export_source"], human_audit.__dict__)
    result["joined"] = []
    original_inventory = human_audit._validated_artifacts
    try:
        for group in request["groups"]:
            root = Path(group["grid"]).parent
            selected = [cell for cell in cells if cell["complete_path"].parent == root]
            roles = {role: [cell["artifacts"][role] for cell in selected]
                     for role in ("attempts", "responses", "judgments", "trails", "results", "manifest")}
            all_paths = [path for paths in roles.values() for path in paths]
            if len(all_paths) != len(set(all_paths)):
                raise ValueError("RR prefix join repeats a source-validated artifact")
            # These exact closed cells have already passed the ORIGINAL full
            # cell, source, request and eligibility checks above. Only the
            # lossless join receives their role inventory; no parent grid is
            # substituted, completed, or admitted by this scoped data view.
            def scoped_inventory(asked):
                if asked != root:
                    raise ValueError("RR prefix join changed its bound root")
                return roles, selected
            human_audit._validated_artifacts = scoped_inventory
            result["joined"].append(human_audit._joined_artifacts(root, frame="common"))
    finally:
        human_audit._validated_artifacts = original_inventory
def json_default(item):
    if isinstance(item, Path):
        return str(item)
    raise TypeError(type(item).__name__)
print(json.dumps(result, default=json_default, allow_nan=False))
'''


def _descriptor(path: Path, label: str = "RR analysis artifact") -> dict:
    return campaign.prior._descriptor(path, label=label)


def _same_launch(completion: dict, launch: dict) -> None:
    if any(completion.get(key) != value for key, value in launch.items() if key != "status"):
        raise ValueError("RR completion changed its bound launch")


def _execution_source_coverage(launch: dict, *, project: Path) -> dict:
    """Reproduce the retained controller's counter, not its completion claim."""
    revision_path = _validate_descriptor(launch["project_revision"], label="RR counter source receipt")
    receipt, descriptor = load_project_revision_file(
        revision_path, launch["project_revision"]["sha256"],
        project / "experiments/run_matrix.py", recheck_checkout=False,
    )
    revision = project_revision_binding(receipt, descriptor)
    commit = launch["expected_commit"]
    if any(revision.get(key) != commit for key in ("expected_commit", "observed_commit")):
        raise ValueError("RR counter source receipt changed")
    retained._git(project, "merge-base", "--is-ancestor", commit, retained._git(project, "rev-parse", "HEAD"))
    if retained._git(project, "rev-parse", f"{commit}^{{tree}}") != revision["head_tree"]:
        raise ValueError("RR counter source tree changed")
    with tempfile.TemporaryDirectory(prefix="ura-rr-counter-reader-") as scratch:
        worktree = Path(scratch).resolve() / "source"
        installed = False
        try:
            retained._git(project, "worktree", "add", "--quiet", "--detach", str(worktree), commit)
            installed = True
            environment = dict(os.environ)
            environment.update(PYTHONPATH=str(worktree / "src"), PYTHONDONTWRITEBYTECODE="1")
            for key in list(environment):
                if key.endswith(("_API_KEY", "_TOKEN")):
                    environment.pop(key)
            result = subprocess.run(
                [sys.executable, "-c", _COVERAGE_WORKER], cwd=worktree, env=environment,
                input=json.dumps({"launch": launch, "revision": revision, "commit": commit}),
                capture_output=True, text=True, encoding="utf-8", timeout=600, check=False,
            )
            if result.returncode:
                raise ValueError("RR original coverage reader failed: " + result.stderr[-4000:])
            value = retained._decode_validator_ipc(result.stdout)
            if (not isinstance(value, dict) or set(value) != {"validator_commit", "coverage"}
                    or value["validator_commit"] != commit or not isinstance(value["coverage"], dict)):
                raise ValueError("RR original coverage reader returned an invalid result")
            return value["coverage"]
        finally:
            if installed:
                retained._git(project, "worktree", "remove", "--force", str(worktree))


def _source_prefix_cells(snapshot: dict, *, project: Path, joined: bool = False):
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
        return ([], []) if joined else []
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
            from experiments.human_audit import _portable_media_references

            request = {"groups": groups, "commit": commit, "tree": tree, "joined": joined,
                       "media_export_source": inspect.getsource(_portable_media_references) if joined else ""}
            result = subprocess.run([sys.executable, "-c", _PREFIX_WORKER], cwd=worktree, env=env,
                                    input=json.dumps(request),
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
            return (cells, value["joined"]) if joined else cells
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


def _retry_results(paths: Sequence[Path], *, original_launch: Path, work: Path) -> dict:
    replacements = {}
    for path_value in paths:
        path = path_value.resolve(strict=True)
        value = _load_json(path, label="RR retry completion")
        launch_path = _validate_descriptor(value["launch"], label="RR retry launch")
        launch = _load_json(launch_path, label="RR retry launch")
        _same_launch(value, launch)
        bound_original = _validate_descriptor(launch["original_launch"], label="RR retry original launch")
        worker_path = _validate_descriptor(launch["original_worker_completion"], label="RR retry original worker")
        if (path.parent.parent != work / "runs/engineering" or launch_path != path.parent / "launch.json"
                or value.get("schema") != campaign.RETRY_SCHEMA or value.get("status") != "complete"
                or value.get("failures") != {} or bound_original != original_launch):
            raise ValueError("RR retry lacks its exact successful terminal and original launch")
        _old, units, evidence = campaign.template_retry_selection(bound_original, worker_path, launch["physical_gpu"])
        revision = _load_json(_validate_descriptor(launch["project_revision"], label="RR retry revision"), label="RR retry revision")
        if (launch["units"] != [campaign.asdict(unit) for unit in units] or launch["failure_evidence"] != evidence
                or set(value["results"]) != {unit.unit_id for unit in units}
                or any(revision.get("repository", {}).get(key) != launch["expected_commit"] for key in ("expected_commit", "observed_commit"))
                or value["target_attempts"] != sum(result["target_attempts"] for result in value["results"].values())
                or value["successful_generations"] != sum(result["successful_target_generations"] for result in value["results"].values())):
            raise ValueError("RR retry changed its qualified failures, selection, revision or accounting")
        for unit in units:
            terminal = _load_json(path.parent / f"{unit.unit_id}.terminal.json", label="RR retry unit terminal")
            if unit.unit_id in replacements or terminal != {"result": value["results"][unit.unit_id], "failure": None}:
                raise ValueError("RR retry repeats a unit or changed its terminal result")
            replacements[unit.unit_id] = {"result": value["results"][unit.unit_id], "root": path.parent,
                "completion": _descriptor(path), "original_worker": launch["original_worker_completion"],
                "revision": launch["project_revision"], "commit": launch["expected_commit"], "gpu": launch["physical_gpu"]}
    return replacements


def validate(completion_path: Path, *, work: Path, project: Path,
             retry_completions: Sequence[Path] = ()) -> tuple[dict, dict, list[dict], list[dict]]:
    path = completion_path.resolve(strict=True)
    root = path.parent
    if root.parent != work / "runs/engineering":
        raise ValueError("RR parallel completion is outside the campaign directory")
    value = _load_json(path, label="RR parallel completion")
    launch_path = _validate_descriptor(value["launch"], label="RR parallel launch")
    launch = _load_json(launch_path, label="RR parallel launch")
    if (launch_path != root / "launch.json" or value.get("schema") != campaign.SCHEMA
            or value.get("status") not in ({"responses_complete_pending_prefix_validation", "complete_with_failures"}
                                          if retry_completions else {"responses_complete_pending_prefix_validation"})
            or (not retry_completions and value.get("worker_exit_codes") != {"0": 0, "1": 0})
            or set(value.get("worker_exit_codes", {})) != {"0", "1"}
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
    replacements = _retry_results(retry_completions, original_launch=launch_path, work=work)
    snapshot_path = _validate_descriptor(launch["interruption"], label="RR interrupted prefix")
    snapshot = _load_json(snapshot_path, label="RR interrupted prefix")
    prefix_cells, prefix = validated_prefix(snapshot, runner_root=work / "runs/thesis/runner", project=project)
    original_coverage = campaign.coverage(launch)
    measured_coverage = (campaign.coverage(launch, replacement_roots={
        key: work / "runs/thesis/runner" / key / item["root"].name for key, item in replacements.items()})
        if replacements else original_coverage)
    if not measured_coverage["complete"] or measured_coverage["expected_inputs"] != 7606:
        raise ValueError("RR parallel analysis requires the exact 7,606-input disjoint union")
    reported_coverage = value.get("coverage")
    counter_correction = original_coverage != reported_coverage
    if counter_correction and _execution_source_coverage(launch, project=project) != reported_coverage:
        raise ValueError("RR reported coverage differs from its exact original execution source")
    revision_path = _validate_descriptor(launch["project_revision"], label="RR parallel revision")
    revision = _load_json(revision_path, label="RR parallel revision")["repository"]
    if any(revision.get(key) != launch["expected_commit"] for key in ("expected_commit", "observed_commit")):
        raise ValueError("RR parallel analysis source receipt changed")
    by_id = {unit.unit_id: unit for unit in units}
    validated, cells = {}, []
    source_strata = set()
    replaced = set()
    for gpu in ("0", "1"):
        worker_root = root.with_name(root.name + f"-gpu{gpu}")
        worker_path = _validate_descriptor(value["worker_completions"][gpu], label="RR worker completion")
        worker = _load_json(worker_path, label="RR worker completion")
        worker_launch_path = _validate_descriptor(worker["launch"], label="RR worker launch")
        worker_launch = _load_json(worker_launch_path, label="RR worker launch")
        failures = worker.get("failures", {})
        retried = {key for key, item in replacements.items() if item["gpu"] == gpu}
        if (launch["workers"][gpu] != str(worker_root) or worker_path != worker_root / "completion.json"
                or worker_launch_path != worker_root / "launch.json"
                or worker_launch != {"schema": campaign.SCHEMA, "parent": value["launch"],
                                     "physical_gpu": gpu, "unit_order": launch["queues"][gpu]}
                or worker.get("schema") != campaign.SCHEMA
                or worker.get("status") != ("complete_with_failures" if failures else "complete")
                or value["worker_exit_codes"][gpu] != int(bool(failures))
                or worker.get("physical_gpu") != gpu or set(failures) != retried
                or set(worker.get("results", {})) & retried
                or set(worker.get("results", {})) | retried != set(launch["queues"][gpu])):
            raise ValueError("RR worker terminal or original GPU assignment changed")
        worker_cells = []
        for unit_id in launch["queues"][gpu]:
            unit = by_id[unit_id]
            retry = replacements.get(unit_id)
            if retry and retry["original_worker"] != value["worker_completions"][gpu]:
                raise ValueError("RR retry refers to a different original worker completion")
            segment_root = retry["root"] if retry else worker_root
            completion = retry["completion"] if retry else value["worker_completions"][gpu]
            result = retry["result"] if retry else worker["results"][unit_id]
            revision_descriptor = retry["revision"] if retry else launch["project_revision"]
            item = _validate_metric_result(
                result, logical_lane=unit.source_lane, physical_unit=unit_id,
                source_lane=unit.source_lane, corpus=unit.corpus, selected_records=unit.selected_records,
                runner_root=work / "runs/thesis/runner", control_root=segment_root,
                state_schema=campaign.STATE_SCHEMA, completion=completion)
            if item["revision"] != revision_descriptor["sha256"]:
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
            if retry:
                replaced.add(unit_id)
                cells.extend(current)
            else:
                worker_cells.extend(current)
        if (worker.get("target_attempts") != sum(len(cell["responses"]) for cell in worker_cells)
                or worker.get("successful_generations") != sum(validated[key]["successful"] for key in worker["results"])):
            raise ValueError("RR worker terminal response accounting changed")
        cells.extend(worker_cells)
    if replaced != set(replacements):
        raise ValueError("RR retry coverage omitted or added a failed unit")
    if value["status"] != ("complete_with_failures" if replaced else "responses_complete_pending_prefix_validation"):
        raise ValueError("RR original parent terminal status changed")
    if len(source_strata) != 1 or len({cell["run_id"] for cell in [*prefix_cells, *cells]}) != len(prefix_cells) + len(cells):
        raise ValueError("RR supplement has duplicate cells or mixed source conformance")
    handoff = {"schema": SCHEMA, "status": "complete" if prefix["judging_complete"] else "complete_with_pending_prefix_judging",
               "source_completion": _descriptor(path), "interruption": launch["interruption"],
               "execution_commit": launch["expected_commit"],
               "coverage": measured_coverage, "prefix": prefix,
               "completed_grid_roots": [item["root"] for item in validated.values()],
               "source_validated_prefix_markers": [_descriptor(cell["complete_path"]) for cell in prefix_cells],
               "historical_144_conditions_replaced": False, "old_grid_promoted": False,
               "cross_condition_pooling_permitted": False, "target_calls": 0, "judge_calls": 0}
    if replacements:
        handoff.update(retry_completions=[_descriptor(path) for path in retry_completions],
                       original_coverage=original_coverage,
                       retry_execution_commits=sorted({item["commit"] for item in replacements.values()}))
    if counter_correction:
        handoff.update(reported_original_coverage=reported_coverage,
                       corrected_original_coverage=original_coverage,
                       reported_coverage_validator_commit=launch["expected_commit"])
    return handoff, validated, cells, prefix_cells


def _merge_judge_views(parts: list[tuple]) -> tuple[list[dict], dict, dict, dict]:
    """Merge identities only; the ordinary Haiku matcher retains every stratum."""
    cells, metadata, judgments, seen = [], {}, {}, set()
    audit = {"policy_evaluable_samples": 0, "common_ineligible_evaluable_rows_excluded": 0}
    for current, meta, labels, counts in parts:
        run_ids = [cell["run_id"] for cell in current]
        if (len(set(run_ids)) != len(run_ids) or seen.intersection(run_ids)
                or meta.keys() != labels.keys() or metadata.keys() & meta.keys()):
            raise ValueError("RR judge view contains duplicate or incomplete source joins")
        seen.update(run_ids)
        cells.extend(current)
        metadata.update(meta)
        judgments.update(labels)
        for key in audit:
            value = counts[key]
            if type(value) is not int or value < 0:
                raise ValueError("RR judge view has invalid source-frame accounting")
            audit[key] += value
    return cells, metadata, judgments, audit


def load_judge_view(root: Path, *, project: Path = retained._REPOSITORY):
    """Revalidate an already complete analysis before any paid-plan selection.

    This is not a new judge plan or execution schema. Its return value is the
    same source-validated join consumed by the existing candidate builder.
    """
    root = root.resolve(strict=True)
    saved = _load_json(root / "completion.json", label="RR completed analysis")
    if saved.get("schema") != SCHEMA or saved.get("status") != "complete":
        raise ValueError("RR judging requires a fully complete parallel analysis handoff")
    source_path = _validate_descriptor(saved["source_completion"], label="RR analysis source completion")
    source = _load_json(source_path, label="RR analysis source completion")
    work = Path(source["work_root"]).resolve(strict=True)
    retry_paths = [_validate_descriptor(item, label="RR retained retry completion")
                   for item in saved.get("retry_completions", [])]
    retry_options = {"retry_completions": retry_paths} if retry_paths else {}
    fresh, units, cells, prefix_cells = validate(source_path, work=work, project=project, **retry_options)
    if (fresh["status"] != "complete" or not fresh["prefix"]["judging_complete"]
            or any(saved.get(key) != value for key, value in fresh.items())):
        raise ValueError("RR judging handoff changed its complete coverage/source bindings")
    expected_level2 = {"completed-segments", *(["closed-prefix-cells"] if prefix_cells else [])}
    if (set(saved["level1_by_execution_revision"]) != {item["revision"] for item in units.values()}
            or set(saved["level2_by_evidence_scope"]) != expected_level2):
        raise ValueError("RR judging handoff changed its revision or evidence-scope reports")
    reports = [saved["retained_inputs"], *saved["level1_by_execution_revision"].values(),
               *saved["level2_by_evidence_scope"].values()]
    for descriptor in reports:
        if not _validate_descriptor(descriptor, label="RR analysis report").is_relative_to(root):
            raise ValueError("RR judging report escaped its completed analysis root")
    parts = [retained.load_joined(Path(item["root"]), code_repository=project) for item in units.values()]
    snapshot_path = _validate_descriptor(saved["interruption"], label="RR stopped prefix")
    snapshot = _load_json(snapshot_path, label="RR stopped prefix")
    old_cells, joins = _source_prefix_cells(snapshot, project=project, joined=True)
    if {cell["run_id"] for cell in old_cells} != {cell["run_id"] for cell in prefix_cells}:
        raise ValueError("RR judge join changed its source-validated prefix cells")
    for _predictors, meta, judgments, audit in joins:
        runs = {row["run_id"] for row in meta.values()}
        scoped = [cell for cell in old_cells if cell["run_id"] in runs]
        parts.append((scoped, meta, judgments, audit))
    result = _merge_judge_views(parts)
    if {cell["run_id"] for cell in result[0]} != {cell["run_id"] for cell in [*cells, *prefix_cells]}:
        raise ValueError("RR judge view omitted or added a retained cell")
    return result


def _publish(output: Path, *, handoff: dict, units: dict, cells: list[dict],
             prefix_cells: list[dict], project: Path, work: Path, job_id: str) -> None:
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
        work / "runs", job_id=job_id, analysis_root=output,
        work_label="GraySwan RR - two-GPU supplement", completion_status="complete_with_explicit_limitations",
        explicit_limitations={"prefix_scope": "Old closed cells are independently source-validated; their interrupted parent grid is not promoted.",
                              "prefix_judging": f"{pending} retained prefix responses still need post-factum judging; no old judgment is rerun automatically.",
                              "comparison_scope": "Historical 144 conditions and execution revisions remain separate; a paired contrast requires exact matching."},
        reports=reports)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("completion", "work-root", "project-root", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    for name in ("tmux-socket", "tmux-session"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--retry-completion", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    work, project = args.work_root.resolve(strict=True), args.project_root.resolve(strict=True)
    retry_options = {"retry_completions": args.retry_completion} if args.retry_completion else {}
    handoff, units, cells, prefix_cells = validate(args.completion, work=work, project=project, **retry_options)
    handoff["analysis_commit"] = retained._git(project, "rev-parse", "HEAD")
    output = args.out
    if not output.is_absolute() or output.exists() or not output.is_relative_to(work / "runs"):
        raise ValueError("RR parallel analysis needs a fresh output directory")
    control = work / "runs/engineering" / (args.completion.parent.name + "-analysis")
    control.mkdir(mode=0o700)
    output.mkdir(parents=True, mode=0o700)
    # The measured parent has two registered workers, but no fake parent job.
    # Register this actual analysis process so Stats can discover its reports.
    start_child_controller(work_root=work, control_root=control, campaign_id=control.name,
                           release_commit=handoff["analysis_commit"], evidence_class="rr_analysis_read_only",
                           hard_stop_hours=6, tmux_socket=args.tmux_socket, tmux_session=args.tmux_session,
                           target_execution=False)
    code = 1
    try:
        _publish(output, handoff=handoff, units=units, cells=cells, prefix_cells=prefix_cells,
                 project=project, work=work, job_id=control.name)
        _create_json(control / "completion.json", {"schema": SCHEMA, "status": handoff["status"],
                     "analysis_completion": _descriptor(output / "completion.json"),
                     "target_calls": 0, "judge_calls": 0})
        code = 0
    finally:
        finish_child_controller(work_root=work, control_root=control, exit_code=code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
