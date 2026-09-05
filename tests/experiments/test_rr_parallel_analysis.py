from __future__ import annotations

from dataclasses import asdict
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_parallel_analysis as mod


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return mod._descriptor(path)


def cell(root, ids, *, arm="arm", run_id="cell"):
    return {"run_id": run_id, "source_identity_validated": True,
            "complete_path": root / (run_id + ".complete.json"),
            "manifest": {"config": {"run": {"corpus": arm}}},
            "attempts": {f"attempt-{key}": {"datapoint_id": key} for key in ids},
            "responses": {f"attempt-{key}": {} for key in ids}}


@pytest.mark.parametrize("pending", [False, True])
def test_prefix_preserves_existing_judgments_and_reports_only_actually_unjudged(tmp_path, monkeypatch, pending):
    ids = ["a", "b"] if pending else ["a"]
    snapshot = {"observation": {}, "retained_response_count": len(ids),
                "selected_ids": {"lane": {"arm": ids}}, "lanes": {"lane": {
                    "result_root": str(tmp_path), "outcomes": {key: "usable_first_response" for key in ids},
                    "retained_judgment_ids": ["a"]}}}
    monkeypatch.setattr(mod.campaign, "inspect_prefix", lambda *a, **kw: snapshot)
    monkeypatch.setattr(mod, "_source_prefix_cells", lambda *a, **kw: [cell(tmp_path, ["a"])])
    cells, result = mod.validated_prefix(snapshot, runner_root=tmp_path, project=tmp_path)
    assert len(cells) == 1 and result["source_validated_judgments"] == 1
    assert result["judging_complete"] is (not pending)
    assert result["post_factum_judging_required_ids"] == {"lane": ["b"] if pending else []}
    assert result["new_judge_calls"] == 0 and result["old_grid_promoted"] is False
    assert result["evidence_scope"] == mod.PREFIX_SCOPE


@pytest.mark.parametrize("change", ["snapshot", "foreign", "duplicate", "unvalidated", "judgment"])
def test_prefix_rejects_changed_bytes_or_unvalidated_or_duplicate_judgments(tmp_path, monkeypatch, change):
    snapshot = {"observation": {}, "retained_response_count": 1,
                "selected_ids": {"lane": {"arm": ["a"]}}, "lanes": {"lane": {
                    "result_root": str(tmp_path), "outcomes": {"a": "usable_first_response"},
                    "retained_judgment_ids": ["a"]}}}
    cells = [cell(tmp_path, ["a"])]
    if change == "foreign":
        cells = [cell(tmp_path, ["b"])]
    elif change == "duplicate":
        cells *= 2
    elif change == "unvalidated":
        cells[0]["source_identity_validated"] = False
    elif change == "judgment":
        snapshot["lanes"]["lane"]["retained_judgment_ids"] = []
    monkeypatch.setattr(mod.campaign, "inspect_prefix", lambda *a, **kw: {} if change == "snapshot" else snapshot)
    monkeypatch.setattr(mod, "_source_prefix_cells", lambda *a, **kw: cells)
    with pytest.raises(ValueError):
        mod.validated_prefix(snapshot, runner_root=tmp_path, project=tmp_path)


@pytest.mark.parametrize("change", [None, "source", "membership", "grid"])
def test_prefix_worker_reuses_complete_source_cell_checks_without_promoting_grid(tmp_path, monkeypatch, change):
    from experiments import figure_results, level1_evidence
    from ura import runner

    commit, tree = "a" * 40, "b" * 40
    revision = {"expected_commit": commit, "observed_commit": commit, "head_tree": tree,
                "harness_source_sha256": "c" * 64,
                "driver_source_sha256": hashlib.sha256(Path("experiments/run_matrix.py").read_bytes()).hexdigest()}
    original = {"project_revision": revision, "eligibility_plan": {}, "corpora": ["arm"],
                "models": ["target"], "attackers": ["replay"]}
    grid = {"grid_id": "grid-test", "request": original, "status": "running", "cells": []}
    marker = tmp_path / "cell.complete.json"
    marker_value = {"run_id": "cell", "artifacts": {"manifest": {"file": "cell.manifest.json"}}}
    manifest = {"config": {"run": {"corpus": "arm", "model_spec": "target", "attacker": "replay", "grid_id": "grid-test"}}}
    objects = {tmp_path / "grid-test.grid.json": grid, marker: marker_value,
               tmp_path / "cell.manifest.json": manifest}
    checked = []
    monkeypatch.setattr(level1_evidence, "_read_object", lambda path: objects[path])
    monkeypatch.setattr(level1_evidence, "_plan_artifact", lambda path: ({"bindings": {}},))
    monkeypatch.setattr(level1_evidence, "_plan_descriptor_matches", lambda *a: True)
    monkeypatch.setattr(level1_evidence, "_grid_id", lambda *a: "changed" if change == "grid" else "grid-test")
    monkeypatch.setattr(level1_evidence, "_grid_condition", lambda *a: {})
    monkeypatch.setattr(level1_evidence, "_condition_from_plan", lambda *a: {})
    monkeypatch.setattr(level1_evidence, "_validate_grid_plan_bindings", lambda *a: checked.append("plan"))
    monkeypatch.setattr(level1_evidence, "_validate_grid_model_acquisition", lambda *a, **kw: checked.append("acquisition"))
    monkeypatch.setattr(runner, "_harness_source_identity", lambda: {"sha256": "c" * 64})
    def validate(path, refs):
        assert path == marker and len(refs) == 1
        assert refs[0].request is original and refs[0].grid_id == "grid-test"
        assert "status" not in refs[0].status  # No fabricated terminal status.
        checked.append("full_cell")
        return {"complete_path": str(marker)}
    monkeypatch.setattr(figure_results, "_validate_cell", validate)
    if change == "source":
        revision["harness_source_sha256"] = "d" * 64
    elif change == "membership":
        manifest["config"]["run"]["corpus"] = "foreign"
    request = {"commit": commit, "tree": tree, "groups": [{"grid": str(tmp_path / "grid-test.grid.json"),
                "eligibility": str(tmp_path / "eligibility.json"), "markers": [str(marker)]}]}
    monkeypatch.setattr(mod.sys, "stdin", io.StringIO(json.dumps(request)))
    stdout = io.StringIO()
    monkeypatch.setattr(mod.sys, "stdout", stdout)
    if change:
        with pytest.raises(ValueError):
            exec(mod._PREFIX_WORKER, {})
        assert "full_cell" not in checked
    else:
        exec(mod._PREFIX_WORKER, {})
        assert checked == ["plan", "acquisition", "full_cell"]
        assert json.loads(stdout.getvalue())["validator_commit"] == commit
    assert grid["status"] == "running" and grid["cells"] == []


@pytest.fixture
def complete(tmp_path, monkeypatch):
    work = tmp_path
    root = work / "runs/engineering/parallel"
    root.mkdir(parents=True)
    revision = write(root / "revision.json", {"repository": {"expected_commit": "a" * 40, "observed_commit": "a" * 40}})
    units, selected = [], {}
    for index, (lane, count) in enumerate(mod.campaign.prior.LAYOUT):
        selected[lane] = {"arm": [f"{lane}-{number}" for number in range(count)]}
        units.append(mod.Unit(f"u{index}", lane, "arm", {"base_argv": ["--local-config-sha256", "b" * 64]}, count))
    snapshot = {"selected_ids": selected, "lanes": {lane: {"outcomes": {}} for lane in selected}}
    prefix = {"judging_complete": True, "post_factum_judging_required_ids": {lane: [] for lane in selected}}
    monkeypatch.setattr(mod, "validated_prefix", lambda *a, **kw: ([], prefix))
    coverage = {"complete": True, "expected_inputs": 7606, "retained_inputs": 7606}
    monkeypatch.setattr(mod.campaign, "coverage", lambda launch: coverage)
    launch = {"schema": mod.campaign.SCHEMA, "status": "running", "work_root": str(work),
              "original_population": 7606, "max_tokens": 4096, "tensor_parallel_size": 1,
              "target_answer_retries": 1, "old_grid_promoted": False, "cross_condition_pooling_permitted": False,
              "project_revision": revision, "expected_commit": "a" * 40, "units": [asdict(u) for u in units],
              "queues": mod.campaign.balanced_queues(units),
              "interruption": write(root / "snapshot.json", snapshot),
              "workers": {gpu: str(root.with_name(root.name + f"-gpu{gpu}")) for gpu in ("0", "1")}}
    launch_descriptor = write(root / "launch.json", launch)
    results, cells, workers, worker_descriptors = {}, {}, {}, {}
    for gpu, queue in launch["queues"].items():
        worker_root = Path(launch["workers"][gpu])
        worker_launch = {"schema": mod.campaign.SCHEMA, "parent": launch_descriptor,
                         "physical_gpu": gpu, "unit_order": queue}
        worker = {"schema": mod.campaign.SCHEMA, "status": "complete", "physical_gpu": gpu, "failures": {},
                  "launch": write(worker_root / "launch.json", worker_launch), "results": {key: {"unit_id": key} for key in queue},
                  "target_attempts": 0, "successful_generations": 0}
        for key in queue:
            unit = next(u for u in units if u.unit_id == key)
            result_root = work / "runs/thesis/runner" / key / worker_root.name
            result_root.mkdir(parents=True)
            state = write(worker_root / "units" / key / "state.json", {"runner_argv": [
                "--guardrail-device", "cuda:0", "--local-config-sha256", "b" * 64]})
            grid = write(result_root / "grid.grid.json", {"status": "complete"})
            results[key] = {"revision": revision["sha256"], "source": "c" * 64, "root": str(result_root),
                            "evidence": {"state": state}, "grid": grid, "successful": unit.selected_records,
                            "eligibility_plan": {"path": "bound.eligibility.json"}}
            cells[result_root] = [cell(result_root, selected[unit.source_lane]["arm"], run_id=key)]
            worker["target_attempts"] += unit.selected_records
            worker["successful_generations"] += unit.selected_records
        workers[gpu] = worker
        worker_descriptors[gpu] = write(worker_root / "completion.json", worker)
    checked = []
    def load(root, **kwargs):
        checked.append(root)
        return cells[root]
    monkeypatch.setattr(mod.retained, "load_cells", load)
    monkeypatch.setattr(mod, "_validate_metric_result", lambda result, **kwargs: results[result["unit_id"]])
    value = {**launch, "status": "responses_complete_pending_prefix_validation", "launch": launch_descriptor,
             "worker_exit_codes": {"0": 0, "1": 0}, "worker_completions": worker_descriptors, "coverage": dict(coverage)}
    path = root / "completion.json"
    write(path, value)
    return SimpleNamespace(work=work, root=root, path=path, value=value, workers=workers,
                           results=results, cells=cells, checked=checked, coverage=coverage, launch=launch)


def test_complete_analysis_requires_all_grids_and_preserves_separate_prefix_scope(complete):
    f = complete
    handoff, units, cells, prefix = mod.validate(f.path, work=f.work, project=f.work)
    assert handoff["status"] == "complete" and handoff["prefix"]["judging_complete"] is True
    assert handoff["coverage"]["retained_inputs"] == 7606
    assert len(f.checked) == len(units) == len(cells) == 4 and prefix == []
    assert handoff["target_calls"] == handoff["judge_calls"] == 0
    assert handoff["old_grid_promoted"] is handoff["historical_144_conditions_replaced"] is False


@pytest.mark.parametrize("change", ["running_grid", "worker_failed", "worker_gpu", "missing", "revision", "foreign_cell", "changed_launch", "loader_rejects"])
def test_analysis_rejects_unfinished_or_changed_segments(complete, monkeypatch, change):
    f = complete
    if change == "running_grid":
        write(Path(f.results["u0"]["grid"]["path"]), {"status": "running"})
    elif change in {"worker_failed", "worker_gpu"}:
        f.workers["0"]["status" if change == "worker_failed" else "physical_gpu"] = "failed" if change == "worker_failed" else "1"
        f.value["worker_completions"]["0"] = write(Path(f.launch["workers"]["0"]) / "completion.json", f.workers["0"])
    elif change == "missing":
        f.coverage["complete"] = False
    elif change == "revision":
        f.results["u0"]["revision"] = "d" * 64
    elif change == "foreign_cell":
        attempts = next(iter(f.cells.values()))[0]["attempts"]
        attempts[next(iter(attempts))]["datapoint_id"] = "foreign"
    elif change == "changed_launch":
        f.value["max_tokens"] = 2048
    else:
        def reject(*a, **kw):
            raise ValueError("source cell artifact changed")
        monkeypatch.setattr(mod.retained, "load_cells", reject)
    write(f.path, f.value)
    with pytest.raises(ValueError):
        mod.validate(f.path, work=f.work, project=f.work)


def test_publication_keeps_prefix_metrics_separate_and_has_no_paid_authority(tmp_path, monkeypatch):
    output = tmp_path / "runs/analysis"
    source = tmp_path / "runs/engineering/parallel/completion.json"
    source_descriptor = write(source, {})
    cells, prefix = [cell(tmp_path, ["new"], run_id="new")], [cell(tmp_path, ["old"], run_id="old")]
    handoff = {"source_completion": source_descriptor, "prefix": {"post_factum_judging_required_ids": {"lane": []}}}
    monkeypatch.setattr(mod, "validate", lambda *a, **kw: (handoff, {}, cells, prefix))
    monkeypatch.setattr(mod, "export_level1_strata", lambda *a, **kw: {})
    populations = []
    def report(rows, native):
        populations.append([row["run_id"] for row in rows])
        return {"rows": populations[-1]}
    monkeypatch.setattr(mod, "build_level2_report", report)
    monkeypatch.setattr(mod, "candidates_from_cells", lambda rows: [{"run_id": row["run_id"]} for row in rows])
    published = []
    monkeypatch.setattr(mod, "publish_external_analysis_registration", lambda *a, **kw: published.append(kw))
    assert mod.main(["--completion", str(source), "--work-root", str(tmp_path),
                     "--project-root", str(tmp_path), "--out", str(output)]) == 0
    assert populations == [["new"], ["old"]]
    inputs = json.loads((output / "retained-inputs.json").read_text())
    assert inputs["input_count"] == 2 and inputs["paid_calls_authorized"] is False
    assert len(published) == 1 and len(published[0]["reports"]) == 2
    assert "not promoted" in published[0]["explicit_limitations"]["prefix_scope"]
