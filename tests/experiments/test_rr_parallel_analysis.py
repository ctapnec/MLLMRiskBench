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
@pytest.mark.parametrize("joined", [False, True])
def test_prefix_worker_reuses_complete_source_cell_checks_without_promoting_grid(tmp_path, monkeypatch, change, joined):
    from experiments import figure_results, human_audit, level1_evidence
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
        return {"complete_path": marker, "artifacts": {
            role: tmp_path / f"cell.{role}" for role in
            ("attempts", "responses", "judgments", "trails", "results", "manifest")}}
    monkeypatch.setattr(figure_results, "_validate_cell", validate)
    inventory = human_audit._validated_artifacts
    def join(root, frame):
        assert checked == ["plan", "acquisition", "full_cell"]
        assert root == tmp_path and frame == "common"
        roles, selected = human_audit._validated_artifacts(root)
        assert selected[0]["complete_path"] == marker
        assert set(roles) == {"attempts", "responses", "judgments", "trails", "results", "manifest"}
        assert all(paths == [tmp_path / f"cell.{role}"] for role, paths in roles.items())
        with pytest.raises(ValueError, match="bound root"):
            human_audit._validated_artifacts(root / "foreign")
        checked.append("lossless_join")
        return {}, {}, {}, {}
    monkeypatch.setattr(human_audit, "_joined_artifacts", join)
    if change == "source":
        revision["harness_source_sha256"] = "d" * 64
    elif change == "membership":
        manifest["config"]["run"]["corpus"] = "foreign"
    request = {"commit": commit, "tree": tree, "joined": joined, "media_export_source": "", "groups": [{"grid": str(tmp_path / "grid-test.grid.json"),
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
        assert checked == ["plan", "acquisition", "full_cell", *(["lossless_join"] if joined else [])]
        assert json.loads(stdout.getvalue())["validator_commit"] == commit
    assert human_audit._validated_artifacts is inventory
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
    assert "reported_original_coverage" not in handoff


@pytest.mark.parametrize("change", [None, "harness", "driver"])
def test_original_counter_worker_requires_the_exact_execution_source(monkeypatch, change):
    from ura import runner

    revision = {"harness_source_sha256": "c" * 64,
                "driver_source_sha256": hashlib.sha256(Path("experiments/run_matrix.py").read_bytes()).hexdigest()}
    if change:
        revision[f"{change}_source_sha256"] = "d" * 64
    request = {"commit": "a" * 40, "revision": revision, "launch": {"original": True}}
    counted = []
    def count(launch):
        counted.append(launch)
        return {"complete": False, "retained_inputs": 515}
    monkeypatch.setattr(mod.campaign, "coverage", count)
    monkeypatch.setattr(runner, "_harness_source_identity", lambda: {"sha256": "c" * 64})
    monkeypatch.setattr(mod.sys, "stdin", io.StringIO(json.dumps(request)))
    output = io.StringIO()
    monkeypatch.setattr(mod.sys, "stdout", output)
    if change:
        with pytest.raises(ValueError, match="original checkout"):
            exec(mod._COVERAGE_WORKER, {})
        assert counted == []
    else:
        exec(mod._COVERAGE_WORKER, {})
        assert counted == [request["launch"]]
        assert json.loads(output.getvalue()) == {
            "validator_commit": "a" * 40, "coverage": {"complete": False, "retained_inputs": 515},
        }


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
    handoff = {"source_completion": source_descriptor, "execution_commit": "a" * 40, "status": "complete",
               "prefix": {"post_factum_judging_required_ids": {"lane": []}}}
    monkeypatch.setattr(mod, "validate", lambda *a, **kw: (handoff, {}, cells, prefix))
    monkeypatch.setattr(mod.retained, "_git", lambda *a: "b" * 40)
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
                     "--project-root", str(tmp_path), "--out", str(output),
                     "--tmux-socket", "rr-analysis", "--tmux-session", "rr-analysis"]) == 0
    assert populations == [["new"], ["old"]]
    inputs = json.loads((output / "retained-inputs.json").read_text())
    assert inputs["input_count"] == 2 and inputs["paid_calls_authorized"] is False
    assert len(published) == 1 and len(published[0]["reports"]) == 2
    assert published[0]["job_id"] == "parallel-analysis"
    assert "not promoted" in published[0]["explicit_limitations"]["prefix_scope"]
    job = tmp_path / "runs/engineering/parallel-analysis"
    marker = json.loads((job / "ENGINEERING_ONLY.json").read_text())
    assert marker["release_commit"] == "b" * 40
    assert marker["model_tasks"] == [] and marker["hosted_calls_allowed"] is False
    assert not (job / "model-execution.jsonl").exists()
    terminal = json.loads((job / "completion.json").read_text())
    assert terminal["target_calls"] == terminal["judge_calls"] == 0
    events = [json.loads(line) for line in (job / "task-log.jsonl").read_text().splitlines()]
    assert events[-1]["event"] == "campaign_end" and events[-1]["status"] == "passed"


@pytest.fixture
def judge_handoff(tmp_path, monkeypatch):
    root = tmp_path / "analysis"
    source = write(tmp_path / "parallel/completion.json", {"work_root": str(tmp_path)})
    snapshot = write(tmp_path / "snapshot.json", {"retained_response_count": 200})
    old = cell(tmp_path / "old", ["old"], run_id="old")
    new = cell(tmp_path / "new", ["new"], run_id="new")
    units = {"unit": {"root": str(tmp_path / "new"), "revision": "a" * 64}}
    fresh = {"schema": mod.SCHEMA, "status": "complete", "source_completion": source,
             "interruption": snapshot, "coverage": {"expected_inputs": 7606, "complete": True},
             "prefix": {"judging_complete": True}, "old_grid_promoted": False}
    saved = {**fresh, "level1_by_execution_revision": {
                 "a" * 64: write(root / "level1.json", {})},
             "level2_by_evidence_scope": {
                 scope: write(root / f"{scope}.json", {}) for scope in
                 ("completed-segments", "closed-prefix-cells")},
             "retained_inputs": write(root / "inputs.json", {})}
    write(root / "completion.json", saved)
    checked = []
    def validate(path, *, work, project):
        assert path == Path(source["path"]) and work == project == tmp_path
        checked.append("full_validation")
        return fresh, units, [new], [old]
    monkeypatch.setattr(mod, "validate", validate)
    audit = {"policy_evaluable_samples": 1, "common_ineligible_evaluable_rows_excluded": 0}
    def load(root, **kwargs):
        assert checked == ["full_validation"] and root == tmp_path / "new"
        return [new], {"new": {"run_id": "new"}}, {"new": {}}, audit
    monkeypatch.setattr(mod.retained, "load_joined", load)
    monkeypatch.setattr(mod, "_source_prefix_cells", lambda _snapshot, **kwargs: (
        [old], [[{}, {"old": {"run_id": "old"}}, {"old": {}}, audit]]))
    return SimpleNamespace(root=root, work=tmp_path, saved=saved, fresh=fresh,
                           checked=checked, old=old, new=new)


def test_judge_handoff_revalidates_complete_population_and_merges_only_identities(judge_handoff):
    f = judge_handoff
    cells, meta, judgments, audit = mod.load_judge_view(f.root, project=f.work)
    assert f.checked == ["full_validation"]
    assert {row["run_id"] for row in cells} == {"new", "old"}
    assert meta.keys() == judgments.keys() == {"new", "old"}
    assert audit == {"policy_evaluable_samples": 2, "common_ineligible_evaluable_rows_excluded": 0}
    assert f.saved["old_grid_promoted"] is False


@pytest.mark.parametrize("change", ["pending", "coverage", "fresh_pending", "source", "report",
                                    "scope", "revision", "prefix", "duplicate", "full_reject"])
def test_judge_handoff_rejects_changed_or_incomplete_source_before_selection(judge_handoff, monkeypatch, change):
    f = judge_handoff
    if change == "pending":
        f.saved["status"] = "complete_with_pending_prefix_judging"
    elif change == "coverage":
        f.saved["coverage"] = {"expected_inputs": 7605, "complete": True}
    elif change == "fresh_pending":
        f.fresh["status"] = "complete_with_pending_prefix_judging"
    elif change == "source":
        Path(f.saved["source_completion"]["path"]).write_text("{}")
    elif change == "report":
        Path(f.saved["retained_inputs"]["path"]).write_text('{"changed":true}')
    elif change == "scope":
        f.saved["level2_by_evidence_scope"].pop("closed-prefix-cells")
    elif change == "revision":
        f.saved["level1_by_execution_revision"] = {}
    elif change == "prefix":
        monkeypatch.setattr(mod, "_source_prefix_cells", lambda *a, **kw: ([], []))
    elif change == "duplicate":
        monkeypatch.setattr(mod, "_source_prefix_cells", lambda *a, **kw: ([f.old], [[
            {}, {"new": {"run_id": "old"}}, {"new": {}},
            {"policy_evaluable_samples": 1, "common_ineligible_evaluable_rows_excluded": 0}]]))
    else:
        def reject(*a, **kw):
            raise ValueError("original full source validation failed")
        monkeypatch.setattr(mod, "validate", reject)
    write(f.root / "completion.json", f.saved)
    with pytest.raises(ValueError):
        mod.load_judge_view(f.root, project=f.work)


@pytest.mark.parametrize("change", ["duplicate_run", "incomplete", "negative", "boolean"])
def test_judge_view_merge_rejects_ambiguous_accounting(tmp_path, change):
    rows = [cell(tmp_path, ["x"])]
    meta, labels = {"x": {}}, {"x": {}}
    counts = {"policy_evaluable_samples": 1, "common_ineligible_evaluable_rows_excluded": 0}
    if change == "duplicate_run":
        rows *= 2
    elif change == "incomplete":
        labels = {}
    else:
        counts["policy_evaluable_samples"] = -1 if change == "negative" else True
    with pytest.raises(ValueError):
        mod._merge_judge_views([(rows, meta, labels, counts)])


@pytest.fixture
def retried(complete, monkeypatch):
    f = complete
    gpu = next(gpu for gpu, queue in f.launch["queues"].items() if "u0" in queue)
    unit = next(mod.Unit(**item) for item in f.launch["units"] if item["unit_id"] == "u0")
    worker = f.workers[gpu]
    worker["results"].pop("u0")
    worker.update(status="complete_with_failures", failures={"u0": {"error": "template"}})
    worker["target_attempts"] -= unit.selected_records
    worker["successful_generations"] -= unit.selected_records
    f.value["worker_completions"][gpu] = write(Path(f.launch["workers"][gpu]) / "completion.json", worker)
    f.value["worker_exit_codes"][gpu] = 1
    f.value["status"] = "complete_with_failures"
    old_coverage = {**f.coverage, "complete": False, "retained_inputs": 7606 - unit.selected_records}
    f.value["coverage"] = old_coverage
    write(f.path, f.value)
    root = f.work / "runs/engineering/retry"
    result_root = f.work / "runs/thesis/runner/u0/retry"
    revision = write(root / "revision.json", {"repository": {"expected_commit": "d" * 40, "observed_commit": "d" * 40}})
    result = {"unit_id": "u0", "target_attempts": unit.selected_records,
              "successful_target_generations": unit.selected_records}
    admission = {"schema": mod.campaign.RETRY_SCHEMA, "original_launch": f.value["launch"],
                 "original_worker_completion": f.value["worker_completions"][gpu], "physical_gpu": gpu,
                 "project_revision": revision, "expected_commit": "d" * 40,
                 "units": [asdict(unit)], "failure_evidence": {"u0": {"bound": True}}}
    value = {**admission, "status": "complete", "launch": write(root / "launch.json", admission),
             "results": {"u0": result}, "failures": {}, "target_attempts": unit.selected_records,
             "successful_generations": unit.selected_records}
    path = root / "completion.json"
    write(path, value)
    write(root / "u0.terminal.json", {"result": result, "failure": None})
    old_root = Path(f.results["u0"]["root"])
    rows = f.cells[old_root][0]["attempts"]
    f.cells[result_root] = [cell(result_root, [row["datapoint_id"] for row in rows.values()], run_id="retry-u0")]
    f.results["u0"].update(root=str(result_root), revision=revision["sha256"],
        evidence={"state": write(root / "units/u0/state.json", {"runner_argv": [
            "--guardrail-device", "cuda:0", "--local-config-sha256", "b" * 64]})},
        grid=write(result_root / "grid.grid.json", {"status": "complete"}))
    def coverage(launch, **kwargs):
        if kwargs:
            assert kwargs == {"replacement_roots": {"u0": result_root}}
            return f.coverage
        return old_coverage
    monkeypatch.setattr(mod.campaign, "coverage", coverage)
    monkeypatch.setattr(mod.campaign, "template_retry_selection", lambda *a: (f.launch, [unit], admission["failure_evidence"]))
    return SimpleNamespace(base=f, root=root, path=path, value=value, unit=unit, admission=admission, result_root=result_root)


def test_analysis_keeps_failed_parent_and_validates_complete_retry_union_separately(retried):
    f = retried
    original = f.base.path.read_bytes()
    handoff, units, cells, _prefix = mod.validate(f.base.path, work=f.base.work, project=f.base.work,
                                                retry_completions=[f.path])
    assert f.base.path.read_bytes() == original
    assert handoff["status"] == "complete" and handoff["coverage"]["retained_inputs"] == 7606
    assert handoff["original_coverage"]["complete"] is False
    assert handoff["retry_completions"] == [mod._descriptor(f.path)]
    assert handoff["retry_execution_commits"] == ["d" * 40]
    assert units["u0"]["root"] == str(f.result_root)
    assert "retry-u0" in {row["run_id"] for row in cells} and "u0" not in {row["run_id"] for row in cells}
    assert len({item["revision"] for item in units.values()}) == 2


@pytest.mark.parametrize("forged", [False, True])
def test_analysis_reconciles_only_source_reproduced_historical_counters(retried, monkeypatch, forged):
    f = retried
    corrected_original = dict(mod.campaign.coverage(f.base.launch))
    # Isolate accounting reconciliation from the separately tested grid/retry
    # validators. Both old and corrected original populations remain incomplete;
    # only the validated replacement union supplies full coverage.
    reported = {**corrected_original, "retained_inputs": corrected_original["retained_inputs"] - 224}
    f.base.value["coverage"] = reported
    write(f.base.path, f.base.value)
    before = f.base.path.read_bytes()
    checked = []
    def original_source(launch, *, project):
        assert launch == f.base.launch and project == f.base.work
        checked.append(launch["expected_commit"])
        return {**reported, "retained_inputs": reported["retained_inputs"] - 1} if forged else reported
    monkeypatch.setattr(mod, "_execution_source_coverage", original_source)
    if forged:
        with pytest.raises(ValueError, match="exact original execution source"):
            mod.validate(f.base.path, work=f.base.work, project=f.base.work, retry_completions=[f.path])
    else:
        handoff, _units, _cells, _prefix = mod.validate(
            f.base.path, work=f.base.work, project=f.base.work, retry_completions=[f.path],
        )
        assert handoff["coverage"]["complete"] is True
        assert handoff["coverage"]["retained_inputs"] == 7606
        assert handoff["reported_original_coverage"] == reported
        assert handoff["corrected_original_coverage"] == corrected_original
        assert handoff["reported_coverage_validator_commit"] == f.base.launch["expected_commit"]
        assert handoff["old_grid_promoted"] is False
    assert checked == [f.base.launch["expected_commit"]]
    assert f.base.path.read_bytes() == before


def test_historical_counter_cannot_replace_missing_current_coverage(retried, monkeypatch):
    f = retried
    f.base.coverage["complete"] = False
    monkeypatch.setattr(mod, "_execution_source_coverage", lambda *a, **kw: pytest.fail(
        "historical counts must not authorize incomplete current coverage"))
    with pytest.raises(ValueError, match="7,606-input disjoint union"):
        mod.validate(f.base.path, work=f.base.work, project=f.base.work, retry_completions=[f.path])


@pytest.mark.parametrize("change", ["missing", "duplicate", "input", "missing_row", "running_grid", "revision", "terminal", "pending", "selection"])
def test_retry_analysis_rejects_incomplete_duplicate_or_changed_union(retried, monkeypatch, change):
    f = retried
    paths = [f.path]
    if change == "missing":
        paths = []
    elif change == "duplicate":
        paths *= 2
    elif change == "input":
        rows = f.base.cells[f.result_root][0]["attempts"]
        rows[next(iter(rows))]["datapoint_id"] = "foreign"
    elif change == "missing_row":
        rows = f.base.cells[f.result_root][0]["attempts"]
        rows.pop(next(iter(rows)))
    elif change == "running_grid":
        write(Path(f.base.results["u0"]["grid"]["path"]), {"status": "running"})
    elif change == "revision":
        f.base.results["u0"]["revision"] = "e" * 64
    elif change == "terminal":
        write(f.root / "u0.terminal.json", {"result": None, "failure": {"error": "failed"}})
    elif change == "pending":
        f.value["status"] = "complete_with_failures"
        write(f.path, f.value)
    else:
        monkeypatch.setattr(mod.campaign, "template_retry_selection", lambda *a: (f.base.launch, [], {}))
    with pytest.raises(ValueError):
        mod.validate(f.base.path, work=f.base.work, project=f.base.work, retry_completions=paths)


def test_haiku_view_revalidates_exact_optional_retry_descriptors(judge_handoff, monkeypatch):
    f = judge_handoff
    retry = write(f.work / "retry/completion.json", {"bound": True})
    f.saved["retry_completions"] = f.fresh["retry_completions"] = [retry]
    write(f.root / "completion.json", f.saved)
    original = mod.validate
    def validate(path, *, retry_completions, **kwargs):
        assert retry_completions == [Path(retry["path"])]
        return original(path, **kwargs)
    monkeypatch.setattr(mod, "validate", validate)
    assert len(mod.load_judge_view(f.root, project=f.work)[0]) == 2
    Path(retry["path"]).write_text("{}")
    with pytest.raises(ValueError):
        mod.load_judge_view(f.root, project=f.work)
