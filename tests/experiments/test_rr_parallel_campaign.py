from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_parallel_campaign as mod


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))
    return mod.prior._descriptor(path, label="fixture")


def test_partition_keeps_4096_selection_and_excludes_every_retained_status():
    unit = mod.Unit("lane", "lane", None, {"base_argv": ["--limit", "100", "--seeds", "0"]}, 7)
    selected = {"lane": {"done": ["a", "b"], "partial": ["c", "d", "e"], "new": ["f", "g"]}}
    retained = {"lane": {"outcomes": {"a": "failed_output", "b": "input_incompatible",
                                      "c": "usable_first_response", "d": "recovered_after_retry"}}}
    units, selectors = mod.partition_units([unit], selected, retained)
    assert [(item.corpus, item.selected_records) for item in units] == [("partial", 1), ("new", 2)]
    assert all(item.spec == unit.spec and item.source_lane == "lane" for item in units)
    assert units[1].recovery is None
    assert list(selectors) == [units[0].unit_id]
    entry = units[0].recovery["corpora"]["partial"]
    assert entry["completed_record_count"] == 2
    assert entry["completed_datapoint_ids"] == ["c", "d"]
    assert entry["remaining_datapoint_ids_sha256"] == mod._sha256_json(["e"])
    assert all(entry["completed_record_count"] > 0
               for selector in selectors.values() for entry in selector["corpora"].values())


def test_assignment_is_deterministic_disjoint_and_balances_remaining_rows():
    units = [mod.Unit(str(i), "lane", str(i), {}, count) for i, count in enumerate([900, 800, 500, 400, 100, 50])]
    queues = mod.balanced_queues(units)
    assert queues == mod.balanced_queues(list(reversed(units)))
    assert not set(queues["0"]) & set(queues["1"])
    assert set(queues["0"] + queues["1"]) == {u.unit_id for u in units}
    counts = {u.unit_id: u.selected_records for u in units}
    assert abs(sum(counts[key] for key in queues["0"]) - sum(counts[key] for key in queues["1"])) <= 100
    with pytest.raises(ValueError, match="duplicated"):
        mod.balanced_queues([units[0], units[0]])


@pytest.mark.parametrize("change", ["gpu", "queue", "tp", "tokens"])
def test_worker_rejects_changed_device_or_policy(monkeypatch, change):
    units = [mod.Unit("unit", "lane", "arm", {}, 10)]
    launch = {"schema": mod.SCHEMA, "units": [asdict(u) for u in units],
              "queues": mod.balanced_queues(units), "max_tokens": 4096, "tensor_parallel_size": 1}
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    assert mod._worker_units(launch, "0") == units
    if change == "gpu":
        monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0,1")
    elif change == "queue":
        launch["queues"] = {"0": [], "1": ["unit"]}
    elif change == "tp":
        launch["tensor_parallel_size"] = 2
    else:
        launch["max_tokens"] = 2048
    with pytest.raises(ValueError, match="GPU or deterministic queue"):
        mod._worker_units(launch, "0")


@pytest.fixture
def interrupted(tmp_path, monkeypatch):
    root = tmp_path / "runs/engineering/original"
    runner = tmp_path / "runs/thesis/runner"
    root.mkdir(parents=True)
    runner.mkdir(parents=True)
    revision = write(root / "revision.json", {"repository": {"expected_commit": "a" * 40, "observed_commit": "a" * 40}})
    config = write(root / "config.json", {mod.prior.RR_SPEC: {
        "revision": mod.prior.RR_REVISION, "max_tokens": 4096, "tensor_parallel_size": 1, "max_model_len": -1}})
    evidence, source_rows = {}, {}
    for index, (lane, count) in enumerate(mod.prior.LAYOUT):
        arm = f"arm-{index}"
        source_rows[arm] = [f"{arm}-{number}" for number in range(count)]
        spec = {"lane_id": lane, "target": {"revision": mod.prior.RR_REVISION},
                "base_argv": ["--local", mod.prior.RR_SPEC, "--limit", "100", "--seeds", "0",
                              "--sample-seed", "0", "--attackers", "replay", "--corpora", arm,
                              "--local-config", config["path"], "--local-config-sha256", config["sha256"]]}
        evidence[lane] = {"source_specification": write(root / f"{lane}.json", spec), "local_config": config}
    launch = {"schema": mod.prior.SCHEMA, "planned_unique_rows": 7606, "units": evidence,
              "unit_order": list(dict(mod.prior.LAYOUT)), "target_answer_retries": 1, "paid_provider_calls": 0,
              "project_revision": revision, "expected_commit": "a" * 40}
    observation = {"schema": mod.OBSERVATION_SCHEMA, "prior_root": str(root), "controller_pid": 777,
                   "boot_id": "fixture", "processes": [{"pid": 777, "start_ticks": 4,
                   "argv": ["python", "-m", "experiments.local_campaign.rr_profiled_phase6", "--control-root", str(root)]}],
                   "launch": write(root / "launch.json", launch)}
    monkeypatch.setattr(mod.prior, "_selected_rows", lambda argv: ({arm: [SimpleNamespace(id=i) for i in source_rows[arm]]
                       for arm in mod._option(argv, "--corpora").split(",")}, {}))
    monkeypatch.setattr(mod, "_process", lambda pid: None)
    original_iterdir = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()) if path == Path("/proc") else original_iterdir(path))
    lane = mod.prior.LAYOUT[0][0]
    result_root = runner / lane / root.name
    write(result_root / "cell.responses.checkpoint.jsonl", {"retained": True})
    write(result_root / "grid-retained.grid.json", {"status": "running", "cells": []})
    spec = mod._load_json(Path(evidence[lane]["source_specification"]["path"]), label="fixture")
    base = mod._base_argv(mod.Unit(lane, lane, None, spec, 3854),
                          project_revision=Path(revision["path"]), project_revision_sha256=revision["sha256"])
    write(root / "units" / lane / "state.json", {"schema": mod.prior.STATE_SCHEMA, "unit_id": lane,
          "source_lane": lane, "corpus": None, "result_root": str(result_root),
          "runner_argv": base, "selected_records": 3854})
    outcomes = {"arm-0-0": "usable_first_response", "arm-0-1": "failed_output"}
    monkeypatch.setattr(mod.prior, "_durable_outcomes", lambda path: ({f"attempt-{key}": key for key in outcomes},
                                                                       dict(outcomes), [], []))
    return SimpleNamespace(root=root, runner=runner, observation=observation, launch=launch,
                           outcomes=outcomes, result_root=result_root)


def test_snapshot_preserves_running_grid_without_promoting_or_repeating(interrupted):
    f = interrupted
    before = (f.result_root / "grid-retained.grid.json").read_bytes()
    snapshot = mod.inspect_prefix(f.observation, runner_root=f.runner)
    assert snapshot["planned_unique_rows"] == 7606
    assert snapshot["retained_response_count"] == 2
    assert snapshot["old_grid_promoted"] is False and snapshot["judging_complete"] is False
    lane = snapshot["lanes"][mod.prior.LAYOUT[0][0]]
    assert lane["outcomes"] == f.outcomes
    assert lane["post_factum_judging_required_ids"] == ["arm-0-0", "arm-0-1"]
    assert (f.result_root / "grid-retained.grid.json").read_bytes() == before
    assert not (f.root / "completion.json").exists()
    assert not (f.root / ".exit").exists()
    assert snapshot == mod.inspect_prefix(f.observation, runner_root=f.runner)


def test_snapshot_keeps_existing_judgment_ids_out_of_pending_judging(interrupted):
    f = interrupted
    judgment = mod.Judgment(attempt_id="attempt-arm-0-0", judge="guardrail", label="compliant", score=0)
    path = f.result_root / "retained.jsonl"
    path.write_text(judgment.model_dump_json() + "\n")
    descriptor = mod.prior._descriptor(path, label="fixture")
    write(f.result_root / "retained.complete.json", {"artifacts": {"judgments": {
        "file": path.name, "sha256": descriptor["sha256"], "bytes": descriptor["bytes"]}}})
    snapshot = mod.inspect_prefix(f.observation, runner_root=f.runner)
    lane = snapshot["lanes"][mod.prior.LAYOUT[0][0]]
    assert lane["retained_judgment_ids"] == ["arm-0-0"]
    assert lane["post_factum_judging_required_ids"] == ["arm-0-1"]
    assert lane["retained_judgments_require_source_validation"] is True
    assert lane["old_grid_promoted"] is False
    path.write_text("{}\n")
    with pytest.raises(ValueError, match="no longer match"):
        mod.inspect_prefix(f.observation, runner_root=f.runner)


def test_snapshot_rejects_unobserved_live_controller_token(interrupted, tmp_path, monkeypatch):
    directory = tmp_path / "999"
    directory.mkdir()
    (directory / "cmdline").write_bytes(b"python\0--control-root\0" + str(interrupted.root).encode() + b"\0")
    original = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda path: iter([directory]) if path == Path("/proc") else original(path))
    with pytest.raises(ValueError, match="original root is still live"):
        mod.inspect_prefix(interrupted.observation, runner_root=interrupted.runner)


@pytest.mark.parametrize("change", ["live", "foreign", "state", "config", "complete", "lock"])
def test_snapshot_rejects_live_or_changed_prefix(interrupted, monkeypatch, change):
    f = interrupted
    if change == "live":
        monkeypatch.setattr(mod, "_process", lambda pid: {"pid": pid})
    elif change == "foreign":
        f.outcomes["foreign-id"] = "usable_first_response"
    elif change == "state":
        path = f.root / "units" / mod.prior.LAYOUT[0][0] / "state.json"
        state = json.loads(path.read_text())
        state["runner_argv"][3] = "50"
        write(path, state)
    elif change == "config":
        (f.root / "config.json").write_text("{}")
    elif change == "complete":
        write(f.root / "completion.json", {"status": "complete"})
    else:
        write(f.result_root / "grid.lock", {"pid": 888})
        monkeypatch.setattr(mod, "_process", lambda pid: {"pid": pid} if pid == 888 else None)
    with pytest.raises(ValueError):
        mod.inspect_prefix(f.observation, runner_root=f.runner)


def test_coverage_rejects_duplicates_and_counts_unexecuted_entries(tmp_path, monkeypatch):
    snapshot = {"selected_ids": {"lane": {"arm": ["a", "b", "c"]}}, "retained_response_count": 1,
                "lanes": {"lane": {"outcomes": {"a": "failed_output"}, "post_factum_judging_required_ids": ["a"]}}}
    unit = mod.Unit("u", "lane", "arm", {}, 2)
    launch = {"interruption": write(tmp_path / "snapshot.json", snapshot), "work_root": str(tmp_path),
              "queues": {"0": ["u"], "1": []}, "workers": {"0": str(tmp_path / "worker0"), "1": str(tmp_path / "worker1")},
              "units": [asdict(unit)]}
    write(tmp_path / "runs/thesis/runner/u/worker0/cell.responses.jsonl", {})
    current = {"b": "failed_output"}
    monkeypatch.setattr(mod.prior, "_durable_outcomes", lambda path: ({}, dict(current), [], []))
    result = mod.coverage(launch)
    assert result["expected_inputs"] == 3 and result["retained_inputs"] == 2 and not result["complete"]
    current["c"] = "usable_first_response"
    assert mod.coverage(launch)["complete"]
    current["a"] = "usable_first_response"
    with pytest.raises(ValueError, match="repeated"):
        mod.coverage(launch)


def test_worker_uses_one_gpu_long_bound_and_existing_unit_executor(tmp_path, monkeypatch):
    unit = mod.Unit("u", "lane", "arm", {}, 2)
    work = tmp_path
    root = work / "runs/engineering/worker0"
    root.parent.mkdir(parents=True)
    project = tmp_path / "project"
    project.mkdir()
    revision = write(tmp_path / "revision.json", {})
    launch = {"schema": mod.SCHEMA, "units": [asdict(unit)], "queues": {"0": ["u"], "1": []},
              "max_tokens": 4096, "tensor_parallel_size": 1, "workers": {"0": str(root)}, "work_root": str(work),
              "project_root": str(project), "project_revision": revision, "expected_commit": "a" * 40,
              "execution_scope_id": "rr", "tmux_socket": "default", "tmux_session": "test", "selectors": {}}
    path = tmp_path / "launch.json"
    descriptor = write(path, launch)
    events = []
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    monkeypatch.setattr(mod, "_project_python", lambda p, py: py)
    monkeypatch.setattr(mod, "_framework_lock_id", lambda: "b" * 64)
    monkeypatch.setattr(mod, "start_child_controller", lambda **kw: events.append(("start", kw)))
    monkeypatch.setattr(mod, "finish_child_controller", lambda **kw: events.append(("finish", kw)))
    monkeypatch.setattr(mod, "publish_target_execution", lambda **kw: events.append(("count", kw)))
    def execute(actual, **kwargs):
        assert actual == unit and kwargs["measured_wall_time_seconds"] == 259200
        assert kwargs["live_attestation_max_age_hours"] == 96 and kwargs["scoring_device"] == "cuda:0"
        assert kwargs["state_schema"] == mod.STATE_SCHEMA
        assert kwargs["scope"] == "rr-gpu0" and os_environ_gpu() == "0"
        assert kwargs["recovery_path"] is None
        return {"target_attempts": 2, "successful_target_generations": 1}
    monkeypatch.setattr(mod, "_run_unit", execute)
    assert mod.worker(path, descriptor["sha256"], "0") == 0
    assert [event for event, _ in events] == ["start", "count", "finish"]
    assert events[0][1]["target_execution"] is True
    assert events[-1][1]["exit_code"] == 0
    assert json.loads((root / "completion.json").read_text())["physical_gpu"] == "0"


def os_environ_gpu():
    import os
    return os.environ["CUDA_VISIBLE_DEVICES"]
