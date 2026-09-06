from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_parallel_campaign as mod


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return mod.prior._descriptor(path, label="fixture")


@pytest.fixture
def failed(tmp_path, monkeypatch):
    work = tmp_path
    root = work / "runs/engineering/original"
    worker = root.with_name(root.name + "-gpu0")
    config = write(root / "config.json", {mod.prior.RR_SPEC: {
        "revision": mod.prior.RR_REVISION, "max_tokens": 4096, "tensor_parallel_size": 1, "max_model_len": 32768}})
    ids = ["old", "a", "b", "c", "d"]
    selected = {"lane": {"arm": ids}}
    snapshot = {"selected_ids": selected, "selected_ids_sha256": mod._sha256_json(selected),
                "lanes": {"lane": {"outcomes": {"old": "failed_output"}}}}
    selector, _count = mod.prior.checkpoint_selection(selected["lane"], ["old"])
    base = ["--local", mod.prior.RR_SPEC, "--limit", "100", "--sample-seed", "0", "--seeds", "0",
            "--attackers", "replay", "--corpora", "arm", "--local-config", config["path"],
            "--local-config-sha256", config["sha256"]]
    unit = mod.Unit("failed", "lane", "arm", {"base_argv": base}, 4, recovery=selector)
    units = [unit, mod.Unit("other-gpu", "lane2", "arm2", {}, 4), mod.Unit("passed", "lane3", "arm3", {}, 1)]
    launch = {"schema": mod.SCHEMA, "original_population": 7606, "max_tokens": 4096,
              "tensor_parallel_size": 1, "target_answer_retries": 1, "work_root": str(work),
              "queues": mod.balanced_queues(units), "units": [asdict(u) for u in units],
              "workers": {gpu: str(root.with_name(root.name + f"-gpu{gpu}")) for gpu in ("0", "1")},
              "interruption": write(root / "snapshot.json", snapshot),
              "selectors": {"failed": write(root / "selector.json", selector)}}
    parent_path = root / "launch.json"
    parent = write(parent_path, launch)
    failure = {"error_type": "RuntimeError", "error": "diagnostic canary failed"}
    terminal = {"result": None, "failure": failure}
    write(worker / "failed.terminal.json", terminal)
    canary = worker / "units/failed/canary"
    error = {"exception_type": "ExternalCallFailure", "message": "sealed target: " + mod._ROLE_ERROR,
             "completed_attempts": 0, "corpus": "arm",
             "model_spec": f"{mod.prior.RR_SPEC}@{mod.prior.RR_REVISION}"}
    write(canary / "cell.error.json", error)
    write(canary / "grid.grid.json", {"status": "error"})
    (canary.parent / "canary.run.log").write_text(mod._ROLE_ERROR)
    worker_value = {"schema": mod.SCHEMA, "status": "complete_with_failures", "physical_gpu": "0",
                    "failures": {"failed": failure}, "results": {"passed": {"status": "complete"}},
                    "launch": write(worker / "launch.json", {"schema": mod.SCHEMA, "parent": parent,
                        "physical_gpu": "0", "unit_order": launch["queues"]["0"]})}
    worker_path = worker / "completion.json"
    completion = write(worker_path, worker_value)
    original_iterdir = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda path: iter(()) if path == Path("/proc") else original_iterdir(path))
    monkeypatch.setattr(mod.prior, "_selected_rows", lambda argv: ({"arm": [SimpleNamespace(id=key) for key in ids]}, {}))
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    project = work / "project"
    project.mkdir()
    revision = write(root / "revision.json", {"repository": {"expected_commit": "a" * 40, "observed_commit": "a" * 40}})
    args = SimpleNamespace(launch=parent_path, launch_sha256=parent["sha256"], worker_completion=worker_path,
        worker_completion_sha256=completion["sha256"], gpu="0", project_root=project,
        project_revision=Path(revision["path"]), project_revision_sha256=revision["sha256"], expected_commit="a" * 40,
        control_root=work / "runs/engineering/retry", execution_scope_id="rr-template-retry", tmux_socket="retry", tmux_session="retry")
    return SimpleNamespace(work=work, root=root, worker=worker, launch=launch, parent_path=parent_path,
        worker_path=worker_path, worker_value=worker_value, unit=unit, args=args, error=error,
        canary=canary, original_iterdir=original_iterdir)


def test_selection_keeps_only_qualified_failed_unit_and_original_positive_selector(failed):
    f = failed
    launch, units, evidence = mod.template_retry_selection(f.parent_path, f.worker_path, "0")
    assert launch == f.launch and units == [f.unit]
    assert evidence["failed"]["remaining_ids_sha256"] == mod._sha256_json(["a", "b", "c", "d"])
    assert "passed" not in evidence and units[0].recovery["corpora"]["arm"]["completed_datapoint_ids"] == ["old"]


@pytest.mark.parametrize("identity", ["resolved", "legacy", "wrong_revision", "wrong_repository"])
def test_retry_model_identity_matches_only_the_independently_pinned_target(failed, identity):
    f = failed
    model = f"{mod.prior.RR_SPEC}@{mod.prior.RR_REVISION}"
    if identity == "legacy":
        model = mod.prior.RR_SPEC
    elif identity == "wrong_revision":
        model = mod.prior.RR_SPEC + "@" + "f" * 40
    elif identity == "wrong_repository":
        model = "vllm:another/model@" + mod.prior.RR_REVISION
    f.error["model_spec"] = model
    write(f.canary / "cell.error.json", f.error)
    if identity in {"resolved", "legacy"}:
        _launch, units, _evidence = mod.template_retry_selection(f.parent_path, f.worker_path, "0")
        assert units == [f.unit]
    else:
        with pytest.raises(ValueError, match="model identity"):
            mod.template_retry_selection(f.parent_path, f.worker_path, "0")


@pytest.mark.parametrize("change", ["wrong_failure", "measured", "state", "running", "ids", "config", "selector"])
def test_selection_refuses_wrong_failure_measured_rows_or_changed_input_binding(failed, monkeypatch, change):
    f = failed
    if change == "wrong_failure":
        f.error["message"] = "HTTP timeout"
        write(f.canary / "cell.error.json", f.error)
    elif change == "measured":
        write(f.work / "runs/thesis/runner/failed" / f.worker.name / "cell.responses.jsonl", {"already": "measured"})
    elif change == "state":
        write(f.worker / "units/failed/state.json", {})
    elif change == "running":
        f.worker_value["status"] = "running"
        write(f.worker_path, f.worker_value)
    elif change == "ids":
        monkeypatch.setattr(mod.prior, "_selected_rows", lambda argv: ({"arm": [SimpleNamespace(id="foreign")]}, {}))
    elif change == "config":
        Path(mod._option(f.unit.spec["base_argv"], "--local-config")).write_text("{}")
    else:
        Path(f.launch["selectors"]["failed"]["path"]).write_text("{}")
    with pytest.raises(ValueError):
        mod.template_retry_selection(f.parent_path, f.worker_path, "0")


@pytest.mark.parametrize("kind", ["worker", "canary", "measured"])
def test_selection_refuses_a_live_original_worker_or_descendant(failed, monkeypatch, kind):
    f = failed
    process = f.work / "999"
    process.mkdir()
    if kind == "worker":
        argv = ["python", "-m", mod.MODULE, "worker", "--launch", str(f.parent_path), "--gpu", "0"]
    else:
        out = f.canary if kind == "canary" else f.work / "runs/thesis/runner/failed" / f.worker.name
        argv = ["python", "-m", "experiments.run_matrix", "--out", str(out)]
    (process / "cmdline").write_bytes("\0".join(argv).encode() + b"\0")
    monkeypatch.setattr(Path, "iterdir", lambda path: iter([process]) if path == Path("/proc") else f.original_iterdir(path))
    with pytest.raises(ValueError, match="still live"):
        mod.template_retry_selection(f.parent_path, f.worker_path, "0")


def test_retry_uses_existing_executor_and_never_rewrites_success_or_old_failure(failed, monkeypatch):
    f = failed
    retained = write(f.work / "runs/thesis/runner/passed" / f.worker.name / "cell.responses.jsonl", {"keep": "unchanged"})
    old_failure = (f.worker / "failed.terminal.json").read_bytes()
    calls, events = [], []
    monkeypatch.setattr(mod, "_project_python", lambda project, python: python)
    monkeypatch.setattr(mod, "_framework_lock_id", lambda: "lock")
    monkeypatch.setattr(mod, "start_child_controller", lambda **kw: events.append("start"))
    monkeypatch.setattr(mod, "finish_child_controller", lambda **kw: events.append("finish"))
    monkeypatch.setattr(mod, "publish_target_execution", lambda **kw: events.append("counts"))
    def execute(unit, **kwargs):
        calls.append((unit, kwargs))
        assert unit == f.unit and kwargs["scoring_device"] == "cuda:0"
        assert kwargs["measured_wall_time_seconds"] == 259200 and kwargs["live_attestation_max_age_hours"] == 96
        assert kwargs["recovery_sha256"] == f.launch["selectors"]["failed"]["sha256"]
        write(f.work / "runs/thesis/runner/failed/retry/cell.responses.jsonl", {"fresh": True})
        return {"status": "complete", "target_attempts": 4, "successful_target_generations": 3}
    monkeypatch.setattr(mod, "_run_unit", execute)
    monkeypatch.setattr(mod.prior, "_durable_outcomes", lambda path: ({}, {
        "a": "usable_first_response", "b": "usable_first_response", "c": "recovered_after_retry", "d": "failed_output"}, [], []))
    assert mod.retry(f.args) == 0 and len(calls) == 1
    assert events == ["start", "counts", "finish"]
    assert (f.worker / "failed.terminal.json").read_bytes() == old_failure
    assert mod.prior._descriptor(Path(retained["path"]), label="fixture") == retained
    completion = json.loads((f.args.control_root / "completion.json").read_text())
    assert completion["schema"] == mod.RETRY_SCHEMA and completion["status"] == "complete"
    assert completion["target_attempts"] == 4 and completion["successful_generations"] == 3


@pytest.mark.parametrize("change", ["device", "other_measured"])
def test_retry_refuses_wrong_gpu_or_existing_response_in_another_retry(failed, monkeypatch, change):
    f = failed
    monkeypatch.setattr(mod, "_project_python", lambda project, python: python)
    if change == "device":
        monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0,1")
    else:
        write(f.work / "runs/thesis/runner/failed/earlier-retry/cell.responses.jsonl", {"retained": True})
    with pytest.raises(ValueError):
        mod.retry(f.args)
    assert not f.args.control_root.exists()


@pytest.mark.parametrize("change", [None, "missing", "foreign", "repeated", "unknown_unit"])
def test_replacement_coverage_reads_only_bound_new_segment_and_exact_missing_ids(tmp_path, monkeypatch, change):
    snapshot = {"selected_ids": {"lane": {"arm": ["a", "b", "c"]}}, "retained_response_count": 1,
                "lanes": {"lane": {"outcomes": {"a": "failed_output"}, "post_factum_judging_required_ids": []}}}
    unit = mod.Unit("u", "lane", "arm", {}, 2)
    launch = {"interruption": write(tmp_path / "snapshot.json", snapshot), "work_root": str(tmp_path),
              "queues": {"0": ["u"], "1": []}, "workers": {"0": str(tmp_path / "original"), "1": str(tmp_path / "other")},
              "units": [asdict(unit)]}
    replacement = tmp_path / "runs/thesis/runner/u/retry"
    write(replacement / "cell.responses.jsonl", {})
    outcomes = {"b": "failed_output", "c": "usable_first_response"}
    if change == "missing":
        outcomes.pop("c")
    elif change in {"foreign", "repeated"}:
        outcomes["outside" if change == "foreign" else "a"] = "usable_first_response"
    def read(path):
        assert path == replacement
        return {}, outcomes, [], []
    monkeypatch.setattr(mod.prior, "_durable_outcomes", read)
    original = mod.coverage(launch)
    assert not original["complete"] and original["retained_inputs"] == 1
    roots = {"unknown" if change == "unknown_unit" else "u": replacement}
    if change in {"foreign", "repeated", "unknown_unit"}:
        with pytest.raises(ValueError):
            mod.coverage(launch, replacement_roots=roots)
    else:
        combined = mod.coverage(launch, replacement_roots=roots)
        assert combined["complete"] is (change is None)
        assert combined["retained_inputs"] == (2 if change == "missing" else 3)
        assert combined["segments"][0]["result_root"] == str(replacement)
        assert mod.coverage(launch) == original
