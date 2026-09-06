"""Recovery keeps target calls impossible and preserves the selected cascade."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_retained_judging as recovery
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import DataPoint, DialogTurn, Response, RiskCategory
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.runner import Runner, _component_config
from ura.targets.base import BaseTarget


def manifest():
    cascade = JudgeCascade([RuleJudge(), GuardrailJudge(
        model="meta-llama/Llama-Guard-3-8B", revision="b" * 40,
        device="cuda:0", max_new_tokens=20,
    )])
    return SimpleNamespace(
        judges=["rules", "guardrail"], models=["retained-rr"],
        config={"components": {
            "judge_cascade": _component_config(cascade),
            "target": {"modality_support": ["text", "image"]},
        }},
    )


def test_target_execution_is_impossible_even_if_called_by_mistake():
    target = recovery._NoTarget(manifest())
    assert target.name == "retained-rr"
    assert target.modality_support == ("text", "image")
    with pytest.raises(RuntimeError, match="cannot execute a target"):
        target.generate([])


def test_recovery_preserves_every_saved_judge_setting_without_loading_models():
    original = manifest()
    runtime = object()
    cascade = recovery.source_cascade(original, model_runtime=runtime)
    assert _component_config(cascade) == original.config["components"]["judge_cascade"]
    assert cascade.stages[1]._model_runtime is runtime
    assert cascade.stages[1]._model is None
    assert cascade.stages[1]._tokenizer is None


@pytest.mark.parametrize("changed", ["class", "extra", "roster"])
def test_recovery_does_not_silently_replace_a_different_judge_configuration(changed):
    original = manifest()
    if changed == "roster":
        original.judges = ["rules", "llm"]
    elif changed == "class":
        original.config["components"]["judge_cascade"]["stages"][1]["class"] = "AnotherGuard"
    else:
        original.config["components"]["judge_cascade"]["unrecognized_setting"] = True
    with pytest.raises(ValueError, match="cascade|configuration"):
        recovery.source_cascade(original)


def test_pending_selection_excludes_every_existing_judgment():
    source = recovery.RetainedUnit(
        manifest(), {}, {}, None, {"a": None, "b": None, "c": None},
        {"a": {}, "b": {}, "c": {}}, {"b": {}},
    )
    assert source.pending_ids == ["a", "c"]


def test_source_files_must_remain_exactly_bound(tmp_path):
    path = tmp_path / "responses.jsonl"
    path.write_text("original\n")
    source = recovery.RetainedUnit(
        manifest(), {}, {"files": [recovery._descriptor(path, label="source")]},
        None, {}, {}, {},
    )
    source.validate_unchanged()
    path.write_text("modified\n")
    with pytest.raises(ValueError):
        source.validate_unchanged()


def _fixture_cascade():
    cascade = recovery.source_cascade(manifest())
    calls = []
    guard = cascade.stages[1]
    guard._ensure_loaded = lambda: None

    def classify(conversation):
        calls.append(conversation)
        return "unsafe\nS1"

    guard._run_guard = classify
    return cascade, calls


@pytest.fixture
def retained_source(tmp_path):
    class FixtureTarget(BaseTarget):
        name = "vllm:retained-rr"
        modality_support = ("text", "image")

        def generate(self, dialog, *, seed=None):
            return Response(attempt_id="pending", target=self.name,
                            output_turns=[DialogTurn(role="assistant", content="fixture answer")],
                            raw={"sampling_control": "seeded"})

    points = [DataPoint(id=key, source="unit", modalities=["text"], payload_text="fixture prompt",
                        risk_category=RiskCategory.INFORMATION_SECURITY, expected_behavior="refuse")
              for key in ("a", "b")]
    cascade, _calls = _fixture_cascade()
    original = Runner(ReplayAttacker(), FixtureTarget(), cascade,
                      AttackBudget(max_queries=1, max_turns=1, seed=0), [0])
    responses, records = [], []
    _judgments, saved_manifest = original.run(
        points, on_response=responses.append, on_record=records.append,
        run_config={"expected_target_identity": None, "approximate_common_metrics": False,
                    "model_spec": "vllm:retained-rr", "corpus": "unit", "defense": "none",
                    "attacker": "replay", "dry_run": False,
                    "group_keys": ["model", "source", "risk", "effective_modality", "expected_behavior",
                                   "attacker", "source_policy_id", "source_policy_version"]},
    )
    root = tmp_path / "original"
    root.mkdir()
    path = root / "source.json"
    path.write_text(json.dumps({"responses": responses, "judgments": records[:1]}))
    prepared, _media = original._prepare_corpus(points)
    by_id = {point.id: point for point in prepared}
    return recovery.RetainedUnit(
        saved_manifest, {"result_root": str(root), "selected_records": 2},
        {"files": [recovery._descriptor(path, label="source")],
         "generation_revision": {"expected_commit": "b" * 40}}, original,
        {attempt.id: (by_id[attempt.datapoint_id], attempt) for attempt in original.attempts},
        {record["attempt"]["id"]: record for record in responses},
        {record["attempt"]["id"]: record for record in records[:1]},
    )


def test_writer_scores_only_missing_rows_and_resumes_without_any_call(retained_source, tmp_path):
    source = retained_source
    cascade, calls = _fixture_cascade()
    checkpoint = tmp_path / "new-judgments.jsonl"
    result = recovery.score_pending(source, cascade, checkpoint=checkpoint)
    assert len(calls) == 1 and len(result.judgments) == 2
    saved = Runner.load_checkpoint(checkpoint, expected_run_id=source.manifest.run_id)
    assert set(saved) == set(source.pending_ids)
    assert [response.model_dump(mode="json") for response in result.responses] == [
        row["response"] for row in source.responses.values()
    ]
    first = checkpoint.read_bytes()
    cascade, calls = _fixture_cascade()
    resumed = recovery.score_pending(source, cascade, checkpoint=checkpoint)
    assert calls == [] and len(resumed.judgments) == 2
    assert checkpoint.read_bytes() == first
    source.validate_unchanged()


def test_saved_scoring_cannot_substitute_an_internally_valid_different_response(retained_source, tmp_path):
    source = retained_source
    key = source.pending_ids[0]
    point, attempt = source.inputs[key]
    modified = copy.deepcopy(source.responses[key])
    modified["response"]["output_turns"][0]["content"] = "different fixture answer"
    cascade, _calls = _fixture_cascade()
    forging_fixture = recovery._reader_runner(source.manifest, cascade)
    records = []
    forging_fixture._execute_or_restore(point, attempt, source.manifest.run_id, None,
                                       records.append, response_record=modified)
    # This is a valid standalone record, but it is not the retained output.
    forging_fixture._restore_record(point, attempt, records[0], source.manifest.run_id)
    checkpoint = tmp_path / "substituted.jsonl"
    Runner.append_checkpoint(checkpoint, records[0])
    cascade, calls = _fixture_cascade()
    with pytest.raises(ValueError, match="original target response"):
        recovery.score_pending(source, cascade, checkpoint=checkpoint)
    assert calls == []


def test_checkpoint_cannot_repeat_an_original_judgment(retained_source, tmp_path):
    checkpoint = tmp_path / "repeated.jsonl"
    Runner.append_checkpoint(checkpoint, next(iter(retained_source.judgments.values())))
    cascade, calls = _fixture_cascade()
    with pytest.raises(ValueError, match="original completed judgment"):
        recovery.score_pending(retained_source, cascade, checkpoint=checkpoint)
    assert calls == []


def test_writer_cannot_write_into_original_generation_directory(retained_source):
    cascade, calls = _fixture_cascade()
    checkpoint = recovery.Path(retained_source.state["result_root"]) / "new.jsonl"
    with pytest.raises(ValueError, match="original generation root"):
        recovery.score_pending(retained_source, cascade, checkpoint=checkpoint)
    assert calls == [] and not checkpoint.exists()


@pytest.fixture
def prepared_launch(retained_source, tmp_path, monkeypatch):
    work = tmp_path / "work"
    (work / "runs/engineering").mkdir(parents=True)
    project = tmp_path / "project"
    project.mkdir()
    receipt = tmp_path / "revision.json"
    receipt.write_text("fixture revision")
    state = tmp_path / "state.json"
    state.write_text("fixture state")
    retained_source.source["state"] = recovery._descriptor(state, label="state")
    monkeypatch.setattr(recovery, "load_source", lambda *a, **k: retained_source)
    revision = {"expected_commit": "c" * 40}
    monkeypatch.setattr(recovery, "_revision", lambda *a: revision)
    monkeypatch.setattr(recovery, "_runtime", lambda source: (object(), {"selection": "fixture"}))
    root = work / "runs/engineering/new-judging"
    launch = recovery.prepare(state, work=work, project=project, out=root,
                              revision_path=receipt, revision_sha256="a" * 64)
    path = root / "launch.json"
    digest = recovery._descriptor(path, label="launch")["sha256"]
    return work, project, root, path, digest, launch


def test_prepare_is_call_free_and_binding_rejects_changed_selection(prepared_launch, monkeypatch):
    work, project, _root, path, digest, launch = prepared_launch
    saved, source = recovery.load_launch(path, digest, work=work, project=project)
    assert saved == launch
    assert saved["target_calls"] == saved["hosted_calls"] == 0
    assert saved["pending_ids"] == source.pending_ids
    source.inputs = dict(reversed(list(source.inputs.items())))
    source.judgments = {}
    with pytest.raises(ValueError, match="source or scoring binding"):
        recovery.load_launch(path, digest, work=work, project=project)


def test_launch_requires_its_actual_scoring_revision(prepared_launch, monkeypatch):
    work, project, _root, path, digest, _launch = prepared_launch
    monkeypatch.setattr(recovery, "_revision", lambda *a: {"expected_commit": "d" * 40})
    with pytest.raises(ValueError, match="source or scoring binding"):
        recovery.load_launch(path, digest, work=work, project=project)


@pytest.mark.parametrize("visible,owners", [("1", ""), ("0,1", ""), ("0", "GPU-fixture, 123")])
def test_scoring_rejects_wrong_visibility_or_an_occupied_gpu(monkeypatch, visible, owners):
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", visible)
    monkeypatch.setattr(recovery.subprocess, "check_output", lambda argv, **kw:
                        "GPU-fixture" if "--id=0" in argv else owners)
    with pytest.raises((ValueError, RuntimeError), match="visibility|occupied"):
        recovery._require_free_gpu()


def test_scoring_accepts_gpu0_free_while_gpu1_is_busy(monkeypatch):
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    monkeypatch.setattr(recovery.subprocess, "check_output", lambda argv, **kw:
                        "GPU-fixture" if "--id=0" in argv else "GPU-other, 456")
    recovery._require_free_gpu()


def test_execution_retains_new_provenance_and_refuses_second_execution(
    prepared_launch, monkeypatch,
):
    pytest.importorskip("fcntl")
    work, project, root, path, digest, launch = prepared_launch
    cascade, calls = _fixture_cascade()
    monkeypatch.setattr(recovery, "source_cascade", lambda *a, **k: cascade)
    monkeypatch.setattr(recovery, "_require_free_gpu", lambda: None)
    completion = recovery.execute(path, digest, work=work, project=project,
                                  control=work / "runs/engineering/invocation-one",
                                  tmux_socket="fixture", tmux_session="fixture")
    assert len(calls) == completion["new_judgments"] == 1
    assert completion["total_judgments"] == 2
    assert completion["target_calls"] == completion["hosted_calls"] == 0
    assert completion["old_grid_promoted"] is False
    assert completion["judging_revision"] == launch["judging_revision"]
    assert recovery._load_json(root / "completion.json", label="completion") == completion
    with pytest.raises(ValueError, match="already completed"):
        recovery.execute(path, digest, work=work, project=project,
                         control=work / "runs/engineering/invocation-two",
                         tmux_socket="fixture", tmux_session="fixture")
    assert len(calls) == 1


def test_failed_execution_retains_checkpoint_and_resumes_without_reclassifying(
    prepared_launch, monkeypatch,
):
    pytest.importorskip("fcntl")
    work, project, root, path, digest, _launch = prepared_launch
    cascade, calls = _fixture_cascade()
    monkeypatch.setattr(recovery, "source_cascade", lambda *a, **k: cascade)
    monkeypatch.setattr(recovery, "_require_free_gpu", lambda: None)
    original = recovery.score_pending

    def fail_after_checkpoint(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("fixture interruption after durable judgment")

    monkeypatch.setattr(recovery, "score_pending", fail_after_checkpoint)
    first = work / "runs/engineering/invocation-one"
    with pytest.raises(RuntimeError, match="fixture interruption"):
        recovery.execute(path, digest, work=work, project=project, control=first,
                         tmux_socket="fixture", tmux_session="fixture")
    assert not (root / "completion.json").exists()
    assert (first / "error.json").is_file() and len(calls) == 1
    monkeypatch.setattr(recovery, "score_pending", original)
    completion = recovery.execute(path, digest, work=work, project=project,
                                  control=work / "runs/engineering/invocation-two",
                                  tmux_socket="fixture", tmux_session="fixture")
    assert len(calls) == 1 and completion["total_judgments"] == 2


@pytest.fixture
def boundary_fixture(tmp_path, monkeypatch):
    worker = tmp_path / "worker"
    parent = tmp_path / "parent.json"
    worker.mkdir()
    parent.write_text(json.dumps({"workers": {"0": str(worker)}}))
    descriptor = recovery._descriptor(parent, label="parent")
    (worker / "launch.json").write_text(json.dumps({"parent": descriptor}))
    source = SimpleNamespace(source={"state": {"path": str(worker / "units/unit/state.json")}})
    controller = {"pid": 10, "start_ticks": 1, "children": [11], "argv": [
        "python", "-m", "experiments.local_campaign.rr_parallel_campaign", "worker",
        "--gpu", "0", "--launch", str(parent), "--launch-sha256", descriptor["sha256"],
    ]}
    child = {"pid": 11, "start_ticks": 2, "children": [], "argv": [
        "python", "-m", "experiments.run_matrix", "--diagnostic-canary", "--out", str(worker / "canary"),
    ]}
    signals = []
    monkeypatch.setattr(recovery.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    return source, controller, child, signals


@pytest.mark.parametrize("failure", [False, True])
def test_boundary_waits_for_canary_and_always_resumes_scheduler(boundary_fixture, monkeypatch, failure):
    source, controller, child, signals = boundary_fixture
    observations = iter([child, child, None])
    monkeypatch.setattr(recovery.rr_parallel_campaign, "_process",
                        lambda pid: controller if pid == 10 else next(observations))
    calls = []

    def action():
        assert signals == [(10, recovery.signal.SIGSTOP)]
        calls.append("scoring")
        if failure:
            raise RuntimeError("fixture scoring failure")
        return 0

    if failure:
        with pytest.raises(RuntimeError, match="fixture scoring failure"):
            recovery.at_canary_boundary(source, 10, action)
    else:
        assert recovery.at_canary_boundary(source, 10, action) == 0
    assert calls == ["scoring"]
    assert signals == [(10, recovery.signal.SIGSTOP), (10, recovery.signal.SIGCONT)]


def test_boundary_never_pauses_or_runs_on_measured_child(boundary_fixture, monkeypatch):
    source, controller, child, signals = boundary_fixture
    child["argv"].remove("--diagnostic-canary")
    monkeypatch.setattr(recovery.rr_parallel_campaign, "_process",
                        lambda pid: controller if pid == 10 else child)

    def stop_waiting(_seconds):
        raise InterruptedError("fixture stopped waiting")

    monkeypatch.setattr(recovery.time, "sleep", stop_waiting)
    with pytest.raises(InterruptedError, match="stopped waiting"):
        recovery.at_canary_boundary(source, 10, lambda: pytest.fail("must not score"))
    assert signals == []


@pytest.mark.parametrize("source_gpu", ["0", "1", "foreign"])
def test_boundary_scores_either_original_worker_on_gpu0_only(boundary_fixture, monkeypatch, source_gpu):
    source, controller, child, signals = boundary_fixture
    worker0 = recovery.Path(source.source["state"]["path"]).parents[2]
    parent = recovery.Path(recovery._option(controller["argv"], "--launch"))
    source_worker = worker0 if source_gpu == "0" else worker0.with_name("source-" + source_gpu)
    source_worker.mkdir(exist_ok=True)
    workers = {"0": str(worker0)}
    if source_gpu == "1":
        workers["1"] = str(source_worker)
    parent.write_text(json.dumps({"workers": workers}))
    descriptor = recovery._descriptor(parent, label="parent")
    (source_worker / "launch.json").write_text(json.dumps({"parent": descriptor}))
    controller["argv"][-1] = descriptor["sha256"]
    source.source["state"]["path"] = str(source_worker / "units/unit/state.json")
    observations = iter([child, child, None])
    monkeypatch.setattr(recovery.rr_parallel_campaign, "_process",
                        lambda pid: controller if pid == 10 else next(observations))
    calls = []

    def score():
        assert signals == [(10, recovery.signal.SIGSTOP)]
        assert recovery._option(controller["argv"], "--gpu") == "0"
        calls.append("scoring")
        return 0

    if source_gpu == "foreign":
        with pytest.raises(ValueError, match="original GPU0 RR worker"):
            recovery.at_canary_boundary(source, 10, score)
        assert signals == calls == []
    else:
        assert recovery.at_canary_boundary(source, 10, score) == 0
        assert calls == ["scoring"]
        assert signals == [(10, recovery.signal.SIGSTOP), (10, recovery.signal.SIGCONT)]


def test_report_scopes_keep_original_and_recovered_judging_separate(
    completed_scoring, retained_source,
):
    from experiments import level2_report
    from experiments.local_campaign import rr_retained_judging_analysis as analysis

    work, project, root, completion = completed_scoring
    original_manifest = retained_source.manifest.model_dump(mode="json")
    manifest_path = recovery.Path(retained_source.state["result_root"]) / "fixture.manifest.json"
    manifest_path.write_text(json.dumps(original_manifest))
    view = analysis._completed_view(root / "completion.json", work=work, project=project)
    reports = analysis._report_views(retained_source, view["records"], completion, joined=True)
    assert len(reports["input_cell"]["responses"]) == 2
    assert reports["input_cell"]["aggregate_results"] == []
    assert len(reports["joined"][1]) == 2
    original, recovered = reports["metric_cells"].values()
    assert set(original["responses"]).isdisjoint(recovered["responses"])
    assert set(original["responses"]) | set(recovered["responses"]) == set(view["records"])
    for name, cell in reports["metric_cells"].items():
        assert len(cell["responses"]) == 1
        assert cell["manifest"] == original_manifest
        report = level2_report.build_level2_report([cell], [])
        assert report["inputs"]["cells"][0]["post_factum_judging"]["scope"] == name
        assert all(row["post_factum_judging"]["scope"] == name for row in report["common"]["estimates"])
    assert retained_source.manifest.model_dump(mode="json") == original_manifest


def test_boundary_closes_canary_to_measured_transition_race(boundary_fixture, monkeypatch):
    source, controller, child, signals = boundary_fixture
    measured = copy.deepcopy(child)
    measured["argv"].remove("--diagnostic-canary")
    observations = iter([child, measured])
    monkeypatch.setattr(recovery.rr_parallel_campaign, "_process",
                        lambda pid: controller if pid == 10 else next(observations))

    def stop_waiting(_seconds):
        raise InterruptedError("fixture stopped waiting")

    monkeypatch.setattr(recovery.time, "sleep", stop_waiting)
    with pytest.raises(InterruptedError, match="stopped waiting"):
        recovery.at_canary_boundary(source, 10, lambda: pytest.fail("must not score"))
    assert signals == [(10, recovery.signal.SIGSTOP), (10, recovery.signal.SIGCONT)]


def test_boundary_rejects_other_gpu_controller(boundary_fixture, monkeypatch):
    source, controller, _child, signals = boundary_fixture
    controller["argv"][controller["argv"].index("--gpu") + 1] = "1"
    monkeypatch.setattr(recovery.rr_parallel_campaign, "_process", lambda pid: controller)
    with pytest.raises(ValueError, match="original GPU0"):
        recovery.at_canary_boundary(source, 10, lambda: pytest.fail("must not score"))
    assert signals == []


@pytest.fixture
def completed_scoring(prepared_launch, monkeypatch):
    pytest.importorskip("fcntl")
    work, project, root, path, digest, _launch = prepared_launch
    cascade, calls = _fixture_cascade()
    monkeypatch.setattr(recovery, "source_cascade", lambda *a, **k: cascade)
    monkeypatch.setattr(recovery, "_require_free_gpu", lambda: None)
    completion = recovery.execute(path, digest, work=work, project=project,
                                  control=work / "runs/engineering/invocation-one",
                                  tmux_socket="fixture", tmux_session="fixture")
    assert len(calls) == 1

    def forbidden(*a, **k):
        pytest.fail("analysis cannot classify or append a checkpoint")

    monkeypatch.setattr(cascade.stages[1], "_run_guard", forbidden)
    monkeypatch.setattr(Runner, "append_checkpoint", forbidden)
    return work, project, root, completion


def test_analysis_restores_every_judgment_without_calls_or_source_relabelling(completed_scoring):
    from experiments.local_campaign import rr_retained_judging_analysis as analysis

    work, project, root, completion = completed_scoring
    view = analysis._completed_view(root / "completion.json", work=work, project=project)
    assert view["counts"]["total_judgments"] == len(view["records"]) == 2
    assert view["generation_manifest"]["run_id"] == completion["generation_run_id"]
    assert view["launch"]["judging_revision"] == completion["judging_revision"]
    assert view["target_calls"] == view["judge_calls"] == 0
    assert view["old_grid_promoted"] is False
    original, recovered = view["judging_strata"].values()
    assert len(original) == len(recovered) == 1
    assert set(original).isdisjoint(recovered)
    assert set(original) | set(recovered) == set(view["records"])


@pytest.mark.parametrize("reports", [False, True])
def test_analysis_worker_protocol_uses_self_contained_strict_reader(
    completed_scoring, retained_source, monkeypatch, reports,
):
    import inspect
    import io
    from experiments.local_campaign import rr_retained_judging_analysis as analysis

    work, _project, root, _completion = completed_scoring
    request = {"completion": str(root / "completion.json"), "work": str(work),
               "reader_source": inspect.getsource(analysis._completed_view)}
    if reports:
        manifest_path = recovery.Path(retained_source.state["result_root"]) / "fixture.manifest.json"
        manifest_path.write_text(json.dumps(retained_source.manifest.model_dump(mode="json")))
        request.update(report_source=inspect.getsource(analysis._report_views), joined=True)
    monkeypatch.setattr(analysis.sys, "stdin", io.StringIO(json.dumps(request)))
    output = io.StringIO()
    monkeypatch.setattr(analysis.sys, "stdout", output)
    exec(analysis._WORKER, {})
    result = json.loads(output.getvalue())
    assert result["counts"]["total_judgments"] == 2
    assert result["target_calls"] == result["judge_calls"] == 0
    if reports:
        assert len(result["report_views"]["joined"][1]) == 2
        assert set(result["report_views"]["metric_cells"]) == {"original-judgments", "recovered-judgments"}


@pytest.mark.parametrize("change", ["counts", "revision", "old_grid", "incomplete"])
def test_analysis_cannot_admit_changed_or_incomplete_completion(completed_scoring, change):
    from experiments.local_campaign import rr_retained_judging_analysis as analysis

    work, project, root, completion = completed_scoring
    if change == "counts":
        completion["new_judgments"] = 99
    elif change == "revision":
        completion["judging_revision"] = {"expected_commit": "d" * 40}
    elif change == "old_grid":
        completion["old_grid_promoted"] = True
    else:
        checkpoint = root / "judgments.checkpoint.jsonl"
        checkpoint.write_text("\n")
        completion["checkpoint"] = recovery._descriptor(checkpoint, label="empty checkpoint")
        completion["new_judgments"] = 0
        completion["total_judgments"] = 1
    (root / "completion.json").write_text(json.dumps(completion))
    with pytest.raises(ValueError, match="identity|omits or repeats"):
        analysis._completed_view(root / "completion.json", work=work, project=project)


def test_analysis_rejects_even_a_valid_new_judgment_on_another_response(
    completed_scoring, retained_source, monkeypatch,
):
    from experiments.local_campaign import rr_retained_judging_analysis as analysis

    work, project, root, completion = completed_scoring
    key = retained_source.pending_ids[0]
    point, attempt = retained_source.inputs[key]
    modified = copy.deepcopy(retained_source.responses[key])
    modified["response"]["output_turns"][0]["content"] = "different fixture answer"
    # Build the substitute using the real Runner record writer, not a fictitious shape.
    cascade, _calls = _fixture_cascade()
    writer = recovery._reader_runner(retained_source.manifest, cascade)
    records = []
    writer._execute_or_restore(point, attempt, retained_source.manifest.run_id, None,
                              records.append, response_record=modified)
    checkpoint = root / "judgments.checkpoint.jsonl"
    checkpoint.write_text(json.dumps(records[0]) + "\n")
    completion["checkpoint"] = recovery._descriptor(checkpoint, label="substituted checkpoint")
    (root / "completion.json").write_text(json.dumps(completion))
    with pytest.raises(ValueError, match="retained target response"):
        analysis._completed_view(root / "completion.json", work=work, project=project)
