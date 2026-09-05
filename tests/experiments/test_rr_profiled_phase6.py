from __future__ import annotations

import json
from argparse import Namespace
from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_profiled_phase6 as mod


def test_rr_parent_job_spans_preparation_execution_and_terminal(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    work = tmp_path / "work"
    (work / "runs/engineering").mkdir(parents=True)
    source = tmp_path / "specs"
    source.mkdir()
    registry = tmp_path / "profiles.json"
    registry.write_text("{}", encoding="utf-8")
    receipt = tmp_path / "revision.json"
    receipt.write_text(json.dumps({"repository": {
        "expected_commit": "a" * 40, "observed_commit": "a" * 40}}), encoding="utf-8")
    digest = mod._descriptor(receipt, label="fixture")["sha256"]
    units = [mod.Unit(lane, lane, None, {}, count) for lane, count in mod.LAYOUT]
    events = []
    monkeypatch.setattr(mod, "_project_python", lambda root, python: python)
    monkeypatch.setattr(mod, "_framework_lock_id", lambda: "b" * 64)
    monkeypatch.setattr(mod, "configure_units", lambda *args: (units, {}))

    def start(**kwargs):
        assert kwargs["target_execution"] is True
        assert kwargs["tmux_session"] == "rr-test"
        events.append("start")

    def execute(unit, **kwargs):
        assert events[0] == "start"
        events.append(unit.unit_id)
        return {"target_attempts": unit.selected_records,
                "successful_target_generations": unit.selected_records}

    def publish(**kwargs):
        assert kwargs["target_attempts"] == kwargs["successful_target_generations"] == 7606
        events.append("accounting")

    def finish(**kwargs):
        assert kwargs["exit_code"] == 0
        events.append("end")

    monkeypatch.setattr(mod, "start_child_controller", start)
    monkeypatch.setattr(mod, "_run_unit", execute)
    monkeypatch.setattr(mod, "publish_target_execution", publish)
    monkeypatch.setattr(mod, "finish_child_controller", finish)
    args = Namespace(project_root=project, python=None, work_root=work,
                     control_root=work / "runs/engineering/rr-test", source_spec_root=source,
                     profile_registry=registry, project_revision=receipt,
                     project_revision_sha256=digest, expected_commit="a" * 40,
                     execution_scope_id="test", tmux_socket="default", tmux_session="rr-test")
    assert mod.run(args) == 0
    assert events == ["start", *(lane for lane, _count in mod.LAYOUT), "accounting", "end"]


def test_rr_accounting_retains_partial_checkpoint_outputs(tmp_path, monkeypatch):
    control = tmp_path / "runs/engineering/campaign"
    lane = mod.LAYOUT[0][0]
    root = tmp_path / "runs/thesis/runner" / lane / control.name
    root.mkdir(parents=True)
    def durable(path):
        assert path == root
        return {"a": "row-a", "b": "row-b"}, {
            "row-a": "usable_first_response", "row-b": "failed_output"}, [], []
    monkeypatch.setattr(mod, "_durable_outcomes", durable)
    assert mod.execution_counts({mod.LAYOUT[1][0]: {
        "target_attempts": 10, "successful_target_generations": 9}},
        work_root=tmp_path, control_root=control) == {
            "target_attempts": 12, "successful_target_generations": 10, "missing_responses": 2}


@pytest.mark.parametrize("mutation", [None, "model", "seed", "limit", "revision"])
def test_rr_uses_all_four_retained_selections_and_the_admitted_profile(tmp_path, monkeypatch, mutation):
    source = tmp_path / "specs"
    source.mkdir()
    control = tmp_path / "campaign"
    (control / "configs").mkdir(parents=True)
    registry = tmp_path / "profiles.json"
    registry.write_text("{}", encoding="utf-8")
    config = tmp_path / "old-config.json"
    config.write_text(json.dumps({mod.RR_SPEC: {"revision": mod.RR_REVISION}}), encoding="utf-8")
    config_desc = mod._descriptor(config, label="fixture")
    originals = []
    for index, (lane, count) in enumerate(mod.LAYOUT, 1):
        argv = ["--local", mod.RR_SPEC, "--local-config", str(config),
                "--local-config-sha256", config_desc["sha256"], "--limit", "100",
                "--sample-seed", "0", "--seeds", "0", "--attackers", "replay",
                "--corpora", f"corpus-{index}"]
        value = {"lane_id": lane, "base_argv": argv, "local_config": config_desc,
                 "target": {"revision": mod.RR_REVISION}, "approved_caps": {"target_calls": count}}
        originals.append(list(argv))
        if index == 1:
            if mutation == "model":
                argv[argv.index("--local") + 1] = "vllm:base"
            elif mutation == "seed":
                argv[argv.index("--sample-seed") + 1] = "1"
            elif mutation == "limit":
                argv[argv.index("--limit") + 1] = "50"
            elif mutation == "revision":
                value["target"]["revision"] = "f" * 40
        (source / f"{index:02d}-{lane}.json").write_text(json.dumps(value), encoding="utf-8")
    calls = []

    def profile(config, *, spec, profile_registry):
        assert spec == mod.RR_SPEC and profile_registry == registry
        calls.append(spec)
        return {spec: {**config[spec], "max_tokens": 4096, "max_model_len": -1,
                       "timeout": 120, "tensor_parallel_size": 1}}, {"verified": True}

    monkeypatch.setattr(mod, "profiled_bounded_local_config", profile)
    if mutation:
        with pytest.raises(ValueError, match="retained selection"):
            mod.configure_units(source, control, registry)
        assert not calls
        return
    units, evidence = mod.configure_units(source, control, registry)
    assert sum(unit.selected_records for unit in units) == 7606
    assert [unit.unit_id for unit in units] == [lane for lane, _count in mod.LAYOUT]
    assert len(calls) == 4
    for unit, original in zip(units, originals, strict=True):
        assert unit.recovery is None
        rewritten = unit.spec["base_argv"]
        for flag in ("--local", "--limit", "--sample-seed", "--seeds", "--corpora", "--attackers"):
            assert mod._option(rewritten, flag) == mod._option(original, flag)
        current = json.loads((control / "configs" / f"{unit.unit_id}.json").read_text())
        assert current[mod.RR_SPEC]["max_tokens"] == 4096
        assert evidence[unit.unit_id]["execution_profile"] == {"verified": True}


def test_rr_checkpoint_selection_retains_failed_and_length_ended_rows():
    # The selector takes durable IDs, never filters on response quality.
    selected = {"partial": ["failed", "length", "pending"], "new": ["new-1", "new-2"]}
    selector, count = mod.checkpoint_selection(selected, ["failed", "length"])
    assert count == 3
    assert selector["corpora"]["partial"]["completed_datapoint_ids"] == ["failed", "length"]
    first, corpora, count = mod.continuation_partition(selected, ["failed", "length"])
    assert corpora == ["partial"] and count == 1
    assert first["corpora"]["partial"]["completed_record_count"] == 2
    second, corpora, count = mod.continuation_partition(selected, ["failed", "length", "pending"])
    assert second is None and corpora == ["new"] and count == 2
    empty, corpora, count = mod.continuation_partition(selected, ["failed", "length", "pending", "new-1", "new-2"])
    assert empty is None and corpora == [] and count == 0


@pytest.mark.parametrize("completed", [["foreign"], ["a", "a"]])
def test_rr_checkpoint_selector_rejects_changed_or_duplicate_ids(completed):
    with pytest.raises(ValueError, match="exact selected subset"):
        mod.checkpoint_selection({"arm": ["a", "b"]}, completed)


@pytest.fixture
def terminal_rr(tmp_path, monkeypatch):
    runner = tmp_path / "runs/thesis/runner"
    root = tmp_path / "runs/engineering/original"
    root.mkdir(parents=True)
    config = root / "config.json"
    config.write_text(json.dumps({mod.RR_SPEC: {"revision": mod.RR_REVISION, "max_tokens": 4096}}))
    config_desc = mod._descriptor(config, label="fixture")
    revision = root / "revision.json"
    revision.write_text(json.dumps({"repository": {"expected_commit": "a" * 40, "observed_commit": "a" * 40}}))
    revision_desc = mod._descriptor(revision, label="fixture")
    selected, evidence, results, failures, retained, arguments = {}, {}, {}, {}, {}, {}

    def write(path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload))
        return mod._descriptor(path, label="fixture")

    for index, (lane, count) in enumerate(mod.LAYOUT):
        corpus = f"corpus-{index}"
        ids = [f"{corpus}-{row}" for row in range(count)]
        selected[corpus] = ids
        argv = ["--local", mod.RR_SPEC, "--local-config", str(config),
                "--local-config-sha256", config_desc["sha256"], "--corpora", corpus,
                "--limit", "100", "--sample-seed", "0", "--seeds", "0", "--attackers", "replay",
                "--max-turns", "1"]
        spec = {"lane_id": lane, "base_argv": argv, "modality": "text",
                "target": {"revision": mod.RR_REVISION}}
        evidence[lane] = {"source_specification": write(root / "specs" / f"{lane}.json", spec),
                          "local_config": config_desc, "execution_profile": {"verified": True}}
        state_argv = [*argv, "--project-revision", str(revision),
                      "--project-revision-sha256", revision_desc["sha256"],
                      "--target-answer-retries", "1", "--deadline-seconds", "86400",
                      "--max-total-target-calls", str(count * 2), "--max-total-judge-calls", "0",
                      "--max-total-http-attempts", "0"]
        arguments[lane] = state_argv
        result_root = runner / lane / root.name
        response_file = result_root / "arm.responses.checkpoint.jsonl"
        write(response_file, {})
        current = {item: "usable_first_response" for item in (ids[:2] if index == 0 else ids)}
        if index == 0:
            current[ids[0]] = "failed_output"
        retained[result_root] = current
        state = write(root / "units" / lane / "state.json", {
            "schema": mod.STATE_SCHEMA, "unit_id": lane, "source_lane": lane, "corpus": None,
            "result_root": str(result_root), "selected_records": count,
            "target_answer_retries": 1, "runner_argv": state_argv,
        })
        if index == 0:
            failures[lane] = {"status": "failed", "error_type": "TimeoutExpired"}
        else:
            results[lane] = {"target_attempts": count, "successful_target_generations": count, "state": state}
        write(root / "units" / lane / "canary" / "eligibility-fixture.eligibility.json", {})
    launch = {"schema": mod.SCHEMA, "status": "running", "unit_order": list(dict(mod.LAYOUT)),
              "units": evidence, "planned_unique_rows": 7606, "target_answer_retries": 1,
              "successful_rows_repeated": 0, "paid_provider_calls": 0,
              "cross_condition_pooling_permitted": False, "project_revision": revision_desc,
              "expected_commit": "a" * 40}
    total = sum(map(len, retained.values()))
    completion = {**launch, "status": "complete_with_failures", "controller_exit_code": 1,
                  "launch": write(root / "launch.json", launch), "unit_results": results,
                  "unit_failures": failures, "target_execution": {
                      "target_attempts": total, "successful_target_generations": total - 1, "missing_responses": 1}}
    completion_path = root / "completion.json"
    write(completion_path, completion)

    def rows(argv):
        return {corpus: [SimpleNamespace(id=item) for item in selected[corpus]]
                for corpus in mod._option(argv, "--corpora").split(",")}, {}

    def durable(path):
        current = retained[path]
        return {f"attempt-{item}": item for item in current}, dict(current), [], [path / "arm.responses.checkpoint.jsonl"]

    monkeypatch.setattr(mod, "_selected_rows", rows)
    monkeypatch.setattr(mod, "_durable_outcomes", durable)
    return SimpleNamespace(root=root, runner=runner, completion_path=completion_path, completion=completion,
                           retained=retained, config=config, write=write, arguments=arguments)


def test_rr_continuation_binds_terminal_prefix_and_skips_three_completed_lanes(terminal_rr):
    fixture = terminal_rr
    root = fixture.root.with_name("continuation")
    (root / "inputs").mkdir(parents=True)
    units, evidence, inputs, canaries = mod.configure_continuation(
        fixture.completion_path, mod._descriptor(fixture.completion_path, label="fixture")["sha256"],
        control_root=root, runner_root=fixture.runner,
    )
    assert len(units) == 1 and units[0].unit_id == mod.LAYOUT[0][0]
    assert units[0].selected_records == 3852
    assert units[0].recovery["corpora"]["corpus-0"]["completed_datapoint_ids"] == ["corpus-0-0", "corpus-0-1"]
    assert inputs["retained_response_count"] == 3754
    assert len(inputs["retained_inputs"][0]["lanes"]) == 4
    assert evidence == fixture.completion["units"]
    assert canaries == {units[0].unit_id: fixture.root / "units" / units[0].unit_id / "canary"}


@pytest.mark.parametrize("mutation", ["running", "selection", "deadline", "config", "duplicate", "envelope"])
def test_rr_terminal_chain_rejects_changed_source(terminal_rr, mutation):
    fixture = terminal_rr
    lane = mod.LAYOUT[0][0]
    state_path = fixture.root / "units" / lane / "state.json"
    if mutation == "running":
        fixture.completion["status"] = "running"
        fixture.write(fixture.completion_path, fixture.completion)
    elif mutation in {"selection", "deadline", "envelope"}:
        state = json.loads(state_path.read_text())
        flag = {"selection": "--sample-seed", "deadline": "--deadline-seconds", "envelope": "--max-turns"}[mutation]
        state["runner_argv"] = mod._replace_option(state["runner_argv"], flag, "7")
        fixture.write(state_path, state)
    elif mutation == "config":
        fixture.config.write_text("{}")
    elif mutation == "duplicate":
        fixture.retained[fixture.runner / lane / fixture.root.name]["outside-selection"] = "usable_first_response"
    with pytest.raises(ValueError):
        mod.terminal_chain(fixture.completion_path, runner_root=fixture.runner)


def test_rr_continuation_requires_exact_source_digest(terminal_rr):
    with pytest.raises(ValueError, match="completion digest"):
        mod.configure_continuation(terminal_rr.completion_path, "f" * 64,
                                   control_root=terminal_rr.root.with_name("unused"),
                                   runner_root=terminal_rr.runner)


def test_rr_continuation_cannot_branch_around_later_durable_rows(terminal_rr):
    fixture = terminal_rr
    fixture.write(fixture.runner / mod.LAYOUT[0][0] / "other-successor" / "arm.responses.checkpoint.jsonl", {})
    with pytest.raises(ValueError, match="omits a later measured result root"):
        mod.configure_continuation(fixture.completion_path,
                                   mod._descriptor(fixture.completion_path, label="fixture")["sha256"],
                                   control_root=fixture.root.with_name("unused"), runner_root=fixture.runner)


@pytest.mark.parametrize("mutation", [None, "repeat", "prefix_bytes"])
def test_rr_second_terminal_revalidates_bound_prefix_and_exact_union(terminal_rr, mutation):
    fixture = terminal_rr
    root = fixture.root.with_name("suffix")
    (root / "inputs").mkdir(parents=True)
    units, evidence, inputs, _canaries = mod.configure_continuation(
        fixture.completion_path, mod._descriptor(fixture.completion_path, label="fixture")["sha256"],
        control_root=root, runner_root=fixture.runner,
    )
    unit = units[0]
    lane = unit.unit_id
    selector = inputs["selectors"][lane]
    argv = mod._replace_option(fixture.arguments[lane], "--max-total-target-calls", str(unit.selected_records * 2))
    position = argv.index("--deadline-seconds")
    argv[position:position] = ["--recovery-completed-prefix", selector["path"],
                              "--recovery-completed-prefix-sha256", selector["sha256"]]
    result_root = fixture.runner / lane / root.name
    fixture.write(result_root / "arm.responses.checkpoint.jsonl", {})
    fixture.retained[result_root] = {f"corpus-0-{index}": "usable_first_response" for index in range(2, 3854)}
    state = fixture.write(root / "units" / lane / "state.json", {
        "schema": mod.STATE_SCHEMA, "unit_id": lane, "source_lane": lane, "corpus": None,
        "result_root": str(result_root), "selected_records": unit.selected_records,
        "target_answer_retries": 1, "runner_argv": argv,
    })
    launch = {**fixture.completion, "schema": mod.CONTINUATION_SCHEMA, "status": "running",
              "units": evidence, "unit_order": [lane], "planned_unique_rows": unit.selected_records,
              **inputs}
    for field in ("launch", "unit_results", "unit_failures", "target_execution", "controller_exit_code"):
        launch.pop(field)
    completion = {**launch, "launch": fixture.write(root / "launch.json", launch),
                  "status": "complete", "controller_exit_code": 0, "unit_failures": {},
                  "unit_results": {lane: {"state": state, "target_attempts": 3852,
                                           "successful_target_generations": 3852}},
                  "target_execution": {"target_attempts": 3852, "successful_target_generations": 3852, "missing_responses": 0}}
    path = root / "completion.json"
    fixture.write(path, completion)
    if mutation == "repeat":
        fixture.retained[result_root]["corpus-0-0"] = "usable_first_response"
    elif mutation == "prefix_bytes":
        fixture.write(fixture.runner / lane / fixture.root.name / "arm.responses.checkpoint.jsonl", {"changed": True})
    if mutation:
        with pytest.raises(ValueError):
            mod.terminal_chain(path, runner_root=fixture.runner)
        return
    chain, _selected, outcomes, snapshots, segments = mod.terminal_chain(path, runner_root=fixture.runner)
    assert len(chain) == len(snapshots) == 2
    assert sum(map(len, outcomes.values())) == 7606
    assert outcomes[lane]["corpus-0-0"] == "failed_output"
    assert sum(item["selected_records"] for item in segments) == 7604
