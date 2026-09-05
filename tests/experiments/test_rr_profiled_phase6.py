from __future__ import annotations

import json
from argparse import Namespace

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
