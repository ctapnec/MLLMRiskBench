from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.local_campaign import rr_profiled_analysis as mod


@pytest.mark.parametrize("mutation", [None, "partial", "missing_unit", "counter", "config_bytes"])
def test_rr_analysis_requires_complete_bound_separate_cohort(tmp_path, monkeypatch, mutation):
    root = tmp_path / "runs/engineering/rr-campaign"
    root.mkdir(parents=True)

    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return mod._descriptor(path, label="fixture")

    units, results, configs = {}, {}, []
    revision = {"sha256": "a" * 64}
    for lane, count in mod.LAYOUT:
        config = write(root / "configs" / f"{lane}.json", {"max_tokens": 4096})
        configs.append(config)
        units[lane] = {"source_specification": write(root / "specs" / f"{lane}.json", {
            "lane_id": lane}), "local_config": config}
        state = write(root / "units" / lane / "state.json", {"runner_argv": [
            "--local-config", config["path"], "--local-config-sha256", config["sha256"]]})
        results[lane] = {"state": state}
    launch = {"schema": mod.SCHEMA, "status": "running", "units": units,
              "unit_order": [lane for lane, _count in mod.LAYOUT], "planned_unique_rows": 7606,
              "target_answer_retries": 1, "successful_rows_repeated": 0,
              "paid_provider_calls": 0, "cross_condition_pooling_permitted": False,
              "project_revision": revision}
    completion = {**launch, "status": "complete", "controller_exit_code": 0,
                  "launch": write(root / "launch.json", launch),
                  "unit_results": results, "unit_failures": {}, "target_execution": {
                      "target_attempts": 7606, "successful_target_generations": 7606, "missing_responses": 0}}
    checked = []

    def metric(result, **kwargs):
        checked.append(kwargs["physical_unit"])
        assert kwargs["state_schema"] == mod.STATE_SCHEMA
        return {"revision": revision["sha256"], "source": "b" * 64,
                "successful": kwargs["selected_records"], "missing": 0}

    monkeypatch.setattr(mod, "_validate_metric_result", metric)
    if mutation == "partial":
        completion["status"] = "complete_with_failures"
    elif mutation == "missing_unit":
        results.pop(mod.LAYOUT[-1][0])
    elif mutation == "counter":
        completion["target_execution"]["successful_target_generations"] = 7605
    elif mutation == "config_bytes":
        from pathlib import Path
        Path(configs[0]["path"]).write_text("{}", encoding="utf-8")
    path = root / "completion.json"
    write(path, completion)
    if mutation:
        with pytest.raises(ValueError):
            mod.validated_units(path, runner_root=tmp_path / "runs/thesis/runner")
        return
    value, validated = mod.validated_units(path, runner_root=tmp_path / "runs/thesis/runner")
    assert checked == [lane for lane, _count in mod.LAYOUT]
    assert list(validated) == checked
    assert value["cross_condition_pooling_permitted"] is False


@pytest.mark.parametrize("missing", [False, True])
def test_rr_chain_analysis_counts_prefix_without_promoting_interrupted_grids(tmp_path, monkeypatch, missing):
    root = tmp_path / "campaign"
    root.mkdir()
    completion = root / "completion.json"
    completion.write_text("{}")
    revision = {"sha256": "a" * 64}
    generation = {"root": root, "path": completion,
                  "value": {"project_revision": revision, "unit_failures": {"prefix": {}}}}
    outcomes = {lane: {f"{lane}-{index}": "usable_first_response" for index in range(count)}
                for lane, count in mod.LAYOUT}
    first_lane = mod.LAYOUT[0][0]
    outcomes[first_lane][f"{first_lane}-0"] = "failed_output"
    if missing:
        outcomes[first_lane].pop(f"{first_lane}-1")
    segments = [{"generation": generation, "lane": lane, "result": {},
                 "selected_records": count - (2 if lane == first_lane else 0)}
                for lane, count in mod.LAYOUT]
    monkeypatch.setattr(mod, "terminal_chain", lambda *args, **kwargs: (
        [generation], {}, outcomes, [{"retained": True}], segments))
    checked = []

    def metric(result, **kwargs):
        checked.append(kwargs["selected_records"])
        return {"revision": revision["sha256"], "source": "b" * 64,
                "successful": kwargs["selected_records"], "missing": 0}

    monkeypatch.setattr(mod, "_validate_metric_result", metric)
    if missing:
        with pytest.raises(ValueError, match="all 7,606"):
            mod.validated_continuation(completion, runner_root=tmp_path)
        assert not checked
        return
    value, units, coverage = mod.validated_continuation(completion, runner_root=tmp_path)
    assert value["target_execution"] == {"target_attempts": 7606,
                                         "successful_target_generations": 7605, "missing_responses": 1}
    assert len(units) == 4
    assert sum(checked) == coverage["completed_grid_responses"] == 7604
    assert coverage["interrupted_grid_responses"] == 2
    assert coverage["interrupted_grids_promoted"] is False
    assert coverage["judge_coverage_requires_retained_postfactum_analysis"] is True


@pytest.mark.parametrize("continuation", [False, True])
def test_rr_level1_reports_never_pool_distinct_execution_revisions(tmp_path, monkeypatch, continuation):
    units = {name: {"revision": revision, "root": name, "eligibility_plan": {"path": name + ".eligibility"}}
             for name, revision in (("original-image", "a" * 64), ("original-rjudge", "a" * 64), ("suffix-text", "b" * 64))}
    calls = []

    def export(argv):
        calls.append(argv)
        Path(argv[argv.index("--out-json") + 1]).write_text("{}")
        return 0

    monkeypatch.setattr(mod.level1_evidence, "main", export)
    if not continuation:
        with pytest.raises(ValueError, match="execution revision stratum"):
            mod.export_level1_strata(units, output=tmp_path, project=tmp_path, continuation=False)
        assert not calls
        return
    reports = mod.export_level1_strata(units, output=tmp_path, project=tmp_path, continuation=True)
    assert set(reports) == {"a" * 64, "b" * 64}
    assert len(calls) == 2
    roots = [[argv[index + 1] for index, value in enumerate(argv) if value == "--results"] for argv in calls]
    assert roots == [["original-image", "original-rjudge"], ["suffix-text"]]
    for argv in calls:
        assert argv[argv.index("--historical-code-repository") + 1] == str(tmp_path)
