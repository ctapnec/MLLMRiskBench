from __future__ import annotations

import json

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
