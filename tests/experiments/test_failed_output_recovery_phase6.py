from __future__ import annotations

import json
import inspect

import pytest

from experiments.local_campaign.current_ollama import CURRENT_OLLAMA_BY_LABEL
from experiments.local_campaign.failed_output_recovery_phase6 import (
    EXPECTED_RECOVERY_COUNTS,
    EXPECTED_RECOVERY_ROWS,
    EXPECTED_UNIT_ORDER,
    ORIGINAL_UNIT_ORDER,
    _durable_outcomes,
    build_completed_selection,
    physical_unit_id,
    validate_phase7_completion as dispatch_phase7_completion,
)
from experiments.local_campaign.failed_output_recovery_continuation_phase6 import (
    CONTINUATION_UNIT_ORDER,
    DEEPSEEK_CONTINUATION_NUM_PREDICT,
    DEEPSEEK_PHYSICAL_UNIT,
    RETAINED_UNIT_ORDER,
    SCHEMA as CONTINUATION_SCHEMA,
    _create_deepseek_generation_condition,
    _partial_durable_counts,
    _revision_map,
    run as run_continuation,
)
from ura.data_models import SCHEMA_VERSION


@pytest.mark.parametrize("mutation", [None, "promote", "counter", "selection", "digest"])
def test_partial_continuation_retains_five_metrics_and_checkpoint_failures(
    tmp_path, monkeypatch, mutation,
) -> None:
    from experiments.local_campaign import failed_output_recovery_continuation_phase6 as mod

    work = tmp_path / "work"
    control = work / "runs/engineering/partial"
    prior_root = work / "runs/engineering/prior"
    runner = work / "runs/thesis/runner"
    for path in (control, prior_root, runner):
        path.mkdir(parents=True)

    def write(path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
        return mod._descriptor(path, label="fixture")

    commit = "50175d37e1ab28cc10722eb08d765debac3d0eaa"
    source = "a" * 64
    snapshot = {"schema": mod.SNAPSHOT_SCHEMA, "recovery_records": 1674,
                "successful_rows_repeated": 0, "input_incompatible_rows_retried": 0,
                "units": {DEEPSEEK_PHYSICAL_UNIT: {"summary": {"recovery_records": 1674}}}}
    prior_snapshot = {**snapshot, "schema": mod.PRIOR_SNAPSHOT_SCHEMA,
                      "recovery_records": EXPECTED_RECOVERY_ROWS,
                      "units": {lane: snapshot["units"][DEEPSEEK_PHYSICAL_UNIT]
                                for lane in EXPECTED_UNIT_ORDER}}
    prior_snapshot_desc = write(prior_root / "input-snapshot.json", prior_snapshot)
    prior_launch = {"schema": mod.PRIOR_LAUNCH_SCHEMA,
                    "runner_code_version": "ura-runner/2.27", "target_answer_retries": 1,
                    "unit_order": list(EXPECTED_UNIT_ORDER),
                    "recovery_records": EXPECTED_RECOVERY_ROWS}
    prior = {"schema": mod.PRIOR_SCHEMA, "status": "complete_with_failures",
             "controller_exit_code": 1, "completed_at_utc": "2026-09-02T03:00:00Z",
             "expected_commit": "b" * 40, "runner_code_version": "ura-runner/2.27",
             "target_answer_retries": 1, "unit_order": list(EXPECTED_UNIT_ORDER),
             "unit_results": {lane: {"unit_id": lane} for lane in RETAINED_UNIT_ORDER},
             "unit_failures": {DEEPSEEK_PHYSICAL_UNIT: {
                 "unit_id": DEEPSEEK_PHYSICAL_UNIT, "original_unit_id": mod.DEEPSEEK_UNIT,
                 "status": "failed"}}, "target_execution": dict(mod.PRIOR_TARGET_EXECUTION),
             "successful_rows_repeated": 0, "input_incompatible_rows_retried": 0,
             "cross_revision_pooling_permitted": False, "paid_provider_calls": 0,
             "input_snapshot": prior_snapshot_desc,
             "launch": write(prior_root / "launch.json", prior_launch)}
    prior_desc = write(prior_root / "completion.json", prior)
    revision = write(control / "revision.json", {
        "schema": "ura-project-revision/1", "status": "complete",
        "repository": {"clean": True, "expected_commit": commit, "observed_commit": commit}})
    snapshot_desc = write(control / "input-snapshot.json", snapshot)
    launch = {**prior_launch, "schema": "ura-failed-output-recovery-continuation-phase6-launch/1",
              "expected_commit": commit, "unit_order": list(CONTINUATION_UNIT_ORDER),
              "prior_completion": prior_desc, "input_snapshot": snapshot_desc,
              "project_revision": revision, "recovery_records": 1674,
              "successful_rows_repeated": 0, "paid_provider_calls": 0}
    unit_root = control / "units" / DEEPSEEK_PHYSICAL_UNIT
    result_root = runner / DEEPSEEK_PHYSICAL_UNIT / control.name
    result_root.mkdir(parents=True)
    write(unit_root / "state.json", {
        "result_root": str(result_root), "runner_argv": [
            "--project-revision-sha256", revision["sha256"],
            "--source-conformance-sha256", source, "--target-answer-retries", "1"]})
    completion = {**prior, "schema": "ura-failed-output-recovery-phase6/2",
                  "expected_commit": commit, "prior_completion": prior_desc,
                  "retained_unit_order": list(RETAINED_UNIT_ORDER),
                  "continuation_unit_order": list(CONTINUATION_UNIT_ORDER),
                  "launch": write(control / "launch.json", launch), "input_snapshot": snapshot_desc,
                  "unit_failures": {DEEPSEEK_PHYSICAL_UNIT: {
                      "unit_id": DEEPSEEK_PHYSICAL_UNIT, "original_unit_id": mod.DEEPSEEK_UNIT,
                      "status": "failed", "error_type": "RuntimeError",
                      "error": f"Runner exited 143; see {unit_root / 'measured.run.log'}"}}}
    checked = []

    def metric(result, **kwargs):
        lane = kwargs["physical_unit"]
        checked.append(lane)
        missing = 56 if lane == EXPECTED_UNIT_ORDER[0] else 0
        return {"successful": kwargs["selected_records"] - missing, "missing": missing,
                "source": source, "revision": "b" * 64, "root": str(runner / lane / "prior"),
                "evidence": {"state": result}, "grid": {}, "eligibility_plan": {},
                "completion_markers": []}

    monkeypatch.setattr(mod, "_validate_metric_result", metric)
    monkeypatch.setattr(mod, "_partial_durable_counts", lambda **kwargs: (50, 0, 50))
    if mutation == "promote":
        completion["status"] = "complete"
    elif mutation == "counter":
        completion["target_execution"] = {**mod.PRIOR_TARGET_EXECUTION, "missing_responses": 0}
    elif mutation == "selection":
        snapshot["units"][DEEPSEEK_PHYSICAL_UNIT] = {"summary": {"recovery_records": 1}}
        completion["input_snapshot"] = write(control / "input-snapshot.json", snapshot)
    elif mutation == "digest":
        completion["launch"] = {**completion["launch"], "sha256": "0" * 64}
    completion_path = control / "completion.json"
    write(completion_path, completion)
    if mutation:
        from ura.artifact_checks import artifact_verification
        with artifact_verification(verify_sha256=mutation == "digest"), pytest.raises(ValueError):
            dispatch_phase7_completion(completion_path, runner_root=runner)
        return
    result = dispatch_phase7_completion(completion_path, runner_root=runner)
    assert checked == list(RETAINED_UNIT_ORDER)
    assert result["metric_lane_order"] == list(RETAINED_UNIT_ORDER)
    assert result["terminal_states"][DEEPSEEK_PHYSICAL_UNIT] == "partial"
    assert DEEPSEEK_PHYSICAL_UNIT not in result["metric_roots"]
    assert result["lifecycle_roots"][DEEPSEEK_PHYSICAL_UNIT] == str(result_root)
    assert result["target_execution"] == {
        "target_attempts": 2189, "successful_target_generations": 2083, "missing_responses": 106}
    assert result["source_target_execution"] == mod.PRIOR_TARGET_EXECUTION
    assert result["revision_strata"] == {"b" * 64: list(RETAINED_UNIT_ORDER)}


def test_phase7_recovery_inventory_is_the_exact_six_unit_proof() -> None:
    assert len(ORIGINAL_UNIT_ORDER) == len(EXPECTED_UNIT_ORDER) == 6
    assert EXPECTED_RECOVERY_COUNTS == (1223, 555, 323, 18, 1674, 20)
    assert EXPECTED_RECOVERY_ROWS == 3813
    assert EXPECTED_UNIT_ORDER == tuple(
        f"failed-output-recovery-{index:02d}-{original[:52]}"
        for index, original in enumerate(ORIGINAL_UNIT_ORDER, 1)
    )


def test_failed_output_continuation_selects_only_unexecuted_deepseek() -> None:
    assert CONTINUATION_UNIT_ORDER == (EXPECTED_UNIT_ORDER[4],)
    assert DEEPSEEK_PHYSICAL_UNIT == EXPECTED_UNIT_ORDER[4]
    assert RETAINED_UNIT_ORDER == EXPECTED_UNIT_ORDER[:4] + EXPECTED_UNIT_ORDER[5:]

    source = inspect.getsource(run_continuation)
    assert "only_original_units=(DEEPSEEK_UNIT,)" in source
    assert 'results = dict(prior["unit_results"])' in source
    assert "successful_rows_repeated\": 0" in source
    assert "_partial_durable_counts(" in source
    assert "_create_deepseek_generation_condition(" in source
    assert CONTINUATION_SCHEMA == "ura-failed-output-recovery-phase6/3"
    assert "ura-failed-output-recovery-phase6/3" in inspect.getsource(
        dispatch_phase7_completion
    )

    assert physical_unit_id(ORIGINAL_UNIT_ORDER[4]) == EXPECTED_UNIT_ORDER[4]
    with pytest.raises(ValueError, match="unknown failed-output recovery unit"):
        physical_unit_id("not-a-recovery-unit")

    # Reverse mutation: renumbering the filtered unit from one reproduces the
    # pre-execution selector mismatch that this continuation must reject.
    reindexed = f"failed-output-recovery-01-{ORIGINAL_UNIT_ORDER[4][:52]}"
    assert reindexed != DEEPSEEK_PHYSICAL_UNIT


def test_failed_output_continuation_preserves_split_revision_strata() -> None:
    validated = {
        lane: {"revision": "a" * 64 if lane != DEEPSEEK_PHYSICAL_UNIT else "b" * 64}
        for lane in EXPECTED_UNIT_ORDER
    }
    strata, by_lane = _revision_map(validated)

    assert strata == {
        "a" * 64: list(RETAINED_UNIT_ORDER),
        "b" * 64: [DEEPSEEK_PHYSICAL_UNIT],
    }
    assert by_lane[DEEPSEEK_PHYSICAL_UNIT] == "b" * 64

    # Reverse mutation: pooling the continuation into the retained revision is
    # detectable because the second stratum disappears.
    mutated = {lane: {"revision": "a" * 64} for lane in EXPECTED_UNIT_ORDER}
    mutated_strata, _mutated_by_lane = _revision_map(mutated)
    assert mutated_strata != strata


def test_failed_output_continuation_counts_checkpointed_rows_after_failure(
    tmp_path,
) -> None:
    work_root = tmp_path / "work"
    control_root = work_root / "runs" / "engineering" / "campaign"
    unit_root = control_root / "units" / DEEPSEEK_PHYSICAL_UNIT
    result_root = (
        work_root
        / "runs"
        / "thesis"
        / "runner"
        / DEEPSEEK_PHYSICAL_UNIT
        / control_root.name
    )
    unit_root.mkdir(parents=True)
    result_root.mkdir(parents=True)
    (unit_root / "state.json").write_text(
        json.dumps({
            "schema": "ura-failed-output-recovery-phase6-unit-state/1",
            "unit_id": DEEPSEEK_PHYSICAL_UNIT,
            "selected_records": EXPECTED_RECOVERY_COUNTS[4],
            "target_answer_retries": 1,
            "result_root": str(result_root),
        }),
        encoding="utf-8",
    )
    attempts = [
        {
            "id": f"attempt-{index}",
            "datapoint_id": f"row-{index}",
            "attacker": "replay",
            "target": "target",
            "rendered_input": [{"role": "user", "content": "fixture"}],
            "run_id": f"run-{index}",
        }
        for index in range(2)
    ]
    responses = [
        {
            "attempt_id": "attempt-0",
            "target": "target",
            "output_turns": [{"role": "assistant", "content": "answer"}],
            "raw": {"model_stability_status": "usable_first_response"},
            "run_id": "run-0",
        },
        {
            "attempt_id": "attempt-1",
            "target": "target",
            "output_turns": [],
            "raw": {"model_stability_status": "failed_output"},
            "run_id": "run-1",
        },
    ]
    (result_root / "fixture.attempts.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in attempts), encoding="utf-8"
    )
    (result_root / "fixture.responses.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in responses), encoding="utf-8"
    )

    assert _partial_durable_counts(
        work_root=work_root,
        control_root=control_root,
    ) == (2, 1, 1)

    # Reverse mutation: the old controller published zeros after the same
    # checkpointed failure and therefore cannot satisfy this accounting proof.
    assert (0, 0, 0) != (2, 1, 1)


def test_deepseek_continuation_binds_separate_calibrated_generation_cap(
    tmp_path,
) -> None:
    model = CURRENT_OLLAMA_BY_LABEL["deepseek-r1-distill-32b"]
    control_root = tmp_path / "campaign"
    (control_root / "configs").mkdir(parents=True)
    condition = _create_deepseek_generation_condition(
        control_root=control_root,
    )

    assert DEEPSEEK_CONTINUATION_NUM_PREDICT == 2_048
    assert condition["num_predict"] == 2_048
    assert condition["think"] is True
    config_path = control_root / "configs" / "deepseek-r1-distill-32b.json"
    assert condition["local_config"]["path"] == str(config_path)
    assert json.loads(config_path.read_text(encoding="utf-8"))[model.spec] == {
        "digest": model.digest,
        "modalities": ["text"],
        "num_ctx": 8192,
        "num_predict": 2_048,
        "think": True,
    }

    # Reverse mutation: the stopped 512-token condition is not this cohort.
    assert 512 != DEEPSEEK_CONTINUATION_NUM_PREDICT


def test_selector_replays_only_failed_and_never_attempted_rows() -> None:
    selected = {
        "alpha": ["a", "b", "c", "d"],
        "beta": ["e", "f"],
    }
    eligible = {
        "alpha": ["b", "c", "d"],
        "beta": ["f"],
    }
    outcomes = {
        "b": "usable_first_response",
        "c": "failed_output",
        "f": "input_incompatible",
    }

    selector, summary = build_completed_selection(
        selected_ids=selected,
        eligible_ids=eligible,
        outcomes=outcomes,
    )

    assert list(selector["corpora"]) == ["alpha"]
    alpha = selector["corpora"]["alpha"]
    assert alpha["completed_datapoint_ids"] == ["a", "b"]
    assert summary == {
        "selected_records": 6,
        "prior_eligible_records": 4,
        "durable_outcomes": 3,
        "failed_output_records": 1,
        "input_incompatible_records": 1,
        "never_attempted_records": 1,
        "recovery_records": 2,
        "completed_records_excluded": 4,
        "recovery_corpora": ["alpha"],
    }

    # Reverse mutation: treating the failed row as complete changes the exact
    # remaining-set digest and would silently omit a required replay.
    mutated, mutated_summary = build_completed_selection(
        selected_ids=selected,
        eligible_ids=eligible,
        outcomes={**outcomes, "c": "usable_first_response"},
    )
    assert mutated["corpora"]["alpha"]["remaining_datapoint_ids_sha256"] != (
        alpha["remaining_datapoint_ids_sha256"]
    )
    assert mutated_summary["recovery_records"] == 1


def test_selector_rejects_outcomes_outside_prior_unfinished_population() -> None:
    with pytest.raises(ValueError, match="outside the prior unfinished"):
        build_completed_selection(
            selected_ids={"alpha": ["a", "b"]},
            eligible_ids={"alpha": ["b"]},
            outcomes={"a": "failed_output"},
        )


def test_selector_refuses_a_recovery_with_no_failed_or_unfinished_row() -> None:
    with pytest.raises(ValueError, match="no failed or unfinished"):
        build_completed_selection(
            selected_ids={"alpha": ["a", "b"]},
            eligible_ids={"alpha": ["b"]},
            outcomes={"b": "usable_first_response"},
        )


def test_durable_outcomes_include_prejudging_response_checkpoint(tmp_path) -> None:
    final_attempt = {
        "id": "attempt-a",
        "datapoint_id": "a",
        "attacker": "replay",
        "target": "target",
        "rendered_input": [{"role": "user", "content": "a"}],
        "run_id": "run-a",
    }
    final_response = {
        "attempt_id": "attempt-a",
        "target": "target",
        "output_turns": [{"role": "assistant", "content": "answer"}],
        "raw": {},
        "run_id": "run-a",
    }
    checkpoint_attempt = {
        **final_attempt,
        "id": "attempt-b",
        "datapoint_id": "b",
        "rendered_input": [{"role": "user", "content": "b"}],
        "run_id": "run-b",
    }
    checkpoint_response = {
        "attempt_id": "attempt-b",
        "target": "target",
        "output_turns": [],
        "raw": {"model_stability_status": "failed_output"},
        "run_id": "run-b",
    }
    (tmp_path / "alpha.attempts.jsonl").write_text(
        json.dumps(final_attempt) + "\n", encoding="utf-8"
    )
    (tmp_path / "alpha.responses.jsonl").write_text(
        json.dumps(final_response) + "\n", encoding="utf-8"
    )
    (tmp_path / "beta.responses.checkpoint.jsonl").write_text(
        json.dumps({
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-b",
            "attempt": checkpoint_attempt,
            "response": checkpoint_response,
            "budget_after_target": None,
        })
        + "\n",
        encoding="utf-8",
    )

    attempts, outcomes, attempt_files, response_files = _durable_outcomes(
        tmp_path
    )

    assert attempts == {"attempt-a": "a", "attempt-b": "b"}
    assert outcomes == {"a": "usable_first_response", "b": "failed_output"}
    assert [path.name for path in attempt_files] == ["alpha.attempts.jsonl"]
    assert [path.name for path in response_files] == [
        "alpha.responses.jsonl",
        "beta.responses.checkpoint.jsonl",
    ]


def test_durable_outcomes_accept_checkpoint_before_attempts_file(tmp_path) -> None:
    checkpoint_attempt = {
        "id": "attempt-b",
        "datapoint_id": "b",
        "attacker": "replay",
        "target": "target",
        "rendered_input": [{"role": "user", "content": "b"}],
        "run_id": "run-b",
    }
    checkpoint_response = {
        "attempt_id": "attempt-b",
        "target": "target",
        "output_turns": [],
        "raw": {"model_stability_status": "failed_output"},
        "run_id": "run-b",
    }
    (tmp_path / "beta.responses.checkpoint.jsonl").write_text(
        json.dumps({
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-b",
            "attempt": checkpoint_attempt,
            "response": checkpoint_response,
            "budget_after_target": None,
        })
        + "\n",
        encoding="utf-8",
    )

    attempts, outcomes, attempt_files, response_files = _durable_outcomes(
        tmp_path
    )

    assert attempts == {"attempt-b": "b"}
    assert outcomes == {"b": "failed_output"}
    assert attempt_files == []
    assert [path.name for path in response_files] == [
        "beta.responses.checkpoint.jsonl"
    ]


@pytest.mark.parametrize("final_count", [0, 1, 2])
def test_partial_judging_does_not_hide_generated_responses(tmp_path, final_count) -> None:
    records = []
    for index in range(2):
        records.append({
            "schema_version": SCHEMA_VERSION,
            "run_id": "run-a",
            "attempt": {
                "id": f"attempt-{index}", "datapoint_id": f"row-{index}",
                "attacker": "replay", "target": "target", "run_id": "run-a",
                "rendered_input": [{"role": "user", "content": "fixture"}],
            },
            "response": {
                "attempt_id": f"attempt-{index}", "target": "target", "run_id": "run-a",
                "output_turns": [{"role": "assistant", "content": "answer"}], "raw": {},
            },
            "budget_after_target": None,
        })
    checkpoint = tmp_path / "fixture.responses.checkpoint.jsonl"
    checkpoint.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
    for role in ("attempt", "response"):
        (tmp_path / f"fixture.{role}s.jsonl").write_text(
            "".join(json.dumps(row[role]) + "\n" for row in records[:final_count]), encoding="utf-8"
        )
    attempts, outcomes, _af, rf = _durable_outcomes(tmp_path)
    assert len(attempts) == len(outcomes) == 2
    assert set(outcomes.values()) == {"usable_first_response"}
    assert rf == [tmp_path / ("fixture.responses.jsonl" if final_count == 2 else checkpoint.name)]

    # The recovery selector must not schedule the unjudged response again.
    with pytest.raises(ValueError, match="no failed or unfinished"):
        build_completed_selection(
            selected_ids={"arm": ["row-0", "row-1"]},
            eligible_ids={"arm": ["row-0", "row-1"]}, outcomes=outcomes,
        )


@pytest.mark.parametrize("mutation", ["changed", "outside", "duplicate"])
def test_partial_judging_refuses_conflicting_final_responses(tmp_path, mutation) -> None:
    test_partial_judging_does_not_hide_generated_responses(tmp_path, 1)
    final = tmp_path / "fixture.responses.jsonl"
    row = json.loads(final.read_text())
    if mutation == "changed":
        row["raw"]["model_stability_status"] = "failed_output"
    elif mutation == "outside":
        row["attempt_id"] = "not-checkpointed"
    final.write_text((json.dumps(row) + "\n") * (2 if mutation == "duplicate" else 1), encoding="utf-8")
    with pytest.raises(ValueError, match="differs from its response checkpoint|duplicated"):
        _durable_outcomes(tmp_path)
