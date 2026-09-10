"""Shared inputs survive model-specific budgets, serialization and batch splits."""
import copy

import pytest

from experiments import hosted_retained_inputs as subject
from test_hosted_retained_inputs import _cell, _bindings, TARGET


def _cohort(tmp_path, candidates, excluded=()):
    value = subject.build_shared_cohort(candidates=candidates, excluded_input_ids=excluded)
    path = tmp_path / "cohort.json"
    subject._write_new(path, value)
    return value, subject._descriptor(path)


def _build(candidates, cohort, descriptor, start=0, stop=4, **updates):
    return subject.build_cohort_plan(candidates=candidates, cohort=cohort,
        cohort_descriptor=descriptor, target=TARGET, prefix_start=start, prefix_stop=stop,
        call_cap=stop-start, request_builder=lambda row: {"messages": row["rendered_input"]},
        **_bindings(**updates))


def test_same_inputs_across_model_controls_and_nested_batches(tmp_path):
    candidates = subject.candidates_from_cells([_cell(tmp_path, count=12)])
    cohort, descriptor = _cohort(tmp_path, candidates)
    first = _build(candidates, cohort, descriptor)
    second = _build(candidates, cohort, descriptor, start=4, stop=8)
    full = _build(candidates, cohort, descriptor, stop=8)
    changed = copy.deepcopy(_bindings()["api_config"])
    changed[TARGET]["max_tokens"] = 8192
    other = _build(candidates, cohort, descriptor, api_config=changed)
    payloads = lambda plan: set(plan["selection"]["selected_input_payload_sha256"])
    assert payloads(first) == payloads(other)
    assert not payloads(first) & payloads(second)
    assert payloads(first) | payloads(second) == payloads(full)
    assert first["sources"]["shared_input_cohort"] == second["sources"]["shared_input_cohort"]
    assert subject.resolve_inputs(first, candidates=candidates,
        request_builder=lambda row: {"messages": row["rendered_input"]}, **_bindings())


def test_previous_payload_alias_excludes_entire_cluster(tmp_path):
    cell = _cell(tmp_path, count=8)
    cell["attempts"]["attempt-1"]["rendered_input"] = copy.deepcopy(cell["attempts"]["attempt-0"]["rendered_input"])
    for index in [1, 2]:
        cell["attempts"][f"attempt-{index}"]["params"]["source_cluster_id"] = "shared-cluster"
        cell["attempts"][f"attempt-{index}"]["params"]["planning_source"] = "one-source"
    candidates = subject.candidates_from_cells([cell])
    excluded = next(row["input_identity_sha256"] for row in candidates if row["datapoint_id"] == "data-0")
    cohort, descriptor = _cohort(tmp_path, candidates, [excluded])
    plan = _build(candidates, cohort, descriptor, stop=8)
    assert {row["datapoint_id"] for row in plan["selected"]} == {f"data-{i}" for i in range(3, 8)}


def test_batch_boundary_cannot_split_cluster_or_exceed_funding(tmp_path):
    cell = _cell(tmp_path, count=8)
    for i, attempt in enumerate(cell["attempts"].values()):
        attempt["params"].update(source_cluster_id=f"cluster-{i // 4}", planning_source="one-arm")
    candidates = subject.candidates_from_cells([cell])
    cohort, descriptor = _cohort(tmp_path, candidates)
    with pytest.raises(ValueError, match="splits a whole source cluster"):
        _build(candidates, cohort, descriptor, start=3, stop=8)
    plan = _build(candidates, cohort, descriptor, stop=5)
    assert len(plan["selected"]) == 4
    with pytest.raises(ValueError, match="funded physical request cap"):
        subject.build_cohort_plan(candidates=candidates, cohort=cohort, cohort_descriptor=descriptor,
            target=TARGET, prefix_start=0, prefix_stop=8, call_cap=3,
            request_builder=lambda row: {"messages": row["rendered_input"]}, **_bindings())


@pytest.mark.parametrize("change", ["cohort", "input", "interval", "budget"])
def test_changed_source_or_batch_refuses_before_any_call(tmp_path, change):
    candidates = subject.candidates_from_cells([_cell(tmp_path)])
    cohort, descriptor = _cohort(tmp_path, candidates)
    plan = _build(candidates, cohort, descriptor)
    bindings = _bindings()
    if change == "cohort":
        plan["sources"]["shared_input_cohort"]["sha256"] = "f" * 64
    elif change == "input":
        candidates[0]["rendered_input"][0]["content"] = "changed prompt"
    elif change == "interval":
        plan["selection"]["prefix_stop"] += 1
    else:
        bindings["budget"]["routes"][0]["paid_call_cap"] = 1
    with pytest.raises(ValueError):
        subject.resolve_inputs(plan, candidates=candidates,
            request_builder=lambda row: {"messages": row["rendered_input"]}, **bindings)


def test_shared_cohort_executes_through_real_preparation_and_runner_admission(tmp_path, monkeypatch):
    from experiments import hosted_campaign_prepare as prepare
    from test_hosted_campaign_prepare import _distinct_request
    # The existing fixture supplies actual DataPoints and retained Attempt shapes.
    # Only source acquisition and network generation are replaced, not selection.
    request, _, _ = _distinct_request(tmp_path, monkeypatch, cohort=True)
    result = prepare.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "prepared-cohort", allow_network_counts=False)
    program = prepare.executor._bound({key: result["programs"][0][key] for key in ("path", "sha256", "bytes")})[0]
    assert program["schema"] == prepare.executor.COHORT_INPUT_SCHEMA
    budget = prepare.AttemptBudget(tmp_path / "prepared-cohort/budget", result["budget"]["sha256"])
    assert prepare.executor._validated_jobs(program, budget)
    assert result["target_calls"] == result["judge_calls"] == 0
