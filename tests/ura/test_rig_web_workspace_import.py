"""Saved Runner record shapes, including policy outcomes and unfinished jobs."""

import json

import pytest

from experiments.rig_web_app.storage import ConsoleDB
from experiments.rig_web_app.workspace_import import publish_hosted_program


@pytest.fixture
def retained(tmp_path):
    db = ConsoleDB(tmp_path / "console.db")
    campaign = db.create_workspace("API campaign", "api")
    out = tmp_path / "outputs"
    out.mkdir()
    choices = [dict(input_identity_sha256=str(i), modality="text", framework="replay", corpus="corpus") for i in range(4)]
    requests = {str(i): dict(call_id=f"call-{i}", request_sha256=f"request-{i}", max_output_tokens=4096) for i in range(4)}
    program = dict(target="api:model", requests=requests, jobs=[dict(purpose="measured_run",
        input_ids=list(requests), argv=["--out", str(out)])])
    records = []
    for i in range(3):
        attempt = dict(run_id="run", id=str(i), params=dict(retained_origin=dict(selection=choices[i])))
        raw = dict(generation=dict(max_tokens=4096), transport_attempt_count=1,
                   output_truncated=i == 0, finish_reason="length" if i == 0 else "stop")
        if i == 1:
            raw.update(provider_refusal=True, provider_policy_rejection=True)
        if i == 2:
            raw.update(model_stability_status="failed_output")
        response = dict(run_id="run", attempt_id=str(i), target="api:model", raw=raw,
            tokens=None if i == 1 else dict(input=80, output=4096 if i == 0 else 0),
            output_turns=[dict(content="Usable but truncated answer")] if i == 0 else [])
        records.append(dict(attempt=attempt, response=response))
    path = out / "test.responses.checkpoint.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in records))
    plan = dict(planned_calls=[dict(call_id=f"call-{i}", provider="openai", pool="target", bound_microusd=50000) for i in range(4)])
    ledger = dict(attempts={f"call-{i}": {"1": dict(state="unknown", actual_cost_microusd=None)} for i in range(3)})
    args = dict(program=program, selections=choices, budget_plan=plan, ledger=ledger, ledger_path="budget/ledger.json")
    yield db, campaign, args, path, records
    db.close()


def test_full_assignment_denominator_policy_and_truncation_survive_republication(retained):
    db, campaign, args, _, _ = retained
    for _ in range(2):
        assert publish_hosted_program(db, campaign, **args) == dict(assignments=4, responses=3, judgments=0, costs=3)
    total = db.workspace_model_totals(campaign)[0]
    assert tuple(total[key] for key in ("assigned", "usable", "policy", "missing", "pending", "truncated")) == (4, 1, 1, 1, 1, 1)
    assert db.workspace_judging_totals(campaign) == []
    costs = db.workspace_cost_totals(campaign)[0]
    assert costs["http_attempts"] == 3 and costs["unknown_attempts"] == 3 and costs["cost_microusd"] is None
    assert costs["output_tokens"] == 4096 and costs["input_unknown"] == 1


def test_final_files_and_checkpoint_copies_are_one_response(retained):
    db, campaign, args, path, records = retained
    path.with_name("test.responses.jsonl").write_text("".join(json.dumps(r["response"]) + "\n" for r in records))
    path.with_name("test.attempts.jsonl").write_text("".join(json.dumps(r["attempt"]) + "\n" for r in records))
    assert publish_hosted_program(db, campaign, **args)["responses"] == 3
    records[0]["response"]["output_turns"] = [dict(content="changed")]
    path.with_name("test.responses.jsonl").write_text("".join(json.dumps(r["response"]) + "\n" for r in records))
    with pytest.raises(ValueError, match="differs"):
        publish_hosted_program(db, campaign, **args)


def test_live_incomplete_tail_is_not_an_output(retained):
    db, campaign, args, path, _ = retained
    with path.open("a") as stream:
        stream.write('{"response":')
    assert publish_hosted_program(db, campaign, **args)["responses"] == 3


def test_retries_do_not_copy_final_tokens_onto_network_failures(retained):
    db, campaign, args, path, records = retained
    records[0]["response"]["raw"]["transport_attempt_count"] = 2
    path.write_text("".join(json.dumps(row) + "\n" for row in records))
    args["ledger"]["attempts"]["call-0"]["2"] = dict(state="bounded_unknown", actual_cost_microusd=None,
        usage_bound=dict(input_tokens=80, output_tokens=4096, bound_microusd=25000))
    publish_hosted_program(db, campaign, **args)
    costs = db.workspace_cost_totals(campaign)[0]
    assert costs["http_attempts"] == 4 and costs["output_tokens"] == 4096
    assert costs["input_unknown"] == 2


def test_another_response_needs_explicit_recovery_selection(retained):
    db, campaign, args, path, records = retained
    other = json.loads(json.dumps(records[0]))
    other["attempt"]["run_id"] = other["response"]["run_id"] = "recovery"
    with path.open("a") as stream:
        stream.write(json.dumps(other) + "\n")
    with pytest.raises(ValueError, match="explicit recovery"):
        publish_hosted_program(db, campaign, **args)
    assert db.workspace_model_totals(campaign) == []


def test_selection_cannot_invent_a_different_framework(retained):
    db, campaign, args, _, _ = retained
    args["selections"][0]["framework"] = "other"
    with pytest.raises(ValueError, match="metadata differs"):
        publish_hosted_program(db, campaign, **args)
