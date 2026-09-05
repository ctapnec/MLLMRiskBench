"""Paired judging funds unique retained outputs, never repeated pair edges."""
from __future__ import annotations

import hashlib
import json

import pytest

from experiments import hosted_attempt_budget as money
from experiments import retained_response_judge_execute as executor
from experiments import retained_response_judge_pair as planner
from experiments import retained_response_judge_pair_execute as paired
from test_retained_judge_shared_budget import HookHaiku
from test_retained_response_judge_execute import JUDGE, _audit, _prepared
from test_retained_response_judge_pair import _candidate
from ura.targets import api


@pytest.mark.parametrize("shared", [False, True])
def test_paired_forwarding_is_optional_and_keeps_original_default_call(tmp_path, monkeypatch, shared):
    captured = []
    monkeypatch.setattr(paired, "execute_retained", lambda **kwargs: captured.append(kwargs) or tmp_path)
    budget, requests = object(), {"output": {"call_id": "funded-slot"}}
    args = {key: tmp_path for key in (
        "plan_path", "local_runner_view", "hosted_runner_view", "source_receipt", "api_config", "pricing_config", "out"
    )}
    if shared:
        args.update(shared_budget=budget, shared_requests=requests)
    assert paired.execute(**args) == tmp_path
    assert captured[0]["plan_validator"] is planner.validate_pair_plan
    if shared:
        assert captured[0]["shared_budget"] is budget
        assert captured[0]["shared_requests"] is requests
    else:
        assert "shared_budget" not in captured[0] and "shared_requests" not in captured[0]


def test_shared_local_counterpart_has_one_funded_judgment_across_three_pairs(tmp_path, monkeypatch):
    prepared = _prepared(tmp_path, monkeypatch)
    api_config = json.loads(prepared["api_config"].read_bytes())
    api_config[JUDGE]["max_tokens"] = 512
    prepared["api_config"].write_bytes(executor._canonical(api_config))
    api_sha = hashlib.sha256(prepared["api_config"].read_bytes()).hexdigest()
    local, hosted = [_candidate(0, cohort="local")], [_candidate(i, cohort="hosted", input_index=0) for i in range(3)]
    metadata = {"local": {}, "hosted": {}}
    for cohort, rows in (("local", local), ("hosted", hosted)):
        for index, row in enumerate(rows):
            text = f"{cohort} retained answer {index}"
            row["risk"] = "jailbreak"
            row["prompt_sha256"] = hashlib.sha256(b"one common prompt").hexdigest()
            row["response_sha256"] = hashlib.sha256(text.encode()).hexdigest()
            row["input_identity_sha256"] = planner._sha({key: row[key] for key in planner._MATCH_IDENTITY_FIELDS})
            row["retained_row_sha256"] = planner._sha(row)
            metadata[cohort][row["sample_key"]] = {"prepared_prompt": "one common prompt", "prepared_response": text}
    condition = prepared["plan"]["judge_condition"]
    pricing = {key: condition[key] for key in (
        "pricing_config_sha256", "pricing_as_of", "pricing_effective_date", "pricing_currency",
        "input_microusd_per_token", "output_microusd_per_token"
    )}
    plan = planner.build_pair_plan(local, hosted, local_population_audit=_audit(1), hosted_population_audit=_audit(3),
        source_descriptor=prepared["plan"]["source"], judge_model=JUDGE, api_config_sha256=api_sha,
        pricing_condition=pricing, limit=3, share_local_judgments=True)
    prepared["plan_path"].write_bytes(executor._canonical(plan))
    hosted_view = tmp_path / "hosted"
    hosted_view.mkdir()
    monkeypatch.setattr(paired, "load_pair_candidate_views", lambda *_: ((local, _audit(1)), (hosted, _audit(3)), metadata))
    items = paired._reconcile_pair_selection(prepared["runner_view"], hosted_view, plan, plan["source"])
    config, _ = executor._load_api_config(prepared["api_config"], judge_model=JUDGE, expected_sha256=api_sha)
    call_ids = {row["retained_row_sha256"]: "judge:" + row["retained_row_sha256"] for row, _, _ in items}
    requests = executor.build_shared_request_receipts(items, judge_model=JUDGE, normalized_api=config, call_ids=call_ids)
    slots = [{"call_id": receipt["call_id"], "provider": "anthropic", "pool": "judge",
              "bound_microusd": receipt["input_tokens_estimate"] + receipt["max_output_tokens"] * 5}
             for receipt in requests.values()]
    descriptor = money.create_budget(tmp_path / "funding", provider_budgets_microusd={"anthropic": 90_000_000}, planned_calls=slots)
    budget = money.AttemptBudget(tmp_path / "funding", descriptor["sha256"])
    fake = HookHaiku(config)
    monkeypatch.setattr(api, "_require", lambda *_: pytest.fail("real SDK construction"))
    kwargs = {key: prepared[key] for key in ("plan_path", "source_receipt", "api_config", "pricing_config", "out")}
    kwargs.update(local_runner_view=prepared["runner_view"], hosted_runner_view=hosted_view,
                  shared_budget=budget, shared_requests=requests, judge_factory=lambda *_: fake)
    result = paired.execute(**kwargs)
    assert plan["schema"] == planner.SHARED_SCHEMA
    assert plan["selection"]["selected_pairs"] == 3
    assert len(plan["selected"]) == len(slots) == 4
    assert sum(row["cohort"] == "local" for row in plan["selected"]) == 1
    assert fake.http_calls == fake.calls == 4
    assert json.loads(result.read_bytes())["actual_cost_microusd"] == 640
    assert budget.snapshot()["pools"]["anthropic:judge"]["settled_attempts"] == 4
    assert paired.execute(**kwargs) == result
    assert fake.http_calls == 4
