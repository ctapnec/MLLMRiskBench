from __future__ import annotations

import hashlib
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_campaign_prepare as subject
from test_hosted_retained_execute import _program
from test_retained_input_replay import _fixture
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker


def _save(path: Path, value: object) -> dict:
    path.write_text(json.dumps(value), encoding="utf-8")
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
    }


def _request(tmp_path: Path, monkeypatch, **program_options) -> tuple[dict, Path]:
    program_options.setdefault("scoring_probes", True)
    program, _budget = _program(tmp_path, monkeypatch, **program_options)
    config_path = Path(
        program["jobs"][0]["argv"][
            program["jobs"][0]["argv"].index("--attacker-config") + 1
        ]
    )
    config = json.loads(config_path.read_text(encoding="utf-8"))
    replay_path = Path(config["replay"]["replay_artifact"])
    replay = {
        "path": str(replay_path),
        "sha256": hashlib.sha256(replay_path.read_bytes()).hexdigest(),
        "bytes": replay_path.stat().st_size,
    }
    historical = _save(tmp_path / "historical-result.json", {"fixture": True})
    execution_root = tmp_path / "execution"
    execution_root.mkdir()
    request = {
        "schema": subject.REQUEST_SCHEMA,
        "results_root": str(tmp_path),
        "runner_view": str(tmp_path),
        "rr_analysis_root": str(tmp_path),
        "pricing_as_of": program["pricing_as_of"],
        "sources": {**program["sources"], "historical_result": historical},
        "routes": [{"target": program["target"], "replay_artifacts": [replay]}],
        "runner_common_argv": [],
        "execution_root": str(execution_root),
    }
    return request, execution_root


def test_preparation_creates_funded_disjoint_pilot_and_measured_program_without_generation(
    tmp_path, monkeypatch
):
    request, _execution_root = _request(tmp_path, monkeypatch)
    calls = []
    actual_count = subject.count_request

    def count(target, body, *, allow_network=False):
        calls.append((target.name, allow_network))
        return actual_count(target, body, allow_network=allow_network)

    monkeypatch.setattr(subject, "count_request", count)
    receipt = subject.prepare_campaign(
        request=request,
        request_descriptor={"path": str(tmp_path / "request.json"), "sha256": "a" * 64, "bytes": 1},
        out_root=tmp_path / "prepared",
        allow_network_counts=False,
    )
    assert receipt["status"] == "prepared_no_generation_calls"
    assert receipt["target_calls"] == receipt["judge_calls"] == 0
    assert receipt["generation_http_attempts"] == 0
    assert len(calls) == receipt["programs"][0]["selected_target_calls"] == 2
    assert calls == [(request["routes"][0]["target"], False)] * 2
    saved = json.loads(Path(receipt["programs"][0]["path"]).read_text(encoding="utf-8"))
    assert [job["purpose"] for job in saved["jobs"]] == ["diagnostic_canary", "measured_run"]
    ids = [identity for job in saved["jobs"] for identity in job["input_ids"]]
    assert len(ids) == len(set(ids)) == len(saved["requests"]) == 2
    budget = json.loads((tmp_path / "prepared" / "budget" / "plan.json").read_text())
    assert len(budget["planned_calls"]) == 6


def _distinct_request(tmp_path, monkeypatch, **program_options):
    from experiments import run_matrix
    capture = {}
    request, _ = _request(tmp_path, monkeypatch, extra_points=8, source_capture=capture, **program_options)
    sources = request["sources"]
    budget = json.loads(Path(sources["budget_projection"]["path"]).read_text())
    api = json.loads(Path(sources["api_config"]["path"]).read_text())
    old_replay = json.loads(Path(request["routes"][0]["replay_artifacts"][0]["path"]).read_text())
    predecessor = old_replay["plan"]
    descriptor = _save(tmp_path / "original-plan.json", predecessor)
    cells, inventory = subject.executor._validated_local_cells({})
    normalized, _ = run_matrix._load_api_config(sources["api_config"]["path"], [request["routes"][0]["target"]], sources["api_config"]["sha256"])
    target = run_matrix.build_target(request["routes"][0]["target"], api_config=normalized.get(request["routes"][0]["target"]))
    bindings = {"budget": budget, "budget_descriptor": subject._portable(sources["budget_projection"]),
                "api_config": api, "api_descriptor": subject._portable(sources["api_config"]),
                "media_index": {}, "local_inventory_descriptor": subject._portable(inventory)}
    candidates = subject.inputs.candidates_from_cells(cells)
    builder = subject.inputs.provider_request_builder(target, {})
    plan = subject.inputs.build_distinct_plan(candidates=candidates, predecessor=predecessor,
        predecessor_descriptor=descriptor, source_prefix_cap=len(candidates), call_cap=5,
        request_builder=builder, **bindings)
    replay = subject.inputs.materialize_replay(plan, cells=cells,
        source_corpora={capture["cell"]["run_id"]: capture["points"]}, corpus="retained-corpus",
        request_builder=builder, **bindings)
    request["routes"][0]["replay_artifacts"] = [_save(tmp_path / "distinct-replay.json", replay)]
    old_root = tmp_path / "program-money"
    old_plan = json.loads((old_root / "plan.json").read_text())
    old_ledger = json.loads((old_root / "ledger.json").read_text())
    allocation = {"schema": "ura-hosted-additional-funding/1",
        "previous_budget_plan": {"path": str(old_root / "plan.json"),
            "sha256": hashlib.sha256((old_root / "plan.json").read_bytes()).hexdigest(),
            "bytes": (old_root / "plan.json").stat().st_size},
        "previous_budget_ledger": {"path": str(old_root / "ledger.json"),
            "sha256": hashlib.sha256((old_root / "ledger.json").read_bytes()).hexdigest(),
            "bytes": (old_root / "ledger.json").stat().st_size},
        "balances_microusd": dict(old_plan["provider_budgets_microusd"]),
        "known_new_charges_microusd": dict.fromkeys(old_plan["provider_budgets_microusd"], 0),
        "unposted_margin_microusd": dict.fromkeys(old_plan["provider_budgets_microusd"], 100000),
        "minimum_reserves_microusd": {key: value // 5 for key, value in old_plan["provider_budgets_microusd"].items()},
        "provider_budgets_microusd": {key: value - 1000000 for key, value in old_plan["provider_budgets_microusd"].items()},
        "protected_haiku_microusd": 1000000,
        "judging_inventory": _save(tmp_path / "local-judges.json", {"unjudged_rows": [
            {"retained_row_sha256": "e" * 64}, {"retained_row_sha256": "f" * 64}]}),
    }
    sources["additional_funding"] = _save(tmp_path / "funding.json", allocation)
    request.update(schema=subject.DISTINCT_INPUT_REQUEST_SCHEMA, input_budget_policy=subject.executor.COUNTED_INPUT_POLICY)
    return request, old_plan, old_ledger


def test_distinct_preparation_funds_all_local_answers_and_preserves_old_accounting(tmp_path, monkeypatch):
    request, old_plan, old_ledger = _distinct_request(tmp_path, monkeypatch)
    old_bytes = {name: (tmp_path / "program-money" / name).read_bytes() for name in ["plan.json", "ledger.json"]}
    receipt = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "prepared",
                                       allow_network_counts=False)
    program = json.loads(Path(receipt["programs"][0]["path"]).read_text())
    assert program["schema"] == subject.executor.DISTINCT_INPUT_SCHEMA
    assert receipt["target_calls"] == receipt["judge_calls"] == 0
    assert all(set(row["judge_call_ids"]) == {"hosted"} for row in program["requests"].values())
    budget = subject.AttemptBudget(tmp_path / "prepared/budget", receipt["budget"]["sha256"])
    assert budget.call("judge-local-" + "e" * 64)["pool"] == "judge"
    assert budget.call("judge-local-" + "f" * 64)["pool"] == "judge"
    assert len(subject.executor._validated_jobs(program, budget)) >= 2
    assert all((tmp_path / "program-money" / name).read_bytes() == value for name, value in old_bytes.items())
    assert not old_ledger["attempts"] and old_plan["provider_budgets_microusd"]["openai"] == 40000000
    changed = copy.deepcopy(program)
    changed["schema"] = subject.executor.COUNTED_INPUT_SCHEMA
    with pytest.raises(ValueError, match="historical execution"):
        subject.executor._validated_jobs(changed, budget)


def test_preparation_uses_supplied_slots_without_new_allocation_or_ledger_writes(tmp_path, monkeypatch):
    request, _old, _ledger = _distinct_request(tmp_path, monkeypatch)
    first = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "first", allow_network_counts=False)
    budget = subject.AttemptBudget(tmp_path / "first/budget", first["budget"]["sha256"])
    before = {name: (budget.root / name).read_bytes() for name in ["plan.json", "ledger.json"]}
    monkeypatch.setattr(subject, "create_budget", lambda *args, **kwargs: pytest.fail("shared preparation created a second allocation"))
    second = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "second",
                                      allow_network_counts=False, shared_budget=budget)
    assert second["budget"] == first["budget"]
    assert not (tmp_path / "second/budget").exists()
    assert all((budget.root / name).read_bytes() == value for name, value in before.items())
    program = json.loads(Path(second["programs"][0]["path"]).read_text())
    assert subject.executor._validated_jobs(program, budget)


def test_preparation_refuses_shared_slot_that_already_has_a_paid_attempt(tmp_path, monkeypatch):
    request, _old, _ledger = _distinct_request(tmp_path, monkeypatch)
    first = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "first", allow_network_counts=False)
    budget = subject.AttemptBudget(tmp_path / "first/budget", first["budget"]["sha256"])
    program = json.loads(Path(first["programs"][0]["path"]).read_text())
    call_id = next(iter(program["requests"].values()))["call_id"]
    budget.reserve(call_id, 1, provider=program["provider"])
    budget.settle(call_id, 1, None)
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(ValueError, match="exact unstarted shared slots"):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "second",
                                 allow_network_counts=False, shared_budget=budget)
    assert (budget.root / "ledger.json").read_bytes() == before


def test_shared_allocation_mismatch_is_rejected_before_count_endpoints(tmp_path, monkeypatch):
    request, _old, _ledger = _distinct_request(tmp_path, monkeypatch)
    first = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "first", allow_network_counts=False)
    budget = subject.AttemptBudget(tmp_path / "first/budget", first["budget"]["sha256"])
    funding = json.loads(Path(request["sources"]["additional_funding"]["path"]).read_text())
    funding["protected_haiku_microusd"] += 1
    request["sources"]["additional_funding"] = _save(tmp_path / "changed-shared-allocation.json", funding)
    monkeypatch.setattr(subject, "count_request", lambda *args, **kwargs: pytest.fail("counter reached before allocation check"))
    with pytest.raises(ValueError, match="supplied shared budget"):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "second",
                                 allow_network_counts=True, shared_budget=budget)
    assert not (tmp_path / "second").exists()


def test_distinct_funding_does_not_require_new_balance_for_unselected_registry_provider(tmp_path, monkeypatch):
    request, old_plan, _ledger = _distinct_request(tmp_path, monkeypatch)
    funding = json.loads(Path(request["sources"]["additional_funding"]["path"]).read_text())
    configured = {key: {"configured_budget_microusd": amount}
                  for key, amount in old_plan["provider_budgets_microusd"].items()}
    configured["google"] = {"configured_budget_microusd": 25000000}
    old_root = tmp_path / "old-registry-including-google"
    subject.create_budget(old_root,
        provider_budgets_microusd={**old_plan["provider_budgets_microusd"], "google": 25000000},
        planned_calls=old_plan["planned_calls"], protected_haiku_microusd=old_plan["protected_haiku_microusd"])
    for field, name in [("previous_budget_plan", "plan.json"), ("previous_budget_ledger", "ledger.json")]:
        path = old_root / name
        funding[field] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                          "bytes": path.stat().st_size}
    source = _save(tmp_path / "active-provider-funding.json", funding)
    before = (old_root / "ledger.json").read_bytes()
    result = subject.executor._additional_funding(source, configured)
    assert "google" not in result["provider_budgets_microusd"]
    assert "google" not in result["balances_microusd"]
    assert (old_root / "ledger.json").read_bytes() == before
    for field in ["provider_budgets_microusd", "balances_microusd", "known_new_charges_microusd",
                  "minimum_reserves_microusd", "unposted_margin_microusd"]:
        funding[field]["unconfigured"] = funding[field].pop("kimi")
    changed = _save(tmp_path / "unconfigured-provider-funding.json", funding)
    with pytest.raises(ValueError, match="provider inventory"):
        subject.executor._additional_funding(changed, configured)


@pytest.mark.parametrize("change", [None, "new_output", "different_model", "hosted_verdict", "wrong_artifact"])
def test_distinct_already_judged_local_outputs_are_reused_only_by_exact_answer(tmp_path, monkeypatch, change):
    request, old, _ledger = _distinct_request(tmp_path, monkeypatch)
    funding = json.loads(Path(request["sources"]["additional_funding"]["path"]).read_text())
    row = {"retained_row_sha256": "e" * 64, "exact_model": "ollama:local-example",
           "run_id": "local-run", "attempt_id": "local-attempt", "input_identity_sha256": "a" * 64}
    record = {**row, "cohort": "local", "judgment_artifact": _save(tmp_path / "verdict.json",
              {"retained_row_sha256": "f" * 64 if change == "wrong_artifact" else row["retained_row_sha256"]})}
    if change == "new_output":
        row["retained_row_sha256"] = "b" * 64  # Same input, different generated answer.
    elif change == "different_model":
        row["exact_model"] = "google:gemini-example"
    elif change == "hosted_verdict":
        record["cohort"] = "hosted"
    inventory = {"unjudged_rows": [], "all_matching_rows": [row],
                 "reused_judgments": _save(tmp_path / "prior-judgments.json", {"records": [record]})}
    funding["judging_inventory"] = _save(tmp_path / "matched-local.json", inventory)
    descriptor = _save(tmp_path / "reused-local-funding.json", funding)
    configured = {key: {"configured_budget_microusd": amount}
                  for key, amount in old["provider_budgets_microusd"].items()}
    if change:
        with pytest.raises(ValueError, match="different output|exact selected model output"):
            subject.executor._additional_funding(descriptor, configured)
    else:
        assert subject.executor._additional_funding(descriptor, configured) == funding
        request["sources"]["additional_funding"] = descriptor
        receipt = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "prepared",
                                           allow_network_counts=False)
        budget = subject.AttemptBudget(tmp_path / "prepared/budget", receipt["budget"]["sha256"])
        program = json.loads(Path(receipt["programs"][0]["path"]).read_text())
        assert len(subject.executor._validated_jobs(program, budget)) >= 2
        slots = json.loads((budget.root / "plan.json").read_text())["planned_calls"]
        assert not any(slot["call_id"].startswith("judge-local-") for slot in slots)
        assert sum(slot["call_id"].startswith("judge-hosted-") for slot in slots) == len(program["requests"])


def test_distinct_selected_provider_cannot_be_omitted_before_token_counting(tmp_path, monkeypatch):
    request, _old, _ledger = _distinct_request(tmp_path, monkeypatch)
    funding = json.loads(Path(request["sources"]["additional_funding"]["path"]).read_text())
    for field in ["provider_budgets_microusd", "balances_microusd", "known_new_charges_microusd",
                  "minimum_reserves_microusd", "unposted_margin_microusd"]:
        del funding[field]["openai"]
    request["sources"]["additional_funding"] = _save(tmp_path / "unfunded-selected-provider.json", funding)
    monkeypatch.setattr(subject, "count_request", lambda *a, **k: pytest.fail("counter reached"))
    with pytest.raises(ValueError, match="selected target and judge providers"):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "prepared",
                                 allow_network_counts=True)


@pytest.mark.parametrize("change", ["reserve", "balance", "margin", "old_ledger", "duplicates"])
def test_distinct_funding_refuses_unavailable_money_or_changed_sources_before_counting(tmp_path, monkeypatch, change):
    request, _old, _ledger = _distinct_request(tmp_path, monkeypatch)
    descriptor = request["sources"]["additional_funding"]
    value = json.loads(Path(descriptor["path"]).read_text())
    if change == "reserve":
        value["minimum_reserves_microusd"]["openai"] = 0
    elif change == "balance":
        value["balances_microusd"]["openai"] = 1000000
    elif change == "margin":
        value["unposted_margin_microusd"]["openai"] = 40000000
    elif change == "old_ledger":
        Path(value["previous_budget_ledger"]["path"]).write_text("{}")
    else:
        value["judging_inventory"] = _save(tmp_path / "duplicates.json", {"unjudged_rows": [
            {"retained_row_sha256": "e" * 64}, {"retained_row_sha256": "e" * 64}]})
    request["sources"]["additional_funding"] = _save(tmp_path / "changed-funding.json", value)
    monkeypatch.setattr(subject, "count_request", lambda *a, **k: pytest.fail("counter reached"))
    with pytest.raises(ValueError):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "prepared", allow_network_counts=True)
    assert not (tmp_path / "prepared").exists()


@pytest.mark.parametrize("target_spec", [
    "anthropic-fable:claude-fable-5-1;effort=high;max_tokens=8192",
    "openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns;max_output_tokens=8192",
])
def test_preparation_accepts_inherent_target_without_generic_config(
    tmp_path, monkeypatch, target_spec
):
    from experiments import run_matrix
    from ura.targets.api import AnthropicTarget, OpenAITarget

    request, _execution_root = _request(tmp_path, monkeypatch, target_spec=target_spec)
    api = request["sources"]["api_config"]
    normalized, _artifact = run_matrix._load_api_config(
        api["path"], [target_spec], api["sha256"]
    )
    assert target_spec not in normalized  # The actual loader's fixed-condition contract.
    for cls in (AnthropicTarget, OpenAITarget):
        monkeypatch.setattr(cls, "_get_client", lambda self: pytest.fail("SDK client reached"))
    receipt = subject.prepare_campaign(
        request=request,
        request_descriptor={},
        out_root=tmp_path / "prepared",
        allow_network_counts=False,
    )
    assert receipt["status"] == "prepared_no_generation_calls"
    assert receipt["target_calls"] == receipt["judge_calls"] == 0
    assert receipt["generation_http_attempts"] == 0
    program = json.loads(Path(receipt["programs"][0]["path"]).read_text())
    assert program["target"] == target_spec
    assert program["max_output_tokens"] == 8192
    assert len(program["requests"]) == 2


def test_preparation_rejects_controlled_runner_argument_before_creating_artifacts(
    tmp_path, monkeypatch
):
    request, _execution_root = _request(tmp_path, monkeypatch)
    request["runner_common_argv"] = ["--api", "openai:wrong"]
    out = tmp_path / "prepared"
    with pytest.raises(ValueError, match="cannot override --api"):
        subject.prepare_campaign(
            request=request,
            request_descriptor={},
            out_root=out,
            allow_network_counts=False,
        )
    assert not out.exists()


def test_preparation_blocks_over_ceiling_exact_input_count_before_budget_or_program(
    tmp_path, monkeypatch
):
    request, _execution_root = _request(tmp_path, monkeypatch)
    monkeypatch.setattr(
        subject,
        "count_request",
        lambda target, body, **kwargs: {
            "request_sha256": subject.projection._sha(body),
            "count_request_sha256": "b" * 64,
            "provider": target.provider,
            "requested_spec": target.requested_spec,
            "requested_model": target.model,
            "input_tokens": 4001,
            "method": "provider_exact",
            "method_id": "fixture",
            "count_http_attempts": 1,
            "count_fee_status": "fixture",
        },
    )
    out = tmp_path / "prepared"
    with pytest.raises(ValueError, match="input-token ceiling"):
        subject.prepare_campaign(
            request=request,
            request_descriptor={},
            out_root=out,
            allow_network_counts=True,
        )
    assert not out.exists()


def test_prepared_replay_budget_covers_multiple_retained_turns_per_datapoint(tmp_path):
    from experiments import run_matrix

    points, _cell, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=True)
    argv = subject._job_argv(
        common=[], target="openai:gpt-5.5",
        api_config={"path": "api.json", "sha256": "a" * 64},
        corpus="retained-corpus",
        attacker_config={"path": "attacker.json", "sha256": "b" * 64},
        output=tmp_path / "out", count=len(value["entries"]), pilot=False,
    )
    args = run_matrix.build_parser().parse_args(argv)
    attacker = ReplayAttacker(**config)
    observed = list(attacker.generate(points[0], AttackBudget(
        max_queries=args.max_queries, max_turns=args.max_turns, seed=0,
    )))
    assert len(observed) == args.max_total_target_calls == 2


def test_invalid_local_membership_stops_before_network_count(tmp_path, monkeypatch):
    request, _execution_root = _request(tmp_path, monkeypatch)
    def invalid(*args, **kwargs):
        raise ValueError("changed retained source membership")
    monkeypatch.setattr(subject.inputs, "resolve_inputs", invalid)
    monkeypatch.setattr(subject, "count_request", lambda *args, **kwargs: pytest.fail("network count reached"))
    out = tmp_path / "prepared"
    with pytest.raises(ValueError, match="changed retained source membership"):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=out,
                                 allow_network_counts=True)
    assert not out.exists()


@pytest.mark.parametrize("tokens, fits", [(27116, True), (1000000, False)])
def test_counted_successor_preserves_large_inputs_but_not_above_route_money(
    tmp_path, monkeypatch, tokens, fits
):
    from ura.targets.api import OpenAITarget

    request, _execution_root = _request(tmp_path, monkeypatch)
    request.update(schema=subject.COUNTED_INPUT_REQUEST_SCHEMA,
                   input_budget_policy=subject.executor.COUNTED_INPUT_POLICY)
    client = SimpleNamespace(responses=SimpleNamespace(input_tokens=SimpleNamespace(
        count=lambda **body: SimpleNamespace(object="response.input_tokens", input_tokens=tokens)
    )))
    client.with_options = lambda **options: client
    monkeypatch.setattr(OpenAITarget, "_get_client", lambda self: client)
    out = tmp_path / "prepared"
    if not fits:
        with pytest.raises(ValueError, match="route's funded projection"):
            subject.prepare_campaign(request=request, request_descriptor={}, out_root=out,
                                     allow_network_counts=True)
        assert not out.exists()
        return
    receipt = subject.prepare_campaign(request=request, request_descriptor={}, out_root=out,
                                       allow_network_counts=True)
    program = json.loads(Path(receipt["programs"][0]["path"]).read_text())
    assert program["schema"] == subject.executor.COUNTED_INPUT_SCHEMA
    assert {row["input_tokens"] for row in program["requests"].values()} == {tokens}
    budget = subject.AttemptBudget(out / "budget", receipt["budget"]["sha256"])
    assert len(subject.executor._validated_jobs(program, budget)) == 2
    route = next(row for row in json.loads(Path(request["sources"]["budget_projection"]["path"]).read_text())["routes"]
                 if row["target_spec"] == program["target"])
    changed = dict(program, requests={key: dict(row, bound_microusd=route["maximum_cost_microusd"])
                                    for key, row in program["requests"].items()})
    with pytest.raises(ValueError, match="route's funded projection"):
        subject.executor._validate_input_budget(changed, route)
    program["schema"] = subject.executor.SCHEMA
    program.pop("input_budget_policy")
    with pytest.raises(ValueError, match="input-token ceiling"):
        subject.executor._validated_jobs(program, budget)


def test_counted_input_policy_must_be_explicit_before_counting(tmp_path, monkeypatch):
    request, _execution_root = _request(tmp_path, monkeypatch)
    request["schema"] = subject.COUNTED_INPUT_REQUEST_SCHEMA
    monkeypatch.setattr(subject, "count_request", lambda *a, **k: pytest.fail("counter reached"))
    with pytest.raises(ValueError, match="request fields differ"):
        subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "out",
                                 allow_network_counts=True)


def test_resumed_preparation_reports_zero_new_http_attempts_for_retained_counts(tmp_path, monkeypatch):
    from experiments import run_matrix
    from ura.adapters.replay import retained_dialog
    from ura.targets.api import OpenAITarget

    request, _execution_root = _request(tmp_path, monkeypatch)
    api = request["sources"]["api_config"]
    spec = request["routes"][0]["target"]
    normalized, _artifact = run_matrix._load_api_config(api["path"], [spec], api["sha256"])
    target = run_matrix.build_target(spec, api_config=normalized[spec])
    calls = []
    def count(**body):
        calls.append(body)
        return SimpleNamespace(object="response.input_tokens", input_tokens=731)
    client = SimpleNamespace(responses=SimpleNamespace(input_tokens=SimpleNamespace(count=count)))
    client.with_options = lambda **options: client
    monkeypatch.setattr(OpenAITarget, "_get_client", lambda self: client)
    cache = tmp_path / "counts"
    cache.mkdir()
    route = subject._replay_inventory(request["routes"])[0]
    for replay in route["replays"]:
        for entry in replay["entries"]:
            subject.cached_count_request(target, target.build_request(retained_dialog(entry["rendered_input"]), seed=0),
                                         cache_root=cache, allow_network=True)
    assert len(calls) == 2
    monkeypatch.setattr(OpenAITarget, "_get_client", lambda self: pytest.fail("completed count repeated"))
    receipt = subject.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path / "out",
                                       allow_network_counts=True, count_cache=cache)
    assert receipt["schema"] == subject.CACHED_RECEIPT_SCHEMA
    assert receipt["token_count_http_attempts"] == 0
    assert receipt["referenced_count_http_attempts"] == 2
    assert receipt["count_cache"] == {"cache_hits": 2, "new_receipts": 0, "http_attempts": 0}


def test_shared_image_cluster_is_one_pilot_group_with_all_datapoints_and_variants():
    def row(identity, *, point=None, image=False):
        return {"input_identity_sha256": identity, "corpus": "holisafe_full" if image else "text-arm",
                "source": "holisafe" if image else "text-source",
                "source_cluster_id": "holisafe:image:shared.jpg" if image else identity,
                "datapoint_id": point or identity, "modality": "image" if image else "text",
                "required_modalities": ["text", "image"] if image else ["text"]}

    # A real HoliSafe shared-image cluster has multiple question records and
    # several retained local-model inputs for each, not a singleton image row.
    selected = [row("text-1"), row("text-2"), row("text-3")]
    selected += [row(f"image-{index}", point=f"holisafe:{index % 2}", image=True)
                 for index in range(6)]
    selected.append(row("measured-text"))
    original = json.dumps(selected, sort_keys=True)
    groups = subject._pilot_groups({"selected": selected})
    assert groups == [["text-1"], ["text-2"], ["text-3"],
                      [f"image-{index}" for index in range(6)]]
    assert json.dumps(selected, sort_keys=True) == original
    assert "measured-text" not in {identity for group in groups for identity in group}


def test_preparation_uses_the_grouped_partition_for_config_calls_and_measurement(tmp_path, monkeypatch):
    request, _execution_root = _request(tmp_path, monkeypatch)
    seen = []

    def last_input_pilot(plan, **kwargs):
        group = [plan["selected"][-1]["input_identity_sha256"]]
        seen.append(group)
        return [group]

    monkeypatch.setattr(subject, "_pilot_groups", last_input_pilot)
    receipt = subject.prepare_campaign(request=request, request_descriptor={},
                                       out_root=tmp_path / "grouped", allow_network_counts=False)
    program = json.loads(Path(receipt["programs"][0]["path"]).read_text())
    assert len(seen) == 2  # Before counting and when constructing the jobs.
    assert program["jobs"][0]["input_ids"] == seen[0] == seen[1]
    assert program["jobs"][0]["input_ids"] != program["jobs"][1]["input_ids"]
    assert receipt["programs"][0]["selected_target_calls"] == 2


def test_unrunnable_cluster_partition_stops_before_counting(tmp_path, monkeypatch):
    request, _execution_root = _request(tmp_path, monkeypatch)

    def invalid(plan, **kwargs):
        raise ValueError("cannot partition whole source clusters")

    monkeypatch.setattr(subject, "_pilot_groups", invalid)
    monkeypatch.setattr(subject, "count_request", lambda *a, **k: pytest.fail("count endpoint reached"))
    with pytest.raises(ValueError, match="cannot partition whole source clusters"):
        subject.prepare_campaign(request=request, request_descriptor={},
                                 out_root=tmp_path / "invalid", allow_network_counts=True)
    assert not (tmp_path / "invalid").exists()


def test_single_multirecord_cluster_cannot_be_split_into_pilot_and_measurement():
    selected = [{"input_identity_sha256": str(index), "corpus": "holisafe_full",
                 "source": "holisafe", "source_cluster_id": "shared-image",
                 "datapoint_id": str(index), "modality": "image", "required_modalities": ["image"]}
                for index in range(2)]
    with pytest.raises(ValueError, match="whole source cluster"):
        subject._pilot_groups({"selected": selected})


def test_single_datapoint_request_variants_stay_in_one_funded_pilot_cluster():
    selected = [{"input_identity_sha256": str(index), "corpus": "jailbreakbench_harmful",
                 "source": "jailbreakbench", "source_cluster_id": "jailbreakbench:harmful:1",
                 "datapoint_id": "jailbreakbench:harmful:1", "modality": "text", "required_modalities": ["text"]}
                for index in range(4)]
    selected.append({**selected[0], "input_identity_sha256": "measured", "source_cluster_id": "other",
                     "datapoint_id": "other"})
    assert subject._pilot_groups({"selected": selected}) == [["0", "1", "2", "3"]]
    with pytest.raises(ValueError, match="whole source cluster"):
        subject._pilot_groups({"selected": selected[:-1]})
