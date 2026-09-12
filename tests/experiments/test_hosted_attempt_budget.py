from __future__ import annotations

import json
import multiprocessing
import os
import threading
from types import SimpleNamespace

import pytest

from experiments import hosted_attempt_budget as mod


pytestmark = pytest.mark.skipif(os.name != "posix", reason="uses the existing POSIX executor lock")


def slots():
    return [{"call_id": name, "provider": provider, "pool": pool, "bound_microusd": bound}
            for name, provider, pool, bound in (
                ("A", "anthropic", "target", 20), ("B", "anthropic", "target", 20),
                ("J", "anthropic", "judge", 30), ("O", "openai", "target", 10))]


@pytest.fixture
def budget(tmp_path):
    root = tmp_path / "money"
    descriptor = mod.create_budget(root, provider_budgets_microusd={"anthropic": 100, "openai": 100},
                                   planned_calls=slots(), protected_haiku_microusd=33)
    return mod.AttemptBudget(root, descriptor["sha256"])


def reopen(budget):
    return mod.AttemptBudget(budget.root, budget.expected_plan_sha256)


def test_bulk_attempt_counts_use_one_fresh_read_without_changing_ledger(budget, monkeypatch):
    original = budget._load
    reads = []
    def load():
        reads.append(True)
        return original()
    monkeypatch.setattr(budget, "_load", load)
    before = (budget.root / "ledger.json").read_bytes()
    assert budget.reserved_attempt_counts(["A", "B", "J", "O"]) == dict(A=0, B=0, J=0, O=0)
    assert len(reads) == 1
    assert (budget.root / "ledger.json").read_bytes() == before
    budget.reserve("A", 1, provider="anthropic")
    reads.clear()
    assert budget.reserved_attempt_counts(["A", "B"]) == dict(A=1, B=0)
    assert len(reads) == 1
    with pytest.raises(mod.BudgetError, match="outside"):
        budget.reserved_attempt_counts(["unknown"])
    with pytest.raises(mod.BudgetError, match="sequence"):
        budget.reserved_attempt_counts("A")


def queued_budget(tmp_path):
    calls = [{"call_id": f"T{number}", "provider": "anthropic", "pool": "target", "bound_microusd": 20}
             for number in range(10)] + [{"call_id": "J", "provider": "anthropic", "pool": "judge", "bound_microusd": 30}]
    descriptor = mod.create_budget(tmp_path / "continuous", provider_budgets_microusd={"anthropic": 100},
        planned_calls=calls, protected_haiku_microusd=33, reservation_policy="per_attempt")
    return mod.AttemptBudget(tmp_path / "continuous", descriptor["sha256"])


def test_continuous_inventory_does_not_need_financial_batches_or_completed_judging(tmp_path):
    money = queued_budget(tmp_path)
    initial_plan = (money.root / "plan.json").read_bytes()
    assert json.loads(initial_plan)["schema"] == mod.PER_ATTEMPT_PLAN_SCHEMA
    assert money.snapshot()["planned_calls"] == 11
    for number in range(10):
        money = reopen(money)
        money.reserve(f"T{number}", 1, provider="anthropic")
        money.settle(f"T{number}", 1, 1)
    assert (money.root / "plan.json").read_bytes() == initial_plan
    snapshot = money.snapshot()
    assert snapshot["pools"]["anthropic:target"]["settled_cost_microusd"] == 10
    assert snapshot["pools"]["anthropic:judge"]["cap_microusd"] == 33
    assert money.reserved_attempt_count("J") == 0
    money.reserve("J", 1, provider="anthropic")
    money.settle("J", 1, 2)


def test_precalculated_execution_does_not_hold_maximums_or_rewrite_history(tmp_path):
    money = queued_budget(tmp_path)
    money.reserve('T0', 1, provider='anthropic')
    money.settle('T0', 1, None)
    before = {name: (money.root / name).read_bytes() for name in ('plan.json', 'ledger.json')}
    money.use_precalculated_spending()
    assert all((money.root / name).read_bytes() == raw for name, raw in before.items())
    for number in range(1, 10):
        money = reopen(money)
        money.reserve(f'T{number}', 1, provider='anthropic')
        money.settle(f'T{number}', 1, 1)
    pool = money.snapshot()['pools']['anthropic:target']
    assert pool['tracked_spend_microusd'] == 9
    assert pool['unknown_usage_attempts'] == 1
    assert pool['maximum_exposure_is_reserved'] is False
    assert json.loads((money.root / 'ledger.json').read_text())['attempts']['T0']['1']['actual_cost_microusd'] is None
    assert money.reserved_attempt_count('J') == 0
    with pytest.raises(mod.BudgetError, match='duplicated'):
        money.reserve('T1', 1, provider='anthropic')


def test_precalculated_inflight_maxima_do_not_block_dispatch_but_reported_cap_does(tmp_path):
    money = queued_budget(tmp_path)
    money.use_precalculated_spending()
    for number in range(4):
        money.reserve(f'T{number}', 1, provider='anthropic')
    # Four maxima exceed the target pool; no money is being reserved.
    assert reopen(money).snapshot()['pools']['anthropic:target']['unresolved_attempts'] == 4
    money.settle('T0', 1, 20)
    money.settle('T1', 1, 20)
    money.settle('T2', 1, 7)
    before = (money.root / 'ledger.json').read_bytes()
    with pytest.raises(mod.BudgetCapacityUnavailable, match='reported spending'):
        money.reserve('T4', 1, provider='anthropic')
    assert (money.root / 'ledger.json').read_bytes() == before
    # Finishing an already-issued call records its charge, including overshoot.
    money.settle('T3', 1, 3)
    assert money.snapshot()['pools']['anthropic:target']['tracked_spend_over_cap_microusd'] == 3
    money.reserve('J', 1, provider='anthropic')


def test_precalculated_policy_binding_and_cli_preserve_plan(tmp_path, capsys):
    money = queued_budget(tmp_path)
    before = (money.root / 'plan.json').read_bytes()
    assert mod.main(['--budget-root', str(money.root), '--plan-sha256', money.expected_plan_sha256,
                     '--spending-policy', 'precalculated']) == 0
    assert json.loads(capsys.readouterr().out)['spending_policy'] == 'precalculated'
    assert (money.root / 'plan.json').read_bytes() == before
    path = money.root / 'spending-policy.json'
    path.write_text(json.dumps({'budget_plan_sha256': '0' * 64, 'mode': 'precalculated'}))
    with pytest.raises(mod.BudgetError, match='policy'):
        reopen(money)


def test_precalculated_provider_exhaustion_does_not_stop_independent_target(budget):
    budget.use_precalculated_spending()
    budget.reserve('A', 1, provider='anthropic')
    budget.settle('A', 1, None)
    budget.stop_provider_funding('anthropic', 'A')
    budget.reserve('O', 1, provider='openai')
    with pytest.raises(mod.BudgetError, match='funding'):
        budget.reserve('B', 1, provider='anthropic')


def test_immutable_slots_reuse_plan_but_reservations_read_live_ledger(tmp_path, monkeypatch):
    from ura import validation_cache

    now = validation_cache.time.time_ns()
    monkeypatch.setattr(validation_cache.time, "time_ns", lambda: now + 2_000_000_000)
    money = queued_budget(tmp_path)
    reads = []
    original = mod._read_regular
    def counted(path, **kwargs):
        reads.append(path.name)
        return original(path, **kwargs)
    monkeypatch.setattr(mod, "_read_regular", counted)
    for index in range(10):
        slot = money.call("T" + str(index))
        slot["bound_microusd"] = 0
    assert money.call("T0")["bound_microusd"] == 20
    assert reads == []
    money.reserve("T0", 1, provider="anthropic")
    assert "ledger.json" in reads and "plan.json" not in reads
    money.settle("T0", 1, None)
    money.reserve("T1", 1, provider="anthropic")
    with pytest.raises(mod.BudgetError):
        money.reserve("T2", 1, provider="anthropic")
    path = money.root / "plan.json"
    path.write_text(path.read_text() + " ")
    with pytest.raises(mod.BudgetError, match="plan bytes changed"):
        money.call("T0")


def test_continuous_first_attempt_is_reserved_before_spending_and_unknown_stays_held(tmp_path):
    money = queued_budget(tmp_path)
    money.reserve("T0", 1, provider="anthropic")
    money.settle("T0", 1, None)
    money.reserve("T1", 1, provider="anthropic")
    before = (money.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError):
        money.reserve("T2", 1, provider="anthropic")
    assert (money.root / "ledger.json").read_bytes() == before
    assert money.snapshot()["pools"]["anthropic:target"]["reserved_exposure_microusd"] == 40
    money.settle("T1", 1, 1)
    money.reserve("T2", 1, provider="anthropic")
    assert money.snapshot()["pools"]["anthropic:target"]["liability_microusd"] == 41


def test_continuous_forecast_includes_unstarted_first_attempts(tmp_path):
    money = queued_budget(tmp_path)
    forecast = money.continuation_liability([])
    assert forecast["extra_transport_reserve_microusd"]["anthropic:target"] == 10 * 4 * 20
    assert forecast["extra_transport_reserve_microusd"]["anthropic:judge"] == 4 * 30
    assert forecast["continuation_liability_microusd"]["anthropic:target"] == 47


def test_upfront_budget_contract_is_unchanged_and_still_checks_all_first_attempts(tmp_path):
    plan = mod._plan({"anthropic": 100, "openai": 100}, slots(), 33)
    assert plan["schema"] == mod.PLAN_SCHEMA
    assert "reservation_policy" not in plan
    with pytest.raises(mod.BudgetError, match="first attempts"):
        mod.create_budget(tmp_path / "too-much", provider_budgets_microusd={"anthropic": 100},
            planned_calls=[{"call_id": f"T{n}", "provider": "anthropic", "pool": "target", "bound_microusd": 20}
                           for n in range(10)], protected_haiku_microusd=33)


def _reserve_continuous_slot(root, digest, name, barrier, results):
    money = mod.AttemptBudget(root, digest)
    barrier.wait(timeout=15)
    try:
        money.reserve(name, 1, provider="anthropic")
    except mod.BudgetError:
        results.put("denied")
    else:
        results.put("reserved")


def test_continuous_concurrent_first_attempts_cannot_overbook_the_pool(tmp_path):
    money = queued_budget(tmp_path)
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(3), context.Queue()
    processes = [context.Process(target=_reserve_continuous_slot,
        args=(money.root, money.expected_plan_sha256, f"T{n}", barrier, results)) for n in range(3)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    assert sorted(results.get(timeout=5) for _ in processes) == ["denied", "reserved", "reserved"]
    assert reopen(money).snapshot()["pools"]["anthropic:target"]["liability_microusd"] == 40


def test_continuous_mode_does_not_reset_attempt_count(tmp_path):
    money = queued_budget(tmp_path)
    for number in range(1, 5):
        money.reserve("T0", number, provider="anthropic")
        money.settle("T0", number, 0)
    with pytest.raises(mod.BudgetError, match="four-attempt cap"):
        reopen(money).reserve("T0", 5, provider="anthropic")


def usage_bound(**changes):
    return {"input_tokens": 2, "output_tokens": 1, "input_unit_price": "1.5", "output_unit_price": "2",
            "response_sha256": "a" * 64, "pricing_sha256": "b" * 64, "bound_microusd": 5, **changes}


def finish_targets(budget):
    for call, provider in (("A", "anthropic"), ("B", "anthropic"), ("O", "openai")):
        budget.reserve(call, 1, provider=provider)
        budget.settle(call, 1, None if call == "O" else 2)


def test_close_releases_only_unissued_judging_not_unknown_charges(budget):
    finish_targets(budget)
    before = {name: (budget.root / name).read_bytes() for name in ("plan.json", "ledger.json")}
    closed = budget.close(reason="All eligible retained outputs have completed judgments")
    assert closed["state"] == "closed"
    assert closed["pools"]["anthropic:judge"]["released_unstarted_commitments_microusd"] == 30
    assert closed["pools"]["anthropic:judge"]["liability_microusd"] == 0
    assert closed["pools"]["openai:target"]["reserved_exposure_microusd"] == 10
    assert closed["pools"]["openai:target"]["unknown_usage_attempts"] == 1
    assert closed["pools"]["anthropic:target"]["settled_cost_microusd"] == 4
    assert reopen(budget).snapshot() == closed
    assert budget.close(reason="Repeated close") == closed
    assert all((budget.root / name).read_bytes() == value for name, value in before.items())
    for call, provider, number in (("J", "anthropic", 1), ("O", "openai", 2)):
        with pytest.raises(mod.BudgetError, match="circuit is open"):
            reopen(budget).reserve(call, number, provider=provider)


def test_close_preserves_real_judgments_and_accepts_later_usage_settlement(budget):
    finish_targets(budget)
    budget.reserve("J", 1, provider="anthropic")
    budget.settle("J", 1, 3)
    closed = budget.close(reason="Finished selected outputs")
    assert closed["pools"]["anthropic:judge"]["released_unstarted_commitments_microusd"] == 0
    assert closed["pools"]["anthropic:judge"]["settled_cost_microusd"] == 3
    budget.bound_reported_usage("O", 1, usage_bound())
    assert budget.snapshot()["pools"]["openai:target"]["reserved_exposure_microusd"] == 5
    budget.settle("O", 1, 4)
    assert budget.snapshot()["state"] == "closed"
    assert budget.snapshot()["pools"]["openai:target"]["settled_cost_microusd"] == 4


@pytest.mark.parametrize("state", ["unstarted_target", "in_flight", "existing_stop"])
def test_close_refuses_pending_or_stopped_work(budget, state):
    if state == "in_flight":
        budget.reserve("A", 1, provider="anthropic")
    elif state == "existing_stop":
        finish_targets(budget)
        mod._write_new(budget.root / "paid-circuit.json", {"category": "missing_target_output"})
    with pytest.raises(mod.BudgetError):
        budget.close(reason="Cannot retire unfinished work")


def test_close_rejects_a_changed_cancellation_inventory(budget):
    finish_targets(budget)
    budget.close(reason="Finished")
    path = budget.root / "paid-circuit.json"
    closure = json.loads(path.read_text())
    closure["unstarted_judge_call_ids"] = []
    mod._write_atomic(path, closure)
    with pytest.raises(mod.BudgetError, match="closure differs"):
        reopen(budget)


def test_reported_token_bound_remains_unknown_not_an_invented_exact_bill(budget):
    budget.reserve("O", 1, provider="openai")
    budget.settle("O", 1, None)
    before = budget.snapshot()["pools"]["openai:target"]
    budget.bound_reported_usage("O", 1, usage_bound())
    current = reopen(budget)
    after = current.snapshot()["pools"]["openai:target"]
    assert before["reserved_exposure_microusd"] == 10
    assert after["reserved_exposure_microusd"] == 5
    assert after["settled_cost_microusd"] == after["settled_attempts"] == 0
    assert after["unknown_usage_attempts"] == after["bounded_usage_attempts"] == 1
    saved = (budget.root / "ledger.json").read_bytes()
    current.bound_reported_usage("O", 1, usage_bound())
    current.settle("O", 1, None)
    assert (budget.root / "ledger.json").read_bytes() == saved
    current.reserve("O", 2, provider="openai")
    assert current.snapshot()["pools"]["openai:target"]["reserved_exposure_microusd"] == 15


def test_precalculated_usage_above_forecast_is_counted_and_still_stops_at_pool_cap(budget):
    budget.use_precalculated_spending()
    original_plan = (budget.root / "plan.json").read_bytes()
    budget.reserve("O", 1, provider="openai")
    budget.settle("O", 1, None)
    evidence = usage_bound(input_tokens=20, bound_microusd=32)
    budget.bound_reported_usage("O", 1, evidence)
    current = reopen(budget)
    pool = current.snapshot()["pools"]["openai:target"]
    assert pool["tracked_spend_microusd"] == 32
    assert pool["settled_cost_microusd"] == 0
    assert pool["unknown_usage_attempts"] == 1
    assert current.attempt_bound("O") == 32
    assert (current.root / "plan.json").read_bytes() == original_plan
    saved = (current.root / "ledger.json").read_bytes()
    current.bound_reported_usage("O", 1, evidence)
    assert (current.root / "ledger.json").read_bytes() == saved
    current.reserve("O", 2, provider="openai")
    current.settle("O", 2, None)
    current.bound_reported_usage("O", 2, usage_bound(input_tokens=40, bound_microusd=62))
    assert current.snapshot()["pools"]["openai:target"]["tracked_spend_microusd"] == 94
    with pytest.raises(mod.BudgetCapacityUnavailable, match="reported spending"):
        reopen(current).reserve("O", 3, provider="openai")
    current.reserve("A", 1, provider="anthropic")


@pytest.mark.parametrize("evidence", [usage_bound(bound_microusd=4), usage_bound(input_tokens=True),
    usage_bound(input_unit_price="NaN"), usage_bound(output_unit_price="-1"),
    usage_bound(response_sha256="bad"), usage_bound(input_tokens=20, bound_microusd=32)])
def test_reported_usage_bound_rejects_invalid_or_unfunded_evidence(budget, evidence):
    budget.reserve("O", 1, provider="openai")
    budget.settle("O", 1, None)
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError):
        budget.bound_reported_usage("O", 1, evidence)
    assert (budget.root / "ledger.json").read_bytes() == before


def test_reported_bound_never_releases_unstarted_or_in_flight_requests(budget):
    with pytest.raises(mod.BudgetError, match="completed unknown-cost"):
        budget.bound_reported_usage("O", 1, usage_bound())
    budget.reserve("O", 1, provider="openai")
    with pytest.raises(mod.BudgetError, match="completed unknown-cost"):
        budget.bound_reported_usage("O", 1, usage_bound())
    budget.settle("O", 1, None)
    budget.bound_reported_usage("O", 1, usage_bound())
    with pytest.raises(mod.BudgetError, match="conflicting reported usage"):
        budget.bound_reported_usage("O", 1, usage_bound(response_sha256="c" * 64))
    current = json.loads((budget.root / "ledger.json").read_text())
    current["schema"] = mod.ADJUSTED_LEDGER_SCHEMA
    (budget.root / "ledger.json").write_text(json.dumps(current))
    with pytest.raises(mod.BudgetError):
        reopen(budget)


def test_bound_survives_allowance_increase_and_later_exact_settlement(budget):
    import hashlib
    budget.reserve("O", 1, provider="openai")
    budget.settle("O", 1, None)
    budget.bound_reported_usage("O", 1, usage_bound())
    budget.increase_allowances({"O": 12}, reason="test explicit allocation", expected_ledger_sha256=
        hashlib.sha256((budget.root / "ledger.json").read_bytes()).hexdigest())
    assert reopen(budget).snapshot()["pools"]["openai:target"]["reserved_exposure_microusd"] == 5
    budget.settle("O", 1, 4)
    pool = reopen(budget).snapshot()["pools"]["openai:target"]
    assert pool["settled_cost_microusd"] == 4 and pool["reserved_exposure_microusd"] == 0


def test_exhausted_target_provider_preserves_hold_but_other_funded_provider_continues(budget):
    budget.reserve("O", 1, provider="openai")
    budget.settle("O", 1, None)
    before = (budget.root / "ledger.json").read_bytes()
    budget.stop_provider_funding("openai", "O")
    assert (budget.root / "ledger.json").read_bytes() == before
    current = reopen(budget)
    assert current.provider_funding_stops()[0]["provider"] == "openai"
    with pytest.raises(mod.BudgetError, match="funding is unavailable"):
        current.reserve("O", 2, provider="openai")
    current.reserve("A", 1, provider="anthropic")
    assert current.snapshot()["pools"]["openai:target"]["reserved_exposure_microusd"] == 10


def test_exhausted_haiku_account_also_stops_targets_owing_haiku_judgments(budget):
    budget.reserve("A", 1, provider="anthropic")
    budget.settle("A", 1, None)
    budget.stop_provider_funding("anthropic", "A")
    for call, provider in [("B", "anthropic"), ("J", "anthropic"), ("O", "openai")]:
        with pytest.raises(mod.BudgetError, match="funding is unavailable"):
            reopen(budget).reserve(call, 1, provider=provider)
    assert budget.reserved_attempt_count("O") == 0


def test_provider_stop_cannot_name_an_unstarted_or_other_accounts_call(budget):
    with pytest.raises(mod.BudgetError, match="actual admitted attempt"):
        budget.stop_provider_funding("openai", "O")
    budget.reserve("O", 1, provider="openai")
    with pytest.raises(mod.BudgetError, match="actual admitted attempt"):
        budget.stop_provider_funding("anthropic", "O")


def _hold_budget_lock(root, ready, release):
    with mod._exclusive_lock(root):
        ready.set()
        if not release.wait(10):
            raise TimeoutError("test did not release the shared budget lock")


@pytest.mark.parametrize("operation", ["snapshot", "call", "liability", "count", "reserve", "settle",
                                       "target_circuit", "judge_circuit"])
def test_short_budget_contention_waits_instead_of_aborting_unrelated_work(budget, operation):
    from experiments import hosted_retained_execute, retained_response_judge_execute

    if operation == "settle":
        budget.reserve("A", 1, provider="anthropic")
    before = (budget.root / "ledger.json").read_bytes()
    actions = {
        "snapshot": budget.snapshot,
        "call": lambda: budget.call("A"),
        "liability": lambda: budget.liability(["A"]),
        "count": lambda: budget.reserved_attempt_count("A"),
        "reserve": lambda: budget.reserve("A", 1, provider="anthropic"),
        "settle": lambda: budget.settle("A", 1, 7),
        "target_circuit": lambda: hosted_retained_execute._Admission._circuit(
            SimpleNamespace(budget=budget, program={"target": "anthropic:haiku", "provider": "anthropic"}),
            "missing_target_output", "A"),
        "judge_circuit": lambda: retained_response_judge_execute._open_shared_circuit(
            budget, {"retained_row_sha256": "0" * 64}, ValueError("missing judge output")),
    }
    context = multiprocessing.get_context("spawn")
    ready, release = context.Event(), context.Event()
    holder = context.Process(target=_hold_budget_lock, args=(budget.root, ready, release))
    timer = threading.Timer(0.1, release.set)
    holder.start()
    try:
        assert ready.wait(10)
        timer.start()
        actions[operation]()
    finally:
        release.set()
        timer.cancel()
        holder.join(timeout=10)
        assert holder.exitcode == 0
    if operation in {"snapshot", "call", "liability", "count", "target_circuit", "judge_circuit"}:
        assert (budget.root / "ledger.json").read_bytes() == before
    if operation == "judge_circuit":
        with pytest.raises(mod.BudgetError, match="circuit is open"):
            budget.reserve("A", 1, provider="anthropic")
    elif operation == "target_circuit":
        pause = hosted_retained_execute.target_pause(budget, "anthropic:haiku")
        assert pause["category"] == "missing_target_output" and pause["call_id"] == "A"
        assert hosted_retained_execute.target_pause(budget, "openai:model") is None
        budget.reserve("O", 1, provider="openai")
    elif operation == "reserve":
        assert budget.reserved_attempt_count("A") == 1
    elif operation == "settle":
        assert budget.snapshot()["pools"]["anthropic:target"]["settled_cost_microusd"] == 7


def test_budget_lock_wait_is_bounded_and_never_modifies_money_on_timeout(budget, monkeypatch):
    monkeypatch.setattr(mod, "_LOCK_WAIT_SECONDS", 0.02)
    before = (budget.root / "ledger.json").read_bytes()
    with mod._exclusive_lock(budget.root):
        with pytest.raises(mod.BudgetError, match="lock wait expired"):
            budget.reserve("A", 1, provider="anthropic")
    assert (budget.root / "ledger.json").read_bytes() == before


def test_transaction_body_error_is_not_retried_as_lock_contention(budget, monkeypatch):
    calls = []
    def broken_read(*args, **kwargs):
        calls.append(args)
        raise RuntimeError("transaction body failed") from BlockingIOError("not lock acquisition")
    monkeypatch.setattr(mod, "_read_regular", broken_read)
    monkeypatch.setattr(mod.time, "sleep", lambda _: pytest.fail("transaction body was retried"))
    with pytest.raises(RuntimeError, match="transaction body failed"):
        budget.snapshot()
    assert len(calls) == 1


def test_initial_commitments_protect_first_calls_and_separate_judge_pool(budget):
    before = (budget.root / "ledger.json").read_bytes()
    snapshot = budget.snapshot()
    assert snapshot["provider_ceilings_microusd"] == {"anthropic": 80, "openai": 80}
    target, judge = snapshot["pools"]["anthropic:target"], snapshot["pools"]["anthropic:judge"]
    assert target["cap_microusd"] == 47 and judge["cap_microusd"] == 33
    assert target["unstarted_first_commitments_microusd"] == 40
    assert target["available_retry_margin_microusd"] == 7
    assert judge["unstarted_first_commitments_microusd"] == 30
    assert target["reserved_exposure_microusd"] == target["settled_cost_microusd"] == 0
    assert (budget.root / "ledger.json").read_bytes() == before
    descriptor = budget.call("A")
    descriptor["provider"] = "changed"
    assert budget.call("A")["provider"] == "anthropic"


def test_default_haiku_allocation_is_33_dollars_not_33_microdollars(tmp_path):
    root = tmp_path / "money"
    descriptor = mod.create_budget(root, provider_budgets_microusd={"anthropic": 90_000_000},
        planned_calls=[{"call_id": "one", "provider": "anthropic", "pool": "target", "bound_microusd": 1}])
    pools = mod.AttemptBudget(root, descriptor["sha256"]).snapshot()["pools"]
    assert pools["anthropic:judge"]["cap_microusd"] == 33_000_000
    assert pools["anthropic:target"]["cap_microusd"] == 39_000_000


def test_unknown_cost_retry_cannot_spend_other_first_calls_or_protected_pool(budget):
    budget.reserve("A", 1, provider="anthropic")
    budget.settle("A", 1, None)
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError, match="planned first attempts or another pool"):
        budget.reserve("A", 2, provider="anthropic")
    assert (budget.root / "ledger.json").read_bytes() == before
    budget.reserve("B", 1, provider="anthropic")
    budget.reserve("J", 1, provider="anthropic")
    snapshot = budget.snapshot()
    assert snapshot["pools"]["anthropic:target"]["liability_microusd"] == 40
    assert snapshot["pools"]["anthropic:judge"]["liability_microusd"] == 30
    assert snapshot["pools"]["anthropic:target"]["unknown_usage_attempts"] == 1


def test_reconciled_savings_fund_retry_without_unfunding_future_first_attempts(budget):
    budget.reserve("A", 1, provider="anthropic")
    budget.settle("A", 1, None)
    budget.settle("A", 1, 3)
    assert budget.snapshot()["pools"]["anthropic:target"]["available_retry_margin_microusd"] == 24
    budget.reserve("A", 2, provider="anthropic")
    snapshot = budget.snapshot()["pools"]["anthropic:target"]
    assert snapshot["liability_microusd"] == 43 and snapshot["unstarted_first_commitments_microusd"] == 20
    budget.reserve("B", 1, provider="anthropic")
    assert budget.snapshot()["pools"]["anthropic:target"]["liability_microusd"] == 43


def test_crash_after_reservation_reopens_full_exposure_without_automatic_reissue(budget):
    budget.reserve("A", 1, provider="anthropic")
    resumed = reopen(budget)
    assert resumed.snapshot()["pools"]["anthropic:target"]["unresolved_attempts"] == 1
    for number in (1, 2):
        with pytest.raises(mod.BudgetError, match="duplicated|unresolved"):
            resumed.reserve("A", number, provider="anthropic")
    resumed.settle("A", 1, None)
    with pytest.raises(mod.BudgetError, match="duplicated"):
        resumed.reserve("A", 1, provider="anthropic")
    assert resumed.snapshot()["pools"]["anthropic:target"]["reserved_exposure_microusd"] == 20


@pytest.mark.parametrize("actual", [None, 0, 7])
def test_settlement_is_idempotent_and_cannot_rewrite_known_charge(budget, monkeypatch, actual):
    budget.reserve("A", 1, provider="anthropic")
    expected = budget.settle("A", 1, actual)
    before = (budget.root / "ledger.json").read_bytes()
    monkeypatch.setattr(mod, "_write_atomic", lambda *a: pytest.fail("idempotent settlement rewrote ledger"))
    assert budget.settle("A", 1, actual) == expected
    assert (budget.root / "ledger.json").read_bytes() == before
    if actual is not None:
        with pytest.raises(mod.BudgetError, match="conflicting settlement"):
            budget.settle("A", 1, actual + 1)


def test_known_above_bound_usage_is_durable_and_blocks_every_provider(budget):
    budget.reserve("A", 1, provider="anthropic")
    with pytest.raises(mod.BudgetError, match="durably retained"):
        budget.settle("A", 1, 100)
    resumed = reopen(budget)
    snapshot = resumed.snapshot()
    assert snapshot["state"] == "blocked_known_bound_exceeded"
    assert snapshot["pools"]["anthropic:target"]["settled_cost_microusd"] == 100
    assert snapshot["pools"]["anthropic:target"]["liability_microusd"] == 120
    assert snapshot["pools"]["anthropic:target"]["over_cap_microusd"] == 73
    assert snapshot["bound_exceeded_attempts"] == [{"call_id": "A", "attempt_number": 1,
                                                   "bound_microusd": 20, "actual_cost_microusd": 100}]
    with pytest.raises(mod.BudgetError, match="blocks all new spending"):
        resumed.reserve("O", 1, provider="openai")
    with pytest.raises(mod.BudgetError, match="durably retained"):
        resumed.settle("A", 1, 100)


def ledger_sha(budget):
    import hashlib
    return hashlib.sha256((budget.root / "ledger.json").read_bytes()).hexdigest()


def test_explicit_contingency_preserves_plan_charge_and_original_overrun(budget):
    original_plan = (budget.root / "plan.json").read_bytes()
    original_slot = budget.call("A")
    budget.reserve("A", 1, provider="anthropic")
    with pytest.raises(mod.BudgetError, match="durably retained"):
        budget.settle("A", 1, 23)
    paid = json.loads((budget.root / "ledger.json").read_text())["attempts"]
    result = budget.increase_allowances({"A": 25}, reason="Reviewed provider aggregate billing",
                                       expected_ledger_sha256=ledger_sha(budget))
    assert result["state"] == "active"
    assert result["bound_exceeded_attempts"][0]["actual_cost_microusd"] == 23
    assert result["unfunded_bound_exceeded_attempts"] == []
    assert result["pools"]["anthropic:target"]["liability_microusd"] == 43
    assert json.loads((budget.root / "ledger.json").read_text())["attempts"] == paid
    assert (budget.root / "plan.json").read_bytes() == original_plan
    assert reopen(budget).call("A") == original_slot
    assert reopen(budget).attempt_bound("A") == 25
    with pytest.raises(mod.BudgetError, match="conflicting settlement"):
        budget.settle("A", 1, 20)
    reopen(budget).reserve("O", 1, provider="openai")


def test_future_contingency_is_committed_and_held_for_each_unknown_attempt(budget):
    budget.increase_allowances({"O": 25}, reason="Prospective billing contingency",
                              expected_ledger_sha256=ledger_sha(budget))
    assert budget.snapshot()["pools"]["openai:target"]["unstarted_first_commitments_microusd"] == 25
    assert budget.liability(["O"]) == 25
    for number in range(1, 4):
        assert budget.reserve("O", number, provider="openai")["bound_microusd"] == 25
        budget.settle("O", number, None)
    assert budget.liability(["O"]) == 75
    with pytest.raises(mod.BudgetError, match="planned first attempts"):
        budget.reserve("O", 4, provider="openai")


@pytest.mark.parametrize("bounds,reason", [({"A": 28}, "over pool"), ({"A": 20}, "not increasing"),
    ({"A": 19}, "decrease"), ({"absent": 1}, "outside plan"), ({"A": True}, "invalid"),
    ({"A": 21}, ""), ({}, "empty")])
def test_invalid_contingency_does_not_change_any_durable_file(budget, bounds, reason):
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError):
        budget.increase_allowances(bounds, reason=reason, expected_ledger_sha256=ledger_sha(budget))
    assert (budget.root / "ledger.json").read_bytes() == before


def test_stale_review_and_pool_overage_cannot_be_waived(budget):
    digest = ledger_sha(budget)
    budget.reserve("A", 1, provider="anthropic")
    with pytest.raises(mod.BudgetError, match="stale"):
        budget.increase_allowances({"A": 21}, reason="stale review", expected_ledger_sha256=digest)
    with pytest.raises(mod.BudgetError, match="durably retained"):
        budget.settle("A", 1, 100)
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError, match="dedicated pool cap"):
        budget.increase_allowances({"A": 100}, reason="cannot fund this", expected_ledger_sha256=ledger_sha(budget))
    assert (budget.root / "ledger.json").read_bytes() == before


def test_new_overrun_and_paid_circuit_still_stop_with_contingency(budget):
    budget.increase_allowances({"O": 25}, reason="reviewed estimate", expected_ledger_sha256=ledger_sha(budget))
    budget.reserve("O", 1, provider="openai")
    with pytest.raises(mod.BudgetError, match="durably retained"):
        budget.settle("O", 1, 26)
    with pytest.raises(mod.BudgetError, match="blocks all new spending"):
        budget.reserve("A", 1, provider="anthropic")
    budget.increase_allowances({"O": 30}, reason="second reviewed allocation", expected_ledger_sha256=ledger_sha(budget))
    assert len(reopen(budget).snapshot()["allowance_adjustments"]) == 2
    (budget.root / "paid-circuit.json").write_text("{}")
    with pytest.raises(mod.BudgetError, match="circuit is open"):
        budget.reserve("A", 1, provider="anthropic")


@pytest.mark.parametrize("change", ["previous", "decrease", "unknown", "boolean", "empty", "extra"])
def test_reopen_rejects_malformed_contingency_history(budget, change):
    budget.increase_allowances({"O": 25}, reason="reviewed estimate", expected_ledger_sha256=ledger_sha(budget))
    path = budget.root / "ledger.json"
    value = json.loads(path.read_text())
    adjustment = value["allowance_adjustments"][0]
    if change == "previous":
        adjustment["previous_bound_microusd"] = 11
    elif change == "decrease":
        adjustment["bound_microusd"] = 9
    elif change == "unknown":
        adjustment["call_id"] = "absent"
    elif change == "boolean":
        adjustment["bound_microusd"] = True
    elif change == "empty":
        value["allowance_adjustments"] = []
    else:
        adjustment["override"] = True
    path.write_text(json.dumps(value))
    with pytest.raises(mod.BudgetError):
        reopen(budget)


def test_three_http_retries_each_hold_their_own_full_exposure(budget):
    for number in range(1, 5):
        budget.reserve("O", number, provider="openai")
        budget.settle("O", number, None)
    assert budget.snapshot()["pools"]["openai:target"]["reserved_exposure_microusd"] == 40
    with pytest.raises(mod.BudgetError, match="four-attempt"):
        budget.reserve("O", 5, provider="openai")


def test_actual_attempt_count_preserves_unknown_settled_and_unstarted_prefixes_on_resume(budget):
    initial = (budget.root / "ledger.json").read_bytes()
    assert budget.reserved_attempt_count("O") == 0
    assert (budget.root / "ledger.json").read_bytes() == initial
    budget.reserve("O", 1, provider="openai")
    assert budget.reserved_attempt_count("O") == 1
    budget.settle("O", 1, None)
    resumed = reopen(budget)
    assert resumed.reserved_attempt_count("O") == 1
    assert resumed.reserved_attempt_count("A") == 0
    resumed.reserve("O", 2, provider="openai")
    resumed.settle("O", 2, 2)
    before = (budget.root / "ledger.json").read_bytes()
    assert reopen(budget).reserved_attempt_count("O") == 2
    assert (budget.root / "ledger.json").read_bytes() == before


@pytest.mark.parametrize("call_id", ["missing", None, True, []])
def test_actual_attempt_count_rejects_unknown_or_malformed_call_id(budget, call_id):
    with pytest.raises(mod.BudgetError):
        budget.reserved_attempt_count(call_id)


@pytest.mark.parametrize("number,provider", [(True, "anthropic"), (0, "anthropic"), (2, "anthropic"),
                                              (1.0, "anthropic"), (1, "openai")])
def test_invalid_attempt_number_or_provider_is_refused_without_charge(budget, number, provider):
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError):
        budget.reserve("A", number, provider=provider)
    assert (budget.root / "ledger.json").read_bytes() == before


@pytest.mark.parametrize("change", ["bool_budget", "zero_budget", "bool_bound", "zero_bound", "float_bound", "negative_bound",
                                    "duplicate", "provider", "judge_provider", "overcommitted", "haiku_over33", "haiku_unfunded"])
def test_invalid_plan_is_rejected_before_creating_any_state(tmp_path, change):
    budgets, calls, protected = {"anthropic": 100, "openai": 100}, slots(), 33
    if change == "bool_budget":
        budgets["openai"] = True
    elif change == "zero_budget":
        budgets["openai"] = 0
    elif change in {"bool_bound", "zero_bound", "float_bound", "negative_bound"}:
        calls[0]["bound_microusd"] = {"bool_bound": True, "zero_bound": 0, "float_bound": 1.5, "negative_bound": -1}[change]
    elif change == "duplicate":
        calls.append(dict(calls[0]))
    elif change == "provider":
        calls[0]["provider"] = "missing"
    elif change == "judge_provider":
        calls[2]["provider"] = "openai"
    elif change == "overcommitted":
        calls[0]["bound_microusd"] = 28
    elif change == "haiku_over33":
        protected = mod.MAX_HAIKU_MICROUSD + 1
    else:
        budgets["anthropic"] = 41
    root = tmp_path / "never-created"
    with pytest.raises(mod.BudgetError):
        mod.create_budget(root, provider_budgets_microusd=budgets, planned_calls=calls, protected_haiku_microusd=protected)
    assert not root.exists()


def test_atomic_write_failure_prevents_mock_http_call_and_does_not_release_money(budget, monkeypatch):
    import experiments.retained_response_judge_execute as persistence
    attempts = []
    original = (budget.root / "ledger.json").read_bytes()
    def broken_replace(*args):
        raise OSError("simulated disk interruption")
    with monkeypatch.context() as change:
        change.setattr(persistence.os, "replace", broken_replace)
        with pytest.raises(OSError, match="disk interruption"):
            budget.reserve("A", 1, provider="anthropic")
            attempts.append("HTTP")
    assert attempts == [] and (budget.root / "ledger.json").read_bytes() == original
    resumed = reopen(budget)
    resumed.reserve("A", 1, provider="anthropic")
    with monkeypatch.context() as change:
        change.setattr(persistence.os, "replace", broken_replace)
        with pytest.raises(OSError):
            resumed.settle("A", 1, 1)
    assert reopen(budget).snapshot()["pools"]["anthropic:target"]["reserved_exposure_microusd"] == 20


@pytest.mark.parametrize("change", ["plan", "ledger_binding", "sequence", "cost_type", "invented_reservations"])
def test_reopen_rejects_changed_plan_or_malformed_reservation_history(budget, change):
    path = budget.root / "ledger.json"
    ledger = json.loads(path.read_text())
    if change == "plan":
        path = budget.root / "plan.json"
        ledger = json.loads(path.read_text())
        ledger["protected_haiku_microusd"] = 32
    elif change == "ledger_binding":
        ledger["plan_sha256"] = "0" * 64
    elif change == "sequence":
        ledger["attempts"] = {"A": {"2": {"state": "unknown", "actual_cost_microusd": None}}}
    elif change == "cost_type":
        ledger["attempts"] = {"A": {"1": {"state": "settled", "actual_cost_microusd": True}}}
    else:
        ledger["attempts"] = {"A": {str(n): {"state": "unknown", "actual_cost_microusd": None} for n in (1, 2)}}
    path.write_text(json.dumps(ledger))
    with pytest.raises(mod.BudgetError):
        reopen(budget)


def _race_reserve(budget, barrier, results):
    barrier.wait()
    try:
        budget.reserve("A", 1, provider="anthropic")
        results.put("reserved")
    except (ValueError, RuntimeError):
        results.put("refused")


def test_funding_stop_observation_does_not_reload_spending_ledger(budget, monkeypatch):
    budget.reserve("O", 1, provider="openai")
    budget.stop_provider_funding("openai", "O")
    monkeypatch.setattr(budget, "_load", lambda: pytest.fail("Stop observation reread mutable spending ledger"))
    assert [row["provider"] for row in budget.provider_funding_stops()] == ["openai"]


def test_process_lock_prevents_duplicate_physical_admission(budget):
    context = multiprocessing.get_context("spawn")
    barrier, results = context.Barrier(2), context.Queue()
    workers = [context.Process(target=_race_reserve,
               args=(budget, barrier, results)) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
        assert worker.exitcode == 0
    assert sorted(results.get(timeout=2) for _ in workers) == ["refused", "reserved"]
    assert budget.snapshot()["pools"]["anthropic:target"]["reserved_exposure_microusd"] == 20


def test_primitive_never_constructs_a_provider_client_or_sends_a_call(budget, monkeypatch):
    from ura.targets import api
    monkeypatch.setattr(api, "_require", lambda *a: pytest.fail("provider SDK construction"))
    budget.reserve("A", 1, provider="anthropic")
    budget.settle("A", 1, None)
    assert reopen(budget).call("J")["pool"] == "judge"


@pytest.mark.parametrize("call_id,provider,expected_calls", [("A", "anthropic", 1), ("O", "openai", 4)])
def test_actual_sdk_hook_stops_before_unfunded_retry_without_any_network(budget, monkeypatch, call_id, provider, expected_calls):
    from ura.targets import api
    monkeypatch.setattr(api.time, "sleep", lambda _: None)
    monkeypatch.setattr(api, "_require", lambda *a: pytest.fail("real provider SDK construction"))
    sent = []
    class HttpFailure(RuntimeError):
        status_code = 500

    def reserve(observed_provider, request, number):
        assert observed_provider == provider and request == {"max_tokens": 512}
        if number > 1:
            # Only the controller's observed HTTP error permits this explicit
            # unknown settlement. A restarted unresolved slot cannot do this.
            budget.settle(call_id, number - 1, None)
        budget.reserve(call_id, number, provider=observed_provider)

    def mock_http(**request):
        assert budget.snapshot()["pools"][f"{provider}:target"]["unresolved_attempts"] == 1
        sent.append(request)
        if len(sent) < 4:
            raise HttpFailure()
        return "response"

    with api.provider_attempt_admission(reserve):
        if expected_calls == 1:
            with pytest.raises(mod.BudgetError, match="planned first attempts"):
                api._call_with_retry(mock_http, {"max_tokens": 512}, provider=provider, max_retries=3)
        else:
            result, audit = api._call_with_retry(mock_http, {"max_tokens": 512}, provider=provider, max_retries=3)
            assert result == "response" and len(audit) == 4
            budget.settle(call_id, 4, 2)
    assert len(sent) == expected_calls
    pool = reopen(budget).snapshot()["pools"][f"{provider}:target"]
    assert pool["liability_microusd"] == (40 if expected_calls == 1 else 32)


@pytest.mark.parametrize("actual", [True, -1, 0.5])
def test_invalid_actual_cost_does_not_release_reserved_exposure(budget, actual):
    budget.reserve("A", 1, provider="anthropic")
    before = (budget.root / "ledger.json").read_bytes()
    with pytest.raises(mod.BudgetError):
        budget.settle("A", 1, actual)
    assert (budget.root / "ledger.json").read_bytes() == before
