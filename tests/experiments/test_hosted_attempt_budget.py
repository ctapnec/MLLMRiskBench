from __future__ import annotations

import json
import multiprocessing
import os

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
