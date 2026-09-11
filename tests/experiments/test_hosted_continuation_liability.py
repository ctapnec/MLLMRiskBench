import os

import pytest

from experiments.hosted_attempt_budget import AttemptBudget, BudgetError, create_budget


pytestmark = pytest.mark.skipif(os.name != "posix", reason="uses the executor's POSIX budget lock")


@pytest.fixture
def budget(tmp_path):
    root = tmp_path / "budget"
    descriptor = create_budget(root, provider_budgets_microusd={"anthropic": 1000, "google": 1000},
        planned_calls=[{"call_id": key, "provider": provider, "pool": pool, "bound_microusd": bound}
            for key, provider, pool, bound in (("done", "anthropic", "target", 20),
                ("retry", "anthropic", "target", 20), ("judge", "anthropic", "judge", 30),
                ("active", "google", "target", 10))], protected_haiku_microusd=300)
    value = AttemptBudget(root, descriptor["sha256"])
    value.reserve("done", 1, provider="anthropic")
    value.settle("done", 1, 2)
    value.reserve("retry", 1, provider="anthropic")
    value.settle("retry", 1, None)
    value.reserve("active", 1, provider="google")
    return value


def test_pending_forecast_holds_all_remaining_retries_and_changes_no_budget_bytes(budget):
    before = {p.name: p.read_bytes() for p in budget.root.glob("*.json")}
    forecast = budget.continuation_liability(["done"])
    assert forecast["continuation_liability_microusd"] == {
        "anthropic:target": 82, "anthropic:judge": 120, "google:target": 40}
    assert forecast["extra_transport_reserve_microusd"] == {
        "anthropic:target": 60, "anthropic:judge": 90, "google:target": 30}
    assert {p.name: p.read_bytes() for p in budget.root.glob("*.json")} == before


@pytest.mark.parametrize("finished", [["active"], ["judge"], ["outside"], ["done", "done"], "done"])
def test_unsettled_unissued_or_invalid_completion_does_not_release_capacity(budget, finished):
    with pytest.raises(BudgetError):
        budget.continuation_liability(finished)


def test_normal_retry_progress_cannot_exceed_the_preceding_forecast(budget):
    original = budget.continuation_liability(["done"])["continuation_liability_microusd"]
    budget.reserve("retry", 2, provider="anthropic")
    budget.settle("retry", 2, 5)
    later = budget.continuation_liability(["done"])["continuation_liability_microusd"]
    assert all(later[key] <= original[key] for key in original)
    assert later["anthropic:target"] == 67


def test_allowance_increase_is_visible_to_the_concurrent_allocation_guard(budget):
    import hashlib

    before = budget.continuation_liability(["done"])["continuation_liability_microusd"]
    budget.increase_allowances({"active": 50}, reason="explicit review",
        expected_ledger_sha256=hashlib.sha256((budget.root / "ledger.json").read_bytes()).hexdigest())
    after = budget.continuation_liability(["done"])["continuation_liability_microusd"]
    assert after["google:target"] == 200 > before["google:target"]


def test_closed_cohort_does_not_reserve_canceled_judge_retries(budget):
    budget.settle("active", 1, 3)
    budget.close(reason="All intended target outcomes and eligible judging are terminal")
    result = budget.continuation_liability(["done", "retry", "active"])
    assert result["continuation_liability_microusd"] == {
        "anthropic:target": 22, "anthropic:judge": 0, "google:target": 3}
    assert not any(result["extra_transport_reserve_microusd"].values())


def test_growth_guard_stops_before_a_child_reservation(budget):
    ceilings = budget.continuation_liability(["done"])["continuation_liability_microusd"]
    ceilings["google:target"] -= 1
    reservations = []
    with pytest.raises(BudgetError, match="continuation ceiling"):
        with budget.hold_continuation_ceiling(["done"], ceilings):
            reservations.append("must not reserve")
    assert reservations == []


def test_parent_ledger_is_locked_during_child_reservation_not_afterward(budget):
    import threading
    from experiments.hosted_attempt_budget import _budget_lock

    ceilings = budget.continuation_liability(["done"])["continuation_liability_microusd"]
    waiting, entered = threading.Event(), threading.Event()

    def edit():
        waiting.set()
        with _budget_lock(budget.root):
            entered.set()

    with budget.hold_continuation_ceiling(["done"], ceilings):
        worker = threading.Thread(target=edit)
        worker.start()
        assert waiting.wait(2)
        assert not entered.wait(0.1)
    worker.join(timeout=2)
    assert entered.is_set() and not worker.is_alive()
