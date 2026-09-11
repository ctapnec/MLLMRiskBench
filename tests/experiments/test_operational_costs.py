from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import operational_costs as subject
from experiments.rig_web_app.dashboard import DashboardMixin


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def budget(root, name="cohort", *, settled=1_500_000, closed=False):
    path = root / name / "budget"
    path.mkdir(parents=True)
    calls = [{"call_id": key, "provider": provider, "pool": role, "bound_microusd": bound}
             for key, provider, role, bound in (
                 ("answer", "openai", "target", 2_000_000),
                 ("unknown", "openai", "target", 500_000),
                 ("bounded", "openai", "target", 900_000),
                 ("pending", "anthropic", "target", 1_000_000),
                 ("judge", "anthropic", "judge", 30_000),
                 ("unused-judge", "anthropic", "judge", 40_000))]
    plan = {"schema": "ura-hosted-attempt-budget-plan/1", "planned_calls": calls,
            "pool_caps_microusd": {"openai:target": 10_000_000, "anthropic:target": 5_000_000,
                                   "anthropic:judge": 1_000_000}}
    ledger = {"schema": "ura-hosted-attempt-budget-ledger/3", "plan_sha256": "a" * 64,
        "allowance_adjustments": [{"call_id": "unknown", "bound_microusd": 600_000}],
        "attempts": {
            "answer": {"1": {"state": "settled", "actual_cost_microusd": settled}},
            "unknown": {"1": {"state": "unknown", "actual_cost_microusd": None}},
            "bounded": {"1": {"state": "bounded_unknown", "actual_cost_microusd": None,
                               "usage_bound": {"bound_microusd": 100_000}}},
            "pending": {"1": {"state": "reserved", "actual_cost_microusd": None}},
            "judge": {"1": {"state": "settled", "actual_cost_microusd": 20_000}}}}
    save(path / "plan.json", plan)
    save(path / "ledger.json", ledger)
    if closed:
        save(path / "paid-circuit.json", {"schema": "ura-hosted-budget-close/1",
            "category": "completed_budget_closed", "unstarted_judge_call_ids": ["unused-judge"]})
    subject.register_budget(root, path)
    return path


def by_role(result, provider, role):
    return next(row for row in result["rows"] if (row["provider"], row["role"]) == (provider, role))


def test_real_ledger_states_copies_and_retry_attempts_are_not_conflated(tmp_path):
    first = budget(tmp_path)
    second = budget(tmp_path, "recovery")
    ledger = json.loads((second / "ledger.json").read_text())
    ledger["attempts"]["unknown"]["2"] = {"state": "settled", "actual_cost_microusd": 50_000}
    save(second / "ledger.json", ledger)
    subject.register_budget(tmp_path, first)  # Idempotent registration.
    result = subject.campaign_costs(tmp_path)
    assert result["errors"] == []
    row = by_role(result, "openai", "target")
    assert row["http_attempts"] == 4
    assert row["reported_cost_microusd"] == 1_550_000
    assert row["unknown_exposure_microusd"] == 700_000
    assert row["unknown_attempts"] == 2
    assert by_role(result, "anthropic", "target")["unsettled_exposure_microusd"] == 1_000_000
    assert by_role(result, "anthropic", "judge")["unstarted_commitments_microusd"] == 40_000


def test_closure_removes_only_unused_judge_commitments(tmp_path):
    budget(tmp_path, closed=True)
    result = subject.campaign_costs(tmp_path)
    assert by_role(result, "anthropic", "judge")["unstarted_commitments_microusd"] == 0
    assert by_role(result, "anthropic", "judge")["reported_cost_microusd"] == 20_000
    assert by_role(result, "openai", "target")["unknown_exposure_microusd"] == 700_000


@pytest.mark.parametrize("problem", ["conflicting-copy", "missing-file", "unplanned-attempt"])
def test_incomplete_or_conflicting_sources_are_not_plausible_totals(tmp_path, problem):
    path = budget(tmp_path)
    if problem == "conflicting-copy":
        budget(tmp_path, "copy", settled=1)
    elif problem == "missing-file":
        (path / "ledger.json").unlink()
    else:
        ledger = json.loads((path / "ledger.json").read_text())
        ledger["attempts"]["outside-plan"] = {"1": {"state": "settled", "actual_cost_microusd": 5}}
        save(path / "ledger.json", ledger)
    result = subject.campaign_costs(tmp_path)
    assert result["registered"] and result["errors"] and result["rows"] == []


def test_cost_view_reuses_unchanged_files_and_refreshes_atomic_settlement(tmp_path, monkeypatch):
    path = budget(tmp_path)
    original = subject.campaign_costs(tmp_path)
    real_open = Path.open

    def no_read(*args, **kwargs):
        pytest.fail("unchanged cost source was reparsed")

    with monkeypatch.context() as context:
        context.setattr(Path, "open", no_read)
        assert subject.campaign_costs(tmp_path) == original
    with real_open(path / "ledger.json") as stream:
        ledger = json.load(stream)
    ledger["attempts"]["unknown"]["1"] = {"state": "settled", "actual_cost_microusd": 40_000}
    temporary = path / "replacement.json"
    save(temporary, ledger)
    temporary.replace(path / "ledger.json")
    refreshed = subject.campaign_costs(tmp_path)
    assert by_role(refreshed, "openai", "target")["reported_cost_microusd"] == 1_540_000
    assert by_role(refreshed, "openai", "target")["unknown_exposure_microusd"] == 100_000


def test_stats_uses_retained_costs_even_when_sqlite_usage_is_empty(tmp_path):
    budget(tmp_path)

    class View(DashboardMixin):
        results_root = tmp_path
        db = SimpleNamespace(usage_totals=lambda: pytest.fail("stale index used for campaign costs"))

    page = View()._spend_card()
    assert "Retained campaign costs" in page
    assert "$1.5000" in page and "$0.7000" in page
    assert "no billable calls recorded" not in page
    assert "not live provider credit balances" in page


def test_no_registry_uses_legacy_view_and_outside_source_is_rejected(tmp_path):
    assert subject.campaign_costs(tmp_path)["registered"] is False
    inside = tmp_path / "results"
    inside.mkdir()
    path = budget(tmp_path)
    with pytest.raises(ValueError):
        subject.register_budget(inside, path)
