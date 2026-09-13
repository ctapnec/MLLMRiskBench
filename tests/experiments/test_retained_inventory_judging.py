import json
from pathlib import Path

import pytest

from experiments import retained_inventory_judging as subject
from experiments import hosted_attempt_budget as money
from test_retained_inventory_judge_items import population  # noqa: F401
from test_retained_response_judge_execute import _prepared, JUDGE
from test_retained_judge_shared_budget import HookHaiku
from ura.targets import api


@pytest.fixture
def prepared(population, tmp_path, monkeypatch):  # noqa: F811
    for slot in population.slots.values():
        slot['bound_microusd'] = 100_000
    pending, _, _, _ = population.collect()
    budget_path = tmp_path / 'actual-budget'
    descriptor = money.create_budget(budget_path, provider_budgets_microusd={'anthropic': 40_000_000},
        planned_calls=[dict(call_id=key, **value) for key, value in population.slots.items()])
    for item in pending:
        item['budget'] = dict(root=str(budget_path), plan_sha256=descriptor['sha256'])
    root = tmp_path / 'items'
    root.mkdir()
    (root/'validated-items.json').write_text(json.dumps(pending))
    (root/'sources.json').write_text('{}')
    coverage = dict(status='prepared_no_calls', scope='all_saved_outputs_on_selected_inputs',
        selected_outputs=5, retained_outputs=8, input_entries=1, existing_execution_owned=1,
        missing_outputs=1, unfunded_outputs=1)
    (root/'result.json').write_text(json.dumps(coverage))
    monkeypatch.setattr(subject, '_original_items', lambda _: (pending, coverage))
    base = _prepared(tmp_path, monkeypatch)
    config = json.loads(base['api_config'].read_text())
    config[JUDGE]['max_tokens'] = 512
    base['api_config'].write_text(json.dumps(config))
    kwargs = dict(items_root=root, judge_model=JUDGE, api_config=base['api_config'],
        pricing_config=base['pricing_config'], pricing_as_of='2026-09-13', out=tmp_path/'plans')
    monkeypatch.setattr(api, '_require', lambda *_: pytest.fail('Unexpected SDK construction'))
    monkeypatch.setattr(api.time, 'sleep', lambda _: None)
    return kwargs, pending, coverage, money.AttemptBudget(budget_path, descriptor['sha256'])


def test_plans_include_every_model_without_new_funding_and_resume_preparation(prepared):
    kwargs, items, _, budget = prepared
    before = (budget.root/'ledger.json').read_bytes()
    result = subject.prepare(**kwargs)
    assert result['status'] == 'ready_for_funded_judging' and result['selected_outputs'] == 5
    plan = subject.read(Path(result['plans'][0]['root'])/'plan.json')
    assert {r['retained_row_sha256'] for r in plan['selected']} == {i['row']['retained_row_sha256'] for i in items}
    assert plan['judge_condition']['transport_retries'] == 3
    assert plan['judge_condition']['max_cost_microusd'] == 2_000_000
    assert result['target_calls'] == result['judge_calls'] == result['token_count_http_attempts'] == 0
    assert subject.prepare(**kwargs) == result
    assert (budget.root/'ledger.json').read_bytes() == before


def test_real_executor_keeps_retries_all_outputs_and_resume_without_duplicate_calls(prepared, monkeypatch):
    kwargs, _, _, budget = prepared
    subject.prepare(**kwargs)
    config, _ = subject.execution._load_api_config(kwargs['api_config'], judge_model=JUDGE,
        expected_sha256=subject._descriptor(kwargs['api_config'])['sha256'])
    fake = HookHaiku(config, failures=1)
    real_execute = subject.execution.execute
    def execute(**values):
        assert values['retain_invalid_verdicts'] is True
        return real_execute(**values, judge_factory=lambda *_: fake)
    monkeypatch.setattr(subject.execution, 'execute', execute)
    args = dict(preparation=kwargs['out'], out=kwargs['out'].parent/'judgments')
    result = subject.execute(**args)
    assert result['status'] == 'selected_judging_complete' and result['selected_outputs'] == 5
    assert fake.calls == 5 and fake.http_calls == 6
    assert sum(row['judge_calls'] for row in result['plans']) == 5
    assert result['whole_campaign_complete'] is False
    assert subject.execute(**args) == result and fake.http_calls == 6
    assert budget.snapshot()['pools']['anthropic:judge']['settled_attempts'] == 5


@pytest.mark.parametrize('change', ['omit-group', 'duplicate-group', 'changed-text'])
def test_changed_group_or_answer_stops_before_paid_execution(prepared, monkeypatch, change):
    kwargs, items, _, _ = prepared
    ready = subject.prepare(**kwargs)
    if change == 'omit-group':
        ready['plans'] = []
    elif change == 'duplicate-group':
        ready['plans'] *= 2
    else:
        items[0]['text'] = 'Replaced response'
    if change != 'changed-text':
        (kwargs['out']/'result.json').write_text(json.dumps(ready))
    monkeypatch.setattr(subject.execution, 'execute', lambda **_: pytest.fail('Paid executor reached'))
    with pytest.raises(ValueError):
        subject.execute(preparation=kwargs['out'], out=kwargs['out'].parent/'judgments')


def test_request_over_existing_funding_stays_visible_and_cannot_execute(prepared, monkeypatch):
    kwargs, _, _, _ = prepared
    original = subject.execution.build_shared_request_receipts
    def excessive(*args, **kw):
        result = original(*args, **kw)
        next(iter(result.values()))['input_tokens_estimate'] = 200_000
        return result
    monkeypatch.setattr(subject.execution, 'build_shared_request_receipts', excessive)
    result = subject.prepare(**kwargs)
    assert result['status'] == 'needs_funding_review' and len(result['funding_review']) == 1
    assert result['selected_outputs'] == 5
    with pytest.raises(ValueError, match='funding review'):
        subject.execute(preparation=kwargs['out'], out=kwargs['out'].parent/'judgments')


def test_counting_uses_network_only_for_oversized_requests(prepared, monkeypatch):
    kwargs, raw, _, _ = prepared
    ready = subject.prepare(**kwargs)
    plan = subject.read(Path(ready['plans'][0]['root'])/'plan.json')
    items = subject._selected_items(plan, {i['row']['retained_row_sha256']: i for i in raw})
    requests = subject.read(Path(ready['plans'][0]['root'])/'shared-requests.json')
    first = next(iter(requests))
    bounds = {r['call_id']: 100_000 for r in requests.values()}
    bounds[requests[first]['call_id']] = 1
    observed = []
    def count(target, request, *, cache_root, allow_network, audit):
        observed.append(allow_network)
        return dict(input_tokens=100)
    monkeypatch.setattr(subject, 'cached_count_request', count)
    monkeypatch.setattr(subject.execution, 'build_shared_request_receipts', lambda items, **kw: {
        row['retained_row_sha256']: dict(counted=True) for row, _, _ in items})
    config, _ = subject.execution._load_api_config(kwargs['api_config'], judge_model=JUDGE,
        expected_sha256=subject._descriptor(kwargs['api_config'])['sha256'])
    receipts, calls = subject._count_oversized(items, requests, bounds, model=JUDGE, normalized=config,
        cache=kwargs['out']/'cache', allow_network=True)
    assert len(observed) == 5 and sum(observed) == 1
    assert all(r == dict(counted=True) for r in receipts.values()) and calls == 0


def test_empty_pending_selection_does_not_claim_all_existing_verdicts_complete(prepared, monkeypatch):
    kwargs, _, coverage, _ = prepared
    coverage = dict(coverage, selected_outputs=0, existing_execution_owned=6)
    (kwargs['items_root']/'validated-items.json').write_text('[]')
    monkeypatch.setattr(subject, '_original_items', lambda _: ([], coverage))
    ready = subject.prepare(**kwargs)
    assert ready['selected_outputs'] == 0 and ready['plans'] == []
    result = subject.execute(preparation=kwargs['out'], out=kwargs['out'].parent/'judgments')
    assert result['whole_campaign_complete'] is False and result['coverage']['existing_execution_owned'] == 6
