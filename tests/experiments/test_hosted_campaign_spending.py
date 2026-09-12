"""Campaign-wide precalculated spending, without historical batch holds."""
import copy
import hashlib
import json
import os

import pytest

from experiments import hosted_campaign_spending as scope
from experiments.hosted_attempt_budget import AttemptBudget, BudgetError, BudgetCapacityUnavailable, create_budget

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='existing POSIX budget locks')


@pytest.fixture
def campaign(tmp_path):
    def make(name, cap):
        root = tmp_path / name
        descriptor = create_budget(root, provider_budgets_microusd={'anthropic': cap},
            protected_haiku_microusd=10, reservation_policy='per_attempt',
            planned_calls=[{'call_id': key, 'provider': 'anthropic', 'pool': pool, 'bound_microusd': 100}
                           for key, pool in [('A', 'target'), ('B', 'target'), ('J', 'judge')]])
        budget = AttemptBudget(root, descriptor['sha256'])
        budget.use_precalculated_spending()
        return budget
    prior, current = make('prior', 200), make('current', 25)
    document = {'schema': scope.SCHEMA, 'pool_caps_microusd': {'anthropic:target': 100, 'anthropic:judge': 10},
                'budgets': [{'root': str(b.root), 'plan_sha256': b.expected_plan_sha256} for b in (prior, current)]}
    return prior, current, document


def test_full_precomputed_ceiling_replaces_batch_cap_without_rewriting_history(campaign):
    prior, current, document = campaign
    prior.reserve('A', 1, provider='anthropic')
    prior.settle('A', 1, 15)
    current.reserve('A', 1, provider='anthropic')
    current.settle('A', 1, 10)  # Reaches the old child cap, not the campaign cap.
    before = {(b.root, name): (b.root / name).read_bytes() for b in (prior, current) for name in ('plan.json', 'ledger.json')}
    current.use_campaign_spending(document)
    assert all((root / name).read_bytes() == value for (root, name), value in before.items())
    current = AttemptBudget(current.root, current.expected_plan_sha256)
    current.reserve('B', 1, provider='anthropic')
    current.settle('B', 1, 75)
    pool = current.snapshot()['campaign_spending']['pools']['anthropic:target']
    assert pool['tracked_spend_microusd'] == 100
    with pytest.raises(BudgetCapacityUnavailable, match='reported spending'):
        current.reserve('B', 2, provider='anthropic')
    current.reserve('J', 1, provider='anthropic')  # Separate precomputed judge pool.


def test_changed_predecessor_spending_invalidates_cached_subtotal(campaign, monkeypatch):
    prior, current, document = campaign
    current.use_campaign_spending(document)
    reads = []
    original = scope._read
    def read(path):
        reads.append(path)
        return original(path)
    monkeypatch.setattr(scope, '_read', read)
    current.snapshot()
    current.snapshot()
    assert prior.root / 'ledger.json' not in reads
    prior.reserve('A', 1, provider='anthropic')
    prior.settle('A', 1, 100)
    with pytest.raises(BudgetCapacityUnavailable):
        current.reserve('A', 1, provider='anthropic')
    assert prior.root / 'ledger.json' in reads
    assert current.reserved_attempt_count('A') == 0


def test_judge_only_continuation_keeps_all_provider_totals_and_own_ceiling(campaign, tmp_path):
    prior,current,document=campaign
    other_root=tmp_path/'other-provider'
    descriptor=create_budget(other_root,provider_budgets_microusd={'anthropic':200,'google':200},
        protected_haiku_microusd=10,reservation_policy='per_attempt',
        planned_calls=[dict(call_id='G',provider='google',pool='target',bound_microusd=100)])
    other=AttemptBudget(other_root,descriptor['sha256'])
    other.reserve('G',1,provider='google')
    other.settle('G',1,50)
    expanded=copy.deepcopy(document)
    expanded['pool_caps_microusd']['google:target']=100
    expanded['budgets'].append(dict(root=str(other_root),plan_sha256=descriptor['sha256']))
    current.use_campaign_spending(expanded)
    current.reserve('J',1,provider='anthropic')
    current.settle('J',1,10)
    pools=current.snapshot()['campaign_spending']['pools']
    assert pools['google:target']['tracked_spend_microusd']==50
    assert pools['anthropic:judge']['tracked_spend_microusd']==10
    with pytest.raises(BudgetCapacityUnavailable,match='reported spending'):
        current.reserve('J',2,provider='anthropic')
    missing=copy.deepcopy(expanded)
    del missing['pool_caps_microusd']['anthropic:judge']
    with pytest.raises(BudgetError,match='configuration fields'):
        scope.validate_scope(missing,current.root,current.expected_plan_sha256,{'anthropic:target':0,'anthropic:judge':10})


def test_added_campaign_inventory_shares_unchanged_ceiling_and_retains_history(campaign, tmp_path):
    prior, current, document = campaign
    current.use_campaign_spending(document)
    original = (current.root / 'campaign-spending.json').read_bytes()
    added_root = tmp_path / 'additional-inputs'
    descriptor = create_budget(added_root, provider_budgets_microusd={'anthropic': 200},
        protected_haiku_microusd=10, reservation_policy='per_attempt',
        planned_calls=[{'call_id': 'new', 'provider': 'anthropic', 'pool': 'target', 'bound_microusd': 100}])
    added = AttemptBudget(added_root, descriptor['sha256'])
    added.use_precalculated_spending()
    expanded = copy.deepcopy(document)
    expanded['budgets'].append({'root': str(added_root), 'plan_sha256': descriptor['sha256']})
    preserved = {(b.root, name): (b.root/name).read_bytes() for b in (prior, current)
                 for name in ('plan.json', 'ledger.json')}
    current.use_campaign_spending(expanded)
    added.use_campaign_spending(expanded)
    assert (current.root / 'campaign-spending-before-extension-2.json').read_bytes() == original
    assert all((root/name).read_bytes() == value for (root,name),value in preserved.items())
    added.reserve('new', 1, provider='anthropic')
    added.settle('new', 1, 100)
    with pytest.raises(BudgetCapacityUnavailable, match='reported spending'):
        current.reserve('A', 1, provider='anthropic')
    assert current.reserved_attempt_count('A') == 0
    current.use_campaign_spending(expanded)  # Restart does not duplicate history or costs.
    assert current.snapshot()['campaign_spending']['budget_ledgers'] == 3
    for changed in (document, {**expanded, 'pool_caps_microusd': {'anthropic:target': 101, 'anthropic:judge': 10}}):
        with pytest.raises(BudgetError, match='retain all ledgers'):
            current.use_campaign_spending(changed)
        assert json.loads((current.root/'campaign-spending.json').read_text()) == expanded


def test_added_inventory_can_lower_the_shared_credit_stop_without_resetting_spend(campaign, tmp_path):
    prior, current, document = campaign
    prior.reserve('A', 1, provider='anthropic')
    prior.settle('A', 1, 60)
    current.use_campaign_spending(document)
    original = (current.root/'campaign-spending.json').read_bytes()
    added_root = tmp_path/'lower-credit-extension'
    descriptor = create_budget(added_root, provider_budgets_microusd={'anthropic': 200},
        protected_haiku_microusd=10, reservation_policy='per_attempt',
        planned_calls=[{'call_id':'new','provider':'anthropic','pool':'target','bound_microusd':100}])
    added = AttemptBudget(added_root, descriptor['sha256'])
    added.use_precalculated_spending()
    expanded = copy.deepcopy(document)
    expanded['budgets'].append({'root':str(added_root),'plan_sha256':descriptor['sha256']})
    expanded['pool_caps_microusd']['anthropic:target'] = 60
    current.use_campaign_spending(expanded)
    added.use_campaign_spending(expanded)
    assert (current.root/'campaign-spending-before-extension-2.json').read_bytes() == original
    for money, call_id in ((current,'A'),(added,'new')):
        assert money.snapshot()['campaign_spending']['pools']['anthropic:target']['tracked_spend_microusd'] == 60
        with pytest.raises(BudgetCapacityUnavailable):
            money.reserve(call_id,1,provider='anthropic')
        assert money.reserved_attempt_count(call_id) == 0


def test_unknown_and_inflight_are_not_maximum_holds_or_zero_settlements(campaign):
    prior, current, document = campaign
    prior.reserve('A', 1, provider='anthropic')
    prior.settle('A', 1, None)
    prior.reserve('B', 1, provider='anthropic')
    current.use_campaign_spending(document)
    current.reserve('A', 1, provider='anthropic')
    pool = current.snapshot()['campaign_spending']['pools']['anthropic:target']
    assert pool['tracked_spend_microusd'] == 0
    assert pool['unknown_usage_attempts'] == 1
    assert pool['unresolved_attempts'] == 2
    assert json.loads((prior.root / 'ledger.json').read_text())['attempts']['A']['1']['actual_cost_microusd'] is None


def test_revised_output_forecast_does_not_reintroduce_maximum_cost_holds(campaign):
    _, current, document = campaign
    current.use_campaign_spending(document)
    current.reserve('A', 1, provider='anthropic')
    current.settle('A', 1, None)
    # An explicit new output condition updates the forecast, not the campaign ceiling.
    current.increase_allowances({'A': 200}, reason='Explicit larger-output recovery',
        expected_ledger_sha256=hashlib.sha256((current.root / 'ledger.json').read_bytes()).hexdigest())
    assert current.attempt_bound('A') == 200
    current.reserve('A', 2, provider='anthropic')
    assert current.snapshot()['campaign_spending']['pools']['anthropic:target']['cap_microusd'] == 100
    current.settle('A', 2, 100)
    with pytest.raises(BudgetCapacityUnavailable):
        current.reserve('B', 1, provider='anthropic')


@pytest.mark.parametrize('change', ['duplicate', 'omit_current', 'wrong_plan', 'wrong_pool', 'negative'])
def test_invalid_scope_does_not_install_partial_configuration(campaign, change):
    _, current, original = campaign
    document = copy.deepcopy(original)
    if change == 'duplicate':
        document['budgets'].append(document['budgets'][0])
    elif change == 'omit_current':
        document['budgets'].pop()
    elif change == 'wrong_plan':
        document['budgets'][0]['plan_sha256'] = '0' * 64
    elif change == 'wrong_pool':
        document['pool_caps_microusd']['other:target'] = 100
    else:
        document['pool_caps_microusd']['anthropic:target'] = -1
    with pytest.raises(BudgetError):
        current.use_campaign_spending(document)
    assert not (current.root / 'campaign-spending.json').exists()
