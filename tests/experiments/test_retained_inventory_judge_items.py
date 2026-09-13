import copy
from contextlib import nullcontext
import hashlib
import json
from types import SimpleNamespace

import pytest

from experiments import retained_inventory_judge_items as subject
from test_retained_response_judge_pair import _candidate, _population


@pytest.fixture
def population(tmp_path, monkeypatch):
    rows = {cohort: [_candidate(i, cohort=cohort, input_index=0) for i in range(count)]
            for cohort, count in (('local', 3), ('hosted', 2))}
    metadata = {cohort: {} for cohort in rows}
    owners, cells, slots = {}, {}, {}
    for cohort, part in rows.items():
        for index, row in enumerate(part):
            prompt, text = 'The same retained question', f'{cohort} answer {index}'
            row['prompt_sha256'] = hashlib.sha256(prompt.encode()).hexdigest()
            row['response_sha256'] = hashlib.sha256(text.encode()).hexdigest()
            row['input_identity_sha256'] = subject.retained._sha({
                field: row[field] for field in subject.retained._MATCH_IDENTITY_FIELDS})
            metadata[cohort][row['sample_key']] = dict(prepared_prompt=prompt, prepared_response=text)
            call = 'judge-local-' + row['retained_row_sha256'] if cohort == 'local' else f'judge-hosted-{index}'
            slots[call] = dict(provider='anthropic', pool='judge')
            if cohort == 'hosted':
                owners[row['run_id']] = (dict(target=row['exact_model'], budget_plan_sha256='a'*64,
                    requests={'original-input': dict(judge_call_ids=dict(hosted=call))}),
                    dict(input_ids=['original-input']))
                cells[row['run_id']] = dict(attempts={row['attempt_id']: dict(params=dict(
                    retained_origin=dict(selection=dict(input_identity_sha256='original-input'))))})
    audit = {cohort: _population(len(part)) for cohort, part in rows.items()}
    monkeypatch.setattr(subject, 'source_population', lambda *_: (
        rows['local'], rows['hosted'], audit['local'], audit['hosted'], metadata, cells))
    monkeypatch.setattr(subject, 'hosted_sources', lambda _: owners)
    monkeypatch.setattr(subject.funding, '_budget_lock', lambda _: nullcontext())
    ledger, reads = dict(attempts={}), []
    def load():
        reads.append(True)
        return {}, ledger, slots
    budget = SimpleNamespace(root=tmp_path/'budget', expected_plan_sha256='a'*64, _load=load)
    def inventory():
        return subject.inventory.build_inventory(rows['local'], rows['hosted'],
            local_audit=audit['local'], hosted_audit=audit['hosted'])
    def collect(saved=None):
        return subject.collect_items(saved_inventory=inventory() if saved is None else saved,
            local_views=[], hosted_views=[], budgets=[budget, budget])
    return SimpleNamespace(rows=rows, metadata=metadata, owners=owners, ledger=ledger, slots=slots,
        budget=budget, reads=reads, inventory=inventory, collect=collect)


def test_all_local_and_hosted_answers_use_distinct_existing_slots_once(population):
    pending, owned, unfunded, missing = population.collect()
    assert len(pending) == 5 and owned == unfunded == missing == []
    assert len({item['call_id'] for item in pending}) == 5
    assert {item['row']['exact_model'] for item in pending} == {
        row['exact_model'] for part in population.rows.values() for row in part}
    assert len(population.reads) == 1


def test_missing_unfunded_and_owned_answers_are_not_replaced_or_called(population):
    absent, started, unfunded_row = population.rows['local']
    absent['response_sha256'] = subject.inventory.EMPTY_RESPONSE_SHA256
    population.ledger['attempts']['judge-local-' + started['retained_row_sha256']] = {'1': {'state': 'reserved'}}
    del population.slots['judge-local-' + unfunded_row['retained_row_sha256']]
    pending, owned, unfunded, missing = population.collect()
    assert len(pending) == 2 and len(owned) == len(unfunded) == len(missing) == 1
    assert {item['row']['cohort'] for item in pending} == {'hosted'}
    assert owned[0]['reason'] == 'paid_slot_owned_by_existing_execution'


@pytest.mark.parametrize('change', ['inventory', 'model', 'input', 'text', 'provider', 'duplicate-call'])
def test_changed_inventory_output_or_slot_cannot_be_spent(population, change):
    saved = population.inventory()
    first, second = population.rows['hosted']
    if change == 'inventory':
        saved['outputs'].pop()
    elif change == 'model':
        population.owners[first['run_id']][0]['target'] = 'other-model'
    elif change == 'input':
        population.owners[first['run_id']][1]['input_ids'] = ['other-input']
    elif change == 'text':
        population.metadata['hosted'][first['sample_key']]['prepared_response'] = 'Changed answer'
    elif change == 'provider':
        population.slots['judge-hosted-0']['provider'] = 'google'
    else:
        population.owners[second['run_id']][0]['requests']['original-input']['judge_call_ids']['hosted'] = 'judge-hosted-0'
    with pytest.raises(ValueError):
        population.collect(saved)


def test_another_budget_cannot_stand_in_for_original_hosted_funding(population):
    population.budget.expected_plan_sha256 = 'b'*64
    pending, owned, unfunded, missing = population.collect()
    assert len(pending) == 3 and len(unfunded) == 2 and owned == missing == []
    assert all(row['cohort'] == 'hosted' for row in unfunded)


def test_all_output_build_handoff_uses_recorded_successor_and_keeps_old_slot_ownership(population,tmp_path,monkeypatch):
    old=population.budget
    old.root.mkdir()
    current=tmp_path/'current';current.mkdir()
    (current/'plan.json').write_text('{}')
    (old.root/'paid-circuit.json').write_text(json.dumps(dict(schema='ura-hosted-budget-superseded/1',
        status='superseded_not_a_target_failure',predecessor_plan_sha256='a'*64,
        successor=dict(path=str(current/'plan.json'),sha256='b'*64))))
    ledger=copy.deepcopy(population.ledger)
    ledger['attempts']['judge-hosted-0']={'1':{'state':'settled'}}
    successor=SimpleNamespace(root=current,expected_plan_sha256='b'*64,
        _load=lambda:({},ledger,population.slots))
    monkeypatch.setattr(subject.funding,'AttemptBudget',lambda *a:successor)
    monkeypatch.setattr(subject.funding,'load_bound_json',lambda *a:({},{}))
    pending,owned,unfunded,missing=population.collect()
    assert len(pending)==4 and len(owned)==1 and not unfunded and not missing
    assert all(item['budget']==dict(root=str(current),plan_sha256='b'*64) for item in pending)
    assert owned[0]['call_id']=='judge-hosted-0'
    assert len(population.reads)==1


def test_prepare_and_tools_preserve_all_output_coverage_without_calls(population, tmp_path, monkeypatch):
    from experiments.rig_web_app.catalog import build_argv
    monkeypatch.setattr(subject, 'AttemptBudget', lambda *_: population.budget)
    source = tmp_path/'inventory.json'
    source.write_text(json.dumps(population.inventory()))
    argv = build_argv('retained_inventory_judge_items', dict(
        **{'--inventory': str(source), '--local-view': str(tmp_path/'local'),
           '--hosted-view': str(tmp_path/'hosted'), '--budget-root': str(population.budget.root),
           '--budget-plan-sha256': 'a'*64, '--out': str(tmp_path/'items')}))
    assert subject.main(argv[3:]) == 0
    result = json.loads((tmp_path/'items/result.json').read_text())
    assert result['retained_outputs'] == result['selected_outputs'] == 5
    assert result['input_entries'] == 1 and result['new_budget_created'] is False
    assert result['target_calls'] == result['judge_calls'] == result['provider_http_calls'] == result['model_loads'] == 0


def test_repeated_unstarted_local_funding_selects_one_slot_in_declared_order(population, tmp_path):
    second = SimpleNamespace(root=tmp_path/'second', expected_plan_sha256='b'*64,
        _load=lambda: ({}, copy.deepcopy(population.ledger), copy.deepcopy(population.slots)))
    pending, _, _, _ = subject.collect_items(saved_inventory=population.inventory(), local_views=[],
        hosted_views=[], budgets=[population.budget, second])
    assert len(pending) == 5
    assert {item['budget']['root'] for item in pending} == {str(population.budget.root)}
