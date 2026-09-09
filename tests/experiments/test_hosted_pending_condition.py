from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from experiments import hosted_pending_condition as subject
from experiments import hosted_campaign_prepare as prepare, hosted_campaign_budget as projection
from experiments import hosted_retained_execute as retained, run_matrix
from experiments.hosted_attempt_budget import AttemptBudget, create_budget
from experiments.hosted_request_tokens import count_request
from test_hosted_campaign_prepare import _distinct_request, _save
from ura.adapters.replay import retained_dialog


def _pending(tmp_path, monkeypatch, *, change_output=True):
    request, _initial, _ = _distinct_request(tmp_path, monkeypatch)
    receipt = prepare.prepare_campaign(request=request, request_descriptor={}, out_root=tmp_path/'old', allow_network_counts=False)
    old = json.loads(Path(receipt['programs'][0]['path']).read_text())
    old_budget = AttemptBudget(tmp_path/'old/budget', receipt['budget']['sha256'])
    started = old['jobs'][0]['input_ids'][0]
    call_id = old['requests'][started]['call_id']
    old_budget.reserve(call_id, 1, provider=old['provider'])
    old_budget.settle(call_id, 1, None)
    old_plan = json.loads((old_budget.root/'plan.json').read_text())
    old_ledger = json.loads((old_budget.root/'ledger.json').read_text())
    old_admissions = retained._validated_jobs(old, old_budget)
    entries = {key: entry for admission in old_admissions for key, entry in admission.entries.items()}
    pending = [key for job in old['jobs'] for key in job['input_ids'] if key != started]
    sources = copy.deepcopy(old['sources'])
    api = json.loads(Path(sources['api_config']['path']).read_text())
    output_tokens = 16384 if change_output else api[old['target']]['max_tokens']
    api[old['target']]['max_tokens'] = output_tokens
    sources['api_config'] = _save(tmp_path/'new-api.json', api)
    price = json.loads(Path(sources['pricing']['path']).read_text())
    configured = json.loads(Path(sources['budgets']['path']).read_text())
    config = [{'label': 'Pending fixture', 'spec': old['target'], 'provider': old['provider'],
               'model': old['target'].split(':', 1)[1], 'call_cap': len(pending), 'max_output_tokens': output_tokens}]
    projected = projection.build_projection(api_config=api, pricing=price, budgets=configured,
        descriptors={'api_config': prepare._portable(sources['api_config']),
                     'pricing_config': prepare._portable(sources['pricing']), 'budgets': prepare._portable(sources['budgets'])},
        pricing_as_of=old['pricing_as_of'], route_configuration=config)
    sources['budget_projection'] = _save(tmp_path/'new-projection.json', projected)
    target = run_matrix.build_target(old['target'], api_config=api[old['target']])
    requests = {}
    prices = old_admissions[0].prices
    for key in pending:
        body = target.build_request(retained_dialog(entries[key]['rendered_input']), seed=0)
        count = count_request(target, body, allow_network=False)
        requests[key] = {**old['requests'][key], 'max_output_tokens': output_tokens,
            'request_sha256': retained._sha(body), 'token_count': count, 'input_tokens': count['input_tokens'],
            'bound_microusd': retained._cost(count['input_tokens'], output_tokens,
                {'input': prices['reservation_input'], 'output': prices['reservation_output']})}
    replacement = {r['call_id']: r['bound_microusd'] for r in requests.values()}
    slots = [{**row, 'bound_microusd': replacement.get(row['call_id'], row['bound_microusd'])} for row in old_plan['planned_calls']]
    descriptor = create_budget(tmp_path/'new-budget', provider_budgets_microusd=old_plan['provider_budgets_microusd'],
        planned_calls=slots, protected_haiku_microusd=old_plan['protected_haiku_microusd'])
    _save(tmp_path/'new-budget/ledger.json', {**old_ledger, 'plan_sha256': descriptor['sha256']})
    _save(old_budget.root/'paid-circuit.json', {'schema': 'ura-hosted-budget-superseded/1', 'successor': descriptor})
    budget = AttemptBudget(tmp_path/'new-budget', descriptor['sha256'])
    jobs = []
    for number, selection in enumerate([pending[:1], pending[1:]]):
        job = copy.deepcopy(next(j for j in old['jobs'] if selection[0] in j['input_ids']))
        argv = job['argv']
        attacker = json.loads(Path(argv[argv.index('--attacker-config')+1]).read_text())
        attacker['replay']['retained_input_ids'] = selection
        attack_desc = _save(tmp_path/f'new-attacker-{number}.json', attacker)
        for flag in ['--diagnostic-canary', '--attestation-probe']:
            if flag in argv:
                argv.remove(flag)
        if number == 0:
            argv.append('--diagnostic-canary')
        for flag, value in {'--api-config': sources['api_config']['path'], '--api-config-sha256': sources['api_config']['sha256'],
            '--attacker-config': attack_desc['path'], '--attacker-config-sha256': attack_desc['sha256'],
            '--out': str(tmp_path/f'new-output-{number}'), '--max-total-target-calls': len(selection),
            '--max-total-judge-calls': len(selection), '--max-total-http-attempts': 4*len(selection)}.items():
            argv[argv.index(flag)+1] = str(value)
        job.update(name=f'new-{number}', input_ids=selection, purpose='diagnostic_canary' if number == 0 else 'measured_run')
        jobs.append(job)
    program = {**old, 'schema': subject.SCHEMA, 'sources': sources, 'budget_plan_sha256': descriptor['sha256'],
        'max_output_tokens': output_tokens, 'requests': requests, 'jobs': jobs,
        'predecessor': {'program': {k: receipt['programs'][0][k] for k in ['path', 'sha256', 'bytes']}}}
    def descriptor_for(path):
        import hashlib
        raw = path.read_bytes()
        return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    program['predecessor'].update(budget_plan=descriptor_for(old_budget.root/'plan.json'),
                                  budget_ledger=descriptor_for(old_budget.root/'ledger.json'))
    return program, budget, old_budget, started


def test_pending_condition_keeps_complete_paid_prefix_and_exact_remaining_inputs(tmp_path, monkeypatch):
    program, budget, old_budget, started = _pending(tmp_path, monkeypatch)
    before = (old_budget.root/'ledger.json').read_bytes()
    admitted = retained._validated_jobs(program, budget)
    assert len(admitted) == 2
    assert {key for a in admitted for key in a.entries} == set(program['requests'])
    assert started not in program['requests']
    assert all(a.program['max_output_tokens'] == 16384 for a in admitted)
    assert (old_budget.root/'ledger.json').read_bytes() == before


def test_pending_continuation_accepts_unchanged_requests_without_mutating_v1(tmp_path, monkeypatch):
    program, budget, old_budget, started = _pending(tmp_path, monkeypatch, change_output=False)
    with pytest.raises(ValueError, match='declared output settings'):
        retained._validated_jobs(program, budget)
    program['schema'] = subject.CONTINUATION_SCHEMA
    before = (old_budget.root/'ledger.json').read_bytes()
    admitted = retained._validated_jobs(program, budget)
    assert {key for a in admitted for key in a.entries} == set(program['requests'])
    assert started not in program['requests']
    assert (old_budget.root/'ledger.json').read_bytes() == before


@pytest.mark.parametrize('change', ['history', 'old_spending', 'omit_pending', 'include_paid', 'api_hash', 'request_hash', 'old_output'])
def test_pending_condition_rejects_changed_history_requests_or_incomplete_complement(tmp_path, monkeypatch, change):
    program, budget, old_budget, started = _pending(tmp_path, monkeypatch)
    if change == 'history':
        ledger = json.loads((budget.root/'ledger.json').read_text())
        ledger['attempts'] = {}
        _save(budget.root/'ledger.json', ledger)
    elif change == 'old_spending':
        _save(old_budget.root/'paid-circuit.json', {'schema': 'not-a-closed-budget'})
    elif change == 'omit_pending':
        del program['requests'][next(iter(program['requests']))]
    elif change == 'include_paid':
        program['requests'][started] = copy.deepcopy(next(iter(program['requests'].values())))
    elif change == 'api_hash':
        program['jobs'][0]['argv'][program['jobs'][0]['argv'].index('--api-config-sha256')+1] = '0'*64
    elif change == 'request_hash':
        next(iter(program['requests'].values()))['request_sha256'] = '0'*64
    else:
        old = retained._bound(program['predecessor']['program'])[0]
        argv = program['jobs'][0]['argv']
        argv[argv.index('--out')+1] = old['jobs'][0]['argv'][old['jobs'][0]['argv'].index('--out')+1]
    with pytest.raises(ValueError):
        retained._validated_jobs(program, budget)
