import copy
import json

import pytest

from experiments.hosted_checkpoint_resume import renew_interrupted_transport
from experiments.hosted_retained_execute import _Admission
from test_hosted_checkpoint_resume import setup
from test_hosted_retained_execute import _runner
from ura.adapters.replay import ReplayAttacker
from ura.runner import GlobalCallBudget, Runner


def prepared(tmp_path):
    points, attacker, target, calls, original, key, old_logical = setup(tmp_path)
    retained = set(original.requests) - {key}
    for _ in retained:
        old_logical.charge_target(http_exposure=4)
    snapshot = dict(old_logical.snapshot(), deadline_epoch=1)
    original.job['argv'] = ['--out', str(tmp_path / 'old')]
    narrowed = ReplayAttacker(replay_artifact=str(tmp_path / 'replay.json'),
        replay_artifact_sha256=attacker.replay_artifact_sha256, retained_input_ids=[key])
    resumed = _Admission(program=original.program,
        job=dict(purpose=original.job['purpose'], input_ids=[key], argv=['--out', str(tmp_path / 'new')]),
        budget=original.budget, attacker=narrowed,
        requests={key: original.requests[key]}, prices=original.prices)
    return points, narrowed, target, calls, original, resumed, key, retained, snapshot


def test_expired_run_continues_exact_paid_prefix_once_and_preserves_original(tmp_path):
    points, attacker, target, calls, old, new, key, retained, snapshot = prepared(tmp_path)
    before = copy.deepcopy(snapshot)
    review = renew_interrupted_transport(old, new, input_id=key,
        retained_input_ids=retained, held_snapshot=snapshot)
    assert review['next_http_attempt'] == 2 and review['new_campaign_inputs'] == 0
    runner = _runner(attacker, target, new)
    runner.call_budget = GlobalCallBudget(max_target_calls=1, max_http_attempts=4)
    checkpoint = tmp_path / 'new' / 'answer.responses.checkpoint.jsonl'
    checkpoint.parent.mkdir()
    runner.run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    assert len(calls) == len(runner.responses) == 1
    assert snapshot == before and old.transport_recoveries == {}
    ledger = json.loads((new.budget.root / 'ledger.json').read_text())
    assert ledger['attempts'][key]['1'] == dict(state='unknown', actual_cost_microusd=None)
    assert ledger['attempts'][key]['2']['state'] == 'settled'
    assert set(ledger['attempts']) == {key}
    resumed = _runner(attacker, target, new)
    resumed.run(points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 1


@pytest.mark.parametrize('change', ['retained', 'request', 'origin', 'active', 'settled',
    'exhausted', 'deadline', 'logical', 'same_output', 'used_output', 'recovery'])
def test_renewal_rejects_changed_condition_or_existing_output_before_http(tmp_path, change):
    _, _, _, calls, old, new, key, retained, snapshot = prepared(tmp_path)
    if change == 'retained': retained.add(key)
    if change == 'request': new.requests[key]['request_sha256'] = '0' * 64
    if change == 'origin': new.entries[key]['origin']['delivered_input_sha256'] = '0' * 64
    if change == 'active': new.budget.reserve(key, 2, provider='openai')
    if change == 'settled': new.budget.settle(key, 1, 1)
    if change == 'exhausted':
        for ordinal in range(2, 5):
            new.budget.reserve(key, ordinal, provider='openai')
            new.budget.settle(key, ordinal, None)
    if change == 'deadline': snapshot['deadline_epoch'] = 1e20
    if change == 'logical': snapshot['target_calls'] -= 1
    if change == 'same_output': new.job['argv'] = old.job['argv'][:]
    if change == 'used_output':
        directory = tmp_path / 'new'
        directory.mkdir()
        (directory / 'grid.budget.json').write_text('{}')
    if change == 'recovery': new.transport_recoveries[key] = 1
    with pytest.raises(ValueError):
        renew_interrupted_transport(old, new, input_id=key,
            retained_input_ids=retained, held_snapshot=snapshot)
    assert not calls
