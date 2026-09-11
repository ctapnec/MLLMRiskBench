import json

import pytest

from experiments.hosted_checkpoint_resume import resume_interrupted_transport
from test_hosted_retained_execute import _runner, _setup
from ura.runner import GlobalCallBudget


def setup(tmp_path):
    points, attacker, target, calls, admission = _setup(tmp_path)
    key = next(iter(admission.requests))
    call = admission.requests[key]["call_id"]
    admission.budget.reserve(call, 1, provider="openai")
    admission.budget.settle(call, 1, None)
    logical = GlobalCallBudget(max_target_calls=len(admission.requests), max_http_attempts=4*len(admission.requests))
    logical.charge_target(http_exposure=4)
    return points, attacker, target, calls, admission, key, logical


def test_interrupted_http_reuses_logical_slot_but_reserves_next_paid_attempt(tmp_path):
    points, attacker, target, calls, admission, key, logical = setup(tmp_path)
    proof = resume_interrupted_transport(admission,input_id=key,retained_input_ids=set(),held_snapshot=logical.snapshot())
    assert proof["next_http_attempt"] == 2 and proof["maximum_total_http_attempts"] == 4
    runner = _runner(attacker,target,admission)
    runner.call_budget = logical
    runner.run(points)
    assert len(calls) == len(runner.responses) == len(admission.requests)
    assert logical.target_calls == len(admission.requests)
    assert logical.http_attempts == 4*len(admission.requests)
    ledger = json.loads((admission.budget.root/'ledger.json').read_text())
    assert ledger['attempts'][key]['1'] == dict(state='unknown',actual_cost_microusd=None)
    assert ledger['attempts'][key]['2']['state'] == 'settled'


@pytest.mark.parametrize("condition",["retained","active","settled","exhausted","changed_logical"])
def test_interrupted_retry_never_replays_a_retained_answer_or_resets_attempts(tmp_path,condition):
    _,_,_,calls,admission,key,logical = setup(tmp_path)
    retained = {key} if condition == 'retained' else set()
    if condition in {'active','exhausted'}:
        for number in range(2,5 if condition == 'exhausted' else 3):
            admission.budget.reserve(key,number,provider='openai')
            if condition == 'exhausted':admission.budget.settle(key,number,None)
    if condition == 'settled':admission.budget.settle(key,1,3)
    if condition == 'changed_logical':logical.charge_target(http_exposure=4)
    with pytest.raises(ValueError):
        resume_interrupted_transport(admission,input_id=key,retained_input_ids=retained,held_snapshot=logical.snapshot())
    assert not calls
