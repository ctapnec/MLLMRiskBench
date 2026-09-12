"""CLI and console preserve the exact pre-funded judging requests."""
import hashlib
import json

import pytest

from experiments import retained_response_judge_pair_execute as subject
from experiments.rig_web_app.catalog import build_argv
from test_retained_judge_shared_budget import HookHaiku, prepared_shared


def invocation(prepared, budget=None, requests=None):
    values = {'--plan':str(prepared['plan_path']), '--local-runner-view':str(prepared['runner_view']),
        '--hosted-runner-view':str(prepared['runner_view']), '--source-receipt':str(prepared['source_receipt']),
        '--api-config':str(prepared['api_config']), '--pricing-config':str(prepared['pricing_config']),
        '--out':str(prepared['out']), '--ack-paid-execution':'on', '--retain-invalid-verdicts':'on'}
    if budget is not None:
        path = prepared['out'].parent/'shared-requests.json'
        raw = (json.dumps(requests,sort_keys=True)+'\n').encode()
        path.write_bytes(raw)
        values.update({'--shared-budget-root':str(budget.root),
            '--shared-budget-sha256':budget.expected_plan_sha256, '--shared-requests':str(path),
            '--shared-requests-sha256':hashlib.sha256(raw).hexdigest()})
    argv=build_argv('retained_response_judge_pair_execute',values)
    return argv[argv.index('experiments.retained_response_judge_pair_execute')+1:]


def test_cli_uses_existing_budget_and_resumes_without_repeating_calls(tmp_path,monkeypatch):
    prepared,kwargs,budget,config,_=prepared_shared(tmp_path,monkeypatch)
    fake=HookHaiku(config)
    captured=[]
    # The pair reconciler has separate exact-input tests. Here execute the real
    # paid-attempt/checkpoint engine through the actual CLI and console catalog.
    def execute(**values):
        captured.append(values)
        from experiments.retained_response_judge_execute import execute as retained
        return retained(plan_path=values['plan_path'],runner_view=values['local_runner_view'],
            source_receipt=values['source_receipt'],api_config=values['api_config'],
            pricing_config=values['pricing_config'],out=values['out'],judge_factory=lambda *_:fake,
            shared_budget=values['shared_budget'],shared_requests=values['shared_requests'])
    monkeypatch.setattr(subject,'execute',execute)
    argv=invocation(prepared,budget,kwargs['shared_requests'])
    assert subject.main(argv)==0
    assert fake.http_calls==2
    assert subject.main(argv)==0
    assert fake.http_calls==2
    assert budget.snapshot()['pools']['anthropic:judge']['settled_attempts']==2
    assert captured[0]['shared_budget'].root==budget.root
    assert captured[0]['shared_requests']==kwargs['shared_requests']
    assert captured[0]['retain_invalid_verdicts'] is True


@pytest.mark.parametrize('missing',['--shared-budget-root','--shared-budget-sha256',
    '--shared-requests','--shared-requests-sha256'])
def test_partial_shared_binding_cannot_fall_back_to_independent_spending(tmp_path,monkeypatch,missing):
    prepared,kwargs,budget,_,_=prepared_shared(tmp_path,monkeypatch)
    argv=invocation(prepared,budget,kwargs['shared_requests'])
    del argv[argv.index(missing):argv.index(missing)+2]
    monkeypatch.setattr(subject,'execute',lambda **_:pytest.fail('Execution must not start'))
    with pytest.raises(SystemExit) as error:
        subject.main(argv)
    assert error.value.code==2
    assert budget.reserved_attempt_counts([r['call_id'] for r in kwargs['shared_requests'].values()])=={
        r['call_id']:0 for r in kwargs['shared_requests'].values()}


def test_changed_request_receipt_fails_before_execution(tmp_path,monkeypatch):
    prepared,kwargs,budget,_,_=prepared_shared(tmp_path,monkeypatch)
    argv=invocation(prepared,budget,kwargs['shared_requests'])
    from pathlib import Path
    path=Path(argv[argv.index('--shared-requests')+1])
    path.write_text('{}\n')
    monkeypatch.setattr(subject,'execute',lambda **_:pytest.fail('Execution must not start'))
    with pytest.raises(ValueError):
        subject.main(argv)


def test_original_cli_does_not_add_an_implicit_budget(tmp_path,monkeypatch):
    prepared,_,_,_,_=prepared_shared(tmp_path,monkeypatch)
    captured=[]
    monkeypatch.setattr(subject,'execute',lambda **values:captured.append(values) or tmp_path)
    assert subject.main(invocation(prepared))==0
    assert 'shared_budget' not in captured[0] and 'shared_requests' not in captured[0]
