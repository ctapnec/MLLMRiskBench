"""Optional no-call selection binds requests to already funded campaign slots."""
import hashlib
import json
from pathlib import Path

import pytest

from experiments import hosted_retained_execute as funding
from experiments import retained_response_judge_execute as executor
from experiments import retained_response_judge_pair as subject
from experiments.rig_web_app.catalog import build_argv
from test_retained_response_judge_pair import _candidate, _population, PRICING, JUDGE


@pytest.fixture
def selection(tmp_path,monkeypatch):
    source=tmp_path/'source.json'
    source.write_text('{}')
    program=tmp_path/'program.json'
    program.write_text('{"target":"hosted:model-0"}')
    local,hosted=[_candidate(0,cohort='local')],[_candidate(0,cohort='hosted')]
    monkeypatch.setattr(subject,'load_pair_candidate_views',lambda *a:
        ((local,_population(1)),(hosted,_population(1)),{}))
    monkeypatch.setattr(subject,'load_pricing_condition',lambda *a,**k: PRICING)
    monkeypatch.setattr(executor,'_load_api_config',lambda *a,**k:({'max_tokens':512},{}))
    values={'--local-runner-view':str(tmp_path/'local.json'),'--hosted-runner-view':str(tmp_path/'hosted.json'),
        '--source-receipt':str(source),'--source-receipt-sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        '--judge-model':JUDGE,'--api-config-sha256':'a'*64,'--api-config':str(tmp_path/'api.json'),
        '--shared-budget-root':str(tmp_path/'budget'),'--shared-budget-sha256':'b'*64,
        '--program':str(program),'--program-sha256':hashlib.sha256(program.read_bytes()).hexdigest(),
        '--pricing-config':str(tmp_path/'pricing.json'),'--pricing-config-sha256':'a'*64,
        '--pricing-as-of':'2026-09-03','--pair-limit':'1','--out':str(tmp_path/'plan.json'),
        '--ack-hosted-judge-data-transfer':'on'}
    return values


def argv(values):
    return build_argv('retained_response_judge_pair',values)[3:]


def test_selection_prepares_existing_funding_without_judge_calls(selection,monkeypatch):
    captured=[]
    requests={'output':{'call_id':'existing-funded-slot'}}
    def prepare(**kwargs):
        captured.append(kwargs)
        plan=json.loads(kwargs['plan_path'].read_text())
        assert plan['selection']['selected_outputs']==2 and plan['judge_condition']['target_calls']==0
        assert kwargs['plan_sha256']==hashlib.sha256(kwargs['plan_path'].read_bytes()).hexdigest()
        return requests
    monkeypatch.setattr(funding,'build_matched_judge_requests',prepare)
    assert subject.main(argv(selection))==0
    assert captured[0]['programs']==[{'target':'hosted:model-0'}]
    assert str(captured[0]['budget'].root)==selection['--shared-budget-root']
    assert json.loads(Path(selection['--out']).with_suffix('.shared-requests.json').read_text())==requests
    assert not Path(selection['--shared-budget-root']).exists()


@pytest.mark.parametrize('missing',['--api-config','--shared-budget-root','--shared-budget-sha256','--program','--program-sha256'])
def test_incomplete_funding_cannot_silently_create_an_unfunded_plan(selection,monkeypatch,missing):
    selection.pop(missing)
    monkeypatch.setattr(subject,'load_pair_candidate_views',lambda *a:pytest.fail('Incomplete funding must fail before source reads'))
    with pytest.raises(SystemExit) as error:
        subject.main(argv(selection))
    assert error.value.code==2 and not Path(selection['--out']).exists()


def test_failed_slot_binding_does_not_publish_ready_requests(selection,monkeypatch):
    def fail(**_):raise ValueError('Actual full judge request exceeds its existing funded slot')
    monkeypatch.setattr(funding,'build_matched_judge_requests',fail)
    with pytest.raises(ValueError,match='existing funded slot'):
        subject.main(argv(selection))
    assert Path(selection['--out']).is_file()
    assert not Path(selection['--out']).with_suffix('.shared-requests.json').exists()


def test_plain_selector_keeps_original_no_funding_behavior(selection,monkeypatch):
    for flag in ['--api-config','--shared-budget-root','--shared-budget-sha256','--program','--program-sha256']:
        selection.pop(flag)
    monkeypatch.setattr(funding,'build_matched_judge_requests',lambda **_:pytest.fail('Not selected'))
    assert subject.main(argv(selection))==0
    assert not Path(selection['--out']).with_suffix('.shared-requests.json').exists()
