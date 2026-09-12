import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import retained_hosted_judge_items as subject
from test_retained_prepared_judge_view import prepared  # noqa: F401
from test_retained_native_judge_execute import retained  # noqa: F401


@pytest.fixture
def funded(prepared,tmp_path,monkeypatch):  # noqa: F811
    records,value,path=prepared
    program_path=Path(value['programs'][0]['path'])
    program=json.loads(program_path.read_text())
    program['budget_plan_sha256']='a'*64
    program['requests']={}
    program['jobs'][0]['input_ids']=[]
    slots={}
    for index,record in enumerate(records.responses.values()):
        identity='input-'+str(index)
        call_id='judge-hosted-'+str(index)
        record['attempt']['params']['retained_origin']={'selection':{'input_identity_sha256':identity}}
        program['requests'][identity]={'judge_call_ids':{'hosted':call_id}}
        program['jobs'][0]['input_ids'].append(identity)
        slots[call_id]=dict(provider='anthropic',pool='judge')
    def save():
        program_path.write_text(json.dumps(program))
        value['programs'][0].update(sha256=hashlib.sha256(program_path.read_bytes()).hexdigest(),
            bytes=program_path.stat().st_size)
        path.write_text(json.dumps(value))
    save()
    ledger={'attempts':{}}
    reads=[]
    def load():
        reads.append(True)
        return {},ledger,slots
    budget=SimpleNamespace(root=tmp_path/'budget',expected_plan_sha256='a'*64,_load=load)
    monkeypatch.setattr(subject,'_budget_lock',lambda root:nullcontext())
    return SimpleNamespace(records=records,prepared=path,program=program,save=save,
        budget=budget,ledger=ledger,slots=slots,reads=reads)


def test_saved_outputs_bind_their_own_funded_calls_with_one_ledger_read(funded):
    items,owned,audit=subject.collect_items(funded.prepared,funded.budget)
    assert len(items)==2 and owned==[] and audit['eligible_usable_outputs']==2
    assert {item['call_id'] for item in items}==set(funded.slots)
    assert {item['row']['attempt_id'] for item in items}==set(funded.records.responses)
    assert len(funded.reads)==1


def test_unfinished_paid_slot_stays_with_its_existing_executor_not_called_again(funded,tmp_path):
    funded.ledger['attempts']['judge-hosted-0']={'1':{'state':'reserved'}}
    result=subject.prepare(preparation=funded.prepared,budget=funded.budget,out=tmp_path/'items')
    assert result['selected_outputs']==result['existing_execution_owned']==1
    assert result['existing_judgments_reused'] is False
    assert result['provider_http_calls']==result['judge_calls']==0
    items=json.loads((tmp_path/'items/validated-items.json').read_text())
    assert [item['call_id'] for item in items]==['judge-hosted-1']


def test_empty_outputs_remain_in_coverage_without_judging_or_budget_work(funded,tmp_path):
    for record in funded.records.responses.values():
        record['response']['output_turns']=[]
    result=subject.prepare(preparation=funded.prepared,budget=funded.budget,out=tmp_path/'empty')
    assert result['selected_outputs']==0
    assert result['population']['excluded_missing_outputs']==2


@pytest.mark.parametrize('change',['budget','target','input','duplicate-slot','provider','pool'])
def test_changed_output_owner_or_funding_is_rejected(funded,change):
    if change=='budget':
        funded.program['budget_plan_sha256']='b'*64
    elif change=='target':
        funded.program['target']='openai:different'
    elif change=='input':
        funded.program['jobs'][0]['input_ids']=['different']
    elif change=='duplicate-slot':
        funded.program['requests']['input-1']=copy.deepcopy(funded.program['requests']['input-0'])
    elif change=='provider':
        funded.slots['judge-hosted-0']['provider']='google'
    else:
        funded.slots['judge-hosted-0']['pool']='target'
    funded.save()
    with pytest.raises(ValueError):
        subject.collect_items(funded.prepared,funded.budget)


def test_tools_builds_the_same_no_call_cli(funded,tmp_path,monkeypatch):
    from experiments.rig_web_app.catalog import build_argv
    monkeypatch.setattr(subject,'AttemptBudget',lambda root,digest:funded.budget)
    argv=build_argv('retained_hosted_judge_items',{'--preparation':str(funded.prepared),
        '--budget-root':str(funded.budget.root),'--budget-plan-sha256':'a'*64,'--out':str(tmp_path/'tools')})
    assert subject.main(argv)==0
    result=json.loads((tmp_path/'tools/result.json').read_text())
    assert result['selected_outputs']==2 and result['judge_calls']==result['provider_http_calls']==0
