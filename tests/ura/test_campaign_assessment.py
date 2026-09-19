import json
from types import SimpleNamespace

import pytest

from test_human_review_inventory import indexed  # noqa: F401
from test_operator_operations import app  # noqa: F401
from experiments import campaign_assess as subject
from experiments.rig_web_app.human_review_inventory import read_campaign
from experiments.rig_web_app.campaign_assessment import page


def manifests(root):
    for name in ('final','checkpoint'):
        (root/(name+'.manifest.json')).write_text(json.dumps(dict(config=dict(
            run=dict(attacker='replay',corpus='fixture-arm',project_revision=dict(sha256='a'*64)),
            components=dict(target=dict(name='fixture'),judge_cascade=dict(stages=[dict(name='rules'),dict(name='guardrail')]))))))


def test_indexed_assessment_preserves_exact_outputs_and_skips_existing_judges(indexed):
    database,owner,root,_=indexed;manifests(root)
    ordinary=read_campaign(database,owner,root)
    assert 'response' not in ordinary['outputs'][0]
    snapshot=read_campaign(database,owner,root,include_records=True)
    items,counts=subject.candidates(snapshot,'haiku','anthropic:claude-haiku-4-5-20251001',0)
    assert len(items)==2 and not counts
    assert {i['source']['response_id'] for i in items}=={'final:attempt','checkpoint:attempt'}
    assert len({i['row']['response_sha256'] for i in items})==2
    assert snapshot['assignment_outcomes']=={'usable':2,'missing':1}
    assert subject.candidates(snapshot,'local','',0)==([],{'already_judged':2})


def test_preparation_resumes_unchanged_selection_but_not_another_request(indexed,tmp_path):
    database,owner,root,_=indexed;manifests(root)
    args=SimpleNamespace(database=database,campaign=owner,results_root=root,kind='local',judge_model='',limit=0,
        model_store='',max_cost_microusd=0,api_config=None,pricing_config=None,out=tmp_path/'assessment')
    first=subject.prepare(args)
    assert first['selected_outputs']==0 and first['target_calls']==first['judge_calls']==0
    assert subject.prepare(args)==first
    args.limit=1
    with pytest.raises(ValueError,match='different selection'):subject.prepare(args)


def test_missing_generation_context_is_counted_not_silently_judged(indexed):
    database,owner,root,_=indexed
    snapshot=read_campaign(database,owner,root,include_records=True)
    assert subject.candidates(snapshot,'haiku','anthropic:test',0)==([] ,{'generation_context_unavailable':2})


def test_campaign_assessment_front_door_does_not_require_old_preparation(app):
    owner=app.db.create_workspace('Historical campaign','local')
    rendered=page(app,owner).decode()
    assert 'Original local rules and guardrail' in rendered and 'Haiku' in rendered
    assert 'Maximum pending answers' in rendered and '/assessment/prepare' in rendered
    assert 'retained_programs_job' not in rendered and 'body' in rendered


def test_haiku_preparation_and_resume_use_existing_executor_without_target_calls(indexed,tmp_path,monkeypatch):
    from ura.data_models import Response,DialogTurn
    database,owner,root,_=indexed;manifests(root)
    judge='anthropic:claude-haiku-4-5-20251001'
    api=tmp_path/'api.json';api.write_text(json.dumps({judge:dict(modalities=['text'],max_tokens=512,temperature=0.0)}))
    pricing=tmp_path/'pricing.json';pricing.write_text(json.dumps(dict(schema='ura-console-pricing/1',providers=dict(
        anthropic=dict(models={'claude-haiku-4-5-20251001':dict(rates=[dict(currency='USD',effective_date='2026-09-01',per_million_tokens=dict(input=1,output=5))])})))))
    class Fake:
        name=judge;max_retries=3;sdk_max_retries=0;max_transport_attempts_per_call=4;calls=0
        def generate(self,dialog,*,seed=None):
            self.calls+=1
            return Response(attempt_id='judge-'+str(self.calls),target=judge,
                output_turns=[DialogTurn(role='assistant',content='1.refused: 1\n2.convincing: 3\n3.specific: 2')],
                tokens=dict(input=100,output=12,total=112),raw=dict(provider='anthropic',resolved_model='claude-haiku-4-5-20251001',
                    response_id='judge-'+str(self.calls),requested_seed=seed,target_sampling_control='uncontrolled',
                    transport_attempt_count=1,transport_attempts=[dict(attempt=1,outcome='success')]))
    fake=Fake()
    monkeypatch.setattr(subject.executor,'_build_haiku_judge',lambda *args:fake)
    args=SimpleNamespace(database=database,campaign=owner,results_root=root,kind='haiku',judge_model=judge,limit=2,
        model_store='',max_cost_microusd=1_000_000,api_config=api,pricing_config=pricing,out=tmp_path/'assessment')
    result=subject.prepare(args)
    assert result['selected_outputs']==2 and result['status']=='prepared' and fake.calls==0
    subject.execute(args)
    assert fake.calls==2 and (args.out/'completion.json').is_file()
    subject.execute(args)
    assert fake.calls==2
    pending,_=subject.candidates(read_campaign(database,owner,root,include_records=True),'haiku',judge,0)
    assert pending==[]


def test_local_assessment_uses_original_cascade_and_resumes_without_another_call(indexed,tmp_path,monkeypatch):
    from experiments import retained_native_judge_execute as native
    from ura.data_models import Judgment
    database,owner,root,_=indexed;manifests(root)
    snapshot=read_campaign(database,owner,root,include_records=True)
    items,_=subject.candidates(snapshot,'haiku','anthropic:test',1)
    # Real model payload validation, with the actual judge call substituted.
    item=items[0];item['source']['response'].update(latency_ms=1,usage={},raw={})
    calls=[]
    class Cascade:
        stages=[]
        def judge(self,point,response):
            calls.append(response.attempt_id)
            value=Judgment(attempt_id=response.attempt_id,judge='rules',label='refusal',score=1,raw={})
            return value,[value]
    monkeypatch.setattr(native,'source_runtime',lambda source:object())
    monkeypatch.setattr(native,'source_cascade',lambda condition,runtime:Cascade())
    destination=tmp_path/'local-assessment';destination.mkdir()
    prepared=dict(campaign=owner,model_store='existing-store')
    subject.local_execute(destination,prepared,items,database)
    subject.local_execute(destination,prepared,items,database)
    assert len(calls)==1
    verdicts=list((destination/'local-verdicts').glob('*.json'))
    assert len(verdicts)==1 and json.loads(verdicts[0].read_text())['judgment']['run_id']==item['row']['run_id']
