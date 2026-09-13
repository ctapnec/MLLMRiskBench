"""Actual final/checkpoint shapes feed campaign review, not synthetic grids."""
import json

import pytest

from experiments.rig_web_app.storage import ConsoleDB
from experiments.rig_web_app.human_review_inventory import read_campaign


@pytest.fixture
def indexed(tmp_path):
    database=tmp_path/'console.db';db=ConsoleDB(database)
    owner=db.create_workspace('Finished API','api');other=db.create_workspace('Other campaign','local')
    root=tmp_path/'runs';root.mkdir()
    def add(name, *, outcome='usable', evidence='measured', campaign=owner, final=False):
        params=dict(planning_source='fixture',planning_expected_behavior='refuse',planning_common_metrics_eligible=True,
                    policy_evaluable_turn=True,policy_challenge_index=0,policy_challenge_horizon=1,source_cluster_id='cluster')
        attempt=dict(run_id=name,id='attempt',target='test:model',datapoint_id='point',seed=0,params=params,
                     rendered_input=[dict(role='user',content='Synthetic input')])
        response=dict(run_id=name,attempt_id='attempt',target='test:model',
                      output_turns=[dict(role='assistant',content='Saved answer '+name)])
        path=root/(name+('.responses.jsonl' if final else '.responses.checkpoint.jsonl'))
        path.write_text(json.dumps(response if final else dict(attempt=attempt,response=response))+'\n')
        if final:(root/(name+'.attempts.jsonl')).write_text(json.dumps(attempt)+'\n')
        judgment=dict(run_id=name,attempt_id='attempt',label='refusal',raw=dict(
            model='test:model',source='fixture',risk_category='jailbreak',expected_behavior='refuse'))
        judge=root/(name+'.judge.jsonl');judge.write_text(json.dumps(dict(response=response,judgment=judgment))+'\n')
        identity=name+':attempt'
        db.publish_workspace_results(campaign,assignments=[dict(assignment_id=name,model='test:model',input_id='input',
            condition_id='condition-'+name,modality='text',framework='replay',corpus='fixture-arm',response_id=identity,evidence_class=evidence)],
            responses=[dict(response_id=identity,assignment_id=name,condition_id='condition-'+name,outcome=outcome,
                            truncated=True,source_ref=str(path)+':1')],
            judgments=[dict(response_id=identity,judge_id='local-cascade-test',status='valid',label='refusal',source_ref=str(judge)+':1')])
        return judge
    add('final',final=True);add('checkpoint');add('missing',outcome='missing');add('probe',evidence='diagnostic');add('unrelated',campaign=other)
    yield database,owner,root,add
    db.close()


def test_indexed_final_and_posthoc_outputs_preserve_conditions_and_exclusions(indexed):
    database,owner,root,_=indexed
    value=read_campaign(database,owner,root)
    assert value['measured_assignments']==3 and value['assignment_outcomes']=={'usable':2,'missing':1}
    assert len(value['outputs'])==2 and value['unavailable']==[]
    assert {row['response_id'] for row in value['outputs']}=={'final:attempt','checkpoint:attempt'}
    assert all(row['truncated']==1 and row['judgments']['local-cascade-test']['label']=='refusal' for row in value['outputs'])
    assert {row['metadata']['generation_condition'] for row in value['outputs']}=={'condition-final','condition-checkpoint'}
    assert all(row['metadata']['defense']=='not_recorded' for row in value['outputs'])
    assert value['target_calls']==value['judge_calls']==value['human_ratings']==0


def test_posthoc_judgment_cannot_follow_an_input_to_a_different_answer(indexed):
    database,owner,root,add=indexed;path=add('changed')
    record=json.loads(path.read_text());record['response']['output_turns'][0]['content']='Different answer'
    path.write_text(json.dumps(record)+'\n')
    with pytest.raises(ValueError,match='different saved answer'):read_campaign(database,owner,root)


def test_absent_input_context_is_reported_not_fabricated(indexed):
    database,owner,root,add=indexed;path=add('no-context')
    record=json.loads(path.read_text());record['judgment']['raw'].pop('risk_category')
    path.write_text(json.dumps(record)+'\n')
    value=read_campaign(database,owner,root)
    assert len(value['outputs'])==2
    assert [row['reason'] for row in value['unavailable']]==['source_context_unavailable']


def test_hosted_posthoc_verdict_uses_exact_saved_sample_key(indexed):
    database,owner,root,add=indexed;path=add('hosted-judge')
    record=json.loads(path.read_text());record.pop('response')
    record['judgment']['run_id']=None
    record['sample_key']='hosted-judge|test:model|attempt'
    path.write_text(json.dumps(record)+'\n')
    assert len(read_campaign(database,owner,root)['outputs'])==3
    record['sample_key']='different-run|test:model|attempt'
    path.write_text(json.dumps(record)+'\n')
    with pytest.raises(ValueError,match='output identity'):read_campaign(database,owner,root)
