import json
from types import SimpleNamespace
import pytest
from experiments.rig_web_app import workspace_direct as subject
from experiments.rig_web_app.workspace_import import local_generation_condition
from experiments.rig_web_app.lifecycle import LifecycleMixin
from test_rig_web_local_publication import example,append


def saved(tmp_path,*,policy=False):
    db,owner,manifest,dp,record,paths=example(tmp_path,'anthropic:example')
    manifest['config']['run']['api_config']=dict(max_tokens=2048,temperature=0)
    raw=record['response']['raw']
    raw.update(provider='anthropic',resolved_model='example',transport_attempts=[dict(attempt=1,outcome='success')])
    if policy:raw.update(provider_refusal=True);record['response']['output_turns']=[]
    verdict=dict(run_id='run-sample',attempt_id='attempt-1',label='safe',raw=dict(risk_category='violence',source='sample-source',expected_behavior='refuse'))
    (tmp_path/'cell.manifest.json').write_text(json.dumps(manifest))
    for name,row in [('cell.attempts.jsonl',record['attempt']),('cell.responses.jsonl',record['response']),('cell.jsonl',verdict)]:append(tmp_path/name,row)
    return db,owner,manifest,record


@pytest.mark.parametrize('policy',[False,True])
def test_saved_direct_hosted_results_judging_usage_and_idempotent_publication(tmp_path,policy):
    db,owner,manifest,record=saved(tmp_path,policy=policy)
    try:
        for _ in range(2):
            counts=subject.publish(db,owner,tmp_path,{'anthropic:example'})
            assert counts==dict(assignments=1,responses=1,judgments=1,physical_attempts=1)
        rows=db._query('SELECT * FROM campaign_responses')
        assert len(rows)==1 and rows[0]['outcome']==('policy' if policy else 'usable')
        assert rows[0]['truncated']==1
        assert len(db._query('SELECT * FROM campaign_judgments'))==1
        costs=db._query('SELECT * FROM campaign_cost_attempts')
        assert len(costs)==1 and costs[0]['state']=='unknown' and costs[0]['cost_microusd'] is None
        assert costs[0]['output_tokens']==4096 and costs[0]['input_tokens']==17
        before=local_generation_condition(manifest['config']['run'])
        manifest['config']['run']['api_config']['max_tokens']=4096
        assert local_generation_condition(manifest['config']['run'])!=before
    finally:db.close()


def test_direct_hosted_import_rejects_different_target_before_publication(tmp_path):
    db,owner,_,_=saved(tmp_path)
    try:
        with pytest.raises(ValueError,match='target differs'):subject.publish(db,owner,tmp_path,{'openai:other'})
        assert not db._query('SELECT * FROM campaign_responses')
    finally:db.close()


def test_terminal_or_startup_publication_runs_once_without_repeating_generation(tmp_path,monkeypatch):
    db,owner,_,_=saved(tmp_path)
    directory=tmp_path/'job';directory.mkdir()
    db.attach_workspace_member(owner,'job','direct-job','collection')
    app=SimpleNamespace(db=db,repo_root=tmp_path)
    job=SimpleNamespace(command='run_matrix',argv=['--api','anthropic:example','--out',str(tmp_path)],directory=directory,job_id='direct-job')
    try:
        LifecycleMixin._publish_direct_hosted_job(app,job)
        marker=json.loads((directory/'campaign-publication.json').read_text())
        assert marker['status']=='published' and marker['responses']==1
        monkeypatch.setattr(subject,'publish',lambda *a:pytest.fail('Completed publication must not rescan'))
        LifecycleMixin._publish_direct_hosted_job(app,job)
        assert len(db._query('SELECT * FROM campaign_responses'))==1
    finally:db.close()
