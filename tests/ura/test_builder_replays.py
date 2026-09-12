import hashlib
import json
from types import SimpleNamespace

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app import builder_replays as subject
from experiments.rig_web_app.catalog import build_argv


@pytest.fixture
def study(tmp_path,monkeypatch):
    app = RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,
        gpu_hardware={},system_hardware={})
    owner = app.db.create_workspace('Matched replay preparation','api')
    api = {'example:model':{'modalities':['text','image'],'max_tokens':4096}}
    route = dict(label='model',provider='example',model='model',spec='example:model',max_output_tokens=4096)
    monkeypatch.setattr(subject,'selected_routes',lambda app,params: ([dict(route)],api))
    jobs = {}
    source = tmp_path/'source.json'
    source.write_text('{}')
    forecast = tmp_path/'forecast.json'
    forecast.write_text('{}')
    jobs['source-job'] = dict(command='retained_local_sources',state='complete',exit_code=0,
        argv=json.dumps(['python','-m','experiments.retained_local_sources','--run-id','run-one','--out',str(source)]))
    args = ['python','-m','experiments.hosted_campaign_budget','--out',str(forecast),'--pricing-as-of','2026-09-12']
    for name,data in [('api-config',api),('route-configuration',[dict(route,call_cap=12)])]:
        path = tmp_path/(name+'.json')
        path.write_text(json.dumps(data))
        args += ['--'+name,str(path),'--'+name+'-sha256',hashlib.sha256(path.read_bytes()).hexdigest()]
    jobs['budget-job'] = dict(command='hosted_campaign_budget',state='complete',exit_code=0,argv=json.dumps(args))
    monkeypatch.setattr(app.db,'load_job',lambda name: jobs.get(name))
    monkeypatch.setattr(app.db,'workspace_for_job',lambda name: owner)
    calls = []
    monkeypatch.setattr(app,'start_job',lambda command,values,**kw:
        calls.append((command,values,kw)) or SimpleNamespace(job_id='replays-job'))
    params = dict(work_kind='campaign',campaign_id=owner,retained_sources_job='source-job',retained_budget_job='budget-job',
        retained_source_runs='["run-one"]',api='example:model',retained_budget_caps='{"example:model":12}',
        retained_pricing_date='2026-09-12')
    try:
        yield app,params,calls,jobs
    finally:
        app.close()


def test_normal_build_resolves_owned_preparation_jobs_and_retains_workflow(study):
    app,params,calls,_ = study
    status,location,_ = app.handle('POST','/build/prepare-replays',params)
    assert status == 303 and location == '/jobs/replays-job'
    command,values,kwargs = calls[0]
    assert command == 'hosted_selected_replays' and kwargs == {'campaign_id':params['campaign_id']}
    assert build_argv(command,values)[2] == 'experiments.hosted_selected_replays'
    assert '--verify-artifact-sha256' not in values
    saved = app.db.workspace_definition(params['campaign_id'])
    assert saved['retained_replays_job'] == 'replays-job' and saved['retained_budget_job'] == 'budget-job'
    assert len(calls) == 1


@pytest.mark.parametrize('change',[{'retained_source_runs':'["other"]'},
    {'retained_budget_caps':'{"example:model":13}'},{'retained_pricing_date':'2026-09-11'},
    {'retained_budget_job':'unknown'},{'retained_budget_caps':'{"example:model":true}'}])
def test_changed_selection_cannot_use_stale_preparations(study,change):
    app,params,calls,_ = study
    with pytest.raises(ValueError):
        subject.prepare_replays(app,dict(params,**change))
    assert not calls


@pytest.mark.parametrize('state,code',[('running',None),('failed',1),('complete',2)])
def test_unfinished_or_failed_jobs_are_not_prepared_inputs(study,state,code):
    app,params,calls,jobs = study
    jobs['source-job'].update(state=state,exit_code=code)
    with pytest.raises(ValueError):
        subject.prepare_replays(app,params)
    assert not calls


def test_other_campaign_job_cannot_be_silently_adopted(study,monkeypatch):
    app,params,calls,_ = study
    monkeypatch.setattr(app.db,'workspace_for_job',lambda name: 'other-owner')
    with pytest.raises(ValueError):
        subject.prepare_replays(app,params)
    assert not calls


@pytest.mark.parametrize('command',['hosted_retained_inputs','hosted_selected_replays'])
def test_preparation_receives_source_locations_but_no_provider_credentials(study,monkeypatch,command):
    app,_,_,_ = study
    monkeypatch.setattr(app,'_load_registry',lambda *args: {'arm':{'path_env':'URA_TEST_SOURCE_PATH'}})
    for name,value in [('URA_TEST_SOURCE_PATH','/corpus'),('URA_MEDIA_ROOTS','/media'),
        ('OPENAI_API_KEY','not-a-real-key'),('HF_TOKEN','not-a-real-token')]:
        monkeypatch.setenv(name,value)
    env = app._generic_child_environment(command,{})
    assert env['URA_TEST_SOURCE_PATH'] == '/corpus' and env['URA_MEDIA_ROOTS'] == '/media'
    assert 'OPENAI_API_KEY' not in env and 'HF_TOKEN' not in env


def test_replay_panel_owns_its_submit_and_saved_job_link():
    assert subject.replay_panel({}) == ''
    page = subject.replay_panel(dict(retained_budget_job='budget',retained_replays_job='saved'))
    assert "form='builder' formaction='/build/prepare-replays'" in page
    assert "name='retained_replays_job' value='saved'" in page
    assert 'does not start execution' in page
