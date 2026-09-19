"""Automatic setup keeps actual receipt shapes and never starts a model."""
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

import pytest

from test_builder_project_refresh import state  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401
from test_live_attestation import _record, _SPEC, _SCOPE
from ura.live_attestation import build_live_attestation_manifest
from ura.project_revision import project_revision_binding


@pytest.fixture
def campaign(state,monkeypatch):  # noqa: F811
    app, _, latest, _ = state
    (app.repo_root/'experiments/api-targets.json').write_text(json.dumps({_SPEC:{'modalities':['text','image']}}))
    owner=app.db.create_workspace('Automatic test','mixed')
    params=dict(latest,campaign_id=owner,work_kind='campaign',mode='measured',api=_SPEC,
                corpora='xstest_full',scope=_SCOPE,judges='rules,llm',attackers='replay',limit='2')
    app.db.save_workspace_definition(owner,params)
    raw=open(latest['project_revision'],'rb').read()
    project=json.loads(raw)
    canonical=app.results_root/(project['revision_id']+'.project-revision.json')
    canonical.parent.mkdir(exist_ok=True);canonical.write_bytes(raw)
    params['project_revision']=str(canonical)
    app.db.save_workspace_definition(owner,params)
    monkeypatch.setenv('URA_PROJECT_REVISION_MANIFEST',str(canonical))
    binding=project_revision_binding(project,dict(file=canonical.name,
        sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),revision_id=project['revision_id']))
    def add(name,mods=('text',),*,owner_override=None,age=1,scope=_SCOPE,spec=_SPEC,status='complete',project_sha=None):
        record=_record(modalities=list(mods),observed_at=(datetime.now(timezone.utc)-timedelta(hours=age)).isoformat().replace('+00:00','Z'))
        record.update(execution_scope_id=scope,requested_target_spec=spec)
        record['probe'].update(project_revision=copy.deepcopy(binding),
            harness_source_sha256=binding['harness_source_sha256'],driver_source_sha256=binding['driver_source_sha256'])
        if project_sha:record['probe']['project_revision']['sha256']=project_sha
        path=app.results_root/(name+'.json');path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(build_live_attestation_manifest([record])))
        with app.db._conn:
            app.db._conn.execute('INSERT INTO jobs(job_id,command,argv,state,exit_code,started_at) VALUES(?,?,?,?,?,?)',
                (name,'live_attestation',json.dumps(['python','--out',str(path)]),status,0 if status=='complete' else 2,datetime.now().timestamp()))
        if owner_override!='':app.db.attach_workspace_member(owner_override or owner,'job',name,'preparation')
        return path
    return app,params,add


def test_automatic_setup_selects_only_current_owned_checks_and_freezes_review(campaign):
    app,params,add=campaign
    text=add('text');image=add('image',('text','image'))
    other=app.db.create_workspace('Other','mixed')
    add('other',owner_override=other,age=0.1)
    add('expired',age=25);add('failed',status='failed');add('wrong-scope',scope='other')
    add('old-software',project_sha='b'*64);add('future',age=-1)
    add('other-model',spec='openai:unselected')
    result=app._builder_params(dict(params,setup_mode='automatic',_refresh_setup='yes'))
    assert {result['att_path1'],result['att_path2']}=={str(text),str(image)}
    assert result['max_age']=='24' and result['scope']==_SCOPE
    assert '/campaigns/'+params['campaign_id']+'/measured-' in result['out']
    assert not app.jobs
    reviewed=dict(result)
    add('newer',age=0.2)
    assert app._builder_params(reviewed)==reviewed, 'Reviewed receipt bytes/paths must not drift'
    assert app._builder_params(dict(reviewed,_refresh_setup='yes'))['out']==reviewed['out']


def test_manual_override_and_probe_mode(campaign):
    app,params,add=campaign;add('text')
    manual=dict(params,setup_mode='manual',out='custom',max_age='9',att_path1='explicit',att_sha1='a'*64)
    assert app._builder_params(manual)==manual
    probe=app._builder_params(dict(manual,setup_mode='automatic',mode='attestation_probe',_refresh_setup='yes'))
    assert not any(k.startswith('att_path') or k=='max_age' for k in probe)
    assert probe['scope']==_SCOPE


def test_automatic_output_covers_settings_and_preserves_review_or_preparation(campaign):
    app,params,_=campaign
    params=dict(params,setup_mode='automatic',mode='attestation_probe',_refresh_setup='yes')
    first=app._builder_params(params)
    for change in ({'cap_target':'23'}, {'judge_model':'openai:other'},
                   {'limit':'3'}, {'max_queries':'4'}):
        assert app._builder_params(dict(params,**change))['out']!=first['out']
    with app.db._conn:
        app.db._conn.execute('INSERT INTO jobs(job_id,command,argv,state,exit_code,run_kind,out_dir) VALUES(?,?,?,?,?,?,?)',
            ('preflight','run_matrix','[]','complete',0,'preflight',first['out']))
    assert app._builder_params(params)['out']==first['out']
    with app.db._conn:
        app.db._conn.execute('INSERT INTO jobs(job_id,command,argv,state,exit_code,run_kind,out_dir) VALUES(?,?,?,?,?,?,?)',
            ('done','run_matrix','[]','complete',0,'attestation_probe',first['out']))
    assert app._builder_params(first)==first, 'Review/recovery stays on the exact original output'
    second=app._builder_params(params)
    assert second['out']==first['out']+'-attempt-2'
    assert app._builder_params(dict(second,_refresh_setup='yes'))['out']==second['out']


def test_standalone_does_not_borrow_campaign_checks(campaign):
    app,params,add=campaign;add('campaign')
    add('standalone',owner_override='',scope='standalone')
    params={k:v for k,v in params.items() if k not in {'campaign_id','scope'}}
    result=app._builder_params(dict(params,work_kind='run',setup_mode='automatic',_refresh_setup='yes'))
    assert result['att_path1'].endswith('standalone.json')
    assert '/standalone/measured-' in result['out']


@pytest.mark.parametrize('width',[1440,390])
def test_automatic_fields_hidden_and_no_manual_receipts_on_save(browser,campaign,width):  # noqa: F811
    app,params,add=campaign;add('text');add('image',('text','image'))
    page=browser.new_page(viewport=dict(width=width,height=1000));errors=[];submissions=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    def route(route):
        req=route.request;url=urlsplit(req.url)
        form=dict(parse_qsl(req.post_data or '',keep_blank_values=True))
        if req.method=='POST':
            assert url.path=='/build/save';submissions.append(form)
        status,mime,body=app.handle(req.method,url.path+('?'+url.query if url.query else ''),form)
        if status==303:route.fulfill(status=status,headers={'Location':mime},body=body)
        else:route.fulfill(status=status,content_type=mime,body=body)
    page.route('http://setup.test/**',route)
    try:
        page.goto('http://setup.test/build?campaign_id='+params['campaign_id'])
        page.get_by_role('tab',name='Admission',exact=True).click()
        assert not page.locator('[name=att_path1]').is_visible()
        assert not page.locator('[name=project_revision]').is_visible()
        assert '2 completed' in page.locator('#automatic-transport-status').inner_text()
        page.locator('#setup-mode').select_option('manual')
        assert page.locator('[name=att_path1]').is_visible()
        page.locator('#setup-mode').select_option('automatic')
        page.get_by_role('tab',name='General',exact=True).click()
        page.get_by_role('button',name='Save campaign',exact=True).filter(visible=True).click()
        page.wait_for_url('**/build?campaign_id=*&saved=1#build-general')
        assert page.get_by_role('button',name='Review campaign',exact=True).filter(visible=True).count() == 1
        assert 'att_path1' not in submissions[-1] and 'out' not in submissions[-1]
        saved=app.db.workspace_definition(params['campaign_id'])
        assert saved['att_path1'] and saved['att_path2']
        assert not errors and not app.jobs
    finally:page.close()


def test_console_can_keep_runner_checkout_pinned(tmp_path,monkeypatch):
    from experiments.rig_web_app import server
    seen={}
    def create(**kwargs):seen.update(kwargs);return SimpleNamespace(state_dir=tmp_path/'state')
    monkeypatch.setattr(server,'RigWebApp',create)
    monkeypatch.setattr(server,'_serve',lambda *args:None)
    assert server.main(['--runner-root',str(tmp_path),'--state-dir',str(tmp_path/'state')])==0
    assert seen['repo_root']==tmp_path.resolve()


@pytest.mark.parametrize('width',[1440,390])
def test_saved_probe_action_derives_fields_and_reuses_existing_job(campaign,browser,width):  # noqa: F811
    app,params,add=campaign
    root=app.results_root/'completed-probe';root.mkdir(parents=True,exist_ok=True)
    probe=dict(params,mode='attestation_probe',out=str(root))
    with app.db._conn:
        app.db._conn.execute('INSERT INTO jobs(job_id,command,argv,builder_params,state,exit_code,run_kind,out_dir,started_at) VALUES(?,?,?,?,?,?,?,?,?)',
            ('probe','run_matrix','[]',json.dumps(probe),'complete',0,'attestation_probe',str(root),1))
    app.db.attach_workspace_member(params['campaign_id'],'job','probe','preparation')
    owner,values,existing=app._transport_check_from_job('probe',params['campaign_id'])
    assert owner==params['campaign_id'] and not existing
    assert values['--probe-root']==str(root) and values['--execution-scope-id']==_SCOPE
    path=add('ready')
    with app.db._conn:
        app.db._conn.execute('UPDATE jobs SET argv=? WHERE job_id=?',(json.dumps(['python','--probe-root',str(root),
            '--execution-scope-id',_SCOPE,'--out',str(path)]),'ready'))
    status,location,_=app.handle('POST','/jobs',{'command':'live_attestation','campaign_id':owner,'probe_job':'probe'})
    assert status==303 and location=='/jobs/ready'
    assert not app.jobs
    other=app.db.create_workspace('Not this campaign','mixed')
    with pytest.raises(ValueError,match='completed probe'):
        app._transport_check_from_job('probe',other)
    page=browser.new_page(viewport=dict(width=width,height=900))
    submissions=[]
    def route(route):
        req=route.request;url=urlsplit(req.url)
        if url.path=='/jobs/ready':
            route.fulfill(status=200,content_type='text/html',body='<h1>Existing transport check</h1>')
            return
        fields=dict(parse_qsl(req.post_data or '',keep_blank_values=True))
        if req.method=='POST':submissions.append(fields)
        status,mime,body=app.handle(req.method,url.path+('?'+url.query if url.query else ''),fields)
        if status==303:route.fulfill(status=status,headers={'Location':mime},body=body)
        else:route.fulfill(status=status,content_type=mime,body=body)
    page.route('http://setup.test/**',route)
    try:
        page.goto('http://setup.test/commands?cmd=live_attestation&campaign_id='+owner)
        select=page.locator('[name=probe_job]')
        assert select.is_visible()
        select.select_option('probe')
        assert not page.locator('input[name="--probe-root"]').is_visible()
        page.get_by_role('button',name='Prepare transport check',exact=True).click()
        page.wait_for_url('**/jobs/ready')
        assert len(submissions)==1 and submissions[0]['probe_job']=='probe'
        assert '--probe-root' not in submissions[0] and not app.jobs
    finally:page.close()
