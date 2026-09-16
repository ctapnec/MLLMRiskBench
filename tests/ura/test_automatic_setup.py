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
def campaign(state):  # noqa: F811
    app, _, latest, _ = state
    (app.repo_root/'experiments/api-targets.json').write_text(json.dumps({_SPEC:{'modalities':['text','image']}}))
    owner=app.db.create_workspace('Automatic test','mixed')
    params=dict(latest,campaign_id=owner,work_kind='campaign',mode='measured',api=_SPEC,
                corpora='xstest_full',scope=_SCOPE,judges='rules,llm',attackers='replay',limit='2')
    app.db.save_workspace_definition(owner,params)
    raw=open(latest['project_revision'],'rb').read()
    project=json.loads(raw)
    binding=project_revision_binding(project,dict(file=__import__('pathlib').Path(latest['project_revision']).name,
        sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),revision_id=project['revision_id']))
    def add(name,mods=('text',),*,owner_override=None,age=1,scope=_SCOPE,spec=_SPEC,status='complete',project_sha=None):
        record=_record(modalities=list(mods),observed_at=(datetime.now(timezone.utc)-timedelta(hours=age)).isoformat())
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
        page.wait_for_url('**/campaigns/**')
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
