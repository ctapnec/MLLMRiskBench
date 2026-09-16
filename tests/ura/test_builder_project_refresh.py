"""A saved draft must not launch an acquisition plan for yesterday's code."""
import hashlib
from urllib.parse import parse_qsl, urlsplit

import pytest

from experiments.rig_web import RigWebApp
from test_project_revision import _git, _repo
from test_rig_web_busy_browser import browser  # noqa: F401
from ura.project_revision import create_project_revision, project_revision_bytes


@pytest.fixture
def state(tmp_path, monkeypatch):
    repo, driver, harness, old_commit = _repo(tmp_path)
    old = project_revision_bytes(create_project_revision(old_commit, driver, harness_module_path=harness))
    driver.write_text('DRIVER = 2\n')
    _git(repo, 'add', '.')
    _git(repo, 'commit', '-qm', 'updated deployment')
    current = project_revision_bytes(create_project_revision(_git(repo,'rev-parse','HEAD'),driver,harness_module_path=harness))
    receipts=[]
    for name, raw in (('old',old),('current',current)):
        path=tmp_path/(name+'.json');path.write_bytes(raw)
        receipts.append(dict(project_revision=str(path),project_revision_sha=hashlib.sha256(raw).hexdigest()))
    previous, latest=receipts
    monkeypatch.setenv('URA_PROJECT_REVISION_MANIFEST',latest['project_revision'])
    monkeypatch.setenv('URA_PROJECT_REVISION_SHA256',latest['project_revision_sha'])
    app=RigWebApp(results_root=repo/'runs',state_dir=repo/'runs/rig-web',repo_root=repo,
        gpu_hardware={},system_hardware={})
    monkeypatch.setattr(app,'start_job',lambda *a,**k:pytest.fail('Review must not launch'))
    yield app, previous, latest, old
    app.close()


@pytest.mark.parametrize('captured',[False,True])
def test_stale_receipt_rejected_before_private_files_or_acquisition_job(state, monkeypatch, captured):
    app,previous,latest,old=state
    params=dict(previous,mode='attestation_probe',corpora='synth',attackers='replay',judges='rules,llm',
        out=str(app.results_root/'probe'),scope='demo',limit='1')
    with pytest.raises(ValueError,match='Use current project receipt'):
        app._compose_from_builder(params)
    assert not list(app.results_root.rglob('*.json'))
    # Exercise the plan controller, including a previously reviewed snapshot.
    monkeypatch.setattr(app,'_validate_builder',lambda params:{})
    params,snapshot,_=app._capture_execution_config_snapshot(params)
    with pytest.raises(ValueError,match='Use current project receipt'):
        app._start_model_acquisition_plan(dict(params,_model_acquisition_next='preflight'),
            execution_snapshot=snapshot if captured else None)
    assert not app.jobs and not app.db.load_jobs()
    assert app._project_revision_snapshot(previous)==(old,previous['project_revision_sha'])
    path,digest=app._materialize_selected_project_revision(dict(latest,mode='attestation_probe'))
    assert digest==latest['project_revision_sha'] and path.is_file()
    assert open(previous['project_revision'],'rb').read()==old


def test_stale_receipt_does_not_block_offline_work(state):
    app,previous,_,_=state
    path,_=app._materialize_selected_project_revision(dict(previous,mode='dry_run'))
    assert path.is_file()


@pytest.mark.parametrize('width',[1440,390])
def test_refresh_button_keeps_other_choices_and_is_explicitly_saved(browser,state,width):  # noqa: F811
    app,previous,latest,old=state
    params=dict(previous,work_kind='campaign',campaign_name='Existing Qwen draft',mode='attestation_probe',
        corpora='xstest_full',modality_scope='text,image',attackers='replay',judges='rules,llm',limit='1',
        sample_seed='0',scope='demo',cap_target='16',cap_judge='16',cap_http='1',deadline='3600',
        out=str(app.results_root/'probe-text'))
    saved=app._save_build_campaign(params)
    owner=saved['campaign_id']
    page=browser.new_page(viewport=dict(width=width,height=1000))
    requests=[];errors=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    def route(route):
        req=route.request;url=urlsplit(req.url)
        requests.append((req.method,url.path))
        if req.method=='POST':assert url.path=='/build/save'
        status,mime,body=app.handle(req.method,url.path+('?'+url.query if url.query else ''),
            dict(parse_qsl(req.post_data or '',keep_blank_values=True)))
        if status==303:route.fulfill(status=status,headers={'Location':mime},body=body)
        else:route.fulfill(status=status,content_type=mime,body=body)
    page.route('http://refresh.test/**',route)
    try:
        page.goto('http://refresh.test/build?campaign_id='+owner)
        page.get_by_role('tab',name='Admission',exact=True).click()
        assert 'differs' in page.locator('#project-receipt-refresh-status').inner_text()
        assert page.locator('[name=project_revision]').input_value()==previous['project_revision']
        assert page.locator('#use-current-project-receipt').evaluate(
            'e=>e.getBoundingClientRect().top-e.parentElement.previousElementSibling.getBoundingClientRect().bottom') >= 12
        before=page.locator('form#builder').evaluate('f=>Object.fromEntries(new FormData(f))')
        n=len(requests)
        page.get_by_role('button',name='Use current project receipt',exact=True).click()
        after=page.locator('form#builder').evaluate('f=>Object.fromEntries(new FormData(f))')
        assert {k for k in before if before[k]!=after[k]}=={'project_revision','project_revision_sha'}
        assert len(requests)==n and not page.evaluate('uraBusy.isBusy()')
        for field,value in latest.items():assert page.locator('[name='+field+']').input_value()==value
        assert app.db.workspace_definition(owner)==saved, 'Click alone must not save'
        page.get_by_role('tab',name='General',exact=True).click()
        page.get_by_role('button',name='Save campaign',exact=True).filter(visible=True).click()
        page.wait_for_url('**/campaigns/*?section=definition')
        page.get_by_role('link',name='Configure in Build',exact=True).click()
        for field,value in latest.items():assert page.locator('[name='+field+']').input_value()==value
        assert page.locator('[name=modality_scope]').input_value()=='text,image'
        assert page.locator('.armbox[data-arm=xstest_full]').is_checked()
        assert not errors and not app.db.load_jobs()
        assert open(previous['project_revision'],'rb').read()==old
    finally:page.close()
