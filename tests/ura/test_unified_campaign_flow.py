"""One reviewed start owns collection and selected saved-answer assessment."""
import json
from types import SimpleNamespace

import pytest

from test_operator_operations import app, child  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401
from experiments.rig_web_app import campaign_flow as flow


def prepared(app, kind='matched', **options):
    owner = app.db.create_workspace('Unified workflow', 'mixed')
    params = dict(campaign_id=owner, mode='measured', campaign_flow='on', campaign_collection_cost='100', **options)
    operation = app._operations[app._start_operation('campaign', params)]
    selection = app._operations[app._start_operation(kind, params)]
    selection['status'] = 'ready'
    operation['preparation'] = selection['id']
    for judge in ('local','haiku'):
        root=app.results_root/'assessments'/operation['id']/judge
        root.mkdir(parents=True)
        (root/'result.json').write_text(json.dumps(dict(status='prepared',selected_outputs=1,dispositions={})))
        operation[judge+'_values']={'--out':str(root)}
        operation[judge+'_root']=str(root)
    return operation, selection


@pytest.fixture(autouse=True)
def collection_values(monkeypatch):
    from experiments.rig_web_app import builder_collection
    monkeypatch.setattr(builder_collection,'collection_launch_values',lambda *a:({'--out':'collection'},[],None,'2'))


def launches(app, monkeypatch):
    saved=[]
    def launch(command, values, **kwargs):
        row=child(app,kwargs['reserved_job_id'],command,state='running',code=None)
        saved.append((command,values,kwargs,row))
        return row
    monkeypatch.setattr(app,'start_job',launch)
    return saved


def test_preparation_never_starts_collection_or_judges(app, monkeypatch):
    operation,_=prepared(app,campaign_local='on',campaign_haiku='on')
    started=launches(app,monkeypatch)
    flow.advance(app,operation)
    assert operation['status']=='ready' and not started
    app._advance_operation(operation)
    assert not started


def test_one_start_runs_collection_then_both_assessments_and_reopens_without_calls(app,monkeypatch):
    from experiments.rig_web_app import builder_collection, campaign_assessment
    operation,_=prepared(app,campaign_local='on',campaign_haiku='on')
    operation.update(status='preparing',step=1,execution_authorized=True)
    started=launches(app,monkeypatch)
    monkeypatch.setattr(builder_collection,'collection_launch_values',lambda *a:({'--out':'collection'},[],None,'2'))
    def prepare(app,owner,**kwargs):
        root=kwargs['root'];root.mkdir(parents=True)
        (root/'result.json').write_text(json.dumps(dict(status='prepared',selected_outputs=1,dispositions={})))
        return {'--out':str(root)}
    monkeypatch.setattr(campaign_assessment,'prepare_values',prepare)
    for _ in range(15):
        app._advance_operation(operation)
        if started:
            previous=started[-1][3]
            child(app,previous.job_id,previous.command)
    assert operation['status']=='complete'
    assert [row[0] for row in started]==['hosted_campaign_execute','campaign_assess','campaign_assess','campaign_assess','campaign_assess']
    assert ['--execute' in row[1] for row in started]==[False,False,True,False,True]
    assert 'Results ready' in app._operation_page(operation['id']).decode()
    assert app._start_operation('campaign',operation['params'])==operation['id']
    app._advance_operation(operation)
    assert len(started)==5


def test_campaign_restart_waits_for_existing_collection(app,monkeypatch):
    operation,_=prepared(app)
    operation.update(step=1,status='preparing',execution_authorized=True,collection_job='existing')
    child(app,'existing','hosted_campaign_execute',state='running',code=None)
    app._save_operation(app._operations[operation['preparation']])
    app._save_operation(operation)
    started=launches(app,monkeypatch)
    app._restore_operations()
    app._advance_operation(app._operations[operation['id']])
    assert not started
    assert app._operations[operation['id']]['step']==1


def test_assessment_failure_keeps_successful_collection_and_local_judging(app,monkeypatch):
    operation,_=prepared(app,campaign_haiku='on')
    operation.update(step=3,status='preparing',execution_authorized=True,collection_job='collected',local_execution='local',haiku_preparation='failed')
    child(app,'collected','hosted_campaign_execute')
    child(app,'local','campaign_assess')
    child(app,'failed','campaign_assess',state='failed',code=2)
    app._advance_operation(operation)
    assert operation['status']=='failed'
    app._retry_operation(operation['id'])
    assert operation['collection_job']=='collected' and operation['local_execution']=='local'
    assert 'haiku_preparation' not in operation and operation['step']==3


def test_over_budget_haiku_never_calls_judge(app,monkeypatch,tmp_path):
    operation,_=prepared(app,campaign_haiku='on')
    operation.update(step=3,status='preparing',execution_authorized=True,haiku_preparation='prepared',haiku_root=str(tmp_path))
    child(app,'prepared','campaign_assess')
    (tmp_path/'result.json').write_text(json.dumps(dict(status='over_budget',selected_outputs=5,dispositions={})))
    started=launches(app,monkeypatch)
    app._advance_operation(operation)
    assert operation['status']=='failed' and not started
    assert 'ceiling' in operation['error']


def test_stop_marks_parent_before_stopping_child_and_never_launches_judging(app,monkeypatch):
    operation,selection=prepared(app,campaign_local='on')
    operation.update(step=1,status='preparing',execution_authorized=True,collection_job='active')
    child(app,'active','hosted_campaign_execute',state='running',code=None)
    stopped=[]
    def stop(job):
        assert operation['status']=='stopped'
        stopped.append(job)
    monkeypatch.setattr(app,'stop_job',stop)
    app._stop_operation(operation['id'])
    app._advance_operation(operation)
    assert stopped==['active'] and operation['step']==1


def test_campaign_start_ticket_cannot_be_used_twice(app,monkeypatch):
    operation,_=prepared(app)
    operation['status']='ready'
    token=app._new_launch_ticket(dict(operation=operation['id']),purpose='campaign-start')
    first=app.handle('POST','/operations/start-campaign',{'launch_ticket':token})
    second=app.handle('POST','/operations/start-campaign',{'launch_ticket':token})
    assert first[0]==303 and second[0]==400
    assert operation['execution_authorized'] and operation['step']==1


def test_unchecked_assessment_stays_unchecked_after_save(app):
    owner=app.db.create_workspace('Selection','mixed')
    params=app._builder_params(dict(campaign_id=owner,campaign_flow='on'))
    assert params['campaign_local']==params['campaign_haiku']=='off'
    page=flow.panel(app,params)
    assert 'name="campaign_local" type="checkbox" checked' not in page


def test_direct_resume_keeps_original_acquisition_and_output_settings(app,monkeypatch):
    monkeypatch.setattr(app,'_builder_model_acquisition_required',lambda p:False)
    operation,selection=prepared(app,kind='direct')
    operation.update(step=1,status='failed',execution_authorized=True,collection_job='failed')
    selection.update(execution_job='failed',jobs=['original-acquisition'])
    child(app,'failed','run_matrix',state='failed',code=2)
    before=dict(selection['params'])
    flow.retry(app,operation)
    assert selection['resume_job']=='failed' and 'execution_job' not in selection
    assert selection['params']==before and selection['jobs']==['original-acquisition']
    assert operation['step']==1


@pytest.mark.parametrize('width',[1440,390])
def test_shared_builder_controls_hide_other_input_route_and_keep_spinners(app,browser,width):
    from urllib.parse import urlsplit, parse_qsl
    owner=app.db.create_workspace('Same workflow','mixed')
    app.db.save_workspace_definition(owner,dict(campaign_id=owner,work_kind='campaign',campaign_flow='on',
        campaign_inputs='fresh',campaign_local='off',campaign_haiku='off',mode='measured'))
    page=browser.new_page(viewport={'width':width,'height':1000})
    errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
    def route(request):
        url=urlsplit(request.request.url)
        status,mime,body=app.handle(request.request.method,url.path+('?'+url.query if url.query else ''),
            dict(parse_qsl(request.request.post_data or '',keep_blank_values=True)))
        if status==303:request.fulfill(status=status,headers={'Location':mime},body=body)
        else:request.fulfill(status=status,content_type=mime,body=body)
    page.route('http://ui.test/**',route)
    try:
        page.goto('http://ui.test/build?campaign_id='+owner)
        assert page.locator('body > nav').is_visible()
        page.get_by_role('tab',name='General',exact=True).click()
        page.get_by_role('button',name='Review campaign',exact=True).filter(visible=True).wait_for()
        assert not page.locator('[data-saved-inputs]').is_visible()
        assert not page.locator('[name=campaign_local]').is_checked()
        page.locator('[name=campaign_inputs]').select_option('saved')
        assert page.locator('[data-saved-inputs]').is_visible()
        assert not page.get_by_role('button',name='Prepare comparison and review',exact=True).count()
        page.locator('[name=campaign_haiku]').check()
        assert page.locator('[name=campaign_judge_cost]').is_visible()
        page.locator('[name=campaign_haiku]').uncheck()
        assert page.locator('[name=campaign_judge_cost]').is_disabled()
        page.locator('[name=campaign_inputs]').select_option('fresh')
        assert page.locator('[name=retained_source_campaign]').is_disabled()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
        assert not page.evaluate('window.uraBusy.isBusy()')
        assert not errors
    finally:page.close()
