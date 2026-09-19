"""Automatic preparation must not turn into automatic model execution."""
import importlib
import json
from types import SimpleNamespace
from urllib.parse import urlsplit, parse_qsl

import pytest

from experiments.rig_web_app.operations import _STEPS
from test_rig_web_model_acquisition import _app
from test_rig_web_busy_browser import browser, _burst  # noqa: F401


@pytest.fixture
def app(tmp_path, monkeypatch):
    value = _app(tmp_path)
    monkeypatch.setattr(value, '_ensure_operation_worker', lambda key: None)
    monkeypatch.setattr(value, '_reconcile_locked', lambda: None)
    monkeypatch.setattr(value, '_read_lane_projection', lambda p:(None, 'not prepared'))
    yield value
    value.jobs.clear()
    value.close()


def child(app, name, command='preparation', state='complete', code=0):
    row = SimpleNamespace(job_id=name, command=command, failure='', state=lambda:state, exit_code=lambda:code)
    app.jobs[name] = row
    return row


def setup_stages(app, monkeypatch, kind):
    launched = []
    for index, (_, module, function) in enumerate(_STEPS[kind]):
        def prepare(context, params, index=index):
            # The preceding private handoff is available without editing the draft.
            assert all(params.get('retained_test_'+str(i)) == str(i) for i in range(index))
            context._save_build_campaign(dict(params, **{'retained_test_'+str(index):str(index)}))
            launched.append(index)
            return child(app, 'stage-'+str(index))
        monkeypatch.setattr(importlib.import_module('experiments.rig_web_app.'+module), function, prepare)
    return launched


@pytest.mark.parametrize('kind', ['matched', 'local-judging', 'haiku-judging', 'paired-haiku'])
def test_preparation_advances_every_stage_without_starting_targets_or_judges(app, monkeypatch, kind):
    owner = app.db.create_workspace('Automatic', 'mixed')
    params = dict(campaign_id=owner, api='openai:test')
    app.db.save_workspace_definition(owner, params)
    launched = setup_stages(app, monkeypatch, kind)
    def forbidden(*args, **kwargs):
        raise AssertionError('No generation or judging may start here')
    monkeypatch.setattr(app, 'start_job', forbidden)
    key = app._start_operation(kind, params)
    assert app._start_operation(kind, params) == key
    operation = app._operations[key]
    for _ in range(len(_STEPS[kind])+1):
        app._advance_operation(operation)
    assert operation['status'] == 'ready' and launched == list(range(len(_STEPS[kind])))
    assert app.db.workspace_definition(owner) == operation['params']
    app._advance_operation(operation)
    assert len(launched) == len(_STEPS[kind])


def test_preparation_never_overwrites_a_concurrently_edited_campaign(app, monkeypatch):
    owner = app.db.create_workspace('Concurrent edit', 'mixed')
    params = dict(campaign_id=owner, api='original')
    app.db.save_workspace_definition(owner, params)
    setup_stages(app, monkeypatch, 'local-judging')
    operation = app._operations[app._start_operation('local-judging', params)]
    app._advance_operation(operation)
    changed = dict(params, api='new choice')
    app.db.save_workspace_definition(owner, changed)
    app._advance_operation(operation)
    assert operation['status'] == 'ready'
    assert app.db.workspace_definition(owner) == changed
    assert operation['params']['api'] == 'original'


def test_stop_and_failed_child_prevent_next_stage_and_retry_keeps_completed_stages(app, monkeypatch):
    owner = app.db.create_workspace('Failure', 'mixed')
    launched = setup_stages(app, monkeypatch, 'matched')
    operation = app._operations[app._start_operation('matched', dict(campaign_id=owner))]
    app._advance_operation(operation)
    app._advance_operation(operation)
    child(app, 'stage-1', state='failed', code=2)
    app._advance_operation(operation)
    assert operation['status'] == 'failed' and launched == [0,1]
    assert operation['jobs'] == ['stage-0']
    app._retry_operation(operation['id'])
    for _ in range(4):
        app._advance_operation(operation)
    assert operation['status'] == 'ready' and launched == [0,1,1,2,3]
    assert operation['failed_jobs'] == ['stage-1']
    other = app._operations[app._start_operation('matched', dict(campaign_id=owner, api='changed'))]
    app._advance_operation(other)
    app._stop_operation(other['id'])
    app._advance_operation(other)
    assert other['status'] == 'stopped' and len(launched) == 6


def test_restored_operation_observes_current_job_without_relaunch(app, monkeypatch):
    owner = app.db.create_workspace('Restart', 'mixed')
    launched = setup_stages(app, monkeypatch, 'matched')
    key = app._start_operation('matched', dict(campaign_id=owner))
    app._advance_operation(app._operations[key])
    child(app, 'stage-0', state='running', code=None)
    app._restore_operations()
    app._advance_operation(app._operations[key])
    assert launched == [0]
    child(app, 'stage-0')
    app._advance_operation(app._operations[key])
    assert launched == [0,1]


@pytest.mark.parametrize('acquisition', [False, True])
def test_direct_preparation_only_launches_no_call_work(app, monkeypatch, acquisition):
    monkeypatch.setattr(app, '_builder_model_acquisition_required', lambda p:acquisition)
    monkeypatch.setattr(app, '_operation_snapshot', lambda op:{})
    monkeypatch.setattr(app, '_compose_from_builder', lambda p, **kw:('run_matrix', {'--out':'original'}, p))
    monkeypatch.setattr(app, '_materialize_prepared_attacker_config', lambda *a, **kw:None)
    monkeypatch.setattr(app, '_preflight_output_dir', lambda p:'projection')
    monkeypatch.setattr(app, '_builder_preflight_values', lambda values, **kw:dict(values, **{'--preflight-only':'on'}))
    launches = []
    def launch(command, values, **kwargs):
        assert '--preflight-only' in values
        launches.append(command)
        return child(app, kwargs['reserved_job_id'], command=command)
    monkeypatch.setattr(app, 'start_job', launch)
    def plan(params, **kwargs):
        key = kwargs['reserved_job_id']
        app._model_acquisition_workflows[key] = dict(next_stage=params['_model_acquisition_next'])
        launches.append('plan-'+params['_model_acquisition_next'])
        return child(app, key)
    def acquire(key, **kwargs):
        app._model_acquisition_workflows[kwargs['reserved_job_id']] = app._model_acquisition_workflows[key]
        launches.append('reuse-installed')
        return child(app, kwargs['reserved_job_id'])
    def preflight(key, **kwargs):
        assert app._model_acquisition_workflows[key]['next_stage'] == 'preflight'
        launches.append('preflight')
        return child(app, kwargs['reserved_job_id'])
    monkeypatch.setattr(app, '_start_model_acquisition_plan', plan)
    monkeypatch.setattr(app, '_start_model_acquisition_download', acquire)
    monkeypatch.setattr(app, '_start_model_acquisition_run', preflight)
    operation = app._operations[app._start_operation('direct', {'local':'vllm:test'})]
    for _ in range(6):
        app._advance_operation(operation)
    assert operation['status'] == 'ready'
    assert launches == (['plan-preflight','reuse-installed','preflight','plan-run','reuse-installed']
        if acquisition else ['run_matrix'])


def test_unknown_operation_kind_does_not_save_a_draft(app, monkeypatch):
    monkeypatch.setattr(app, '_save_build_campaign', lambda p:pytest.fail('Unknown action must not save'))
    status, _, _ = app.handle('POST', '/build/prepare-operation/not-real', {})
    assert status == 400


def test_automatic_preparation_ticket_retains_and_revalidates_execution_snapshot(app):
    params, snapshot, _ = app._capture_execution_config_snapshot(
        dict(mode='dry_run', local='', api='', judges='rules', attackers='replay'))
    assert snapshot, 'Exercise real execution bytes, not an empty mocked ticket'
    token = app._new_launch_ticket(params, purpose='automatic-preparation', execution_snapshot=snapshot)
    bound, held = app._consume_launch_ticket(token, purpose='automatic-preparation')
    assert held == snapshot
    assert app._validate_execution_snapshot(bound, held) == snapshot
    assert app._consume_launch_ticket(token, purpose='automatic-preparation') is None


def test_corrupt_operation_metadata_cannot_crash_startup(app):
    root = app.state_dir/'.private-operations'/('a'*32)
    root.mkdir(parents=True)
    (root/'operation.json').write_text(json.dumps(dict(id='a'*32,kind='direct',status='preparing',params=[],jobs=[],current_job='',step=-1)))
    app._restore_operations()
    assert not app._operations


def test_retry_before_job_registration_clears_only_an_unlaunched_identity(app, monkeypatch):
    monkeypatch.setattr(app, '_builder_model_acquisition_required', lambda p:False)
    operation = app._operations[app._start_operation('direct', {})]
    operation.update(status='failed', current_job='not-launched', launch_pending=True)
    app._retry_operation(operation['id'])
    assert operation['current_job'] == '' and not operation['launch_pending']
    operation.update(status='failed', current_job='retained-launch', launch_pending=True)
    (app.state_dir/'retained-launch').mkdir()
    with pytest.raises(ValueError, match='saved launch files'):
        app._retry_operation(operation['id'])
    assert operation['status'] == 'failed' and operation['current_job'] == 'retained-launch'


@pytest.mark.parametrize('state', ['stopped', 'interrupted'])
def test_stopped_acquisition_continues_from_same_plan(app, monkeypatch, state):
    monkeypatch.setattr(app, '_builder_model_acquisition_required', lambda p:True)
    operation = app._operations[app._start_operation('direct', {})]
    operation.update(status='stopped', step=1, jobs=['plan'], current_job='old')
    child(app, 'old', state=state, code=1)
    app._model_acquisition_workflows['plan'] = dict(acquisition_job_id='old')
    launched = []
    def acquire(plan, **kwargs):
        launched.append(plan)
        return child(app, kwargs['reserved_job_id'])
    monkeypatch.setattr(app, '_start_model_acquisition_download', acquire)
    app._retry_operation(operation['id'])
    app._advance_operation(operation)
    assert launched == ['plan'] and operation['step'] == 1
    assert operation['failed_jobs'] == ['old']


def test_completed_probe_saves_connection_check_without_an_operator_handoff(app, monkeypatch):
    probe = child(app, 'probe', command='run_matrix', state='running', code=None)
    probe.argv = ['python','-m','experiments.run_matrix','--attestation-probe']
    probe.builder_params = {}
    key = app._finish_probe_automatically(probe)
    assert app._finish_probe_automatically(probe) == key
    operation = app._operations[key]
    calls = []
    monkeypatch.setattr(app, '_transport_check_from_job', lambda job, owner:('', {'--probe-root':'saved'}, ''))
    def launch(command, values, **kwargs):
        assert command == 'live_attestation'
        calls.append(values)
        return child(app, kwargs['reserved_job_id'], command=command)
    monkeypatch.setattr(app, 'start_job', launch)
    app._advance_operation(operation)
    assert not calls
    child(app, 'probe', command='run_matrix')
    app._advance_operation(operation)
    app._advance_operation(operation)
    assert operation['status'] == 'ready' and calls == [{'--probe-root':'saved'}]
    assert b'No receipt needs copying' in app._operation_page(key)


def test_exact_projection_and_unconsumed_preparation_are_reused(app, monkeypatch):
    monkeypatch.setattr(app, '_builder_model_acquisition_required', lambda p:True)
    monkeypatch.setattr(app, '_read_lane_projection', lambda p:({'existing':True}, ''))
    monkeypatch.setattr(app, '_durable_builder_params', lambda p:p)
    params = dict(local='same-model', max_target='4')
    app._model_acquisition_workflows['ready'] = dict(params=params, next_stage='run', consumed=False,
        plan_job_id='plan', acquisition_job_id='ready')
    child(app, 'ready')
    key = app._start_operation('direct', params)
    operation = app._operations[key]
    assert operation['step'] == 5 and operation['jobs'][-1] == 'ready'
    app._advance_operation(operation)
    assert operation['status'] == 'ready'
    changed = app._operations[app._start_operation('direct', dict(params, max_target='5'))]
    assert changed['step'] == 3, 'A receipt for different caps must not be adopted'


@pytest.mark.parametrize('width', [1440, 390])
def test_progress_stop_busy_guard_and_final_review_in_browser(app, monkeypatch, browser, width):
    monkeypatch.setattr(app, '_builder_model_acquisition_required', lambda p:True)
    monkeypatch.setattr(app, '_ceilings_card', lambda p:('<p>Four target calls, no hosted charges.</p>',True))
    key = app._start_operation('direct', dict(local='vllm:Qwen/Qwen3-VL-8B-Instruct',corpora='xstest_full,vlsbench_release'))
    operation = app._operations[key]
    page = browser.new_page(viewport=dict(width=width,height=1000))
    held, errors = [], []
    page.on('pageerror', lambda error:errors.append(str(error)))
    def route(request):
        path = urlsplit(request.request.url).path
        if request.request.method == 'POST':
            held.append(request)
        else:
            status,mime,body = app.handle('GET', path)
            request.fulfill(status=status,content_type=mime,body=body)
    page.route('http://operations.test/**', route)
    try:
        page.goto('http://operations.test/operations/'+key)
        assert page.get_by_role('button',name='Stop preparation',exact=True).is_visible()
        assert page.locator('body > nav').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        assert _burst(page, 'form[action$="/stop"] button') == {'visible':True, 'inert':True}
        assert len(held) == 1
        request = held.pop()
        status,location,body = app.handle('POST',urlsplit(request.request.url).path,dict(parse_qsl(request.request.post_data or '')))
        request.fulfill(status=status,headers={'Location':location},body=body)
        page.get_by_role('button',name='Continue preparation',exact=True).wait_for()
        assert not page.locator('#busy-overlay').is_visible()
        assert operation['status'] == 'stopped'
        app._model_acquisition_workflows['ready'] = dict(params=operation['params'],consumed=False)
        operation.update(status='ready',step=5,jobs=['','','','plan','ready'])
        page.reload()
        assert page.get_by_role('button',name='Start run',exact=True).is_visible()
        assert not page.get_by_role('button',name='Start run',exact=True).is_disabled()
        assert not page.get_by_role('button',name='Download / acquire models',exact=True).count()
        assert not app.jobs
        assert not errors
    finally:
        page.close()
