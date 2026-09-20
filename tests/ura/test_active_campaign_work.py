"""Campaign return links expose real active children, not preparation history."""
from copy import deepcopy
from uuid import uuid4

import pytest

from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.operations import operation_job_ids
from test_operator_operations import app as app_fixture
from test_campaign_guide import _browser_page
from test_rig_web_busy_browser import browser  # noqa: F401

app = app_fixture


def running_campaign(app, state='running'):
    owner = app.db.create_workspace('Active demonstration', 'local')
    params = dict(campaign_id=owner, work_kind='campaign', campaign_name='Active demonstration',
                  mode='measured', local='vllm:test', corpora='synth')
    app.db.save_workspace_definition(owner, params)

    def operation(kind, **values):
        row = dict(id=uuid4().hex, kind=kind, status='preparing', step=0,
                   params=dict(params), jobs=[], current_job='', created_at=1, **values)
        app._operations[row['id']] = row
        return row

    parent = operation('campaign', execution_authorized=True)
    parent['step'] = 1
    preparation = operation('direct', campaign_parent=parent['id'])
    probe = operation('direct')
    check = operation('transport-check')
    probe['status'] = 'ready'
    parent['preparation'] = preparation['id']
    preparation['connection_operations'] = [dict(preparation=probe['id'], check=check['id'], probe='job-image-probe')]
    probe['execution_job'] = check['current_job'] = 'job-image-probe'
    job = Job('job-image-probe', 'run_matrix', ['--attestation-probe'],
              app.state_dir/'job-image-probe', restored_state=state)
    app.jobs[job.job_id] = job
    return owner, parent, preparation, job


@pytest.mark.parametrize('state', ['running', 'queued', 'starting', 'retry_wait', 'retry_waiting'])
def test_nested_active_probe_is_visible_once_without_new_operator_tasks(app, state):
    owner, parent, preparation, job = running_campaign(app, state)
    before = deepcopy(app._operations)
    body = app._operation_links(owner)
    assert 'Campaign - Running' in body
    assert 'Current stage: Connection checks before measured collection' in body
    assert 'model probe' in body
    assert body.count('href="/jobs/' + job.job_id + '"') == 1
    assert 'href="/operations/' + parent['id'] in body
    assert 'href="/operations/' + preparation['id'] not in body
    assert 'Review and start' not in body
    assert app._operations == before


def test_active_work_is_not_hidden_by_eight_newer_finished_workflows(app):
    owner, parent, _, _ = running_campaign(app)
    for i in range(12):
        row = deepcopy(parent)
        row.update(id=uuid4().hex, created_at=i+2, status='complete', step=4)
        row.pop('preparation')
        app._operations[row['id']] = row
    other = deepcopy(parent)
    other.update(id=uuid4().hex, params=dict(campaign_id='another-campaign'))
    app._operations[other['id']] = other
    body = app._operation_links(owner)
    assert body.index('/operations/' + parent['id']) < body.index('Campaign - Complete')
    assert body.count('Campaign - Complete') == 8
    assert other['id'] not in body


def test_terminal_child_is_not_presented_as_still_running(app):
    owner, parent, _, job = running_campaign(app)
    job.restored_state, job.restored_exit = 'complete', 0
    body = app._operation_links(owner)
    assert '/jobs/' + job.job_id not in body
    assert 'workflow is between jobs' in body
    parent.update(status='complete', step=4)
    body = app._operation_links(owner)
    assert 'Campaign - Complete' in body and 'Current stage:' not in body


@pytest.mark.parametrize('step,key,label', [
    (1, 'collection_job', 'Collecting answers'),
    (2, 'local_execution', 'Local assessment'),
    (3, 'haiku_execution', 'Haiku assessment'),
])
def test_collection_and_assessment_jobs_use_current_stage(app, step, key, label):
    owner, parent, preparation, probe = running_campaign(app)
    preparation['connections_complete'] = True
    probe.restored_state = 'complete'
    job = Job('job-current', 'campaign_assess', ['--execute'], app.state_dir/'job-current', restored_state='running')
    app.jobs[job.job_id] = job
    parent.update(step=step, **{key: job.job_id})
    body = app._operation_links(owner)
    assert 'Current stage: ' + label in body
    assert '/jobs/job-current' in body
    assert '/jobs/job-image-probe' not in body


def test_saved_connection_graph_handles_missing_or_repeated_references(app):
    _, parent, preparation, _ = running_campaign(app)
    preparation['connection_operations'].append(dict(probe='job-second', preparation=parent['id'], check='unavailable'))
    assert operation_job_ids(app._operations, parent['id']) == {'job-image-probe', 'job-second'}


@pytest.mark.parametrize('state', ['running', 'complete', 'failed'])
def test_executed_single_run_does_not_claim_to_be_unstarted(app, state):
    owner, parent, _, job = running_campaign(app, state)
    parent.update(kind='direct', status='ready', execution_job=job.job_id)
    body = app._operation_links(owner)
    assert 'Review and start' not in body
    assert ('Inspect problem' if state == 'failed' else 'View progress') in body


@pytest.mark.parametrize('width', [1440, 390])
def test_browser_shows_active_work_in_overview_and_build_without_losing_draft(browser, app, width):  # noqa: F811
    owner, parent, _, job = running_campaign(app)
    page, requests, errors = _browser_page(browser, app, width)
    page.set_default_timeout(5000)
    try:
        for path in ('/campaigns/'+owner+'?section=overview', '/build?campaign_id='+owner):
            page.goto('http://guide.test'+path)
            if path.startswith('/build'):
                page.get_by_role('tab', name='General', exact=True).click()
                page.locator('[name=campaign_collection_cost]').fill('0.73')
            card = page.locator('[data-operation-work]')
            assert 'Campaign - Running' in card.inner_text()
            assert card.locator('a[href="/jobs/'+job.job_id+'"]').is_visible()
            assert card.locator('a[href="/operations/'+parent['id']+'"]').is_visible()
            card.scroll_into_view_if_needed()
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            if path.startswith('/build'):
                assert page.locator('[name=campaign_collection_cost]').input_value() == '0.73'
        assert not errors
        assert all(method == 'GET' for method, _ in requests)
    finally:
        page.close()
