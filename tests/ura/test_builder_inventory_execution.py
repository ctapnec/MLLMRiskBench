import json
from pathlib import Path
import re

import pytest

from experiments.rig_web import Job
from experiments.rig_web_app import builder_inventory_execution as subject, ui
from test_builder_inventory_judging import complete_items, inventory, native, study, browser  # noqa: F401

JUDGE = 'anthropic:claude-haiku-4-5-20251001'


@pytest.fixture
def ready(inventory, monkeypatch):  # noqa: F811
    app, _, calls, _ = inventory
    params = complete_items(inventory)
    folder = Path(app.results_root)
    job = Job(job_id='forecast', command='hosted_campaign_budget',
        argv=['python', '-m', 'experiments.hosted_campaign_budget', '--pricing-config', str(folder/'prices.json'),
            '--pricing-as-of', '2026-09-13', '--out', str(folder/'forecast.json')],
        directory=folder/'budget-job', restored_state='complete', restored_exit=0)
    app.db.upsert_job(job, state='complete', exit_code=0)
    app.db.attach_workspace_member(params['campaign_id'], 'job', job.job_id, 'budget')
    params.update(retained_budget_job=job.job_id, retained_haiku_model=JUDGE,
        retained_source_campaign=app.db.create_workspace('Original local answers', 'local'))
    monkeypatch.setattr(subject, '_choices', lambda _: [JUDGE])
    monkeypatch.setattr(app, '_selected_api_config_snapshot', lambda _: ({}, '', '', {JUDGE: dict(max_tokens=4096)}))
    return app, params, calls


def complete(ready):
    app, params, _ = ready
    job = subject.prepare(app, params)
    argv = json.loads(app.db.load_job(job.job_id)['argv'])
    root = Path(subject.argument(argv, '--out'))
    root.mkdir()
    value = dict(status='ready_for_funded_judging', selected_outputs=5, funding_review=[],
        first_attempt_estimate_microusd=20000, coverage=dict(input_entries=1, retained_outputs=8,
            existing_execution_owned=1, missing_outputs=1, unfunded_outputs=1))
    (root/'result.json').write_text(json.dumps(value))
    app.db._conn.execute("UPDATE jobs SET state='complete',exit_code=0 WHERE job_id=?", (job.job_id,))
    app.db._conn.commit()
    return dict(params, retained_inventory_plan_job=job.job_id), root


def test_prepare_uses_all_output_items_and_reuses_identical_job(ready):
    app, params, calls = ready
    count = len(calls)
    status, location, body = app.handle('POST', '/build/prepare-inventory-haiku', params)
    assert status == 303, body.decode()
    command, values, options = calls[-1]
    assert command == subject.COMMAND and values['--items-root'].endswith('judging-items')
    assert '--execute' not in values and '--ack-paid-execution' not in values
    assert json.loads(Path(values['--api-config']).read_text())[JUDGE]['max_tokens'] == 512
    assert options['campaign_id'] == params['campaign_id']
    assert subject.prepare(app, params).job_id == location.rsplit('/', 1)[-1] and len(calls) == count+1


def test_review_launch_and_resume_preserve_both_owners_and_execution_directory(ready):
    app, _, calls = ready
    params, _ = complete(ready)
    def review():
        status, _, body = app.handle('POST', '/build/review-inventory-haiku', params)
        assert status == 200, body.decode()
        assert b'5 funded answers' in body and b'not one counterpart' in body
        assert b'no answer retries' in body and b'three HTTP-error retries' in body
        return re.search("name='launch_ticket' value='([^']+)'", body.decode())[1]
    token = review()
    count = len(calls)
    job = subject.launch(app, dict(launch_ticket=token))
    values = dict(calls[-1][1])
    assert values['--execute'] == values['--ack-paid-execution'] == 'on'
    assert values['--matching-workspace-id'] == params['retained_source_campaign'] and values['--workers'] == '2'
    assert subject.launch(app, dict(launch_ticket=review())).job_id == job.job_id
    assert len(calls) == count+1
    app.db._conn.execute("UPDATE jobs SET state='failed',exit_code=1 WHERE job_id=?", (job.job_id,))
    app.db._conn.commit()
    subject.launch(app, dict(launch_ticket=review()))
    assert calls[-1][1] == values and len(calls) == count+2


def test_empty_or_unfunded_review_does_not_offer_paid_execution(ready):
    app, _, calls = ready
    params, root = complete(ready)
    original = json.loads((root/'result.json').read_text())
    count = len(calls)
    for values in (dict(selected_outputs=0), dict(status='needs_funding_review', funding_review=[{}])):
        (root/'result.json').write_text(json.dumps(dict(original, **values)))
        body = subject.review(app, params)
        assert b'Start or resume all-output Haiku judging' not in body
    assert len(calls) == count


def test_all_output_review_is_readable_on_mobile(browser, ready):  # noqa: F811
    app, _, _ = ready
    params, _ = complete(ready)
    page = browser.new_page(viewport={'width': 390, 'height': 844})
    try:
        body = subject.review(app, params).decode()
        page.set_content(body.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('button', name='Start or resume all-output Haiku judging').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    finally:
        page.close()
