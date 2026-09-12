"""Build includes every completed source increment, without a paid launch."""
import json
from pathlib import Path

import pytest

from experiments.rig_web import Job
from experiments.rig_web_app import builder_judging_inventory as subject, ui
from test_builder_native_judging import native, complete_preparation  # noqa: F401
from test_builder_collection import study  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401


@pytest.fixture
def inventory(native):  # noqa: F811
    app, _, calls, receipt = native
    first = complete_preparation(native, selected=[0], failed=True)
    second = complete_preparation(native, selected=[1])
    directory = Path(receipt['programs'][0]['path']).parent
    job = Job(job_id='local-sources', command='retained_local_sources',
        argv=['python', '-m', 'experiments.retained_local_sources', '--out', str(directory/'local-sources.json')],
        directory=directory/'local-job', restored_state='complete', restored_exit=0)
    app.db.upsert_job(job, state='complete', exit_code=0)
    app.db.attach_workspace_member(second['campaign_id'], 'job', job.job_id, 'preparation')
    return app, dict(second, retained_sources_job=job.job_id), calls, first


def completed(inventory):
    app, params, _, _ = inventory
    job = subject.prepare_judging_inventory(app, params)
    argv = json.loads(app.db.load_job(job.job_id)['argv'])
    path = Path(subject.argument(argv, '--out'))
    path.write_text(json.dumps(dict(schema=subject.SCHEMA, status='inventory_only_no_calls',
        selection=dict(selected_inputs=1), coverage=dict(retained_outputs=4, judgeable_text=3,
            missing_text=1, hosted_inputs_without_local_records=0),
        population=dict(local={}, hosted=dict(unprepared_outputs=2)),
        by_model=[dict(cohort='local', model='local:a', retained_outputs=2, judgeable_text=1, missing_text=1),
                  dict(cohort='local', model='local:b', retained_outputs=1, judgeable_text=1),
                  dict(cohort='hosted', model='api:c', retained_outputs=1, judgeable_text=1)])))
    app.db._conn.execute("UPDATE jobs SET state='complete',exit_code=0 WHERE job_id=?", (job.job_id,))
    app.db._conn.commit()
    return dict(params, retained_inventory_job=job.job_id)


def test_all_preparation_increments_are_included_and_duplicate_click_is_reused(inventory):
    app, params, calls, first = inventory
    before = len(calls)
    status, location, body = app.handle('POST', '/build/prepare-judging-inventory', params)
    assert status == 303, body.decode()
    command, values, kw = calls[-1]
    assert command == 'retained_judge_inventory'
    paths = [value for flag, value in values.items() if flag.startswith('--hosted-view')]
    assert len(paths) == 2
    for job_id in (first['retained_native_judging_job'], params['retained_native_judging_job']):
        argv = json.loads(app.db.load_job(job_id)['argv'])
        assert str(Path(subject.argument(argv, '--out'))/'result.json') in paths
    assert values['--input-limit'] == '0' and values['--sample-seed'] == '0'
    assert '--ack-paid-execution' not in values and '--shared-budget-root' not in values
    assert kw['campaign_id'] == params['campaign_id']
    assert subject.prepare_judging_inventory(app, params).job_id == location.rsplit('/', 1)[-1]
    assert len(calls) == before+1


@pytest.mark.parametrize('change', [dict(retained_inventory_limit='-1'), dict(retained_inventory_limit='1.5'),
    dict(retained_inventory_seed='bad'), dict(retained_native_judging_job='not-this-campaign')])
def test_invalid_selection_does_not_start_work(inventory, change):
    app, params, calls, _ = inventory
    before = len(calls)
    with pytest.raises(ValueError):
        subject.prepare_judging_inventory(app, dict(params, **change))
    assert len(calls) == before


def test_review_retains_missing_and_unprepared_counts_without_claiming_judgments(inventory):
    app, _, calls, _ = inventory
    params = completed(inventory)
    before = len(calls)
    status, _, body = app.handle('POST', '/build/review-judging-inventory', params)
    assert status == 200, body.decode()
    assert b'4 retained outputs' in body and b'1 have missing text' in body
    assert b'2 source outputs remain unprepared' in body
    assert b'not completed judging' in body and b'local:a' in body and b'local:b' in body
    assert b'Start or resume Haiku judging' not in body
    assert len(calls) == before
    other = app.db.create_workspace('Unrelated', 'api')
    with pytest.raises(ValueError):
        subject.judging_inventory_review(app, dict(params, campaign_id=other))


def test_inventory_panel_and_review_fit_mobile(browser, inventory):  # noqa: F811
    app, _, _, _ = inventory
    params = completed(inventory)
    page = browser.new_page(viewport={'width':390, 'height':844})
    try:
        panel = ui._page('Coverage', "<form id='builder'></form>"+subject.judging_inventory_panel(params)).decode()
        page.set_content(panel.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('button', name='Prepare all-output coverage').is_visible()
        assert page.get_by_label('Input limit (0 = all hosted inputs)').input_value() == '0'
        fields = page.locator('.campaign-field')
        first, second = fields.nth(0).bounding_box(), fields.nth(1).bounding_box()
        assert second['y'] >= first['y']+first['height']+15
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        body = subject.judging_inventory_review(app, params).decode()
        page.set_content(body.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('heading', name='Same-input output coverage').is_visible()
        assert page.locator('table tr').count() == 4
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    finally:
        page.close()
