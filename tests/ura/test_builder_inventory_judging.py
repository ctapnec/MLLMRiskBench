import json
from pathlib import Path

import pytest

from experiments.rig_web_app import builder_judging_inventory as subject, ui
from test_builder_judging_inventory import completed, inventory, native, study, browser  # noqa: F401


def complete_items(state):
    app, _, _, _ = state
    params = completed(state)
    job = subject.prepare_inventory_judging(app, params)
    argv = json.loads(app.db.load_job(job.job_id)['argv'])
    out = Path(subject.argument(argv, '--out'))
    out.mkdir()
    (out/'result.json').write_text(json.dumps(dict(status='prepared_no_calls',
        scope='all_saved_outputs_on_selected_inputs', input_entries=1, retained_outputs=4,
        selected_outputs=1, existing_execution_owned=1, unfunded_outputs=1, missing_outputs=1)))
    app.db._conn.execute("UPDATE jobs SET state='complete',exit_code=0 WHERE job_id=?", (job.job_id,))
    app.db._conn.commit()
    return dict(params, retained_inventory_items_job=job.job_id)


def test_funding_handoff_keeps_every_source_view_and_reuses_duplicate_click(inventory):  # noqa: F811
    app, _, calls, _ = inventory
    params = completed(inventory)
    before = len(calls)
    status, location, body = app.handle('POST', '/build/prepare-inventory-judging', params)
    assert status == 303, body.decode()
    command, values, options = calls[-1]
    assert command == 'retained_inventory_judge_items'
    assert len([key for key in values if key.startswith('--hosted-view')]) == 2
    assert '--local-view' in values and '--inventory' in values
    assert '--budget-root' in values and '--budget-plan-sha256' in values
    assert '--ack-paid-execution' not in values and options['campaign_id'] == params['campaign_id']
    assert subject.prepare_inventory_judging(app, params).job_id == location.rsplit('/', 1)[-1]
    assert len(calls) == before+1


def test_review_separates_pending_owned_unfunded_missing_and_does_not_spend(inventory):  # noqa: F811
    app, _, calls, _ = inventory
    params = complete_items(inventory)
    before = len(calls)
    status, _, body = app.handle('POST', '/build/review-inventory-judging', params)
    assert status == 200, body.decode()
    for phrase in ('Funded and not yet started', 'Owned by existing judging executions',
                   'No matching funding in this selection', 'Missing response text', 'not proof of a valid verdict'):
        assert phrase.encode() in body
    assert b'does not start paid execution' in body and len(calls) == before
    owner = app.db.create_workspace('Unrelated', 'api')
    with pytest.raises(ValueError):
        subject.inventory_judging_review(app, dict(params, campaign_id=owner))


def test_funding_panel_and_review_fit_narrow_screen(browser, inventory):  # noqa: F811
    app, _, _, _ = inventory
    params = complete_items(inventory)
    page = browser.new_page(viewport={'width':390, 'height':844})
    try:
        body = ui._page('Coverage', "<form id='builder'></form>"+subject.judging_inventory_panel(params)).decode()
        page.set_content(body.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('button', name='Prepare all-output judging funding').is_visible()
        assert page.get_by_role('button', name='Review all-output judging funding').is_visible()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        body = subject.inventory_judging_review(app, params).decode()
        page.set_content(body.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('heading', name='Judging coverage and funding').is_visible()
        assert page.locator('dt').count() == page.locator('dd').count() == 4
        cards = page.locator('.judging-funding-summary>div')
        assert cards.count() == 4
        first, second = cards.nth(0).bounding_box(), cards.nth(1).bounding_box()
        assert second['y'] >= first['y']+first['height']+15
        assert float(page.locator('dd').first.evaluate('el=>getComputedStyle(el).fontSize').removesuffix('px')) >= 24
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    finally:
        page.close()
