"""Browser geometry for actual console controls, without launching work."""
from types import SimpleNamespace
import re

import pytest

from experiments.rig_web import Job
from experiments.rig_web_app import (
    builder_collection, builder_haiku_judging, builder_inventory_execution,
    builder_judging_inventory, builder_native_judging, builder_programs, builder_sources, ui,
)
from test_builder_collection import study  # noqa: F401
from test_builder_native_judging import native, complete_preparation  # noqa: F401
from test_builder_haiku_judging import haiku, completed as complete_haiku  # noqa: F401
from test_builder_judging_inventory import inventory  # noqa: F401
from test_builder_inventory_execution import ready, complete as complete_inventory  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401


def render(page, body):
    if isinstance(body, bytes):
        body = body.decode()
    body = body.replace("<link rel='stylesheet' href='/static/style.css'>", '<style>'+ui._STYLE+'</style>')
    # A synthetic running-job page has no server to reload. Keep its real markup.
    body = re.sub(r'<script>setTimeout\(function\(\).*?</script>', '', body)
    page.set_content(body)


def assert_action_gap(page, button):
    row = button.locator('..')
    gap = row.evaluate("""row => {
      let previous=row.previousElementSibling;
      while(previous && !previous.getClientRects().length) previous=previous.previousElementSibling;
      return row.getBoundingClientRect().top-previous.getBoundingClientRect().bottom;
    }""")
    assert gap >= 12, gap
    assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')


@pytest.mark.parametrize('width', [390, 1440])
def test_stop_action_is_separated_from_command(browser, study, tmp_path, width):
    app, _, calls, _ = study
    job = Job(job_id='layout-only', command='run_matrix', argv=['python', '-m', 'experiments.run_matrix'],
              directory=tmp_path, process=SimpleNamespace(poll=lambda: None))
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        render(page, app._job_page(job))
        button = page.get_by_role('button', name='Stop job', exact=True)
        assert_action_gap(page, button)
        assert button.locator('..').get_attribute('action') == '/jobs/layout-only/stop'
        assert not calls
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
@pytest.mark.parametrize('kind', ['collection', 'native', 'haiku', 'inventory'])
def test_review_actions_have_clear_spacing(browser, request, kind, width):
    if kind == 'collection':
        app, params, calls, _ = request.getfixturevalue('study')
        review, label = builder_collection.collection_review, 'Start prepared collection'
    elif kind == 'native':
        fixture = request.getfixturevalue('native')
        app, _, calls, _ = fixture
        params = complete_preparation(fixture)
        review, label = builder_native_judging.native_judging_review, 'Start or resume local judging'
    elif kind == 'haiku':
        fixture = request.getfixturevalue('haiku')
        app, _, calls, _ = fixture
        params = complete_haiku(fixture)
        review, label = builder_haiku_judging.haiku_judging_review, 'Start or resume Haiku judging'
    else:
        fixture = request.getfixturevalue('ready')
        app, _, calls = fixture
        params, _ = complete_inventory(fixture)
        review, label = builder_inventory_execution.review, 'Start or resume all-output Haiku judging'
    before = len(calls)
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        render(page, review(app, params))
        button = page.get_by_role('button', name=label, exact=True)
        assert_action_gap(page, button)
        page.get_by_text('Exact command', exact=True).click()
        assert_action_gap(page, button)
        assert len(calls) == before
    finally:
        page.close()


def assert_checkbox_row(page, name):
    checkbox = page.locator('input[name="'+name+'"]')
    row = checkbox.locator('..')
    box, text = checkbox.bounding_box(), row.locator(':scope > span').bounding_box()
    assert box and text
    assert text['x'] - (box['x']+box['width']) >= 8
    assert abs(text['y']-box['y']) <= 6
    assert float(row.evaluate('row=>getComputedStyle(row).marginTop').removesuffix('px')) >= 8
    assert not checkbox.is_checked()
    row.locator(':scope > span').click()
    assert checkbox.is_checked()
    assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')


@pytest.mark.parametrize('width', [390, 1440])
def test_build_and_preparation_checkbox_rows_align(browser, native, width):
    app, _, _, _ = native
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        render(page, app._build_page())
        page.locator('#build-execution-tab').click()
        assert_checkbox_row(page, 'verify_model_sha256')
        render(page, ui._page('Preparation', "<form id='builder'></form>" +
            builder_programs.program_panel({'retained_replays_job': 'saved-replay'})))
        assert_checkbox_row(page, 'retained_network_counts')
        params = complete_preparation(native)
        render(page, ui._page('Local judging', "<form id='builder'></form>" +
            builder_native_judging.native_judging_panel(app, params)))
        for name in ('retained_native_verify_model', 'retained_native_verify_artifacts'):
            assert_checkbox_row(page, name)
        render(page, ui._page('Database', app._db_card('')))
        assert_checkbox_row(page, 'verify_artifact_sha256')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_judging_action_groups_have_gaps_and_wrap(browser, width):
    panel = builder_judging_inventory.judging_inventory_panel(dict(
        retained_inventory_job='coverage', retained_inventory_items_job='funding',
        retained_inventory_plan_job='judging'))
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        render(page, ui._page('Judging', "<form id='builder'></form>"+panel))
        for action in ['/build/review-judging-inventory', '/build/review-inventory-judging']:
            first = page.locator('button[formaction="'+action+'"]')
            second = first.locator('xpath=following-sibling::button[1]')
            a, b = first.bounding_box(), second.bounding_box()
            if abs(a['y']-b['y']) < 1:
                assert b['x']-a['x']-a['width'] >= 12
            else:
                assert b['y']-a['y']-a['height'] >= 12
            assert first.get_attribute('form') == second.get_attribute('form') == 'builder'
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_source_preparation_action_has_spacing(browser, study, width):
    app, params, _, _ = study
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        panel = builder_sources.source_panel(app, {'retained_source_campaign': params['campaign_id']})
        render(page, ui._page('Sources', "<form id='builder'></form>"+panel))
        button = page.get_by_role('button', name='Prepare selected inputs', exact=True)
        assert_action_gap(page, button)
        assert button.get_attribute('formaction') == '/build/prepare-inputs'
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_config_editor_actions_wrap_without_overflow(browser, study, monkeypatch, width):
    app, _, _, _ = study
    monkeypatch.setattr(app, '_config_example_text', lambda key: '{}')
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        render(page, app._config_page('api-targets', ''))
        row = page.locator('.editor-actions')
        assert row.evaluate('row=>getComputedStyle(row).flexWrap') == 'wrap'
        assert len(row.get_by_role('button').all()) == 3
        bounds = row.bounding_box()
        for button in row.get_by_role('button').all():
            box = button.bounding_box()
            assert box['x'] >= bounds['x']
            assert box['x']+box['width'] <= bounds['x']+bounds['width']+1
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()
