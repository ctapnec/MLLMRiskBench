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
def test_collection_review_button_is_separated_from_workers_control(browser, width):
    params = {'retained_programs_job':'prepared', 'retained_collection_workers':'3'}
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, ui._page('Collection', "<form id='builder'></form>"+
                             builder_collection.collection_panel(params)))
        workers = page.locator('[name=retained_collection_workers]')
        button = page.get_by_role('button', name='Review prepared collection', exact=True)
        field_box, button_box = workers.bounding_box(), button.bounding_box()
        assert button_box['y'] - (field_box['y']+field_box['height']) >= 16
        assert workers.input_value() == '3'
        assert button.get_attribute('form') == workers.get_attribute('form') == 'builder'
        assert button.get_attribute('formaction') == '/build/review-collection'
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_job_command_wraps_long_paths_and_identifiers(browser, study, tmp_path, width):
    app, _, calls, _ = study
    argv = ['python', '-m', 'experiments.run_matrix', '--out',
            '/mnt/stor/data/ura-work/runs/rig-web/matched-programs/'+'a'*32+'/prepared/programs/google-gemini-3-8-flash.json',
            '--project-revision-sha256', 'b'*64]
    job = Job(job_id='long-command', command='run_matrix', argv=argv,
              directory=tmp_path, process=SimpleNamespace(poll=lambda: 2))
    page = browser.new_page(viewport={'width': width, 'height': 1000})
    try:
        render(page, app._job_page(job))
        assert page.locator('.argv code').all_text_contents() == argv
        bounds = page.locator('.argv').bounding_box()
        for chip in page.locator('.argv code').all():
            box = chip.bounding_box()
            assert box['x']+box['width'] <= bounds['x']+bounds['width']+1
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
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
        assert row.evaluate('row=>getComputedStyle(row).gap') == '12px'
        assert len(row.get_by_role('button').all()) == 3
        bounds = row.bounding_box()
        for button in row.get_by_role('button').all():
            box = button.bounding_box()
            assert box['x'] >= bounds['x']
            assert box['x']+box['width'] <= bounds['x']+bounds['width']+1
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_saved_judging_field_is_separated_from_preparation_action(browser, native, width):
    app, _, calls, _ = native
    params = complete_preparation(native)
    before = len(calls)
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, ui._page('Local judging', "<form id='builder'></form>"+
                             builder_native_judging.native_judging_panel(app, params)))
        button = page.get_by_role('button', name='Prepare remaining source runs', exact=True)
        field = page.locator('[name=retained_native_judging_job]').locator('..')
        a, b = button.bounding_box(), field.bounding_box()
        assert b['y']-a['y']-a['height'] >= 16
        assert len(calls) == before
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_tools_submit_is_separated_from_last_control(browser, study, width):
    app, _, calls, _ = study
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, ui._page('Tools', app._command_card('retained_native_judge_prepare')))
        page.locator('details.cmd > summary').click()
        gap = page.locator('form.cmd > button[type=submit]').evaluate("""button => {
          let previous=button.previousElementSibling;
          while(previous && (!previous.getClientRects().length || previous.matches('span:empty')))
            previous=previous.previousElementSibling;
          return button.getBoundingClientRect().top-previous.getBoundingClientRect().bottom;
        }""")
        assert gap >= 16
        rows = page.locator('.repeat-row')
        assert rows.count()
        for row in rows.all():
            assert row.evaluate('row=>getComputedStyle(row).gap') == '12px'
        assert not calls
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_human_setup_footer_keeps_action_spacing_on_mobile(browser, study, width):
    app, params, calls, _ = study
    status, _, body = app.handle('GET', '/human-evaluation?campaign_id='+params['campaign_id'])
    assert status == 200
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, body)
        footer = page.locator('[data-study-wizard] .review-wizard-footer')
        assert footer.evaluate('row=>getComputedStyle(row).gap') == '12px'
        assert not calls
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 768, 1440])
def test_comparison_conditions_have_spaced_fields(browser, study, width):
    from experiments.rig_web_app.workspace_comparison import comparison_page
    app, params, calls, _ = study
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, ui._page('Compare', comparison_page(app.db, params['campaign_id'], {})))
        fields = page.locator('.comparison-condition')
        assert fields.count() == 2
        for fieldset in fields.all():
            assert fieldset.evaluate('e=>getComputedStyle(e).padding') == '16px'
            boxes = [field.bounding_box() for field in fieldset.locator('.campaign-field').all()]
            assert all(b['y']-a['y']-a['height'] >= 16 for a,b in zip(boxes, boxes[1:]))
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        assert not calls
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_provider_key_editor_has_padded_fields_and_action_gaps(browser, study, monkeypatch, width, scheme):
    app, _, calls, _ = study
    monkeypatch.setattr(app, 'secret_status', lambda: [dict(name='GEMINI_API_KEY', label='Google', funded=True, present=True, hint='synthetic configured state')])
    page = browser.new_page(viewport={'width':width, 'height':1000}, color_scheme=scheme)
    try:
        render(page, app._secrets_page())
        page.locator('.provider-key-editor summary').click()
        row = page.locator('.provider-key-input-row')
        assert row.evaluate('e=>getComputedStyle(e).gap') == '12px'
        field = row.locator('input')
        assert field.evaluate('e=>parseFloat(getComputedStyle(e).paddingLeft)') >= 12
        assert field.evaluate('e=>getComputedStyle(e).backgroundColor') == page.locator('body').evaluate('e=>getComputedStyle(e).backgroundColor')
        assert field.input_value() == ''
        clear = page.locator('.provider-key-clear')
        a, b = row.bounding_box(), clear.bounding_box()
        assert b['y']-a['y']-a['height'] >= 16
        assert clear.locator('[name=action]').input_value() == 'clear'
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        assert not calls
    finally:
        page.close()


def test_judging_funding_cards_follow_dark_palette(browser):
    page = browser.new_page(color_scheme='dark')
    try:
        panel = builder_judging_inventory.judging_inventory_panel(dict(retained_inventory_job='coverage', retained_inventory_items_job='funding'))
        # Funding cards are conditional; the shared CSS must also cover that state.
        render(page, ui._page('Judging', panel+"<dl class='judging-funding-summary'><div><dt>Budget</dt><dd>0</dd></div></dl><section class='card'>Reference</section>"))
        assert page.locator('.judging-funding-summary>div').last.evaluate('e=>getComputedStyle(e).backgroundColor') == page.locator('.card').last.evaluate('e=>getComputedStyle(e).backgroundColor')
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 1440])
def test_model_search_and_framework_action_spacing(browser, tmp_path, monkeypatch, width):
    from test_rig_web_model_picker import _repo_app
    app = _repo_app(tmp_path)
    calls = []
    monkeypatch.setattr(app, 'start_job', lambda *a, **kw: calls.append((a,kw)))
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, app._build_page())
        page.locator('#build-pipeline-tab').click()
        page.locator('[data-open-model-picker=target]').click()
        page.locator('[data-picker-kind=local]').click()
        search = page.locator('.picker-model-panel[data-picker-panel=local] .targetfilters input[type=search]')
        assert search.count()
        for field in search.all():
            assert field.evaluate('e=>parseFloat(getComputedStyle(e).paddingLeft)') >= 10
        page.locator('[data-close-model-picker]:visible').first.click()
        for row in page.locator('.workflow-actions').all():
            assert row.evaluate('e=>getComputedStyle(e).gap') == '12px'
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        assert not calls
    finally:
        page.close()
        app.close()


@pytest.mark.parametrize('width', [390, 768, 1440])
@pytest.mark.parametrize('kind', ['campaigns', 'workspace', 'exports', 'runtime', 'legacy-stats'])
def test_action_links_are_spaced_as_actions(browser, study, width, kind):
    from test_rig_web_workspace_results import assignment, response
    app, params, calls, _ = study
    owner = params['campaign_id']
    if kind == 'campaigns':
        body = app._workspaces_page()
        selector = "a[href='/build?work_kind=campaign#build-general']"
    elif kind == 'workspace':
        body = app._workspace_page(owner, {})
        selector = "a[href='/build?campaign_id="+owner+"']"
    elif kind == 'exports':
        app.db.publish_workspace_results(owner, assignments=[assignment()], responses=[response()], judgments=[])
        body = ui._page('Results', app._workspace_results(owner, 'overview', {}))
        selector = '#campaign-exports a'
    elif kind == 'runtime':
        body = ui._page('Runtimes', app._framework_runtime_panel())
        selector = "a[href='/build#build-runtimes']"
    else:
        body = ui._page('Stats', "<div class='stats-campaign-actions'><a class='button' href='/stats'>Details</a><a class='button' href='/jobs'>Jobs</a></div><nav class='stats-pagination'><a href='/stats'>Previous</a><a href='/stats'>Next</a></nav>")
        selector = '.stats-campaign-actions a'
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, body)
        row = page.locator(selector).first.locator('..')
        assert row.evaluate('e=>getComputedStyle(e).display') == 'flex'
        assert row.evaluate('e=>getComputedStyle(e).gap') == '12px'
        boxes = [link.bounding_box() for link in row.locator(':scope>a').all()]
        assert len(boxes)>=2
        for a,b in zip(boxes, boxes[1:]):
            assert (b['x']-a['x']-a['width'] if abs(a['y']-b['y'])<1 else b['y']-a['y']-a['height'])>=12
        if kind=='legacy-stats':assert page.locator('.stats-pagination').evaluate('e=>getComputedStyle(e).gap')=='12px'
        assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
        assert not calls
    finally:
        page.close()


@pytest.mark.parametrize('width', [390, 768, 1440])
def test_notice_title_does_not_overlap_dismiss_button(browser, study, monkeypatch, width):
    app, _, calls, _ = study
    monkeypatch.setattr(app, '_load_warnings', lambda: [dict(level='warning',title='BIPIA qa blocked - NewsQA base data is license-gated (operator action needed)',detail='Synthetic layout notice.')])
    page = browser.new_page(viewport={'width':width, 'height':1000})
    try:
        render(page, ui._page('Dashboard', app._warnings_html()))
        notice = page.locator('.notice')
        assert notice.evaluate('e=>parseFloat(getComputedStyle(e).paddingRight)')>=40
        assert notice.evaluate("""e=>{
          const b=e.querySelector('button').getBoundingClientRect(),r=document.createRange();
          r.selectNodeContents(e.querySelector('strong'));
          return [...r.getClientRects()].every(a=>a.right<=b.left||a.left>=b.right||a.bottom<=b.top||a.top>=b.bottom);
        }""")
        assert not calls
    finally:
        page.close()
