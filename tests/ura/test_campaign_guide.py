"""Guidance is persisted UI help, never a change to experiment semantics."""
from types import SimpleNamespace
from urllib.parse import urlsplit
from pathlib import Path
import os

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app import campaign_guide, ui
from test_rig_web_busy_browser import browser  # noqa: F401


@pytest.fixture
def app(tmp_path, monkeypatch):
    result = RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state',
        repo_root=tmp_path, gpu_hardware={}, system_hardware={})
    def forbidden(*args, **kwargs):
        raise AssertionError('Campaign guidance must never launch work')
    monkeypatch.setattr(result, 'start_job', forbidden)
    yield result
    result.close()


def draft(**changes):
    return dict(work_kind='campaign', campaign_name='My guided campaign', mode='dry_run',
        corpora='synth', attackers='replay', judges='rules,llm', limit='1', **changes)


def test_opt_in_survives_save_reopen_and_can_be_disabled(app):
    plain = app.handle('GET', '/build?work_kind=campaign')[2].decode()
    assert "name='campaign_guide'><span>" in plain
    assert "data-guide-enabled='false'" in plain
    status, location, _ = app.handle('POST', '/build/save', draft(campaign_guide='on'))
    assert status == 303
    owner = location.split('/campaigns/')[1].split('?')[0]
    assert app.db.workspace_definition(owner)['campaign_guide'] == 'on'
    for path in (location, '/build?campaign_id='+owner):
        page = app.handle('GET', path)[2].decode()
        assert "data-guide-enabled='true'" in page
        assert page.count("<dialog class='campaign-guide-dialog'") == 1
    assert "data-guide-enabled='true'" in app._campaign_banner(owner)
    plain = app.db.workspace_definition(owner)
    plain.pop('campaign_guide')
    app._save_build_campaign(plain)
    assert 'campaign_guide' not in app.db.workspace_definition(owner)
    assert 'campaign-guide-dialog' not in app.handle('GET', location)[2].decode()
    assert not app.db.load_jobs()


def test_help_does_not_change_cli_or_projection_and_never_applies_to_single_runs(app, tmp_path):
    params = draft(out=str(tmp_path/'runs'/'demo'))
    guided = dict(params, campaign_guide='on')
    assert app._projection_params(params) == app._projection_params(guided)
    command, values, _ = app._compose_from_builder(params)
    other_command, other_values, _ = app._compose_from_builder(guided)
    # Composition intentionally creates uniquely named configuration snapshots.
    # Compare their actual payloads, then all the remaining CLI fields exactly.
    assert Path(values.pop('--source-config')).read_bytes() == Path(other_values.pop('--source-config')).read_bytes()
    assert (command, values) == (other_command, other_values)
    single = app._builder_params(dict(guided, work_kind='run'))
    assert 'campaign_guide' not in single and 'campaign_name' not in single
    with pytest.raises(ValueError, match='guidance choice'):
        app._builder_params(dict(guided, campaign_guide='yes'))


@pytest.mark.parametrize('state,role,expected', [
    ('running', 'collection', 'Run'), ('failed', 'judging', 'Recovery'),
    ('complete', 'collection', 'Judge'), ('complete', 'judging', 'Results'),
    ('complete', 'preparation', 'Prepare')])
def test_suggestions_use_bounded_activity_not_preparation_field_presence(state, role, expected):
    row = dict(member_kind='job', member_id='job-one', state=state, role=role)
    reads = []
    db = SimpleNamespace(workspace_activity=lambda owner: reads.append(owner) or [row])
    steps, stage, notice, _ = campaign_guide._guidance(SimpleNamespace(db=db),
        dict(campaign_id='a'*32, api='google:flash', retained_source_campaign='b'*32,
             retained_inventory_plan_job='saved-is-not-completed'))
    assert steps[stage][0] == expected and reads == ['a'*32]
    assert 'whole campaign is finished' in notice if state == 'complete' else state in notice


def test_matched_and_local_suggestions_are_distinct_and_links_do_not_execute(app):
    from html.parser import HTMLParser
    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.hrefs = []
        def handle_starttag(self, tag, attrs):
            if tag == 'a':
                self.hrefs.append(dict(attrs)['href'])
    local = campaign_guide.render(app, dict(local='vllm:qwen', campaign_guide='on'), builder=True)
    hosted = campaign_guide.render(app, dict(api='google:flash', retained_source_campaign='b'*32,
        campaign_guide='on'), builder=True)
    assert 'Compose &amp; review' in local and 'Prepare comparison and review' in hosted
    assert 'sampled paired comparison' in hosted and 'text proxy' in hosted
    links = Links()
    links.feed(local + hosted)
    assert all(urlsplit(href).path in {'/build', '/config', '/config/secrets', '/commands', '/jobs', '/campaigns'} for href in links.hrefs)
    assert all(not urlsplit(href).fragment or urlsplit(href).fragment in {
        'build-general','build-evaluation','target-models','input-corpora','retained-inputs',
        'local-hardware','framework-runtimes','attack-frameworks','sample-size-control',
        'evaluation-judges','execution-budgets','local-serving','cfg-editor','pipeline-review','transport-evidence','automatic-comparison'
    } for href in links.hrefs)


@pytest.mark.parametrize('command', ['retained_native_judge_prepare', 'retained_response_judge_pair',
    'retained_judge_inventory', 'retained_inventory_judge_items', 'retained_inventory_judging'])
def test_completed_judging_preparation_is_not_a_completed_judgment(command):
    row = dict(member_kind='job', member_id='prepared', state='complete', role='judging', command=command)
    db = SimpleNamespace(workspace_activity=lambda owner: [row])
    steps, stage, _, _ = campaign_guide._guidance(SimpleNamespace(db=db),
        dict(campaign_id='a'*32, api='google:flash', retained_source_campaign='b'*32,
             retained_inventory_plan_job='prepared'))
    assert steps[stage][0] == 'Judge'


def test_guide_covers_all_build_sections_and_optional_campaign_analysis(app):
    saved = app._save_build_campaign(draft(campaign_guide='on'))
    content = campaign_guide.render(app, saved)
    for target in ('retained-inputs','local-hardware','target-models','evaluation-judges','transport-evidence','local-serving'):
        assert '#' + target in content
    for topic in ('Runtimes', 'Human review', 'SVM analysis', 'Recovery'):
        assert topic in content
    owner = saved['campaign_id']
    for href in ('/human-evaluation?campaign_id='+owner,
        '/analysis?campaign_id='+owner,
        '/commands?cmd=local_model_readiness&campaign_id='+owner):
        import html
        assert html.escape(href, quote=True) in content
        assert app.handle('GET', href)[0] == 200
    assert 'finished campaigns' in content and 'static text' in content
    assert 'No target or judge call' in content and not app.db.load_jobs()
    assert 'workflow companion, not a preset recipe' in content


def _browser_page(browser, app, width=1440):
    page = browser.new_page(viewport={'width': width, 'height': 900})
    requests, errors = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    def route(request):
        parsed = urlsplit(request.request.url)
        requests.append((request.request.method, parsed.path))
        if parsed.path == '/static/style.css':
            request.fulfill(status=200, content_type='text/css', body=ui._STYLE)
        elif request.request.method == 'GET':
            status, mime, body = app.handle('GET', parsed.path + ('?'+parsed.query if parsed.query else ''))
            request.fulfill(status=status, content_type=mime, body=body)
        else:
            raise AssertionError('Guide browser navigation may not submit jobs')
    page.route('http://guide.test/**', route)
    return page, requests, errors


@pytest.mark.parametrize('width', [1440, 390])
def test_browser_checkbox_modal_keyboard_steps_links_and_single_run(browser, app, width):  # noqa: F811
    page, requests, errors = _browser_page(browser, app, width)
    try:
        page.goto('http://guide.test/build?work_kind=campaign')
        dialog = page.locator('.campaign-guide-dialog')
        assert not dialog.is_visible()
        assert not page.locator('[data-guide-open]').is_visible()
        page.locator('[name=campaign_guide]').check()
        assert dialog.is_visible()
        page.get_by_text('Browse all 11 topics', exact=True).click()
        page.get_by_role('button', name='4. Settings', exact=True).click()
        assert 'Choose evaluation' in page.locator('.campaign-guide-section:visible').inner_text()
        page.locator('[data-guide-next]').click()
        assert 'Prepare and review' in page.locator('.campaign-guide-section:visible').inner_text()
        page.locator('[data-guide-back]').click()
        page.keyboard.press('Escape')
        assert not dialog.is_visible()
        assert page.locator('[name=campaign_guide]').evaluate('e=>e===document.activeElement')
        page.locator('[data-guide-open]').click()
        assert dialog.is_visible()
        page.locator('.campaign-guide-topics').evaluate('e=>e.open=false')
        for theme in ('harbor', 'slate', 'parchment', 'midnight', 'ash'):
            page.evaluate('(theme)=>document.documentElement.dataset.theme=theme', theme)
            assert dialog.evaluate('e=>e.scrollWidth<=e.clientWidth+1')
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        if os.environ.get('URA_GUIDE_SCREENSHOTS'):
            page.screenshot(path=str(Path(os.environ['URA_GUIDE_SCREENSHOTS'])/f'guide-{width}.png'))
        page.get_by_role('link', name='Choose judges', exact=True).click()
        assert not dialog.is_visible()
        page.locator('#build-evaluation').wait_for(state='visible')
        assert page.locator('#build-evaluation').is_visible()
        page.locator('[data-guide-open]').click()
        page.locator('[data-guide-close]').click()
        page.locator('[name=work_kind][value=run]').check()
        assert page.locator('[name=campaign_guide]').is_disabled()
        assert not page.locator('[data-guide-open]').is_visible()
        assert not errors and not [row for row in requests if row[0] != 'GET']
        assert not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('topic,link,path', [
    ('9. Human review','Open human-evaluation wizard','/human-evaluation'),
    ('10. SVM analysis','Open SVM analysis','/analysis')])
def test_guide_backend_links_close_dialog_and_use_shared_wait_guard(browser, app, topic, link, path):  # noqa: F811
    from urllib.parse import urlsplit
    saved = app._save_build_campaign(draft(campaign_guide='on'))
    page, _, errors = _browser_page(browser, app, 390)
    pending = []
    try:
        page.goto('http://guide.test/build?campaign_id='+saved['campaign_id'])
        page.get_by_text('Browse all 11 topics', exact=True).click()
        page.get_by_role('button', name=topic, exact=True).click()
        page.route('http://guide.test'+path+'?*', lambda route: pending.append(route))
        # Read the departing document in the click itself: once navigation is
        # pending, browser queries may wait for the next document to commit.
        state = page.get_by_role('link', name=link, exact=True).evaluate("""e=>{
            e.click();return {busy:uraBusy.isBusy(),dialog:document.querySelector('.campaign-guide-dialog').open,
            visible:getComputedStyle(document.getElementById('busy-overlay')).display==='flex',
            inert:document.querySelector('main').inert};}""")
        assert state==dict(busy=True,dialog=False,visible=True,inert=True)
        page.wait_for_timeout(80)
        assert len(pending)==1
        request = urlsplit(pending[0].request.url)
        code,mime,content = app.handle('GET',request.path+'?'+request.query)
        assert code==200
        pending[0].fulfill(status=code,content_type=mime,body=content)
        page.wait_for_url('http://guide.test'+path+'?*')
        page.wait_for_function('!window.uraBusy.isBusy()')
        assert not page.locator('#busy-overlay').is_visible()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('width', [1440,390])
def test_guide_links_reveal_scroll_and_focus_exact_controls_including_same_hash(browser, app, width):  # noqa: F811
    saved=app._save_build_campaign(draft(campaign_guide='on'))
    page,requests,errors=_browser_page(browser,app,width)
    base='http://guide.test/build?campaign_id='+saved['campaign_id']
    try:
        page.goto(base)
        original=page.locator('[name=cap_target]').input_value()
        def topic(label):
            if not page.locator('.campaign-guide-dialog').is_visible():
                page.locator('[data-guide-open]').click()
            if not page.locator('.campaign-guide-topics').evaluate('e=>e.open'):
                page.get_by_text('Browse all 11 topics',exact=True).click()
            page.get_by_role('button',name=label,exact=True).click()
        def destination(anchor,panel):
            page.wait_for_function("""([id,panel])=>{const node=document.getElementById(id),r=node.getBoundingClientRect();
                return !document.getElementById(panel).hidden&&r.top>=document.querySelector('body>nav').getBoundingClientRect().bottom-2
                &&r.top<innerHeight-70&&node.contains(document.activeElement);}""",arg=[anchor,panel])
            assert page.url.endswith('#'+anchor)
            assert not page.locator('.campaign-guide-dialog').is_visible()
            assert not page.evaluate('uraBusy.isBusy()')
        for _ in range(2):
            topic('4. Settings')
            before=requests.count(('GET','/build'))
            page.get_by_role('link',name='Inspect local serving',exact=True).click()
            destination('local-serving','build-execution')
            assert requests.count(('GET','/build'))==before, 'Same-document help must not reload Build'
        topic('3. Inputs')
        page.get_by_role('link',name='Set limits and sampling',exact=True).click()
        destination('sample-size-control','build-execution')
        topic('3. Inputs')
        page.get_by_role('link',name='Select saved source runs',exact=True).click()
        destination('retained-inputs','build-general')
        topic('5. Prepare')
        page.get_by_role('link',name='Check transport evidence',exact=True).click()
        destination('transport-evidence','build-admission')
        assert page.locator('#setup-mode').is_visible()
        assert not page.locator('#advanced-setup-fields').is_visible()
        # A new page with an inner fragment overrides the remembered General tab.
        page.goto(base+'#target-models')
        destination('target-models','build-pipeline')
        assert page.locator('[name=cap_target]').input_value()==original
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('field,target', [
        ('retained_sources_job','automatic-comparison'),('retained_budget_job','automatic-comparison'),
        ('retained_replays_job','automatic-comparison')])
def test_matched_guide_preparation_links_follow_available_prerequisites(app,field,target):
    steps,_,_,_=campaign_guide._guidance(app,draft(api='google:flash',retained_source_campaign='source',**{field:'prepared'}))
    prepare=next(step for step in steps if step[0]=='Prepare')
    assert prepare[3][0][1].endswith('#'+target)
    judge=next(step for step in steps if step[0]=='Judge')
    assert judge[3][0][1].endswith('#'+target)


def test_browser_remembers_dismissal_per_campaign_and_reopens_on_demand(browser, app):  # noqa: F811
    saved = app._save_build_campaign(draft(campaign_guide='on'))
    path = '/campaigns/'+saved['campaign_id']+'?section=definition'
    page, requests, errors = _browser_page(browser, app)
    try:
        page.goto('http://guide.test'+path)
        assert page.locator('.campaign-guide-dialog').is_visible()
        page.locator('[data-guide-close]').click()
        page.reload()
        assert not page.locator('.campaign-guide-dialog').is_visible()
        page.locator('[data-guide-open]').click()
        assert page.locator('.campaign-guide-dialog').is_visible()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()
