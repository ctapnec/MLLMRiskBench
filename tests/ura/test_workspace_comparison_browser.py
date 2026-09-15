"""Dependent Compare controls refresh without manual-submit guesswork."""
import os
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import pytest
expect = pytest.importorskip('playwright.sync_api').expect

from experiments.rig_web_app import ui
from test_workspace_comparison import study, pair, put  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401
from test_workspace_comparison_scope import scoped_study, expected_conditions  # noqa: F401
from experiments.rig_web_app.workspace_comparison_many import CONDITION_MODES


def open_page(browser, study, width=1440, query=None):
    app, left, _, _ = study
    page = browser.new_page(viewport={'width':width,'height':900})
    requests, errors = [], []
    page.on('pageerror', lambda error: errors.append(str(error)))
    def route(item):
        req = item.request
        assert req.method == 'GET', 'Comparison must never submit campaign work'
        parsed = urlsplit(req.url)
        requests.append(req.url)
        if parsed.path == '/static/style.css':
            item.fulfill(status=200, content_type='text/css', body=ui._STYLE)
        else:
            status, mime, body = app.handle('GET', parsed.path+('?' + parsed.query if parsed.query else ''))
            item.fulfill(status=status, content_type=mime, body=body)
    page.route('http://compare.test/**', route)
    page.goto('http://compare.test/campaigns/'+left+'?'+urlencode(dict(section='compare', **(query or {}))))
    return page, requests, errors


def ready(page):
    expect(page.locator('[data-comparison-feedback]')).to_have_text(
        'Choices updated. Select the next available field or inspect the comparison below.')
    page.wait_for_function('!window.uraBusy.isBusy()')


@pytest.mark.parametrize('width',[1440,390])
def test_condition_options_follow_model_and_campaign_switches_exactly(browser,study,scoped_study,width):  # noqa: F811
    app,left,right,other=scoped_study
    page,_,errors=open_page(browser,study,width,dict(right_campaign=right))
    def choose(name,value):
        page.locator('[name='+name+']').select_option(value)
        ready(page)
    def conditions(side,owner,model):
        values=page.locator('select[name='+side+'_condition] option').evaluate_all('(items)=>items.map(e=>e.value).filter(Boolean)')
        assert set(values)==set(CONDITION_MODES) | expected_conditions(owner,model,right)
        assert model in page.locator('[data-comparison-scope='+side+']').inner_text()
    try:
        for side,owner in [('left',left),('right',right)]:
            for model in ('qwen','gemma','qwen'):
                choose(side+'_model',model)
                conditions(side,owner,model)
                expect(page.locator('[name='+side+'_judge]')).to_be_disabled()
                choose(side+'_condition',owner+'-'+model+'-image')
                offered=page.locator('[name='+side+'_judge] option').evaluate_all('(items)=>items.map(e=>e.value).filter(Boolean)')
                assert offered==[owner+'-'+model+'-image-judge']
                page.locator('[data-condition-details='+side+'] summary').click()
                assert 'Corpora: '+owner+'-source' in page.locator('[data-condition-details='+side+']').inner_text()
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            choose(side+'_model','*')
            assert 'all measured conditions, compared separately' in page.locator('[data-comparison-scope='+side+']').inner_text()
            choose(side+'_model','qwen')
            conditions(side,owner,'qwen')
        choose('left_condition',left+'-qwen-text')
        for owner in (other,right):
            choose('right_campaign',owner)
            expect(page.locator('[name=right_condition]')).to_be_disabled()
            expect(page.locator('[name=left_condition]')).to_have_value(left+'-qwen-text')
            choose('right_model','qwen')
            conditions('right',owner,'qwen')
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('side',['left','right'])
def test_condition_changes_preserve_only_the_exact_available_judge(browser,study,side):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    owner,model=(left,'local') if side=='left' else (right,'api')
    put(app,owner,'next','shared',model=model,condition='next',judge='judge')
    put(app,owner,'different','shared',model=model,condition='different',judge='different-judge')
    page,requests,errors=open_page(browser,study,query=query)
    try:
        for condition in ('next',query[side+'_condition']):
            page.locator('[name='+side+'_condition]').select_option(condition)
            ready(page)
            expect(page.locator('[name='+side+'_judge]')).to_have_value('judge')
            assert 'matched: 1' in page.locator('[data-comparison-results]').inner_text()
            before=len(requests)
            # Repeated same-value selection must not reload or discard a judge.
            page.locator('[name='+side+'_condition]').select_option(condition)
            page.wait_for_timeout(50)
            assert len(requests)==before
            expect(page.locator('[name='+side+'_judge]')).to_have_value('judge')
        page.locator('[name='+side+'_condition]').select_option('different')
        ready(page)
        expect(page.locator('[name='+side+'_judge]')).to_have_value('')
        assert page.locator('[data-judge-reset='+side+']').is_visible()
        assert not page.locator('[data-comparison-results]').count()
        page.locator('[name='+side+'_judge]').select_option('different-judge')
        ready(page)
        assert 'matched: 1' in page.locator('[data-comparison-results]').inner_text()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('width', [1440,390])
def test_compare_populates_all_dependencies_and_keeps_exports_working(browser, study, width):  # noqa: F811
    app, left, right, _ = study
    pair(study, 'shared')
    page, requests, errors = open_page(browser, study, width)
    try:
        expect(page.locator('[name=right_model]')).to_be_disabled()
        expect(page.locator('[name=left_condition]')).to_be_disabled()
        assert 'Choose a campaign first' in page.locator('#right_model-help').inner_text()
        page.locator('[name=right_campaign]').select_option(right)
        ready(page)
        expect(page.locator('[name=right_model]')).to_be_enabled()
        assert page.locator('[name=right_model]').evaluate('e=>getComputedStyle(e).backgroundImage')!='none'
        assert page.locator('[name=right_model] option').count() == 3
        # Use the actual control with keyboard input, not only DOM selection.
        field = page.locator('[name=left_model]')
        field.focus()
        field.press('End')
        ready(page)
        expect(page.locator('[name=left_model]')).to_have_value('local')
        expect(page.locator('[name=left_condition]')).to_be_enabled()
        for name, value in [('right_model','api'),('left_condition','lc'),('right_condition','rc'),
                            ('left_judge','judge'),('right_judge','judge')]:
            page.locator('[name='+name+']').select_option(value)
            ready(page)
        assert 'matched: 1' in page.locator('[data-comparison-results]').inner_text()
        page.locator('[name=compare_corpus]').select_option('corpus')
        ready(page)
        for name in ('left_model','right_model','left_condition','right_condition','left_judge','right_judge',
                     'compare_corpus','compare_framework','compare_modality'):
            expect(page.locator('[name='+name+']')).to_be_enabled()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        if os.environ.get('URA_COMPARE_SCREENSHOTS'):
            page.screenshot(path=str(Path(os.environ['URA_COMPARE_SCREENSHOTS'])/f'compare-{width}.png'),full_page=True)
        with page.expect_download():
            page.get_by_role('link', name="Download this page's counts",exact=True).click()
        page.wait_for_function('!window.uraBusy.isBusy()')
        expect(page.locator('#campaign-export-status')).to_have_text('Export prepared.')
        assert 'compare_corpus=corpus' in page.url
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


def test_changing_campaign_clears_only_its_dependents_and_explains_empty_judges(browser, study):  # noqa: F811
    app, left, right, query = study
    pair(study,'shared')
    unjudged = app.db.create_workspace('Unjudged','local')
    put(app,unjudged,'unjudged','shared',model='third',condition='new',status=None)
    page, _, errors = open_page(browser,study,query=query)
    try:
        page.locator('[name=right_campaign]').select_option(unjudged)
        ready(page)
        expect(page.locator('[name=left_judge]')).to_have_value('judge')
        for name in ('right_model','right_condition','right_judge'):
            expect(page.locator('[name='+name+']')).to_have_value('')
        assert not page.locator('[data-comparison-results]').count()
        page.locator('[name=right_model]').select_option('third')
        ready(page)
        page.locator('[name=right_condition]').select_option('new')
        ready(page)
        expect(page.locator('[name=right_judge]')).to_be_disabled()
        assert 'No indexed judgments' in page.locator('#right_judge-help').inner_text()
        assert not errors
    finally:
        page.close()


@pytest.mark.parametrize('outcome', ['success','http_error','network_error','timeout'])
@pytest.mark.parametrize('scope',['single','models','conditions'])
def test_compare_wait_blocks_duplicate_interactions_and_releases_for_retry(browser,study,outcome,scope):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    if scope=='models':
        query=dict(query,left_model='*',right_model='*')
    elif scope=='conditions':
        query=dict(query,left_condition='*',right_condition='*')
    page,_,errors=open_page(browser,study,query=query)
    pending=[]
    pattern='http://compare.test/campaigns/'+left+'?*'
    page.route(pattern,lambda route:pending.append(route))
    try:
        if outcome=='timeout':
            page.evaluate("""()=>{const original=window.setTimeout;
                window.setTimeout=(fn,delay,...args)=>original(fn,delay===30000?500:delay,...args);} """)
        page.locator('[name=compare_modality]').select_option('text')
        page.wait_for_function('window.uraBusy.isBusy()')
        assert page.locator('main').evaluate('e=>e.inert')
        assert page.locator('#busy-overlay').is_visible()
        assert not page.locator('[data-comparison-results]').is_visible()
        page.evaluate("""()=>{const form=document.querySelector('[data-comparison-form]');
            for(let i=0;i<10;i++){form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
            form.querySelector('select').dispatchEvent(new Event('change',{bubbles:true,cancelable:true}));}}""")
        page.wait_for_timeout(50)
        assert len(pending)==1
        if outcome=='success':
            parsed=urlsplit(pending[0].request.url)
            code,mime,content=app.handle('GET',parsed.path+'?'+parsed.query)
            pending[0].fulfill(status=code,content_type=mime,body=content)
        elif outcome=='http_error':
            pending[0].fulfill(status=503,body='temporarily unavailable')
        elif outcome=='network_error':
            pending[0].abort('failed')
        page.wait_for_function('!window.uraBusy.isBusy()')
        assert not page.locator('main').evaluate('e=>e.inert')
        assert not page.locator('#busy-overlay').is_visible()
        if outcome!='success':
            assert page.locator('[data-comparison-feedback]').inner_text()
            assert not page.locator('[data-comparison-results]').is_visible()
            page.unroute(pattern)
            page.get_by_role('button',name='Update choices / compare',exact=True).click()
            ready(page)
        assert page.locator('[data-comparison-results]').is_visible()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('width',[1440,390])
@pytest.mark.parametrize('scope',['left','right','both'])
def test_all_models_on_either_side_keep_choices_results_and_downloads_usable(browser,study,width,scope):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    put(app,left,'local-other','shared',model='local-other',condition='new')
    put(app,right,'api-other','shared',model='api-other',condition='new',status=None)
    page,_,errors=open_page(browser,study,width,query)
    try:
        for side in (('left','right') if scope=='both' else (scope,)):
            page.locator('[name='+side+'_model]').select_option('*')
            ready(page)
            expect(page.locator('select[name='+side+'_condition]')).to_have_value('*')
            page.locator('[name='+side+'_judge]').select_option('judge')
            ready(page)
        assert page.locator('[data-model-comparison]').count()==(4 if scope=='both' else 2)
        page.locator('[data-model-comparison] summary').first.click()
        assert page.locator('[data-model-comparison]').first.evaluate('e=>e.open')
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        with page.expect_download():
            page.get_by_role('link',name="Download this page's counts",exact=True).click()
        page.wait_for_function('!window.uraBusy.isBusy()')
        expect(page.locator('#campaign-export-status')).to_have_text('Export prepared.')
        for side in (('left','right') if scope=='both' else (scope,)):
            page.locator('[name='+side+'_model]').select_option('local' if side=='left' else 'api')
            ready(page)
            assert page.locator('select[name='+side+'_condition]').count()==1
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('width',[1440,390])
@pytest.mark.parametrize('scope',['left','right','both'])
def test_all_conditions_on_either_side_roundtrip_and_preserve_judges(browser,study,width,scope):  # noqa: F811
    import csv
    app,left,right,query=study
    pair(study,'shared')
    put(app,left,'local-second','shared',condition='second')
    put(app,right,'api-second','shared',model='api',condition='second')
    put(app,right,'other-model','shared',model='other',condition='unrelated')
    page,requests,errors=open_page(browser,study,width,query)
    sides=('left','right') if scope=='both' else (scope,)
    try:
        for side in sides:
            page.locator('[name='+side+'_condition]').select_option('*')
            ready(page)
            expect(page.locator('[name='+side+'_judge]')).to_have_value('judge')
            expect(page.locator('[name='+side+'_model]')).to_have_value(query[side+'_model'])
            assert page.locator('[data-all-conditions='+side+']').is_visible()
            before=len(requests)
            page.locator('[name='+side+'_condition]').select_option('*')
            page.wait_for_timeout(50)
            assert len(requests)==before
        assert page.locator('[data-model-comparison]').count()==(4 if scope=='both' else 2)
        assert 'other (condition' not in page.locator('[data-comparison-results]').inner_text()
        page.locator('[data-model-comparison] summary').first.click()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        with page.expect_download() as event:
            page.get_by_role('link',name="Download this page's counts",exact=True).click()
        with open(event.value.path(),encoding='utf-8-sig',newline='') as stream:
            rows=list(csv.DictReader(stream))
        assert {r['left_model'] for r in rows}=={'local'} and {r['right_model'] for r in rows}=={'api'}
        assert all(r['left_condition']!='*' and r['right_condition']!='*' for r in rows)
        page.wait_for_function('!window.uraBusy.isBusy()')
        for side in sides:
            page.locator('[name='+side+'_condition]').select_option(query[side+'_condition'])
            ready(page)
            expect(page.locator('[name='+side+'_judge]')).to_have_value('judge')
        assert 'matched: 1' in page.locator('[data-comparison-results]').inner_text()
        assert not page.locator('[data-model-comparison]').count()
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()


@pytest.mark.parametrize('width',[1440,390])
@pytest.mark.parametrize('side',['left','right'])
def test_condition_rules_work_for_single_and_all_models(browser,study,width,side):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared',output_allowance=1024,context_tokens=4096)
    owner=left if side=='left' else right
    for model in (query[side+'_model'],'other'):
        put(app,owner,model+'-large','shared',model=model,condition='large',output_allowance=8192,context_tokens=32768)
    page,_,errors=open_page(browser,study,width,query)
    try:
        for model in (query[side+'_model'],'*'):
            if model=='*':
                page.locator('[name='+side+'_model]').select_option('*')
                ready(page)
            for rule in ('__max_output__','__max_context__','__best_response__'):
                page.locator('[name='+side+'_condition]').select_option(rule)
                ready(page)
                expect(page.locator('[name='+side+'_condition]')).to_have_value(rule)
                assert page.locator('[data-condition-rule='+side+']').is_visible()
                if not page.locator('[name='+side+'_judge]').input_value():
                    page.locator('[name='+side+'_judge]').select_option('judge')
                    ready(page)
                assert page.locator('[data-model-comparison]').count()>=1
                if rule!='__best_response__':
                    assert all('output allowance 8192' in d for d in page.locator('[data-model-comparison]').all_text_contents())
                assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        page.locator('[name='+side+'_condition]').select_option('*')
        ready(page)
        expect(page.locator('[name='+side+'_judge]')).to_have_value('judge')
        assert not errors and not app.db.load_jobs()
    finally:
        page.close()
