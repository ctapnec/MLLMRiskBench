from urllib.parse import urlsplit
import pytest
from test_human_personal_review import personal  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401
from experiments.rig_web_app import ui


@pytest.mark.parametrize('width',[1440,390])
def test_saved_answers_reach_rating_form_save_and_resume(browser,personal,width):
    app,owner,_=personal
    page=browser.new_page(viewport=dict(width=width,height=1000))
    errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
    export_fault={'enabled':False}
    def route(item):
        from urllib.parse import parse_qs
        req=item.request;parsed=urlsplit(req.url)
        if parsed.path.endswith('/personal.csv') and export_fault['enabled']:
            return item.fulfill(status=503,body='Synthetic unavailable export')
        if parsed.path=='/static/style.css':return item.fulfill(status=200,content_type='text/css',body=ui._STYLE)
        data={key:values[-1] for key,values in parse_qs(req.post_data or '',keep_blank_values=True).items()}
        status,mime,body=app.handle(req.method,parsed.path+('?' + parsed.query if parsed.query else ''),data)
        if status==303:return item.fulfill(status=303,headers={'Location':mime},body='')
        item.fulfill(status=status,content_type=mime,body=body)
    page.route('http://review.test/**',route)
    try:
        page.goto('http://review.test/human-evaluation?campaign_id='+owner)
        assert page.locator('[name=ethics_status]').count()==0
        page.locator('[name=source]').select_option(label='Saved text answers')
        page.locator('[name=clusters]').fill('1')
        page.locator('[name=acknowledge]').check()
        page.get_by_role('button',name='Prepare answers for review',exact=True).click()
        page.get_by_role('heading',name='Personal evaluation',exact=True).wait_for()
        assert page.title()=='Personal evaluation'
        assert page.locator('body > nav').count()==1
        assert page.locator('body > nav a.active').inner_text()=='Campaigns'
        assert page.locator('body > nav #theme-picker').count()==1
        page.evaluate("() => { window.endReviewWait=window.uraBusy.begin('Synthetic wait'); }")
        assert page.locator('body > nav').evaluate('e=>e.inert')
        page.evaluate('window.endReviewWait()')
        assert not page.locator('body > nav').evaluate('e=>e.inert')
        assert 'A substantial example answer.' in page.locator('#review-body').inner_text()
        assert page.get_by_role('button',name='Consent and begin').count()==0
        assert page.get_by_role('button',name='Withdraw from further review').count()==0
        assert page.get_by_role('navigation',name='Assessment steps').bounding_box()['y'] < page.locator('.review-reference').bounding_box()['y']
        refusal_box=page.get_by_role('button',name='2. Refusal',exact=True).bounding_box()
        assert 0 <= refusal_box['y'] and refusal_box['y']+refusal_box['height'] <= 1000
        page.get_by_role('button',name='Next',exact=True).click()
        for key,value in [('refusal_label','not_refusal'),('harmfulness_label','not_harmful'),
                          ('convincingness_label','not_applicable'),('specificity_label','not_applicable')]:
            page.locator('[data-rating='+key+']').select_option(value)
            page.get_by_role('button',name='Next',exact=True).click()
        page.locator('[data-rating=label]').select_option('safe')
        page.locator('[data-rating=confidence]').select_option('4')
        page.get_by_role('button',name='Save evaluation',exact=True).click()
        page.wait_for_function("document.querySelector('#review-status').textContent==='Personal evaluation saved.'")
        page.reload()
        page.get_by_role('heading',name='Personal evaluation',exact=True).wait_for()
        assert page.locator('[data-rating=label]').input_value()=='safe'
        assert page.locator('[data-rating=label]').is_enabled()
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        page.get_by_role('link',name='Review progress and export',exact=True).click()
        assert '1 / 1 evaluations saved' in page.locator('main').inner_text()
        assert page.get_by_role('link',name='Download personal evaluations',exact=True).count()==1
        with page.expect_download() as download:
            page.get_by_role('link',name='Download personal evaluations',exact=True).click()
        assert download.value.suggested_filename=='personal-evaluations.csv'
        page.wait_for_function("!window.uraBusy.isBusy() && document.querySelector('#campaign-export-status').textContent==='Export prepared.'")
        export_fault['enabled']=True
        page.get_by_role('link',name='Download personal evaluations',exact=True).click()
        page.wait_for_function("!window.uraBusy.isBusy() && document.querySelector('#campaign-export-status').textContent.includes('503')")
        export_fault['enabled']=False
        with page.expect_download():page.get_by_role('link',name='Download personal evaluations',exact=True).click()
        page.wait_for_function('!window.uraBusy.isBusy()')
        page.locator('body > nav').get_by_role('link',name='Campaigns',exact=True).click()
        page.wait_for_url('**/campaigns')
        assert page.locator('body > nav a.active').inner_text()=='Campaigns'
        assert not errors
    finally:page.close()
