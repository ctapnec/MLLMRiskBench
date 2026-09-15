"""Synthetic image ratings exercise the screenshot's omitted confirmation."""
import base64
import json
from pathlib import Path
from urllib.parse import parse_qs,urlsplit

import pytest

from test_human_personal_review import personal,open_personal  # noqa: F401
from test_human_review_ui import prepared,qualification
from test_rig_web_busy_browser import browser  # noqa: F401
from experiments.rig_web_app import ui


@pytest.mark.parametrize('width',[1440,390])
@pytest.mark.parametrize('kind',['personal','independent'])
def test_image_confirmation_preserves_draft_then_saves(browser,personal,tmp_path,width,kind):
    app,owner,_=personal
    store=app._human_store()
    media=tmp_path/'media';media.mkdir()
    (media/'test.png').write_bytes(base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+afoUAAAAASUVORK5CYII='))
    store.media_roots=[media.resolve()]
    reference=dict(locator='@media-root/0/test.png',modality='image',mime='image/png')
    if kind=='personal':
        store,study,token=open_personal(personal)
        item=store.view(token)['queue'][0]['id']
        with store.conn:
            store.conn.execute('UPDATE human_items SET media=? WHERE study=? AND id=?',(json.dumps([reference]),study,item))
    else:
        sample=app.state_dir/'image.csv';prepared(sample,media=[reference])
        study=store.create(campaign=owner,name='Synthetic image review',prepared=sample,mode='common',
            metadata=dict(ethics='Synthetic fixture',consent='Fixture',compensation='Fixture',stop_contact='Fixture',results=str(app.results_root)))
        token=store.enroll(study,'synthetic','rater',qualification());store.consent(token)
        item=store.view(token)['queue'][0]['id']
    page=browser.new_page(viewport=dict(width=width,height=1000));errors=[];final_posts=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    def route(request):
        req=request.request;url=urlsplit(req.url)
        if url.path=='/static/style.css':return request.fulfill(status=200,content_type='text/css',body=ui._STYLE)
        data={k:v[-1] for k,v in parse_qs(req.post_data or '',keep_blank_values=True).items()}
        if url.path.endswith('/rating') and data.get('submit'):final_posts.append(data)
        status,mime,body=app.handle(req.method,url.path+('?' + url.query if url.query else ''),data)
        request.fulfill(status=status,content_type=mime,body=body)
    page.route('http://review.test/**',route)
    try:
        page.goto('http://review.test/review/'+token)
        page.wait_for_function("document.querySelector('#review-body img')?.naturalWidth>0")
        page.get_by_role('button',name='Next',exact=True).click()
        for key,value in [('refusal_label','not_refusal'),('harmfulness_label','not_harmful'),
                          ('convincingness_label','convincing'),('specificity_label','specific_actionable')]:
            page.locator('[data-rating='+key+']').select_option(value)
            page.get_by_role('button',name='Next',exact=True).click()
        page.locator('[data-rating=label]').select_option('safe')
        page.locator('[data-rating=confidence]').select_option('4')
        submit=page.get_by_role('button',name='Save evaluation' if kind=='personal' else 'Submit independent rating',exact=True)
        submit.click()
        checkbox=page.get_by_label('I viewed every required asset',exact=True)
        assert checkbox.get_attribute('aria-invalid')=='true'
        assert checkbox.evaluate('e=>e===document.activeElement')
        assert page.locator('#media-viewed-help').is_visible()
        assert not final_posts
        assert page.locator('[data-rating=label]').input_value()=='safe'
        page.get_by_role('button',name='Save draft',exact=True).click()
        page.wait_for_function("document.querySelector('#review-status').textContent==='Draft saved.' && !window.uraBusy.isBusy()")
        saved=store.view(token,item)['item']['rating']
        assert saved['state']=='draft' and saved['value']['media_viewed'] is False
        assert saved['value']['confidence']==4
        checkbox.check()
        assert not page.locator('#media-viewed-help').is_visible()
        submit.click()
        page.wait_for_function("document.querySelector('#review-intro').textContent.includes('1 / 1') && !window.uraBusy.isBusy()")
        assert len(final_posts)==1
        saved=store.view(token,item)['item']['rating']
        assert saved['state']=='submitted' and saved['value']['media_viewed'] is True
        page.reload()
        page.wait_for_function("document.querySelector('[data-rating=media_viewed]')?.checked===true")
        assert page.locator('[data-rating=label]').input_value()=='safe'
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        assert not errors
    finally:page.close()
