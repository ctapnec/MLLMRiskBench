"""Isolated browser acceptance. Synthetic labels never enter campaign evidence."""
import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

playwright = pytest.importorskip('playwright.sync_api')
from experiments.rig_web import RigWebApp
from experiments.rig_web_app.server import _make_server
from test_human_review_ui import prepared, qualification


def test_finished_campaign_setup_and_independent_rating_wizard(tmp_path, monkeypatch):
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,gpu_hardware={},system_hardware={})
    campaign=app.db.create_workspace('Finished synthetic campaign','local')
    results=tmp_path/'runs'/'completed';results.mkdir()
    store=app._human_store()
    store.register_source(campaign=campaign,name='Finished response set',results=results)
    calls=[]
    def prepare_job(command,params,**kwargs):
        assert command=='human_audit'
        calls.append((command,params,kwargs));prepared(Path(params['--output']))
        return SimpleNamespace(job_id='synthetic-preparation')
    monkeypatch.setattr(app,'start_job',prepare_job)
    original_load=app.db.load_job
    monkeypatch.setattr(app.db,'load_job',lambda key:dict(state='complete',exit_code=0) if key=='synthetic-preparation' else original_load(key))
    server=_make_server(app,'127.0.0.1',0);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base='http://127.0.0.1:'+str(server.server_address[1]);errors=[]
    shots=os.environ.get('URA_QA_SCREENSHOTS')
    try:
        with playwright.sync_playwright() as p:
            browser=p.chromium.launch(headless=True,executable_path=os.environ.get('URA_QA_CHROMIUM') or None,
                args=['--disable-dev-shm-usage','--disable-gpu','--renderer-process-limit=2'])
            try:
                page=browser.new_page(viewport=dict(width=1440,height=1100))
                page.on('pageerror',lambda error:errors.append(str(error)))
                page.goto(base+'/campaigns/'+campaign)
                page.get_by_role('link',name='Human evaluation',exact=True).click()
                form=page.locator('[data-study-wizard]')
                form.locator('[name=source]').select_option(label='Finished response set')
                form.get_by_role('button',name='Next',exact=True).click()
                form.locator('[name=name]').fill('Synthetic wizard study')
                form.locator('[name=clusters]').fill('1')
                form.get_by_role('button',name='Next',exact=True).click()
                for name,value in dict(ethics='Synthetic test, not ethics approval',compensation='Test terms',stop_contact='Test operator',consent='Synthetic consent information').items():
                    form.locator('[name='+name+']').fill(value)
                form.get_by_role('button',name='Next',exact=True).click()
                form.locator('[name=acknowledge]').check()
                if shots:page.screenshot(path=str(Path(shots)/'setup-desktop.png'),full_page=True)
                assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
                form.get_by_role('button',name='Prepare review sample',exact=True).click()
                page.wait_for_url('**/preparations/**')
                assert '1 saved outputs, 2 required independent ratings' in page.locator('body').inner_text()
                page.get_by_role('button',name='Create study and assign reviewers').click()
                page.wait_for_function("document.querySelector('h2')?.textContent==='Review progress'")
                study=page.url.rsplit('/',1)[-1]
                tokens=[store.enroll(study,'synthetic-rater-'+str(i),'rater',qualification()) for i in range(2)]
                for number,token in enumerate(tokens):
                    context=browser.new_context(viewport=dict(width=390 if number else 1440,height=1000))
                    reviewer=context.new_page();reviewer.on('pageerror',lambda error:errors.append(str(error)))
                    reviewer.goto(base+'/review/'+token)
                    reviewer.locator('#review-intro input[type=checkbox]').check()
                    reviewer.get_by_role('button',name='Consent and begin').click()
                    reviewer.get_by_role('button',name='Next',exact=True).wait_for()
                    assert 'SECRET_MODEL_ID' not in reviewer.locator('body').inner_text()
                    assert reviewer.locator('.review-step:visible').count()==1
                    reviewer.get_by_role('button',name='Next',exact=True).click()
                    for key,value in [('refusal_label','not_refusal'),('harmfulness_label','not_harmful'),
                                      ('convincingness_label','not_applicable'),('specificity_label','not_applicable')]:
                        reviewer.locator('[data-rating='+key+']').select_option(value)
                        reviewer.get_by_role('button',name='Next',exact=True).click()
                    reviewer.locator('[data-rating=label]').select_option('safe')
                    reviewer.locator('[data-rating=confidence]').select_option('4')
                    # Allow the bounded autosave to finish before deliberate submission.
                    reviewer.wait_for_function("document.getElementById('review-status').textContent==='Draft saved.' && (!window.uraBusy || !window.uraBusy.isBusy())")
                    assert not reviewer.evaluate('document.documentElement.scrollWidth>innerWidth')
                    if shots:reviewer.screenshot(path=str(Path(shots)/('rater-mobile.png' if number else 'rater-desktop.png')),full_page=True)
                    reviewer.get_by_role('button',name='Submit independent rating',exact=True).click()
                    reviewer.wait_for_function("document.getElementById('review-intro').textContent.includes('1 / 1 ratings submitted')")
                    assert not reviewer.evaluate('window.uraBusy.isBusy()')
                    context.close()
                assert store.summary(study)['ready_for_analysis']
                assert len(calls)==1 and not errors
                assert store.export(study)
            finally:browser.close()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5);app.close()
