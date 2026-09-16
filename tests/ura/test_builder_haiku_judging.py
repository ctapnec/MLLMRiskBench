"""Normal Build owns paired judging selection, funding and continuation."""
import json
from pathlib import Path
import re

import pytest

from experiments.rig_web import Job
from experiments.rig_web_app import builder_haiku_judging as subject, ui
from test_builder_native_judging import native, complete_preparation  # noqa: F401
from test_builder_collection import study  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401

JUDGE='anthropic:claude-haiku-4-5-20251001'


@pytest.fixture
def haiku(native,monkeypatch):  # noqa: F811
    app,_,calls,receipt=native
    params=complete_preparation(native)
    entry=app.db.load_job(params['retained_native_judging_job'])
    path=Path(subject.argument(json.loads(entry['argv']),'--out'))/'result.json'
    prepared=json.loads(path.read_text())
    prepared['programs']=receipt['programs']
    for unit in prepared['units']:
        unit['runner_argv']=['--source-conformance',str(path.parent/'source.json'),'--source-conformance-sha256','c'*64]
    path.write_text(json.dumps(prepared))
    matching=app.db.create_workspace('Original local outputs','local')
    params.update(retained_source_campaign=matching,retained_haiku_model=JUDGE)
    for field,command,argv in [
        ('retained_sources_job','retained_local_sources',['--out',str(path.parent/'local.json')]),
        ('retained_budget_job','hosted_campaign_budget',['--out',str(path.parent/'forecast.json'),
            '--pricing-config',str(path.parent/'pricing.json'),'--pricing-config-sha256','d'*64,
            '--pricing-as-of','2026-09-12'])]:
        job=Job(job_id=field,command=command,argv=['python','-m','experiments.'+command,*argv],
            directory=path.parent/field,restored_state='complete',restored_exit=0)
        app.db.upsert_job(job,state='complete',exit_code=0)
        app.db.attach_workspace_member(params['campaign_id'],'job',job.job_id,'preparation')
        params[field]=job.job_id
    monkeypatch.setattr(subject,'_choices',lambda _: [JUDGE])
    monkeypatch.setattr(app,'_selected_api_config_snapshot',lambda _:
        ({'routes':[{'model':JUDGE}]},'','',{JUDGE:{'max_tokens':4096,'temperature':0}}))
    # Selection content validation is covered by the planner's own tests and
    # the real-source browser check. These tests exercise ownership and launch.
    monkeypatch.setattr(subject,'validate_pair_plan',lambda value:value)
    return app,params,calls,receipt


def completed(haiku):
    app,params,_,_=haiku
    job=subject.prepare_haiku_judging(app,params)
    argv=json.loads(app.db.load_job(job.job_id)['argv'])
    path=Path(subject.argument(argv,'--out'))
    path.write_text(json.dumps(dict(pairs=[{}],selected=[dict(cohort='local',exact_model='local:model'),
        dict(cohort='hosted',exact_model='hosted:model')],judge_condition=dict(model=JUDGE,max_cost_microusd=7000000))))
    path.with_suffix('.shared-requests.json').write_text('{}')
    app.db._conn.execute("UPDATE jobs SET state='complete',exit_code=0 WHERE job_id=?",(job.job_id,))
    app.db._conn.commit()
    return dict(params,retained_haiku_job=job.job_id)


def review(app,params):
    status,_,body=app.handle('POST','/build/review-haiku-judging',params)
    assert status==200,body.decode()
    return body,re.search("name='launch_ticket' value='([^']+)'",body.decode())[1]


def test_preparation_reuses_saved_sources_and_budget_without_paid_calls(haiku):
    app,params,calls,receipt=haiku
    before=len(calls)
    status,location,body=app.handle('POST','/build/prepare-haiku-judging',dict(params,api='unrelated:target'))
    assert status==303,body.decode()
    command,values,kw=calls[-1]
    assert command=='retained_response_judge_pair'
    assert values['--shared-budget-root']==str(Path(receipt['budget']['path']).parent)
    assert values['--shared-budget-sha256']==receipt['budget']['sha256']
    assert values['--program']==receipt['programs'][0]['path']
    assert values['--program#1']==receipt['programs'][1]['path']
    assert json.loads(Path(values['--api-config']).read_text())[JUDGE]['max_tokens']==512
    assert kw['campaign_id']==params['campaign_id'] and '--ack-paid-execution' not in values
    assert subject.prepare_haiku_judging(app,params).job_id==location.rsplit('/',1)[-1]
    assert len(calls)==before+1


def test_review_and_execution_keep_shared_money_and_both_output_owners(haiku):
    app,_,calls,_=haiku
    params=completed(haiku)
    body,token=review(app,params)
    assert b'2 distinct saved answers' in body and b'not an additional allocation' in body
    assert b'not sent as image pixels' in body and b'no automatic retries' in body
    job=subject.judge_retained_haiku(app,dict(launch_ticket=token))
    command,values,kw=calls[-1]
    assert command=='retained_response_judge_pair_execute'
    assert values['--shared-budget-root'] and len(values['--shared-requests-sha256'])==64
    assert values['--matching-workspace-id']==params['retained_source_campaign']
    assert kw['campaign_id']==params['campaign_id']
    assert values['--retain-invalid-verdicts']=='on'
    assert app.db.workspace_for_job(job.job_id)==params['campaign_id']


def test_two_tabs_cannot_launch_the_same_paid_selection(haiku):
    app,_,calls,_=haiku
    params=completed(haiku)
    _,a=review(app,params)
    _,b=review(app,params)
    before=len(calls)
    subject.judge_retained_haiku(app,dict(launch_ticket=a))
    with pytest.raises(ValueError,match='already used'):
        subject.judge_retained_haiku(app,dict(launch_ticket=a))
    with pytest.raises(ValueError,match='newer launch'):
        subject.judge_retained_haiku(app,dict(launch_ticket=b))
    _,c=review(app,params)
    with pytest.raises(ValueError,match='already active'):
        subject.judge_retained_haiku(app,dict(launch_ticket=c))
    assert len(calls)==before+1


def test_continuation_preserves_saved_execution_and_prevents_reselection(haiku):
    app,_,calls,_=haiku
    params=completed(haiku)
    _,token=review(app,params)
    first=subject.judge_retained_haiku(app,dict(launch_ticket=token))
    previous=dict(calls[-1][1])
    app.db._conn.execute("UPDATE jobs SET state='failed',exit_code=1 WHERE job_id=?",(first.job_id,))
    app.db._conn.commit()
    _,token=review(app,params)
    subject.judge_retained_haiku(app,dict(launch_ticket=token))
    assert calls[-1][1]==previous
    with pytest.raises(ValueError,match='Resume the saved judging selection'):
        subject.prepare_haiku_judging(app,dict(params,retained_haiku_limit='101'))


@pytest.mark.parametrize('change',[{'retained_haiku_cost':'NaN'},{'retained_haiku_cost':'-1'},
    {'retained_haiku_cost':'0.0000001'},{'retained_haiku_limit':'1.5'},
    {'retained_haiku_model':'other:judge'},{'retained_native_judging_job':'unknown'}])
def test_invalid_options_do_not_start_jobs(haiku,change):
    app,params,calls,_=haiku
    before=len(calls)
    with pytest.raises(ValueError):
        subject.prepare_haiku_judging(app,dict(params,**change))
    assert len(calls)==before


def test_other_campaign_cannot_use_the_saved_selection(haiku):
    app,_,calls,_=haiku
    params=completed(haiku)
    other=app.db.create_workspace('Unrelated API campaign','api')
    before=len(calls)
    with pytest.raises(ValueError):
        subject.haiku_judging_review(app,dict(params,campaign_id=other))
    assert len(calls)==before


def test_haiku_panel_and_review_are_usable_at_mobile_width(browser,haiku):  # noqa: F811
    app,_,_,_=haiku
    params=completed(haiku)
    panel=subject.haiku_judging_panel(app,params)
    assert "formaction='/build/prepare-operation/paired-haiku'" in panel
    assert "formaction='/build/prepare-operation/haiku-judging'" in panel
    assert "formaction='/build/review-haiku-judging'" in panel
    body,_=review(app,params)
    page=browser.new_page(viewport={'width':390,'height':844})
    try:
        page.set_content(body.decode().replace("<link rel='stylesheet' href='/static/style.css'>",'<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('heading',name='Review Haiku judging').is_visible()
        assert page.get_by_role('button',name='Start or resume Haiku judging').is_visible()
        assert page.locator('table tr').count()==3
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    finally:
        page.close()


def test_haiku_controls_have_separate_rows_and_responsive_spacing(browser,haiku):  # noqa: F811
    app,params,_,_=haiku
    content=ui._page('Haiku controls',"<form id='builder'></form>"+subject.haiku_judging_panel(app,params)).decode()
    content=content.replace("<link rel='stylesheet' href='/static/style.css'>",'<style>'+ui._STYLE+'</style>')
    page=browser.new_page(viewport={'width':1440,'height':900})
    try:
        page.set_content(content)
        fields=page.locator('#retained-judging-coverage .campaign-field')
        a,b=fields.nth(0).bounding_box(),fields.nth(1).bounding_box()
        assert abs(a['y']-b['y'])<1 and b['x']>=a['x']+a['width']+15
        page.set_viewport_size({'width':390,'height':844})
        for index in range(1,3):
            previous,current=fields.nth(index-1).bounding_box(),fields.nth(index).bounding_box()
            assert current['y']>=previous['y']+previous['height']+15
        last=fields.nth(2).bounding_box()
        button=page.get_by_role('button',name='Review all-output Haiku judging').bounding_box()
        assert button['y']>=last['y']+last['height']+15
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    finally:
        page.close()
