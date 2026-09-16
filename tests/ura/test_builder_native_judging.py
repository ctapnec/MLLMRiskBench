import json
import re
from pathlib import Path

import pytest

from experiments.rig_web_app import builder_native_judging as subject, ui
from experiments.rig_web_app.catalog import build_argv
from test_builder_collection import study  # noqa: F401
from test_rig_web_busy_browser import browser  # noqa: F401
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.runner import _component_config


@pytest.fixture
def native(study):  # noqa: F811
    app,params,calls,receipt=study
    for index,descriptor in enumerate(receipt['programs']):
        path=Path(descriptor['path'])
        program=json.loads(path.read_text())
        program['jobs']=[dict(name=f'source-{index}',input_ids=['same-input'])]
        path.write_text(json.dumps(program))
    return app,params,calls,receipt


def complete_preparation(native, selected=None, failed=False):
    app,params,calls,receipt=native
    job=subject.prepare_native_judging(app,params)
    entry=app.db.load_job(job.job_id)
    path=Path(subject.argument(json.loads(entry['argv']),'--out'))
    path.mkdir()
    cascade=_component_config(JudgeCascade([RuleJudge(),GuardrailJudge(
        model='meta-llama/Llama-Guard-3-8B',revision='b'*40,device='cuda:0',max_new_tokens=20)]))
    selected=range(2) if selected is None else selected
    units=[dict(program=receipt['programs'][index]['path'],job=f'source-{index}',
        target=f'example:model-{index}',assigned=1,judge_cascade=cascade) for index in selected]
    result=dict(status='preparation_incomplete' if failed else 'prepared',units=units,
        outputs=len(units),failed=[dict(assigned=1)] if failed else [])
    (path/'result.json').write_text(json.dumps(result))
    app.db._conn.execute('UPDATE jobs SET state=?,exit_code=? WHERE job_id=?',
        ('failed' if failed else 'complete',1 if failed else 0,job.job_id))
    app.db._conn.commit()
    return dict(params,retained_native_judging_job=job.job_id)


def review(app,params):
    status,_,body=app.handle('POST','/build/review-native-judging',params)
    assert status==200,body.decode()
    token=re.search("name='launch_ticket' value='([^']+)'",body.decode())
    assert token
    return body,token[1]


def test_preparation_reuses_active_and_completed_work(native):
    app,params,calls,_=native
    first=subject.prepare_native_judging(app,params)
    assert subject.prepare_native_judging(app,params).job_id==first.job_id
    assert len(calls)==1
    selected=complete_preparation(native)
    assert subject.prepare_native_judging(app,params).job_id==selected['retained_native_judging_job']
    assert len(calls)==1
    assert calls[0][0]=='retained_native_judge_prepare'
    assert calls[0][2]['campaign_id']==params['campaign_id']


def test_partial_preparation_adds_only_previously_unprepared_sources(native):
    app,params,calls,_=native
    first=complete_preparation(native,selected=[0],failed=True)
    second=subject.prepare_native_judging(app,params)
    assert second.job_id!=first['retained_native_judging_job']
    argv=build_argv(calls[-1][0],calls[-1][1])
    assert subject._program_paths(argv,'--job')==['source-1']
    # A stale Build form must still see the active preparation through SQLite.
    assert subject.prepare_native_judging(app,params).job_id==second.job_id
    assert len(calls)==2


def test_review_uses_saved_scoring_condition_and_optional_checks(native):
    app,_,calls,_=native
    params=complete_preparation(native)
    body,token=review(app,dict(params,guardrail_model='unrelated-draft-model'))
    assert len(calls)==1
    assert b'Rules, then meta-llama/Llama-Guard-3-8B on cuda:0' in body
    assert b'20 tokens' in body and b'unrelated-draft-model' not in body
    assert b'&quot;stages&quot;' not in body
    subject.judge_retained_local(app,dict(launch_ticket=token))
    command,values,kw=calls[-1]
    assert command=='retained_native_judge_execute' and kw['campaign_id']==params['campaign_id']
    assert '--verify-model-sha256' not in values and '--verify-artifact-sha256' not in values
    assert '--program' not in values


def test_two_reviews_and_reused_ticket_cannot_repeat_judging(native):
    app,_,calls,_=native
    params=complete_preparation(native)
    _,first=review(app,params)
    _,second=review(app,params)
    subject.judge_retained_local(app,dict(launch_ticket=first))
    with pytest.raises(ValueError,match='already used'):
        subject.judge_retained_local(app,dict(launch_ticket=first))
    with pytest.raises(ValueError,match='newer launch'):
        subject.judge_retained_local(app,dict(launch_ticket=second))
    _,third=review(app,params)
    with pytest.raises(ValueError,match='already active'):
        subject.judge_retained_local(app,dict(launch_ticket=third))
    assert len(calls)==2


def test_judging_continuation_uses_same_checkpoints(native):
    app,_,calls,_=native
    params=complete_preparation(native)
    _,first=review(app,params)
    job=subject.judge_retained_local(app,dict(launch_ticket=first))
    previous=dict(calls[-1][1],**{'--out':str(app.results_root/'retained-checkpoints')})
    app.db._conn.execute("UPDATE jobs SET state='failed',exit_code=1,argv=? WHERE job_id=?",
        (json.dumps(build_argv('retained_native_judge_execute',previous)),job.job_id))
    app.db._conn.commit()
    _,second=review(app,params)
    subject.judge_retained_local(app,dict(launch_ticket=second))
    assert calls[-1][1]==previous
    with pytest.raises(ValueError,match='original model-verification'):
        subject.native_judging_review(app,dict(params,retained_native_verify_model='on'))


def test_partial_subset_keeps_unprepared_population_visible(native):
    app,_,_,_=native
    params=complete_preparation(native,selected=[0],failed=True)
    body,_=review(app,params)
    assert b'1 assigned outputs are not prepared' in body
    assert b'cannot complete the whole campaign' in body


def test_other_campaign_cannot_review_preparation(native):
    app,_,calls,_=native
    params=complete_preparation(native)
    other=app.db.create_workspace('Unrelated campaign','api')
    with pytest.raises(ValueError):
        subject.native_judging_review(app,dict(params,campaign_id=other))
    assert len(calls)==1


def test_panel_retains_preparation_history_and_normal_build_controls(native):
    app,_,_,_=native
    assert subject.native_judging_panel(app,{})==''
    params=complete_preparation(native,selected=[0],failed=True)
    second=subject.prepare_native_judging(app,params)
    body=subject.native_judging_panel(app,params)
    assert params['retained_native_judging_job'] in body and second.job_id in body
    assert "select form='builder' name='retained_native_judging_job'" in body
    assert "formaction='/build/prepare-operation/local-judging'" in body
    assert "formaction='/build/review-native-judging'" in body
    assert ' checked' not in body


def test_native_review_browser_renders_scoring_without_raw_configuration(browser,native):  # noqa: F811
    app,_,_,_=native
    params=complete_preparation(native)
    body,_=review(app,params)
    page=browser.new_page(viewport={'width':1440,'height':900})
    try:
        page.set_content(body.decode().replace("<link rel='stylesheet' href='/static/style.css'>",'<style>'+ui._STYLE+'</style>'))
        assert page.get_by_role('heading',name='Review local judging').is_visible()
        assert page.locator('table tr').count()==3
        assert 'cuda:0' in page.locator('table').inner_text()
        assert page.get_by_role('button',name='Start or resume local judging').is_visible()
        page.set_viewport_size({'width':390,'height':844})
        assert page.locator('table').bounding_box()['width']>=864
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
    finally:
        page.close()
