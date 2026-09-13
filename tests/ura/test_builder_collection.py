import json
import re
from urllib.parse import parse_qs

import pytest

from experiments.rig_web import Job, RigWebApp
from experiments.rig_web_app import builder_collection as subject, ui
from experiments.rig_web_app.catalog import build_argv
from test_rig_web_busy_browser import browser  # noqa: F401


@pytest.fixture
def study(tmp_path, monkeypatch):
    app = RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,
        gpu_hardware={},system_hardware={})
    owner = app.db.create_workspace('Saved matched collection','api')
    monkeypatch.setattr(subject.subprocess,'check_output',lambda *a,**kw:'a'*40+'\n')
    folder = tmp_path/'prepared'
    folder.mkdir()
    descriptors = []
    for index,target in enumerate(('example:model-a','second:model-b')):
        path = folder/f'model-{index}.json'
        path.write_text(json.dumps(dict(target=target,max_output_tokens=4096,requests={'same-input':{'bound_microusd':24000}})))
        descriptors.append(dict(path=str(path),sha256=str(index)*64,selected_target_calls=1))
    receipt = dict(status='prepared_no_generation_calls',programs=descriptors,
        budget=dict(path=str(folder/'budget'/'plan.json'),sha256='b'*64))
    (folder/'receipt.json').write_text(json.dumps(receipt))
    preparation = Job(job_id='prepared-job',command='hosted_campaign_prepare',
        argv=['python','-m','experiments.hosted_campaign_prepare','--out-root',str(folder)],
        directory=tmp_path/'preparation-job',restored_state='complete',restored_exit=0)
    app.db.upsert_job(preparation,state='complete',exit_code=0)
    app.db.attach_workspace_member(owner,'job',preparation.job_id,'preparation')
    calls=[]
    def launch(command,values,**kw):
        job = Job(job_id=f'collection-{len(calls)}',command=command,argv=build_argv(command,values),
            directory=tmp_path/f'job-{len(calls)}',restored_state='running')
        calls.append((command,dict(values),kw))
        app.db.upsert_job(job,state='running',exit_code=None)
        app.db.attach_workspace_member(kw['campaign_id'],'job',job.job_id,'collection')
        # A started collector writes this before runtime preparation or calls.
        if command == 'hosted_campaign_execute':
            control = __import__('pathlib').Path(values['--out'])
            control.mkdir(parents=True)
            (control/'selection.json').write_text('{}')
        return job
    monkeypatch.setattr(app,'start_job',launch)
    params=dict(work_kind='campaign',campaign_id=owner,retained_programs_job=preparation.job_id)
    try:
        yield app,params,calls,receipt
    finally:
        app.close()


def review(app, params):
    status,_,body = app.handle('POST','/build/review-collection',params)
    assert status == 200,body.decode()
    token = re.search("name='launch_ticket' value='([^']+)'",body.decode())
    assert token,body.decode()
    return body,token[1]


def test_review_uses_saved_programs_without_calls_or_draft_recomposition(study):
    app,params,calls,receipt = study
    body,ticket = review(app,dict(params,api='unrelated:changed-draft',retained_collection_workers='3'))
    assert not calls
    assert b'example:model-a' in body and b'second:model-b' in body and b'$0.024000' in body
    assert b'unrelated:changed-draft' not in body
    assert b'local and Haiku judging are separate stages' in body
    status,location,_ = app.handle('POST','/build/collect-prepared',dict(launch_ticket=ticket))
    assert status == 303 and location == '/jobs/collection-0'
    command,values,kw = calls[0]
    assert command == 'hosted_campaign_execute' and kw == {'campaign_id':params['campaign_id']}
    assert subject._program_paths(build_argv(command,values)) == [row['path'] for row in receipt['programs']]
    assert values['--workers-per-provider'] == '3' and '--resume-from' not in values
    assert '--verify-artifact-sha256' not in values
    assert len(calls) == 1
    assert app.db.workspace_for_job('collection-0') == params['campaign_id']


def test_two_open_reviews_cannot_launch_same_collection_twice(study):
    app,params,calls,_ = study
    _,first = review(app,params)
    _,second = review(app,params)
    subject.collect_prepared(app,{'launch_ticket':first})
    with pytest.raises(ValueError,match='already used'):
        subject.collect_prepared(app,{'launch_ticket':first})
    with pytest.raises(ValueError,match='newer launch'):
        subject.collect_prepared(app,{'launch_ticket':second})
    _,third = review(app,params)
    with pytest.raises(ValueError,match='already active'):
        subject.collect_prepared(app,{'launch_ticket':third})
    assert len(calls) == 1


def test_continuation_uses_same_program_budget_and_previous_control(study):
    app,params,calls,_ = study
    _,ticket = review(app,params)
    subject.collect_prepared(app,{'launch_ticket':ticket})
    previous = calls[0][1]
    app.db._conn.execute("UPDATE jobs SET state='failed',exit_code=1 WHERE job_id='collection-0'")
    app.db._conn.commit()
    body,ticket = review(app,params)
    assert b'Continue saved collection' in body
    subject.collect_prepared(app,{'launch_ticket':ticket})
    current = calls[1][1]
    assert current['--resume-from'] == previous['--out']
    assert current['--out'] != previous['--out']
    for flag in ('--program','--program#1','--budget-root','--budget-plan-sha256','--expected-commit'):
        assert current[flag] == previous[flag]


def test_failed_before_collection_initialization_can_retry_without_a_phantom_resume(study, monkeypatch):
    from pathlib import Path
    app,params,calls,_ = study
    _,ticket = review(app,params)
    subject.collect_prepared(app,{'launch_ticket':ticket})
    prior = Path(calls[0][1]['--out'])
    (prior/'selection.json').unlink()
    prior.rmdir()
    app.db._conn.execute("UPDATE jobs SET state='failed',exit_code=1 WHERE job_id='collection-0'")
    app.db._conn.commit()
    monkeypatch.setattr(subject.subprocess,'check_output',lambda *a,**kw:'c'*40+'\n')
    _,ticket = review(app,params)
    subject.collect_prepared(app,{'launch_ticket':ticket})
    assert '--resume-from' not in calls[1][1]
    assert calls[1][1]['--expected-commit'] == 'c'*40
    assert calls[1][1]['--program'] == calls[0][1]['--program']
    assert calls[1][1]['--budget-plan-sha256'] == calls[0][1]['--budget-plan-sha256']


@pytest.mark.parametrize('change',[{'retained_collection_workers':'0'}, {'retained_collection_workers':'9'},
    {'retained_collection_workers':'1.5'}, {'retained_programs_job':'unknown'}])
def test_invalid_collection_options_do_not_launch(study,change):
    app,params,calls,_ = study
    with pytest.raises(ValueError):
        subject.collection_review(app,dict(params,**change))
    assert not calls


def test_other_campaign_cannot_launch_prepared_work(study):
    app,params,calls,_ = study
    other=app.db.create_workspace('Other','api')
    with pytest.raises(ValueError):
        subject.collection_review(app,dict(params,campaign_id=other))
    assert not calls


def test_confirm_cannot_replace_reviewed_values(study):
    app,params,calls,_ = study
    _,ticket=review(app,params)
    with pytest.raises(ValueError):
        subject.collect_prepared(app,{'launch_ticket':ticket,'campaign_id':'other'})
    assert not calls


def test_real_review_form_busy_guard_submits_one_exact_launch(browser,study):  # noqa: F811
    app,params,calls,_ = study
    body,_=review(app,params)
    content=body.decode().replace("<link rel='stylesheet' href='/static/style.css'>",'<style>'+ui._STYLE+'</style>')
    page=browser.new_page()
    posts=[]
    def route(request):
        if request.request.method == 'POST':
            posts.append(request)
        else:
            request.fulfill(status=200,content_type='text/html',body=content)
    page.route('http://ui.test/**',route)
    try:
        page.goto('http://ui.test/')
        assert page.locator('form').count()==1
        busy = page.evaluate("() => {for(let i=0;i<1000;i++) document.querySelector('form button').click(); "
            "return window.uraBusy.isBusy();}")
        page.wait_for_timeout(80)
        assert len(posts)==1
        # Do not evaluate in the next document while its POST is deliberately held.
        assert busy
        form={key:values[0] for key,values in parse_qs(posts[0].request.post_data).items()}
        status,location,_=app.handle('POST','/build/collect-prepared',form)
        assert status==303 and location=='/jobs/collection-0' and len(calls)==1
        posts[0].fulfill(status=200,content_type='text/html',body=ui._page('Job','<h1>Collection job</h1>').decode())
        page.wait_for_function('!window.uraBusy.isBusy()')
    finally:
        page.close()


def test_collection_panel_uses_normal_build_form():
    assert subject.collection_panel({}) == ''
    page=subject.collection_panel({'retained_programs_job':'prepared'})
    assert "form='builder' name='retained_collection_workers'" in page
    assert "formaction='/build/review-collection'" in page
    assert "value='2'" in page


def test_build_includes_runtime_and_both_judging_stages_use_actual_outputs(study, monkeypatch, tmp_path):
    from pathlib import Path
    from experiments.hosted_retained_inputs import _descriptor
    app,params,calls,receipt = study
    store = tmp_path/'installed-models'
    store.mkdir()
    monkeypatch.setenv('URA_MODEL_STORE', str(store))
    for descriptor in receipt['programs']:
        path = Path(descriptor['path'])
        program = json.loads(path.read_text())
        program['jobs'] = [dict(name='run',purpose='measured_run',argv=['--out','/old'])]
        path.write_text(json.dumps(program))
    body,ticket = review(app,params)
    assert b'Installed runtime binding and transport checks are included' in body
    subject.collect_prepared(app,{'launch_ticket':ticket})
    assert calls[0][1]['--prepare-runtime'] == 'on'
    assert calls[0][1]['--model-store'] == str(store.resolve())
    control = Path(calls[0][1]['--out'])
    root = control/'runtime'
    root.mkdir(parents=True)
    (control/'selection.json').write_text(json.dumps({'runtime_root':str(root)}))
    descriptors = []
    for number,descriptor in enumerate(receipt['programs']):
        folder = root/str(number)
        folder.mkdir()
        path = folder/'runtime-program.json'
        path.write_text(Path(descriptor['path']).read_text())
        descriptors.append(_descriptor(path))
        observed = json.loads(path.read_text())
        observed['jobs'][0]['argv'] = ['--out','/actual-collected-output']
        (folder/'attested-program.json').write_text(json.dumps(observed))
    (root/'programs.json').write_text(json.dumps(dict(original_programs=receipt['programs'],programs=descriptors)))
    effective = subject.prepared_collection(app,params)
    assert all(Path(row['path']).name == 'attested-program.json' for row in effective['programs'])
    assert all(json.loads(Path(row['path']).read_text())['jobs'][0]['argv'][1] == '/actual-collected-output'
        for row in effective['programs'])
    assert subject.prepared_collection(app,params,for_execution=True) == receipt
    app.db._conn.execute("UPDATE jobs SET state='failed',exit_code=1 WHERE job_id='collection-0'")
    app.db._conn.commit()
    _,ticket = review(app,params)
    subject.collect_prepared(app,{'launch_ticket':ticket})
    assert calls[1][1]['--prepare-runtime'] == 'on'
    assert calls[1][1]['--program'] == receipt['programs'][0]['path']


def test_collection_environment_keeps_installed_store_locator(study, monkeypatch):
    app,_,_,_ = study
    monkeypatch.setenv('URA_MODEL_STORE','/existing/models')
    monkeypatch.setattr(app,'_strict_config_document',lambda *a: {'jobs':[{'argv':[]}]})
    monkeypatch.setattr(app,'_selected_matrix_environment_names',lambda *a: set())
    env = app._generic_child_environment('hosted_campaign_execute',
        {'--program':'/prepared/model.json','--program-sha256':'a'*64})
    assert env['URA_MODEL_STORE'] == '/existing/models'


def test_generic_child_imports_the_console_selected_checkout(study, tmp_path):
    import subprocess
    import sys
    app,_,_,_ = study
    package = tmp_path/'src'/'ura'
    package.mkdir(parents=True)
    (package/'__init__.py').write_text("checkout_marker = 'selected-code'\n")
    env = app._generic_child_environment('response_svm', {})
    result = subprocess.run([sys.executable, '-c', 'import ura; print(ura.checkout_marker)'],
        env=env, cwd=tmp_path, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'selected-code'
