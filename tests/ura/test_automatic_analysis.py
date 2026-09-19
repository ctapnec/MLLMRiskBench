"""Operator selections replace SVM path and job handoffs."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import response_svm
from experiments.rig_web_app import response_analysis, prepared_inputs
from test_response_svm import dataset_fixture
from test_response_svm_models import fitted_study  # noqa: F401
from test_operator_operations import app, child  # noqa: F401
from test_rig_web_busy_browser import browser, _burst  # noqa: F401


def test_study_retains_real_small_cohort_limitations_and_reuses_completed_work(tmp_path, monkeypatch):
    pytest.importorskip('sklearn')
    args=dataset_fixture(tmp_path)
    out=tmp_path/'study'
    argv=['--study','--database',str(args['database']),'--candidates',str(args['candidates']),
          '--campaign','campaign','--matched-campaign','campaign','--judge-condition','haiku',
          '--bootstrap','100','--out',str(out)]
    before=args['database'].read_bytes()
    assert response_svm.main(argv)==0
    result=json.loads((out/'result.json').read_text())
    assert result['status']=='study_complete'
    assert result['models'] is None and result['packaging_status']=='not_applicable'
    assert result['target_calls']==result['judge_calls']==0
    assert not result['human_validated'] and not result['campaign_judgments_modified']
    # Simulate interruption between a successful stage and controller publication.
    (out/'result.json').unlink();(out/'dataset-complete.json').unlink()
    from ura import response_svm as engine
    monkeypatch.setattr(engine,'evaluate_study',lambda *a,**kw:pytest.fail('Completed evaluation was repeated'))
    assert response_svm.main(argv)==0
    assert not (out/'dataset-2').exists()
    assert args['database'].read_bytes()==before
    with pytest.raises(ValueError,match='original scientific selection'):
        response_svm.main([*argv,'--seed','3'])


def test_failed_study_resumes_only_unfinished_stages(tmp_path, monkeypatch,fitted_study):
    pytest.importorskip('sklearn')
    args=dataset_fixture(tmp_path);out=tmp_path/'study'
    argv=['--study','--database',str(args['database']),'--candidates',str(args['candidates']),
          '--campaign','campaign','--matched-campaign','campaign','--judge-condition','haiku',
          '--bootstrap','100','--out',str(out)]
    from ura import response_svm as engine
    from experiments import response_svm_dataset
    monkeypatch.setattr(response_svm_dataset,'export_dataset',lambda **kw:(fitted_study[0],dict(status='exported')))
    original=engine.evaluate_study
    monkeypatch.setattr(engine,'evaluate_study',lambda *a,**kw:(_ for _ in ()).throw(RuntimeError('interrupted')))
    with pytest.raises(RuntimeError,match='interrupted'):response_svm.main(argv)
    monkeypatch.setattr(engine,'evaluate_study',original)
    monkeypatch.setattr(response_svm_dataset,'export_dataset',lambda **kw:pytest.fail('Completed export repeated'))
    assert response_svm.main(argv)==0
    assert (out/'evaluation-1/error.json').exists()
    assert (out/'evaluation-2/result.json').exists()
    assert not (out/'dataset-2').exists()


def test_supported_study_packages_without_operator_handoff(tmp_path,monkeypatch,fitted_study):
    rows,report,predictions,_=fitted_study
    from experiments import response_svm_dataset
    from ura import response_svm as engine
    monkeypatch.setattr(response_svm_dataset,'export_dataset',lambda **kw:(rows,dict(status='exported')))
    monkeypatch.setattr(engine,'evaluate_study',lambda *a,**kw:(report,predictions))
    candidates=tmp_path/'candidates.json';candidates.write_text('[]')
    out=tmp_path/'study'
    args=['--study','--database',str(tmp_path/'db'),'--candidates',str(candidates),'--campaign','campaign',
        '--matched-campaign','campaign','--judge-condition','haiku','--out',str(out)]
    assert response_svm.main(args)==0
    result=json.loads((out/'result.json').read_text())
    assert Path(result['models']).is_file() and result['packaging_status']=='saved'
    (out/'classifiers-complete.json').unlink();(out/'result.json').unlink()
    from ura import response_svm_models
    monkeypatch.setattr(response_svm_models,'package_study',lambda *a,**kw:pytest.fail('Finished package repeated'))
    assert response_svm.main(args)==0 and not (out/'classifiers-2').exists()


def test_resume_uses_original_selection_even_before_controller_file_exists(app,monkeypatch):
    owner=app.db.create_workspace('Resume','api')
    from experiments.rig_web_app.catalog import build_argv
    values={'--study':'on','--database':str(app.db.path),'--campaign':owner,
        '--matched-campaign':owner,'--judge-condition':'haiku-old','--source-root':str(app.results_root),
        '--run-id':'saved-run','--out':str(app.results_root/'unstarted-analysis')}
    row=dict(job_id='old',argv=json.dumps(build_argv('response_svm',values)),state='interrupted')
    monkeypatch.setattr(response_analysis,'history',lambda *a:[row])
    calls=[]
    monkeypatch.setattr(app,'start_job',lambda command,arguments,**kw:calls.append(arguments))
    ticket=app._new_launch_ticket(dict(campaign_id=owner,job='old'),purpose='svm-resume')
    response_analysis.resume(app,dict(launch_ticket=ticket))
    assert calls==[values]


def test_analysis_process_uses_console_tool_and_bounded_threads(app,monkeypatch):
    import inspect
    import ast
    import textwrap
    from experiments.rig_web_app.lifecycle import LifecycleMixin
    # The command remains typed; execution source is recorded separately from Runner.
    source=inspect.getsource(LifecycleMixin.start_job)
    assert 'analysis_code_repository' in source
    tree = ast.parse(textwrap.dedent(source))
    assert any(isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add)
               and isinstance(node.left, ast.Name) and node.left.id == 'command'
               and isinstance(node.right, ast.Constant) and node.right.value == '.py'
               for node in ast.walk(tree))
    monkeypatch.setenv('OPENBLAS_NUM_THREADS','24')
    env=app._generic_child_environment('response_svm',{})
    assert env['OPENBLAS_NUM_THREADS']==env['OMP_NUM_THREADS']==env['MKL_NUM_THREADS']=='2'


def setup_choices(app, monkeypatch):
    owner=app.db.create_workspace('Hosted study','api')
    source=app.db.create_workspace('Local source','local')
    directory=app.results_root/'original';directory.mkdir()
    rows=[dict(run_id='real-run',source_ref=str(directory/'responses.jsonl')+':1')]*2
    monkeypatch.setattr(response_analysis,'source_runs',lambda db,key:rows if key==source else [])
    monkeypatch.setattr(response_analysis,'teachers',lambda app,key:[dict(judge_id='haiku-selected',n=5)])
    return owner,source


def test_ambiguous_scientific_choice_is_not_silently_set_to_first_campaign():
    options=[('demo','Small demonstration'),('thesis','Full retained local campaign')]
    rendered=response_analysis.select('source','Source campaign',options,'unknown')
    assert '<option value="" selected>' in rendered and 'required' in rendered
    chosen=response_analysis.select('source','Source campaign',options,'thesis')
    assert '<option value="thesis" selected>' in chosen and '<option value=""' not in chosen


def test_analysis_resolves_named_selection_and_bounds_threads(app, monkeypatch):
    owner,source=setup_choices(app,monkeypatch)
    captured=[]
    monkeypatch.setattr(app,'start_job',lambda command,values,**kw:captured.append((command,values,kw)) or SimpleNamespace(job_id='study'))
    token=app._new_launch_ticket(dict(campaign_id=owner),purpose='svm-study')
    result=response_analysis.start(app,dict(launch_ticket=token,source_campaign=source,matched_campaign=owner,
        teacher='haiku-selected',include_source='on',seed='0',bootstrap='100'))
    assert result.job_id=='study'
    command,values,kw=captured[0]
    assert command=='response_svm' and values['--study']=='on'
    assert values['--database']==str(app.db.path) and values['--campaign#1']==source
    assert '--source-root' not in values and '--run-id' not in values
    assert values['--source-campaign']==source and kw['campaign_id']==owner


@pytest.mark.parametrize('width',[1440,390])
def test_analysis_browser_has_choices_not_preparation_paths(app,monkeypatch,browser,width):
    owner,source=setup_choices(app,monkeypatch)
    page=browser.new_page(viewport=dict(width=width,height=1000))
    page.set_default_timeout(5000)
    held=[];errors=[]
    page.on('pageerror',lambda error:errors.append(str(error)))
    def route(request):
        from urllib.parse import urlsplit
        if request.request.method=='POST':held.append(request)
        elif urlsplit(request.request.url).path=='/analysis':
            request.fulfill(content_type='text/html',body=response_analysis.page(app,owner))
        else:
            status,mime,body=app.handle('GET',urlsplit(request.request.url).path)
            request.fulfill(status=status,content_type=mime,body=body)
    page.route('http://analysis.test/**',route)
    try:
        page.goto('http://analysis.test/analysis')
        assert page.locator('body > nav').is_visible()
        assert page.get_by_label('Saved local input source',exact=True).input_value()==source
        assert page.locator('input[name="--database"],input[name="--out"],input[name="--candidates"]').count()==0
        assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
        assert _burst(page,'form[action="/analysis/start"] button')==dict(visible=True,inert=True)
        assert len(held)==1 and not errors
        held.pop().fulfill(status=400,content_type='text/html',body='<p>Analysis failed clearly</p>')
        page.get_by_text('Analysis failed clearly',exact=True).wait_for()
    finally:
        page.unroute_all(behavior='ignoreErrors')
        page.close()


def test_capture_defaults_use_installed_source_and_own_venv_without_installing(app,monkeypatch,tmp_path):
    from experiments import framework_runtime_installer as installer
    entry=dict(name='harmbench',source=dict(commit='a'*40))
    monkeypatch.setattr(installer,'load_lock',lambda path:dict(lock_id='lock',frameworks=[entry]))
    monkeypatch.setattr(installer,'published_store',lambda *a:tmp_path/'installed')
    monkeypatch.setattr(installer,'canonical_python_interpreter',lambda *a:tmp_path/'installed/bin/python')
    actual=prepared_inputs.capture_defaults(app,'harmbench',{})
    assert actual['hcap_repo']==str(tmp_path/'installed/source/harmbench')
    assert actual['hcap_python']==str(tmp_path/'installed/bin/python')
    assert actual['hcap_revision']=='a'*40
    assert Path(actual['hcap_artifact_out']).is_relative_to(app.results_root)
    assert actual['hcap_artifact_out']!=prepared_inputs.capture_defaults(app,'harmbench',{})['hcap_artifact_out']


def test_unavailable_installed_capture_reports_problem_without_an_internal_job(app,monkeypatch):
    monkeypatch.setattr(prepared_inputs,'capture_defaults',lambda *a:(_ for _ in ()).throw(RuntimeError('runtime unavailable')))
    status,_,body=app.handle('POST','/build/harmbench/prepare',{})
    assert status==200 and b'Installed capture settings are unavailable' in body
    assert not app.jobs


def test_completed_capture_attaches_without_copying_and_preserves_concurrent_edits(app,monkeypatch):
    owner=app.db.create_workspace('Capture','local')
    params=dict(campaign_id=owner,attackers='harmbench')
    app.db.save_workspace_definition(owner,params)
    capture=child(app,'capture',command='harmbench_capture')
    config=app.results_root/'saved.json';config.write_text('{}')
    capture.argv=['python','-m','experiments.harmbench_capture','--attacker-config-out',str(config)]
    operation=app._operations[app._start_operation('attack-capture',dict(params,capture_job='capture'))]
    app._advance_operation(operation)
    assert operation['status']=='ready'
    assert app.db.workspace_definition(owner)['harm_config']==str(config)
    app.db.save_workspace_definition(owner,params)
    capture2=child(app,'capture2',command='harmbench_capture');capture2.argv=capture.argv
    operation=app._operations[app._start_operation('attack-capture',dict(params,capture_job='capture2'))]
    app.db.save_workspace_definition(owner,dict(params,harm_config='user-change'))
    app._advance_operation(operation)
    assert app.db.workspace_definition(owner)['harm_config']=='user-change'


def test_compose_starts_automatic_preparation_without_second_prepare_form(app,monkeypatch):
    params=dict(mode='attestation_probe',local='vllm:test',corpora='xstest_full')
    monkeypatch.setattr(app,'_builder_params',lambda data:params)
    monkeypatch.setattr(app,'_runtime_builder_params',lambda data:data)
    monkeypatch.setattr(app,'_validate_builder',lambda data,**kw:{})
    monkeypatch.setattr(app,'_save_build_campaign',lambda data:data)
    monkeypatch.setattr(app,'_compose_from_builder',lambda data,**kw:('run_matrix',{},data))
    monkeypatch.setattr(app,'_materialize_prepared_attacker_config',lambda *a,**kw:None)
    monkeypatch.setattr(app,'_capture_execution_config_snapshot',lambda p:(p,{},''))
    monkeypatch.setattr(app,'_bind_execution_config_bundle_identity',lambda p:p)
    calls=[]
    monkeypatch.setattr(app,'_start_operation',lambda kind,p,**kw:calls.append((kind,p)) or 'prepared')
    status,location,_=app.handle('POST','/build/review',params)
    assert status==303 and location=='/operations/prepared'
    assert calls==[('direct',params)]
