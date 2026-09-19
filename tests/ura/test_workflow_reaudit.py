import json
from types import SimpleNamespace

from test_operator_operations import app, child  # noqa: F401
from experiments.rig_web_app import connection_workflow as connection
from experiments.rig_web_app.analysis_summary import render


def test_save_stays_in_build(app):
    owner=app.db.create_workspace('Keep editing','local')
    status,location,_=app.handle('POST','/build/save',dict(campaign_id=owner,work_kind='campaign',mode='dry_run'))
    assert status==303 and location=='/build?campaign_id='+owner+'&saved=1#build-general'


def test_automatic_bounds_use_exact_projection_before_execution(app,monkeypatch):
    operation=dict(id='a'*32,params=dict(automatic_caps='on',cap_target='1000000000'))
    monkeypatch.setattr(app,'_read_lane_projection',lambda p:({'call_projection':dict(target_calls=8,judge_calls=4,http_attempts=0)},''))
    app._resolve_operation_caps(operation)
    assert operation['params']==dict(automatic_caps='on',cap_target='8',cap_judge='4',cap_http='1',_caps_resolved='yes')


def test_manual_bounds_are_not_silently_raised(app):
    operation=dict(params=dict(cap_target='2'))
    app._resolve_operation_caps(operation)
    assert operation['params']==dict(cap_target='2')


def test_derive_only_missing_routes_without_changing_measured_draft(app,monkeypatch):
    monkeypatch.setattr(app,'_campaign_transport_receipts',lambda p:([{'keys':[('vllm:Qwen',('text',))]}],''))
    monkeypatch.setattr(app,'_automatic_campaign_setup',lambda p,**kw:p)
    monkeypatch.setattr(app,'_builder_params',lambda p:p)
    params=dict(setup_mode='automatic',mode='measured',local='vllm:Qwen',corpora='xstest_full,vlsbench_release',
                limit='100',seeds='2,3',attackers='replay',max_queries='8',max_turns='4',scope='saved')
    original=dict(params)
    probes=connection.missing(app,params)
    assert params==original and len(probes)==1
    assert probes[0]['corpora']=='vlsbench_release' and probes[0]['limit']=='1'
    assert probes[0]['seeds']=='2' and probes[0]['max_queries']=='1'
    assert probes[0]['mode']=='attestation_probe' and probes[0]['scope']=='saved'


def test_ready_checks_do_not_launch_without_reviewed_start(app,monkeypatch):
    app._operations['check']=dict(status='ready')
    operation=dict(id='b'*32,params={},connection_operations=[dict(preparation='check')])
    monkeypatch.setattr(connection,'launch',lambda *a:(_ for _ in ()).throw(AssertionError('unreviewed call')))
    assert connection.advance(app,operation)
    assert operation['awaiting_connections'] and operation['status']=='ready'


def test_double_start_reopens_same_execution(app):
    job=child(app,'saved-run')
    assert connection.launch(app,dict(execution_job='saved-run')) is job


def test_analysis_summary_readable_and_reports_insufficient_support(app):
    root=app.results_root/'summary';root.mkdir(parents=True)
    evaluation=root/'evaluation';evaluation.mkdir()
    (root/'result.json').write_text(json.dumps(dict(stages=dict(evaluation=str(evaluation)),packaging_reason='Insufficient class support')))
    (evaluation/'result.json').write_text(json.dumps(dict(selected_responses=20,independent_groups=8,
        experiments=[dict(task='over_refusal',protocol='grouped',features='response',estimator='linear_svm',status='evaluated',test=dict(macro_f1=.75))])))
    page=render(app,root)
    assert '20 selected text answers' in page and '8 independent input groups' in page
    assert '0.750' in page and 'Insufficient class support' in page
    assert 'Metrics, predictions and baselines' in page


def test_cost_scenarios_use_recorded_rates_and_output_allowance(app,monkeypatch):
    from experiments.rig_web_app.direct_costs import forecast
    from experiments.rig_web_app import direct_costs
    monkeypatch.setattr(app,'_selected_api_config_snapshot',lambda p:({'routes':[dict(requested_spec='anthropic:test',provider='anthropic',model='test',config=dict(max_tokens=512))]},None,None,None))
    monkeypatch.setattr(app,'_load_registry',lambda *a:{})
    monkeypatch.setattr(direct_costs,'rate_for',lambda *a:(dict(currency='USD',per_million_tokens=dict(input=1,output=5)),''))
    page=forecast(app,dict(api='anthropic:test'),dict(call_projection=dict(target_calls=2,judge_calls=0)))
    assert '$0.0095' in page and '$0.0133' in page
    assert 'not counted input tokens' in page and 'before HTTP retries' in page
