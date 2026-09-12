"""Selected-route forecasts use the existing CLI, never a second scheduler."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_campaign_budget as budget
from experiments.rig_web import RigWebApp
from experiments.rig_web_app import builder_budget as subject
from experiments.rig_web_app.catalog import build_argv


def _pricing():
    # Synthetic no-call tariffs, not a claim about current provider prices.
    return {'schema':'ura-console-pricing/1','providers':{
        provider:{'models':{model:{'rates':[{'currency':'USD','effective_date':'2026-09-03',
            'per_million_tokens':{'input':1,'output':5}}]}}}
        for provider,model in [('deepseek','deepseek-v4-pro'),('anthropic',budget.JUDGE_MODEL)]}}


def _budgets():
    return {'providers':[{'name':provider,'match':provider,'prepaid':'$90'} for provider in ('deepseek','anthropic')]}


@pytest.fixture
def study(tmp_path, monkeypatch):
    app = RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,
                    gpu_hardware={},system_hardware={})
    owner = app.db.create_workspace('Matched comparison','api')
    spec = 'deepseek:deepseek-v4-pro'
    config = {'modalities':['text'],'max_tokens':16384,'reasoning_effort':'low','key_env':'DEEPSEEK_API_KEY'}
    snapshot = {'routes':[{'requested_spec':spec,'provider':'deepseek','model':'deepseek-v4-pro','config':config}]}
    calls = []
    def selected(params):
        assert params['judges'] == '' and params['judge_model'] == ''
        assert params['mode'] == 'measured'
        return copy.deepcopy(snapshot),'unused','unused',{spec:copy.deepcopy(config)}
    monkeypatch.setattr(app,'_selected_api_config_snapshot',selected)
    monkeypatch.setattr(app,'_load_registry',lambda name, example: _pricing() if name=='pricing.json' else _budgets())
    monkeypatch.setattr(app,'start_job',lambda command, values, **kwargs:
        calls.append((command,values,kwargs)) or SimpleNamespace(job_id='budget-job'))
    params = dict(work_kind='campaign',campaign_id=owner,api=spec,judges='rules,llm',judge_model='selected-judge',
                  retained_sources_job='source-job',retained_budget_caps=json.dumps({spec:12}),retained_pricing_date='2026-09-12')
    try:
        yield app,params,calls,snapshot
    finally:
        app.close()


def test_forecast_uses_selected_caps_and_existing_budget_cli(study):
    app,params,calls,_ = study
    status,location,_ = app.handle('POST','/build/forecast-matched',params)
    assert status == 303 and location == '/jobs/budget-job'
    command,values,kwargs = calls[0]
    assert command == 'hosted_campaign_budget' and kwargs == {'campaign_id':params['campaign_id']}
    assert values['--reservation-policy'] == 'per_attempt'
    assert '--allow-network-counts' not in values and '--verify-artifact-sha256' not in values
    argv = build_argv(command,values)
    assert argv[2] == 'experiments.hosted_campaign_budget'
    assert budget.main(argv[3:]) == 0
    result = json.loads(Path(values['--out']).read_text())
    route = result['routes'][0]
    assert len(result['routes']) == 1
    assert route['target_spec'] == params['api'] and route['paid_call_cap'] == 12
    assert route['maximum_output_tokens_per_call'] == 16384
    assert result['route_configuration'][0]['reservation_rate_multiplier'] == 2
    saved = app.db.workspace_definition(params['campaign_id'])
    assert saved['retained_sources_job'] == 'source-job' and saved['retained_budget_job'] == 'budget-job'
    assert saved['judges'] == 'rules,llm' and saved['judge_model'] == 'selected-judge'
    assert len(calls) == 1  # No target or judge launch follows a forecast.


@pytest.mark.parametrize('caps',[{}, {'other':2},{'deepseek:deepseek-v4-pro':True},
    {'deepseek:deepseek-v4-pro':0},{'deepseek:deepseek-v4-pro':1.5}])
def test_invalid_or_stale_caps_cannot_start_or_write(study,caps):
    app,params,calls,_ = study
    with pytest.raises(ValueError):
        subject.prepare_budget(app,dict(params,retained_budget_caps=json.dumps(caps)))
    assert calls == [] and not (app.results_root/'rig-web'/'matched-budgets').exists()


def test_duplicate_json_caps_rejected(study):
    app,params,calls,_ = study
    with pytest.raises(ValueError):
        subject.prepare_budget(app,dict(params,retained_budget_caps='{"deepseek:deepseek-v4-pro":1,"deepseek:deepseek-v4-pro":2}'))
    assert not calls


def test_forecast_table_has_form_ownership_and_retains_links(study):
    app,params,_,_ = study
    page = subject.budget_panel(app,dict(params,retained_budget_job='budget-job'))
    assert 'Forecast matched hosted work' in page and '16384' in page
    assert "form='builder' name='retained_budget_caps'" in page
    assert "form='builder' name='retained_pricing_date'" in page
    assert "type='number' form='builder'" in page
    assert "name='retained_budget_job' value='budget-job'" in page
    assert "formaction='/build/forecast-matched'" in page
    assert subject.budget_panel(app,{}) == ''


def test_fixed_route_uses_its_actual_inherent_output_policy(study,monkeypatch):
    app,params,_,_ = study
    fixed = next(row for row in budget.ROUTES if row.get('inherent_config'))
    monkeypatch.setattr(app,'_selected_api_config_snapshot',lambda params: (
        {'routes':[dict(requested_spec=fixed['spec'],provider=fixed['provider'],model=fixed['model'],
                        config={'inherent_route':True,'modalities':['text','image']})]},'', '', {}))
    routes,api = subject.selected_routes(app,dict(params,api=fixed['spec']))
    assert routes[0]['max_output_tokens'] == fixed['max_output_tokens']
    assert routes[0]['inherent_config'] is True and api[fixed['spec']] == {'modalities':['text','image']}
