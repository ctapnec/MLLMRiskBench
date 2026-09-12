"""Normal Build selects source runs without outcome bias or manual artifact paths."""
import json
from types import SimpleNamespace

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app import builder_sources as subject
from experiments.rig_web_app.catalog import build_argv


@pytest.fixture
def study(tmp_path):
    app = RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state', repo_root=tmp_path,
        gpu_hardware={}, system_hardware={})
    local = app.db.create_workspace('Local sources', 'local')
    api = app.db.create_workspace('Hosted comparison', 'api')
    try:
        yield app, local, api
    finally:
        app.close()


def put(app, owner, run, *, model='ollama:model', outcome='missing', evidence='measured', n=1, suffix=''):
    root = app.results_root / (run + suffix)
    root.mkdir(parents=True, exist_ok=True)
    aid = run + suffix + str(n)
    response_id = run + ':' + str(n)
    assignment = dict(assignment_id=aid, model=model, input_id=aid, condition_id=run,
        modality='text', framework='replay', corpus='arm', response_id=response_id, evidence_class=evidence)
    response = dict(response_id=response_id, assignment_id=aid, condition_id=run, outcome=outcome,
        truncated=True, source_ref=str(root/(run+'.responses.checkpoint.jsonl'))+':'+str(n))
    app.db.publish_workspace_results(owner, assignments=[assignment], responses=[response], judgments=[])
    return assignment, response


def test_index_selection_includes_missing_historical_outputs_and_vllm(study, monkeypatch):
    app, local, other = study
    assignment, response = put(app, local, 'old')
    put(app, local, 'vllm', model='vllm:repo/model')
    put(app, local, 'hosted', model='openai:model')
    put(app, local, 'probe', evidence='diagnostic')
    put(app, other, 'other')
    put(app, local, 'old', n=2)
    # Replacement does not erase the source run whose missing response was saved.
    replacement = dict(response, response_id='replacement:1', condition_id='new', outcome='usable',
        source_ref=str(app.results_root/'replacement.responses.jsonl')+':1')
    app.db.publish_workspace_results(local, assignments=[dict(assignment, response_id='replacement:1')],
        responses=[replacement], judgments=[])
    monkeypatch.setattr(subject.Path, 'read_bytes', lambda *a: pytest.fail('Page read opened an artifact'))
    rows = subject.source_runs(app.db, local)
    assert {row['run_id'] for row in rows} == {'old', 'replacement', 'vllm'}
    assert next(row for row in rows if row['run_id']=='old')['responses'] == 2


@pytest.mark.parametrize('selected', ['[]', '["unknown"]', '["one","one"]', '{}', 'not-json'])
def test_selection_rejects_missing_duplicate_or_malformed_runs(selected):
    with pytest.raises(ValueError):
        subject.selected_runs(dict(retained_source_runs=selected), [dict(run_id='one')])


def test_exact_source_arguments_are_shared_cli_arguments(study):
    app, local, _ = study
    put(app, local, 'first')
    put(app, local, 'second', model='vllm:model')
    rows = subject.source_runs(app.db, local)
    chosen = subject.selected_runs(dict(retained_source_runs='["second"]'), rows)
    values = subject.source_arguments(chosen, app.results_root, app.results_root/'inventory.json')
    assert values['--run-id'] == 'second'
    assert values['--source-root'] == str((app.results_root/'second').resolve())
    argv = build_argv('retained_local_sources', values)
    assert argv[2] == 'experiments.retained_local_sources'
    assert '--verify-artifact-sha256' not in argv
    assert 'first' not in argv and '--api' not in argv


def test_prepare_action_preserves_campaign_and_draft_without_generation(study, monkeypatch):
    app, local, api = study
    put(app, local, 'saved')
    seen = []
    monkeypatch.setattr(app, 'start_job', lambda command, values, **kw:
        seen.append((command, values, kw)) or SimpleNamespace(job_id='prepared-job'))
    params = dict(work_kind='campaign', campaign_id=api, retained_source_campaign=local,
        retained_source_runs='["saved"]', api='openai:selected', corpora='original-arm', attackers='replay')
    status, location, _ = app.handle('POST', '/build/prepare-inputs', params)
    assert status == 303 and location == '/jobs/prepared-job'
    command, values, kwargs = seen[0]
    assert command == 'retained_local_sources' and kwargs == dict(campaign_id=api)
    assert values['--run-id'] == 'saved'
    assert '--verify-artifact-sha256' not in values
    saved = app.db.workspace_definition(api)
    assert saved['retained_sources_job'] == 'prepared-job'
    assert saved['retained_source_runs'] == '["saved"]'
    assert saved['api'] == 'openai:selected' and saved['corpora'] == 'original-arm'
    assert not list(app.results_root.glob('**/inventory.json'))


def test_build_renders_indexed_selection_and_distinct_prepare_action(study, monkeypatch):
    app, local, api = study
    put(app, local, 'saved')
    monkeypatch.setattr(app, 'start_job', lambda *a, **kw: pytest.fail('Opening Build launched a job'))
    params = dict(work_kind='campaign', campaign_id=api, retained_source_campaign=local,
        retained_source_runs='["saved"]')
    status, _, body = app.handle('POST', '/build/source-runs', params)
    page = body.decode()
    assert status == 200
    assert "formaction='/build/prepare-inputs'" in page
    assert "<option value='saved' selected>" in page
    assert 'Missing and truncated responses are included' in page
    assert 'does not change the current pipeline' in page
    assert 'DOMContentLoaded' in page and 'selectedOptions' in page
    assert app.db.workspace_definition(api) == {}


def test_preparation_requires_campaign_and_exact_source(study, monkeypatch):
    app, local, _ = study
    put(app, local, 'saved')
    monkeypatch.setattr(app, 'start_job', lambda *a, **kw: pytest.fail('Invalid selection launched'))
    with pytest.raises(ValueError, match='Campaign'):
        subject.prepare_selected_inputs(app, dict(work_kind='run', retained_source_campaign=local,
            retained_source_runs='["saved"]'))
    with pytest.raises(ValueError, match='absent'):
        subject.prepare_selected_inputs(app, dict(work_kind='campaign', campaign_name='new',
            retained_source_campaign=local, retained_source_runs='["unlisted"]'))


def test_preparation_fields_do_not_change_native_projection(study):
    app, local, api = study
    params = dict(work_kind='campaign', campaign_id=api, corpora='synth')
    before = app._projection_params(params)
    assert app._projection_params(dict(params, retained_source_campaign=local,
        retained_source_runs=json.dumps(['saved']), retained_sources_job='job')) == before


def test_budget_form_exposes_custom_routes_and_shared_per_attempt_policy():
    values = {'--'+name: value for name, value in dict(api_config='api.json', pricing_config='pricing.json',
        budgets='budgets.json', pricing_as_of='2026-09-12', out='projection.json').items()}
    values = {key.replace('_', '-'): value for key, value in values.items()}
    for key in ('api-config', 'pricing-config', 'budgets'):
        values['--'+key+'-sha256'] = 'a'*64
    values.update({'--route-configuration':'routes.json', '--route-configuration-sha256':'b'*64,
        '--reservation-policy':'per_attempt'})
    argv = build_argv('hosted_campaign_budget', values)
    assert argv[argv.index('--route-configuration')+1] == 'routes.json'
    assert argv[argv.index('--reservation-policy')+1] == 'per_attempt'
