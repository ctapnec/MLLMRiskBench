import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments.rig_web_app import builder_programs as subject
from experiments.rig_web_app.catalog import build_argv
from test_builder_replays import study  # noqa: F401


@pytest.fixture
def prepared(study, monkeypatch, tmp_path):  # noqa: F811 - imported pytest fixture
    app, params, calls, jobs = study
    params = dict(params, judges='rules,guardrail', retained_replays_job='replay-ready',
                  corpora='unrelated-draft-arm', attackers='unrelated-draft-attacker',
                  approximate_common_metrics='on', guardrail_model='local-guard', deadline='3600')
    forecast = json.loads(jobs['budget-job']['argv'])
    for flag in ('--pricing-config', '--budgets'):
        path = tmp_path/(flag[2:]+'.json')
        path.write_text('{}')
        forecast += [flag,str(path),flag+'-sha256',hashlib.sha256(path.read_bytes()).hexdigest()]
    jobs['budget-job']['argv'] = json.dumps(forecast)
    folder = tmp_path/'replay'
    folder.mkdir()
    media = folder/'media.json'
    media.write_text('{}')
    payload = dict(status='prepared_replay_inputs_only',
        routes=[dict(target='example:model',replay_artifacts=[dict(path='retained.json',sha256='a'*64,bytes=1)])],
        media_index=subject._descriptor(media),route_summary=[dict(source_arms=['source-arm'])])
    (folder/'prepared-replays.json').write_text(json.dumps(payload))
    args = ['python','-m','experiments.hosted_selected_replays','--out-root',str(folder)]
    for flag,value in [('--local-inventory',str(tmp_path/'source.json')),('--budget',str(tmp_path/'forecast.json')),
        ('--api-config',subject.argument(forecast,'--api-config')),
        ('--api-config-sha256',subject.argument(forecast,'--api-config-sha256'))]:
        args += [flag,value]
    jobs['replay-ready'] = dict(command='hosted_selected_replays',state='complete',exit_code=0,argv=json.dumps(args))
    composed = []
    def compose(draft):
        composed.append(copy.deepcopy(draft))
        return 'run_matrix', {'--api':draft['api'],'--corpora':draft['corpora'],'--out':'not-used',
            '--limit':draft['limit'],'--attackers':draft['attackers'],'--judges':draft['judges'],
            '--target-answer-retries':draft['target_answer_retries'],'--approximate-common-metrics':'on',
            '--deadline-seconds':draft.get('deadline',''),
            '--guardrail-model':'local-guard','--guardrail-device':'cuda:1',
            **({'--exclude-tool-conditioned':'on'} if draft.get('exclude_tool_conditioned') == 'on' else {})}, draft
    monkeypatch.setattr(app,'_compose_from_builder',compose)
    return app,params,calls,jobs,composed


def test_build_prepares_existing_counted_command_not_generation(prepared):
    app,params,calls,_,composed = prepared
    before = copy.deepcopy(params)
    status,location,_ = app.handle('POST','/build/prepare-programs',params)
    assert status == 303 and location == '/jobs/replays-job'
    assert len(calls) == 1
    command,values,kw = calls[0]
    assert command == 'hosted_campaign_prepare' and kw == {'campaign_id':params['campaign_id']}
    assert build_argv(command,values)[2] == 'experiments.hosted_campaign_prepare'
    assert '--allow-network-counts' not in values and '--verify-artifact-sha256' not in values
    request = json.loads(Path(values['--request']).read_text())
    assert request['schema'] == subject.prepare.LOCAL_SOURCES_REQUEST_SCHEMA
    assert request['input_budget_policy'] == subject.COUNTED_INPUT_POLICY
    assert set(request['sources']) == {'local_sources','budget_projection','media_index','api_config','pricing','budgets'}
    assert request['routes'][0]['target'] == params['api']
    assert not any(flag in request['runner_common_argv'] for flag in subject.prepare._CONTROLLED)
    assert '--approximate-common-metrics' in request['runner_common_argv']
    assert subject.argument(request['runner_common_argv'],'--guardrail-model') == 'local-guard'
    assert subject.argument(request['runner_common_argv'],'--deadline-seconds') == '3600'
    assert Path(request['execution_root']).is_dir() and Path(values['--count-cache']).is_dir()
    assert params == before and composed[0]['corpora'] == 'source-arm'
    assert composed[0]['attackers'] == 'replay' and composed[0]['target_answer_retries'] == '0'
    assert app.db.workspace_definition(params['campaign_id'])['retained_programs_job'] == 'replays-job'


def test_network_counting_is_an_explicit_separate_option(prepared):
    app,params,calls,_,_ = prepared
    subject.prepare_programs(app,dict(params,retained_network_counts='on'))
    assert calls[0][1]['--allow-network-counts'] == 'on'
    assert len(calls) == 1


@pytest.mark.parametrize('network_counts', [False, True])
def test_counted_preparation_preserves_image_roots_without_extra_keys(study, monkeypatch, tmp_path, network_counts):
    app, _, _, _ = study
    api = tmp_path/'counted-api.json'
    api.write_text(json.dumps({'google:gemini-3.8-flash': {'modalities': ['text', 'image'], 'max_tokens': 4096}}))
    request = tmp_path/'counted-request.json'
    request.write_text(json.dumps({'sources': {'api_config': subject._descriptor(api)},
                                  'routes': [{'target': 'google:gemini-3.8-flash'}]}))
    values = {'--request': str(request), '--request-sha256': subject._descriptor(request)['sha256']}
    if network_counts:
        values['--allow-network-counts'] = 'on'
    for name, value in [('URA_MEDIA_ROOTS', '/approved/images:/approved/derived-images'),
                        ('GEMINI_API_KEY', 'test-only-google-key'),
                        ('OPENAI_API_KEY', 'test-only-other-key'), ('HF_TOKEN', 'test-only-hub-token')]:
        monkeypatch.setenv(name, value)
    child = app._generic_child_environment('hosted_campaign_prepare', values)
    assert child['URA_MEDIA_ROOTS'] == '/approved/images:/approved/derived-images'
    assert ('GEMINI_API_KEY' in child) is network_counts
    assert 'OPENAI_API_KEY' not in child and 'HF_TOKEN' not in child


@pytest.mark.parametrize('deadline', ['', None, '0', '-1', '1.5', 'nan', 'inf', 'later'])
def test_missing_or_invalid_deadline_is_reported_before_counting(prepared, deadline):
    app, params, calls, _, composed = prepared
    with pytest.raises(ValueError, match='call-start window'):
        subject.prepare_programs(app, dict(params, deadline=deadline))
    assert not calls and not composed


def test_matched_preparation_drops_only_the_synthetic_draft_exclusion(prepared):
    app, params, calls, _, composed = prepared
    # A fresh real Build page checks this while its general mode is dry_run.
    draft = dict(params, mode='dry_run', exclude_tool_conditioned='on')
    original = copy.deepcopy(draft)
    subject.prepare_programs(app, draft)
    request = json.loads(Path(calls[0][1]['--request']).read_text())
    assert '--exclude-tool-conditioned' not in request['runner_common_argv']
    assert composed[0]['mode'] == 'measured'
    assert 'exclude_tool_conditioned' not in composed[0]
    assert draft == original


@pytest.mark.parametrize('change',[
    {'retained_replays_job':'unknown'}, {'retained_budget_caps':'{"example:model":13}'},
    {'judges':'rules,llm'}, {'local':'vllm:other'}, {'target_answer_retries':'1'},
    {'defense':'input'},
])
def test_incompatible_settings_do_not_start_counting(prepared,change):
    app,params,calls,_,_ = prepared
    with pytest.raises(ValueError):
        subject.prepare_programs(app,dict(params,**change))
    assert not calls


def test_replay_from_another_forecast_cannot_be_used(prepared):
    app,params,calls,jobs,_ = prepared
    args = json.loads(jobs['replay-ready']['argv'])
    args[args.index('--budget')+1] = '/different/forecast.json'
    jobs['replay-ready']['argv'] = json.dumps(args)
    with pytest.raises(ValueError,match='different source or forecast'):
        subject.prepare_programs(app,params)
    assert not calls


def test_preparation_panel_explains_network_and_retains_job():
    assert subject.program_panel({}) == ''
    page = subject.program_panel(dict(retained_replays_job='ready',retained_programs_job='programs'))
    assert "formaction='/build/prepare-programs'" in page
    assert "form='builder' name='retained_network_counts'" in page
    assert "name='retained_programs_job' value='programs'" in page
    assert 'No answers are generated or judged' in page and 'prompts and images' in page
