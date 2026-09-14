"""Connect matched replay preparation to the existing counted-program command."""
from __future__ import annotations

import html
import json
from pathlib import Path
from uuid import uuid4

from experiments import hosted_campaign_prepare as prepare
from experiments.hosted_retained_execute import COUNTED_INPUT_POLICY
from experiments.hosted_retained_inputs import _descriptor
from experiments.hosted_campaign_budget import _write_new

from .builder_replays import argument, completed_argv, prepared_sources
from .catalog import build_argv


def prepare_programs(app, params):
    from ura.guardrail_setup import resolve_scoring_settings
    params = resolve_scoring_settings(params)
    source, forecast = prepared_sources(app, params)
    owner = params['campaign_id']
    replay_argv = completed_argv(app,params.get('retained_replays_job'),owner,'hosted_selected_replays')
    for flag, expected in (
        ('--local-inventory',argument(source,'--out')), ('--budget',argument(forecast,'--out')),
        ('--api-config',argument(forecast,'--api-config')),
        ('--api-config-sha256',argument(forecast,'--api-config-sha256')),
    ):
        if argument(replay_argv,flag) != expected:
            raise ValueError('Replay preparation belongs to different source or forecast jobs')
    replay = json.loads((Path(argument(replay_argv,'--out-root'))/'prepared-replays.json').read_text())
    if replay.get('status') != 'prepared_replay_inputs_only':
        raise ValueError('Finish matched replay preparation first')
    if params.get('local'):
        raise ValueError('This matched follow-on prepares hosted targets; keep local source models in the source selection')
    if params.get('defense', 'none') not in {'', 'none'}:
        raise ValueError('Matched hosted collection requires defense none; its saved inputs define the comparison')
    if params.get('judges') != 'rules,guardrail':
        raise ValueError('Matched collection retains rules,guardrail for local post-hoc scoring; select this cascade in Evaluation')
    if params.get('target_answer_retries','0') not in {'','0'}:
        raise ValueError('Matched hosted work uses zero answer retries; HTTP retries remain separate')
    try:
        deadline = int(params.get('deadline', ''))
    except (TypeError, ValueError):
        deadline = 0
    if deadline <= 0:
        raise ValueError('Set a positive whole-number call-start window (--deadline-seconds) in Execution before counted preparation')
    # The replay job, not the unrelated ordinary Runner arm picker, determines
    # the exact source arms. Keep this composition separate from the saved draft.
    arms = sorted({arm for row in replay['route_summary'] for arm in row['source_arms']})
    draft = {key:value for key,value in params.items() if not key.startswith('_')}
    draft.update(mode='measured',corpora=','.join(arms),attackers='replay',limit='0',
                 seeds='0',sample_seed='0',target_answer_retries='0')
    # This is a standalone synthetic dry-run option, initially checked in
    # Build. The retained replay selection already fixes the actual inputs.
    draft.pop('exclude_tool_conditioned', None)
    command, values, _ = app._compose_from_builder(draft)
    if command != 'run_matrix':
        raise ValueError('Matched preparation requires the ordinary Runner composition')
    # The existing preparer supplies target, corpus, replay and exact call counts.
    common_values = {flag:value for flag,value in values.items() if flag.split('#',1)[0] not in prepare._CONTROLLED}
    common = build_argv(command,common_values)[3:]
    prepare._common_argv(common)
    folder = (app.results_root/'rig-web'/'matched-programs'/uuid4().hex).resolve()
    folder.mkdir(parents=True,mode=0o700)
    execution = folder/'execution'
    execution.mkdir(mode=0o700)
    counts = folder/'count-cache'
    counts.mkdir(mode=0o700)
    sources = {'local_sources':_descriptor(Path(argument(source,'--out'))),
               'budget_projection':_descriptor(Path(argument(forecast,'--out'))),
               'media_index':replay['media_index']}
    for name,flag in [('api_config','--api-config'),('pricing','--pricing-config'),('budgets','--budgets')]:
        sources[name] = _descriptor(Path(argument(forecast,flag)))
    request = dict(schema=prepare.LOCAL_SOURCES_REQUEST_SCHEMA,input_budget_policy=COUNTED_INPUT_POLICY,
        results_root=str(app.results_root.resolve()),pricing_as_of=params['retained_pricing_date'],
        execution_root=str(execution),runner_common_argv=common,sources=sources,routes=replay['routes'])
    path = folder/'request.json'
    _write_new(path,request)
    descriptor = _descriptor(path)
    options = {'--request':str(path),'--request-sha256':descriptor['sha256'],
               '--out-root':str(folder/'prepared'),'--count-cache':str(counts)}
    if params.get('retained_network_counts') == 'on':
        options['--allow-network-counts'] = 'on'
    params = app._save_build_campaign(params)
    job = app.start_job('hosted_campaign_prepare',options,campaign_id=owner)
    app._save_build_campaign(dict(params,retained_programs_job=job.job_id))
    return job


def program_panel(params):
    if not any(params.get(key) for key in ('retained_sources_job','retained_budget_job','retained_replays_job')):
        return ''
    ready = bool(params.get('retained_replays_job'))
    disabled = '' if ready else ' disabled'
    prerequisite = ''
    if not ready:
        if params.get('retained_budget_job'):
            prerequisite = ("<p class='notice amber'>Waiting for replay preparation. "
                "Click <strong>Prepare replay inputs</strong> in the panel above, wait for its job to complete, "
                "then reopen this campaign in Build. This is different from Prepare selected inputs. "
                "Your existing input selection and forecast do not need to be repeated. "
                "<a href='#matched-replay-inputs'>Go to replay preparation</a>.</p>")
        else:
            prerequisite = ("<p class='notice amber'>Waiting for the forecast and replay preparation. "
                "Use <strong>Prepare forecast</strong>, followed by <strong>Prepare replay inputs</strong>, "
                "then return to this step. No counting or generation has started.</p>")
    job = html.escape(params.get('retained_programs_job',''),quote=True)
    checked = ' checked' if params.get('retained_network_counts') == 'on' else ''
    return (
        "<section class='card' id='counted-collection'><h2>Count inputs and prepare collection</h2>"
        + prerequisite +
        "<p>Prepare one shared spending plan and executable programs for the saved replay selection. "
        "Output allowances and request caps remain those of the forecast. No answers are generated or judged. "
        "Select rules,guardrail in Evaluation. The scoring model's installed revision and GPU placement "
        "are resolved automatically for transport checks and local post-hoc scoring; "
        "Haiku judgments are a separate output-specific stage. Set a positive call-start window "
        "in Execution before preparation; this is not a per-answer timeout.</p>"
        "<label class='checkrow'><input type='checkbox' form='builder' name='retained_network_counts'" + checked + disabled + ">"
        "<span>Allow provider token counting for these selected inputs</span></label>"
        "<p class='note'>When required, counting sends the saved prompts and images to their selected provider. "
        "It does not call a generation endpoint. Without this option, only locally supported counts and "
        "existing count receipts are usable. Review actual prepared costs before collection; the initial "
        "Haiku estimate is not a completed judging selection.</p>"
        "<button form='builder' formaction='/build/prepare-programs'" + disabled + ">Prepare counted collection</button>"
        + ("<p><a href='/jobs/" + job + "'>Open collection preparation and its artifacts</a></p>"
           "<input type='hidden' form='builder' name='retained_programs_job' value='"+job+"'>" if job else '')
        + "</section>"
    )
