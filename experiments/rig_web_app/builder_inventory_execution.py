"""Use the common funded judging executor for Build's all-output selection."""
from __future__ import annotations

import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.retained_response_judge_execute import _write_new

from .builder_collection import collection_history
from .builder_haiku_judging import _choices
from .builder_native_judging import _state
from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


COMMAND = 'retained_inventory_judging'


def prepare(app, params):
    owner = params.get('campaign_id', '')
    source = completed_argv(app, params.get('retained_inventory_items_job'), owner, 'retained_inventory_judge_items')
    forecast = completed_argv(app, params.get('retained_budget_job'), owner, 'hosted_campaign_budget')
    model = params.get('retained_haiku_model', '')
    if model not in _choices(app):
        raise ValueError('Choose a configured Haiku model in the judging controls')
    _, _, _, configs = app._selected_api_config_snapshot(dict(mode='measured', api='', judges='llm', judge_model=model))
    config = {model: dict(configs[model], max_tokens=512)}
    values = {'--items-root': argument(source, '--out'), '--judge-model': model,
        '--pricing-config': argument(forecast, '--pricing-config'),
        '--pricing-as-of': argument(forecast, '--pricing-as-of'), '--allow-token-counts': 'on'}
    with app._app_lock:
        previous = collection_history(app, owner, [values['--items-root']], command=COMMAND, input_flag='--items-root')
        if previous is not None:
            argv = json.loads(previous['argv'])
            api = Path(argument(argv, '--api-config'))
            equivalent = argv == build_argv(COMMAND, dict(values, **{'--api-config': str(api), '--out': argument(argv, '--out')}))
            if equivalent and json.loads(api.read_text()) == config and _state(app, previous) in {'complete', 'running', 'queued', 'starting'}:
                app._save_build_campaign(dict(params, retained_inventory_plan_job=previous['job_id']))
                return SimpleNamespace(job_id=previous['job_id'])
            if _state(app, previous) in {'running', 'queued', 'starting'}:
                raise ValueError('The all-output judging preparation is active; open that job')
        folder = (app.results_root / 'rig-web' / 'inventory-judging' / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        api = folder / 'api-config.json'
        _write_new(api, config)
        values.update({'--api-config': str(api), '--out': str(folder / 'prepared')})
        job = app.start_job(COMMAND, values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_inventory_plan_job=job.job_id))
        return job


def review(app, params):
    owner = params.get('campaign_id', '')
    argv = completed_argv(app, params.get('retained_inventory_plan_job'), owner, COMMAND)
    root = Path(argument(argv, '--out'))
    ready = json.loads((root / 'result.json').read_text())
    if ready.get('status') not in {'ready_for_funded_judging', 'needs_funding_review'}:
        raise ValueError('Select a completed all-output judging preparation')
    coverage = ready['coverage']
    body = '<h1>Review all-output Haiku judging</h1>' + app._campaign_banner(owner)
    body += (f"<p>{coverage['input_entries']:,} shared inputs; {coverage['retained_outputs']:,} saved outputs; "
        f"{ready['selected_outputs']:,} funded answers selected for output-specific judging. "
        f"{coverage['existing_execution_owned']:,} outputs remain with their existing judging executions; "
        f"{coverage['missing_outputs']:,} have missing text and {coverage['unfunded_outputs']:,} lack matching funding.</p>"
        '<p>Each saved answer receives its own verdict. All matching local model answers are included, not one counterpart. '
        'Existing execution ownership is not proof of a valid verdict. Target models are not called. '
        'Haiku uses the saved prompt and answer; physical media are represented by their retained text proxy.</p>'
        '<p>512 output tokens per assessment; no answer retries; up to three HTTP-error retries. '
        'Two network workers use the original campaign funding. Completed judgments resume without another paid call. '
        'Invalid verdicts remain recorded, and each verdict and cost is published to its exact campaign output.</p>'
        f"<p>First-attempt estimate: USD {ready['first_attempt_estimate_microusd']/1e6:,.6f}. "
        'This is an estimate, not spending or a new allowance.</p>')
    if ready['funding_review']:
        body += f"<p>{len(ready['funding_review']):,} requests exceed their existing funded slot. Review their saved counts and funding before execution.</p>"
    elif ready['selected_outputs']:
        values = {'--preparation': str(root), '--execute': 'on', '--ack-paid-execution': 'on',
            '--workers': '2', '--out': str(root.parent / 'judgments')}
        matching = params.get('retained_source_campaign', '')
        app.db.require_workspace(matching)
        if matching != owner:
            values['--matching-workspace-id'] = matching
        previous = collection_history(app, owner, [str(root)], command=COMMAND, input_flag='--preparation')
        if previous is not None:
            old = json.loads(previous['argv'])
            values['--out'] = argument(old, '--out')
            if old != build_argv(COMMAND, values):
                raise ValueError('Resume the original all-output judging campaigns and execution settings')
        ticket = app._new_launch_ticket(dict(campaign_id=owner, values=json.dumps(values)), purpose='all-output-haiku')
        body += ("<details><summary>Exact command</summary><pre>" + html.escape(' '.join(build_argv(COMMAND, values)))
            + "</pre></details><form method='post' action='/build/execute-inventory-haiku'>"
            "<input type='hidden' name='launch_ticket' value='" + html.escape(ticket, quote=True) + "'>"
            '<button type="submit">Start or resume all-output Haiku judging</button></form>')
    else:
        body += '<p>No unstarted funded answers remain in this selection. Existing verdict validity is not inferred.</p>'
    body += "<p><a href='/build?campaign_id=" + html.escape(owner, quote=True) + "'>Return to Build</a></p>"
    return _page('Review all-output Haiku judging', body, active='Build')


def launch(app, params):
    saved = app._consume_launch_ticket(params.get('launch_ticket', ''), purpose='all-output-haiku')
    owner, values = saved['campaign_id'], json.loads(saved['values'])
    with app._app_lock:
        previous = collection_history(app, owner, [values['--preparation']], command=COMMAND, input_flag='--preparation')
        if previous is not None and _state(app, previous) in {'running', 'starting', 'queued', 'complete'}:
            return SimpleNamespace(job_id=previous['job_id'])
        return app.start_job(COMMAND, values, campaign_id=owner)
