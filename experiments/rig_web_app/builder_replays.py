"""Resolve completed Build preparation jobs without asking for artifact paths."""
from __future__ import annotations

import html
import json
from pathlib import Path
from uuid import uuid4

from experiments.hosted_campaign_budget import load_bound_json
from experiments.hosted_retained_inputs import _descriptor
from ura.strict_json import strict_json_loads

from .builder_budget import selected_routes


def completed_argv(app, job_id, campaign_id, command):
    job = app.db.load_job(job_id)
    if (job is None or job['command'] != command or job['state'] != 'complete'
        or job['exit_code'] != 0 or app.db.workspace_for_job(job_id) != campaign_id):
        raise ValueError("Finish this campaign's source preparation and budget forecast first")
    return json.loads(job['argv'])


def argument(argv, name):
    if argv.count(name) != 1 or argv.index(name) + 1 >= len(argv):
        raise ValueError("The saved preparation job lacks an unambiguous " + name + " argument")
    return argv[argv.index(name) + 1]


def prepared_sources(app, params):
    owner = params.get('campaign_id', '')
    app.db.require_workspace(owner)
    source = completed_argv(app,params.get('retained_sources_job'),owner,'retained_local_sources')
    forecast = completed_argv(app,params.get('retained_budget_job'),owner,'hosted_campaign_budget')
    recorded_ids = [source[index+1] for index,value in enumerate(source[:-1]) if value == '--run-id']
    chosen = strict_json_loads(params.get('retained_source_runs','[]'))
    if not isinstance(chosen,list) or sorted(chosen) != sorted(recorded_ids):
        raise ValueError("Source selection changed; prepare the selected inputs again")
    routes, api = selected_routes(app,params)
    caps = strict_json_loads(params.get('retained_budget_caps','{}'))
    if not isinstance(caps,dict) or set(caps) != {route['spec'] for route in routes}:
        raise ValueError("Target selection changed; prepare a new forecast")
    for route in routes:
        if type(caps[route['spec']]) is not int or caps[route['spec']] <= 0:
            raise ValueError("Request caps must be positive whole numbers")
        route['call_cap'] = caps[route['spec']]
    saved_routes,_ = load_bound_json(Path(argument(forecast,'--route-configuration')),
        argument(forecast,'--route-configuration-sha256'),expect_list=True)
    saved_api,_ = load_bound_json(Path(argument(forecast,'--api-config')),argument(forecast,'--api-config-sha256'))
    if (routes != saved_routes or api != saved_api
        or params.get('retained_pricing_date') != argument(forecast,'--pricing-as-of')):
        raise ValueError("Model settings or pricing date changed; prepare a new forecast")
    return source, forecast


def prepare_replays(app, params):
    source, forecast = prepared_sources(app, params)
    owner = params['campaign_id']
    values = {'--out-root':str((app.results_root/'rig-web'/'prepared-replays'/uuid4().hex).resolve())}
    for name,argv in [('local-inventory',source),('budget',forecast)]:
        descriptor = _descriptor(Path(argument(argv,'--out')))
        values['--'+name] = descriptor['path']
        values['--'+name+'-sha256'] = descriptor['sha256']
    values['--api-config'] = argument(forecast,'--api-config')
    values['--api-config-sha256'] = argument(forecast,'--api-config-sha256')
    params = app._save_build_campaign(params)
    job = app.start_job('hosted_selected_replays',values,campaign_id=owner)
    app._save_build_campaign(dict(params,retained_replays_job=job.job_id))
    return job


def replay_panel(params):
    if not params.get('retained_budget_job'):
        return ''
    job = html.escape(params.get('retained_replays_job',''),quote=True)
    return (
        "<section class='card'><h2>Prepare matched replay inputs</h2>"
        "<p>Use the completed source selection and forecast to prepare every selected model and source arm. "
        "Prompts, earlier conversation turns, images and sampling remain those of the saved local runs. "
        "This makes no target or judge calls and does not start execution.</p>"
        "<button form='builder' formaction='/build/prepare-replays'>Prepare replay inputs</button>"
        + ("<p><a href='/jobs/" + job + "'>Open replay preparation and its artifacts</a></p>"
           "<input type='hidden' form='builder' name='retained_replays_job' value='"+job+"'>" if job else '')
        + "</section>"
    )
