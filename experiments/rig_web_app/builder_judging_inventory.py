"""Review all saved model outputs on shared inputs without buying judgments."""
from __future__ import annotations

import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.retained_judge_inventory import SCHEMA

from .builder_collection import prepared_collection, collection_history
from .builder_native_judging import preparation_history, _state
from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


def prepare_judging_inventory(app, params):
    owner = params.get('campaign_id', '')
    receipt = prepared_collection(app, params)
    source = completed_argv(app, params.get('retained_sources_job'), owner, 'retained_local_sources')
    preparations = preparation_history(app, owner, receipt['programs'])
    views = []
    eligible = set()
    for job in preparations:
        if _state(app, job) not in {'complete', 'failed'} or job['exit_code'] not in {0, 1}:
            continue
        path = Path(argument(json.loads(job['argv']), '--out')) / 'result.json'
        if not path.is_file():
            continue
        saved = json.loads(path.read_text())
        if saved.get('status') not in {'prepared', 'preparation_incomplete'}:
            continue
        views.append(str(path))
        eligible.add(job['job_id'])
    if params.get('retained_native_judging_job') not in eligible:
        raise ValueError("Select this campaign's completed saved-output preparation first")
    try:
        limit = int(params.get('retained_inventory_limit', '0'))
        seed = int(params.get('retained_inventory_seed', '0'))
    except ValueError:
        raise ValueError('Use a whole-number input limit and selection seed') from None
    if limit < 0:
        raise ValueError('Input limit must be zero for all inputs or a positive integer')
    values = {'--local-view': argument(source, '--out'), '--input-limit': str(limit), '--sample-seed': str(seed)}
    views = sorted(set(views))
    for index, path in enumerate(views):
        values['--hosted-view' + (f'#{index}' if index else '')] = path
    with app._app_lock:
        previous = collection_history(app, owner, views, command='retained_judge_inventory', input_flag='--hosted-view')
        if previous is not None:
            argv = json.loads(previous['argv'])
            if (argv == build_argv('retained_judge_inventory', dict(values, **{'--out': argument(argv, '--out')}))
                    and _state(app, previous) in {'running', 'starting', 'queued', 'complete'}):
                app._save_build_campaign(dict(params, retained_inventory_job=previous['job_id']))
                return SimpleNamespace(job_id=previous['job_id'])
            if _state(app, previous) in {'running', 'starting', 'queued'}:
                raise ValueError('This source inventory is still being prepared; open its job')
        folder = (app.results_root / 'rig-web' / 'judging-inventory' / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        values['--out'] = str(folder / 'inventory.json')
        app._save_build_campaign(params)
        job = app.start_job('retained_judge_inventory', values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_inventory_job=job.job_id))
        return job


def judging_inventory_review(app, params):
    owner = params.get('campaign_id', '')
    argv = completed_argv(app, params.get('retained_inventory_job'), owner, 'retained_judge_inventory')
    value = json.loads(Path(argument(argv, '--out')).read_text())
    if value.get('schema') != SCHEMA or value.get('status') != 'inventory_only_no_calls':
        raise ValueError('The saved job has no completed same-input output inventory')
    selection, coverage = value['selection'], value['coverage']
    pending = sum(part.get('unprepared_outputs', 0) for part in value['population'].values())
    rows = ''.join('<tr><td>' + html.escape(row['cohort']) + "</td><td title='" + html.escape(row['model'], quote=True)
        + "'>" + html.escape(row['model'].split('@', 1)[0])
        + f"</td><td data-label='Saved outputs'>{row['retained_outputs']:,}</td>"
        + f"<td data-label='With text'>{row.get('judgeable_text', 0):,}</td>"
        + f"<td data-label='Missing text'>{row.get('missing_text', 0):,}</td></tr>" for row in value['by_model'])
    body = '<h1>Same-input output coverage</h1>' + app._campaign_banner(owner)
    body += (f"<p>{selection['selected_inputs']:,} selected input entries; {coverage['retained_outputs']:,} retained outputs. "
        'Every saved local and hosted answer on those inputs is included, including separate generation conditions. '
        'Inputs are selected independently of answer availability. Output counts are not independent input counts.</p>'
        f"<p>{coverage['judgeable_text']:,} outputs have text; {coverage['missing_text']:,} have missing text. "
        f"{coverage['hosted_inputs_without_local_records']:,} selected inputs have no retained local record. "
        f"{pending:,} source outputs remain unprepared outside this observed population.</p>"
        '<p>This is coverage, not completed judging. Text availability does not establish rubric eligibility, '
        'an existing verdict or funding. No target or judge calls were made. The separately reviewed paired '
        'Haiku selection in Build is not changed by this inventory.</p>'
        "<table class='judging-inventory-table'><thead><tr><th>Population</th><th>Model</th><th>Saved outputs</th>"
        '<th>With text</th><th>Missing text</th></tr></thead><tbody>' + rows + '</tbody></table>'
        + "<details><summary>Exact command</summary><pre>" + html.escape(' '.join(argv)) + '</pre></details>'
        + "<p><a href='/jobs/" + html.escape(params['retained_inventory_job'], quote=True) + "'>Open full inventory</a>"
        + " | <a href='/build?campaign_id=" + html.escape(owner, quote=True) + "'>Return to Build</a></p>")
    return _page('Same-input output coverage', body, active='Build')


def prepare_inventory_judging(app, params):
    owner = params.get('campaign_id', '')
    receipt = prepared_collection(app, params)
    argv = completed_argv(app, params.get('retained_inventory_job'), owner, 'retained_judge_inventory')
    inventory_path = argument(argv, '--out')
    values = {'--inventory': inventory_path, '--budget-root': str(Path(receipt['budget']['path']).parent),
        '--budget-plan-sha256': receipt['budget']['sha256']}
    for flag in ('--local-view', '--hosted-view'):
        paths = [argv[index+1] for index, value in enumerate(argv[:-1]) if value == flag]
        for index, path in enumerate(paths):
            values[flag + (f'#{index}' if index else '')] = path
    with app._app_lock:
        previous = collection_history(app, owner, [inventory_path],
            command='retained_inventory_judge_items', input_flag='--inventory')
        if previous is not None:
            old = json.loads(previous['argv'])
            if (old == build_argv('retained_inventory_judge_items', dict(values, **{'--out': argument(old, '--out')}))
                    and _state(app, previous) in {'running', 'starting', 'queued', 'complete'}):
                app._save_build_campaign(dict(params, retained_inventory_items_job=previous['job_id']))
                return SimpleNamespace(job_id=previous['job_id'])
            if _state(app, previous) in {'running', 'starting', 'queued'}:
                raise ValueError('This all-output funding review is still active; open its job')
        folder = (app.results_root / 'rig-web' / 'judging-inventory' / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        values['--out'] = str(folder / 'judging-items')
        job = app.start_job('retained_inventory_judge_items', values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_inventory_items_job=job.job_id))
        return job


def inventory_judging_review(app, params):
    owner = params.get('campaign_id', '')
    argv = completed_argv(app, params.get('retained_inventory_items_job'), owner, 'retained_inventory_judge_items')
    value = json.loads((Path(argument(argv, '--out')) / 'result.json').read_text())
    if value.get('status') != 'prepared_no_calls' or value.get('scope') != 'all_saved_outputs_on_selected_inputs':
        raise ValueError('The selected job has no completed all-output funding review')
    categories = (('selected_outputs', 'Funded and not yet started'),
        ('existing_execution_owned', 'Owned by existing judging executions'),
        ('unfunded_outputs', 'No matching funding in this selection'), ('missing_outputs', 'Missing response text'))
    body = '<h1>Judging coverage and funding</h1>' + app._campaign_banner(owner)
    body += (f"<p>{value['input_entries']:,} input entries; {value['retained_outputs']:,} saved local and hosted outputs. "
        'Every matching model answer is accounted for, not one local counterpart per hosted answer.</p>'
        '<dl>' + ''.join('<dt>' + label + f"</dt><dd>{value[field]:,}</dd>" for field, label in categories) + '</dl>'
        '<p>This review made no calls and allocated no money. Existing execution ownership is not proof of a valid verdict. '
        'Resume its original judgment artifacts instead of charging that output again. Missing responses remain unscored. '
        'Unfunded answers have not been silently removed or funded from another pool.</p>'
        '<p>The full-output handoff is saved for judging preparation. It is not the separately reviewed paired selection, '
        'and does not start paid execution.</p>'
        "<details><summary>Exact command</summary><pre>" + html.escape(' '.join(argv)) + '</pre></details>'
        + "<p><a href='/jobs/" + html.escape(params['retained_inventory_items_job'], quote=True) + "'>Open output-level details</a>"
        + " | <a href='/build?campaign_id=" + html.escape(owner, quote=True) + "'>Return to Build</a></p>")
    return _page('Judging coverage and funding', body, active='Build')


def judging_inventory_panel(params):
    body = ("<section class='card'><h2>Same-input output coverage</h2>"
        '<p>Include all local models and every saved output on the hosted input entries. '
        'Uses all completed source preparations for this collection, including earlier increments. '
        'Missing answers stay visible. This preparation makes no provider calls.</p>'
        "<div class='haiku-judging-controls'>")
    for field, label, default in (('limit', 'Input limit (0 = all hosted inputs)', '0'),
                                  ('seed', 'Input selection seed', '0')):
        body += "<label class='campaign-field'>" + label + "<input form='builder' type='number' step='1' name='retained_inventory_" + field
        body += "' value='" + html.escape(params.get('retained_inventory_' + field, default), quote=True) + "'></label>"
    body += "</div><div class='campaign-actions'><button form='builder' formaction='/build/prepare-judging-inventory'>Prepare all-output coverage</button></div>"
    if params.get('retained_inventory_job'):
        body += "<input form='builder' type='hidden' name='retained_inventory_job' value='" + html.escape(params['retained_inventory_job'], quote=True) + "'>"
        body += "<button form='builder' formaction='/build/review-judging-inventory'>Review all-output coverage</button>"
        body += "<button form='builder' formaction='/build/prepare-inventory-judging'>Prepare all-output judging funding</button>"
    if params.get('retained_inventory_items_job'):
        body += "<input form='builder' type='hidden' name='retained_inventory_items_job' value='" + html.escape(params['retained_inventory_items_job'], quote=True) + "'>"
        body += "<button form='builder' formaction='/build/review-inventory-judging'>Review all-output judging funding</button>"
    return body + '</section>'
