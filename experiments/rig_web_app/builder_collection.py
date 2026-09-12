"""Review and launch saved Build programs through the existing collection command."""
from __future__ import annotations

import html
import json
from pathlib import Path
import subprocess
from uuid import uuid4

from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


def _program_paths(argv, input_flag='--program'):
    return [argv[index+1] for index,flag in enumerate(argv[:-1]) if flag == input_flag]


def collection_history(app, owner, paths, *, command='hosted_campaign_execute', input_flag='--program'):
    rows = app.db._query(
        "SELECT j.* FROM jobs j JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id "
        "WHERE m.campaign_id=? AND j.command=? ORDER BY j.started_at DESC,j.job_id DESC",
        (owner,command))
    if rows is None:
        raise ValueError('Campaign collection history is unavailable')
    for row in rows:
        if _program_paths(json.loads(row['argv']),input_flag) == paths:
            return row
    return None


def prepared_collection(app, params):
    owner = params.get('campaign_id','')
    app.db.require_workspace(owner)
    argv = completed_argv(app,params.get('retained_programs_job'),owner,'hosted_campaign_prepare')
    receipt = json.loads((Path(argument(argv,'--out-root'))/'receipt.json').read_text())
    if receipt.get('status') != 'prepared_no_generation_calls' or not receipt.get('programs'):
        raise ValueError('Complete counted collection preparation first')
    return receipt


def collection_review(app, params):
    owner = params.get('campaign_id','')
    receipt = prepared_collection(app,params)
    workers = params.get('retained_collection_workers','2') or '2'
    if workers not in {str(number) for number in range(1,9)}:
        raise ValueError('Choose 1 to 8 collection workers per provider')
    project = app.repo_root.resolve()
    revision = subprocess.check_output(['git','-C',str(project),'rev-parse','HEAD'],text=True).strip()
    values = {'--budget-root':str(Path(receipt['budget']['path']).parent),
        '--budget-plan-sha256':receipt['budget']['sha256'],'--project-root':str(project),
        '--expected-commit':revision,'--workers-per-provider':workers}
    rows = []
    for index,descriptor in enumerate(receipt['programs']):
        suffix = f'#{index}' if index else ''
        values['--program'+suffix] = descriptor['path']
        values['--program-sha256'+suffix] = descriptor['sha256']
        program = json.loads(Path(descriptor['path']).read_text())
        rows.append((program['target'],len(program['requests']),program['max_output_tokens'],
            sum(request['bound_microusd'] for request in program['requests'].values())))
    parent = (app.results_root/'rig-web'/'hosted-collections').resolve()
    parent.mkdir(parents=True,exist_ok=True)
    values['--out'] = str(parent/uuid4().hex)
    history = collection_history(app,owner,[row['path'] for row in receipt['programs']])
    if history is not None:
        old = json.loads(history['argv'])
        for flag in ('--budget-root','--budget-plan-sha256','--project-root','--expected-commit'):
            if argument(old,flag) != values[flag]:
                raise ValueError('This collection needs a reviewed revision or budget recovery; its previous settings cannot change silently')
        values['--resume-from'] = argument(old,'--out')
    action = 'Continue saved collection' if history is not None else 'Start prepared collection'
    ticket = app._new_launch_ticket({'campaign_id':owner,'values':json.dumps(values),
        'previous_job':history['job_id'] if history is not None else ''},purpose='matched-collection')
    body = '<h1>Review prepared collection</h1>'+app._campaign_banner(owner)
    body += ("<p>This review uses the completed preparation's saved inputs and model settings, not later draft edits. "
        "Providers run concurrently with "+workers+" worker(s) each. Collection makes paid target calls; "
        "local and Haiku judging are separate stages. Existing transport retries, spending limits, "
        "readiness and admission checks remain active. No automatic answer retries are added.</p>"
        "<div class='scroll'><table><tr><th>Prepared model</th><th>Assigned inputs</th>"
        "<th>Output allowance</th><th>Initial-attempt ceiling (USD)</th></tr>"
        +''.join('<tr><td>'+html.escape(model)+f'</td><td>{count:,}</td><td>{tokens:,}</td><td>${cost/1e6:,.6f}</td></tr>'
                 for model,count,tokens,cost in rows)+'</table></div>'
        '<p>These ceilings are not reported charges. HTTP retries and judging use the shared prepared spending plan. '
        'A continuation restores completed jobs and resumes eligible checkpoints; it does not select replacement inputs.</p>')
    if history is not None:
        body += "<p>Previous collection: <a href='/jobs/"+history['job_id']+"'>Open job and retained results</a></p>"
    body += ("<details><summary>Exact command</summary><pre>"+html.escape(' '.join(build_argv('hosted_campaign_execute',values)))
        +"</pre></details><form method='post' action='/build/collect-prepared'>"
        "<input type='hidden' name='launch_ticket' value='"+html.escape(ticket,quote=True)+"'>"
        "<button type='submit'>"+action+"</button></form>"
        "<p><a href='/build?campaign_id="+owner+"'>Return to Build</a></p>")
    return _page('Review prepared collection',body,active='Build')


def collect_prepared(app, form):
    if set(form) != {'launch_ticket'}:
        raise ValueError('Review the prepared collection before starting it')
    params = app._launch_ticket_params(form['launch_ticket'],purpose='matched-collection')
    if params is None:
        raise ValueError('Collection review expired or was already used; reopen the review')
    values = json.loads(params['values'])
    owner = params['campaign_id']
    # Use the existing console lock and persisted job index, not a new scheduler.
    # Two reviews opened in separate tabs must not launch the same paid work.
    with app._app_lock:
        history = collection_history(app,owner,_program_paths(build_argv('hosted_campaign_execute',values)))
        previous = history['job_id'] if history is not None else ''
        if previous != params['previous_job']:
            raise ValueError('This collection has a newer launch; open that job before continuing')
        if history is not None:
            live = app.jobs.get(previous)
            state = live.state() if live is not None else history['state']
            if state in {'running','queued','starting'}:
                raise ValueError('This collection is already active; open its job to monitor it')
        return app.start_job('hosted_campaign_execute',values,campaign_id=owner)


def collection_panel(params):
    if not params.get('retained_programs_job'):
        return ''
    value = html.escape(params.get('retained_collection_workers','2'),quote=True)
    return ("<section class='card'><h2>Collect prepared inputs</h2>"
        "<p>Review the saved model assignments and costs, then start or continue the existing provider-parallel collection. "
        "Later draft edits do not change a prepared collection. Judging follows separately.</p>"
        "<label class='campaign-field'>Workers per provider<input type='number' min='1' max='8' step='1' "
        "form='builder' name='retained_collection_workers' value='"+value+"'></label>"
        "<button form='builder' formaction='/build/review-collection'>Review prepared collection</button></section>")
