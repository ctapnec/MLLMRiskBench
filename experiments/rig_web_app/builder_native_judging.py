"""Native post-hoc scoring in Build, using the existing saved-output commands."""
from __future__ import annotations

import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.hosted_retained_inputs import _descriptor

from .builder_collection import prepared_collection, collection_history, _program_paths
from .builder_replays import argument
from .catalog import build_argv
from .ui import _page


def preparation_history(app, owner, programs):
    rows = app.db._query(
        "SELECT j.* FROM jobs j JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id "
        "WHERE m.campaign_id=? AND j.command='retained_native_judge_prepare' ORDER BY j.started_at DESC,j.job_id DESC",
        (owner,))
    if rows is None:
        raise ValueError('Campaign judging history is unavailable')
    return [row for row in rows if
        _program_paths(json.loads(row['argv'])) == [p['path'] for p in programs]
        and _program_paths(json.loads(row['argv']),'--program-sha256') == [p['sha256'] for p in programs]]


def _state(app, job):
    live = app.jobs.get(job['job_id'])
    return live.state() if live is not None else job['state']


def prepare_native_judging(app, params):
    receipt = prepared_collection(app,params)
    with app._app_lock:
        history = preparation_history(app,params['campaign_id'],receipt['programs'])
        covered = set()
        for previous in history:
            if _state(app,previous) in {'running','queued','starting'}:
                app._save_build_campaign(dict(params,retained_native_judging_job=previous['job_id']))
                return SimpleNamespace(job_id=previous['job_id'])
            path = Path(argument(json.loads(previous['argv']),'--out'))/'result.json'
            if path.exists():
                prepared = json.loads(path.read_text())
                covered.update((unit['program'],unit['job']) for unit in prepared.get('units',[]))
        sources = [(p['path'],job['name']) for p in receipt['programs']
            for job in json.loads(Path(p['path']).read_text())['jobs']]
        remaining = [source for source in sources if source not in covered]
        if not remaining:
            if not history:
                raise ValueError('No source runs are available in these programs')
            app._save_build_campaign(dict(params,retained_native_judging_job=history[0]['job_id']))
            return SimpleNamespace(job_id=history[0]['job_id'])
        names = {name for _,name in remaining}
        if any(name in names for path,name in sources if (path,name) in covered):
            raise ValueError('Ambiguous source run names across programs; select these programs separately')
        values = {'--out':str((app.results_root/'rig-web'/'native-judging'/uuid4().hex).resolve())}
        Path(values['--out']).parent.mkdir(parents=True,exist_ok=True)
        for index,descriptor in enumerate(receipt['programs']):
            suffix = f'#{index}' if index else ''
            values['--program'+suffix] = descriptor['path']
            values['--program-sha256'+suffix] = descriptor['sha256']
        for index,name in enumerate(sorted(names)):
            values['--job'+(f'#{index}' if index else '')] = name
        params = app._save_build_campaign(params)
        job = app.start_job('retained_native_judge_prepare',values,campaign_id=params['campaign_id'])
        app._save_build_campaign(dict(params,retained_native_judging_job=job.job_id))
        return job


def scoring_description(source):
    stages = source['judge_cascade']['stages']
    guard = stages[1]
    device = guard.get('device') or 'automatic GPU placement'
    return (f"Rules, then {guard['model_id']} on {device}; "
        f"classifier output allowance {guard['max_new_tokens']:,} tokens")


def native_judging_review(app, params):
    owner = params.get('campaign_id','')
    app.db.require_workspace(owner)
    job = app.db.load_job(params.get('retained_native_judging_job'))
    if (job is None or job['command'] != 'retained_native_judge_prepare'
        or job['state'] not in {'complete','failed'} or job['exit_code'] not in {0,1}
        or app.db.workspace_for_job(job['job_id']) != owner):
        raise ValueError('Finish this campaign\'s native judging preparation first')
    root = Path(argument(json.loads(job['argv']),'--out'))
    path = root/'result.json'
    prepared = json.loads(path.read_text())
    if prepared.get('status') not in {'prepared','preparation_incomplete'} or not prepared.get('units'):
        raise ValueError('No complete retained source units are available for local judging; inspect preparation errors')
    descriptor = _descriptor(path)
    values = {'--preparation':str(path),'--preparation-sha256':descriptor['sha256'],'--out':str(root/'judgments')}
    if params.get('retained_native_verify_model') == 'on':
        values['--verify-model-sha256'] = 'on'
    if params.get('retained_native_verify_artifacts') == 'on':
        values['--verify-artifact-sha256'] = 'on'
    history = collection_history(app,owner,[str(path)],command='retained_native_judge_execute',input_flag='--preparation')
    if history is not None:
        old = json.loads(history['argv'])
        values['--out'] = argument(old,'--out')
        if ('--verify-model-sha256' in old) != ('--verify-model-sha256' in values):
            raise ValueError('Keep the original model-verification setting when resuming local judging')
    ticket = app._new_launch_ticket(dict(campaign_id=owner,values=json.dumps(values),
        previous_job=history['job_id'] if history is not None else ''),purpose='matched-native-judge')
    failed = sum(source['assigned'] for source in prepared.get('failed',[]))
    rows = ''.join('<tr><td>'+html.escape(source['target'])+'</td><td>'+html.escape(source['job'])
        +f"</td><td>{source['assigned']:,}</td><td>"+html.escape(scoring_description(source))+'</td></tr>'
        for source in prepared['units'])
    body = '<h1>Review local judging</h1>'+app._campaign_banner(owner)
    body += (f"<p>{prepared['outputs']:,} retained outputs in {len(prepared['units']):,} prepared source units. "
        "The original source criteria and scoring cascade are preserved; later draft edits do not replace them. "
        "Existing judgments and saved checkpoints are restored before new scoring. This count is not a forecast "
        "of new classifier calls. No target is regenerated and no hosted provider is called.</p>"
        "<p>Judging preserves the saved placement policy, including automatic GPU placement. "
        "Avoid starting it on GPUs occupied by another local task. "
        "Haiku assessment is a separate output-specific stage.</p>"
        +(f"<p class='notice amber'>{failed:,} assigned outputs are not prepared. Their source errors remain "
          "visible and this judging subset cannot complete the whole campaign.</p>" if failed else '')
        +"<div class='scroll'><table style='min-width:54rem'><tr><th>Target model</th><th>Source run</th><th>Outputs</th>"
        "<th>Saved scoring condition</th></tr>"+rows+'</table></div>'
        +"<details><summary>Exact command</summary><pre>"+html.escape(' '.join(build_argv('retained_native_judge_execute',values)))
        +"</pre></details><form class='action-row' method='post' action='/build/judge-retained-local'>"
        "<input type='hidden' name='launch_ticket' value='"+html.escape(ticket,quote=True)+"'>"
        '<button type="submit">Start or resume local judging</button></form>'
        +"<p><a href='/build?campaign_id="+owner+"'>Return to Build</a></p>")
    return _page('Review local judging',body,active='Build')


def judge_retained_local(app, form):
    if set(form) != {'launch_ticket'}:
        raise ValueError('Review the retained local judging selection first')
    params = app._launch_ticket_params(form['launch_ticket'],purpose='matched-native-judge')
    if params is None:
        raise ValueError('Local judging review expired or was already used')
    values,owner = json.loads(params['values']),params['campaign_id']
    with app._app_lock:
        history = collection_history(app,owner,[values['--preparation']],
            command='retained_native_judge_execute',input_flag='--preparation')
        if (history['job_id'] if history is not None else '') != params['previous_job']:
            raise ValueError('This judging selection has a newer launch; open that job before continuing')
        if history is not None:
            if _state(app,history) in {'running','queued','starting'}:
                raise ValueError('This local judging selection is already active')
        return app.start_job('retained_native_judge_execute',values,campaign_id=owner)


def native_judging_panel(app, params):
    if not params.get('retained_programs_job'):
        return ''
    job = params.get('retained_native_judging_job','')
    body = ("<section class='card' id='retained-local-judging'><h2>Judge retained outputs locally</h2>"
        "<p>Prepare the saved collection outputs for their original source-specific or rules/guardrail scoring. "
        "Preparation makes no target or judge calls. Incomplete source runs remain listed as unprepared.</p>"
        "<p>Preparation reuses active or already prepared work. After more source runs finish, it adds only "
        "runs not previously prepared. Resume earlier judging from the selection below or from Jobs.</p>"
        "<button form='builder' formaction='/build/prepare-native-judging'>Prepare remaining source runs</button>")
    if job:
        escaped = html.escape(job,quote=True)
        try:
            receipt = prepared_collection(app,params)
        except (ValueError,OSError,KeyError):
            return body+"<p>Finish the selected collection preparation to review its judging. Previous jobs remain in Jobs.</p></section>"
        history = preparation_history(app,params['campaign_id'],receipt['programs'])
        body += "<label class='campaign-field separated-field'>Saved judging preparation<select form='builder' name='retained_native_judging_job'>"
        body += ''.join("<option value='"+html.escape(row['job_id'],quote=True)+"'"+(
            ' selected' if row['job_id']==job else '')+'>'+html.escape(row['job_id']+' - '+_state(app,row))+'</option>'
            for row in history)
        body += '</select></label>'
        body += "<p><a href='/jobs/"+escaped+"'>Open judging preparation and source errors</a></p>"
        for field,label in [('retained_native_verify_model','Full model checksum revalidation'),
            ('retained_native_verify_artifacts','Full result-file checksum revalidation')]:
            body += "<label class='checkrow'><input type='checkbox' form='builder' name='"+field+"'"+(
                ' checked' if params.get(field)=='on' else '')+'><span>'+label+' (optional)</span></label>'
        body += "<button form='builder' formaction='/build/review-native-judging'>Review local judging</button>"
    return body+'</section>'
