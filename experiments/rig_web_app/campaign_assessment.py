"""Campaign-level assessment independent of how its answers were collected."""
from decimal import Decimal, InvalidOperation
import html
import json
import os
from pathlib import Path
from uuid import uuid4

from .builder_haiku_judging import _choices
from .builder_replays import argument
from .ui import _page


def panel(owner):
    if not owner:return ''
    return '<section class="card" id="campaign-assessment"><h2>Evaluate saved campaign answers</h2><p>Fill missing local or Haiku verdicts on indexed answers, regardless of whether collection used Build, the CLI or a matched-input campaign. Existing valid verdicts are retained.</p><a href="/assessment?campaign_id='+html.escape(owner)+'">Choose saved-output assessment</a></section>'


def history(app, owner):
    return app.db._query("SELECT j.* FROM jobs j JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id WHERE m.campaign_id=? AND j.command='campaign_assess' ORDER BY j.started_at DESC",(owner,)) or []


def page(app, owner):
    app.db.require_workspace(owner)
    ticket=app._new_launch_ticket(dict(campaign_id=owner),purpose='campaign-assessment')
    body='<h1>Evaluate saved answers</h1>'+app._campaign_banner(owner)
    body+='<section class="card"><h2>Fill missing judgments</h2><p>Select the evaluator and workload. Saved prompts and each model\'s own answer are selected automatically; generation is never repeated. Existing valid verdicts for the selected evaluator are skipped.</p>'
    body+='<form method="post" action="/assessment/prepare"><input type="hidden" name="launch_ticket" value="'+ticket+'"><div class="campaign-grid">'
    body+='<label class="campaign-field">Evaluator<select name="kind" aria-label="Evaluator"><option value="local">Original local rules and guardrail</option><option value="haiku">Haiku</option></select></label>'
    body+='<label class="campaign-field">Maximum pending answers (0 = all)<input name="limit" type="number" min="0" value="0" required></label>'
    choices=_choices(app)
    body+='<label class="campaign-field" data-haiku-option>Haiku judge<select name="judge_model" aria-label="Haiku judge">'+''.join('<option>'+html.escape(model)+'</option>' for model in choices)+'</select></label>'
    body+='<label class="campaign-field" data-haiku-option>Maximum assessment spending (USD)<input name="cost" type="number" min="0.000001" step="0.000001" placeholder="Choose a spending limit"></label></div>'
    body+='<p>Common-metric evaluable answers only. Images use their saved text proxy, not image pixels. Missing answers, source-specific tasks and missing source context are listed separately. Haiku uses 512 output tokens, no answer retries and three eligible HTTP retries.</p><div class="action-row"><button>Prepare assessment and review</button></div></form></section>'
    body+='''<script>(()=>{const kind=document.querySelector('[name=kind]');const update=()=>{document.querySelectorAll('[data-haiku-option]').forEach(e=>{e.hidden=kind.value!=='haiku';e.querySelector('input,select').disabled=e.hidden;});};kind.addEventListener('change',update);update();})();</script>'''
    rows=history(app,owner)
    if rows:
        body+='<section class="card"><h2>Prepared assessments and progress</h2><ul>'
        for row in rows:
            argv=json.loads(row['argv'])
            if '--execute' in argv:continue
            body+='<li><a href="/assessment/review?campaign_id='+owner+'&job='+row['job_id']+'">Saved assessment - '+html.escape(row['state'])+'</a></li>'
        body+='</ul></section>'
    return _page('Evaluate saved answers',body,active='Campaigns')


def prepare(app,data):
    if set(data)-{'launch_ticket','kind','limit','judge_model','cost'}:raise ValueError('Unexpected assessment field')
    ticket=app._consume_launch_ticket(data.get('launch_ticket',''),purpose='campaign-assessment')
    if ticket is None:raise ValueError('Reopen the assessment form')
    owner=ticket[0]['campaign_id'];kind=data.get('kind');limit=int(data.get('limit','0'))
    if kind not in {'local','haiku'} or limit<0:raise ValueError('Choose an evaluator and a nonnegative answer limit')
    values=prepare_values(app,owner,kind=kind,limit=limit,judge=data.get('judge_model',''),cost=data.get('cost',''))
    return app.start_job('campaign_assess',values,campaign_id=owner)


def prepare_values(app,owner,*,kind,limit=0,judge='',cost='',root=None):
    app.db.require_workspace(owner)
    root=root or (app.results_root/'rig-web'/'campaign-assessment'/uuid4().hex).resolve()
    root.mkdir(parents=True,mode=0o700)
    values={'--database':str(app.db.path),'--campaign':owner,'--results-root':str(app.results_root),
            '--kind':kind,'--limit':str(limit),'--out':str(root)}
    if os.environ.get('URA_MODEL_STORE'):
        values['--model-store']=os.environ['URA_MODEL_STORE']
    if kind=='haiku':
        if judge not in _choices(app):raise ValueError('Choose a configured Haiku judge')
        try:
            cost=Decimal(cost)*1_000_000
            if not cost.is_finite() or cost<=0 or cost!=cost.to_integral_value():raise ValueError('cost')
        except (InvalidOperation,ValueError):raise ValueError('Choose a positive USD ceiling with at most six decimal places')
        _,_,_,configs=app._selected_api_config_snapshot(dict(api=judge,judges='',mode='measured'))
        config=dict(configs[judge],max_tokens=512)
        for name,value in [('api.json',{judge:config}),('pricing.json',app._load_registry('pricing.json','rig/pricing.example.json'))]:
            app._write_private_workflow_file(root/name,(json.dumps(value)+'\n').encode())
        values.update({'--judge-model':judge,'--max-cost-microusd':str(int(cost)),
                       '--api-config':str(root/'api.json'),'--pricing-config':str(root/'pricing.json')})
    return values


def reviewed(app,owner,job_id):
    row=next((r for r in history(app,owner) if r['job_id']==job_id),None)
    if row is None:raise ValueError('Choose an assessment belonging to this campaign')
    argv=json.loads(row['argv'])
    root=Path(argument(argv,'--out')).resolve()
    if not root.is_relative_to(app.results_root.resolve()):raise ValueError('Assessment output is unavailable')
    return row,root


def review(app,owner,job_id):
    row,root=reviewed(app,owner,job_id)
    body='<h1>Review saved-output assessment</h1>'+app._campaign_banner(owner)
    body+='<p><a href="/jobs/'+job_id+'">Preparation progress and error details</a></p>'
    live=app.jobs.get(job_id);state=live.state() if live else row['state']
    if state in {'running','queued','starting'}:
        return _page('Preparing assessment',body+'<p role="status">Connecting saved answers and calculating assessment costs...</p><script>setTimeout(()=>window.uraBusy.reload(),3000);</script>',active='Campaigns')
    if not (root/'result.json').is_file():
        return _page('Assessment needs attention',body+'<p>Preparation did not complete. Open its job to inspect the cause; no assessment calls were made.</p>',active='Campaigns')
    result=json.loads((root/'result.json').read_text())
    body+='<section class="card"><h2>'+str(result['selected_outputs'])+' answers selected</h2><p>No target generation will be repeated.</p>'
    body+='<ul>'+''.join('<li>'+html.escape(key.replace('_',' '))+': '+str(value)+'</li>' for key,value in result['dispositions'].items())+'</ul>'
    body+='<p>Missing source context: '+str(len(result['unavailable']))+'. Missing responses remain in campaign coverage, not the judging denominator.</p>'
    if result['kind']=='haiku':
        for key,label in [('first_attempt_bound_microusd','First-attempt conservative bound'),('retry_inclusive_bound_microusd','Including all eligible HTTP retries'),('max_cost_microusd','Your spending ceiling')]:
            body+='<p>'+label+': $'+f"{result.get(key,0)/1e6:.4f}"+'</p>'
    if result['status']=='over_budget':
        body+='<p class="notice amber">The selected workload exceeds your ceiling. Return to assessment and reduce the answer limit or choose a different spending ceiling.</p>'
    elif not result['selected_outputs']:
        body+='<p>No eligible pending answers. Existing valid judgments have not been repeated.</p>'
    elif (root/'completion.json').exists():
        body+='<p>Assessment complete.</p><a href="/campaigns/'+owner+'?section=judging">View campaign judgments</a>'
    else:
        active=next((j for j in history(app,owner) if '--execute' in json.loads(j['argv']) and argument(json.loads(j['argv']),'--out')==str(root) and (app.jobs[j['job_id']].state() if j['job_id'] in app.jobs else j['state']) in {'running','queued','starting'}),None)
        if active:
            body+='<a href="/jobs/'+active['job_id']+'">Open active assessment and Stop job</a>'
        else:
            ticket=app._new_launch_ticket(dict(campaign_id=owner,job=job_id),purpose='campaign-assessment-start')
            body+='<form class="action-row" method="post" action="/assessment/start"><input type="hidden" name="launch_ticket" value="'+ticket+'"><button>Start or resume assessment</button></form>'
    body+='</section><p><a href="/assessment?campaign_id='+owner+'">Back to campaign assessment</a></p>'
    return _page('Review assessment',body,active='Campaigns')


def launch(app,data):
    if set(data)!={'launch_ticket'}:raise ValueError('Review the saved assessment first')
    ticket=app._consume_launch_ticket(data['launch_ticket'],purpose='campaign-assessment-start')
    if ticket is None:raise ValueError('This assessment start was already used or expired')
    owner=ticket[0]['campaign_id'];row,root=reviewed(app,owner,ticket[0]['job'])
    result=json.loads((root/'result.json').read_text())
    if result['status']!='prepared' or not result['selected_outputs'] or (root/'completion.json').exists():
        raise ValueError('This assessment has no pending reviewed work')
    for previous in history(app,owner):
        live=app.jobs.get(previous['job_id'])
        if (live.state() if live else previous['state']) in {'running','queued','starting'}:
            raise ValueError('An assessment is already active in this campaign; open its existing job')
    return app.start_job('campaign_assess',{'--execute':'on','--database':str(app.db.path),'--out':str(root)},campaign_id=owner)
