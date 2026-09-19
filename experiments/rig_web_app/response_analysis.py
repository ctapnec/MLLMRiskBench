"""Scientific SVM choices, with no operator-managed export or file handoffs."""
import html
import json
from uuid import uuid4

from .builder_replays import argument
from .builder_sources import source_runs
from .ui import _page
from .workspace_judge_settings import indexed_settings, judge_name


def history(app, owner):
    return app.db._query("SELECT j.* FROM jobs j JOIN campaign_members m ON "
        "m.member_kind='job' AND m.member_id=j.job_id WHERE m.campaign_id=? "
        "AND j.command='response_svm' ORDER BY j.started_at DESC",(owner,)) or []


def teachers(app, owner):
    return app.db._query("SELECT judge_id,COUNT(*) AS n FROM campaign_judgments "
        "WHERE campaign_id=? AND status='valid' AND judge_id LIKE '%haiku%' "
        "GROUP BY judge_id ORDER BY judge_id",(owner,)) or []


def select(name,label,options,selected=''):
    escape=lambda v:html.escape(str(v),quote=True)
    placeholder=('<option value="" selected>Choose '+escape(label.lower())+'</option>'
                 if len(options)>1 and selected not in {key for key,_ in options} else '')
    return '<label class="campaign-field">'+escape(label)+'<select aria-label="'+escape(label)+'" name="'+name+'" required>'+placeholder+''.join(
        '<option value="'+escape(key)+'"'+(' selected' if key==selected else '')+'>'+escape(value)+'</option>'
        for key,value in options)+'</select></label>'


def page(app, owner):
    app.db.require_workspace(owner)
    saved=app.db.workspace_definition(owner)
    campaigns=app.db.workspaces() or []
    campaign_options=[(r['campaign_id'],r['name']) for r in campaigns]
    local_options=[(r['campaign_id'],r['name']) for r in campaigns if source_runs(app.db,r['campaign_id'])]
    teacher_rows=teachers(app,owner)
    settings=indexed_settings(app.db,owner)
    teacher_options=[(r['judge_id'],judge_name(r['judge_id'],settings.get(r['judge_id']))+
        ' - condition '+str(i+1)+'; '+str(r['n'])+' valid recorded verdicts') for i,r in enumerate(teacher_rows)]
    body='<h1>Response classifier analysis</h1>'+app._campaign_banner(owner)
    body+=('<section class="card"><h2>Evaluate and save the three classifiers</h2>'
        '<p>Choose the data population and recorded teacher. The system selects saved input metadata, '
        'exports eligible text responses, evaluates the classifiers and saves reusable fitted models automatically.</p>'
        '<p>Tasks: harmful compliance, over-refusal and local/Haiku disagreement. Prompt-only, response-only and '
        'combined features are compared with grouped held-out evaluation. Small cohorts can have insufficient '
        'class support; no extra responses are generated to fill them.</p>')
    if local_options and teacher_options:
        token=app._new_launch_ticket({'campaign_id':owner},purpose='svm-study')
        body+='<form method="post" action="/analysis/start"><input type="hidden" name="launch_ticket" value="'+html.escape(token)+'">'
        body+='<div class="campaign-grid">'+select('source_campaign','Saved local input source',local_options,
            saved.get('retained_source_campaign',owner))
        body+=select('matched_campaign','Restrict to inputs assigned in',campaign_options,owner)
        body+=select('teacher','Recorded Haiku condition',teacher_options)+'</div>'
        body+='<label class="checkrow"><input type="checkbox" name="include_source" checked><span>Include matching answers from the local source campaign</span></label>'
        body+='<details class="card"><summary>Scientific analysis options</summary><div class="campaign-grid">'
        body+='<label class="campaign-field">Split seed<input name="seed" type="number" value="0" required></label>'
        body+='<label class="campaign-field">Bootstrap samples<input name="bootstrap" type="number" min="100" max="10000" value="1000" required></label></div></details>'
        body+=('<p>No target or judge calls are made. This fits recorded teacher labels, not independently established human truth. '
        'Existing campaign judgments remain unchanged.</p><div class="action-row"><button>Start classifier study</button></div></form>')
    else:
        body+=('<p class="notice amber">This study needs indexed local source inputs and valid Haiku verdicts on saved answers. '
        'Complete the relevant evaluation first; missing labels are not invented.</p>')
    body+='</section>'
    rows=history(app,owner)
    if rows:
        body+='<section class="card"><h2>Saved analyses</h2><ul>'
        for row in rows:
            argv=json.loads(row['argv'])
            label='Classifier study' if '--study' in argv else 'Classifier analysis'
            body+='<li><a href="/jobs/'+row['job_id']+'">'+label+' - '+html.escape(row['state'])+'</a>'
            from .analysis_summary import render
            if argument(argv, '--out'):
                body += render(app, argument(argv, '--out'))
            if '--study' in argv and row['state'] in {'failed','stopped','interrupted'}:
                ticket=app._new_launch_ticket(dict(campaign_id=owner,job=row['job_id']),purpose='svm-resume')
                body+='<form class="action-row" method="post" action="/analysis/resume"><input type="hidden" name="launch_ticket" value="'+ticket+'"><button>Resume unfinished analysis</button></form>'
            body+='</li>'
        body+='</ul></section>'
    return _page('Response classifier analysis',body,active='Stats')


def start(app, data):
    fields={'launch_ticket','source_campaign','matched_campaign','teacher','include_source','seed','bootstrap'}
    if set(data)-fields:raise ValueError('Unexpected analysis setting')
    ticket=app._launch_ticket_params(data.get('launch_ticket',''),purpose='svm-study')
    if ticket is None:raise ValueError('Reopen the analysis form before starting')
    owner=ticket['campaign_id'];source=data.get('source_campaign','');matched=data.get('matched_campaign','')
    for key in (owner,source,matched):app.db.require_workspace(key)
    if data.get('teacher') not in {r['judge_id'] for r in teachers(app,owner)}:
        raise ValueError('Choose a recorded Haiku condition for this campaign')
    seed=int(data.get('seed','0'));bootstrap=int(data.get('bootstrap','1000'))
    if not 100<=bootstrap<=10000:raise ValueError('Bootstrap samples must be between 100 and 10000')
    for row in history(app,owner):
        live=app.jobs.get(row['job_id'])
        if (live.state() if live else row['state']) in {'running','queued','starting'}:
            raise ValueError('This campaign already has active classifier analysis; open that job')
    rows=source_runs(app.db,source)
    if not rows:raise ValueError('Choose a saved local source campaign')
    out=(app.results_root/'rig-web'/'response-analysis'/uuid4().hex).resolve()
    values={'--source-campaign':source,'--out':str(out)}
    values.update({'--study':'on','--database':str(app.db.path),'--campaign':owner,
        '--matched-campaign':matched,'--judge-condition':data['teacher'],'--seed':str(seed),'--bootstrap':str(bootstrap)})
    if data.get('include_source')=='on' and source!=owner:values['--campaign#1']=source
    return app.start_job('response_svm',values,campaign_id=owner)


def resume(app, data):
    if set(data)!={'launch_ticket'}:raise ValueError('Use the saved analysis continuation')
    ticket=app._launch_ticket_params(data['launch_ticket'],purpose='svm-resume')
    if ticket is None:raise ValueError('Reopen the saved analysis before continuing')
    rows=history(app,ticket['campaign_id'])
    row=next((r for r in rows if r['job_id']==ticket['job']),None)
    if row is None or row['state'] not in {'failed','stopped','interrupted'}:raise ValueError('Only unfinished analysis can resume')
    argv=json.loads(row['argv'])
    if '--study' not in argv:raise ValueError('This older analysis is not an automatic study')
    out=argument(argv,'--out')
    for previous in rows:
        live=app.jobs.get(previous['job_id'])
        if argument(json.loads(previous['argv']),'--out')==out and (live.state() if live else previous['state']) in {'running','queued','starting'}:
            raise ValueError('This study is already running')
    # The original typed argv also covers interruption before selection.json
    # was written. Do not infer a new population from the current campaign.
    from .catalog import COMMANDS
    definitions={p.flag:p for p in COMMANDS['response_svm'].params}
    values={};counts={};index=3
    while index<len(argv):
        flag=argv[index]
        definition=definitions.get(flag)
        if definition is None:raise ValueError('Saved analysis arguments are unavailable')
        count=counts.get(flag,0);counts[flag]=count+1
        key=flag+(f'#{count}' if count else '')
        if definition.kind=='flag':values[key]='on';index+=1
        else:values[key]=argv[index+1];index+=2
    return app.start_job('response_svm',values,campaign_id=ticket['campaign_id'])
