"""Campaign-aware human study setup, separate from the blinded rater wizard."""
import csv
import html
import json
import secrets
from pathlib import Path

from .ui import _page

ETHICS_CHOICES = {'pending': 'Not decided yet - prepare a sample only',
    'approved': 'Approved by the responsible institution / supervisor',
    'exempt': 'Exemption confirmed by the responsible institution',
    'not_required': 'Formal review not required, as confirmed by the responsible institution'}
COMPENSATION_CHOICES = {'unpaid': 'Voluntary, unpaid participation',
    'paid': 'Paid participation', 'credit': 'Academic credit', 'other': 'Other agreed arrangement'}


def select_field(name, label, choices):
    return ("<label>"+html.escape(label)+"<select name='"+name+"' required><option value=''>Choose...</option>"
        + ''.join("<option value='"+key+"'>"+html.escape(value)+"</option>" for key,value in choices.items())
        + "</select></label>")


def arrangements(data):
    """Keep legacy submissions readable; new UI records explicit actual choices."""
    result={k:data.get(k,'').strip() for k in ('ethics','compensation','stop_contact','consent')}
    if 'ethics_status' in data:
        status=data['ethics_status']
        if status not in ETHICS_CHOICES: raise ValueError('Choose the actual ethics determination status')
        if status!='pending' and not result['ethics']: raise ValueError('Record who made the determination and its date')
        result.update(ethics_status=status,ethics=ETHICS_CHOICES[status]+(': '+result['ethics'] if result['ethics'] else ''))
    if 'compensation_type' in data:
        kind=data['compensation_type']
        if kind not in COMPENSATION_CHOICES: raise ValueError('Choose the participation arrangement')
        result.update(compensation_type=kind,compensation=COMPENSATION_CHOICES[kind]+': '+result['compensation'])
    return result


def sources(app, campaign):
    app.db.require_workspace(campaign)
    rows = app._human_store().sources(campaign)
    result = [dict(id='scope-'+r['id'], name=r['name'], **r['metadata']) for r in rows]
    indexed = app.db._query("SELECT 1 FROM campaign_assignments WHERE campaign_id=? "
        "AND evidence_class='measured' AND response_id IS NOT NULL LIMIT 1", (campaign,))
    if indexed:
        result.insert(0, dict(id='campaign-index', name='All indexed measured campaign outputs',
            source_kind='campaign_index', results=str(app.results_root)))
    # Terminal result directories only. Do not scan corpora or reopen artifacts
    # when displaying a page. Imported historical campaigns use registered scopes.
    runs = app.db._query("SELECT r.job_id,r.out_dir FROM runs r JOIN campaign_members m "
        "ON m.member_kind IN ('job','external') AND m.member_id=r.job_id "
        "WHERE m.campaign_id=? AND r.command='run_matrix' AND r.exit_code=0 ORDER BY r.created_at DESC", (campaign,))
    if runs is None: raise ValueError('Campaign result index is unavailable')
    known = {r['results'] for r in result}
    for row in runs:
        if row['out_dir'] and row['out_dir'] not in known:
            result.append(dict(id='run-'+row['job_id'], name='Completed run: '+row['job_id'], results=row['out_dir'],
                               historical_code_repository=str(app.repo_root), judge_configuration_sha256=''))
            known.add(row['out_dir'])
    return result


SETUP_SCRIPT = r"""<script>
document.querySelectorAll('[data-study-wizard]').forEach(form=>{
 const panels=Array.from(form.querySelectorAll('[data-study-step]')),nav=form.querySelector('.review-steps');let current=0;
 const buttons=panels.map((p,i)=>{const b=document.createElement('button');b.type='button';b.textContent=(i+1)+'. '+p.dataset.studyStep;b.onclick=()=>go(i);nav.append(b);return b;});
 const back=form.querySelector('[data-study-back]'),next=form.querySelector('[data-study-next]'),submit=form.querySelector('[type=submit]');
 function valid(index){for(const e of panels[index].querySelectorAll('input,select,textarea')){if(!e.checkValidity()){e.reportValidity();return false;}}return true;}
 function render(){panels.forEach((p,i)=>p.hidden=i!==current);buttons.forEach((b,i)=>{if(i===current)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});back.disabled=current===0;next.hidden=current===panels.length-1;submit.hidden=current!==panels.length-1;
 const summary=form.querySelector('[data-study-summary]');summary.replaceChildren();for(const name of ['source','name','mode','clusters']){const e=form.elements[name];const p=document.createElement('p');p.textContent=({source:'Saved results',name:'Study',mode:'Rubric',clusters:'Requested source clusters'})[name]+': '+(e.tagName==='SELECT'?e.selectedOptions[0]?.textContent:e.value);summary.append(p);}}
 function go(i){if(i>current){for(let j=current;j<i;j++)if(!valid(j))return;}current=i;render();panels[i].querySelector('h2').focus();}
 back.onclick=()=>go(current-1);next.onclick=()=>go(current+1);form.addEventListener('submit',e=>{for(let i=0;i<panels.length;i++){if(!valid(i)){e.preventDefault();current=i;render();return;}}});render();
});</script>"""


def setup_body(app, campaign, field, *, kind='personal'):
    escape = lambda value: html.escape(str(value), quote=True)
    if not campaign:
        return "<section class='review-card'><h2>Choose a campaign</h2><p>Open an existing local or API campaign, including a finished campaign, to review its saved outputs.</p><div class='review-actions'>" + ''.join(
            "<a class='button ghost' href='/human-evaluation?campaign_id="+r['campaign_id']+"'>"+escape(r['name'])+"</a>" for r in app.db.workspaces() or []) + '</div></section>'
    choices = sources(app,campaign)
    options = "<option value=''>Choose saved results</option>"+''.join("<option value='"+escape(r['id'])+"'>"+escape(r['name'])+"</option>" for r in choices)
    hidden = "<input type='hidden' name='campaign_id' value='"+escape(campaign)+"'>"
    navigation = ("<div class='review-actions'><a class='button"+('' if kind=='personal' else ' ghost')
        +"' href='/human-evaluation?campaign_id="+escape(campaign)+"'>Review saved answers</a>"
        "<a class='button"+('' if kind=='independent' else ' ghost')+"' href='/human-evaluation?campaign_id="
        +escape(campaign)+"&amp;kind=independent'>Independent two-rater study</a></div>")
    if kind != 'independent':
        options = options.replace("value='campaign-index'", "value='campaign-index' selected")
        body = navigation + ("<section class='review-card'><h2>Review saved answers</h2>"
            "<p>Read the actual prompt, images and saved answer, then record your own evaluation in the guided form. "
            "Personal review needs no reviewer enrollment, qualification scores or study-arrangement fields. "
            "Its decisions remain labelled personal, not independent research ratings.</p>"
            "<form method='post' action='/human-evaluation/prepare-personal'>"+hidden
            +"<label>Saved results<select name='source' required>"+options+"</select></label>"
            +field('name','Review name','My review of saved answers')
            +"<div class='review-grid'><label>Rubric<select name='mode'><option value='common'>Common safety dimensions</option>"
            "<option value='source_task'>Source-task classification</option></select></label>"
            +field('clusters','Source clusters',0 if any(r.get('source_kind')=='campaign_index' for r in choices) else 20,'number')
            +"</div><p>For indexed campaign outputs, 0 selects the minimum-coverage sample. It does not mean zero answers. "
            "Whole clusters stay together; inspect the actual number of answers before opening the form.</p>"
            "<label class='review-check'><input type='checkbox' name='acknowledge' value='1' required>"
            "<span>I am ready to view potentially harmful saved content.</span></label>"
            "<button>Prepare answers for review</button></form><p>This prepares saved content only. No model or judge is called.</p></section>")
        drafts = [r for r in app._human_store().preparations(campaign) if r['value']['metadata'].get('review_kind')=='personal']
        if drafts:
            body += "<section class='review-card'><h2>Prepared personal reviews</h2><ul>"+''.join(
                "<li><a href='/human-evaluation/preparations/"+r['id']+"'>"+escape(r['value']['name'])+"</a></li>" for r in drafts)+"</ul></section>"
        return body
    body = "<section class='review-card'><h2>New human evaluation</h2><p>Use saved results from this campaign. Collection can already be finished. No model is rerun and no API credit is spent.</p><ol><li><strong>You, the study operator:</strong> choose saved answers, inspect the sample size and record participation arrangements.</li><li><strong>You:</strong> assign two independent raters and a separate adjudicator, then share each person's private review link.</li><li><strong>Each reviewer:</strong> read the prompt and answer, choose ratings in the guided review, then submit.</li></ol><p>This page sets up the study; it is not the rating form.</p><form method='post' action='/human-evaluation/prepare-study' data-study-wizard novalidate>"+hidden
    body += "<div class='review-steps' role='navigation' aria-label='Study setup steps'></div><section class='review-step' data-study-step='Saved results'><h2 tabindex='-1'>Choose the saved result set</h2><label>Saved results<select name='source' required>"+options+"</select></label><p class='review-help'>A result set may cover one run or a registered combined analysis. Its label describes the scope; choosing it does not imply every campaign output is eligible. Missing outputs remain in campaign statistics.</p></section>"
    body += "<section class='review-step' data-study-step='Sample'><h2 tabindex='-1'>Define the assessment sample</h2>"+field('name','Study name')+"<div class='review-grid'><label>Rubric<select name='mode'><option value='common'>Common safety dimensions</option><option value='source_task'>Source-task classification</option></select></label>"+field('clusters','Source clusters',0 if any(r.get('source_kind')=='campaign_index' for r in choices) else 20,'number')+"</div><p>For indexed campaign outputs, zero selects the smallest sample produced by the deterministic coverage procedure. For a registered result set, enter a positive count. Whole selected clusters stay together across models and conditions. The prepared sample shows the actual output count and two-rater workload before a study is created; a broad campaign can require substantial review.</p><details><summary>Media lookup for imported results</summary>"+field('media_index','Existing retained media index (optional)',required=False)+"<p>Leave blank to use the selected result set's registered index. This connects saved image identities to their existing local files; it does not download media.</p></details></section>"
    body += "<section class='review-step' data-study-step='Arrangements'><h2 tabindex='-1'>Record the actual study arrangements</h2>"+select_field('ethics_status','Ethics determination',ETHICS_CHOICES)+field('ethics','Who made the determination, and when? (leave blank if not decided)',required=False)+"<p class='review-help'>Choose the decision actually received, not the one you expect. Not decided yet allows sample preparation and workload inspection, but not reviewer enrollment.</p>"+select_field('compensation_type','Participation arrangement',COMPENSATION_CHOICES)+field('compensation','Expected time, any payment / credit, and recorded-data withdrawal terms')+field('stop_contact','Contact person and email for questions or stopping participation')+"<label>Information shown before a reviewer consents<textarea name='consent' required placeholder='Explain the study purpose, sensitive content, voluntary participation, breaks, and how to withdraw.'></textarea></label><p>Only actual decisions and participation terms belong here. These choices do not grant institutional approval or constitute a reviewer's consent.</p></section>"
    body += "<section class='review-step' data-study-step='Review'><h2 tabindex='-1'>Review sample preparation</h2><div data-study-summary></div><label class='review-check'><input type='checkbox' name='acknowledge' value='1' required><span>I understand the sample contains potentially harmful content and will be shared only with the assigned reviewers.</span></label><p>Preparation runs in Jobs. You will inspect the workload before creating the study and assigning raters.</p></section><div class='review-wizard-footer'><button type='button' class='ghost' data-study-back>Back</button><button type='button' data-study-next>Next</button><button type='submit'>Prepare review sample</button></div></form></section>"
    drafts=app._human_store().preparations(campaign)
    if drafts:
        body += "<section class='review-card'><h2>Sample preparations</h2><ul>"+''.join("<li><a href='/human-evaluation/preparations/"+r['id']+"'>"+escape(r['value']['name'])+"</a></li>" for r in drafts)+"</ul></section>"
    body += "<details class='review-card'><summary>Register an existing analysis result set</summary><p>For imported historical campaigns, associate their existing combined analysis once. This neither copies nor regenerates responses. Normal completed runs are listed automatically.</p><form method='post' action='/human-evaluation/register-source'>"+hidden+field('name','Result-set name')+field('results','Existing analysis results directory')+field('historical_code_repository','Historical code repository (if needed)',required=False)+field('judge_configuration_sha256','Historical judge configuration reference (if needed)',required=False)+"<button>Register saved results</button></form></details>"
    return navigation+body+SETUP_SCRIPT


def setup_route(app, method, path, data, style):
    store=app._human_store()
    if method=='POST' and path=='/human-evaluation/register-source':
        owner=data.get('campaign_id','');app.db.require_workspace(owner)
        store.register_source(campaign=owner, **{k:data.get(k,'') for k in ('name','results','historical_code_repository','judge_configuration_sha256','media_index')})
        return 303,'/human-evaluation?campaign_id='+owner,b''
    if method=='POST' and path in {'/human-evaluation/prepare-study','/human-evaluation/prepare-personal'}:
        personal = path.endswith('/prepare-personal')
        owner=data.get('campaign_id',''); choices=sources(app,owner)
        source=next((r for r in choices if r['id']==data.get('source')),None)
        if source is None: raise ValueError('Choose saved results from this campaign')
        if data.get('acknowledge')!='1': raise ValueError('Acknowledge sensitive content before preparing a sample')
        indexed = source.get('source_kind')=='campaign_index'
        if data.get('mode') not in {'common','source_task'} or int(data.get('clusters','0')) < (0 if indexed else 1):
            raise ValueError('Choose a rubric and cluster count; zero selects minimum coverage for indexed campaigns')
        metadata = dict(review_kind='personal') if personal else arrangements(data)
        if not data.get('name','').strip() or (not personal and any(not metadata[k] for k in ('ethics','compensation','stop_contact','consent'))):
            raise ValueError('Complete the study name and actual review arrangements')
        if not personal and not data.get('compensation','').strip(): raise ValueError('Record participation time and withdrawal terms')
        directory=store.root/('preparation-'+secrets.token_hex(8));directory.mkdir(mode=0o700)
        params={'--results':source['results'],'--output':str(directory/'sample.csv'),'--acknowledge-sensitive-content':'1',
                '--prepare-source-task' if data['mode']=='source_task' else '--prepare':data['clusters']}
        for key in ('historical_code_repository','judge_configuration_sha256'):
            if source.get(key):params['--'+key.replace('_','-')]=source[key]
        supplied_index=data.get('media_index','').strip() or source.get('media_index','')
        if supplied_index: params['--media-index']=str(store._path(supplied_index))
        if indexed:
            params={'--database':str(app.db.path),'--campaign':owner,'--results-root':str(app.results_root),
                '--output':str(directory/'sample.csv'),'--mode':data['mode'],'--clusters':data['clusters'],
                '--acknowledge-sensitive-content':'1',**({'--media-index':params['--media-index']} if '--media-index' in params else {})}
        job=app.start_job('human_review_campaign' if indexed else 'human_audit',params,campaign_id=owner)
        metadata.update({k:source.get(k,'') for k in ('results','historical_code_repository','judge_configuration_sha256','media_index')})
        if indexed:
            metadata.update(source_kind='campaign_index',snapshot=str(directory/'sample.SNAPSHOT.json.gz'))
        if data.get('media_index','').strip(): metadata['media_index']=str(store._path(data['media_index']))
        key=store.save_preparation(owner,job.job_id,dict(name=data['name'],mode=data['mode'],prepared=str(directory/'sample.csv'),metadata=metadata))
        return 303,'/human-evaluation/preparations/'+key,b''
    if path.startswith('/human-evaluation/preparations/'):
        key=path.rsplit('/',1)[-1];draft=store.preparation(key);job=app.db.load_job(draft['job'])
        if job is None:raise ValueError('The sample preparation job is unavailable')
        live=app.jobs.get(draft['job'])
        if live is not None and live.process is not None:
            # Read one process result, not its new terminal state paired with
            # an older SQLite exit code that the watcher has not saved yet.
            exit_code=live.exit_code()
            state='running' if exit_code is None else 'complete' if exit_code==0 else 'failed'
        else:
            state,exit_code=job['state'],job['exit_code']
        ready=state=='complete' and exit_code==0
        personal=draft['value']['metadata'].get('review_kind')=='personal'
        pending_ethics=draft['value']['metadata'].get('ethics_status')=='pending'
        if method=='POST':
            if not ready:raise ValueError('Finish sample preparation before creating the study')
            if pending_ethics:raise ValueError('Record the actual ethics determination before creating a study for reviewers')
            study=store.create_prepared_study(key)
            return 303,('/review/'+store.study(study)['metadata']['personal_token'] if personal else '/human-evaluation/'+study),b''
        body=style+"<div class='review-stack'><section class='review-card'><h1>"+html.escape(draft['value']['name'])+"</h1><p>Sample preparation: "+html.escape(state)+"</p><p><a href='/jobs/"+draft['job']+"'>Open preparation job</a> | <a href='/human-evaluation?campaign_id="+draft['campaign']+"'>Human evaluation</a></p>"
        if ready:
            with Path(draft['value']['prepared']).open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
            count=len({r['sample_key'] for r in rows});clusters=len({r.get('cluster_key',r['sample_key']) for r in rows})
            body+=f"<h2>Check the review workload</h2><p>{clusters:,} source clusters, {count:,} saved outputs. "
            body+=(f"{count:,} personal evaluations. These are not independent two-rater assessments.</p>" if personal else
                f"{2*count:,} required independent ratings, plus any adjudication.</p>")
            body+="<p>No human ratings have been created by preparation.</p>"
            if personal:
                body+="<form method='post'><button>Open evaluation form</button></form>"
            elif pending_ethics:
                body+="<p>Ethics determination is not decided yet. You can inspect this sample, but cannot invite reviewers. Return to study setup when the actual determination is available.</p>"
            else:body+="<form method='post'><button>Create study and assign reviewers</button></form>"
            frame_path=Path(draft['value']['prepared']).with_suffix('.FRAME.json')
            if frame_path.is_file():
                frame=json.loads(frame_path.read_text(encoding='utf-8'))
                body+=f"<p>Eligible source frame: {frame['population_outputs']:,} outputs in {frame['population_clusters']:,} clusters. This is a deterministic achieved sample, not a representative population estimate. Historical generation conditions remain separate.</p>"
                body+="<p>Campaign outcome accounting: "+html.escape(', '.join(f'{k}: {v:,}' for k,v in frame['assignment_outcomes'].items()))+".</p>"
            media_report=Path(draft['value']['prepared']).with_suffix('.MEDIA-REPORT.json')
            if media_report.is_file():
                report=json.loads(media_report.read_text(encoding='utf-8'))
                body+=f"<p>Saved media: {report.get('resolved_references',0):,} / {report.get('media_references',0):,} references connected.</p>"
                if report.get('outputs_with_unavailable_media'):
                    body+=f"<p class='review-error'>{report['outputs_with_unavailable_media']:,} outputs have unavailable media. Restore these assets before rating affected items; those rows have not been removed.</p>"
        elif state in {'running','starting','queued'}:
            body+="<p>The sample is preparing in the background. Refresh this page when the job finishes.</p><a class='button ghost' href=''>Refresh preparation</a>"
        else:body+="<p class='review-error'>Preparation did not finish successfully. Inspect the job before continuing; no study has been created.</p>"
        return 200,'text/html; charset=utf-8',_page('Human evaluation preparation',body+'</section></div>',active='Campaigns')
    return None
