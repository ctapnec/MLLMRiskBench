"""Campaign-aware human study setup, separate from the blinded rater wizard."""
import csv
import html
import json
import secrets
from pathlib import Path

from .ui import _page


def sources(app, campaign):
    app.db.require_workspace(campaign)
    rows = app._human_store().sources(campaign)
    result = [dict(id='scope-'+r['id'], name=r['name'], **r['metadata']) for r in rows]
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


def setup_body(app, campaign, field):
    escape = lambda value: html.escape(str(value), quote=True)
    if not campaign:
        return "<section class='review-card'><h2>Choose a campaign</h2><p>Open an existing local or API campaign, including a finished campaign, to review its saved outputs.</p><div class='review-actions'>" + ''.join(
            "<a class='button ghost' href='/human-evaluation?campaign_id="+r['campaign_id']+"'>"+escape(r['name'])+"</a>" for r in app.db.workspaces() or []) + '</div></section>'
    options = "<option value=''>Choose saved results</option>"+''.join("<option value='"+escape(r['id'])+"'>"+escape(r['name'])+"</option>" for r in sources(app,campaign))
    hidden = "<input type='hidden' name='campaign_id' value='"+escape(campaign)+"'>"
    body = "<section class='review-card'><h2>New human evaluation</h2><p>Use saved results from this campaign. Collection can already be finished. No model is rerun and no API credit is spent.</p><form method='post' action='/human-evaluation/prepare-study' data-study-wizard novalidate>"+hidden
    body += "<div class='review-steps' role='navigation' aria-label='Study setup steps'></div><section class='review-step' data-study-step='Saved results'><h2 tabindex='-1'>Choose the saved result set</h2><label>Saved results<select name='source' required>"+options+"</select></label><p class='review-help'>A result set may cover one run or a registered combined analysis. Its label describes the scope; choosing it does not imply every campaign output is eligible. Missing outputs remain in campaign statistics.</p></section>"
    body += "<section class='review-step' data-study-step='Sample'><h2 tabindex='-1'>Define the assessment sample</h2>"+field('name','Study name')+"<div class='review-grid'><label>Rubric<select name='mode'><option value='common'>Common safety dimensions</option><option value='source_task'>Source-task classification</option></select></label>"+field('clusters','Source clusters',20,'number')+"</div><p>Whole selected clusters stay together. The prepared sample will show the actual output count and two-rater workload before the study is created.</p><details><summary>Media lookup for imported results</summary>"+field('media_index','Existing retained media index (optional)',required=False)+"<p>Leave blank to use the selected result set's registered index. This connects saved image identities to their existing local files; it does not download media.</p></details></section>"
    body += "<section class='review-step' data-study-step='Arrangements'><h2 tabindex='-1'>Record the actual study arrangements</h2>"+field('ethics','Supervisor / institution determination and date')+field('compensation','Time, compensation and withdrawal terms')+field('stop_contact','Stop / escalation contact')+"<label>Consent and sensitive-content information<textarea name='consent' required></textarea></label><p>These fields record real decisions. They do not constitute institutional approval or replace consent from each reviewer.</p></section>"
    body += "<section class='review-step' data-study-step='Review'><h2 tabindex='-1'>Review sample preparation</h2><div data-study-summary></div><label class='review-check'><input type='checkbox' name='acknowledge' value='1' required><span>I understand the sample contains potentially harmful content and will be shared only with the assigned reviewers.</span></label><p>Preparation runs in Jobs. You will inspect the workload before creating the study and assigning raters.</p></section><div class='review-wizard-footer'><button type='button' class='ghost' data-study-back>Back</button><button type='button' data-study-next>Next</button><button type='submit'>Prepare review sample</button></div></form></section>"
    drafts=app._human_store().preparations(campaign)
    if drafts:
        body += "<section class='review-card'><h2>Sample preparations</h2><ul>"+''.join("<li><a href='/human-evaluation/preparations/"+r['id']+"'>"+escape(r['value']['name'])+"</a></li>" for r in drafts)+"</ul></section>"
    body += "<details class='review-card'><summary>Register an existing analysis result set</summary><p>For imported historical campaigns, associate their existing combined analysis once. This neither copies nor regenerates responses. Normal completed runs are listed automatically.</p><form method='post' action='/human-evaluation/register-source'>"+hidden+field('name','Result-set name')+field('results','Existing analysis results directory')+field('historical_code_repository','Historical code repository (if needed)',required=False)+field('judge_configuration_sha256','Historical judge configuration reference (if needed)',required=False)+"<button>Register saved results</button></form></details>"
    return body+SETUP_SCRIPT


def setup_route(app, method, path, data, style):
    store=app._human_store()
    if method=='POST' and path=='/human-evaluation/register-source':
        owner=data.get('campaign_id','');app.db.require_workspace(owner)
        store.register_source(campaign=owner, **{k:data.get(k,'') for k in ('name','results','historical_code_repository','judge_configuration_sha256','media_index')})
        return 303,'/human-evaluation?campaign_id='+owner,b''
    if method=='POST' and path=='/human-evaluation/prepare-study':
        owner=data.get('campaign_id',''); choices=sources(app,owner)
        source=next((r for r in choices if r['id']==data.get('source')),None)
        if source is None: raise ValueError('Choose saved results from this campaign')
        if data.get('acknowledge')!='1': raise ValueError('Acknowledge sensitive content before preparing a sample')
        if data.get('mode') not in {'common','source_task'} or int(data.get('clusters','0'))<1: raise ValueError('Choose a rubric and a positive cluster count')
        if any(not data.get(k,'').strip() for k in ('name','ethics','compensation','stop_contact','consent')): raise ValueError('Complete the study name and actual review arrangements')
        directory=store.root/('preparation-'+secrets.token_hex(8));directory.mkdir(mode=0o700)
        params={'--results':source['results'],'--output':str(directory/'sample.csv'),'--acknowledge-sensitive-content':'1',
                '--prepare-source-task' if data['mode']=='source_task' else '--prepare':data['clusters']}
        for key in ('historical_code_repository','judge_configuration_sha256'):
            if source.get(key):params['--'+key.replace('_','-')]=source[key]
        supplied_index=data.get('media_index','').strip() or source.get('media_index','')
        if supplied_index: params['--media-index']=str(store._path(supplied_index))
        job=app.start_job('human_audit',params,campaign_id=owner)
        metadata={k:data[k] for k in ('ethics','compensation','stop_contact','consent')}
        metadata.update({k:source.get(k,'') for k in ('results','historical_code_repository','judge_configuration_sha256','media_index')})
        if data.get('media_index','').strip(): metadata['media_index']=str(store._path(data['media_index']))
        key=store.save_preparation(owner,job.job_id,dict(name=data['name'],mode=data['mode'],prepared=str(directory/'sample.csv'),metadata=metadata))
        return 303,'/human-evaluation/preparations/'+key,b''
    if path.startswith('/human-evaluation/preparations/'):
        key=path.rsplit('/',1)[-1];draft=store.preparation(key);job=app.db.load_job(draft['job'])
        if job is None:raise ValueError('The sample preparation job is unavailable')
        live=app.jobs.get(draft['job']);state=live.state() if live else job['state']
        ready=state=='complete' and job['exit_code']==0
        if method=='POST':
            if not ready:raise ValueError('Finish sample preparation before creating the study')
            return 303,'/human-evaluation/'+store.create_prepared_study(key),b''
        body=style+"<div class='review-stack'><section class='review-card'><h1>"+html.escape(draft['value']['name'])+"</h1><p>Sample preparation: "+html.escape(state)+"</p><p><a href='/jobs/"+draft['job']+"'>Open preparation job</a> | <a href='/human-evaluation?campaign_id="+draft['campaign']+"'>Human evaluation</a></p>"
        if ready:
            with Path(draft['value']['prepared']).open(encoding='utf-8-sig',newline='') as f:rows=list(csv.DictReader(f))
            count=len({r['sample_key'] for r in rows});clusters=len({r.get('cluster_key',r['sample_key']) for r in rows})
            body+=f"<h2>Check the review workload</h2><p>{clusters:,} source clusters, {count:,} saved outputs, {2*count:,} required independent ratings, plus any adjudication.</p><p>No human ratings have been created by preparation.</p><form method='post'><button>Create study and assign reviewers</button></form>"
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
