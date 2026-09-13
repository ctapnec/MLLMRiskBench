"""Operator study management and a separate blinded reviewer surface."""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
import re
import secrets
from urllib.parse import quote

from .human_review_store import HumanReviewStore, COMMON
from .ui import _page


def _field(name, label, value="", kind="text", required=True):
    return ("<label class='campaign-field'>"+html.escape(label)+"<input name='"+name+"' type='"+kind
            +"' value='"+html.escape(str(value), quote=True)+"'"+(" required" if required else "")+"></label>")


_REVIEW_STYLE = """<style>
.review-stack{display:grid;gap:1rem;max-width:1100px;margin:0 auto}.review-card{padding:1.25rem;border:1px solid var(--border,#999);border-radius:12px;min-width:0}
.review-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}.review-text{white-space:pre-wrap;overflow-wrap:anywhere;max-height:42vh;overflow:auto;line-height:1.6;padding:.75rem;background:var(--bg,#fff);border-radius:6px}
.review-card textarea{width:100%;min-height:5rem}.review-card label{display:flex;flex-direction:column;gap:.4rem;margin:.7rem 0}.review-card img,.review-card video{max-width:100%;max-height:55vh;object-fit:contain}.review-card audio{max-width:100%}
.review-actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1rem}.review-error{color:var(--red,#b42318);white-space:pre-wrap}.review-card select{max-width:100%}.review-status{min-height:1.6em}#review-body[hidden]{display:none}
</style>"""


_REVIEW_SCRIPT = r"""<script>
(function(){
const base=location.pathname.replace(/\/$/,''),status=document.getElementById('review-status');
let current=null,revision=0,dirty=false,timer=null,queue=[];
function node(tag,text,parent){let e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(parent)parent.append(e);return e;}
async function request(action,values){const response=await fetch(base+action,{method:values?'POST':'GET',headers:values?{'Content-Type':'application/x-www-form-urlencoded'}:{},body:values?new URLSearchParams(values):undefined});let value=await response.json();if(!response.ok)throw Error(value.error||'Request failed');return value;}
function error(e){status.textContent=e.message;status.className='review-status review-error';}
function values(){let result={};document.querySelectorAll('[data-rating]').forEach(e=>{let key=e.dataset.rating;if(e.type==='checkbox')result[key]=e.checked;else if(key==='confidence')result[key]=e.value?Number(e.value):'';else result[key]=e.value;});return result;}
async function save(submit=false,defer=false){clearTimeout(timer);if(!current)return;try{status.className='review-status';status.textContent='Saving...';let result=await request('/rating',{item:current,revision:String(revision),value:JSON.stringify(values()),submit:submit?'1':'',defer:defer?'1':''});revision=result.revision;dirty=false;status.textContent=submit?'Submitted independently.':defer?'Deferred for remediation.':'Draft saved.';if(submit||defer)await load();}catch(e){dirty=true;error(e);}}
function changed(){dirty=true;clearTimeout(timer);timer=setTimeout(()=>save(),900);}
function choices(container,allowed,saved){Object.entries(allowed).forEach(([key,items])=>{let label=node('label',key.replaceAll('_',' '),container),select=node('select',undefined,label);select.dataset.rating=key;node('option','Choose...',select).value='';items.forEach(v=>node('option',v.replaceAll('_',' '),select).value=v);select.value=saved[key]||'';select.onchange=changed;});}
async function show(id){if(dirty){await save();if(dirty)return;}try{let data=await request('?item='+encodeURIComponent(id));current=id;const body=document.getElementById('review-body');body.replaceChildren();let item=data.item;
node('h2','Assessment',body);node('p','Apply the supplied policy. Do not consult automated judgments or other raters. Take regular breaks; you may defer a category or withdraw without penalty.',body);
[['Policy',item.source_policy_instruction],['Assessment purpose',item.source_policy_intended_metric],['Prompt',item.prompt],['Saved response',item.response]].forEach(([title,text])=>{node('h3',title,body);node('div',text||'Not provided',body).className='review-text';});
let mediaOk=true;item.media.forEach(m=>{if(!m.available){node('p','Required media unavailable. Defer this item; do not guess.',body).className='review-error';mediaOk=false;return;}let e=node(m.modality==='image'?'img':m.modality,undefined,body);if(m.modality==='image')e.alt='Assigned prompt image';else e.controls=true;e.src=base+'/media?item='+encodeURIComponent(id)+'&index='+m.index;e.onerror=()=>{mediaOk=false;node('p','Media loading failed. Do not submit this item.',body).className='review-error';let submit=document.getElementById('submit-rating');if(submit)submit.disabled=true;};});
if(data.role==='adjudicator'){item.independent_ratings.forEach((r,i)=>{node('h3','Independent rating '+(i+1),body);node('pre',JSON.stringify(r.value,null,2),body).className='review-text';});choices(body,item.choices,{});node('label','Reason for the final decision',body).append(node('textarea'));const reason=body.querySelector('textarea');let button=node('button','Submit adjudication',body);button.onclick=async()=>{try{await request('/adjudicate',{item:id,value:JSON.stringify(values()),rationale:reason.value});dirty=false;await load();}catch(e){error(e);}};body.querySelectorAll('[data-rating]').forEach(e=>e.onchange=null);return;}
revision=item.rating.revision;const saved=item.rating.value;choices(body,item.choices,saved);let label=node('label','Confidence',body),select=node('select',undefined,label);select.dataset.rating='confidence';node('option','Choose...',select).value='';[1,2,3,4,5].forEach(n=>node('option',n+' / 5',select).value=n);select.value=saved.confidence||'';select.onchange=changed;
for(let [key,title] of [['notes','Notes (optional)'],['defer_reason','Reason for deferral / category opt-out']]){let l=node('label',title,body),e=node('textarea',undefined,l);e.dataset.rating=key;e.value=saved[key]||'';e.oninput=changed;}
if(item.media.length){let l=node('label','I viewed every required asset',body),e=node('input',undefined,l);e.type='checkbox';e.dataset.rating='media_viewed';e.checked=Boolean(saved.media_viewed);e.onchange=changed;}
const actions=node('div',undefined,body);actions.className='review-actions';node('button','Save draft',actions).onclick=()=>save();let submit=node('button','Submit independent rating',actions);submit.id='submit-rating';submit.disabled=!mediaOk;submit.onclick=()=>save(true);node('button','Defer / opt out of this item',actions).onclick=()=>save(false,true);
if(item.rating.state==='submitted'){body.querySelectorAll('select,textarea,input,button').forEach(e=>e.disabled=true);node('p','Submitted rating is fixed. It remains separate from adjudication.',body);}
}catch(e){error(e);}}
async function load(){try{let data=await request('/data'),intro=document.getElementById('review-intro'),body=document.getElementById('review-body');current=null;body.replaceChildren();intro.replaceChildren();node('h1','Independent human evaluation',intro);
if(!data.consented){node('p',data.consent,intro).className='review-text';node('p','Time and compensation: '+data.compensation,intro);node('p','Stop / escalation contact: '+data.stop_contact,intro);let l=node('label','I understand the sensitive-content warning, participation terms and withdrawal arrangements.',intro),c=node('input',undefined,l);c.type='checkbox';let b=node('button','Consent and begin',intro);b.onclick=async()=>{if(!c.checked){error(Error('Record consent before beginning.'));return;}try{await request('/consent',{agree:'1'});await load();}catch(e){error(e);}};return;}
queue=data.queue;let done=queue.filter(q=>q.state==='submitted').length;node('p',done+' / '+queue.length+' '+(data.role==='adjudicator'?'disagreements adjudicated':'ratings submitted')+'. No automated labels are shown.',intro);let select=node('select',undefined,intro);select.setAttribute('aria-label','Assigned item');queue.forEach((q,i)=>{let o=node('option','Item '+(i+1)+' - '+q.state,select);o.value=q.id;});select.onchange=()=>show(select.value);let exit=node('button','Withdraw from further review',intro);exit.onclick=async()=>{if(!confirm('Withdraw from further reviewing? Contact the study operator about your recorded-data withdrawal terms.'))return;try{await request('/withdraw',{confirm:'1'});dirty=false;intro.replaceChildren();node('p','Further review is disabled. Contact: '+data.stop_contact,intro);body.replaceChildren();}catch(e){error(e);}};
const next=queue.find(q=>q.state!=='submitted')||queue[0];if(next){select.value=next.id;await show(next.id);}else node('p','No eligible items currently await your review.',body);
}catch(e){error(e);}}
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});load();
})();</script>"""


class HumanReviewPagesMixin:
    def _human_store(self):
        with self._app_lock:
            if not hasattr(self, '_human_reviews'):
                self._human_reviews = HumanReviewStore(self.state_dir/'console.db', self.state_dir/'human-reviews',
                    allowed_roots=(self.results_root, self.state_dir),
                    media_roots=[p for p in os.environ.get('URA_MEDIA_ROOTS', '').split(os.pathsep) if p])
            return self._human_reviews

    def _human_index(self, campaign=''):
        if campaign: self.db.require_workspace(campaign)
        store = self._human_store()
        cards = ''.join("<li><a href='/human-evaluation/"+r['id']+"'>"+html.escape(r['name'])+"</a> ("+r['mode'].replace('_',' ')+")</li>" for r in store.studies(campaign))
        hidden = "<input type='hidden' name='campaign_id' value='"+html.escape(campaign, quote=True)+"'>"
        return _page('Human evaluation', _REVIEW_STYLE+"<div class='review-stack'><h1>Human evaluation</h1>"
            "<p>Review saved outputs independently. No target or hosted judge calls are made.</p>"
            "<ul>"+cards+"</ul><section class='review-card'><h2>1. Prepare the sample</h2>"
            "<p>Use complete source clusters and the intended analysis population. The background job reports actual outputs and two-rater workload before recruitment.</p>"
            "<form method='post' action='/human-evaluation/prepare'>"+hidden
            +_field('results','Analysis results directory')+_field('clusters','Source clusters',20,'number')
            +"<label>Frame<select name='mode'><option value='common'>Common safety dimensions</option><option value='source_task'>Source-task classification</option></select></label>"
            +_field('historical_code_repository','Historical code repository (if required)',required=False)
            +_field('judge_configuration_sha256','Exact historical judge configuration (if required)',required=False)
            +"<label><input type='checkbox' name='acknowledge' value='1' required>I understand this exports potentially harmful content.</label><button>Prepare sample</button></form></section>"
            "<section class='review-card'><h2>2. Create the review study</h2><p>Import the completed preparation. Study documents and reviewer qualification must describe actual human arrangements.</p>"
            "<form method='post' action='/human-evaluation/create'>"+hidden
            +_field('name','Study name')+_field('prepared','Prepared sample CSV')+_field('results','Same analysis results directory')
            +"<label>Frame<select name='mode'><option value='common'>Common safety dimensions</option><option value='source_task'>Source-task classification</option></select></label>"
            +_field('ethics','Supervisor / institution determination and date')+_field('compensation','Time, compensation and withdrawal terms')+_field('stop_contact','Stop / escalation contact')
            +"<label>Consent and sensitive-content information<textarea name='consent' required></textarea></label>"
            +_field('historical_code_repository','Historical code repository (if required)',required=False)
            +_field('judge_configuration_sha256','Exact historical judge configuration (if required)',required=False)
            +"<button>Create study</button></form></section></div>", active='Campaigns')

    def _human_study_page(self, study):
        summary = self._human_store().summary(study); info = summary['study']; counts = summary['counts']
        members = ''.join('<li>'+html.escape(r['id'])+' - '+r['role']+(' - withdrawn' if r['withdrawn'] else ' - consent recorded' if r['consent'] else ' - consent pending')+'</li>' for r in summary['reviewers'])
        dimensions = COMMON if info['mode']=='common' else {'task_label':None,'parse_status_label':None}
        qualifications = ''.join(_field('correct_'+k,k.replace('_',' ')+' correct / 20','','number') for k in dimensions)
        body = _REVIEW_STYLE+"<div class='review-stack'><h1>"+html.escape(info['name'])+"</h1><p><a href='/human-evaluation?campaign_id="+quote(info['campaign'])+"'>All studies</a></p>"
        body += "<section class='review-card'><h2>Review progress</h2><dl>"+''.join('<dt>'+k.replace('_',' ').title()+'</dt><dd>'+str(v)+'</dd>' for k,v in counts.items())+"</dl><p>"
        body += ('Complete ratings are ready for the existing audit analysis. This is not a population-validity claim.' if summary['ready_for_analysis'] else 'Incomplete human evidence: finish independent ratings, unresolved items and adjudication.')+"</p></section>"
        body += "<section class='review-card'><h2>Reviewers</h2><ul>"+members+"</ul><p>Two raters and a distinct adjudicator. Record the actual out-of-sample qualification results; the interface does not create human reference labels.</p>"
        body += "<form method='post' action='/human-evaluation/"+study+"/enroll'>"+_field('reviewer','Pseudonymous reviewer ID')+"<label>Role<select name='role'><option value='rater'>Independent rater</option><option value='adjudicator'>Adjudicator</option></select></label>"
        body += _field('reference','Independent 20-item qualification evidence reference')+"<div class='review-grid'>"+qualifications+"</div><label><input type='checkbox' name='qualified' value='1' required>Language, relevant experience and conflicts have been reviewed; the qualification reference was independently adjudicated.</label><button>Issue individual review link</button></form></section>"
        body += "<section class='review-card'><h2>Analysis and exports</h2><p>Independent ratings remain distinct from adjudication. The analysis reports agreement, support, coverage and evaluator comparisons in its appropriate frame.</p><form method='post' action='/human-evaluation/"+study+"/analyse'><button"+('' if summary['ready_for_analysis'] else ' disabled')+">Export and run human audit analysis</button></form>"
        if summary['ready_for_analysis']: body += "<p><a href='/human-evaluation/"+study+"/labels.csv'>Download completed ratings</a></p>"
        body += "</section></div>"
        return _page('Human evaluation study',body,active='Campaigns')

    def _human_route(self, method, path, query, data):
        store = self._human_store()
        if path.startswith('/review/'):
            parts=path.removeprefix('/review/').split('/');token=parts[0];action='/'.join(parts[1:])
            try:
                if method=='GET' and not action:
                    store.view(token)
                    if query.get('item'):
                        result=store.view(token,query['item'])
                    else:
                        page=_page('Independent human evaluation',_REVIEW_STYLE+"<div class='review-stack'><section id='review-intro' class='review-card'></section><p id='review-status' class='review-status' role='status' aria-live='polite'></p><section id='review-body' class='review-card'></section></div>"+_REVIEW_SCRIPT)
                        page=re.sub(rb'<nav>.*?</nav>',b'',page,count=1,flags=re.S)
                        return 200,'text/html; charset=utf-8',page
                elif method=='GET' and action=='data': result=store.view(token)
                elif method=='GET' and action=='media':
                    mime,body=store.media(token,query.get('item',''),int(query.get('index','-1')));return 200,mime,body
                elif method=='POST' and action=='consent' and data.get('agree')=='1': store.consent(token);result={'saved':True}
                elif method=='POST' and action=='withdraw' and data.get('confirm')=='1': store.withdraw(token);result={'saved':True}
                elif method=='POST' and action=='rating':
                    result=store.save(token,data.get('item',''),revision=int(data.get('revision','-1')),value=json.loads(data.get('value','{}')),submit=data.get('submit')=='1',defer=data.get('defer')=='1')
                elif method=='POST' and action=='adjudicate':
                    store.adjudicate(token,data.get('item',''),json.loads(data.get('value','{}')),data.get('rationale',''));result={'saved':True}
                else: return 404,'application/json',b'{"error":"Unknown review action"}'
                return 200,'application/json; charset=utf-8',json.dumps(result).encode()
            except (ValueError,KeyError,OSError) as error:
                # Never echo a filesystem locator, response or hidden metadata.
                message=str(error) if isinstance(error,ValueError) and not isinstance(error,json.JSONDecodeError) else 'Review request could not be completed. Your unsaved draft is still on screen.'
                return 400,'application/json; charset=utf-8',json.dumps({'error':message}).encode()
        if method=='GET' and path=='/human-evaluation': return 200,'text/html; charset=utf-8',self._human_index(query.get('campaign_id',''))
        if method=='POST' and path=='/human-evaluation/prepare':
            if data.get('acknowledge')!='1': raise ValueError('Acknowledge sensitive content before preparation')
            directory=store.root/('preparation-'+secrets.token_hex(8));directory.mkdir(mode=0o700)
            params={'--results':data.get('results',''),'--output':str(directory/'sample.csv'),'--acknowledge-sensitive-content':'1',
                    '--prepare-source-task' if data.get('mode')=='source_task' else '--prepare':data.get('clusters','')}
            for key in ('historical_code_repository','judge_configuration_sha256'):
                if data.get(key): params['--'+key.replace('_','-')]=data[key]
            job=self.start_job('human_audit',params,campaign_id=data.get('campaign_id',''))
            return 303,'/jobs/'+job.job_id,b''
        if method=='POST' and path=='/human-evaluation/create':
            if data.get('campaign_id'):self.db.require_workspace(data['campaign_id'])
            metadata={k:data.get(k,'') for k in ('ethics','consent','compensation','stop_contact','results','historical_code_repository','judge_configuration_sha256')}
            study=store.create(campaign=data.get('campaign_id',''),name=data.get('name',''),prepared=data.get('prepared',''),mode=data.get('mode',''),metadata=metadata)
            return 303,'/human-evaluation/'+study,b''
        parts=path.removeprefix('/human-evaluation/').split('/');study=parts[0];action='/'.join(parts[1:])
        info=store.study(study)
        if method=='GET' and not action:return 200,'text/html; charset=utf-8',self._human_study_page(study)
        if method=='POST' and action=='enroll':
            dimensions=COMMON if info['mode']=='common' else {'task_label':None,'parse_status_label':None}
            qualification={'reference':data.get('reference',''),'items':20,'correct':{k:int(data.get('correct_'+k,'-1')) for k in dimensions},'independent_reference':data.get('qualified')=='1','language_and_experience_confirmed':data.get('qualified')=='1'}
            token=store.enroll(study,data.get('reviewer',''),data.get('role',''),qualification)
            return 200,'text/html; charset=utf-8',_page('Individual review link',"<h1>Individual review link</h1><p>Share only with this reviewer. It does not reveal other reviewers' ratings. Keep the operator console private.</p><p><a href='/review/"+token+"'>/review/"+token+"</a></p><p><a href='/human-evaluation/"+study+"'>Return to study</a></p>",active='Campaigns')
        if method=='GET' and action=='labels.csv':return 200,'text/csv; charset=utf-8',store.export(study)
        if method=='POST' and action=='analyse':
            payload=store.export(study);directory=store.root/study/('analysis-'+secrets.token_hex(8));directory.mkdir(mode=0o700)
            (directory/'labels.csv').write_bytes(payload)
            params={'--results':info['metadata']['results'],'--labels' if info['mode']=='common' else '--source-task-labels':str(directory/'labels.csv'),
                '--prepared-rating-form':str(store.root/study/'prepared.csv'),'--prepared-rating-form-sha256':info['metadata']['prepared_sha256'],'--output':str(directory/'analysis.json')}
            for key in ('historical_code_repository','judge_configuration_sha256'):
                if info['metadata'].get(key):params['--'+key.replace('_','-')]=info['metadata'][key]
            job=self.start_job('human_audit',params,campaign_id=info['campaign']);return 303,'/jobs/'+job.job_id,b''
        return 404,'text/plain; charset=utf-8',b'Unknown human evaluation action'
