"""Optional campaign help. Reads saved UI state; never prepares or starts work."""
from __future__ import annotations

import html
from urllib.parse import quote


STYLE = """
.campaign-guide-option { display:flex; align-items:flex-start; gap:.65rem; flex:1 1 100%;
  padding:.8rem; border:1px solid var(--line); border-radius:10px; background:var(--soft); }
.campaign-guide-option input { flex:none; margin-top:.25rem; }
.campaign-guide-option small { display:block; color:var(--muted); margin-top:.3rem; }
.campaign-guide-launch { margin:.65rem 0; }
.campaign-guide-dialog { box-sizing:border-box; width:min(720px,calc(100vw - 2rem));
  max-height:calc(100dvh - 2rem); padding:0; overflow:auto; color:var(--ink);
  background:var(--card); border:1px solid var(--line); border-radius:14px; box-shadow:var(--shadow); }
.campaign-guide-dialog::backdrop { background:rgba(0,0,0,.55); }
.campaign-guide-header { display:flex; align-items:flex-start; justify-content:space-between;
  gap:1rem; padding:1.25rem 1.25rem .5rem; }
.campaign-guide-header h2 { margin:0; }
.campaign-guide-header button { flex:none; }
.campaign-guide-content { padding:0 1.25rem 1.25rem; }
.campaign-guide-steps { display:flex; flex-wrap:wrap; gap:.4rem; margin:1rem 0; }
.campaign-guide-steps button { padding:.45rem .65rem; }
.campaign-guide-steps button[aria-current=step] { background:var(--accent); color:var(--accent-ink); }
.campaign-guide-section[hidden] { display:none; }
.campaign-guide-section:focus { outline:none; }
.campaign-guide-links { display:grid; gap:.6rem; margin:1rem 0; }
.campaign-guide-links a { display:block; padding:.75rem; border:1px solid var(--line);
  border-radius:8px; background:var(--soft); overflow-wrap:anywhere; }
.campaign-guide-footer { display:flex; justify-content:space-between; flex-wrap:wrap;
  gap:.75rem; border-top:1px solid var(--line); padding-top:1rem; margin-top:1rem; }
@media(max-width:520px) { .campaign-guide-header { padding:1rem 1rem .5rem; }
  .campaign-guide-content { padding:0 1rem 1rem; } }
"""


def _guidance(app, params):
    """Bounded index reads only, not filesystem scans or inference checks."""
    owner = params.get('campaign_id', '')
    base = '/build?campaign_id=' + quote(owner, safe='') if owner else '/build?work_kind=campaign'
    campaign = '/campaigns/' + quote(owner, safe='') if owner else base
    link = lambda tab: base + '#build-' + tab
    matched = bool(params.get('retained_source_campaign'))
    local = bool(params.get('local'))
    hosted = bool(params.get('api'))
    route = 'matched' if matched else 'mixed' if local and hosted else 'local' if local else 'hosted' if hosted else 'choose'
    steps = [
        ('Choose a route', 'Choose what you want to compare',
         'Use local models, hosted APIs, or both in one campaign. For a fresh workload, choose arms, '
         'corpora and frameworks in Pipeline. To compare hosted answers against saved local answers, '
         'use Reuse local inputs for an API comparison in General. Sharing a seed alone does not prove matched inputs.',
         [('Choose models and a fresh workload', link('pipeline')),
          ('Reuse saved local inputs', link('general'))]),
        ('Inputs', 'Choose a small, interpretable input selection',
         'For fresh inputs, select your corpora and attacks in Pipeline, then set the per-arm limit, '
         'sampling policy and seeds in Execution. Keep text and image counts explicit. For reused inputs, '
         'select the source campaign and saved runs, then Prepare selected inputs. That preparation makes no generation calls.',
         [('Select corpora and frameworks', link('pipeline')),
          ('Set limits and sampling', link('execution')),
          ('Select saved source runs', link('general'))]),
        ('Settings', 'Choose evaluation and realistic bounds',
         'Select your judges in Evaluation. Local models use their assessed serving profiles; scoring revision '
         'and placement are automatic. Hosted output allowances come from API target configuration and, for '
         'matched work, the model forecast. Review target, judge and HTTP ceilings in Execution. '
         'The call-start window is not an individual response timeout. Full model checksum scans are optional.',
         [('Choose judges', link('evaluation')), ('Set execution bounds', link('execution')),
          ('Inspect local serving', link('execution')), ('Configure hosted targets', '/config')]),
        ('Prepare', 'Prepare and review before making target calls',
         ('For this matched selection: Prepare selected inputs, Prepare forecast, Prepare replay inputs, '
          'then Prepare counted collection. After each job completes, return to this saved campaign in Build. '
          'Review prepared collection shows the exact workload and cost bound. Token counting can contact '
          'the provider but does not generate answers.') if matched else
         ('Save the campaign, then Compose & review. Run the no-call preflight and inspect its counts. '
          'Local acquisition controls reuse installed models, not a new runtime installation. Measured work '
          'needs valid transport evidence for each selected route/modality. Use a diagnostic probe when that '
          'evidence is missing, then return to the measured selection. The probe makes real calls; the projection does not.'),
         [('Open preparation controls', link('general')), ('Check transport evidence', link('admission'))]),
        ('Run', 'Start once and follow the existing job',
         'Use the explicit start on the reviewed job or prepared collection. Hosted generation spends credits. '
         'Watch Campaign jobs or Activity; an active or retry-waiting job is not a reason to start a duplicate. '
         'If interrupted, inspect the original error and its offered continuation. Keep saved answers and '
         'recover only the unfinished stage. This guide never starts or resumes jobs for you.',
         [('Open review controls', link('general')),
          ('Open campaign jobs', '/jobs?campaign_id=' + owner if owner else link('general'))]),
        ('Judge', 'Judge each saved answer, not just its input',
         ('Use Judge retained outputs locally: prepare remaining source runs, select the saved preparation, '
          'then Review local judging. For Haiku, review Same-input output coverage and all-output judging '
          'funding. Select Haiku in Haiku comparison of saved outputs, then prepare and review all-output '
          'Haiku judging. Only its explicit start buys verdicts. The paired comparison limit and USD fields '
          'do not change all-output judging. Image assessments use the retained text proxy.') if matched else
         ('For direct Runner work, the selected judging cascade evaluates collected answers. A cascade may '
          'decide before reaching its model-backed judge; it is not two independent verdicts. Missing text, '
          'abstentions and invalid assessments must remain visible. Post-hoc Haiku comparison needs a prepared '
          'saved-output selection and its own budget. A verdict for one model cannot be copied to another answer.'),
         [('Open judging controls', link('general') if matched else link('evaluation')),
          ('Inspect saved verdicts', campaign + '?section=judging' if owner else link('evaluation'))]),
        ('Results', 'Inspect coverage before comparing rates',
         'Results shows answers, effective generation settings, usage and truncation. Judging shows '
         'answer-specific decisions and coverage. Costs reports recorded attempts and charges, not the balance '
         'in your provider account. In Compare, the left campaign is fixed to the page you opened. Select '
         'the right campaign and Update choices / compare to load its models. Select models and update '
         'again for generation conditions, then select those and update again for judging conditions. Keep diagnostic '
         'probes and historical replacements separate. Human evaluation is optional setup here, not a claim '
         'that independent raters have already assessed the outputs.',
         [(label, campaign + '?section=' + section if owner else link('general'))
          for label, section in [('Inspect results', 'results'), ('Compare matched inputs', 'compare'), ('Inspect costs', 'costs')]])
    ]
    stage = 0 if not (local or hosted) else 1 if not (params.get('corpora') or matched) else 2
    notice = 'Suggested next step from the saved draft. It is guidance, not a validation or completion certificate.'
    actions = []
    if owner:
        actions = app.db.workspace_activity(owner) or []
    latest = next((row for row in actions if row['member_kind'] == 'job'), None)
    if latest is not None and latest['state'] in {'queued', 'starting', 'running', 'retry_wait', 'retry_waiting', 'failed', 'aborted', 'interrupted'}:
        stage = 4
        state = latest['state']
        notice = 'The latest console job is recorded as ' + state + '. Open that job before starting or preparing another copy.'
        steps[4][3].insert(0, ('Open the current job', '/jobs/' + quote(latest['member_id'], safe='')))
    elif latest is not None and latest['state'] == 'complete':
        stage = 6 if latest['role'] == 'judging' else 5 if latest['role'] == 'collection' else 3
        notice = 'The latest console job completed. Check what that job covered; this does not mean the whole campaign is finished.'
    elif matched:
        stage = 3
    if latest is not None and latest['role'] == 'collection' and not matched and params.get('mode') == 'attestation_probe':
        notice += ' A diagnostic probe is not a measured result; finish its transport evidence before measured execution.'
    return steps, stage, notice, route


def render(app, params, *, builder=False):
    enabled = params.get('campaign_guide') == 'on'
    if not builder and not enabled:
        return ''
    steps, stage, notice, route = _guidance(app, params)
    escape = html.escape
    owner = params.get('campaign_id') or 'new'
    sections = ''
    navigation = ''
    for index, (short, title, text, links) in enumerate(steps):
        navigation += (f"<button type='button' class='ghost' data-guide-step='{index}'>"
                       + str(index + 1) + '. ' + escape(short) + '</button>')
        sections += (f"<section class='campaign-guide-section' data-guide-section='{index}' tabindex='-1' hidden>"
            + '<h3>' + escape(title) + '</h3><p>' + escape(text) + "</p><div class='campaign-guide-links'>"
            + ''.join("<a href='" + escape(href, quote=True) + "'>" + escape(label) + '</a>' for label, href in links)
            + '</div></section>')
    return (
        "<div class='campaign-guide' data-guide-enabled='" + ('true' if enabled else 'false')
        + "' data-guide-key='" + escape(owner + ':' + route + ':' + str(stage), quote=True)
        + f"' data-guide-initial='{stage}'>"
        "<div class='campaign-guide-launch'><button type='button' class='ghost' data-guide-open"
        + ('' if enabled else ' hidden') + ">Campaign guide</button></div>"
        "<dialog class='campaign-guide-dialog' aria-labelledby='campaign-guide-title'>"
        "<div class='campaign-guide-header'><h2 id='campaign-guide-title'>Your campaign, step by step</h2>"
        "<button type='button' class='ghost' data-guide-close aria-label='Close campaign guide'>Close</button></div>"
        "<div class='campaign-guide-content'><p class='note'>" + escape(notice) + '</p>'
        "<p>No calls are made by this guide. Links open controls; you decide what to run.</p>"
        "<div class='campaign-guide-steps' role='group' aria-label='Guide steps'>" + navigation + '</div>'
        "<p class='note' data-guide-progress aria-live='polite'></p>" + sections
        + "<div class='campaign-guide-footer'><button type='button' class='ghost' data-guide-back>Back</button>"
        "<button type='button' data-guide-next>Next</button></div>"
        "<p class='note'>Close this window to work. Reopen it with Campaign guide. To disable automatic guidance, "
        "uncheck Guide me through this campaign in Build and save the campaign.</p>"
        '</div></dialog></div>' + SCRIPT
    )


SCRIPT = """<script>(()=>{
const root=document.querySelector('.campaign-guide');if(!root)return;
const dialog=root.querySelector('dialog'),open=root.querySelector('[data-guide-open]');
const choice=document.querySelector('[name=campaign_guide]');
const steps=[...root.querySelectorAll('[data-guide-step]')],panels=[...root.querySelectorAll('[data-guide-section]')];
const back=root.querySelector('[data-guide-back]'),next=root.querySelector('[data-guide-next]');
let current=Number(root.dataset.guideInitial),focusBefore;
function show(index,focus=false){current=Math.max(0,Math.min(index,panels.length-1));
panels.forEach((p,i)=>p.hidden=i!==current);steps.forEach((b,i)=>{if(i===current)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});
back.disabled=current===0;next.textContent=current===panels.length-1?'Done':'Next';
root.querySelector('[data-guide-progress]').textContent='Step '+(current+1)+' of '+panels.length;
if(focus)panels[current].focus();}
const key='ura-campaign-guide:'+root.dataset.guideKey;
function launch(){if(dialog.open||!dialog.showModal||window.uraBusy?.isBusy())return;
focusBefore=document.activeElement;show(current);dialog.showModal();
try{sessionStorage.setItem(key,'shown');}catch(e){}}
function close(){dialog.close();}
open.addEventListener('click',launch);root.querySelector('[data-guide-close]').addEventListener('click',close);
dialog.addEventListener('close',()=>{if(focusBefore?.isConnected)focusBefore.focus();});
dialog.querySelectorAll('a').forEach(a=>a.addEventListener('click',close));
steps.forEach((b,i)=>b.addEventListener('click',()=>show(i,true)));
back.addEventListener('click',()=>show(current-1,true));
next.addEventListener('click',()=>current===panels.length-1?close():show(current+1,true));
function enabled(){return choice?choice.checked&&!choice.disabled:root.dataset.guideEnabled==='true';}
function sync(){open.hidden=!enabled();if(!enabled()&&dialog.open)close();}
if(choice)choice.addEventListener('change',()=>{sync();if(enabled())launch();});
document.querySelectorAll('[name=work_kind]').forEach(e=>e.addEventListener('change',()=>setTimeout(sync,0)));
show(current);sync();
document.addEventListener('DOMContentLoaded',()=>{sync();let seen=false;
try{seen=sessionStorage.getItem(key)==='shown';}catch(e){}
if(enabled()&&!seen)launch();},{once:true});
})();</script>"""
