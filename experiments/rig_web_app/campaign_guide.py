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
.campaign-guide [hidden] { display:none !important; }
.campaign-guide-dialog { box-sizing:border-box; width:min(720px,calc(100vw - 2rem));
  max-height:calc(100dvh - 2rem); padding:0; overflow:auto; color:var(--ink);
  background:var(--card); border:1px solid var(--line); border-radius:14px; box-shadow:var(--shadow); }
.campaign-guide-dialog::backdrop { background:rgba(0,0,0,.55); }
.campaign-guide-header { display:flex; align-items:flex-start; justify-content:space-between;
  gap:1rem; padding:1.25rem 1.25rem .5rem; position:sticky; top:0;
  background:var(--card); z-index:1; }
.campaign-guide-header h2 { margin:0; }
.campaign-guide-header button { flex:none; }
.campaign-guide-content { padding:0 1.25rem 1.25rem; }
.campaign-guide-steps { display:flex; flex-wrap:wrap; gap:.4rem; margin:1rem 0; }
.campaign-guide-steps button { padding:.45rem .65rem; }
.campaign-guide-steps button[aria-current=step] { background:var(--accent); color:var(--accent-ink); }
.campaign-guide-topics { margin:.8rem 0; }
.campaign-guide-topics summary { cursor:pointer; padding:.45rem 0; font-weight:600; }
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
    def link(tab, target=''):
        if target == 'retained-inputs' and params.get('campaign_inputs') != 'saved':
            target = 'campaign-workflow'
        return base + '#' + (target or 'build-' + tab)
    tool = lambda command: '/commands?cmd=' + command + ('&campaign_id=' + owner if owner else '')
    matched = params.get('campaign_inputs') == 'saved' or (
        not params.get('campaign_flow') and bool(params.get('retained_source_campaign')))
    local = bool(params.get('local'))
    hosted = bool(params.get('api'))
    route = 'matched' if matched else 'mixed' if local and hosted else 'local' if local else 'hosted' if hosted else 'choose'
    prepare_target = 'automatic-comparison' if matched else 'pipeline-review'
    judging_links = ([('Open local saved-output judging', link('general', 'retained-local-judging'))]
        if params.get('retained_programs_job') else [('Complete collection preparation', link('general', prepare_target))]) if matched else [
            ('Choose judges', link('evaluation', 'evaluation-judges'))]
    if matched and params.get('retained_programs_job'):
        judging_links += [('Open Haiku saved-output judging', link('general', 'retained-haiku-judging')),
            ('Review same-input output coverage', link('general', 'retained-haiku-judging'))]
    if owner:
        judging_links.insert(0,('Evaluate saved campaign answers','/assessment?campaign_id='+owner))
    steps = [
        ('Choose a route', 'Choose what you want to compare',
         'Use local models, hosted APIs, or both in one campaign. For a fresh workload, choose arms, '
         'corpora and frameworks in Pipeline. To compare hosted answers against saved local answers, '
         'use Reuse local inputs for an API comparison in General. Sharing a seed alone does not prove matched inputs.',
         [('Choose target models', link('pipeline', 'target-models')),
          ('Choose a fresh workload', link('pipeline', 'input-corpora')),
          ('Reuse saved local inputs', link('general', 'retained-inputs'))]),
        ('Runtimes', 'Check model and framework readiness',
         'For local work, inspect the available GPUs, local services and installed framework environments in '
         'Runtimes. Reuse working installations and assessed model profiles. A newly downloaded or changed local '
         'model needs its text/image responsiveness assessment before security testing; an existing valid profile '
         'does not need repeated assessment. For hosted work, check the configured target and provider credentials '
         'in Config. Opening these pages does not install models or call a provider.',
         [('Inspect local hardware', link('runtimes', 'local-hardware')),
          ('Inspect framework runtimes', link('runtimes', 'framework-runtimes')),
          ('Open local-model assessment', tool('local_model_readiness')), ('Inspect provider credentials', '/config/secrets')]),
        ('Inputs', 'Choose a small, interpretable input selection',
         'For fresh inputs, select your corpora and attacks in Pipeline, then set the per-arm limit, '
         'sampling policy and seeds in Execution. Keep text and image counts explicit. For reused inputs, '
         'choose saved inputs in General -> Campaign workflow, select the source campaign and runs, then set request caps. Review campaign '
         'handles input extraction and the following preparation stages automatically. It makes no generation calls. '
         'HarmBench, T3MP3ST, NanoGCG and IDEATOR have additional preparation controls when selected. '
         'Follow the chosen attacker panel before measured execution; corpus selection alone does not prepare an attack.',
         [('Select arms and corpora', link('pipeline', 'input-corpora')),
          ('Select attack frameworks and preparation', link('pipeline', 'attack-frameworks')),
          ('Set limits and sampling', link('execution', 'sample-size-control')),
          ('Select saved source runs', link('general', 'retained-inputs'))]),
        ('Settings', 'Choose evaluation and realistic bounds',
         'Select your judges in Evaluation. Local models use their assessed serving profiles; scoring revision '
         'and placement are automatic. Hosted output allowances come from API target configuration and, for '
         'matched work, the model forecast. Keep Calculate call limits automatically enabled in Execution; '
         'target, judge and HTTP limits come from the workload projection. Manual overrides and technical recovery settings are collapsed. '
         'The call-start window is not an individual response timeout. Full model checksum scans are optional.',
         [('Choose judges', link('evaluation', 'evaluation-judges')), ('Set execution bounds', link('execution', 'execution-budgets')),
          ('Inspect local serving', link('execution', 'local-serving')), ('Configure hosted targets', '/config?file=api-targets#cfg-editor')]),
        ('Prepare', 'Prepare and review before making target calls',
         ('Click Prepare comparison and review in General. One progress page follows input extraction, forecasting, '
          'replay and execution preparation. Do not open or start the child jobs. The completed page shows the '
          'workload and cost bound, then offers the explicit collection start. Token counting can contact '
          'the provider but does not generate answers. Prepared and active work reopens this progress or review.') if matched else
         ('Use Compose & review. Automatic preparation starts directly. The console handles model planning, installed-model reuse, '
          'the no-call preflight and final execution preparation on one page. Existing exact preparation is reused. '
          'When ready, review the workload and click Start run, or Start experiment including connection checks. '
          'Keep Admission on Automatic: output locations, execution scope, software/source records and saved '
          'transport checks are supplied for campaigns and single runs. Technical text fields are optional '
          'Advanced overrides. Diagnostic probes started here save their connection checks automatically; '
          'the same progress page follows both. For older probes, Tools can select the completed probe by name. No receipt rows or hashes '
          'need copying. No separate plan/acquire/preflight buttons are required. Measured work '
          'needs valid transport evidence for each selected route/modality. Missing checks are derived and included '
          'in the reviewed start before measured collection. Your experiment settings stay intact. No separate '
          'probe setup or return to measured mode is required. Hosted review shows clearly labelled cost scenarios; '
          'these are not the matched-input route\'s counted monetary bounds.'),
         [('Open the next preparation controls', link('general', prepare_target)),
          ('Check transport evidence', link('admission', 'transport-evidence'))]),
        ('Run', 'Start once and follow the existing job',
         'Use the explicit start on the reviewed job or prepared collection. Hosted generation spends credits. '
         'Watch Campaign jobs or Activity; an active or retry-waiting job is not a reason to start a duplicate. '
         'If interrupted, inspect the original error and its offered continuation. Keep saved answers and '
         'recover only the unfinished stage. This guide never starts or resumes jobs for you.',
         [('Open review controls', link('general', 'prepared-collection' if params.get('retained_programs_job') else 'pipeline-review')),
          ('Open campaign jobs', '/jobs?campaign_id=' + owner if owner else link('general'))]),
        ('Judge', 'Judge each saved answer, not just its input',
         ('In General, click Review local judging. Preparation is automatic; the completed page offers Start or resume '
          'local judging. For Haiku choose the judge and input limit, then Review all-output Haiku judging. Its '
          'inventory, matching, counting and cost calculation run automatically before the final paid start. '
          'Missing answers and funding shortfalls remain explicit. Optional sampled paired comparison has its own '
          'limit and USD fields; these do not change all-output judging. Image assessments use the retained text proxy.') if matched else
         ('For direct Runner work, the selected judging cascade evaluates collected answers. A cascade may '
          'decide before reaching its model-backed judge; it is not two independent verdicts. Missing text, '
          'abstentions and invalid assessments must remain visible. Open Evaluate saved answers for any campaign, '
          'including finished or CLI-collected work. Choose the original local evaluator or Haiku, an answer limit '
          'and, for Haiku, a USD ceiling. Prepare assessment and review resolves saved outputs automatically, then '
          'Start or resume assessment evaluates them. Valid verdicts are skipped; missing answers and unsupported '
          'source contexts remain visible. A verdict for one model cannot be copied to another answer.'),
         judging_links + [('Inspect saved verdicts', campaign + '?section=judging' if owner else link('evaluation', 'evaluation-judges'))]),
        ('Results', 'Inspect coverage before comparing rates',
         'Results shows answers, effective generation settings, usage and truncation. Judging shows '
         'answer-specific decisions and coverage. Costs reports recorded attempts and charges, not the balance '
         'in your provider account. In Compare, the left campaign is fixed to the page you opened. Choose '
         'the right campaign, models, generation conditions and judging conditions; dependent choices load '
         'automatically. The generation scope names the campaign and model; options show modality, context and '
         'output allowance. Expand the selected condition for frameworks and corpora. Changing conditions '
         'does not merge judges: local choices distinguish rules-only from model-backed judging and show '
         'the recorded approximate-metrics mode. Read Selected judging settings below the selector; '
         'unindexed historical settings are not guessed. Changing conditions '
         'preserves the exact selected judge only when it is still available. Fields explain missing prerequisites or unavailable indexed records. Keep diagnostic '
         'probes separate. All models on either side compares model and generation-setting pairs separately, '
         'within each selected campaign, twelve pairs per page; expand a pair to inspect outcomes. All does not '
         'pool scores, choose the latest/best response or start jobs. For one model, All generation conditions '
         'includes its settings separately. Both single-model and All-model scopes offer highest/lowest output '
         'allowance, largest/smallest context and highest usable-response rate, applied per model within source '
         'filters. Ties remain separate. Rate-based selection is post-hoc, not attack success or a safety score; '
         'inspect its denominator and coverage. Missing judgments are not substituted. Keep '
         'missing responses and historical replacements explicit. Export figures and their counts '
         'from Overview and Judging, and the exact paired counts from Compare. Definition is the editable '
         'draft, not a replacement for each job\'s recorded execution settings. Stats -> Compare campaigns '
         'also links to individual measured-job comparisons: select two indexed jobs with separate output '
         'directories to inspect input overlap, outcomes, truncation and token usage. Shared recovery '
         'histories require campaign comparison; saved-output counts are not all scheduled inputs.',
         [(label, campaign + '?section=' + section if owner else link('general'))
          for label, section in [('Inspect results', 'results'), ('Compare matched inputs', 'compare'),
              ('Inspect costs', 'costs'), ('Coverage figures and exports', 'overview'), ('Inspect the saved draft', 'definition')]]
          + [('Compare individual measured jobs', '/stats?view=compare&scope=jobs')]),
        ('Human review', 'Evaluate saved answers or arrange independent review',
         'For active or finished campaigns, open Human evaluation and use Review saved answers for your own evaluation: choose Saved results, '
         'name the review, choose its rubric and source-cluster count, acknowledge sensitive content and click '
         'Prepare answers for review. The evaluation form opens automatically after preparation. Read the prompt, '
         'images and answer, use Next through the rating dimensions, then Save evaluation. Review progress and '
         'export reopens your saved work and downloads personal evaluations, including unfinished items. '
         'This path has no study-arrangement or enrollment fields; personal ratings are not independent evidence. '
         'For the separate Independent two-rater study option, choose Saved results, '
         'name the study, select the rubric and sample, record the actual participation and ethics arrangements, '
         'then review and prepare the sample. Inspect prompts, images and workload before creating the study. '
         'Assign qualified independent raters and an adjudicator, and share their individual review links. '
         'After ratings and adjudication, export and analyze the completed sample. Setup does not create human '
         'verdicts; automated judging and SVM predictions cannot replace actual raters.',
         [('Open human-evaluation wizard', '/human-evaluation?campaign_id=' + owner if owner else link('general')),
          ('Inspect campaign judging coverage', campaign + '?section=judging' if owner else link('evaluation'))]),
        ('SVM analysis', 'Optional: analyze retained responses with SVMs',
         'Open the campaign SVM analysis tab. Choose the saved local input source, the campaign whose inputs '
         'define the matched population and a recorded Haiku condition. Include matching local answers if desired, '
         'then click Start classifier study. Input extraction, dataset export, grouped evaluation and reusable '
         'classifier packaging happen automatically as one job. No database, output directory or intermediate '
         'file needs entering. Saved analyses shows answer/group counts, task status, held-out macro-F1 and named '
         'links to complete reports. Stats -> SVM results shows saved-study scores, baselines, class/group support, '
         'recorded confidence intervals and filtered CSV/SVG exports without retraining. Resume unfinished analysis reuses completed '
         'stages. The three tasks are harmful compliance, over-refusal and local/Haiku disagreement. '
         'A few demonstration answers are too small for meaningful training and held-out evaluation. '
         'The current study supports static text, not arbitrary image or live-attack data. '
         'Prediction scores are uncalibrated margins, not human verdicts or safety probabilities. No target or judge call is made.',
         [('Open SVM analysis', '/analysis?campaign_id='+owner if owner else '/campaigns'),
          ('Inspect SVM results', '/stats?view=svm&campaign_id='+owner if owner else '/stats?view=svm'),
          ('Inspect existing analysis jobs', '/jobs?campaign_id=' + owner if owner else '/jobs')]),
        ('Recovery', 'Recover the unfinished stage without duplicating work',
         'Open the original job and read its error and saved outputs. Continue an interrupted prepared collection '
         'from its offered continuation; do not create a second campaign. For saved-output judging, reuse the '
         'same preparation and Start or resume action. A transport retry wait is not a model refusal. Keep '
         'missing, truncated and invalid outcomes visible rather than silently relabelling them. After recovery, '
         'check the replacement and its own judgments in Results. Refresh only transport evidence actually '
         'affected by expiration or changed execution conditions, not every runtime or successful probe.',
         [('Inspect campaign jobs', '/jobs?campaign_id=' + owner if owner else '/jobs'),
          ('Inspect campaign activity', campaign + '?section=activity' if owner else link('general'))])
    ]
    if params.get('work_kind') == 'campaign' or owner:
        replacements = {
            'Prepare': ('Review the complete campaign',
                'In General, choose Campaign workflow inputs and assessment, then click Review campaign. '
                'The same action handles installed corpora/frameworks and saved local inputs. Preparation runs '
                'automatically without target or judge generation. Token counting may contact the selected provider. '
                'Review required diagnostics, measured requests, output allowances and collection/Haiku spending limits. '
                'Keep Admission on Automatic; no receipt rows or preparation jobs need coordinating.',
                [('Open campaign choices',link('general','campaign-workflow')),('Review the campaign',link('general','pipeline-review')),
                 ('Inspect automatic connection settings',link('admission','transport-evidence'))]),
            'Run': ('Start once and follow campaign progress',
                'Click Start campaign on the completed review. Required checks, collection and selected saved-answer '
                'assessment proceed on one progress page. Stop campaign prevents later stages and stops active work. '
                'Resume campaign retains completed answers and judgments. Prepared and active work reopens the page. '
                'Technical jobs are for inspection, not required handoffs. The Guide itself never starts work.',
                [('Open prepared and active work',link('general','pipeline-review')),('Open campaign',campaign)]),
            'Judge': ('Choose assessment before collection',
                'Choose local assessment and optional independent Haiku assessment in General -> Campaign workflow. '
                'They run after collection without another preparation/start action. Haiku has a separate spending '
                'ceiling and evaluates each model answer independently; images use their saved text proxy. Existing '
                'valid verdicts are reused. Missing outputs, exclusions and invalid verdicts remain visible. '
                'Evaluate saved answers remains available for older campaigns or a deliberately changed assessment.',
                [('Choose automatic assessment',link('general','campaign-workflow')),
                 ('Inspect saved verdicts',campaign+'?section=judging'),
                 ('Assess existing saved answers','/assessment?campaign_id='+owner if owner else link('general'))]),
        }
        steps = [(short,*replacements[short]) if short in replacements else (short,title,text,links)
                 for short,title,text,links in steps]
    positions = {step[0]: index for index, step in enumerate(steps)}
    stage = 'Choose a route' if not (local or hosted) else 'Inputs' if not (params.get('corpora') or matched) else 'Settings'
    notice = 'Suggested next step from your saved settings.'
    actions = []
    if owner:
        actions = app.db.workspace_activity(owner) or []
    latest = next((row for row in actions if row['member_kind'] == 'job'), None)
    if latest is not None and latest['state'] in {'queued', 'starting', 'running', 'retry_wait', 'retry_waiting', 'failed', 'aborted', 'interrupted'}:
        state = latest['state']
        stage = 'Recovery' if state in {'failed', 'aborted', 'interrupted'} else 'Run'
        notice = 'The latest console job is recorded as ' + state + '. Open that job before starting or preparing another copy.'
        steps[positions[stage]][3].insert(0, ('Open the current job', '/jobs/' + quote(latest['member_id'], safe='')))
    elif latest is not None and latest['state'] == 'complete':
        command = dict(latest).get('command', '')
        judging_preparation = command in {'retained_native_judge_prepare', 'retained_response_judge_pair',
            'retained_judge_inventory', 'retained_inventory_judge_items'} or (
            latest['member_id'] == params.get('retained_inventory_plan_job'))
        stage = ('Judge' if judging_preparation else 'SVM analysis' if command == 'response_svm' else
                 'Results' if latest['role'] in {'judging', 'analysis'} else 'Judge' if latest['role'] == 'collection' else 'Prepare')
        notice = 'The latest console job completed. Check what that job covered; this does not mean the whole campaign is finished.'
    elif matched:
        stage = 'Prepare'
    all_operations = getattr(app, '_operations', {})
    operations = sorted((row for row in all_operations.values()
        if not row.get('campaign_parent') and row['params'].get('campaign_id') == owner
        and row['status'] in {'preparing', 'ready', 'failed', 'stopped','complete'}),
        key=lambda row:row.get('created_at', 0))
    if operations and (operations[-1]['status'] == 'preparing' or latest is None
            or operations[-1].get('created_at', 0) >= (dict(latest).get('started_at') or 0)
            or latest['member_id'] in operations[-1]['jobs']):
        current = operations[-1]
        stage = 'Recovery' if current['status'] in {'failed', 'stopped'} else 'Prepare'
        notice = ('Preparation is '+current['status']+'. Open the operation, not its internal child jobs. '
            'Completed preparation still requires an explicit execution start.')
        steps[positions[stage]][3].insert(0, ('Open prepared or active work', '/operations/'+current['id']))
        if current['kind'] == 'campaign':
            stage = ('Results' if current['status'] == 'complete' else 'Recovery' if current['status'] in {'failed','stopped'}
                     else 'Run' if current.get('execution_authorized') else 'Prepare')
            notice = 'Campaign is '+current['status']+'. Follow its progress page; internal jobs need no separate starts.'
            steps[positions[stage]][3].insert(0,('Open campaign progress','/operations/'+current['id']))
    if latest is not None and latest['role'] == 'collection' and not matched and params.get('mode') == 'attestation_probe':
        notice += ' A diagnostic probe is not a measured result; finish its transport evidence before measured execution.'
        if latest['state'] == 'complete':
            stage = 'Prepare'
    return steps, positions[stage], notice, route


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
        "<p>This is a workflow companion, not a preset recipe. The small-campaign documents provide "
        "the specific models, field values and example counts; this guide does not fill them in.</p>"
        "<details class='campaign-guide-topics'><summary>Browse all " + str(len(steps)) + " topics</summary>"
        "<div class='campaign-guide-steps' role='group' aria-label='Guide steps'>" + navigation + '</div></details>'
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
let current=Number(root.dataset.guideInitial),focusBefore,restoreFocus=true;
function show(index,focus=false){current=Math.max(0,Math.min(index,panels.length-1));
panels.forEach((p,i)=>p.hidden=i!==current);steps.forEach((b,i)=>{if(i===current)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});
back.disabled=current===0;next.textContent=current===panels.length-1?'Done':'Next';
root.querySelector('[data-guide-progress]').textContent='Step '+(current+1)+' of '+panels.length;
if(focus)panels[current].focus();}
const key='ura-campaign-guide:'+root.dataset.guideKey;
function launch(){if(dialog.open||!dialog.showModal||window.uraBusy?.isBusy())return;
restoreFocus=true;focusBefore=document.activeElement;show(current);dialog.showModal();
try{sessionStorage.setItem(key,'shown');}catch(e){}}
function close(){dialog.close();}
open.addEventListener('click',launch);root.querySelector('[data-guide-close]').addEventListener('click',close);
dialog.addEventListener('close',()=>{if(restoreFocus&&focusBefore?.isConnected)focusBefore.focus();});
dialog.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{restoreFocus=false;close();}));
steps.forEach((b,i)=>b.addEventListener('click',()=>show(i,true)));
back.addEventListener('click',()=>show(current-1,true));
next.addEventListener('click',()=>current===panels.length-1?close():show(current+1,true));
function enabled(){const kind=document.querySelector('[name=work_kind]:checked');
return choice?choice.checked&&(!kind||kind.value==='campaign'):root.dataset.guideEnabled==='true';}
function sync(){open.hidden=!enabled();if(!enabled()&&dialog.open)close();}
if(choice)choice.addEventListener('change',()=>{sync();if(enabled())launch();});
document.querySelectorAll('[name=work_kind]').forEach(e=>e.addEventListener('change',sync));
show(current);sync();
document.addEventListener('DOMContentLoaded',()=>{sync();let seen=false;
try{seen=sessionStorage.getItem(key)==='shown';}catch(e){}
if(enabled()&&!seen)launch();},{once:true});
})();</script>"""
