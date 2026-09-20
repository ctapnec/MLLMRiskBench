"""Study management and review forms within the shared console layout."""

from __future__ import annotations

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import html
import json
import os
from pathlib import Path
import secrets
from urllib.parse import quote

from .human_review_store import HumanReviewStore, COMMON
from .ui import _page
from .workspace_charts import EXPORT_SCRIPT


def _field(name, label, value="", kind="text", required=True):
    return (
        "<label class='campaign-field'>"
        + html.escape(label)
        + "<input name='"
        + name
        + "' type='"
        + kind
        + "' value='"
        + html.escape(str(value), quote=True)
        + "'"
        + (" required" if required else "")
        + "></label>"
    )


_REVIEW_STYLE = """<style>
.review-stack{display:grid;gap:1.25rem;max-width:960px;margin:0 auto}.review-card{padding:1.5rem;border:1px solid var(--line);border-radius:12px;min-width:0;background:var(--card);box-shadow:var(--shadow)}
.review-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,240px),1fr));gap:1rem}.review-text{white-space:pre-wrap;overflow-wrap:anywhere;max-height:42vh;overflow:auto;line-height:1.6;padding:.9rem;background:var(--soft);border-radius:8px}
.review-card textarea{width:100%;min-height:5rem}.review-card label{display:flex;flex-direction:column;gap:.4rem;margin:.7rem 0}.review-card img,.review-card video{max-width:100%;max-height:55vh;object-fit:contain}.review-card audio{max-width:100%}
.review-actions{display:flex;flex-wrap:wrap;gap:.75rem;margin-top:1rem}.review-error{color:var(--red,#b42318);white-space:pre-wrap}.review-card select{max-width:100%}.review-status{min-height:1.6em}#review-status:empty,#review-body[hidden]{display:none}
.review-steps{display:flex;flex-wrap:wrap;gap:.5rem;margin:1rem 0}.review-steps button{padding:.55rem .75rem}.review-steps [aria-current=step]{outline:2px solid currentColor;font-weight:700}.review-step{min-height:180px}.review-step[hidden]{display:none}.review-step h3{margin-top:.5rem}.review-reference{margin-bottom:1rem}.review-wizard-footer{display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;margin-top:1.5rem}.review-wizard-footer progress{flex:1;min-width:120px}.review-help{line-height:1.6;max-width:75ch}
.review-card input:not([type=checkbox]),.review-card select,.review-card textarea{display:block;width:100%;min-width:0;font:inherit;line-height:1.5;color:var(--ink);background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:.7rem .85rem;min-height:2.75rem;margin:0}
.review-card .review-check,.review-card label:has(>input[type=checkbox]){display:flex;flex-direction:row;align-items:flex-start;gap:.7rem;font-weight:400}.review-card input[type=checkbox]{flex:0 0 auto;margin:.25rem 0 0}
.review-card form{display:grid;gap:.8rem;margin:1rem 0 0}.review-card h2{margin-bottom:1rem}.review-card .review-step{padding:1rem 0}.review-steps button{background:var(--soft);color:var(--muted);border:1px solid var(--line);font-weight:500}.review-steps button[aria-current=step]{background:var(--accent);color:var(--accent-ink);outline:0}.review-card [hidden]{display:none!important}
.review-card button:focus-visible,.review-card input:focus-visible,.review-card select:focus-visible,.review-card textarea:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.review-card dl{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:.5rem 1rem}.review-card dd{margin:0;overflow-wrap:anywhere}.review-wizard-footer{border-top:1px solid var(--line);padding-top:1rem}.review-card summary{cursor:pointer;font-weight:600}
@media(max-width:540px){.review-card{padding:1rem}.review-steps{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.review-steps button{text-align:left;font-size:.8rem}.review-card dl{grid-template-columns:minmax(0,1fr)}.review-card dd{margin-bottom:.5rem}}
#review-intro > select{margin:1rem 0}#review-intro > button{margin-top:.5rem}#review-intro > button:last-child{background:var(--soft);color:var(--ink);border:1px solid var(--line)}
</style>"""


_REVIEW_SCRIPT = _ui_template("""<script>
(function(){
const base=location.pathname.replace(/\\/$/,''),status=document.getElementById('review-status');
let current=null,revision=0,dirty=false,timer=null,queue=[],personalReview=false;
function node(tag,text,parent){let e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(parent)parent.append(e);return e;}
async function request(action,values){
 const end=window.uraBusy.begin([[js:human_review_pages.waiting_for_review_server]]),controller=new AbortController();
 const timeout=setTimeout(()=>controller.abort(),30000);
 try{
  let response;
  try{response=await fetch(base+action,{method:values?'POST':'GET',headers:values?{'Content-Type':'application/x-www-form-urlencoded'}:{},body:values?new URLSearchParams(values):undefined,signal:controller.signal});}
  catch(e){if(controller.signal.aborted)throw e;throw Error([[js:human_review_pages.network_error]]);}
  let value;
  try{value=await response.json();}catch(e){if(controller.signal.aborted)throw e;throw Error(response.ok?[[js:human_review_pages.unreadable_response]]:window.uraFormat([[js:human_review_pages.request_failed_http]],{status:response.status}));}
  if(!response.ok)throw Error(value?.error||[[js:human_review_pages.request_failed]]);
  if(!value||typeof value!=='object'||Array.isArray(value))throw Error([[js:human_review_pages.unreadable_response]]);
  return value;
 }catch(e){if(controller.signal.aborted)throw Error([[js:human_review_pages.request_timed_out]]);throw e;}
 finally{clearTimeout(timeout);end();}
}
function error(e){status.textContent=e.message;status.className=\"review-status review-error\";}
function values(){let result={};document.querySelectorAll('[data-rating]').forEach(e=>{let key=e.dataset.rating;if(e.type==='checkbox')result[key]=e.checked;else if(key==='confidence')result[key]=e.value?Number(e.value):'';else result[key]=e.value;});return result;}
async function save(submit=false,defer=false){if(!current)return;const media=document.querySelector('[data-rating=media_viewed]');if(submit&&media&&!media.checked){media.setAttribute('aria-invalid','true');document.getElementById('media-viewed-help').hidden=false;media.focus();return;}clearTimeout(timer);try{status.className='review-status';status.textContent=[[js:human_review_pages.saving]];let result=await request('/rating',{item:current,revision:String(revision),value:JSON.stringify(values()),submit:submit?'1':'',defer:defer?'1':''});revision=result.revision;dirty=false;status.textContent=submit?(personalReview?[[js:human_review_pages.personal_evaluation_saved]]:[[js:human_review_pages.submitted_independently]]):defer?[[js:human_review_pages.deferred_for_remediation]]:[[js:human_review_pages.draft_saved]];if(submit||defer)await load();}catch(e){dirty=true;error(e);}}
function changed(){dirty=true;clearTimeout(timer);timer=setTimeout(()=>save(),900);}
function choices(container,allowed,saved){const title=window.uraLabel;Object.entries(allowed).forEach(([key,items])=>{let label=node('label',title(key),container),select=node('select',undefined,label);select.dataset.rating=key;node('option',[[js:human_review_pages.choose]],select).value='';items.forEach(v=>node('option',window.uraLabel(v),select).value=v);select.value=saved[key]||'';select.onchange=changed;});}
function assessmentWizard(body,item){
const definitions={refusal_label:[[[js:human_review_pages.refusal]],[[js:human_review_pages.does_the_answer_decline_the_requested_task_use_uncertain_if_the_r]]],harmfulness_label:[[[js:human_review_pages.harmfulness]],[[js:human_review_pages.would_the_response_materially_facilitate_the_prohibited_harm_unde]]],convincingness_label:[[[js:human_review_pages.convincingness]],[[js:human_review_pages.are_harmful_claims_or_instructions_plausible_enough_to_influence]]],specificity_label:[[[js:human_review_pages.specificity]],[[js:human_review_pages.does_the_answer_provide_concrete_actionable_details_or_only_gener]]],task_label:[[[js:human_review_pages.task_decision]],[[js:human_review_pages.answer_this_source_defined_classification_task_using_its_policy_a]]],parse_status_label:[[[js:human_review_pages.answer_format]],[[js:human_review_pages.does_the_saved_response_contain_one_clean_task_label_ambiguous_or]]]};
const labels={};body.querySelectorAll('[data-rating]').forEach(e=>labels[e.dataset.rating]=e.closest('label'));
const first=Object.values(labels)[0];if(!first)return;const initial=Array.from(body.children);const split=initial.indexOf(first);
const reference=node('details');reference.className='review-reference';node('summary',[[js:human_review_pages.review_prompt_policy_media_and_saved_response]],reference);initial.slice(0,split).forEach(e=>reference.append(e));
const actions=body.querySelector('.review-actions'),panels=[],titles=[[[js:human_review_pages.context]]];let context=node('section');context.className='review-step';node('h3',[[js:human_review_pages.1_read_the_evaluation_context]],context);node('p',[[js:human_review_pages.inspect_the_policy_prompt_every_required_asset_and_the_complete_s]],context).className='review-help';panels.push(context);
Object.entries(definitions).forEach(([key,[title,help]])=>{if(!labels[key])return;let panel=node('section');panel.className='review-step';node('h3',title,panel);node('p',help,panel).className='review-help';panel.append(labels[key]);titles.push(title);panels.push(panel);});
const final=node('section');final.className='review-step';node('h3',personalReview?[[js:human_review_pages.review_and_save]]:[[js:human_review_pages.review_and_submit]],final);node('p',personalReview?[[js:human_review_pages.check_and_save_your_personal_evaluation_you_can_return_to_edit_it]]:[[js:human_review_pages.check_your_independent_decisions_submission_fixes_this_rating_dis]],final).className='review-help';
if(labels.label){node('p',[[js:human_review_pages.overall_decision_safe_harmful_assistance_violation_justified_refu]],final);final.append(labels.label);}['confidence','notes','media_viewed'].forEach(k=>{if(labels[k])final.append(labels[k]);});if(labels.media_viewed){const help=node('p',[[js:human_review_pages.before_saving_the_final_evaluation_view_every_image_audio_or_vide]],final);help.id='media-viewed-help';help.className='review-error';help.setAttribute('role','alert');help.hidden=true;}let summary=node('dl',undefined,final);summary.setAttribute('aria-label',[[js:human_review_pages.your_assessment_summary]]);
titles.push([[js:human_review_pages.review]]);panels.push(final);const optout=node('details');node('summary',[[js:human_review_pages.cannot_assess_this_item_category_opt_out]],optout);if(labels.defer_reason)optout.append(labels.defer_reason);
const optoutActions=node('div',undefined,optout),finalActions=node('div',undefined,final);optoutActions.className=finalActions.className='review-actions';
let saveButton=null;if(actions){for(const button of Array.from(actions.children)){if(button.dataset.reviewAction==='defer')optoutActions.append(button);else if(button.dataset.reviewAction==='draft')saveButton=button;else finalActions.append(button);}}
body.replaceChildren();const steps=node('div',undefined,body);steps.className='review-steps';steps.setAttribute('role','navigation');steps.setAttribute('aria-label',[[js:human_review_pages.assessment_steps]]);body.append(reference);panels.forEach(p=>body.append(p));body.append(optout);
let index=0;const buttons=titles.map((title,i)=>{let button=node('button',(i+1)+'. '+title,steps);button.type='button';button.onclick=()=>go(i);return button;});let footer=node('div',undefined,body);footer.className='review-wizard-footer';let back=node('button',[[js:human_review_pages.back]],footer),progress=node('progress',undefined,footer),next=node('button',[[js:human_review_pages.next]],footer);if(saveButton)footer.append(saveButton);progress.max=panels.length;progress.setAttribute('aria-label',[[js:human_review_pages.assessment_progress]]);
function render(){panels.forEach((p,i)=>p.hidden=i!==index);buttons.forEach((b,i)=>{if(i===index)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});back.disabled=index===0;next.hidden=index===panels.length-1;progress.value=index+1;reference.open=index===0;summary.replaceChildren();Object.entries(values()).filter(([k])=>k in definitions).forEach(([k,v])=>{node('dt',definitions[k][0],summary);node('dd',v?window.uraLabel(v):[[js:human_review_pages.not_answered]],summary);});}
async function go(i){if(i<0||i>=panels.length)return;if(dirty){await save();if(dirty)return;}index=i;render();panels[index].querySelector('h3').setAttribute('tabindex','-1');panels[index].querySelector('h3').focus();}
back.onclick=()=>go(index-1);next.onclick=()=>go(index+1);render();
}
async function show(id){if(dirty){await save();if(dirty)return;}try{let data=await request('?item='+encodeURIComponent(id));current=id;const body=document.getElementById('review-body');body.replaceChildren();let item=data.item;
node('h2',[[js:human_review_pages.assessment]],body);node('p',personalReview?[[js:human_review_pages.read_the_prompt_required_media_and_saved_answer_then_use_the_asse]]:[[js:human_review_pages.apply_the_supplied_policy_do_not_consult_automated_judgments_or_o]],body);
[[[[js:human_review_pages.policy]],item.source_policy_instruction],[[[js:human_review_pages.assessment_purpose]],item.source_policy_intended_metric],[[[js:human_review_pages.prompt]],item.prompt],[[[js:human_review_pages.saved_response]],item.response]].forEach(([title,text])=>{node('h3',title,body);node('div',text||[[js:human_review_pages.not_provided]],body).className='review-text';});
let mediaOk=true;item.media.forEach(m=>{if(!m.available){node('p',[[js:human_review_pages.required_media_unavailable_defer_this_item_do_not_guess]],body).className='review-error';mediaOk=false;return;}let e=node(m.modality==='image'?'img':m.modality,undefined,body);if(m.modality==='image')e.alt=[[js:human_review_pages.assigned_prompt_image]];else e.controls=true;e.src=base+'/media?item='+encodeURIComponent(id)+'&index='+m.index;e.onerror=()=>{mediaOk=false;node('p',[[js:human_review_pages.media_loading_failed_do_not_submit_this_item]],body).className='review-error';let submit=document.getElementById('submit-rating');if(submit)submit.disabled=true;};});
if(data.role==='adjudicator'){item.independent_ratings.forEach((r,i)=>{node('h3',[[js:human_review_pages.independent_rating]]+(i+1),body);node('pre',JSON.stringify(r.value,null,2),body).className='review-text';});choices(body,item.choices,{});node('label',[[js:human_review_pages.reason_for_the_final_decision]],body).append(node('textarea'));const reason=body.querySelector('textarea');let button=node('button',[[js:human_review_pages.submit_adjudication]],body);button.onclick=async()=>{try{await request('/adjudicate',{item:id,value:JSON.stringify(values()),rationale:reason.value});dirty=false;await load();}catch(e){error(e);}};body.querySelectorAll('[data-rating]').forEach(e=>e.onchange=null);return;}
revision=item.rating.revision;const saved=item.rating.value;choices(body,item.choices,saved);let label=node('label',[[js:human_review_pages.confidence]],body),select=node('select',undefined,label);select.dataset.rating='confidence';node('option',[[js:human_review_pages.choose]],select).value='';[1,2,3,4,5].forEach(n=>node('option',n+' / 5',select).value=n);select.value=saved.confidence||'';select.onchange=changed;
let notesLabel=node('label',[[js:human_review_pages.notes_optional_including_any_explanation_for_deferral]],body),notes=node('textarea',undefined,notesLabel);notes.dataset.rating='notes';notes.value=saved.notes||'';notes.oninput=changed;
let deferLabel=node('label',[[js:human_review_pages.why_can_you_not_assess_this_item]],body),defer=node('select',undefined,deferLabel);defer.dataset.rating='defer_reason';node('option',[[js:human_review_pages.choose_a_reason]],defer).value='';const reasons=[[[js:human_review_pages.required_image_audio_or_video_is_unavailable]],[[js:human_review_pages.prompt_or_response_is_unreadable]],[[js:human_review_pages.policy_or_task_is_unclear]],[[js:human_review_pages.outside_my_language_or_subject_expertise]],[[js:human_review_pages.sensitive_content_category_opt_out]],[[js:human_review_pages.need_a_break_defer_until_later]],[[js:human_review_pages.other_explain_in_notes]]];if(saved.defer_reason&&!reasons.includes(saved.defer_reason))reasons.push(saved.defer_reason);reasons.forEach(v=>node('option',v,defer).value=v);defer.value=saved.defer_reason||'';defer.onchange=changed;
if(item.media.length){let l=node('label',[[js:human_review_pages.i_viewed_every_required_asset]],body),e=node('input',undefined,l);e.type='checkbox';e.dataset.rating='media_viewed';e.required=true;e.setAttribute('aria-describedby','media-viewed-help');e.checked=Boolean(saved.media_viewed);e.onchange=()=>{e.removeAttribute('aria-invalid');document.getElementById('media-viewed-help').hidden=true;changed();};}
const actions=node('div',undefined,body);actions.className='review-actions';const draft=node('button',[[js:human_review_pages.save_draft]],actions);draft.dataset.reviewAction='draft';draft.onclick=()=>save();let submit=node('button',personalReview?[[js:human_review_pages.save_evaluation]]:[[js:human_review_pages.submit_independent_rating]],actions);submit.id='submit-rating';submit.disabled=!mediaOk;submit.onclick=()=>save(true);const deferButton=node('button',[[js:human_review_pages.defer_opt_out_of_this_item]],actions);deferButton.dataset.reviewAction='defer';deferButton.onclick=()=>save(false,true);
if(item.rating.state==='submitted'&&!personalReview){body.querySelectorAll('select,textarea,input,button').forEach(e=>e.disabled=true);node('p',[[js:human_review_pages.submitted_rating_is_fixed_it_remains_separate_from_adjudication]],body);}
assessmentWizard(body,item);
}catch(e){error(e);}}
async function load(){try{let data=await request('/data'),intro=document.getElementById('review-intro'),body=document.getElementById('review-body');personalReview=data.role==='personal';current=null;body.replaceChildren();intro.replaceChildren();node('h1',personalReview?[[js:human_review_pages.personal_evaluation]]:[[js:human_review_pages.independent_human_evaluation]],intro);if(personalReview){node('p',[[js:human_review_pages.your_own_review_of_saved_answers_these_evaluations_do_not_count_a]],intro);node('a',[[js:human_review_pages.review_progress_and_export]],intro).href=data.summary_url;}
if(!data.consented){node('p',data.consent,intro).className='review-text';node('p',[[js:human_review_pages.time_and_compensation]]+data.compensation,intro);node('p',[[js:human_review_pages.stop_escalation_contact]]+data.stop_contact,intro);let l=node('label',[[js:human_review_pages.i_understand_the_sensitive_content_warning_participation_terms_an]],intro),c=node('input',undefined,l);c.type='checkbox';let b=node('button',[[js:human_review_pages.consent_and_begin]],intro);b.onclick=async()=>{if(!c.checked){error(Error([[js:human_review_pages.record_consent_before_beginning]]));return;}try{await request('/consent',{agree:'1'});await load();}catch(e){error(e);}};return;}
queue=data.queue;let done=queue.filter(q=>q.state==='submitted').length;node('p',done+' / '+queue.length+' '+(personalReview?[[js:human_review_pages.evaluations_saved]]:data.role==='adjudicator'?[[js:human_review_pages.disagreements_adjudicated]]:[[js:human_review_pages.ratings_submitted]])+[[js:human_review_pages.no_automated_labels_are_shown]],intro);let select=node('select',undefined,intro);select.setAttribute('aria-label',[[js:human_review_pages.assigned_item]]);queue.forEach((q,i)=>{let o=node('option',[[js:human_review_pages.item]]+(i+1)+' - '+window.uraLabel(q.state),select);o.value=q.id;});select.onchange=()=>show(select.value);if(!personalReview){let exit=node('button',[[js:human_review_pages.withdraw_from_further_review]],intro);exit.onclick=async()=>{if(!confirm([[js:human_review_pages.withdraw_from_further_reviewing_contact_the_study_operator_about]]))return;try{await request('/withdraw',{confirm:'1'});dirty=false;intro.replaceChildren();node('p',[[js:human_review_pages.further_review_is_disabled_contact]]+data.stop_contact,intro);body.replaceChildren();}catch(e){error(e);}};}
const next=queue.find(q=>q.state!=='submitted')||queue[0];if(next){select.value=next.id;await show(next.id);}else node('p',[[js:human_review_pages.no_eligible_items_currently_await_your_review]],body);
}catch(e){error(e);}}
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue='';}});load();
})();</script>""")


class HumanReviewPagesMixin:
    def _human_store(self):
        with self._app_lock:
            if not hasattr(self, "_human_reviews"):
                self._human_reviews = HumanReviewStore(
                    self.state_dir / "console.db",
                    self.state_dir / "human-reviews",
                    allowed_roots=(self.results_root, self.state_dir),
                    media_roots=[
                        p for p in os.environ.get("URA_MEDIA_ROOTS", "").split(os.pathsep) if p
                    ],
                )
            return self._human_reviews

    def _human_index(self, campaign="", kind="personal"):
        from .human_review_setup import setup_body

        if campaign:
            self.db.require_workspace(campaign)
        cards = "".join(
            "<li><a href='/human-evaluation/"
            + r["id"]
            + "'>"
            + html.escape(r["name"])
            + "</a> ("
            + (
                _ui_text("human_review_pages.personal_review")
                if r["review_kind"] == "personal"
                else _ui_text("human_review_pages.independent_study")
            )
            + "; "
            + html.escape(_ui_label(r["mode"]))
            + ")</li>"
            for r in self._human_store().studies(campaign)
        )
        banner = self._campaign_banner(campaign) if campaign else ""
        content = (
            _REVIEW_STYLE
            + _ui_template(
                "<div class='review-stack'><header><h1>[[text:human_review_pages.human_evaluation]]</h1>"
            )
            + banner
        )
        content += _ui_template(
            "<p>[[text:human_review_pages.evaluate_saved_answers_yourself_or_organize_a_separate_independen]]</p></header>"
        )
        if cards:
            content += (
                _ui_template(
                    "<section class='review-card'><h2>[[text:human_review_pages.existing_studies]]</h2><ul>"
                )
                + cards
                + "</ul></section>"
            )
        return _page(
            _ui_text("human_review_pages.human_evaluation"),
            content + setup_body(self, campaign, _field, kind=kind) + "</div>",
            active=_ui_text("human_review_pages.campaigns"),
        )

    def _human_study_page(self, study):
        summary = self._human_store().summary(study)
        info = summary["study"]
        counts = summary["counts"]
        if info["metadata"].get("review_kind") == "personal":
            body = (
                _REVIEW_STYLE
                + "<div class='review-stack'><section class='review-card'><h1>"
                + html.escape(info["name"])
                + _ui_template(
                    "</h1><p>[[text:human_review_pages.personal_evaluation_of_saved_answers_not_independent_human_assess]]</p>"
                )
                + (
                    "<p>"
                    + html.escape(
                        _ui_text(
                            "human_review_pages.review_progress_counts",
                            submitted=counts["submitted"],
                            total=counts["outputs"],
                            deferred=counts["deferred"],
                        )
                    )
                    + "</p>"
                )
                + "<div class='review-actions' id='campaign-exports'><a class='button' href='/review/"
                + info["metadata"]["personal_token"]
                + _ui_template(
                    "'>[[text:human_review_pages.open_evaluation_form]]</a><a class='button ghost' data-campaign-export download='personal-evaluations.csv' href='/human-evaluation/"
                )
                + study
                + _ui_template(
                    "/personal.csv'>[[text:human_review_pages.download_personal_evaluations]]</a></div><p>[[text:human_review_pages.the_csv_includes_pending_and_deferred_items_personal_decisions_ar]]</p>"
                )
                + "<a href='/human-evaluation?campaign_id="
                + quote(info["campaign"])
                + _ui_template(
                    "'>[[text:human_review_pages.back_to_campaign_reviews]]</a></section></div>"
                )
            )
            return _page(
                _ui_text("human_review_pages.personal_human_evaluation"),
                body + "<p id='campaign-export-status' role='status'></p>" + EXPORT_SCRIPT,
                active=_ui_text("human_review_pages.campaigns"),
            )
        members = "".join(
            "<li>"
            + html.escape(r["id"])
            + " - "
            + html.escape(
                _ui_text("human_review_pages.independent_rater")
                if r["role"] == "rater"
                else _ui_text("human_review_pages.adjudicator")
            )
            + (
                _ui_text("human_review_pages.withdrawn")
                if r["withdrawn"]
                else _ui_text("human_review_pages.consent_recorded")
                if r["consent"]
                else _ui_text("human_review_pages.consent_pending")
            )
            + "</li>"
            for r in summary["reviewers"]
        )
        dimensions = (
            COMMON if info["mode"] == "common" else {"task_label": None, "parse_status_label": None}
        )
        qualifications = "".join(
            "<label>"
            + html.escape(_ui_label(k))
            + _ui_template(
                " [[text:human_review_pages.correct_answers_out_of_20]]<select name='correct_"
            )
            + k
            + _ui_template(
                "' required><option value=''>[[text:human_review_pages.choose_score]]</option>"
            )
            + "".join(
                "<option value='" + str(n) + "'>" + str(n) + " / 20</option>" for n in range(21)
            )
            + "</select></label>"
            for k in dimensions
        )
        body = (
            _REVIEW_STYLE
            + "<div class='review-stack'><h1>"
            + html.escape(info["name"])
            + "</h1><p><a href='/human-evaluation?campaign_id="
            + quote(info["campaign"])
            + _ui_template("'>[[text:human_review_pages.all_studies]]</a></p>")
        )
        body += (
            _ui_template(
                "<section class='review-card'><h2>[[text:human_review_pages.review_progress]]</h2><dl>"
            )
            + "".join(
                "<dt>" + html.escape(_ui_label(k)) + "</dt><dd>" + str(v) + "</dd>"
                for k, v in counts.items()
            )
            + "</dl><p>"
        )
        body += (
            _ui_text(
                "human_review_pages.complete_ratings_are_ready_for_the_existing_audit_analysis_this_i"
            )
            if summary["ready_for_analysis"]
            else _ui_text(
                "human_review_pages.incomplete_human_evidence_finish_independent_ratings_unresolved_i"
            )
        ) + "</p></section>"
        body += (
            _ui_template(
                "<section class='review-card'><h2>[[text:human_review_pages.assign_reviewers_and_issue_their_links]]</h2><ul>"
            )
            + members
            + _ui_template(
                "</ul><ol><li>[[text:human_review_pages.use_a_pseudonym_for_example_rater_a_not_an_api_model_name]]</li><li>[[text:human_review_pages.select_independent_rater_for_the_first_two_people_and_adjudicator]]</li><li>[[text:human_review_pages.record_their_actual_scores_from_the_separate_20_item_qualificatio]]</li><li>[[text:human_review_pages.each_person_follows_that_link_consents_and_selects_ratings_one_di]]</li></ol><p>[[text:human_review_pages.the_qualification_exercise_is_separate_from_this_study_sample_its]]</p>"
            )
        )
        body += (
            "<form method='post' action='/human-evaluation/"
            + study
            + "/enroll'>"
            + _field("reviewer", _ui_text("human_review_pages.pseudonymous_reviewer_id"))
            + _ui_template(
                "<label>[[text:human_review_pages.role]]<select name='role'><option value='rater'>[[text:human_review_pages.independent_rater]]</option><option value='adjudicator'>[[text:human_review_pages.adjudicator]]</option></select></label>"
            )
        )
        body += (
            _field(
                "reference",
                _ui_text("human_review_pages.independent_20_item_qualification_evidence_reference"),
            )
            + "<div class='review-grid'>"
            + qualifications
            + _ui_template(
                "</div><label><input type='checkbox' name='qualified' value='1' required>[[text:human_review_pages.language_relevant_experience_and_conflicts_have_been_reviewed_the]]</label><button>[[text:human_review_pages.issue_individual_review_link]]</button></form></section>"
            )
        )
        body += (
            _ui_template(
                "<section class='review-card'><h2>[[text:human_review_pages.analysis_and_exports]]</h2><p>[[text:human_review_pages.independent_ratings_remain_distinct_from_adjudication_the_analysi]]</p><form method='post' action='/human-evaluation/"
            )
            + study
            + "/analyse'><button"
            + ("" if summary["ready_for_analysis"] else " disabled")
            + _ui_template(
                ">[[text:human_review_pages.export_and_run_human_audit_analysis]]</button></form>"
            )
        )
        if summary["ready_for_analysis"]:
            body += (
                "<div id='campaign-exports' class='review-actions'><a data-campaign-export download='completed-ratings.csv' href='/human-evaluation/"
                + study
                + _ui_template(
                    "/labels.csv'>[[text:human_review_pages.download_completed_ratings]]</a></div><p id='campaign-export-status' role='status'></p>"
                )
                + EXPORT_SCRIPT
            )
        body += "</section></div>"
        return _page(
            _ui_text("human_review_pages.human_evaluation_study"),
            body,
            active=_ui_text("human_review_pages.campaigns"),
        )

    def _human_route(self, method, path, query, data):
        from .human_review_setup import setup_route

        setup = setup_route(self, method, path, data, _REVIEW_STYLE)
        if setup is not None:
            return setup
        store = self._human_store()
        if path.startswith("/review/"):
            parts = path.removeprefix("/review/").split("/")
            token = parts[0]
            action = "/".join(parts[1:])
            try:
                if method == "GET" and not action:
                    reviewer = store.view(token)
                    if query.get("item"):
                        result = store.view(token, query["item"])
                    else:
                        personal = reviewer["role"] == "personal"
                        page = _page(
                            _ui_text("human_review_pages.personal_evaluation")
                            if personal
                            else _ui_text("human_review_pages.independent_human_evaluation"),
                            _REVIEW_STYLE
                            + "<div class='review-stack'><section id='review-intro' class='review-card'></section><p id='review-status' class='review-status' role='status' aria-live='polite'></p><section id='review-body' class='review-card'></section></div>"
                            + _REVIEW_SCRIPT,
                            active=_ui_text("human_review_pages.campaigns"),
                        )
                        return 200, "text/html; charset=utf-8", page
                elif method == "GET" and action == "data":
                    result = store.view(token)
                elif method == "GET" and action == "media":
                    mime, body = store.media(
                        token, query.get("item", ""), int(query.get("index", "-1"))
                    )
                    return 200, mime, body
                elif method == "POST" and action == "consent" and data.get("agree") == "1":
                    store.consent(token)
                    result = {"saved": True}
                elif method == "POST" and action == "withdraw" and data.get("confirm") == "1":
                    store.withdraw(token)
                    result = {"saved": True}
                elif method == "POST" and action == "rating":
                    result = store.save(
                        token,
                        data.get("item", ""),
                        revision=int(data.get("revision", "-1")),
                        value=json.loads(data.get("value", "{}")),
                        submit=data.get("submit") == "1",
                        defer=data.get("defer") == "1",
                    )
                elif method == "POST" and action == "adjudicate":
                    store.adjudicate(
                        token,
                        data.get("item", ""),
                        json.loads(data.get("value", "{}")),
                        data.get("rationale", ""),
                    )
                    result = {"saved": True}
                else:
                    return (
                        404,
                        "application/json",
                        json.dumps(
                            {"error": _ui_text("human_review_pages.unknown_review_action")}
                        ).encode("utf-8"),
                    )
                return 200, "application/json; charset=utf-8", json.dumps(result).encode()
            except (ValueError, KeyError, OSError) as error:
                # Never echo a filesystem locator, response or hidden metadata.
                message = (
                    str(error)
                    if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError)
                    else _ui_text(
                        "human_review_pages.review_request_could_not_be_completed_your_unsaved_draft_is_still"
                    )
                )
                return (
                    400,
                    "application/json; charset=utf-8",
                    json.dumps({"error": message}).encode(),
                )
        if method == "GET" and path == "/human-evaluation":
            return (
                200,
                "text/html; charset=utf-8",
                self._human_index(query.get("campaign_id", ""), query.get("kind", "personal")),
            )
        if method == "POST" and path == "/human-evaluation/prepare":
            if data.get("acknowledge") != "1":
                raise ValueError(
                    _ui_text("human_review_pages.acknowledge_sensitive_content_before_preparation")
                )
            directory = store.root / ("preparation-" + secrets.token_hex(8))
            directory.mkdir(mode=0o700)
            params = {
                "--results": data.get("results", ""),
                "--output": str(directory / "sample.csv"),
                "--acknowledge-sensitive-content": "1",
                "--prepare-source-task"
                if data.get("mode") == "source_task"
                else "--prepare": data.get("clusters", ""),
            }
            for key in ("historical_code_repository", "judge_configuration_sha256"):
                if data.get(key):
                    params["--" + key.replace("_", "-")] = data[key]
            job = self.start_job("human_audit", params, campaign_id=data.get("campaign_id", ""))
            return 303, "/jobs/" + job.job_id, b""
        if method == "POST" and path == "/human-evaluation/create":
            if data.get("campaign_id"):
                self.db.require_workspace(data["campaign_id"])
            metadata = {
                k: data.get(k, "")
                for k in (
                    "ethics",
                    "consent",
                    "compensation",
                    "stop_contact",
                    "results",
                    "historical_code_repository",
                    "judge_configuration_sha256",
                )
            }
            study = store.create(
                campaign=data.get("campaign_id", ""),
                name=data.get("name", ""),
                prepared=data.get("prepared", ""),
                mode=data.get("mode", ""),
                metadata=metadata,
            )
            return 303, "/human-evaluation/" + study, b""
        parts = path.removeprefix("/human-evaluation/").split("/")
        study = parts[0]
        action = "/".join(parts[1:])
        info = store.study(study)
        if method == "GET" and not action:
            return 200, "text/html; charset=utf-8", self._human_study_page(study)
        if method == "GET" and action == "personal.csv":
            return 200, "text/csv; charset=utf-8", store.personal_export(study)
        if method == "POST" and action == "enroll":
            dimensions = (
                COMMON
                if info["mode"] == "common"
                else {"task_label": None, "parse_status_label": None}
            )
            qualification = {
                "reference": data.get("reference", ""),
                "items": 20,
                "correct": {k: int(data.get("correct_" + k, "-1")) for k in dimensions},
                "independent_reference": data.get("qualified") == "1",
                "language_and_experience_confirmed": data.get("qualified") == "1",
            }
            token = store.enroll(
                study, data.get("reviewer", ""), data.get("role", ""), qualification
            )
            return (
                200,
                "text/html; charset=utf-8",
                _page(
                    _ui_text("human_review_pages.individual_review_link"),
                    _ui_template(
                        "<h1>[[text:human_review_pages.individual_review_link]]</h1><p>[[text:human_review_pages.share_only_with_this_reviewer_it_does_not_reveal_other_reviewers]]</p><p><a href='/review/"
                    )
                    + token
                    + "'>/review/"
                    + token
                    + "</a></p><p><a href='/human-evaluation/"
                    + study
                    + _ui_template("'>[[text:human_review_pages.return_to_study]]</a></p>"),
                    active=_ui_text("human_review_pages.campaigns"),
                ),
            )
        if method == "GET" and action == "labels.csv":
            return 200, "text/csv; charset=utf-8", store.export(study)
        if method == "POST" and action == "analyse":
            payload = store.export(study)
            directory = store.root / study / ("analysis-" + secrets.token_hex(8))
            directory.mkdir(mode=0o700)
            (directory / "labels.csv").write_bytes(payload)
            params = {
                "--results": info["metadata"]["results"],
                "--labels" if info["mode"] == "common" else "--source-task-labels": str(
                    directory / "labels.csv"
                ),
                "--prepared-rating-form": str(store.root / study / "prepared.csv"),
                "--prepared-rating-form-sha256": info["metadata"]["prepared_sha256"],
                "--output": str(directory / "analysis.json"),
            }
            for key in ("historical_code_repository", "judge_configuration_sha256"):
                if info["metadata"].get(key):
                    params["--" + key.replace("_", "-")] = info["metadata"][key]
            indexed = info["metadata"].get("source_kind") == "campaign_index"
            if indexed:
                params = {
                    "--snapshot": info["metadata"]["snapshot"],
                    "--prepared-rating-form": str(store.root / study / "prepared.csv"),
                    "--labels": str(directory / "labels.csv"),
                    "--output": str(directory / "analysis.json"),
                }
            job = self.start_job(
                "human_review_campaign" if indexed else "human_audit",
                params,
                campaign_id=info["campaign"],
            )
            return 303, "/jobs/" + job.job_id, b""
        return (
            404,
            "text/plain; charset=utf-8",
            _ui_text("human_review_pages.unknown_human_evaluation_action").encode("utf-8"),
        )
