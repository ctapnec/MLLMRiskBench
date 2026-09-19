"""Optional campaign help. Reads saved UI state; never prepares or starts work."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

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
    owner = params.get("campaign_id", "")
    base = "/build?campaign_id=" + quote(owner, safe="") if owner else "/build?work_kind=campaign"
    campaign = "/campaigns/" + quote(owner, safe="") if owner else base

    def link(tab, target=""):
        if target == "retained-inputs" and params.get("campaign_inputs") != "saved":
            target = "campaign-workflow"
        return base + "#" + (target or "build-" + tab)

    tool = lambda command: "/commands?cmd=" + command + ("&campaign_id=" + owner if owner else "")
    matched = params.get("campaign_inputs") == "saved" or (
        not params.get("campaign_flow") and bool(params.get("retained_source_campaign"))
    )
    local = bool(params.get("local"))
    hosted = bool(params.get("api"))
    route = (
        "matched"
        if matched
        else "mixed"
        if local and hosted
        else "local"
        if local
        else "hosted"
        if hosted
        else "choose"
    )
    prepare_target = "automatic-comparison" if matched else "pipeline-review"
    judging_links = (
        (
            [
                (
                    _ui_text("campaign_guide.open_local_saved_output_judging"),
                    link("general", "retained-local-judging"),
                )
            ]
            if params.get("retained_programs_job")
            else [
                (
                    _ui_text("campaign_guide.complete_collection_preparation"),
                    link("general", prepare_target),
                )
            ]
        )
        if matched
        else [(_ui_text("campaign_guide.choose_judges"), link("evaluation", "evaluation-judges"))]
    )
    if matched and params.get("retained_programs_job"):
        judging_links += [
            (
                _ui_text("campaign_guide.open_haiku_saved_output_judging"),
                link("general", "retained-haiku-judging"),
            ),
            (
                _ui_text("campaign_guide.review_same_input_output_coverage"),
                link("general", "retained-haiku-judging"),
            ),
        ]
    if owner:
        judging_links.insert(
            0,
            (
                _ui_text("campaign_guide.evaluate_saved_campaign_answers"),
                "/assessment?campaign_id=" + owner,
            ),
        )
    steps = [
        (
            _ui_text("campaign_guide.choose_a_route"),
            _ui_text("campaign_guide.choose_what_you_want_to_compare"),
            _ui_text(
                "campaign_guide.use_local_models_hosted_apis_or_both_in_one_campaign_for_a_fresh"
            ),
            [
                (
                    _ui_text("campaign_guide.choose_target_models"),
                    link("pipeline", "target-models"),
                ),
                (
                    _ui_text("campaign_guide.choose_a_fresh_workload"),
                    link("pipeline", "input-corpora"),
                ),
                (
                    _ui_text("campaign_guide.reuse_saved_local_inputs"),
                    link("general", "retained-inputs"),
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.runtimes"),
            _ui_text("campaign_guide.check_model_and_framework_readiness"),
            _ui_text(
                "campaign_guide.for_local_work_inspect_the_available_gpus_local_services_and_inst"
            ),
            [
                (
                    _ui_text("campaign_guide.inspect_local_hardware"),
                    link("runtimes", "local-hardware"),
                ),
                (
                    _ui_text("campaign_guide.inspect_framework_runtimes"),
                    link("runtimes", "framework-runtimes"),
                ),
                (
                    _ui_text("campaign_guide.open_local_model_assessment"),
                    tool("local_model_readiness"),
                ),
                (_ui_text("campaign_guide.inspect_provider_credentials"), "/config/secrets"),
            ],
        ),
        (
            _ui_text("campaign_guide.inputs"),
            _ui_text("campaign_guide.choose_a_small_interpretable_input_selection"),
            _ui_text(
                "campaign_guide.for_fresh_inputs_select_your_corpora_and_attacks_in_pipeline_then"
            ),
            [
                (
                    _ui_text("campaign_guide.select_arms_and_corpora"),
                    link("pipeline", "input-corpora"),
                ),
                (
                    _ui_text("campaign_guide.select_attack_frameworks_and_preparation"),
                    link("pipeline", "attack-frameworks"),
                ),
                (
                    _ui_text("campaign_guide.set_limits_and_sampling"),
                    link("execution", "sample-size-control"),
                ),
                (
                    _ui_text("campaign_guide.select_saved_source_runs"),
                    link("general", "retained-inputs"),
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.settings"),
            _ui_text("campaign_guide.choose_evaluation_and_realistic_bounds"),
            _ui_text(
                "campaign_guide.select_your_judges_in_evaluation_local_models_use_their_assessed"
            ),
            [
                (_ui_text("campaign_guide.choose_judges"), link("evaluation", "evaluation-judges")),
                (
                    _ui_text("campaign_guide.set_execution_bounds"),
                    link("execution", "execution-budgets"),
                ),
                (
                    _ui_text("campaign_guide.inspect_local_serving"),
                    link("execution", "local-serving"),
                ),
                (
                    _ui_text("campaign_guide.configure_hosted_targets"),
                    "/config?file=api-targets#cfg-editor",
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.prepare"),
            _ui_text("campaign_guide.prepare_and_review_before_making_target_calls"),
            (
                _ui_text(
                    "campaign_guide.click_prepare_comparison_and_review_in_general_one_progress_page"
                )
            )
            if matched
            else (
                _ui_text(
                    "campaign_guide.use_compose_review_automatic_preparation_starts_directly_the_cons"
                )
            ),
            [
                (
                    _ui_text("campaign_guide.open_the_next_preparation_controls"),
                    link("general", prepare_target),
                ),
                (
                    _ui_text("campaign_guide.check_transport_evidence"),
                    link("admission", "transport-evidence"),
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.run"),
            _ui_text("campaign_guide.start_once_and_follow_the_existing_job"),
            _ui_text(
                "campaign_guide.use_the_explicit_start_on_the_reviewed_job_or_prepared_collection"
            ),
            [
                (
                    _ui_text("campaign_guide.open_review_controls"),
                    link(
                        "general",
                        "prepared-collection"
                        if params.get("retained_programs_job")
                        else "pipeline-review",
                    ),
                ),
                (
                    _ui_text("campaign_guide.open_campaign_jobs"),
                    "/jobs?campaign_id=" + owner if owner else link("general"),
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.judge"),
            _ui_text("campaign_guide.judge_each_saved_answer_not_just_its_input"),
            (
                _ui_text(
                    "campaign_guide.in_general_click_review_local_judging_preparation_is_automatic_th"
                )
            )
            if matched
            else (
                _ui_text(
                    "campaign_guide.for_direct_runner_work_the_selected_judging_cascade_evaluates_col"
                )
            ),
            judging_links
            + [
                (
                    _ui_text("campaign_guide.inspect_saved_verdicts"),
                    campaign + "?section=judging"
                    if owner
                    else link("evaluation", "evaluation-judges"),
                )
            ],
        ),
        (
            _ui_text("campaign_guide.results"),
            _ui_text("campaign_guide.inspect_coverage_before_comparing_rates"),
            _ui_text(
                "campaign_guide.results_shows_answers_effective_generation_settings_usage_and_tru"
            ),
            [
                (label, campaign + "?section=" + section if owner else link("general"))
                for label, section in [
                    (_ui_text("campaign_guide.inspect_results"), "results"),
                    (_ui_text("campaign_guide.compare_matched_inputs"), "compare"),
                    (_ui_text("campaign_guide.inspect_costs"), "costs"),
                    (_ui_text("campaign_guide.coverage_figures_and_exports"), "overview"),
                    (_ui_text("campaign_guide.inspect_the_saved_draft"), "definition"),
                ]
            ]
            + [
                (
                    _ui_text("campaign_guide.compare_individual_measured_jobs"),
                    "/stats?view=compare&scope=jobs",
                )
            ],
        ),
        (
            _ui_text("campaign_guide.human_review"),
            _ui_text("campaign_guide.evaluate_saved_answers_or_arrange_independent_review"),
            _ui_text(
                "campaign_guide.for_active_or_finished_campaigns_open_human_evaluation_and_use_re"
            ),
            [
                (
                    _ui_text("campaign_guide.open_human_evaluation_wizard"),
                    "/human-evaluation?campaign_id=" + owner if owner else link("general"),
                ),
                (
                    _ui_text("campaign_guide.inspect_campaign_judging_coverage"),
                    campaign + "?section=judging" if owner else link("evaluation"),
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.svm_analysis"),
            _ui_text("campaign_guide.optional_analyze_retained_responses_with_svms"),
            _ui_text(
                "campaign_guide.open_the_campaign_svm_analysis_tab_choose_the_saved_local_input_s"
            ),
            [
                (
                    _ui_text("campaign_guide.open_svm_analysis"),
                    "/analysis?campaign_id=" + owner if owner else "/campaigns",
                ),
                (
                    _ui_text("campaign_guide.inspect_svm_results"),
                    "/stats?view=svm&campaign_id=" + owner if owner else "/stats?view=svm",
                ),
                (
                    _ui_text("campaign_guide.inspect_existing_analysis_jobs"),
                    "/jobs?campaign_id=" + owner if owner else "/jobs",
                ),
            ],
        ),
        (
            _ui_text("campaign_guide.recovery"),
            _ui_text("campaign_guide.recover_the_unfinished_stage_without_duplicating_work"),
            _ui_text(
                "campaign_guide.open_the_original_job_and_read_its_error_and_saved_outputs_contin"
            ),
            [
                (
                    _ui_text("campaign_guide.inspect_campaign_jobs"),
                    "/jobs?campaign_id=" + owner if owner else "/jobs",
                ),
                (
                    _ui_text("campaign_guide.inspect_campaign_activity"),
                    campaign + "?section=activity" if owner else link("general"),
                ),
            ],
        ),
    ]
    if params.get("work_kind") == "campaign" or owner:
        replacements = {
            "Prepare": (
                _ui_text("campaign_guide.review_the_complete_campaign"),
                _ui_text(
                    "campaign_guide.in_general_choose_campaign_workflow_inputs_and_assessment_then_cl"
                ),
                [
                    (
                        _ui_text("campaign_guide.open_campaign_choices"),
                        link("general", "campaign-workflow"),
                    ),
                    (
                        _ui_text("campaign_guide.review_the_campaign"),
                        link("general", "pipeline-review"),
                    ),
                    (
                        _ui_text("campaign_guide.inspect_automatic_connection_settings"),
                        link("admission", "transport-evidence"),
                    ),
                ],
            ),
            "Run": (
                _ui_text("campaign_guide.start_once_and_follow_campaign_progress"),
                _ui_text(
                    "campaign_guide.click_start_campaign_on_the_completed_review_required_checks_coll"
                ),
                [
                    (
                        _ui_text("campaign_guide.open_prepared_and_active_work"),
                        link("general", "pipeline-review"),
                    ),
                    (_ui_text("campaign_guide.open_campaign"), campaign),
                ],
            ),
            "Judge": (
                _ui_text("campaign_guide.choose_assessment_before_collection"),
                _ui_text(
                    "campaign_guide.choose_local_assessment_and_optional_independent_haiku_assessment"
                ),
                [
                    (
                        _ui_text("campaign_guide.choose_automatic_assessment"),
                        link("general", "campaign-workflow"),
                    ),
                    (
                        _ui_text("campaign_guide.inspect_saved_verdicts"),
                        campaign + "?section=judging",
                    ),
                    (
                        _ui_text("campaign_guide.assess_existing_saved_answers"),
                        "/assessment?campaign_id=" + owner if owner else link("general"),
                    ),
                ],
            ),
        }
        steps = [
            (short, *replacements[short]) if short in replacements else (short, title, text, links)
            for short, title, text, links in steps
        ]
    positions = {step[0]: index for index, step in enumerate(steps)}
    stage = (
        _ui_text("campaign_guide.choose_a_route")
        if not (local or hosted)
        else _ui_text("campaign_guide.inputs")
        if not (params.get("corpora") or matched)
        else _ui_text("campaign_guide.settings")
    )
    notice = _ui_text("campaign_guide.suggested_next_step_from_your_saved_settings")
    actions = []
    if owner:
        actions = app.db.workspace_activity(owner) or []
    latest = next((row for row in actions if row["member_kind"] == "job"), None)
    if latest is not None and latest["state"] in {
        "queued",
        "starting",
        "running",
        "retry_wait",
        "retry_waiting",
        "failed",
        "aborted",
        "interrupted",
    }:
        state = latest["state"]
        stage = (
            _ui_text("campaign_guide.recovery")
            if state in {"failed", "aborted", "interrupted"}
            else _ui_text("campaign_guide.run")
        )
        notice = (
            _ui_text("campaign_guide.the_latest_console_job_is_recorded_as")
            + state
            + _ui_text("campaign_guide.open_that_job_before_starting_or_preparing_another_copy")
        )
        steps[positions[stage]][3].insert(
            0,
            (
                _ui_text("campaign_guide.open_the_current_job"),
                "/jobs/" + quote(latest["member_id"], safe=""),
            ),
        )
    elif latest is not None and latest["state"] == "complete":
        command = dict(latest).get("command", "")
        judging_preparation = command in {
            "retained_native_judge_prepare",
            "retained_response_judge_pair",
            "retained_judge_inventory",
            "retained_inventory_judge_items",
        } or (latest["member_id"] == params.get("retained_inventory_plan_job"))
        stage = (
            _ui_text("campaign_guide.judge")
            if judging_preparation
            else _ui_text("campaign_guide.svm_analysis")
            if command == "response_svm"
            else _ui_text("campaign_guide.results")
            if latest["role"] in {"judging", "analysis"}
            else _ui_text("campaign_guide.judge")
            if latest["role"] == "collection"
            else _ui_text("campaign_guide.prepare")
        )
        notice = _ui_text(
            "campaign_guide.the_latest_console_job_completed_check_what_that_job_covered_this"
        )
    elif matched:
        stage = _ui_text("campaign_guide.prepare")
    all_operations = getattr(app, "_operations", {})
    from .operations import operator_operations, operation_contains_job, completed_equivalent

    operations = sorted(
        (
            row
            for row in operator_operations(all_operations, owner)
            if row["status"] in {"preparing", "ready", "failed", "stopped", "complete"}
        ),
        key=lambda row: row.get("created_at", 0),
    )
    if operations and (
        operations[-1]["status"] == "preparing"
        or latest is None
        or operations[-1].get("created_at", 0) >= (dict(latest).get("started_at") or 0)
        or operation_contains_job(all_operations, operations[-1]["id"], latest["member_id"])
    ):
        current = completed_equivalent(all_operations, operations[-1]) or operations[-1]
        stage = (
            _ui_text("campaign_guide.recovery")
            if current["status"] in {"failed", "stopped"}
            else _ui_text("campaign_guide.prepare")
        )
        notice = (
            _ui_text("campaign_guide.preparation_is")
            + current["status"]
            + _ui_text(
                "campaign_guide.open_the_operation_not_its_internal_child_jobs_completed_preparat"
            )
        )
        steps[positions[stage]][3].insert(
            0,
            (
                _ui_text("campaign_guide.open_prepared_or_active_work"),
                "/operations/" + current["id"],
            ),
        )
        if current.get("kind") == "campaign":
            stage = (
                _ui_text("campaign_guide.results")
                if current["status"] == "complete"
                else _ui_text("campaign_guide.recovery")
                if current["status"] in {"failed", "stopped"}
                else _ui_text("campaign_guide.run")
                if current.get("execution_authorized")
                else _ui_text("campaign_guide.prepare")
            )
            notice = (
                _ui_text("campaign_guide.campaign_is")
                + current["status"]
                + _ui_text(
                    "campaign_guide.follow_its_progress_page_internal_jobs_need_no_separate_starts"
                )
            )
            steps[positions[stage]][3].insert(
                0,
                (_ui_text("campaign_guide.open_campaign_progress"), "/operations/" + current["id"]),
            )
    if (
        latest is not None
        and latest["role"] == "collection"
        and not matched
        and params.get("mode") == "attestation_probe"
    ):
        notice += _ui_text(
            "campaign_guide.a_diagnostic_probe_is_not_a_measured_result_finish_its_transport"
        )
        if latest["state"] == "complete":
            stage = _ui_text("campaign_guide.prepare")
    return steps, positions[stage], notice, route


def render(app, params, *, builder=False):
    enabled = params.get("campaign_guide") == "on"
    if not builder and not enabled:
        return ""
    steps, stage, notice, route = _guidance(app, params)
    escape = html.escape
    owner = params.get("campaign_id") or "new"
    sections = ""
    navigation = ""
    for index, (short, title, text, links) in enumerate(steps):
        navigation += (
            f"<button type='button' class='ghost' data-guide-step='{index}'>"
            + str(index + 1)
            + ". "
            + escape(short)
            + "</button>"
        )
        sections += (
            f"<section class='campaign-guide-section' data-guide-section='{index}' tabindex='-1' hidden>"
            + "<h3>"
            + escape(title)
            + "</h3><p>"
            + escape(text)
            + "</p><div class='campaign-guide-links'>"
            + "".join(
                "<a href='" + escape(href, quote=True) + "'>" + escape(label) + "</a>"
                for label, href in links
            )
            + "</div></section>"
        )
    return (
        "<div class='campaign-guide' data-guide-enabled='"
        + ("true" if enabled else "false")
        + "' data-guide-key='"
        + escape(owner + ":" + route + ":" + str(stage), quote=True)
        + f"' data-guide-initial='{stage}'>"
        "<div class='campaign-guide-launch'><button type='button' class='ghost' data-guide-open"
        + ("" if enabled else " hidden")
        + _ui_template(
            ">[[text:campaign_guide.campaign_guide]]</button></div><dialog class='campaign-guide-dialog' aria-labelledby='campaign-guide-title'><div class='campaign-guide-header'><h2 id='campaign-guide-title'>[[text:campaign_guide.your_campaign_step_by_step]]</h2><button type='button' class='ghost' data-guide-close aria-label='[[attr:campaign_guide.close_campaign_guide]]'>[[text:campaign_guide.close]]</button></div><div class='campaign-guide-content'><p class='note'>"
        )
        + escape(notice)
        + _ui_template(
            "</p><p>[[text:campaign_guide.no_calls_are_made_by_this_guide_links_open_controls_you_decide_wh]]</p><p>[[text:campaign_guide.this_is_a_workflow_companion_not_a_preset_recipe_the_small_campai]]</p><details class='campaign-guide-topics'><summary>[[text:campaign_guide.browse_all]] "
        )
        + str(len(steps))
        + _ui_template(
            " [[text:campaign_guide.topics]]</summary><div class='campaign-guide-steps' role='group' aria-label='[[attr:campaign_guide.guide_steps]]'>"
        )
        + navigation
        + "</div></details>"
        "<p class='note' data-guide-progress aria-live='polite'></p>"
        + sections
        + _ui_template(
            "<div class='campaign-guide-footer'><button type='button' class='ghost' data-guide-back>[[text:campaign_guide.back]]</button><button type='button' data-guide-next>[[text:campaign_guide.next]]</button></div><p class='note'>[[text:campaign_guide.close_this_window_to_work_reopen_it_with_campaign_guide_to_disabl]]</p></div></dialog></div>"
        )
        + SCRIPT
    )


SCRIPT = _ui_template("""<script>(()=>{
const root=document.querySelector('.campaign-guide');if(!root)return;
const dialog=root.querySelector('dialog'),open=root.querySelector('[data-guide-open]');
const choice=document.querySelector('[name=campaign_guide]');
const steps=[...root.querySelectorAll('[data-guide-step]')],panels=[...root.querySelectorAll('[data-guide-section]')];
const back=root.querySelector('[data-guide-back]'),next=root.querySelector('[data-guide-next]');
let current=Number(root.dataset.guideInitial),focusBefore,restoreFocus=true;
function show(index,focus=false){current=Math.max(0,Math.min(index,panels.length-1));
panels.forEach((p,i)=>p.hidden=i!==current);steps.forEach((b,i)=>{if(i===current)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});
back.disabled=current===0;next.textContent=current===panels.length-1?[[js:campaign_guide.done]]:[[js:campaign_guide.next]];
root.querySelector('[data-guide-progress]').textContent=[[js:campaign_guide.step]]+(current+1)+' of '+panels.length;
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
})();</script>""")
