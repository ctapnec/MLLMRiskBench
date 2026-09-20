"""Campaign-aware human study setup, separate from the blinded rater wizard."""

from .i18n import template as _ui_template, text as _ui_text
import csv
import html
import json
import secrets
from pathlib import Path

from .ui import _page

ETHICS_CHOICES = {
    "pending": _ui_text("human_review_setup.not_decided_yet_prepare_a_sample_only"),
    "approved": _ui_text("human_review_setup.approved_by_the_responsible_institution_supervisor"),
    "exempt": _ui_text("human_review_setup.exemption_confirmed_by_the_responsible_institution"),
    "not_required": _ui_text(
        "human_review_setup.formal_review_not_required_as_confirmed_by_the_responsible_instit"
    ),
}
COMPENSATION_CHOICES = {
    "unpaid": _ui_text("human_review_setup.voluntary_unpaid_participation"),
    "paid": _ui_text("human_review_setup.paid_participation"),
    "credit": _ui_text("human_review_setup.academic_credit"),
    "other": _ui_text("human_review_setup.other_agreed_arrangement"),
}


def select_field(name, label, choices):
    return (
        "<label>"
        + html.escape(label)
        + "<select name='"
        + name
        + _ui_template("' required><option value=''>[[text:human_review_setup.choose]]</option>")
        + "".join(
            "<option value='" + key + "'>" + html.escape(value) + "</option>"
            for key, value in choices.items()
        )
        + "</select></label>"
    )


def arrangements(data):
    """Keep legacy submissions readable; new UI records explicit actual choices."""
    result = {
        k: data.get(k, "").strip() for k in ("ethics", "compensation", "stop_contact", "consent")
    }
    if "ethics_status" in data:
        status = data["ethics_status"]
        if status not in ETHICS_CHOICES:
            raise ValueError(
                _ui_text("human_review_setup.choose_the_actual_ethics_determination_status")
            )
        if status != "pending" and not result["ethics"]:
            raise ValueError(
                _ui_text("human_review_setup.record_who_made_the_determination_and_its_date")
            )
        result.update(
            ethics_status=status,
            ethics=ETHICS_CHOICES[status] + (": " + result["ethics"] if result["ethics"] else ""),
        )
    if "compensation_type" in data:
        kind = data["compensation_type"]
        if kind not in COMPENSATION_CHOICES:
            raise ValueError(_ui_text("human_review_setup.choose_the_participation_arrangement"))
        result.update(
            compensation_type=kind,
            compensation=COMPENSATION_CHOICES[kind] + ": " + result["compensation"],
        )
    return result


def sources(app, campaign):
    app.db.require_workspace(campaign)
    rows = app._human_store().sources(campaign)
    result = [dict(id="scope-" + r["id"], name=r["name"], **r["metadata"]) for r in rows]
    indexed = app.db._query(
        "SELECT 1 FROM campaign_assignments WHERE campaign_id=? "
        "AND evidence_class='measured' AND response_id IS NOT NULL LIMIT 1",
        (campaign,),
    )
    if indexed:
        result.insert(
            0,
            dict(
                id="campaign-index",
                name=_ui_text("human_review_setup.all_indexed_measured_campaign_outputs"),
                source_kind="campaign_index",
                results=str(app.results_root),
            ),
        )
    # Completed measured results only, not successful internal preparations or
    # diagnostics. Do not scan corpora or reopen artifacts
    # when displaying a page. Imported historical campaigns use registered scopes.
    runs = app.db._query(
        "SELECT r.job_id,r.out_dir FROM runs r JOIN campaign_members m "
        "ON m.member_kind IN ('job','external') AND m.member_id=r.job_id "
        "WHERE m.campaign_id=? AND r.command='run_matrix' AND r.kind='measured' "
        "AND r.exit_code=0 ORDER BY r.created_at DESC",
        (campaign,),
    )
    if runs is None:
        raise ValueError(_ui_text("human_review_setup.campaign_result_index_is_unavailable"))
    known = {r["results"] for r in result}
    for row in runs:
        if row["out_dir"] and row["out_dir"] not in known:
            result.append(
                dict(
                    id="run-" + row["job_id"],
                    name=_ui_text("human_review_setup.completed_run") + row["job_id"],
                    results=row["out_dir"],
                    historical_code_repository=str(app.repo_root),
                    judge_configuration_sha256="",
                )
            )
            known.add(row["out_dir"])
    return result


SETUP_SCRIPT = _ui_template("""<script>
document.querySelectorAll('[data-study-wizard]').forEach(form=>{
 const panels=Array.from(form.querySelectorAll('[data-study-step]')),nav=form.querySelector('.review-steps');let current=0;
 const buttons=panels.map((p,i)=>{const b=document.createElement('button');b.type='button';b.textContent=(i+1)+'. '+p.dataset.studyStep;b.onclick=()=>go(i);nav.append(b);return b;});
 const back=form.querySelector('[data-study-back]'),next=form.querySelector('[data-study-next]'),submit=form.querySelector('[type=submit]');
 function valid(index){for(const e of panels[index].querySelectorAll('input,select,textarea')){if(!e.checkValidity()){e.reportValidity();return false;}}return true;}
 function render(){panels.forEach((p,i)=>p.hidden=i!==current);buttons.forEach((b,i)=>{if(i===current)b.setAttribute('aria-current','step');else b.removeAttribute('aria-current');});back.disabled=current===0;next.hidden=current===panels.length-1;submit.hidden=current!==panels.length-1;
 const summary=form.querySelector('[data-study-summary]');summary.replaceChildren();for(const name of ['source','name','mode','clusters']){const e=form.elements[name];const p=document.createElement('p');p.textContent=({source:[[js:human_review_setup.saved_results]],name:[[js:human_review_setup.study]],mode:[[js:human_review_setup.rubric]],clusters:[[js:human_review_setup.requested_source_clusters]]})[name]+': '+(e.tagName==='SELECT'?e.selectedOptions[0]?.textContent:e.value);summary.append(p);}}
 function go(i){if(i>current){for(let j=current;j<i;j++)if(!valid(j))return;}current=i;render();panels[i].querySelector('h2').focus();}
 back.onclick=()=>go(current-1);next.onclick=()=>go(current+1);form.addEventListener('submit',e=>{for(let i=0;i<panels.length;i++){if(!valid(i)){e.preventDefault();current=i;render();return;}}});render();
});</script>""")


def setup_body(app, campaign, field, *, kind="personal"):
    escape = lambda value: html.escape(str(value), quote=True)
    if not campaign:
        return (
            _ui_template(
                "<section class='review-card'><h2>[[text:human_review_setup.choose_a_campaign]]</h2><p>[[text:human_review_setup.open_an_existing_local_or_api_campaign_including_a_finished_campa]]</p><div class='review-actions'>"
            )
            + "".join(
                "<a class='button ghost' href='/human-evaluation?campaign_id="
                + r["campaign_id"]
                + "'>"
                + escape(r["name"])
                + "</a>"
                for r in app.db.workspaces() or []
            )
            + "</div></section>"
        )
    choices = sources(app, campaign)
    options = _ui_template(
        "<option value=''>[[text:human_review_setup.choose_saved_results]]</option>"
    ) + "".join(
        "<option value='" + escape(r["id"]) + "'>" + escape(r["name"]) + "</option>"
        for r in choices
    )
    hidden = "<input type='hidden' name='campaign_id' value='" + escape(campaign) + "'>"
    navigation = (
        "<div class='review-actions'><a class='button"
        + ("" if kind == "personal" else " ghost")
        + "' href='/human-evaluation?campaign_id="
        + escape(campaign)
        + _ui_template("'>[[text:human_review_setup.review_saved_answers]]</a><a class='button")
        + ("" if kind == "independent" else " ghost")
        + "' href='/human-evaluation?campaign_id="
        + escape(campaign)
        + _ui_template(
            "&amp;kind=independent'>[[text:human_review_setup.independent_two_rater_study]]</a></div>"
        )
    )
    if kind != "independent":
        options = options.replace("value='campaign-index'", "value='campaign-index' selected")
        body = navigation + (
            _ui_template(
                "<section class='review-card'><h2>[[text:human_review_setup.review_saved_answers]]</h2><p>[[text:human_review_setup.read_the_actual_prompt_images_and_saved_answer_then_record_your_o]]</p><form method='post' action='/human-evaluation/prepare-personal'>"
            )
            + hidden
            + _ui_template(
                "<label>[[text:human_review_setup.saved_results]]<select name='source' required>"
            )
            + options
            + "</select></label>"
            + field(
                "name",
                _ui_text("human_review_setup.review_name"),
                _ui_text("human_review_setup.my_review_of_saved_answers"),
            )
            + _ui_template(
                "<div class='review-grid'><label>[[text:human_review_setup.rubric]]<select name='mode'><option value='common'>[[text:human_review_setup.common_safety_dimensions]]</option><option value='source_task'>[[text:human_review_setup.source_task_classification]]</option></select></label>"
            )
            + field(
                "clusters",
                _ui_text("human_review_setup.source_clusters"),
                0 if any(r.get("source_kind") == "campaign_index" for r in choices) else 20,
                "number",
            )
            + _ui_template(
                "</div><p>[[text:human_review_setup.for_indexed_campaign_outputs_0_selects_the_minimum_coverage_sampl]]</p><label class='review-check'><input type='checkbox' name='acknowledge' value='1' required><span>[[text:human_review_setup.i_am_ready_to_view_potentially_harmful_saved_content]]</span></label><button>[[text:human_review_setup.prepare_answers_for_review]]</button></form><p>[[text:human_review_setup.this_prepares_saved_content_only_no_model_or_judge_is_called]]</p></section>"
            )
        )
        drafts = [
            r
            for r in app._human_store().preparations(campaign)
            if r["value"]["metadata"].get("review_kind") == "personal"
        ]
        if drafts:
            body += (
                _ui_template(
                    "<section class='review-card'><h2>[[text:human_review_setup.prepared_personal_reviews]]</h2><ul>"
                )
                + "".join(
                    "<li><a href='/human-evaluation/preparations/"
                    + r["id"]
                    + "'>"
                    + escape(r["value"]["name"])
                    + "</a></li>"
                    for r in drafts
                )
                + "</ul></section>"
            )
        return body
    body = (
        _ui_template(
            "<section class='review-card'><h2>[[text:human_review_setup.new_human_evaluation]]</h2><p>[[text:human_review_setup.use_saved_results_from_this_campaign_collection_can_already_be_fi]]</p><ol><li><strong>[[text:human_review_setup.you_the_study_operator]]</strong> [[text:human_review_setup.choose_saved_answers_inspect_the_sample_size_and_record_participa]]</li><li><strong>[[text:human_review_setup.you]]</strong> [[text:human_review_setup.assign_two_independent_raters_and_a_separate_adjudicator_then_sha]]</li><li><strong>[[text:human_review_setup.each_reviewer]]</strong> [[text:human_review_setup.read_the_prompt_and_answer_choose_ratings_in_the_guided_review_th]]</li></ol><p>[[text:human_review_setup.this_page_sets_up_the_study_it_is_not_the_rating_form]]</p><form method='post' action='/human-evaluation/prepare-study' data-study-wizard novalidate>"
        )
        + hidden
    )
    body += (
        _ui_template(
            "<div class='review-steps' role='navigation' aria-label='[[attr:human_review_setup.study_setup_steps]]'></div><section class='review-step' data-study-step='Saved results'><h2 tabindex='-1'>[[text:human_review_setup.choose_the_saved_result_set]]</h2><label>[[text:human_review_setup.saved_results]]<select name='source' required>"
        )
        + options
        + _ui_template(
            "</select></label><p class='review-help'>[[text:human_review_setup.a_result_set_may_cover_one_run_or_a_registered_combined_analysis]]</p></section>"
        )
    )
    body += (
        _ui_template(
            "<section class='review-step' data-study-step='Sample'><h2 tabindex='-1'>[[text:human_review_setup.define_the_assessment_sample]]</h2>"
        )
        + field("name", _ui_text("human_review_setup.study_name"))
        + _ui_template(
            "<div class='review-grid'><label>[[text:human_review_setup.rubric]]<select name='mode'><option value='common'>[[text:human_review_setup.common_safety_dimensions]]</option><option value='source_task'>[[text:human_review_setup.source_task_classification]]</option></select></label>"
        )
        + field(
            "clusters",
            _ui_text("human_review_setup.source_clusters"),
            0 if any(r.get("source_kind") == "campaign_index" for r in choices) else 20,
            "number",
        )
        + _ui_template(
            "</div><p>[[text:human_review_setup.for_indexed_campaign_outputs_zero_selects_the_smallest_sample_pro]]</p><details><summary>[[text:human_review_setup.media_lookup_for_imported_results]]</summary>"
        )
        + field(
            "media_index",
            _ui_text("human_review_setup.existing_retained_media_index_optional"),
            required=False,
        )
        + _ui_template(
            "<p>[[text:human_review_setup.leave_blank_to_use_the_selected_result_set_s_registered_index_thi]]</p></details></section>"
        )
    )
    body += (
        _ui_template(
            "<section class='review-step' data-study-step='Arrangements'><h2 tabindex='-1'>[[text:human_review_setup.record_the_actual_study_arrangements]]</h2>"
        )
        + select_field(
            "ethics_status", _ui_text("human_review_setup.ethics_determination"), ETHICS_CHOICES
        )
        + field(
            "ethics",
            _ui_text(
                "human_review_setup.who_made_the_determination_and_when_leave_blank_if_not_decided"
            ),
            required=False,
        )
        + _ui_template(
            "<p class='review-help'>[[text:human_review_setup.choose_the_decision_actually_received_not_the_one_you_expect_not]]</p>"
        )
        + select_field(
            "compensation_type",
            _ui_text("human_review_setup.participation_arrangement"),
            COMPENSATION_CHOICES,
        )
        + field(
            "compensation",
            _ui_text(
                "human_review_setup.expected_time_any_payment_credit_and_recorded_data_withdrawal_ter"
            ),
        )
        + field(
            "stop_contact",
            _ui_text(
                "human_review_setup.contact_person_and_email_for_questions_or_stopping_participation"
            ),
        )
        + _ui_template(
            "<label>[[text:human_review_setup.information_shown_before_a_reviewer_consents]]<textarea name='consent' required placeholder='[[attr:human_review_setup.explain_the_study_purpose_sensitive_content_voluntary_participati]]'></textarea></label><p>[[text:human_review_setup.only_actual_decisions_and_participation_terms_belong_here_these_c]]</p></section>"
        )
    )
    body += _ui_template(
        "<section class='review-step' data-study-step='Review'><h2 tabindex='-1'>[[text:human_review_setup.review_sample_preparation]]</h2><div data-study-summary></div><label class='review-check'><input type='checkbox' name='acknowledge' value='1' required><span>[[text:human_review_setup.i_understand_the_sample_contains_potentially_harmful_content_and]]</span></label><p>[[text:human_review_setup.preparation_runs_in_jobs_you_will_inspect_the_workload_before_cre]]</p></section><div class='review-wizard-footer'><button type='button' class='ghost' data-study-back>[[text:human_review_setup.back]]</button><button type='button' data-study-next>[[text:human_review_setup.next]]</button><button type='submit'>[[text:human_review_setup.prepare_review_sample]]</button></div></form></section>"
    )
    drafts = app._human_store().preparations(campaign)
    if drafts:
        body += (
            _ui_template(
                "<section class='review-card'><h2>[[text:human_review_setup.sample_preparations]]</h2><ul>"
            )
            + "".join(
                "<li><a href='/human-evaluation/preparations/"
                + r["id"]
                + "'>"
                + escape(r["value"]["name"])
                + "</a></li>"
                for r in drafts
            )
            + "</ul></section>"
        )
    body += (
        _ui_template(
            "<details class='review-card'><summary>[[text:human_review_setup.register_an_existing_analysis_result_set]]</summary><p>[[text:human_review_setup.for_imported_historical_campaigns_associate_their_existing_combin]]</p><form method='post' action='/human-evaluation/register-source'>"
        )
        + hidden
        + field("name", _ui_text("human_review_setup.result_set_name"))
        + field("results", _ui_text("human_review_setup.existing_analysis_results_directory"))
        + field(
            "historical_code_repository",
            _ui_text("human_review_setup.historical_code_repository_if_needed"),
            required=False,
        )
        + field(
            "judge_configuration_sha256",
            _ui_text("human_review_setup.historical_judge_configuration_reference_if_needed"),
            required=False,
        )
        + _ui_template(
            "<button>[[text:human_review_setup.register_saved_results]]</button></form></details>"
        )
    )
    return navigation + body + SETUP_SCRIPT


def setup_route(app, method, path, data, style):
    store = app._human_store()
    if method == "POST" and path == "/human-evaluation/register-source":
        owner = data.get("campaign_id", "")
        app.db.require_workspace(owner)
        store.register_source(
            campaign=owner,
            **{
                k: data.get(k, "")
                for k in (
                    "name",
                    "results",
                    "historical_code_repository",
                    "judge_configuration_sha256",
                    "media_index",
                )
            },
        )
        return 303, "/human-evaluation?campaign_id=" + owner, b""
    if method == "POST" and path in {
        "/human-evaluation/prepare-study",
        "/human-evaluation/prepare-personal",
    }:
        personal = path.endswith("/prepare-personal")
        owner = data.get("campaign_id", "")
        choices = sources(app, owner)
        source = next((r for r in choices if r["id"] == data.get("source")), None)
        if source is None:
            raise ValueError(_ui_text("human_review_setup.choose_saved_results_from_this_campaign"))
        if data.get("acknowledge") != "1":
            raise ValueError(
                _ui_text(
                    "human_review_setup.acknowledge_sensitive_content_before_preparing_a_sample"
                )
            )
        indexed = source.get("source_kind") == "campaign_index"
        if data.get("mode") not in {"common", "source_task"} or int(data.get("clusters", "0")) < (
            0 if indexed else 1
        ):
            raise ValueError(
                _ui_text(
                    "human_review_setup.choose_a_rubric_and_cluster_count_zero_selects_minimum_coverage_f"
                )
            )
        metadata = dict(review_kind="personal") if personal else arrangements(data)
        if not data.get("name", "").strip() or (
            not personal
            and any(not metadata[k] for k in ("ethics", "compensation", "stop_contact", "consent"))
        ):
            raise ValueError(
                _ui_text(
                    "human_review_setup.complete_the_study_name_and_actual_review_arrangements"
                )
            )
        if not personal and not data.get("compensation", "").strip():
            raise ValueError(
                _ui_text("human_review_setup.record_participation_time_and_withdrawal_terms")
            )
        directory = store.root / ("preparation-" + secrets.token_hex(8))
        directory.mkdir(mode=0o700)
        params = {
            "--results": source["results"],
            "--output": str(directory / "sample.csv"),
            "--acknowledge-sensitive-content": "1",
            "--prepare-source-task" if data["mode"] == "source_task" else "--prepare": data[
                "clusters"
            ],
        }
        for key in ("historical_code_repository", "judge_configuration_sha256"):
            if source.get(key):
                params["--" + key.replace("_", "-")] = source[key]
        supplied_index = data.get("media_index", "").strip() or source.get("media_index", "")
        if supplied_index:
            params["--media-index"] = str(store._path(supplied_index))
        if indexed:
            params = {
                "--database": str(app.db.path),
                "--campaign": owner,
                "--results-root": str(app.results_root),
                "--output": str(directory / "sample.csv"),
                "--mode": data["mode"],
                "--clusters": data["clusters"],
                "--acknowledge-sensitive-content": "1",
                **({"--media-index": params["--media-index"]} if "--media-index" in params else {}),
            }
        job = app.start_job(
            "human_review_campaign" if indexed else "human_audit", params, campaign_id=owner
        )
        metadata.update(
            {
                k: source.get(k, "")
                for k in (
                    "results",
                    "historical_code_repository",
                    "judge_configuration_sha256",
                    "media_index",
                )
            }
        )
        if indexed:
            metadata.update(
                source_kind="campaign_index", snapshot=str(directory / "sample.SNAPSHOT.json.gz")
            )
        if data.get("media_index", "").strip():
            metadata["media_index"] = str(store._path(data["media_index"]))
        key = store.save_preparation(
            owner,
            job.job_id,
            dict(
                name=data["name"],
                mode=data["mode"],
                prepared=str(directory / "sample.csv"),
                metadata=metadata,
            ),
        )
        return 303, "/human-evaluation/preparations/" + key, b""
    if path.startswith("/human-evaluation/preparations/"):
        key = path.rsplit("/", 1)[-1]
        draft = store.preparation(key)
        job = app.db.load_job(draft["job"])
        if job is None:
            raise ValueError(
                _ui_text("human_review_setup.the_sample_preparation_job_is_unavailable")
            )
        live = app.jobs.get(draft["job"])
        if live is not None and live.process is not None:
            # Read one process result, not its new terminal state paired with
            # an older SQLite exit code that the watcher has not saved yet.
            exit_code = live.exit_code()
            state = "running" if exit_code is None else "complete" if exit_code == 0 else "failed"
        else:
            state, exit_code = job["state"], job["exit_code"]
        ready = state == "complete" and exit_code == 0
        personal = draft["value"]["metadata"].get("review_kind") == "personal"
        pending_ethics = draft["value"]["metadata"].get("ethics_status") == "pending"
        if method == "POST":
            if not ready:
                raise ValueError(
                    _ui_text(
                        "human_review_setup.finish_sample_preparation_before_creating_the_study"
                    )
                )
            if pending_ethics:
                raise ValueError(
                    _ui_text(
                        "human_review_setup.record_the_actual_ethics_determination_before_creating_a_study_fo"
                    )
                )
            study = store.create_prepared_study(key)
            return (
                303,
                (
                    "/review/" + store.study(study)["metadata"]["personal_token"]
                    if personal
                    else "/human-evaluation/" + study
                ),
                b"",
            )
        body = (
            style
            + "<div class='review-stack'><section class='review-card'><h1>"
            + html.escape(draft["value"]["name"])
            + _ui_template("</h1><p>[[text:human_review_setup.sample_preparation]] ")
            + html.escape(state)
            + "</p><p><a href='/jobs/"
            + draft["job"]
            + _ui_template(
                "'>[[text:human_review_setup.open_preparation_job]]</a> | <a href='/human-evaluation?campaign_id="
            )
            + draft["campaign"]
            + _ui_template("'>[[text:human_review_setup.human_evaluation]]</a></p>")
        )
        if ready:
            with Path(draft["value"]["prepared"]).open(encoding="utf-8-sig", newline="") as f:
                rows = list(csv.DictReader(f))
            count = len({r["sample_key"] for r in rows})
            clusters = len({r.get("cluster_key", r["sample_key"]) for r in rows})
            body += (
                _ui_template("<h2>[[text:human_review_setup.check_the_review_workload]]</h2><p>")
                + f"{clusters:,}"
                + _ui_text("human_review_setup.source_clusters_2")
                + f"{count:,}"
                + _ui_text("human_review_setup.saved_outputs")
            )
            body += (
                (
                    f"{count:,}"
                    + _ui_template(
                        " [[text:human_review_setup.personal_evaluations_these_are_not_independent_two_rater_assessme]]</p>"
                    )
                )
                if personal
                else (
                    f"{2 * count:,}"
                    + _ui_template(
                        " [[text:human_review_setup.required_independent_ratings_plus_any_adjudication]]</p>"
                    )
                )
            )
            body += _ui_template(
                "<p>[[text:human_review_setup.no_human_ratings_have_been_created_by_preparation]]</p>"
            )
            if personal:
                body += _ui_template(
                    "<form method='post' id='open-personal-review'><button>[[text:human_review_setup.open_evaluation_form]]</button></form>"
                )
                body += "<script>document.addEventListener('DOMContentLoaded',()=>document.getElementById('open-personal-review').requestSubmit());</script>"
            elif pending_ethics:
                body += _ui_template(
                    "<p>[[text:human_review_setup.ethics_determination_is_not_decided_yet_you_can_inspect_this_samp]]</p>"
                )
            else:
                body += _ui_template(
                    "<form method='post'><button>[[text:human_review_setup.create_study_and_assign_reviewers]]</button></form>"
                )
            frame_path = Path(draft["value"]["prepared"]).with_suffix(".FRAME.json")
            if frame_path.is_file():
                frame = json.loads(frame_path.read_text(encoding="utf-8"))
                body += (
                    _ui_template("<p>[[text:human_review_setup.eligible_source_frame]] ")
                    + f"{frame['population_outputs']:,}"
                    + _ui_text("human_review_setup.outputs_in")
                    + f"{frame['population_clusters']:,}"
                    + _ui_template(
                        " [[text:human_review_setup.clusters_this_is_a_deterministic_achieved_sample_not_a_representa]]</p>"
                    )
                )
                body += (
                    _ui_template("<p>[[text:human_review_setup.campaign_outcome_accounting]] ")
                    + html.escape(
                        ", ".join(f"{k}: {v:,}" for k, v in frame["assignment_outcomes"].items())
                    )
                    + ".</p>"
                )
            media_report = Path(draft["value"]["prepared"]).with_suffix(".MEDIA-REPORT.json")
            if media_report.is_file():
                report = json.loads(media_report.read_text(encoding="utf-8"))
                body += (
                    _ui_template("<p>[[text:human_review_setup.saved_media]] ")
                    + f"{report.get('resolved_references', 0):,}"
                    + " / "
                    + f"{report.get('media_references', 0):,}"
                    + _ui_template(" [[text:human_review_setup.references_connected]]</p>")
                )
                if report.get("outputs_with_unavailable_media"):
                    body += (
                        "<p class='review-error'>"
                        + f"{report['outputs_with_unavailable_media']:,}"
                        + _ui_template(
                            " [[text:human_review_setup.outputs_have_unavailable_media_restore_these_assets_before_rating]]</p>"
                        )
                    )
        elif state in {"running", "starting", "queued"}:
            body += _ui_template(
                "<p role='status'>[[text:human_review_setup.preparing_the_selected_answers_automatically_you_can_leave_and_re]]</p><a class='button ghost' href=''>[[text:human_review_setup.refresh_preparation]]</a>"
            )
            body += "<script>setTimeout(()=>window.uraBusy.reload(),3000);</script>"
        else:
            body += _ui_template(
                "<p class='review-error'>[[text:human_review_setup.preparation_did_not_finish_successfully_inspect_the_job_before_co]]</p>"
            )
        return (
            200,
            "text/html; charset=utf-8",
            _page(
                _ui_text("human_review_setup.human_evaluation_preparation"),
                body + "</section></div>",
                active=_ui_text("human_review_setup.campaigns"),
            ),
        )
    return None
