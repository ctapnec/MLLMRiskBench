"""Campaign-level assessment independent of how its answers were collected."""

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text
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
    if not owner:
        return ""
    return (
        _ui_template(
            '<section class="card" id="campaign-assessment"><h2>[[text:campaign_assessment.evaluate_saved_campaign_answers]]</h2><p>[[text:campaign_assessment.fill_missing_local_or_haiku_verdicts_on_indexed_answers_regardles]]</p><a href="/assessment?campaign_id='
        )
        + html.escape(owner)
        + _ui_template(
            '">[[text:campaign_assessment.choose_saved_output_assessment]]</a></section>'
        )
    )


def history(app, owner):
    return (
        app.db._query(
            "SELECT j.* FROM jobs j JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id WHERE m.campaign_id=? AND j.command='campaign_assess' ORDER BY j.started_at DESC",
            (owner,),
        )
        or []
    )


def page(app, owner):
    app.db.require_workspace(owner)
    ticket = app._new_launch_ticket(dict(campaign_id=owner), purpose="campaign-assessment")
    body = _ui_template(
        "<h1>[[text:campaign_assessment.evaluate_saved_answers]]</h1>"
    ) + app._campaign_banner(owner)
    body += _ui_template(
        '<section class="card"><h2>[[text:campaign_assessment.fill_missing_judgments]]</h2><p>[[text:campaign_assessment.select_the_evaluator_and_workload_saved_prompts_and_each_model_s]]</p>'
    )
    body += (
        '<form method="post" action="/assessment/prepare"><input type="hidden" name="launch_ticket" value="'
        + ticket
        + '"><div class="campaign-grid">'
    )
    body += _ui_template(
        '<label class="campaign-field">[[text:campaign_assessment.evaluator]]<select name="kind" aria-label="[[attr:campaign_assessment.evaluator]]"><option value="local">[[text:campaign_assessment.original_local_rules_and_guardrail]]</option><option value="haiku">[[text:campaign_assessment.haiku]]</option></select></label>'
    )
    body += _ui_template(
        '<label class="campaign-field">[[text:campaign_assessment.maximum_pending_answers_0_all]]<input name="limit" type="number" min="0" value="0" required></label>'
    )
    choices = _choices(app)
    body += (
        _ui_template(
            '<label class="campaign-field" data-haiku-option>[[text:campaign_assessment.haiku_judge]]<select name="judge_model" aria-label="[[attr:campaign_assessment.haiku_judge]]">'
        )
        + "".join("<option>" + html.escape(model) + "</option>" for model in choices)
        + "</select></label>"
    )
    body += _ui_template(
        '<label class="campaign-field" data-haiku-option>[[text:campaign_assessment.maximum_assessment_spending_usd]]<input name="cost" type="number" min="0.000001" step="0.000001" placeholder="[[attr:campaign_assessment.choose_a_spending_limit]]"></label></div>'
    )
    body += _ui_template(
        '<p>[[text:campaign_assessment.common_metric_evaluable_answers_only_images_use_their_saved_text]]</p><div class="action-row"><button>[[text:campaign_assessment.prepare_assessment_and_review]]</button></div></form></section>'
    )
    body += """<script>(()=>{const kind=document.querySelector('[name=kind]');const update=()=>{document.querySelectorAll('[data-haiku-option]').forEach(e=>{e.hidden=kind.value!=='haiku';e.querySelector('input,select').disabled=e.hidden;});};kind.addEventListener('change',update);update();})();</script>"""
    rows = history(app, owner)
    if rows:
        body += _ui_template(
            '<section class="card"><h2>[[text:campaign_assessment.prepared_assessments_and_progress]]</h2><ul>'
        )
        for row in rows:
            argv = json.loads(row["argv"])
            if "--execute" in argv:
                continue
            body += (
                '<li><a href="/assessment/review?campaign_id='
                + owner
                + "&job="
                + row["job_id"]
                + _ui_template('">[[text:campaign_assessment.saved_assessment]] ')
                + html.escape(row["state"])
                + "</a></li>"
            )
        body += "</ul></section>"
    return _page(
        _ui_text("campaign_assessment.evaluate_saved_answers"),
        body,
        active=_ui_text("campaign_assessment.campaigns"),
    )


def prepare(app, data):
    if set(data) - {"launch_ticket", "kind", "limit", "judge_model", "cost"}:
        raise ValueError(_ui_text("campaign_assessment.unexpected_assessment_field"))
    ticket = app._consume_launch_ticket(
        data.get("launch_ticket", ""), purpose="campaign-assessment"
    )
    if ticket is None:
        raise ValueError(_ui_text("campaign_assessment.reopen_the_assessment_form"))
    owner = ticket[0]["campaign_id"]
    kind = data.get("kind")
    limit = int(data.get("limit", "0"))
    if kind not in {"local", "haiku"} or limit < 0:
        raise ValueError(
            _ui_text("campaign_assessment.choose_an_evaluator_and_a_nonnegative_answer_limit")
        )
    values = prepare_values(
        app,
        owner,
        kind=kind,
        limit=limit,
        judge=data.get("judge_model", ""),
        cost=data.get("cost", ""),
    )
    return app.start_job("campaign_assess", values, campaign_id=owner)


def prepare_values(app, owner, *, kind, limit=0, judge="", cost="", root=None):
    app.db.require_workspace(owner)
    root = root or (app.results_root / "rig-web" / "campaign-assessment" / uuid4().hex).resolve()
    root.mkdir(parents=True, mode=0o700)
    values = {
        "--database": str(app.db.path),
        "--campaign": owner,
        "--results-root": str(app.results_root),
        "--kind": kind,
        "--limit": str(limit),
        "--out": str(root),
    }
    if os.environ.get("URA_MODEL_STORE"):
        values["--model-store"] = os.environ["URA_MODEL_STORE"]
    if kind == "haiku":
        if judge not in _choices(app):
            raise ValueError(_ui_text("campaign_assessment.choose_a_configured_haiku_judge"))
        try:
            cost = Decimal(cost) * 1_000_000
            if not cost.is_finite() or cost <= 0 or cost != cost.to_integral_value():
                raise ValueError("cost")
        except (InvalidOperation, ValueError):
            raise ValueError(
                _ui_text(
                    "campaign_assessment.choose_a_positive_usd_ceiling_with_at_most_six_decimal_places"
                )
            )
        _, _, _, configs = app._selected_api_config_snapshot(
            dict(api=judge, judges="", mode="measured")
        )
        config = dict(configs[judge], max_tokens=512)
        for name, value in [
            ("api.json", {judge: config}),
            ("pricing.json", app._load_registry("pricing.json", "rig/pricing.example.json")),
        ]:
            app._write_private_workflow_file(root / name, (json.dumps(value) + "\n").encode())
        values.update(
            {
                "--judge-model": judge,
                "--max-cost-microusd": str(int(cost)),
                "--api-config": str(root / "api.json"),
                "--pricing-config": str(root / "pricing.json"),
            }
        )
    return values


def reviewed(app, owner, job_id):
    row = next((r for r in history(app, owner) if r["job_id"] == job_id), None)
    if row is None:
        raise ValueError(
            _ui_text("campaign_assessment.choose_an_assessment_belonging_to_this_campaign")
        )
    argv = json.loads(row["argv"])
    root = Path(argument(argv, "--out")).resolve()
    if not root.is_relative_to(app.results_root.resolve()):
        raise ValueError(_ui_text("campaign_assessment.assessment_output_is_unavailable"))
    return row, root


def review(app, owner, job_id):
    row, root = reviewed(app, owner, job_id)
    body = _ui_template(
        "<h1>[[text:campaign_assessment.review_saved_output_assessment]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        '<p><a href="/jobs/'
        + job_id
        + _ui_template(
            '">[[text:campaign_assessment.preparation_progress_and_error_details]]</a></p>'
        )
    )
    live = app.jobs.get(job_id)
    state = live.state() if live else row["state"]
    if state in {"running", "queued", "starting"}:
        return _page(
            _ui_text("campaign_assessment.preparing_assessment"),
            body
            + _ui_template(
                '<p role="status">[[text:campaign_assessment.connecting_saved_answers_and_calculating_assessment_costs]]</p><script>setTimeout(()=>window.uraBusy.reload(),3000);</script>'
            ),
            active=_ui_text("campaign_assessment.campaigns"),
        )
    if not (root / "result.json").is_file():
        return _page(
            _ui_text("campaign_assessment.assessment_needs_attention"),
            body
            + _ui_template(
                "<p>[[text:campaign_assessment.preparation_did_not_complete_open_its_job_to_inspect_the_cause_no]]</p>"
            ),
            active=_ui_text("campaign_assessment.campaigns"),
        )
    result = json.loads((root / "result.json").read_text())
    body += (
        '<section class="card"><h2>'
        + str(result["selected_outputs"])
        + _ui_template(
            " [[text:campaign_assessment.answers_selected]]</h2><p>[[text:campaign_assessment.no_target_generation_will_be_repeated]]</p>"
        )
    )
    body += (
        "<ul>"
        + "".join(
            "<li>" + html.escape(_ui_label(key)) + ": " + str(value) + "</li>"
            for key, value in result["dispositions"].items()
        )
        + "</ul>"
    )
    body += (
        _ui_template("<p>[[text:campaign_assessment.missing_source_context]] ")
        + str(len(result["unavailable"]))
        + _ui_template(
            "[[text:campaign_assessment.missing_responses_remain_in_campaign_coverage_not_the_judging_den]]</p>"
        )
    )
    if result["kind"] == "haiku":
        for key, label in [
            (
                "first_attempt_bound_microusd",
                _ui_text("campaign_assessment.first_attempt_conservative_bound"),
            ),
            (
                "retry_inclusive_bound_microusd",
                _ui_text("campaign_assessment.including_all_eligible_http_retries"),
            ),
            ("max_cost_microusd", _ui_text("campaign_assessment.your_spending_ceiling")),
        ]:
            body += "<p>" + label + ": $" + f"{result.get(key, 0) / 1e6:.4f}" + "</p>"
    if result["status"] == "over_budget":
        body += _ui_template(
            '<p class="notice amber">[[text:campaign_assessment.the_selected_workload_exceeds_your_ceiling_return_to_assessment_a]]</p>'
        )
    elif not result["selected_outputs"]:
        body += _ui_template(
            "<p>[[text:campaign_assessment.no_eligible_pending_answers_existing_valid_judgments_have_not_bee]]</p>"
        )
    elif (root / "completion.json").exists():
        body += (
            _ui_template(
                '<p>[[text:campaign_assessment.assessment_complete]]</p><a href="/campaigns/'
            )
            + owner
            + _ui_template(
                '?section=judging">[[text:campaign_assessment.view_campaign_judgments]]</a>'
            )
        )
    else:
        active = next(
            (
                j
                for j in history(app, owner)
                if "--execute" in json.loads(j["argv"])
                and argument(json.loads(j["argv"]), "--out") == str(root)
                and (app.jobs[j["job_id"]].state() if j["job_id"] in app.jobs else j["state"])
                in {"running", "queued", "starting"}
            ),
            None,
        )
        if active:
            body += (
                '<a href="/jobs/'
                + active["job_id"]
                + _ui_template(
                    '">[[text:campaign_assessment.open_active_assessment_and_stop_job]]</a>'
                )
            )
        else:
            ticket = app._new_launch_ticket(
                dict(campaign_id=owner, job=job_id), purpose="campaign-assessment-start"
            )
            body += (
                '<form class="action-row" method="post" action="/assessment/start"><input type="hidden" name="launch_ticket" value="'
                + ticket
                + _ui_template(
                    '"><button>[[text:campaign_assessment.start_or_resume_assessment]]</button></form>'
                )
            )
    body += (
        '</section><p><a href="/assessment?campaign_id='
        + owner
        + _ui_template('">[[text:campaign_assessment.back_to_campaign_assessment]]</a></p>')
    )
    return _page(
        _ui_text("campaign_assessment.review_assessment"),
        body,
        active=_ui_text("campaign_assessment.campaigns"),
    )


def launch(app, data):
    if set(data) != {"launch_ticket"}:
        raise ValueError(_ui_text("campaign_assessment.review_the_saved_assessment_first"))
    ticket = app._consume_launch_ticket(data["launch_ticket"], purpose="campaign-assessment-start")
    if ticket is None:
        raise ValueError(
            _ui_text("campaign_assessment.this_assessment_start_was_already_used_or_expired")
        )
    owner = ticket[0]["campaign_id"]
    row, root = reviewed(app, owner, ticket[0]["job"])
    result = json.loads((root / "result.json").read_text())
    if (
        result["status"] != "prepared"
        or not result["selected_outputs"]
        or (root / "completion.json").exists()
    ):
        raise ValueError(
            _ui_text("campaign_assessment.this_assessment_has_no_pending_reviewed_work")
        )
    for previous in history(app, owner):
        live = app.jobs.get(previous["job_id"])
        if (live.state() if live else previous["state"]) in {"running", "queued", "starting"}:
            raise ValueError(
                _ui_text(
                    "campaign_assessment.an_assessment_is_already_active_in_this_campaign_open_its_existin"
                )
            )
    return app.start_job(
        "campaign_assess",
        {"--execute": "on", "--database": str(app.db.path), "--out": str(root)},
        campaign_id=owner,
    )
