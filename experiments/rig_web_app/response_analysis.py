"""Scientific SVM choices, with no operator-managed export or file handoffs."""

from .i18n import template as _ui_template, text as _ui_text
import html
import json
from uuid import uuid4

from .builder_replays import argument
from .builder_sources import source_runs
from .ui import _page
from .workspace_judge_settings import indexed_settings, judge_name


def history(app, owner):
    return (
        app.db._query(
            "SELECT j.* FROM jobs j JOIN campaign_members m ON "
            "m.member_kind='job' AND m.member_id=j.job_id WHERE m.campaign_id=? "
            "AND j.command='response_svm' ORDER BY j.started_at DESC",
            (owner,),
        )
        or []
    )


def teachers(app, owner):
    return (
        app.db._query(
            "SELECT judge_id,COUNT(*) AS n FROM campaign_judgments "
            "WHERE campaign_id=? AND status='valid' AND judge_id LIKE '%haiku%' "
            "GROUP BY judge_id ORDER BY judge_id",
            (owner,),
        )
        or []
    )


def select(name, label, options, selected=""):
    escape = lambda v: html.escape(str(v), quote=True)
    placeholder = (
        _ui_template('<option value="" selected>[[text:response_analysis.choose]] ')
        + escape(label.lower())
        + "</option>"
        if len(options) > 1 and selected not in {key for key, _ in options}
        else ""
    )
    return (
        '<label class="campaign-field">'
        + escape(label)
        + '<select aria-label="'
        + escape(label)
        + '" name="'
        + name
        + '" required>'
        + placeholder
        + "".join(
            '<option value="'
            + escape(key)
            + '"'
            + (" selected" if key == selected else "")
            + ">"
            + escape(value)
            + "</option>"
            for key, value in options
        )
        + "</select></label>"
    )


def page(app, owner):
    app.db.require_workspace(owner)
    saved = app.db.workspace_definition(owner)
    campaigns = app.db.workspaces() or []
    campaign_options = [(r["campaign_id"], r["name"]) for r in campaigns]
    local_options = [
        (r["campaign_id"], r["name"]) for r in campaigns if source_runs(app.db, r["campaign_id"])
    ]
    teacher_rows = teachers(app, owner)
    settings = indexed_settings(app.db, owner)
    teacher_options = [
        (
            r["judge_id"],
            judge_name(r["judge_id"], settings.get(r["judge_id"]))
            + _ui_text("response_analysis.condition")
            + str(i + 1)
            + "; "
            + str(r["n"])
            + _ui_text("response_analysis.valid_recorded_verdicts"),
        )
        for i, r in enumerate(teacher_rows)
    ]
    body = _ui_template(
        "<h1>[[text:response_analysis.response_classifier_analysis]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        '<div class="action-row"><a class="button ghost" href="/stats?view=svm&amp;campaign_id='
        + owner
        + _ui_template('">[[text:response_analysis.view_svm_results_in_stats]]</a></div>')
    )
    body += _ui_template(
        '<section class="card"><h2>[[text:response_analysis.evaluate_and_save_the_three_classifiers]]</h2><p>[[text:response_analysis.choose_the_data_population_and_recorded_teacher_the_system_select]]</p><p>[[text:response_analysis.tasks_harmful_compliance_over_refusal_and_local_haiku_disagreemen]]</p>'
    )
    if local_options and teacher_options:
        token = app._new_launch_ticket({"campaign_id": owner}, purpose="svm-study")
        body += (
            '<form method="post" action="/analysis/start"><input type="hidden" name="launch_ticket" value="'
            + html.escape(token)
            + '">'
        )
        body += '<div class="campaign-grid">' + select(
            "source_campaign",
            _ui_text("response_analysis.saved_local_input_source"),
            local_options,
            saved.get("retained_source_campaign", owner),
        )
        body += select(
            "matched_campaign",
            _ui_text("response_analysis.restrict_to_inputs_assigned_in"),
            campaign_options,
            owner,
        )
        body += (
            select(
                "teacher", _ui_text("response_analysis.recorded_haiku_condition"), teacher_options
            )
            + "</div>"
        )
        body += _ui_template(
            '<label class="checkrow"><input type="checkbox" name="include_source" checked><span>[[text:response_analysis.include_matching_answers_from_the_local_source_campaign]]</span></label>'
        )
        body += _ui_template(
            '<details class="card"><summary>[[text:response_analysis.scientific_analysis_options]]</summary><div class="campaign-grid">'
        )
        body += _ui_template(
            '<label class="campaign-field">[[text:response_analysis.split_seed]]<input name="seed" type="number" value="0" required></label>'
        )
        body += _ui_template(
            '<label class="campaign-field">[[text:response_analysis.bootstrap_samples]]<input name="bootstrap" type="number" min="100" max="10000" value="1000" required></label></div></details>'
        )
        body += _ui_template(
            '<p>[[text:response_analysis.no_target_or_judge_calls_are_made_this_fits_recorded_teacher_labe]]</p><div class="action-row"><button>[[text:response_analysis.start_classifier_study]]</button></div></form>'
        )
    else:
        body += _ui_template(
            '<p class="notice amber">[[text:response_analysis.this_study_needs_indexed_local_source_inputs_and_valid_haiku_verd]]</p>'
        )
    body += "</section>"
    rows = history(app, owner)
    if rows:
        body += _ui_template(
            '<section class="card"><h2>[[text:response_analysis.saved_analyses]]</h2><ul>'
        )
        for row in rows:
            argv = json.loads(row["argv"])
            label = (
                _ui_text("response_analysis.classifier_study")
                if "--study" in argv
                else _ui_text("response_analysis.classifier_analysis")
            )
            body += (
                '<li><a href="/jobs/'
                + row["job_id"]
                + '">'
                + label
                + " - "
                + html.escape(row["state"])
                + "</a>"
            )
            from .analysis_summary import render

            if argument(argv, "--out"):
                body += render(app, argument(argv, "--out"))
            if "--study" in argv and row["state"] in {"failed", "stopped", "interrupted"}:
                ticket = app._new_launch_ticket(
                    dict(campaign_id=owner, job=row["job_id"]), purpose="svm-resume"
                )
                body += (
                    '<form class="action-row" method="post" action="/analysis/resume"><input type="hidden" name="launch_ticket" value="'
                    + ticket
                    + _ui_template(
                        '"><button>[[text:response_analysis.resume_unfinished_analysis]]</button></form>'
                    )
                )
            body += "</li>"
        body += "</ul></section>"
    return _page(
        _ui_text("response_analysis.response_classifier_analysis"),
        body,
        active=_ui_text("response_analysis.stats"),
    )


def start(app, data):
    fields = {
        "launch_ticket",
        "source_campaign",
        "matched_campaign",
        "teacher",
        "include_source",
        "seed",
        "bootstrap",
    }
    if set(data) - fields:
        raise ValueError(_ui_text("response_analysis.unexpected_analysis_setting"))
    ticket = app._launch_ticket_params(data.get("launch_ticket", ""), purpose="svm-study")
    if ticket is None:
        raise ValueError(_ui_text("response_analysis.reopen_the_analysis_form_before_starting"))
    owner = ticket["campaign_id"]
    source = data.get("source_campaign", "")
    matched = data.get("matched_campaign", "")
    for key in (owner, source, matched):
        app.db.require_workspace(key)
    if data.get("teacher") not in {r["judge_id"] for r in teachers(app, owner)}:
        raise ValueError(
            _ui_text("response_analysis.choose_a_recorded_haiku_condition_for_this_campaign")
        )
    seed = int(data.get("seed", "0"))
    bootstrap = int(data.get("bootstrap", "1000"))
    if not 100 <= bootstrap <= 10000:
        raise ValueError(
            _ui_text("response_analysis.bootstrap_samples_must_be_between_100_and_10000")
        )
    for row in history(app, owner):
        live = app.jobs.get(row["job_id"])
        if (live.state() if live else row["state"]) in {"running", "queued", "starting"}:
            raise ValueError(
                _ui_text(
                    "response_analysis.this_campaign_already_has_active_classifier_analysis_open_that_jo"
                )
            )
    rows = source_runs(app.db, source)
    if not rows:
        raise ValueError(_ui_text("response_analysis.choose_a_saved_local_source_campaign"))
    out = (app.results_root / "rig-web" / "response-analysis" / uuid4().hex).resolve()
    values = {"--source-campaign": source, "--out": str(out)}
    values.update(
        {
            "--study": "on",
            "--database": str(app.db.path),
            "--campaign": owner,
            "--matched-campaign": matched,
            "--judge-condition": data["teacher"],
            "--seed": str(seed),
            "--bootstrap": str(bootstrap),
        }
    )
    if data.get("include_source") == "on" and source != owner:
        values["--campaign#1"] = source
    return app.start_job("response_svm", values, campaign_id=owner)


def resume(app, data):
    if set(data) != {"launch_ticket"}:
        raise ValueError(_ui_text("response_analysis.use_the_saved_analysis_continuation"))
    ticket = app._launch_ticket_params(data["launch_ticket"], purpose="svm-resume")
    if ticket is None:
        raise ValueError(_ui_text("response_analysis.reopen_the_saved_analysis_before_continuing"))
    rows = history(app, ticket["campaign_id"])
    row = next((r for r in rows if r["job_id"] == ticket["job"]), None)
    if row is None or row["state"] not in {"failed", "stopped", "interrupted"}:
        raise ValueError(_ui_text("response_analysis.only_unfinished_analysis_can_resume"))
    argv = json.loads(row["argv"])
    if "--study" not in argv:
        raise ValueError(
            _ui_text("response_analysis.this_older_analysis_is_not_an_automatic_study")
        )
    out = argument(argv, "--out")
    for previous in rows:
        live = app.jobs.get(previous["job_id"])
        if argument(json.loads(previous["argv"]), "--out") == out and (
            live.state() if live else previous["state"]
        ) in {"running", "queued", "starting"}:
            raise ValueError(_ui_text("response_analysis.this_study_is_already_running"))
    # The original typed argv also covers interruption before selection.json
    # was written. Do not infer a new population from the current campaign.
    from .catalog import COMMANDS

    definitions = {p.flag: p for p in COMMANDS["response_svm"].params}
    values = {}
    counts = {}
    index = 3
    while index < len(argv):
        flag = argv[index]
        definition = definitions.get(flag)
        if definition is None:
            raise ValueError(_ui_text("response_analysis.saved_analysis_arguments_are_unavailable"))
        count = counts.get(flag, 0)
        counts[flag] = count + 1
        key = flag + (f"#{count}" if count else "")
        if definition.kind == "flag":
            values[key] = "on"
            index += 1
        else:
            values[key] = argv[index + 1]
            index += 2
    return app.start_job("response_svm", values, campaign_id=ticket["campaign_id"])
