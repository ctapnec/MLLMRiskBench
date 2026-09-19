"""Native post-hoc scoring in Build, using the existing saved-output commands."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.hosted_retained_inputs import _descriptor

from .builder_collection import prepared_collection, collection_history, _program_paths
from .builder_replays import argument
from .catalog import build_argv
from .ui import _page


def preparation_history(app, owner, programs):
    rows = app.db._query(
        "SELECT j.* FROM jobs j JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id "
        "WHERE m.campaign_id=? AND j.command='retained_native_judge_prepare' ORDER BY j.started_at DESC,j.job_id DESC",
        (owner,),
    )
    if rows is None:
        raise ValueError(_ui_text("builder_native_judging.campaign_judging_history_is_unavailable"))
    return [
        row
        for row in rows
        if _program_paths(json.loads(row["argv"])) == [p["path"] for p in programs]
        and _program_paths(json.loads(row["argv"]), "--program-sha256")
        == [p["sha256"] for p in programs]
    ]


def _state(app, job):
    live = app.jobs.get(job["job_id"])
    return live.state() if live is not None else job["state"]


def prepare_native_judging(app, params):
    receipt = prepared_collection(app, params)
    with app._app_lock:
        history = preparation_history(app, params["campaign_id"], receipt["programs"])
        covered = set()
        for previous in history:
            if _state(app, previous) in {"running", "queued", "starting"}:
                app._save_build_campaign(
                    dict(params, retained_native_judging_job=previous["job_id"])
                )
                return SimpleNamespace(job_id=previous["job_id"])
            path = Path(argument(json.loads(previous["argv"]), "--out")) / "result.json"
            if path.exists():
                prepared = json.loads(path.read_text())
                covered.update((unit["program"], unit["job"]) for unit in prepared.get("units", []))
        sources = [
            (p["path"], job["name"])
            for p in receipt["programs"]
            for job in json.loads(Path(p["path"]).read_text())["jobs"]
        ]
        remaining = [source for source in sources if source not in covered]
        if not remaining:
            if not history:
                raise ValueError(
                    _ui_text(
                        "builder_native_judging.no_source_runs_are_available_in_these_programs"
                    )
                )
            app._save_build_campaign(dict(params, retained_native_judging_job=history[0]["job_id"]))
            return SimpleNamespace(job_id=history[0]["job_id"])
        names = {name for _, name in remaining}
        if any(name in names for path, name in sources if (path, name) in covered):
            raise ValueError(
                _ui_text(
                    "builder_native_judging.ambiguous_source_run_names_across_programs_select_these_programs"
                )
            )
        values = {
            "--out": str((app.results_root / "rig-web" / "native-judging" / uuid4().hex).resolve())
        }
        Path(values["--out"]).parent.mkdir(parents=True, exist_ok=True)
        for index, descriptor in enumerate(receipt["programs"]):
            suffix = f"#{index}" if index else ""
            values["--program" + suffix] = descriptor["path"]
            values["--program-sha256" + suffix] = descriptor["sha256"]
        for index, name in enumerate(sorted(names)):
            values["--job" + (f"#{index}" if index else "")] = name
        params = app._save_build_campaign(params)
        job = app.start_job(
            "retained_native_judge_prepare", values, campaign_id=params["campaign_id"]
        )
        app._save_build_campaign(dict(params, retained_native_judging_job=job.job_id))
        return job


def scoring_description(source):
    stages = source["judge_cascade"]["stages"]
    guard = stages[1]
    device = guard.get("device") or _ui_text("builder_native_judging.automatic_gpu_placement")
    return (
        "Rules, then "
        + f"{guard['model_id']}"
        + " on "
        + f"{device}"
        + _ui_text("builder_native_judging.classifier_output_allowance")
        + f"{guard['max_new_tokens']:,}"
        + " tokens"
    )


def native_judging_review(app, params):
    owner = params.get("campaign_id", "")
    app.db.require_workspace(owner)
    job = app.db.load_job(params.get("retained_native_judging_job"))
    if (
        job is None
        or job["command"] != "retained_native_judge_prepare"
        or job["state"] not in {"complete", "failed"}
        or job["exit_code"] not in {0, 1}
        or app.db.workspace_for_job(job["job_id"]) != owner
    ):
        raise ValueError(
            _ui_text(
                "builder_native_judging.finish_this_campaign_s_native_judging_preparation_first"
            )
        )
    root = Path(argument(json.loads(job["argv"]), "--out"))
    path = root / "result.json"
    prepared = json.loads(path.read_text())
    if prepared.get("status") not in {"prepared", "preparation_incomplete"} or not prepared.get(
        "units"
    ):
        raise ValueError(
            _ui_text(
                "builder_native_judging.no_complete_retained_source_units_are_available_for_local_judging"
            )
        )
    descriptor = _descriptor(path)
    values = {
        "--preparation": str(path),
        "--preparation-sha256": descriptor["sha256"],
        "--out": str(root / "judgments"),
    }
    if params.get("retained_native_verify_model") == "on":
        values["--verify-model-sha256"] = "on"
    if params.get("retained_native_verify_artifacts") == "on":
        values["--verify-artifact-sha256"] = "on"
    history = collection_history(
        app, owner, [str(path)], command="retained_native_judge_execute", input_flag="--preparation"
    )
    if history is not None:
        old = json.loads(history["argv"])
        values["--out"] = argument(old, "--out")
        if ("--verify-model-sha256" in old) != ("--verify-model-sha256" in values):
            raise ValueError(
                _ui_text(
                    "builder_native_judging.keep_the_original_model_verification_setting_when_resuming_local"
                )
            )
    ticket = app._new_launch_ticket(
        dict(
            campaign_id=owner,
            values=json.dumps(values),
            previous_job=history["job_id"] if history is not None else "",
        ),
        purpose="matched-native-judge",
    )
    failed = sum(source["assigned"] for source in prepared.get("failed", []))
    rows = "".join(
        "<tr><td>"
        + html.escape(source["target"])
        + "</td><td>"
        + html.escape(source["job"])
        + f"</td><td>{source['assigned']:,}</td><td>"
        + html.escape(scoring_description(source))
        + "</td></tr>"
        for source in prepared["units"]
    )
    body = _ui_template(
        "<h1>[[text:builder_native_judging.review_local_judging]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        (
            "<p>"
            + f"{prepared['outputs']:,}"
            + _ui_text("builder_native_judging.retained_outputs_in")
            + f"{len(prepared['units']):,}"
            + _ui_template(
                " [[text:builder_native_judging.prepared_source_units_the_original_source_criteria_and_scoring_ca]]</p><p>[[text:builder_native_judging.judging_preserves_the_saved_placement_policy_including_automatic]]</p>"
            )
        )
        + (
            (
                "<p class='notice amber'>"
                + f"{failed:,}"
                + _ui_template(
                    " [[text:builder_native_judging.assigned_outputs_are_not_prepared_their_source_errors_remain_visi]]</p>"
                )
            )
            if failed
            else ""
        )
        + _ui_template(
            "<div class='scroll'><table style='min-width:54rem'><tr><th>[[text:builder_native_judging.target_model]]</th><th>[[text:builder_native_judging.source_run]]</th><th>[[text:builder_native_judging.outputs]]</th><th>[[text:builder_native_judging.saved_scoring_condition]]</th></tr>"
        )
        + rows
        + "</table></div>"
        + _ui_template(
            "<details><summary>[[text:builder_native_judging.exact_command]]</summary><pre>"
        )
        + html.escape(" ".join(build_argv("retained_native_judge_execute", values)))
        + "</pre></details><form class='action-row' method='post' action='/build/judge-retained-local'>"
        "<input type='hidden' name='launch_ticket' value='"
        + html.escape(ticket, quote=True)
        + _ui_template(
            '\'><button type="submit">[[text:builder_native_judging.start_or_resume_local_judging]]</button></form>'
        )
        + "<p><a href='/build?campaign_id="
        + owner
        + _ui_template("'>[[text:builder_native_judging.return_to_build]]</a></p>")
    )
    return _page(
        _ui_text("builder_native_judging.review_local_judging"),
        body,
        active=_ui_text("builder_native_judging.build"),
    )


def judge_retained_local(app, form):
    if set(form) != {"launch_ticket"}:
        raise ValueError(
            _ui_text("builder_native_judging.review_the_retained_local_judging_selection_first")
        )
    params = app._launch_ticket_params(form["launch_ticket"], purpose="matched-native-judge")
    if params is None:
        raise ValueError(
            _ui_text("builder_native_judging.local_judging_review_expired_or_was_already_used")
        )
    values, owner = json.loads(params["values"]), params["campaign_id"]
    with app._app_lock:
        history = collection_history(
            app,
            owner,
            [values["--preparation"]],
            command="retained_native_judge_execute",
            input_flag="--preparation",
        )
        if (history["job_id"] if history is not None else "") != params["previous_job"]:
            raise ValueError(
                _ui_text(
                    "builder_native_judging.this_judging_selection_has_a_newer_launch_open_that_job_before_co"
                )
            )
        if history is not None:
            if _state(app, history) in {"running", "queued", "starting"}:
                raise ValueError(
                    _ui_text(
                        "builder_native_judging.this_local_judging_selection_is_already_active"
                    )
                )
        return app.start_job("retained_native_judge_execute", values, campaign_id=owner)


def native_judging_panel(app, params):
    if not params.get("retained_programs_job"):
        return ""
    job = params.get("retained_native_judging_job", "")
    body = _ui_template(
        "<section class='card' id='retained-local-judging'><h2>[[text:builder_native_judging.judge_retained_outputs_locally]]</h2><p>[[text:builder_native_judging.prepare_the_saved_collection_outputs_for_their_original_source_sp]]</p><p>[[text:builder_native_judging.preparation_reuses_active_or_already_prepared_work_after_more_sou]]</p><button form='builder' formaction='/build/prepare-operation/local-judging'>[[text:builder_native_judging.review_local_judging]]</button>"
    )
    if job:
        escaped = html.escape(job, quote=True)
        try:
            receipt = prepared_collection(app, params)
        except (ValueError, OSError, KeyError):
            return body + _ui_template(
                "<p>[[text:builder_native_judging.finish_the_selected_collection_preparation_to_review_its_judging]]</p></section>"
            )
        history = preparation_history(app, params["campaign_id"], receipt["programs"])
        body += _ui_template(
            "<details class='card'><summary>[[text:builder_native_judging.earlier_judging_selections_and_technical_options]]</summary><label class='campaign-field separated-field'>[[text:builder_native_judging.saved_judging_preparation]]<select form='builder' name='retained_native_judging_job'>"
        )
        body += "".join(
            "<option value='"
            + html.escape(row["job_id"], quote=True)
            + "'"
            + (" selected" if row["job_id"] == job else "")
            + ">"
            + html.escape(row["job_id"] + " - " + _state(app, row))
            + "</option>"
            for row in history
        )
        body += "</select></label>"
        body += (
            "<p><a href='/jobs/"
            + escaped
            + _ui_template(
                "'>[[text:builder_native_judging.open_judging_preparation_and_source_errors]]</a></p>"
            )
        )
        for field, label in [
            (
                "retained_native_verify_model",
                _ui_text("builder_native_judging.full_model_checksum_revalidation"),
            ),
            (
                "retained_native_verify_artifacts",
                _ui_text("builder_native_judging.full_result_file_checksum_revalidation"),
            ),
        ]:
            body += (
                "<label class='checkrow'><input type='checkbox' form='builder' name='"
                + field
                + "'"
                + (" checked" if params.get(field) == "on" else "")
                + "><span>"
                + label
                + _ui_template(" [[text:builder_native_judging.optional]]</span></label>")
            )
        body += _ui_template(
            "<button form='builder' formaction='/build/review-native-judging'>[[text:builder_native_judging.review_earlier_selection]]</button></details>"
        )
    return body + "</section>"
