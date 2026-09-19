"""Use the common funded judging executor for Build's all-output selection."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.retained_response_judge_execute import _write_new

from .builder_collection import collection_history
from .builder_haiku_judging import _choices
from .builder_native_judging import _state
from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


COMMAND = "retained_inventory_judging"


def prepare(app, params):
    owner = params.get("campaign_id", "")
    source = completed_argv(
        app, params.get("retained_inventory_items_job"), owner, "retained_inventory_judge_items"
    )
    forecast = completed_argv(
        app, params.get("retained_budget_job"), owner, "hosted_campaign_budget"
    )
    model = params.get("retained_haiku_model", "")
    if model not in _choices(app):
        raise ValueError(
            _ui_text(
                "builder_inventory_execution.choose_a_configured_haiku_model_in_the_judging_controls"
            )
        )
    _, _, _, configs = app._selected_api_config_snapshot(
        dict(mode="measured", api="", judges="llm", judge_model=model)
    )
    config = {model: dict(configs[model], max_tokens=512)}
    values = {
        "--items-root": argument(source, "--out"),
        "--judge-model": model,
        "--pricing-config": argument(forecast, "--pricing-config"),
        "--pricing-as-of": argument(forecast, "--pricing-as-of"),
        "--allow-token-counts": "on",
    }
    with app._app_lock:
        previous = collection_history(
            app, owner, [values["--items-root"]], command=COMMAND, input_flag="--items-root"
        )
        if previous is not None:
            argv = json.loads(previous["argv"])
            api = Path(argument(argv, "--api-config"))
            equivalent = argv == build_argv(
                COMMAND,
                dict(values, **{"--api-config": str(api), "--out": argument(argv, "--out")}),
            )
            if (
                equivalent
                and json.loads(api.read_text()) == config
                and _state(app, previous) in {"complete", "running", "queued", "starting"}
            ):
                app._save_build_campaign(
                    dict(params, retained_inventory_plan_job=previous["job_id"])
                )
                return SimpleNamespace(job_id=previous["job_id"])
            if _state(app, previous) in {"running", "queued", "starting"}:
                raise ValueError(
                    _ui_text(
                        "builder_inventory_execution.the_all_output_judging_preparation_is_active_open_that_job"
                    )
                )
        folder = (app.results_root / "rig-web" / "inventory-judging" / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        api = folder / "api-config.json"
        _write_new(api, config)
        values.update({"--api-config": str(api), "--out": str(folder / "prepared")})
        job = app.start_job(COMMAND, values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_inventory_plan_job=job.job_id))
        return job


def review(app, params):
    owner = params.get("campaign_id", "")
    argv = completed_argv(app, params.get("retained_inventory_plan_job"), owner, COMMAND)
    root = Path(argument(argv, "--out"))
    ready = json.loads((root / "result.json").read_text())
    if ready.get("status") not in {"ready_for_funded_judging", "needs_funding_review"}:
        raise ValueError(
            _ui_text(
                "builder_inventory_execution.select_a_completed_all_output_judging_preparation"
            )
        )
    coverage = ready["coverage"]
    body = _ui_template(
        "<h1>[[text:builder_inventory_execution.review_all_output_haiku_judging]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        "<p>"
        + f"{coverage['input_entries']:,}"
        + _ui_text("builder_inventory_execution.shared_inputs")
        + f"{coverage['retained_outputs']:,}"
        + _ui_text("builder_inventory_execution.saved_outputs")
        + f"{ready['selected_outputs']:,}"
        + _ui_text(
            "builder_inventory_execution.funded_answers_selected_for_output_specific_judging"
        )
        + f"{coverage['existing_execution_owned']:,}"
        + _ui_text(
            "builder_inventory_execution.outputs_remain_with_their_existing_judging_executions"
        )
        + f"{coverage['missing_outputs']:,}"
        + _ui_text("builder_inventory_execution.have_missing_text_and")
        + f"{coverage['unfunded_outputs']:,}"
        + _ui_template(
            " [[text:builder_inventory_execution.lack_matching_funding]]</p><p>[[text:builder_inventory_execution.each_saved_answer_receives_its_own_verdict_all_matching_local_mod]]</p><p>[[text:builder_inventory_execution.512_output_tokens_per_assessment_no_answer_retries_up_to_three_ht]]</p><p>[[text:builder_inventory_execution.first_attempt_estimate_usd]] "
        )
        + f"{ready['first_attempt_estimate_microusd'] / 1000000.0:,.6f}"
        + _ui_template(
            "[[text:builder_inventory_execution.this_is_an_estimate_not_spending_or_a_new_allowance]]</p>"
        )
    )
    if ready["funding_review"]:
        body += (
            "<p>"
            + f"{len(ready['funding_review']):,}"
            + _ui_template(
                " [[text:builder_inventory_execution.requests_exceed_their_existing_funded_slot_review_their_saved_cou]]</p>"
            )
        )
    elif ready["selected_outputs"]:
        values = {
            "--preparation": str(root),
            "--execute": "on",
            "--ack-paid-execution": "on",
            "--workers": "2",
            "--out": str(root.parent / "judgments"),
        }
        matching = params.get("retained_source_campaign", "")
        app.db.require_workspace(matching)
        if matching != owner:
            values["--matching-workspace-id"] = matching
        previous = collection_history(
            app, owner, [str(root)], command=COMMAND, input_flag="--preparation"
        )
        if previous is not None:
            old = json.loads(previous["argv"])
            values["--out"] = argument(old, "--out")
            if old != build_argv(COMMAND, values):
                raise ValueError(
                    _ui_text(
                        "builder_inventory_execution.resume_the_original_all_output_judging_campaigns_and_execution_se"
                    )
                )
        ticket = app._new_launch_ticket(
            dict(campaign_id=owner, values=json.dumps(values)), purpose="all-output-haiku"
        )
        body += (
            _ui_template(
                "<details><summary>[[text:builder_inventory_execution.exact_command]]</summary><pre>"
            )
            + html.escape(" ".join(build_argv(COMMAND, values)))
            + "</pre></details><form class='action-row' method='post' action='/build/execute-inventory-haiku'>"
            "<input type='hidden' name='launch_ticket' value='"
            + html.escape(ticket, quote=True)
            + _ui_template(
                '\'><button type="submit">[[text:builder_inventory_execution.start_or_resume_all_output_haiku_judging]]</button></form>'
            )
        )
    else:
        body += _ui_template(
            "<p>[[text:builder_inventory_execution.no_unstarted_funded_answers_remain_in_this_selection_existing_ver]]</p>"
        )
    body += (
        "<p><a href='/build?campaign_id="
        + html.escape(owner, quote=True)
        + _ui_template("'>[[text:builder_inventory_execution.return_to_build]]</a></p>")
    )
    return _page(
        _ui_text("builder_inventory_execution.review_all_output_haiku_judging"),
        body,
        active=_ui_text("builder_inventory_execution.build"),
    )


def launch(app, params):
    saved = app._launch_ticket_params(params.get("launch_ticket", ""), purpose="all-output-haiku")
    if saved is None:
        raise ValueError(
            _ui_text(
                "builder_inventory_execution.the_all_output_judging_review_expired_or_was_already_used"
            )
        )
    owner, values = saved["campaign_id"], json.loads(saved["values"])
    with app._app_lock:
        previous = collection_history(
            app, owner, [values["--preparation"]], command=COMMAND, input_flag="--preparation"
        )
        if previous is not None and _state(app, previous) in {
            "running",
            "starting",
            "queued",
            "complete",
        }:
            return SimpleNamespace(job_id=previous["job_id"])
        return app.start_job(COMMAND, values, campaign_id=owner)
