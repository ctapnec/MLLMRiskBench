"""Review all saved model outputs on shared inputs without buying judgments."""

from __future__ import annotations


from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.retained_judge_inventory import SCHEMA

from .builder_collection import prepared_collection, collection_history
from .builder_native_judging import preparation_history, _state
from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


def prepare_judging_inventory(app, params):
    owner = params.get("campaign_id", "")
    receipt = prepared_collection(app, params)
    source = completed_argv(
        app, params.get("retained_sources_job"), owner, "retained_local_sources"
    )
    preparations = preparation_history(app, owner, receipt["programs"])
    views = []
    eligible = set()
    for job in preparations:
        if _state(app, job) not in {"complete", "failed"} or job["exit_code"] not in {0, 1}:
            continue
        path = Path(argument(json.loads(job["argv"]), "--out")) / "result.json"
        if not path.is_file():
            continue
        saved = json.loads(path.read_text())
        if saved.get("status") not in {"prepared", "preparation_incomplete"}:
            continue
        views.append(str(path))
        eligible.add(job["job_id"])
    if params.get("retained_native_judging_job") not in eligible:
        raise ValueError(
            _ui_text(
                "builder_judging_inventory.select_this_campaign_s_completed_saved_output_preparation_first"
            )
        )
    try:
        limit = int(params.get("retained_inventory_limit", "0"))
        seed = int(params.get("retained_inventory_seed", "0"))
    except ValueError:
        raise ValueError(
            _ui_text("builder_judging_inventory.use_a_whole_number_input_limit_and_selection_seed")
        ) from None
    if limit < 0:
        raise ValueError(
            _ui_text(
                "builder_judging_inventory.input_limit_must_be_zero_for_all_inputs_or_a_positive_integer"
            )
        )
    values = {
        "--local-view": argument(source, "--out"),
        "--input-limit": str(limit),
        "--sample-seed": str(seed),
    }
    views = sorted(set(views))
    for index, path in enumerate(views):
        values["--hosted-view" + (f"#{index}" if index else "")] = path
    with app._app_lock:
        previous = collection_history(
            app, owner, views, command="retained_judge_inventory", input_flag="--hosted-view"
        )
        if previous is not None:
            argv = json.loads(previous["argv"])
            if argv == build_argv(
                "retained_judge_inventory", dict(values, **{"--out": argument(argv, "--out")})
            ) and _state(app, previous) in {"running", "starting", "queued", "complete"}:
                app._save_build_campaign(dict(params, retained_inventory_job=previous["job_id"]))
                return SimpleNamespace(job_id=previous["job_id"])
            if _state(app, previous) in {"running", "starting", "queued"}:
                raise ValueError(
                    _ui_text(
                        "builder_judging_inventory.this_source_inventory_is_still_being_prepared_open_its_job"
                    )
                )
        folder = (app.results_root / "rig-web" / "judging-inventory" / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        values["--out"] = str(folder / "inventory.json")
        app._save_build_campaign(params)
        job = app.start_job("retained_judge_inventory", values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_inventory_job=job.job_id))
        return job


def judging_inventory_review(app, params):
    owner = params.get("campaign_id", "")
    argv = completed_argv(
        app, params.get("retained_inventory_job"), owner, "retained_judge_inventory"
    )
    value = json.loads(Path(argument(argv, "--out")).read_text())
    if value.get("schema") != SCHEMA or value.get("status") != "inventory_only_no_calls":
        raise ValueError(
            _ui_text(
                "builder_judging_inventory.the_saved_job_has_no_completed_same_input_output_inventory"
            )
        )
    selection, coverage = value["selection"], value["coverage"]
    pending = sum(part.get("unprepared_outputs", 0) for part in value["population"].values())
    rows = "".join(
        "<tr><td>"
        + html.escape(row["cohort"])
        + "</td><td title='"
        + html.escape(row["model"], quote=True)
        + "'>"
        + html.escape(row["model"].split("@", 1)[0])
        + (
            _ui_template("</td><td data-label='[[attr:builder_judging_inventory.saved_outputs]]'>")
            + f"{row['retained_outputs']:,}"
            + "</td>"
        )
        + (
            _ui_template("<td data-label='[[attr:builder_judging_inventory.with_text]]'>")
            + f"{row.get('judgeable_text', 0):,}"
            + "</td>"
        )
        + (
            _ui_template("<td data-label='[[attr:builder_judging_inventory.missing_text]]'>")
            + f"{row.get('missing_text', 0):,}"
            + "</td></tr>"
        )
        for row in value["by_model"]
    )
    body = _ui_template(
        "<h1>[[text:builder_judging_inventory.same_input_output_coverage]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        (
            "<p>"
            + f"{selection['selected_inputs']:,}"
            + _ui_text("builder_judging_inventory.selected_input_entries")
            + f"{coverage['retained_outputs']:,}"
            + _ui_template(
                " [[text:builder_judging_inventory.retained_outputs_every_saved_local_and_hosted_answer_on_those_inp]]</p><p>"
            )
            + f"{coverage['judgeable_text']:,}"
            + _ui_text("builder_judging_inventory.outputs_have_text")
            + f"{coverage['missing_text']:,}"
            + _ui_text("builder_judging_inventory.have_missing_text")
            + f"{coverage['hosted_inputs_without_local_records']:,}"
            + _ui_text("builder_judging_inventory.selected_inputs_have_no_retained_local_record")
            + f"{pending:,}"
            + _ui_template(
                " [[text:builder_judging_inventory.source_outputs_remain_unprepared_outside_this_observed_population]]</p><p>[[text:builder_judging_inventory.this_is_coverage_not_completed_judging_text_availability_does_not]]</p><table class='judging-inventory-table'><thead><tr><th>[[text:builder_judging_inventory.population]]</th><th>[[text:builder_judging_inventory.model]]</th><th>[[text:builder_judging_inventory.saved_outputs]]</th><th>[[text:builder_judging_inventory.with_text]]</th><th>[[text:builder_judging_inventory.missing_text]]</th></tr></thead><tbody>"
            )
        )
        + rows
        + "</tbody></table>"
        + _ui_template(
            "<details><summary>[[text:builder_judging_inventory.exact_command]]</summary><pre>"
        )
        + html.escape(" ".join(argv))
        + "</pre></details>"
        + "<p><a href='/jobs/"
        + html.escape(params["retained_inventory_job"], quote=True)
        + _ui_template("'>[[text:builder_judging_inventory.open_full_inventory]]</a>")
        + " | <a href='/build?campaign_id="
        + html.escape(owner, quote=True)
        + _ui_template("'>[[text:builder_judging_inventory.return_to_build]]</a></p>")
    )
    return _page(
        _ui_text("builder_judging_inventory.same_input_output_coverage"),
        body,
        active=_ui_text("builder_judging_inventory.build"),
    )


def prepare_inventory_judging(app, params):
    owner = params.get("campaign_id", "")
    receipt = prepared_collection(app, params)
    argv = completed_argv(
        app, params.get("retained_inventory_job"), owner, "retained_judge_inventory"
    )
    inventory_path = argument(argv, "--out")
    values = {
        "--inventory": inventory_path,
        "--budget-root": str(Path(receipt["budget"]["path"]).parent),
        "--budget-plan-sha256": receipt["budget"]["sha256"],
    }
    for flag in ("--local-view", "--hosted-view"):
        paths = [argv[index + 1] for index, value in enumerate(argv[:-1]) if value == flag]
        for index, path in enumerate(paths):
            values[flag + (f"#{index}" if index else "")] = path
    with app._app_lock:
        previous = collection_history(
            app,
            owner,
            [inventory_path],
            command="retained_inventory_judge_items",
            input_flag="--inventory",
        )
        if previous is not None:
            old = json.loads(previous["argv"])
            if old == build_argv(
                "retained_inventory_judge_items", dict(values, **{"--out": argument(old, "--out")})
            ) and _state(app, previous) in {"running", "starting", "queued", "complete"}:
                app._save_build_campaign(
                    dict(params, retained_inventory_items_job=previous["job_id"])
                )
                return SimpleNamespace(job_id=previous["job_id"])
            if _state(app, previous) in {"running", "starting", "queued"}:
                raise ValueError(
                    _ui_text(
                        "builder_judging_inventory.this_all_output_funding_review_is_still_active_open_its_job"
                    )
                )
        folder = (app.results_root / "rig-web" / "judging-inventory" / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        values["--out"] = str(folder / "judging-items")
        job = app.start_job("retained_inventory_judge_items", values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_inventory_items_job=job.job_id))
        return job


def inventory_judging_review(app, params):
    owner = params.get("campaign_id", "")
    argv = completed_argv(
        app, params.get("retained_inventory_items_job"), owner, "retained_inventory_judge_items"
    )
    value = json.loads((Path(argument(argv, "--out")) / "result.json").read_text())
    if (
        value.get("status") != "prepared_no_calls"
        or value.get("scope") != "all_saved_outputs_on_selected_inputs"
    ):
        raise ValueError(
            _ui_text(
                "builder_judging_inventory.the_selected_job_has_no_completed_all_output_funding_review"
            )
        )
    categories = (
        ("selected_outputs", _ui_text("builder_judging_inventory.funded_and_not_yet_started")),
        (
            "existing_execution_owned",
            _ui_text("builder_judging_inventory.owned_by_existing_judging_executions"),
        ),
        (
            "unfunded_outputs",
            _ui_text("builder_judging_inventory.no_matching_funding_in_this_selection"),
        ),
        ("missing_outputs", _ui_text("builder_judging_inventory.missing_response_text")),
    )
    body = _ui_template(
        "<h1>[[text:builder_judging_inventory.judging_coverage_and_funding]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        (
            "<p>"
            + f"{value['input_entries']:,}"
            + _ui_text("builder_judging_inventory.input_entries")
            + f"{value['retained_outputs']:,}"
            + _ui_template(
                " [[text:builder_judging_inventory.saved_local_and_hosted_outputs_every_matching_model_answer_is_acc]]</p><dl class='judging-funding-summary'>"
            )
        )
        + "".join(
            "<div><dt>" + label + f"</dt><dd>{value[field]:,}</dd></div>"
            for field, label in categories
        )
        + _ui_template(
            "</dl><p>[[text:builder_judging_inventory.this_review_made_no_calls_and_allocated_no_money_existing_executi]]</p><p>[[text:builder_judging_inventory.the_full_output_handoff_is_saved_for_judging_preparation_it_is_no]]</p><details><summary>[[text:builder_judging_inventory.exact_command]]</summary><pre>"
        )
        + html.escape(" ".join(argv))
        + "</pre></details>"
        + "<p><a href='/jobs/"
        + html.escape(params["retained_inventory_items_job"], quote=True)
        + _ui_template("'>[[text:builder_judging_inventory.open_output_level_details]]</a>")
        + " | <a href='/build?campaign_id="
        + html.escape(owner, quote=True)
        + _ui_template("'>[[text:builder_judging_inventory.return_to_build]]</a></p>")
    )
    return _page(
        _ui_text("builder_judging_inventory.judging_coverage_and_funding"),
        body,
        active=_ui_text("builder_judging_inventory.build"),
    )


def judging_inventory_panel(params):
    body = _ui_template(
        "<section class='card' id='retained-judging-coverage'><h2>[[text:builder_judging_inventory.same_input_output_coverage]]</h2><p>[[text:builder_judging_inventory.include_all_local_models_and_every_saved_output_on_the_hosted_inp]]</p><div class='haiku-judging-controls'>"
    )
    for field, label, default in (
        ("limit", _ui_text("builder_judging_inventory.input_limit_0_all_hosted_inputs"), "0"),
        ("seed", _ui_text("builder_judging_inventory.input_selection_seed"), "0"),
    ):
        body += (
            "<label class='campaign-field'>"
            + label
            + "<input form='builder' type='number' step='1' name='retained_inventory_"
            + field
        )
        body += (
            "' value='"
            + html.escape(params.get("retained_inventory_" + field, default), quote=True)
            + "'></label>"
        )
    body += _ui_template(
        "</div><div class='campaign-actions'><button form='builder' formaction='/build/prepare-judging-inventory'>[[text:builder_judging_inventory.prepare_all_output_coverage]]</button></div>"
    )
    if params.get("retained_inventory_job"):
        body += (
            "<input form='builder' type='hidden' name='retained_inventory_job' value='"
            + html.escape(params["retained_inventory_job"], quote=True)
            + "'>"
        )
        body += _ui_template(
            "<div class='action-row'><button form='builder' formaction='/build/review-judging-inventory'>[[text:builder_judging_inventory.review_all_output_coverage]]</button>"
        )
        body += _ui_template(
            "<button form='builder' formaction='/build/prepare-inventory-judging'>[[text:builder_judging_inventory.prepare_all_output_judging_funding]]</button></div>"
        )
    if params.get("retained_inventory_items_job"):
        body += (
            "<input form='builder' type='hidden' name='retained_inventory_items_job' value='"
            + html.escape(params["retained_inventory_items_job"], quote=True)
            + "'>"
        )
        body += _ui_template(
            "<div class='action-row'><button form='builder' formaction='/build/review-inventory-judging'>[[text:builder_judging_inventory.review_all_output_judging_funding]]</button>"
        )
        body += _ui_template(
            "<button form='builder' formaction='/build/prepare-inventory-haiku'>[[text:builder_judging_inventory.prepare_all_output_haiku_judging]]</button></div>"
        )
        body += _ui_template(
            "<p>[[text:builder_judging_inventory.uses_the_haiku_model_selected_in_the_judging_controls_counts_over]]</p>"
        )
    if params.get("retained_inventory_plan_job"):
        body += (
            "<input form='builder' type='hidden' name='retained_inventory_plan_job' value='"
            + html.escape(params["retained_inventory_plan_job"], quote=True)
            + "'>"
        )
        body += _ui_template(
            "<div class='action-row'><button form='builder' formaction='/build/review-inventory-haiku'>[[text:builder_judging_inventory.review_all_output_haiku_judging]]</button></div>"
        )
    return body + "</section>"
