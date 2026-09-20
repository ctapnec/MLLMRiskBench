"""Resolve completed Build preparation jobs without asking for artifact paths."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from uuid import uuid4

from experiments.hosted_campaign_budget import load_bound_json
from experiments.hosted_retained_inputs import _descriptor
from ura.strict_json import strict_json_loads

from .builder_budget import selected_routes


def completed_argv(app, job_id, campaign_id, command):
    job = app.db.load_job(job_id)
    if (
        job is None
        or job["command"] != command
        or job["state"] != "complete"
        or job["exit_code"] != 0
        or app.db.workspace_for_job(job_id) != campaign_id
    ):
        raise ValueError(
            _ui_text(
                "builder_replays.finish_this_campaign_s_source_preparation_and_budget_forecast_fir"
            )
        )
    return json.loads(job["argv"])


def argument(argv, name):
    if argv.count(name) != 1 or argv.index(name) + 1 >= len(argv):
        raise ValueError(
            _ui_text("builder_replays.the_saved_preparation_job_lacks_an_unambiguous")
            + name
            + _ui_text("builder_replays.argument")
        )
    return argv[argv.index(name) + 1]


def prepared_sources(app, params):
    owner = params.get("campaign_id", "")
    app.db.require_workspace(owner)
    source = completed_argv(
        app, params.get("retained_sources_job"), owner, "retained_local_sources"
    )
    forecast = completed_argv(
        app, params.get("retained_budget_job"), owner, "hosted_campaign_budget"
    )
    recorded_ids = [
        source[index + 1] for index, value in enumerate(source[:-1]) if value == "--run-id"
    ]
    chosen = strict_json_loads(params.get("retained_source_runs", "[]"))
    if not isinstance(chosen, list) or sorted(chosen) != sorted(recorded_ids):
        raise ValueError(
            _ui_text("builder_replays.source_selection_changed_prepare_the_selected_inputs_again")
        )
    routes, api = selected_routes(app, params)
    caps = strict_json_loads(params.get("retained_budget_caps", "{}"))
    if not isinstance(caps, dict) or set(caps) != {route["spec"] for route in routes}:
        raise ValueError(
            _ui_text("builder_replays.target_selection_changed_prepare_a_new_forecast")
        )
    for route in routes:
        if type(caps[route["spec"]]) is not int or caps[route["spec"]] <= 0:
            raise ValueError(
                _ui_text("builder_replays.request_caps_must_be_positive_whole_numbers")
            )
        route["call_cap"] = caps[route["spec"]]
    saved_routes, _ = load_bound_json(
        Path(argument(forecast, "--route-configuration")),
        argument(forecast, "--route-configuration-sha256"),
        expect_list=True,
    )
    saved_api, _ = load_bound_json(
        Path(argument(forecast, "--api-config")), argument(forecast, "--api-config-sha256")
    )
    if (
        routes != saved_routes
        or api != saved_api
        or params.get("retained_pricing_date") != argument(forecast, "--pricing-as-of")
    ):
        raise ValueError(
            _ui_text(
                "builder_replays.model_settings_or_pricing_date_changed_prepare_a_new_forecast"
            )
        )
    return source, forecast


def prepare_replays(app, params):
    source, forecast = prepared_sources(app, params)
    owner = params["campaign_id"]
    values = {
        "--out-root": str(
            (app.results_root / "rig-web" / "prepared-replays" / uuid4().hex).resolve()
        )
    }
    for name, argv in [("local-inventory", source), ("budget", forecast)]:
        descriptor = _descriptor(Path(argument(argv, "--out")))
        values["--" + name] = descriptor["path"]
        values["--" + name + "-sha256"] = descriptor["sha256"]
    values["--api-config"] = argument(forecast, "--api-config")
    values["--api-config-sha256"] = argument(forecast, "--api-config-sha256")
    params = app._save_build_campaign(params)
    job = app.start_job("hosted_selected_replays", values, campaign_id=owner)
    app._save_build_campaign(dict(params, retained_replays_job=job.job_id))
    return job


def replay_panel(params):
    if not params.get("retained_budget_job"):
        return ""
    job = html.escape(params.get("retained_replays_job", ""), quote=True)
    return (
        _ui_template(
            "<section class='card' id='matched-replay-inputs'><h2>[[text:builder_replays.prepare_matched_replay_inputs]]</h2><p>[[text:builder_replays.use_the_completed_source_selection_and_forecast_to_prepare_every]]</p><button form='builder' formaction='/build/prepare-replays'>[[text:builder_replays.prepare_replay_inputs]]</button>"
        )
        + (
            "<p><a href='/jobs/"
            + job
            + _ui_template(
                "'>[[text:builder_replays.open_replay_preparation_and_its_artifacts]]</a></p><input type='hidden' form='builder' name='retained_replays_job' value='"
            )
            + job
            + "'>"
            if job
            else ""
        )
        + "</section>"
    )
