"""Connect matched replay preparation to the existing counted-program command."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from uuid import uuid4

from experiments import hosted_campaign_prepare as prepare
from experiments.hosted_retained_execute import COUNTED_INPUT_POLICY
from experiments.hosted_retained_inputs import _descriptor
from experiments.hosted_campaign_budget import _write_new

from .builder_replays import argument, completed_argv, prepared_sources
from .catalog import build_argv


def prepare_programs(app, params):
    from ura.guardrail_setup import resolve_scoring_settings

    params = resolve_scoring_settings(params)
    source, forecast = prepared_sources(app, params)
    owner = params["campaign_id"]
    replay_argv = completed_argv(
        app, params.get("retained_replays_job"), owner, "hosted_selected_replays"
    )
    for flag, expected in (
        ("--local-inventory", argument(source, "--out")),
        ("--budget", argument(forecast, "--out")),
        ("--api-config", argument(forecast, "--api-config")),
        ("--api-config-sha256", argument(forecast, "--api-config-sha256")),
    ):
        if argument(replay_argv, flag) != expected:
            raise ValueError(
                _ui_text(
                    "builder_programs.replay_preparation_belongs_to_different_source_or_forecast_jobs"
                )
            )
    replay = json.loads(
        (Path(argument(replay_argv, "--out-root")) / "prepared-replays.json").read_text()
    )
    if replay.get("status") != "prepared_replay_inputs_only":
        raise ValueError(_ui_text("builder_programs.finish_matched_replay_preparation_first"))
    if params.get("local"):
        raise ValueError(
            _ui_text(
                "builder_programs.this_matched_follow_on_prepares_hosted_targets_keep_local_source"
            )
        )
    if params.get("defense", "none") not in {"", "none"}:
        raise ValueError(
            _ui_text(
                "builder_programs.matched_hosted_collection_requires_defense_none_its_saved_inputs"
            )
        )
    if params.get("judges") != "rules,guardrail":
        raise ValueError(
            _ui_text(
                "builder_programs.matched_collection_retains_rules_guardrail_for_local_post_hoc_sco"
            )
        )
    if params.get("target_answer_retries", "0") not in {"", "0"}:
        raise ValueError(
            _ui_text(
                "builder_programs.matched_hosted_work_uses_zero_answer_retries_http_retries_remain"
            )
        )
    try:
        deadline = int(params.get("deadline", ""))
    except (TypeError, ValueError):
        deadline = 0
    if deadline <= 0:
        raise ValueError(
            _ui_text(
                "builder_programs.set_a_positive_whole_number_call_start_window_deadline_seconds_in"
            )
        )
    # The replay job, not the unrelated ordinary Runner arm picker, determines
    # the exact source arms. Keep this composition separate from the saved draft.
    arms = sorted({arm for row in replay["route_summary"] for arm in row["source_arms"]})
    draft = {key: value for key, value in params.items() if not key.startswith("_")}
    draft.update(
        mode="measured",
        corpora=",".join(arms),
        attackers="replay",
        limit="0",
        seeds="0",
        sample_seed="0",
        target_answer_retries="0",
    )
    # This is a standalone synthetic dry-run option, initially checked in
    # Build. The retained replay selection already fixes the actual inputs.
    draft.pop("exclude_tool_conditioned", None)
    command, values, _ = app._compose_from_builder(draft)
    if command != "run_matrix":
        raise ValueError(
            _ui_text(
                "builder_programs.matched_preparation_requires_the_ordinary_runner_composition"
            )
        )
    # The existing preparer supplies target, corpus, replay and exact call counts.
    common_values = {
        flag: value
        for flag, value in values.items()
        if flag.split("#", 1)[0] not in prepare._CONTROLLED
    }
    common = build_argv(command, common_values)[3:]
    prepare._common_argv(common)
    folder = (app.results_root / "rig-web" / "matched-programs" / uuid4().hex).resolve()
    folder.mkdir(parents=True, mode=0o700)
    execution = folder / "execution"
    execution.mkdir(mode=0o700)
    counts = folder / "count-cache"
    counts.mkdir(mode=0o700)
    sources = {
        "local_sources": _descriptor(Path(argument(source, "--out"))),
        "budget_projection": _descriptor(Path(argument(forecast, "--out"))),
        "media_index": replay["media_index"],
    }
    for name, flag in [
        ("api_config", "--api-config"),
        ("pricing", "--pricing-config"),
        ("budgets", "--budgets"),
    ]:
        sources[name] = _descriptor(Path(argument(forecast, flag)))
    request = dict(
        schema=prepare.LOCAL_SOURCES_REQUEST_SCHEMA,
        input_budget_policy=COUNTED_INPUT_POLICY,
        results_root=str(app.results_root.resolve()),
        pricing_as_of=params["retained_pricing_date"],
        execution_root=str(execution),
        runner_common_argv=common,
        sources=sources,
        routes=replay["routes"],
    )
    path = folder / "request.json"
    _write_new(path, request)
    descriptor = _descriptor(path)
    options = {
        "--request": str(path),
        "--request-sha256": descriptor["sha256"],
        "--out-root": str(folder / "prepared"),
        "--count-cache": str(counts),
    }
    if params.get("retained_network_counts") == "on":
        options["--allow-network-counts"] = "on"
    params = app._save_build_campaign(params)
    job = app.start_job("hosted_campaign_prepare", options, campaign_id=owner)
    app._save_build_campaign(dict(params, retained_programs_job=job.job_id))
    return job


def program_panel(params):
    if not any(
        params.get(key)
        for key in ("retained_sources_job", "retained_budget_job", "retained_replays_job")
    ):
        return ""
    ready = bool(params.get("retained_replays_job"))
    disabled = "" if ready else " disabled"
    prerequisite = ""
    if not ready:
        if params.get("retained_budget_job"):
            prerequisite = _ui_template(
                "<p class='notice amber'>[[text:builder_programs.waiting_for_replay_preparation_click]] <strong>[[text:builder_programs.prepare_replay_inputs]]</strong> [[text:builder_programs.in_the_panel_above_wait_for_its_job_to_complete_then_reopen_this]] <a href='#matched-replay-inputs'>[[text:builder_programs.go_to_replay_preparation]]</a>.</p>"
            )
        else:
            prerequisite = _ui_template(
                "<p class='notice amber'>[[text:builder_programs.waiting_for_the_forecast_and_replay_preparation_use]] <strong>[[text:builder_programs.prepare_forecast]]</strong>[[text:builder_programs.followed_by]] <strong>[[text:builder_programs.prepare_replay_inputs]]</strong>[[text:builder_programs.then_return_to_this_step_no_counting_or_generation_has_started]]</p>"
            )
    job = html.escape(params.get("retained_programs_job", ""), quote=True)
    checked = " checked" if params.get("retained_network_counts") == "on" else ""
    return (
        _ui_template(
            "<section class='card' id='counted-collection'><h2>[[text:builder_programs.count_inputs_and_prepare_collection]]</h2>"
        )
        + prerequisite
        + _ui_template(
            "<p>[[text:builder_programs.prepare_one_shared_spending_plan_and_executable_programs_for_the]]</p><label class='checkrow'><input type='checkbox' form='builder' name='retained_network_counts'"
        )
        + checked
        + disabled
        + _ui_template(
            "><span>[[text:builder_programs.allow_provider_token_counting_for_these_selected_inputs]]</span></label><p class='note'>[[text:builder_programs.when_required_counting_sends_the_saved_prompts_and_images_to_thei]]</p><button form='builder' formaction='/build/prepare-programs'"
        )
        + disabled
        + _ui_template(">[[text:builder_programs.prepare_counted_collection]]</button>")
        + (
            "<p><a href='/jobs/"
            + job
            + _ui_template(
                "'>[[text:builder_programs.open_collection_preparation_and_its_artifacts]]</a></p><input type='hidden' form='builder' name='retained_programs_job' value='"
            )
            + job
            + "'>"
            if job
            else ""
        )
        + "</section>"
    )
