"""Review saved-output Haiku comparisons in Build under their existing funding."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

from collections import Counter
from decimal import Decimal, InvalidOperation
import html
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from experiments.hosted_retained_inputs import _descriptor
from experiments.retained_response_judge_execute import _write_new
from experiments.retained_response_judge_pair import (
    MAX_PAIR_LIMIT,
    MAX_COST_MICROUSD,
    validate_pair_plan,
)

from .builder_collection import prepared_collection, collection_history
from .builder_native_judging import _state
from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


def _choices(app):
    registry = app._load_registry("api-targets.json", "rig/api-targets.example.json")
    return sorted(key for key in registry if key.startswith("anthropic:claude-haiku-"))


def prepare_haiku_judging(app, params):
    owner = params.get("campaign_id", "")
    receipt = prepared_collection(app, params)
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
                "builder_haiku_judging.select_this_campaign_s_completed_saved_output_preparation_first"
            )
        )
    hosted = Path(argument(json.loads(job["argv"]), "--out")) / "result.json"
    native = json.loads(hosted.read_text())
    if not native.get("units") or native.get("programs") != receipt["programs"]:
        # Receipt descriptors may also carry prepared request counts.
        actual = [(row["path"], row["sha256"]) for row in native.get("programs", [])]
        expected = [(row["path"], row["sha256"]) for row in receipt["programs"]]
        if not native.get("units") or actual != expected:
            raise ValueError(
                _ui_text("builder_haiku_judging.saved_outputs_belong_to_a_different_collection")
            )
    source = completed_argv(
        app, params.get("retained_sources_job"), owner, "retained_local_sources"
    )
    forecast = completed_argv(
        app, params.get("retained_budget_job"), owner, "hosted_campaign_budget"
    )
    model = params.get("retained_haiku_model", "")
    if model not in _choices(app):
        raise ValueError(_ui_text("builder_haiku_judging.choose_a_configured_haiku_judge_model"))
    try:
        limit = int(params.get("retained_haiku_limit", "100"))
        seed = int(params.get("retained_haiku_seed", "0"))
        cost = Decimal(params.get("retained_haiku_cost", "7")) * 1_000_000
        if not cost.is_finite() or cost != cost.to_integral_value():
            raise ValueError(_ui_text("builder_haiku_judging.invalid_cost"))
        cap = int(cost)
    except (ValueError, InvalidOperation):
        raise ValueError(
            _ui_text(
                "builder_haiku_judging.use_whole_number_comparison_seed_values_and_a_usd_ceiling_with_at"
            )
        ) from None
    if not 1 <= limit <= MAX_PAIR_LIMIT or not 1 <= cap <= MAX_COST_MICROUSD:
        raise ValueError(
            _ui_text(
                "builder_haiku_judging.comparison_count_or_judging_ceiling_is_outside_the_supported_rang"
            )
        )
    conditions = {
        (
            argument(unit["runner_argv"], "--source-conformance"),
            argument(unit["runner_argv"], "--source-conformance-sha256"),
        )
        for unit in native["units"]
    }
    if len(conditions) != 1:
        raise ValueError(
            _ui_text(
                "builder_haiku_judging.these_outputs_use_different_source_assessments_select_their_prepa"
            )
        )
    condition = next(iter(conditions))
    snapshot, _, _, configs = app._selected_api_config_snapshot(
        dict(mode="measured", api="", judges="llm", judge_model=model)
    )
    if model not in configs or len(snapshot["routes"]) != 1:
        raise ValueError(
            _ui_text("builder_haiku_judging.the_selected_judge_needs_an_explicit_api_configuration")
        )
    config = dict(configs[model], max_tokens=512)
    # Native output selection, not a freshly edited target draft, owns this work.
    values = {
        "--local-runner-view": argument(source, "--out"),
        "--hosted-runner-view": str(hosted),
        "--source-receipt": condition[0],
        "--source-receipt-sha256": condition[1],
        "--judge-model": model,
        "--pricing-config": argument(forecast, "--pricing-config"),
        "--pricing-config-sha256": argument(forecast, "--pricing-config-sha256"),
        "--pricing-as-of": argument(forecast, "--pricing-as-of"),
        "--pair-limit": str(limit),
        "--sample-seed": str(seed),
        "--max-cost-microusd": str(cap),
        "--ack-hosted-judge-data-transfer": "on",
        "--shared-budget-root": str(Path(receipt["budget"]["path"]).parent),
        "--shared-budget-sha256": receipt["budget"]["sha256"],
    }
    for index, row in enumerate(receipt["programs"]):
        suffix = f"#{index}" if index else ""
        values["--program" + suffix] = row["path"]
        values["--program-sha256" + suffix] = row["sha256"]
    with app._app_lock:
        previous = collection_history(
            app,
            owner,
            [str(hosted)],
            command="retained_response_judge_pair",
            input_flag="--hosted-runner-view",
        )
        if previous is not None:
            saved = json.loads(previous["argv"])
            api_path = Path(argument(saved, "--api-config"))
            equivalent = saved == build_argv(
                "retained_response_judge_pair",
                dict(
                    values,
                    **{
                        "--api-config": str(api_path),
                        "--api-config-sha256": argument(saved, "--api-config-sha256"),
                        "--out": argument(saved, "--out"),
                    },
                ),
            )
            equivalent = equivalent and json.loads(api_path.read_text()) == {model: config}
            if equivalent and _state(app, previous) in {
                "running",
                "queued",
                "starting",
                "complete",
            }:
                app._save_build_campaign(dict(params, retained_haiku_job=previous["job_id"]))
                return SimpleNamespace(job_id=previous["job_id"])
            if _state(app, previous) in {"running", "queued", "starting"}:
                raise ValueError(
                    _ui_text(
                        "builder_haiku_judging.this_source_selection_already_has_an_active_haiku_preparation"
                    )
                )
            prior_plan = argument(saved, "--out")
            if collection_history(
                app,
                owner,
                [prior_plan],
                command="retained_response_judge_pair_execute",
                input_flag="--plan",
            ):
                raise ValueError(
                    _ui_text(
                        "builder_haiku_judging.resume_the_saved_judging_selection_before_preparing_different_com"
                    )
                )
        folder = (app.results_root / "rig-web" / "haiku-judging" / uuid4().hex).resolve()
        folder.mkdir(parents=True, mode=0o700)
        api_path = folder / "api-config.json"
        _write_new(api_path, {model: config})
        values.update(
            {
                "--api-config": str(api_path),
                "--api-config-sha256": _descriptor(api_path)["sha256"],
                "--out": str(folder / "plan.json"),
            }
        )
        app._save_build_campaign(params)
        launched = app.start_job("retained_response_judge_pair", values, campaign_id=owner)
        app._save_build_campaign(dict(params, retained_haiku_job=launched.job_id))
        return launched


def haiku_judging_review(app, params):
    owner = params.get("campaign_id", "")
    app.db.require_workspace(owner)
    argv = completed_argv(
        app, params.get("retained_haiku_job"), owner, "retained_response_judge_pair"
    )
    plan_path = Path(argument(argv, "--out"))
    plan = validate_pair_plan(json.loads(plan_path.read_text()))
    requests = _descriptor(plan_path.with_suffix(".shared-requests.json"))
    values = {
        flag: argument(argv, flag)
        for flag in (
            "--local-runner-view",
            "--hosted-runner-view",
            "--source-receipt",
            "--api-config",
            "--pricing-config",
            "--shared-budget-root",
            "--shared-budget-sha256",
        )
    }
    values.update(
        {
            "--plan": str(plan_path),
            "--shared-requests": requests["path"],
            "--shared-requests-sha256": requests["sha256"],
            "--out": str(plan_path.parent / "judgments"),
            "--ack-paid-execution": "on",
            "--retain-invalid-verdicts": "on",
        }
    )
    matching = params.get("retained_source_campaign", "")
    app.db.require_workspace(matching)
    if matching != owner:
        values["--matching-workspace-id"] = matching
    history = collection_history(
        app,
        owner,
        [str(plan_path)],
        command="retained_response_judge_pair_execute",
        input_flag="--plan",
    )
    if history is not None:
        old = json.loads(history["argv"])
        values["--out"] = argument(old, "--out")
        if ("--matching-workspace-id" in old) != ("--matching-workspace-id" in values) or (
            "--matching-workspace-id" in old
            and argument(old, "--matching-workspace-id") != matching
        ):
            raise ValueError(
                _ui_text(
                    "builder_haiku_judging.keep_the_original_matching_campaign_when_resuming_judgments"
                )
            )
    ticket = app._new_launch_ticket(
        dict(
            campaign_id=owner,
            values=json.dumps(values),
            previous_job=history["job_id"] if history is not None else "",
        ),
        purpose="matched-haiku-judge",
    )
    counts = Counter((row["cohort"], row["exact_model"]) for row in plan["selected"])
    condition = plan["judge_condition"]
    rows = "".join(
        "<tr><td>"
        + html.escape(cohort)
        + "</td><td>"
        + html.escape(model)
        + f"</td><td>{count:,}</td></tr>"
        for (cohort, model), count in sorted(counts.items())
    )
    body = _ui_template(
        "<h1>[[text:builder_haiku_judging.review_haiku_judging]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        (
            "<p>"
            + f"{len(plan['pairs']):,}"
            + _ui_text("builder_haiku_judging.matched_input_comparisons")
            + f"{len(plan['selected']):,}"
            + _ui_template(
                " [[text:builder_haiku_judging.distinct_saved_answers_each_answer_has_its_own_verdict_a_shared_l]]</p><p>Judge: "
            )
        )
        + html.escape(condition["model"])
        + (
            _ui_text("builder_haiku_judging.512_output_tokens_per_verdict_usd")
            + f"{condition['max_cost_microusd'] / 1000000.0:,.6f}"
            + _ui_template(
                " [[text:builder_haiku_judging.selection_ceiling_under_the_existing_campaign_allocation_this_cei]]</p><p>[[text:builder_haiku_judging.haiku_receives_the_rendered_prompt_text_and_each_target_answer_im]]</p><div class='scroll'><table><tr><th>[[text:builder_haiku_judging.population]]</th><th>[[text:builder_haiku_judging.model]]</th><th>[[text:builder_haiku_judging.answers]]</th></tr>"
            )
        )
        + rows
        + _ui_template(
            "</table></div><details><summary>[[text:builder_haiku_judging.exact_command]]</summary><pre>"
        )
        + html.escape(" ".join(build_argv("retained_response_judge_pair_execute", values)))
        + "</pre></details><form class='action-row' method='post' action='/build/judge-retained-haiku'>"
        "<input type='hidden' name='launch_ticket' value='"
        + html.escape(ticket, quote=True)
        + _ui_template(
            '\'><button type="submit">[[text:builder_haiku_judging.start_or_resume_haiku_judging]]</button></form>'
        )
        + "<p><a href='/build?campaign_id="
        + owner
        + _ui_template("'>[[text:builder_haiku_judging.return_to_build]]</a></p>")
    )
    return _page(
        _ui_text("builder_haiku_judging.review_haiku_judging"),
        body,
        active=_ui_text("builder_haiku_judging.build"),
    )


def judge_retained_haiku(app, form):
    if set(form) != {"launch_ticket"}:
        raise ValueError(
            _ui_text("builder_haiku_judging.review_the_prepared_haiku_selection_first")
        )
    params = app._launch_ticket_params(form["launch_ticket"], purpose="matched-haiku-judge")
    if params is None:
        raise ValueError(_ui_text("builder_haiku_judging.haiku_review_expired_or_was_already_used"))
    values, owner = json.loads(params["values"]), params["campaign_id"]
    with app._app_lock:
        history = collection_history(
            app,
            owner,
            [values["--plan"]],
            command="retained_response_judge_pair_execute",
            input_flag="--plan",
        )
        if (history["job_id"] if history is not None else "") != params["previous_job"]:
            raise ValueError(
                _ui_text(
                    "builder_haiku_judging.this_selection_has_a_newer_launch_open_its_saved_job"
                )
            )
        if history is not None and _state(app, history) in {"running", "queued", "starting"}:
            raise ValueError(
                _ui_text("builder_haiku_judging.this_haiku_selection_is_already_active")
            )
        return app.start_job("retained_response_judge_pair_execute", values, campaign_id=owner)


def haiku_judging_panel(app, params):
    if not params.get("retained_programs_job"):
        return ""
    choices = _choices(app)
    chosen = params.get("retained_haiku_model") or next(iter(choices), "")
    body = (
        _ui_template(
            "<section class='card' id='retained-haiku-judging'><h2>[[text:builder_haiku_judging.haiku_comparison_of_saved_outputs]]</h2><p>[[text:builder_haiku_judging.judge_saved_hosted_answers_and_all_matching_local_answers_the_con]]</p><div class='haiku-judging-controls' id='retained-judging-coverage'><label class='campaign-field'>[[text:builder_haiku_judging.haiku_judge]]<select form='builder' name='retained_haiku_model'>"
        )
        + "".join(
            "<option value='"
            + html.escape(model, quote=True)
            + "'"
            + (" selected" if model == chosen else "")
            + ">"
            + html.escape(model)
            + "</option>"
            for model in choices
        )
        + "</select></label>"
    )
    for field, label, default in (
        ("limit", "Input limit (0 = all selected hosted inputs)", "0"),
        ("seed", _ui_text("builder_haiku_judging.input_selection_seed"), "0"),
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
        "</div><p>[[text:builder_haiku_judging.uses_this_campaign_s_existing_judging_allocation_the_review_shows]]</p><div class='campaign-actions'><button form='builder' formaction='/build/prepare-operation/haiku-judging'>[[text:builder_haiku_judging.review_all_output_haiku_judging]]</button></div><details class='card'><summary>[[text:builder_haiku_judging.optional_sampled_paired_comparison]]</summary><p>[[text:builder_haiku_judging.this_alternative_selects_pairs_of_local_and_hosted_answers_its_li]]</p><div class='haiku-judging-controls'>"
    )
    for name, label, default, maximum, step in (
        (
            "limit",
            _ui_text("builder_haiku_judging.maximum_matched_comparisons"),
            "100",
            MAX_PAIR_LIMIT,
            "1",
        ),
        ("seed", _ui_text("builder_haiku_judging.selection_seed"), "0", None, "1"),
        (
            "cost",
            _ui_text("builder_haiku_judging.judging_ceiling_usd"),
            "7",
            MAX_COST_MICROUSD / 1e6,
            "0.000001",
        ),
    ):
        body += (
            "<label class='campaign-field'>"
            + label
            + "<input type='number' form='builder' name='retained_haiku_"
            + name
            + "' step='"
            + step
            + "'"
            + (" max='" + str(maximum) + "'" if maximum is not None else "")
            + " value='"
            + html.escape(params.get("retained_haiku_" + name, default), quote=True)
            + "'></label>"
        )
    body += _ui_template(
        "</div><div class='campaign-actions'><button form='builder' formaction='/build/prepare-operation/paired-haiku'>[[text:builder_haiku_judging.review_sampled_haiku_comparison]]</button></div>"
    )
    job = params.get("retained_haiku_job", "")
    if job:
        body += (
            "<input type='hidden' form='builder' name='retained_haiku_job' value='"
            + html.escape(job, quote=True)
            + "'>"
        )
        body += (
            "<p><a href='/jobs/"
            + html.escape(job, quote=True)
            + _ui_template("'>[[text:builder_haiku_judging.open_selection_and_exclusions]]</a></p>")
        )
        body += _ui_template(
            "<button form='builder' formaction='/build/review-haiku-judging'>[[text:builder_haiku_judging.review_haiku_judging]]</button>"
        )
    return body + "</details></section>"
