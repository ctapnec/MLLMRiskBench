"""One campaign action over the existing preparation, collection and assessment jobs.

The operation is durable; it does not introduce another experiment executor.
No real calls occur before the operator starts the reviewed campaign.
"""

from __future__ import annotations

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import html
import json

from .ui import _page


ACTIVE = {"running", "queued", "starting", "retry_wait", "retry_waiting"}


def microusd(value):
    try:
        amount = Decimal(value) * 1_000_000
        if not amount.is_finite() or amount <= 0 or amount != amount.to_integral_value():
            raise ValueError()
        return int(amount)
    except (InvalidOperation, ValueError):
        raise ValueError(
            _ui_text("campaign_flow.enter_a_positive_usd_ceiling_with_at_most_six_decimal_places")
        )


def settings(app, params):
    """Validate operator choices before starting even a preparation job."""
    params = dict(params)
    if (
        params.get("campaign_local") == "on"
        and not params.get("judge_model")
        and params.get("judges", "") in {"", "rules,llm"}
    ):
        params["judges"] = "rules,guardrail"
    if params.get("campaign_inputs", "fresh") not in {"fresh", "saved"}:
        raise ValueError(_ui_text("campaign_flow.choose_installed_corpora_or_saved_local_inputs"))
    if params.get("mode") != "measured":
        raise ValueError(
            _ui_text(
                "campaign_flow.choose_measured_execution_for_a_campaign_diagnostic_runs_remain_a"
            )
        )
    if params.get("api") or (
        "llm" in params.get("judges", "").split(",")
        and params.get("judge_model")
        and not params["judge_model"].startswith(("vllm:", "ollama:"))
    ):
        microusd(params.get("campaign_collection_cost", ""))
    if params.get("campaign_haiku") == "on":
        from .builder_haiku_judging import _choices

        if params.get("campaign_judge_model") not in _choices(app):
            raise ValueError(_ui_text("campaign_flow.choose_a_configured_haiku_evaluator"))
        try:
            cost = Decimal(params.get("campaign_judge_cost", "")) * 1_000_000
            if not cost.is_finite() or cost <= 0 or cost != cost.to_integral_value():
                raise ValueError()
        except (InvalidOperation, ValueError):
            raise ValueError(
                _ui_text(
                    "campaign_flow.enter_a_positive_haiku_assessment_ceiling_with_at_most_six_decima"
                )
            )
    if params.get("campaign_inputs", "fresh") == "saved":
        from .builder_sources import selected_runs, source_runs
        from .builder_budget import selected_routes

        selected_runs(params, source_runs(app.db, params.get("retained_source_campaign", "")))
        routes, _ = selected_routes(app, params)
        caps = json.loads(params.get("retained_budget_caps") or "{}")
        if not isinstance(caps, dict):
            raise ValueError(
                _ui_text("campaign_flow.request_caps_must_describe_the_selected_models")
            )
        params["retained_budget_caps"] = json.dumps(
            {route["spec"]: caps.get(route["spec"], 10) for route in routes}
        )
        if params.get("local"):
            raise ValueError(
                _ui_text(
                    "campaign_flow.saved_input_comparison_uses_hosted_targets_the_source_models_stay"
                )
            )
        params.update(
            retained_network_counts="on",
            retained_pricing_date=datetime.now(timezone.utc).date().isoformat(),
            judges="rules,guardrail",
            target_answer_retries="0",
        )
        params["deadline"] = params.get("deadline") or "3600"
    return params


def panel(app, params):
    from .builder_haiku_judging import _choices

    escape = lambda value: html.escape(str(value), quote=True)
    saved = params.get("campaign_inputs") == "saved"
    choices = _choices(app)
    judge = params.get("campaign_judge_model", choices[0] if choices else "")
    return (
        _ui_template(
            '<section class="card" id="campaign-workflow" data-campaign-only><h2>[[text:campaign_flow.campaign_workflow]]</h2><input form="builder" type="hidden" name="campaign_flow" value="on"><p>[[text:campaign_flow.choose_inputs_and_evaluation_here_review_campaign_prepares_the_wo]]</p><label class="campaign-field">[[text:campaign_flow.input_selection]]<select form="builder" name="campaign_inputs"><option value="fresh"'
        )
        + ("" if saved else " selected")
        + _ui_template(
            '>[[text:campaign_flow.installed_corpora_and_attack_frameworks]]</option><option value="saved"'
        )
        + (" selected" if saved else "")
        + _ui_template(
            '>[[text:campaign_flow.reuse_saved_local_inputs_for_comparison]]</option></select></label><p>[[text:campaign_flow.for_installed_inputs_choose_arms_and_attacks_in_pipeline_for_save]]</p><label class="campaign-field">[[text:campaign_flow.api_collection_ceiling_usd_leave_empty_for_fully_local_collection]]<input form="builder" name="campaign_collection_cost" type="number" min="0.000001" step="0.000001" value="'
        )
        + escape(params.get("campaign_collection_cost", ""))
        + _ui_template(
            '"></label><p>[[text:campaign_flow.covers_target_calls_necessary_diagnostics_and_inline_hosted_scori]]</p><fieldset class="campaign-assessment-options"><legend>[[text:campaign_flow.assessment_after_collection]]</legend><label class="checkrow"><input form="builder" name="campaign_local" type="checkbox"'
        )
        + (" checked" if params.get("campaign_local", "on") == "on" else "")
        + _ui_template(
            '><span>[[text:campaign_flow.fill_missing_original_local_evaluator_verdicts]]</span></label><label class="checkrow"><input form="builder" name="campaign_haiku" type="checkbox"'
        )
        + (" checked" if params.get("campaign_haiku") == "on" else "")
        + _ui_template(
            '><span>[[text:campaign_flow.assess_saved_answers_independently_with_haiku]]</span></label><div class="campaign-grid" data-campaign-haiku><label class="campaign-field">[[text:campaign_flow.haiku_evaluator]]<select form="builder" name="campaign_judge_model">'
        )
        + "".join(
            "<option" + (" selected" if value == judge else "") + ">" + escape(value) + "</option>"
            for value in choices
        )
        + _ui_template(
            '</select></label><label class="campaign-field">[[text:campaign_flow.haiku_assessment_ceiling_usd]]<input form="builder" name="campaign_judge_cost" type="number" min="0.000001" step="0.000001" value="'
        )
        + escape(params.get("campaign_judge_cost", ""))
        + _ui_template(
            '"></label></div></fieldset><p>[[text:campaign_flow.assessment_uses_saved_measured_answers_in_this_campaign_including]]</p><script>document.addEventListener("DOMContentLoaded",()=>{const mode=document.querySelector("[name=campaign_inputs]");const haiku=document.querySelector("[name=campaign_haiku]");const update=()=>{const campaign=document.querySelector("[name=work_kind]:checked")?.value==="campaign";document.querySelectorAll("[data-campaign-only]").forEach(e=>{e.hidden=!campaign;e.querySelectorAll("input,select").forEach(i=>i.disabled=!campaign);});document.querySelectorAll("[data-review-campaign]").forEach(e=>e.textContent=campaign?[[js:campaign_flow.review_campaign]]:[[js:campaign_flow.compose_review]]);document.querySelectorAll("[data-saved-inputs]").forEach(e=>{e.hidden=!campaign||mode.value!=="saved";e.querySelectorAll("input,select,button").forEach(i=>i.disabled=e.hidden);});document.querySelectorAll("[data-campaign-haiku]").forEach(e=>{e.hidden=!haiku.checked;e.querySelectorAll("input,select").forEach(i=>i.disabled=e.hidden||!campaign);});};document.querySelectorAll("[name=work_kind]").forEach(e=>e.addEventListener("change",update));mode.addEventListener("change",update);haiku.addEventListener("change",update);update();});</script></section>'
        )
    )


def _child(app, operation):
    return app._operations[operation["preparation"]]


def advance(app, operation):
    if not operation.get("preparation"):
        params = dict(operation["params"])
        if "guardrail" in params.get("judges", "").split(","):
            from ura.guardrail_setup import resolve_scoring_settings

            params = resolve_scoring_settings(params)
        from .campaign_assessment import prepare_values

        for kind in ("local", "haiku"):
            if params.get("campaign_" + kind) == "on" and not operation.get(kind + "_values"):
                root = (
                    app.results_root / "rig-web" / "campaign-assessment" / operation["id"] / kind
                ).resolve()
                operation[kind + "_values"] = prepare_values(
                    app,
                    params["campaign_id"],
                    kind=kind,
                    judge=params.get("campaign_judge_model", ""),
                    cost=params.get("campaign_judge_cost", ""),
                    root=root,
                )
                operation[kind + "_root"] = str(root)
                app._save_operation(operation)
        params["campaign_operation"] = operation["id"]
        if params.get("campaign_inputs", "fresh") == "saved":
            kind, snapshot = "matched", None
        else:
            errors = app._validate_builder(params, preparation=True)
            if errors:
                raise ValueError("; ".join(errors.values()))
            params, snapshot, _ = app._capture_execution_config_snapshot(params)
            params = app._bind_execution_config_bundle_identity(params)
            freeze_spending(app, operation, params)
            kind = "direct"
        operation["preparation"] = app._start_operation(kind, params, snapshot=snapshot)
        child = _child(app, operation)
        child["campaign_parent"] = operation["id"]
        app._save_operation(child)
        app._save_operation(operation)
        return
    child = _child(app, operation)
    if operation["step"] == 0:
        if child["status"] in {"failed", "stopped"}:
            raise ValueError(child.get("error") or _ui_text("campaign_flow.preparation_stopped"))
        if child["status"] != "ready":
            return
        if child["kind"] == "matched":
            from .builder_collection import collection_launch_values

            _, rows, _, _ = collection_launch_values(app, child["params"])
            if sum(row[3] for row in rows) * 4 > microusd(
                operation["params"]["campaign_collection_cost"]
            ):
                raise ValueError(
                    _ui_text(
                        "campaign_flow.the_selected_api_requests_including_three_possible_http_retries_e"
                    )
                )
        operation.update(status="ready")
        app._save_operation(operation)
        return
    if not operation.get("execution_authorized"):
        raise ValueError(_ui_text("campaign_flow.review_and_start_the_campaign_before_execution"))
    if operation["step"] == 1:
        if child["kind"] == "direct":
            if child.get("awaiting_connections"):
                child.update(
                    execution_authorized=True, awaiting_connections=False, status="preparing"
                )
                app._save_operation(child)
                app._ensure_operation_worker(child["id"])
                return
            if child["status"] in {"failed", "stopped"}:
                raise ValueError(child.get("error") or _ui_text("campaign_flow.collection_stopped"))
            if child["status"] != "ready":
                return
            if not child.get("execution_job"):
                from .connection_workflow import launch

                launch(app, child)
            operation["collection_job"] = child["execution_job"]
        elif not operation.get("collection_job"):
            from .builder_collection import collection_launch_values

            values, _, _, _ = collection_launch_values(app, child["params"])
            operation["collection_values"] = values
            launch_job(app, operation, "collection_job", "hosted_campaign_execute", values)
        job = app.jobs.get(operation["collection_job"])
        require_complete(job, _ui_text("campaign_flow.collection"))
        if job.state() in ACTIVE:
            return
        operation["step"] = 2
        app._save_operation(operation)
        return
    from pathlib import Path

    for step, kind in ((2, "local"), (3, "haiku")):
        if operation["step"] != step:
            continue
        params = operation["params"]
        if params.get("campaign_" + kind) != "on":
            operation["step"] += 1
            app._save_operation(operation)
            return
        key = kind + "_preparation"
        if not operation.get(key):
            launch_job(app, operation, key, "campaign_assess", operation[kind + "_values"])
            return
        job = app.jobs.get(operation[key])
        require_complete(job, _ui_text("campaign_flow.assessment_preparation"))
        if job.state() in ACTIVE:
            return
        root = Path(operation[kind + "_root"])
        result = json.loads((root / "result.json").read_text())
        operation[kind + "_summary"] = result
        if result["status"] == "over_budget":
            raise ValueError(
                _ui_text(
                    "campaign_flow.haiku_assessment_exceeds_the_reviewed_ceiling_collection_is_retai"
                )
            )
        if result["selected_outputs"]:
            execution = kind + "_execution"
            if not operation.get(execution):
                launch_job(
                    app,
                    operation,
                    execution,
                    "campaign_assess",
                    {"--execute": "on", "--database": str(app.db.path), "--out": str(root)},
                )
                return
            job = app.jobs.get(operation[execution])
            require_complete(job, _ui_label(kind) + _ui_text("campaign_flow.assessment"))
            if job.state() in ACTIVE:
                return
        operation["step"] += 1
        app._save_operation(operation)
        return
    operation["status"] = "complete"
    app._save_operation(operation)


def require_complete(job, label):
    if job is None:
        raise ValueError(
            label + _ui_text("campaign_flow.is_awaiting_job_recovery_no_duplicate_will_be_launched")
        )
    if job.state() not in ACTIVE and (job.state() != "complete" or job.exit_code() != 0):
        raise ValueError(
            label
            + _ui_text("campaign_flow.needs_attention_saved_work_is_retained")
            + (job.failure or "")
        )


def launch_job(app, operation, key, command, values):
    job_id = app._job_id_factory()
    operation[key] = job_id
    app._save_operation(operation)
    return app.start_job(
        command, values, campaign_id=operation["params"]["campaign_id"], reserved_job_id=job_id
    )


def review(app, operation):
    from .operations import completed_equivalent

    completed = completed_equivalent(app._operations, operation)
    if completed:
        return progress(app, completed)
    child = _child(app, operation)
    params = operation["params"]
    body = _ui_template("<h1>[[text:campaign_flow.review_campaign]]</h1>") + app._campaign_banner(
        params["campaign_id"]
    )
    body += _ui_template(
        '<section class="card"><h2>[[text:campaign_flow.collection_and_evaluation]]</h2><p>[[text:campaign_flow.one_start_runs_the_required_checks]] '
    )
    body += _ui_template(
        "[[text:campaign_flow.collects_answers_and_completes_the_selected_assessments_no_calls]]</p>"
    )
    body += (
        _ui_template("<p>[[text:campaign_flow.models]] ")
        + html.escape(", ".join(filter(None, (params.get("api"), params.get("local")))))
        + "</p>"
    )
    eligible = True
    if child["kind"] == "matched":
        from .builder_collection import collection_launch_values

        _, rows, _, _ = collection_launch_values(app, child["params"])
        body += _ui_template(
            '<div class="scroll"><table><tr><th>[[text:campaign_flow.model]]</th><th>[[text:campaign_flow.total_requests]]</th><th>[[text:campaign_flow.measured]]</th><th>[[text:campaign_flow.diagnostic]]</th><th>[[text:campaign_flow.unclassified]]</th><th>[[text:campaign_flow.output_allowance]]</th><th>[[text:campaign_flow.first_attempt_bound]]</th></tr>'
        )
        body += (
            "".join(
                "<tr><td>"
                + html.escape(model)
                + f"</td><td>{count}</td><td>{parts['measured']}</td><td>{parts['diagnostic']}</td><td>{parts['unclassified']}</td><td>{tokens}</td><td>${cost / 1e6:.4f}</td></tr>"
                for model, count, tokens, cost, parts in rows
            )
            + "</table></div>"
        )
        body += _ui_template(
            "<p>[[text:campaign_flow.whole_source_clusters_are_retained_diagnostic_inputs_remain_separ]] "
        )
        body += _ui_text(
            "campaign_flow.unclassified_requests_have_missing_or_conflicting_saved_purposes"
        )
        body += _ui_template(
            "[[text:campaign_flow.the_prepared_spending_plan_also_covers_eligible_http_retries]]</p>"
        )
    else:
        card, eligible = app._ceilings_card(child["params"])
        body += card
        for item in child.get("connection_operations", []):
            probe = app._operations[item["preparation"]]
            card, valid = app._ceilings_card(probe["params"])
            body += (
                _ui_template("<h3>[[text:campaign_flow.additional_connection_check]]</h3>") + card
            )
            eligible &= valid
    body += (
        _ui_template("<ul><li>[[text:campaign_flow.local_saved_answer_assessment]] ")
        + (
            "selected"
            if params.get("campaign_local") == "on"
            else _ui_text("campaign_flow.not_selected")
        )
        + "</li>"
    )
    body += (
        _ui_template("<li>[[text:campaign_flow.independent_haiku_assessment]] ")
        + (
            html.escape(params.get("campaign_judge_model", ""))
            + _ui_text("campaign_flow.maximum")
            + html.escape(params.get("campaign_judge_cost", ""))
            if params.get("campaign_haiku") == "on"
            else _ui_text("campaign_flow.not_selected")
        )
        + "</li></ul>"
    )
    body += _ui_template(
        "<p>[[text:campaign_flow.assessment_includes_pending_measured_answers_in_this_campaign_exi]] "
    )
    body += _ui_text(
        "campaign_flow.missing_and_ineligible_answers_remain_reported_haiku_receives_eac"
    )
    body += _ui_template(
        "[[text:campaign_flow.if_the_assessment_cannot_fit_the_ceiling_collection_stays_saved_a]]</p></section>"
    )
    if params.get("campaign_collection_cost"):
        body += (
            _ui_template(
                '<section class="card"><h2>[[text:campaign_flow.api_spending_limits]]</h2><p>[[text:campaign_flow.collection_allowance]]'
            )
            + html.escape(params["campaign_collection_cost"])
            + ".</p>"
        )
        body += _ui_template(
            "<p>[[text:campaign_flow.every_runner_api_attempt_including_http_retries_and_required_diag]] "
        )
        body += _ui_text(
            "campaign_flow.request_counts_and_configured_prices_guide_admission_these_are_no"
        )
        body += _ui_template(
            "[[text:campaign_flow.independent_haiku_judging_has_the_separate_ceiling_shown_above_co]]</p></section>"
        )
    ticket = app._new_launch_ticket(dict(operation=operation["id"]), purpose="campaign-start")
    body += (
        '<form class="action-row" method="post" action="/operations/start-campaign"><input type="hidden" name="launch_ticket" value="'
        + ticket
        + '"><button'
        + ("" if eligible else " disabled")
        + _ui_template(">[[text:campaign_flow.start_campaign]]</button></form>")
    )
    body += (
        '<p><a href="/build?campaign_id='
        + params["campaign_id"]
        + _ui_template('">[[text:campaign_flow.change_campaign_settings]]</a></p>')
    )
    return _page(
        _ui_text("campaign_flow.review_campaign"), body, active=_ui_text("campaign_flow.build")
    )


def stop(app, operation):
    operation["status"] = "stopped"
    app._save_operation(operation)
    child = app._operations.get(operation.get("preparation"))
    if child and child["status"] == "preparing":
        app._stop_operation(child["id"])
    if child and child.get("execution_job"):
        # A child may have launched just before the parent's next poll.
        # Stopping in this handoff gap must still stop the measured process.
        operation["collection_job"] = child["execution_job"]
        app._save_operation(operation)
    for key in (
        "collection_job",
        "local_preparation",
        "local_execution",
        "haiku_preparation",
        "haiku_execution",
    ):
        job = app.jobs.get(operation.get(key))
        if job and job.state() in ACTIVE:
            app.stop_job(job.job_id)


def retry(app, operation):
    from .connection_workflow import check_recovery, resume_probes

    child = app._operations.get(operation.get("preparation"))
    stages = (
        "collection_job",
        "local_preparation",
        "local_execution",
        "haiku_preparation",
        "haiku_execution",
    )
    check_recovery(app, child or {}, (operation.get(key) for key in stages))
    if child and child["kind"] == "direct":
        resume_probes(app, child)
    if child and child["status"] in {"failed", "stopped"}:
        app._retry_operation(child["id"])
    # Successful stages are immutable. Failed execution needs its checkpoint
    # continuation, never a new campaign or a repeated completed collection.
    for key in stages:
        job_id = operation.get(key)
        if not job_id:
            continue
        job = app.jobs.get(job_id)
        if job and job.state() == "complete" and job.exit_code() == 0:
            continue
        if key == "collection_job" and child["kind"] == "direct" and job is not None:
            child["resume_job"] = job_id
            child.pop("execution_job", None)
            app._save_operation(child)
        # A lost no-call preparation can restart at the same deterministic
        # output. Actual assessment execution always resumes that output.
        operation.pop(key, None)
    operation.update(status="preparing", error="")
    app._save_operation(operation)
    app._ensure_operation_worker(operation["id"])


def progress(app, operation):
    if operation["status"] == "ready":
        return review(app, operation)
    owner = operation["params"]["campaign_id"]
    labels = (
        _ui_text("campaign_flow.preparing_campaign"),
        _ui_text("campaign_flow.collecting_answers"),
        _ui_text("campaign_flow.local_assessment"),
        _ui_text("campaign_flow.haiku_assessment"),
        _ui_text("campaign_flow.results_ready"),
    )
    body = _ui_template("<h1>[[text:campaign_flow.campaign_progress]]</h1>") + app._campaign_banner(
        owner
    )
    body += '<section class="card"><h2>' + labels[min(operation["step"], 4)] + "</h2>"
    if operation["status"] == "preparing":
        body += (
            _ui_template(
                '<p role="status">[[text:campaign_flow.work_continues_automatically_you_may_leave_this_page_and_return]]</p><form class="action-row" method="post" action="/operations/'
            )
            + operation["id"]
            + _ui_template(
                '/stop"><button class="danger">[[text:campaign_flow.stop_campaign]]</button></form><script>setTimeout(()=>window.uraBusy.reload(),3000);</script>'
            )
        )
    elif operation["status"] == "complete":
        body += _ui_template(
            "<p>[[text:campaign_flow.collection_and_selected_assessment_stages_have_finished_coverage]]</p>"
        )
    else:
        body += (
            '<p class="notice amber">'
            + html.escape(operation.get("error") or _ui_text("campaign_flow.campaign_stopped"))
            + '</p><form class="action-row" method="post" action="/operations/'
            + operation["id"]
            + _ui_template('/retry"><button>[[text:campaign_flow.resume_campaign]]</button></form>')
        )
        body += (
            '<p><a href="/build?campaign_id='
            + owner
            + _ui_template(
                '#campaign-workflow">[[text:campaign_flow.change_the_reported_campaign_choice]]</a></p>'
            )
        )
    body += (
        '<p><a href="/campaigns/'
        + owner
        + _ui_template(
            '?section=results">[[text:campaign_flow.results]]</a> | <a href="/campaigns/'
        )
        + owner
        + _ui_template(
            '?section=judging">[[text:campaign_flow.judging]]</a> | <a href="/campaigns/'
        )
        + owner
        + _ui_template('?section=costs">[[text:campaign_flow.costs]]</a></p></section>')
    )
    for kind in ("local", "haiku"):
        summary = operation.get(kind + "_summary")
        if summary:
            body += (
                '<section class="card"><h2>'
                + _ui_label(kind)
                + _ui_template(" [[text:campaign_flow.assessment_coverage]]</h2><p>")
                + str(summary["selected_outputs"])
                + _ui_template(" [[text:campaign_flow.selected_answers]]</p><ul>")
            )
            body += (
                "".join(
                    "<li>" + html.escape(_ui_label(key)) + ": " + str(value) + "</li>"
                    for key, value in summary["dispositions"].items()
                )
                + "</ul></section>"
            )
    body += _ui_template(
        '<details class="card"><summary>[[text:campaign_flow.technical_jobs]]</summary><ul>'
    )
    if operation.get("preparation"):
        body += (
            '<li><a href="/operations/'
            + operation["preparation"]
            + _ui_template('">[[text:campaign_flow.preparation_and_connection_details]]</a></li>')
        )
    for key in (
        "collection_job",
        "local_preparation",
        "local_execution",
        "haiku_preparation",
        "haiku_execution",
    ):
        if operation.get(key):
            body += (
                '<li><a href="/jobs/'
                + operation[key]
                + '">'
                + html.escape(_ui_label(key))
                + "</a></li>"
            )
    return _page(
        _ui_text("campaign_flow.campaign_progress"),
        body + "</ul></details>",
        active=_ui_text("campaign_flow.campaigns"),
    )


def freeze_spending(app, operation, params):
    from .reports import rate_for

    snapshot, _, _, configs = app._selected_api_config_snapshot(params)
    if not snapshot["routes"]:
        return
    pricing = app._load_registry("pricing.json", "rig/pricing.example.json")
    routes = []
    for row in snapshot["routes"]:
        rate, why = rate_for(pricing, row["provider"], row["model"])
        if rate is None or rate.get("currency") != "USD":
            raise ValueError(
                _ui_text("campaign_flow.configure_usd_pricing_for")
                + row["requested_spec"]
                + ": "
                + why
            )
        rates = rate["per_million_tokens"]
        for key in ("input", "output"):
            value = Decimal(str(rates.get(key)))
            if not value.is_finite() or value < 0:
                raise ValueError(
                    _ui_text("campaign_flow.complete_nonnegative_input_output_prices_are_required")
                )
        routes.append(
            dict(
                spec=row["requested_spec"],
                provider=row["provider"],
                model=row["model"],
                config=configs.get(row["requested_spec"]),
                input_price=rates["input"],
                output_price=rates["output"],
            )
        )
    root = (app.results_root / "rig-web" / "campaign-spending" / operation["id"]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = root / "policy.json"
    payload = dict(max_microusd=microusd(params.get("campaign_collection_cost", "")), routes=routes)
    if path.exists() and json.loads(path.read_text()) != payload:
        raise ValueError(
            _ui_text(
                "campaign_flow.the_prepared_spending_policy_changed_review_a_new_campaign_operat"
            )
        )
    if not path.exists():
        app._write_private_workflow_file(
            path, (json.dumps(payload, sort_keys=True) + "\n").encode()
        )
    operation["spending_policy"] = str(path)
    app._save_operation(operation)
