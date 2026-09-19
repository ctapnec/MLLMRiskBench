"""Review and launch saved Build programs through the existing collection command."""

from __future__ import annotations

from .i18n import template as _ui_template, text as _ui_text

import html
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

from .builder_replays import argument, completed_argv
from .catalog import build_argv
from .ui import _page


def _program_paths(argv, input_flag="--program"):
    return [argv[index + 1] for index, flag in enumerate(argv[:-1]) if flag == input_flag]


def collection_history(
    app, owner, paths, *, command="hosted_campaign_execute", input_flag="--program"
):
    rows = app.db._query(
        "SELECT j.* FROM jobs j JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id "
        "WHERE m.campaign_id=? AND j.command=? ORDER BY j.started_at DESC,j.job_id DESC",
        (owner, command),
    )
    if rows is None:
        raise ValueError(_ui_text("builder_collection.campaign_collection_history_is_unavailable"))
    for row in rows:
        if _program_paths(json.loads(row["argv"]), input_flag) == paths:
            return row
    return None


def prepared_collection(app, params, *, for_execution=False):
    owner = params.get("campaign_id", "")
    app.db.require_workspace(owner)
    argv = completed_argv(
        app, params.get("retained_programs_job"), owner, "hosted_campaign_prepare"
    )
    receipt = json.loads((Path(argument(argv, "--out-root")) / "receipt.json").read_text())
    if receipt.get("status") != "prepared_no_generation_calls" or not receipt.get("programs"):
        raise ValueError(
            _ui_text("builder_collection.complete_counted_collection_preparation_first")
        )
    if not for_execution:
        history = collection_history(app, owner, [row["path"] for row in receipt["programs"]])
        if history is not None:
            collection_argv = json.loads(history["argv"])
            if "--prepare-runtime" in collection_argv:
                from experiments.hosted_runtime_collection import effective_program_descriptors

                selection_path = Path(argument(collection_argv, "--out")) / "selection.json"
                if not selection_path.is_file():
                    raise ValueError(
                        _ui_text(
                            "builder_collection.runtime_preparation_has_not_published_its_execution_settings_yet"
                        )
                    )
                selection = json.loads(selection_path.read_text())
                root = Path(selection["runtime_root"])
                if not (root / "programs.json").is_file():
                    raise ValueError(
                        _ui_text(
                            "builder_collection.finish_installed_runtime_preparation_before_preparing_output_judg"
                        )
                    )
                manifest = json.loads((root / "programs.json").read_text())
                if [row["path"] for row in manifest["original_programs"]] != [
                    row["path"] for row in receipt["programs"]
                ]:
                    raise ValueError(
                        _ui_text(
                            "builder_collection.collection_runtime_belongs_to_different_prepared_inputs"
                        )
                    )
                receipt = dict(receipt, programs=effective_program_descriptors(root))
    return receipt


def request_purposes(program):
    """Describe prepared requests without treating diagnostics as measured inputs."""
    purposes = {identity: set() for identity in program["requests"]}
    kinds = {
        "measured_run": "measured",
        "diagnostic_canary": "diagnostic",
        "attestation_probe": "diagnostic",
    }
    for job in program.get("jobs", []):
        for identity in job.get("input_ids", []):
            if identity in purposes:
                purposes[identity].add(kinds.get(job.get("purpose"), "unclassified"))
    counts = dict(measured=0, diagnostic=0, unclassified=0)
    for categories in purposes.values():
        counts[next(iter(categories)) if len(categories) == 1 else "unclassified"] += 1
    return counts


def collection_launch_values(app, params):
    owner = params.get("campaign_id", "")
    receipt = prepared_collection(app, params, for_execution=True)
    workers = params.get("retained_collection_workers", "2") or "2"
    if workers not in {str(number) for number in range(1, 9)}:
        raise ValueError(
            _ui_text("builder_collection.choose_1_to_8_collection_workers_per_provider")
        )
    project = app.repo_root.resolve()
    revision = subprocess.check_output(
        ["git", "-C", str(project), "rev-parse", "HEAD"], text=True
    ).strip()
    values = {
        "--budget-root": str(Path(receipt["budget"]["path"]).parent),
        "--budget-plan-sha256": receipt["budget"]["sha256"],
        "--project-root": str(project),
        "--expected-commit": revision,
        "--workers-per-provider": workers,
    }
    rows = []
    needs_runtime = False
    for index, descriptor in enumerate(receipt["programs"]):
        suffix = f"#{index}" if index else ""
        values["--program" + suffix] = descriptor["path"]
        values["--program-sha256" + suffix] = descriptor["sha256"]
        program = json.loads(Path(descriptor["path"]).read_text())
        needs_runtime |= any(
            "--model-acquisition-plan" not in job["argv"]
            or (job["purpose"] != "attestation_probe" and "--live-attestation" not in job["argv"])
            for job in program.get("jobs", [])
        )
        rows.append(
            (
                program["target"],
                len(program["requests"]),
                program["max_output_tokens"],
                sum(request["bound_microusd"] for request in program["requests"].values()),
                request_purposes(program),
            )
        )
    parent = (app.results_root / "rig-web" / "hosted-collections").resolve()
    parent.mkdir(parents=True, exist_ok=True)
    values["--out"] = str(parent / uuid4().hex)
    history = collection_history(app, owner, [row["path"] for row in receipt["programs"]])
    if needs_runtime:
        values["--prepare-runtime"] = "on"
        store = os.environ.get("URA_MODEL_STORE")
        if store:
            values["--model-store"] = str(Path(store).resolve(strict=True))
    if history is not None:
        old = json.loads(history["argv"])
        previous_root = Path(argument(old, "--out"))
        initialized = (previous_root / "selection.json").is_file()
        failed_before_start = (
            not previous_root.exists()
            and history["state"] == "failed"
            and history["exit_code"] == 1
        )
        if not initialized and not failed_before_start:
            raise ValueError(
                _ui_text(
                    "builder_collection.previous_collection_control_records_are_incomplete_inspect_its_jo"
                )
            )
        # Continue the saved execution policy, not a newly inferred preparation.
        values.pop("--prepare-runtime", None)
        if "--prepare-runtime" in old:
            values["--prepare-runtime"] = "on"
        if "--model-store" in old:
            values["--model-store"] = argument(old, "--model-store")
        flags = ("--budget-root", "--budget-plan-sha256", "--project-root")
        for flag in flags:
            if argument(old, flag) != values[flag]:
                raise ValueError(
                    _ui_text(
                        "builder_collection.this_collection_needs_a_reviewed_revision_or_budget_recovery_its"
                    )
                )
        if initialized:
            # Deployment does not change the saved experiment. The collector
            # runs its original revision in a detached source-only checkout.
            values["--expected-commit"] = argument(old, "--expected-commit")
            values["--resume-from"] = str(previous_root)
    return values, rows, history, workers


def collection_review(app, params):
    owner = params.get("campaign_id", "")
    values, rows, history, workers = collection_launch_values(app, params)
    action = (
        _ui_text("builder_collection.continue_saved_collection")
        if history is not None
        else _ui_text("builder_collection.start_prepared_collection")
    )
    ticket = app._new_launch_ticket(
        {
            "campaign_id": owner,
            "values": json.dumps(values),
            "previous_job": history["job_id"] if history is not None else "",
        },
        purpose="matched-collection",
    )
    body = _ui_template(
        "<h1>[[text:builder_collection.review_prepared_collection]]</h1>"
    ) + app._campaign_banner(owner)
    body += (
        _ui_template(
            "<p>[[text:builder_collection.this_review_uses_the_completed_preparation_s_saved_inputs_and_mod]] "
        )
        + workers
        + _ui_template(
            " [[text:builder_collection.worker_s_each_collection_makes_paid_target_calls_local_and_haiku]]</p><div class='scroll'><table><tr><th>[[text:builder_collection.prepared_model]]</th><th>[[text:builder_collection.total_requests]]</th><th>[[text:builder_collection.measured]]</th><th>[[text:builder_collection.diagnostic]]</th><th>[[text:builder_collection.unclassified]]</th><th>[[text:builder_collection.output_allowance]]</th><th>[[text:builder_collection.initial_attempt_ceiling_usd]]</th></tr>"
        )
        + "".join(
            "<tr><td>"
            + html.escape(model)
            + f"</td><td>{count:,}</td><td>{parts['measured']:,}</td><td>{parts['diagnostic']:,}</td><td>{parts['unclassified']:,}</td><td>{tokens:,}</td><td>${cost / 1e6:,.6f}</td></tr>"
            for model, count, tokens, cost, parts in rows
        )
        + _ui_template(
            "</table></div><p>[[text:builder_collection.diagnostics_are_not_measured_results_unclassified_requests_have_m]]</p><p>[[text:builder_collection.these_ceilings_are_not_reported_charges_http_retries_and_judging]]</p>"
        )
    )
    if "--prepare-runtime" in values:
        body += _ui_template(
            "<p>[[text:builder_collection.installed_runtime_binding_and_transport_checks_are_included_in_th]]</p>"
        )
    if history is not None:
        body += (
            _ui_template("<p>[[text:builder_collection.previous_collection]] <a href='/jobs/")
            + history["job_id"]
            + _ui_template("'>[[text:builder_collection.open_job_and_retained_results]]</a></p>")
        )
        body += _ui_template(
            "<p>[[text:builder_collection.continuation_keeps_the_original_execution_revision_even_after_a_c]]</p>"
        )
    body += (
        _ui_template("<details><summary>[[text:builder_collection.exact_command]]</summary><pre>")
        + html.escape(" ".join(build_argv("hosted_campaign_execute", values)))
        + "</pre></details><form class='action-row' method='post' action='/build/collect-prepared'>"
        "<input type='hidden' name='launch_ticket' value='" + html.escape(ticket, quote=True) + "'>"
        "<button type='submit'>" + action + "</button></form>"
        "<p><a href='/build?campaign_id="
        + owner
        + _ui_template("'>[[text:builder_collection.return_to_build]]</a></p>")
    )
    return _page(
        _ui_text("builder_collection.review_prepared_collection"),
        body,
        active=_ui_text("builder_collection.build"),
    )


def collect_prepared(app, form):
    if set(form) != {"launch_ticket"}:
        raise ValueError(
            _ui_text("builder_collection.review_the_prepared_collection_before_starting_it")
        )
    params = app._launch_ticket_params(form["launch_ticket"], purpose="matched-collection")
    if params is None:
        raise ValueError(
            _ui_text(
                "builder_collection.collection_review_expired_or_was_already_used_reopen_the_review"
            )
        )
    values = json.loads(params["values"])
    owner = params["campaign_id"]
    # Use the existing console lock and persisted job index, not a new scheduler.
    # Two reviews opened in separate tabs must not launch the same paid work.
    with app._app_lock:
        history = collection_history(
            app, owner, _program_paths(build_argv("hosted_campaign_execute", values))
        )
        previous = history["job_id"] if history is not None else ""
        if previous != params["previous_job"]:
            raise ValueError(
                _ui_text(
                    "builder_collection.this_collection_has_a_newer_launch_open_that_job_before_continuin"
                )
            )
        if history is not None:
            live = app.jobs.get(previous)
            state = live.state() if live is not None else history["state"]
            if state in {"running", "queued", "starting"}:
                raise ValueError(
                    _ui_text(
                        "builder_collection.this_collection_is_already_active_open_its_job_to_monitor_it"
                    )
                )
        return app.start_job("hosted_campaign_execute", values, campaign_id=owner)


def collection_panel(params):
    if not params.get("retained_programs_job"):
        return ""
    value = html.escape(params.get("retained_collection_workers", "2"), quote=True)
    return (
        _ui_template(
            "<section class='card' id='prepared-collection'><h2>[[text:builder_collection.collect_prepared_inputs]]</h2><p>[[text:builder_collection.review_the_saved_model_assignments_and_costs_then_start_or_contin]]</p><label class='campaign-field'>[[text:builder_collection.workers_per_provider]]<input type='number' min='1' max='8' step='1' form='builder' name='retained_collection_workers' value='"
        )
        + value
        + _ui_template(
            "'></label><div class='action-row'><button form='builder' formaction='/build/review-collection'>[[text:builder_collection.review_prepared_collection]]</button></div></section>"
        )
    )
