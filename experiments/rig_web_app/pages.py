"""Overview, command, job, and artifact pages."""

from __future__ import annotations

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import csv
import html
import io
import json
import math
import os
import shutil
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Mapping
from urllib.parse import quote, urlencode
from uuid import uuid4

from ura.strict_json import strict_json_loads
from .command_forms import REPEAT_FIELDS_SCRIPT

from .catalog import (
    _MAX_RENDER_BYTES,
    _CSV_PREVIEW_ROWS,
    CommandParam,
    _PARAM_HELP,
    _SUGGEST_STATIC,
    COMMAND_GROUPS,
    _contained,
    evidence_badges,
    _icon,
)

from .ui import (
    _badges_html,
    _crumbs,
    _human_duration,
    _human_size,
    _page,
    _page_tablist,
    _page_tabpanel,
)

from .artifacts import (
    _PIPELINE_STAGES,
    _STAGE_PATHS_SHOWN,
    Job,
    _pipeline_svg,
    artifact_inventory,
    run_kind,
)
from .campaigns import EngineeringCampaign
from .external_measured import ExternalMeasuredJob


_DASHBOARD_RECENT_FAILURE_LIMIT = 5
_DASHBOARD_RECENT_PARTIAL_LIMIT = 5
_JOBS_HISTORY_DISPLAY_LIMIT = 5000


class PagesMixin:
    @staticmethod
    def _job_status_tag(state: str) -> str:
        return "passed" if state == "complete" else state

    @staticmethod
    def _job_work_label(job: Job) -> str:
        kind = run_kind(job.command, job.argv)
        if kind == "acquisition_plan":
            return _ui_text("pages.acquisition_plan")
        if kind == "preflight":
            return _ui_text("pages.preflight_work")
        if kind == "dry_run":
            return _ui_text("pages.offline_dry_run")
        if kind == "attestation_probe":
            return _ui_text("pages.model_probe")
        if kind == "diagnostic_canary":
            return _ui_text("pages.diagnostic_model_run")
        if kind == "measured":
            return _ui_text("pages.model_campaign")
        if job.command == "model_acquire":
            return _ui_text("pages.model_acquisition")
        if job.command == "capture_t3mp3st":
            return _ui_text("pages.model_capture")
        if job.command == "harmbench_capture":
            return _ui_text("pages.preparation_work")
        from .job_presentation import work_label

        if label := work_label(job.command, job.argv):
            return label
        return _ui_text("pages.tool_validation")

    @staticmethod
    def _job_execution_label(job: Job) -> str:
        kind = run_kind(job.command, job.argv)
        if kind in {"acquisition_plan", "preflight", "dry_run"}:
            return _ui_text("pages.no_model_call")
        if job.command == "model_acquire":
            return _ui_text("pages.no_model_call")
        if job.command == "harmbench_capture":
            methods = [
                job.argv[index + 1]
                for index, value in enumerate(job.argv[:-1])
                if value == "--method"
            ]
            if methods and all(method.casefold() == "directrequest" for method in methods):
                return _ui_text("pages.no_model_call")
            return _ui_text("pages.verify_capture_artifact")
        if kind in {"attestation_probe", "diagnostic_canary", "measured"}:
            return _ui_text("pages.verify_artifacts")
        if job.command == "capture_t3mp3st":
            return _ui_text("pages.verify_capture_artifact")
        return _ui_text("pages.not_applicable")

    @staticmethod
    def _playbook_card() -> str:
        steps = (
            (
                "1",
                _ui_text("pages.author_revision_receipt"),
                "project_revision",
                {
                    "--expected-revision": _ui_text("pages.lt_40_hex_pin_gt"),
                    "--out": "runs/thesis/project-revision",
                },
            ),
            (
                "2",
                _ui_text("pages.preflight_no_calls"),
                "rig_check",
                {
                    "--dry-run": "on",
                    "--corpora": "synth",
                    # rig_check always adds --preflight-only, so the
                    # standalone-dry-only row exclusion is not valid here.
                    # One synth row keeps this convenience vector executable
                    # without selecting either tool-conditioned fixture row.
                    "--limit": "1",
                },
            ),
            # run_matrix is Build-only (the generic Run form rejects it), so
            # the paid steps open the validated Build workflow instead of a
            # Run-page prefill; the operator composes the lane there.
            ("3", _ui_text("pages.attestation_probe_paid"), "run_matrix", {}),
            ("4", _ui_text("pages.diagnostic_canary_paid"), "run_matrix", {}),
            ("5", _ui_text("pages.measured_lane_paid"), "run_matrix", {}),
        )
        rows = []
        for num, title, command, values in steps:
            if command == "run_matrix":
                link = _ui_template("<a href='/build'>[[text:pages.open_build]]</a>")
            else:
                params = "&".join(
                    f"{quote(flag)}={quote(str(val))}" for flag, val in values.items()
                )
                link = (
                    "<a href='/commands?cmd="
                    + f"{quote(command)}"
                    + "&"
                    + f"{params}"
                    + _ui_template("'>[[text:pages.prefill]]</a>")
                )
            rows.append(
                "<li><span class='step-n'>" + num + "</span>"
                f"<strong>{html.escape(title)}</strong> "
                f"<code>{html.escape(command)}</code> " + link + "</li>"
            )
        return (
            "<div class='card'><h2>"
            + _icon("book")
            + _ui_template(
                "[[text:pages.campaign_playbook]]</h2><p class='note'>[[text:pages.the_runbook_sequence_in_order_prefill_opens_the_run_page_with_tha]]</p><ol class='playbook'>"
            )
            + "".join(rows)
            + "</ol></div>"
        )

    def _db_card(self, reindexed: str) -> str:
        """Database health, schema version, and the one Reindex action."""

        health = self.db.health()
        tone = "green" if health["healthy"] else "red"
        state = _ui_text("pages.healthy") if health["healthy"] else _ui_text("pages.unavailable")
        counts = health["counts"]
        count_text = (
            ", ".join(
                f"{name}: {value if value is not None else _ui_text('pages.unknown')}"
                for name, value in counts.items()
            )
            if counts
            else _ui_text("pages.counts_unknown")
        )
        note = ""
        if reindexed:
            try:
                summary = strict_json_loads(reindexed)
            except ValueError:
                summary = {}
            if isinstance(summary, dict) and summary:
                # Always show the load-bearing counts (even when zero) and
                # escape every key/value - the query string is attacker
                # controlled, so this must never be a raw HTML sink.
                always = ("usage_rows", "markers", "reports", "roots")
                stat_bits = [
                    f"{html.escape(str(name))} {html.escape(str(summary.get(name, 0)))}"
                    for name in always
                ]
                stat_bits += [
                    f"{html.escape(str(key))} {html.escape(str(value))}"
                    for key, value in sorted(summary.items())
                    if key not in {"ok", *always} and value
                ]
                note = (
                    "<div class='notice "
                    + ("blue" if summary.get("ok") else "red")
                    + _ui_template("'><strong>[[text:pages.reindex]] ")
                    + html.escape(
                        _ui_text("pages.completed")
                        if summary.get("ok")
                        else _ui_text("pages.failed_status")
                    )
                    + _ui_template(
                        ".</strong><p class='note'>[[text:pages.derived_usage_cost_and_report_indexes_were_rebuilt_from_retained]]"
                    )
                    + ", ".join(stat_bits)
                    + _ui_template("[[text:pages.skip_counts_are_reported_never_silent]]</p></div>")
                )
        error = (
            (
                _ui_template("<p class='note'>[[text:pages.last_error]] <code>")
                + f"{html.escape(health['last_error'])}"
                + "</code></p>"
            )
            if health["last_error"]
            else ""
        )
        return (
            "<div class='card'><h2>"
            + _icon("disk")
            + _ui_template("[[text:pages.console_database]]</h2>")
            + note
            + (
                "<p><span class='badge "
                + f"{tone}"
                + "'>"
                + f"{html.escape(state)}"
                + _ui_template("</span> [[text:pages.schema_v]]")
                + f"{health['schema_version']}"
                + " - "
                + f"{html.escape(count_text)}"
                + "</p>"
            )
            + error
            + _ui_template(
                "<form method='post' action='/db/reindex' data-busy='[[attr:pages.rebuilding_the_index_from_retained_artifacts]]'><label class='checkrow'><input type='checkbox' name='verify_artifact_sha256'><span>[[text:pages.also_verify_file_checksums_slow_off_by_default]]</span></label> <button type='submit' class='small'>[[text:pages.reindex_from_artifacts]]</button></form><p class='note'>[[text:pages.operational_state_only_jobs_runs_recorded_usage_report_index_unde]]</p></div>"
            )
        )

    def _overview(self, reindexed: str = "") -> bytes:
        self._reconcile()
        jobs = list(self.jobs.values())
        campaigns, campaign_scan_note = self._engineering_campaign_scan()
        job_states = [(job, job.state()) for job in jobs]
        running_jobs = [job for job, state in job_states if state == "running"]
        failed_jobs = [job for job, state in job_states if state == "failed"]
        indeterminate_jobs = [
            (job, state) for job, state in job_states if state in {"orphaned", "unknown"}
        ]
        running_campaigns = [campaign for campaign in campaigns if campaign.state == "running"]
        failed_campaigns = [campaign for campaign in campaigns if campaign.status_tag == "failed"]
        blocked_stopped_campaigns = [
            campaign for campaign in campaigns if campaign.status_tag in {"blocked", "stopped"}
        ]
        indeterminate_campaigns = [
            campaign for campaign in campaigns if campaign.status_tag in {"orphaned", "unknown"}
        ]
        partial_campaigns = [campaign for campaign in campaigns if campaign.status_tag == "partial"]
        counts, truncated = artifact_inventory(self.results_root)
        source_receipt_value = os.environ.get("URA_SOURCE_CONFORMANCE_MANIFEST", "")
        if source_receipt_value:
            try:
                results_root = self.results_root.resolve()
                source_receipt = Path(source_receipt_value).resolve(strict=True)
                if not source_receipt.is_file():
                    raise ValueError(_ui_text("pages.configured_source_receipt_is_not_a_file"))
                source_relative = source_receipt.relative_to(results_root).as_posix()
            except (OSError, ValueError):
                pass
            else:
                source_stage = counts["Source receipts"]
                scanner_already_counts = source_receipt.name.casefold().endswith(
                    "source-conformance.json"
                )
                if not scanner_already_counts:
                    if "superseded" in source_relative.split("/"):
                        source_stage.superseded += 1
                    else:
                        source_stage.count += 1
                if source_relative not in source_stage.paths:
                    source_stage.paths.insert(0, source_relative)
                    del source_stage.paths[_STAGE_PATHS_SHOWN:]
        disk_html = _ui_template("<p class='note'>[[text:pages.disk_usage_unavailable]]</p>")
        try:
            usage = shutil.disk_usage(self.results_root)
        except OSError:
            usage = None
        if usage is not None and usage.total > 0:
            used_pct = 100.0 * (usage.total - usage.free) / usage.total
            disk_html = (
                "<div class='stat'><span class='value'>"
                + f"{_human_size(usage.free)}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.free_on_results_volume]]</span></div><div class='meter'><div style='width:"
                )
                + f"{used_pct:.1f}"
                + "%'></div></div><p class='note'>"
                + f"{used_pct:.0f}"
                + _ui_text("pages.used_of")
                + f"{_human_size(usage.total)}"
                + "</p>"
            )
        pin = os.environ.get("REF_URA", "")
        cost_rows, _cost_unavailable = self._usage_cost_rows()
        if cost_rows is None:
            spend_value, spend_label = (
                _ui_text("pages.unknown"),
                _ui_text("pages.calculated_spend_db_unavailable"),
            )
        else:
            billable = [r for r in cost_rows if r["billable"]]
            if not billable:
                spend_value = _ui_text("pages.n_a")
                spend_label = _ui_text("pages.calculated_spend_no_recorded_billable_usage")
            elif any(r["cost"] is None for r in billable):
                spend_value = _ui_text("pages.n_a")
                spend_label = _ui_text("pages.calculated_spend_price_tokens_missing")
            else:
                by_currency: dict[str, float] = {}
                for row in billable:
                    subtotals = row.get("by_currency")
                    if isinstance(subtotals, Mapping) and subtotals:
                        for currency, amount in subtotals.items():
                            if isinstance(amount, (int, float)) and not isinstance(amount, bool):
                                code = str(currency).upper()
                                by_currency[code] = by_currency.get(code, 0.0) + float(amount)
                    elif row.get("currency") and isinstance(row.get("cost"), (int, float)):
                        code = str(row["currency"]).upper()
                        by_currency[code] = by_currency.get(code, 0.0) + float(row["cost"])
                if len(by_currency) == 1:
                    currency, amount = next(iter(by_currency.items()))
                    spend_value = self._fmt_money(amount, currency)
                    spend_label = _ui_text("pages.calculated_spend_recorded_usage_x_pricing")
                elif len(by_currency) > 1:
                    spend_value = " / ".join(
                        self._fmt_money(amount, currency)
                        for currency, amount in sorted(by_currency.items())
                    )
                    spend_label = _ui_text("pages.calculated_spend_mixed_currencies_not_summed")
                else:
                    spend_value = _ui_text("pages.n_a")
                    spend_label = _ui_text("pages.calculated_spend_currency_unavailable")
        stats = (
            "<div class='cols'><div class='card'><div class='stat'><span class='value'>"
            + f"{len(jobs) + len(campaigns)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.jobs_console_external]]</span></div></div><div class='card'><div class='stat'><span class='value'><span class='dot blue'></span>"
            )
            + f"{len(running_jobs)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.running_console_owned]]</span></div></div><div class='card'><div class='stat'><span class='value'><span class='dot blue'></span>"
            )
            + f"{len(running_campaigns)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.running_external_task_log_report]]</span></div></div><div class='card'><div class='stat'><span class='value'><span class='dot red'></span>"
            )
            + f"{len(failed_jobs) + len(failed_campaigns)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.failed]]</span></div></div><div class='card'><div class='stat'><span class='value'><span class='dot red'></span>"
            )
            + f"{len(blocked_stopped_campaigns)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.blocked_stopped]]</span></div></div><div class='card'><div class='stat'><span class='value'><span class='dot amber'></span>"
            )
            + f"{len(indeterminate_jobs) + len(indeterminate_campaigns)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.orphaned_unknown]]</span></div></div><div class='card'><div class='stat'><span class='value'><span class='dot amber'></span>"
            )
            + f"{len(partial_campaigns)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.partial]]</span></div></div><div class='card'><div class='stat'><span class='value'><code>"
            )
            + f"{html.escape(pin[:10] or 'unpinned')}"
            + _ui_template(
                "</code></span><span class='label'>[[text:pages.project_revision_ref_ura]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
            )
            + f"{spend_value}"
            + "</span><span class='label'>"
            + f"{html.escape(spend_label)}"
            + "</span></div></div><div class='card'>"
            + f"{disk_html}"
            + "</div></div>"
        )
        running_rows = []
        for job in running_jobs:
            activity = (
                _ui_template(
                    " <span class='badge blue' title='[[attr:pages.explicit_job_activity_metadata]]'>[[text:pages.downloading]]</span>"
                )
                if getattr(job, "activity", None) == "model_download"
                else ""
            )
            running_rows.append(
                (
                    job.started_at,
                    f"<tr><td><a href='/jobs/{html.escape(job.job_id)}'>"
                    f"{html.escape(job.job_id)}</a></td>"
                    f"<td>{html.escape(job.command)}{activity}</td>"
                    f"<td>{_human_duration(job.runtime_seconds())}</td></tr>",
                )
            )
        for campaign in running_campaigns:
            route_id = quote(campaign.route_id)
            activity = (
                _ui_template(
                    " <span class='badge blue' title='[[attr:pages.explicit_task_kind_model_download_in_the_retained_task_log]]'>[[text:pages.downloading]]</span>"
                )
                if campaign.download_tasks
                else ""
            )
            running_rows.append(
                (
                    campaign.started_at,
                    (
                        "<tr><td><a href='/jobs/campaign/"
                        + f"{route_id}"
                        + "'>"
                        + f"{html.escape(campaign.campaign_id)}"
                        + _ui_template(
                            "</a></td><td>[[text:pages.engineering_campaign]] <span class='badge gray'>[[text:pages.external]]</span> <span class='badge blue'>[[text:pages.running]]</span>"
                        )
                        + f"{activity}"
                        + "</td><td>"
                        + f"{_human_duration(campaign.runtime_seconds())}"
                        + "</td></tr>"
                    ),
                )
            )
        running_rows_html = "".join(row for _started, row in sorted(running_rows))
        running_html = (
            "<div class='card'><h2>"
            + _icon("pulse")
            + _ui_template(
                "[[text:pages.running_2]]</h2><div class='scroll'><table><tr><th>[[text:pages.job]]</th><th>[[text:pages.command]]</th><th>[[text:pages.runtime]]</th></tr>"
            )
            + running_rows_html
            + _ui_template(
                "</table></div><p class='note'>[[text:pages.external_running_state_is_a_task_log_report_framework_installer_c]]</p></div>"
            )
            if running_rows_html
            else ""
        )
        attention_rows = []
        for job in failed_jobs:
            attention_rows.append(
                (
                    job.started_at,
                    (
                        "<tr><td><a href='/jobs/"
                        + f"{html.escape(job.job_id)}"
                        + "'>"
                        + f"{html.escape(job.job_id)}"
                        + "</a></td><td>"
                        + f"{html.escape(job.command)}"
                        + _ui_template(
                            " <span class='badge red'>[[text:pages.failed]]</span></td><td>"
                        )
                        + f"{_human_duration(job.runtime_seconds())}"
                        + "</td></tr>"
                    ),
                )
            )
        for job, state in indeterminate_jobs:
            attention_rows.append(
                (
                    job.started_at,
                    f"<tr><td><a href='/jobs/{html.escape(job.job_id)}'>"
                    f"{html.escape(job.job_id)}</a></td>"
                    f"<td>{html.escape(job.command)} "
                    f"<span class='badge amber'>{html.escape(_ui_label(state))}</span></td>"
                    f"<td>{_human_duration(job.runtime_seconds())}</td></tr>",
                )
            )
        for campaign in [
            *failed_campaigns,
            *blocked_stopped_campaigns,
            *indeterminate_campaigns,
        ]:
            route_id = quote(campaign.route_id)
            detail = (
                f" <span class='fieldhint'>{html.escape(campaign.state_detail)}</span>"
                if campaign.state_detail
                else ""
            )
            tag_tone = {
                "failed": "red",
                "blocked": "red",
                "stopped": "red",
                "orphaned": "amber",
                "unknown": "amber",
            }.get(campaign.status_tag, "gray")
            attention_rows.append(
                (
                    campaign.started_at,
                    (
                        "<tr><td><a href='/jobs/campaign/"
                        + f"{route_id}"
                        + "'>"
                        + f"{html.escape(campaign.campaign_id)}"
                        + _ui_template(
                            "</a></td><td>[[text:pages.engineering_campaign]] <span class='badge "
                        )
                        + f"{tag_tone}"
                        + _ui_template("'>[[text:pages.external_2]] ")
                        + f"{html.escape(campaign.status_tag)}"
                        + "</span>"
                        + f"{detail}"
                        + "</td><td>"
                        + f"{_human_duration(campaign.runtime_seconds())}"
                        + "</td></tr>"
                    ),
                )
            )
        recent_attention_rows = sorted(attention_rows, reverse=True)[
            :_DASHBOARD_RECENT_FAILURE_LIMIT
        ]
        attention_html = (
            "<div class='card'><h2>"
            + _icon("pulse")
            + _ui_template(
                "[[text:pages.needs_attention]]</h2><div class='scroll'><table><tr><th>[[text:pages.job]]</th><th>[[text:pages.command]]</th><th>[[text:pages.runtime]]</th></tr>"
            )
            + "".join(row for _started, row in recent_attention_rows)
            + (
                _ui_template("</table></div><p class='note'>[[text:pages.showing_up_to]] ")
                + f"{_DASHBOARD_RECENT_FAILURE_LIMIT}"
                + _ui_template(
                    " [[text:pages.most_recently_started_failed_blocked_stopped_orphaned_or_unknown]]</p></div>"
                )
            )
            if recent_attention_rows
            else ""
        )
        partial_rows = []
        for campaign in partial_campaigns:
            route_id = quote(campaign.route_id)
            pending = (
                _ui_text("pages.unknown")
                if campaign.pending_tasks is None
                else str(campaign.pending_tasks)
            )
            partial_rows.append(
                (
                    campaign.started_at,
                    (
                        "<tr><td><a href='/jobs/campaign/"
                        + f"{route_id}"
                        + "'>"
                        + f"{html.escape(campaign.campaign_id)}"
                        + _ui_template(
                            "</a></td><td><span class='badge amber'>[[text:pages.partial]]</span> "
                        )
                        + f"{campaign.succeeded_tasks}"
                        + _ui_text("pages.succeeded")
                        + f"{campaign.failed_tasks}"
                        + _ui_text("pages.failed_copy")
                        + f"{campaign.skipped_tasks}"
                        + _ui_text("pages.skipped")
                        + f"{pending}"
                        + _ui_template(" [[text:pages.pending]]</td><td>")
                        + f"{_human_duration(campaign.runtime_seconds())}"
                        + "</td></tr>"
                    ),
                )
            )
        recent_partial_rows = sorted(partial_rows, reverse=True)[:_DASHBOARD_RECENT_PARTIAL_LIMIT]
        partial_html = (
            "<div class='card'><h2>"
            + _icon("pulse")
            + _ui_template(
                "[[text:pages.partial_campaigns]]</h2><div class='scroll'><table><tr><th>[[text:pages.job]]</th><th>[[text:pages.task_results]]</th><th>[[text:pages.runtime]]</th></tr>"
            )
            + "".join(row for _started, row in recent_partial_rows)
            + _ui_template(
                "</table></div><p class='note'>[[text:pages.a_successful_campaign_terminal_does_not_hide_failed_skipped_or_pe]]</p></div>"
            )
            if recent_partial_rows
            else ""
        )
        stage_sections = []
        for label, _suffixes in _PIPELINE_STAGES:
            stage = counts.get(label)
            if stage is None or not stage.paths:
                continue
            items = "".join(
                f"<li><a href='/artifacts?path={quote(path)}'>{html.escape(path)}</a></li>"
                for path in stage.paths
            )
            total = stage.count + stage.superseded
            if total > len(stage.paths):
                items += (
                    _ui_template("<li class='note'>[[text:pages.first]] ")
                    + f"{len(stage.paths)}"
                    + _ui_text("pages.of")
                    + f"{total}"
                    + _ui_template(" [[text:pages.shown]]</li>")
                )
            summary = (
                f"{html.escape(label)}" + ": " + f"{stage.count}" + _ui_text("pages.non_archived")
            )
            if stage.superseded:
                summary += ", " + f"{stage.superseded}" + _ui_text("pages.archived")
            stage_sections.append(
                f"<details class='stagefiles'><summary>{summary}</summary>"
                f"<ul>{items}</ul></details>"
            )
        stage_files = "".join(stage_sections)
        refresh = (
            "<script>setTimeout(function(){window.uraBusy.reload();}, 10000);</script>"
            if running_rows
            else ""
        )
        global_notices = (
            self._health_banner()
            + self._warnings_html()
            + (
                "<div class='notice amber'>" + html.escape(campaign_scan_note) + "</div>"
                if campaign_scan_note
                else ""
            )
        )
        system_panel = (
            stats
            + self._dashboard_hardware_card()
            + self._db_card(reindexed)
            + running_html
            + partial_html
            + attention_html
        )
        campaign_panel = (
            "<div class='card'><h2>"
            + _icon("chart")
            + _ui_template("[[text:pages.campaign_pipeline]]</h2>")
            + _pipeline_svg(counts)
            + _ui_template(
                "<p class='note'>[[text:pages.click_a_stage_to_browse_its_files_counts_are_retained_file_presen]] <code>superseded/</code> [[text:pages.directory_kept_as_history_not_active_for_example_an_earlier_pin_s]]"
            )
            + (
                _ui_text("pages.inventory_scan_truncated_at_its_entry_cap_counts_are_a_lower_boun")
                if truncated
                else ""
            )
            + "</p>"
            + stage_files
            + "</div>"
            + self._next_hint(counts)
            + self._playbook_card()
            + "<div class='card'><h2>"
            + _icon("file")
            + _ui_template("[[text:pages.campaign_bindings]]</h2>")
            + self._campaign_context()
            + "</div>"
        )
        governance_panel = (
            self._budget_card()
            + "<div class='card'><h2>"
            + _icon("logo")
            + _ui_template(
                "[[text:pages.boundaries]]</h2><p class='note'>[[text:pages.allowlisted_commands_only_no_arbitrary_shell_dry_run_canary_probe]]</p></div>"
            )
        )
        dashboard_tabs = (
            ("dashboard-system", _ui_text("pages.system")),
            ("dashboard-campaigns", _ui_text("pages.campaigns")),
            ("dashboard-governance", _ui_text("pages.governance")),
        )
        body = (
            "<h1>"
            + _icon("grid", size=22)
            + _ui_template("[[text:pages.dashboard]]</h1>")
            + global_notices
            + "<div class='page-tabs' data-page-tabs data-tab-key='dashboard' "
            "data-default-tab='dashboard-system'>"
            + _page_tablist(
                _ui_text("pages.dashboard_sections"), dashboard_tabs, default="dashboard-system"
            )
            + _page_tabpanel("dashboard-system", system_panel)
            + _page_tabpanel("dashboard-campaigns", campaign_panel)
            + _page_tabpanel("dashboard-governance", governance_panel)
            + "</div>"
            + refresh
        )
        return _page(_ui_text("pages.ura_rig_console"), body, active=_ui_text("pages.dashboard"))

    def _param_input(self, param: CommandParam) -> str:
        flag = html.escape(param.flag)
        if param.repeat:
            field = self._param_input(replace(param, repeat=False))
            field = field.replace(
                "name='" + flag + "'", "name='" + flag + "' aria-label='" + flag + " 1'"
            )
            return (
                "<div class='repeat-fields' data-repeat-flag='"
                + flag
                + "'><div class='repeat-row'>"
                + field
                + _ui_template(
                    "<button type='button' class='ghost' data-repeat-remove disabled>[[text:pages.remove]]</button></div><button type='button' class='ghost' data-repeat-add>[[text:pages.add_another_value]]</button></div>"
                )
            )
        if param.kind == "flag":
            return f"<input type='checkbox' name='{flag}'>"
        if param.choices:
            options = "".join(
                f"<option value='{html.escape(choice)}'>{html.escape(choice)}</option>"
                for choice in param.choices
            )
            if param.required:
                # argparse has no default for a required choice and build_argv
                # rejects a blank submission; the blank entry is only a
                # non-selectable prompt so the form agrees with that contract.
                return (
                    (
                        "<select name='"
                        + f"{flag}"
                        + _ui_template(
                            "' required><option value='' disabled selected>[[text:pages.select]]</option>"
                        )
                    )
                    + options
                    + "</select>"
                )
            return (
                (
                    "<select name='"
                    + f"{flag}"
                    + _ui_template("'><option value=''>[[text:pages.default]]</option>")
                )
                + options
                + "</select>"
            )
        if param.kind == "int":
            return f"<input type='number' step='1' name='{flag}'>"
        if param.kind == "float":
            return f"<input type='number' step='any' name='{flag}'>"
        listattr = f" list='dl-{html.escape(param.suggest)}'" if param.suggest else ""
        return f"<input type='text' name='{flag}'{listattr}>"

    def _command_card(self, name: str, campaign_id: str = "", *, manual: bool = False) -> str:
        if name == "live_attestation" and not manual:
            return (
                self._transport_check_form(campaign_id)
                + _ui_template(
                    "<details><summary>[[text:pages.advanced_transport_check_overrides]]</summary>"
                )
                + self._command_card(name, campaign_id, manual=True)
                + "</details>"
            )
        entry = self.commands[name]
        fields = []
        for param in entry.params:
            required = (
                _ui_template("<span class='req' title='[[attr:pages.required]]'>*</span>")
                if param.required
                else ""
            )
            help_text = param.help or _PARAM_HELP.get(param.flag, "")
            title = f" title='{html.escape(help_text)}'" if help_text else ""
            hint = f"<span class='fieldhint'>{html.escape(help_text)}</span>" if help_text else ""
            scope = ""
            if name == "human_audit":
                if param.flag in {
                    "--prepared-rating-form",
                    "--prepared-rating-form-sha256",
                    "--bootstrap-resamples",
                    "--alpha",
                    "--seed",
                    "--allow-single-rater",
                }:
                    scope = " data-human-audit-scope='analysis' hidden"
                elif param.flag == "--acknowledge-sensitive-content":
                    scope = " data-human-audit-scope='preparation' hidden"
            fields.append(
                f"<label{title}{scope}>{html.escape(param.flag)}{required} "
                f"<span class='kind'>{html.escape(param.kind)}</span>"
                "</label>"
                f"<div class='fieldwrap'{scope}>{self._param_input(param)}{hint}</div>"
            )
        haystack = html.escape(f"{name} {entry.description}".lower())
        return (
            f"<details class='cmd' data-name='{haystack}'><summary>"
            + _icon("terminal")
            + f"<span class='name'>{html.escape(name)}</span>"
            f"<span class='desc'>{html.escape(entry.description)}</span>"
            "</summary><div class='inner'>"
            f"<p class='note'><code>python -m {html.escape(entry.module)}"
            "</code></p>"
            "<form class='cmd' method='post' action='/jobs'>"
            f"<input type='hidden' name='command' value='{html.escape(name)}'>"
            + self._campaign_selector(campaign_id)
            + "".join(fields)
            + "<span></span><button type='submit'>"
            + _icon("play", size=15)
            + _ui_template("[[text:pages.start_job]]</button></form></div></details>")
        )

    def _registry_keys(self, name: str, example: str) -> list[str]:
        """Keys of an operator-local registry, falling back to the example.

        Presentation-only suggestions: the local file is authoritative for
        runs; the checked-in example keeps the console useful before the
        operator copies it. Malformed files yield no suggestions.
        """

        for candidate in (name, example):
            path = self.repo_root / "experiments" / candidate
            try:
                data = strict_json_loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                return sorted(data)
        return []

    def _datalists(self) -> str:
        lists = dict(_SUGGEST_STATIC)
        lists["arms"] = tuple(
            ["synth"]
            + self._registry_keys("source-instances.json", "rig/source-instances.example.json")
        )
        lists["api"] = tuple(
            ["mock"] + self._registry_keys("api-targets.json", "rig/api-targets.example.json")
        )
        return "".join(
            f"<datalist id='dl-{html.escape(key)}'>"
            + "".join(f"<option value='{html.escape(value)}'></option>" for value in values)
            + "</datalist>"
            for key, values in lists.items()
        )

    def _commands_page(self, campaign_id: str = "") -> bytes:
        grouped: set[str] = set()
        sections = []

        def card(name: str) -> str:
            if name == "run_matrix":
                return ""
            if name == "response_svm":
                target = "/analysis?campaign_id=" + campaign_id if campaign_id else "/campaigns"
                return (
                    _ui_template(
                        '<section class="card"><h2>[[text:pages.response_classifier_analysis]]</h2><p>[[text:pages.choose_saved_campaigns_and_a_teacher_condition_dataset_export_eva]]</p><a class="button" href="'
                    )
                    + target
                    + _ui_template(
                        '">[[text:pages.open_svm_analysis]]</a></section><details class="card"><summary>[[text:pages.advanced_svm_cli_form_and_imports]]</summary>'
                    )
                    + self._command_card(name, campaign_id)
                    + "</details>"
                )
            if name not in {"capture_t3mp3st", "harmbench_capture"}:
                return self._command_card(name, campaign_id)
            label = (
                _ui_text("pages.t3mp3st_capture")
                if name == "capture_t3mp3st"
                else _ui_text("pages.harmbench_prepare")
            )
            return (
                "<details class='cmd' data-name='"
                + f"{html.escape(name)}"
                + "'><summary>"
                + f"{_icon('flask')}"
                + "<strong>"
                + f"{html.escape(label)}"
                + _ui_template(
                    "</strong><span class='desc'>[[text:pages.validated_capture_first_workflow]]</span></summary><p class='note'>[[text:pages.open_the_build_workflow_for_field_validation_and_an_exact_command]]</p><p><a href='/build#prepared-workflows'>[[text:pages.open_in_build]]</a></p></details>"
                )
            )

        for title, icon, ref, names in COMMAND_GROUPS:
            cards = "".join(card(name) for name in names if name in self.commands)
            if not cards:
                continue
            grouped.update(names)
            sections.append(
                f"<div class='group-head'>{_icon(icon, size=20)}"
                f"<h2>{html.escape(title)}</h2>"
                f"<span class='ref'>{html.escape(ref)}</span></div>" + cards
            )
        # Internal controller commands have dedicated validated Build actions;
        # exposing their raw generic form would bypass that controller contract.
        internal_ui_commands = {"model_acquire", "ollama_pull", "run_matrix", "campaign_assess"}
        leftovers = "".join(
            card(name) for name in sorted(set(self.commands) - grouped - internal_ui_commands)
        )
        if leftovers:
            sections.append(
                (
                    "<div class='group-head'>"
                    + f"{_icon('file', size=20)}"
                    + _ui_template("<h2>[[text:pages.other]]</h2></div>")
                )
                + leftovers
            )
        body = (
            "<h1>"
            + _icon("terminal", size=22)
            + _ui_template(
                "[[text:pages.tools]]</h1><section class='card'><h2>[[text:pages.choose_what_you_want_to_do]]</h2><p>[[text:pages.build_handles_experiment_preparation_automatically_human_evaluati]]</p><div class='action-row'>"
            )
            + "<a class='button' href='/build"
            + ("?campaign_id=" + campaign_id if campaign_id else "")
            + _ui_template("'>[[text:pages.configure_an_experiment]]</a>")
            + "<a class='button ghost' href='/human-evaluation"
            + ("?campaign_id=" + campaign_id if campaign_id else "")
            + _ui_template("'>[[text:pages.review_saved_answers]]</a>")
            + "<a class='button ghost' href='"
            + ("/analysis?campaign_id=" + campaign_id if campaign_id else "/campaigns")
            + _ui_template("'>[[text:pages.svm_analysis]]</a>")
            + _ui_template(
                "</div></section><details class='card' id='advanced-cli-tools'><summary>[[text:pages.advanced_cli_tools_and_troubleshooting]]</summary><p class='note'>[[text:pages.typed_forms_over_the_allowlisted_experiment_clis_the_argument_vec]] <span class='req'>*</span> [[text:pages.marks_a_required_field]]</p><p><input id='cmdfilter' type='text' placeholder='[[attr:pages.type_to_filter_commands]]' aria-label='[[attr:pages.filter_commands]]'></p>"
            )
            + self._datalists()
            + "".join(sections)
            + "</details>"
            + "<script>(function(){"
            "var box=document.getElementById('cmdfilter');"
            "if(box){box.addEventListener('input',function(){"
            "var q=this.value.toLowerCase();"
            "document.querySelectorAll('details.cmd').forEach(function(d){"
            "var hay=d.getAttribute('data-name')||'';"
            "d.style.display=hay.indexOf(q)>=0?'':'none';});});}"
            # Playbook prefill: ?cmd=<name>&--flag=value opens and fills the
            # matching command form. Values still go through the typed form and
            # build_argv validation on submit; nothing is auto-run.
             + REPEAT_FIELDS_SCRIPT + "var params=new URLSearchParams(window.location.search);"
            "var cmd=params.get('cmd');"
            "if(cmd){var card=document.querySelector("
            '"details.cmd input[name=command][value=\'"+cmd+"\']");'
            "if(card){document.getElementById('advanced-cli-tools').open=true;var det=card.closest('details.cmd');det.open=true;"
            "params.forEach(function(val,key){"
            "if(key==='cmd'){return;}"
            "var field=commandField(det,key);"
            "if(!field){return;}"
            "if(field.type==='checkbox'){field.checked="
            "(val==='on'||val==='true'||val==='1'||val==='yes');}"
            "else{field.value=val;}});"
            "det.scrollIntoView({behavior:'smooth',block:'center'});}}"
            "function syncHumanAudit(form){"
            "function filled(name){var field=form.querySelector('[name=\"'+name+'\"]');"
            "return !!(field&&String(field.value||'').trim());}"
            "var analysis=filled('--labels')||filled('--source-task-labels');"
            "var preparation=filled('--prepare')||filled('--prepare-source-task');"
            "form.querySelectorAll('[data-human-audit-scope]').forEach(function(node){"
            "var scope=node.getAttribute('data-human-audit-scope');"
            "var visible=(scope==='analysis'&&analysis)||(scope==='preparation'&&preparation);"
            "node.hidden=!visible;node.querySelectorAll('input,select,textarea').forEach("
            "function(control){control.disabled=!visible;});});}"
            "document.querySelectorAll('form.cmd input[name=command][value=human_audit]')"
            ".forEach(function(command){var form=command.closest('form');"
            "syncHumanAudit(form);form.addEventListener('input',function(){syncHumanAudit(form);});"
            "form.addEventListener('change',function(){syncHumanAudit(form);});});"
            "})();</script>"
        )
        body = (
            _ui_template(
                "<p><a class='button ghost' href='/human-evaluation'>[[text:pages.human_evaluation_studies]]</a></p>"
            )
            + body
        )
        return _page(_ui_text("pages.run_a_command"), body, active=_ui_text("pages.tools"))

    @staticmethod
    def _jobs_history_bound(
        query: Mapping[str, str],
        name: str,
        default: float,
    ) -> float:
        raw_ms = query.get(f"{name}_ms", "")
        if raw_ms:
            try:
                value = float(raw_ms) / 1000.0
            except ValueError:
                value = float("nan")
            if math.isfinite(value):
                return value
        raw = query.get(name, "")
        if raw:
            try:
                parsed = datetime.fromisoformat(raw).timestamp()
            except (ValueError, OSError, OverflowError):
                parsed = float("nan")
            if math.isfinite(parsed):
                if name == "to" and "." not in raw:
                    parsed += 59.999 if len(raw) == 16 else 0.999
                return parsed
        return default

    def _jobs_page(self, query: Mapping[str, str] | None = None) -> bytes:
        if (query or {}).get("view") == "campaigns":
            return self._workspaces_page(context="jobs")
        self._reconcile()
        filters = dict(query or {})
        scope = filters.get("view", "all")
        campaign_id = filters.get("campaign_id", "")
        if campaign_id:
            self.db.require_workspace(campaign_id)
        now = time.time()
        started_from = self._jobs_history_bound(
            filters,
            "from",
            now - 7 * 86400,
        )
        started_to = self._jobs_history_bound(filters, "to", now)
        history_note = ""
        valid_window = started_from <= started_to
        if started_from > started_to:
            history_jobs = []
            history_note = _ui_text("pages.from_must_not_be_after_to")
        else:
            history_jobs, history_truncated = self._jobs_for_history_window(
                started_from,
                started_to,
                limit=_JOBS_HISTORY_DISPLAY_LIMIT,
            )
            if history_truncated:
                history_note = (
                    _ui_text("pages.showing_the_newest")
                    + f"{_JOBS_HISTORY_DISPLAY_LIMIT}"
                    + _ui_text(
                        "pages.console_jobs_in_this_date_range_narrow_from_to_to_retrieve_older"
                    )
                )

        def in_window(started_at: float) -> bool:
            return valid_window and started_from <= started_at <= started_to

        # A start-time filter is a history filter, not a process-visibility
        # control. Keep genuinely live work visible even when a multi-day run
        # began before the default seven-day window. Every source remains
        # bounded by its existing display/scan limit, and terminal rows never
        # receive this exception.
        pinned_console_ids: set[str] = set()
        outside_console = sorted(
            (
                job
                for job in self.jobs.values()
                if job.process is not None
                and job.state() == "running"
                and not in_window(job.started_at)
            ),
            key=lambda item: item.started_at,
            reverse=True,
        )
        console_live_truncated = len(outside_console) > _JOBS_HISTORY_DISPLAY_LIMIT
        history_by_id = {job.job_id: job for job in history_jobs}
        for job in outside_console[:_JOBS_HISTORY_DISPLAY_LIMIT]:
            pinned_console_ids.add(job.job_id)
            history_by_id.setdefault(job.job_id, job)
        history_jobs = sorted(
            history_by_id.values(),
            key=lambda item: item.started_at,
            reverse=True,
        )

        campaign_notes: list[str] = []
        if valid_window:
            campaigns, campaign_window_note = self._engineering_campaign_scan(
                started_from=started_from,
                started_to=started_to,
            )
            if campaign_window_note:
                campaign_notes.append(campaign_window_note)
        else:
            campaigns = []
        recent_campaigns, recent_campaign_note = self._engineering_campaign_scan()
        if not valid_window and recent_campaign_note and recent_campaign_note not in campaign_notes:
            campaign_notes.append(recent_campaign_note)
        pinned_campaign_ids: set[str] = set()
        campaign_by_route = {campaign.route_id: campaign for campaign in campaigns}
        for campaign in recent_campaigns:
            # Only an exact, positively verified named session may override an
            # operator-selected history window.
            if (
                campaign.state == "running"
                and campaign.named_session_liveness_verified
                and not in_window(campaign.started_at)
            ):
                pinned_campaign_ids.add(campaign.route_id)
                campaign_by_route.setdefault(campaign.route_id, campaign)
        campaigns = sorted(
            campaign_by_route.values(),
            key=lambda item: item.started_at,
            reverse=True,
        )
        campaign_scan_note = " ".join(campaign_notes)

        # Registration state is reconciled against its exact named tmux
        # session before this filter. Thus only a verified-live registration,
        # never an old nonterminal file by itself, may cross the date window.
        scanned_external_jobs, external_scan_note = self._external_measured_job_scan()
        external_jobs = [
            job
            for job in scanned_external_jobs
            if in_window(job.started_at) or job.state == "running"
        ]
        if scope == "standalone" or campaign_id:
            owners = self.db.workspace_member_owners(
                [("job", j.job_id) for j in history_jobs]
                + [("external", j.job_id) for j in external_jobs]
                + [("controller", c.route_id) for c in campaigns]
            )

            def selected(kind, key):
                owner = owners.get((kind, key), "")
                return owner == campaign_id if campaign_id else not owner

            history_jobs = [
                j
                for j in history_jobs
                if selected("job", j.job_id)
                and (campaign_id or j.command in {"run_matrix", "hosted_retained_execute"})
            ]
            external_jobs = [j for j in external_jobs if selected("external", j.job_id)]
            campaigns = [c for c in campaigns if campaign_id and selected("controller", c.route_id)]
            pinned_console_ids.intersection_update(j.job_id for j in history_jobs)
            pinned_campaign_ids.intersection_update(c.route_id for c in campaigns)
        technical_note = ""
        if scope == "work":
            from .job_presentation import substantive

            hidden = [j for j in history_jobs if not substantive(j.command, j.argv)]
            history_jobs = [j for j in history_jobs if substantive(j.command, j.argv)]
            indexed_work = self.db._query(
                "SELECT member_id FROM campaign_members WHERE member_kind='controller' "
                "AND role IN ('collection','judging','analysis')"
            )
            if indexed_work is None:
                raise ValueError(_ui_text("pages.campaign_work_index_unavailable"))
            work_ids = {r["member_id"] for r in indexed_work}
            hidden_controllers = [
                c for c in campaigns if not c.model_tasks and c.route_id not in work_ids
            ]
            campaigns = [c for c in campaigns if c.model_tasks or c.route_id in work_ids]
            pinned_console_ids.intersection_update(j.job_id for j in history_jobs)
            pinned_campaign_ids.intersection_update(c.route_id for c in campaigns)
            attention = sum(
                j.state() in {"failed", "interrupted", "orphaned", "running"} for j in hidden
            )
            attention += sum(
                c.state in {"failed", "interrupted", "orphaned", "running"}
                for c in hidden_controllers
            )
            technical_query = dict(filters, view="all")
            technical_note = (
                (
                    _ui_template(
                        "<p class='notice blue'>[[text:pages.collection_judging_and_analysis_are_shown_here]] "
                    )
                    + f"{len(hidden) + len(hidden_controllers)}"
                    + _ui_text("pages.technical_stages_in_this_window_are_listed_separately")
                    + f"{attention}"
                    + _ui_template(" [[text:pages.are_active_or_need_attention]] <a href='/jobs?")
                )
                + html.escape(urlencode(technical_query), quote=True)
                + _ui_template(
                    "'>[[text:pages.open_technical_jobs]]</a>.</p><style>#jobstable th:nth-child(2),#jobstable td:nth-child(2),#jobstable th:nth-child(4),#jobstable td:nth-child(4),#jobstable th:nth-child(9),#jobstable td:nth-child(9){display:none}</style>"
                )
            )
        pinned_external_ids = {
            job.job_id
            for job in external_jobs
            if job.state == "running" and not in_window(job.started_at)
        }
        pinned_live_count = (
            len(pinned_console_ids) + len(pinned_campaign_ids) + len(pinned_external_ids)
        )
        live_window_note = ""
        if pinned_live_count:
            live_window_note = (
                f"{pinned_live_count}"
                + _ui_text("pages.currently_live_row")
                + f"{(_ui_text('pages.remains') if pinned_live_count == 1 else _ui_text('pages.s_remain'))}"
                + _ui_text(
                    "pages.visible_although_its_start_time_is_outside_from_to_terminal_histo"
                )
            )
        if console_live_truncated:
            live_window_note += (
                _ui_text("pages.only_the_newest")
                + f"{_JOBS_HISTORY_DISPLAY_LIMIT}"
                + _ui_text("pages.out_of_window_live_console_jobs_are_shown")
            )
        rows = []
        row_started_at: list[float] = []
        tallies: dict[str, int] = {}
        for job in history_jobs:
            job_id = job.job_id
            state = job.state()
            state_tag = self._job_status_tag(state)
            tallies[state_tag] = tallies.get(state_tag, 0) + 1
            tone = {
                "running": "blue",
                "passed": "green",
                "failed": "red",
                "orphaned": "amber",
            }.get(state_tag, "gray")
            started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job.started_at))
            started_ms = int(job.started_at * 1000)
            stop = (
                (
                    "<form class='inline' method='post' action='/jobs/"
                    + f"{html.escape(job_id)}"
                    + _ui_template(
                        "/stop'><button class='danger small' type='submit'>[[text:pages.stop]]</button></form>"
                    )
                )
                if state == "running" and job.process is not None
                else ""
            )
            hay = html.escape(f"{job_id} {job.command}".lower())
            activity = (
                _ui_template(
                    "<span class='badge blue' title='[[attr:pages.explicit_job_activity_metadata]]'>[[text:pages.downloading]]</span>"
                )
                if state == "running" and getattr(job, "activity", None) == "model_download"
                else "-"
            )
            rows.append(
                f"<tr data-state='{html.escape(state_tag)}' "
                f"data-started='{started_ms}' data-hay='{hay}'"
                + (" data-live-window-pin='true'" if job_id in pinned_console_ids else "")
                + ">"
                f"<td><a href='/jobs/{html.escape(job_id)}'>"
                f"{html.escape(job_id)}</a></td>"
                f"<td>{html.escape(job.command)}</td>"
                f"<td>{html.escape(self._job_work_label(job))}</td>"
                f"<td>{html.escape(self._job_execution_label(job))}</td>"
                f"<td><span class='dot {tone}'></span>"
                f"<span class='badge {tone}'>{html.escape(_ui_label(state_tag))}</span></td>"
                f"<td><time class='job-started' data-epoch-ms='{started_ms}'>"
                f"{started}</time></td>"
                f"<td>{_human_duration(job.runtime_seconds())}</td>"
                f"<td>{activity}</td>"
                f"<td>{'' if job.exit_code() is None else job.exit_code()}"
                f"</td><td>{stop}</td></tr>"
            )
            row_started_at.append(job.started_at)
        for job in external_jobs:
            state_tag = self._job_status_tag(job.state)
            tallies[state_tag] = tallies.get(state_tag, 0) + 1
            tone = {
                "running": "blue",
                "passed": "green",
                "failed": "red",
                "orphaned": "amber",
            }.get(state_tag, "gray")
            started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job.started_at))
            started_ms = int(job.started_at * 1000)
            hay = html.escape(
                (
                    f"{job.job_id}"
                    + " "
                    + f"{job.command}"
                    + _ui_text("pages.external_measured")
                    + f"{' '.join(job.argv)}"
                ).lower()
            )
            output_link = (
                "<a href='/artifacts?path="
                + f"{quote(job.artifact_relative)}"
                + _ui_template("'>[[text:pages.exact_output]]</a>")
            )
            rows.append(
                f"<tr data-state='{html.escape(state_tag)}' "
                f"data-started='{started_ms}' data-hay='{hay}'"
                + (" data-live-window-pin='true'" if job.job_id in pinned_external_ids else "")
                + (
                    "><td><a href='/jobs/external/"
                    + f"{quote(job.job_id)}"
                    + "'>"
                    + f"{html.escape(job.job_id)}"
                    + _ui_template(
                        "</a></td><td>run_matrix <span class='badge blue'>[[text:pages.external_read_only]]</span></td><td>[[text:pages.model_campaign]]</td><td>[[text:pages.verify_artifacts]]</td><td><span class='dot "
                    )
                    + f"{tone}"
                    + "'></span><span class='badge "
                    + f"{tone}"
                    + "'>"
                    + f"{html.escape(_ui_label(state_tag))}"
                    + "</span></td><td><time class='job-started' data-epoch-ms='"
                    + f"{started_ms}"
                    + "'>"
                    + f"{started}"
                    + "</time></td><td>"
                    + f"{_human_duration(job.runtime_seconds())}"
                    + "</td><td>"
                    + f"{output_link}"
                    + _ui_template("[[text:pages.tmux]] <code>")
                    + f"{html.escape(job.tmux_session)}"
                    + "</code></td><td>"
                    + f"{('' if job.exit_code is None else job.exit_code)}"
                    + "</td><td></td></tr>"
                )
            )
            row_started_at.append(job.started_at)
        for campaign in campaigns:
            state = campaign.state
            state_tag = campaign.status_tag
            tallies[state_tag] = tallies.get(state_tag, 0) + 1
            tone = {
                "running": "blue",
                "passed": "green",
                "partial": "amber",
                "blocked": "red",
                "failed": "red",
                "orphaned": "amber",
            }.get(state_tag, "gray")
            started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(campaign.started_at))
            started_ms = int(campaign.started_at * 1000)
            route_id = quote(campaign.route_id)
            hay = html.escape(
                (
                    f"{campaign.campaign_id}"
                    + _ui_text("pages.engineering_campaign_external")
                    + f"{campaign.status_tag}"
                    + " "
                    + f"{campaign.progress}"
                ).lower()
            )
            work = _ui_text("pages.model_work_undeclared")
            if campaign.model_tasks is not None:
                roles = {role for _task, _status, role in campaign.task_outcomes}
                if campaign.model_execution_scope == "target_only_mixed_controller":
                    work = _ui_text("pages.target_capable_mixed_controller")
                elif campaign.model_tasks:
                    work = (
                        _ui_text("pages.model_support")
                        if "support" in roles
                        else _ui_text("pages.model_only")
                    )
                else:
                    work = _ui_text("pages.support_only")
                if "unplanned" in roles:
                    work += _ui_text("pages.unplanned")
            if campaign.model_execution_error:
                execution = _ui_text("pages.report_invalid")
            elif campaign.model_tasks == ():
                execution = _ui_text("pages.not_applicable_support_only")
            elif campaign.model_attempted_calls is None:
                execution = _ui_text("pages.not_reported")
            else:
                if campaign.model_execution_scope == "target_only_mixed_controller":
                    execution = (
                        f"{campaign.model_successful_generations}"
                        + "/"
                        + f"{campaign.model_attempted_calls}"
                        + _ui_text(
                            "pages.target_calls_returned_successfully_1_1_target_execution_controlle"
                        )
                    )
                else:
                    execution = (
                        f"{campaign.model_successful_generations}"
                        + "/"
                        + f"{campaign.model_attempted_calls}"
                        + _ui_text("pages.reported_successful")
                        + f"{campaign.model_execution_covered_tasks}"
                        + "/"
                        + f"{len(campaign.model_tasks or ())}"
                        + _ui_text("pages.model_tasks")
                    )
            rows.append(
                f"<tr data-state='{html.escape(state_tag)}' "
                f"data-started='{started_ms}' data-hay='{hay}'"
                + (
                    " data-live-window-pin='true'"
                    if campaign.route_id in pinned_campaign_ids
                    else ""
                )
                + (
                    "><td><a href='/jobs/campaign/"
                    + f"{route_id}"
                    + "'>"
                    + f"{html.escape(campaign.campaign_id)}"
                    + _ui_template(
                        "</a></td><td>[[text:pages.engineering_campaign]] <span class='badge gray'>[[text:pages.external]]</span></td><td>"
                    )
                    + f"{html.escape(work)}"
                    + "</td><td>"
                    + f"{html.escape(execution)}"
                    + "</td><td><span class='dot "
                    + f"{tone}"
                    + "'></span><span class='badge "
                    + f"{tone}"
                    + "'>"
                    + f"{html.escape(_ui_label(state_tag))}"
                    + "</span></td><td><time class='job-started' data-epoch-ms='"
                    + f"{started_ms}"
                    + "'>"
                    + f"{started}"
                    + "</time></td><td>"
                    + f"{_human_duration(campaign.runtime_seconds())}"
                    + "</td><td>"
                )
                + (
                    _ui_template(
                        "<span class='badge blue' title='[[attr:pages.explicit_task_kind_model_download_in_retained_task_log]]'>[[text:pages.downloading]]</span> "
                    )
                    if campaign.download_tasks
                    else ""
                )
                + (
                    f"{html.escape(campaign.progress)}"
                    + " <a href='/jobs/campaign/"
                    + f"{route_id}"
                    + _ui_template("'>[[text:pages.logs]]</a></td><td>-</td><td></td></tr>")
                )
            )
            row_started_at.append(campaign.started_at)
        rows = [
            row
            for _started, row in sorted(
                zip(row_started_at, rows, strict=True),
                key=lambda item: item[0],
                reverse=True,
            )
        ]
        chips = (
            (
                _ui_template(
                    "<div class='chips'><button type='button' class='chip on' data-state=''>[[text:pages.all]]<span class='chip-count'>"
                )
                + f"{len(history_jobs) + len(external_jobs) + len(campaigns)}"
                + "</span>)</button>"
            )
            + "".join(
                f"<button type='button' class='chip' data-state='{state}'>"
                f"{html.escape(_ui_label(state))} (<span class='chip-count'>{count}</span>)</button>"
                for state, count in sorted(tallies.items())
            )
            + "</div>"
        )
        controls = chips + _ui_template(
            "<div class='targetfilters job-date-filters'><div class='fieldcell'><label class='fieldlabel' for='job-from'>[[text:pages.from]]</label><input id='job-from' type='datetime-local' step='1'></div><div class='fieldcell'><label class='fieldlabel' for='job-to'>[[text:pages.to]]</label><input id='job-to' type='datetime-local' step='1'></div></div><p><input id='jobfilter' type='text' placeholder='[[attr:pages.type_to_filter_jobs]]' aria-label='[[attr:pages.filter_jobs]]'></p>"
        )
        table = (
            _ui_template(
                "<div class='card scroll'><table id='jobstable'><tr><th>[[text:pages.job]]</th><th>[[text:pages.command]]</th><th>[[text:pages.work]]</th><th>[[text:pages.execution]]</th><th>[[text:pages.state]]</th><th>[[text:pages.started]]</th><th>[[text:pages.runtime]]</th><th>[[text:pages.progress]]</th><th>[[text:pages.exit]]</th><th></th></tr>"
            )
            + "".join(rows)
            + "</table></div>"
            if rows
            else _ui_template(
                "<div class='card'><p class='note'>[[text:pages.no_jobs_are_retained_in_this_window_start_one_from_the]] <a href='/commands'>[[text:pages.run]]</a> [[text:pages.page]]</p></div>"
            )
        )
        script = (
            "<script>(function(){"
            "var state='';var box=document.getElementById('jobfilter');"
            "var fromBox=document.getElementById('job-from');"
            "var toBox=document.getElementById('job-to');"
            "var params=new URLSearchParams(window.location.search);"
            "var explicitFrom=params.has('from');var explicitTo=params.has('to');"
            "var needsServerWindow=(explicitFrom&&!params.has('from_ms'))||"
            "(explicitTo&&!params.has('to_ms'));"
            "if(box&&params.has('q')){box.value=params.get('q');}"
            "state=params.get('state')||'';"
            "function pad(value){return String(value).padStart(2,'0');}"
            "function localValue(ms){var date=new Date(ms);return "
            "date.getFullYear()+'-'+pad(date.getMonth()+1)+'-'+pad(date.getDate())+"
            "'T'+pad(date.getHours())+':'+pad(date.getMinutes())+':' +"
            "pad(date.getSeconds());}"
            "function localStamp(ms){return localValue(ms).replace('T',' ');}"
            "var now=Date.now();"
            "fromBox.value=explicitFrom?params.get('from'):localValue(now-7*86400000);"
            "toBox.value=explicitTo?params.get('to'):localValue(now);"
            "document.querySelectorAll('time.job-started[data-epoch-ms]').forEach("
            "function(out){var ms=Number(out.getAttribute('data-epoch-ms'));"
            "if(Number.isFinite(ms)){out.textContent=localStamp(ms);}});"
            "function lowerBound(box,fallback){var value=Date.parse(box.value);"
            "return Number.isFinite(value)?value:fallback;}"
            "function upperBound(box,fallback){var value=Date.parse(box.value);"
            "if(!Number.isFinite(value)){return fallback;}"
            "if(!box.value.includes('.')){value+=box.value.length===16?59999:999;}"
            "return value;}"
            "function syncFilters(){var url=new URL(window.location.href);"
            "var fromMs=lowerBound(fromBox,NaN);var toMs=upperBound(toBox,NaN);"
            "if(explicitFrom&&Number.isFinite(fromMs)){"
            "url.searchParams.set('from',fromBox.value);"
            "url.searchParams.set('from_ms',String(fromMs));}else{"
            "url.searchParams.delete('from');url.searchParams.delete('from_ms');}"
            "if(explicitTo&&Number.isFinite(toMs)){"
            "url.searchParams.set('to',toBox.value);"
            "url.searchParams.set('to_ms',String(toMs));}else{"
            "url.searchParams.delete('to');url.searchParams.delete('to_ms');}"
            "url.searchParams.set('state',state);"
            "url.searchParams.set('q',box?box.value:'');"
            "history.replaceState(null,'',url.pathname+url.search+url.hash);}"
            "function apply(){var q=box?box.value.toLowerCase():'';"
            "var from=lowerBound(fromBox,Number.NEGATIVE_INFINITY);"
            "var to=upperBound(toBox,Number.POSITIVE_INFINITY);"
            "var counts={all:0};var visible=0;"
            "document.querySelectorAll('#jobstable tr[data-state]')"
            ".forEach(function(r){"
            "var okState=!state||r.getAttribute('data-state')===state;"
            "var okText=(r.getAttribute('data-hay')||'').indexOf(q)>=0;"
            "var started=Number(r.getAttribute('data-started'));"
            "var livePinned=r.getAttribute('data-live-window-pin')==='true';"
            "var okDate=livePinned||(Number.isFinite(started)&&started>=from&&started<=to);"
            "var base=okText&&okDate;if(base){counts.all++;var key="
            "r.getAttribute('data-state')||'unknown';counts[key]=(counts[key]||0)+1;}"
            "var show=okState&&base;if(show){visible++;}"
            "r.style.display=show?'':'none';});"
            "document.querySelectorAll('.chip').forEach(function(c){"
            "var key=c.getAttribute('data-state')||'all';var count="
            "c.querySelector('.chip-count');if(count){count.textContent=counts[key]||0;}});"
            "var empty=document.getElementById('jobs-filter-empty');"
            "var table=document.getElementById('jobstable');"
            "if(empty){empty.hidden=!table||visible!==0;}}"
            "document.querySelectorAll('.chip').forEach(function(c){"
            "c.addEventListener('click',function(){"
            "state=this.getAttribute('data-state')||'';"
            "document.querySelectorAll('.chip').forEach(function(o){"
            "o.classList.remove('on');});this.classList.add('on');"
            "syncFilters();apply();});});"
            "var matchedState=false;document.querySelectorAll('.chip').forEach("
            "function(c){var selected=(c.getAttribute('data-state')||'')===state;"
            "c.classList.toggle('on',selected);matchedState=matchedState||selected;});"
            "if(!matchedState){state='';var all=document.querySelector("
            "'.chip[data-state=\"\"]');if(all){all.classList.add('on');}}"
            "if(box){box.addEventListener('input',function(){syncFilters();apply();});}"
            "fromBox.addEventListener('change',function(){explicitFrom=true;"
            "syncFilters();window.uraBusy.reload();});"
            "toBox.addEventListener('change',function(){explicitTo=true;"
            "syncFilters();window.uraBusy.reload();});"
            "syncFilters();if(needsServerWindow){window.uraBusy.reload();return;}apply();"
            "})();</script>"
        )
        refresh = (
            "<script>setTimeout(function(){window.uraBusy.reload();}, 5000);</script>"
            if tallies.get("running", 0)
            else ""
        )
        attention_count = sum(
            tallies.get(state, 0)
            for state in (
                "failed",
                "blocked",
                "stopped",
                "partial",
                "orphaned",
                "unknown",
            )
        )
        overview_items = (
            (
                _ui_text("pages.window_verified_live")
                if pinned_live_count
                else _ui_text("pages.all_in_current_window"),
                len(history_jobs) + len(external_jobs) + len(campaigns),
                "",
            ),
            (_ui_text("pages.console_jobs"), len(history_jobs), None),
            (_ui_text("pages.external_measured_jobs"), len(external_jobs), None),
            (_ui_text("pages.external_campaigns"), len(campaigns), None),
            (_ui_text("pages.running_2"), tallies.get("running", 0), "running"),
            (_ui_text("pages.needs_attention"), attention_count, None),
            (_ui_text("pages.passed"), tallies.get("passed", 0), "passed"),
        )
        overview_cards_parts = []
        for label, count, state in overview_items:
            content = (
                "<div class='stat'>"
                f"<span class='value'>{count}</span>"
                f"<span class='label'>{html.escape(label)}</span></div>"
            )
            if state is None:
                overview_cards_parts.append("<div class='card'>" + content + "</div>")
            else:
                card_query = {
                    k: v
                    for k, v in filters.items()
                    if k in {"view", "campaign_id", "from", "to", "from_ms", "to_ms", "q"}
                }
                if state:
                    card_query["state"] = state
                overview_cards_parts.append(
                    "<a class='card' href='/jobs"
                    + ("?" + html.escape(urlencode(card_query), quote=True) if card_query else "")
                    + "#jobs-history'>"
                    + content
                    + "</a>"
                )
        overview_cards = "".join(overview_cards_parts)
        overview_panel = (
            "<div class='cols tab-summary'>"
            + overview_cards
            + _ui_template(
                "</div><div class='card'><h2>[[text:pages.job_sources]]</h2><p class='note'>[[text:pages.console_jobs_are_owned_by_this_process_registered_external_measur]]</p></div>"
            )
        )
        history_panel = (
            controls
            + table
            + _ui_template(
                "<p id='jobs-filter-empty' class='notice amber' hidden>[[text:pages.no_jobs_match_the_selected_dates_state_and_text]]</p>"
            )
            + script
        )
        jobs_tabs = (
            ("jobs-overview", _ui_text("pages.overview")),
            ("jobs-history", _ui_text("pages.history")),
        )
        explicit_filter = any(
            str(filters.get(name, "")).strip()
            for name in ("from", "to", "from_ms", "to_ms", "state", "q")
        )
        jobs_default = "jobs-history" if explicit_filter or scope == "work" else "jobs-overview"
        force_default = " data-force-default='true'" if explicit_filter else ""
        return _page(
            _ui_text("pages.jobs"),
            "<h1>"
            + _icon("pulse", size=22)
            + _ui_template("[[text:pages.jobs]]</h1>")
            + self._work_view_tabs("jobs", "campaigns" if campaign_id else scope)
            + (self._campaign_banner(campaign_id) if campaign_id else "")
            + technical_note
            + (
                _ui_template(
                    "<p>[[text:pages.standalone_runs_exclude_campaign_owned_jobs_and_administrative_to]]</p>"
                )
                if scope == "standalone"
                else ""
            )
            + self._health_banner()
            + (
                "<div class='notice amber'>" + html.escape(campaign_scan_note) + "</div>"
                if campaign_scan_note
                else ""
            )
            + (
                "<div class='notice amber'>" + html.escape(external_scan_note) + "</div>"
                if external_scan_note
                else ""
            )
            + (
                "<div class='notice amber'>" + html.escape(history_note) + "</div>"
                if history_note
                else ""
            )
            + (
                "<div class='notice blue'>" + html.escape(live_window_note) + "</div>"
                if live_window_note
                else ""
            )
            + "<div class='page-tabs' data-page-tabs data-tab-key='jobs' "
            f"data-default-tab='{jobs_default}'{force_default}>"
            + _page_tablist(_ui_text("pages.job_sections"), jobs_tabs, default=jobs_default)
            + _page_tabpanel("jobs-overview", overview_panel)
            + _page_tabpanel("jobs-history", history_panel)
            + "</div>"
            + refresh,
            active=_ui_text("pages.jobs"),
        )

    def _campaign_page(self, campaign: EngineeringCampaign) -> bytes:
        tone = {
            "running": "blue",
            "passed": "green",
            "partial": "amber",
            "blocked": "red",
            "failed": "red",
            "orphaned": "amber",
        }.get(campaign.status_tag, "gray")
        route_id = quote(campaign.route_id)
        relative = f"engineering/{campaign.route_id}"
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(campaign.started_at))
        call_cap = "-" if campaign.target_call_cap is None else str(campaign.target_call_cap)
        hard_stop = (
            "-"
            if campaign.hard_stop_hours is None
            else (f"{campaign.hard_stop_hours:g}" + _ui_text("pages.hours"))
        )
        declaration_label = (
            _ui_text("pages.target_capable_mixed_controller_2")
            if campaign.model_execution_scope == "target_only_mixed_controller"
            else _ui_text("pages.declared_model_tasks")
        )
        details = (
            (
                _ui_template(
                    "<div class='card scroll'><table><tr><td>[[text:pages.release_commit]]</td><td><code>"
                )
                + f"{html.escape(campaign.release_commit)}"
                + _ui_template("</code></td></tr><tr><td>[[text:pages.evidence_class]]</td><td>")
                + f"{html.escape(campaign.evidence_class)}"
                + _ui_template(
                    "</td></tr><tr><td>[[text:pages.thesis_empirical_evidence]]</td><td>[[text:pages.no]]</td></tr><tr><td>[[text:pages.hosted_calls_allowed]]</td><td>"
                )
                + f"{html.escape(_ui_text('pages.yes') if campaign.hosted_calls_allowed else _ui_text('pages.no'))}"
                + _ui_template(
                    "</td></tr><tr><td>[[text:pages.reserved_call_budget_not_execution]]</td><td>"
                )
                + f"{campaign.reserved_calls}"
                + "/"
                + f"{call_cap}"
                + "</td></tr><tr><td>"
                + f"{declaration_label}"
                + "</td><td>"
            )
            + (
                _ui_text("pages.invalid") + html.escape(campaign.model_declaration_error)
                if campaign.model_declaration_error
                else _ui_text("pages.not_declared")
                if campaign.model_tasks is None
                else _ui_text("pages.support_only")
                if campaign.model_tasks == ()
                else str(len(campaign.model_tasks))
            )
            + "</td></tr>"
            + (
                _ui_template("<tr><td>[[text:pages.reported_target_execution]]</td><td>")
                if campaign.model_execution_scope == "target_only_mixed_controller"
                else _ui_template("<tr><td>[[text:pages.reported_model_execution]]</td><td>")
            )
            + (
                _ui_text("pages.report_invalid_2") + html.escape(campaign.model_execution_error)
                if campaign.model_execution_error
                else _ui_text("pages.not_applicable_support_only")
                if campaign.model_tasks == ()
                else _ui_text("pages.not_reported")
                if campaign.model_attempted_calls is None
                else (
                    (
                        f"{campaign.model_successful_generations}"
                        + _ui_text("pages.successful_target_generation_s")
                        + f"{campaign.model_attempted_calls}"
                        + _ui_text(
                            "pages.target_attempt_s_1_1_target_execution_controller_reported"
                        )
                    )
                    if campaign.model_execution_scope == "target_only_mixed_controller"
                    else (
                        f"{campaign.model_successful_generations}"
                        + _ui_text("pages.successful_generation_s")
                        + f"{campaign.model_attempted_calls}"
                        + _ui_text("pages.attempt_s")
                        + f"{campaign.model_execution_covered_tasks}"
                        + "/"
                        + f"{len(campaign.model_tasks or ())}"
                        + _ui_text("pages.model_tasks_reported")
                    )
                )
            )
            + (
                _ui_template("</td></tr><tr><td>[[text:pages.hard_stop]]</td><td>")
                + f"{hard_stop}"
                + "</td></tr></table></div>"
            )
        )
        task_rows = "".join(
            "<tr><td><code>"
            + html.escape(task)
            + "</code>"
            + (
                _ui_template(
                    " <span class='badge blue' title='[[attr:pages.explicit_task_kind_model_download_in_retained_task_log]]'>[[text:pages.downloading]]</span>"
                )
                if task in campaign.download_tasks
                else ""
            )
            + "</td><td>"
            + html.escape(role)
            + "</td><td>"
            + html.escape(status)
            + "</td></tr>"
            for task, status, role in campaign.task_outcomes
        )
        accounting_note = (
            _ui_text("pages.reported_target_call_counts_omit_guard_defense_attacker_and_frame")
            if campaign.model_execution_scope == "target_only_mixed_controller"
            else _ui_text("pages.reported_call_counts_remain_operational_self_reports_validated_re")
        )
        task_table = (
            _ui_template(
                "<div class='card'><h2>[[text:pages.task_outcomes]]</h2><p class='note'>[[text:pages.a_passed_support_task_proves_only_that_its_command_exited_success]] "
            )
            + accounting_note
            + _ui_template(
                "</p><div class='scroll'><table><tr><th>[[text:pages.task]]</th><th>[[text:pages.work]]</th><th>[[text:pages.result]]</th></tr>"
            )
            + task_rows
            + "</table></div></div>"
            if task_rows
            else ""
        )
        log_links = "".join(
            "<li>"
            f"<a href='/jobs/campaign/{route_id}/log?stream={quote(key)}'>"
            f"{html.escape(label)}</a></li>"
            for key, label, _path in campaign.logs
        )
        logs = (
            "<div class='card'><h2>"
            + _icon("pulse")
            + _ui_template("[[text:pages.task_logs]]</h2>")
            + (
                f"<ul>{log_links}</ul>"
                if log_links
                else _ui_template("<p class='note'>[[text:pages.no_task_logs_yet]]</p>")
            )
            + (
                "<p><a href='/artifacts?path="
                + f"{quote(relative)}"
                + _ui_template("'>[[text:pages.browse_all_retained_campaign_files]]</a></p></div>")
            )
        )
        artifact_links = "".join(
            "<li><a href='/artifacts?path="
            + quote(relative)
            + "'>"
            + html.escape(label)
            + "</a></li>"
            for label, relative in campaign.artifact_links
        )
        related_artifacts = (
            _ui_template("<div class='card'><h2>[[text:pages.related_retained_artifacts]]</h2>")
            + (
                f"<div class='notice red'>{html.escape(campaign.artifact_link_error)}</div>"
                if campaign.artifact_link_error
                else f"<ul>{artifact_links}</ul>"
            )
            + "</div>"
            if campaign.artifact_links or campaign.artifact_link_error
            else ""
        )
        last_detail = (
            "<div class='card'><h2>"
            + _icon("terminal")
            + (
                _ui_template("[[text:pages.latest_activity]]</h2><pre>")
                + f"{html.escape(campaign.last_detail)}"
                + "</pre></div>"
            )
            if campaign.last_detail
            else ""
        )
        refresh = (
            "<script>setTimeout(function(){window.uraBusy.reload();}, 5000);</script>"
            if campaign.state == "running"
            else ""
        )
        body = (
            "<h1>"
            + _icon("pulse", size=22)
            + (
                _ui_text("pages.campaign")
                + f"{html.escape(campaign.campaign_id)}"
                + _ui_template(
                    "</h1><div class='notice amber'><strong>[[text:pages.externally_managed_engineering_work]]</strong> [[text:pages.this_console_observes_its_retained_files_read_only_process_owners]]</div><div class='cols'><div class='card'><div class='stat'><span class='value'><span class='dot "
                )
                + f"{tone}"
                + "'></span>"
                + f"{html.escape(campaign.status_tag)}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.campaign_status]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
                )
                + f"{_human_duration(campaign.runtime_seconds())}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.runtime_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
                )
                + f"{started}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.started_2]]</span></div></div></div><div class='card'><h2>"
                )
            )
            + _icon("chart")
            + _ui_template("[[text:pages.progress]]</h2>")
            + (
                _ui_template(
                    "<p><span class='badge blue' title='[[attr:pages.explicit_task_kind_model_download_in_retained_task_log]]'>[[text:pages.downloading]]</span></p>"
                )
                if campaign.download_tasks
                else ""
            )
            + f"<p>{html.escape(campaign.progress)}</p>"
            + (
                f"<p class='fieldhint'>{html.escape(campaign.state_detail)}</p>"
                if campaign.state_detail
                else ""
            )
            + "</div>"
            + details
            + task_table
            + last_detail
            + related_artifacts
            + logs
            + refresh
        )
        return _page(
            (_ui_text("pages.campaign") + f"{campaign.campaign_id}"),
            body,
            active=_ui_text("pages.jobs"),
        )

    def _external_measured_job_page(self, job: ExternalMeasuredJob) -> bytes:
        state_tag = self._job_status_tag(job.state)
        tone = {
            "running": "blue",
            "passed": "green",
            "failed": "red",
            "orphaned": "amber",
        }.get(state_tag, "gray")
        started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job.started_at))
        ended = (
            time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(job.ended_at))
            if job.ended_at is not None
            else _ui_text("pages.not_recorded")
        )
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in job.argv)
            + "</div>"
        )
        attach = f"tmux -L {job.tmux_socket} attach -t {job.tmux_session}"
        body = (
            (
                "<h1>"
                + f"{_icon('terminal', size=22)}"
                + _ui_text("pages.job_2")
                + f"{html.escape(job.job_id)}"
                + _ui_template(
                    "</h1><div class='notice blue'><strong>[[text:pages.externally_owned_read_only_measured_job]]</strong><p class='note'>[[text:pages.the_campaign_controller_owns_this_tmux_process_rig_web_reads_its]]</p></div><div class='cols'><div class='card'><div class='stat'><span class='value'><span class='dot "
                )
                + f"{tone}"
                + "'></span>"
                + f"{html.escape(_ui_label(state_tag))}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.state_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
                )
                + f"{_human_duration(job.runtime_seconds())}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.runtime_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
                )
                + f"{html.escape(started)}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.started_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
                )
                + f"{html.escape(ended)}"
                + _ui_template(
                    "</span><span class='label'>[[text:pages.ended]]</span></div></div></div><div class='card'><h2>[[text:pages.operational_identity]]</h2><div class='scroll'><table><tr><td>[[text:pages.command_kind]]</td><td><code>"
                )
                + f"{html.escape(job.command)}"
                + "</code> / "
                + f"{html.escape(job.run_kind)}"
                + _ui_template("</td></tr><tr><td>[[text:pages.expected_commit]]</td><td><code>")
                + f"{html.escape(job.expected_commit)}"
                + _ui_template(
                    "</code></td></tr><tr><td>[[text:pages.framework_lock]]</td><td><code>"
                )
                + f"{html.escape(job.framework_lock_id)}"
                + _ui_template(
                    "</code></td></tr><tr><td>[[text:pages.admission_digest]]</td><td><code>"
                )
                + f"{html.escape(job.admission_sha256)}"
                + _ui_template(
                    "</code></td></tr><tr><td>[[text:pages.argument_digest]]</td><td><code>"
                )
                + f"{html.escape(job.argv_sha256)}"
                + _ui_template("</code></td></tr><tr><td>[[text:pages.tmux_2]]</td><td><code>")
                + f"{html.escape(attach)}"
                + _ui_template(
                    "</code></td></tr></table></div></div><div class='card'><h2>[[text:pages.sanitized_exact_argument_vector]]</h2>"
                )
            )
            + argv_chips
            + "<p><a href='/artifacts?path="
            + quote(job.artifact_relative)
            + _ui_template("'>[[text:pages.browse_exact_output_artifacts]]</a></p></div>")
            + (
                "<script>setTimeout(function(){window.uraBusy.reload();}, 5000);</script>"
                if job.state == "running"
                else ""
            )
        )
        return _page(
            (_ui_text("pages.job_2") + f"{job.job_id}"), body, active=_ui_text("pages.jobs")
        )

    def _collection_continuation_action(self, job: Job) -> str:
        if job.command != "hosted_campaign_execute" or job.state() not in {
            "complete",
            "failed",
            "interrupted",
            "stopped",
        }:
            return ""
        command = self.commands[job.command]
        try:
            argv = job.argv[job.argv.index(command.module) + 1 :]
        except ValueError:
            return ""
        allowed = {param.flag: param for param in command.params}
        values, counts, index = {}, {}, 0
        while index < len(argv):
            flag = argv[index]
            param = allowed.get(flag)
            if param is None or (param.kind != "flag" and index + 1 == len(argv)):
                return ""
            ordinal = counts.get(flag, 0)
            if ordinal and not param.repeat:
                return ""
            key = flag + ("#" + str(ordinal) if ordinal else "")
            values[key] = "on" if param.kind == "flag" else argv[index + 1]
            counts[flag] = ordinal + 1
            index += 1 if param.kind == "flag" else 2
        if not values.get("--out"):
            return ""
        values["--resume-from"] = values["--out"]
        values["--out"] = str(Path(values["--out"]).parent / uuid4().hex)
        values.update(cmd=job.command, campaign_id=self.db.workspace_for_job(job.job_id))
        href = "/commands?" + urlencode(values)
        return (
            _ui_template(
                "<section class='card'><h2>[[text:pages.continue_collection]]</h2><p>[[text:pages.keep_the_saved_model_programs_inputs_budget_and_campaign_complete]]</p><p><a class='button' href='"
            )
            + html.escape(href, quote=True)
            + _ui_template(
                "'>[[text:pages.review_continuation]]</a></p><p class='note'>[[text:pages.a_fresh_output_directory_is_filled_in_for_the_continuation_record]]</p></section>"
            )
        )

    def _job_page(self, job: Job) -> bytes:
        state = job.state()
        tone = {
            "running": "blue",
            "complete": "green",
            "failed": "red",
            "interrupted": "amber",
            "stopped": "amber",
        }.get(state, "gray")
        state_tag = self._job_status_tag(state)
        stdout_tail = self._log_tail(job, "stdout") or "(empty)"
        stderr_tail = self._log_tail(job, "stderr") or "(empty)"
        nested_failure = ""
        if state == "failed" and job.command == "hosted_campaign_execute" and "--out" in job.argv:
            from experiments.hosted_program_runtime import retained_planning_failure

            nested_failure = retained_planning_failure(
                Path(job.argv[job.argv.index("--out") + 1]), self.results_root
            )
        stop_form = (
            (
                "<form class='action-row' method='post' action='/jobs/"
                + f"{html.escape(job.job_id)}"
                + _ui_template(
                    "/stop'><button class='danger' type='submit'>[[text:pages.stop_job]]</button></form>"
                )
            )
            if state == "running" and job.process is not None
            else ""
        )
        refresh = (
            "<script>setTimeout(function(){window.uraBusy.reload();}, 2000);</script>"
            if state == "running"
            else ""
        )
        failure = (
            "<div class='card'><h2>"
            + _icon("pulse")
            + (
                _ui_template(
                    "[[text:pages.failure]]</h2><p>[[text:pages.the_command_exited_with_code]] "
                )
                + f"{job.exit_code()}"
                + _ui_template("[[text:pages.retained_error_details_are_shown_below]]</p>")
            )
            + (f"<pre>{html.escape(job.failure)}</pre>" if job.failure else "")
            + (
                _ui_template("<h3>[[text:pages.runtime_preparation_error]]</h3><pre>")
                + html.escape(nested_failure)
                + "</pre>"
                if nested_failure
                else ""
            )
            + (
                f"<pre>{html.escape(stderr_tail)}</pre>"
                if not nested_failure and stderr_tail != "(empty)"
                else ""
            )
            + "</div>"
            if state == "failed"
            else ""
        )
        if state in {"interrupted", "stopped"}:
            failure = (
                _ui_template("<div class='notice amber'><strong>[[text:pages.execution]] ")
                + state
                + ".</strong><p>"
                + html.escape(
                    job.failure
                    or _ui_text(
                        "pages.no_terminal_process_record_is_available_saved_outputs_remain_avai"
                    )
                )
                + "</p></div>"
            )
        try:
            publication = json.loads((job.directory / "campaign-publication.json").read_text())
            if publication.get("status") == "publication_pending":
                failure += (
                    _ui_template(
                        '<div class="notice amber"><strong>[[text:pages.campaign_results_publication_needs_attention]]</strong><p>'
                    )
                    + html.escape(
                        publication.get(
                            "reason", _ui_text("pages.saved_records_are_not_yet_indexed")
                        )
                    )
                    + _ui_template(
                        " [[text:pages.saved_generation_artifacts_remain_available_do_not_regenerate_ans]]</p></div>"
                    )
                )
        except (OSError, ValueError):
            pass
        activity = (
            _ui_template(
                "<div class='notice blue'><strong>[[text:pages.model_download_in_progress]]</strong> [[text:pages.this_indicator_comes_from_explicit_job_activity_metadata_and_is_s]]</div>"
            )
            if state == "running" and getattr(job, "activity", None) == "model_download"
            else ""
        )
        model_acquisition_actions = self._model_acquisition_job_actions(job)
        builder = ""
        if job.builder_params:
            rows = "".join(
                f"<tr><td>{html.escape(key)}</td><td><code>{html.escape(value)}</code></td></tr>"
                for key, value in sorted(job.builder_params.items())
            )
            reopen = "".join(
                f"<input type='hidden' name='{html.escape(key)}' value='{html.escape(value)}'>"
                for key, value in sorted(job.builder_params.items())
            )
            builder = (
                "<div class='card'><h2>"
                + _icon("flask")
                + _ui_template("[[text:pages.builder_parameters]]</h2><div class='scroll'><table>")
                + rows
                + _ui_template(
                    "</table></div><p class='note'>[[text:pages.the_durable_campaign_builder_selections_retained_with_this_job_ex]]</p><form method='post' action='/build'>"
                )
                + reopen
                + _ui_template(
                    "<button type='submit' class='ghost'>[[text:pages.review_this_exact_lane_in_the_builder]]</button></form></div>"
                )
            )
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in job.argv)
            + "</div>"
        )
        retained_links: list[str] = []
        for flag in (
            "--out",
            "--output",
            "--out-json",
            "--out-csv",
            "--out-md",
            "--artifact-out",
            "--attacker-config-out",
        ):
            if flag not in job.argv:
                continue
            index = job.argv.index(flag)
            if index + 1 >= len(job.argv):
                continue
            candidate = Path(job.argv[index + 1]).expanduser()
            if not candidate.is_absolute():
                candidate = self.repo_root / candidate
            try:
                resolved = candidate.resolve(strict=True)
                relative = resolved.relative_to(self.results_root.resolve()).as_posix()
            except (OSError, ValueError):
                continue
            retained_links.append(
                f"<a href='/artifacts?path={quote(relative)}'>"
                f"{html.escape(flag)}: {html.escape(relative)}</a>"
            )
        retained = (
            _ui_template("<p class='note'>[[text:pages.retained_output]] ")
            + " - ".join(retained_links)
            + "</p>"
            if retained_links
            else ""
        )
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.started_at))
        exit_code = job.exit_code()
        meta = (
            "<div class='cols'><div class='card'><div class='stat'><span class='value'><span class='dot "
            + f"{tone}"
            + "'></span>"
            + f"{html.escape(_ui_label(state_tag))}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.state_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
            )
            + f"{job.runtime_seconds():,.0f}"
            + _ui_template(
                "[[text:pages.s]]</span><span class='label'>[[text:pages.runtime_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
            )
            + f"{started}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.started_2]]</span></div></div><div class='card'><div class='stat'><span class='value'>"
            )
            + f"{('-' if exit_code is None else exit_code)}"
            + _ui_template(
                "</span><span class='label'>[[text:pages.exit_code]]</span></div></div></div>"
            )
        )
        stop_failure = (
            _ui_template(
                "<div class='notice red'><strong>[[text:pages.stop_could_not_be_confirmed]]</strong><p class='note'>"
            )
            + html.escape(job.stop_error)
            + _ui_template(
                " [[text:pages.check_the_rig_for_a_surviving_process_and_terminate_it_manually_t]]</p></div>"
            )
            if job.stop_error
            else ""
        )
        body = (
            (
                "<h1>"
                + f"{_icon('terminal', size=22)}"
                + _ui_text("pages.job_2")
                + f"{html.escape(job.job_id)}"
                + "</h1>"
            )
            + self._campaign_banner(self.db.workspace_for_job(job.job_id))
            + meta
            + activity
            + self._collection_continuation_action(job)
            + model_acquisition_actions
            + stop_failure
            + "<div class='card'><h2>"
            + _icon("file")
            + _ui_template("[[text:pages.durable_command_identity]]</h2>")
            + argv_chips
            + retained
            + stop_form
            + "</div>"
            + builder
            + failure
            + "<div class='card'><h2>"
            + _icon("chart")
            + (
                _ui_template("[[text:pages.stdout]]</h2><pre>")
                + f"{html.escape(stdout_tail)}"
                + "</pre></div><div class='card'><h2>"
            )
            + _icon("pulse")
            + (
                _ui_template("[[text:pages.stderr]]</h2><pre>")
                + f"{html.escape(stderr_tail)}"
                + "</pre></div>"
            )
            + refresh
        )
        return _page(
            (_ui_text("pages.job_2") + f"{job.job_id}"), body, active=_ui_text("pages.jobs")
        )

    # -- artifact browsing -------------------------------------------------

    def _artifacts(self, relative: str) -> tuple[int, str, bytes]:
        target = _contained(self.results_root, relative)
        if target.is_dir():
            return 200, "text/html; charset=utf-8", self._directory_page(target, relative)
        if not target.is_file():
            return (
                404,
                "text/plain; charset=utf-8",
                _ui_text("pages.no_such_artifact").encode("utf-8"),
            )
        return self._file_page(target, relative)

    def _directory_page(self, directory: Path, relative: str) -> bytes:
        entries = sorted(directory.iterdir(), key=lambda item: (item.is_file(), item.name))
        rows = []
        for entry in entries:
            child = f"{relative}/{entry.name}".lstrip("/")
            is_dir = entry.is_dir()
            icon = _icon("folder", size=15) if is_dir else _icon("file", size=15)
            size = "" if is_dir else _human_size(entry.stat().st_size)
            rows.append(
                f"<tr><td>{icon}<a href='/artifacts?path={quote(child)}'>"
                f"{html.escape(entry.name)}{'/' if is_dir else ''}</a></td>"
                f"<td>{size}</td></tr>"
            )
        listing = (
            _ui_template(
                "<div class='card scroll'><table class='filelist'><tr><th>[[text:pages.name]]</th><th>[[text:pages.size]]</th></tr>"
            )
            + "".join(rows)
            + "</table></div>"
            if rows
            else _ui_template(
                "<div class='card'><p class='note'>[[text:pages.empty_directory]]</p></div>"
            )
        )
        body = (
            "<h1>"
            + _icon("folder", size=22)
            + _ui_template("[[text:pages.artifacts]]</h1>")
            + _crumbs(relative)
            + listing
        )
        return _page(_ui_text("pages.artifacts"), body, active=_ui_text("pages.artifacts"))

    def _file_page(self, target: Path, relative: str) -> tuple[int, str, bytes]:
        suffix = target.suffix.lower()
        if suffix == ".png":
            return 200, "image/png", target.read_bytes()
        if target.stat().st_size > _MAX_RENDER_BYTES:
            return (
                200,
                "text/html; charset=utf-8",
                _page(
                    _ui_text("pages.artifact"),
                    "<h1>"
                    + _icon("file", size=22)
                    + f"{html.escape(relative)}</h1>"
                    + _crumbs(relative)
                    + _ui_template(
                        "<div class='card'><p>[[text:pages.file_exceeds_the_inline_render_limit_inspect_it_on_disk]]</p></div>"
                    ),
                ),
            )
        text = target.read_text(encoding="utf-8", errors="replace")
        badges_html = ""
        if suffix == ".json":
            try:
                document = strict_json_loads(text)
                badges_html = _badges_html(evidence_badges(document))
                text = json.dumps(document, indent=2, sort_keys=True)
            except ValueError:
                pass
            rendered = f"<pre>{html.escape(text)}</pre>"
        elif suffix == ".csv":
            reader = csv.reader(io.StringIO(text))
            rows = []
            for index, row in enumerate(reader):
                if index > _CSV_PREVIEW_ROWS:
                    rows.append(
                        _ui_template(
                            "<tr><td colspan='99'>[[text:pages.truncated_preview]]</td></tr>"
                        )
                    )
                    break
                tag = "th" if index == 0 else "td"
                rows.append(
                    "<tr>"
                    + "".join(f"<{tag}>{html.escape(cell)}</{tag}>" for cell in row)
                    + "</tr>"
                )
            rendered = "<div class='card scroll'><table>" + "".join(rows) + "</table></div>"
        else:
            rendered = f"<pre>{html.escape(text)}</pre>"
        body = (
            "<h1>"
            + _icon("file", size=22)
            + f"{html.escape(target.name)}</h1>"
            + _crumbs(relative)
            + (f"<p>{badges_html}</p>" if badges_html else "")
            + rendered
        )
        return (
            200,
            "text/html; charset=utf-8",
            _page(relative, body, active=_ui_text("pages.artifacts")),
        )
