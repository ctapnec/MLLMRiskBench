"""Overview, command, job, and artifact pages."""

from __future__ import annotations

import csv
import html
import io
import json
import math
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Mapping
from urllib.parse import quote

from ura.strict_json import strict_json_loads

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

from .artifacts import _PIPELINE_STAGES, artifact_inventory, _pipeline_svg, Job, run_kind
from .campaigns import EngineeringCampaign


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
            return "acquisition plan"
        if kind == "preflight":
            return "preflight"
        if kind == "dry_run":
            return "offline dry run"
        if kind == "attestation_probe":
            return "model probe"
        if kind == "diagnostic_canary":
            return "diagnostic model run"
        if kind == "measured":
            return "model campaign"
        if job.command == "model_acquire":
            return "model acquisition"
        if job.command == "capture_t3mp3st":
            return "model capture"
        if job.command == "harmbench_capture":
            return "preparation"
        return "tool / validation"

    @staticmethod
    def _job_execution_label(job: Job) -> str:
        kind = run_kind(job.command, job.argv)
        if kind in {"acquisition_plan", "preflight", "dry_run"}:
            return "no model call"
        if job.command == "model_acquire":
            return "no model call"
        if job.command == "harmbench_capture":
            methods = [
                job.argv[index + 1]
                for index, value in enumerate(job.argv[:-1])
                if value == "--method"
            ]
            if methods and all(method.casefold() == "directrequest" for method in methods):
                return "no model call"
            return "verify capture artifact"
        if kind in {"attestation_probe", "diagnostic_canary", "measured"}:
            return "verify artifacts"
        if job.command == "capture_t3mp3st":
            return "verify capture artifact"
        return "not applicable"

    @staticmethod
    def _playbook_card() -> str:
        steps = (
            (
                "1",
                "Author revision receipt",
                "project_revision",
                {
                    "--expected-revision": "&lt;40-hex pin&gt;",
                    "--out": "runs/thesis/project-revision",
                },
            ),
            (
                "2",
                "Preflight (no calls)",
                "rig_check",
                {"--dry-run": "on", "--api": "$FABLE", "--corpora": "synth"},
            ),
            (
                "3",
                "Attestation probe (paid)",
                "run_matrix",
                {"--attestation-probe": "on", "--api": "$FABLE", "--out": "runs/thesis/attest"},
            ),
            (
                "4",
                "Diagnostic canary (paid)",
                "run_matrix",
                {
                    "--diagnostic-canary": "on",
                    "--api": "$FABLE",
                    "--corpora": "strongreject_official",
                    "--sample-seed": "0",
                    "--out": "runs/thesis/canary",
                },
            ),
            (
                "5",
                "Measured lane (paid)",
                "run_matrix",
                {
                    "--api": "$FABLE,$SOL",
                    "--corpora": "strongreject_official",
                    "--attackers": "replay,crescendo",
                    "--judges": "rules,llm",
                    "--judge-model": "anthropic:claude-haiku-4-5-20251001",
                    "--limit": "&lt;set from canary&gt;",
                    "--sample-seed": "0",
                    "--out": "runs/thesis/measured",
                },
            ),
        )
        rows = []
        for num, title, command, values in steps:
            params = "&".join(
                f"{quote(flag)}={quote(str(val).replace('&lt;', '<').replace('&gt;', '>'))}"
                for flag, val in values.items()
            )
            rows.append(
                "<li><span class='step-n'>" + num + "</span>"
                f"<strong>{html.escape(title)}</strong> "
                f"<code>{html.escape(command)}</code> "
                f"<a href='/commands?cmd={quote(command)}&{params}'>"
                "prefill &rarr;</a></li>"
            )
        return (
            "<div class='card'><h2>" + _icon("book") + "Campaign playbook</h2>"
            "<p class='note'>The runbook sequence in order. 'Prefill' opens the "
            "Run page with that command's form filled - review every value "
            "before starting. Steps 3+ spend real money.</p>"
            "<ol class='playbook'>" + "".join(rows) + "</ol></div>"
        )

    def _db_card(self, reindexed: str) -> str:
        """Database health, schema version, and the one Reindex action."""

        health = self.db.health()
        tone = "green" if health["healthy"] else "red"
        state = "healthy" if health["healthy"] else "UNAVAILABLE"
        counts = health["counts"]
        count_text = (
            ", ".join(
                f"{name}: {value if value is not None else 'unknown'}"
                for name, value in counts.items()
            )
            if counts
            else "counts unknown"
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
                    + "'><strong>Reindex "
                    + ("completed" if summary.get("ok") else "FAILED")
                    + ".</strong><p class='note'>Derived usage, cost, and "
                    "report indexes were rebuilt from retained artifacts "
                    "with full digest verification ("
                    + ", ".join(stat_bits)
                    + "). Skip counts are reported, never silent.</p></div>"
                )
        error = (
            f"<p class='note'>Last error: <code>{html.escape(health['last_error'])}</code></p>"
            if health["last_error"]
            else ""
        )
        return (
            "<div class='card'><h2>"
            + _icon("disk")
            + "Console database</h2>"
            + note
            + f"<p><span class='badge {tone}'>{state}</span> "
            f"schema v{health['schema_version']} - {html.escape(count_text)}"
            "</p>" + error + "<form method='post' action='/db/reindex' "
            "data-busy='Rebuilding the index from retained artifacts...'>"
            "<button type='submit' class='small'>Reindex from artifacts"
            "</button></form>"
            "<p class='note'>Operational state only (jobs, runs, recorded "
            "usage, report index) under the console state directory; the "
            "validated artifacts remain the scientific authority. Reindex "
            "rebuilds every derived row from the retained artifacts.</p>"
            "</div>"
        )

    def _overview(self, reindexed: str = "") -> bytes:
        self._reconcile()
        jobs = list(self.jobs.values())
        campaigns, campaign_scan_note = self._engineering_campaign_scan()
        job_states = [(job, job.state()) for job in jobs]
        running_jobs = [job for job, state in job_states if state == "running"]
        failed_jobs = [job for job, state in job_states if state == "failed"]
        indeterminate_jobs = [
            (job, state)
            for job, state in job_states
            if state in {"orphaned", "unknown"}
        ]
        running_campaigns = [campaign for campaign in campaigns if campaign.state == "running"]
        failed_campaigns = [
            campaign for campaign in campaigns if campaign.status_tag == "failed"
        ]
        blocked_stopped_campaigns = [
            campaign
            for campaign in campaigns
            if campaign.status_tag in {"blocked", "stopped"}
        ]
        indeterminate_campaigns = [
            campaign
            for campaign in campaigns
            if campaign.status_tag in {"orphaned", "unknown"}
        ]
        partial_campaigns = [
            campaign for campaign in campaigns if campaign.status_tag == "partial"
        ]
        counts, truncated = artifact_inventory(self.results_root)
        disk_html = "<p class='note'>disk usage unavailable</p>"
        try:
            usage = shutil.disk_usage(self.results_root)
        except OSError:
            usage = None
        if usage is not None and usage.total > 0:
            used_pct = 100.0 * (usage.total - usage.free) / usage.total
            disk_html = (
                f"<div class='stat'><span class='value'>"
                f"{_human_size(usage.free)}</span>"
                "<span class='label'>free on results volume</span></div>"
                f"<div class='meter'><div style='width:{used_pct:.1f}%'>"
                "</div></div>"
                f"<p class='note'>{used_pct:.0f}% used of "
                f"{_human_size(usage.total)}</p>"
            )
        pin = os.environ.get("REF_URA", "")
        cost_rows, _cost_unavailable = self._usage_cost_rows()
        if cost_rows is None:
            spend_value, spend_label = "unknown", "calculated spend (db unavailable)"
        else:
            billable = [r for r in cost_rows if r["billable"]]
            if not billable:
                spend_value = "N/A"
                spend_label = "calculated spend (no recorded billable usage)"
            elif any(r["cost"] is None for r in billable):
                spend_value = "N/A"
                spend_label = "calculated spend (price/tokens missing)"
            else:
                by_currency: dict[str, float] = {}
                for row in billable:
                    subtotals = row.get("by_currency")
                    if isinstance(subtotals, Mapping) and subtotals:
                        for currency, amount in subtotals.items():
                            if isinstance(amount, (int, float)) and not isinstance(
                                amount, bool
                            ):
                                code = str(currency).upper()
                                by_currency[code] = by_currency.get(code, 0.0) + float(
                                    amount
                                )
                    elif row.get("currency") and isinstance(
                        row.get("cost"), (int, float)
                    ):
                        code = str(row["currency"]).upper()
                        by_currency[code] = by_currency.get(code, 0.0) + float(
                            row["cost"]
                        )
                if len(by_currency) == 1:
                    currency, amount = next(iter(by_currency.items()))
                    spend_value = self._fmt_money(amount, currency)
                    spend_label = "calculated spend (recorded usage x pricing)"
                elif len(by_currency) > 1:
                    spend_value = " / ".join(
                        self._fmt_money(amount, currency)
                        for currency, amount in sorted(by_currency.items())
                    )
                    spend_label = (
                        "calculated spend (mixed currencies; not summed)"
                    )
                else:
                    spend_value = "N/A"
                    spend_label = "calculated spend (currency unavailable)"
        stats = (
            "<div class='cols'>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{len(jobs) + len(campaigns)}</span>"
            "<span class='label'>jobs (console + external)</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot blue'></span>"
            f"{len(running_jobs)}</span>"
            "<span class='label'>running (console-owned)</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot blue'></span>"
            f"{len(running_campaigns)}</span>"
            "<span class='label'>running (external task-log report)</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot red'></span>"
            f"{len(failed_jobs) + len(failed_campaigns)}</span>"
            "<span class='label'>failed</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot red'></span>"
            f"{len(blocked_stopped_campaigns)}</span>"
            "<span class='label'>blocked / stopped</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot amber'></span>"
            f"{len(indeterminate_jobs) + len(indeterminate_campaigns)}</span>"
            "<span class='label'>orphaned / unknown</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot amber'></span>"
            f"{len(partial_campaigns)}</span>"
            "<span class='label'>partial</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><code>{html.escape(pin[:10] or 'unpinned')}"
            "</code></span>"
            "<span class='label'>project revision (REF_URA)</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{spend_value}</span>"
            f"<span class='label'>{html.escape(spend_label)}</span></div></div>"
            f"<div class='card'>{disk_html}</div>"
            "</div>"
        )
        running_rows = []
        for job in running_jobs:
            activity = (
                " <span class='badge blue' title='Explicit job activity metadata'>"
                "downloading</span>"
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
                " <span class='badge blue' title='Explicit task_kind model_download "
                "in the retained task log'>downloading</span>"
                if campaign.download_tasks
                else ""
            )
            running_rows.append(
                (
                    campaign.started_at,
                    f"<tr><td><a href='/jobs/campaign/{route_id}'>"
                    f"{html.escape(campaign.campaign_id)}</a></td>"
                    "<td>engineering campaign "
                    "<span class='badge gray'>external</span> "
                    "<span class='badge blue'>running</span>"
                    f"{activity}</td>"
                    f"<td>{_human_duration(campaign.runtime_seconds())}</td></tr>",
                )
            )
        running_rows_html = "".join(row for _started, row in sorted(running_rows))
        running_html = (
            "<div class='card'><h2>" + _icon("pulse") + "Running</h2>"
            "<div class='scroll'><table><tr><th>Job</th><th>Command</th>"
            "<th>Runtime</th></tr>" + running_rows_html + "</table></div>"
            "<p class='note'>External running state is a task-log report; it is derived "
            "from retained task logs; this console does not own "
            "or stop its process.</p></div>"
            if running_rows_html
            else ""
        )
        attention_rows = []
        for job in failed_jobs:
            attention_rows.append(
                (
                    job.started_at,
                    f"<tr><td><a href='/jobs/{html.escape(job.job_id)}'>"
                    f"{html.escape(job.job_id)}</a></td>"
                    f"<td>{html.escape(job.command)} "
                    "<span class='badge red'>failed</span></td>"
                    f"<td>{_human_duration(job.runtime_seconds())}</td></tr>",
                )
            )
        for job, state in indeterminate_jobs:
            attention_rows.append(
                (
                    job.started_at,
                    f"<tr><td><a href='/jobs/{html.escape(job.job_id)}'>"
                    f"{html.escape(job.job_id)}</a></td>"
                    f"<td>{html.escape(job.command)} "
                    f"<span class='badge amber'>{html.escape(state)}</span></td>"
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
                    f"<tr><td><a href='/jobs/campaign/{route_id}'>"
                    f"{html.escape(campaign.campaign_id)}</a></td>"
                    "<td>engineering campaign "
                    f"<span class='badge {tag_tone}'>external, "
                    f"{html.escape(campaign.status_tag)}</span>{detail}</td>"
                    f"<td>{_human_duration(campaign.runtime_seconds())}</td></tr>",
                )
            )
        recent_attention_rows = sorted(attention_rows, reverse=True)[
            :_DASHBOARD_RECENT_FAILURE_LIMIT
        ]
        attention_html = (
            "<div class='card'><h2>" + _icon("pulse") + "Needs attention</h2>"
            "<div class='scroll'><table><tr><th>Job</th><th>Command</th>"
            "<th>Runtime</th></tr>"
            + "".join(row for _started, row in recent_attention_rows)
            + "</table></div><p class='note'>Showing up to "
            f"{_DASHBOARD_RECENT_FAILURE_LIMIT} most recently started failed, "
            "blocked, stopped, orphaned, or unknown jobs. "
            "External engineering campaign state is filesystem-backed and "
            "read-only; open the job for its retained logs.</p></div>"
            if recent_attention_rows
            else ""
        )
        partial_rows = []
        for campaign in partial_campaigns:
            route_id = quote(campaign.route_id)
            pending = (
                "unknown" if campaign.pending_tasks is None else str(campaign.pending_tasks)
            )
            partial_rows.append(
                (
                    campaign.started_at,
                    f"<tr><td><a href='/jobs/campaign/{route_id}'>"
                    f"{html.escape(campaign.campaign_id)}</a></td>"
                    "<td><span class='badge amber'>partial</span> "
                    f"{campaign.succeeded_tasks} succeeded; "
                    f"{campaign.failed_tasks} failed; "
                    f"{campaign.skipped_tasks} skipped; {pending} pending</td>"
                    f"<td>{_human_duration(campaign.runtime_seconds())}</td></tr>",
                )
            )
        recent_partial_rows = sorted(partial_rows, reverse=True)[
            :_DASHBOARD_RECENT_PARTIAL_LIMIT
        ]
        partial_html = (
            "<div class='card'><h2>" + _icon("pulse") + "Partial campaigns</h2>"
            "<div class='scroll'><table><tr><th>Job</th><th>Task results</th>"
            "<th>Runtime</th></tr>"
            + "".join(row for _started, row in recent_partial_rows)
            + "</table></div><p class='note'>A successful campaign terminal does "
            "not hide failed, skipped, or pending tasks. Open the campaign for "
            "its model-work declaration and execution report.</p></div>"
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
                items += f"<li class='note'>first {len(stage.paths)} of {total} shown</li>"
            summary = f"{html.escape(label)}: {stage.count} current"
            if stage.superseded:
                summary += f", {stage.superseded} archived"
            stage_sections.append(
                f"<details class='stagefiles'><summary>{summary}</summary>"
                f"<ul>{items}</ul></details>"
            )
        stage_files = "".join(stage_sections)
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 10000);</script>"
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
            + "Campaign pipeline"
            "</h2>"
            + _pipeline_svg(counts)
            + "<p class='note'>Click a stage to browse its files. Counts are "
            "retained-file presence under the results root only; presence "
            "never asserts validity, authorization, or measurement status. "
            "“archived” counts files under a "
            "<code>superseded/</code> directory (kept as history, not "
            "current - for example an earlier pin's revision receipt)."
            + (
                " Inventory scan truncated at its entry cap; counts are a lower bound."
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
            + "Campaign bindings</h2>"
            + self._campaign_context()
            + "</div>"
        )
        governance_panel = (
            self._budget_card()
            + self._policy_card()
            + "<div class='card'><h2>"
            + _icon("logo")
            + "Boundaries</h2>"
            "<p class='note'>Allowlisted commands only; no arbitrary shell. "
            "Dry-run/canary/probe artifacts stay diagnostic; measured "
            "claims come only from validated artifacts and the maintained "
            "analysis CLIs.</p></div>"
        )
        dashboard_tabs = (
            ("dashboard-system", "System"),
            ("dashboard-campaigns", "Campaigns"),
            ("dashboard-governance", "Governance"),
        )
        body = (
            "<h1>"
            + _icon("grid", size=22)
            + "Dashboard</h1>"
            + global_notices
            + "<div class='page-tabs' data-page-tabs data-tab-key='dashboard' "
            "data-default-tab='dashboard-system'>"
            + _page_tablist("Dashboard sections", dashboard_tabs, default="dashboard-system")
            + _page_tabpanel("dashboard-system", system_panel)
            + _page_tabpanel("dashboard-campaigns", campaign_panel)
            + _page_tabpanel("dashboard-governance", governance_panel)
            + "</div>"
            + refresh
        )
        return _page("URA rig console", body, active="Dashboard")

    def _param_input(self, param: CommandParam) -> str:
        flag = html.escape(param.flag)
        if param.kind == "flag":
            return f"<input type='checkbox' name='{flag}'>"
        if param.choices:
            options = "".join(
                f"<option value='{html.escape(choice)}'>{html.escape(choice)}</option>"
                for choice in param.choices
            )
            return (
                f"<select name='{flag}'><option value=''>(default)</option>" + options + "</select>"
            )
        if param.kind == "int":
            return f"<input type='number' step='1' name='{flag}'>"
        if param.kind == "float":
            return f"<input type='number' step='any' name='{flag}'>"
        listattr = f" list='dl-{html.escape(param.suggest)}'" if param.suggest else ""
        return f"<input type='text' name='{flag}'{listattr}>"

    def _command_card(self, name: str) -> str:
        entry = self.commands[name]
        fields = []
        for param in entry.params:
            required = "<span class='req' title='required'>*</span>" if param.required else ""
            help_text = param.help or _PARAM_HELP.get(param.flag, "")
            title = f" title='{html.escape(help_text)}'" if help_text else ""
            hint = f"<span class='fieldhint'>{html.escape(help_text)}</span>" if help_text else ""
            fields.append(
                f"<label{title}>{html.escape(param.flag)}{required} "
                f"<span class='kind'>{html.escape(param.kind)}</span>"
                "</label>"
                f"<div class='fieldwrap'>{self._param_input(param)}{hint}</div>"
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
            + "".join(fields)
            + "<span></span><button type='submit'>"
            + _icon("play", size=15)
            + "Start job</button>"
            "</form></div></details>"
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

    def _commands_page(self) -> bytes:
        grouped: set[str] = set()
        sections = []

        def card(name: str) -> str:
            if name == "run_matrix":
                return ""
            if name not in {"capture_t3mp3st", "harmbench_capture"}:
                return self._command_card(name)
            label = "T3MP3ST Capture" if name == "capture_t3mp3st" else "HarmBench Prepare"
            return (
                f"<details class='cmd' data-name='{html.escape(name)}'><summary>"
                f"{_icon('flask')}<strong>{html.escape(label)}</strong>"
                "<span class='desc'>Validated capture-first workflow</span></summary>"
                "<p class='note'>Open the Build workflow for field validation and "
                "an exact-command review before any process starts.</p>"
                "<p><a href='/build#prepared-workflows'>Open in Build</a></p></details>"
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
        internal_ui_commands = {"model_acquire", "ollama_pull", "run_matrix"}
        leftovers = "".join(
            card(name)
            for name in sorted(set(self.commands) - grouped - internal_ui_commands)
        )
        if leftovers:
            sections.append(
                f"<div class='group-head'>{_icon('file', size=20)}<h2>Other</h2></div>" + leftovers
            )
        body = (
            "<h1>" + _icon("terminal", size=22) + "Run a command</h1>"
            "<p class='note'>Typed forms over the allowlisted experiment "
            "CLIs; the argument vector shown on each job page is exactly "
            "what runs. Fields map one-to-one to documented CLI flags; "
            "<span class='req'>*</span> marks a required field.</p>"
            "<p><input id='cmdfilter' type='text' "
            "placeholder='Type to filter commands...' "
            "aria-label='filter commands'></p>"
            + self._datalists()
            + "".join(sections)
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
            "var params=new URLSearchParams(window.location.search);"
            "var cmd=params.get('cmd');"
            "if(cmd){var card=document.querySelector("
            '"details.cmd input[name=command][value=\'"+cmd+"\']");'
            "if(card){var det=card.closest('details.cmd');det.open=true;"
            "params.forEach(function(val,key){"
            "if(key==='cmd'){return;}"
            'var field=det.querySelector("[name=\'"+key+"\']");'
            "if(!field){return;}"
            "if(field.type==='checkbox'){field.checked="
            "(val==='on'||val==='true'||val==='1'||val==='yes');}"
            "else{field.value=val;}});"
            "det.scrollIntoView({behavior:'smooth',block:'center'});}}"
            "})();</script>"
        )
        return _page("Run a command", body, active="Run")

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
        self._reconcile()
        filters = dict(query or {})
        now = time.time()
        started_from = self._jobs_history_bound(
            filters,
            "from",
            now - 7 * 86400,
        )
        started_to = self._jobs_history_bound(filters, "to", now)
        history_note = ""
        if started_from > started_to:
            history_jobs = []
            history_note = "From must not be after To."
        else:
            history_jobs, history_truncated = self._jobs_for_history_window(
                started_from,
                started_to,
                limit=_JOBS_HISTORY_DISPLAY_LIMIT,
            )
            if history_truncated:
                history_note = (
                    f"Showing the newest {_JOBS_HISTORY_DISPLAY_LIMIT} console jobs "
                    "in this date range. Narrow From/To to retrieve older rows."
                )
        campaigns, campaign_scan_note = self._engineering_campaign_scan(
            started_from=started_from,
            started_to=started_to,
        )
        rows = []
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
                "<form class='inline' method='post' "
                f"action='/jobs/{html.escape(job_id)}/stop'>"
                "<button class='danger small' type='submit'>Stop</button>"
                "</form>"
                if state == "running" and job.process is not None
                else ""
            )
            hay = html.escape(f"{job_id} {job.command}".lower())
            activity = (
                "<span class='badge blue' title='Explicit job activity metadata'>"
                "downloading</span>"
                if state == "running" and getattr(job, "activity", None) == "model_download"
                else "-"
            )
            rows.append(
                f"<tr data-state='{html.escape(state_tag)}' "
                f"data-started='{started_ms}' data-hay='{hay}'>"
                f"<td><a href='/jobs/{html.escape(job_id)}'>"
                f"{html.escape(job_id)}</a></td>"
                f"<td>{html.escape(job.command)}</td>"
                f"<td>{html.escape(self._job_work_label(job))}</td>"
                f"<td>{html.escape(self._job_execution_label(job))}</td>"
                f"<td><span class='dot {tone}'></span>"
                f"<span class='badge {tone}'>{html.escape(state_tag)}</span></td>"
                f"<td><time class='job-started' data-epoch-ms='{started_ms}'>"
                f"{started}</time></td>"
                f"<td>{_human_duration(job.runtime_seconds())}</td>"
                f"<td>{activity}</td>"
                f"<td>{'' if job.exit_code() is None else job.exit_code()}"
                f"</td><td>{stop}</td></tr>"
            )
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
            started = time.strftime(
                "%Y-%m-%d %H:%M:%S UTC", time.gmtime(campaign.started_at)
            )
            started_ms = int(campaign.started_at * 1000)
            route_id = quote(campaign.route_id)
            hay = html.escape(
                f"{campaign.campaign_id} engineering campaign external "
                f"{campaign.status_tag} {campaign.progress}".lower()
            )
            work = "model work undeclared"
            if campaign.model_tasks is not None:
                roles = {role for _task, _status, role in campaign.task_outcomes}
                if campaign.model_tasks:
                    work = "model + support" if "support" in roles else "model only"
                else:
                    work = "support only"
                if "unplanned" in roles:
                    work += " + unplanned"
            if campaign.model_execution_error:
                execution = "report invalid"
            elif campaign.model_attempted_calls is None:
                execution = "not reported"
            else:
                execution = (
                    f"{campaign.model_successful_generations}/{campaign.model_attempted_calls} "
                    "reported successful; "
                    f"{campaign.model_execution_covered_tasks}/"
                    f"{len(campaign.model_tasks or ())} model tasks"
                )
            rows.append(
                f"<tr data-state='{html.escape(state_tag)}' "
                f"data-started='{started_ms}' data-hay='{hay}'>"
                f"<td><a href='/jobs/campaign/{route_id}'>"
                f"{html.escape(campaign.campaign_id)}</a></td>"
                "<td>engineering campaign <span class='badge gray'>external</span></td>"
                f"<td>{html.escape(work)}</td>"
                f"<td>{html.escape(execution)}</td>"
                f"<td><span class='dot {tone}'></span>"
                f"<span class='badge {tone}'>{html.escape(state_tag)}</span></td>"
                f"<td><time class='job-started' data-epoch-ms='{started_ms}'>"
                f"{started}</time></td>"
                f"<td>{_human_duration(campaign.runtime_seconds())}</td>"
                f"<td>"
                + (
                    "<span class='badge blue' title='Explicit task_kind "
                    "model_download in retained task log'>downloading</span> "
                    if campaign.download_tasks
                    else ""
                )
                + f"{html.escape(campaign.progress)} "
                f"<a href='/jobs/campaign/{route_id}'>logs</a></td>"
                "<td>-</td><td></td></tr>"
            )
        chips = (
            "<div class='chips'>"
            f"<button type='button' class='chip on' data-state=''>All "
            "(<span class='chip-count'>"
            f"{len(history_jobs) + len(campaigns)}</span>)</button>"
            + "".join(
                f"<button type='button' class='chip' data-state='{state}'>"
                f"{state.capitalize()} (<span class='chip-count'>{count}</span>)</button>"
                for state, count in sorted(tallies.items())
            )
            + "</div>"
        )
        controls = (
            chips + "<div class='targetfilters job-date-filters'><div class='fieldcell'>"
            "<label class='fieldlabel' for='job-from'>From</label>"
            "<input id='job-from' type='datetime-local' step='1'>"
            "</div><div class='fieldcell'>"
            "<label class='fieldlabel' for='job-to'>To</label>"
            "<input id='job-to' type='datetime-local' step='1'>"
            "</div></div><p><input id='jobfilter' type='text' "
            "placeholder='Type to filter jobs...' "
            "aria-label='filter jobs'></p>"
        )
        table = (
            "<div class='card scroll'><table id='jobstable'>"
            "<tr><th>Job</th><th>Command</th>"
            "<th>Work</th><th>Execution</th><th>State</th><th>Started</th><th>Runtime</th>"
            "<th>Progress</th><th>Exit</th>"
            "<th></th></tr>" + "".join(rows) + "</table></div>"
            if rows
            else "<div class='card'><p class='note'>No jobs this session. Start "
            "one from the <a href='/commands'>Run</a> page.</p></div>"
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
            "var okDate=Number.isFinite(started)&&started>=from&&started<=to;"
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
            "syncFilters();location.reload();});"
            "toBox.addEventListener('change',function(){explicitTo=true;"
            "syncFilters();location.reload();});"
            "syncFilters();if(needsServerWindow){location.reload();return;}apply();"
            "})();</script>"
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 5000);</script>"
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
            ("All in current window", len(history_jobs) + len(campaigns), ""),
            ("Console jobs", len(history_jobs), None),
            ("External campaigns", len(campaigns), None),
            ("Running", tallies.get("running", 0), "running"),
            ("Needs attention", attention_count, None),
            ("Passed", tallies.get("passed", 0), "passed"),
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
                overview_cards_parts.append(
                    "<a class='card' href='/jobs"
                    + (f"?state={quote(state)}" if state else "")
                    + "#jobs-history'>"
                    + content
                    + "</a>"
                )
        overview_cards = "".join(overview_cards_parts)
        overview_panel = (
            "<div class='cols tab-summary'>"
            + overview_cards
            + "</div><div class='card'><h2>Job sources</h2>"
            "<p class='note'>Console jobs are owned by this process. External "
            "campaigns are read-only task-log reports. Open History for the "
            "full table, date window, state chips, text search, logs, and "
            "available stop controls.</p></div>"
        )
        history_panel = (
            controls
            + table
            + "<p id='jobs-filter-empty' class='notice amber' hidden>"
            "No jobs match the selected dates, state, and text.</p>"
            + script
        )
        jobs_tabs = (
            ("jobs-overview", "Overview"),
            ("jobs-history", "History"),
        )
        explicit_filter = any(
            str(filters.get(name, "")).strip()
            for name in ("from", "to", "from_ms", "to_ms", "state", "q")
        )
        jobs_default = "jobs-history" if explicit_filter else "jobs-overview"
        force_default = " data-force-default='true'" if explicit_filter else ""
        return _page(
            "Jobs",
            "<h1>"
            + _icon("pulse", size=22)
            + "Jobs</h1>"
            + self._health_banner()
            + (
                "<div class='notice amber'>" + html.escape(campaign_scan_note) + "</div>"
                if campaign_scan_note
                else ""
            )
            + (
                "<div class='notice amber'>" + html.escape(history_note) + "</div>"
                if history_note
                else ""
            )
            + "<div class='page-tabs' data-page-tabs data-tab-key='jobs' "
            f"data-default-tab='{jobs_default}'{force_default}>"
            + _page_tablist("Job sections", jobs_tabs, default=jobs_default)
            + _page_tabpanel("jobs-overview", overview_panel)
            + _page_tabpanel("jobs-history", history_panel)
            + "</div>"
            + refresh,
            active="Jobs",
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
            "-" if campaign.hard_stop_hours is None else f"{campaign.hard_stop_hours:g} hours"
        )
        details = (
            "<div class='card scroll'><table>"
            f"<tr><td>Release commit</td><td><code>{html.escape(campaign.release_commit)}</code></td></tr>"
            f"<tr><td>Evidence class</td><td>{html.escape(campaign.evidence_class)}</td></tr>"
            "<tr><td>Thesis empirical evidence</td><td>no</td></tr>"
            f"<tr><td>Hosted calls allowed</td><td>{'yes' if campaign.hosted_calls_allowed else 'no'}</td></tr>"
            f"<tr><td>Reserved call budget (not execution)</td>"
            f"<td>{campaign.reserved_calls}/{call_cap}</td></tr>"
            "<tr><td>Declared model tasks</td><td>"
            + (
                "invalid: " + html.escape(campaign.model_declaration_error)
                if campaign.model_declaration_error
                else "not declared"
                if campaign.model_tasks is None
                else str(len(campaign.model_tasks))
            )
            + "</td></tr>"
            "<tr><td>Reported model execution</td><td>"
            + (
                "report invalid: " + html.escape(campaign.model_execution_error)
                if campaign.model_execution_error
                else "not reported"
                if campaign.model_attempted_calls is None
                else f"{campaign.model_successful_generations} successful generation(s) / "
                f"{campaign.model_attempted_calls} attempt(s); "
                f"{campaign.model_execution_covered_tasks}/"
                f"{len(campaign.model_tasks or ())} model tasks reported"
            )
            + "</td></tr>"
            f"<tr><td>Hard stop</td><td>{hard_stop}</td></tr>"
            "</table></div>"
        )
        task_rows = "".join(
            "<tr><td><code>"
            + html.escape(task)
            + "</code>"
            + (
                " <span class='badge blue' title='Explicit task_kind "
                "model_download in retained task log'>downloading</span>"
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
        task_table = (
            "<div class='card'><h2>Task outcomes</h2>"
            "<p class='note'>A passed support task proves only that its command "
            "exited successfully. It is not model-execution evidence. Reported "
            "call counts remain operational self-reports; validated response "
            "artifacts are authoritative.</p>"
            "<div class='scroll'><table><tr><th>Task</th><th>Work</th>"
            "<th>Result</th></tr>"
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
            + "Task logs</h2>"
            + (f"<ul>{log_links}</ul>" if log_links else "<p class='note'>No task logs yet.</p>")
            + f"<p><a href='/artifacts?path={quote(relative)}'>"
            "Browse all retained campaign files</a></p></div>"
        )
        last_detail = (
            "<div class='card'><h2>" + _icon("terminal") + "Latest activity</h2>"
            f"<pre>{html.escape(campaign.last_detail)}</pre></div>"
            if campaign.last_detail
            else ""
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 5000);</script>"
            if campaign.state == "running"
            else ""
        )
        body = (
            "<h1>" + _icon("pulse", size=22) + "Campaign "
            f"{html.escape(campaign.campaign_id)}</h1>"
            "<div class='notice amber'><strong>Externally managed engineering work.</strong> "
            "This console observes its retained files read-only; process ownership remains "
            "with the campaign launcher. Status comes from retained task logs, not an "
            "operating-system liveness check. It is not thesis empirical evidence.</div>"
            "<div class='cols'>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot {tone}'></span>"
            f"{html.escape(campaign.status_tag)}</span>"
            "<span class='label'>campaign status</span>"
            "</div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{_human_duration(campaign.runtime_seconds())}</span>"
            "<span class='label'>runtime</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{started}</span><span class='label'>started</span></div></div>"
            "</div>"
            "<div class='card'><h2>" + _icon("chart") + "Progress</h2>"
            + (
                "<p><span class='badge blue' title='Explicit task_kind "
                "model_download in retained task log'>downloading</span></p>"
                if campaign.download_tasks
                else ""
            )
            + f"<p>{html.escape(campaign.progress)}</p></div>"
            + details
            + task_table
            + last_detail
            + logs
            + refresh
        )
        return _page(f"Campaign {campaign.campaign_id}", body, active="Jobs")

    def _job_page(self, job: Job) -> bytes:
        state = job.state()
        tone = {"running": "blue", "complete": "green", "failed": "red"}.get(state, "gray")
        state_tag = self._job_status_tag(state)
        stdout_tail = self._log_tail(job, "stdout") or "(empty)"
        stderr_tail = self._log_tail(job, "stderr") or "(empty)"
        stop_form = (
            f"<form method='post' action='/jobs/{html.escape(job.job_id)}/stop'>"
            "<button class='danger' type='submit'>Stop job</button></form>"
            if state == "running" and job.process is not None
            else ""
        )
        refresh = (
            "<script>setTimeout(function(){location.reload();}, 2000);</script>"
            if state == "running"
            else ""
        )
        failure = (
            "<div class='card'><h2>" + _icon("pulse") + "Failure</h2>"
            "<p>The command exited with "
            f"code {job.exit_code()}. Standard error is shown below; the "
            "underlying CLI message is authoritative.</p>"
            + (f"<pre>{html.escape(job.failure)}</pre>" if job.failure else "")
            + "</div>"
            if state == "failed"
            else ""
        )
        activity = (
            "<div class='notice blue'><strong>Model download in progress.</strong> "
            "This indicator comes from explicit job activity metadata and is "
            "shown only while the process is running.</div>"
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
                + "Builder parameters</h2><div class='scroll'><table>"
                + rows
                + "</table></div><p class='note'>The durable campaign-builder "
                "selections retained with this job. Explicit workstation "
                "checkpoint locators appear only as declared SHA-256 content "
                "identities.</p><form method='post' action='/build'>"
                + reopen
                + "<button type='submit' class='ghost'>Review this exact "
                "lane in the builder</button></form></div>"
            )
        argv_chips = (
            "<div class='argv'>"
            + "".join(f"<code>{html.escape(part)}</code>" for part in job.argv)
            + "</div>"
        )
        retained_links: list[str] = []
        for flag in ("--out", "--output", "--artifact-out", "--attacker-config-out"):
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
            "<p class='note'>Retained output: " + " &middot; ".join(retained_links) + "</p>"
            if retained_links
            else ""
        )
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(job.started_at))
        exit_code = job.exit_code()
        meta = (
            "<div class='cols'>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'><span class='dot {tone}'></span>"
            f"{html.escape(state_tag)}</span>"
            "<span class='label'>state</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{job.runtime_seconds():,.0f}s</span>"
            "<span class='label'>runtime</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{started}</span>"
            "<span class='label'>started</span></div></div>"
            "<div class='card'><div class='stat'>"
            f"<span class='value'>{'-' if exit_code is None else exit_code}"
            "</span><span class='label'>exit code</span></div></div>"
            "</div>"
        )
        stop_failure = (
            "<div class='notice red'><strong>Stop could not be confirmed."
            "</strong><p class='note'>"
            + html.escape(job.stop_error)
            + " Check the rig for a surviving process and terminate it "
            "manually; this run's usage/cost may be incomplete.</p></div>"
            if job.stop_error
            else ""
        )
        body = (
            f"<h1>{_icon('terminal', size=22)}Job {html.escape(job.job_id)}"
            "</h1>"
            + meta
            + activity
            + model_acquisition_actions
            + stop_failure
            + "<div class='card'><h2>"
            + _icon("file")
            + "Durable command identity</h2>"
            + argv_chips
            + retained
            + stop_form
            + "</div>"
            + builder
            + failure
            + "<div class='card'><h2>"
            + _icon("chart")
            + "stdout</h2>"
            f"<pre>{html.escape(stdout_tail)}</pre></div>"
            "<div class='card'><h2>" + _icon("pulse") + "stderr</h2>"
            f"<pre>{html.escape(stderr_tail)}</pre></div>" + refresh
        )
        return _page(f"Job {job.job_id}", body, active="Jobs")

    # -- artifact browsing -------------------------------------------------

    def _artifacts(self, relative: str) -> tuple[int, str, bytes]:
        target = _contained(self.results_root, relative)
        if target.is_dir():
            return 200, "text/html; charset=utf-8", self._directory_page(target, relative)
        if not target.is_file():
            return 404, "text/plain; charset=utf-8", b"no such artifact"
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
            "<div class='card scroll'><table class='filelist'>"
            "<tr><th>Name</th><th>Size</th></tr>" + "".join(rows) + "</table></div>"
            if rows
            else "<div class='card'><p class='note'>Empty directory.</p></div>"
        )
        body = "<h1>" + _icon("folder", size=22) + "Artifacts</h1>" + _crumbs(relative) + listing
        return _page("Artifacts", body, active="Artifacts")

    def _file_page(self, target: Path, relative: str) -> tuple[int, str, bytes]:
        suffix = target.suffix.lower()
        if suffix == ".png":
            return 200, "image/png", target.read_bytes()
        if target.stat().st_size > _MAX_RENDER_BYTES:
            return (
                200,
                "text/html; charset=utf-8",
                _page(
                    "Artifact",
                    "<h1>"
                    + _icon("file", size=22)
                    + f"{html.escape(relative)}</h1>"
                    + _crumbs(relative)
                    + "<div class='card'><p>"
                    "File exceeds the inline render limit; inspect it on "
                    "disk.</p></div>",
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
                    rows.append("<tr><td colspan='99'>(truncated preview)</td></tr>")
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
            _page(relative, body, active="Artifacts"),
        )
