"""Warnings, reports, statistics, and dashboard rendering."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

from ura.strict_json import strict_json_loads

from .catalog import _WARNINGS_FILE, _WARNINGS_MAX, _WARNING_TONES, _icon

from .ui import _page, _page_tablist, _page_tabpanel

from .artifacts import (
    StageInventory,
    _TOKEN_CATEGORIES,
    collect_usage,
    derived_index_path_quarantined,
    derived_path_quarantined,
    iter_completed_markers,
    run_kind,
)

from .reports import (
    _LEVEL2_STRATUM_FIELDS,
    _validate_report_document,
    collect_reports,
    load_pricing,
    compute_costs,
)
from .external_measured import ExternalMeasuredJob
from .campaigns import EngineeringCampaign
from .external_analysis import (
    ExternalAnalysisReport,
    ExternalAnalysisRegistration,
    load_external_analysis_report,
    load_external_analysis_registration,
)


class DashboardMixin:
    # -- pages -------------------------------------------------------------

    def _load_warnings(self) -> list[dict[str, str]]:
        """Operator-facing notices from ``console-warnings.json``.

        The file is an operator/tooling-authored presentation input under the
        results root: ``{"warnings": [{"level", "title", "detail"}, ...]}``.
        It never changes experiment semantics; unknown levels render as
        ``warning``.  Malformed content is ignored (the console must not 500
        over a notice file).
        """

        path = self.results_root / _WARNINGS_FILE
        try:
            raw = strict_json_loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        entries = raw.get("warnings") if isinstance(raw, dict) else None
        if not isinstance(entries, list):
            return []
        out: list[dict[str, str]] = []
        for entry in entries[:_WARNINGS_MAX]:
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title", "")).strip()
            if not title:
                continue
            out.append(
                {
                    "level": str(entry.get("level", "warning")).lower(),
                    "title": title,
                    "detail": str(entry.get("detail", "")).strip(),
                }
            )
        return out

    def _warnings_html(self) -> str:
        entries = self._load_warnings()
        if not entries:
            return ""
        rows = []
        for entry in entries:
            tone = _WARNING_TONES.get(entry["level"], "amber")
            nid = hashlib.sha1(f"{entry['level']}|{entry['title']}".encode("utf-8")).hexdigest()[
                :12
            ]
            detail = (
                f"<p class='note'>{html.escape(entry['detail'])}</p>" if entry["detail"] else ""
            )
            rows.append(
                f"<div class='notice {tone}' data-nid='{nid}'>"
                "<button type='button' class='notice-close' "
                "aria-label='dismiss notice' title='Dismiss (this browser "
                "only)'>&times;</button>"
                f"<span class='badge {tone}'>{html.escape(entry['level'])}"
                f"</span> <strong>{html.escape(entry['title'])}</strong>" + detail + "</div>"
            )
        return (
            "<div class='card'><h2>"
            + _icon("pulse")
            + "Notices</h2>"
            + "".join(rows)
            + "<p class='note'>Operator-recorded notices from "
            f"<code>{_WARNINGS_FILE}</code>; they annotate, and never "
            "authorize or invalidate, the artifacts themselves. Dismissing "
            "a notice hides it in this browser only - the file is "
            "unchanged. <a href='#' id='notice-restore' "
            "style='display:none'></a></p></div>"
            "<script>(function(){"
            "var KEY='ura-dismissed-notices';"
            "function load(){try{return JSON.parse("
            "localStorage.getItem(KEY))||[]}catch(e){return[]}}"
            "function save(v){localStorage.setItem(KEY,JSON.stringify(v));}"
            "var restore=document.getElementById('notice-restore');"
            "function apply(){var d=load();var hidden=0;"
            "document.querySelectorAll('.notice').forEach(function(n){"
            "var on=d.indexOf(n.getAttribute('data-nid'))>=0;"
            "n.style.display=on?'none':'';if(on){hidden++;}});"
            "if(restore){restore.style.display=hidden?'':'none';"
            "restore.textContent='Show '+hidden+' dismissed notice'+"
            "(hidden===1?'':'s');}}"
            "document.querySelectorAll('.notice-close').forEach(function(b){"
            "b.addEventListener('click',function(){"
            "var id=this.parentElement.getAttribute('data-nid');"
            "var d=load();if(d.indexOf(id)<0){d.push(id);save(d);}"
            "apply();});});"
            "if(restore){restore.addEventListener('click',function(e){"
            "e.preventDefault();save([]);apply();});}"
            "apply();})();</script>"
        )

    def _campaign_context(self) -> str:
        """Non-secret campaign bindings from the environment, if present."""

        rows = []
        for label, name in (
            ("Pinned revision", "REF_URA"),
            ("Revision receipt", "URA_PROJECT_REVISION_MANIFEST"),
            ("Receipt SHA-256", "URA_PROJECT_REVISION_SHA256"),
            ("Corpora root", "URA_CORPORA"),
        ):
            value = os.environ.get(name, "")
            if not value:
                continue
            shown = value if len(value) <= 64 else value[:30] + "..." + value[-22:]
            rows.append(
                f"<tr><td>{html.escape(label)}</td><td><code>{html.escape(shown)}</code></td></tr>"
            )
        if not rows:
            return (
                "<p class='note'>No campaign bindings exported in this console's environment.</p>"
            )
        return (
            "<div class='scroll'><table>" + "".join(rows) + "</table></div>"
            "<p class='note'>Values echoed from this console's environment "
            "for orientation only; nothing here validates them. The receipt "
            "and attestation validators are the only authority.</p>"
        )

    @staticmethod
    def _next_hint(stages: Mapping[str, StageInventory]) -> str:
        order = (
            (
                "Revision receipt",
                "project_revision",
                "author the prospective revision receipt (runbook section 2)",
            ),
            (
                "Source receipts",
                "source_conformance",
                "run the bounded one-arm observations and author the source "
                "receipt (runbook section 4.1)",
            ),
            (
                "Attestations",
                "run_matrix",
                "run the account attestation probes and derive transport "
                "receipts (runbook section 8)",
            ),
            (
                "Canaries",
                "run_matrix",
                "run diagnostic canaries and record exact observed tokens/spend "
                "(runbook section 9.1)",
            ),
            ("Grids", "run_matrix", "start the measured lanes (runbook sections 10-13)"),
        )
        note = (
            "<p class='note'>This suggestion reads file presence only; the "
            "runbook and its fail-closed gates decide what is actually "
            "admissible.</p>"
        )
        for label, form, description in order:
            stage = stages.get(label)
            if stage is None or stage.count == 0:
                return (
                    "<div class='card'><h2>"
                    + _icon("play")
                    + "Suggested next step</h2><p>Runbook order points to: "
                    f"<strong>{html.escape(description)}</strong> - the "
                    f"<code>{html.escape(form)}</code> form on the "
                    "<a href='/commands'>Run</a> page.</p>" + note + "</div>"
                )
        return (
            "<div class='card'><h2>" + _icon("play") + "Suggested next step"
            "</h2><p>All pipeline stages have files; analysis and reporting "
            "live in runbook section 16.</p>" + note + "</div>"
        )

    # -- stats -------------------------------------------------------------

    @staticmethod
    def _bar_chart(rows: list[tuple[str, float]], *, unit: str = "") -> str:
        """A minimal horizontal bar chart (values in [0,1]); presentation only."""

        if not rows:
            return ""
        bar_h, gap, pad_l, width = 22, 10, 220, 640
        height = len(rows) * (bar_h + gap) + gap
        parts = [
            f"<svg class='barchart' viewBox='0 0 {width} {height}' "
            "role='img' aria-label='result chart'>"
        ]
        for index, (label, value) in enumerate(rows):
            value = 0.0 if value < 0 else (1.0 if value > 1 else value)
            y = gap + index * (bar_h + gap)
            bar_w = (width - pad_l - 60) * value
            shown = f"{value * 100:.0f}%" if not unit else f"{value:g}{unit}"
            parts.append(
                f"<text class='bl' x='{pad_l - 8}' y='{y + bar_h - 6}' "
                f"text-anchor='end'>{html.escape(label[:34])}</text>"
                f"<rect class='bt' x='{pad_l}' y='{y}' "
                f"width='{width - pad_l - 60}' height='{bar_h}' rx='4'/>"
                f"<rect class='bv' x='{pad_l}' y='{y}' width='{bar_w:.1f}' "
                f"height='{bar_h}' rx='4'/>"
                f"<text class='bn' x='{pad_l + bar_w + 6}' y='{y + bar_h - 6}'>"
                f"{html.escape(shown)}</text>"
            )
        parts.append("</svg>")
        return "<div class='scroll'>" + "".join(parts) + "</div>"

    def _health_banner(self) -> str:
        """A visible banner when the database is unhealthy - never silent."""

        health = self.db.health()
        if health["healthy"] and not health["last_error"]:
            return ""
        return (
            "<div class='notice red'><span class='badge red'>database</span> "
            "<strong>Console database "
            + ("error" if health["healthy"] else "unavailable")
            + f"</strong><p class='note'>{html.escape(health['last_error'])} "
            "- job history, run registry, and recorded usage may be "
            "incomplete or unavailable (shown as unknown, never as empty). "
            "Jobs still run; validated artifacts are unaffected. Use "
            "Reindex on the dashboard after repairing the file.</p></div>"
        )

    def _usage_cost_rows(self) -> tuple[list[dict[str, Any]] | None, str]:
        """Cost rows from recorded usage, or (None, why-unavailable)."""

        totals = self.db.usage_totals()
        if totals is None:
            return None, "database unavailable - recorded usage unknown"
        pricing = load_pricing(self.repo_root)
        return compute_costs(totals, pricing), ""

    def _has_completion_markers(self) -> bool:
        """True if any completed-run artifacts exist under the results root.

        Used to distinguish a genuinely empty campaign (no spend) from a fresh
        or stale index pointed at retained artifacts (spend UNKNOWN, not zero).
        """

        try:
            _markers, stats = iter_completed_markers(self.results_root)
        except OSError:
            return False
        return bool(stats.get("markers"))

    @staticmethod
    def _fmt_money(value: float | None, currency: str) -> str:
        if value is None:
            return "N/A"
        unit = {"USD": "$"}.get(currency.upper(), currency + " ")
        return f"{unit}{value:,.4f}"

    def _spend_card(self) -> str:
        cost_rows, unavailable = self._usage_cost_rows()
        if cost_rows is None:
            body = f"<p class='note'><strong>N/A</strong> - {html.escape(unavailable)}.</p>"
            return (
                "<div class='card'><h2>"
                + _icon("coins")
                + "Budgets, usage &amp; calculated cost</h2>"
                + body
                + "</div>"
            )
        # Per-model usage/cost table (recorded tokens by category, the rate
        # applied, and the calculated cost - or N/A naming what is missing).
        detail = []
        for row in cost_rows:
            cats = row["tokens"]
            token_cells = "".join(
                f"<td>{cats[c]:,}</td>" if cats[c] else "<td>-</td>" for c in _TOKEN_CATEGORIES
            )
            if not row["billable"]:
                cost_cell = "<td>local (not billed)</td>"
            elif row["cost"] is not None:
                source = (
                    " - <span class='badge amber'>auto-fetched, verify</span>"
                    if row.get("auto_fetched")
                    else " - <span class='badge gray'>operator-set</span>"
                )
                cost_cell = (
                    f"<td><strong>{self._fmt_money(row['cost'], row['currency'])}"
                    f"</strong><br><span class='fieldhint'>rate of "
                    f"{html.escape(row['effective_date'])}{source}</span></td>"
                )
            elif row.get("currency") == "mixed" and row.get("by_currency"):
                parts = " + ".join(
                    self._fmt_money(value, currency)
                    for currency, value in row["by_currency"].items()
                )
                cost_cell = (
                    f"<td><strong>{html.escape(parts)}</strong><br>"
                    "<span class='fieldhint'>mixed currencies - shown per "
                    "currency, never summed</span></td>"
                )
            else:
                why = "; ".join(row["missing"]) or "price not recorded"
                cost_cell = "<td>N/A <span class='fieldhint'>" + html.escape(why) + "</span></td>"
            detail.append(
                f"<tr><td>{html.escape(row['role'])}</td>"
                f"<td>{html.escape(row['provider'])}<br><code>"
                f"{html.escape(row['model'][:44])}</code></td>"
                f"<td>{row['calls']:,}"
                + (
                    f"<br><span class='fieldhint'>{row['missing_tokens']} "
                    "with incomplete token usage</span>"
                    if row["missing_tokens"]
                    else ""
                )
                + f"</td>{token_cells}{cost_cell}</tr>"
            )
        heads = "".join(f"<th>{c.replace('_', ' ')}</th>" for c in _TOKEN_CATEGORIES)
        unindexed = not detail and self._has_completion_markers()
        if detail:
            detail_table = (
                "<div class='scroll'><table><tr><th>Role</th><th>Provider / "
                f"model</th><th>Calls</th>{heads}<th>Calculated cost</th></tr>"
                + "".join(detail)
                + "</table></div>"
            )
        elif unindexed:
            # Retained artifacts exist but the derived index is empty (a fresh
            # or stale SQLite file): the spend is UNKNOWN, not $0.  Never show a
            # zero here; prompt a reindex from the artifacts.
            detail_table = (
                "<div class='notice amber'><strong>Recorded usage not indexed."
                "</strong><p class='note'>Completed run artifacts exist under "
                "the results root but this database has no usage rows yet "
                "(a fresh or rebuilt index), so recorded spend is "
                "<strong>unknown, not zero</strong>. "
                "<form class='inline' method='post' action='/db/reindex' "
                "data-busy='Rebuilding the index from retained artifacts...'>"
                "<button type='submit' class='small'>Reindex from artifacts"
                "</button></form></p></div>"
            )
        else:
            detail_table = (
                "<p class='note'>No recorded usage yet. Usage appears here once "
                "a completed run's artifacts are recorded (reconcile on job "
                "finish, or Reindex on the dashboard).</p>"
            )
        # Provider budget summary: prepaid minus calculated spend.  Spend is
        # tracked PER CURRENCY and never summed across currencies; each provider
        # carries a completeness flag (a None-cost row = a model lacks a price).
        # A match prefix that hits no provider with recorded usage shows "no
        # recorded usage", never a fabricated $0.0000.
        by_provider: dict[str, dict] = {}
        for row in cost_rows:
            if not row["billable"]:
                continue
            prov = row["provider"].lower()
            entry = by_provider.setdefault(prov, {"by_ccy": {}, "complete": True})
            if row["cost"] is None:
                entry["complete"] = False
            else:
                # Normalise the currency key (as _fmt_money does) so an
                # inconsistently-cased config never reads all-USD as "mixed".
                ccy = str(row.get("currency") or "USD").upper()
                entry["by_ccy"][ccy] = entry["by_ccy"].get(ccy, 0.0) + row["cost"]
        budget_rows = []
        for name, amount, match, _role in self._budgets():
            matched = [v for p, v in by_provider.items() if p.startswith(match)]
            prepaid = self._parse_money(amount)
            merged: dict[str, float] = {}
            complete = True
            for v in matched:
                complete = complete and v["complete"]
                for ccy, amt in v["by_ccy"].items():
                    merged[ccy] = merged.get(ccy, 0.0) + amt
            if unindexed:
                spent_text = (
                    "unknown <span class='fieldhint'>not indexed - reindex from artifacts</span>"
                )
                remaining = "N/A <span class='fieldhint'>cost incomplete</span>"
            elif not matched:
                # No billable usage recorded under this budget's provider: the
                # spend is genuinely absent, not zero, and there is nothing to
                # net against prepaid.
                spent_text = (
                    "no recorded usage <span class='fieldhint'>no "
                    "billable calls recorded for this provider</span>"
                )
                remaining = "N/A <span class='fieldhint'>no recorded spend to subtract</span>"
            elif not complete:
                spent_text = "N/A <span class='fieldhint'>some models lack a recorded price</span>"
                remaining = "N/A <span class='fieldhint'>cost incomplete</span>"
            elif len(merged) > 1:
                # Different currencies are never summed into one spend nor
                # subtracted from a single prepaid figure.
                spent_text = (
                    " + ".join(self._fmt_money(amt, ccy) for ccy, amt in sorted(merged.items()))
                    + " <span class='fieldhint'>mixed currencies (not summed)"
                    "</span>"
                )
                remaining = (
                    "N/A <span class='fieldhint'>mixed currencies - "
                    "cannot net one prepaid figure</span>"
                )
            else:
                ccy, amt = next(iter(merged.items())) if merged else ("USD", 0.0)
                spent_text = self._fmt_money(amt, ccy)
                if prepaid is None:
                    remaining = "N/A <span class='fieldhint'>prepaid not numeric</span>"
                elif ccy != "USD":
                    # The maintained budgets config records dollar-denominated
                    # prepaid balances (for example "$100").  Never subtract
                    # those dollars from a non-USD spend without an exchange
                    # rate that the console deliberately does not invent.
                    remaining = (
                        "N/A <span class='fieldhint'>prepaid balance is USD; "
                        "no currency conversion recorded</span>"
                    )
                else:
                    remaining = self._fmt_money(prepaid - amt, ccy)
            budget_rows.append(
                f"<tr><td>{html.escape(name)}</td>"
                f"<td><strong>{html.escape(amount)}</strong></td>"
                f"<td>{spent_text}</td><td>{remaining}</td></tr>"
            )
        return (
            "<div class='card'><h2>" + _icon("coins") + "Budgets, usage &amp; calculated cost</h2>"
            "<div class='scroll'><table><tr><th>Provider</th><th>Prepaid</th>"
            "<th>Calculated spend</th><th>Remaining</th></tr>"
            + "".join(budget_rows)
            + "</table></div>"
            + detail_table
            + "<p class='note'>Tokens are the recorded usage read from "
            "completion-bound run artifacts (Response tokens and provider "
            "usage detail; judge-call tokens from completed trails) - never "
            "an estimate. Cost multiplies those tokens by the operator-edited "
            "<a href='/config?file=pricing'>pricing</a> table (effective-"
            "dated); a missing token count or price renders as N/A, never as "
            "zero. <code>target_failed</code>/<code>judge_failed</code> rows are "
            "observable paid work from cells that later errored (operational "
            "spend only, never part of any scientific result); "
            "<code>reserved</code> rows are attempted calls with no recorded "
            "token detail, shown as N/A exposure, never zero. Prepaid budgets "
            "come from the editable <a href='/config?file=budgets'>budgets</a> "
            "config. If a provider ever reports an actually billed amount in an "
            "artifact, that amount is authoritative over this calculation."
            "</p></div>"
        )

    @staticmethod
    def _parse_money(amount: str) -> float | None:
        match = re.fullmatch(r"\$?\s*([0-9]+(?:\.[0-9]+)?)", amount.strip())
        return float(match.group(1)) if match else None

    def _runs_card(self) -> str:
        runs = self.db.list_runs()
        if runs is None:
            return (
                "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
                "<p class='note'><strong>Unavailable</strong> - the console "
                "database cannot be read, so the run registry is unknown "
                "(not empty).</p></div>"
            )
        if not runs:
            return (
                "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
                "<p class='note'>No lanes recorded yet. Each rig_check and "
                "run_matrix job is registered here (kind, output, pinned "
                "revision) as it finishes - durable across console "
                "restarts.</p></div>"
            )
        tone = {"complete": "green", "failed": "red", "running": "blue"}
        work_labels = {
            "preflight": "preflight - no model call",
            "dry_run": "offline dry run - no model call",
            "diagnostic_canary": "diagnostic model-capable run",
            "attestation_probe": "model probe",
            "measured": "model campaign",
        }
        rows = []
        for row in runs:
            state = str(row["state"] or "")
            state_tag = "passed" if state == "complete" else state
            kind = str(row["kind"] or "")
            restored_job = self.jobs.get(str(row["job_id"] or ""))
            if restored_job is not None:
                # Older rows may carry a pre-fix run-kind label. The exact
                # persisted argv is authoritative for this operational view.
                kind = run_kind(restored_job.command, restored_job.argv) or kind
            out = str(row["out_dir"] or "")
            link = f"<a href='/artifacts?path={quote(out)}'>{html.escape(out)}</a>" if out else "-"
            when = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(float(row["created_at"] or 0))
            )
            rows.append(
                f"<tr><td>{when}</td>"
                f"<td><span class='badge {tone.get(state, 'gray')}'>"
                f"{html.escape(state_tag)}</span></td>"
                f"<td>{html.escape(work_labels.get(kind, kind or 'unknown'))}</td>"
                f"<td>{html.escape(str(row['command'] or ''))}</td>"
                f"<td>{link}</td>"
                f"<td><code>{html.escape(str(row['pin'] or '')[:10])}</code>"
                "</td></tr>"
            )
        return (
            "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
            "<div class='scroll'><table><tr><th>When</th><th>State</th><th>Work</th>"
            "<th>Command</th><th>Output</th><th>Pin</th></tr>" + "".join(rows) + "</table></div>"
            "<p class='note'>This is an operational process registry. Passed "
            "means the CLI exited with status 0; it does not by itself prove "
            "that a model generated a response. Preflight and offline dry-run "
            "rows make no model calls. For model-capable rows, only the linked "
            "validated artifacts and recorded usage establish execution.</p>"
            "</div>"
        )

    # -- campaign-first Stats presentation --------------------------------

    @staticmethod
    def _stats_argv_value(argv: list[str], *flags: str) -> str:
        for flag in flags:
            try:
                index = argv.index(flag)
            except ValueError:
                continue
            if index + 1 < len(argv):
                return str(argv[index + 1]).strip()
        return ""

    @classmethod
    def _stats_argv_list(cls, argv: list[str], *flags: str) -> tuple[str, ...]:
        raw = cls._stats_argv_value(argv, *flags)
        return tuple(item.strip() for item in raw.split(",") if item.strip())

    def _stats_resolve_path(self, value: str, *, strict: bool = True) -> Path | None:
        if not value:
            return None
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        try:
            return candidate.resolve(strict=strict)
        except (OSError, RuntimeError):
            return None

    @staticmethod
    def _stats_exact_argv_value(argv: list[str], flag: str) -> str:
        """One unambiguous bounded flag value, or an empty fail-closed result."""

        positions = [index for index, part in enumerate(argv) if part == flag]
        if len(positions) != 1 or positions[0] + 1 >= len(argv):
            return ""
        value = argv[positions[0] + 1].strip()
        if not value or len(value) > 32_768 or "\x00" in value or value.startswith("--"):
            return ""
        return value

    def _stats_artifact_relative(self, path: Path | None) -> str:
        if path is None:
            return ""
        try:
            return path.relative_to(self.results_root.resolve()).as_posix()
        except (OSError, ValueError):
            return ""

    @staticmethod
    def _stats_usage_totals(
        usage_rows: list[dict[str, Any]],
    ) -> dict[tuple[str, str, str, str], dict[str, int]]:
        totals: dict[tuple[str, str, str, str], dict[str, int]] = {}
        for row in usage_rows:
            key = (
                str(row.get("role") or "unknown"),
                str(row.get("provider") or "unknown"),
                str(row.get("model") or "unknown"),
                str(row.get("usage_date") or ""),
            )
            category = str(row.get("category") or "")
            amount = row.get("amount")
            if (
                not category
                or not isinstance(amount, int)
                or isinstance(amount, bool)
                or amount < 0
            ):
                continue
            bucket = totals.setdefault(key, {})
            bucket[category] = bucket.get(category, 0) + amount
        return totals

    @staticmethod
    def _stats_cost_text(cost_rows: list[dict[str, Any]]) -> str:
        billable = [row for row in cost_rows if row.get("billable")]
        if not billable:
            return "local / not billed" if cost_rows else "N/A"
        if any(row.get("cost") is None for row in billable):
            return "N/A (incomplete pricing or usage)"
        by_currency: dict[str, float] = {}
        for row in billable:
            currency = str(row.get("currency") or "")
            cost = row.get("cost")
            if not currency or not isinstance(cost, (int, float)):
                return "N/A (incomplete pricing or usage)"
            by_currency[currency] = by_currency.get(currency, 0.0) + float(cost)
        return " + ".join(
            DashboardMixin._fmt_money(value, currency)
            for currency, value in sorted(by_currency.items())
        )

    @staticmethod
    def _stats_usage_summary(
        usage_rows: list[dict[str, Any]],
    ) -> dict[str, int]:
        summary = {
            "target_calls": 0,
            "judge_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
        }
        for row in usage_rows:
            role = str(row.get("role") or "")
            category = str(row.get("category") or "")
            amount = row.get("amount")
            if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                continue
            if category == "calls":
                if role == "target":
                    summary["target_calls"] += amount
                elif role == "judge":
                    summary["judge_calls"] += amount
            elif category == "input":
                summary["input_tokens"] += amount
            elif category == "output":
                summary["output_tokens"] += amount
        return summary

    @staticmethod
    def _stats_work_label(kind: str) -> str:
        return {
            "acquisition_plan": "model acquisition plan - no model call",
            "preflight": "preflight - no model call",
            "dry_run": "offline dry run - no model call",
            "diagnostic_canary": "diagnostic model-capable run",
            "attestation_probe": "model probe",
            "measured": "model campaign",
        }.get(kind, kind or "unknown")

    @staticmethod
    def _stats_authority(
        *,
        kind: str,
        corpora: tuple[str, ...],
        state: str,
        evidence: Mapping[str, int],
        engineering: bool,
        external_operational: bool = False,
    ) -> tuple[str, str, str]:
        if engineering:
            return "engineering", "engineering / non-thesis", "gray"
        if external_operational:
            # The create-only external registry is an operational ownership and
            # visibility record. Even valid completion artifacts do not turn
            # that record itself into thesis authority; promotion requires a
            # separate validated evidence binding that this schema does not
            # claim to provide.
            return (
                "external-operational",
                "external operational record / non-thesis",
                "gray",
            )
        if kind in {"preflight", "acquisition_plan"}:
            return "preflight", "preflight / no-call", "gray"
        if kind in {"dry_run", "diagnostic_canary", "attestation_probe"}:
            return "diagnostic", "diagnostic / non-thesis", "amber"
        if any("synth" in corpus.casefold() for corpus in corpora):
            return "synthetic", "synthetic / non-authoritative", "amber"
        complete = int(evidence.get("markers", 0))
        invalid = (
            int(evidence.get("skipped_invalid", 0))
            + int(evidence.get("unreadable_artifacts", 0))
            + int(evidence.get("truncated", 0))
        )
        if (
            kind == "measured"
            and corpora
            and state == "complete"
            and complete > 0
            and invalid == 0
        ):
            return "thesis-measured", "thesis measured evidence", "green"
        if kind == "measured":
            return "measured-incomplete", "measured attempt / evidence incomplete", "amber"
        return "unknown", "unclassified / non-authoritative", "gray"

    _STATS_PAGE_SIZE = 24

    def _stats_analysis_job_records(self) -> list[dict[str, Any]]:
        """Live and DB-only analysis Jobs with strict argv recovery.

        ``self.jobs`` is a recent process cache, not retained history.  Live
        records take precedence, while persisted rows restore completed report
        ownership after a console restart.  An oversized DB result fails closed
        instead of treating a truncated producer set as complete.
        """

        records: dict[str, dict[str, Any]] = {}
        live_job_ids: set[str] = set()
        for job in self.jobs.values():
            if job.command not in {"level1_evidence", "level2_report"}:
                continue
            live_job_ids.add(job.job_id)
            # A path from a running/failed producer may name a valid stale file.
            # It becomes campaign evidence only after that exact Job succeeds.
            if job.state() != "complete" or job.exit_code() != 0:
                continue
            argv = list(job.argv)
            if not all(isinstance(part, str) for part in argv):
                continue
            records[job.job_id] = {
                "job_id": job.job_id,
                "command": job.command,
                "argv": argv,
            }
        stored = self.db.load_report_jobs(limit=10_001)
        if stored is None or len(stored) > 10_000:
            return list(records.values())
        for row in stored:
            job_id = str(row["job_id"] or "")
            command = str(row["command"] or "")
            if not job_id or job_id in live_job_ids or command not in {
                "level1_evidence",
                "level2_report",
            }:
                continue
            if str(row["state"] or "") != "complete" or row["exit_code"] != 0:
                continue
            try:
                loaded = strict_json_loads(str(row["argv"] or "[]"))
            except (TypeError, ValueError):
                continue
            if not isinstance(loaded, list) or not all(
                isinstance(part, str) for part in loaded
            ):
                continue
            records[job_id] = {
                "job_id": job_id,
                "command": command,
                "argv": list(loaded),
            }
        return list(records.values())

    def _stats_bounded_run_owners(
        self,
        *,
        external_jobs: list[ExternalMeasuredJob] | None = None,
    ) -> list[dict[str, Any]]:
        """Complete bounded canonical run-output ownership set."""

        rows = self.db.list_run_owners(limit=10_001)
        if rows is None or len(rows) > 10_000:
            return []
        owners: list[dict[str, Any]] = []
        for row in rows:
            job_id = str(row["job_id"] or "")
            root = self._stats_resolve_path(str(row["out_dir"] or ""))
            if not job_id or root is None or not root.is_dir():
                continue
            relative = self._stats_artifact_relative(root)
            if derived_path_quarantined(root, self.results_root):
                continue
            owners.append(
                {
                    "job_id": job_id,
                    "root": root,
                    "artifact_relative": relative,
                }
            )
        if external_jobs is None:
            try:
                external_jobs, _notice = self._external_measured_job_scan()
            except (AttributeError, OSError, ValueError):
                external_jobs = []
        for job in external_jobs:
            # A console-owned row wins an accidental identifier collision.
            # The external registration is never imported or allowed to
            # become a second owner for that same identifier.
            if self.db.load_campaign(job.job_id) is not None:
                continue
            root = job.out_dir
            if not root.is_dir() or derived_path_quarantined(root, self.results_root):
                continue
            owners.append(
                {
                    "job_id": job.job_id,
                    "root": root,
                    "artifact_relative": job.artifact_relative,
                }
            )
        return owners

    def _stats_report_bindings(
        self,
        *,
        external_jobs: list[ExternalMeasuredJob] | None = None,
    ) -> list[dict[str, Any]]:
        """Bind each exact report to one unique most-specific retained run."""

        owners = self._stats_bounded_run_owners(external_jobs=external_jobs)
        if not owners:
            return []
        bindings_by_path: dict[Path, dict[str, Any]] = {}
        ambiguous_paths: set[Path] = set()
        for analysis_job in self._stats_analysis_job_records():
            argv = analysis_job["argv"]
            results_value = self._stats_exact_argv_value(argv, "--results")
            report_value = self._stats_exact_argv_value(argv, "--out-json")
            result_root = self._stats_resolve_path(results_value)
            report_path = self._stats_resolve_path(report_value)
            if (
                result_root is None
                or not result_root.is_dir()
                or report_path is None
                or not report_path.is_file()
            ):
                continue
            raw_report = Path(report_value).expanduser()
            if not raw_report.is_absolute():
                raw_report = self.repo_root / raw_report
            try:
                if raw_report.is_symlink():
                    continue
            except OSError:
                continue
            report_relative = self._stats_artifact_relative(report_path)
            if (
                derived_path_quarantined(result_root, self.results_root)
                or derived_path_quarantined(report_path, self.results_root)
            ):
                continue
            candidates = [
                owner
                for owner in owners
                if owner["root"] == result_root
                or self._stats_contains_path(owner["root"], result_root)
            ]
            if not candidates:
                continue
            deepest = max(len(owner["root"].parts) for owner in candidates)
            most_specific = [
                owner for owner in candidates if len(owner["root"].parts) == deepest
            ]
            owner_ids = {str(owner["job_id"]) for owner in most_specific}
            if len(owner_ids) != 1:
                continue
            binding = {
                "owner_job_id": next(iter(owner_ids)),
                "path": report_relative,
                # Canonical source is retained only in memory. External
                # locators are never rendered or placed in artifact links.
                "source_path": report_path,
                "display_name": report_relative or report_path.name,
                "kind": (
                    "level1"
                    if analysis_job["command"] == "level1_evidence"
                    else "level2"
                ),
                "producer_job_id": str(analysis_job["job_id"]),
            }
            prior = bindings_by_path.get(report_path)
            if prior is None:
                bindings_by_path[report_path] = binding
            elif (
                prior["owner_job_id"] != binding["owner_job_id"]
                or prior["kind"] != binding["kind"]
            ):
                ambiguous_paths.add(report_path)
        return [
            binding
            for path, binding in bindings_by_path.items()
            if path not in ambiguous_paths
        ]

    @staticmethod
    def _stats_external_row(job: ExternalMeasuredJob) -> dict[str, Any]:
        return {
            "job_id": job.job_id,
            "kind": job.run_kind,
            "command": job.command,
            "out_dir": str(job.out_dir),
            "pin": job.expected_commit,
            "state": job.state,
            "exit_code": job.exit_code,
            "created_at": job.started_at,
            "record_source": "external_registration",
            "source_priority": 2,
            "_external_job": job,
        }

    def _stats_console_campaign_prefix(
        self,
        *,
        limit: int,
    ) -> list[dict[str, Any]] | None:
        """Load a bounded prefix so external rows can be paginated exactly."""

        rows: list[dict[str, Any]] = []
        while len(rows) < limit:
            size = min(100, limit - len(rows))
            chunk = self.db.list_campaigns_page(limit=size, offset=len(rows))
            if chunk is None:
                return None
            rows.extend(dict(row) for row in chunk)
            if len(chunk) < size:
                break
        return rows

    def _stats_registered_external_jobs(self) -> tuple[list[ExternalMeasuredJob], str]:
        try:
            jobs, notice = self._external_measured_job_scan()
        except (AttributeError, OSError, ValueError):
            return [], "External measured registry scan unavailable."
        return (
            [
                job
                for job in jobs
                if self.db.load_campaign(job.job_id) is None
            ],
            notice,
        )

    def _stats_run_campaigns(
        self,
        *,
        page: int = 1,
        exact_job_id: str = "",
    ) -> tuple[list[dict[str, Any]], str, bool]:
        external_jobs: list[ExternalMeasuredJob]
        unavailable = ""
        if exact_job_id:
            exact = self.db.load_campaign(exact_job_id)
            if exact is not None:
                runs: list[dict[str, Any]] = [dict(exact)]
                external_jobs = []
            else:
                # Exact detail routes use the direct bounded loader. They must
                # not depend on an arbitrary prefix of the list scanner.
                try:
                    external = self._external_measured_job(exact_job_id)
                except (AttributeError, OSError, ValueError):
                    external = None
                if external is not None and self.db.load_campaign(exact_job_id) is not None:
                    external = None
                external_jobs = [] if external is None else [external]
                runs = [] if external is None else [self._stats_external_row(external)]
            has_more = False
        else:
            external_jobs, external_notice = self._stats_registered_external_jobs()
            unavailable = external_notice
            offset = (page - 1) * self._STATS_PAGE_SIZE
            required = offset + self._STATS_PAGE_SIZE + 1
            bounded_required = min(required, 10_001)
            console_rows = self._stats_console_campaign_prefix(
                limit=bounded_required,
            )
            if console_rows is None:
                console_rows = []
                db_notice = (
                    "Console campaign registry unavailable; externally registered "
                    "measured jobs remain read-only and visible."
                )
                unavailable = " ".join(part for part in (unavailable, db_notice) if part)
            combined = console_rows + [
                self._stats_external_row(job) for job in external_jobs
            ]
            combined.sort(
                key=lambda row: (
                    float(row.get("created_at") or 0),
                    str(row.get("job_id") or ""),
                ),
                reverse=True,
            )
            runs = combined[offset : offset + self._STATS_PAGE_SIZE]
            has_more = len(combined) > offset + self._STATS_PAGE_SIZE
            if required > 10_001 and not runs:
                page_notice = (
                    "Campaign pagination reached the bounded 10,001-row registry view."
                )
                unavailable = " ".join(part for part in (unavailable, page_notice) if part)
        pricing = load_pricing(self.repo_root)
        run_owners = self._stats_bounded_run_owners(external_jobs=external_jobs)
        owners_by_root: dict[Path, set[str]] = {}
        for owner in run_owners:
            owners_by_root.setdefault(owner["root"], set()).add(owner["job_id"])
        owned_roots = tuple(owners_by_root)
        campaigns: list[dict[str, Any]] = []
        for run_row in runs:
            row = dict(run_row)
            job_id = str(row.get("job_id") or "")
            external_job = row.get("_external_job")
            job = self.jobs.get(job_id)
            argv: list[str] = []
            started_at = float(row.get("created_at") or 0)
            ended_at: float | None = None
            state = str(row.get("state") or "unknown")
            command = str(row.get("command") or "")
            terminal_run = str(row.get("record_source") or "run") == "run"
            if isinstance(external_job, ExternalMeasuredJob):
                argv = list(external_job.argv)
                started_at = external_job.started_at
                ended_at = external_job.ended_at
                state = external_job.state
                command = external_job.command
            elif job is not None:
                argv = list(job.argv)
                started_at = float(job.started_at)
                ended_at = job.ended_at
                if not terminal_run:
                    state = job.state()
                    command = job.command
            else:
                stored = self.db.load_job(job_id)
                if stored is not None:
                    try:
                        loaded = strict_json_loads(str(stored["argv"] or "[]"))
                    except (TypeError, ValueError):
                        loaded = []
                    if isinstance(loaded, list) and all(
                        isinstance(part, str) for part in loaded
                    ):
                        argv = list(loaded)
                    started_at = float(stored["started_at"] or started_at)
                    ended_at = (
                        float(stored["ended_at"])
                        if stored["ended_at"] is not None
                        else None
                    )
                    if not terminal_run:
                        state = str(stored["state"] or state)
                        command = str(stored["command"] or command)
            kind = (
                external_job.run_kind
                if isinstance(external_job, ExternalMeasuredJob)
                else run_kind(command, argv) or str(row.get("kind") or "")
            )
            out_dir = str(row.get("out_dir") or "")
            output_root = self._stats_resolve_path(out_dir)
            artifact_relative = self._stats_artifact_relative(output_root)
            quarantined_output = (
                derived_path_quarantined(output_root, self.results_root)
                if output_root is not None
                else False
            )
            uniquely_owned = (
                output_root is not None
                and owners_by_root.get(output_root) == {job_id}
            )
            usage_rows: list[dict[str, Any]] = []
            evidence: dict[str, int] = {
                "markers": 0,
                "skipped_error": 0,
                "skipped_invalid": 0,
                "orphan_responses": 0,
                "truncated": 0,
                "unreadable_artifacts": 0,
                "failed_cells": 0,
            }
            if (
                output_root is not None
                and output_root.is_dir()
                and not quarantined_output
                and uniquely_owned
            ):
                excluded_roots = tuple(
                    root
                    for root in owned_roots
                    if root != output_root
                    and self._stats_contains_path(output_root, root)
                )
                usage_rows, observed = collect_usage(
                    output_root,
                    verify_sha=True,
                    excluded_roots=excluded_roots,
                )
                evidence.update(
                    {
                        key: int(value)
                        for key, value in observed.items()
                        if isinstance(value, int) and not isinstance(value, bool)
                    }
                )
            usage_totals = self._stats_usage_totals(usage_rows)
            cost_rows = compute_costs(usage_totals, pricing)
            usage = self._stats_usage_summary(usage_rows)
            corpora = self._stats_argv_list(argv, "--corpora")
            authority, authority_label, authority_tone = self._stats_authority(
                kind=kind,
                corpora=corpora,
                state=state,
                evidence=evidence,
                engineering=quarantined_output,
                external_operational=isinstance(external_job, ExternalMeasuredJob),
            )
            campaigns.append(
                {
                    "job_id": job_id,
                    "command": command,
                    "argv": argv,
                    "kind": kind,
                    "work_label": self._stats_work_label(kind),
                    "state": state,
                    "started_at": started_at,
                    "ended_at": ended_at,
                    "out_dir": out_dir,
                    "output_root": output_root,
                    "artifact_relative": artifact_relative,
                    "targets": (
                        self._stats_argv_list(argv, "--api", "--models")
                        + self._stats_argv_list(argv, "--local")
                    ),
                    "frameworks": self._stats_argv_list(argv, "--attackers"),
                    "corpora": corpora,
                    "usage_rows": usage_rows,
                    "usage": usage,
                    "cost_rows": cost_rows,
                    "cost_text": self._stats_cost_text(cost_rows),
                    "evidence": evidence,
                    "authority": authority,
                    "authority_label": authority_label,
                    "authority_tone": authority_tone,
                    "reports": [],
                    "external_owned": isinstance(external_job, ExternalMeasuredJob),
                    "_external_job": external_job,
                    "job_href": (
                        f"/jobs/external/{quote(job_id)}"
                        if isinstance(external_job, ExternalMeasuredJob)
                        else f"/jobs/{quote(job_id)}"
                    ),
                }
            )
        return campaigns, unavailable, has_more

    @staticmethod
    def _stats_contains_path(parent: Path, child: Path) -> bool:
        try:
            child.relative_to(parent)
            return True
        except ValueError:
            return False

    def _stats_attach_job_reports(self, campaigns: list[dict[str, Any]]) -> set[str]:
        """Attach exact analysis-job outputs to the run they analysed."""

        attached: set[str] = set()
        by_job_id = {str(campaign["job_id"]): campaign for campaign in campaigns}
        external_jobs = [
            job
            for campaign in campaigns
            if isinstance((job := campaign.get("_external_job")), ExternalMeasuredJob)
        ]
        for binding in self._stats_report_bindings(external_jobs=external_jobs or None):
            owner = by_job_id.get(str(binding["owner_job_id"]))
            if owner is None:
                continue
            owner["reports"].append(binding)
            if binding["path"]:
                attached.add(str(binding["path"]))
        return attached

    def _stats_owned_report_paths(self) -> set[str]:
        owned = {
            str(binding["path"])
            for binding in self._stats_report_bindings()
            if binding["path"]
        }
        try:
            engineering, _notice = self._engineering_campaign_scan()
        except (AttributeError, OSError, ValueError):
            engineering = []
        for campaign in engineering:
            registration = load_external_analysis_registration(
                self.results_root,
                campaign.route_id,
            )
            if registration is not None:
                owned.update(
                    report.artifact_relative for report in registration.reports
                )
        return owned

    @staticmethod
    def _stats_external_analysis_campaign(
        campaign: EngineeringCampaign,
        registration: ExternalAnalysisRegistration,
    ) -> dict[str, Any]:
        evidence = {
            "markers": 0,
            "skipped_error": 0,
            "skipped_invalid": 0,
            "orphan_responses": 0,
            "truncated": 0,
            "unreadable_artifacts": 0,
            "failed_cells": 0,
        }
        reports = [
            {
                "owner_job_id": campaign.route_id,
                "path": report.artifact_relative,
                "source_path": report.path,
                "display_name": report.display_name,
                "kind": report.kind,
                "producer_job_id": campaign.route_id,
                "_external_analysis_report": report,
            }
            for report in registration.reports
        ]
        return {
            "job_id": campaign.route_id,
            "command": "external_analysis",
            "argv": [],
            "kind": "external_analysis",
            "work_label": registration.work_label,
            "state": campaign.status_tag,
            "started_at": campaign.started_at,
            "ended_at": campaign.ended_at,
            "out_dir": str(registration.analysis_root),
            "output_root": registration.analysis_root,
            "artifact_relative": registration.artifact_relative,
            "targets": (),
            "frameworks": (),
            "corpora": (),
            "usage_rows": [],
            "usage": {
                "target_calls": 0,
                "judge_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
            },
            "usage_reported": False,
            "cost_rows": [],
            "cost_text": "not reported by analysis registration",
            "evidence": evidence,
            "authority": "external-analysis",
            "authority_label": "registered external analysis / non-thesis",
            "authority_tone": "blue",
            "reports": reports,
            "analysis_limitations": registration.explicit_limitations,
            "analysis_status": registration.completion_status,
            "external_owned": True,
            "job_href": f"/jobs/campaign/{quote(campaign.route_id)}",
            "_external_analysis_registration": registration,
        }

    @staticmethod
    def _stats_state_badge(state: str) -> tuple[str, str]:
        label = {
            "complete": "passed",
            "complete_with_explicit_limitations": "complete with explicit limitations",
        }.get(state, state or "unknown")
        tone = {
            "complete": "green",
            "complete_with_explicit_limitations": "amber",
            "running": "blue",
            "failed": "red",
            "orphaned": "amber",
        }.get(state, "gray")
        return label, tone

    @staticmethod
    def _stats_list_text(values: tuple[str, ...]) -> str:
        return ", ".join(values) if values else "not declared"

    @staticmethod
    def _stats_coverage_text(evidence: Mapping[str, int]) -> str:
        complete = int(evidence.get("markers", 0))
        failed = int(evidence.get("failed_cells", 0))
        invalid = int(evidence.get("skipped_invalid", 0)) + int(
            evidence.get("unreadable_artifacts", 0)
        )
        text = f"{complete} complete cell{'s' if complete != 1 else ''}"
        extras = []
        if failed:
            extras.append(f"{failed} failed")
        if invalid:
            extras.append(f"{invalid} invalid/unreadable")
        if evidence.get("truncated"):
            extras.append("scan truncated")
        return text + ("; " + ", ".join(extras) if extras else "")

    def _stats_usage_table(self, campaign: Mapping[str, Any]) -> str:
        if campaign.get("usage_reported") is False:
            return (
                "<p class='note'>This external analysis registration does not "
                "carry a model-usage record.</p>"
            )
        rows = []
        for cost in campaign["cost_rows"]:
            tokens = cost["tokens"]
            if not cost["billable"]:
                cost_text = "local / not billed"
            elif cost["cost"] is not None:
                cost_text = self._fmt_money(cost["cost"], cost["currency"])
            elif cost.get("currency") == "mixed" and cost.get("by_currency"):
                cost_text = " + ".join(
                    self._fmt_money(value, currency)
                    for currency, value in sorted(cost["by_currency"].items())
                )
            else:
                cost_text = "N/A"
            rows.append(
                "<tr>"
                f"<td>{html.escape(str(cost['role']))}</td>"
                f"<td>{html.escape(str(cost['provider']))}<br><code>"
                f"{html.escape(str(cost['model']))}</code></td>"
                f"<td>{int(cost['calls']):,}</td>"
                f"<td>{int(tokens['input']):,}</td>"
                f"<td>{int(tokens['output']):,}</td>"
                f"<td>{html.escape(cost_text)}</td></tr>"
            )
        if not rows:
            return "<p class='note'>No completion-bound model usage was recorded.</p>"
        return (
            "<div class='scroll'><table><tr><th>Role</th><th>Provider / model</th>"
            "<th>Calls</th><th>Input tokens</th><th>Output tokens</th>"
            "<th>Calculated cost</th></tr>"
            + "".join(rows)
            + "</table></div>"
        )

    def _stats_campaign_card(self, campaign: Mapping[str, Any]) -> str:
        state_label, state_tone = self._stats_state_badge(str(campaign["state"]))
        job_href = str(campaign.get("job_href") or f"/jobs/{quote(str(campaign['job_id']))}")
        external_badge = (
            "<span class='badge blue'>external / read-only</span>"
            if campaign.get("external_owned") is True
            else ""
        )
        started = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(campaign["started_at"]))
        )
        ended_at = campaign["ended_at"]
        ended = (
            time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(ended_at)))
            if ended_at is not None
            else "running / not recorded"
        )
        usage = campaign["usage"]
        usage_reported = campaign.get("usage_reported") is not False
        calls = (
            f"{usage['target_calls']:,} target / {usage['judge_calls']:,} judge"
            if usage_reported
            else "not reported"
        )
        tokens = (
            f"{usage['input_tokens']:,} input / {usage['output_tokens']:,} output"
            if usage_reported
            else "not reported"
        )
        has_chart = any(
            "class='barchart'" in self._stats_report_card(report)
            for report in campaign["reports"]
        )
        detail_label = "Statistics &amp; diagrams" if has_chart else "Statistics details"
        return (
            "<article class='stats-campaign-card' "
            f"data-job-id='{html.escape(str(campaign['job_id']))}' "
            f"data-authority='{html.escape(str(campaign['authority']))}'>"
            "<div class='stats-campaign-head'><div><h3><a href='"
            f"{html.escape(job_href, quote=True)}'>{html.escape(str(campaign['job_id']))}</a>"
            "</h3><p class='note'>"
            f"{html.escape(str(campaign['work_label']))}</p></div>"
            "<div class='stats-badges'>"
            f"<span class='badge {state_tone}'>{html.escape(state_label)}</span>"
            f"<span class='badge {html.escape(str(campaign['authority_tone']))}'>"
            f"{html.escape(str(campaign['authority_label']))}</span>{external_badge}</div></div>"
            "<dl class='stats-campaign-meta'>"
            f"<dt>Target</dt><dd>{html.escape(self._stats_list_text(campaign['targets']))}</dd>"
            f"<dt>Framework</dt><dd>{html.escape(self._stats_list_text(campaign['frameworks']))}</dd>"
            f"<dt>Corpus</dt><dd>{html.escape(self._stats_list_text(campaign['corpora']))}</dd>"
            f"<dt>Started</dt><dd>{html.escape(started)}</dd>"
            f"<dt>Ended</dt><dd>{html.escape(ended)}</dd>"
            f"<dt>Calls</dt><dd>{html.escape(calls)}</dd>"
            f"<dt>Tokens</dt><dd>{html.escape(tokens)}</dd>"
            f"<dt>Cost</dt><dd>{html.escape(str(campaign['cost_text']))}</dd>"
            f"<dt>Results</dt><dd>{html.escape(self._stats_coverage_text(campaign['evidence']))}</dd>"
            "</dl><div class='stats-campaign-actions'>"
            f"<a class='button ghost stats-detail-trigger' href='/stats/job/"
            f"{quote(str(campaign['job_id']))}' data-stats-job='"
            f"{html.escape(str(campaign['job_id']))}' "
            "aria-controls='campaign-stats-modal' aria-haspopup='dialog' "
            "aria-expanded='false'>"
            f"{detail_label}</a></div></article>"
        )

    def _stats_report_card(self, report: Mapping[str, Any]) -> str:
        rel = str(report.get("path") or "")
        display_name = str(report.get("display_name") or rel or "external report")
        kind = str(report.get("kind") or "")
        registered_report = report.get("_external_analysis_report")
        source = report.get("source_path")
        report_path = source if isinstance(source, Path) else self.results_root / rel
        if isinstance(registered_report, ExternalAnalysisReport):
            doc = load_external_analysis_report(registered_report)
        else:
            try:
                doc = strict_json_loads(report_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                doc = None
        if doc is None:
            return (
                "<div class='card'><h3>"
                + _icon("file")
                + f"{html.escape(display_name)} <span class='badge red'>invalid</span></h3>"
                "<p class='note'>The exact report output is missing or malformed; "
                "no chart is rendered.</p></div>"
            )
        if not isinstance(doc, dict):
            return (
                f"<div class='card'><h3>{html.escape(display_name)} "
                "<span class='badge red'>invalid</span></h3></div>"
            )
        expected = (
            {"ura-level1-evidence/3", "ura-level1-evidence/2"}
            if kind == "level1"
            else {"ura-level2-report/1"}
        )
        if str(doc.get("schema_version")) not in expected:
            return (
                "<div class='card'><h3>"
                + _icon("file")
                + f"{html.escape(display_name)} <span class='badge red'>invalid</span></h3>"
                "<p class='note'>The declared schema does not match this analysis job; "
                "no chart is rendered.</p></div>"
            )
        try:
            _validate_report_document(kind, doc)
        except ValueError as exc:
            return (
                "<div class='card'><h3>"
                + _icon("file")
                + f"{html.escape(display_name)} <span class='badge red'>invalid</span></h3>"
                f"<p class='note'>{html.escape(str(exc))}. Not rendered; no chart "
                "is produced.</p></div>"
            )
        try:
            return (
                self._render_level2(display_name, doc, artifact_relative=rel)
                if kind == "level2"
                else self._render_level1(display_name, doc, artifact_relative=rel)
            )
        except (KeyError, TypeError, ValueError):
            return (
                f"<div class='card'><h3>{html.escape(display_name)} "
                "<span class='badge red'>invalid</span></h3>"
                "<p class='note'>Validated identity but unrenderable structure; "
                "no chart is rendered.</p></div>"
            )

    def _stats_report_index_badge(self, report: Mapping[str, Any]) -> str:
        """Compact validation status for an unlinked report; never a chart."""

        rel = str(report.get("path") or "")
        kind = str(report.get("kind") or "")
        if kind not in {"level1", "level2"}:
            return (
                "<span class='badge red' title='Only Level-1/Level-2 reports "
                "belong in this compatibility list'>unsupported kind</span>"
            )
        try:
            doc = strict_json_loads((self.results_root / rel).read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("report is not an object")
            _validate_report_document(kind, doc)
        except (OSError, TypeError, ValueError) as exc:
            return (
                "<span class='badge red' title='"
                + html.escape(str(exc), quote=True)
                + "'>invalid</span>"
            )
        return "<span class='badge green'>validated but unlinked</span>"

    def _stats_campaign_detail(self, campaign: Mapping[str, Any]) -> str:
        state_label, state_tone = self._stats_state_badge(str(campaign["state"]))
        job_href = str(campaign.get("job_href") or f"/jobs/{quote(str(campaign['job_id']))}")
        artifact_link = ""
        if campaign["artifact_relative"]:
            artifact_link = (
                " <a href='/artifacts?path="
                + quote(str(campaign["artifact_relative"]))
                + "'>Browse exact output artifacts</a>."
            )
        evidence = campaign["evidence"]
        evidence_tone = "green"
        evidence_label = "validated"
        if (
            evidence.get("skipped_invalid")
            or evidence.get("unreadable_artifacts")
            or evidence.get("truncated")
        ):
            evidence_tone = "red"
            evidence_label = "incomplete / invalid"
        elif not evidence.get("markers") and campaign["kind"] not in {
            "preflight",
            "acquisition_plan",
            "dry_run",
            "external_analysis",
        }:
            evidence_tone = "amber"
            evidence_label = "not established"
        reports = "".join(
            self._stats_report_card(report) for report in campaign["reports"]
        )
        if not reports:
            reports = (
                "<div class='card'><p class='note'>No validated Level-1/Level-2 "
                "analysis job is bound to this campaign yet. Completion-bound "
                "usage and result coverage are still shown above.</p></div>"
            )
        external_analysis_note = (
            "<div class='notice blue'><strong>Registered external analysis.</strong>"
            "<p class='note'>The generic operational registration and exact report "
            "bytes were validated before these diagrams were linked. Registration "
            "does not grant thesis-evidence authority. Analysis status: <code>"
            + html.escape(str(campaign.get("analysis_status") or "unknown"))
            + "</code>.</p></div>"
            if campaign.get("_external_analysis_registration") is not None
            else ""
        )
        limitations = campaign.get("analysis_limitations") or ()
        limitations_note = (
            "<div class='notice amber'><strong>Analysis completed with explicit "
            "limitations.</strong><ul>"
            + "".join(
                "<li><code>"
                + html.escape(str(name))
                + "</code>: "
                + html.escape(str(status))
                + "</li>"
                for name, status in limitations
            )
            + "</ul></div>"
            if limitations
            else ""
        )
        return (
            "<p class='stats-detail-state'>Campaign status: "
            f"<span class='badge {state_tone}'>{html.escape(state_label)}</span></p>"
            f"<div class='notice {evidence_tone}'><strong>Evidence {evidence_label}."
            "</strong><p class='note'>"
            f"{html.escape(self._stats_coverage_text(evidence))}. "
            "Charts below are rendered only from producer-contract-validated "
            f"reports attached to this job.{artifact_link}</p></div>"
            + external_analysis_note
            + limitations_note
            + "<div class='card'><h3>Recorded calls, tokens &amp; calculated cost</h3>"
            + self._stats_usage_table(campaign)
            + "<p class='note'>Usage is read only from this job's exact output "
            "root and completion-bound artifacts. It is not mixed with diagnostic, "
            "synthetic, engineering, or temporary trees.</p></div>"
            + reports
            + "<p class='stats-modal-links'><a href='"
            + html.escape(job_href, quote=True)
            + "'>Open full job record</a></p>"
        )

    def _stats_campaign_panel(self, page: int) -> str:
        campaigns, unavailable, has_more = self._stats_run_campaigns(page=page)
        self._stats_attach_job_reports(campaigns)
        cards = [self._stats_campaign_card(campaign) for campaign in campaigns]
        if cards:
            listing = "<div class='stats-campaign-list'>" + "".join(cards) + "</div>"
            if unavailable:
                listing = f"<div class='notice amber'>{html.escape(unavailable)}</div>" + listing
        elif unavailable:
            listing = f"<div class='notice red'>{html.escape(unavailable)}</div>"
        else:
            listing = (
                "<div class='card'><p class='note'>No console-owned or explicitly "
                "registered external campaign jobs are retained yet. Start a preflight, "
                "diagnostic, or measured lane from Build; it will appear here without "
                "importing unrelated files.</p></div>"
            )
        try:
            engineering, engineering_note = self._engineering_campaign_scan()
        except (AttributeError, OSError, ValueError):
            engineering, engineering_note = [], "Engineering campaign scan unavailable."
        engineering_cards = []
        for campaign in engineering:
            label = html.escape(campaign.campaign_id)
            route = quote(campaign.route_id)
            artifact_route = quote(f"engineering/{campaign.route_id}")
            registration = load_external_analysis_registration(
                self.results_root,
                campaign.route_id,
            )
            display_state_label, display_state_tone = self._stats_state_badge(
                campaign.status_tag
            )
            analysis_state = (
                "<dt>Analysis</dt><dd>"
                + html.escape(
                    self._stats_state_badge(registration.completion_status)[0]
                )
                + "</dd>"
                if registration is not None
                else ""
            )
            analysis_action = (
                "<a class='button ghost stats-detail-trigger' href='/stats/job/"
                + route
                + "' data-stats-job='"
                + html.escape(campaign.route_id)
                + "' aria-controls='campaign-stats-modal' aria-haspopup='dialog' "
                "aria-expanded='false'>Statistics &amp; diagrams</a>"
                if registration is not None
                else ""
            )
            engineering_cards.append(
                "<article class='stats-campaign-card engineering' "
                "data-authority='engineering'><div class='stats-campaign-head'>"
                f"<div><h3><a href='/jobs/campaign/{route}'>{label}</a></h3>"
                "<p class='note'>externally managed engineering campaign</p></div>"
                f"<span class='badge {display_state_tone}'>"
                f"{html.escape(display_state_label)}</span>"
                "</div><dl class='stats-campaign-meta'>"
                "<dt>Authority</dt><dd>engineering / non-thesis</dd>"
                f"<dt>Progress</dt><dd>{html.escape(campaign.progress)}</dd>"
                + analysis_state
                + "<dt>Reported calls</dt><dd>"
                + (
                    "not reported"
                    if campaign.model_attempted_calls is None
                    else str(campaign.model_attempted_calls)
                )
                + " (operational self-report)</dd></dl>"
                f"<p><a href='/jobs/campaign/{route}'>Open engineering details</a> "
                f"<a href='/artifacts?path={artifact_route}'>Browse campaign artifacts</a></p>"
                + analysis_action
                + "</article>"
            )
        engineering_html = (
            "<h2>Engineering campaigns <span class='badge gray'>never thesis "
            "evidence</span></h2>"
            + (
                f"<div class='notice amber'>{html.escape(engineering_note)}</div>"
                if engineering_note
                else ""
            )
            + (
                "<div class='stats-campaign-list'>"
                + "".join(engineering_cards)
                + "</div>"
                if engineering_cards
                else "<p class='note'>No external engineering campaigns retained.</p>"
            )
        )
        page_links = "<nav class='stats-pagination' aria-label='Campaign pages'>"
        if page > 1:
            page_links += f"<a class='button ghost' href='/stats?page={page - 1}'>Newer</a>"
        page_links += f"<span>Page {page}</span>"
        if has_more:
            page_links += f"<a class='button ghost' href='/stats?page={page + 1}'>Older</a>"
        page_links += "</nav>"
        reusable_modal = (
            "<section class='stats-modal' id='campaign-stats-modal' data-stats-modal "
            "role='dialog' aria-modal='false' aria-labelledby='campaign-stats-title' "
            "tabindex='-1'><div class='stats-modal-shell'>"
            "<header class='stats-modal-head'><div><p class='wizard-kicker'>"
            "Campaign details</p><h2 id='campaign-stats-title'>"
            "<span data-stats-modal-title>Statistics &amp; diagrams</span>"
            "</h2></div><button type='button' class='ghost small "
            "stats-modal-close' data-stats-close aria-label='Close campaign "
            "statistics'>Close</button></header><div class='stats-modal-body' "
            "data-stats-modal-body aria-live='polite'><p class='note'>Choose a "
            "campaign to load its validated details.</p></div></div></section>"
        )
        return (
            "<h2>Campaign runs</h2>"
            "<p class='note'>Externally managed campaign records appear first, "
            "followed by console run attempts. Passed means the CLI exited with "
            "status 0 for a console run attempt; external campaign status comes "
            "from its generic terminal record. Only completion-bound artifacts "
            "establish model execution. "
            "Thesis-measured, diagnostic, synthetic, engineering, and preflight "
            "work remain visibly separate.</p>"
            + engineering_html
            + "<h2>Console run attempts</h2>"
            + listing
            + page_links
            + reusable_modal
            + self._stats_modal_script()
        )

    def _stats_job_detail_page(
        self,
        job_id: str,
        *,
        fragment: bool,
    ) -> bytes | None:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_id) is None:
            return None
        self._reconcile()
        campaigns, unavailable, _has_more = self._stats_run_campaigns(
            exact_job_id=job_id
        )
        if not campaigns:
            try:
                engineering = self._engineering_campaign(job_id)
            except (AttributeError, OSError, ValueError):
                engineering = None
            registration = (
                load_external_analysis_registration(self.results_root, job_id)
                if engineering is not None
                else None
            )
            if engineering is None or registration is None:
                return None
            campaigns = [
                self._stats_external_analysis_campaign(engineering, registration)
            ]
            unavailable = ""
        if unavailable:
            return None
        campaign = campaigns[0]
        if campaign.get("_external_analysis_registration") is None:
            self._stats_attach_job_reports(campaigns)
        detail = self._stats_campaign_detail(campaign)
        if fragment:
            return detail.encode("utf-8")
        title = f"Campaign statistics: {job_id}"
        return _page(
            title,
            "<p><a href='/stats'>&larr; Back to campaign statistics</a></p>"
            f"<h1>{_icon('chart', size=22)}{html.escape(job_id)}</h1>"
            + detail,
            active="Stats",
        )

    @staticmethod
    def _stats_modal_script() -> str:
        return """<script>(function(){
var root=document.documentElement;root.classList.add('stats-modal-ready');
var modal=document.getElementById('campaign-stats-modal');
var body=modal&&modal.querySelector('[data-stats-modal-body]');
var title=modal&&modal.querySelector('[data-stats-modal-title]');
var active=false,lastFocus=null,requestId=0;
function focusable(modal){return Array.prototype.slice.call(modal.querySelectorAll(
'a[href],button:not([disabled]),[tabindex]:not([tabindex="-1"])'))
.filter(function(node){return !node.hidden;});}
function close(){if(!active||!modal){return;}modal.classList.remove('is-open');
modal.setAttribute('aria-modal','false');document.body.classList.remove(
'stats-modal-open');var prior=lastFocus;active=false;lastFocus=null;requestId++;
if(prior){prior.setAttribute('aria-expanded','false');}
if(prior&&prior.focus){prior.focus();}}
function open(opener){if(!modal||!body){return;}if(active){close();}
active=true;lastFocus=opener||document.activeElement;modal.classList.add('is-open');
modal.setAttribute('aria-modal','true');document.body.classList.add(
'stats-modal-open');var nodes=focusable(modal);(nodes[0]||modal).focus();}
document.querySelectorAll('[data-stats-job]').forEach(function(trigger){
trigger.addEventListener('click',function(event){event.preventDefault();
open(trigger);if(title){title.textContent=trigger.getAttribute('data-stats-job')||
'Campaign statistics';}trigger.setAttribute('aria-expanded','true');
var current=++requestId;body.setAttribute('aria-busy','true');
body.innerHTML="<p class='note'>Loading " +
"validated campaign statistics...</p>";var separator=trigger.href.indexOf('?')>=0?'&':'?';
fetch(trigger.href+separator+'fragment=1',{credentials:'same-origin',headers:{
'X-Requested-With':'ura-stats-modal'}}).then(function(response){
if(!response.ok){throw new Error('detail request failed');}return response.text();})
.then(function(markup){if(active&&current===requestId){body.innerHTML=markup;
body.removeAttribute('aria-busy');}})
.catch(function(){if(active&&current===requestId){body.innerHTML=
"<div class='notice red'>Campaign details could not be loaded. <a href='"+
trigger.href+"'>Open the standalone detail page</a>.</div>";
body.removeAttribute('aria-busy');}});});});
document.querySelectorAll('[data-stats-close]').forEach(function(button){
button.addEventListener('click',close);});
if(modal){modal.addEventListener('click',function(event){
if(event.target===modal){close();}});}
document.addEventListener('keydown',function(event){if(!active){return;}
if(event.key==='Escape'){event.preventDefault();close();return;}
if(event.key!=='Tab'){return;}var nodes=focusable(modal);if(!nodes.length){
event.preventDefault();modal.focus();return;}var first=nodes[0],last=nodes[nodes.length-1];
if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}});
})();</script>"""

    def _report_index(self) -> list[dict[str, Any]]:
        """Unlinked-compatible Level-1/2 reports, DB index then live scan."""

        rows = self.db.list_reports()
        if rows:
            candidates = [dict(row) for row in rows]
        else:
            candidates = collect_reports(self.results_root)
        reports = []
        for report in candidates:
            relative = str(report.get("path") or "")
            if (
                str(report.get("kind") or "") in {"level1", "level2"}
                and relative
                and not derived_path_quarantined(
                    self.results_root / relative,
                    self.results_root,
                )
            ):
                reports.append(report)
        return reports

    #: The fields that define a compatible Level-2 metric stratum.  Two
    #: estimates may share a chart/section ONLY when every one of these matches
    #: - so the same metric in two different populations, sources, policies,
    #: modalities, attackers, defenses or judges is charted separately, never
    #: pooled or mislabelled by the first row's metadata.
    _LEVEL2_COMPAT_FIELDS = _LEVEL2_STRATUM_FIELDS
    #: Chart bars are capped for legibility; the table always shows every row,
    #: so nothing is silently dropped.
    _LEVEL2_CHART_CAP = 40

    def _render_level2(
        self,
        rel: str,
        doc: Mapping[str, Any],
        *,
        artifact_relative: str | None = None,
    ) -> str:
        """Render one ura-level2-report/1: real estimate rows, one chart per
        COMPATIBLE metric stratum, never a cross-stratum combination or a
        universal score."""

        common = doc.get("common")
        estimates = common.get("estimates") if isinstance(common, Mapping) else None
        if not isinstance(estimates, list) or not estimates:
            return (
                "<div class='card'><h2>"
                + _icon("chart")
                + f"{html.escape(rel)}</h2><p class='note'>Validated Level-2 "
                "report with no common estimate rows (native-only or empty)."
                "</p></div>"
            )
        contains_approximate = any(
            isinstance(row, Mapping)
            and row.get("metric_authority") == "supplementary_non_authoritative"
            for row in estimates
        )
        by_stratum: dict[tuple, list[Mapping[str, Any]]] = {}
        for row in estimates:
            if not isinstance(row, Mapping):
                continue
            key = tuple(
                json.dumps(
                    row.get(field),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                for field in self._LEVEL2_COMPAT_FIELDS
            )
            by_stratum.setdefault(key, []).append(row)
        sections = []
        for key in sorted(by_stratum):
            rows = by_stratum[key]
            fields = {
                name: strict_json_loads(value)
                for name, value in zip(self._LEVEL2_COMPAT_FIELDS, key)
            }
            # The section label reflects THIS stratum's own compatibility
            # fields (they are identical for every row in the group), never a
            # single arbitrary row's metadata standing in for a mixed set.
            label_parts = []
            for name, value in fields.items():
                if value is None or value == "":
                    continue
                shown = (
                    value
                    if isinstance(value, str)
                    else json.dumps(
                        value,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                label_parts.append(f"<span class='modtag'>{html.escape(name + '=' + shown)}</span>")
            label_bits = "".join(label_parts)
            values = [row.get("value") for row in rows]
            chartable = all(
                isinstance(v, (int, float)) and not isinstance(v, bool) and 0.0 <= float(v) <= 1.0
                for v in values
            )
            if chartable:
                bars = [
                    (
                        f"{row.get('model_spec', '?')} · {row.get('resolved_model', '?')}",
                        float(row.get("value", 0.0)),
                    )
                    for row in rows[: self._LEVEL2_CHART_CAP]
                ]
                chart = self._bar_chart(bars)
                if len(rows) > self._LEVEL2_CHART_CAP:
                    chart += (
                        f"<p class='note'>Chart shows {self._LEVEL2_CHART_CAP} "
                        f"of {len(rows)} rows; all {len(rows)} are in the table "
                        "below.</p>"
                    )
            else:
                chart = (
                    "<p class='note'>Not charted: values are not rates in "
                    "[0, 1]; the table below is the presentation.</p>"
                )
            table_rows = []
            for row in rows:  # every bounded row, never truncated
                ci_low, ci_high = row.get("ci_low"), row.get("ci_high")
                ci = (
                    f"[{ci_low:.3f}, {ci_high:.3f}]"
                    if isinstance(ci_low, (int, float)) and isinstance(ci_high, (int, float))
                    else "N/A (no CI recorded)"
                )
                completed = row.get("judgments_completed")
                decided = row.get("judgments_decided")
                coverage = (
                    f"{decided}/{completed}"
                    if isinstance(decided, int) and isinstance(completed, int)
                    else "N/A"
                )
                n_clusters = row.get("n_clusters")
                value = row.get("value")
                value_text = (
                    f"{float(value):.4f}"
                    if isinstance(value, (int, float)) and not isinstance(value, bool)
                    else "N/A"
                )
                if row.get("metric_authority") == "supplementary_non_authoritative":
                    synthetic = row.get("evidence_class") == "synthetic"
                    evidence = (
                        "⚠ synthetic + approximate"
                        if synthetic
                        else "⚠ approximate"
                    )
                    reliability = row.get("reliability_score")
                    reliability_text = (
                        f"{float(reliability):.4f} heuristic (not probability)"
                        if isinstance(reliability, (int, float))
                        and not isinstance(reliability, bool)
                        else "invalid/missing"
                    )
                else:
                    evidence = "authoritative/source-native"
                    reliability_text = "N/A"
                query_count = row.get("approximate_model_query_count")
                reference_count = row.get(
                    "approximate_source_reference_use_count"
                )
                proxy_support = (
                    f"{query_count}/{reference_count}"
                    if isinstance(query_count, int)
                    and isinstance(reference_count, int)
                    else "N/A"
                )
                table_rows.append(
                    f"<tr><td><code>{html.escape(str(row.get('model_spec', '')))}"
                    "</code></td>"
                    f"<td>{html.escape(str(row.get('corpus_arm', '')))}</td>"
                    f"<td>{html.escape(str(row.get('attacker', '')))}</td>"
                    f"<td>{html.escape(str(row.get('defense', '')))}</td>"
                    f"<td><strong>{value_text}</strong></td>"
                    f"<td>{ci}</td>"
                    f"<td>{html.escape(str(row.get('n_records', 'N/A')))}</td>"
                    f"<td>{html.escape(str(n_clusters) if n_clusters is not None else 'N/A')}</td>"
                    f"<td>{coverage}</td>"
                    f"<td>{proxy_support}</td>"
                    f"<td>{html.escape(evidence)}</td>"
                    f"<td>{html.escape(reliability_text)}</td></tr>"
                )
            authority_badge = ""
            authority_note = ""
            if rows[0].get("metric_authority") == "supplementary_non_authoritative":
                synthetic = rows[0].get("evidence_class") == "synthetic"
                authority_badge = (
                    " <span class='badge red'>⚠ synthetic + approximate</span>"
                    if synthetic
                    else " <span class='badge amber'>⚠ approximate</span>"
                )
                authority_note = (
                    "<p class='note'>Supplementary, non-authoritative response "
                    "proxy. Reliability is an uncalibrated heuristic, not a "
                    "probability or accuracy estimate.</p>"
                )
            sections.append(
                f"<h3>{html.escape(str(fields['metric']))}{authority_badge} "
                f"<span class='fieldhint'>({len(rows)} row(s))</span><br>"
                + label_bits
                + "</h3>"
                + authority_note
                + chart
                + "<div class='scroll'><table><tr><th>model_spec</th>"
                "<th>corpus_arm</th><th>attacker</th><th>defense</th>"
                "<th>value</th><th>ci_low, ci_high</th><th>n_records</th>"
                "<th>n_clusters</th><th>decided/completed</th>"
                "<th>model queries/reference uses</th><th>evidence</th>"
                "<th>reliability</th></tr>"
                + "".join(table_rows)
                + "</table></div>"
            )
        if artifact_relative is None:
            artifact_relative = rel
        artifact_note = (
            f"<p class='note'><a href='/artifacts?path={quote(artifact_relative)}'>open "
            "the full validated artifact &rarr;</a></p>"
            if artifact_relative
            else "<p class='note'>This report is retained outside the configured "
            "artifact root, so no artifact-browser link is offered.</p>"
        )
        return (
            "<div class='card'><h2>"
            + _icon("chart")
            + f"{html.escape(rel)} <span class='badge blue'>measured artifact</span>"
            + (
                " <span class='badge amber'>contains supplementary proxies</span>"
                if contains_approximate
                else ""
            )
            + "</h2>"
            + "<p class='note'>Deterministic Level-2 export "
            "(<code>common.estimates</code>). One chart per COMPATIBLE metric "
            "stratum (exact run/served target/source/policy/modality/population/"
            "attacker/defense/judge/sampling condition); distinct targets or "
            "runs are not presented as a ranking, and no universal safety "
            "score exists. Diagnostic evidence cannot reach this report by "
            "construction.</p>"
            + "".join(sections)
            + artifact_note
            + "</div>"
        )

    def _render_level1(
        self,
        rel: str,
        doc: Mapping[str, Any],
        *,
        artifact_relative: str | None = None,
    ) -> str:
        """Render one supported Level-1 artifact: separate unit ledgers with the
        real count fields, diagnostic/measured distinct."""

        scope = doc.get("scope") if isinstance(doc.get("scope"), Mapping) else {}
        counts = doc.get("counts") if isinstance(doc.get("counts"), Mapping) else {}
        kind = str(scope.get("evidence_kind", "unknown"))
        # Map ONLY the exact measured evidence kind to the measured badge.
        # Diagnostic stays diagnostic; a missing, malformed, or unknown kind is
        # unknown/invalid - never silently promoted to measured.
        if kind == "measured_run":
            badge = "<span class='badge blue'>measured</span>"
        elif kind == "diagnostic_dry_run":
            badge = "<span class='badge amber'>diagnostic dry-run</span>"
        else:
            badge = (
                "<span class='badge gray'>unknown/invalid evidence kind"
                f" ({html.escape(kind)})</span>"
            )
        tables = []
        for title, key in (
            ("Prospective request units", "prospective_request_units"),
            ("Planning strata", "planning_strata"),
            ("Execution units", "execution_units"),
            ("Judgment records", "judgment_records"),
            (
                "Supplementary approximate proxy judgment records",
                "approximate_proxy_judgment_records",
            ),
            ("Request-level errors", "request_level_errors"),
        ):
            block = counts.get(key)
            if not isinstance(block, Mapping):
                tables.append(
                    f"<h3>{html.escape(title)}</h3><p class='note'>"
                    "N/A - not supplied in this artifact.</p>"
                )
                continue
            cells = "".join(
                "<tr><td>"
                + html.escape(str(name).replace("_", " "))
                + "</td><td>"
                + (
                    "null (by design)"
                    if value is None
                    else f"{value:,}"
                    if isinstance(value, int) and not isinstance(value, bool)
                    else html.escape(str(value))  # malformed count: show raw,
                    #                                never crash the whole page
                )
                + "</td></tr>"
                for name, value in block.items()
                if name != "unit"
            )
            tables.append(
                f"<h3>{html.escape(title)} <span class='modtag'>"
                f"{html.escape(str(block.get('unit', '')))}</span></h3>"
                "<div class='scroll'><table>" + cells + "</table></div>"
            )
        if artifact_relative is None:
            artifact_relative = rel
        artifact_note = (
            f"<p class='note'><a href='/artifacts?path={quote(artifact_relative)}'>open "
            "the full validated artifact &rarr;</a></p>"
            if artifact_relative
            else "<p class='note'>This report is retained outside the configured "
            "artifact root, so no artifact-browser link is offered.</p>"
        )
        return (
            "<div class='card'><h2>" + _icon("file") + f"{html.escape(rel)} {badge}</h2>"
            "<p class='note'>Level-1 lifecycle inventory. Request units, "
            "planning strata, execution units, and judgment records are "
            "separate unit ledgers and are never summed into each other; "
            "structural N/A, missing, and error are distinct states.</p>"
            + "".join(tables)
            + artifact_note
            + "</div>"
        )

    def _stats_page(self, query: Mapping[str, str] | None = None) -> bytes:
        self._reconcile()
        raw_page = str((query or {}).get("page", "1"))
        try:
            page = int(raw_page)
        except ValueError:
            page = 1
        page = min(max(page, 1), 100_000)
        campaign_panel = self._stats_campaign_panel(page)
        attached_reports = self._stats_owned_report_paths()
        reports = self._report_index()
        listed = []
        for report in reports:
            rel = str(report["path"])
            if (
                str(report.get("kind") or "") not in {"level1", "level2"}
                or rel in attached_reports
                or derived_index_path_quarantined(rel)
                or derived_path_quarantined(
                    self.results_root / rel,
                    self.results_root,
                )
            ):
                continue
            listed.append(
                f"<li><a href='/artifacts?path={quote(rel)}'>"
                f"{html.escape(rel)}</a> <span class='modtag'>"
                f"{html.escape(str(report['kind']))}</span> "
                f"{self._stats_report_index_badge(report)}</li>"
            )
        results = (
            "<div class='card'><h2>" + _icon("file") + "Unlinked report artifacts</h2>"
            f"<ul>{''.join(listed)}</ul></div>"
            if listed
            else "<div class='card'><p class='note'>No Level-1/Level-2 report "
            "artifacts remain unlinked. Analysis jobs attached to a campaign "
            "appear only in that campaign's Statistics &amp; diagrams modal.</p></div>"
        )
        unlinked_panel = (
            "<div class='notice amber'><strong>Unlinked analysis artifacts are "
            "not campaign evidence.</strong><p class='note'>This compatibility "
            "view contains only report schemas outside explicit analysis-job "
            "bindings. It never contributes to a thesis aggregate. Engineering "
            "and temporary subtrees are excluded. Full tables are not expanded "
            "here; bind an analysis Job to a campaign to render its diagrams in "
            "that job's detail view.</p></div>"
            + results
        )
        stats_tabs = (
            ("stats-campaigns", "Campaigns"),
            ("stats-operational", "Operational cost"),
            ("stats-unlinked", "Unlinked reports"),
        )
        body = (
            "<h1>"
            + _icon("chart", size=22)
            + "Campaign statistics</h1>"
            + self._health_banner()
            + "<div class='notice blue'><strong>Campaign-first evidence view.</strong>"
            "<p class='note'>Each card is one retained console Job/run. Calls, "
            "tokens, costs, coverage, and diagrams stay bound to that job; "
            "non-authoritative diagnostics are never blended into thesis "
            "results.</p></div>"
            + "<div class='page-tabs' data-page-tabs data-tab-key='stats' "
            "data-default-tab='stats-campaigns'>"
            + _page_tablist("Statistics sections", stats_tabs, default="stats-campaigns")
            + _page_tabpanel("stats-campaigns", campaign_panel)
            + _page_tabpanel(
                "stats-operational",
                "<p class='note'>Operational spend is accounting only; it is "
                "never a scientific aggregate.</p>" + self._spend_card(),
            )
            + _page_tabpanel("stats-unlinked", unlinked_panel)
            + "</div>"
        )
        return _page("Campaign statistics", body, active="Stats")

    # -- campaign builder --------------------------------------------------

    def _dashboard_hardware_card(self) -> str:
        gpus = [gpu for gpu in self.gpu_hardware.get("gpus", []) if isinstance(gpu, Mapping)]
        if not self.gpu_hardware.get("available"):
            summary = "No NVIDIA GPU detected; local model fit is unknown."
        else:
            names = ", ".join(
                f"GPU {gpu.get('index', '?')}: {gpu.get('name', 'unknown')} "
                f"({gpu.get('vram_gib', '?')} GiB, SM {gpu.get('compute_capability', '?')})"
                for gpu in gpus
            )
            summary = (
                f"{self.gpu_hardware.get('gpu_count', len(gpus))} GPU(s), "
                f"{self.gpu_hardware.get('aggregate_vram_gib', 0)} GiB aggregate VRAM"
                + (f" - {names}" if names else "")
            )
        system = self.system_hardware

        def shown(value: object, suffix: str = "") -> str:
            if value is None or value == "":
                return "unknown"
            return html.escape(str(value)) + suffix

        physical = system.get("physical_cpu_count")
        logical = system.get("logical_cpu_count")
        cores = (
            f"{physical if physical is not None else '?'} physical / "
            f"{logical if logical is not None else '?'} logical"
        )
        gpu_rows = []
        for gpu in gpus:
            details = [f"{shown(gpu.get('vram_gib'))} GiB VRAM"]
            if gpu.get("compute_capability"):
                details.append("SM " + shown(gpu["compute_capability"]))
            if gpu.get("pci_bus_id"):
                details.append("PCI " + shown(gpu["pci_bus_id"]))
            if gpu.get("driver_version"):
                details.append("driver " + shown(gpu["driver_version"]))
            gpu_rows.append(
                "<li><strong>GPU "
                + shown(gpu.get("index", "?"))
                + " - "
                + shown(gpu.get("name", "unknown"))
                + "</strong>"
                "<span class='fieldhint'>" + " &middot; ".join(details) + "</span></li>"
            )
        gpu_content = (
            "<ul class='hardware-list'>" + "".join(gpu_rows) + "</ul>"
            if self.gpu_hardware.get("available") and gpu_rows
            else "<div class='notice amber'>No NVIDIA GPU detected; local model "
            "fit is unknown.</div>"
        )
        return (
            "<div class='card' id='rig-hardware' aria-label='"
            + html.escape(summary, quote=True)
            + "'><h2>Rig hardware</h2>"
            "<div class='hardware-grid'><section><h3>System</h3>"
            "<dl class='hardware-spec'><dt>OS</dt><dd>"
            + shown(system.get("platform"))
            + "</dd><dt>CPU</dt><dd>"
            + shown(system.get("cpu_model"))
            + "</dd><dt>Cores</dt><dd>"
            + html.escape(cores)
            + "</dd><dt>RAM</dt><dd>"
            + shown(system.get("total_ram_gib"), " GiB")
            + "</dd></dl></section><section><h3>GPUs "
            "<span class='badge blue'>"
            + shown(self.gpu_hardware.get("gpu_count", len(gpus)))
            + "</span></h3>"
            + gpu_content
            + "</section></div>"
            "<p class='note'>Detected once at console startup; no model or "
            "provider call is made. Aggregate VRAM: <strong>"
            + shown(self.gpu_hardware.get("aggregate_vram_gib"), " GiB")
            + "</strong>.</p></div>"
        )
