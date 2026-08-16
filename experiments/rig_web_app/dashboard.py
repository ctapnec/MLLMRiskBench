"""Warnings, reports, statistics, and dashboard rendering."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import time
from typing import Any, Mapping
from urllib.parse import quote

from .catalog import _WARNINGS_FILE, _WARNINGS_MAX, _WARNING_TONES, _CAMPAIGN_POLICY, _icon

from .ui import _page

from .artifacts import StageInventory, _TOKEN_CATEGORIES, iter_completed_markers

from .reports import (
    _LEVEL2_STRATUM_FIELDS,
    _validate_report_document,
    collect_reports,
    load_pricing,
    compute_costs,
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
            raw = json.loads(path.read_text(encoding="utf-8"))
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

    @staticmethod
    def _policy_card() -> str:
        rows = "".join(
            f"<tr><td>{html.escape(term)}</td><td>{html.escape(rule)}</td></tr>"
            for term, rule in _CAMPAIGN_POLICY
        )
        return (
            "<div class='card'><h2>" + _icon("receipt") + "Campaign sampling policy</h2>"
            "<div class='scroll'><table>" + rows + "</table></div>"
            "<p class='note'>Operator-recorded policy (thesis ledger "
            "Sections 11.22/11.27; runbook section 5.2). Enforcement lives "
            "in each recorded run_matrix invocation, not in this card.</p>"
            "</div>"
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
        rows = []
        for row in runs:
            state = str(row["state"] or "")
            out = str(row["out_dir"] or "")
            link = f"<a href='/artifacts?path={quote(out)}'>{html.escape(out)}</a>" if out else "-"
            when = time.strftime("%m-%d %H:%M", time.localtime(float(row["created_at"] or 0)))
            rows.append(
                f"<tr><td>{when}</td>"
                f"<td><span class='badge {tone.get(state, 'gray')}'>"
                f"{html.escape(str(row['kind'] or ''))}</span></td>"
                f"<td>{html.escape(str(row['command'] or ''))}</td>"
                f"<td>{link}</td>"
                f"<td><code>{html.escape(str(row['pin'] or '')[:10])}</code>"
                "</td></tr>"
            )
        return (
            "<div class='card'><h2>" + _icon("book") + "Campaign runs</h2>"
            "<div class='scroll'><table><tr><th>When</th><th>Kind</th>"
            "<th>Command</th><th>Output</th><th>Pin</th></tr>" + "".join(rows) + "</table></div>"
            "<p class='note'>Every rig_check/run_matrix lane, recorded as it "
            "finishes and durable across restarts. This is an operational "
            "index; the validated artifacts it links remain authoritative.</p>"
            "</div>"
        )

    def _report_index(self) -> list[dict[str, Any]]:
        """Indexed report artifacts: the database index, else a live scan."""

        rows = self.db.list_reports()
        if rows:
            return [dict(row) for row in rows]
        return collect_reports(self.results_root)

    #: The fields that define a compatible Level-2 metric stratum.  Two
    #: estimates may share a chart/section ONLY when every one of these matches
    #: - so the same metric in two different populations, sources, policies,
    #: modalities, attackers, defenses or judges is charted separately, never
    #: pooled or mislabelled by the first row's metadata.
    _LEVEL2_COMPAT_FIELDS = _LEVEL2_STRATUM_FIELDS
    #: Chart bars are capped for legibility; the table always shows every row,
    #: so nothing is silently dropped.
    _LEVEL2_CHART_CAP = 40

    def _render_level2(self, rel: str, doc: Mapping[str, Any]) -> str:
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
                name: json.loads(value) for name, value in zip(self._LEVEL2_COMPAT_FIELDS, key)
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
                    f"<td>{coverage}</td></tr>"
                )
            sections.append(
                f"<h3>{html.escape(str(fields['metric']))} "
                f"<span class='fieldhint'>({len(rows)} row(s))</span><br>"
                + label_bits
                + "</h3>"
                + chart
                + "<div class='scroll'><table><tr><th>model_spec</th>"
                "<th>corpus_arm</th><th>attacker</th><th>defense</th>"
                "<th>value</th><th>ci_low, ci_high</th><th>n_records</th>"
                "<th>n_clusters</th><th>decided/completed</th></tr>"
                + "".join(table_rows)
                + "</table></div>"
            )
        return (
            "<div class='card'><h2>"
            + _icon("chart")
            + f"{html.escape(rel)} <span class='badge blue'>measured</span>"
            "</h2>"
            "<p class='note'>Deterministic Level-2 export "
            "(<code>common.estimates</code>). One chart per COMPATIBLE metric "
            "stratum (exact run/served target/source/policy/modality/population/"
            "attacker/defense/judge/sampling condition); distinct targets or "
            "runs are not presented as a ranking, and no universal safety "
            "score exists. Diagnostic evidence cannot reach this report by "
            "construction.</p>"
            + "".join(sections)
            + f"<p class='note'><a href='/artifacts?path={quote(rel)}'>open "
            "the full validated artifact &rarr;</a></p></div>"
        )

    def _render_level1(self, rel: str, doc: Mapping[str, Any]) -> str:
        """Render one ura-level1-evidence/2: separate unit ledgers with the
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
        return (
            "<div class='card'><h2>" + _icon("file") + f"{html.escape(rel)} {badge}</h2>"
            "<p class='note'>Level-1 lifecycle inventory. Request units, "
            "planning strata, execution units, and judgment records are "
            "separate unit ledgers and are never summed into each other; "
            "structural N/A, missing, and error are distinct states.</p>"
            + "".join(tables)
            + f"<p class='note'><a href='/artifacts?path={quote(rel)}'>open "
            "the full validated artifact &rarr;</a></p></div>"
        )

    def _stats_page(self) -> bytes:
        self._reconcile()
        reports = self._report_index()
        cards = []
        listed = []
        for report in reports:
            rel = str(report["path"])
            listed.append(
                f"<li><a href='/artifacts?path={quote(rel)}'>"
                f"{html.escape(rel)}</a> <span class='modtag'>"
                f"{html.escape(str(report['kind']))}</span></li>"
            )
            if report["kind"] not in {"level1", "level2"} or len(cards) >= 6:
                continue
            try:
                doc = json.loads((self.results_root / rel).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict):
                continue
            # Validate the declared schema before rendering, so a malformed or
            # mislabelled artifact is shown as invalid rather than rendered (and
            # possibly badged measured) from untrusted content.
            expected = {"level1": "ura-level1-evidence/2", "level2": "ura-level2-report/1"}[
                report["kind"]
            ]
            if str(doc.get("schema_version")) != expected:
                cards.append(
                    "<div class='card'><h2>"
                    + _icon("file")
                    + f"{html.escape(rel)} <span class='badge red'>invalid"
                    "</span></h2><p class='note'>Declared schema "
                    f"<code>{html.escape(str(doc.get('schema_version')))}</code> "
                    f"does not match the expected <code>{expected}</code>; not "
                    "rendered.</p></div>"
                )
                continue
            try:
                _validate_report_document(str(report["kind"]), doc)
            except ValueError as exc:
                cards.append(
                    "<div class='card'><h2>"
                    + _icon("file")
                    + f"{html.escape(rel)} <span class='badge red'>invalid"
                    "</span></h2><p class='note'>The declared schema matches, "
                    "but the producer contract or content-derived identity "
                    f"does not: {html.escape(str(exc))}. Not rendered.</p></div>"
                )
                continue
            try:
                if report["kind"] == "level2":
                    cards.append(self._render_level2(rel, doc))
                else:
                    cards.append(self._render_level1(rel, doc))
            except (KeyError, ValueError, TypeError):
                # A version-valid but structurally malformed artifact must not
                # 500 the whole Stats page; show it as unrenderable (fail
                # closed) and keep every other card.
                cards.append(
                    "<div class='card'><h2>"
                    + _icon("file")
                    + f"{html.escape(rel)} <span class='badge red'>invalid"
                    "</span></h2><p class='note'>The artifact declares the "
                    "expected schema but could not be rendered (malformed "
                    "structure); not shown.</p></div>"
                )
        results = (
            "<div class='card'><h2>" + _icon("file") + "Report artifacts</h2>"
            f"<ul>{''.join(listed)}</ul></div>"
            if listed
            else "<div class='card'><p class='note'>No Level-1/Level-2 report "
            "artifacts retained yet. They appear here once lanes and the "
            "analysis CLIs have run; diagrams render from the real "
            "<code>ura-level2-report/1</code> estimate rows.</p></div>"
        )
        body = (
            "<h1>"
            + _icon("chart", size=22)
            + "Campaign stats</h1>"
            + self._health_banner()
            + self._spend_card()
            + self._runs_card()
            + "".join(cards)
            + results
        )
        return _page("Campaign stats", body, active="Stats")

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
