"""Warnings, reports, statistics, and dashboard rendering."""

from __future__ import annotations


from .i18n import template as _ui_template, text as _ui_text

import hashlib
import html
import json
import math
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
    _marker_artifact_path,
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
    _STATS_RUNNER_RESULT_ROWS_MAX = 10_000
    _STATS_RUNNER_RESULT_FILE_BYTES_MAX = 32 * 1024 * 1024
    _STATS_RUNNER_RESULT_TABLE_MAX = 1_000
    _STATS_RUNNER_RESULT_CHART_MAX = 40

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
                (
                    "<div class='notice "
                    + f"{tone}"
                    + "' data-nid='"
                    + f"{nid}"
                    + _ui_template(
                        "'><button type='button' class='notice-close' aria-label='[[attr:dashboard.dismiss_notice]]' title='[[attr:dashboard.dismiss_this_browser_only]]'>[[text:dashboard.message]]</button><span class='badge "
                    )
                    + f"{tone}"
                    + "'>"
                    + f"{html.escape(entry['level'])}"
                    + "</span> <strong>"
                    + f"{html.escape(entry['title'])}"
                    + "</strong>"
                )
                + detail
                + "</div>"
            )
        return (
            "<div class='card'><h2>"
            + _icon("pulse")
            + _ui_template("[[text:dashboard.notices]]</h2>")
            + "".join(rows)
            + (
                _ui_template(
                    "<p class='note'>[[text:dashboard.operator_recorded_notices_from]] <code>"
                )
                + f"{_WARNINGS_FILE}"
                + _ui_template(
                    "</code>[[text:dashboard.they_annotate_and_never_authorize_or_invalidate_the_artifacts_the]] <a href='#' id='notice-restore' style='display:none'></a></p></div><script>(function(){var KEY='ura-dismissed-notices';function load(){try{return JSON.parse(localStorage.getItem(KEY))||[]}catch(e){return[]}}function save(v){localStorage.setItem(KEY,JSON.stringify(v));}var restore=document.getElementById('notice-restore');function apply(){var d=load();var hidden=0;document.querySelectorAll('.notice').forEach(function(n){var on=d.indexOf(n.getAttribute('data-nid'))>=0;n.style.display=on?'none':'';if(on){hidden++;}});if(restore){restore.style.display=hidden?'':'none';restore.textContent=[[js:dashboard.show]]+hidden+[[js:dashboard.dismissed_notice]]+(hidden===1?'':'s');}}document.querySelectorAll('.notice-close').forEach(function(b){b.addEventListener('click',function(){var id=this.parentElement.getAttribute('data-nid');var d=load();if(d.indexOf(id)<0){d.push(id);save(d);}apply();});});if(restore){restore.addEventListener('click',function(e){e.preventDefault();save([]);apply();});}apply();})();</script>"
                )
            )
        )

    def _campaign_context(self) -> str:
        """Non-secret campaign bindings from the environment, if present."""

        rows = []
        for label, name in (
            (_ui_text("dashboard.pinned_revision"), "REF_URA"),
            (_ui_text("dashboard.revision_receipt"), "URA_PROJECT_REVISION_MANIFEST"),
            (_ui_text("dashboard.receipt_sha_256"), "URA_PROJECT_REVISION_SHA256"),
            (_ui_text("dashboard.source_receipt"), "URA_SOURCE_CONFORMANCE_MANIFEST"),
            (_ui_text("dashboard.source_receipt_sha_256"), "URA_SOURCE_CONFORMANCE_SHA256"),
            (_ui_text("dashboard.corpora_root"), "URA_CORPORA"),
        ):
            value = os.environ.get(name, "")
            if not value:
                continue
            shown = value if len(value) <= 64 else value[:30] + "..." + value[-22:]
            rows.append(
                f"<tr><td>{html.escape(label)}</td><td><code>{html.escape(shown)}</code></td></tr>"
            )
        if not rows:
            return _ui_template(
                "<p class='note'>[[text:dashboard.no_campaign_bindings_exported_in_this_console_s_environment]]</p>"
            )
        return (
            "<div class='scroll'><table>"
            + "".join(rows)
            + _ui_template(
                "</table></div><p class='note'>[[text:dashboard.values_echoed_from_this_console_s_environment_for_orientation_onl]]</p>"
            )
        )

    @staticmethod
    def _next_hint(stages: Mapping[str, StageInventory]) -> str:
        order = (
            (
                _ui_text("dashboard.revision_receipt"),
                "project_revision",
                _ui_text("dashboard.author_the_prospective_revision_receipt_runbook_section_2"),
            ),
            (
                _ui_text("dashboard.source_receipts"),
                "source_conformance",
                _ui_text(
                    "dashboard.run_the_bounded_one_arm_observations_and_author_the_source_receip"
                ),
            ),
            (
                _ui_text("dashboard.attestations"),
                "run_matrix",
                _ui_text(
                    "dashboard.run_the_account_attestation_probes_and_derive_transport_receipts"
                ),
            ),
            (
                _ui_text("dashboard.canaries"),
                "run_matrix",
                _ui_text(
                    "dashboard.run_diagnostic_canaries_and_record_exact_observed_tokens_spend_ru"
                ),
            ),
            (
                _ui_text("dashboard.grids"),
                "run_matrix",
                _ui_text("dashboard.start_the_measured_lanes_runbook_sections_10_13"),
            ),
        )
        note = _ui_template(
            "<p class='note'>[[text:dashboard.this_suggestion_reads_file_presence_only_the_runbook_and_its_fail]]</p>"
        )
        for label, form, description in order:
            stage = stages.get(label)
            if stage is None or stage.count == 0:
                return (
                    "<div class='card'><h2>"
                    + _icon("play")
                    + (
                        _ui_template(
                            "[[text:dashboard.suggested_next_step]]</h2><p>[[text:dashboard.runbook_order_points_to]] <strong>"
                        )
                        + f"{html.escape(description)}"
                        + _ui_template("</strong> [[text:dashboard.the]] <code>")
                        + f"{html.escape(form)}"
                        + _ui_template(
                            "</code> [[text:dashboard.form_on_the]] <a href='/commands'>[[text:dashboard.run]]</a> page.</p>"
                        )
                    )
                    + note
                    + "</div>"
                )
        return (
            "<div class='card'><h2>"
            + _icon("play")
            + _ui_template(
                "[[text:dashboard.suggested_next_step]]</h2><p>[[text:dashboard.all_pipeline_stages_have_files_analysis_and_reporting_live_in_run]]</p>"
            )
            + note
            + "</div>"
        )

    # -- stats -------------------------------------------------------------

    @staticmethod
    def _bar_chart(rows: list[tuple[str, float]], *, unit: str = "") -> str:
        """A minimal horizontal bar chart (values in [0,1]); presentation only."""

        if not rows:
            return ""
        bar_h, gap, pad_l, width = 22, 10, 340, 760
        height = len(rows) * (bar_h + gap) + gap
        parts = [
            (
                "<svg class='barchart' viewBox='0 0 "
                + f"{width}"
                + " "
                + f"{height}"
                + _ui_template("' role='img' aria-label='[[attr:dashboard.result_chart]]'>")
            )
        ]
        for index, (label, value) in enumerate(rows):
            value = 0.0 if value < 0 else (1.0 if value > 1 else value)
            y = gap + index * (bar_h + gap)
            bar_w = (width - pad_l - 60) * value
            shown = f"{value * 100:.0f}%" if not unit else f"{value:g}{unit}"
            parts.append(
                f"<text class='bl' x='{pad_l - 8}' y='{y + bar_h - 6}' "
                f"text-anchor='end'>{html.escape(label[:44])}</text>"
                f"<rect class='bt' x='{pad_l}' y='{y}' "
                f"width='{width - pad_l - 60}' height='{bar_h}' rx='4'/>"
                f"<rect class='bv' x='{pad_l}' y='{y}' width='{bar_w:.1f}' "
                f"height='{bar_h}' rx='4'/>"
                f"<text class='bn' x='{pad_l + bar_w + 6}' y='{y + bar_h - 6}'>"
                f"{html.escape(shown)}</text>"
            )
        parts.append("</svg>")
        return "<div class='scroll'>" + "".join(parts) + "</div>"

    @staticmethod
    def _count_bar_chart(rows: list[tuple[str, int]], *, label: str) -> str:
        """A compact count chart that never presents counts as percentages."""

        if not rows:
            return ""
        maximum = max(1, max(value for _name, value in rows))
        bar_h, gap, pad_l, width = 22, 10, 340, 760
        height = len(rows) * (bar_h + gap) + gap
        parts = [
            f"<svg class='barchart' viewBox='0 0 {width} {height}' "
            f"role='img' aria-label='{html.escape(label, quote=True)}'>"
        ]
        for index, (name, value) in enumerate(rows):
            y = gap + index * (bar_h + gap)
            bar_w = (width - pad_l - 60) * value / maximum
            parts.append(
                f"<text class='bl' x='{pad_l - 8}' y='{y + bar_h - 6}' "
                f"text-anchor='end'>{html.escape(name[:44])}</text>"
                f"<rect class='bt' x='{pad_l}' y='{y}' "
                f"width='{width - pad_l - 60}' height='{bar_h}' rx='4'/>"
                f"<rect class='bv' x='{pad_l}' y='{y}' width='{bar_w:.1f}' "
                f"height='{bar_h}' rx='4'/>"
                f"<text class='bn' x='{pad_l + bar_w + 6}' y='{y + bar_h - 6}'>"
                f"{value:,}</text>"
            )
        parts.append("</svg>")
        return "<div class='scroll'>" + "".join(parts) + "</div>"

    def _health_banner(self) -> str:
        """A visible banner when the database is unhealthy - never silent."""

        health = self.db.health()
        if health["healthy"] and not health["last_error"]:
            return ""
        return (
            _ui_template(
                "<div class='notice red'><span class='badge red'>[[text:dashboard.database]]</span> <strong>[[text:dashboard.console_database]] "
            )
            + ("error" if health["healthy"] else "unavailable")
            + (
                "</strong><p class='note'>"
                + f"{html.escape(health['last_error'])}"
                + _ui_template(
                    " [[text:dashboard.job_history_run_registry_and_recorded_usage_may_be_incomplete_or]]</p></div>"
                )
            )
        )

    def _usage_cost_rows(self) -> tuple[list[dict[str, Any]] | None, str]:
        """Cost rows from recorded usage, or (None, why-unavailable)."""

        totals = self.db.usage_totals()
        if totals is None:
            return None, _ui_text("dashboard.database_unavailable_recorded_usage_unknown")
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
        from experiments.operational_costs import campaign_costs

        retained = campaign_costs(self.results_root)
        if retained["registered"]:
            return self._retained_spend_card(retained)
        cost_rows, unavailable = self._usage_cost_rows()
        if cost_rows is None:
            body = f"<p class='note'><strong>N/A</strong> - {html.escape(unavailable)}.</p>"
            return (
                "<div class='card'><h2>"
                + _icon("coins")
                + _ui_template("[[text:dashboard.budgets_usage_calculated_cost]]</h2>")
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
                cost_cell = _ui_template("<td>[[text:dashboard.local_not_billed]]</td>")
            elif row["cost"] is not None:
                source = (
                    _ui_template(
                        " - <span class='badge amber'>[[text:dashboard.auto_fetched_verify]]</span>"
                    )
                    if row.get("auto_fetched")
                    else " - <span class='badge gray'>operator-set</span>"
                )
                cost_cell = (
                    "<td><strong>"
                    + f"{self._fmt_money(row['cost'], row['currency'])}"
                    + _ui_template(
                        "</strong><br><span class='fieldhint'>[[text:dashboard.rate_of]] "
                    )
                    + f"{html.escape(row['effective_date'])}"
                    + f"{source}"
                    + "</span></td>"
                )
            elif row.get("currency") == "mixed" and row.get("by_currency"):
                parts = " + ".join(
                    self._fmt_money(value, currency)
                    for currency, value in row["by_currency"].items()
                )
                cost_cell = (
                    "<td><strong>"
                    + f"{html.escape(parts)}"
                    + _ui_template(
                        "</strong><br><span class='fieldhint'>[[text:dashboard.mixed_currencies_shown_per_currency_never_summed]]</span></td>"
                    )
                )
            else:
                why = "; ".join(row["missing"]) or _ui_text("dashboard.price_not_recorded")
                cost_cell = "<td>N/A <span class='fieldhint'>" + html.escape(why) + "</span></td>"
            detail.append(
                f"<tr><td>{html.escape(row['role'])}</td>"
                f"<td>{html.escape(row['provider'])}<br><code>"
                f"{html.escape(row['model'][:44])}</code></td>"
                f"<td>{row['calls']:,}"
                + (
                    (
                        "<br><span class='fieldhint'>"
                        + f"{row['missing_tokens']}"
                        + _ui_template(" [[text:dashboard.with_incomplete_token_usage]]</span>")
                    )
                    if row["missing_tokens"]
                    else ""
                )
                + f"</td>{token_cells}{cost_cell}</tr>"
            )
        heads = "".join(f"<th>{c.replace('_', ' ')}</th>" for c in _TOKEN_CATEGORIES)
        unindexed = not detail and self._has_completion_markers()
        if detail:
            detail_table = (
                (
                    _ui_template(
                        "<div class='scroll'><table><tr><th>[[text:dashboard.role]]</th><th>[[text:dashboard.provider_model]]</th><th>[[text:dashboard.calls]]</th>"
                    )
                    + f"{heads}"
                    + _ui_template("<th>[[text:dashboard.calculated_cost]]</th></tr>")
                )
                + "".join(detail)
                + "</table></div>"
            )
        elif unindexed:
            # Retained artifacts exist but the derived index is empty (a fresh
            # or stale SQLite file): the spend is UNKNOWN, not $0.  Never show a
            # zero here; prompt a reindex from the artifacts.
            detail_table = _ui_template(
                "<div class='notice amber'><strong>[[text:dashboard.recorded_usage_not_indexed]]</strong><p class='note'>[[text:dashboard.completed_run_artifacts_exist_under_the_results_root_but_this_dat]] <strong>[[text:dashboard.unknown_not_zero]]</strong>. <form class='inline' method='post' action='/db/reindex' data-busy='[[attr:dashboard.rebuilding_the_index_from_retained_artifacts]]'><button type='submit' class='small'>[[text:dashboard.reindex_from_artifacts]]</button></form></p></div>"
            )
        else:
            detail_table = _ui_template(
                "<p class='note'>[[text:dashboard.no_recorded_usage_yet_usage_appears_here_once_a_completed_run_s_a]]</p>"
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
                spent_text = _ui_template(
                    "[[text:dashboard.unknown]] <span class='fieldhint'>[[text:dashboard.not_indexed_reindex_from_artifacts]]</span>"
                )
                remaining = _ui_template(
                    "N/A <span class='fieldhint'>[[text:dashboard.cost_incomplete]]</span>"
                )
            elif not matched:
                # No billable usage recorded under this budget's provider: the
                # spend is genuinely absent, not zero, and there is nothing to
                # net against prepaid.
                spent_text = _ui_template(
                    "[[text:dashboard.no_recorded_usage]] <span class='fieldhint'>[[text:dashboard.no_billable_calls_recorded_for_this_provider]]</span>"
                )
                remaining = _ui_template(
                    "N/A <span class='fieldhint'>[[text:dashboard.no_recorded_spend_to_subtract]]</span>"
                )
            elif not complete:
                spent_text = _ui_template(
                    "N/A <span class='fieldhint'>[[text:dashboard.some_models_lack_a_recorded_price]]</span>"
                )
                remaining = _ui_template(
                    "N/A <span class='fieldhint'>[[text:dashboard.cost_incomplete]]</span>"
                )
            elif len(merged) > 1:
                # Different currencies are never summed into one spend nor
                # subtracted from a single prepaid figure.
                spent_text = " + ".join(
                    self._fmt_money(amt, ccy) for ccy, amt in sorted(merged.items())
                ) + _ui_template(
                    " <span class='fieldhint'>[[text:dashboard.mixed_currencies_not_summed]]</span>"
                )
                remaining = _ui_template(
                    "N/A <span class='fieldhint'>[[text:dashboard.mixed_currencies_cannot_net_one_prepaid_figure]]</span>"
                )
            else:
                ccy, amt = next(iter(merged.items())) if merged else ("USD", 0.0)
                spent_text = self._fmt_money(amt, ccy)
                if prepaid is None:
                    remaining = _ui_template(
                        "N/A <span class='fieldhint'>[[text:dashboard.prepaid_not_numeric]]</span>"
                    )
                elif ccy != "USD":
                    # The maintained budgets config records dollar-denominated
                    # prepaid balances (for example "$100").  Never subtract
                    # those dollars from a non-USD spend without an exchange
                    # rate that the console deliberately does not invent.
                    remaining = _ui_template(
                        "N/A <span class='fieldhint'>[[text:dashboard.prepaid_balance_is_usd_no_currency_conversion_recorded]]</span>"
                    )
                else:
                    remaining = self._fmt_money(prepaid - amt, ccy)
            budget_rows.append(
                f"<tr><td>{html.escape(name)}</td>"
                f"<td><strong>{html.escape(amount)}</strong></td>"
                f"<td>{spent_text}</td><td>{remaining}</td></tr>"
            )
        return (
            "<div class='card'><h2>"
            + _icon("coins")
            + _ui_template(
                "[[text:dashboard.budgets_usage_calculated_cost]]</h2><div class='scroll'><table><tr><th>[[text:dashboard.provider]]</th><th>[[text:dashboard.prepaid]]</th><th>[[text:dashboard.calculated_spend]]</th><th>[[text:dashboard.remaining]]</th></tr>"
            )
            + "".join(budget_rows)
            + "</table></div>"
            + detail_table
            + _ui_template(
                "<p class='note'>[[text:dashboard.tokens_are_the_recorded_usage_read_from_completion_bound_run_arti]] <a href='/config?file=pricing'>[[text:dashboard.pricing]]</a> table (effective-dated); a missing token count or price renders as N/A, never as zero. <code>target_failed</code>/<code>judge_failed</code> rows are observable paid work from cells that later errored (operational spend only, never part of any scientific result); <code>reserved</code> [[text:dashboard.rows_are_attempted_calls_with_no_recorded_token_detail_shown_as_n]] <a href='/config?file=budgets'>[[text:dashboard.budgets]]</a> [[text:dashboard.config_if_a_provider_ever_reports_an_actually_billed_amount_in_an]]</p></div>"
            )
        )

    def _retained_spend_card(self, inventory: dict) -> str:
        if inventory["errors"]:
            content = (
                _ui_template(
                    "<div class='notice amber'>[[text:dashboard.campaign_costs_are_unavailable_not_zero]]<ul>"
                )
                + "".join("<li>" + html.escape(error) + "</li>" for error in inventory["errors"])
                + "</ul></div>"
            )
        else:

            def money(row, key):
                return self._fmt_money(row[key] / 1_000_000, "USD")

            rows = []
            for row in inventory["rows"]:
                settled = (
                    money(row, "reported_cost_microusd")
                    if row["settled_attempts"]
                    else _ui_text("dashboard.not_settled")
                )
                rows.append(
                    "<tr><td>"
                    + html.escape(row["provider"])
                    + "</td><td>"
                    + html.escape(row["role"])
                    + f"</td><td>{row['http_attempts']:,}</td>"
                    + f"<td>{settled}</td>"
                    + (
                        "<td>"
                        + f"{money(row, 'unknown_exposure_microusd')}"
                        + " ("
                        + f"{row['unknown_attempts']:,}"
                        + _ui_template(" [[text:dashboard.attempts]]</td>")
                    )
                    + (
                        "<td>"
                        + f"{money(row, 'unsettled_exposure_microusd')}"
                        + " ("
                        + f"{row['unsettled_attempts']:,}"
                        + _ui_template(" [[text:dashboard.attempts]]</td>")
                    )
                    + f"<td>{money(row, 'unstarted_commitments_microusd')}</td></tr>"
                )
            content = (
                _ui_template(
                    "<div class='scroll'><table><tr><th>[[text:dashboard.provider]]</th><th>[[text:dashboard.role]]</th><th>[[text:dashboard.request_attempt_records]]</th><th>[[text:dashboard.settled_usage_cost]]</th><th>[[text:dashboard.unknown_charge_exposure]]</th><th>[[text:dashboard.unsettled_attempt_exposure]]</th><th>[[text:dashboard.unissued_retained_plan_allowance]]</th></tr>"
                )
                + "".join(rows)
                + "</table></div>"
            )
        links = "".join(
            "<li><a href='/artifacts?path="
            + quote(source["budget"])
            + "'>"
            + html.escape(source["label"])
            + "</a></li>"
            for source in inventory["sources"]
        )
        if any(source.get("spending_policy") == "precalculated" for source in inventory["sources"]):
            content += _ui_template(
                "<p class='note'>[[text:dashboard.pre_calculated_execution_is_present_maximum_cost_forecasts_are_no]]</p>"
            )
        return (
            "<div class='card'><h2>"
            + _icon("coins")
            + _ui_template("[[text:dashboard.retained_campaign_costs]]</h2>")
            + content
            + _ui_template(
                "<p class='note'>[[text:dashboard.target_generation_and_hosted_judging_are_separate_each_physical_r]]</p>"
            )
            + _ui_template(
                "<details><summary>[[text:dashboard.registered_accounting_sources]]</summary><ul>"
            )
            + links
            + "</ul></details></div>"
        )

    @staticmethod
    def _parse_money(amount: str) -> float | None:
        match = re.fullmatch(r"\$?\s*([0-9]+(?:\.[0-9]+)?)", amount.strip())
        return float(match.group(1)) if match else None

    def _runs_card(self) -> str:
        runs = self.db.list_runs()
        if runs is None:
            return (
                "<div class='card'><h2>"
                + _icon("book")
                + _ui_template(
                    "[[text:dashboard.campaign_runs]]</h2><p class='note'><strong>[[text:dashboard.unavailable]]</strong> [[text:dashboard.the_console_database_cannot_be_read_so_the_run_registry_is_unknow]]</p></div>"
                )
            )
        if not runs:
            return (
                "<div class='card'><h2>"
                + _icon("book")
                + _ui_template(
                    "[[text:dashboard.campaign_runs]]</h2><p class='note'>[[text:dashboard.no_lanes_recorded_yet_each_rig_check_and_run_matrix_job_is_regist]]</p></div>"
                )
            )
        tone = {"complete": "green", "failed": "red", "running": "blue"}
        work_labels = {
            "preflight": _ui_text("dashboard.preflight_no_model_call"),
            "dry_run": _ui_text("dashboard.offline_dry_run_no_model_call"),
            "diagnostic_canary": _ui_text("dashboard.diagnostic_model_capable_run"),
            "attestation_probe": _ui_text("dashboard.model_probe"),
            "measured": _ui_text("dashboard.model_campaign"),
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
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(row["created_at"] or 0)))
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
            "<div class='card'><h2>"
            + _icon("book")
            + _ui_template(
                "[[text:dashboard.campaign_runs]]</h2><div class='scroll'><table><tr><th>[[text:dashboard.when]]</th><th>[[text:dashboard.state]]</th><th>[[text:dashboard.work]]</th><th>[[text:dashboard.command]]</th><th>[[text:dashboard.output]]</th><th>[[text:dashboard.pin]]</th></tr>"
            )
            + "".join(rows)
            + _ui_template(
                "</table></div><p class='note'>[[text:dashboard.this_is_an_operational_process_registry_passed_means_the_cli_exit]]</p></div>"
            )
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
            return _ui_text("dashboard.local_not_billed_2") if cost_rows else "N/A"
        if any(row.get("cost") is None for row in billable):
            return _ui_text("dashboard.n_a_incomplete_pricing_or_usage")
        by_currency: dict[str, float] = {}
        for row in billable:
            currency = str(row.get("currency") or "")
            cost = row.get("cost")
            if not currency or not isinstance(cost, (int, float)):
                return _ui_text("dashboard.n_a_incomplete_pricing_or_usage")
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
            "acquisition_plan": _ui_text("dashboard.model_acquisition_plan_no_model_call"),
            "preflight": _ui_text("dashboard.preflight_no_model_call"),
            "dry_run": _ui_text("dashboard.offline_dry_run_no_model_call"),
            "diagnostic_canary": _ui_text("dashboard.diagnostic_model_capable_run"),
            "attestation_probe": _ui_text("dashboard.model_probe"),
            "measured": _ui_text("dashboard.model_campaign"),
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
                _ui_text("dashboard.external_operational_record_non_thesis"),
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
        if kind == "measured" and corpora and state == "complete" and complete > 0 and invalid == 0:
            return "thesis-measured", _ui_text("dashboard.thesis_measured_evidence"), "green"
        if kind == "measured":
            return (
                "measured-incomplete",
                _ui_text("dashboard.measured_attempt_evidence_incomplete"),
                "amber",
            )
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
            if (
                not job_id
                or job_id in live_job_ids
                or command
                not in {
                    "level1_evidence",
                    "level2_report",
                }
            ):
                continue
            if str(row["state"] or "") != "complete" or row["exit_code"] != 0:
                continue
            try:
                loaded = strict_json_loads(str(row["argv"] or "[]"))
            except (TypeError, ValueError):
                continue
            if not isinstance(loaded, list) or not all(isinstance(part, str) for part in loaded):
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
            if derived_path_quarantined(result_root, self.results_root) or derived_path_quarantined(
                report_path, self.results_root
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
            most_specific = [owner for owner in candidates if len(owner["root"].parts) == deepest]
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
                "kind": ("level1" if analysis_job["command"] == "level1_evidence" else "level2"),
                "producer_job_id": str(analysis_job["job_id"]),
            }
            prior = bindings_by_path.get(report_path)
            if prior is None:
                bindings_by_path[report_path] = binding
            elif (
                prior["owner_job_id"] != binding["owner_job_id"] or prior["kind"] != binding["kind"]
            ):
                ambiguous_paths.add(report_path)
        return [
            binding for path, binding in bindings_by_path.items() if path not in ambiguous_paths
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
            return [], _ui_text("dashboard.external_measured_registry_scan_unavailable")
        return (
            [job for job in jobs if self.db.load_campaign(job.job_id) is None],
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
                db_notice = _ui_text(
                    "dashboard.console_campaign_registry_unavailable_externally_registered_measu"
                )
                unavailable = " ".join(part for part in (unavailable, db_notice) if part)
            combined = console_rows + [self._stats_external_row(job) for job in external_jobs]
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
                page_notice = _ui_text(
                    "dashboard.campaign_pagination_reached_the_bounded_10_001_row_registry_view"
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
                    if isinstance(loaded, list) and all(isinstance(part, str) for part in loaded):
                        argv = list(loaded)
                    started_at = float(stored["started_at"] or started_at)
                    ended_at = float(stored["ended_at"]) if stored["ended_at"] is not None else None
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
            uniquely_owned = output_root is not None and owners_by_root.get(output_root) == {job_id}
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
                    if root != output_root and self._stats_contains_path(output_root, root)
                )
                usage_rows, observed = collect_usage(
                    output_root,
                    verify_sha=False,
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
                    "output_quarantined": quarantined_output,
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
            str(binding["path"]) for binding in self._stats_report_bindings() if binding["path"]
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
                owned.update(report.artifact_relative for report in registration.reports)
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
        reports = []
        terminal_inventory: dict[str, object] | None = None
        for report in registration.reports:
            reports.append(
                {
                    "owner_job_id": campaign.route_id,
                    "path": report.artifact_relative,
                    "source_path": report.path,
                    "display_name": report.display_name,
                    "kind": report.kind,
                    "producer_job_id": campaign.route_id,
                    "_external_analysis_report": report,
                }
            )
            if report.kind == "terminal_inventory":
                document = load_external_analysis_report(report)
                if isinstance(document, dict):
                    terminal_inventory = document
        terminal_rows = (
            terminal_inventory.get("rows") if isinstance(terminal_inventory, Mapping) else None
        )
        failure_rows = (
            terminal_inventory.get("failure_rows")
            if isinstance(terminal_inventory, Mapping)
            else None
        )
        coverage_text = (
            (
                f"{len(terminal_rows):,}"
                + _ui_text("dashboard.terminal_campaign_rows")
                + f"{len(failure_rows):,}"
                + _ui_text("dashboard.failure_rows")
            )
            if isinstance(terminal_rows, list) and isinstance(failure_rows, list)
            else _ui_text("dashboard.validated_external_analysis_reports")
        )
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
            "cost_text": _ui_text("dashboard.not_reported_by_analysis_registration"),
            "evidence": evidence,
            "coverage_text": coverage_text,
            "terminal_inventory": terminal_inventory,
            "authority": "external-analysis",
            "authority_label": _ui_text("dashboard.registered_external_analysis_non_thesis"),
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
            "complete_with_explicit_limitations": _ui_text(
                "dashboard.complete_with_explicit_limitations"
            ),
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
        return ", ".join(values) if values else _ui_text("dashboard.not_declared")

    @staticmethod
    def _stats_coverage_text(evidence: Mapping[str, int]) -> str:
        complete = int(evidence.get("markers", 0))
        failed = int(evidence.get("failed_cells", 0))
        invalid = int(evidence.get("skipped_invalid", 0)) + int(
            evidence.get("unreadable_artifacts", 0)
        )
        text = (
            f"{complete}"
            + _ui_text("dashboard.complete_cell")
            + f"{('s' if complete != 1 else '')}"
        )
        extras = []
        if failed:
            extras.append(f"{failed} failed")
        if invalid:
            extras.append(f"{invalid} invalid/unreadable")
        if evidence.get("truncated"):
            extras.append(_ui_text("dashboard.scan_truncated"))
        return text + ("; " + ", ".join(extras) if extras else "")

    def _stats_usage_table(self, campaign: Mapping[str, Any]) -> str:
        if campaign.get("usage_reported") is False:
            return _ui_template(
                "<p class='note'>[[text:dashboard.this_external_analysis_registration_does_not_carry_a_model_usage]]</p>"
            )
        rows = []
        for cost in campaign["cost_rows"]:
            tokens = cost["tokens"]
            if not cost["billable"]:
                cost_text = _ui_text("dashboard.local_not_billed_2")
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
            return _ui_template(
                "<p class='note'>[[text:dashboard.no_completion_bound_model_usage_was_recorded]]</p>"
            )
        return (
            _ui_template(
                "<div class='scroll'><table><tr><th>[[text:dashboard.role]]</th><th>[[text:dashboard.provider_model]]</th><th>[[text:dashboard.calls]]</th><th>[[text:dashboard.input_tokens]]</th><th>[[text:dashboard.output_tokens]]</th><th>[[text:dashboard.calculated_cost]]</th></tr>"
            )
            + "".join(rows)
            + "</table></div>"
        )

    def _stats_completion_has_results(self, campaign: Mapping[str, Any]) -> bool:
        """Whether an exact completed Runner cell declares aggregate results."""

        if campaign.get("kind") != "measured" or campaign.get("output_quarantined") is True:
            return False
        root = campaign.get("output_root")
        if not isinstance(root, Path) or not root.is_dir():
            return False
        try:
            markers, observed = iter_completed_markers(root)
        except (OSError, ValueError):
            return False
        if observed.get("truncated") or observed.get("skipped_invalid"):
            return False
        return any(
            isinstance(marker.get("artifacts"), Mapping)
            and isinstance(marker["artifacts"].get("results"), Mapping)
            for _path, marker in markers
        )

    def _stats_runner_result_rows(
        self, campaign: Mapping[str, Any]
    ) -> tuple[list[dict[str, Any]], str]:
        """Load completion-bound per-cell Runner aggregates for one exact Job.

        This is a presentation of already produced Runner rows, not cross-run
        pooling or a replacement for a bound Level-2 report. Every source file
        is resolved through its completion marker and digest-checked before any
        row is rendered.
        """

        if campaign.get("kind") != "measured" or campaign.get("output_quarantined") is True:
            return [], ""
        root = campaign.get("output_root")
        if not isinstance(root, Path) or not root.is_dir():
            return [], ""
        try:
            markers, observed = iter_completed_markers(root)
        except (OSError, ValueError) as exc:
            return [], (_ui_text("dashboard.runner_completion_scan_failed") + f"{exc}")
        if observed.get("truncated"):
            return [], _ui_text("dashboard.runner_completion_scan_was_truncated")
        if observed.get("skipped_invalid"):
            return [], _ui_text("dashboard.runner_completion_inventory_contains_an_invalid_marker")

        rows: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        try:
            for marker_path, marker in markers:
                artifacts = marker.get("artifacts")
                descriptor = artifacts.get("results") if isinstance(artifacts, Mapping) else None
                if descriptor is None:
                    continue
                result_path = _marker_artifact_path(marker_path, descriptor, verify_sha=False)
                if result_path.stat().st_size > self._STATS_RUNNER_RESULT_FILE_BYTES_MAX:
                    raise ValueError(
                        _ui_text("dashboard.runner_results_artifact_exceeds_the_stats_byte_cap")
                    )
                expected_records = descriptor.get("records")
                if (
                    not isinstance(expected_records, int)
                    or isinstance(expected_records, bool)
                    or expected_records < 0
                ):
                    raise ValueError(
                        _ui_text("dashboard.runner_results_descriptor_has_no_valid_record_count")
                    )
                observed_records = 0
                with result_path.open(encoding="utf-8") as handle:
                    for line_number, line in enumerate(handle, 1):
                        if not line.strip():
                            continue
                        observed_records += 1
                        if len(rows) >= self._STATS_RUNNER_RESULT_ROWS_MAX:
                            raise ValueError(
                                _ui_text("dashboard.runner_aggregate_row_cap_exceeded")
                            )
                        value = strict_json_loads(line)
                        if not isinstance(value, Mapping):
                            raise ValueError(
                                (
                                    _ui_text("dashboard.runner_result_row")
                                    + f"{line_number}"
                                    + _ui_text("dashboard.is_not_an_object")
                                )
                            )
                        row_id = value.get("id")
                        metric = value.get("metric")
                        estimate = value.get("value")
                        group = value.get("group_by")
                        provenance = value.get("provenance")
                        n = value.get("n")
                        if (
                            not isinstance(row_id, str)
                            or not row_id
                            or len(row_id) > 256
                            or row_id in seen_ids
                            or not isinstance(metric, str)
                            or not metric
                            or len(metric) > 256
                            or (
                                estimate is not None
                                and (
                                    not isinstance(estimate, (int, float))
                                    or isinstance(estimate, bool)
                                    or not math.isfinite(float(estimate))
                                )
                            )
                            or not isinstance(group, Mapping)
                            or not isinstance(provenance, Mapping)
                            or provenance.get("evidence_class") != "measured"
                            or value.get("run_id") != marker.get("run_id")
                            or not isinstance(n, int)
                            or isinstance(n, bool)
                            or n < 0
                        ):
                            raise ValueError(
                                (
                                    _ui_text("dashboard.runner_result_row")
                                    + f"{line_number}"
                                    + _ui_text("dashboard.has_an_invalid_identity")
                                )
                            )
                        for bound in ("ci_low", "ci_high"):
                            candidate = value.get(bound)
                            if candidate is not None and (
                                not isinstance(candidate, (int, float))
                                or isinstance(candidate, bool)
                                or not math.isfinite(float(candidate))
                            ):
                                raise ValueError(
                                    (
                                        _ui_text("dashboard.runner_result_row")
                                        + f"{line_number}"
                                        + _ui_text("dashboard.has_an_invalid")
                                        + f"{bound}"
                                    )
                                )
                        seen_ids.add(row_id)
                        rows.append(dict(value))
                if observed_records != expected_records:
                    raise ValueError(
                        _ui_text("dashboard.runner_results_record_count_changed_since_completion")
                    )
        except (OSError, TypeError, ValueError, RecursionError) as exc:
            return [], (_ui_text("dashboard.runner_aggregate_artifact_invalid") + f"{exc}")
        return rows, ""

    def _stats_runner_results_card(self, campaign: Mapping[str, Any]) -> str:
        rows, error = self._stats_runner_result_rows(campaign)
        if error:
            return (
                _ui_template(
                    "<div class='notice red'><strong>[[text:dashboard.runner_aggregates_not_rendered]]</strong><p class='note'>"
                )
                + html.escape(error)
                + ".</p></div>"
            )
        if not rows:
            return ""

        by_metric: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_metric.setdefault(str(row["metric"]), []).append(row)
        sections: list[str] = []
        for metric, metric_rows in sorted(by_metric.items()):
            ordered = sorted(
                metric_rows,
                key=lambda row: tuple(
                    str(row.get("group_by", {}).get(field) or "")
                    for field in ("source", "risk", "effective_modality", "attacker", "model")
                ),
            )
            chartable = [
                row
                for row in ordered
                if isinstance(row["value"], (int, float))
                and not isinstance(row["value"], bool)
                and 0.0 <= float(row["value"]) <= 1.0
            ]
            chart = self._bar_chart(
                [
                    (
                        " / ".join(
                            str(row.get("group_by", {}).get(field) or "?")
                            for field in ("source", "risk", "attacker")
                        ),
                        float(row["value"]),
                    )
                    for row in chartable[: self._STATS_RUNNER_RESULT_CHART_MAX]
                ]
            )
            if len(chartable) > self._STATS_RUNNER_RESULT_CHART_MAX:
                chart += (
                    _ui_template("<p class='note'>[[text:dashboard.chart_shows]] ")
                    + f"{self._STATS_RUNNER_RESULT_CHART_MAX}"
                    + " of "
                    + f"{len(chartable)}"
                    + _ui_template(
                        " [[text:dashboard.rate_rows_for_this_metric_the_bounded_table_below_retains_the_per]]</p>"
                    )
                )
            table_rows = []
            for row in ordered[: self._STATS_RUNNER_RESULT_TABLE_MAX]:
                group = row["group_by"]
                ci_low = row.get("ci_low")
                ci_high = row.get("ci_high")
                ci_text = (
                    "N/A"
                    if ci_low is None or ci_high is None
                    else f"{float(ci_low):.4f}, {float(ci_high):.4f}"
                )
                value_text = "N/A" if row["value"] is None else f"{float(row['value']):.4f}"
                table_rows.append(
                    "<tr>"
                    f"<td>{html.escape(str(group.get('model') or 'N/A'))}</td>"
                    f"<td>{html.escape(str(group.get('source') or 'N/A'))}</td>"
                    f"<td>{html.escape(str(group.get('risk') or 'N/A'))}</td>"
                    f"<td>{html.escape(str(group.get('effective_modality') or 'N/A'))}</td>"
                    f"<td>{html.escape(str(group.get('attacker') or 'N/A'))}</td>"
                    f"<td>{value_text}</td>"
                    f"<td>{html.escape(ci_text)}</td><td>{int(row['n']):,}</td></tr>"
                )
            table_note = ""
            if len(ordered) > self._STATS_RUNNER_RESULT_TABLE_MAX:
                table_note = (
                    _ui_template("<p class='note'>[[text:dashboard.table_is_bounded_to]] ")
                    + f"{self._STATS_RUNNER_RESULT_TABLE_MAX}"
                    + " of "
                    + f"{len(ordered)}"
                    + _ui_template(
                        " [[text:dashboard.rows_open_the_exact_output_artifacts_for_the_full_file]]</p>"
                    )
                )
            sections.append(
                (
                    "<h3>"
                    + f"{html.escape(metric)}"
                    + " <span class='fieldhint'>("
                    + f"{len(ordered)}"
                    + _ui_template(" [[text:dashboard.row_s]]</span></h3>")
                )
                + chart
                + _ui_template(
                    "<div class='scroll'><table><tr><th>[[text:dashboard.model]]</th><th>[[text:dashboard.source]]</th><th>[[text:dashboard.risk]]</th><th>[[text:dashboard.modality]]</th><th>[[text:dashboard.attacker]]</th><th>[[text:dashboard.value]]</th><th>[[text:dashboard.ci_low_high]]</th><th>[[text:dashboard.n]]</th></tr>"
                )
                + "".join(table_rows)
                + "</table></div>"
                + table_note
            )
        return (
            "<div class='card'><h2>"
            + _icon("chart")
            + _ui_template(
                "[[text:dashboard.runner_cell_aggregates]] <span class='badge blue'>[[text:dashboard.exact_job]]</span></h2><p class='note'>Digest-verified <code>*.results.jsonl</code> [[text:dashboard.rows_bound_by_each_completed_cell_marker_this_is_a_per_job_view_o]]</p>"
            )
            + "".join(sections)
            + "</div>"
        )

    def _stats_campaign_card(self, campaign: Mapping[str, Any]) -> str:
        state = str(campaign["state"])
        state_label, state_tone = self._stats_state_badge(state)
        job_href = str(campaign.get("job_href") or f"/jobs/{quote(str(campaign['job_id']))}")
        external_badge = (
            _ui_template("<span class='badge blue'>[[text:dashboard.external_read_only]]</span>")
            if campaign.get("external_owned") is True
            else ""
        )
        started = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(campaign["started_at"])))
        ended_at = campaign["ended_at"]
        if ended_at is not None:
            ended = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(ended_at)))
        else:
            ended = (
                _ui_text("dashboard.running_not_recorded")
                if state == "running"
                else _ui_text("dashboard.not_recorded")
            )
        usage = campaign["usage"]
        usage_reported = campaign.get("usage_reported") is not False
        calls = (
            f"{usage['target_calls']:,} target / {usage['judge_calls']:,} judge"
            if usage_reported
            else _ui_text("dashboard.not_reported")
        )
        tokens = (
            f"{usage['input_tokens']:,} input / {usage['output_tokens']:,} output"
            if usage_reported
            else _ui_text("dashboard.not_reported")
        )
        has_chart = self._stats_completion_has_results(campaign) or any(
            "class='barchart'" in self._stats_report_card(report) for report in campaign["reports"]
        )
        detail_label = (
            "Statistics &amp; diagrams" if has_chart else _ui_text("dashboard.statistics_details")
        )
        coverage_text = str(
            campaign.get("coverage_text") or self._stats_coverage_text(campaign["evidence"])
        )
        return (
            "<article class='stats-campaign-card' data-job-id='"
            + f"{html.escape(str(campaign['job_id']))}"
            + "' data-authority='"
            + f"{html.escape(str(campaign['authority']))}"
            + "'><div class='stats-campaign-head'><div><h3><a href='"
            + f"{html.escape(job_href, quote=True)}"
            + "'>"
            + f"{html.escape(str(campaign['job_id']))}"
            + "</a></h3><p class='note'>"
            + f"{html.escape(str(campaign['work_label']))}"
            + "</p></div><div class='stats-badges'><span class='badge "
            + f"{state_tone}"
            + "'>"
            + f"{html.escape(state_label)}"
            + "</span><span class='badge "
            + f"{html.escape(str(campaign['authority_tone']))}"
            + "'>"
            + f"{html.escape(str(campaign['authority_label']))}"
            + "</span>"
            + f"{external_badge}"
            + _ui_template(
                "</div></div><dl class='stats-campaign-meta'><dt>[[text:dashboard.target]]</dt><dd>"
            )
            + f"{html.escape(self._stats_list_text(campaign['targets']))}"
            + _ui_template("</dd><dt>[[text:dashboard.framework]]</dt><dd>")
            + f"{html.escape(self._stats_list_text(campaign['frameworks']))}"
            + _ui_template("</dd><dt>[[text:dashboard.corpus]]</dt><dd>")
            + f"{html.escape(self._stats_list_text(campaign['corpora']))}"
            + _ui_template("</dd><dt>[[text:dashboard.started]]</dt><dd>")
            + f"{html.escape(started)}"
            + _ui_template("</dd><dt>[[text:dashboard.ended]]</dt><dd>")
            + f"{html.escape(ended)}"
            + _ui_template("</dd><dt>[[text:dashboard.calls]]</dt><dd>")
            + f"{html.escape(calls)}"
            + _ui_template("</dd><dt>[[text:dashboard.tokens]]</dt><dd>")
            + f"{html.escape(tokens)}"
            + _ui_template("</dd><dt>[[text:dashboard.cost]]</dt><dd>")
            + f"{html.escape(str(campaign['cost_text']))}"
            + _ui_template("</dd><dt>[[text:dashboard.results]]</dt><dd>")
            + f"{html.escape(coverage_text)}"
            + "</dd></dl><div class='stats-campaign-actions'><a class='button ghost stats-detail-trigger' href='/stats/job/"
            + f"{quote(str(campaign['job_id']))}"
            + "' data-stats-job='"
            + f"{html.escape(str(campaign['job_id']))}"
            + "' aria-controls='campaign-stats-modal' aria-haspopup='dialog' aria-expanded='false'>"
            + f"{detail_label}"
            + "</a></div></article>"
        )

    def _stats_report_card(
        self,
        report: Mapping[str, Any],
        *,
        detail_url: str | None = None,
        detail_section: str = "overview",
        detail_page: int = 0,
    ) -> str:
        rel = str(report.get("path") or "")
        display_name = str(
            report.get("display_name") or rel or _ui_text("dashboard.external_report")
        )
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
                + (
                    f"{html.escape(display_name)}"
                    + _ui_template(
                        " <span class='badge red'>[[text:dashboard.invalid]]</span></h3><p class='note'>[[text:dashboard.the_exact_report_output_is_missing_or_malformed_no_chart_is_rende]]</p></div>"
                    )
                )
            )
        if not isinstance(doc, dict):
            return (
                "<div class='card'><h3>"
                + f"{html.escape(display_name)}"
                + _ui_template(
                    " <span class='badge red'>[[text:dashboard.invalid]]</span></h3></div>"
                )
            )
        expected = {
            "level1": {"ura-level1-evidence/3", "ura-level1-evidence/2"},
            "level2": {"ura-level2-report/1", "ura-level2-report/2"},
        }.get(kind)
        if (
            kind
            not in {
                "level1",
                "level2",
                "judge_comparison",
                "terminal_inventory",
                "execution_accounting",
            }
            or (expected is not None and str(doc.get("schema_version")) not in expected)
            or (
                kind == "execution_accounting"
                and doc.get("schema") != "ura-local-campaign-execution-accounting/1"
            )
        ):
            return (
                "<div class='card'><h3>"
                + _icon("file")
                + (
                    f"{html.escape(display_name)}"
                    + _ui_template(
                        " <span class='badge red'>[[text:dashboard.invalid]]</span></h3><p class='note'>[[text:dashboard.the_declared_schema_does_not_match_this_analysis_job_no_chart_is]]</p></div>"
                    )
                )
            )
        try:
            # The registered reader already validates this exact kind and
            # invalidates its cache when file metadata changes. Do not rebuild
            # the same scientific summary again on every pagination request.
            if not (
                isinstance(registered_report, ExternalAnalysisReport)
                and registered_report.kind == kind
            ):
                _validate_report_document(kind, doc)
        except ValueError as exc:
            return (
                "<div class='card'><h3>"
                + _icon("file")
                + (
                    f"{html.escape(display_name)}"
                    + _ui_template(
                        " <span class='badge red'>[[text:dashboard.invalid]]</span></h3><p class='note'>"
                    )
                    + f"{html.escape(str(exc))}"
                    + _ui_template("[[text:dashboard.not_rendered_no_chart_is_produced]]</p></div>")
                )
            )
        try:
            if kind == "judge_comparison":
                return self._render_judge_comparison(
                    display_name,
                    doc,
                    detail_url=detail_url,
                    detail_section=detail_section,
                    detail_page=detail_page,
                )
            if kind == "terminal_inventory":
                return self._render_terminal_inventory(display_name, doc, artifact_relative=rel)
            if kind == "execution_accounting":
                return self._render_execution_accounting(display_name, doc, artifact_relative=rel)
            if kind == "level2":
                return self._render_level2(display_name, doc, artifact_relative=rel)
            return self._render_level1(display_name, doc, artifact_relative=rel)
        except (KeyError, TypeError, ValueError):
            return (
                "<div class='card'><h3>"
                + f"{html.escape(display_name)}"
                + _ui_template(
                    " <span class='badge red'>[[text:dashboard.invalid]]</span></h3><p class='note'>[[text:dashboard.validated_identity_but_unrenderable_structure_no_chart_is_rendere]]</p></div>"
                )
            )

    def _render_judge_comparison(
        self,
        name: str,
        doc: Mapping[str, Any],
        *,
        detail_url: str | None = None,
        detail_section: str = "overview",
        detail_page: int = 0,
    ) -> str:
        """Display matched judgments, never infer them from logs or job state."""

        def estimate(value: Mapping[str, Any]) -> str:
            point = value["value"]
            if point is None:
                return _ui_text("dashboard.no_comparable_decisions")
            ci = (
                f"95% CI {value['ci_low']:.3f} to {value['ci_high']:.3f}"
                if value["ci_low"] is not None
                else _ui_text("dashboard.ci_unavailable_fewer_than_two_source_clusters")
            )
            inputs = (
                (" / " + f"{value['n_inputs']}" + _ui_text("dashboard.distinct_inputs"))
                if "n_inputs" in value
                else ""
            )
            return f"{point:.3f}; {ci}; {value['n_records']} rows{inputs} / {value['n_clusters']} clusters"

        def condition_label(condition: Mapping[str, Any]) -> str:
            annotation = (
                _ui_text("dashboard.same_model_haiku_judge")
                if condition["same_model_judge"]
                else ""
            )
            return (
                " / ".join(
                    str(condition[key])
                    for key in (
                        "cohort",
                        "exact_model",
                        "modality",
                        "framework",
                        "corpus",
                        "risk",
                        "expected_behavior",
                    )
                )
                + annotation
            )

        summary, completion = doc["summary"], doc["completion"]
        # Collapsed details still allocate their full DOM. Bound rendered rows,
        # not the retained report or the population used to compute aggregates.
        groups = {
            "outcomes": (_ui_text("dashboard.outcome_conditions"), summary["strata"]),
            "contrasts": (_ui_text("dashboard.matched_model_contrasts"), summary["contrasts"]),
            "tokens": (
                _ui_text("dashboard.token_windows"),
                doc.get("generation_conditions", {}).get("conditions", []),
            ),
        }
        if detail_section not in {"overview", *groups} or detail_page < 0:
            raise ValueError(_ui_text("dashboard.unknown_comparison_detail_page"))
        page_size = 20
        navigation = ""
        if detail_url:
            links = []
            for key, title in [
                ("overview", _ui_text("dashboard.overview")),
                *[(key, value[0]) for key, value in groups.items()],
            ]:
                href = f"{detail_url}&detail_section={key}"
                current = " aria-current='page'" if key == detail_section else ""
                links.append(
                    f"<a data-stats-report href='{html.escape(href, quote=True)}'{current}>{title}</a>"
                )
            navigation = (
                _ui_template(
                    "<nav class='page-tabs' aria-label='[[attr:dashboard.comparison_details]]'>"
                )
                + " ".join(links)
                + "</nav>"
            )

        def window(key: str) -> list:
            title, rows = groups[key]
            if detail_section not in {"overview", key}:
                return []
            page = (
                0
                if detail_section == "overview"
                else min(detail_page, max(0, (len(rows) - 1) // page_size))
            )
            start = page * page_size
            chosen = rows[start : start + page_size]
            if rows:
                parts.append(
                    (
                        "<p class='note'>"
                        + f"{title}"
                        + ": showing "
                        + f"{start + 1}"
                        + "-"
                        + f"{start + len(chosen)}"
                        + " of "
                        + f"{len(rows)}"
                        + _ui_template(
                            "[[text:dashboard.summary_counts_and_rates_above_cover_the_full_selected_population]]</p>"
                        )
                    )
                )
            if len(rows) > page_size and detail_url:
                base = f"{detail_url}&detail_section={key}"
                links = []
                if page:
                    href = html.escape(f"{base}&detail_page={page - 1}", quote=True)
                    links.append(
                        (
                            "<a data-stats-report href='"
                            + f"{href}"
                            + _ui_template("'>[[text:dashboard.previous]] ")
                            + f"{title.lower()}"
                            + "</a>"
                        )
                    )
                if start + len(chosen) < len(rows):
                    href = html.escape(f"{base}&detail_page={page + 1}", quote=True)
                    links.append(
                        (
                            "<a data-stats-report href='"
                            + f"{href}"
                            + _ui_template("'>[[text:dashboard.next]] ")
                            + f"{title.lower()}"
                            + "</a>"
                        )
                    )
                parts.append("<nav aria-label='" + title + " pages'>" + " ".join(links) + "</nav>")
            return chosen

        if doc.get("schema") in {
            "ura-retained-judge-comparison/4",
            "ura-retained-judge-comparison/5",
        }:
            usage = (
                _ui_template("<p>[[text:dashboard.completed_source_batches]] ")
                + f"{len(doc['source_partitions'])}"
                + _ui_text("dashboard.no_new_judge_calls_selected_verdicts")
                + f"{completion['judge_calls']}"
                + "; "
                + f"{completion['http_attempts']}"
                + _ui_text("dashboard.recorded_http_attempts")
                + f"{completion['input_tokens']:,}"
                + " input / "
                + f"{completion['output_tokens']:,}"
                + _ui_text("dashboard.output_tokens_token_priced_selected_usage_usd")
                + f"{completion['actual_cost_microusd'] / 1000000.0:.6f}"
                + _ui_template("[[text:dashboard.source_spending_ledgers_remain_separate]]</p>")
            )
        else:
            usage = (
                "<p>Haiku: "
                + f"{completion['judge_calls']}"
                + _ui_text("dashboard.logical_calls")
                + f"{completion['http_attempts']}"
                + _ui_text("dashboard.http_attempts")
                + f"{completion['input_tokens']:,}"
                + " input / "
                + f"{completion['output_tokens']:,}"
                + _ui_text("dashboard.output_tokens_token_priced_usage_usd")
                + f"{completion['actual_cost_microusd'] / 1000000.0:.6f}"
                + _ui_text("dashboard.plan_ceiling_usd")
                + f"{completion['max_cost_microusd'] / 1000000.0:.6f}"
                + ".</p>"
            )
        parts = [
            f"<div class='card'><h3>{html.escape(name)}</h3>",
            _ui_template(
                "<p class='note'>[[text:dashboard.selected_matched_output_comparison_counts_precede_rates_shared_lo]]</p>"
            ),
            self._count_bar_chart(
                [
                    (
                        _ui_text("dashboard.distinct_local_outputs_judged"),
                        summary["cohorts"]["local"],
                    ),
                    (
                        _ui_text("dashboard.distinct_hosted_outputs_judged"),
                        summary["cohorts"]["hosted"],
                    ),
                    (
                        _ui_text("dashboard.comparison_links_not_paid_calls"),
                        summary["comparison_pairs"],
                    ),
                ],
                label=_ui_text("dashboard.unique_judged_outputs_and_comparison_links"),
            ),
            usage,
            navigation,
            _ui_template(
                "<details><summary>[[text:dashboard.source_view_coverage_before_matched_selection]]</summary>"
            ),
        ]
        if "input_weighting" in summary:
            parts.insert(
                1,
                (
                    _ui_template("<p>[[text:dashboard.input_balanced_comparison]] ")
                    + f"{summary['distinct_inputs']}"
                    + _ui_template(
                        " [[text:dashboard.distinct_inputs_repeated_outputs_are_averaged_per_input_before_eq]]</p>"
                    )
                ),
            )
        if "invalid_verdicts" in completion:
            parts.insert(
                -1,
                (
                    _ui_template("<p>[[text:dashboard.judge_abstentions_from_invalid_verdicts]] ")
                    + f"{completion['invalid_verdicts']}"
                    + _ui_text("dashboard.attempts_with_unknown_usage")
                    + f"{completion['unknown_usage_judgments']}"
                    + _ui_template(
                        "[[text:dashboard.the_displayed_token_priced_amount_is_known_usage_only_not_the_tot]]</p>"
                    )
                ),
            )
        for cohort in ("local", "hosted"):
            audit = doc["plan"]["population"][cohort]
            parts.append(
                (
                    "<h4>"
                    + f"{cohort.title()}"
                    + _ui_template(" [[text:dashboard.source_frame]]</h4>")
                )
                + self._count_bar_chart(
                    [(key.replace("_", " "), value) for key, value in audit.items()],
                    label=(
                        f"{cohort}"
                        + _ui_text("dashboard.source_view_coverage_not_selected_cohort_rates")
                    ),
                )
            )
        parts.append("</details>")
        for row in window("outcomes"):
            condition = row["condition"]
            label = condition_label(condition)
            parts.extend(
                [
                    (
                        "<details><summary>"
                        + f"{html.escape(label)}"
                        + " - "
                        + f"{row['selected_outputs']}"
                        + _ui_template(" [[text:dashboard.outputs]]</summary>")
                    ),
                    _ui_template(
                        "<p class='note'>[[text:dashboard.separate_revision_output_policy_cascade_condition]] "
                    )
                    + html.escape(
                        " / ".join(
                            str(condition[key])
                            for key in (
                                "project_revision_sha256",
                                "output_policy_sha256",
                                "cascade_configuration_sha256",
                            )
                        )
                    )
                    + "</p>",
                ]
            )
            for judge in ("cascade", "haiku"):
                outcome = row[judge]
                parts.append(
                    (
                        "<h4>"
                        + f"{judge.title()}"
                        + ": "
                        + f"{outcome['decided']}"
                        + " decided / "
                        + f"{outcome['abstained']}"
                        + _ui_template(" [[text:dashboard.abstained]]</h4>")
                    )
                )
                chart = self._bar_chart(
                    [
                        (label_name.replace("_", " "), rate["value"])
                        for label_name, rate in outcome["rates"].items()
                        if rate["value"] is not None
                    ]
                )
                parts.append(
                    chart.replace(
                        "aria-label='result chart'",
                        "aria-label='"
                        + html.escape(judge + " outcomes: " + label, quote=True)
                        + "'",
                    )
                )
                parts.append(
                    _ui_template(
                        "<div class='table-scroll'><table><thead><tr><th>[[text:dashboard.label]]</th><th>[[text:dashboard.count]]</th><th>[[text:dashboard.equal_cluster_rate_and_uncertainty]]</th></tr></thead><tbody>"
                    )
                )
                for label_name, rate in outcome["rates"].items():
                    parts.append(
                        f"<tr><td>{html.escape(label_name)}</td><td>{outcome['labels'][label_name]}</td><td>{estimate(rate)}</td></tr>"
                    )
                parts.append("</tbody></table></div>")
            parts.append(
                _ui_template("<p>[[text:dashboard.same_output_label_agreement]] ")
                + estimate(row["agreement"])
                + (
                    "; "
                    + f"{row['agreement']['excluded_abstentions']}"
                    + _ui_template(" [[text:dashboard.excluded_for_abstention]]</p></details>")
                )
            )
        parts.append(
            _ui_template("<details><summary>[[text:dashboard.matched_model_contrasts]]</summary>")
        )
        for contrast in window("contrasts"):
            label = (
                condition_label(contrast["hosted_condition"])
                + " versus "
                + condition_label(contrast["local_condition"])
            )
            parts.append(
                (
                    "<h4>"
                    + f"{html.escape(label)}"
                    + "</h4><p>"
                    + f"{contrast['pairs']}"
                    + _ui_text("dashboard.matched_links")
                    + f"{html.escape(contrast['event'])}"
                    + _ui_template("[[text:dashboard.hosted_minus_local]]</p>")
                )
            )
            for judge in ("cascade", "haiku"):
                rate = contrast[judge]
                parts.append(
                    (
                        "<p>"
                        + f"{judge.title()}"
                        + ": "
                        + f"{estimate(rate)}"
                        + "; "
                        + f"{rate['excluded_abstentions']}"
                        + _ui_template(" [[text:dashboard.abstained_pairs]]</p>")
                    )
                )
        parts.append("</details>")
        conditions = window("tokens")
        if detail_section in {"overview", "tokens"}:
            token_doc = (
                doc
                if "generation_conditions" not in doc
                else {
                    **doc,
                    "generation_conditions": {
                        **doc["generation_conditions"],
                        "conditions": conditions,
                    },
                }
            )
            parts.append(self._render_generation_conditions(token_doc))
        parts.extend(f"<p class='note'>{html.escape(note)}</p>" for note in doc["limitations"])
        return "".join(parts) + "</div>"

    def _stats_report_index_badge(self, report: Mapping[str, Any]) -> str:
        """Compact validation status for an unlinked report; never a chart."""

        rel = str(report.get("path") or "")
        kind = str(report.get("kind") or "")
        if kind not in {"level1", "level2"}:
            return _ui_template(
                "<span class='badge red' title='[[attr:dashboard.only_level_1_level_2_reports_belong_in_this_compatibility_list]]'>[[text:dashboard.unsupported_kind]]</span>"
            )
        try:
            doc = strict_json_loads((self.results_root / rel).read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError(_ui_text("dashboard.report_is_not_an_object"))
            _validate_report_document(kind, doc)
        except (OSError, TypeError, ValueError) as exc:
            return (
                "<span class='badge red' title='"
                + html.escape(str(exc), quote=True)
                + _ui_template("'>[[text:dashboard.invalid]]</span>")
            )
        return _ui_template(
            "<span class='badge green'>[[text:dashboard.validated_but_unlinked]]</span>"
        )

    def _stats_campaign_detail(
        self,
        campaign: Mapping[str, Any],
        *,
        report_index: int | None = None,
        detail_section: str = "overview",
        detail_page: int = 0,
    ) -> str:
        state_label, state_tone = self._stats_state_badge(str(campaign["state"]))
        job_href = str(campaign.get("job_href") or f"/jobs/{quote(str(campaign['job_id']))}")
        artifact_link = ""
        if campaign["artifact_relative"]:
            artifact_link = (
                " <a href='/artifacts?path="
                + quote(str(campaign["artifact_relative"]))
                + _ui_template("'>[[text:dashboard.browse_exact_output_artifacts]]</a>.")
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
            evidence_label = _ui_text("dashboard.not_established")
        available = campaign["reports"]
        rendered: dict[int, str] = {}

        def report_card(index: int) -> str:
            if index not in rendered:
                rendered[index] = self._stats_report_card(
                    available[index],
                    detail_url="/stats/job/" + quote(str(campaign["job_id"])) + f"?report={index}",
                    detail_section=detail_section,
                    detail_page=detail_page,
                )
            return rendered[index]

        if report_index is not None:
            selected = [report_index]
        else:
            selected = [
                index
                for index, report in enumerate(available)
                if report.get("kind")
                in {
                    "terminal_inventory",
                    "execution_accounting",
                }
            ]
            if not selected and available:
                # A diagrams link must not default to a table-only lifecycle
                # report when this campaign has a validated outcome chart.
                selected = [
                    next(
                        (
                            index
                            for index in range(len(available))
                            if "class='barchart'" in report_card(index)
                        ),
                        0,
                    )
                ]
        report_navigation = ""
        if len(available) > 1:
            detail_url = "/stats/job/" + quote(str(campaign["job_id"]))
            links = []
            for index, report in enumerate(available):
                label = str(
                    report.get("display_name")
                    or report.get("path")
                    or (_ui_text("dashboard.report") + f"{index + 1}")
                )
                current = " aria-current='page'" if index == report_index else ""
                artifact = str(report.get("path") or "")
                links.append(
                    f"<li><a data-stats-report href='{detail_url}?report={index}'{current}>"
                    + html.escape(label)
                    + "</a>"
                    + (
                        (
                            " <a href='/artifacts?path="
                            + f"{quote(artifact)}"
                            + _ui_template("'>[[text:dashboard.json]]</a>")
                        )
                        if artifact
                        else ""
                    )
                    + "</li>"
                )
            report_navigation = (
                (
                    _ui_template(
                        "<nav class='card' aria-label='[[attr:dashboard.campaign_reports]]'><h3>[[text:dashboard.reports]]</h3><a data-stats-report href='"
                    )
                    + f"{detail_url}"
                    + _ui_template(
                        "'>[[text:dashboard.overview]]</a><p class='note'>[[text:dashboard.choose_a_report_to_view_its_tables_and_diagrams]]</p><ul>"
                    )
                )
                + "".join(links)
                + "</ul></nav>"
            )
        reports = "".join(report_card(index) for index in selected)
        if not reports:
            reports = _ui_template(
                "<div class='card'><p class='note'>[[text:dashboard.no_validated_level_1_level_2_analysis_job_is_bound_to_this_campai]]</p></div>"
            )
        external_analysis_note = (
            _ui_template(
                "<div class='notice blue'><strong>[[text:dashboard.registered_external_analysis]]</strong><p class='note'>[[text:dashboard.the_generic_operational_registration_and_exact_report_bytes_were]] <code>"
            )
            + html.escape(str(campaign.get("analysis_status") or "unknown"))
            + "</code>.</p></div>"
            if campaign.get("_external_analysis_registration") is not None
            else ""
        )
        limitations = campaign.get("analysis_limitations") or ()
        limitations_note = (
            _ui_template(
                "<div class='notice amber'><strong>[[text:dashboard.analysis_completed_with_explicit_limitations]]</strong><ul>"
            )
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
        runner_results = self._stats_runner_results_card(campaign)
        coverage_text = str(campaign.get("coverage_text") or self._stats_coverage_text(evidence))
        return (
            (
                _ui_template(
                    "<p class='stats-detail-state'>[[text:dashboard.campaign_status]] <span class='badge "
                )
                + f"{state_tone}"
                + "'>"
                + f"{html.escape(state_label)}"
                + "</span></p><div class='notice "
                + f"{evidence_tone}"
                + _ui_template("'><strong>[[text:dashboard.evidence]] ")
                + f"{evidence_label}"
                + ".</strong><p class='note'>"
                + f"{html.escape(coverage_text)}"
                + _ui_text(
                    "dashboard.charts_below_are_rendered_only_from_completion_bound_runner_aggre"
                )
                + f"{artifact_link}"
                + "</p></div>"
            )
            + external_analysis_note
            + limitations_note
            + _ui_template(
                "<div class='card'><h3>[[text:dashboard.recorded_calls_tokens_calculated_cost]]</h3>"
            )
            + self._stats_usage_table(campaign)
            + _ui_template(
                "<p class='note'>[[text:dashboard.usage_is_read_only_from_this_job_s_exact_output_root_and_completi]]</p></div>"
            )
            + runner_results
            + report_navigation
            + reports
            + "<p class='stats-modal-links'><a href='"
            + html.escape(job_href, quote=True)
            + _ui_template("'>[[text:dashboard.open_full_job_record]]</a></p>")
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
            listing = _ui_template(
                "<div class='card'><p class='note'>[[text:dashboard.no_console_owned_or_explicitly_registered_external_campaign_jobs]]</p></div>"
            )
        try:
            engineering, engineering_note = self._engineering_campaign_scan()
        except (AttributeError, OSError, ValueError):
            engineering, engineering_note = (
                [],
                _ui_text("dashboard.engineering_campaign_scan_unavailable"),
            )
        engineering_cards = []
        for campaign in engineering:
            label = html.escape(campaign.campaign_id)
            route = quote(campaign.route_id)
            artifact_route = quote(f"engineering/{campaign.route_id}")
            registration = load_external_analysis_registration(
                self.results_root,
                campaign.route_id,
            )
            display_state_label, display_state_tone = self._stats_state_badge(campaign.status_tag)
            analysis_state = (
                _ui_template("<dt>[[text:dashboard.analysis]]</dt><dd>")
                + html.escape(self._stats_state_badge(registration.completion_status)[0])
                + "</dd>"
                if registration is not None
                else ""
            )
            analysis_action = (
                "<a class='button ghost stats-detail-trigger' href='/stats/job/"
                + route
                + "' data-stats-job='"
                + html.escape(campaign.route_id)
                + _ui_template(
                    "' aria-controls='campaign-stats-modal' aria-haspopup='dialog' aria-expanded='false'>[[text:dashboard.statistics_diagrams]]</a>"
                )
                if registration is not None
                else ""
            )
            engineering_cards.append(
                (
                    "<article class='stats-campaign-card engineering' data-authority='engineering'><div class='stats-campaign-head'><div><h3><a href='/jobs/campaign/"
                    + f"{route}"
                    + "'>"
                    + f"{label}"
                    + _ui_template(
                        "</a></h3><p class='note'>[[text:dashboard.externally_managed_engineering_campaign]]</p></div><span class='badge "
                    )
                    + f"{display_state_tone}"
                    + "'>"
                    + f"{html.escape(display_state_label)}"
                    + _ui_template(
                        "</span></div><dl class='stats-campaign-meta'><dt>[[text:dashboard.authority]]</dt><dd>[[text:dashboard.engineering_non_thesis]]</dd><dt>[[text:dashboard.progress]]</dt><dd>"
                    )
                    + f"{html.escape(campaign.progress)}"
                    + "</dd>"
                )
                + analysis_state
                + (
                    _ui_template("<dt>[[text:dashboard.reported_target_attempts]]</dt><dd>")
                    if campaign.model_execution_scope == "target_only_mixed_controller"
                    else _ui_template("<dt>[[text:dashboard.reported_calls]]</dt><dd>")
                )
                + (
                    _ui_text("dashboard.not_applicable_support_only")
                    if campaign.model_tasks == ()
                    else _ui_text("dashboard.not_reported")
                    if campaign.model_attempted_calls is None
                    else str(campaign.model_attempted_calls)
                )
                + (
                    _ui_template(
                        " [[text:dashboard.operational_self_report]]</dd></dl><p><a href='/jobs/campaign/"
                    )
                    + f"{route}"
                    + _ui_template(
                        "'>[[text:dashboard.open_engineering_details]]</a> <a href='/artifacts?path="
                    )
                    + f"{artifact_route}"
                    + _ui_template("'>[[text:dashboard.browse_campaign_artifacts]]</a></p>")
                )
                + analysis_action
                + "</article>"
            )
        engineering_html = ""
        if page == 1:
            engineering_html = (
                (
                    _ui_template(
                        "<details class='stats-engineering-disclosure'><summary>[[text:dashboard.engineering_campaigns]]"
                    )
                    + f"{len(engineering_cards)}"
                    + _ui_template("[[text:dashboard.non_thesis_operational_records]]</summary>")
                )
                + (
                    f"<div class='notice amber'>{html.escape(engineering_note)}</div>"
                    if engineering_note
                    else ""
                )
                + (
                    "<div class='stats-campaign-list'>" + "".join(engineering_cards) + "</div>"
                    if engineering_cards
                    else _ui_template(
                        "<p class='note'>[[text:dashboard.no_external_engineering_campaigns_retained]]</p>"
                    )
                )
                + "</details>"
            )
        page_links = _ui_template(
            "<nav class='stats-pagination' aria-label='[[attr:dashboard.campaign_pages]]'>"
        )
        if page > 1:
            page_links += (
                "<a class='button ghost' href='/stats?view=legacy&amp;page="
                + f"{page - 1}"
                + _ui_template("'>[[text:dashboard.newer]]</a>")
            )
        page_links += _ui_template("<span>[[text:dashboard.page]] ") + f"{page}" + "</span>"
        if has_more:
            page_links += (
                "<a class='button ghost' href='/stats?view=legacy&amp;page="
                + f"{page + 1}"
                + _ui_template("'>[[text:dashboard.older]]</a>")
            )
        page_links += "</nav>"
        reusable_modal = _ui_template(
            "<section class='stats-modal' id='campaign-stats-modal' data-stats-modal role='dialog' aria-modal='false' aria-labelledby='campaign-stats-title' tabindex='-1'><div class='stats-modal-shell'><header class='stats-modal-head'><div><p class='wizard-kicker'>[[text:dashboard.campaign_details]]</p><h2 id='campaign-stats-title'><span data-stats-modal-title>[[text:dashboard.statistics_diagrams]]</span></h2></div><button type='button' class='ghost small stats-modal-close' data-stats-close aria-label='[[attr:dashboard.close_campaign_statistics]]'>[[text:dashboard.close]]</button></header><div class='stats-modal-body' data-stats-modal-body aria-live='polite'><p class='note'>[[text:dashboard.choose_a_campaign_to_load_its_validated_details]]</p></div></div></section>"
        )
        return (
            _ui_template(
                "<h2>[[text:dashboard.model_campaign_runs]]</h2><p class='note'>[[text:dashboard.model_campaign_attempts_appear_first_passed_means_the_cli_exited]]</p>"
            )
            + listing
            + page_links
            + engineering_html
            + reusable_modal
            + self._stats_modal_script()
        )

    def _stats_job_detail_page(
        self,
        job_id: str,
        *,
        fragment: bool,
        report: str | None = None,
        detail_section: str = "overview",
        detail_page: str = "0",
    ) -> bytes | None:
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_id) is None:
            return None
        if (
            detail_section not in {"overview", "outcomes", "contrasts", "tokens"}
            or re.fullmatch(r"[0-9]{1,6}", detail_page) is None
        ):
            return None
        self._reconcile()
        campaigns, unavailable, _has_more = self._stats_run_campaigns(exact_job_id=job_id)
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
            campaigns = [self._stats_external_analysis_campaign(engineering, registration)]
            unavailable = ""
        if unavailable:
            return None
        campaign = campaigns[0]
        if campaign.get("_external_analysis_registration") is None:
            self._stats_attach_job_reports(campaigns)
        report_index = None
        if report is not None:
            if not re.fullmatch(r"[0-9]{1,6}", report):
                return None
            report_index = int(report)
            if report_index >= len(campaign["reports"]):
                return None
        detail = self._stats_campaign_detail(
            campaign,
            report_index=report_index,
            detail_section=detail_section,
            detail_page=int(detail_page),
        )
        if fragment:
            return detail.encode("utf-8")
        title = _ui_text("dashboard.campaign_statistics") + f"{job_id}"
        return _page(
            title,
            (
                _ui_template(
                    "<p><a href='/stats'>[[text:dashboard.back_to_campaign_statistics]]</a></p><h1>"
                )
                + f"{_icon('chart', size=22)}"
                + f"{html.escape(job_id)}"
                + "</h1>"
            )
            + detail,
            active=_ui_text("dashboard.stats"),
        )

    @staticmethod
    def _stats_modal_script() -> str:
        return _ui_template("""<script>(function(){
var root=document.documentElement;root.classList.add('stats-modal-ready');
var modal=document.getElementById('campaign-stats-modal');
var body=modal&&modal.querySelector('[data-stats-modal-body]');
var title=modal&&modal.querySelector('[data-stats-modal-title]');
var active=false,lastFocus=null,requestId=0;
function focusable(modal){return Array.prototype.slice.call(modal.querySelectorAll(
'a[href],button:not([disabled]),[tabindex]:not([tabindex=\"-1\"])'))
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
function load(href){
var release=window.uraBusy.begin([[js:dashboard.loading_campaign_statistics]]);
var controller=new AbortController(),timer=setTimeout(function(){controller.abort();},90000);
var current=++requestId;body.setAttribute('aria-busy','true');
body.innerHTML=(\"<p class='note'>\"+[[jshtml:dashboard.loading]]+\" \") +
([[jshtml:dashboard.validated_campaign_statistics]]+\"</p>\");var separator=href.indexOf('?')>=0?'&':'?';
fetch(href+separator+'fragment=1',{credentials:'same-origin',signal:controller.signal,headers:{
'X-Requested-With':'ura-stats-modal'}}).then(function(response){
if(!response.ok){throw new Error([[js:dashboard.detail_request_failed]]);}return response.text();})
.then(function(markup){if(active&&current===requestId){body.innerHTML=markup;
body.removeAttribute('aria-busy');}})
.catch(function(){if(active&&current===requestId){body.innerHTML=
(\"<div class='notice red'>\"+[[jshtml:dashboard.campaign_details_could_not_be_loaded]]+\" <a href='\")+
href+(\"'>\"+[[jshtml:dashboard.open_the_standalone_detail_page]]+\"</a>.</div>\");
body.removeAttribute('aria-busy');}}).finally(function(){clearTimeout(timer);release();});}
document.querySelectorAll('[data-stats-job]').forEach(function(trigger){
trigger.addEventListener('click',function(event){event.preventDefault();
open(trigger);if(title){title.textContent=trigger.getAttribute('data-stats-job')||
[[js:dashboard.campaign_statistics_2]];}trigger.setAttribute('aria-expanded','true');load(trigger.href);});});
if(body){body.addEventListener('click',function(event){
var link=event.target.closest('[data-stats-report]');
if(active&&link&&body.contains(link)){event.preventDefault();load(link.href);}});}
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
})();</script>""")

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

    def _render_execution_accounting(
        self,
        rel: str,
        doc: Mapping[str, Any],
        *,
        artifact_relative: str | None = None,
    ) -> str:
        """Render the exact local input/call/output/judge accounting table."""

        rows = doc["rows"]
        totals = doc["totals"]
        plan = doc["population_plan"]
        provider_calls: dict[str, int] = {}
        for row in rows:
            provider = str(row["target_provider"])
            provider_calls[provider] = provider_calls.get(provider, 0) + int(
                row["initial_target_calls"]
            )
        funnel_chart = self._count_bar_chart(
            [
                (_ui_text("dashboard.selected_inputs"), int(totals["selected_inputs"])),
                (_ui_text("dashboard.initial_target_calls"), int(totals["initial_target_calls"])),
                (_ui_text("dashboard.answer_retries"), int(totals["answer_retry_calls"])),
                (
                    _ui_text("dashboard.successful_outputs"),
                    int(totals["successful_output_generations"]),
                ),
                (_ui_text("dashboard.missing_outputs"), int(totals["retained_missing_outputs"])),
            ],
            label=_ui_text("dashboard.local_campaign_input_call_and_output_funnel"),
        )
        provider_chart = self._count_bar_chart(
            sorted(provider_calls.items()),
            label=_ui_text("dashboard.initial_target_calls_by_local_serving_provider"),
        )
        judge_chart = self._count_bar_chart(
            [
                (
                    _ui_text("dashboard.common_local_judgments"),
                    int(totals["common_local_judgments"]),
                ),
                (_ui_text("dashboard.rules_decisions"), int(totals["local_rules_decisions"])),
                (_ui_text("dashboard.guardrail_calls"), int(totals["local_guardrail_calls"])),
                (
                    _ui_text("dashboard.source_authoritative_decisions"),
                    int(totals["source_authoritative_decisions"]),
                ),
                (_ui_text("dashboard.haiku_calls"), int(totals["haiku_judge_calls"])),
            ],
            label=_ui_text("dashboard.local_and_hosted_judge_path_accounting"),
        )
        table_rows = []
        for row in rows:
            table_rows.append(
                "<tr>"
                f"<td>{html.escape(str(row['target_provider']))}<br><code>"
                f"{html.escape(str(row['exact_model']))}</code></td>"
                f"<td>{html.escape(str(row['framework']))}</td>"
                f"<td>{html.escape(str(row['corpus_family']))}<br><code>"
                f"{html.escape(str(row['logical_arm']))}</code></td>"
                f"<td>{html.escape(str(row['modality']))}<br>"
                f"{html.escape(str(row['risk']))}<br>"
                f"{html.escape(str(row['expected_behavior']))}</td>"
                f"<td>{int(row['seed'])}</td>"
                "<td><code>"
                f"{html.escape(str(row['project_revision_sha256'])[:12])}</code><br>"
                f"<code>{html.escape(str(row['output_policy_sha256'])[:12])}</code></td>"
                f"<td>{int(row['selected_inputs']):,}</td>"
                f"<td>{int(row['initial_target_calls']):,}</td>"
                f"<td>{int(row['answer_retry_calls']):,}</td>"
                f"<td>{int(row['successful_output_generations']):,}</td>"
                f"<td>{int(row['retained_missing_outputs']):,}</td>"
                f"<td>{int(row['local_rules_decisions']):,}</td>"
                f"<td>{int(row['local_guardrail_calls']):,}</td>"
                f"<td>{int(row['source_authoritative_decisions']):,}</td>"
                f"<td>{int(row['common_local_judgments']):,}</td>"
                f"<td>{int(row['haiku_judge_calls']):,}</td></tr>"
            )
        if artifact_relative is None:
            artifact_relative = rel
        artifact_note = (
            (
                "<p class='note'><a href='/artifacts?path="
                + f"{quote(artifact_relative)}"
                + _ui_template(
                    "'>[[text:dashboard.open_the_full_validated_execution_accounting]]</a></p>"
                )
            )
            if artifact_relative
            else ""
        )
        return (
            "<div class='card'><h2>"
            + _icon("chart")
            + (
                _ui_template(
                    "[[text:dashboard.campaign_execution_accounting]] <span class='badge blue'>[[text:dashboard.validated_local_evidence]]</span></h2><p class='note'>[[text:dashboard.the_planned_population_contains]] <strong>"
                )
                + f"{int(plan['intended_target_calls_before_optional_defense']):,}"
                + _ui_template(
                    "</strong> [[text:dashboard.target_calls_before_optional_defense_work]] "
                )
                + f"{int(plan['source_authoritative_rows']):,}"
                + _ui_text("dashboard.source_authoritative_and")
                + f"{int(plan['common_judge_eligible_rows']):,}"
                + _ui_template(
                    " [[text:dashboard.common_judge_eligible_the_table_below_reports_observed_success_vi]]</p><h3>[[text:dashboard.input_to_output_funnel]]</h3>"
                )
            )
            + funnel_chart
            + _ui_template("<h3>[[text:dashboard.calls_by_local_provider]]</h3>")
            + provider_chart
            + _ui_template("<h3>[[text:dashboard.judge_coverage]]</h3>")
            + judge_chart
            + _ui_template(
                "<div class='scroll'><table><tr><th>[[text:dashboard.local_provider_exact_model]]</th><th>[[text:dashboard.framework]]</th><th>[[text:dashboard.corpus_logical_arm]]</th><th>[[text:dashboard.modality_risk_behavior]]</th><th>[[text:dashboard.seed]]</th><th>[[text:dashboard.revision_output_policy]]</th><th>[[text:dashboard.selected_inputs_2]]</th><th>[[text:dashboard.initial_calls]]</th><th>[[text:dashboard.retries]]</th><th>[[text:dashboard.successful_outputs_2]]</th><th>[[text:dashboard.missing_outputs_2]]</th><th>[[text:dashboard.rules_decisions_2]]</th><th>[[text:dashboard.guardrail_calls_2]]</th><th>[[text:dashboard.source_authoritative_decisions_2]]</th><th>[[text:dashboard.common_local_judgments_2]]</th><th>[[text:dashboard.haiku_calls]]</th></tr>"
            )
            + "".join(table_rows)
            + "</table></div>"
            + artifact_note
            + "</div>"
        )

    def _render_terminal_inventory(
        self,
        rel: str,
        doc: Mapping[str, Any],
        *,
        artifact_relative: str | None = None,
    ) -> str:
        """Render generic terminal rows without relabelling them as cells."""

        rows = doc["rows"]
        cohort_order = doc["cohort_order"]
        cohort_counts = doc["cohort_counts"]
        failure_rows = doc["failure_rows"]
        revision_pooling = bool(doc["cross_revision_pooling_permitted"])
        source_pooling = bool(doc["cross_source_pooling_permitted"])
        state_counts: dict[str, int] = {}
        for row in rows:
            state = str(row["terminal_state"])
            state_counts[state] = state_counts.get(state, 0) + 1

        cohort_chart = self._count_bar_chart(
            [
                (str(cohort).replace("_", " "), int(cohort_counts[cohort]))
                for cohort in cohort_order
            ],
            label=_ui_text("dashboard.campaign_terminal_rows_by_cohort"),
        )
        state_chart = self._count_bar_chart(
            [(state.replace("_", " "), count) for state, count in sorted(state_counts.items())],
            label=_ui_text("dashboard.campaign_terminal_rows_by_terminal_state"),
        )
        failure_chart = self._count_bar_chart(
            [
                (_ui_text("dashboard.failure_rows_2"), len(failure_rows)),
                (_ui_text("dashboard.other_terminal_rows"), len(rows) - len(failure_rows)),
            ],
            label=_ui_text("dashboard.campaign_failure_row_accounting"),
        )

        def stratum_table(title: str, field: str) -> str:
            strata = doc[field]
            body = "".join(
                "<tr><td><code>"
                + html.escape(str(identity))
                + "</code></td><td>"
                + f"{len(keys):,}"
                + "</td></tr>"
                for identity, keys in strata.items()
            )
            return (
                (
                    "<h3>"
                    + f"{html.escape(title)}"
                    + _ui_template(
                        "</h3><div class='scroll'><table><tr><th>[[text:dashboard.exact_identity]]</th><th>[[text:dashboard.terminal_rows]]</th></tr>"
                    )
                )
                + body
                + "</table></div>"
            )

        failure_detail = (
            _ui_template(
                "<h3>[[text:dashboard.failure_rows_3]]</h3><div class='scroll'><table><tr><th>[[text:dashboard.namespaced_row_key]]</th></tr>"
            )
            + "".join(
                f"<tr><td><code>{html.escape(str(key))}</code></td></tr>" for key in failure_rows
            )
            + "</table></div>"
            if failure_rows
            else _ui_template(
                "<h3>[[text:dashboard.failure_rows_3]]</h3><p class='note'>[[text:dashboard.none_recorded]]</p>"
            )
        )
        if artifact_relative is None:
            artifact_relative = rel
        artifact_note = (
            (
                "<p class='note'><a href='/artifacts?path="
                + f"{quote(artifact_relative)}"
                + _ui_template(
                    "'>[[text:dashboard.open_the_full_validated_terminal_inventory]]</a></p>"
                )
            )
            if artifact_relative
            else ""
        )
        return (
            "<div class='card'><h2>"
            + _icon("chart")
            + _ui_template(
                "[[text:dashboard.campaign_terminal_rows]] <span class='badge blue'>[[text:dashboard.validated_inventory]]</span>"
            )
            + (
                _ui_template(
                    "</h2><p class='note'>[[text:dashboard.terminal_lifecycle_rows_are_not_relabelled_as_runner_cells_the_re]] <strong>"
                )
                + f"{('permitted' if revision_pooling else _ui_text('dashboard.not_permitted'))}"
                + _ui_template("</strong> [[text:dashboard.and_cross_source_pooling_as]] <strong>")
                + f"{('permitted' if source_pooling else _ui_text('dashboard.not_permitted'))}"
                + _ui_template("</strong>[[text:dashboard.the_inventory_contains]] <strong>")
                + f"{len(rows):,}"
                + _ui_template("</strong> [[text:dashboard.terminal_rows_across]] <strong>")
                + f"{len(cohort_order):,}"
                + "</strong> cohorts.</p>"
            )
            + _ui_template("<h3>[[text:dashboard.rows_by_cohort]]</h3>")
            + cohort_chart
            + _ui_template("<h3>[[text:dashboard.rows_by_terminal_state]]</h3>")
            + state_chart
            + _ui_template("<h3>[[text:dashboard.failure_accounting]]</h3>")
            + failure_chart
            + failure_detail
            + stratum_table(
                _ui_text("dashboard.project_revision_strata"), "project_revision_strata"
            )
            + stratum_table(
                _ui_text("dashboard.source_conformance_strata"), "source_conformance_strata"
            )
            + artifact_note
            + "</div>"
        )

    def _render_generation_conditions(self, doc: Mapping[str, Any]) -> str:
        report = doc.get("generation_conditions")
        if not isinstance(report, Mapping):
            return _ui_template(
                "<p class='note'>[[text:dashboard.token_windows_and_truncation_not_recorded_in_this_older_report]]</p>"
            )
        sections = [
            _ui_template(
                "<section data-section='generation-conditions'><h3>[[text:dashboard.token_windows_and_completion]]</h3><p class='note'>[[text:dashboard.context_capacity_output_allowance_and_reported_usage_are_separate]]</p>"
            )
        ]

        def shown(value: Any) -> str:
            return (
                _ui_text("dashboard.not_recorded")
                if value is None
                else _ui_text("dashboard.runtime_maximum")
                if value == -1
                else html.escape(str(value))
            )

        def usage(value: Mapping[str, Any], rows: int) -> str:
            n = value["reported_rows"]
            if not n:
                return _ui_text("dashboard.not_recorded_0") + f"{rows}" + " rows)"
            return (
                f"{value['sum']:,}"
                + " total; "
                + f"{value['minimum']:,}"
                + "-"
                + f"{value['maximum']:,}"
                + _ui_text("dashboard.per_row_reported")
                + f"{n}"
                + "/"
                + f"{rows}"
            )

        for row in report["conditions"]:
            label = " / ".join(
                str(row[k]) for k in ("model_spec", "corpus_arm", "attacker", "modality")
            )
            label += f" / context {shown(row['context_tokens'])}, output {shown(row['output_allowance'])}"
            sections.append(
                "<details class='card'><summary>"
                + html.escape(label)
                + (
                    " - "
                    + f"{row['rows']}"
                    + _ui_template(" [[text:dashboard.responses]]</summary>")
                )
                + _ui_template(
                    "<div class='scroll'><table><thead><tr><th>[[text:dashboard.run]]</th><th>[[text:dashboard.context_tokens]]</th><th>[[text:dashboard.output_allowance]]</th><th>[[text:dashboard.reported_input_tokens]]</th><th>[[text:dashboard.reported_output_tokens]]</th><th>[[text:dashboard.missing_output]]</th><th>[[text:dashboard.input_context_errors]]</th><th>[[text:dashboard.transport_failures]]</th><th>[[text:dashboard.transport_retry_pending]]</th></tr></thead><tbody><tr>"
                )
                + f"<td>{html.escape(row['run_id'])}</td>"
                + f"<td>{shown(row['context_tokens'])} ({html.escape(row['context_source'])}; "
                + f"policy {shown(row['context_policy'])})</td>"
                + f"<td>{shown(row['output_allowance'])} ({html.escape(row['output_source'])})</td>"
                + f"<td>{usage(row['input_tokens'], row['rows'])}</td>"
                + f"<td>{usage(row['output_tokens'], row['rows'])}</td>"
                + f"<td>{row['missing_output']}/{row['rows']}</td>"
                + f"<td>{row['input_context_error']}/{row['rows']}</td>"
                + f"<td>{shown(row.get('transport_failure'))}</td>"
                + f"<td>{shown(row.get('transport_retry_pending'))}</td></tr></tbody></table></div>"
                + _ui_template(
                    "<h4 data-chart='generation-completion'>[[text:dashboard.provider_completion_reasons]]</h4>"
                )
                + self._count_bar_chart(
                    [
                        (_ui_text("dashboard.normal_stop"), row["normal_stop"]),
                        (_ui_text("dashboard.truncated"), row["truncated"]),
                        (_ui_text("dashboard.other_stop"), row["other_stop"]),
                        (_ui_text("dashboard.not_recorded_2"), row["unknown_stop"]),
                    ],
                    label=_ui_text("dashboard.generation_completion_counts"),
                )
                + "</details>"
            )
        return "".join(sections) + "</section>"

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
            if artifact_relative is None:
                artifact_relative = rel
            artifact_note = (
                (
                    "<p class='note'><a href='/artifacts?path="
                    + f"{quote(artifact_relative)}"
                    + _ui_template("'>[[text:dashboard.open_the_full_validated_artifact]]</a></p>")
                )
                if artifact_relative
                else _ui_template(
                    "<p class='note'>[[text:dashboard.this_report_is_retained_outside_the_configured_artifact_root_so_n]]</p>"
                )
            )
            return (
                "<div class='card'><h2>"
                + _icon("chart")
                + (
                    f"{html.escape(rel)}"
                    + _ui_template(
                        "</h2><p class='note'>[[text:dashboard.validated_level_2_report_with_no_common_estimate_rows_native_only]]</p>"
                    )
                )
                + artifact_note
                + self._render_generation_conditions(doc)
                + "</div>"
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
                        _ui_template("<p class='note'>[[text:dashboard.chart_shows]] ")
                        + f"{self._LEVEL2_CHART_CAP}"
                        + " of "
                        + f"{len(rows)}"
                        + " rows; all "
                        + f"{len(rows)}"
                        + _ui_template(" [[text:dashboard.are_in_the_table_below]]</p>")
                    )
            else:
                chart = _ui_template(
                    "<p class='note'>[[text:dashboard.not_charted_values_are_not_rates_in_0_1_the_table_below_is_the_pr]]</p>"
                )
            stability_bars = []
            for row in rows[: self._LEVEL2_CHART_CAP]:
                completed = row.get("judgments_completed")
                missing = row.get("judgments_missing_responses")
                if (
                    isinstance(completed, int)
                    and not isinstance(completed, bool)
                    and completed > 0
                    and isinstance(missing, int)
                    and not isinstance(missing, bool)
                    and 0 <= missing <= completed
                ):
                    stability_bars.append(
                        (
                            f"{row.get('model_spec', '?')} / {row.get('corpus_arm', '?')}",
                            missing / completed,
                        )
                    )
            stability_chart = (
                _ui_template(
                    "<h4 data-chart='model-stability-failed-output'>[[text:dashboard.response_availability_failed_output_rate]]</h4>"
                )
                + self._bar_chart(stability_bars)
                + _ui_template(
                    "<p class='note'>[[text:dashboard.missing_responses_include_model_output_and_infrastructure_failure]]</p>"
                )
                if stability_bars
                else _ui_template(
                    "<h4>[[text:dashboard.response_availability]]</h4><p class='note'>[[text:dashboard.n_a_this_older_report_does_not_carry_completed_and_missing_respon]]</p>"
                )
            )
            table_rows = []
            for row in rows:  # every bounded row, never truncated
                ci_low, ci_high = row.get("ci_low"), row.get("ci_high")
                ci = (
                    f"[{ci_low:.3f}, {ci_high:.3f}]"
                    if isinstance(ci_low, (int, float)) and isinstance(ci_high, (int, float))
                    else _ui_text("dashboard.n_a_no_ci_recorded")
                )
                completed = row.get("judgments_completed")
                decided = row.get("judgments_decided")
                coverage = (
                    f"{decided}/{completed}"
                    if isinstance(decided, int) and isinstance(completed, int)
                    else "N/A"
                )
                missing_responses = row.get("judgments_missing_responses")
                missing_response_text = (
                    f"{missing_responses:,}"
                    if isinstance(missing_responses, int)
                    and not isinstance(missing_responses, bool)
                    else _ui_text("dashboard.n_a_older_report")
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
                    evidence = "⚠ synthetic + approximate" if synthetic else "⚠ approximate"
                    reliability = row.get("reliability_score")
                    reliability_text = (
                        (
                            f"{float(reliability):.4f}"
                            + _ui_text("dashboard.heuristic_not_probability")
                        )
                        if isinstance(reliability, (int, float))
                        and not isinstance(reliability, bool)
                        else "invalid/missing"
                    )
                else:
                    evidence = "authoritative/source-native"
                    reliability_text = "N/A"
                query_count = row.get("approximate_model_query_count")
                reference_count = row.get("approximate_source_reference_use_count")
                proxy_support = (
                    f"{query_count}/{reference_count}"
                    if isinstance(query_count, int) and isinstance(reference_count, int)
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
                    f"<td>{html.escape(missing_response_text)}</td>"
                    f"<td>{proxy_support}</td>"
                    f"<td>{html.escape(evidence)}</td>"
                    f"<td>{html.escape(reliability_text)}</td></tr>"
                )
            authority_badge = ""
            authority_note = ""
            if rows[0].get("metric_authority") == "supplementary_non_authoritative":
                synthetic = rows[0].get("evidence_class") == "synthetic"
                authority_badge = (
                    _ui_template(
                        " <span class='badge red'>[[text:dashboard.synthetic_approximate]]</span>"
                    )
                    if synthetic
                    else _ui_template(
                        " <span class='badge amber'>[[text:dashboard.approximate]]</span>"
                    )
                )
                authority_note = _ui_template(
                    "<p class='note'>[[text:dashboard.supplementary_non_authoritative_response_proxy_reliability_is_an]]</p>"
                )
            sections.append(
                (
                    "<h3>"
                    + f"{html.escape(str(fields['metric']))}"
                    + f"{authority_badge}"
                    + " <span class='fieldhint'>("
                    + f"{len(rows)}"
                    + _ui_template(" [[text:dashboard.row_s]]</span><br>")
                )
                + label_bits
                + "</h3>"
                + authority_note
                + chart
                + stability_chart
                + _ui_template(
                    "<div class='scroll'><table><tr><th>model_spec</th><th>corpus_arm</th><th>[[text:dashboard.attacker_2]]</th><th>[[text:dashboard.defense]]</th><th>[[text:dashboard.value_2]]</th><th>[[text:dashboard.ci_low_ci_high]]</th><th>n_records</th><th>n_clusters</th><th>decided/completed</th><th>[[text:dashboard.failed_missing_responses_all_causes]]</th><th>[[text:dashboard.model_queries_reference_uses]]</th><th>[[text:dashboard.evidence_2]]</th><th>[[text:dashboard.reliability]]</th></tr>"
                )
                + "".join(table_rows)
                + "</table></div>"
            )
        if artifact_relative is None:
            artifact_relative = rel
        artifact_note = (
            (
                "<p class='note'><a href='/artifacts?path="
                + f"{quote(artifact_relative)}"
                + _ui_template("'>[[text:dashboard.open_the_full_validated_artifact]]</a></p>")
            )
            if artifact_relative
            else _ui_template(
                "<p class='note'>[[text:dashboard.this_report_is_retained_outside_the_configured_artifact_root_so_n]]</p>"
            )
        )
        return (
            "<div class='card'><h2>"
            + _icon("chart")
            + (
                f"{html.escape(rel)}"
                + _ui_template(
                    " <span class='badge blue'>[[text:dashboard.measured_artifact]]</span>"
                )
            )
            + (
                _ui_template(
                    " <span class='badge amber'>[[text:dashboard.contains_supplementary_proxies]]</span>"
                )
                if contains_approximate
                else ""
            )
            + "</h2>"
            + _ui_template(
                "<p class='note'>[[text:dashboard.deterministic_level_2_export]]<code>common.estimates</code>). One chart per COMPATIBLE metric stratum (exact run/served target/source/policy/modality/population/attacker/defense/judge/sampling condition); distinct targets or runs are not presented as a ranking, and no universal safety score exists. Diagnostic evidence cannot reach this report by construction.</p>"
            )
            + self._render_generation_conditions(doc)
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
            badge = _ui_template("<span class='badge blue'>[[text:dashboard.measured]]</span>")
        elif kind == "diagnostic_dry_run":
            badge = _ui_template(
                "<span class='badge amber'>[[text:dashboard.diagnostic_dry_run]]</span>"
            )
        else:
            badge = (
                _ui_template(
                    "<span class='badge gray'>[[text:dashboard.unknown_invalid_evidence_kind]]"
                )
                + f"{html.escape(kind)}"
                + ")</span>"
            )
        tables = []
        for title, key in (
            (_ui_text("dashboard.prospective_request_units"), "prospective_request_units"),
            (_ui_text("dashboard.planning_strata"), "planning_strata"),
            (_ui_text("dashboard.execution_units"), "execution_units"),
            (_ui_text("dashboard.judgment_records"), "judgment_records"),
            (
                _ui_text("dashboard.supplementary_approximate_proxy_judgment_records"),
                "approximate_proxy_judgment_records",
            ),
            (_ui_text("dashboard.request_level_errors"), "request_level_errors"),
        ):
            block = counts.get(key)
            if not isinstance(block, Mapping):
                tables.append(
                    (
                        "<h3>"
                        + f"{html.escape(title)}"
                        + _ui_template(
                            "</h3><p class='note'>[[text:dashboard.n_a_not_supplied_in_this_artifact]]</p>"
                        )
                    )
                )
                continue
            cells = "".join(
                "<tr><td>"
                + html.escape(str(name).replace("_", " "))
                + "</td><td>"
                + (
                    _ui_text("dashboard.null_by_design")
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
            (
                "<p class='note'><a href='/artifacts?path="
                + f"{quote(artifact_relative)}"
                + _ui_template("'>[[text:dashboard.open_the_full_validated_artifact]]</a></p>")
            )
            if artifact_relative
            else _ui_template(
                "<p class='note'>[[text:dashboard.this_report_is_retained_outside_the_configured_artifact_root_so_n]]</p>"
            )
        )
        return (
            "<div class='card'><h2>"
            + _icon("file")
            + (
                f"{html.escape(rel)}"
                + " "
                + f"{badge}"
                + _ui_template(
                    "</h2><p class='note'>[[text:dashboard.level_1_lifecycle_inventory_request_units_planning_strata_executi]]</p>"
                )
            )
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
            "<div class='card'><h2>"
            + _icon("file")
            + (
                _ui_template("[[text:dashboard.unlinked_report_artifacts]]</h2><ul>")
                + f"{''.join(listed)}"
                + "</ul></div>"
            )
            if listed
            else _ui_template(
                "<div class='card'><p class='note'>[[text:dashboard.no_level_1_level_2_report_artifacts_remain_unlinked_analysis_jobs]]</p></div>"
            )
        )
        unlinked_panel = (
            _ui_template(
                "<div class='notice amber'><strong>[[text:dashboard.unlinked_analysis_artifacts_are_not_campaign_evidence]]</strong><p class='note'>[[text:dashboard.this_compatibility_view_contains_only_report_schemas_outside_expl]]</p></div>"
            )
            + results
        )
        stats_tabs = (
            ("stats-campaigns", _ui_text("dashboard.executions")),
            ("stats-operational", _ui_text("dashboard.operational_cost")),
            ("stats-unlinked", _ui_text("dashboard.unlinked_reports")),
        )
        body = (
            "<h1>"
            + _icon("chart", size=22)
            + _ui_template("[[text:dashboard.earlier_run_reports]]</h1>")
            + self._health_banner()
            + self._work_view_tabs("stats", "legacy")
            + _ui_template(
                "<div class='notice blue'><strong>[[text:dashboard.earlier_report_publications]]</strong><p class='note'>[[text:dashboard.each_card_is_one_retained_console_job_run_calls_tokens_costs_cove]]</p></div>"
            )
            + "<div class='page-tabs' data-page-tabs data-tab-key='stats' "
            "data-default-tab='stats-campaigns'>"
            + _page_tablist(
                _ui_text("dashboard.statistics_sections"), stats_tabs, default="stats-campaigns"
            )
            + _page_tabpanel("stats-campaigns", campaign_panel)
            + _page_tabpanel(
                "stats-operational",
                _ui_template(
                    "<p class='note'>[[text:dashboard.operational_spend_is_accounting_only_it_is_never_a_scientific_agg]]</p>"
                )
                + self._spend_card(),
            )
            + _page_tabpanel("stats-unlinked", unlinked_panel)
            + "</div>"
        )
        return _page(
            _ui_text("dashboard.campaign_statistics_2"), body, active=_ui_text("dashboard.stats")
        )

    # -- campaign builder --------------------------------------------------

    def _dashboard_hardware_card(self) -> str:
        gpus = [gpu for gpu in self.gpu_hardware.get("gpus", []) if isinstance(gpu, Mapping)]
        if not self.gpu_hardware.get("available"):
            summary = _ui_text("dashboard.no_nvidia_gpu_detected_local_model_fit_is_unknown")
        else:
            names = ", ".join(
                f"GPU {gpu.get('index', '?')}: {gpu.get('name', 'unknown')} "
                f"({gpu.get('vram_gib', '?')} GiB, SM {gpu.get('compute_capability', '?')})"
                for gpu in gpus
            )
            summary = (
                f"{self.gpu_hardware.get('gpu_count', len(gpus))}"
                + " GPU(s), "
                + f"{self.gpu_hardware.get('aggregate_vram_gib', 0)}"
                + _ui_text("dashboard.gib_aggregate_vram")
            ) + (f" - {names}" if names else "")
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
            details = [(f"{shown(gpu.get('vram_gib'))}" + _ui_text("dashboard.gib_vram"))]
            if gpu.get("compute_capability"):
                details.append("SM " + shown(gpu["compute_capability"]))
            if gpu.get("pci_bus_id"):
                details.append("PCI " + shown(gpu["pci_bus_id"]))
            if gpu.get("driver_version"):
                details.append("driver " + shown(gpu["driver_version"]))
            gpu_rows.append(
                _ui_template("<li><strong>[[text:dashboard.gpu]] ")
                + shown(gpu.get("index", "?"))
                + " - "
                + shown(gpu.get("name", "unknown"))
                + "</strong>"
                "<span class='fieldhint'>" + " &middot; ".join(details) + "</span></li>"
            )
        gpu_content = (
            "<ul class='hardware-list'>" + "".join(gpu_rows) + "</ul>"
            if self.gpu_hardware.get("available") and gpu_rows
            else _ui_template(
                "<div class='notice amber'>[[text:dashboard.no_nvidia_gpu_detected_local_model_fit_is_unknown]]</div>"
            )
        )
        return (
            "<div class='card' id='rig-hardware' aria-label='"
            + html.escape(summary, quote=True)
            + _ui_template(
                "'><h2>[[text:dashboard.rig_hardware]]</h2><div class='hardware-grid'><section><h3>[[text:dashboard.system]]</h3><dl class='hardware-spec'><dt>[[text:dashboard.os]]</dt><dd>"
            )
            + shown(system.get("platform"))
            + _ui_template("</dd><dt>[[text:dashboard.cpu]]</dt><dd>")
            + shown(system.get("cpu_model"))
            + _ui_template("</dd><dt>[[text:dashboard.cores]]</dt><dd>")
            + html.escape(cores)
            + _ui_template("</dd><dt>[[text:dashboard.ram]]</dt><dd>")
            + shown(system.get("total_ram_gib"), _ui_text("dashboard.gib"))
            + _ui_template(
                "</dd></dl></section><section><h3>[[text:dashboard.gpus]] <span class='badge blue'>"
            )
            + shown(self.gpu_hardware.get("gpu_count", len(gpus)))
            + "</span></h3>"
            + gpu_content
            + _ui_template(
                "</section></div><p class='note'>[[text:dashboard.detected_once_at_console_startup_no_model_or_provider_call_is_mad]] <strong>"
            )
            + shown(self.gpu_hardware.get("aggregate_vram_gib"), _ui_text("dashboard.gib"))
            + "</strong>.</p></div>"
        )
