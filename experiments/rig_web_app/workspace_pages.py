"""Campaign navigation. Configuration and execution remain in Build/Run."""

from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from .ui import _page


class WorkspacePagesMixin:
    def _workspace_source_link(self, reference: str) -> str:
        path, separator, row = reference.rpartition(":")
        locator = path if separator and row.isdigit() else reference
        candidate = Path(locator)
        if not candidate.is_absolute():
            candidate = self.results_root / candidate
        try:
            relative = candidate.resolve().relative_to(self.results_root.resolve()).as_posix()
        except (OSError, ValueError, RuntimeError):
            return html.escape(reference)
        label = "Open retained artifact" + (f" (row {row})" if separator and row.isdigit() else "")
        return "<a href='/artifacts?path=" + quote(relative, safe="") + "'>" + label + "</a>"

    def _campaign_selector(self, selected: str = "", *, form_id: str = "") -> str:
        if selected:
            self.db.require_workspace(selected)
        rows = self.db.workspaces()
        if rows is None:
            return "<p class='notice red'>Campaign index unavailable. No ownership was inferred.</p>"
        options = "<option value=''>Standalone work (no campaign)</option>" + "".join(
            "<option value='" + row["campaign_id"] + "'"
            + (" selected" if row["campaign_id"] == selected else "")
            + ">" + html.escape(row["name"]) + "</option>"
            for row in rows
        )
        association = f" form='{html.escape(form_id)}'" if form_id else ""
        return (
            "<label>Campaign <select name='campaign_id'" + association + ">"
            + options + "</select></label> "
            "<a href='/campaigns#new-campaign'>New campaign</a>"
            "<p class='note'>Saved with this launch. Changing another tab does not move running work.</p>"
        )

    def _campaign_banner(self, campaign_id: str) -> str:
        if not campaign_id:
            return "<p class='note'>Standalone work (no campaign).</p>"
        self.db.require_workspace(campaign_id)
        campaign = self.db.workspace(campaign_id)
        return (
            "<p>Campaign: <a href='/campaigns/" + campaign_id + "'>"
            + html.escape(campaign["name"]) + "</a></p>"
        )

    def _workspaces_page(self) -> bytes:
        rows = self.db.workspaces()
        cards = "<p class='notice red'>Campaign index unavailable.</p>" if rows is None else "".join(
            "<article class='card'><h2><a href='/campaigns/" + row["campaign_id"] + "'>"
            + html.escape(row["name"]) + "</a></h2><p>"
            + html.escape(row["kind"].upper()) + " campaign</p>"
            "<a class='button' href='/build?campaign_id=" + row["campaign_id"]
            + "'>Continue in Build</a></article>" for row in rows
        )
        if rows == []:
            cards = "<p>No campaigns created yet. Existing standalone jobs are unchanged.</p>"
        return _page(
            "Campaigns", "<h1>Campaigns</h1>"
            "<p>Keep related collection, judging and analysis together. Configure work in Build.</p>"
            + cards
            + "<section class='card' id='new-campaign'><h2>New campaign</h2>"
            "<form method='post' action='/campaigns' data-busy>"
            "<label>Name <input name='name' required maxlength='120'></label> "
            "<label>Targets <select name='kind'><option value='local'>Local</option>"
            "<option value='api'>API</option><option value='mixed'>Mixed</option></select></label> "
            "<button>Create and open Build</button></form></section>", active="Campaigns",
        )

    def _workspace_page(self, campaign_id: str, query: dict[str, str]) -> bytes:
        self.db.require_workspace(campaign_id)
        campaign = self.db.workspace(campaign_id)
        section = query.get("section", "overview")
        sections = ("overview", "results", "judging", "costs", "activity")
        if section not in sections:
            raise ValueError("Unknown campaign section")
        base = "/campaigns/" + campaign_id
        navigation = "<nav class='page-tablist' aria-label='Campaign sections'>" + "".join(
            "<a class='page-tab' href='" + base + "?section=" + tab + "'"
            + (" aria-current='page'" if tab == section else "") + ">"
            + tab.title() + "</a>" for tab in sections
        ) + "</nav>"
        if section == "activity":
            offset = max(0, int(query.get("page", "0"))) * 50
            rows = self.db.workspace_activity(campaign_id, offset=offset)
            if rows is None:
                content = "<p class='notice red'>Activity index unavailable.</p>"
            elif not rows:
                content = "<p>No activities on this page.</p>"
            else:
                records = []
                for row in rows[:50]:
                    kind, key = row["member_kind"], row["member_id"]
                    prefixes = {"job": "/jobs/", "external": "/jobs/external/",
                                "controller": "/jobs/campaign/", "analysis": "/stats/job/"}
                    link = ("<a href='" + prefixes[kind] + quote(key, safe="") + "'>"
                            + html.escape(row["command"] or key) + "</a>") if kind in prefixes else html.escape(key)
                    records.append("<tr><td>" + link + "</td><td>" + html.escape(row["role"])
                                   + "</td><td>" + ("Console" if kind == "job" else "External reference")
                                   + "</td><td>" + html.escape(row["state"] or "See original record") + "</td></tr>")
                content = "<div class='scroll'><table><tr><th>Activity</th><th>Stage</th><th>Origin</th><th>Status</th></tr>" + "".join(records) + "</table></div>"
                if offset:
                    content += f"<a href='{base}?section=activity&amp;page={offset // 50 - 1}'>Previous</a> "
                if len(rows) > 50:
                    content += f"<a href='{base}?section=activity&amp;page={offset // 50 + 1}'>Next</a>"
        else:
            content = self._workspace_results(campaign_id, section, query)
        return _page(
            campaign["name"], "<h1>" + html.escape(campaign["name"]) + "</h1>"
            "<p><a class='button' href='/build?campaign_id=" + campaign_id + "'>Configure in Build</a> "
            "<a class='button ghost' href='/commands?campaign_id=" + campaign_id + "'>Run tools</a></p>"
            + navigation + "<section class='card'><h2>" + section.title() + "</h2>" + content + "</section>",
            active="Campaigns",
        )

    def _workspace_results(self, campaign_id: str, section: str, query: dict[str, str]) -> str:
        unknown = (
            "<p class='notice amber'>Retained " + html.escape(section)
            + " data has not been indexed for this campaign yet. Totals are unknown, not zero.</p>"
            "<p>Build launches are associated automatically. Original jobs and reports remain accessible in Activity.</p>"
        )
        if section == "costs":
            return unknown  # no invented zero bill before cost attribution
        page = max(0, int(query.get("page", "0")))
        base = "/campaigns/" + campaign_id + "?section=" + section

        def pagination(has_next):
            return ((f"<a href='{base}&amp;page={page - 1}'>Previous</a> " if page else "")
                    + (f"<a href='{base}&amp;page={page + 1}'>Next</a>" if has_next else ""))

        def table(headers, rows):
            return "<div class='scroll'><table><tr>" + "".join("<th>" + h + "</th>" for h in headers) + "</tr>" + "".join(
                "<tr>" + "".join("<td>" + cell + "</td>" for cell in row) + "</tr>" for row in rows
            ) + "</table></div>"

        if section == "judging":
            rows = self.db.workspace_judging_totals(campaign_id)
            if not rows:
                return unknown
            return "<p>Verdicts for the explicitly selected outputs. Other historical judgments remain retained.</p>" + table(
                ("Judge condition", "Status", "Verdicts"),
                [[html.escape(row["judge_id"]), html.escape(row["status"]), str(row["count"])] for row in rows],
            )
        if section == "overview":
            rows = self.db.workspace_model_totals(campaign_id, offset=page * 25)
            if not rows:
                return unknown
            chart = self._count_bar_chart(
                [(row["model"] + " / " + row["evidence_class"], int(row["usable"] or 0) + int(row["policy"] or 0)) for row in rows[:25]],
                label="Retained usable and policy outcomes by model",
            )
            return (
                "<p>Explicitly indexed assignments, not sums of overlapping job reports. "
                "Pending means no selected retained outcome; it does not establish that no HTTP attempt occurred. "
                "Truncation overlaps usable/missing outcomes and is not an additional outcome bucket. "
                "Execution conditions remain distinct; these counts are not pooled safety rates.</p>"
                + chart + table(
                    ("Model", "Evidence", "Conditions", "Assigned", "Usable", "Policy", "Missing", "Retry pending", "Pending", "Truncated", "Truncation unknown"),
                    [["<a href='/campaigns/" + campaign_id + "?section=results&amp;model=" + quote(row["model"], safe="") + "'>" + html.escape(row["model"]) + "</a>"]
                     + [html.escape(row["evidence_class"])]
                     + [str(row[key] or 0) for key in ("conditions", "assigned", "usable", "policy", "missing", "retry_pending", "pending", "truncated", "truncation_unknown")]
                     for row in rows[:25]],
                ) + pagination(len(rows) > 25)
            )
        model = query.get("model", "")
        if model:
            base += "&amp;model=" + quote(model, safe="")
        rows = self.db.workspace_result_rows(campaign_id, offset=page * 50, model=model)
        if not rows:
            return unknown
        output = []
        for row in rows[:50]:
            details = json.loads(row["details"]) if row["details"] else {}
            def value(key):
                item = details.get(key)
                return "unknown" if item is None else html.escape(str(item))
            metadata = "<details><summary>Generation settings and usage</summary><dl>" + "".join(
                "<dt>" + label + "</dt><dd>" + value(key) + "</dd>" for key, label in (
                    ("context_tokens", "Effective context"), ("output_allowance", "Output allowance"),
                    ("input_tokens", "Reported input tokens"), ("output_tokens", "Reported output tokens"),
                    ("reasoning_tokens", "Reported reasoning tokens"), ("finish_reason", "Finish reason"),
                    ("missing_category", "Missing-output category"))) + "</dl>"
            metadata += "<p>Condition: " + html.escape(row["response_condition"] or row["condition_id"]) + "</p>"
            metadata += "<p>Source: " + (self._workspace_source_link(details["source_ref"]) if details.get("source_ref") else "unknown") + "</p></details>"
            output.append([html.escape(row["model"]), html.escape(row["input_id"]),
                           html.escape(row["evidence_class"]), html.escape(row["modality"]), html.escape(row["framework"] + " / " + row["corpus"]),
                           html.escape(row["outcome"] or "pending"),
                           "unknown" if row["truncated"] is None else "yes" if row["truncated"] else "no", metadata])
        return table(("Model", "Input", "Evidence", "Modality", "Framework / corpus", "Outcome", "Truncated", "Details"), output) + pagination(len(rows) > 50)
