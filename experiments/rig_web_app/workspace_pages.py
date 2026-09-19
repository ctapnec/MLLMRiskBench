"""Campaign navigation. Configuration and execution remain in Build/Run."""

from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import quote

from .ui import _page
from .workspace_charts import coverage_html, coverage_svg, quality_svg, model_counts_csv, EXPORT_SCRIPT
from .workspace_judging_charts import judgment_groups, judgment_breakdown_html, judgment_counts_csv, judgment_breakdown_svg
from .workspace_judge_settings import indexed_settings, judge_name
from .workspace_review_coverage import review_coverage_html


class WorkspacePagesMixin:
    @staticmethod
    def _workspace_result_scope(query: dict[str, str]) -> tuple[str, str]:
        model, condition = query.get("model", ""), query.get("condition", "")
        if condition and not model:
            raise ValueError("Choose a model before selecting its execution condition")
        return model, condition

    def _workspace_result_filters(self, campaign_id: str, section: str, query: dict[str, str]) -> str:
        model, condition = self._workspace_result_scope(query)
        models = self.db.workspace_result_models(campaign_id)
        if not models:
            return ""
        action = "/campaigns/" + campaign_id
        retained_judge = ("<input type='hidden' name='judge' value='"+html.escape(query['judge'],quote=True)+"'>"
            if section=='judging' and query.get('judge') else '')
        options = "<option value=''>All models</option>" + "".join(
            "<option value='" + html.escape(row["model"], quote=True) + "'"
            + (" selected" if row["model"] == model else "") + ">" + html.escape(row["model"]) + "</option>"
            for row in models
        )
        if model and not any(row["model"] == model for row in models):
            options += "<option selected value='" + html.escape(model, quote=True) + "'>Unknown model</option>"
        content = (
            "<div class='campaign-result-filters'><form method='get' action='" + action + "'>"
            "<input type='hidden' name='section' value='" + section + "'>"
            + retained_judge +
            "<label class='campaign-field'>Model<select name='model'>" + options + "</select></label>"
            "<button type='submit'>Choose model</button></form>"
        )
        if model:
            conditions = self.db.workspace_result_conditions(campaign_id, model=model)
            if conditions is None:
                return content + "<p class='notice red'>Execution-condition index unavailable.</p></div>"

            def allowance(row, prefix):
                low, high = row[prefix + "_min"], row[prefix + "_max"]
                def tokens(value):
                    return "native maximum" if value == -1 else f"{value:,}"
                value = "unknown" if low is None else tokens(low) if low == high else tokens(low) + " to " + tokens(high)
                if 0 < row[prefix + "_known"] < row["assigned"]:
                    value += " (partly unknown)"
                return value

            options = "<option value=''>All retained conditions (includes history)</option>"
            for index, row in enumerate(conditions, 1):
                label = (f"Condition {index}: context {allowance(row, 'context')}; output {allowance(row, 'output')}; "
                         f"{row['assigned']:,} assignments")
                options += ("<option value='" + html.escape(row["condition_id"], quote=True) + "'"
                    + (" selected" if row["condition_id"] == condition else "") + ">" + html.escape(label) + "</option>")
            if condition and not any(row["condition_id"] == condition for row in conditions):
                options += "<option selected value='" + html.escape(condition, quote=True) + "'>Unknown execution condition</option>"
            content += (
                "<form method='get' action='" + action + "'><input type='hidden' name='section' value='" + section + "'>"
                + retained_judge +
                "<input type='hidden' name='model' value='" + html.escape(model, quote=True) + "'>"
                "<label class='campaign-field'>Execution condition<select name='condition'>" + options + "</select></label>"
                "<button type='submit'>View condition</button></form>"
            )
        else:
            content += "<p class='note'>Choose a model to inspect its individual execution conditions.</p>"
        return content + (
            "</div><p class='note'>All conditions includes historical failures and later corrections. "
            "A condition filter keeps charts, output rows, verdict counts and exports on the same selection. "
            "It does not select the newest or best answer automatically. Costs remain campaign-wide.</p>"
        )

    def _save_build_campaign(self, params: dict[str, str]) -> dict[str, str]:
        if params.get("work_kind") != "campaign" and not params.get("campaign_id"):
            return params
        result = self._builder_params(params)
        campaign_id = result.get("campaign_id")
        if not campaign_id:
            campaign_id = self.db.create_workspace(result["campaign_name"], "mixed")
        result.update(campaign_id=campaign_id, work_kind="campaign")
        result = self._automatic_campaign_setup(result)
        result.pop("campaign_name", None)
        # An editable draft must retain its configured locators. Report-only
        # identities cannot be reopened as files. The builder allowlist excludes
        # credentials, and launched jobs still use their separate durable,
        # path-free snapshots and normal source/revision validation.
        self.db.save_workspace_definition(campaign_id, result)
        return result

    @staticmethod
    def _work_view_tabs(context: str, selected: str) -> str:
        views = [("campaigns", "Campaigns"), ("standalone", "Standalone runs")]
        if context == "jobs":
            views.append(("all", "All jobs and tools"))
        else:
            views.append(("legacy", "Earlier reports"))
        return "<nav class='page-tablist server-tablist' aria-label='" + context.title() + " scope'>" + "".join(
            "<a class='page-tab' href='/" + context + "?view=" + value + "'"
            + (" aria-current='page'" if value == selected else "") + ">" + label + "</a>"
            for value, label in views
        ) + "</nav>"

    def _build_work_choice(self, params: dict[str, str]) -> str:
        selected = params.get("campaign_id", "")
        campaign_mode = params.get("work_kind", "campaign" if selected else "run") == "campaign"
        rows = self.db.workspaces()
        if rows is None:
            return "<p class='notice red'>Campaign index unavailable.</p>"
        options = "<option value=''>New campaign</option>" + "".join(
            "<option value='" + r["campaign_id"] + "'" + (" selected" if selected == r["campaign_id"] else "")
            + ">" + html.escape(r["name"]) + "</option>" for r in rows
        )
        return (
            "<section class='card build-purpose'><h2>What are you building?</h2>"
            "<div class='work-kind-choices'>" + "".join(
                "<label class='work-kind-choice'><input type='radio' name='work_kind' form='builder' value='"
                + value + "'" + (" checked" if enabled else "") + "><span><strong>" + label
                + "</strong><span>" + description + "</span></span></label>"
                for value, label, description, enabled in (
                    ("campaign", "Campaign", "Coordinate arms, corpora and frameworks across a set of models.", campaign_mode),
                    ("run", "Single run", "Execute one independent job with the selected pipeline.", not campaign_mode),
                )
            ) + "</div><div id='build-campaign-fields' class='campaign-ownership-row'>"
            "<label class='campaign-field'>Campaign <select name='campaign_id' form='builder'>" + options + "</select></label>"
            "<label class='campaign-field' id='build-campaign-name'>New campaign name "
            "<input name='campaign_name' form='builder' maxlength='120' value='"
            + html.escape(params.get("campaign_name", ""), quote=True) + "'></label>"
            + ("<a class='button ghost' href='/campaigns/" + selected + "'>Open campaign</a>" if selected else "")
            + "<label class='campaign-guide-option'><input type='checkbox' form='builder' name='campaign_guide'"
            + (" checked" if params.get('campaign_guide') == 'on' else '')
            + "><span><strong>Guide me through this campaign</strong>"
            "<small>Optional step-by-step help with choices, explanations and links. No jobs start automatically.</small></span></label>"
            + "</div><p class='note'>Choose models once below. Local, API or mixed follows from your model selection. "
            "Campaign drafts do not change jobs that are already running.</p></section>"
            + self._campaign_guide(selected, params=params, builder=True)
        )

    def _standalone_results_page(self, query: dict[str, str]) -> bytes:
        page = max(0, int(query.get("page", "0")))
        rows = self.db.standalone_runs(offset=page * 50)
        if rows is None:
            content = "<p class='notice red'>Run result index unavailable.</p>"
        elif not rows:
            content = "<p>No indexed standalone runs on this page.</p>"
        else:
            content = "<div class='scroll'><table><tr><th>Run</th><th>Command</th><th>Status</th><th>Results</th></tr>" + "".join(
                "<tr><td><a href='/jobs/" + quote(row['job_id'], safe='') + "'>" + html.escape(row['job_id']) + "</a></td>"
                "<td>" + html.escape(row['command'] or '') + "</td><td>" + html.escape(row['state'] or 'unknown')
                + "</td><td><a href='/stats/job/" + quote(row['job_id'], safe='') + "'>Results and diagrams</a></td></tr>"
                for row in rows[:50]
            ) + "</table></div>"
            if page:
                content += f"<a href='/stats?view=standalone&amp;page={page - 1}'>Previous</a> "
            if len(rows) > 50:
                content += f"<a href='/stats?view=standalone&amp;page={page + 1}'>Next</a>"
        return _page("Standalone run statistics", "<h1>Stats</h1>"
            + self._work_view_tabs("stats", "standalone")
            + "<section class='card'><h2>Standalone runs</h2><p>Independent executions, excluding campaign-owned runs. "
            "Unindexed external reports remain available under Earlier reports.</p>" + content + "</section>", active="Stats")

    def _workspace_export(self, campaign_id: str, name: str, query: dict[str, str]) -> tuple[int, str, bytes]:
        self.db.require_workspace(campaign_id)
        page = max(0, int(query.get("page", "0")))
        if name == 'costs.csv':
            from .workspace_costs import cost_totals_csv
            rows=self.db.workspace_cost_totals(campaign_id,all_rows=True)
            if rows is None:return 503,'text/plain; charset=utf-8',b'Campaign cost index unavailable'
            if not rows:return 404,'text/plain; charset=utf-8',b'No indexed campaign costs'
            return 200,'text/csv; charset=utf-8',cost_totals_csv(rows,campaign_id)
        if name == "comparison.csv":
            from .workspace_comparison import comparison_rows, comparison_groups, comparison_csv
            from . import workspace_comparison_many as many
            query = many.normalize(query)
            if many.broad(query):
                data = many.page_data(self.db,campaign_id,query,page=page)
                rows = None if data is None else many.export_rows(data)
            else:
                rows = comparison_rows(self.db, campaign_id, query, offset=page * 12)
                if rows is not None:
                    rows = [row for group in comparison_groups(rows)[:12] for row in group]
            if rows is None:
                return 503, "text/plain; charset=utf-8", b"Campaign comparison index unavailable"
            if not rows:
                return 404, "text/plain; charset=utf-8", b"No measured comparison inputs on this page"
            return 200, "text/csv; charset=utf-8", comparison_csv(rows, campaign_id, query)
        model, condition = self._workspace_result_scope(query)
        if name in {"judgments.csv", "judgments.svg"}:
            rows = self.db.workspace_judgment_breakdown(campaign_id, offset=page * 12, model=model, condition=condition,
                judge=query.get('judge',''))
            if rows is None:
                return 503, "text/plain; charset=utf-8", b"Campaign judgment index unavailable"
            rows = [row for group in judgment_groups(rows)[:12] for row in group]
            if not rows:
                return 404, "text/plain; charset=utf-8", b"No indexed judgments for this page"
            if name == "judgments.csv":
                return 200, "text/csv; charset=utf-8", judgment_counts_csv(rows)
            figure = judgment_breakdown_svg(rows, scope=f"Page {page + 1}. Retained assessment counts, not pooled security rates.",
                settings=indexed_settings(self.db,campaign_id))
            from .ui import _STYLE  # noqa: PLC0415
            figure = figure.replace("<style>", "<style>" + _STYLE.split("* { box-sizing:", 1)[0], 1)
            return 200, "image/svg+xml; charset=utf-8", figure.encode("utf-8")
        rows = self.db.workspace_model_totals(campaign_id, offset=page * 25, model=model, condition=condition)
        if rows is None:
            return 503, "text/plain; charset=utf-8", b"Campaign result index unavailable"
        rows = rows[:25]
        if not rows:
            return 404, "text/plain; charset=utf-8", b"No indexed results for this page"
        if name == "model-counts.csv":
            return 200, "text/csv; charset=utf-8", model_counts_csv(rows, condition=condition)
        if name not in {"coverage.svg", "quality.svg"}:
            return 404, "text/plain; charset=utf-8", b"Unknown figure"
        scope = ("Selected execution condition" if condition else "All retained conditions, including history")
        scope += f", page {page + 1}. Operational coverage; not pooled security rates."
        figure = (coverage_svg(rows, title="Campaign outcome composition", scope=scope)
                  if name == "coverage.svg" else quality_svg(rows, scope=scope))
        # Preserve the project's light/dark theme variables in the standalone
        # vector. No remote library, script, image or external stylesheet.
        from .ui import _STYLE  # noqa: PLC0415
        theme = _STYLE.split("* { box-sizing:", 1)[0]
        figure = figure.replace("<style>", "<style>" + theme, 1)
        figure = figure.replace("<style>", "<metadata>" + html.escape(json.dumps(
            dict(model_filter=model, condition_filter=condition))) + "</metadata><style>", 1)
        return 200, "image/svg+xml; charset=utf-8", figure.encode("utf-8")

    def _workspace_source_link(self, reference: str) -> str:
        path, separator, row = reference.rpartition(":")
        locator = path if separator and row.isdigit() else reference
        candidate = Path(locator)
        if not candidate.is_absolute():
            candidate = self.results_root / candidate
        fallback = False
        if not candidate.exists():
            for before, after in ((".responses.jsonl", ".responses.checkpoint.jsonl"),
                                  (".responses.checkpoint.jsonl", ".responses.jsonl")):
                if candidate.name.endswith(before):
                    alternate = candidate.with_name(candidate.name.removesuffix(before) + after)
                    if alternate.is_file():
                        candidate, fallback = alternate, True
                    break
        try:
            relative = candidate.resolve().relative_to(self.results_root.resolve()).as_posix()
        except (OSError, ValueError, RuntimeError):
            return html.escape(reference)
        label = "Open retained artifact"
        if fallback:
            label += " (alternate export; row position may differ)"
        elif separator and row.isdigit():
            label += f" (row {row})"
        return "<a href='/artifacts?path=" + quote(relative, safe="") + "'>" + label + "</a>"

    def _campaign_selector(self, selected: str = "", *, form_id: str = "") -> str:
        if selected:
            self.db.require_workspace(selected)
        rows = self.db.workspaces()
        if rows is None:
            return "<p class='notice red'>Campaign index unavailable. No ownership was inferred.</p>"
        options = "<option value=''>No campaign - standalone job</option>" + "".join(
            "<option value='" + row["campaign_id"] + "'"
            + (" selected" if row["campaign_id"] == selected else "")
            + ">" + html.escape(row["name"]) + "</option>"
            for row in rows
        )
        association = f" form='{html.escape(form_id)}'" if form_id else ""
        return (
            "<div class='campaign-ownership'><div class='campaign-ownership-row'>"
            "<label class='campaign-field'>Save under campaign <select name='campaign_id'" + association + ">"
            + options + "</select></label>"
            "<a class='button ghost' href='/campaigns/new'>Create campaign</a></div>"
            "<p class='note'>Groups this job and its results. Choose models in Build. "
            "Changing this selection does not move running jobs.</p></div>"
        )

    def _campaign_banner(self, campaign_id: str) -> str:
        if not campaign_id:
            return "<p class='note'>Standalone work (no campaign).</p>"
        self.db.require_workspace(campaign_id)
        campaign = self.db.workspace(campaign_id)
        return (
            "<p>Campaign: <a href='/campaigns/" + campaign_id + "'>"
            + html.escape(campaign["name"]) + "</a></p>"
            + self._campaign_guide(campaign_id)
        )

    def _campaign_guide(self, campaign_id: str, *, params=None, builder=False) -> str:
        from .campaign_guide import render
        definition = params if params is not None else self.db.workspace_definition(campaign_id)
        return render(self, dict(definition, campaign_id=campaign_id), builder=builder)

    def _workspaces_page(self, *, context: str = "campaigns") -> bytes:
        rows = self.db.workspaces()
        cards = "<p class='notice red'>Campaign index unavailable.</p>" if rows is None else "".join(
            "<article class='card campaign-card'><h2><a href='/campaigns/" + row["campaign_id"] + "'>"
            + html.escape(row["name"]) + "</a></h2>"
            "<div class='campaign-actions'><a class='button' href='/build?campaign_id=" + row["campaign_id"]
            + "'>Edit in Build</a><a class='button ghost' href='/jobs?campaign_id=" + row["campaign_id"]
            + "'>Jobs</a><a class='button ghost' href='/campaigns/" + row["campaign_id"]
            + "?section=overview'>Stats</a></div></article>" for row in rows
        )
        if rows == []:
            cards = "<p>No campaigns created yet. Existing standalone jobs are unchanged.</p>"
        return _page(
            context.title(), "<h1>" + context.title() + "</h1>"
            + (self._work_view_tabs(context, "campaigns") if context in {"jobs", "stats"} else "")
            + "<p>Campaigns evaluate arms, corpora and frameworks across model sets. Define them in Build.</p>"
            "<p class='action-row'><a class='button' href='/build?work_kind=campaign#build-general'>Build a campaign</a> "
            "<a class='button ghost' href='/build?work_kind=run#build-general'>Build a single run</a></p>"
            + "<div class='campaign-grid'>" + cards + "</div>", active=context.title(),
        )

    def _workspace_page(self, campaign_id: str, query: dict[str, str]) -> bytes:
        self.db.require_workspace(campaign_id)
        campaign = self.db.workspace(campaign_id)
        section = query.get("section", "overview")
        sections = ("overview", "definition", "results", "judging", "compare", "costs", "activity")
        if section not in sections:
            raise ValueError("Unknown campaign section")
        base = "/campaigns/" + campaign_id
        model, condition = self._workspace_result_scope(query)
        scope_query = ("&amp;model=" + quote(model, safe="") if model else "") + (
            "&amp;condition=" + quote(condition, safe="") if condition else "")
        navigation = "<nav class='page-tablist server-tablist' aria-label='Campaign sections'>" + "".join(
            "<a class='page-tab' href='" + base + "?section=" + tab
            + (scope_query if tab in {"overview", "results", "judging"} else "") + "'"
            + (" aria-current='page'" if tab == section else "") + ">"
            + tab.title() + "</a>" for tab in sections
        ) + "<a class='page-tab' href='/human-evaluation?campaign_id=" + campaign_id + "'>Human evaluation</a>" \
            + "<a class='page-tab' href='/analysis?campaign_id=" + campaign_id + "'>SVM analysis</a></nav>"
        if section == "definition":
            definition = self.db.workspace_definition(campaign_id)
            content = "<p>No Build definition has been saved for this retained campaign. Its existing jobs are unchanged.</p>"
            if definition:
                content = "<p>Saved configuration for future runs. Each launched job retains its own reviewed settings.</p><dl class='builder-summary'>" + "".join(
                    "<div><dt>" + label + "</dt><dd>" + html.escape(definition.get(key) or "Not set") + "</dd></div>"
                    for key, label in (("local", "Local models"), ("api", "API models"), ("corpora", "Arms / corpora"),
                        ("attackers", "Frameworks / attacks"), ("seeds", "Seeds"), ("sampling_policy", "Sampling"),
                        ("limit", "Per-arm limit"), ("judges", "Judges"), ("judge_model", "Judge model"), ("out", "Output"))
                ) + "</dl>"
        elif section == "compare":
            from .workspace_comparison import comparison_page
            content = comparison_page(self.db, campaign_id, query)
        elif section == "activity":
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
        if section in {"overview", "results", "judging"}:
            content = self._workspace_result_filters(campaign_id, section, query) + content
        return _page(
            campaign["name"], "<h1>" + html.escape(campaign["name"]) + "</h1>"
            "<p class='action-row'><a class='button' href='/build?campaign_id=" + campaign_id + "'>Configure in Build</a> "
            "<a class='button ghost' href='/jobs?campaign_id=" + campaign_id + "'>Campaign jobs</a> "
            "<a class='button ghost' href='/commands?campaign_id=" + campaign_id + "'>Run tools</a></p>"
            + self._campaign_guide(campaign_id)
            + navigation + (self._operation_links(campaign_id) if section in {'overview', 'activity'} else '')
            + "<section class='card'><h2>" + section.title() + "</h2>" + content + "</section>",
            active="Campaigns" if section in {"definition", "activity"} else "Stats",
        )

    def _workspace_results(self, campaign_id: str, section: str, query: dict[str, str]) -> str:
        unknown = (
            "<p class='notice amber'>Retained " + html.escape(section)
            + " data has not been indexed for this campaign yet. Totals are unknown, not zero.</p>"
            "<p>Build launches are associated automatically. Original jobs and reports remain accessible in Activity.</p>"
        )
        page = max(0, int(query.get("page", "0")))
        base = "/campaigns/" + campaign_id + "?section=" + section
        model, condition = self._workspace_result_scope(query)
        scope_query = ("&amp;model=" + quote(model, safe="") if model else "") + (
            "&amp;condition=" + quote(condition, safe="") if condition else "")
        base += scope_query
        if model or condition:
            unknown = ("<p class='notice amber'>No indexed " + html.escape(section)
                       + " rows for this selection. Missing data are unknown, not zero.</p>")

        def pagination(has_next):
            return ((f"<a href='{base}&amp;page={page - 1}'>Previous</a> " if page else "")
                    + (f"<a href='{base}&amp;page={page + 1}'>Next</a>" if has_next else ""))

        def table(headers, rows):
            return "<div class='scroll'><table><tr>" + "".join("<th>" + h + "</th>" for h in headers) + "</tr>" + "".join(
                "<tr>" + "".join("<td>" + cell + "</td>" for cell in row) + "</tr>" for row in rows
            ) + "</table></div>"

        if section == "costs":
            rows = self.db.workspace_cost_totals(campaign_id, offset=page * 25)
            if not rows:
                return unknown

            def amount(value):
                return "unknown" if value is None else f"${value / 1_000_000:,.6f}"

            def tokens(row, name):
                total = row[name + "_tokens"]
                missing = row[name + "_unknown"]
                return ("unknown" if total is None else f"{total:,}") + (f"; {missing:,} attempt(s) unknown" if missing else "")

            return (
                "<p>Indexed physical attempts counted once, including retries and historical outcomes. "
                "Unindexed charges remain unknown. "
                "Judging costs belong to the campaign whose output was judged. "
                "Recorded costs are not account balances; uncertain exposure is not a money hold. "
                "Local work has no API charge; electricity and hardware costs are not estimated.</p>"
                + "<p class='action-row' id='campaign-exports'><a class='button ghost' data-campaign-export download='campaign-costs.csv' href='/campaigns/"+campaign_id+"/figures/costs.csv'>Download full campaign cost table</a></p><p id='campaign-export-status' role='status'></p>"+EXPORT_SCRIPT
                + "<div class='campaign-costs'>" + table(("Provider / model", "Role", "HTTP attempts / local evaluations", "Recorded cost (USD)",
                         "Uncertain charge exposure (USD)", "Reported tokens: input / output / reasoning"),
                    [[html.escape(row["provider"] + " / " + row["model"]), html.escape(row["role"]),
                      f"{row['http_attempts']:,} / {row['local_evaluations']:,}",
                      ("No API charge" if row["provider"] == "local" else amount(row["cost_microusd"]))
                      + f"<br>{row['settled_attempts']:,} settled; {row['unknown_attempts']:,} unknown; {row['unsettled_attempts']:,} in flight",
                      amount(row["exposure_microusd"]) + (f"; {row['unknown_exposure_count']:,} without a bound" if row["unknown_exposure_count"] else ""),
                      " / ".join(tokens(row, name) for name in ("input", "output", "reasoning"))]
                     for row in rows[:25]]) + "</div>"
                + pagination(len(rows) > 25)
            )
        if section == "judging":
            settings = indexed_settings(self.db,campaign_id)
            review_coverage = review_coverage_html(self.db,campaign_id,settings,model=model,condition=condition)
            judge=query.get('judge','')
            rows = self.db.workspace_judging_totals(campaign_id, model=model, condition=condition)
            if rows and judge:
                rows=[row for row in rows if row['judge_id']==judge]
            if not rows:
                return review_coverage + unknown
            if judge:
                all_link='/campaigns/'+campaign_id+'?section=judging'+scope_query
                review_coverage += '<p>Showing only '+html.escape(judge_name(judge,settings.get(judge)))+". <a href='"+all_link+"'>Show all evaluators</a>.</p>"
                scope_query += '&amp;judge='+quote(judge,safe='')
                base += '&amp;judge='+quote(judge,safe='')
            breakdown = self.db.workspace_judgment_breakdown(campaign_id, offset=page * 12, model=model, condition=condition,judge=judge)
            if breakdown is None:
                return "<p class='notice amber'>Judgment label index unavailable.</p>"
            groups = judgment_groups(breakdown)
            selected = [row for group in groups[:12] for row in group]
            exports = "<p class='action-row' id='campaign-exports'>" + " ".join(
                "<a class='button ghost' data-campaign-export download='campaign-" + name + "' href='/campaigns/" + campaign_id
                + "/figures/" + name + "?page=" + str(page) + scope_query + "'>" + label + "</a>"
                for name, label in (("judgments.svg", "Export judgment figure"), ("judgments.csv", "Export judgment table"))
            ) + "</p><p id='campaign-export-status' role='status'></p>" + EXPORT_SCRIPT
            return ("<p>Labels for the selected outputs, separated by model, source, framework, modality and generation/judging condition. "
                "Each bar counts retained assessments, including invalid verdicts and missing-output assessments. "
                "Pending judgments are not part of these bars. These are label distributions, not pooled security rates.</p>"
                "<p>For source-classification corpora, task labels describe the classified material, not the answering model's safety. "
                "Task correctness and answer-format validity are separate from common refusal and harmful-compliance measures.</p>"
                "<p class='note'>Measured conditions are listed first. Diagnostics remain separate and accessible on later pages.</p>"
                + review_coverage + exports + judgment_breakdown_html(selected,settings=settings) + pagination(len(groups) > 12)
                + "<details><summary>All indexed judging totals for this selection</summary>" + table(
                ("Judge condition", "Status", "Verdicts"),
                [[html.escape(judge_name(row['judge_id'],settings.get(row['judge_id']))), html.escape(row["status"]), str(row["count"])] for row in rows],
            ) + "</details>")
        if section == "overview":
            inputs = self.db.workspace_input_totals(campaign_id, offset=page * 25, model=model, condition=condition)
            input_coverage = ""
            if inputs:
                input_coverage = (
                    "<h3>Native collection input coverage</h3>"
                    "<p>Source rows in the indexed local run plans. Reached means at least one durable "
                    "response record, including missing output. It does not mean every seed, adaptive turn "
                    "or judgment is complete. The same source row in separate runs is counted separately. "
                    "Older runs without an indexed input plan are not represented here.</p>"
                    + table(("Model", "Evidence", "Runs", "Source rows planned", "Reached", "Not reached"),
                        [[html.escape(row["model"]), html.escape(row["evidence_class"]), str(row["runs"]),
                          str(row["planned"]), str(row["reached"]), str(row["planned"] - row["reached"])]
                         for row in inputs[:25]])
                    + pagination(len(inputs) > 25)
                )
            elif inputs is None:
                input_coverage = "<p class='notice amber'>Native input-plan index unavailable.</p>"
            rows = self.db.workspace_model_totals(campaign_id, offset=page * 25, model=model, condition=condition)
            if not rows:
                return input_coverage + unknown
            chart = coverage_html(rows[:25])
            exports = "<p class='action-row' id='campaign-exports'>" + " ".join(
                "<a class='button ghost' data-campaign-export download='campaign-" + name + "' href='/campaigns/" + campaign_id
                + "/figures/" + name + "?page=" + str(page) + scope_query + "'>" + label + "</a>"
                for name, label in (("coverage.svg", "Export coverage figure"), ("quality.svg", "Export missing/truncation figure"),
                                    ("model-counts.csv", "Export matching table"))
            ) + "</p><p id='campaign-export-status' role='status'></p>" + EXPORT_SCRIPT
            return (
                "<p>Explicitly indexed assignments, not sums of overlapping job reports. "
                "Pending means no selected retained outcome; it does not establish that no HTTP attempt occurred. "
                "Truncation overlaps usable/missing outcomes and is not an additional outcome bucket. "
                "Execution conditions remain distinct; these counts are not pooled safety rates.</p>"
                + input_coverage + exports + chart + "<details><summary>Exact counts and execution-condition coverage</summary>" + table(
                    ("Model", "Evidence", "Conditions", "Assigned", "Usable", "Policy", "Missing", "Retry pending", "Pending", "Truncated", "Truncation unknown"),
                    [["<a href='/campaigns/" + campaign_id + "?section=results&amp;model=" + quote(row["model"], safe="")
                      + ("&amp;condition=" + quote(condition, safe="") if condition else "") + "'>" + html.escape(row["model"]) + "</a>"]
                     + [html.escape(row["evidence_class"])]
                     + [str(row[key] or 0) for key in ("conditions", "assigned", "usable", "policy", "missing", "retry_pending", "pending", "truncated", "truncation_unknown")]
                     for row in rows[:25]],
                ) + "</details>" + pagination(len(rows) > 25)
            )
        rows = self.db.workspace_result_rows(campaign_id, offset=page * 50, model=model, condition=condition)
        if not rows:
            return unknown
        recoveries=self.db.workspace_recovery_rows(campaign_id,model=model,condition=condition,offset=page*50)
        recovery_html=''
        if recoveries:
            recovery_rows=[]
            for link in recoveries[:50]:
                old=json.loads(link['old_details']);new=json.loads(link['new_details'])
                recovery_rows.append([html.escape(link['model'].partition(';')[0]),
                    html.escape(link['corpus']+' / '+link['modality']),
                    html.escape(link['old_outcome'])+' - '+self._workspace_source_link(old['source_ref']),
                    html.escape(link['new_outcome'])+' - '+self._workspace_source_link(new['source_ref']),
                    html.escape(link['reason'])+' '+self._workspace_source_link(link['evidence_ref'])])
            recovery_html="<section><h2>Recovery history</h2><p>Explicit links connect original outcomes to saved recovery answers for the same model and input. Both executions remain in the historical counts and costs. Each answer keeps its own judgments; a link does not select the best answer or transfer a verdict.</p>"+table(('Model','Corpus / modality','Original outcome','Recovery outcome','Reason / evidence'),recovery_rows)+"</section>"
        output = []
        for row in rows[:50]:
            details = json.loads(row["details"]) if row["details"] else {}
            def value(key):
                item = details.get(key)
                if key == "output_allowance" and item == -1:
                    return "Native maximum (no fixed output cap)"
                return "unknown" if item is None else html.escape(str(item))
            metadata = "<details><summary>Generation settings and usage</summary><dl>" + "".join(
                "<dt>" + label + "</dt><dd>" + value(key) + "</dd>" for key, label in (
                    ("context_tokens", "Effective context"), ("output_allowance", "Output allowance"),
                    ("input_tokens", "Reported input tokens"), ("output_tokens", "Reported output tokens"),
                    ("reasoning_tokens", "Reported reasoning tokens"), ("finish_reason", "Finish reason"),
                    ("missing_category", "Missing-output category"))) + "</dl>"
            metadata += "<p>Exact model: " + html.escape(row["model"]) + "</p>"
            metadata += "<p>Input identity: " + html.escape(row["input_id"]) + "</p>"
            metadata += "<p>Condition: " + html.escape(row["response_condition"] or row["condition_id"]) + "</p>"
            metadata += "<p>Source: " + (self._workspace_source_link(details["source_ref"]) if details.get("source_ref") else "unknown") + "</p></details>"
            input_label = row["input_id"] if len(row["input_id"]) <= 16 else row["input_id"][:12] + "..."
            model_label = row["model"].partition(";")[0].partition("@sha256:")[0]
            output.append([html.escape(model_label),
                           "<span title='" + html.escape(row["input_id"], quote=True) + "'>" + html.escape(input_label) + "</span>",
                           html.escape(row["evidence_class"]), html.escape(row["modality"]), html.escape(row["framework"] + " / " + row["corpus"]),
                           html.escape(row["outcome"] or "pending"),
                           "unknown" if row["truncated"] is None else "yes" if row["truncated"] else "no", metadata])
        return recovery_html+"<div class='campaign-output-table'>" + table(("Model", "Input", "Evidence", "Modality", "Framework / corpus", "Outcome", "Truncated", "Details"), output) + "</div>" + pagination(len(rows) > 50 or len(recoveries or [])>50)
