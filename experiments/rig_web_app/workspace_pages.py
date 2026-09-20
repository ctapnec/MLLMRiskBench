"""Campaign navigation. Configuration and execution remain in Build/Run."""

from __future__ import annotations

from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import html
import json
from pathlib import Path
from urllib.parse import quote

from .ui import _page
from .workspace_charts import (
    coverage_html,
    coverage_svg,
    quality_svg,
    model_counts_csv,
    EXPORT_SCRIPT,
)
from .workspace_judging_charts import (
    judgment_groups,
    judgment_breakdown_html,
    judgment_counts_csv,
    judgment_breakdown_svg,
)
from .workspace_judge_settings import indexed_settings, judge_name
from .workspace_review_coverage import review_coverage_html


class WorkspacePagesMixin:
    @staticmethod
    def _workspace_result_scope(query: dict[str, str]) -> tuple[str, str]:
        model, condition = query.get("model", ""), query.get("condition", "")
        if condition and not model:
            raise ValueError(
                _ui_text("workspace_pages.choose_a_model_before_selecting_its_execution_condition")
            )
        return model, condition

    def _workspace_result_filters(
        self, campaign_id: str, section: str, query: dict[str, str]
    ) -> str:
        model, condition = self._workspace_result_scope(query)
        models = self.db.workspace_result_models(campaign_id)
        if not models:
            return ""
        action = "/campaigns/" + campaign_id
        retained_judge = (
            "<input type='hidden' name='judge' value='"
            + html.escape(query["judge"], quote=True)
            + "'>"
            if section == "judging" and query.get("judge")
            else ""
        )
        options = _ui_template(
            "<option value=''>[[text:workspace_pages.all_models]]</option>"
        ) + "".join(
            "<option value='"
            + html.escape(row["model"], quote=True)
            + "'"
            + (" selected" if row["model"] == model else "")
            + ">"
            + html.escape(row["model"])
            + "</option>"
            for row in models
        )
        if model and not any(row["model"] == model for row in models):
            options += (
                "<option selected value='"
                + html.escape(model, quote=True)
                + _ui_template("'>[[text:workspace_pages.unknown_model]]</option>")
            )
        content = (
            "<div class='campaign-result-filters'><form method='get' action='" + action + "'>"
            "<input type='hidden' name='section' value='"
            + section
            + "'>"
            + retained_judge
            + _ui_template(
                "<label class='campaign-field'>[[text:workspace_pages.model]]<select name='model'>"
            )
            + options
            + _ui_template(
                "</select></label><button type='submit'>[[text:workspace_pages.choose_model]]</button></form>"
            )
        )
        if model:
            conditions = self.db.workspace_result_conditions(campaign_id, model=model)
            if conditions is None:
                return content + _ui_template(
                    "<p class='notice red'>[[text:workspace_pages.execution_condition_index_unavailable]]</p></div>"
                )

            def allowance(row, prefix):
                low, high = row[prefix + "_min"], row[prefix + "_max"]

                def tokens(value):
                    return (
                        _ui_text("workspace_pages.native_maximum") if value == -1 else f"{value:,}"
                    )

                value = (
                    _ui_text("workspace_pages.unknown_status")
                    if low is None
                    else tokens(low)
                    if low == high
                    else tokens(low) + _ui_text("workspace_pages.to") + tokens(high)
                )
                if 0 < row[prefix + "_known"] < row["assigned"]:
                    value += _ui_text("workspace_pages.partly_unknown")
                return value

            options = _ui_template(
                "<option value=''>[[text:workspace_pages.all_retained_conditions_includes_history]]</option>"
            )
            for index, row in enumerate(conditions, 1):
                label = (
                    _ui_text("workspace_pages.condition")
                    + f"{index}"
                    + _ui_text("workspace_pages.context")
                    + f"{allowance(row, 'context')}"
                    + _ui_text("workspace_pages.output_copy")
                    + f"{allowance(row, 'output')}"
                    + "; "
                    + f"{row['assigned']:,}"
                    + _ui_text("workspace_pages.assignments")
                )
                options += (
                    "<option value='"
                    + html.escape(row["condition_id"], quote=True)
                    + "'"
                    + (" selected" if row["condition_id"] == condition else "")
                    + ">"
                    + html.escape(label)
                    + "</option>"
                )
            if condition and not any(row["condition_id"] == condition for row in conditions):
                options += (
                    "<option selected value='"
                    + html.escape(condition, quote=True)
                    + _ui_template(
                        "'>[[text:workspace_pages.unknown_execution_condition]]</option>"
                    )
                )
            content += (
                "<form method='get' action='"
                + action
                + "'><input type='hidden' name='section' value='"
                + section
                + "'>"
                + retained_judge
                + "<input type='hidden' name='model' value='"
                + html.escape(model, quote=True)
                + _ui_template(
                    "'><label class='campaign-field'>[[text:workspace_pages.execution_condition]]<select name='condition'>"
                )
                + options
                + _ui_template(
                    "</select></label><button type='submit'>[[text:workspace_pages.view_condition]]</button></form>"
                )
            )
        else:
            content += _ui_template(
                "<p class='note'>[[text:workspace_pages.choose_a_model_to_inspect_its_individual_execution_conditions]]</p>"
            )
        return content + (
            _ui_template(
                "</div><p class='note'>[[text:workspace_pages.all_conditions_includes_historical_failures_and_later_corrections]]</p>"
            )
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
        views = [
            ("campaigns", _ui_text("workspace_pages.campaigns")),
            ("standalone", _ui_text("workspace_pages.standalone_runs")),
        ]
        if context == "jobs":
            views.insert(0, ("work", _ui_text("workspace_pages.substantive_work")))
            views.append(("all", _ui_text("workspace_pages.technical_all_jobs")))
        else:
            views.append(("compare", _ui_text("workspace_pages.compare_campaigns")))
            views.append(("svm", _ui_text("workspace_pages.svm_results")))
            views.append(("legacy", _ui_text("workspace_pages.earlier_reports")))
        return (
            "<nav class='page-tablist server-tablist' aria-label='"
            + html.escape(
                _ui_text("workspace_pages.jobs_scope")
                if context == "jobs"
                else _ui_text("workspace_pages.stats_scope"),
                quote=True,
            )
            + "'>"
            + "".join(
                "<a class='page-tab' href='/"
                + context
                + "?view="
                + value
                + "'"
                + (" aria-current='page'" if value == selected else "")
                + ">"
                + label
                + "</a>"
                for value, label in views
            )
            + "</nav>"
        )

    def _build_work_choice(self, params: dict[str, str]) -> str:
        selected = params.get("campaign_id", "")
        campaign_mode = params.get("work_kind", "campaign" if selected else "run") == "campaign"
        rows = self.db.workspaces()
        if rows is None:
            return _ui_template(
                "<p class='notice red'>[[text:workspace_pages.campaign_index_unavailable]]</p>"
            )
        options = _ui_template(
            "<option value=''>[[text:workspace_pages.new_campaign]]</option>"
        ) + "".join(
            "<option value='"
            + r["campaign_id"]
            + "'"
            + (" selected" if selected == r["campaign_id"] else "")
            + ">"
            + html.escape(r["name"])
            + "</option>"
            for r in rows
        )
        return (
            _ui_template(
                "<section class='card build-purpose'><h2>[[text:workspace_pages.what_are_you_building]]</h2><div class='work-kind-choices'>"
            )
            + "".join(
                "<label class='work-kind-choice'><input type='radio' name='work_kind' form='builder' value='"
                + value
                + "'"
                + (" checked" if enabled else "")
                + "><span><strong>"
                + label
                + "</strong><span>"
                + description
                + "</span></span></label>"
                for value, label, description, enabled in (
                    (
                        "campaign",
                        _ui_text("workspace_pages.campaign"),
                        _ui_text(
                            "workspace_pages.coordinate_arms_corpora_and_frameworks_across_a_set_of_models"
                        ),
                        campaign_mode,
                    ),
                    (
                        "run",
                        _ui_text("workspace_pages.single_run"),
                        _ui_text(
                            "workspace_pages.execute_one_independent_job_with_the_selected_pipeline"
                        ),
                        not campaign_mode,
                    ),
                )
            )
            + _ui_template(
                "</div><div id='build-campaign-fields' class='campaign-ownership-row'><label class='campaign-field'>[[text:workspace_pages.campaign]] <select name='campaign_id' form='builder'>"
            )
            + options
            + _ui_template(
                "</select></label><label class='campaign-field' id='build-campaign-name'>[[text:workspace_pages.new_campaign_name]] <input name='campaign_name' form='builder' maxlength='120' value='"
            )
            + html.escape(params.get("campaign_name", ""), quote=True)
            + "'></label>"
            + (
                "<a class='button ghost' href='/campaigns/"
                + selected
                + _ui_template("'>[[text:workspace_pages.open_campaign]]</a>")
                if selected
                else ""
            )
            + "<label class='campaign-guide-option'><input type='checkbox' form='builder' name='campaign_guide'"
            + (" checked" if params.get("campaign_guide") == "on" else "")
            + _ui_template(
                "><span><strong>[[text:workspace_pages.guide_me_through_this_campaign]]</strong><small>[[text:workspace_pages.optional_step_by_step_help_with_choices_explanations_and_links_no]]</small></span></label>"
            )
            + _ui_template(
                "</div><p class='note'>[[text:workspace_pages.choose_models_once_below_local_api_or_mixed_follows_from_your_mod]]</p></section>"
            )
            + self._campaign_guide(selected, params=params, builder=True)
        )

    def _standalone_results_page(self, query: dict[str, str]) -> bytes:
        page = max(0, int(query.get("page", "0")))
        rows = self.db.standalone_runs(offset=page * 50)
        if rows is None:
            content = _ui_template(
                "<p class='notice red'>[[text:workspace_pages.run_result_index_unavailable]]</p>"
            )
        elif not rows:
            content = _ui_template(
                "<p>[[text:workspace_pages.no_indexed_standalone_runs_on_this_page]]</p>"
            )
        else:
            content = (
                _ui_template(
                    "<div class='scroll'><table><tr><th>[[text:workspace_pages.run]]</th><th>[[text:workspace_pages.command]]</th><th>[[text:workspace_pages.status]]</th><th>[[text:workspace_pages.results]]</th></tr>"
                )
                + "".join(
                    "<tr><td><a href='/jobs/"
                    + quote(row["job_id"], safe="")
                    + "'>"
                    + html.escape(row["job_id"])
                    + "</a></td>"
                    "<td>"
                    + html.escape(row["command"] or "")
                    + "</td><td>"
                    + html.escape(_ui_label(row["state"] or "unknown"))
                    + "</td><td><a href='/stats/job/"
                    + quote(row["job_id"], safe="")
                    + _ui_template("'>[[text:workspace_pages.results_and_diagrams]]</a></td></tr>")
                    for row in rows[:50]
                )
                + "</table></div>"
            )
            if page:
                content += (
                    "<a href='/stats?view=standalone&amp;page="
                    + f"{page - 1}"
                    + _ui_template("'>[[text:workspace_pages.previous]]</a> ")
                )
            if len(rows) > 50:
                content += (
                    "<a href='/stats?view=standalone&amp;page="
                    + f"{page + 1}"
                    + _ui_template("'>[[text:workspace_pages.next]]</a>")
                )
        return _page(
            _ui_text("workspace_pages.standalone_run_statistics"),
            _ui_template("<h1>[[text:workspace_pages.stats]]</h1>")
            + self._work_view_tabs("stats", "standalone")
            + _ui_template(
                "<section class='card'><h2>[[text:workspace_pages.standalone_runs]]</h2><p>[[text:workspace_pages.independent_executions_excluding_campaign_owned_runs_unindexed_ex]]</p>"
            )
            + content
            + "</section>",
            active=_ui_text("workspace_pages.stats"),
        )

    def _workspace_export(
        self, campaign_id: str, name: str, query: dict[str, str]
    ) -> tuple[int, str, bytes]:
        self.db.require_workspace(campaign_id)
        page = max(0, int(query.get("page", "0")))
        if name == "costs.csv":
            from .workspace_costs import cost_totals_csv

            rows = self.db.workspace_cost_totals(campaign_id, all_rows=True)
            if rows is None:
                return (
                    503,
                    "text/plain; charset=utf-8",
                    _ui_text("workspace_pages.campaign_cost_index_unavailable").encode("utf-8"),
                )
            if not rows:
                return (
                    404,
                    "text/plain; charset=utf-8",
                    _ui_text("workspace_pages.no_indexed_campaign_costs").encode("utf-8"),
                )
            return 200, "text/csv; charset=utf-8", cost_totals_csv(rows, campaign_id)
        if name == "comparison.csv":
            from .workspace_comparison import comparison_rows, comparison_groups, comparison_csv
            from . import workspace_comparison_many as many

            query = many.normalize(query)
            if many.broad(query):
                data = many.page_data(self.db, campaign_id, query, page=page)
                rows = None if data is None else many.export_rows(data)
            else:
                rows = comparison_rows(self.db, campaign_id, query, offset=page * 12)
                if rows is not None:
                    rows = [row for group in comparison_groups(rows)[:12] for row in group]
            if rows is None:
                return (
                    503,
                    "text/plain; charset=utf-8",
                    _ui_text("workspace_pages.campaign_comparison_index_unavailable").encode(
                        "utf-8"
                    ),
                )
            if not rows:
                return (
                    404,
                    "text/plain; charset=utf-8",
                    _ui_text("workspace_pages.no_measured_comparison_inputs_on_this_page").encode(
                        "utf-8"
                    ),
                )
            return 200, "text/csv; charset=utf-8", comparison_csv(rows, campaign_id, query)
        model, condition = self._workspace_result_scope(query)
        if name in {"judgments.csv", "judgments.svg"}:
            rows = self.db.workspace_judgment_breakdown(
                campaign_id,
                offset=page * 12,
                model=model,
                condition=condition,
                judge=query.get("judge", ""),
            )
            if rows is None:
                return (
                    503,
                    "text/plain; charset=utf-8",
                    _ui_text("workspace_pages.campaign_judgment_index_unavailable").encode("utf-8"),
                )
            rows = [row for group in judgment_groups(rows)[:12] for row in group]
            if not rows:
                return (
                    404,
                    "text/plain; charset=utf-8",
                    _ui_text("workspace_pages.no_indexed_judgments_for_this_page").encode("utf-8"),
                )
            if name == "judgments.csv":
                return 200, "text/csv; charset=utf-8", judgment_counts_csv(rows)
            figure = judgment_breakdown_svg(
                rows,
                scope=(
                    _ui_text("workspace_pages.page")
                    + f"{page + 1}"
                    + _ui_text(
                        "workspace_pages.retained_assessment_counts_not_pooled_security_rates"
                    )
                ),
                settings=indexed_settings(self.db, campaign_id),
            )
            from .ui import _STYLE  # noqa: PLC0415

            figure = figure.replace("<style>", "<style>" + _STYLE.split("* { box-sizing:", 1)[0], 1)
            return 200, "image/svg+xml; charset=utf-8", figure.encode("utf-8")
        rows = self.db.workspace_model_totals(
            campaign_id, offset=page * 25, model=model, condition=condition
        )
        if rows is None:
            return (
                503,
                "text/plain; charset=utf-8",
                _ui_text("workspace_pages.campaign_result_index_unavailable").encode("utf-8"),
            )
        rows = rows[:25]
        if not rows:
            return (
                404,
                "text/plain; charset=utf-8",
                _ui_text("workspace_pages.no_indexed_results_for_this_page").encode("utf-8"),
            )
        if name == "model-counts.csv":
            return 200, "text/csv; charset=utf-8", model_counts_csv(rows, condition=condition)
        if name not in {"coverage.svg", "quality.svg"}:
            return (
                404,
                "text/plain; charset=utf-8",
                _ui_text("workspace_pages.unknown_figure").encode("utf-8"),
            )
        scope = (
            _ui_text("workspace_pages.selected_execution_condition")
            if condition
            else _ui_text("workspace_pages.all_retained_conditions_including_history")
        )
        scope += (
            _ui_text("workspace_pages.page_copy")
            + f"{page + 1}"
            + _ui_text("workspace_pages.operational_coverage_not_pooled_security_rates")
        )
        figure = (
            coverage_svg(
                rows, title=_ui_text("workspace_pages.campaign_outcome_composition"), scope=scope
            )
            if name == "coverage.svg"
            else quality_svg(rows, scope=scope)
        )
        # Preserve the project's light/dark theme variables in the standalone
        # vector. No remote library, script, image or external stylesheet.
        from .ui import _STYLE  # noqa: PLC0415

        theme = _STYLE.split("* { box-sizing:", 1)[0]
        figure = figure.replace("<style>", "<style>" + theme, 1)
        figure = figure.replace(
            "<style>",
            "<metadata>"
            + html.escape(json.dumps(dict(model_filter=model, condition_filter=condition)))
            + "</metadata><style>",
            1,
        )
        return 200, "image/svg+xml; charset=utf-8", figure.encode("utf-8")

    def _workspace_source_link(self, reference: str) -> str:
        path, separator, row = reference.rpartition(":")
        locator = path if separator and row.isdigit() else reference
        candidate = Path(locator)
        if not candidate.is_absolute():
            candidate = self.results_root / candidate
        fallback = False
        if not candidate.exists():
            for before, after in (
                (".responses.jsonl", ".responses.checkpoint.jsonl"),
                (".responses.checkpoint.jsonl", ".responses.jsonl"),
            ):
                if candidate.name.endswith(before):
                    alternate = candidate.with_name(candidate.name.removesuffix(before) + after)
                    if alternate.is_file():
                        candidate, fallback = alternate, True
                    break
        try:
            relative = candidate.resolve().relative_to(self.results_root.resolve()).as_posix()
        except (OSError, ValueError, RuntimeError):
            return html.escape(reference)
        label = _ui_text("workspace_pages.open_retained_artifact")
        if fallback:
            label += _ui_text("workspace_pages.alternate_export_row_position_may_differ")
        elif separator and row.isdigit():
            label += _ui_text("workspace_pages.row") + f"{row}" + ")"
        return "<a href='/artifacts?path=" + quote(relative, safe="") + "'>" + label + "</a>"

    def _campaign_selector(self, selected: str = "", *, form_id: str = "") -> str:
        if selected:
            self.db.require_workspace(selected)
        rows = self.db.workspaces()
        if rows is None:
            return _ui_template(
                "<p class='notice red'>[[text:workspace_pages.campaign_index_unavailable_no_ownership_was_inferred]]</p>"
            )
        options = _ui_template(
            "<option value=''>[[text:workspace_pages.no_campaign_standalone_job]]</option>"
        ) + "".join(
            "<option value='"
            + row["campaign_id"]
            + "'"
            + (" selected" if row["campaign_id"] == selected else "")
            + ">"
            + html.escape(row["name"])
            + "</option>"
            for row in rows
        )
        association = f" form='{html.escape(form_id)}'" if form_id else ""
        return (
            _ui_template(
                "<div class='campaign-ownership'><div class='campaign-ownership-row'><label class='campaign-field'>[[text:workspace_pages.save_under_campaign]] <select name='campaign_id'"
            )
            + association
            + ">"
            + options
            + _ui_template(
                "</select></label><a class='button ghost' href='/campaigns/new'>[[text:workspace_pages.create_campaign]]</a></div><p class='note'>[[text:workspace_pages.groups_this_job_and_its_results_choose_models_in_build_changing_t]]</p></div>"
            )
        )

    def _campaign_banner(self, campaign_id: str) -> str:
        if not campaign_id:
            return _ui_template(
                "<p class='note'>[[text:workspace_pages.standalone_work_no_campaign]]</p>"
            )
        self.db.require_workspace(campaign_id)
        campaign = self.db.workspace(campaign_id)
        return (
            _ui_template("<p>[[text:workspace_pages.campaign_copy]] <a href='/campaigns/")
            + campaign_id
            + "'>"
            + html.escape(campaign["name"])
            + "</a></p>"
            + self._campaign_guide(campaign_id)
        )

    def _campaign_guide(self, campaign_id: str, *, params=None, builder=False) -> str:
        from .campaign_guide import render

        definition = params if params is not None else self.db.workspace_definition(campaign_id)
        return render(self, dict(definition, campaign_id=campaign_id), builder=builder)

    def _workspaces_page(self, *, context: str = "campaigns") -> bytes:
        rows = self.db.workspaces()
        cards = (
            _ui_template(
                "<p class='notice red'>[[text:workspace_pages.campaign_index_unavailable]]</p>"
            )
            if rows is None
            else "".join(
                "<article class='card campaign-card'><h2><a href='/campaigns/"
                + row["campaign_id"]
                + "'>"
                + html.escape(row["name"])
                + "</a></h2>"
                "<div class='campaign-actions'><a class='button' href='/build?campaign_id="
                + row["campaign_id"]
                + _ui_template(
                    "'>[[text:workspace_pages.edit_in_build]]</a><a class='button ghost' href='/jobs?campaign_id="
                )
                + row["campaign_id"]
                + _ui_template(
                    "'>[[text:workspace_pages.jobs]]</a><a class='button ghost' href='/campaigns/"
                )
                + row["campaign_id"]
                + _ui_template(
                    "?section=overview'>[[text:workspace_pages.stats]]</a></div></article>"
                )
                for row in rows
            )
        )
        if rows == []:
            cards = _ui_template(
                "<p>[[text:workspace_pages.no_campaigns_created_yet_existing_standalone_jobs_are_unchanged]]</p>"
            )
        return _page(
            _ui_label(context),
            "<h1>"
            + html.escape(_ui_label(context))
            + "</h1>"
            + (self._work_view_tabs(context, "campaigns") if context in {"jobs", "stats"} else "")
            + _ui_template(
                "<p>[[text:workspace_pages.campaigns_evaluate_arms_corpora_and_frameworks_across_model_sets]]</p><p class='action-row'><a class='button' href='/build?work_kind=campaign#build-general'>[[text:workspace_pages.build_a_campaign]]</a> <a class='button ghost' href='/build?work_kind=run#build-general'>[[text:workspace_pages.build_a_single_run]]</a></p>"
            )
            + "<div class='campaign-grid'>"
            + cards
            + "</div>",
            active=_ui_label(context),
        )

    def _workspace_page(self, campaign_id: str, query: dict[str, str]) -> bytes:
        self.db.require_workspace(campaign_id)
        campaign = self.db.workspace(campaign_id)
        section = query.get("section", "overview")
        sections = ("overview", "definition", "results", "judging", "compare", "costs", "activity")
        if section not in sections:
            raise ValueError(_ui_text("workspace_pages.unknown_campaign_section"))
        base = "/campaigns/" + campaign_id
        model, condition = self._workspace_result_scope(query)
        scope_query = ("&amp;model=" + quote(model, safe="") if model else "") + (
            "&amp;condition=" + quote(condition, safe="") if condition else ""
        )
        navigation = (
            _ui_template(
                "<nav class='page-tablist server-tablist' aria-label='[[attr:workspace_pages.campaign_sections]]'>"
            )
            + "".join(
                "<a class='page-tab' href='"
                + base
                + "?section="
                + tab
                + (scope_query if tab in {"overview", "results", "judging"} else "")
                + "'"
                + (" aria-current='page'" if tab == section else "")
                + ">"
                + html.escape(_ui_label(tab))
                + "</a>"
                for tab in sections
            )
            + "<a class='page-tab' href='/human-evaluation?campaign_id="
            + campaign_id
            + _ui_template("'>[[text:workspace_pages.human_evaluation]]</a>")
            + "<a class='page-tab' href='/assessment?campaign_id="
            + campaign_id
            + _ui_template("'>[[text:workspace_pages.evaluate_saved_answers]]</a>")
            + "<a class='page-tab' href='/analysis?campaign_id="
            + campaign_id
            + _ui_template("'>[[text:workspace_pages.svm_analysis]]</a></nav>")
        )
        if section == "definition":
            definition = self.db.workspace_definition(campaign_id)
            content = _ui_template(
                "<p>[[text:workspace_pages.no_build_definition_has_been_saved_for_this_retained_campaign_its]]</p>"
            )
            if definition:
                content = (
                    _ui_template(
                        "<p>[[text:workspace_pages.saved_configuration_for_future_runs_each_launched_job_retains_its]]</p><dl class='builder-summary'>"
                    )
                    + "".join(
                        "<div><dt>"
                        + label
                        + "</dt><dd>"
                        + html.escape(definition.get(key) or _ui_text("workspace_pages.not_set"))
                        + "</dd></div>"
                        for key, label in (
                            ("local", _ui_text("workspace_pages.local_models")),
                            ("api", _ui_text("workspace_pages.api_models")),
                            ("corpora", _ui_text("workspace_pages.arms_corpora")),
                            ("attackers", _ui_text("workspace_pages.frameworks_attacks")),
                            ("seeds", _ui_text("workspace_pages.seeds")),
                            ("sampling_policy", _ui_text("workspace_pages.sampling")),
                            ("limit", _ui_text("workspace_pages.per_arm_limit")),
                            ("judges", _ui_text("workspace_pages.judges")),
                            ("judge_model", _ui_text("workspace_pages.judge_model")),
                            ("out", _ui_text("workspace_pages.output")),
                        )
                    )
                    + "</dl>"
                )
        elif section == "compare":
            from .workspace_comparison import comparison_page

            content = comparison_page(self.db, campaign_id, query)
        elif section == "activity":
            offset = max(0, int(query.get("page", "0"))) * 50
            rows = self.db.workspace_activity(campaign_id, offset=offset)
            if rows is None:
                content = _ui_template(
                    "<p class='notice red'>[[text:workspace_pages.activity_index_unavailable]]</p>"
                )
            elif not rows:
                content = _ui_template("<p>[[text:workspace_pages.no_activities_on_this_page]]</p>")
            else:
                records = []
                for row in rows[:50]:
                    kind, key = row["member_kind"], row["member_id"]
                    prefixes = {
                        "job": "/jobs/",
                        "external": "/jobs/external/",
                        "controller": "/jobs/campaign/",
                        "analysis": "/stats/job/",
                    }
                    link = (
                        (
                            "<a href='"
                            + prefixes[kind]
                            + quote(key, safe="")
                            + "'>"
                            + html.escape(row["command"] or key)
                            + "</a>"
                        )
                        if kind in prefixes
                        else html.escape(key)
                    )
                    records.append(
                        "<tr><td>"
                        + link
                        + "</td><td>"
                        + html.escape(_ui_label(row["role"]))
                        + "</td><td>"
                        + (
                            _ui_text("workspace_pages.console")
                            if kind == "job"
                            else _ui_text("workspace_pages.external_reference")
                        )
                        + "</td><td>"
                        + html.escape(
                            _ui_label(row["state"])
                            if row["state"]
                            else _ui_text("workspace_pages.see_original_record")
                        )
                        + "</td></tr>"
                    )
                content = (
                    _ui_template(
                        "<div class='scroll'><table><tr><th>[[text:workspace_pages.activity]]</th><th>[[text:workspace_pages.stage]]</th><th>[[text:workspace_pages.origin]]</th><th>[[text:workspace_pages.status]]</th></tr>"
                    )
                    + "".join(records)
                    + "</table></div>"
                )
                if offset:
                    content += (
                        "<a href='"
                        + f"{base}"
                        + "?section=activity&amp;page="
                        + f"{offset // 50 - 1}"
                        + _ui_template("'>[[text:workspace_pages.previous]]</a> ")
                    )
                if len(rows) > 50:
                    content += (
                        "<a href='"
                        + f"{base}"
                        + "?section=activity&amp;page="
                        + f"{offset // 50 + 1}"
                        + _ui_template("'>[[text:workspace_pages.next]]</a>")
                    )
        else:
            content = self._workspace_results(campaign_id, section, query)
        if section in {"overview", "results", "judging"}:
            content = self._workspace_result_filters(campaign_id, section, query) + content
        return _page(
            campaign["name"],
            "<h1>" + html.escape(campaign["name"]) + "</h1>"
            "<p class='action-row'><a class='button' href='/build?campaign_id="
            + campaign_id
            + _ui_template(
                "'>[[text:workspace_pages.configure_in_build]]</a> <a class='button ghost' href='/jobs?campaign_id="
            )
            + campaign_id
            + _ui_template(
                "'>[[text:workspace_pages.campaign_jobs]]</a> <a class='button ghost' href='/commands?campaign_id="
            )
            + campaign_id
            + _ui_template("'>[[text:workspace_pages.run_tools]]</a></p>")
            + self._campaign_guide(campaign_id)
            + navigation
            + (self._operation_links(campaign_id) if section in {"overview", "activity"} else "")
            + "<section class='card'><h2>"
            + html.escape(_ui_label(section))
            + "</h2>"
            + content
            + "</section>",
            active=_ui_text("workspace_pages.campaigns")
            if section in {"definition", "activity"}
            else _ui_text("workspace_pages.stats"),
        )

    def _workspace_results(self, campaign_id: str, section: str, query: dict[str, str]) -> str:
        unknown = (
            _ui_template("<p class='notice amber'>[[text:workspace_pages.retained]] ")
            + html.escape(section)
            + _ui_template(
                " [[text:workspace_pages.data_has_not_been_indexed_for_this_campaign_yet_totals_are_unknow]]</p><p>[[text:workspace_pages.build_launches_are_associated_automatically_original_jobs_and_rep]]</p>"
            )
        )
        page = max(0, int(query.get("page", "0")))
        base = "/campaigns/" + campaign_id + "?section=" + section
        model, condition = self._workspace_result_scope(query)
        scope_query = ("&amp;model=" + quote(model, safe="") if model else "") + (
            "&amp;condition=" + quote(condition, safe="") if condition else ""
        )
        base += scope_query
        if model or condition:
            unknown = (
                _ui_template("<p class='notice amber'>[[text:workspace_pages.no_indexed]] ")
                + html.escape(section)
                + _ui_template(
                    " [[text:workspace_pages.rows_for_this_selection_missing_data_are_unknown_not_zero]]</p>"
                )
            )

        def pagination(has_next):
            return (
                (
                    "<a href='"
                    + f"{base}"
                    + "&amp;page="
                    + f"{page - 1}"
                    + _ui_template("'>[[text:workspace_pages.previous]]</a> ")
                )
                if page
                else ""
            ) + (
                (
                    "<a href='"
                    + f"{base}"
                    + "&amp;page="
                    + f"{page + 1}"
                    + _ui_template("'>[[text:workspace_pages.next]]</a>")
                )
                if has_next
                else ""
            )

        def table(headers, rows):
            return (
                "<div class='scroll'><table><tr>"
                + "".join("<th>" + h + "</th>" for h in headers)
                + "</tr>"
                + "".join(
                    "<tr>" + "".join("<td>" + cell + "</td>" for cell in row) + "</tr>"
                    for row in rows
                )
                + "</table></div>"
            )

        if section == "costs":
            rows = self.db.workspace_cost_totals(campaign_id, offset=page * 25)
            if not rows:
                return unknown

            def amount(value):
                return (
                    _ui_text("workspace_pages.unknown_status")
                    if value is None
                    else f"${value / 1_000_000:,.6f}"
                )

            def tokens(row, name):
                total = row[name + "_tokens"]
                missing = row[name + "_unknown"]
                return (
                    _ui_text("workspace_pages.unknown_status") if total is None else f"{total:,}"
                ) + (
                    ("; " + f"{missing:,}" + _ui_text("workspace_pages.attempt_s_unknown"))
                    if missing
                    else ""
                )

            return (
                _ui_template(
                    "<p>[[text:workspace_pages.indexed_physical_attempts_counted_once_including_retries_and_hist]]</p>"
                )
                + "<p class='action-row' id='campaign-exports'><a class='button ghost' data-campaign-export download='campaign-costs.csv' href='/campaigns/"
                + campaign_id
                + _ui_template(
                    "/figures/costs.csv'>[[text:workspace_pages.download_full_campaign_cost_table]]</a></p><p id='campaign-export-status' role='status'></p>"
                )
                + EXPORT_SCRIPT
                + "<div class='campaign-costs'>"
                + table(
                    (
                        _ui_text("workspace_pages.provider_model"),
                        _ui_text("workspace_pages.role"),
                        _ui_text("workspace_pages.http_attempts_local_evaluations"),
                        _ui_text("workspace_pages.recorded_cost_usd"),
                        _ui_text("workspace_pages.uncertain_charge_exposure_usd"),
                        _ui_text("workspace_pages.reported_tokens_input_output_reasoning"),
                    ),
                    [
                        [
                            html.escape(row["provider"] + " / " + row["model"]),
                            html.escape(row["role"]),
                            f"{row['http_attempts']:,} / {row['local_evaluations']:,}",
                            (
                                _ui_text("workspace_pages.no_api_charge")
                                if row["provider"] == "local"
                                else amount(row["cost_microusd"])
                            )
                            + (
                                "<br>"
                                + f"{row['settled_attempts']:,}"
                                + _ui_text("workspace_pages.settled")
                                + f"{row['unknown_attempts']:,}"
                                + _ui_text("workspace_pages.unknown")
                                + f"{row['unsettled_attempts']:,}"
                                + _ui_text("workspace_pages.in_flight")
                            ),
                            amount(row["exposure_microusd"])
                            + (
                                (
                                    "; "
                                    + f"{row['unknown_exposure_count']:,}"
                                    + _ui_text("workspace_pages.without_a_bound")
                                )
                                if row["unknown_exposure_count"]
                                else ""
                            ),
                            " / ".join(
                                tokens(row, name) for name in ("input", "output", "reasoning")
                            ),
                        ]
                        for row in rows[:25]
                    ],
                )
                + "</div>"
                + pagination(len(rows) > 25)
            )
        if section == "judging":
            settings = indexed_settings(self.db, campaign_id)
            review_coverage = review_coverage_html(
                self.db, campaign_id, settings, model=model, condition=condition
            )
            judge = query.get("judge", "")
            rows = self.db.workspace_judging_totals(campaign_id, model=model, condition=condition)
            if rows and judge:
                rows = [row for row in rows if row["judge_id"] == judge]
            if not rows:
                return review_coverage + unknown
            if judge:
                all_link = "/campaigns/" + campaign_id + "?section=judging" + scope_query
                review_coverage += (
                    _ui_template("<p>[[text:workspace_pages.showing_only]] ")
                    + html.escape(judge_name(judge, settings.get(judge)))
                    + ". <a href='"
                    + all_link
                    + _ui_template("'>[[text:workspace_pages.show_all_evaluators]]</a>.</p>")
                )
                scope_query += "&amp;judge=" + quote(judge, safe="")
                base += "&amp;judge=" + quote(judge, safe="")
            breakdown = self.db.workspace_judgment_breakdown(
                campaign_id, offset=page * 12, model=model, condition=condition, judge=judge
            )
            if breakdown is None:
                return _ui_template(
                    "<p class='notice amber'>[[text:workspace_pages.judgment_label_index_unavailable]]</p>"
                )
            groups = judgment_groups(breakdown)
            selected = [row for group in groups[:12] for row in group]
            exports = (
                "<p class='action-row' id='campaign-exports'>"
                + " ".join(
                    "<a class='button ghost' data-campaign-export download='campaign-"
                    + name
                    + "' href='/campaigns/"
                    + campaign_id
                    + "/figures/"
                    + name
                    + "?page="
                    + str(page)
                    + scope_query
                    + "'>"
                    + label
                    + "</a>"
                    for name, label in (
                        ("judgments.svg", _ui_text("workspace_pages.export_judgment_figure")),
                        ("judgments.csv", _ui_text("workspace_pages.export_judgment_table")),
                    )
                )
                + "</p><p id='campaign-export-status' role='status'></p>"
                + EXPORT_SCRIPT
            )
            return (
                _ui_template(
                    "<p>[[text:workspace_pages.labels_for_the_selected_outputs_separated_by_model_source_framewo]]</p><p>[[text:workspace_pages.for_source_classification_corpora_task_labels_describe_the_classi]]</p><p class='note'>[[text:workspace_pages.measured_conditions_are_listed_first_diagnostics_remain_separate]]</p>"
                )
                + review_coverage
                + exports
                + judgment_breakdown_html(selected, settings=settings)
                + pagination(len(groups) > 12)
                + _ui_template(
                    "<details><summary>[[text:workspace_pages.all_indexed_judging_totals_for_this_selection]]</summary>"
                )
                + table(
                    (
                        _ui_text("workspace_pages.judge_condition"),
                        _ui_text("workspace_pages.status"),
                        _ui_text("workspace_pages.verdicts"),
                    ),
                    [
                        [
                            html.escape(judge_name(row["judge_id"], settings.get(row["judge_id"]))),
                            html.escape(row["status"]),
                            str(row["count"]),
                        ]
                        for row in rows
                    ],
                )
                + "</details>"
            )
        if section == "overview":
            inputs = self.db.workspace_input_totals(
                campaign_id, offset=page * 25, model=model, condition=condition
            )
            input_coverage = ""
            if inputs:
                input_coverage = (
                    _ui_template(
                        "<h3>[[text:workspace_pages.native_collection_input_coverage]]</h3><p>[[text:workspace_pages.source_rows_in_the_indexed_local_run_plans_reached_means_at_least]]</p>"
                    )
                    + table(
                        (
                            _ui_text("workspace_pages.model"),
                            _ui_text("workspace_pages.evidence"),
                            _ui_text("workspace_pages.runs"),
                            _ui_text("workspace_pages.source_rows_planned"),
                            _ui_text("workspace_pages.reached"),
                            _ui_text("workspace_pages.not_reached"),
                        ),
                        [
                            [
                                html.escape(row["model"]),
                                html.escape(row["evidence_class"]),
                                str(row["runs"]),
                                str(row["planned"]),
                                str(row["reached"]),
                                str(row["planned"] - row["reached"]),
                            ]
                            for row in inputs[:25]
                        ],
                    )
                    + pagination(len(inputs) > 25)
                )
            elif inputs is None:
                input_coverage = _ui_template(
                    "<p class='notice amber'>[[text:workspace_pages.native_input_plan_index_unavailable]]</p>"
                )
            rows = self.db.workspace_model_totals(
                campaign_id, offset=page * 25, model=model, condition=condition
            )
            if not rows:
                return input_coverage + unknown
            chart = coverage_html(rows[:25])
            exports = (
                "<p class='action-row' id='campaign-exports'>"
                + " ".join(
                    "<a class='button ghost' data-campaign-export download='campaign-"
                    + name
                    + "' href='/campaigns/"
                    + campaign_id
                    + "/figures/"
                    + name
                    + "?page="
                    + str(page)
                    + scope_query
                    + "'>"
                    + label
                    + "</a>"
                    for name, label in (
                        ("coverage.svg", _ui_text("workspace_pages.export_coverage_figure")),
                        (
                            "quality.svg",
                            _ui_text("workspace_pages.export_missing_truncation_figure"),
                        ),
                        ("model-counts.csv", _ui_text("workspace_pages.export_matching_table")),
                    )
                )
                + "</p><p id='campaign-export-status' role='status'></p>"
                + EXPORT_SCRIPT
            )
            return (
                _ui_template(
                    "<p>[[text:workspace_pages.explicitly_indexed_assignments_not_sums_of_overlapping_job_report]]</p>"
                )
                + input_coverage
                + exports
                + chart
                + _ui_template(
                    "<details><summary>[[text:workspace_pages.exact_counts_and_execution_condition_coverage]]</summary>"
                )
                + table(
                    (
                        _ui_text("workspace_pages.model"),
                        _ui_text("workspace_pages.evidence"),
                        _ui_text("workspace_pages.conditions"),
                        _ui_text("workspace_pages.assigned"),
                        _ui_text("workspace_pages.usable"),
                        _ui_text("workspace_pages.policy"),
                        _ui_text("workspace_pages.missing"),
                        _ui_text("workspace_pages.retry_pending"),
                        _ui_text("workspace_pages.pending"),
                        _ui_text("workspace_pages.truncated"),
                        _ui_text("workspace_pages.truncation_unknown"),
                    ),
                    [
                        [
                            "<a href='/campaigns/"
                            + campaign_id
                            + "?section=results&amp;model="
                            + quote(row["model"], safe="")
                            + ("&amp;condition=" + quote(condition, safe="") if condition else "")
                            + "'>"
                            + html.escape(row["model"])
                            + "</a>"
                        ]
                        + [html.escape(row["evidence_class"])]
                        + [
                            str(row[key] or 0)
                            for key in (
                                "conditions",
                                "assigned",
                                "usable",
                                "policy",
                                "missing",
                                "retry_pending",
                                "pending",
                                "truncated",
                                "truncation_unknown",
                            )
                        ]
                        for row in rows[:25]
                    ],
                )
                + "</details>"
                + pagination(len(rows) > 25)
            )
        rows = self.db.workspace_result_rows(
            campaign_id, offset=page * 50, model=model, condition=condition
        )
        if not rows:
            return unknown
        recoveries = self.db.workspace_recovery_rows(
            campaign_id, model=model, condition=condition, offset=page * 50
        )
        recovery_html = ""
        if recoveries:
            recovery_rows = []
            for link in recoveries[:50]:
                old = json.loads(link["old_details"])
                new = json.loads(link["new_details"])
                recovery_rows.append(
                    [
                        html.escape(link["model"].partition(";")[0]),
                        html.escape(link["corpus"] + " / " + link["modality"]),
                        html.escape(link["old_outcome"])
                        + " - "
                        + self._workspace_source_link(old["source_ref"]),
                        html.escape(link["new_outcome"])
                        + " - "
                        + self._workspace_source_link(new["source_ref"]),
                        html.escape(link["reason"])
                        + " "
                        + self._workspace_source_link(link["evidence_ref"]),
                    ]
                )
            recovery_html = (
                _ui_template(
                    "<section><h2>[[text:workspace_pages.recovery_history]]</h2><p>[[text:workspace_pages.explicit_links_connect_original_outcomes_to_saved_recovery_answer]]</p>"
                )
                + table(
                    (
                        _ui_text("workspace_pages.model"),
                        _ui_text("workspace_pages.corpus_modality"),
                        _ui_text("workspace_pages.original_outcome"),
                        _ui_text("workspace_pages.recovery_outcome"),
                        _ui_text("workspace_pages.reason_evidence"),
                    ),
                    recovery_rows,
                )
                + "</section>"
            )
        output = []
        for row in rows[:50]:
            details = json.loads(row["details"]) if row["details"] else {}

            def value(key):
                item = details.get(key)
                if key == "output_allowance" and item == -1:
                    return _ui_text("workspace_pages.native_maximum_no_fixed_output_cap")
                return (
                    html.escape(_ui_text("workspace_pages.unknown_status"))
                    if item is None
                    else html.escape(str(item))
                )

            metadata = (
                _ui_template(
                    "<details><summary>[[text:workspace_pages.generation_settings_and_usage]]</summary><dl>"
                )
                + "".join(
                    "<dt>" + label + "</dt><dd>" + value(key) + "</dd>"
                    for key, label in (
                        ("context_tokens", _ui_text("workspace_pages.effective_context")),
                        ("output_allowance", _ui_text("workspace_pages.output_allowance")),
                        ("input_tokens", _ui_text("workspace_pages.reported_input_tokens")),
                        ("output_tokens", _ui_text("workspace_pages.reported_output_tokens")),
                        ("reasoning_tokens", _ui_text("workspace_pages.reported_reasoning_tokens")),
                        ("finish_reason", _ui_text("workspace_pages.finish_reason")),
                        ("missing_category", _ui_text("workspace_pages.missing_output_category")),
                    )
                )
                + "</dl>"
            )
            metadata += (
                _ui_template("<p>[[text:workspace_pages.exact_model]] ")
                + html.escape(row["model"])
                + "</p>"
            )
            metadata += (
                _ui_template("<p>[[text:workspace_pages.input_identity]] ")
                + html.escape(row["input_id"])
                + "</p>"
            )
            metadata += (
                _ui_template("<p>[[text:workspace_pages.condition_copy]] ")
                + html.escape(row["response_condition"] or row["condition_id"])
                + "</p>"
            )
            metadata += (
                _ui_template("<p>[[text:workspace_pages.source]] ")
                + (
                    self._workspace_source_link(details["source_ref"])
                    if details.get("source_ref")
                    else html.escape(_ui_text("workspace_pages.unknown_status"))
                )
                + "</p></details>"
            )
            input_label = (
                row["input_id"] if len(row["input_id"]) <= 16 else row["input_id"][:12] + "..."
            )
            model_label = row["model"].partition(";")[0].partition("@sha256:")[0]
            output.append(
                [
                    html.escape(model_label),
                    "<span title='"
                    + html.escape(row["input_id"], quote=True)
                    + "'>"
                    + html.escape(input_label)
                    + "</span>",
                    html.escape(row["evidence_class"]),
                    html.escape(row["modality"]),
                    html.escape(row["framework"] + " / " + row["corpus"]),
                    html.escape(row["outcome"] or "pending"),
                    html.escape(
                        _ui_text("workspace_pages.unknown_status")
                        if row["truncated"] is None
                        else _ui_text("workspace_pages.yes")
                        if row["truncated"]
                        else _ui_text("workspace_pages.no")
                    ),
                    metadata,
                ]
            )
        return (
            recovery_html
            + "<div class='campaign-output-table'>"
            + table(
                (
                    _ui_text("workspace_pages.model"),
                    _ui_text("workspace_pages.input"),
                    _ui_text("workspace_pages.evidence"),
                    _ui_text("workspace_pages.modality"),
                    _ui_text("workspace_pages.framework_corpus"),
                    _ui_text("workspace_pages.outcome"),
                    _ui_text("workspace_pages.truncated"),
                    _ui_text("workspace_pages.details"),
                ),
                output,
            )
            + "</div>"
            + pagination(len(rows) > 50 or len(recoveries or []) > 50)
        )
