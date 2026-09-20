"""Read-only, exact-input comparisons of explicitly selected indexed conditions."""

from __future__ import annotations


from .display_labels import label as _ui_label
from .i18n import template as _ui_template, text as _ui_text

import csv
import html
import io
from itertools import groupby
from urllib.parse import urlencode

from .workspace_judging_charts import _judge_name
from .workspace_judge_settings import indexed_settings, settings_html
from .workspace_charts import EXPORT_SCRIPT
from . import workspace_comparison_many as many

FACETS = ("corpus", "framework", "modality")
FIELDS = (
    "match_status",
    "left_outcome",
    "right_outcome",
    "left_truncated",
    "right_truncated",
    "left_status",
    "left_label",
    "right_status",
    "right_label",
)
CHOICES = (
    "left_model",
    "left_condition",
    "left_judge",
    "right_campaign",
    "right_model",
    "right_condition",
    "right_judge",
)
FILTERS = tuple("compare_" + facet for facet in FACETS)


def judge_choices(db, campaign, model, condition):
    return db._query(
        "SELECT DISTINCT j.judge_id FROM campaign_assignments a "
        "JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
        "AND r.assignment_id=a.assignment_id "
        "JOIN campaign_judgments j ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
        "WHERE a.campaign_id=? AND a.model=? AND COALESCE(r.condition_id,a.condition_id)=? AND a.evidence_class='measured' "
        "ORDER BY j.judge_id",
        (campaign, model, condition),
    )


def comparison_rows(
    db, campaign, query, *, offset=0, permit_missing_judges=False, all_facets=False
):
    """Return thirteen whole source facets, the last for pagination lookahead.

    Multiple assignments for one input are ambiguous, never a Cartesian pair
    or an invitation to select the newest/best answer. Only measured evidence
    and the assignment-selected response are considered. Missing judgments
    mean not indexed, not necessarily scheduled work.
    """
    if type(offset) is not int or offset < 0 or any(not query.get(key) for key in CHOICES):
        raise ValueError(
            _ui_text(
                "workspace_comparison.select_both_models_generation_conditions_and_judging_conditions"
            )
        )
    sides, params = [], []
    for side, owner in (("left", campaign), ("right", query["right_campaign"])):
        db.require_workspace(owner)
        if not permit_missing_judges:
            judges = judge_choices(db, owner, query[side + "_model"], query[side + "_condition"])
            if judges is None:
                return None
            if query[side + "_judge"] not in {row["judge_id"] for row in judges}:
                raise ValueError(
                    _ui_text(
                        "workspace_comparison.select_an_indexed_judging_condition_for_each_model_and_generation"
                    )
                )
        filters = "".join(
            " AND a." + facet + "=?" for facet, name in zip(FACETS, FILTERS) if query.get(name)
        )
        sides.append(
            side + "_inputs AS (SELECT a.input_id,a.corpus,a.framework,a.modality,COUNT(*) AS n,"
            "CASE WHEN COUNT(*)=1 THEN MAX(r.outcome) END AS outcome,"
            "CASE WHEN COUNT(*)=1 THEN MAX(r.truncated) END AS truncated,"
            "CASE WHEN COUNT(*)=1 THEN MAX(j.status) END AS status,"
            "CASE WHEN COUNT(*)=1 THEN MAX(j.label) END AS label "
            "FROM campaign_assignments a LEFT JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "AND r.assignment_id=a.assignment_id "
            "LEFT JOIN campaign_judgments j ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
            "AND j.judge_id=? WHERE a.campaign_id=? AND a.model=? AND COALESCE(r.condition_id,a.condition_id)=? "
            "AND a.evidence_class='measured'"
            + filters
            + " GROUP BY a.input_id,a.corpus,a.framework,a.modality)"
        )
        params.extend(
            (query[side + "_judge"], owner, query[side + "_model"], query[side + "_condition"])
        )
        params.extend(query[name] for name in FILTERS if query.get(name))
    keys = "input_id,corpus,framework,modality"
    fields = ",".join(FACETS + FIELDS)
    sql = (
        "WITH "
        + ",".join(sides)
        + ", input_keys AS (SELECT "
        + keys
        + " FROM left_inputs UNION SELECT "
        + keys
        + " FROM right_inputs), paired AS (SELECT k.corpus,k.framework,k.modality,"
    )
    sql += "CASE WHEN l.n IS NULL THEN 'right_only' WHEN r.n IS NULL THEN 'left_only' WHEN l.n>1 OR r.n>1 THEN 'ambiguous' ELSE 'matched' END AS match_status,"
    sql += ",".join(
        f"{alias}.{field} AS {side}_{field}"
        for side, alias in (("left", "l"), ("right", "r"))
        for field in ("outcome", "truncated", "status", "label")
    )
    sql += (
        " FROM input_keys k LEFT JOIN left_inputs l USING("
        + keys
        + ") LEFT JOIN right_inputs r USING("
        + keys
        + "))"
    )
    sql += (
        ", counts AS (SELECT " + fields + ",COUNT(*) AS count FROM paired GROUP BY " + fields + ")"
    )
    if all_facets:
        return db._query(sql + " SELECT * FROM counts ORDER BY " + fields, params)
    sql += ", ranked AS (SELECT *,DENSE_RANK() OVER(ORDER BY corpus,framework,modality) AS facet FROM counts)"
    sql += " SELECT * FROM ranked WHERE facet>? AND facet<=? ORDER BY " + fields
    return db._query(sql, (*params, offset, offset + 13))


def comparison_groups(rows):
    return [
        list(values)
        for _key, values in groupby(rows, key=lambda row: tuple(row[key] for key in FACETS))
    ]


def comparison_csv(rows, campaign, query):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    fields = (
        "left_campaign",
        *CHOICES,
        "left_condition_selection",
        "right_condition_selection",
        *FILTERS,
        *FACETS,
        *FIELDS,
        "count",
    )
    writer.writerow(fields)
    for row in rows:
        value = {
            "left_campaign": campaign,
            **{key: query[key] for key in CHOICES},
            **{
                side + "_condition_selection": many.CONDITION_MODES.get(
                    query[side + "_condition"], _ui_text("workspace_comparison.explicit_condition")
                )
                for side in ("left", "right")
            },
            **{key: query.get(key, "") for key in FILTERS},
            **dict(row),
        }
        writer.writerow(
            [
                "'" + value[key]
                if isinstance(value[key], str) and value[key].startswith(("=", "+", "-", "@"))
                else value[key]
                for key in fields
            ]
        )
    return stream.getvalue().encode("utf-8-sig")


def _select(name, label, values, selected, *, optional=False, empty_hint=""):
    empty = not values and not optional
    prompt = (
        empty_hint
        if empty and empty_hint
        else _ui_text("workspace_comparison.all")
        if optional
        else _ui_text("workspace_comparison.choose") + label.lower()
    )
    options = "<option value=''>" + html.escape(prompt) + "</option>"
    options += "".join(
        "<option value='"
        + html.escape(value, quote=True)
        + "'"
        + (" selected" if value == selected else "")
        + ">"
        + html.escape(text)
        + "</option>"
        for value, text in values
    )
    hint = (
        "<small class='fieldhint' id='" + name + "-help'>" + html.escape(prompt) + "</small>"
        if empty
        else ""
    )
    return (
        "<label class='campaign-field'>"
        + html.escape(label)
        + "<select name='"
        + name
        + "'"
        + (" disabled aria-describedby='" + name + "-help'" if empty else "")
        + ">"
        + options
        + "</select>"
        + hint
        + "</label>"
    )


def facet_choices(db, campaign, query):
    values = {facet: set() for facet in FACETS}
    for side, owner in (("left", campaign), ("right", query.get("right_campaign", ""))):
        if not owner or not query.get(side + "_model") or not query.get(side + "_condition"):
            continue
        db.require_workspace(owner)
        condition = query[side + "_condition"]
        if condition in many.CONDITION_MODES:
            condition = many.ALL
        rows = db._query(
            "SELECT DISTINCT a.corpus,a.framework,a.modality FROM campaign_assignments a "
            "LEFT JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "AND r.assignment_id=a.assignment_id WHERE a.campaign_id=? AND (?='*' OR a.model=?) "
            "AND (?='*' OR COALESCE(r.condition_id,a.condition_id)=?) AND a.evidence_class='measured'",
            (owner, query[side + "_model"], query[side + "_model"], condition, condition),
        )
        if rows is None:
            return None
        for row in rows:
            for facet in FACETS:
                values[facet].add(row[facet])
    return values


def _condition_tokens(row, prefix):
    low, high = row[prefix + "_min"], row[prefix + "_max"]

    def tokens(value):
        return _ui_text("workspace_comparison.native_maximum") if value == -1 else f"{value:,}"

    value = (
        "unknown"
        if low is None
        else tokens(low)
        + ((_ui_text("workspace_comparison.to") + tokens(high)) if high != low else "")
    )
    if 0 < row[prefix + "_known"] < row["assigned"]:
        value += _ui_text("workspace_comparison.partly_unknown")
    return value


def _condition_sources(row, key):
    return ", ".join(sorted((row[key] or "").split(","))) or "unknown"


def _condition_label(row, number):
    return (
        _ui_text("workspace_comparison.condition")
        + f"{number}"
        + ": "
        + f"{_condition_sources(row, 'modalities')}"
        + _ui_text("workspace_comparison.context")
        + f"{_condition_tokens(row, 'context')}"
        + _ui_text("workspace_comparison.output_allowance")
        + f"{_condition_tokens(row, 'output')}"
        + "; "
        + f"{row['assigned']:,}"
        + _ui_text("workspace_comparison.assignments")
    )


def _comparison_body(db, campaign, query):
    query = many.normalize(query)
    base = "/campaigns/" + campaign
    campaigns = db.workspaces()
    if campaigns is None:
        return _ui_template(
            "<p class='notice red'>[[text:workspace_comparison.campaign_index_unavailable]]</p>"
        )
    owners = {row["campaign_id"]: row["name"] for row in campaigns}
    form = (
        "<form data-comparison-form method='get' action='"
        + base
        + "'><input type='hidden' name='section' value='compare'><div class='cols'>"
    )
    for side, owner in (("left", campaign), ("right", query.get("right_campaign", ""))):
        form += (
            "<fieldset class='comparison-condition'><legend>"
            + _ui_label(side)
            + _ui_template(" [[text:workspace_comparison.condition_2]]</legend>")
        )
        if side == "right":
            form += _select(
                "right_campaign",
                _ui_text("workspace_comparison.campaign"),
                list(owners.items()),
                owner,
            )
        else:
            form += "<p>" + html.escape(owners[campaign]) + "</p>"
        model, condition = query.get(side + "_model", ""), query.get(side + "_condition", "")
        models = db.workspace_result_models(owner) if owner in owners else []
        if models is not None and (
            (model == many.ALL and not models)
            or (model != many.ALL and model not in {row["model"] for row in models})
        ):
            model = query[side + "_model"] = ""
        conditions = (
            db.workspace_result_conditions(owner, model=model, measured_only=True)
            if owner in owners and model and model != many.ALL
            else []
        )
        if (
            conditions is not None
            and model != many.ALL
            and condition
            not in (
                {row["condition_id"] for row in conditions}
                | (set(many.CONDITION_MODES) if conditions else set())
            )
        ):
            condition = query[side + "_condition"] = ""
        judges = (
            many.scope_judges(db, owner, model, condition, query=query)
            if owner in owners and model and condition
            else []
        )
        if models is None or conditions is None or judges is None:
            return _ui_template(
                "<p class='notice red'>[[text:workspace_comparison.comparison_selection_index_unavailable]]</p>"
            )
        model_values = (
            [(many.ALL, _ui_text("workspace_comparison.all_models"))] if models else []
        ) + [(row["model"], many.model_label(row["model"])) for row in models]
        form += _select(
            side + "_model",
            _ui_text("workspace_comparison.model"),
            model_values,
            model,
            empty_hint=_ui_text("workspace_comparison.choose_a_campaign_first")
            if owner not in owners
            else _ui_text("workspace_comparison.no_indexed_model_results_in_this_campaign"),
        )
        if model == many.ALL:
            form += _select(
                side + "_condition",
                _ui_text("workspace_comparison.generation_condition"),
                list(many.CONDITION_MODES.items()),
                condition,
            )
            form += (
                "<p class='fieldhint' data-comparison-scope='"
                + side
                + _ui_template("'>[[text:workspace_comparison.only]] ")
                + html.escape(owners[owner])
                + _ui_text("workspace_comparison.all_indexed_models")
                + (
                    _ui_text(
                        "workspace_comparison.generation_conditions_all_measured_conditions_compared_separately"
                    )
                    if condition == many.ALL
                    else _ui_text(
                        "workspace_comparison.the_selected_condition_rule_is_applied_independently_per_model_ti"
                    )
                )
                + _ui_template(
                    "[[text:workspace_comparison.models_without_eligible_measured_conditions_are_identified_below]]</p>"
                )
            )
        else:
            form += _select(
                side + "_condition",
                _ui_text("workspace_comparison.generation_condition"),
                (list(many.CONDITION_MODES.items()) if conditions else [])
                + [
                    (row["condition_id"], _condition_label(row, number))
                    for number, row in enumerate(conditions, 1)
                ],
                condition,
                empty_hint=_ui_text("workspace_comparison.choose_a_model_first")
                if not model
                else _ui_text(
                    "workspace_comparison.no_indexed_generation_conditions_for_this_model"
                ),
            )
            if model:
                form += (
                    "<p class='fieldhint' data-comparison-scope='"
                    + side
                    + _ui_template(
                        "' style='overflow-wrap:anywhere'>[[text:workspace_comparison.only]] "
                    )
                    + html.escape(owners[owner])
                    + " / "
                    + html.escape(many.model_label(model))
                    + (
                        ": "
                        + f"{len(conditions)}"
                        + _ui_template(
                            " [[text:workspace_comparison.measured_generation_conditions_condition_numbers_are_local_to_thi]]</p>"
                        )
                    )
                )
                if condition == many.ALL:
                    form += (
                        "<p class='fieldhint' data-all-conditions='"
                        + side
                        + _ui_template(
                            "'>[[text:workspace_comparison.all_generation_conditions_for_this_model_are_compared_separately]]</p>"
                        )
                    )
            selected = next((row for row in conditions if row["condition_id"] == condition), None)
            if selected is not None:
                form += (
                    "<details data-condition-details='"
                    + side
                    + _ui_template(
                        "' style='overflow-wrap:anywhere'><summary>[[text:workspace_comparison.selected_condition_settings_and_inputs]]</summary><p>"
                    )
                    + html.escape(
                        _condition_label(
                            selected,
                            next(
                                i
                                for i, row in enumerate(conditions, 1)
                                if row["condition_id"] == condition
                            ),
                        )
                    )
                    + _ui_template("</p><p>[[text:workspace_comparison.frameworks]] ")
                    + html.escape(_condition_sources(selected, "frameworks"))
                    + _ui_template("</p><p>[[text:workspace_comparison.corpora]] ")
                    + html.escape(_condition_sources(selected, "corpora"))
                    + _ui_template(
                        "</p><p>[[text:workspace_comparison.similar_token_allowances_do_not_make_conditions_identical_retaine]]</p></details>"
                    )
                )
        if many.ranked(condition):
            form += (
                "<p class='fieldhint' data-condition-rule='"
                + side
                + "'>"
                + html.escape(many.CONDITION_MODES[condition])
                + _ui_text(
                    "workspace_comparison.applied_within_each_selected_model_and_the_active_source_filters"
                )
                + (
                    _ui_text(
                        "workspace_comparison.usable_response_rate_uses_saved_terminal_responses_not_attack_suc"
                    )
                    if condition == "__best_response__"
                    else _ui_text(
                        "workspace_comparison.only_fully_recorded_uniform_finite_settings_can_be_ranked_unknown"
                    )
                )
                + "</p>"
            )
        settings = indexed_settings(db, owner) if judges else {}
        judge_values = [
            (
                row["judge_id"],
                (_ui_text("workspace_comparison.condition") + f"{number}" + ": ")
                + _judge_name(row["judge_id"], settings.get(row["judge_id"])),
            )
            for number, row in enumerate(judges, 1)
        ]
        if many.broad(query) and model and condition and not judges:
            judge_values = [
                (
                    many.UNJUDGED,
                    _ui_text("workspace_comparison.no_indexed_judgments_show_coverage_only"),
                )
            ]
        if query.get(side + "_judge") not in {value for value, _label in judge_values}:
            if query.get(side + "_judge") and condition:
                form += (
                    "<p class='notice amber' data-judge-reset='"
                    + side
                    + _ui_template(
                        "'>[[text:workspace_comparison.the_previously_selected_judge_is_not_indexed_for_this_generation]]</p>"
                    )
                )
            query[side + "_judge"] = ""
        form += _select(
            side + "_judge",
            _ui_text("workspace_comparison.judging_condition"),
            judge_values,
            query.get(side + "_judge", ""),
            empty_hint=_ui_text("workspace_comparison.choose_a_generation_condition_first")
            if not condition
            else _ui_text(
                "workspace_comparison.no_indexed_judgments_for_this_model_and_generation_condition"
            ),
        )
        selected_judge = query.get(side + "_judge")
        if selected_judge and selected_judge != many.UNJUDGED:
            form += settings_html(selected_judge, settings.get(selected_judge), side=side)
        form += "</fieldset>"
    form += "</div>"
    try:
        facets = facet_choices(db, campaign, query)
    except ValueError:
        facets = {facet: set() for facet in FACETS}
    if facets is None:
        return _ui_template(
            "<p class='notice red'>[[text:workspace_comparison.comparison_filter_index_unavailable]]</p>"
        )
    form += "<div class='cols' style='margin-top:1rem'>"
    for facet, name in zip(FACETS, FILTERS):
        # Preserve a previously selected empty slice rather than substituting
        # another source when the selected model or condition changes.
        values = facets[facet] | ({query[name]} if query.get(name) else set())
        form += _select(
            name,
            _ui_label(facet),
            [(v, v) for v in sorted(values)],
            query.get(name, ""),
            optional=True,
        )
    form += _ui_template(
        "</div><p>[[text:workspace_comparison.choose_campaigns_and_models_then_generation_and_judging_condition]]</p><p>[[text:workspace_comparison.corpus_framework_and_modality_filters_apply_to_both_sides_and_rem]]</p><p>[[text:workspace_comparison.missing_a_judge_inspect_that_campaign_s_judging_tab_before_rerunn]]</p><button type='submit'>[[text:workspace_comparison.update_choices_compare]]</button></form>"
    )
    explanation = _ui_template(
        "<p>[[text:workspace_comparison.read_only_comparison_of_measured_indexed_inputs_matching_uses_the]]</p>"
    )
    if not all(query.get(key) for key in CHOICES):
        return form + explanation
    if many.broad(query):
        try:
            data = many.page_data(db, campaign, query, page=max(0, int(query.get("page", "0"))))
        except ValueError as exc:
            return form + explanation + "<p class='notice amber'>" + html.escape(str(exc)) + "</p>"
        return (
            form
            + explanation
            + (
                many.render(data, campaign, query)
                if data is not None
                else _ui_template(
                    "<p class='notice red'>[[text:workspace_comparison.comparison_index_unavailable]]</p>"
                )
            )
        )
    # Intermediate form updates can leave a previous model's condition selected.
    # Require an explicit valid choice instead of silently substituting another.
    try:
        page = max(0, int(query.get("page", "0")))
        rows = comparison_rows(db, campaign, query, offset=page * 12)
    except ValueError as exc:
        return form + explanation + "<p class='notice amber'>" + html.escape(str(exc)) + "</p>"
    if rows is None:
        return (
            form
            + explanation
            + _ui_template(
                "<p class='notice red'>[[text:workspace_comparison.comparison_index_unavailable]]</p>"
            )
        )
    groups = comparison_groups(rows)
    if not groups:
        return (
            form
            + explanation
            + _ui_template(
                "<p>[[text:workspace_comparison.no_measured_inputs_on_this_comparison_page]]</p>"
            )
        )
    saved = {key: query[key] for key in (*CHOICES, *FILTERS) if query.get(key)}
    export = base + "/figures/comparison.csv?" + urlencode({**saved, "page": page})
    content = (
        "<p id='campaign-exports'><a class='button ghost' data-campaign-export download='comparison.csv' href='"
        + html.escape(export, quote=True)
        + _ui_template(
            "'>[[text:workspace_comparison.download_this_page_s_counts]]</a></p><p id='campaign-export-status' role='status'></p>"
        )
    )
    content += render_groups([row for group in groups[:12] for row in group])
    for label, number in (
        (_ui_text("workspace_comparison.previous"), page - 1),
        (_ui_text("workspace_comparison.next"), page + 1),
    ):
        if number >= 0 and (number < page or len(groups) > 12):
            link = base + "?" + urlencode({"section": "compare", **saved, "page": number})
            content += (
                "<a class='button ghost' href='"
                + html.escape(link, quote=True)
                + "'>"
                + label
                + "</a> "
            )
    return form + explanation + "<div data-comparison-results>" + content + "</div>"


def render_groups(rows):
    content = ""
    for group in comparison_groups(rows):
        totals = {
            key: sum(row["count"] for row in group if row["match_status"] == key)
            for key in ("matched", "left_only", "right_only", "ambiguous")
        }
        title = " / ".join(group[0][key] for key in FACETS)
        content += (
            "<section style='margin-top:1.5rem;overflow-wrap:anywhere'><h3>"
            + html.escape(title)
            + "</h3>"
        )
        content += (
            _ui_template("<p>[[text:workspace_comparison.input_union]] ")
            + f"{sum(totals.values()):,}"
            + _ui_text("workspace_comparison.matched_copy")
            + f"{totals['matched']:,}"
            + _ui_text("workspace_comparison.left_only")
            + f"{totals['left_only']:,}"
            + _ui_text("workspace_comparison.right_only")
            + f"{totals['right_only']:,}"
            + _ui_text("workspace_comparison.ambiguous_shared_inputs")
            + f"{totals['ambiguous']:,}"
            + ".</p>"
        )
        content += coverage_chart(totals)
        paired = [row for row in group if row["match_status"] == "matched"]
        if not paired:
            content += _ui_template(
                "<p>[[text:workspace_comparison.no_unambiguous_matched_inputs_to_compare_in_this_source]]</p></section>"
            )
            continue
        content += judgment_matrix(paired)
        content += _ui_template(
            "<div class='scroll'><table><thead><tr><th>[[text:workspace_comparison.left_outcome]]</th><th>[[text:workspace_comparison.right_outcome]]</th><th>[[text:workspace_comparison.left_assessment]]</th><th>[[text:workspace_comparison.right_assessment]]</th><th>[[text:workspace_comparison.inputs]]</th></tr></thead><tbody>"
        )
        for row in paired:
            cells = []
            for side in ("left", "right"):
                trunc = row[side + "_truncated"]
                cells.append(
                    (row[side + "_outcome"] or _ui_text("workspace_comparison.not_indexed"))
                    + (
                        _ui_text("workspace_comparison.truncated")
                        if trunc == 1
                        else _ui_text("workspace_comparison.truncation_unknown")
                        if trunc is None
                        else ""
                    )
                )
            for side in ("left", "right"):
                cells.append(
                    (row[side + "_status"] or _ui_text("workspace_comparison.not_indexed"))
                    + (": " + row[side + "_label"] if row[side + "_label"] is not None else "")
                )
            content += (
                "<tr>"
                + "".join("<td>" + html.escape(value) + "</td>" for value in cells)
                + f"<td>{row['count']:,}</td></tr>"
            )
        content += "</tbody></table></div></section>"
    return content


def judgment_matrix(rows):
    """Recorded paired labels, with the same unambiguous input denominator as the table."""
    from collections import Counter

    paired = [row for row in rows if row["match_status"] == "matched"]
    matched = sum(row["count"] for row in paired)
    cells = Counter()
    for row in paired:
        if all(
            row[side + "_status"] == "valid" and row[side + "_label"] is not None
            for side in ("left", "right")
        ):
            cells[(str(row["left_label"]), str(row["right_label"]))] += row["count"]
    valid = sum(cells.values())
    note = (
        f"{valid:,}"
        + _ui_text("workspace_comparison.jointly_valid_judgments_out_of")
        + f"{matched:,}"
        + _ui_text("workspace_comparison.matched_inputs")
        + f"{matched - valid:,}"
        + _ui_text(
            "workspace_comparison.matched_inputs_lack_two_valid_labelled_judgments_and_are_not_plot"
        )
    )
    if not valid:
        return (
            _ui_template('<p class="note">[[text:workspace_comparison.no_paired_judgment_matrix]] ')
            + note
            + "</p>"
        )
    left = sorted({labels[0] for labels in cells})
    right = sorted({labels[1] for labels in cells})
    size, x0, y0 = 112, 168, 70
    width, height = x0 + size * len(right) + 20, y0 + size * len(left) + 16
    marks = [
        (
            "<text x='"
            + f"{x0}"
            + _ui_template("' y='20'>[[text:workspace_comparison.right_assessment]]</text>")
        ),
        _ui_template("<text x='8' y='20'>[[text:workspace_comparison.left_assessment]]</text>"),
    ]

    def short(label):
        return html.escape(label if len(label) <= 16 else label[:13] + "...")

    for column, label in enumerate(right):
        marks.append(
            f"<text x='{x0 + size * (column + 0.5)}' y='52' text-anchor='middle'>"
            f"<title>{html.escape(label)}</title>{short(label)}</text>"
        )
    peak = max(cells.values())
    for row, label in enumerate(left):
        y = y0 + row * size
        marks.append(
            f"<text x='{x0 - 12}' y='{y + size / 2 + 5}' text-anchor='end'>"
            f"<title>{html.escape(label)}</title>{short(label)}</text>"
        )
        for column, other in enumerate(right):
            count = cells[(label, other)]
            x = x0 + column * size
            desc = (
                _ui_text("workspace_comparison.left")
                + f"{label}"
                + _ui_text("workspace_comparison.right")
                + f"{other}"
                + ": "
                + f"{count}"
                + _ui_text("workspace_comparison.of")
                + f"{valid}"
                + _ui_text("workspace_comparison.jointly_valid_judgments")
            )
            marks.append(
                f"<g data-left-label='{html.escape(label, quote=True)}' "
                f"data-right-label='{html.escape(other, quote=True)}' data-count='{count}'>"
                f"<title>{html.escape(desc)}</title><rect x='{x}' y='{y}' width='{size - 4}' "
                f"height='{size - 4}' rx='6' style='fill:var(--accent);opacity:{0.08 + 0.22 * count / peak:.3f}'/>"
                f"<text x='{x + (size - 4) / 2}' y='{y + size / 2 + 5}' text-anchor='middle'>{count:,}</text></g>"
            )
    return (
        _ui_template(
            '<figure style="margin:1.25rem 0"><figcaption><strong>[[text:workspace_comparison.paired_judging_outcomes]]</strong><p class="note">'
        )
        + note
        + (
            _ui_template(
                "</p></figcaption><svg xmlns='http://www.w3.org/2000/svg' role='img' aria-label='[[attr:workspace_comparison.paired_judging_outcomes]]' class='judgment-matrix' viewBox='0 0 "
            )
            + f"{width}"
            + " "
            + f"{height}"
            + "' style='width:100%;max-width:"
            + f"{width}"
            + _ui_template(
                "px;height:auto;color:var(--ink)'><title>[[text:workspace_comparison.paired_judging_outcomes]]</title><desc>"
            )
        )
        + note
        + "</desc>"
        "<style>.judgment-matrix text{fill:currentColor;font-family:system-ui,sans-serif;font-size:14px}</style>"
        + "".join(marks)
        + "</svg></figure>"
    )


def coverage_chart(totals):
    """Composition of the input union, not a pooled safety or success score."""
    n = sum(totals.values())
    if not n:
        return ""
    from .workspace_charts import SERIES

    segments = []
    legend = []
    offset = 0
    for (key, caption), color in zip(
        (
            ("matched", _ui_text("workspace_comparison.matched")),
            ("left_only", _ui_text("workspace_comparison.left_only_2")),
            ("right_only", _ui_text("workspace_comparison.right_only_2")),
            ("ambiguous", _ui_text("workspace_comparison.ambiguous")),
        ),
        SERIES,
    ):
        count = totals[key]
        size = 100 * count / n
        if count:
            segments.append(
                f"<circle cx='90' cy='90' r='60' pathLength='100' fill='none' stroke='{color}' "
                f"stroke-width='24' stroke-dasharray='{size:.6f} {100 - size:.6f}' stroke-dashoffset='{-offset:.6f}' "
                f"transform='rotate(-90 90 90)' data-count='{count}'><title>{caption}: {count}/{n}</title></circle>"
            )
        legend.append(
            f"<li><span style='display:inline-block;width:.8em;height:.8em;background:{color}' aria-hidden='true'></span> {caption}: {count:,} ({size:.1f}%)</li>"
        )
        offset += size
    return (
        _ui_template(
            "<figure style='display:flex;flex-wrap:wrap;align-items:center;gap:1rem;margin:1rem 0'><svg xmlns='http://www.w3.org/2000/svg' role='img' aria-label='[[attr:workspace_comparison.matched_input_coverage]]' viewBox='0 0 180 180' width='180' height='180'><title>[[text:workspace_comparison.matched_input_coverage]]</title><desc>[[text:workspace_comparison.input_union_divided_into_matched_left_only_right_only_and_ambiguo]]</desc>"
        )
        + "".join(segments)
        + (
            "<text x='90' y='96' text-anchor='middle' fill='currentColor'>"
            + f"{n:,}"
            + _ui_template(" [[text:workspace_comparison.inputs_2]]</text></svg><figcaption><ul>")
        )
        + "".join(legend)
        + "</ul></figcaption></figure>"
    )


def comparison_page(db, campaign, query):
    return (
        "<div id='campaign-comparison'><p data-comparison-feedback role='status' aria-live='polite'></p>"
        "<div data-comparison-body>"
        + _comparison_body(db, campaign, query)
        + "</div></div>"
        + EXPORT_SCRIPT
        + COMPARISON_SCRIPT
    )


COMPARISON_SCRIPT = _ui_template("""<script>(()=>{
const root=document.getElementById('campaign-comparison');if(!root)return;
const body=root.querySelector('[data-comparison-body]'),feedback=root.querySelector('[data-comparison-feedback]');
const descendants={right_campaign:['right_model','right_condition','right_judge'],
left_model:['left_condition','left_judge'],right_model:['right_condition','right_judge'],
left_condition:['left_judge'],right_condition:['right_judge']};let loading=false;
async function update(form,changed){if(loading)return;
if(changed&&form.elements.namedItem(changed)?.selectedOptions?.[0]?.defaultSelected)return;
loading=true;
const judgeName=changed.endsWith('_condition')?changed.replace('_condition','_judge'):'';
const retainedJudge=judgeName?form.elements.namedItem(judgeName)?.value:'';
for(const name of descendants[changed]||[]){const field=form.elements.namedItem(name);
if(field){field.value='';field.disabled=true;}}
const url=new URL(form.action,location.href),values=new FormData(form);
if(retainedJudge)values.set(judgeName,retainedJudge);
url.search=new URLSearchParams(values).toString();
body.querySelectorAll('[data-comparison-results]').forEach(e=>e.hidden=true);
feedback.textContent=[[js:workspace_comparison.loading_comparison_choices]];feedback.className='note';
const end=window.uraBusy.begin([[js:workspace_comparison.loading_comparison_choices]]);
const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),30000);
try{const response=await fetch(url,{signal:abort.signal});
if(!response.ok)throw new Error([[js:workspace_comparison.comparison_request_failed_http]]+response.status+[[js:workspace_comparison.use_update_choices_compare_to_retry]]);
const doc=new DOMParser().parseFromString(await response.text(),'text/html');
const replacement=doc.querySelector('[data-comparison-body]');
if(!replacement||!replacement.querySelector('[data-comparison-form]')||replacement.querySelector('.notice.red'))
throw new Error([[js:workspace_comparison.comparison_choices_are_unavailable_use_update_choices_compare_to]]);
body.replaceChildren(...replacement.childNodes);history.replaceState(null,'',url.pathname+url.search+location.hash);
feedback.textContent=[[js:workspace_comparison.choices_updated_select_the_next_available_field_or_inspect_the_co]];
}catch(error){feedback.className=\"notice amber\";feedback.textContent=error.name===\"AbortError\"?
[[js:workspace_comparison.comparison_request_timed_out_use_update_choices_compare_to_retry]]:
error.message+[[js:workspace_comparison.check_the_connection_and_use_update_choices_compare_to_retry]];
}finally{clearTimeout(timer);loading=false;end();
if(changed){const field=body.querySelector('[name=\"'+changed+'\"]');if(field&&!field.disabled)field.focus({preventScroll:true});}}
}
root.addEventListener('change',event=>{const form=event.target.closest('[data-comparison-form]');
if(form&&event.target.tagName==='SELECT')update(form,event.target.name);});
root.addEventListener('submit',event=>{if(!event.target.matches('[data-comparison-form]'))return;
event.preventDefault();update(event.target,'');});
})();</script>""")
