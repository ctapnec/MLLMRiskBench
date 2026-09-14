"""Read-only, exact-input comparisons of explicitly selected indexed conditions."""
from __future__ import annotations

import csv
import html
import io
from itertools import groupby
from urllib.parse import urlencode

from .workspace_judging_charts import _judge_name
from .workspace_charts import EXPORT_SCRIPT

FACETS = ("corpus", "framework", "modality")
FIELDS = ("match_status", "left_outcome", "right_outcome", "left_truncated", "right_truncated",
          "left_status", "left_label", "right_status", "right_label")
CHOICES = ("left_model", "left_condition", "left_judge", "right_campaign",
           "right_model", "right_condition", "right_judge")
FILTERS = tuple("compare_" + facet for facet in FACETS)


def judge_choices(db, campaign, model, condition):
    return db._query(
        "SELECT DISTINCT j.judge_id FROM campaign_assignments a "
        "JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
        "AND r.assignment_id=a.assignment_id "
        "JOIN campaign_judgments j ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
        "WHERE a.campaign_id=? AND a.model=? AND COALESCE(r.condition_id,a.condition_id)=? AND a.evidence_class='measured' "
        "ORDER BY j.judge_id", (campaign, model, condition))


def comparison_rows(db, campaign, query, *, offset=0):
    """Return thirteen whole source facets, the last for pagination lookahead.

    Multiple assignments for one input are ambiguous, never a Cartesian pair
    or an invitation to select the newest/best answer. Only measured evidence
    and the assignment-selected response are considered. Missing judgments
    mean not indexed, not necessarily scheduled work.
    """
    if type(offset) is not int or offset < 0 or any(not query.get(key) for key in CHOICES):
        raise ValueError("Select both models, generation conditions and judging conditions")
    sides, params = [], []
    for side, owner in (("left", campaign), ("right", query["right_campaign"])):
        db.require_workspace(owner)
        judges = judge_choices(db, owner, query[side + "_model"], query[side + "_condition"])
        if judges is None:
            return None
        if query[side + "_judge"] not in {row["judge_id"] for row in judges}:
            raise ValueError("Select an indexed judging condition for each model and generation condition")
        filters = "".join(" AND a." + facet + "=?" for facet, name in zip(FACETS, FILTERS) if query.get(name))
        sides.append(side + "_inputs AS (SELECT a.input_id,a.corpus,a.framework,a.modality,COUNT(*) AS n,"
            "CASE WHEN COUNT(*)=1 THEN MAX(r.outcome) END AS outcome,"
            "CASE WHEN COUNT(*)=1 THEN MAX(r.truncated) END AS truncated,"
            "CASE WHEN COUNT(*)=1 THEN MAX(j.status) END AS status,"
            "CASE WHEN COUNT(*)=1 THEN MAX(j.label) END AS label "
            "FROM campaign_assignments a LEFT JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "AND r.assignment_id=a.assignment_id "
            "LEFT JOIN campaign_judgments j ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
            "AND j.judge_id=? WHERE a.campaign_id=? AND a.model=? AND COALESCE(r.condition_id,a.condition_id)=? "
            "AND a.evidence_class='measured'" + filters + " GROUP BY a.input_id,a.corpus,a.framework,a.modality)")
        params.extend((query[side + "_judge"], owner, query[side + "_model"], query[side + "_condition"]))
        params.extend(query[name] for name in FILTERS if query.get(name))
    keys = "input_id,corpus,framework,modality"
    fields = ",".join(FACETS + FIELDS)
    sql = "WITH " + ",".join(sides) + ", input_keys AS (SELECT " + keys + " FROM left_inputs UNION SELECT " + keys + " FROM right_inputs), paired AS (SELECT k.corpus,k.framework,k.modality,"
    sql += ("CASE WHEN l.n IS NULL THEN 'right_only' WHEN r.n IS NULL THEN 'left_only' "
        "WHEN l.n>1 OR r.n>1 THEN 'ambiguous' ELSE 'matched' END AS match_status,")
    sql += ",".join(f"{alias}.{field} AS {side}_{field}" for side, alias in (("left", "l"), ("right", "r"))
                    for field in ("outcome", "truncated", "status", "label"))
    sql += " FROM input_keys k LEFT JOIN left_inputs l USING(" + keys + ") LEFT JOIN right_inputs r USING(" + keys + "))"
    sql += ", counts AS (SELECT " + fields + ",COUNT(*) AS count FROM paired GROUP BY " + fields + ")"
    sql += ", ranked AS (SELECT *,DENSE_RANK() OVER(ORDER BY corpus,framework,modality) AS facet FROM counts)"
    sql += " SELECT * FROM ranked WHERE facet>? AND facet<=? ORDER BY " + fields
    return db._query(sql, (*params, offset, offset + 13))


def comparison_groups(rows):
    return [list(values) for _key, values in groupby(rows, key=lambda row: tuple(row[key] for key in FACETS))]


def comparison_csv(rows, campaign, query):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    fields = ("left_campaign", *CHOICES, *FILTERS, *FACETS, *FIELDS, "count")
    writer.writerow(fields)
    for row in rows:
        value = {"left_campaign": campaign, **{key: query[key] for key in CHOICES},
                 **{key: query.get(key, "") for key in FILTERS}, **dict(row)}
        writer.writerow(["'" + value[key] if isinstance(value[key], str) and value[key].startswith(("=", "+", "-", "@"))
                         else value[key] for key in fields])
    return stream.getvalue().encode("utf-8-sig")


def _select(name, label, values, selected, *, optional=False):
    options = "<option value=''>" + ("All" if optional else "Choose " + html.escape(label.lower())) + "</option>"
    options += "".join("<option value='" + html.escape(value, quote=True) + "'"
        + (" selected" if value == selected else "") + ">" + html.escape(text) + "</option>" for value, text in values)
    return "<label class='campaign-field'>" + html.escape(label) + "<select name='" + name + "'>" + options + "</select></label>"


def facet_choices(db, campaign, query):
    values = {facet: set() for facet in FACETS}
    for side, owner in (("left", campaign), ("right", query.get("right_campaign", ""))):
        if not owner or not query.get(side + "_model") or not query.get(side + "_condition"):
            continue
        db.require_workspace(owner)
        rows = db._query("SELECT DISTINCT a.corpus,a.framework,a.modality FROM campaign_assignments a "
            "LEFT JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "AND r.assignment_id=a.assignment_id WHERE a.campaign_id=? AND a.model=? "
            "AND COALESCE(r.condition_id,a.condition_id)=? AND a.evidence_class='measured'",
            (owner, query[side + "_model"], query[side + "_condition"]))
        if rows is None:
            return None
        for row in rows:
            for facet in FACETS:
                values[facet].add(row[facet])
    return values


def comparison_page(db, campaign, query):
    base = "/campaigns/" + campaign
    campaigns = db.workspaces()
    if campaigns is None:
        return "<p class='notice red'>Campaign index unavailable.</p>"
    owners = {row["campaign_id"]: row["name"] for row in campaigns}
    form = "<form method='get' action='" + base + "'><input type='hidden' name='section' value='compare'><div class='cols'>"
    for side, owner in (("left", campaign), ("right", query.get("right_campaign", ""))):
        form += "<fieldset class='comparison-condition'><legend>" + side.title() + " condition</legend>"
        if side == "right":
            form += _select("right_campaign", "Campaign", list(owners.items()), owner)
        else:
            form += "<p>" + html.escape(owners[campaign]) + "</p>"
        model, condition = query.get(side + "_model", ""), query.get(side + "_condition", "")
        models = db.workspace_result_models(owner) if owner in owners else []
        conditions = db.workspace_result_conditions(owner, model=model) if owner in owners and model else []
        judges = judge_choices(db, owner, model, condition) if owner in owners and model and condition else []
        if models is None or conditions is None or judges is None:
            return "<p class='notice red'>Comparison selection index unavailable.</p>"
        form += _select(side + "_model", "Model", [(row["model"], row["model"]) for row in models], model)
        form += _select(side + "_condition", "Generation condition", [
            (row["condition_id"], f"Condition {number}: {row['assigned']:,} assignments; output allowance "
                + ("unknown" if row["output_min"] is None else str(row["output_min"])
                   + (" to " + str(row["output_max"]) if row["output_min"] != row["output_max"] else "")))
            for number, row in enumerate(conditions, 1)], condition)
        form += _select(side + "_judge", "Judging condition", [(row["judge_id"], f"Condition {number}: " + _judge_name(row["judge_id"]))
            for number, row in enumerate(judges, 1)], query.get(side + "_judge", "")) + "</fieldset>"
    form += "</div>"
    try:
        facets = facet_choices(db, campaign, query)
    except ValueError:
        facets = {facet: set() for facet in FACETS}
    if facets is None:
        return "<p class='notice red'>Comparison filter index unavailable.</p>"
    form += "<div class='cols' style='margin-top:1rem'>"
    for facet, name in zip(FACETS, FILTERS):
        # Preserve a previously selected empty slice rather than substituting
        # another source when the selected model or condition changes.
        values = facets[facet] | ({query[name]} if query.get(name) else set())
        form += _select(name, facet.title(), [(v, v) for v in sorted(values)], query.get(name, ""), optional=True)
    form += ("</div><p>Choose campaigns and models, then update the choices to select generation and judging conditions. "
        "Each side has one explicit condition; historical and corrected settings are not combined.</p>"
        "<p>Corpus, framework and modality filters apply to both sides and remain in exported counts.</p>"
        "<button type='submit'>Update choices / compare</button></form>")
    explanation = ("<p>Read-only comparison of measured, indexed inputs. Matching uses the exact retained input identity "
        "and the same corpus, framework and modality. Multiple assignments for an input are ambiguous and excluded "
        "from paired outcomes; no newest or best answer is selected. These are descriptive paired outcome counts, "
        "not pooled safety rates, independent-sample counts or a causal model ranking. "
        "Not indexed does not establish that a request or judgment was never attempted.</p>")
    if not all(query.get(key) for key in CHOICES):
        return form + explanation
    # Intermediate form updates can leave a previous model's condition selected.
    # Require an explicit valid choice instead of silently substituting another.
    try:
        page = max(0, int(query.get("page", "0")))
        rows = comparison_rows(db, campaign, query, offset=page * 12)
    except ValueError as exc:
        return form + explanation + "<p class='notice amber'>" + html.escape(str(exc)) + "</p>"
    if rows is None:
        return form + explanation + "<p class='notice red'>Comparison index unavailable.</p>"
    groups = comparison_groups(rows)
    if not groups:
        return form + explanation + "<p>No measured inputs on this comparison page.</p>"
    saved = {key: query[key] for key in (*CHOICES, *FILTERS) if query.get(key)}
    export = base + "/figures/comparison.csv?" + urlencode({**saved, "page": page})
    content = ("<p id='campaign-exports'><a class='button ghost' data-campaign-export download='comparison.csv' href='"
        + html.escape(export, quote=True) + "'>Download this page's counts</a></p>"
        "<p id='campaign-export-status' role='status'></p>" + EXPORT_SCRIPT)
    for group in groups[:12]:
        totals = {key: sum(row["count"] for row in group if row["match_status"] == key)
                  for key in ("matched", "left_only", "right_only", "ambiguous")}
        title = " / ".join(group[0][key] for key in FACETS)
        content += "<section style='margin-top:1.5rem;overflow-wrap:anywhere'><h3>" + html.escape(title) + "</h3>"
        content += (f"<p>Input union: {sum(totals.values()):,}; matched: {totals['matched']:,}; "
            f"left only: {totals['left_only']:,}; right only: {totals['right_only']:,}; ambiguous shared inputs: {totals['ambiguous']:,}.</p>")
        paired = [row for row in group if row["match_status"] == "matched"]
        content += "<div class='scroll'><table><thead><tr><th>Left outcome</th><th>Right outcome</th><th>Left assessment</th><th>Right assessment</th><th>Inputs</th></tr></thead><tbody>"
        for row in paired:
            cells = []
            for side in ("left", "right"):
                trunc = row[side + "_truncated"]
                cells.append((row[side + "_outcome"] or "Not indexed") + ("; truncated" if trunc == 1 else "; truncation unknown" if trunc is None else ""))
            for side in ("left", "right"):
                cells.append((row[side + "_status"] or "Not indexed") + (": " + row[side + "_label"] if row[side + "_label"] is not None else ""))
            content += "<tr>" + "".join("<td>" + html.escape(value) + "</td>" for value in cells) + f"<td>{row['count']:,}</td></tr>"
        content += "</tbody></table></div></section>"
    for label, number in (("Previous", page - 1), ("Next", page + 1)):
        if number >= 0 and (label == "Previous" or len(groups) > 12):
            link = base + "?" + urlencode({"section": "compare", **saved, "page": number})
            content += "<a class='button ghost' href='" + html.escape(link, quote=True) + "'>" + label + "</a> "
    return form + explanation + content
