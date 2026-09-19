"""Read-only, exact-input comparisons of explicitly selected indexed conditions."""
from __future__ import annotations

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


def comparison_rows(db, campaign, query, *, offset=0, permit_missing_judges=False, all_facets=False):
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
        if not permit_missing_judges:
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
    if all_facets:
        return db._query(sql + ' SELECT * FROM counts ORDER BY ' + fields, params)
    sql += ", ranked AS (SELECT *,DENSE_RANK() OVER(ORDER BY corpus,framework,modality) AS facet FROM counts)"
    sql += " SELECT * FROM ranked WHERE facet>? AND facet<=? ORDER BY " + fields
    return db._query(sql, (*params, offset, offset + 13))


def comparison_groups(rows):
    return [list(values) for _key, values in groupby(rows, key=lambda row: tuple(row[key] for key in FACETS))]


def comparison_csv(rows, campaign, query):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    fields = ("left_campaign", *CHOICES, "left_condition_selection", "right_condition_selection", *FILTERS, *FACETS, *FIELDS, "count")
    writer.writerow(fields)
    for row in rows:
        value = {"left_campaign": campaign, **{key: query[key] for key in CHOICES},
                 **{side+'_condition_selection':many.CONDITION_MODES.get(query[side+'_condition'],'Explicit condition')
                    for side in ('left','right')}, **{key: query.get(key, "") for key in FILTERS}, **dict(row)}
        writer.writerow(["'" + value[key] if isinstance(value[key], str) and value[key].startswith(("=", "+", "-", "@"))
                         else value[key] for key in fields])
    return stream.getvalue().encode("utf-8-sig")


def _select(name, label, values, selected, *, optional=False, empty_hint=''):
    empty = not values and not optional
    prompt = empty_hint if empty and empty_hint else 'All' if optional else 'Choose ' + label.lower()
    options = "<option value=''>" + html.escape(prompt) + "</option>"
    options += "".join("<option value='" + html.escape(value, quote=True) + "'"
        + (" selected" if value == selected else "") + ">" + html.escape(text) + "</option>" for value, text in values)
    hint = "<small class='fieldhint' id='" + name + "-help'>" + html.escape(prompt) + '</small>' if empty else ''
    return ("<label class='campaign-field'>" + html.escape(label) + "<select name='" + name + "'"
        + (" disabled aria-describedby='" + name + "-help'" if empty else '') + '>' + options + '</select>' + hint + '</label>')


def facet_choices(db, campaign, query):
    values = {facet: set() for facet in FACETS}
    for side, owner in (("left", campaign), ("right", query.get("right_campaign", ""))):
        if not owner or not query.get(side + "_model") or not query.get(side + "_condition"):
            continue
        db.require_workspace(owner)
        condition = query[side + '_condition']
        if condition in many.CONDITION_MODES:
            condition = many.ALL
        rows = db._query("SELECT DISTINCT a.corpus,a.framework,a.modality FROM campaign_assignments a "
            "LEFT JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "AND r.assignment_id=a.assignment_id WHERE a.campaign_id=? AND (?='*' OR a.model=?) "
            "AND (?='*' OR COALESCE(r.condition_id,a.condition_id)=?) AND a.evidence_class='measured'",
            (owner, query[side + "_model"], query[side + "_model"], condition, condition))
        if rows is None:
            return None
        for row in rows:
            for facet in FACETS:
                values[facet].add(row[facet])
    return values


def _condition_tokens(row, prefix):
    low, high = row[prefix + '_min'], row[prefix + '_max']
    def tokens(value):
        return 'native maximum' if value == -1 else f'{value:,}'
    value = 'unknown' if low is None else tokens(low) + ((' to ' + tokens(high)) if high != low else '')
    if 0 < row[prefix + '_known'] < row['assigned']:
        value += ' (partly unknown)'
    return value


def _condition_sources(row, key):
    return ', '.join(sorted((row[key] or '').split(','))) or 'unknown'


def _condition_label(row, number):
    return (f"Condition {number}: {_condition_sources(row, 'modalities')}; "
        f"context {_condition_tokens(row, 'context')}; output allowance {_condition_tokens(row, 'output')}; "
        f"{row['assigned']:,} assignments")


def _comparison_body(db, campaign, query):
    query = many.normalize(query)
    base = "/campaigns/" + campaign
    campaigns = db.workspaces()
    if campaigns is None:
        return "<p class='notice red'>Campaign index unavailable.</p>"
    owners = {row["campaign_id"]: row["name"] for row in campaigns}
    form = "<form data-comparison-form method='get' action='" + base + "'><input type='hidden' name='section' value='compare'><div class='cols'>"
    for side, owner in (("left", campaign), ("right", query.get("right_campaign", ""))):
        form += "<fieldset class='comparison-condition'><legend>" + side.title() + " condition</legend>"
        if side == "right":
            form += _select("right_campaign", "Campaign", list(owners.items()), owner)
        else:
            form += "<p>" + html.escape(owners[campaign]) + "</p>"
        model, condition = query.get(side + "_model", ""), query.get(side + "_condition", "")
        models = db.workspace_result_models(owner) if owner in owners else []
        if models is not None and ((model == many.ALL and not models)
                or (model != many.ALL and model not in {row['model'] for row in models})):
            model = query[side + '_model'] = ''
        conditions = db.workspace_result_conditions(owner, model=model, measured_only=True) if owner in owners and model and model!=many.ALL else []
        if conditions is not None and model != many.ALL and condition not in (
                {row['condition_id'] for row in conditions} | (set(many.CONDITION_MODES) if conditions else set())):
            condition = query[side + '_condition'] = ''
        judges = many.scope_judges(db, owner, model, condition, query=query) if owner in owners and model and condition else []
        if models is None or conditions is None or judges is None:
            return "<p class='notice red'>Comparison selection index unavailable.</p>"
        model_values = ([(many.ALL,'All models')] if models else []) + [(row['model'],many.model_label(row['model'])) for row in models]
        form += _select(side + "_model", "Model", model_values, model,
            empty_hint='Choose a campaign first' if owner not in owners else 'No indexed model results in this campaign')
        if model==many.ALL:
            form += _select(side+'_condition','Generation condition',list(many.CONDITION_MODES.items()),condition)
            form += ("<p class='fieldhint' data-comparison-scope='" + side + "'>Only " + html.escape(owners[owner])
                + ": all indexed models. " + ('Generation conditions: all measured conditions, compared separately. '
                'No latest/best response is chosen and scores are not pooled. ' if condition==many.ALL else
                'The selected condition rule is applied independently per model; tied conditions remain separate and scores are not pooled. ')
                + "Models without eligible measured conditions are identified below.</p>")
        else:
            form += _select(side + "_condition", "Generation condition",
            (list(many.CONDITION_MODES.items()) if conditions else []) + [
            (row["condition_id"], _condition_label(row, number))
            for number, row in enumerate(conditions, 1)], condition,
            empty_hint='Choose a model first' if not model else 'No indexed generation conditions for this model')
            if model:
                form += ("<p class='fieldhint' data-comparison-scope='" + side + "' style='overflow-wrap:anywhere'>Only "
                    + html.escape(owners[owner]) + ' / ' + html.escape(many.model_label(model))
                    + f": {len(conditions)} measured generation conditions. Condition numbers are local to this model in this campaign.</p>")
                if condition == many.ALL:
                    form += ("<p class='fieldhint' data-all-conditions='" + side + "'>All generation conditions for this model "
                        "are compared separately. No other model is included on this side; scores are not pooled "
                        "and no latest/best response is chosen.</p>")
            selected = next((row for row in conditions if row['condition_id'] == condition), None)
            if selected is not None:
                form += ("<details data-condition-details='" + side + "' style='overflow-wrap:anywhere'><summary>Selected condition: settings and inputs</summary><p>"
                    + html.escape(_condition_label(selected, next(i for i, row in enumerate(conditions, 1) if row['condition_id'] == condition)))
                    + '</p><p>Frameworks: ' + html.escape(_condition_sources(selected, 'frameworks'))
                    + '</p><p>Corpora: ' + html.escape(_condition_sources(selected, 'corpora'))
                    + '</p><p>Similar token allowances do not make conditions identical. Retained runtime and execution settings can differ; '
                    'these conditions are not merged.</p></details>')
        if many.ranked(condition):
            form += ("<p class='fieldhint' data-condition-rule='"+side+"'>"+html.escape(many.CONDITION_MODES[condition])
                +': applied within each selected model and the active source filters. All ties remain separate. '
                +('Usable-response rate uses saved terminal responses, not attack success or a safety verdict. This is a post-hoc selection; '
                  'inspect the displayed numerator, denominator and assigned count.' if condition=='__best_response__' else
                  'Only fully recorded, uniform finite settings can be ranked. Unknown, mixed or native-maximum settings are disclosed as unranked.')+'</p>')
        settings = indexed_settings(db, owner) if judges else {}
        judge_values = [(row['judge_id'],f'Condition {number}: '+_judge_name(row['judge_id'], settings.get(row['judge_id'])))
            for number,row in enumerate(judges,1)]
        if many.broad(query) and model and condition and not judges:
            judge_values = [(many.UNJUDGED,'No indexed judgments - show coverage only')]
        if query.get(side + '_judge') not in {value for value, _label in judge_values}:
            if query.get(side + '_judge') and condition:
                form += ("<p class='notice amber' data-judge-reset='" + side + "'>The previously selected judge is not indexed "
                    "for this generation condition. Choose an available judging condition; no other judge was substituted.</p>")
            query[side + '_judge'] = ''
        form += _select(side + "_judge", "Judging condition", judge_values, query.get(side + "_judge", ""),
            empty_hint='Choose a generation condition first' if not condition else
            'No indexed judgments for this model and generation condition')
        selected_judge = query.get(side + '_judge')
        if selected_judge and selected_judge != many.UNJUDGED:
            form += settings_html(selected_judge, settings.get(selected_judge), side=side)
        form += "</fieldset>"
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
    form += ("</div><p>Choose campaigns and models, then generation and judging conditions. "
        "Dependent choices load automatically when you change a selection. Empty fields explain their prerequisite. "
        "All models is available on either side. For one model, choose All generation conditions to include "
        "all of its measured settings. Highest/lowest output allowance, largest/smallest context and highest usable-response rate "
        "are optional rules on either side, including All models. There is no universal optimal condition. Their generation conditions are compared separately; "
        "historical and corrected settings are not combined. One All selection gives one-to-many comparisons; "
        "All on both sides gives model/condition pairs, twelve per page. Changing these controls starts no jobs.</p>"
        "<p>Corpus, framework and modality filters apply to both sides and remain in exported counts.</p>"
        "<p>Missing a judge? Inspect that campaign's Judging tab before rerunning anything. "
        "Judges are offered within the selected campaign/model/condition scope. With All, the selected judge may not "
        "cover every pair; those assessments stay Not indexed.</p>"
        "<button type='submit'>Update choices / compare</button></form>")
    explanation = ("<p>Read-only comparison of measured, indexed inputs. Matching uses the exact retained input identity "
        "and the same corpus, framework and modality. Multiple assignments for an input are ambiguous and excluded "
        "from paired outcomes; no newest or best answer is selected. These are descriptive paired outcome counts, "
        "not pooled safety rates, independent-sample counts or a causal model ranking. "
        "Not indexed does not establish that a request or judgment was never attempted.</p>")
    if not all(query.get(key) for key in CHOICES):
        return form + explanation
    if many.broad(query):
        try:
            data = many.page_data(db,campaign,query,page=max(0,int(query.get('page','0'))))
        except ValueError as exc:
            return form+explanation+"<p class='notice amber'>"+html.escape(str(exc))+'</p>'
        return form+explanation+(many.render(data,campaign,query) if data is not None else
            "<p class='notice red'>Comparison index unavailable.</p>")
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
        "<p id='campaign-export-status' role='status'></p>")
    content += render_groups([row for group in groups[:12] for row in group])
    for label, number in (("Previous", page - 1), ("Next", page + 1)):
        if number >= 0 and (label == "Previous" or len(groups) > 12):
            link = base + "?" + urlencode({"section": "compare", **saved, "page": number})
            content += "<a class='button ghost' href='" + html.escape(link, quote=True) + "'>" + label + "</a> "
    return form + explanation + "<div data-comparison-results>" + content + '</div>'


def render_groups(rows):
    content = ''
    for group in comparison_groups(rows):
        totals = {key: sum(row["count"] for row in group if row["match_status"] == key)
                  for key in ("matched", "left_only", "right_only", "ambiguous")}
        title = " / ".join(group[0][key] for key in FACETS)
        content += "<section style='margin-top:1.5rem;overflow-wrap:anywhere'><h3>" + html.escape(title) + "</h3>"
        content += (f"<p>Input union: {sum(totals.values()):,}; matched: {totals['matched']:,}; "
            f"left only: {totals['left_only']:,}; right only: {totals['right_only']:,}; ambiguous shared inputs: {totals['ambiguous']:,}.</p>")
        content += coverage_chart(totals)
        paired = [row for row in group if row["match_status"] == "matched"]
        if not paired:
            content += '<p>No unambiguous matched inputs to compare in this source.</p></section>'
            continue
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
    return content


def coverage_chart(totals):
    """Composition of the input union, not a pooled safety or success score."""
    n = sum(totals.values())
    if not n:
        return ''
    from .workspace_charts import SERIES
    segments = []; legend = []; offset = 0
    for (key, caption), color in zip((('matched','Matched'),('left_only','Left only'),
            ('right_only','Right only'),('ambiguous','Ambiguous')), SERIES):
        count = totals[key]; size = 100 * count/n
        if count:
            segments.append(f"<circle cx='90' cy='90' r='60' pathLength='100' fill='none' stroke='{color}' "
                f"stroke-width='24' stroke-dasharray='{size:.6f} {100-size:.6f}' stroke-dashoffset='{-offset:.6f}' "
                f"transform='rotate(-90 90 90)' data-count='{count}'><title>{caption}: {count}/{n}</title></circle>")
        legend.append(f"<li><span style='display:inline-block;width:.8em;height:.8em;background:{color}' aria-hidden='true'></span> {caption}: {count:,} ({size:.1f}%)</li>")
        offset += size
    return ("<figure style='display:flex;flex-wrap:wrap;align-items:center;gap:1rem;margin:1rem 0'>"
        "<svg xmlns='http://www.w3.org/2000/svg' role='img' aria-label='Matched-input coverage' viewBox='0 0 180 180' width='180' height='180'>"
        "<title>Matched-input coverage</title><desc>Input union divided into matched, left-only, right-only and ambiguous inputs. This is coverage, not model safety.</desc>"
        + ''.join(segments) + f"<text x='90' y='96' text-anchor='middle' fill='currentColor'>{n:,} inputs</text></svg>"
        '<figcaption><ul>'+''.join(legend)+'</ul></figcaption></figure>')


def comparison_page(db, campaign, query):
    return ("<div id='campaign-comparison'><p data-comparison-feedback role='status' aria-live='polite'></p>"
        "<div data-comparison-body>" + _comparison_body(db, campaign, query)
        + '</div></div>' + EXPORT_SCRIPT + COMPARISON_SCRIPT)


COMPARISON_SCRIPT = """<script>(()=>{
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
feedback.textContent='Loading comparison choices...';feedback.className='note';
const end=window.uraBusy.begin('Loading comparison choices...');
const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),30000);
try{const response=await fetch(url,{signal:abort.signal});
if(!response.ok)throw new Error('Comparison request failed (HTTP '+response.status+'). Use Update choices / compare to retry.');
const doc=new DOMParser().parseFromString(await response.text(),'text/html');
const replacement=doc.querySelector('[data-comparison-body]');
if(!replacement||!replacement.querySelector('[data-comparison-form]')||replacement.querySelector('.notice.red'))
throw new Error('Comparison choices are unavailable. Use Update choices / compare to retry.');
body.replaceChildren(...replacement.childNodes);history.replaceState(null,'',url.pathname+url.search+location.hash);
feedback.textContent='Choices updated. Select the next available field or inspect the comparison below.';
}catch(error){feedback.className='notice amber';feedback.textContent=error.name==='AbortError'?
'Comparison request timed out. Use Update choices / compare to retry.':
error.message+' Check the connection and use Update choices / compare to retry.';
}finally{clearTimeout(timer);loading=false;end();
if(changed){const field=body.querySelector('[name="'+changed+'"]');if(field&&!field.disabled)field.focus({preventScroll:true});}}
}
root.addEventListener('change',event=>{const form=event.target.closest('[data-comparison-form]');
if(form&&event.target.tagName==='SELECT')update(form,event.target.name);});
root.addEventListener('submit',event=>{if(!event.target.matches('[data-comparison-form]'))return;
event.preventDefault();update(event.target,'');});
})();</script>"""
