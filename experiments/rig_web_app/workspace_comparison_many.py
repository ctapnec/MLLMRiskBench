"""Paginated model/condition pairs; never pool different generation settings."""
from __future__ import annotations

import html
import re
from fractions import Fraction
from itertools import groupby, islice, product
from urllib.parse import urlencode

ALL = '*'
UNJUDGED = '__not_indexed__'
PAGE_SIZE = 12
CONDITION_MODES = {
    ALL: 'All generation conditions',
    '__max_output__': 'Highest output allowance',
    '__min_output__': 'Lowest output allowance',
    '__max_context__': 'Largest recorded context',
    '__min_context__': 'Smallest recorded context',
    '__best_response__': 'Highest usable-response rate',
}


def ranked(condition):
    return condition in CONDITION_MODES and condition != ALL


def model_label(identity):
    """Readable labels only; stored identities and exported fields stay exact."""
    match = re.fullmatch(r'(.+)@(?:sha256:)?([0-9a-f]{40}|[0-9a-f]{64})',identity)
    return match[1]+' (revision '+match[2][:8]+')' if match else identity


def normalize(query):
    query = dict(query)
    for side in ('left', 'right'):
        if query.get(side+'_model') == ALL and query.get(side+'_condition') not in CONDITION_MODES:
            query[side+'_condition'] = ALL
    return query


def broad(query):
    return any(query.get(side+'_model') == ALL or query.get(side+'_condition') in CONDITION_MODES
               for side in ('left','right'))


def scope_judges(db, owner, model, condition, *, selected_units=None, query=None):
    """Offer the union, retaining models without this judge in the comparison."""
    filters, params = "AND (?='*' OR COALESCE(r.condition_id,a.condition_id)=?) ", [owner,model,model,condition,condition]
    if ranked(condition):
        selected_units = units(db,owner,model,condition,query=query) if selected_units is None else selected_units
        if selected_units is None:
            return None
        if not selected_units:
            return []
        filters = 'AND ('+' OR '.join('(a.model=? AND COALESCE(r.condition_id,a.condition_id)=?)' for _ in selected_units)+') '
        params = [owner,model,model]+[v for row in selected_units for v in (row['model'],row['condition_id'])]
    return db._query(
        "SELECT DISTINCT j.judge_id FROM campaign_assignments a "
        "JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
        "AND r.assignment_id=a.assignment_id JOIN campaign_judgments j "
        "ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
        "WHERE a.campaign_id=? AND a.evidence_class='measured' "
        "AND (?='*' OR a.model=?) " + filters + "ORDER BY j.judge_id", params)


def unit_scope(db, owner, model, condition, *, query=None):
    sql = (
        "SELECT a.model,COALESCE(r.condition_id,a.condition_id) AS condition_id,"
        "MIN(json_extract(r.details,'$.output_allowance')) AS output_min,"
        "MAX(json_extract(r.details,'$.output_allowance')) AS output_max,"
        "COUNT(json_extract(r.details,'$.output_allowance')) AS output_known,"
        "MIN(json_extract(r.details,'$.context_tokens')) AS context_min,"
        "MAX(json_extract(r.details,'$.context_tokens')) AS context_max,"
        "COUNT(json_extract(r.details,'$.context_tokens')) AS context_known,"
        "COUNT(*) AS assigned,SUM(r.outcome='usable') AS usable,"
        "SUM(r.outcome IN ('usable','policy','missing')) AS terminal "
        "FROM campaign_assignments a LEFT JOIN campaign_responses r "
        "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id AND r.assignment_id=a.assignment_id "
        "WHERE a.campaign_id=? AND a.evidence_class='measured' "
        "AND (?='*' OR a.model=?) "
        "GROUP BY a.model,COALESCE(r.condition_id,a.condition_id) ORDER BY a.model,condition_id")
    params = (owner,model,model)
    rows = db._query(sql,params)
    if rows is None:
        return None
    # Interleave models so the first page is not consumed by one model's history.
    result = [dict(row, number=index) for _, group in groupby(rows, key=lambda r:r['model'])
              for index, row in enumerate(group,1)]
    filters = [(facet,(query or {}).get('compare_'+facet)) for facet in ('corpus','framework','modality')
               if (query or {}).get('compare_'+facet)]
    if ranked(condition) and filters:
        numbers = {(row['model'],row['condition_id']):row['number'] for row in result}
        filtered_sql = sql.replace('GROUP BY a.model', ''.join('AND a.'+facet+'=? ' for facet,_ in filters)+'GROUP BY a.model')
        filtered = db._query(filtered_sql,(*params,*(value for _,value in filters)))
        if filtered is None:
            return None
        result = [dict(row,number=numbers[(row['model'],row['condition_id'])]) for row in filtered]
    # Number within the model's complete measured list before selecting a
    # condition, so a fixed condition keeps the same label beside an All scope.
    unranked = []
    if ranked(condition):
        selected = []
        for _model, group in groupby(result,key=lambda row:row['model']):
            scored = []
            for row in group:
                if condition == '__best_response__':
                    score = Fraction(row['usable'] or 0,row['terminal']) if row['terminal'] else None
                else:
                    field = 'output' if condition.endswith('output__') else 'context'
                    value = row[field+'_min']
                    score = value if row[field+'_known']==row['assigned'] and value is not None and value>0 and value==row[field+'_max'] else None
                if score is None:
                    unranked.append(row)
                else:
                    scored.append((score,row))
            if scored:
                best = (min if condition.startswith('__min_') else max)(score for score,_row in scored)
                selected.extend(row for score,row in scored if score==best)
        result = selected
    else:
        result = [row for row in result if condition == ALL or row['condition_id'] == condition]
    return dict(units=sorted(result, key=lambda row:(row['number'],row['model'])),unranked=unranked)


def units(db, owner, model, condition, *, query=None):
    scope = unit_scope(db,owner,model,condition,query=query)
    return None if scope is None else scope['units']


def page_data(db, campaign, query, page=0):
    from .workspace_comparison import CHOICES, comparison_rows
    query = normalize(query)
    if type(page) is not int or page < 0 or not all(query.get(k) for k in CHOICES):
        raise ValueError('Select models, generation conditions and judging conditions on both sides')
    scopes, absent, unranked = [], {}, {}
    for side, owner in (('left',campaign),('right',query['right_campaign'])):
        db.require_workspace(owner)
        model, condition = query[side+'_model'], query[side+'_condition']
        scope = unit_scope(db,owner,model,condition,query=query)
        if scope is None:
            return None
        rows = scope['units']
        unranked[side] = scope['unranked']
        choices = scope_judges(db,owner,model,condition,selected_units=rows)
        roster = db.workspace_result_models(owner)
        if choices is None or rows is None or roster is None:
            return None
        allowed = {r['judge_id'] for r in choices} or {UNJUDGED}
        if query[side+'_judge'] not in allowed:
            raise ValueError('Select a judging condition offered for the selected model scope')
        selected = {r['model'] for r in roster} if model==ALL else {model}
        absent[side] = sorted(selected - {r['model'] for r in rows})
        scopes.append(rows)
    total = len(scopes[0])*len(scopes[1])
    pairs = []
    # Slice metadata before reading outcomes; never query every model pair on
    # one request. Source facets within each selected pair remain complete.
    for left, right in islice(product(*scopes),page*PAGE_SIZE,(page+1)*PAGE_SIZE):
        selected = dict(query, left_model=left['model'],left_condition=left['condition_id'],
            right_model=right['model'],right_condition=right['condition_id'])
        rows = comparison_rows(db,campaign,selected,permit_missing_judges=True,all_facets=True)
        if rows is None:
            return None
        pairs.append(dict(left=left,right=right,query=selected,rows=rows))
    return dict(pairs=pairs,total=total,absent=absent,unranked=unranked,page=page)


def export_rows(data):
    return [dict(row,**{side+'_'+key:pair[side][field] for side in ('left','right')
                       for key,field in (('model','model'),('condition','condition_id'))})
            for pair in data['pairs'] for row in pair['rows']]


def render(data, campaign, query):
    from .workspace_comparison import CHOICES, FILTERS, render_groups, _condition_tokens
    from .workspace_judging_charts import _judge_name
    escape = html.escape
    page, total = data['page'], data['total']
    start = min(page*PAGE_SIZE+1,total)
    end = min((page+1)*PAGE_SIZE,total)
    content = (f"<p>Model / generation-condition pairs {start:,}-{end:,} of {total:,}. "
        "Each comparison is separate. Condition numbers belong to each model, not equivalent settings. "
        "Counts across these comparisons must not be added as independent inputs.</p>")
    for side in ('left','right'):
        condition = query[side+'_condition']
        if ranked(condition):
            content += '<p>'+side.title()+' condition rule: '+escape(CONDITION_MODES[condition])+'. Applied independently per model within the selected source filters; all ties are retained.</p>'
            if condition == '__best_response__':
                content += ("<p class='notice amber'>Post-hoc selection by observed usable-response rate: usable outputs divided by saved "
                    "terminal responses (usable, provider-policy or missing). Pending responses are excluded from that denominator. "
                    "This is not attack success or a safety score; small or incomplete conditions can rank highest. "
                    "It is not an unbiased comparison of preselected conditions.</p>")
            else:
                content += '<p>Only fully recorded, uniform finite settings are ranked. Unknown, mixed and native-maximum values remain unranked.</p>'
            skipped = data.get('unranked',{}).get(side,[])
            if skipped:
                content += '<details><summary>'+side.title()+f': {len(skipped)} unranked conditions</summary><ul>'
                content += ''.join('<li>'+escape(model_label(row['model']))+f"; condition {row['number']}</li>" for row in skipped)
                content += '</ul></details>'
    for side, models in data['absent'].items():
        if models:
            reason = 'no eligible generation conditions for this rule' if ranked(query[side+'_condition']) else 'no indexed measured generation conditions'
            content += '<p class="notice amber" title="'+escape(', '.join(models),quote=True)+'">'+side.title()+': '+reason+' for '+escape(', '.join(model_label(model) for model in models))+'.</p>'
    saved = {key:query[key] for key in (*CHOICES,*FILTERS) if query.get(key)}
    if any(pair['rows'] for pair in data['pairs']):
        export='/campaigns/'+campaign+'/figures/comparison.csv?'+urlencode(dict(saved,page=page))
        content += ("<p id='campaign-exports'><a class='button ghost' data-campaign-export download='comparison.csv' href='"
            +escape(export,quote=True)+"'>Download this page's counts</a></p><p id='campaign-export-status' role='status'></p>")
    def label(unit):
        known = unit['terminal'] or 0
        usable = unit['usable'] or 0
        return ("<span title='"+escape(unit['model'],quote=True)+"'>"+escape(model_label(unit['model']))+'</span>'
            +f"; condition {unit['number']}; context "+_condition_tokens(unit,'context')
            +'; output allowance '+_condition_tokens(unit,'output')
            +f"; usable responses {usable:,}/{known:,}; assigned {unit['assigned']:,}")
    for pair in data['pairs']:
        rows=pair['rows']
        matched=sum(r['count'] for r in rows if r['match_status']=='matched')
        valid=sum(r['count'] for r in rows if r['match_status']=='matched' and r['left_status']=='valid' and r['right_status']=='valid')
        content += ("<details class='comparison-pair' data-model-comparison><summary>"
            +escape(model_label(pair['left']['model']))+f" (condition {pair['left']['number']}) versus "
            +escape(model_label(pair['right']['model']))+f" (condition {pair['right']['number']})"
            +f" - matched: {matched:,}; jointly valid judgments: {valid:,}</summary>"
            +'<p>Left: '+label(pair['left'])+'</p><p>Right: '+label(pair['right'])+'</p>'
            +'<p>Judges: '+escape(_judge_name(query['left_judge']) if query['left_judge']!=UNJUDGED else 'Not indexed')
            +' / '+escape(_judge_name(query['right_judge']) if query['right_judge']!=UNJUDGED else 'Not indexed')
            +'. Missing judgments remain Not indexed; another judge is not substituted.</p>')
        content += render_groups(rows) if rows else '<p>No measured inputs in these conditions under the selected filters.</p>'
        content += '</details>'
    for label,number in (('Previous',page-1),('Next',page+1)):
        if number>=0 and (label=='Previous' or (page+1)*PAGE_SIZE<total):
            url='/campaigns/'+campaign+'?'+urlencode(dict(saved,section='compare',page=number))
            content += "<a class='button ghost' href='"+escape(url,quote=True)+"'>"+label+'</a> '
    return "<div data-comparison-results style='overflow-wrap:anywhere'>"+content+'</div>'
