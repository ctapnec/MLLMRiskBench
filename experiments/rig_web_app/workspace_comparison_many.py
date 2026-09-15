"""Paginated model/condition pairs; never pool different generation settings."""
from __future__ import annotations

import html
from itertools import groupby, islice, product
from urllib.parse import urlencode

ALL = '*'
UNJUDGED = '__not_indexed__'
PAGE_SIZE = 12


def normalize(query):
    query = dict(query)
    for side in ('left', 'right'):
        if query.get(side+'_model') == ALL:
            query[side+'_condition'] = ALL
    return query


def broad(query):
    return any(query.get(side+'_model') == ALL for side in ('left','right'))


def scope_judges(db, owner, model, condition):
    """Offer the union, retaining models without this judge in the comparison."""
    return db._query(
        "SELECT DISTINCT j.judge_id FROM campaign_assignments a "
        "JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
        "AND r.assignment_id=a.assignment_id JOIN campaign_judgments j "
        "ON j.campaign_id=r.campaign_id AND j.response_id=r.response_id "
        "WHERE a.campaign_id=? AND a.evidence_class='measured' "
        "AND (?='*' OR a.model=?) AND (?='*' OR COALESCE(r.condition_id,a.condition_id)=?) "
        "ORDER BY j.judge_id", (owner, model, model, condition, condition))


def units(db, owner, model, condition):
    rows = db._query(
        "SELECT a.model,COALESCE(r.condition_id,a.condition_id) AS condition_id,"
        "MIN(json_extract(r.details,'$.output_allowance')) AS output_min,"
        "MAX(json_extract(r.details,'$.output_allowance')) AS output_max "
        "FROM campaign_assignments a LEFT JOIN campaign_responses r "
        "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id AND r.assignment_id=a.assignment_id "
        "WHERE a.campaign_id=? AND a.evidence_class='measured' "
        "AND (?='*' OR a.model=?) AND (?='*' OR COALESCE(r.condition_id,a.condition_id)=?) "
        "GROUP BY a.model,COALESCE(r.condition_id,a.condition_id) ORDER BY a.model,condition_id",
        (owner,model,model,condition,condition))
    if rows is None:
        return None
    # Interleave models so the first page is not consumed by one model's history.
    result = [dict(row, number=index) for _, group in groupby(rows, key=lambda r:r['model'])
              for index, row in enumerate(group,1)]
    return sorted(result, key=lambda row:(row['number'],row['model']))


def page_data(db, campaign, query, page=0):
    from .workspace_comparison import CHOICES, comparison_rows
    query = normalize(query)
    if type(page) is not int or page < 0 or not all(query.get(k) for k in CHOICES):
        raise ValueError('Select models, generation conditions and judging conditions on both sides')
    scopes, absent = [], {}
    for side, owner in (('left',campaign),('right',query['right_campaign'])):
        db.require_workspace(owner)
        model, condition = query[side+'_model'], query[side+'_condition']
        choices = scope_judges(db,owner,model,condition)
        rows = units(db,owner,model,condition)
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
    return dict(pairs=pairs,total=total,absent=absent,page=page)


def export_rows(data):
    return [dict(row,**{side+'_'+key:pair[side][field] for side in ('left','right')
                       for key,field in (('model','model'),('condition','condition_id'))})
            for pair in data['pairs'] for row in pair['rows']]


def render(data, campaign, query):
    from .workspace_comparison import CHOICES, FILTERS, render_groups
    escape = html.escape
    page, total = data['page'], data['total']
    start = min(page*PAGE_SIZE+1,total)
    end = min((page+1)*PAGE_SIZE,total)
    content = (f"<p>Model / generation-condition pairs {start:,}-{end:,} of {total:,}. "
        "Each comparison is separate. Condition numbers belong to each model, not equivalent settings. "
        "Counts across these comparisons must not be added as independent inputs.</p>")
    for side, models in data['absent'].items():
        if models:
            content += '<p class="notice amber">'+side.title()+': no indexed measured generation conditions for '+escape(', '.join(models))+'.</p>'
    saved = {key:query[key] for key in (*CHOICES,*FILTERS) if query.get(key)}
    if any(pair['rows'] for pair in data['pairs']):
        export='/campaigns/'+campaign+'/figures/comparison.csv?'+urlencode(dict(saved,page=page))
        content += ("<p id='campaign-exports'><a class='button ghost' data-campaign-export download='comparison.csv' href='"
            +escape(export,quote=True)+"'>Download this page's counts</a></p><p id='campaign-export-status' role='status'></p>")
    def label(unit):
        low, high = unit['output_min'],unit['output_max']
        allowance = 'unknown' if low is None else str(low)+((' to '+str(high)) if high!=low else '')
        return escape(unit['model'])+f"; condition {unit['number']}; output allowance "+allowance
    for pair in data['pairs']:
        rows=pair['rows']
        matched=sum(r['count'] for r in rows if r['match_status']=='matched')
        valid=sum(r['count'] for r in rows if r['match_status']=='matched' and r['left_status']=='valid' and r['right_status']=='valid')
        content += ("<details class='comparison-pair' data-model-comparison><summary>"
            +escape(pair['left']['model'])+f" (condition {pair['left']['number']}) versus "
            +escape(pair['right']['model'])+f" (condition {pair['right']['number']})"
            +f" - matched: {matched:,}; jointly valid judgments: {valid:,}</summary>"
            +'<p>Left: '+label(pair['left'])+'</p><p>Right: '+label(pair['right'])+'</p>'
            +'<p>Judges: '+escape(query['left_judge'])+' / '+escape(query['right_judge'])
            +'. Missing judgments remain Not indexed; another judge is not substituted.</p>')
        content += render_groups(rows) if rows else '<p>No measured inputs in these conditions under the selected filters.</p>'
        content += '</details>'
    for label,number in (('Previous',page-1),('Next',page+1)):
        if number>=0 and (label=='Previous' or (page+1)*PAGE_SIZE<total):
            url='/campaigns/'+campaign+'?'+urlencode(dict(saved,section='compare',page=number))
            content += "<a class='button ghost' href='"+escape(url,quote=True)+"'>"+label+'</a> '
    return "<div data-comparison-results>"+content+'</div>'
