"""Compare indexed job outputs without rebuilding campaigns or reading models."""
import csv
import html
import io
import json
from pathlib import Path
from urllib.parse import urlencode

from .ui import _page
from .workspace_comparison import coverage_chart


def choices(app):
    rows=app.db._query('SELECT r.*,m.campaign_id,c.name AS campaign_name FROM ('+app.db._CAMPAIGN_ROWS+
        ") r JOIN campaign_members m ON m.member_id=r.job_id AND m.member_kind IN ('job','external') "
        "JOIN campaigns c ON c.campaign_id=m.campaign_id WHERE r.command='run_matrix' AND r.kind='measured' "
        'ORDER BY r.created_at DESC,r.job_id')
    if rows is None:raise ValueError('Job index unavailable')
    return [dict(row) for row in rows if row['out_dir']]


def directory(app,row):
    path=Path(row['out_dir'])
    return (path if path.is_absolute() else app.repo_root/path).resolve()


def outputs(app,job,roster):
    root=directory(app,job)
    # A shared/resumed output directory is not attributable to one job.
    # Do not silently credit the same retained answers to both executions.
    for other in roster:
        path=directory(app,other)
        if other['job_id']!=job['job_id'] and (path.is_relative_to(root) or root.is_relative_to(path)):
            raise ValueError('This job shares an output history with another job. Compare its campaign instead; individual execution ownership is ambiguous.')
    prefix=str(root)+'/'
    rows=app.db._query('SELECT a.*,r.outcome,r.truncated,r.details FROM campaign_assignments a '
        'JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.assignment_id=a.assignment_id '
        'AND r.response_id=a.response_id WHERE a.campaign_id=? AND a.evidence_class=\'measured\' '
        "AND substr(json_extract(r.details,'$.source_ref'),1,?)=? ORDER BY a.model,a.condition_id,a.input_id",
        (job['campaign_id'],len(prefix),prefix))
    if rows is None:raise ValueError('Indexed job outputs unavailable')
    return [dict(row) for row in rows]


def summarize(rows):
    from collections import defaultdict
    groups=defaultdict(lambda:dict(outputs=0,usable=0,missing=0,policy=0,other=0,truncated=0,
        truncation_unknown=0,input_tokens=0,output_tokens=0,usage_known=0))
    for row in rows:
        key=tuple(row[k] for k in ('model','condition_id','corpus','framework','modality'))
        value=groups[key];value['outputs']+=1
        value[row['outcome'] if row['outcome'] in {'usable','missing','policy'} else 'other']+=1
        value['truncated']+=row['truncated']==1
        value['truncation_unknown']+=row['truncated'] is None
        details=json.loads(row['details'])
        if all(type(details.get(k)) is int for k in ('input_tokens','output_tokens')):
            value['usage_known']+=1
            for k in ('input_tokens','output_tokens'):value[k]+=details[k]
    return [dict(zip(('model','condition_id','corpus','framework','modality'),key),**values) for key,values in groups.items()]


def overlap(left,right):
    from collections import Counter
    def keys(rows):return Counter(tuple(r[k] for k in ('input_id','corpus','framework','modality')) for r in rows)
    a,b=keys(left),keys(right)
    counts=dict(matched=0,left_only=0,right_only=0,ambiguous=0)
    for key in a.keys()|b.keys():
        name='ambiguous' if a[key]>1 or b[key]>1 else 'matched' if key in a and key in b else 'left_only' if key in a else 'right_only'
        counts[name]+=1
    return counts


def response(app,query):
    roster=choices(app);selected={};data={};reports=[]
    for side in ('left','right'):
        key=query.get(side+'_job','')
        if key:
            selected[side]=next((r for r in roster if r['job_id']==key),None)
            if selected[side] is None:raise ValueError('Choose an indexed measured job')
            data[side]=outputs(app,selected[side],roster)
            reports.extend(dict(side=side,job=key,campaign=selected[side]['campaign_id'],**r) for r in summarize(data[side]))
    if query.get('download')=='csv':
        if len(selected)!=2:raise ValueError('Select two jobs before downloading')
        stream=io.StringIO(newline='')
        fields=['side','job','campaign','model','condition_id','corpus','framework','modality','outputs','usable','missing','policy','other','truncated','truncation_unknown','input_tokens','output_tokens','usage_known']
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        for row in reports:
            writer.writerow({k:"'"+v if isinstance(v,str) and v.startswith(('=','+','-','@')) else v for k,v in row.items()})
        return 200,'text/csv; charset=utf-8',stream.getvalue().encode('utf-8-sig')
    esc=html.escape
    body='<h1>Stats</h1>'+app._work_view_tabs('stats','compare')
    body+='<section class="card"><h2>Compare saved job outputs</h2><p><a href="/stats?view=compare">Compare whole campaigns</a></p>'
    body+='<p>Choose measured jobs with indexed answers and exclusive output directories. Shared recovery directories and unindexed historical jobs require campaign comparison. No source files are scanned.</p>'
    body+='<form method="get" action="/stats"><input type="hidden" name="view" value="compare"><input type="hidden" name="scope" value="jobs"><div class="campaign-grid">'
    for side in ('left','right'):
        body+='<label class="campaign-field">'+side.title()+' job<select name="'+side+'_job" required><option value="">Choose measured job</option>'
        for row in roster:
            body+='<option value="'+esc(row['job_id'])+'"'+(' selected' if query.get(side+'_job')==row['job_id'] else '')+'>'+esc(row['campaign_name']+' / '+row['job_id']+' / '+row['state'])+'</option>'
        body+='</select></label>'
    body+='</div><div class="action-row"><button>Compare job outputs</button></div></form></section>'
    if len(selected)==2:
        body+='<section class="card"><h2>Input overlap</h2>'+coverage_chart(overlap(data['left'],data['right']))
        body+='<p>Exact indexed inputs, corpus, framework and modality. Repeated inputs across conditions are ambiguous, not arbitrarily paired. These are saved-outcome counts, not full scheduled-input coverage or pooled safety scores.</p></section>'
        body+='<section class="card"><h2>Outcomes by model, condition and task</h2><p>Truncation is independent of output usability. Unknown token usage and unstarted inputs are not zero usage or successful answers.</p>'
        headers=('Side','Model / condition','Corpus / framework / modality','Saved','Usable','Missing','Policy refusal','Other','Truncated / unknown','Known token usage')
        body+='<div class="scroll"><table><thead><tr>'+''.join('<th>'+h+'</th>' for h in headers)+'</tr></thead><tbody>'
        for row in reports:
            cells=(row['side'],row['model']+' / '+row['condition_id'],row['corpus']+' / '+row['framework']+' / '+row['modality'],row['outputs'],row['usable'],row['missing'],row['policy'],row['other'],str(row['truncated'])+' / '+str(row['truncation_unknown']),
                (str(row['input_tokens'])+' in / '+str(row['output_tokens'])+' out; '+str(row['usage_known'])+'/'+str(row['outputs'])+' outputs') if row['usage_known'] else 'Not recorded')
            body+='<tr>'+''.join('<td>'+esc(str(v))+'</td>' for v in cells)+'</tr>'
        body+='</tbody></table></div>'
        if not reports:body+='<p>No indexed outcomes resolve to these jobs. Use their campaign reports; no results have been inferred from job names.</p>'
        body+='<div class="action-row"><a href="/stats?'+esc(urlencode(dict(query,download='csv')),quote=True)+'">Export these job statistics (CSV)</a></div></section>'
    return 200,'text/html; charset=utf-8',_page('Compare jobs',body,active='Stats')
