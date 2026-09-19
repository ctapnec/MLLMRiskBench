"""Recorded classifier evaluation in Stats, without fitting or reading datasets."""
from __future__ import annotations

import csv
import html
import io
import json
import math
from pathlib import Path
from urllib.parse import quote, urlencode

from .builder_replays import argument
from .ui import _page
from .workspace_charts import CHART_STYLE, EXPORT_SCRIPT

TASKS = {'harmful_compliance': 'Harmful compliance', 'over_refusal': 'Over-refusal',
         'judge_disagreement': 'Local/Haiku disagreement'}
ESTIMATORS = {'linear_svm': 'Linear SVM', 'logistic': 'Logistic regression',
              'logistic_regression': 'Logistic regression', 'majority': 'Majority baseline',
              'harmful_svm_plus_local_verdict': 'Derived disagreement baseline'}


def label(value):
    return TASKS.get(value, ESTIMATORS.get(value, str(value).replace('_', ' ')))


def score(value):
    return f'{value:.3f}' if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else 'Not estimated'


def load(app, directory):
    root = Path(directory)
    if not root.is_absolute():
        root = app.results_root / root
    root = root.resolve()
    if not root.is_relative_to(app.results_root.resolve()):
        raise ValueError('Study is outside the results directory')

    def read(path):
        path = path.resolve()
        if not path.is_relative_to(root):
            raise ValueError('Study report is outside its directory')
        if path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('Study report is too large for an interactive summary')
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            raise ValueError('Study report is not an object')
        return value

    saved = read(root / 'result.json')
    evaluation = saved.get('stages', {}).get('evaluation')
    report = read(Path(evaluation) / 'result.json') if evaluation else saved
    if not isinstance(report.get('experiments', []), list):
        raise ValueError('Study experiments are unavailable')
    return root, saved, report


def studies(app):
    """Explicit references plus console jobs; do not scan the run tree."""
    records = app.db._query('SELECT * FROM svm_studies ORDER BY title,directory')
    jobs = app.db._query("SELECT j.*,m.campaign_id FROM jobs j LEFT JOIN campaign_members m "
        "ON m.member_kind='job' AND m.member_id=j.job_id WHERE j.command='response_svm' ORDER BY j.started_at")
    if records is None or jobs is None:
        raise ValueError('SVM study index unavailable')
    result = {}

    def add(directory, title, owners, job=''):
        root = Path(directory)
        if not root.is_absolute():
            root = app.repo_root / root if job else app.results_root / root
        root = root.resolve()
        if not root.is_relative_to(app.results_root.resolve()):
            return
        key = root.relative_to(app.results_root.resolve()).as_posix()
        item = result.setdefault(key, dict(key=key, title=title, campaigns=set(), job=job))
        item['campaigns'].update(owners)
        if job:
            item['job'] = job

    for row in records:
        add(row['directory'], row['title'], json.loads(row['campaigns']))
    for row in jobs:
        argv = json.loads(row['argv'])
        if '--study' not in argv and '--evaluate' not in argv:
            continue
        directory = argument(argv, '--out')
        if directory:
            add(directory, 'Classifier study - ' + row['job_id'],
                [row['campaign_id']] if row['campaign_id'] else [], row['job_id'])
    return list(result.values())


def selected_rows(report, query):
    rows = report.get('experiments', []) + report.get('derived_disagreement_baselines', [])
    protocols = list(dict.fromkeys(str(r.get('protocol', 'unknown')) for r in rows))
    protocol = query.get('protocol') or ('group_holdout' if 'group_holdout' in protocols else next(iter(protocols), ''))
    task = query.get('task', '')
    if (protocol and protocol not in protocols) or (task and task not in TASKS):
        raise ValueError('Choose a recorded evaluation split and task')
    return [r for r in rows if r.get('protocol') == protocol and (not task or r.get('task') == task)], protocols, protocol


def metrics_csv(rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(['task', 'protocol', 'features', 'estimator', 'status', 'macro_f1', 'ci95_low', 'ci95_high',
                     'average_precision', 'test_responses', 'test_groups', 'class_0', 'class_1'])
    for row in rows:
        metric = row.get('test', {})
        support = row.get('support', {}).get('test', row.get('support', {}))
        ci = metric.get('macro_f1_cluster_ci95') or [None, None]
        values = [row.get(k, '') for k in ('task', 'protocol', 'features', 'estimator', 'status')]
        values += [metric.get('macro_f1'), *ci, metric.get('average_precision'), support.get('responses'), support.get('groups'),
                   support.get('classes', {}).get('0'), support.get('classes', {}).get('1')]
        writer.writerow(["'" + v if isinstance(v, str) and v[:1] in '=+-@\t\r' else v for v in values])
    return stream.getvalue().encode('utf-8')


def figure(rows):
    rows = [r for r in rows if r.get('estimator') == 'linear_svm' and score(r.get('test', {}).get('macro_f1')) != 'Not estimated']
    height = 60 + len(rows) * 90
    marks = []
    for i, row in enumerate(rows):
        y = 34 + i * 90
        metric = row['test']
        value = metric['macro_f1']
        caption = label(row.get('task')) + ' / ' + label(row.get('features', ''))
        marks.append(f"<text x='16' y='{y}'>{html.escape(caption)}</text>"
            f"<rect class='chart-track' x='16' y='{y+12}' width='360' height='18'/>"
            f"<rect x='16' y='{y+12}' width='{360*value:.3f}' height='18' style='fill:var(--viz-series-1,#2563eb)'/>"
            f"<text x='16' y='{y+54}'>Macro-F1 {score(value)}</text>")
        ci = metric.get('macro_f1_cluster_ci95')
        if isinstance(ci, list) and len(ci) == 2 and all(isinstance(v, (int, float)) and math.isfinite(v) for v in ci):
            lo, hi = [16 + 360 * v for v in ci]
            marks.append(f"<path d='M {lo:.3f} {y+17} v 8 M {lo:.3f} {y+21} H {hi:.3f} M {hi:.3f} {y+17} v 8' "
                "fill='none' stroke='var(--text,#111827)' stroke-width='2'/>"
                f"<text x='180' y='{y+54}'>95% CI {score(ci[0])} - {score(ci[1])}</text>")
    return (f"<svg xmlns='http://www.w3.org/2000/svg' class='campaign-figure' role='img' viewBox='0 0 410 {height}' "
        "aria-label='SVM held-out macro-F1'><title>SVM held-out macro-F1</title>"
        "<desc>Scale zero to one. Lines show recorded input-cluster bootstrap 95 percent intervals, when available. "
        "Tasks and feature sets remain separate. Recorded teacher agreement is not human-validated safety.</desc>"
        '<style>' + CHART_STYLE + '</style>' + ''.join(marks) +
        f"<text x='16' y='{height-8}'>0</text><text x='196' y='{height-8}'>0.5</text><text x='376' y='{height-8}'>1</text></svg>")


def table(rows):
    cells = []
    for row in rows:
        metric = row.get('test', {})
        support = row.get('support', {}).get('test', row.get('support', {}))
        ci = metric.get('macro_f1_cluster_ci95')
        interval = ' - '.join(score(v) for v in ci) if isinstance(ci, list) and len(ci) == 2 else 'Not estimated'
        classes = support.get('classes', {})
        class_counts = ' / '.join(str(classes.get(str(i), 'unknown')) for i in (0, 1))
        values = [label(row.get('task', '')), label(row.get('features', '')), label(row.get('estimator', '')),
            label(row.get('reason') or row.get('status', 'unknown')), score(metric.get('macro_f1')), interval,
            score(metric.get('average_precision')), str(support.get('responses', 'unknown')),
            str(support.get('groups', 'unknown')), class_counts]
        cells.append('<tr>' + ''.join('<td>' + html.escape(v) + '</td>' for v in values) + '</tr>')
    headers = ['Task', 'Features', 'Estimator / baseline', 'Status', 'Test macro-F1', '95% interval',
               'Average precision', 'Test answers', 'Test input groups', 'Test classes 0 / 1']
    return '<div class="scroll"><table><thead><tr>' + ''.join('<th>'+h+'</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(cells) + '</tbody></table></div>'


def response(app, query):
    inventory = studies(app)
    owner = query.get('campaign_id', '')
    if owner:
        app.db.require_workspace(owner)
        inventory = [s for s in inventory if owner in s['campaigns']]
    selected = query.get('study') or (inventory[-1]['key'] if inventory else '')
    item = next((s for s in inventory if s['key'] == selected), None)
    if selected and item is None:
        raise ValueError('Choose an indexed SVM study in the selected campaign')
    body = '<h1>Stats</h1>' + app._work_view_tabs('stats', 'svm')
    body += '<section class="card"><h2>SVM results</h2><p>Predictions of recorded judge labels, not model safety scores or independent human judgments. '
    body += 'Studies, input populations, tasks and evaluation splits are kept separate. Opening this page does not train models or call providers.</p>'
    if not item:
        body += '<p>No indexed SVM studies in this selection. Start a study from a campaign\'s SVM analysis tab.</p></section>'
        return 200, 'text/html; charset=utf-8', _page('SVM results', body, active='Stats')
    try:
        root, saved, report = load(app, item['key'])
    except (OSError, ValueError, TypeError) as exc:
        body += '<p class="notice amber">Saved results are not available yet. '+html.escape(str(exc))+'</p>'
        if item['job']:
            body += '<a href="/jobs/'+quote(item['job'])+'">Open analysis job</a>'
        # Keep the study selector usable even if the latest study is unfinished.
        report = {}; saved = {}; root = app.results_root / item['key']
    rows, protocols, protocol = selected_rows(report, query)
    export = query.get('export')
    if export:
        if export == 'csv':
            return 200, 'text/csv; charset=utf-8', metrics_csv(rows)
        if export == 'svg':
            return 200, 'image/svg+xml; charset=utf-8', figure(rows).encode('utf-8')
        raise ValueError('Unknown SVM export')

    def select(name, caption, choices, value):
        return '<label class="campaign-field">'+caption+'<select name="'+name+'">'+''.join(
            '<option value="'+html.escape(k, quote=True)+'"'+(' selected' if k==value else '')+'>'+html.escape(v)+'</option>' for k,v in choices)+'</select></label>'

    body += '<form method="get" action="/stats"><input type="hidden" name="view" value="svm"><div class="campaign-grid">'
    body += select('campaign_id', 'Campaign', [('', 'All campaigns')] + [(r['campaign_id'], r['name']) for r in app.db.workspaces() or []], owner)
    body += select('study', 'Saved study', [(s['key'],s['title']) for s in inventory], selected)
    body += select('protocol', 'Evaluation split', [(p,label(p)) for p in protocols], protocol)
    body += select('task', 'Task', [('', 'All tasks'), *TASKS.items()], query.get('task', ''))
    body += '</div><div class="action-row"><button>Show SVM results</button></div></form>'
    # A changed population must not retain an incompatible downstream choice.
    body += "<script>(()=>{const f=document.querySelector('select[name=study]').form;f.elements.campaign_id.addEventListener('change',()=>{f.elements.study.value='';f.elements.protocol.value='';});f.elements.study.addEventListener('change',()=>{f.elements.protocol.value='';});})();</script>"
    body += '<p>'+html.escape(str(report.get('selected_responses', 'unknown')))+' selected text answers; '+html.escape(str(report.get('independent_groups', 'unknown')))+' independent input groups.</p>'
    body += '<p>Recorded teacher: '+html.escape(str(report.get('teacher', 'not recorded')))+'. Split seed: '+html.escape(str(report.get('seed', 'not recorded')))+'.</p>'
    if saved.get('packaging_reason'):
        body += '<p class="notice amber">'+html.escape(saved['packaging_reason'])+'</p>'
    if rows:
        body += figure(rows) + table(rows)
    else:
        body += '<p>No evaluated task in this selection. This is not a score of zero.</p>'
    body += '<p>Macro-F1 gives equal weight to both classes. Intervals use input-group resampling, not independent answer resampling. '
    body += 'Class 1 means harmful compliance, over-refusal or local/Haiku disagreement according to the selected task; class 0 is its complement. '
    body += 'Compare SVM and baseline rows only within the same study, task and split. No scores are pooled across studies.</p>'
    params = dict(view='svm', study=selected, protocol=protocol, task=query.get('task',''), campaign_id=owner)
    body += '<div id="campaign-exports" class="action-row">'+''.join('<a data-campaign-export download="svm-results.'+kind+'" href="/stats?'+html.escape(urlencode(dict(params,export=kind)),quote=True)+'">Download '+kind.upper()+'</a>' for kind in ('csv','svg'))+'</div>'
    body += '<div class="action-row"><a href="/artifacts?path='+quote((root/'result.json').relative_to(app.results_root.resolve()).as_posix())+'">Full study report</a>'
    if item['job']:
        body += '<a href="/jobs/'+quote(item['job'])+'">Analysis job</a>'
    body += '</div></section>' + EXPORT_SCRIPT
    return 200, 'text/html; charset=utf-8', _page('SVM results', body, active='Stats')
