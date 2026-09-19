"""Readable saved classifier results; no fitting or artifact reconstruction."""
import html
import json
from pathlib import Path
from urllib.parse import quote


def render(app, directory):
    root = Path(directory).resolve()
    results = app.results_root.resolve()
    if not root.is_relative_to(results):
        return ''

    def read(path):
        path = Path(path).resolve()
        if not path.is_relative_to(root) or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
            return {}
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}

    def link(path, label):
        path = Path(path).resolve()
        if not path.is_relative_to(root) or not path.exists():
            return ''
        return '<a href="/artifacts?path='+quote(path.relative_to(results).as_posix())+'">'+html.escape(label)+'</a>'

    try:
        saved = read(root/'result.json')
        if not saved:
            return '<p>Analysis is not complete. Open its job for progress or recovery.</p>'
        evaluation = saved.get('stages', {}).get('evaluation')
        report = read(Path(evaluation)/'result.json') if evaluation else saved
        body = '<section class="card"><h3>Analysis results</h3>'
        body += '<p>Recorded teacher-label agreement, not human-validated model safety.</p>'
        if report.get('selected_responses') is not None:
            body += '<p>'+html.escape(str(report['selected_responses']))+' selected text answers; '
            body += html.escape(str(report.get('independent_groups', 'unknown')))+' independent input groups.</p>'
        if saved.get('packaging_reason'):
            body += '<p class="notice amber">'+html.escape(saved['packaging_reason'])+'</p>'
        experiments = report.get('experiments', [])
        if experiments:
            body += '<div class="scroll"><table><thead><tr><th>Task</th><th>Evaluation</th><th>Features</th><th>Status</th><th>Test macro-F1</th></tr></thead><tbody>'
            for row in experiments:
                if row.get('estimator') not in {None, 'linear_svm'}:
                    continue
                value = row.get('test', {}).get('macro_f1')
                score = f'{value:.3f}' if isinstance(value, (float, int)) else 'Not estimated'
                cells = (str(row.get('task', '')).replace('_', ' '),
                         str(row.get('protocol', '')).replace('_', ' '),
                         str(row.get('features', '')).replace('_', ' '),
                         str(row.get('reason') or row.get('status', 'unknown')), score)
                body += '<tr>'+''.join('<td>'+html.escape(cell)+'</td>' for cell in cells)+'</tr>'
            body += '</tbody></table></div><p>Macro-F1 balances the two label classes. Compare feature sets within the same task and split. Full reports include baselines, class support and uncertainty.</p>'
        links = [link(root/'result.json', 'Study report')]
        for stage, label in [('dataset', 'Dataset and exclusions'), ('evaluation', 'Metrics, predictions and baselines'), ('classifiers', 'Reusable classifiers')]:
            if saved.get('stages', {}).get(stage):
                links.append(link(saved['stages'][stage], label))
        body += '<div class="action-row">'+' '.join(filter(None, links))+'</div></section>'
        return body
    except (OSError, ValueError, TypeError):
        return '<p class="notice amber">The saved analysis summary is unavailable. Its job and retained artifacts remain available for diagnosis.</p>'
