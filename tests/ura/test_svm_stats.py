import csv
import io
import json

import pytest

from test_operator_operations import app  # noqa: F401
from experiments.rig_web_app import svm_stats
from experiments.rig_web_app.workspace_store import activity_role


def report(app, name='svm', **changes):
    root = app.results_root / name
    root.mkdir(parents=True)
    svm = dict(task='harmful_compliance', protocol='group_holdout', features='response',
        estimator='linear_svm', status='evaluated', test=dict(macro_f1=.75, average_precision=.81,
        macro_f1_cluster_ci95=[.62, .89]), support=dict(test=dict(responses=20, groups=8, classes={'0': 14, '1': 6})))
    baseline = dict(svm, estimator='majority', test=dict(macro_f1=.41, average_precision=.3))
    value = dict(selected_responses=100, independent_groups=40, teacher='Haiku', seed=0,
        experiments=[svm, baseline, dict(svm, protocol='unseen_model:Qwen', test=dict(macro_f1=.2)),
            dict(task='over_refusal', protocol='group_holdout', status='insufficient_class_group_support')])
    value.update(changes)
    (root / 'result.json').write_text(json.dumps(value))
    return root


def test_retained_study_visible_in_stats_without_job_or_new_computation(app, monkeypatch):
    root = report(app)
    owner = app.db.create_workspace('Local and hosted source', 'mixed')
    app.db.register_svm_study('svm', 'Recorded classifier study', [owner])
    monkeypatch.setattr(app, 'start_job', lambda *a, **kw: pytest.fail('Stats must not start analysis'))
    code, _, body = app.handle('GET', '/stats?view=svm&campaign_id='+owner)
    page = body.decode()
    assert code == 200 and 'Recorded classifier study' in page
    assert '100 selected text answers; 40 independent input groups' in page
    assert '0.750' in page and '0.410' in page and '0.620 - 0.890' in page
    assert '0.200' not in page  # An unseen-model split cannot leak into grouped holdout.
    assert 'Majority baseline' in page and '14 / 6' in page
    assert 'insufficient class group support' in page
    assert 'SVM held-out macro-F1' in page and 'not model safety scores' in page
    assert 'id="campaign-export-status"' in page
    assert '/stats?view=svm' in app._workspaces_page(context='stats').decode()
    assert root.exists() and len(app.jobs) == 0


def test_study_selection_and_exports_use_same_task_split(app):
    report(app)
    app.db.register_svm_study('svm', 'Study', [])
    args = dict(view='svm', study='svm', task='harmful_compliance', protocol='unseen_model:Qwen')
    status, kind, data = svm_stats.response(app, dict(args, export='csv'))
    rows = list(csv.DictReader(io.StringIO(data.decode())))
    assert status == 200 and kind.startswith('text/csv')
    assert len(rows) == 1 and rows[0]['macro_f1'] == '0.2'
    assert rows[0]['teacher'] == 'Haiku' and rows[0]['study'] == 'svm' and rows[0]['independent_groups'] == '40'
    _, _, svg = svm_stats.response(app, dict(args, export='svg'))
    assert b'Macro-F1 0.200' in svg and b'0.750' not in svg
    with pytest.raises(ValueError, match='recorded evaluation'):
        svm_stats.response(app, dict(args, protocol='not-recorded'))


def test_no_recorded_metric_is_never_rendered_as_zero(app):
    report(app, experiments=[dict(task='over_refusal',protocol='group_holdout',status='insufficient_class_group_support')])
    app.db.register_svm_study('svm', 'Insufficient cohort', [])
    _, _, body = svm_stats.response(app, {})
    assert b'Not estimated' in body and b'0.000' not in body


def test_path_bounds_and_scoped_study_selection(app, tmp_path):
    report(app)
    owner = app.db.create_workspace('Selected', 'local')
    other = app.db.create_workspace('Other', 'api')
    app.db.register_svm_study('svm', 'Private to selected', [owner])
    with pytest.raises(ValueError, match='selected campaign'):
        svm_stats.response(app, dict(campaign_id=other, study='svm'))
    with pytest.raises(ValueError, match='relative'):
        app.db.register_svm_study('../outside', 'Wrong', [])
    with pytest.raises(ValueError, match='outside'):
        svm_stats.load(app, tmp_path / 'outside')
    root = app.results_root / 'svm'
    (root / 'result.json').write_text(json.dumps(dict(stages=dict(evaluation=str(tmp_path / 'outside')))))
    with pytest.raises(ValueError, match='outside'):
        svm_stats.load(app, root)


def test_resumed_console_study_is_listed_once_and_classifier_role_is_analysis(app):
    root = report(app)
    owner = app.db.create_workspace('UI study', 'mixed')
    app.db.register_svm_study('svm', 'Retained title', [owner])
    for i in range(2):
        with app.db._conn:
            app.db._conn.execute('INSERT INTO jobs(job_id,command,argv,state,started_at) VALUES(?,?,?,?,?)',
                (str(i), 'response_svm', json.dumps(['python','-m','experiments.response_svm','--study','--out',str(root)]), 'complete', i))
        app.db.attach_workspace_member(owner, 'job', str(i), 'analysis')
    studies = svm_stats.studies(app)
    assert len(studies) == 1 and studies[0]['job'] == '1' and studies[0]['title'] == 'Retained title'
    assert activity_role('response_svm') == 'analysis'


def test_unfinished_study_does_not_hide_completed_study_selector(app):
    report(app)
    app.db.register_svm_study('svm', 'Finished', [])
    app.db.register_svm_study('pending', 'Pending', [])
    _, _, body = svm_stats.response(app, dict(study='pending'))
    assert b'Saved results are not available yet' in body and b'Finished' in body


def test_csv_escapes_spreadsheet_formulas():
    data = svm_stats.metrics_csv([dict(task='=CMD()',protocol='group_holdout')]).decode()
    assert "'=CMD()" in data
