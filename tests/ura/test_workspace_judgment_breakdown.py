"""Retained judge labels stay output-owned, source-scoped and fully paginated."""
import csv
import io
import xml.etree.ElementTree as ET

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.storage import ConsoleDB
from experiments.rig_web_app.workspace_judging_charts import (
    judgment_groups, judgment_breakdown_html, judgment_breakdown_svg, judgment_counts_csv,
)


def publish(db, owner, aid, *, condition='c', corpus='corpus', model='model', evidence='measured',
            judge='local-cascade-test', label='compliant', status='valid'):
    assignment = dict(assignment_id=aid, model=model, input_id='i' + aid, condition_id=condition,
        modality='text', framework='replay', corpus=corpus, response_id='r' + aid, evidence_class=evidence)
    response = dict(response_id='r' + aid, assignment_id=aid, condition_id=condition,
        outcome='usable', truncated=False, source_ref='outputs.jsonl:' + aid)
    judgment = dict(response_id='r' + aid, judge_id=judge, status=status, label=label,
        source_ref='judgments.jsonl:' + aid)
    db.publish_workspace_results(owner, assignments=[assignment], responses=[response], judgments=[judgment])
    return response, judgment


def test_breakdown_excludes_unselected_history_and_separates_conditions(tmp_path):
    db = ConsoleDB(tmp_path / 'console.db', repo_root=tmp_path)
    try:
        owner = db.create_workspace('Local', 'local')
        response, judgment = publish(db, owner, '1')
        db.publish_workspace_results(owner, assignments=[], responses=[dict(response, response_id='old')],
            judgments=[dict(judgment, response_id='old', label='violation')])
        publish(db, owner, '2', label='violation')
        publish(db, owner, '3', condition='corrected')
        publish(db, owner, '4', corpus='other')
        publish(db, owner, '5', model='other')
        publish(db, owner, '6', evidence='diagnostic')
        groups = judgment_groups(db.workspace_judgment_breakdown(owner))
        assert len(groups) == 5 and sum(row['count'] for group in groups for row in group) == 6
        filtered = db.workspace_judgment_breakdown(owner, model='model', condition='c')
        assert sum(row['count'] for row in filtered) == 4
        original = next(group for group in groups if group[0]['model'] == 'model' and group[0]['condition_id'] == 'c'
                        and group[0]['evidence_class'] == 'measured' and group[0]['corpus'] == 'corpus')
        assert {row['label']: row['count'] for row in original} == {'compliant': 1, 'violation': 1}
    finally:
        db.close()


def test_pagination_never_splits_a_label_distribution(tmp_path):
    db = ConsoleDB(tmp_path / 'console.db', repo_root=tmp_path)
    try:
        owner = db.create_workspace('Local', 'local')
        for index in range(15):
            publish(db, owner, str(index * 2), corpus=f'corpus-{index:02}')
            publish(db, owner, str(index * 2 + 1), corpus=f'corpus-{index:02}', label='violation')
        first = judgment_groups(db.workspace_judgment_breakdown(owner))
        second = judgment_groups(db.workspace_judgment_breakdown(owner, offset=12))
        assert len(first) == 13 and len(second) == 3
        assert all(len(group) == 2 for group in first + second)
        assert {group[0]['corpus'] for group in first[:12]}.isdisjoint(group[0]['corpus'] for group in second)
    finally:
        db.close()


def rows():
    common = dict(model='provider:<model>', evidence_class='measured', condition_id='exact-condition',
        modality='text', framework='replay', corpus='corpus', judge_id='local-cascade-opaque')
    return [dict(common, status='valid', label='compliant', count=2),
            dict(common, status='valid', label='violation', count=1),
            dict(common, status='invalid', label=None, count=1),
            dict(common, status='missing', label=None, count=1)]


def test_rendered_and_exported_counts_share_denominator_and_escape_labels():
    data = rows()
    page = judgment_breakdown_html(data)
    assert '<model>' not in page and '&lt;model&gt;' in page
    assert 'Missing output: 1/5' in page and 'Invalid verdict: 1/5' in page
    assert 'overflow-wrap:anywhere' in page and 'preserveAspectRatio' in page
    figure = ET.fromstring(judgment_breakdown_svg(data, scope='Selected conditions'))
    marks = [node for node in figure.iter() if node.get('data-count')]
    assert sum(int(node.get('data-count')) for node in marks) == 5
    assert sum(float(node.get('width')) for node in marks) == pytest.approx(850)
    exported = list(csv.DictReader(io.StringIO(judgment_counts_csv(data).decode('utf-8-sig'))))
    assert sum(int(row['count']) for row in exported) == 5
    assert all(row['condition_id'] == 'exact-condition' for row in exported)


def test_empty_and_nonpositive_counts():
    assert judgment_breakdown_html([]) == ''
    with pytest.raises(ValueError, match='positive'):
        judgment_breakdown_html([dict(rows()[0], count=0)])


def test_judgment_page_and_exports_use_same_selected_outputs(tmp_path):
    app = RigWebApp(results_root=tmp_path / 'runs', state_dir=tmp_path / 'state', repo_root=tmp_path,
        gpu_hardware={}, system_hardware={})
    try:
        owner = app.db.create_workspace('Local', 'local')
        publish(app.db, owner, '1')
        publish(app.db, owner, '2', label='violation')
        status, _, body = app.handle('GET', f'/campaigns/{owner}?section=judging&model=model&condition=c')
        page = body.decode()
        assert status == 200 and 'Retained judgment label distribution' in page
        assert 'compliant: 1/2' in page and 'violation: 1/2' in page
        assert 'Pending judgments are not part' in page and 'not pooled security rates' in page
        assert 'data-campaign-export' in page and 'window.uraBusy.begin' in page
        assert '/figures/judgments.svg?page=0&amp;model=model&amp;condition=c' in page
        for name in ('judgments.svg', 'judgments.csv'):
            status, _, data = app.handle('GET', f'/campaigns/{owner}/figures/{name}?model=model&condition=c')
            assert status == 200
            if name.endswith('svg'):
                ET.fromstring(data)
            else:
                assert sum(int(row['count']) for row in csv.DictReader(io.StringIO(data.decode('utf-8-sig')))) == 2
            assert app.handle('GET', f'/campaigns/{owner}/figures/{name}?model=not-selected')[0] == 404
    finally:
        app.close()


def test_breakdown_query_has_bounded_sql_work(tmp_path):
    db = ConsoleDB(tmp_path / 'console.db', repo_root=tmp_path)
    try:
        owner = db.create_workspace('Local', 'local')
        for index in range(500):
            publish(db, owner, str(index))
        ticks = 0

        def limit():
            nonlocal ticks
            ticks += 1000
            return ticks > 500 * 350

        db._conn.set_progress_handler(limit, 1000)
        rows = db.workspace_judgment_breakdown(owner)
        assert rows is not None and sum(row['count'] for row in rows) == 500
    finally:
        if db._conn is not None:
            db._conn.set_progress_handler(None, 0)
        db.close()
