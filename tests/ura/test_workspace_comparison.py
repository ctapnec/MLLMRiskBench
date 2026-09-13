"""Exact-input comparison never pairs by row order or selects a favorable answer."""
import csv
import io
from urllib.parse import urlencode

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.workspace_comparison import comparison_rows, comparison_groups


@pytest.fixture
def study(tmp_path):
    app = RigWebApp(results_root=tmp_path / 'runs', state_dir=tmp_path / 'state', repo_root=tmp_path,
        gpu_hardware={}, system_hardware={})
    left = app.db.create_workspace('Local', 'local')
    right = app.db.create_workspace('API', 'api')
    query = dict(left_model='local', left_condition='lc', left_judge='judge', right_campaign=right,
        right_model='api', right_condition='rc', right_judge='judge')
    try:
        yield app, left, right, query
    finally:
        app.close()


def put(app, owner, aid, input_id, *, model='local', condition='lc', corpus='corpus', evidence='measured',
        outcome='usable', label='safe', status='valid', judge='judge', pending=False, truncated=False,
        modality='text', framework='replay'):
    assignment = dict(assignment_id=aid, model=model, input_id=input_id, condition_id=condition,
        modality=modality, framework=framework, corpus=corpus, response_id=None if pending else 'r'+aid,
        evidence_class=evidence)
    response = dict(response_id='r'+aid, assignment_id=aid, condition_id=condition, outcome=outcome,
        truncated=truncated, source_ref='responses.jsonl:'+aid)
    judgment = dict(response_id='r'+aid, judge_id=judge, status=status, label=label, source_ref='judgments.jsonl:'+aid)
    app.db.publish_workspace_results(owner, assignments=[assignment], responses=[] if pending else [response],
        judgments=[] if pending or status is None else [judgment])
    return response, judgment


def pair(study, aid, **left_options):
    app, left, right, _ = study
    put(app, left, 'l'+aid, aid, **left_options)
    put(app, right, 'r'+aid, aid, model='api', condition='rc')


def totals(rows):
    return {key: sum(row['count'] for row in rows if row['match_status']==key)
            for key in ('matched', 'left_only', 'right_only', 'ambiguous')}


def test_only_exact_selected_measured_outputs_are_compared(study):
    app, left, right, query = study
    pair(study, 'same')
    old, verdict = put(app, left, 'left', 'left-only')
    put(app, right, 'right', 'right-only', model='api', condition='rc')
    app.db.publish_workspace_results(left, assignments=[], responses=[dict(old, response_id='historical')],
        judgments=[dict(verdict, response_id='historical', label='violation')])
    put(app, left, 'old-condition', 'same', condition='historical', label='violation')
    put(app, left, 'probe', 'diagnostic-only', evidence='diagnostic')
    put(app, left, 'other-model', 'other-model-only', model='other')
    rows = comparison_rows(app.db, left, query)
    assert totals(rows) == dict(matched=1, left_only=1, right_only=1, ambiguous=0)
    assert all(row['left_label'] != 'violation' for row in rows)
    assert next(row for row in rows if row['match_status']=='left_only')['left_label']=='safe'


def test_duplicate_assignments_are_not_cartesian_pairs(study):
    app, left, _, query = study
    pair(study, 'duplicate')
    put(app, left, 'duplicate-second', 'duplicate', label='violation')
    rows = comparison_rows(app.db, left, query)
    assert totals(rows) == dict(matched=0, left_only=0, right_only=0, ambiguous=1)
    assert rows[0]['left_label'] is None


def test_selected_replacement_uses_its_own_generation_condition(study):
    app, left, right, query = study
    old, judgment = put(app, left, 'original', 'same', label='violation')
    replacement = dict(old, response_id='replacement', condition_id='corrected')
    assignment = dict(assignment_id='original', model='local', input_id='same', condition_id='lc',
        modality='text', framework='replay', corpus='corpus', response_id='replacement', evidence_class='measured')
    app.db.publish_workspace_results(left, assignments=[assignment], responses=[replacement],
        judgments=[dict(judgment, response_id='replacement', label='safe')])
    put(app, right, 'api', 'same', model='api', condition='rc')
    rows = comparison_rows(app.db, left, dict(query, left_condition='corrected'))
    assert len(rows)==1 and rows[0]['count']==1 and rows[0]['left_label']=='safe'
    with pytest.raises(ValueError, match='judging condition'):
        comparison_rows(app.db, left, query)


def test_missing_truncated_and_absent_judgments_remain_distinct(study):
    app, left, _, query = study
    pair(study, 'normal')
    pair(study, 'missing', outcome='missing', label=None, status='missing', truncated=True)
    pair(study, 'unjudged', status=None)
    pair(study, 'pending', pending=True)
    pair(study, 'invalid', label=None, status='invalid')
    rows = comparison_rows(app.db, left, query)
    assert sum(row['count'] for row in rows) == 5
    assert any(row['left_outcome']=='missing' and row['left_truncated']==1 and row['left_status']=='missing' for row in rows)
    assert any(row['left_outcome']=='usable' and row['left_status'] is None for row in rows)
    assert any(row['left_outcome'] is None and row['left_status'] is None for row in rows)
    assert any(row['left_status']=='invalid' and row['left_label'] is None for row in rows)


def test_source_identity_and_requested_judge_are_not_interchangeable(study):
    app, left, right, query = study
    pair(study, 'normal')
    put(app, left, 'source-a', 'same-id', corpus='source-a')
    put(app, right, 'source-b', 'same-id', corpus='source-b', model='api', condition='rc')
    rows = comparison_rows(app.db, left, query)
    assert totals(rows) == dict(matched=1, left_only=1, right_only=1, ambiguous=0)
    with pytest.raises(ValueError, match='judging condition'):
        comparison_rows(app.db, left, dict(query, right_judge='unobserved'))
    with pytest.raises(ValueError, match='both models'):
        comparison_rows(app.db, left, dict(query, left_condition=''))


def test_pagination_keeps_whole_source_facets(study):
    app, left, right, query = study
    for index in range(15):
        for number, label in enumerate(('safe', 'violation')):
            key = f'{index}-{number}'
            options = dict(corpus=f'corpus-{index:02}', label=label)
            put(app, left, 'l'+key, key, **options)
            put(app, right, 'r'+key, key, model='api', condition='rc', **options)
    first = comparison_groups(comparison_rows(app.db, left, query))
    second = comparison_groups(comparison_rows(app.db, left, query, offset=12))
    assert len(first)==13 and len(second)==3
    assert all(sum(row['count'] for row in group)==2 for group in first + second)
    assert {group[0]['corpus'] for group in first[:12]}.isdisjoint(group[0]['corpus'] for group in second)


def test_page_and_export_match_and_use_existing_busy_guard(study):
    app, left, right, query = study
    pair(study, 'same', label='<visible>')
    path = f'/campaigns/{left}?'+urlencode(dict(query, section='compare'))
    status, _, body = app.handle('GET', path)
    page = body.decode()
    assert status==200 and 'matched: 1' in page and '&lt;visible&gt;' in page
    assert 'not pooled safety rates' in page and "window.uraBusy.begin('Preparing campaign export...')" in page
    assert 'comparison.csv?' in page and "name='right_campaign'" in page
    status, _, body = app.handle('GET', f'/campaigns/{left}/figures/comparison.csv?'+urlencode(query))
    exported = list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert status==200 and sum(int(row['count']) for row in exported)==1
    assert exported[0]['left_campaign']==left and exported[0]['right_campaign']==right
    assert exported[0]['left_label']=='<visible>'
    status, _, body = app.handle('GET', f'/campaigns/{left}?section=compare')
    assert status==200 and 'Choose campaigns and models' in body.decode()


def test_comparison_has_bounded_index_work(study):
    app, left, _, query = study
    for index in range(400):
        pair(study, str(index))
    ticks = 0
    def limit():
        nonlocal ticks
        ticks += 1000
        return ticks > 800_000
    app.db._conn.set_progress_handler(limit, 1000)
    try:
        rows = comparison_rows(app.db, left, query)
        assert rows is not None and totals(rows)['matched']==400
    finally:
        if app.db._conn is not None:
            app.db._conn.set_progress_handler(None, 0)


@pytest.mark.parametrize('facet,chosen,other', [
    ('corpus', 'chosen-source', 'other-source'), ('framework', 'replay', 'crescendo'), ('modality', 'image', 'text')])
def test_scope_filters_both_conditions_before_pairing_and_exports(study, facet, chosen, other):
    app, left, right, query = study
    for name, value in [('selected', chosen), ('excluded', other)]:
        put(app, left, 'l'+name, name, **{facet: value})
        put(app, right, 'r'+name, name, model='api', condition='rc', **{facet: value})
    filtered = dict(query, **{'compare_'+facet: chosen})
    rows = comparison_rows(app.db, left, filtered)
    assert totals(rows) == dict(matched=1, left_only=0, right_only=0, ambiguous=0)
    assert all(row[facet] == chosen for row in rows)
    status, _, body = app.handle('GET', f'/campaigns/{left}?'+urlencode(dict(filtered, section='compare')))
    page = body.decode()
    assert status == 200 and f"name='compare_{facet}'" in page and f"value='{chosen}' selected" in page
    assert f'compare_{facet}={chosen}' in page and 'matched: 1' in page
    status, _, body = app.handle('GET', f'/campaigns/{left}/figures/comparison.csv?'+urlencode(filtered))
    exported = list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert status == 200 and sum(int(row['count']) for row in exported) == 1
    assert all(row['compare_'+facet] == chosen and row[facet] == chosen for row in exported)
    assert comparison_rows(app.db, left, dict(query, **{'compare_'+facet: "absent' OR 1=1 --"})) == []


def test_scope_filters_survive_pagination_and_do_not_reset_empty_selections(study):
    app, left, right, query = study
    for index in range(14):
        key = str(index)
        put(app, left, 'l'+key, key, corpus='source-'+key, modality='image')
        put(app, right, 'r'+key, key, corpus='source-'+key, modality='image', model='api', condition='rc')
    filtered = dict(query, compare_modality='image', compare_framework='replay')
    status, _, body = app.handle('GET', f'/campaigns/{left}?'+urlencode(dict(filtered, section='compare')))
    page = body.decode()
    assert status == 200 and 'compare_modality=image' in page and 'compare_framework=replay' in page
    assert 'page=1' in page and 'Next</a>' in page
    status, _, body = app.handle('GET', f'/campaigns/{left}?'+urlencode(dict(filtered, section='compare', compare_corpus='empty-source')))
    assert status == 200 and "value='empty-source' selected" in body.decode()
    assert 'No measured inputs on this comparison page' in body.decode()
