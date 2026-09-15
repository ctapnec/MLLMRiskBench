import csv
import io
from urllib.parse import urlencode

import pytest

from experiments.rig_web_app import workspace_comparison_many as many
from test_workspace_comparison import study, pair, put, totals  # noqa: F401


@pytest.mark.parametrize('side',['left','right','both'])
def test_all_models_keep_every_model_and_generation_condition_separate(study,side):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    put(app,left,'second-local','shared',model='second-local',condition='other')
    put(app,right,'second-api','shared',model='second-api',condition='other')
    put(app,right,'history','shared',model='api',condition='old',label='violation')
    for part in (('left','right') if side=='both' else (side,)):
        query[part+'_model']=many.ALL
    data=many.page_data(app.db,left,query)
    assert data['total']==({'left':2,'right':3,'both':6}[side])
    assert len(data['pairs'])==data['total']
    for item in data['pairs']:
        assert totals(item['rows'])==dict(matched=1,left_only=0,right_only=0,ambiguous=0)
        if item['right']['condition_id']=='old':assert item['rows'][0]['right_label']=='violation'
        else:assert item['rows'][0]['right_label']=='safe'
    exported=many.export_rows(data)
    assert all(r['left_model']!='*' and r['right_model']!='*' for r in exported)


def test_all_scope_does_not_drop_unjudged_pending_or_diagnostic_only_models(study):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    put(app,right,'unjudged','shared',model='unjudged',condition='plain',status=None)
    put(app,right,'pending','shared',model='pending',condition='plain',pending=True)
    put(app,right,'probe','shared',model='probe-only',condition='probe',evidence='diagnostic')
    data=many.page_data(app.db,left,dict(query,right_model='*'))
    assert data['total']==3 and data['absent']['right']==['probe-only']
    for item in data['pairs']:
        row=item['rows'][0]
        if item['right']['model'] in ('unjudged','pending'):assert row['right_status'] is None
        if item['right']['model']=='pending':assert row['right_outcome'] is None
    with pytest.raises(ValueError,match='judging condition'):
        many.page_data(app.db,left,dict(query,right_model='*',right_judge='invented-judge'))


def test_scope_with_no_judgments_can_show_coverage_but_not_invent_verdicts(study):  # noqa: F811
    app,left,right,query=study
    put(app,left,'left','same',status=None)
    put(app,right,'right','same',model='api',condition='rc',status=None)
    data=many.page_data(app.db,left,dict(query,left_model='*',right_model='*',left_judge=many.UNJUDGED,right_judge=many.UNJUDGED))
    assert data['total']==1
    row=data['pairs'][0]['rows'][0]
    assert row['left_status'] is None and row['right_status'] is None and row['count']==1


def test_pair_pagination_limits_queries_without_cutting_source_facets(study,monkeypatch):  # noqa: F811
    from experiments.rig_web_app import workspace_comparison as comparison
    app,left,right,query=study
    for source in range(14):
        put(app,left,'left-'+str(source),str(source),corpus='source-'+str(source))
        for model in range(15):
            put(app,right,f'right-{source}-{model}',str(source),corpus='source-'+str(source),model=f'api-{model:02}',condition='rc')
    query=dict(query,right_model='*')
    calls=[]
    original=comparison.comparison_rows
    def counted(*args,**kwargs):
        calls.append(1)
        return original(*args,**kwargs)
    monkeypatch.setattr(comparison,'comparison_rows',counted)
    first=many.page_data(app.db,left,query)
    assert len(calls)==12 and len(first['pairs'])==12 and first['total']==15
    second=many.page_data(app.db,left,query,1)
    assert len(calls)==15 and len(second['pairs'])==3
    assert {p['right']['model'] for p in first['pairs']}.isdisjoint(p['right']['model'] for p in second['pairs'])
    assert all(totals(p['rows'])['matched']==14 for p in first['pairs']+second['pairs'])
    code,_,body=app.handle('GET',f'/campaigns/{left}/figures/comparison.csv?'+urlencode(dict(query,page=1)))
    rows=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert code==200 and sum(int(r['count']) for r in rows)==42
    assert {r['right_model'] for r in rows}=={'api-12','api-13','api-14'}


def test_broad_filters_exports_and_ambiguous_inputs_match_the_display(study):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    put(app,left,'duplicate','shared')
    put(app,left,'other-source','other',corpus='excluded')
    put(app,right,'second','shared',model='second',condition='distinct',status=None)
    query=dict(query,left_model='*',right_model='*',compare_corpus='corpus')
    data=many.page_data(app.db,left,query)
    assert all(totals(p['rows'])==dict(matched=0,ambiguous=1,left_only=0,right_only=0) for p in data['pairs'])
    code,_,body=app.handle('GET',f'/campaigns/{left}?'+urlencode(dict(query,section='compare')))
    assert code==200 and body.decode().count("value='*' selected>All models")==2
    assert 'Model / generation-condition pairs 1-2 of 2' in body.decode()
    assert 'No unambiguous matched inputs' in body.decode() and '<tbody></tbody>' not in body.decode()
    code,_,body=app.handle('GET',f'/campaigns/{left}/figures/comparison.csv?'+urlencode(query))
    rows=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert code==200 and len(rows)==2 and all(r['compare_corpus']=='corpus' for r in rows)
    assert {r['right_condition'] for r in rows}=={'rc','distinct'}


def test_no_measured_units_remain_explicit(study):  # noqa: F811
    app,left,right,query=study
    put(app,left,'probe','probe',evidence='diagnostic')
    put(app,right,'probe','probe',model='api',condition='rc',evidence='diagnostic')
    query=many.normalize(dict(query,left_model='*',right_model='*',left_judge=many.UNJUDGED,right_judge=many.UNJUDGED))
    data=many.page_data(app.db,left,query)
    assert data['total']==0 and not data['pairs']
    content=many.render(data,left,query)
    assert 'no indexed measured generation conditions for local' in content
    assert 'no indexed measured generation conditions for api' in content


def test_readable_labels_preserve_exact_identity_in_data_and_exports(study):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    identity='ollama:example:q4@sha256:'+'a'*64
    put(app,right,'pinned','shared',model=identity,condition='pin')
    query=many.normalize(dict(query,right_model='*'))
    data=many.page_data(app.db,left,query)
    assert many.model_label(identity)=='ollama:example:q4 (revision aaaaaaaa)'
    assert many.model_label('model@not-a-revision')=='model@not-a-revision'
    assert identity in {row['right_model'] for row in many.export_rows(data)}
    assert "title='"+identity+"'" in many.render(data,left,query)


@pytest.mark.parametrize('side',['left','right','both'])
def test_all_conditions_keeps_selected_models_and_each_condition_separate(study,side):  # noqa: F811
    app,left,right,query=study
    pair(study,'shared')
    put(app,left,'local-second','shared',condition='second',label='violation')
    put(app,right,'api-second','shared',model='api',condition='second',status=None)
    put(app,left,'local-other','shared',model='other',condition='second')
    put(app,right,'api-other','shared',model='other',condition='second')
    elsewhere=app.db.create_workspace('Elsewhere','mixed')
    put(app,elsewhere,'elsewhere','shared',model='api',condition='elsewhere')
    put(app,right,'probe','shared',model='api',condition='probe',evidence='diagnostic')
    for part in (('left','right') if side=='both' else (side,)):
        query[part+'_condition']='*'
    assert many.broad(query)
    data=many.page_data(app.db,left,query)
    assert data['total']==(4 if side=='both' else 2)
    for item in data['pairs']:
        assert item['left']['model']=='local' and item['right']['model']=='api'
        assert totals(item['rows'])==dict(matched=1,left_only=0,right_only=0,ambiguous=0)
        if item['left']['condition_id']=='second':assert item['rows'][0]['left_label']=='violation'
        if item['right']['condition_id']=='second':assert item['rows'][0]['right_status'] is None
    code,_,body=app.handle('GET',f'/campaigns/{left}?'+urlencode(dict(query,section='compare')))
    assert code==200 and 'All generation conditions</option>' in body.decode()
    assert 'No other model is included on this side' in body.decode()
    assert body.decode().count('data-model-comparison')==data['total']
    code,_,body=app.handle('GET',f'/campaigns/{left}/figures/comparison.csv?'+urlencode(query))
    rows=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert code==200 and sum(int(r['count']) for r in rows)==data['total']
    assert {r['left_model'] for r in rows}=={'local'} and {r['right_model'] for r in rows}=={'api'}
    assert all(r['left_condition']!='*' and r['right_condition']!='*' for r in rows)


def test_all_conditions_pagination_filters_exports_and_stable_condition_numbers(study):  # noqa: F811
    app,left,right,query=study
    put(app,left,'z','shared',condition='z')
    put(app,left,'a','shared',condition='a')
    for index in range(15):
        put(app,right,str(index),'shared',model='api',condition=f'c{index:02}')
        put(app,right,'excluded'+str(index),'excluded',model='api',condition=f'c{index:02}',corpus='excluded')
    query=dict(query,left_condition='z',right_condition='*',compare_corpus='corpus')
    first=many.page_data(app.db,left,query)
    second=many.page_data(app.db,left,query,1)
    assert first['total']==15 and len(first['pairs'])==12 and len(second['pairs'])==3
    assert all(p['left']['number']==2 for p in first['pairs']+second['pairs'])
    assert [p['right']['number'] for p in second['pairs']]==[13,14,15]
    assert all(totals(p['rows'])['matched']==1 for p in first['pairs']+second['pairs'])
    code,_,body=app.handle('GET',f'/campaigns/{left}/figures/comparison.csv?'+urlencode(dict(query,page=1)))
    rows=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert code==200 and len(rows)==3 and {r['right_condition'] for r in rows}=={'c12','c13','c14'}
    assert all(r['compare_corpus']==r['corpus']=='corpus' for r in rows)


def test_all_conditions_with_no_judgments_retains_pending_and_missing_coverage(study):  # noqa: F811
    app,left,right,query=study
    put(app,left,'l','shared',status=None)
    put(app,right,'missing','shared',model='api',condition='missing',outcome='missing',status=None)
    put(app,right,'pending','shared',model='api',condition='pending',pending=True)
    query=dict(query,right_condition='*',left_judge=many.UNJUDGED,right_judge=many.UNJUDGED)
    data=many.page_data(app.db,left,query)
    assert data['total']==2
    assert {p['rows'][0]['right_outcome'] for p in data['pairs']}=={'missing',None}
    assert all(p['rows'][0]['right_status'] is None for p in data['pairs'])
