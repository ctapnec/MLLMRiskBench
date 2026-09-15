"""Named condition criteria are per-model, explicit and never pooled scores."""
import csv
import io
from urllib.parse import urlencode

import pytest

from experiments.rig_web_app import workspace_comparison_many as many
from test_workspace_comparison import study, put  # noqa: F401


@pytest.fixture
def choices(study):
    app,left,right,query=study
    put(app,left,'left','shared',output_allowance=1024)
    specs=[('small',1024,4096,['usable','missing']),('large',4096,8192,['usable']),
        ('tied',4096,8192,['usable']),('unknown',None,None,['missing']),
        ('native',-1,None,['missing']),('mixed',4096,4096,['missing','missing'])]
    for model in ('api','second'):
        for condition,output,context,outcomes in specs:
            for index,outcome in enumerate(outcomes):
                allowance=output+(1024 if index and condition=='mixed' else 0) if output is not None else None
                put(app,right,f'{model}-{condition}-{index}','shared' if index==0 else 'other',model=model,
                    condition=condition,outcome=outcome,output_allowance=allowance,
                    context_tokens=context,judge=condition+'-judge')
        put(app,right,model+'-pending','pending',model=model,condition='pending',pending=True)
        put(app,right,model+'-probe','shared',model=model,condition='probe',evidence='diagnostic',output_allowance=99999,context_tokens=99999)
    return app,left,right,query


@pytest.mark.parametrize('model',['api','*'])
@pytest.mark.parametrize('rule,wanted',[
    ('__max_output__',{'large','tied'}),('__min_output__',{'small'}),
    ('__max_context__',{'large','tied'}),('__min_context__',{'small','mixed'}),
    ('__best_response__',{'large','tied'})])
def test_rules_rank_per_model_keep_ties_and_do_not_guess_unknowns(choices,model,rule,wanted):
    app,_,right,_=choices
    query=many.normalize(dict(right_model=model,right_condition=rule))
    assert query['right_condition']==rule and many.broad(query)
    scope=many.unit_scope(app.db,right,model,rule)
    models={'api','second'} if model=='*' else {'api'}
    assert {(r['model'],r['condition_id']) for r in scope['units']}=={(m,c) for m in models for c in wanted}
    if 'output' in rule:
        assert {r['condition_id'] for r in scope['unranked']}=={'unknown','native','mixed','pending'}
    if rule=='__best_response__':
        assert {r['condition_id'] for r in scope['unranked']}=={'pending'}
    assert {r['judge_id'] for r in many.scope_judges(app.db,right,model,rule)}=={c+'-judge' for c in wanted}


def test_best_response_rate_uses_terminal_denominator_and_exact_fraction_ties(study):  # noqa: F811
    app,_,right,_=study
    for condition,outcomes in [('one-third',['usable','missing','policy']),('two-sixths',['usable']*2+['missing']*3+['policy'])]:
        for index,outcome in enumerate(outcomes):
            put(app,right,condition+str(index),str(index),model='api',condition=condition,outcome=outcome)
    put(app,right,'pending','pending',model='api',condition='one-third',pending=True)
    put(app,right,'retry','retry',model='api',condition='one-third',outcome='retry_pending')
    rows=many.units(app.db,right,'api','__best_response__')
    assert {r['condition_id'] for r in rows}=={'one-third','two-sixths'}
    assert [(r['usable'],r['terminal'],r['assigned']) for r in rows]==[(1,3,5),(2,6,6)]


@pytest.mark.parametrize('facet',['corpus','framework','modality'])
def test_rules_respect_current_source_filters_without_renumbering(study,facet):  # noqa: F811
    from experiments.rig_web_app.workspace_comparison import facet_choices
    app,left,right,query=study
    for condition in ('a','b'):
        for selected in (True,False):
            value=('image' if selected else 'text') if facet=='modality' else ('chosen' if selected else 'other')
            put(app,right,condition+str(selected),'shared',model='api',condition=condition,
                output_allowance=4096 if (condition=='b')==selected else 1024, **{facet:value})
    filters={'compare_'+facet:'image' if facet=='modality' else 'chosen'}
    query=dict(query,right_condition='__max_output__',**filters)
    rows=many.units(app.db,right,'api','__max_output__',query=query)
    assert len(rows)==1 and rows[0]['condition_id']=='b' and rows[0]['number']==2
    assert rows[0]['assigned']==1
    offered=facet_choices(app.db,left,query)
    assert offered[facet]==({'image','text'} if facet=='modality' else {'chosen','other'})


@pytest.mark.parametrize('side',['left','right'])
def test_rules_have_disclosures_and_exact_csv_selection_identity(choices,side):
    app,left,right,query=choices
    if side=='left':
        left,right=right,left
        query=dict(left_model='*',left_condition='__best_response__',left_judge='large-judge',
            right_campaign=right,right_model='local',right_condition='lc',right_judge='judge')
    else:
        query=dict(query,right_model='*',right_condition='__best_response__',right_judge='large-judge')
    code,_,body=app.handle('GET',f'/campaigns/{left}?'+urlencode(dict(query,section='compare')))
    assert code==200
    text=body.decode()
    assert 'Post-hoc selection' in text and 'not attack success or a safety score' in text
    assert 'usable responses 1/1; assigned 1' in text and 'all ties are retained' in text
    code,_,body=app.handle('GET',f'/campaigns/{left}/figures/comparison.csv?'+urlencode(query))
    rows=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert code==200 and len(rows)==4
    assert {r[side+'_model'] for r in rows}=={'api','second'}
    assert {r[side+'_condition'] for r in rows}=={'large','tied'}
    assert {r[side+'_condition_selection'] for r in rows}=={'Highest usable-response rate'}
    assert any(r[side+'_status']=='' for r in rows)


def test_no_rankable_conditions_are_explicit_and_do_not_remove_saved_data(study):  # noqa: F811
    app,left,right,query=study
    put(app,left,'l','shared')
    put(app,right,'r','shared',model='api',condition='unknown')
    query=dict(query,right_condition='__max_context__',right_judge=many.UNJUDGED)
    data=many.page_data(app.db,left,query)
    assert data['total']==0 and data['absent']['right']==['api']
    text=many.render(data,left,query)
    assert 'no eligible generation conditions for this rule for api' in text
    assert '1 unranked conditions' in text
    assert len(many.units(app.db,right,'api','*'))==1
