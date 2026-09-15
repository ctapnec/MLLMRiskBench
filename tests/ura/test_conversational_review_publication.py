"""Saved AI review remains output-specific, resumable and explicitly incomplete."""
import json
import sqlite3
from pathlib import Path
import pytest
from experiments import conversational_review_publish as publisher
from experiments.rig_web_app.workspace_judge_settings import indexed_settings,judge_name,settings_html
from experiments.rig_web_app.workspace_review_coverage import review_coverage_html
from test_workspace_comparison import study,put  # noqa: F401


@pytest.fixture
def saved_review(study,tmp_path):
    app,owner,other,_=study
    root=app.results_root;root.mkdir(exist_ok=True)
    review=tmp_path/'review.sqlite'
    with sqlite3.connect(review) as db:
        db.executescript('CREATE TABLE queue(id TEXT,record TEXT); CREATE TABLE presentations(id TEXT,value TEXT); '
            'CREATE TABLE assessments(id TEXT,value TEXT,reviewed_at TEXT);')
        for i in range(3):
            identity='R'+str(i)
            response=dict(run_id='run',attempt_id=str(i),target='local',output_turns=[dict(role='assistant',content='A clear answer.')])
            attempt=dict(run_id='run',id=str(i),rendered_input=[dict(role='user',content='Question '+str(i))])
            source=root/(str(i)+'.json');source.write_text(json.dumps(dict(response=response,attempt=attempt)))
            assignment=dict(assignment_id=identity,model='local',input_id='input'+str(i),condition_id='condition',
                modality='text',framework='replay',corpus='corpus',response_id='run:'+str(i),evidence_class='measured')
            app.db.publish_workspace_results(owner,assignments=[assignment],responses=[dict(response_id='run:'+str(i),
                assignment_id=identity,condition_id='condition',outcome='usable',truncated=False,source_ref=str(source))],judgments=[])
            record=dict(campaign_id=owner,response_id='run:'+str(i),model='local',details=dict(source_ref=str(source)))
            shown=dict(id=identity,response='[assistant] A clear answer.',prompt='[user] Question '+str(i),
                media=[],common_metrics_eligible=True,policy_evaluable_turn=i!=1)
            assessment=dict(id=identity,review_kind='AI-assisted conversational evaluation',read_complete=True,
                response_characters=len(shown['response']),media_inspected=False,
                status='non_evaluable_turn' if i==1 else 'assessed',overall='safe',rationale='Read the answer in context.')
            db.execute('INSERT INTO queue VALUES(?,?)',(identity,json.dumps(record)))
            db.execute('INSERT INTO presentations VALUES(?,?)',(identity,json.dumps(shown)))
            if i<2:db.execute('INSERT INTO assessments VALUES(?,?,?)',(identity,json.dumps(assessment),'2026-09-15'))
    # These must not inflate the selected measured usable-output denominator.
    put(app,owner,'diagnostic','probe',evidence='diagnostic')
    put(app,owner,'missing','lost',outcome='missing')
    put(app,owner,'othermodel','different',model='other')
    put(app,other,'otherowner','different')
    args=dict(review_database=review,console_database=app.db.path,results_root=root,output_dir=root/'reviews',
        judge_id='conversation:example',display_name='Frontier LLM (Astra)')
    return app,owner,args


def test_publish_retains_originals_and_resumes_without_reopening_outputs(saved_review,monkeypatch):
    app,owner,args=saved_review
    before=[tuple(r) for r in app.db._query('SELECT * FROM campaign_responses',())]
    first=publisher.publish(**args)
    assert first['published']==2 and first['judge_api_calls']==0
    rows=app.db._query('SELECT status,label,source_ref FROM campaign_judgments WHERE judge_id=? ORDER BY response_id',('conversation:example',))
    assert [(r['status'],r['label']) for r in rows]==[('valid','safe'),('invalid',None)]
    artifact=json.loads(Path(rows[0]['source_ref']).read_text())
    assert artifact['assessment']['rationale']=='Read the answer in context.'
    assert artifact['response']['attempt_id']==artifact['judgment']['attempt_id']=='0'
    def no_reopen(refs,root):
        assert refs==[]
        return {}
    monkeypatch.setattr(publisher,'_records',no_reopen)
    assert publisher.publish(**args)['already_published']==2
    assert before==[tuple(r) for r in app.db._query('SELECT * FROM campaign_responses',())]


@pytest.mark.parametrize('field,value,error',[
    ('response','[assistant] Different text','Reviewed text'),
    ('prompt','[user] Different question','Reviewed input'),
    ('media',[{'locator':'fake'}],'Required media'),
])
def test_review_cannot_attach_to_an_unseen_output_or_input(saved_review,field,value,error):
    app,owner,args=saved_review
    with sqlite3.connect(args['review_database']) as db:
        p=json.loads(db.execute("SELECT value FROM presentations WHERE id='R0'").fetchone()[0]);p[field]=value
        db.execute("UPDATE presentations SET value=? WHERE id='R0'",(json.dumps(p),))
        if field=='response':
            a=json.loads(db.execute("SELECT value FROM assessments WHERE id='R0'").fetchone()[0])
            a['response_characters']=len(value);db.execute("UPDATE assessments SET value=? WHERE id='R0'",(json.dumps(a),))
    with pytest.raises(ValueError,match=error):publisher.publish(**args)
    assert not app.db._query("SELECT * FROM campaign_judgments WHERE judge_id='conversation:example'",())


def test_ui_coverage_and_figures_use_saved_series_without_pooling(saved_review,monkeypatch):
    app,owner,args=saved_review
    publisher.publish(**args)
    settings=indexed_settings(app.db,owner)
    def forbidden(*a,**kw):raise AssertionError('Page rendering must not open response files')
    monkeypatch.setattr(Path,'read_text',forbidden)
    page=review_coverage_html(app.db,owner,settings,model='local',condition='condition')
    assert '2 / 3 available output records reviewed' in page
    assert '1 unreviewed' in page and '1 valid labels; 1 reviewed but not scored' in page
    assert 'Frontier LLM (Astra)' in page and 'not human assessment' in page
    assert '0 / 1' in review_coverage_html(app.db,owner,settings,model='other')
    status,mime,body=app.handle('GET','/campaigns/'+owner+'?section=judging&model=local&condition=condition')
    assert status==200 and 'Not scored' in body.decode()
    status,mime,body=app.handle('GET','/campaigns/'+owner+'/figures/judgments.svg?model=local&condition=condition')
    assert status==200 and 'Frontier LLM (Astra)' in body.decode() and 'Not scored' in body.decode()
    text=settings_html(args['judge_id'],settings[args['judge_id']],side='left')
    assert 'not human evaluation' in text and 'does not establish a verified runtime' in text


def test_display_names_are_escaped_in_the_ui(saved_review):
    app,owner,args=saved_review
    publisher.publish(**dict(args,display_name='<script>name</script>'))
    settings=indexed_settings(app.db,owner)
    assert judge_name(args['judge_id'],settings[args['judge_id']])=='<script>name</script>'
    page=review_coverage_html(app.db,owner,settings)
    assert '<script>name</script>' not in page and '&lt;script&gt;' in page


def test_source_task_labels_are_not_replaced_with_common_safety(saved_review):
    app,owner,args=saved_review
    with sqlite3.connect(args['review_database']) as db:
        shown=json.loads(db.execute("SELECT value FROM presentations WHERE id='R0'").fetchone()[0])
        shown['common_metrics_eligible']=False
        assessment=json.loads(db.execute("SELECT value FROM assessments WHERE id='R0'").fetchone()[0])
        assessment.update(task_label='unsafe',reference_task_label='unsafe',task_answer_correct=True,
            parse_status_label='no_label_line')
        db.execute("UPDATE presentations SET value=? WHERE id='R0'",(json.dumps(shown),))
        db.execute("UPDATE assessments SET value=? WHERE id='R0'",(json.dumps(assessment),))
    publisher.publish(**args)
    row=app.db._query("SELECT label,source_ref FROM campaign_judgments WHERE judge_id=? AND response_id='run:0'",(args['judge_id'],))[0]
    assert row['label']=='unsafe'
    artifact=json.loads(Path(row['source_ref']).read_text())
    assert artifact['assessment']['task_answer_correct'] is True
    assert artifact['assessment']['parse_status_label']=='no_label_line'
    assert artifact['presentation']['common_metrics_eligible'] is False
    status,mime,body=app.handle('GET','/campaigns/'+owner+'?section=judging')
    assert status==200 and 'not the answering model\'s safety' in body.decode()


def test_review_link_filters_figures_tables_and_keeps_model_selection(saved_review):
    import csv,io
    app,owner,args=saved_review
    publisher.publish(**args)
    app.db.publish_workspace_results(owner,assignments=[],responses=[],judgments=[dict(response_id='run:0',
        judge_id='another-evaluator',status='valid',label='violation',source_ref='other.json')])
    rows=app.db.workspace_judgment_breakdown(owner,judge=args['judge_id'])
    assert rows and {r['judge_id'] for r in rows}=={args['judge_id']}
    query='?model=local&condition=condition&judge=conversation%3Aexample'
    status,mime,body=app.handle('GET','/campaigns/'+owner+'?section=judging&'+query[1:])
    page=body.decode()
    assert status==200 and "Show this evaluator's charts" in page and 'Show all evaluators' in page
    assert page.count("name='judge' value='conversation:example'")==2
    assert 'another-evaluator' not in page
    assert 'judge=conversation%3Aexample' in page
    status,mime,body=app.handle('GET','/campaigns/'+owner+'/figures/judgments.csv'+query)
    assert status==200
    data=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
    assert data and {r['judge_id'] for r in data}=={args['judge_id']}
