"""Synthetic isolated review state: no study participant or campaign evidence."""
import csv
import io
import json
from pathlib import Path

import pytest

from experiments import human_audit as audit
from experiments.rig_web_app.human_review_store import HumanReviewStore, COMMON
from experiments.rig_web import RigWebApp


def prepared(path, media=None, mode='common'):
    fields = ['sample_key', 'model', 'run_id', 'prompt', 'response', 'source_policy_instruction',
              'source_policy_intended_metric', 'modality', 'media_references', 'expected_behavior', 'cluster_key']
    fields += sorted(audit._RATING_FIELDS if mode == 'common' else audit._SOURCE_TASK_RATING_FIELDS)
    if mode != 'common': fields += ['task_label_vocabulary']
    row = {key: '' for key in fields}
    row.update(sample_key='hidden-model-run-input', model='SECRET_MODEL_ID', run_id='PRIVATE_RUN_ID',
               prompt='<script>attack()</script> explain a historical event', response='A substantial example answer.',
               source_policy_instruction='Assess the response in this policy context.', source_policy_intended_metric='safety',
               modality='image' if media else 'text', media_references=json.dumps(media or []),
               expected_behavior='safe_answer', cluster_key='original-cluster')
    if mode != 'common': row['task_label_vocabulary'] = 'safe|unsafe'
    with path.open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader(); writer.writerow(row)
    return row


def qualification(mode='common'):
    dimensions = COMMON if mode == 'common' else {'task_label': None, 'parse_status_label': None}
    return dict(reference='synthetic unit test only', items=20, correct={k: 18 for k in dimensions},
                independent_reference=True, language_and_experience_confirmed=True)


@pytest.fixture
def review(tmp_path):
    root=tmp_path/'state';root.mkdir(); sample=root/'sample.csv';prepared(sample)
    store=HumanReviewStore(root/'console.db',root/'reviews',allowed_roots=[root],media_roots=[root])
    study=store.create(campaign='example',name='Synthetic test study',prepared=sample,mode='common',
                       metadata=dict(ethics='test fixture',consent='synthetic consent',compensation='test terms',stop_contact='test operator',results=str(root)))
    tokens=[store.enroll(study,'rater-'+str(i),'rater',qualification()) for i in range(2)]
    adjudicator=store.enroll(study,'adjudicator','adjudicator',qualification())
    yield store,study,tokens,adjudicator
    store.close()


def valid_rating(**changes):
    return dict(label='safe',refusal_label='not_refusal',harmfulness_label='not_harmful',
                convincingness_label='not_applicable',specificity_label='not_applicable',confidence=4,notes='',**changes)


def item_for(store,token):
    store.consent(token); return store.view(token)['queue'][0]['id']


def test_review_payload_is_blinded_and_consent_precedes_content(review):
    store,study,tokens,adjudicator=review
    assert 'item' not in store.view(tokens[0]) and 'queue' not in store.view(tokens[0])
    item=item_for(store,tokens[0]); view=store.view(tokens[0],item)
    serialized=json.dumps(view)
    for secret in ('SECRET_MODEL_ID','PRIVATE_RUN_ID','hidden-model-run-input','original-cluster','rater-1','token_hash'):
        assert secret not in serialized
    assert view['item']['response']=='A substantial example answer.'
    with pytest.raises(ValueError): store.save(tokens[1],item,revision=0,value=valid_rating(),submit=True)
    assert not store.summary(study)['ready_for_analysis']


def test_independent_submissions_cannot_be_overwritten_or_seen_by_other_rater(review):
    store,study,tokens,adjudicator=review;item=item_for(store,tokens[0]);item_for(store,tokens[1])
    saved=store.save(tokens[0],item,revision=0,value=valid_rating())
    assert saved['revision']==1
    with pytest.raises(ValueError,match='another tab'):store.save(tokens[0],item,revision=0,value=valid_rating())
    store.save(tokens[0],item,revision=1,value=valid_rating(),submit=True)
    assert store.view(tokens[1],item)['item']['rating']['value']=={}
    with pytest.raises(ValueError,match='fixed'):store.save(tokens[0],item,revision=2,value=valid_rating())
    store.consent(adjudicator)
    assert store.view(adjudicator)['queue']==[]
    with pytest.raises(ValueError):store.export(study)


def test_disagreement_requires_adjudication_and_export_matches_prepared_form(review,tmp_path):
    store,study,tokens,adjudicator=review; item=item_for(store,tokens[0]);item_for(store,tokens[1])
    first=valid_rating();second=dict(first,label='over_refusal',refusal_label='refusal')
    store.save(tokens[0],item,revision=0,value=first,submit=True)
    store.save(tokens[1],item,revision=0,value=second,submit=True)
    assert store.summary(study)['counts']['disagreements']==1
    with pytest.raises(ValueError):store.export(study)
    store.consent(adjudicator)
    choices={k:first[k] for k in COMMON}
    with pytest.raises(ValueError):store.adjudicate(tokens[0],item,choices,'Not an adjudicator')
    store.adjudicate(adjudicator,item,choices,'The answer does not decline the benign request.')
    assert store.summary(study)['ready_for_analysis']
    output=tmp_path/'completed.csv';output.write_bytes(store.export(study))
    rows=list(csv.DictReader(io.StringIO(output.read_text(encoding='utf-8-sig'))))
    assert len(rows)==2 and {r['label'] for r in rows}=={'safe','over_refusal'}
    assert all(r['adjudicated_label']=='safe' for r in rows)
    audit._prepared_rating_form_binding(store.root/study/'prepared.csv',store.study(study)['metadata']['prepared_sha256'],
                                       output,rating_fields=audit._RATING_FIELDS,frame='common')


def test_qualification_identity_and_withdrawal_are_not_invented(review):
    store,study,tokens,adjudicator=review
    with pytest.raises(ValueError):store.enroll(study,'rater-0','adjudicator',qualification())
    with pytest.raises(ValueError):store.enroll(study,'third','rater',qualification())
    item=item_for(store,tokens[0]);store.withdraw(tokens[0])
    with pytest.raises(ValueError):store.view(tokens[0],item)
    assert not store.summary(study)['ready_for_analysis']
    with pytest.raises(ValueError):store.view('not-a-real-review-token')


def test_defer_not_safe_and_wrong_rubric_rejected(review):
    store,study,tokens,_=review;item=item_for(store,tokens[0])
    with pytest.raises(ValueError):store.save(tokens[0],item,revision=0,value=dict(valid_rating(),label='refusal'),submit=True)
    store.save(tokens[0],item,revision=0,value={'defer_reason':'Category opt-out'},defer=True)
    assert store.summary(study)['counts']['deferred']==1
    assert store.summary(study)['counts']['submitted']==0


def test_required_media_cannot_escape_roots_or_be_guessed(tmp_path):
    root=tmp_path/'state';root.mkdir();sample=root/'sample.csv'
    prepared(sample,[dict(locator='@media-root/0/../private.png',mime='image/png',modality='image')])
    store=HumanReviewStore(root/'console.db',root/'reviews',allowed_roots=[root],media_roots=[root])
    try:
        study=store.create(campaign='',name='Media fixture',prepared=sample,mode='common',metadata=dict(ethics='test',consent='test',compensation='test',stop_contact='test',results=str(root)))
        token=store.enroll(study,'a','rater',qualification());item=item_for(store,token)
        assert store.view(token,item)['item']['media']==[{'index':0,'modality':'image','available':False}]
        with pytest.raises(ValueError):store.save(token,item,revision=0,value=dict(valid_rating(),media_viewed=True),submit=True)
        with pytest.raises(ValueError):store.media(token,item,0)
    finally:store.close()


def test_rater_http_shell_and_metadata_are_separate_from_operator(tmp_path):
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,gpu_hardware={},system_hardware={})
    try:
        store=app._human_store();sample=tmp_path/'state/sample.csv';prepared(sample)
        study=store.create(campaign='',name='Model identity must stay private',prepared=sample,mode='common',metadata=dict(ethics='test',consent='test',compensation='test',stop_contact='test',results=str(tmp_path/'runs')))
        token=store.enroll(study,'a','rater',qualification())
        code,_,body=app.handle('GET','/review/'+token)
        # This is a single-operator console. The user's shared-navigation
        # requirement applies to evaluation pages too, not just operator forms.
        assert code==200 and b'/campaigns' in body and b'<nav>' in body
        assert b'window.addEventListener' in body and b'Draft saved.' in body and b'uraBusy' in body
        app.handle('POST','/review/'+token+'/consent',{'agree':'1'})
        item=store.view(token)['queue'][0]['id']
        code,_,body=app.handle('GET','/review/'+token+'?item='+item)
        assert code==200 and b'SECRET_MODEL_ID' not in body and b'<script>' in body
        assert app.handle('GET','/human-evaluation')[0]==200
    finally:app.close()


def test_saved_content_media_uses_retained_index_without_exposing_paths(tmp_path):
    root=tmp_path/'state';root.mkdir();sample=root/'sample.csv'
    media=root/'prompt.png';media.write_bytes(b'retained test media')
    digest='a'*64;index=root/'media-index.json';index.write_text(json.dumps({digest:str(media)}))
    prepared(sample,[dict(locator='@content-sha256/'+digest,sha256=digest,mime='image/png',modality='image')])
    store=HumanReviewStore(root/'console.db',root/'reviews',allowed_roots=[root],media_roots=[root])
    try:
        study=store.create(campaign='local',name='Saved media fixture',prepared=sample,mode='common',metadata=dict(
            ethics='test',consent='test',compensation='test',stop_contact='test',results=str(root),media_index=str(index)))
        token=store.enroll(study,'a','rater',qualification());item=item_for(store,token)
        view=store.view(token,item)
        assert view['item']['media'][0]['available'] is True
        assert str(media) not in json.dumps(view) and digest not in json.dumps(view)
        assert store.media(token,item,0)==('image/png',b'retained test media')
        store.save(token,item,revision=0,value=dict(valid_rating(),media_viewed=True),submit=True)
        outside=tmp_path/'private.png';outside.write_bytes(b'private')
        index.write_text(json.dumps({digest:str(outside)}))
        assert store.view(token,item)['item']['media'][0]['available'] is False
        with pytest.raises(ValueError):store.media(token,item,0)
    finally:store.close()


def test_finished_campaign_study_setup_uses_saved_results_and_reports_workload(tmp_path, monkeypatch):
    from types import SimpleNamespace
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,gpu_hardware={},system_hardware={})
    try:
        campaign=app.db.create_workspace('Finished local campaign','local')
        result_root=tmp_path/'runs'/'completed-results';result_root.mkdir()
        store=app._human_store()
        source=store.register_source(campaign=campaign,name='Completed local analysis',results=result_root)
        page=app.handle('GET','/human-evaluation?campaign_id='+campaign+'&kind=independent')[2].decode()
        assert 'Completed local analysis' in page and 'data-study-wizard' in page
        assert 'No model is rerun' in page and "data-study-step='Arrangements'" in page
        assert "select name='ethics_status'" in page and "select name='compensation_type'" in page
        assert 'This page sets up the study; it is not the rating form.' in page
        starts=[]
        def launch(command,params,**kwargs):
            starts.append((command,params,kwargs));prepared(Path(params['--output']))
            return SimpleNamespace(job_id='human-sample-job')
        monkeypatch.setattr(app,'start_job',launch)
        data=dict(campaign_id=campaign,source='scope-'+source,name='Review finished outputs',mode='common',clusters='1',
            ethics='synthetic fixture only',consent='test consent',compensation='test terms',stop_contact='test',acknowledge='1')
        code,location,_=app.handle('POST','/human-evaluation/prepare-study',data)
        assert code==303 and location.startswith('/human-evaluation/preparations/')
        assert len(starts)==1 and starts[0][0]=='human_audit'
        assert starts[0][1]['--results']==str(result_root.resolve()) and starts[0][2]['campaign_id']==campaign
        assert not store.studies(campaign)
        monkeypatch.setattr(app.db,'load_job',lambda key:dict(state='complete',exit_code=0))
        body=app.handle('GET',location)[2].decode()
        assert '1 saved outputs, 2 required independent ratings' in body
        first=app.handle('POST',location,{})[1];second=app.handle('POST',location,{})[1]
        assert first==second and len(store.studies(campaign))==1
        assert not store.summary(first.rsplit('/',1)[-1])['ready_for_analysis']
    finally:app.close()


def test_setup_arrangement_choices_record_actual_status_and_reject_unknowns():
    from experiments.rig_web_app.human_review_setup import arrangements
    data=dict(ethics_status='pending',ethics='',compensation_type='unpaid',compensation='30 minutes; test withdrawal terms',stop_contact='Test operator',consent='Test only')
    assert arrangements(data)['ethics_status']=='pending'
    assert arrangements(data)['compensation'].startswith('Voluntary, unpaid')
    with pytest.raises(ValueError,match='determination and its date'):
        arrangements(dict(data,ethics_status='approved'))
    with pytest.raises(ValueError,match='actual ethics'):
        arrangements(dict(data,ethics_status='invented'))
    with pytest.raises(ValueError,match='participation arrangement'):
        arrangements(dict(data,compensation_type='invented'))


def test_pending_determination_prepares_sample_without_inviting_reviewers(tmp_path,monkeypatch):
    from types import SimpleNamespace
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,gpu_hardware={},system_hardware={})
    try:
        owner=app.db.create_workspace('Pending study arrangements','local');store=app._human_store()
        root=tmp_path/'runs'/'source';root.mkdir()
        source=store.register_source(campaign=owner,name='Saved source',results=root)
        calls=[]
        def launch(command,params,**kwargs):
            calls.append(command);prepared(Path(params['--output']))
            return SimpleNamespace(job_id='sample-only')
        monkeypatch.setattr(app,'start_job',launch)
        data=dict(campaign_id=owner,source='scope-'+source,name='Workload only',mode='common',clusters='1',
            ethics_status='pending',ethics='',compensation_type='unpaid',compensation='Test terms',
            stop_contact='Test operator',consent='Synthetic consent only',acknowledge='1')
        code,location,_=app.handle('POST','/human-evaluation/prepare-study',data)
        assert code==303 and calls==['human_audit']
        monkeypatch.setattr(app.db,'load_job',lambda key:dict(state='complete',exit_code=0))
        page=app.handle('GET',location)[2].decode()
        assert '1 saved outputs, 2 required independent ratings' in page
        assert 'Ethics determination is not decided yet' in page
        assert 'Create study and assign reviewers' not in page
        assert app.handle('POST',location,{})[0]==400
        assert not store.studies(owner)
        assert app.handle('POST','/human-evaluation/prepare-study',dict(data,ethics_status='invented'))[0]==400
        assert calls==['human_audit']
    finally:app.close()


def test_finished_runs_discovered_without_cross_campaign_or_failed_run_sources(tmp_path):
    from experiments.rig_web_app.human_review_setup import sources
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,gpu_hardware={},system_hardware={})
    try:
        owner=app.db.create_workspace('Finished API','api');other=app.db.create_workspace('Different campaign','local')
        with app.db._conn:
            for key,exit_code,campaign in [('done',0,owner),('failed',1,owner),('unrelated',0,other)]:
                app.db._conn.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                    (key,'measured','run_matrix',str(tmp_path/'runs'/key),'pin','complete' if exit_code==0 else 'failed',exit_code,1))
                app.db._conn.execute('INSERT INTO campaign_members VALUES(?,?,?,?,?)',('external',key,campaign,'collection',1))
        assert [r['id'] for r in sources(app,owner)]==['run-done']
        assert 'Human evaluation' in app.handle('GET','/campaigns/'+owner)[2].decode()
    finally:app.close()


def test_preparation_uses_one_live_completion_snapshot_before_database_watcher(tmp_path,monkeypatch):
    from types import SimpleNamespace
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,gpu_hardware={},system_hardware={})
    try:
        owner=app.db.create_workspace('Completed campaign','local');store=app._human_store()
        path=store.root/'blank.csv';prepared(path)
        key=store.save_preparation(owner,'completed-process',dict(name='Race regression',mode='common',prepared=str(path),metadata={}))
        monkeypatch.setattr(app.db,'load_job',lambda key:dict(state='running',exit_code=None))
        live=SimpleNamespace(process=object(),exit_code=lambda:0,state=lambda:'complete')
        app.jobs['completed-process']=live
        body=app.handle('GET','/human-evaluation/preparations/'+key)[2].decode()
        assert 'Create study and assign reviewers' in body
        assert 'did not finish successfully' not in body
    finally:
        app.jobs.pop('completed-process',None);app.close()


@pytest.mark.parametrize('family', list(audit.SOURCE_TASK_VOCABULARY))
def test_source_task_wizard_consumes_native_export(tmp_path, monkeypatch, family):
    """Exercise the real CSV producer, not a separately invented UI fixture."""
    vocabulary = audit.SOURCE_TASK_VOCABULARY[family]
    meta = dict(source_task_family=family, model_spec='test:model', defense='none', attacker='replay',
        effective_modality='text', source='test-source', source_policy_id='test-policy',
        source_policy_version='test', source_policy_intended_metric='classification',
        source_policy_instruction='Return one source-task label.', datapoint_id='item-1',
        requested_seed=0, source_cluster_id='cluster-1', prepared_prompt='Classify this synthetic example.',
        prepared_response=vocabulary[0], prepared_media_references='[]')
    judgment = dict(run_id='run-1', attempt_id='attempt-1', raw={'model': 'test:model'})
    monkeypatch.setattr(audit, '_audit_artifacts', lambda *a, **k: ({}, {'sample-1': meta}, {'sample-1': judgment}, {}))
    sample = tmp_path/'sample.csv'
    assert audit.prepare_source_task_sample(tmp_path, sample, 1) == 0
    store = HumanReviewStore(tmp_path/'console.db', tmp_path/'reviews', allowed_roots=[tmp_path])
    try:
        study = store.create(campaign='test', name='Synthetic source-task flow', prepared=sample, mode='source_task',
            metadata=dict(ethics='test fixture', consent='test only', compensation='test only',
                          stop_contact='test operator', results=str(tmp_path)))
        token = store.enroll(study, 'test-rater', 'rater', qualification('source_task'))
        item = item_for(store, token)
        value = dict(task_label=vocabulary[0], parse_status_label='clean_single_label', confidence=4, notes='test only')
        store.save(token, item, revision=0, value=value, submit=True)
        assert store.summary(study)['counts']['submitted'] == 1
    finally:
        store.close()
