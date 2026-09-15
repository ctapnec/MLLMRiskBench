"""Personal review works directly, without becoming independent evidence."""
import csv
import io
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from experiments.rig_web import RigWebApp
from test_human_review_ui import prepared,valid_rating,qualification


@pytest.fixture
def personal(tmp_path,monkeypatch):
    app=RigWebApp(results_root=tmp_path/'runs',state_dir=tmp_path/'state',repo_root=tmp_path,
        gpu_hardware={},system_hardware={})
    owner=app.db.create_workspace('Saved answers','local')
    root=tmp_path/'runs'/'saved';root.mkdir()
    store=app._human_store()
    source=store.register_source(campaign=owner,name='Saved text answers',results=root)
    def start(command,params,**kwargs):
        assert command=='human_audit' and kwargs['campaign_id']==owner
        prepared(Path(params['--output']))
        return SimpleNamespace(job_id='sample-only')
    monkeypatch.setattr(app,'start_job',start)
    monkeypatch.setattr(app.db,'load_job',lambda key:dict(state='complete',exit_code=0))
    data=dict(campaign_id=owner,source='scope-'+source,name='My personal review',mode='common',clusters='1',acknowledge='1')
    try:yield app,owner,data
    finally:app.close()


def open_personal(personal):
    app,owner,data=personal
    status,location,_=app.handle('POST','/human-evaluation/prepare-personal',data)
    assert status==303
    page=app.handle('GET',location)[2].decode()
    assert 'Open evaluation form' in page and '1 personal evaluations' in page
    status,review,_=app.handle('POST',location,{})
    assert status==303 and review.startswith('/review/')
    store=app._human_store();study=store.studies(owner)[0]['id']
    return store,study,review.removeprefix('/review/')


def test_personal_default_has_actual_review_path_not_arrangement_fields(personal):
    app,owner,_=personal
    body=app.handle('GET','/human-evaluation?campaign_id='+owner)[2].decode()
    assert 'Prepare answers for review' in body and 'Independent two-rater study' in body
    assert "name='ethics_status'" not in body and "name='compensation'" not in body
    assert app.handle('GET','/human-evaluation?campaign_id='+owner+'&kind=independent')[2].count(b'data-study-wizard')>=1


def test_personal_save_resume_edit_and_export_never_complete_independent_assessment(personal):
    app,owner,_=personal
    store,study,token=open_personal(personal)
    item=store.view(token)['queue'][0]['id']
    assert store.view(token,item)['item']['response']=='A substantial example answer.'
    assert store.summary(study)['counts']['required_ratings']==1
    store.save(token,item,revision=0,value=valid_rating(),submit=True)
    assert not store.summary(study)['ready_for_analysis']
    with pytest.raises(ValueError):store.export(study)
    with pytest.raises(ValueError):store.enroll(study,'second','rater',qualification())
    assert app.handle('POST','/human-evaluation/'+study+'/analyse',{})[0]==400
    store.save(token,item,revision=1,value=dict(valid_rating(),notes='Reconsidered'),submit=True)
    rows=list(csv.DictReader(io.StringIO(store.personal_export(study).decode('utf-8-sig'))))
    assert len(rows)==1 and rows[0]['review_kind']=='personal_not_independent' and rows[0]['notes']=='Reconsidered'
    store.close();del app._human_reviews
    assert app._human_store().view(token,item)['item']['rating']['value']['notes']=='Reconsidered'
    assert app.db._query('SELECT count(*) n FROM campaign_judgments',())[0]['n']==0


def test_personal_incomplete_and_deferred_items_remain_in_export(personal):
    store,study,token=open_personal(personal)
    item=store.view(token)['queue'][0]['id']
    rows=list(csv.DictReader(io.StringIO(store.personal_export(study).decode('utf-8-sig'))))
    assert rows[0]['state']=='unstarted' and rows[0]['label']==''
    store.save(token,item,revision=0,value=dict(defer_reason='Unreadable'),defer=True)
    assert store.summary(study)['counts']['submitted']==0
    assert 'deferred' in store.personal_export(study).decode()


def test_personal_missing_media_blocks_a_final_rating_not_a_draft(personal):
    store,study,token=open_personal(personal)
    item=store.view(token)['queue'][0]['id']
    with store.conn:
        store.conn.execute('UPDATE human_items SET media=? WHERE study=? AND id=?',
            (json.dumps([dict(locator='@media-root/0/absent.png',mime='image/png',modality='image')]),study,item))
    store.save(token,item,revision=0,value=valid_rating())
    with pytest.raises((ValueError,OSError)):
        store.save(token,item,revision=1,value=dict(valid_rating(),media_viewed=True),submit=True)
    assert store.summary(study)['counts']['submitted']==0
