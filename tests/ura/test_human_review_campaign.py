"""Retained index -> native blank form -> isolated ratings -> sample analysis."""
import csv
import gzip
import json
from pathlib import Path

import pytest

from experiments import human_audit as audit
from experiments import human_review_campaign as review
from experiments.rig_web_app.human_review_inventory import read_campaign
from experiments.rig_web_app.human_review_store import HumanReviewStore
from experiments.rig_web import RigWebApp
from test_human_review_inventory import indexed
from test_human_review_ui import qualification, item_for, valid_rating


def test_real_producer_index_to_two_rater_report(indexed,tmp_path):
    database,owner,root,_=indexed
    inventory=read_campaign(database,owner,root); sample=tmp_path/'sample.csv'
    report=review.prepare(inventory,sample,mode='common',clusters=0,results_root=root)
    assert report['selected_outputs']==2 and report['selected_clusters']==1
    assert report['assignment_outcomes']=={'usable':2,'missing':1}
    assert report['human_ratings']==report['target_calls']==report['judge_calls']==0
    store=HumanReviewStore(tmp_path/'human.db',tmp_path/'reviews',allowed_roots=[tmp_path])
    try:
        study=store.create(campaign=owner,name='Synthetic integration only',prepared=sample,mode='common',
            metadata=dict(ethics='fixture',consent='fixture',compensation='fixture',stop_contact='fixture',results=str(root)))
        for name in ('independent-one','independent-two'):
            token=store.enroll(study,name,'rater',qualification())
            store.consent(token)
            for item in store.view(token)['queue']:
                store.save(token,item['id'],revision=0,value=dict(valid_rating(),label='refusal',refusal_label='refusal'),submit=True)
        labels=tmp_path/'labels.csv';labels.write_bytes(store.export(study))
        result=review.analyse(sample.with_suffix('.SNAPSHOT.json.gz'),sample,labels,tmp_path/'report.json',bootstrap_resamples=10)
        assert result['rated_outputs']==2 and result['independent_ratings']==4
        assert result['judge_comparisons'][0]['coverage']==1
        assert result['judge_comparisons'][0]['agreement']['exact_label_accuracy_diagnostic']==1
        assert result['dimensions']['refusal_label']['agreement']==1
        altered=json.loads(gzip.decompress(sample.with_suffix('.SNAPSHOT.json.gz').read_bytes()))
        altered['outputs'][0]['metadata']['prepared_response']='Changed answer'
        changed=tmp_path/'changed.json.gz'
        with gzip.open(changed,'wt') as stream:json.dump(altered,stream)
        with pytest.raises(ValueError,match='frozen saved output'):
            review.analyse(changed,sample,labels,tmp_path/'invalid.json',bootstrap_resamples=10)
        with pytest.raises(ValueError,match='not overwritten'):
            review.prepare(inventory,sample,mode='common',clusters=0,results_root=root)
    finally:store.close()


def test_invalid_judge_not_imputed_safe_and_absent_verdict_does_not_drop_output(indexed,tmp_path):
    database,owner,root,_=indexed
    inventory=read_campaign(database,owner,root)
    inventory['outputs'][0]['judgments']['local-cascade-test'].update(status='invalid',label='refusal')
    inventory['outputs'][1]['judgments']={}
    sample=tmp_path/'sample.csv'
    review.prepare(inventory,sample,mode='common',clusters=0,results_root=root)
    predictions,meta,identities,_=review._view(inventory['outputs'])
    assert len(meta)==len(identities)==2
    assert predictions=={'local-cascade-test':{}}


@pytest.mark.parametrize('family',list(audit.SOURCE_TASK_VOCABULARY))
def test_source_task_keeps_native_parser_frame(indexed,tmp_path,family):
    database,owner,root,_=indexed
    inventory=read_campaign(database,owner,root); label=audit.SOURCE_TASK_VOCABULARY[family][0]
    for row in inventory['outputs']:
        row['metadata'].update(common_metrics_eligible=False,source_task_family=family,
            source_task_evaluation=dict(prediction=label,reference=label,valid=True))
    sample=tmp_path/'sample.csv';review.prepare(inventory,sample,mode='source_task',clusters=0,results_root=root)
    with sample.open(encoding='utf-8-sig',newline='') as stream:
        reader=csv.DictReader(stream);fields=reader.fieldnames;blanks=list(reader)
    labels=tmp_path/'labels.csv'
    with labels.open('w',encoding='utf-8-sig',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        for row in {r['sample_key']:r for r in blanks}.values():
            for rater in ('one','two'):
                writer.writerow(dict(row,rater_id=rater,task_label=label,parse_status_label='clean_single_label',confidence='4'))
    report=review.analyse(sample.with_suffix('.SNAPSHOT.json.gz'),sample,labels,tmp_path/'report.json')
    assert 'judge_comparisons' not in report
    assert report['source_task_families'][family]['human_reference']['agreement']==1


def test_indexed_campaign_setup_uses_readonly_snapshot_job(indexed,tmp_path,monkeypatch):
    database,owner,root,_=indexed
    app=RigWebApp(results_root=root,state_dir=database.parent,repo_root=tmp_path,gpu_hardware={},system_hardware={})
    starts=[]
    def start(command,params,**kwargs):
        from types import SimpleNamespace
        starts.append((command,params,kwargs));return SimpleNamespace(job_id='prepared-job')
    monkeypatch.setattr(app,'start_job',start)
    try:
        body=app.handle('GET','/human-evaluation?campaign_id='+owner)[2].decode()
        assert 'All indexed measured campaign outputs' in body and 'smallest sample' in body
        data=dict(campaign_id=owner,source='campaign-index',name='Synthetic setup',mode='common',clusters='0',
            acknowledge='1',ethics='fixture',compensation='fixture',stop_contact='fixture',consent='fixture')
        assert app.handle('POST','/human-evaluation/prepare-study',data)[0]==303
        command,params,options=starts[0]
        assert command=='human_review_campaign' and params['--campaign']==owner
        assert params['--database']==str(database) and options['campaign_id']==owner
        assert not app._human_store().studies(owner)
    finally:app.close()


def test_coverage_lookup_matches_previous_matcher_without_cross_scanning(monkeypatch):
    rows=[]
    for i in range(100):
        rows.append(dict(sample_key=str(i),cluster_key='cluster-'+str(i%10),_stratum='stratum',
            run_id='run-'+str(i%3),_corpus='corpus',_model_spec='model',_defense='none',_attacker='replay',
            source='source',source_policy_id='policy',source_policy_version='1',common_metrics_eligible=True,
            expected_behavior='refuse' if i%2 else 'safe_answer',risk_category='risk-'+str(i%3),modality='text'))
    requirements=audit._observed_coverage_requirements(rows)
    expected={c:{r['requirement_id'] for r in requirements if any(audit._candidate_matches_requirement(row,r) for row in rows if row['cluster_key']==c)} for c in {r['cluster_key'] for r in rows}}
    def forbidden(*args):raise AssertionError('Quadratic candidate-requirement scan')
    monkeypatch.setattr(audit,'_candidate_matches_requirement',forbidden)
    selected,clusters,_,details=audit._select_sample_clusters(rows,None,requirements)
    assert selected and clusters and details['all_required_cells_covered']
    assert set(details['covered_cell_ids'])==set().union(*(expected[c] for c in clusters))
    for key,count in details['selected_clusters_per_required_cell'].items():
        assert count==sum(key in expected[c] for c in clusters)
