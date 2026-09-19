import json
import sqlite3
import pytest
from experiments.response_svm_sources import indexed_candidates
from test_response_svm import dataset_fixture


@pytest.mark.parametrize('checkpoint',[False,True])
def test_indexed_metadata_reads_attempts_including_failed_outputs_without_reconstruction(tmp_path,monkeypatch,checkpoint):
    fixture=dataset_fixture(tmp_path)
    model='ollama:fixture'
    attempt=dict(run_id='run-1',id='attempt-1',target=model,attacker='replay',seed=7,
        rendered_input=[dict(role='user',content='Saved prompt')],
        params=dict(planning_source='source',source_cluster_id='cluster',planning_expected_behavior='refuse',
                    planning_source_policy=None))
    response=dict(run_id='run-1',attempt_id='attempt-1',target=model,output_turns=[])
    path=tmp_path/('run.responses.checkpoint.jsonl' if checkpoint else 'run.responses.jsonl')
    path.write_text(json.dumps(dict(run_id='run-1',attempt=attempt,response=response) if checkpoint else response)+'\n')
    if not checkpoint:
        (tmp_path/'run.attempts.jsonl').write_text(json.dumps(attempt)+'\n')
    with sqlite3.connect(fixture['database']) as db:
        db.execute('UPDATE campaign_assignments SET model=?',(model,))
        db.execute('UPDATE campaign_responses SET outcome=?,details=?',('missing',json.dumps(dict(source_ref=str(path)+':1'))))
    before=fixture['database'].read_bytes()
    import subprocess
    monkeypatch.setattr(subprocess,'run',lambda *a,**kw:pytest.fail('No historical validator or corpus reconstruction'))
    rows,report=indexed_candidates(fixture['database'],'campaign')
    assert len(rows)==1 and rows[0]['rendered_input']==attempt['rendered_input']
    assert rows[0]['input_identity_sha256']=='input' and rows[0]['source_cluster_id']=='cluster'
    assert report['corpus_reconstructions']==report['model_file_reads']==0
    assert not report['checksum_revalidation'] and not report['dispositions']
    assert fixture['database'].read_bytes()==before
    # The analysis index cannot silently point at another model's response.
    if checkpoint:response['target']='ollama:wrong';raw=dict(run_id='run-1',attempt=attempt,response=response)
    else:raw=dict(response,target='ollama:wrong')
    path.write_text(json.dumps(raw)+'\n')
    with pytest.raises(ValueError,match='ownership differs'):indexed_candidates(fixture['database'],'campaign')
