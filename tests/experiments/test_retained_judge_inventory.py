"""Complete input matching is independent of whether a model answered."""
import copy

import pytest

from experiments import retained_judge_inventory as subject
from experiments import retained_response_judge as retained
from test_retained_response_judge_pair import _candidate, _population


def rows(cohort,count=1,input_index=0):
    return [_candidate(index,cohort=cohort,input_index=input_index) for index in range(count)]


def inventory(local,hosted,**kwargs):
    return subject.build_inventory(local,hosted,local_audit=_population(len(local)),
        hosted_audit=_population(len(hosted)),**kwargs)


def test_every_local_model_answer_is_included_once_not_one_counterpart_per_hosted_answer():
    result=inventory(rows('local',5),rows('hosted',3))
    assert result['selection']['selected_inputs']==1
    assert result['coverage']==dict(retained_outputs=8,judgeable_text=8,missing_text=0,
        hosted_inputs_without_local_records=0)
    assert len(result['outputs'])==8 and len(result['inputs'])==1
    assert result['inputs'][0]['local']['retained_outputs']==5
    assert result['target_calls']==result['judge_calls']==0 and result['budget_created'] is False


@pytest.mark.parametrize('cohort',['local','hosted'])
def test_missing_answers_stay_in_input_coverage_without_becoming_judgeable(cohort):
    local,hosted=rows('local',5),rows('hosted',3)
    for row in local if cohort=='local' else hosted:
        row['response_sha256']=subject.EMPTY_RESPONSE_SHA256
    result=inventory(local,hosted)
    assert result['selection']['selected_inputs']==1
    assert result['inputs'][0][cohort]['judgeable_text']==0
    assert len(result['outputs'])==8
    assert result['coverage']['missing_text']==(5 if cohort=='local' else 3)
    assert not result['coverage']['hosted_inputs_without_local_records']


def test_input_prefix_does_not_change_when_answer_availability_or_model_count_changes():
    local=[_candidate(i,cohort='local') for i in range(30)]
    hosted=[_candidate(i,cohort='hosted') for i in range(30)]
    first=inventory(local,hosted,input_limit=7,seed=8)
    changed=copy.deepcopy(hosted)
    for row in changed[::2]:
        row['response_sha256']=subject.EMPTY_RESPONSE_SHA256
    additional=_candidate(100,cohort='local',input_index=4)
    second=inventory(list(reversed(local))+[additional],list(reversed(changed)),input_limit=7,seed=8)
    assert [row['input_identity_sha256'] for row in first['inputs']]==[
        row['input_identity_sha256'] for row in second['inputs']]


def test_unmatched_hosted_inputs_remain_explicit_not_silently_dropped():
    result=inventory(rows('local',input_index=1),rows('hosted',input_index=2))
    assert result['selection']['selected_inputs']==1
    assert result['coverage']['hosted_inputs_without_local_records']==1
    assert result['inputs'][0]['local']['retained_outputs']==0
    assert len(result['outputs'])==1


@pytest.mark.parametrize('field',['requested_seed','source_policy_version','media_references_sha256'])
def test_same_prompt_is_not_enough_to_match_another_seed_policy_or_image(field):
    local,hosted=rows('local'),rows('hosted')
    hosted[0][field]=1 if field=='requested_seed' else 'different'
    hosted[0]['input_identity_sha256']=retained._sha({name:hosted[0][name] for name in retained._MATCH_IDENTITY_FIELDS})
    assert inventory(local,hosted)['coverage']['hosted_inputs_without_local_records']==1


def test_duplicate_saved_answer_is_not_counted_twice():
    local=rows('local')
    with pytest.raises(ValueError,match='more than once'):
        inventory(local+local,rows('hosted'))


def test_changed_identity_is_rejected():
    local=rows('local')
    local[0]['input_identity_sha256']='f'*64
    with pytest.raises(ValueError,match='identity differs'):
        inventory(local,rows('hosted'))


def test_incremental_preparation_removes_obsolete_pending_job_counts(tmp_path,monkeypatch):
    first,second=tmp_path/'first.json',tmp_path/'second.json'
    first.touch()
    second.touch()
    seen=[]
    def read(path):
        seen.append(path)
        run='a' if path==first else 'b'
        audit=dict(policy_evaluable_samples=1,common_ineligible_evaluable_rows_excluded=0,
            prepared_source_jobs=[('program',run)],unprepared_source_jobs=[dict(program='program',job='b',assigned=4)] if run=='a' else [])
        return [dict(run_id=run)],{run:{}},{run:{}},audit
    monkeypatch.setattr(retained,'_read_view',read)
    result=subject.read_sources([first,first,second])
    assert seen==[first,second]
    assert result[3]['policy_evaluable_samples']==2 and result[3]['unprepared_outputs']==0


def test_disjoint_source_views_cannot_hide_duplicate_runs(tmp_path,monkeypatch):
    paths=[tmp_path/'first.json',tmp_path/'second.json']
    for path in paths:
        path.touch()
    monkeypatch.setattr(retained,'_read_view',lambda _:([dict(run_id='same')],{}, {},dict(policy_evaluable_samples=0)))
    with pytest.raises(ValueError,match='overlap'):
        subject.read_sources(paths)
