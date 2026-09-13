import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments import retained_prepared_judge_view as subject, retained_response_judge as judge
from experiments import retained_local_sources
from test_retained_native_judge_execute import retained  # noqa: F401
from test_retained_local_sources import source  # noqa: F401
from ura.runner import _component_config


@pytest.fixture
def prepared(retained,tmp_path,monkeypatch):  # noqa: F811
    origin=retained.source
    origin['generation_project_revision']['sha256']='d'*64
    origin['target_component']=_component_config(retained.reader().target)
    origin['runner_argv']=['--api',origin['target'],'--corpora','unit','--attackers','replay',
        '--judges','rules,guardrail','--target-answer-retries','0','--out',origin['out']]
    artifact=tmp_path/'recorded-source.json'
    artifact.write_text('{}')
    origin['files']=[subject.sources.metadata(artifact)]
    program=Path(origin['program'])
    program.write_text(json.dumps(dict(target=origin['target'],jobs=[dict(name=origin['job'],purpose='measured_run')])))
    payload=program.read_bytes()
    value=dict(status='prepared',judgments='not_executed',units=[origin],outputs=2,failed=[],
        programs=[dict(path=str(program),sha256=hashlib.sha256(payload).hexdigest(),bytes=len(payload))],
        target_calls=0,judge_calls=0,model_loads=0)
    monkeypatch.setattr(subject.sources,'load_program_job',lambda *a,**k:
        (origin,retained.reader(),retained.inputs,retained.responses))
    path=tmp_path/'preparation.json'
    path.write_text(json.dumps(value))
    return retained,value,path


def test_prepared_outputs_supply_candidates_without_fabricated_manifests_or_verdicts(prepared):
    records,value,path=prepared
    cells,metadata,identities,audit=judge._read_view(path)
    assert 'manifest' not in cells[0] and cells[0]['judgments']==[]
    assert all(set(row)=={'attempt_id'} for row in identities.values())
    assert len(metadata)==len(identities)==audit['policy_evaluable_samples']==2
    candidates,population=judge.load_candidates(path,include_match_identity=True)
    assert len(candidates)==population['eligible_usable_outputs']==2
    assert {row['attempt_id'] for row in candidates}==set(records.inputs)
    # Only the context access path differs; the retained candidate fields and
    # content identities remain byte-equivalent to the original view contract.
    legacy=copy.deepcopy(cells)
    legacy[0]['manifest']={'config':legacy[0].pop('generation_context')}
    legacy_candidates,_=judge._candidates_from_view(legacy,metadata,identities,audit,include_match_identity=True)
    assert candidates==legacy_candidates


def test_empty_output_exclusion_does_not_exclude_usable_truncation_or_depend_on_local_verdict(prepared):
    records,value,path=prepared
    keys=list(records.responses)
    records.responses[keys[0]]['response']['output_turns']=[]
    records.responses[keys[1]]['response']['raw']['output_truncated']=True
    records.judgments.clear()
    candidates,population=judge.load_candidates(path)
    assert len(candidates)==1 and candidates[0]['attempt_id']==keys[1]
    assert population['excluded_missing_outputs']==1


def test_prepared_diagnostics_cannot_enter_measured_haiku_selection(prepared):
    _,value,path=prepared
    program=Path(value['programs'][0]['path'])
    document=json.loads(program.read_text())
    document['jobs'][0]['purpose']='diagnostic_canary'
    program.write_text(json.dumps(document))
    value['programs'][0]['sha256']=hashlib.sha256(program.read_bytes()).hexdigest()
    view=subject.read_hosted_preparation(value)
    rows,audit=judge._candidates_from_view(*view,allow_empty=True)
    assert rows==[] and audit['excluded_diagnostic_outputs']==2


def test_input_inventory_retains_missing_rows_but_legacy_judge_selection_does_not(prepared):
    records,_value,path=prepared
    keys=list(records.responses)
    records.responses[keys[0]]['response']['output_turns']=[]
    view=judge._read_view(path)
    legacy,population=judge._candidates_from_view(*view,include_match_identity=True)
    complete,coverage=judge._candidates_from_view(*view,include_match_identity=True,include_missing=True)
    assert len(legacy)==1 and len(complete)==2
    assert next(row for row in complete if row['attempt_id']==keys[1])==legacy[0]
    assert population==coverage
    assert coverage['eligible_usable_outputs']==1 and coverage['excluded_missing_outputs']==1
    assert next(row for row in complete if row['attempt_id']==keys[0])['response_sha256']==hashlib.sha256(b'').hexdigest()


def test_source_task_rows_remain_outside_common_judging(prepared):
    records,value,_=prepared
    next(iter(records.inputs.values()))[0].meta['common_metrics_eligible']=False
    view=subject.read_hosted_preparation(value)
    rows,audit=judge._candidates_from_view(*view)
    assert len(rows)==1 and audit['excluded_source_authoritative_rows']==1


@pytest.mark.parametrize('change',['source-file','count','repeated-run','non-preparation'])
def test_changed_prepared_source_is_rejected(prepared,change):
    _,value,_=prepared
    if change=='source-file':
        Path(value['units'][0]['files'][0]['path']).write_text('changed')
    elif change=='count':
        value['outputs']+=1
    elif change=='repeated-run':
        value['units']*=2
    else:
        value['judgments']='complete'
    with pytest.raises(ValueError):
        subject.read_hosted_preparation(value)


def test_incomplete_source_count_remains_in_the_population(prepared):
    _,value,_=prepared
    value.update(status='preparation_incomplete',failed=[dict(
        program=value['programs'][0]['path'],job='pending-source',assigned=3)])
    _,audit=judge._candidates_from_view(*subject.read_hosted_preparation(value))
    assert audit['unprepared_outputs']==3


def test_old_preparation_accepts_only_inventory_order_difference(prepared,monkeypatch):
    records,value,_=prepared
    # Repeat a second actual file entry with its own path, as real grid/response inventories do.
    from pathlib import Path
    second=Path(records.source['out'])/'grid.json'
    second.write_text('{}')
    records.source['files'].append(subject.sources.metadata(second))
    actual={**records.source,'files':list(reversed(records.source['files']))}
    monkeypatch.setattr(subject.sources,'load_program_job',lambda *a,**k:
        (actual,records.reader(),records.inputs,records.responses))
    assert len(subject.read_hosted_preparation(value)[1])==2
    actual['runner_argv']=['changed']
    with pytest.raises(ValueError,match='source differs'):
        subject.read_hosted_preparation(value)


def test_partial_source_passes_exact_opt_in_and_keeps_unsaved_coverage(prepared,monkeypatch):
    from experiments.retained_judge_inventory import read_sources
    records,value,path=prepared
    records.source.update(incomplete_generation=True,generation_assigned=3,unsaved_input_ids=['pending'])
    def load(*a,**kwargs):
        assert kwargs['include_incomplete'] is True
        return records.source,records.reader(),records.inputs,records.responses
    monkeypatch.setattr(subject.sources,'load_program_job',load)
    rows,audit=judge._candidates_from_view(*subject.read_hosted_preparation(value))
    assert len(rows)==2 and audit['unprepared_outputs']==1
    assert audit['eligible_usable_outputs']==2
    path.write_text(json.dumps(value))
    assert read_sources([path])[3]['unprepared_outputs']==1


def test_generation_context_cannot_be_passed_as_a_manifest(prepared):
    _,_,path=prepared
    cells,*_=judge._read_view(path)
    cells[0]['manifest']={}
    with pytest.raises(ValueError,match='not a generation manifest'):
        judge._generation_config(cells[0])


def test_local_inventory_keeps_exact_runs_and_does_not_add_new_results(source,monkeypatch,tmp_path):  # noqa: F811
    root,cells=source
    inventory=retained_local_sources.prepare_sources([root])
    extra=copy.deepcopy(cells[0])
    extra['run_id']='other-run'
    cells.append(extra)
    monkeypatch.setattr(judge,'_read_native_view',lambda path:(cells,
        {'selected':{'run_id':'run-1'},'other':{'run_id':'other-run'}},
        {'selected':{'attempt_id':'attempt-1'},'other':{'attempt_id':'extra'}},{}))
    path=tmp_path/'sources.json'
    path.write_text(json.dumps(inventory))
    selected,metadata,records,_=judge._read_view(path)
    assert [cell['run_id'] for cell in selected]==['run-1']
    assert set(metadata)==set(records)=={'selected'}
    cells[0]['attempts']['attempt-1']['rendered_input'][0]['content']='changed source'
    with pytest.raises(ValueError,match='inventory changed'):
        judge._read_view(path)
