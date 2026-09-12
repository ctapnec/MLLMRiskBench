import copy
import json
from pathlib import Path

import pytest

from experiments import hosted_selected_replays as subject
from experiments import hosted_retained_inputs as inputs
from test_retained_input_replay import _fixture, DESC


@pytest.fixture
def selected(tmp_path,monkeypatch):
    points,left,_,bindings,_,_ = _fixture(tmp_path,image=True,source_media_count=1,adaptive=True)
    right = copy.deepcopy(left)
    right['run_id'] = 'other-run'
    right['manifest']['config']['run']['corpus'] = 'other-arm'
    for attempt in right['attempts'].values():
        attempt['run_id'] = right['run_id']
    artifact = tmp_path/'other.attempts.jsonl'
    artifact.write_text('\n'.join(json.dumps(row) for row in right['attempts'].values())+'\n')
    right['artifacts']['attempts'] = artifact
    cells = [left,right]
    second = 'example:second'
    budget = copy.deepcopy(bindings['budget'])
    budget['routes'].append(dict(budget['routes'][0],target_spec=second))
    budget.pop('projection_id')
    budget['projection_id'] = 'hosted-budget-'+inputs._sha(budget)[:24]
    api = {**bindings['api_config'],second:{'modalities':['text','image']}}
    monkeypatch.setattr(subject,'load_sources',lambda inventory: cells)
    conversions = []
    def restore(selected_cells):
        conversions.append([cell['run_id'] for cell in selected_cells])
        return {cell['run_id']:points for cell in selected_cells}
    monkeypatch.setattr(subject,'source_populations',restore)
    kwargs = dict(inventory={'schema':subject.SOURCE_SCHEMA},inventory_descriptor=DESC,
        budget=budget,budget_descriptor=DESC,api_config=api,api_descriptor=DESC,out_root=tmp_path/'prepared')
    return cells,kwargs,conversions


def test_all_models_and_corpora_keep_exact_dialogue_and_shared_source_work(selected):
    cells,kwargs,conversions = selected
    value = subject.prepare(**kwargs)
    assert conversions == [['local-run','other-run']]
    assert value['unique_selected_inputs'] == 4 and value['selected_local_source_conditions'] == 4
    assert len(value['routes']) == 2 and all(len(route['replay_artifacts']) == 2 for route in value['routes'])
    assert value['target_calls'] == value['judge_calls'] == value['model_loads'] == 0
    assert value['paid_execution_authorized'] is False
    for route in value['routes']:
        for descriptor in route['replay_artifacts']:
            replay = json.loads(Path(descriptor['path']).read_text())
            for entry in replay['entries']:
                original = entry['origin']['original_attempt']['rendered_input']
                delivered = entry['rendered_input']
                assert [turn['content'] for turn in original] == [turn['content'] for turn in delivered]
                assert [[ref['sha256'] for ref in turn.get('media',[])] for turn in original] == [
                    [ref['sha256'] for ref in turn.get('media',[])] for turn in delivered]
    assert json.loads((kwargs['out_root']/'prepared-replays.json').read_text()) == value


def test_response_quality_never_changes_replay_selection(selected):
    cells,kwargs,_ = selected
    first = subject.prepare(**kwargs)
    for cell in cells:
        cell['responses'] = {'irrelevant':'Different answer quality and truncation'}
        for row in cell['judgments']:
            row.update(label='safe',score=0)
    second = subject.prepare(**dict(kwargs,out_root=kwargs['out_root'].with_name('again')))
    assert first['route_summary'] == second['route_summary']
    for left,right in zip(first['routes'],second['routes']):
        for a,b in zip(left['replay_artifacts'],right['replay_artifacts']):
            assert Path(a['path']).read_bytes() == Path(b['path']).read_bytes()


def test_too_small_cluster_cap_fails_before_conversion_or_output_creation(selected):
    _,kwargs,conversions = selected
    budget = kwargs['budget']
    for route in budget['routes']:
        route['paid_call_cap'] = 1
    budget.pop('projection_id')
    budget['projection_id'] = 'hosted-budget-'+inputs._sha(budget)[:24]
    with pytest.raises(ValueError,match='no complete compatible source cluster'):
        subject.prepare(**kwargs)
    assert not conversions and not kwargs['out_root'].exists()


def test_existing_output_cannot_be_overwritten(selected):
    _,kwargs,conversions = selected
    kwargs['out_root'].mkdir()
    with pytest.raises(ValueError,match='new resolved output'):
        subject.prepare(**kwargs)
    assert not conversions


def test_cli_shares_the_preparation_function(selected,monkeypatch):
    _,kwargs,_ = selected
    documents = {'source':(kwargs['inventory'],DESC),'budget':(kwargs['budget'],DESC),
                 'api':(kwargs['api_config'],DESC)}
    monkeypatch.setattr(subject,'load_bound_json',lambda path,digest: documents[str(path)])
    argv = ['--local-inventory','source','--budget','budget','--api-config','api','--out-root',str(kwargs['out_root'])]
    for name in ('local-inventory','budget','api-config'):
        argv += ['--'+name+'-sha256','a'*64]
    assert subject.main(argv) == 0
    assert len(json.loads((kwargs['out_root']/'prepared-replays.json').read_text())['routes']) == 2
