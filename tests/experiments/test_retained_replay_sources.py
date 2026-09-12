"""Saved inputs resolve without controller-specific corpus/media JSON scripts."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import retained_replay_sources as subject, run_matrix
from ura.artifact_checks import artifact_verification
from ura.converters._common import canonical_converted_corpus_sha256 as corpus_digest
from ura.data_models import DataPoint, DialogTurn, MediaRef


@pytest.fixture
def retained(tmp_path, monkeypatch):
    location = tmp_path / 'original.jsonl'
    location.write_text('retained converter source')
    points = [DataPoint(id=str(i), source='source', modalities=['text'], payload_text=f'Question {i}',
        risk_category='jailbreak', expected_behavior='refuse') for i in range(4)]
    monkeypatch.setenv('TEST_REPLAY_SOURCE', str(location))
    calls = []
    def parse(path):
        calls.append(path)
        return points
    monkeypatch.setattr(run_matrix, 'get_converter', lambda name: SimpleNamespace(parse=parse))
    def cell(name, indices):
        selected = [points[i] for i in indices]
        return dict(run_id=name, manifest=dict(dataset_hashes={'corpus':corpus_digest(selected)},
            config={'run':dict(corpus='ordinary-arm', sampling_audit=dict(
                source_instance=dict(converter='ordinary', path_env='TEST_REPLAY_SOURCE', path_env_required=True),
                full_converted_corpus_sha256=corpus_digest(points), selected_indices=indices,
                selected_ids=[point.id for point in selected]))}),
            responses={'failed_output': True}, judgments=[])
    return points, cell, calls


def test_original_subset_order_and_shared_conversion(retained):
    points, cell, calls = retained
    first, second = cell('first', [3, 1]), cell('second', [0, 2])
    populations = subject.source_populations([first, second])
    assert populations == {'first':[points[3], points[1]], 'second':[points[0], points[2]]}
    assert len(calls) == 1
    first['responses'] = {'usable': 'Changed answer, not an input selection'}
    first['judgments'] = ['safe']
    assert subject.source_populations([first])['first'] == populations['first']


@pytest.mark.parametrize('indices', [[-1], [4], [True], [1, 1], [{}], None])
def test_invalid_original_positions_are_not_resampled(retained, indices):
    _, cell, _ = retained
    source = cell('run', [1])
    source['manifest']['config']['run']['sampling_audit']['selected_indices'] = indices
    with pytest.raises(ValueError, match='positions'):
        subject.source_populations([source])


@pytest.mark.parametrize('change', ['full', 'selected', 'ids'])
def test_changed_original_population_is_not_silently_replaced(retained, change):
    _, cell, _ = retained
    source = cell('run', [1])
    audit = source['manifest']['config']['run']['sampling_audit']
    if change == 'full':
        audit['full_converted_corpus_sha256'] = 'f'*64
    elif change == 'selected':
        source['manifest']['dataset_hashes']['corpus'] = 'f'*64
    else:
        audit['selected_ids'] = ['wrong-input']
    with pytest.raises(ValueError, match='differs'):
        subject.source_populations([source])


def test_missing_original_sampling_record_and_duplicate_run(retained):
    _, cell, _ = retained
    source = cell('run', [1])
    with pytest.raises(ValueError, match='more than once'):
        subject.source_populations([source, source])
    del source['manifest']['config']['run']['sampling_audit']
    with pytest.raises(ValueError, match='original sampling'):
        subject.source_populations([source])


@pytest.fixture
def media(tmp_path):
    path = tmp_path/'original.png'
    path.write_bytes(b'original media payload')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    ref = MediaRef(modality='image', path=str(path), mime='image/png', sha256=digest)
    point = DataPoint(id='image', source='source', modalities=['text', 'image'],
        dialog_history=[DialogTurn(role='user', content='Look at this image', media=[ref])],
        risk_category='jailbreak', expected_behavior='refuse')
    row = dict(rendered_input=[dict(role='user', content='Exact retained prompt',
        media=[dict(modality='image', path='sha256:'+digest, mime='image/png', sha256=digest)])])
    return path, digest, point, row


def test_original_dialog_media_resolved_without_scan_or_default_file_hash(media, monkeypatch):
    path, digest, point, row = media
    monkeypatch.setattr(Path, 'rglob', lambda *a: pytest.fail('Unexpected result-store scan'))
    monkeypatch.setattr(Path, 'open', lambda *a, **kw: pytest.fail('Default resolution rehashed media'))
    assert subject.source_media_index([row], {'run':[point]}) == {digest:str(path)}
    assert row['rendered_input'][0]['media'][0]['path'] == 'sha256:'+digest


def test_retained_generated_media_alias_uses_configured_roots(media, monkeypatch):
    path, digest, _, row = media
    row['rendered_input'][0]['media'][0]['path'] = '@media-root/0/original.png'
    monkeypatch.setenv('URA_MEDIA_ROOTS', str(path.parent))
    assert subject.source_media_index([row], {}) == {digest:str(path)}
    row['rendered_input'][0]['media'][0]['path'] = '@media-root/0/../outside.png'
    with pytest.raises((ValueError, PermissionError), match='escapes'):
        subject.source_media_index([row], {})


def test_unresolved_selected_media_needs_explicit_location_not_filename_guess(media):
    _, _, _, row = media
    with pytest.raises(ValueError, match='original file location'):
        subject.source_media_index([row], {})


def test_explicit_media_resolution_and_checksum_opt_in(media):
    path, digest, _, row = media
    assert subject.source_media_index([row], {}, {digest:str(path), 'f'*64:'unused'}) == {digest:str(path)}
    path.write_bytes(b'changed')
    with artifact_verification(verify_sha256=True), pytest.raises(ValueError, match='bytes changed'):
        subject.source_media_index([row], {}, {digest:str(path)})


def test_remote_media_is_not_downloaded(media):
    _, _, point, row = media
    remote = copy.deepcopy(row)
    ref = remote['rendered_input'][0]['media'][0]
    ref.pop('path')
    ref['uri'] = 'https://example.invalid/image.png'
    with pytest.raises(ValueError, match='never fetches remote'):
        subject.source_media_index([remote], {'run':[point]})


def test_cli_materializes_selected_sources_without_manual_corpus_or_media_json(tmp_path, monkeypatch):
    from experiments import hosted_retained_inputs as inputs, retained_local_sources as local
    from experiments.rig_web_app.catalog import build_argv
    cells = [dict(run_id='selected-run'), dict(run_id='unselected-run')]
    selected = dict(corpus='arm', local_sources=[dict(run_id='selected-run')], rendered_input=[
        dict(role='user', media=[dict(path='sha256:'+'a'*64)])])
    unused = dict(corpus='other-arm', local_sources=[dict(run_id='unselected-run')],
        rendered_input=[dict(role='user', media=[dict(path='unavailable-video')])])
    inventory = dict(schema=local.SCHEMA)
    desc = dict(file='bound.json', sha256='a'*64, bytes=10)
    monkeypatch.setattr(inputs, 'load_bound_json', lambda *a: (inventory, desc))
    monkeypatch.setattr(local, 'load_sources', lambda value: cells)
    monkeypatch.setattr(inputs, 'candidates_from_cells', lambda value: [selected, unused])
    monkeypatch.setattr(inputs, '_plan_selection', lambda **kw: ({}, 1, ['image'], [selected], {}))
    observed = {}
    def populations(value):
        observed['cells'] = value
        return {'selected-run':['original-point']}
    def media_index(value, sources):
        observed['media_candidates'] = value
        return {'a'*64:'resolved.png'}
    def materialize(plan, **kwargs):
        observed['materialization'] = kwargs
        return dict(replay_id='no-call-replay', status='no_call_materialized', entries=[selected])
    monkeypatch.setattr(subject, 'source_populations', populations)
    monkeypatch.setattr(subject, 'source_media_index', media_index)
    monkeypatch.setattr(inputs, 'build_plan', lambda **kw: dict(selected=[selected]))
    monkeypatch.setattr(inputs, 'materialize_replay', materialize)
    values = {'--'+name:'bound.json' for name in ('budget','api-config','local-inventory')}
    values.update({'--'+name+'-sha256':'a'*64 for name in ('budget','api-config','local-inventory')})
    values.update({'--target':'test:model', '--materialize-corpus':'arm', '--out':str(tmp_path/'replay.json')})
    argv = build_argv('hosted_retained_inputs', values)
    assert inputs.main(argv[argv.index('experiments.hosted_retained_inputs')+1:]) == 0
    assert observed['cells'] == [cells[0]]
    assert observed['media_candidates'] == [selected]
    assert observed['materialization']['source_corpora'] == {'selected-run':['original-point']}
    assert observed['materialization']['media_index'] == {'a'*64:'resolved.png'}
    assert json.loads((tmp_path/'replay.json').read_text())['entries'] == [selected]
