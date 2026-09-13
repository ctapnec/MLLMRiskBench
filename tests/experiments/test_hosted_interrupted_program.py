import copy
import json

import pytest

from experiments import hosted_checkpoint_resume as subject, hosted_retained_execute as retained
from experiments.hosted_retained_inputs import _descriptor
from test_hosted_interrupted_renewal import prepared


def program_fixture(tmp_path, monkeypatch):
    _, _, _, calls, original, resumed, key, found, snapshot = prepared(tmp_path)
    original.job['name'] = 'original'
    old_out = tmp_path / 'old'
    old_out.mkdir()
    snapshot['budget_id'] = 'old-grid'
    budget = old_out / 'old-grid.budget.json'
    budget.write_text(json.dumps(snapshot))
    old_program = dict(original.program, schema=retained.COUNTED_INPUT_SCHEMA,
        requests=original.requests, jobs=[original.job], budget_plan_sha256=original.budget.expected_plan_sha256)
    previous = tmp_path / 'previous.json'
    previous.write_text(json.dumps(old_program))
    config = tmp_path / 'one-input.json'
    config.write_text(json.dumps({'replay': dict(replay_artifact=str(tmp_path / 'replay.json'),
        replay_artifact_sha256=original.attacker.replay_artifact_sha256, retained_input_ids=[key])}))
    job = copy.deepcopy(resumed.job)
    job['name'] = 'renewed'
    job['argv'] += ['--api', original.program['target'], '--attackers', 'replay',
        '--corpora', 'retained-corpus', '--judges', 'rules,guardrail', '--max-total-target-calls', '1',
        '--max-total-http-attempts', '4', '--max-total-judge-calls', '1', '--target-answer-retries', '0',
        '--attacker-config', str(config), '--attacker-config-sha256', _descriptor(config)['sha256']]
    program = dict(old_program, schema=subject.RENEWAL_SCHEMA, jobs=[job], requests={key: original.requests[key]},
        interrupted_predecessor=dict(program=_descriptor(previous), job='original', logical_budget=_descriptor(budget),
            prior_http_attempts=1))
    context, validations = object(), []
    dispatch = retained._validated_jobs

    def validate(value, money, *, local_context=None):
        assert value == old_program and money is original.budget and local_context is context
        validations.append(True)
        return [original]

    monkeypatch.setattr(retained, '_validated_jobs', validate)
    from experiments.rig_web_app import workspace_import
    records = [(dict(params=dict(retained_origin=original.entries[k]['origin'])),
        dict(target=original.program['target']), 'original-checkpoint:1') for k in found]
    monkeypatch.setattr(workspace_import, '_responses', lambda job: iter(records))
    return program, original.budget, context, validations, calls, dispatch, key


def test_standard_execution_dispatch_admits_only_the_inspected_interrupted_input(tmp_path, monkeypatch):
    program, budget, context, validations, calls, dispatch, key = program_fixture(tmp_path, monkeypatch)
    jobs = dispatch(program, budget, local_context=context)
    assert len(jobs) == 1 and jobs[0].transport_recoveries == {key: 1}
    assert set(jobs[0].entries) == {key} and validations == [True] and not calls


@pytest.mark.parametrize('change', ['source', 'prefix', 'budget_source', 'responses'])
def test_renewed_program_rejects_changed_history_before_dispatch(tmp_path, monkeypatch, change):
    program, budget, context, _, calls, dispatch, key = program_fixture(tmp_path, monkeypatch)
    if change == 'source':
        program['max_output_tokens'] += 1
    if change == 'prefix':
        program['interrupted_predecessor']['prior_http_attempts'] = 2
    if change == 'budget_source':
        path = tmp_path / 'other.budget.json'
        original = program['interrupted_predecessor']['logical_budget']['path']
        from pathlib import Path
        path.write_bytes(Path(original).read_bytes())
        program['interrupted_predecessor']['logical_budget'] = _descriptor(path)
    if change == 'responses':
        from experiments.rig_web_app import workspace_import
        monkeypatch.setattr(workspace_import, '_responses', lambda job: iter(()))
    with pytest.raises(ValueError):
        dispatch(program, budget, local_context=context)
    assert not calls


@pytest.mark.parametrize('full_checks', [False, True])
def test_renewal_keeps_modern_local_source_context_and_cache(tmp_path, monkeypatch, full_checks):
    inventory = tmp_path / 'sources.json'
    inventory.write_text(json.dumps(dict(source_roots=[str(tmp_path / 'retained')])) )
    previous = dict(schema=retained.LOCAL_SOURCES_SCHEMA, sources=dict(local_sources=_descriptor(inventory)))
    original = tmp_path / 'original.json'
    original.write_text(json.dumps(previous))
    program = dict(schema=subject.RENEWAL_SCHEMA, interrupted_predecessor=dict(program=_descriptor(original)))
    expected_key = retained._local_context_key(previous)
    assert retained._local_context_key(program) == expected_key
    sentinel, calls = object(), []

    def load(value):
        assert value == previous
        calls.append('load')
        return sentinel

    def cached(key, loader, *, paths, trees):
        assert key == expected_key and paths == (inventory,)
        assert trees == (tmp_path / 'retained',)
        calls.append('cache')
        return loader()

    monkeypatch.setattr(retained, 'artifact_sha256_enabled', lambda: full_checks)
    monkeypatch.setattr(retained, '_load_local_cells', load)
    monkeypatch.setattr(retained._LOCAL_CONTEXT_CACHE, 'get', cached)
    assert retained._validated_local_cells(program) is sentinel
    assert calls == (['load'] if full_checks else ['cache', 'load'])
