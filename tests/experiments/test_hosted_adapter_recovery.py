"""Reviewed parser repair preserves paid history and does not enable answer retries."""
from __future__ import annotations

import copy
import hashlib
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_retained_execute as subject
from experiments.hosted_attempt_budget import AttemptBudget, BudgetError, create_budget
from test_hosted_retained_execute import _runner
from test_retained_input_replay import _fixture
from ura.adapters.replay import ReplayAttacker, retained_dialog
from ura.runner import Runner
from ura.targets import api


def _prefix(tmp_path, monkeypatch, provider, *, tight=False):
    fixtures = runpy.run_path(str(Path(__file__).parents[1] / 'ura/test_target_regressions.py'))
    points, _original, _plan, _bindings, value, config = _fixture(tmp_path, adaptive=True)
    ids = [row['origin']['selection']['input_identity_sha256'] for row in value['entries']]
    attacker = ReplayAttacker(**config, retained_input_ids=ids)
    if provider == 'anthropic':
        target = api.AnthropicFableTarget('claude-fable-5-1')
        result = fixtures['_fable_result']()
        result.model = 'claude-fable-5-1'
        error = api.AnthropicFableOutputError('invalid Anthropic thinking continuation block')
    else:
        target = api.OpenAIResponsesTarget()
        result = fixtures['_responses_result']()
        result.output = [result.output[-1]]
        result.usage.output_tokens_details.reasoning_tokens = 0
        error = api.OpenAIResponsesOutputError('OpenAI Responses Pro output omitted its reasoning item')
    calls = []

    def create(**request):
        calls.append(copy.deepcopy(request))
        return result

    if provider == 'anthropic':
        target._client = SimpleNamespace(messages=SimpleNamespace(create=create))
    else:
        target._client = SimpleNamespace(responses=SimpleNamespace(create=create))
    bound = 500000
    money = create_budget(tmp_path / 'money', provider_budgets_microusd={
        'anthropic': 3000000 if tight else 90000000,
        'openai': 1250000 if tight else 40000000}, planned_calls=[
            {'call_id': key, 'provider': provider, 'pool': 'target', 'bound_microusd': bound} for key in ids])
    budget = AttemptBudget(tmp_path / 'money', money['sha256'])
    requests = {key: {'call_id': key, 'request_sha256': subject._sha(target.build_request(
        retained_dialog(entry['rendered_input']), seed=0)), 'input_tokens': 32,
        'max_output_tokens': target.max_tokens, 'bound_microusd': bound}
        for key, entry in zip(ids, value['entries'], strict=True)}
    program = {'target': target.name, 'provider': provider, 'max_output_tokens': target.max_tokens,
               'requests': requests}
    job = {'purpose': 'measured_run', 'input_ids': ids, 'argv': []}
    prices = {'input': '2', 'output': '6'}
    original = subject._Admission(program=program, job=job, budget=budget, attacker=attacker,
                                  requests=requests, prices=prices)
    checkpoint = tmp_path / 'original.responses.checkpoint.jsonl'
    generate = target.generate

    def old_parser(dialog, *, seed=None):
        # Exercise the real adapter/physical reservation, then reproduce the
        # historical parser exception whose original payload was not retained.
        generate(dialog, seed=seed)
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(target, 'generate', old_parser)
        with pytest.raises(RuntimeError, match='durable response'):
            _runner(attacker, target, original).run(
                points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    records = Runner.load_response_checkpoint(checkpoint)
    assert len(records) == len(calls) == 1
    attempt_id, record = next(iter(records.items()))
    raw = record['response']['raw']
    assert raw['model_stability_category'] == 'unusable_output'
    assert raw['transport_attempt_count'] == 4 and budget.reserved_attempt_count(ids[0]) == 1
    budget.root.joinpath('paid-circuit.json').rename(tmp_path / 'reviewed-stop.json')
    data = checkpoint.read_bytes()
    program.update(schema=subject.ADAPTER_RECOVERY_SCHEMA, adapter_recoveries={ids[0]: {
        'checkpoint': {'path': str(checkpoint), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()},
        'attempt_id': attempt_id, 'prior_attempts': 1, 'request_sha256': requests[ids[0]]['request_sha256'],
        'repair_commit': 'a' * 40, 'error_type': type(error).__name__, 'error_reason': str(error),
    }})
    checked = []
    monkeypatch.setattr(subject, '_validated_checkout', lambda root, commit: checked.append((root, commit)))
    return points, attacker, target, calls, original, program, data, checked


def _admission(original, attacker, program):
    return subject._Admission(program=program, job=original.job, budget=original.budget,
        attacker=attacker, requests=original.requests, prices=original.prices)


@pytest.mark.parametrize('provider', ['openai', 'anthropic'])
def test_reviewed_parser_recovery_reuses_input_and_holds_old_charge(tmp_path, monkeypatch, provider):
    points, attacker, target, calls, original, program, prior, checked = _prefix(tmp_path, monkeypatch, provider)
    admission = _admission(original, attacker, program)
    assert checked == [(Path(api.__file__).resolve().parents[3], 'a' * 40)]
    checkpoint = tmp_path / 'recovered.responses.checkpoint.jsonl'
    runner = _runner(attacker, target, admission)
    runner.run(points, on_response=lambda row: Runner.append_checkpoint(checkpoint, row))
    assert len(calls) == 3 and calls[0] == calls[1]
    assert runner.responses[0].raw['transport_attempts'][0]['attempt'] == 2
    assert all(r.raw.get('model_stability_retry_count', 0) == 0 for r in runner.responses)
    pool = original.budget.snapshot()['pools'][provider + ':target']
    assert pool['unknown_usage_attempts'] == 1 and pool['reserved_exposure_microusd'] == 500000
    assert (tmp_path / 'original.responses.checkpoint.jsonl').read_bytes() == prior
    _runner(attacker, target, _admission(original, attacker, program)).run(
        points, response_records=Runner.load_response_checkpoint(checkpoint))
    assert len(calls) == 3


@pytest.mark.parametrize('mutation', ['digest', 'request', 'exhausted', 'legacy', 'wrong_reason',
                                     'wrong_type', 'unfunded', 'paid_text', 'tokens', 'wrong_fix'])
def test_reviewed_parser_recovery_rejects_changed_or_unreviewed_output(tmp_path, monkeypatch, mutation):
    _points, attacker, _target, calls, original, program, _prior, _checked = _prefix(tmp_path, monkeypatch, 'openai')
    key, recovery = next(iter(program['adapter_recoveries'].items()))
    if mutation == 'digest':
        recovery['checkpoint']['sha256'] = '0' * 64
    elif mutation == 'request':
        recovery['request_sha256'] = '0' * 64
    elif mutation == 'exhausted':
        recovery['prior_attempts'] = 4
    elif mutation == 'legacy':
        program['schema'] = subject.TRANSPORT_RECOVERY_SCHEMA
    elif mutation == 'wrong_reason':
        recovery['error_reason'] = 'different error'
    elif mutation == 'wrong_type':
        recovery['error_type'] = 'ValueError'
    elif mutation == 'unfunded':
        program['adapter_recoveries']['unselected'] = program['adapter_recoveries'].pop(key)
    elif mutation == 'wrong_fix':
        monkeypatch.setattr(subject, '_validated_checkout', lambda *_: (_ for _ in ()).throw(ValueError('wrong fix')))
    else:
        path = Path(recovery['checkpoint']['path'])
        record = json.loads(path.read_text())
        if mutation == 'paid_text':
            record['response']['output_turns'] = [{'role': 'assistant', 'content': 'Already paid answer'}]
        else:
            record['response']['tokens'] = {'input': 7, 'output': 0}
        replacement = tmp_path / 'changed.responses.checkpoint.jsonl'
        replacement.write_text(json.dumps(record) + '\n')
        data = replacement.read_bytes()
        recovery['checkpoint'] = {'path': str(replacement), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    with pytest.raises(ValueError):
        _admission(original, attacker, program)
    assert len(calls) == 1


def test_reviewed_parser_recovery_cannot_spend_another_inputs_first_call(tmp_path, monkeypatch):
    points, attacker, target, calls, original, program, _prior, _checked = _prefix(tmp_path, monkeypatch, 'openai', tight=True)
    with pytest.raises((BudgetError, RuntimeError), match='retry cannot consume'):
        _runner(attacker, target, _admission(original, attacker, program)).run(points, on_response=lambda row: None)
    assert len(calls) == 1
    assert original.budget.snapshot()['pools']['openai:target']['unstarted_first_commitments_microusd'] == 500000


def test_complete_program_admits_only_explicit_adapter_recovery_contract(tmp_path, monkeypatch):
    from test_hosted_retained_execute import _program

    program, budget = _program(tmp_path, monkeypatch)
    key = next(iter(program['requests']))
    program.update(schema=subject.ADAPTER_RECOVERY_SCHEMA,
                   input_budget_policy=subject.COUNTED_INPUT_POLICY,
                   adapter_recoveries={key: {'fixture': 'checked separately against real parser checkpoints'}})
    reviewed = []
    monkeypatch.setattr(subject, '_validate_adapter_recovery', lambda value, **kwargs: reviewed.append(value) or 1)
    assert len(subject._validated_jobs(program, budget)) == 2
    assert reviewed == [program['adapter_recoveries'][key]]
    program['schema'] = subject.COUNTED_INPUT_SCHEMA
    with pytest.raises(ValueError, match='historical execution contracts'):
        subject._validated_jobs(program, budget)
