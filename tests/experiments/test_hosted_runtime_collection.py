"""No-call checks of the shared runtime-to-collection handoff."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_runtime_collection as subject
from experiments.hosted_retained_inputs import _descriptor


def fixture_program(tmp_path):
    jobs = [dict(name=name, purpose=purpose, input_ids=[name],
        argv=['--out', str(tmp_path/'outputs'/name), '--execution-scope-id', 'same-scope'])
        for name, purpose in [('probe','attestation_probe'), ('measured','measured_run')]]
    program = dict(target='google:model', provider='google', sources={'fixed':'source'},
        requests={name:dict(call_id=name) for name in ('probe','measured')}, jobs=jobs)
    path = tmp_path/'runtime-program.json'
    path.write_text(json.dumps(program))
    return program, _descriptor(path)


def test_funded_probe_finishes_native_grid_before_deriving_observation(tmp_path, monkeypatch):
    from experiments import hosted_dispatch, live_attestation
    program, descriptor = fixture_program(tmp_path)
    admission = SimpleNamespace(job=program['jobs'][0],runtime_program=descriptor)
    events = []
    monkeypatch.setattr(hosted_dispatch, 'run_admission', lambda value,**kw:
        events.append(('run',value.job['name'],kw['responses_only'])) or str(tmp_path/'outputs'/'probe'))
    def observe(argv):
        events.append(('derive',argv))
        Path(argv[argv.index('--out')+1]).write_text('{}')
        return 0
    monkeypatch.setattr(live_attestation, 'main', observe)
    subject.run_runtime_admission(admission,responses_only=True)
    assert events[0] == ('run','probe',False)
    assert events[1][1][1] == str(tmp_path/'outputs'/'probe')
    assert events[1][1][3] == 'same-scope'
    completed = frozenset({(0,0),(0,1)})
    jobs = [admission,SimpleNamespace(job=program['jobs'][1],runtime_program=descriptor)]
    assert subject.completed_runtime_jobs(completed,[jobs]) == completed
    subject.transport_path(descriptor['path'],0).unlink()
    assert subject.completed_runtime_jobs(completed,[jobs]) == frozenset({(0,1)})


def test_measured_worker_attaches_saved_observation_without_mutating_original(tmp_path,monkeypatch):
    from experiments import hosted_dispatch
    original, descriptor = fixture_program(tmp_path)
    original_bytes = Path(descriptor['path']).read_bytes()
    subject.transport_path(descriptor['path'],0).write_text('{"observation":"fixed"}')
    admission = SimpleNamespace(job=copy.deepcopy(original['jobs'][1]),runtime_program=descriptor)
    events = []
    monkeypatch.setattr(hosted_dispatch,'run_admission', lambda value,**kw:
        events.append((value,kw)) or str(tmp_path/'outputs'/'measured'))
    subject.run_runtime_admission(admission,responses_only=True)
    assert '--live-attestation' in events[0][0].job['argv']
    assert events[0][1] == {'responses_only':True}
    assert admission.job == original['jobs'][1]
    assert Path(descriptor['path']).read_bytes() == original_bytes
    saved = json.loads((tmp_path/'attested-program.json').read_text())
    assert saved['requests'] == original['requests'] and saved['sources'] == original['sources']
    assert saved['jobs'][0] == original['jobs'][0]
    before = (tmp_path/'attested-program.json').stat().st_mtime_ns
    assert subject.observed_program(descriptor) == saved
    assert (tmp_path/'attested-program.json').stat().st_mtime_ns == before
    (tmp_path/'programs.json').write_text(json.dumps({'programs':[descriptor]}))
    assert subject.effective_program_descriptors(tmp_path) == [_descriptor(tmp_path/'attested-program.json')]


def test_missing_observation_cannot_start_measured_worker(tmp_path,monkeypatch):
    from experiments import hosted_dispatch
    program, descriptor = fixture_program(tmp_path)
    monkeypatch.setattr(hosted_dispatch,'run_admission',lambda *a,**k:pytest.fail('Premature target call'))
    with pytest.raises(FileNotFoundError):
        subject.run_runtime_admission(SimpleNamespace(job=program['jobs'][1],runtime_program=descriptor),responses_only=True)


def test_saved_runtime_is_reused_after_paid_work_starts(tmp_path,monkeypatch):
    original, descriptor = fixture_program(tmp_path)
    root = tmp_path/'collection'
    root.mkdir()
    refs = [dict(descriptor,target=original['target'])]
    budget = SimpleNamespace(root=tmp_path/'budget',expected_plan_sha256='b'*64)
    jobs = [SimpleNamespace(job=job,requests={job['name']:original['requests'][job['name']]}) for job in original['jobs']]
    calls = []
    monkeypatch.setattr(subject,'bind_installed_program',lambda **kw:
        calls.append(kw) or {'program':descriptor})
    kwargs = dict(originals=[original],references=refs,contexts=[object()],admitted=[jobs],budget=budget,
        project_root=tmp_path,expected_commit='c'*40,store=tmp_path,root=root)
    first, first_jobs = subject.runtime_programs(**kwargs)
    monkeypatch.setattr(subject,'bind_installed_program',lambda **kw:pytest.fail('Repeated runtime binding'))
    second, second_jobs = subject.runtime_programs(**kwargs)
    assert first == second == [original] and len(calls) == 1
    assert calls[0]['original_admissions'] is jobs
    assert first_jobs[0][0].runtime_program == second_jobs[0][0].runtime_program == descriptor
    assert not hasattr(jobs[0],'runtime_program')
    with pytest.raises(ValueError,match='changed'):
        subject.runtime_programs(**{**kwargs,'expected_commit':'d'*40})


def test_saved_runtime_cannot_change_funded_requests(tmp_path,monkeypatch):
    original, descriptor = fixture_program(tmp_path)
    changed = copy.deepcopy(original)
    changed['requests']['measured']['call_id'] = 'different'
    path = tmp_path/'changed.json'
    path.write_text(json.dumps(changed))
    monkeypatch.setattr(subject,'bind_installed_program',lambda **kw:{'program':_descriptor(path)})
    with pytest.raises(ValueError,match='funded requests'):
        subject.runtime_programs(originals=[original],references=[descriptor],contexts=[None],
            admitted=[[SimpleNamespace(job=job) for job in original['jobs']]],
            budget=SimpleNamespace(root=tmp_path,expected_plan_sha256='a'*64),
            project_root=tmp_path,expected_commit='b'*40,store=tmp_path,root=tmp_path/'runtime')
