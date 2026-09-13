"""Installed-only preparation preserves funded inputs and resumable no-call work."""
from contextlib import nullcontext
import copy
import json
from types import SimpleNamespace

import pytest

from experiments import hosted_program_runtime as subject


def entry(key, modality='text', *, corpus='harmful', evaluable=True, cluster=None, point=None):
    return dict(origin=dict(selection=dict(required_modalities=[modality], datapoint_id=point or key,
        source_cluster_id=cluster or key, corpus=corpus, source=corpus),
        original_attempt=dict(params=dict(policy_evaluable_turn=evaluable))))


def source():
    jobs = [dict(name=name, purpose=purpose, input_ids=[name], argv=['--out','/old/'+name,
        '--limit','1' if purpose=='diagnostic_canary' else '0','--max-queries','1','--max-turns','1',
        *(['--diagnostic-canary'] if purpose=='diagnostic_canary' else [])])
        for name,purpose in [('text-pilot','diagnostic_canary'), ('image-pilot','diagnostic_canary'),
                             ('measure','measured_run')]]
    entries = {'text-pilot':[entry('text-pilot')], 'image-pilot':[entry('image-pilot','image')],
               'measure':[entry('measure')]}
    program = dict(target='google:test', provider='google', budget_plan_sha256='a'*64, jobs=jobs,
        requests={name:dict(call_id='target-'+name) for name in entries})
    return program, entries


def test_whole_job_probes_preserve_requests_inputs_and_measured_partition(tmp_path):
    original, entries = source()
    retained = copy.deepcopy(original)
    result = subject.prospective_program(original, entries, root=tmp_path,
        project_revision=dict(path='/new/revision.json', sha256='b'*64))
    assert original == retained and result['requests'] == original['requests']
    assert {job['name']:job['input_ids'] for job in result['jobs']} == {job['name']:job['input_ids'] for job in original['jobs']}
    assert [job['purpose'] for job in result['jobs']] == ['attestation_probe','attestation_probe','measured_run']
    for job in result['jobs'][:2]:
        assert '--attestation-probe' in job['argv'] and '--diagnostic-canary' not in job['argv']
        assert '--live-attestation-max-age-hours' not in job['argv']
    assert '--live-attestation-max-age-hours' in result['jobs'][2]['argv']


def test_missing_modality_probe_is_not_silently_ignored():
    program, entries = source()
    entries['image-pilot'] *= 2
    with pytest.raises(ValueError, match='modality'):
        subject.select_transport_jobs(program, entries)


def test_two_record_cluster_cannot_be_split_into_single_point_probe():
    program, entries = source()
    entries['text-pilot'] = [entry('first',cluster='same',point='same'), entry('second',cluster='same',point='same')]
    entries['measure'][0]['origin']['selection']['required_modalities'] = ['image']
    with pytest.raises(ValueError, match='modality'):
        subject.select_transport_jobs(program, entries)


def test_probe_choice_prefers_whole_benign_job_not_observed_outcome():
    program, entries = source()
    entries['measure'] = [entry('measure',corpus='jailbreakbench_benign')]
    assert subject.select_transport_jobs(program, entries)['measure'] == 1


def test_probe_roles_leave_an_evaluable_measured_job(tmp_path):
    program, entries = source()
    entries['measure'] = [entry('measure',corpus='jailbreakbench_benign')]
    result = subject.prospective_program(program, entries, root=tmp_path,
        project_revision=dict(path='/revision.json',sha256='b'*64))
    measured = [job for job in result['jobs'] if job['purpose']=='measured_run']
    assert len(measured)==1 and measured[0]['name']=='text-pilot'
    assert '--diagnostic-canary' not in measured[0]['argv']
    assert measured[0]['argv'][measured[0]['argv'].index('--limit')+1]=='0'


@pytest.mark.parametrize('age',[0,-1,8761,True])
def test_age_setting_cannot_be_invalid(tmp_path, age):
    program, entries = source()
    with pytest.raises(ValueError,match='age'):
        subject.prospective_program(program, entries, root=tmp_path,project_revision={},max_age_hours=age)


@pytest.mark.parametrize('method',['fetch_manifest','cached_file','download_file'])
def test_installed_only_backend_never_contacts_hub(method):
    with pytest.raises(ValueError,match='not installed'):
        getattr(subject.InstalledOnly(),method)('repo','revision')


def fixture_runtime(tmp_path, monkeypatch):
    from experiments import model_acquire, run_matrix
    from ura import model_acquisition, project_revision, runner
    program, entries = source()
    store = tmp_path/'store'
    store.mkdir()
    starts = {request['call_id']:0 for request in program['requests'].values()}
    budget = SimpleNamespace(reserved_attempt_counts=lambda ids:{key:starts[key] for key in ids})
    calls = dict(plans=0, acquire=0, verify=0, contexts=0, revisions=0)
    monkeypatch.setattr(subject.retained,'_validated_checkout',lambda *args:None)
    def context(original):
        calls['contexts']+=1
        return object()
    monkeypatch.setattr(subject.retained,'_validated_local_cells',context)
    monkeypatch.setattr(subject.retained,'_validated_jobs',lambda value,budget,**kwargs:[
        SimpleNamespace(job=job,attacker=SimpleNamespace(_selected_entries=entries[job['name']])) for job in value['jobs']])
    def revision(*args):
        calls['revisions']+=1
        return dict(revision='fixed')
    monkeypatch.setattr(project_revision,'create_project_revision',revision)
    def write_revision(directory,value):
        path=directory/'revision.json'
        path.write_text(json.dumps(value))
        return path
    monkeypatch.setattr(project_revision,'write_project_revision',write_revision)
    monkeypatch.setattr(runner,'retained_execution_admission',lambda admission:nullcontext())
    def planning(argv):
        calls['plans']+=1
        path=subject.Path(argv[argv.index('--model-acquisition-plan-dir')+1])/'selected.plan.json'
        path.write_text(json.dumps(dict(resources=['existing-resource'])))
        return 0
    monkeypatch.setattr(run_matrix,'main',planning)
    monkeypatch.setattr(model_acquisition,'load_plan',lambda path,**kwargs:json.loads(path.read_text()))
    monkeypatch.setattr(model_acquisition,'load_receipt',lambda path,**kwargs:json.loads(path.read_text()))
    def verify(*args,**kwargs):
        calls['verify']+=1
        assert kwargs['verify_sha256'] is False
    monkeypatch.setattr(model_acquisition,'verify_receipt_snapshots',verify)
    def acquire(plan,**kwargs):
        calls['acquire']+=1
        assert isinstance(kwargs['backend'],subject.InstalledOnly)
        assert kwargs['max_download_bytes']==0 and kwargs['verify_model_sha256'] is False
        path=kwargs['receipts_dir']/'installed.receipt.json'
        path.write_text('{}')
        return SimpleNamespace(receipt_path=path,downloaded_bytes=0)
    monkeypatch.setattr(model_acquire,'acquire',acquire)
    kwargs=dict(original=program,budget=budget,project_root=tmp_path,expected_commit='b'*40,
        store=store,out=tmp_path/'runtime')
    return kwargs,calls,starts


def test_runtime_resumes_without_replanning_or_reinstalling(tmp_path,monkeypatch):
    kwargs,calls,_starts=fixture_runtime(tmp_path,monkeypatch)
    first=subject.bind_installed_program(**kwargs)
    second=subject.bind_installed_program(**kwargs)
    assert first==second and first['status']=='installed_runtime_bound_transport_pending'
    assert first['original_requests_unchanged'] and first['assigned_inputs']==3 and first['probe_inputs']==2
    assert calls==dict(plans=3,acquire=3,verify=3,contexts=2,revisions=1)
    assert first['target_calls']==first['judge_calls']==first['downloaded_bytes']==0


def test_started_program_cannot_get_fresh_runtime_arguments(tmp_path,monkeypatch):
    kwargs,calls,starts=fixture_runtime(tmp_path,monkeypatch)
    starts[next(iter(starts))]=1
    with pytest.raises(ValueError,match='has started'):
        subject.bind_installed_program(**kwargs)
    assert not kwargs['out'].exists() and not any(calls.values())


def test_changed_runtime_continuation_does_not_repeat_preparation(tmp_path,monkeypatch):
    kwargs,calls,_starts=fixture_runtime(tmp_path,monkeypatch)
    subject.bind_installed_program(**kwargs)
    with pytest.raises(ValueError,match='continuation changed'):
        subject.bind_installed_program(**kwargs,max_age_hours=48)
    assert calls['plans']==3 and calls['acquire']==3


def test_console_command_is_no_call_preparation_and_checksums_default_off(tmp_path,monkeypatch):
    from experiments.rig_web_app.catalog import build_argv
    from experiments.rig_web_app.workspace_store import activity_role
    import experiments.hosted_campaign_budget as budget_module
    import experiments.hosted_attempt_budget as attempts_module
    values={'--program':str(tmp_path/'program.json'),'--program-sha256':'a'*64,
        '--budget-root':str(tmp_path),'--budget-plan-sha256':'b'*64,'--project-root':str(tmp_path),
        '--expected-commit':'c'*40,'--out':str(tmp_path/'out'),'--store':str(tmp_path)}
    argv=build_argv('hosted_program_runtime',values)
    assert activity_role('hosted_program_runtime')=='preparation'
    assert '--verify-model-sha256' not in argv and '--verify-artifact-sha256' not in argv
    observed=[]
    monkeypatch.setattr(budget_module,'load_bound_json',lambda *args:({},{}))
    monkeypatch.setattr(attempts_module,'AttemptBudget',lambda *args:object())
    monkeypatch.setattr(subject,'bind_installed_program',lambda **kwargs: observed.append(kwargs) or {'status':'prepared'})
    assert subject.main(argv[argv.index('experiments.hosted_program_runtime')+1:])==0
    assert observed[0]['verify_model_sha256'] is False


def test_console_runtime_preparation_does_not_receive_provider_credentials():
    from experiments.rig_web_app.catalog import COMMANDS
    from experiments.rig_web_app.lifecycle import LifecycleMixin
    fake=SimpleNamespace(commands=COMMANDS,_MATRIX_BASE_ENV={'BASE'},_MATRIX_OPTIONAL_ENV={'OPTIONAL'},
        _MATRIX_RECEIPT_ENV={'URA_MODEL_STORE'},
        _strict_config_document=lambda *args:{'jobs':[{'argv':['--api','google:model','--corpora','arm']}]},
        _declared_matrix_environment=lambda values:{'CORPUS_ROOT'},
        _selected_matrix_environment_names=lambda values:pytest.fail('Provider credential selection reached'),
        _selected_child_environment=lambda allowed:allowed)
    assert LifecycleMixin._generic_child_environment(fake,'hosted_program_runtime',
        {'--program':'program.json','--program-sha256':'a'*64}) == {'BASE','OPTIONAL','URA_MODEL_STORE','CORPUS_ROOT'}
