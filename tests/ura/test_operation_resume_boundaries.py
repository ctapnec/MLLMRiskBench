"""A standalone run must recover its internal diagnostics like a campaign."""
import json

import pytest

from test_operator_operations import app, child  # noqa: F401
from experiments.rig_web_app import connection_workflow


def interrupted(app, monkeypatch, state, published):
    monkeypatch.setattr(app, '_builder_model_acquisition_required', lambda p: False)
    owner = app.db.create_workspace('Standalone interrupted connection', 'local')
    run = app._operations[app._start_operation('direct', dict(campaign_id=owner, mode='measured'))]
    probe = app._operations[app._start_operation('direct', dict(campaign_id=owner, mode='attestation_probe'))]
    probe.update(status='ready', execution_job='probe-old')
    job = child(app, 'probe-old', 'run_matrix', state=state, code=143)
    job.argv = ['python', '-m', 'experiments.run_matrix', '--attestation-probe']
    job.builder_params = dict(probe['params'])
    item = dict(preparation=probe['id'])
    if published:
        item.update(probe=job.job_id, check=app._finish_probe_automatically(job))
        app._advance_operation(app._operations[item['check']])
    run.update(status='stopped', step=1, execution_authorized=True, connection_operations=[item])
    for operation in (run, probe): app._save_operation(operation)
    return run, probe, item


@pytest.mark.parametrize('published', [False, True])
@pytest.mark.parametrize('state', ['failed', 'stopped', 'interrupted'])
def test_standalone_retry_recovers_probe_without_separate_operator_job(app, monkeypatch, state, published):
    run, probe, item = interrupted(app, monkeypatch, state, published)
    app._restore_operations()
    run = app._operations[run['id']]; probe = app._operations[probe['id']]
    item = run['connection_operations'][0]
    app._retry_operation(run['id'])
    assert run['status'] == 'preparing'
    assert probe.get('resume_job') == 'probe-old' and 'execution_job' not in probe
    assert item == dict(preparation=probe['id'])
    launched = []
    def resume(context, prepared):
        assert prepared['resume_job'] == 'probe-old'
        launched.append(prepared['id'])
        job = child(app, 'probe-resumed', 'run_matrix')
        job.argv = ['python', '-m', 'experiments.run_matrix', '--attestation-probe']
        job.builder_params = dict(prepared['params'])
        prepared['execution_job'] = job.job_id
        return job
    monkeypatch.setattr(connection_workflow, 'launch', resume)
    assert connection_workflow.advance(app, run)
    assert launched == [probe['id']] and item['probe'] == 'probe-resumed'
    assert app._operations[item['check']]['current_job'] == 'probe-resumed'
    assert app.jobs['probe-old'].state() == state


@pytest.mark.parametrize('retained', [False, True])
def test_standalone_retry_waits_before_any_owned_state_changes(app, monkeypatch, retained):
    run, probe, item = interrupted(app, monkeypatch, 'running', False)
    if retained:
        app.jobs.pop('probe-old')
        (app.state_dir/'probe-old').mkdir()
    before = json.dumps(app._operations, sort_keys=True)
    started = []
    monkeypatch.setattr(app, '_ensure_operation_worker', lambda key: started.append(key))
    with pytest.raises(ValueError, match='stopping|recovery'):
        app._retry_operation(run['id'])
    assert not started and json.dumps(app._operations, sort_keys=True) == before
