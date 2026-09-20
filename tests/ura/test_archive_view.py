"""Copied consoles browse retained evidence without taking over rig work."""
from pathlib import Path

import pytest

from experiments.rig_web_app.app import RigWebApp
from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.server import main


def create(tmp_path, archive_view=True):
    return RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state',
                     repo_root=Path(__file__).resolve().parents[2], archive_view=archive_view,
                     gpu_hardware={}, system_hardware={})


def test_archive_loads_jobs_and_operations_without_recovery(tmp_path, monkeypatch):
    first = create(tmp_path)
    job = Job('job-retained', 'run_matrix', [], first.state_dir/'job-retained',
              restored_state='complete', restored_exit=0)
    first.db.upsert_job(job)
    operation = dict(id='a'*32, kind='campaign', status='preparing', step=0, params={},
                     jobs=['job-retained'], current_job='job-retained', signature='saved')
    first._save_operation(operation)
    first.close()

    def forbidden(*args, **kwargs):
        raise AssertionError('Archive startup must not resume or republish work')

    for method in ('_restore_job_execution', '_publish_direct_hosted_job',
                   '_restore_model_acquisition_workflows', '_recover_unrecorded_runs',
                   '_ensure_operation_worker'):
        monkeypatch.setattr(RigWebApp, method, forbidden)
    app = create(tmp_path)
    try:
        assert app.jobs['job-retained'].state() == 'complete'
        assert app._operations['a'*32] == operation
        assert not app._operation_workers
    finally:
        app.close()


@pytest.mark.parametrize('path', ['/config/secrets', '/operations/start-campaign',
    '/ollama/start', '/jobs/job-retained/stop', '/analysis/start', '/review/example'])
def test_archive_rejects_post_before_any_route(tmp_path, monkeypatch, path):
    app = create(tmp_path)
    try:
        monkeypatch.setattr(app, '_handle_request', lambda *a: pytest.fail('POST reached a route'))
        status, _, body = app.handle('POST', path, {})
        assert status == 403 and b'Archive view' in body
    finally:
        app.close()


@pytest.mark.parametrize('path', ['/campaigns', '/jobs', '/stats'])
def test_archive_browsing_keeps_navigation_and_explains_mode(tmp_path, path):
    app = create(tmp_path)
    try:
        status, kind, body = app.handle('GET', path)
        assert status == 200 and kind.startswith('text/html')
        assert b'Archive view' in body and b'<nav' in body and b'/build' in body
        assert body.count(b'Archive view') == 1
    finally:
        app.close()


def test_archive_direct_execution_and_lazy_recovery_are_disabled(tmp_path, monkeypatch):
    app = create(tmp_path)
    try:
        with pytest.raises(ValueError, match='Archive view'):
            app.start_job('run_matrix', {})
        job = Job('job-retained', 'run_matrix', [], app.state_dir/'job-retained',
                  restored_state='complete', restored_exit=0)
        from experiments.rig_web_app import job_runtime
        monkeypatch.setattr(job_runtime, 'read_state', lambda *a: pytest.fail('Rig PID inspected'))
        app._restore_job_execution(job)
        app.jobs[job.job_id] = job
        monkeypatch.setattr(app, '_reconcile_restored_model_acquisition',
                            lambda *a: pytest.fail('Acquisition inspected'))
        app._reconcile_locked()
        assert job.process is None
    finally:
        app.close()


def test_archive_does_not_change_non_html_exports_or_normal_routes(tmp_path, monkeypatch):
    app = create(tmp_path)
    try:
        expected = (200, 'text/csv', b'id,value\n1,retained\n')
        monkeypatch.setattr(app, '_handle_request', lambda *a: expected)
        assert app.handle('GET', '/export.csv') == expected
        app.archive_view = False
        assert app.handle('POST', '/ordinary', {}) == expected
    finally:
        app.close()


def test_archive_cli_forbids_reindex():
    with pytest.raises(SystemExit) as error:
        main(['--archive-view', '--reindex'])
    assert error.value.code == 2
