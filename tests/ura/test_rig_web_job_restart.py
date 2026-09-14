"""Real Linux child processes, isolated data, no models or provider calls."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.catalog import Command, CommandParam
from experiments.rig_web_app.job_runtime import RecoveredProcess, process_identity, read_state, repository_lease

pytestmark = pytest.mark.skipif(not Path('/proc').is_dir(), reason='Linux process recovery')


def until(condition, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(.03)
    assert condition()


def make_app(tmp_path):
    repo = tmp_path / 'repo'; repo.mkdir(exist_ok=True)
    (repo / 'fixture_job.py').write_text(
        "import argparse,time\nfrom pathlib import Path\n"
        "p=argparse.ArgumentParser();p.add_argument('--exit',type=int,default=0);a=p.parse_args()\n"
        "print('Started live job'+'.'*4096,flush=True)\n"
        "until=time.monotonic()+10\n"
        "while not Path('release').exists() and time.monotonic()<until: time.sleep(.03)\n"
        "print('Finished child',flush=True);raise SystemExit(a.exit)\n")
    return RigWebApp(results_root=tmp_path/'runs', state_dir=tmp_path/'state', repo_root=repo,
        gpu_hardware={}, system_hardware={}, commands={'webui_selftest':Command('webui_selftest','fixture_job','test',
            (CommandParam('--exit','int'),))})


@pytest.mark.parametrize('exit_code', [0, 7])
def test_restart_keeps_running_then_records_actual_exit_and_logs(tmp_path, exit_code):
    first = make_app(tmp_path)
    job = first.start_job('webui_selftest', {'--exit':str(exit_code)})
    until(lambda: read_state(job.directory) is not None)
    # Short logs must be visible before completion, not buffered until EOF.
    until(lambda: 'Started live job' in (job.directory/'stdout.log').read_text())
    assert job.state() == 'running'
    first.close()
    second = make_app(tmp_path)
    try:
        restored = second._job_for_id(job.job_id)
        assert restored.state() == 'running'
        assert b'Stop job' in second._job_page(restored)
        (second.repo_root/'release').touch()
        until(lambda: second._job_for_id(job.job_id).state() != 'running')
        assert restored.state() == ('complete' if exit_code == 0 else 'failed')
        assert restored.exit_code() == exit_code
        assert second.db.load_job(job.job_id)['exit_code'] == exit_code
        until(lambda: 'Finished child' in (job.directory/'stdout.log').read_text())
    finally:
        second.close(); job.process.wait(timeout=5)


def test_restarted_console_can_stop_same_process_tree(tmp_path):
    first = make_app(tmp_path)
    job = first.start_job('webui_selftest', {})
    until(lambda: bool((read_state(job.directory) or {}).get('child')))
    first.close(); second = make_app(tmp_path)
    try:
        restored = second._job_for_id(job.job_id)
        second._terminate_tree(restored)
        until(lambda: second._job_for_id(job.job_id).state() != 'running')
        assert restored.state() == 'failed'
        assert restored.exit_code() == -signal.SIGTERM
        assert not restored.stop_error
    finally:
        second.close(); job.process.wait(timeout=5)


def test_disappeared_supervisor_is_interrupted_not_fake_exit_or_running(tmp_path):
    app = make_app(tmp_path)
    job = app.start_job('webui_selftest', {})
    until(lambda: bool((read_state(job.directory) or {}).get('child')))
    os.killpg(job.process.pid, signal.SIGKILL)
    job.process.wait(timeout=5);app.close()
    restarted = make_app(tmp_path)
    try:
        restored = restarted._job_for_id(job.job_id)
        assert restored.state() == 'interrupted'
        assert restored.exit_code() is None
        assert b'Execution interrupted' in restarted._job_page(restored)
        assert restarted.db.load_job(job.job_id)['exit_code'] is None
    finally:
        restarted.close()


def test_pid_reuse_does_not_adopt_an_unrelated_process(tmp_path):
    identity = process_identity(os.getpid());identity['start'] = 'incorrect'
    record = dict(job_id=tmp_path.name,state='running',supervisor=identity)
    (tmp_path/'execution.json').write_text(json.dumps(record))
    process = RecoveredProcess(tmp_path, record)
    assert process.poll() is not None and process.interrupted


def test_legacy_hosted_terminal_result_reconciles_original_row_without_calls(tmp_path):
    app = make_app(tmp_path)
    directory=app.state_dir/'job-old';directory.mkdir()
    out=app.results_root/'collection';out.mkdir()
    (out/'result.json').write_text(json.dumps(dict(status='collection_needs_continuation',
        jobs=[dict(status='failed'),dict(status='paused')])))
    (directory/'stderr.log').write_text('project checkout revision mismatch')
    job=Job('job-old','hosted_campaign_execute',['python','--out',str(out)],directory,restored_state='running')
    app.db.upsert_job(job);app.close()
    restarted=make_app(tmp_path)
    try:
        restored=restarted._job_for_id('job-old')
        assert restored.state()=='failed' and restored.exit_code()==1
        assert 'revision mismatch' in restored.failure
        assert restarted.db.load_job('job-old')['state']=='failed'
    finally:
        restarted.close()


def test_repository_lease_excludes_in_place_deployment(tmp_path):
    import fcntl
    (tmp_path/'.git').mkdir()
    lease=repository_lease(tmp_path)
    other=(tmp_path/'.git/ura-execution.lock').open('a')
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
        lease.close()
        fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(ValueError,match='Deployment is in progress'):
            repository_lease(tmp_path)
    finally:
        lease.close();other.close()
