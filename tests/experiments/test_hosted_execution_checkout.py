"""Real isolated Python/Git boundary; no provider, model or download calls."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_execution_checkout as subject


def git(repo, *argv):
    return subprocess.check_output(['git', '-C', str(repo), *argv], text=True).strip()


def repository(tmp_path, worker_body=None):
    repo = tmp_path/'repo'
    repo.mkdir()
    git(repo, 'init', '-q')
    git(repo, 'config', 'user.email', 'test@example.invalid')
    git(repo, 'config', 'user.name', 'Test')
    (repo/'experiments').mkdir()
    (repo/'experiments/__init__.py').write_text('')
    # The child must import both validation and execution from the old checkout.
    from experiments.hosted_retained_execute import _validated_checkout
    import inspect
    (repo/'experiments/hosted_retained_execute.py').write_text(
        'import re, subprocess\nfrom pathlib import Path\n_HEX40 = re.compile(r"[0-9a-f]{40}")\n'
        +inspect.getsource(_validated_checkout))
    (repo/'experiments/hosted_dispatch.py').write_text(worker_body or (
        'import json\nfrom pathlib import Path\n'
        'def run_admission(admission, *, responses_only):\n'
        '    assert responses_only is True\n'
        '    assert Path(__file__).parents[1] == Path(admission.execution_checkout)\n'
        '    assert json.loads(Path(admission.checkpoint).read_text()) == admission.saved_response\n'
        '    assert admission.requests == {"input": {"call_id": "already-paid"}}\n'
        '    return admission.job["output"]\n'))
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'original')
    original = git(repo, 'rev-parse', 'HEAD')
    (repo/'experiments/hosted_dispatch.py').write_text('raise AssertionError("New Runner must not run old work")\n')
    git(repo, 'add', '.')
    git(repo, 'commit', '-qm', 'deployed')
    previous = tmp_path/'previous'
    previous.mkdir()
    (previous/'selection.json').write_text(json.dumps(dict(project_root=str(repo),expected_commit=original)))
    return repo, original, previous


def test_deployed_checkout_resumes_with_original_source_and_paid_record(tmp_path):
    repo, original, previous = repository(tmp_path)
    deployed = git(repo, 'rev-parse', 'HEAD')
    checkout = subject.execution_checkout(repo, original, previous)
    assert checkout != repo and git(checkout, 'rev-parse', 'HEAD') == original
    assert git(repo, 'rev-parse', 'HEAD') == deployed
    assert not git(repo, 'status', '--porcelain', '--untracked-files=no')
    assert subject.execution_checkout(repo, original, previous) == checkout
    checkpoint = tmp_path/'saved-response.json'
    saved = dict(text='Existing answer', cost=0.001, attempt=1)
    checkpoint.write_text(json.dumps(saved))
    before = checkpoint.read_bytes(), checkpoint.stat().st_mtime_ns
    admission = SimpleNamespace(execution_checkout=str(checkout),execution_commit=original,
        checkpoint=str(checkpoint),saved_response=saved,requests={'input':{'call_id':'already-paid'}},
        job={'output':str(previous),'argv':['--out',str(previous)]})
    assert subject.run_pinned_admission(admission,responses_only=True) == str(previous)
    assert (checkpoint.read_bytes(),checkpoint.stat().st_mtime_ns) == before
    assert not (checkout/'.venv').exists()


def test_fresh_work_cannot_silently_select_old_source(tmp_path):
    repo, original, _previous = repository(tmp_path)
    with pytest.raises(ValueError, match='expected commit'):
        subject.execution_checkout(repo, original, None)
    assert not (repo/'.git/ura-continuations').exists()


def test_dirty_deployment_and_changed_saved_revision_are_not_bypassed(tmp_path):
    repo, original, previous = repository(tmp_path)
    source = repo/'experiments/hosted_dispatch.py'
    before = source.read_text()
    source.write_text('changed\n')
    with pytest.raises(ValueError, match='expected commit'):
        subject.execution_checkout(repo, original, previous)
    source.write_text(before)
    (previous/'selection.json').write_text(json.dumps(dict(project_root=str(repo),expected_commit='a'*40)))
    with pytest.raises(ValueError, match='saved project and revision'):
        subject.execution_checkout(repo, original, previous)
    assert not (repo/'.git/ura-continuations').exists()


def test_changed_pinned_checkout_is_not_reused(tmp_path):
    repo, original, previous = repository(tmp_path)
    checkout = subject.execution_checkout(repo, original, previous)
    (checkout/'experiments/hosted_dispatch.py').write_text('changed\n')
    with pytest.raises(ValueError, match='expected commit'):
        subject.execution_checkout(repo, original, previous)


def test_incomplete_runtime_is_not_reprepared_after_paid_start(tmp_path):
    repo, original, previous = repository(tmp_path)
    (previous/'selection.json').write_text(json.dumps(dict(project_root=str(repo),expected_commit=original,
        prepare_runtime=True,runtime_root=str(previous/'runtime'))))
    with pytest.raises(ValueError, match='original runtime preparation is incomplete'):
        subject.execution_checkout(repo, original, previous)
    assert not (repo/'.git/ura-continuations').exists()


def test_killed_dispatch_owner_does_not_leave_pinned_runner(tmp_path):
    import os
    import pickle
    import signal
    import sys
    import time
    if sys.platform != 'linux':
        pytest.skip('Linux parent-death process ownership')
    repo, original, previous = repository(tmp_path, worker_body=(
        'import os,time\nfrom pathlib import Path\n'
        'def run_admission(admission, **kwargs):\n'
        '    Path(admission.marker).write_text(str(os.getpid()))\n'
        '    time.sleep(30)\n'))
    checkout = subject.execution_checkout(repo, original, previous)
    marker = tmp_path/'child-pid'
    admission = SimpleNamespace(execution_checkout=str(checkout),execution_commit=original,marker=str(marker),
        job={'argv':['--out',str(previous)]})
    launcher = subprocess.Popen([sys.executable,'-c',
        'import sys,pickle; from experiments.hosted_execution_checkout import run_pinned_admission; '
        'run_pinned_admission(pickle.load(sys.stdin.buffer),responses_only=True)'],stdin=subprocess.PIPE)
    child = None
    def active(pid):
        try:
            return Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[0] != 'Z'
        except FileNotFoundError:
            return False
    try:
        launcher.stdin.write(pickle.dumps(admission))
        launcher.stdin.close()
        end = time.monotonic()+10
        while not marker.exists() and launcher.poll() is None and time.monotonic()<end:
            time.sleep(.05)
        assert marker.exists(), 'Pinned worker did not start'
        child = int(marker.read_text())
        launcher.kill()
        launcher.wait(timeout=5)
        end = time.monotonic()+5
        while active(child) and time.monotonic()<end:
            time.sleep(.05)
        assert not active(child), 'Pinned Runner survived its terminated dispatch owner'
    finally:
        if launcher.poll() is None:
            launcher.kill()
        launcher.wait(timeout=5)
        if child and active(child):
            os.kill(child, signal.SIGKILL)


def test_complete_saved_response_finalization_cannot_extend_paid_window(tmp_path):
    import time
    from experiments import run_matrix
    from experiments.hosted_pinned_worker import saved_output_finalization
    from test_hosted_campaign_execute import _saved_admission
    from ura.runner import BudgetExhausted, GlobalCallBudget
    admission,calls = _saved_admission(tmp_path)
    ledger = tmp_path/'expired-budget.json'
    options = dict(max_target_calls=10,max_judge_calls=10,max_http_attempts=10,
        deadline_epoch=time.time()-10,state_path=ledger,budget_id='same-budget')
    budget = GlobalCallBudget(**options)
    budget.target_calls = len(calls)
    budget._persist()
    before = ledger.read_bytes()
    with saved_output_finalization(admission) as finalizing:
        assert finalizing
        restored = run_matrix.GlobalCallBudget(**options)
        restored.raise_if_deadline_reached()
        with pytest.raises(BudgetExhausted,match='finalization cannot start'):
            restored.charge_target()
        with pytest.raises(BudgetExhausted,match='finalization cannot start'):
            restored.charge_judge(1)
        # The actual call-start deadline itself is never cleared or extended.
        with pytest.raises(BudgetExhausted,match='deadline reached'):
            restored._check_deadline()
        assert restored.snapshot() == budget.snapshot()
    assert ledger.read_bytes()==before and run_matrix.GlobalCallBudget is GlobalCallBudget
    path = tmp_path/'answers/saved.responses.checkpoint.jsonl'
    path.write_text(path.read_text().splitlines()[0]+'\n')
    with saved_output_finalization(admission) as finalizing:
        assert not finalizing and run_matrix.GlobalCallBudget is GlobalCallBudget
        with pytest.raises(BudgetExhausted,match='deadline reached'):
            run_matrix.GlobalCallBudget(**options).raise_if_deadline_reached()


def test_explicit_continuation_renews_time_but_not_consumed_call_caps(tmp_path, monkeypatch):
    import time
    from experiments import run_matrix
    from experiments.hosted_pinned_worker import continuation_call_window
    from ura.runner import BudgetExhausted, GlobalCallBudget
    window = tmp_path/'successor/job-window.json'
    admission = SimpleNamespace(continuation_window_path=str(window),
        requests={'a':{'call_id':'same-funded-call'}},job={'name':'remaining',
        'argv':['--out',str(tmp_path/'answers'),'--deadline-seconds','120']})
    ledger = tmp_path/'original-budget.json'
    options = dict(max_target_calls=3,max_judge_calls=3,max_http_attempts=3,
        deadline_epoch=time.time()-1000,state_path=ledger,budget_id='original')
    original = GlobalCallBudget(**options)
    original.target_calls = original.http_attempts = 2
    original._persist()
    with continuation_call_window(admission):
        continued = run_matrix.GlobalCallBudget(**options)
        assert continued.target_calls == 2
        continued.raise_if_deadline_reached()
        continued.charge_target()
        assert continued.target_calls == 3
        with pytest.raises(BudgetExhausted,match='ceiling'):
            continued.charge_target()
        assert continued.deadline_epoch == original.deadline_epoch
    saved = window.read_bytes()
    metadata = json.loads(saved)
    assert metadata['duration_seconds']==120 and metadata['deadline_epoch']>time.time()
    assert json.loads(ledger.read_text())['target_calls']==3
    with continuation_call_window(admission):
        assert window.read_bytes()==saved
        monkeypatch.setattr(time,'time',lambda:metadata['deadline_epoch']+1)
        with pytest.raises(BudgetExhausted,match='continuation call-start window has expired'):
            run_matrix.GlobalCallBudget(**options).raise_if_deadline_reached()
    assert run_matrix.GlobalCallBudget is GlobalCallBudget
