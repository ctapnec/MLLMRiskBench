"""Real isolated Python/Git boundary; no provider, model or download calls."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_execution_checkout as subject


def git(repo, *argv):
    return subprocess.check_output(['git', '-C', str(repo), *argv], text=True).strip()


def repository(tmp_path):
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
    (repo/'experiments/hosted_dispatch.py').write_text(
        'import json\nfrom pathlib import Path\n'
        'def run_admission(admission, *, responses_only):\n'
        '    assert responses_only is True\n'
        '    assert Path(__file__).parents[1] == Path(admission.execution_checkout)\n'
        '    assert json.loads(Path(admission.checkpoint).read_text()) == admission.saved_response\n'
        '    assert admission.requests == {"input": {"call_id": "already-paid"}}\n'
        '    return admission.job["output"]\n')
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
        job={'output':str(previous)})
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
