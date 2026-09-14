"""Resume saved hosted work with its original executable source after deployment.

The console/controller may advance independently. A continuation keeps the old
request, runtime and checkpoint bindings and runs Runner in a clean detached
checkout of their exact revision. No models or environments are copied.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pickle
import subprocess
import sys


def execution_checkout(project_root, expected_commit, resume_from):
    from experiments.hosted_retained_execute import _validated_checkout

    try:
        _validated_checkout(project_root, expected_commit)
        return project_root
    except ValueError:
        if resume_from is None:
            raise
    if (not resume_from.is_absolute() or resume_from.is_symlink()
            or resume_from.resolve(strict=True) != resume_from or not resume_from.is_dir()):
        raise ValueError('Previous collection must be one resolved directory')
    # A newer clean deployment is recoverable, a dirty or invalid root is not.
    current = subprocess.check_output(
        ['git', '-C', str(project_root), 'rev-parse', 'HEAD'], text=True).strip()
    _validated_checkout(project_root, current)
    previous = json.loads((resume_from/'selection.json').read_text())
    if (previous.get('project_root') != str(project_root)
            or previous.get('expected_commit') != expected_commit):
        raise ValueError('Continuation must keep its saved project and revision')
    if previous.get('prepare_runtime') and not (
            Path(previous['runtime_root'])/'programs.json').is_file():
        raise ValueError('The original runtime preparation is incomplete; inspect its job before recovery')
    return pinned_checkout(project_root, expected_commit)


def pinned_checkout(project_root, expected_commit):
    """Cache only tracked source, serialized against another checkout creator."""
    import fcntl
    import re
    from experiments.hosted_retained_execute import _validated_checkout

    if not re.fullmatch(r'[0-9a-f]{40}', expected_commit):
        raise ValueError('Continuation needs its exact saved commit')
    common = Path(subprocess.check_output(['git', '-C', str(project_root),
        'rev-parse', '--path-format=absolute', '--git-common-dir'], text=True).strip()).resolve(strict=True)
    parent = common/'ura-continuations'
    parent.mkdir(mode=0o700, exist_ok=True)
    checkout = parent/expected_commit
    with (common/'ura-continuations.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if not checkout.exists() and not checkout.is_symlink():
            subprocess.run(['git', '-C', str(project_root), 'worktree', 'add', '--detach',
                str(checkout), expected_commit], check=True)
        _validated_checkout(checkout, expected_commit)
    return checkout


def run_pinned_admission(admission, *, responses_only):
    """Transfer the already-admitted job to the original Runner, not a new call.

    As with the dispatcher's forkserver, pickle travels only over a private
    parent-to-child pipe. No checkpoint, uploaded file or HTTP body is unpickled.
    Native logs remain streamed to the owning job's stdout/stderr.
    """
    checkout = Path(admission.execution_checkout)
    read_fd, write_fd = os.pipe()
    with os.fdopen(read_fd, 'r') as result_stream:
        try:
            process = subprocess.run([sys.executable,
                str(Path(__file__).with_name('hosted_pinned_worker.py')),
                str(checkout), str(write_fd), str(os.getpid())],
                input=pickle.dumps((admission, responses_only)),
                env={**os.environ, 'PYTHONPATH':os.pathsep.join((str(checkout), str(checkout/'src')))},
                pass_fds=(write_fd,), check=False)
        finally:
            os.close(write_fd)
        if process.returncode:
            raise RuntimeError('Original-revision Runner is unfinished; retain its response checkpoints')
        result = json.load(result_stream)
    if result.get('status') != 'complete' or not isinstance(result.get('output'), str):
        raise RuntimeError('Original-revision worker did not report a completed job')
    return result['output']
