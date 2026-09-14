"""Private subprocess entry point for an already-admitted hosted continuation.

Only standard-library modules are imported before selecting the original source.
This file belongs to the current orchestration; Runner and all its dependencies
inside this repository are imported from the saved execution revision.
"""
import json
import os
from pathlib import Path
import pickle
import sys


def main():
    if sys.platform == 'linux':
        # A terminated dispatch worker must not leave this Runner behind.
        import ctypes
        import signal
        if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'Unable to bind worker lifetime to its parent')
        if os.getppid() != int(sys.argv[3]):
            raise RuntimeError('Continuation owner exited before Runner started')
    checkout = Path(sys.argv[1]).resolve(strict=True)
    result_fd = int(sys.argv[2])
    # Remove this script's newer experiments directory from module discovery.
    sys.path[0:1] = [str(checkout), str(checkout/'src')]
    admission, responses_only = pickle.load(sys.stdin.buffer)
    from experiments.hosted_retained_execute import _validated_checkout
    _validated_checkout(checkout, admission.execution_commit)
    if hasattr(admission, 'runtime_program'):
        from experiments.hosted_runtime_collection import run_runtime_admission as execute
    else:
        from experiments.hosted_dispatch import run_admission as execute
    output = execute(admission, responses_only=responses_only)
    with os.fdopen(result_fd, 'w') as stream:
        json.dump(dict(status='complete', output=output), stream)


if __name__ == '__main__':
    main()
