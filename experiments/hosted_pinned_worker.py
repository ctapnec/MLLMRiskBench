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
from contextlib import contextmanager


@contextmanager
def saved_output_finalization(admission):
    """Finish retained output after a start window expires, with no new calls.

    Older Runner versions check the start deadline even while restoring a fully
    saved response set. This controller-side budget specialization leaves the
    persisted deadline/counters untouched and prohibits *every* new reservation.
    It is not an extension of the original call-start window. Runner still
    validates the checkpoints and all the original execution bindings.
    """
    argv = admission.job['argv']
    out = Path(argv[argv.index('--out')+1])
    if not out.is_dir() or not any(out.glob('*.responses*.jsonl')):
        yield False
        return
    from experiments import run_matrix
    from experiments.hosted_campaign_execute import _saved_job_complete
    from ura.runner import BudgetExhausted

    if not _saved_job_complete(admission):
        yield False
        return
    original = run_matrix.GlobalCallBudget

    class SavedOutputBudget(original):
        def raise_if_deadline_reached(self):
            # Preparation/restoration can proceed, but _reserve never can.
            return None

        def _reserve(self, *, target=0, judge=0, http=0):
            if target or judge or http:
                raise BudgetExhausted('Saved-output finalization cannot start a target or model-judge call')

    run_matrix.GlobalCallBudget = SavedOutputBudget
    try:
        print('Finalizing saved responses only; no new target or model-judge calls are permitted.', flush=True)
        yield True
    finally:
        run_matrix.GlobalCallBudget = original


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
    with saved_output_finalization(admission):
        output = execute(admission, responses_only=responses_only)
    with os.fdopen(result_fd, 'w') as stream:
        json.dump(dict(status='complete', output=output), stream)


if __name__ == '__main__':
    main()
