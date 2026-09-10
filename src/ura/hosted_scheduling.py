"""Optional local-scoring serialization for independent hosted job processes.

Only hosted controllers enter this scope. It does not alter model inputs,
generation parameters, verdicts, paid reservations or local campaign execution.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
import time


_SCORING_SLOT = ContextVar("hosted_local_scoring_slot", default=None)


class _ScoringSlot:
    def __init__(self, path: Path, timeout_seconds: float):
        self.path = path
        self.timeout_seconds = timeout_seconds
        self.stream = None

    def acquire(self):
        if self.stream is not None:
            return
        import fcntl

        stream = self.path.open("a+b")
        deadline = time.monotonic() + self.timeout_seconds
        try:
            while True:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("hosted local-judge GPU slot wait expired") from None
                    time.sleep(0.25)
        except BaseException:
            stream.close()
            raise
        self.stream = stream

    def release(self):
        if self.stream is not None:
            import fcntl

            try:
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            finally:
                self.stream.close()
                self.stream = None


@contextmanager
def hosted_local_scoring_slot(path: Path, *, timeout_seconds: float = 3600):
    """Acquire lazily at judge load; release only after Runner model teardown."""
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent or path.is_symlink():
        raise ValueError("hosted scoring slot needs a resolved regular lock path")
    if not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 86400:
        raise ValueError("hosted scoring slot timeout is invalid")
    if _SCORING_SLOT.get() is not None:
        raise RuntimeError("a hosted scoring slot is already configured")
    slot = _ScoringSlot(path, timeout_seconds)
    token = _SCORING_SLOT.set(slot)
    try:
        yield
    finally:
        try:
            slot.release()
        finally:
            _SCORING_SLOT.reset(token)


def acquire_hosted_local_scoring_slot():
    """No-op for ordinary Runner/UI/local execution without a hosted scheduler."""
    slot = _SCORING_SLOT.get()
    if slot is not None:
        slot.acquire()
