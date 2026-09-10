"""Bounded reuse of validation while its observed filesystem inputs are unchanged.

This is a metadata cache, not a claim of cryptographic integrity. No budget,
reservation, network response or live process state belongs in this cache.
"""
from collections import OrderedDict
from contextvars import ContextVar
from copy import deepcopy
import os
from pathlib import Path
from threading import RLock
import time


_OBSERVED = ContextVar("ura_validation_dependencies", default=None)


def _metadata(path: Path, recursive: bool = False):
    def stamp(item):
        try:
            value = item.lstat()
        except FileNotFoundError:
            return (str(item), None)
        return (str(item), value.st_dev, value.st_ino, value.st_mode,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    values = [stamp(path)]
    if recursive and path.is_dir() and not path.is_symlink():
        for directory, dirs, files in os.walk(path, followlinks=False):
            dirs.sort()
            files.sort()
            values.extend(stamp(Path(directory) / name) for name in [*dirs, *files])
    return tuple(values)


def observe_validation_path(path, *, recursive: bool = False):
    """A reader records the actual files it consumes, including indirect inputs."""
    observed = _OBSERVED.get()
    if observed is not None:
        key = (Path(path).absolute(), recursive)
        if key not in observed:
            observed[key] = _metadata(*key)


class ValidationCache:
    def __init__(self, *, entries=8, copy_results=True):
        self.entries = entries
        self.copy_results = copy_results
        self._values = OrderedDict()
        self._lock = RLock()
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)

    def _after_fork(self):
        # A controller can validate once before forking read-only API workers.
        # Each child inherits the result, but never a lock held by another thread.
        self._lock = RLock()

    def _return(self, value):
        return deepcopy(value) if self.copy_results else value

    def get(self, key, loader, *, paths=(), trees=()):
        with self._lock:
            previous = self._values.get(key)
            if previous is not None:
                value, observed = previous
                # Rapid same-size rewrites can share a filesystem clock tick.
                # Do not reuse recently modified data; this never sleeps or
                # delays a request, and old immutable history stays reusable.
                settled = all(row[1] is None or max(row[-2:]) < time.time_ns() - 1_000_000_000
                              for inventory in observed.values() for row in inventory)
                if settled and all(_metadata(*dependency) == stamp for dependency, stamp in observed.items()):
                    self._values.move_to_end(key)
                    parent = _OBSERVED.get()
                    if parent is not None:
                        parent.update(observed)
                    return self._return(value)
                del self._values[key]
            observed = {}
            parent = _OBSERVED.get()
            token = _OBSERVED.set(observed)
            try:
                for path in paths:
                    observe_validation_path(path)
                for path in trees:
                    observe_validation_path(path, recursive=True)
                value = loader()
            finally:
                _OBSERVED.reset(token)
                if parent is not None:
                    parent.update(observed)
            # Live outputs may change during a read. Return the reader's own
            # observation, but never reuse it as validation of a later state.
            if observed and all(_metadata(*dependency) == stamp for dependency, stamp in observed.items()):
                saved = deepcopy(value) if self.copy_results else value
                self._values[key] = saved, observed
                while len(self._values) > self.entries:
                    self._values.popitem(last=False)
            return value
