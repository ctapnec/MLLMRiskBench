"""Explicit, opt-in full-file checksum revalidation of retained artifacts.

Descriptors continue to carry the digest recorded by their producer. Callers
must still check file type, size and their record/schema relationships. With
full checking disabled, those checks do not establish unchanged file bytes.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import hashlib
from pathlib import Path
import sys

_FULL_CHECKS = ContextVar("ura_full_artifact_checks", default=False)


def artifact_sha256_enabled() -> bool:
    return _FULL_CHECKS.get()


def artifact_verification_cli(main):
    """Scope an explicitly declared CLI flag, including nested artifact readers."""
    @wraps(main)
    def wrapped(argv=None):
        arguments = list(sys.argv[1:] if argv is None else argv)
        with artifact_verification(verify_sha256="--verify-artifact-sha256" in arguments):
            return main(arguments)
    return wrapped


@contextmanager
def artifact_verification(*, verify_sha256: bool = False):
    if type(verify_sha256) is not bool:
        raise ValueError("artifact checksum option must be boolean")
    token = _FULL_CHECKS.set(verify_sha256)
    try:
        yield
    finally:
        _FULL_CHECKS.reset(token)


def check_artifact_sha256(path: Path, expected: str, *, payload: bytes | None = None) -> None:
    """Hash only on explicit request; never relabel metadata checks as hashing."""
    if not artifact_sha256_enabled():
        return
    digest = hashlib.sha256()
    if payload is not None:
        digest.update(payload)
    else:
        with Path(path).open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError(f"artifact sha256 mismatch: {path}")
