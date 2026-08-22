"""Fail-closed cleanup of pytest's immutable-controller temporary directory."""

from __future__ import annotations

import argparse
import errno
import os
from pathlib import Path
import shutil
import stat
import sys

if os.name == "posix":  # pragma: no branch - Windows never runs the cleaner
    import pwd


class CleanupRefusal(RuntimeError):
    """The requested cleanup is outside the narrowly authorized root."""


def expected_pytest_tmp_root() -> Path:
    """Return the one per-user pytest root a rig re-pin is allowed to remove."""
    if os.name != "posix":
        raise CleanupRefusal("pytest temporary-root cleanup requires POSIX")
    return Path("/tmp") / f"pytest-of-{pwd.getpwuid(os.getuid()).pw_name}"


def _lstat_directory(path: Path, *, expected_uid: int | None = None) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(metadata.st_mode):
        raise CleanupRefusal(f"refusing symlinked pytest temp root: {path}")
    if not stat.S_ISDIR(metadata.st_mode):
        raise CleanupRefusal(f"refusing non-directory pytest temp root: {path}")
    if expected_uid is not None and metadata.st_uid != expected_uid:
        raise CleanupRefusal(
            f"refusing foreign-owned pytest temp root: {path} "
            f"(uid {metadata.st_uid}, expected {expected_uid})"
        )
    return metadata


def make_directories_user_cleanable(root: Path, *, expected_uid: int | None = None) -> None:
    """Add owner rwx only to directories reached through no-follow descriptors."""
    _lstat_directory(root, expected_uid=expected_uid)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def visit(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise CleanupRefusal("descriptor is not a directory")
        if expected_uid is not None and metadata.st_uid != expected_uid:
            raise CleanupRefusal(
                f"refusing foreign-owned directory beneath pytest temp root: "
                f"uid {metadata.st_uid}, expected {expected_uid}"
            )
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) | stat.S_IRWXU)
        # listdir accepts a directory fd without taking ownership of it. Keep
        # that descriptor live for every following openat operation.
        children = os.listdir(descriptor)
        for name in children:
            try:
                child = os.open(name, flags, dir_fd=descriptor)
            except FileNotFoundError:
                continue
            except OSError as error:
                # Files and symlinks never need a chmod to be removed. A
                # no-follow open of either is intentionally ignored.
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    continue
                raise CleanupRefusal(f"cannot safely open {name!r} beneath cleanup root") from error
            try:
                visit(child)
            finally:
                os.close(child)

    descriptor = os.open(root, flags)
    try:
        visit(descriptor)
    finally:
        os.close(descriptor)


def clean_owned_pytest_tmp_root(root: Path, *, expected_root: Path | None = None) -> None:
    """Safely remove the exact owner-scoped pytest root, if it exists."""
    expected = expected_pytest_tmp_root() if expected_root is None else expected_root
    if root != expected:
        raise CleanupRefusal(f"refusing unexpected pytest temp root: {root}")
    if root.is_symlink():
        raise CleanupRefusal(f"refusing symlinked pytest temp root: {root}")
    if not root.exists():
        return
    _lstat_directory(root, expected_uid=os.getuid())
    if not shutil.rmtree.avoids_symlink_attacks:
        raise CleanupRefusal("Python rmtree lacks fd-safe symlink protection")
    make_directories_user_cleanable(root, expected_uid=os.getuid())
    try:
        shutil.rmtree(root)
    except OSError as error:
        raise CleanupRefusal(f"cannot remove pytest temp root: {root}") from error
    if root.exists() or root.is_symlink():
        raise CleanupRefusal(f"pytest temp root remains after cleanup: {root}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        clean_owned_pytest_tmp_root(arguments.root)
    except CleanupRefusal as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
