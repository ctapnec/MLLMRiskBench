"""Give the no-generation reader access to its explicitly retained media index.

This does not configure a live provider, discover images, or fetch remote media.
The normal replay reader still reconciles the original inputs and media bytes.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from experiments.hosted_campaign_budget import load_bound_json
from ura.artifact_checks import artifact_sha256_enabled


@lru_cache(maxsize=32)
def _index_directories(path, digest, size, metadata, full_checks):
    # Metadata and the explicit checking mode participate in the cache key.
    # A shared index is read once per unchanged file, not once per source job.
    value, descriptor = load_bound_json(Path(path), digest)
    if descriptor['bytes'] != size or not isinstance(value, dict):
        raise ValueError('Retained judging media index differs from its program')
    directories = set()
    for key, locator in value.items():
        if (not isinstance(key, str) or len(key) != 64 or any(c not in '0123456789abcdef' for c in key)
                or not isinstance(locator, str) or not Path(locator).is_absolute()):
            raise ValueError('Retained judging media index needs content IDs and explicit local files')
        media = Path(locator).resolve(strict=True)
        if not media.is_file():
            raise ValueError('Retained judging media locator is not a file')
        directories.add(media.parent)
    return tuple(sorted(directories))


def reader_media_roots(program, existing=()):
    """Extend only the no-call reader, retaining the existing root order."""
    roots = tuple(Path(root) for root in existing)
    descriptor = program.get('sources', {}).get('media_index')
    if descriptor is None:
        return roots
    if not isinstance(descriptor, dict) or set(descriptor) != {'path', 'sha256', 'bytes'}:
        raise ValueError('Retained judging media index descriptor differs')
    path = Path(descriptor['path'])
    stat = path.stat()
    directories = _index_directories(str(path), descriptor['sha256'], descriptor['bytes'],
        (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_ino), artifact_sha256_enabled())
    return roots + tuple(directory for directory in directories
        if not any(directory.is_relative_to(root) for root in roots))
