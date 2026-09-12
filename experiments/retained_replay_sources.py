"""Recover original replay inputs from admitted local runs, without model calls.

Conversion is shared per distinct source within one preparation. This module
does not discover files recursively, inspect answers, change sampling, or fetch
remote media. It supplies the existing retained-input selector/materializer.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ura.converters._common import canonical_converted_corpus_sha256
from ura.data_models import DataPoint


def source_populations(cells: Sequence[Mapping[str, Any]]) -> dict[str, list[DataPoint]]:
    """Restore the recorded source order and subset, never resample a corpus."""
    from experiments import run_matrix

    populations, converted = {}, {}
    for cell in cells:
        run_id = cell["run_id"]
        if run_id in populations:
            raise ValueError("A replay source run was selected more than once")
        manifest = cell["manifest"]
        run = manifest["config"]["run"]
        audit = run.get("sampling_audit")
        if not isinstance(audit, Mapping) or not isinstance(audit.get("source_instance"), Mapping):
            raise ValueError(f"Source run {run_id} lacks its original sampling/source record")
        instance = dict(audit["source_instance"])
        if instance.get("synth") or instance.get("converter") == "synth":
            raise ValueError("Synthetic sources are not measured local replay inputs")
        path = run_matrix._source_instance_path(run["corpus"], instance).resolve(strict=True)
        key = (instance["converter"], str(path), audit["full_converted_corpus_sha256"])
        if key not in converted:
            points = list(run_matrix.get_converter(instance["converter"]).parse(path))
            if canonical_converted_corpus_sha256(points) != audit["full_converted_corpus_sha256"]:
                raise ValueError(f"Original converted source differs for run {run_id}")
            converted[key] = points
        full = converted[key]
        indices = audit.get("selected_indices")
        if (not isinstance(indices, list)
                or any(type(index) is not int or not 0 <= index < len(full) for index in indices)
                or len(indices) != len(set(indices))):
            raise ValueError(f"Original selected source positions are invalid for run {run_id}")
        selected = [full[index] for index in indices]
        if ([point.id for point in selected] != audit.get("selected_ids")
                or canonical_converted_corpus_sha256(selected) != manifest["dataset_hashes"]["corpus"]):
            raise ValueError(f"Original selected source population differs for run {run_id}")
        populations[run_id] = selected
    return populations


def source_media_index(
    candidates: Sequence[Mapping[str, Any]],
    populations: Mapping[str, Sequence[DataPoint]],
    supplied: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Resolve only selected inputs from converted sources or retained aliases.

    A content-only locator with no original source path needs an explicit index;
    guessing a filename or scanning the result store is not a substitute.
    """
    from experiments.hosted_retained_inputs import _descriptor, _media_bindings
    from ura.targets.api import _media_roots, _resolve_local_media_path

    required = {}
    for candidate in candidates:
        for turn in candidate["rendered_input"]:
            for ref in turn.get("media") or []:
                if ref.get("path"):
                    required.setdefault(ref["sha256"], set()).add(ref["path"])
    index = {digest: path for digest, path in (supplied or {}).items() if digest in required}
    for points in populations.values():
        for point in points:
            refs = [*point.media, *(ref for turn in point.dialog_history for ref in turn.media)]
            for ref in refs:
                if ref.sha256 in required and ref.sha256 not in index and ref.path:
                    path = Path(ref.path)
                    # Portable aliases are resolved against the configured roots below.
                    if path.is_absolute():
                        index[ref.sha256] = str(path.resolve(strict=True))
    roots = None
    for digest, locators in required.items():
        if digest not in index:
            aliases = sorted(value for value in locators if value.startswith("@media-root/"))
            if not aliases:
                raise ValueError("Selected media lacks an original file location; supply its media index")
            if roots is None:
                roots = _media_roots()
            path, _ = _resolve_local_media_path(aliases[0], roots)
            index[digest] = str(path)
        index[digest] = _descriptor(Path(index[digest]), digest)["path"]
    # Reuse the existing physical/inline media contract. Full file checksum
    # revalidation remains governed by the caller's opt-in setting.
    for candidate in candidates:
        _media_bindings(candidate["rendered_input"], index)
    return index
