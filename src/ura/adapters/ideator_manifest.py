"""Strict, campaign-neutral manifest contract for IDEATOR seed-pair replay."""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any

from ._native_artifacts import json_sha256

FORMAT_VERSION = "ura-ideator-seed-pairs/2"
_HEX40_64 = re.compile(r"[0-9a-f]{40,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PAIR_FIELDS = {
    "image_path", "image_sha256", "source_id", "source_text_sha256", "text",
    "upstream_image_path", "upstream_index", "upstream_record_sha256",
    "upstream_split",
}


def _nonblank(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _artifact(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "bytes", "file", "records", "sha256",
    }:
        raise ValueError(f"IDEATOR {label} artifact has invalid fields")
    filename = value.get("file")
    if (
        not _nonblank(filename)
        or PurePosixPath(filename).name != filename
        or not isinstance(value.get("sha256"), str)
        or _HEX64.fullmatch(value["sha256"]) is None
        or isinstance(value.get("bytes"), bool)
        or not isinstance(value.get("bytes"), int)
        or value["bytes"] < 1
        or isinstance(value.get("records"), bool)
        or not isinstance(value.get("records"), int)
        or value["records"] < 1
    ):
        raise ValueError(f"IDEATOR {label} artifact identity is invalid")
    return value


def validate_manifest(document: object) -> dict[str, Any]:
    """Validate structural provenance without imposing one campaign selection."""

    if not isinstance(document, dict) or set(document) != {
        "content_sha256", "dataset", "format_version", "generator_source",
        "runner_selection", "seed_pairs", "source_mapping",
    }:
        raise ValueError("IDEATOR v2 manifest has invalid fields")
    if document.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"IDEATOR manifest must use {FORMAT_VERSION}")

    dataset = document.get("dataset")
    if not isinstance(dataset, dict) or set(dataset) != {
        "artifacts", "license", "repo_id", "revision",
    }:
        raise ValueError("IDEATOR dataset provenance has invalid fields")
    artifacts = dataset.get("artifacts")
    if (
        not _nonblank(dataset.get("repo_id"))
        or not isinstance(dataset.get("revision"), str)
        or _HEX40_64.fullmatch(dataset["revision"]) is None
        or not _nonblank(dataset.get("license"))
        or not isinstance(artifacts, list)
        or not artifacts
    ):
        raise ValueError("IDEATOR dataset provenance is invalid")
    for index, artifact in enumerate(artifacts):
        _artifact(artifact, label=f"dataset[{index}]")
    if len({artifact["file"] for artifact in artifacts}) != len(artifacts):
        raise ValueError("IDEATOR dataset artifacts repeat a file")

    generator = document.get("generator_source")
    if not isinstance(generator, dict) or set(generator) != {
        "commit", "license_declared", "license_spdx", "repo", "tree",
    }:
        raise ValueError("IDEATOR generator-source provenance has invalid fields")
    declared = generator.get("license_declared")
    if (
        not _nonblank(generator.get("repo"))
        or not isinstance(generator.get("commit"), str)
        or _HEX40_64.fullmatch(generator["commit"]) is None
        or not isinstance(generator.get("tree"), str)
        or _HEX40_64.fullmatch(generator["tree"]) is None
        or not isinstance(declared, bool)
        or (declared and not _nonblank(generator.get("license_spdx")))
        or (not declared and generator.get("license_spdx") is not None)
    ):
        raise ValueError("IDEATOR generator-source provenance is invalid")

    selection = document.get("runner_selection")
    if not isinstance(selection, dict) or set(selection) != {
        "corpus_name", "limit", "sample_seed", "selected_source_ids",
    }:
        raise ValueError("IDEATOR Runner selection has invalid fields")
    selected_ids = selection.get("selected_source_ids")
    if (
        not _nonblank(selection.get("corpus_name"))
        or isinstance(selection.get("limit"), bool)
        or not isinstance(selection.get("limit"), int)
        or selection["limit"] < 0
        or isinstance(selection.get("sample_seed"), bool)
        or not isinstance(selection.get("sample_seed"), int)
        or not isinstance(selected_ids, list)
        or not selected_ids
        or any(not _nonblank(item) for item in selected_ids)
        or len(set(selected_ids)) != len(selected_ids)
    ):
        raise ValueError("IDEATOR Runner selection is invalid")

    mapping = document.get("source_mapping")
    if not isinstance(mapping, dict) or set(mapping) != {
        "matched_records", "matching_policy", "official_records",
        "source_artifact", "source_corpus", "source_records",
    }:
        raise ValueError("IDEATOR source mapping has invalid fields")
    source_artifact = _artifact(mapping.get("source_artifact"), label="source")
    for field in ("matched_records", "official_records", "source_records"):
        if (
            isinstance(mapping.get(field), bool)
            or not isinstance(mapping.get(field), int)
            or mapping[field] < 1
        ):
            raise ValueError("IDEATOR source mapping counts are invalid")
    if (
        mapping.get("matching_policy") != "exact_utf8_query_v1"
        or mapping.get("source_corpus") != selection["corpus_name"]
        or mapping["source_records"] != source_artifact["records"]
        or mapping["matched_records"] > mapping["official_records"]
    ):
        raise ValueError("IDEATOR source mapping is inconsistent")

    pairs = document.get("seed_pairs")
    if (
        not isinstance(pairs, list)
        or not pairs
        or len(pairs) != mapping["matched_records"]
    ):
        raise ValueError("IDEATOR seed-pair count differs from source mapping")
    observed_source_ids: list[str] = []
    for index, pair in enumerate(pairs):
        if not isinstance(pair, dict) or set(pair) != _PAIR_FIELDS:
            raise ValueError(f"IDEATOR seed pair {index} has invalid fields")
        source_id = pair.get("source_id")
        upstream_path = pair.get("upstream_image_path")
        upstream = PurePosixPath(upstream_path) if _nonblank(upstream_path) else None
        if (
            source_id not in selected_ids
            or not _nonblank(pair.get("text"))
            or not _nonblank(pair.get("image_path"))
            or not _nonblank(pair.get("upstream_split"))
            or isinstance(pair.get("upstream_index"), bool)
            or not isinstance(pair.get("upstream_index"), int)
            or pair["upstream_index"] < 0
            or upstream is None
            or upstream.is_absolute()
            or ".." in upstream.parts
            or any(
                not isinstance(pair.get(field), str)
                or _HEX64.fullmatch(pair[field]) is None
                for field in (
                    "image_sha256", "source_text_sha256",
                    "upstream_record_sha256",
                )
            )
        ):
            raise ValueError(f"IDEATOR seed pair {index} is not exactly source-bound")
        if source_id not in observed_source_ids:
            observed_source_ids.append(source_id)
    if observed_source_ids != selected_ids:
        raise ValueError("IDEATOR selected source IDs differ from mapped seed pairs")

    unsigned = {key: value for key, value in document.items() if key != "content_sha256"}
    if document.get("content_sha256") != json_sha256(unsigned):
        raise ValueError("IDEATOR manifest content digest is stale")
    return document


__all__ = ["FORMAT_VERSION", "validate_manifest"]
