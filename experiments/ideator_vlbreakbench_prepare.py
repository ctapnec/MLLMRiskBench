"""Prepare the eight exact AdvBench-mapped IDEATOR/VLBreakBench seed pairs.

The public IDEATOR source and its released dataset have separate provenance and
licensing. This command runs no generator. It retains only official dataset rows
whose query exactly equals an admitted AdvBench prompt, copies their PNGs under
content-derived names, and emits a one-to-one source-mapped replay manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
for _bootstrap in (ROOT, ROOT / "src"):
    if str(_bootstrap) not in sys.path:
        sys.path.insert(0, str(_bootstrap))

from experiments.run_matrix import _select_corpus  # noqa: E402
from ura.adapters._native_artifacts import (  # noqa: E402
    json_sha256,
    read_binary_artifact,
)
from ura.adapters.ideator_manifest import (  # noqa: E402
    FORMAT_VERSION,
    validate_manifest as validate_generic_manifest,
)
from ura.converters.advbench import AdvBenchConverter  # noqa: E402
from ura.strict_json import strict_json_loads  # noqa: E402


DATASET_REPO_ID = "wang021/VLBreakBench"
DATASET_REVISION = "10b1ce5ab4546b5c2ab27c0aed4e171ab8ee98a0"
DATASET_LICENSE = "apache-2.0"
GENERATOR_SOURCE_REPO = "https://github.com/roywang021/IDEATOR"
GENERATOR_SOURCE_COMMIT = "504a9825f97c833fb4c3da1feb5542594024d0bd"
GENERATOR_SOURCE_TREE = "1e181bca68af2f5fbc4adc6e7bf5c071600e327f"
ADVBENCH_SOURCE_ID = "advbench:245"
ADVBENCH_SOURCE_TEXT_SHA256 = (
    "64259f48114404dccc12f393ea57dd259dffe0180ad51d9840da9ff7e20566f9"
)
ADVBENCH_ARTIFACT = {
    "bytes": 82125,
    "file": "harmful_behaviors.csv",
    "records": 520,
    "sha256": "6cd1a5c63c07610d7eb67307772ee5606017ee950b5770ab288a2c487489d3e1",
}
RUNNER_CORPUS_NAME = "advbench_harmful"
RUNNER_LIMIT = 1
RUNNER_SAMPLE_SEED = 105
DATASET_ARTIFACTS: tuple[dict[str, object], ...] = (
    {
        "file": "vlbreakbench_base.json",
        "sha256": "264f68ac656a6c8880e447821dc9f2858cd26db88fcbd7c4a80941e36945a523",
        "bytes": 759127,
        "records": 916,
    },
    {
        "file": "vlbreakbench_challenge.json",
        "sha256": "c077e482530cf9ec7c403d4022204ff266c2226cd55830439187a67d24404f00",
        "bytes": 2875553,
        "records": 2738,
    },
)
EXPECTED_MATCHES = (
    ("base", 720), ("base", 832),
    ("challenge", 2160), ("challenge", 2161),
    ("challenge", 2162), ("challenge", 2495),
    ("challenge", 2496), ("challenge", 2497),
)


def _official_dataset_descriptor() -> dict[str, object]:
    return {
        "artifacts": [dict(item) for item in DATASET_ARTIFACTS],
        "license": DATASET_LICENSE,
        "repo_id": DATASET_REPO_ID,
        "revision": DATASET_REVISION,
    }


def _generator_source_descriptor() -> dict[str, object]:
    return {
        "commit": GENERATOR_SOURCE_COMMIT,
        "license_declared": False,
        "license_spdx": None,
        "repo": GENERATOR_SOURCE_REPO,
        "tree": GENERATOR_SOURCE_TREE,
    }


def _runner_selection_descriptor() -> dict[str, object]:
    return {
        "corpus_name": RUNNER_CORPUS_NAME,
        "limit": RUNNER_LIMIT,
        "sample_seed": RUNNER_SAMPLE_SEED,
        "selected_source_ids": [ADVBENCH_SOURCE_ID],
    }


def validate_manifest(document: object) -> dict[str, Any]:
    """Apply this campaign's exact release, source, selection and row checks."""

    manifest = validate_generic_manifest(document)
    if manifest["dataset"] != _official_dataset_descriptor():
        raise ValueError("campaign IDEATOR dataset release is invalid")
    if manifest["generator_source"] != _generator_source_descriptor():
        raise ValueError("campaign IDEATOR generator source is invalid")
    if manifest["runner_selection"] != _runner_selection_descriptor():
        raise ValueError("campaign IDEATOR Runner selection is invalid")
    mapping = manifest["source_mapping"]
    if (
        mapping["source_artifact"] != ADVBENCH_ARTIFACT
        or mapping["matched_records"] != len(EXPECTED_MATCHES)
        or mapping["official_records"] != 3654
        or mapping["source_records"] != 520
        or mapping["source_corpus"] != RUNNER_CORPUS_NAME
    ):
        raise ValueError("campaign IDEATOR source artifact identity is invalid")
    observed = []
    for pair in manifest["seed_pairs"]:
        split, index = pair["upstream_split"], pair["upstream_index"]
        if (
            pair["source_id"] != ADVBENCH_SOURCE_ID
            or pair["source_text_sha256"] != ADVBENCH_SOURCE_TEXT_SHA256
            or pair["upstream_image_path"]
            != f"vlbreakbench_{split}/redteam_image_{index}.png"
        ):
            raise ValueError("campaign IDEATOR source-row binding is invalid")
        observed.append((split, index))
    if tuple(observed) != EXPECTED_MATCHES:
        raise ValueError("campaign IDEATOR exact matched rows are invalid")
    return manifest


def _dataset_records(path: Path, expected: Mapping[str, object]) -> list[dict[str, Any]]:
    resolved, raw = read_binary_artifact(path, max_bytes=4 * 1024 * 1024)
    if (
        resolved.name != expected["file"] or len(raw) != expected["bytes"]
        or hashlib.sha256(raw).hexdigest() != expected["sha256"]
    ):
        raise ValueError(f"{expected['file']} differs from the pinned dataset artifact")
    value = strict_json_loads(raw)
    fields = {"category", "subcategory", "query", "image_prompt", "text_prompt", "image"}
    if not isinstance(value, list) or len(value) != expected["records"]:
        raise ValueError(f"{expected['file']} has an invalid record count")
    if any(
        not isinstance(row, dict) or set(row) != fields
        or any(not isinstance(row[field], str) or not row[field].strip() for field in fields)
        for row in value
    ):
        raise ValueError(f"{expected['file']} has an invalid record")
    return [dict(row) for row in value]


def _advbench(path: Path) -> tuple[Path, bytes, list[Any]]:
    resolved, raw = read_binary_artifact(path, max_bytes=4 * 1024 * 1024)
    rows = AdvBenchConverter().parse(resolved)
    _resolved_after, raw_after = read_binary_artifact(resolved, max_bytes=4 * 1024 * 1024)
    prompts = [row.payload_text for row in rows]
    if (
        raw_after != raw or len(rows) != 520
        or [row.id for row in rows] != [f"advbench:{index}" for index in range(520)]
        or len(set(prompts)) != 520
    ):
        raise ValueError("IDEATOR mapping requires the stable 520-row AdvBench release")
    return resolved, raw, rows


def _prepared_image(source: Path, image_dir: Path) -> tuple[Path, str]:
    _path, raw = read_binary_artifact(source, max_bytes=25 * 1024 * 1024)
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"VLBreakBench image is not a PNG: {source.name}")
    digest = hashlib.sha256(raw).hexdigest()
    image_dir.mkdir(parents=True, exist_ok=True)
    root = image_dir.resolve(strict=True)
    if root != image_dir.absolute() or image_dir.is_symlink():
        raise ValueError("prepared image directory must be one resolved directory")
    target = root / f"ideator-image-{digest}.png"
    if target.exists():
        _target, existing = read_binary_artifact(target, max_bytes=25 * 1024 * 1024)
        if existing != raw:
            raise FileExistsError(f"prepared image collision: {target}")
    else:
        with target.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    return target, digest


def build_manifest(
    *, base_json: Path, challenge_json: Path, dataset_root: Path,
    advbench_csv: Path, prepared_image_dir: Path,
) -> dict[str, Any]:
    """Build the narrow eight-pair manifest without running IDEATOR."""

    root = dataset_root.absolute()
    if root.is_symlink() or not root.is_dir() or root.resolve(strict=True) != root:
        raise ValueError("VLBreakBench root must be one resolved directory")
    datasets = {
        "base": _dataset_records(base_json, DATASET_ARTIFACTS[0]),
        "challenge": _dataset_records(challenge_json, DATASET_ARTIFACTS[1]),
    }
    advbench_path, advbench_raw, source_rows = _advbench(advbench_csv)
    selected, indices, clusters, _population = _select_corpus(
        RUNNER_CORPUS_NAME, source_rows, RUNNER_LIMIT, RUNNER_SAMPLE_SEED
    )
    if indices != [245] or clusters != [ADVBENCH_SOURCE_ID]:
        raise ValueError("Runner selection no longer chooses advbench:245 alone")
    source_by_query = {row.payload_text: row for row in source_rows}
    pairs: list[dict[str, object]] = []
    for split, records in datasets.items():
        for upstream_index, row in enumerate(records):
            source = source_by_query.get(row["query"])
            if source is None:
                continue
            relative = f"vlbreakbench_{split}/redteam_image_{upstream_index}.png"
            if row["image"] != relative:
                raise ValueError("VLBreakBench exact-match image path is not canonical")
            try:
                image = (root / relative).resolve(strict=True)
                image.relative_to(root)
            except (OSError, ValueError) as exc:
                raise ValueError("VLBreakBench image escapes its dataset root") from exc
            prepared, image_sha256 = _prepared_image(image, prepared_image_dir)
            pairs.append({
                "image_path": str(prepared),
                "image_sha256": image_sha256,
                "source_id": source.id,
                "source_text_sha256": hashlib.sha256(row["query"].encode()).hexdigest(),
                "text": row["text_prompt"],
                "upstream_image_path": relative,
                "upstream_index": upstream_index,
                "upstream_record_sha256": json_sha256(row),
                "upstream_split": split,
            })
    if [(pair["upstream_split"], pair["upstream_index"]) for pair in pairs] != list(EXPECTED_MATCHES):
        raise ValueError("pinned releases no longer produce the reviewed eight matches")
    if {pair["source_id"] for pair in pairs} != {selected[0].id}:
        raise ValueError("exact matches differ from the selected admitted source row")
    unsigned = {
        "dataset": _official_dataset_descriptor(),
        "format_version": FORMAT_VERSION,
        "generator_source": _generator_source_descriptor(),
        "runner_selection": _runner_selection_descriptor(),
        "seed_pairs": pairs,
        "source_mapping": {
            "matched_records": len(pairs),
            "matching_policy": "exact_utf8_query_v1",
            "official_records": sum(len(rows) for rows in datasets.values()),
            "source_artifact": {
                "bytes": len(advbench_raw), "file": advbench_path.name,
                "records": len(source_rows),
                "sha256": hashlib.sha256(advbench_raw).hexdigest(),
            },
            "source_corpus": RUNNER_CORPUS_NAME,
            "source_records": len(source_rows),
        },
    }
    return validate_manifest({**unsigned, "content_sha256": json_sha256(unsigned)})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-json", required=True)
    parser.add_argument("--challenge-json", required=True)
    parser.add_argument("--dataset-root", required=True)
    parser.add_argument("--advbench", required=True)
    parser.add_argument("--prepared-image-dir", required=True)
    parser.add_argument("--out", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = Path(args.out).expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() or output.is_symlink() or output.parent.resolve(strict=True) != output.parent:
        raise FileExistsError(f"refusing unsafe or existing output: {output}")
    manifest = build_manifest(
        base_json=Path(args.base_json), challenge_json=Path(args.challenge_json),
        dataset_root=Path(args.dataset_root), advbench_csv=Path(args.advbench),
        prepared_image_dir=Path(args.prepared_image_dir).absolute(),
    )
    raw = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"
    with output.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    print(
        f"prepared {len(manifest['seed_pairs'])} exact-source IDEATOR pairs -> "
        f"{output} (sha256:{hashlib.sha256(raw).hexdigest()})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADVBENCH_ARTIFACT", "ADVBENCH_SOURCE_ID", "ADVBENCH_SOURCE_TEXT_SHA256",
    "DATASET_LICENSE", "DATASET_REPO_ID", "DATASET_REVISION", "EXPECTED_MATCHES",
    "FORMAT_VERSION", "GENERATOR_SOURCE_COMMIT", "GENERATOR_SOURCE_REPO",
    "GENERATOR_SOURCE_TREE", "RUNNER_CORPUS_NAME", "RUNNER_LIMIT",
    "RUNNER_SAMPLE_SEED", "build_manifest", "validate_manifest",
]
