"""Freeze disjoint pilot/main prompt-intent cluster partitions before API calls."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src"))

from experiments.analysis_integrity import analysis_source_identity  # noqa: E402
from experiments.run_matrix import load_corpus_with_audit  # noqa: E402

PARTITION_SCHEMA = "ura-cluster-partition/1.1"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def create_partition(specifications: dict[str, int], *, seed: int) -> dict[str, Any]:
    if not specifications:
        raise ValueError("at least one corpus=pilot_cluster_count is required")
    corpora: dict[str, Any] = {}
    for corpus, pilot_count in sorted(specifications.items()):
        if not corpus or pilot_count < 2:
            raise ValueError("each corpus needs at least two pilot clusters")
        _, audit = load_corpus_with_audit(corpus, 0, sample_seed=seed)
        cluster_ids = audit.get("total_cluster_ids")
        if (
            not isinstance(cluster_ids, list) or len(set(cluster_ids)) != len(cluster_ids)
            or pilot_count >= len(cluster_ids)
        ):
            raise ValueError(
                f"corpus {corpus!r} has {len(cluster_ids or [])} clusters; pilot "
                f"count {pilot_count} must be >=2 and leave at least one main cluster"
            )
        converted_digest = audit.get("full_converted_corpus_sha256")
        total_records = audit.get("total_records")
        if (
            not isinstance(converted_digest, str) or len(converted_digest) != 64
            or not isinstance(total_records, int) or total_records < len(cluster_ids)
        ):
            raise ValueError(f"corpus {corpus!r} lacks canonical converted identity")
        scoped = int.from_bytes(hashlib.sha256(
            f"ura-pilot-main-partition-v1\0{seed}\0{corpus}".encode()
        ).digest()[:8], "big")
        shuffled = list(cluster_ids)
        random.Random(scoped).shuffle(shuffled)
        pilot = sorted(shuffled[:pilot_count])
        main = sorted(shuffled[pilot_count:])
        if set(pilot) & set(main) or set(pilot) | set(main) != set(cluster_ids):
            raise AssertionError("internal cluster-partition accounting error")
        corpora[corpus] = {
            "source_kind": audit.get("source_kind"),
            "source_path": audit.get("source_path"),
            "source_tree_sha256": audit.get("source_tree_sha256"),
            "source_file_count": audit.get("source_file_count"),
            "full_converted_corpus_sha256": converted_digest,
            "total_records": total_records,
            "total_clusters": len(cluster_ids),
            "total_cluster_ids": sorted(cluster_ids),
            "total_cluster_ids_sha256": _digest(sorted(cluster_ids)),
            "pilot": {
                "n_clusters": len(pilot), "cluster_ids": pilot,
                "cluster_ids_sha256": _digest(pilot),
            },
            "main": {
                "n_clusters": len(main), "cluster_ids": main,
                "cluster_ids_sha256": _digest(main),
            },
        }
    return {
        "schema_version": PARTITION_SCHEMA,
        "seed": seed,
        "algorithm": "sha256_scoped_seed_random_partition_v1",
        "corpora": corpora,
        "analysis_source": analysis_source_identity([
            Path(__file__), _REPO_ROOT / "experiments" / "run_matrix.py",
        ]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Freeze content-bound, disjoint pilot/main corpus clusters"
    )
    parser.add_argument(
        "--corpus", action="append", required=True, metavar="NAME=PILOT_CLUSTERS",
        help="repeat once per corpus",
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    specifications: dict[str, int] = {}
    try:
        for value in args.corpus:
            name, rendered_count = value.split("=", 1)
            if name in specifications:
                raise ValueError(f"duplicate corpus {name!r}")
            specifications[name] = int(rendered_count)
        output = create_partition(specifications, seed=args.seed)
    except (ValueError, OSError) as exc:
        print(f"cluster partition validation failed: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f"wrote {args.output}; sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
