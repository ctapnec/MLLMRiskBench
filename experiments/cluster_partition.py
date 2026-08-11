"""Freeze disjoint pilot/main prompt-intent cluster partitions before API calls."""
from __future__ import annotations

import argparse
from collections import Counter
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
from experiments.run_matrix import _cluster_key, load_corpus_with_audit  # noqa: E402

PARTITION_SCHEMA = "ura-cluster-partition/1.2"


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()


def _source_policy_key(record: object) -> str:
    policy = getattr(record, "source_policy", None)
    if policy is None:
        return "__untyped_source_policy__"
    return (
        f"{policy.policy_id}@{policy.version}#sha256:{policy.sha256}"
    )


def _cluster_policy_map(points: list[object]) -> dict[str, str]:
    """Require one exact source-evaluation policy per prompt/intent cluster."""

    result: dict[str, str] = {}
    for index, point in enumerate(points):
        cluster_id = _cluster_key(index, point)
        policy_key = _source_policy_key(point)
        previous = result.setdefault(cluster_id, policy_key)
        if previous != policy_key:
            raise ValueError(
                f"source cluster {cluster_id!r} mixes source-evaluation policies"
            )
    return result


def create_partition(
    specifications: dict[str, int],
    *,
    seed: int,
    minimum_pilot_policy_clusters: int = 2,
    minimum_main_policy_clusters: int = 2,
) -> dict[str, Any]:
    if not specifications:
        raise ValueError("at least one corpus=pilot_cluster_count is required")
    if (
        isinstance(minimum_pilot_policy_clusters, bool)
        or not isinstance(minimum_pilot_policy_clusters, int)
        or minimum_pilot_policy_clusters < 1
    ):
        raise ValueError("minimum pilot policy clusters must be a positive integer")
    if (
        isinstance(minimum_main_policy_clusters, bool)
        or not isinstance(minimum_main_policy_clusters, int)
        or minimum_main_policy_clusters < 1
    ):
        raise ValueError("minimum main policy clusters must be a positive integer")
    corpora: dict[str, Any] = {}
    for corpus, pilot_count in sorted(specifications.items()):
        if not corpus or pilot_count < 2:
            raise ValueError("each corpus needs at least two pilot clusters")
        points, audit = load_corpus_with_audit(corpus, 0, sample_seed=seed)
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
        cluster_policies = _cluster_policy_map(list(points))
        if set(cluster_policies) != set(cluster_ids):
            raise ValueError(
                f"corpus {corpus!r} cluster-policy inventory does not match "
                "the converted cluster inventory"
            )
        policy_keys = sorted(set(cluster_policies.values()))
        pilot_policy_counts = Counter(cluster_policies[item] for item in pilot)
        main_policy_counts = Counter(cluster_policies[item] for item in main)
        under_supported = {
            key: pilot_policy_counts.get(key, 0)
            for key in policy_keys
            if pilot_policy_counts.get(key, 0) < minimum_pilot_policy_clusters
        }
        if under_supported:
            detail = ", ".join(
                f"{key}={count}" for key, count in sorted(under_supported.items())
            )
            raise ValueError(
                f"corpus {corpus!r} pilot policy strata are below the minimum "
                f"{minimum_pilot_policy_clusters}: {detail}"
            )
        under_supported_main = {
            key: main_policy_counts.get(key, 0)
            for key in policy_keys
            if main_policy_counts.get(key, 0) < minimum_main_policy_clusters
        }
        if under_supported_main:
            detail = ", ".join(
                f"{key}={count}"
                for key, count in sorted(under_supported_main.items())
            )
            raise ValueError(
                f"corpus {corpus!r} main policy strata are below the minimum "
                f"{minimum_main_policy_clusters}: {detail}"
            )
        corpora[corpus] = {
            "source_locator": audit.get("source_locator"),
            "full_converted_corpus_sha256": converted_digest,
            "total_records": total_records,
            "total_clusters": len(cluster_ids),
            "total_cluster_ids": sorted(cluster_ids),
            "total_cluster_ids_sha256": _digest(sorted(cluster_ids)),
            "pilot": {
                "n_clusters": len(pilot), "cluster_ids": pilot,
                "cluster_ids_sha256": _digest(pilot),
                "source_policy_cluster_counts": dict(sorted(pilot_policy_counts.items())),
            },
            "main": {
                "n_clusters": len(main), "cluster_ids": main,
                "cluster_ids_sha256": _digest(main),
                "source_policy_cluster_counts": dict(sorted(main_policy_counts.items())),
            },
        }
    return {
        "schema_version": PARTITION_SCHEMA,
        "seed": seed,
        "algorithm": "sha256_scoped_seed_random_partition_v1",
        "minimum_pilot_policy_clusters": minimum_pilot_policy_clusters,
        "minimum_main_policy_clusters": minimum_main_policy_clusters,
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
    parser.add_argument(
        "--minimum-pilot-policy-clusters",
        type=int,
        default=2,
        help="minimum source prompt/intent clusters per source-policy stratum",
    )
    parser.add_argument(
        "--minimum-main-policy-clusters",
        type=int,
        default=2,
        help="minimum main clusters retained per source-policy stratum",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    specifications: dict[str, int] = {}
    try:
        for value in args.corpus:
            name, rendered_count = value.split("=", 1)
            if name in specifications:
                raise ValueError(f"duplicate corpus {name!r}")
            specifications[name] = int(rendered_count)
        output = create_partition(
            specifications,
            seed=args.seed,
            minimum_pilot_policy_clusters=args.minimum_pilot_policy_clusters,
            minimum_main_policy_clusters=args.minimum_main_policy_clusters,
        )
    except (ValueError, OSError) as exc:
        print(f"cluster partition validation failed: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    for corpus, entry in sorted(output["corpora"].items()):
        for role in ("pilot", "main"):
            rendered = json.dumps(
                entry[role]["source_policy_cluster_counts"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            print(f"{corpus} {role} source-policy clusters: {rendered}")
    print(f"wrote {args.output}; sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
