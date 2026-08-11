"""Content-bound pilot/main source-policy partition regressions."""
from __future__ import annotations

from typing import Callable

import pytest

from experiments import cluster_partition
from ura.data_models import (
    DataPoint,
    RiskCategory,
    SourceEvaluationPolicy,
)


def _policy(name: str) -> SourceEvaluationPolicy:
    return SourceEvaluationPolicy(
        policy_id=f"fixture:{name}",
        version="1",
        sha256=("a" if name == "a" else "b") * 64,
        intended_metric=f"{name}_rate",
    )


def _point(cluster_id: str, policy: SourceEvaluationPolicy | None) -> DataPoint:
    return DataPoint(
        id=f"point:{cluster_id}",
        source="fixture",
        modalities=["text"],
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
        source_policy=policy,
        meta={"source_cluster_id": cluster_id},
    )


def _loader(points: list[DataPoint]) -> Callable[..., tuple[list[DataPoint], dict]]:
    cluster_ids = sorted(point.meta["source_cluster_id"] for point in points)

    def load(*_args, **_kwargs):
        return points, {
            "source_locator": {
                "corpus": "fixture",
                "configuration_env": "URA_FIXTURE_PATH",
                "source_kind": "file",
                "required_layout": [],
            },
            "full_converted_corpus_sha256": "0" * 64,
            "total_records": len(points),
            "total_cluster_ids": cluster_ids,
        }

    return load


def test_partition_records_exact_policy_cluster_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    points = [_point(f"cluster-{index}", _policy("a")) for index in range(5)]
    monkeypatch.setattr(cluster_partition, "load_corpus_with_audit", _loader(points))

    plan = cluster_partition.create_partition(
        {"fixture": 2}, seed=7, minimum_pilot_policy_clusters=2
    )

    assert plan["schema_version"] == "ura-cluster-partition/1.2"
    assert plan["minimum_pilot_policy_clusters"] == 2
    assert plan["minimum_main_policy_clusters"] == 2
    policy_key = f"fixture:a@1#sha256:{'a' * 64}"
    entry = plan["corpora"]["fixture"]
    assert entry["source_locator"] == {
        "corpus": "fixture",
        "configuration_env": "URA_FIXTURE_PATH",
        "source_kind": "file",
        "required_layout": [],
    }
    assert "source_path" not in entry
    assert entry["pilot"]["source_policy_cluster_counts"] == {policy_key: 2}
    assert entry["main"]["source_policy_cluster_counts"] == {policy_key: 3}


def test_partition_fails_when_any_pilot_policy_stratum_cannot_reach_minimum(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    points = [
        *[_point(f"a-{index}", _policy("a")) for index in range(4)],
        _point("b-only", _policy("b")),
    ]
    monkeypatch.setattr(cluster_partition, "load_corpus_with_audit", _loader(points))

    with pytest.raises(ValueError, match="pilot policy strata.*minimum 2"):
        cluster_partition.create_partition(
            {"fixture": 3}, seed=0, minimum_pilot_policy_clusters=2
        )


def test_partition_fails_when_main_policy_support_would_be_exhausted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    points = [_point(f"cluster-{index}", _policy("a")) for index in range(5)]
    monkeypatch.setattr(cluster_partition, "load_corpus_with_audit", _loader(points))

    with pytest.raises(ValueError, match="main policy strata.*minimum 2"):
        cluster_partition.create_partition(
            {"fixture": 4}, seed=0,
            minimum_pilot_policy_clusters=2,
            minimum_main_policy_clusters=2,
        )
