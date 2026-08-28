"""Regression coverage for prospective, no-call lane projections."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments import rig_check, run_matrix
from ura.eligibility import canonical_json_sha256
from ura.lane_projection import (
    load_lane_projection_file,
    validate_lane_projection,
    validate_lane_projection_binding,
)
from ura.targets.base import BaseTarget
from ura.sampling import DEFAULT_SAMPLING_POLICY, SOURCE_ORDER_CLUSTER_PREFIX


class _NeverGeneratedTarget(BaseTarget):
    name = "lane-projection-target"
    modality_support = ("text", "image")

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, dialog, *, seed=None):
        self.calls += 1
        raise AssertionError("lane projection preflight must not generate")


def _produce_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    limit: int = 2,
    sampling_policy: str | None = None,
) -> tuple[_NeverGeneratedTarget, Path, Path]:
    target = _NeverGeneratedTarget()
    monkeypatch.setattr(run_matrix, "build_target", lambda *_a, **_kw: target)
    arguments = [
        "--dry-run",
        "--attackers", "replay,crescendo",
        "--judges", "rules",
        "--corpora", "synth",
        "--limit", str(limit),
        "--seeds", "0,1",
        "--max-queries", "4",
        "--max-turns", "4",
        "--out", str(tmp_path),
    ]
    if sampling_policy is not None:
        arguments.extend(["--sampling-policy", sampling_policy])
    assert rig_check.main(arguments) == 0
    projections = list(tmp_path.glob("lane-projection-*.lane-projection.json"))
    eligibility = list(tmp_path.glob("eligibility-*.eligibility.json"))
    assert len(projections) == 1
    assert len(eligibility) == 1
    return target, projections[0], eligibility[0]


def test_rig_check_persists_strict_no_call_lane_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, path, eligibility_path = _produce_projection(tmp_path, monkeypatch)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    projection, descriptor = load_lane_projection_file(path, digest)
    eligibility = json.loads(eligibility_path.read_text(encoding="utf-8"))

    assert descriptor == {
        "file": path.name,
        "sha256": digest,
        "bytes": path.stat().st_size,
    }
    assert projection["schema"] == "ura-lane-projection/1"
    assert projection["eligibility_binding"]["plan_id"] == eligibility["plan_id"]
    assert projection["eligibility_binding"]["request_id"] == eligibility["request_id"]
    assert (
        projection["eligibility_binding"]["experiment_conditions"]
        == eligibility["bindings"]["experiment_conditions"]
    )
    arm = projection["selection"]["arms"][0]
    assert arm["logical_source_arm"] == "synth"
    assert arm["selected_records"] == 2
    assert arm["selected_clusters"] == 2
    assert sum(arm["source_policy_cluster_counts"].values()) == 2
    assert arm["selected_input_media"]["status"] == "available"
    assert arm["selected_input_media"]["total_unique_bytes"] > 0
    assert projection["call_projection"]["target_calls"] == 20
    assert projection["call_projection"]["judge_calls"] == 0
    assert all(
        estimate["status"] == "CANNOT-VERIFY" and estimate["value"] is None
        for estimate in projection["unavailable_estimates"].values()
    )
    assert target.calls == 0


def test_text_only_selection_has_explicit_empty_media_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, path, _ = _produce_projection(tmp_path, monkeypatch, limit=1)
    projection = json.loads(path.read_text(encoding="utf-8"))
    media = projection["selection"]["arms"][0]["selected_input_media"]

    assert media == {
        "status": "not_applicable",
        "verification_basis": "no_physical_media_selected",
        "inventory_sha256": canonical_json_sha256([]),
        "refs_by_modality": {},
        "unique_bytes_by_modality": {},
        "total_unique_bytes": 0,
    }


def test_explicit_sampling_policy_is_bound_into_lane_projection_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, legacy_path, _ = _produce_projection(tmp_path / "legacy", monkeypatch)
    _, explicit_path, _ = _produce_projection(
        tmp_path / "explicit",
        monkeypatch,
        sampling_policy=SOURCE_ORDER_CLUSTER_PREFIX,
    )
    legacy = json.loads(legacy_path.read_text(encoding="utf-8"))
    explicit = json.loads(explicit_path.read_text(encoding="utf-8"))

    assert "sampling_policy" not in legacy["selection"]["arms"][0]
    assert (
        explicit["selection"]["arms"][0]["sampling_policy"]
        == SOURCE_ORDER_CLUSTER_PREFIX
    )
    assert explicit["projection_id"] != legacy["projection_id"]

    ignored_policy_mutant = json.loads(json.dumps(explicit))
    ignored_policy_mutant["selection"]["arms"][0]["sampling_policy"] = (
        DEFAULT_SAMPLING_POLICY
    )
    mutant_body = {
        key: value
        for key, value in ignored_policy_mutant.items()
        if key != "projection_id"
    }
    ignored_policy_mutant["projection_id"] = (
        "lane-projection-" + canonical_json_sha256(mutant_body)[:24]
    )
    with pytest.raises(ValueError, match="differs from its condition"):
        validate_lane_projection(ignored_policy_mutant)


def test_lane_projection_rejects_byte_and_internal_content_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, path, _ = _produce_projection(tmp_path, monkeypatch)
    approved_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    changed = json.loads(path.read_text(encoding="utf-8"))
    changed["unavailable_estimates"]["token_usage"]["status"] = "available"
    path.write_text(json.dumps(changed, sort_keys=True), encoding="utf-8")

    with pytest.raises(ValueError, match="byte digest mismatch"):
        load_lane_projection_file(path, approved_digest)
    changed_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="must remain CANNOT-VERIFY"):
        load_lane_projection_file(path, changed_digest)


def test_lane_projection_binding_rejects_another_valid_condition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, path, eligibility_path = _produce_projection(tmp_path, monkeypatch)
    projection = json.loads(path.read_text(encoding="utf-8"))
    eligibility = json.loads(eligibility_path.read_text(encoding="utf-8"))
    descriptor = projection["eligibility_binding"]["artifact"]
    validate_lane_projection_binding(
        projection,
        eligibility_plan=eligibility,
        eligibility_artifact=descriptor,
    )

    alternate = json.loads(json.dumps(projection))
    condition = alternate["eligibility_binding"]["experiment_conditions"]
    condition["values"]["limit"] = 999
    condition["condition_id"] = (
        "condition-" + canonical_json_sha256(condition["values"])[:24]
    )
    body = {key: value for key, value in alternate.items() if key != "projection_id"}
    alternate["projection_id"] = (
        "lane-projection-" + canonical_json_sha256(body)[:24]
    )
    validate_lane_projection(alternate)
    with pytest.raises(ValueError, match="exact eligibility condition"):
        validate_lane_projection_binding(
            alternate,
            eligibility_plan=eligibility,
            eligibility_artifact=descriptor,
        )
