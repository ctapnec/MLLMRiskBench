"""Regression coverage for typed live-route attestation receipts."""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ura.live_attestation import (
    build_live_attestation_manifest,
    load_live_attestation_file,
    realized_identity_matches,
    required_attestation_keys,
    validate_live_attestation_manifest,
    validate_required_live_attestations,
)


_SPEC = "openai:fixture-model"
_TARGET = "openai:fixture-model"
_ROUTE_SHA256 = "a" * 64
_SCOPE = "openai-account:test-project"
_OBSERVED = "2026-08-12T10:00:00Z"


def _project_revision(
    *, harness_sha256: str = "f" * 64, driver_sha256: str = "1" * 64,
) -> dict[str, object]:
    return {
        "mode": "verified",
        "revision_id": "project-revision-" + "2" * 24,
        "file": "project-revision-" + "2" * 24 + ".project-revision.json",
        "sha256": "3" * 64,
        "bytes": 100,
        "expected_commit": "4" * 40,
        "observed_commit": "4" * 40,
        "head_tree": "5" * 40,
        "harness_source_sha256": harness_sha256,
        "driver_source_sha256": driver_sha256,
    }


def _record(
    *,
    modalities: list[str] | None = None,
    observed_at: str = _OBSERVED,
    route_sha256: str = _ROUTE_SHA256,
    resolved_target: str = _TARGET,
    resolved_model: str = "fixture-model-2026-08-01",
) -> dict[str, object]:
    return {
        "execution_scope_id": _SCOPE,
        "requested_target_spec": _SPEC,
        "resolved_target": resolved_target,
        "route_kind": "hosted_api",
        "route_config_sha256": route_sha256,
        "exact_input_modalities": modalities or ["text"],
        "realized_target_identity": {
            "target": resolved_target,
            "provider": "openai",
            "resolved_model": resolved_model,
            "system_fingerprint": "fixture-fingerprint",
        },
        "observed_at_utc": observed_at,
        "probe": {
            "evidence_kind": "synthetic_live_transport_probe",
            "grid_id": "grid-fixture",
            "run_id": "run-fixture",
            "grid_artifact": {
                "file": "grid-fixture.grid.json",
                "sha256": "b" * 64,
                "bytes": 100,
            },
            "completion_artifact": {
                "file": "run-fixture.complete.json",
                "sha256": "c" * 64,
                "bytes": 200,
            },
            "realized_identities_sha256": "d" * 64,
            "attempt_media_hashes_sha256": "e" * 64,
            "harness_source_sha256": "f" * 64,
            "driver_source_sha256": "1" * 64,
            "project_revision": _project_revision(),
        },
    }


def _manifest(**record_overrides: object) -> dict[str, object]:
    return build_live_attestation_manifest([_record(**record_overrides)])


def _match(
    manifest: dict[str, object],
    *,
    modalities: tuple[str, ...] = ("text",),
    resolved_target: str = _TARGET,
    route_sha256: str = _ROUTE_SHA256,
    reference_time: datetime | None = None,
    max_age_hours: float = 2,
) -> dict:
    key = (_SCOPE, _SPEC, modalities)
    return validate_required_live_attestations(
        [manifest],
        required_keys={key},
        resolved_targets={_SPEC: resolved_target},
        route_config_sha256={_SPEC: route_sha256},
        route_kind={_SPEC: "hosted_api"},
        current_harness_source_sha256="f" * 64,
        current_driver_source_sha256="1" * 64,
        current_project_revision=_project_revision(),
        reference_time=reference_time
        or datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc),
        max_age_hours=max_age_hours,
    )


def test_manifest_is_strict_and_ids_are_content_bound() -> None:
    manifest = _manifest()
    assert validate_live_attestation_manifest(manifest) == manifest
    assert manifest["attestation_id"].startswith("live-attestation-")
    assert manifest["records"][0]["record_id"].startswith(
        "live-attestation-record-"
    )

    changed_record = copy.deepcopy(manifest)
    changed_record["records"][0]["requested_target_spec"] = "openai:other"
    with pytest.raises(ValueError, match="record_id/content mismatch"):
        validate_live_attestation_manifest(changed_record)

    changed_manifest_id = copy.deepcopy(manifest)
    changed_manifest_id["attestation_id"] = "live-attestation-" + "0" * 24
    with pytest.raises(ValueError, match="ID/content mismatch"):
        validate_live_attestation_manifest(changed_manifest_id)

    extra_field = copy.deepcopy(manifest)
    extra_field["records"][0]["untyped_claim"] = True
    with pytest.raises(ValueError, match="invalid field inventory"):
        validate_live_attestation_manifest(extra_field)


def test_probe_must_be_live_and_modality_must_be_canonical() -> None:
    dry_run = copy.deepcopy(_manifest())
    dry_run["records"][0]["probe"]["evidence_kind"] = "dry_run"
    with pytest.raises(ValueError, match="evidence_kind is invalid"):
        validate_live_attestation_manifest(dry_run)

    with pytest.raises(ValueError, match="not canonical"):
        _manifest(modalities=["image", "text"])


def test_required_keys_preserve_exact_compatible_modality_strata() -> None:
    keys = required_attestation_keys(
        execution_scope_id=_SCOPE,
        requested_target_specs=[_SPEC],
        eligibility_items=[
            {
                "requested_target_spec": _SPEC,
                "exact_modality_combination": ["text"],
                "status": "compatible_if_isolated",
            },
            {
                "requested_target_spec": _SPEC,
                "exact_modality_combination": ["text", "image"],
                "status": "N/A",
            },
            {
                "requested_target_spec": "openai:unselected",
                "exact_modality_combination": ["text"],
                "status": "compatible_if_isolated",
            },
        ],
    )
    assert keys == {(_SCOPE, _SPEC, ("text",))}

    assert set(_match(_manifest())) == keys
    with pytest.raises(ValueError, match="missing exact live-attestation prerequisites"):
        _match(_manifest(), modalities=("text", "image"))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("resolved_target", "openai:other-runtime", "resolved target mismatch"),
        ("route_sha256", "f" * 64, "route/config mismatch"),
    ],
)
def test_matcher_rejects_wrong_route_binding(
    field: str, value: str, message: str
) -> None:
    kwargs = {field: value}
    with pytest.raises(ValueError, match=message):
        _match(_manifest(), **kwargs)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("harness_source_sha256", "harness source mismatch"),
        ("driver_source_sha256", "experiment driver mismatch"),
    ],
)
def test_matcher_rejects_obsolete_probe_code_identity(
    field: str, message: str,
) -> None:
    manifest = _manifest()
    record = dict(manifest["records"][0])
    probe = dict(record["probe"])
    probe[field] = "2" * 64
    revision = dict(probe["project_revision"])
    revision[field] = "2" * 64
    probe["project_revision"] = revision
    record["probe"] = probe
    changed = build_live_attestation_manifest([
        {key: value for key, value in record.items() if key != "record_id"}
    ])
    with pytest.raises(ValueError, match=message):
        _match(changed)


def test_matcher_rejects_cross_revision_receipt() -> None:
    manifest = _manifest()
    record = dict(manifest["records"][0])
    probe = dict(record["probe"])
    revision = dict(probe["project_revision"])
    revision["revision_id"] = "project-revision-" + "9" * 24
    revision["file"] = revision["revision_id"] + ".project-revision.json"
    revision["expected_commit"] = "8" * 40
    revision["observed_commit"] = "8" * 40
    probe["project_revision"] = revision
    record["probe"] = probe
    changed = build_live_attestation_manifest([
        {key: value for key, value in record.items() if key != "record_id"}
    ])
    with pytest.raises(ValueError, match="project revision mismatch"):
        _match(changed)


def test_realized_identity_match_rejects_resolved_model_drift() -> None:
    expected = {
        "target": _TARGET,
        "provider": "openai",
        "resolved_model": "fixture-model-2026-08-01",
        "system_fingerprint": "old-fingerprint",
    }
    assert realized_identity_matches(
        expected,
        {**expected, "system_fingerprint": "rotated-fingerprint"},
    )
    assert not realized_identity_matches(
        expected,
        {**expected, "resolved_model": "fixture-model-2026-08-02"},
    )


def test_matcher_enforces_age_boundary_and_rejects_stale_or_future() -> None:
    reference = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
    assert _match(_manifest(), reference_time=reference, max_age_hours=2)

    with pytest.raises(ValueError, match="is stale"):
        _match(_manifest(), reference_time=reference, max_age_hours=1.99)

    future = (reference + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    with pytest.raises(ValueError, match="future-dated"):
        _match(_manifest(observed_at=future), reference_time=reference)

    with pytest.raises(ValueError, match="reference time must be timezone-aware"):
        _match(_manifest(), reference_time=reference.replace(tzinfo=None))

    with pytest.raises(ValueError, match="ending in Z"):
        _manifest(observed_at="2026-08-12T10:00:00+00:00")


def test_content_addressed_loader_rejects_digest_tamper_and_symlink(
    tmp_path: Path,
) -> None:
    path = tmp_path / "live-attestation.json"
    payload = json.dumps(_manifest(), sort_keys=True).encode("utf-8")
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    loaded, descriptor = load_live_attestation_file(path, digest)
    assert loaded["schema"] == "ura-live-attestation/2"
    assert descriptor == {
        "file": path.name,
        "sha256": digest,
        "bytes": len(payload),
    }

    path.write_bytes(payload + b"\n")
    with pytest.raises(ValueError, match="byte digest mismatch"):
        load_live_attestation_file(path, digest)

    path.write_bytes(payload)
    link = tmp_path / "live-attestation-link.json"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(ValueError, match="must not be a symlink"):
        load_live_attestation_file(link, digest)
