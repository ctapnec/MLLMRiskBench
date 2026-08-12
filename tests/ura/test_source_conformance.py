"""Regressions for compact source-acquisition receipts."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from experiments import source_conformance as conformance_cli
from experiments import run_matrix
from ura.data_models import DataPoint, SourceEvaluationPolicy
from ura.source_conformance import (
    observed_arm_conformance,
    selected_source_conformance_sha256,
    validate_selected_source_conformance,
    validate_source_conformance_manifest,
    verify_manifest_components,
)
from ura.targets.api import MockTarget


def _point(identifier: str, *, cluster: str | None = None) -> DataPoint:
    meta: dict[str, object] = {"common_metrics_eligible": True}
    if cluster is not None:
        meta["source_cluster_id"] = cluster
    return DataPoint(
        id=identifier,
        source="fixture-source",
        modalities=["text"],
        payload_text="unsafe fixture request",
        risk_category="jailbreak",
        expected_behavior="refuse",
        source_policy=SourceEvaluationPolicy(
            policy_id="fixture:policy",
            version="release-1",
            sha256="d" * 64,
            intended_metric="fixture_metric",
        ),
        meta=meta,
    )


def _receipt(
    rows: list[DataPoint],
    source: Path,
    *,
    disposition: str = "admitted",
    extra_arms: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    admitted = disposition == "admitted"
    arm: dict[str, object] = {
        "arm_id": "fixture_arm",
        "converter": "fixture",
        "path_env": "URA_FIXTURE_SOURCE",
        "source_label": "Fixture source",
        "split": "test",
        "disposition": disposition,
        "reason": "reviewed fixture" if admitted else "blocked fixture",
        "upstream_uri": "https://example.invalid/fixture" if admitted else None,
        "requested_revision": "a" * 40 if admitted else None,
        "observed_revision": "a" * 40 if admitted else None,
        "consumed_input": ({
            "kind": "file",
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "bytes": source.stat().st_size,
        } if admitted else None),
        "components": [],
        "operator_decision": ({
            "decision": "approved",
            "access_status": "not_required",
            "license_identifier_or_notice": "test fixture notice",
            "reviewer": "test reviewer",
            "reviewed_at": "2026-08-12T12:00:00+03:00",
            "evidence_sha256": "e" * 64,
            "notes": "License and access reviewed for this fixture.",
        } if admitted else None),
        "raw_records": ({
            "discovered": len(rows),
            "accepted": len(rows),
            "excluded_by_design": 0,
            "rejected_invalid": 0,
            "reasons": {},
        } if admitted else None),
        "semantic_review": ({
            "status": "passed",
            "reviewer": "test reviewer",
            "reviewed_at": "2026-08-12T12:00:00+03:00",
            "selection_rule": "all fixture records",
            "reviewed_cluster_ids": sorted({
                str(row.meta.get("source_cluster_id") or row.id) for row in rows
            }),
            "reviewed_converted_corpus_sha256": observed_arm_conformance(rows)[
                "converted_corpus_sha256"
            ],
            "notes": "Mapping review only; not evaluator validation.",
        } if admitted else None),
    }
    return {
        "schema": "ura-source-conformance/1",
        "claim_scope": "acquisition_and_conversion_traceability_only",
        "arms": [arm, *(extra_arms or [])],
    }


def _instance() -> dict[str, object]:
    return {
        "converter": "fixture",
        "synth": False,
        "path_env": "URA_FIXTURE_SOURCE",
        "path_env_required": True,
        "source_label": "Fixture source",
        "split": "test",
    }


def _audit(rows: list[DataPoint], *, selected_records: int | None = None) -> dict:
    observation = observed_arm_conformance(rows)
    selected = len(rows) if selected_records is None else selected_records
    return {
        "full_converted_corpus_sha256": observation["converted_corpus_sha256"],
        "total_records": len(rows),
        "selected_records": selected,
        "total_clusters": observation["clusters"]["unique"],
        "total_cluster_ids": sorted({
            str(row.meta.get("source_cluster_id") or row.id) for row in rows
        }),
        "full_source_conformance_observation": observation,
    }


def _validate(
    receipt: dict[str, object], rows: list[DataPoint], *, selected_records: int | None = None,
) -> dict[str, object]:
    audit = _audit(rows, selected_records=selected_records)
    return validate_selected_source_conformance(
        receipt,
        selected_source_instances={"fixture_arm": _instance()},
        full_observations={
            "fixture_arm": audit["full_source_conformance_observation"]
        },
        sampling_audits={"fixture_arm": audit},
        source_config_selected_sha256="c" * 64,
    )


def test_compact_receipt_matches_full_runtime_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("one\ntwo\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1", cluster="cluster-a"), _point("row-2", cluster="cluster-b")]
    receipt = validate_source_conformance_manifest(_receipt(rows, source))

    result = _validate(receipt, rows, selected_records=1)

    assert result["selected_arms"] == ["fixture_arm"]
    assert result["normalized_selected_sha256"] == (
        selected_source_conformance_sha256(receipt, ["fixture_arm"])
    )
    assert result["source_config_selected_sha256"] == "c" * 64
    assert len(result["observed_full_corpus_sha256"]) == 64


def test_load_audit_observes_two_row_full_corpus_before_limit_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("one\ntwo\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1", cluster="cluster-a"), _point("row-2", cluster="cluster-b")]

    class Converter:
        @staticmethod
        def parse(_path: Path) -> list[DataPoint]:
            return rows

    monkeypatch.setattr(run_matrix, "get_converter", lambda _name: Converter())
    selected, audit = run_matrix.load_corpus_with_audit(
        "fixture_arm", 1, source_instance=_instance()
    )
    result = validate_selected_source_conformance(
        _receipt(rows, source),
        selected_source_instances={"fixture_arm": _instance()},
        full_observations={
            "fixture_arm": audit["full_source_conformance_observation"]
        },
        sampling_audits={"fixture_arm": audit},
        source_config_selected_sha256="c" * 64,
    )

    assert len(selected) == audit["selected_records"] == 1
    assert audit["total_records"] == 2
    assert audit["full_source_conformance_observation"]["emitted_datapoints"] == 2
    assert result["selected_arms"] == ["fixture_arm"]


def test_tampered_consumed_file_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("original\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1")]
    receipt = _receipt(rows, source)
    source.write_text("tampered\n", encoding="utf-8")

    with pytest.raises(ValueError, match="consumed input .* changed"):
        verify_manifest_components(receipt, selected_arms=["fixture_arm"])


def test_directory_input_requires_and_rehashes_exact_release_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_dir = tmp_path / "release"
    source_dir.mkdir()
    component = tmp_path / "release-manifest.json"
    component.write_text('{"release":"fixture"}\n', encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source_dir))
    monkeypatch.setenv("URA_FIXTURE_COMPONENT", str(component))
    rows = [_point("row-1")]
    receipt = _receipt(rows, component)
    arm = receipt["arms"][0]
    arm["consumed_input"] = {"kind": "directory"}
    arm["components"] = []

    with pytest.raises(ValueError, match="directory-backed.*component"):
        validate_source_conformance_manifest(receipt)

    arm["components"] = [{
        "role": "release manifest",
        "path_env": "URA_FIXTURE_COMPONENT",
        "sha256": hashlib.sha256(component.read_bytes()).hexdigest(),
        "bytes": component.stat().st_size,
    }]
    assert verify_manifest_components(receipt) == ["fixture_arm"]
    component.write_text('{"release":"changed"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="component .* (byte|hash) mismatch"):
        verify_manifest_components(receipt)


def test_stale_semantic_digest_and_blocked_selected_arm_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("fixture\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1")]

    stale = _receipt(rows, source)
    stale["arms"][0]["semantic_review"][
        "reviewed_converted_corpus_sha256"
    ] = "f" * 64
    with pytest.raises(ValueError, match="semantic review is stale"):
        _validate(stale, rows)

    blocked = _receipt(rows, source, disposition="blocked")
    with pytest.raises(ValueError, match="blocked, not admitted"):
        _validate(blocked, rows)


@pytest.mark.parametrize("failure", ["tampered_input", "stale_review", "blocked"])
def test_matrix_receipt_failures_precede_target_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("fixture\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1")]
    receipt = _receipt(
        rows, source, disposition="blocked" if failure == "blocked" else "admitted"
    )
    if failure == "tampered_input":
        source.write_text("changed after receipt\n", encoding="utf-8")
    elif failure == "stale_review":
        receipt["arms"][0]["semantic_review"][
            "reviewed_converted_corpus_sha256"
        ] = "f" * 64

    source_config = tmp_path / "sources.json"
    source_config.write_text(json.dumps({
        "fixture_arm": {
            "converter": "fixture",
            "path_env": "URA_FIXTURE_SOURCE",
            "source_label": "Fixture source",
            "split": "test",
        }
    }), encoding="utf-8")
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    class Converter:
        @staticmethod
        def parse(_path: Path) -> list[DataPoint]:
            return rows

    monkeypatch.setattr(run_matrix, "get_converter", lambda _name: Converter())
    target_constructions = 0

    def forbidden_target(*_args, **_kwargs):
        nonlocal target_constructions
        target_constructions += 1
        raise AssertionError("target construction must follow source conformance")

    monkeypatch.setattr(run_matrix, "build_target", forbidden_target)
    assert run_matrix.main([
        "--dry-run", "--attackers", "replay", "--judges", "rules",
        "--corpora", "fixture_arm", "--source-config", str(source_config),
        "--source-conformance", str(receipt_path),
        "--source-conformance-sha256",
        hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "--limit", "1", "--out", str(tmp_path / "run"),
    ]) == 1
    assert target_constructions == 0


@pytest.mark.parametrize(
    ("audit_field", "replacement", "message"),
    [
        ("full_converted_corpus_sha256", "f" * 64, "full audit mismatch"),
        ("total_records", 99, "full count mismatch"),
        ("total_clusters", 99, "cluster count mismatch"),
    ],
)
def test_runtime_full_observation_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_field: str,
    replacement: object,
    message: str,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("fixture\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1")]
    audit = _audit(rows)
    audit[audit_field] = replacement

    with pytest.raises(ValueError, match=message):
        validate_selected_source_conformance(
            _receipt(rows, source),
            selected_source_instances={"fixture_arm": _instance()},
            full_observations={
                "fixture_arm": audit["full_source_conformance_observation"]
            },
            sampling_audits={"fixture_arm": audit},
            source_config_selected_sha256="c" * 64,
        )


def test_unused_source_config_change_does_not_change_selected_identity(
    tmp_path: Path,
) -> None:
    config = tmp_path / "sources.json"
    value = {
        "fixture_arm": {
            "converter": "jailbreakbench",
            "path_env": "URA_FIXTURE_SOURCE",
            "source_label": "Fixture source",
            "split": "test",
        },
        "unused": {
            "converter": "jailbreakbench",
            "path_env": "URA_UNUSED_SOURCE",
            "split": "unused-a",
        },
    }
    config.write_text(json.dumps(value), encoding="utf-8")
    _, first = run_matrix._load_source_config(str(config), ["fixture_arm"])
    value["unused"]["split"] = "unused-b"
    config.write_text(json.dumps(value), encoding="utf-8")
    _, second = run_matrix._load_source_config(str(config), ["fixture_arm"])

    assert first is not None and second is not None
    assert first["sha256"] != second["sha256"]
    assert first["normalized_selected_sha256"] == second[
        "normalized_selected_sha256"
    ]


def test_schema_is_strict_and_non_admitted_arms_cannot_carry_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("fixture\n", encoding="utf-8")
    rows = [_point("row-1")]
    unknown = _receipt(rows, source)
    unknown["invented_score"] = 0.9
    with pytest.raises(ValueError, match="extra"):
        validate_source_conformance_manifest(unknown)

    blocked = _receipt(rows, source, disposition="blocked")
    blocked["arms"][0]["consumed_input"] = {
        "kind": "file",
        "sha256": "a" * 64,
        "bytes": 1,
    }
    with pytest.raises(ValueError, match="retain only disposition and reason"):
        validate_source_conformance_manifest(blocked)


def test_cli_only_validates_content_addressed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("fixture\n", encoding="utf-8")
    monkeypatch.setenv("URA_FIXTURE_SOURCE", str(source))
    rows = [_point("row-1")]
    source_config = tmp_path / "sources.json"
    source_config.write_text(json.dumps({
        "fixture_arm": {
            "converter": "fixture",
            "path_env": "URA_FIXTURE_SOURCE",
            "source_label": "Fixture source",
            "split": "test",
        }
    }), encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    receipt.write_text(json.dumps(_receipt(rows, source)), encoding="utf-8")
    digest = hashlib.sha256(receipt.read_bytes()).hexdigest()

    class Converter:
        @staticmethod
        def parse(_path: Path) -> list[DataPoint]:
            return rows

    monkeypatch.setattr(run_matrix, "get_converter", lambda _name: Converter())
    assert conformance_cli.main([
        "--manifest", str(receipt), "--sha256", digest,
        "--source-config", str(source_config),
    ]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "receipt_validated"
    assert output["runtime_conversion_binding"] == "pending_run_matrix_preflight"

    assert conformance_cli.main([
        "--manifest", str(receipt), "--sha256", "0" * 64,
        "--source-config", str(source_config),
    ]) == 1
    assert "sha256 mismatch" in capsys.readouterr().err


def test_selected_receipt_digest_excludes_unused_arm(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.jsonl"
    source.write_text("fixture\n", encoding="utf-8")
    rows = [_point("row-1")]
    unused = {
        "arm_id": "unused",
        "converter": "fixture",
        "path_env": "URA_UNUSED",
        "source_label": None,
        "split": None,
        "disposition": "not_selected",
        "reason": "not selected",
        "upstream_uri": None,
        "requested_revision": None,
        "observed_revision": None,
        "consumed_input": None,
        "components": [],
        "operator_decision": None,
        "raw_records": None,
        "semantic_review": None,
    }
    first = _receipt(rows, source, extra_arms=[unused])
    changed = deepcopy(first)
    changed["arms"][1]["reason"] = "unused receipt changed"

    assert selected_source_conformance_sha256(first, ["fixture_arm"]) == (
        selected_source_conformance_sha256(changed, ["fixture_arm"])
    )


def test_real_source_requires_receipt_before_loading(tmp_path: Path) -> None:
    source_config = tmp_path / "sources.json"
    source_config.write_text(json.dumps({
        "fixture_arm": {
            "converter": "strongreject",
            "path_env": "URA_FIXTURE_SOURCE",
            "split": "test",
        }
    }), encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        run_matrix.main([
            "--api", "mock", "--attackers", "replay", "--judges", "rules",
            "--corpora", "fixture_arm", "--source-config", str(source_config),
            "--out", str(tmp_path / "run"),
        ])
    assert exc.value.code == 2


def test_synthetic_offline_path_ignores_real_source_receipt_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A synthetic-only diagnostic needs neither acquisition nor human review."""

    monkeypatch.setenv(
        "URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "not-present.json")
    )
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "f" * 64)

    assert run_matrix.main([
        "--dry-run", "--attackers", "replay", "--judges", "rules,llm",
        "--judge-model", "mock",
        "--corpora", "synth", "--limit", "2", "--seeds", "0",
        "--max-queries", "1", "--max-turns", "1",
        "--out", str(tmp_path / "synthetic"),
    ]) == 0
    assert not list((tmp_path / "synthetic").glob("source-conformance-*.json"))


def test_synthetic_transport_diagnostic_allows_offline_mock_judge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    project_revision_args,
) -> None:
    """An all-synthetic target diagnostic may use mock labels without a receipt."""

    monkeypatch.setenv(
        "URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "not-present.json")
    )
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "f" * 64)
    original_build_api_target = run_matrix.build_api_target

    def build_diagnostic_target(spec: str, *, config=None):
        if spec == "diagnostic-target":
            return MockTarget(model="synthetic-transport-target")
        return original_build_api_target(spec, config=config)

    monkeypatch.setattr(run_matrix, "build_api_target", build_diagnostic_target)

    assert run_matrix.main([
        "--attestation-probe", "--execution-scope-id", "test-scope",
        *project_revision_args,
        "--api", "diagnostic-target", "--attackers", "replay",
        "--judges", "rules,llm",
        "--judge-model", "mock",
        "--corpora", "synth", "--limit", "2", "--seeds", "0",
        "--max-queries", "1", "--max-turns", "1",
        "--max-total-target-calls", "2", "--max-total-judge-calls", "2",
        "--max-total-http-attempts", "2", "--deadline-seconds", "60",
        "--out", str(tmp_path / "synthetic-transport"),
    ]) == 0
    assert not list(
        (tmp_path / "synthetic-transport").glob("source-conformance-*.json")
    )
