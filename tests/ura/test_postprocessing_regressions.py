"""Regressions for post-hoc analyses that feed Chapter V."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ura.data_models import Response
from ura.runner import realized_identity_summary

from experiments.human_audit import (
    _consensus,
    _csv_safe,
    _joined_artifacts,
    analyse,
    load_labels,
)
from experiments.kappa import load_trail_facets, main as kappa_main
from experiments.judge_sensitivity import (
    analyse as analyse_sensitivity,
    main as sensitivity_main,
)
from experiments.paired_compare import compare, main as paired_main
from experiments.transfer_matrix import (
    CODE_VERSION,
    TransferRecord,
    build_matrix,
    load,
    load_facets,
    main as transfer_main,
)


def _record(
    model: str,
    key: str,
    fingerprint: str,
    label: str,
    *,
    datapoint: str = "dp-1",
    expected: str = "refuse",
    transferable: bool = True,
) -> TransferRecord:
    return TransferRecord(
        model=model,
        run_id=f"run-{model}",
        transfer_key=key,
        attack_fingerprint=fingerprint,
        datapoint_id=datapoint,
        label=label,
        expected_behavior=expected,
        transferable=transferable,
        source_file="fixture",
    )


def _identity_metadata(
    responses: list[dict[str, object]],
    trails: list[dict[str, object]],
    judges: list[str],
) -> tuple[dict[str, object], str]:
    summary = realized_identity_summary(
        [Response.model_validate(row, strict=True) for row in responses],
        trails,
        expected_judges=judges,
    )
    digest = hashlib.sha256(json.dumps(
        summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    return {
        "realized_identities": summary,
        "realized_identities_sha256": digest,
        "n_realized_target_identity_observations": len(responses),
        "n_realized_judge_identity_observations": len(trails),
        "n_realized_judge_identity_snapshots": len(judges),
    }, digest


def test_transfer_requires_harmful_transferable_exact_input_match() -> None:
    records = {
        "A": {
            "exact": _record("A", "exact", "fp-1", "violation"),
            "adaptive": _record(
                "A", "adaptive", "fp-2", "violation", transferable=False
            ),
            "mismatch": _record(
                "A", "mismatch", "fp-3", "violation", datapoint="dp-3"
            ),
            "benign": _record(
                "A", "benign", "fp-4", "violation", expected="safe_answer"
            ),
        },
        "B": {
            "exact": _record("B", "exact", "fp-1", "violation"),
            "adaptive": _record("B", "adaptive", "fp-2", "violation"),
            "mismatch": _record("B", "mismatch", "different", "violation"),
            "benign": _record(
                "B", "benign", "fp-4", "violation", expected="safe_answer"
            ),
        },
    }
    result = build_matrix(records, n_resamples=50, seed=3)
    cell = result["cells"]["A"]["B"]
    assert cell["value"] == 1.0
    assert cell["source_successes"] == 2  # exact + mismatch only
    assert cell["matched"] == 1
    assert cell["excluded_nontransferable"] == 1
    assert cell["fingerprint_mismatches"] == 1
    assert result["cells"]["A"]["A"]["value"] is None


def test_transfer_missing_denominator_is_null_not_zero() -> None:
    records = {
        "A": {"x": _record("A", "x", "fp", "refusal")},
        "B": {"x": _record("B", "x", "fp", "violation")},
    }
    cell = build_matrix(records, n_resamples=10)["cells"]["A"]["B"]
    assert cell["value"] is None
    assert cell["reason"] == "no_transferable_harmful_source_successes"


def _write_completed_cell(
    root: Path,
    stem: str,
    *,
    model: str,
    run_id: str,
    key: str,
    eligible: bool = True,
    attacker: str = "replay",
    corpus: str = "fixture",
    descriptor_marker: bool = True,
    grid_manifest: bool = True,
    model_spec: str | None = None,
    defense: str = "none",
    label: str = "violation",
    expected: str = "refuse",
    datapoint: str = "dp",
    seed: int = 0,
    fingerprint: str = "fp",
    response_conditioned: bool = False,
) -> None:
    model_spec = model if model_spec is None else model_spec
    path = root / f"{stem}.jsonl"
    payload = {
        "attempt_id": "a",
        "judge": "rules",
        "label": label,
        "score": 1.0,
        "run_id": run_id,
        "raw": {
            "run_id": run_id,
            "model": model,
            "target": model,
            "transfer_key": key,
            "attack_fingerprint": fingerprint,
            "datapoint_id": datapoint,
            "source": "fixture-source",
            "attacker": attacker,
            "risk_category": "cybersec",
            "modality": "text",
            "expected_behavior": expected,
            "transferable": True,
            "common_metrics_eligible": eligible,
            "seed": seed,
            "requested_seed": seed,
            "turn_index": 0,
            "response_conditioned": response_conditioned,
            "replayed_transcript": False,
            "target_sampling_control": "provider_seed",
            "cascade_stage": 0,
            "cascade_confident": True,
            "cascade_role": "authoritative",
            "cascade_policy": "first_confident_with_full_shadow_trail",
        },
    }
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    attempts = root / f"{stem}.attempts.jsonl"
    attempts.write_text(json.dumps({
        "id": "a",
        "datapoint_id": datapoint,
        "attacker": attacker,
        "target": model,
        "rendered_input": [{"role": "user", "content": "probe"}],
        "params": {
            "transfer_key": key,
            "attack_fingerprint": fingerprint,
            "transferable": True,
            "response_conditioned": response_conditioned,
            "replayed_transcript": False,
        },
        "seed": seed,
        "turn_index": 0,
        "run_id": run_id,
    }) + "\n", encoding="utf-8")
    responses = root / f"{stem}.responses.jsonl"
    response_payload = {
        "attempt_id": "a",
        "target": model,
        "output_turns": [{"role": "assistant", "content": "reply"}],
        "raw": {
            "requested_seed": seed,
            "target_sampling_control": "provider_seed",
            "provider": "fixture-provider",
            "resolved_model": model_spec,
            "system_fingerprint": hashlib.sha256(
                model_spec.encode("utf-8")
            ).hexdigest(),
        },
        "run_id": run_id,
    }
    responses.write_text(json.dumps(response_payload) + "\n", encoding="utf-8")
    response_sha256 = hashlib.sha256(json.dumps(
        response_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    trails = root / f"{stem}.trails.jsonl"
    trail_payload = {
        "attempt_id": "a",
        "stage": 0,
        "judge": "rules",
        "label": label,
        "score": 1.0,
        "confidence": 0.9,
        "parsed": None,
        "cascade_confident": True,
        "cascade_role": "authoritative",
        "cascade_policy": "first_confident_with_full_shadow_trail",
        "risk_category": "cybersec",
        "modality": "text",
        "model": model,
        "datapoint_id": datapoint,
        "attacker": attacker,
        "seed": seed,
        "requested_seed": seed,
        "turn_index": 0,
        "run_id": run_id,
        "attack_fingerprint": fingerprint,
        "transfer_key": key,
        "transferable": True,
        "expected_behavior": expected,
        "common_metrics_eligible": eligible,
        "response_conditioned": response_conditioned,
        "replayed_transcript": False,
        "target_sampling_control": "provider_seed",
        "response_sha256": response_sha256,
    }
    trails.write_text(json.dumps(trail_payload) + "\n", encoding="utf-8")
    results = root / f"{stem}.results.jsonl"
    results.write_text(json.dumps({
        "id": f"{run_id}:ASR",
        "metric": "ASR",
        "value": 1.0 if label == "violation" else 0.0,
        "n": 1,
        "group_by": {"model": model},
        "run_id": run_id,
    }) + "\n", encoding="utf-8")
    identity_config, identity_digest = _identity_metadata(
        [response_payload], [trail_payload], ["rules"]
    )
    base_component = {
        "class": "FixtureTarget",
        "name": model.removesuffix("+guard"),
    }
    target_component = (
        base_component
        if defense == "none"
        else {
            "class": "GuardedTarget",
            "name": model,
            "mode": defense,
            "base": base_component,
            "guard": {"class": "RuleJudge", "name": "rules"},
        }
    )
    manifest = root / f"{stem}.manifest.json"
    manifest.write_text(json.dumps({
        "run_id": run_id,
        "code_version": CODE_VERSION,
        "config": {
            "budget": {"max_queries": 1, "max_turns": 1, "seed": 0},
            "components": {
                "attacker": {"class": attacker},
                "target": target_component,
                "judge_cascade": {"class": "Cascade"},
            },
            "run": {
                "corpus": corpus,
                "model_spec": model_spec,
                "attacker": attacker,
                "defense": defense,
                "defense_guard": "rules",
                "dry_run": False,
                "driver_source": {
                    "module": "run_matrix.py",
                    "sha256": hashlib.sha256(b"test-driver").hexdigest(),
                    "file_count": 1,
                },
            },
            "harness_source": {
                "algorithm": "sha256_relative_path_size_file_digest_v1",
                "sha256": hashlib.sha256(b"test-harness").hexdigest(),
                "file_count": 1,
                "bytes": 1,
            },
            "media_validation": {},
            "n_datapoints": 1,
            "n_attempts": 1,
            "n_responses": 1,
            "n_judgments": 1,
            "n_media_hashes": 0,
            "realized_attempts_sha256": hashlib.sha256(run_id.encode()).hexdigest(),
            **identity_config,
        },
        "seeds": [seed],
        "models": [model],
        "adapters": [attacker],
        "judges": ["rules"],
        "dataset_hashes": {"corpus": hashlib.sha256(b"fixture-corpus").hexdigest()},
        "started_at": "2026-01-01T00:00:00Z",
        "env": {"python": "test"},
        "schema_version": "1.0",
    }), encoding="utf-8")
    artifact_paths = {
        "attempts": attempts,
        "responses": responses,
        "judgments": path,
        "trails": trails,
        "results": results,
        "manifest": manifest,
    }
    artifacts: dict[str, object] = {
        role: artifact.name for role, artifact in artifact_paths.items()
    }
    if descriptor_marker:
        artifacts = {
            role: {
                "file": artifact.name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "bytes": artifact.stat().st_size,
                "records": (
                    sum(bool(line.strip()) for line in artifact.read_text(encoding="utf-8").splitlines())
                    if artifact.suffix == ".jsonl" else 1
                ),
            }
            for role, artifact in artifact_paths.items()
        }
    complete = root / f"{stem}.complete.json"
    marker = {
        "status": "complete",
        "run_id": run_id,
        "n_attempts": 1,
        "n_responses": 1,
        "n_judgments": 1,
        "n_results": 1,
        "realized_identities_sha256": identity_digest,
        "artifacts": artifacts,
    }
    if descriptor_marker:
        marker.update({
            "format_version": 2,
            "code_version": CODE_VERSION,
            "schema_version": "1.0",
        })
    complete.write_text(json.dumps(marker), encoding="utf-8")
    if grid_manifest:
        _write_grid_manifest(
            root,
            stem,
            model_spec=model_spec,
            resolved_target=model,
            run_id=run_id,
            attacker=attacker,
            corpus=corpus,
        )


def _write_grid_manifest(
    root: Path,
    stem: str,
    *,
    model_spec: str,
    resolved_target: str,
    run_id: str,
    attacker: str,
    corpus: str,
) -> None:
    grid = {
        "status": "complete",
        "grid_id": f"grid-{stem}",
        "request": {
            "models": [model_spec],
            "corpora": [corpus],
            "attackers": [attacker],
        },
        "requested_cells": 1,
        "accounted_cells": 1,
        "n_errors": 0,
        "cells": [{
            "corpus": corpus,
            "model_spec": model_spec,
            "target": resolved_target,
            "attacker": attacker,
            "run_id": run_id,
            "status": "complete",
            "completion_marker": f"{stem}.complete.json",
        }],
    }
    (root / f"{stem}.grid.json").write_text(json.dumps(grid), encoding="utf-8")


def _refresh_descriptors(root: Path, stem: str) -> None:
    marker_path = root / f"{stem}.complete.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    for descriptor in marker["artifacts"].values():
        artifact = root / descriptor["file"]
        descriptor.update({
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "bytes": artifact.stat().st_size,
            "records": (
                sum(bool(line.strip()) for line in artifact.read_text(encoding="utf-8").splitlines())
                if artifact.suffix == ".jsonl" else 1
            ),
        })
    marker_path.write_text(json.dumps(marker), encoding="utf-8")


def _refresh_identity_metadata(root: Path, stem: str) -> None:
    manifest_path = root / f"{stem}.manifest.json"
    marker_path = root / f"{stem}.complete.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    responses = [
        json.loads(line) for line in (root / f"{stem}.responses.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    trails = [
        json.loads(line) for line in (root / f"{stem}.trails.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    response_digests = {
        row["attempt_id"]: hashlib.sha256(json.dumps(
            Response.model_validate(row, strict=True).model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        for row in responses
    }
    for trail in trails:
        trail["response_sha256"] = response_digests[trail["attempt_id"]]
    (root / f"{stem}.trails.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in trails), encoding="utf-8"
    )
    identity_config, identity_digest = _identity_metadata(
        responses, trails, manifest["judges"]
    )
    manifest["config"].update(identity_config)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["realized_identities_sha256"] = identity_digest
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    _refresh_descriptors(root, stem)


def _append_live_turn(root: Path, stem: str, *, label: str) -> None:
    """Extend a v2 fixture to a complete two-turn conversation."""
    artifact_specs = (
        (f"{stem}.attempts.jsonl", "id"),
        (f"{stem}.responses.jsonl", "attempt_id"),
        (f"{stem}.jsonl", "attempt_id"),
        (f"{stem}.trails.jsonl", "attempt_id"),
    )
    for filename, id_field in artifact_specs:
        path = root / filename
        first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        second = json.loads(json.dumps(first))
        second[id_field] = "a-1"
        if filename.endswith(".attempts.jsonl"):
            second["turn_index"] = 1
        elif filename.endswith(".trails.jsonl"):
            second["label"] = label
            second["turn_index"] = 1
            response_rows = [
                json.loads(line) for line in (root / f"{stem}.responses.jsonl")
                .read_text(encoding="utf-8").splitlines() if line.strip()
            ]
            second_response = response_rows[1]
            second["response_sha256"] = hashlib.sha256(json.dumps(
                second_response, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
        elif filename.endswith(".jsonl") and not filename.endswith((
            ".attempts.jsonl", ".responses.jsonl", ".trails.jsonl",
        )):
            second["label"] = label
            second["raw"]["turn_index"] = 1
        path.write_text(
            json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8"
        )
    manifest_path = root / f"{stem}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config"]["n_attempts"] = 2
    manifest["config"]["n_responses"] = 2
    manifest["config"]["n_judgments"] = 2
    response_rows = [
        json.loads(line) for line in (root / f"{stem}.responses.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    trail_rows = [
        json.loads(line) for line in (root / f"{stem}.trails.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    identity_config, identity_digest = _identity_metadata(
        response_rows, trail_rows, manifest["judges"]
    )
    manifest["config"].update(identity_config)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    marker_path = root / f"{stem}.complete.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker.update({
        "n_attempts": 2,
        "n_responses": 2,
        "n_judgments": 2,
        "realized_identities_sha256": identity_digest,
    })
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    _refresh_descriptors(root, stem)


def _configure_two_stage_sensitivity_fixture(
    root: Path,
    stem: str,
    *,
    first_label: str = "safe",
    second_label: str = "violation",
) -> None:
    trail_path = root / f"{stem}.trails.jsonl"
    first = json.loads(trail_path.read_text(encoding="utf-8"))
    first.update({
        "stage": 0,
        "judge": "rules",
        "label": first_label,
        "confidence": 0.2,
        "parsed": None,
        "cascade_confident": False,
        "cascade_role": "shadow",
    })
    second = json.loads(json.dumps(first))
    second.update({
        "stage": 1,
        "judge": "llm-judge",
        "label": second_label,
        "confidence": 0.85,
        "parsed": True,
        "cascade_confident": True,
        "cascade_role": "authoritative",
    })
    trail_path.write_text(
        json.dumps(first) + "\n" + json.dumps(second) + "\n",
        encoding="utf-8",
    )

    judgment_path = root / f"{stem}.jsonl"
    judgment = json.loads(judgment_path.read_text(encoding="utf-8"))
    judgment.update({"judge": "llm-judge", "label": second_label})
    judgment["raw"].update({
        "cascade_stage": 1,
        "cascade_confident": True,
        "cascade_role": "authoritative",
    })
    judgment_path.write_text(json.dumps(judgment) + "\n", encoding="utf-8")

    manifest_path = root / f"{stem}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["judges"] = ["rules", "llm-judge"]
    manifest["config"]["run"]["judge_names"] = ["rules", "llm-judge"]
    responses = [
        json.loads(line) for line in (root / f"{stem}.responses.jsonl")
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    identity_config, identity_digest = _identity_metadata(
        responses, [first, second], manifest["judges"]
    )
    manifest["config"].update(identity_config)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    marker_path = root / f"{stem}.complete.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["realized_identities_sha256"] = identity_digest
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    _refresh_descriptors(root, stem)


def test_transfer_loader_is_recursive_and_rejects_ambiguous_runs(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    _write_completed_cell(nested, "cell", model="A", run_id="r1", key="k")
    per_model, audit = load(tmp_path)
    assert per_model["A"]["k"].run_id == "r1"
    assert audit["records_loaded"] == 1
    assert audit["unexplained_exclusions"] == 0
    assert audit["run_ids"] == {"A": "r1"}

    _write_completed_cell(tmp_path, "duplicate", model="A", run_id="r2", key="k")
    with pytest.raises(ValueError, match="mixed artifacts"):
        load(tmp_path)


def test_transfer_loader_requires_common_metric_eligibility(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "ineligible", model="A", run_id="r1", key="k", eligible=False
    )
    per_model, audit = load(tmp_path)
    assert per_model == {}
    assert audit["excluded"] == {"common_metrics_ineligible": 1}
    assert audit["records_loaded"] + audit["explained_exclusions"] == audit["rows_scanned"]


def test_transfer_loader_rejects_incompatible_cohorts(tmp_path: Path) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r1", key="k")
    _write_completed_cell(tmp_path, "b", model="B", run_id="r2", key="k")
    manifest = tmp_path / "b.manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["seeds"] = [99]
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    _refresh_descriptors(tmp_path, "b")
    with pytest.raises(ValueError, match="mixed/incompatible experiment cohorts"):
        load(tmp_path)


def test_transfer_loader_accepts_target_only_difference_and_emits_lineage(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r1", key="k")
    _write_completed_cell(tmp_path, "b", model="B", run_id="r2", key="k")
    per_model, audit = load(tmp_path)
    result = build_matrix(per_model, n_resamples=10, load_audit=audit)
    assert result["run_ids"] == {"A": "r1", "B": "r2"}
    assert result["judgment_source_files"]["A"] == [str(tmp_path / "a.jsonl")]
    assert result["load_audit"]["cohort_signature"]
    assert result["cells"]["A"]["B"]["unexplained_exclusions"] == 0


def test_transfer_loader_rejects_row_raw_manifest_lineage_mismatch(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r1", key="k")
    judgment = tmp_path / "a.jsonl"
    payload = json.loads(judgment.read_text(encoding="utf-8"))
    payload["raw"]["run_id"] = "wrong-run"
    judgment.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    _refresh_descriptors(tmp_path, "a")
    with pytest.raises(ValueError, match="row/raw/manifest run_id mismatch"):
        load(tmp_path)


def test_completion_descriptors_are_verified_and_tampering_fails(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r1", key="k", descriptor_marker=True
    )
    _, audit = load(tmp_path)
    assert audit["records_loaded"] == 1
    judgment = tmp_path / "a.jsonl"
    judgment.write_text(judgment.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="byte-count mismatch|sha256 mismatch"):
        load(tmp_path)


def test_measured_postprocessors_reject_legacy_filename_only_markers(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path,
        "legacy",
        model="A",
        run_id="r1",
        key="k",
        descriptor_marker=False,
    )
    with pytest.raises(ValueError, match="legacy or mixed artifact inventory"):
        load(tmp_path)


def test_measured_postprocessors_reject_missing_grid_manifest(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path,
        "untracked",
        model="A",
        run_id="r1",
        key="k",
        grid_manifest=False,
    )
    with pytest.raises(ValueError, match="requires a completed grid manifest"):
        load(tmp_path)


def test_measured_postprocessors_apply_canonical_pydantic_schemas(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "bad", model="A", run_id="r1", key="k")
    attempts = tmp_path / "bad.attempts.jsonl"
    row = json.loads(attempts.read_text(encoding="utf-8"))
    del row["rendered_input"]
    attempts.write_text(json.dumps(row) + "\n", encoding="utf-8")
    _refresh_descriptors(tmp_path, "bad")
    with pytest.raises(ValueError, match="Attempt schema validation failed"):
        load(tmp_path)


def test_measured_postprocessors_reject_orphan_marker_and_grid_reference(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r1", key="k")
    orphan = tmp_path / "orphan.complete.json"
    orphan.write_text(json.dumps({"status": "complete"}), encoding="utf-8")
    with pytest.raises(ValueError, match="completion/judgment inventory mismatch"):
        load(tmp_path)
    orphan.unlink()

    grid_path = tmp_path / "a.grid.json"
    grid = json.loads(grid_path.read_text(encoding="utf-8"))
    grid["cells"][0]["completion_marker"] = "ghost.complete.json"
    grid_path.write_text(json.dumps(grid), encoding="utf-8")
    with pytest.raises(ValueError, match="unselected/orphan completion marker"):
        load(tmp_path)


def test_transfer_validates_grid_accounting_and_running_state(tmp_path: Path) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r1", key="k")
    grid_path = tmp_path / "a.grid.json"
    grid = json.loads(grid_path.read_text(encoding="utf-8"))
    _, audit = load(tmp_path)
    assert audit["grid_audit"]["mode"] == "grid_accounted"

    grid["status"] = "running"
    grid_path.write_text(json.dumps(grid), encoding="utf-8")
    with pytest.raises(ValueError, match="still running"):
        load(tmp_path)


def test_completed_cell_rejects_rehashed_realized_identity_inventory_tampering(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "cell", model="A", run_id="r-a", key="k")
    manifest_path = tmp_path / "cell.manifest.json"
    marker_path = tmp_path / "cell.complete.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    identities = manifest["config"]["realized_identities"]
    identities["target"]["snapshot"]["resolved_model"] = "invented-model"
    invented_digest = hashlib.sha256(json.dumps(
        identities, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    manifest["config"]["realized_identities_sha256"] = invented_digest
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["realized_identities_sha256"] = invented_digest
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    _refresh_descriptors(tmp_path, "cell")

    with pytest.raises(ValueError, match="realized identity inventory mismatch"):
        load(tmp_path)


def test_completed_cell_rejects_realized_identity_digest_tampering(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "cell", model="A", run_id="r-a", key="k")
    marker_path = tmp_path / "cell.complete.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["realized_identities_sha256"] = "0" * 64
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    with pytest.raises(ValueError, match="completion marker realized identity digest"):
        load(tmp_path)


def test_paired_compare_exact_static_units_and_cli_lineage(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="shared",
        label="violation", fingerprint="same",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="shared",
        label="refusal", fingerprint="same",
    )
    result = compare(
        tmp_path,
        left_model="A",
        right_model="B",
        corpus="fixture",
        n_resamples=30,
        seed=7,
    )
    facet = result["facets"]["fixture"]
    asr = facet["metrics"]["ASR"]
    assert facet["comparison_type"] == "cross_target_endpoint_noncausal"
    assert facet["causal_interpretation_eligible"] is False
    assert facet["causal_effect_established"] is False
    assert asr["effect_left_minus_right"] == 1.0
    assert (asr["ci_low"], asr["ci_high"]) == (1.0, 1.0)
    assert asr["pairing_audit"]["matched_units"] == 1
    assert facet["left"]["run_id"] == "r-a"
    assert facet["right"]["judgment_source_file"].endswith("b.jsonl")
    assert facet["comparison_config_signature"] == facet["right_comparison_config_signature"]

    assert paired_main([
        "--results", str(tmp_path),
        "--left-model", "A",
        "--right-model", "B",
        "--corpus", "fixture",
        "--bootstrap", "20",
    ]) == 0
    output = json.loads((tmp_path / "paired_comparison.json").read_text(encoding="utf-8"))
    assert output["experiment_status"] == "computed_only_from_supplied_completed_artifacts"


def test_cross_model_comparison_ignores_target_but_retains_same_judge_identity(
    tmp_path: Path,
) -> None:
    for stem, model, run_id in (("a", "A", "r-a"), ("b", "B", "r-b")):
        _write_completed_cell(
            tmp_path, stem, model=model, run_id=run_id, key="shared",
        )
        trail_path = tmp_path / f"{stem}.trails.jsonl"
        trail = json.loads(trail_path.read_text(encoding="utf-8"))
        trail.update({
            "judge_model": "judge-v1",
            "judge_call": {
                "provider": "judge-provider",
                "resolved_model": "judge-v1-resolved",
                "system_fingerprint": "judge-fingerprint-stable",
                "response_target": "judge-endpoint",
            },
        })
        trail_path.write_text(json.dumps(trail) + "\n", encoding="utf-8")
        _refresh_identity_metadata(tmp_path, stem)

    result = compare(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        n_resamples=10,
    )
    facet = result["facets"]["fixture"]
    assert facet["comparison_type"] == "cross_target_endpoint_noncausal"
    assert facet["comparison_config_signature"] == (
        facet["right_comparison_config_signature"]
    )


def test_cross_model_comparison_rejects_realized_judge_identity_mismatch(
    tmp_path: Path,
) -> None:
    for stem, model, run_id, fingerprint in (
        ("a", "A", "r-a", "judge-fingerprint-a"),
        ("b", "B", "r-b", "judge-fingerprint-b"),
    ):
        _write_completed_cell(
            tmp_path, stem, model=model, run_id=run_id, key="shared",
        )
        trail_path = tmp_path / f"{stem}.trails.jsonl"
        trail = json.loads(trail_path.read_text(encoding="utf-8"))
        trail.update({
            "judge_model": "judge-v1",
            "judge_call": {
                "provider": "judge-provider",
                "resolved_model": "judge-v1-resolved",
                "system_fingerprint": fingerprint,
                "response_target": "judge-endpoint",
            },
        })
        trail_path.write_text(json.dumps(trail) + "\n", encoding="utf-8")
        _refresh_identity_metadata(tmp_path, stem)

    with pytest.raises(ValueError, match="incompatible manifests"):
        compare(
            tmp_path, left_model="A", right_model="B", corpus="fixture",
            n_resamples=10,
        )


def test_cross_model_comparison_rejects_judge_endpoint_mismatch(
    tmp_path: Path,
) -> None:
    for stem, model, run_id, judge_endpoint in (
        ("a", "A", "r-a", "judge-endpoint-a"),
        ("b", "B", "r-b", "judge-endpoint-b"),
    ):
        _write_completed_cell(
            tmp_path, stem, model=model, run_id=run_id, key="shared",
        )
        trail_path = tmp_path / f"{stem}.trails.jsonl"
        trail = json.loads(trail_path.read_text(encoding="utf-8"))
        trail.update({
            "judge_model": "judge-v1",
            "judge_call": {
                "provider": "judge-provider",
                "resolved_model": "judge-v1-resolved",
                "system_fingerprint": "judge-fingerprint-stable",
                "response_target": judge_endpoint,
            },
        })
        trail_path.write_text(json.dumps(trail) + "\n", encoding="utf-8")
        _refresh_identity_metadata(tmp_path, stem)

    with pytest.raises(ValueError, match="incompatible manifests"):
        compare(
            tmp_path, left_model="A", right_model="B", corpus="fixture",
            n_resamples=10,
        )


def test_paired_compare_reports_unmatched_and_input_mismatch(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="shared",
        datapoint="dp", fingerprint="left-fp",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="shared",
        datapoint="dp", fingerprint="right-fp",
    )
    result = compare(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        n_resamples=10,
    )
    asr = result["facets"]["fixture"]["metrics"]["ASR"]
    assert asr["status"] == "not_estimable_no_exact_shared_units"
    assert asr["effect_left_minus_right"] is None
    assert asr["pairing_audit"]["static_input_mismatch_units"] == 1
    assert asr["pairing_audit"]["unexplained_exclusions"] == 0


def test_paired_compare_reports_left_and_right_only_units(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="left",
        datapoint="left-dp",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="right",
        datapoint="right-dp",
    )
    result = compare(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        n_resamples=10,
    )
    audit = result["facets"]["fixture"]["metrics"]["ASR"]["pairing_audit"]
    assert audit["matched_units"] == 0
    assert audit["left_only_units"] == audit["right_only_units"] == 1
    assert audit["left_only_unit_keys"] == [{"datapoint_id": "left-dp", "seed": 0}]


def test_paired_compare_rejects_confounded_model_and_defense_change(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="k", defense="none",
    )
    _write_completed_cell(
        tmp_path, "b", model="B+guard", model_spec="B", run_id="r-b",
        key="k", defense="input",
    )
    with pytest.raises(ValueError, match="differ in both model_spec and defense"):
        compare(
            tmp_path,
            left_model="A",
            right_model="B",
            left_defense="none",
            right_defense="input",
            corpus="fixture",
            n_resamples=10,
        )


def test_paired_compare_accepts_same_base_defense_contrast(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "none", model="base", model_spec="provider:base",
        defense="none", run_id="r-none", key="shared", label="violation",
    )
    _write_completed_cell(
        tmp_path, "guard", model="base+guard", model_spec="provider:base",
        defense="input", run_id="r-guard", key="shared", label="refusal",
    )
    result = compare(
        tmp_path,
        left_model="provider:base",
        right_model="provider:base",
        left_defense="none",
        right_defense="input",
        corpus="fixture",
        n_resamples=10,
    )
    facet = result["facets"]["fixture"]
    assert facet["comparison_type"] == "within_target_defense_intervention"
    assert facet["causal_interpretation_eligible"] is True
    assert facet["causal_effect_established"] is False
    assert facet["metrics"]["ASR"]["effect_left_minus_right"] == 1.0


def test_same_base_defense_rejects_realized_provider_identity_mismatch(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "none", model="base", model_spec="provider:base",
        defense="none", run_id="r-none", key="shared",
    )
    _write_completed_cell(
        tmp_path, "guard", model="base+guard", model_spec="provider:base",
        defense="input", run_id="r-guard", key="shared",
    )
    response_path = tmp_path / "guard.responses.jsonl"
    response = json.loads(response_path.read_text(encoding="utf-8"))
    response["raw"]["system_fingerprint"] = "different-realized-endpoint"
    response_path.write_text(json.dumps(response) + "\n", encoding="utf-8")
    _refresh_identity_metadata(tmp_path, "guard")

    with pytest.raises(ValueError, match="conflicting realized underlying"):
        compare(
            tmp_path,
            left_model="provider:base",
            right_model="provider:base",
            left_defense="none",
            right_defense="input",
            corpus="fixture",
            n_resamples=10,
        )


def test_same_base_defense_qualifies_input_blocked_identity_absence(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "none", model="base", model_spec="provider:base",
        defense="none", run_id="r-none", key="shared",
    )
    _write_completed_cell(
        tmp_path, "guard", model="base+guard", model_spec="provider:base",
        defense="input", run_id="r-guard", key="shared",
    )
    response_path = tmp_path / "guard.responses.jsonl"
    response = json.loads(response_path.read_text(encoding="utf-8"))
    for field in ("provider", "resolved_model", "system_fingerprint"):
        response["raw"].pop(field)
    response_path.write_text(json.dumps(response) + "\n", encoding="utf-8")
    _refresh_identity_metadata(tmp_path, "guard")

    result = compare(
        tmp_path,
        left_model="provider:base",
        right_model="provider:base",
        left_defense="none",
        right_defense="input",
        corpus="fixture",
        n_resamples=10,
    )
    qualification = result["facets"]["fixture"]["defense_identity_qualification"]
    assert qualification["status"] == "unobserved_planned_same_base_only"
    assert qualification["realized_identity_equality_claimed"] is False
    assert qualification["right_observed_fields"] == []


def test_paired_compare_live_conversations_use_conversation_units(tmp_path: Path) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="live-a",
        attacker="crescendo", response_conditioned=True,
        fingerprint="arm-specific-a", label="safe",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="live-b",
        attacker="crescendo", response_conditioned=True,
        fingerprint="arm-specific-b", label="refusal",
    )
    _append_live_turn(tmp_path, "a", label="violation")
    _append_live_turn(tmp_path, "b", label="refusal")
    result = compare(
        tmp_path,
        left_model="A",
        right_model="B",
        attacker="crescendo",
        corpus="fixture",
        n_resamples=10,
    )
    facet = result["facets"]["fixture"]
    assert facet["unit_mode"] == "live"
    assert facet["static_exact_input_required"] is False
    assert facet["metrics"]["conversation_ASR"]["n_matched"] == 1
    assert facet["arm_audits"]["left"]["eligible_rows"] == 2
    assert facet["metrics"]["conversation_ASR"]["effect_left_minus_right"] == 1.0
    assert "transcripts may differ" in facet["live_pairing_qualification"]


def test_paired_compare_live_arms_may_realize_different_turn_counts(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="live-a",
        attacker="crescendo", response_conditioned=True,
        fingerprint="arm-specific-a", label="safe",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="live-b",
        attacker="crescendo", response_conditioned=True,
        fingerprint="arm-specific-b", label="refusal",
    )
    _append_live_turn(tmp_path, "a", label="violation")

    result = compare(
        tmp_path,
        left_model="A",
        right_model="B",
        attacker="crescendo",
        corpus="fixture",
        n_resamples=10,
    )
    facet = result["facets"]["fixture"]
    assert facet["arm_audits"]["left"]["eligible_rows"] == 2
    assert facet["arm_audits"]["right"]["eligible_rows"] == 1
    assert facet["metrics"]["conversation_ASR"]["n_matched"] == 1
    assert facet["metrics"]["conversation_ASR"]["effect_left_minus_right"] == 1.0


def test_kappa_cohort_identity_ignores_adaptive_realized_turn_counts(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="live-a",
        attacker="crescendo", response_conditioned=True,
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="live-b",
        attacker="crescendo", response_conditioned=True,
    )
    _append_live_turn(tmp_path, "a", label="violation")

    facets = load_trail_facets(
        tmp_path, attacker="crescendo", corpus="fixture"
    )
    per_judge, metadata, audit = facets["fixture"]
    assert len(per_judge["rules"]) == 3
    assert len(metadata) == 3
    assert audit["completed_cells"] == 2
    assert audit["unexplained_exclusions"] == 0


def test_paired_compare_rejects_requested_seed_lineage_mismatch(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="shared",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="shared",
    )
    path = tmp_path / "a.jsonl"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["raw"]["requested_seed"] = 99
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    _refresh_descriptors(tmp_path, "a")

    with pytest.raises(ValueError, match="requested_seed mismatch"):
        compare(
            tmp_path, left_model="A", right_model="B", corpus="fixture",
            n_resamples=10,
        )


def test_paired_compare_keeps_common_ineligible_as_explicit_exclusion(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="k", eligible=False,
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="k", eligible=False,
    )
    result = compare(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        n_resamples=10,
    )
    facet = result["facets"]["fixture"]
    assert facet["arm_audits"]["left"]["common_ineligible_units"] == 1
    assert facet["metrics"]["ASR"]["status"] == "not_applicable_empty_population"
    assert facet["publishable_real_run"] is False
    assert facet["publishability_checks"]["zero_common_metric_exclusions"] is False
    assert facet["unexplained_exclusions"] == 0


def test_judge_sensitivity_uses_same_response_and_bounds_harmful_abstention(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "cell", model="A", run_id="r-a", key="shared",
        label="violation", expected="refuse",
    )
    _configure_two_stage_sensitivity_fixture(tmp_path, "cell")

    result = analyse_sensitivity(tmp_path, attacker="replay", corpus="fixture")
    facet = result["facets"]["cell"]
    rules = facet["stages"]["0:rules"]
    llm = facet["stages"]["1:llm-judge"]
    rules_asr = rules["metrics"]["harmful"]
    llm_asr = llm["metrics"]["harmful"]

    assert result["no_new_target_calls"] is True
    assert facet["publishable_real_run"] is True
    assert rules["coverage_all_completed_attempts"]["abstained_rows"] == 1
    assert rules["coverage_all_completed_attempts"]["parse_not_applicable_structured_rows"] == 1
    assert rules_asr["status"] == "partially_identified"
    assert rules_asr["point_estimate"] is None
    assert rules_asr["identification_lower_bound"] == 0.0
    assert rules_asr["identification_upper_bound"] == 1.0
    assert llm_asr["status"] == "point_identified"
    assert llm_asr["point_estimate"] == 1.0
    assert facet["artifact_accounting"]["response_digest_matches"] == 2
    assert facet["artifact_accounting"]["unexplained_exclusions"] == 0

    assert sensitivity_main([
        "--results", str(tmp_path),
        "--attacker", "replay",
        "--corpus", "fixture",
    ]) == 0
    written = json.loads(
        (tmp_path / "judge_sensitivity.json").read_text(encoding="utf-8")
    )
    assert written["experiment_status"].endswith("completed_R1_artifacts")


def test_judge_sensitivity_bounds_benign_abstention_without_safe_imputation(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "cell", model="A", run_id="r-a", key="shared",
        label="over_refusal", expected="safe_answer",
    )
    _configure_two_stage_sensitivity_fixture(
        tmp_path, "cell", first_label="safe", second_label="over_refusal",
    )

    result = analyse_sensitivity(tmp_path, attacker="replay", corpus="fixture")
    facet = result["facets"]["cell"]
    rules_frr = facet["stages"]["0:rules"]["metrics"]["benign"]
    llm_frr = facet["stages"]["1:llm-judge"]["metrics"]["benign"]
    assert rules_frr["abstention_units"] == 1
    assert rules_frr["identification_lower_bound"] == 0.0
    assert rules_frr["identification_upper_bound"] == 1.0
    assert llm_frr["point_estimate"] == 1.0


def test_judge_sensitivity_rejects_trail_response_digest_mismatch(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "cell", model="A", run_id="r-a", key="shared",
    )
    trail_path = tmp_path / "cell.trails.jsonl"
    trail = json.loads(trail_path.read_text(encoding="utf-8"))
    trail["response_sha256"] = "0" * 64
    trail_path.write_text(json.dumps(trail) + "\n", encoding="utf-8")
    _refresh_descriptors(tmp_path, "cell")

    with pytest.raises(ValueError, match="trail/Response digest mismatch"):
        analyse_sensitivity(tmp_path, attacker="replay", corpus="fixture")


def test_transfer_facets_multi_corpus_and_defaults_to_replay(tmp_path: Path) -> None:
    for corpus in ("c1", "c2"):
        _write_completed_cell(
            tmp_path, f"{corpus}-a", model="A", run_id=f"r-{corpus}-a",
            key="k", corpus=corpus,
        )
        _write_completed_cell(
            tmp_path, f"{corpus}-b", model="B", run_id=f"r-{corpus}-b",
            key="k", corpus=corpus,
        )
    _write_completed_cell(
        tmp_path, "c1-crescendo", model="C", run_id="r-c1-c",
        key="adaptive", corpus="c1", attacker="crescendo",
    )
    for model in ("A", "B"):
        _write_completed_cell(
            tmp_path, f"c3-{model.lower()}", model=model,
            run_id=f"r-c3-{model.lower()}", key="source-specific",
            corpus="c3", eligible=False,
        )
    facets = load_facets(tmp_path)
    assert sorted(facets) == ["c1", "c2", "c3"]
    assert sorted(facets["c1"][0]) == ["A", "B"]
    assert facets["c1"][1]["facet"] == {"attacker": "replay", "corpus": "c1"}
    with pytest.raises(ValueError, match="spans multiple corpora"):
        load(tmp_path)
    assert transfer_main([
        "--results", str(tmp_path), "--bootstrap", "10",
    ]) == 0
    index = json.loads((tmp_path / "transfer_matrix.json").read_text(encoding="utf-8"))
    assert index["schema_version"] == "2.1-faceted"
    assert sorted(index["facets"]) == ["c1", "c2"]
    assert index["not_applicable_facets"]["c3"]["unexplained_exclusions"] == 0


def test_human_consensus_requires_two_item_level_ratings() -> None:
    labels = {"r1": {"one": "violation", "two": "safe"}, "r2": {"two": "safe"}}
    assert _consensus(labels, {}) == {"two": "safe"}
    assert _consensus(labels, {}, min_independent_ratings=1) == {
        "one": "violation",
        "two": "safe",
    }
    assert _csv_safe("  =HYPERLINK('x')").startswith("'")


def test_conflicting_duplicate_human_label_fails(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "sample_key,rater_id,label,adjudicated_label\n"
        "s,r1,safe,\n"
        "s,r1,violation,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="conflicting labels"):
        load_labels(labels)


def _write_human_artifacts(root: Path, *, descriptor_marker: bool = True) -> str:
    run_id = "run-1"
    model = "model-A"
    attempt_id = "attempt-1"
    key = f"{run_id}|{model}|{attempt_id}"
    (root / "cell.attempts.jsonl").write_text(json.dumps({
        "id": attempt_id,
        "datapoint_id": "dp-1",
        "attacker": "replay",
        "target": model,
        "rendered_input": [{"role": "user", "content": "probe"}],
        "run_id": run_id,
    }) + "\n", encoding="utf-8")
    response_payload = {
        "attempt_id": attempt_id,
        "target": model,
        "output_turns": [{"role": "assistant", "content": "reply"}],
        "raw": {
            "provider": "fixture-provider",
            "resolved_model": model,
            "system_fingerprint": hashlib.sha256(model.encode()).hexdigest(),
        },
        "run_id": run_id,
    }
    (root / "cell.responses.jsonl").write_text(
        json.dumps(response_payload) + "\n", encoding="utf-8"
    )
    raw = {
        "run_id": run_id,
        "model": model,
        "target": model,
        "datapoint_id": "dp-1",
        "risk_category": "cybersec",
        "risk": "cybersec",
        "modality": "text",
        "expected_behavior": "refuse",
    }
    (root / "cell.jsonl").write_text(json.dumps({
        "attempt_id": attempt_id,
        "judge": "rules",
        "label": "violation",
        "score": 1.0,
        "raw": raw,
        "run_id": run_id,
    }) + "\n", encoding="utf-8")
    trail_rows = [{
        "attempt_id": attempt_id,
        "stage": 0,
        "judge": "rules",
        "label": "safe",
        "score": 0.0,
        "confidence": 0.9,
        "parsed": None,
        "cascade_confident": True,
        "risk_category": "cybersec",
        "modality": "text",
        "model": model,
        "run_id": run_id,
    }, {
        "attempt_id": attempt_id,
        "stage": 1,
        "judge": "llm-judge",
        "label": "violation",
        "score": 1.0,
        "confidence": 0.85,
        "parsed": True,
        "cascade_confident": True,
        "risk_category": "cybersec",
        "modality": "text",
        "model": model,
        "run_id": run_id,
    }]
    (root / "cell.trails.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in trail_rows), encoding="utf-8"
    )
    (root / "cell.results.jsonl").write_text(json.dumps({
        "id": f"{run_id}:ASR",
        "metric": "ASR",
        "value": 1.0,
        "n": 1,
        "group_by": {"model": model},
        "run_id": run_id,
    }) + "\n", encoding="utf-8")
    identity_config, identity_digest = _identity_metadata(
        [response_payload], trail_rows, ["rules", "llm-judge"]
    )
    (root / "cell.manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "code_version": CODE_VERSION,
        "config": {
            "budget": {"max_queries": 1, "max_turns": 1, "seed": 0},
            "components": {
                "attacker": {"class": "Replay"},
                "target": {"class": "Target", "name": model},
                "judge_cascade": {"class": "Cascade"},
            },
            "run": {
                "corpus": "fixture",
                "model_spec": model,
                "attacker": "replay",
                "defense": "none",
                "dry_run": False,
                "driver_source": {
                    "module": "run_matrix.py",
                    "sha256": hashlib.sha256(b"test-driver").hexdigest(),
                    "file_count": 1,
                },
            },
            "harness_source": {
                "algorithm": "sha256_relative_path_size_file_digest_v1",
                "sha256": hashlib.sha256(b"test-harness").hexdigest(),
                "file_count": 1,
                "bytes": 1,
            },
            "media_validation": {},
            "n_datapoints": 1,
            "n_attempts": 1,
            "n_responses": 1,
            "n_judgments": 1,
            "n_media_hashes": 0,
            **identity_config,
        },
        "seeds": [0],
        "models": [model],
        "adapters": ["replay"],
        "judges": ["rules", "llm-judge"],
        "dataset_hashes": {"corpus": hashlib.sha256(b"fixture-corpus").hexdigest()},
        "started_at": "2026-01-01T00:00:00Z",
        "env": {"python": "test"},
        "schema_version": "1.0",
    }), encoding="utf-8")
    artifact_names = {
        "attempts": "cell.attempts.jsonl",
        "responses": "cell.responses.jsonl",
        "judgments": "cell.jsonl",
        "trails": "cell.trails.jsonl",
        "results": "cell.results.jsonl",
        "manifest": "cell.manifest.json",
    }
    artifacts: dict[str, object] = dict(artifact_names)
    if descriptor_marker:
        artifacts = {}
        for role, name in artifact_names.items():
            artifact = root / name
            artifacts[role] = {
                "file": name,
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "bytes": artifact.stat().st_size,
                "records": (
                    sum(bool(line.strip()) for line in artifact.read_text(encoding="utf-8").splitlines())
                    if artifact.suffix == ".jsonl" else 1
                ),
            }
    marker = {
        "status": "complete",
        "run_id": run_id,
        "n_attempts": 1,
        "n_responses": 1,
        "n_judgments": 1,
        "n_results": 1,
        "realized_identities_sha256": identity_digest,
        "artifacts": artifacts,
    }
    if descriptor_marker:
        marker.update({
            "format_version": 2,
            "code_version": CODE_VERSION,
            "schema_version": "1.0",
        })
    (root / "cell.complete.json").write_text(json.dumps(marker), encoding="utf-8")
    _write_grid_manifest(
        root,
        "cell",
        model_spec=model,
        resolved_target=model,
        run_id=run_id,
        attacker="replay",
        corpus="fixture",
    )
    return key


def test_human_audit_includes_authoritative_cascade_and_reports_join_audit(
    tmp_path: Path,
) -> None:
    key = _write_human_artifacts(tmp_path)
    predictors, _, _, audit = _joined_artifacts(tmp_path)
    assert predictors["rules"][key] == "safe"
    assert predictors["cascade_authoritative"][key] == "violation"
    assert audit["unexplained_exclusions"] == 0

    labels = tmp_path / "labels.csv"
    header = (
        "sample_key,run_id,model,attempt_id,risk_category,modality,"
        "stratum_population,stratum_selected,selection_probability,"
        "rater_id,label,adjudicated_label\n"
    )
    common = f"{key},run-1,model-A,attempt-1,cybersec,text,1,1,1.0,"
    labels.write_text(
        header + common + "r1,violation,\n" + common + "r2,violation,\n",
        encoding="utf-8",
    )
    assert analyse(tmp_path, labels, allow_single_rater=False) == 0
    report = json.loads((tmp_path / "human_audit.json").read_text(encoding="utf-8"))
    assert "cascade_authoritative" in report["automated_vs_consensus"]
    assert report["audit"]["unexplained_exclusions"] == 0


def test_human_audit_accepts_verified_completion_descriptors(tmp_path: Path) -> None:
    key = _write_human_artifacts(tmp_path, descriptor_marker=True)
    predictors, _, _, audit = _joined_artifacts(tmp_path)
    assert predictors["cascade_authoritative"][key] == "violation"
    assert audit["validated_completed_cells"] == 1
    assert kappa_main(["--results", str(tmp_path)]) == 0
    kappa = json.loads((tmp_path / "judge_kappa.json").read_text(encoding="utf-8"))
    assert kappa["unexplained_exclusions"] == 0


def test_kappa_counts_low_confidence_stage_output_as_abstention(
    tmp_path: Path,
) -> None:
    _write_human_artifacts(tmp_path)
    trail_path = tmp_path / "cell.trails.jsonl"
    rows = [
        json.loads(line) for line in trail_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows[0]["cascade_confident"] = False
    trail_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    _refresh_descriptors(tmp_path, "cell")

    assert kappa_main(["--results", str(tmp_path)]) == 0
    report = json.loads((tmp_path / "judge_kappa.json").read_text(encoding="utf-8"))
    pair = report["pairs"]["llm-judge|rules"]
    assert pair["pooled"] is None
    assert pair["not_evaluable_reason"] == "no_joint_stage_decisions"
    assert pair["coverage_audit"]["judge_b_abstentions"] == 1
    assert pair["coverage_audit"]["one_sided_decisions"] == 1


def test_human_labels_reject_partial_or_conflicting_adjudication(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "sample_key,rater_id,label,adjudicated_label\n"
        "s,r1,safe,safe\n"
        "s,r2,violation,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="repeated on every rater row"):
        load_labels(labels)


def test_human_join_rejects_duplicate_or_orphan_artifacts(tmp_path: Path) -> None:
    _write_human_artifacts(tmp_path)
    response_path = tmp_path / "cell.responses.jsonl"
    row = response_path.read_text(encoding="utf-8")
    response_path.write_text(row + row, encoding="utf-8")
    _refresh_descriptors(tmp_path, "cell")
    with pytest.raises(ValueError, match="completion count|duplicate response"):
        _joined_artifacts(tmp_path)


def test_human_labels_reject_inconsistent_sampling_metadata(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    labels.write_text(
        "sample_key,risk_category,rater_id,label,adjudicated_label\n"
        "s,cybersec,r1,safe,\n"
        "s,privacy,r2,safe,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="inconsistent sampling metadata"):
        load_labels(labels)


def test_human_audit_rejects_partial_or_error_cells(tmp_path: Path) -> None:
    _write_human_artifacts(tmp_path)
    (tmp_path / "cell.complete.json").unlink()
    with pytest.raises(ValueError, match="completion marker"):
        _joined_artifacts(tmp_path)

    _write_human_artifacts(tmp_path)
    (tmp_path / "cell.error.json").write_text(
        json.dumps({"status": "error", "run_id": "run-1"}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="containing failed cells"):
        _joined_artifacts(tmp_path)
