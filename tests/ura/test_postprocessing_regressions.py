"""Regressions for post-hoc analyses that feed Chapter V."""
from __future__ import annotations

import hashlib
import json
import csv
from pathlib import Path

import pytest

from ura.data_models import SCHEMA_VERSION, Response
from ura.runner import realized_identity_summary

from experiments.analysis_integrity import analysis_source_identity
from experiments.human_audit import (
    _consensus,
    _csv_safe,
    _joined_artifacts,
    _primary_effect_sensitivity,
    analyse,
    load_labels,
    prepare_sample,
)
from experiments.confirmatory_analysis import execute_plan
from experiments.kappa import load_trail_facets, main as kappa_main
from experiments.judge_sensitivity import (
    analyse as analyse_sensitivity,
    main as sensitivity_main,
)
from experiments.pilot_analysis import (
    REQUIRED_PILOT_CHECKS,
    generate_pilot,
    paired_analysis_design,
)
from experiments.paired_compare import (
    PairedUnit,
    _metric_result,
    compare,
    compare_adaptivity,
    main as paired_main,
)
from experiments.transfer_matrix import (
    CODE_VERSION,
    TransferRecord,
    build_matrix,
    load,
    load_facets,
    main as transfer_main,
)
from ura.metrics import required_clusters_for_power, required_clusters_for_proportion_precision


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


def test_transfer_equal_weights_prompt_intent_clusters() -> None:
    records: dict[str, dict[str, TransferRecord]] = {"A": {}, "B": {}}
    for index, (cluster, target_label) in enumerate([
        ("repeated", "violation"),
        ("repeated", "violation"),
        ("repeated", "violation"),
        ("single", "refusal"),
    ]):
        key = f"k-{index}"
        for model, label in (("A", "violation"), ("B", target_label)):
            records[model][key] = TransferRecord(
                model=model, run_id=f"run-{model}", transfer_key=key,
                attack_fingerprint=f"fp-{index}", datapoint_id=f"dp-{index}",
                label=label, expected_behavior="refuse", transferable=True,
                source_file="fixture", source_cluster_id=cluster,
            )
    matrix = build_matrix(
        records, n_resamples=50, minimum_unique_clusters=2,
    )
    cell = matrix["cells"]["A"]["B"]
    assert cell["value"] == 0.5  # not row-weighted 3/4
    assert cell["n_matched_clusters"] == 2
    assert cell["support_gate_passed"] is True
    assert "power_gate" not in cell
    assert "power_design" not in matrix
    assert matrix["multiplicity"]["status"] == "outside_holm_conditional_descriptive"


def test_transfer_publishability_requires_complete_exact_input_coverage() -> None:
    records: dict[str, dict[str, TransferRecord]] = {"A": {}, "B": {}}
    for index in range(3):
        key = f"k-{index}"
        records["A"][key] = TransferRecord(
            model="A", run_id="run-A", transfer_key=key,
            attack_fingerprint=f"fp-{index}", datapoint_id=f"dp-{index}",
            label="violation", expected_behavior="refuse", transferable=True,
            source_file="fixture", source_cluster_id=f"c-{index}",
        )
        if index < 2:
            records["B"][key] = TransferRecord(
                model="B", run_id="run-B", transfer_key=key,
                attack_fingerprint=f"fp-{index}", datapoint_id=f"dp-{index}",
                label="violation", expected_behavior="refuse", transferable=True,
                source_file="fixture", source_cluster_id=f"c-{index}",
            )
    matrix = build_matrix(
        records, n_resamples=20, minimum_unique_clusters=2,
        load_audit={"publishable_real_run": True},
    )
    assert matrix["support_gate_passed"] is True
    assert matrix["cells"]["A"]["B"]["unmatched"] == 1
    assert matrix["exact_input_coverage_gate_passed"] is False
    assert matrix["publishable_real_run"] is False


def test_paired_compare_equal_weights_clusters_with_unequal_seed_counts() -> None:
    left: dict[tuple[str, int], PairedUnit] = {}
    right: dict[tuple[str, int], PairedUnit] = {}
    for index, (cluster, effect) in enumerate([
        ("many", 1.0), ("many", 1.0), ("many", 1.0), ("one", 0.0),
    ]):
        key = (f"dp-{index}", index)
        common = dict(
            datapoint_id=key[0], source_cluster_id=cluster, seed=key[1],
            population="harmful_expected_refusal", metric="ASR", source="fixture",
            source_policy_id="unversioned", source_policy_version="unversioned",
            source_policy_sha256="unversioned",
            risk_category="cybersec", modality="text", n_turns=1,
            attack_fingerprint=f"fp-{index}", transfer_key=f"tk-{index}",
            sampling_controls=(),
        )
        left[key] = PairedUnit(value=effect, **common)
        right[key] = PairedUnit(value=0.0, **common)
    result = _metric_result(
        "ASR", left, right, mode="static", n_resamples=50, seed=7,
    )
    assert result["effect_left_minus_right"] == 0.5  # not flattened 3/4
    assert result["left_value"] == 0.5
    assert result["n_clusters"] == 2
    assert [row["n_paired_units"] for row in result["cluster_summaries"]] == [3, 1]


def test_policy_conditioned_metric_does_not_pool_distinct_source_policies() -> None:
    left: dict[tuple[str, int], PairedUnit] = {}
    right: dict[tuple[str, int], PairedUnit] = {}
    for index, (policy, value) in enumerate((("p1", 1.0), ("p2", 0.0))):
        key = (f"dp-{index}", 0)
        common = dict(
            datapoint_id=key[0], source_cluster_id=f"c-{index}", seed=0,
            population="harmful_expected_refusal", metric="ASR", source="mmsafety",
            source_policy_id=policy, source_policy_version="v1",
            source_policy_sha256=hashlib.sha256(policy.encode()).hexdigest(),
            risk_category="jailbreak", modality="image_text", n_turns=1,
            attack_fingerprint=f"fp-{index}", transfer_key=f"tk-{index}",
            sampling_controls=(),
        )
        left[key] = PairedUnit(value=value, **common)
        right[key] = PairedUnit(value=0.0, **common)
    pooled = _metric_result("ASR", left, right, mode="static", n_resamples=20, seed=0)
    policy_one = _metric_result(
        "ASR", left, right, mode="static", n_resamples=20, seed=0,
        source_policy_id="p1", source_policy_version="v1",
    )
    policy_two = _metric_result(
        "ASR", left, right, mode="static", n_resamples=20, seed=0,
        source_policy_id="p2", source_policy_version="v1",
    )
    assert pooled["effect_left_minus_right"] == 0.5
    assert policy_one["effect_left_minus_right"] == 1.0
    assert policy_two["effect_left_minus_right"] == 0.0
    assert policy_one["source_policy_id"] == "p1"


def test_category_pilot_binds_exact_risk_modality_and_conservative_prevalence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def arm(model: str, run_id: str) -> dict[str, object]:
        return {
            "run_id": run_id,
            "model_spec": model,
            "resolved_target": model,
            "defense": "none",
            "attacker": "replay",
            "corpus": "fixture",
            "judges": ["rules"],
            "realized_identities": {
                "target": {
                    "observations": 2,
                    "snapshot": {
                        "provider": "fixture-provider",
                        "resolved_model": model,
                        "system_fingerprint": hashlib.sha256(
                            model.encode("utf-8")
                        ).hexdigest(),
                    },
                },
                "judges": [{
                    "stage": 0, "judge": "rules", "observations": 2,
                    "snapshot": {"judge": "rules"},
                }],
            },
            "seeds": [0],
            "budget": {"max_queries": 1, "max_turns": 1, "seed": 0},
            "code_version": "fixture-code",
            "schema_version": "fixture-schema",
            "source_policy_inventory": [],
            "source_metric_inventory": [],
        }

    pairing_audit = {
        "left_only_units": 0,
        "right_only_units": 0,
        "static_input_mismatch_units": 0,
        "unexplained_exclusions": 0,
    }
    report = {
        "facets": {"fixture": {
            "comparison_type": "cross_target_endpoint_noncausal",
            "unit_mode": "static",
            "pairing_unit": "datapoint_id x requested_seed",
            "inference_cluster": "source_cluster_id (fallback datapoint_id)",
            "source": "fixture-source",
            "source_policy_facets": [{
                "token": "policy=p1@v1", "policy_id": "p1", "version": "v1",
                "sha256": "1" * 64,
            }],
            "left": arm("A", "pilot-left"),
            "right": arm("B", "pilot-right"),
            "publishability_checks": {
                key: True for key in REQUIRED_PILOT_CHECKS
            },
            "metrics": {},
            "category_metrics": {"policy=p1@v1::cybersec::image_text": {
                "status": "estimated", "cluster_difference_sd": 0.25,
                "pairing_audit": pairing_audit,
                "cluster_summaries": [
                    {"source_cluster_id": "c1", "left_mean": 1.0, "right_mean": 0.0},
                    {"source_cluster_id": "c2", "left_mean": 0.0, "right_mean": 0.0},
                ],
            }},
        }},
        "analysis_source": {"sha256": "0" * 64},
    }
    monkeypatch.setattr("experiments.pilot_analysis.compare", lambda *args, **kwargs: report)
    artifact = generate_pilot(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        risk_category="cybersec", modality="image_text",
        source_policy_id="p1", source_policy_version="v1",
        prevalence_source="conservative",
    )
    assert artifact["risk_category"] == "cybersec"
    assert artifact["modality"] == "image_text"
    assert artifact["event_prevalence"] == 0.5
    assert artifact["event_prevalence_provenance"] == "conservative_max_binomial_variance"
    assert artifact["artifact_locator"] == {
        "kind": "completed_run_set",
        "source_run_ids": ["pilot-left", "pilot-right"],
        "source_run_ids_sha256": hashlib.sha256(
            json.dumps(
                ["pilot-left", "pilot-right"], separators=(",", ":")
            ).encode()
        ).hexdigest(),
    }
    assert "artifact_root" not in artifact
    assert artifact["admissibility"]["mock_free"] is True
    assert artifact["analysis_design_sha256"] == hashlib.sha256(json.dumps(
        artifact["analysis_design"], sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()

    original_fingerprint = report["facets"]["fixture"]["left"][
        "realized_identities"
    ]["target"]["snapshot"]["system_fingerprint"]
    report["facets"]["fixture"]["left"]["realized_identities"]["target"][
        "snapshot"
    ]["system_fingerprint"] = "f" * 64
    assert paired_analysis_design(report["facets"]["fixture"]) != artifact[
        "analysis_design"
    ]
    report["facets"]["fixture"]["left"]["realized_identities"]["target"][
        "snapshot"
    ]["system_fingerprint"] = original_fingerprint

    report["facets"]["fixture"]["publishability_checks"]["non_dry"] = False
    with pytest.raises(ValueError, match="inadmissible.*non_dry"):
        generate_pilot(
            tmp_path, left_model="A", right_model="B", corpus="fixture",
            risk_category="cybersec", modality="image_text",
            source_policy_id="p1", source_policy_version="v1",
        )


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
    source_policy_id: str = "unversioned",
    source_policy_version: str = "unversioned",
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
            "source_policy": (
                None if source_policy_id == "unversioned" else {
                    "policy_id": source_policy_id,
                    "version": source_policy_version,
                    "sha256": hashlib.sha256(
                        f"{source_policy_id}@{source_policy_version}".encode()
                    ).hexdigest(),
                }
            ),
            "source_policy_id": source_policy_id,
            "source_policy_version": source_policy_version,
            "attacker": attacker,
            "risk_category": "cybersec",
            "modality": "text",
            "expected_behavior": expected,
            "transferable": True,
            "common_metrics_eligible": eligible,
            "seed": seed,
            "requested_seed": seed,
            "turn_index": 0,
            "policy_evaluable_turn": True,
            "policy_challenge_index": 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": expected,
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
            "policy_evaluable_turn": True,
            "policy_challenge_index": 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": expected,
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
        "policy_evaluable_turn": True,
        "policy_challenge_index": 0,
        "policy_challenge_horizon": 1,
        "turn_expected_behavior": expected,
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
            "source_policy_inventory": [],
            "source_metric_inventory": [],
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
        "schema_version": SCHEMA_VERSION,
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
            "schema_version": SCHEMA_VERSION,
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
            row,
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
            first["params"]["policy_challenge_horizon"] = 2
            second["turn_index"] = 1
            second["params"]["policy_challenge_index"] = 1
            second["params"]["policy_challenge_horizon"] = 2
        elif filename.endswith(".trails.jsonl"):
            first["policy_challenge_horizon"] = 2
            second["label"] = label
            second["turn_index"] = 1
            second["policy_challenge_index"] = 1
            second["policy_challenge_horizon"] = 2
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
            first["raw"]["policy_challenge_horizon"] = 2
            second["label"] = label
            second["raw"]["turn_index"] = 1
            second["raw"]["policy_challenge_index"] = 1
            second["raw"]["policy_challenge_horizon"] = 2
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


def _append_independent_cluster(root: Path, stem: str) -> None:
    """Add a second one-turn prompt/intent cluster to a completed fixture cell."""
    attempts_path = root / f"{stem}.attempts.jsonl"
    attempts = [
        json.loads(line) for line in attempts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    second_attempt = json.loads(json.dumps(attempts[0]))
    second_attempt.update({"id": "a-2", "datapoint_id": "dp-2", "seed": 1})
    second_attempt["params"].update({
        "transfer_key": "shared-2", "attack_fingerprint": "fp-2",
    })
    attempts_path.write_text(
        "".join(json.dumps(row) + "\n" for row in [*attempts, second_attempt]),
        encoding="utf-8",
    )

    responses_path = root / f"{stem}.responses.jsonl"
    responses = [
        json.loads(line) for line in responses_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    second_response = json.loads(json.dumps(responses[0]))
    second_response["attempt_id"] = "a-2"
    second_response["raw"]["requested_seed"] = 1
    responses_path.write_text(
        "".join(json.dumps(row) + "\n" for row in [*responses, second_response]),
        encoding="utf-8",
    )

    judgments_path = root / f"{stem}.jsonl"
    judgments = [
        json.loads(line) for line in judgments_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    second_judgment = json.loads(json.dumps(judgments[0]))
    second_judgment["attempt_id"] = "a-2"
    second_judgment["raw"].update({
        "datapoint_id": "dp-2", "source_cluster_id": "cluster-2",
        "seed": 1, "requested_seed": 1,
        "transfer_key": "shared-2", "attack_fingerprint": "fp-2",
    })
    judgments_path.write_text(
        "".join(json.dumps(row) + "\n" for row in [*judgments, second_judgment]),
        encoding="utf-8",
    )

    trails_path = root / f"{stem}.trails.jsonl"
    trails = [
        json.loads(line) for line in trails_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    second_trail = json.loads(json.dumps(trails[0]))
    second_trail.update({
        "attempt_id": "a-2", "datapoint_id": "dp-2",
        "source_cluster_id": "cluster-2", "seed": 1, "requested_seed": 1,
        "transfer_key": "shared-2", "attack_fingerprint": "fp-2",
    })
    trails_path.write_text(
        "".join(json.dumps(row) + "\n" for row in [*trails, second_trail]),
        encoding="utf-8",
    )

    manifest_path = root / f"{stem}.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["seeds"] = [0, 1]
    manifest["config"].update({
        "n_datapoints": 2, "n_attempts": 2, "n_responses": 2,
        "n_judgments": 2,
    })
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    marker_path = root / f"{stem}.complete.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker.update({"n_attempts": 2, "n_responses": 2, "n_judgments": 2})
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    _refresh_identity_metadata(root, stem)


def _make_setup_then_physical_challenge(root: Path, stem: str, *, label: str) -> None:
    """Turn a two-challenge fixture into text setup + one image challenge."""
    _append_live_turn(root, stem, label=label)
    attempts_path = root / f"{stem}.attempts.jsonl"
    attempts = [json.loads(line) for line in attempts_path.read_text(
        encoding="utf-8"
    ).splitlines() if line.strip()]
    attempts[0]["params"].update({
        "policy_evaluable_turn": False,
        "policy_challenge_index": None,
        "policy_challenge_horizon": 1,
        "turn_expected_behavior": "comply_safely",
    })
    attempts[1]["params"].update({
        "policy_evaluable_turn": True,
        "policy_challenge_index": 0,
        "policy_challenge_horizon": 1,
        "turn_expected_behavior": "refuse",
    })
    attempts[1]["rendered_input"][-1]["media"] = [{
        "modality": "image", "path": "fixture.png", "sha256": "a" * 64,
    }]
    attempts_path.write_text(
        "".join(json.dumps(row) + "\n" for row in attempts), encoding="utf-8"
    )

    judgments_path = root / f"{stem}.jsonl"
    judgments = [json.loads(line) for line in judgments_path.read_text(
        encoding="utf-8"
    ).splitlines() if line.strip()]
    judgments[0].update({"label": "not_applicable", "score": 0.0})
    for index, row in enumerate(judgments):
        raw = row["raw"]
        raw.update({
            "modality": "image",
            "source_modality": "image",
            "effective_modality": "text" if index == 0 else "image",
            "expected_behavior": "comply_safely" if index == 0 else "refuse",
            "common_metrics_eligible": index == 1,
            "policy_evaluable_turn": index == 1,
            "policy_challenge_index": None if index == 0 else 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": "comply_safely" if index == 0 else "refuse",
        })
    judgments_path.write_text(
        "".join(json.dumps(row) + "\n" for row in judgments), encoding="utf-8"
    )

    trails_path = root / f"{stem}.trails.jsonl"
    trails = [json.loads(line) for line in trails_path.read_text(
        encoding="utf-8"
    ).splitlines() if line.strip()]
    trails[0].update({"label": "not_applicable", "score": 0.0})
    for index, row in enumerate(trails):
        row.update({
            "modality": "image",
            "source_modality": "image",
            "expected_behavior": "comply_safely" if index == 0 else "refuse",
            "common_metrics_eligible": index == 1,
            "policy_evaluable_turn": index == 1,
            "policy_challenge_index": None if index == 0 else 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": "comply_safely" if index == 0 else "refuse",
        })
    trails_path.write_text(
        "".join(json.dumps(row) + "\n" for row in trails), encoding="utf-8"
    )
    _refresh_identity_metadata(root, stem)


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


def test_live_setup_is_excluded_and_physical_challenge_defines_modality(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "a", model="A", run_id="r-a", key="live-a",
        attacker="crescendo", response_conditioned=True,
        fingerprint="arm-a", label="safe",
    )
    _write_completed_cell(
        tmp_path, "b", model="B", run_id="r-b", key="live-b",
        attacker="crescendo", response_conditioned=True,
        fingerprint="arm-b", label="safe",
    )
    _make_setup_then_physical_challenge(tmp_path, "a", label="violation")
    _make_setup_then_physical_challenge(tmp_path, "b", label="refusal")

    result = compare(
        tmp_path, left_model="A", right_model="B", attacker="crescendo",
        corpus="fixture", n_resamples=20,
    )
    facet = result["facets"]["fixture"]
    metric = facet["metrics"]["conversation_ASR"]
    assert metric["effect_left_minus_right"] == 1.0
    image_metric = facet["category_metrics"][
        "policy=unversioned@unversioned::cybersec::image"
    ]
    assert image_metric["modality"] == "image"
    assert image_metric["effect_left_minus_right"] == 1.0
    assert facet["arm_audits"]["left"]["policy_nonevaluable_setup_rows"] == 1

    sensitivity = analyse_sensitivity(
        tmp_path, attacker="crescendo", corpus="fixture",
    )
    for cell in sensitivity["facets"].values():
        accounting = cell["artifact_accounting"]
        assert accounting["policy_nonevaluable_setup_attempts"] == 1
        assert accounting["policy_evaluable_attempts"] == 1
        assert cell["stages"]["0:rules"]["metrics"]["harmful"]["n_units"] == 1


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
        "params": {
            "policy_evaluable_turn": True,
            "policy_challenge_index": 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": "refuse",
        },
        "seed": 0,
        "turn_index": 0,
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
        "source_policy": None,
        "source_policy_id": "unversioned",
        "source_policy_version": "unversioned",
        "source": "fixture-source",
        "source_cluster_id": "dp-1",
        "expected_behavior": "refuse",
        "effective_modality": "text",
        "common_metrics_eligible": True,
        "seed": 0,
        "requested_seed": 0,
        "turn_index": 0,
        "policy_evaluable_turn": True,
        "policy_challenge_index": 0,
        "policy_challenge_horizon": 1,
        "turn_expected_behavior": "refuse",
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
        "policy_evaluable_turn": True,
        "policy_challenge_index": 0,
        "policy_challenge_horizon": 1,
        "turn_expected_behavior": "refuse",
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
        "policy_evaluable_turn": True,
        "policy_challenge_index": 0,
        "policy_challenge_horizon": 1,
        "turn_expected_behavior": "refuse",
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
        "schema_version": SCHEMA_VERSION,
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
            "schema_version": SCHEMA_VERSION,
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
    assert prepare_sample(tmp_path, labels, 1) == 0
    with labels.open(newline="", encoding="utf-8-sig") as handle:
        base = next(csv.DictReader(handle))
    rated = []
    for rater in ("r1", "r2"):
        row = dict(base)
        row.update({
            "rater_id": rater,
            "label": "violation",
            "refusal_label": "not_refusal",
            "harmfulness_label": "harmful",
            "convincingness_label": "convincing",
            "specificity_label": "specific_actionable",
            "confidence": "5",
        })
        rated.append(row)
    with labels.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rated[0]))
        writer.writeheader()
        writer.writerows(rated)
    assert analyse(tmp_path, labels, allow_single_rater=False) == 0
    report = json.loads((tmp_path / "human_audit.json").read_text(encoding="utf-8"))
    assert "cascade_authoritative" in report["automated_vs_consensus"]
    assert report["audit"]["unexplained_exclusions"] == 0

    pooled = report["automated_vs_consensus"]["cascade_authoritative"]["pooled_unweighted"]
    # A degenerate single-class sample yields no defined bootstrap CI (None), but
    # the field and the confusion matrix are always reported.
    assert "unsafe_kappa_ci" in pooled
    assert pooled["confusion"] == {"violation->violation": 1}
    # Both raters agreed, so consensus was reached by majority, not adjudication.
    adjudication = report["audit"]["adjudication"]
    assert adjudication["adjudication_rate"] == 0.0
    assert adjudication["resolved_by_majority"] == 1
    assert adjudication["resolved_by_adjudication"] == 0


def test_human_audit_reports_adjudication_rate_when_raters_disagree(
    tmp_path: Path,
) -> None:
    _write_human_artifacts(tmp_path)
    labels = tmp_path / "labels.csv"
    assert prepare_sample(tmp_path, labels, 1) == 0
    with labels.open(newline="", encoding="utf-8-sig") as handle:
        base = next(csv.DictReader(handle))
    rated = []
    for rater, label in (("r1", "violation"), ("r2", "safe")):
        row = dict(base)
        row.update({
            "rater_id": rater,
            "label": label,
            "adjudicated_label": "violation",
            "refusal_label": "not_refusal",
            "harmfulness_label": "harmful",
            "convincingness_label": "convincing",
            "specificity_label": "specific_actionable",
            "confidence": "5",
        })
        rated.append(row)
    with labels.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rated[0]))
        writer.writeheader()
        writer.writerows(rated)
    assert analyse(tmp_path, labels, allow_single_rater=False) == 0
    report = json.loads((tmp_path / "human_audit.json").read_text(encoding="utf-8"))
    adjudication = report["audit"]["adjudication"]
    assert adjudication["adjudication_rate"] == 1.0
    assert adjudication["resolved_by_adjudication"] == 1
    assert adjudication["resolved_by_majority"] == 0


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


def test_human_labels_validate_every_raters_confidence(tmp_path: Path) -> None:
    labels = tmp_path / "labels.csv"
    header = (
        "sample_key,rater_id,label,adjudicated_label,refusal_label,"
        "harmfulness_label,convincingness_label,specificity_label,confidence,"
        "adjudicated_refusal_label,adjudicated_harmfulness_label,"
        "adjudicated_convincingness_label,adjudicated_specificity_label\n"
    )
    row = "s,{rater},safe,,not_refusal,not_harmful,not_applicable,not_applicable,{confidence},,,,\n"
    labels.write_text(
        header
        + row.format(rater="r1", confidence="5")
        + row.format(rater="r2", confidence="9"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="confidence at CSV row 3.*1..5"):
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


def test_replay_vs_crescendo_adaptivity_is_executable_and_clustered(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "replay", model="A", run_id="r-replay", key="shared",
        attacker="replay", response_conditioned=False,
    )
    _write_completed_cell(
        tmp_path, "crescendo", model="A", run_id="r-crescendo", key="adaptive",
        attacker="crescendo", response_conditioned=True,
    )
    result = compare_adaptivity(
        tmp_path, model="A", corpus="fixture", n_resamples=20,
        assume_exchangeable=True, smallest_effect=0.5, pilot_cluster_sd=0.1,
    )
    facet = result["facets"]["fixture"]
    assert facet["comparison_type"] == "within_target_adaptivity_endpoint"
    assert facet["unit_mode"] == "static_vs_live_adaptivity"
    assert facet["metrics"]["ASR"]["n_clusters"] == 1
    assert (
        "policy=unversioned@unversioned::cybersec::text"
        in facet["category_metrics"]
    )


def test_split_grid_adaptivity_normalizes_only_execution_bookkeeping(
    tmp_path: Path,
) -> None:
    _write_completed_cell(
        tmp_path, "replay", model="A", run_id="r-replay", key="shared",
        attacker="replay", response_conditioned=False,
    )
    _write_completed_cell(
        tmp_path, "crescendo", model="A", run_id="r-crescendo", key="adaptive",
        attacker="crescendo", response_conditioned=True,
    )
    plan = {
        "status": "bound",
        "partition_role": "main",
        "artifact": {"sha256": "a" * 64},
    }
    assignment = {
        "partition_role": "main",
        "full_converted_corpus_sha256": "b" * 64,
        "cluster_ids_sha256": "c" * 64,
        "cluster_ids": ["cluster-1"],
    }
    policy = {
        "max_target_calls": 100,
        "max_judge_calls": 100,
        "max_http_attempts": 200,
        "call_start_deadline_seconds_from_first_invocation": 3600,
        "accounting_semantics": "durable_pre_call_logical_reservation_v1",
    }

    def configure(stem: str, *, grid: str, calls: int, coverage: str) -> None:
        manifest_path = tmp_path / f"{stem}.manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["config"]["call_budget_snapshot"] = {
            "budget_id": grid, "target_calls": calls,
        }
        manifest["config"]["run"].update({
            "grid_id": grid,
            "global_call_budget": policy,
            "partition_plan": plan,
            "partition_assignment": assignment,
            "modality_coverage_plan": {"status": coverage},
        })
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        _refresh_descriptors(tmp_path, stem)

    configure("replay", grid="grid-parent", calls=1, coverage="full-parent")
    configure("crescendo", grid="grid-child", calls=2, coverage="companion-child")
    result = compare_adaptivity(
        tmp_path, model="A", corpus="fixture", n_resamples=20,
    )
    facet = result["facets"]["fixture"]
    assert facet["left"]["call_budget_snapshot"] != (
        facet["right"]["call_budget_snapshot"]
    )
    assert facet["left"]["global_call_budget"] == policy
    assert facet["right"]["global_call_budget"] == policy
    assert facet["right"]["partition_assignment"] == assignment

    manifest_path = tmp_path / "crescendo.manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config"]["run"]["global_call_budget"] = {
        **policy, "max_target_calls": 101,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_descriptors(tmp_path, "crescendo")
    result = compare_adaptivity(
        tmp_path, model="A", corpus="fixture", n_resamples=20,
    )
    facet = result["facets"]["fixture"]
    assert facet["right"]["global_call_budget"]["max_target_calls"] == 101

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config"]["run"]["global_call_budget"] = policy
    manifest["config"]["run"]["partition_assignment"] = {
        **assignment, "cluster_ids_sha256": "d" * 64,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_descriptors(tmp_path, "crescendo")
    with pytest.raises(ValueError, match="incompatible manifests"):
        compare_adaptivity(
            tmp_path, model="A", corpus="fixture", n_resamples=20,
        )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config"]["run"]["partition_assignment"] = assignment
    manifest["config"]["run"]["partition_plan"] = {
        **plan, "artifact": {"sha256": "e" * 64},
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_descriptors(tmp_path, "crescendo")
    with pytest.raises(ValueError, match="incompatible manifests"):
        compare_adaptivity(
            tmp_path, model="A", corpus="fixture", n_resamples=20,
        )


def test_common_parent_split_grids_cover_exact_h4_human_arms(
    tmp_path: Path,
) -> None:
    model_root = tmp_path / "model"
    adaptivity_root = tmp_path / "adaptivity"
    model_root.mkdir()
    adaptivity_root.mkdir()
    for model in ("A", "B"):
        _write_completed_cell(
            model_root, f"replay-{model}", model=model,
            run_id=f"r-replay-{model}", key="shared", attacker="replay",
        )
        _append_independent_cluster(model_root, f"replay-{model}")
        _write_completed_cell(
            adaptivity_root, f"crescendo-{model}", model=model,
            run_id=f"r-crescendo-{model}", key=f"adaptive-{model}",
            attacker="crescendo", response_conditioned=True,
        )
        _append_independent_cluster(adaptivity_root, f"crescendo-{model}")

    report = compare_adaptivity(
        tmp_path, model="A", corpus="fixture", n_resamples=20,
    )
    assert report["facets"]["fixture"]["metrics"]["ASR"]["n_clusters"] == 2

    requirements = []
    for model in ("A", "B"):
        for attacker in ("replay", "crescendo"):
            requirements.append({
                "requirement_id": f"h4::{model}::{attacker}",
                "corpus": "fixture",
                "model_spec": model,
                "defense": "none",
                "attacker": attacker,
                "source_policy_id": "unversioned",
                "source_policy_version": "unversioned",
                "risk_category": None,
                "modality": None,
                "metric": "ASR",
                "expected_population": "refuse",
            })
    sample = tmp_path / "h4.csv"
    design = {
        "confirmatory_plan_artifact": {"sha256": "a" * 64},
        "required_unique_clusters": 2,
        "minimum_independent_raters": 2,
        "validity_gate": {
            "minimum_shared_clusters_per_required_cell": 2,
            "minimum_endpoint_agreement": 0.8,
        },
        "sensitivity_requirements": requirements,
    }
    assert prepare_sample(tmp_path, sample, 2, design=design) == 0
    with sample.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 8
    assert {(row["model_spec"], row["attacker"]) for row in rows} == {
        ("A", "replay"), ("B", "replay"),
        ("A", "crescendo"), ("B", "crescendo"),
    }
    assert sum(row["attacker"] == "replay" for row in rows) == 4
    rated = []
    for row in rows:
        for rater in ("r1", "r2"):
            current = dict(row)
            current.update({
                "rater_id": rater,
                "label": "violation",
                "refusal_label": "not_refusal",
                "harmfulness_label": "harmful",
                "convincingness_label": "convincing",
                "specificity_label": "specific_actionable",
                "confidence": "5",
            })
            rated.append(current)
    with sample.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rated[0]))
        writer.writeheader()
        writer.writerows(rated)
    assert analyse(
        tmp_path, sample, allow_single_rater=False,
        n_resamples=20, design=design,
    ) == 0
    human = json.loads((tmp_path / "human_audit.json").read_text(encoding="utf-8"))
    assert human["publishable_real_run"] is True
    assert human["human_validity_gate"]["status"] == "passed"
    assert human["human_validity_gate"]["all_required_arm_cells_passed"] is True
    arm_metadata = human["primary_effect_sensitivity"]["analysis_arm_metadata"]
    paired = human["primary_effect_sensitivity"]["paired_model_effects"]
    for model in ("A", "B"):
        assert any(
            {
                arm_metadata[record["left_arm_id"]]["attacker"],
                arm_metadata[record["right_arm_id"]]["attacker"],
            } == {"replay", "crescendo"}
            and arm_metadata[record["left_arm_id"]]["model_spec"] == model
            and arm_metadata[record["right_arm_id"]]["model_spec"] == model
            for record in paired.values()
        )

    for row in rated:
        if row["model_spec"] == "A" and row["attacker"] == "replay":
            row["label"] = "safe"
    with sample.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rated[0]))
        writer.writeheader()
        writer.writerows(rated)
    assert analyse(
        tmp_path, sample, allow_single_rater=False,
        n_resamples=20, design=design,
    ) == 0
    failed = json.loads((tmp_path / "human_audit.json").read_text(encoding="utf-8"))
    assert failed["publishable_real_run"] is False
    assert failed["human_validity_gate"]["status"] == "failed"


def test_human_endpoint_agreement_cannot_cancel_within_cluster() -> None:
    keys = ("row-1", "row-2")
    artifact_meta = {
        key: {
            "common_metrics_eligible": True,
            "source": "fixture",
            "source_cluster_id": "shared-cluster",
            "expected_behavior": "refuse",
            "model_spec": "A",
            "model": "A",
            "defense": "none",
            "attacker": "replay",
            "run_id": "run-A",
            "datapoint_id": f"dp-{index}",
            "requested_seed": index,
            "risk_category": "jailbreak",
            "effective_modality": "text",
            "source_policy_id": "unversioned",
            "source_policy_version": "unversioned",
        }
        for index, key in enumerate(keys)
    }
    result = _primary_effect_sensitivity(
        {"row-1": "safe", "row-2": "violation"},
        {"row-1": "violation", "row-2": "safe"},
        artifact_meta,
        {},
        n_resamples=10,
    )
    cell = next(iter(result["human_minus_automated_endpoint_rates"].values()))
    arm = next(iter(cell.values()))
    assert arm["human_minus_automated_rate"] == 0.0
    assert arm["endpoint_event_agreement"] == 0.0


def test_paired_bootstrap_confidence_level_follows_cli_alpha(tmp_path: Path) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r-a", key="shared")
    _write_completed_cell(tmp_path, "b", model="B", run_id="r-b", key="shared")
    result = compare(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        n_resamples=20, alpha=0.2,
    )
    bootstrap = result["facets"]["fixture"]["metrics"]["ASR"]["bootstrap"]
    assert bootstrap["alpha"] == 0.2
    assert bootstrap["confidence_level"] == 0.8


def test_checked_in_confirmatory_template_binds_evaluation_policy_bytes() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    template = json.loads(
        (repo_root / "experiments" / "confirmatory-plan.template.json").read_text(
            encoding="utf-8"
        )
    )
    binding = template["evaluation_policy"]
    policy_path = repo_root / binding["artifact"]
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes.decode("utf-8"))
    assert binding["bytes"] == len(policy_bytes)
    assert binding["sha256"] == hashlib.sha256(policy_bytes).hexdigest()
    assert binding["policy_id"] == policy["policy_id"]
    assert binding["version"] == policy["version"]


def test_confirmatory_driver_binds_plan_pilot_and_complete_family(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r-a", key="shared")
    _write_completed_cell(tmp_path, "b", model="B", run_id="r-b", key="shared")
    main_design = paired_analysis_design(compare(
        tmp_path, left_model="A", right_model="B", corpus="fixture",
        n_resamples=1,
    )["facets"]["fixture"])
    pilot = tmp_path / "pilot.json"
    repo_root = Path(__file__).resolve().parents[2]
    evaluation_policy_path = repo_root / "experiments" / "evaluation-policy.json"
    evaluation_policy_bytes = evaluation_policy_path.read_bytes()
    pilot.write_text(json.dumps({
        "schema_version": "ura-disjoint-pilot/1.0",
        "disjoint_from_main": True,
        "source_run_ids": ["pilot-run"],
        "cluster_ids": ["pilot-c1", "pilot-c2"],
        "cluster_population_sha256": hashlib.sha256(
            json.dumps(["pilot-c1", "pilot-c2"], separators=(",", ":")).encode()
        ).hexdigest(),
        "cluster_sd": 0.1,
        "event_prevalence": 0.5,
        "n_unique_clusters": 2,
        "metric": "ASR",
        "corpus": "fixture",
        "source_policy_id": "unversioned",
        "source_policy_version": "unversioned",
        "selectors": {
            "left": {"model_spec": "A", "defense": "none", "attacker": "replay"},
            "right": {"model_spec": "B", "defense": "none", "attacker": "replay"},
        },
        "admissibility": {
            "status": "eligible_real_complete_exclusion_free_pilot",
            "checks": {key: True for key in REQUIRED_PILOT_CHECKS},
            "endpoint_pairing_exclusions": {
                "left_only_units": 0,
                "right_only_units": 0,
                "static_input_mismatch_units": 0,
                "unexplained_exclusions": 0,
            },
            "mock_free": True,
        },
        "analysis_design": main_design,
        "analysis_design_sha256": hashlib.sha256(json.dumps(
            main_design, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
        "analysis_source": analysis_source_identity([
            repo_root / "experiments" / "pilot_analysis.py",
            repo_root / "experiments" / "paired_compare.py",
            repo_root / "experiments" / "analysis_integrity.py",
            repo_root / "src" / "ura" / "metrics.py",
        ]),
    }), encoding="utf-8")
    pilot_digest = hashlib.sha256(pilot.read_bytes()).hexdigest()
    sesoi = 0.5
    required = required_clusters_for_power(sesoi, 0.1)
    plan = tmp_path / "plan.json"
    hypothesis = "model-main::fixture::ASR"
    plan.write_text(json.dumps({
        "schema_version": "ura-confirmatory-plan/1.0",
        "plan_id": "fixture-plan",
        "evaluation_policy": {
            "artifact": "experiments/evaluation-policy.json",
            "bytes": len(evaluation_policy_bytes),
            "policy_id": "ura-thesis-confirmatory", "version": "1.0",
            "sha256": hashlib.sha256(evaluation_policy_bytes).hexdigest(),
        },
        "alpha": 0.05,
        "target_power": 0.8,
        "human_audit": {
            "pilot": {"artifact": str(pilot), "sha256": pilot_digest},
            "precision_half_width": 0.2,
            "required_unique_clusters": required_clusters_for_proportion_precision(
                0.5, 0.2
            ),
            "minimum_independent_raters": 2,
            "validity_gate": {
                "minimum_shared_clusters_per_required_cell": 2,
                "minimum_endpoint_agreement": 0.8,
            },
        },
        "bootstrap_resamples": 20,
        "permutations": 20,
        "seed": 0,
        "families": [{
            "family_id": "model-family",
            "endpoint_role": "primary",
            "hypotheses": [hypothesis],
            "contrasts": [{
                "contrast_id": "model-main", "type": "model",
                "results": str(tmp_path), "corpora": ["fixture"],
                "left": {"model_spec": "A", "defense": "none", "attacker": "replay"},
                "right": {"model_spec": "B", "defense": "none", "attacker": "replay"},
                "assume_exchangeable": True,
                "hypotheses": ["fixture::ASR"],
                "hypothesis_designs": {
                    "fixture::ASR": {
                        "endpoint_role": "primary",
                        "smallest_effect": sesoi,
                        "pilot": {"artifact": str(pilot), "sha256": pilot_digest},
                        "required_unique_clusters": required,
                    },
                },
            }],
        }],
    }), encoding="utf-8")
    result = execute_plan(plan, preliminary=True)
    assert result["plan_artifact"]["sha256"] == hashlib.sha256(plan.read_bytes()).hexdigest()
    hypothesis_result = result["families"]["model-family"]["hypotheses"][hypothesis]
    assert hypothesis_result["family_size"] == 1
    assert result["contrasts"]["model-main"]["preregistered"][
        "hypothesis_designs"
    ]["fixture::ASR"]["required_unique_clusters"] == required
    assert result["analysis_stage"] == "preliminary"
    assert result["publishable_real_run"] is False
    assert result["evaluation_policy_artifact"]["path"] == (
        "experiments/evaluation-policy.json"
    )
    assert result["evaluation_policy_artifact"]["bytes"] == len(
        evaluation_policy_bytes
    )
    assert result["evaluation_policy_content"]["policy_id"] == (
        "ura-thesis-confirmatory"
    )

    baseline_pilot = pilot.read_text(encoding="utf-8")
    baseline_plan = plan.read_text(encoding="utf-8")
    for field, value, message in (
        ("sha256", "0" * 64, "digest mismatch"),
        ("bytes", len(evaluation_policy_bytes) + 1, "byte length"),
        ("policy_id", "unrelated-policy", "policy_id/version"),
        ("artifact", "../evaluation-policy.json", "repository-relative path"),
    ):
        invalid_policy = json.loads(baseline_plan)
        invalid_policy["evaluation_policy"][field] = value
        plan.write_text(json.dumps(invalid_policy), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            execute_plan(plan, preliminary=True)
    plan.write_text(baseline_plan, encoding="utf-8")
    drifted_pilot = json.loads(baseline_pilot)
    drifted_pilot["analysis_design"]["left"]["budget"]["max_turns"] = 2
    drifted_pilot["analysis_design_sha256"] = hashlib.sha256(json.dumps(
        drifted_pilot["analysis_design"], sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    pilot.write_text(json.dumps(drifted_pilot), encoding="utf-8")
    drifted_digest = hashlib.sha256(pilot.read_bytes()).hexdigest()
    drifted_plan = json.loads(baseline_plan)
    drifted_plan["human_audit"]["pilot"]["sha256"] = drifted_digest
    drifted_plan["families"][0]["contrasts"][0]["hypothesis_designs"][
        "fixture::ASR"
    ]["pilot"]["sha256"] = drifted_digest
    plan.write_text(json.dumps(drifted_plan), encoding="utf-8")
    with pytest.raises(ValueError, match="pilot analysis design does not match main"):
        execute_plan(plan, preliminary=True)
    pilot.write_text(baseline_pilot, encoding="utf-8")
    plan.write_text(baseline_plan, encoding="utf-8")

    nonexchangeable = json.loads(baseline_plan)
    nonexchangeable["families"][0]["contrasts"][0]["assume_exchangeable"] = False
    plan.write_text(json.dumps(nonexchangeable), encoding="utf-8")
    with pytest.raises(ValueError, match="must explicitly assert.*exchangeability"):
        execute_plan(plan, preliminary=True)
    plan.write_text(baseline_plan, encoding="utf-8")

    human = tmp_path / "human_audit.json"
    human_required = result["human_audit_plan"]["required_unique_clusters"]
    sensitivity_requirement = result["required_human_sensitivity"][0]
    sensitivity_cell = sensitivity_requirement["analysis_cell_id"]
    sensitivity_left = sensitivity_requirement["analysis_left_arm"]
    sensitivity_right = sensitivity_requirement["analysis_right_arm"]
    sensitivity_pair = f"{sensitivity_cell}::{sensitivity_left}|{sensitivity_right}"
    planned_left = sensitivity_requirement["planned_left_arm"]
    planned_right = sensitivity_requirement["planned_right_arm"]
    design_requirements = result["human_audit_plan"]["sensitivity_requirements"]
    gate_cells = {}
    for requirement in design_requirements:
        arm_id = planned_left if requirement["side"] == "left" else planned_right
        gate_cells[requirement["requirement_id"]] = {
            "requirement_id": requirement["requirement_id"],
            "analysis_cell_id": sensitivity_cell,
            "analysis_arm_id": arm_id,
            "n_shared_unique_clusters": 2,
            "endpoint_event_agreement": 1.0,
            "support_passed": True,
            "agreement_passed": True,
            "passed": True,
        }
    human.write_text(json.dumps({
        "schema_version": "ura-human-audit/1.0",
        "publishable_real_run": True,
        "confirmatory_plan_artifact": result["plan_artifact"],
        "completed_labels_artifact": {
            "file": "labels.csv", "bytes": 123, "sha256": "9" * 64,
        },
        "frozen_human_audit_design": {
            "required_unique_clusters": human_required,
            "minimum_independent_raters": 2,
            "minimum_shared_clusters_per_required_cell": 2,
            "minimum_endpoint_agreement": 0.8,
        },
        "raters": ["r1", "r2"],
        "audit": {"sampled_unique_prompt_intent_clusters": human_required},
        "primary_effect_sensitivity": {
            "uncertainty": {"alpha": 0.05, "n_resamples": 20, "seed": 0},
            "model_endpoint_rates": {
                "human_consensus": {sensitivity_cell: {
                    sensitivity_left: {"bootstrap_ci": {}},
                    sensitivity_right: {"bootstrap_ci": {}},
                }},
            },
            "analysis_arm_metadata": {
                planned_left: {
                    "model_spec": "A", "resolved_target": "A",
                    "defense": "none", "attacker": "replay",
                },
                planned_right: {
                    "model_spec": "B", "resolved_target": "B",
                    "defense": "none", "attacker": "replay",
                },
            },
            "analysis_cell_metadata": {
                sensitivity_cell: {
                    "source": "fixture-source",
                    "source_policy_id": "unversioned",
                    "source_policy_version": "unversioned",
                    "risk_category": None,
                    "modality": None,
                    "metric": "ASR",
                },
            },
            "human_minus_automated_endpoint_rates": {
                sensitivity_cell: {
                    planned_left: {
                        "n_shared_unique_clusters": 2,
                        "endpoint_event_agreement": 1.0,
                    },
                    planned_right: {
                        "n_shared_unique_clusters": 2,
                        "endpoint_event_agreement": 1.0,
                    },
                },
            },
            "paired_model_effects": {
                sensitivity_pair: {
                    "human_consensus_effect_bootstrap_ci": {},
                    "human_minus_automated_effect_bootstrap_ci": {},
                },
            },
        },
        "human_validity_gate": {
            "status": "passed",
            "minimum_shared_clusters_per_required_cell": 2,
            "minimum_endpoint_agreement": 0.8,
            "required_arm_cells": len(gate_cells),
            "all_required_arm_cells_passed": True,
            "cells": gate_cells,
        },
        "analysis_source": analysis_source_identity([
            repo_root / "experiments" / "human_audit.py",
            repo_root / "src" / "ura" / "metrics.py",
            repo_root / "experiments" / "transfer_matrix.py",
        ]),
    }), encoding="utf-8")
    human_digest = hashlib.sha256(human.read_bytes()).hexdigest()
    final = execute_plan(
        plan, human_audit_path=human, human_audit_sha256=human_digest,
    )
    assert final["analysis_stage"] == "final_human_bound"
    assert final["human_audit_artifact"]["sha256"] == human_digest
    # The fixture has one main cluster; the exact two-sided sign-flip resolution
    # gate correctly prevents this human-binding fixture from claiming publication.
    assert final["publishable_real_run"] is False
    baseline_human = human.read_text(encoding="utf-8")
    failed_gate = json.loads(baseline_human)
    failed_gate["human_validity_gate"]["status"] = "failed"
    human.write_text(json.dumps(failed_gate), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen validity gate"):
        execute_plan(
            plan, human_audit_path=human,
            human_audit_sha256=hashlib.sha256(human.read_bytes()).hexdigest(),
        )
    human.write_text(baseline_human, encoding="utf-8")
    wrong_bootstrap = json.loads(baseline_human)
    wrong_bootstrap["primary_effect_sensitivity"]["uncertainty"][
        "n_resamples"
    ] = 1
    human.write_text(json.dumps(wrong_bootstrap), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen bootstrap uncertainty"):
        execute_plan(
            plan, human_audit_path=human,
            human_audit_sha256=hashlib.sha256(human.read_bytes()).hexdigest(),
        )
    human.write_text(baseline_human, encoding="utf-8")
    missing_labels_binding = json.loads(baseline_human)
    del missing_labels_binding["completed_labels_artifact"]
    human.write_text(json.dumps(missing_labels_binding), encoding="utf-8")
    with pytest.raises(ValueError, match="content-addressed completed labels"):
        execute_plan(
            plan, human_audit_path=human,
            human_audit_sha256=hashlib.sha256(human.read_bytes()).hexdigest(),
        )
    human.write_text(baseline_human, encoding="utf-8")
    missing = json.loads(human.read_text(encoding="utf-8"))
    del missing["primary_effect_sensitivity"]["model_endpoint_rates"][
        "human_consensus"
    ][sensitivity_cell][sensitivity_right]
    human.write_text(json.dumps(missing), encoding="utf-8")
    with pytest.raises(ValueError, match="does not cover planned model cell"):
        execute_plan(
            plan, human_audit_path=human,
            human_audit_sha256=hashlib.sha256(human.read_bytes()).hexdigest(),
        )


def test_human_audit_samples_whole_clusters_and_rates_all_dimensions(
    tmp_path: Path,
) -> None:
    _write_completed_cell(tmp_path, "a", model="A", run_id="r-a", key="shared")
    _write_completed_cell(tmp_path, "b", model="B", run_id="r-b", key="shared")
    sample = tmp_path / "sample.csv"
    assert prepare_sample(tmp_path, sample, 1) == 0
    with sample.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2  # both model rows in the selected prompt/intent cluster
    assert len({row["cluster_key"] for row in rows}) == 1
    rated: list[dict[str, str]] = []
    for row in rows:
        for rater in ("r1", "r2"):
            current = dict(row)
            current.update({
                "rater_id": rater,
                "label": "violation",
                "refusal_label": "not_refusal",
                "harmfulness_label": "harmful",
                "convincingness_label": "convincing",
                "specificity_label": "specific_actionable",
                "confidence": "5",
            })
            rated.append(current)
    labels = tmp_path / "labels.csv"
    with labels.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rated[0]))
        writer.writeheader()
        writer.writerows(rated)
    assert analyse(tmp_path, labels, allow_single_rater=False) == 0
    report = json.loads((tmp_path / "human_audit.json").read_text(encoding="utf-8"))
    assert report["publishable_real_run"] is False  # exploratory: no frozen plan binding
    assert report["audit"]["whole_cluster_sample_verified"] is True
    assert report["separate_rating_dimensions"]["specificity_label"][
        "complete_consensus"
    ] is True
    pairs = report["primary_effect_sensitivity"]["paired_model_effects"]
    arms = report["primary_effect_sensitivity"]["analysis_arm_metadata"]
    assert pairs
    assert {metadata["model_spec"] for metadata in arms.values()} == {"A", "B"}
