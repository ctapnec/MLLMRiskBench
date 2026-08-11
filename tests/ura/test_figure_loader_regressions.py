from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
import pytest

from experiments import figure_results
from ura.data_models import SCHEMA_VERSION, Response
from ura.runner import CODE_VERSION, realized_identity_summary

_HASH_A = "a" * 64
_HASH_B = "b" * 64


def test_figure_point_and_bootstrap_equal_weight_prompt_clusters() -> None:
    paired = {}
    for index, (datapoint, left_value) in enumerate([
        ("repeated", 1.0),
        ("repeated", 1.0),
        ("repeated", 1.0),
        ("single", 0.0),
    ]):
        common = dict(
            corpus="fixture", source="source", datapoint_id=datapoint,
            seed=index, expected_behavior="refuse", risk_category="cybersec",
            declared_modality="text", effective_modality="text", eligible=True,
            attack_fingerprint=f"fp-{index}", transfer_key=f"key-{index}",
        )
        left = figure_results._Unit(value=left_value, **common)
        right = figure_results._Unit(value=0.0, **common)
        paired[left.key] = (left, right)
    left_value, right_value = figure_results._equal_cluster_arm_values(
        list(paired.values())
    )
    assert left_value - right_value == 0.5
    assert left_value == 0.5


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _descriptor(path: Path) -> dict[str, object]:
    return {
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
        "records": (
            1
            if path.name.endswith(".manifest.json")
            else sum(bool(line) for line in path.read_text(encoding="utf-8").splitlines())
        ),
    }


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _identity_metadata(
    responses: list[dict[str, Any]], trails: list[dict[str, Any]], judges: list[str],
) -> tuple[dict[str, Any], str]:
    summary = realized_identity_summary(
        [Response.model_validate(row, strict=True) for row in responses],
        trails,
        expected_judges=judges,
    )
    digest = _canonical_sha256(summary)
    return {
        "realized_identities": summary,
        "realized_identities_sha256": digest,
        "n_realized_target_identity_observations": len(responses),
        "n_realized_judge_identity_observations": len(trails),
        "n_realized_judge_identity_snapshots": len(judges),
    }, digest


def _cell(
    root: Path,
    *,
    stem: str,
    model_spec: str,
    corpus: str,
    defense: str = "none",
    attacker: str = "replay",
    run_id: str | None = None,
    datapoints: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    run_id = run_id or f"run-{hashlib.sha256(stem.encode()).hexdigest()[:24]}"
    resolved_model = f"resolved:{model_spec}"
    datapoints = datapoints or [{
        "id": "probe",
        "source": f"source-{corpus}",
        "risk": "cybersec",
        "modality": "text",
        "expected": "refuse",
        "label": "violation",
        "eligible": True,
        "seed": 0,
    }]
    paths = {
        "attempts": root / f"{stem}.attempts.jsonl",
        "responses": root / f"{stem}.responses.jsonl",
        "judgments": root / f"{stem}.jsonl",
        "trails": root / f"{stem}.trails.jsonl",
        "results": root / f"{stem}.results.jsonl",
        "manifest": root / f"{stem}.manifest.json",
    }
    attempts: list[dict[str, Any]] = []
    responses: list[dict[str, Any]] = []
    judgments: list[dict[str, Any]] = []
    trails: list[dict[str, Any]] = []
    seeds: set[int] = set()
    for index, datapoint in enumerate(datapoints):
        datapoint_id = datapoint["id"]
        seed = int(datapoint.get("seed", 0))
        seeds.add(seed)
        attempt_id = f"{datapoint_id}::{attacker}::s{seed}"
        fingerprint = _canonical_sha256([corpus, datapoint_id, seed, "prompt"])
        transfer_key = _canonical_sha256([corpus, datapoint_id, seed, attacker])
        effective_modality = datapoint.get("effective_modality", "text")
        media = (
            [{
                "modality": effective_modality,
                "path": f"fixture-{datapoint_id}.{effective_modality}",
                "sha256": _canonical_sha256([datapoint_id, effective_modality]),
            }]
            if effective_modality in {"image", "audio", "video"}
            else []
        )
        attempt = {
            "id": attempt_id,
            "datapoint_id": datapoint_id,
            "attacker": attacker,
            "strategy": "replay",
            "target": resolved_model,
            "turn_index": 0,
            "rendered_input": [{
                "role": "user",
                "content": f"prompt {datapoint_id}",
                "media": media,
            }],
            "seed": seed,
            "params": {
                "attack_fingerprint": fingerprint,
                "transfer_key": transfer_key,
                "transferable": True,
                "response_conditioned": False,
                "replayed_transcript": False,
                "attempt_media_hashes": {},
                "policy_evaluable_turn": True,
                "policy_challenge_index": 0,
                "policy_challenge_horizon": 1,
                "turn_expected_behavior": datapoint.get("expected", "refuse"),
            },
            "run_id": run_id,
        }
        response = {
            "attempt_id": attempt_id,
            "target": resolved_model,
            "output_turns": [{"role": "assistant", "content": "fixture response"}],
            "tool_trace": [],
            "latency_ms": 1.0,
            "tokens": {"input": 4, "output": 2},
            "raw": {
                "requested_seed": seed,
                "target_sampling_control": "provider_seed",
                "provider": "fixture-provider",
                "resolved_model": model_spec,
                "system_fingerprint": _canonical_sha256(model_spec),
            },
            "run_id": run_id,
        }
        expected = datapoint.get("expected", "refuse")
        raw = {
            "run_id": run_id,
            "model": resolved_model,
            "target": resolved_model,
            "attacker": attacker,
            "datapoint_id": datapoint_id,
            "source": datapoint.get("source", f"source-{corpus}"),
            "source_policy": None,
            "source_policy_id": "unversioned",
            "source_policy_version": "unversioned",
            "risk_category": datapoint.get("risk", "cybersec"),
            "risk": datapoint.get("risk", "cybersec"),
            "modality": datapoint.get("modality", "text"),
            "effective_modality": effective_modality,
            "expected_behavior": expected,
            "common_metrics_eligible": datapoint.get("eligible", True),
            "seed": seed,
            "requested_seed": seed,
            "turn_index": 0,
            "policy_evaluable_turn": True,
            "policy_challenge_index": 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": expected,
            "attack_fingerprint": fingerprint,
            "transfer_key": transfer_key,
            "transferable": True,
            "response_conditioned": False,
            "replayed_transcript": False,
            "target_sampling_control": "provider_seed",
            "cascade_stage": 0,
            "cascade_confident": True,
            "cascade_role": "authoritative",
            "cascade_policy": "first_confident_with_full_shadow_trail",
        }
        label = datapoint.get("label", "violation")
        score = 1.0 if label in {"violation", "over_refusal"} else 0.0
        judgment = {
            "attempt_id": attempt_id,
            "run_id": run_id,
            "judge": "rules",
            "label": label,
            "score": score,
            "raw": raw,
        }
        canonical_response = Response.model_validate(response).model_dump(mode="json")
        trail = {
            "attempt_id": attempt_id,
            "stage": 0,
            "judge": "rules",
            "label": label,
            "score": score,
            "confidence": 0.95,
            "parsed": None,
            "cascade_confident": True,
            "cascade_role": "authoritative",
            "cascade_policy": "first_confident_with_full_shadow_trail",
            "risk_category": raw["risk_category"],
            "modality": raw["modality"],
            "model": resolved_model,
            "datapoint_id": datapoint_id,
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
            "transfer_key": transfer_key,
            "transferable": True,
            "expected_behavior": expected,
            "common_metrics_eligible": raw["common_metrics_eligible"],
            "response_conditioned": False,
            "replayed_transcript": False,
            "target_sampling_control": "provider_seed",
            "response_sha256": _canonical_sha256(canonical_response),
        }
        attempts.append(attempt)
        responses.append(response)
        judgments.append(judgment)
        trails.append(trail)

    _write_jsonl(paths["attempts"], attempts)
    _write_jsonl(paths["responses"], responses)
    _write_jsonl(paths["judgments"], judgments)
    _write_jsonl(paths["trails"], trails)
    _write_jsonl(paths["results"], [{
        "id": f"result-{stem}",
        "run_id": run_id,
        "metric": "ASR",
        "value": 0.5,
        "ci_low": 0.0,
        "ci_high": 1.0,
        "n": len(datapoints),
        "group_by": {"model": resolved_model},
        "provenance": {"fixture": True},
    }])
    dataset_hash = _canonical_sha256([corpus, [item["id"] for item in datapoints]])
    identity_config, identity_digest = _identity_metadata(
        responses, trails, ["rules"]
    )
    base_component = {
        "class": "FixtureTarget",
        "name": resolved_model.removesuffix("+guard"),
    }
    target_component = (
        base_component
        if defense == "none"
        else {
            "class": "GuardedTarget",
            "name": resolved_model,
            "mode": defense,
            "base": base_component,
            "guard": {"class": "RuleJudge", "name": "rules"},
        }
    )
    manifest = {
        "run_id": run_id,
        "code_version": CODE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "seeds": sorted(seeds),
        "models": [resolved_model],
        "adapters": [attacker],
        "judges": ["rules"],
        "dataset_hashes": {
            "corpus": dataset_hash,
            f"source:source-{corpus}": _canonical_sha256([corpus, "source"]),
        },
        "started_at": "2026-08-10T00:00:00+00:00",
        "env": {"python": "3.12.0", "platform": "fixture"},
        "config": {
            "budget": {"max_queries": 1, "max_turns": 1, "seed": 0},
            "components": {
                "attacker": {"class": "ReplayAttacker", "name": attacker},
                "target": target_component,
                "judge_cascade": {"class": "JudgeCascade", "stages": ["rules"]},
            },
            "run": {
                "corpus": corpus,
                "limit": 0,
                "sample_seed": 0,
                "sampling_audit": {
                    "corpus": corpus,
                    "selected_ids": [item["id"] for item in datapoints],
                },
                "model_spec": model_spec,
                "local_identity": None,
                "attacker": attacker,
                "attacker_config": {},
                "judge_names": ["rules"],
                "judge_model": "rules-v1",
                "group_keys": ["model", "risk", "modality"],
                "defense": defense,
                "defense_guard": "rules",
                "quantization": "none",
                "dtype": "auto",
                "dry_run": False,
                "driver_source": {
                    "module": "run_matrix.py",
                    "sha256": _HASH_A,
                    "file_count": 1,
                },
            },
            "media_validation": {"media_refs": 0},
            "harness_source": {
                "algorithm": "sha256_relative_path_size_file_digest_v1",
                "sha256": _HASH_B,
                "file_count": 1,
                "bytes": 100,
            },
            "n_datapoints": len(datapoints),
            "n_attempts": len(attempts),
            "n_responses": len(responses),
            "n_judgments": len(judgments),
            "n_media_hashes": 0,
            "n_attempt_media_hashes": 0,
            "attempt_media_hashes": {},
            "realized_attempts_sha256": _canonical_sha256(attempts),
            **identity_config,
        },
    }
    paths["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    marker_path = root / f"{stem}.complete.json"
    marker = {
        "status": "complete",
        "format_version": 2,
        "run_id": run_id,
        "code_version": CODE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "n_attempts": len(attempts),
        "n_responses": len(responses),
        "n_judgments": len(judgments),
        "n_results": 1,
        "realized_identities_sha256": identity_digest,
        "artifacts": {name: _descriptor(path) for name, path in paths.items()},
    }
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    return {
        "corpus": corpus,
        "model_spec": model_spec,
        "target": resolved_model,
        "attacker": attacker,
        "run_id": run_id,
        "status": "complete",
        "completion_marker": marker_path.name,
        "defense": defense,
        "paths": paths,
        "marker": marker_path,
    }


def _grid(root: Path, *, name: str, cells: list[dict[str, Any]]) -> Path:
    models = sorted({cell["model_spec"] for cell in cells})
    corpora = sorted({cell["corpus"] for cell in cells})
    attackers = sorted({cell["attacker"] for cell in cells})
    defenses = {cell["defense"] for cell in cells}
    assert len(defenses) == 1
    expected = len(models) * len(corpora) * len(attackers)
    assert len(cells) == expected
    grid_id = f"grid-{name}"
    path = root / f"{grid_id}.grid.json"
    path.write_text(json.dumps({
        "status": "complete",
        "grid_id": grid_id,
        "started_at": "2026-08-10T00:00:00+00:00",
        "finished_at": "2026-08-10T00:01:00+00:00",
        "request": {
            "models": models,
            "corpora": corpora,
            "attackers": attackers,
            "defense": next(iter(defenses)),
            "dry_run": False,
        },
        "requested_cells": expected,
        "accounted_cells": expected,
        "n_new_complete": expected,
        "n_existing_complete": 0,
        "n_errors": 0,
        "cells": [{key: cell[key] for key in (
            "corpus", "model_spec", "target", "attacker", "run_id", "status",
            "completion_marker",
        )} for cell in cells],
    }), encoding="utf-8")
    return path


def _refresh_marker(cell: dict[str, Any]) -> None:
    marker = json.loads(cell["marker"].read_text(encoding="utf-8"))
    marker["artifacts"] = {
        name: _descriptor(path) for name, path in cell["paths"].items()
    }
    cell["marker"].write_text(json.dumps(marker), encoding="utf-8")


def _refresh_identity_metadata(cell: dict[str, Any]) -> None:
    responses = [
        json.loads(line) for line in cell["paths"]["responses"]
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    trails = [
        json.loads(line) for line in cell["paths"]["trails"]
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    response_digests = {
        row["attempt_id"]: _canonical_sha256(
            Response.model_validate(row, strict=True).model_dump(mode="json")
        )
        for row in responses
    }
    for trail in trails:
        trail["response_sha256"] = response_digests[trail["attempt_id"]]
    _write_jsonl(cell["paths"]["trails"], trails)
    manifest = json.loads(
        cell["paths"]["manifest"].read_text(encoding="utf-8")
    )
    identity_config, identity_digest = _identity_metadata(
        responses, trails, manifest["judges"]
    )
    manifest["config"].update(identity_config)
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    marker = json.loads(cell["marker"].read_text(encoding="utf-8"))
    marker["realized_identities_sha256"] = identity_digest
    cell["marker"].write_text(json.dumps(marker), encoding="utf-8")
    _refresh_marker(cell)


def _paired_model_grid(root: Path, corpora: tuple[str, ...] = ("alpha",)) -> list[dict]:
    cells = [
        _cell(
            root,
            stem=f"{corpus}-{model}",
            model_spec=model,
            corpus=corpus,
            datapoints=[{
                "id": f"probe-{corpus}",
                "source": f"source-{corpus}",
                "risk": "cybersec" if corpus == "alpha" else "privacy",
                "modality": "text",
                "effective_modality": "text" if corpus == "alpha" else "image",
                "expected": "refuse",
                "label": "violation" if model == "left" else "safe",
                "eligible": True,
                "seed": 0,
            }],
        )
        for corpus in corpora
        for model in ("left", "right")
    ]
    _grid(root, name="models", cells=cells)
    return cells


def test_measured_loader_facets_multi_corpus_sampling_without_pooling(tmp_path: Path) -> None:
    _paired_model_grid(tmp_path, ("alpha", "beta"))
    result = figure_results.load_model_results(
        tmp_path,
        left_model="left",
        right_model="right",
        corpora=["alpha", "beta"],
        policy_label="declared-policy-v1",
        multiplicity_family="model-comparison",
        minimum_cell_n=1,
        n_resamples=20,
    )
    assert [point["corpus"] for point in result["overall"]] == ["alpha", "beta"]
    assert all(point["n_clusters"] == 1 for point in result["overall"])
    assert len(result["categories"]) == 2
    assert {point["modality"] for point in result["categories"]} == {"text", "image"}
    assert all(point["value"] == 1.0 for point in result["overall"])
    assert all("sampling_audit" in point["left_arm"] for point in result["overall"])


def test_policy_label_binds_to_single_judge_configuration() -> None:
    arm = {"judges": ["rules"], "judge_configuration": {"stages": ["rules"]}}
    binding = figure_results._bind_policy_label(
        [{"left_arm": arm, "right_arm": arm}], "declared-policy-v1"
    )
    assert binding["policy_label"] == "declared-policy-v1"
    assert binding["policy_fingerprint"]  # non-empty digest of the decision config
    assert binding["policy_defining_fields"]["judges"] == ["rules"]


def test_policy_fingerprint_excludes_the_contrasted_defense_axis() -> None:
    # A same-base defense contrast changes only `defense`; the judge/decision
    # configuration is identical, so both arms must share one policy fingerprint.
    judge = {"judges": ["rules"], "judge_configuration": {"stages": ["rules"]}}
    left = {**judge, "defense": "none"}
    right = {**judge, "defense": "guard-input"}
    binding = figure_results._bind_policy_label(
        [{"left_arm": left, "right_arm": right}], "policy"
    )
    assert binding["policy_defining_fields"]["judges"] == ["rules"]


def test_policy_label_binding_rejects_mixed_judge_configurations() -> None:
    arm_a = {"judges": ["rules"], "judge_configuration": {"stages": ["rules"]}}
    arm_b = {
        "judges": ["rules", "llm"],
        "judge_configuration": {"stages": ["rules", "llm"]},
    }
    points = [
        {"left_arm": arm_a, "right_arm": arm_a},
        {"left_arm": arm_b, "right_arm": arm_b},
    ]
    with pytest.raises(ValueError, match="mix judge/decision configurations"):
        figure_results._bind_policy_label(points, "declared-policy-v1")


def test_loader_requires_grid_allowlist_and_rejects_orphan_marker(tmp_path: Path) -> None:
    _paired_model_grid(tmp_path)
    orphan = _cell(
        tmp_path, stem="orphan", model_spec="other", corpus="alpha", run_id="run-orphan"
    )
    assert orphan["marker"].is_file()
    with pytest.raises(ValueError, match="allowlist mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_ambiguous_grid_accounted_rerun(tmp_path: Path) -> None:
    _paired_model_grid(tmp_path)
    reruns = [
        _cell(
            tmp_path,
            stem=f"rerun-{model}",
            model_spec=model,
            corpus="alpha",
            run_id=f"run-rerun-{model}",
        )
        for model in ("left", "right")
    ]
    _grid(tmp_path, name="rerun", cells=reruns)
    with pytest.raises(ValueError, match="exactly one grid-accounted cell"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_pydantic_validates_every_attempt(tmp_path: Path) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    rows = [json.loads(line) for line in cell["paths"]["attempts"].read_text().splitlines()]
    rows[0].pop("rendered_input")
    _write_jsonl(cell["paths"]["attempts"], rows)
    _refresh_marker(cell)
    with pytest.raises(ValueError, match="schema-invalid Attempt"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_coercible_but_noncanonical_attempt_types(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    rows = [json.loads(line) for line in cell["paths"]["attempts"].read_text().splitlines()]
    rows[0]["turn_index"] = "0"
    _write_jsonl(cell["paths"]["attempts"], rows)
    _refresh_marker(cell)
    with pytest.raises(ValueError, match="schema-invalid Attempt"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_stale_runner_version(tmp_path: Path) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    manifest = json.loads(cell["paths"]["manifest"].read_text(encoding="utf-8"))
    manifest["code_version"] = "ura-runner/1.8"
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    marker = json.loads(cell["marker"].read_text(encoding="utf-8"))
    marker["code_version"] = "ura-runner/1.8"
    cell["marker"].write_text(json.dumps(marker), encoding="utf-8")
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="current runner/schema"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_marker_counts_even_when_descriptors_are_fresh(tmp_path: Path) -> None:
    cells = _paired_model_grid(tmp_path)
    marker = json.loads(cells[0]["marker"].read_text(encoding="utf-8"))
    marker["n_attempts"] = 2
    cells[0]["marker"].write_text(json.dumps(marker), encoding="utf-8")
    with pytest.raises(ValueError, match="n_attempts mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_recomputes_and_rejects_rehashed_identity_inventory_tampering(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    manifest = json.loads(cell["paths"]["manifest"].read_text(encoding="utf-8"))
    identities = manifest["config"]["realized_identities"]
    identities["target"]["snapshot"]["system_fingerprint"] = "invented"
    invented_digest = _canonical_sha256(identities)
    manifest["config"]["realized_identities_sha256"] = invented_digest
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    marker = json.loads(cell["marker"].read_text(encoding="utf-8"))
    marker["realized_identities_sha256"] = invented_digest
    cell["marker"].write_text(json.dumps(marker), encoding="utf-8")
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="realized identity inventory mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_trail_response_join_tampering(tmp_path: Path) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    rows = [json.loads(line) for line in cell["paths"]["trails"].read_text().splitlines()]
    rows[0]["response_sha256"] = "0" * 64
    _write_jsonl(cell["paths"]["trails"], rows)
    _refresh_marker(cell)
    with pytest.raises(ValueError, match="response_sha256 mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_defense_loader_is_same_base_paired_and_reports_both_populations(
    tmp_path: Path,
) -> None:
    datapoints = [
        {
            "id": "harmful",
            "source": "source-utility",
            "risk": "cybersec",
            "expected": "refuse",
            "label": "violation",
        },
        {
            "id": "benign",
            "source": "source-utility",
            "risk": "legality",
            "expected": "safe_answer",
            "label": "safe",
        },
    ]
    baseline = _cell(
        tmp_path,
        stem="base-none",
        model_spec="base",
        corpus="utility",
        defense="none",
        datapoints=datapoints,
    )
    defended_points = [dict(item) for item in datapoints]
    defended_points[0]["label"] = "refusal"
    defended_points[1]["label"] = "over_refusal"
    defended = _cell(
        tmp_path,
        stem="base-both",
        model_spec="base",
        corpus="utility",
        defense="both",
        datapoints=defended_points,
    )
    _grid(tmp_path, name="baseline", cells=[baseline])
    _grid(tmp_path, name="defended", cells=[defended])
    points = figure_results.load_defense_results(
        tmp_path,
        model="base",
        left_defense="none",
        right_defense="both",
        corpora=["utility"],
        policy_label="policy",
        multiplicity_family="H3",
        minimum_cell_n=1,
        n_resamples=20,
    )
    assert {point["metric"] for point in points} == {"ASR", "FRR"}
    values = {point["metric"]: point["value"] for point in points}
    assert values == {"ASR": 1.0, "FRR": -1.0}
    assert all(point["comparison_type"] == "within_target_defense_intervention" for point in points)
    assert all(point["causal_effect_established"] is False for point in points)
    assert all(
        point["defense_identity_qualification"]["status"] == "observed_equal"
        for point in points
    )


def test_defense_figure_marks_all_input_blocked_identity_as_unobserved(
    tmp_path: Path,
) -> None:
    baseline = _cell(
        tmp_path, stem="base-none", model_spec="base", corpus="utility",
        defense="none",
    )
    defended = _cell(
        tmp_path, stem="base-input", model_spec="base", corpus="utility",
        defense="input",
    )
    response_rows = [
        json.loads(line) for line in defended["paths"]["responses"]
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    for response in response_rows:
        for field in ("provider", "resolved_model", "system_fingerprint"):
            response["raw"].pop(field)
        response["raw"].update({
            "defense": "blocked",
            "stage": "input",
            "target_sampling_control": "not_queried",
        })
    _write_jsonl(defended["paths"]["responses"], response_rows)
    judgment_rows = [
        json.loads(line) for line in defended["paths"]["judgments"]
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    for judgment in judgment_rows:
        judgment["raw"]["target_sampling_control"] = "not_queried"
    _write_jsonl(defended["paths"]["judgments"], judgment_rows)
    trail_rows = [
        json.loads(line) for line in defended["paths"]["trails"]
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    for trail in trail_rows:
        trail["target_sampling_control"] = "not_queried"
    _write_jsonl(defended["paths"]["trails"], trail_rows)
    _refresh_identity_metadata(defended)
    _grid(tmp_path, name="baseline", cells=[baseline])
    _grid(tmp_path, name="defended", cells=[defended])

    points = figure_results.load_defense_results(
        tmp_path,
        model="base",
        left_defense="none",
        right_defense="input",
        corpora=["utility"],
        policy_label="policy",
        multiplicity_family="H3",
        minimum_cell_n=1,
        n_resamples=10,
    )
    assert all(
        point["defense_identity_qualification"]["status"]
        == "unobserved_planned_same_base_only"
        for point in points
    )
    assert all(
        point["defense_identity_qualification"][
            "realized_identity_equality_claimed"
        ] is False
        for point in points
    )


def test_underpowered_category_cell_is_explicitly_unestimated(tmp_path: Path) -> None:
    _paired_model_grid(tmp_path)
    result = figure_results.load_model_results(
        tmp_path,
        left_model="left",
        right_model="right",
        corpora=["alpha"],
        policy_label="policy",
        multiplicity_family="family",
        minimum_cell_n=2,
        n_resamples=10,
    )
    point = result["categories"][0]
    assert point["status"] == "not_estimable_underpowered"
    assert point["value"] is point["ci_low"] is point["ci_high"] is None
    assert point["n_pairs"] == point["n_clusters"] == 1


def _direct_metric(
    metric: str, *, source: str, policy_id: str | None = None,
    policy_version: str | None = None,
) -> dict[str, Any]:
    alias = "ASR" if metric == "ASR" else "FRR"
    return {
        "metric": metric,
        "metric_alias": alias,
        "population": (
            "harmful_expected_refusal" if metric == "ASR"
            else "benign_expected_answer"
        ),
        "risk_category": None,
        "modality": None,
        "source": source,
        "source_policy_id": policy_id,
        "source_policy_version": policy_version,
        "status": "estimated",
        "left_value": 0.75,
        "right_value": 0.25,
        "effect_left_minus_right": 0.5,
        "ci_low": 0.25,
        "ci_high": 0.75,
        "n_matched": 8,
        "n_clusters": 4,
        "pairing_audit": {
            "left_only_units": 0,
            "right_only_units": 0,
            "static_input_mismatch_units": 0,
            "unexplained_exclusions": 0,
        },
        "bootstrap": {"method": "fixture"},
        "missingness_sensitivity": {"status": "fixture"},
    }


def _direct_arm(run_id: str, model: str, attacker: str, corpus: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "model_spec": model,
        "resolved_target": model,
        "defense": "none",
        "attacker": attacker,
        "corpus": corpus,
        "judges": ["rules", "guardrail", "llm"],
        "judge_configuration": {"stages": ["rules", "guardrail", "llm"]},
    }


def _direct_facet(
    corpus: str, left_model: str, right_model: str, *, attacker: str = "replay",
) -> dict[str, Any]:
    kind = corpus.split("_", 1)[0]
    source = f"fixture-source-{kind}"
    harmful = _direct_metric(
        "ASR", source=source,
        policy_id=("strongreject:unsafe-assistance" if kind == "strongreject" else None),
        policy_version=("fixture-v1" if kind == "strongreject" else None),
    )
    benign = _direct_metric("over_refusal_rate", source=source)
    policy_metrics: dict[str, Any] = {}
    if kind == "mmsafety":
        for name in figure_results.MM_SAFETYBENCH_POLICY_DESCRIPTORS:
            policy = figure_results.mm_safetybench_policy(name)
            policy_metrics[
                f"{figure_results.source_policy_token(policy.policy_id, policy.version)}::ASR"
            ] = _direct_metric(
                "ASR", source=source, policy_id=policy.policy_id,
                policy_version=policy.version,
            )
    if kind == "mossbench":
        policy = figure_results.mossbench_policy()
        policy_metrics[
            f"{figure_results.source_policy_token(policy.policy_id, policy.version)}::"
            "over_refusal_rate"
        ] = _direct_metric(
            "over_refusal_rate",
            source=source,
            policy_id=policy.policy_id,
            policy_version=policy.version,
        )
    return {
        "analysis_ready_real_run": True,
        "analysis_readiness_checks": {"integrity": True, "estimable": True},
        "unexplained_exclusions": 0,
        "comparison_type": (
            "within_target_adaptivity_endpoint"
            if attacker == "crescendo" else "cross_target_endpoint_noncausal"
        ),
        "left": _direct_arm(f"{corpus}-{left_model}-{attacker}", left_model, attacker, corpus),
        "right": _direct_arm(
            f"{corpus}-{right_model}-{attacker}", right_model, attacker, corpus,
        ),
        "metrics": {"ASR": harmful, "over_refusal_rate": benign},
        "policy_metrics": policy_metrics,
    }


def _write_direct_human_audit(
    path: Path, run_ids: list[str], *, completed_run_ids: list[str] | None = None,
    primary_effect_sensitivity: dict[str, Any] | None = None,
) -> str:
    artifact = {
        "schema_version": "ura-human-audit/1.1",
        "analysis_ready_real_run": True,
        "analysis_readiness": {
            "status": "complete_sample_conditional",
            "checks": {"multi_rater": True, "integrity": True},
            "population_validity_claimed": False,
        },
        "results_identity": {
            "completed_run_ids": sorted(completed_run_ids or run_ids),
            "labelled_run_ids": sorted(run_ids),
        },
        "analysis_source": {"fixture": True},
    }
    if primary_effect_sensitivity is not None:
        artifact["primary_effect_sensitivity"] = primary_effect_sensitivity
    path.write_text(json.dumps(artifact), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _direct_primary_sensitivity(
    left: str, right: str, *, strong: str, mm: str, moss: str,
) -> dict[str, Any]:
    arm_metadata: dict[str, Any] = {}
    cell_metadata: dict[str, Any] = {}
    human_rates: dict[str, Any] = {}
    paired: dict[str, Any] = {}

    def add_effect(
        *, source: str, policy_id: str, policy_version: str, metric: str,
        left_arm: dict[str, Any], right_arm: dict[str, Any], name: str,
    ) -> None:
        cell_id = figure_results.human_analysis_cell_id(
            left_arm["corpus"], source, policy_id, policy_version,
            None, None, metric,
        )
        cell_metadata[cell_id] = {
            "corpus": left_arm["corpus"],
            "source": source,
            "source_policy_id": policy_id,
            "source_policy_version": policy_version,
            "risk_category": None,
            "modality": None,
            "metric": metric,
        }
        arm_ids = []
        for arm in (left_arm, right_arm):
            arm_id = figure_results.human_analysis_arm_id(
                arm["model_spec"], arm["resolved_target"],
                arm["defense"], arm["attacker"],
            )
            arm_metadata[arm_id] = {
                "model_spec": arm["model_spec"],
                "resolved_target": arm["resolved_target"],
                "defense": arm["defense"],
                "attacker": arm["attacker"],
            }
            human_rates.setdefault(cell_id, {})[arm_id] = {
                "rate": 0.5, "n_unique_clusters": 1,
            }
            arm_ids.append(arm_id)
        paired[name] = {
            "analysis_cell_id": cell_id,
            "left_arm_id": arm_ids[0],
            "right_arm_id": arm_ids[1],
            "human_consensus_effect": 0.0,
            "n_shared_unique_clusters": 1,
        }

    replay = {
        corpus: _direct_facet(corpus, left, right)
        for corpus in (strong, mm, moss)
    }
    strong_policy = ("strongreject:unsafe-assistance", "fixture-v1")
    add_effect(
        source="fixture-source-strongreject", policy_id=strong_policy[0],
        policy_version=strong_policy[1], metric="ASR",
        left_arm=replay[strong]["left"], right_arm=replay[strong]["right"],
        name="strong-model",
    )
    for policy_name in figure_results.MM_SAFETYBENCH_POLICY_DESCRIPTORS:
        descriptor = figure_results.mm_safetybench_policy(policy_name)
        add_effect(
            source="fixture-source-mmsafety", policy_id=descriptor.policy_id,
            policy_version=descriptor.version, metric="ASR",
            left_arm=replay[mm]["left"], right_arm=replay[mm]["right"],
            name=f"mm-{policy_name}",
        )
    moss_policy = figure_results.mossbench_policy()
    add_effect(
        source="fixture-source-mossbench", policy_id=moss_policy.policy_id,
        policy_version=moss_policy.version, metric="FRR",
        left_arm=replay[moss]["left"], right_arm=replay[moss]["right"],
        name="moss",
    )
    for model in (left, right):
        add_effect(
            source="fixture-source-strongreject", policy_id=strong_policy[0],
            policy_version=strong_policy[1], metric="ASR",
            left_arm=_direct_arm(f"{strong}-{model}-replay", model, "replay", strong),
            right_arm=_direct_arm(
                f"{strong}-{model}-crescendo", model, "crescendo", strong,
            ),
            name=f"adaptive-{model}",
        )
    return {
        "analysis_arm_metadata": arm_metadata,
        "analysis_cell_metadata": cell_metadata,
        "model_endpoint_rates": {"human_consensus": human_rates},
        "paired_model_effects": paired,
    }


def test_direct_figure_loader_emits_exact_sample_conditional_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    left, right = "provider:left", "provider:right"
    replay_facets = {
        corpus: _direct_facet(corpus, left, right)
        for corpus in ("strongreject", "mmsafety", "mossbench")
    }

    def fake_compare(*args: Any, **kwargs: Any) -> dict[str, Any]:
        corpus = kwargs["corpus"]
        return {"facets": {corpus: replay_facets[corpus]}, "unavailable_facets": {}}

    def fake_adaptivity(*args: Any, model: str, **kwargs: Any) -> dict[str, Any]:
        facet = _direct_facet("strongreject", model, model, attacker="crescendo")
        facet["left"] = _direct_arm("strongreject-" + model + "-replay", model, "replay", "strongreject")
        return {"facets": {"strongreject": facet}, "unavailable_facets": {}}

    monkeypatch.setattr(figure_results, "compare", fake_compare)
    monkeypatch.setattr(figure_results, "compare_adaptivity", fake_adaptivity)
    monkeypatch.setattr(figure_results, "validate_analysis_source_identity", lambda value: value)
    run_ids = {
        arm["run_id"]
        for facet in replay_facets.values()
        for arm in (facet["left"], facet["right"])
    }
    for model in (left, right):
        run_ids.update({
            "strongreject-" + model + "-replay",
            "strongreject-" + model + "-crescendo",
        })
    audit = tmp_path / "human_audit.json"
    digest = _write_direct_human_audit(
        audit, sorted(run_ids),
        primary_effect_sensitivity=_direct_primary_sensitivity(
            left, right, strong="strongreject", mm="mmsafety", moss="mossbench",
        ),
    )

    result = figure_results.load_postrun_results(
        tmp_path,
        left_model=left,
        right_model=right,
        human_audit=audit,
        human_audit_sha256=digest,
        n_resamples=10,
    )

    assert result["illustrative"] is False
    assert result["analysis"]["status"] == "post_experiment_sample_conditional"
    assert result["analysis"]["population_validity_claimed"] is False
    figures = result["figures"]
    assert len(figures["fig-v-asr-by-model.png"]["points"]) == 1
    assert len(figures["fig-v-policy-proxies.png"]["points"]) == 7
    assert len(figures["fig-v-adaptivity.png"]["points"]) == 2
    assert [
        point["metric"] for point in figures["fig-v-policy-proxies.png"]["points"]
    ] == ["ASR"] * 6 + ["FRR"]
    assert all(
        point["status"] == "estimated_sample_conditional"
        for figure in figures.values() for point in figure["points"]
    )


def test_direct_figures_use_logical_aliases_and_audited_broad_cohort_subset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    left, right = "provider:left", "provider:right"
    aliases = {
        "strong": "strongreject_official",
        "mm": "mmsafety_official",
        "moss": "mossbench_official",
    }
    replay_facets = {
        corpus: _direct_facet(corpus, left, right) for corpus in aliases.values()
    }
    compared: list[str] = []

    def fake_compare(*args: Any, **kwargs: Any) -> dict[str, Any]:
        corpus = kwargs["corpus"]
        compared.append(corpus)
        return {"facets": {corpus: replay_facets[corpus]}, "unavailable_facets": {}}

    def fake_adaptivity(
        *args: Any, model: str, corpus: str, **kwargs: Any,
    ) -> dict[str, Any]:
        facet = _direct_facet(corpus, model, model, attacker="crescendo")
        facet["left"] = _direct_arm(
            f"{corpus}-{model}-replay", model, "replay", corpus,
        )
        return {"facets": {corpus: facet}, "unavailable_facets": {}}

    monkeypatch.setattr(figure_results, "compare", fake_compare)
    monkeypatch.setattr(figure_results, "compare_adaptivity", fake_adaptivity)
    monkeypatch.setattr(
        figure_results, "validate_analysis_source_identity", lambda value: value,
    )
    run_ids = {
        arm["run_id"]
        for facet in replay_facets.values()
        for arm in (facet["left"], facet["right"])
    }
    for model in (left, right):
        run_ids.update({
            f"{aliases['strong']}-{model}-replay",
            f"{aliases['strong']}-{model}-crescendo",
        })
    sensitivity = _direct_primary_sensitivity(
        left, right, strong=aliases["strong"], mm=aliases["mm"], moss=aliases["moss"],
    )
    audit = tmp_path / "human_audit.json"
    digest = _write_direct_human_audit(
        audit, sorted(run_ids),
        completed_run_ids=sorted({*run_ids, "unrelated-broad-run"}),
        primary_effect_sensitivity=sensitivity,
    )

    result = figure_results.load_postrun_results(
        tmp_path, left_model=left, right_model=right,
        human_audit=audit, human_audit_sha256=digest, n_resamples=10,
        strongreject_corpus=aliases["strong"],
        mmsafety_corpus=aliases["mm"], mossbench_corpus=aliases["moss"],
    )

    assert compared == [aliases["strong"], aliases["mm"], aliases["moss"]]
    assert result["analysis"]["corpus_arm_aliases"] == {
        "strongreject": aliases["strong"],
        "mmsafety": aliases["mm"],
        "mossbench": aliases["moss"],
    }
    binding = result["analysis"]["human_coverage_binding"]
    assert binding["mode"] == "exact_human_sensitivity_for_selected_figure_effects"
    assert binding["cohort_relation"] == (
        "selected_figure_runs_within_broader_audit_cohort"
    )
    assert len(binding["verified_points"]) == 10

    missing_pair = json.loads(json.dumps(sensitivity))
    missing_pair["paired_model_effects"].pop(next(iter(missing_pair["paired_model_effects"])))
    point = result["figures"]["fig-v-asr-by-model.png"]["points"][0]
    with pytest.raises(ValueError, match="exact paired figure effect"):
        figure_results._validate_human_figure_coverage(
            {"primary_effect_sensitivity": missing_pair}, [point],
        )


def test_direct_figure_loader_rejects_unbound_human_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    left, right = "provider:left", "provider:right"
    replay_facets = {
        corpus: _direct_facet(corpus, left, right)
        for corpus in ("strongreject", "mmsafety", "mossbench")
    }
    monkeypatch.setattr(
        figure_results, "compare",
        lambda *args, **kwargs: {
            "facets": {kwargs["corpus"]: replay_facets[kwargs["corpus"]]},
            "unavailable_facets": {},
        },
    )
    monkeypatch.setattr(
        figure_results, "compare_adaptivity",
        lambda *args, model, **kwargs: {
            "facets": {"strongreject": _direct_facet(
                "strongreject", model, model, attacker="crescendo",
            )},
            "unavailable_facets": {},
        },
    )
    monkeypatch.setattr(figure_results, "validate_analysis_source_identity", lambda value: value)
    audit = tmp_path / "human_audit.json"
    digest = _write_direct_human_audit(audit, ["wrong-run"])
    with pytest.raises(ValueError, match="bind every completed figure run"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model=left,
            right_model=right,
            human_audit=audit,
            human_audit_sha256=digest,
            n_resamples=10,
        )


def test_direct_figure_loader_rejects_human_audit_digest_mismatch(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "human_audit.json"
    _write_direct_human_audit(audit, [])
    with pytest.raises(ValueError, match="digest mismatch"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model="provider:left",
            right_model="provider:right",
            human_audit=audit,
            human_audit_sha256="0" * 64,
            n_resamples=10,
        )
