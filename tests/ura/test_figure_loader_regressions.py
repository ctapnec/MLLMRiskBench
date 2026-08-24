from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any
import pytest

from experiments import figure_results
from experiments.transfer_matrix import _cohort_payload, load as load_transfer
from ura.adapters._engine_runtime import (
    ENGINE_RUNTIME_EXECUTION_SCHEMA,
    ENGINE_RUNTIME_IDENTITY_SCHEMA,
    ENGINE_RUNTIME_RECEIPT_SCHEMA,
    ENGINE_RUNTIME_REQUIREMENTS,
    ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
)
from ura.adapters.base import AttackBudget
from ura.adapters.pyrit import PyRITAttacker
from ura.adapters.replay import ReplayAttacker
from ura.attacker_input_contract import attacker_input_payload_sha256
from ura.data_models import (
    SCHEMA_VERSION,
    DataPoint,
    DialogTurn,
    MediaRef,
    Response,
    RiskCategory,
)
from ura.eligibility import build_eligibility_plan
from ura.model_identity import canonical_https_endpoint_identity
from ura.model_acquisition import (
    build_receipt,
    build_upstream_manifest,
    write_document_create_only,
)
from ura.model_acquisition_runtime import (
    ManagedModelRuntime,
    ModelRequirementSet,
    build_runtime_plan,
    build_runtime_selection,
    collect_run_requirements,
    model_acquisition_cell_role_projection,
    model_acquisition_execution_descriptor,
    public_selection_descriptor,
)
from ura.runner import CODE_VERSION, realized_identity_summary
from ura.targets.guarded import GUARDED_BLOCK_TEMPLATE_ID, GUARDED_BLOCK_TEXT

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "+A8AAQUBAScY42YAAAAASUVORK5CYII="
)
_NO_ACQUISITION_FULL = {
    "selection": public_selection_descriptor(
        build_runtime_selection(
            ModelRequirementSet((), ()),
            input_bindings={"fixture_sha256": hashlib.sha256(
                b"figure-acquisition-fixture"
            ).hexdigest()},
        )
    ),
    "status": "not_required",
}
_NO_ACQUISITION_EXECUTION = model_acquisition_execution_descriptor(
    _NO_ACQUISITION_FULL
)
_NO_ACQUISITION_CELL = model_acquisition_cell_role_projection(
    _NO_ACQUISITION_EXECUTION,
    {
        "attacker": "replay",
        "attacker_config": {},
        "judge_names": ["rules"],
        "local_identity": None,
        "model_spec": "mock",
    },
)


class _Target:
    def __init__(self, name: str) -> None:
        self.name = name
        self.modality_support = ("text", "image", "audio", "video")


def _request_envelope() -> dict[str, object]:
    envelope_id = "request-envelope-" + "7" * 24
    return {
        "envelope_id": envelope_id,
        "file": f"{envelope_id}.request-envelope.json",
        "sha256": "6" * 64,
        "bytes": 100,
    }


def _project_revision() -> dict[str, object]:
    return {
        "mode": "verified",
        "revision_id": "project-revision-" + "c" * 24,
        "file": "project-revision-" + "c" * 24 + ".project-revision.json",
        "sha256": "d" * 64,
        "bytes": 100,
        "expected_commit": "e" * 40,
        "observed_commit": "e" * 40,
        "head_tree": "f" * 40,
        "harness_source_sha256": _HASH_B,
        "driver_source_sha256": _HASH_A,
    }


def test_figure_point_and_bootstrap_equal_weight_source_clusters() -> None:
    """Sibling rows of one source cluster carry DISTINCT datapoint ids.

    MM-SafetyBench emits three variants per cluster as
    ``{cluster_id}/SD``, ``/SD_TYPO`` and ``/TYPO``, and an AIR-Bench leaf
    category holds a varying number of prompts under one cluster id. Keying the
    resampling unit on the datapoint therefore split every such cluster, which
    weighted a three-row cluster three times as heavily as a one-row cluster.
    The earlier fixture repeated one datapoint id to stand in for a cluster,
    which is a shape the converters never produce, so it could not show this.
    """

    paired = {}
    rows = [
        ("cluster-a", "cluster-a/SD", 1.0),
        ("cluster-a", "cluster-a/SD_TYPO", 1.0),
        ("cluster-a", "cluster-a/TYPO", 1.0),
        ("cluster-b", "cluster-b/SD", 0.0),
    ]
    for index, (cluster_id, datapoint, left_value) in enumerate(rows):
        common = dict(
            corpus="fixture", source="source", datapoint_id=datapoint,
            source_cluster_id=cluster_id,
            seed=index, expected_behavior="refuse", risk_category="information_security",
            declared_modality="text", effective_modality="text", eligible=True,
            attack_fingerprint=f"fp-{index}", transfer_key=f"key-{index}",
        )
        left = figure_results._Unit(value=left_value, **common)
        right = figure_results._Unit(value=0.0, **common)
        paired[left.key] = (left, right)
    left_value, right_value = figure_results._equal_cluster_arm_values(
        list(paired.values())
    )
    # Two clusters, weighted equally: (1.0 + 0.0) / 2. Weighting by datapoint
    # would give (1+1+1+0)/4 = 0.75.
    assert left_value == 0.5, "clusters must be weighted equally, not by row count"
    assert left_value - right_value == 0.5

    # And the unit really is the cluster, so the four rows form two of them.
    units = [left for left, _ in paired.values()]
    assert len({unit.cluster for unit in units}) == 2
    assert len({unit.datapoint_id for unit in units}) == 4


def test_figure_loader_rejects_only_alias_arms_with_the_same_condition() -> None:
    def cell(
        model_spec: str,
        provider: str,
        **run_overrides: object,
    ) -> dict[str, Any]:
        snapshot = {
            "provider": provider,
            "resolved_model": "provider-resolved-model-20260818",
        }
        endpoint = run_overrides.pop("endpoint_identity", None)
        if endpoint is not None:
            snapshot["endpoint_identity"] = endpoint
        return {
            "manifest": {"config": {"run": {
                "model_spec": model_spec,
                "corpus": "source-a",
                "attacker": "replay",
                "resolved_quantization": "none",
                **run_overrides,
            }}},
            "realized_identities": {
                "target": {
                    "snapshot": snapshot
                }
            },
        }

    with pytest.raises(
        ValueError,
        match="distinct figure target arms resolve to one stable realized model",
    ):
        figure_results._reject_duplicate_realized_target_arms([
            cell("zhipu:requested-a", "zhipu"),
            cell("glm:requested-b", "glm"),
        ])

    # Mutable Ollama tag/model spellings are base-identity provenance, not an
    # execution condition: aliases of one immutable digest remain one arm.
    ollama_a = cell("ollama:alias-a", "ollama")
    ollama_b = cell("ollama:alias-b", "ollama")
    for alias_cell, tag in ((ollama_a, "alias-a"), (ollama_b, "alias-b")):
        alias_cell["realized_identities"]["target"]["snapshot"] = {
            "provider": "ollama",
            "resolved_model": tag,
            "model_digest": "a" * 64,
        }
        alias_cell["manifest"]["config"]["run"]["local_identity"] = {
            "model": tag,
            "tag": tag,
            "digest": "a" * 64,
            "modalities": ["text"],
            "num_predict": 64,
        }
    with pytest.raises(
        ValueError,
        match="distinct figure target arms resolve to one stable realized model",
    ):
        figure_results._reject_duplicate_realized_target_arms([
            ollama_a, ollama_b
        ])

    # Defense wrappers remain valid arms of one requested base model.
    figure_results._reject_duplicate_realized_target_arms([
        cell("glm:requested-a", "glm"),
        cell("glm:requested-a+guard", "zhipu"),
    ])

    bare = cell("glm:requested-a", "glm")
    guarded_alias = cell("zhipu:requested-b+guard", "zhipu")
    bare_component = {
        "class": "ura.targets.api.OpenAICompatibleTarget",
        "model": "provider-resolved-model-20260818",
        "temperature": 0.0,
        "max_tokens": 64,
    }
    bare["manifest"]["config"]["components"] = {
        "target": bare_component
    }
    guarded_alias["manifest"]["config"]["components"] = {
        "target": {
            "class": "ura.targets.guarded.GuardedTarget",
            "base": {**bare_component, "requested_spec": "zhipu:requested-b"},
            "guard": {"class": "ura.judges.rules.RuleJudge"},
            "mode": "both",
        }
    }
    with pytest.raises(ValueError, match="distinct figure target arms"):
        figure_results._reject_duplicate_realized_target_arms([
            bare, guarded_alias
        ])

    # The same base model is a legitimate distinct target arm only when its
    # target execution condition differs.
    figure_results._reject_duplicate_realized_target_arms([
        cell("glm:bf16", "glm", resolved_quantization="none"),
        cell("zhipu:fp8", "zhipu", resolved_quantization="fp8"),
    ])
    with pytest.raises(ValueError, match="distinct figure target arms"):
        figure_results._reject_duplicate_realized_target_arms([
            cell("glm:source-a", "glm", corpus="source-a"),
            cell("zhipu:source-b", "zhipu", corpus="source-b"),
        ])
    # Repeating one requested target across scientific strata is expected and
    # must remain legal; it does not fabricate a second model identity.
    figure_results._reject_duplicate_realized_target_arms([
        cell("glm:one-target", "glm", corpus="source-a"),
        cell("glm:one-target", "glm", corpus="source-b"),
    ])
    figure_results._reject_duplicate_realized_target_arms([
        cell("glm:one-target", "glm", max_queries=1),
        cell("glm:one-target", "glm", max_queries=4),
    ])
    seeded_a = cell("glm:one-target", "glm")
    seeded_b = cell("glm:one-target", "glm")
    seeded_a["manifest"]["seeds"] = [0]
    seeded_b["manifest"]["seeds"] = [1]
    figure_results._reject_duplicate_realized_target_arms([seeded_a, seeded_b])
    configured_a = cell("glm:config-a", "glm")
    configured_b = cell("zhipu:config-b", "zhipu")
    configured_a["manifest"]["config"]["components"] = {
        "target": {"class": "Fixture", "max_model_len": 4096}
    }
    configured_b["manifest"]["config"]["components"] = {
        "target": {"class": "Fixture", "max_model_len": 8192}
    }
    figure_results._reject_duplicate_realized_target_arms([
        configured_a, configured_b
    ])
    figure_results._reject_duplicate_realized_target_arms([
        cell(
            "glm:service-a",
            "glm",
            endpoint_identity="https-base-url-sha256:" + "a" * 64,
        ),
        cell(
            "glm:service-b",
            "glm",
            endpoint_identity="https-base-url-sha256:" + "b" * 64,
        ),
    ])


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


def _runtime_evidence(
    engine: str = "pyrit", *, digit: str = "1"
) -> tuple[dict, dict, dict, dict]:
    requirement = ENGINE_RUNTIME_REQUIREMENTS[engine]
    receipt = {
        "schema": ENGINE_RUNTIME_RECEIPT_SCHEMA,
        "engine": engine,
        "distribution": requirement.distribution,
        "version": requirement.version,
        "python": {
            "implementation": "cpython",
            "version": "3.12.10",
            "cache_tag": "cpython-312",
            "executable_sha256": digit * 64,
            "executable_bytes": 10,
        },
        "pyvenv_cfg_sha256": "2" * 64,
        "package_tree_sha256": "3" * 64,
        "package_files": 2,
        "package_bytes": 20,
        "inventory_sha256": "4" * 64,
        "environment_tree_sha256": digit * 64,
        "environment_files": 7,
        "environment_bytes": 70,
    }
    receipt["runtime_id"] = f"engine-runtime-{_canonical_sha256(receipt)[:24]}"
    identity = {
        "schema": ENGINE_RUNTIME_IDENTITY_SCHEMA,
        "bridge_sha256": "a" * 64,
        "receipt": receipt,
    }
    close = {
        **identity,
        "schema": ENGINE_RUNTIME_EXECUTION_SCHEMA,
        "status": "closed_verified",
    }
    selection_identity = {
        "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
        "runtimes": [identity],
    }
    closed_body = {
        "schema": "ura-engine-runtime-selection/1",
        "runtimes": [close],
    }
    selection_sha256 = _canonical_sha256(selection_identity)
    opened = {**selection_identity, "selection_sha256": selection_sha256}
    closed = {**closed_body, "selection_sha256": selection_sha256}
    return identity, close, opened, closed


def _attach_runtime_evidence(cell: dict[str, Any], grid_path: Path) -> None:
    identity, close, opened, closed = _runtime_evidence()
    manifest_path = cell["paths"]["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config"]["run"]["engine_runtime"] = identity
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    marker = json.loads(cell["marker"].read_text(encoding="utf-8"))
    marker["engine_runtime_close"] = close
    marker["artifacts"]["manifest"] = _descriptor(manifest_path)
    cell["marker"].write_text(json.dumps(marker), encoding="utf-8")
    grid = json.loads(grid_path.read_text(encoding="utf-8"))
    grid["request"]["engine_runtimes"] = opened
    grid["engine_runtime_close"] = closed
    grid_path.write_text(json.dumps(grid), encoding="utf-8")


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
    model_acquisition: dict[str, Any] | None = None,
    local_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    run_id = run_id or f"run-{hashlib.sha256(stem.encode()).hexdigest()[:24]}"
    resolved_model = f"resolved:{model_spec}"
    datapoints = datapoints or [{
        "id": "probe",
        "source": f"source-{corpus}",
        "risk": "information_security",
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
    planned_contracts: dict[tuple[str, int], Any] = {}
    planned_datapoints: list[DataPoint] = []
    for datapoint in datapoints:
        datapoint_id = datapoint["id"]
        seed = int(datapoint.get("seed", 0))
        seeds.add(seed)
        attempt_id = f"{datapoint_id}::{attacker}::s{seed}"
        fingerprint = _canonical_sha256([corpus, datapoint_id, seed, "prompt"])
        transfer_key = _canonical_sha256([corpus, datapoint_id, seed, attacker])
        effective_modality = datapoint.get("effective_modality", "text")
        media: list[dict[str, Any]] = []
        if effective_modality in {"image", "audio", "video"}:
            if effective_modality != "image":
                raise ValueError("figure fixture only materializes image media")
            media_path = root / f"fixture-{datapoint_id}.png"
            media_path.write_bytes(_PNG)
            media = [{
                "modality": "image",
                "path": str(media_path),
                "sha256": hashlib.sha256(_PNG).hexdigest(),
                "mime": "image/png",
            }]
        source_modalities = ["text", *(
            [effective_modality]
            if effective_modality in {"image", "audio", "video"}
            else []
        )]
        planned_datapoint = DataPoint(
            id=datapoint_id,
            source=datapoint.get("source", f"source-{corpus}"),
            modalities=source_modalities,
            dialog_history=[DialogTurn.model_validate({
                "role": "user",
                "content": f"prompt {datapoint_id}",
                "media": media,
            })],
            payload_text=f"prompt {datapoint_id}",
            media=[MediaRef.model_validate(item) for item in media],
            risk_category=RiskCategory(datapoint.get("risk", "information_security")),
            expected_behavior=datapoint.get("expected", "refuse"),
            meta={
                "common_metrics_eligible": datapoint.get("eligible", True),
                "automated_metric_scope": "response_only",
            },
        )
        planner = PyRITAttacker() if attacker == "pyrit" else ReplayAttacker()
        contract = planner.plan_target_inputs(
            planned_datapoint,
            AttackBudget(max_queries=1, max_turns=1, seed=seed),
        )
        planned_contracts[(datapoint_id, seed)] = contract
        planned_datapoints.append(planned_datapoint)
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
                "planning_expected_behavior": datapoint.get(
                    "expected", "refuse"
                ),
                "planning_common_metrics_eligible": datapoint.get(
                    "eligible", True
                ),
                "planning_exact_modality_combination": source_modalities,
                "attacker_input_contract_id": contract.contract_id,
                "planned_target_input": contract.turns[0].manifest_payload(),
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
                "run_id": run_id,
                "attack_fingerprint": fingerprint,
                "transfer_key": transfer_key,
                "transferable": True,
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
            "risk_category": datapoint.get("risk", "information_security"),
            "risk": datapoint.get("risk", "information_security"),
            "modality": datapoint.get("modality", "text"),
            "source_modality": datapoint.get("modality", "text"),
            "delivered_modality": effective_modality,
            "effective_modality": effective_modality,
            "target_input_delivered": True,
            "target_modalities": ["text", "image", "audio", "video"],
            "is_multimodal": len(source_modalities) > 1,
            "expected_behavior": expected,
            "common_metrics_eligible": datapoint.get("eligible", True),
            "seed": seed,
            "requested_seed": seed,
            "turn_index": 0,
            "policy_evaluable_turn": True,
            "policy_challenge_index": 0,
            "policy_challenge_horizon": 1,
            "turn_expected_behavior": expected,
            "planning_exact_modality_combination": source_modalities,
            "attack_fingerprint": fingerprint,
            "transfer_key": transfer_key,
            "transferable": True,
            "response_conditioned": False,
            "replayed_transcript": False,
            "target_sampling_control": "provider_seed",
            "cascade_stage": 0,
            "confidence": 0.95,
            "parsed": None,
            "cascade_confident": True,
            "cascade_role": "authoritative",
            "cascade_policy": "first_confident_with_full_shadow_trail",
            "stage_queried": True,
            "policy_evaluation_status": "evaluated",
            "metric_authority": None,
            "required_metric": None,
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
            "judge_model": None,
            "judge_model_revision": None,
            "judge_model_digest": None,
            "judge_model_identity": None,
            "judge_model_queried": None,
            "guardrail_queried": None,
            "provider_signal_authoritative": None,
            "provider_refusal_category": None,
            "judge_call": None,
            "label": label,
            "score": score,
            "confidence": 0.95,
            "parsed": None,
            "cascade_confident": True,
            "cascade_role": "authoritative",
            "cascade_policy": "first_confident_with_full_shadow_trail",
            "stage_queried": True,
            "policy_evaluation_status": "evaluated",
            "metric_authority": None,
            "required_metric": None,
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
    attacker_input_plan = {
        "schema": "ura-attacker-input-plan/1",
        "entries": [
            {"seed": seed, **contract.manifest_payload()}
            for (_datapoint_id, seed), contract in sorted(
                planned_contracts.items()
            )
        ],
    }
    base_component = {
        "class": "FixtureTarget",
        "name": resolved_model.removesuffix("+guard"),
        "provider": "fixture-provider",
        "model": model_spec,
        "modality_support": ["text", "image", "audio", "video"],
    }
    target_component = (
        base_component
        if defense == "none"
        else {
            "class": "GuardedTarget",
            "name": resolved_model,
            "mode": defense,
            "modality_support": ["text", "image", "audio", "video"],
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
                "expected_target_identity": {
                    "provider": "fixture-provider",
                    "resolved_model": model_spec,
                },
                "local_identity": local_identity,
                "attacker": attacker,
                "attacker_config": {},
                "engine_runtime": {
                    "schema": "ura-engine-runtime-not-required/1",
                    "framework_execution": (
                        "not_invoked" if attacker == "nanogcg" else None
                    ),
                },
                "judge_names": ["rules"],
                "judge_model": "rules-v1",
                "group_keys": ["model", "risk", "modality"],
                "defense": defense,
                "defense_guard": "rules",
                "quantization": "none",
                "dtype": "auto",
                "dry_run": False,
                "model_acquisition": _NO_ACQUISITION_CELL,
                "project_revision": _project_revision(),
                "request_envelope": _request_envelope(),
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
            "attacker_input_plan": attacker_input_plan,
            "attacker_input_plan_sha256": attacker_input_payload_sha256(
                attacker_input_plan
            ),
            "n_attacker_input_contracts": len(planned_contracts),
            **identity_config,
        },
    }
    if model_acquisition is not None:
        run_config = manifest["config"]["run"]
        run_config["model_acquisition"] = model_acquisition_cell_role_projection(
            model_acquisition,
            run_config,
        )
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
        "contracts": planned_contracts,
        "datapoints": planned_datapoints,
    }


def _grid(
    root: Path,
    *,
    name: str,
    cells: list[dict[str, Any]],
    acquisition_full: dict[str, Any] | None = None,
    acquisition_execution: dict[str, Any] | None = None,
    local_configs: dict[str, dict[str, Any]] | None = None,
) -> Path:
    models = sorted({cell["model_spec"] for cell in cells})
    corpora = sorted({cell["corpus"] for cell in cells})
    attackers = sorted({cell["attacker"] for cell in cells})
    defenses = {cell["defense"] for cell in cells}
    assert len(defenses) == 1
    expected = len(models) * len(corpora) * len(attackers)
    assert len(cells) == expected
    grid_id = f"grid-{name}"
    planned_corpora: dict[str, list[DataPoint]] = {}
    planned_contracts: dict[tuple[str, str, str, int], Any] = {}
    for cell in cells:
        existing = planned_corpora.setdefault(
            cell["corpus"], cell["datapoints"]
        )
        assert existing == cell["datapoints"]
        for (datapoint_id, seed), contract in cell["contracts"].items():
            key = (cell["corpus"], cell["attacker"], datapoint_id, seed)
            prior = planned_contracts.setdefault(key, contract)
            assert prior == contract
    eligibility_plan = build_eligibility_plan(
        requested_targets=models,
        targets={
            model: _Target(next(
                cell["target"] for cell in cells if cell["model_spec"] == model
            ))
            for model in models
        },
        corpora=planned_corpora,
        attackers=attackers,
        attacker_input_contracts=planned_contracts,
        bindings={
            "model_acquisition": (
                acquisition_execution or _NO_ACQUISITION_EXECUTION
            )
        },
        dry_run=False,
        whole_request_preflight_complete=True,
    )
    eligibility_path = root / (
        f"{eligibility_plan['plan_id']}.eligibility.json"
    )
    eligibility_path.write_text(
        json.dumps(eligibility_plan, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    eligibility_descriptor = {
        "plan_id": eligibility_plan["plan_id"],
        **_descriptor(eligibility_path),
        "counts": eligibility_plan["counts"],
    }
    # The real driver binds every completed cell back to the exact grid
    # condition in manifest.config.run. Keep the synthetic fixture faithful,
    # then refresh the completion marker's manifest descriptor.
    for cell in cells:
        manifest_path = cell["paths"]["manifest"]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["config"]["run"]["grid_id"] = grid_id
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        marker_path = cell["marker"]
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker["artifacts"]["manifest"] = _descriptor(manifest_path)
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
    path = root / f"{grid_id}.grid.json"
    path.write_text(json.dumps({
        "status": "complete",
        "grid_id": grid_id,
        "started_at": "2026-08-10T00:00:00+00:00",
        "finished_at": "2026-08-10T00:01:00+00:00",
        "request": {
            "models": models,
            "local_configs": local_configs or {},
            "corpora": corpora,
            "attackers": attackers,
            "attacker_configs": {name: {} for name in attackers},
            "judges": ["rules"],
            "judge_model": None,
            "defense": next(iter(defenses)),
            "dry_run": False,
            "project_revision": _project_revision(),
            "request_envelope": _request_envelope(),
            "model_acquisition": acquisition_full or _NO_ACQUISITION_FULL,
            "model_acquisition_execution": (
                acquisition_execution or _NO_ACQUISITION_EXECUTION
            ),
            "eligibility_plan": eligibility_descriptor,
            "attestation_probe": False,
            "live_attestation": {
                "mode": "measured",
                "execution_scope_id": "synthetic-figure-fixture",
                "max_age_hours": 24.0,
                "artifacts": [{
                    "file": "synthetic-live-attestation.json",
                    "sha256": "0" * 64,
                    "bytes": 1,
                    "attestation_id": "live-attestation-" + "0" * 24,
                }],
            },
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
                "risk": "information_security" if corpus == "alpha" else "privacy",
                "modality": "text" if corpus == "alpha" else "image",
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


def _one_hub_local_acquisition(
    root: Path,
    *,
    model: str,
    revision: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    selection = build_runtime_selection(
        collect_run_requirements(
            target_specs=["anthropic:hosted-left", "openai:hosted-right", model],
            local_configs={model: {"revision": revision}},
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings={
            "fixture_sha256": hashlib.sha256(
                f"{model}@{revision}".encode("utf-8")
            ).hexdigest()
        },
    )
    plan = build_runtime_plan(selection)
    store = (root / "private-model-store").resolve()
    store.mkdir()
    resource = plan["resources"][0]
    resource_root = store / resource["resource_id"]
    snapshot = resource_root / "snapshot"
    snapshot.mkdir(parents=True)
    content = b'{"fixture":"one-legal-local-target"}\n'
    (snapshot / "config.json").write_bytes(content)
    blob_id = hashlib.sha1(  # noqa: S324 - Git blob protocol identity
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()
    manifest = build_upstream_manifest(
        resource["repo_id"],
        resource["revision"],
        [{
            "path": "config.json",
            "size": len(content),
            "blob_id": blob_id,
            "lfs_sha256": None,
        }],
    )
    write_document_create_only(
        resource_root.resolve(),
        manifest,
        identifier=manifest["manifest_id"],
        suffix="upstream-manifest.json",
    )
    receipt = build_receipt(
        plan,
        snapshots={resource["resource_id"]: snapshot},
        manifests={resource["resource_id"]: manifest},
    )
    plan_path, plan_sha = write_document_create_only(
        root.resolve(), plan, identifier=plan["plan_id"], suffix="plan.json"
    )
    receipt_path, receipt_sha = write_document_create_only(
        root.resolve(),
        receipt,
        identifier=receipt["receipt_id"],
        suffix="receipt.json",
    )
    runtime = ManagedModelRuntime(
        selection=selection,
        plan_path=plan_path,
        plan_sha256=plan_sha,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha,
        managed_store=store,
    )
    full = {
        **runtime.admit(),
        "evidence": {
            "plan": _descriptor(plan_path),
            "receipt": _descriptor(receipt_path),
        },
        "selection": public_selection_descriptor(selection),
    }
    return full, model_acquisition_execution_descriptor(full, evidence_root=root)


def test_multi_target_acquisition_survives_figure_and_transfer_loaders(
    tmp_path: Path,
) -> None:
    revision = "1" * 40
    local_model = f"vllm:Org/LocalTarget@{revision}"
    models = (
        "anthropic:hosted-left",
        "openai:hosted-right",
        local_model,
    )
    full, stable = _one_hub_local_acquisition(
        tmp_path,
        model="vllm:Org/LocalTarget",
        revision=revision,
    )
    cells = [
        _cell(
            tmp_path,
            stem=f"model-{index}",
            model_spec=model,
            corpus="alpha",
            local_identity=(
                {"revision": revision} if model == local_model else None
            ),
            model_acquisition=stable,
            datapoints=[{
                "id": "shared-probe",
                "source": "source-alpha",
                "risk": "information_security",
                "modality": "text",
                "effective_modality": "text",
                "expected": "refuse",
                "label": "violation" if index == 0 else "safe",
                "eligible": True,
                "seed": 0,
            }],
        )
        for index, model in enumerate(models)
    ]
    grid_path = _grid(
        tmp_path,
        name="hosted-plus-one-local-acquisition",
        cells=cells,
        acquisition_full=full,
        acquisition_execution=stable,
        local_configs={local_model: {"revision": revision}},
    )

    assert len(figure_results._load_cells(tmp_path)) == 3
    per_model, audit = load_transfer(tmp_path)
    assert set(per_model) == {"resolved:" + model for model in models}
    assert audit["grid_audit"]["selected_cells"] == 3

    original = json.loads(grid_path.read_text(encoding="utf-8"))
    other = "vllm:Org/OtherTarget@" + ("3" * 40)
    mutations = (
        {
            "models": list(models[:2]),
            "local_configs": {},
        },
        {
            "models": [*models, other],
            "local_configs": {
                **original["request"]["local_configs"],
                other: {"revision": "3" * 40},
            },
        },
        {
            "models": [*models[:2], other],
            "local_configs": {other: {"revision": "3" * 40}},
        },
    )
    for mutation in mutations:
        changed = json.loads(json.dumps(original))
        changed["request"].update(mutation)
        grid_path.write_text(json.dumps(changed), encoding="utf-8")
        with pytest.raises(ValueError, match="model-acquisition"):
            figure_results._load_cells(tmp_path)
        with pytest.raises(ValueError, match="model-acquisition"):
            load_transfer(tmp_path)
    grid_path.write_text(json.dumps(original), encoding="utf-8")


def test_runtime_backed_cell_seal_survives_figure_and_transfer_loaders(
    tmp_path: Path,
) -> None:
    cell = _cell(
        tmp_path,
        stem="pyrit-sealed",
        model_spec="fixture:runtime-target",
        corpus="alpha",
        attacker="pyrit",
    )
    grid_path = _grid(tmp_path, name="pyrit-sealed", cells=[cell])
    _attach_runtime_evidence(cell, grid_path)

    loaded = figure_results._load_cells(tmp_path)
    assert len(loaded) == 1
    per_model, audit = load_transfer(tmp_path, attacker="pyrit", corpus="alpha")
    assert set(per_model) == {"resolved:fixture:runtime-target"}
    assert audit["grid_audit"]["selected_cells"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_marker_seal",
        "downgraded_marker_seal",
        "different_marker_bridge",
        "extra_marker_runtime_inventory",
        "missing_grid_close",
        "different_grid_receipt",
    ],
)
def test_figure_and_transfer_loaders_reject_runtime_seal_confusion(
    tmp_path: Path,
    mutation: str,
) -> None:
    cell = _cell(
        tmp_path,
        stem="pyrit-confused",
        model_spec="fixture:runtime-target",
        corpus="alpha",
        attacker="pyrit",
    )
    grid_path = _grid(tmp_path, name="pyrit-confused", cells=[cell])
    _attach_runtime_evidence(cell, grid_path)
    marker = json.loads(cell["marker"].read_text(encoding="utf-8"))
    grid = json.loads(grid_path.read_text(encoding="utf-8"))

    if mutation == "missing_marker_seal":
        marker.pop("engine_runtime_close")
    elif mutation == "downgraded_marker_seal":
        marker["engine_runtime_close"]["status"] = "verified"
    elif mutation == "different_marker_bridge":
        marker["engine_runtime_close"]["bridge_sha256"] = "b" * 64
    elif mutation == "extra_marker_runtime_inventory":
        marker["engine_runtime_close"]["runtimes"] = []
    elif mutation == "missing_grid_close":
        grid.pop("engine_runtime_close")
    elif mutation == "different_grid_receipt":
        _identity, _close, _opened, changed_close = _runtime_evidence(digit="5")
        grid["engine_runtime_close"] = changed_close

    cell["marker"].write_text(json.dumps(marker), encoding="utf-8")
    grid_path.write_text(json.dumps(grid), encoding="utf-8")
    with pytest.raises(ValueError, match="engine runtime"):
        figure_results._load_cells(tmp_path)
    with pytest.raises(ValueError, match="engine runtime"):
        load_transfer(tmp_path, attacker="pyrit", corpus="alpha")


def test_figure_loader_binds_realized_target_to_planned_attestation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "target-attestation"
    root.mkdir()
    cell = _cell(
        root,
        stem="target-attestation",
        model_spec="fixture:planned-model",
        corpus="alpha",
    )
    _grid(root, name="target-attestation", cells=[cell])
    manifest_path = cell["paths"]["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["config"]["run"]["expected_target_identity"] = {
        "provider": "fixture-provider",
        "resolved_model": "fixture:planned-model",
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_marker(cell)
    assert len(figure_results._load_cells(root)) == 1

    responses = [
        json.loads(line)
        for line in cell["paths"]["responses"].read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    responses[0]["raw"]["resolved_model"] = "fixture:changed-model"
    _write_jsonl(cell["paths"]["responses"], responses)
    _refresh_identity_metadata(cell)

    with pytest.raises(ValueError, match="does not match.*attestation"):
        figure_results._load_cells(root)


def test_figure_loader_binds_realized_llm_judge_to_planned_route(
    tmp_path: Path,
) -> None:
    root = tmp_path / "judge-route"
    root.mkdir()
    cell = _cell(
        root,
        stem="judge-route",
        model_spec="fixture:target",
        corpus="alpha",
    )
    _grid(root, name="judge-route", cells=[cell])
    planned_judge = "anthropic:planned-judge"
    endpoint_identity = canonical_https_endpoint_identity(
        "https://api.anthropic.com"
    )

    judgments = [
        json.loads(line)
        for line in cell["paths"]["judgments"].read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    trails = [
        json.loads(line)
        for line in cell["paths"]["trails"].read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    judgments[0]["judge"] = "llm-judge"
    judge_call = {
        "response_target": planned_judge,
        "provider": "anthropic",
        "endpoint_identity": endpoint_identity,
        "provider_resolved_model": "planned-judge",
    }
    judgments[0]["raw"].update({
        "judge_model": planned_judge,
        "judge_model_queried": True,
        "judge_call": judge_call,
    })
    trails[0].update({
        "judge": "llm-judge",
        "judge_model": planned_judge,
        "judge_model_queried": True,
        "judge_call": judge_call,
    })
    _write_jsonl(cell["paths"]["judgments"], judgments)
    _write_jsonl(cell["paths"]["trails"], trails)
    manifest_path = cell["paths"]["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["judges"] = ["llm-judge"]
    manifest["config"]["components"]["judge_cascade"] = {
        "class": "JudgeCascade",
        "stages": [{
            "class": "ura.judges.llm.LLMJudge",
            "name": "llm-judge",
            "judge_target": {
                "class": "ura.targets.api.AnthropicTarget",
                "provider": "anthropic",
                "model": "planned-judge",
                "requested_spec": planned_judge,
                "endpoint_identity": endpoint_identity,
            },
        }],
    }
    manifest["config"]["run"].update({
        "judge_names": ["llm"],
        "judge_model": planned_judge,
        "judge_api_config": {
            "modalities": ["text"],
            "max_tokens": 64,
            "temperature": 0.0,
        },
    })
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_identity_metadata(cell)
    assert len(figure_results._load_cells(root)) == 1

    trails = [
        json.loads(line)
        for line in cell["paths"]["trails"].read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    trails[0]["judge_call"]["provider_resolved_model"] = "changed-judge"
    _write_jsonl(cell["paths"]["trails"], trails)
    _refresh_identity_metadata(cell)
    with pytest.raises(
        ValueError, match="judge_call differs|LLM judge identity differs"
    ):
        figure_results._load_cells(root)


def test_cross_target_cohort_ignores_only_per_cell_attestation_identity() -> None:
    def manifest(model: str, expected: dict[str, str]) -> dict[str, Any]:
        return {
            "run_id": f"run-{model}",
            "started_at": "2026-08-18T00:00:00+00:00",
            "models": [model],
            "config": {
                "components": {
                    "target": {"class": "FixtureTarget", "name": model},
                },
                "realized_identities": {
                    "target": {"snapshot": expected, "observations": 1},
                    "judges": [{
                        "stage": 0,
                        "judge": "rules",
                        "snapshot": {"judge": "rules"},
                        "observations": 1,
                    }],
                },
                    "run": {
                        "model_spec": model,
                        "expected_target_identity": expected,
                        "defense": "none",
                        "model_acquisition": _NO_ACQUISITION_CELL,
                    },
            },
        }

    left = manifest(
        "glm:model-a", {"provider": "glm", "resolved_model": "model-a"}
    )
    right = manifest(
        "kimi:model-b", {"provider": "kimi", "resolved_model": "model-b"}
    )
    left["config"]["run"].update({
        "api_config": {
            "modalities": ["text"],
            "max_tokens": 64,
            "temperature": 0.0,
        },
        "local_identity": None,
        "resolved_quantization": "none",
        "corpus": "mmsafetybench",
        "attacker": "replay",
        "judge_names": ["rules"],
        "sample_seed": 17,
    })
    right["config"]["run"].update({
        "api_config": None,
        "local_identity": {
            "revision": "a" * 40,
            "modalities": ["text"],
            "max_tokens": 64,
        },
        "resolved_quantization": "fp8",
        "corpus": "mmsafetybench",
        "attacker": "replay",
        "judge_names": ["rules"],
        "sample_seed": 17,
    })
    assert _cohort_payload(left) == _cohort_payload(right)

    defended = manifest(
        "glm:model-a", {"provider": "glm", "resolved_model": "model-a"}
    )
    defended["config"]["run"]["defense"] = "input"
    assert _cohort_payload(left) != _cohort_payload(defended)
    different_sample = json.loads(json.dumps(right))
    different_sample["config"]["run"]["sample_seed"] = 18
    assert _cohort_payload(left) != _cohort_payload(different_sample)


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


def test_loader_rejects_rehashed_response_with_conflicting_identity_aliases(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    responses = [
        json.loads(line)
        for line in cell["paths"]["responses"].read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    responses[0]["raw"]["model"] = "invented-conflicting-model"
    _write_jsonl(cell["paths"]["responses"], responses)
    trails = [
        json.loads(line)
        for line in cell["paths"]["trails"].read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    trails[0]["response_sha256"] = figure_results._canonical_response_digest(
        Response.model_validate(responses[0], strict=True)
    )
    _write_jsonl(cell["paths"]["trails"], trails)
    # Even a refreshed outer descriptor cannot make contradictory provider
    # aliases into valid realized-identity evidence.
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="identity aliases .* conflict"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_completed_response_with_duplicate_identity_key(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    responses_path = cell["paths"]["responses"]
    raw = responses_path.read_text(encoding="utf-8")
    original = '"resolved_model": "left"'
    assert raw.count(original) == 1
    responses_path.write_text(
        raw.replace(
            original,
            '"resolved_model": "invented-conflict", '
            '"resolved_model": "left"',
            1,
        ),
        encoding="utf-8",
    )
    # Refreshing the completion descriptor makes the altered bytes outer-
    # hash-valid. A last-wins reader would also preserve the original
    # content-derived response digest, so rejection must happen at decoding.
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="duplicate JSON object key 'resolved_model'"):
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
            "risk": "information_security",
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
                "base_target": "resolved:base",
                "base_target_queried": False,
                "defense_stages_evaluated": ["input"],
                "defense_block_template_id": GUARDED_BLOCK_TEMPLATE_ID,
                "target_sampling_control": "not_queried",
            })
            response["output_turns"] = [{
                "role": "assistant", "content": GUARDED_BLOCK_TEXT,
            }]
            response["latency_ms"] = None
            response["tokens"] = None
    _write_jsonl(defended["paths"]["responses"], response_rows)
    judgment_rows = [
        json.loads(line) for line in defended["paths"]["judgments"]
        .read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    for judgment in judgment_rows:
        judgment["raw"]["target_sampling_control"] = "not_queried"
        judgment["raw"]["target_input_delivered"] = False
        judgment["raw"]["effective_modality"] = "none"
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
        "left": _direct_arm(
            f"{corpus}-{left_model}-{attacker}", left_model, attacker, corpus
        ),
        "right": _direct_arm(
            f"{corpus}-{right_model}-{attacker}", right_model, attacker, corpus,
        ),
        "metrics": {"ASR": harmful, "over_refusal_rate": benign},
        "policy_metrics": policy_metrics,
    }


def test_loader_rejects_manifest_plan_drift_with_refreshed_outer_descriptor(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    manifest = json.loads(cell["paths"]["manifest"].read_text(encoding="utf-8"))
    manifest["config"]["attacker_input_plan"]["entries"][0]["turns"][0][
        "bound_text_sha256"
    ] = "0" * 64
    manifest["config"]["attacker_input_plan"]["entries"][0]["turns"][0][
        "bound_text_bytes"
    ] = 1
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="attacker input plan"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )
def test_loader_rejects_completion_from_a_different_grid_condition(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    manifest = json.loads(cell["paths"]["manifest"].read_text(encoding="utf-8"))
    manifest["config"]["run"]["grid_id"] = "grid-other-condition"
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="grid/completed-artifact condition mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_completion_from_a_different_project_revision(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    manifest = json.loads(cell["paths"]["manifest"].read_text(encoding="utf-8"))
    revision = manifest["config"]["run"]["project_revision"]
    revision["revision_id"] = "project-revision-" + "9" * 24
    revision["file"] = revision["revision_id"] + ".project-revision.json"
    revision["expected_commit"] = "8" * 40
    revision["observed_commit"] = "8" * 40
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="project-revision mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def test_loader_rejects_completion_from_a_different_request_envelope(
    tmp_path: Path,
) -> None:
    cells = _paired_model_grid(tmp_path)
    cell = cells[0]
    manifest = json.loads(cell["paths"]["manifest"].read_text(encoding="utf-8"))
    descriptor = manifest["config"]["run"]["request_envelope"]
    descriptor["sha256"] = "5" * 64
    cell["paths"]["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    _refresh_marker(cell)

    with pytest.raises(ValueError, match="request-envelope mismatch"):
        figure_results.load_model_results(
            tmp_path,
            left_model="left",
            right_model="right",
            corpora=["alpha"],
            policy_label="policy",
            multiplicity_family="family",
            minimum_cell_n=1,
        )


def _write_direct_human_audit(
    path: Path, run_ids: list[str], *, completed_run_ids: list[str] | None = None,
    primary_effect_sensitivity: dict[str, Any] | None = None,
    prepared_bound: bool = True,
    prepared_name: str = "human-audit-rating-form.csv",
) -> str:
    prepared_path = path.parent / prepared_name
    if not prepared_path.exists():
        prepared_path.write_text("sample_key,rater_id,label\n", encoding="utf-8")
    prepared_descriptor = {
        "path": str(prepared_path.resolve(strict=True)),
        "bytes": prepared_path.stat().st_size,
        "sha256": hashlib.sha256(prepared_path.read_bytes()).hexdigest(),
    }
    checks = {
        name: True for name in figure_results._HUMAN_AUDIT_READINESS_CHECKS
    }
    checks["prepared_rating_form_bound"] = prepared_bound
    selection_policy = dict(figure_results._HUMAN_AUDIT_SELECTION_POLICY)
    artifact = {
        "schema_version": "ura-human-audit/1.2",
        "analysis_ready_real_run": prepared_bound,
        "analysis_readiness": {
            "status": (
                "complete_sample_conditional" if prepared_bound else "incomplete"
            ),
            "checks": checks,
            "population_validity_claimed": False,
        },
        "prepared_rating_form": (
            prepared_descriptor if prepared_bound else None
        ),
        "achieved_audit_design": {"selection_policy": selection_policy},
        "audit": {
            "achieved_selection_coverage": {
                "selection_policy": dict(selection_policy),
            },
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


def test_human_audit_loader_uses_content_bindings_not_basenames(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        figure_results, "validate_analysis_source_identity", lambda value: value,
    )
    results = tmp_path / "runner"
    results.mkdir()
    analysis = tmp_path / "analysis"
    analysis.mkdir()
    audit = analysis / "renamed-human-report.json"
    digest = _write_direct_human_audit(
        audit,
        [],
        prepared_name="renamed-blank-rating-form.csv",
    )

    loaded, identity = figure_results._load_human_audit(
        results,
        audit,
        expected_sha256=digest,
    )

    assert loaded["schema_version"] == "ura-human-audit/1.2"
    assert loaded["prepared_rating_form"]["path"].endswith(
        "renamed-blank-rating-form.csv"
    )
    assert identity["sha256"] == digest


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
    analysis_root = tmp_path / "phase8-analysis"
    analysis_root.mkdir()
    audit = analysis_root / "human_audit.json"
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


def test_direct_figure_loader_rejects_unbound_prepared_rating_form(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "human_audit.json"
    digest = _write_direct_human_audit(audit, [], prepared_bound=False)
    with pytest.raises(ValueError, match="not integrity-complete"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model="provider:left",
            right_model="provider:right",
            human_audit=audit,
            human_audit_sha256=digest,
            n_resamples=10,
        )


def test_direct_figure_loader_rejects_legacy_global_rater_readiness(
    tmp_path: Path,
) -> None:
    current_names = figure_results._HUMAN_AUDIT_READINESS_CHECKS
    assert {
        "exactly_two_distinct_raters_per_sample",
        "all_observed_overlapping_rater_pairs_reported",
    }.issubset(current_names)
    assert {
        "full_rater_coverage",
        "all_inter_rater_pairs_reported",
    }.isdisjoint(current_names)

    audit = tmp_path / "human_audit.json"
    _write_direct_human_audit(audit, [])
    artifact = json.loads(audit.read_text(encoding="utf-8"))
    checks = artifact["analysis_readiness"]["checks"]
    checks["full_rater_coverage"] = checks.pop(
        "exactly_two_distinct_raters_per_sample"
    )
    checks["all_inter_rater_pairs_reported"] = checks.pop(
        "all_observed_overlapping_rater_pairs_reported"
    )
    audit.write_text(json.dumps(artifact), encoding="utf-8")
    digest = hashlib.sha256(audit.read_bytes()).hexdigest()

    with pytest.raises(ValueError, match="not integrity-complete"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model="provider:left",
            right_model="provider:right",
            human_audit=audit,
            human_audit_sha256=digest,
            n_resamples=10,
        )


def test_direct_figure_loader_rejects_false_prepared_form_descriptor(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "human_audit.json"
    _write_direct_human_audit(audit, [])
    artifact = json.loads(audit.read_text(encoding="utf-8"))
    artifact["prepared_rating_form"]["sha256"] = "0" * 64
    audit.write_text(json.dumps(artifact), encoding="utf-8")
    digest = hashlib.sha256(audit.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="descriptor differs"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model="provider:left",
            right_model="provider:right",
            human_audit=audit,
            human_audit_sha256=digest,
            n_resamples=10,
        )


def test_direct_figure_loader_rejects_unversioned_selection_claim(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "human_audit.json"
    _write_direct_human_audit(audit, [])
    artifact = json.loads(audit.read_text(encoding="utf-8"))
    artifact["achieved_audit_design"]["selection_policy"]["algorithm"] = (
        "unversioned-selection"
    )
    audit.write_text(json.dumps(artifact), encoding="utf-8")
    digest = hashlib.sha256(audit.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="versioned selector policy"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model="provider:left",
            right_model="provider:right",
            human_audit=audit,
            human_audit_sha256=digest,
            n_resamples=10,
        )


def test_direct_figure_loader_rejects_superseded_human_audit_schema(
    tmp_path: Path,
) -> None:
    audit = tmp_path / "human_audit.json"
    _write_direct_human_audit(audit, [])
    artifact = json.loads(audit.read_text(encoding="utf-8"))
    artifact["schema_version"] = "ura-human-audit/1.1"
    audit.write_text(json.dumps(artifact), encoding="utf-8")
    digest = hashlib.sha256(audit.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="not integrity-complete"):
        figure_results.load_postrun_results(
            tmp_path,
            left_model="provider:left",
            right_model="provider:right",
            human_audit=audit,
            human_audit_sha256=digest,
            n_resamples=10,
        )
