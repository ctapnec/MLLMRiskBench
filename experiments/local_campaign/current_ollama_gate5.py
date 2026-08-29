"""Build and validate the additive Gate 5 amendment for current Ollama targets."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_BY_LABEL,
    CURRENT_OLLAMA_IMAGE_MODELS,
    CURRENT_OLLAMA_MODELS,
    CURRENT_OLLAMA_RUNNABLE_LANES,
    CURRENT_OLLAMA_TYPED_TERMINAL_LANES,
    gptgeochat_lane,
    image_lane,
    rjudge_lane,
    text_lane,
)
from experiments.local_model_readiness import validate_readiness


SCHEMA = "ura-current-ollama-gate5-amendment/1"
TEXT_ARMS = (
    "strongreject_official",
    "advbench_harmful",
    "jailbreakbench_harmful",
    "jailbreakbench_benign",
    "harmbench_text",
    "cyberseceval_mitre",
    "cyberseceval_interpreter",
    "cyberseceval_insecure_coding",
    "saladbench_base",
    "airbench_full",
    "xstest_full",
    "simplesafetytests_full",
    "decodingtrust_stereotype",
)
IMAGE_ARMS = (
    "mmsafety_official",
    "jailbreakv_full",
    "harmbench_multimodal",
    "vlsbench_release",
    "mossbench_official",
    "siuo_release",
    "figstep_full",
    "mllmguard_privacy",
    "mllmguard_bias",
    "mllmguard_toxicity",
    "mllmguard_legality",
    "holisafe_full",
)
GROUP = (
    "model,source,risk,effective_modality,expected_behavior,attacker,"
    "source_policy_id,source_policy_version"
)
SCORE_GUARD = "meta-llama/Llama-Guard-3-8B"
SCORE_GUARD_REVISION = "7327bd9f6efbbe6101dc6cc4736302b3cbb6e425"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")

PROJECTION_FIELDS = (
    "lane",
    "model_label",
    "requested_spec",
    "digest",
    "metric_mode",
    "preliminary_projection_id",
    "final_projection_id",
    "target_cap",
    "judge_cap",
    "local_guardrail_evaluations",
    "http_cap",
    "selected_clusters",
    "selected_records",
    "preliminary_root",
    "final_root",
)
ATTESTATION_FIELDS = (
    "model_label",
    "modality",
    "requested_spec",
    "digest",
    "attestation_id",
    "receipt",
    "sha256",
    "probe_root",
    "target_attempts",
    "successful_target_generations",
)
CANARY_FIELDS = (
    "lane",
    "model_label",
    "requested_spec",
    "digest",
    "metric_mode",
    "rehearsal_projection_id",
    "target_cap",
    "judge_cap",
    "local_guardrail_evaluations",
    "http_cap",
    "canary_id",
    "all_configured_stages_represented",
    "target_status",
    "attacker_status",
    "source_evaluator_status",
    "decided",
    "decision_coverage",
    "diagnostic_root",
    "disposition",
    "reason_code",
    "reason",
    "target_runtime_terminal_artifact",
    "target_attempts",
    "successful_target_generations",
)
DISPOSITION_FIELDS = ("phase", "unit", "disposition", "reason")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _stable_file(path: Path, *, label: str, max_bytes: int = 64 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical regular file")
    size = path.stat().st_size
    if size < 1 or size > max_bytes:
        raise ValueError(f"{label} has an invalid size")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ValueError(f"{label} changed while it was read")
    return payload


def _descriptor(path: Path, *, label: str) -> dict[str, object]:
    payload = _stable_file(path, label=label)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _descriptor_file(value: object, *, label: str) -> Path:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}:
        raise ValueError(f"{label} is not one file descriptor")
    raw_path = value.get("path")
    digest = value.get("sha256")
    size = value.get("bytes")
    if (
        not isinstance(raw_path, str)
        or not raw_path.startswith("/")
        or HEX64.fullmatch(str(digest)) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 1
    ):
        raise ValueError(f"{label} descriptor is malformed")
    path = Path(raw_path)
    payload = _stable_file(path, label=label)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError(f"{label} descriptor content changed")
    return path


def _canonical_dir(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical directory")
    return path


def _read_tsv(path: Path, fields: tuple[str, ...], *, label: str) -> list[dict[str, str]]:
    payload = _stable_file(path, label=label)
    text = payload.decode("utf-8")
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    if tuple(reader.fieldnames or ()) != fields:
        raise ValueError(f"{label} field order changed")
    rows = list(reader)
    if any(set(row) != set(fields) or None in row.values() for row in rows):
        raise ValueError(f"{label} contains a malformed row")
    return rows


def _exact_int(value: str, *, label: str, minimum: int = 0) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not an integer") from exc
    if str(result) != value or result < minimum:
        raise ValueError(f"{label} is not canonical")
    return result


def _load_json(path: Path, *, label: str) -> Any:
    try:
        return json.loads(_stable_file(path, label=label).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc


def _validate_roster(path: Path, *, label: str) -> dict[str, object]:
    value = _load_json(path, label=label)
    expected = [
        {
            "spec": model.spec,
            "digest": model.digest,
            "quantization": model.quantization,
            "modalities": list(model.modalities),
        }
        for model in CURRENT_OLLAMA_MODELS
    ]
    if not isinstance(value, dict) or value.get("available") is not True:
        raise ValueError(f"{label} is not an available roster")
    selected = value.get("selected")
    if not isinstance(selected, list) or len(selected) != len(expected):
        raise ValueError(f"{label} selected inventory changed")
    for observed, exact in zip(selected, expected, strict=True):
        if (
            not isinstance(observed, dict)
            or any(observed.get(field) != item for field, item in exact.items())
            or "completion" not in observed.get("capabilities", [])
        ):
            raise ValueError(f"{label} exact model identity changed")
    return value


def _validate_local_config(path: Path, *, model_label: str) -> None:
    model = CURRENT_OLLAMA_BY_LABEL[model_label]
    expected = {
        model.spec: {
            "digest": model.digest,
            "modalities": list(model.modalities),
        }
    }
    if _load_json(path, label=f"{model_label} local configuration") != expected:
        raise ValueError(f"{model_label}: exact local configuration changed")


def _expected_dispositions() -> set[tuple[str, str]]:
    return {
        *(("projection", lane) for lane in CURRENT_OLLAMA_RUNNABLE_LANES),
        *(("canary", lane) for lane in CURRENT_OLLAMA_RUNNABLE_LANES),
        *(("attestation", f"{model.label}/text") for model in CURRENT_OLLAMA_MODELS),
        *(("attestation", f"{model.label}/image") for model in CURRENT_OLLAMA_IMAGE_MODELS),
        ("integrity", "roster-final"),
    }


def _lane_contract(lane: str, label: str) -> tuple[str, str, tuple[str, ...], str]:
    model = CURRENT_OLLAMA_BY_LABEL[label]
    if lane == text_lane(model):
        return "static", "text", TEXT_ARMS, "rules,guardrail"
    if "image" in model.modalities and lane == image_lane(model):
        return "static", "image", IMAGE_ARMS, "rules,guardrail"
    if lane == rjudge_lane(model):
        return "rjudge", "text", ("rjudge_release",), "rules"
    if "image" in model.modalities and lane == gptgeochat_lane(model):
        return "gptgeochat", "image", ("gptgeochat_release",), "rules"
    raise ValueError(f"{lane}: no current Ollama lane contract")


def _base_argv(
    *,
    model_label: str,
    mode: str,
    arms: tuple[str, ...],
    judges: str,
    project_revision: Path,
    project_sha256: str,
    source_config: Path,
    source_sha256: str,
    source_conformance: Path,
    conformance_sha256: str,
    local_config: Path,
    local_config_sha256: str,
) -> list[str]:
    model = CURRENT_OLLAMA_BY_LABEL[model_label]
    result = [
        "--project-revision",
        str(project_revision),
        "--project-revision-sha256",
        project_sha256,
        "--local",
        model.spec,
        "--local-config",
        str(local_config),
        "--local-config-sha256",
        local_config_sha256,
        "--attackers",
        "replay",
        "--judges",
        judges,
        "--corpora",
        ",".join(arms),
        "--source-config",
        str(source_config),
        "--source-config-sha256",
        source_sha256,
        "--source-conformance",
        str(source_conformance),
        "--source-conformance-sha256",
        conformance_sha256,
        "--limit",
        "50",
        "--sample-seed",
        "0",
        "--seeds",
        "0",
        "--max-queries",
        "1",
        "--max-turns",
        "1",
        "--group",
        GROUP,
    ]
    if mode == "static":
        result.extend(
            [
                "--guardrail-model",
                SCORE_GUARD,
                "--guardrail-revision",
                SCORE_GUARD_REVISION,
                "--guardrail-device",
                "cuda:1",
                "--approximate-common-metrics",
            ]
        )
    return result


def build_amendment(
    *,
    control_root: Path,
    out: Path,
    expected_commit: str,
    framework_lock_id: str,
    project_revision: Path,
    project_revision_sha256: str,
    source_config: Path,
    source_config_sha256: str,
    source_conformance: Path,
    source_conformance_sha256: str,
    readiness_root: Path,
) -> dict[str, object]:
    control = _canonical_dir(control_root, label="Phase 5 Ollama control root")
    if not control.name.startswith("phase5-ollama-"):
        raise ValueError("Phase 5 Ollama control-root identity changed")
    if out.parent != control or out.name != "gate5-current-ollama-amendment.json":
        raise ValueError("current Ollama amendment path changed")
    if out.exists() or out.is_symlink():
        raise FileExistsError(f"current Ollama amendment already exists: {out}")
    if HEX40.fullmatch(expected_commit) is None or HEX64.fullmatch(framework_lock_id) is None:
        raise ValueError("current campaign code identity is malformed")
    bindings = (
        (project_revision, project_revision_sha256, "project revision"),
        (source_config, source_config_sha256, "source config"),
        (source_conformance, source_conformance_sha256, "source conformance"),
    )
    for path, digest, label in bindings:
        payload = _stable_file(path, label=label)
        if HEX64.fullmatch(digest) is None or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"{label} binding changed")

    projections = _read_tsv(
        control / "projections.tsv", PROJECTION_FIELDS, label="Ollama projections"
    )
    attestations = _read_tsv(
        control / "attestations.tsv", ATTESTATION_FIELDS, label="Ollama attestations"
    )
    canaries = _read_tsv(control / "canaries.tsv", CANARY_FIELDS, label="Ollama canaries")
    dispositions = _read_tsv(
        control / "dispositions.tsv", DISPOSITION_FIELDS, label="Ollama dispositions"
    )
    expected_lanes = list(CURRENT_OLLAMA_RUNNABLE_LANES)
    disposition_pairs = {(row["phase"], row["unit"]) for row in dispositions}
    if (
        len(projections) != 12
        or len(canaries) != 12
        or [row["lane"] for row in projections] != expected_lanes
        or [row["lane"] for row in canaries] != expected_lanes
        or len(attestations) != 6
        or len(dispositions) != 31
        or disposition_pairs != _expected_dispositions()
        or any(row["disposition"] != "completed" for row in dispositions)
    ):
        raise ValueError("current Ollama Gate 5 row inventory changed")
    by_projection = {row["lane"]: row for row in projections}
    by_canary = {row["lane"]: row for row in canaries}
    if len(by_projection) != 12 or len(by_canary) != 12:
        raise ValueError("current Ollama Gate 5 contains duplicate lanes")

    expected_attestations = {
        (model.label, modality) for model in CURRENT_OLLAMA_MODELS for modality in model.modalities
    }
    by_attestation = {(row["model_label"], row["modality"]): row for row in attestations}
    if set(by_attestation) != expected_attestations:
        raise ValueError("current Ollama attestation inventory changed")
    _validate_roster(control / "roster-start.json", label="initial Ollama roster")
    _validate_roster(control / "roster-final.json", label="final Ollama roster")

    readiness = _canonical_dir(readiness_root, label="local readiness root")
    readiness_evidence: dict[str, object] = {}
    for model in CURRENT_OLLAMA_MODELS:
        receipt = readiness / f"{model.label}.readiness.json"
        sha_file = readiness / f"{model.label}.sha256"
        receipt_payload = _stable_file(receipt, label=f"{model.label} readiness receipt")
        digest = (
            _stable_file(sha_file, label=f"{model.label} readiness digest").decode("ascii").strip()
        )
        if HEX64.fullmatch(digest) is None or hashlib.sha256(receipt_payload).hexdigest() != digest:
            raise ValueError(f"{model.label} readiness binding changed")
        validate_readiness(json.loads(receipt_payload), expected_spec=model.spec)
        readiness_evidence[model.label] = {
            "receipt": _descriptor(receipt, label=f"{model.label} readiness receipt"),
            "sha256_file": _descriptor(sha_file, label=f"{model.label} readiness digest"),
        }

    lane_rows: list[dict[str, object]] = []
    canary_target_attempts = 0
    canary_successful_generations = 0
    attestation_target_attempts = 0
    attestation_successful_generations = 0
    for (label, modality), attestation in by_attestation.items():
        model = CURRENT_OLLAMA_BY_LABEL.get(label)
        if (
            model is None
            or modality not in model.modalities
            or attestation["requested_spec"] != model.spec
            or attestation["digest"] != model.digest
        ):
            raise ValueError(f"{label}/{modality}: attestation identity changed")
        attestation_target_attempts += _exact_int(
            attestation["target_attempts"],
            label=f"{label}/{modality} attestation target attempts",
            minimum=1,
        )
        attestation_successful_generations += _exact_int(
            attestation["successful_target_generations"],
            label=f"{label}/{modality} attestation successful generations",
            minimum=1,
        )
    for lane in expected_lanes:
        projection = by_projection[lane]
        canary = by_canary[lane]
        label = projection["model_label"]
        if label not in CURRENT_OLLAMA_BY_LABEL or canary["model_label"] != label:
            raise ValueError(f"{lane}: model label changed")
        model = CURRENT_OLLAMA_BY_LABEL[label]
        mode, modality, arms, judges = _lane_contract(lane, label)
        if (
            projection["metric_mode"] != mode
            or canary["metric_mode"] != mode
            or projection["requested_spec"] != model.spec
            or canary["requested_spec"] != model.spec
            or projection["digest"] != model.digest
            or canary["digest"] != model.digest
            or canary["disposition"] != "runnable"
            or canary["target_status"] != "exercised"
            or canary["attacker_status"] != "exercised"
        ):
            raise ValueError(f"{lane}: projection/canary identity changed")
        if mode == "static":
            if canary["all_configured_stages_represented"] != "true":
                raise ValueError(f"{lane}: scoring stages were not represented")
        elif canary["source_evaluator_status"] != "exercised":
            raise ValueError(f"{lane}: source evaluator was not exercised")
        target_cap = _exact_int(projection["target_cap"], label=f"{lane} target cap", minimum=1)
        judge_cap = _exact_int(projection["judge_cap"], label=f"{lane} judge cap")
        http_cap = _exact_int(projection["http_cap"], label=f"{lane} HTTP cap")
        guard_evaluations = _exact_int(
            projection["local_guardrail_evaluations"],
            label=f"{lane} local guardrail evaluations",
        )
        clusters = _exact_int(
            projection["selected_clusters"], label=f"{lane} selected clusters", minimum=1
        )
        records = _exact_int(
            projection["selected_records"], label=f"{lane} selected records", minimum=1
        )
        canary_target_cap = _exact_int(
            canary["target_cap"], label=f"{lane} canary target cap", minimum=1
        )
        canary_judge_cap = _exact_int(canary["judge_cap"], label=f"{lane} canary judge cap")
        canary_http_cap = _exact_int(canary["http_cap"], label=f"{lane} canary HTTP cap")
        canary_guard_evaluations = _exact_int(
            canary["local_guardrail_evaluations"],
            label=f"{lane} canary local guardrail evaluations",
        )
        if (
            judge_cap != 0
            or http_cap != 0
            or canary_judge_cap != 0
            or canary_http_cap != 0
            or (mode == "static" and min(guard_evaluations, canary_guard_evaluations) < 1)
            or (mode != "static" and (guard_evaluations or canary_guard_evaluations))
        ):
            raise ValueError(f"{lane}: hosted-call cap changed")
        local_config = control / "local-configs" / f"{label}.json"
        _validate_local_config(local_config, model_label=label)
        local_config_descriptor = _descriptor(local_config, label=f"{lane} local configuration")
        attestation = by_attestation[(label, modality)]
        receipt = Path(attestation["receipt"])
        receipt_payload = _stable_file(receipt, label=f"{lane} live attestation")
        if (
            attestation["requested_spec"] != model.spec
            or attestation["digest"] != model.digest
            or HEX64.fullmatch(attestation["sha256"]) is None
            or hashlib.sha256(receipt_payload).hexdigest() != attestation["sha256"]
        ):
            raise ValueError(f"{lane}: live-attestation binding changed")
        final_root = _canonical_dir(
            Path(projection["final_root"]), label=f"{lane} final projection root"
        )
        diagnostic_root = _canonical_dir(
            Path(canary["diagnostic_root"]), label=f"{lane} canary root"
        )
        canary_target_attempts += _exact_int(
            canary["target_attempts"], label=f"{lane} target attempts", minimum=1
        )
        canary_successful_generations += _exact_int(
            canary["successful_target_generations"],
            label=f"{lane} successful target generations",
            minimum=1,
        )
        lane_rows.append(
            {
                "lane_id": lane,
                "model": {
                    "label": label,
                    "spec": model.spec,
                    "digest": model.digest,
                    "quantization": model.quantization,
                    "modalities": list(model.modalities),
                },
                "metric_mode": mode,
                "modality": modality,
                "base_argv": _base_argv(
                    model_label=label,
                    mode=mode,
                    arms=arms,
                    judges=judges,
                    project_revision=project_revision,
                    project_sha256=project_revision_sha256,
                    source_config=source_config,
                    source_sha256=source_config_sha256,
                    source_conformance=source_conformance,
                    conformance_sha256=source_conformance_sha256,
                    local_config=local_config,
                    local_config_sha256=str(local_config_descriptor["sha256"]),
                ),
                "selection": {
                    "corpora": list(arms),
                    "limit": 50,
                    "sampling_policy": "per_arm_seeded_cluster_priority_v1",
                    "sample_seed": 0,
                    "seeds": [0],
                },
                "approved_caps": {
                    "target_calls": target_cap,
                    "model_judge_calls": judge_cap,
                    "http_attempts": http_cap,
                    "deadline_seconds": 86_400,
                    "wall_time_seconds": 86_400,
                },
                "selected_clusters": clusters,
                "selected_records": records,
                "local_config": local_config_descriptor,
                "projection": {
                    "projection_id": projection["final_projection_id"],
                    "root": str(final_root),
                },
                "canary": {
                    "canary_id": canary["canary_id"],
                    "root": str(diagnostic_root),
                },
                "attestation": {
                    "attestation_id": attestation["attestation_id"],
                    "receipt": _descriptor(receipt, label=f"{lane} live attestation"),
                    "probe_root": str(
                        _canonical_dir(
                            Path(attestation["probe_root"]),
                            label=f"{lane} attestation probe root",
                        )
                    ),
                },
            }
        )

    value: dict[str, object] = {
        "schema": SCHEMA,
        "status": "approved",
        "created_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "project_commit": expected_commit,
        "framework_lock_id": framework_lock_id,
        "control_root": str(control),
        "project_revision": _descriptor(project_revision, label="project revision"),
        "source_config": _descriptor(source_config, label="source config"),
        "source_conformance": _descriptor(source_conformance, label="source conformance"),
        "readiness": readiness_evidence,
        "roster_start": _descriptor(control / "roster-start.json", label="initial Ollama roster"),
        "roster_final": _descriptor(control / "roster-final.json", label="final Ollama roster"),
        "status_tables": {
            "projections": _descriptor(control / "projections.tsv", label="Ollama projections"),
            "attestations": _descriptor(control / "attestations.tsv", label="Ollama attestations"),
            "canaries": _descriptor(control / "canaries.tsv", label="Ollama canaries"),
            "dispositions": _descriptor(control / "dispositions.tsv", label="Ollama dispositions"),
        },
        "runnable_lane_order": expected_lanes,
        "typed_terminal_lanes": {
            lane: {
                "disposition": "unavailable",
                "reason_code": "target_transport_text_only_for_image_source",
                "reason": (
                    "GPTGeoChat requires image-bearing source inputs, while this "
                    "exact Ollama target is text-only."
                ),
            }
            for lane in CURRENT_OLLAMA_TYPED_TERMINAL_LANES
        },
        "lanes": lane_rows,
        "target_execution": {
            "canary_target_attempts": canary_target_attempts,
            "canary_successful_target_generations": canary_successful_generations,
            "attestation_target_attempts": attestation_target_attempts,
            "attestation_successful_target_generations": (attestation_successful_generations),
            "total_target_attempts": (canary_target_attempts + attestation_target_attempts),
            "total_successful_target_generations": (
                canary_successful_generations + attestation_successful_generations
            ),
        },
        "unrelated_completed_work_repeated": False,
        "paid_provider_calls": 0,
    }
    payload = _canonical(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(out, flags, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)
    return value


def validate_amendment(path: Path, *, expected_commit: str | None = None) -> dict[str, Any]:
    value = _load_json(path, label="current Ollama Gate 5 amendment")
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("current Ollama Gate 5 amendment schema changed")
    if value.get("status") != "approved" or value.get("paid_provider_calls") != 0:
        raise ValueError("current Ollama Gate 5 amendment is not approved local evidence")
    if expected_commit is not None and value.get("project_commit") != expected_commit:
        raise ValueError("current Ollama Gate 5 amendment project commit changed")
    if value.get("runnable_lane_order") != list(CURRENT_OLLAMA_RUNNABLE_LANES):
        raise ValueError("current Ollama runnable lane order changed")
    expected_terminals = {
        lane: {
            "disposition": "unavailable",
            "reason_code": "target_transport_text_only_for_image_source",
            "reason": (
                "GPTGeoChat requires image-bearing source inputs, while this "
                "exact Ollama target is text-only."
            ),
        }
        for lane in CURRENT_OLLAMA_TYPED_TERMINAL_LANES
    }
    if value.get("typed_terminal_lanes") != expected_terminals:
        raise ValueError("current Ollama typed terminal inventory changed")
    rows = value.get("lanes")
    if (
        not isinstance(rows, list)
        or len(rows) != len(CURRENT_OLLAMA_RUNNABLE_LANES)
        or [row.get("lane_id") for row in rows if isinstance(row, dict)]
        != list(CURRENT_OLLAMA_RUNNABLE_LANES)
    ):
        raise ValueError("current Ollama amendment lane rows changed")
    bound_files = {
        field: _descriptor_file(value.get(field), label=field)
        for field in ("project_revision", "source_config", "source_conformance")
    }
    readiness = value.get("readiness")
    if not isinstance(readiness, dict) or set(readiness) != set(CURRENT_OLLAMA_BY_LABEL):
        raise ValueError("current Ollama readiness inventory changed")
    for model in CURRENT_OLLAMA_MODELS:
        evidence = readiness[model.label]
        if not isinstance(evidence, dict) or set(evidence) != {"receipt", "sha256_file"}:
            raise ValueError(f"{model.label} readiness evidence changed")
        receipt = _descriptor_file(evidence["receipt"], label=f"{model.label} readiness receipt")
        sha_file = _descriptor_file(
            evidence["sha256_file"], label=f"{model.label} readiness digest"
        )
        digest = sha_file.read_text(encoding="ascii").strip()
        if hashlib.sha256(receipt.read_bytes()).hexdigest() != digest:
            raise ValueError(f"{model.label} readiness digest differs")
        validate_readiness(_load_json(receipt, label="readiness receipt"), expected_spec=model.spec)
    for field in ("roster_start", "roster_final"):
        roster = _descriptor_file(value.get(field), label=field)
        _validate_roster(roster, label=field)
    tables = value.get("status_tables")
    if not isinstance(tables, dict) or set(tables) != {
        "projections",
        "attestations",
        "canaries",
        "dispositions",
    }:
        raise ValueError("current Ollama status-table inventory changed")
    table_paths = {
        field: _descriptor_file(descriptor, label=f"status table {field}")
        for field, descriptor in tables.items()
    }
    projections = _read_tsv(
        table_paths["projections"], PROJECTION_FIELDS, label="Ollama projections"
    )
    canaries = _read_tsv(table_paths["canaries"], CANARY_FIELDS, label="Ollama canaries")
    dispositions = _read_tsv(
        table_paths["dispositions"], DISPOSITION_FIELDS, label="Ollama dispositions"
    )
    by_projection = {row["lane"]: row for row in projections}
    by_canary = {row["lane"]: row for row in canaries}
    if (
        list(by_projection) != list(CURRENT_OLLAMA_RUNNABLE_LANES)
        or list(by_canary) != list(CURRENT_OLLAMA_RUNNABLE_LANES)
        or {(row["phase"], row["unit"]) for row in dispositions} != _expected_dispositions()
        or any(row["disposition"] != "completed" for row in dispositions)
    ):
        raise ValueError("current Ollama status-table inventory changed")
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("current Ollama lane row is malformed")
        lane = row.get("lane_id")
        model_value = row.get("model")
        if not isinstance(lane, str) or not isinstance(model_value, dict):
            raise ValueError("current Ollama lane model binding changed")
        label = model_value.get("label")
        model = CURRENT_OLLAMA_BY_LABEL.get(str(label))
        if model is None:
            raise ValueError(f"{lane}: current Ollama model label changed")
        mode, modality, arms, judges = _lane_contract(lane, model.label)
        if model_value != {
            "label": model.label,
            "spec": model.spec,
            "digest": model.digest,
            "quantization": model.quantization,
            "modalities": list(model.modalities),
        }:
            raise ValueError(f"{lane}: current Ollama model identity changed")
        projection = by_projection[lane]
        canary = by_canary[lane]
        selection = row.get("selection")
        approved_caps = row.get("approved_caps")
        if selection != {
            "corpora": list(arms),
            "limit": 50,
            "sampling_policy": "per_arm_seeded_cluster_priority_v1",
            "sample_seed": 0,
            "seeds": [0],
        }:
            raise ValueError(f"{lane}: approved selection changed")
        if approved_caps != {
            "target_calls": int(projection["target_cap"]),
            "model_judge_calls": 0,
            "http_attempts": 0,
            "deadline_seconds": 86_400,
            "wall_time_seconds": 86_400,
        }:
            raise ValueError(f"{lane}: approved caps changed")
        local_config_value = row.get("local_config")
        local_config = _descriptor_file(local_config_value, label=f"{lane} local configuration")
        _validate_local_config(local_config, model_label=model.label)
        if not isinstance(local_config_value, dict):
            raise ValueError(f"{lane}: local configuration descriptor changed")
        expected_argv = _base_argv(
            model_label=model.label,
            mode=mode,
            arms=arms,
            judges=judges,
            project_revision=bound_files["project_revision"],
            project_sha256=str(value["project_revision"]["sha256"]),
            source_config=bound_files["source_config"],
            source_sha256=str(value["source_config"]["sha256"]),
            source_conformance=bound_files["source_conformance"],
            conformance_sha256=str(value["source_conformance"]["sha256"]),
            local_config=local_config,
            local_config_sha256=str(local_config_value["sha256"]),
        )
        if (
            row.get("metric_mode") != mode
            or row.get("modality") != modality
            or row.get("base_argv") != expected_argv
            or row.get("selected_clusters") != int(projection["selected_clusters"])
            or row.get("selected_records") != int(projection["selected_records"])
            or row.get("projection")
            != {
                "projection_id": projection["final_projection_id"],
                "root": projection["final_root"],
            }
            or row.get("canary")
            != {"canary_id": canary["canary_id"], "root": canary["diagnostic_root"]}
        ):
            raise ValueError(f"{lane}: bound Gate 5 evidence changed")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    modes = result.add_mutually_exclusive_group(required=True)
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--validate", type=Path)
    result.add_argument("--control-root", type=Path)
    result.add_argument("--out", type=Path)
    result.add_argument("--expected-commit")
    result.add_argument("--framework-lock-id")
    result.add_argument("--project-revision", type=Path)
    result.add_argument("--project-revision-sha256")
    result.add_argument("--source-config", type=Path)
    result.add_argument("--source-config-sha256")
    result.add_argument("--source-conformance", type=Path)
    result.add_argument("--source-conformance-sha256")
    result.add_argument("--readiness-root", type=Path)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.validate is not None:
            value = validate_amendment(args.validate, expected_commit=args.expected_commit)
            print(
                json.dumps(
                    {
                        "status": "validated",
                        "schema": value["schema"],
                        "runnable_lanes": len(value["runnable_lane_order"]),
                    },
                    sort_keys=True,
                )
            )
            return 0
        required = {
            "control_root": args.control_root,
            "out": args.out,
            "expected_commit": args.expected_commit,
            "framework_lock_id": args.framework_lock_id,
            "project_revision": args.project_revision,
            "project_revision_sha256": args.project_revision_sha256,
            "source_config": args.source_config,
            "source_config_sha256": args.source_config_sha256,
            "source_conformance": args.source_conformance,
            "source_conformance_sha256": args.source_conformance_sha256,
            "readiness_root": args.readiness_root,
        }
        if any(value is None for value in required.values()):
            parser().error("--build requires every binding argument")
        value = build_amendment(**required)  # type: ignore[arg-type]
        print(
            json.dumps(
                {
                    "status": "created",
                    "schema": value["schema"],
                    "path": str(args.out),
                    "sha256": hashlib.sha256(_canonical(value)).hexdigest(),
                },
                sort_keys=True,
            )
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"current Ollama Gate 5 failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
