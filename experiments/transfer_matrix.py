"""Exact-input attack-transferability analysis (thesis V.2.4, RQ4).

For an ordered model pair A -> B, the estimand is the violation rate on B among
harmful, transferable inputs that violated A *and* whose rendered-input SHA-256
fingerprint is identical on B. Response-conditioned live conversations (for
example Crescendo) are not transferable unless explicitly replayed, because a
different target reply changes the subsequent attack.

The script consumes only current v2, grid-accounted Runner artifacts. Legacy or
unhashed evidence and rows without complete transfer provenance are rejected
before an estimand can be produced.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from pydantic import BaseModel, ValidationError  # noqa: E402
from ura.data_models import (  # noqa: E402
    SCHEMA_VERSION,
    Attempt,
    EvalResult,
    Judgment,
    Response,
    RunManifest,
)
from ura.engine_runtime_evidence import (  # noqa: E402
    validate_cell_engine_runtime_marker,
    validate_engine_runtime_artifact_version,
    validate_grid_engine_runtime_binding,
)
from ura.metrics import clustered_bootstrap_ci  # noqa: E402
from ura.model_acquisition_runtime import (  # noqa: E402
    model_acquisition_execution_descriptor,
    model_acquisition_shared_from_cell_projection,
    validate_model_acquisition_execution_descriptor,
    validate_model_acquisition_grid_binding,
    validate_model_acquisition_role_projection,
    validate_model_acquisition_role_projection_binding,
)
from experiments.analysis_integrity import analysis_source_identity  # noqa: E402
from experiments.retained_artifact_reader import load_analysis_cells  # noqa: E402
from ura.runner import (  # noqa: E402
    CODE_VERSION,
    realized_identity_summary,
    validate_persisted_judgment_trails,
    validate_planned_realized_identities,
)
from ura.strict_json import strict_json_loads  # noqa: E402


_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
_TRANSFER_ESTIMAND = (
    "P(target violation | source violation, harmful probe, transferable=true, "
    "identical rendered-input fingerprint)"
)

_NON_JUDGMENT_SUFFIXES = (
    ".results.jsonl",
    ".trails.jsonl",
    ".attempts.jsonl",
    ".responses.jsonl",
    ".checkpoint.jsonl",
)


@dataclass(frozen=True)
class TransferRecord:
    model: str
    run_id: str
    transfer_key: str
    attack_fingerprint: str
    datapoint_id: str
    label: str
    expected_behavior: str
    transferable: bool
    source_file: str
    source_cluster_id: str | None = None


def _truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def _read_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink JSON file: {path}")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON object exceeds {_MAX_JSON_BYTES} bytes: {path}")
    try:
        value = strict_json_loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise ValueError(f"cannot read valid JSON object from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def _artifact_path(directory: Path, value: Any, *, marker: Path, role: str) -> Path:
    if not isinstance(value, dict):
        raise ValueError(
            f"legacy filename-only artifact for {role} in {marker} is not measured evidence"
        )
    descriptor = value
    required = {"file", "sha256", "bytes", "records"}
    if set(descriptor) != required:
        raise ValueError(
            f"artifact descriptor for {role} in {marker} must contain exactly "
            f"{sorted(required)!r}"
        )
    value = descriptor["file"]
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise ValueError(f"unsafe or missing {role} artifact name in {marker}")
    path = directory / value
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"completion marker {marker} references invalid artifact {path}")
    expected_hash = descriptor["sha256"]
    expected_bytes = descriptor["bytes"]
    expected_records = descriptor["records"]
    if (
        not isinstance(expected_hash, str)
        or len(expected_hash) != 64
        or any(char not in "0123456789abcdef" for char in expected_hash)
    ):
        raise ValueError(f"invalid lowercase sha256 descriptor for {role} in {marker}")
    if not isinstance(expected_bytes, int) or isinstance(expected_bytes, bool) or expected_bytes < 0:
        raise ValueError(f"invalid byte count descriptor for {role} in {marker}")
    if (
        not isinstance(expected_records, int)
        or isinstance(expected_records, bool)
        or expected_records < 0
    ):
        raise ValueError(f"invalid record count descriptor for {role} in {marker}")
    actual_size = path.stat().st_size
    if actual_size != expected_bytes:
        raise ValueError(f"artifact byte-count mismatch for {role}: {path}")
    if actual_size > _MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact exceeds {_MAX_ARTIFACT_BYTES} bytes for {role}: {path}")
    payload = path.read_bytes()
    observed_hash = hashlib.sha256(payload).hexdigest()
    if observed_hash != expected_hash:
        raise ValueError(f"artifact sha256 mismatch for {role}: {path}")
    try:
        observed_records = (
            sum(bool(line.strip()) for line in payload.decode("utf-8").splitlines())
            if path.suffix == ".jsonl" else 1
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"artifact is not UTF-8 for {role}: {path}") from exc
    if observed_records != expected_records:
        raise ValueError(f"artifact record-count mismatch for {role}: {path}")
    return path


def _validate_model(
    model: type[BaseModel], value: dict[str, Any], *, path: Path, line: int | None = None,
) -> None:
    """Apply the canonical Pydantic contract and retain a useful artifact location."""
    clean = {key: item for key, item in value.items() if key != "_line"}
    location = f"{path}:{line}" if line is not None else str(path)
    try:
        model.model_validate(clean, strict=True)
    except ValidationError as exc:
        raise ValueError(
            f"{model.__name__} schema validation failed at {location}: {exc}"
        ) from exc


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _validate_source_identity(manifest: dict[str, Any], *, path: Path) -> None:
    """Require both code trees that determine a matrix cell to be content-addressed."""
    config = manifest.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"manifest {path} lacks config")
    harness = config.get("harness_source")
    if (
        not isinstance(harness, dict)
        or harness.get("algorithm") != "sha256_relative_path_size_file_digest_v1"
        or not _valid_sha256(harness.get("sha256"))
        or not isinstance(harness.get("file_count"), int)
        or isinstance(harness.get("file_count"), bool)
        or harness["file_count"] < 1
        or not isinstance(harness.get("bytes"), int)
        or isinstance(harness.get("bytes"), bool)
        or harness["bytes"] < 1
    ):
        raise ValueError(f"manifest {path} lacks a valid harness source identity")
    run = config.get("run")
    driver = run.get("driver_source") if isinstance(run, dict) else None
    if (
        not isinstance(driver, dict)
        or driver.get("module") != "run_matrix.py"
        or not _valid_sha256(driver.get("sha256"))
        or driver.get("file_count") != 1
    ):
        raise ValueError(f"manifest {path} lacks a valid experiment-driver source identity")


def _cohort_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    """Semantic run identity with only execution/target identity removed."""
    payload = copy.deepcopy(manifest)
    # These are execution identifiers, not experimental factors.  run_id is
    # itself a hash that necessarily changes when target identity changes.
    payload.pop("run_id", None)
    payload.pop("started_at", None)
    payload.pop("models", None)
    config = payload.get("config")
    if not isinstance(config, dict):
        raise ValueError("manifest.config must be an object")
    components = config.get("components")
    if not isinstance(components, dict) or "target" not in components:
        raise ValueError("manifest lacks config.components.target")
    components.pop("target")
    # These are realized outputs, not declared design factors.  Stateful attacks
    # can legitimately stop at different turns on different targets, and target-
    # generated media can likewise differ.  Exact row joins, fingerprints, and
    # completion descriptors remain the authority for every downstream
    # estimand; retaining realized counts/digests here would falsely declare
    # compatible adaptive cohorts different before those joins are inspected.
    for field in (
        "n_attempts",
        "n_responses",
        "n_judgments",
        "n_attempt_media_hashes",
        "attempt_media_hashes",
        "realized_attempts_sha256",
        "realized_identities_sha256",
        "n_realized_target_identity_observations",
        "n_realized_judge_identity_observations",
        "n_realized_judge_identity_snapshots",
    ):
        config.pop(field, None)
    realized = config.get("realized_identities")
    if not isinstance(realized, dict) or not isinstance(realized.get("judges"), list):
        raise ValueError("manifest lacks validated realized judge identities")
    # A transfer/cross-model cohort intentionally varies the target endpoint.
    # Retain each realized judge snapshot as a compatibility factor, while
    # discarding target identity and observation counts that are consequences
    # of executing a (potentially response-conditioned) cell.
    normalized_judges: list[dict[str, Any]] = []
    for item in realized["judges"]:
        if not isinstance(item, dict):
            raise ValueError("manifest has an invalid realized judge identity")
        normalized = {
            key: copy.deepcopy(value)
            for key, value in item.items()
            if key != "observations"
        }
        if not isinstance(normalized.get("snapshot"), dict):
            raise ValueError("manifest has an invalid realized judge snapshot")
        normalized_judges.append(normalized)
    config["realized_identities"] = {"judges": normalized_judges}
    run_config = config.get("run")
    if not isinstance(run_config, dict) or not run_config.get("model_spec"):
        raise ValueError("manifest lacks config.run.model_spec")
    run_config.pop("model_spec")
    # Each cell has already been checked against its own immutable attestation
    # snapshot.  That snapshot is target-specific provenance, so retaining it
    # here would make every honest cross-model cohort incompatible.  Defense
    # comparisons separately require identical planned base components and
    # compatible realized base identities in paired_compare.
    run_config.pop("expected_target_identity", None)
    for target_specific_field in (
        "api_config",
        "local_identity",
        "resolved_quantization",
    ):
        run_config.pop(target_specific_field, None)
    run_config["model_acquisition"] = (
        model_acquisition_shared_from_cell_projection(
            run_config.get("model_acquisition")
        )
    )
    return payload


def _cohort_signature(manifest: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    payload = _cohort_payload(manifest)
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), payload


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_realized_identity_inventory(
    manifest: dict[str, Any],
    marker: dict[str, Any],
    responses: list[Response],
    trails: list[dict[str, Any]],
    *,
    context: Path,
) -> dict[str, Any]:
    """Re-derive provider identities from content-addressed cell artifacts."""
    judges = manifest.get("judges")
    if (
        not isinstance(judges, list)
        or any(not isinstance(name, str) or not name for name in judges)
    ):
        raise ValueError(f"manifest {context} has invalid judge identity")
    try:
        summary = realized_identity_summary(responses, trails)
    except ValueError as exc:
        raise ValueError(
            f"realized identity validation failed for {context}: {exc}"
        ) from exc
    config = manifest.get("config")
    if not isinstance(config, dict):
        raise ValueError(f"manifest {context} lacks config")
    if config.get("realized_identities") != summary:
        raise ValueError(f"manifest realized identity inventory mismatch for {context}")
    digest = _sha256_json(summary)
    if config.get("realized_identities_sha256") != digest:
        raise ValueError(f"manifest realized identity digest mismatch for {context}")
    if marker.get("realized_identities_sha256") != digest:
        raise ValueError(f"completion marker realized identity digest mismatch for {context}")
    expected_counts = {
        "n_realized_target_identity_observations": len(responses),
        "n_realized_judge_identity_observations": len(trails),
        "n_realized_judge_identity_snapshots": len(summary["judges"]),
    }
    for field, expected in expected_counts.items():
        value = config.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise ValueError(
                f"manifest {field} mismatch for {context}: {value!r} != {expected}"
            )
    run = config.get("run")
    components = config.get("components")
    if not isinstance(run, dict) or not isinstance(components, dict):
        raise ValueError(f"manifest {context} lacks planned identity config")
    try:
        validate_planned_realized_identities(
            run, components, responses, trails, summary
        )
    except ValueError as exc:
        raise ValueError(
            f"planned/realized identity mismatch for {context}: {exc}"
        ) from exc
    return summary


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = strict_json_loads(line)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"invalid JSON at {path}:{line_no}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"non-object JSONL row at {path}:{line_no}")
        row["_line"] = line_no
        rows.append(row)
    return rows


def _completed_cell(path: Path) -> dict[str, Any]:
    stem = path.name[:-len(".jsonl")]
    manifest_path = path.with_name(f"{stem}.manifest.json")
    complete_path = path.with_name(f"{stem}.complete.json")
    error_path = path.with_name(f"{stem}.error.json")
    if error_path.exists():
        raise ValueError(f"mixed success/error artifacts for cell {stem!r}: {error_path}")
    if not manifest_path.is_file() or not complete_path.is_file():
        raise ValueError(
            f"judgment artifact {path} is not backed by both manifest and completion marker"
        )
    manifest = _read_object(manifest_path)
    marker = _read_object(complete_path)
    _validate_model(RunManifest, manifest, path=manifest_path)
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError(f"manifest {manifest_path} lacks run_id")
    if marker.get("status") != "complete" or marker.get("run_id") != run_id:
        raise ValueError(f"completion marker/manifest run_id mismatch for {stem!r}")
    models = manifest.get("models")
    if not isinstance(models, list) or len(models) != 1 or not isinstance(models[0], str):
        raise ValueError(f"transfer cell manifest must name exactly one model: {manifest_path}")

    artifacts = marker.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError(f"completion marker {complete_path} lacks artifacts map")
    required = {"attempts", "responses", "judgments", "trails", "results", "manifest"}
    if set(artifacts) != required:
        raise ValueError(
            f"completion marker {complete_path} artifact inventory differs from "
            f"{sorted(required)!r}"
        )
    if not all(isinstance(value, dict) for value in artifacts.values()):
        raise ValueError(
            f"legacy or mixed artifact inventory in {complete_path} is not measured evidence"
        )
    if (
        not isinstance(marker.get("format_version"), int)
        or isinstance(marker.get("format_version"), bool)
        or marker["format_version"] != 2
    ):
        raise ValueError(f"completion marker {complete_path} must declare integer format_version=2")
    if marker.get("code_version") != manifest.get("code_version"):
        raise ValueError(f"completion/manifest code_version mismatch for {stem!r}")
    if marker.get("schema_version") != manifest.get("schema_version"):
        raise ValueError(f"completion/manifest schema_version mismatch for {stem!r}")
    _validate_source_identity(manifest, path=manifest_path)
    run_config = (manifest.get("config") or {}).get("run")
    if not isinstance(run_config, dict):
        raise ValueError(f"completed cell manifest lacks config.run: {manifest_path}")
    try:
        legacy_runtime_free = validate_engine_runtime_artifact_version(
            attacker=run_config.get("attacker"),
            code_version=manifest.get("code_version"),
            schema_version=manifest.get("schema_version"),
            current_code_version=CODE_VERSION,
            current_schema_version=SCHEMA_VERSION,
        )
        runtime_identity, runtime_close = validate_cell_engine_runtime_marker(
            attacker=run_config.get("attacker"),
            run_config=run_config,
            completion_marker=marker,
            allow_legacy_missing=legacy_runtime_free,
        )
    except ValueError as exc:
        raise ValueError(
            f"completed cell engine runtime evidence is invalid: "
            f"{manifest_path}: {exc}"
        ) from exc
    try:
        acquisition_execution = validate_model_acquisition_role_projection(
            run_config.get("model_acquisition")
        )
    except ValueError as exc:
        raise ValueError(
            f"completed cell model-acquisition binding is invalid: "
            f"{manifest_path}: {exc}"
        ) from exc
    if run_config.get("execution_purpose") == "diagnostic_canary":
        raise ValueError(
            f"diagnostic canary is not measured postprocessing evidence: {manifest_path}"
        )
    if (
        run_config.get("execution_purpose") == "attestation_probe"
        or run_config.get("attestation_probe") is True
    ):
        raise ValueError(
            f"live-attestation probe is not measured postprocessing evidence: "
            f"{manifest_path}"
        )
    resolved = {
        role: _artifact_path(path.parent, artifacts[role], marker=complete_path, role=role)
        for role in sorted(required)
    }
    if resolved["judgments"] != path or resolved["manifest"] != manifest_path:
        raise ValueError(f"completion marker points at a different cell for {path}")

    attempts = _read_jsonl(resolved["attempts"])
    responses = _read_jsonl(resolved["responses"])
    judgments = _read_jsonl(path)
    trails = _read_jsonl(resolved["trails"])
    aggregate_results = _read_jsonl(resolved["results"])
    for row in attempts:
        _validate_model(
            Attempt, row, path=resolved["attempts"], line=int(row["_line"])
        )
    parsed_responses: list[Response] = []
    for row in responses:
        _validate_model(
            Response, row, path=resolved["responses"], line=int(row["_line"])
        )
        parsed_responses.append(Response.model_validate(
            {key: value for key, value in row.items() if key != "_line"},
            strict=True,
        ))
    parsed_judgments: list[Judgment] = []
    for row in judgments:
        _validate_model(Judgment, row, path=path, line=int(row["_line"]))
        parsed_judgments.append(Judgment.model_validate(
            {key: value for key, value in row.items() if key != "_line"},
            strict=True,
        ))
    for row in trails:
        _validate_model(
            Judgment, row, path=resolved["trails"], line=int(row["_line"])
        )
    for row in aggregate_results:
        _validate_model(
            EvalResult, row, path=resolved["results"], line=int(row["_line"])
        )
    expected_counts = {
        "n_attempts": len(attempts),
        "n_responses": len(responses),
        "n_judgments": len(judgments),
        "n_results": len(aggregate_results),
    }
    for field, observed in expected_counts.items():
        if marker.get(field) != observed:
            raise ValueError(
                f"completion count {field}={marker.get(field)!r} does not match "
                f"{observed} rows for {stem!r}"
            )
    if not attempts or not responses or not judgments:
        raise ValueError(f"completed scored cell {stem!r} has an empty core/result artifact")
    if not aggregate_results:
        from experiments.figure_results import _zero_result_guardrail_abstention_population

        if not _zero_result_guardrail_abstention_population(parsed_judgments):
            raise ValueError(
                f"completed scored cell {stem!r} has no results without an exact "
                "all-abstention population"
            )
    manifest_counts = {
        "n_attempts": len(attempts),
        "n_responses": len(responses),
        "n_judgments": len(judgments),
    }
    for field, observed in manifest_counts.items():
        if (manifest.get("config") or {}).get(field) != observed:
            raise ValueError(f"manifest {field} mismatch for {stem!r}")

    model = models[0]
    attempt_by_id: dict[str, dict[str, Any]] = {}
    for row in attempts:
        attempt_id = row.get("id")
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValueError(f"attempt without id in {resolved['attempts']}:{row['_line']}")
        if attempt_id in attempt_by_id:
            raise ValueError(f"duplicate attempt id {attempt_id!r} in {resolved['attempts']}")
        if row.get("run_id") != run_id or row.get("target") != model:
            raise ValueError(f"attempt run/model lineage mismatch for {attempt_id!r}")
        attempt_by_id[attempt_id] = row

    response_by_id: dict[str, dict[str, Any]] = {}
    for row in responses:
        attempt_id = row.get("attempt_id")
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValueError(f"response without attempt_id in {resolved['responses']}")
        if attempt_id in response_by_id:
            raise ValueError(f"duplicate response for attempt {attempt_id!r}")
        if row.get("run_id") != run_id or row.get("target") != model:
            raise ValueError(f"response run/model lineage mismatch for {attempt_id!r}")
        response_by_id[attempt_id] = row

    judgment_ids = [row.get("attempt_id") for row in judgments]
    if any(not isinstance(value, str) or not value for value in judgment_ids):
        raise ValueError(f"judgment without attempt_id in {path}")
    if len(set(judgment_ids)) != len(judgment_ids):
        raise ValueError(f"duplicate authoritative judgment attempt_id in {path}")
    if set(judgment_ids) != set(attempt_by_id) or set(judgment_ids) != set(response_by_id):
        raise ValueError(f"lossy Attempt/Response/Judgment join for completed cell {stem!r}")
    trail_ids = {row.get("attempt_id") for row in trails}
    if trail_ids != set(judgment_ids):
        raise ValueError(f"judge trails do not cover every attempt for {stem!r}")
    manifest_judges = set(manifest.get("judges") or [])
    for row in trails:
        if row.get("judge") not in manifest_judges:
            raise ValueError(f"unknown trail judge in completed cell {stem!r}")
    for role, artifact_rows in (("trails", trails), ("results", aggregate_results)):
        if any(row.get("run_id") != run_id for row in artifact_rows):
            raise ValueError(f"mixed or missing run_id in completed {role} for {stem!r}")

    validate_persisted_judgment_trails(
        attempt_by_id,
        {row.attempt_id: row for row in parsed_responses},
        {row.attempt_id: row for row in parsed_judgments},
        trails,
        manifest["config"],
        list(manifest["judges"]),
    )

    identity_summary = _validate_realized_identity_inventory(
        manifest,
        marker,
        parsed_responses,
        trails,
        context=manifest_path,
    )

    signature, signature_payload = _cohort_signature(manifest)
    return {
        "stem": stem,
        "run_id": run_id,
        "model": model,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "complete_path": complete_path,
        "artifacts": resolved,
        "attempts": attempt_by_id,
        "judgments": judgments,
        "cohort_signature": signature,
        "cohort_payload": signature_payload,
        "integrity_mode": "v2_sha256_bytes_records",
        "source_identity_validated": True,
        "realized_identities": identity_summary,
        "model_acquisition_execution": acquisition_execution,
        "engine_runtime_identity": runtime_identity,
        "engine_runtime_close": runtime_close,
    }


def _discover_facets(results: Path) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    for path in sorted(results.rglob("*.jsonl")):
        if path.name.endswith(_NON_JUDGMENT_SUFFIXES):
            continue
        stem = path.name[:-len(".jsonl")]
        manifest_path = path.with_name(f"{stem}.manifest.json")
        if not manifest_path.is_file():
            raise ValueError(f"judgment artifact {path} has no manifest for facet discovery")
        manifest = _read_object(manifest_path)
        run_config = (manifest.get("config") or {}).get("run")
        if not isinstance(run_config, dict):
            raise ValueError(f"manifest {manifest_path} lacks config.run")
        attacker = run_config.get("attacker")
        corpus = run_config.get("corpus")
        defense = run_config.get("defense")
        if not isinstance(attacker, str) or not attacker:
            raise ValueError(f"manifest {manifest_path} lacks attacker facet")
        if not isinstance(corpus, str) or not corpus:
            raise ValueError(f"manifest {manifest_path} lacks corpus facet")
        if not isinstance(defense, str) or not defense:
            raise ValueError(f"manifest {manifest_path} lacks defense facet")
        discovered.append({
            "path": path,
            "attacker": attacker,
            "corpus": corpus,
            "defense": defense,
            "manifest_path": manifest_path,
        })
    expected_markers = {
        item["path"].with_name(f"{item['path'].name[:-len('.jsonl')]}.complete.json")
        for item in discovered
    }
    observed_markers = set(results.rglob("*.complete.json"))
    orphaned_markers = sorted(observed_markers - expected_markers)
    missing_markers = sorted(expected_markers - observed_markers)
    if orphaned_markers or missing_markers:
        raise ValueError(
            "completion/judgment inventory mismatch: "
            f"orphaned={list(map(str, orphaned_markers[:3]))!r}, "
            f"missing={list(map(str, missing_markers[:3]))!r}"
        )
    judgment_stems = {
        item["path"].with_name(item["path"].name[:-len(".jsonl")])
        for item in discovered
    }
    orphaned_artifacts: list[Path] = []
    for suffix in (
        ".attempts.jsonl", ".responses.jsonl", ".trails.jsonl",
        ".results.jsonl", ".manifest.json",
    ):
        for artifact in results.rglob(f"*{suffix}"):
            base = artifact.with_name(artifact.name[:-len(suffix)])
            if base not in judgment_stems:
                orphaned_artifacts.append(artifact)
    if orphaned_artifacts:
        raise ValueError(
            "partial/orphan artifacts are not measured evidence: "
            f"{list(map(str, sorted(orphaned_artifacts)[:3]))!r}"
        )
    return discovered


def _validate_grid_scope(
    results: Path,
    *,
    attacker: str,
    corpus: str,
    defense: str,
    cells: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate requested-grid accounting for one attacker/corpus/defense facet."""
    locks = sorted([
        *results.rglob("*.grid.lock"),
        *results.rglob("*.cell.lock"),
    ])
    if locks:
        raise ValueError(f"grid execution is still locked/running: {str(locks[0])}")
    grid_paths = sorted(results.rglob("*.grid.json"))
    if not grid_paths:
        raise ValueError("measured postprocessing requires a completed grid manifest")
    relevant: list[tuple[Path, dict[str, Any]]] = []
    for path in grid_paths:
        grid = _read_object(path)
        request = grid.get("request")
        if not isinstance(request, dict):
            raise ValueError(f"grid manifest {path} lacks request")
        if (
            attacker in (request.get("attackers") or [])
            and corpus in (request.get("corpora") or [])
            and request.get("defense") == defense
        ):
            relevant.append((path, grid))
    if not relevant:
        raise ValueError(
            f"completed cells for attacker={attacker!r}, corpus={corpus!r}, "
            f"defense={defense!r} "
            "are not tracked by any grid manifest"
        )

    selected_by_marker = {
        Path(cell["complete_path"]).resolve(): cell for cell in cells
    }
    accounted_markers: set[Path] = set()
    grid_ids: list[str] = []
    for path, grid in relevant:
        if grid.get("status") == "running":
            raise ValueError(f"grid manifest is still running: {path}")
        if grid.get("status") != "complete" or grid.get("n_errors") != 0:
            raise ValueError(f"grid manifest is not completely successful: {path}")
        requested = grid.get("requested_cells")
        accounted = grid.get("accounted_cells")
        statuses = grid.get("cells")
        if (
            not isinstance(requested, int)
            or not isinstance(accounted, int)
            or requested != accounted
            or not isinstance(statuses, list)
            or len(statuses) != requested
        ):
            raise ValueError(f"incomplete grid accounting in {path}")
        request = grid["request"]
        try:
            stable_acquisition = model_acquisition_execution_descriptor(
                request.get("model_acquisition"),
                evidence_root=path.parent.resolve(),
            )
            requested_stable_acquisition = (
                validate_model_acquisition_execution_descriptor(
                    request.get("model_acquisition_execution")
                )
            )
            validate_model_acquisition_grid_binding(
                requested_stable_acquisition,
                request,
            )
        except ValueError as exc:
            raise ValueError(
                f"grid model-acquisition evidence is invalid: {path}: {exc}"
            ) from exc
        if stable_acquisition != requested_stable_acquisition:
            raise ValueError(
                f"grid model-acquisition execution identity is stale: {path}"
            )
        if request.get("execution_purpose") == "diagnostic_canary":
            raise ValueError(f"diagnostic canary is not measured evidence: {path}")
        if (
            request.get("execution_purpose") == "attestation_probe"
            or request.get("attestation_probe") is True
        ):
            raise ValueError(
                f"live-attestation probe is not measured evidence: {path}"
            )
        models = request.get("models")
        corpora = request.get("corpora")
        attackers = request.get("attackers")
        if not all(
            isinstance(values, list)
            and values
            and all(isinstance(value, str) and value for value in values)
            and len(set(values)) == len(values)
            for values in (models, corpora, attackers)
        ):
            raise ValueError(f"grid manifest {path} has invalid requested axes")
        requested_keys = {
            (model, grid_corpus, grid_attacker)
            for model in models
            for grid_corpus in corpora
            for grid_attacker in attackers
        }
        if requested != len(requested_keys):
            raise ValueError(f"grid requested_cells is not its exact Cartesian product: {path}")
        if any(not isinstance(status, dict) for status in statuses):
            raise ValueError(f"grid manifest {path} contains a non-object cell status")
        observed_keys = {
            (status.get("model_spec"), status.get("corpus"), status.get("attacker"))
            for status in statuses
        }
        if len(observed_keys) != len(statuses) or observed_keys != requested_keys:
            raise ValueError(f"grid manifest {path} has duplicate/missing requested cell keys")
        if any(status.get("status") not in {"complete", "complete_existing"} for status in statuses):
            raise ValueError(f"grid manifest {path} contains a non-complete cell")
        selected_statuses = [
            status for status in statuses
            if isinstance(status, dict)
            and status.get("attacker") == attacker
            and status.get("corpus") == corpus
        ]
        if len(selected_statuses) != len(models):
            raise ValueError(
                f"grid {path} accounts for {len(selected_statuses)} of "
                f"{len(models)} requested cells in attacker/corpus facet"
            )
        observed_models = [status.get("model_spec") for status in selected_statuses]
        if len(set(observed_models)) != len(observed_models) or set(observed_models) != set(models):
            raise ValueError(f"duplicate/missing model cells in grid facet {path}")
        for status in selected_statuses:
            if status.get("status") not in {"complete", "complete_existing"}:
                raise ValueError(
                    f"selected grid cell is not complete in {path}: {status!r}"
                )
            marker = status.get("completion_marker")
            if (
                not isinstance(marker, str)
                or not marker
                or Path(marker).name != marker
            ):
                raise ValueError(f"completed grid cell lacks completion marker in {path}")
            marker_path = (path.parent / marker).resolve()
            if marker_path in accounted_markers:
                raise ValueError(f"completion marker is accounted more than once: {marker_path}")
            cell = selected_by_marker.get(marker_path)
            if cell is None:
                raise ValueError(f"grid references an unselected/orphan completion marker: {marker_path}")
            run = (cell["manifest"].get("config") or {}).get("run") or {}
            if status.get("model_spec") != run.get("model_spec"):
                raise ValueError(f"grid/manifest model_spec mismatch for {marker_path}")
            if status.get("run_id") not in (None, cell["run_id"]):
                raise ValueError(f"grid/manifest run_id mismatch for {marker_path}")
            if status.get("target") not in (None, cell["model"]):
                raise ValueError(f"grid/manifest target mismatch for {marker_path}")
            try:
                validate_grid_engine_runtime_binding(
                    attacker=run.get("attacker"),
                    cell_identity=cell["engine_runtime_identity"],
                    cell_close=cell["engine_runtime_close"],
                    grid_request=request,
                    grid_close=grid.get("engine_runtime_close"),
                )
            except ValueError as exc:
                raise ValueError(
                    f"grid/completed-cell engine runtime mismatch for "
                    f"{marker_path}: {exc}"
                ) from exc
            try:
                validate_model_acquisition_role_projection_binding(
                    cell["model_acquisition_execution"],
                    stable_acquisition,
                    run_config=run,
                )
            except ValueError as exc:
                raise ValueError(
                    f"grid/manifest model-acquisition mismatch for {marker_path}: "
                    f"{exc}"
                ) from exc
            accounted_markers.add(marker_path)
        grid_ids.append(str(grid.get("grid_id") or path.stem))

    selected_markers = set(selected_by_marker)
    if accounted_markers != selected_markers:
        raise ValueError(
            "grid/completed-cell marker inventory mismatch for "
            f"attacker={attacker!r}, corpus={corpus!r}, defense={defense!r}: "
            f"grid={sorted(accounted_markers)!r}, cells={sorted(selected_markers)!r}"
        )
    return {
        "mode": "grid_accounted",
        "grid_ids": sorted(grid_ids),
        "grid_files": [str(path) for path, _ in relevant],
        "selected_cells": len(cells),
        "unexplained_exclusions": 0,
    }


def load(
    results: Path,
    *,
    attacker: str = "replay",
    corpus: str | None = None,
    defense: str = "none",
    historical_code_repository: Path | None = None,
) -> tuple[dict[str, dict[str, TransferRecord]], dict[str, Any]]:
    """Load one complete, compatible run per model and audit every row."""
    if historical_code_repository is not None:
        facets = load_facets(results, attacker=attacker, corpus=corpus, defense=defense,
                             historical_code_repository=historical_code_repository)
        if len(facets) != 1:
            raise ValueError("historical transfer spans multiple exact cohorts; use load_facets()")
        return next(iter(facets.values()))
    discovered = _discover_facets(results)
    error_files = sorted(results.rglob("*.error.json"))
    if error_files:
        raise ValueError(
            "measured postprocessing refuses a results tree containing failed cells: "
            f"{list(map(str, error_files[:3]))!r}"
        )
    selected = [
        item for item in discovered
        if item["attacker"] == attacker
        and (corpus is None or item["corpus"] == corpus)
        and item["defense"] == defense
    ]
    selected_corpora = sorted({item["corpus"] for item in selected})
    if corpus is None and len(selected_corpora) > 1:
        raise ValueError(
            f"attacker {attacker!r} spans multiple corpora {selected_corpora!r}; "
            "select --corpus or use load_facets()"
        )
    if not selected:
        qualifier = f", corpus={corpus!r}" if corpus is not None else ""
        raise ValueError(
            f"no judgment cells for attacker={attacker!r}{qualifier}, "
            f"defense={defense!r} in {results}"
        )
    effective_corpus = selected_corpora[0]
    cells = [_completed_cell(item["path"]) for item in selected]
    grid_audit = _validate_grid_scope(
        results,
        attacker=attacker,
        corpus=effective_corpus,
        defense=defense,
        cells=cells,
    )
    return _load_validated_cells(cells, attacker=attacker, effective_corpus=effective_corpus,
                                 defense=defense, grid_audit=grid_audit, discovered_count=len(discovered))


def _load_validated_cells(
    cells: list[dict], *, attacker: str, effective_corpus: str, defense: str,
    grid_audit: dict, discovered_count: int,
) -> tuple[dict[str, dict[str, TransferRecord]], dict[str, Any]]:
    """Unchanged row accounting after current or exact-original cell validation."""
    per_model: dict[str, dict[str, TransferRecord]] = defaultdict(dict)
    excluded: dict[str, int] = defaultdict(int)
    rows = 0

    signatures = {cell["cohort_signature"] for cell in cells}
    if len(signatures) != 1:
        details = {cell["stem"]: cell["cohort_signature"] for cell in cells}
        raise ValueError(
            "mixed/incompatible experiment cohorts (only target identity may differ): "
            f"{details!r}"
        )
    seen_models: dict[str, str] = {}
    seen_runs: set[str] = set()
    for cell in cells:
        model = cell["model"]
        run_id = cell["run_id"]
        if model in seen_models:
            raise ValueError(
                f"mixed artifacts: model {model!r} appears in runs "
                f"{seen_models[model]!r} and {run_id!r}"
            )
        if run_id in seen_runs:
            raise ValueError(f"run_id {run_id!r} is reused across model cells")
        seen_models[model] = run_id
        seen_runs.add(run_id)
        path = Path(cell["artifacts"]["judgments"])
        for row in cell["judgments"]:
            rows += 1
            if not isinstance(row, dict) or "label" not in row or "judge" not in row:
                raise ValueError(f"non-judgment row in {path}:{row.get('_line')}")
            raw = row.get("raw") or {}
            if not isinstance(raw, dict):
                raise ValueError(f"judgment raw provenance is not an object in {path}")
            if row.get("run_id") != run_id or raw.get("run_id") != run_id:
                raise ValueError(f"row/raw/manifest run_id mismatch in {path}:{row['_line']}")
            if raw.get("model") != model or raw.get("target") not in (None, model):
                raise ValueError(f"row/manifest model mismatch in {path}:{row['_line']}")
            attempt_id = row.get("attempt_id")
            attempt = cell["attempts"].get(attempt_id)
            if attempt is None:
                raise ValueError(f"judgment has no joined Attempt in {path}:{row['_line']}")
            params = attempt.get("params")
            if not isinstance(params, dict):
                raise ValueError(f"Attempt {attempt_id!r} lacks params")
            for name in (
                "policy_evaluable_turn", "policy_challenge_index",
                "policy_challenge_horizon", "turn_expected_behavior",
            ):
                if raw.get(name) != params.get(name):
                    raise ValueError(
                        f"Attempt/Judgment {name} mismatch for attempt {attempt_id!r}"
                    )
            evaluable = raw.get("policy_evaluable_turn")
            challenge_index = raw.get("policy_challenge_index")
            challenge_horizon = raw.get("policy_challenge_horizon")
            turn_expected = raw.get("turn_expected_behavior")
            if (
                not isinstance(evaluable, bool)
                or not isinstance(challenge_horizon, int)
                or isinstance(challenge_horizon, bool)
                or challenge_horizon < 1
                or turn_expected not in {"refuse", "safe_answer", "comply_safely"}
            ):
                raise ValueError(f"invalid policy-turn contract in {path}:{row['_line']}")
            eligibility = raw.get("common_metrics_eligible")
            if not isinstance(eligibility, bool):
                raise ValueError(
                    f"common_metrics_eligible must be an explicit boolean in "
                    f"{path}:{row['_line']}"
                )
            if not evaluable:
                if (
                    challenge_index is not None
                    or turn_expected != "comply_safely"
                    or eligibility is not False
                    or row.get("label") != "not_applicable"
                ):
                    raise ValueError(
                        f"invalid non-evaluable setup row in {path}:{row['_line']}"
                    )
                excluded["policy_nonevaluable_setup"] += 1
                continue
            if (
                not isinstance(challenge_index, int)
                or isinstance(challenge_index, bool)
                or not 0 <= challenge_index < challenge_horizon
                or turn_expected != raw.get("expected_behavior")
            ):
                raise ValueError(f"invalid policy challenge in {path}:{row['_line']}")
            if eligibility is not True:
                excluded["common_metrics_ineligible"] += 1
                continue
            required = (
                "model",
                "transfer_key",
                "attack_fingerprint",
                "datapoint_id",
                "expected_behavior",
                "transferable",
            )
            missing = [name for name in required if raw.get(name) is None]
            if missing:
                raise ValueError(
                    f"missing transfer provenance {missing!r} in {path}:{row['_line']}"
                )
            if not isinstance(raw["transferable"], bool):
                raise ValueError(f"transferable must be boolean in {path}:{row['_line']}")
            if raw["expected_behavior"] not in {"refuse", "safe_answer", "comply_safely"}:
                raise ValueError(f"invalid expected_behavior in {path}:{row['_line']}")
            automated_abstention = row["label"] == "not_applicable"
            model_nonresponse = (
                automated_abstention
                and row.get("score") == 0.0
                and raw.get("policy_evaluable_turn") is True
                and raw.get("common_metrics_eligible") is True
                and raw.get("stage_queried") is False
                and raw.get("policy_evaluation_status") == "model_nonresponse"
                and isinstance(raw.get("confidence"), (int, float))
                and not isinstance(raw.get("confidence"), bool)
                and float(raw["confidence"]) == 1.0
                and raw.get("parsed") is None
                and raw.get("cascade_role") == "authoritative"
                and raw.get("cascade_confident") is True
                and raw.get("metric_authority") is None
                and raw.get("required_metric") is None
            )
            if automated_abstention:
                if not model_nonresponse and not (
                    row.get("judge") == "guardrail"
                    and row.get("score") == 0.0
                    and isinstance(raw.get("confidence"), (int, float))
                    and not isinstance(raw.get("confidence"), bool)
                    and float(raw["confidence"]) == 0.0
                    and raw.get("expected_behavior")
                    in {"safe_answer", "comply_safely"}
                    and raw.get("parsed") is True
                    and raw.get("unsafe") is False
                    and raw.get("guardrail_queried") is True
                    and raw.get("over_refusal_expressible") is False
                    and raw.get("automated_decision_status") == "abstained"
                    and raw.get("abstention_reason")
                    == "guardrail_safe_cannot_adjudicate_benign_over_refusal"
                    and raw.get("cascade_role") == "authoritative"
                    and raw.get("cascade_confident") is True
                ):
                    raise ValueError(f"invalid abstention in {path}:{row['_line']}")
            elif row["label"] not in {"safe", "violation", "refusal", "over_refusal"}:
                raise ValueError(f"invalid label in {path}:{row['_line']}")
            lineage_pairs = {
                "datapoint_id": attempt.get("datapoint_id"),
                "transfer_key": params.get("transfer_key"),
                "attack_fingerprint": params.get("attack_fingerprint"),
                "transferable": params.get("transferable"),
            }
            for name, expected in lineage_pairs.items():
                if raw.get(name) != expected:
                    raise ValueError(
                        f"Attempt/Judgment {name} mismatch for attempt {attempt_id!r}"
                    )
            source_modality = raw.get("source_modality") or raw.get("modality")
            if source_modality in {"image", "audio", "video"}:
                rendered = attempt.get("rendered_input")
                current_turn = rendered[-1] if isinstance(rendered, list) and rendered else None
                attached = {
                    media.get("modality")
                    for media in (
                        current_turn.get("media") or []
                        if isinstance(current_turn, dict) else []
                    )
                    if isinstance(media, dict)
                }
                if source_modality not in attached:
                    raise ValueError(
                        f"policy-evaluable {source_modality} transfer row "
                        f"{attempt_id!r} lacks current-turn media"
                    )
            if automated_abstention:
                excluded[
                    "model_nonresponse"
                    if model_nonresponse
                    else "automated_over_refusal_abstention"
                ] += 1
                continue
            record = TransferRecord(
                model=str(raw["model"]),
                run_id=str(run_id),
                transfer_key=str(raw["transfer_key"]),
                attack_fingerprint=str(raw["attack_fingerprint"]),
                datapoint_id=str(raw["datapoint_id"]),
                source_cluster_id=str(raw.get("source_cluster_id") or raw["datapoint_id"]),
                label=str(row["label"]),
                expected_behavior=str(raw["expected_behavior"]),
                transferable=raw["transferable"],
                source_file=str(path),
            )
            prior = per_model[record.model].get(record.transfer_key)
            if prior is not None:
                raise ValueError(
                    "ambiguous repeated transfer key for model "
                    f"{record.model!r}: {record.transfer_key!r} in "
                    f"{prior.source_file!r} and {str(path)!r}; analyze one run set"
                )
            per_model[record.model][record.transfer_key] = record

    total_excluded = sum(excluded.values())
    loaded = sum(len(records) for records in per_model.values())
    if loaded + total_excluded != rows:
        raise AssertionError("internal transfer-loader accounting error")
    source_files = sorted({str(path) for cell in cells for path in cell["artifacts"].values()})
    artifact_integrity_checks = {
        "non_dry": all(
            not bool(((cell["manifest"].get("config") or {}).get("run") or {}).get(
                "dry_run"
            ))
            for cell in cells
        ),
        "v2_integrity": all(
            cell["integrity_mode"] == "v2_sha256_bytes_records" for cell in cells
        ),
        "grid_accounted": grid_audit["mode"] == "grid_accounted",
        "source_identity_validated": all(
            cell["source_identity_validated"] is True for cell in cells
        ),
        "zero_unexplained_exclusions": True,
    }
    audit = {
        "completed_cells": len(cells),
        "files_scanned": len(cells),
        "rows_scanned": rows,
        "records_loaded": loaded,
        "excluded": dict(sorted(excluded.items())),
        "explained_exclusions": total_excluded,
        "unexplained_exclusions": 0,
        "cohort_signature": next(iter(signatures)),
        "run_ids": dict(sorted(seen_models.items())),
        "judgment_source_files": {
            cell["model"]: str(cell["artifacts"]["judgments"])
            for cell in sorted(cells, key=lambda value: value["model"])
        },
        "source_files": source_files,
        "integrity_modes": {
            cell["model"]: cell["integrity_mode"]
            for cell in sorted(cells, key=lambda value: value["model"])
        },
        "facet": {
            "attacker": attacker,
            "corpus": effective_corpus,
            "defense": defense,
        },
        "discovered_judgment_cells": discovered_count,
        "selected_judgment_cells": len(cells),
        "not_selected_other_facets": discovered_count - len(cells),
        "grid_audit": grid_audit,
        "source_identity_validated": all(
            cell["source_identity_validated"] is True for cell in cells
        ),
        "artifact_integrity_ready_real_run": all(artifact_integrity_checks.values()),
        "artifact_integrity_checks": artifact_integrity_checks,
    }
    return dict(per_model), audit


def load_facets(
    results: Path,
    *,
    attacker: str = "replay",
    corpus: str | None = None,
    defense: str = "none",
    historical_code_repository: Path | None = None,
) -> dict[str, tuple[dict[str, dict[str, TransferRecord]], dict[str, Any]]]:
    """Load one strict transfer cohort per corpus for one attacker/defense."""
    if historical_code_repository is not None:
        cells = load_analysis_cells(results, code_repository=historical_code_repository)
        grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for cell in cells:
            run = cell["manifest"]["config"]["run"]
            if (run["attacker"] == attacker and run["defense"] == defense
                    and (corpus is None or run["corpus"] == corpus)):
                grouped[(run["corpus"], cell["cohort_signature"])].append(cell)
        if not grouped:
            raise ValueError("no historical transfer facets match the explicit selector")
        facets = {}
        for (name, signature), cohort in sorted(grouped.items()):
            facet = f"{name}__{signature}" if sum(key[0] == name for key in grouped) > 1 else name
            duplicate_models = len({cell["model"] for cell in cohort}) != len(cohort)
            # No arbitrary run selection or pooling across repeated conditions.
            # Retain each run as unavailable for this ordered comparison.
            subsets = [[cell] for cell in cohort] if duplicate_models else [cohort]
            for selected in subsets:
                audits = [cell["grid_audit"] for cell in selected]
                if any(audit["mode"] != "grid_accounted" for audit in audits):
                    raise ValueError("historical transfer requires original grid accounting")
                grid_audit = {"mode": "grid_accounted",
                    "grid_ids": sorted({key for audit in audits for key in audit["grid_ids"]}),
                    "grid_files": sorted({key for audit in audits for key in audit["grid_files"]}),
                    "selected_cells": len(selected), "unexplained_exclusions": 0}
                records, audit = _load_validated_cells(selected, attacker=attacker, effective_corpus=name,
                    defense=defense, grid_audit=grid_audit, discovered_count=len(cells))
                audit["retained_source_validations"] = [cell["retained_source_validation"] for cell in selected]
                key = facet
                if duplicate_models:
                    key += "__" + selected[0]["run_id"]
                    audit["comparison_unavailable_reason"] = "multiple_completed_runs_for_same_model_in_exact_cohort"
                facets[key] = records, audit
        return facets
    discovered = _discover_facets(results)
    corpora = sorted({
        item["corpus"] for item in discovered
        if item["attacker"] == attacker
        and (corpus is None or item["corpus"] == corpus)
        and item["defense"] == defense
    })
    if not corpora:
        qualifier = f", corpus={corpus!r}" if corpus is not None else ""
        raise ValueError(
            f"no facets for attacker={attacker!r}{qualifier}, "
            f"defense={defense!r} in {results}"
        )
    return {
        name: load(
            results,
            attacker=attacker,
            corpus=name,
            defense=defense,
        )
        for name in corpora
    }


def _cell(
    source: str,
    target: str,
    per_model: dict[str, dict[str, TransferRecord]],
    *,
    n_resamples: int,
    seed: int,
    minimum_unique_clusters: int = 2,
    alpha: float = 0.05,
) -> dict[str, Any]:
    if source == target:
        return {
            "value": None,
            "ci_low": None,
            "ci_high": None,
            "source_successes": 0,
            "matched": 0,
            "target_successes": 0,
            "excluded_nontransferable": 0,
            "unmatched": 0,
            "unmatched_reasons": {},
            "unexplained_exclusions": 0,
            "reason": "same_model",
        }

    source_records = list(per_model[source].values())
    harmful_source = [
        record for record in source_records if record.expected_behavior == "refuse"
    ]
    nontransferable = sum(not record.transferable for record in harmful_source)
    source_successes = [
        record
        for record in harmful_source
        if record.transferable
        and record.label == "violation"
    ]
    source_audit = {
        "common_eligible_records": len(source_records),
        "excluded_non_harmful": len(source_records) - len(harmful_source),
        "harmful_records": len(harmful_source),
        "excluded_nontransferable_harmful": nontransferable,
        "transferable_harmful_non_successes": sum(
            record.transferable and record.label != "violation"
            for record in harmful_source
        ),
        "source_successes": len(source_successes),
        "unexplained_exclusions": 0,
    }
    if not source_successes:
        return {
            "value": None,
            "ci_low": None,
            "ci_high": None,
            "source_successes": 0,
            "matched": 0,
            "target_successes": 0,
            "excluded_nontransferable": nontransferable,
            "unmatched": 0,
            "unmatched_reasons": {},
            "source_population_audit": source_audit,
            "unexplained_exclusions": 0,
            "reason": "no_transferable_harmful_source_successes",
        }

    matched: list[tuple[TransferRecord, TransferRecord]] = []
    fingerprint_mismatches = 0
    target_missing = 0
    target_nontransferable = 0
    target_construct_mismatch = 0
    target_records = per_model[target]
    for source_record in source_successes:
        target_record = target_records.get(source_record.transfer_key)
        if target_record is None:
            target_missing += 1
            continue
        if not target_record.transferable:
            target_nontransferable += 1
            continue
        if target_record.attack_fingerprint != source_record.attack_fingerprint:
            fingerprint_mismatches += 1
            continue
        if target_record.expected_behavior != "refuse":
            target_construct_mismatch += 1
            continue
        matched.append((source_record, target_record))

    unmatched = len(source_successes) - len(matched)
    unmatched_reasons = {
        "missing_target_transfer_key": target_missing,
        "target_nontransferable": target_nontransferable,
        "fingerprint_mismatch": fingerprint_mismatches,
        "target_expected_behavior_mismatch": target_construct_mismatch,
    }
    if sum(unmatched_reasons.values()) != unmatched:
        raise AssertionError("internal transfer-pair exclusion accounting error")
    if not matched:
        return {
            "value": None,
            "ci_low": None,
            "ci_high": None,
            "source_successes": len(source_successes),
            "matched": 0,
            "target_successes": 0,
            "excluded_nontransferable": nontransferable,
            "unmatched": unmatched,
            "fingerprint_mismatches": fingerprint_mismatches,
            "unmatched_reasons": unmatched_reasons,
            "source_population_audit": source_audit,
            "unexplained_exclusions": 0,
            "reason": "no_exact_rendered_input_matches",
        }

    values = [1.0 if target_record.label == "violation" else 0.0
              for _, target_record in matched]
    cluster_ids = [
        source_record.source_cluster_id or source_record.datapoint_id
        for source_record, _ in matched
    ]
    by_cluster: dict[str, list[float]] = defaultdict(list)
    for cluster_id, value in zip(cluster_ids, values):
        by_cluster[cluster_id].append(value)
    cluster_values = [
        sum(by_cluster[cluster_id]) / len(by_cluster[cluster_id])
        for cluster_id in sorted(by_cluster)
    ]
    unique_clusters = sorted(by_cluster)
    cluster_mean = sum(cluster_values) / len(cluster_values)
    cluster_rate_sd = (
        math.sqrt(sum((value - cluster_mean) ** 2 for value in cluster_values) / (
            len(cluster_values) - 1
        ))
        if len(cluster_values) >= 2 else None
    )
    source_success_clusters = sorted({
        record.source_cluster_id or record.datapoint_id for record in source_successes
    })
    lo, hi = clustered_bootstrap_ci(
        cluster_values,
        unique_clusters,
        n_resamples=n_resamples,
        seed=seed,
        alpha=alpha,
    )
    support_ok = len(unique_clusters) >= minimum_unique_clusters
    return {
        "value": cluster_mean,
        "ci_low": lo,
        "ci_high": hi,
        "source_successes": len(source_successes),
        "matched": len(matched),
        "target_successes": int(sum(values)),
        "n_unique_source_clusters": len(source_success_clusters),
        "source_success_cluster_ids": source_success_clusters,
        "source_success_cluster_set_sha256": _sha256_json(source_success_clusters),
        "n_matched_clusters": len(unique_clusters),
        "matched_cluster_ids": unique_clusters,
        "matched_cluster_set_sha256": _sha256_json(unique_clusters),
        "cluster_rate_sd": cluster_rate_sd,
        "cluster_reduction": "equal_weight_mean_of_source_prompt_intent_clusters",
        "minimum_unique_clusters": minimum_unique_clusters,
        "support_gate_passed": support_ok,
        "excluded_nontransferable": nontransferable,
        "unmatched": unmatched,
        "fingerprint_mismatches": fingerprint_mismatches,
        "unmatched_reasons": unmatched_reasons,
        "source_population_audit": source_audit,
        "unexplained_exclusions": 0,
        "reason": None,
    }


def build_matrix(
    per_model: dict[str, dict[str, TransferRecord]],
    *,
    n_resamples: int = 2000,
    seed: int = 0,
    load_audit: dict[str, Any] | None = None,
    minimum_unique_clusters: int = 2,
    alpha: float = 0.05,
) -> dict[str, Any]:
    if minimum_unique_clusters < 2:
        raise ValueError("transfer minimum_unique_clusters must be at least 2")
    models = sorted(per_model)
    run_ids: dict[str, str] = {}
    source_files: dict[str, list[str]] = {}
    for model in models:
        observed_runs = {record.run_id for record in per_model[model].values()}
        if len(observed_runs) != 1:
            raise ValueError(f"model {model!r} mixes run_ids: {sorted(observed_runs)!r}")
        run_ids[model] = next(iter(observed_runs))
        source_files[model] = sorted(
            {record.source_file for record in per_model[model].values()}
        )
    audit = load_audit or {}
    cells: dict[str, dict[str, dict[str, Any]]] = {}
    for source in models:
        cells[source] = {}
        for target in models:
            cell = _cell(
                source,
                target,
                per_model,
                n_resamples=n_resamples,
                seed=seed,
                minimum_unique_clusters=minimum_unique_clusters,
                alpha=alpha,
            )
            cells[source][target] = cell
    estimated_cells = [
        cells[source][target]
        for source in models for target in models
        if source != target and cells[source][target].get("value") is not None
    ]
    source_success_cells = [
        cells[source][target]
        for source in models for target in models
        if source != target
        and cells[source][target].get("source_successes", 0) > 0
    ]
    support_ok = bool(estimated_cells) and all(
        cell.get("support_gate_passed") is True for cell in estimated_cells
    )
    exact_input_coverage_ok = all(
        cell.get("unmatched") == 0 for cell in source_success_cells
    )
    analysis_readiness_checks = {
        "artifact_integrity_ready_real_run": bool(
            audit.get("artifact_integrity_ready_real_run")
        ),
        "at_least_one_estimable_ordered_cell": bool(estimated_cells),
        "all_estimated_cells_have_cluster_support": support_ok,
        "complete_exact_input_coverage": exact_input_coverage_ok,
        "complete_transfer_population": audit.get("explained_exclusions", 0) == 0,
    }
    return {
        "schema_version": "2.1",
        "analysis_kind": "diagnostic_conditional_transfer",
        "analysis_scope": (
            "descriptive_ordered_source_to_target_cells_conditioned_on_source_success"
        ),
        "analysis_status": (
            "conditional_descriptive_ready"
            if all(analysis_readiness_checks.values())
            else "conditional_descriptive_not_estimable_or_incomplete"
        ),
        "estimand": _TRANSFER_ESTIMAND,
        "multiplicity": {
            "status": "outside_holm_conditional_descriptive",
            "reason": (
                "ordered source-target cells condition on different source-success "
                "populations and have no declared null p-value"
            ),
        },
        "models": models,
        "run_ids": run_ids,
        "judgment_source_files": source_files,
        "cells": cells,
        "bootstrap": {
            "unit": "source prompt/intent cluster",
            "reduction": "equal weight per unique cluster",
            "confidence_level": 1.0 - alpha,
            "n_resamples": n_resamples,
            "seed": seed,
        },
        "support_gate_passed": support_ok,
        "exact_input_coverage_gate_passed": exact_input_coverage_ok,
        "support_design": {
            "minimum_unique_clusters": minimum_unique_clusters,
            "qualification": (
                "descriptive support threshold only; no null hypothesis or power "
                "claim is defined for conditional transfer cells"
            ),
        },
        "analysis_ready_real_run": all(analysis_readiness_checks.values()),
        "analysis_readiness_checks": analysis_readiness_checks,
        "analysis_source": analysis_source_identity([
            Path(__file__), Path(__file__).resolve().parents[1] / "src" / "ura" / "metrics.py",
            *([Path(__file__).with_name("retained_artifact_reader.py")]
              if "retained_source_validations" in audit else []),
        ]),
        "load_audit": audit,
    }


def _safe_component(value: str) -> str:
    rendered = "".join(char if char.isalnum() or char in "-_" else "-" for char in value)
    return rendered.strip("-") or "facet"


def _write_json_create_only(path: Path, value: object) -> None:
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(
                json.dumps(
                    value,
                    indent=2,
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(f"transfer output already exists: {path}") from exc


def _heatmap(
    result: dict[str, Any], out: Path, *, filename: str = "transfer_matrix.png",
) -> bool:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    models = result["models"]
    cells = result["cells"]
    grid = [
        [
            float("nan") if cells[a][b]["value"] is None
            else float(cells[a][b]["value"])
            for b in models
        ]
        for a in models
    ]
    fig, ax = plt.subplots(
        figsize=(1.2 + 0.75 * len(models), 1.0 + 0.7 * len(models))
    )
    cmap = plt.get_cmap("Blues").copy()
    cmap.set_bad(color="#e5e7eb")
    im = ax.imshow(grid, cmap=cmap, vmin=0, vmax=1)
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels(models, rotation=30, ha="right", fontsize=8)
    ax.set_yticks(range(len(models)))
    ax.set_yticklabels(models, fontsize=8)
    ax.set_xlabel("target model B")
    ax.set_ylabel("source model A")
    ax.set_title("Exact-input transferability A -> B")
    for i, source in enumerate(models):
        for j, target in enumerate(models):
            cell = cells[source][target]
            value = cell["value"]
            label = "-" if value is None else f"{value:.0%}\n(n={cell['matched']})"
            ax.text(
                j,
                i,
                label,
                ha="center",
                va="center",
                color="white" if value is not None and value > 0.5 else "#0b0b0b",
                fontsize=7,
            )
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out / filename, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return True


def _print_matrix(result: dict[str, Any], *, corpus: str) -> None:
    print(f"transfer A->B for corpus={corpus!r} (exact inputs; rows=source):")
    print("            " + "  ".join(f"{model[:10]:>10}" for model in result["models"]))
    for source in result["models"]:
        rendered = []
        for target in result["models"]:
            cell = result["cells"][source][target]
            rendered.append(
                "       -  " if cell["value"] is None
                else f"{cell['value']:>8.0%}/{cell['matched']:<2}"
            )
        print(f"{source[:10]:>10}  " + "  ".join(rendered))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exact-input transferability matrix")
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--historical-code-repository", type=Path)
    parser.add_argument("--bootstrap", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--minimum-unique-clusters", type=int, default=2,
        help="required minimum source prompt/intent clusters per estimable cell",
    )
    parser.add_argument("--alpha", type=float, default=0.05)
    parser.add_argument(
        "--attacker", default="replay",
        help="attacker facet (default: replay; response-conditioned Crescendo is not pooled)",
    )
    parser.add_argument(
        "--defense",
        default="none",
        help="exact defense facet (default: none; defended cells are not pooled)",
    )
    parser.add_argument(
        "--corpus", default=None,
        help="optional corpus facet; without it, write one matrix per available corpus",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="create-only output directory (default: write under RESULTS)",
    )
    args = parser.parse_args(argv)
    if args.bootstrap < 1:
        parser.error("--bootstrap must be positive")
    if args.minimum_unique_clusters < 2:
        parser.error("--minimum-unique-clusters must be at least 2")
    if not 0 < args.alpha < 1:
        parser.error("--alpha must be strictly between 0 and 1")
    try:
        loaded_facets = load_facets(
            args.results,
            attacker=args.attacker,
            corpus=args.corpus,
            defense=args.defense,
            **({"historical_code_repository": args.historical_code_repository}
               if args.historical_code_repository is not None else {}),
        )
    except ValueError as exc:
        print(f"transfer input validation failed: {exc}", file=sys.stderr)
        return 1
    results_by_corpus: dict[str, dict[str, Any]] = {}
    not_applicable: dict[str, dict[str, Any]] = {}
    try:
        for corpus_name, (per_model, audit) in loaded_facets.items():
            if len(per_model) < 2:
                if (
                    audit.get("records_loaded") == 0
                    and audit.get("explained_exclusions") == audit.get("rows_scanned")
                    and len(audit.get("run_ids", {})) >= 2
                ):
                    not_applicable[corpus_name] = {
                        "reason": "no_common_metrics_eligible_transfer_records",
                        "load_audit": audit,
                        "unexplained_exclusions": 0,
                    }
                    continue
                not_applicable[corpus_name] = {
                    "reason": audit.get("comparison_unavailable_reason", "insufficient_eligible_models"),
                    "eligible_models": sorted(per_model),
                    "eligible_model_count": len(per_model),
                    "minimum_required": 2,
                    "load_audit": audit,
                    "unexplained_exclusions": 0,
                }
                continue
            results_by_corpus[corpus_name] = build_matrix(
                per_model,
                n_resamples=args.bootstrap,
                seed=args.seed,
                load_audit=audit,
                minimum_unique_clusters=args.minimum_unique_clusters,
                alpha=args.alpha,
            )
    except ValueError as exc:
        print(f"transfer analysis validation failed: {exc}", file=sys.stderr)
        return 1

    output_dir = args.output_dir or args.results
    if args.output_dir is not None:
        if output_dir.exists() or output_dir.is_symlink():
            print(
                f"transfer output directory already exists: {output_dir}",
                file=sys.stderr,
            )
            return 1
        output_dir.mkdir(parents=True, exist_ok=False)
    existing_outputs = sorted(output_dir.glob("transfer_matrix*"))
    if existing_outputs:
        print(
            f"transfer output already exists: {existing_outputs[0]}",
            file=sys.stderr,
        )
        return 1

    output = output_dir / "transfer_matrix.json"
    try:
        if len(results_by_corpus) == 1 and not not_applicable:
            corpus_name, result = next(iter(results_by_corpus.items()))
            _write_json_create_only(output, result)
            _heatmap(result, output_dir)
            _print_matrix(result, corpus=corpus_name)
        else:
            artifacts: dict[str, dict[str, str]] = {}
            for corpus_name, result in results_by_corpus.items():
                facet_stem = (
                    f"transfer_matrix__{_safe_component(args.attacker)}__"
                    f"{_safe_component(corpus_name)}"
                )
                json_path = output_dir / f"{facet_stem}.json"
                png_name = f"{facet_stem}.png"
                _write_json_create_only(json_path, result)
                artifacts[corpus_name] = {"json": json_path.name}
                if _heatmap(result, output_dir, filename=png_name):
                    artifacts[corpus_name]["png"] = png_name
                _print_matrix(result, corpus=corpus_name)
            index = {
                "schema_version": "2.1-faceted",
                "attacker": args.attacker,
                "defense": args.defense,
                "corpora": sorted(results_by_corpus),
                "artifacts": artifacts,
                "facets": results_by_corpus,
                "not_applicable_facets": not_applicable,
                "unexplained_exclusions": 0,
                "analysis_source": analysis_source_identity([
                    Path(__file__),
                    Path(__file__).resolve().parents[1] / "src" / "ura" / "metrics.py",
                    *([Path(__file__).with_name("retained_artifact_reader.py")]
                      if args.historical_code_repository is not None else []),
                ]),
            }
            _write_json_create_only(output, index)
    except ValueError as exc:
        print(f"transfer output validation failed: {exc}", file=sys.stderr)
        return 1
    excluded = {
        corpus_name: result["load_audit"].get("excluded", {})
        for corpus_name, result in results_by_corpus.items()
    }
    print(
        f"wrote {output}; explained row exclusions by corpus: {excluded}; "
        f"not-applicable facets: {sorted(not_applicable)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
