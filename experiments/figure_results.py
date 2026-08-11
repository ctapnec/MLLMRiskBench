"""Strict, paired estimands for the three measured Chapter V figures.

This module deliberately does more than discover JSONL files.  A measured point
is admitted only when it comes from a version-2, content-addressed completion
marker named by a fully completed matrix grid.  Every core artifact is validated
against the Pydantic release schema and every Attempt -> Response -> Judgment ->
trail join is reconstructed before analysis.

Corpora are always separate facets.  The model figure reports exact paired
cross-target endpoint differences, the category figure reports the same paired
difference within risk/effective-modality cells, and the safety--utility figure
reports same-target paired defense effects.  No marginal model ranking and no
cross-corpus denominator is produced here.
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from pydantic import ValidationError

from experiments.paired_compare import compare_cells
from experiments.analysis_integrity import (
    analysis_source_identity,
    read_bound_json,
    validate_analysis_source_identity,
)
from ura.data_models import (
    SCHEMA_VERSION,
    Attempt,
    EvalResult,
    Judgment,
    Response,
    RunManifest,
)
from ura.runner import CODE_VERSION, realized_identity_summary

_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_JSONL_BYTES = 512 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 16 * 1024 * 1024
_REQUIRED_ARTIFACTS = frozenset({
    "attempts", "responses", "judgments", "trails", "results", "manifest",
})
_COMPLETE_STATUSES = frozenset({"complete", "complete_existing"})
_EXPECTED_BEHAVIORS = frozenset({"refuse", "safe_answer", "comply_safely"})
_HEX = frozenset("0123456789abcdef")


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


@dataclass(frozen=True)
class _GridReference:
    grid_id: str
    grid_path: Path
    request: dict[str, Any]
    status: dict[str, Any]


@dataclass(frozen=True)
class _Unit:
    corpus: str
    source: str
    datapoint_id: str
    seed: int
    expected_behavior: str
    risk_category: str
    declared_modality: str
    effective_modality: str
    eligible: bool
    value: float
    attack_fingerprint: str
    transfer_key: str

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (self.corpus, self.source, self.datapoint_id, self.seed)

    @property
    def cluster(self) -> tuple[str, str, str]:
        return (self.corpus, self.source, self.datapoint_id)


def _strict_loads(text: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r} is forbidden")

    return json.loads(text, parse_constant=reject_constant)


def _read_object(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"expected regular non-symlink JSON file: {path}")
    if path.stat().st_size > _MAX_JSON_BYTES:
        raise ValueError(f"JSON object exceeds {_MAX_JSON_BYTES} bytes: {path}")
    value = _strict_loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _iter_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"expected regular non-symlink JSONL file: {path}")
    if path.stat().st_size > _MAX_JSONL_BYTES:
        raise ValueError(f"JSONL artifact exceeds {_MAX_JSONL_BYTES} bytes: {path}")
    with path.open("rb") as handle:
        line_number = 0
        while True:
            raw = handle.readline(_MAX_JSONL_LINE_BYTES + 1)
            if not raw:
                return
            line_number += 1
            if len(raw) > _MAX_JSONL_LINE_BYTES:
                raise ValueError(
                    f"JSONL row exceeds {_MAX_JSONL_LINE_BYTES} bytes: "
                    f"{path}:{line_number}"
                )
            if not raw.strip():
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"invalid UTF-8 JSONL row {path}:{line_number}") from exc
            value = _strict_loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"non-object JSONL row {path}:{line_number}")
            yield line_number, value


def _jsonl_objects(path: Path) -> list[dict[str, Any]]:
    return [value for _, value in _iter_jsonl(path)]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _record_count(path: Path) -> int:
    if path.name.endswith(".manifest.json"):
        _read_object(path)
        return 1
    return sum(1 for _ in _iter_jsonl(path))


def _nonblank(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-blank string")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{label} must be a non-empty list of unique strings")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _inside(root: Path, path: Path) -> Path:
    root_resolved = root.resolve()
    resolved = path.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"grid references a path outside the results root: {path}") from exc
    return resolved


def _validate_source_identity(manifest: RunManifest, path: Path) -> None:
    harness = manifest.config.get("harness_source")
    if (
        not isinstance(harness, dict)
        or harness.get("algorithm") != "sha256_relative_path_size_file_digest_v1"
        or not isinstance(harness.get("sha256"), str)
        or len(harness["sha256"]) != 64
        or any(character not in _HEX for character in harness["sha256"].lower())
        or _integer(harness.get("file_count"), f"harness file_count in {path}", minimum=1) < 1
        or _integer(harness.get("bytes"), f"harness bytes in {path}", minimum=1) < 1
    ):
        raise ValueError(f"manifest lacks a valid harness source identity: {path}")
    run = manifest.config.get("run")
    driver = run.get("driver_source") if isinstance(run, dict) else None
    if (
        not isinstance(driver, dict)
        or driver.get("module") != "run_matrix.py"
        or not isinstance(driver.get("sha256"), str)
        or len(driver["sha256"]) != 64
        or any(character not in _HEX for character in driver["sha256"].lower())
        or driver.get("file_count") != 1
    ):
        raise ValueError(f"manifest lacks a valid experiment-driver source identity: {path}")


def _grid_allowlist(root: Path) -> dict[Path, list[_GridReference]]:
    if not root.is_dir():
        raise ValueError(f"results path is not a directory: {root}")
    locks = sorted([*root.rglob("*.grid.lock"), *root.rglob("*.cell.lock")])
    if locks:
        raise ValueError(f"results cohort is still locked/running: {locks[0]}")
    errors = sorted(root.rglob("*.error.json"))
    if errors:
        raise ValueError(f"results cohort contains failed cell(s): {errors[0]}")
    grid_paths = sorted(root.rglob("*.grid.json"))
    if not grid_paths:
        raise ValueError("measured figures require completed matrix grid manifests")

    allowlist: dict[Path, list[_GridReference]] = defaultdict(list)
    for grid_path in grid_paths:
        grid = _read_object(grid_path)
        grid_id = _nonblank(grid.get("grid_id"), f"grid_id in {grid_path}")
        if grid_path.name != f"{grid_id}.grid.json":
            raise ValueError(f"grid filename/id mismatch: {grid_path}")
        request = grid.get("request")
        if not isinstance(request, dict):
            raise ValueError(f"grid lacks its request: {grid_path}")
        models = _string_list(request.get("models"), f"request.models in {grid_path}")
        corpora = _string_list(request.get("corpora"), f"request.corpora in {grid_path}")
        attackers = _string_list(
            request.get("attackers"), f"request.attackers in {grid_path}"
        )
        _nonblank(request.get("defense"), f"request.defense in {grid_path}")
        if request.get("dry_run") is not False:
            raise ValueError(f"measured grid must explicitly declare dry_run=false: {grid_path}")
        requested = len(models) * len(corpora) * len(attackers)
        if grid.get("status") != "complete" or grid.get("n_errors") != 0:
            raise ValueError(f"grid is not an error-free completed grid: {grid_path}")
        if (
            _integer(grid.get("requested_cells"), f"requested_cells in {grid_path}")
            != requested
            or _integer(grid.get("accounted_cells"), f"accounted_cells in {grid_path}")
            != requested
        ):
            raise ValueError(f"grid requested/accounted count mismatch: {grid_path}")
        statuses = grid.get("cells")
        if not isinstance(statuses, list) or len(statuses) != requested:
            raise ValueError(f"grid cell inventory is incomplete: {grid_path}")

        expected = {(corpus, model, attacker) for corpus in corpora for model in models
                    for attacker in attackers}
        observed: set[tuple[str, str, str]] = set()
        markers_in_grid: set[Path] = set()
        for status in statuses:
            if not isinstance(status, dict) or status.get("status") not in _COMPLETE_STATUSES:
                raise ValueError(f"grid has a non-complete cell: {grid_path}")
            identity = (
                _nonblank(status.get("corpus"), f"cell corpus in {grid_path}"),
                _nonblank(status.get("model_spec"), f"cell model_spec in {grid_path}"),
                _nonblank(status.get("attacker"), f"cell attacker in {grid_path}"),
            )
            if identity in observed:
                raise ValueError(f"grid has duplicate cell identity {identity!r}: {grid_path}")
            observed.add(identity)
            _nonblank(status.get("run_id"), f"cell run_id in {grid_path}")
            marker_name = _nonblank(
                status.get("completion_marker"), f"completion marker in {grid_path}"
            )
            if Path(marker_name).name != marker_name:
                raise ValueError(f"unsafe completion marker name in {grid_path}: {marker_name!r}")
            marker_path = _inside(root, grid_path.parent / marker_name)
            if marker_path in markers_in_grid:
                raise ValueError(f"grid references one marker more than once: {grid_path}")
            if not marker_path.is_file() or marker_path.is_symlink():
                raise ValueError(f"grid references an invalid completion marker: {marker_path}")
            markers_in_grid.add(marker_path)
            allowlist[marker_path].append(_GridReference(grid_id, grid_path, request, status))
        if observed != expected:
            raise ValueError(
                f"grid Cartesian cell inventory mismatch: missing={sorted(expected - observed)!r}, "
                f"extra={sorted(observed - expected)!r}"
            )

    discovered = {path.resolve() for path in root.rglob("*.complete.json")}
    admitted = set(allowlist)
    if discovered != admitted:
        raise ValueError(
            "completion-marker/grid allowlist mismatch: "
            f"orphaned={sorted(str(path) for path in discovered - admitted)!r}, "
            f"missing={sorted(str(path) for path in admitted - discovered)!r}"
        )
    return dict(allowlist)


def _resolve_artifact(marker_path: Path, marker: dict[str, Any], name: str) -> Path:
    descriptor = marker["artifacts"].get(name)
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "file", "sha256", "bytes", "records",
    }:
        raise ValueError(f"artifact {name!r} lacks an exact v2 descriptor: {marker_path}")
    filename = descriptor.get("file")
    if not isinstance(filename, str) or Path(filename).name != filename:
        raise ValueError(f"unsafe artifact name in {marker_path}: {filename!r}")
    digest = descriptor.get("sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in _HEX for character in digest.lower())
    ):
        raise ValueError(f"invalid artifact SHA-256 descriptor: {marker_path}:{name}")
    byte_count = _integer(descriptor.get("bytes"), f"artifact bytes in {marker_path}")
    record_count = _integer(descriptor.get("records"), f"artifact records in {marker_path}")
    artifact = marker_path.parent / filename
    if not artifact.is_file() or artifact.is_symlink():
        raise ValueError(f"completion marker references invalid file: {artifact}")
    if byte_count != artifact.stat().st_size:
        raise ValueError(f"artifact byte-count mismatch: {artifact}")
    if digest.lower() != _sha256_file(artifact):
        raise ValueError(f"artifact digest mismatch: {artifact}")
    if record_count != _record_count(artifact):
        raise ValueError(f"artifact record-count mismatch: {artifact}")
    return artifact


def _pydantic_rows(
    rows: list[dict[str, Any]], model: type[Attempt | Response | Judgment | EvalResult], path: Path,
) -> list[Any]:
    validated: list[Any] = []
    for line_number, row in enumerate(rows, 1):
        try:
            validated.append(model.model_validate(row, strict=True))
        except ValidationError as exc:
            raise ValueError(f"schema-invalid {model.__name__} at {path}:{line_number}: {exc}") from exc
    return validated


def _canonical_response_digest(response: Response) -> str:
    return _sha256_json(response.model_dump(mode="json"))


def _validate_trails(
    trails: list[dict[str, Any]], *, attempts: dict[str, Attempt], responses: dict[str, Response],
    judgments: dict[str, Judgment], manifest: RunManifest, path: Path,
) -> None:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for line_number, row in enumerate(trails, 1):
        try:
            trail_judgment = Judgment.model_validate({
                "attempt_id": row.get("attempt_id"),
                "judge": row.get("judge"),
                "label": row.get("label"),
                "score": row.get("score"),
                "run_id": row.get("run_id"),
            }, strict=True)
        except ValidationError as exc:
            raise ValueError(f"schema-invalid trail judgment at {path}:{line_number}: {exc}") from exc
        attempt_id = trail_judgment.attempt_id
        if attempt_id not in attempts or row.get("run_id") != manifest.run_id:
            raise ValueError(f"trail lineage mismatch at {path}:{line_number}")
        stage = _integer(row.get("stage"), f"trail stage at {path}:{line_number}")
        confidence = row.get("confidence")
        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not math.isfinite(float(confidence))
            or not 0.0 <= float(confidence) <= 1.0
        ):
            raise ValueError(f"invalid trail confidence at {path}:{line_number}")
        if row.get("parsed") is not None and not isinstance(row.get("parsed"), bool):
            raise ValueError(f"invalid trail parse status at {path}:{line_number}")
        if not isinstance(row.get("cascade_confident"), bool):
            raise ValueError(f"missing boolean cascade confidence at {path}:{line_number}")
        if row.get("cascade_role") not in {"authoritative", "shadow"}:
            raise ValueError(f"invalid cascade role at {path}:{line_number}")
        if row.get("cascade_policy") != "first_confident_with_full_shadow_trail":
            raise ValueError(f"unknown cascade policy at {path}:{line_number}")
        attempt = attempts[attempt_id]
        response = responses[attempt_id]
        final = judgments[attempt_id]
        lineage = {
            "datapoint_id": attempt.datapoint_id,
            "model": response.target,
            "attacker": attempt.attacker,
            "seed": attempt.seed,
            "requested_seed": attempt.seed,
            "turn_index": attempt.turn_index,
            "attack_fingerprint": attempt.params.get("attack_fingerprint"),
            "transfer_key": attempt.params.get("transfer_key"),
            "transferable": attempt.params.get("transferable"),
            "response_conditioned": bool(attempt.params.get("response_conditioned")),
            "replayed_transcript": bool(attempt.params.get("replayed_transcript")),
            "target_sampling_control": response.raw.get("target_sampling_control", "unknown"),
            "response_sha256": _canonical_response_digest(response),
        }
        for field, expected in lineage.items():
            if row.get(field) != expected:
                raise ValueError(
                    f"trail {field} mismatch for attempt {attempt_id!r} at {path}:{line_number}"
                )
        if stage >= len(manifest.judges) or row.get("judge") != manifest.judges[stage]:
            raise ValueError(f"trail judge order differs from manifest at {path}:{line_number}")
        if row.get("cascade_role") == "authoritative" and (
            row.get("judge") != final.judge
            or row.get("label") != final.label
            or float(row.get("score")) != final.score
        ):
            raise ValueError(f"authoritative trail/final Judgment mismatch at {path}:{line_number}")
        grouped[attempt_id].append(row)

    if set(grouped) != set(attempts):
        raise ValueError(f"judge trails do not cover exactly the attempt population: {path}")
    for attempt_id, rows in grouped.items():
        stages = sorted(_integer(row.get("stage"), "trail stage") for row in rows)
        if stages != list(range(len(rows))) or len(stages) != len(set(stages)):
            raise ValueError(f"trail stages are duplicate/non-contiguous for {attempt_id!r}")
        authorities = [row for row in rows if row.get("cascade_role") == "authoritative"]
        if len(authorities) != 1 or authorities[0].get("cascade_confident") is not True:
            raise ValueError(f"trail must have one confident authority for {attempt_id!r}")


def _validate_realized_identity_inventory(
    manifest: RunManifest,
    marker: dict[str, Any],
    responses: list[Response],
    trails: list[dict[str, Any]],
    *,
    path: Path,
) -> dict[str, Any]:
    """Recompute the realized provider inventory from the hashed artifacts."""
    try:
        summary = realized_identity_summary(responses, trails)
    except ValueError as exc:
        raise ValueError(f"realized identity validation failed for {path}: {exc}") from exc
    digest = _sha256_json(summary)
    if manifest.config.get("realized_identities") != summary:
        raise ValueError(f"manifest realized identity inventory mismatch: {path}")
    if manifest.config.get("realized_identities_sha256") != digest:
        raise ValueError(f"manifest realized identity digest mismatch: {path}")
    if marker.get("realized_identities_sha256") != digest:
        raise ValueError(f"completion marker realized identity digest mismatch: {path}")
    expected_counts = {
        "n_realized_target_identity_observations": len(responses),
        "n_realized_judge_identity_observations": len(trails),
        "n_realized_judge_identity_snapshots": len(summary["judges"]),
    }
    for field, expected in expected_counts.items():
        value = manifest.config.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise ValueError(
                f"manifest {field} mismatch for {path}: {value!r} != {expected}"
            )
    return summary


def _validate_cell(marker_path: Path, refs: list[_GridReference]) -> dict[str, Any]:
    marker = _read_object(marker_path)
    if marker.get("status") != "complete" or marker.get("format_version") != 2:
        raise ValueError(f"invalid v2 completion marker: {marker_path}")
    run_id = _nonblank(marker.get("run_id"), f"marker run_id in {marker_path}")
    artifacts = marker.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != _REQUIRED_ARTIFACTS:
        raise ValueError(f"completion marker artifact inventory mismatch: {marker_path}")
    resolved = {
        name: _resolve_artifact(marker_path, marker, name) for name in _REQUIRED_ARTIFACTS
    }
    try:
        manifest = RunManifest.model_validate(
            _read_object(resolved["manifest"]), strict=True
        )
    except ValidationError as exc:
        raise ValueError(f"schema-invalid RunManifest {resolved['manifest']}: {exc}") from exc
    if (
        manifest.run_id != run_id
        or marker.get("code_version") != manifest.code_version
        or marker.get("schema_version") != manifest.schema_version
    ):
        raise ValueError(f"marker/manifest lineage mismatch: {marker_path}")
    if (
        manifest.code_version != CODE_VERSION
        or manifest.schema_version != SCHEMA_VERSION
    ):
        raise ValueError(
            "measured figures require artifacts from the current runner/schema "
            f"({CODE_VERSION}, {SCHEMA_VERSION}): {marker_path}"
        )
    if len(manifest.models) != 1:
        raise ValueError(f"figure cell must have exactly one resolved target: {marker_path}")
    _validate_source_identity(manifest, resolved["manifest"])
    run = manifest.config.get("run")
    if not isinstance(run, dict):
        raise ValueError(f"manifest lacks config.run: {resolved['manifest']}")
    for field in ("corpus", "attacker", "model_spec", "defense"):
        _nonblank(run.get(field), f"manifest run.{field} in {resolved['manifest']}")
    if run.get("dry_run") is not False:
        raise ValueError(f"dry-run cell is not measured evidence: {marker_path}")
    if not isinstance(run.get("sampling_audit"), dict):
        raise ValueError(f"manifest lacks corpus-specific sampling audit: {marker_path}")
    if run["attacker"] not in manifest.adapters:
        raise ValueError(f"manifest adapter/run attacker mismatch: {marker_path}")

    attempts_raw = _jsonl_objects(resolved["attempts"])
    responses_raw = _jsonl_objects(resolved["responses"])
    judgments_raw = _jsonl_objects(resolved["judgments"])
    trails_raw = _jsonl_objects(resolved["trails"])
    results_raw = _jsonl_objects(resolved["results"])
    attempts = _pydantic_rows(attempts_raw, Attempt, resolved["attempts"])
    responses = _pydantic_rows(responses_raw, Response, resolved["responses"])
    judgments = _pydantic_rows(judgments_raw, Judgment, resolved["judgments"])
    results = _pydantic_rows(results_raw, EvalResult, resolved["results"])
    if not attempts or not responses or not judgments or not results or not trails_raw:
        raise ValueError(f"completed scored cell has an empty required artifact: {marker_path}")

    counts = {
        "n_attempts": len(attempts),
        "n_responses": len(responses),
        "n_judgments": len(judgments),
        "n_results": len(results),
    }
    for field, count in counts.items():
        if _integer(marker.get(field), f"marker {field} in {marker_path}") != count:
            raise ValueError(f"completion marker {field} mismatch: {marker_path}")
        if field != "n_results" and manifest.config.get(field) != count:
            raise ValueError(f"manifest {field} mismatch: {marker_path}")

    attempt_ids = [row.id for row in attempts]
    response_ids = [row.attempt_id for row in responses]
    judgment_ids = [row.attempt_id for row in judgments]
    if len(set(attempt_ids)) != len(attempt_ids):
        raise ValueError(f"duplicate Attempt identity: {marker_path}")
    if Counter(attempt_ids) != Counter(response_ids) or Counter(attempt_ids) != Counter(
        judgment_ids
    ):
        raise ValueError(f"Attempt/Response/Judgment identities do not join exactly: {marker_path}")
    attempts_by_id = {row.id: row for row in attempts}
    responses_by_id = {row.attempt_id: row for row in responses}
    judgments_by_id = {row.attempt_id: row for row in judgments}
    target = manifest.models[0]
    for attempt in attempts:
        if (
            attempt.run_id != run_id
            or attempt.target != target
            or attempt.attacker != run["attacker"]
        ):
            raise ValueError(f"Attempt/manifest lineage mismatch: {marker_path}")
        if not attempt.rendered_input:
            raise ValueError(f"Attempt has no rendered input: {marker_path}")
    for response in responses:
        if response.run_id != run_id or response.target != target:
            raise ValueError(f"Response/manifest lineage mismatch: {marker_path}")
    for judgment in judgments:
        raw = judgment.raw
        attempt = attempts_by_id[judgment.attempt_id]
        response = responses_by_id[judgment.attempt_id]
        if judgment.run_id != run_id or raw.get("run_id") != run_id:
            raise ValueError(f"Judgment run lineage mismatch: {marker_path}")
        required_lineage = {
            "model": target,
            "target": target,
            "attacker": run["attacker"],
            "datapoint_id": attempt.datapoint_id,
            "seed": attempt.seed,
            "requested_seed": attempt.seed,
            "turn_index": attempt.turn_index,
            "attack_fingerprint": attempt.params.get("attack_fingerprint"),
            "transfer_key": attempt.params.get("transfer_key"),
            "transferable": attempt.params.get("transferable"),
            "response_conditioned": bool(attempt.params.get("response_conditioned")),
            "replayed_transcript": bool(attempt.params.get("replayed_transcript")),
            "target_sampling_control": response.raw.get("target_sampling_control", "unknown"),
        }
        for field, expected in required_lineage.items():
            if raw.get(field) != expected:
                raise ValueError(
                    f"Attempt/Response/Judgment {field} mismatch for {judgment.attempt_id!r}"
                )
        for field in ("source", "risk_category", "modality", "effective_modality"):
            _nonblank(raw.get(field), f"Judgment raw.{field} in {marker_path}")
        if raw.get("expected_behavior") not in _EXPECTED_BEHAVIORS:
            raise ValueError(f"invalid expected behavior in {marker_path}")
        if not isinstance(raw.get("common_metrics_eligible"), bool):
            raise ValueError(f"missing explicit common-metric eligibility in {marker_path}")
    if any(result.run_id != run_id for result in results):
        raise ValueError(f"EvalResult run lineage mismatch: {marker_path}")
    _validate_trails(
        trails_raw,
        attempts=attempts_by_id,
        responses=responses_by_id,
        judgments=judgments_by_id,
        manifest=manifest,
        path=resolved["trails"],
    )
    identity_summary = _validate_realized_identity_inventory(
        manifest,
        marker,
        responses,
        trails_raw,
        path=resolved["manifest"],
    )

    ref_identities = {
        (
            ref.status.get("run_id"),
            ref.status.get("corpus"),
            ref.status.get("model_spec"),
            ref.status.get("attacker"),
            ref.request.get("defense"),
        )
        for ref in refs
    }
    actual_identity = (
        run_id, run["corpus"], run["model_spec"], run["attacker"], run["defense"]
    )
    if ref_identities != {actual_identity}:
        raise ValueError(
            f"grid status/completed-cell identity mismatch for {marker_path}: "
            f"grid={sorted(ref_identities)!r}, artifact={actual_identity!r}"
        )

    manifest_dict = manifest.model_dump(mode="json")
    return {
        "stem": marker_path.name.removesuffix(".complete.json"),
        "run_id": run_id,
        "model": target,
        "manifest": manifest_dict,
        "manifest_path": resolved["manifest"],
        "complete_path": marker_path,
        "artifacts": resolved,
        "attempts": {row.id: raw for row, raw in zip(attempts, attempts_raw)},
        "responses": {row.attempt_id: raw for row, raw in zip(responses, responses_raw)},
        "judgments": judgments_raw,
        "trails": trails_raw,
        "aggregate_results": results_raw,
        "integrity_mode": "v2_content_addressed_grid_allowlisted",
        "source_identity_validated": True,
        "realized_identities": identity_summary,
        "grid_audit": {
            "mode": "exact_completed_grid_allowlist",
            "grid_ids": sorted({ref.grid_id for ref in refs}),
            "grid_files": sorted({str(ref.grid_path) for ref in refs}),
            "completion_marker": str(marker_path),
            "unexplained_exclusions": 0,
        },
    }


def _load_cells(root: Path) -> list[dict[str, Any]]:
    allowlist = _grid_allowlist(root)
    return [_validate_cell(marker, allowlist[marker]) for marker in sorted(allowlist)]


def _run_config(cell: dict[str, Any]) -> dict[str, Any]:
    return cell["manifest"]["config"]["run"]


def _select_cell(
    cells: list[dict[str, Any]], *, corpus: str, attacker: str, model: str, defense: str,
) -> dict[str, Any]:
    matches = [
        cell for cell in cells
        if _run_config(cell)["corpus"] == corpus
        and _run_config(cell)["attacker"] == attacker
        and _run_config(cell)["model_spec"] == model
        and _run_config(cell)["defense"] == defense
    ]
    if len(matches) != 1:
        raise ValueError(
            "each measured arm must resolve to exactly one grid-accounted cell; "
            f"corpus={corpus!r}, attacker={attacker!r}, model={model!r}, "
            f"defense={defense!r}, matches={len(matches)}"
        )
    return matches[0]


def _units(cell: dict[str, Any]) -> dict[tuple[str, str, str, int], _Unit]:
    run = _run_config(cell)
    output: dict[tuple[str, str, str, int], _Unit] = {}
    for row in cell["judgments"]:
        raw = row["raw"]
        attempt = cell["attempts"][row["attempt_id"]]
        response_conditioned = raw["response_conditioned"]
        replayed = raw["replayed_transcript"]
        if response_conditioned and not replayed:
            raise ValueError(
                "Chapter V static figure path cannot admit a live response-conditioned "
                "trajectory; use paired_compare/survival analysis"
            )
        expected = raw["expected_behavior"]
        if expected == "refuse" and row["label"] == "over_refusal":
            raise ValueError("harmful unit uses benign-only over_refusal label")
        if expected != "refuse" and row["label"] == "refusal":
            raise ValueError("benign unit uses harmful-only refusal label")
        source = _nonblank(raw.get("source"), "judgment source")
        datapoint_id = _nonblank(raw.get("datapoint_id"), "judgment datapoint_id")
        seed = _integer(raw.get("requested_seed"), "judgment requested seed")
        fingerprint = _nonblank(raw.get("attack_fingerprint"), "attack fingerprint")
        transfer_key = _nonblank(raw.get("transfer_key"), "transfer key")
        unit = _Unit(
            corpus=run["corpus"],
            source=source,
            datapoint_id=datapoint_id,
            seed=seed,
            expected_behavior=expected,
            risk_category=_nonblank(raw.get("risk_category"), "risk category"),
            declared_modality=_nonblank(raw.get("modality"), "declared modality"),
            effective_modality=_nonblank(
                raw.get("effective_modality"), "effective modality"
            ),
            eligible=raw["common_metrics_eligible"],
            value=float(
                row["label"] == ("violation" if expected == "refuse" else "over_refusal")
            ),
            attack_fingerprint=fingerprint,
            transfer_key=transfer_key,
        )
        if unit.key in output:
            raise ValueError(
                "static figure unit is ambiguous: duplicate "
                f"corpus/source/datapoint/seed key {unit.key!r}"
            )
        if attempt.get("datapoint_id") != datapoint_id or attempt.get("seed") != seed:
            raise ValueError(f"Attempt/unit key mismatch for {row['attempt_id']!r}")
        output[unit.key] = unit
    return output


def _paired_units(
    left: dict[str, Any], right: dict[str, Any], *, seed: int,
) -> tuple[
    dict[tuple[str, str, str, int], tuple[_Unit, _Unit]], dict[str, Any]
]:
    # Reuse the prespecified comparison implementation for configuration-factor,
    # exact-input and construct validation.  Figure estimates below strengthen
    # its cluster identity with explicit corpus and source components.
    semantic = compare_cells(left, right, mode="static", n_resamples=1, seed=seed)
    left_units = _units(left)
    right_units = _units(right)
    if set(left_units) != set(right_units):
        raise ValueError(
            "paired figure arms do not contain the identical unit population: "
            f"left_only={sorted(set(left_units) - set(right_units))!r}, "
            f"right_only={sorted(set(right_units) - set(left_units))!r}"
        )
    paired: dict[tuple[str, str, str, int], tuple[_Unit, _Unit]] = {}
    for key in sorted(left_units):
        left_unit, right_unit = left_units[key], right_units[key]
        comparable = (
            left_unit.expected_behavior,
            left_unit.risk_category,
            left_unit.declared_modality,
            left_unit.effective_modality,
            left_unit.eligible,
            left_unit.attack_fingerprint,
            left_unit.transfer_key,
        )
        counterpart = (
            right_unit.expected_behavior,
            right_unit.risk_category,
            right_unit.declared_modality,
            right_unit.effective_modality,
            right_unit.eligible,
            right_unit.attack_fingerprint,
            right_unit.transfer_key,
        )
        if comparable != counterpart:
            raise ValueError(f"paired unit construct/input mismatch for {key!r}")
        paired[key] = (left_unit, right_unit)
    return paired, semantic


def _quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    position = q * (len(ordered) - 1)
    low = int(math.floor(position))
    high = int(math.ceil(position))
    if low == high:
        return ordered[low]
    return ordered[low] + (position - low) * (ordered[high] - ordered[low])


def _paired_cluster_ci(
    pairs: list[tuple[_Unit, _Unit]], *, n_resamples: int, seed_material: str,
) -> tuple[float, float]:
    clusters: dict[tuple[str, str, str], list[tuple[_Unit, _Unit]]] = defaultdict(list)
    for pair in pairs:
        clusters[pair[0].cluster].append(pair)
    keys = sorted(clusters)
    cluster_differences = {
        key: sum(left.value - right.value for left, right in clusters[key])
        / len(clusters[key])
        for key in keys
    }
    rng = random.Random(int(hashlib.sha256(seed_material.encode()).hexdigest()[:16], 16))
    draws: list[float] = []
    for _ in range(n_resamples):
        sampled = [keys[rng.randrange(len(keys))] for _ in keys]
        draws.append(sum(cluster_differences[key] for key in sampled) / len(sampled))
    return _quantile(draws, 0.025), _quantile(draws, 0.975)


def _equal_cluster_arm_values(
    pairs: list[tuple[_Unit, _Unit]],
) -> tuple[float, float]:
    by_cluster: dict[tuple[str, str, str], list[tuple[_Unit, _Unit]]] = defaultdict(list)
    for pair in pairs:
        by_cluster[pair[0].cluster].append(pair)
    left = sum(
        sum(pair[0].value for pair in cluster_pairs) / len(cluster_pairs)
        for cluster_pairs in by_cluster.values()
    ) / len(by_cluster)
    right = sum(
        sum(pair[1].value for pair in cluster_pairs) / len(cluster_pairs)
        for cluster_pairs in by_cluster.values()
    ) / len(by_cluster)
    return left, right


def _arm_provenance(cell: dict[str, Any]) -> dict[str, Any]:
    manifest = cell["manifest"]
    run = _run_config(cell)
    components = manifest["config"].get("components") or {}
    return {
        "run_id": cell["run_id"],
        "requested_model_spec": run["model_spec"],
        "resolved_target": cell["model"],
        "defense": run["defense"],
        "attacker": run["attacker"],
        "corpus": run["corpus"],
        "code_version": manifest["code_version"],
        "schema_version": manifest["schema_version"],
        "started_at": manifest["started_at"],
        "seeds": manifest["seeds"],
        "judges": manifest["judges"],
        "judge_model": run.get("judge_model"),
        "judge_configuration": components.get("judge_cascade"),
        "source_policy_inventory": manifest["config"].get("source_policy_inventory"),
        "source_metric_inventory": manifest["config"].get("source_metric_inventory"),
        "realized_identities": cell.get("realized_identities"),
        "budget": manifest["config"].get("budget"),
        "sampling_audit": run.get("sampling_audit"),
        "dataset_hashes": manifest["dataset_hashes"],
        "environment": manifest["env"],
        "run_config": run,
        "source_files": {
            role: str(path) for role, path in sorted(cell["artifacts"].items())
        },
        "completion_marker": str(cell["complete_path"]),
        "grid_audit": cell["grid_audit"],
    }


def _policy_fingerprint(arm: dict[str, Any]) -> str:
    """Digest the policy/decision-defining configuration of one arm.

    The judge stage identities and the judge-cascade configuration define the
    decision boundary. The contrasted defense axis is deliberately excluded so a
    same-base defense contrast (Figure V.3) still shares one policy across arms.
    """
    return _sha256_json({
        "judges": arm.get("judges"),
        "judge_configuration": arm.get("judge_configuration"),
        "source_policy_inventory": arm.get("source_policy_inventory"),
    })


def _bind_policy_label(
    points: list[dict[str, Any]], policy_label: str
) -> dict[str, Any]:
    """Bind the free-form policy label to a single verified policy fingerprint.

    A figure caption asserts one decision boundary; if the underlying cells mix
    judge/cascade configurations the label is unverifiable, so this fails closed
    rather than let a figure claim a policy its artifacts do not share.
    """
    fingerprints: dict[str, dict[str, Any]] = {}
    for point in points:
        for side in ("left_arm", "right_arm"):
            arm = point.get(side)
            if not arm:
                continue
            fingerprints.setdefault(_policy_fingerprint(arm), {
                "judges": arm.get("judges"),
                "judge_configuration": arm.get("judge_configuration"),
                "source_policy_inventory": arm.get("source_policy_inventory"),
            })
    if not fingerprints:
        raise ValueError("cannot bind a policy label: no arm provenance to fingerprint")
    if len(fingerprints) != 1:
        raise ValueError(
            "figure inputs mix judge/decision configurations, so the policy label "
            f"{policy_label!r} cannot be bound to one policy: {sorted(fingerprints)!r}"
        )
    (fingerprint, defining_fields), = fingerprints.items()
    return {
        "policy_label": policy_label,
        "policy_fingerprint": fingerprint,
        "policy_defining_fields": defining_fields,
    }


def _estimate(
    paired: dict[tuple[str, str, str, int], tuple[_Unit, _Unit]],
    predicate: Callable[[_Unit], bool], *, point_id: str, corpus: str,
    population: str, left: dict[str, Any], right: dict[str, Any], semantic: dict[str, Any],
    policy_label: str, multiplicity_family: str, minimum_cell_n: int,
    n_resamples: int, seed: int, risk_category: str | None = None,
    modality: str | None = None,
) -> dict[str, Any]:
    pairs = [pair for pair in paired.values() if pair[0].eligible and predicate(pair[0])]
    cluster_keys = sorted({pair[0].cluster for pair in pairs})
    unit_keys = sorted(pair[0].key for pair in pairs)
    status = "estimated"
    if not pairs:
        status = "not_estimable_empty_population"
    elif len(cluster_keys) < minimum_cell_n:
        status = "not_estimable_underpowered"
    value: float | None = None
    ci_low: float | None = None
    ci_high: float | None = None
    left_value: float | None = None
    right_value: float | None = None
    if status == "estimated":
        left_value, right_value = _equal_cluster_arm_values(pairs)
        value = left_value - right_value
        ci_low, ci_high = _paired_cluster_ci(
            pairs,
            n_resamples=n_resamples,
            seed_material=f"{seed}:{point_id}",
        )
    return {
        "point_id": point_id,
        "status": status,
        "value": value,
        "ci_low": ci_low,
        "ci_high": ci_high,
        "effect_direction": "left_minus_right",
        "left_value": left_value,
        "right_value": right_value,
        "n_pairs": len(pairs),
        "n_clusters": len(cluster_keys),
        "minimum_clusters": minimum_cell_n,
        "population": population,
        "population_definition": {
            "common_metrics_eligible": True,
            "expected_behavior": "refuse" if population == "harmful_expected_refusal" else (
                "safe_answer_or_comply_safely"
                if population == "benign_expected_answer" else population
            ),
            "corpus": corpus,
            "risk_category": risk_category,
            "effective_modality": modality,
            "cluster": "corpus x source x datapoint_id",
            "unit": "corpus x source x datapoint_id x requested_seed",
        },
        "population_sha256": _sha256_json(unit_keys),
        "cluster_population_sha256": _sha256_json(cluster_keys),
        "sources": sorted({pair[0].source for pair in pairs}),
        "corpus": corpus,
        "risk_category": risk_category,
        "modality": modality,
        "policy_label": policy_label,
        "multiplicity_family": multiplicity_family,
        "bootstrap": {
            "method": "paired corpus/source/datapoint-cluster percentile bootstrap",
            "confidence_level": 0.95,
            "n_resamples": n_resamples,
            "seed": seed,
        },
        "comparison_type": semantic["comparison_type"],
        "causal_interpretation_eligible": semantic["causal_interpretation_eligible"],
        "causal_effect_established": False,
        "comparison_config_signature": semantic["comparison_config_signature"],
        "right_comparison_config_signature": semantic[
            "right_comparison_config_signature"
        ],
        "defense_identity_qualification": semantic.get(
            "defense_identity_qualification"
        ),
        "left_arm": _arm_provenance(left),
        "right_arm": _arm_provenance(right),
    }


def _validate_analysis_options(
    *, corpora: list[str], policy_label: str, multiplicity_family: str,
    minimum_cell_n: int, n_resamples: int,
) -> list[str]:
    selected = _string_list(corpora, "explicit corpus facets")
    _nonblank(policy_label, "policy label")
    _nonblank(multiplicity_family, "multiplicity family")
    _integer(minimum_cell_n, "minimum cell n", minimum=1)
    _integer(n_resamples, "bootstrap resamples", minimum=1)
    return selected


def load_model_results(
    path: Path, *, left_model: str, right_model: str, corpora: list[str],
    attacker: str = "replay", defense: str = "none", policy_label: str,
    multiplicity_family: str, minimum_cell_n: int, n_resamples: int = 2000,
    seed: int = 0,
) -> dict[str, list[dict[str, Any]]]:
    """Return corpus-faceted paired model and category contrasts."""
    selected_corpora = _validate_analysis_options(
        corpora=corpora,
        policy_label=policy_label,
        multiplicity_family=multiplicity_family,
        minimum_cell_n=minimum_cell_n,
        n_resamples=n_resamples,
    )
    if left_model == right_model:
        raise ValueError("model contrast requires two different model specifications")
    cells = _load_cells(Path(path))
    overall_points: list[dict[str, Any]] = []
    category_points: list[dict[str, Any]] = []
    for corpus in selected_corpora:
        left = _select_cell(
            cells, corpus=corpus, attacker=attacker, model=left_model, defense=defense
        )
        right = _select_cell(
            cells, corpus=corpus, attacker=attacker, model=right_model, defense=defense
        )
        paired, semantic = _paired_units(left, right, seed=seed)
        overall_points.append(_estimate(
            paired,
            lambda unit: unit.expected_behavior == "refuse",
            point_id=f"model:{corpus}:harmful",
            corpus=corpus,
            population="harmful_expected_refusal",
            left=left,
            right=right,
            semantic=semantic,
            policy_label=policy_label,
            multiplicity_family=multiplicity_family,
            minimum_cell_n=minimum_cell_n,
            n_resamples=n_resamples,
            seed=seed,
        ))
        cells_present = sorted({
            (pair[0].risk_category, pair[0].effective_modality)
            for pair in paired.values()
            if pair[0].eligible and pair[0].expected_behavior == "refuse"
        })
        if not cells_present:
            category_points.append(_estimate(
                paired,
                lambda unit: False,
                point_id=f"category:{corpus}:empty",
                corpus=corpus,
                population="harmful_expected_refusal",
                left=left,
                right=right,
                semantic=semantic,
                policy_label=policy_label,
                multiplicity_family=multiplicity_family,
                minimum_cell_n=minimum_cell_n,
                n_resamples=n_resamples,
                seed=seed,
            ))
        for risk, modality in cells_present:
            category_points.append(_estimate(
                paired,
                lambda unit, risk=risk, modality=modality: (
                    unit.expected_behavior == "refuse"
                    and unit.risk_category == risk
                    and unit.effective_modality == modality
                ),
                point_id=f"category:{corpus}:{risk}:{modality}",
                corpus=corpus,
                population="harmful_expected_refusal",
                left=left,
                right=right,
                semantic=semantic,
                policy_label=policy_label,
                multiplicity_family=multiplicity_family,
                minimum_cell_n=minimum_cell_n,
                n_resamples=n_resamples,
                seed=seed,
                risk_category=risk,
                modality=modality,
            ))
    return {"overall": overall_points, "categories": category_points}


def load_defense_results(
    path: Path, *, model: str, left_defense: str, right_defense: str,
    corpora: list[str], attacker: str = "replay", policy_label: str,
    multiplicity_family: str, minimum_cell_n: int, n_resamples: int = 2000,
    seed: int = 0,
) -> list[dict[str, Any]]:
    """Return corpus-faceted same-base paired harmful and benign defense effects."""
    selected_corpora = _validate_analysis_options(
        corpora=corpora,
        policy_label=policy_label,
        multiplicity_family=multiplicity_family,
        minimum_cell_n=minimum_cell_n,
        n_resamples=n_resamples,
    )
    if left_defense == right_defense:
        raise ValueError("defense contrast requires two different defense configurations")
    cells = _load_cells(Path(path))
    points: list[dict[str, Any]] = []
    populations: tuple[tuple[str, str, Callable[[_Unit], bool]], ...] = (
        (
            "ASR",
            "harmful_expected_refusal",
            lambda unit: unit.expected_behavior == "refuse",
        ),
        (
            "FRR",
            "benign_expected_answer",
            lambda unit: unit.expected_behavior in {"safe_answer", "comply_safely"},
        ),
    )
    for corpus in selected_corpora:
        left = _select_cell(
            cells, corpus=corpus, attacker=attacker, model=model, defense=left_defense
        )
        right = _select_cell(
            cells, corpus=corpus, attacker=attacker, model=model, defense=right_defense
        )
        paired, semantic = _paired_units(left, right, seed=seed)
        if semantic["comparison_type"] != "within_target_defense_intervention":
            raise ValueError("Figure V.3 requires a same-base within-target defense contrast")
        for metric, population, predicate in populations:
            point = _estimate(
                paired,
                predicate,
                point_id=f"defense:{corpus}:{metric}",
                corpus=corpus,
                population=population,
                left=left,
                right=right,
                semantic=semantic,
                policy_label=policy_label,
                multiplicity_family=multiplicity_family,
                minimum_cell_n=minimum_cell_n,
                n_resamples=n_resamples,
                seed=seed,
            )
            point["metric"] = metric
            points.append(point)
    return points


def load_results(
    model_path: Path, defense_path: Path, *, model_left: str, model_right: str,
    model_defense: str, model_corpora: list[str], defense_model: str,
    defense_left: str, defense_right: str, defense_corpora: list[str], attacker: str,
    policy_label: str, multiplicity_family: str, minimum_cell_n: int,
    n_resamples: int = 2000, seed: int = 0,
) -> dict[str, Any]:
    """Load all three Chapter V measured figure inputs without pooling corpora."""
    model_results = load_model_results(
        model_path,
        left_model=model_left,
        right_model=model_right,
        corpora=model_corpora,
        attacker=attacker,
        defense=model_defense,
        policy_label=policy_label,
        multiplicity_family=multiplicity_family,
        minimum_cell_n=minimum_cell_n,
        n_resamples=n_resamples,
        seed=seed,
    )
    defense_results = load_defense_results(
        defense_path,
        model=defense_model,
        left_defense=defense_left,
        right_defense=defense_right,
        corpora=defense_corpora,
        attacker=attacker,
        policy_label=policy_label,
        multiplicity_family=multiplicity_family,
        minimum_cell_n=minimum_cell_n,
        n_resamples=n_resamples,
        seed=seed,
    )
    figures = {
        "fig-v-asr-by-model.png": {
            "estimand": "paired harmful ASR risk difference, left model minus right model",
            "points": model_results["overall"],
        },
        "fig-v-asr-by-category.png": {
            "estimand": (
                "paired harmful ASR risk difference by benchmark, risk, and "
                "effective modality"
            ),
            "points": model_results["categories"],
        },
        "fig-v-safety-utility.png": {
            "estimand": (
                "same-base paired defense effects on harmful ASR and benign false refusal"
            ),
            "points": defense_results,
        },
    }
    policy_binding = _bind_policy_label(
        model_results["overall"] + model_results["categories"] + defense_results,
        policy_label,
    )
    return {
        "schema_version": "ura-chapter-v-figures/1.0",
        "illustrative": False,
        "analysis": {
            "attacker": attacker,
            **policy_binding,
            "multiplicity_family": multiplicity_family,
            "minimum_clusters_per_cell": minimum_cell_n,
            "bootstrap_resamples": n_resamples,
            "bootstrap_seed": seed,
            "corpus_pooling": "forbidden; every point is one explicit corpus facet",
            "effect_direction": "left_minus_right",
        },
        "figures": figures,
    }


def load_confirmatory_results(
    path: Path, *, expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Build measured figure data only from a publishable analysis artifact."""
    artifact = read_bound_json(Path(path), expected_sha256=expected_sha256)
    artifact_identity = artifact.pop("_artifact_identity")
    if artifact.get("schema_version") != "ura-confirmatory-analysis/1.0":
        raise ValueError("figure analysis artifact has an unsupported schema_version")
    if artifact.get("publishable_real_run") is not True:
        raise ValueError("figures refuse a non-publishable confirmatory analysis artifact")
    if artifact.get("analysis_stage") != "final_human_bound":
        raise ValueError("figures require the final human-bound confirmatory stage")
    human_artifact = artifact.get("human_audit_artifact")
    if (
        not isinstance(human_artifact, dict)
        or not _valid_sha256(human_artifact.get("sha256"))
    ):
        raise ValueError("confirmatory artifact lacks a content-addressed human audit")
    checks = artifact.get("publishability_checks")
    if not isinstance(checks, dict) or not checks or not all(value is True for value in checks.values()):
        raise ValueError("confirmatory artifact has incomplete publishability checks")
    plan_artifact = artifact.get("plan_artifact")
    if not isinstance(plan_artifact, dict) or not _valid_sha256(plan_artifact.get("sha256")):
        raise ValueError("confirmatory artifact lacks a content-addressed plan")
    policy = artifact.get("evaluation_policy")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"policy_id", "version", "sha256"}
        or not all(isinstance(policy.get(name), str) and policy[name] for name in policy)
        or not _valid_sha256(policy.get("sha256"))
    ):
        raise ValueError("confirmatory artifact lacks typed evaluation-policy identity")
    source = artifact.get("analysis_source")
    validated_source = validate_analysis_source_identity(source)
    expected_source_paths = {
        "experiments/analysis_integrity.py",
        "experiments/confirmatory_analysis.py",
        "experiments/paired_compare.py",
        "src/ura/metrics.py",
    }
    if {record["path"] for record in validated_source["files"]} != expected_source_paths:
        raise ValueError("confirmatory artifact has the wrong analysis-source inventory")
    source_files = source.get("files")
    if not isinstance(source_files, list) or source.get("file_count") != len(source_files):
        raise ValueError("confirmatory artifact has an invalid analysis-source inventory")
    for record in source_files:
        if not isinstance(record, dict) or not _valid_sha256(record.get("sha256")):
            raise ValueError("confirmatory artifact has an invalid source-file record")
        relative = record.get("path")
        if not isinstance(relative, str) or not relative:
            raise ValueError("confirmatory source record lacks a relative path")
        candidate = (Path(__file__).resolve().parents[1] / relative).resolve()
        try:
            candidate.relative_to(Path(__file__).resolve().parents[1])
        except ValueError as exc:
            raise ValueError("confirmatory source path escapes the repository") from exc
        if (
            candidate.is_symlink() or not candidate.is_file()
            or candidate.stat().st_size != record.get("bytes")
            or hashlib.sha256(candidate.read_bytes()).hexdigest() != record["sha256"]
        ):
            raise ValueError(f"confirmatory analysis source has drifted: {relative}")

    families = artifact.get("families")
    contrasts = artifact.get("contrasts")
    if not isinstance(families, dict) or not isinstance(contrasts, dict):
        raise ValueError("confirmatory artifact lacks families/contrasts")
    hypothesis_adjustment: dict[str, dict[str, Any]] = {}
    hypothesis_family: dict[str, str] = {}
    for family_id, family in families.items():
        hypotheses = family.get("hypotheses") if isinstance(family, dict) else None
        if not isinstance(hypotheses, dict):
            raise ValueError(f"multiplicity family {family_id!r} is invalid")
        for hypothesis, adjustment in hypotheses.items():
            if hypothesis in hypothesis_adjustment:
                raise ValueError(f"hypothesis {hypothesis!r} appears in multiple families")
            if not isinstance(adjustment, dict) or adjustment.get("status") != "estimated":
                raise ValueError(f"figure hypothesis {hypothesis!r} was not estimable")
            hypothesis_adjustment[hypothesis] = adjustment
            hypothesis_family[hypothesis] = str(family_id)

    overall: list[dict[str, Any]] = []
    categories: list[dict[str, Any]] = []
    defenses: list[dict[str, Any]] = []
    policy_inventories: list[Any] = []
    for contrast_id, report in sorted(contrasts.items()):
        if not isinstance(report, dict):
            raise ValueError(f"contrast {contrast_id!r} is invalid")
        preregistered = report.get("preregistered")
        if (
            not isinstance(preregistered, dict)
            or preregistered.get("all_planned_metrics_adequately_powered") is not True
        ):
            raise ValueError(f"contrast {contrast_id!r} failed its frozen power gate")
        facets = report.get("facets")
        if not isinstance(facets, dict) or not facets:
            raise ValueError(f"contrast {contrast_id!r} has no facets")
        for local_id in preregistered.get("hypotheses", []):
            global_id = f"{contrast_id}::{local_id}"
            adjustment = hypothesis_adjustment.get(global_id)
            if adjustment is None:
                raise ValueError(f"planned hypothesis {global_id!r} lacks family adjustment")
            parts = local_id.split("::")
            corpus = parts[0]
            facet = facets.get(corpus)
            facet_checks = (
                facet.get("publishability_checks") if isinstance(facet, dict) else None
            )
            if (
                not isinstance(facet, dict)
                or not isinstance(facet_checks, dict)
                or not facet_checks
                or any(
                    value is not True for key, value in facet_checks.items()
                    if key != "adequately_powered"
                )
            ):
                raise ValueError(f"figure facet {contrast_id!r}/{corpus!r} is not publishable")
            if len(parts) == 2:
                metric_name = parts[1]
                metric = (facet.get("metrics") or {}).get(metric_name)
                risk = modality = None
            elif len(parts) == 3:
                metric_name, policy_token = parts[1:]
                metric = (facet.get("policy_metrics") or {}).get(
                    f"{policy_token}::{metric_name}"
                )
                risk = modality = None
            elif len(parts) == 5:
                metric_name, policy_token, risk, modality = parts[1:]
                metric = (facet.get("category_metrics") or {}).get(
                    f"{policy_token}::{risk}::{modality}"
                )
            else:
                raise ValueError(f"invalid planned figure hypothesis {local_id!r}")
            if not isinstance(metric, dict) or metric.get("status") != "estimated":
                raise ValueError(f"figure metric {global_id!r} is not estimated")
            preregistered_power = metric.get("preregistered_power_gate")
            if not isinstance(preregistered_power, dict) or preregistered_power.get(
                "adequately_powered"
            ) is not True:
                raise ValueError(f"figure metric {global_id!r} is underpowered")
            left_arm, right_arm = facet.get("left"), facet.get("right")
            if not isinstance(left_arm, dict) or not isinstance(right_arm, dict):
                raise ValueError(f"figure metric {global_id!r} lacks arm provenance")
            for arm in (left_arm, right_arm):
                inventory = arm.get("source_metric_inventory") or []
                if not isinstance(inventory, list):
                    raise ValueError("source_metric_inventory must be a list")
                for source_metric in inventory:
                    if not isinstance(source_metric, dict):
                        raise ValueError("source-metric inventory entries must be objects")
                    metric_id = str(source_metric.get("required_metric") or "")
                    if (
                        metric_id == "mmsafety_official_attack_rate"
                        and source_metric.get("source_metric_emitted") is True
                        and source_metric.get("official_evaluator_executed") is not True
                    ):
                        raise ValueError(
                            "MM-SafetyBench official attack rate was emitted without the "
                            "official evaluator executing"
                        )
            policy_inventories.extend([
                left_arm.get("source_policy_inventory"),
                right_arm.get("source_policy_inventory"),
            ])
            point = {
                "point_id": global_id,
                "status": "estimated_publishable_confirmatory",
                "value": metric["effect_left_minus_right"],
                "ci_low": metric["ci_low"],
                "ci_high": metric["ci_high"],
                "effect_direction": "left_minus_right",
                "left_value": metric["left_value"],
                "right_value": metric["right_value"],
                "n_pairs": metric["n_matched"],
                "n_clusters": metric["n_clusters"],
                "population": metric["population"],
                "corpus": corpus,
                "risk_category": risk,
                "modality": modality,
                "source_policy_id": metric.get("source_policy_id"),
                "source_policy_version": metric.get("source_policy_version"),
                "metric": metric.get("metric_alias", metric_name),
                "multiplicity_family": hypothesis_family[global_id],
                "multiplicity_adjustment": adjustment,
                "power_gate": preregistered_power,
                "left_arm": left_arm,
                "right_arm": right_arm,
                "source_metric_qualification": {
                    "common_ura_metric": True,
                    "source_metric_inventories": [
                        left_arm.get("source_metric_inventory") or [],
                        right_arm.get("source_metric_inventory") or [],
                    ],
                },
            }
            comparison_type = facet.get("comparison_type")
            if comparison_type == "cross_target_endpoint_noncausal":
                (categories if len(parts) == 5 else overall).append(point)
            elif (
                comparison_type == "within_target_defense_intervention"
                and len(parts) in {2, 3}
            ):
                defenses.append(point)

    if not overall or not categories or not defenses:
        raise ValueError(
            "publishable figure artifact must include model-overall, model-category, "
            "and defense hypotheses"
        )
    policy_binding = {
        "evaluation_policy": policy,
        "policy_fingerprint": _sha256_json({
            "evaluation_policy": policy,
            "source_policy_inventories": sorted(
                policy_inventories,
                key=lambda value: json.dumps(value, sort_keys=True, default=str),
            ),
        }),
    }
    return {
        "schema_version": "ura-chapter-v-figures/1.1",
        "illustrative": False,
        "analysis": {
            **policy_binding,
            "confirmatory_analysis_artifact": artifact_identity,
            "confirmatory_plan_artifact": plan_artifact,
            "human_audit_artifact": human_artifact,
            "multiplicity": families,
            "analysis_source": source,
            "figure_loader_source": analysis_source_identity([
                Path(__file__), Path(__file__).resolve().parent / "figures.py",
            ]),
            "effect_direction": "left_minus_right",
            "corpus_pooling": "forbidden; every point is one explicit corpus facet",
        },
        "figures": {
            "fig-v-asr-by-model.png": {
                "estimand": "paired harmful ASR risk difference, left model minus right model",
                "points": overall,
            },
            "fig-v-asr-by-category.png": {
                "estimand": "paired harmful ASR difference by corpus/risk/modality",
                "points": categories,
            },
            "fig-v-safety-utility.png": {
                "estimand": "same-base paired defense effects on ASR and false refusal",
                "points": defenses,
            },
        },
    }


__all__ = [
    "load_confirmatory_results", "load_defense_results", "load_model_results", "load_results",
]
