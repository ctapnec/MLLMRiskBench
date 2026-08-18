"""Strict, paired estimands for the three measured Chapter V figures.

This module deliberately does more than discover JSONL files.  A measured point
is admitted only when it comes from a version-2, content-addressed completion
marker named by a fully completed matrix grid.  Every core artifact is validated
against the Pydantic release schema and every Attempt -> Response -> Judgment ->
trail join is reconstructed before analysis.

Corpora are always separate facets.  The post-experiment loader maps completed
paired comparisons to a primary model contrast, policy-qualified multimodal and
utility proxy endpoints, and within-target adaptivity contrasts.  It routes
points by explicit endpoint semantics, so benign false-refusal endpoints cannot
be presented as harmful ASR.  The output is descriptive and exploratory: no
prospective power, multiplicity, or confirmation claim is manufactured.
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

from experiments.paired_compare import compare, compare_adaptivity, compare_cells
from experiments.analysis_integrity import (
    analysis_source_identity,
    human_analysis_arm_id,
    human_analysis_cell_id,
    read_bound_json,
    source_policy_token,
    validate_analysis_source_identity,
)
from ura.converters.release_specs import (
    MM_SAFETYBENCH_POLICY_DESCRIPTORS,
    mm_safetybench_policy,
    mossbench_policy,
)
from ura.attacker_input_contract import (
    AttackerInputContractError,
    reconcile_runner_and_grid_attacker_input_plans,
    target_modality_support_from_component_config,
    validate_attempts_against_attacker_input_plan,
)
from ura.data_models import (
    SCHEMA_VERSION,
    Attempt,
    EvalResult,
    Judgment,
    Response,
    RunManifest,
)
from ura.project_revision import validate_project_revision_binding
from ura.eligibility import validate_eligibility_plan
from ura.live_attestation import stable_realized_target_identity_keys
from ura.model_acquisition_runtime import (
    model_acquisition_execution_descriptor,
    validate_model_acquisition_execution_descriptor,
    validate_model_acquisition_grid_binding,
    validate_model_acquisition_role_projection,
    validate_model_acquisition_role_projection_binding,
)
from ura.request_envelope import validate_request_envelope_descriptor
from ura.runner import (
    CODE_VERSION,
    realized_identity_summary,
    validate_persisted_judgment_trails,
    validate_planned_realized_identities,
)
from ura.strict_json import strict_json_loads

_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_JSONL_BYTES = 512 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 16 * 1024 * 1024
_REQUIRED_ARTIFACTS = frozenset({
    "attempts", "responses", "judgments", "trails", "results", "manifest",
})
_COMPLETE_STATUSES = frozenset({"complete", "complete_existing"})
_EXPECTED_BEHAVIORS = frozenset({"refuse", "safe_answer", "comply_safely"})
_HEX = frozenset("0123456789abcdef")
_FIGURE_NAMES = (
    "fig-v-asr-by-model.png",
    "fig-v-policy-proxies.png",
    "fig-v-adaptivity.png",
)
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
    eligibility_plan: dict[str, Any]


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
    return strict_json_loads(text)


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


def _validate_source_identity(
    manifest: RunManifest, path: Path,
) -> dict[str, Any]:
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
    project_revision = validate_project_revision_binding(
        run.get("project_revision"), allow_not_required=run.get("dry_run") is True
    )
    if project_revision["harness_source_sha256"] != harness["sha256"]:
        raise ValueError(f"manifest project/harness source mismatch: {path}")
    if project_revision["driver_source_sha256"] != driver["sha256"]:
        raise ValueError(f"manifest project/experiment-driver source mismatch: {path}")
    return project_revision


def _grid_allowlist(
    root: Path, *, allow_diagnostic_canary: bool = False,
) -> dict[Path, list[_GridReference]]:
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
        eligibility_descriptor = request.get("eligibility_plan")
        if not isinstance(eligibility_descriptor, dict) or set(
            eligibility_descriptor
        ) != {"plan_id", "file", "sha256", "bytes", "records", "counts"}:
            raise ValueError(f"grid lacks an exact eligibility descriptor: {grid_path}")
        eligibility_name = eligibility_descriptor.get("file")
        if (
            not isinstance(eligibility_name, str)
            or Path(eligibility_name).name != eligibility_name
        ):
            raise ValueError(f"grid has an unsafe eligibility filename: {grid_path}")
        eligibility_path = _inside(root, grid_path.parent / eligibility_name)
        if not eligibility_path.is_file() or eligibility_path.is_symlink():
            raise ValueError(f"grid eligibility artifact is invalid: {grid_path}")
        with eligibility_path.open("r", encoding="utf-8") as handle:
            eligibility_records = sum(1 for line in handle if line.strip())
        if (
            eligibility_descriptor.get("bytes") != eligibility_path.stat().st_size
            or eligibility_descriptor.get("sha256") != _sha256_file(eligibility_path)
            or eligibility_descriptor.get("records") != eligibility_records
        ):
            raise ValueError(f"grid eligibility descriptor mismatch: {grid_path}")
        eligibility_plan = validate_eligibility_plan(_read_object(eligibility_path))
        if (
            eligibility_descriptor.get("plan_id") != eligibility_plan["plan_id"]
            or eligibility_descriptor.get("counts") != eligibility_plan["counts"]
        ):
            raise ValueError(f"grid eligibility identity/count mismatch: {grid_path}")
        try:
            acquisition_execution = model_acquisition_execution_descriptor(
                request.get("model_acquisition"),
                evidence_root=grid_path.parent.resolve(),
            )
            requested_acquisition_execution = (
                validate_model_acquisition_execution_descriptor(
                    request.get("model_acquisition_execution")
                )
            )
            validate_model_acquisition_grid_binding(
                requested_acquisition_execution,
                request,
            )
        except ValueError as exc:
            raise ValueError(
                f"grid model-acquisition evidence is invalid: {grid_path}: {exc}"
            ) from exc
        if (
            acquisition_execution != requested_acquisition_execution
            or eligibility_plan["bindings"].get("model_acquisition")
            != acquisition_execution
        ):
            raise ValueError(
                f"grid/eligibility model-acquisition identity mismatch: {grid_path}"
            )
        models = _string_list(request.get("models"), f"request.models in {grid_path}")
        corpora = _string_list(request.get("corpora"), f"request.corpora in {grid_path}")
        attackers = _string_list(
            request.get("attackers"), f"request.attackers in {grid_path}"
        )
        _nonblank(request.get("defense"), f"request.defense in {grid_path}")
        is_canary = request.get("execution_purpose") == "diagnostic_canary"
        if is_canary and not allow_diagnostic_canary:
            raise ValueError(f"diagnostic canary is not measured evidence: {grid_path}")
        if allow_diagnostic_canary and not is_canary:
            raise ValueError(
                f"diagnostic-canary loader received non-canary evidence: {grid_path}"
            )
        if not allow_diagnostic_canary and request.get("dry_run") is not False:
            raise ValueError(f"measured grid must explicitly declare dry_run=false: {grid_path}")
        if request.get("attestation_probe") is not False:
            raise ValueError(
                f"live-attestation probe is not measured evidence: {grid_path}"
            )
        live_attestation = request.get("live_attestation")
        required_attestation_mode = (
            "not_required"
            if allow_diagnostic_canary and request.get("dry_run") is True
            else "measured"
        )
        if (
            not isinstance(live_attestation, dict)
            or live_attestation.get("mode") != required_attestation_mode
        ):
            raise ValueError(
                f"grid lacks execution-purpose-compatible live-attestation admission: "
                f"{grid_path}"
            )
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
            allowlist[marker_path].append(_GridReference(
                grid_id, grid_path, request, status, eligibility_plan
            ))
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
    validate_persisted_judgment_trails(
        attempts, responses, judgments, trails, manifest.config, manifest.judges
    )


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
    run = manifest.config.get("run")
    if not isinstance(run, dict):
        raise ValueError(f"manifest lacks config.run for identity validation: {path}")
    components = manifest.config.get("components")
    if not isinstance(components, dict):
        raise ValueError(f"manifest lacks config.components: {path}")
    try:
        validate_planned_realized_identities(
            run, components, responses, trails, summary
        )
    except ValueError as exc:
        raise ValueError(f"planned/realized identity mismatch for {path}: {exc}") from exc
    return summary


def _validate_cell(
    marker_path: Path,
    refs: list[_GridReference],
    *,
    allow_diagnostic_dry_run: bool = False,
    allow_diagnostic_canary: bool = False,
) -> dict[str, Any]:
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
    project_revision = _validate_source_identity(manifest, resolved["manifest"])
    run = manifest.config.get("run")
    if not isinstance(run, dict):
        raise ValueError(f"manifest lacks config.run: {resolved['manifest']}")
    try:
        cell_acquisition = validate_model_acquisition_role_projection(
            run.get("model_acquisition")
        )
    except ValueError as exc:
        raise ValueError(
            f"manifest model-acquisition binding is invalid: "
            f"{resolved['manifest']}: {exc}"
        ) from exc
    completed_request_envelope = validate_request_envelope_descriptor(
        run.get("request_envelope")
    )
    for ref in refs:
        request_revision = validate_project_revision_binding(
            ref.request.get("project_revision"),
            allow_not_required=ref.request.get("dry_run") is True,
        )
        if request_revision != project_revision:
            raise ValueError(
                f"grid/completed-artifact project-revision mismatch: {marker_path}"
            )
        grid_request_envelope = validate_request_envelope_descriptor(
            ref.request.get("request_envelope")
        )
        if grid_request_envelope != completed_request_envelope:
            raise ValueError(
                f"grid/completed-artifact request-envelope mismatch: {marker_path}"
            )
        grid_acquisition = validate_model_acquisition_execution_descriptor(
            ref.request.get("model_acquisition_execution")
        )
        try:
            validate_model_acquisition_role_projection_binding(
                cell_acquisition,
                grid_acquisition,
                run_config=run,
            )
        except ValueError as exc:
            raise ValueError(
                f"grid/completed-artifact model-acquisition mismatch: {marker_path}: "
                f"{exc}"
            ) from exc
    for field in ("corpus", "attacker", "model_spec", "defense"):
        _nonblank(run.get(field), f"manifest run.{field} in {resolved['manifest']}")
    if run.get("dry_run") is not False and not allow_diagnostic_dry_run:
        raise ValueError(f"dry-run cell is not measured evidence: {marker_path}")
    is_canary = run.get("execution_purpose") == "diagnostic_canary"
    if is_canary and not allow_diagnostic_canary:
        raise ValueError(f"diagnostic canary is not measured evidence: {marker_path}")
    if allow_diagnostic_canary and not is_canary:
        raise ValueError(
            f"diagnostic-canary loader received non-canary cell: {marker_path}"
        )
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
    plan = manifest.config.get("attacker_input_plan")
    plan_sha256 = manifest.config.get("attacker_input_plan_sha256")
    plan_count = manifest.config.get("n_attacker_input_contracts")
    if not isinstance(plan_sha256, str) or isinstance(plan_count, bool) or not isinstance(
        plan_count, int
    ):
        raise ValueError(f"manifest attacker input plan metadata is invalid: {marker_path}")
    try:
        validate_attempts_against_attacker_input_plan(
            plan,
            attempts,
            responses,
            judgments,
            target_modalities=target_modality_support_from_component_config(
                manifest.config["components"]["target"]
            ),
            expected_sha256=plan_sha256,
            expected_count=plan_count,
        )
        for ref in refs:
            grid_plan = ref.eligibility_plan["bindings"]["attacker_input_plan"]
            reconcile_runner_and_grid_attacker_input_plans(
                plan,
                grid_plan,
                runner_sha256=plan_sha256,
                logical_source_arm=str(run["corpus"]),
                attacker=str(run["attacker"]),
            )
    except (AttackerInputContractError, KeyError, TypeError) as exc:
        raise ValueError(
            f"manifest/execution attacker input plan mismatch: {marker_path}"
        ) from exc
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
    grid_ids = {ref.grid_id for ref in refs}
    if grid_ids != {run.get("grid_id")}:
        raise ValueError(
            f"grid/completed-artifact condition mismatch for {marker_path}: "
            f"grid={sorted(grid_ids)!r}, artifact={run.get('grid_id')!r}"
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


_TARGET_EXECUTION_CONDITION_FIELDS = frozenset({
    "api_config",
    "local_identity",
    "quantization",
    "resolved_quantization",
    "dtype",
})
_COMPONENT_BASE_IDENTITY_FIELDS = frozenset({
    "name",
    "model",
    "provider",
    "requested_spec",
    "requested_model",
    "requested_target_spec",
    "resolved_model",
    "revision",
    "digest",
    "model_digest",
    "model_identity",
    "endpoint_identity",
    "base_url_identity",
    "tag",
    "base_url",
    "key_env",
})


def _component_execution_condition(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _component_execution_condition(child)
            for key, child in sorted(value.items())
            if key not in _COMPONENT_BASE_IDENTITY_FIELDS
        }
    if isinstance(value, list):
        return [_component_execution_condition(child) for child in value]
    return value


def _base_target_component(value: Any) -> Any:
    """Unwrap defense-only GuardedTarget layers for model-arm identity."""

    current = value
    while (
        isinstance(current, dict)
        and str(current.get("class", "")).endswith(".GuardedTarget")
        and isinstance(current.get("base"), dict)
    ):
        current = current["base"]
    return current


def _target_arm_condition_sha256(cell: dict[str, Any]) -> str:
    """Bind one realized base route to its target execution condition only.

    Corpus, attacker, judge, seed, and attack-horizon strata may repeat one
    requested target, but they must not let aliases for that target become
    distinct portfolio model identities.  Precision, decoding/context and
    other actual target component knobs remain legitimate target variants.
    """

    manifest = cell["manifest"]
    config = manifest["config"]
    run = config["run"]
    run_condition = {
        field: run.get(field) for field in _TARGET_EXECUTION_CONDITION_FIELDS
    }
    components = config.get("components")
    target_component = (
        components.get("target") if isinstance(components, dict) else None
    )
    return _sha256_json({
        "run": _component_execution_condition(run_condition),
        "target_component_condition": _component_execution_condition(
            _base_target_component(target_component)
        ),
    })


def _reject_duplicate_realized_target_arms(cells: list[dict[str, Any]]) -> None:
    """Prevent aliases for one realized model/condition becoming separate arms.

    One requested target may legitimately recur across corpus, attacker,
    defense, judge, seed, and horizon strata.  A distinct requested alias may
    not claim those strata as a second portfolio model.  Only a distinct target
    execution condition (for example BF16 vs FP8 or decoding/context knobs)
    permits distinct arm labels for one immutable base identity.
    """

    identity_owners: dict[tuple[tuple[str, ...], str], str] = {}
    for cell in cells:
        run = cell["manifest"]["config"]["run"]
        owner = str(
            run.get("requested_model_spec") or run.get("model_spec") or ""
        ).removesuffix("+guard")
        snapshot = cell["realized_identities"]["target"]["snapshot"]
        expected = run.get("expected_target_identity")
        keys = stable_realized_target_identity_keys(snapshot)
        if isinstance(expected, dict):
            keys.update(stable_realized_target_identity_keys(expected))
        condition = _target_arm_condition_sha256(cell)
        for key in keys:
            prior = identity_owners.setdefault((key, condition), owner)
            if prior != owner:
                raise ValueError(
                    "distinct figure target arms resolve to one stable realized "
                    "model identity"
                )


def _load_cells(
    root: Path, *, _allow_diagnostic_canary: bool = False,
) -> list[dict[str, Any]]:
    allowlist = _grid_allowlist(
        root, allow_diagnostic_canary=_allow_diagnostic_canary
    )
    cells = [
        _validate_cell(
            marker,
            allowlist[marker],
            allow_diagnostic_dry_run=_allow_diagnostic_canary,
            allow_diagnostic_canary=_allow_diagnostic_canary,
        )
        for marker in sorted(allowlist)
    ]
    _reject_duplicate_realized_target_arms(cells)
    return cells


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
    # Reuse the shared comparison implementation for configuration-factor,
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
    defense_intervention = (
        semantic.get("comparison_type") == "within_target_defense_intervention"
    )
    for key in sorted(left_units):
        left_unit, right_unit = left_units[key], right_units[key]
        comparable = (
            left_unit.expected_behavior,
            left_unit.risk_category,
            left_unit.declared_modality,
            None if defense_intervention else left_unit.effective_modality,
            left_unit.eligible,
            left_unit.attack_fingerprint,
            left_unit.transfer_key,
        )
        counterpart = (
            right_unit.expected_behavior,
            right_unit.risk_category,
            right_unit.declared_modality,
            None if defense_intervention else right_unit.effective_modality,
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


def _require_ready_facet(
    report: dict[str, Any], corpus: str, *, metric_name: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    facets = report.get("facets")
    unavailable = report.get("unavailable_facets")
    if not isinstance(facets, dict) or set(facets) != {corpus}:
        raise ValueError(
            f"figure contrast must resolve exactly the {corpus!r} corpus facet"
        )
    if unavailable not in ({}, None):
        raise ValueError("figure contrast contains unavailable corpus facets")
    facet = facets[corpus]
    checks = facet.get("analysis_readiness_checks")
    if (
        facet.get("analysis_ready_real_run") is not True
        or not isinstance(checks, dict)
        or not checks
        or not all(value is True for value in checks.values())
        or facet.get("unexplained_exclusions") != 0
    ):
        raise ValueError(f"figure contrast for {corpus!r} is not analysis-ready")
    metrics = facet.get("metrics")
    metric = metrics.get(metric_name) if isinstance(metrics, dict) else None
    if not isinstance(metric, dict) or metric.get("status") != "estimated":
        raise ValueError(
            f"figure endpoint {corpus!r}/{metric_name!r} is not estimable"
        )
    audit = metric.get("pairing_audit")
    if (
        not isinstance(audit, dict)
        or audit.get("unexplained_exclusions") != 0
        or any(
            audit.get(name) != 0
            for name in (
                "left_only_units", "right_only_units", "static_input_mismatch_units",
            )
        )
    ):
        raise ValueError(
            f"figure endpoint {corpus!r}/{metric_name!r} has pairing exclusions"
        )
    return facet, metric


def _require_policy_metric(
    facet: dict[str, Any], *, policy_id: str, policy_version: str, metric_name: str,
) -> dict[str, Any]:
    metrics = facet.get("policy_metrics")
    key = f"{source_policy_token(policy_id, policy_version)}::{metric_name}"
    metric = metrics.get(key) if isinstance(metrics, dict) else None
    if (
        not isinstance(metric, dict)
        or metric.get("status") != "estimated"
        or metric.get("source_policy_id") != policy_id
        or metric.get("source_policy_version") != policy_version
    ):
        raise ValueError(f"required policy endpoint {key!r} is not estimable")
    audit = metric.get("pairing_audit")
    if (
        not isinstance(audit, dict)
        or audit.get("unexplained_exclusions") != 0
        or any(
            audit.get(name) != 0
            for name in (
                "left_only_units", "right_only_units", "static_input_mismatch_units",
            )
        )
    ):
        raise ValueError(f"required policy endpoint {key!r} has pairing exclusions")
    return metric


def _measured_point(
    *, point_id: str, corpus: str, metric: dict[str, Any], facet: dict[str, Any],
    figure_group: str,
) -> dict[str, Any]:
    numeric = (
        metric.get("effect_left_minus_right"), metric.get("ci_low"),
        metric.get("ci_high"), metric.get("left_value"), metric.get("right_value"),
    )
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        for value in numeric
    ):
        raise ValueError(f"figure endpoint {point_id!r} has non-finite estimates")
    if any(not -1.0 <= float(value) <= 1.0 for value in numeric[:3]):
        raise ValueError(f"figure endpoint {point_id!r} lies outside the effect range")
    n_matched = metric.get("n_matched")
    n_clusters = metric.get("n_clusters")
    if (
        not isinstance(n_matched, int) or isinstance(n_matched, bool) or n_matched < 1
        or not isinstance(n_clusters, int) or isinstance(n_clusters, bool)
        or n_clusters < 1 or n_clusters > n_matched
    ):
        raise ValueError(f"figure endpoint {point_id!r} has invalid sample counts")
    return {
        "point_id": point_id,
        "status": "estimated_sample_conditional",
        "value": float(numeric[0]),
        "ci_low": float(numeric[1]),
        "ci_high": float(numeric[2]),
        "effect_direction": "left_minus_right",
        "left_value": float(numeric[3]),
        "right_value": float(numeric[4]),
        "n_pairs": n_matched,
        "n_clusters": n_clusters,
        "population": metric.get("population"),
        "corpus": corpus,
        "source": metric.get("source"),
        "risk_category": metric.get("risk_category"),
        "modality": metric.get("modality"),
        "source_policy_id": metric.get("source_policy_id"),
        "source_policy_version": metric.get("source_policy_version"),
        "metric": metric.get("metric_alias"),
        "requested_metric": metric.get("metric"),
        "comparison_type": facet.get("comparison_type"),
        "figure_group": figure_group,
        "left_arm": facet.get("left"),
        "right_arm": facet.get("right"),
        "bootstrap": metric.get("bootstrap"),
        "missingness_sensitivity": metric.get("missingness_sensitivity"),
    }


def _decision_binding(points: list[dict[str, Any]]) -> dict[str, Any]:
    configurations: dict[str, dict[str, Any]] = {}
    for point in points:
        for side in ("left_arm", "right_arm"):
            arm = point.get(side)
            if not isinstance(arm, dict):
                raise ValueError("figure endpoint lacks arm provenance")
            identities = arm.get("realized_identities")
            judges = identities.get("judges") if isinstance(identities, dict) else None
            normalized_judges = None
            if isinstance(judges, list):
                normalized_judges = [
                    {
                        "stage": judge.get("stage"),
                        "judge": judge.get("judge"),
                        "snapshot": judge.get("snapshot"),
                    }
                    for judge in judges if isinstance(judge, dict)
                ]
            value = {
                "judges": arm.get("judges"),
                "judge_configuration": arm.get("judge_configuration"),
                "realized_judges": normalized_judges,
            }
            configurations.setdefault(_sha256_json(value), value)
    if len(configurations) != 1:
        raise ValueError("figure cells mix judge-cascade decision configurations")
    (digest, configuration), = configurations.items()
    return {"policy_fingerprint": digest, "policy_defining_fields": configuration}


def _load_human_audit(
    results: Path, path: Path, *, expected_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    results = results.resolve()
    path = Path(path)
    if path.name != "human_audit.json" or path.resolve().parent != results:
        raise ValueError(
            "measured figures require human_audit.json directly under --results"
        )
    artifact = read_bound_json(path, expected_sha256=expected_sha256)
    identity = artifact.pop("_artifact_identity")
    readiness = artifact.get("analysis_readiness")
    checks = readiness.get("checks") if isinstance(readiness, dict) else None
    if (
        artifact.get("schema_version") != "ura-human-audit/1.1"
        or artifact.get("analysis_ready_real_run") is not True
        or not isinstance(readiness, dict)
        or readiness.get("status") != "complete_sample_conditional"
        or readiness.get("population_validity_claimed") is not False
        or not isinstance(checks, dict)
        or not checks
        or not all(value is True for value in checks.values())
    ):
        raise ValueError(
            "human audit is not integrity-complete, real-run, and sample-conditional"
        )
    validate_analysis_source_identity(artifact.get("analysis_source"))
    return artifact, identity


def _validate_human_figure_coverage(
    audit: dict[str, Any], points: list[dict[str, Any]],
) -> dict[str, Any]:
    """Require exact audited human sensitivity for every selected figure effect."""
    sensitivity = audit.get("primary_effect_sensitivity")
    if not isinstance(sensitivity, dict):
        raise ValueError(
            "broader human-audit cohort lacks primary effect sensitivity evidence"
        )
    arm_metadata = sensitivity.get("analysis_arm_metadata")
    cell_metadata = sensitivity.get("analysis_cell_metadata")
    pairwise = sensitivity.get("paired_model_effects")
    model_rates = sensitivity.get("model_endpoint_rates")
    human_rates = (
        model_rates.get("human_consensus") if isinstance(model_rates, dict) else None
    )
    if not all(isinstance(value, dict) for value in (
        arm_metadata, cell_metadata, pairwise, human_rates,
    )):
        raise ValueError(
            "broader human-audit cohort has incomplete primary sensitivity inventories"
        )

    verified: list[dict[str, Any]] = []
    for point in points:
        source = point.get("source")
        corpus = point.get("corpus")
        policy_id = point.get("source_policy_id")
        policy_version = point.get("source_policy_version")
        metric = point.get("metric")
        if any(
            not isinstance(value, str) or not value
            for value in (corpus, source, policy_id, policy_version, metric)
        ):
            raise ValueError(
                f"figure point {point.get('point_id')!r} lacks an exact human-analysis cell"
            )
        cell_id = human_analysis_cell_id(
            corpus, source, policy_id, policy_version,
            point.get("risk_category"), point.get("modality"), metric,
        )
        expected_cell = {
            "corpus": corpus,
            "source": source,
            "source_policy_id": policy_id,
            "source_policy_version": policy_version,
            "risk_category": point.get("risk_category"),
            "modality": point.get("modality"),
            "metric": metric,
        }
        observed_cell = cell_metadata.get(cell_id)
        if not isinstance(observed_cell, dict) or any(
            observed_cell.get(key) != value for key, value in expected_cell.items()
        ):
            raise ValueError(
                f"human audit lacks exact figure analysis cell {cell_id!r}"
            )

        arm_ids: list[str] = []
        for side in ("left_arm", "right_arm"):
            arm = point.get(side)
            if not isinstance(arm, dict):
                raise ValueError(f"figure point {point.get('point_id')!r} lacks {side}")
            model_spec = arm.get("model_spec", arm.get("requested_model_spec"))
            values = {
                "model_spec": model_spec,
                "resolved_target": arm.get("resolved_target"),
                "defense": arm.get("defense"),
                "attacker": arm.get("attacker"),
            }
            if any(not isinstance(value, str) or not value for value in values.values()):
                raise ValueError(
                    f"figure point {point.get('point_id')!r} has incomplete {side} identity"
                )
            arm_id = human_analysis_arm_id(
                values["model_spec"], values["resolved_target"],
                values["defense"], values["attacker"],
            )
            observed_arm = arm_metadata.get(arm_id)
            if not isinstance(observed_arm, dict) or any(
                observed_arm.get(key) != value for key, value in values.items()
            ):
                raise ValueError(
                    f"human audit lacks exact figure analysis arm {arm_id!r}"
                )
            rate = human_rates.get(cell_id, {}).get(arm_id)
            if (
                not isinstance(rate, dict)
                or not isinstance(rate.get("n_unique_clusters"), int)
                or isinstance(rate.get("n_unique_clusters"), bool)
                or rate["n_unique_clusters"] < 1
                or not isinstance(rate.get("rate"), (int, float))
                or isinstance(rate.get("rate"), bool)
                or not math.isfinite(float(rate["rate"]))
            ):
                raise ValueError(
                    f"human audit lacks supported human endpoint rate for {cell_id!r}/{arm_id!r}"
                )
            arm_ids.append(arm_id)

        matches = [
            record for record in pairwise.values()
            if isinstance(record, dict)
            and record.get("analysis_cell_id") == cell_id
            and {record.get("left_arm_id"), record.get("right_arm_id")} == set(arm_ids)
        ]
        if len(matches) != 1:
            raise ValueError(
                "human audit does not prove the exact paired figure effect for "
                f"{point.get('point_id')!r}"
            )
        record = matches[0]
        if (
            not isinstance(record.get("n_shared_unique_clusters"), int)
            or isinstance(record.get("n_shared_unique_clusters"), bool)
            or record["n_shared_unique_clusters"] < 1
            or not isinstance(record.get("human_consensus_effect"), (int, float))
            or isinstance(record.get("human_consensus_effect"), bool)
            or not math.isfinite(float(record["human_consensus_effect"]))
        ):
            raise ValueError(
                f"human audit paired figure effect lacks shared human support for {cell_id!r}"
            )
        verified.append({
            "point_id": point["point_id"],
            "analysis_cell_id": cell_id,
            "analysis_arm_ids": arm_ids,
            "n_shared_unique_clusters": record["n_shared_unique_clusters"],
        })
    return {
        "mode": "exact_human_sensitivity_for_selected_figure_effects",
        "verified_points": verified,
    }


def load_postrun_results(
    results: Path, *, left_model: str, right_model: str,
    human_audit: Path, human_audit_sha256: str, n_resamples: int = 2000,
    seed: int = 0, strongreject_corpus: str = "strongreject",
    mmsafety_corpus: str = "mmsafety", mossbench_corpus: str = "mossbench",
) -> dict[str, Any]:
    """Build the measured figure payload directly from completed run artifacts."""
    results = Path(results)
    if left_model == right_model:
        raise ValueError("measured figures require two different exact model specifications")
    corpus_aliases = {
        "strongreject": strongreject_corpus,
        "mmsafety": mmsafety_corpus,
        "mossbench": mossbench_corpus,
    }
    if any(
        not isinstance(value, str) or not value.strip()
        for value in corpus_aliases.values()
    ) or len(set(corpus_aliases.values())) != len(corpus_aliases):
        raise ValueError("figure corpus-arm aliases must be three distinct non-blank names")
    if not _valid_sha256(human_audit_sha256.lower()):
        raise ValueError("--human-audit-sha256 must be a lowercase SHA-256 digest")
    audit, audit_identity = _load_human_audit(
        results, human_audit, expected_sha256=human_audit_sha256.lower(),
    )

    replay_reports = {
        name: compare(
            results,
            left_model=left_model,
            right_model=right_model,
            attacker="replay",
            corpus=corpus,
            n_resamples=n_resamples,
            seed=seed,
        )
        for name, corpus in corpus_aliases.items()
    }

    strong_facet, strong_metric = _require_ready_facet(
        replay_reports["strongreject"], strongreject_corpus,
        metric_name="ASR",
    )
    overall_model = [_measured_point(
        point_id="model:strongreject:replay:ASR",
        corpus=strongreject_corpus,
        metric=strong_metric,
        facet=strong_facet,
        figure_group="overall_model",
    )]

    mm_facet, _ = _require_ready_facet(
        replay_reports["mmsafety"], mmsafety_corpus,
        metric_name="ASR",
    )
    policy_proxies: list[dict[str, Any]] = []
    for policy_name in MM_SAFETYBENCH_POLICY_DESCRIPTORS:
        policy = mm_safetybench_policy(policy_name)
        metric = _require_policy_metric(
            mm_facet,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            metric_name="ASR",
        )
        policy_proxies.append(_measured_point(
            point_id=f"proxy:mmsafety:{policy_name}:ASR",
            corpus=mmsafety_corpus,
            metric=metric,
            facet=mm_facet,
            figure_group="policy_proxies",
        ))

    moss_facet, _ = _require_ready_facet(
        replay_reports["mossbench"], mossbench_corpus,
        metric_name="over_refusal_rate",
    )
    moss_policy = mossbench_policy()
    policy_proxies.append(_measured_point(
        point_id="proxy:mossbench:benign-refusal-rate:FRR",
        corpus=mossbench_corpus,
        metric=_require_policy_metric(
            moss_facet,
            policy_id=moss_policy.policy_id,
            policy_version=moss_policy.version,
            metric_name="over_refusal_rate",
        ),
        facet=moss_facet,
        figure_group="policy_proxies",
    ))

    adaptivity: list[dict[str, Any]] = []
    adaptivity_reports: list[dict[str, Any]] = []
    for model in (left_model, right_model):
        report = compare_adaptivity(
            results,
            model=model,
            corpus=strongreject_corpus,
            n_resamples=n_resamples,
            seed=seed,
        )
        facet, metric = _require_ready_facet(
            report, strongreject_corpus, metric_name="ASR",
        )
        adaptivity_reports.append(report)
        adaptivity.append(_measured_point(
            point_id=f"adaptivity:{model}:replay-minus-crescendo:ASR",
            corpus=strongreject_corpus,
            metric=metric,
            facet=facet,
            figure_group="adaptivity",
        ))

    all_points = [*overall_model, *policy_proxies, *adaptivity]
    run_ids = sorted({
        str(arm["run_id"])
        for point in all_points
        for arm in (point["left_arm"], point["right_arm"])
        if isinstance(arm, dict) and arm.get("run_id")
    })
    results_identity = audit.get("results_identity")
    completed_run_ids = (
        results_identity.get("completed_run_ids")
        if isinstance(results_identity, dict) else None
    )
    labelled_run_ids = (
        results_identity.get("labelled_run_ids")
        if isinstance(results_identity, dict) else None
    )
    if (
        not isinstance(completed_run_ids, list)
        or completed_run_ids != sorted(set(completed_run_ids))
        or any(not isinstance(value, str) or not value for value in completed_run_ids)
        or not set(run_ids).issubset(completed_run_ids)
    ):
        raise ValueError("human audit does not bind every completed figure run")
    if (
        not isinstance(labelled_run_ids, list)
        or labelled_run_ids != sorted(set(labelled_run_ids))
        or any(not isinstance(value, str) or not value for value in labelled_run_ids)
        or not set(run_ids).issubset(labelled_run_ids)
    ):
        raise ValueError("human audit does not directly label every completed figure run")
    human_coverage_binding = _validate_human_figure_coverage(audit, all_points)
    human_coverage_binding["cohort_relation"] = (
        "exact_completed_figure_run_cohort"
        if completed_run_ids == run_ids
        else "selected_figure_runs_within_broader_audit_cohort"
    )
    binding = _decision_binding(all_points)
    return {
        "schema_version": "ura-chapter-v-figures/1.3",
        "illustrative": False,
        "analysis": {
            "status": "post_experiment_sample_conditional",
            "qualification": (
                "measured endpoints are conditional on the completed benchmark, "
                "judge cascade, and achieved human-audit sample; no population-wide "
                "judge-validity claim is made"
            ),
            "population_validity_claimed": False,
            "human_audit_artifact": audit_identity,
            "human_audit_readiness": audit["analysis_readiness"],
            "completed_run_ids": run_ids,
            "human_audit_completed_run_ids": completed_run_ids,
            "human_audit_labelled_run_ids": labelled_run_ids,
            "human_coverage_binding": human_coverage_binding,
            "corpus_arm_aliases": corpus_aliases,
            "results_locator": ".",
            **binding,
            "analysis_source": analysis_source_identity([
                Path(__file__), Path(__file__).resolve().parent / "figures.py",
                Path(__file__).resolve().parent / "paired_compare.py",
                Path(__file__).resolve().parents[1] / "src" / "ura" / "metrics.py",
            ]),
            "effect_direction": "left_minus_right",
            "corpus_pooling": "forbidden; every point is one explicit corpus facet",
        },
        "figures": {
            _FIGURE_NAMES[0]: {
                "estimand": "paired StrongREJECT replay ASR difference, left minus right",
                "figure_role": "primary_model",
                "points": overall_model,
            },
            _FIGURE_NAMES[1]: {
                "estimand": (
                    "paired policy-qualified proxy differences: six MM-SafetyBench "
                    "ASR strata and MOSSBench benign FRR"
                ),
                "figure_role": "secondary_policy_proxies",
                "points": policy_proxies,
            },
            _FIGURE_NAMES[2]: {
                "estimand": (
                    "per-model StrongREJECT replay-minus-Crescendo ASR difference"
                ),
                "figure_role": "adaptivity",
                "points": adaptivity,
            },
        },
    }

__all__ = [
    "load_defense_results", "load_model_results", "load_postrun_results",
]
