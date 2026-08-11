"""Content identities and strict readers shared by measured analyses."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, unquote

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MAX_ANALYSIS_JSON_BYTES = 64 * 1024 * 1024


def sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"analysis source/artifact must be a regular file: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analysis_source_identity(paths: Iterable[Path | str]) -> dict[str, Any]:
    """Digest every analysis implementation file and their ordered inventory."""
    records: list[dict[str, Any]] = []
    raw_paths = {Path(value) for value in paths}
    for raw in sorted(raw_paths, key=str):
        if raw.is_symlink():
            raise ValueError(f"analysis source must not be a symlink: {raw}")
        candidate = raw.resolve()
        try:
            relative = candidate.relative_to(_REPO_ROOT).as_posix()
        except ValueError as exc:
            raise ValueError(f"analysis source lies outside repository: {candidate}") from exc
        size = candidate.stat().st_size if candidate.is_file() else -1
        records.append({
            "path": relative,
            "bytes": size,
            "sha256": sha256_file(candidate),
        })
    if not records:
        raise ValueError("analysis source identity requires at least one file")
    encoded = json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {
        "algorithm": "sha256_canonical_file_inventory_v1",
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "file_count": len(records),
        "files": records,
    }


def read_bound_json(path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
    """Read one bounded regular JSON object and optionally verify its digest."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"expected a regular non-symlink JSON artifact: {path}")
    path = path.resolve()
    size = path.stat().st_size
    if size > _MAX_ANALYSIS_JSON_BYTES:
        raise ValueError(f"analysis JSON exceeds {_MAX_ANALYSIS_JSON_BYTES} bytes: {path}")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ValueError(f"analysis JSON changed while it was being read: {path}")
    observed = hashlib.sha256(payload).hexdigest()
    if expected_sha256 is not None and observed != expected_sha256.lower():
        raise ValueError(
            f"analysis artifact digest mismatch for {path}: {observed} != {expected_sha256}"
        )
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid UTF-8 JSON analysis artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"analysis artifact must be a JSON object: {path}")
    if "_artifact_identity" in value:
        raise ValueError(
            "analysis artifact contains the reserved _artifact_identity field: "
            f"{path}"
        )
    value["_artifact_identity"] = {
        "path": str(path), "bytes": size, "sha256": observed,
    }
    return value


def validate_analysis_source_identity(identity: Any) -> dict[str, Any]:
    """Verify a recorded analysis implementation inventory against this checkout."""
    if not isinstance(identity, dict) or set(identity) != {
        "algorithm", "sha256", "file_count", "files",
    }:
        raise ValueError("analysis-source identity has an invalid shape")
    if identity.get("algorithm") != "sha256_canonical_file_inventory_v1":
        raise ValueError("analysis-source identity has an unsupported algorithm")
    files = identity.get("files")
    if (
        not isinstance(files, list)
        or not files
        or identity.get("file_count") != len(files)
    ):
        raise ValueError("analysis-source identity has an invalid file inventory")
    paths: list[Path] = []
    recorded_paths: list[str] = []
    for record in files:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            raise ValueError("analysis-source file record has an invalid shape")
        relative = record.get("path")
        if not isinstance(relative, str) or not relative or "\\" in relative:
            raise ValueError("analysis-source record lacks a canonical repository path")
        candidate = (_REPO_ROOT / relative).resolve()
        try:
            canonical = candidate.relative_to(_REPO_ROOT).as_posix()
        except ValueError as exc:
            raise ValueError("analysis-source path escapes the repository") from exc
        if canonical != relative or candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"analysis-source path is not a regular canonical file: {relative}")
        observed_size = candidate.stat().st_size
        observed_digest = sha256_file(candidate)
        if record.get("bytes") != observed_size or record.get("sha256") != observed_digest:
            raise ValueError(f"analysis source has drifted: {relative}")
        paths.append(candidate)
        recorded_paths.append(relative)
    if recorded_paths != sorted(set(recorded_paths)):
        raise ValueError("analysis-source paths must be unique and canonically ordered")
    observed = analysis_source_identity(paths)
    if observed != identity:
        raise ValueError("analysis-source aggregate identity does not match its files")
    return observed


def source_policy_token(policy_id: str, version: str) -> str:
    """Unambiguous URL-escaped policy token safe inside ``::`` hypothesis IDs."""
    if not policy_id or not version:
        raise ValueError("source policy id/version must be non-blank")
    return f"policy={quote(policy_id, safe='')}@{quote(version, safe='')}"


def parse_source_policy_token(token: str) -> tuple[str, str]:
    if not token.startswith("policy=") or "@" not in token:
        raise ValueError(f"invalid source-policy token {token!r}")
    encoded_id, encoded_version = token[len("policy="):].split("@", 1)
    policy_id, version = unquote(encoded_id), unquote(encoded_version)
    if source_policy_token(policy_id, version) != token:
        raise ValueError(f"non-canonical source-policy token {token!r}")
    return policy_id, version


def human_analysis_cell_id(
    source: str, policy_id: str, policy_version: str,
    risk_category: str | None, modality: str | None, metric: str,
) -> str:
    """Canonical human-sensitivity cell matching a confirmatory endpoint scope."""
    values = (source, policy_id, policy_version, metric)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("human analysis cell components must be non-blank")
    risk = risk_category or "all"
    channel = modality or "all"
    return "::".join((
        f"source={quote(source, safe='')}",
        source_policy_token(policy_id, policy_version),
        f"risk={quote(risk, safe='')}",
        f"modality={quote(channel, safe='')}",
        f"metric={quote(metric, safe='')}",
    ))


def human_analysis_arm_id(
    model_spec: str, resolved_target: str, defense: str, attacker: str,
) -> str:
    """Canonical condition identity for human re-estimation of planned effects."""
    values = (model_spec, resolved_target, defense, attacker)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError("human analysis arm components must be non-blank")
    return "::".join((
        f"model_spec={quote(model_spec, safe='')}",
        f"target={quote(resolved_target, safe='')}",
        f"defense={quote(defense, safe='')}",
        f"attacker={quote(attacker, safe='')}",
    ))


__all__ = [
    "analysis_source_identity", "human_analysis_arm_id", "human_analysis_cell_id",
    "read_bound_json",
    "parse_source_policy_token", "sha256_file", "source_policy_token",
    "validate_analysis_source_identity",
]
