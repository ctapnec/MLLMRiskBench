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
    value.setdefault("_artifact_identity", {
        "path": str(path), "bytes": size, "sha256": observed,
    })
    return value


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


__all__ = [
    "analysis_source_identity", "human_analysis_cell_id", "read_bound_json",
    "parse_source_policy_token", "sha256_file", "source_policy_token",
]
