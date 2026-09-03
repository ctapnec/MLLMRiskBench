"""Persistent readiness-derived execution profiles for local models.

The operator registry is machine-local because it points at rig evidence. Each
entry is bound to an immutable model revision/digest and one validated
readiness receipt. CLI and Rig Web resolve the same registry.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from ura.strict_json import strict_json_loads


SCHEMA = "ura-local-model-execution-profiles/1"
_HEX40_64 = re.compile(r"[0-9a-f]{40,64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 4 * 1024 * 1024


def registry_path(repo_root: Path | None = None) -> Path:
    configured = os.environ.get("URA_LOCAL_MODEL_PROFILE_REGISTRY", "").strip()
    if configured:
        return Path(configured).expanduser()
    root = repo_root or Path(__file__).resolve().parents[1]
    return root / "experiments/local-model-profiles.json"


def _identity(config: Mapping[str, object]) -> dict[str, str]:
    revision = config.get("revision")
    digest = config.get("digest")
    if isinstance(revision, str) and _HEX40_64.fullmatch(revision.lower()):
        return {"revision": revision.lower()}
    if isinstance(digest, str) and _HEX64.fullmatch(digest.lower()):
        return {"digest": digest.lower()}
    raise ValueError("local model profile requires one immutable revision or digest")


def _read_document(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("local model profile registry must be a regular file")
    raw = path.read_bytes()
    if not 0 < len(raw) <= _MAX_BYTES:
        raise ValueError("local model profile registry exceeds its size bound")
    value = strict_json_loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise ValueError("local model profile registry schema changed")
    models = value.get("models")
    if not isinstance(models, dict):
        raise ValueError("local model profile registry models changed")
    return value


def load_profiles(
    repo_root: Path | None = None, *, path: Path | None = None
) -> dict[str, dict[str, Any]]:
    selected_path = path or registry_path(repo_root)
    if not selected_path.exists():
        return {}
    value = _read_document(selected_path)
    profiles: dict[str, dict[str, Any]] = {}
    for spec, entry in value["models"].items():
        if (
            not isinstance(spec, str)
            or not spec.startswith(("vllm:", "ollama:"))
            or not isinstance(entry, dict)
            or set(entry)
            != {
                "generation_tokens",
                "identity",
                "modalities",
                "readiness",
                "request_timeout_seconds",
            }
        ):
            raise ValueError("local model profile entry changed")
        identity = entry["identity"]
        modalities = entry["modalities"]
        readiness = entry["readiness"]
        generation_tokens = entry["generation_tokens"]
        timeout = entry["request_timeout_seconds"]
        if (
            not isinstance(identity, dict)
            or set(identity) not in ({"revision"}, {"digest"})
            or _identity(identity) != identity
            or not isinstance(modalities, list)
            or not modalities
            or "text" not in modalities
            or any(
                item not in {"text", "image", "audio", "video"}
                for item in modalities
            )
            or len(set(modalities)) != len(modalities)
            or isinstance(generation_tokens, bool)
            or not isinstance(generation_tokens, int)
            or not 1 <= generation_tokens <= 25_000
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 1 <= float(timeout) <= 3_600
            or not isinstance(readiness, dict)
            or set(readiness) != {"path", "sha256", "readiness_id"}
            or not isinstance(readiness["path"], str)
            or not readiness["path"]
            or _HEX64.fullmatch(str(readiness["sha256"])) is None
            or _HEX64.fullmatch(str(readiness["readiness_id"])) is None
        ):
            raise ValueError(f"local model profile {spec!r} is invalid")
        profiles[spec] = dict(entry)
    return profiles


def apply_profile(
    spec: str,
    config: Mapping[str, object],
    *,
    repo_root: Path | None = None,
    path: Path | None = None,
) -> tuple[dict[str, object], dict[str, Any] | None]:
    """Apply the identity-bound approved profile to one local config."""

    if not spec.startswith(("vllm:", "ollama:")):
        raise ValueError("execution profiles apply only to local vLLM or Ollama targets")
    result = dict(config)
    profile = load_profiles(repo_root, path=path).get(spec)
    if profile is None:
        return result, None
    from ura.targets.local import (
        validate_local_request_timeout,
        validate_ollama_num_predict,
        validate_vllm_max_tokens,
    )

    if spec.startswith("vllm:") and "max_tokens" in result:
        validate_vllm_max_tokens(result["max_tokens"])
    if spec.startswith("ollama:") and "num_predict" in result:
        validate_ollama_num_predict(result["num_predict"])
    if "timeout" in result:
        validate_local_request_timeout(result["timeout"])
    if _identity(result) != profile["identity"]:
        raise ValueError(f"local model profile identity differs for {spec!r}")
    if list(result.get("modalities", [])) != profile["modalities"]:
        raise ValueError(f"local model profile modalities differ for {spec!r}")
    if spec.startswith("vllm:"):
        result["max_tokens"] = profile["generation_tokens"]
    else:
        result["num_predict"] = profile["generation_tokens"]
    result["timeout"] = profile["request_timeout_seconds"]
    return result, profile


def update_registry(
    *,
    spec: str,
    local_config: Mapping[str, object],
    readiness_path: Path,
    readiness_sha256: str,
    readiness: Mapping[str, object],
    path: Path | None = None,
) -> Path:
    """Atomically retain one verified readiness-derived profile."""

    from experiments.local_model_readiness import validate_readiness

    validate_readiness(dict(readiness), expected_spec=spec)
    raw = readiness_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != readiness_sha256:
        raise ValueError("readiness receipt digest changed before profile update")
    execution = readiness.get("execution_profile")
    if not isinstance(execution, dict):
        raise ValueError("readiness receipt omitted its execution profile")
    selected = execution.get("selected_generation_tokens")
    timeout = execution.get("per_request_deadline_seconds")
    target = (path or registry_path()).expanduser()
    if target.exists():
        document = _read_document(target)
    else:
        document = {"schema": SCHEMA, "models": {}}
    models = dict(document["models"])
    models[spec] = {
        "generation_tokens": selected,
        "identity": _identity(local_config),
        "modalities": list(local_config["modalities"]),
        "readiness": {
            "path": str(readiness_path.resolve(strict=True)),
            "sha256": readiness_sha256,
            "readiness_id": readiness["readiness_id"],
        },
        "request_timeout_seconds": timeout,
    }
    payload = (
        json.dumps(
            {"schema": SCHEMA, "models": dict(sorted(models.items()))},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    if len(payload) > _MAX_BYTES:
        raise ValueError("local model profile registry exceeds its size bound")
    if target.is_symlink():
        raise ValueError("local model profile registry cannot be a symlink")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + f".tmp-{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


__all__ = ["SCHEMA", "apply_profile", "load_profiles", "registry_path", "update_registry"]
