"""Turnkey experiment driver for URA-Bench (thesis Chapter V).

Runs the model x attacker x judge matrix over one or more corpora, aggregates the
metrics, and writes per-cell JSONL plus a completed-grid directory consumed by
the integrity-checked analysis commands. Measured figures consume only the final
human-audit-bound confirmatory artifact, not raw grid roots.
Each cell also writes joinable Attempt/Response artifacts and an append-only
checkpoint. A matching completion marker makes reruns call-free; an interrupted
cell restores completed responses locally, including state needed by native
multi-turn attackers.

This is designed to run on the project rig with provider API keys in the
environment. Construction failures are reported before a cell begins; lazy SDK,
credential, model, and runtime failures produce a per-cell ``*.error.json`` plus
any partial checkpoint rather than silently shrinking the requested matrix. A
`--dry-run` uses the offline MockTarget so the whole flow is verifiable with no
keys and no GPU.

Examples
--------
# offline smoke of the whole matrix (no keys, no GPU):
python experiments/run_matrix.py --dry-run --limit 12 --out runs/dry

# cross-provider run: use the frozen Fable and Responses conditions (Pro is a
# mode, not a model slug):
# POSIX shell environment syntax is shown here. In PowerShell use
# ``$env:ANTHROPIC_API_KEY='...'`` and ``$env:OPENAI_API_KEY='...'``; see README.
export ANTHROPIC_API_KEY=...  OPENAI_API_KEY=...  GOOGLE_API_KEY=...
python experiments/run_matrix.py \
    --api "anthropic-fable:claude-fable-5;effort=high;max_tokens=25000,openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns" \
    --local vllm:Qwen/Qwen3-VL-8B-Instruct,vllm:google/gemma-3-27b-it,ollama:llama3.3:70b \
    --attackers replay,crescendo --judges rules,llm --judge-model claude-haiku-4-5-20251001 \
    --corpora synth --limit 200 --seeds 0,1 --out runs/full

Hosted comparison ids should be provider-qualified. The Fable case is the public
``claude-fable-5`` model with explicit high effort, adaptive thinking, a 25,000
token output ceiling, and no temperature parameter; live account access still
must pass preflight. The OpenAI case is the exact public ``gpt-5.6-sol`` model via
the Responses API with Pro mode, medium effort, and current-turn reasoning
context frozen as ``all_turns`` in the target specification; no Sol-Pro slug is
inferred. Such a
comparison is cross-provider and is not a causal same-base-model defense ablation.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import platform
import random
import re
import secrets
import sys
import time
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

# make `import ura` work when run as a script from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ura.adapters.base import AttackBudget           # noqa: E402
from ura.adapters.engines import get_attacker         # noqa: E402
from ura.converters import get_converter, synth_corpus  # noqa: E402
from ura.converters._common import (                    # noqa: E402
    canonical_converted_corpus_sha256,
)
from ura.converters.release_specs import CORPUS_RELEASE_SPECS  # noqa: E402
from ura.data_models import (                         # noqa: E402
    SCHEMA_VERSION,
    Attempt,
    DataPoint,
    EvalResult,
    Judgment,
    Response,
    RunManifest,
)
from ura.judges.base import JudgeCascade              # noqa: E402
from ura.judges.llm import LLMJudge                   # noqa: E402
from ura.judges.rules import RuleJudge                # noqa: E402
from ura.modality_coverage import (                    # noqa: E402
    ModalityCoverageError,
    ModalityCoveragePlan,
    plan_modality_coverage,
    verify_executed_modality_coverage,
)
from ura.runner import (                              # noqa: E402
    BudgetExhausted,
    CODE_VERSION,
    ExternalCallFailure,
    GlobalCallBudget,
    Runner,
    _component_config,
    _harness_source_identity,
    _portable_attempt_dump,
    realized_identity_summary,
)
from ura import source_metrics                        # noqa: E402
from ura.targets.api import (                              # noqa: E402
    build_api_target,
    preflight_api_target_runtime,
)


_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

_PROVIDER_DATA_POLICY_SCHEMA = "ura-provider-data-policy-approval/1.0"
_PARTITION_SCHEMA = "ura-cluster-partition/1.2"
_ALLOWED_GROUP_KEYS = {
    "model",
    "target",
    "attacker",
    "strategy",
    "source",
    "risk",
    "risk_category",
    "risk_subtype",
    "modality",
    "effective_modality",
    "is_multimodal",
    "expected_behavior",
    "attack_family",
    "seed",
    "source_policy_id",
    "source_policy_version",
}


class LockHeldError(RuntimeError):
    """An artifact lock has a live or not-yet-stale owner."""


class CircuitOpenError(RuntimeError):
    """A durable dependency circuit blocked a repeated external call."""


def _acquire_artifact_lock(
    path: Path, payload: dict[str, object], *, stale_seconds: int
) -> str:
    """Atomically acquire a lock; existing locks require manual removal.

    An earlier implementation inspected and then unlinked apparently stale
    locks.  That compare/delete sequence cannot be made ownership-safe across
    all supported filesystems.  Fail closed instead: PID/host/age metadata is
    diagnostic only, and an operator must verify and remove an abandoned lock.
    """
    if stale_seconds < 0:
        raise ValueError("lock stale interval must not be negative")
    token = secrets.token_hex(16)
    body = {
        **payload,
        "owner_token": token,
        "pid": os.getpid(),
        "host": platform.node(),
        "process_identity": _process_identity(os.getpid()),
        "created_epoch": time.time(),
    }
    encoded = (json.dumps(body, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        descriptor = os.open(str(path), flags)
    except FileExistsError as exc:
        raise LockHeldError(
            f"artifact lock already exists: {path}; automatic stale-lock "
            "reclamation is disabled. Verify that no owner is active, then "
            "remove this lock manually"
        ) from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    return token


def _release_artifact_lock(path: Path, token: str) -> None:
    """Remove only the lock still owned by ``token``."""
    try:
        payload = _json_loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if isinstance(payload, dict) and payload.get("owner_token") == token:
        path.unlink(missing_ok=True)


def _safe_external_audit(exc: Exception) -> dict[str, object]:
    value = getattr(exc, "call_audit", None)
    return dict(value) if isinstance(value, dict) else {}


def _remove_superseded_cell_errors(
    out: Path, *, corpus: str, model_spec: str, attacker: str
) -> None:
    """Remove old-code failure artifacts only after the same axis succeeds."""
    for path in out.glob("*.error.json"):
        try:
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                continue
            payload = _json_loads_strict(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            continue
        if not isinstance(payload, dict) or payload.get("status") != "error":
            continue
        if (
            payload.get("corpus") == corpus
            and payload.get("model_spec") == model_spec
            and payload.get("attacker") == attacker
        ):
            path.unlink(missing_ok=True)


def _safe_component(value: str, *, max_base: int = 48) -> str:
    """Return a bounded filesystem component with collision-resistant identity."""
    raw = str(value)
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", raw)
    cleaned = re.sub(r"\s+", "_", cleaned).strip(" ._") or "unnamed"
    if cleaned.lower() in _WINDOWS_RESERVED:
        cleaned = f"item-{cleaned}"
    cleaned = cleaned[:max_base].rstrip(" ._") or "unnamed"
    suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{cleaned}--{suffix}"


def _runtime_env() -> dict:
    """Capture reproducibility-relevant versions without importing backends."""
    packages = {}
    for package in (
        "pydantic", "numpy", "pandas", "torch", "transformers", "vllm",
        "anthropic", "openai", "google-genai", "google-generativeai", "ollama",
    ):
        try:
            packages[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            packages[package] = None
    return {
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "packages": packages,
    }


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(
        json.dumps(
            payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False
        ) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: object) -> str:
    material = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _partition_cluster_ids(
    cluster_ids: list[str], *, seed: int, corpus: str, pilot_count: int,
) -> tuple[list[str], list[str]]:
    """Reproduce the declared scoped-seed pilot/main assignment exactly."""
    if (
        not corpus
        or isinstance(seed, bool) or not isinstance(seed, int)
        or isinstance(pilot_count, bool) or not isinstance(pilot_count, int)
        or pilot_count < 1 or pilot_count >= len(cluster_ids)
        or len(set(cluster_ids)) != len(cluster_ids)
    ):
        raise ValueError("invalid deterministic cluster-partition inputs")
    scoped = int.from_bytes(hashlib.sha256(
        f"ura-pilot-main-partition-v1\0{seed}\0{corpus}".encode()
    ).digest()[:8], "big")
    shuffled = sorted(cluster_ids)
    random.Random(scoped).shuffle(shuffled)
    return sorted(shuffled[:pilot_count]), sorted(shuffled[pilot_count:])


def _record_count(path: Path) -> int:
    if path.name.endswith(".manifest.json"):
        return 1
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def _artifact_descriptor(path: Path) -> dict[str, object]:
    return {
        "file": path.name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
        "records": _record_count(path),
}


def _json_loads_strict(text: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r} is forbidden")

    return json.loads(text, parse_constant=reject_constant)


def _read_content_addressed_json(
    path_value: str,
    expected_sha256: str,
    *,
    flag_name: str,
    max_bytes: int,
) -> tuple[object, dict[str, object]]:
    """Read a bounded regular JSON file only when its exact bytes are approved."""
    if re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256 or "") is None:
        raise ValueError(f"{flag_name}-sha256 must be exactly 64 hexadecimal digits")
    path = Path(path_value)
    if path.is_symlink():
        raise ValueError(f"{flag_name} must be a regular non-symlink JSON file")
    path = path.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{flag_name} must be a regular non-symlink JSON file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(
            f"{flag_name} must be non-empty and no larger than {max_bytes} bytes"
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read {flag_name}: {exc}") from exc
    if len(raw) != size:
        raise ValueError(f"{flag_name} changed while being read")
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"{flag_name} sha256 mismatch: expected {expected_sha256.lower()}, "
            f"got {actual_sha256}"
        )
    try:
        value = _json_loads_strict(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {flag_name} JSON: {exc}") from exc
    return value, {
        "file": path.name,
        "sha256": actual_sha256,
        "bytes": size,
    }


def _hosted_provider(spec: str) -> str | None:
    """Return a stable provider namespace for a hosted model specification."""
    rendered = spec.strip()
    if not rendered or rendered == "mock":
        return None
    if ":" in rendered:
        provider = rendered.split(":", 1)[0].strip().lower()
        if provider in {"vllm", "ollama", "mock"}:
            return None
        return provider
    lowered = rendered.lower()
    if lowered.startswith("claude-"):
        return "anthropic"
    if lowered.startswith(("gpt-", "o1", "o3", "o4")):
        return "openai"
    if lowered.startswith("gemini-"):
        return "google"
    # A bare non-mock id is resolved through the hosted registry. Preserve that
    # fact explicitly when its provider cannot be inferred from the id alone.
    return "hosted-registry"


def _provider_policy_requirements(
    api_specs: list[str], judge_names: list[str], judge_model: str, *, dry_run: bool
) -> list[dict[str, object]]:
    if dry_run:
        return []
    roles_by_spec: dict[str, set[str]] = {}
    providers: dict[str, str] = {}
    for spec in api_specs:
        provider = _hosted_provider(spec)
        if provider is not None:
            roles_by_spec.setdefault(spec, set()).add("target")
            providers[spec] = provider
    if "llm" in judge_names:
        provider = _hosted_provider(judge_model)
        if provider is not None:
            roles_by_spec.setdefault(judge_model, set()).add("judge")
            providers[judge_model] = provider
    return [
        {
            "model_spec": spec,
            "provider": providers[spec],
            "roles": sorted(roles_by_spec[spec]),
        }
        for spec in sorted(roles_by_spec)
    ]


def _load_provider_data_policy_approval(
    path_value: str,
    sha256_value: str,
    requirements: list[dict[str, object]],
) -> dict[str, object]:
    """Validate explicit retention/data-use approval for every hosted call arm."""
    if not requirements:
        if path_value or sha256_value:
            raise ValueError(
                "provider data-policy approval was supplied, but this run makes no "
                "hosted provider calls"
            )
        return {
            "status": "not_applicable",
            "reason": "no_hosted_provider_calls",
        }
    if not path_value or not sha256_value:
        raise ValueError(
            "real hosted calls require both --provider-data-policy-approval and "
            "--provider-data-policy-sha256"
        )
    value, artifact = _read_content_addressed_json(
        path_value,
        sha256_value,
        flag_name="--provider-data-policy-approval",
        max_bytes=256 * 1024,
    )
    top_level = {
        "schema_version", "approval_id", "approved_by", "approved_at", "approvals",
    }
    if not isinstance(value, dict) or set(value) != top_level:
        raise ValueError(
            "provider data-policy approval must contain exactly schema_version, "
            "approval_id, approved_by, approved_at, and approvals"
        )
    if value.get("schema_version") != _PROVIDER_DATA_POLICY_SCHEMA:
        raise ValueError(
            f"provider data-policy schema must be {_PROVIDER_DATA_POLICY_SCHEMA!r}"
        )
    for field in ("approval_id", "approved_by"):
        item = value.get(field)
        if not isinstance(item, str) or not item.strip() or len(item) > 256:
            raise ValueError(f"provider data-policy {field} must be a bounded string")
    approved_at = value.get("approved_at")
    if not isinstance(approved_at, str) or len(approved_at) > 128:
        raise ValueError("provider data-policy approved_at must be an ISO-8601 string")
    try:
        timestamp = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("provider data-policy approved_at is not valid ISO-8601") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError("provider data-policy approved_at must include a timezone")

    approvals = value.get("approvals")
    if not isinstance(approvals, list) or not approvals:
        raise ValueError("provider data-policy approvals must be a non-empty list")
    expected = {
        str(item["model_spec"]): {
            "provider": item["provider"], "roles": item["roles"]
        }
        for item in requirements
    }
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    approval_fields = {
        "model_spec", "provider", "roles", "retention_terms",
        "data_use_terms", "policy_urls",
    }
    for index, item in enumerate(approvals):
        if not isinstance(item, dict) or set(item) != approval_fields:
            raise ValueError(
                f"provider data-policy approvals[{index}] has an invalid field inventory"
            )
        spec = item.get("model_spec")
        provider = item.get("provider")
        roles = item.get("roles")
        if not isinstance(spec, str) or spec not in expected or spec in seen:
            raise ValueError(
                "provider data-policy approvals must name each selected hosted "
                "model specification exactly once"
            )
        seen.add(spec)
        if provider != expected[spec]["provider"]:
            raise ValueError(f"provider data-policy provider mismatch for {spec!r}")
        if (
            not isinstance(roles, list)
            or any(role not in {"target", "judge"} for role in roles)
            or len(set(roles)) != len(roles)
            or sorted(roles) != expected[spec]["roles"]
        ):
            raise ValueError(f"provider data-policy roles mismatch for {spec!r}")
        for field in ("retention_terms", "data_use_terms"):
            term = item.get(field)
            if not isinstance(term, str) or not term.strip() or len(term) > 4096:
                raise ValueError(
                    f"provider data-policy {field} for {spec!r} must be an "
                    "explicit bounded acceptance string"
                )
        urls = item.get("policy_urls")
        if (
            not isinstance(urls, list) or not urls or len(urls) > 16
            or any(
                not isinstance(url, str) or not url.startswith("https://")
                or len(url) > 2048 for url in urls
            )
            or len(set(urls)) != len(urls)
        ):
            raise ValueError(
                f"provider data-policy policy_urls for {spec!r} must be unique "
                "HTTPS URLs"
            )
        normalized.append({
            "model_spec": spec,
            "provider": provider,
            "roles": sorted(roles),
            "retention_terms": item["retention_terms"].strip(),
            "data_use_terms": item["data_use_terms"].strip(),
            "policy_urls": list(urls),
        })
    if seen != set(expected):
        missing = sorted(set(expected) - seen)
        raise ValueError(
            "provider data-policy approval is missing selected model specs: "
            + ", ".join(missing)
        )
    return {
        "status": "approved",
        "schema_version": _PROVIDER_DATA_POLICY_SCHEMA,
        "approval_id": value["approval_id"].strip(),
        "approved_by": value["approved_by"].strip(),
        "approved_at": timestamp.isoformat(),
        "approvals": sorted(normalized, key=lambda item: str(item["model_spec"])),
        "artifact": artifact,
    }


def _load_partition_plan(
    path_value: str,
    sha256_value: str,
    role: str,
    corpora: list[str],
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Validate and normalize an exhaustive pilot/main source-cluster plan."""
    value, artifact = _read_content_addressed_json(
        path_value,
        sha256_value,
        flag_name="--partition-plan",
        max_bytes=16 * 1024 * 1024,
    )
    if not isinstance(value, dict):
        raise ValueError("--partition-plan must contain a JSON object")
    if set(value) != {
        "schema_version", "seed", "algorithm", "minimum_pilot_policy_clusters",
        "minimum_main_policy_clusters", "corpora", "analysis_source",
    }:
        raise ValueError("partition plan has an invalid top-level field inventory")
    schema = value.get("schema_version")
    if schema != _PARTITION_SCHEMA:
        raise ValueError(f"partition plan schema must be {_PARTITION_SCHEMA!r}")
    algorithm = value.get("algorithm")
    seed = value.get("seed")
    minimum_pilot_policy_clusters = value.get("minimum_pilot_policy_clusters")
    minimum_main_policy_clusters = value.get("minimum_main_policy_clusters")
    plan_corpora = value.get("corpora")
    if algorithm != "sha256_scoped_seed_random_partition_v1":
        raise ValueError("partition plan algorithm is unsupported")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("partition plan seed must be an integer")
    if (
        isinstance(minimum_pilot_policy_clusters, bool)
        or not isinstance(minimum_pilot_policy_clusters, int)
        or minimum_pilot_policy_clusters < 1
    ):
        raise ValueError(
            "partition plan minimum_pilot_policy_clusters must be positive"
        )
    if (
        isinstance(minimum_main_policy_clusters, bool)
        or not isinstance(minimum_main_policy_clusters, int)
        or minimum_main_policy_clusters < 1
    ):
        raise ValueError(
            "partition plan minimum_main_policy_clusters must be positive"
        )
    expected_corpora = {name for name in corpora if name != "synth"}
    if (
        not isinstance(plan_corpora, dict)
        or any(
            not isinstance(name, str) or not name.strip()
            for name in plan_corpora
        )
        or not expected_corpora.issubset(plan_corpora)
    ):
        raise ValueError(
            "partition plan must contain every selected non-synthetic corpus"
        )
    assignments: dict[str, dict[str, object]] = {}
    for name in sorted(plan_corpora):
        entry = plan_corpora[name]
        if not isinstance(entry, dict):
            raise ValueError(f"partition plan corpus {name!r} must be an object")
        if set(entry) != {
            "source_locator", "full_converted_corpus_sha256", "total_records",
            "total_clusters",
            "total_cluster_ids", "total_cluster_ids_sha256", "pilot", "main",
        }:
            raise ValueError(
                f"partition plan corpus {name!r} has an invalid field inventory"
            )
        source_locator = entry.get("source_locator")
        expected_locator = _stable_source_locator(name, None)
        if (
            not isinstance(source_locator, dict)
            or set(source_locator) != {
                "corpus", "configuration_env", "source_kind", "required_layout"
            }
            or source_locator.get("corpus") != expected_locator["corpus"]
            or source_locator.get("configuration_env")
            != expected_locator["configuration_env"]
            or source_locator.get("required_layout")
            != expected_locator["required_layout"]
            or source_locator.get("source_kind") not in {"file", "directory"}
        ):
            raise ValueError(
                f"partition plan corpus {name!r} has an invalid source locator"
            )
        converted_sha = entry.get("full_converted_corpus_sha256")
        total_records = entry.get("total_records")
        total_clusters = entry.get("total_clusters")
        total_cluster_ids = entry.get("total_cluster_ids")
        total_cluster_digest = entry.get("total_cluster_ids_sha256")
        if re.fullmatch(r"[0-9a-f]{64}", str(converted_sha or "")) is None:
            raise ValueError(f"partition plan corpus {name!r} has invalid converted digest")
        if (
            isinstance(total_records, bool) or not isinstance(total_records, int)
            or total_records <= 0
            or isinstance(total_clusters, bool) or not isinstance(total_clusters, int)
            or total_clusters <= 1
            or not isinstance(total_cluster_ids, list)
            or any(
                not isinstance(item, str) or not item.strip()
                for item in total_cluster_ids
            )
            or len(total_cluster_ids) != total_clusters
            or len(set(total_cluster_ids)) != len(total_cluster_ids)
            or total_cluster_ids != sorted(total_cluster_ids)
            or _sha256_json(total_cluster_ids) != total_cluster_digest
            or re.fullmatch(r"[0-9a-f]{64}", str(total_cluster_digest or "")) is None
        ):
            raise ValueError(f"partition plan corpus {name!r} has invalid totals")
        role_payloads: dict[str, dict[str, object]] = {}
        role_sets: dict[str, set[str]] = {}
        for partition_role in ("pilot", "main"):
            selection = entry.get(partition_role)
            if (
                not isinstance(selection, dict)
                or set(selection) != {
                    "n_clusters", "cluster_ids", "cluster_ids_sha256",
                    "source_policy_cluster_counts",
                }
            ):
                raise ValueError(
                    f"partition plan corpus {name!r} lacks {partition_role!r} selection"
                )
            ids = selection.get("cluster_ids")
            count = selection.get("n_clusters")
            digest = selection.get("cluster_ids_sha256")
            policy_counts = selection.get("source_policy_cluster_counts")
            if (
                not isinstance(ids, list) or not ids
                or any(not isinstance(item, str) or not item.strip() for item in ids)
                or len(set(ids)) != len(ids)
                or ids != sorted(ids)
                or count != len(ids)
                or digest != _sha256_json(ids)
                or not isinstance(policy_counts, dict)
                or not policy_counts
                or any(
                    not isinstance(key, str) or not key.strip()
                    or isinstance(value, bool) or not isinstance(value, int)
                    or value <= 0
                    for key, value in policy_counts.items()
                )
                or sum(policy_counts.values()) != len(ids)
            ):
                raise ValueError(
                    f"partition plan corpus {name!r} has invalid {partition_role} clusters"
                )
            if partition_role == "pilot" and any(
                value < minimum_pilot_policy_clusters
                for value in policy_counts.values()
            ):
                raise ValueError(
                    f"partition plan corpus {name!r} pilot source-policy strata "
                    "are below minimum_pilot_policy_clusters"
                )
            if partition_role == "main" and any(
                value < minimum_main_policy_clusters
                for value in policy_counts.values()
            ):
                raise ValueError(
                    f"partition plan corpus {name!r} main source-policy strata "
                    "are below minimum_main_policy_clusters"
                )
            role_sets[partition_role] = set(ids)
            role_payloads[partition_role] = {
                "n_clusters": len(ids),
                "cluster_ids": list(ids),
                "cluster_ids_sha256": digest,
                "source_policy_cluster_counts": dict(sorted(policy_counts.items())),
            }
        union = role_sets["pilot"] | role_sets["main"]
        if role_sets["pilot"] & role_sets["main"]:
            raise ValueError(f"partition plan corpus {name!r} pilot/main overlap")
        if union != set(total_cluster_ids):
            raise ValueError(
                f"partition plan corpus {name!r} is not exhaustive over source clusters"
            )
        expected_pilot, expected_main = _partition_cluster_ids(
            list(total_cluster_ids), seed=seed, corpus=name,
            pilot_count=len(role_payloads["pilot"]["cluster_ids"]),
        )
        if (
            role_payloads["pilot"]["cluster_ids"] != expected_pilot
            or role_payloads["main"]["cluster_ids"] != expected_main
        ):
            raise ValueError(
                f"partition plan corpus {name!r} does not match its declared "
                "scoped-seed random assignment"
            )
        if name in expected_corpora:
            assignments[name] = {
                "source_locator": source_locator,
                "full_converted_corpus_sha256": converted_sha,
                "total_records": total_records,
                "total_clusters": total_clusters,
                "total_cluster_ids": list(total_cluster_ids),
                "total_cluster_ids_sha256": total_cluster_digest,
                "partition_role": role,
                **role_payloads[role],
            }
    binding = {
        "status": "bound",
        "schema_version": schema,
        "algorithm": algorithm,
        "seed": seed,
        "minimum_pilot_policy_clusters": minimum_pilot_policy_clusters,
        "minimum_main_policy_clusters": minimum_main_policy_clusters,
        "partition_role": role,
        "artifact": artifact,
    }
    return binding, assignments


_SECRET_CONFIG_KEY = re.compile(
    r"(?:api[_-]?key|token|secret|password|authorization|cookie|private[_-]?key)",
    re.IGNORECASE,
)


def _load_attacker_config(
    path_value: str, selected_attackers: list[str]
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load constructor kwargs without admitting literal secrets.

    External tools receive credentials only through their explicit
    ``credential_env`` allowlist. Persisting a literal key in this JSON would
    leak it into grid and run manifests, so secret-like keys are rejected at any
    nesting level.
    """

    if not path_value:
        return {}, None
    path = Path(path_value).resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError("--attacker-config must be a regular non-symlink JSON file")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("--attacker-config exceeds the 1 MiB limit")
    try:
        value = _json_loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid --attacker-config JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("--attacker-config must be an object keyed by attacker name")
    normalized: dict[str, dict[str, object]] = {}
    for raw_name, raw_config in value.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            raise ValueError("attacker config keys must be non-blank strings")
        name = raw_name.strip().lower()
        if name in normalized:
            raise ValueError(f"duplicate normalized attacker config key {name!r}")
        if not isinstance(raw_config, dict):
            raise ValueError(f"attacker config {name!r} must be an object")

        def reject_secrets(node: object, trail: tuple[str, ...] = ()) -> None:
            if isinstance(node, dict):
                for key, child in node.items():
                    if not isinstance(key, str):
                        raise ValueError(
                            f"attacker config {name!r} contains a non-string key"
                        )
                    if key != "credential_env" and _SECRET_CONFIG_KEY.search(key):
                        location = ".".join((*trail, key))
                        raise ValueError(
                            f"literal secret-like attacker config field {location!r} "
                            "is forbidden; use credential_env names"
                        )
                    reject_secrets(child, (*trail, key))
            elif isinstance(node, list):
                for index, child in enumerate(node):
                    reject_secrets(child, (*trail, str(index)))

        reject_secrets(raw_config)
        normalized[name] = dict(raw_config)
    selected = {name.lower() for name in selected_attackers}
    unused = sorted(set(normalized) - selected)
    if unused:
        raise ValueError(
            "--attacker-config contains unselected attackers: " + ", ".join(unused)
        )
    return normalized, {
        "file": path.name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _record_executed_modality_evidence(
    target_name: str,
    attempts: list[Attempt],
    responses: list[Response],
    destination: dict[str, set[tuple[str, tuple[str, ...]]]],
) -> None:
    """Record exact evaluable combinations that reached the base target."""
    response_by_attempt = {response.attempt_id: response for response in responses}
    if len(response_by_attempt) != len(responses):
        raise ValueError("duplicate response attempt id in modality evidence")
    for attempt in attempts:
        response = response_by_attempt.get(attempt.id)
        if response is None:
            raise ValueError("modality evidence lacks an Attempt/Response join")
        input_blocked = (
            response.raw.get("defense") == "blocked"
            and response.raw.get("stage") == "input"
        )
        policy_evaluable = attempt.params.get("policy_evaluable_turn")
        if not isinstance(policy_evaluable, bool):
            raise ValueError(
                "modality evidence attempt lacks boolean policy_evaluable_turn"
            )
        if not input_blocked and policy_evaluable:
            physical = {
                media.modality
                for turn in attempt.rendered_input
                for media in turn.media
            }
            has_text = any(
                bool((turn.content or "").strip())
                or turn.tool_call is not None
                or bool((turn.tool_result or "").strip())
                for turn in attempt.rendered_input
            )
            combination = tuple(
                modality
                for modality in ("text", "image", "audio", "video")
                if modality in physical or (modality == "text" and has_text)
            )
            destination[target_name].add((attempt.datapoint_id, combination))


_COVERAGE_PROOF_SCHEMA = "ura-modality-coverage-proof/1.0"


def _coverage_condition(
    target_name: str,
    target_component: object,
    defense: str,
    defense_guard: str,
) -> tuple[str, str, str, str | None]:
    return (
        target_name,
        _sha256_json(target_component),
        defense,
        defense_guard if defense != "none" else None,
    )


def _verified_relative_artifact(
    root: Path,
    descriptor: object,
    *,
    label: str,
    max_bytes: int,
) -> Path:
    if not isinstance(descriptor, dict):
        raise ValueError(f"{label} lacks an artifact descriptor")
    name = descriptor.get("file")
    if (
        not isinstance(name, str)
        or not name
        or Path(name).name != name
    ):
        raise ValueError(f"{label} has an unsafe artifact name")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} artifact is missing or not regular")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes or descriptor.get("bytes") != size:
        raise ValueError(f"{label} artifact byte count is invalid")
    if descriptor.get("sha256") != _sha256_file(path):
        raise ValueError(f"{label} artifact digest mismatch")
    records = descriptor.get("records")
    if records is not None and records != _record_count(path):
        raise ValueError(f"{label} artifact record count mismatch")
    return path


def _reconstruct_companion_conditions(
    root: Path,
    grid_descriptor: object,
    marker_descriptors: object,
    *,
    expected_driver_source: dict[str, object],
    expected_harness_source: dict[str, object],
) -> list[dict[str, object]]:
    grid_path = _verified_relative_artifact(
        root, grid_descriptor, label="companion grid", max_bytes=16 * 1024 * 1024
    )
    grid = _json_loads_strict(grid_path.read_text(encoding="utf-8"))
    if (
        not isinstance(grid, dict)
        or grid.get("status") != "complete"
        or grid.get("n_errors") != 0
        or not isinstance(grid.get("cells"), list)
    ):
        raise ValueError("companion grid is not a completed zero-error grid")
    request = grid.get("request")
    if (
        not isinstance(request, dict)
        or request.get("driver_source") != expected_driver_source
    ):
        raise ValueError("companion grid was produced by stale experiment-driver source")
    if not isinstance(marker_descriptors, list) or not marker_descriptors:
        raise ValueError("companion proof has no completion markers")
    expected_markers = {
        cell.get("completion_marker")
        for cell in grid["cells"]
        if isinstance(cell, dict)
        and cell.get("status") in {"complete", "complete_existing"}
    }
    described_markers = {
        item.get("file") for item in marker_descriptors if isinstance(item, dict)
    }
    if None in expected_markers or described_markers != expected_markers:
        raise ValueError(
            "companion proof completion markers do not exactly cover its grid"
        )

    evidence_by_condition: dict[
        tuple[str, str, str, str | None],
        set[tuple[str, tuple[str, ...]]],
    ] = defaultdict(set)
    required = {
        "attempts", "responses", "judgments", "trails", "results", "manifest"
    }
    for marker_descriptor in marker_descriptors:
        marker_path = _verified_relative_artifact(
            root, marker_descriptor,
            label="companion completion marker", max_bytes=1024 * 1024,
        )
        marker = _json_loads_strict(marker_path.read_text(encoding="utf-8"))
        if (
            not isinstance(marker, dict)
            or marker.get("status") != "complete"
            or marker.get("format_version") != 2
            or marker.get("code_version") != CODE_VERSION
            or marker.get("schema_version") != SCHEMA_VERSION
            or not isinstance(marker.get("artifacts"), dict)
            or set(marker["artifacts"]) != required
        ):
            raise ValueError("companion completion marker is stale or malformed")
        paths = {
            name: _verified_relative_artifact(
                root, marker["artifacts"][name],
                label=f"companion {name}", max_bytes=512 * 1024 * 1024,
            )
            for name in required
        }
        manifest = RunManifest.model_validate_json(
            paths["manifest"].read_text(encoding="utf-8")
        )
        if (
            manifest.run_id != marker.get("run_id")
            or manifest.code_version != CODE_VERSION
            or manifest.schema_version != SCHEMA_VERSION
            or len(manifest.models) != 1
        ):
            raise ValueError("companion manifest identity is inconsistent")
        run_config = manifest.config.get("run")
        components = manifest.config.get("components")
        if not isinstance(run_config, dict) or not isinstance(components, dict):
            raise ValueError("companion manifest lacks run/component identity")
        if (
            run_config.get("driver_source") != expected_driver_source
            or manifest.config.get("harness_source") != expected_harness_source
        ):
            raise ValueError("companion manifest was produced by stale source code")
        condition = _coverage_condition(
            manifest.models[0],
            components.get("target"),
            str(run_config.get("defense")),
            str(run_config.get("defense_guard")),
        )
        attempts = [Attempt.model_validate(row) for row in _read_jsonl(
            paths["attempts"]
        )]
        responses = [Response.model_validate(row) for row in _read_jsonl(
            paths["responses"]
        )]
        if (
            not attempts
            or Counter(row.id for row in attempts)
            != Counter(row.attempt_id for row in responses)
            or any(row.target != manifest.models[0] for row in attempts)
            or any(row.target != manifest.models[0] for row in responses)
            or any(row.run_id != manifest.run_id for row in attempts)
            or any(row.run_id != manifest.run_id for row in responses)
        ):
            raise ValueError("companion Attempt/Response lineage is inconsistent")
        observed = {manifest.models[0]: set()}
        _record_executed_modality_evidence(
            manifest.models[0], attempts, responses, observed
        )
        evidence_by_condition[condition].update(observed[manifest.models[0]])

    return [
        {
            "target": condition[0],
            "target_component_sha256": condition[1],
            "defense": condition[2],
            "defense_guard": condition[3],
            "evidence": [
                {"datapoint_id": datapoint_id, "combination": list(combination)}
                for datapoint_id, combination in sorted(evidence)
            ],
        }
        for condition, evidence in sorted(evidence_by_condition.items())
    ]


def _load_companion_coverage(
    path_value: str,
    sha256_value: str,
    expected_conditions: set[tuple[str, str, str, str | None]],
    *,
    expected_driver_source: dict[str, object],
    expected_harness_source: dict[str, object],
) -> tuple[dict[str, object], dict[str, set[tuple[str, tuple[str, ...]]]]]:
    value, artifact = _read_content_addressed_json(
        path_value, sha256_value,
        flag_name="--modality-coverage-companion", max_bytes=16 * 1024 * 1024,
    )
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema_version", "grid", "completion_markers", "conditions"
        }
        or value.get("schema_version") != _COVERAGE_PROOF_SCHEMA
    ):
        raise ValueError("modality companion proof has an invalid schema")
    root = Path(path_value).resolve(strict=True).parent
    reconstructed = _reconstruct_companion_conditions(
        root, value["grid"], value["completion_markers"],
        expected_driver_source=expected_driver_source,
        expected_harness_source=expected_harness_source,
    )
    if reconstructed != value.get("conditions"):
        raise ValueError("modality companion proof evidence does not reconstruct")
    found: set[tuple[str, str, str, str | None]] = set()
    evidence: dict[str, set[tuple[str, tuple[str, ...]]]] = defaultdict(set)
    for row in reconstructed:
        condition = (
            str(row["target"]), str(row["target_component_sha256"]),
            str(row["defense"]),
            row["defense_guard"] if row["defense_guard"] is None
            else str(row["defense_guard"]),
        )
        if condition not in expected_conditions:
            continue
        found.add(condition)
        for item in row["evidence"]:
            evidence[condition[0]].add((
                str(item["datapoint_id"]), tuple(item["combination"])
            ))
    if found != expected_conditions:
        raise ValueError(
            "modality companion does not prove every exact target/defense condition"
        )
    binding = {
        "status": "verified",
        "artifact": artifact,
        "grid_sha256": value["grid"]["sha256"],
        "conditions_sha256": _sha256_json(reconstructed),
    }
    return binding, evidence


def _apply_companion_coverage(
    plan: ModalityCoveragePlan,
    evidence: dict[str, set[tuple[str, tuple[str, ...]]]],
    proof_sha256: str,
) -> ModalityCoveragePlan:
    items = []
    missing: list[str] = []
    for item in plan.items:
        if item.status != "available_but_unselected":
            items.append(item)
            continue
        matching_ids = sorted({
            datapoint_id
            for datapoint_id, combination in evidence.get(item.target, set())
            if combination == item.combination
        })
        if not matching_ids:
            missing.append(f"{item.target}:{'+'.join(item.combination)}")
            items.append(item)
            continue
        items.append(replace(
            item,
            status="executed",
            eligible_datapoint_ids=tuple(matching_ids),
            justification=(
                "executed in content-addressed companion modality proof "
                f"sha256:{proof_sha256.lower()}"
            ),
        ))
    if missing:
        raise ModalityCoverageError(
            "companion modality proof lacks required combinations: "
            + ", ".join(missing)
        )
    return replace(plan, enforcement="strict", items=tuple(items))


def _load_local_config(
    path_value: str, selected_specs: list[str]
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load exact immutable identities and declared modalities for local targets."""
    if not selected_specs:
        if path_value:
            raise ValueError("--local-config was supplied but --local selected no targets")
        return {}, None
    if not path_value:
        raise ValueError(
            "measured --local targets require --local-config with immutable identity "
            "and modalities"
        )
    path = Path(path_value).resolve(strict=True)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("--local-config must be a regular <=1 MiB JSON file")
    value = _json_loads_strict(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != set(selected_specs):
        raise ValueError(
            "--local-config keys must exactly match the selected --local specs"
        )
    normalized: dict[str, dict[str, object]] = {}
    for spec in selected_specs:
        config = value[spec]
        if not isinstance(config, dict) or set(config) - {
            "revision", "digest", "modalities",
        }:
            raise ValueError(
                f"local config {spec!r} may contain only revision/digest/modalities"
            )
        modalities = config.get("modalities")
        if (
            not isinstance(modalities, list)
            or not modalities
            or any(item not in {"text", "image"} for item in modalities)
            or "text" not in modalities
            or len(set(modalities)) != len(modalities)
        ):
            raise ValueError(
                f"local config {spec!r} requires unique declared text[/image] modalities"
            )
        backend = spec.split(":", 1)[0].lower()
        revision = config.get("revision")
        digest = config.get("digest")
        if backend == "vllm":
            if bool(revision) == bool(digest):
                raise ValueError(
                    f"vLLM config {spec!r} requires exactly one revision or digest"
                )
        elif backend == "ollama":
            if revision is not None or not isinstance(digest, str):
                raise ValueError(
                    f"Ollama config {spec!r} requires digest and forbids revision"
                )
        else:
            raise ValueError(f"unsupported local backend in {spec!r}")
        normalized[spec] = dict(config)
    return normalized, {
        "file": path.name,
        "sha256": _sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = _json_loads_strict(line)
            if not isinstance(value, dict):
                raise ValueError(f"non-object JSONL row in {path}:{line_number}")
            rows.append(value)
    return rows


_BUDGET_COUNTER_FIELDS = ("target_calls", "judge_calls", "http_attempts")
_CALL_AUDIT_FIELDS = {
    "transport_attempt_count", "logical_call_count", "provider", "operation",
    "resolved_model", "status_code", "error_type", "provider_request_id",
    "provider_response_id",
}
_CIRCUIT_ENTRY_FIELDS = {
    "opened_at", "exception_type", "phase", "message", "call_audit",
    "budget_snapshot",
}


def _read_bounded_recovery_json(
    path: Path, *, label: str, max_bytes: int = 1024 * 1024,
) -> dict[str, object]:
    """Read one bounded regular recovery artifact without following symlinks."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink JSON file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(
            f"{label} must be non-empty and no larger than {max_bytes} bytes"
        )
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError(f"{label} changed while being read")
    try:
        payload = _json_loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is malformed JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return payload


def _validate_recovery_call_audit(value: object, *, label: str) -> None:
    if not isinstance(value, dict) or set(value) - _CALL_AUDIT_FIELDS:
        raise ValueError(f"{label} has invalid failed-call audit provenance")
    for key, item in value.items():
        if key in {"transport_attempt_count", "logical_call_count"}:
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise ValueError(f"{label} has invalid failed-call audit {key}")
        elif not (
            (isinstance(item, int) and not isinstance(item, bool))
            or (isinstance(item, str) and len(item) <= 512)
        ):
            raise ValueError(f"{label} has invalid failed-call audit {key}")


def _validate_circuit_entry(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _CIRCUIT_ENTRY_FIELDS:
        raise ValueError(f"{label} has an invalid circuit entry")
    for field in ("opened_at", "exception_type", "phase", "message"):
        item = value.get(field)
        if not isinstance(item, str) or not item or len(item) > 2000:
            raise ValueError(f"{label} has invalid circuit {field}")
    _validate_recovery_call_audit(
        value.get("call_audit"), label=f"{label} circuit"
    )
    if not isinstance(value.get("budget_snapshot"), dict):
        raise ValueError(f"{label} lacks a circuit budget snapshot")
    return dict(value)


def _load_circuit_state(path: Path, *, grid_id: str) -> dict[str, dict[str, object]]:
    payload = _read_bounded_recovery_json(path, label="circuit state")
    if (
        set(payload) != {"format_version", "grid_id", "circuits"}
        or payload.get("format_version") != 1
        or payload.get("grid_id") != grid_id
        or not isinstance(payload.get("circuits"), dict)
    ):
        raise ValueError("invalid circuit state")
    circuits: dict[str, dict[str, object]] = {}
    for key, value in payload["circuits"].items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("circuit state has an invalid dependency key")
        circuits[key] = _validate_circuit_entry(
            value, label=f"circuit state {key!r}"
        )
    return circuits


def _same_grid_budget_snapshot(
    value: object, current: dict[str, object], *, label: str,
) -> dict[str, object] | None:
    """Validate one persisted snapshot if it belongs to the active grid."""
    if not isinstance(value, dict) or value.get("budget_id") != current["budget_id"]:
        return None
    if set(value) != set(current):
        raise ValueError(f"{label} has an invalid call-budget snapshot")
    for field in set(current) - set(_BUDGET_COUNTER_FIELDS):
        if value.get(field) != current[field]:
            raise ValueError(f"{label} call-budget {field} mismatch")
    for field in _BUDGET_COUNTER_FIELDS:
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"{label} has invalid call-budget {field}")
    return dict(value)


def _completion_budget_snapshots(
    out: Path, current: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    """Read budget high-water marks from manifest-bound completion markers."""
    found: list[tuple[str, dict[str, object]]] = []
    grid_id = str(current["budget_id"])
    suffix = ".complete.json"
    for marker_path in sorted(out.glob(f"*{suffix}")):
        # The filename does not carry a grid id. We therefore cannot safely
        # discard an uninspectable candidate before parsing its lineage.
        marker = _read_bounded_recovery_json(
            marker_path, label=f"completion marker {marker_path.name!r}"
        )
        snapshot = _same_grid_budget_snapshot(
            marker.get("call_budget_snapshot"), current,
            label=f"completion marker {marker_path.name!r}",
        )
        if snapshot is None:
            continue
        if marker.get("status") != "complete" or marker.get("format_version") != 2:
            raise ValueError(
                f"same-grid completion marker {marker_path.name!r} is not trustworthy"
            )
        artifacts = marker.get("artifacts")
        descriptor = artifacts.get("manifest") if isinstance(artifacts, dict) else None
        expected_name = marker_path.name.removesuffix(suffix) + ".manifest.json"
        if (
            not isinstance(descriptor, dict)
            or set(descriptor) != {"file", "sha256", "bytes", "records"}
            or descriptor.get("file") != expected_name
        ):
            raise ValueError(
                f"same-grid completion marker {marker_path.name!r} lacks a bound manifest"
            )
        manifest_path = out / expected_name
        if (
            manifest_path.is_symlink()
            or not manifest_path.is_file()
            or descriptor.get("bytes") != manifest_path.stat().st_size
            or descriptor.get("sha256") != _sha256_file(manifest_path)
            or descriptor.get("records") != 1
        ):
            raise ValueError(
                f"same-grid completion marker {marker_path.name!r} manifest mismatch"
            )
        manifest = RunManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
        run_config = manifest.config.get("run")
        if (
            not isinstance(run_config, dict)
            or run_config.get("grid_id") != grid_id
            or manifest.config.get("call_budget_snapshot") != snapshot
        ):
            raise ValueError(
                f"same-grid completion marker {marker_path.name!r} budget lineage mismatch"
            )
        found.append((f"completion marker {marker_path.name}", snapshot))
    return found


def _response_checkpoint_budget_snapshots(
    out: Path, current: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    """Read budget high-water marks from strict response recovery records."""
    found: list[tuple[str, dict[str, object]]] = []
    for path in sorted(out.glob("*.responses.checkpoint.jsonl")):
        # The filename does not identify a grid, so every candidate must be
        # safely parsed before its lineage can be known. The runner scanner is
        # bounded and streaming; malformed, oversized, and symlinked candidates
        # fail closed instead of disappearing from the high-water calculation.
        snapshots = Runner.response_checkpoint_budget_snapshots(path)
        matching = [
            _same_grid_budget_snapshot(
                value, current, label=f"response checkpoint {path.name!r}"
            )
            for value in snapshots
        ]
        matching = [value for value in matching if value is not None]
        if not matching:
            continue
        if len(matching) != len(snapshots):
            raise ValueError(
                f"response checkpoint {path.name!r} mixes call-budget lineages"
            )
        found.extend(
            (f"response checkpoint {path.name}", value) for value in matching
        )
    return found


def _checkpoint_budget_snapshots(
    out: Path, current: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    """Read post-attempt high-water marks from strict completed bundles."""
    found: list[tuple[str, dict[str, object]]] = []
    paths = (
        path for path in sorted(out.glob("*.checkpoint.jsonl"))
        if not path.name.endswith(".responses.checkpoint.jsonl")
    )
    for path in paths:
        snapshots = Runner.checkpoint_budget_snapshots(path)
        matching = [
            _same_grid_budget_snapshot(
                value, current, label=f"checkpoint {path.name!r}"
            )
            for value in snapshots
        ]
        matching = [value for value in matching if value is not None]
        if not matching:
            continue
        if len(matching) != len(snapshots):
            raise ValueError(
                f"checkpoint {path.name!r} mixes call-budget lineages"
            )
        found.extend((f"checkpoint {path.name}", value) for value in matching)
    return found


def _error_budget_snapshots(
    out: Path, current: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    """Read strictly validated same-grid failure snapshots."""
    found: list[tuple[str, dict[str, object]]] = []
    for path in sorted(out.glob("*.error.json")):
        payload = _read_bounded_recovery_json(
            path, label=f"error artifact {path.name!r}"
        )
        snapshot = _same_grid_budget_snapshot(
            payload.get("call_budget_snapshot"), current,
            label=f"error artifact {path.name!r}",
        )
        if snapshot is None:
            continue
        if payload.get("status") != "error":
            raise ValueError(
                f"same-grid error artifact {path.name!r} is not trustworthy"
            )
        audit = payload.get("call_audit")
        nested_circuit = payload.get("circuit")
        if audit is None and nested_circuit is None:
            raise ValueError(
                f"same-grid error artifact {path.name!r} lacks failure provenance"
            )
        if audit is not None:
            _validate_recovery_call_audit(
                audit, label=f"error artifact {path.name!r}"
            )
        if nested_circuit is not None:
            circuit = _validate_circuit_entry(
                nested_circuit, label=f"error artifact {path.name!r}"
            )
            circuit_snapshot = _same_grid_budget_snapshot(
                circuit["budget_snapshot"], current,
                label=f"error artifact {path.name!r} nested circuit",
            )
            if circuit_snapshot is None:
                raise ValueError(
                    f"same-grid error artifact {path.name!r} mixes budget lineages"
                )
            found.append((f"error artifact {path.name} nested circuit", circuit_snapshot))
        found.append((f"error artifact {path.name}", snapshot))
    return found


def _circuit_budget_snapshots(
    circuits: dict[str, dict[str, object]], current: dict[str, object],
) -> list[tuple[str, dict[str, object]]]:
    found: list[tuple[str, dict[str, object]]] = []
    for key, circuit in circuits.items():
        snapshot = _same_grid_budget_snapshot(
            circuit.get("budget_snapshot"), current,
            label=f"circuit state {key!r}",
        )
        if snapshot is None:
            raise ValueError(f"circuit state {key!r} mixes budget lineages")
        found.append((f"circuit state {key}", snapshot))
    return found


def _validate_budget_recovery_high_water(
    out: Path, current: dict[str, object], *,
    circuits: dict[str, dict[str, object]] | None = None,
) -> None:
    """Reject a rolled-back ledger before another external call can start."""
    snapshots = [
        *_completion_budget_snapshots(out, current),
        *_checkpoint_budget_snapshots(out, current),
        *_response_checkpoint_budget_snapshots(out, current),
        *_error_budget_snapshots(out, current),
        *_circuit_budget_snapshots(circuits or {}, current),
    ]
    for label, snapshot in snapshots:
        ahead = {
            field: (int(current[field]), int(snapshot[field]))
            for field in _BUDGET_COUNTER_FIELDS
            if int(snapshot[field]) > int(current[field])
        }
        if ahead:
            detail = ", ".join(
                f"{field} ledger={ledger} artifact={artifact}"
                for field, (ledger, artifact) in ahead.items()
            )
            raise ValueError(
                "durable call-budget ledger is behind trustworthy same-grid "
                f"recovery evidence ({label}: {detail}); manual audit required"
            )


def _validate_completion_marker(
    paths: dict[str, Path], planned: RunManifest, required: tuple[str, ...]
) -> dict:
    """Validate a completed cell before allowing a call-free skip."""
    marker = _json_loads_strict(paths["complete"].read_text(encoding="utf-8"))
    if not isinstance(marker, dict) or marker.get("status") != "complete":
        raise ValueError("completion marker does not declare status=complete")
    if marker.get("format_version") != 2:
        raise ValueError(
            "completion marker lacks v2 integrity metadata; manual audit required"
        )
    if marker.get("run_id") != planned.run_id:
        raise ValueError("completion marker run_id differs from planned cell")
    if marker.get("code_version") != planned.code_version:
        raise ValueError("completion marker code_version differs from planned cell")
    if marker.get("schema_version") != planned.schema_version:
        raise ValueError("completion marker schema_version differs from planned cell")
    artifacts = marker.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(required):
        raise ValueError("completion marker has an incomplete artifact inventory")
    for name in required:
        descriptor = artifacts.get(name)
        if not isinstance(descriptor, dict):
            raise ValueError(f"completion artifact {name!r} lacks an integrity descriptor")
        path = paths[name]
        if descriptor.get("file") != path.name or not path.is_file():
            raise ValueError(f"completion artifact {name!r} is missing or renamed")
        if descriptor.get("bytes") != path.stat().st_size:
            raise ValueError(f"completion artifact {name!r} byte count mismatch")
        if descriptor.get("sha256") != _sha256_file(path):
            raise ValueError(f"completion artifact {name!r} digest mismatch")
        if descriptor.get("records") != _record_count(path):
            raise ValueError(f"completion artifact {name!r} record count mismatch")

    manifest = RunManifest.model_validate_json(
        paths["manifest"].read_text(encoding="utf-8")
    )
    if manifest.run_id != planned.run_id:
        raise ValueError("stored manifest run_id differs from planned cell")
    if manifest.code_version != CODE_VERSION or manifest.schema_version != SCHEMA_VERSION:
        raise ValueError("stored manifest code/schema version is stale")
    if marker.get("call_budget_snapshot") != manifest.config.get(
        "call_budget_snapshot"
    ):
        raise ValueError("completion marker call-budget snapshot mismatch")

    attempt_rows = _read_jsonl(paths["attempts"])
    response_rows = _read_jsonl(paths["responses"])
    judgment_rows = _read_jsonl(paths["judgments"])
    trails = _read_jsonl(paths["trails"])
    result_rows = _read_jsonl(paths["results"])
    attempts = [Attempt.model_validate(row) for row in attempt_rows]
    responses = [Response.model_validate(row) for row in response_rows]
    judgments = [Judgment.model_validate(row) for row in judgment_rows]
    results = [EvalResult.model_validate(row) for row in result_rows]
    expected_counts = {
        "n_attempts": len(attempts),
        "n_responses": len(responses),
        "n_judgments": len(judgments),
        "n_results": len(results),
    }
    for field, count in expected_counts.items():
        if marker.get(field) != count:
            raise ValueError(f"completion marker {field} mismatch")
        if field != "n_results" and manifest.config.get(field) != count:
            raise ValueError(f"stored manifest {field} mismatch")
    if not attempts or not responses or not judgments or not results:
        raise ValueError("completed scored cell has an empty core/result artifact")
    attempt_ids = [row.id for row in attempts]
    response_ids = [row.attempt_id for row in responses]
    judgment_ids = [row.attempt_id for row in judgments]
    if len(set(attempt_ids)) != len(attempt_ids):
        raise ValueError("duplicate attempt id in completed artifact")
    if (
        Counter(attempt_ids) != Counter(response_ids)
        or Counter(attempt_ids) != Counter(judgment_ids)
    ):
        raise ValueError("Attempt/Response/Judgment identities do not join exactly")
    if {str(row.get("attempt_id")) for row in trails} != set(attempt_ids):
        raise ValueError("judge trails do not cover every completed attempt")
    for name, rows in (
        ("attempts", attempts), ("responses", responses),
        ("judgments", judgments), ("results", results),
    ):
        if any(row.run_id != planned.run_id for row in rows):
            raise ValueError(f"mixed or missing run_id in completed {name}")
    if any(row.get("run_id") != planned.run_id for row in trails):
        raise ValueError("mixed or missing run_id in completed trails")

    immutable_manifest_fields = (
        "code_version", "schema_version", "seeds", "models", "adapters",
        "judges", "dataset_hashes", "env",
    )
    for field in immutable_manifest_fields:
        if getattr(manifest, field) != getattr(planned, field):
            raise ValueError(f"stored manifest immutable field {field!r} changed")
    for key in (
        "budget", "components", "run", "media_validation", "n_datapoints",
        "n_media_hashes", "harness_source", "source_policy_inventory",
        "source_policy_inventory_sha256", "source_metric_plan",
    ):
        if manifest.config.get(key) != planned.config.get(key):
            raise ValueError(f"stored manifest config field {key!r} changed")
    if manifest.config.get("realized_attempts_sha256") != _sha256_json(
        [_portable_attempt_dump(row) for row in attempts]
    ):
        raise ValueError("stored manifest realized_attempts_sha256 mismatch")
    realized_media: dict[str, str] = {}
    for attempt in attempts:
        if attempt.target not in planned.models:
            raise ValueError("completed Attempt names an unexpected target")
        media = attempt.params.get("attempt_media_hashes")
        if not isinstance(media, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in media.items()
        ):
            raise ValueError("completed Attempt has invalid realized media hashes")
        for key, value in media.items():
            if key in realized_media and realized_media[key] != value:
                raise ValueError("completed Attempts have conflicting media hashes")
            realized_media[key] = value
    if manifest.config.get("attempt_media_hashes") != dict(sorted(realized_media.items())):
        raise ValueError("stored manifest realized media digest inventory mismatch")
    if manifest.config.get("n_attempt_media_hashes") != len(realized_media):
        raise ValueError("stored manifest realized media digest count mismatch")
    for response in responses:
        if response.target not in planned.models:
            raise ValueError("completed Response names an unexpected target")
        if response.raw.get("run_id") != planned.run_id:
            raise ValueError("completed Response raw lineage lacks the run_id")
        if not isinstance(response.raw.get("target_sampling_control"), str):
            raise ValueError("completed Response lacks sampling-control provenance")
    for judgment in judgments:
        if judgment.raw.get("run_id") != planned.run_id:
            raise ValueError("completed Judgment raw lineage lacks the run_id")
        if judgment.raw.get("target") not in planned.models:
            raise ValueError("completed Judgment names an unexpected target")
    policy_inventory = sorted(
        {
            json.dumps(
                attempt.params["source_policy"],
                sort_keys=True,
                separators=(",", ":"),
            )
            for attempt in attempts
            if attempt.params.get("source_policy") is not None
        }
    )
    reconstructed_policies = [json.loads(item) for item in policy_inventory]
    if manifest.config.get("source_policy_inventory") != reconstructed_policies:
        raise ValueError("stored manifest source-policy inventory mismatch")
    if manifest.config.get("source_policy_inventory_sha256") != _sha256_json(
        reconstructed_policies
    ):
        raise ValueError("stored manifest source-policy digest mismatch")
    attempt_policy = {row.id: row.params.get("source_policy") for row in attempts}
    if any(
        judgment.raw.get("source_policy") != attempt_policy[judgment.attempt_id]
        for judgment in judgments
    ):
        raise ValueError("Judgment source-policy lineage mismatch")
    source_metric_inventory = manifest.config.get("source_metric_inventory")
    if not isinstance(source_metric_inventory, list):
        raise ValueError("stored manifest lacks source-metric execution inventory")
    realized_source_metrics: dict[tuple[str, str], int] = {}
    for judgment in judgments:
        observation = judgment.raw.get("source_evaluation")
        if not isinstance(observation, dict) or observation.get("implemented") is not True:
            continue
        key = (
            str(judgment.raw.get("source", "")),
            str(observation.get("family", "")),
        )
        realized_source_metrics[key] = realized_source_metrics.get(key, 0) + 1
    for entry in source_metric_inventory:
        if not isinstance(entry, dict):
            raise ValueError("source-metric inventory entries must be objects")
        key = (str(entry.get("source")), str(entry.get("required_metric")))
        emitted = key in realized_source_metrics
        if entry.get("source_metric_emitted") is not emitted:
            raise ValueError("stored source-metric emitted status mismatch")
        if entry.get("n_source_evaluations") != realized_source_metrics.get(key, 0):
            raise ValueError("stored source-metric evaluation count mismatch")
        if (
            key == ("mmsafety", "mmsafety_official_attack_rate")
            and emitted
            and entry.get("official_evaluator_executed") is not True
        ):
            raise ValueError(
                "MM-SafetyBench official attack rate lacks official-evaluator evidence"
            )

    # A response-conditioned trajectory ends at its first authoritative harmful
    # completion; post-break turns would be extra paid calls and alter severity.
    live: dict[tuple[str, object], list[Judgment]] = defaultdict(list)
    for judgment in judgments:
        if (
            judgment.raw.get("response_conditioned") is True
            and judgment.raw.get("expected_behavior") == "refuse"
        ):
            live[(
                str(judgment.raw.get("datapoint_id")),
                judgment.raw.get("seed"),
            )].append(judgment)
    for key, conversation in live.items():
        ordered = sorted(conversation, key=lambda row: row.raw.get("turn_index", -1))
        first_break = next(
            (index for index, row in enumerate(ordered) if row.label == "violation"),
            None,
        )
        if first_break is not None and first_break != len(ordered) - 1:
            raise ValueError(f"live trajectory {key!r} continues after harmful completion")

    trails_by_attempt: dict[str, list[dict]] = defaultdict(list)
    for row in trails:
        trails_by_attempt[str(row["attempt_id"])].append(row)
    if set(trails_by_attempt) != set(attempt_ids):
        raise ValueError("judge trails do not cover exactly the completed attempts")
    for attempt_id, rows in trails_by_attempt.items():
        ordered = sorted(rows, key=lambda row: row.get("stage", -1))
        if len(ordered) != len(planned.judges):
            raise ValueError(f"judge trail stage count mismatch for {attempt_id}")
        if [row.get("stage") for row in ordered] != list(range(len(ordered))):
            raise ValueError(f"judge trail stage ordering mismatch for {attempt_id}")
        if [row.get("judge") for row in ordered] != planned.judges:
            raise ValueError(f"judge trail identities mismatch for {attempt_id}")
        if sum(row.get("cascade_role") == "authoritative" for row in ordered) != 1:
            raise ValueError(f"judge trail authority count mismatch for {attempt_id}")
        for row in ordered:
            if row.get("cascade_policy") != "first_confident_with_full_shadow_trail":
                raise ValueError(f"judge trail policy mismatch for {attempt_id}")
            if not isinstance(row.get("cascade_confident"), bool):
                raise ValueError(f"judge trail confidence state mismatch for {attempt_id}")
            confidence = row.get("confidence")
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0.0 <= float(confidence) <= 1.0
            ):
                raise ValueError(f"judge trail numeric confidence mismatch for {attempt_id}")
    identity_summary = realized_identity_summary(
        responses,
        trails,
        expected_judges=planned.judges,
    )
    identity_digest = _sha256_json(identity_summary)
    if manifest.config.get("realized_identities") != identity_summary:
        raise ValueError("stored manifest realized identity inventory mismatch")
    if manifest.config.get("realized_identities_sha256") != identity_digest:
        raise ValueError("stored manifest realized identity digest mismatch")
    if marker.get("realized_identities_sha256") != identity_digest:
        raise ValueError("completion marker realized identity digest mismatch")
    expected_identity_counts = {
        "n_realized_target_identity_observations": len(responses),
        "n_realized_judge_identity_observations": len(trails),
        "n_realized_judge_identity_snapshots": len(planned.judges),
    }
    for field, expected_count in expected_identity_counts.items():
        if manifest.config.get(field) != expected_count:
            raise ValueError(f"stored manifest {field} mismatch")
    for result in results:
        if result.n <= 0:
            raise ValueError("completed aggregate has a non-positive population")
        horizon = result.provenance.get("horizon_turns")
        if result.metric in {
            "median_turns_to_break", "restricted_mean_turns_to_break"
        }:
            if (
                isinstance(horizon, bool) or not isinstance(horizon, int)
                or horizon <= 0 or not 0.0 <= result.value <= float(horizon)
            ):
                raise ValueError("turn metric is outside its explicit horizon domain")
        elif not 0.0 <= result.value <= 1.0:
            raise ValueError("completed aggregate value is outside its metric domain")
        if (result.ci_low is None) != (result.ci_high is None):
            raise ValueError("completed aggregate has a half-defined confidence interval")
        if result.ci_low is not None and result.ci_low > result.ci_high:
            raise ValueError("completed aggregate confidence interval is inverted")
    return marker


def _source_tree_digest(path: Path) -> tuple[str | None, int]:
    """Hash a bounded regular source tree for portable source identity.

    Scored corpus identity remains the canonical converted-corpus digest in the
    partition plan. This separate digest binds the experiment driver used by a
    completion or companion proof while omitting mutable tool/cache directories.
    """
    if not path.exists():
        return None, 0
    if path.is_symlink():
        raise ValueError(f"refusing to hash symlink source path: {path}")
    if path.is_file():
        return _sha256_file(path), 1
    digest = hashlib.sha256()
    count = 0
    total_bytes = 0
    excluded = {
        ".git", ".pytest_cache", ".ruff_cache", "__pycache__", ".mypy_cache",
    }
    candidates = sorted(path.rglob("*"))
    for file_path in candidates:
        relative_parts = file_path.relative_to(path).parts
        if any(part in excluded or part.startswith((".tmp-", ".smoke-"))
               for part in relative_parts):
            continue
        if file_path.is_symlink():
            raise ValueError(f"refusing to hash symlink source member: {file_path}")
        if not file_path.is_file():
            continue
        size = file_path.stat().st_size
        count += 1
        total_bytes += size
        if count > 100_000 or size > 2 * 1024**3 or total_bytes > 16 * 1024**3:
            raise ValueError("source tree exceeds diagnostic hashing bounds")
        relative = file_path.relative_to(path).as_posix()
        file_digest = _sha256_file(file_path)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest(), count


def build_target(
    spec: str,
    *,
    quantization: str = "",
    dtype: str = "auto",
    local_identity: dict[str, object] | None = None,
):
    """Resolve a target spec to a :class:`BaseTarget`.

    spec is one of:
      * a registered hosted id (including "mock") or the preferred
        "<provider>:<exact-account-visible-id>" form;
      * a local "<backend>:<model>" - "vllm:Qwen/Qwen3-VL-8B-Instruct",
        "ollama:llama3.3:70b".

    ``quantization``/``dtype`` are forwarded to the vLLM engine so a 27B-class
    model fits the 2x RTX 4090 rig (e.g. ``--quantization awq``); a pre-quantized
    (AWQ/GPTQ) checkpoint is auto-detected and needs no flag. Vision-language
    Local capabilities and immutable identities come only from ``local_identity``;
    model-name substrings are never treated as capability evidence.
    """
    if ":" in spec:
        backend, model = spec.split(":", 1)
        backend = backend.lower().strip()
        model = model.strip()
        if not backend or not model:
            raise ValueError(
                "provider/backend-qualified targets require non-empty "
                "'<provider>:<exact-id>' components"
            )
        if backend in {"vllm", "ollama"}:
            if local_identity is None:
                raise ValueError(
                    f"local target {spec!r} requires an explicit local identity config"
                )
            modalities = tuple(local_identity["modalities"])
            if backend == "vllm":
                from ura.targets.local import VLLMTarget
                kwargs: dict = {
                    "dtype": dtype,
                    "modality_support": modalities,
                    "revision": local_identity.get("revision"),
                    "model_digest": local_identity.get("digest"),
                }
                if quantization:
                    kwargs["quantization"] = quantization
                target = VLLMTarget(model=model, **kwargs)
                target.validate_research_identity()
                return target
            from ura.targets.local import OllamaTarget
            target = OllamaTarget(
                model=model,
                model_digest=str(local_identity["digest"]),
                modality_support=modalities,
            )
            target.validate_research_identity()
            return target
        # provider:model (anthropic/openai/google/gemini)
        return build_api_target(spec)
    # bare id: resolve against the verified hosted/mock registry
    return build_api_target(spec)


def _persisted_model_spec(
    spec: str, local_identity: dict[str, object] | None,
) -> str:
    """Return a research identity that never embeds a local checkpoint path."""
    if local_identity is None or ":" not in spec:
        return spec
    backend, model = spec.split(":", 1)
    if backend.lower() != "vllm":
        return spec
    from ura.targets.local import _is_explicit_local_path
    if not _is_explicit_local_path(model):
        return spec
    digest = local_identity.get("digest")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
        raise ValueError("local vLLM path requires a content digest identity")
    return f"vllm:local-checkpoint@sha256:{digest.lower()}"


def _artifact_safe_model_error(
    exc: Exception, spec: str, persisted_spec: str,
) -> str:
    """Remove an explicit local checkpoint locator from persisted diagnostics."""
    message = str(exc)[:2000]
    if spec == persisted_spec or ":" not in spec:
        return message
    backend, runtime_model = spec.split(":", 1)
    if backend.lower() != "vllm":
        return message
    logical_model = persisted_spec.split(":", 1)[-1]
    message = message.replace(spec, persisted_spec)
    candidates = {runtime_model}
    try:
        candidates.add(str(Path(runtime_model).expanduser().resolve(strict=False)))
    except (OSError, RuntimeError):
        pass
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate:
            message = message.replace(candidate, logical_model)
    return message


def build_judges(
    names: list[str],
    judge_model: str,
    *,
    guardrail_model: str = "meta-llama/Llama-Guard-3-8B",
    guardrail_revision: str = "",
    guardrail_device: str = "",
) -> JudgeCascade:
    if "llm" in names and judge_model == "mock":
        # The llm judge backed by the offline MockTarget is a keyword heuristic, not
        # a model. Fine for a keyless smoke run, but it silently invalidates any
        # scored run (ASR, and especially the inter-judge kappa of V.2.5). Warn loud.
        print(
            "  ! WARNING: --judges includes 'llm' but --judge-model is 'mock'. "
            "The llm stage will use the offline keyword mock, NOT a real model; "
            "kappa and llm-judged ASR will be meaningless. Pass e.g. "
            "--judge-model claude-haiku-4-5-20251001 for a scored run.",
            file=sys.stderr,
        )
    stages = []
    for n in names:
        if n == "rules":
            stages.append(RuleJudge())
        elif n == "llm":
            # build_api_target resolves both bare registered ids and provider:model
            # forms, so the judge can be any provider (e.g. kimi:kimi-k3), not only a
            # registry default; falls back to REGISTRY.create for bare ids like "mock".
            stages.append(LLMJudge(judge_target=build_api_target(judge_model)))
        elif n == "guardrail":
            from ura.judges.guardrail import GuardrailJudge
            stages.append(GuardrailJudge(
                model=guardrail_model,
                revision=guardrail_revision,
                device=guardrail_device or None,
            ))
        else:
            raise ValueError(f"unknown judge {n!r}")
    return JudgeCascade(stages or [RuleJudge()])


def _cluster_key(index: int, record: object) -> str:
    """Group key for whole-cluster sampling: a source cluster id (e.g. a
    GPTGeoChat conversation's five threshold rows, or an R-Judge trajectory)
    if present, else the DataPoint id, else the row index (independent rows)."""
    meta = getattr(record, "meta", None)
    if isinstance(meta, dict):
        cluster = meta.get("source_cluster_id")
        if isinstance(cluster, str) and cluster.strip():
            return cluster
    identifier = getattr(record, "id", None)
    if isinstance(identifier, str) and identifier.strip():
        return identifier
    return f"__row_{index}__"


def _source_policy_key(record: object) -> str:
    policy = getattr(record, "source_policy", None)
    if policy is None:
        return "__untyped_source_policy__"
    return f"{policy.policy_id}@{policy.version}#sha256:{policy.sha256}"


def _source_policy_cluster_counts(records: list[DataPoint]) -> dict[str, int]:
    """Count homogeneous source-policy strata at prompt/intent-cluster scale."""
    cluster_policies: dict[str, str] = {}
    for index, record in enumerate(records):
        cluster_id = _cluster_key(index, record)
        policy_key = _source_policy_key(record)
        previous = cluster_policies.setdefault(cluster_id, policy_key)
        if previous != policy_key:
            raise ValueError(
                f"source cluster {cluster_id!r} mixes source-evaluation policies"
            )
    return dict(sorted(Counter(cluster_policies.values()).items()))


def _declared_transport_attempts(component: object) -> int:
    value = getattr(component, "max_transport_attempts_per_call", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            "max_transport_attempts_per_call must be a non-negative integer"
        )
    return value


def _project_grid_call_upper_bounds(
    *,
    targets: dict[str, object],
    corpora: dict[str, list[DataPoint]],
    attackers: dict[str, object],
    cascade: JudgeCascade,
    seeds: list[int],
    max_queries: int,
    max_turns: int,
) -> dict[str, object]:
    """Conservative complete-grid exposure using already-built components.

    These are ledger-aligned upper bounds, not price or token estimates. Stateful
    trajectories may stop early after a policy violation, and provider refusals
    can avoid judge calls, but a complete grid must be budgeted for the longest
    permitted path.
    """
    logical_limit = min(max_queries, max_turns)
    model_judges = [
        getattr(stage, "judge_target")
        for stage in cascade.stages
        if getattr(stage, "judge_target", None) is not None
    ]
    judge_calls_per_evaluable = len(model_judges)
    judge_http_per_evaluable = sum(
        _declared_transport_attempts(target) for target in model_judges
    )
    by_attacker: dict[str, dict[str, int]] = {}
    total_target = total_judge = total_http = total_trajectories = 0
    for name, attacker in attackers.items():
        canonical_name = str(getattr(attacker, "name", name)).lower()
        if canonical_name == "replay":
            target_turns = evaluable_turns = 1
        elif canonical_name == "crescendo":
            ladder = getattr(attacker, "_ladder")(logical_limit)
            target_turns = len(ladder)
            evaluable_turns = sum(int(rung >= 2) for rung in ladder)
        else:
            # External/static adapters can emit fewer attempts, but Runner caps
            # every trajectory at this value. Do not execute an engine merely to
            # make a planning estimate.
            target_turns = evaluable_turns = logical_limit
        attacker_target = attacker_judge = attacker_http = attacker_trajectories = 0
        for target in targets.values():
            trajectories = sum(len(rows) for rows in corpora.values()) * len(seeds)
            target_calls = trajectories * target_turns
            judge_calls = trajectories * evaluable_turns * judge_calls_per_evaluable
            http_attempts = (
                target_calls * _declared_transport_attempts(target)
                + trajectories * evaluable_turns * judge_http_per_evaluable
            )
            attacker_trajectories += trajectories
            attacker_target += target_calls
            attacker_judge += judge_calls
            attacker_http += http_attempts
        by_attacker[name] = {
            "trajectories": attacker_trajectories,
            "target_calls": attacker_target,
            "judge_calls": attacker_judge,
            "http_attempts": attacker_http,
        }
        total_trajectories += attacker_trajectories
        total_target += attacker_target
        total_judge += attacker_judge
        total_http += attacker_http
    return {
        "semantics": "conservative_complete_grid_upper_bound_v1",
        "trajectories": total_trajectories,
        "target_calls": total_target,
        "judge_calls": total_judge,
        "http_attempts": total_http,
        "by_attacker": by_attacker,
    }


def _validate_planned_call_budget(
    projection: dict[str, object], *, target: int, judge: int, http: int,
    deadline_seconds: int, dry_run: bool, require_complete: bool,
) -> None:
    """Require finite real-run limits; rig-check also requires full coverage."""
    if dry_run:
        return
    requirements = {
        "--max-total-target-calls": int(projection["target_calls"]),
        "--max-total-judge-calls": int(projection["judge_calls"]),
        "--max-total-http-attempts": int(projection["http_attempts"]),
    }
    supplied = {
        "--max-total-target-calls": target,
        "--max-total-judge-calls": judge,
        "--max-total-http-attempts": http,
    }
    shortfalls = []
    for flag, required in requirements.items():
        if required <= 0:
            continue
        minimum = required if require_complete else 1
        if supplied[flag] < minimum:
            shortfalls.append(
                f"{flag}={supplied[flag]} (need >= {minimum}"
                + (" for the complete planned grid)" if require_complete else ")")
            )
    if deadline_seconds <= 0:
        shortfalls.append("--deadline-seconds must be positive")
    if shortfalls:
        raise ValueError(
            "real grid has invalid planned call limits: "
            + "; ".join(shortfalls)
        )


def _select_corpus(
    name: str,
    dps: list[DataPoint],
    limit: int,
    sample_seed: int,
    *,
    exact_cluster_ids: list[str] | None = None,
) -> tuple[list[DataPoint], list[int], list[str], list[str]]:
    """Select exactly ``limit`` prompt/intent clusters, retaining every row."""
    clusters: dict[str, list[int]] = {}
    for index, record in enumerate(dps):
        clusters.setdefault(_cluster_key(index, record), []).append(index)
    keys = list(clusters)
    if exact_cluster_ids is not None:
        if limit != 0:
            raise ValueError("exact partition selection requires limit=0")
        if (
            not exact_cluster_ids
            or len(set(exact_cluster_ids)) != len(exact_cluster_ids)
            or any(key not in clusters for key in exact_cluster_ids)
        ):
            raise ValueError("partition names missing or duplicate source clusters")
        selected_set = set(exact_cluster_ids)
        selected_cluster_ids = [key for key in keys if key in selected_set]
        if set(selected_cluster_ids) != selected_set:
            raise ValueError("partition cluster selection is not exact")
        indices = [
            index for key in selected_cluster_ids for index in clusters[key]
        ]
        return [dps[index] for index in indices], indices, selected_cluster_ids, keys
    if not limit or limit >= len(keys):
        return dps, list(range(len(dps))), keys, keys
    seed_material = f"ura-corpus-cluster-sample-v3\0{name}\0{sample_seed}".encode(
        "utf-8"
    )
    scoped_seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big")
    positions = set(random.Random(scoped_seed).sample(range(len(keys)), k=limit))
    selected_cluster_ids = [key for index, key in enumerate(keys) if index in positions]
    indices = sorted(
        index for key in selected_cluster_ids for index in clusters[key]
    )
    return [dps[index] for index in indices], indices, selected_cluster_ids, keys


def _process_identity(pid: int) -> str | None:
    """Best-effort process creation identity for manual lock diagnosis."""
    if os.name == "nt":
        import ctypes

        query = 0x1000
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(query, False, pid)
        if not handle:
            return None
        try:
            creation = ctypes.c_ulonglong()
            exit_time = ctypes.c_ulonglong()
            kernel = ctypes.c_ulonglong()
            user = ctypes.c_ulonglong()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                return None
            return f"win-filetime:{creation.value}"
        finally:
            kernel32.CloseHandle(handle)
    stat = Path(f"/proc/{pid}/stat")
    try:
        fields = stat.read_text(encoding="utf-8").split()
    except OSError:
        return None
    # Linux /proc stat field 22 is the process start time in clock ticks.
    return f"proc-start:{fields[21]}" if len(fields) > 21 else None


def _corpus_path(name: str) -> Path:
    return Path(os.environ.get(
        f"URA_{name.upper()}_PATH", f"datasets/samples/{name}.jsonl"
    ))


def _stable_source_locator(
    name: str, source_kind: str | None,
) -> dict[str, object]:
    """Configuration-level locator with no checkout- or author-specific path."""
    if name == "synth":
        return {
            "corpus": "synth",
            "configuration_env": None,
            "source_kind": "generated_fixture",
            "required_layout": [],
        }
    release = CORPUS_RELEASE_SPECS.get(name)
    return {
        "corpus": name,
        "configuration_env": f"URA_{name.upper()}_PATH",
        "source_kind": source_kind,
        "required_layout": list(release.required_layout) if release else [],
    }


def load_corpus(name: str, limit: int, sample_seed: int = 0) -> list[DataPoint]:
    """Load a corpus and take a deterministic seeded subset when limited.

    The seed is scoped by corpus name so independent corpora do not reuse the same
    pseudo-random index pattern. Selected records retain source order, which makes
    artifacts easy to compare while avoiding the bias of first-N slicing.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if name == "synth":
        return synth_corpus(12 if limit == 0 else limit)
    conv = get_converter(name)
    # expects data under datasets/<name>.jsonl by default; override via env
    path = _corpus_path(name)
    dps = conv.parse(path)
    selected, _, _, _ = _select_corpus(name, dps, limit, sample_seed)
    return selected


def load_corpus_with_audit(
    name: str,
    limit: int,
    sample_seed: int = 0,
    *,
    exact_cluster_ids: list[str] | None = None,
) -> tuple[list[DataPoint], dict[str, object]]:
    """Load one source and retain enough information to audit the frozen sample."""
    if limit < 0:
        raise ValueError("limit must be non-negative")
    if name == "synth":
        selected = synth_corpus(12 if limit == 0 else limit)
        cluster_ids = [_cluster_key(index, row) for index, row in enumerate(selected)]
        full_digest = canonical_converted_corpus_sha256(selected)
        return selected, {
            "corpus": name,
            "source_locator": _stable_source_locator(name, "generated_fixture"),
            "full_converted_corpus_sha256": full_digest,
            "total_records": len(selected),
            "selected_records": len(selected),
            "selected_indices": list(range(len(selected))),
            "selected_ids": [datapoint.id for datapoint in selected],
            "limit_unit": "source_prompt_or_intent_clusters",
            "total_clusters": len(cluster_ids),
            "selected_clusters": len(cluster_ids),
            "total_cluster_ids": cluster_ids,
            "selected_cluster_ids": cluster_ids,
            "sample_seed": sample_seed,
            "limit": limit,
        }
    path = _corpus_path(name)
    full = get_converter(name).parse(path)
    selected, indices, selected_clusters, total_clusters = _select_corpus(
        name,
        full,
        limit,
        sample_seed,
        exact_cluster_ids=exact_cluster_ids,
    )
    resolved = path.expanduser().resolve(strict=True)
    full_digest = canonical_converted_corpus_sha256(full)
    return selected, {
        "corpus": name,
        "source_locator": _stable_source_locator(
            name, "directory" if resolved.is_dir() else "file"
        ),
        "full_converted_corpus_sha256": full_digest,
        "total_records": len(full),
        "selected_records": len(selected),
        "selected_indices": indices,
        "selected_ids": [datapoint.id for datapoint in selected],
        "limit_unit": "source_prompt_or_intent_clusters",
        "total_clusters": len(total_clusters),
        "selected_clusters": len(selected_clusters),
        "total_cluster_ids": total_clusters,
        "selected_cluster_ids": selected_clusters,
        "sample_seed": sample_seed,
        "limit": limit,
        "selection_method": (
            "content_addressed_partition_plan"
            if exact_cluster_ids is not None
            else "seeded_source_cluster_sample"
        ),
    }


def _validate_partitioned_corpus(
    name: str,
    records: list[DataPoint],
    audit: dict[str, object],
    assignment: dict[str, object],
) -> None:
    """Bind converted records and the exact executed cluster role to its plan."""
    checks = {
        "source_locator": audit.get("source_locator"),
        "full_converted_corpus_sha256": audit.get(
            "full_converted_corpus_sha256"
        ),
        "total_records": audit.get("total_records"),
        "total_clusters": audit.get("total_clusters"),
        "n_clusters": audit.get("selected_clusters"),
    }
    for field, actual in checks.items():
        if assignment.get(field) != actual:
            raise ValueError(
                f"corpus {name!r} partition {field} mismatch: plan "
                f"{assignment.get(field)!r}, converted {actual!r}"
            )
    total_ids = audit.get("total_cluster_ids")
    selected_ids = audit.get("selected_cluster_ids")
    if (
        not isinstance(total_ids, list)
        or _sha256_json(sorted(total_ids))
        != assignment.get("total_cluster_ids_sha256")
    ):
        raise ValueError(f"corpus {name!r} full source-cluster identity mismatch")
    if (
        not isinstance(selected_ids, list)
        or sorted(selected_ids) != assignment.get("cluster_ids")
        or _sha256_json(sorted(selected_ids))
        != assignment.get("cluster_ids_sha256")
    ):
        raise ValueError(f"corpus {name!r} selected partition identity mismatch")
    actual_policy_counts = _source_policy_cluster_counts(records)
    if actual_policy_counts != assignment.get("source_policy_cluster_counts"):
        raise ValueError(
            f"corpus {name!r} selected source-policy strata mismatch: plan "
            f"{assignment.get('source_policy_cluster_counts')!r}, converted "
            f"{actual_policy_counts!r}"
        )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="URA-Bench experiment matrix.")
    ap.add_argument("--dry-run", action="store_true", help="use MockTarget only")
    ap.add_argument(
        "--preflight-only", action="store_true",
        help="validate and project the complete grid without model/judge calls",
    )
    ap.add_argument("--api", default="", help="comma list of API model ids")
    ap.add_argument("--local", default="", help="comma list of backend:model specs")
    ap.add_argument(
        "--local-config",
        default="",
        help=(
            "JSON keyed by each exact --local spec with immutable revision/digest "
            "and explicit modalities"
        ),
    )
    ap.add_argument("--attackers", default="replay,crescendo")
    ap.add_argument(
        "--attacker-config",
        default="",
        help=(
            "JSON object mapping selected attacker names to constructor kwargs; "
            "literal secrets are forbidden (use credential_env names)"
        ),
    )
    ap.add_argument("--judges", default="rules,llm")
    ap.add_argument("--judge-model", default="mock", help="target id used by LLMJudge")
    ap.add_argument(
        "--guardrail-model",
        default="meta-llama/Llama-Guard-3-8B",
        help="exact Hugging Face model id for guardrail judge/defense cells",
    )
    ap.add_argument(
        "--guardrail-revision",
        default="",
        help="required immutable 40-64 hex Hugging Face commit for guardrail cells",
    )
    ap.add_argument(
        "--guardrail-device",
        default="",
        help="optional torch device for guardrail inference (empty uses device_map=auto)",
    )
    ap.add_argument("--corpora", default="synth")
    ap.add_argument(
        "--limit", type=int, default=50,
        help=(
            "maximum unique source prompt/intent clusters per corpus; every row "
            "in each selected cluster is retained (0 = all clusters)"
        ),
    )
    ap.add_argument(
        "--sample-seed", type=int, default=0,
        help="seed for deterministic corpus subsampling (real corpora only)",
    )
    ap.add_argument(
        "--partition-plan", default="",
        help="content-addressed ura-cluster-partition/1.2 JSON for scored corpora",
    )
    ap.add_argument(
        "--partition-sha256", default="",
        help="exact SHA-256 of --partition-plan bytes",
    )
    ap.add_argument(
        "--partition-role", default="", choices=["", "pilot", "main"],
        help="execute exactly the pilot or main source-cluster assignment",
    )
    ap.add_argument(
        "--modality-coverage-companion", default="",
        help="content-addressed completed companion-grid modality proof",
    )
    ap.add_argument(
        "--modality-coverage-companion-sha256", default="",
        help="exact SHA-256 of --modality-coverage-companion bytes",
    )
    ap.add_argument("--seeds", default="0")
    ap.add_argument("--max-queries", type=int, default=4,
                    help="maximum target calls per datapoint and seed")
    ap.add_argument("--max-turns", type=int, default=4,
                    help="maximum dialog turns per datapoint and seed")
    ap.add_argument("--group", default="model,risk",
                    help="aggregation group keys, e.g. model,risk,modality (E5 m-ASR)")
    ap.add_argument("--defense", default="none",
                    choices=["none", "input", "output", "both"],
                    help="wrap targets in a GuardedTarget pre/post-filter (E4 ablation)")
    ap.add_argument("--defense-guard", default="rules", choices=["rules", "guardrail"],
                    help="judge used as the defense guardrail when --defense is set")
    ap.add_argument("--quantization", default="",
                    help="vLLM quantization for local models (e.g. awq, gptq, fp8); "
                         "empty auto-detects from a pre-quantized checkpoint")
    ap.add_argument("--dtype", default="auto",
                    help="vLLM dtype for local models (auto, bfloat16, float16)")
    ap.add_argument("--max-total-target-calls", type=int, default=0,
                    help="durable matrix-wide ceiling on model-under-test logical "
                         "calls (0 = unbounded)")
    ap.add_argument("--max-total-judge-calls", type=int, default=0,
                    help="durable matrix-wide ceiling on model-backed judge calls "
                         "(0 = unbounded)")
    ap.add_argument("--max-total-http-attempts", type=int, default=0,
                    help="durable ceiling on declared provider transport-attempt "
                         "exposure across target and judge calls (0 = unbounded)")
    ap.add_argument("--deadline-seconds", type=int, default=0,
                    help="durable call-start admission deadline from the matrix's "
                         "first invocation; an admitted in-flight call retains its "
                         "configured provider timeout (0 = none)")
    ap.add_argument("--lock-stale-seconds", type=int, default=86400,
                    help="diagnostic stale-age metadata only; locks are never "
                         "removed automatically (default: 86400)")
    ap.add_argument("--reset-open-circuits", action="store_true",
                    help="operator acknowledgement: clear the durable provider/"
                         "judge circuit after correcting its root cause")
    ap.add_argument(
        "--provider-data-policy-approval", default="",
        help="content-addressed JSON accepting hosted-provider retention/data-use terms",
    )
    ap.add_argument(
        "--provider-data-policy-sha256", default="",
        help="exact SHA-256 of --provider-data-policy-approval bytes",
    )
    ap.add_argument("--out", default="runs/exp")
    args = ap.parse_args(argv)

    if args.limit < 0:
        ap.error("--limit must be non-negative")
    if args.max_queries <= 0 or args.max_turns <= 0:
        ap.error("--max-queries and --max-turns must be positive")
    if any(value < 0 for value in (
        args.max_total_target_calls, args.max_total_judge_calls,
        args.max_total_http_attempts, args.deadline_seconds,
    )):
        ap.error("call ceilings and --deadline-seconds must be non-negative")
    if args.lock_stale_seconds <= 0:
        ap.error("--lock-stale-seconds must be positive")

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    if not seeds:
        ap.error("--seeds must contain at least one integer")
    if len(set(seeds)) != len(seeds):
        ap.error("--seeds must be unique")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    # Wall-clock provenance for V.2.6 (run date). Recorded in the manifest but kept
    # OUT of the run_id hash, so runs stay reproducible while the date is captured.
    run_started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_env = _runtime_env()
    api_specs = [s.strip() for s in args.api.split(",") if s.strip()]
    local_specs = [s.strip() for s in args.local.split(",") if s.strip()]
    if len(set(api_specs)) != len(api_specs):
        ap.error("--api specs must be unique")
    if len(set(local_specs)) != len(local_specs):
        ap.error("--local specs must be unique")
    model_specs = ["mock"] if args.dry_run else (api_specs + local_specs)
    if len(set(model_specs)) != len(model_specs):
        ap.error("target specs must be unique across --api and --local")
    if not model_specs:
        ap.error("a real run requires at least one --api or --local target; use --dry-run for mock")

    attacker_names = [a.strip() for a in args.attackers.split(",") if a.strip()]
    judge_names = [j.strip() for j in args.judges.split(",") if j.strip()]
    corpora = [c.strip() for c in args.corpora.split(",") if c.strip()]
    if not attacker_names:
        ap.error("--attackers must contain at least one adapter name")
    if not judge_names:
        ap.error("--judges must contain at least one judge name")
    if not corpora:
        ap.error("--corpora must contain at least one corpus name")
    for _label, _values in (
        ("--attackers", attacker_names), ("--judges", judge_names),
        ("--corpora", corpora),
    ):
        if len(set(_values)) != len(_values):
            ap.error(f"{_label} entries must be unique")
    try:
        attacker_configs, attacker_config_artifact = _load_attacker_config(
            args.attacker_config, attacker_names
        )
        local_configs, local_config_artifact = _load_local_config(
            args.local_config, [] if args.dry_run else local_specs
        )
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    persisted_model_specs = {
        spec: _persisted_model_spec(spec, local_configs.get(spec))
        for spec in model_specs
    }
    if not args.dry_run and "llm" in judge_names and args.judge_model == "mock":
        ap.error("a real run with the llm judge requires an explicit non-mock --judge-model")
    guardrail_selected = "guardrail" in judge_names or (
        args.defense != "none" and args.defense_guard == "guardrail"
    )
    if guardrail_selected:
        if not args.guardrail_model.strip():
            ap.error("guardrail cells require a non-blank --guardrail-model")
        if re.fullmatch(r"[0-9a-fA-F]{40,64}", args.guardrail_revision) is None:
            ap.error(
                "guardrail cells require --guardrail-revision as an immutable "
                "40-64 hex Hugging Face commit"
            )

    group_keys = [k.strip() for k in args.group.split(",") if k.strip()]
    if not group_keys:
        ap.error("--group must contain at least one grouping key")
    duplicate_group_keys = sorted(
        key for key, count in Counter(group_keys).items() if count > 1
    )
    if duplicate_group_keys:
        ap.error(
            "--group keys must be unique; duplicates: "
            + ", ".join(duplicate_group_keys)
        )
    unknown_group_keys = sorted(set(group_keys) - _ALLOWED_GROUP_KEYS)
    if unknown_group_keys:
        ap.error(
            "--group contains unsupported keys: " + ", ".join(unknown_group_keys)
        )

    try:
        provider_data_policy = _load_provider_data_policy_approval(
            args.provider_data_policy_approval,
            args.provider_data_policy_sha256,
            _provider_policy_requirements(
                api_specs, judge_names, args.judge_model, dry_run=args.dry_run
            ),
        )
    except (OSError, ValueError) as exc:
        ap.error(str(exc))

    partition_flags = (
        bool(args.partition_plan),
        bool(args.partition_sha256),
        bool(args.partition_role),
    )
    partition_required = not args.dry_run and any(
        name != "synth" for name in corpora
    )
    if any(partition_flags) and not all(partition_flags):
        ap.error(
            "--partition-plan, --partition-sha256, and --partition-role must be "
            "supplied together"
        )
    if partition_required and not all(partition_flags):
        ap.error(
            "real scored non-synthetic corpora require --partition-plan, "
            "--partition-sha256, and --partition-role"
        )
    if all(partition_flags) and args.limit != 0:
        ap.error("content-addressed partition execution requires --limit 0")
    if all(partition_flags):
        try:
            partition_binding, partition_assignments = _load_partition_plan(
                args.partition_plan,
                args.partition_sha256,
                args.partition_role,
                corpora,
            )
        except (OSError, ValueError) as exc:
            ap.error(str(exc))
    else:
        partition_binding = {
            "status": "not_applicable",
            "reason": (
                "offline_or_synthetic_fixture"
                if args.dry_run or set(corpora) == {"synth"}
                else "no_partitioned_corpora"
            ),
        }
        partition_assignments: dict[str, dict[str, object]] = {}

    companion_flags = (
        bool(args.modality_coverage_companion),
        bool(args.modality_coverage_companion_sha256),
    )
    if any(companion_flags) and not all(companion_flags):
        ap.error(
            "--modality-coverage-companion and its --sha256 must be supplied together"
        )

    # The experiment driver controls sampling, grid accounting, and completion
    # semantics that the runner's src/ura source hash does not cover. Content-
    # address it so a changed driver yields a different grid_id and cannot reuse
    # stale completion evidence, and record it in per-cell provenance.
    driver_digest, driver_file_count = _source_tree_digest(Path(__file__).resolve())
    driver_source = {
        "module": Path(__file__).name,
        "sha256": driver_digest,
        "file_count": driver_file_count,
    }
    harness_source = _harness_source_identity()

    # Preload the complete selected corpus set and construct lazy target objects
    # before any target/judge call. Modality coverage is a grid-wide property:
    # planning it one corpus at a time can silently omit an available image arm.
    loaded_corpora: dict[str, list[DataPoint]] = {}
    sampling_audits: dict[str, dict[str, object]] = {}
    for corpus_name in corpora:
        try:
            assignment = partition_assignments.get(corpus_name)
            corpus, sampling_audit = load_corpus_with_audit(
                corpus_name,
                args.limit,
                args.sample_seed,
                exact_cluster_ids=(
                    list(assignment["cluster_ids"])
                    if assignment is not None else None
                ),
            )
            if not corpus:
                raise ValueError("requested corpus converted to zero datapoints")
            if assignment is not None:
                _validate_partitioned_corpus(
                    corpus_name, corpus, sampling_audit, assignment
                )
                sampling_audit["partition_assignment"] = assignment
        except Exception as exc:  # noqa: BLE001 - fail pre-call preflight
            _write_json(out / f"{_safe_component(corpus_name)}.corpus.error.json", {
                "status": "error",
                "phase": "corpus_preflight",
                "corpus": corpus_name,
                "exception_type": type(exc).__name__,
                "message": str(exc),
            })
            print(
                f"corpus '{corpus_name}' preflight failed: "
                f"{type(exc).__name__}: {exc}", file=sys.stderr,
            )
            return 1
        loaded_corpora[corpus_name] = corpus
        sampling_audits[corpus_name] = sampling_audit
        (out / f"{_safe_component(corpus_name)}.corpus.error.json").unlink(
            missing_ok=True
        )

    prebuilt_targets: dict[str, object] = {}
    hosted_runtime_checks: list[dict[str, str]] = []
    for spec in model_specs:
        setup_phase = "target_construction"
        try:
            target = build_target(
                spec,
                quantization=args.quantization,
                dtype=args.dtype,
                local_identity=local_configs.get(spec),
            )
            if args.preflight_only:
                setup_phase = "hosted_runtime_preflight"
                readiness = preflight_api_target_runtime(target)
                if readiness is not None:
                    hosted_runtime_checks.append({
                        "role": "target", "model_spec": spec, **readiness,
                    })
            setup_phase = "target_construction"
            if args.defense != "none":
                from ura.targets.guarded import GuardedTarget
                if args.defense_guard == "guardrail":
                    from ura.judges.guardrail import GuardrailJudge
                    defense_guard = GuardrailJudge(
                        model=args.guardrail_model,
                        revision=args.guardrail_revision,
                        device=args.guardrail_device or None,
                    )
                else:
                    defense_guard = RuleJudge()
                target = GuardedTarget(target, defense_guard, mode=args.defense)
            prebuilt_targets[spec] = target
            persisted_model_specs[spec] = str(getattr(target, "name"))
        except Exception as exc:  # noqa: BLE001 - fail pre-call preflight
            for corpus_name in corpora:
                setup_error = out / (
                    "__".join((
                        _safe_component(corpus_name),
                        _safe_component(persisted_model_specs[spec]),
                        "target-setup",
                    )) + ".error.json"
                )
                _write_json(setup_error, {
                    "status": "error",
                    "phase": setup_phase,
                    "preflight": True,
                    "corpus": corpus_name,
                    "model_spec": persisted_model_specs[spec],
                    "exception_type": type(exc).__name__,
                    "message": _artifact_safe_model_error(
                        exc, spec, persisted_model_specs[spec]
                    ),
                })
            print(
                f"target '{spec}' preflight failed: {type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 1
    target_names = [str(getattr(target, "name", "")) for target in prebuilt_targets.values()]
    if len(set(target_names)) != len(target_names):
        ap.error("target specs resolve to duplicate runtime target identities")
    if args.preflight_only and "llm" in judge_names:
        try:
            judge_target = build_api_target(args.judge_model)
            readiness = preflight_api_target_runtime(judge_target)
            if readiness is not None:
                hosted_runtime_checks.append({
                    "role": "judge",
                    "model_spec": args.judge_model,
                    **readiness,
                })
        except Exception as exc:  # noqa: BLE001 - fail no-call preflight
            error_path = out / "judge-hosted-runtime-preflight.error.json"
            _write_json(error_path, {
                "status": "error",
                "phase": "hosted_runtime_preflight",
                "preflight": True,
                "role": "judge",
                "model_spec": args.judge_model,
                "exception_type": type(exc).__name__,
                "message": str(exc)[:2000],
            })
            print(
                "judge hosted runtime preflight failed: "
                f"{type(exc).__name__}: {exc}",
                file=sys.stderr,
            )
            return 1
    companion_binding: dict[str, object] | None = None
    companion_evidence: dict[
        str, set[tuple[str, tuple[str, ...]]]
    ] = {}
    expected_coverage_conditions = {
        _coverage_condition(
            str(getattr(target, "name")), _component_config(target),
            args.defense, args.defense_guard,
        )
        for target in prebuilt_targets.values()
    }
    try:
        if all(companion_flags):
            companion_binding, companion_evidence = _load_companion_coverage(
                args.modality_coverage_companion,
                args.modality_coverage_companion_sha256,
                expected_coverage_conditions,
                expected_driver_source=driver_source,
                expected_harness_source=harness_source,
            )
        modality_plan = plan_modality_coverage(
            list(prebuilt_targets.values()), loaded_corpora,
            enforce_available=not args.dry_run and companion_binding is None,
        )
        if companion_binding is not None:
            modality_plan = _apply_companion_coverage(
                modality_plan, companion_evidence,
                args.modality_coverage_companion_sha256,
            )
    except (OSError, ValueError, ModalityCoverageError) as exc:
        _write_json(out / "modality-coverage.error.json", {
            "status": "error",
            "phase": "modality_coverage_preflight",
            "exception_type": type(exc).__name__,
            "message": str(exc),
        })
        print(f"modality coverage preflight failed: {exc}", file=sys.stderr)
        return 1
    modality_plan_payload = modality_plan.manifest_payload()
    (out / "modality-coverage.error.json").unlink(missing_ok=True)

    try:
        for rows in loaded_corpora.values():
            source_metrics.validate_scored_source_metrics(rows)
        for target in prebuilt_targets.values():
            validator = getattr(target, "validate_research_identity", None)
            if callable(validator):
                validator()
        planned_attackers = {}
        for attacker_name in attacker_names:
            attacker = get_attacker(
                attacker_name,
                **attacker_configs.get(attacker_name.lower(), {}),
            )
            if getattr(attacker, "runner_replay_eligible", True) is False:
                raise ValueError(
                    f"attacker {attacker_name!r} is a native-artifact integration "
                    "and cannot be replayed through Runner"
                )
            _component_config(attacker)
            planned_attackers[attacker_name] = attacker
        planned_cascade = build_judges(
            judge_names,
            args.judge_model,
            guardrail_model=args.guardrail_model,
            guardrail_revision=args.guardrail_revision,
            guardrail_device=args.guardrail_device,
        )
        _component_config(planned_cascade)
        policy_strata = {
            name: _source_policy_cluster_counts(rows)
            for name, rows in loaded_corpora.items()
        }
        call_projection = _project_grid_call_upper_bounds(
            targets=prebuilt_targets,
            corpora=loaded_corpora,
            attackers=planned_attackers,
            cascade=planned_cascade,
            seeds=seeds,
            max_queries=args.max_queries,
            max_turns=args.max_turns,
        )
        _validate_planned_call_budget(
            call_projection,
            target=args.max_total_target_calls,
            judge=args.max_total_judge_calls,
            http=args.max_total_http_attempts,
            deadline_seconds=args.deadline_seconds,
            dry_run=bool(args.dry_run),
            require_complete=bool(args.preflight_only),
        )
    except Exception as exc:  # noqa: BLE001 - fail closed at the pre-call boundary
        _write_json(out / "grid-planning.error.json", {
            "status": "error",
            "phase": "grid_planning_preflight",
            "exception_type": type(exc).__name__,
            "message": str(exc),
        })
        print(f"grid planning preflight failed: {exc}", file=sys.stderr)
        return 1
    for corpus_name, counts in policy_strata.items():
        print(
            f"plan '{corpus_name}' source-policy clusters: "
            + json.dumps(counts, sort_keys=True, separators=(",", ":"))
        )
    print(
        "planned complete-grid call upper bounds: "
        + json.dumps(call_projection, sort_keys=True, separators=(",", ":"))
    )

    grid_request = {
        "models": [persisted_model_specs[spec] for spec in model_specs],
        "corpora": corpora,
        "attackers": attacker_names,
        "attacker_configs": attacker_configs,
        "attacker_config_artifact": attacker_config_artifact,
        "local_configs": {
            persisted_model_specs[spec]: config
            for spec, config in local_configs.items()
        },
        "local_config_artifact": local_config_artifact,
        "judges": judge_names,
        "judge_model": args.judge_model,
        "guardrail_model": args.guardrail_model if guardrail_selected else None,
        "guardrail_revision": (
            args.guardrail_revision.lower() if guardrail_selected else None
        ),
        "guardrail_device": args.guardrail_device or None,
        "seeds": seeds,
        "sample_seed": args.sample_seed,
        "limit": args.limit,
        "max_queries": args.max_queries,
        "max_turns": args.max_turns,
        "global_call_budget": {
            "max_target_calls": args.max_total_target_calls or None,
            "max_judge_calls": args.max_total_judge_calls or None,
            "max_http_attempts": args.max_total_http_attempts or None,
            "call_start_deadline_seconds_from_first_invocation": (
                args.deadline_seconds or None
            ),
            "accounting_semantics": "durable_pre_call_logical_reservation_v1",
        },
        "group_keys": group_keys,
        "defense": args.defense,
        "defense_guard": args.defense_guard,
        "quantization": args.quantization,
        "dtype": args.dtype,
        "dry_run": bool(args.dry_run),
        "driver_source": driver_source,
        "provider_data_policy_approval": provider_data_policy,
        "partition_plan": partition_binding,
        "partition_assignments": partition_assignments,
        "modality_coverage_plan": modality_plan_payload,
        "modality_coverage_companion": companion_binding,
        "source_policy_cluster_counts": policy_strata,
        "call_projection": call_projection,
    }
    grid_material = json.dumps(
        grid_request, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    grid_id = f"grid-{hashlib.sha256(grid_material).hexdigest()[:24]}"
    grid_path = out / f"{grid_id}.grid.json"
    grid_lock = out / f"{grid_id}.grid.lock"
    budget_path = out / f"{grid_id}.budget.json"
    circuit_path = out / f"{grid_id}.circuits.json"
    circuits: dict[str, dict[str, object]] = {}

    if args.preflight_only:
        if hosted_runtime_checks:
            print(
                "local hosted readiness passed (SDK import and credential "
                "presence only; provider account access and model visibility "
                "were not checked): "
                + json.dumps(
                    hosted_runtime_checks,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
        print(
            f"rig preflight passed for {grid_id}; no target or judge generation "
            "calls were made"
        )
        return 0

    def persist_circuits() -> None:
        _write_json(circuit_path, {
            "format_version": 1,
            "grid_id": grid_id,
            "circuits": circuits,
        })

    def open_circuit(
        key: str, exc: Exception, *, model_spec: str | None = None,
    ) -> None:
        if key in circuits:
            return
        circuits[key] = {
            "opened_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "exception_type": type(exc).__name__,
            "phase": getattr(exc, "phase", "unknown"),
            "message": (
                _artifact_safe_model_error(
                    exc, model_spec, persisted_model_specs[model_spec]
                )
                if model_spec is not None else str(exc)[:2000]
            ),
            "call_audit": _safe_external_audit(exc),
            "budget_snapshot": call_budget.snapshot(),
        }
        persist_circuits()

    def blocking_circuit(spec: str) -> tuple[str, dict[str, object]] | None:
        target_key = f"target:{persisted_model_specs[spec]}"
        for key in ("budget", "judge", target_key):
            if key in circuits:
                return key, circuits[key]
        return None

    try:
        grid_lock_token = _acquire_artifact_lock(
            grid_lock,
            {"grid_id": grid_id, "started_at": run_started},
            stale_seconds=args.lock_stale_seconds,
        )
    except (OSError, ValueError, LockHeldError) as exc:
        print(f"cannot initialize matrix lifecycle: {exc}", file=sys.stderr)
        return 1
    try:
        # Circuit reset/read and budget-ledger initialization are protected by
        # the grid lock.  A concurrent operator can neither erase an active
        # circuit nor race the first durable budget reservation.
        persisted_circuits = (
            _load_circuit_state(circuit_path, grid_id=grid_id)
            if circuit_path.exists() or circuit_path.is_symlink()
            else {}
        )

        budget_ledger_existed = budget_path.exists()
        if budget_ledger_existed:
            existing_budget = _json_loads_strict(
                budget_path.read_text(encoding="utf-8")
            )
            deadline_epoch = (
                existing_budget.get("deadline_epoch")
                if isinstance(existing_budget, dict) else None
            )
        else:
            deadline_epoch = (
                time.time() + args.deadline_seconds
                if args.deadline_seconds else None
            )
        call_budget = GlobalCallBudget(
            max_target_calls=args.max_total_target_calls or None,
            max_judge_calls=args.max_total_judge_calls or None,
            max_http_attempts=args.max_total_http_attempts or None,
            deadline_epoch=deadline_epoch,
            state_path=budget_path,
            budget_id=grid_id,
        )
        _validate_budget_recovery_high_water(
            out, call_budget.snapshot(), circuits=persisted_circuits,
        )
        # Reset only after every durable failure/recovery artifact has been
        # validated against the ledger. Otherwise reset could erase the sole
        # high-water evidence for a paid failed call.
        if args.reset_open_circuits:
            circuit_path.unlink(missing_ok=True)
            circuits = {}
        else:
            circuits = persisted_circuits
    except (OSError, ValueError) as exc:
        _release_artifact_lock(grid_lock, grid_lock_token)
        print(f"cannot initialize matrix lifecycle: {exc}", file=sys.stderr)
        return 1
    atexit.register(_release_artifact_lock, grid_lock, grid_lock_token)
    cell_statuses: list[dict[str, object]] = []
    _write_json(grid_path, {
        "status": "running",
        "grid_id": grid_id,
        "started_at": run_started,
        "request": grid_request,
        "call_budget_snapshot": call_budget.snapshot(),
        "requested_cells": len(model_specs) * len(corpora) * len(attacker_names),
        "cells": cell_statuses,
    })

    n_cells = 0
    n_skipped = 0
    n_errors = 0
    executed_modality_evidence: dict[
        str, set[tuple[str, tuple[str, ...]]]
    ] = {
        str(getattr(target, "name")): set()
        for target in prebuilt_targets.values()
    }
    for corpus_name in corpora:
        corpus = loaded_corpora[corpus_name]
        sampling_audit = sampling_audits[corpus_name]
        print(f"corpus '{corpus_name}': {len(corpus)} datapoints")
        (out / f"{_safe_component(corpus_name)}.corpus.error.json").unlink(
            missing_ok=True
        )
        for spec in model_specs:
            blocked = blocking_circuit(spec)
            if blocked is not None:
                circuit_key, circuit = blocked
                n_errors += len(attacker_names)
                circuit_error = out / (
                    "__".join((
                        _safe_component(corpus_name),
                        _safe_component(persisted_model_specs[spec]),
                        "circuit-open",
                    ))
                    + ".error.json"
                )
                _write_json(circuit_error, {
                    "status": "error",
                    "phase": "circuit_open",
                    "corpus": corpus_name,
                    "model_spec": persisted_model_specs[spec],
                    "circuit_key": circuit_key,
                    "circuit": circuit,
                    "call_budget_snapshot": call_budget.snapshot(),
                })
                for attacker_name in attacker_names:
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "status": "error",
                        "phase": "circuit_open",
                        "error_artifact": circuit_error.name,
                    })
                continue
            target = prebuilt_targets[spec]
            (out / (
                "__".join((
                    _safe_component(corpus_name),
                    _safe_component(persisted_model_specs[spec]),
                    "target-setup",
                )) + ".error.json"
            )).unlink(missing_ok=True)
            (out / (
                "__".join((
                    _safe_component(corpus_name),
                    _safe_component(persisted_model_specs[spec]),
                    "circuit-open",
                )) + ".error.json"
            )).unlink(missing_ok=True)
            for attacker_name in attacker_names:
                runner = None
                planned = None
                stem = None
                execution_started = False
                cell_lock_acquired = False
                cell_lock_conflict = False
                cell_lock: Path | None = None
                cell_lock_token: str | None = None
                paths: dict[str, Path] = {}
                fallback_error = out / (
                    "__".join((
                        _safe_component(corpus_name),
                        _safe_component(persisted_model_specs[spec]),
                        _safe_component(attacker_name),
                        "unplanned",
                    ))
                    + ".error.json"
                )
                blocked = blocking_circuit(spec)
                if blocked is not None:
                    circuit_key, circuit = blocked
                    n_errors += 1
                    _write_json(fallback_error, {
                        "status": "error",
                        "phase": "circuit_open",
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "circuit_key": circuit_key,
                        "circuit": circuit,
                        "call_budget_snapshot": call_budget.snapshot(),
                    })
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "status": "error",
                        "phase": "circuit_open",
                        "error_artifact": fallback_error.name,
                    })
                    continue
                try:
                    attacker_config = attacker_configs.get(
                        attacker_name.lower(), {}
                    )
                    attacker = get_attacker(attacker_name, **attacker_config)
                    if getattr(attacker, "runner_replay_eligible", True) is False:
                        raise ValueError(
                            f"attacker {attacker_name!r} is a native-artifact "
                            "integration and cannot be replayed through Runner"
                        )
                    cascade = build_judges(
                        judge_names,
                        args.judge_model,
                        guardrail_model=args.guardrail_model,
                        guardrail_revision=args.guardrail_revision,
                        guardrail_device=args.guardrail_device,
                    )
                    runner = Runner(
                        attacker,
                        target,
                        cascade,
                        AttackBudget(
                            max_queries=args.max_queries,
                            max_turns=args.max_turns,
                            seed=seeds[0],
                        ),
                        seeds,
                        call_budget=call_budget,
                    )
                    cell_config = {
                        "grid_id": grid_id,
                        "corpus": corpus_name,
                        "limit": args.limit,
                        "sample_seed": args.sample_seed,
                        "sampling_audit": sampling_audit,
                        "model_spec": persisted_model_specs[spec],
                        "local_identity": local_configs.get(spec),
                        "attacker": attacker_name,
                        "attacker_config": attacker_config,
                        "judge_names": judge_names,
                        "judge_model": args.judge_model,
                        "guardrail_model": (
                            args.guardrail_model if guardrail_selected else None
                        ),
                        "guardrail_revision": (
                            args.guardrail_revision.lower()
                            if guardrail_selected else None
                        ),
                        "guardrail_device": args.guardrail_device or None,
                        "group_keys": group_keys,
                        "defense": args.defense,
                        "defense_guard": args.defense_guard,
                        "quantization": args.quantization,
                        "dtype": args.dtype,
                        "dry_run": bool(args.dry_run),
                        "driver_source": driver_source,
                        "provider_data_policy_approval": provider_data_policy,
                        "partition_plan": partition_binding,
                        "partition_assignment": partition_assignments.get(
                            corpus_name
                        ),
                        "global_call_budget": grid_request["global_call_budget"],
                        "modality_coverage_plan": modality_plan_payload,
                        "modality_coverage_companion": companion_binding,
                    }
                    planned = runner.plan_manifest(
                        corpus,
                        started_at=run_started,
                        env=run_env,
                        run_config=cell_config,
                    )
                    stem = "__".join((
                        _safe_component(corpus_name),
                        _safe_component(target.name),
                        _safe_component(attacker_name),
                        planned.run_id,
                    ))
                    paths = {
                        "attempts": out / f"{stem}.attempts.jsonl",
                        "responses": out / f"{stem}.responses.jsonl",
                        "judgments": out / f"{stem}.jsonl",
                        "trails": out / f"{stem}.trails.jsonl",
                        "results": out / f"{stem}.results.jsonl",
                        "manifest": out / f"{stem}.manifest.json",
                        "checkpoint": out / f"{stem}.checkpoint.jsonl",
                        "response_checkpoint": out / f"{stem}.responses.checkpoint.jsonl",
                        "complete": out / f"{stem}.complete.json",
                        "error": out / f"{stem}.error.json",
                    }
                    cell_lock = out / f"{stem}.cell.lock"
                    try:
                        cell_lock_token = _acquire_artifact_lock(
                            cell_lock,
                            {
                                "grid_id": grid_id,
                                "run_id": planned.run_id,
                                "started_at": run_started,
                            },
                            stale_seconds=args.lock_stale_seconds,
                        )
                    except LockHeldError as exc:
                        cell_lock_conflict = True
                        raise RuntimeError(str(exc)) from exc
                    cell_lock_acquired = True

                    required = (
                        "attempts", "responses", "judgments", "trails",
                        "results", "manifest",
                    )
                    if (
                        not budget_ledger_existed
                        and any(paths[name].exists() for name in (
                            "checkpoint", "response_checkpoint", "complete",
                        ))
                    ):
                        raise ValueError(
                            "resume/completion artifacts exist but the durable "
                            "call-budget ledger is missing; manual audit required"
                        )
                    if paths["complete"].is_file():
                        _validate_completion_marker(paths, planned, required)
                        _record_executed_modality_evidence(
                            target.name,
                            [Attempt.model_validate(row) for row in _read_jsonl(
                                paths["attempts"]
                            )],
                            [Response.model_validate(row) for row in _read_jsonl(
                                paths["responses"]
                            )],
                            executed_modality_evidence,
                        )
                        # A fully verified success supersedes a stale same-stem
                        # failure from an earlier retry.
                        paths["error"].unlink(missing_ok=True)
                        paths["checkpoint"].unlink(missing_ok=True)
                        paths["response_checkpoint"].unlink(missing_ok=True)
                        fallback_error.unlink(missing_ok=True)
                        _remove_superseded_cell_errors(
                            out, corpus=corpus_name,
                            model_spec=persisted_model_specs[spec],
                            attacker=attacker_name,
                        )
                        for stale in out.glob("*.lock.error.json"):
                            if stale.name.startswith(f"{stem}__"):
                                stale.unlink(missing_ok=True)
                        print(f"  [{stem}] already complete; no calls made")
                        n_skipped += 1
                        cell_statuses.append({
                            "corpus": corpus_name,
                            "model_spec": persisted_model_specs[spec],
                            "target": target.name,
                            "attacker": attacker_name,
                            "run_id": planned.run_id,
                            "status": "complete_existing",
                            "completion_marker": paths["complete"].name,
                        })
                        continue

                    resumed = Runner.load_checkpoint(
                        paths["checkpoint"], expected_run_id=planned.run_id
                    )
                    resumed_responses = Runner.load_response_checkpoint(
                        paths["response_checkpoint"], expected_run_id=planned.run_id
                    )
                    execution_started = True
                    judgments, manifest = runner.run(
                        corpus,
                        started_at=run_started,
                        env=run_env,
                        run_config=cell_config,
                        manifest=planned,
                        resume_records=resumed,
                        on_record=lambda record, checkpoint=paths["checkpoint"]: (
                            Runner.append_checkpoint(checkpoint, record)
                        ),
                        response_records=resumed_responses,
                        on_response=lambda record, sidecar=paths["response_checkpoint"]: (
                            Runner.append_checkpoint(sidecar, record)
                        ),
                    )
                    results = runner.aggregate(judgments, group_keys=group_keys)
                    _record_executed_modality_evidence(
                        target.name, runner.attempts, runner.responses,
                        executed_modality_evidence,
                    )

                    runner.save_attempts(paths["attempts"])
                    runner.save_responses(paths["responses"])
                    runner.save_results(judgments, paths["judgments"])
                    runner.save_trails(paths["trails"])
                    paths["results"].write_text(
                        "\n".join(r.model_dump_json() for r in results) + "\n",
                        encoding="utf-8",
                    )
                    paths["manifest"].write_text(
                        manifest.model_dump_json(indent=1), encoding="utf-8"
                    )
                    completion_payload = {
                        "status": "complete",
                        "format_version": 2,
                        "run_id": manifest.run_id,
                        "code_version": manifest.code_version,
                        "schema_version": manifest.schema_version,
                        "n_attempts": len(runner.attempts),
                        "n_responses": len(runner.responses),
                        "n_judgments": len(judgments),
                        "n_results": len(results),
                        "realized_identities_sha256": manifest.config[
                            "realized_identities_sha256"
                        ],
                        "call_budget_snapshot": call_budget.snapshot(),
                        "artifacts": {
                            name: _artifact_descriptor(paths[name])
                            for name in required
                        },
                    }
                    pending_complete = paths["complete"].with_name(
                        f".{paths['complete'].name}.pending-{os.getpid()}"
                    )
                    _write_json(pending_complete, completion_payload)
                    validation_paths = {**paths, "complete": pending_complete}
                    try:
                        _validate_completion_marker(
                            validation_paths, planned, required
                        )
                    except Exception:
                        pending_complete.unlink(missing_ok=True)
                        raise
                    pending_complete.replace(paths["complete"])
                    paths["error"].unlink(missing_ok=True)
                    paths["checkpoint"].unlink(missing_ok=True)
                    paths["response_checkpoint"].unlink(missing_ok=True)
                    fallback_error.unlink(missing_ok=True)
                    _remove_superseded_cell_errors(
                        out, corpus=corpus_name,
                        model_spec=persisted_model_specs[spec],
                        attacker=attacker_name,
                    )
                    for stale in out.glob("*.lock.error.json"):
                        if stale.name.startswith(f"{stem}__"):
                            stale.unlink(missing_ok=True)
                    print(
                        f"  [{stem}] {len(judgments)} judgments -> {len(results)} "
                        f"results (run {manifest.run_id}; resumed {len(resumed)})"
                    )
                    n_cells += 1
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "target": target.name,
                        "attacker": attacker_name,
                        "run_id": manifest.run_id,
                        "status": "complete",
                        "completion_marker": paths["complete"].name,
                    })
                except Exception as exc:  # noqa: BLE001 - isolate matrix cells
                    n_errors += 1
                    if isinstance(exc, BudgetExhausted):
                        open_circuit("budget", exc)
                    elif isinstance(exc, ExternalCallFailure):
                        target_failure = exc.phase != "judge_call"
                        open_circuit(
                            "judge" if not target_failure else (
                                f"target:{persisted_model_specs[spec]}"
                            ),
                            exc,
                            model_spec=spec if target_failure else None,
                        )
                    run_id = planned.run_id if planned is not None else None
                    if execution_started and runner is not None and paths:
                        # These snapshots are diagnostic fallbacks; the append-only
                        # checkpoint remains the authoritative resume source.
                        try:
                            runner.save_attempts(paths["attempts"])
                            runner.save_responses(paths["responses"])
                            runner.save_results(runner.judgments, paths["judgments"])
                            runner.save_trails(paths["trails"])
                            partial_manifest = runner.last_manifest or planned
                            if partial_manifest is not None:
                                paths["manifest"].write_text(
                                    partial_manifest.model_dump_json(indent=1),
                                    encoding="utf-8",
                                )
                        except Exception as artifact_exc:  # noqa: BLE001
                            print(
                                f"  ! partial artifact write also failed: "
                                f"{type(artifact_exc).__name__}: {artifact_exc}",
                                file=sys.stderr,
                            )
                    error_path = (
                        out / f"{stem}__{grid_id}.lock.error.json"
                        if cell_lock_conflict and stem is not None
                        else paths.get("error", fallback_error)
                    )
                    _write_json(error_path, {
                            "status": "error",
                            "run_id": run_id,
                            "corpus": corpus_name,
                            "model_spec": persisted_model_specs[spec],
                            "target": getattr(
                                target, "name", persisted_model_specs[spec]
                            ),
                            "attacker": attacker_name,
                            "exception_type": type(exc).__name__,
                            "message": _artifact_safe_model_error(
                                exc, spec, persisted_model_specs[spec]
                            ),
                            "completed_attempts": len(runner.attempts) if runner else 0,
                            "call_budget_snapshot": call_budget.snapshot(),
                            "call_audit": _safe_external_audit(exc),
                        })
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "target": getattr(
                            target, "name", persisted_model_specs[spec]
                        ),
                        "attacker": attacker_name,
                        "run_id": run_id,
                        "status": "error",
                        "phase": "cell_execution_or_validation",
                        "error_artifact": error_path.name,
                    })
                    print(
                        f"  ! cell failed [{stem or f'{corpus_name}/{spec}/{attacker_name}'}]: "
                        f"{type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )
                finally:
                    if (
                        cell_lock_acquired and cell_lock is not None
                        and cell_lock_token is not None
                    ):
                        _release_artifact_lock(cell_lock, cell_lock_token)

    requested_cells = len(model_specs) * len(corpora) * len(attacker_names)
    if len(cell_statuses) != requested_cells:
        n_errors += 1
        cell_statuses.append({
            "status": "error",
            "phase": "grid_accounting",
            "message": (
                f"accounted for {len(cell_statuses)} of {requested_cells} "
                "requested cells"
            ),
        })
    try:
        modality_result = verify_executed_modality_coverage(
            modality_plan, executed_modality_evidence
        )
        modality_result_payload = modality_result.manifest_payload()
    except ModalityCoverageError as exc:
        n_errors += 1
        modality_result_payload = {
            "status": "failed",
            "error": str(exc),
            "executed_modality_evidence": {
                key: [
                    {
                        "datapoint_id": datapoint_id,
                        "combination": list(combination),
                    }
                    for datapoint_id, combination in sorted(value)
                ]
                for key, value in executed_modality_evidence.items()
            },
        }
    final_grid = {
        "status": "complete" if n_errors == 0 else "partial",
        "grid_id": grid_id,
        "started_at": run_started,
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "request": grid_request,
        "requested_cells": requested_cells,
        "accounted_cells": min(len(cell_statuses), requested_cells),
        "n_new_complete": n_cells,
        "n_existing_complete": n_skipped,
        "n_errors": n_errors,
        "call_budget_snapshot": call_budget.snapshot(),
        "modality_coverage_plan": modality_plan_payload,
        "modality_coverage_result": modality_result_payload,
        "cells": cell_statuses,
    }
    _write_json(grid_path, final_grid)
    coverage_proof_path = out / f"{grid_id}.modality-coverage-proof.json"
    coverage_proof_sha256: str | None = None
    if n_errors == 0:
        try:
            marker_paths = sorted({
                out / str(cell["completion_marker"])
                for cell in cell_statuses
                if cell.get("status") in {"complete", "complete_existing"}
            })
            marker_descriptors = [
                _artifact_descriptor(path) for path in marker_paths
            ]
            grid_descriptor = _artifact_descriptor(grid_path)
            proof_payload = {
                "schema_version": _COVERAGE_PROOF_SCHEMA,
                "grid": grid_descriptor,
                "completion_markers": marker_descriptors,
                "conditions": _reconstruct_companion_conditions(
                    out, grid_descriptor, marker_descriptors,
                    expected_driver_source=driver_source,
                    expected_harness_source=harness_source,
                ),
            }
            _write_json(coverage_proof_path, proof_payload)
            coverage_proof_sha256 = _sha256_file(coverage_proof_path)
        except Exception as exc:  # noqa: BLE001 - proof is a release artifact
            n_errors += 1
            final_grid["status"] = "partial"
            final_grid["n_errors"] = n_errors
            cell_statuses.append({
                "status": "error",
                "phase": "modality_coverage_proof",
                "exception_type": type(exc).__name__,
                "message": str(exc),
            })
            _write_json(grid_path, final_grid)
            coverage_proof_path.unlink(missing_ok=True)
    _release_artifact_lock(grid_lock, grid_lock_token)

    print(
        f"\ndone: {n_cells} cells written, {n_skipped} already complete, "
        f"{n_errors} failed; artifacts in {out}"
    )
    print(
        "figures: python -m experiments.figures --help  "
        "# pass explicit model/defense grid roots and preregistered corpus facets"
    )
    if coverage_proof_sha256 is not None:
        print(
            f"modality companion proof: {coverage_proof_path} "
            f"sha256={coverage_proof_sha256}"
        )
    return 1 if n_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
