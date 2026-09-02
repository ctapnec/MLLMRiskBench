"""Turnkey experiment driver for URA-Bench (thesis Chapter V).

Runs the model x attacker x judge matrix over one or more corpora, aggregates the
metrics, and writes per-cell JSONL plus a completed-grid directory consumed by
the integrity-checked analysis commands.
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
# offline smoke of the whole matrix (no keys, no GPU). --exclude-tool-conditioned
# drops the two tool-conditioned synth rows (which no attacker can execute yet)
# with a recorded exclusion count; omit it to see the fail-closed tool contract:
python experiments/run_matrix.py --dry-run --corpora synth --limit 12 \
    --exclude-tool-conditioned --out runs/dry

# one-local-target no-call preflight (replace receipt placeholders with the
# content-addressed artifacts prepared by the runbook):
python experiments/run_matrix.py \
    --local vllm:Qwen/Qwen3-VL-8B-Instruct \
    --local-config experiments/local-targets.json --preflight-only \
    --project-revision runs/project-revision.json --project-revision-sha256 <64-hex> \
    --attackers replay --judges rules --corpora synth --limit 12 \
    --max-total-target-calls 12 --max-total-judge-calls 1 \
    --max-total-http-attempts 1 --deadline-seconds 3600 --out runs/local-preflight

Hosted comparison ids should be provider-qualified. The Fable case is the public
``claude-fable-5`` model with explicit high effort, adaptive thinking, a 25,000
token output ceiling, and no temperature parameter; live account access still
must pass preflight. The OpenAI case is the exact public ``gpt-5.6-sol`` model via
the Responses API with Pro mode, medium effort, and current-turn reasoning
context configured as ``all_turns`` in the target specification; no Sol-Pro slug is
inferred. Such a
comparison is cross-provider and is not a causal same-base-model defense ablation.
"""
from __future__ import annotations

import argparse
import atexit
import difflib
import hashlib
import json
import math
import os
import platform
import random
import re
import secrets
import signal
import stat
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

# make `import ura` and `import experiments.*` work when run as a script
# (`python experiments/run_matrix.py ...`), not only as `python -m experiments.run_matrix`
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "src"))
sys.path.insert(0, str(_REPO_ROOT))

from ura.adapters.base import AttackBudget           # noqa: E402
from ura.adapters._engine_runtime import (            # noqa: E402
    RUNTIME_REQUIRED_ATTACKERS,
    EngineRuntimeSelection,
    engine_runtime_identity_descriptor,
    parse_engine_runtime_config,
    validate_engine_runtime_execution_descriptor,
    validate_engine_runtime_identity_descriptor,
    validate_engine_runtime_selection_descriptor,
)
from ura.adapters.engines import get_attacker         # noqa: E402
from ura.adapters.nanogcg import LIVE_NANOGCG_DISABLED_MESSAGE  # noqa: E402
from ura.attacker_input_contract import (              # noqa: E402
    AttackerInputContract,
    AttackerInputContractError,
    deserialize_attacker_input_plan,
    is_tool_conditioned_source,
    media_input_identity,
    target_modality_support_from_component_config,
    validate_attempts_against_attacker_input_plan,
)
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
    MediaRef,
    Response,
    RunManifest,
)
from ura.eligibility import build_eligibility_plan    # noqa: E402
from ura.judges.base import JudgeCascade              # noqa: E402
from ura.judges.llm import LLMJudge                   # noqa: E402
from ura.judges.rules import RuleJudge                # noqa: E402
from ura.lane_projection import (                     # noqa: E402
    build_lane_projection,
    write_lane_projection,
)
from ura.model_identity import canonical_https_endpoint_identity  # noqa: E402
from ura.model_acquisition import (                     # noqa: E402
    ModelAcquisitionError,
    load_plan,
    load_receipt,
    write_document_create_only,
)
from ura.model_acquisition_runtime import (             # noqa: E402
    ManagedModelRuntime,
    RuntimeSelection,
    admit_managed_model_runtime,
    build_runtime_plan,
    build_runtime_selection,
    collect_run_requirements,
    hf_offline_environment_overrides,
    model_acquisition_cell_role_projection,
    model_acquisition_execution_descriptor,
    model_acquisition_shared_role_projection,
    public_selection_descriptor,
    sanitize_private_paths,
    validate_model_acquisition_descriptor,
    validate_model_acquisition_grid_binding,
    validate_model_acquisition_role_projection,
    validate_model_acquisition_role_projection_binding,
)
from ura.live_attestation import (                    # noqa: E402
    load_live_attestation_file,
    required_attestation_keys,
    route_config_sha256,
    stable_realized_target_identity,
    validate_execution_scope_id,
    validate_live_attestation_manifest,
    validate_required_live_attestations,
)
from ura.modality_coverage import (                    # noqa: E402
    ModalityCoverageError,
    plan_modality_coverage,
    verify_executed_modality_coverage,
)
from ura.project_revision import (                     # noqa: E402
    diagnostic_project_revision_binding,
    load_project_revision_file,
    project_revision_binding,
    recheck_project_revision,
    validate_project_revision,
)
from ura.request_envelope import (                     # noqa: E402
    build_request_envelope,
    build_request_error,
    load_request_error_file,
    request_envelope_descriptor,
    write_request_envelope,
    write_request_error,
)
from ura.sampling import (                            # noqa: E402
    DEFAULT_SAMPLING_POLICY,
    SAMPLING_POLICIES,
    effective_sampling_policy,
)
from ura.runner import (                              # noqa: E402
    BudgetExhausted,
    CODE_VERSION,
    ExternalCallFailure,
    GlobalCallBudget,
    RetainedFailedOutputStop,
    Runner,
    _component_config,
    _harness_source_identity,
    _portable_attempt_dump,
    realized_identity_summary,
    validate_persisted_judgment_trails,
    validate_planned_realized_identities,
)
from ura.strict_json import strict_json_loads         # noqa: E402
from ura.source_conformance import (                  # noqa: E402
    observed_arm_conformance,
    validate_selected_source_conformance,
    validate_source_conformance_manifest,
    verify_manifest_components,
)
from ura.targets.api import (                              # noqa: E402
    api_target_requires_config,
    build_api_target,
    canonical_provider_name,
    normalize_api_target_config,
    preflight_api_target_runtime,
)
from ura.targets.local import canonical_local_model_identity  # noqa: E402


_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

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


def _discard_unsealed_engine_cell_state(paths: dict[str, Path]) -> tuple[str, ...]:
    """Make an incomplete runtime-backed cell non-resumable across sessions.

    A checkpoint is useful only inside the still-open worker session that
    produced it. Without a verified completion marker and closing seal, a new
    process must regenerate the cell rather than attach a different session's
    seal to old attempts, responses, judgments, or aggregates.
    """

    removable = (
        "attempts",
        "responses",
        "judgments",
        "trails",
        "results",
        "manifest",
        "checkpoint",
        "response_checkpoint",
    )
    candidates = [paths[name] for name in removable if name in paths]
    complete = paths.get("complete")
    if complete is not None:
        candidates.extend(
            complete.parent.glob(f".{complete.name}.pending-*")
        )
    removed: list[str] = []
    for path in dict.fromkeys(candidates):
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_dir() and not path.is_symlink():
            raise ValueError(
                f"unsealed engine cell artifact {path.name!r} is not a file"
            )
        path.unlink()
        removed.append(path.name)
    return tuple(sorted(removed))


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


def _load_or_create_invocation_deadline(
    out: Path,
    *,
    request_envelope_id: str,
    invocation_started_epoch: float,
    deadline_seconds: int,
) -> tuple[float | None, Path | None]:
    """Persist the first-invocation deadline before expensive preparation."""

    if deadline_seconds <= 0:
        return None, None
    if re.fullmatch(r"request-envelope-[0-9a-f]{24}", request_envelope_id) is None:
        raise ValueError("invocation deadline requires a valid request-envelope id")
    proposed = float(invocation_started_epoch) + deadline_seconds
    path = out / f"{request_envelope_id}.deadline.json"
    record = {
        "schema": "ura-invocation-deadline/1",
        "request_envelope_id": request_envelope_id,
        "deadline_seconds": deadline_seconds,
        "deadline_epoch": proposed,
    }
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(
                record,
                handle,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            handle.write("\n")
        return proposed, path
    except FileExistsError:
        pass
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 4096:
        raise ValueError("invocation deadline artifact is not a bounded regular file")
    existing = _json_loads_strict(path.read_text(encoding="utf-8"))
    if (
        not isinstance(existing, dict)
        or set(existing) != set(record)
        or existing.get("schema") != record["schema"]
        or existing.get("request_envelope_id") != request_envelope_id
        or existing.get("deadline_seconds") != deadline_seconds
        or isinstance(existing.get("deadline_epoch"), bool)
        or not isinstance(existing.get("deadline_epoch"), (int, float))
        or not math.isfinite(float(existing["deadline_epoch"]))
    ):
        raise ValueError("invocation deadline artifact is invalid or mismatched")
    retained = float(existing["deadline_epoch"])
    if retained > proposed:
        raise ValueError(
            "system clock moved backward across invocation deadline recovery"
        )
    return retained, path


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
    return strict_json_loads(text)


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
    # Keep the unresolved final component so O_NOFOLLOW and the descriptor/path
    # identity checks can actually detect a link or an inspect -> open swap.
    path = Path(os.path.abspath(Path(path_value).expanduser()))
    raw, opened = _bounded_nofollow_read(
        path,
        label=flag_name,
        max_bytes=max_bytes,
    )
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256.lower():
        raise ValueError(
            f"{flag_name} sha256 mismatch: expected {expected_sha256.lower()}, "
            f"got {actual_sha256}"
        )
    try:
        value = _json_loads_strict(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(f"invalid {flag_name} JSON: {exc}") from exc
    return value, {
        "file": path.name,
        "sha256": actual_sha256,
        "bytes": opened.st_size,
    }


def _retain_content_addressed_input(
    out: Path, path_value: str, expected_sha256: str, *, stem: str,
    filename: str | None = None,
) -> Path:
    """Copy an already approved input into the return tree without overwrite."""

    if re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256 or "") is None:
        raise ValueError(f"{stem} input digest must be exactly 64 hexadecimal digits")
    # Do not resolve the final component before the no-follow open: resolving it
    # would turn a symlink into an apparently safe regular target.
    source = Path(os.path.abspath(Path(path_value).expanduser()))
    payload, _opened = _bounded_nofollow_read(
        source,
        label=f"{stem} input",
        max_bytes=256 * 1024 * 1024,
    )
    if not secrets.compare_digest(
        hashlib.sha256(payload).hexdigest(), expected_sha256.lower()
    ):
        raise ValueError(f"{stem} input changed after content validation")
    return _retain_content_addressed_bytes(
        out,
        payload,
        expected_sha256,
        stem=stem,
        filename=filename,
    )


def _retain_content_addressed_bytes(
    out: Path,
    payload: bytes,
    expected_sha256: str,
    *,
    stem: str,
    filename: str | None = None,
) -> Path:
    """Retain already-approved held bytes without reopening a private input."""

    actual = hashlib.sha256(payload).hexdigest()
    if not secrets.compare_digest(actual, expected_sha256.lower()):
        raise ValueError(f"held {stem} bytes no longer match their digest")
    if filename is not None and (
        not filename or Path(filename).name != filename
    ):
        raise ValueError(f"content-addressed {stem} filename must be a safe basename")
    if out.is_symlink() or out.is_junction():
        raise ValueError(f"content-addressed {stem} output directory is unsafe")
    output = out.resolve(strict=True)
    output_info = output.lstat()
    if (
        output.is_symlink()
        or output.is_junction()
        or not stat.S_ISDIR(output_info.st_mode)
    ):
        raise ValueError(f"content-addressed {stem} output directory is unsafe")
    destination = output / (filename or f"{stem}-{actual[:24]}.json")
    try:
        destination_info = destination.lstat()
    except FileNotFoundError:
        destination_info = None
    if destination_info is not None:
        existing, _opened = _bounded_nofollow_read(
            destination,
            label=f"retained {stem}",
            max_bytes=max(len(payload), 1),
        )
        if existing != payload:
            raise ValueError(
                f"content-addressed {stem} artifact collision: {destination}"
            )
        return destination

    descriptor: int | None = None
    created_identity: tuple[int, int, int] | None = None
    creation_complete = False
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        opened = os.fstat(descriptor)
        created_identity = (opened.st_dev, opened.st_ino, opened.st_mode)
        visible = destination.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or visible.st_nlink != 1
            or (visible.st_dev, visible.st_ino, visible.st_mode)
            != created_identity
        ):
            raise ValueError(f"retained {stem} inode changed while being created")
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            after = os.fstat(handle.fileno())
        final = destination.lstat()
        if (
            after.st_nlink != 1
            or after.st_size != len(payload)
            or (after.st_dev, after.st_ino, after.st_mode) != created_identity
            or final.st_nlink != 1
            or (final.st_dev, final.st_ino, final.st_mode) != created_identity
        ):
            raise ValueError(f"retained {stem} inode changed while being written")
        creation_complete = True
    except FileExistsError:
        # A concurrent exact writer is admitted only after the same bounded
        # no-follow byte comparison as the pre-existing branch.
        existing, _opened = _bounded_nofollow_read(
            destination,
            label=f"retained {stem}",
            max_bytes=max(len(payload), 1),
        )
        if existing != payload:
            raise ValueError(
                f"content-addressed {stem} artifact collision: {destination}"
            )
    except OSError as exc:
        raise ValueError(f"content-addressed {stem} artifact cannot be retained") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created_identity is not None and not creation_complete:
            try:
                current = destination.lstat()
            except OSError:
                current = None
            if current is not None and (
                (current.st_dev, current.st_ino, current.st_mode)
                == created_identity
                and not destination.is_symlink()
                and not destination.is_junction()
            ):
                destination.unlink(missing_ok=True)
    return destination


_SECRET_CONFIG_KEY = re.compile(
    r"(?:api[_-]?key|token|secret|password|authorization|cookie|private[_-]?key)",
    re.IGNORECASE,
)

_IDEATOR_TRANSIENT_IMAGE_DIGESTS_FIELD = "seed_pair_image_sha256"


_PATH_ROOT = re.compile(r"^(?:[/\\]+|[A-Za-z]:[/\\]*)$")
_PATH_LAST_COMPONENT = re.compile(r"[/\\]+[^/\\]+[/\\]*$")


def _scrub_operator_paths(
    message: str, configured_paths: list[object],
) -> str:
    """Replace configured operator paths AND their ancestor directories.

    An OS error may name a missing parent directory rather than the configured
    file itself (the exact message shape is platform-dependent), so every
    ancestor of every configured input is scrubbed too; otherwise a retained
    early-failure artifact could leak a host-specific absolute path.  Ancestors
    are derived textually so the original separator style is preserved and the
    scrub behaves identically on every platform.
    """

    replacements: dict[str, str] = {}

    def register(text_value: str, *, is_input: bool) -> None:
        text_value = text_value.rstrip("/\\") or text_value
        if not text_value or _PATH_ROOT.fullmatch(text_value):
            return  # never scrub a filesystem root
        label = re.split(r"[/\\]", text_value)[-1] or "path"
        kind = "operator-input" if is_input else "operator-input-dir"
        replacements.setdefault(text_value, f"<{kind}:{label}>")

    def register_with_ancestors(text_value: str, *, is_input: bool) -> None:
        register(text_value, is_input=is_input)
        current = text_value
        while True:
            trimmed = _PATH_LAST_COMPONENT.sub("", current)
            if not trimmed or trimmed == current or _PATH_ROOT.fullmatch(trimmed):
                return
            register(trimmed, is_input=False)
            current = trimmed

    for configured in configured_paths:
        if not configured:
            continue
        register_with_ancestors(str(configured), is_input=True)
        try:
            resolved = str(Path(str(configured)).expanduser().resolve(strict=False))
        except (OSError, RuntimeError):
            resolved = ""
        if resolved and resolved != str(configured):
            register_with_ancestors(resolved, is_input=True)
    for variant in sorted(replacements, key=len, reverse=True):
        message = message.replace(variant, replacements[variant])
    return message


def _portable_attacker_configs(
    configs: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Remove host-only replay paths while retaining their exact byte identity."""

    portable: dict[str, dict[str, object]] = {}
    for name, config in configs.items():
        item = dict(config)
        reserved_runtime_fields = {
            "engine_runtime",
            "model_runtime",
            "interpreter",
            "interpreter_path",
            "python_path",
            "runtime_path",
            "venv",
            "venv_path",
        }
        forbidden_runtime_fields = sorted(set(item) & reserved_runtime_fields)
        if forbidden_runtime_fields:
            raise ValueError(
                f"attacker config {name!r} contains private runtime fields; "
                "supply them only through their typed private controller: "
                + ", ".join(forbidden_runtime_fields)
            )
        if name == "ideator" and "out_dir" in item:
            out_dir = item.pop("out_dir")
            if out_dir is not None and (
                not isinstance(out_dir, str) or not out_dir.strip()
            ):
                raise ValueError("IDEATOR out_dir must be null or a non-blank path")
            item["out_dir_configured"] = out_dir is not None
        if name == "ideator" and _IDEATOR_TRANSIENT_IMAGE_DIGESTS_FIELD in item:
            raise ValueError(
                "IDEATOR private image-digest metadata must be verified and "
                "removed before portable attacker configuration is derived"
            )
        if name == "ideator" and "seed_pairs" in item:
            raw_pairs = item.pop("seed_pairs")
            if not isinstance(raw_pairs, list) or not raw_pairs:
                raise ValueError("IDEATOR seed_pairs must be a non-empty list")
            portable_pairs: list[dict[str, object]] = []
            for index, pair in enumerate(raw_pairs):
                if (
                    not isinstance(pair, (list, tuple))
                    or len(pair) != 2
                    or not isinstance(pair[0], str)
                    or not pair[0].strip()
                    or not isinstance(pair[1], str)
                    or not pair[1].strip()
                ):
                    raise ValueError(
                        f"IDEATOR seed_pairs[{index}] must be a non-blank "
                        "(text, image_path) pair"
                    )
                encoded_text = pair[0].encode("utf-8")
                media = media_input_identity(
                    MediaRef(
                        modality="image", path=pair[1], mime="image/png"
                    ),
                    origin="attacker_generated",
                    require_declared_sha256=False,
                )
                portable_pairs.append({
                    "index": index,
                    "text_sha256": hashlib.sha256(encoded_text).hexdigest(),
                    "text_bytes": len(encoded_text),
                    "image": media.manifest_payload(),
                })
            item["seed_pairs_identity"] = portable_pairs
        artifact_spec = (
            ("response_artifact", "response_artifact_sha256", 256 * 1024 * 1024)
            if name == "t3mp3st"
            else ("replay_artifact", "replay_artifact_sha256", 64 * 1024 * 1024)
            if name == "harmbench"
            else None
        )
        declared_path_fields = {
            field for field in ("response_artifact", "replay_artifact") if field in item
        }
        supported_path_field = artifact_spec[0] if artifact_spec is not None else None
        unsupported_path_fields = sorted(declared_path_fields - {supported_path_field})
        if unsupported_path_fields:
            raise ValueError(
                f"attacker config {name!r} has unsupported replay path fields: "
                + ", ".join(unsupported_path_fields)
            )
        if artifact_spec is not None and artifact_spec[0] in item:
            path_field, digest_field, max_bytes = artifact_spec
            path_value = item.pop(path_field)
            label = f"{name} {path_field}"
            if not isinstance(path_value, str) or not path_value:
                raise ValueError(f"{label} must be a non-blank path")
            unresolved = Path(path_value).expanduser()
            if unresolved.is_symlink():
                raise ValueError(f"{label} must not be a symlink")
            path = unresolved.resolve(strict=True)
            if (
                not path.is_file()
                or path.is_symlink()
                or not 0 < path.stat().st_size <= max_bytes
            ):
                raise ValueError(
                    f"{label} must be a regular file no larger than "
                    f"{max_bytes // (1024 * 1024)} MiB"
                )
            identity = {
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
            declared = item.get(digest_field)
            if declared is not None and (
                not isinstance(declared, str)
                or declared.lower() != identity["sha256"]
            ):
                raise ValueError(
                    f"{label} does not match {digest_field}"
                )
            item[f"{path_field}_identity"] = identity
        portable[name] = item
    return portable


def _portable_api_configs(
    configs: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Project hosted configs without disclosing compatible endpoint URLs."""

    portable: dict[str, dict[str, object]] = {}
    for spec, config in configs.items():
        item = dict(config)
        base_url = item.pop("base_url", None)
        if base_url is not None:
            if not isinstance(base_url, str):
                raise ValueError(f"API config {spec!r} base_url must be a string")
            item["base_url_identity"] = canonical_https_endpoint_identity(base_url)
        portable[spec] = item
    return portable


def _bounded_nofollow_read(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[bytes, os.stat_result]:
    """Read one exact regular inode through a bounded no-follow descriptor."""

    descriptor: int | None = None
    try:
        initial = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or not 0 < initial.st_size <= max_bytes
        ):
            raise ValueError(f"{label} must be one regular file within its size bound")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        identity = (initial.st_dev, initial.st_ino, initial.st_mode)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size != initial.st_size
            or (opened.st_dev, opened.st_ino, opened.st_mode) != identity
        ):
            raise ValueError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            raw = stream.read(max_bytes + 1)
            after = os.fstat(stream.fileno())
        if (
            len(raw) != opened.st_size
            or len(raw) > max_bytes
            or (after.st_dev, after.st_ino, after.st_mode)
            != (opened.st_dev, opened.st_ino, opened.st_mode)
            or after.st_nlink != 1
            or after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
        ):
            raise ValueError(f"{label} changed while it was read")
        final = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or (final.st_dev, final.st_ino, final.st_mode)
            != (opened.st_dev, opened.st_ino, opened.st_mode)
            or final.st_size != opened.st_size
            or final.st_mtime_ns != opened.st_mtime_ns
        ):
            raise ValueError(f"{label} path changed while it was read")
        return raw, opened
    except OSError as exc:
        raise ValueError(f"{label} cannot be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _consume_exact_transient_file(
    path: Path,
    *,
    opened: os.stat_result,
    label: str,
) -> None:
    """Move the opened inode into a private quarantine, verify it, then unlink."""

    quarantine = path.parent / (".ura-consumed-" + secrets.token_hex(16))
    destination = quarantine / path.name
    try:
        quarantine.mkdir(mode=0o700)
        os.rename(path, destination)
        moved = destination.lstat()
        if (
            destination.is_symlink()
            or moved.st_nlink != 1
            or (moved.st_dev, moved.st_ino, moved.st_mode)
            != (opened.st_dev, opened.st_ino, opened.st_mode)
            or moved.st_size != opened.st_size
        ):
            raise ValueError(f"{label} changed before it could be consumed")
        destination.unlink()
        quarantine.rmdir()
    except OSError as exc:
        raise ValueError(f"{label} could not be consumed after its exact read") from exc


def _read_optional_bound_config(
    path_value: str,
    expected_sha256: str,
    *,
    flag_name: str,
    transient_environment: str,
    transient_directory: str,
    transient_prefix: str,
    max_bytes: int = 1024 * 1024,
) -> tuple[bytes, Path, int, str, bool] | None:
    """Read one optional config exactly once and consume private materialization."""

    transient_marker = os.environ.pop(transient_environment, "").strip()
    if expected_sha256 and not path_value:
        raise ValueError(
            f"{flag_name} and {flag_name}-sha256 must be provided together"
        )
    if transient_marker and not path_value:
        raise ValueError(f"private transient {flag_name} marker has no config")
    if not path_value:
        return None
    if transient_marker and not expected_sha256:
        raise ValueError(f"private transient {flag_name} requires {flag_name}-sha256")
    unresolved = Path(path_value).expanduser()
    if unresolved.is_symlink() or unresolved.is_junction():
        raise ValueError(f"{flag_name} must be a regular non-symlink JSON file")
    path = unresolved.resolve(strict=True)
    transient = bool(transient_marker)
    if transient_marker:
        try:
            marked_path = Path(transient_marker).expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError(
                f"private transient {flag_name} marker is invalid"
            ) from exc
        if (
            marked_path != path
            or path.parent.name != transient_directory
            or re.fullmatch(
                rf"selected-{transient_prefix}-[0-9a-f]{{24}}-"
                rf"[0-9a-f]{{16}}\.json",
                path.name,
            )
            is None
        ):
            raise ValueError(
                f"private transient {flag_name} marker does not match the config"
            )
    raw, opened = _bounded_nofollow_read(
        path,
        label=flag_name,
        max_bytes=max_bytes,
    )
    if transient:
        _consume_exact_transient_file(
            path,
            opened=opened,
            label=f"private transient {flag_name}",
        )
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256:
        if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
            raise ValueError(
                f"{flag_name}-sha256 must be exactly 64 lowercase hex"
            )
        if not secrets.compare_digest(observed_sha256, expected_sha256):
            raise ValueError(f"{flag_name}-sha256 does not match the read bytes")
    return raw, path, opened.st_size, observed_sha256, transient


def _load_attacker_config(
    path_value: str,
    selected_attackers: list[str],
    expected_sha256: str = "",
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load constructor kwargs without admitting literal secrets.

    External tools receive credentials only through their explicit
    ``credential_env`` allowlist. Persisting a literal key in this JSON would
    leak it into grid and run manifests, so secret-like keys are rejected at any
    nesting level.
    """

    loaded = _read_optional_bound_config(
        path_value,
        expected_sha256,
        flag_name="--attacker-config",
        transient_environment="URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG",
        transient_directory=".private-attacker-configs",
        transient_prefix="attacker",
    )
    if loaded is None:
        return {}, None
    raw, path, size, observed_sha256, transient = loaded
    try:
        value = _json_loads_strict(raw.decode("utf-8"))
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
    if transient:
        # The transient config has already been consumed. Transfer ownership
        # of exact Builder-held artifacts before any digest or portable-identity
        # check can fail so a rejected launch cannot orphan private copies.
        _register_transient_attacker_artifact_cleanup(normalized, path)
    ideator = normalized.get("ideator")
    if ideator is not None:
        has_digest_metadata = _IDEATOR_TRANSIENT_IMAGE_DIGESTS_FIELD in ideator
        if not transient and has_digest_metadata:
            raise ValueError(
                "IDEATOR seed_pair_image_sha256 is reserved for the private "
                "transient Builder handoff"
            )
        raw_pairs = ideator.get("seed_pairs")
        if transient and raw_pairs is not None:
            raw_digests = ideator.get(_IDEATOR_TRANSIENT_IMAGE_DIGESTS_FIELD)
            if (
                not isinstance(raw_pairs, list)
                or not raw_pairs
                or not isinstance(raw_digests, list)
                or len(raw_digests) != len(raw_pairs)
            ):
                raise ValueError(
                    "private transient IDEATOR seed pairs require one exact "
                    "reviewed image digest per pair"
                )
            for index, (pair, declared_sha256) in enumerate(
                zip(raw_pairs, raw_digests, strict=True)
            ):
                if (
                    not isinstance(pair, (list, tuple))
                    or len(pair) != 2
                    or not isinstance(pair[1], str)
                    or not pair[1].strip()
                    or not isinstance(declared_sha256, str)
                    or re.fullmatch(r"[0-9a-f]{64}", declared_sha256) is None
                ):
                    raise ValueError(
                        f"private transient IDEATOR seed pair {index} lacks an "
                        "exact reviewed image path and digest"
                    )
                media_input_identity(
                    MediaRef(
                        modality="image",
                        path=pair[1],
                        sha256=declared_sha256,
                        mime="image/png",
                    ),
                    origin="attacker_generated",
                    require_declared_sha256=True,
                )
            ideator.pop(_IDEATOR_TRANSIENT_IMAGE_DIGESTS_FIELD)
        elif transient and has_digest_metadata:
            raise ValueError(
                "private transient IDEATOR image digests require seed_pairs"
            )
    portable = _portable_attacker_configs(normalized)
    return normalized, {
        "file": (
            f"private-attacker-config@sha256:{observed_sha256}"
            if transient
            else path.name
        ),
        "sha256": observed_sha256,
        "bytes": size,
        "normalized_selected_sha256": _sha256_json(portable),
    }


def _cleanup_transient_attacker_artifacts(
    identities: tuple[tuple[Path, int, int, int, int], ...],
) -> None:
    """Remove only the unchanged private artifacts owned by this Runner child."""

    for path, device, inode, mode, size in identities:
        try:
            if path.is_symlink() or path.is_junction():
                continue
            current = path.lstat()
            if (
                not stat.S_ISREG(current.st_mode)
                or (
                    current.st_dev,
                    current.st_ino,
                    current.st_mode,
                    current.st_size,
                )
                != (device, inode, mode, size)
                or path.resolve(strict=True) != path
            ):
                continue
            path.unlink()
        except OSError:
            continue


def _register_transient_attacker_artifact_cleanup(
    configs: dict[str, dict[str, object]],
    transient_config_path: Path,
) -> None:
    """Give a detached Runner ownership of exact Builder-held attacker files."""

    try:
        root = (
            transient_config_path.parent.parent / ".private-attacker-artifacts"
        ).resolve(strict=True)
    except OSError:
        return
    candidates: list[str] = []
    for config in configs.values():
        for field in ("response_artifact", "replay_artifact"):
            value = config.get(field)
            if isinstance(value, str):
                candidates.append(value)
        pairs = config.get("seed_pairs")
        if isinstance(pairs, list):
            for pair in pairs:
                if (
                    isinstance(pair, list)
                    and len(pair) == 2
                    and isinstance(pair[1], str)
                ):
                    candidates.append(pair[1])
    identities: list[tuple[Path, int, int, int, int]] = []
    filename = re.compile(
        r"selected-(?:(?:t3mp3st|harmbench)-artifact|"
        r"ideator-image-[0-9]{4})-[0-9a-f]{24}-[0-9a-f]{16}\.json"
    )
    for raw in dict.fromkeys(candidates):
        unresolved = Path(raw).expanduser()
        try:
            if unresolved.is_symlink() or unresolved.is_junction():
                continue
            path = unresolved.resolve(strict=True)
            opened = path.lstat()
        except OSError:
            continue
        if (
            path.parent != root
            or filename.fullmatch(path.name) is None
            or not stat.S_ISREG(opened.st_mode)
        ):
            continue
        identities.append((
            path,
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_size,
        ))
    if identities:
        atexit.register(
            _cleanup_transient_attacker_artifacts,
            tuple(identities),
        )


def _load_engine_runtime_config(
    path_value: str,
    selected_attackers: list[str],
    expected_sha256: str = "",
) -> tuple[EngineRuntimeSelection | None, dict[str, object] | None]:
    """Load private venv locators and return only their path-free projection."""

    if bool(path_value) != bool(expected_sha256):
        raise ValueError(
            "--engine-runtime-config and --engine-runtime-config-sha256 "
            "must be provided together"
        )
    required = sorted(
        set(name.strip().lower() for name in selected_attackers)
        & RUNTIME_REQUIRED_ATTACKERS
    )
    loaded = _read_optional_bound_config(
        path_value,
        expected_sha256,
        flag_name="--engine-runtime-config",
        transient_environment="URA_PRIVATE_TRANSIENT_ENGINE_RUNTIME_CONFIG",
        transient_directory=".private-engine-runtime-configs",
        transient_prefix="engine-runtime",
        max_bytes=4 * 1024 * 1024,
    )
    if loaded is None:
        if required:
            raise ValueError(
                "selected third-party attackers require --engine-runtime-config "
                "and --engine-runtime-config-sha256: " + ", ".join(required)
            )
        return None, None
    raw, _path, size, observed_sha256, _transient = loaded
    selection = parse_engine_runtime_config(
        raw, selected_attackers=selected_attackers
    )
    projection = selection.identity_descriptor()
    return selection, {
        "file": f"private-engine-runtime-config@sha256:{observed_sha256}",
        "sha256": observed_sha256,
        "bytes": size,
        "normalized_selected_sha256": _sha256_json(projection),
    }


def _load_api_config(
    path_value: str,
    selected_specs: list[str],
    expected_sha256: str = "",
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load exact, credential-free execution conditions for generic API targets."""

    required_specs = [
        spec for spec in selected_specs if api_target_requires_config(spec)
    ]
    if expected_sha256 and not path_value:
        raise ValueError(
            "--api-config and --api-config-sha256 must be provided together"
        )
    if not path_value:
        if required_specs:
            raise ValueError(
                "measured generic API targets and judges require --api-config "
                "containing each exact selected spec"
            )
        return {}, None

    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError("--api-config must be a regular non-symlink JSON file")
    path = unresolved.resolve(strict=True)
    size = path.stat().st_size
    if not path.is_file() or path.is_symlink() or size <= 0 or size > 1024 * 1024:
        raise ValueError("--api-config must be a regular <=1 MiB JSON file")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError("--api-config changed while it was read")
    observed_sha256 = hashlib.sha256(raw).hexdigest()
    transient_marker = os.environ.pop("URA_PRIVATE_TRANSIENT_API_CONFIG", "").strip()
    transient = False
    if transient_marker:
        if not expected_sha256:
            raise ValueError(
                "private transient API config requires --api-config-sha256"
            )
        try:
            marked_path = Path(transient_marker).expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("private transient API config marker is invalid") from exc
        if (
            marked_path != path
            or path.parent.name != ".private-api-configs"
            or re.fullmatch(
                r"selected-api-[0-9a-f]{24}-[0-9a-f]{16}\.json", path.name
            ) is None
        ):
            raise ValueError(
                "private transient API config marker does not match the selected config"
            )
        try:
            path.unlink()
        except OSError as exc:
            raise ValueError(
                "private transient API config could not be removed after startup read"
            ) from exc
        transient = True
    if expected_sha256:
        if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
            raise ValueError("--api-config-sha256 must be exactly 64 lowercase hex")
        if not secrets.compare_digest(observed_sha256, expected_sha256):
            raise ValueError("--api-config-sha256 does not match the read config bytes")
    try:
        value = _json_loads_strict(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid --api-config JSON: {exc}") from exc
    if not isinstance(value, dict) or not set(required_specs).issubset(value):
        missing = sorted(set(required_specs) - set(value if isinstance(value, dict) else {}))
        raise ValueError(
            "--api-config is missing selected generic API target/judge specs: "
            + ", ".join(missing)
        )

    normalized: dict[str, dict[str, object]] = {}
    for spec in required_specs:
        config = value[spec]
        if not isinstance(config, dict):
            raise ValueError(f"API config {spec!r} must be a JSON object")
        normalized[spec] = normalize_api_target_config(spec, config)
    return normalized, {
        "file": (
            f"private-api-config@sha256:{observed_sha256}"
            if transient
            else path.name
        ),
        "sha256": observed_sha256,
        "bytes": size,
        "normalized_selected_sha256": _sha256_json(normalized),
    }


_SOURCE_CONFIG_FIELDS = frozenset({
    "converter", "path_env", "synth", "source_label", "split",
})
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _default_source_instance(arm_id: str) -> dict[str, object]:
    """Return the backward-compatible source mapping for one corpus arm."""

    if arm_id == "synth":
        return {
            "converter": "synth",
            "synth": True,
        }
    return {
        "converter": arm_id,
        "synth": False,
        "path_env": f"URA_{arm_id.upper()}_PATH",
        "path_env_required": False,
        "default_relative_path": f"datasets/samples/{arm_id}.jsonl",
    }


def _load_source_config(
    path_value: str,
    selected_arms: list[str],
    expected_sha256: str = "",
) -> tuple[dict[str, dict[str, object]], dict[str, object] | None]:
    """Load logical source arms without persisting checkout-specific paths.

    A configured real source names an environment variable containing its path;
    the environment variable's value is deliberately never copied into an
    artifact. Unconfigured converter-name arms retain the historical
    ``URA_<CONVERTER>_PATH`` or ``datasets/samples/<converter>.jsonl`` behavior.
    """

    raw_configs: dict[str, object] = {}
    artifact: dict[str, object] | None = None
    loaded = _read_optional_bound_config(
        path_value,
        expected_sha256,
        flag_name="--source-config",
        transient_environment="URA_PRIVATE_TRANSIENT_SOURCE_CONFIG",
        transient_directory=".private-source-configs",
        transient_prefix="source",
    )
    if loaded is not None:
        raw, path, size, observed_sha256, transient = loaded
        try:
            value = _json_loads_strict(raw.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid --source-config JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValueError("--source-config must be an object keyed by corpus arm id")
        raw_configs = value
        artifact = {
            "file": (
                f"private-source-config@sha256:{observed_sha256}"
                if transient
                else path.name
            ),
            "sha256": observed_sha256,
            "bytes": size,
        }

    for raw_arm in raw_configs:
        if (
            not isinstance(raw_arm, str)
            or not raw_arm.strip()
            or raw_arm != raw_arm.strip()
            or "," in raw_arm
        ):
            raise ValueError(
                "source config arm ids must be non-blank, unpadded strings "
                "without commas"
            )
    normalized: dict[str, dict[str, object]] = {}
    for arm_id in selected_arms:
        if arm_id not in raw_configs:
            if arm_id == "synth":
                normalized[arm_id] = _default_source_instance(arm_id)
                continue
            raise ValueError(
                f"real source arm {arm_id!r} requires an explicit "
                "--source-config entry"
            )
        raw_config = raw_configs[arm_id]
        if not isinstance(raw_config, dict):
            raise ValueError(f"source config {arm_id!r} must be an object")
        unknown = sorted(set(raw_config) - _SOURCE_CONFIG_FIELDS)
        if unknown:
            raise ValueError(
                f"source config {arm_id!r} contains unsupported fields: "
                + ", ".join(unknown)
            )
        converter = raw_config.get("converter")
        if not isinstance(converter, str) or not converter.strip():
            raise ValueError(
                f"source config {arm_id!r} requires a non-blank converter"
            )
        converter = converter.strip().lower()
        synth = raw_config.get("synth", False)
        if not isinstance(synth, bool):
            raise ValueError(f"source config {arm_id!r} synth marker must be boolean")
        if arm_id != "synth" and (converter == "synth" or synth):
            raise ValueError(
                f"real source arm {arm_id!r} cannot be reclassified as synthetic; "
                "use the literal 'synth' arm"
            )
        if arm_id == "synth" and (converter != "synth" or synth is not True):
            raise ValueError(
                "literal 'synth' arm requires converter='synth' and synth=true"
            )
        if converter == "synth":
            if synth is not True or "path_env" in raw_config:
                raise ValueError(
                    f"synthetic source config {arm_id!r} requires synth=true and "
                    "forbids path_env"
                )
        else:
            if synth or "path_env" not in raw_config:
                raise ValueError(
                    f"real source config {arm_id!r} requires path_env and forbids "
                    "synth=true"
                )
            path_env = raw_config["path_env"]
            if not isinstance(path_env, str) or _ENV_NAME.fullmatch(path_env) is None:
                raise ValueError(
                    f"source config {arm_id!r} path_env must be an environment "
                    "variable name"
                )
            # Validate the converter now, while CLI configuration errors can
            # still stop the whole grid before any target construction.
            get_converter(converter)

        item: dict[str, object] = {
            "converter": converter,
            "synth": synth,
        }
        if converter != "synth":
            item.update({
                "path_env": raw_config["path_env"],
                "path_env_required": True,
            })
        for field in ("source_label", "split"):
            optional = raw_config.get(field)
            if optional is not None:
                if not isinstance(optional, str) or not optional.strip():
                    raise ValueError(
                        f"source config {arm_id!r} {field} must be a non-blank string"
                    )
                item[field] = optional.strip()
        normalized[arm_id] = item

    if artifact is not None:
        artifact["normalized_selected_sha256"] = _sha256_json(normalized)
    return normalized, artifact


def _selected_config_artifact_identity(
    artifact: dict[str, object] | None,
) -> dict[str, str] | None:
    """Return only the selected execution subset's content identity.

    Reusable API/source registries may contain entries for other experiment
    lanes.  Their full file hash is useful acquisition provenance, but an edit
    to an unselected entry must not invalidate this grid or repeat paid calls.
    The normalized selected configuration is already persisted separately and
    is the only artifact digest admitted to execution identity.
    """

    if artifact is None:
        return None
    digest = artifact.get("normalized_selected_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("selected config artifact identity requires a SHA-256 digest")
    return {"normalized_selected_sha256": digest}


def _content_artifact_identity(
    artifact: dict[str, object] | None,
) -> dict[str, object] | None:
    """Return the exact byte identity of one standalone bound artifact."""

    if artifact is None:
        return None
    digest = artifact.get("sha256")
    size = artifact.get("bytes")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size <= 0
    ):
        raise ValueError("content artifact identity requires exact SHA-256 and bytes")
    return {"bytes": size, "sha256": digest}


def _record_executed_modality_evidence(
    target_name: str,
    attempts: list[Attempt],
    responses: list[Response],
    destination: dict[str, set[tuple[str, str, tuple[str, ...]]]],
) -> None:
    """Record every contract-verified combination that reached the base target."""
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
        planned_input = attempt.params.get("planned_target_input")
        if not isinstance(planned_input, dict):
            raise ValueError("modality evidence lacks planned target-input binding")
        combination = planned_input.get("combination")
        if not isinstance(combination, list):
            raise ValueError("modality evidence has an invalid target combination")
        if not input_blocked:
            destination[target_name].add((
                attempt.attacker,
                attempt.datapoint_id,
                tuple(str(item) for item in combination),
            ))


def _load_local_config(
    path_value: str,
    selected_specs: list[str],
    *,
    quantization: str = "",
    hardware: dict[str, object] | None = None,
    expected_sha256: str = "",
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
    unresolved_path = Path(path_value).expanduser()
    if unresolved_path.is_symlink():
        raise ValueError("--local-config must be a regular <=1 MiB JSON file")
    path = unresolved_path.resolve(strict=True)
    size = path.stat().st_size
    if not path.is_file() or size <= 0 or size > 1024 * 1024:
        raise ValueError("--local-config must be a regular <=1 MiB JSON file")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError("--local-config changed while it was read")
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    transient_marker = os.environ.pop(
        "URA_PRIVATE_TRANSIENT_LOCAL_CONFIG", ""
    ).strip()
    if transient_marker:
        if not expected_sha256:
            raise ValueError(
                "private transient local config requires --local-config-sha256"
            )
        try:
            marked_path = Path(transient_marker).expanduser().resolve(strict=True)
        except OSError as exc:
            raise ValueError("private transient local config marker is invalid") from exc
        if (
            marked_path != path
            or path.parent.name
            not in {"generated-local-configs", ".private-local-configs"}
            or re.fullmatch(
                r"selected-[0-9a-f]{24}(?:-[0-9a-f]{16})?\.json",
                path.name,
            )
            is None
        ):
            raise ValueError(
                "private transient local config marker does not match the "
                "generated selected config"
            )
        try:
            path.unlink()
        except OSError as exc:
            raise ValueError(
                "private transient local config could not be removed after startup read"
            ) from exc
    if expected_sha256:
        if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
            raise ValueError("--local-config-sha256 must be exactly 64 lowercase hex")
        if not secrets.compare_digest(raw_sha256, expected_sha256):
            raise ValueError("--local-config-sha256 does not match the read config bytes")
    try:
        value = _json_loads_strict(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("--local-config must be UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != set(selected_specs):
        raise ValueError(
            "--local-config keys must exactly match the selected --local specs"
        )
    normalized: dict[str, dict[str, object]] = {}
    for spec in selected_specs:
        config = value[spec]
        display_spec = spec
        if isinstance(config, dict) and spec.startswith("vllm:"):
            from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

            runtime_model = spec.split(":", 1)[1]
            if _is_explicit_local_path(runtime_model):
                configured_digest = config.get("digest")
                if isinstance(configured_digest, str) and re.fullmatch(
                    r"[0-9a-fA-F]{64}", configured_digest
                ):
                    display_spec = (
                        "vllm:local-checkpoint@sha256:"
                        + configured_digest.lower()
                    )
                else:
                    display_spec = _prematerialization_target_key(spec)
        if not isinstance(config, dict) or set(config) - {
            "revision", "digest", "modalities", "tensor_parallel_size",
            "gpu_memory_utilization", "max_tokens", "max_model_len",
            "num_ctx", "num_predict", "think",
            "parameter_count_b",
            "multi_gpu_compatible", "quantization", "allow_unknown_fit",
        }:
            raise ValueError(
                f"local config {display_spec!r} contains unsupported execution fields"
            )
        modalities = config.get("modalities")
        if (
            not isinstance(modalities, list)
            or not modalities
            or any(
                not isinstance(item, str) or item not in {"text", "image"}
                for item in modalities
            )
            or "text" not in modalities
            or len(set(modalities)) != len(modalities)
        ):
            raise ValueError(
                f"local config {display_spec!r} requires unique declared text[/image] modalities"
            )
        backend = spec.split(":", 1)[0].lower()
        config = dict(config)
        revision = config.get("revision")
        digest = config.get("digest")
        if isinstance(revision, str):
            revision = revision.lower()
            config["revision"] = revision
        if isinstance(digest, str):
            digest = digest.lower()
            config["digest"] = digest
        if backend == "vllm":
            from ura.targets.local import (  # noqa: PLC0415
                VLLM_FORBIDDEN_LOCAL_CONFIG_FIELDS,
            )

            forbidden = sorted(set(config) & VLLM_FORBIDDEN_LOCAL_CONFIG_FIELDS)
            if forbidden:
                raise ValueError(
                    f"vLLM config {display_spec!r} forbids Ollama fields: "
                    + ", ".join(forbidden)
                )
            if bool(revision) == bool(digest):
                raise ValueError(
                    f"vLLM config {display_spec!r} requires exactly one revision or digest"
                )
            tensor_parallel_size = config.get("tensor_parallel_size")
            if (
                isinstance(tensor_parallel_size, bool)
                or tensor_parallel_size not in {None, "auto", 1, 2}
            ):
                raise ValueError(
                    f"vLLM config {display_spec!r} requires tensor_parallel_size auto, 1, or 2"
                )
            utilization = config.get("gpu_memory_utilization", 0.90)
            if (
                isinstance(utilization, bool)
                or not isinstance(utilization, (int, float))
                or not 0.1 <= float(utilization) <= 0.95
            ):
                raise ValueError(
                    f"vLLM config {display_spec!r} gpu_memory_utilization must be in [0.1, 0.95]"
                )
            from ura.targets.local import (  # noqa: PLC0415
                DEFAULT_VLLM_GENERATION_TOKENS,
                validate_vllm_max_model_len,
                validate_vllm_max_tokens,
            )

            max_tokens = DEFAULT_VLLM_GENERATION_TOKENS
            if "max_tokens" in config:
                try:
                    max_tokens = validate_vllm_max_tokens(config["max_tokens"])
                except ValueError as exc:
                    raise ValueError(f"vLLM config {display_spec!r} {exc}") from exc
                config["max_tokens"] = max_tokens
            if "max_model_len" in config:
                try:
                    max_model_len = validate_vllm_max_model_len(
                        config["max_model_len"]
                    )
                except ValueError as exc:
                    raise ValueError(f"vLLM config {display_spec!r} {exc}") from exc
                if max_tokens is not None and max_tokens > max_model_len:
                    raise ValueError(
                        f"vLLM config {display_spec!r} max_tokens must not exceed "
                        "max_model_len"
                    )
            allow_unknown_fit = config.get("allow_unknown_fit", False)
            if not isinstance(allow_unknown_fit, bool):
                raise ValueError(
                    f"vLLM config {display_spec!r} allow_unknown_fit must be boolean"
                )
            explicit_quantization = config.get("quantization")
            if allow_unknown_fit and explicit_quantization not in {
                "none", "fp8", "bitsandbytes", "awq", "gptq",
            }:
                raise ValueError(
                    f"vLLM config {display_spec!r} allow_unknown_fit requires an "
                    "explicit per-model quantization"
                )
            from experiments.local_targets import (  # noqa: PLC0415
                detect_gpu_hardware, installed_vllm_version,
                model_hardware_profile,
                tensor_parallel_capacity_gib,
            )
            selected_hardware = (
                hardware if hardware is not None else detect_gpu_hardware()
            )
            try:
                profile = model_hardware_profile(
                    spec,
                    config,
                    selected_hardware,
                    default_quantization=quantization,
                    runtime_version=installed_vllm_version(),
                )
            except (OSError, TypeError, ValueError) as exc:
                safe_message = str(exc).replace(spec, display_spec)
                safe_message = safe_message.replace(
                    spec.split(":", 1)[1], display_spec.split(":", 1)[1]
                )
                raise ValueError(
                    f"vLLM config {display_spec!r} {safe_message}"
                ) from exc
            config["parameter_count_b"] = profile["parameter_count_b"]
            config["multi_gpu_compatible"] = profile["multi_gpu_compatible"]
            config["multi_gpu_support_basis"] = profile["multi_gpu_support_basis"]
            # Exact resolved value for this selected model, never an "auto" token.
            config["quantization"] = profile["recommended_quantization"]
            resolved_tp = (
                int(profile["recommended_tensor_parallel_size"])
                if tensor_parallel_size in {None, "auto"}
                else int(tensor_parallel_size)
            )
            if resolved_tp > 1 and profile["multi_gpu_compatible"] is False:
                raise ValueError(
                    f"vLLM config {display_spec!r} declares multi_gpu_compatible false "
                    "but requests tensor_parallel_size > 1"
                )
            if selected_hardware.get("available"):
                gpu_count = int(selected_hardware.get("gpu_count", 0) or 0)
                if resolved_tp > gpu_count:
                    raise ValueError(
                        f"vLLM config {display_spec!r} requests tensor_parallel_size "
                        f"{resolved_tp} but only {gpu_count} GPU(s) were detected"
                    )
                if profile["fits"] is False:
                    note = str(profile.get("compatibility_note") or "estimated VRAM exceeds available VRAM")
                    raise ValueError(
                        f"vLLM config {display_spec!r} does not fit: {note}"
                    )
                estimated = profile.get("estimated_vram_gib")
                tp_capacity = tensor_parallel_capacity_gib(
                    selected_hardware, float(utilization), resolved_tp
                )
                if isinstance(estimated, (int, float)) and (
                    tp_capacity is None or float(estimated) > tp_capacity
                ):
                    raise ValueError(
                        f"vLLM config {display_spec!r} tensor_parallel_size {resolved_tp} "
                        "cannot fit its estimated VRAM across the detected cards"
                    )
            config["tensor_parallel_size"] = resolved_tp
        elif backend == "ollama":
            from ura.targets.local import (  # noqa: PLC0415
                DEFAULT_OLLAMA_NUM_CTX,
                DEFAULT_OLLAMA_NUM_PREDICT,
                OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS,
                validate_ollama_num_ctx,
                validate_ollama_num_predict,
                validate_ollama_think,
            )

            if (
                set(config) & OLLAMA_FORBIDDEN_LOCAL_CONFIG_FIELDS
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError(
                    f"Ollama config {spec!r} requires digest and forbids vLLM fields"
                )
            unsupported = sorted(
                set(config) - {
                    "digest", "modalities", "num_ctx", "num_predict", "think"
                }
            )
            if unsupported:
                raise ValueError(
                    f"Ollama config {spec!r} contains unsupported fields: "
                    + ", ".join(unsupported)
                )
            try:
                config["num_ctx"] = validate_ollama_num_ctx(
                    config.get("num_ctx", DEFAULT_OLLAMA_NUM_CTX)
                )
                config["num_predict"] = validate_ollama_num_predict(
                    config.get("num_predict", DEFAULT_OLLAMA_NUM_PREDICT)
                )
                config["think"] = validate_ollama_think(
                    config.get("think", False)
                )
            except ValueError as exc:
                raise ValueError(f"Ollama config {spec!r} {exc}") from exc
        else:
            raise ValueError(f"unsupported local backend in {spec!r}")
        normalized[spec] = dict(config)
    ollama_specs = [spec for spec in normalized if spec.startswith("ollama:")]
    if ollama_specs:
        # Re-query under the shared inference/mutation lock at Runner
        # admission. Builder materialization is useful UX, never authority:
        # a pulled tag, digest, capabilities, or modalities can change after
        # preview. Ollama and vLLM are independent execution conditions, so a
        # family resemblance never excludes an installed Ollama model.
        from experiments.rig_web_app.ollama_service import (  # noqa: PLC0415
            OllamaService,
        )

        live = OllamaService(Path.cwd()).roster({}, force=True)
        if live.get("available") is not True:
            raise ValueError(
                "Runner Ollama admission requires a current exact live roster: "
                + str(live.get("error") or "discovery unavailable")
            )
        candidates: dict[str, dict[str, object]] = {}
        rows = live.get("models")
        if not isinstance(rows, list):
            raise ValueError("Runner Ollama live roster is malformed")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("Runner Ollama live roster row is malformed")
            live_spec = row.get("spec")
            if (
                not isinstance(live_spec, str)
                or not live_spec.startswith("ollama:")
                or live_spec in candidates
            ):
                raise ValueError("Runner Ollama live roster identity is ambiguous")
            candidates[live_spec] = row
        for spec in ollama_specs:
            row = candidates.get(spec)
            if row is None:
                raise ValueError(
                    f"Ollama config {spec!r} is absent from the current exact live roster"
                )
            if (
                row.get("digest") != normalized[spec].get("digest")
                or row.get("modalities") != normalized[spec].get("modalities")
            ):
                raise ValueError(
                    f"Ollama config {spec!r} digest/modalities do not match current "
                    "live Runner admission"
                )
    durable_normalized: list[dict[str, object]] = []
    seen_local_conditions: set[tuple[str, str]] = set()
    for spec, config in sorted(normalized.items()):
        persisted_spec = _persisted_model_spec(spec, config)
        condition_config = {
            key: value
            for key, value in config.items()
            if key not in {"revision", "digest"}
        }
        condition_sha256 = _sha256_json(condition_config)
        key = (persisted_spec, condition_sha256)
        if key in seen_local_conditions:
            raise ValueError(
                "local configs collapse to a duplicate content identity and "
                "execution condition"
            )
        seen_local_conditions.add(key)
        durable_normalized.append({
            "model_spec": persisted_spec,
            "execution_condition_sha256": condition_sha256,
            "config": config,
        })
    return normalized, {
        "file": path.name,
        "sha256": raw_sha256,
        "bytes": size,
        "normalized_selected_sha256": _sha256_json(durable_normalized),
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


def _manifest_engine_runtime_identity(
    run_config: object,
) -> dict[str, object] | None:
    """Return one cell's immutable engine identity, or ``None`` for replay."""

    if not isinstance(run_config, dict):
        raise ValueError("manifest run configuration is invalid")
    value = run_config.get("engine_runtime")
    if not isinstance(value, dict):
        raise ValueError("manifest lacks engine-runtime disposition")
    if value.get("schema") == "ura-engine-runtime-not-required/1":
        if set(value) != {"schema", "framework_execution"} or value.get(
            "framework_execution"
        ) not in {None, "not_invoked"}:
            raise ValueError("manifest engine-runtime replay disposition is invalid")
        return None
    return validate_engine_runtime_identity_descriptor(value)


def _validate_completion_engine_runtime_close(
    marker: dict[str, object],
    run_config: object,
    *,
    allow_pending: bool = False,
) -> dict[str, object] | None:
    """Bind a runtime-backed completion to its verified closing observation."""

    identity = _manifest_engine_runtime_identity(run_config)
    close_value = marker.get("engine_runtime_close")
    if identity is None:
        if close_value is not None:
            raise ValueError(
                "completion marker has unexpected engine-runtime closing evidence"
            )
        return None
    if close_value is None and allow_pending:
        return None
    close = validate_engine_runtime_execution_descriptor(
        close_value, required_status="closed_verified"
    )
    if engine_runtime_identity_descriptor(close) != identity:
        raise ValueError(
            "completion marker engine-runtime closing identity differs from manifest"
        )
    return close


def _closed_runtime_descriptor_for_engine(
    selection: object,
    engine: str,
) -> dict[str, object]:
    closed = validate_engine_runtime_selection_descriptor(
        selection, required_status="closed_verified"
    )
    matches = [
        item for item in closed["runtimes"]
        if item["receipt"]["engine"] == engine
    ]
    if len(matches) != 1:
        raise ValueError(
            f"engine runtime closing selection does not contain exactly one {engine!r}"
        )
    return matches[0]


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
        manifest = RunManifest.model_validate(
            _json_loads_strict(manifest_path.read_text(encoding="utf-8")),
            strict=True,
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
        _validate_completion_engine_runtime_close(marker, run_config)
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


def _completed_scored_population_is_admissible(
    attempts: list[Attempt],
    responses: list[Response],
    judgments: list[Judgment],
    results: list[EvalResult],
) -> bool:
    """Admit scored cells, including an exact all-nonresponse population."""

    if not attempts or not responses or not judgments:
        return False
    if results:
        return True
    attempt_ids = [row.id for row in attempts]
    response_by_attempt = {row.attempt_id: row for row in responses}
    if (
        len(response_by_attempt) != len(responses)
        or Counter(attempt_ids) != Counter(response_by_attempt.keys())
        or Counter(attempt_ids) != Counter(row.attempt_id for row in judgments)
    ):
        return False
    for judgment in judgments:
        raw = judgment.raw
        response = response_by_attempt[judgment.attempt_id]
        confidence = raw.get("confidence")
        metric_binding = (
            raw.get("common_metrics_eligible") is True
            and raw.get("required_metric") is None
        ) or (
            raw.get("common_metrics_eligible") is False
            and isinstance(raw.get("required_metric"), str)
            and bool(raw["required_metric"].strip())
        )
        if not (
            judgment.label == "not_applicable"
            and judgment.score == 0.0
            and raw.get("policy_evaluable_turn") is True
            and metric_binding
            and raw.get("stage_queried") is False
            and raw.get("policy_evaluation_status") == "model_nonresponse"
            and isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and float(confidence) == 1.0
            and raw.get("parsed") is None
            and raw.get("cascade_role") == "authoritative"
            and raw.get("cascade_confident") is True
            and raw.get("metric_authority") is None
            and response.output_turns == []
            and response.raw.get("empty_completion_observed") is True
        ):
            return False
    return True


def _validate_completion_marker(
    paths: dict[str, Path],
    planned: RunManifest,
    required: tuple[str, ...],
    grid_acquisition: dict[str, object],
    *,
    allow_pending_engine_runtime_close: bool = False,
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

    manifest = RunManifest.model_validate(
        _json_loads_strict(paths["manifest"].read_text(encoding="utf-8")),
        strict=True,
    )
    if manifest.run_id != planned.run_id:
        raise ValueError("stored manifest run_id differs from planned cell")
    if manifest.code_version != CODE_VERSION or manifest.schema_version != SCHEMA_VERSION:
        raise ValueError("stored manifest code/schema version is stale")
    planned_run_config = planned.config.get("run")
    stored_run_config = manifest.config.get("run")
    if not isinstance(planned_run_config, dict) or not isinstance(
        stored_run_config, dict
    ):
        raise ValueError("completion manifest lacks run configuration")
    planned_acquisition = validate_model_acquisition_role_projection(
        planned_run_config.get("model_acquisition")
    )
    stored_acquisition = validate_model_acquisition_role_projection(
        stored_run_config.get("model_acquisition")
    )
    if stored_acquisition != planned_acquisition:
        raise ValueError("stored model acquisition evidence differs from plan")
    _validate_completion_engine_runtime_close(
        marker,
        stored_run_config,
        allow_pending=allow_pending_engine_runtime_close,
    )
    validate_model_acquisition_role_projection_binding(
        stored_acquisition,
        grid_acquisition,
        run_config=stored_run_config,
    )
    if marker.get("call_budget_snapshot") != manifest.config.get(
        "call_budget_snapshot"
    ):
        raise ValueError("completion marker call-budget snapshot mismatch")

    attempt_rows = _read_jsonl(paths["attempts"])
    response_rows = _read_jsonl(paths["responses"])
    judgment_rows = _read_jsonl(paths["judgments"])
    trails = _read_jsonl(paths["trails"])
    result_rows = _read_jsonl(paths["results"])
    attempts = [Attempt.model_validate(row, strict=True) for row in attempt_rows]
    responses = [Response.model_validate(row, strict=True) for row in response_rows]
    judgments = [Judgment.model_validate(row, strict=True) for row in judgment_rows]
    results = [EvalResult.model_validate(row, strict=True) for row in result_rows]
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
    if not _completed_scored_population_is_admissible(
        attempts, responses, judgments, results
    ):
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
        "attacker_input_plan", "attacker_input_plan_sha256",
        "n_attacker_input_contracts",
    ):
        if manifest.config.get(key) != planned.config.get(key):
            raise ValueError(f"stored manifest config field {key!r} changed")
    for label, candidate in (("planned", planned), ("stored", manifest)):
        plan = candidate.config.get("attacker_input_plan")
        digest = candidate.config.get("attacker_input_plan_sha256")
        count = candidate.config.get("n_attacker_input_contracts")
        try:
            contracts = deserialize_attacker_input_plan(
                plan,
                expected_sha256=digest if isinstance(digest, str) else None,
            )
        except AttackerInputContractError as exc:
            raise ValueError(
                f"{label} manifest attacker input plan is invalid"
            ) from exc
        if (
            not isinstance(digest, str)
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count != len(contracts)
            or any(len(key) != 3 for key in contracts)
        ):
            raise ValueError(
                f"{label} manifest attacker input plan count/schema mismatch"
            )
    try:
        validate_attempts_against_attacker_input_plan(
            manifest.config["attacker_input_plan"],
            attempts,
            responses,
            judgments,
            target_modalities=target_modality_support_from_component_config(
                manifest.config["components"]["target"]
            ),
            expected_sha256=manifest.config["attacker_input_plan_sha256"],
            expected_count=manifest.config["n_attacker_input_contracts"],
        )
    except AttackerInputContractError as exc:
        raise ValueError(
            "completed execution differs from the stored attacker input plan"
        ) from exc
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
    reconstructed_policies = [_json_loads_strict(item) for item in policy_inventory]
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
    # Mirror the writer's two-rule accounting (_realized_source_metric_inventory):
    # n_source_evaluations counts EVERY source-evaluation observation, including
    # diagnostic implemented:False ones for sources whose official evaluator is
    # not executed (for example MM-SafetyBench), while emitted requires at least
    # one implemented observation.
    realized_source_metric_counts: dict[tuple[str, str], int] = {}
    realized_source_metric_implemented: set[tuple[str, str]] = set()
    for judgment in judgments:
        observation = judgment.raw.get("source_evaluation")
        if not isinstance(observation, dict):
            continue
        key = (
            str(judgment.raw.get("source", "")),
            str(observation.get("family", "")),
        )
        realized_source_metric_counts[key] = (
            realized_source_metric_counts.get(key, 0) + 1
        )
        if observation.get("implemented") is True:
            realized_source_metric_implemented.add(key)
    for entry in source_metric_inventory:
        if not isinstance(entry, dict):
            raise ValueError("source-metric inventory entries must be objects")
        key = (str(entry.get("source")), str(entry.get("required_metric")))
        emitted = key in realized_source_metric_implemented
        if entry.get("source_metric_emitted") is not emitted:
            raise ValueError("stored source-metric emitted status mismatch")
        if entry.get("n_source_evaluations") != realized_source_metric_counts.get(key, 0):
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
    validate_persisted_judgment_trails(
        {row.id: row for row in attempts},
        {row.attempt_id: row for row in responses},
        {row.attempt_id: row for row in judgments},
        trails,
        planned.config,
        planned.judges,
    )
    planned_run = planned.config.get("run")
    planned_components = planned.config.get("components")
    if not isinstance(planned_run, dict) or not isinstance(
        planned_components, dict
    ):
        raise ValueError("planned manifest lacks identity-bearing run/components")
    validate_planned_realized_identities(
        planned_run,
        planned_components,
        responses,
        trails,
        identity_summary,
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
    sampling audit. This separate digest binds the experiment driver used by a
    completion while omitting mutable tool/cache directories.
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
    api_config: dict[str, object] | None = None,
    model_runtime: ManagedModelRuntime | None = None,
    managed_model_role: str = "vllm_target",
):
    """Resolve a target spec to a :class:`BaseTarget`.

    spec is one of:
      * a registered hosted id (including "mock") or the preferred
        "<provider>:<exact-account-visible-id>" form;
      * a local "<backend>:<model>" - "vllm:Qwen/Qwen3-VL-8B-Instruct",
        "ollama:llama3.3:70b".

    The exact per-model ``quantization``/``dtype`` condition is forwarded to
    vLLM. Empty quantization uses offline hardware-fit resolution and selects
    the highest fitting precision in the order 16-bit, FP8 8-bit, then
    in-flight ``bitsandbytes`` 4-bit; AWQ/GPTQ remain explicit overrides for
    pinned pre-quantized checkpoints.
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
                from ura.targets.local import (
                    DEFAULT_VLLM_GENERATION_TOKENS,
                    VLLMTarget,
                )
                kwargs: dict = {
                    "dtype": dtype,
                    "modality_support": modalities,
                    "revision": local_identity.get("revision"),
                    "model_digest": local_identity.get("digest"),
                    "tensor_parallel_size": local_identity["tensor_parallel_size"],
                    "gpu_memory_utilization": local_identity.get(
                        "gpu_memory_utilization", 0.90
                    ),
                    "max_tokens": local_identity.get(
                        "max_tokens", DEFAULT_VLLM_GENERATION_TOKENS
                    ),
                    "max_model_len": local_identity.get("max_model_len"),
                }
                resolved_quantization = str(
                    local_identity.get("quantization") or quantization
                ).strip().lower()
                if resolved_quantization and resolved_quantization != "none":
                    kwargs["quantization"] = resolved_quantization
                target = VLLMTarget(
                    model=model,
                    model_runtime=model_runtime,
                    managed_model_role=managed_model_role,
                    **kwargs,
                )
                target.validate_research_identity()
                return target
            from ura.targets.local import OllamaTarget
            target = OllamaTarget(
                model=model,
                model_digest=str(local_identity["digest"]),
                modality_support=modalities,
                num_ctx=local_identity["num_ctx"],
                num_predict=int(local_identity["num_predict"]),
                think=local_identity["think"],
            )
            target.validate_research_identity()
            return target
        # provider:model (anthropic/openai/google/gemini)
        return build_api_target(spec, config=api_config)
    # bare id: resolve against the verified hosted/mock registry
    return build_api_target(spec, config=api_config)


def _require_local_hardware_fit(
    target: object,
    spec: str,
    config: dict[str, object],
    hardware: dict[str, object],
) -> None:
    """Require proven fit or an explicit operator-owned unknown-fit override."""

    from ura.targets.local import VLLMTarget  # noqa: PLC0415
    if not isinstance(target, VLLMTarget):
        return
    if not hardware.get("available"):
        raise ValueError(f"local vLLM target {spec!r} requires a detected NVIDIA GPU")
    from experiments.local_targets import (  # noqa: PLC0415
        installed_vllm_version,
        model_hardware_profile,
    )
    profile = model_hardware_profile(
        spec, config, hardware, runtime_version=installed_vllm_version()
    )
    if profile["fits"] is None and config.get("allow_unknown_fit") is True:
        if config.get("quantization") in {
            "none", "fp8", "bitsandbytes", "awq", "gptq",
        }:
            return
    if profile["fits"] is not True:
        reason = str(
            profile.get("compatibility_note")
            or "parameter count/VRAM fit is unknown or insufficient"
        )
        raise ValueError(f"local vLLM target {spec!r} is not admitted: {reason}")


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


def _prematerialization_target_key(spec: str) -> str:
    """Return a request key without persisting an explicit local path.

    Immutable local checkpoint identity is available only after local-config
    loading.  The request envelope necessarily precedes that step, so an
    explicit vLLM path receives an opaque, collision-resistant request key.
    Repository IDs and hosted target specifications are already path-free.
    """

    if ":" not in spec:
        return spec
    backend, model = spec.split(":", 1)
    if backend.lower() != "vllm":
        return spec
    from ura.targets.local import _is_explicit_local_path

    if not _is_explicit_local_path(model):
        return spec
    digest = hashlib.sha256(spec.encode("utf-8")).hexdigest()
    return f"vllm:local-path-request@sha256:{digest}"


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
    candidates: set[str | Path] = {runtime_model}
    try:
        candidates.add(Path(runtime_model).expanduser().resolve(strict=False))
    except (OSError, RuntimeError):
        pass
    return sanitize_private_paths(
        message,
        candidates,
        replacement=logical_model,
    )


def build_judges(
    names: list[str],
    judge_model: str,
    *,
    judge_api_config: dict[str, object] | None = None,
    judge_target: object | None = None,
    guardrail_model: str = "meta-llama/Llama-Guard-3-8B",
    guardrail_revision: str = "",
    guardrail_device: str = "",
    model_runtime: ManagedModelRuntime | None = None,
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
            # A caller may supply one already-validated local or hosted target.
            # Reuse it so a local judge engine is never constructed twice. The
            # fallback retains the standalone hosted/mock helper contract.
            resolved_judge = judge_target or build_api_target(
                judge_model, config=judge_api_config
            )
            stages.append(LLMJudge(judge_target=resolved_judge))
        elif n == "guardrail":
            from ura.judges.guardrail import GuardrailJudge
            stages.append(GuardrailJudge(
                model=guardrail_model,
                revision=guardrail_revision,
                device=guardrail_device or None,
                model_runtime=model_runtime,
                managed_model_role="guardrail_judge",
            ))
        else:
            raise ValueError(f"unknown judge {n!r}")
    return JudgeCascade(stages or [RuleJudge()])


def _attacker_constructor_kwargs(
    name: str,
    configs: dict[str, dict[str, object]],
    model_runtime: ManagedModelRuntime | None,
    engine_runtimes: EngineRuntimeSelection | None = None,
) -> dict[str, object]:
    """Attach private runtime handles without persisting their locators."""

    kwargs = dict(configs.get(name.lower(), {}))
    key = name.lower()
    if key in RUNTIME_REQUIRED_ATTACKERS:
        if engine_runtimes is None:
            raise RuntimeError(
                f"selected third-party attacker {key!r} has no runtime selection"
            )
        kwargs["engine_runtime"] = engine_runtimes.runtime_for(key)
    if key == "nanogcg" and "suffix" not in kwargs:
        # The configuration gate should reject this before any acquisition or
        # component construction.  Keep the constructor boundary independently
        # fail-closed if it is called by another entry point.
        raise RuntimeError(LIVE_NANOGCG_DISABLED_MESSAGE)
    return kwargs


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


def _precall_model_identity(component: object) -> frozenset[tuple[str, ...]]:
    """Independent strong identities for pre-call duplicate/self-judge checks."""

    local_identity = canonical_local_model_identity(
        getattr(component, "model", None),
        revision=getattr(component, "revision", None),
        model_digest=getattr(component, "model_digest", None),
    )
    if local_identity is not None:
        return frozenset({local_identity})
    keys: set[tuple[str, ...]] = set()
    model = str(getattr(component, "model", "")).strip()
    endpoint = getattr(component, "base_url", None)
    if isinstance(endpoint, str) and endpoint.strip() and model:
        keys.add((
            "endpoint-model",
            canonical_https_endpoint_identity(endpoint),
            model,
        ))
    else:
        provider = canonical_provider_name(
            str(getattr(component, "provider", ""))
        )
        if provider and model:
            keys.add(("provider-model", provider, model))
    if not keys:
        keys.add(("runtime-name", str(getattr(component, "name", "")).strip()))
    return frozenset(keys)


def _target_execution_condition_identity(component: object) -> str:
    """Hash effective target knobs separately from immutable/base identity.

    Duplicate target admission combines this value with a strong model/route
    identity.  Consequently two aliases for the same route and condition are
    rejected, while explicit precision, context, decoding, or API-surface
    comparisons remain distinct scientific arms.
    """

    condition = _component_config(component)
    for identity_field in {
        "name",
        "model",
        "provider",
        "requested_spec",
        "revision",
        "model_digest",
        "key_env",
        "base_url",
    }:
        condition.pop(identity_field, None)
    return _sha256_json(condition)


def _pinned_hub_model_identity(model: str, revision: str) -> frozenset[tuple[str, ...]]:
    model = model.strip()
    revision = revision.strip().lower()
    if not model or re.fullmatch(r"[0-9a-f]{40,64}", revision) is None:
        return frozenset()
    return frozenset({("model-revision", model, revision)})


def _project_grid_call_upper_bounds(
    *,
    targets: dict[str, object],
    corpora: dict[str, list[DataPoint]],
    attackers: dict[str, object],
    cascade: JudgeCascade,
    seeds: list[int],
    max_queries: int,
    max_turns: int,
    target_answer_retries: int = 1,
    approximate_common_metrics: bool = False,
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
    local_guardrails_per_evaluable = sum(
        int(getattr(stage, "name", "") == "guardrail")
        for stage in cascade.stages
    )
    judge_http_per_evaluable = sum(
        _declared_transport_attempts(target) for target in model_judges
    )
    by_attacker: dict[str, dict[str, int]] = {}
    total_target = total_judge = total_http = total_trajectories = 0
    total_local_guardrail = 0
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
        attacker_local_guardrail = 0
        for target in targets.values():
            trajectories = sum(len(rows) for rows in corpora.values()) * len(seeds)
            judge_eligible_trajectories = sum(
                sum(
                    int(
                        row.meta.get("common_metrics_eligible", True) is True
                        or approximate_common_metrics
                    )
                    for row in rows
                )
                for rows in corpora.values()
            ) * len(seeds)
            intended_target_calls = trajectories * target_turns
            target_calls = intended_target_calls * (target_answer_retries + 1)
            judge_calls = (
                judge_eligible_trajectories
                * evaluable_turns
                * judge_calls_per_evaluable
            )
            defense_guard = getattr(target, "guard", None)
            defense_mode = getattr(target, "mode", None)
            defense_guardrails_per_target_turn = (
                int(defense_mode in {"input", "both"})
                + int(defense_mode in {"output", "both"})
                if getattr(defense_guard, "name", "") == "guardrail"
                else 0
            )
            local_guardrail_evaluations = (
                judge_eligible_trajectories
                * evaluable_turns
                * local_guardrails_per_evaluable
                + target_calls * defense_guardrails_per_target_turn
            )
            http_attempts = (
                target_calls * _declared_transport_attempts(target)
                + judge_eligible_trajectories
                * evaluable_turns
                * judge_http_per_evaluable
            )
            attacker_trajectories += trajectories
            attacker_target += target_calls
            attacker_judge += judge_calls
            attacker_local_guardrail += local_guardrail_evaluations
            attacker_http += http_attempts
        by_attacker[name] = {
            "trajectories": attacker_trajectories,
            "target_calls": attacker_target,
            "judge_calls": attacker_judge,
            "local_guardrail_evaluations": attacker_local_guardrail,
            "http_attempts": attacker_http,
        }
        total_trajectories += attacker_trajectories
        total_target += attacker_target
        total_judge += attacker_judge
        total_local_guardrail += attacker_local_guardrail
        total_http += attacker_http
    return {
        "semantics": "conservative_complete_grid_upper_bound_v2",
        "target_answer_retries": target_answer_retries,
        "trajectories": total_trajectories,
        "target_calls": total_target,
        "judge_calls": total_judge,
        "local_guardrail_evaluations": total_local_guardrail,
        "http_attempts": total_http,
        "by_attacker": by_attacker,
    }


def _validate_planned_call_budget(
    projection: dict[str, object], *, target: int, judge: int, http: int,
    deadline_seconds: int, dry_run: bool, require_complete: bool,
) -> None:
    """Require every provider-backed request ceiling to cover its full projection."""
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
    sampling_policy: str | None = None,
) -> tuple[list[DataPoint], list[int], list[str], list[str]]:
    """Select exactly ``limit`` prompt/intent clusters, retaining every row."""
    policy = effective_sampling_policy(sampling_policy)
    clusters: dict[str, list[int]] = {}
    for index, record in enumerate(dps):
        clusters.setdefault(_cluster_key(index, record), []).append(index)
    keys = list(clusters)
    if not limit or limit >= len(keys):
        return dps, list(range(len(dps))), keys, keys
    ordered_positions = list(range(len(keys)))
    if policy == DEFAULT_SAMPLING_POLICY:
        seed_material = f"ura-corpus-cluster-order-v1\0{name}\0{sample_seed}".encode(
            "utf-8"
        )
        scoped_seed = int.from_bytes(
            hashlib.sha256(seed_material).digest()[:8], "big"
        )
        # One deterministic permutation supplies every bounded sample for this
        # source/seed. Taking prefixes makes a one-cluster diagnostic canary a
        # true subset of a later N-cluster campaign.
        random.Random(scoped_seed).shuffle(ordered_positions)
    positions = set(ordered_positions[:limit])
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


def _source_instance_path(
    arm_id: str, source_instance: dict[str, object],
) -> Path:
    """Resolve a real source at runtime while keeping the value out of artifacts."""

    path_env = source_instance.get("path_env")
    if not isinstance(path_env, str) or not path_env:
        raise ValueError(f"real source arm {arm_id!r} lacks a path_env locator")
    if source_instance.get("path_env_required") is not True:
        converter = source_instance.get("converter")
        if not isinstance(converter, str) or not converter:
            raise ValueError(f"source arm {arm_id!r} lacks a converter")
        return _corpus_path(converter)
    configured = os.environ.get(path_env)
    if configured is not None and configured.strip():
        return Path(configured)
    raise ValueError(
        f"source arm {arm_id!r} requires non-blank environment variable {path_env}"
    )


def _stable_source_locator(
    name: str,
    source_kind: str | None,
    source_instance: dict[str, object] | None = None,
) -> dict[str, object]:
    """Configuration-level locator with no checkout- or author-specific path."""
    instance = dict(source_instance or _default_source_instance(name))
    converter = str(instance["converter"])
    if instance.get("synth") is True:
        return {
            "corpus": name,
            "converter": converter,
            "configuration_env": None,
            "source_kind": "generated_fixture",
            "required_layout": [],
            "source_label": instance.get("source_label"),
            "split": instance.get("split"),
        }
    release = CORPUS_RELEASE_SPECS.get(converter)
    return {
        "corpus": name,
        "converter": converter,
        "configuration_env": instance.get("path_env"),
        "configuration_env_required": instance.get("path_env_required") is True,
        "default_relative_path": instance.get("default_relative_path"),
        "source_kind": source_kind,
        "required_layout": list(release.required_layout) if release else [],
        "source_label": instance.get("source_label"),
        "split": instance.get("split"),
    }


def load_corpus(
    name: str,
    limit: int,
    sample_seed: int = 0,
    sampling_policy: str | None = None,
) -> list[DataPoint]:
    """Load a corpus and take a deterministic whole-cluster prefix when limited.

    Omission preserves the historical arm-scoped seeded pseudorandom ordering.
    The explicit source-order policy instead takes the first source clusters.
    Selected records retain source order under both policies.
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    effective_sampling_policy(sampling_policy)
    if name == "synth":
        return synth_corpus(12 if limit == 0 else limit)
    conv = get_converter(name)
    # expects data under datasets/<name>.jsonl by default; override via env
    path = _corpus_path(name)
    dps = conv.parse(path)
    selected, _, _, _ = _select_corpus(
        name, dps, limit, sample_seed, sampling_policy
    )
    return selected


def _partition_tool_conditioned(
    selected: list[DataPoint],
    indices: list[int],
    cluster_ids_per_row: list[str],
) -> tuple[list[DataPoint], list[int], list[str], list[str]]:
    """Split a selected sample into executable rows and recorded tool exclusions.

    The parallel ``indices`` and ``cluster_ids_per_row`` are filtered alongside
    the rows so every downstream audit field stays mutually consistent (no row
    re-enumeration that would shift cluster identity).
    """
    kept_rows: list[DataPoint] = []
    kept_indices: list[int] = []
    kept_cluster_ids: list[str] = []
    excluded_ids: list[str] = []
    for row, index, cluster_id in zip(selected, indices, cluster_ids_per_row):
        if is_tool_conditioned_source(row):
            excluded_ids.append(row.id)
        else:
            kept_rows.append(row)
            kept_indices.append(index)
            kept_cluster_ids.append(cluster_id)
    return kept_rows, kept_indices, kept_cluster_ids, excluded_ids


def load_corpus_with_audit(
    name: str,
    limit: int,
    sample_seed: int = 0,
    *,
    sampling_policy: str | None = None,
    source_instance: dict[str, object] | None = None,
    exclude_tool_conditioned: bool = False,
) -> tuple[list[DataPoint], dict[str, object]]:
    """Load one source and retain enough information to audit the selected sample.

    When ``exclude_tool_conditioned`` is set, tool-conditioned rows (which no
    Runner attacker can execute yet) are dropped from the executed sample with a
    recorded ``excluded_tool_conditioned_*`` count, while
    ``full_converted_corpus_sha256`` and ``total_*`` still describe the complete
    selection. This lets the standalone offline smoke run without weakening the
    fail-closed default (which rejects the whole request).
    """
    if limit < 0:
        raise ValueError("limit must be non-negative")
    policy = effective_sampling_policy(sampling_policy)
    instance = dict(source_instance or _default_source_instance(name))
    converter = instance.get("converter")
    if not isinstance(converter, str) or not converter:
        raise ValueError(f"source arm {name!r} lacks a converter")
    if instance.get("synth") is True:
        if converter != "synth":
            raise ValueError(
                f"source arm {name!r} has synth=true but converter={converter!r}"
            )
        full_selected = synth_corpus(12 if limit == 0 else limit)
        cluster_ids = [
            _cluster_key(index, row) for index, row in enumerate(full_selected)
        ]
        full_digest = canonical_converted_corpus_sha256(full_selected)
        selected = full_selected
        selected_indices = list(range(len(full_selected)))
        selected_cluster_ids = list(cluster_ids)
        excluded_ids: list[str] = []
        if exclude_tool_conditioned:
            selected, selected_indices, selected_cluster_ids, excluded_ids = (
                _partition_tool_conditioned(
                    full_selected, list(range(len(full_selected))), cluster_ids
                )
            )
        audit: dict[str, object] = {
            "corpus": name,
            "converter": converter,
            "source_instance": instance,
            "source_locator": _stable_source_locator(
                name, "generated_fixture", instance
            ),
            "full_converted_corpus_sha256": full_digest,
            "selected_converted_corpus_sha256": (
                canonical_converted_corpus_sha256(selected)
            ),
            "total_records": len(full_selected),
            "selected_records": len(selected),
            "selected_indices": selected_indices,
            "selected_ids": [datapoint.id for datapoint in selected],
            "limit_unit": "source_prompt_or_intent_clusters",
            "total_clusters": len(cluster_ids),
            "selected_clusters": len(selected_cluster_ids),
            "total_cluster_ids": cluster_ids,
            "selected_cluster_ids": selected_cluster_ids,
            "excluded_tool_conditioned_ids": excluded_ids,
            "excluded_tool_conditioned_count": len(excluded_ids),
            "sample_seed": sample_seed,
            "limit": limit,
        }
        if sampling_policy is not None:
            audit["sampling_policy"] = policy
        return selected, audit
    if converter == "synth":
        raise ValueError(
            f"source arm {name!r} uses converter='synth' without synth=true"
        )
    path = _source_instance_path(name, instance)
    full = get_converter(converter).parse(path)
    selected, indices, selected_clusters, total_clusters = _select_corpus(
        name,
        full,
        limit,
        sample_seed,
        sampling_policy,
    )
    resolved = path.expanduser().resolve(strict=True)
    full_digest = canonical_converted_corpus_sha256(full)
    full_observation = observed_arm_conformance(full)
    if full_observation["converted_corpus_sha256"] != full_digest:
        raise ValueError("full source observation/corpus digest mismatch")
    excluded_ids = []
    if exclude_tool_conditioned:
        per_row_clusters = [
            _cluster_key(index, row) for index, row in zip(indices, selected)
        ]
        selected, indices, kept_row_clusters, excluded_ids = (
            _partition_tool_conditioned(selected, indices, per_row_clusters)
        )
        surviving = set(kept_row_clusters)
        # preserve the selection order of distinct clusters that still run
        selected_clusters = [key for key in selected_clusters if key in surviving]
    audit = {
        "corpus": name,
        "converter": converter,
        "source_instance": instance,
        "source_locator": _stable_source_locator(
            name, "directory" if resolved.is_dir() else "file", instance
        ),
        "full_converted_corpus_sha256": full_digest,
        "selected_converted_corpus_sha256": (
            canonical_converted_corpus_sha256(selected)
        ),
        "full_source_conformance_observation": full_observation,
        "total_records": len(full),
        "selected_records": len(selected),
        "selected_indices": indices,
        "selected_ids": [datapoint.id for datapoint in selected],
        "limit_unit": "source_prompt_or_intent_clusters",
        "total_clusters": len(total_clusters),
        "selected_clusters": len(selected_clusters),
        "total_cluster_ids": total_clusters,
        "selected_cluster_ids": selected_clusters,
        "excluded_tool_conditioned_ids": excluded_ids,
        "excluded_tool_conditioned_count": len(excluded_ids),
        "sample_seed": sample_seed,
        "limit": limit,
        "selection_method": (
            "seeded_nested_source_cluster_prefix_v1"
            if policy == DEFAULT_SAMPLING_POLICY
            else "source_order_source_cluster_prefix_v1"
        ),
    }
    if sampling_policy is not None:
        audit["sampling_policy"] = policy
    return selected, audit


_RECOVERY_PREFIX_FIELDS = frozenset({
    "schema",
    "corpus",
    "completed_prefix_count",
    "selected_datapoint_ids_sha256",
    "completed_prefix_ids_sha256",
    "remaining_datapoint_ids_sha256",
})
_RECOVERY_MULTI_PREFIX_FIELDS = frozenset({"schema", "corpora"})
_RECOVERY_PREFIX_ENTRY_FIELDS = frozenset({
    "completed_prefix_count",
    "selected_datapoint_ids_sha256",
    "completed_prefix_ids_sha256",
    "remaining_datapoint_ids_sha256",
})
_RECOVERY_MULTI_SELECTION_FIELDS = frozenset({"schema", "corpora"})
_RECOVERY_SELECTION_ENTRY_FIELDS = frozenset({
    "completed_record_count",
    "selected_datapoint_ids_sha256",
    "completed_datapoint_ids",
    "completed_datapoint_ids_sha256",
    "remaining_datapoint_ids_sha256",
})


def _validate_recovery_prefix_entry(
    value: object, *, label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _RECOVERY_PREFIX_ENTRY_FIELDS:
        raise ValueError(f"{label} field inventory changed")
    count = value.get("completed_prefix_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError(f"{label} count must be positive")
    for field in (
        "selected_datapoint_ids_sha256",
        "completed_prefix_ids_sha256",
        "remaining_datapoint_ids_sha256",
    ):
        digest = value.get(field)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"{label} {field} is invalid")
    return value


def _validate_recovery_selection_entry(
    value: object, *, label: str
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _RECOVERY_SELECTION_ENTRY_FIELDS:
        raise ValueError(f"{label} field inventory changed")
    count = value.get("completed_record_count")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError(f"{label} count must be positive")
    completed = value.get("completed_datapoint_ids")
    if (
        not isinstance(completed, list)
        or len(completed) != count
        or any(
            not isinstance(item, str) or not item or item != item.strip()
            for item in completed
        )
        or len(set(completed)) != len(completed)
    ):
        raise ValueError(f"{label} completed datapoint IDs are invalid")
    for field in (
        "selected_datapoint_ids_sha256",
        "completed_datapoint_ids_sha256",
        "remaining_datapoint_ids_sha256",
    ):
        digest = value.get(field)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError(f"{label} {field} is invalid")
    if _sha256_json(completed) != value["completed_datapoint_ids_sha256"]:
        raise ValueError(f"{label} completed datapoint identity changed")
    return value


def load_recovery_completed_prefix(
    path_value: str,
    expected_sha256: str,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Load one exact completed-prefix or completed-ID-set selection."""

    if bool(path_value) != bool(expected_sha256):
        raise ValueError(
            "--recovery-completed-prefix and its SHA-256 must be provided together"
        )
    if not path_value:
        return None, None
    value, artifact = _read_content_addressed_json(
        path_value,
        expected_sha256,
        flag_name="--recovery-completed-prefix",
        max_bytes=1024 * 1024,
    )
    if not isinstance(value, dict):
        raise ValueError("recovery completed-prefix must be one object")
    schema = value.get("schema")
    if schema == "ura-recovery-completed-prefix/1":
        if set(value) != _RECOVERY_PREFIX_FIELDS:
            raise ValueError("recovery completed-prefix field inventory changed")
        corpus = value.get("corpus")
        if not isinstance(corpus, str) or not corpus.strip() or corpus != corpus.strip():
            raise ValueError("recovery completed-prefix corpus is invalid")
        entry = _validate_recovery_prefix_entry(
            {field: value[field] for field in _RECOVERY_PREFIX_ENTRY_FIELDS},
            label="recovery completed-prefix",
        )
        binding = {
            "schema": schema,
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
            "corpus": corpus,
            **entry,
        }
    elif schema == "ura-recovery-completed-prefix/2":
        if set(value) != _RECOVERY_MULTI_PREFIX_FIELDS:
            raise ValueError("recovery multi-prefix field inventory changed")
        corpora = value.get("corpora")
        if not isinstance(corpora, dict) or not corpora:
            raise ValueError("recovery multi-prefix corpus inventory is empty")
        normalized: dict[str, dict[str, object]] = {}
        for corpus, item in corpora.items():
            if (
                not isinstance(corpus, str)
                or not corpus.strip()
                or corpus != corpus.strip()
            ):
                raise ValueError("recovery multi-prefix corpus is invalid")
            normalized[corpus] = dict(
                _validate_recovery_prefix_entry(
                    item,
                    label=f"recovery completed-prefix corpus {corpus}",
                )
            )
        binding = {
            "schema": schema,
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
            "corpora": normalized,
        }
    elif schema == "ura-recovery-completed-selection/1":
        if set(value) != _RECOVERY_MULTI_SELECTION_FIELDS:
            raise ValueError("recovery completed-selection field inventory changed")
        corpora = value.get("corpora")
        if not isinstance(corpora, dict) or not corpora:
            raise ValueError("recovery completed-selection corpus inventory is empty")
        normalized = {}
        for corpus, item in corpora.items():
            if (
                not isinstance(corpus, str)
                or not corpus.strip()
                or corpus != corpus.strip()
            ):
                raise ValueError("recovery completed-selection corpus is invalid")
            normalized[corpus] = dict(
                _validate_recovery_selection_entry(
                    item,
                    label=f"recovery completed-selection corpus {corpus}",
                )
            )
        binding = {
            "schema": schema,
            "sha256": artifact["sha256"],
            "bytes": artifact["bytes"],
            "corpora": normalized,
        }
    else:
        raise ValueError("recovery completed-prefix schema is unsupported")
    return value, binding


def apply_recovery_completed_prefix(
    name: str,
    corpus: list[DataPoint],
    audit: dict[str, object],
    recovery: dict[str, object] | None,
) -> tuple[list[DataPoint], dict[str, object]]:
    """Exclude only an exactly bound durable prefix or completed ID set."""

    if recovery is None:
        return corpus, audit
    schema = recovery.get("schema")
    if schema == "ura-recovery-completed-prefix/1":
        if recovery["corpus"] != name:
            raise ValueError("recovery completed-prefix corpus does not match selection")
        entry = recovery
        audit_recovery = dict(recovery)
    elif schema == "ura-recovery-completed-prefix/2":
        corpora = recovery.get("corpora")
        if not isinstance(corpora, dict) or name not in corpora:
            raise ValueError("recovery multi-prefix corpus does not match selection")
        entry = corpora[name]
        if not isinstance(entry, dict):
            raise ValueError("recovery multi-prefix entry changed")
        audit_recovery = {"schema": schema, "corpus": name, **entry}
        completed_ids: list[str] | None = None
    elif schema == "ura-recovery-completed-selection/1":
        corpora = recovery.get("corpora")
        if not isinstance(corpora, dict) or name not in corpora:
            raise ValueError("recovery completed-selection corpus does not match selection")
        entry = corpora[name]
        if not isinstance(entry, dict):
            raise ValueError("recovery completed-selection entry changed")
        audit_recovery = {"schema": schema, "corpus": name, **entry}
        completed_value = entry.get("completed_datapoint_ids")
        if not isinstance(completed_value, list):
            raise ValueError("recovery completed-selection IDs changed")
        completed_ids = list(completed_value)
    else:
        raise ValueError("recovery completed-prefix schema is unsupported")
    selected_ids = [datapoint.id for datapoint in corpus]
    if _sha256_json(selected_ids) != entry["selected_datapoint_ids_sha256"]:
        raise ValueError("recovery selected datapoint identity changed")
    if schema == "ura-recovery-completed-selection/1":
        if len(set(selected_ids)) != len(selected_ids):
            raise ValueError("recovery selected datapoint IDs are not unique")
        completed_set = set(completed_ids or [])
        if len(completed_set) >= len(corpus) or not completed_set.issubset(selected_ids):
            raise ValueError("recovery completed selection leaves no exact unfinished set")
        remaining_positions = [
            index for index, item in enumerate(selected_ids) if item not in completed_set
        ]
        remaining_ids = [selected_ids[index] for index in remaining_positions]
    else:
        count = int(entry["completed_prefix_count"])
        if count >= len(corpus):
            raise ValueError("recovery completed prefix leaves no unfinished row")
        prefix_ids = selected_ids[:count]
        remaining_ids = selected_ids[count:]
        if _sha256_json(prefix_ids) != entry["completed_prefix_ids_sha256"]:
            raise ValueError("recovery completed-prefix identity changed")
        remaining_positions = list(range(count, len(corpus)))
    if _sha256_json(remaining_ids) != entry["remaining_datapoint_ids_sha256"]:
        raise ValueError("recovery remaining-row identity changed")
    selected_indices = audit.get("selected_indices")
    if not isinstance(selected_indices, list) or len(selected_indices) != len(corpus):
        raise ValueError("recovery sampling audit selected-index inventory changed")
    remaining = [corpus[index] for index in remaining_positions]
    remaining_indices = [selected_indices[index] for index in remaining_positions]
    remaining_cluster_ids = [
        _cluster_key(index, row)
        for index, row in zip(remaining_indices, remaining)
    ]
    audit = {
        **audit,
        "pre_recovery_selected_records": len(corpus),
        "pre_recovery_selected_datapoint_ids_sha256": _sha256_json(selected_ids),
        (
            "recovery_completed_selection"
            if schema == "ura-recovery-completed-selection/1"
            else "recovery_completed_prefix"
        ): audit_recovery,
        "selected_records": len(remaining),
        "selected_indices": remaining_indices,
        "selected_ids": remaining_ids,
        "selected_converted_corpus_sha256": canonical_converted_corpus_sha256(
            remaining
        ),
        "selected_cluster_ids": list(dict.fromkeys(remaining_cluster_ids)),
        "selected_clusters": len(set(remaining_cluster_ids)),
        "selection_method": (
            "content_bound_never_completed_selection_v1"
            if schema == "ura-recovery-completed-selection/1"
            else "content_bound_never_completed_suffix_v1"
        ),
    }
    return remaining, audit


def _resolve_model_selection(
    names: list[str], api_registry_path: Path, local_registry_path: Path,
) -> tuple[list[str], list[str]]:
    """Resolve ``--models`` names through the hosted and local registries.

    A name that is a key of the hosted registry becomes an ``--api`` spec; a
    key of the local registry becomes a ``--local`` spec.  Unknown and
    ambiguous names are rejected with the registries that were consulted, so
    the operator sees exactly why a selection failed and where to fix it.
    """

    def registry_object(path: Path) -> dict[str, object]:
        if not path.is_file():
            return {}
        try:
            data = _json_loads_strict(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"--models could not read the target registry {path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise ValueError(
                f"--models target registry {path} must be a JSON object "
                "keyed by exact model spec"
            )
        return data

    hosted = registry_object(api_registry_path)
    local = registry_object(local_registry_path)
    if not hosted and not local:
        raise ValueError(
            "--models requires at least one target registry; found neither "
            f"{api_registry_path} nor {local_registry_path}"
        )
    api_specs: list[str] = []
    local_specs: list[str] = []
    for name in names:
        in_hosted = name in hosted
        in_local = name in local
        if in_hosted and in_local:
            raise ValueError(
                f"ambiguous model {name!r}: present in both the hosted "
                f"registry ({api_registry_path}) and the local registry "
                f"({local_registry_path}); select it explicitly with "
                "--api or --local"
            )
        if in_hosted:
            api_specs.append(name)
        elif in_local:
            local_specs.append(name)
        else:
            candidates = difflib.get_close_matches(
                name, [*hosted, *local], n=4, cutoff=0.5
            )
            hint = (
                "; closest registry entries: " + ", ".join(candidates)
                if candidates else ""
            )
            raise ValueError(
                f"unknown model {name!r}: not present in the hosted registry "
                f"({api_registry_path}) or the local registry "
                f"({local_registry_path}){hint}"
            )
    return api_specs, local_specs


def _apply_model_selection(
    ap: argparse.ArgumentParser, args: argparse.Namespace,
) -> None:
    """Rewrite ``--models`` into the equivalent ``--api``/``--local`` split.

    Runs immediately after parsing so every later gate (probe/canary shape,
    per-spec config requirements, uniqueness) sees the same values an explicit
    selection would have produced.  When the operator gave no registry paths,
    the conventional operator-local registries are consulted and, when a side
    resolves, bound as that side's config so a ``--models`` run is
    self-contained.
    """

    names = [s.strip() for s in args.models.split(",") if s.strip()]
    if not names:
        return
    if args.api or args.local:
        ap.error("--models is mutually exclusive with explicit --api/--local")
    if len(set(names)) != len(names):
        ap.error("--models entries must be unique")
    repo_root = Path(__file__).resolve().parents[1]
    api_path = (
        Path(args.api_config) if args.api_config
        else repo_root / "experiments" / "api-targets.json"
    )
    local_path = (
        Path(args.local_config) if args.local_config
        else repo_root / "experiments" / "local-targets.json"
    )
    try:
        api_specs, local_specs = _resolve_model_selection(
            names, api_path, local_path
        )
    except ValueError as exc:
        ap.error(str(exc))
    args.api = ",".join(api_specs)
    args.local = ",".join(local_specs)
    if api_specs and not args.api_config and api_path.is_file():
        args.api_config = str(api_path)
    if local_specs and not args.local_config and local_path.is_file():
        args.local_config = str(local_path)


def build_parser() -> argparse.ArgumentParser:
    """The complete run_matrix argument surface (also forwarded by rig_check).

    Importable so interface-parity tests can validate a generated argument
    vector against the real parser without executing a run.
    """

    ap = argparse.ArgumentParser(description="URA-Bench experiment matrix.")
    ap.add_argument("--dry-run", action="store_true", help="use MockTarget only")
    ap.add_argument(
        "--preflight-only", action="store_true",
        help="validate and project the complete grid without model/judge calls",
    )
    ap.add_argument(
        "--attestation-probe",
        action="store_true",
        help=(
            "mark one bounded non-dry target/corpus/attacker grid as live "
            "route/transport prerequisite evidence, never measured evidence"
        ),
    )
    ap.add_argument(
        "--diagnostic-canary",
        action="store_true",
        help=(
            "execute exactly one target/source/attacker/seed and one whole source "
            "cluster as diagnostic evidence, never measured evidence; combine with "
            "--dry-run --corpora synth for a fully offline/no-human canary"
        ),
    )
    ap.add_argument(
        "--exclude-tool-conditioned",
        action="store_true",
        help=(
            "drop tool-conditioned source rows (which no Runner attacker can "
            "execute yet) with a recorded exclusion count instead of failing the "
            "whole request; valid only for a standalone offline dry-run smoke"
        ),
    )
    ap.add_argument(
        "--execution-scope-id",
        default="",
        help=(
            "non-secret account/runtime scope label shared by a live probe and "
            "the measured grid it may admit"
        ),
    )
    ap.add_argument(
        "--live-attestation",
        action="append",
        default=[],
        help="repeatable content-addressed ura-live-attestation/2 receipt",
    )
    ap.add_argument(
        "--live-attestation-sha256",
        action="append",
        default=[],
        help="repeatable exact byte digest paired with --live-attestation",
    )
    ap.add_argument(
        "--live-attestation-max-age-hours",
        type=float,
        default=0.0,
        help="maximum receipt age at measured-grid admission (hosted/local policy)",
    )
    ap.add_argument(
        "--project-revision",
        default=os.environ.get("URA_PROJECT_REVISION_MANIFEST", ""),
        help=(
            "content-addressed ura-project-revision/1 receipt for the exact clean "
            "checkout; required for every non-dry invocation"
        ),
    )
    ap.add_argument(
        "--project-revision-sha256",
        default=os.environ.get("URA_PROJECT_REVISION_SHA256", ""),
        help="exact byte digest paired with --project-revision",
    )
    ap.add_argument(
        "--models",
        default="",
        help=(
            "comma list of model names resolved through the hosted "
            "(--api-config, default experiments/api-targets.json) and local "
            "(--local-config, default experiments/local-targets.json) target "
            "registries; mutually exclusive with explicit --api/--local"
        ),
    )
    ap.add_argument("--api", default="", help="comma list of API model ids")
    ap.add_argument(
        "--api-config",
        default="",
            help=(
                "JSON containing each selected generic API target/judge spec with "
                "modalities, max_tokens, and temperature (null omits it); Claude 5 "
                "adaptive models also require thinking+effort, and compatible "
                "providers may declare an HTTPS base_url"
            ),
    )
    ap.add_argument(
        "--api-config-sha256",
        default="",
        help="exact byte digest paired with --api-config",
    )
    ap.add_argument("--local", default="", help="comma list of backend:model specs")
    ap.add_argument(
        "--local-config",
        default="",
        help=(
            "JSON keyed by each exact --local spec with immutable revision/digest "
            "and explicit modalities"
        ),
    )
    ap.add_argument(
        "--local-config-sha256",
        default="",
        help="optional exact byte digest for a read-once selected local config",
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
    ap.add_argument(
        "--attacker-config-sha256",
        default="",
        help="optional exact byte digest for a read-once selected attacker config",
    )
    ap.add_argument(
        "--engine-runtime-config",
        default="",
        help=(
            "private ura-engine-runtime-config/1 mapping selected PyRIT, DeepTeam, "
            "h4rm3l, and Spikee adapters to their explicit venv interpreters and "
            "approved path-free receipts"
        ),
    )
    ap.add_argument(
        "--engine-runtime-config-sha256",
        default="",
        help="exact byte digest paired with --engine-runtime-config",
    )
    ap.add_argument("--judges", default="rules,llm")
    ap.add_argument("--judge-model", default="mock", help="target id used by LLMJudge")
    ap.add_argument(
        "--ack-hosted-judge-data-transfer",
        action="store_true",
        help=(
            "acknowledge that a hosted judge receives target output and "
            "source/reference grading context under that provider's terms"
        ),
    )
    ap.add_argument(
        "--approximate-common-metrics",
        action="store_true",
        help=(
            "opt in to separately named, non-authoritative approximate_* common "
            "response-proxy metrics for source-specific constructs; reliability "
            "is an uncalibrated heuristic indicator, not probability or accuracy"
        ),
    )
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
    ap.add_argument(
        "--defense-guardrail-model",
        default="",
        help=(
            "exact Hugging Face model id for a model-backed defense; required "
            "with --defense-guard guardrail and separate from the scoring guard"
        ),
    )
    ap.add_argument(
        "--defense-guardrail-revision",
        default="",
        help="immutable 40-64 hex commit for the model-backed defense",
    )
    ap.add_argument(
        "--defense-guardrail-device",
        default="",
        help="explicit torch device for the model-backed defense (for example cuda:0)",
    )
    ap.add_argument("--corpora", default="synth")
    ap.add_argument(
        "--source-config",
        default="",
        help=(
            "optional JSON mapping corpus arm ids to {converter,path_env} or "
            "{converter:'synth',synth:true}, plus optional source_label/split; "
            "path values stay in environment variables"
        ),
    )
    ap.add_argument(
        "--source-config-sha256",
        default="",
        help="optional exact byte digest for a read-once selected source config",
    )
    ap.add_argument(
        "--source-conformance",
        default=os.environ.get("URA_SOURCE_CONFORMANCE_MANIFEST", ""),
        help=(
            "content-addressed ura-source-conformance/1 manifest; defaults to "
            "URA_SOURCE_CONFORMANCE_MANIFEST"
        ),
    )
    ap.add_argument(
        "--source-conformance-sha256",
        default=os.environ.get("URA_SOURCE_CONFORMANCE_SHA256", ""),
        help=(
            "exact manifest byte digest; defaults to "
            "URA_SOURCE_CONFORMANCE_SHA256"
        ),
    )
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
        "--sampling-policy",
        choices=sorted(SAMPLING_POLICIES),
        default=None,
        help=(
            "whole-cluster prefix policy; omission preserves the seeded "
            "pseudorandom legacy default, while an explicit value is bound into "
            "request, acquisition, projection, and run identity"
        ),
    )
    ap.add_argument("--seeds", default="0")
    ap.add_argument("--max-queries", type=int, default=4,
                    help="maximum target calls per datapoint and seed")
    ap.add_argument("--max-turns", type=int, default=4,
                    help="maximum dialog turns per datapoint and seed")
    ap.add_argument(
        "--target-answer-retries",
        type=int,
        choices=range(0, 11),
        default=1,
        help=(
            "additional calls after an empty, malformed, binary/control-like, "
            "or symbol-only target answer (default: 1); exhausted attempts are "
            "retained as model-stability missing responses"
        ),
    )
    ap.add_argument(
        "--recovery-completed-prefix",
        default="",
        help=(
            "content-bound recovery selection for one or every requested corpus; "
            "excludes only exact durable completed prefixes from a fresh "
            "output-policy stratum"
        ),
    )
    ap.add_argument(
        "--recovery-completed-prefix-sha256",
        default="",
        help="exact byte digest paired with --recovery-completed-prefix",
    )
    ap.add_argument(
        "--group",
        default=(
            "model,source,risk,effective_modality,expected_behavior,attacker,"
            "source_policy_id,source_policy_version"
        ),
        help=(
            "aggregation group keys; the default preserves source, effective "
            "modality, population, attacker, and source-policy identity"
        ),
    )
    ap.add_argument("--defense", default="none",
                    choices=["none", "input", "output", "both"],
                    help="wrap targets in a GuardedTarget pre/post-filter (E4 ablation)")
    ap.add_argument("--defense-guard", default="rules", choices=["rules", "guardrail"],
                    help="judge used as the defense guardrail when --defense is set")
    ap.add_argument("--quantization", default="",
                    help="default vLLM quantization override (bitsandbytes, awq, "
                         "gptq, fp8, none); each model config wins; empty resolves "
                         "the highest fitting 16-, 8-, or 4-bit precision from "
                         "detected GPU VRAM and parameter count")
    ap.add_argument("--dtype", default="auto",
                    help="vLLM dtype for local models (auto, bfloat16, float16)")
    ap.add_argument("--max-total-target-calls", type=int, default=0,
                    help="durable matrix-wide ceiling on model-under-test logical "
                         "calls (real grids require a finite positive value)")
    ap.add_argument("--max-total-judge-calls", type=int, default=0,
                    help="durable matrix-wide ceiling on model-backed judge calls "
                         "(real grids require a finite positive value)")
    ap.add_argument("--max-total-http-attempts", type=int, default=0,
                    help="durable ceiling on declared provider transport-attempt "
                         "exposure across target and judge calls (real grids require "
                         "a finite positive value)")
    ap.add_argument("--deadline-seconds", type=int, default=0,
                    help="durable call-start admission deadline from the matrix's "
                         "first invocation; an admitted in-flight call retains its "
                         "configured provider timeout (real grids require a positive "
                         "value)")
    ap.add_argument("--lock-stale-seconds", type=int, default=86400,
                    help="diagnostic stale-age metadata only; locks are never "
                         "removed automatically (default: 86400)")
    ap.add_argument("--reset-open-circuits", action="store_true",
                    help="operator acknowledgement: clear the durable provider/"
                         "judge circuit after correcting its root cause")
    ap.add_argument(
        "--model-acquisition-plan-only",
        action="store_true",
        help=(
            "derive the exact sealed-Hugging-Face acquisition plan and stop "
            "before constructing any attacker, target, judge, or model"
        ),
    )
    ap.add_argument(
        "--model-acquisition-plan-dir",
        default=os.environ.get("URA_MODEL_ACQUISITION_PLAN_DIR", ""),
        help="private create-only destination used only by plan-only mode",
    )
    ap.add_argument(
        "--model-acquisition-plan",
        default=os.environ.get("URA_MODEL_ACQUISITION_PLAN", ""),
        help="private exact acquisition-plan locator for normal/preflight execution",
    )
    ap.add_argument(
        "--model-acquisition-plan-sha256",
        default=os.environ.get("URA_MODEL_ACQUISITION_PLAN_SHA256", ""),
        help="exact byte digest paired with --model-acquisition-plan",
    )
    ap.add_argument(
        "--model-acquisition-receipt",
        default=os.environ.get("URA_MODEL_ACQUISITION_RECEIPT", ""),
        help="private exact acquisition-receipt locator",
    )
    ap.add_argument(
        "--model-acquisition-receipt-sha256",
        default=os.environ.get("URA_MODEL_ACQUISITION_RECEIPT_SHA256", ""),
        help="exact byte digest paired with --model-acquisition-receipt",
    )
    ap.add_argument(
        "--model-acquisition-store",
        default=os.environ.get("URA_MODEL_ACQUISITION_STORE", ""),
        help="private managed immutable model store",
    )
    ap.add_argument("--out", default="runs/exp")
    return ap


_ACTIVE_ENGINE_RUNTIME_SELECTION: EngineRuntimeSelection | None = None
_ACTIVE_MODEL_COMPONENTS: list[object] = []


def _track_model_component(component: object) -> object:
    """Register one process-owned model component for unconditional teardown."""

    if not any(existing is component for existing in _ACTIVE_MODEL_COMPONENTS):
        _ACTIVE_MODEL_COMPONENTS.append(component)
    return component


def _close_model_components() -> tuple[list[str], BaseException | None]:
    """Close every tracked component once, newest first, without leaking errors."""

    components = list(reversed(_ACTIVE_MODEL_COMPONENTS))
    _ACTIVE_MODEL_COMPONENTS.clear()
    failures: list[str] = []
    deferred_interrupt: BaseException | None = None
    seen: set[int] = set()
    for component in components:
        identity = id(component)
        if identity in seen:
            continue
        seen.add(identity)
        try:
            close = getattr(component, "close", None)
            if callable(close):
                close()
        except BaseException as exc:  # finish every independent GPU owner
            if isinstance(exc, Exception):
                component_type = type(component)
                failures.append(
                    f"{component_type.__module__}.{component_type.__qualname__}: "
                    f"{type(exc).__name__}"
                )
            elif deferred_interrupt is None:
                deferred_interrupt = exc
    return failures, deferred_interrupt


class _EngineRuntimeTermination(BaseException):
    def __init__(self, signum: int) -> None:
        super().__init__(f"termination signal {signum}")
        self.signum = signum


def _main(argv=None) -> int:
    global _ACTIVE_ENGINE_RUNTIME_SELECTION
    invocation_started_epoch = time.time()
    ap = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    sample_seed_explicit = any(
        token == "--sample-seed" or token.startswith("--sample-seed=")
        for token in raw_argv
    )
    args = ap.parse_args(raw_argv)
    sampling_policy_binding = (
        {"sampling_policy": effective_sampling_policy(args.sampling_policy)}
        if args.sampling_policy is not None
        else {}
    )
    # Only the explicit model-acquisition controller may receive Hub tokens.
    # Planned and measured children use sealed local snapshots exclusively.
    os.environ.pop("HF_TOKEN", None)
    os.environ.pop("HUGGING_FACE_HUB_TOKEN", None)
    _apply_model_selection(ap, args)

    for left, right in (
        (
            args.model_acquisition_plan,
            args.model_acquisition_plan_sha256,
        ),
        (
            args.model_acquisition_receipt,
            args.model_acquisition_receipt_sha256,
        ),
    ):
        if bool(left) != bool(right):
            ap.error("each private model-acquisition locator requires its exact SHA-256")
    normal_acquisition_values = (
        args.model_acquisition_plan,
        args.model_acquisition_plan_sha256,
        args.model_acquisition_receipt,
        args.model_acquisition_receipt_sha256,
        args.model_acquisition_store,
    )
    if args.model_acquisition_plan_only:
        if any(normal_acquisition_values):
            ap.error(
                "--model-acquisition-plan-only cannot consume a plan, receipt, or store"
            )
        if not args.model_acquisition_plan_dir:
            ap.error(
                "--model-acquisition-plan-only requires "
                "--model-acquisition-plan-dir"
            )
    elif args.model_acquisition_plan_dir:
        ap.error(
            "--model-acquisition-plan-dir is valid only with "
            "--model-acquisition-plan-only"
        )

    if args.diagnostic_canary and (args.preflight_only or args.attestation_probe):
        ap.error(
            "--diagnostic-canary cannot be combined with --preflight-only "
            "or --attestation-probe"
        )
    execution_purpose = (
        "diagnostic_canary"
        if args.diagnostic_canary
        else "diagnostic_dry_run"
        if args.dry_run
        else "preflight_only"
        if args.preflight_only
        else "attestation_probe"
        if args.attestation_probe
        else "measured_run"
    )
    if args.exclude_tool_conditioned and (
        not args.dry_run
        or args.diagnostic_canary
        or args.preflight_only
        or args.attestation_probe
        or args.model_acquisition_plan_only
    ):
        ap.error(
            "--exclude-tool-conditioned is valid only for a standalone "
            "diagnostic --dry-run; preflight, acquisition, attestation, "
            "canary, and measured routes must retain every selected cluster row"
        )

    if bool(args.project_revision) != bool(args.project_revision_sha256):
        ap.error(
            "--project-revision and --project-revision-sha256 must be provided together"
        )
    if not args.dry_run and not args.project_revision:
        ap.error(
            "every non-dry invocation requires --project-revision and "
            "--project-revision-sha256"
        )
    project_revision_receipt: dict[str, object] | None = None
    project_revision_artifact: dict[str, object] | None = None
    project_revision_payload: bytes | None = None
    if args.project_revision:
        try:
            if os.environ.get("URA_PRIVATE_TRANSIENT_PROJECT_REVISION", "").strip():
                loaded_revision = _read_optional_bound_config(
                    args.project_revision,
                    args.project_revision_sha256,
                    flag_name="--project-revision",
                    transient_environment=(
                        "URA_PRIVATE_TRANSIENT_PROJECT_REVISION"
                    ),
                    transient_directory=".private-project-revision",
                    transient_prefix="project-revision",
                    max_bytes=4 * 1024 * 1024,
                )
                if loaded_revision is None:  # pragma: no cover - path is present
                    raise ValueError("private project revision is missing")
                (
                    project_revision_payload,
                    revision_path,
                    revision_size,
                    revision_sha256,
                    _revision_transient,
                ) = loaded_revision
                project_revision_receipt = validate_project_revision(
                    _json_loads_strict(project_revision_payload.decode("utf-8"))
                )
                recheck_project_revision(
                    project_revision_receipt,
                    Path(__file__).resolve(),
                )
                revision_filename = (
                    f"{project_revision_receipt['revision_id']}"
                    ".project-revision.json"
                )
                project_revision_artifact = {
                    # The randomized private path is a read-once transport
                    # detail.  The persisted binding names the canonical
                    # content-addressed receipt that is retained below, just
                    # like the ordinary non-private loader does.
                    "file": revision_filename,
                    "sha256": revision_sha256,
                    "bytes": revision_size,
                    "revision_id": project_revision_receipt["revision_id"],
                }
            else:
                project_revision_receipt, project_revision_artifact = (
                    load_project_revision_file(
                        Path(args.project_revision),
                        args.project_revision_sha256,
                        Path(__file__).resolve(),
                    )
                )
            project_revision_state = project_revision_binding(
                project_revision_receipt, project_revision_artifact
            )
        except (OSError, TypeError, UnicodeError, ValueError) as exc:
            ap.error(str(exc))
    else:
        driver_sha256 = _sha256_file(Path(__file__).resolve())
        project_revision_state = diagnostic_project_revision_binding(
            str(_harness_source_identity()["sha256"]), driver_sha256
        )

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
    scope_id = args.execution_scope_id.strip()
    if args.execution_scope_id != scope_id:
        ap.error("--execution-scope-id must not have surrounding whitespace")
    if scope_id:
        try:
            scope_id = validate_execution_scope_id(scope_id)
        except ValueError as exc:
            ap.error(str(exc))
    if len(args.live_attestation) != len(args.live_attestation_sha256):
        ap.error(
            "each --live-attestation requires one paired "
            "--live-attestation-sha256"
        )
    if args.dry_run and (
        args.attestation_probe
        or scope_id
        or args.live_attestation
        or args.live_attestation_max_age_hours
    ):
        ap.error("diagnostic --dry-run cannot consume or produce live attestation")
    if args.preflight_only and (
        args.attestation_probe
        or scope_id
        or args.live_attestation
        or args.live_attestation_max_age_hours
    ):
        ap.error("--preflight-only does not consume or produce live attestation")
    if args.attestation_probe:
        if not scope_id:
            ap.error("--attestation-probe requires --execution-scope-id")
        if args.live_attestation or args.live_attestation_max_age_hours:
            ap.error("an attestation probe cannot consume prior live attestations")
    elif not args.dry_run and not args.preflight_only:
        if not scope_id:
            ap.error("measured execution requires --execution-scope-id")
        if not 0 < args.live_attestation_max_age_hours <= 24 * 365:
            ap.error(
                "measured execution requires --live-attestation-max-age-hours "
                "in (0, 8760]"
            )

    seeds = [int(s) for s in args.seeds.split(",") if s.strip()]
    if not seeds:
        ap.error("--seeds must contain at least one integer")
    if len(set(seeds)) != len(seeds):
        ap.error("--seeds must be unique")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if project_revision_receipt is not None and project_revision_artifact is not None:
        try:
            revision_filename = (
                f"{project_revision_receipt['revision_id']}.project-revision.json"
            )
            retained_project_revision = (
                _retain_content_addressed_bytes(
                    out,
                    project_revision_payload,
                    args.project_revision_sha256,
                    stem="project-revision",
                    filename=revision_filename,
                )
                if project_revision_payload is not None
                else _retain_content_addressed_input(
                    out,
                    args.project_revision,
                    args.project_revision_sha256,
                    stem="project-revision",
                    filename=revision_filename,
                )
            )
        except (OSError, ValueError) as exc:
            ap.error(str(exc))
        project_revision_artifact = {
            **project_revision_artifact,
            "file": retained_project_revision.name,
        }
        project_revision_state = project_revision_binding(
            project_revision_receipt, project_revision_artifact
        )

    def recheck_bound_project_revision() -> None:
        if project_revision_receipt is not None:
            recheck_project_revision(
                project_revision_receipt, Path(__file__).resolve()
            )

    # Wall-clock provenance for Runner 2.10 (run date). Recorded in the manifest but kept
    # OUT of the run_id hash, so runs stay reproducible while the date is captured.
    run_started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_env = _runtime_env()
    api_specs = [s.strip() for s in args.api.split(",") if s.strip()]
    local_specs = [s.strip() for s in args.local.split(",") if s.strip()]
    judge_names = [j.strip() for j in args.judges.split(",") if j.strip()]
    local_judge_spec = (
        args.judge_model
        if (
            not args.dry_run
            and "llm" in judge_names
            and args.judge_model.startswith(("vllm:", "ollama:"))
        )
        else None
    )
    local_config_specs = local_specs + (
        [local_judge_spec] if local_judge_spec is not None else []
    )
    hosted_judge_selected = (
        not args.dry_run
        and "llm" in judge_names
        and args.judge_model != "mock"
        and local_judge_spec is None
    )
    if (
        execution_purpose == "measured_run"
        and args.limit > 0
        and not sample_seed_explicit
    ):
        ap.error(
            "measured bounded-cluster routes require explicit --sample-seed"
        )
    transfers_to_hosted_judge = (
        hosted_judge_selected and not args.preflight_only
    )
    if transfers_to_hosted_judge and not args.ack_hosted_judge_data_transfer:
        ap.error(
            "a live hosted LLM judge requires "
            "--ack-hosted-judge-data-transfer"
        )
    if args.ack_hosted_judge_data_transfer and not transfers_to_hosted_judge:
        ap.error(
            "--ack-hosted-judge-data-transfer is valid only when a live hosted "
            "LLM judge will receive grading context"
        )
    from experiments.local_targets import detect_gpu_hardware  # noqa: PLC0415
    gpu_hardware = detect_gpu_hardware() if local_config_specs else {
        "available": False, "source": "not_requested", "gpu_count": 0,
        "aggregate_vram_gib": 0.0, "max_gpu_vram_gib": 0.0, "gpus": [],
    }
    if len(set(api_specs)) != len(api_specs):
        ap.error("--api specs must be unique")
    if api_specs and args.target_answer_retries != 0:
        ap.error("paid hosted targets require --target-answer-retries 0")
    if len(set(local_specs)) != len(local_specs):
        ap.error("--local specs must be unique")
    if len(local_specs) > 1:
        ap.error(
            "one local target is allowed per process; cached vLLM/Ollama engines "
            "must not accumulate on the two-GPU rig"
        )
    if len(set(local_config_specs)) != len(local_config_specs):
        ap.error("the LLM judge must differ from every model under test")
    if len(local_config_specs) > 1:
        ap.error(
            "a local target and a distinct local LLM judge cannot share one "
            "process; run one local engine per process to avoid GPU engine "
            "double-load conflicts"
        )
    model_specs = ["mock"] if args.dry_run else (api_specs + local_specs)
    if len(set(model_specs)) != len(model_specs):
        ap.error("target specs must be unique across --api and --local")
    if not model_specs:
        ap.error("a real run requires at least one --api or --local target; use --dry-run for mock")

    attacker_names = [a.strip() for a in args.attackers.split(",") if a.strip()]
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
        recovery_completed_prefix, recovery_selection_binding = (
            load_recovery_completed_prefix(
                args.recovery_completed_prefix,
                args.recovery_completed_prefix_sha256,
            )
        )
    except (OSError, UnicodeError, ValueError) as exc:
        ap.error(str(exc))
    if recovery_completed_prefix is not None:
        recovery_schema = recovery_completed_prefix.get("schema")
        recovery_corpora = (
            [recovery_completed_prefix["corpus"]]
            if recovery_schema == "ura-recovery-completed-prefix/1"
            else list(recovery_completed_prefix.get("corpora", {}))
        )
        if (
            set(corpora) != set(recovery_corpora)
            or len(corpora) != len(recovery_corpora)
            or args.dry_run
            or args.attestation_probe
            or args.diagnostic_canary
        ):
            ap.error(
                "--recovery-completed-prefix requires its exact real corpus "
                "inventory and is valid only for acquisition preflight, preflight, "
                "or measured recovery"
            )
    if args.attestation_probe and (
        len(model_specs) != 1
        or len(corpora) != 1
        or len(attacker_names) != 1
        or attacker_names != ["replay"]
        or args.defense != "none"
        or len(seeds) != 1
        or args.limit not in {1, 2}
        or args.max_queries != 1
        or args.max_turns != 1
    ):
        ap.error(
            "--attestation-probe requires one target/corpus/replay attacker/seed, "
            "--defense none, --limit 1 or 2, and one query/turn"
        )
    if args.diagnostic_canary and (
        len(model_specs) != 1
        or len(corpora) != 1
        or len(attacker_names) != 1
        or len(seeds) != 1
        or args.limit != 1
    ):
        ap.error(
            "--diagnostic-canary requires exactly one target, corpus, attacker, "
            "seed, and --limit 1 (all rows in that source cluster are retained)"
        )
    if args.diagnostic_canary and args.dry_run and corpora != ["synth"]:
        ap.error(
            "a dry-run --diagnostic-canary must use exactly --corpora synth; "
            "real source canaries require a live-attested route"
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

    # Freeze the selected whole-arm universe before config loading or corpus
    # conversion.  The driver/source digests are distinct from the Git commit
    # receipt and make this early identity agree with all later Runner evidence.
    driver_digest, driver_file_count = _source_tree_digest(Path(__file__).resolve())
    driver_source = {
        "module": Path(__file__).name,
        "sha256": driver_digest,
        "file_count": driver_file_count,
    }
    harness_source = _harness_source_identity()
    request_target_keys = [
        _prematerialization_target_key(spec) for spec in model_specs
    ]
    request_judge_model = (
        _prematerialization_target_key(args.judge_model)
        if "llm" in judge_names
        else None
    )
    if len(set(request_target_keys)) != len(request_target_keys):
        ap.error("target specs collapse to duplicate pre-materialization request keys")
    request_envelope = build_request_envelope(
        request={
            "execution_purpose": execution_purpose,
            "requested_target_keys": request_target_keys,
            "logical_source_arms": corpora,
            "selected_attackers": attacker_names,
            "judges": judge_names,
            "judge_model": request_judge_model,
            "seeds": seeds,
            "sample_seed": args.sample_seed,
            "limit": args.limit,
            **sampling_policy_binding,
            "max_queries": args.max_queries,
            "max_turns": args.max_turns,
            "target_answer_retries": args.target_answer_retries,
            "recovery_selection": recovery_selection_binding,
            "defense": args.defense,
            "defense_guard": args.defense_guard,
            "group_keys": group_keys,
            "quantization": args.quantization,
            "dtype": args.dtype,
            "dry_run": bool(args.dry_run),
            "approximate_common_metrics": bool(args.approximate_common_metrics),
            "hosted_judge_data_transfer_acknowledged": bool(
                args.ack_hosted_judge_data_transfer
            ),
            "call_caps": {
                "target": args.max_total_target_calls or None,
                "judge": args.max_total_judge_calls or None,
                "http_attempts": args.max_total_http_attempts or None,
                "deadline_seconds": args.deadline_seconds or None,
            },
        },
        project_revision=project_revision_state,
        harness_source=harness_source,
        driver_source=driver_source,
    )
    request_envelope_path = write_request_envelope(out, request_envelope)
    request_envelope_artifact = request_envelope_descriptor(
        request_envelope_path, request_envelope
    )
    try:
        if args.model_acquisition_plan_only:
            invocation_deadline_epoch = None
            _invocation_deadline_path = None
        else:
            invocation_deadline_epoch, _invocation_deadline_path = (
                _load_or_create_invocation_deadline(
                    out,
                    request_envelope_id=str(request_envelope["envelope_id"]),
                    invocation_started_epoch=invocation_started_epoch,
                    deadline_seconds=args.deadline_seconds,
                )
            )
    except (OSError, TypeError, ValueError) as exc:
        ap.error(f"cannot bind first-invocation deadline: {exc}")
    request_key_by_model_spec = dict(zip(model_specs, request_target_keys))
    source_instances: dict[str, dict[str, object]] = {}

    def safe_request_error_message(exc: Exception) -> str:
        """Remove operator-local input paths from retained early failures."""

        configured_paths = [
            args.attacker_config,
            args.engine_runtime_config,
            args.api_config,
            args.local_config,
            args.source_config,
            args.source_conformance,
            args.model_acquisition_plan_dir,
            args.model_acquisition_plan,
            args.model_acquisition_receipt,
            args.model_acquisition_store,
            args.recovery_completed_prefix,
            *args.live_attestation,
        ]
        configured_paths.extend(
            os.environ.get(str(instance.get("path_env")), "")
            for instance in source_instances.values()
            if instance.get("path_env")
        )
        media_roots = os.environ.get("URA_MEDIA_ROOTS", "")
        if media_roots:
            configured_paths.extend(media_roots.split(os.pathsep))
        # Local checkpoint locators are runtime-only input, just like config
        # file paths. Configuration errors often interpolate the selected spec
        # before its content identity has been materialized, so scrub the model
        # path (and its resolved form/ancestors) from retained request errors.
        from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

        for selected_spec in [*model_specs, args.judge_model]:
            if not selected_spec.startswith("vllm:"):
                continue
            runtime_model = selected_spec.split(":", 1)[1]
            if _is_explicit_local_path(runtime_model):
                configured_paths.append(runtime_model)
        return _scrub_operator_paths(str(exc), configured_paths)

    def persist_request_error(
        *,
        phase: str,
        category: str,
        exc: Exception,
        requested_target_key: str | None = None,
        logical_source_arm: str | None = None,
        attacker: str | None = None,
    ) -> Path:
        # A rerun may pass an earlier gate and fail at a later one. Retain only
        # the current terminal pre-materialization outcome for this envelope.
        clear_resolved_request_errors()
        error = build_request_error(
            envelope=request_envelope,
            envelope_descriptor=request_envelope_artifact,
            phase=phase,
            category=category,
            exception_type=type(exc).__name__,
            message=safe_request_error_message(exc),
            requested_target_key=requested_target_key,
            logical_source_arm=logical_source_arm,
            attacker=attacker,
        )
        return write_request_error(out, error)

    def clear_resolved_request_errors() -> None:
        """Remove only validated stale early errors for this exact envelope."""

        for candidate in sorted(out.glob("request-error-*.request.error.json")):
            try:
                error = load_request_error_file(
                    candidate, envelope=request_envelope
                )
            except (OSError, TypeError, ValueError):
                continue
            if error["request_envelope"] == request_envelope_artifact:
                candidate.unlink()

    source_conformance_manifest: dict[str, object] | None = None
    source_conformance_artifact: dict[str, object] | None = None
    engine_runtime_selection: EngineRuntimeSelection | None = None
    engine_runtime_config_artifact: dict[str, object] | None = None
    engine_runtime_descriptor: dict[str, object] | None = None
    engine_runtime_close_descriptor: dict[str, object] | None = None
    live_attestation_manifests: list[dict[str, object]] = []
    live_attestation_artifacts: list[dict[str, object]] = []
    try:
        attacker_configs, attacker_config_artifact = _load_attacker_config(
            args.attacker_config,
            attacker_names,
            args.attacker_config_sha256,
        )
        portable_attacker_configs = _portable_attacker_configs(attacker_configs)
        engine_runtime_selection, engine_runtime_config_artifact = (
            _load_engine_runtime_config(
                args.engine_runtime_config,
                attacker_names,
                args.engine_runtime_config_sha256,
            )
        )
        configured_api_specs = list(api_specs)
        if (
            not args.dry_run
            and "llm" in judge_names
            and local_judge_spec is None
            and args.judge_model not in configured_api_specs
        ):
            configured_api_specs.append(args.judge_model)
        api_configs, api_config_artifact = _load_api_config(
            args.api_config,
            [] if args.dry_run else configured_api_specs,
            args.api_config_sha256,
        )
        portable_api_configs = _portable_api_configs(api_configs)
        local_configs, local_config_artifact = _load_local_config(
            args.local_config,
            [] if args.dry_run else local_config_specs,
            quantization=args.quantization,
            hardware=gpu_hardware,
            expected_sha256=args.local_config_sha256,
        )
        resolved_quantizations = {
            spec: str(config["quantization"])
            for spec, config in local_configs.items()
            if spec.startswith("vllm:")
        }
        source_instances, source_config_artifact = _load_source_config(
            args.source_config,
            corpora,
            args.source_config_sha256,
        )
        real_source_arms = [
            arm for arm in corpora if arm != "synth"
        ]
        held_source_conformance = None
        if os.environ.get(
            "URA_PRIVATE_TRANSIENT_SOURCE_CONFORMANCE", ""
        ).strip():
            held_source_conformance = _read_optional_bound_config(
                args.source_conformance,
                args.source_conformance_sha256,
                flag_name="--source-conformance",
                transient_environment=(
                    "URA_PRIVATE_TRANSIENT_SOURCE_CONFORMANCE"
                ),
                transient_directory=".private-source-conformance",
                transient_prefix="source-conformance",
                max_bytes=4 * 1024 * 1024,
            )
        if real_source_arms:
            if bool(args.source_conformance) != bool(args.source_conformance_sha256):
                raise ValueError(
                    "--source-conformance and --source-conformance-sha256 must be "
                    "provided together"
                )
            if not args.dry_run and not args.source_conformance:
                raise ValueError(
                    "real-source execution requires a content-addressed "
                    "--source-conformance manifest"
                )
        elif args.source_conformance or args.source_conformance_sha256:
            print(
                "synthetic-only run: ignoring real-source conformance environment",
                file=sys.stderr,
            )
            args.source_conformance = ""
            args.source_conformance_sha256 = ""
        if args.source_conformance:
            if source_config_artifact is None:
                raise ValueError(
                    "source conformance requires an explicit --source-config file"
                )
            source_conformance_payload: bytes | None = None
            if held_source_conformance is not None:
                (
                    source_conformance_payload,
                    conformance_path,
                    conformance_size,
                    conformance_sha256,
                    _conformance_transient,
                ) = held_source_conformance
                raw_conformance = _json_loads_strict(
                    source_conformance_payload.decode("utf-8")
                )
                source_conformance_artifact = {
                    "file": conformance_path.name,
                    "sha256": conformance_sha256,
                    "bytes": conformance_size,
                }
            else:
                raw_conformance, source_conformance_artifact = (
                    _read_content_addressed_json(
                        args.source_conformance,
                        args.source_conformance_sha256,
                        flag_name="--source-conformance",
                        max_bytes=4 * 1024 * 1024,
                    )
                )
            source_conformance_manifest = validate_source_conformance_manifest(
                raw_conformance
            )
            retained = (
                _retain_content_addressed_bytes(
                    out,
                    source_conformance_payload,
                    args.source_conformance_sha256,
                    stem="source-conformance",
                )
                if source_conformance_payload is not None
                else _retain_content_addressed_input(
                    out,
                    args.source_conformance,
                    args.source_conformance_sha256,
                    stem="source-conformance",
                )
            )
            source_conformance_artifact["file"] = retained.name
        for attestation_index, (path_value, expected_digest) in enumerate(
            zip(args.live_attestation, args.live_attestation_sha256),
            start=1,
        ):
            marker_name = (
                f"URA_PRIVATE_TRANSIENT_LIVE_ATTESTATION_{attestation_index:02d}"
            )
            attestation_payload: bytes | None = None
            if os.environ.get(marker_name, "").strip():
                held_attestation = _read_optional_bound_config(
                    path_value,
                    expected_digest,
                    flag_name="--live-attestation",
                    transient_environment=marker_name,
                    transient_directory=".private-live-attestations",
                    transient_prefix=f"live-attestation-{attestation_index:02d}",
                    max_bytes=4 * 1024 * 1024,
                )
                if held_attestation is None:  # pragma: no cover - path is present
                    raise ValueError("private live attestation is missing")
                (
                    attestation_payload,
                    attestation_path,
                    attestation_size,
                    attestation_sha256,
                    _attestation_transient,
                ) = held_attestation
                manifest = validate_live_attestation_manifest(
                    _json_loads_strict(attestation_payload.decode("utf-8"))
                )
                descriptor = {
                    "file": attestation_path.name,
                    "sha256": attestation_sha256,
                    "bytes": attestation_size,
                }
            else:
                manifest, descriptor = load_live_attestation_file(
                    path_value, expected_digest
                )
            retained = (
                _retain_content_addressed_bytes(
                    out,
                    attestation_payload,
                    expected_digest,
                    stem="live-attestation",
                )
                if attestation_payload is not None
                else _retain_content_addressed_input(
                    out,
                    path_value,
                    expected_digest,
                    stem="live-attestation",
                )
            )
            live_attestation_manifests.append(manifest)
            live_attestation_artifacts.append({
                **descriptor,
                "file": retained.name,
                "attestation_id": manifest["attestation_id"],
            })
        live_attestation_artifacts.sort(
            key=lambda item: (
                str(item["attestation_id"]),
                str(item["sha256"]),
                str(item["file"]),
            )
        )
        if len({
            (item["attestation_id"], item["sha256"], item["bytes"])
            for item in live_attestation_artifacts
        }) != len(live_attestation_artifacts):
            raise ValueError("duplicate --live-attestation receipt input")
    except (OSError, KeyError, ValueError) as exc:
        persist_request_error(
            phase="configuration_preflight",
            category="configuration_invalid",
            exc=exc,
        )
        print(f"configuration preflight failed: {exc}", file=sys.stderr)
        return 1
    persisted_model_specs = {
        spec: _persisted_model_spec(spec, local_configs.get(spec))
        for spec in model_specs
    }
    persisted_judge_model = (
        _persisted_model_spec(
            args.judge_model, local_configs.get(args.judge_model)
        )
        if "llm" in judge_names
        else None
    )
    # Preserve the sanitized request independently of the resolved target name.
    # Some target constructors replace the display identity below, while the
    # eligibility ledger must retain both sides of that mapping.
    requested_model_specs = dict(request_key_by_model_spec)
    if args.dry_run or args.preflight_only:
        live_attestation_projection: dict[str, object] = {
            "mode": "not_required",
            "execution_scope_id": None,
            "max_age_hours": None,
            "artifacts": [],
        }
    elif args.attestation_probe:
        live_attestation_projection = {
            "mode": "probe",
            "execution_scope_id": scope_id,
            "max_age_hours": None,
            "artifacts": [],
        }
    else:
        live_attestation_projection = {
            "mode": "measured",
            "execution_scope_id": scope_id,
            "max_age_hours": args.live_attestation_max_age_hours,
            "artifacts": live_attestation_artifacts,
        }
    if (
        not args.dry_run
        and real_source_arms
        and "llm" in judge_names
        and args.judge_model == "mock"
    ):
        exc = ValueError(
            "a run containing real source arms requires an explicit non-mock "
            "--judge-model for the llm judge"
        )
        persist_request_error(
            phase="configuration_preflight",
            category="configuration_invalid",
            exc=exc,
        )
        print(f"configuration preflight failed: {exc}", file=sys.stderr)
        return 1
    scoring_guardrail_selected = "guardrail" in judge_names
    defense_guardrail_selected = (
        args.defense != "none" and args.defense_guard == "guardrail"
    )
    if scoring_guardrail_selected:
        if not args.guardrail_model.strip():
            exc = ValueError(
                "scoring guardrail cells require a non-blank --guardrail-model"
            )
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            ap.error(str(exc))
        if re.fullmatch(r"[0-9a-fA-F]{40,64}", args.guardrail_revision) is None:
            exc = ValueError(
                "scoring guardrail cells require --guardrail-revision as an immutable "
                "40-64 hex Hugging Face commit"
            )
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            ap.error(str(exc))
    if defense_guardrail_selected:
        if not args.defense_guardrail_model.strip():
            exc = ValueError(
                "model-backed defense cells require --defense-guardrail-model"
            )
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            ap.error(str(exc))
        if re.fullmatch(
            r"[0-9a-fA-F]{40,64}", args.defense_guardrail_revision
        ) is None:
            exc = ValueError(
                "model-backed defense cells require --defense-guardrail-revision "
                "as an immutable 40-64 hex Hugging Face commit"
            )
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            ap.error(str(exc))
        if not args.defense_guardrail_device.strip():
            exc = ValueError(
                "model-backed defense cells require an explicit "
                "--defense-guardrail-device"
            )
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            ap.error(str(exc))
        if (
            scoring_guardrail_selected
            and args.defense_guardrail_model.strip() == args.guardrail_model.strip()
        ):
            exc = ValueError(
                "the defense guard and scoring guard must be different models; "
                "a guard must not grade its own defense decisions"
            )
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            ap.error(str(exc))

    # Stage 1 NanoGCG is precomputed-suffix replay only.  Reject live
    # optimization before deriving an acquisition plan so a disabled surrogate
    # can never cause snapshot planning, verification, or admission.
    if "nanogcg" in {name.lower() for name in attacker_names}:
        nanogcg_config = attacker_configs.get("nanogcg", {})
        suffix = nanogcg_config.get("suffix")
        live_model_fields = sorted(
            {"model_id", "model_revision"} & set(nanogcg_config)
        )
        if (
            not isinstance(suffix, str)
            or not suffix.strip()
            or live_model_fields
        ):
            exc = RuntimeError(LIVE_NANOGCG_DISABLED_MESSAGE)
            persist_request_error(
                phase="configuration_preflight",
                category="configuration_invalid",
                exc=exc,
            )
            print(f"nanoGCG runtime admission failed: {exc}", file=sys.stderr)
            return 1

    # Derive and admit the complete immutable Hugging Face selection before
    # constructing any attacker, target, judge, or defense object. Normal and
    # preflight runs have no network fallback: every Hub role needs the exact
    # plan, receipt, and fully verified managed snapshot.
    model_runtime: ManagedModelRuntime | None = None
    acquisition_runtime_descriptor: dict[str, object] | None = None
    acquisition_execution_descriptor: dict[str, object] | None = None
    acquisition_selection: RuntimeSelection | None = None
    try:
        acquisition_requirements = collect_run_requirements(
            target_specs=model_specs,
            local_configs=local_configs,
            judge_names=judge_names,
            judge_model=args.judge_model,
            attacker_names=attacker_names,
            attacker_configs=attacker_configs,
            guardrail_model=(
                args.guardrail_model if scoring_guardrail_selected else None
            ),
            guardrail_revision=(
                args.guardrail_revision if scoring_guardrail_selected else None
            ),
            defense_guardrail_model=(
                args.defense_guardrail_model
                if defense_guardrail_selected
                else None
            ),
            defense_guardrail_revision=(
                args.defense_guardrail_revision
                if defense_guardrail_selected
                else None
            ),
        )
        if args.dry_run and acquisition_requirements.requirements:
            raise ModelAcquisitionError(
                "diagnostic --dry-run forbids Hub-backed attackers or judges; "
                "NanoGCG requires an exact precomputed suffix replay"
            )
        acquisition_local_configs = {
            _persisted_model_spec(spec, config): config
            for spec, config in local_configs.items()
        }
        if len(acquisition_local_configs) != len(local_configs):
            raise ModelAcquisitionError(
                "local acquisition configs collapse to a duplicate content identity"
            )
        input_bindings = {
            "api_configs_sha256": _sha256_json(portable_api_configs),
            "attacker_configs_sha256": _sha256_json(portable_attacker_configs),
            "engine_runtime_config_sha256": _sha256_json(
                _selected_config_artifact_identity(engine_runtime_config_artifact)
            ),
            "local_configs_sha256": _sha256_json(acquisition_local_configs),
            "project_revision_sha256": _sha256_json(project_revision_state),
            "request_envelope_sha256": str(request_envelope_artifact["sha256"]),
            "source_config_sha256": _sha256_json(
                _selected_config_artifact_identity(source_config_artifact)
            ),
            "source_conformance_sha256": _sha256_json(
                _content_artifact_identity(source_conformance_artifact)
            ),
            "source_instances_sha256": _sha256_json(source_instances),
        }
        has_hub_requirements = bool(acquisition_requirements.requirements)
        supplied_runtime_values = bool(
            args.model_acquisition_plan
            or args.model_acquisition_plan_sha256
            or args.model_acquisition_receipt
            or args.model_acquisition_receipt_sha256
            or args.model_acquisition_store
        )
        if has_hub_requirements:
            acquisition_selection = build_runtime_selection(
                acquisition_requirements,
                input_bindings=input_bindings,
            )
            selection_descriptor = public_selection_descriptor(
                acquisition_selection
            )
            if args.model_acquisition_plan_only:
                plan = build_runtime_plan(acquisition_selection)
                _plan_path, plan_digest = write_document_create_only(
                    args.model_acquisition_plan_dir,
                    plan,
                    identifier=plan["plan_id"],
                    suffix="plan.json",
                )
                print(json.dumps({
                    "plan_id": plan["plan_id"],
                    "plan_sha256": plan_digest,
                    "selection": selection_descriptor,
                }, sort_keys=True, separators=(",", ":")))
                return 0
            if not all(normal_acquisition_values):
                raise ModelAcquisitionError(
                    "normal and preflight Hub runs require exact acquisition "
                    "plan, plan SHA-256, receipt, receipt SHA-256, and managed store"
                )
            os.environ.update(hf_offline_environment_overrides())
            model_runtime, acquisition_runtime_descriptor = (
                admit_managed_model_runtime(
                    selection=acquisition_selection,
                    plan_path=args.model_acquisition_plan,
                    plan_sha256=args.model_acquisition_plan_sha256,
                    receipt_path=args.model_acquisition_receipt,
                    receipt_sha256=args.model_acquisition_receipt_sha256,
                    managed_store=args.model_acquisition_store,
                )
            )
            admitted_plan = load_plan(
                args.model_acquisition_plan,
                expected_sha256=args.model_acquisition_plan_sha256,
            )
            admitted_receipt = load_receipt(
                args.model_acquisition_receipt,
                expected_sha256=args.model_acquisition_receipt_sha256,
                plan=admitted_plan,
            )
            evidence_directory = (out / "model-acquisition").resolve()
            plan_copy, _plan_copy_sha = write_document_create_only(
                evidence_directory,
                admitted_plan,
                identifier=admitted_plan["plan_id"],
                suffix="plan.json",
            )
            receipt_copy, _receipt_copy_sha = write_document_create_only(
                evidence_directory,
                admitted_receipt,
                identifier=admitted_receipt["receipt_id"],
                suffix="receipt.json",
            )
            plan_artifact = _artifact_descriptor(plan_copy)
            plan_artifact["file"] = plan_copy.relative_to(out.resolve()).as_posix()
            receipt_artifact = _artifact_descriptor(receipt_copy)
            receipt_artifact["file"] = (
                receipt_copy.relative_to(out.resolve()).as_posix()
            )
            acquisition_runtime_descriptor = {
                **acquisition_runtime_descriptor,
                "evidence": {
                    "plan": plan_artifact,
                    "receipt": receipt_artifact,
                },
                "selection": selection_descriptor,
            }
        else:
            acquisition_selection = build_runtime_selection(
                acquisition_requirements,
                input_bindings=input_bindings,
            )
            if args.model_acquisition_plan_only:
                raise ModelAcquisitionError(
                    "selected lane has no Hugging Face resources to acquire"
                )
            if supplied_runtime_values:
                raise ModelAcquisitionError(
                    "model-acquisition arguments are forbidden when no Hub "
                    "resource is selected"
                )
            acquisition_runtime_descriptor = {
                "selection": public_selection_descriptor(acquisition_selection),
                "status": "not_required",
            }
        acquisition_runtime_descriptor = validate_model_acquisition_descriptor(
            acquisition_runtime_descriptor,
            evidence_root=(
                out.resolve()
                if acquisition_requirements.requirements
                else None
            ),
        )
        acquisition_execution_descriptor = model_acquisition_execution_descriptor(
            acquisition_runtime_descriptor,
            evidence_root=(
                out.resolve()
                if acquisition_requirements.requirements
                else None
            ),
        )
        acquisition_shared_projection = model_acquisition_shared_role_projection(
            acquisition_execution_descriptor
        )
    except (KeyError, OSError, TypeError, ValueError) as exc:
        persist_request_error(
            phase="model_acquisition_admission",
            category="model_acquisition_invalid",
            exc=exc,
        )
        print(f"model acquisition admission failed: {exc}", file=sys.stderr)
        return 1

    # Rehash declared acquisition inputs before conversion. Selected conformance
    # is checked again afterward, so a file changed during conversion fails
    # closed before any target/judge construction.
    if source_conformance_manifest is not None:
        try:
            verify_manifest_components(
                source_conformance_manifest, selected_arms=real_source_arms
            )
        except (OSError, ValueError) as exc:
            persist_request_error(
                phase="source_conformance_input_preflight",
                category="source_integrity_failed",
                exc=exc,
            )
            print(f"source receipt input preflight failed: {exc}", file=sys.stderr)
            return 1

    # Preload the complete selected corpus set and construct lazy target objects
    # before any target/judge call. Modality coverage is a grid-wide property:
    # planning it one corpus at a time can silently omit an available image arm.
    loaded_corpora: dict[str, list[DataPoint]] = {}
    sampling_audits: dict[str, dict[str, object]] = {}
    for corpus_name in corpora:
        try:
            corpus, sampling_audit = load_corpus_with_audit(
                corpus_name,
                args.limit,
                args.sample_seed,
                sampling_policy=args.sampling_policy,
                source_instance=source_instances[corpus_name],
                exclude_tool_conditioned=args.exclude_tool_conditioned,
            )
            corpus, sampling_audit = apply_recovery_completed_prefix(
                corpus_name,
                corpus,
                sampling_audit,
                recovery_completed_prefix,
            )
            if not corpus:
                raise ValueError(
                    "requested corpus has no executable rows after excluding "
                    "tool-conditioned sources"
                    if args.exclude_tool_conditioned
                    and sampling_audit.get("excluded_tool_conditioned_count")
                    else "requested corpus converted to zero datapoints"
                )
            excluded_ids = sampling_audit.get("excluded_tool_conditioned_ids") or []
            if excluded_ids:
                print(
                    f"excluded {len(excluded_ids)} tool-conditioned row(s) from "
                    f"'{corpus_name}' (no Runner attacker can execute them yet): "
                    f"{', '.join(excluded_ids)}",
                    file=sys.stderr,
                )
        except Exception as exc:  # noqa: BLE001 - fail pre-call preflight
            persist_request_error(
                phase="corpus_preflight",
                category=(
                    "empty_converted_corpus"
                    if str(exc) == "requested corpus converted to zero datapoints"
                    else "conversion_failed"
                ),
                exc=exc,
                logical_source_arm=corpus_name,
            )
            print(
                f"corpus '{corpus_name}' preflight failed: "
                f"{type(exc).__name__}: {exc}", file=sys.stderr,
            )
            return 1
        loaded_corpora[corpus_name] = corpus
        sampling_audits[corpus_name] = sampling_audit

    if args.diagnostic_canary:
        selected_clusters = sampling_audits[corpora[0]].get("selected_clusters")
        if selected_clusters != 1:
            admission_error = ValueError(
                "diagnostic canary requires exactly one selected whole source cluster"
            )
            persist_request_error(
                phase="diagnostic_canary_cluster_admission",
                category="diagnostic_admission_failed",
                exc=admission_error,
                logical_source_arm=corpora[0],
            )
            print(
                "diagnostic canary admission failed: expected exactly one "
                "selected whole source cluster",
                file=sys.stderr,
            )
            return 1

    source_conformance_binding: dict[str, object] | None = None
    if source_conformance_manifest is not None:
        try:
            if not real_source_arms:
                raise ValueError(
                    "source conformance was supplied but no real source arm was selected"
                )
            if source_config_artifact is None:  # pragma: no cover - earlier gate
                raise ValueError("source conformance lacks source-config provenance")
            source_conformance_binding = validate_selected_source_conformance(
                source_conformance_manifest,
                selected_source_instances={
                    arm: source_instances[arm] for arm in real_source_arms
                },
                full_observations={
                    arm: sampling_audits[arm][
                        "full_source_conformance_observation"
                    ]
                    for arm in real_source_arms
                },
                sampling_audits={
                    arm: sampling_audits[arm] for arm in real_source_arms
                },
                source_config_selected_sha256=str(
                    source_config_artifact["normalized_selected_sha256"]
                ),
            )
            source_conformance_artifact.update(source_conformance_binding)
        except (OSError, ValueError) as exc:
            persist_request_error(
                phase="source_conformance_preflight",
                category="source_integrity_failed",
                exc=exc,
            )
            print(f"source conformance preflight failed: {exc}", file=sys.stderr)
            return 1

    # Admit every selected third-party engine before constructing an attacker,
    # target, judge, or defense object.  Each runtime starts one persistent sealed
    # worker for this matrix; private interpreter paths never enter run state.
    if engine_runtime_selection is not None:
        try:
            engine_runtime_selection.admit()
            engine_runtime_descriptor = engine_runtime_selection.identity_descriptor()
            _ACTIVE_ENGINE_RUNTIME_SELECTION = engine_runtime_selection
            run_env["engine_runtimes"] = engine_runtime_descriptor
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            cleanup_failure: Exception | None = None
            try:
                engine_runtime_selection.abort()
            except Exception as cleanup_exc:
                cleanup_failure = cleanup_exc
            reported = cleanup_failure or exc
            persist_request_error(
                phase="engine_runtime_admission",
                category="engine_runtime_invalid",
                exc=reported,
            )
            print(
                "engine runtime admission failed: "
                + safe_request_error_message(reported),
                file=sys.stderr,
            )
            return 1

    def close_engine_runtimes() -> dict[str, object] | None:
        global _ACTIVE_ENGINE_RUNTIME_SELECTION
        if engine_runtime_selection is None:
            return None
        descriptor = engine_runtime_selection.close()
        _ACTIVE_ENGINE_RUNTIME_SELECTION = None
        return descriptor

    prebuilt_targets: dict[str, object] = {}
    prebuilt_judge_target: object | None = None
    base_target_identities: list[frozenset[tuple[str, ...]]] = []
    target_execution_conditions: dict[str, str] = {}
    base_resolved_targets: dict[str, str] = {}
    route_kinds: dict[str, str] = {}
    route_config_digests: dict[str, str] = {}
    hosted_runtime_checks: list[dict[str, str]] = []
    current_eligibility_path: Path | None = None
    planned_attackers: dict[str, object] = {}
    planned_input_contracts: dict[
        tuple[str, str, str, int], AttackerInputContract
    ] = {}
    try:
        contract_budget = AttackBudget(
            max_queries=args.max_queries,
            max_turns=args.max_turns,
            seed=seeds[0],
        )
        for attacker_name in attacker_names:
            attacker = get_attacker(
                attacker_name,
                **_attacker_constructor_kwargs(
                    attacker_name,
                    attacker_configs,
                    model_runtime,
                    engine_runtime_selection,
                ),
            )
            if getattr(attacker, "runner_replay_eligible", True) is False:
                raise ValueError(
                    f"attacker {attacker_name!r} is a native-artifact integration "
                    "and cannot be replayed through Runner"
                )
            _component_config(attacker)
            planned_attackers[attacker_name] = attacker
            for corpus_name, corpus in loaded_corpora.items():
                attacker.validate_measured_run(corpus)
                for datapoint in corpus:
                    for seed in seeds:
                        contract = attacker.plan_target_inputs(
                            datapoint,
                            AttackBudget(
                                max_queries=contract_budget.max_queries,
                                max_turns=contract_budget.max_turns,
                                seed=seed,
                            ),
                        )
                        if (
                            contract.attacker != attacker.name
                            or contract.datapoint_id != datapoint.id
                        ):
                            raise ValueError(
                                "attacker input contract identity differs from its "
                                "CLI planning cell"
                            )
                        key = (corpus_name, attacker_name, datapoint.id, seed)
                        planned_input_contracts[key] = contract
        attacker_input_plan_projection = {
            "schema": "ura-grid-attacker-input-plan/1",
            "entries": [
                {
                    "logical_source_arm": arm,
                    "selected_attacker": attacker,
                    "seed": seed,
                    **contract.manifest_payload(),
                }
                for (arm, attacker, _datapoint_id, seed), contract
                in sorted(planned_input_contracts.items())
            ],
        }
        attacker_input_plan_projection["sha256"] = _sha256_json(
            attacker_input_plan_projection
        )
    except Exception as exc:  # noqa: BLE001 - no-call contract boundary
        persist_request_error(
            phase="attacker_input_contract_preflight",
            category="configuration_invalid",
            exc=exc,
        )
        _write_json(out / "attacker-input-contract.error.json", {
            "status": "error",
            "phase": "attacker_input_contract_preflight",
            "exception_type": type(exc).__name__,
            "message": str(exc)[:2000],
            "execution_started": False,
        })
        print(f"attacker input contract preflight failed: {exc}", file=sys.stderr)
        return 1
    (out / "attacker-input-contract.error.json").unlink(missing_ok=True)

    # Construct model-backed defenses only after every selected attacker,
    # datapoint, and seed has a valid prospective target-input contract.  This
    # keeps contract rejection a true zero-engine-load boundary.
    shared_defense_guard: object | None = None
    if args.defense != "none":
        if defense_guardrail_selected:
            from ura.judges.guardrail import GuardrailJudge

            shared_defense_guard = GuardrailJudge(
                model=args.defense_guardrail_model,
                revision=args.defense_guardrail_revision,
                device=args.defense_guardrail_device,
                model_runtime=model_runtime,
                managed_model_role="defense_guardrail",
            )
        else:
            shared_defense_guard = RuleJudge()
        _track_model_component(shared_defense_guard)

    def persist_eligibility_plan(
        target_failures: dict[str, dict[str, str]] | None = None,
        global_failures: list[dict[str, str]] | None = None,
        *,
        whole_request_preflight_complete: bool = False,
    ) -> tuple[dict[str, object], Path]:
        """Write the selected-cell admission/N/A ledger before any model call."""

        nonlocal current_eligibility_path

        clear_resolved_request_errors()

        compact_corpus_bindings = {
            arm: {
                "converter": source_instances[arm]["converter"],
                "full_converted_corpus_sha256": sampling_audits[arm][
                    "full_converted_corpus_sha256"
                ],
                "selected_converted_corpus_sha256": (
                    canonical_converted_corpus_sha256(loaded_corpora[arm])
                ),
                "selected_datapoint_ids_sha256": _sha256_json(sorted(
                    datapoint.id for datapoint in loaded_corpora[arm]
                )),
                "selected_records": len(loaded_corpora[arm]),
                "sample_seed": args.sample_seed,
                "limit": args.limit,
                **sampling_policy_binding,
            }
            for arm in sorted(loaded_corpora)
        }
        targets_by_request = {
            requested_model_specs[spec]: target
            for spec, target in prebuilt_targets.items()
        }
        failures_by_request = {
            requested_model_specs[spec]: failure
            for spec, failure in (target_failures or {}).items()
        }
        selected_artifact_identities = {
            "source_config": _selected_config_artifact_identity(
                source_config_artifact
            ),
            "source_conformance": _content_artifact_identity(
                source_conformance_artifact
            ),
            "attacker_config": _selected_config_artifact_identity(
                attacker_config_artifact
            ),
            "engine_runtime_config": _selected_config_artifact_identity(
                engine_runtime_config_artifact
            ),
            "api_config": _selected_config_artifact_identity(api_config_artifact),
            "local_config": _selected_config_artifact_identity(
                local_config_artifact
            ),
        }
        experiment_condition_values = {
            "execution_purpose": execution_purpose,
            "project_revision": project_revision_state,
            "defense": args.defense,
            "defense_guard": args.defense_guard,
            "judges": judge_names,
            "judge_model": persisted_judge_model,
            "guardrail_model": (
                args.guardrail_model if scoring_guardrail_selected else None
            ),
            "guardrail_revision": (
                args.guardrail_revision.lower() if scoring_guardrail_selected else None
            ),
            "guardrail_device": (
                (args.guardrail_device or None) if scoring_guardrail_selected else None
            ),
            "defense_guardrail_model": (
                args.defense_guardrail_model if defense_guardrail_selected else None
            ),
            "defense_guardrail_revision": (
                args.defense_guardrail_revision.lower()
                if defense_guardrail_selected else None
            ),
            "defense_guardrail_device": (
                args.defense_guardrail_device if defense_guardrail_selected else None
            ),
            "seeds": seeds,
            "sample_seed": args.sample_seed,
            "limit": args.limit,
            **sampling_policy_binding,
            "max_queries": args.max_queries,
            "max_turns": args.max_turns,
            "target_answer_retries": args.target_answer_retries,
            "recovery_selection": recovery_selection_binding,
            "call_caps": {
                "target": args.max_total_target_calls or None,
                "judge": args.max_total_judge_calls or None,
                "http_attempts": args.max_total_http_attempts or None,
                "deadline_seconds": args.deadline_seconds or None,
            },
            "group_keys": group_keys,
            "quantization": args.quantization,
            "dtype": args.dtype,
            "dry_run": bool(args.dry_run),
            "hosted_judge_data_transfer_acknowledged": bool(
                args.ack_hosted_judge_data_transfer
            ),
            "selected_config_identities": selected_artifact_identities,
            "engine_runtimes": engine_runtime_descriptor,
            "model_acquisition": acquisition_shared_projection,
            "live_attestation": live_attestation_projection,
        }
        experiment_conditions = {
            "condition_id": (
                "condition-" + _sha256_json(experiment_condition_values)[:24]
            ),
            "values": experiment_condition_values,
        }
        plan = build_eligibility_plan(
            requested_targets=[requested_model_specs[spec] for spec in model_specs],
            targets=targets_by_request,
            corpora=loaded_corpora,
            attackers=attacker_names,
            attacker_input_contracts=planned_input_contracts,
            target_failures=failures_by_request,
            global_failures=global_failures or (),
            dry_run=bool(args.dry_run),
            approximate_common_metrics=bool(args.approximate_common_metrics),
            whole_request_preflight_complete=whole_request_preflight_complete,
            bindings={
                "driver_source": driver_source,
                "project_revision": project_revision_state,
                "request_envelope": request_envelope_artifact,
                "source_instances_sha256": _sha256_json(source_instances),
                "attacker_configs_sha256": _sha256_json(portable_attacker_configs),
                "attacker_input_plan": attacker_input_plan_projection,
                "api_configs_sha256": _sha256_json(api_configs),
                "local_configs_sha256": _sha256_json({
                    persisted_model_specs[spec]: local_configs[spec]
                    for spec in local_specs
                }),
                "selected_config_identities": selected_artifact_identities,
                "engine_runtimes": engine_runtime_descriptor,
                "model_acquisition": acquisition_execution_descriptor,
                "experiment_conditions": experiment_conditions,
                "selected_corpora": compact_corpus_bindings,
            },
        )
        path = out / f"{plan['plan_id']}.eligibility.json"
        _write_json(path, plan)
        (out / "eligibility-plan.error.json").unlink(missing_ok=True)
        if current_eligibility_path is not None and current_eligibility_path != path:
            current_eligibility_path.unlink(missing_ok=True)
        current_eligibility_path = path
        print(
            "eligibility/N/A plan written: "
            + json.dumps({
                "artifact": path.name,
                "plan_id": plan["plan_id"],
                "counts": plan["counts"],
            }, sort_keys=True, separators=(",", ":"))
        )
        return plan, path

    for spec in model_specs:
        setup_phase = "target_construction"
        try:
            target = build_target(
                spec,
                quantization=args.quantization,
                dtype=args.dtype,
                local_identity=local_configs.get(spec),
                api_config=api_configs.get(spec),
                model_runtime=model_runtime,
                managed_model_role="vllm_target",
            )
            _track_model_component(target)
            if spec.startswith("vllm:"):
                _require_local_hardware_fit(
                    target, spec, local_configs[spec], gpu_hardware
                )
            base_target_identities.append(_precall_model_identity(target))
            requested_spec = requested_model_specs[spec]
            target_execution_conditions[requested_spec] = (
                _target_execution_condition_identity(target)
            )
            base_resolved_targets[requested_spec] = str(getattr(target, "name"))
            route_kind = (
                "local_runtime"
                if spec.startswith(("vllm:", "ollama:"))
                else "hosted_api"
            )
            route_kinds[requested_spec] = route_kind
            route_config_digests[requested_spec] = route_config_sha256(
                route_kind=route_kind,
                requested_target_spec=requested_spec,
                resolved_target=base_resolved_targets[requested_spec],
                route_config=(
                    local_configs.get(spec)
                    if route_kind == "local_runtime"
                    else api_configs.get(spec)
                ),
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
                if shared_defense_guard is None:  # pragma: no cover - invariant
                    raise RuntimeError("defense guard was not constructed")
                target = GuardedTarget(target, shared_defense_guard, mode=args.defense)
            prebuilt_targets[spec] = target
            persisted_model_specs[spec] = str(getattr(target, "name"))
            for corpus_name in corpora:
                for stale_spec in {
                    requested_model_specs[spec], persisted_model_specs[spec]
                }:
                    (out / (
                        "__".join((
                            _safe_component(corpus_name),
                            _safe_component(stale_spec),
                            "target-setup",
                        )) + ".error.json"
                    )).unlink(missing_ok=True)
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
                f"target '{persisted_model_specs[spec]}' preflight failed: "
                f"{type(exc).__name__}: "
                + _artifact_safe_model_error(
                    exc, spec, persisted_model_specs[spec]
                ),
                file=sys.stderr,
            )
            failure_map: dict[str, dict[str, str]] = {}
            for requested_spec in model_specs:
                if requested_spec in prebuilt_targets:
                    continue
                if requested_spec == spec:
                    failure_map[requested_spec] = {
                        "gate": setup_phase,
                        "reason": _artifact_safe_model_error(
                            exc, spec, requested_model_specs[spec]
                        ),
                    }
                else:
                    failure_map[requested_spec] = {
                        "gate": "target_setup_not_attempted",
                        "reason": (
                            "target setup was not attempted after an earlier "
                            "requested target failed preflight"
                        ),
                    }
            try:
                persist_eligibility_plan(failure_map)
            except Exception as eligibility_exc:  # noqa: BLE001 - diagnostic only
                _write_json(out / "eligibility-plan.error.json", {
                    "status": "error",
                    "phase": "eligibility_plan",
                    "exception_type": type(eligibility_exc).__name__,
                    "message": str(eligibility_exc)[:2000],
                })
            return 1
    seen_target_identity_keys: set[tuple[tuple[str, ...], str]] = set()
    duplicate_target_identity = False
    for spec, identity_keys in zip(model_specs, base_target_identities):
        requested_spec = requested_model_specs[spec]
        condition = target_execution_conditions[requested_spec]
        condition_keys = {(identity, condition) for identity in identity_keys}
        if seen_target_identity_keys & condition_keys:
            duplicate_target_identity = True
        seen_target_identity_keys.update(condition_keys)
    if duplicate_target_identity:
        persist_eligibility_plan()
        ap.error("target specs resolve to duplicate runtime target identities")
    configured_guard_identities = []
    if scoring_guardrail_selected:
        configured_guard_identities.append((
            "scoring guardrail",
            _pinned_hub_model_identity(
                args.guardrail_model, args.guardrail_revision
            ),
        ))
    if defense_guardrail_selected:
        configured_guard_identities.append((
            "defense guardrail",
            _pinned_hub_model_identity(
                args.defense_guardrail_model,
                args.defense_guardrail_revision,
            ),
        ))
    for role, guard_identity in configured_guard_identities:
        if guard_identity and any(
            guard_identity & target_identity
            for target_identity in base_target_identities
        ):
            persist_eligibility_plan()
            ap.error(
                f"the {role} must differ from every model under test; "
                "a target model cannot grade or guard itself"
            )
    if "llm" in judge_names:
        try:
            prebuilt_judge_target = build_target(
                args.judge_model,
                quantization=args.quantization,
                dtype=args.dtype,
                local_identity=local_configs.get(args.judge_model),
                api_config=api_configs.get(args.judge_model),
                model_runtime=model_runtime,
                managed_model_role="llm_judge",
            )
            _track_model_component(prebuilt_judge_target)
            if local_judge_spec is not None:
                _require_local_hardware_fit(
                    prebuilt_judge_target,
                    args.judge_model,
                    local_configs[args.judge_model],
                    gpu_hardware,
                )
            judge_identity = _precall_model_identity(prebuilt_judge_target)
            if not args.dry_run and any(
                judge_identity & target_identity
                for target_identity in base_target_identities
            ):
                raise ValueError(
                    "the LLM judge must differ from every model under test; "
                    f"resolved identity {judge_identity!r} is self-certifying"
                )
            if args.preflight_only:
                readiness = preflight_api_target_runtime(prebuilt_judge_target)
                if readiness is not None:
                    hosted_runtime_checks.append({
                        "role": "judge",
                        "model_spec": persisted_judge_model,
                        **readiness,
                    })
        except Exception as exc:  # noqa: BLE001 - fail no-call preflight
            error_path = out / "judge-runtime-preflight.error.json"
            _write_json(error_path, {
                "status": "error",
                "phase": "judge_runtime_preflight",
                "preflight": True,
                "role": "judge",
                "model_spec": persisted_judge_model,
                "exception_type": type(exc).__name__,
                "message": _artifact_safe_model_error(
                    exc, args.judge_model, persisted_judge_model or "unknown"
                ),
            })
            print(
                "judge runtime preflight failed: "
                f"{type(exc).__name__}: "
                + _artifact_safe_model_error(
                    exc, args.judge_model, persisted_judge_model or "unknown"
                ),
                file=sys.stderr,
            )
            persist_eligibility_plan(global_failures=[{
                "gate": "judge_runtime_preflight",
                "reason": _artifact_safe_model_error(
                    exc, args.judge_model, persisted_judge_model or "unknown"
                ),
            }])
            return 1
    (out / "judge-runtime-preflight.error.json").unlink(missing_ok=True)
    # Remove the pre-generic artifact name after a successful retry.
    (out / "judge-hosted-runtime-preflight.error.json").unlink(missing_ok=True)
    eligibility_plan, eligibility_path = persist_eligibility_plan()
    try:
        modality_plan = plan_modality_coverage(
            list(prebuilt_targets.values()), loaded_corpora,
            attacker_input_contracts=planned_input_contracts,
            enforce_available=not args.dry_run,
        )
    except (OSError, ValueError, ModalityCoverageError) as exc:
        eligibility_plan, eligibility_path = persist_eligibility_plan(
            global_failures=[{
                "gate": "modality_coverage_preflight",
                "reason": str(exc)[:2000],
            }]
        )
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
        for target in prebuilt_targets.values():
            validator = getattr(target, "validate_research_identity", None)
            if callable(validator):
                validator()
        if prebuilt_judge_target is not None:
            validator = getattr(prebuilt_judge_target, "validate_research_identity", None)
            if callable(validator):
                validator()
        planned_cascade = build_judges(
            judge_names,
            args.judge_model,
            judge_api_config=api_configs.get(args.judge_model),
            judge_target=prebuilt_judge_target,
            guardrail_model=args.guardrail_model,
            guardrail_revision=args.guardrail_revision,
            guardrail_device=args.guardrail_device,
            model_runtime=model_runtime,
        )
        for stage in planned_cascade.stages:
            _track_model_component(stage)
        _component_config(planned_cascade)
        admission_failures: list[dict[str, str]] = []
        for spec, target in prebuilt_targets.items():
            for corpus_name, corpus in loaded_corpora.items():
                for attacker_name, attacker in planned_attackers.items():
                    try:
                        Runner(
                            attacker,
                            target,
                            planned_cascade,
                            AttackBudget(
                                max_queries=args.max_queries,
                                max_turns=args.max_turns,
                                seed=seeds[0],
                            ),
                            seeds,
                            approximate_common_metrics=bool(
                                args.approximate_common_metrics
                            ),
                            approximate_evidence_class=(
                                "synthetic" if args.dry_run else "measured"
                            ),
                            target_answer_retries=args.target_answer_retries,
                            stop_on_failed_output=spec in api_specs,
                        ).plan_manifest(
                            corpus,
                            started_at=run_started,
                            env=run_env,
                            run_config={
                                "preflight_admission": True,
                                "execution_purpose": execution_purpose,
                                "model_spec": persisted_model_specs[spec],
                                "corpus": corpus_name,
                                "attacker": attacker_name,
                                "approximate_common_metrics": bool(
                                    args.approximate_common_metrics
                                ),
                                "target_answer_retries": args.target_answer_retries,
                                "stop_on_failed_output": spec in api_specs,
                                "recovery_selection": recovery_selection_binding,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001 - audit all cells
                        admission_failures.append({
                            "model_spec": persisted_model_specs[spec],
                            "corpus": corpus_name,
                            "attacker": attacker_name,
                            "exception_type": type(exc).__name__,
                            "message": str(exc)[:1000],
                        })
        if admission_failures:
            rendered = json.dumps(
                admission_failures[:8],
                sort_keys=True,
                separators=(",", ":"),
            )
            suffix = (
                f"; and {len(admission_failures) - 8} more"
                if len(admission_failures) > 8
                else ""
            )
            raise ValueError(
                "whole-execution Runner.plan_manifest admission rejected "
                f"{len(admission_failures)} requested cell(s): {rendered}{suffix}"
            )
        policy_strata = {
            name: _source_policy_cluster_counts(rows)
            for name, rows in loaded_corpora.items()
        }
        # The selected rows have already passed Runner's byte-level corpus
        # admission above. Reuse the compact conformance projection to retain
        # selected media-byte pressure without inventing expected output size.
        selected_media_inventories = {
            name: observed_arm_conformance(rows)["media"]
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
            target_answer_retries=args.target_answer_retries,
            approximate_common_metrics=bool(args.approximate_common_metrics),
        )
        _validate_planned_call_budget(
            call_projection,
            target=args.max_total_target_calls,
            judge=args.max_total_judge_calls,
            http=args.max_total_http_attempts,
            deadline_seconds=args.deadline_seconds,
            dry_run=bool(args.dry_run),
            # Every provider-backed invocation is admitted only when its hard
            # ceilings cover the complete conservative projection.  A smaller
            # value is not a harmless safety cap: it would deliberately create
            # a partial grid after paid calls and weaken the fixed-universe
            # accounting contract.  Use a separately typed diagnostic canary
            # with a prospectively smaller selected cluster universe instead.
            require_complete=not bool(args.dry_run),
        )
    except Exception as exc:  # noqa: BLE001 - fail closed at the pre-call boundary
        eligibility_plan, eligibility_path = persist_eligibility_plan(
            global_failures=[{
                "gate": "grid_planning_preflight",
                "reason": str(exc)[:2000],
            }]
        )
        _write_json(out / "grid-planning.error.json", {
            "status": "error",
            "phase": "grid_planning_preflight",
            "exception_type": type(exc).__name__,
            "message": str(exc),
        })
        print(f"grid planning preflight failed: {exc}", file=sys.stderr)
        return 1
    attested_target_identities: dict[str, dict[str, str]] = {}
    if live_attestation_projection["mode"] == "measured":
        try:
            required_live_keys = required_attestation_keys(
                execution_scope_id=scope_id,
                requested_target_specs=requested_model_specs.values(),
                eligibility_items=eligibility_plan["items"],
            )
            admitted_live_records = validate_required_live_attestations(
                live_attestation_manifests,
                required_keys=required_live_keys,
                resolved_targets=base_resolved_targets,
                route_config_sha256=route_config_digests,
                route_kind=route_kinds,
                target_condition_sha256=target_execution_conditions,
                current_harness_source_sha256=str(harness_source["sha256"]),
                current_driver_source_sha256=str(driver_source["sha256"]),
                current_project_revision=project_revision_state,
                reference_time=datetime.fromisoformat(run_started),
                max_age_hours=args.live_attestation_max_age_hours,
            )
            for key, record in admitted_live_records.items():
                requested_spec = key[1]
                identity = dict(record["realized_target_identity"])
                prior = attested_target_identities.setdefault(
                    requested_spec, identity
                )
                if stable_realized_target_identity(
                    prior
                ) != stable_realized_target_identity(identity):
                    raise ValueError(
                        "one requested target has conflicting admitted identities"
                    )
        except (KeyError, TypeError, ValueError) as exc:
            eligibility_plan, eligibility_path = persist_eligibility_plan(
                global_failures=[{
                    "gate": "live_attestation_preflight",
                    "reason": str(exc)[:2000],
                }]
            )
            _write_json(out / "live-attestation.error.json", {
                "status": "error",
                "phase": "live_attestation_preflight",
                "exception_type": type(exc).__name__,
                "message": str(exc)[:2000],
                "live_attestation": live_attestation_projection,
            })
            print(f"live attestation preflight failed: {exc}", file=sys.stderr)
            return 1
    eligibility_plan, eligibility_path = persist_eligibility_plan(
        whole_request_preflight_complete=True
    )
    try:
        lane_projection = build_lane_projection(
            eligibility_plan=eligibility_plan,
            eligibility_artifact=_artifact_descriptor(eligibility_path),
            sampling_audits=sampling_audits,
            source_policy_cluster_counts=policy_strata,
            selected_media_inventories=selected_media_inventories,
            call_projection=call_projection,
        )
        lane_projection_path = write_lane_projection(out, lane_projection)
    except (OSError, TypeError, ValueError) as exc:
        _write_json(out / "lane-projection.error.json", {
            "status": "error",
            "phase": "lane_projection_persistence",
            "exception_type": type(exc).__name__,
            "message": str(exc)[:2000],
        })
        print(f"lane projection persistence failed: {exc}", file=sys.stderr)
        return 1
    (out / "live-attestation.error.json").unlink(missing_ok=True)
    (out / "grid-planning.error.json").unlink(missing_ok=True)
    (out / "lane-projection.error.json").unlink(missing_ok=True)
    for corpus_name, counts in policy_strata.items():
        print(
            f"plan '{corpus_name}' source-policy clusters: "
            + json.dumps(counts, sort_keys=True, separators=(",", ":"))
        )
    print(
        "planned complete-grid call upper bounds: "
        + json.dumps(call_projection, sort_keys=True, separators=(",", ":"))
    )
    print(
        "prospective no-call lane projection written: "
        + json.dumps({
            "artifact": lane_projection_path.name,
            "projection_id": lane_projection["projection_id"],
        }, sort_keys=True, separators=(",", ":"))
    )

    grid_request = {
        "execution_purpose": execution_purpose,
        "project_revision": project_revision_state,
        "request_envelope": request_envelope_artifact,
        "models": [persisted_model_specs[spec] for spec in model_specs],
        "target_execution_conditions": dict(sorted(
            target_execution_conditions.items()
        )),
        "corpora": corpora,
        "source_instances": source_instances,
        "source_config_artifact": source_config_artifact,
        "source_conformance_artifact": source_conformance_artifact,
        "attackers": attacker_names,
        "attacker_configs": portable_attacker_configs,
        "attacker_config_artifact": attacker_config_artifact,
        "engine_runtimes": engine_runtime_descriptor,
        "engine_runtime_config_artifact": engine_runtime_config_artifact,
        "api_configs": portable_api_configs,
        "api_config_artifact": api_config_artifact,
        "local_configs": {
            persisted_model_specs[spec]: local_configs[spec]
            for spec in local_specs
        },
        "local_config_artifact": local_config_artifact,
        "judges": judge_names,
        "judge_model": persisted_judge_model,
        "hosted_judge_data_transfer_acknowledged": bool(
            args.ack_hosted_judge_data_transfer
        ),
        "judge_api_config": portable_api_configs.get(args.judge_model),
        "judge_local_identity": local_configs.get(args.judge_model),
        "guardrail_model": (
            args.guardrail_model if scoring_guardrail_selected else None
        ),
        "guardrail_revision": (
            args.guardrail_revision.lower() if scoring_guardrail_selected else None
        ),
        "guardrail_device": (
            (args.guardrail_device or None) if scoring_guardrail_selected else None
        ),
        "defense_guardrail_model": (
            args.defense_guardrail_model if defense_guardrail_selected else None
        ),
        "defense_guardrail_revision": (
            args.defense_guardrail_revision.lower()
            if defense_guardrail_selected else None
        ),
        "defense_guardrail_device": (
            args.defense_guardrail_device if defense_guardrail_selected else None
        ),
        "seeds": seeds,
        "sample_seed": args.sample_seed,
        "limit": args.limit,
        **sampling_policy_binding,
        "max_queries": args.max_queries,
        "max_turns": args.max_turns,
        "target_answer_retries": args.target_answer_retries,
        "recovery_selection": recovery_selection_binding,
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
        "resolved_quantizations": {
            persisted_model_specs[spec]: resolved_quantizations[spec]
            for spec in model_specs
            if spec in resolved_quantizations
        },
        "gpu_hardware": gpu_hardware,
        "dtype": args.dtype,
        "dry_run": bool(args.dry_run),
        "approximate_common_metrics": bool(args.approximate_common_metrics),
        "attestation_probe": bool(args.attestation_probe),
        "live_attestation": live_attestation_projection,
        "model_acquisition": acquisition_runtime_descriptor,
        "model_acquisition_execution": acquisition_execution_descriptor,
        "driver_source": driver_source,
        "harness_source": harness_source,
        "eligibility_plan": {
            "plan_id": eligibility_plan["plan_id"],
            **_artifact_descriptor(eligibility_path),
            "counts": eligibility_plan["counts"],
        },
        "lane_projection": {
            "projection_id": lane_projection["projection_id"],
            **_artifact_descriptor(lane_projection_path),
        },
        "modality_coverage_plan": modality_plan_payload,
        "source_policy_cluster_counts": policy_strata,
        "call_projection": call_projection,
    }
    try:
        validate_model_acquisition_grid_binding(
            acquisition_execution_descriptor,
            grid_request,
        )
    except (TypeError, ValueError) as exc:
        persist_request_error(
            phase="model_acquisition_admission",
            category="model_acquisition_invalid",
            exc=exc,
        )
        print(f"model acquisition grid binding failed: {exc}", file=sys.stderr)
        return 1
    # Keep complete reusable-registry provenance in the grid artifact while
    # excluding unselected roster entries from execution identity.  The
    # normalized selected configs above, plus these selected-subset digests,
    # still bind every requested execution condition exactly.
    grid_identity_request = {
        **grid_request,
        # A receipt is a timestamped audit event. Scientific/grid identity is
        # instead the validated immutable plan + manifest + complete tree seal,
        # so reacquiring unchanged cached bytes cannot fragment resume/cohorts.
        "model_acquisition": acquisition_execution_descriptor,
        "source_config_artifact": _selected_config_artifact_identity(
            source_config_artifact
        ),
        "source_conformance_artifact": _content_artifact_identity(
            source_conformance_artifact
        ),
        "attacker_config_artifact": _selected_config_artifact_identity(
            attacker_config_artifact
        ),
        "engine_runtime_config_artifact": _selected_config_artifact_identity(
            engine_runtime_config_artifact
        ),
        "api_config_artifact": _selected_config_artifact_identity(
            api_config_artifact
        ),
        "local_config_artifact": _selected_config_artifact_identity(
            local_config_artifact
        ),
    }
    grid_material = json.dumps(
        grid_identity_request, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    grid_id = f"grid-{hashlib.sha256(grid_material).hexdigest()[:24]}"
    grid_path = out / f"{grid_id}.grid.json"
    grid_lock = out / f"{grid_id}.grid.lock"
    budget_path = out / f"{grid_id}.budget.json"
    circuit_path = out / f"{grid_id}.circuits.json"
    circuits: dict[str, dict[str, object]] = {}

    if args.preflight_only:
        try:
            recheck_bound_project_revision()
            engine_runtime_close_descriptor = close_engine_runtimes()
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            print(f"preflight closing verification failed: {exc}", file=sys.stderr)
            return 1
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
            "calls were made; isolated engine closing seals passed"
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
        for key in ("budget", "judge", "paid_provider", target_key):
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
            budget_deadline = (
                existing_budget.get("deadline_epoch")
                if isinstance(existing_budget, dict) else None
            )
            if budget_deadline is None:
                deadline_epoch = invocation_deadline_epoch
            elif invocation_deadline_epoch is None:
                deadline_epoch = budget_deadline
            else:
                deadline_epoch = min(
                    float(budget_deadline), invocation_deadline_epoch
                )
        else:
            deadline_epoch = invocation_deadline_epoch
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
        # Every zero-engine gate is now complete: exact whole-grid projection,
        # call ceilings, live-attestation admission, durable ledger recovery,
        # and the first-invocation deadline. Only now may a surrogate, local
        # target, judge, or guard load already-receipted offline model weights.
        call_budget.raise_if_deadline_reached()
        for attacker in planned_attackers.values():
            call_budget.raise_if_deadline_reached()
            preflight = getattr(attacker, "preflight", None)
            if callable(preflight):
                preflight()
            call_budget.raise_if_deadline_reached()
        for target in prebuilt_targets.values():
            call_budget.raise_if_deadline_reached()
            base_preflight = getattr(target, "preflight_base", None)
            if callable(base_preflight):
                base_preflight()
            call_budget.raise_if_deadline_reached()
        if prebuilt_judge_target is not None:
            call_budget.raise_if_deadline_reached()
            base_preflight = getattr(prebuilt_judge_target, "preflight_base", None)
            if callable(base_preflight):
                base_preflight()
            call_budget.raise_if_deadline_reached()
        if shared_defense_guard is not None:
            call_budget.raise_if_deadline_reached()
            preflight = getattr(shared_defense_guard, "preflight", None)
            if callable(preflight):
                preflight()
            call_budget.raise_if_deadline_reached()
        # Reuse one loaded local model-backed judge cascade across cells.
        for stage in planned_cascade.stages:
            call_budget.raise_if_deadline_reached()
            preflight = getattr(stage, "preflight", None)
            if callable(preflight):
                preflight()
            call_budget.raise_if_deadline_reached()
        # Reset only after every durable failure/recovery artifact has been
        # validated against the ledger. Otherwise reset could erase the sole
        # high-water evidence for a paid failed call.
        if args.reset_open_circuits:
            circuit_path.unlink(missing_ok=True)
            circuits = {}
        else:
            circuits = persisted_circuits
    except Exception as exc:  # noqa: BLE001 - zero-call lifecycle boundary
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
    deferred_engine_completions: list[dict[str, object]] = []
    executed_modality_evidence: dict[
        str, set[tuple[str, str, tuple[str, ...]]]
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
                for attacker_name in attacker_names:
                    circuit_error = out / (
                        "__".join((
                            _safe_component(corpus_name),
                            _safe_component(persisted_model_specs[spec]),
                            _safe_component(attacker_name),
                            "circuit-open",
                        ))
                        + ".error.json"
                    )
                    _write_json(circuit_error, {
                        "status": "error",
                        "grid_id": grid_id,
                        "run_id": None,
                        "phase": "circuit_open",
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "circuit_key": circuit_key,
                        "circuit": circuit,
                        "call_budget_snapshot": call_budget.snapshot(),
                        "execution_started": False,
                    })
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "run_id": None,
                        "status": "error",
                        "phase": "circuit_open",
                        "execution_started": False,
                        "error_artifact": _artifact_descriptor(circuit_error),
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
                        "grid_id": grid_id,
                        "run_id": None,
                        "phase": "circuit_open",
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "circuit_key": circuit_key,
                        "circuit": circuit,
                        "call_budget_snapshot": call_budget.snapshot(),
                        "execution_started": False,
                    })
                    cell_statuses.append({
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "attacker": attacker_name,
                        "run_id": None,
                        "status": "error",
                        "phase": "circuit_open",
                        "execution_started": False,
                        "error_artifact": _artifact_descriptor(fallback_error),
                    })
                    continue
                try:
                    attacker_config = _attacker_constructor_kwargs(
                        attacker_name,
                        attacker_configs,
                        model_runtime,
                        engine_runtime_selection,
                    )
                    attacker = (
                        planned_attackers[attacker_name]
                        if attacker_name.lower() == "nanogcg"
                        else get_attacker(attacker_name, **attacker_config)
                    )
                    if getattr(attacker, "runner_replay_eligible", True) is False:
                        raise ValueError(
                            f"attacker {attacker_name!r} is a native-artifact "
                            "integration and cannot be replayed through Runner"
                        )
                    runner = Runner(
                        attacker,
                        target,
                        planned_cascade,
                        AttackBudget(
                            max_queries=args.max_queries,
                            max_turns=args.max_turns,
                            seed=seeds[0],
                        ),
                        seeds,
                        call_budget=call_budget,
                        expected_target_identity=attested_target_identities.get(
                            requested_model_specs[spec]
                        ),
                        approximate_common_metrics=bool(
                            args.approximate_common_metrics
                        ),
                        approximate_evidence_class=(
                            "synthetic" if args.dry_run else "measured"
                        ),
                        target_answer_retries=args.target_answer_retries,
                        stop_on_failed_output=spec in api_specs,
                    )
                    cell_config = {
                        "grid_id": grid_id,
                        "execution_purpose": execution_purpose,
                        "project_revision": project_revision_state,
                        "request_envelope": request_envelope_artifact,
                        "corpus": corpus_name,
                        "limit": args.limit,
                        "sample_seed": args.sample_seed,
                        **sampling_policy_binding,
                        "sampling_audit": sampling_audit,
                        "recovery_selection": recovery_selection_binding,
                        "source_conformance_artifact": (
                            _content_artifact_identity(
                                source_conformance_artifact
                            )
                        ),
                        "model_spec": persisted_model_specs[spec],
                        "api_config": portable_api_configs.get(spec),
                        "api_config_artifact": _selected_config_artifact_identity(
                            api_config_artifact
                        ),
                        "local_identity": local_configs.get(spec),
                        "attacker": attacker_name,
                        "attacker_config": portable_attacker_configs.get(
                            attacker_name.lower(), {}
                        ),
                        "engine_runtime": (
                            engine_runtime_identity_descriptor(
                                engine_runtime_selection.runtime_for(
                                    attacker_name.lower()
                                ).public_descriptor()
                            )
                            if (
                                engine_runtime_selection is not None
                                and attacker_name.lower()
                                in RUNTIME_REQUIRED_ATTACKERS
                            )
                            else {
                                "schema": "ura-engine-runtime-not-required/1",
                                "framework_execution": (
                                    "not_invoked"
                                    if attacker_name.lower() == "nanogcg"
                                    else None
                                ),
                            }
                        ),
                        "judge_names": judge_names,
                        "judge_model": persisted_judge_model,
                        "hosted_judge_data_transfer_acknowledged": bool(
                            args.ack_hosted_judge_data_transfer
                        ),
                        "judge_api_config": portable_api_configs.get(args.judge_model),
                        "judge_local_identity": local_configs.get(args.judge_model),
                        "guardrail_model": (
                            args.guardrail_model
                            if scoring_guardrail_selected else None
                        ),
                        "guardrail_revision": (
                            args.guardrail_revision.lower()
                            if scoring_guardrail_selected else None
                        ),
                        "guardrail_device": (
                            (args.guardrail_device or None)
                            if scoring_guardrail_selected else None
                        ),
                        "defense_guardrail_model": (
                            args.defense_guardrail_model
                            if defense_guardrail_selected else None
                        ),
                        "defense_guardrail_revision": (
                            args.defense_guardrail_revision.lower()
                            if defense_guardrail_selected else None
                        ),
                        "defense_guardrail_device": (
                            args.defense_guardrail_device
                            if defense_guardrail_selected else None
                        ),
                        "group_keys": group_keys,
                        "defense": args.defense,
                        "defense_guard": args.defense_guard,
                        "quantization": args.quantization,
                        "resolved_quantization": resolved_quantizations.get(spec),
                        "dtype": args.dtype,
                        "dry_run": bool(args.dry_run),
                        "approximate_common_metrics": bool(
                            args.approximate_common_metrics
                        ),
                        "target_answer_retries": args.target_answer_retries,
                        "stop_on_failed_output": spec in api_specs,
                        "attestation_probe": bool(args.attestation_probe),
                        "live_attestation": live_attestation_projection,
                        "expected_target_identity": (
                            attested_target_identities.get(
                                requested_model_specs[spec]
                            )
                        ),
                        "driver_source": driver_source,
                        "global_call_budget": grid_request["global_call_budget"],
                        "modality_coverage_plan": modality_plan_payload,
                    }
                    cell_config["model_acquisition"] = (
                        model_acquisition_cell_role_projection(
                            acquisition_execution_descriptor,
                            cell_config,
                        )
                    )
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
                    recheck_bound_project_revision()
                    if paths["complete"].is_file():
                        _validate_completion_marker(
                            paths,
                            planned,
                            required,
                            acquisition_execution_descriptor,
                        )
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

                    if attacker_name.lower() in RUNTIME_REQUIRED_ATTACKERS:
                        discarded = _discard_unsealed_engine_cell_state(paths)
                        if discarded:
                            print(
                                f"  [{stem}] discarded {len(discarded)} unsealed "
                                "cross-session runtime artifact(s); regenerating"
                            )
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
                        "completed_at": time.time(),
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
                        # A runtime-backed cell remains pending until the global
                        # worker closing seal is projected here. Replay cells
                        # explicitly carry no such observation.
                        "engine_runtime_close": None,
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
                            validation_paths,
                            planned,
                            required,
                            acquisition_execution_descriptor,
                            allow_pending_engine_runtime_close=(
                                attacker_name.lower() in RUNTIME_REQUIRED_ATTACKERS
                            ),
                        )
                        recheck_bound_project_revision()
                    except Exception:
                        pending_complete.unlink(missing_ok=True)
                        raise
                    status_entry: dict[str, object] = {
                        "corpus": corpus_name,
                        "model_spec": persisted_model_specs[spec],
                        "target": target.name,
                        "attacker": attacker_name,
                        "run_id": manifest.run_id,
                        "status": "pending_engine_runtime_seal",
                        "completion_marker": pending_complete.name,
                    }
                    if attacker_name.lower() in RUNTIME_REQUIRED_ATTACKERS:
                        deferred_engine_completions.append({
                            "pending": pending_complete,
                            "complete": paths["complete"],
                            "checkpoint": paths["checkpoint"],
                            "response_checkpoint": paths["response_checkpoint"],
                            "error": paths["error"],
                            "fallback_error": fallback_error,
                            "corpus": corpus_name,
                            "model_spec": persisted_model_specs[spec],
                            "attacker": attacker_name,
                            "stem": stem,
                            "status_entry": status_entry,
                            "paths": dict(paths),
                            "planned": planned,
                            "required": required,
                        })
                        print(
                            f"  [{stem}] {len(judgments)} judgments -> {len(results)} "
                            "results pending the isolated-engine closing seal"
                        )
                    else:
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
                        status_entry["status"] = "complete"
                        status_entry["completion_marker"] = paths["complete"].name
                        print(
                            f"  [{stem}] {len(judgments)} judgments -> {len(results)} "
                            f"results (run {manifest.run_id}; resumed {len(resumed)})"
                        )
                        n_cells += 1
                    cell_statuses.append(status_entry)
                except Exception as exc:  # noqa: BLE001 - isolate matrix cells
                    n_errors += 1
                    if isinstance(exc, BudgetExhausted):
                        open_circuit("budget", exc)
                    elif isinstance(exc, RetainedFailedOutputStop):
                        open_circuit("paid_provider", exc)
                    elif isinstance(exc, ExternalCallFailure):
                        target_failure = exc.phase != "judge_call"
                        open_circuit(
                            "judge"
                            if not target_failure
                            else "paid_provider"
                            if spec in api_specs
                            else f"target:{persisted_model_specs[spec]}",
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
                            "grid_id": grid_id,
                            "run_id": run_id,
                            "phase": "cell_execution_or_validation",
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
                            "execution_started": execution_started,
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
                        "execution_started": execution_started,
                        "error_artifact": _artifact_descriptor(error_path),
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
                        "attacker": attacker,
                        "datapoint_id": datapoint_id,
                        "combination": list(combination),
                    }
                    for attacker, datapoint_id, combination in sorted(value)
                ]
                for key, value in executed_modality_evidence.items()
            },
        }
    try:
        engine_runtime_close_descriptor = close_engine_runtimes()
        recheck_bound_project_revision()
        for deferred in deferred_engine_completions:
            pending = deferred["pending"]
            complete = deferred["complete"]
            paths_value = deferred["paths"]
            planned_value = deferred["planned"]
            required_value = deferred["required"]
            status_entry = deferred["status_entry"]
            if (
                not isinstance(pending, Path)
                or not isinstance(complete, Path)
                or not isinstance(paths_value, dict)
                or not isinstance(status_entry, dict)
                or not isinstance(required_value, tuple)
            ):
                raise ValueError("deferred engine completion state is invalid")
            pending_payload = _json_loads_strict(
                pending.read_text(encoding="utf-8")
            )
            if not isinstance(pending_payload, dict):
                raise ValueError("deferred engine completion marker is invalid")
            pending_payload["engine_runtime_close"] = (
                _closed_runtime_descriptor_for_engine(
                    engine_runtime_close_descriptor,
                    str(deferred["attacker"]).lower(),
                )
            )
            _write_json(pending, pending_payload)
            _validate_completion_marker(
                {**paths_value, "complete": pending},
                planned_value,
                required_value,
                acquisition_execution_descriptor,
            )
            pending.replace(complete)
            for field in ("error", "checkpoint", "response_checkpoint"):
                path = paths_value.get(field)
                if isinstance(path, Path):
                    path.unlink(missing_ok=True)
            fallback_error = deferred.get("fallback_error")
            if isinstance(fallback_error, Path):
                fallback_error.unlink(missing_ok=True)
            _remove_superseded_cell_errors(
                out,
                corpus=str(deferred["corpus"]),
                model_spec=str(deferred["model_spec"]),
                attacker=str(deferred["attacker"]),
            )
            stem_value = str(deferred["stem"])
            for stale in out.glob("*.lock.error.json"):
                if stale.name.startswith(f"{stem_value}__"):
                    stale.unlink(missing_ok=True)
            status_entry["status"] = "complete"
            status_entry["completion_marker"] = complete.name
            n_cells += 1
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        invalidated = 0
        for deferred in deferred_engine_completions:
            status_entry = deferred.get("status_entry")
            if not isinstance(status_entry, dict) or status_entry.get("status") != (
                "pending_engine_runtime_seal"
            ):
                continue
            invalidated += 1
            pending = deferred.get("pending")
            if isinstance(pending, Path):
                pending.unlink(missing_ok=True)
            paths_value = deferred.get("paths")
            if isinstance(paths_value, dict) and all(
                isinstance(key, str) and isinstance(value, Path)
                for key, value in paths_value.items()
            ):
                _discard_unsealed_engine_cell_state(paths_value)
            error_path = deferred.get("error")
            if isinstance(error_path, Path):
                _write_json(error_path, {
                    "status": "error",
                    "grid_id": grid_id,
                    "run_id": status_entry.get("run_id"),
                    "phase": "engine_runtime_closing_seal",
                    "corpus": status_entry.get("corpus"),
                    "model_spec": status_entry.get("model_spec"),
                    "attacker": status_entry.get("attacker"),
                    "exception_type": type(exc).__name__,
                    "message": safe_request_error_message(exc),
                    "execution_started": True,
                })
                status_entry["error_artifact"] = _artifact_descriptor(error_path)
            status_entry.pop("completion_marker", None)
            status_entry["status"] = "error"
            status_entry["phase"] = "engine_runtime_closing_seal"
        n_errors += max(1, invalidated)
        if invalidated:
            modality_result_payload = {
                "status": "failed",
                "error": (
                    "isolated-engine cells were invalidated because their "
                    "closing runtime seal failed"
                ),
            }
        engine_runtime_close_descriptor = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "message": safe_request_error_message(exc),
        }
        print(f"engine runtime closing seal failed: {exc}", file=sys.stderr)
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
        "engine_runtime_close": engine_runtime_close_descriptor,
        "cells": cell_statuses,
    }
    try:
        recheck_bound_project_revision()
    except (OSError, TypeError, ValueError) as exc:
        _release_artifact_lock(grid_lock, grid_lock_token)
        print(
            f"project revision changed before final grid publication: {exc}",
            file=sys.stderr,
        )
        return 1
    _write_json(grid_path, final_grid)
    _release_artifact_lock(grid_lock, grid_lock_token)

    print(
        f"\ndone: {n_cells} cells written, {n_skipped} already complete, "
        f"{n_errors} failed; artifacts in {out}"
    )
    print(
        "figures: python -m experiments.figures --help  "
        "# pass explicit completed result artifacts and corpus facets"
    )
    return 1 if n_errors else 0


def main(argv=None) -> int:
    """Run one matrix and tear down every admitted runtime/model owner."""

    global _ACTIVE_ENGINE_RUNTIME_SELECTION
    if _ACTIVE_ENGINE_RUNTIME_SELECTION is not None:
        raise RuntimeError("an isolated engine runtime selection is already active")
    if _ACTIVE_MODEL_COMPONENTS:
        raise RuntimeError("a model component lifecycle is already active")
    prior_signal_handlers: dict[int, object] = {}
    cleanup_failures: list[str] = []
    deferred_cleanup_interrupt: BaseException | None = None
    pending_signal: int | None = None
    execution_active = False
    result: int | None = None
    if os.name == "posix":
        try:
            def terminate(signum: int, _frame: object) -> None:
                nonlocal execution_active, pending_signal
                pending_signal = signum
                if execution_active:
                    # Mark execution inactive before unwinding. A later signal
                    # is then recorded without interrupting bounded teardown.
                    execution_active = False
                    raise _EngineRuntimeTermination(signum)

            for owned_signal in (signal.SIGTERM, signal.SIGINT):
                prior_signal_handlers[owned_signal] = signal.getsignal(owned_signal)
                signal.signal(owned_signal, terminate)
        except ValueError:
            # Library callers may run a no-call matrix from a non-main thread.
            # Only the process main thread can own POSIX signal dispatch.
            pass
    try:
        try:
            execution_active = True
            if pending_signal is not None:
                raise _EngineRuntimeTermination(pending_signal)
            try:
                result = _main(argv)
            except _EngineRuntimeTermination as exc:
                pending_signal = exc.signum
                result = 128 + exc.signum
            finally:
                execution_active = False
        finally:
            try:
                (
                    cleanup_failures,
                    deferred_cleanup_interrupt,
                ) = _close_model_components()
                for failure in cleanup_failures:
                    print(
                        f"model component cleanup failed: {failure}",
                        file=sys.stderr,
                    )
            finally:
                selection = _ACTIVE_ENGINE_RUNTIME_SELECTION
                _ACTIVE_ENGINE_RUNTIME_SELECTION = None
                try:
                    if selection is not None:
                        selection.abort()
                finally:
                    for owned_signal, prior_handler in prior_signal_handlers.items():
                        signal.signal(owned_signal, prior_handler)
            if deferred_cleanup_interrupt is not None:
                raise deferred_cleanup_interrupt
    except _EngineRuntimeTermination as exc:
        # A signal can land while execution is transitioning into its outer
        # finally. Teardown has completed by the time it reaches this handler.
        pending_signal = exc.signum
        result = 128 + exc.signum
    if result is None:  # pragma: no cover - defensive lifecycle invariant
        raise RuntimeError("matrix lifecycle returned no process status")
    if pending_signal is not None:
        return 128 + pending_signal
    # A teardown failure cannot retroactively replace an already-persisted
    # partial/error result. A nominally successful process does fail closed so
    # an operator never mistakes leaked GPU/process state for a clean exit.
    return 1 if cleanup_failures and result == 0 else result


if __name__ == "__main__":
    raise SystemExit(main())
