"""Private, fail-closed runtime admission for sealed Hugging Face snapshots.

The acquisition controller in :mod:`ura.model_acquisition` proves what was
downloaded.  This module is the complementary measured-run boundary: it derives
the exact set of Hub consumers from already-normalized run configuration, binds
that selection to caller-owned configuration/ticket digests, and admits only a
matching plan, receipt, and full-content managed snapshot.

Filesystem locators deliberately remain private attributes.  Public scientific
identity is always the Hub repository plus immutable commit; a managed snapshot
path is only an in-process loader argument and must never be serialized into a
run manifest, console job, or command receipt.
"""

from __future__ import annotations

import gc
import hashlib
import json
import logging
import os
import re
import stat
import sys
import threading
from collections.abc import Callable, Iterable, Mapping
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, TypeVar

from .model_acquisition import (
    MAX_DOCUMENT_BYTES,
    MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_FILES,
    HubRequirement,
    ModelAcquisitionError,
    build_plan,
    guardrail_requirement,
    hub_requirement,
    load_plan,
    load_receipt,
    nanogcg_requirement,
    plan_sha256,
    validate_plan,
    validate_repo_id,
    validate_revision,
    verify_receipt_snapshots,
    vllm_requirement,
)


SELECTION_SCHEMA = "ura-model-acquisition-selection/1"
RUNTIME_DESCRIPTOR_SCHEMA = "ura-model-acquisition-runtime/1"
EXECUTION_DESCRIPTOR_SCHEMA = "ura-model-acquisition-execution/1"
ROLE_PROJECTION_SCHEMA = "ura-model-acquisition-role-projection/1"

# Keep this equal to NanoGCGAttacker's public constructor default.  The core
# projection helper intentionally accepts an explicit model_id, so integration
# does not depend on a second module's fallback changing silently.
NANOGCG_DEFAULT_MODEL_ID = "meta-llama/Llama-2-7b-chat-hf"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_BINDING_KEY = re.compile(r"[a-z][a-z0-9_.-]{0,63}")
_RESOURCE_ID = re.compile(r"hf-[0-9a-f]{32}")
_MANIFEST_ID = re.compile(r"hf-manifest-[0-9a-f]{32}")
_SHARED_SCIENTIFIC_ROLES = frozenset({
    "llm_judge",
    "guardrail_judge",
    "defense_guardrail",
    "nanogcg_surrogate",
})

_HF_OFFLINE_ENVIRONMENT = MappingProxyType(
    {
        "DO_NOT_TRACK": "1",
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "VLLM_NO_USAGE_STATS": "1",
    }
)

_T = TypeVar("_T")
_PRIVATE_STREAM_LOCK = threading.RLock()


@dataclass(frozen=True, slots=True)
class ModelRequirementSet:
    """Exact Hub requirements plus path-free acquisition exceptions."""

    requirements: tuple[HubRequirement, ...]
    exceptions: tuple[Mapping[str, str], ...]


@dataclass(frozen=True, slots=True)
class RuntimeSelection:
    """Canonical public selection and the bindings required in its plan."""

    requirements: tuple[HubRequirement, ...]
    exceptions: tuple[Mapping[str, str], ...]
    input_bindings: Mapping[str, str]
    selection_sha256: str

    @property
    def plan_bindings(self) -> dict[str, str]:
        return {
            **dict(self.input_bindings),
            "selection_sha256": self.selection_sha256,
        }


class ManagedModelLoadError(ModelAcquisitionError):
    """One sealed model could not be safely constructed."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validated_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ModelAcquisitionError(f"{label} must be 64 lowercase hex characters")
    return value


def _normalized_names(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ModelAcquisitionError(f"{label} contains a blank or non-string value")
        item = value.strip().lower()
        if item in normalized:
            raise ModelAcquisitionError(f"{label} contains a duplicate value")
        normalized.append(item)
    return tuple(normalized)


def _vllm_projection(
    spec: str,
    config: Mapping[str, object],
    *,
    role: str,
) -> tuple[HubRequirement | None, Mapping[str, str] | None]:
    if not isinstance(spec, str) or not spec.startswith("vllm:"):
        raise ModelAcquisitionError("vLLM acquisition selection has an invalid spec")
    if not isinstance(config, Mapping):
        raise ModelAcquisitionError("vLLM acquisition selection lacks local config")
    revision = config.get("revision")
    digest = config.get("digest")
    if bool(revision) == bool(digest):
        raise ModelAcquisitionError(
            "vLLM acquisition selection requires exactly one revision or digest"
        )
    # Match VLLMTarget's authoritative path classification exactly.  A digest
    # on a Hub-looking repository id must not be reinterpreted as an explicit
    # local exception, and a revision must not bless an operator-local path.
    from .targets.local import _is_explicit_local_path

    runtime_model = spec.split(":", 1)[1]
    explicit_local_path = _is_explicit_local_path(runtime_model)
    if explicit_local_path and revision:
        raise ModelAcquisitionError(
            "explicit local vLLM selection requires a digest, not a Hub revision"
        )
    if not explicit_local_path and digest:
        raise ModelAcquisitionError(
            "Hub vLLM selection requires an immutable revision, not a local digest"
        )
    if revision:
        return vllm_requirement(spec, revision, role=role), None
    normalized_digest = _validated_digest(digest, label="local checkpoint digest")
    return None, {
        "identity": "sha256:" + normalized_digest,
        "kind": "explicit_local_checkpoint",
        "role": role,
    }


def collect_run_requirements(
    *,
    target_specs: Iterable[str],
    local_configs: Mapping[str, Mapping[str, object]],
    judge_names: Iterable[str],
    judge_model: str,
    attacker_names: Iterable[str],
    attacker_configs: Mapping[str, Mapping[str, object]],
    guardrail_model: str | None = None,
    guardrail_revision: str | None = None,
    defense_guardrail_model: str | None = None,
    defense_guardrail_revision: str | None = None,
) -> ModelRequirementSet:
    """Project the five supported Hub roles from normalized run configuration.

    Hosted and Ollama routes do not use Hugging Face acquisition.  A vLLM row
    with a content digest is an explicit local checkpoint and is represented by
    a path-free exception.  A NanoGCG suffix is likewise a replay exception and
    never causes model loading.  The target and local-judge roles are projected
    in separate process selections because the runner permits only one local
    engine per process.
    """

    targets = tuple(target_specs)
    judges = _normalized_names(judge_names, label="judge selection")
    attackers = _normalized_names(attacker_names, label="attacker selection")
    local_targets = tuple(
        spec for spec in targets
        if isinstance(spec, str) and spec.startswith(("vllm:", "ollama:"))
    )
    local_judge_selected = (
        "llm" in judges
        and isinstance(judge_model, str)
        and judge_model.startswith(("vllm:", "ollama:"))
    )
    if len(local_targets) > 1:
        raise ModelAcquisitionError(
            "one local target is allowed per process and acquisition plan"
        )
    if local_targets and local_judge_selected:
        raise ModelAcquisitionError(
            "a local target and local LLM judge cannot share one process"
        )
    requirements: list[HubRequirement] = []
    exceptions: list[Mapping[str, str]] = []

    seen_targets: set[str] = set()
    for raw_spec in targets:
        if not isinstance(raw_spec, str) or raw_spec != raw_spec.strip() or not raw_spec:
            raise ModelAcquisitionError("target selection contains an invalid spec")
        spec = raw_spec
        if spec in seen_targets:
            raise ModelAcquisitionError("target selection contains a duplicate spec")
        seen_targets.add(spec)
        if not spec.startswith("vllm:"):
            continue
        config = local_configs.get(spec)
        if not isinstance(config, Mapping):
            raise ModelAcquisitionError("selected vLLM target lacks exact local config")
        requirement, exception = _vllm_projection(spec, config, role="vllm_target")
        if requirement is not None:
            requirements.append(requirement)
        if exception is not None:
            exceptions.append(exception)

    if "llm" in judges and judge_model.startswith("vllm:"):
        config = local_configs.get(judge_model)
        if not isinstance(config, Mapping):
            raise ModelAcquisitionError("selected vLLM judge lacks exact local config")
        requirement, exception = _vllm_projection(
            judge_model,
            config,
            role="llm_judge",
        )
        if requirement is not None:
            requirements.append(requirement)
        if exception is not None:
            exceptions.append(exception)

    if "guardrail" in judges:
        if guardrail_model is None or guardrail_revision is None:
            raise ModelAcquisitionError("selected guardrail judge lacks immutable identity")
        requirements.append(
            guardrail_requirement(
                guardrail_model,
                guardrail_revision,
                defense=False,
            )
        )
    elif guardrail_model is not None or guardrail_revision is not None:
        raise ModelAcquisitionError(
            "guardrail judge acquisition identity was supplied for an unselected stage"
        )

    if defense_guardrail_model is not None or defense_guardrail_revision is not None:
        if defense_guardrail_model is None or defense_guardrail_revision is None:
            raise ModelAcquisitionError("defense guardrail lacks immutable identity")
        requirements.append(
            guardrail_requirement(
                defense_guardrail_model,
                defense_guardrail_revision,
                defense=True,
            )
        )

    if "nanogcg" in attackers:
        raw_config = attacker_configs.get("nanogcg", {})
        if not isinstance(raw_config, Mapping):
            raise ModelAcquisitionError("NanoGCG attacker config must be an object")
        config = dict(raw_config)
        config.setdefault("model_id", NANOGCG_DEFAULT_MODEL_ID)
        requirement = nanogcg_requirement(config)
        if requirement is None:
            suffix = config.get("suffix")
            # nanogcg_requirement already validates that this is non-empty.
            exceptions.append(
                {
                    "identity": "sha256:"
                    + hashlib.sha256(str(suffix).encode("utf-8")).hexdigest(),
                    "kind": "precomputed_suffix_replay",
                    "role": "nanogcg_surrogate",
                }
            )
        else:
            requirements.append(requirement)
    elif "nanogcg" in attacker_configs:
        raise ModelAcquisitionError(
            "NanoGCG acquisition config was supplied for an unselected attacker"
        )

    canonical_requirements = tuple(
        sorted(
            (
                hub_requirement(item.role, item.repo_id, item.revision)
                for item in requirements
            ),
            key=lambda item: (item.repo_id, item.revision, item.role),
        )
    )
    if len(set(canonical_requirements)) != len(canonical_requirements):
        raise ModelAcquisitionError("model acquisition selection repeats one consumer role")
    target_resources = {
        (item.repo_id, item.revision)
        for item in canonical_requirements
        if item.role == "vllm_target"
    }
    self_certifying_resources = {
        (item.repo_id, item.revision)
        for item in canonical_requirements
        if item.role in {
            "llm_judge",
            "guardrail_judge",
            "defense_guardrail",
        }
    }
    if target_resources & self_certifying_resources:
        raise ModelAcquisitionError(
            "an evaluated vLLM target cannot also be its LLM judge, scoring "
            "guardrail, or defense guard"
        )
    surrogate_resources = {
        (item.repo_id, item.revision)
        for item in canonical_requirements
        if item.role == "nanogcg_surrogate"
    }
    if target_resources & surrogate_resources:
        raise ModelAcquisitionError(
            "NanoGCG surrogate must differ from every evaluated target; the "
            "current attack semantics are surrogate-transfer, not white-box"
        )
    target_exception_identities = {
        str(item["identity"])
        for item in exceptions
        if item["role"] == "vllm_target"
    }
    judge_exception_identities = {
        str(item["identity"])
        for item in exceptions
        if item["role"] == "llm_judge"
    }
    if target_exception_identities & judge_exception_identities:
        raise ModelAcquisitionError(
            "an explicit-local vLLM target cannot also be its LLM judge"
        )
    canonical_exceptions = tuple(
        MappingProxyType(dict(item))
        for item in sorted(
            exceptions,
            key=lambda item: (item["role"], item["kind"], item["identity"]),
        )
    )
    if len({tuple(item.items()) for item in canonical_exceptions}) != len(
        canonical_exceptions
    ):
        raise ModelAcquisitionError("model acquisition exceptions are duplicated")
    return ModelRequirementSet(canonical_requirements, canonical_exceptions)


def build_runtime_selection(
    requirement_set: ModelRequirementSet,
    *,
    input_bindings: Mapping[str, str],
) -> RuntimeSelection:
    """Bind a public consumer selection to exact caller-owned config digests."""

    if not isinstance(requirement_set, ModelRequirementSet):
        raise ModelAcquisitionError("runtime requirement set is invalid")
    if not isinstance(input_bindings, Mapping) or not input_bindings:
        raise ModelAcquisitionError("runtime selection needs immutable input bindings")
    normalized_bindings: dict[str, str] = {}
    for key, value in input_bindings.items():
        if (
            not isinstance(key, str)
            or _BINDING_KEY.fullmatch(key) is None
            or key == "selection_sha256"
        ):
            raise ModelAcquisitionError("runtime selection binding key is invalid")
        normalized_bindings[key] = _validated_digest(
            value,
            label=f"runtime selection binding {key!r}",
        )
    requirements = tuple(
        sorted(
            (
                hub_requirement(item.role, item.repo_id, item.revision)
                for item in requirement_set.requirements
            ),
            key=lambda item: (item.repo_id, item.revision, item.role),
        )
    )
    exceptions = tuple(
        MappingProxyType(dict(item))
        for item in sorted(
            requirement_set.exceptions,
            key=lambda item: (
                str(item.get("role", "")),
                str(item.get("kind", "")),
                str(item.get("identity", "")),
            ),
        )
    )
    target_roles = sum(item.role == "vllm_target" for item in requirements) + sum(
        item.get("role") == "vllm_target" for item in exceptions
    )
    judge_roles = sum(item.role == "llm_judge" for item in requirements) + sum(
        item.get("role") == "llm_judge" for item in exceptions
    )
    if target_roles > 1:
        raise ModelAcquisitionError(
            "one local target is allowed per process and acquisition selection"
        )
    if target_roles and judge_roles:
        raise ModelAcquisitionError(
            "a local target and local LLM judge cannot share one process"
        )
    for exception in exceptions:
        if set(exception) != {"identity", "kind", "role"}:
            raise ModelAcquisitionError("runtime acquisition exception fields are invalid")
        identity = exception["identity"]
        if (
            not isinstance(identity, str)
            or not identity.startswith("sha256:")
            or _SHA256.fullmatch(identity.removeprefix("sha256:")) is None
            or not isinstance(exception["kind"], str)
            or exception["kind"]
            not in {"explicit_local_checkpoint", "precomputed_suffix_replay"}
            or not isinstance(exception["role"], str)
            or exception["role"] not in {"vllm_target", "llm_judge", "nanogcg_surrogate"}
        ):
            raise ModelAcquisitionError("runtime acquisition exception is invalid")
    projection = {
        "exceptions": [dict(item) for item in exceptions],
        "input_bindings": dict(sorted(normalized_bindings.items())),
        "requirements": [
            {
                "repo_id": item.repo_id,
                "revision": item.revision,
                "role": item.role,
            }
            for item in requirements
        ],
        "schema": SELECTION_SCHEMA,
    }
    return RuntimeSelection(
        requirements=requirements,
        exceptions=exceptions,
        input_bindings=MappingProxyType(dict(sorted(normalized_bindings.items()))),
        selection_sha256=_sha256(projection),
    )


def validate_runtime_selection(value: object) -> RuntimeSelection:
    """Reject a manually constructed selection with stale/non-canonical state."""

    if not isinstance(value, RuntimeSelection):
        raise ModelAcquisitionError("runtime selection is invalid")
    canonical = build_runtime_selection(
        ModelRequirementSet(
            tuple(value.requirements),
            tuple(value.exceptions),
        ),
        input_bindings=dict(value.input_bindings),
    )
    if (
        canonical.requirements != value.requirements
        or tuple(dict(item) for item in canonical.exceptions)
        != tuple(dict(item) for item in value.exceptions)
        or dict(canonical.input_bindings) != dict(value.input_bindings)
        or canonical.selection_sha256 != value.selection_sha256
    ):
        raise ModelAcquisitionError("runtime selection is non-canonical or stale")
    return canonical


def public_selection_descriptor(selection: RuntimeSelection) -> dict[str, Any]:
    """Return the path-free prospective model selection for durable evidence."""

    canonical = validate_runtime_selection(selection)
    merged: dict[tuple[str, str], set[str]] = {}
    for requirement in canonical.requirements:
        merged.setdefault(
            (requirement.repo_id, requirement.revision),
            set(),
        ).add(requirement.role)
    return {
        "exceptions": [dict(item) for item in canonical.exceptions],
        "input_bindings": dict(canonical.input_bindings),
        "resources": [
            {
                "repo_id": repo_id,
                "revision": revision,
                "roles": sorted(roles),
            }
            for (repo_id, revision), roles in sorted(merged.items())
        ],
        "schema": SELECTION_SCHEMA,
        "selection_sha256": canonical.selection_sha256,
    }


def validate_public_selection_descriptor(value: object) -> dict[str, Any]:
    """Strictly validate the durable, path-free selection projection."""

    if not isinstance(value, dict) or set(value) != {
        "exceptions",
        "input_bindings",
        "resources",
        "schema",
        "selection_sha256",
    }:
        raise ModelAcquisitionError("model acquisition selection descriptor is invalid")
    if value.get("schema") != SELECTION_SCHEMA:
        raise ModelAcquisitionError("model acquisition selection schema is invalid")
    _validated_digest(value.get("selection_sha256"), label="selection SHA-256")
    resources = value.get("resources")
    if not isinstance(resources, list):
        raise ModelAcquisitionError("model acquisition selection resources are invalid")
    normalized_resources: list[dict[str, Any]] = []
    prior_key: tuple[str, str] | None = None
    for resource in resources:
        if not isinstance(resource, dict) or set(resource) != {
            "repo_id",
            "revision",
            "roles",
        }:
            raise ModelAcquisitionError(
                "model acquisition selection resource fields are invalid"
            )
        repo_id = validate_repo_id(resource["repo_id"])
        revision = validate_revision(resource["revision"])
        roles = resource["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or roles != sorted(set(roles))
        ):
            raise ModelAcquisitionError(
                "model acquisition selection resource roles are invalid"
            )
        for role in roles:
            hub_requirement(role, repo_id, revision)
        key = (repo_id, revision)
        if prior_key is not None and key <= prior_key:
            raise ModelAcquisitionError(
                "model acquisition selection resources are not canonical"
            )
        prior_key = key
        normalized_resources.append({
            "repo_id": repo_id,
            "revision": revision,
            "roles": list(roles),
        })
    exceptions = value.get("exceptions")
    if not isinstance(exceptions, list):
        raise ModelAcquisitionError("model acquisition selection exceptions are invalid")
    normalized_exceptions: list[dict[str, str]] = []
    for exception in exceptions:
        if not isinstance(exception, dict) or set(exception) != {
            "identity",
            "kind",
            "role",
        }:
            raise ModelAcquisitionError(
                "model acquisition selection exception fields are invalid"
            )
        identity = exception.get("identity")
        kind = exception.get("kind")
        role = exception.get("role")
        if (
            not isinstance(identity, str)
            or not identity.startswith("sha256:")
            or _SHA256.fullmatch(identity.removeprefix("sha256:")) is None
            or kind not in {
                "explicit_local_checkpoint",
                "precomputed_suffix_replay",
            }
            or role not in {"vllm_target", "llm_judge", "nanogcg_surrogate"}
        ):
            raise ModelAcquisitionError(
                "model acquisition selection exception is invalid"
            )
        normalized_exceptions.append(dict(exception))
    if normalized_exceptions != sorted(
        normalized_exceptions,
        key=lambda item: (item["role"], item["kind"], item["identity"]),
    ) or len({
        (item["role"], item["kind"], item["identity"])
        for item in normalized_exceptions
    }) != len(normalized_exceptions):
        raise ModelAcquisitionError(
            "model acquisition selection exceptions are not canonical"
        )
    bindings = value.get("input_bindings")
    if not isinstance(bindings, dict) or not bindings:
        raise ModelAcquisitionError(
            "model acquisition selection input bindings are invalid"
        )
    normalized_bindings: dict[str, str] = {}
    for key, digest in bindings.items():
        if (
            not isinstance(key, str)
            or _BINDING_KEY.fullmatch(key) is None
            or key == "selection_sha256"
        ):
            raise ModelAcquisitionError(
                "model acquisition selection binding key is invalid"
            )
        normalized_bindings[key] = _validated_digest(
            digest,
            label=f"selection binding {key!r}",
        )
    if list(bindings) != sorted(bindings):
        raise ModelAcquisitionError(
            "model acquisition selection bindings are not canonical"
        )
    reconstructed = build_runtime_selection(
        ModelRequirementSet(
            tuple(
                hub_requirement(role, resource["repo_id"], resource["revision"])
                for resource in normalized_resources
                for role in resource["roles"]
            ),
            tuple(normalized_exceptions),
        ),
        input_bindings=normalized_bindings,
    )
    if reconstructed.selection_sha256 != value["selection_sha256"]:
        raise ModelAcquisitionError(
            "model acquisition selection digest is stale"
        )
    return {
        "exceptions": normalized_exceptions,
        "input_bindings": dict(sorted(normalized_bindings.items())),
        "resources": normalized_resources,
        "schema": SELECTION_SCHEMA,
        "selection_sha256": value["selection_sha256"],
    }


def _verified_evidence_file(
    descriptor: object,
    *,
    evidence_root: Path,
    expected_sha256: str,
    label: str,
) -> Path:
    if not isinstance(descriptor, dict) or set(descriptor) != {
        "bytes",
        "file",
        "records",
        "sha256",
    }:
        raise ModelAcquisitionError(f"{label} evidence descriptor is invalid")
    filename = descriptor.get("file")
    relative = PurePosixPath(filename) if isinstance(filename, str) else None
    if (
        relative is None
        or relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or "\\" in filename
        or ":" in filename
    ):
        raise ModelAcquisitionError(f"{label} evidence filename is invalid")
    if descriptor.get("sha256") != expected_sha256:
        raise ModelAcquisitionError(f"{label} evidence digest differs from runtime")
    if descriptor.get("records") != 1:
        raise ModelAcquisitionError(f"{label} evidence record count is invalid")
    byte_count = descriptor.get("bytes")
    if (
        not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count <= 0
        or byte_count > MAX_DOCUMENT_BYTES
    ):
        raise ModelAcquisitionError(f"{label} evidence byte count is invalid")
    path = evidence_root.joinpath(*relative.parts)
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError(f"{label} evidence cannot be inspected") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(info.st_mode)
        or resolved != path
        or path.stat().st_size != byte_count
    ):
        raise ModelAcquisitionError(f"{label} evidence file is unsafe")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if digest != expected_sha256:
        raise ModelAcquisitionError(f"{label} evidence bytes changed")
    return path


def validate_model_acquisition_descriptor(
    value: object,
    *,
    evidence_root: Path | str | None = None,
) -> dict[str, Any]:
    """Validate durable acquisition evidence at run and analysis boundaries."""

    if not isinstance(value, dict):
        raise ModelAcquisitionError("model acquisition descriptor is invalid")
    if value.get("status") == "not_required":
        if set(value) != {"selection", "status"}:
            raise ModelAcquisitionError(
                "not-required model acquisition descriptor fields are invalid"
            )
        selection = validate_public_selection_descriptor(value["selection"])
        if selection["resources"]:
            raise ModelAcquisitionError(
                "not-required model acquisition descriptor contains Hub resources"
            )
        return {"selection": selection, "status": "not_required"}
    expected_fields = {
        "evidence",
        "plan_id",
        "plan_sha256",
        "receipt_id",
        "receipt_sha256",
        "resources",
        "schema",
        "selection",
        "selection_sha256",
    }
    if set(value) != expected_fields or value.get("schema") != RUNTIME_DESCRIPTOR_SCHEMA:
        raise ModelAcquisitionError("verified model acquisition descriptor is invalid")
    plan_sha = _validated_digest(value.get("plan_sha256"), label="plan SHA-256")
    receipt_sha = _validated_digest(
        value.get("receipt_sha256"),
        label="receipt SHA-256",
    )
    selection = validate_public_selection_descriptor(value["selection"])
    if value.get("selection_sha256") != selection["selection_sha256"]:
        raise ModelAcquisitionError("runtime and selection digests differ")
    if value.get("resources") != selection["resources"]:
        raise ModelAcquisitionError("runtime and selection resources differ")
    if evidence_root is None:
        raise ModelAcquisitionError("verified acquisition evidence root is required")
    root = _validated_store(evidence_root)
    evidence = value.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != {"plan", "receipt"}:
        raise ModelAcquisitionError("model acquisition evidence fields are invalid")
    plan_path = _verified_evidence_file(
        evidence["plan"],
        evidence_root=root,
        expected_sha256=plan_sha,
        label="acquisition plan",
    )
    plan = load_plan(plan_path, expected_sha256=plan_sha)
    receipt_path = _verified_evidence_file(
        evidence["receipt"],
        evidence_root=root,
        expected_sha256=receipt_sha,
        label="acquisition receipt",
    )
    receipt = load_receipt(receipt_path, expected_sha256=receipt_sha, plan=plan)
    reconstructed = build_runtime_selection(
        ModelRequirementSet(
            tuple(
                hub_requirement(role, resource["repo_id"], resource["revision"])
                for resource in selection["resources"]
                for role in resource["roles"]
            ),
            tuple(selection["exceptions"]),
        ),
        input_bindings=selection["input_bindings"],
    )
    if (
        {
            key: digest
            for key, digest in plan["bindings"].items()
            if key != "selection_sha256"
        }
        != selection["input_bindings"]
        or
        reconstructed.selection_sha256 != selection["selection_sha256"]
        or public_selection_descriptor(reconstructed) != selection
    ):
        raise ModelAcquisitionError(
            "model acquisition selection digest is not reproducible from evidence"
        )
    if (
        value.get("plan_id") != plan["plan_id"]
        or value.get("receipt_id") != receipt["receipt_id"]
        or plan["bindings"].get("selection_sha256")
        != selection["selection_sha256"]
    ):
        raise ModelAcquisitionError("model acquisition evidence identity differs")
    plan_resources = [
        {
            "repo_id": resource["repo_id"],
            "revision": resource["revision"],
            "roles": list(resource["roles"]),
        }
        for resource in plan["resources"]
    ]
    if plan_resources != selection["resources"]:
        raise ModelAcquisitionError("model acquisition plan resources differ")
    return {
        **value,
        "evidence": {
            "plan": dict(evidence["plan"]),
            "receipt": dict(evidence["receipt"]),
        },
        "resources": plan_resources,
        "selection": selection,
    }


def _execution_receipt_resources(
    resources: object,
    *,
    expected_plan: Mapping[str, Any],
    from_full_receipt: bool = False,
) -> list[dict[str, Any]]:
    """Validate and project the content-stable facts from one receipt.

    ``inventory_sha256`` is an admission accelerator over paths, sizes, types,
    and mtimes. It remains required in the full receipt and is compared during
    every pre/post-load verification, but mtime is not scientific model
    identity. The stable projection therefore deliberately omits that one
    host-stat digest while retaining the full content tree and upstream seal.
    """

    if not isinstance(resources, list) or len(resources) != len(
        expected_plan["resources"]
    ):
        raise ModelAcquisitionError(
            "model acquisition execution resources do not match the plan"
        )
    stable_fields = {
        "file_count",
        "repo_id",
        "resource_id",
        "revision",
        "roles",
        "storage",
        "total_bytes",
        "tree_sha256",
        "upstream_manifest_id",
        "upstream_manifest_sha256",
    }
    expected_fields = stable_fields | (
        {"inventory_sha256"} if from_full_receipt else set()
    )
    normalized: list[dict[str, Any]] = []
    for expected, resource in zip(
        expected_plan["resources"], resources, strict=True
    ):
        if not isinstance(resource, dict) or set(resource) != expected_fields:
            raise ModelAcquisitionError(
                "model acquisition execution resource fields are invalid"
            )
        for field in ("repo_id", "resource_id", "revision", "roles"):
            if resource.get(field) != expected[field]:
                raise ModelAcquisitionError(
                    "model acquisition execution resource identity differs"
                )
        if resource.get("storage") != "managed_store":
            raise ModelAcquisitionError(
                "model acquisition execution storage kind is invalid"
            )
        for field in ("tree_sha256", "upstream_manifest_sha256"):
            _validated_digest(
                resource.get(field),
                label=f"model acquisition execution {field}",
            )
        manifest_id = resource.get("upstream_manifest_id")
        if (
            not isinstance(manifest_id, str)
            or _MANIFEST_ID.fullmatch(manifest_id) is None
        ):
            raise ModelAcquisitionError(
                "model acquisition execution upstream manifest ID is invalid"
            )
        file_count = resource.get("file_count")
        total_bytes = resource.get("total_bytes")
        if (
            isinstance(file_count, bool)
            or not isinstance(file_count, int)
            or not 1 <= file_count <= MAX_SNAPSHOT_FILES
            or isinstance(total_bytes, bool)
            or not isinstance(total_bytes, int)
            or not 0 <= total_bytes <= MAX_SNAPSHOT_BYTES
        ):
            raise ModelAcquisitionError(
                "model acquisition execution snapshot bounds are invalid"
            )
        normalized.append({field: resource[field] for field in stable_fields})
    return normalized


def validate_model_acquisition_execution_descriptor(
    value: object,
) -> dict[str, Any]:
    """Validate the stable acquisition projection used for scientific identity.

    A receipt is an audit event and truthfully includes its wall-clock completion
    time.  That event identity must not fragment a run whose selected revisions
    and fully sealed snapshot bytes are unchanged.  This projection therefore
    retains every immutable plan, manifest, size, role, revision, and content-
    tree fact while deliberately excluding receipt-instance fields (timestamp,
    receipt ID, receipt document digest, and evidence filename) plus the
    host-stat inventory digest whose admission-only inventory includes mtimes.
    """

    if not isinstance(value, dict):
        raise ModelAcquisitionError(
            "model acquisition execution descriptor is invalid"
        )
    status = value.get("status")
    if status == "not_required":
        if set(value) != {
            "execution_sha256",
            "schema",
            "selection",
            "status",
        }:
            raise ModelAcquisitionError(
                "not-required acquisition execution fields are invalid"
            )
        if value.get("schema") != EXECUTION_DESCRIPTOR_SCHEMA:
            raise ModelAcquisitionError(
                "model acquisition execution schema is invalid"
            )
        selection = validate_public_selection_descriptor(value["selection"])
        if selection["resources"]:
            raise ModelAcquisitionError(
                "not-required acquisition execution contains Hub resources"
            )
        body = {
            "schema": EXECUTION_DESCRIPTOR_SCHEMA,
            "selection": selection,
            "status": "not_required",
        }
        if value.get("execution_sha256") != _sha256(body):
            raise ModelAcquisitionError(
                "model acquisition execution digest is stale"
            )
        return {**body, "execution_sha256": value["execution_sha256"]}

    expected_fields = {
        "execution_sha256",
        "plan_id",
        "plan_sha256",
        "resources",
        "schema",
        "selection",
        "status",
    }
    if (
        status != "verified"
        or set(value) != expected_fields
        or value.get("schema") != EXECUTION_DESCRIPTOR_SCHEMA
    ):
        raise ModelAcquisitionError(
            "verified acquisition execution descriptor is invalid"
        )
    selection = validate_public_selection_descriptor(value["selection"])
    if not selection["resources"]:
        raise ModelAcquisitionError(
            "verified acquisition execution lacks Hub resources"
        )
    reconstructed_selection = build_runtime_selection(
        ModelRequirementSet(
            tuple(
                hub_requirement(role, resource["repo_id"], resource["revision"])
                for resource in selection["resources"]
                for role in resource["roles"]
            ),
            tuple(selection["exceptions"]),
        ),
        input_bindings=selection["input_bindings"],
    )
    expected_plan = build_runtime_plan(reconstructed_selection)
    if (
        value.get("plan_id") != expected_plan["plan_id"]
        or value.get("plan_sha256") != plan_sha256(expected_plan)
    ):
        raise ModelAcquisitionError(
            "model acquisition execution plan identity is stale"
        )
    resources = _execution_receipt_resources(
        value.get("resources"), expected_plan=expected_plan
    )
    body = {
        "plan_id": expected_plan["plan_id"],
        "plan_sha256": plan_sha256(expected_plan),
        "resources": resources,
        "schema": EXECUTION_DESCRIPTOR_SCHEMA,
        "selection": selection,
        "status": "verified",
    }
    if value.get("execution_sha256") != _sha256(body):
        raise ModelAcquisitionError("model acquisition execution digest is stale")
    return {**body, "execution_sha256": value["execution_sha256"]}


def model_acquisition_execution_descriptor(
    value: object,
    *,
    evidence_root: Path | str | None = None,
) -> dict[str, Any]:
    """Derive stable scientific identity from fully validated receipt evidence."""

    descriptor = validate_model_acquisition_descriptor(
        value,
        evidence_root=evidence_root,
    )
    if descriptor.get("status") == "not_required":
        body = {
            "schema": EXECUTION_DESCRIPTOR_SCHEMA,
            "selection": descriptor["selection"],
            "status": "not_required",
        }
        return validate_model_acquisition_execution_descriptor({
            **body,
            "execution_sha256": _sha256(body),
        })

    root = _validated_store(evidence_root)  # type: ignore[arg-type]
    evidence = descriptor["evidence"]
    plan_path = _verified_evidence_file(
        evidence["plan"],
        evidence_root=root,
        expected_sha256=descriptor["plan_sha256"],
        label="acquisition plan",
    )
    plan = load_plan(plan_path, expected_sha256=descriptor["plan_sha256"])
    receipt_path = _verified_evidence_file(
        evidence["receipt"],
        evidence_root=root,
        expected_sha256=descriptor["receipt_sha256"],
        label="acquisition receipt",
    )
    receipt = load_receipt(
        receipt_path,
        expected_sha256=descriptor["receipt_sha256"],
        plan=plan,
    )
    stable_resources = _execution_receipt_resources(
        receipt["resources"],
        expected_plan=plan,
        from_full_receipt=True,
    )
    body = {
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256(plan),
        "resources": stable_resources,
        "schema": EXECUTION_DESCRIPTOR_SCHEMA,
        "selection": descriptor["selection"],
        "status": "verified",
    }
    return validate_model_acquisition_execution_descriptor({
        **body,
        "execution_sha256": _sha256(body),
    })


_RoleResources = dict[str, set[tuple[str, str]]]
_RoleExceptions = dict[str, set[tuple[str, str]]]


def _selection_role_inventories(
    selection: Mapping[str, Any],
) -> tuple[_RoleResources, _RoleExceptions]:
    resources: _RoleResources = {}
    exceptions: _RoleExceptions = {}
    for resource in selection["resources"]:
        identity = (resource["repo_id"], resource["revision"])
        for role in resource["roles"]:
            resources.setdefault(role, set()).add(identity)
    for exception in selection["exceptions"]:
        exceptions.setdefault(exception["role"], set()).add(
            (exception["kind"], exception["identity"])
        )
    return resources, exceptions


def _add_persisted_vllm_identity(
    spec: object,
    identity: object,
    *,
    role: str,
    resources: _RoleResources,
    exceptions: _RoleExceptions,
) -> None:
    """Project one path-free, persisted vLLM identity into a role multimap."""

    if not isinstance(spec, str) or not spec.startswith("vllm:"):
        return
    model = spec.removeprefix("vllm:")
    local_prefix = "local-checkpoint@sha256:"
    if model.startswith(local_prefix):
        digest = _validated_digest(
            model.removeprefix(local_prefix),
            label=f"persisted {role} local digest",
        )
        if isinstance(identity, dict) and identity.get("digest") is not None:
            if _validated_digest(
                identity.get("digest"),
                label=f"persisted {role} config digest",
            ) != digest:
                raise ModelAcquisitionError(
                    f"persisted {role} local digest differs from local identity"
                )
        exceptions.setdefault(role, set()).add(
            ("explicit_local_checkpoint", "sha256:" + digest)
        )
        return
    persisted_revision: str | None = None
    if "@" in model:
        model, revision_suffix = model.rsplit("@", 1)
        persisted_revision = validate_revision(revision_suffix)
    if not isinstance(identity, dict):
        raise ModelAcquisitionError(
            f"persisted {role} lacks immutable local identity"
        )
    revision = validate_revision(identity.get("revision"))
    if persisted_revision is not None and persisted_revision != revision:
        raise ModelAcquisitionError(
            f"persisted {role} revision suffix differs from local identity"
        )
    resources.setdefault(role, set()).add((validate_repo_id(model), revision))


def _add_shared_run_identities(
    config: Mapping[str, Any],
    *,
    judge_key: str,
    attacker_key: str,
    attacker_config_key: str,
    resources: _RoleResources,
    exceptions: _RoleExceptions,
) -> None:
    judge_names = config.get(judge_key)
    if not isinstance(judge_names, list) or any(
        not isinstance(name, str) for name in judge_names
    ):
        raise ModelAcquisitionError(
            "model acquisition binding lacks judge inventory"
        )
    if len(set(judge_names)) != len(judge_names):
        raise ModelAcquisitionError("model acquisition binding repeats a judge")
    if "llm" in judge_names:
        _add_persisted_vllm_identity(
            config.get("judge_model"),
            config.get("judge_local_identity"),
            role="llm_judge",
            resources=resources,
            exceptions=exceptions,
        )
    if "guardrail" in judge_names:
        resources.setdefault("guardrail_judge", set()).add((
            validate_repo_id(config.get("guardrail_model")),
            validate_revision(config.get("guardrail_revision")),
        ))
    elif (
        config.get("guardrail_model") is not None
        or config.get("guardrail_revision") is not None
    ):
        raise ModelAcquisitionError(
            "unselected guardrail acquisition identity is present"
        )
    defense_model = config.get("defense_guardrail_model")
    defense_revision = config.get("defense_guardrail_revision")
    if defense_model is not None or defense_revision is not None:
        resources.setdefault("defense_guardrail", set()).add((
            validate_repo_id(defense_model),
            validate_revision(defense_revision),
        ))

    attackers = config.get(attacker_key)
    if attacker_key == "attacker":
        selected_nanogcg = attackers == "nanogcg"
        attacker_config = config.get(attacker_config_key)
    else:
        if not isinstance(attackers, list) or any(
            not isinstance(name, str) for name in attackers
        ):
            raise ModelAcquisitionError(
                "model acquisition grid binding lacks attacker inventory"
            )
        if len(set(attackers)) != len(attackers):
            raise ModelAcquisitionError(
                "model acquisition grid binding repeats an attacker"
            )
        selected_nanogcg = "nanogcg" in attackers
        all_configs = config.get(attacker_config_key)
        if not isinstance(all_configs, dict):
            raise ModelAcquisitionError(
                "model acquisition grid binding lacks attacker configs"
            )
        attacker_config = all_configs.get("nanogcg", {})
    if selected_nanogcg:
        if not isinstance(attacker_config, dict):
            raise ModelAcquisitionError(
                "model acquisition NanoGCG binding is invalid"
            )
        suffix = attacker_config.get("suffix")
        if isinstance(suffix, str) and suffix.strip():
            exceptions.setdefault("nanogcg_surrogate", set()).add((
                "precomputed_suffix_replay",
                "sha256:" + hashlib.sha256(suffix.encode("utf-8")).hexdigest(),
            ))
        else:
            resources.setdefault("nanogcg_surrogate", set()).add((
                validate_repo_id(
                    attacker_config.get("model_id", NANOGCG_DEFAULT_MODEL_ID)
                ),
                validate_revision(attacker_config.get("model_revision")),
            ))


def _validate_shared_role_inventories(
    observed_resources: _RoleResources,
    observed_exceptions: _RoleExceptions,
    expected_resources: _RoleResources,
    expected_exceptions: _RoleExceptions,
) -> None:
    for role in (
        "llm_judge",
        "guardrail_judge",
        "defense_guardrail",
        "nanogcg_surrogate",
    ):
        if (
            observed_resources.get(role, set())
            != expected_resources.get(role, set())
            or observed_exceptions.get(role, set())
            != expected_exceptions.get(role, set())
        ):
            raise ModelAcquisitionError(
                "model acquisition shared roles or immutable identities differ "
                "from run config"
            )


def validate_model_acquisition_run_binding(
    descriptor: object,
    run_config: object,
) -> dict[str, Any]:
    """Bind a cell to its grid-wide acquisition inventory.

    A legal grid may mix multiple hosted targets with at most one local target.
    Hosted cells therefore carry the same grid-wide local acquisition evidence
    without consuming that target role; the one local cell must match it
    exactly. The grid boundary separately proves the complete target roster.
    """

    canonical = validate_model_acquisition_execution_descriptor(descriptor)
    if not isinstance(run_config, dict):
        raise ModelAcquisitionError("model acquisition run binding is invalid")
    observed_resources, observed_exceptions = _selection_role_inventories(
        canonical["selection"]
    )
    expected_resources: _RoleResources = {}
    expected_exceptions: _RoleExceptions = {}
    _add_persisted_vllm_identity(
        run_config.get("model_spec"),
        run_config.get("local_identity"),
        role="vllm_target",
        resources=expected_resources,
        exceptions=expected_exceptions,
    )
    _add_shared_run_identities(
        run_config,
        judge_key="judge_names",
        attacker_key="attacker",
        attacker_config_key="attacker_config",
        resources=expected_resources,
        exceptions=expected_exceptions,
    )
    expected_target_resources = expected_resources.get("vllm_target", set())
    expected_target_exceptions = expected_exceptions.get("vllm_target", set())
    observed_target_resources = observed_resources.get("vllm_target", set())
    observed_target_exceptions = observed_exceptions.get("vllm_target", set())
    if (
        len(observed_target_resources) + len(observed_target_exceptions) > 1
        or len(expected_target_resources) + len(expected_target_exceptions) > 1
        or (
            (expected_target_resources or expected_target_exceptions)
            and (
                expected_target_resources != observed_target_resources
                or expected_target_exceptions != observed_target_exceptions
            )
        )
    ):
        raise ModelAcquisitionError(
            "cell local target differs from the grid-wide model acquisition inventory"
        )
    _validate_shared_role_inventories(
        observed_resources,
        observed_exceptions,
        expected_resources,
        expected_exceptions,
    )
    if bool(observed_resources) != (canonical.get("status") == "verified"):
        raise ModelAcquisitionError(
            "model acquisition status differs from selected Hub roles"
        )
    return canonical


def validate_model_acquisition_grid_binding(
    descriptor: object,
    grid_request: object,
) -> dict[str, Any]:
    """Bind the complete repeatable-target inventory to one grid request."""

    canonical = validate_model_acquisition_execution_descriptor(descriptor)
    if not isinstance(grid_request, dict):
        raise ModelAcquisitionError("model acquisition grid binding is invalid")
    observed_resources, observed_exceptions = _selection_role_inventories(
        canonical["selection"]
    )
    expected_resources: _RoleResources = {}
    expected_exceptions: _RoleExceptions = {}
    models = grid_request.get("models")
    local_configs = grid_request.get("local_configs")
    if (
        not isinstance(models, list)
        or any(not isinstance(model, str) for model in models)
        or len(set(models)) != len(models)
        or not isinstance(local_configs, dict)
    ):
        raise ModelAcquisitionError(
            "model acquisition grid target inventory is invalid"
        )
    for model in models:
        _add_persisted_vllm_identity(
            model,
            local_configs.get(model),
            role="vllm_target",
            resources=expected_resources,
            exceptions=expected_exceptions,
        )
    if (
        len(expected_resources.get("vllm_target", set()))
        + len(expected_exceptions.get("vllm_target", set()))
        > 1
    ):
        raise ModelAcquisitionError(
            "model acquisition grid contains more than one local target"
        )
    _add_shared_run_identities(
        grid_request,
        judge_key="judges",
        attacker_key="attackers",
        attacker_config_key="attacker_configs",
        resources=expected_resources,
        exceptions=expected_exceptions,
    )
    if (
        observed_resources != expected_resources
        or observed_exceptions != expected_exceptions
    ):
        raise ModelAcquisitionError(
            "model acquisition inventory differs from the complete grid request"
        )
    if bool(expected_resources) != (canonical.get("status") == "verified"):
        raise ModelAcquisitionError(
            "model acquisition status differs from grid Hub roles"
        )
    return canonical


def validate_model_acquisition_role_projection(value: object) -> dict[str, Any]:
    """Validate a plan-free scientific projection of acquisition role evidence.

    Grid plan IDs, caller input bindings, and unrelated target resources are
    deliberately absent.  The projection remains meaningful only together with
    an exact projection check against the grid's fully validated execution
    descriptor.
    """

    if not isinstance(value, dict) or set(value) != {
        "exceptions",
        "projection_sha256",
        "resources",
        "schema",
        "scope",
    }:
        raise ModelAcquisitionError(
            "model acquisition role projection fields are invalid"
        )
    if value.get("schema") != ROLE_PROJECTION_SCHEMA:
        raise ModelAcquisitionError(
            "model acquisition role projection schema is invalid"
        )
    scope = value.get("scope")
    if scope not in {"cell", "shared"}:
        raise ModelAcquisitionError(
            "model acquisition role projection scope is invalid"
        )
    allowed_roles = set(_SHARED_SCIENTIFIC_ROLES)
    if scope == "cell":
        allowed_roles.add("vllm_target")

    raw_resources = value.get("resources")
    if not isinstance(raw_resources, list):
        raise ModelAcquisitionError(
            "model acquisition role projection resources are invalid"
        )
    resource_fields = {
        "file_count",
        "repo_id",
        "resource_id",
        "revision",
        "roles",
        "storage",
        "total_bytes",
        "tree_sha256",
        "upstream_manifest_id",
        "upstream_manifest_sha256",
    }
    resources: list[dict[str, Any]] = []
    prior_resource_key: tuple[str, str] | None = None
    target_count = 0
    for resource in raw_resources:
        if not isinstance(resource, dict) or set(resource) != resource_fields:
            raise ModelAcquisitionError(
                "model acquisition role projection resource fields are invalid"
            )
        repo_id = validate_repo_id(resource.get("repo_id"))
        revision = validate_revision(resource.get("revision"))
        roles = resource.get("roles")
        if (
            not isinstance(roles, list)
            or not roles
            or roles != sorted(set(roles))
            or any(role not in allowed_roles for role in roles)
        ):
            raise ModelAcquisitionError(
                "model acquisition role projection resource roles are invalid"
            )
        for role in roles:
            hub_requirement(role, repo_id, revision)
        resource_id = resource.get("resource_id")
        manifest_id = resource.get("upstream_manifest_id")
        if (
            not isinstance(resource_id, str)
            or _RESOURCE_ID.fullmatch(resource_id) is None
            or not isinstance(manifest_id, str)
            or _MANIFEST_ID.fullmatch(manifest_id) is None
            or resource.get("storage") != "managed_store"
        ):
            raise ModelAcquisitionError(
                "model acquisition role projection resource identity is invalid"
            )
        _validated_digest(
            resource.get("tree_sha256"),
            label="role projection tree SHA-256",
        )
        _validated_digest(
            resource.get("upstream_manifest_sha256"),
            label="role projection manifest SHA-256",
        )
        file_count = resource.get("file_count")
        total_bytes = resource.get("total_bytes")
        if (
            isinstance(file_count, bool)
            or not isinstance(file_count, int)
            or not 1 <= file_count <= MAX_SNAPSHOT_FILES
            or isinstance(total_bytes, bool)
            or not isinstance(total_bytes, int)
            or not 0 <= total_bytes <= MAX_SNAPSHOT_BYTES
        ):
            raise ModelAcquisitionError(
                "model acquisition role projection snapshot bounds are invalid"
            )
        key = (repo_id, revision)
        if prior_resource_key is not None and key <= prior_resource_key:
            raise ModelAcquisitionError(
                "model acquisition role projection resources are not canonical"
            )
        prior_resource_key = key
        target_count += int("vllm_target" in roles)
        resources.append({field: resource[field] for field in sorted(resource_fields)})

    raw_exceptions = value.get("exceptions")
    if not isinstance(raw_exceptions, list):
        raise ModelAcquisitionError(
            "model acquisition role projection exceptions are invalid"
        )
    exceptions: list[dict[str, str]] = []
    for exception in raw_exceptions:
        if not isinstance(exception, dict) or set(exception) != {
            "identity",
            "kind",
            "role",
        }:
            raise ModelAcquisitionError(
                "model acquisition role projection exception fields are invalid"
            )
        identity = exception.get("identity")
        kind = exception.get("kind")
        role = exception.get("role")
        if (
            not isinstance(identity, str)
            or not identity.startswith("sha256:")
            or _SHA256.fullmatch(identity.removeprefix("sha256:")) is None
            or role not in allowed_roles
            or (kind == "explicit_local_checkpoint" and role not in {
                "vllm_target", "llm_judge",
            })
            or (kind == "precomputed_suffix_replay" and role != "nanogcg_surrogate")
            or kind not in {
                "explicit_local_checkpoint",
                "precomputed_suffix_replay",
            }
        ):
            raise ModelAcquisitionError(
                "model acquisition role projection exception is invalid"
            )
        target_count += int(role == "vllm_target")
        exceptions.append(dict(exception))
    canonical_exceptions = sorted(
        exceptions,
        key=lambda item: (item["role"], item["kind"], item["identity"]),
    )
    if exceptions != canonical_exceptions or len({
        (item["role"], item["kind"], item["identity"])
        for item in exceptions
    }) != len(exceptions):
        raise ModelAcquisitionError(
            "model acquisition role projection exceptions are not canonical"
        )
    if target_count > 1:
        raise ModelAcquisitionError(
            "model acquisition cell projection contains more than one local target"
        )
    body = {
        "exceptions": exceptions,
        "resources": resources,
        "schema": ROLE_PROJECTION_SCHEMA,
        "scope": scope,
    }
    if value.get("projection_sha256") != _sha256(body):
        raise ModelAcquisitionError(
            "model acquisition role projection digest is stale"
        )
    return {**body, "projection_sha256": value["projection_sha256"]}


def _model_acquisition_role_projection(
    descriptor: object,
    *,
    scope: str,
    include_target: bool,
) -> dict[str, Any]:
    canonical = validate_model_acquisition_execution_descriptor(descriptor)
    roles = set(_SHARED_SCIENTIFIC_ROLES)
    if include_target:
        roles.add("vllm_target")
    resources: list[dict[str, Any]] = []
    receipt_resources = {
        (item["repo_id"], item["revision"]): item
        for item in canonical.get("resources", [])
    }
    for resource in canonical["selection"]["resources"]:
        selected_roles = sorted(set(resource["roles"]) & roles)
        if not selected_roles:
            continue
        receipt_resource = receipt_resources[(
            resource["repo_id"],
            resource["revision"],
        )]
        projected = dict(receipt_resource)
        projected["roles"] = selected_roles
        resources.append(projected)
    exceptions = [
        dict(item)
        for item in canonical["selection"]["exceptions"]
        if item["role"] in roles
    ]
    body = {
        "exceptions": exceptions,
        "resources": resources,
        "schema": ROLE_PROJECTION_SCHEMA,
        "scope": scope,
    }
    return validate_model_acquisition_role_projection({
        **body,
        "projection_sha256": _sha256(body),
    })


def model_acquisition_shared_role_projection(
    descriptor: object,
) -> dict[str, Any]:
    """Project only judge/guard/defense/surrogate acquisition facts."""

    return _model_acquisition_role_projection(
        descriptor,
        scope="shared",
        include_target=False,
    )


def model_acquisition_cell_role_projection(
    descriptor: object,
    run_config: object,
) -> dict[str, Any]:
    """Project shared facts plus this cell's exact local target, if any."""

    canonical = validate_model_acquisition_run_binding(descriptor, run_config)
    if not isinstance(run_config, dict):
        raise ModelAcquisitionError("model acquisition run binding is invalid")
    expected_resources: _RoleResources = {}
    expected_exceptions: _RoleExceptions = {}
    _add_persisted_vllm_identity(
        run_config.get("model_spec"),
        run_config.get("local_identity"),
        role="vllm_target",
        resources=expected_resources,
        exceptions=expected_exceptions,
    )
    include_target = bool(
        expected_resources.get("vllm_target")
        or expected_exceptions.get("vllm_target")
    )
    return _model_acquisition_role_projection(
        canonical,
        scope="cell",
        include_target=include_target,
    )


def model_acquisition_shared_from_cell_projection(
    projection: object,
) -> dict[str, Any]:
    """Normalize a cell projection for cross-target cohort comparison."""

    canonical = validate_model_acquisition_role_projection(projection)
    if canonical["scope"] != "cell":
        raise ModelAcquisitionError(
            "shared cohort normalization requires a cell role projection"
        )
    resources: list[dict[str, Any]] = []
    for resource in canonical["resources"]:
        roles = sorted(set(resource["roles"]) & _SHARED_SCIENTIFIC_ROLES)
        if roles:
            resources.append({**resource, "roles": roles})
    exceptions = [
        dict(item)
        for item in canonical["exceptions"]
        if item["role"] in _SHARED_SCIENTIFIC_ROLES
    ]
    body = {
        "exceptions": exceptions,
        "resources": resources,
        "schema": ROLE_PROJECTION_SCHEMA,
        "scope": "shared",
    }
    return validate_model_acquisition_role_projection({
        **body,
        "projection_sha256": _sha256(body),
    })


def validate_model_acquisition_role_projection_binding(
    projection: object,
    descriptor: object,
    *,
    run_config: object | None = None,
) -> dict[str, Any]:
    """Require one projection to be the exact subset of full grid evidence."""

    canonical = validate_model_acquisition_role_projection(projection)
    if canonical["scope"] == "shared":
        expected = model_acquisition_shared_role_projection(descriptor)
    else:
        if run_config is None:
            raise ModelAcquisitionError(
                "cell role projection binding requires run configuration"
            )
        expected = model_acquisition_cell_role_projection(descriptor, run_config)
    if canonical != expected:
        raise ModelAcquisitionError(
            "model acquisition role projection differs from full grid evidence"
        )
    return canonical


def build_runtime_plan(selection: RuntimeSelection) -> dict[str, Any]:
    """Build the only acquisition plan admissible for ``selection``."""

    canonical = validate_runtime_selection(selection)
    if not canonical.requirements:
        raise ModelAcquisitionError("runtime selection has no Hub resources to acquire")
    return build_plan(canonical.requirements, bindings=canonical.plan_bindings)


def validate_runtime_plan(
    value: object,
    *,
    selection: RuntimeSelection,
) -> dict[str, Any]:
    """Require byte-for-byte canonical resource and binding equality."""

    if not isinstance(value, dict):
        raise ModelAcquisitionError("runtime acquisition plan must be an object")
    canonical = validate_plan(value)
    expected = build_runtime_plan(selection)
    if canonical != expected:
        raise ModelAcquisitionError(
            "acquisition plan resources or immutable selection bindings differ"
        )
    return canonical


def hf_offline_environment_overrides() -> dict[str, str]:
    """Return the non-secret environment overrides for a measured child."""

    return dict(_HF_OFFLINE_ENVIRONMENT)


def ensure_interpreter_scripts_on_path() -> None:
    """Make console scripts installed beside this interpreter reachable.

    A local engine can compile a kernel at first use and shell out to a build
    tool: vLLM's sampler path JIT-builds a FlashInfer kernel and runs ``ninja``,
    and Torch's C++ extension loader does the same. Those tools are installed as
    ordinary dependencies, into the scripts directory of the very interpreter
    that is running, but invoking an interpreter by absolute path does not put
    that directory on PATH the way activating its environment would, and the
    documented commands and the console both invoke it by absolute path. The
    build then fails with ``FileNotFoundError: 'ninja'`` inside a worker
    subprocess, and the engine reports only that initialization failed.

    Prepending the interpreter's own scripts directory is deterministic and
    exposes nothing that was not already installed alongside the interpreter.
    """

    scripts = Path(sys.executable).resolve().parent
    current = os.environ.get("PATH", "")
    entries = [entry for entry in current.split(os.pathsep) if entry] if current else []
    if str(scripts) in entries:
        return
    os.environ["PATH"] = os.pathsep.join([str(scripts), *entries])


def transformers_local_only_kwargs() -> dict[str, bool]:
    """Arguments that prohibit a Transformers loader from consulting the Hub."""

    return {"local_files_only": True}


def vllm_managed_snapshot_kwargs(snapshot: Path | str) -> dict[str, str]:
    """Private in-memory vLLM loader arguments for one verified snapshot."""

    path = _validated_private_snapshot(snapshot)
    return {"model": str(path), "tokenizer": str(path)}


def transformers_managed_snapshot_args(snapshot: Path | str) -> tuple[str, dict[str, bool]]:
    """Private in-memory positional path and local-only Transformers kwargs."""

    path = _validated_private_snapshot(snapshot)
    return str(path), transformers_local_only_kwargs()


def _validated_private_snapshot(snapshot: Path | str) -> Path:
    path = Path(snapshot)
    if not path.is_absolute():
        raise ModelAcquisitionError("managed snapshot loader input must be absolute")
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError("managed snapshot loader input cannot be inspected") from exc
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or resolved != path:
        raise ModelAcquisitionError("managed snapshot loader input is not a safe directory")
    return resolved


def _validated_private_file(value: Path | str, *, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ModelAcquisitionError(f"private {label} locator must be absolute")
    return path


def _validated_store(value: Path | str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ModelAcquisitionError("managed model store must be absolute")
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ModelAcquisitionError("managed model store cannot be inspected") from exc
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or resolved != path:
        raise ModelAcquisitionError("managed model store is not a safe directory")
    return resolved


class _SharedResourceLock:
    """Non-blocking shared counterpart to the acquisition controller lock."""

    def __init__(self, store: Path, resource_id: str) -> None:
        if _RESOURCE_ID.fullmatch(resource_id) is None:
            raise ModelAcquisitionError("managed model resource id is invalid")
        self._path = store / f".{resource_id}.lock"
        self._stream: Any = None

    def __enter__(self) -> "_SharedResourceLock":
        if self._path.parent == self._path or self._path.is_symlink():
            raise ModelAcquisitionError("managed model resource lock is unsafe")
        descriptor: int | None = None
        try:
            parent = self._path.parent.resolve(strict=True)
            if self._path.parent != parent or parent.is_junction():
                raise ModelAcquisitionError(
                    "managed model resource lock parent is unsafe"
                )
            before: os.stat_result | None
            try:
                before = self._path.lstat()
            except FileNotFoundError:
                before = None
            if before is not None and (
                self._path.is_symlink()
                or self._path.is_junction()
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
            ):
                raise ModelAcquisitionError(
                    "managed model resource lock path is unsafe"
                )
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(self._path, flags, 0o600)
            info = os.fstat(descriptor)
            after = self._path.lstat()
            identity = (info.st_dev, info.st_ino, info.st_mode)
            named_identity = (after.st_dev, after.st_ino, after.st_mode)
            if (
                self._path.is_symlink()
                or self._path.is_junction()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or identity != named_identity
                or (
                    before is not None
                    and (before.st_dev, before.st_ino, before.st_mode) != identity
                )
                or self._path.resolve(strict=True) != self._path
            ):
                raise ModelAcquisitionError("managed model resource lock is not regular")
            self._stream = os.fdopen(descriptor, "r+b", closefd=True)
            descriptor = None
            self._stream.seek(0)
            if self._stream.read(1) != b"L":
                self._stream.seek(0)
                self._stream.write(b"L")
                self._stream.flush()
            self._stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._stream.fileno(), msvcrt.LK_NBRLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._stream.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
        except (ImportError, OSError, ModelAcquisitionError) as exc:
            if descriptor is not None:
                os.close(descriptor)
            if self._stream is not None:
                self._stream.close()
                self._stream = None
            raise ModelAcquisitionError(
                "managed model resource is busy with another acquisition or load"
            ) from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        del exc_type, exc, traceback
        if self._stream is None:
            return
        try:
            self._stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
        finally:
            self._stream.close()
            self._stream = None


def sanitize_private_paths(
    message: object,
    private_values: Iterable[Path | str],
    *,
    replacement: str = "[managed-model-private]",
) -> str:
    """Redact private path spellings from one bounded diagnostic.

    Windows paths are case-insensitive and third-party libraries routinely
    render the same locator with native separators, POSIX separators, JSON
    escaping, or ``file:`` URI quoting.  Literal case-sensitive replacement
    therefore is not a privacy boundary.  Generate every relevant spelling
    and replace it case-insensitively before a diagnostic reaches stdout,
    stderr, an exception, or a persisted error artifact.
    """

    if not isinstance(replacement, str) or not replacement:
        raise ModelAcquisitionError("private path replacement is invalid")
    rendered = str(message)
    raw_candidates: set[str] = set()
    for value in private_values:
        path = Path(value)
        raw_candidates.add(str(value))
        raw_candidates.add(str(path))
        try:
            resolved = path.expanduser().resolve(strict=False)
        except (OSError, RuntimeError):
            resolved = None
        if resolved is not None:
            raw_candidates.add(str(resolved))
            try:
                raw_candidates.add(resolved.as_uri())
            except ValueError:
                pass

    candidates: set[str] = set()
    for candidate in raw_candidates:
        if not candidate:
            continue
        spellings = {
            candidate,
            candidate.replace("\\", "/"),
            candidate.replace("/", "\\"),
        }
        for spelling in spellings:
            if not spelling:
                continue
            candidates.add(spelling)
            # json.dumps supplies the exact backslash/quote escaping a nested
            # library may have embedded in its error string.
            candidates.add(json.dumps(spelling, ensure_ascii=False)[1:-1])
            candidates.add(spelling.replace("/", r"\/"))

    for candidate in sorted(candidates, key=len, reverse=True):
        rendered = re.sub(
            re.escape(candidate),
            lambda _match: replacement,
            rendered,
            flags=re.IGNORECASE,
        )
    return rendered[:2000]


def _sanitize_private_error(message: str, private_values: Iterable[Path]) -> str:
    return sanitize_private_paths(message, private_values)


class _BoundedPrivateOutput:
    """Capture loader/model output without allowing private locators to logs."""

    encoding = "utf-8"
    errors = "replace"

    def __init__(self, *, maximum: int = 256 * 1024) -> None:
        self._maximum = maximum
        self._parts: list[str] = []
        self._length = 0
        self._truncated = False
        self._lock = threading.Lock()

    @property
    def buffer(self) -> "_BoundedPrivateOutput":
        return self

    def write(self, value: object) -> int:
        raw_length = len(value) if isinstance(value, (str, bytes)) else len(str(value))
        text = (
            value.decode("utf-8", errors="replace")
            if isinstance(value, bytes)
            else str(value)
        )
        with self._lock:
            remaining = self._maximum - self._length
            if remaining > 0:
                retained = text[:remaining]
                self._parts.append(retained)
                self._length += len(retained)
            if len(text) > max(remaining, 0):
                self._truncated = True
        return raw_length

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False

    def text(self) -> str:
        with self._lock:
            value = "".join(self._parts)
            truncated = self._truncated
        if truncated:
            value += "\n[managed-model output truncated]\n"
        return value


@contextmanager
def _capture_file_descriptor(
    descriptor: int,
    destination: _BoundedPrivateOutput,
):  # noqa: ANN202
    """Drain one process fd while a third-party callback owns model locators."""

    saved = os.dup(descriptor)
    read_descriptor, write_descriptor = os.pipe()
    reader_error: list[BaseException] = []

    def drain() -> None:
        try:
            while chunk := os.read(read_descriptor, 64 * 1024):
                destination.write(chunk)
        except OSError as exc:
            reader_error.append(exc)
        finally:
            try:
                os.close(read_descriptor)
            except OSError:
                pass

    reader = threading.Thread(
        target=drain,
        name=f"ura-private-fd-{descriptor}",
        daemon=True,
    )
    try:
        os.dup2(write_descriptor, descriptor)
        os.close(write_descriptor)
        write_descriptor = -1
        reader.start()
        yield
    finally:
        try:
            os.dup2(saved, descriptor)
        finally:
            os.close(saved)
            if write_descriptor >= 0:
                os.close(write_descriptor)
        reader.join(timeout=5)
        if reader.is_alive():
            try:
                os.close(read_descriptor)
            except OSError:
                pass
            reader.join(timeout=1)
        # A closed read side during bounded teardown is expected. Other reader
        # errors cannot be rendered because doing so could itself expose data.
        del reader_error[:]


@contextmanager
def _capture_process_output(
    stdout_destination: _BoundedPrivateOutput,
    stderr_destination: _BoundedPrivateOutput,
):  # noqa: ANN202
    """Capture Python, native, logging-handler, and inherited-child output."""

    with _PRIVATE_STREAM_LOCK:
        for stream in (os.sys.stdout, os.sys.stderr):
            try:
                stream.flush()
            except (AttributeError, OSError):
                pass
        with _capture_file_descriptor(1, stdout_destination):
            with _capture_file_descriptor(2, stderr_destination):
                yield


class _PrivateLoggingFilter(logging.Filter):
    """Sanitize handlers bound before stdout/stderr redirection begins."""

    def __init__(self, private_values: tuple[Path, ...]) -> None:
        super().__init__()
        self._private_values = private_values

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = "managed-model logging event"
        if record.exc_info is not None:
            message += ": " + str(record.exc_info[1])
        record.msg = _sanitize_private_error(message, self._private_values)
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


@contextmanager
def _redact_prebound_logging(private_values: tuple[Path, ...]):  # noqa: ANN202
    sanitizer = _PrivateLoggingFilter(private_values)
    handlers: list[logging.Handler] = []
    loggers = [logging.getLogger()]
    loggers.extend(
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    )
    for logger in loggers:
        for handler in logger.handlers:
            if handler not in handlers:
                handler.addFilter(sanitizer)
                handlers.append(handler)
    try:
        yield
    finally:
        for handler in handlers:
            handler.removeFilter(sanitizer)


def private_model_execution(
    callback: Callable[[], _T],
    *,
    role: str,
    private_values: Iterable[Path | str],
) -> _T:
    """Run third-party model code with path-redacted output and exceptions."""

    if not callable(callback):
        raise ModelAcquisitionError("private model callback must be callable")
    checked_values = tuple(Path(value) for value in private_values)
    stdout_capture = _BoundedPrivateOutput()
    stderr_capture = _BoundedPrivateOutput()
    original_stdout = os.sys.stdout
    original_stderr = os.sys.stderr
    error: BaseException | None = None
    result: _T | None = None
    with _redact_prebound_logging(checked_values):
        with _capture_process_output(stdout_capture, stderr_capture):
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                try:
                    result = callback()
                except BaseException as exc:
                    error = exc
    for original, captured in (
        (original_stdout, stdout_capture.text()),
        (original_stderr, stderr_capture.text()),
    ):
        sanitized = _sanitize_private_error(captured, checked_values)
        if sanitized:
            original.write(sanitized)
            original.flush()
    if error is not None and isinstance(error, Exception):
        raise ManagedModelLoadError(
            f"sealed {role} execution failed: "
            + _sanitize_private_error(str(error), checked_values)
        ) from None
    if error is not None:
        raise error
    return result  # type: ignore[return-value]


class ManagedModelRuntime:
    """Private plan/receipt/store handles for zero-network model construction.

    ``admit`` is the normal preflight gate. ``construct`` is the stronger engine
    boundary: it holds a shared lock for every planned resource across complete
    pre-verification, loader construction, and complete post-verification.  The
    loaded object is returned only after the post-check succeeds, so callers
    cannot issue a target, judge, guard, or surrogate call beforehand.
    """

    def __init__(
        self,
        *,
        selection: RuntimeSelection,
        plan_path: Path | str,
        plan_sha256: str,
        receipt_path: Path | str,
        receipt_sha256: str,
        managed_store: Path | str,
    ) -> None:
        if not isinstance(selection, RuntimeSelection) or not selection.requirements:
            raise ModelAcquisitionError("managed runtime needs a non-empty selection")
        self._selection = validate_runtime_selection(selection)
        self._plan_path = _validated_private_file(plan_path, label="plan")
        self._plan_sha256 = _validated_digest(plan_sha256, label="plan SHA-256")
        self._receipt_path = _validated_private_file(receipt_path, label="receipt")
        self._receipt_sha256 = _validated_digest(
            receipt_sha256,
            label="receipt SHA-256",
        )
        self._managed_store = _validated_store(managed_store)
        self._expected_plan = build_runtime_plan(selection)
        self._receipt_id: str | None = None

    @contextmanager
    def _resource_locks(self):  # noqa: ANN202
        with ExitStack() as stack:
            for resource in self._expected_plan["resources"]:
                stack.enter_context(
                    _SharedResourceLock(self._managed_store, resource["resource_id"])
                )
            yield

    def _load_and_verify(self) -> tuple[dict[str, Any], dict[str, Path]]:
        plan = load_plan(self._plan_path, expected_sha256=self._plan_sha256)
        plan = validate_runtime_plan(plan, selection=self._selection)
        receipt = load_receipt(
            self._receipt_path,
            expected_sha256=self._receipt_sha256,
            plan=plan,
        )
        resolved = verify_receipt_snapshots(
            plan,
            receipt,
            managed_store=self._managed_store,
        )
        self._receipt_id = receipt["receipt_id"]
        return receipt, resolved

    def admit(self) -> dict[str, Any]:
        """Perform a call-free, full-content plan/receipt admission check."""

        with self._resource_locks():
            receipt, _resolved = self._load_and_verify()
        return self.public_descriptor(receipt_id=receipt["receipt_id"])

    def _resource_for(self, requirement: HubRequirement) -> Mapping[str, Any]:
        requested = hub_requirement(
            requirement.role,
            requirement.repo_id,
            requirement.revision,
        )
        if requested not in self._selection.requirements:
            raise ModelAcquisitionError("model loader requested an unplanned resource role")
        matches = [
            resource
            for resource in self._expected_plan["resources"]
            if resource["repo_id"] == requested.repo_id
            and resource["revision"] == requested.revision
            and requested.role in resource["roles"]
        ]
        if len(matches) != 1:
            raise ModelAcquisitionError("planned model resource mapping is ambiguous")
        return matches[0]

    def construct(
        self,
        requirement: HubRequirement,
        constructor: Callable[[Path], _T],
        *,
        cleanup: Callable[[_T], None] | None = None,
    ) -> _T:
        """Construct one model under a full pre/post verification lease.

        ``constructor`` must only construct/load the engine.  It must not issue a
        model inference or judge call; the object is intentionally unavailable
        to its caller until the post-load full-content verification completes.
        """

        if not callable(constructor):
            raise ModelAcquisitionError("managed model constructor must be callable")
        resource = self._resource_for(requirement)
        private_values = (
            self._plan_path,
            self._receipt_path,
            self._managed_store,
        )
        loaded: _T | None = None
        constructor_error: BaseException | None = None
        with self._resource_locks():
            _before_receipt, before = self._load_and_verify()
            snapshot = before[resource["resource_id"]]
            try:
                loaded = private_model_execution(
                    lambda: constructor(snapshot),
                    role=requirement.role,
                    private_values=private_values,
                )
            except BaseException as exc:  # post-verification also runs on cancellation
                constructor_error = exc
            try:
                _after_receipt, after = self._load_and_verify()
                if after != before:
                    raise ModelAcquisitionError(
                        "managed model snapshot mapping changed during construction"
                    )
            except Exception:
                if loaded is not None:
                    self._discard_loaded(loaded, cleanup=cleanup)
                    loaded = None
                raise
        if constructor_error is not None and isinstance(constructor_error, Exception):
            raise ManagedModelLoadError(
                f"sealed {requirement.role} model construction failed: "
                + _sanitize_private_error(str(constructor_error), private_values)
            ) from None
        if constructor_error is not None:
            raise constructor_error
        if loaded is None:
            raise ManagedModelLoadError("sealed model constructor returned no object")
        return loaded

    def private_execution(
        self,
        role: str,
        callback: Callable[[], _T],
    ) -> _T:
        """Run inference while keeping managed locators out of logs/errors."""

        return private_model_execution(
            callback,
            role=role,
            private_values=(
                self._plan_path,
                self._receipt_path,
                self._managed_store,
            ),
        )

    @staticmethod
    def _discard_loaded(
        loaded: _T,
        *,
        cleanup: Callable[[_T], None] | None,
    ) -> None:
        try:
            if cleanup is not None:
                cleanup(loaded)
            else:
                close = getattr(loaded, "close", None)
                if callable(close):
                    close()
        except Exception:
            # Integrity failure remains authoritative; cleanup diagnostics must
            # not mask it or accidentally publish a private loader locator.
            pass
        finally:
            del loaded
            gc.collect()

    def public_descriptor(self, *, receipt_id: str | None = None) -> dict[str, Any]:
        """Return path/token-free acquisition provenance suitable for artifacts."""

        selected_receipt = receipt_id or self._receipt_id
        if selected_receipt is None:
            raise ModelAcquisitionError("managed model runtime has not passed admission")
        return {
            "plan_id": self._expected_plan["plan_id"],
            "plan_sha256": self._plan_sha256,
            "receipt_id": selected_receipt,
            "receipt_sha256": self._receipt_sha256,
            "resources": [
                {
                    "repo_id": resource["repo_id"],
                    "revision": resource["revision"],
                    "roles": list(resource["roles"]),
                }
                for resource in self._expected_plan["resources"]
            ],
            "schema": RUNTIME_DESCRIPTOR_SCHEMA,
            "selection_sha256": self._selection.selection_sha256,
        }


def admit_managed_model_runtime(
    *,
    selection: RuntimeSelection,
    plan_path: Path | str,
    plan_sha256: str,
    receipt_path: Path | str,
    receipt_sha256: str,
    managed_store: Path | str,
) -> tuple[ManagedModelRuntime, dict[str, Any]]:
    """Build and fully admit a private runtime in one call-free operation."""

    runtime = ManagedModelRuntime(
        selection=selection,
        plan_path=plan_path,
        plan_sha256=plan_sha256,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha256,
        managed_store=managed_store,
    )
    return runtime, runtime.admit()


__all__ = [
    "EXECUTION_DESCRIPTOR_SCHEMA",
    "ManagedModelLoadError",
    "ManagedModelRuntime",
    "ModelRequirementSet",
    "NANOGCG_DEFAULT_MODEL_ID",
    "ROLE_PROJECTION_SCHEMA",
    "RUNTIME_DESCRIPTOR_SCHEMA",
    "RuntimeSelection",
    "SELECTION_SCHEMA",
    "admit_managed_model_runtime",
    "build_runtime_plan",
    "build_runtime_selection",
    "collect_run_requirements",
    "hf_offline_environment_overrides",
    "model_acquisition_execution_descriptor",
    "model_acquisition_cell_role_projection",
    "model_acquisition_shared_from_cell_projection",
    "model_acquisition_shared_role_projection",
    "public_selection_descriptor",
    "private_model_execution",
    "sanitize_private_paths",
    "validate_model_acquisition_descriptor",
    "validate_model_acquisition_execution_descriptor",
    "validate_model_acquisition_grid_binding",
    "validate_model_acquisition_role_projection",
    "validate_model_acquisition_role_projection_binding",
    "validate_model_acquisition_run_binding",
    "validate_public_selection_descriptor",
    "transformers_local_only_kwargs",
    "transformers_managed_snapshot_args",
    "validate_runtime_plan",
    "validate_runtime_selection",
    "vllm_managed_snapshot_kwargs",
]
