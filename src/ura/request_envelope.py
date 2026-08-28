"""Pre-materialization request and early-failure provenance.

The request envelope fixes the operator-selected target/source-arm/attacker
universe before source configuration is loaded or a converter runs.  It names
whole Runner execution units only.  In particular, it does not guess source,
policy, modality, or metric strata that can be observed only after conversion.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

from .eligibility import canonical_json_sha256
from .project_revision import validate_project_revision_binding
from .sampling import effective_sampling_policy


REQUEST_ENVELOPE_SCHEMA = "ura-request-envelope/2"
_LEGACY_REQUEST_ENVELOPE_SCHEMA = "ura-request-envelope/1"
REQUEST_ERROR_SCHEMA = "ura-request-error/1"
_ENVELOPE_ID = re.compile(r"request-envelope-[0-9a-f]{24}")
_ERROR_ID = re.compile(r"request-error-[0-9a-f]{24}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MAX_MESSAGE_CHARS = 2000
_MAX_ENVELOPE_BYTES = 4 * 1024 * 1024
_MAX_ERROR_BYTES = 1024 * 1024
_ENVELOPE_FIELDS = frozenset({
    "schema", "status", "envelope_id", "request", "bindings",
    "execution_units", "limitations",
})
_REQUEST_FIELDS_V1 = frozenset({
    "execution_purpose", "requested_target_keys", "logical_source_arms",
    "selected_attackers", "judges", "judge_model", "seeds", "sample_seed",
    "limit", "max_queries", "max_turns", "defense", "defense_guard",
    "group_keys", "quantization", "dtype", "dry_run", "call_caps",
})
_REQUEST_FIELDS = frozenset({
    *_REQUEST_FIELDS_V1,
    "approximate_common_metrics",
    "hosted_judge_data_transfer_acknowledged",
})
_REQUEST_FIELDS_WITH_SAMPLING_POLICY = frozenset({
    *_REQUEST_FIELDS,
    "sampling_policy",
})
# Omitted CLI policy must keep already-retained /2 envelopes byte-compatible.
# The validator therefore admits exactly the deployed inventory or this one
# explicit, content-addressed extension - never an arbitrary optional object.
_BINDING_FIELDS = frozenset({
    "project_revision", "harness_source", "driver_source",
})
_HARNESS_SOURCE_FIELDS = frozenset({
    "algorithm", "sha256", "file_count", "bytes",
})
_DRIVER_SOURCE_FIELDS = frozenset({"module", "sha256", "file_count"})
_UNIT_FIELDS = frozenset({
    "request_unit_id", "requested_target_key", "logical_source_arm",
    "attacker",
})
_DESCRIPTOR_FIELDS = frozenset({"envelope_id", "file", "sha256", "bytes"})
_ERROR_FIELDS = frozenset({
    "schema", "status", "error_id", "request_envelope", "scope", "failure",
    "execution", "limitations",
})
_SCOPE_FIELDS = frozenset({
    "level", "requested_target_key", "logical_source_arm", "attacker",
})
_FAILURE_FIELDS = frozenset({
    "phase", "category", "exception_type", "message",
})
_EXECUTION_FIELDS = frozenset({"execution_started", "provider_calls_started"})
_CALL_CAP_FIELDS = frozenset({
    "target", "judge", "http_attempts", "deadline_seconds",
})
_ERROR_PHASES = frozenset({
    "configuration_preflight",
    "model_acquisition_admission",
    "source_conformance_input_preflight",
    "corpus_preflight",
    "attacker_input_contract_preflight",
    "diagnostic_canary_cluster_admission",
    "source_conformance_preflight",
})
_ERROR_CATEGORIES = frozenset({
    "configuration_invalid",
    "model_acquisition_invalid",
    "source_input_unavailable",
    "source_integrity_failed",
    "conversion_failed",
    "empty_converted_corpus",
    "diagnostic_admission_failed",
})
_SCOPE_LEVELS = frozenset({
    "whole_request", "requested_target", "logical_source_arm", "execution_unit",
})
_ENVELOPE_LIMITATIONS = {
    "source_strata_materialized": False,
    "modality_strata_materialized": False,
    "compatibility_evaluated": False,
    "execution_started": False,
    "provider_calls_made": False,
    "empirical_evidence_established": False,
    "interpretation": (
        "prospective requested whole-arm universe only; source, policy, modality, "
        "metric, eligibility, execution, and empirical claims require later evidence"
    ),
}
_ERROR_LIMITATIONS = {
    "planning_strata_attributed": False,
    "failed_execution_unit_inferred": False,
    "empirical_evidence_established": False,
    "interpretation": (
        "bound early failure only; absent materialized strata are not reconstructed "
        "or counted as attempted"
    ),
}


def _strict_object(
    value: object, fields: frozenset[str], label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{label} has an invalid field inventory")
    return value


def _nonblank(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"{label} must be one nonblank unpadded string")
    return value


def _unique_strings(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty list")
    result = [_nonblank(item, label) for item in value]
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must contain unique strings")
    return result


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value




def _harness_source_binding(value: object) -> dict[str, Any]:
    source = _strict_object(value, _HARNESS_SOURCE_FIELDS, "harness source")
    _nonblank(source["algorithm"], "harness source algorithm")
    if not isinstance(source["sha256"], str) or _HEX64.fullmatch(
        source["sha256"]
    ) is None:
        raise ValueError("harness source SHA-256 is invalid")
    _integer(source["file_count"], "harness source file_count", minimum=1)
    _integer(source["bytes"], "harness source bytes", minimum=1)
    return source


def _driver_source_binding(value: object) -> dict[str, Any]:
    source = _strict_object(value, _DRIVER_SOURCE_FIELDS, "driver source")
    _nonblank(source["module"], "driver source module")
    if not isinstance(source["sha256"], str) or _HEX64.fullmatch(
        source["sha256"]
    ) is None:
        raise ValueError("driver source SHA-256 is invalid")
    _integer(source["file_count"], "driver source file_count", minimum=1)
    return source


def _request_unit_id(value: Mapping[str, str]) -> str:
    identity = {
        "requested_target_key": value["requested_target_key"],
        "logical_source_arm": value["logical_source_arm"],
        "attacker": value["attacker"],
    }
    return "request-unit-" + canonical_json_sha256(identity)[:24]


def request_envelope_id(value_without_id: Mapping[str, Any]) -> str:
    """Return the content identity for one strict request envelope body."""

    return "request-envelope-" + canonical_json_sha256(value_without_id)[:24]


def build_request_envelope(
    *,
    request: Mapping[str, Any],
    project_revision: Mapping[str, Any],
    harness_source: Mapping[str, Any],
    driver_source: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the fixed whole-arm request universe before source materialization."""

    request_value = dict(request)
    # Preserve the public builder API for callers authored before schema v2.
    # Newly built artifacts still persist the explicit default-off policy;
    # already-retained v1 artifacts are validated unchanged below.
    request_value.setdefault("approximate_common_metrics", False)
    request_value.setdefault("hosted_judge_data_transfer_acknowledged", False)
    request_fields = (
        _REQUEST_FIELDS_WITH_SAMPLING_POLICY
        if "sampling_policy" in request_value
        else _REQUEST_FIELDS
    )
    _strict_object(request_value, request_fields, "request-envelope request")
    if "sampling_policy" in request_value:
        effective_sampling_policy(request_value["sampling_policy"])
    targets = _unique_strings(
        request_value["requested_target_keys"], "requested target keys"
    )
    arms = _unique_strings(request_value["logical_source_arms"], "logical source arms")
    attackers = _unique_strings(
        request_value["selected_attackers"], "selected attackers"
    )
    units = [
        {
            "request_unit_id": _request_unit_id({
                "requested_target_key": target,
                "logical_source_arm": arm,
                "attacker": attacker,
            }),
            "requested_target_key": target,
            "logical_source_arm": arm,
            "attacker": attacker,
        }
        for target in targets
        for arm in sorted(arms)
        for attacker in attackers
    ]
    units.sort(key=lambda item: item["request_unit_id"])
    bindings = {
        "project_revision": dict(project_revision),
        "harness_source": dict(harness_source),
        "driver_source": dict(driver_source),
    }
    body: dict[str, Any] = {
        "schema": REQUEST_ENVELOPE_SCHEMA,
        "status": "fixed_before_source_materialization",
        "request": request_value,
        "bindings": bindings,
        "execution_units": units,
        "limitations": dict(_ENVELOPE_LIMITATIONS),
    }
    body["envelope_id"] = request_envelope_id(body)
    return validate_request_envelope(body)


def validate_request_envelope(value: object) -> dict[str, Any]:
    """Strictly validate and self-recompute one request envelope."""

    envelope = _strict_object(value, _ENVELOPE_FIELDS, "request envelope")
    schema = envelope["schema"]
    if schema not in {
        REQUEST_ENVELOPE_SCHEMA,
        _LEGACY_REQUEST_ENVELOPE_SCHEMA,
    } or envelope["status"] != "fixed_before_source_materialization":
        raise ValueError("unsupported or incomplete request envelope")
    envelope_id = envelope["envelope_id"]
    body = {key: item for key, item in envelope.items() if key != "envelope_id"}
    if (
        not isinstance(envelope_id, str)
        or _ENVELOPE_ID.fullmatch(envelope_id) is None
        or envelope_id != request_envelope_id(body)
    ):
        raise ValueError("request envelope ID/content mismatch")

    request_value = envelope["request"]
    request_fields = _REQUEST_FIELDS_V1
    if schema == REQUEST_ENVELOPE_SCHEMA:
        request_fields = (
            _REQUEST_FIELDS_WITH_SAMPLING_POLICY
            if isinstance(request_value, dict) and "sampling_policy" in request_value
            else _REQUEST_FIELDS
        )
    request = _strict_object(
        request_value, request_fields, "request-envelope request"
    )
    if "sampling_policy" in request:
        effective_sampling_policy(request["sampling_policy"])
    targets = _unique_strings(request["requested_target_keys"], "requested target keys")
    arms = _unique_strings(request["logical_source_arms"], "logical source arms")
    attackers = _unique_strings(request["selected_attackers"], "selected attackers")
    judges = _unique_strings(request["judges"], "request judges")
    group_keys = _unique_strings(request["group_keys"], "request group keys")
    del judges, group_keys
    purpose = _nonblank(request["execution_purpose"], "execution purpose")
    if purpose not in {
        "diagnostic_canary", "diagnostic_dry_run", "preflight_only",
        "attestation_probe", "measured_run",
    }:
        raise ValueError("request envelope has an invalid execution purpose")
    if request["dry_run"] is True and purpose not in {
        "diagnostic_dry_run", "diagnostic_canary",
    }:
        raise ValueError("request envelope purpose/dry-run state is inconsistent")
    if request["dry_run"] is False and purpose == "diagnostic_dry_run":
        raise ValueError("request envelope purpose/dry-run state is inconsistent")
    for field in ("defense", "defense_guard", "quantization", "dtype"):
        if not isinstance(request[field], str) or request[field] != request[field].strip():
            raise ValueError(f"request envelope {field} must be an unpadded string")
    judge_model = request["judge_model"]
    if judge_model is not None:
        _nonblank(judge_model, "request judge_model")
    seeds = request["seeds"]
    if (
        not isinstance(seeds, list)
        or not seeds
        or any(isinstance(seed, bool) or not isinstance(seed, int) for seed in seeds)
        or len(set(seeds)) != len(seeds)
    ):
        raise ValueError("request envelope seeds must be unique integers")
    if isinstance(request["sample_seed"], bool) or not isinstance(
        request["sample_seed"], int
    ):
        raise ValueError("request sample_seed must be an integer")
    _integer(request["limit"], "request limit")
    _integer(request["max_queries"], "request max_queries", minimum=1)
    _integer(request["max_turns"], "request max_turns", minimum=1)
    if not isinstance(request["dry_run"], bool) or (
        schema == REQUEST_ENVELOPE_SCHEMA
        and (
            not isinstance(request["approximate_common_metrics"], bool)
            or not isinstance(
                request["hosted_judge_data_transfer_acknowledged"], bool
            )
        )
    ):
        raise ValueError(
            "request envelope dry_run/approximate_common_metrics/hosted-judge "
            "data-transfer acknowledgement must be boolean"
        )
    caps = _strict_object(request["call_caps"], _CALL_CAP_FIELDS, "request call caps")
    for field, item in caps.items():
        if item is not None:
            _integer(item, f"request call cap {field}", minimum=1)

    bindings = _strict_object(
        envelope["bindings"], _BINDING_FIELDS, "request-envelope bindings"
    )
    project = validate_project_revision_binding(
        bindings["project_revision"], allow_not_required=request["dry_run"] is True
    )
    harness = _harness_source_binding(bindings["harness_source"])
    driver = _driver_source_binding(bindings["driver_source"])
    if project["harness_source_sha256"] != harness["sha256"]:
        raise ValueError("request envelope project/harness source mismatch")
    if project["driver_source_sha256"] != driver["sha256"]:
        raise ValueError("request envelope project/driver source mismatch")

    units = envelope["execution_units"]
    if not isinstance(units, list) or not units:
        raise ValueError("request envelope requires execution units")
    observed: set[tuple[str, str, str]] = set()
    prior_id = ""
    for unit in units:
        item = _strict_object(unit, _UNIT_FIELDS, "request-envelope execution unit")
        key = (
            _nonblank(item["requested_target_key"], "unit target key"),
            _nonblank(item["logical_source_arm"], "unit source arm"),
            _nonblank(item["attacker"], "unit attacker"),
        )
        unit_id = item["request_unit_id"]
        if unit_id != _request_unit_id({
            "requested_target_key": key[0],
            "logical_source_arm": key[1],
            "attacker": key[2],
        }):
            raise ValueError("request-envelope execution-unit ID/content mismatch")
        if unit_id <= prior_id or key in observed:
            raise ValueError("request-envelope execution units are not canonical")
        prior_id = unit_id
        observed.add(key)
    expected = {
        (target, arm, attacker)
        for target in targets for arm in arms for attacker in attackers
    }
    if observed != expected:
        raise ValueError("request envelope omits a requested whole-arm execution unit")
    if envelope["limitations"] != _ENVELOPE_LIMITATIONS:
        raise ValueError("request envelope limitations are invalid")
    return envelope


def request_envelope_bytes(value: object) -> bytes:
    """Return deterministic retained bytes after strict validation."""

    envelope = validate_request_envelope(value)
    return (
        json.dumps(
            envelope, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def write_request_envelope(out: Path, value: object) -> Path:
    """Create or verify one content-addressed envelope without overwriting."""

    envelope = validate_request_envelope(value)
    payload = request_envelope_bytes(envelope)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{envelope['envelope_id']}.request-envelope.json"
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
            raise ValueError(f"request envelope artifact collision: {path}")
    else:
        with path.open("xb") as handle:
            handle.write(payload)
    return path


def request_envelope_descriptor(path: Path, value: object) -> dict[str, Any]:
    """Describe the exact retained bytes used by later lifecycle identities."""

    envelope = validate_request_envelope(value)
    if path.is_symlink() or not path.is_file():
        raise ValueError("request envelope descriptor requires a regular file")
    payload = path.read_bytes()
    if payload != request_envelope_bytes(envelope):
        raise ValueError("request envelope artifact bytes do not match content")
    return {
        "envelope_id": envelope["envelope_id"],
        "file": path.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def load_request_envelope_file(path_value: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load one bounded, strict, content-self-identifying envelope file."""

    path, raw, value = _load_strict_json_file(
        path_value, label="request envelope", max_bytes=_MAX_ENVELOPE_BYTES
    )
    envelope = validate_request_envelope(value)
    expected_name = f"{envelope['envelope_id']}.request-envelope.json"
    if path.name != expected_name:
        raise ValueError("request envelope filename/content identity mismatch")
    canonical = request_envelope_bytes(envelope)
    if raw != canonical:
        raise ValueError("request envelope file is not canonical deterministic JSON")
    descriptor = {
        "envelope_id": envelope["envelope_id"],
        "file": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
    return envelope, validate_request_envelope_descriptor(descriptor)


def validate_request_envelope_descriptor(value: object) -> dict[str, Any]:
    descriptor = _strict_object(
        value, _DESCRIPTOR_FIELDS, "request-envelope descriptor"
    )
    if (
        not isinstance(descriptor["envelope_id"], str)
        or _ENVELOPE_ID.fullmatch(descriptor["envelope_id"]) is None
        or not isinstance(descriptor["file"], str)
        or Path(descriptor["file"]).name != descriptor["file"]
        or descriptor["file"]
        != f"{descriptor['envelope_id']}.request-envelope.json"
        or not isinstance(descriptor["sha256"], str)
        or _HEX64.fullmatch(descriptor["sha256"]) is None
    ):
        raise ValueError("request-envelope descriptor identity is invalid")
    _integer(descriptor["bytes"], "request-envelope descriptor bytes", minimum=1)
    return descriptor


def request_error_id(value_without_id: Mapping[str, Any]) -> str:
    return "request-error-" + canonical_json_sha256(value_without_id)[:24]


def build_request_error(
    *,
    envelope: Mapping[str, Any],
    envelope_descriptor: Mapping[str, Any],
    phase: str,
    category: str,
    exception_type: str,
    message: str,
    requested_target_key: str | None = None,
    logical_source_arm: str | None = None,
    attacker: str | None = None,
) -> dict[str, Any]:
    """Build a bound, no-call error without fabricating planning strata."""

    validated = validate_request_envelope(dict(envelope))
    descriptor = validate_request_envelope_descriptor(dict(envelope_descriptor))
    if descriptor["envelope_id"] != validated["envelope_id"]:
        raise ValueError("request error descriptor/envelope identity mismatch")
    scope_values = (requested_target_key, logical_source_arm, attacker)
    present = tuple(value is not None for value in scope_values)
    if present == (False, False, False):
        level = "whole_request"
    elif present == (True, False, False):
        level = "requested_target"
    elif present == (False, True, False):
        level = "logical_source_arm"
    elif present == (True, True, True):
        level = "execution_unit"
    else:
        raise ValueError("request error has an unsupported partial scope")
    message_value = " ".join(str(message).split()) or str(exception_type)
    body: dict[str, Any] = {
        "schema": REQUEST_ERROR_SCHEMA,
        "status": "error",
        "request_envelope": dict(descriptor),
        "scope": {
            "level": level,
            "requested_target_key": requested_target_key,
            "logical_source_arm": logical_source_arm,
            "attacker": attacker,
        },
        "failure": {
            "phase": phase,
            "category": category,
            "exception_type": exception_type,
            "message": message_value[:_MAX_MESSAGE_CHARS],
        },
        "execution": {
            "execution_started": False,
            "provider_calls_started": False,
        },
        "limitations": dict(_ERROR_LIMITATIONS),
    }
    body["error_id"] = request_error_id(body)
    return validate_request_error(body, envelope=validated)


def validate_request_error(
    value: object, *, envelope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    error = _strict_object(value, _ERROR_FIELDS, "request error")
    if error["schema"] != REQUEST_ERROR_SCHEMA or error["status"] != "error":
        raise ValueError("unsupported request error")
    error_id = error["error_id"]
    body = {key: item for key, item in error.items() if key != "error_id"}
    if (
        not isinstance(error_id, str)
        or _ERROR_ID.fullmatch(error_id) is None
        or error_id != request_error_id(body)
    ):
        raise ValueError("request error ID/content mismatch")
    descriptor = validate_request_envelope_descriptor(error["request_envelope"])
    scope = _strict_object(error["scope"], _SCOPE_FIELDS, "request-error scope")
    level = scope["level"]
    if level not in _SCOPE_LEVELS:
        raise ValueError("request error scope level is invalid")
    values = tuple(
        scope[field] for field in (
            "requested_target_key", "logical_source_arm", "attacker"
        )
    )
    expected_presence = {
        "whole_request": (False, False, False),
        "requested_target": (True, False, False),
        "logical_source_arm": (False, True, False),
        "execution_unit": (True, True, True),
    }[level]
    if tuple(item is not None for item in values) != expected_presence:
        raise ValueError("request error scope fields disagree with its level")
    for item in values:
        if item is not None:
            _nonblank(item, "request error scope value")
    failure = _strict_object(
        error["failure"], _FAILURE_FIELDS, "request-error failure"
    )
    if failure["phase"] not in _ERROR_PHASES:
        raise ValueError("request error phase is invalid")
    if failure["category"] not in _ERROR_CATEGORIES:
        raise ValueError("request error category is invalid")
    _nonblank(failure["exception_type"], "request error exception type")
    message = _nonblank(failure["message"], "request error message")
    if len(message) > _MAX_MESSAGE_CHARS:
        raise ValueError("request error message exceeds its limit")
    execution = _strict_object(
        error["execution"], _EXECUTION_FIELDS, "request-error execution"
    )
    if execution != {"execution_started": False, "provider_calls_started": False}:
        raise ValueError("early request error cannot claim execution or provider calls")
    if error["limitations"] != _ERROR_LIMITATIONS:
        raise ValueError("request error limitations are invalid")
    if envelope is not None:
        expected = validate_request_envelope(dict(envelope))
        if descriptor["envelope_id"] != expected["envelope_id"]:
            raise ValueError("request error is bound to another envelope")
        request = expected["request"]
        membership = zip(
            values,
            (
                request["requested_target_keys"], request["logical_source_arms"],
                request["selected_attackers"],
            ),
        )
        if any(item is not None and item not in allowed for item, allowed in membership):
            raise ValueError("request error scope is outside the requested universe")
    return error


def _load_strict_json_file(
    path_value: Path, *, label: str, max_bytes: int,
) -> tuple[Path, bytes, object]:
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink JSON file")
    path = unresolved.resolve(strict=True)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink JSON file")
    size = path.stat().st_size
    if size <= 0 or size > max_bytes:
        raise ValueError(f"{label} has an invalid byte size")
    raw = path.read_bytes()
    if len(raw) != size:
        raise ValueError(f"{label} changed while being read")

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number {value!r} is forbidden in {label}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError(f"duplicate JSON key {key!r} is forbidden in {label}")
            output[key] = value
        return output

    try:
        value = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label} JSON: {exc}") from exc
    return path, raw, value


def load_request_error_file(
    path_value: Path, *, envelope: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Load one strict content-addressed early request error."""

    path, raw, value = _load_strict_json_file(
        path_value, label="request error", max_bytes=_MAX_ERROR_BYTES
    )
    error = validate_request_error(value, envelope=envelope)
    expected_name = f"{error['error_id']}.request.error.json"
    if path.name != expected_name:
        raise ValueError("request error filename/content identity mismatch")
    canonical = (
        json.dumps(error, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise ValueError("request error file is not canonical deterministic JSON")
    return error


def write_request_error(out: Path, value: object) -> Path:
    """Write one strict content-addressed early-error artifact."""

    error = validate_request_error(value)
    payload = (
        json.dumps(error, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    # The final ``.error.json`` suffix lets lifecycle collectors distinguish
    # this evidence from successful content-addressed inputs.
    path = out / f"{error['error_id']}.request.error.json"
    if path.exists():
        if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
            raise ValueError(f"request error artifact collision: {path}")
    else:
        with path.open("xb") as handle:
            handle.write(payload)
    return path


__all__ = [
    "REQUEST_ENVELOPE_SCHEMA",
    "REQUEST_ERROR_SCHEMA",
    "build_request_envelope",
    "build_request_error",
    "load_request_envelope_file",
    "load_request_error_file",
    "request_envelope_bytes",
    "request_envelope_descriptor",
    "request_envelope_id",
    "request_error_id",
    "validate_request_envelope",
    "validate_request_envelope_descriptor",
    "validate_request_error",
    "write_request_envelope",
    "write_request_error",
]
