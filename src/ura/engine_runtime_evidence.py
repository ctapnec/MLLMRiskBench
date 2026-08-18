"""Strict downstream validation for isolated attacker-runtime evidence.

The private interpreter locator never enters measured artifacts.  A runtime-
backed cell instead binds a status-free execution identity in its manifest to
one closing seal in its completion marker.  Completed grid manifests retain
the full pre-close and post-close selections for audit, but their mutable
statuses are not part of the cell's scientific identity.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .adapters._engine_runtime import (
    ENGINE_RUNTIME_SELECTION_SCHEMA,
    RUNTIME_REQUIRED_ATTACKERS,
    engine_runtime_identity_descriptor,
    validate_engine_runtime_execution_descriptor,
    validate_engine_runtime_identity_descriptor,
    validate_engine_runtime_selection_descriptor,
    validate_engine_runtime_selection_identity_descriptor,
)


LEGACY_RUNTIME_FREE_CODE_VERSION = "ura-runner/2.19"
LEGACY_RUNTIME_FREE_SCHEMA_VERSION = "1.4"


def validate_engine_runtime_artifact_version(
    *,
    attacker: object,
    code_version: object,
    schema_version: object,
    current_code_version: str,
    current_schema_version: str,
) -> bool:
    """Return ``True`` only for an admitted runtime-free legacy cell."""

    if not isinstance(attacker, str) or not attacker:
        raise ValueError("completed cell lacks an attacker identity")
    if (
        code_version == current_code_version
        and schema_version == current_schema_version
    ):
        return False
    if (
        code_version == LEGACY_RUNTIME_FREE_CODE_VERSION
        and schema_version == LEGACY_RUNTIME_FREE_SCHEMA_VERSION
    ):
        if attacker.lower() in RUNTIME_REQUIRED_ATTACKERS:
            raise ValueError(
                "legacy framework evidence predates the required isolated-runtime "
                "closing seal"
            )
        return True
    raise ValueError(
        "completed cell does not use the current runner/schema or the exact "
        "admitted runtime-free legacy pair"
    )


def validate_engine_runtime_identity(
    value: object,
    *,
    expected_engine: str,
) -> dict[str, Any]:
    """Return one canonical, status-free runtime identity."""

    identity = validate_engine_runtime_identity_descriptor(value)
    receipt = identity["receipt"]
    if receipt["engine"] != expected_engine:
        raise ValueError(
            f"engine runtime receipt names {receipt['engine']!r}, expected "
            f"{expected_engine!r}"
        )
    return identity


def validate_closed_engine_runtime(
    value: object,
    *,
    expected_engine: str,
) -> dict[str, Any]:
    """Return one canonical exact closing seal, rejecting status downgrades."""

    close = validate_engine_runtime_execution_descriptor(
        value, required_status="closed_verified"
    )
    if close["receipt"]["engine"] != expected_engine:
        raise ValueError(
            f"engine runtime receipt names {close['receipt']['engine']!r}, expected "
            f"{expected_engine!r}"
        )
    return close


def _runtime_identity_from_seal(value: Mapping[str, Any]) -> dict[str, Any]:
    return engine_runtime_identity_descriptor(value)


def validate_cell_engine_runtime_marker(
    *,
    attacker: object,
    run_config: Mapping[str, Any],
    completion_marker: Mapping[str, Any],
    allow_legacy_missing: bool = True,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Validate the manifest/marker half of one cell runtime binding.

    Non-runtime attackers remain independent: they neither require nor may
    acquire a closing seal merely because another cell in their grid used one.
    """

    if not isinstance(attacker, str) or not attacker:
        raise ValueError("completed cell lacks an attacker identity")
    normalized_attacker = attacker.lower()
    if normalized_attacker not in RUNTIME_REQUIRED_ATTACKERS:
        if completion_marker.get("engine_runtime_close") is not None:
            raise ValueError(
                "non-runtime attacker completion marker has an engine runtime seal"
            )
        # Schema-1.4 evidence predates the disposition field entirely. Preserve
        # that non-runtime read path, but once a producer emits the field it is
        # authoritative and must be one of the exact path-free dispositions.
        if "engine_runtime" not in run_config:
            if allow_legacy_missing:
                return None, None
            raise ValueError(
                "current non-runtime attacker manifest lacks its exact engine "
                "runtime disposition"
            )
        framework_execution = (
            "not_invoked" if normalized_attacker == "nanogcg" else None
        )
        disposition = run_config["engine_runtime"]
        accepted = [{
            "schema": "ura-engine-runtime-not-required/1",
            "framework_execution": framework_execution,
        }]
        if allow_legacy_missing:
            accepted.append({
                "status": "not_required",
                "framework_execution": framework_execution,
            })
        if disposition not in accepted:
            raise ValueError(
                "non-runtime attacker manifest has an invalid engine runtime "
                "disposition"
            )
        return None, None

    if "engine_runtime" not in run_config:
        raise ValueError("runtime-backed cell manifest lacks engine runtime identity")
    if "engine_runtime_close" not in completion_marker:
        raise ValueError("runtime-backed completion marker lacks engine runtime closing seal")
    identity = validate_engine_runtime_identity(
        run_config["engine_runtime"], expected_engine=normalized_attacker
    )
    close = validate_closed_engine_runtime(
        completion_marker["engine_runtime_close"],
        expected_engine=normalized_attacker,
    )
    if engine_runtime_identity_descriptor(close) != identity:
        raise ValueError(
            "completion marker engine runtime seal differs from the manifest identity"
        )
    return identity, close


def validate_grid_engine_runtime_binding(
    *,
    attacker: object,
    cell_identity: dict[str, Any] | None,
    cell_close: dict[str, Any] | None,
    grid_request: Mapping[str, Any],
    grid_close: object,
) -> None:
    """Bind a runtime-backed cell to the exact grid opening and closing sets."""

    selected_attackers = grid_request.get("attackers")
    if not isinstance(selected_attackers, list) or any(
        not isinstance(name, str) or not name
        for name in selected_attackers
    ):
        raise ValueError("grid lacks a valid selected-attacker inventory")
    expected_engines = {
        name.lower()
        for name in selected_attackers
        if name.lower() in RUNTIME_REQUIRED_ATTACKERS
    }
    if not expected_engines:
        if grid_request.get("engine_runtimes") is not None or grid_close is not None:
            raise ValueError(
                "runtime-free grid contains unexpected engine runtime evidence"
            )
        return

    opened = validate_engine_runtime_selection_identity_descriptor(
        grid_request.get("engine_runtimes")
    )
    opened_by_engine = {
        str(item["receipt"]["engine"]): item
        for item in opened["runtimes"]
    }
    closed = validate_engine_runtime_selection_descriptor(
        grid_close, required_status="closed_verified"
    )
    closed_by_engine = {
        str(item["receipt"]["engine"]): item
        for item in closed["runtimes"]
    }
    opened_identities = dict(opened_by_engine)
    closed_identities = {
        name: _runtime_identity_from_seal(item)
        for name, item in closed_by_engine.items()
    }
    if opened_identities != closed_identities:
        raise ValueError(
            "grid engine runtime closing selection differs from its opening selection"
        )
    if set(opened_identities) != expected_engines:
        raise ValueError(
            "grid engine runtime selection differs from its selected attackers"
        )

    if not isinstance(attacker, str) or attacker.lower() not in (
        RUNTIME_REQUIRED_ATTACKERS
    ):
        if cell_identity is not None or cell_close is not None:
            raise ValueError("runtime-free cell contains engine runtime evidence")
        return

    engine = attacker.lower()
    if cell_identity is None or cell_close is None:
        raise ValueError("runtime-backed cell lacks validated runtime evidence")
    if engine not in opened_identities:
        raise ValueError(
            f"grid engine runtime selection lacks cell engine {engine!r}"
        )
    if opened_identities[engine] != cell_identity:
        raise ValueError(
            "grid engine runtime identity differs from the completed cell identity"
        )
    if closed_by_engine[engine] != cell_close:
        raise ValueError(
            "grid engine runtime closing seal differs from the completion marker"
        )

__all__ = [
    "ENGINE_RUNTIME_SELECTION_SCHEMA",
    "LEGACY_RUNTIME_FREE_CODE_VERSION",
    "LEGACY_RUNTIME_FREE_SCHEMA_VERSION",
    "validate_cell_engine_runtime_marker",
    "validate_closed_engine_runtime",
    "validate_engine_runtime_identity",
    "validate_engine_runtime_artifact_version",
    "validate_grid_engine_runtime_binding",
]
