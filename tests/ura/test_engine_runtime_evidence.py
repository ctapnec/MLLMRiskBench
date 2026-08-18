from __future__ import annotations

import hashlib
import json

import pytest

from ura.adapters._engine_runtime import (
    ENGINE_RUNTIME_EXECUTION_SCHEMA,
    ENGINE_RUNTIME_IDENTITY_SCHEMA,
    ENGINE_RUNTIME_RECEIPT_SCHEMA,
    ENGINE_RUNTIME_REQUIREMENTS,
    ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
)
from ura.engine_runtime_evidence import (
    ENGINE_RUNTIME_SELECTION_SCHEMA,
    validate_cell_engine_runtime_marker,
    validate_engine_runtime_artifact_version,
    validate_engine_runtime_identity,
    validate_grid_engine_runtime_binding,
)


def test_artifact_version_gate_accepts_only_exact_runtime_free_legacy_pair() -> None:
    assert validate_engine_runtime_artifact_version(
        attacker="replay",
        code_version="ura-runner/2.19",
        schema_version="1.4",
        current_code_version="ura-runner/2.20",
        current_schema_version="1.5",
    ) is True
    assert validate_engine_runtime_artifact_version(
        attacker="replay",
        code_version="ura-runner/2.20",
        schema_version="1.5",
        current_code_version="ura-runner/2.20",
        current_schema_version="1.5",
    ) is False
    with pytest.raises(ValueError, match="predates.*closing seal"):
        validate_engine_runtime_artifact_version(
            attacker="pyrit",
            code_version="ura-runner/2.19",
            schema_version="1.4",
            current_code_version="ura-runner/2.20",
            current_schema_version="1.5",
        )
    with pytest.raises(ValueError, match="current runner/schema"):
        validate_engine_runtime_artifact_version(
            attacker="replay",
            code_version="ura-runner/2.19",
            schema_version="1.5",
            current_code_version="ura-runner/2.20",
            current_schema_version="1.5",
        )


def _sha256_json(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()).hexdigest()


def _identity(engine: str, *, digit: str = "1") -> dict:
    requirement = ENGINE_RUNTIME_REQUIREMENTS[engine]
    receipt = {
        "schema": ENGINE_RUNTIME_RECEIPT_SCHEMA,
        "engine": engine,
        "distribution": requirement.distribution,
        "version": requirement.version,
        "python": {
            "implementation": "cpython",
            "version": "3.12.10",
            "cache_tag": "cpython-312",
            "executable_sha256": digit * 64,
            "executable_bytes": 10,
        },
        "pyvenv_cfg_sha256": "2" * 64,
        "package_tree_sha256": "3" * 64,
        "package_files": 2,
        "package_bytes": 20,
        "inventory_sha256": "4" * 64,
        "environment_tree_sha256": digit * 64,
        "environment_files": 7,
        "environment_bytes": 70,
    }
    receipt["runtime_id"] = f"engine-runtime-{_sha256_json(receipt)[:24]}"
    return {
        "schema": ENGINE_RUNTIME_IDENTITY_SCHEMA,
        "bridge_sha256": "a" * 64,
        "receipt": receipt,
    }


def _seal(identity: dict, *, status: str = "closed_verified") -> dict:
    return {
        **identity,
        "schema": ENGINE_RUNTIME_EXECUTION_SCHEMA,
        "status": status,
    }


def _selection(identities: list[dict], *, status: str) -> dict:
    runtimes = [
        _seal(identity, status=status)
        for identity in sorted(
            identities, key=lambda item: item["receipt"]["engine"]
        )
    ]
    identity_body = {
        "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
        "runtimes": [{
            "schema": ENGINE_RUNTIME_IDENTITY_SCHEMA,
            "bridge_sha256": item["bridge_sha256"],
            "receipt": item["receipt"],
        } for item in runtimes],
    }
    body = {
        "schema": ENGINE_RUNTIME_SELECTION_SCHEMA,
        "runtimes": runtimes,
    }
    return {**body, "selection_sha256": _sha256_json(identity_body)}


def _selection_identity(identities: list[dict]) -> dict:
    body = {
        "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
        "runtimes": sorted(
            identities, key=lambda item: item["receipt"]["engine"]
        ),
    }
    return {**body, "selection_sha256": _sha256_json(body)}


def _validated_cell(identity: dict) -> tuple[dict, dict]:
    return validate_cell_engine_runtime_marker(
        attacker="pyrit",
        run_config={"attacker": "pyrit", "engine_runtime": identity},
        completion_marker={"engine_runtime_close": _seal(identity)},
    )


def test_runtime_cell_binds_status_free_identity_to_exact_closed_grid() -> None:
    identity = _identity("pyrit")
    cell_identity, cell_close = _validated_cell(identity)
    validate_grid_engine_runtime_binding(
        attacker="pyrit",
        cell_identity=cell_identity,
        cell_close=cell_close,
        grid_request={
            "attackers": ["pyrit", "replay"],
            "engine_runtimes": _selection_identity([identity]),
        },
        grid_close=_selection([identity], status="closed_verified"),
    )

    assert set(cell_identity) == {"schema", "bridge_sha256", "receipt"}
    with pytest.raises(ValueError, match="identity descriptor has invalid fields"):
        validate_engine_runtime_identity(
            {**identity, "status": "verified"}, expected_engine="pyrit"
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "lacks engine runtime closing seal"),
        ("downgraded", "closed_verified"),
        ("different_bridge", "differs from the manifest identity"),
        ("different_receipt", "differs from the manifest identity"),
        ("extra_field", "execution descriptor has invalid fields"),
        ("path_field", "execution descriptor has invalid fields"),
        ("selection_shape", "execution descriptor has invalid fields"),
    ],
)
def test_runtime_cell_rejects_missing_downgraded_or_confused_marker_seal(
    mutation: str,
    message: str,
) -> None:
    identity = _identity("pyrit")
    marker: dict = {"engine_runtime_close": _seal(identity)}
    if mutation == "missing":
        marker = {}
    elif mutation == "downgraded":
        marker["engine_runtime_close"]["status"] = "verified"
    elif mutation == "different_bridge":
        marker["engine_runtime_close"]["bridge_sha256"] = "b" * 64
    elif mutation == "different_receipt":
        marker["engine_runtime_close"] = _seal(_identity("pyrit", digit="5"))
    elif mutation == "extra_field":
        marker["engine_runtime_close"]["extra"] = True
    elif mutation == "path_field":
        marker["engine_runtime_close"]["interpreter"] = "/private/venv/bin/python"
    elif mutation == "selection_shape":
        marker["engine_runtime_close"] = _selection(
            [identity], status="closed_verified"
        )

    with pytest.raises(ValueError, match=message):
        validate_cell_engine_runtime_marker(
            attacker="pyrit",
            run_config={"attacker": "pyrit", "engine_runtime": identity},
            completion_marker=marker,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_close",
        "downgraded",
        "different_bridge",
        "different_receipt",
        "extra",
        "statusful_open",
    ],
)
def test_runtime_cell_rejects_grid_closing_selection_confusion(mutation: str) -> None:
    identity = _identity("pyrit")
    cell_identity, cell_close = _validated_cell(identity)
    opened_identities = [identity]
    closed_identities = [identity]
    close_status = "closed_verified"
    opened: object = _selection_identity(opened_identities)
    grid_close: object
    if mutation == "missing_close":
        grid_close = None
    else:
        if mutation == "downgraded":
            close_status = "verified"
        elif mutation == "different_bridge":
            changed = _identity("pyrit")
            changed["bridge_sha256"] = "b" * 64
            closed_identities = [changed]
        elif mutation == "different_receipt":
            closed_identities = [_identity("pyrit", digit="5")]
        elif mutation == "extra":
            extra = _identity("deepteam", digit="6")
            opened_identities.append(extra)
            closed_identities.append(extra)
        elif mutation == "statusful_open":
            opened = _selection(opened_identities, status="verified")
        if mutation == "extra":
            opened = _selection_identity(opened_identities)
        grid_close = _selection(closed_identities, status=close_status)

    with pytest.raises(ValueError, match="engine runtime"):
        validate_grid_engine_runtime_binding(
            attacker="pyrit",
            cell_identity=cell_identity,
            cell_close=cell_close,
            grid_request={
                "attackers": ["pyrit"],
                "engine_runtimes": opened,
            },
            grid_close=grid_close,
        )


def test_replay_cell_validates_other_grid_runtime_seals() -> None:
    identity, close = validate_cell_engine_runtime_marker(
        attacker="replay",
        run_config={"attacker": "replay"},
        completion_marker={"engine_runtime_close": None},
    )
    assert identity is None
    assert close is None
    validate_grid_engine_runtime_binding(
        attacker="replay",
        cell_identity=None,
        cell_close=None,
        grid_request={
            "attackers": ["pyrit", "replay"],
            "engine_runtimes": _selection_identity([_identity("pyrit")]),
        },
        grid_close=_selection([_identity("pyrit")], status="closed_verified"),
    )
    with pytest.raises(ValueError, match="closing selection differs"):
        validate_grid_engine_runtime_binding(
            attacker="replay",
            cell_identity=None,
            cell_close=None,
            grid_request={
                "attackers": ["pyrit", "replay"],
                "engine_runtimes": _selection_identity([_identity("pyrit")]),
            },
            grid_close=_selection(
                [_identity("pyrit", digit="5")], status="closed_verified"
            ),
        )

    with pytest.raises(ValueError, match="non-runtime attacker"):
        validate_cell_engine_runtime_marker(
            attacker="replay",
            run_config={"attacker": "replay"},
            completion_marker={"engine_runtime_close": _seal(_identity("pyrit"))},
        )

    with pytest.raises(ValueError, match="current non-runtime attacker"):
        validate_cell_engine_runtime_marker(
            attacker="replay",
            run_config={"attacker": "replay"},
            completion_marker={},
            allow_legacy_missing=False,
        )


def test_runtime_free_grid_rejects_unexpected_runtime_selection() -> None:
    validate_grid_engine_runtime_binding(
        attacker="replay",
        cell_identity=None,
        cell_close=None,
        grid_request={"attackers": ["replay"], "engine_runtimes": None},
        grid_close=None,
    )

    with pytest.raises(ValueError, match="runtime-free grid contains unexpected"):
        validate_grid_engine_runtime_binding(
            attacker="replay",
            cell_identity=None,
            cell_close=None,
            grid_request={
                "attackers": ["replay"],
                "engine_runtimes": {"unexpected": "accepted"},
            },
            grid_close={"unexpected": "accepted"},
        )


@pytest.mark.parametrize(
    "disposition",
    [
        {"schema": "invalid"},
        _identity("pyrit"),
        {
            "schema": "ura-engine-runtime-not-required/1",
            "framework_execution": "not_invoked",
        },
        {
            "status": "not_required",
            "framework_execution": None,
            "extra": True,
        },
    ],
)
def test_replay_rejects_explicit_malformed_runtime_disposition(
    disposition: dict,
) -> None:
    with pytest.raises(ValueError, match="invalid engine runtime disposition"):
        validate_cell_engine_runtime_marker(
            attacker="replay",
            run_config={"attacker": "replay", "engine_runtime": disposition},
            completion_marker={"engine_runtime_close": None},
        )


@pytest.mark.parametrize(
    "run_config",
    [
        {"attacker": "replay"},
        {
            "attacker": "replay",
            "engine_runtime": {
                "schema": "ura-engine-runtime-not-required/1",
                "framework_execution": None,
            },
        },
        {
            "attacker": "replay",
            "engine_runtime": {
                "status": "not_required",
                "framework_execution": None,
            },
        },
    ],
)
def test_replay_accepts_pre_feature_and_exact_non_runtime_dispositions(
    run_config: dict,
) -> None:
    assert validate_cell_engine_runtime_marker(
        attacker="replay",
        run_config=run_config,
        completion_marker={},
    ) == (None, None)


def test_current_replay_rejects_legacy_explicit_non_runtime_disposition() -> None:
    with pytest.raises(ValueError, match="invalid engine runtime disposition"):
        validate_cell_engine_runtime_marker(
            attacker="replay",
            run_config={
                "attacker": "replay",
                "engine_runtime": {
                    "status": "not_required",
                    "framework_execution": None,
                },
            },
            completion_marker={},
            allow_legacy_missing=False,
        )
