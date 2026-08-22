from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from types import ModuleType

import pytest

from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    CONTROLLERS,
    DERIVED_BINDINGS,
    render_controller_set,
)
from ura.request_envelope import (
    build_request_envelope,
    request_envelope_descriptor,
    write_request_envelope,
)


def _template_tokens() -> set[str]:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    return {
        match
        for controller in CONTROLLERS
        for match in token.findall(
            (root / controller.template).read_text(encoding="utf-8")
        )
    } - DERIVED_BINDINGS


def _bindings(path: Path) -> Path:
    values = {name: f"value-{name.lower()}" for name in _template_tokens()}
    values["EXPECTED_COMMIT"] = "1" * 40
    for name in tuple(values):
        if name.endswith("SHA256"):
            values[name] = "2" * 64
        elif name == "PHASE3_DOWNLOADED_BYTES":
            values[name] = "0"
        elif name.endswith("_BYTES"):
            values[name] = "1"
        elif name.endswith("_TAG"):
            values[name] = "20260822T120000Z"
        elif name == "CONTROLLER_INSTALL_ROOT":
            values[name] = "/bound/.ura-controller-active"
        elif name.endswith(("_PATH", "_ROOT")):
            values[name] = f"/bound/{name.lower()}"
    path.write_text(
        json.dumps({"schema": BINDINGS_SCHEMA, "values": values}),
        encoding="utf-8",
    )
    return path


@pytest.fixture(scope="module")
def phase7(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    root = tmp_path_factory.mktemp("phase7-lifecycle")
    output = root / "rendered"
    render_controller_set(_bindings(root / "bindings.json"), output)
    path = output / "phase7_analysis.py"
    spec = importlib.util.spec_from_file_location("phase7_lifecycle_test_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _kinds(
    phase7: ModuleType,
    *,
    grids: list[str],
    envelopes: int,
    eligibility: int,
    errors: int,
) -> dict[str, int]:
    return phase7.lifecycle_artifact_kinds(
        grid_statuses=grids,
        measured_request_envelopes=envelopes,
        eligibility_artifacts=eligibility,
        error_artifacts=errors,
    )


def test_lifecycle_status_requires_exact_request_artifact_kinds(
    phase7: ModuleType,
) -> None:
    cases = (
        (
            "measured_complete",
            "complete",
            _kinds(
                phase7,
                grids=["complete"],
                envelopes=1,
                eligibility=1,
                errors=0,
            ),
            "complete_runner_grid",
        ),
        (
            "failed",
            "partial",
            _kinds(
                phase7,
                grids=["partial"],
                envelopes=1,
                eligibility=1,
                errors=1,
            ),
            "partial_runner_grid",
        ),
        (
            "failed",
            "failed",
            _kinds(
                phase7,
                grids=[],
                envelopes=1,
                eligibility=0,
                errors=1,
            ),
            "failed_after_runner_request",
        ),
        (
            "failed",
            "failed",
            _kinds(
                phase7,
                grids=["running"],
                envelopes=0,
                eligibility=0,
                errors=1,
            ),
            "failed_after_runner_request",
        ),
        (
            "failed",
            "failed",
            _kinds(
                phase7,
                grids=[],
                envelopes=0,
                eligibility=0,
                errors=1,
            ),
            "pre_runner_failure_no_request_artifact",
        ),
        (
            "failed",
            "failed",
            _kinds(
                phase7,
                grids=[],
                envelopes=0,
                eligibility=1,
                errors=0,
            ),
            "pre_runner_failure_no_request_artifact",
        ),
    )
    for terminal, lifecycle, kinds, expected in cases:
        assert (
            phase7.lifecycle_authorization_status(
                terminal_state=terminal,
                lifecycle_state=lifecycle,
                artifact_kinds=kinds,
            )
            == expected
        )

    partial_without_envelope = _kinds(
        phase7, grids=["partial"], envelopes=0, eligibility=1, errors=1
    )
    with pytest.raises(phase7.Phase7Error, match="exact artifact kinds"):
        phase7.lifecycle_authorization_status(
            terminal_state="failed",
            lifecycle_state="partial",
            artifact_kinds=partial_without_envelope,
        )
    with pytest.raises(phase7.Phase7Error, match="more than one grid request"):
        _kinds(
            phase7,
            grids=["running", "partial"],
            envelopes=1,
            eligibility=1,
            errors=1,
        )
    unknown_kind = _kinds(
        phase7, grids=[], envelopes=0, eligibility=0, errors=1
    )
    unknown_kind["generic_artifact"] = 1
    with pytest.raises(phase7.Phase7Error, match="artifact kinds are not exact"):
        phase7.lifecycle_authorization_status(
            terminal_state="failed",
            lifecycle_state="failed",
            artifact_kinds=unknown_kind,
        )


def _source_bindings() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    harness = {
        "algorithm": "sha256_relative_path_size_file_digest_v1",
        "sha256": "a" * 64,
        "file_count": 2,
        "bytes": 100,
    }
    driver = {
        "module": "run_matrix.py",
        "sha256": "b" * 64,
        "file_count": 1,
    }
    revision_id = "project-revision-" + "c" * 24
    project = {
        "mode": "verified",
        "revision_id": revision_id,
        "file": f"{revision_id}.project-revision.json",
        "sha256": "d" * 64,
        "bytes": 100,
        "expected_commit": "e" * 40,
        "observed_commit": "e" * 40,
        "head_tree": "f" * 40,
        "harness_source_sha256": harness["sha256"],
        "driver_source_sha256": driver["sha256"],
    }
    return project, harness, driver


def _request(phase7: ModuleType, purpose: str) -> dict[str, object]:
    return {
        "execution_purpose": purpose,
        "requested_target_keys": ["vllm:model-a"],
        "logical_source_arms": ["arm-a"],
        "selected_attackers": ["replay"],
        "judges": ["rules"],
        "judge_model": None,
        "seeds": [0],
        "sample_seed": 0,
        "limit": 0,
        "max_queries": 1,
        "max_turns": 1,
        "defense": "none",
        "defense_guard": "rules",
        "group_keys": list(phase7.GROUP_KEYS),
        "quantization": "",
        "dtype": "auto",
        "dry_run": False,
        "approximate_common_metrics": False,
        "hosted_judge_data_transfer_acknowledged": False,
        "call_caps": {
            "target": 1,
            "judge": None,
            "http_attempts": None,
            "deadline_seconds": 60,
        },
    }


def _artifact_descriptor(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _request_fixture(
    phase7: ModuleType, tmp_path: Path
) -> tuple[
    dict[str, object],
    dict[str, object],
    Path,
    dict[str, object],
    dict[str, object],
]:
    project, harness, driver = _source_bindings()
    gate5 = build_request_envelope(
        request=_request(phase7, "preflight_only"),
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )
    measured = build_request_envelope(
        request=_request(phase7, "measured_run"),
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )
    gate5_path = write_request_envelope(tmp_path / "gate5", gate5)
    measured_path = write_request_envelope(tmp_path / "measured", measured)
    spec = {
        "lane_id": "lane-a",
        "target": {"spec": "vllm:model-a"},
        "expected_corpora": ["arm-a"],
        "expected_attacker": "replay",
        "expected_judges": ["rules"],
        "approximate_common_metrics": False,
        "defense": "none",
        "defense_guard": "rules",
        "approved_caps": {
            "target_calls": 1,
            "model_judge_calls": 0,
            "http_attempts": 0,
            "deadline_seconds": 60,
        },
        "gate5": {"final_request_envelope": _artifact_descriptor(gate5_path)},
    }
    return project, spec, measured_path, measured, request_envelope_descriptor(
        measured_path, measured
    )


def test_measured_envelope_and_grid_requests_are_semantically_bound(
    phase7: ModuleType, tmp_path: Path
) -> None:
    project, spec, measured_path, measured, envelope_descriptor = _request_fixture(
        phase7, tmp_path
    )
    assert phase7.validate_measured_request_envelope_artifact(
        measured_path,
        lane="lane-a",
        spec=spec,
        expected_project_binding=project,
    ) == envelope_descriptor

    source_sha = "1" * 64
    source_config_sha = "2" * 64
    grid_request = {
        "execution_purpose": "measured_run",
        "project_revision": project,
        "request_envelope": envelope_descriptor,
        "models": ["vllm:model-a"],
        "corpora": ["arm-a"],
        "source_conformance_artifact": {"sha256": source_sha},
        "source_config_artifact": {"sha256": source_config_sha},
        "attackers": ["replay"],
        "judges": ["rules"],
        "judge_model": None,
        "hosted_judge_data_transfer_acknowledged": False,
        "seeds": [0],
        "sample_seed": 0,
        "limit": 0,
        "group_keys": list(phase7.GROUP_KEYS),
        "defense": "none",
        "defense_guard": "rules",
        "quantization": "",
        "dtype": "auto",
        "dry_run": False,
        "approximate_common_metrics": False,
        "attestation_probe": False,
        "global_call_budget": {
            "max_target_calls": 1,
            "max_judge_calls": None,
            "max_http_attempts": None,
            "call_start_deadline_seconds_from_first_invocation": 60,
            "accounting_semantics": "durable_pre_call_logical_reservation_v1",
        },
        "live_attestation": {
            "mode": "measured",
            "artifacts": [{"file": "live.json", "sha256": "3" * 64, "bytes": 1}],
        },
    }
    assert phase7.validate_measured_grid_request(
        grid_request,
        lane="lane-a",
        spec=spec,
        model_selector="vllm:model-a",
        expected_project_binding=project,
        expected_source_sha=source_sha,
        expected_source_config_sha=source_config_sha,
    ) == envelope_descriptor

    for field, bad_value in (
        ("dry_run", True),
        ("models", ["vllm:model-b"]),
        ("corpora", ["arm-b"]),
        ("source_conformance_artifact", {"sha256": "4" * 64}),
    ):
        mutated = copy.deepcopy(grid_request)
        mutated[field] = bad_value
        with pytest.raises(phase7.Phase7Error, match="sealed measured lane"):
            phase7.validate_measured_grid_request(
                mutated,
                lane="lane-a",
                spec=spec,
                model_selector="vllm:model-a",
                expected_project_binding=project,
                expected_source_sha=source_sha,
                expected_source_config_sha=source_config_sha,
            )

    mismatched_request = _request(phase7, "measured_run")
    mismatched_request["selected_attackers"] = ["other-attacker"]
    _project, harness, driver = _source_bindings()
    mismatched = build_request_envelope(
        request=mismatched_request,
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )
    mismatch_path = write_request_envelope(tmp_path / "mismatch", mismatched)
    with pytest.raises(phase7.Phase7Error, match="exact Gate 5 request"):
        phase7.validate_measured_request_envelope_artifact(
            mismatch_path,
            lane="lane-a",
            spec=spec,
            expected_project_binding=project,
        )

    assert measured["request"]["execution_purpose"] == "measured_run"
