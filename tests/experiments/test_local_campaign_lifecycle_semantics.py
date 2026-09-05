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
    pre_runner: int = 0,
) -> dict[str, int]:
    return phase7.lifecycle_artifact_kinds(
        grid_statuses=grids,
        measured_request_envelopes=envelopes,
        eligibility_artifacts=eligibility,
        error_artifacts=errors,
        pre_runner_failure_artifacts=pre_runner,
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
            "failed_after_runner_request",
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
                errors=0,
                pre_runner=1,
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
    with pytest.raises(phase7.Phase7Error, match="lacks one typed"):
        phase7.lifecycle_authorization_status(
            terminal_state="failed",
            lifecycle_state="failed",
            artifact_kinds=_kinds(
                phase7,
                grids=[],
                envelopes=0,
                eligibility=0,
                errors=0,
            ),
        )
    with pytest.raises(phase7.Phase7Error, match="coexists"):
        phase7.lifecycle_authorization_status(
            terminal_state="failed",
            lifecycle_state="failed",
            artifact_kinds=_kinds(
                phase7,
                grids=[],
                envelopes=1,
                eligibility=0,
                errors=1,
                pre_runner=1,
            ),
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
        "limit": 100,
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
        "lane_id": "local-qwen3-vl-text-primary-100",
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
        "base_argv": [
            "--local-config-sha256",
            "4" * 64,
            "--max-queries",
            "1",
            "--max-turns",
            "1",
        ],
        "gate5": {"final_request_envelope": _artifact_descriptor(gate5_path)},
    }
    return project, spec, measured_path, measured, request_envelope_descriptor(
        measured_path, measured
    )


def _grid_request_fixture(
    phase7: ModuleType,
    *,
    project: dict[str, object],
    envelope_descriptor: dict[str, object],
    source_sha: str,
    source_config_sha: str,
    approximate: bool = False,
) -> dict[str, object]:
    return {
        "execution_purpose": "measured_run",
        "project_revision": project,
        "request_envelope": envelope_descriptor,
        "models": ["vllm:model-a"],
        "corpora": ["arm-a"],
        "source_conformance_artifact": {"sha256": source_sha},
        "source_config_artifact": {"sha256": source_config_sha},
        "local_config_artifact": {"sha256": "4" * 64},
        "attackers": ["replay"],
        "judges": ["rules", "guardrail"] if approximate else ["rules"],
        "judge_model": None,
        "guardrail_model": (
            phase7.EXPECTED_GUARDRAIL_MODEL if approximate else None
        ),
        "guardrail_revision": (
            phase7.EXPECTED_GUARDRAIL_REVISION if approximate else None
        ),
        "guardrail_device": (
            phase7.EXPECTED_GUARDRAIL_DEVICE if approximate else None
        ),
        "hosted_judge_data_transfer_acknowledged": False,
        "seeds": [0],
        "sample_seed": 0,
        "limit": 100,
        "max_queries": 1,
        "max_turns": 1,
        "group_keys": list(phase7.GROUP_KEYS),
        "defense": "none",
        "defense_guard": "rules",
        "quantization": "",
        "dtype": "auto",
        "dry_run": False,
        "approximate_common_metrics": approximate,
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


def test_measured_envelope_and_grid_requests_are_semantically_bound(
    phase7: ModuleType, tmp_path: Path
) -> None:
    project, spec, measured_path, measured, envelope_descriptor = _request_fixture(
        phase7, tmp_path
    )
    assert phase7.validate_measured_request_envelope_artifact(
        measured_path,
        lane="local-qwen3-vl-text-primary-100",
        spec=spec,
        expected_project_binding=project,
    ) == envelope_descriptor

    source_sha = "1" * 64
    source_config_sha = "2" * 64
    grid_request = _grid_request_fixture(
        phase7,
        project=project,
        envelope_descriptor=envelope_descriptor,
        source_sha=source_sha,
        source_config_sha=source_config_sha,
    )
    assert phase7.validate_measured_grid_request(
        grid_request,
        lane="local-qwen3-vl-text-primary-100",
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
        ("limit", 0),
        ("sample_seed", 1),
        ("sampling_policy", "seeded_pseudorandom_whole_cluster_prefix_v1"),
        ("source_conformance_artifact", {"sha256": "4" * 64}),
    ):
        mutated = copy.deepcopy(grid_request)
        mutated[field] = bad_value
        with pytest.raises(phase7.Phase7Error, match="sealed measured lane"):
            phase7.validate_measured_grid_request(
                mutated,
                lane="local-qwen3-vl-text-primary-100",
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
            lane="local-qwen3-vl-text-primary-100",
            spec=spec,
            expected_project_binding=project,
        )

    assert measured["request"]["execution_purpose"] == "measured_run"


@pytest.mark.parametrize("rich", [False, True])
def test_measured_envelope_accepts_exact_retained_descriptor_shapes(
    phase7: ModuleType, tmp_path: Path, rich: bool
) -> None:
    project, spec, measured_path, _, expected = _request_fixture(phase7, tmp_path)
    descriptor = spec["gate5"]["final_request_envelope"]
    if rich:
        gate5_path = Path(descriptor["path"])
        value = json.loads(gate5_path.read_text(encoding="utf-8"))
        descriptor.update(request_envelope_descriptor(gate5_path, value))
    assert phase7.validate_measured_request_envelope_artifact(
        measured_path, lane="rjudge-qwen3-vl", spec=spec,
        expected_project_binding=project,
    ) == expected
    if rich:
        descriptor["envelope_id"] = "request-envelope-" + "0" * 24
        with pytest.raises(phase7.Phase7Error, match="validation failed"):
            phase7.validate_measured_request_envelope_artifact(
                measured_path, lane="rjudge-qwen3-vl", spec=spec,
                expected_project_binding=project,
            )


def test_measured_grid_binds_runner_resolved_vllm_revision(
    phase7: ModuleType, tmp_path: Path
) -> None:
    project, spec, _, _, envelope = _request_fixture(phase7, tmp_path)
    revision = "a" * 40
    spec["target"] = {"spec": "vllm:model-a", "repo_id": "model-a", "revision": revision}
    request = _grid_request_fixture(
        phase7, project=project, envelope_descriptor=envelope,
        source_sha="1" * 64, source_config_sha="2" * 64,
    )
    request["models"] = [f"vllm:model-a@{revision}"]
    kwargs = dict(
        lane="rjudge-qwen3-vl", spec=spec, model_selector="vllm:model-a",
        expected_project_binding=project, expected_source_sha="1" * 64,
        expected_source_config_sha="2" * 64,
    )
    assert phase7.validate_measured_grid_request(request, **kwargs) == envelope
    assert phase7._measured_model_selector(request["models"][0], spec) == request["models"][0]
    for wrong in ("vllm:model-a", "vllm:model-a@" + "b" * 40,
                  "vllm:model-b@" + revision):
        request["models"] = [wrong]
        with pytest.raises(phase7.Phase7Error, match="sealed measured lane"):
            phase7.validate_measured_grid_request(request, **kwargs)
    with pytest.raises(phase7.Phase7Error, match="selector and revision differ"):
        phase7._measured_model_selector("vllm:model-a@" + "b" * 40, spec)


def test_measured_grid_binds_runner_resolved_ollama_digest(
    phase7: ModuleType, tmp_path: Path
) -> None:
    project, spec, _, _, envelope = _request_fixture(phase7, tmp_path)
    selector = "ollama:mollysama/rwkv-7-g1d:0.4b"
    digest = "78e699bd71f0cef7ed8fb38a469088310af0ab07d678661980c6b8c7f130a7f8"
    spec["target"] = {"spec": selector, "repo_id": None, "revision": None,
                      "digest": digest}
    request = _grid_request_fixture(
        phase7, project=project, envelope_descriptor=envelope,
        source_sha="1" * 64, source_config_sha="2" * 64,
    )
    request["models"] = [f"{selector}@sha256:{digest}"]
    kwargs = dict(
        lane="rjudge-ollama-rwkv-g1d-0p4b", spec=spec, model_selector=selector,
        expected_project_binding=project, expected_source_sha="1" * 64,
        expected_source_config_sha="2" * 64,
    )
    assert phase7.validate_measured_grid_request(request, **kwargs) == envelope
    assert phase7._measured_model_selector(request["models"][0], spec) == request["models"][0]
    for wrong in (selector, selector + "@sha256:" + "b" * 64,
                  "ollama:another-model@sha256:" + digest):
        request["models"] = [wrong]
        with pytest.raises(phase7.Phase7Error, match="sealed measured lane"):
            phase7.validate_measured_grid_request(request, **kwargs)
        if "@" in wrong:
            with pytest.raises(phase7.Phase7Error, match="selector and digest differ"):
                phase7._measured_model_selector(wrong, spec)
    spec["target"]["digest"] = "invalid"
    with pytest.raises(phase7.Phase7Error, match="digest is invalid"):
        phase7._measured_model_selector(selector, spec)


def test_approximate_grid_request_binds_the_exact_selected_guardrail(
    phase7: ModuleType, tmp_path: Path
) -> None:
    project, spec, _measured_path, _measured, envelope_descriptor = _request_fixture(
        phase7, tmp_path
    )
    source_sha = "1" * 64
    source_config_sha = "2" * 64
    spec["expected_judges"] = ["rules", "guardrail"]
    spec["approximate_common_metrics"] = True
    spec["base_argv"].extend(
        [
            "--guardrail-model",
            phase7.EXPECTED_GUARDRAIL_MODEL,
            "--guardrail-revision",
            phase7.EXPECTED_GUARDRAIL_REVISION,
            "--guardrail-device",
            phase7.EXPECTED_GUARDRAIL_DEVICE,
        ]
    )
    grid_request = _grid_request_fixture(
        phase7,
        project=project,
        envelope_descriptor=envelope_descriptor,
        source_sha=source_sha,
        source_config_sha=source_config_sha,
        approximate=True,
    )
    assert phase7.validate_measured_grid_request(
        grid_request,
        lane="local-qwen3-vl-text-primary-100",
        spec=spec,
        model_selector="vllm:model-a",
        expected_project_binding=project,
        expected_source_sha=source_sha,
        expected_source_config_sha=source_config_sha,
    ) == envelope_descriptor

    wrong_request = copy.deepcopy(grid_request)
    wrong_request["guardrail_model"] = "example/other-judge"
    with pytest.raises(phase7.Phase7Error, match="sealed measured lane"):
        phase7.validate_measured_grid_request(
            wrong_request,
            lane="local-qwen3-vl-text-primary-100",
            spec=spec,
            model_selector="vllm:model-a",
            expected_project_binding=project,
            expected_source_sha=source_sha,
            expected_source_config_sha=source_config_sha,
        )

    self_referential_spec = copy.deepcopy(spec)
    model_index = self_referential_spec["base_argv"].index("--guardrail-model") + 1
    self_referential_spec["base_argv"][model_index] = "example/other-judge"
    with pytest.raises(phase7.Phase7Error, match="selected common-metric guardrail"):
        phase7.validate_measured_grid_request(
            wrong_request,
            lane="local-qwen3-vl-text-primary-100",
            spec=self_referential_spec,
            model_selector="vllm:model-a",
            expected_project_binding=project,
            expected_source_sha=source_sha,
            expected_source_config_sha=source_config_sha,
        )

    non_guard_spec = copy.deepcopy(spec)
    non_guard_spec["expected_judges"] = ["rules"]
    non_guard_spec["approximate_common_metrics"] = False
    for option in (
        "--guardrail-model",
        "--guardrail-revision",
        "--guardrail-device",
    ):
        option_index = non_guard_spec["base_argv"].index(option)
        del non_guard_spec["base_argv"][option_index : option_index + 2]
    unexpected_guard = copy.deepcopy(grid_request)
    unexpected_guard["judges"] = ["rules"]
    unexpected_guard["approximate_common_metrics"] = False
    with pytest.raises(phase7.Phase7Error, match="sealed measured lane"):
        phase7.validate_measured_grid_request(
            unexpected_guard,
            lane="local-qwen3-vl-text-primary-100",
            spec=non_guard_spec,
            model_selector="vllm:model-a",
            expected_project_binding=project,
            expected_source_sha=source_sha,
            expected_source_config_sha=source_config_sha,
        )


def _analysis_prerequisite_runner(
    phase7: ModuleType,
    *,
    measured: tuple[str, ...] = (),
) -> dict[str, object]:
    lanes = tuple(
        dict.fromkeys(
            (*phase7.REPLAY_ANALYSIS_LANES, phase7.ADAPTIVITY_RIGHT_LANE)
        )
    )
    measured_set = set(measured)
    states = {
        lane: "measured_complete" if lane in measured_set else "failed"
        for lane in lanes
    }
    lifecycle = {
        lane: "complete" if state == "measured_complete" else "failed"
        for lane, state in states.items()
    }
    authorizations: dict[str, dict[str, object]] = {}
    for index, lane in enumerate(lanes, 1):
        complete = states[lane] == "measured_complete"
        authorizations[lane] = {
            "lifecycle_registry_status": (
                "complete_runner_grid"
                if complete
                else "pre_runner_failure_no_request_artifact"
            ),
            "controller_failure": (
                None
                if complete
                else {
                    "path": f"/phase6/failure-{lane}.json",
                    "sha256": f"{index:064x}",
                    "bytes": index,
                }
            ),
        }
    return {
        "terminal_states": states,
        "lifecycle_states": lifecycle,
        "lifecycle_authorizations": authorizations,
        "conditional_na_lanes": [],
    }


def _analysis_controller(
    phase7: ModuleType,
    tmp_path: Path,
    runner: dict[str, object],
) -> tuple[object, list[tuple[object, ...]], list[tuple[object, ...]]]:
    controller = object.__new__(phase7.AnalysisController)
    runner.setdefault(
        "model_selectors", {"llava_base": "vllm:fixture/llava-base"}
    )
    failure = {
        "path": "/phase6/fixture-failure.json",
        "sha256": "f" * 64,
        "bytes": 1,
    }
    rr_states = {lane: "failed" for lane in phase7.RR_CURRENT_LANES}
    controller.inputs = {
        "runner": runner,
        "canonical_recoveries": {
            "attempts": [],
            "latest": {
                phase7.LLAVA_BASE_IMAGE_LANE: {
                    "state": "failed",
                    "evidence": {"failure": copy.deepcopy(failure)},
                }
            },
        },
        "seven_output_policy_amendment": {
            "lane_order": [],
            "terminal_states": rr_states,
            "metric_roots": {},
            "lifecycle": {
                lane: {
                    "state": "failed",
                    "evidence": {"failure": copy.deepcopy(failure)},
                }
                for lane in phase7.RR_CURRENT_LANES
            },
            "rr_model_selector": "vllm:fixture/llava-rr",
        },
        "followon": {"lane_order": [], "lifecycle": {}},
    }
    controller.analysis = tmp_path / "analysis"
    subprocesses: list[tuple[object, ...]] = []
    statuses: list[tuple[object, ...]] = []
    controller.run = lambda *args, **kwargs: subprocesses.append((args, kwargs))
    controller.status = lambda *args, **kwargs: statuses.append((args, kwargs))
    return controller, subprocesses, statuses


def test_phase7_accepts_only_exact_suite_all_abstained_proxy_conditions(
    phase7: ModuleType,
    tmp_path: Path,
) -> None:
    key = (
        "vllm:fixture/model",
        phase7.PROMPT_PROXY_ARM,
        "purplellama",
        phase7.PROMPT_PROXY_METRIC,
    )
    expected = {
        key: {
            "lane_id": "bridge-purplellama",
            "model_spec": key[0],
            "corpus_arm": key[1],
            "attacker": key[2],
            "required_metric": key[3],
        }
    }
    stratum = {
        "model_spec": key[0],
        "corpus_arm": key[1],
        "attacker": key[2],
        "source_metric_family": key[3],
        "common_metrics_eligible": False,
        "execution_mode": "static_or_exact_replay",
        "expected_behavior": "safe_answer",
        "measurement_families": [
            "approximate_benign_refusal_rate",
            "classification_quality",
        ],
        "n_completed_records": 2,
        "n_source_clusters": 2,
        "label_counts": {"not_applicable": 2},
        "approximate_proxy_label_counts": {},
        "n_approximate_proxy_abstained": 2,
        "n_approximate_strongreject_graded": 0,
        "descriptive_common_endpoint": {
            "endpoint": "approximate_over_refusal_rate",
            "value": None,
            "reason": "no_decided_judgments",
            "decision_support": {
                "judgments_completed": 2,
                "judgments_evaluable": 2,
                "judgments_decided": 0,
                "judgments_abstained": 2,
                "decision_coverage": 0.0,
            },
            "metric_authority": "supplementary_non_authoritative",
        },
    }
    suite = {"runner": {"strata": [stratum]}}

    assert phase7.all_abstained_proxy_conditions(suite, expected) == {key}

    mutations = (
        (
            "reason",
            lambda row: row["descriptive_common_endpoint"].__setitem__(
                "reason", "generic_failure"
            ),
        ),
        (
            "coverage",
            lambda row: row["descriptive_common_endpoint"][
                "decision_support"
            ].__setitem__("decision_coverage", 1.0),
        ),
        (
            "abstentions",
            lambda row: row.__setitem__("n_approximate_proxy_abstained", 1),
        ),
        (
            "metric",
            lambda row: row.__setitem__("source_metric_family", "detached_metric"),
        ),
    )
    for _label, mutate in mutations:
        changed = copy.deepcopy(suite)
        mutate(changed["runner"]["strata"][0])
        assert phase7.all_abstained_proxy_conditions(changed, expected) == set()

    runner = {
        "metric_lane_order": ["bridge-purplellama"],
        "classification_lanes": [],
        "cascade_expected_lanes": ["bridge-purplellama"],
        "proxy_expected_conditions": list(expected.values()),
        "guardrail_selector": {
            "model": phase7.EXPECTED_GUARDRAIL_MODEL,
            "revision": phase7.EXPECTED_GUARDRAIL_REVISION,
            "device": phase7.EXPECTED_GUARDRAIL_DEVICE,
        },
        "terminal_states": {"bridge-purplellama": "measured_complete"},
        "lifecycle_states": {"bridge-purplellama": "complete"},
        "lifecycle_authorizations": {"bridge-purplellama": {}},
    }
    controller, _subprocesses, _statuses = _analysis_controller(
        phase7, tmp_path, runner
    )
    controller.inputs.update(
        {
            "gate5": {"conditional_na_lanes": []},
            "native_outcomes": {"states": {}},
        }
    )
    level2 = {
        "common": {
            "estimates": [
                {
                    "ordered_judges": ["rules", "guardrail"],
                    "corpus_arm": "ordinary_common_arm",
                    "metric": "ordinary_common_metric",
                }
            ]
        }
    }
    malformed_suite = copy.deepcopy(suite)
    malformed_suite["runner"]["strata"][0]["descriptive_common_endpoint"]["reason"] = (
        "generic_failure"
    )
    malformed_suite["source_native_presence"] = {}
    with pytest.raises(
        phase7.Phase7Error,
        match="estimated/all-abstained proxy conditions differ",
    ):
        controller.build_boundaries(
            suite=malformed_suite,
            level2=level2,
            transfer={"schema_version": "2.1"},
            llava_pairs={},
            adaptivity_pairs={},
        )

    suite["source_native_presence"] = {}
    boundary = controller.build_boundaries(
        suite=suite,
        level2=level2,
        transfer={"schema_version": "2.1"},
        llava_pairs={},
        adaptivity_pairs={},
    )
    assert boundary["approximate_common_metrics"] == {
        "supplementary_non_authoritative": True,
        "expected_from_ineligible_opted_in_strata": True,
        "expected_conditions": list(expected.values()),
        "estimated_conditions": [],
        "all_abstained_conditions": [
            {
                "condition": next(iter(expected.values())),
                "estimate_rows": 0,
                "completed_records": 2,
                "typed_abstentions": 2,
            }
        ],
        "estimate_rows": 0,
        "selected_judges": [],
        "judge_models": [],
        "selected_guardrail": runner["guardrail_selector"],
        "queried_rows_bind_selected_guardrail": True,
    }
    assert boundary["schema"] == "ura-phase7-analysis-boundaries/2"


def test_phase7_persists_disjoint_mixed_proxy_condition_partitions(
    phase7: ModuleType,
    tmp_path: Path,
) -> None:
    estimated_condition = {
        "lane_id": "bridge-purplellama",
        "model_spec": "vllm:fixture/model",
        "corpus_arm": phase7.PROMPT_PROXY_ARM,
        "attacker": "purplellama",
        "required_metric": phase7.PROMPT_PROXY_METRIC,
    }
    all_abstained_condition = {
        **estimated_condition,
        "corpus_arm": "fixture_second_benign_proxy",
        "required_metric": "fixture_second_benign_judge_question",
    }

    def condition_key(row: dict[str, str]) -> tuple[str, str, str, str]:
        return (
            row["model_spec"],
            row["corpus_arm"],
            row["attacker"],
            row["required_metric"],
        )

    expected_conditions = sorted(
        [estimated_condition, all_abstained_condition], key=condition_key
    )
    runner = {
        "metric_lane_order": ["bridge-purplellama"],
        "classification_lanes": [],
        "cascade_expected_lanes": ["bridge-purplellama"],
        "proxy_expected_conditions": expected_conditions,
        "guardrail_selector": {
            "model": phase7.EXPECTED_GUARDRAIL_MODEL,
            "revision": phase7.EXPECTED_GUARDRAIL_REVISION,
            "device": phase7.EXPECTED_GUARDRAIL_DEVICE,
        },
        "terminal_states": {"bridge-purplellama": "measured_complete"},
        "lifecycle_states": {"bridge-purplellama": "complete"},
        "lifecycle_authorizations": {"bridge-purplellama": {}},
    }
    controller, _subprocesses, _statuses = _analysis_controller(
        phase7, tmp_path, runner
    )
    controller.inputs.update(
        {
            "gate5": {"conditional_na_lanes": []},
            "native_outcomes": {"states": {}},
        }
    )
    suite = {
        "runner": {
            "strata": [
                {
                    "model_spec": estimated_condition["model_spec"],
                    "corpus_arm": estimated_condition["corpus_arm"],
                    "attacker": estimated_condition["attacker"],
                    "source_metric_family": estimated_condition["required_metric"],
                    "n_completed_records": 1,
                    "n_approximate_proxy_abstained": 0,
                },
                {
                    "model_spec": all_abstained_condition["model_spec"],
                    "corpus_arm": all_abstained_condition["corpus_arm"],
                    "attacker": all_abstained_condition["attacker"],
                    "source_metric_family": all_abstained_condition["required_metric"],
                    "common_metrics_eligible": False,
                    "execution_mode": "static_or_exact_replay",
                    "expected_behavior": "safe_answer",
                    "measurement_families": ["approximate_benign_refusal_rate"],
                    "n_completed_records": 2,
                    "n_source_clusters": 2,
                    "label_counts": {"not_applicable": 2},
                    "approximate_proxy_label_counts": {},
                    "n_approximate_proxy_abstained": 2,
                    "n_approximate_strongreject_graded": 0,
                    "descriptive_common_endpoint": {
                        "endpoint": "approximate_over_refusal_rate",
                        "value": None,
                        "reason": "no_decided_judgments",
                        "decision_support": {
                            "judgments_completed": 2,
                            "judgments_evaluable": 2,
                            "judgments_decided": 0,
                            "judgments_abstained": 2,
                            "decision_coverage": 0.0,
                        },
                        "metric_authority": "supplementary_non_authoritative",
                    },
                },
            ]
        },
        "source_native_presence": {},
    }
    level2 = {
        "common": {
            "estimates": [
                {
                    "ordered_judges": ["rules", "guardrail"],
                    "model_spec": estimated_condition["model_spec"],
                    "corpus_arm": estimated_condition["corpus_arm"],
                    "attacker": estimated_condition["attacker"],
                    "metric": "approximate_over_refusal_rate",
                    "metric_authority": "supplementary_non_authoritative",
                    "endpoint_status": "approximate_common_proxy",
                    "warning_tag": "warning_approximate",
                    "approximate_provenance": {
                        "method": "common_judge_cascade_response_proxy",
                        "source_required_metric": estimated_condition[
                            "required_metric"
                        ],
                        "selected_judges": ["guardrail"],
                        "n_model_queried_decisions": 1,
                        "judge_models": [phase7.EXPECTED_GUARDRAIL_MODEL],
                        "judge_model_identities": [phase7.EXPECTED_GUARDRAIL_REVISION],
                        "judge_model_identity_types": ["revision"],
                        "judge_identity_kinds": ["exact"],
                    },
                }
            ]
        }
    }

    boundary = controller.build_boundaries(
        suite=suite,
        level2=level2,
        transfer={"schema_version": "2.1"},
        llava_pairs={},
        adaptivity_pairs={},
    )

    approximate = boundary["approximate_common_metrics"]
    assert approximate["expected_conditions"] == expected_conditions
    assert approximate["estimated_conditions"] == [
        {
            "condition": estimated_condition,
            "estimate_rows": 1,
            "completed_records": 1,
            "typed_abstentions": 0,
        }
    ]
    assert approximate["all_abstained_conditions"] == [
        {
            "condition": all_abstained_condition,
            "estimate_rows": 0,
            "completed_records": 2,
            "typed_abstentions": 2,
        }
    ]
    assert approximate["estimate_rows"] == 1
    assert approximate["selected_judges"] == ["guardrail"]
    assert approximate["judge_models"] == [phase7.EXPECTED_GUARDRAIL_MODEL]
    assert set(approximate["all_abstained_conditions"][0]) == {
        "condition",
        "estimate_rows",
        "completed_records",
        "typed_abstentions",
    }


@pytest.mark.parametrize(
    ("measured", "missing_roles", "reason_code"),
    (
        (
            ("crescendo-qwen3-vl",),
            ["left_replay"],
            "left_replay_lane_failed",
        ),
        (
            ("local-qwen3-vl-text-primary-100",),
            ["right_crescendo"],
            "right_crescendo_lane_failed",
        ),
        (
            (),
            ["left_replay", "right_crescendo"],
            "left_replay_and_right_crescendo_lanes_failed",
        ),
    ),
)
def test_phase7_adaptivity_writes_typed_non_estimable_artifacts_without_calls(
    phase7: ModuleType,
    tmp_path: Path,
    measured: tuple[str, ...],
    missing_roles: list[str],
    reason_code: str,
) -> None:
    runner = _analysis_prerequisite_runner(phase7, measured=measured)
    controller, subprocesses, statuses = _analysis_controller(
        phase7, tmp_path, runner
    )

    results = controller.run_adaptivity_pairs()

    assert subprocesses == []
    assert len(statuses) == len(phase7.ADAPTIVE_ARMS)
    assert set(results) == set(phase7.ADAPTIVE_ARMS)
    for corpus, value in results.items():
        assert value["schema"] == phase7.NON_ESTIMABLE_ADAPTIVITY_SCHEMA
        assert value["status"] == "unavailable"
        assert value["facet"] == corpus
        assert value["missing_roles"] == missing_roles
        assert value["reason_code"] == reason_code
        assert value["paired_compare_invoked"] is False
        assert value["estimate"] is None
        phase7.validate_non_estimable_adaptivity(
            value,
            runner=runner,
            corpus=corpus,
        )


def test_phase7_conditional_analyses_write_typed_unavailable_without_calls(
    phase7: ModuleType,
    tmp_path: Path,
) -> None:
    runner = _analysis_prerequisite_runner(phase7)
    controller, subprocesses, statuses = _analysis_controller(
        phase7, tmp_path, runner
    )

    results = {
        "judge-sensitivity": controller.run_judge_sensitivity(),
        "kappa": controller.run_kappa(),
        "transfer-matrix": controller.run_transfer(),
    }

    assert subprocesses == []
    assert len(statuses) == 3
    for analysis, value in results.items():
        assert value["schema"] == phase7.NON_ESTIMABLE_ANALYSIS_SCHEMA
        assert value["status"] == "unavailable"
        assert value["analysis"] == analysis
        assert value["subprocess_invoked"] is False
        assert value["result"] is None
        phase7.validate_non_estimable_analysis(
            value,
            runner=runner,
            analysis=analysis,
        )


def test_phase7_conditional_analysis_availability_is_lane_specific(
    phase7: ModuleType,
) -> None:
    cases = (
        ((), (False, False, False)),
        (("rjudge-qwen3-vl",), (True, False, True)),
        (("local-qwen3-vl-text-primary-100",), (True, True, True)),
        (("defense-local",), (False, False, False)),
        (("crescendo-qwen3-vl",), (False, False, False)),
    )
    analyses = ("judge-sensitivity", "kappa", "transfer-matrix")
    for measured, expected in cases:
        runner = _analysis_prerequisite_runner(phase7, measured=measured)
        observed = tuple(
            phase7.conditional_analysis_plan(runner, analysis)["runnable"]
            for analysis in analyses
        )
        assert observed == expected


def test_phase7_non_estimable_artifacts_reject_mutations_and_bad_evidence(
    phase7: ModuleType,
) -> None:
    runner = _analysis_prerequisite_runner(phase7)
    transfer = phase7.non_estimable_analysis_value(runner, "transfer-matrix")
    analysis_mutations = (
        ("subprocess_invoked", True),
        ("result", {}),
        ("target_calls", 1),
        ("judge_calls", 1),
    )
    for field, replacement in analysis_mutations:
        mutated = copy.deepcopy(transfer)
        mutated[field] = replacement
        with pytest.raises(phase7.Phase7Error, match="artifact changed"):
            phase7.validate_non_estimable_analysis(
                mutated,
                runner=runner,
                analysis="transfer-matrix",
            )

    adaptivity = phase7.non_estimable_adaptivity_value(
        runner, phase7.ADAPTIVE_ARMS[0]
    )
    for field, replacement in (
        ("paired_compare_invoked", True),
        ("estimate", 0.0),
        ("target_calls", 1),
    ):
        mutated = copy.deepcopy(adaptivity)
        mutated[field] = replacement
        with pytest.raises(phase7.Phase7Error, match="contrast changed"):
            phase7.validate_non_estimable_adaptivity(
                mutated,
                runner=runner,
                corpus=phase7.ADAPTIVE_ARMS[0],
            )

    invalid_runner = copy.deepcopy(runner)
    invalid_runner["lifecycle_authorizations"][
        "local-qwen3-vl-text-primary-100"
    ]["controller_failure"]["sha256"] = "not-a-digest"
    with pytest.raises(phase7.Phase7Error, match="failure descriptor changed"):
        phase7.non_estimable_analysis_value(invalid_runner, "transfer-matrix")


def test_phase7_transfer_index_accepts_single_and_faceted_outputs(
    phase7: ModuleType,
) -> None:
    single = {
        "schema_version": "2.1",
        "analysis_kind": "diagnostic_conditional_transfer",
        "load_audit": {
            "facet": {
                "attacker": "replay",
                "corpus": "fixture",
                "defense": "none",
            }
        },
        "unexplained_exclusions": 0,
    }
    facets, unavailable = phase7.validated_transfer_index_facets(single)
    assert facets == {"fixture": single}
    assert unavailable == {}

    faceted = {
        "schema_version": "2.1-faceted",
        "attacker": "replay",
        "defense": "none",
        "corpora": ["fixture"],
        "artifacts": {
            "fixture": {
                "json": "transfer_matrix__replay__fixture.json",
            }
        },
        "facets": {"fixture": copy.deepcopy(single)},
        "not_applicable_facets": {
            "empty": {
                "reason": "insufficient_eligible_models",
                "load_audit": {
                    "facet": {
                        "attacker": "replay",
                        "corpus": "empty",
                        "defense": "none",
                    }
                },
                "unexplained_exclusions": 0,
            }
        },
        "unexplained_exclusions": 0,
    }
    facets, unavailable = phase7.validated_transfer_index_facets(faceted)
    assert set(facets) == {"fixture"}
    assert set(unavailable) == {"empty"}

    for mutation in (
        {**faceted, "schema_version": "2.1-facet"},
        {**faceted, "defense": "both"},
        {**faceted, "corpora": []},
    ):
        with pytest.raises(phase7.Phase7Error):
            phase7.validated_transfer_index_facets(mutation)
    collision = copy.deepcopy(faceted)
    collision["corpora"] = ["fixture", "fixture."]
    collision["facets"]["fixture."] = copy.deepcopy(single)
    collision["facets"]["fixture."]["load_audit"]["facet"]["corpus"] = (
        "fixture."
    )
    collision["artifacts"]["fixture."] = {
        "json": "transfer_matrix__replay__fixture.json",
    }
    with pytest.raises(phase7.Phase7Error, match="artifact names collide"):
        phase7.validated_transfer_index_facets(collision)


def test_lifecycle_root_does_not_absorb_nested_recovery(
    phase7: ModuleType, tmp_path: Path
) -> None:
    original = tmp_path / "original"
    recovery = original / "recovery"
    recovery.mkdir(parents=True)
    support = original / "model-acquisition"
    support.mkdir()
    (support / "plan.json").write_text("{}", encoding="utf-8")
    for root, revision in ((original, "a" * 64), (recovery, "b" * 64)):
        (root / "cell.grid.json").write_text(json.dumps({"request": {
            "project_revision": {"sha256": revision},
            "source_conformance_artifact": {"sha256": "c" * 64},
        }}), encoding="utf-8")
        (root / "cell.responses.checkpoint.jsonl").write_text("{}\n", encoding="utf-8")
    assert set(phase7._runner_root_files(original, label="original")) == {
        "cell.grid.json", "cell.responses.checkpoint.jsonl", "model-acquisition/plan.json",
    }
    assert set(phase7._runner_root_files(recovery, label="recovery")) == {
        "cell.grid.json", "cell.responses.checkpoint.jsonl",
    }
    controller = object.__new__(phase7.AnalysisController)
    assert controller._lifecycle_root_stratum(str(original), label="original") == (
        "a" * 64, "c" * 64,
    )
    assert controller._lifecycle_root_stratum(str(recovery), label="recovery") == (
        "b" * 64, "c" * 64,
    )


def _runner_view_controller(
    phase7: ModuleType,
    tmp_path: Path,
) -> tuple[object, Path, Path]:
    source_root = tmp_path / "source"
    lane_root = source_root / "lane-a"
    lane_root.mkdir(parents=True)
    source_file = lane_root / "cell.manifest.json"
    source_file.write_bytes(b"sealed-runner-input")
    controller = object.__new__(phase7.AnalysisController)
    controller.inputs = {
        "runner": {
            "root": str(source_root.resolve()),
            "metric_lane_order": ["lane-a"],
        }
    }
    # This copy-integrity fixture supplies its one already-selected input lane.
    # Full campaign population selection is exercised independently.
    controller._all_metric_lanes = lambda: ["lane-a"]
    controller.runner_view = tmp_path / "view"
    controller.runner_view_receipt = tmp_path / "view-receipt.json"
    controller.runner_view_ready = False
    view = controller.analysis_runner_view()
    return controller, source_file, view / "lane-a" / source_file.name


@pytest.mark.parametrize(
    "mutation",
    ("in-place-copy-write", "selector-visible-extra"),
)
def test_phase7_runner_view_receipt_rejects_content_and_inventory_mutations(
    phase7: ModuleType,
    tmp_path: Path,
    mutation: str,
) -> None:
    controller, source_file, view_file = _runner_view_controller(
        phase7, tmp_path
    )
    receipt = json.loads(
        controller.runner_view_receipt.read_text(encoding="utf-8")
    )
    assert receipt["schema"] == phase7.RUNNER_VIEW_SCHEMA
    assert receipt["permitted_view_outputs"] == []
    assert receipt["regular_files_copied"] == 1
    assert receipt["file_inventory"][0]["relative_path"] == (
        "lane-a/cell.manifest.json"
    )
    assert receipt["file_inventory"][0]["source"]["path"] == str(
        source_file.resolve()
    )
    binding = receipt["file_inventory"][0]
    assert binding["independent_copy"] is True
    assert binding["source_view_samefile"] is False
    assert binding["source_file_identity"] != binding["view_file_identity"]
    assert binding["view_mode"] & 0o222 == 0
    assert binding["view_link_count"] == 1
    assert not source_file.samefile(view_file)

    if mutation == "in-place-copy-write":
        sealed_source = source_file.read_bytes()
        view_file.chmod(0o600)
        view_file.write_bytes(b"X" * len(sealed_source))
        assert source_file.read_bytes() == sealed_source
    else:
        (controller.runner_view / "forged.manifest.json").write_bytes(b"{}")

    with pytest.raises(phase7.Phase7Error):
        controller.analysis_runner_view()


def test_phase7_zero_output_view_rejects_selector_visible_extra(
    phase7: ModuleType,
    tmp_path: Path,
) -> None:
    controller, _source_file, _view_file = _runner_view_controller(
        phase7, tmp_path
    )
    forged = (
        controller.runner_view
        / "transfer_matrix__replay__forged.manifest.json"
    )
    forged.write_bytes(b"{}")
    receipt = json.loads(
        controller.runner_view_receipt.read_text(encoding="utf-8")
    )
    with pytest.raises(phase7.Phase7Error, match="unbound extra"):
        phase7.validate_runner_input_view_receipt(
            receipt,
            source_root=Path(controller.inputs["runner"]["root"]),
            view_root=controller.runner_view,
            included_measured_lanes=["lane-a"],
        )


def test_phase7_lifecycle_view_write_cannot_modify_phase6_source(
    phase7: ModuleType,
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "lifecycle-source"
    lane_root = source_root / "lane-a"
    lane_root.mkdir(parents=True)
    source_file = lane_root / "cell.grid.json"
    source_file.write_bytes(b"sealed-lifecycle-input")
    controller = object.__new__(phase7.AnalysisController)
    controller.inputs = {
        "runner": {
            "root": str(source_root.resolve()),
            "lifecycle_lane_order": ["lane-a"],
            "lifecycle_lane_roots": {"lane-a": str(lane_root.resolve())},
            "lifecycle_states": {"lane-a": "complete"},
            "lifecycle_authorizations": {
                "lane-a": {
                    "level1_tool_input_status": "retained_runner_artifacts",
                }
            },
        },
        "canonical_recoveries": {"attempts": []},
        "seven_output_policy_amendment": {
            "lane_order": [],
            "lifecycle": {},
            "metric_roots": {},
        },
        "followon": {"lane_order": [], "lifecycle": {}},
    }
    controller.lifecycle_runner_view_path = tmp_path / "lifecycle-view"
    controller.inputs["current_ollama"] = {"lane_order": [], "lifecycle": {}}
    for family in (
        "current_ollama_stability", "current_ollama_population_alignment",
        "failed_output_recovery", "vllm_stability", "vllm_context_recovery",
        "local_hardware_fit_recovery",
    ):
        controller.inputs[family] = {"unit_order": []}
    controller.lifecycle_runner_view_receipt = (
        tmp_path / "lifecycle-view-receipt.json"
    )
    controller.lifecycle_runner_view_ready = False

    view = controller.lifecycle_runner_view()
    view_file = view / "lane-a" / source_file.name
    sealed_source = source_file.read_bytes()
    assert not source_file.samefile(view_file)
    view_file.chmod(0o600)
    view_file.write_bytes(b"X" * len(sealed_source))
    assert source_file.read_bytes() == sealed_source
    with pytest.raises(phase7.Phase7Error):
        controller.lifecycle_runner_view()
