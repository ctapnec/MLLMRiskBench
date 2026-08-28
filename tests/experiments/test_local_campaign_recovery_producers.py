from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re

import pytest

from experiments.local_campaign.generate import (
    CONTROLLERS,
    EXTERNAL_BINDINGS,
    PRE_RECOVERY_EXTERNAL_BINDINGS,
    RECOVERY_BINDINGS_ADDED_AFTER_73C5331,
    external_binding_keys_from_templates,
)


ROOT = Path(__file__).parents[2]
TEMPLATES = ROOT / "experiments" / "local_campaign" / "templates"
CORE = TEMPLATES / "phase6_core_length_recovery.py.in"
SEVEN = TEMPLATES / "phase6_seven_output_policy.py.in"
LAUNCHER = TEMPLATES / "launch_phase6_recovery_and_seven.sh.in"
PHASE7 = TEMPLATES / "phase7_analysis.py.in"

CORE_LANES = (
    "local-qwen3-vl-text-primary-100",
    "local-qwen3-vl-image-primary-100",
    "local-llava-base-text-primary-100",
    "local-llava-base-image-primary-100",
    "gptgeochat-qwen3-vl",
    "crescendo-qwen3-vl",
)
SEVEN_LANES = (
    "local-llava-rr-text-primary-100",
    "local-llava-rr-image-primary-100",
    "rjudge-llava-rr",
    "gptgeochat-llava-rr",
    "ollama-rwkv-g1d-0p4b-text-exploratory-50",
    "ollama-rwkv-g1f-2p9b-text-exploratory-50",
    "ollama-rwkv-g1g-1p5b-text-exploratory-50",
)
PRIOR_RECOVERY_LANES = (
    "rjudge-ollama-rwkv-g1d-0p4b",
    "rjudge-ollama-rwkv-g1f-2p9b",
    "rjudge-ollama-rwkv-g1g-1p5b",
)
PRIOR_RECOVERY_EXPECTED_COMMIT = "73c5331c59d1192f3338170cfee374af5e03a07f"
PRIOR_RECOVERY_FRAMEWORK_LOCK_ID = (
    "49581308fb249f808ed21735c6badcfa9664156cc66aa14fa1490d6b28ccd406"
)
PRIOR_RECOVERY_SOURCE_SPEC_FILES = (
    "07-rjudge-ollama-rwkv-g1d-0p4b.json",
    "08-rjudge-ollama-rwkv-g1f-2p9b.json",
    "09-rjudge-ollama-rwkv-g1g-1p5b.json",
)
COMPLETION_FIELDS = {
    "schema",
    "status",
    "controller_exit_code",
    "completed_at_utc",
    "attempt",
    "expected_commit",
    "framework_lock_id",
    "inventory_complete",
    "runnable_lanes",
    "lane_terminal_states",
    "amendment",
    "launch",
    "controller",
    "retained_executor_payload",
    "summary",
    "lane_results",
    "lane_failures",
    "all_independent_lanes_attempted",
    "output_policy",
    "generation_caps_changed",
    "unrelated_passed_work_repeated",
    "paid_provider_calls",
}
GATE5_FAILURE_FIELDS = {
    "schema",
    "status",
    "failed_at_utc",
    "attempt",
    "lane_id",
    "stage",
    "reason_code",
    "error_type",
    "error",
    "lane_spec",
    "evidence_eligible",
}
RECOVERY_FILE_INPUT_FIELDS = frozenset({
    "retained_executor_payload",
    "historical_gate5_manifest",
    "historical_gate5_runnote",
    "historical_gate5_promotion",
    "focused_tests",
    "mutation_tests",
    "deployment_exit",
})


def _source(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tree(path: Path) -> ast.Module:
    return ast.parse(_source(path), filename=str(path))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )


def _assigned_literal(node: ast.AST, name: str):
    for candidate in ast.walk(node):
        if (
            isinstance(candidate, ast.Assign)
            and len(candidate.targets) == 1
            and isinstance(candidate.targets[0], ast.Name)
            and candidate.targets[0].id == name
        ):
            return ast.literal_eval(candidate.value)
    raise AssertionError(f"missing literal assignment: {name}")


def _assigned_frozenset(node: ast.AST, name: str) -> frozenset[str]:
    for candidate in ast.walk(node):
        if (
            isinstance(candidate, ast.Assign)
            and len(candidate.targets) == 1
            and isinstance(candidate.targets[0], ast.Name)
            and candidate.targets[0].id == name
            and isinstance(candidate.value, ast.Call)
            and isinstance(candidate.value.func, ast.Name)
            and candidate.value.func.id == "frozenset"
            and len(candidate.value.args) == 1
        ):
            value = ast.literal_eval(candidate.value.args[0])
            assert isinstance(value, set)
            assert all(isinstance(item, str) for item in value)
            return frozenset(value)
    raise AssertionError(f"missing frozenset assignment: {name}")


def _dict_keys(node: ast.AST, name: str) -> set[str]:
    for candidate in ast.walk(node):
        if (
            isinstance(candidate, ast.Assign)
            and len(candidate.targets) == 1
            and isinstance(candidate.targets[0], ast.Name)
            and candidate.targets[0].id == name
            and isinstance(candidate.value, ast.Dict)
        ):
            keys = [ast.literal_eval(key) for key in candidate.value.keys]
            assert all(isinstance(key, str) for key in keys)
            return set(keys)
    raise AssertionError(f"missing dictionary assignment: {name}")


def _nested_dict_literal(node: ast.AST, name: str, key: str) -> dict[str, object]:
    for candidate in ast.walk(node):
        if (
            isinstance(candidate, ast.Assign)
            and len(candidate.targets) == 1
            and isinstance(candidate.targets[0], ast.Name)
            and candidate.targets[0].id == name
            and isinstance(candidate.value, ast.Dict)
        ):
            for raw_key, raw_value in zip(
                candidate.value.keys, candidate.value.values, strict=True
            ):
                if ast.literal_eval(raw_key) == key:
                    value = ast.literal_eval(raw_value)
                    assert isinstance(value, dict)
                    return value
    raise AssertionError(f"missing nested dictionary: {name}.{key}")


def _compared_dict_literal(node: ast.AST, left_name: str) -> dict[str, object]:
    for candidate in ast.walk(node):
        if (
            isinstance(candidate, ast.Compare)
            and isinstance(candidate.left, ast.Name)
            and candidate.left.id == left_name
            and len(candidate.ops) == 1
            and isinstance(candidate.ops[0], ast.NotEq)
            and len(candidate.comparators) == 1
            and isinstance(candidate.comparators[0], ast.Dict)
        ):
            value = ast.literal_eval(candidate.comparators[0])
            assert isinstance(value, dict)
            return value
    raise AssertionError(f"missing compared dictionary: {left_name}")


def _helper_namespace(path: Path) -> dict[str, object]:
    tree = _tree(path)
    wanted = {
        "_verified_file_descriptor",
        "_validated_input_value",
        "_bound_inputs",
        "_revalidate_payload_before_import",
    }
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in wanted
    ]
    assert {node.name for node in functions} == wanted
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations")],
                level=0,
            ),
            *functions,
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    namespace: dict[str, object] = {
        "Path": Path,
        "hashlib": hashlib,
        "json": json,
    }
    exec(compile(module, str(path), "exec"), namespace)
    return namespace


def _prior_validator_namespace(path: Path) -> dict[str, object]:
    tree = _tree(path)
    wanted_assignments = {
        "OLLAMA_SPEC_FILES",
        "PRIOR_RECOVERY_LANES",
        "PRIOR_RECOVERY_EXPECTED_COMMIT",
        "PRIOR_RECOVERY_FRAMEWORK_LOCK_ID",
        "PRIOR_RECOVERY_SOURCE_SPEC_FILES",
        "PRIOR_RECOVERY_COMPLETION_FIELDS",
        "PRIOR_RECOVERY_LAUNCH_FIELDS",
        "PRIOR_RECOVERY_AMENDMENT_FIELDS",
        "PRIOR_RECOVERY_SUMMARY_FIELDS",
        "PRIOR_RECOVERY_OUTPUT_POLICY",
    }
    wanted_functions = {
        "_verified_file_descriptor",
        "sha256_bytes",
        "descriptor",
        "strict_json",
        "_nested_descriptor_path",
        "validate_prior_recovery_completion",
    }
    body: list[ast.stmt] = [
        ast.ImportFrom(
            module="__future__",
            names=[ast.alias(name="annotations")],
            level=0,
        )
    ]
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in wanted_assignments
        ) or (
            isinstance(node, ast.FunctionDef)
            and node.name in wanted_functions
        ):
            body.append(node)
    module = ast.Module(body=body, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace: dict[str, object] = {
        "Path": Path,
        "hashlib": hashlib,
        "json": json,
        "os": os,
    }
    exec(compile(module, str(path), "exec"), namespace)
    assert wanted_functions <= set(namespace)
    namespace["EXPECTED_COMMIT"] = "a" * 40
    return namespace


def _file_descriptor(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": path.resolve(strict=True).as_posix(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    )


def _prior_recovery_fixture(root: Path) -> dict[str, object]:
    control = (root / "recovery").resolve()
    attempt = control / "attempts" / "attempt-a"
    attempt.mkdir(parents=True)
    retained_control = (root / "retained-extended").resolve()
    retained_payload = retained_control / "payload.py"
    retained_payload.parent.mkdir(parents=True)
    retained_payload.write_bytes(b"# retained executor\n")
    for name in PRIOR_RECOVERY_SOURCE_SPEC_FILES:
        _write_json(retained_control / "lane-specs" / name, {"source": name})
    recovery_specs: dict[str, Path] = {}
    for index, lane in enumerate(PRIOR_RECOVERY_LANES, 1):
        name = f"{index:02d}-{lane}.json"
        path = control / "lane-specs" / name
        _write_json(path, {"lane_id": lane})
        recovery_specs[name] = path

    evidence: dict[str, Path] = {}
    for name in (
        "runnote", "project_revision", "source_conformance", "focused_tests",
        "mutation_tests", "gate5_manifest", "gate5_runnote", "gate5_promotion",
    ):
        path = root / "evidence" / f"{name}.json"
        _write_json(path, {"artifact": name})
        evidence[name] = path
    _write_json(
        evidence["project_revision"],
        {
            "schema": "ura-project-revision/1",
            "status": "complete",
            "purpose": "immutable_clean_project_source_receipt",
            "revision_id": "project-revision-test",
            "repository": {
                "clean": True,
                "expected_commit": PRIOR_RECOVERY_EXPECTED_COMMIT,
                "observed_commit": PRIOR_RECOVERY_EXPECTED_COMMIT,
                "head_tree": "d" * 40,
                "root_relationship": (
                    "experiments_driver_and_src_ura_share_one_git_toplevel"
                ),
            },
            "source": {},
            "limitations": {},
        },
    )
    controller = root / "controller.py"
    controller.write_bytes(b"# controller\n")

    expected_caps = {
        "deadline_seconds": 86_400,
        "http_attempts": 0,
        "model_judge_calls": 0,
        "target_calls": 50,
        "wall_time_seconds": 86_400,
    }
    output_policy = {
        "nonempty_length_capped_text": "retain_and_analyze",
        "successful_empty_completion": "retain_as_typed_model_nonresponse",
        "common_metric_denominator": "exclude_model_nonresponse",
        "source_specific_parser": "retain_invalid_prediction",
        "terminal_reason_retained": True,
        "unknown_terminal_reason": "error",
        "generation_caps_changed": False,
    }
    amendment_path = control / "runner-2.24-source-metric-amendment.json"
    amendment = {
        "schema": "ura-local-campaign-model-output-amendment/1",
        "status": "approved_for_targeted_recanary_and_measured_recovery",
        "created_at_utc": "2026-08-27T10:28:41Z",
        "project_commit": PRIOR_RECOVERY_EXPECTED_COMMIT,
        "runner_code_version": "ura-runner/2.24",
        "output_policy": output_policy,
        "operator_authorization": "bounded retained-output correction",
        "runnote": _file_descriptor(evidence["runnote"]),
        "project_revision": _file_descriptor(evidence["project_revision"]),
        "source_conformance": _file_descriptor(evidence["source_conformance"]),
        "framework_lock_id": PRIOR_RECOVERY_FRAMEWORK_LOCK_ID,
        "focused_tests": _file_descriptor(evidence["focused_tests"]),
        "mutation_tests": _file_descriptor(evidence["mutation_tests"]),
        "historical_gate5": {
            "manifest": _file_descriptor(evidence["gate5_manifest"]),
            "runnote": _file_descriptor(evidence["gate5_runnote"]),
            "promotion": _file_descriptor(evidence["gate5_promotion"]),
        },
        "retained_completed_lanes": [
            "bridge-pyrit", "bridge-deepteam", "bridge-h4rm3l",
            "bridge-spikee", "bridge-purplellama", "harmbench-replay",
        ],
        "affected_lanes": [
            {
                "lane_id": lane,
                "retained_lane_spec": _file_descriptor(
                    retained_control / "lane-specs" / source_name
                ),
                "approved_caps": expected_caps,
                "selection_and_sampling_changed": False,
            }
            for lane, source_name in zip(
                PRIOR_RECOVERY_LANES,
                PRIOR_RECOVERY_SOURCE_SPEC_FILES,
                strict=True,
            )
        ],
        "unrelated_passed_work_repeated": False,
        "paid_provider_calls": 0,
    }
    _write_json(amendment_path, amendment)

    expected_states = {lane: "measured_complete" for lane in PRIOR_RECOVERY_LANES}
    summary_path = attempt / "summary.json"
    _write_json(
        summary_path,
        {
            "schema": "ura-phase6-failed-lane-recovery-summary/1",
            "status": "complete",
            "controller_exit_code": 0,
            "completed_at_utc": "2026-08-27T10:33:49Z",
            "attempt": attempt.name,
            "runnable_inventory": list(PRIOR_RECOVERY_LANES),
            "lane_terminal_states": expected_states,
            "completed_lanes": list(PRIOR_RECOVERY_LANES),
            "failed_lanes": [],
            "failures": [],
            "all_independent_lanes_attempted": True,
            "output_policy": "retain_length_capped_text_and_typed_model_nonresponse",
            "generation_caps_changed": False,
            "unrelated_passed_work_repeated": False,
            "paid_provider_calls": 0,
            "hosted_judge_calls": 0,
            "http_attempts": 0,
            "model_downloads": 0,
        },
    )
    results: dict[str, dict[str, object]] = {}
    for lane in PRIOR_RECOVERY_LANES:
        result_path = attempt / f"{lane}.complete.json"
        _write_json(result_path, {"lane_id": lane, "status": "complete"})
        results[lane] = _file_descriptor(result_path)

    launch_path = control / "launch.json"
    launch = {
        "schema": "ura-phase6-failed-lane-recovery-launch/1",
        "launched_at_utc": "2026-08-27T10:28:41Z",
        "expected_commit": PRIOR_RECOVERY_EXPECTED_COMMIT,
        "framework_lock_id": PRIOR_RECOVERY_FRAMEWORK_LOCK_ID,
        "execution_scope_id": "bigrigsys-local-vllm",
        "control_root": str(control),
        "attempt": attempt.name,
        "controller": _file_descriptor(controller),
        "retained_executor_payload": _file_descriptor(retained_payload),
        "amendment": _file_descriptor(amendment_path),
        "lane_order": list(PRIOR_RECOVERY_LANES),
    }
    _write_json(launch_path, launch)
    completion_path = attempt / "completion.json"
    completion = {
        "schema": "ura-phase6-failed-lane-recovery-completion/1",
        "status": "complete",
        "controller_exit_code": 0,
        "completed_at_utc": "2026-08-27T10:33:49Z",
        "attempt": attempt.name,
        "expected_commit": PRIOR_RECOVERY_EXPECTED_COMMIT,
        "framework_lock_id": PRIOR_RECOVERY_FRAMEWORK_LOCK_ID,
        "inventory_complete": True,
        "runnable_lanes": list(PRIOR_RECOVERY_LANES),
        "lane_terminal_states": expected_states,
        "amendment": _file_descriptor(amendment_path),
        "launch": _file_descriptor(launch_path),
        "controller": _file_descriptor(controller),
        "retained_executor_payload": _file_descriptor(retained_payload),
        "summary": _file_descriptor(summary_path),
        "lane_results": results,
        "lane_failures": {},
        "all_independent_lanes_attempted": True,
        "output_policy": "retain_length_capped_text_and_typed_model_nonresponse",
        "generation_caps_changed": False,
        "unrelated_passed_work_repeated": False,
        "paid_provider_calls": 0,
    }
    _write_json(completion_path, completion)
    exit_marker = attempt / ".exit"
    exit_marker.write_bytes(b"0\n")
    return {
        "attempt": attempt,
        "exit_marker": exit_marker,
        "completion_file": completion_path,
        "retained_payload": retained_payload,
        "recovery_control": control,
        "recovery_lane_specs": recovery_specs,
        "launch_path": launch_path,
    }


def _seven_lane_ids(tree: ast.Module) -> tuple[str, ...]:
    assignment = next(
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "SPEC_SOURCES"
    )
    assert isinstance(assignment.value, ast.Tuple)
    result: list[str] = []
    for row in assignment.value.elts:
        assert isinstance(row, ast.Tuple)
        value = ast.literal_eval(row.elts[0])
        assert isinstance(value, str)
        result.append(value)
    return tuple(result)


def _assert_prior_recovery_provenance(source: str, *, seven: bool) -> None:
    tree = ast.parse(source)
    assert _assigned_literal(tree, "PRIOR_RECOVERY_LANES") == (
        PRIOR_RECOVERY_LANES
    )
    assert _assigned_literal(tree, "PRIOR_RECOVERY_SOURCE_SPEC_FILES") == (
        PRIOR_RECOVERY_SOURCE_SPEC_FILES
    )
    assert _assigned_literal(tree, "PRIOR_RECOVERY_EXPECTED_COMMIT") == (
        PRIOR_RECOVERY_EXPECTED_COMMIT
    )
    assert _assigned_literal(tree, "PRIOR_RECOVERY_FRAMEWORK_LOCK_ID") == (
        PRIOR_RECOVERY_FRAMEWORK_LOCK_ID
    )
    assert _assigned_frozenset(tree, "PRIOR_RECOVERY_COMPLETION_FIELDS") == (
        frozenset(COMPLETION_FIELDS)
    )
    validator = ast.get_source_segment(
        source, _function(tree, "validate_prior_recovery_completion")
    )
    assert validator is not None
    for condition in (
        'completion_file != attempt / "completion.json"',
        'exit_marker != attempt / ".exit"',
        "control = attempt.parent.parent",
        "recovery_control is not None and control != recovery_control",
        'completion.get("schema")\n        != "ura-phase6-failed-lane-recovery-completion/1"',
        'completion.get("status") != "complete"',
        'completion.get("controller_exit_code") != 0',
        'completion.get("expected_commit") != PRIOR_RECOVERY_EXPECTED_COMMIT',
        'completion.get("framework_lock_id")',
        'completion.get("runnable_lanes") != list(PRIOR_RECOVERY_LANES)',
        'completion.get("lane_terminal_states") != expected_states',
        'completion.get("lane_failures") != {}',
        '"retain_length_capped_text_and_typed_model_nonresponse"',
        'exact=control / "launch.json"',
        'exact=attempt / "summary.json"',
        'launch.get("control_root") != str(control)',
        'amendment.get("framework_lock_id")',
        'repository.get("expected_commit") != PRIOR_RECOVERY_EXPECTED_COMMIT',
        'repository.get("observed_commit") != PRIOR_RECOVERY_EXPECTED_COMMIT',
        'exact=retained_payload.parent / "lane-specs" / source_name',
    ):
        assert condition in validator
    assert validator.count("_nested_descriptor_path(") >= 9
    assert 'set(summary) != PRIOR_RECOVERY_SUMMARY_FIELDS' in validator
    assert 'summary.get("completed_lanes") != list(PRIOR_RECOVERY_LANES)' in validator
    assert 'summary.get("failed_lanes") != []' in validator
    assert 'summary.get("failures") != []' in validator
    assert 'summary.get("output_policy") != completion["output_policy"]' in validator
    assert_source = ast.get_source_segment(source, _function(tree, "assert_inputs"))
    assert assert_source is not None
    assert "validate_prior_recovery_completion(" in assert_source
    assert assert_source.index("validate_prior_recovery_completion(") < (
        assert_source.index("for path in (")
    )
    if seven:
        assert "recovery_control=OLD_OLLAMA_CONTROL" in assert_source
        assert "recovery_lane_specs=OLD_OLLAMA_SPECS" in assert_source
        assert 'set(recovery_lane_specs) != set(OLLAMA_SPEC_FILES)' in validator
        assert 'path != control / "lane-specs" / name' in validator
    else:
        assert "retained_payload=PAYLOAD_PATH" in assert_source


def _assert_core_contract(source: str) -> None:
    tree = ast.parse(source)
    _assert_prior_recovery_provenance(source, seven=False)
    assert _assigned_frozenset(tree, "FILE_INPUT_FIELDS") == (
        RECOVERY_FILE_INPUT_FIELDS
    )
    assert _dict_keys(tree, "DIRECTORY_INPUT_ARTIFACTS") == {
        "base_core_control_root",
        "prior_recovery_attempt",
    }
    lane_files = _assigned_literal(tree, "LANE_FILES")
    assert tuple(name[3:-5] for name in lane_files) == CORE_LANES
    validator = _function(tree, "validate_specs_contract")
    expected_caps = _assigned_literal(validator, "expected_caps")
    assert expected_caps == {
        "local-qwen3-vl-text-primary-100": 3854,
        "local-qwen3-vl-image-primary-100": 1632,
        "local-llava-base-text-primary-100": 3854,
        "local-llava-base-image-primary-100": 1632,
        "gptgeochat-qwen3-vl": 2020,
        "crescendo-qwen3-vl": 2800,
    }
    assert _dict_keys(_function(tree, "finalize"), "completion") == COMPLETION_FIELDS
    assert 'caps.get("wall_time_seconds") != 86_400' in source
    assert 'caps.get("deadline_seconds") != 86_400' in source
    assert 'caps.get("model_judge_calls") != 0' in source
    assert 'caps.get("http_attempts") != 0' in source
    assert '"generation_caps_changed": False' in source
    assert '"unrelated_passed_work_repeated": False' in source
    assert 'option_value(argv, "--sample-seed") != "0"' in source
    assert 'option_value(argv, "--seeds") != "0"' in source
    assert '"--sampling-policy" in argv' in source
    assert 'option_value(argv, "--source-conformance")' in source
    assert 'option_value(argv, "--source-config-sha256") != source_config_sha' in source
    assert '"spec": "vllm:Qwen/Qwen3-VL-8B-Instruct"' in source
    assert '"revision": "60595ebc30ec8e3b1d3b9e65d4943ca011c0006a"' in source
    assert '"spec": "vllm:llava-hf/llava-v1.6-mistral-7b-hf"' in source
    assert '"revision": "2424fdd47412fccc66d91719126b420e9fbd7065"' in source
    assert 'schema="ura-phase6-core-length-recovery-inputs/2"' in source
    assert "retained_pyrit" not in source.lower()
    main_source = ast.get_source_segment(source, _function(tree, "main"))
    assert main_source is not None
    assert "validate_specs_contract(module, specs)" in main_source
    assert main_source.index("specs = assert_inputs(module)") < main_source.index(
        "validate_specs_contract(module, specs)"
    ) < main_source.index("CONTROL.mkdir")
    assert "record_gate5_failure(" in main_source
    assert 'ctl.record_failure(lane, "gate5"' not in main_source
    assert 'lane, "measured", measured_error' in main_source
    assert _dict_keys(_function(tree, "record_gate5_failure"), "value") == (
        GATE5_FAILURE_FIELDS
    )


def _assert_seven_contract(source: str) -> None:
    tree = ast.parse(source)
    _assert_prior_recovery_provenance(source, seven=True)
    assert _assigned_frozenset(tree, "FILE_INPUT_FIELDS") == (
        RECOVERY_FILE_INPUT_FIELDS
    )
    assert _dict_keys(tree, "DIRECTORY_INPUT_ARTIFACTS") == {
        "base_core_control_root",
        "base_ollama_control_root",
        "prior_ollama_recovery_attempt",
    }
    assert _seven_lane_ids(tree) == SEVEN_LANES
    validator = _function(tree, "validate_specs_contract")
    expected_caps = _assigned_literal(validator, "expected_caps")
    assert expected_caps == {
        "local-llava-rr-text-primary-100": 3854,
        "local-llava-rr-image-primary-100": 1632,
        "rjudge-llava-rr": 100,
        "gptgeochat-llava-rr": 2020,
        "ollama-rwkv-g1d-0p4b-text-exploratory-50": 1945,
        "ollama-rwkv-g1f-2p9b-text-exploratory-50": 1945,
        "ollama-rwkv-g1g-1p5b-text-exploratory-50": 1945,
    }
    assert _dict_keys(_function(tree, "finalize"), "completion") == COMPLETION_FIELDS
    gate5_fields = _dict_keys(_function(tree, "write_gate5_inventory"), "value")
    assert gate5_fields == {
        "schema",
        "status",
        "completed_at_utc",
        "project_commit",
        "runner_code_version",
        "base_manifest",
        "policy_amendment",
        "profile",
        "rows",
        "all_seven_evaluated_before_measured_execution",
        "generation_caps_changed",
        "paid_provider_calls",
    }
    assert '"target_runtime_terminal": 7 - len(ready)' in source
    assert '"runnable": 18 + len(ready)' in source
    assert '"typed_terminal": 28 - len(ready)' in source
    assert '"conditional_na_lanes": ["defense-local"]' in source
    assert '"all_seven_evaluated_before_measured_execution": True' in source
    assert '"generation_caps_changed": False' in source
    assert 'option_value(argv, "--sample-seed") != "0"' in source
    assert 'option_value(argv, "--seeds") != "0"' in source
    assert '"--sampling-policy" in argv' in source
    assert 'option_value(argv, "--source-conformance")' in source
    assert 'option_value(argv, "--source-config-sha256") != source_config_sha' in source
    for selector, digest in (
        (
            "ollama:mollysama/rwkv-7-g1d:0.4b",
            "78e699bd71f0cef7ed8fb38a469088310af0ab07d678661980c6b8c7f130a7f8",
        ),
        (
            "ollama:mollysama/rwkv-7-g1f:2.9b",
            "7813f2283a135ef1264b8cec647b339d92fa7ecffafefeac61a2670b572f03f7",
        ),
        (
            "ollama:mollysama/rwkv-7-g1g:1.5b",
            "8ff95f43952c361048310b50a5c4b16f98d8f0642a87b536452e627224a0dddc",
        ),
    ):
        assert selector in source
        assert digest in source
    assert 'schema="ura-seven-output-policy-amendment-inputs/2"' in source
    assert "retained_pyrit" not in source.lower()
    assert '"unavailable": 7,' in source
    assert '"target_runtime_terminal": 7,' in source
    assert 'target_runtime_ids != HISTORICAL_AFFECTED_IDS' in source
    assert 'if row["lane_id"] in by_lane:' in source
    assert _compared_dict_literal(_function(tree, "assert_inputs"), "dispositions") == {
        "runnable": 18,
        "unavailable": 7,
        "conditional_na": 1,
        "target_runtime_terminal": 7,
        "structural_na": 13,
    }
    amendment = _function(tree, "write_amendment")
    assert _nested_dict_literal(amendment, "value", "historical_profile") == {
        "rows": 46,
        "runnable": 18,
        "typed_terminal": 28,
        "unavailable": 7,
        "conditional_na": 1,
        "target_runtime_terminal": 7,
        "structural_na": 13,
    }
    assert _nested_dict_literal(amendment, "value", "all_pass_profile") == {
        "rows": 46,
        "runnable": 25,
        "typed_terminal": 21,
        "unavailable": 7,
        "conditional_na": 1,
        "target_runtime_terminal": 0,
        "structural_na": 13,
        "conditional_na_lanes": ["defense-local"],
    }
    main_source = ast.get_source_segment(source, _function(tree, "main"))
    assert main_source is not None
    assert "validate_specs_contract(module, specs)" in main_source
    assert main_source.index("specs = assert_inputs(module)") < main_source.index(
        "validate_specs_contract(module, specs)"
    ) < main_source.index("CONTROL.mkdir")
    assert "record_gate5_failure(" in main_source
    assert 'ctl.record_failure(lane, "gate5"' not in main_source
    assert 'ctl.record_failure(lane, "measured"' in main_source
    assert _dict_keys(_function(tree, "record_gate5_failure"), "value") == (
        GATE5_FAILURE_FIELDS
    )


def _assert_core_attestation_modalities(source: str) -> None:
    tree = ast.parse(source)
    derive = ast.get_source_segment(source, _function(tree, "derive_core_attestation"))
    corrective = ast.get_source_segment(source, _function(tree, "corrective_gate5"))
    assert derive is not None and corrective is not None
    assert (
        'expected_modalities = ["text"] if modality == "text" else ["text", "image"]'
        in derive
    )
    assert 'records[0].get("exact_input_modalities") != expected_modalities' in derive
    assert "derive_core_attestation(module, ctl, spec, gate_root)" in corrective
    assert "module.validate_live_attestation_for_lane" not in corrective


def _assert_phase7_recovery_artifact_layers(source: str) -> None:
    assert 'envelope_bindings = envelope.get("bindings")' in source
    assert 'envelope_bindings.get("project_revision")' in source
    assert 'request.get("source_conformance_artifact")' in source
    assert 'request.get("source_config_artifact")' in source
    assert 'envelope_request.get("project_revision")' not in source
    assert 'envelope_request.get("source_conformance_artifact")' not in source
    assert 'envelope_request.get("source_config_artifact")' not in source


def _assert_phase7_seven_failure_schema(source: str) -> None:
    start = source.index("def current_phase6_failure_record(")
    end = source.index("\n\ndef git_output", start)
    validator = source[start:end]
    assert 'schema == "ura-phase6-gate5-lane-failure/1"' in validator
    assert 'set(failure) != GATE5_LANE_FAILURE_FIELDS' in validator
    assert 'schema == "ura-phase6-extended-lane-failure/1"' in validator
    assert 'set(failure) != EXTENDED_LANE_FAILURE_FIELDS' in validator
    assert 'not isinstance(failure.get("error"), str)' in validator
    assert 'not failure["error"].strip()' in validator
    assert 'failure.get("reason")' not in validator
    assert source.count("current_phase6_failure_record(") == 3
    assert 'control / "lane-specs" / f"{lane_index:02d}-{lane}.json"' in source


def _assert_phase7_seven_gate5_layers(source: str) -> None:
    assert "policy_sha = sha256_file(policy_file)" in source
    assert "amendment_sha = hashlib.sha256(amendment_payload).hexdigest()" in source
    assert 'if key != "manifest_sha256"' in source
    assert 'amendment_gate5.get("manifest_sha256") != policy_sha' in source
    assert 'spec_gate5.get("manifest_sha256") != amendment_sha' in source
    assert 'spec.get("gate5") != amendment_row["gate5"]' not in source
    assert 'policy.get("output_policy") != expected_output_policy' in source
    assert 'policy.get("historical_profile") != expected_historical_profile' in source
    assert 'policy.get("all_pass_profile") != expected_all_pass_profile' in source
    historical = source[
        source.index("expected_historical_profile = {"):
        source.index("expected_all_pass_profile = {")
    ]
    assert '"target_runtime_terminal": 7' in historical


def _assert_phase7_seven_policy_launch_chain(source: str) -> None:
    start = source.index("def validate_seven_output_policy_inventory(")
    end = source.index("\n\ndef ", start + 5)
    validator = source[start:end]
    signature = validator[:validator.index(") -> dict[str, Any]:")]
    assert "gate5_runnote: Path," in signature
    assert "gate5_promotion: Path," in signature
    assert "project_and_source: Mapping[str, Any]," in signature
    assert "= None" not in signature
    for condition in (
        "set(policy) != policy_fields",
        'policy.get("status") != "approved_for_targeted_readmission"',
        'policy.get("output_policy") != expected_output_policy',
        'policy.get("operator_authorization")',
        '"4 passed" not in focused_tests_text',
        '"2 failed" not in mutation_tests_text',
        'historical_gate5.get("manifest") != descriptor(gate5_manifest)',
        'historical_gate5.get("runnote") != descriptor(gate5_runnote)',
        'historical_gate5.get("promotion") != descriptor(gate5_promotion)',
        "validate_phase6_recovery_completions(",
        'prior_attempts[0].get("expected_commit")',
        "!= RECOVERY_RUNNER_224_HISTORICAL_COMMIT",
        "project_revision_value = validate_project_revision(project_revision_value)",
        "validate_source_conformance_manifest(strict_object(source_conformance_path))",
        "set(row) != policy_row_fields",
        'row.get("approved_caps") != expected_caps',
        "set(launch) != launch_fields",
        'launch.get("schema")',
        '!= "ura-seven-output-policy-amendment-launch/1"',
        'launch.get("execution_scope_id") != "bigrigsys-local-vllm"',
        'launch.get("control_root", ""), label="seven-row launch control root"',
        'launch.get("attempt") != attempt_name',
        'launch.get("amendment") != descriptor(policy_file)',
        'launch.get("lane_order") != list(SEVEN_AMENDMENT_LANES)',
        'completion.get("amendment") != descriptor(amendment_file)',
        'completion.get("launch") != descriptor(launch_path)',
        'set(states) != set(SEVEN_AMENDMENT_LANES)',
        'control.name\n        != f"seven-output-policy-amendment-{short_commit}-{policy_tag}"',
        'runnote_path.name\n        != f"RUNNOTE.runner-2.24-seven-output-policy-amendment-{policy_tag}.md"',
    ):
        assert condition in validator
    assert 'completion.get("amendment") != descriptor(policy_file)' not in validator
    prepare_start = source.index("seven = validate_seven_output_policy_inventory(")
    prepare_end = source.index("\n    )", prepare_start) + len("\n    )")
    prepare_call = source[prepare_start:prepare_end]
    assert "gate5_runnote=gate5_runnote" in prepare_call
    assert "gate5_promotion=gate5_promotion" in prepare_call
    assert "project_and_source=project_and_source" in prepare_call
    authorized_start = source.index(
        "validated_seven = validate_seven_output_policy_inventory("
    )
    authorized_end = source.index("\n        )", authorized_start) + len("\n        )")
    authorized_call = source[authorized_start:authorized_end]
    assert "gate5_runnote=gate5_runnote_path" in authorized_call
    assert "gate5_promotion=gate5_promotion_path" in authorized_call
    assert "project_and_source=validated_project_and_source" in authorized_call


def _assert_phase7_seven_measured_request_contract(source: str) -> None:
    validator_start = source.index("def validate_measured_grid_request(")
    validator_end = source.index("\n\ndef ", validator_start + 5)
    validator = source[validator_start:validator_end]
    for condition in (
        'request.get("models") != [model_selector]',
        'request.get("corpora") != contract["corpora"]',
        'request.get("limit") != expected_limit',
        'request.get("global_call_budget")',
    ):
        assert condition in validator
    assert "lane in SEVEN_AMENDMENT_LANES[:4]" in validator
    assert "lane in SEVEN_AMENDMENT_LANES[4:]" in validator

    seven_start = source.index("def validate_seven_output_policy_inventory(")
    seven_end = source.index("\n\ndef ", seven_start + 5)
    seven = source[seven_start:seven_end]
    assert "validate_seven_lane_spec(lane, spec)" in seven
    assert "grid_request_descriptor = validate_measured_grid_request(" in seven
    assert 'spec.get("base_argv"), "--source-config-sha256", lane=lane' in seven
    assert "expected_project_binding=seven_project_binding" in seven
    assert "or set(summary) != summary_fields" in seven
    assert 'summary.get("controller_exit_code") != completion["controller_exit_code"]' in seven
    assert 'summary.get("runnable_inventory") != ready' in seven
    assert 'summary.get("completed_lanes") != ordered_completed' in seven
    assert 'summary.get("failed_lanes") != ordered_failed' in seven
    assert 'summary.get("failures") != inline_failures' in seven
    exact_start = source.index("def validate_seven_lane_spec(")
    exact_end = source.index("\n\ndef ", exact_start + 5)
    exact = source[exact_start:exact_end]
    assert 'spec.get("target") != expected["target"]' in exact
    assert 'spec.get("expected_corpora") != list(expected["corpora"])' in exact
    assert 'spec.get("approved_caps") != expected_caps' in exact
    assert '!= SEVEN_SOURCE_CONFIG_SHA256' in exact
    assert "OLLAMA_STATIC_TERMINAL_MODELS[lane][2]" in source


def _assert_phase7_recovery_amendment_contract(source: str) -> None:
    constants = source[
        source.index("RECOVERY_AMENDMENT_ROW_FIELDS = {"):
        source.index("CAMPAIGN_COHORTS = (")
    ]
    variants = {
        ("ura-local-campaign-length-output-amendment/1", "ura-runner/2.22"): 2,
        ("ura-local-campaign-model-output-amendment/1", "ura-runner/2.23"): 3,
        ("ura-local-campaign-model-output-amendment/1", "ura-runner/2.24"): 2,
        ("ura-local-campaign-core-length-output-amendment/1", "ura-runner/2.24"): 2,
    }
    for (schema, runner), expected_count in variants.items():
        assert constants.count(f'"{schema}", "{runner}"') == expected_count
    assert '"retained_field": "retained_prerequisites"' in constants
    assert '"completed_under_runner_2_22_before_controller_retry"' in source
    assert '"06-harmbench-replay.json"' in constants
    assert '"07-gptgeochat-qwen3-vl.json"' in constants
    assert '"09-crescendo-qwen3-vl.json"' in constants
    assert '"bridge-spikee", "bridge-purplellama", "harmbench-replay"' in constants
    assert '"73c5331c59d1192f3338170cfee374af5e03a07f"' in constants
    assert (
        '"49581308fb249f808ed21735c6badcfa9664156cc66aa14fa1490d6b28ccd406"'
        in constants
    )
    expected_cap_occurrences = {
        '("bridge-pyrit", 150)': 1,
        '("bridge-deepteam", 150)': 1,
        '("bridge-h4rm3l", 600)': 1,
        '("bridge-spikee", 600)': 1,
        '("bridge-purplellama", 200)': 1,
        '("harmbench-replay", 50)': 2,
        '("rjudge-ollama-rwkv-g1d-0p4b", 50)': 3,
        '("rjudge-ollama-rwkv-g1f-2p9b", 50)': 3,
        '("rjudge-ollama-rwkv-g1g-1p5b", 50)': 3,
        '("local-qwen3-vl-text-primary-100", 3854)': 1,
        '("local-qwen3-vl-image-primary-100", 1632)': 1,
        '("local-llava-base-text-primary-100", 3854)': 1,
        '("local-llava-base-image-primary-100", 1632)': 1,
        '("gptgeochat-qwen3-vl", 2020)': 1,
        '("crescendo-qwen3-vl", 2800)': 1,
    }
    for marker, expected_count in expected_cap_occurrences.items():
        assert constants.count(marker) == expected_count

    request_start = source.index("def _recovery_request_identity(")
    request_end = source.index("\n\ndef ", request_start + 5)
    request = source[request_start:request_end]
    assert 'or "--sampling-policy" in argv' in request
    assert '("--project-revision", "--project-revision-sha256")' in request

    retained_start = source.index("def _validate_recovery_retained_provenance(")
    retained_end = source.index("\n\ndef ", retained_start + 5)
    retained = source[retained_start:retained_end]
    for condition in (
        "set(prior) != prior_completion_fields",
        'prior.get("expected_commit")\n            != RECOVERY_RUNNER_224_HISTORICAL_COMMIT',
        'prior.get("framework_lock_id") != RECOVERY_FRAMEWORK_LOCK_ID',
        'prior_amendment.get("project_commit")\n            != RECOVERY_RUNNER_224_HISTORICAL_COMMIT',
        'prior_launch.get("amendment") != descriptor(prior_amendment_path)',
        'prior_launch.get("lane_order") != expected_prior_lanes',
        'prior_repository.get("observed_commit")\n            != RECOVERY_RUNNER_224_HISTORICAL_COMMIT',
        'row.get("lane_id") != lane',
        'result.get("target_call_cap")\n                != row["approved_caps"]["target_calls"]',
    ):
        assert condition in retained

    amendment_start = source.index("def _validate_phase6_recovery_amendment(")
    amendment_end = source.index(
        "\n\ndef validate_phase6_recovery_completions(", amendment_start
    )
    amendment = source[amendment_start:amendment_end]
    for condition in (
        'set(amendment) != contract["fields"]',
        'amendment_path.name != contract["amendment_name"]',
        'amendment.get("runner_code_version") != contract["runner_code_version"]',
        'amendment.get("output_policy") != contract["output_policy"]',
        'framework_lock != RECOVERY_FRAMEWORK_LOCK_ID',
        'runnote_path != control / str(contract["runnote_name"])',
        'completion.get("runnable_lanes") != expected_lanes',
        'historical.get("manifest") != descriptor(gate5_manifest)',
        'historical.get("runnote") != descriptor(gate5_runnote)',
        'historical.get("promotion") != descriptor(gate5_promotion)',
        'source_descriptor != canonical_source_descriptor',
        'project_receipt = validate_project_revision(project_receipt)',
        'validate_source_conformance_manifest(strict_object(source_path))',
        'retained_spec_path.name != retained_name',
        'retained_spec.get("lane_id") != lane',
        'retained_spec.get("approved_caps") != expected_caps',
        'row.get("selection_and_sampling_changed") is not False',
        'launch.get("controller") != completion.get("controller")',
        'launch.get("retained_executor_payload")',
        'launch.get("lane_order") != expected_lanes',
        'completion.get("amendment") != descriptor(amendment_path)',
        'completion.get("launch") != descriptor(launch_path)',
    ):
        assert condition in amendment

    recovery_start = source.index("def validate_phase6_recovery_completions(")
    recovery_end = source.index(
        "\n\ndef validate_phase6_recovery_transitions(", recovery_start
    )
    recovery = source[recovery_start:recovery_end]
    recovery_signature = recovery[:recovery.index(") -> dict[str, Any]:")]
    assert "gate5_runnote: Path," in recovery_signature
    assert "gate5_promotion: Path," in recovery_signature
    assert "project_and_source: Mapping[str, Any]," in recovery_signature
    assert "= None" not in recovery_signature
    for condition in (
        'summary.get("schema") != recovery_contract["summary_schema"]',
        'spec.get("approved_caps") != amendment_row["approved_caps"]',
        '_recovery_request_identity(spec, lane=lane)',
        '_recovery_request_identity(retained_spec, lane=lane)',
        'if not isinstance(spec.get("gate5"), dict)',
        'and spec_gate5 is not None',
        'and not isinstance(spec_gate5, dict)',
        'target_cap != amendment_row["approved_caps"]["target_calls"]',
    ):
        assert condition in recovery
    assert "gate5_runnote=gate5_runnote" in recovery
    assert "gate5_promotion=gate5_promotion" in recovery
    assert "project_and_source=project_and_source" in recovery


def test_recovery_producers_are_allowlisted_and_templates_compile() -> None:
    specs = {spec.output: spec for spec in CONTROLLERS}
    assert len(CONTROLLERS) == 30
    assert specs["phase6_core_length_recovery.py"].self_test == "none"
    assert specs["phase6_seven_output_policy.py"].self_test == "none"
    assert specs["launch_phase6_recovery_and_seven.sh"].self_test == "recovery-sequence"
    assert external_binding_keys_from_templates() == EXTERNAL_BINDINGS

    replacements = {
        "PROJECT_ROOT": "/mnt/project",
        "WORK_ROOT": "/mnt/work",
        "EXPECTED_COMMIT": "a" * 40,
        "COMMIT_SHORT": "a" * 7,
        "PHASE6_RECOVERY_INPUTS_PATH": "/mnt/core-inputs.json",
        "PHASE6_RECOVERY_INPUTS_SHA256": "b" * 64,
        "PHASE6_RECOVERY_INPUTS_BYTES": "1",
        "PHASE6_RECOVERY_TAG": "20260828T120000Z",
        "SEVEN_POLICY_INPUTS_PATH": "/mnt/seven-inputs.json",
        "SEVEN_POLICY_INPUTS_SHA256": "c" * 64,
        "SEVEN_POLICY_INPUTS_BYTES": "1",
        "SEVEN_POLICY_TAG": "20260828T130000Z",
    }
    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    for path in (CORE, SEVEN):
        rendered = token.sub(lambda match: replacements[match.group(1)], _source(path))
        assert "@@" not in rendered
        compile(rendered, str(path), "exec")


def test_recovery_binding_migration_is_exact_and_create_only() -> None:
    assert RECOVERY_BINDINGS_ADDED_AFTER_73C5331 == {
        "PHASE6_RECOVERY_INPUTS_BYTES",
        "PHASE6_RECOVERY_INPUTS_PATH",
        "PHASE6_RECOVERY_INPUTS_SHA256",
        "PHASE6_RECOVERY_TAG",
        "SEVEN_POLICY_INPUTS_BYTES",
        "SEVEN_POLICY_INPUTS_PATH",
        "SEVEN_POLICY_INPUTS_SHA256",
        "SEVEN_POLICY_TAG",
    }
    assert PRE_RECOVERY_EXTERNAL_BINDINGS == (
        EXTERNAL_BINDINGS - RECOVERY_BINDINGS_ADDED_AFTER_73C5331
    )
    for source in (_source(CORE), _source(SEVEN)):
        assert "os.O_EXCL" in source
        assert "WORK_ROOT = Path(\"@@WORK_ROOT@@\")" in source
        assert "/home/ura" not in source
        assert source.count(PRIOR_RECOVERY_EXPECTED_COMMIT) == 1


def test_core_recovery_contract_and_cap_mutation() -> None:
    source = _source(CORE)
    _assert_core_contract(source)
    mutant = source.replace(
        '"local-qwen3-vl-text-primary-100": 3854,',
        '"local-qwen3-vl-text-primary-100": 3855,',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(mutant)

    sampling_mutant = source.replace(
        'option_value(argv, "--sample-seed") != "0"',
        'option_value(argv, "--sample-seed") != "1"',
        1,
    )
    assert sampling_mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(sampling_mutant)

    policy_mutant = source.replace(
        '            or "--sampling-policy" in argv\n', "", 1
    )
    assert policy_mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(policy_mutant)

    main_mutant = source.replace(
        "    validate_specs_contract(module, specs)\n", "", 1
    )
    assert main_mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(main_mutant)

    completion_mutant = source.replace(
        'completion_file != attempt / "completion.json"',
        'completion_file == attempt / "completion.json"',
        1,
    )
    assert completion_mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(completion_mutant)

    control_mutant = source.replace(
        "recovery_control is not None and control != recovery_control",
        "recovery_control is not None and control == recovery_control",
        1,
    )
    assert control_mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(control_mutant)

    current_commit_mutant = source.replace(
        PRIOR_RECOVERY_EXPECTED_COMMIT,
        "c" * 40,
        1,
    )
    assert current_commit_mutant != source
    with pytest.raises(AssertionError):
        _assert_core_contract(current_commit_mutant)


def test_seven_row_contract_and_terminal_profile_mutation() -> None:
    source = _source(SEVEN)
    _assert_seven_contract(source)
    mutant = source.replace(
        '"target_runtime_terminal": 7 - len(ready)',
        '"target_runtime_terminal": 3 - len(ready)',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(mutant)

    historical_mutant = source.replace(
        '"target_runtime_terminal": 7,',
        '"target_runtime_terminal": 3,',
        1,
    )
    assert historical_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(historical_mutant)

    sampling_mutant = source.replace(
        'option_value(argv, "--sample-seed") != "0"',
        'option_value(argv, "--sample-seed") != "1"',
        1,
    )
    assert sampling_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(sampling_mutant)

    policy_mutant = source.replace(
        '            or "--sampling-policy" in argv\n', "", 1
    )
    assert policy_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(policy_mutant)

    main_mutant = source.replace(
        "    validate_specs_contract(module, specs)\n", "", 1
    )
    assert main_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(main_mutant)

    completion_mutant = source.replace(
        'completion_file != attempt / "completion.json"',
        'completion_file == attempt / "completion.json"',
        1,
    )
    assert completion_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(completion_mutant)

    control_mutant = source.replace(
        "recovery_control is not None and control != recovery_control",
        "recovery_control is not None and control == recovery_control",
        1,
    )
    assert control_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(control_mutant)

    current_commit_mutant = source.replace(
        PRIOR_RECOVERY_EXPECTED_COMMIT,
        "c" * 40,
        1,
    )
    assert current_commit_mutant != source
    with pytest.raises(AssertionError):
        _assert_seven_contract(current_commit_mutant)


@pytest.mark.skipif(os.name == "nt", reason="producer input paths are POSIX-only")
@pytest.mark.parametrize("template", [CORE, SEVEN])
def test_bound_payload_and_directory_artifact_mutations_reject_before_use(
    tmp_path: Path, template: Path
) -> None:
    namespace = _helper_namespace(template)
    payload = tmp_path / "payload.py"
    payload.write_bytes(b"x")
    dependency = tmp_path / "dependency"
    dependency.mkdir()
    required = dependency / "required.json"
    required.write_bytes(b"a")
    manifest = {
        "schema": "test-recovery-inputs/1",
        "retained_executor_payload": _file_descriptor(payload),
        "dependency": {
            "path": dependency.resolve(strict=True).as_posix(),
            "artifacts": {"required": _file_descriptor(required)},
        },
    }
    manifest_path = tmp_path / "inputs.json"
    manifest_payload = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    manifest_path.write_bytes(manifest_payload)
    bound = namespace["_bound_inputs"]
    bound(
        source=manifest_path.resolve(strict=True),
        expected_sha256=hashlib.sha256(manifest_payload).hexdigest(),
        expected_bytes=len(manifest_payload),
        schema="test-recovery-inputs/1",
        file_fields=frozenset({"retained_executor_payload"}),
        directory_artifacts={"dependency": frozenset({"required"})},
    )

    namespace["INPUT_MANIFEST"] = manifest
    payload.write_bytes(b"y")
    with pytest.raises(ValueError, match="content identity changed"):
        namespace["_revalidate_payload_before_import"]()

    payload.write_bytes(b"x")
    required.write_bytes(b"b")
    with pytest.raises(ValueError, match="content identity changed"):
        namespace["_validated_input_value"](
            manifest,
            schema="test-recovery-inputs/1",
            file_fields=frozenset({"retained_executor_payload"}),
            directory_artifacts={"dependency": frozenset({"required"})},
        )


@pytest.mark.skipif(os.name == "nt", reason="prior artifact paths are POSIX-only")
@pytest.mark.parametrize("template", [CORE, SEVEN])
def test_prior_recovery_swapped_completion_and_control_root_reject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    template: Path,
) -> None:
    monkeypatch.setenv("URA_FRAMEWORK_LOCK_ID", "b" * 64)
    monkeypatch.setenv("URA_EXECUTION_SCOPE_ID", "bigrigsys-local-vllm")
    namespace = _prior_validator_namespace(template)
    validate = namespace["validate_prior_recovery_completion"]

    def arguments(fixture: dict[str, object]) -> dict[str, object]:
        result = {
            "attempt": fixture["attempt"],
            "exit_marker": fixture["exit_marker"],
            "completion_file": fixture["completion_file"],
            "retained_payload": fixture["retained_payload"],
        }
        if template == SEVEN:
            result["recovery_control"] = fixture["recovery_control"]
            result["recovery_lane_specs"] = fixture["recovery_lane_specs"]
        return result

    valid = _prior_recovery_fixture(tmp_path / "valid")
    validate(**arguments(valid))

    swapped_target = _prior_recovery_fixture(tmp_path / "swapped-target")
    unrelated = _prior_recovery_fixture(tmp_path / "unrelated")
    unrelated_completion = json.loads(
        Path(unrelated["completion_file"]).read_text(encoding="utf-8")
    )
    _write_json(Path(swapped_target["completion_file"]), unrelated_completion)
    with pytest.raises(ValueError, match="escapes its bound directory"):
        validate(**arguments(swapped_target))

    if template == SEVEN:
        wrong_control = (tmp_path / "wrong-base-control").resolve()
        wrong_control.mkdir()
        wrong_args = arguments(valid)
        wrong_args["recovery_control"] = wrong_control
        with pytest.raises(ValueError, match="differs from its bound base control"):
            validate(**wrong_args)

    control_mutation = _prior_recovery_fixture(tmp_path / "control-mutation")
    launch_path = Path(control_mutation["launch_path"])
    launch = json.loads(launch_path.read_text(encoding="utf-8"))
    launch["control_root"] = str((tmp_path / "foreign-control").resolve())
    _write_json(launch_path, launch)
    completion_path = Path(control_mutation["completion_file"])
    completion = json.loads(completion_path.read_text(encoding="utf-8"))
    completion["launch"] = _file_descriptor(launch_path)
    _write_json(completion_path, completion)
    with pytest.raises(ValueError, match="launch chain changed"):
        validate(**arguments(control_mutation))


@pytest.mark.parametrize("template", [CORE, SEVEN])
def test_gate5_failure_writer_exact_schema_and_reason_mutation(template: Path) -> None:
    source = _source(template)
    assertion = _assert_core_contract if template == CORE else _assert_seven_contract
    assertion(source)
    mutant = source.replace(
        '        "reason_code": "corrective_gate5_failed",\n', "", 1
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        assertion(mutant)


def test_core_qwen_image_attestation_accepts_exact_text_image_modalities() -> None:
    source = _source(CORE)
    _assert_core_attestation_modalities(source)
    mutant = source.replace(
        '["text"] if modality == "text" else ["text", "image"]',
        '["text"] if modality == "text" else ["text"]',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_core_attestation_modalities(mutant)


def test_recovery_launcher_is_opt_in_exact_tmux_serialization() -> None:
    source = _source(LAUNCHER)
    assert "tmux -L \"$SOCKET\" new-session -d -s \"$SESSION\"" in source
    assert '"$PY" "$CORE"' in source
    assert 'core_terminal_allows_seven "$core_rc"' in source
    assert '"$PY" "$SEVEN"' in source
    assert source.index('"$PY" "$CORE"') < source.index('"$PY" "$SEVEN"')
    assert 'core_exit_gates_seven":false' in source
    assert 'model_calls":0' in source
    assert "test ! -e \"$SEQUENCE_CONTROL\"" in source
    assert "launch_phase6_recovery_and_seven.sh" not in _source(
        TEMPLATES / "launch_chain.sh.in"
    )


def test_phase7_recovery_reads_each_artifact_from_its_schema_layer() -> None:
    source = _source(PHASE7)
    _assert_phase7_recovery_artifact_layers(source)

    mutant = source.replace(
        'envelope_bindings.get("project_revision")',
        'envelope_request.get("project_revision")',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_recovery_artifact_layers(mutant)


def test_phase7_consumes_the_retained_seven_lane_failure_schema() -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_failure_schema(source)

    validator_start = source.index("def current_phase6_failure_record(")
    mutant = source[:validator_start] + source[validator_start:].replace(
        'not isinstance(failure.get("error"), str)',
        'not isinstance(failure.get("reason"), str)',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_seven_failure_schema(mutant)


def test_phase7_separates_policy_and_completed_gate5_amendment_digests() -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_gate5_layers(source)

    mutant = source.replace(
        'amendment_gate5.get("manifest_sha256") != policy_sha',
        'amendment_gate5.get("manifest_sha256") != amendment_sha',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_seven_gate5_layers(mutant)

    historical_start = source.index("expected_historical_profile = {")
    historical_end = source.index("expected_all_pass_profile = {", historical_start)
    profile_mutant = (
        source[:historical_start]
        + source[historical_start:historical_end].replace(
            '"target_runtime_terminal": 7',
            '"target_runtime_terminal": 3',
            1,
        )
        + source[historical_end:]
    )
    assert profile_mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_seven_gate5_layers(profile_mutant)


@pytest.mark.parametrize(
    "condition",
    (
        "set(policy) != policy_fields",
        'policy.get("status") != "approved_for_targeted_readmission"',
        'policy.get("output_policy") != expected_output_policy',
        '"4 passed" not in focused_tests_text',
        '"2 failed" not in mutation_tests_text',
        'historical_gate5.get("runnote") != descriptor(gate5_runnote)',
        "set(row) != policy_row_fields",
        'row.get("approved_caps") != expected_caps',
        "set(launch) != launch_fields",
        'launch.get("execution_scope_id") != "bigrigsys-local-vllm"',
        'launch.get("amendment") != descriptor(policy_file)',
        'launch.get("lane_order") != list(SEVEN_AMENDMENT_LANES)',
        'completion.get("amendment") != descriptor(amendment_file)',
        'completion.get("launch") != descriptor(launch_path)',
        'set(states) != set(SEVEN_AMENDMENT_LANES)',
    ),
)
def test_phase7_seven_policy_and_launch_chain_mutations(condition: str) -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_policy_launch_chain(source)
    start = source.index("def validate_seven_output_policy_inventory(")
    end = source.index("\n\ndef ", start + 5)
    validator = source[start:end]
    assert condition in validator
    mutant_validator = validator.replace(condition, condition + "_mutated", 1)
    mutant = source[:start] + mutant_validator + source[end:]
    with pytest.raises(AssertionError):
        _assert_phase7_seven_policy_launch_chain(mutant)


def test_phase7_seven_completion_does_not_bind_the_policy_descriptor() -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_policy_launch_chain(source)
    start = source.index("def validate_seven_output_policy_inventory(")
    end = source.index("\n\ndef ", start + 5)
    validator = source[start:end]
    mutant_validator = validator.replace(
        'completion.get("amendment") != descriptor(amendment_file)',
        'completion.get("amendment") != descriptor(policy_file)',
        1,
    )
    assert mutant_validator != validator
    mutant = source[:start] + mutant_validator + source[end:]
    with pytest.raises(AssertionError):
        _assert_phase7_seven_policy_launch_chain(mutant)


def test_phase7_seven_provenance_parameters_are_required() -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_policy_launch_chain(source)
    start = source.index("def validate_seven_output_policy_inventory(")
    end = source.index("\n\ndef ", start + 5)
    validator = source[start:end]
    mutant_validator = validator.replace(
        "gate5_promotion: Path,",
        "gate5_promotion: Path | None = None,",
        1,
    )
    assert mutant_validator != validator
    mutant = source[:start] + mutant_validator + source[end:]
    with pytest.raises(AssertionError):
        _assert_phase7_seven_policy_launch_chain(mutant)


@pytest.mark.parametrize(
    ("call_marker", "condition"),
    (
        (
            "seven = validate_seven_output_policy_inventory(",
            "gate5_runnote=gate5_runnote",
        ),
        (
            "seven = validate_seven_output_policy_inventory(",
            "project_and_source=project_and_source",
        ),
        (
            "validated_seven = validate_seven_output_policy_inventory(",
            "gate5_promotion=gate5_promotion_path",
        ),
        (
            "validated_seven = validate_seven_output_policy_inventory(",
            "project_and_source=validated_project_and_source",
        ),
    ),
)
def test_phase7_seven_policy_provenance_call_mutations(
    call_marker: str, condition: str
) -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_policy_launch_chain(source)
    start = source.index(call_marker)
    indent = "\n        )" if call_marker.startswith("validated_") else "\n    )"
    end = source.index(indent, start) + len(indent)
    call = source[start:end]
    assert condition in call
    mutant_call = call.replace(condition, condition + "_mutated", 1)
    mutant = source[:start] + mutant_call + source[end:]
    with pytest.raises(AssertionError):
        _assert_phase7_seven_policy_launch_chain(mutant)


@pytest.mark.parametrize(
    "condition",
    (
        'request.get("models") != [model_selector]',
        'request.get("corpora") != contract["corpora"]',
        'request.get("limit") != expected_limit',
        'request.get("global_call_budget")',
    ),
)
def test_phase7_seven_measured_request_contract_mutations(condition: str) -> None:
    source = _source(PHASE7)
    _assert_phase7_seven_measured_request_contract(source)
    mutant = source.replace(condition, condition + "_mutated", 1)
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_seven_measured_request_contract(mutant)

    call_mutant = source.replace(
        "validate_seven_lane_spec(lane, spec)",
        "pass  # mutated exact seven-lane contract",
        1,
    )
    assert call_mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_seven_measured_request_contract(call_mutant)

    summary_mutant = source.replace(
        'summary.get("failures") != inline_failures',
        'summary.get("failures") != []',
        1,
    )
    assert summary_mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_seven_measured_request_contract(summary_mutant)


@pytest.mark.parametrize(
    "condition",
    (
        'set(amendment) != contract["fields"]',
        'amendment_path.name != contract["amendment_name"]',
        'amendment.get("output_policy") != contract["output_policy"]',
        'framework_lock != RECOVERY_FRAMEWORK_LOCK_ID',
        'historical.get("runnote") != descriptor(gate5_runnote)',
        'source_descriptor != canonical_source_descriptor',
        'retained_spec_path.name != retained_name',
        'completion.get("runnable_lanes") != expected_lanes',
        'launch.get("lane_order") != expected_lanes',
        'spec.get("approved_caps") != amendment_row["approved_caps"]',
        'if not isinstance(spec.get("gate5"), dict)',
        'and spec_gate5 is not None',
        'and not isinstance(spec_gate5, dict)',
        'target_cap != amendment_row["approved_caps"]["target_calls"]',
        'prior.get("framework_lock_id") != RECOVERY_FRAMEWORK_LOCK_ID',
        'prior_launch.get("amendment") != descriptor(prior_amendment_path)',
        "set(prior) != prior_completion_fields",
        'result.get("target_call_cap")\n                != row["approved_caps"]["target_calls"]',
    ),
)
def test_phase7_recovery_amendment_exact_contract_mutations(condition: str) -> None:
    source = _source(PHASE7)
    _assert_phase7_recovery_amendment_contract(source)
    mutant = source.replace(condition, condition + "_mutated", 1)
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_recovery_amendment_contract(mutant)


def test_phase7_recovery_rejects_new_sampling_policy_binding() -> None:
    source = _source(PHASE7)
    _assert_phase7_recovery_amendment_contract(source)
    mutant = source.replace('or "--sampling-policy" in argv', "or False", 1)
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_recovery_amendment_contract(mutant)


def test_phase7_recovery_provenance_parameters_are_required() -> None:
    source = _source(PHASE7)
    _assert_phase7_recovery_amendment_contract(source)
    start = source.index("def validate_phase6_recovery_completions(")
    end = source.index("\n\ndef validate_phase6_recovery_transitions(", start)
    validator = source[start:end]
    mutant_validator = validator.replace(
        "gate5_runnote: Path,",
        "gate5_runnote: Path | None = None,",
        1,
    )
    assert mutant_validator != validator
    mutant = source[:start] + mutant_validator + source[end:]
    with pytest.raises(AssertionError):
        _assert_phase7_recovery_amendment_contract(mutant)


def test_phase7_recovery_supports_both_model_output_revisions() -> None:
    source = _source(PHASE7)
    _assert_phase7_recovery_amendment_contract(source)
    mutant = source.replace(
        '"ura-local-campaign-model-output-amendment/1", "ura-runner/2.24"',
        '"ura-local-campaign-model-output-amendment/1", "ura-runner/2.25"',
        1,
    )
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_recovery_amendment_contract(mutant)


@pytest.mark.parametrize(
    ("original", "replacement"),
    (
        (
            '("rjudge-ollama-rwkv-g1d-0p4b", 50)',
            '("rjudge-ollama-rwkv-g1d-0p4b", 51)',
        ),
        (
            '("local-qwen3-vl-text-primary-100", 3854)',
            '("local-qwen3-vl-text-primary-100", 3855)',
        ),
    ),
)
def test_phase7_recovery_amendment_cap_mutations(
    original: str, replacement: str
) -> None:
    source = _source(PHASE7)
    _assert_phase7_recovery_amendment_contract(source)
    mutant = source.replace(original, replacement, 1)
    assert mutant != source
    with pytest.raises(AssertionError):
        _assert_phase7_recovery_amendment_contract(mutant)
