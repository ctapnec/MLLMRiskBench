from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    CONTROLLERS,
    ControllerGenerationError,
    DERIVED_BINDINGS,
    SUPPORT_TEMPLATES,
    package_controller_set,
    render_controller_set,
    verify_controller_set,
)
from experiments.local_campaign.rebind import main as rebind_main


def _template_tokens() -> set[str]:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    import re

    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    return {
        match
        for spec in CONTROLLERS
        for match in token.findall((root / spec.template).read_text(encoding="utf-8"))
    } - DERIVED_BINDINGS


def _bindings(path: Path, commit: str = "1" * 40) -> Path:
    values = {name: f"value-{name.lower()}" for name in _template_tokens()}
    values["EXPECTED_COMMIT"] = commit
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
    path.write_text(json.dumps({"schema": BINDINGS_SCHEMA, "values": values}), encoding="utf-8")
    return path


def test_all_controller_implementations_are_versioned() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    expected = {spec.template for spec in CONTROLLERS}
    assert len(CONTROLLERS) == 24
    assert {path.name for path in root.glob("*.in")} == expected | SUPPORT_TEMPLATES
    assert "phase6_native_diagnostics.sh.in" in expected
    assert "phase6_native_measured.sh.in" not in expected
    assert {spec.output for spec in CONTROLLERS} >= {"phase6_native_diagnostics.sh"}
    assert "phase6_native_measured.sh" not in {spec.output for spec in CONTROLLERS}
    for spec in CONTROLLERS:
        source = (root / spec.template).read_text(encoding="utf-8")
        if "EXPECTED_COMMIT" in source:
            assert "@@EXPECTED_COMMIT@@" in source


def test_controller_templates_are_repository_normalized_to_lf() -> None:
    project_root = Path(__file__).parents[2]
    templates = sorted(
        (project_root / "experiments" / "local_campaign" / "templates").glob("*.in")
    )
    assert templates
    result = subprocess.run(
        [
            "git",
            "-C",
            str(project_root),
            "check-attr",
            "text",
            "eol",
            "--",
            *[path.relative_to(project_root).as_posix() for path in templates],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    rows = result.stdout.splitlines()
    assert len(rows) == len(templates) * 2
    for path in templates:
        relative = path.relative_to(project_root).as_posix()
        assert f"{relative}: text: set" in rows
        assert f"{relative}: eol: lf" in rows
        payload = path.read_bytes()
        assert payload.endswith(b"\n")
        assert b"\r" not in payload


def test_phase3_uses_one_exact_bound_create_only_tag(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    phase3 = (output / "phase3_guard1b_acquire_fit.sh").read_text(
        encoding="utf-8"
    )
    launch_chain = (output / "launch_chain_1111111.sh").read_text(
        encoding="utf-8"
    )
    assert "readonly BOUND_TAG='20260822T120000Z'" in phase3
    assert 'tag="$BOUND_TAG"' in phase3
    assert 'tag="$(date' not in phase3
    assert 'validate_bound_tag "${BOUND_TAG%?}0"' in phase3
    assert "phase3-guard1b-acquire-fit-20260822T120000Z" in launch_chain
    assert "phase3-guard1b-20260822T120000Z" in launch_chain
    assert "guard1b-fit-20260822T120000Z" in launch_chain

    malformed = json.loads(bindings.read_text(encoding="utf-8"))
    malformed["values"]["PHASE3_GUARD_TAG"] = "20260822-120000Z"
    invalid = tmp_path / "invalid-bindings.json"
    invalid.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(ControllerGenerationError, match="UTC campaign tag"):
        render_controller_set(invalid, tmp_path / "invalid-workspace")


def test_native_diagnostics_distinguish_importer_from_canonical_engine() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_native_diagnostics.sh.in"
    ).read_text(encoding="utf-8")
    assert "from experiments.native_import import canonical_native_engine_ids" in source
    assert 'native_run.get("engine") not in canonical_native_engine_ids(engine)' in source
    assert 'native_import.get("native_engine") not in canonical_native_engine_ids(engine)' in source


def test_gptgeochat_rwkv_cross_products_are_exact_typed_terminals() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    lanes = (
        "gptgeochat-ollama-rwkv-g1d-0p4b",
        "gptgeochat-ollama-rwkv-g1f-2p9b",
        "gptgeochat-ollama-rwkv-g1g-1p5b",
    )
    semantic_templates = (
        "phase5_finalize_gate5.sh.in",
        "phase5_promote_gate5.sh.in",
        "phase5_ollama_workflow.sh.in",
        "phase6_core_measured.sh.in",
        "phase6_extended_measured.sh.in",
        "phase6_native_diagnostics.sh.in",
        "phase7_analysis.py.in",
        "phase8_human_audit.py.in",
    )
    for name in semantic_templates:
        source = (root / name).read_text(encoding="utf-8")
        assert "target_transport_text_only_for_image_source" in source
        if name == "phase5_promote_gate5.sh.in":
            assert '"lane_id": f"gptgeochat-ollama-{model}"' in source
            assert (
                'for model in ("rwkv-g1d-0p4b", "rwkv-g1f-2p9b", '
                '"rwkv-g1g-1p5b")'
            ) in source
        else:
            for lane in lanes:
                assert lane in source

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in root.glob("*.in")
    )
    assert '"total": 43' not in combined
    assert '"total": 46' in combined
    assert '(26, 17, [])' not in combined
    assert '(25, 18, ["defense-local"])' not in combined


def test_phase7_splits_lifecycle_from_success_only_metric_views() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    assert '"metric_lane_order"' in source
    assert '"lifecycle_lane_order"' in source
    assert '"lifecycle_authorizations"' in source
    assert '"lifecycle_registry_status"' in source
    assert '"level1_tool_input_status"' in source
    assert '"runner_request_envelopes"' in source
    assert '"runner_error_artifacts"' in source
    assert '"runner_lifecycle_authorizations"' in source
    assert '"lifecycle_registry_states"' in source
    assert '"level1_includes_complete_partial_failed_runner_lifecycle"' not in source
    assert '"failed_runner_artifacts"' in source
    assert '"metric_eligibility_plans"' in source
    assert '"lifecycle_eligibility_plans"' in source
    assert "require_lifecycle_metric_partition(" in source
    level1 = source[source.index("    def run_level1("):source.index("    def run_suite_summary(")]
    suite = source[source.index("    def run_suite_summary("):source.index("    def run_level2(")]
    level2 = source[source.index("    def run_level2("):source.index("    def run_judge_sensitivity(")]
    assert "self.lifecycle_runner_view()" in level1
    assert "self.eligibility_args(lifecycle=True)" in level1
    assert "self.analysis_runner_view()" in suite
    assert "self.eligibility_args(lifecycle=False)" in suite
    assert "self.analysis_runner_view()" in level2
    assert "failed_phase6_lanes_excluded_from_analysis" not in source


def test_rendered_phase7_lifecycle_partition_mutations_fail(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    result = subprocess.run(
        [sys.executable, str(output / "phase7_analysis.py"), "contract-self-test"],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(result.stdout)
    assert value["status"] == "passed"
    assert "phase7-lifecycle-vs-metric-partition" in value["contracts"]
    assert "phase7-lifecycle-authorization-cases" in value["contracts"]


def test_render_is_commit_bound_and_workspace_drift_fails(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    record = render_controller_set(bindings, output)
    assert record["expected_commit"] == "1" * 40
    assert (output / "launch_chain_1111111.sh").is_file()
    verify_controller_set(bindings, output)
    inventory_names = [
        line.split("\t", 1)[0]
        for line in (output / "controller_inventory_1111111.tsv")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert inventory_names == [
        spec.output.format(commit_short="1111111") for spec in CONTROLLERS
    ]

    changed = output / "phase5_core_projections.sh"
    changed.write_bytes(changed.read_bytes() + b"# workspace-only edit\n")
    with pytest.raises(ControllerGenerationError, match="diverges"):
        verify_controller_set(bindings, output)

    render_controller_set(bindings, output)
    inventory = output / "controller_inventory_1111111.tsv"
    inventory.write_bytes(
        inventory.read_bytes()
        + b"workspace_only.sh\t1\t"
        + b"0" * 64
        + b"\tnone\n"
    )
    with pytest.raises(ControllerGenerationError, match="diverges"):
        verify_controller_set(bindings, output)


def test_a_new_commit_is_a_binding_not_a_source_edit(tmp_path: Path) -> None:
    first = _bindings(tmp_path / "first.json", "1" * 40)
    second = _bindings(tmp_path / "second.json", "3" * 40)
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"
    render_controller_set(first, first_output)
    render_controller_set(second, second_output)
    first_bytes = (first_output / "phase7_analysis.py").read_bytes()
    second_bytes = (second_output / "phase7_analysis.py").read_bytes()
    assert b"1" * 40 in first_bytes
    assert b"3" * 40 in second_bytes
    assert first_bytes != second_bytes


def test_phase6_gate5_launch_identity_uses_the_rendered_commit(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path / "bindings.json", "3" * 40)
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    phase6 = (output / "phase6_sequence.sh").read_text(encoding="utf-8")

    expected_identity = "ura-gate5-after-phase5-3333333"
    assert f"GATE5_SESSION='{expected_identity}'" in phase6
    assert f"GATE5_SOCKET='{expected_identity}'" in phase6
    assert phase6.count('"session": gate5_session') == 2
    assert phase6.count('"socket": gate5_socket') == 2
    assert '"$AUTHORIZED_SEQUENCE_SHA256" "$GATE5_SESSION" "$GATE5_SOCKET"' in phase6
    assert "ura-gate5-after-phase5-a0ce1f9" not in phase6


def test_phase7_completion_identity_uses_the_rendered_payload(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path / "bindings.json", "3" * 40)
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    watcher = (output / "phase7_after_phase6_sequence.sh").read_text(
        encoding="utf-8"
    )
    payload_sha = hashlib.sha256(
        (output / "phase7_analysis.py").read_bytes()
    ).hexdigest()

    assert f"PAYLOAD_SHA256='{payload_sha}'" in watcher
    assert '"$EXPECTED_FRAMEWORK_LOCK" "$PAYLOAD_SHA256"' in watcher
    assert 'completion["payload"]["sha256"] != payload_sha' in watcher
    assert (
        "4ef7105dcc92cbaa2c3f3fe67b03ca631894c87afd1cce80ca4d1c57fbc2c57e"
        not in watcher
    )


def test_phase7_watcher_cross_checks_phase6_inventory_profiles() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_after_phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")
    begin = "# BEGIN_PHASE6_COMPLETION_PROFILE_CONTRACT\n"
    end = "# END_PHASE6_COMPLETION_PROFILE_CONTRACT\n"
    contract = template.split(begin, 1)[1].split(end, 1)[0]
    namespace: dict[str, object] = {}
    exec(compile(contract, "<phase6-completion-profile>", "exec"), namespace)

    self_test = namespace["phase6_inventory_profile_self_test"]
    assert callable(self_test)
    self_test()
    require_profile = namespace["require_phase6_inventory_profile"]
    candidate_lanes = namespace["CORE_CANDIDATE_LANES"]
    assert callable(require_profile)
    assert isinstance(candidate_lanes, set)
    complete = {lane: "measured_complete" for lane in candidate_lanes}
    conditional = {
        lane: "measured_complete"
        for lane in candidate_lanes
        if lane != "defense-local"
    }

    assert require_profile(
        {
            "runnable_lanes": 26,
            "typed_terminal_lanes": 20,
            "conditional_na_lanes": [],
        },
        sequence_conditional=[],
        core_states=complete,
        label="test-success",
    ) == (26, 20, [])
    assert require_profile(
        {
            "runnable_lanes": 25,
            "typed_terminal_lanes": 21,
            "conditional_na_lanes": ["defense-local"],
        },
        sequence_conditional=["defense-local"],
        core_states=conditional,
        label="test-conditional",
    ) == (25, 21, ["defense-local"])
    with pytest.raises(SystemExit, match="conditional and core inventories differ"):
        require_profile(
            {
                "runnable_lanes": 25,
                "typed_terminal_lanes": 21,
                "conditional_na_lanes": ["defense-local"],
            },
            sequence_conditional=[],
            core_states=conditional,
            label="test-mismatch",
        )

    completion_fields = template.split(
        "value = strict_json_loads(completion_path.read_bytes())", 1
    )[1].split("if (", 1)[0]
    assert '"conditional_na_lanes",' in completion_fields
    assert "gate5_descriptor_fields | gate5_profile_fields" in template
    assert "for field in sorted(gate5_descriptor_fields)" in template
    assert 'sequence_conditional=value.get("conditional_na_lanes")' in template
    assert 'core_states=inventories.get("core")' in template


def test_phase7_watcher_cross_checks_preparation_metric_profiles() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_after_phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")
    begin = "# BEGIN_PHASE7_PREPARATION_PROFILE_CONTRACT\n"
    end = "# END_PHASE7_PREPARATION_PROFILE_CONTRACT\n"
    contract = template.split(begin, 1)[1].split(end, 1)[0]
    namespace: dict[str, object] = {}
    exec(compile(contract, "<phase7-preparation-profile>", "exec"), namespace)
    require_profile = namespace["require_preparation_profile"]
    assert callable(require_profile)

    def profile(
        runnable: int, terminal: int, conditional: list[str]
    ) -> tuple[dict[str, object], dict[str, object]]:
        lifecycle = [f"lane-{index}" for index in range(runnable)]
        if conditional:
            assert conditional == ["defense-local"]
        else:
            lifecycle[-1] = "defense-local"
        states = {lane: "measured_complete" for lane in lifecycle}
        states[lifecycle[0]] = "failed"
        measured = lifecycle[1:]
        result = {
            "runner_lanes": runnable,
            "metric_runner_lanes": len(measured),
        }
        manifest = {
            "gate5": {
                "lane_count": 46,
                "runnable_lane_count": runnable,
                "terminal_lane_count": terminal,
                "conditional_na_lanes": conditional,
            },
            "phase6": {"runner_lane_count": runnable},
            "runner": {
                "lifecycle_lane_order": lifecycle,
                "metric_lane_order": measured,
                "terminal_states": states,
                "conditional_na_lanes": conditional,
            },
        }
        return result, manifest

    success_result, success_manifest = profile(26, 20, [])
    assert require_profile(
        success_result, success_manifest, label="test-success"
    )[:3] == (26, 20, [])
    conditional_result, conditional_manifest = profile(
        25, 21, ["defense-local"]
    )
    assert require_profile(
        conditional_result, conditional_manifest, label="test-conditional"
    )[:3] == (25, 21, ["defense-local"])

    stale_runner_count = {**conditional_result, "runner_lanes": 26}
    with pytest.raises(SystemExit, match="metric lanes differ"):
        require_profile(
            stale_runner_count, conditional_manifest, label="test-stale-count"
        )
    stale_metric_count = {
        **conditional_result,
        "metric_runner_lanes": conditional_result["metric_runner_lanes"] + 1,
    }
    with pytest.raises(SystemExit, match="metric lanes differ"):
        require_profile(
            stale_metric_count, conditional_manifest, label="test-stale-metric"
        )

    preparation_fields = template.split(
        "result = strict_json_loads(result_path.read_bytes())", 1
    )[1].split("payload = input_path.read_bytes()", 1)[0]
    assert '"metric_runner_lanes",' in preparation_fields
    assert 'result.get("runner_lanes") != runnable' in template
    assert 'result.get("metric_runner_lanes") != len(measured)' in template
    assert 'result.get("runner_lanes") != 26' not in template


def test_packager_and_installer_are_versioned_and_reproducible(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    first = tmp_path / "first"
    second = tmp_path / "second"
    render_controller_set(bindings, first)
    render_controller_set(bindings, second)
    one = package_controller_set(bindings, first)
    two = package_controller_set(bindings, second)
    assert one["archive"] == two["archive"]
    assert (first / "verify_controllers_1111111.sh").is_file()
    assert (first / "install_controller_set_1111111.sh").is_file()
    verifier = (first / "verify_controllers_1111111.sh").read_text(
        encoding="utf-8"
    )
    assert 'PYTHON="$PROJECT_PY" bash "$path" --self-test' in verifier
    assert "PYTHON_FOR_SELF_TEST" not in verifier
    assert (first / "controller-set-1111111.tar").read_bytes() == (
        second / "controller-set-1111111.tar"
    ).read_bytes()

    changed = first / "phase6_sequence.sh"
    changed.write_bytes(changed.read_bytes() + b"# local divergence\n")
    with pytest.raises(ControllerGenerationError, match="diverges"):
        package_controller_set(bindings, first)


def test_rebind_is_create_only_and_validates_named_changes(tmp_path: Path) -> None:
    base = _bindings(tmp_path / "base.json")
    output = tmp_path / "next.json"
    assert rebind_main([
        "--base", str(base),
        "--out", str(output),
        "--expected-commit", "4" * 40,
        "--phase5-sequence-tag", "20260823T120000Z",
    ]) == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["values"]["EXPECTED_COMMIT"] == "4" * 40
    assert document["values"]["PHASE5_SEQUENCE_TAG"] == "20260823T120000Z"
    with pytest.raises(SystemExit, match="already exists"):
        rebind_main([
            "--base", str(base),
            "--out", str(output),
            "--expected-commit", "5" * 40,
        ])
