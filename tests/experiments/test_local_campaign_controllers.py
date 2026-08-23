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
    assert len(CONTROLLERS) == 25
    assert {path.name for path in root.glob("*.in")} == expected | SUPPORT_TEMPLATES
    assert "phase6_native_diagnostics.sh.in" in expected
    assert "phase8_human_audit.README.md.in" in expected
    assert "phase6_native_measured.sh.in" not in expected
    assert {spec.output for spec in CONTROLLERS} >= {
        "phase6_native_diagnostics.sh",
        "phase8_human_audit.README.md",
    }
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


def test_phase8_operator_readme_is_rendered_and_current(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    readme = (output / "phase8_human_audit.README.md").read_text(
        encoding="ascii"
    )
    assert "`1111111111111111111111111111111111111111`" in readme
    assert "46 lanes: 22 runnable and 24 typed terminal" in readme
    assert "21 runnable and 25 typed terminal" in readme
    assert "C >= N + 20" in readme
    assert "S >= M" in readme
    assert "human_only_blocked" in readme
    assert "gate8_met: false" in readme
    assert "43 total lanes" not in readme
    assert "8461790bb3e2fe75589c0cd547857406442a0c99" not in readme


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
    assert "eligibility_payload = checked_bytes(" in launch_chain
    assert '"records": sum(' in launch_chain
    assert '"records": 442' not in launch_chain
    assert "json.loads(eligibility_payload)" in launch_chain
    assert "json.loads(projection_payload)" in launch_chain
    assert "json.loads(envelope_payload)" in launch_chain

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
    assert "phase7-conditional-analysis-prerequisites" in value["contracts"]
    assert "phase7-adaptivity-non-estimable-contrasts" in value["contracts"]
    assert "phase7-transfer-faceted-index" in value["contracts"]
    assert "phase7-runner-view-content-binding" in value["contracts"]


def test_phase7_conditional_analyses_branch_before_subprocesses() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    method_bounds = (
        ("run_judge_sensitivity", "run_kappa", "judge-sensitivity"),
        ("run_kappa", "run_transfer", "kappa"),
        ("run_transfer", "_validate_paired", "transfer-matrix"),
    )
    for method, next_method, analysis in method_bounds:
        start = source.index(f"    def {method}(")
        end = source.index(f"    def {next_method}(", start)
        body = source[start:end]
        plan = body.index("conditional_analysis_plan(")
        dispatch = body.index("self.run(")
        assert plan < dispatch
        assert f'"{analysis}"' in body[:dispatch]
        assert "_emit_non_estimable_analysis(" in body[:dispatch]
        defense = body.index('"--defense"')
        assert defense < dispatch
        assert '"none"' in body[defense:dispatch]
        if analysis == "kappa":
            assert '"--output"' in body[:dispatch]
        if analysis == "transfer-matrix":
            assert '"--output-dir"' in body[:dispatch]

    start = source.index("    def run_adaptivity_pairs(")
    end = source.index("    def record_native_outcomes(", start)
    adaptivity = source[start:end]
    plan = adaptivity.index("adaptivity_prerequisite_plan(")
    qwen = adaptivity.index('self.inputs["runner"]["model_selectors"]')
    dispatch = adaptivity.index("self.run(")
    assert plan < qwen < dispatch
    assert "non_estimable_adaptivity_value(" in adaptivity[plan:qwen]
    assert "return results" in adaptivity[plan:qwen]


def test_phase7_rr_runtime_terminal_never_invokes_paired_compare() -> None:
    import re

    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    start = source.index("    def run_llava_pairs(")
    end = source.index("    def run_adaptivity_pairs(", start)
    rr_contrast = source[start:end]
    image_start = source.index("IMAGE_ARMS = (")
    image_end = source.index("ADAPTIVE_ARMS = (", image_start)
    image_arms = re.findall(r'"([a-z0-9_]+)"', source[image_start:image_end])
    assert len(image_arms) == 12
    assert len(set(image_arms)) == 12
    assert "ura-phase7-non-estimable-contrast/1" in source
    assert '"paired_compare_invoked": False' in rr_contrast
    assert '"estimate": None' in rr_contrast
    assert '"modality": "image"' in rr_contrast
    assert "for corpus in IMAGE_ARMS:" in rr_contrast
    assert "experiments.paired_compare" not in rr_contrast
    assert "self.run(" not in rr_contrast
    selector_start = source.index('"model_selectors": {')
    selector_end = source.index('"guardrail_selector":', selector_start)
    assert '"llava_rr"' not in source[selector_start:selector_end]
    assert "RR_TARGET_IDENTITY_MARKERS" in source
    assert 'project_root / "experiments" / "local-llava-rr.json"' in source
    assert "RR_LOCAL_CONFIG_SHA256" in source
    assert "RR_OBSERVED_PROJECT_COMMIT" in source
    assert '"diff",' in source
    gate5_start = source.index("def validate_gate5(")
    gate5_end = source.index("def validate_exact_source_portfolio(", gate5_start)
    assert "validate_rr_runtime_project_continuity(" in source[gate5_start:gate5_end]
    assert '"10-defense-local.json"' in source
    assert '"14-defense-local.json"' not in source
    assert 'set(projection) != {"path", "file", "sha256", "bytes"}' in source
    assert (
        '{"path", "envelope_id", "file", "sha256", "bytes"}' in source
    )
    assert 'set(eligibility) != {"path", "sha256", "bytes"}' in source
    assert 'eligibility.get("bindings", {}).get("request_envelope_sha256")' in source
    assert '"records": eligibility_records' in source
    assert "projection-file-mismatch" in source
    assert "request-envelope-id-mismatch" in source
    assert "candidate.lstat()" in source
    assert "not stat.S_ISREG(entry.st_mode)" in source
    assert "evidence member changed while reading" in source
    assert 'getattr(os, "O_NOFOLLOW", 0)' in source
    assert "members_after != members_before" in source
    assert "evidence root changed while reading" in source


def test_rendered_phase8_rr_terminal_mutations_fail(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    result = subprocess.run(
        [sys.executable, str(output / "phase8_human_audit.py"), "--self-test"],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(result.stdout)
    assert value["status"] == "passed"
    assert value["gate5_inventory_profiles"] == [
        "46/22/24 with four RR runtime terminals and defense-local runnable",
        "46/21/25 with four RR runtime terminals and defense-local conditional N/A",
    ]


def test_phase8_rejects_rr_human_samples_and_metric_inputs() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase8_human_audit.py.in"
    ).read_text(encoding="utf-8")
    assert "def _reject_rr_human_row(" in source
    assert '_reject_rr_human_row(row, label="common sample")' in source
    assert '_reject_rr_human_row(row, label="source-task sample")' in source
    assert 'or RR_RUNTIME_TERMINAL_LANE_SET & set(specs)' in source
    assert "for marker in RR_TARGET_IDENTITY_MARKERS" in source
    assert 'project_root / "experiments" / "local-llava-rr.json"' in source
    assert "RR_LOCAL_CONFIG_SHA256" in source
    assert "RR_OBSERVED_PROJECT_COMMIT" in source
    gate5_start = source.index("def validate_gate5(")
    gate5_end = source.index("def validate_core_completion(", gate5_start)
    assert "_validate_rr_runtime_project_continuity(" in source[gate5_start:gate5_end]
    assert '"10-defense-local.json"' in source
    assert '"14-defense-local.json"' not in source
    assert "validate_rr_non_estimable_contrast(" in source
    assert 'set(projection) != {"path", "file", "sha256", "bytes"}' in source
    assert (
        '{"path", "envelope_id", "file", "sha256", "bytes"}' in source
    )
    assert 'set(eligibility) != {"path", "sha256", "bytes"}' in source
    assert 'eligibility.get("bindings", {}).get("request_envelope_sha256")' in source
    assert '"records": eligibility_records' in source
    assert "RR projection descriptor filename mismatch" in source
    assert "RR request-envelope descriptor identity mismatch" in source
    assert "candidate.lstat()" in source
    assert "not stat.S_ISREG(entry.st_mode)" in source
    assert "evidence member changed while reading" in source
    assert 'getattr(os, "O_NOFOLLOW", 0)' in source
    assert "members_after != members_before" in source
    assert "evidence root changed while reading" in source


def test_phase5_rr_preserves_projections_and_starts_terminal_at_canary(
    tmp_path: Path,
) -> None:
    import re

    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    projections = (root / "phase5_core_projections.sh.in").read_text(encoding="utf-8")
    canaries = (root / "phase5_core_attest_canary.sh.in").read_text(encoding="utf-8")
    finalizer = (root / "phase5_finalize_gate5.sh.in").read_text(encoding="utf-8")
    promoter = (root / "phase5_promote_gate5.sh.in").read_text(encoding="utf-8")
    sequence = (root / "gate5_after_phase5_sequence.sh.in").read_text(encoding="utf-8")
    rr_lanes = (
        "local-llava-rr-text-full",
        "local-llava-rr-image-full",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    )
    for lane in rr_lanes:
        assert projections.count(f"run_preflight {lane} ") == 1
        assert f"run_canary {lane} " not in canaries
        assert lane in finalizer
        assert lane in promoter
    assert "write_rr_target_runtime_terminal \"$RR_TERMINAL\" \"$RR_CFG\"" in canaries
    assert canaries.index(
        'write_rr_target_runtime_terminal "$RR_TERMINAL" "$RR_CFG"'
    ) < canaries.index(
        "probe_target qwen3-vl text"
    )
    assert '"schema": SCHEMA' in canaries
    assert 'SCHEMA = "ura-phase5-target-runtime-terminal/1"' in canaries
    assert 'REASON_CODE = "target_baseline_nontermination_at_generation_cap"' in canaries
    assert (
        'OBSERVED_PROJECT_COMMIT = "5719a4ff4ba4a711fee433d1f9990c1d3cf2f8a3"'
        in canaries
    )
    assert (
        'EXPECTED_CONFIG_SHA256 = "3a53ab82405636116e9c95850dae1e0c1e394021317707c978bc35b4178ca334"'
        in canaries
    )
    assert '"normalized_selected_sha256": "5e64bdc1ddc8e3a719f226cc2ffbb7325248ef03995a5eb9992cc3bd6bff5590"' in canaries
    assert "not exact_normalized_local_identity(local_identity)" in canaries
    assert "RR exact commit/config mutation self-test failed" in canaries
    assert "revision_content_identities([config_descriptor, *observed_config_descriptors])" in canaries
    assert '"status": "passed", "value": rr_projection_value(prelim)' in finalizer
    assert '"target_runtime_terminal_artifact": dict(artifact["descriptor"])' in finalizer
    assert "def validate_rr_projection_lane(" in finalizer
    assert "rr_swapped_projection_lane" in finalizer
    assert '{"path", "file", "sha256", "bytes"}' in finalizer
    assert '{"path", "envelope_id", "file", "sha256", "bytes"}' in finalizer
    assert '"target_runtime_terminal": 4' in finalizer
    assert '"target_runtime_terminal": 4' in promoter
    for source in (finalizer, promoter):
        assert re.search(r'(?<![A-Za-z_])"records"\s*:\s*1\b', source) is None
        assert source.count("load_eligibility_artifact(") == 5
        assert "validate_eligibility_envelope_binding(" in source
        assert "load_stable_request_envelope_file(" in source
        assert 'getattr(os, "O_NOFOLLOW", 0)' in source
        assert "inventory_after != inventory_before" in source
        assert "member.read_bytes()" not in source
    assert "inventory_after != inventory_before" in canaries
    assert "member.read_bytes()" not in canaries
    assert ".read_bytes()" not in canaries
    assert ".read_text(" not in canaries
    assert canaries.count("_bounded_nofollow_read(") >= 4
    assert canaries.count("validate_lane_projection_binding(") >= 3
    assert "grid is not bound to the exact retained eligibility plan" in canaries
    assert "grid is not bound to the exact retained lane projection" in canaries
    assert "acquisition binding names another request envelope" in canaries
    assert '(22, 24, 4, [])' in sequence
    assert '(21, 25, 4, ["defense-local"])' in sequence

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    for filename, flag, expected_mutations in (
        (
            "phase5_finalize_gate5.sh",
            "--inventory-contract-self-test",
            {
                "rr_projection_unavailable", "rr_missing_projection_descriptor",
                "rr_split_terminal_evidence", "rr_duplicate_projection",
                "rr_swapped_projection_lane",
            },
        ),
        (
            "phase5_promote_gate5.sh",
            "--promotion-self-test",
            {
                "rr_projection_unavailable", "rr_projection_descriptor_missing",
                "rr_split_terminal_artifact", "rr_duplicate_projection",
            },
        ),
    ):
        shell = (output / filename).read_text(encoding="utf-8")
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", shell, re.DOTALL)
        assert len(blocks) == 1
        result = subprocess.run(
            [sys.executable, "-", flag],
            cwd=Path(__file__).parents[2],
            input=blocks[0],
            capture_output=True,
            text=True,
            check=True,
        )
        value = json.loads(result.stdout)
        assert value["status"] == "passed"
        assert value["expected_rows"] == 46
        assert value["expected_runnable"] == [21, 22]
        assert value["expected_target_runtime_terminal"] == 4
        assert expected_mutations <= set(value["rejected_mutations"])
        assert value["retained_binding_self_test"] == {
            "eligibility_nonblank_records": 3,
            "hardcoded_one_rejected": True,
            "request_envelope_swap_rejected": True,
        }


def test_gate5_failed_attestation_retry_is_content_bound_and_mutation_tested(
    tmp_path: Path,
) -> None:
    import re

    template_root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    finalizer_source = (
        template_root / "phase5_finalize_gate5.sh.in"
    ).read_text(encoding="utf-8")
    controller_source = (
        template_root / "phase5_core_attest_canary.sh.in"
    ).read_text(encoding="utf-8")
    assert (
        "target\\tmodality\\tarm\\tsample_seed\\trun_root\\texit_code"
        in controller_source
    )
    for required in (
        "def validate_failed_attestation_candidate(",
        "failed_attestation_tree_descriptor(run_root)",
        "Runner.load_response_checkpoint(path, expected_run_id=run_id)",
        'grid.get("call_budget_snapshot") != budget',
        "read_failed_attestation_tsv(attempt_failure_path)",
        '"deleted_budget_ledger"',
        '"rolled_back_budget_target_calls"',
        '"deleted_paid_response_checkpoint"',
        '"rolled_back_checkpoint_target_calls"',
        '"rolled_back_grid_target_calls"',
        '"deleted_circuit_ledger"',
        '"rolled_back_circuit_target_calls"',
        '"deleted_circuit_and_paid_response"',
    ):
        assert required in finalizer_source

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    shell = (output / "phase5_finalize_gate5.sh").read_text(encoding="utf-8")
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", shell, re.DOTALL)
    assert len(blocks) == 1
    result = subprocess.run(
        [sys.executable, "-", "--inventory-contract-self-test"],
        cwd=Path(__file__).parents[2],
        input=blocks[0],
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(result.stdout)["failed_live_attestation_self_test"]
    assert value["schema"] == (
        "ura-phase5-failed-live-attestation-contract-self-test/1"
    )
    assert value["status"] == "passed"
    assert value["call_accounting"] == {
        "accounting_semantics": "durable_pre_call_logical_reservation_v1",
        "budget_id": "grid-" + "a" * 24,
        "target_calls": 1,
        "model_judge_calls": 0,
        "http_attempts": 0,
        "checkpointed_target_responses": 1,
        "completed_attempts": 0,
    }
    assert value["target_stage_call_accounting"] == {
        "accounting_semantics": "durable_pre_call_logical_reservation_v1",
        "budget_id": "grid-" + "a" * 24,
        "target_calls": 1,
        "model_judge_calls": 0,
        "http_attempts": 0,
        "checkpointed_target_responses": 0,
        "completed_attempts": 0,
    }
    assert set(value["rejected_mutations"]) == {
        "deleted_budget_ledger",
        "rolled_back_budget_target_calls",
        "deleted_paid_response_checkpoint",
        "rolled_back_checkpoint_target_calls",
        "rolled_back_grid_target_calls",
        "deleted_circuit_ledger",
        "rolled_back_circuit_target_calls",
        "deleted_circuit_and_paid_response",
    }
    empty = json.loads(result.stdout)[
        "empty_failed_live_attestation_tsv_self_test"
    ]
    assert empty == {
        "schema": "ura-phase5-empty-failed-attestation-tsv-self-test/1",
        "status": "passed",
        "canonical_empty_rows": 0,
        "rejected_mutations": [
            "reordered_empty_ledger_header",
            "crlf_empty_ledger_header",
            "blank_row_after_empty_ledger_header",
        ],
    }


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


def test_phase6_rr_runtime_terminals_are_required_but_never_scheduled() -> None:
    import re

    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    names = (
        "phase6_core_measured.sh.in",
        "phase6_extended_measured.sh.in",
        "phase6_native_diagnostics.sh.in",
        "phase6_sequence.sh.in",
    )
    sources = {
        name: (root / name).read_text(encoding="utf-8") for name in names
    }
    rr_lanes = (
        "local-llava-rr-text-full",
        "local-llava-rr-image-full",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    )
    semantic_sources = (
        sources["phase6_core_measured.sh.in"],
        sources["phase6_extended_measured.sh.in"],
        sources["phase6_native_diagnostics.sh.in"],
    )
    for source_index, source in enumerate(sources.values()):
        python_blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", source, re.DOTALL)
        assert python_blocks
        for block_index, block in enumerate(python_blocks):
            compile(block, f"<phase6-{source_index}-{block_index}>", "exec")
    for source in semantic_sources:
        for lane in rr_lanes:
            assert lane in source
        assert "ura-phase5-target-runtime-terminal/1" in source
        assert "target_baseline_nontermination_at_generation_cap" in source
        assert 'canary.get("target_runtime_terminal_artifact")' in source
        assert 'projection_field.get("status") != "passed"' in source or (
            'value.get("status") != "passed"' in source
        )
        assert '"target_runtime_terminal": 4' in source
        assert '"runnable": 22' in source
        assert '"typed_terminal": 24' in source
        assert '"runnable": 21' in source
        assert '"typed_terminal": 25' in source
        assert '"local-llava-rr.json"' in source
        assert "5719a4ff4ba4a711fee433d1f9990c1d3cf2f8a3" in source
        assert (
            "3a53ab82405636116e9c95850dae1e0c1e394021317707c978bc35b4178ca334"
            in source
        )
        assert 'target["local_config"].get("bytes") != 246' in source
        assert '"tensor_parallel_size": 1' in source
        assert '"gpu_memory_utilization": 0.85' in source
        assert 'tree_hash.update(relative.encode("utf-8"))' in source or (
            'digest_value.update(relative.encode("utf-8"))' in source
        )
        assert 'update(b"\\0")' in source
        assert 'update(member_sha.encode("ascii"))' in source
        assert "not stat.S_ISREG(after.st_mode)" in source
        assert 'getattr(os, "O_NOFOLLOW", 0)' in source
        assert "members_after != members_before" in source
        assert "RR evidence root changed while reading" in source
        assert "member.read_bytes()" not in source

    core = sources["phase6_core_measured.sh.in"]
    extended = sources["phase6_extended_measured.sh.in"]
    native = sources["phase6_native_diagnostics.sh.in"]
    sequence = sources["phase6_sequence.sh.in"]
    assert core.count("def rr_tree_descriptor(") == 2
    assert native.count("def rr_tree_descriptor(") == 2
    assert "revalidate_rr_runtime_terminal_artifact(" in core
    assert native.count("validate_rr_runtime_terminal_artifact(shared") == 2
    assert "if lane not in RR_TERMINAL_LANE_SET" in core
    assert 'test "${#SPEC_FILES[@]}" -eq 9 || test "${#SPEC_FILES[@]}" -eq 10' in core
    assert 'test "${#SPEC_FILES[@]}" -eq 13' not in core
    assert "Phase 6 core contains an RR spec, argv, result, root, or reservation" in core
    assert "Phase 6 extended generated an RR lane spec" in extended
    assert (
        "Phase 6 extended contains an RR argv, spec, root, result, or reservation"
        in extended
    )
    assert "native controller contains an RR argv, spec, root, result, or reservation" in native
    for source in (core, extended, native):
        assert 'projection.get("bindings", {}).get("request_envelope_sha256")' not in source
        assert 'eligibility.get("bindings", {}).get("request_envelope_sha256")' in source
        assert '{"path", "file", "sha256", "bytes"}' in source
        assert '{"path", "envelope_id", "file", "sha256", "bytes"}' in source
        assert '"records": eligibility_records' in source
        assert 'for line in eligibility_payload.decode("utf-8").splitlines()' in source
        assert "eligibility_path.read_text" not in source
    assert 'eligibility_content.get("bindings", {}).get(' in core
    assert native.count(
        'eligibility.get("bindings", {}).get("request_envelope_sha256")'
    ) == 2
    assert "rr-envelope-eligibility-binding" in native
    assert "rr-projection-byte-mutation" in native
    assert "rr-envelope-byte-mutation" in native
    for source in semantic_sources:
        rr_projection_validators = re.findall(
            r"def validate_rr_projection_field\(.*?(?=\n\ndef )",
            source,
            re.DOTALL,
        )
        assert rr_projection_validators
        for validator in rr_projection_validators:
            assert "projection_from_bytes(" in validator
            assert "envelope_from_bytes(" in validator
            assert "load_lane_projection_file(" not in validator
            assert "load_request_envelope_file(" not in validator
    assert "projection_content, observed_projection = projection_from_bytes(" in core
    assert "envelope_content, observed_envelope = envelope_from_bytes(" in core
    assert '"target_runtime_terminal": 4' in sequence
    assert "(22, 24, 4, [])" in sequence
    assert '(21, 25, 4, ["defense-local"])' in sequence
    assert "RR_TERMINAL_LANES[0]: \"measured_complete\"" in sequence

    combined = "\n".join(sources.values())
    assert '"runnable": 26' not in combined
    assert '"runnable": 25' not in combined
    assert "(26, 20" not in combined
    assert "(25, 21" not in combined


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
    rr_terminals = {
        "local-llava-rr-text-full",
        "local-llava-rr-image-full",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    }
    complete = {
        lane: state for lane, state in complete.items() if lane not in rr_terminals
    }
    conditional = {
        lane: "measured_complete"
        for lane in candidate_lanes
        if lane not in rr_terminals and lane != "defense-local"
    }

    assert require_profile(
        {
            "runnable_lanes": 22,
            "typed_terminal_lanes": 24,
            "target_runtime_terminal": 4,
            "conditional_na_lanes": [],
        },
        sequence_conditional=[],
        core_states=complete,
        label="test-success",
    ) == (22, 24, 4, [])
    assert require_profile(
        {
            "runnable_lanes": 21,
            "typed_terminal_lanes": 25,
            "target_runtime_terminal": 4,
            "conditional_na_lanes": ["defense-local"],
        },
        sequence_conditional=["defense-local"],
        core_states=conditional,
        label="test-conditional",
    ) == (21, 25, 4, ["defense-local"])
    with pytest.raises(SystemExit, match="conditional and core inventories differ"):
        require_profile(
            {
                "runnable_lanes": 21,
                "typed_terminal_lanes": 25,
                "target_runtime_terminal": 4,
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
                "target_runtime_terminal": 4,
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

    success_result, success_manifest = profile(22, 24, [])
    assert require_profile(
        success_result, success_manifest, label="test-success"
    )[:4] == (22, 24, 4, [])
    conditional_result, conditional_manifest = profile(
        21, 25, ["defense-local"]
    )
    assert require_profile(
        conditional_result, conditional_manifest, label="test-conditional"
    )[:4] == (21, 25, 4, ["defense-local"])

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
