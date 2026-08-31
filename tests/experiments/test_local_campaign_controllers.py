from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence

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
from experiments.local_campaign.console_events import (
    finish_child_controller,
    start_child_controller,
)
from experiments.local_campaign.rebind import main as rebind_main
from experiments.rig_web_app.campaigns import load_engineering_campaign


def _template_tokens() -> set[str]:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    import re

    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    return {
        match
        for spec in CONTROLLERS
        for match in token.findall((root / spec.template).read_text(encoding="utf-8"))
    } - DERIVED_BINDINGS


def _template_source(name: str) -> str:
    return (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / name
    ).read_text(encoding="utf-8")


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


def _rendered_gate5_namespace(tmp_path: Path) -> dict[str, object]:
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    shell = (output / "phase5_finalize_gate5.sh").read_text(encoding="utf-8")
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", shell, re.DOTALL)
    assert len(blocks) == 1
    source = blocks[0].split(
        "\ntry:\n    raise SystemExit(main(sys.argv[1:]))", 1
    )[0]
    namespace: dict[str, object] = {"__name__": "gate5_contract_test"}
    exec(compile(source, "phase5_finalize_gate5.py", "exec"), namespace)
    return namespace


def _rendered_gate5_promoter_namespace(tmp_path: Path) -> dict[str, object]:
    import re

    bindings = _bindings(tmp_path / "bindings-promoter.json")
    output = tmp_path / "workspace-promoter"
    render_controller_set(bindings, output)
    shell = (output / "phase5_promote_gate5.sh").read_text(encoding="utf-8")
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", shell, re.DOTALL)
    assert len(blocks) == 1
    source = blocks[0].split(
        "\ntry:\n    raise SystemExit(main(sys.argv[1:]))", 1
    )[0]
    namespace: dict[str, object] = {"__name__": "gate5_promoter_contract_test"}
    exec(compile(source, "phase5_promote_gate5.py", "exec"), namespace)
    return namespace


def _rendered_phase6_extended_namespace(tmp_path: Path) -> dict[str, object]:
    import re

    bindings = _bindings(tmp_path / "bindings-phase6.json")
    output = tmp_path / "workspace-phase6"
    render_controller_set(bindings, output)
    shell = (output / "phase6_extended_measured.sh").read_text(encoding="utf-8")
    blocks = re.findall(
        r"<<'PHASE6_PAYLOAD'\n(.*?)\nPHASE6_PAYLOAD(?:\n|$)",
        shell,
        re.DOTALL,
    )
    assert len(blocks) == 1
    source = blocks[0].split('\nif __name__ == "__main__":', 1)[0]
    source = source.replace(
        'PROJECT = Path.home() / "MLLMRiskBench"\n'
        "os.chdir(PROJECT)\n"
        "sys.path.insert(0, str(PROJECT))",
        "PROJECT = Path.cwd()\nsys.path.insert(0, str(PROJECT))",
        1,
    )
    namespace: dict[str, object] = {"__name__": "phase6_extended_contract_test"}
    exec(compile(source, "phase6_extended_payload.py", "exec"), namespace)
    return namespace


def _rendered_phase7_namespace(tmp_path: Path) -> dict[str, object]:
    bindings = _bindings(tmp_path / "bindings-phase7.json")
    output = tmp_path / "workspace-phase7"
    render_controller_set(bindings, output)
    source = (output / "phase7_analysis.py").read_text(encoding="utf-8")
    source = source.split('\nif __name__ == "__main__":', 1)[0]
    namespace: dict[str, object] = {"__name__": "phase7_contract_test"}
    exec(compile(source, "phase7_analysis.py", "exec"), namespace)
    return namespace


def _bridge_canary_fields_namespace() -> dict[str, object]:
    import re

    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_bridge_attest_canary.sh.in"
    ).read_text(encoding="utf-8")
    function = template.split("canary_fields() {", 1)[1].split(
        "\n}\n\nrun_canary()", 1
    )[0]
    match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", function, re.DOTALL)
    assert match is not None
    source = match.group(1).split("\nroot = pathlib.Path", 1)[0]
    namespace: dict[str, object] = {"__name__": "bridge_canary_contract_test"}
    exec(compile(source, "phase5_bridge_canary_fields.py", "exec"), namespace)
    return namespace


def test_all_controller_implementations_are_versioned() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    expected = {spec.template for spec in CONTROLLERS}
    assert len(CONTROLLERS) == 32
    assert {path.name for path in root.glob("*.in")} == expected | SUPPORT_TEMPLATES
    assert "phase6_native_diagnostics.sh.in" in expected
    assert "phase6_current_ollama.sh.in" in expected
    assert "phase6_core_length_recovery.py.in" in expected
    assert "phase6_seven_output_policy.py.in" in expected
    assert "launch_phase6_recovery_and_seven.sh.in" in expected
    assert "phase8_human_audit.README.md.in" in expected
    assert "phase6_native_measured.sh.in" not in expected
    assert {spec.output for spec in CONTROLLERS} >= {
        "phase6_current_ollama.sh",
        "phase6_native_diagnostics.sh",
        "phase8_human_audit.README.md",
    }
    assert "phase6_native_measured.sh" not in {spec.output for spec in CONTROLLERS}
    for spec in CONTROLLERS:
        source = (root / spec.template).read_text(encoding="utf-8")
        if "EXPECTED_COMMIT" in source:
            assert "@@EXPECTED_COMMIT@@" in source


def test_independently_launched_children_render_native_jobs_registration(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)

    shell_registered = (
        "phase5_core_projections.sh",
        "phase5_core_attest_canary.sh",
        "phase5_bridge_projections.sh",
        "phase5_bridge_attest_canary.sh",
        "phase5_ollama_workflow.sh",
        "phase5_finalize_gate5.sh",
    )
    for name in shell_registered:
        source = (output / name).read_text(encoding="utf-8")
        assert "console_events" in source
        assert "child-start" in source
        assert "child-finish" in source
        assert source.index("CONSOLE_CAMPAIGN_STARTED=1") < source.index("child-start")

    target_capable = (
        "phase5_core_attest_canary.sh",
        "phase5_bridge_attest_canary.sh",
        "phase5_ollama_workflow.sh",
    )
    for name in target_capable:
        source = (output / name).read_text(encoding="utf-8")
        assert "--target-execution" in source
        assert "target-execution --work-root" in source
        assert "completed_target_execution" in source
        assert "aggregate_target_execution" in source
        assert "target_attempts" in source
        assert "successful_target_generations" in source

    core_canary = (output / "phase5_core_attest_canary.sh").read_text(
        encoding="utf-8"
    )
    assert "accounting_unavailable=bool(failed_attestations)" in core_canary
    assert "TARGET_EXECUTION_UNAVAILABLE=failed_attestation_candidates" in core_canary

    for name in (
        "phase5_core_projections.sh",
        "phase5_bridge_projections.sh",
        "phase5_finalize_gate5.sh",
    ):
        source = (output / name).read_text(encoding="utf-8")
        assert "--target-execution" not in source
        assert "target-execution --work-root" not in source

    phase7_payload = (output / "phase7_analysis.py").read_text(encoding="utf-8")
    assert '_console_child("child-start", terminal_root)' in phase7_payload
    assert '_console_child("child-finish", terminal_root, exit_code)' in phase7_payload
    assert phase7_payload.index("console_registered = True") < phase7_payload.index(
        '_console_child("child-start", terminal_root)'
    )

    for name in (
        "phase6_core_measured.sh",
        "phase6_extended_measured.sh",
        "phase6_native_diagnostics.sh",
        "phase6_core_length_recovery.py",
        "phase6_seven_output_policy.py",
        "launch_phase6_recovery_and_seven.sh",
    ):
        source = (output / name).read_text(encoding="utf-8")
        assert "child-start" not in source
        assert "start_child_controller" not in source

    phase7_launcher = (output / "phase7_analysis.sh").read_text(encoding="utf-8")
    assert 'SESSION=$(printf \'%q\' "$SESSION")' in phase7_launcher
    assert 'SOCKET=$(printf \'%q\' "$SOCKET")' in phase7_launcher


@pytest.mark.parametrize(
    "case", ("mismatch", "success", "start_failure", "constructor_failure")
)
def test_phase7_registers_only_the_launch_validated_control_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    namespace = _rendered_phase7_namespace(tmp_path)
    authoritative = tmp_path / "work" / "runs" / "engineering" / "phase7-analysis"
    ambient = authoritative if case != "mismatch" else authoritative.parent / "spoofed"
    authoritative.mkdir(parents=True)
    if ambient != authoritative:
        ambient.mkdir()
    launch_path = authoritative / "launch.json"
    launch_path.write_text(
        json.dumps(
            {
                "schema": "ura-phase7-analysis-launch/1",
                "authorized_input_manifest_sha256": "a" * 64,
                "input_manifest": {},
                "payload": {},
                "control_root": str(authoritative),
                "analysis_root": str(tmp_path / "analysis"),
            }
        ),
        encoding="utf-8",
    )
    calls: list[tuple[object, ...]] = []

    class FakeController:
        def __init__(self, launch: Path) -> None:
            calls.append(("validated", launch))
            if case == "constructor_failure":
                raise RuntimeError("injected full controller validation failure")
            self.control = authoritative
            self.failure_path = authoritative / "failure.json"
            self.current_name = "startup"

        def execute_all(self) -> None:
            calls.append(("execute", self.control))

        def terminate_child(self) -> None:
            calls.append(("terminate", self.control))

        def clean_scratch(self) -> None:
            calls.append(("clean", self.control))

        def emit(self, message: str) -> None:
            calls.append(("emit", message))

    def console_child(action: str, control: Path, exit_code: int | None = None) -> None:
        calls.append((action, control, exit_code))
        if action == "child-start":
            start_child_controller(
                work_root=tmp_path / "work",
                control_root=control,
                campaign_id=control.name,
                release_commit="1" * 40,
                evidence_class="local_campaign_control",
                hard_stop_hours=720,
                tmux_socket="ura-phase7-test",
                tmux_session="ura-phase7-test",
            )
            if case == "start_failure":
                raise RuntimeError("injected post-marker interruption")
        elif action == "child-finish" and exit_code is not None:
            finish_child_controller(
                work_root=tmp_path / "work",
                control_root=control,
                exit_code=exit_code,
            )

    monkeypatch.setenv("CONTROL_ROOT", str(ambient))
    monkeypatch.setenv("URA_WORK", str(tmp_path / "work"))
    for name, value in (("SIGHUP", 1), ("SIGINT", 2), ("SIGTERM", 15)):
        monkeypatch.setattr(namespace["signal"], name, value, raising=False)
    monkeypatch.setattr(namespace["signal"], "signal", lambda *_args: None)
    namespace["AnalysisController"] = FakeController
    namespace["_console_child"] = console_child
    result = namespace["execute"](argparse.Namespace(launch=str(launch_path)))

    if case == "success":
        assert result == 0
        assert ("child-start", authoritative, None) in calls
        assert ("validated", launch_path) in calls
        assert ("execute", authoritative) in calls
        assert ("child-finish", authoritative, 0) in calls
    elif case == "mismatch":
        assert result == 1
        assert not any(call[0] in {"child-start", "child-finish"} for call in calls)
        assert (authoritative / ".exit").read_text(encoding="ascii") == "1\n"
        assert not (ambient / ".exit").exists()
    elif case == "start_failure":
        assert result == 1
        assert ("child-start", authoritative, None) in calls
        assert not any(call[0] == "validated" for call in calls)
        assert ("child-finish", authoritative, 1) in calls
    else:
        assert result == 1
        assert ("child-start", authoritative, None) in calls
        assert ("validated", launch_path) in calls
        assert ("child-finish", authoritative, 1) in calls
        assert (authoritative / ".exit").read_text(encoding="ascii") == "1\n"
        assert (authoritative / "ENGINEERING_ONLY.json").is_file()
        terminal = load_engineering_campaign(tmp_path / "work" / "runs", authoritative.name)
        assert terminal is not None
        assert terminal.state == "failed"
        assert terminal.task_outcomes == (("controller", "failed", "support"),)


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
    assert "exactly 46 lanes: 18 runnable" in readme
    assert "and 28 typed terminal, including seven target-runtime terminals" in readme
    assert "seven Runner 2.24" in readme
    assert "a separate amendment and revision stratum" in readme
    assert "C >= N + 20" in readme
    assert "S >= M" in readme
    assert "human_only_blocked" in readme
    assert "gate8_met: false" in readme
    assert "pairs may rotate between rows" in readme
    assert "pair with shared assignments" in readme
    assert "deterministic, seedless, and without" in readme
    assert "coverage_priority_then_stratum_round_robin_sha256_v1" in readme
    assert "coverage_priority_then_sha256_fill_v1" in readme
    assert (
        "disjoint_risk_modality_behavior_coverage_then_sha256_"
        "lexicographic_representative_fill_v1"
        in readme
    )
    assert "not every sibling row" in readme
    assert "43 total lanes" not in readme
    assert "8461790bb3e2fe75589c0cd547857406442a0c99" not in readme


def test_phase8_preparation_binds_versioned_seedless_selector_policies() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase8_human_audit.py.in"
    ).read_text(encoding="utf-8")
    for algorithm in (
        "coverage_priority_then_stratum_round_robin_sha256_v1",
        "coverage_priority_then_sha256_fill_v1",
    ):
        assert source.count(algorithm) == 1
    assert (
        source.count(
            '"disjoint_risk_modality_behavior_coverage_then_sha256_"'
        )
        == 1
    )
    assert source.count('"lexicographic_representative_fill_v1"') == 1
    for policy in (
        "COMMON_SELECTION_POLICY",
        "SOURCE_TASK_SELECTION_POLICY",
    ):
        start = source.index(policy + " = {")
        end = source.index("}\n", start) + 2
        descriptor = source[start:end]
        assert '"deterministic": True' in descriptor
        assert '"randomized": False' in descriptor
        assert '"without_replacement": True' in descriptor
        assert '"whole_cluster": True' in descriptor

    qualification_start = source.index("QUALIFICATION_SELECTION_POLICY = {")
    qualification_end = source.index("}\n", qualification_start) + 2
    qualification = source[qualification_start:qualification_end]
    assert '"deterministic": True' in qualification
    assert '"randomized": False' in qualification
    assert '"without_replacement": True' in qualification
    assert '"whole_cluster": False' in qualification
    assert (
        '"output_unit": "one_representative_row_per_selected_cluster"'
        in qualification
    )
    assert (
        '"representative_rule": "lexicographic_min_sample_key_v1"'
        in qualification
    )
    assert "qualification-sibling-substitution" in source
    assert "Phase 8 qualification items differ from exact selector replay" in source

    manifest_start = source.index('        "sampling": {')
    manifest_end = source.index('        "claims": {', manifest_start)
    manifest = source[manifest_start:manifest_end]
    assert '"seed"' not in manifest
    assert '"--seed"' not in manifest
    execution_start = source.index("    common_argv = [")
    execution_end = source.index("    revalidate_execution_view()", execution_start)
    assert '"--seed"' not in source[execution_start:execution_end]


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


def test_launch_chain_stops_before_the_explicit_phase7_artifact_launch() -> None:
    launch_chain = _template_source("launch_chain.sh.in")
    launch_section = launch_chain.split(
        "if [[ \"${URA_LAUNCH_CHAIN_VALIDATE_ONLY:-0}\" == '1' ]]; then", 1
    )[1]
    assert "campaign launch chain through Phase 6 validated" in launch_section
    assert "launch_phase7_watcher.sh" not in launch_section
    assert "P7_SESSION" not in launch_chain

    readme = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "README.md"
    ).read_text(encoding="utf-8")
    assert "The launch chain stops after Phase 6." in readme
    for option in (
        "--phase6-sequence-completion",
        "--phase6-recovery-completion",
        "--seven-output-policy-amendment",
        "--phase6-seven-output-policy-completion",
        "--followon-gate5-amendment",
        "--phase6-followon-completion",
    ):
        assert option in readme


def test_phase7_watcher_launcher_owns_its_registered_tmux_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "1" * 40
    bindings = _bindings(tmp_path / "bindings.json", commit=commit)
    generations = tmp_path / ".ura-controller-generations"
    generations.mkdir()
    archive_sha = "a" * 64
    generation = generations / f"{commit[:7]}-{archive_sha}"
    render_controller_set(bindings, generation)
    (generation / ".ura-controller-generation.tsv").write_text(
        "schema\tura-controller-generation/1\n"
        f"expected_commit\t{commit}\n"
        f"archive_sha256\t{archive_sha}\n",
        encoding="ascii",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state = tmp_path / "tmux-state"
    capture = tmp_path / "tmux-new-session-argv"
    tmux = fake_bin / "tmux"
    tmux.write_text(
        "#!/usr/bin/env bash\n"
        "set -Eeuo pipefail\n"
        "case \" $* \" in\n"
        "  *\" has-session \"*) test -f \"$FAKE_TMUX_STATE\" ;;\n"
        "  *\" new-session \"*)\n"
        "    printf '%s\\n' \"$@\" > \"$FAKE_TMUX_CAPTURE\"\n"
        "    : > \"$FAKE_TMUX_STATE\"\n"
        "    ;;\n"
        "  *) exit 2 ;;\n"
        "esac\n",
        encoding="ascii",
    )
    tmux.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_TMUX_STATE", str(state))
    monkeypatch.setenv("FAKE_TMUX_CAPTURE", str(capture))
    monkeypatch.delenv("URA_CONTROLLER_GENERATION_ROOT", raising=False)

    completed = subprocess.run(
        [
            "bash",
            str(generation / "launch_phase7_watcher.sh"),
            "--phase6-sequence-completion",
            "/bound/core completion.json",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    socket = f"ura-phase7-after-phase6-{commit[:7]}"
    assert f"PHASE7_WATCHER_SOCKET={socket}" in completed.stdout
    assert f"PHASE7_WATCHER_SESSION={socket}" in completed.stdout
    captured = capture.read_text(encoding="utf-8").splitlines()
    assert captured[:6] == ["-L", socket, "new-session", "-d", "-s", socket]
    assert captured[6].startswith(
        "exec env AUTHORIZED_WATCHER_SHA256="
    )
    assert "PHASE7_WATCHER_TAG=20260822T120000Z" in captured[6]
    assert "--phase6-sequence-completion" in captured[6]
    assert "/bound/core\\ completion.json" in captured[6]
    assert state.is_file()


def test_phase3_registers_one_tmux_owned_console_campaign_with_exact_progress(
    tmp_path: Path,
) -> None:
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    source = (output / "phase3_guard1b_acquire_fit.sh").read_text(
        encoding="utf-8"
    )
    expected_tasks = (
        "validate-deployed-inputs",
        "derive-plan",
        "sealed-acquisition",
        "zero-call-fit-preflight",
        "validate-fit-evidence",
    )

    def assert_contract(value: str) -> None:
        task_block = re.search(
            r"(?m)^readonly -a CONTROL_TASKS=\(\n"
            r"(?P<tasks>(?:  [a-z0-9-]+\n)+)\)$",
            value,
        )
        assert task_block is not None
        assert tuple(
            line.strip() for line in task_block.group("tasks").splitlines()
        ) == expected_tasks
        assert re.findall(
            r"(?m)^  controller_task_start ([a-z0-9-]+)$", value
        ) == list(expected_tasks)
        assert re.findall(
            r"(?m)^  controller_task_pass ([a-z0-9-]+)$", value
        ) == list(expected_tasks)
        assert value.count(
            "-m experiments.local_campaign.console_events start"
        ) == 1
        assert '--campaign-id "${control_root##*/}"' in value
        assert '--release-commit "$EXPECTED_COMMIT"' in value
        assert "--evidence-class local_campaign_control" in value
        assert "readonly CONTROL_HARD_STOP_HOURS='25'" in value
        assert '--hard-stop-hours "$CONTROL_HARD_STOP_HOURS"' in value
        assert '--tmux-socket "$socket"' in value
        assert '--tmux-session "$session"' in value
        assert 'console_start_args+=(--planned-task "$task")' in value
        registration = value.index(
            "-m experiments.local_campaign.console_events start"
        )
        tmux_launch = value.index('tmux -L "$socket" new-session -d -s "$session"')
        assert registration < tmux_launch

        launch_failure = value[tmux_launch : value.index("  printf 'SESSION=%s", tmux_launch)]
        assert 'if (( launch_rc != 0 )); then' in launch_failure
        assert (
            '--event task_skip --task "$task" --status skipped'
            in launch_failure
        )
        assert (
            '--event campaign_end --task bootstrap --status failed'
            in launch_failure
        )
        assert 'return "$launch_rc"' in launch_failure

        finish = value.split("\n  finish() {", 1)[1].split(
            "\n  }\n  trap finish EXIT", 1
        )[0]
        exit_publication = finish.index(
            'mv -T -- "$CONTROL_ROOT/.exit.tmp" "$CONTROL_ROOT/.exit"'
        )
        assert 'controller_finish "$rc"' in finish
        terminal_publication = finish.index('controller_finish "$rc"')
        assert exit_publication < terminal_publication < finish.index('exit "$rc"')
        assert "[[ \"$STAGE\" == 'complete' ]]" in value
        assert "CONTROL_TASK_INDEX == ${#CONTROL_TASKS[@]}" in value
        assert 'console_event task_end "$task" failed "$detail"' in value
        assert 'console_event task_skip "$task" skipped' in value
        assert 'console_event campaign_end bootstrap "$status" "$detail"' in value

    assert_contract(source)
    for original, replacement in (
        ('--tmux-session "$session"', '--tmux-session wrong-session'),
        (
            '--event campaign_end --task bootstrap --status failed',
            '--event campaign_end --task bootstrap --status passed',
        ),
        ('controller_finish "$rc"', ':'),
        ('controller_task_start sealed-acquisition', ':'),
        ('[[ "$STAGE" == \'complete\' ]]', '[[ -n "$STAGE" ]]'),
    ):
        assert original in source
        with pytest.raises(AssertionError):
            assert_contract(source.replace(original, replacement, 1))


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


def test_gate5_approval_scope_consumers_use_current_time_semantics() -> None:
    template_root = (
        Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    )
    current_scope = (
        "exact frozen Gate-5 lane inventory, caps, call-start and measured-lane "
        "wall-time semantics, and external storage policy"
    )
    obsolete_scope = (
        "exact frozen Gate-5 lane inventory, caps, deadline semantics, and "
        "external storage policy"
    )
    expected_consumers = {
        "phase5_promote_gate5.sh.in": 1,
        "phase6_native_diagnostics.sh.in": 2,
    }

    def assert_contract(candidate: str, expected_count: int) -> None:
        assert candidate.count(current_scope) == expected_count
        assert obsolete_scope not in candidate

    for filename, expected_count in expected_consumers.items():
        source = (template_root / filename).read_text(encoding="utf-8")
        assert_contract(source, expected_count)
        reverted = source.replace(current_scope, obsolete_scope)
        assert reverted != source
        with pytest.raises(AssertionError):
            assert_contract(reverted, expected_count)


def _assert_direct_runtime_alias_contract(
    source: str, *, receipt_lock_token: str
) -> None:
    required = (
        "raw_target = Path(os.readlink(alias))",
        "raw_target.is_absolute()",
        "len(raw_target.parts) != 2",
        'raw_target.parts[0] != ".store"',
        "[0-9a-f]{{16}}",
        "unresolved_store.is_symlink()",
        receipt_lock_token,
    )
    for token in required:
        assert token in source


def test_campaign_runtime_consumers_accept_only_direct_receipt_bound_aliases() -> None:
    templates = (
        Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    )
    canary = (templates / "phase5_bridge_attest_canary.sh.in").read_text(
        encoding="utf-8"
    )
    projection = (templates / "phase5_bridge_projections.sh.in").read_text(
        encoding="utf-8"
    )
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    native = (templates / "phase6_native_diagnostics.sh.in").read_text(
        encoding="utf-8"
    )
    phase8 = (templates / "phase8_human_audit.py.in").read_text(encoding="utf-8")
    blocks = (
        (
            canary.split("runtime_store() {", 1)[1].split("\nPY\n}", 1)[0],
            '"lock_id": lock["lock_id"]',
        ),
        (
            projection.split("runtime_store() {", 1)[1].split("\nPY\n}", 1)[0],
            '"lock_id": lock["lock_id"]',
        ),
        (
            extended.split("def managed_framework_store(", 1)[1].split(
                "\n\ndef validate_runtime_config", 1
            )[0],
            '"lock_id": EXPECTED_LOCK',
        ),
        (
            native.split('for engine in ORDER:', 1)[1].split(
                "\nwith OllamaProcessLock", 1
            )[0],
            '"lock_id": lock_id',
        ),
        (
            native.split("def validate_runtime(", 1)[1].split(
                "\n\ndef validate_planned_ollama_models", 1
            )[0],
            'value.get("lock_id") != LOCK_ID',
        ),
        (
            phase8.split('alias = Path(runtime["alias"])', 1)[1].split(
                "\n    plan_by_engine", 1
            )[0],
            'runtime_receipt.get("lock_id") != EXPECTED_FRAMEWORK_LOCK',
        ),
    )
    for block, receipt_lock_token in blocks:
        _assert_direct_runtime_alias_contract(
            block, receipt_lock_token=receipt_lock_token
        )
        assert "EXPECTED_FRAMEWORK_LOCK:0:16" not in block
        assert "EXPECTED_LOCK[:16]" not in block
        assert "LOCK_ID[:16]" not in block
        assert "lock_id[:16]" not in block
        mutated = block.replace(
            'raw_target.parts[0] != ".store"',
            'raw_target.parts[0] == ".store"',
            1,
        )
        assert mutated != block
        with pytest.raises(AssertionError):
            _assert_direct_runtime_alias_contract(
                mutated, receipt_lock_token=receipt_lock_token
            )


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


def test_phase6_extended_uses_the_real_full_gate5_transport_terminal_rows() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_extended_measured.sh.in"
    ).read_text(encoding="utf-8")
    start = source.index("GPTGEOCHAT_OLLAMA_TERMINAL_ROWS = {")
    end = source.index("\nPORTFOLIO_TERMINALS = {", start)
    contract = source[start:end]
    required = (
        '"family": "ollama"',
        '"disposition": "unavailable"',
        '"reason_code": "target_transport_text_only_for_image_source"',
        '"projection": {"status": "UNAVAILABLE", "value": None}',
        '"canary": {"status": "UNAVAILABLE", "value": None}',
        '"final_preflight": {"status": "UNAVAILABLE", "value": None}',
        '"approved_caps": {"status": "UNAVAILABLE", "value": None}',
    )

    def assert_real_row_shape(candidate: str) -> None:
        _assert_source_contract(candidate, required)

    assert_real_row_shape(contract)
    reverted = contract.replace(required[-1], "", 1)
    with pytest.raises(AssertionError):
        assert_real_row_shape(reverted)


def test_phase6_extended_preserves_the_sealed_venv_executable_spelling() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_extended_measured.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        'runner_python = PROJECT / ".venv" / "bin" / "python"',
        "if not runner_python.is_file() or not os.access(runner_python, os.X_OK):",
        'raise ValueError("project Runner venv interpreter is unavailable")',
        'executable = [str(runner_python), "-m"]',
    )

    def assert_contract(candidate: str) -> None:
        _assert_source_contract(candidate, required)
        assert (
            'runner_python = (PROJECT / ".venv" / "bin" / "python").resolve('
            not in candidate
        )

    assert_contract(source)
    reverted = source.replace(
        required[0],
        'runner_python = (PROJECT / ".venv" / "bin" / "python").resolve(strict=True)',
        1,
    )
    assert reverted != source
    with pytest.raises(AssertionError):
        assert_contract(reverted)


def test_phase6_extended_compares_receipt_to_the_semantic_plan_digest() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_extended_measured.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        "from ura.model_acquisition import load_plan, load_receipt, plan_sha256",
        'or receipt["plan_sha256"] != plan_sha256(plan)',
    )

    def assert_contract(candidate: str) -> None:
        _assert_source_contract(candidate, required)
        assert 'receipt["plan_sha256"] != plan_sha:' not in candidate

    assert_contract(source)
    reverted = source.replace(
        required[1],
        'or receipt["plan_sha256"] != plan_sha:',
        1,
    )
    assert reverted != source
    with pytest.raises(AssertionError):
        assert_contract(reverted)


def test_phase6_extended_scopes_retry_outputs_without_reusing_job_evidence() -> None:
    project = Path(__file__).parents[2]
    extended = (
        project
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_extended_measured.sh.in"
    ).read_text(encoding="utf-8")
    phase7 = (
        project
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    documents = (
        (project / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
            encoding="utf-8"
        ),
        (project / "experiments" / "RUN_AND_RETURN.md").read_text(
            encoding="utf-8"
        ),
    )
    extended_contract = (
        "def expected_result_root(",
        '        / spec["lane_id"]\n        / control_root.name',
        "result_root = expected_result_root(ctl.work, spec, ctl.control)",
    )
    phase7_contract = (
        "def extended_result_root(runner_root: Path, lane: str, control: Path)",
        "return runner_root / lane / control.name",
        "measured_roots[lane].rglob",
        "expected_lane_root(lane).resolve()",
    )
    document_contract = "runs/thesis/runner/<lane>/<phase6-extended-control>"

    def assert_contract(
        extended_source: str,
        phase7_source: str,
        document_sources: tuple[str, str],
    ) -> None:
        _assert_source_contract(extended_source, extended_contract)
        _assert_source_contract(phase7_source, phase7_contract)
        for document in document_sources:
            assert document_contract in document

    assert_contract(extended, phase7, documents)
    reverted = extended.replace("\n        / control_root.name", "", 1)
    assert reverted != extended
    with pytest.raises(AssertionError):
        assert_contract(reverted, phase7, documents)


def test_phase6_extended_final_event_uses_dynamic_typed_terminal_count() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_extended_measured.sh.in"
    ).read_text(encoding="utf-8")
    dynamic_event = (
        'f"measured_complete={len(complete)}, failed={len(failed)}, "\n'
        '            f"typed_terminals={len(TERMINALS)}",'
    )

    def assert_contract(candidate: str) -> None:
        assert "TERMINALS.update(typed_terminal_dispositions)" in candidate
        assert dynamic_event in candidate
        assert "typed_terminals=6" not in candidate

    assert_contract(source)
    mutated = source.replace(
        "typed_terminals={len(TERMINALS)}",
        "typed_terminals=6",
        1,
    )
    assert mutated != source
    with pytest.raises(AssertionError):
        assert_contract(mutated)


def test_core_follow_on_terminals_match_campaign_documents() -> None:
    project = Path(__file__).parents[2]
    templates = project / "experiments" / "local_campaign" / "templates"
    finalizer = (templates / "phase5_finalize_gate5.sh.in").read_text(
        encoding="utf-8"
    )
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    documents = {
        "plan": (project / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
            encoding="utf-8"
        ),
        "runbook": (project / "experiments" / "RUN_AND_RETURN.md").read_text(
            encoding="utf-8"
        ),
        "controller README": (
            project / "experiments" / "local_campaign" / "README.md"
        ).read_text(encoding="utf-8"),
    }
    runnable = (
        "bridge-pyrit",
        "bridge-deepteam",
        "bridge-h4rm3l",
        "bridge-spikee",
        "bridge-purplellama",
        "harmbench-replay",
    )
    core_terminals = ("bridge-nanogcg", "bridge-ideator", "t3mp3st")
    document_contract = (
        "The core cohort records `bridge-nanogcg`, `bridge-ideator`, and "
        "`t3mp3st` as `unavailable` only because their prepared artifacts are "
        "assigned to a separate follow-on cohort",
        "This is not a current capability disposition",
        "does not schedule those three lanes for core-cohort measured execution",
        "prepared artifact, no-call projection, diagnostic canary, Gate 5 record, "
        "and measured schedule",
    )

    def assert_contract(
        finalizer_source: str,
        extended_source: str,
        document_sources: dict[str, str],
    ) -> None:
        finalizer_order = finalizer_source.split(
            "EXPECTED_BRIDGE_LANES = frozenset({", 1
        )[1].split("})", 1)[0]
        extended_order = extended_source.split("BRIDGE_ORDER = [", 1)[1].split(
            "]", 1
        )[0]
        for lane in runnable:
            assert f'"{lane}"' in finalizer_order
            assert f'"{lane}"' in extended_order
        for lane in core_terminals:
            assert f'"{lane}"' not in finalizer_order
            assert f'"{lane}"' not in extended_order
            assert f'"{lane}": "unavailable"' in finalizer_source
            assert f'"{lane}": "unavailable"' in extended_source
        for source in document_sources.values():
            flat = " ".join(source.split())
            for required in document_contract:
                assert required in flat

    assert_contract(finalizer, extended, documents)

    controller_mutations = (
        (
            finalizer.replace(
                '"bridge-ideator": "unavailable"',
                '"bridge-ideator": "runnable"',
                1,
            ),
            extended,
        ),
        (
            finalizer,
            extended.replace(
                '"bridge-pyrit", "bridge-deepteam"',
                '"bridge-pyrit", "bridge-ideator", "bridge-deepteam"',
                1,
            ),
        ),
        (
            finalizer,
            extended.replace(
                '"bridge-purplellama", "harmbench-replay",',
                '"bridge-purplellama",',
                1,
            ),
        ),
    )
    for changed_finalizer, changed_extended in controller_mutations:
        assert (changed_finalizer, changed_extended) != (finalizer, extended)
        with pytest.raises(AssertionError):
            assert_contract(changed_finalizer, changed_extended, documents)

    for required in document_contract:
        changed_documents = dict(documents)
        flat_plan = " ".join(changed_documents["plan"].split())
        changed_documents["plan"] = flat_plan.replace(
            required, "MUTATED_FROZEN_COHORT_CONTRACT", 1
        )
        assert changed_documents["plan"] != flat_plan
        with pytest.raises(AssertionError):
            assert_contract(finalizer, extended, changed_documents)


def test_ollama_bounded_lane_identity_is_used_by_every_workflow_stage() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_ollama_workflow.sh.in"
    ).read_text(encoding="utf-8")

    assert source.count(
        'static_lane="ollama-${label}-text-primary-50"'
    ) == 3
    assert 'static_lane="ollama-${label}-text-exploratory-50"' not in source
    assert 'static_lane="ollama-${label}-text-full"' not in source
    assert '"num_ctx": num_ctx' in source
    assert '"num_predict": num_predict' in source
    assert 'if num_ctx != 8192 or num_predict != 512:' in source


def test_rendered_ollama_roster_validator_imports_json(tmp_path: Path) -> None:
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    shell = (output / "phase5_ollama_workflow.sh").read_text(encoding="utf-8")
    function = shell.split("verify_live_roster() {", 1)[1].split(
        "\n}\n\nroster_args=()", 1
    )[0]
    match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", function, re.DOTALL)
    assert match is not None

    imports = match.group(1).split("\nitems = sys.argv[1:]", 1)[0]
    namespace: dict[str, object] = {}
    exec(
        compile(
            imports + '\nserialized = json.dumps({"available": True})',
            "phase5_ollama_verify_live_roster.py",
            "exec",
        ),
        namespace,
    )
    assert namespace["serialized"] == '{"available": true}'


def test_rendered_ollama_projection_validator_imports_its_dependencies(
    tmp_path: Path,
) -> None:
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    shell = (output / "phase5_ollama_workflow.sh").read_text(encoding="utf-8")
    function = shell.split("projection_fields() {", 1)[1].split(
        "\n}\n\ncompare_projections()", 1
    )[0]
    match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", function, re.DOTALL)
    assert match is not None

    imports = match.group(1).split("\nroot = pathlib.Path", 1)[0]
    namespace: dict[str, object] = {}
    exec(
        compile(
            imports,
            "phase5_ollama_projection_fields.py",
            "exec",
        ),
        namespace,
    )
    for name in (
        "hashlib",
        "os",
        "_bounded_nofollow_read",
        "validate_eligibility_plan",
        "validate_lane_projection_binding",
        "strict_json_loads",
    ):
        assert name in namespace


def test_current_ollama_roles_compile_in_rendered_analysis_controllers(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    for name in ("phase7_analysis.py", "phase8_human_audit.py"):
        source = (output / name).read_text(encoding="utf-8")
        compile(source, name, "exec")
        assert "CURRENT_OLLAMA_NATIVE_ROLES" in source


def test_rendered_phase6_runtime_validators_import_their_used_globals(
    tmp_path: Path,
) -> None:
    import ast
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)

    cases = (
        (
            "phase6_core_measured.sh",
            "def defense_conditional_variant_for_row(",
            {"Mapping"},
            "from typing import Any, Mapping",
            "from typing import Any",
        ),
        (
            "phase6_sequence.sh",
            'started_at = launch.get("started_at_utc")',
            {"re"},
            "import re",
            "",
        ),
    )

    def assert_imported(block: str, required: set[str]) -> None:
        tree = ast.parse(block)
        imported: set[str] = set()
        loaded = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.update(alias.asname or alias.name for alias in node.names)
        assert required <= loaded
        assert required <= imported

    for filename, marker, required, original, replacement in cases:
        shell = (output / filename).read_text(encoding="utf-8")
        blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", shell, re.DOTALL)
        matches = [block for block in blocks if marker in block]
        assert len(matches) == 1
        block = matches[0]
        assert_imported(block, required)

        mutation = block.replace(original, replacement, 1)
        assert mutation != block
        with pytest.raises(AssertionError):
            assert_imported(mutation, required)


def test_gate5_revalidates_nested_samples_without_inventing_projection_fields() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    finalizer = (root / "phase5_finalize_gate5.sh.in").read_text(encoding="utf-8")
    promoter = (root / "phase5_promote_gate5.sh.in").read_text(encoding="utf-8")
    finalizer_required = (
        'BOUNDED_SELECTION_METHOD = "seeded_nested_source_cluster_prefix_v1"',
        'audit.get("selection_method") != BOUNDED_SELECTION_METHOD',
        'load_corpus_with_audit(',
        'for bounded_arm in request_arms:',
        '"full_converted_corpus_sha256"',
        'not set(canary_clusters).issubset(set(bounded_clusters))',
        'revalidate_nested_selection(',
    )
    promoter_required = (
        'BOUNDED_SELECTION_METHOD = "seeded_nested_source_cluster_prefix_v1"',
        'or arm.get("limit") != expected_limit',
        'tests.append(("bounded_selection_limit", wrong_selection_limit))',
        '"selection_method": BOUNDED_SELECTION_METHOD',
    )
    _assert_source_contract(finalizer, finalizer_required)
    _assert_source_contract(promoter, promoter_required)
    assert 'selected_arm.get("selection_method")' not in finalizer
    assert 'arm.get("selection_method")' not in promoter
    assert (
        'for field in ("converter", "selected_converted_corpus_sha256", "sample_seed")'
        not in finalizer
    )
    for source, required, original in (
        (
            finalizer,
            finalizer_required,
            'not set(canary_clusters).issubset(set(bounded_clusters))',
        ),
        (
            finalizer,
            finalizer_required,
            'for bounded_arm in request_arms:',
        ),
        (
            promoter,
            promoter_required,
            'tests.append(("bounded_selection_limit", wrong_selection_limit))',
        ),
    ):
        changed = source.replace(original, "MUTATED_SAMPLING_CONTRACT", 1)
        assert changed != source
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)


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
    assert "self.lifecycle_eligibility_args_for_roots(roots)" in level1
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
    assert "phase6-campaign-terminal-inventory-109-row-union" in value["contracts"]
    rendered = (output / "phase7_analysis.py").read_text(encoding="utf-8")
    rr_prerequisite = (
        "                    ADAPTIVITY_RIGHT_LANE,\n"
        "                    LLAVA_RR_IMAGE_LANE,\n"
    )
    assert rr_prerequisite in rendered
    mutant = rendered.replace(
        rr_prerequisite,
        "                    ADAPTIVITY_RIGHT_LANE,\n",
        1,
    )
    mutant_path = output / "phase7_analysis-rr-prerequisite-mutant.py"
    mutant_path.write_text(mutant, encoding="utf-8")
    rejected = subprocess.run(
        [sys.executable, str(mutant_path), "contract-self-test"],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode != 0
    assert "analysis prerequisite lane inventory changed" in (
        rejected.stdout + rejected.stderr
    )


def test_phase7_requires_current_ollama_terminal_and_metric_cohort() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    analysis = (root / "phase7_analysis.py.in").read_text(encoding="utf-8")
    wrapper = (root / "phase7_analysis.sh.in").read_text(encoding="utf-8")
    watcher = (root / "phase7_after_phase6_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    required_analysis = (
        '"current_ollama": (',
        'current_ollama=current_ollama,',
        '"current_ollama": current_ollama,',
        'def _current_ollama_metric_lanes(self)',
        'self.record_current_ollama_outcomes()',
        '"current_ollama_target_execution"',
        '"phase6-campaign-terminal-inventory-109-row-union"',
        "if CAMPAIGN_TOTAL_ROWS != 109:",
    )
    for token in required_analysis:
        assert token in analysis
    for token in (
        "--current-ollama-gate5-amendment",
        "--phase6-current-ollama-completion",
        "--phase6-current-ollama-recovery-completion",
    ):
        assert token in wrapper and token in watcher
    assert "validate_current_ollama_recovery_completion(" in analysis
    assert "current Ollama Phase 6 failures require their exact recovery completion" in analysis
    assert 'result.get("campaign_terminal_rows") != 109' in watcher
    assert '"current_ollama": 14' in watcher

    mutant = analysis.replace('"current_ollama": current_ollama,', "", 1)
    assert mutant != analysis
    with pytest.raises(AssertionError):
        for token in required_analysis:
            assert token in mutant


def test_phase7_requires_vllm_failure_and_input_recovery_as_separate_strata() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    analysis = (root / "phase7_analysis.py.in").read_text(encoding="utf-8")
    wrapper = (root / "phase7_analysis.sh.in").read_text(encoding="utf-8")
    watcher = (root / "phase7_after_phase6_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    required_analysis = (
        "validate_vllm_stability_completion(",
        "vllm_input_recovery_phase6 import (",
        'vllm_stability.get("input_recovery_completion")',
        'vllm_stability["metric_project_revision_receipt_sha256"][lane]',
        '"vllm_stability": vllm_stability,',
        'vllm_stability=vllm_stability,',
        "def _vllm_stability_metric_lanes(self)",
        "self.record_vllm_stability_outcomes()",
        '"vllm_stability": len(VLLM_STABILITY_UNIT_LAYOUT)',
        '"phase6-campaign-terminal-inventory-109-row-union"',
    )
    for token in required_analysis:
        assert token in analysis
    for token in (wrapper, watcher):
        assert "--phase6-vllm-stability-completion" in token
        assert "--phase6-vllm-input-recovery-completion" in token
    assert '"vllm_stability": 7' in watcher

    mutant = analysis.replace('"vllm_stability": vllm_stability,', "", 1)
    assert mutant != analysis
    with pytest.raises(AssertionError):
        for token in required_analysis:
            assert token in mutant


def test_phase7_requires_current_ollama_stability_as_a_separate_stratum() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    analysis = (root / "phase7_analysis.py.in").read_text(encoding="utf-8")
    wrapper = (root / "phase7_analysis.sh.in").read_text(encoding="utf-8")
    watcher = (root / "phase7_after_phase6_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    required = (
        "validate_current_ollama_stability_completion(",
        '"current_ollama_stability": current_ollama_stability,',
        "current_ollama_stability=current_ollama_stability,",
        "def _current_ollama_stability_metric_lanes(self)",
        "self.record_current_ollama_stability_outcomes()",
        '"current_ollama_stability": len(CURRENT_OLLAMA_STABILITY_LAYOUT)',
        '"phase6-campaign-terminal-inventory-109-row-union"',
    )
    for token in required:
        assert token in analysis
    for token in (wrapper, watcher):
        assert "--phase6-current-ollama-stability-completion" in token
    assert '"current_ollama_stability": 14' in watcher
    mutant = analysis.replace(
        '"current_ollama_stability": current_ollama_stability,', "", 1
    )
    assert mutant != analysis
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant


def test_phase7_requires_matched_ollama_population_alignment() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    analysis = (root / "phase7_analysis.py.in").read_text(encoding="utf-8")
    wrapper = (root / "phase7_analysis.sh.in").read_text(encoding="utf-8")
    watcher = (root / "phase7_after_phase6_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    required = (
        "validate_current_ollama_alignment_completion(",
        '"current_ollama_population_alignment": (',
        "current_ollama_population_alignment=(",
        "def _current_ollama_alignment_metric_lanes(self)",
        "self.record_current_ollama_alignment_outcomes()",
        '"current_ollama_population_alignment": len(CURRENT_OLLAMA_ALIGNMENT_LANES)',
        '"phase6-campaign-terminal-inventory-109-row-union"',
    )
    for token in required:
        assert token in analysis
    flag = "--phase6-current-ollama-population-alignment-completion"
    assert flag in wrapper and flag in watcher
    assert '"current_ollama_population_alignment": 12' in watcher
    assert 'result.get("campaign_terminal_rows") != 109' in watcher

    mutant = analysis.replace(
        '"current_ollama_population_alignment": (',
        '"removed_population_alignment": (',
        1,
    )
    assert mutant != analysis
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant


def test_phase7_docs_bind_exact_109_row_stability_partition() -> None:
    root = Path(__file__).parents[2]
    plan = (root / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
        encoding="utf-8"
    )
    runbook = (root / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )
    local_readme = (
        root / "experiments" / "local_campaign" / "README.md"
    ).read_text(encoding="utf-8")

    for document in (plan, runbook, local_readme):
        normalized = " ".join(document.split())
        assert "109" in normalized
        assert "14 current-Ollama stability" in normalized
        assert "12 current-Ollama population" in normalized
        assert "seven vLLM stability" in normalized
    assert "--phase6-current-ollama-stability-completion" in local_readme
    assert (
        "--phase6-current-ollama-population-alignment-completion"
        in local_readme
    )
    assert "83-row Phase 7 campaign union" not in local_readme


def test_phase8_replays_current_ollama_oracle_and_sampling_cohort() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase8_human_audit.py.in"
    ).read_text(encoding="utf-8")
    required = (
        '"validate_current_ollama_completion": (',
        '("current_ollama", keyword_only),',
        "oracle_current_ollama = oracle.validate_current_ollama_completion(",
        "current_ollama=oracle_current_ollama,",
        'or oracle_current_ollama != inputs.get("current_ollama")',
        '"current_ollama_terminal_states",',
        '"included_current_ollama_lanes",',
        '"ura-phase7-human-audit-sampling-view/6"',
        'current_ollama=support["current_ollama"],',
        '"validate_current_ollama_recovery_completion": (',
        "oracle.validate_current_ollama_recovery_completion(",
        '"validate_current_ollama_stability_completion": (',
        '("current_ollama_stability", keyword_only),',
        "oracle_current_ollama_stability = (",
        "current_ollama_stability=oracle_current_ollama_stability,",
        '!= inputs.get("current_ollama_stability")',
        '"current_ollama_stability_terminal_states",',
        '"included_current_ollama_stability_lanes",',
        'current_ollama_stability=support["current_ollama_stability"],',
        '"current_ollama_stability": support["current_ollama_stability"],',
        '"validate_current_ollama_alignment_completion": (',
        '("current_ollama_population_alignment", keyword_only),',
        "oracle_current_ollama_alignment = (",
        "current_ollama_population_alignment=(",
        '!= inputs.get("current_ollama_population_alignment")',
        '"current_ollama_population_alignment_terminal_states",',
        '"included_current_ollama_alignment_lanes",',
        '"current_ollama_population_alignment": support[',
        '"validate_vllm_stability_completion": (',
        '("vllm_stability", keyword_only),',
        "oracle_vllm_stability = oracle.validate_vllm_stability_completion(",
        'inputs["vllm_stability"]["input_recovery_completion"]',
        "vllm_stability=oracle_vllm_stability,",
        'or oracle_vllm_stability != inputs.get("vllm_stability")',
        '"vllm_stability_terminal_states",',
        '"included_vllm_stability_lanes",',
        'vllm_stability=support["vllm_stability"],',
        '"vllm_stability": support["vllm_stability"],',
    )
    for token in required:
        assert token in source

    mutant = source.replace("current_ollama=oracle_current_ollama,", "", 1)
    assert mutant != source
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant

    mutant = source.replace("vllm_stability=oracle_vllm_stability,", "", 1)
    assert mutant != source
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant


def test_rendered_phase8_current_ollama_contract_self_test(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    result = subprocess.run(
        [sys.executable, str(output / "phase8_human_audit.py"), "--self-test"],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_phase7_conditional_defense_uses_runner_eligibility_binding_shape() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")

    def assert_real_shape(candidate: str) -> None:
        assert 'eligibility_bindings = eligibility.get("bindings")' in candidate
        assert 'eligibility_bindings.get("experiment_conditions")' in candidate
        assert 'eligibility_v2["bindings"]["experiment_conditions"]' in candidate
        assert (
            'integer_age_eligibility["bindings"]["experiment_conditions"]'
            in candidate
        )
        assert 'mismatched_eligibility["bindings"][' in candidate

    assert_real_shape(source)
    reverted = source.replace(
        'eligibility_bindings = eligibility.get("bindings")',
        'experiment_conditions = eligibility.get("experiment_conditions")',
        1,
    )
    with pytest.raises(AssertionError):
        assert_real_shape(reverted)

    phase8 = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase8_human_audit.py.in"
    ).read_text(encoding="utf-8")
    assert 'eligibility_bindings = eligibility.get("bindings")' in phase8
    assert 'eligibility_bindings.get("experiment_conditions")' in phase8
    assert 'eligibility_v2["bindings"]["experiment_conditions"]' in phase8
    assert (
        'integer_age_eligibility["bindings"]["experiment_conditions"]'
        in phase8
    )
    assert 'mismatched_eligibility["bindings"][' in phase8


def test_phase6_phase7_rr_use_runner_eligibility_envelope_binding_shape() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    expected = {
        "phase6_core_measured.sh.in": (2, 1),
        "phase6_extended_measured.sh.in": (1, 0),
        "phase6_native_diagnostics.sh.in": (2, 0),
        "phase7_analysis.py.in": (1, 0),
        "phase8_human_audit.py.in": (1, 0),
    }
    direct = 'eligibility.get("bindings", {}).get("request_envelope")'
    stale = 'eligibility.get("bindings", {}).get("request_envelope_sha256")'
    content = 'eligibility_content.get("bindings", {}).get("request_envelope")'
    stale_content = (
        'eligibility_content.get("bindings", {}).get(\n'
        '                "request_envelope_sha256"\n'
        "            )"
    )

    def assert_real_shape(name: str, candidate: str) -> None:
        direct_count, content_count = expected[name]
        assert stale not in candidate
        assert stale_content not in candidate
        assert candidate.count(direct) == direct_count
        assert candidate.count(content) == content_count

    sources = {
        name: (root / name).read_text(encoding="utf-8") for name in expected
    }
    for name, source in sources.items():
        assert_real_shape(name, source)

    reverted = sources["phase7_analysis.py.in"].replace(direct, stale, 1)
    with pytest.raises(AssertionError):
        assert_real_shape("phase7_analysis.py.in", reverted)


def test_phase7_binds_rr_errors_to_actual_attestation_run_roots() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    expected_text = "error_path.parent != expected_text_error_root"
    expected_image = "image_error_path.parent != expected_image_error_root"
    stale_text = (
        'is_beneath(error_path, Path(evidence_roots["text_vllm_4096"]["path"]))'
    )

    def assert_actual_roots(candidate: str) -> None:
        assert expected_text in candidate
        assert expected_image in candidate
        assert stale_text not in candidate
        assert (
            'f"llava-rr-text-seed{seed}-{text_evidence_match.group(1)}"'
            in candidate
        )
        assert (
            'attestation_root / image_evidence_match.group(0) / "run"'
            in candidate
        )

    assert_actual_roots(source)
    reverted = source.replace(expected_text, stale_text, 1)
    with pytest.raises(AssertionError):
        assert_actual_roots(reverted)


def test_phase7_phase8_bind_historical_c926_and_separate_seven_amendment() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    sources = {
        name: (root / name).read_text(encoding="utf-8")
        for name in ("phase7_analysis.py.in", "phase8_human_audit.py.in")
    }
    value_check = (
        'finalization.get("target_runtime_terminal")\n'
        '        != profile["target_runtime_terminal"]'
    )
    type_check = (
        'type(finalization.get("target_runtime_terminal")) is not int'
    )

    def assert_current_receipt(candidate: str) -> None:
        assert candidate.count('"target_runtime_terminal",') >= 1
        assert value_check in candidate
        assert type_check in candidate
        assert "RR_RUNTIME_TERMINAL_LANES = (" in candidate
        assert (
            '"target_runtime_terminal": 7' in candidate
            or "HISTORICAL_GATE5_TARGET_RUNTIME_TERMINAL = 7" in candidate
        )
        assert "SEVEN_AMENDMENT_LANES = (" in candidate
        assert '"local-llava-rr-text-primary-100"' in candidate
        assert '"local-llava-rr-image-primary-100"' in candidate

    for source in sources.values():
        assert_current_receipt(source)

    reverted = sources["phase7_analysis.py.in"].replace(value_check, "", 1)
    with pytest.raises(AssertionError):
        assert_current_receipt(reverted)


def test_phase7_phase8_bind_archived_placeholder_to_its_new_path() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    sources = {
        name: (root / name).read_text(encoding="utf-8")
        for name in ("phase7_analysis.py.in", "phase8_human_audit.py.in")
    }
    archived = '"path": str(archive_path)'
    plan_path = '"path": str(runnote_path)'

    def assert_relocation_contract(candidate: str) -> None:
        assert archived in candidate
        assert plan_path in candidate
        assert '"state": "exact_placeholder"' in candidate
        assert "placeholder_archive_destination" in candidate

    for source in sources.values():
        assert_relocation_contract(source)

    reverted = sources["phase7_analysis.py.in"].replace(archived, plan_path, 1)
    with pytest.raises(AssertionError):
        assert_relocation_contract(reverted)


def test_phase6_core_binds_archived_placeholder_to_its_new_path() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")
    archived = 'artifact != {"path": str(archived_path), **placeholder_identity}'
    planned = '{"path": str(expected_canonical), **placeholder_identity}'

    def assert_relocation_contract(candidate: str) -> None:
        assert archived in candidate
        assert planned in candidate
        assert "or archive != artifact" in candidate

    assert_relocation_contract(source)
    reverted = source.replace(archived, planned, 1)
    with pytest.raises(AssertionError):
        assert_relocation_contract(reverted)


def test_phase6_core_reads_normalized_conditional_config_identities() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")
    normalized = 'get("normalized_selected_sha256", "")'
    raw = 'get("sha256", "")'

    def assert_normalized_identity_contract(candidate: str) -> None:
        start = candidate.index(
            'selected = conditions.get("selected_config_identities", {})'
        )
        end = candidate.index(
            'raise ValueError(f"{label}: defense-local conditional selection binding changed")',
            start,
        )
        contract = candidate[start:end]
        assert contract.count(normalized) == 2
        assert (
            'set(selected["source_config"]) != {"normalized_selected_sha256"}'
            in contract
        )
        assert (
            'set(selected["local_config"]) != {"normalized_selected_sha256"}'
            in contract
        )
        assert raw not in contract

    assert_normalized_identity_contract(source)
    reverted = source.replace(normalized, raw, 1)
    with pytest.raises(AssertionError):
        assert_normalized_identity_contract(reverted)


def test_phase6_core_reads_zero_downloads_from_acquisition_result() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")
    stale = 'receipt.get("downloaded_bytes")'

    def assert_receipt_schema_contract(candidate: str) -> None:
        start = candidate.index("def validate_defense_conditional_artifact(")
        end = candidate.index("def validate_rr_projection_field(", start)
        contract = candidate[start:end]
        assert stale not in contract
        assert "validate_acquisition_result_rows(" in contract
        assert '"downloaded_bytes", "receipt_id", "receipt_sha256"' in contract
        assert 'value.get("resource_identities") != expected_resources' in contract

    assert_receipt_schema_contract(source)
    mutated = source.replace(
        'value.get("resource_identities") != expected_resources',
        'receipt.get("downloaded_bytes") != 0\n'
        '        or value.get("resource_identities") != expected_resources',
        1,
    )
    with pytest.raises(AssertionError):
        assert_receipt_schema_contract(mutated)


def test_phase6_core_preserves_no_resource_gate5_acquisition_mode() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")
    no_resource_mode = (
        'raw_lane.get("acquisition_mode") == (\n'
        '            "not_applicable_no_managed_hub_resource"'
    )
    typed_na = '"downloaded_bytes": {"status": "N/A", "value": None}'

    def assert_acquisition_modes(candidate: str) -> None:
        start = candidate.index("for lane_id, raw_lane in manifest_lanes.items():")
        end = candidate.index("conditional_na_lanes =", start)
        contract = candidate[start:end]
        assert 'raw_lane.get("acquisition_mode") == "required_zero_download"' in contract
        assert no_resource_mode in contract
        assert typed_na in contract
        assert "or not acquisition_complete" in contract

    assert_acquisition_modes(source)
    mutated = source.replace(no_resource_mode, "False", 1)
    with pytest.raises(AssertionError):
        assert_acquisition_modes(mutated)


def test_phase6_local_attestations_use_realized_local_identity_schema() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    core = (root / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (root / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )

    core_start = core.index('expected_resolved = f"{target}@{revision}"')
    core_end = core.index("event \"$LANE\" attestation-probe complete", core_start)
    core_contract = core[core_start:core_end]
    stored_start = core.index(
        'expected_resolved = f"{spec[\'target\'][\'spec\']}@{spec[\'target\'][\'revision\']}"'
    )
    stored_end = core.index("expected_tail = [", stored_start)
    stored_contract = core[stored_start:stored_end]
    extended_start = extended.index("def validate_attestation_identity(")
    extended_end = extended.index("def derive_attestation(", extended_start)
    extended_contract = extended[extended_start:extended_end]

    assert "identity != expected_identity" in core_contract
    assert 'row["resolved_target"] != expected_resolved' in core_contract
    assert '"provider"' not in core_contract
    assert "identity != expected_identity" in stored_contract
    assert 'row["resolved_target"] != expected_resolved' in stored_contract
    assert '"provider"' not in stored_contract
    assert "identity != expected_identity" in extended_contract
    assert 'record["resolved_target"] != expected_resolved' in extended_contract
    assert '"provider"' not in extended_contract

    mutated_contract = core_contract.replace(
        "identity != expected_identity",
        'identity.get("provider") != "vllm"',
        1,
    )
    with pytest.raises(AssertionError):
        assert '"provider"' not in mutated_contract

    stored_mutated_contract = stored_contract.replace(
        "identity != expected_identity",
        'identity.get("provider") != "vllm"',
        1,
    )
    with pytest.raises(AssertionError):
        assert '"provider"' not in stored_mutated_contract


def test_phase6_core_validates_materialized_probe_group_keys() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")
    start = source.index('probe_request = probe_envelope["request"]')
    end = source.index("del probe_receipt", start)
    contract = source[start:end]
    expected = (
        'probe_request.get("group_keys") != [\n'
        '        "model", "source", "risk", "effective_modality", "expected_behavior",\n'
        '        "attacker", "source_policy_id", "source_policy_version",\n'
        "    ]"
    )
    assert expected in contract

    mutated = source.replace(
        expected,
        'probe_request.get("group_keys")\n'
        '    != "model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version"',
        1,
    )
    mutated_contract = mutated[start:mutated.index("del probe_receipt", start)]
    with pytest.raises(AssertionError):
        assert expected in mutated_contract


def test_phase6_core_attestation_probe_uses_local_guardrail_fallback() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")

    def assert_probe_contract(candidate: str) -> None:
        shell_start = candidate.index("    probe_args=(")
        shell_end = candidate.index(
            '    event "$LANE" attestation-probe complete', shell_start
        )
        shell_contract = candidate[shell_start:shell_end]
        state_start = candidate.index("probe_target_resources = {")
        state_end = candidate.index("del probe_receipt", state_start)
        state_contract = candidate[state_start:state_end]
        assert "--judges rules,guardrail" in shell_contract
        assert "--guardrail-model meta-llama/Llama-Guard-3-8B" in shell_contract
        assert "--guardrail-revision 7327bd9f6efbbe6101dc6cc4736302b3cbb6e425" in shell_contract
        assert "--guardrail-device cuda:1" in shell_contract
        assert '"$PROBE_RECEIPT_PATH" "$PROBE_RECEIPT_SHA" target_and_guard' in shell_contract
        assert '["guardrail_judge"]' in state_contract
        assert 'probe_judges == ["rules"]' in state_contract
        assert 'probe_judges == ["rules", "guardrail"]' in state_contract
        assert "expected_resources=(probe_target_resources, probe_guard_resources)" in state_contract
        assert "observed_probe_resources != expected_probe_resources" in state_contract
        assert '"meta-llama/Llama-Guard-3-8B"' in state_contract
        assert '"7327bd9f6efbbe6101dc6cc4736302b3cbb6e425"' in state_contract
        assert 'probe_request.get("guardrail_model")' not in state_contract

    assert_probe_contract(source)
    mutated = source.replace(
        "      --judges rules,guardrail\n      --guardrail-model",
        "      --judges rules\n      --guardrail-model",
        1,
    )
    with pytest.raises(AssertionError):
        assert_probe_contract(mutated)
    stale_request_field = source.replace(
        "elif probe_judges == [\"rules\", \"guardrail\"]:\n"
        "    expected_probe_resources = probe_guard_resources",
        "elif probe_judges == [\"rules\", \"guardrail\"]:\n"
        "    expected_probe_resources = probe_guard_resources\n"
        "    probe_request.get(\"guardrail_model\")",
        1,
    )
    with pytest.raises(AssertionError):
        assert_probe_contract(stale_request_field)


def test_phase6_recovery_attestation_probes_keep_local_guardrail_fallback() -> None:
    templates = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    for name in (
        "phase6_core_length_recovery.py.in",
        "phase6_seven_output_policy.py.in",
    ):
        source = (templates / name).read_text(encoding="utf-8")
        start = source.index("def derive_core_attestation(")
        end = source.index("\ndef ", start + 5)
        contract = source[start:end]
        assert '"--judges", "rules,guardrail"' in contract
        assert '"--guardrail-model", "meta-llama/Llama-Guard-3-8B"' in contract
        assert (
            '"--guardrail-revision", '
            '"7327bd9f6efbbe6101dc6cc4736302b3cbb6e425"'
        ) in contract
        assert '"--guardrail-device", "cuda:1"' in contract
        assert '"target_and_guard"' in contract

    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    start = extended.index("def derive_attestation(")
    end = extended.index("\ndef ", start + 5)
    contract = extended[start:end]
    assert '"--judges", "rules,guardrail"' in contract
    assert '"--guardrail-model", GUARD' in contract
    assert '"--guardrail-revision", GUARD_REV' in contract
    assert '"--guardrail-device", "cuda:1"' in contract
    assert '"target_and_guard"' in contract
    assert 'else "guard_only"' in contract
    assert "argv.extend(acquisition_args(probe_acquisition))" in contract

    documentation = {
        name: " ".join((templates.parents[1] / name).read_text(encoding="utf-8").split())
        for name in (
            "LOCAL_CAMPAIGN_PLAN.md",
            "RUN_AND_RETURN.md",
            "local_campaign/README.md",
        )
    }
    assert "rules,guardrail" in documentation["LOCAL_CAMPAIGN_PLAN.md"]
    assert "target plus guard for vLLM targets" in documentation[
        "LOCAL_CAMPAIGN_PLAN.md"
    ]
    assert "target and scoring guard" in documentation["RUN_AND_RETURN.md"]
    assert "Ollama probe's acquisition contains the scoring guard" in documentation[
        "RUN_AND_RETURN.md"
    ]
    assert "`target_and_guard` for vLLM" in documentation[
        "local_campaign/README.md"
    ]
    assert "`guard_only` for Ollama" in documentation["local_campaign/README.md"]


def test_phase6_core_owned_commands_preserve_here_document_stdin() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_core_measured.sh.in"
    ).read_text(encoding="utf-8")

    def assert_stdin_contract(candidate: str) -> None:
        function = candidate.split("run_owned() {", 1)[1].split("\n}\n", 1)[0]
        assert '"$@" <&0 &' in function
        assert 'run_owned "$PY" - "$COMPLETION"' in candidate

    assert_stdin_contract(source)
    reverted = source.replace('"$@" <&0 &', '"$@" &', 1)
    with pytest.raises(AssertionError):
        assert_stdin_contract(reverted)


def test_phase6_sequence_recovers_only_content_identical_sealed_lane_state() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    sequence = (root / "phase6_sequence.sh.in").read_text(encoding="utf-8")
    core = (root / "phase6_core_measured.sh.in").read_text(encoding="utf-8")

    assert 'IFS=: read -r -a core_recovery_roots <<< "$PHASE6_CORE_RECOVERY_ROOTS"' in sequence
    assert 'core_recovery_args+=(--recover-lane-state-from "$core_recovery_root")' in sequence
    assert '--recover-lane-state-from)' in core
    assert 'event "$LANE" resume-state imported' in core
    assert 'current_spec_payload != old_spec_payload' in core
    assert 'for artifact_field in ("plan", "receipt")' in core
    assert 'path_replacements[str(source_artifact)] = str(target_artifact)' in core
    assert 'state["runner_argv"] = [path_replacements.get(item, item) for item in runner_argv]' in core
    assert '"schema": "ura-phase6-core-state-import/1"' in core
    assert 'RECOVERY_STATE_ROOTS+=("$2")' in core
    assert 'RECOVERY_STATE_ROOTS_SERIALIZED=$(printf \'%q\' "$RECOVERY_STATE_ROOTS_SERIALIZED")' in core

    mutated = core.replace(
        "current_spec_payload != old_spec_payload",
        "False",
        1,
    )
    with pytest.raises(AssertionError):
        assert "current_spec_payload != old_spec_payload" in mutated
    stale_locators = core.replace(
        'state["runner_argv"] = [path_replacements.get(item, item) for item in runner_argv]',
        'state["runner_argv"] = runner_argv',
        1,
    )
    with pytest.raises(AssertionError):
        assert 'state["runner_argv"] = [path_replacements.get(item, item) for item in runner_argv]' in stale_locators


def test_phase6_sequence_adopts_only_exact_terminal_measured_launches() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")

    core_required = (
        'if [[ -n "${PHASE6_CORE_ADOPT_LAUNCH-}" ]]; then',
        'test -z "${PHASE6_CORE_RECOVERY_ROOTS-}"',
        'test -f "$PHASE6_CORE_ADOPT_LAUNCH" && test ! -L "$PHASE6_CORE_ADOPT_LAUNCH"',
        'test "$adopted_core_launch" = "$PHASE6_CORE_ADOPT_LAUNCH"',
        '"$URA_WORK"/runs/engineering/phase6-sequence-*/core.launch.txt)',
        'test "$(stat -c \'%a\' -- "$adopted_core_launch")" = \'600\'',
        'test "$(stat -c \'%h\' -- "$adopted_core_launch")" = \'1\'',
        'cmp -s -- "$adopted_core_launch" "$CORE_LAUNCH"',
        'wait_for_child core "$CORE" "$CORE_SHA256" "$CORE_BYTES" "$CORE_LAUNCH"',
    )
    extended_required = (
        'if [[ -n "${PHASE6_EXTENDED_ADOPT_LAUNCH-}" ]]; then',
        'test -f "$PHASE6_EXTENDED_ADOPT_LAUNCH" '
        '&& test ! -L "$PHASE6_EXTENDED_ADOPT_LAUNCH"',
        'test "$adopted_extended_launch" = "$PHASE6_EXTENDED_ADOPT_LAUNCH"',
        '"$URA_WORK"/runs/engineering/phase6-sequence-*/extended.launch.txt)',
        'test "$(stat -c \'%a\' -- "$adopted_extended_launch")" = \'600\'',
        'test "$(stat -c \'%h\' -- "$adopted_extended_launch")" = \'1\'',
        'cmp -s -- "$adopted_extended_launch" "$EXTENDED_LAUNCH"',
        'wait_for_child extended "$EXTENDED" "$EXTENDED_SHA256"',
    )
    native_required = (
        'if [[ -n "${PHASE6_NATIVE_ADOPT_LAUNCH-}" ]]; then',
        'test -f "$PHASE6_NATIVE_ADOPT_LAUNCH" '
        '&& test ! -L "$PHASE6_NATIVE_ADOPT_LAUNCH"',
        'test "$adopted_native_launch" = "$PHASE6_NATIVE_ADOPT_LAUNCH"',
        '"$URA_WORK"/runs/engineering/phase6-sequence-*/native.launch.txt)',
        'adopted_native_plan="$adopted_native_root/native-plan.json"',
        'adopted_native_plan_result="$adopted_native_root/native-plan-result.json"',
        'cmp -s -- "$adopted_native_plan" "$NATIVE_PLAN"',
        'cmp -s -- "$adopted_native_plan_result" "$NATIVE_PLAN_RESULT"',
        'cmp -s -- "$adopted_native_launch" "$NATIVE_LAUNCH"',
        'wait_for_child native "$NATIVE" "$NATIVE_SHA256" "$NATIVE_BYTES"',
    )

    def assert_adoption_contract(candidate: str) -> None:
        for item in (*core_required, *extended_required, *native_required):
            assert item in candidate
        native_adoption = candidate.split(native_required[0], 1)[1].split(
            "else", 1
        )[0]
        assert 'bash "$NATIVE"' not in native_adoption

    assert_adoption_contract(source)
    for item in (*core_required[:-1], *extended_required[:-1], *native_required[:-1]):
        mutated = source.replace(item, "removed-adoption-check", 1)
        with pytest.raises(AssertionError):
            assert_adoption_contract(mutated)


def test_phase6_sequence_uses_gate5_identity_for_measured_children() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")
    source = source.split("validate_child_now() {", 1)[1].split(
        "declare -A CHILD_SESSION", 1
    )[0]
    required = (
        'gate5_code_identity = gate5.get("code_identity")',
        'set(gate5_code_identity) != {"expected_commit", "framework_lock_id"}',
        'gate5_code_identity.get("framework_lock_id") != lock',
        'if kind in {"core", "extended"}:\n'
        '    code_identity = gate5_code_identity',
        "else:\n    code_identity = phase7.native_code_identity_from_completion(completion)",
        'if code_identity["framework_lock_id"] != lock:',
        '"code_identity": code_identity,',
    )

    def assert_identity_contract(candidate: str) -> None:
        _assert_source_contract(candidate, required)

    assert_identity_contract(source)
    for item in required[:-1]:
        mutated = source.replace(item, "False", 1)
        with pytest.raises(AssertionError):
            assert_identity_contract(mutated)


def test_phase6_sequence_preserves_validated_historical_gate5_identity() -> None:
    source = _template_source("phase6_sequence.sh.in")
    aggregate = source.split(
        'gate5_initial = strict_json(gate5_validation_value, "initial Gate 5 validation")',
        1,
    )[1].split('launch = strict_json(launch_value, "Phase 6 sequence launch")', 1)[0]
    required = (
        'gate5_code_identity = gate5_initial.get("code_identity")',
        'set(gate5_code_identity) != {"expected_commit", "framework_lock_id"}',
        'r"[0-9a-f]{40}", str(gate5_code_identity.get("expected_commit"))',
        'gate5_code_identity.get("framework_lock_id") != lock',
    )

    def assert_historical_identity_contract(candidate: str) -> None:
        _assert_source_contract(candidate, required)
        assert '{"expected_commit": commit, "framework_lock_id": lock}' not in candidate

    assert_historical_identity_contract(aggregate)
    reverted = aggregate.replace(
        'not isinstance(gate5_code_identity, dict)',
        'gate5_code_identity != {"expected_commit": commit, "framework_lock_id": lock}',
        1,
    )
    with pytest.raises(AssertionError):
        assert_historical_identity_contract(reverted)


def test_phase6_sequence_passes_the_validated_gate5_profile_to_core() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        'if kind == "core":',
        'gate5 = phase7.strict_object(Path(manifest_value))',
        'kwargs["gate5_profile"] = phase7.gate5_inventory_profile(',
        'gate5["lanes"], label="Phase 6 sequence validated Gate 5 manifest"',
        'validated = validators[kind](**kwargs)',
    )

    def assert_profile_contract(candidate: str) -> None:
        _assert_source_contract(candidate, required)

    assert_profile_contract(source)
    reverted = source.replace(
        'kwargs["gate5_profile"] = phase7.gate5_inventory_profile(',
        'phase7.gate5_inventory_profile(',
        1,
    )
    with pytest.raises(AssertionError):
        assert_profile_contract(reverted)


def test_phase6_sequence_core_inventory_is_exact_but_order_independent() -> None:
    source = _template_source("phase6_sequence.sh.in")
    block = "def require_exact_core_inventory" + source.split(
        "def require_exact_core_inventory", 1
    )[1].split("steps = checked_file", 1)[0]
    rr_terminal_lanes = (
        "local-llava-rr-text-full",
        "local-llava-rr-image-full",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    )
    namespace = {
        "CORE_CANDIDATE_ORDER": [
            "local-qwen3-vl-text-primary-100",
            "local-qwen3-vl-image-primary-100",
            "local-llava-base-text-primary-100",
            "local-llava-base-image-primary-100",
            "local-llava-rr-text-full",
            "local-llava-rr-image-full",
            "rjudge-qwen3-vl",
            "rjudge-llava-base",
            "rjudge-llava-rr",
            "gptgeochat-qwen3-vl",
            "gptgeochat-llava-base",
            "gptgeochat-llava-rr",
            "crescendo-qwen3-vl",
            "defense-local",
        ],
        "RR_TERMINAL_LANES": rr_terminal_lanes,
        "RR_TERMINAL_LANE_SET": set(rr_terminal_lanes),
    }
    exec(compile(block, "<phase6-core-inventory>", "exec"), namespace)

    reverted = block.replace(
        "or set(states) != set(expected)", "or list(states) != expected", 1
    )
    assert reverted != block
    with pytest.raises(SystemExit, match="core inventory differs"):
        exec(compile(reverted, "<phase6-core-inventory-reverted>", "exec"), namespace)


def test_phase7_validates_controller_gate5_copies_by_location_and_bytes() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")

    core = source.split("def validate_core_controller(", 1)[1].split(
        "def validate_extended_controller(", 1
    )[0]
    extended = source.split("def validate_extended_controller(", 1)[1].split(
        "def validate_native_controller(", 1
    )[0]
    native = source.split("def validate_native_controller(", 1)[1].split(
        "def build_runner_input_view(", 1
    )[0]

    def assert_copy_contract(candidate: tuple[str, str, str]) -> None:
        core_value, extended_value, native_value = candidate
        for value in (core_value, extended_value):
            before_launch = value.split("_validate_launch_gate5(", 1)[0]
            assert "require_gate5_input_identities(" not in before_launch
            assert "copied != authoritative_path" not in before_launch
            assert "_validate_launch_gate5(" in value
        assert "Phase 6 native Gate 5 input inventory changed" in native_value
        assert "if copied_payload != authoritative_payload:" in native_value
        assert "copied != authoritative_path" not in native_value
        assert '!= control / "inputs" / filename' in native_value

    values = (core, extended, native)
    assert_copy_contract(values)
    reverted_native = native.replace(
        "if copied_payload != authoritative_payload:",
        "if _copied != _authoritative_path or copied_payload != authoritative_payload:",
        1,
    )
    with pytest.raises(AssertionError):
        assert_copy_contract((core, extended, reverted_native))


def test_phase7_native_adoption_revalidates_only_whitelisted_history() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    helper = source.split("def native_code_identity_from_completion(", 1)[1].split(
        "\ndef ", 1
    )[0]
    native = source.split("def validate_native_controller(", 1)[1].split(
        "def _retained_descriptor(", 1
    )[0]

    def assert_history_contract() -> None:
        assert "RETAINED_PHASE6_PAYLOADS_BY_COMMIT.get(" in helper
        assert ').get("native")' in helper
        assert "RETAINED_NATIVE_OLLAMA_MODELS_BY_COMMIT.get(" in native
        assert "expected_native_models" in native
        assert "recheck_checkout=False" in native
        assert "native_project_path.parent != expected_project_root" in native
        assert "!= EXPECTED_PROJECT_REVISION_SHA256" not in native

    assert_history_contract()
    mutated = native.replace("recheck_checkout=False", "recheck_checkout=True", 1)
    assert mutated != native
    with pytest.raises(AssertionError):
        assert "recheck_checkout=False" in mutated


def test_phase6_failure_sealers_create_missing_runner_parent() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    core = (root / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (root / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )

    core_start = core.index("write_lane_failure() {")
    core_end = core.index("lane_attempt_finish() {", core_start)
    extended_start = extended.index("    def record_failure(")
    extended_end = extended.index("def parse_result_json(", extended_start)

    def assert_parent_creation(contract: str) -> None:
        assert "runner_container" in contract
        assert "os.mkdir(runner_parent, 0o700)" in contract
        assert "runner_parent.resolve(strict=True) != runner_parent" in contract

    assert_parent_creation(core[core_start:core_end])
    assert_parent_creation(extended[extended_start:extended_end])
    mutated = core.replace("os.mkdir(runner_parent, 0o700)", "pass", 1)
    mutated_end = mutated.index("lane_attempt_finish() {", core_start)
    with pytest.raises(AssertionError):
        assert_parent_creation(mutated[core_start:mutated_end])


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


def test_phase7_rr_pair_dispatch_is_conditioned_on_current_measured_cells() -> None:
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
    assert "non_estimable_llava_pair_value(" in rr_contrast
    llava_value_start = source.index("def non_estimable_llava_pair_value(")
    llava_value_end = source.index(
        "def validate_non_estimable_llava_pair(", llava_value_start
    )
    llava_value = source[llava_value_start:llava_value_end]
    assert '"modality": "image"' in llava_value
    assert "for corpus in IMAGE_ARMS:" in rr_contrast
    plan = rr_contrast.index("llava_pair_prerequisite_plan(")
    unavailable = rr_contrast.index('if not prerequisite_plan["runnable"]:')
    dispatch = rr_contrast.index('"experiments.paired_compare"')
    assert plan < unavailable < dispatch
    assert "return results" not in rr_contrast[:plan]
    assert "llava_comparison_runner(" in rr_contrast[:plan]
    assert "non_estimable_llava_pair_value(" in rr_contrast[unavailable:dispatch]
    assert "self._validate_non_estimable_rr_contrast(" in rr_contrast[unavailable:dispatch]
    failure_start = source.index("def runner_prerequisite_snapshot(")
    failure_end = source.index("def non_estimable_adaptivity_value(", failure_start)
    failure_contract = source[failure_start:failure_end]
    assert '"controller_failure": copy.deepcopy(failure)' in failure_contract
    assert '"failed_lane_metric_evidence_admitted": False' in failure_contract
    validator_start = source.index("    def _validate_non_estimable_rr_contrast(")
    validator = source[validator_start:start]
    assert "validate_non_estimable_llava_pair(" in validator
    rr_selector_binding = rr_contrast.index('rr_selector = selectors["llava_rr"]')
    assert unavailable < rr_selector_binding < dispatch
    assert 'selectors["llava_base"]' in rr_contrast[dispatch:]
    assert '"--right-model",\n                rr_selector,' in rr_contrast[dispatch:]
    assert "right_selector=rr_selector" in rr_contrast[dispatch:]
    identity_start = source.index("def validate_llava_pair_output_identity(")
    identity_end = source.index("\ndef ", identity_start + 4)
    identity = source[identity_start:identity_end]
    assert 'facet.get("comparison_type")' in identity
    assert '!= "cross_target_endpoint_noncausal"' in identity
    assert "allow_paired_validation_failure=True" in rr_contrast
    assert '"kind": "validation_failure"' in rr_contrast
    assert '"kind": "readiness_failure"' in rr_contrast
    assert '"paired_compare_validation_failed"' in source
    assert '"paired_compare_readiness_failed"' in source
    selector_start = source.index('"model_selectors": {')
    selector_end = source.index('"guardrail_selector":', selector_start)
    assert '"llava_rr"' in source[selector_start:selector_end]
    assert '"local-llava-rr-text-primary-100"' in source
    assert '"local-llava-rr-image-primary-100"' in source
    canonical_inventory = source[
        source.index("CORE_LANES = (") : source.index("RR_CURRENT_LANES = (")
    ]
    assert "local-llava-rr-text-full" in canonical_inventory
    assert "local-llava-rr-image-full" in canonical_inventory
    assert "local-llava-rr-text-primary-100" not in canonical_inventory
    assert "local-llava-rr-image-primary-100" not in canonical_inventory
    assert "local-llava-rr-text-full" not in rr_contrast
    assert "local-llava-rr-image-full" not in rr_contrast
    rr_terminal_start = source.index("RR_RUNTIME_TERMINAL_LANES = (")
    rr_terminal_end = source.index(
        "RR_RUNTIME_TERMINAL_LANE_SET", rr_terminal_start
    )
    rr_terminal_block = source[rr_terminal_start:rr_terminal_end]
    for lane in (
        "local-llava-rr-text-full",
        "local-llava-rr-image-full",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    ):
        assert f'"{lane}"' in rr_terminal_block
    for reason_code in (
        "left_base_lane_failed",
        "right_rr_lane_failed",
        "left_base_and_right_rr_lanes_failed",
    ):
        assert reason_code in source
    assert "RR_TARGET_IDENTITY_MARKERS" in source
    assert 'project_root / "experiments" / "local-llava-rr.json"' in source
    assert "RR_LOCAL_CONFIG_SHA256" in source
    assert "RR_OBSERVED_PROJECT_COMMIT" in source
    assert '"diff",' in source
    gate5_start = source.index("def validate_gate5(")
    gate5_end = source.index("def validate_exact_source_portfolio(", gate5_start)
    gate5 = source[gate5_start:gate5_end]
    assert "validate_rr_runtime_project_continuity(" in gate5
    assert "covered_commit=expected_commit" in gate5
    continuity_start = source.index("def validate_rr_runtime_project_continuity(")
    continuity_end = source.index("\ndef ", continuity_start + 4)
    continuity = source[continuity_start:continuity_end]
    assert "covered_commit: str" in continuity
    assert "RR_OBSERVED_PROJECT_COMMIT,\n            covered_commit," in continuity
    reverted_continuity = continuity.replace(
        "RR_OBSERVED_PROJECT_COMMIT,\n            covered_commit,",
        "RR_OBSERVED_PROJECT_COMMIT,\n            EXPECTED_COMMIT,",
        1,
    )
    assert reverted_continuity != continuity
    with pytest.raises(AssertionError):
        assert "RR_OBSERVED_PROJECT_COMMIT,\n            EXPECTED_COMMIT," not in (
            reverted_continuity
        )
    retained_start = source.index("RETAINED_PHASE6_PAYLOADS_BY_COMMIT = {")
    retained_end = source.index("\n\nCORE_LANES", retained_start)
    retained = source[retained_start:retained_end]
    retained_commit = "c62e027b0143d1db29c57f66605ac3d8dc23f11a"
    retained_core_sha = (
        "d4d7b17bab706665688b4fd49fc55eb7be9ac25906c21224805eff6accb6c755"
    )
    retained_extended_sha = (
        "e94c4be93eb1bfcd2e4b5c17cbb5fbaf32b56f97cdb55a4e3ff3ffaf501e2903"
    )
    retained_native_commit = "da062d0e2121ea2104b0c81374ef40f4f4f74473"
    retained_native_sha = (
        "393a53d174ee5ca0ef52ed9a8be0f0ed6acb784a037e62d03d55cf2e32a6ba9f"
    )
    for value in (
        retained_commit,
        retained_core_sha,
        retained_extended_sha,
        retained_native_commit,
        retained_native_sha,
        '"bytes": 303543',
        '"bytes": 330057',
        '"bytes": 172062',
    ):
        assert value in retained
    payload_start = source.index("def require_frozen_phase6_payload(")
    payload_end = source.index("\ndef ", payload_start + 4)
    payload_contract = source[payload_start:payload_end]
    assert "expected_commit: str" in payload_contract
    assert "expected_commit == EXPECTED_COMMIT" in payload_contract
    assert "RETAINED_PHASE6_PAYLOADS_BY_COMMIT.get(" in payload_contract
    assert "if expected is None:" in payload_contract
    assert source.count('expected_commit=code_identity["expected_commit"]') >= 3
    reverted_retained = retained.replace(retained_core_sha, "0" * 64, 1)
    assert reverted_retained != retained
    with pytest.raises(AssertionError):
        assert retained_core_sha in reverted_retained
    native_models_start = source.index("RETAINED_NATIVE_OLLAMA_MODELS_BY_COMMIT = {")
    native_models_end = source.index(
        "\nRETAINED_EXTENDED_LANE_PARENT_FAILURE_COMMIT", native_models_start
    )
    retained_native_models = source[native_models_start:native_models_end]
    for value in (
        retained_native_commit,
        "mollysama/rwkv-7-g1f:2.9b",
        "mollysama/rwkv-7-g1d:0.4b",
        "mollysama/rwkv-7-g1g:1.5b",
    ):
        assert value in retained_native_models
    rr_roots_start = source.index("rr_execution_roots = (")
    rr_roots_end = source.index("\n    )", rr_roots_start) + len("\n    )")
    rr_roots = source[rr_roots_start:rr_roots_end]
    assert 'control / "lane-specs"' in rr_roots
    assert 'control / "lanes"' in rr_roots
    assert "attempt," in rr_roots
    assert "runner_root" not in rr_roots
    reverted_rr_roots = rr_roots.replace(
        "        attempt,",
        "        attempt,\n        runner_root,",
        1,
    )
    assert reverted_rr_roots != rr_roots
    with pytest.raises(AssertionError):
        assert "runner_root" not in reverted_rr_roots
    conditional_start = source.index("forbidden_defense_paths = (")
    conditional_end = source.index("\n        )", conditional_start)
    conditional = source[conditional_start:conditional_end]
    assert "runner_root / DEFENSE_LOCAL_LANE" not in conditional
    assert '"10-defense-local.json"' in source
    assert '"14-defense-local.json"' not in source
    assert 'set(projection) != {"path", "file", "sha256", "bytes"}' in source
    assert (
        '{"path", "envelope_id", "file", "sha256", "bytes"}' in source
    )
    assert 'set(eligibility) != {"path", "sha256", "bytes"}' in source
    assert 'eligibility.get("bindings", {}).get("request_envelope")' in source
    assert '"records": eligibility_records' in source
    assert "RR projection artifact descriptor changed" in source
    assert "RR request-envelope identity changed" in source
    assert "candidate.lstat()" in source
    assert "not stat.S_ISREG(entry.st_mode)" in source
    assert "evidence member changed while reading" in source
    assert 'getattr(os, "O_NOFOLLOW", 0)' in source
    assert "members_after != members_before" in source
    assert "evidence root changed while reading" in source

    # Reverse mutation: restoring the old unconditional non-estimable branch
    # removes the paired comparison dispatch and must fail the current contract.
    reverted = rr_contrast.replace('"experiments.paired_compare"', '"obsolete"', 1)
    assert reverted != rr_contrast
    with pytest.raises(ValueError):
        reverted.index('"experiments.paired_compare"')


def test_phase7_llava_pair_contract_uses_the_selected_facet(
    tmp_path: Path,
) -> None:
    phase7 = _rendered_phase7_namespace(tmp_path)
    corpus = phase7["IMAGE_ARMS"][0]
    cluster = "source_cluster_id (fallback datapoint_id)"
    runner = {
        "model_selectors": {
            "llava_base": "vllm:fixture/llava-base",
            "llava_rr": "vllm:fixture/llava-rr",
        }
    }
    paired = {
        "schema_version": "1.0-faceted",
        "attacker": "replay",
        "requested_mode": "auto",
        "left_selector": {
            "model_spec": runner["model_selectors"]["llava_base"],
            "defense": "none",
        },
        "right_selector": {
            "model_spec": runner["model_selectors"]["llava_rr"],
            "defense": "none",
        },
        "facets": {
            corpus: {
                "comparison_type": "cross_target_endpoint_noncausal",
                "causal_effect_established": False,
                "analysis_ready_real_run": True,
                "pairing_unit": "datapoint_id x requested_seed",
                "inference_cluster": cluster,
                "unexplained_exclusions": 0,
                "static_exact_input_required": True,
                "analysis_readiness_checks": {"exact_pair_keys": True},
                "metrics": {
                    "ASR": {
                        "status": "estimated",
                        "inference_cluster": cluster,
                        "missingness_sensitivity": {"unit": cluster},
                        "bootstrap": {
                            "unit": cluster,
                            "statistic": (
                                "equal-weight mean of within-source-cluster left "
                                "means minus equal-weight mean of within-source-cluster "
                                "right means"
                            ),
                        },
                        "pairing_audit": {"unexplained_exclusions": 0},
                    }
                },
            }
        },
        "unavailable_facets": {},
        "unexplained_exclusions": 0,
    }
    phase7["validate_llava_pair_output_identity"](
        paired, runner=runner, corpus=corpus, unavailable=False
    )
    controller = object.__new__(phase7["AnalysisController"])
    status, _limitations = controller._validate_paired(
        value=paired, corpus=corpus, adaptivity=False
    )
    assert status == "complete"

    # Reverse mutation: a correct-looking top-level surrogate must not hide a
    # changed comparison type in the selected corpus facet.
    wrong_facet = json.loads(json.dumps(paired))
    wrong_facet["comparison_type"] = "cross_target_endpoint_noncausal"
    wrong_facet["facets"][corpus]["comparison_type"] = "within_target_adaptivity_endpoint"
    with pytest.raises(phase7["Phase7Error"], match="output identity differs"):
        phase7["validate_llava_pair_output_identity"](
            wrong_facet, runner=runner, corpus=corpus, unavailable=False
        )

    wrong_selector = json.loads(json.dumps(paired))
    wrong_selector["right_selector"]["model_spec"] = "vllm:fixture/other"
    with pytest.raises(phase7["Phase7Error"], match="output identity differs"):
        phase7["validate_llava_pair_output_identity"](
            wrong_selector, runner=runner, corpus=corpus, unavailable=False
        )


def test_phase7_completed_llava_pair_failure_is_strictly_non_estimable(
    tmp_path: Path,
) -> None:
    phase7 = _rendered_phase7_namespace(tmp_path)
    corpus = phase7["IMAGE_ARMS"][0]
    left = phase7["LLAVA_BASE_IMAGE_LANE"]
    right = phase7["LLAVA_RR_IMAGE_LANE"]
    runner = {
        "terminal_states": {left: "measured_complete", right: "measured_complete"},
        "lifecycle_states": {left: "complete", right: "complete"},
        "lifecycle_authorizations": {
            left: {
                "lifecycle_registry_status": "complete_runner_grid",
                "controller_failure": None,
            },
            right: {
                "lifecycle_registry_status": "complete_runner_grid",
                "controller_failure": None,
            },
        },
        "conditional_na_lanes": [],
    }
    log = tmp_path / "paired-validation.log"
    log.write_text(
        "paired comparison validation failed: requested corpus lacks one exact arm\n",
        encoding="utf-8",
    )
    evidence = {
        "kind": "validation_failure",
        "artifact": phase7["descriptor"](log),
    }
    value = phase7["non_estimable_llava_pair_value"](
        runner, corpus, paired_compare_evidence=evidence
    )
    assert value["schema"] == "ura-phase7-non-estimable-contrast/1"
    assert value["reason_code"] == "paired_compare_validation_failed"
    assert value["paired_compare_invoked"] is True
    assert value["missing_roles"] == []
    assert value["estimate"] is None
    assert value["human_audit_eligible"] is False
    phase7["validate_non_estimable_llava_pair"](
        value, runner=runner, corpus=corpus
    )

    fabricated = json.loads(json.dumps(value))
    fabricated["estimate"] = 0.0
    with pytest.raises(phase7["Phase7Error"], match="non-estimable contrast changed"):
        phase7["validate_non_estimable_llava_pair"](
            fabricated, runner=runner, corpus=corpus
        )


def test_phase7_llava_pair_uses_separate_seven_row_prerequisites(
    tmp_path: Path,
) -> None:
    phase7 = _rendered_phase7_namespace(tmp_path)
    base = phase7["LLAVA_BASE_IMAGE_LANE"]
    rr = phase7["LLAVA_RR_IMAGE_LANE"]
    rr_lanes = phase7["RR_CURRENT_LANES"]
    rr_target = phase7["RR_TARGET_SPEC"]
    for lane in rr_lanes:
        assert phase7["require_rr_amendment_selector"](
            lane, {"spec": rr_target}, None
        ) == rr_target
    with pytest.raises(phase7["Phase7Error"], match="target selector changed"):
        phase7["require_rr_amendment_selector"](
            rr_lanes[0], {"spec": "vllm:fixture/selector-swap"}, None
        )
    runner = {
        "terminal_states": {base: "measured_complete"},
        "lifecycle_states": {base: "complete"},
        "lifecycle_authorizations": {
            base: {
                "lifecycle_registry_status": "complete_runner_grid",
                "controller_failure": None,
            }
        },
        "conditional_na_lanes": [],
        "model_selectors": {"llava_base": "vllm:fixture/base"},
    }
    seven = {
        "terminal_states": {lane: "measured_complete" for lane in rr_lanes},
        "lifecycle": {lane: {"evidence": {}} for lane in rr_lanes},
        "metric_roots": {lane: f"/fixture/{lane}" for lane in rr_lanes},
        "rr_model_selector": "vllm:fixture/rr",
    }
    assert phase7["rr_amendment_metric_ready"](seven) is True
    comparison = phase7["llava_comparison_runner"](
        runner, {"latest": {}}, seven
    )
    assert comparison["model_selectors"] == {
        "llava_base": "vllm:fixture/base",
        "llava_rr": "vllm:fixture/rr",
    }
    assert phase7["llava_pair_prerequisite_plan"](comparison)["runnable"] is True

    failure = tmp_path / "rr-amendment.failure.json"
    failure.write_text("{}\n", encoding="utf-8")
    failed_seven = copy.deepcopy(seven)
    failed_lane = rr_lanes[-1]
    failed_seven["terminal_states"][failed_lane] = "measured_failed"
    failed_seven["lifecycle"][failed_lane]["evidence"] = {
        "failure": phase7["descriptor"](failure)
    }
    failed_comparison = phase7["llava_comparison_runner"](
        runner, {"latest": {}}, failed_seven
    )
    failed_plan = phase7["llava_pair_prerequisite_plan"](failed_comparison)
    assert failed_plan["runnable"] is False
    assert failed_plan["missing_roles"] == ["right_rr"]
    assert failed_comparison["terminal_states"][rr] == "failed"
    assert phase7["rr_amendment_metric_ready"](failed_seven) is False

    missing_sibling_root = copy.deepcopy(seven)
    missing_sibling_root["metric_roots"].pop(rr_lanes[-1])
    assert phase7["rr_amendment_metric_ready"](missing_sibling_root) is False

    source = _template_source("phase7_analysis.py.in")
    record_body = source.split(
        "def record_seven_output_policy_outcomes(self) -> None:", 1
    )[1].split("\n    def record_campaign_terminal_inventory", 1)[0]
    assert "rr_available = rr_amendment_metric_ready(seven)" in record_body
    boundary_body = source.split("def build_boundaries(", 1)[1].split(
        "\n    def finish", 1
    )[0]
    assert "llava_runner = llava_comparison_runner(" in boundary_body
    assert "value, runner=llava_runner, corpus=corpus" in boundary_body


def test_phase7_seven_row_and_recovery_boundary_contracts(tmp_path: Path) -> None:
    phase7 = _rendered_phase7_namespace(tmp_path)
    validate_transitions = phase7["validate_phase6_recovery_transitions"]
    failed_record = {"state": "failed"}
    complete_record = {"state": "measured_complete"}
    runner = {
        "lifecycle_lane_order": ["lane-a"],
        "terminal_states": {"lane-a": "failed"},
    }
    gate5_manifest = tmp_path / "gate5-manifest.json"
    gate5_manifest.write_text("{}\n", encoding="utf-8")
    empty_recoveries = phase7["validate_phase6_recovery_completions"](
        [],
        gate5_manifest=gate5_manifest,
        gate5_runnote=gate5_manifest,
        gate5_promotion=gate5_manifest,
        project_and_source={},
    )
    assert empty_recoveries["attempts"] == []
    assert empty_recoveries["history"] == {}
    assert empty_recoveries["latest"] == {}
    validate_transitions(recoveries=empty_recoveries, runner=runner)

    recoveries = {
        "history": {
            "lane-a": [copy.deepcopy(failed_record), copy.deepcopy(complete_record)]
        },
        "latest": {"lane-a": copy.deepcopy(complete_record)},
    }
    validate_transitions(recoveries=recoveries, runner=runner)

    originally_successful = copy.deepcopy(runner)
    originally_successful["terminal_states"]["lane-a"] = "measured_complete"
    with pytest.raises(phase7["Phase7Error"], match="failed scheduled lane"):
        validate_transitions(
            recoveries=recoveries, runner=originally_successful
        )

    unscheduled = {
        "history": {"lane-b": [copy.deepcopy(failed_record)]},
        "latest": {"lane-b": copy.deepcopy(failed_record)},
    }
    with pytest.raises(phase7["Phase7Error"], match="failed scheduled lane"):
        validate_transitions(recoveries=unscheduled, runner=runner)

    after_completion = copy.deepcopy(recoveries)
    after_completion["history"]["lane-a"].append(copy.deepcopy(failed_record))
    after_completion["latest"]["lane-a"] = copy.deepcopy(failed_record)
    with pytest.raises(
        phase7["Phase7Error"], match="continues after measured completion"
    ):
        validate_transitions(recoveries=after_completion, runner=runner)

    source = _template_source("phase7_analysis.py.in")
    seven_body = source.split(
        "def validate_seven_output_policy_inventory(", 1
    )[1].split("\ndef validate_phase6_recovery_completions", 1)[0]
    assert "framework_lock != RECOVERY_FRAMEWORK_LOCK_ID" in seven_body
    assert "or not successes <= ready_set" in seven_body
    assert 'states[lane] != "gate5_failed"' in seven_body
    assert 'spec.get("approved_caps") != amendment_row["approved_caps"]' in seven_body

    def assert_two_layer_gate5_digests(candidate: str) -> None:
        assert "policy_sha = sha256_file(policy_file)" in candidate
        assert "amendment_sha = hashlib.sha256(amendment_payload).hexdigest()" in candidate
        assert 'if key != "manifest_sha256"' in candidate
        assert 'amendment_gate5.get("manifest_sha256") != policy_sha' in candidate
        assert 'spec_gate5.get("manifest_sha256") != amendment_sha' in candidate
        assert 'spec.get("gate5") != amendment_row["gate5"]' not in candidate

    assert_two_layer_gate5_digests(seven_body)
    digest_mutant = seven_body.replace(
        'amendment_gate5.get("manifest_sha256") != policy_sha',
        'amendment_gate5.get("manifest_sha256") != amendment_sha',
        1,
    )
    assert digest_mutant != seven_body
    with pytest.raises(AssertionError):
        assert_two_layer_gate5_digests(digest_mutant)
    assert "require_rr_amendment_selector(lane, target, rr_selector)" in seven_body
    campaign_body = source.split(
        "def build_phase6_campaign_terminal_inventory(", 1
    )[1].split("\ndef validate_runner_inventory", 1)[0]
    assert (
        "validate_phase6_recovery_transitions(recoveries=recoveries, runner=runner)"
        in campaign_body
    )
    prepare_argv = [
        "prepare",
        "--out",
        "out.json",
        "--gate5-manifest",
        "gate5.json",
        "--gate5-runnote",
        "RUNNOTE.md",
        "--gate5-promotion-receipt",
        "promotion.json",
        "--phase6-core-completion",
        "core.json",
        "--phase6-extended-completion",
        "extended.json",
        "--phase6-native-completion",
        "native.json",
        "--seven-output-policy-amendment",
        "seven-amendment.json",
        "--phase6-seven-output-policy-completion",
        "seven-completion.json",
        "--followon-gate5-amendment",
        "followon-amendment.json",
        "--phase6-followon-completion",
        "followon-completion.json",
        "--current-ollama-gate5-amendment",
        "current-ollama-amendment.json",
        "--phase6-current-ollama-completion",
        "current-ollama-completion.json",
        "--phase6-vllm-stability-completion",
        "vllm-stability-completion.json",
        "--phase6-current-ollama-stability-completion",
        "current-ollama-stability-completion.json",
        "--phase6-current-ollama-population-alignment-completion",
        "current-ollama-population-alignment-completion.json",
        "--phase6-vllm-input-recovery-completion",
        "vllm-input-recovery-completion.json",
    ]
    parsed = phase7["build_parser"]().parse_args(prepare_argv)
    assert parsed.phase6_recovery_completion == []
    assert parsed.phase6_current_ollama_recovery_completion is None
    parsed_with_recovery = phase7["build_parser"]().parse_args(
        [
            *prepare_argv,
            "--phase6-recovery-completion",
            "recovery.json",
        ]
    )
    assert parsed_with_recovery.phase6_recovery_completion == ["recovery.json"]
    parsed_with_current_ollama_recovery = phase7["build_parser"]().parse_args(
        [
            *prepare_argv,
            "--phase6-current-ollama-recovery-completion",
            "current-ollama-recovery.json",
        ]
    )
    assert (
        parsed_with_current_ollama_recovery.phase6_current_ollama_recovery_completion
        == "current-ollama-recovery.json"
    )
    wrapper = _template_source("phase7_analysis.sh.in")
    watcher = _template_source("phase7_after_phase6_sequence.sh.in")
    assert '[[ ${#recovery_completions[@]} -gt 0 ]] || usage' not in wrapper
    assert '[[ ${#RECOVERY_COMPLETIONS[@]} -gt 0 ]] || exit 2' not in watcher
    assert (
        'recovery_args+=(--phase6-recovery-completion "$recovery_completion")'
        in wrapper
    )
    assert (
        'RECOVERY_ARGS+=(--phase6-recovery-completion "$recovery_completion")'
        in watcher
    )
    assert "CURRENT_OLLAMA_RECOVERY_ARGS+=(" in watcher
    assert "current_ollama_recovery_args+=(" in wrapper


def test_phase7_and_phase8_do_not_require_defense_success_at_gate6() -> None:
    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    phase7 = (root / "phase7_analysis.py.in").read_text(encoding="utf-8")
    phase8 = (root / "phase8_human_audit.py.in").read_text(encoding="utf-8")
    phase7_core = phase7[
        phase7.index("def validate_core_controller(") : phase7.index(
            "def validate_extended_controller("
        )
    ]
    phase8_core = phase8[
        phase8.index("def validate_core_completion(") : phase8.index(
            "def validate_extended_completion("
        )
    ]

    def assert_failure_allowed(source: str) -> None:
        assert 'state not in {"measured_complete", "failed"}' in source or (
            'success_state="measured_complete"' in source
        )
        assert "complete_with_failures" in source
        assert "runnable defense-local lacks complete measured" not in source
        assert "runnable defense-local must retain complete measured" not in source
        assert (
            'DEFENSE_LOCAL_LANE) != "measured_complete"' not in source
        )

    assert_failure_allowed(phase7_core)
    assert_failure_allowed(phase8_core)

    # Reverse mutation: restoring either old defense-only success gate must
    # violate the shared Gate 6 terminal-partition contract.
    for source, message in (
        (phase7_core, "runnable defense-local must retain complete measured"),
        (phase8_core, "runnable defense-local lacks complete measured"),
    ):
        mutated = source.replace(
            'expected_status = "complete"',
            f'# {message}\n    expected_status = "complete"',
            1,
        )
        if mutated == source:
            mutated = source.replace(
                'expected_status = "complete_with_failures"',
                f'# {message}\n    expected_status = "complete_with_failures"',
                1,
            )
        assert mutated != source
        with pytest.raises(AssertionError):
            assert_failure_allowed(mutated)


def test_rendered_phase8_declares_historical_gate5_profile(tmp_path: Path) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    source = (output / "phase8_human_audit.py").read_text(encoding="utf-8")

    def assert_historical_profile(candidate: str) -> None:
        assert "HISTORICAL_GATE5_RUNNABLE = 18" in candidate
        assert "HISTORICAL_GATE5_TYPED_TERMINAL = 28" in candidate
        assert "HISTORICAL_GATE5_TARGET_RUNTIME_TERMINAL = 7" in candidate
        assert "target_runtime_terminals = len(RR_RUNTIME_TERMINAL_LANES)" in candidate
        assert (
            candidate.count(
                '"target_runtime_terminal": len(RR_RUNTIME_TERMINAL_LANES)'
            )
            >= 2
        )
        assert '+ len(profile["ollama_static_terminal_lanes"])' in candidate
        assert '"runnable": HISTORICAL_GATE5_RUNNABLE' in candidate
        assert '"typed_terminal": HISTORICAL_GATE5_TYPED_TERMINAL' in candidate
        assert (
            '"target_runtime_terminal": '
            "HISTORICAL_GATE5_TARGET_RUNTIME_TERMINAL"
        ) in candidate
        assert '"conditional_na_lanes": [DEFENSE_LOCAL_LANE]' in candidate

    assert_historical_profile(source)
    for old, replacement in (
        ("HISTORICAL_GATE5_RUNNABLE = 18", "HISTORICAL_GATE5_RUNNABLE = 22"),
        (
            "HISTORICAL_GATE5_TARGET_RUNTIME_TERMINAL = 7",
            "HISTORICAL_GATE5_TARGET_RUNTIME_TERMINAL = 3",
        ),
        (
            "target_runtime_terminals = len(RR_RUNTIME_TERMINAL_LANES) + len(",
            "target_runtime_terminals = len(",
        ),
        (
            '"target_runtime_terminal": len(RR_RUNTIME_TERMINAL_LANES)\n'
            "        + len(ollama_static_terminals),",
            '"target_runtime_terminal": len(ollama_static_terminals),',
        ),
        (
            '"target_runtime_terminal": len(RR_RUNTIME_TERMINAL_LANES)\n'
            '        + len(profile["ollama_static_terminal_lanes"]),',
            '"target_runtime_terminal": '
            'len(profile["ollama_static_terminal_lanes"]),',
        ),
    ):
        reverted = source.replace(old, replacement, 1)
        assert reverted != source
        with pytest.raises(AssertionError):
            assert_historical_profile(reverted)


def test_phase8_accepts_current_rr_and_rejects_only_historical_terminal_rows() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase8_human_audit.py.in"
    ).read_text(encoding="utf-8")
    assert "HISTORICAL_RR_RUNTIME_TERMINAL_LANES" in source
    assert "def _reject_historical_rr_terminal_human_row(" in source
    assert (
        '_reject_historical_rr_terminal_human_row(row, label="common sample")'
        in source
    )
    assert (
        '_reject_historical_rr_terminal_human_row(row, label="source-task sample")'
        in source
    )
    assert "for marker in HISTORICAL_RR_RUNTIME_TERMINAL_LANES" in source
    rejection_start = source.index("def _reject_historical_rr_terminal_human_row(")
    rejection_end = source.index("\ndef ", rejection_start + 4)
    rejection = source[rejection_start:rejection_end]
    assert "RR_TARGET_IDENTITY_MARKERS" not in rejection
    assert "RR_CURRENT_LANES" not in rejection
    assert 'seven["rr_model_selector"]' in source
    assert 'project_root / "experiments" / "local-llava-rr.json"' in source
    assert "RR_LOCAL_CONFIG_SHA256" in source
    assert "RR_OBSERVED_PROJECT_COMMIT" in source
    gate5_start = source.index("def validate_gate5(")
    gate5_end = source.index("def validate_core_completion(", gate5_start)
    gate5 = source[gate5_start:gate5_end]
    assert "_validate_rr_runtime_project_continuity(" in gate5
    assert 'covered_commit=code_identity["expected_commit"]' in gate5
    continuity_start = source.index("def _validate_rr_runtime_project_continuity(")
    continuity_end = source.index("\ndef ", continuity_start + 4)
    continuity = source[continuity_start:continuity_end]
    assert "covered_commit: str" in continuity
    assert "RR_OBSERVED_PROJECT_COMMIT,\n            covered_commit," in continuity
    reverted_continuity = continuity.replace(
        "RR_OBSERVED_PROJECT_COMMIT,\n            covered_commit,",
        "RR_OBSERVED_PROJECT_COMMIT,\n            EXPECTED_COMMIT,",
        1,
    )
    assert reverted_continuity != continuity
    with pytest.raises(AssertionError):
        assert "RR_OBSERVED_PROJECT_COMMIT,\n            EXPECTED_COMMIT," not in (
            reverted_continuity
        )
    retained_start = source.index("RETAINED_PHASE6_PAYLOADS_BY_COMMIT = {")
    retained_end = source.index("\nFROZEN_PHASE7_PAYLOAD", retained_start)
    retained = source[retained_start:retained_end]
    retained_commit = "c62e027b0143d1db29c57f66605ac3d8dc23f11a"
    retained_core_sha = (
        "d4d7b17bab706665688b4fd49fc55eb7be9ac25906c21224805eff6accb6c755"
    )
    retained_extended_sha = (
        "e94c4be93eb1bfcd2e4b5c17cbb5fbaf32b56f97cdb55a4e3ff3ffaf501e2903"
    )
    retained_native_commit = "da062d0e2121ea2104b0c81374ef40f4f4f74473"
    retained_native_sha = (
        "393a53d174ee5ca0ef52ed9a8be0f0ed6acb784a037e62d03d55cf2e32a6ba9f"
    )
    for value in (
        retained_commit,
        retained_core_sha,
        retained_extended_sha,
        retained_native_commit,
        retained_native_sha,
        '"bytes": 303543',
        '"bytes": 330057',
        '"bytes": 172062',
        "mollysama/rwkv-7-g1f:2.9b",
        "mollysama/rwkv-7-g1d:0.4b",
        "mollysama/rwkv-7-g1g:1.5b",
    ):
        assert value in retained
    payload_start = source.index("def phase6_payload_identity(")
    payload_end = source.index("\ndef ", payload_start + 4)
    payload_contract = source[payload_start:payload_end]
    assert "expected_commit == EXPECTED_COMMIT" in payload_contract
    assert "RETAINED_PHASE6_PAYLOADS_BY_COMMIT.get(expected_commit, {})" in (
        payload_contract
    )
    assert "if retained is None:" in payload_contract
    assert 'expected_commit=historical_identity["expected_commit"]' in source
    reverted_retained = retained.replace(retained_extended_sha, "0" * 64, 1)
    assert reverted_retained != retained
    with pytest.raises(AssertionError):
        assert retained_extended_sha in reverted_retained
    conditional_start = source.index("forbidden_defense_paths = (")
    conditional_end = source.index("\n        )", conditional_start)
    conditional = source[conditional_start:conditional_end]
    assert "runner_root / DEFENSE_LOCAL_LANE" not in conditional
    reverted_conditional = conditional.replace(
        '            attempt / f"{DEFENSE_LOCAL_LANE}.failure.json",',
        '            attempt / f"{DEFENSE_LOCAL_LANE}.failure.json",\n'
        "            runner_root / DEFENSE_LOCAL_LANE,",
        1,
    )
    assert reverted_conditional != conditional
    with pytest.raises(AssertionError):
        assert "runner_root / DEFENSE_LOCAL_LANE" not in reverted_conditional
    assert '"10-defense-local.json"' in source
    assert '"14-defense-local.json"' not in source
    assert "validate_llava_pair_artifact(" in source
    assert "paired_invoked=" in source
    assert "prerequisite_roles=" in source
    assert 'set(projection) != {"path", "file", "sha256", "bytes"}' in source
    assert (
        '{"path", "envelope_id", "file", "sha256", "bytes"}' in source
    )
    assert 'set(eligibility) != {"path", "sha256", "bytes"}' in source
    assert 'eligibility.get("bindings", {}).get("request_envelope")' in source
    assert '"records": eligibility_records' in source
    assert "RR projection artifact descriptor changed" in source
    assert "RR request-envelope identity changed" in source
    assert "candidate.lstat()" in source
    assert "not stat.S_ISREG(entry.st_mode)" in source
    assert "evidence member changed while reading" in source
    assert 'getattr(os, "O_NOFOLLOW", 0)' in source
    assert "members_after != members_before" in source
    assert "evidence root changed while reading" in source

    # Reverse mutation: rejecting the live RR identity marker would recreate
    # the obsolete policy and must fail the historical-only contract.
    reverted = rejection.replace(
        "for marker in HISTORICAL_RR_RUNTIME_TERMINAL_LANES",
        "for marker in (*HISTORICAL_RR_RUNTIME_TERMINAL_LANES, *RR_TARGET_IDENTITY_MARKERS)",
        1,
    )
    assert reverted != rejection
    with pytest.raises(AssertionError):
        assert "RR_TARGET_IDENTITY_MARKERS" not in reverted


def test_canonical_c926_contract_stays_separate_from_seven_amendment() -> None:
    import re

    root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    canonical_names = (
        "phase5_core_projections.sh.in",
        "phase5_core_attest_canary.sh.in",
        "phase5_finalize_gate5.sh.in",
        "phase5_promote_gate5.sh.in",
        "phase6_core_measured.sh.in",
        "phase6_extended_measured.sh.in",
        "phase6_native_diagnostics.sh.in",
        "phase6_sequence.sh.in",
    )
    canonical = {
        name: (root / name).read_text(encoding="utf-8") for name in canonical_names
    }
    historical_rr = (
        "local-llava-rr-text-full",
        "local-llava-rr-image-full",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    )
    current_rr_primary = (
        "local-llava-rr-text-primary-100",
        "local-llava-rr-image-primary-100",
    )
    for source in canonical.values():
        for lane in current_rr_primary:
            assert lane not in source
        for lane in historical_rr:
            assert lane in source

    watcher = (root / "phase7_after_phase6_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    watcher_profile = watcher.split(
        "def require_phase6_inventory_profile(", 1
    )[1].split("\ndef phase6_inventory_profile_self_test", 1)[0]
    assert "or runnable != 18" in watcher_profile
    assert "or terminal != 28" in watcher_profile
    assert "or target_runtime != 7" in watcher_profile
    assert 'or gate_conditional != ["defense-local"]' in watcher_profile
    assert '(success_profile, [], complete)' in watcher
    assert '"runnable_lanes": 18' in watcher
    assert '"typed_terminal_lanes": 28' in watcher
    assert '"target_runtime_terminal": 7' in watcher
    gate5_sequence = (root / "gate5_after_phase5_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    assert "exact_profile(19, 27, 7, [])" in gate5_sequence
    assert 'exact_profile(18, 28, 7, ["defense-local"])' in gate5_sequence

    phase7 = (root / "phase7_analysis.py.in").read_text(encoding="utf-8")
    assert "def require_phase7_c926_gate5_profile(" in phase7
    assert phase7.count("require_phase7_c926_gate5_profile(") >= 5
    amendment_start = phase7.index("SEVEN_AMENDMENT_LANES = (")
    amendment_end = phase7.index("SEVEN_TERMINAL_STATES", amendment_start)
    amendment = phase7[amendment_start:amendment_end]
    assert re.findall(r'"([a-z0-9-]+)"', amendment) == [
        "local-llava-rr-text-primary-100",
        "local-llava-rr-image-primary-100",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    ]


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
    assert 'write_rr_target_runtime_terminal "$RR_TERMINAL" "$RR_CFG"' in canaries
    assert canaries.index(
        'write_rr_target_runtime_terminal "$RR_TERMINAL" "$RR_CFG"'
    ) < canaries.index("probe_target qwen3-vl text")
    assert 'manifest.get("code_version") != "ura-runner/2.24"' in canaries
    assert 'SCHEMA = "ura-phase5-target-runtime-terminal/1"' in canaries
    assert (
        'OBSERVED_PROJECT_COMMIT = "5c0a288e7b19dcd748c3169abdf52e2e7d37b2fa"'
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
    for source in (finalizer, promoter):
        assert "historical_inventory_counts as ollama_inventory_counts" in source
        assert '"expected_runnable": [18, 19, 20, 21, 22]' in source
        assert '"expected_target_runtime_terminal": [4, 5, 6, 7]' in source
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
    for profile in (
        "exact_profile(22, 24, 4, [])",
        'exact_profile(21, 25, 4, ["defense-local"])',
        "exact_profile(21, 25, 5, [])",
        'exact_profile(20, 26, 5, ["defense-local"])',
        "exact_profile(20, 26, 6, [])",
        'exact_profile(19, 27, 6, ["defense-local"])',
        "exact_profile(19, 27, 7, [])",
        'exact_profile(18, 28, 7, ["defense-local"])',
    ):
        assert profile in sequence

    completion_source = sequence[sequence.index("controller_task_start sequence-completion"):]
    completion_blocks = re.findall(
        r"<<'PY'\n(.*?)\nPY(?:\n|$)", completion_source, re.DOTALL
    )
    assert len(completion_blocks) == 1

    def run_completion_profile_self_test(block: str) -> None:
        import ast

        tree = ast.parse(block)
        function_index = next(
            index
            for index, node in enumerate(tree.body)
            if isinstance(node, ast.FunctionDef) and node.name == "exact_profile"
        )
        profile_self_test = tree.body[function_index + 1]
        assert isinstance(profile_self_test, ast.If)
        imports = [
            node
            for node in tree.body[:function_index]
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        isolated = ast.Module(
            body=[*imports, tree.body[function_index], profile_self_test],
            type_ignores=[],
        )
        exec(compile(ast.fix_missing_locations(isolated), "<gate5-completion>", "exec"), {})

    run_completion_profile_self_test(completion_blocks[0])

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
                "rr_swapped_projection_lane", "conditional_v2_cross_mix",
            },
        ),
        (
            "phase5_promote_gate5.sh",
            "--promotion-self-test",
            {
                "rr_projection_unavailable", "rr_projection_descriptor_missing",
                "rr_split_terminal_artifact", "rr_duplicate_projection",
                "bounded_selection_limit",
                "conditional_v2_cross_mix",
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
        assert value["expected_runnable"] == [18, 19, 20, 21, 22]
        assert value["expected_target_runtime_terminal"] == [4, 5, 6, 7]
        assert expected_mutations <= set(value["rejected_mutations"])
        assert set(value["rejected_conditional_variant_mutations"]) == {
            "v2_reason_from_v1",
            "v2_accounting_from_v1",
            "v1_with_evidence_limits",
            "v2_boolean_stream_count",
        }
        if filename == "phase5_finalize_gate5.sh":
            assert {
                "adaptive_policy_evaluable_query_missing",
                "proxy_decision_missing_metric",
                "proxy_decision_abstention_mismatch",
                "proxy_abstention_invents_metric",
                "proxy_abstention_invents_selected_judge",
                "proxy_abstention_wrong_coverage",
                "proxy_abstention_integer_coverage",
                "proxy_multiple_authorities",
                "proxy_decision_authority_mismatch",
                "proxy_abstention_rules_authority",
                "proxy_abstention_not_terminal_na",
                "proxy_boolean_stage",
                "proxy_confident_shadow",
                "proxy_boolean_trail_confidence",
                "proxy_nonzero_trail_confidence",
                "proxy_decision_score_detached",
                "proxy_abstention_source_evaluator_claim",
                "proxy_abstention_wrong_judge_model",
                "proxy_abstention_wrong_judge_revision",
                "proxy_abstention_wrong_judge_identity",
                "proxy_abstention_missing_status",
                "proxy_abstention_boolean_judgment_confidence",
                "proxy_abstention_nonzero_judgment_confidence",
            } <= set(value["rejected_canary_stage_mutations"])
        else:
            assert {
                "proxy-decision-missing-result",
                "proxy-abstention-metric",
                "proxy-abstention-coverage",
                "proxy-abstention-integer-coverage",
                "proxy-abstention-multiple-authorities",
                "proxy-abstention-boolean-stage",
                "proxy-abstention-confident-shadow",
                "proxy-abstention-boolean-trail-confidence",
                "proxy-abstention-nonzero-trail-confidence",
                "proxy-abstention-source-evaluator-claim",
                "proxy-abstention-wrong-judge-model",
                "proxy-abstention-wrong-judge-revision",
                "proxy-abstention-wrong-judge-identity",
                "proxy-abstention-boolean-judgment-confidence",
                "proxy-abstention-nonzero-judgment-confidence",
            } <= set(value["rejected_proxy_mutations"])
        assert value["retained_binding_self_test"] == {
            "eligibility_nonblank_records": 3,
            "hardcoded_one_rejected": True,
            "request_envelope_swap_rejected": True,
        }


def test_every_rr_consumer_binds_the_current_commit_observation() -> None:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    observed_commit = "5c0a288e7b19dcd748c3169abdf52e2e7d37b2fa"
    superseded_commits = (
        "5719a4ff4ba4a711fee433d1f9990c1d3cf2f8a3",
        "21b27d56da0d081125f4cf4117884a8262386e5d",
    )
    consumers = (
        "phase5_core_attest_canary.sh.in",
        "phase5_finalize_gate5.sh.in",
        "phase5_promote_gate5.sh.in",
        "phase6_core_measured.sh.in",
        "phase6_extended_measured.sh.in",
        "phase6_native_diagnostics.sh.in",
        "phase7_analysis.py.in",
        "phase8_human_audit.py.in",
    )
    for name in consumers:
        source = (root / name).read_text(encoding="utf-8")
        assert observed_commit in source, name
        assert not any(commit in source for commit in superseded_commits), name

    current_text_root = "phase5-core-canaries-20260824T053641Z"
    current_image_root = "rr-image-probe-20260824T053641Z"
    old_roots = (
        "phase5-core-canaries-20260822T173216Z",
        "rr-image-probe-20260822T182300Z",
        "phase5-core-canaries-20260824T012347Z",
        "rr-image-probe-20260824T012347Z",
    )
    for path in (
        Path(__file__).parents[2] / "experiments" / "RUN_AND_RETURN.md",
        root.parent / "README.md",
    ):
        source = path.read_text(encoding="utf-8")
        assert current_text_root in source, path.name
        assert current_image_root in source, path.name
        assert not any(old in source for old in old_roots), path.name


def test_phase5_defense_failure_classifiers_are_disjoint_and_mutation_bound() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_core_attest_canary.sh.in"
    ).read_text(encoding="utf-8")
    oom_start = source.index("write_defense_conditional_na() {")
    output_start = source.index("write_defense_output_noncompletion_na() {")
    rr_start = source.index("write_rr_target_runtime_terminal() {")
    oom_classifier = source[oom_start:output_start].rstrip()
    output_classifier = source[output_start:rr_start].rstrip()

    # The admitted pre-call OOM classifier is an existing evidence contract.
    # Keep it byte-for-byte stable while adding the disjoint post-call terminal.
    assert hashlib.sha256(oom_classifier.encode("utf-8")).hexdigest() == (
        "6df16db7fac421d9eef29ac40d94d323423b7ceaceca36c774c377733f1690b6"
    )
    assert 'SCHEMA = "ura-phase5-defense-canary-na/1"' in oom_classifier
    assert 'REASON_CODE = "co_resident_cuda_oom_before_calls"' in oom_classifier
    assert "target_calls\": 0" in oom_classifier
    assert "grid_paths or response_paths or completion_paths or error_paths" in (
        oom_classifier
    )

    required = (
        'SCHEMA = "ura-phase5-defense-canary-na/2"',
        'REASON_CODE = "target_output_noncompletion_at_generation_cap"',
        'EXPECTED_TARGET_REVISION = "60595ebc30ec8e3b1d3b9e65d4943ca011c0006a"',
        'EXPECTED_SCORING_GUARD_REVISION = "7327bd9f6efbbe6101dc6cc4736302b3cbb6e425"',
        'EXPECTED_DEFENSE_GUARD_REVISION = "acf7aafa60f0410f8f42b1fa35e077d705892029"',
        'error.get("model_spec") != resolved_target',
        'error.get("target") != resolved_target',
        'type(budget.get(field)) is not int',
        'budget.get("target_calls") != 1',
        'grid.get("n_errors") != 2',
        'grid.get("engine_runtime_close") is not None',
        '"model_spec", "phase", "run_id", "status", "target"',
        '"class": "ura.targets.guarded.GuardedTarget"',
        'components != expected_components',
        'set(circuits) != {"format_version", "grid_id", "circuits"}',
        'circuit.get("message") != expected_error_message',
        'runner_log.splitlines().count(expected_failure_line) != 1',
        'runner_log.splitlines().count(expected_done_line) != 1',
        '"target_calls": 1',
        '"defense_guardrail_evaluations": 1',
        '"output_defense_guardrail_evaluations": 0',
        '"scoring_guardrail_evaluations": 0',
        '"category": "target_output_noncompletion"',
        '"partial_grid": descriptor(grid_path)',
        '"circuit_ledger": descriptor(circuits_path)',
        '"target_error": descriptor(error_path)',
        '"failed_cell_manifest": descriptor(manifest_path)',
        '"parquet_placeholder": descriptor(parquet_path)',
        'parquet_metadata.num_rows != 0',
        'parquet_metadata.num_columns != 0',
        'grid_resources != receipt_runtime_resources',
        'manifest_resources != receipt_runtime_resources',
        'retained_attestation_payload != attestation_payload',
        '"retained_live_attestation": retained_attestation_desc',
        'allow_empty: bool = False',
        'allow_empty=True',
        'initial.st_size != 0',
        '"per_attempt_defense_audit_retained": False',
    )
    _assert_source_contract(output_classifier, required)
    python_body = output_classifier.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    compile(python_body, "phase5-defense-output-noncompletion", "exec")

    mutations = (
        (
            'SCHEMA = "ura-phase5-defense-canary-na/2"',
            'SCHEMA = "ura-phase5-defense-canary-na/1"',
        ),
        ('budget.get("target_calls") != 1', 'budget.get("target_calls") != 0'),
        ('"target_calls": 1', '"target_calls": 0'),
        (
            '"defense_guardrail_evaluations": 1',
            '"defense_guardrail_evaluations": 0',
        ),
        (
            'error.get("target") != resolved_target',
            'error.get("target") != error.get("model_spec")',
        ),
        (
            '"class": "ura.targets.guarded.GuardedTarget"',
            '"class": "ura.targets.local.VLLMTarget"',
        ),
        (
            'EXPECTED_SCORING_GUARD_REVISION = "7327bd9f6efbbe6101dc6cc4736302b3cbb6e425"',
            'EXPECTED_SCORING_GUARD_REVISION = "0" * 40',
        ),
        (
            'set(circuits) != {"format_version", "grid_id", "circuits"}',
            'set(circuits) != {"format_version", "grid_id"}',
        ),
        (
            'runner_log.splitlines().count(expected_failure_line) != 1',
            'runner_log.splitlines().count(expected_failure_line) < 0',
        ),
        (
            '"failed_cell_manifest": descriptor(manifest_path)',
            '"failed_cell_manifest": None',
        ),
        ('parquet_metadata.num_rows != 0', 'parquet_metadata.num_rows < 0'),
        (
            'grid_resources != receipt_runtime_resources',
            'grid_resources == receipt_runtime_resources',
        ),
        ('initial.st_size != 0', 'initial.st_size < 0'),
        (
            'retained_attestation_payload != attestation_payload',
            'retained_attestation_payload == attestation_payload',
        ),
    )
    for original, replacement in mutations:
        changed = output_classifier.replace(original, replacement, 1)
        assert changed != output_classifier
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)

    dispatch = source[source.index("if (( canary_rc != 0 )); then"):]
    dispatch_required = (
        "if write_defense_conditional_na \\",
        "elif write_defense_output_noncompletion_na \\",
        'return "$canary_rc"',
        '[[ -f "$conditional_artifact" && ! -L "$conditional_artifact" ]]',
        "conditional_attempts=0\n        conditional_successes=0",
        "conditional_attempts=1\n        conditional_successes=0",
        '"$conditional_artifact" "$conditional_attempts" \\',
        '"$conditional_successes" | tee -a "$STATUS"',
    )
    _assert_source_contract(dispatch, dispatch_required)
    dispatch_mutation = dispatch.replace(
        "elif write_defense_output_noncompletion_na \\",
        "elif write_defense_conditional_na \\",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_source_contract(dispatch_mutation, dispatch_required)
    for original, replacement in (
        ("conditional_attempts=1", "conditional_attempts=0"),
        ('"$conditional_artifact" "$conditional_attempts"',
         '"$conditional_artifact" "$conditional_successes"'),
    ):
        changed = dispatch.replace(original, replacement, 1)
        assert changed != dispatch
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, dispatch_required)


def test_defense_output_noncompletion_log_prefix_is_shared_end_to_end() -> None:
    template_root = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    writer = (template_root / "phase5_core_attest_canary.sh.in").read_text(
        encoding="utf-8"
    )
    finalizer = (template_root / "phase5_finalize_gate5.sh.in").read_text(
        encoding="utf-8"
    )
    promoter = (template_root / "phase5_promote_gate5.sh.in").read_text(
        encoding="utf-8"
    )
    core = (template_root / "phase6_core_measured.sh.in").read_text(
        encoding="utf-8"
    )
    exact_prefix = (
        'r"^  ! cell failed \\[[^\\r\\n]+\\]: ExternalCallFailure: target_call failed "'
    )
    assert 'f"  ! cell failed [{cell_prefix}]: ExternalCallFailure: "' in writer
    for downstream, expected_count in (
        (finalizer, 1),
        (promoter, 1),
        (core, 2),
    ):
        assert downstream.count(exact_prefix) == expected_count
        assert exact_prefix.replace("^  !", "^!") not in downstream
        assert '"retained_live_attestation"' in downstream


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
        "include_runner_records=True",
        '"records": error_artifact["records"]',
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

    def assert_failed_root_summary(source: str) -> None:
        assert "four HarmBench multimodal probes exited 134" in source
        assert "seed 6 completed its one-cell grid and real response" in source
        assert (
            "three admitted HarmBench multimodal probes failed before generation"
            not in source
        )

    assert_failed_root_summary(finalizer_source)
    stale_summary = finalizer_source.replace(
        "four HarmBench multimodal probes exited 134",
        "three admitted HarmBench multimodal probes failed before generation",
        1,
    )
    assert stale_summary != finalizer_source
    with pytest.raises(AssertionError):
        assert_failed_root_summary(stale_summary)

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
    assert value["error_artifact_records"] > 1
    assert set(value["rejected_mutations"]) == {
        "deleted_budget_ledger",
        "rolled_back_budget_target_calls",
        "deleted_paid_response_checkpoint",
        "rolled_back_checkpoint_target_calls",
        "rolled_back_grid_target_calls",
        "omitted_error_artifact_records",
        "wrong_error_artifact_records",
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


def test_gate5_guard_snapshot_matches_runner_local_judge_identity() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_finalize_gate5.sh.in"
    ).read_text(encoding="utf-8")

    def assert_contract(value: str) -> None:
        snapshot = value.split("expected_guard_snapshot = {", 1)[1].split(
            "\n        }", 1
        )[0]
        assert '"resolved_model": model,' in snapshot
        assert (
            'realized_judges[1]["snapshot"] != expected_guard_snapshot'
            in value
        )

    assert_contract(source)
    reverted = source.replace('            "resolved_model": model,\n', "", 1)
    assert reverted != source
    with pytest.raises(AssertionError):
        assert_contract(reverted)


def test_gate5_maps_raw_vllm_request_to_exact_sealed_runtime() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_finalize_gate5.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        'elif requested_target.startswith("vllm:"):',
        'set(local_configs) != {expected_realized}',
        'condition["requested_model_spec"] != expected_realized',
        'condition["resolved_target"] != expected_realized',
        'snapshot.get("target") != expected_realized',
        'requested_target.removeprefix("vllm:")',
        'snapshot.get("model_revision") != revision',
    )
    _assert_source_contract(source, required)
    reverted = source.replace(
        'elif requested_target.startswith("vllm:"):',
        'elif requested_targets == [condition["requested_model_spec"]]:',
        1,
    )
    assert reverted != source
    with pytest.raises(AssertionError):
        _assert_source_contract(reverted, required)


def test_gate5_accepts_private_engine_runtime_logical_name_with_content_seals() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_finalize_gate5.sh.in"
    ).read_text(encoding="utf-8")

    def assert_contract(value: str) -> None:
        bound_config = value.split("    def bound_config(", 1)[1].split(
            "\n    source_config = bound_config(", 1
        )[0]
        for required in (
            'if descriptor_field == "engine_runtime_config_artifact":',
            'f"private-engine-runtime-config@sha256:{retained[\'sha256\']}"',
            'retained_name_matches = path.name == Path(str(retained["file"])).name',
            'sha_value != retained["sha256"]',
            'observed["sha256"] != retained["sha256"]',
            'observed["bytes"] != retained["bytes"]',
            "or not retained_name_matches",
        ):
            assert required in bound_config
        selected_relationship = value.split(
            "def validate_selected_config_relationship(", 1
        )[1].split("\ndef sampling_binding_from_audit(", 1)[0]
        assert (
            '"source_conformance", "engine_runtime_config", "api_config", '
            '"local_config",'
            in selected_relationship
        )
        assert "if canary.get(field) != preliminary.get(field):" in selected_relationship

    assert_contract(source)
    exact_private_branch = '''        if descriptor_field == "engine_runtime_config_artifact":
            retained_name_matches = retained["file"] == (
                f"private-engine-runtime-config@sha256:{retained['sha256']}"
            )
        else:
            retained_name_matches = path.name == Path(str(retained["file"])).name
'''
    reverted = source.replace(
        exact_private_branch,
        '        retained_name_matches = path.name == Path(str(retained["file"])).name\n',
        1,
    )
    assert reverted != source
    with pytest.raises(AssertionError):
        assert_contract(reverted)


def test_gate5_accepts_header_only_status_for_known_incomplete_failed_attempt(
    tmp_path: Path,
) -> None:
    namespace = _rendered_gate5_namespace(tmp_path)
    fields = namespace["FAILED_CORE_STATUS_FIELDS"]
    status = tmp_path / "status.tsv"
    status.write_text("\t".join(fields) + "\n", encoding="utf-8")

    assert namespace["read_tsv"](
        status,
        allow_empty=True,
        expected_fields=fields,
    ) == []
    with pytest.raises(namespace["Gate5Error"], match="no data rows"):
        namespace["read_tsv"](status)

    status.write_text("wrong\theader\n", encoding="utf-8")
    with pytest.raises(namespace["Gate5Error"], match="header changed"):
        namespace["read_tsv"](
            status,
            allow_empty=True,
            expected_fields=fields,
        )


def test_gate5_expands_project_receipt_descriptor_to_experiment_binding(
    tmp_path: Path,
) -> None:
    namespace = _rendered_gate5_namespace(tmp_path)
    manifest = tmp_path / "project-revision.json"
    manifest.write_text("{}\n", encoding="utf-8")
    expected_sha = "a" * 64
    receipt = {"revision_id": "project-revision-test"}
    descriptor_binding = {
        "file": manifest.name,
        "sha256": expected_sha,
        "bytes": manifest.stat().st_size,
        "revision_id": receipt["revision_id"],
    }
    expanded = {"mode": "verified", "sha256": expected_sha}
    calls: list[tuple[object, object]] = []

    namespace["EXPECTED_PROJECT_RECEIPT"] = str(manifest)
    namespace["EXPECTED_PROJECT_RECEIPT_SHA256"] = expected_sha
    namespace["required_env"] = lambda name: (
        str(manifest) if name == "URA_PROJECT_REVISION_MANIFEST" else expected_sha
    )
    namespace["load_project_revision_file"] = (
        lambda *_args, **_kwargs: (receipt, descriptor_binding)
    )
    namespace["project_revision_binding"] = lambda observed_receipt, observed_descriptor: (
        calls.append((observed_receipt, observed_descriptor)) or expanded
    )

    result = namespace["validate_project_receipt"](tmp_path)
    assert result["binding"] == expanded
    assert calls == [(receipt, descriptor_binding)]


def test_gate5_promoter_compares_the_normalized_project_revision_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _rendered_gate5_promoter_namespace(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    work = tmp_path / "work"
    framework_state = (
        work
        / "runs"
        / "engineering"
        / f"framework-runtime-{namespace['EXPECTED_FRAMEWORK_LOCK'][:12]}"
    )
    framework_state.mkdir(parents=True)

    project_manifest = tmp_path / "project-revision-test.project-revision.json"
    project_manifest.write_text("{}\n", encoding="utf-8")
    source_manifest = tmp_path / "source-conformance.json"
    source_manifest.write_text("{}\n", encoding="utf-8")
    project_sha = hashlib.sha256(project_manifest.read_bytes()).hexdigest()
    source_sha = hashlib.sha256(source_manifest.read_bytes()).hexdigest()
    expected_commit = namespace["EXPECTED_COMMIT"]
    receipt = {"revision_id": "project-revision-test"}
    descriptor_binding = {
        "file": project_manifest.name,
        "sha256": project_sha,
        "bytes": project_manifest.stat().st_size,
        "revision_id": receipt["revision_id"],
    }
    normalized_binding = {
        "mode": "verified",
        **descriptor_binding,
        "expected_commit": expected_commit,
        "observed_commit": expected_commit,
        "head_tree": "3" * 40,
        "harness_source_sha256": "4" * 64,
        "driver_source_sha256": "5" * 64,
    }
    source_value = {
        "arms": [
            *(
                {"arm_id": f"admitted-{index}", "disposition": "admitted"}
                for index in range(44)
            ),
            {"arm_id": "bipia_test_qa", "disposition": "blocked"},
        ]
    }
    normalization_calls: list[tuple[object, object]] = []

    namespace["EXPECTED_PROJECT_RECEIPT"] = str(project_manifest)
    namespace["EXPECTED_PROJECT_RECEIPT_SHA256"] = project_sha
    namespace["EXPECTED_SOURCE_RECEIPT"] = str(source_manifest)
    namespace["EXPECTED_SOURCE_RECEIPT_SHA256"] = source_sha
    namespace["run_capture"] = lambda argv, *, cwd: (
        expected_commit if argv == ["git", "rev-parse", "HEAD"] else ""
    )
    namespace["load_project_revision_file"] = (
        lambda *_args, **_kwargs: (receipt, descriptor_binding)
    )
    namespace["project_revision_binding"] = (
        lambda observed_receipt, observed_descriptor: (
            normalization_calls.append((observed_receipt, observed_descriptor))
            or normalized_binding
        )
    )
    namespace["strict_json"] = lambda _path: source_value
    namespace["validate_source_conformance_manifest"] = lambda value: value
    monkeypatch.setenv(
        "URA_FRAMEWORK_LOCK_ID", str(namespace["EXPECTED_FRAMEWORK_LOCK"])
    )
    monkeypatch.setenv("URA_FRAMEWORK_STATE", str(framework_state))
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project_manifest))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", project_sha)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(source_manifest))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", source_sha)

    identities = namespace["current_identities"](project, work)
    candidate_project_revision = {
        "artifact": identities["project_revision"]["artifact"],
        "revision_id": receipt["revision_id"],
        "binding": normalized_binding,
    }
    raw_descriptor_identity = {
        **candidate_project_revision,
        "binding": descriptor_binding,
    }

    def assert_candidate_identity(observed: dict[str, object]) -> None:
        assert observed["project_revision"] == candidate_project_revision

    assert_candidate_identity(identities)
    with pytest.raises(AssertionError):
        assert_candidate_identity({"project_revision": raw_descriptor_identity})
    assert normalization_calls == [(receipt, descriptor_binding)]


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


def test_top_level_controllers_register_exact_console_campaigns(
    tmp_path: Path,
) -> None:
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    expected = {
        "phase5_sequence_after_core.sh": (
            24,
            (
                "core-projections",
                "core-canaries",
                "bridge-projections",
                "bridge-canaries",
                "ollama",
            ),
        ),
        "gate5_after_phase5_sequence.sh": (
            24,
            (
                "await-phase5",
                "validate-evidence",
                "finalize-gate5",
                "prepare-promotion",
                "promote-runnote",
                "sequence-completion",
            ),
        ),
        "phase6_sequence.sh": (
            720,
            (
                "controller-preflight",
                "await-gate5",
                "core-measured",
                "extended-measured",
                "native-diagnostics",
                "final-validation",
                "sequence-completion",
            ),
        ),
        "phase7_after_phase6_sequence.sh": (
            720,
            (
                "await-phase6",
                "validate-phase6",
                "prepare-analysis",
                "run-analysis",
                "validate-analysis",
                "publish-stats",
            ),
        ),
    }
    for name, (hard_stop, planned_tasks) in expected.items():
        source = (output / name).read_text(encoding="utf-8")
        task_block = re.search(
            r"(?m)^CONTROL_TASKS=\(\n(?P<tasks>(?:  [a-z0-9-]+\n)+)\)$",
            source,
        )
        assert task_block is not None
        assert tuple(
            line.strip() for line in task_block.group("tasks").splitlines()
        ) == planned_tasks
        assert re.findall(
            r"(?m)^controller_task_start ([a-z0-9-]+)$", source
        ) == list(planned_tasks)
        assert re.findall(
            r"(?m)^[ \t]*controller_task_pass ([a-z0-9-]+)$", source
        ) == list(planned_tasks)
        expected_failures = (
            (
                "core-measured",
                "extended-measured",
                "native-diagnostics",
                "sequence-completion",
            )
            if name == "phase6_sequence.sh"
            else ()
        )
        assert tuple(
            re.findall(
                r"(?m)^[ \t]*controller_task_fail ([a-z0-9-]+)$",
                source,
            )
        ) == expected_failures
        assert source.count("-m experiments.local_campaign.console_events") == 2
        assert '--campaign-id "${CONTROL_ROOT##*/}"' in source
        assert '--release-commit "$EXPECTED_COMMIT"' in source
        assert "--evidence-class local_campaign_control" in source
        assert f"CONTROL_HARD_STOP_HOURS={hard_stop}" in source
        assert '--hard-stop-hours "$CONTROL_HARD_STOP_HOURS"' in source
        assert 'CONSOLE_START_ARGS+=(--planned-task "$task")' in source
        assert 'console_event task_skip "$task" skipped' in source
        assert 'console_event campaign_end bootstrap "$status"' in source
        assert "--hosted-calls" not in source
        registration = source.index(
            "-m experiments.local_campaign.console_events start"
        )
        first_task = source.index(f"controller_task_start {planned_tasks[0]}")
        assert registration < first_task
        finish = source.split("finish() {", 1)[1].split(
            "\n}\ntrap finish EXIT", 1
        )[0]
        assert 'controller_finish "$rc"' in finish
        assert finish.index("printf '%s\\n' \"$rc\"") < finish.index(
            'controller_finish "$rc"'
        )
        if name == "phase6_sequence.sh":
            assert "CONTROL_TMUX_SESSION='ura-phase6-sequence-1111111'" in source
            assert "CONTROL_TMUX_SOCKET='ura-phase6-sequence-1111111'" in source
            assert '--tmux-socket "$CONTROL_TMUX_SOCKET"' in source
            assert '--tmux-session "$CONTROL_TMUX_SESSION"' in source


def test_phase7_stats_publication_is_plan_owned_ordered_and_fail_closed(
    tmp_path: Path,
) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    source = (output / "phase7_after_phase6_sequence.sh").read_text(
        encoding="utf-8"
    )

    required = (
        "set -Eeuo pipefail",
        "controller_task_pass validate-analysis",
        "controller_task_start publish-stats",
        '"$PY" -m experiments.local_campaign.stats_adapter',
        '--results-root "$URA_WORK/runs"',
        '--campaign-root "$CONTROL_ROOT"',
        '--release-commit "$EXPECTED_COMMIT"',
        'EXPECTED_STATS_REGISTRATION="$URA_WORK/runs/external-analysis-jobs/',
        'test "$STATS_REGISTRATION" = "$EXPECTED_STATS_REGISTRATION"',
        'test -f "$STATS_REGISTRATION" && test ! -L "$STATS_REGISTRATION"',
        'test "$(readlink -e -- "$STATS_REGISTRATION")" = "$STATS_REGISTRATION"',
        "controller_task_pass publish-stats",
    )

    def assert_publication_contract(value: str) -> None:
        _assert_source_contract(value, required)
        start = value.index("controller_task_start publish-stats")
        end = value.index("controller_task_pass publish-stats", start) + len(
            "controller_task_pass publish-stats"
        )
        assert value.index("controller_task_pass validate-analysis") < start
        publication = value[start:end]
        ordered = tuple(publication.index(snippet) for snippet in required[2:])
        assert ordered == tuple(sorted(ordered))
        assert "experiments.rig_web_app" not in publication

    assert_publication_contract(source)

    for original, replacement in (
        (
            '"$PY" -m experiments.local_campaign.stats_adapter',
            '"$PY" -m experiments.rig_web_app.dashboard',
        ),
        (
            'test -f "$STATS_REGISTRATION" && test ! -L "$STATS_REGISTRATION"',
            ":",
        ),
        (
            "controller_task_pass validate-analysis\n\n"
            "controller_task_start publish-stats",
            "controller_task_start publish-stats\n\n"
            "controller_task_pass validate-analysis",
        ),
    ):
        changed = source.replace(original, replacement, 1)
        assert changed != source
        with pytest.raises(AssertionError):
            assert_publication_contract(changed)


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
        assert 'projection_field.get("status") != "passed"' in source or (
            'value.get("status") != "passed"' in source
        )
        assert (
            "historical_inventory_counts as ollama_static_inventory_counts"
            in source
        )
        assert "validate_gate5_terminal_rows as validate_ollama_static_gate5_rows" in source
        assert "OLLAMA_STATIC_TERMINAL_LANES" in source
        assert "ollama_static_inventory_counts(" in source
        assert '"target_runtime_terminal": 4' in source
        assert '"runnable": 22' in source
        assert '"typed_terminal": 24' in source
        assert '"local-llava-rr.json"' in source
        assert "5c0a288e7b19dcd748c3169abdf52e2e7d37b2fa" in source
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
    native_self_test_start = native.index("def gate5_contract_self_test(")
    native_self_test_end = native.index(
        "def validate_plan(", native_self_test_start
    )
    native_self_test = native[native_self_test_start:native_self_test_end]
    assert "alternate_static_terminals = [" in native_self_test
    assert "complete_gate5_counts(alternate_static_terminals, [])" in native_self_test
    assert (
        'complete_gate5_counts(alternate_static_terminals, ["defense-local"])'
        in native_self_test
    )
    assert (
        "alternate_counts not in (SUCCESS_GATE5_COUNTS, DEFENSE_NA_GATE5_COUNTS)"
        not in native_self_test
    )
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
        assert 'eligibility.get("bindings", {}).get("request_envelope")' in source
        assert '{"path", "file", "sha256", "bytes"}' in source
        assert '{"path", "envelope_id", "file", "sha256", "bytes"}' in source
        assert '"records": eligibility_records' in source
        assert 'for line in eligibility_payload.decode("utf-8").splitlines()' in source
        assert "eligibility_path.read_text" not in source
    assert 'eligibility_content.get("bindings", {}).get(' in core
    assert native.count(
        'eligibility.get("bindings", {}).get("request_envelope")'
    ) == 2

    def assert_rr_projection_binding(candidate: str) -> None:
        validators = re.findall(
            r"def validate_rr_projection_field\(.*?(?=\n\ndef )",
            candidate,
            re.DOTALL,
        )
        assert validators
        for validator in validators:
            assert "projection_from_bytes(" in validator
            assert "envelope_from_bytes(" in validator
            assert (
                'eligibility.get("bindings", {}).get("request_envelope")'
                in validator
            )
            assert "!= observed_envelope" in validator
            assert (
                "!= {\"path\": str(projection_path), **observed_projection}"
                in validator
            )
            assert (
                "!= {\"path\": str(envelope_path), **observed_envelope}"
                in validator
            )

    assert_rr_projection_binding(native)
    for original, replacement in (
        ("!= observed_envelope", "== observed_envelope"),
        (
            "!= {\"path\": str(projection_path), **observed_projection}",
            "== {\"path\": str(projection_path), **observed_projection}",
        ),
        (
            "!= {\"path\": str(envelope_path), **observed_envelope}",
            "== {\"path\": str(envelope_path), **observed_envelope}",
        ),
    ):
        mutant = native.replace(original, replacement, 1)
        assert mutant != native
        with pytest.raises(AssertionError):
            assert_rr_projection_binding(mutant)
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
    assert "for static_count in range(4)" in sequence
    assert "runnable != 22 - ollama_static_terminals - defense_terminal" in sequence
    assert "terminal != 24 + ollama_static_terminals + defense_terminal" in sequence
    assert '"target_runtime_terminal": 4 + static_count' in sequence
    assert 'RR_TERMINAL_LANES[0]: "measured_complete"' in sequence

    combined = "\n".join(sources.values())
    assert '"runnable": 26' not in combined
    assert '"runnable": 25' not in combined
    assert "(26, 20" not in combined
    assert "(25, 21" not in combined
    for current_lane in (
        "local-llava-rr-text-primary-100",
        "local-llava-rr-image-primary-100",
    ):
        assert current_lane not in combined


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

    expected = (18, 28, 7, ["defense-local"])
    assert require_profile(
        {
            "runnable_lanes": expected[0],
            "typed_terminal_lanes": expected[1],
            "target_runtime_terminal": expected[2],
            "conditional_na_lanes": expected[3],
        },
        sequence_conditional=["defense-local"],
        core_states=conditional,
        label="test-c926-exact",
    ) == expected
    with pytest.raises(SystemExit, match="Gate 5 inventory profile changed"):
        require_profile(
            {
                "runnable_lanes": 19,
                "typed_terminal_lanes": 27,
                "target_runtime_terminal": 7,
                "conditional_na_lanes": [],
            },
            sequence_conditional=[],
            core_states=complete,
            label="test-c926-no-defense-rejected",
        )
    with pytest.raises(SystemExit, match="conditional and core inventories differ"):
        require_profile(
            {
                "runnable_lanes": 18,
                "typed_terminal_lanes": 28,
                "target_runtime_terminal": 7,
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
    from experiments.local_campaign.ollama_static_terminal import (
        DISPOSITION as OLLAMA_STATIC_TERMINAL_DISPOSITION,
        OLLAMA_STATIC_TERMINAL_LANES,
        REASON_CODE as OLLAMA_STATIC_TERMINAL_REASON_CODE,
        historical_inventory_counts as ollama_static_inventory_counts,
    )

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
    namespace: dict[str, object] = {
        "OLLAMA_STATIC_TERMINAL_DISPOSITION": OLLAMA_STATIC_TERMINAL_DISPOSITION,
        "OLLAMA_STATIC_TERMINAL_LANES": OLLAMA_STATIC_TERMINAL_LANES,
        "OLLAMA_STATIC_TERMINAL_REASON_CODE": OLLAMA_STATIC_TERMINAL_REASON_CODE,
        "ollama_static_inventory_counts": ollama_static_inventory_counts,
    }
    exec(compile(contract, "<phase7-preparation-profile>", "exec"), namespace)
    require_profile = namespace["require_preparation_profile"]
    assert callable(require_profile)

    def profile(
        static_count: int, conditional: list[str]
    ) -> tuple[dict[str, object], dict[str, object]]:
        terminal_lanes = OLLAMA_STATIC_TERMINAL_LANES[:static_count]
        counts = ollama_static_inventory_counts(terminal_lanes, conditional)
        runnable = int(counts["runnable"])
        terminal = int(counts["typed_terminal"])
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
                "target_runtime_terminal": counts["target_runtime_terminal"],
                "conditional_na_lanes": conditional,
                "terminal_inventory": {
                    lane: {
                        "disposition": OLLAMA_STATIC_TERMINAL_DISPOSITION,
                        "reason_code": OLLAMA_STATIC_TERMINAL_REASON_CODE,
                    }
                    for lane in terminal_lanes
                },
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

    conditional_result, conditional_manifest = profile(3, ["defense-local"])
    assert require_profile(
        conditional_result,
        conditional_manifest,
        label="test-exact-c926-preparation",
    )[:4] == (18, 28, 7, ["defense-local"])
    for static_count in range(4):
        for conditional in ([], ["defense-local"]):
            if static_count == 3 and conditional == ["defense-local"]:
                continue
            result, manifest = profile(static_count, conditional)
            with pytest.raises(SystemExit, match="lifecycle profile differs"):
                require_profile(
                    result,
                    manifest,
                    label=(
                        f"test-rejected-static-{static_count}-"
                        f"conditional-{bool(conditional)}"
                    ),
                )

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


def test_bridge_canary_preserves_source_role_and_typed_abstention_contracts() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_bridge_attest_canary.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        'source_evaluator = execution["source_evaluator"]\n'
        'if expected_arm == "cyberseceval_prompt_injection":',
        'source_evaluator["status"] != "not_exercised"',
        'elif source_evaluator != {\n    "status": "not_applicable",',
        'source_evaluator["required_records"] <= 0',
        'source_evaluator["observed_records"] != 0',
        'source_evaluator["valid_records"] != 0',
        r'attacker_status\tsource_evaluator_status\ttarget_attempts\tsuccessful_target_generations\n',
        '"not_exercised" if row["lane"] == "bridge-purplellama" else "not_applicable"',
        'if row["source_evaluator_status"] != expected_source:',
        'responses = artifact_rows("responses")',
        "bound_decisions = validate_approximate_completion_bindings(\n",
        'proxy_policy = supplementary_metric_policy("measured")',
        "if decision is None:\n            try:\n"
        "                validate_prompt_proxy_abstention_guard_identity(",
        "validate_prompt_proxy_abstention_guard_identity(\n",
        'raw.get("judge_model") != expected_guard',
        'raw.get("model_revision") != expected_revision',
        'f"{expected_guard}@{expected_revision}"',
        "bound_results = validate_prompt_proxy_aggregate_bindings(\n",
        "aggregate_approximate_provenance(\n",
        'result.value != sum(values) / len(values)',
        'result.n != recomputed["n_result_units"]',
        'result.ci_low is not None',
        'raise ValueError(\n                "prompt-injection approximate result bucket is duplicated"',
        'raise ValueError(\n            "prompt-injection approximate result bucket inventory differs"',
        'provenance.model_dump(mode="json") != recomputed',
        "or decision.judge_model != expected_guard\n"
        "            or decision.judge_model_identity != expected_revision",
    )
    _assert_source_contract(template, required)
    for original, replacement in (
        (
            'source_evaluator = execution["source_evaluator"]\n'
            'if expected_arm == "cyberseceval_prompt_injection":',
            'source_evaluator = execution["source_evaluator"]\nif False:',
        ),
        (
            'elif source_evaluator != {\n    "status": "not_applicable",',
            'elif source_evaluator != {\n    "status": "not_exercised",',
        ),
        (
            'if row["source_evaluator_status"] != expected_source:',
            'if False:',
        ),
        (
            "bound_decisions = validate_approximate_completion_bindings(\n",
            "bound_decisions = validate_approximate_decision(\n",
        ),
        (
            "if decision is None:",
            "if False:",
        ),
        (
            'raw.get("judge_model") != expected_guard',
            "False",
        ),
        (
            "bound_results = validate_prompt_proxy_aggregate_bindings(\n",
            "bound_results = []  # ",
        ),
        (
            'provenance.model_dump(mode="json") != recomputed',
            "False",
        ),
        (
            "or decision.judge_model != expected_guard\n"
            "            or decision.judge_model_identity != expected_revision",
            "or False\n            or False",
        ),
    ):
        changed = template.replace(original, replacement, 1)
        assert changed != template
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)


def _mixed_prompt_proxy_fixture(tmp_path: Path) -> dict[str, object]:
    from ura.adapters.base import AttackBudget
    from ura.adapters.replay import ReplayAttacker
    from ura.approximate_metrics import validate_approximate_completion_bindings
    from ura.data_models import (
        DataPoint,
        DialogTurn,
        Judgment,
        Response,
        RiskCategory,
    )
    from ura.judges.base import BaseJudge, JudgeCascade
    from ura.judges.guardrail import GuardrailJudge
    from ura.runner import Runner
    from ura.targets.base import BaseTarget

    guard_model = "fixture/prompt-proxy-guard"
    guard_revision = "b" * 40
    required_metric = "cyberseceval_prompt_injection_judge_question"

    class FixtureTarget(BaseTarget):
        name = "fixture-target"
        modality_support = ("text",)

        def generate(self, dialog, *, seed=None):
            del dialog
            return Response(
                attempt_id="rebound-by-runner",
                target=self.name,
                output_turns=[
                    DialogTurn(role="assistant", content="harmless fixture answer")
                ],
                raw={
                    "requested_seed": seed,
                    "target_sampling_control": "deterministic_fixture",
                },
            )

    class MixedRules(BaseJudge):
        name = "rules"
        escalate_below = 0.75

        def judge(self, datapoint, response):
            decided = "abstain" not in datapoint.id
            return Judgment(
                attempt_id=response.attempt_id,
                judge=self.name,
                label="over_refusal" if decided else "safe",
                score=1.0 if decided else 0.0,
                raw={"confidence": 0.9 if decided else 0.0},
            )

    class SafeGuard(GuardrailJudge):
        def __init__(self) -> None:
            super().__init__(
                model=guard_model,
                revision=guard_revision,
                escalate_below=0.75,
            )

        def _ensure_loaded(self) -> None:
            return None

        def _run_guard(self, conversation) -> str:
            del conversation
            return "safe"

    def point(identifier: str, source: str) -> DataPoint:
        return DataPoint(
            id=identifier,
            source=source,
            modalities=["text"],
            dialog_history=[
                DialogTurn(role="user", content="Explain a harmless concept.")
            ],
            payload_text="Explain a harmless concept.",
            risk_category=RiskCategory.AGENTIC_MISUSE,
            expected_behavior="safe_answer",
            meta={
                "source_cluster_id": f"{source}-cluster",
                "common_metrics_eligible": False,
                "required_metric": required_metric,
                "source_metric_attackers": ["replay"],
            },
        )

    runner = Runner(
        ReplayAttacker(),
        FixtureTarget(),
        JudgeCascade([MixedRules(), SafeGuard()]),
        AttackBudget(max_queries=1, max_turns=1, seed=0),
        [0],
        approximate_common_metrics=True,
    )
    judgments, manifest = runner.run(
        [
            point("proxy-a-decision-1", "proxy-a"),
            point("proxy-a-decision-2", "proxy-a"),
            point("proxy-a-abstain", "proxy-a"),
            point("proxy-b-decision", "proxy-b"),
        ]
    )
    results = runner.aggregate(judgments, ["source"])
    trail_path = tmp_path / "mixed-prompt-proxy.trails.jsonl"
    runner.save_trails(trail_path)
    trails = [
        json.loads(line)
        for line in trail_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    policy = manifest.config["supplementary_metric_policy"]
    bound_decisions = validate_approximate_completion_bindings(
        judgments=judgments,
        responses=runner.responses,
        supplementary_policy=policy,
        trails=trails,
    )
    return {
        "namespace": _bridge_canary_fields_namespace(),
        "guard_model": guard_model,
        "guard_revision": guard_revision,
        "required_metric": required_metric,
        "judgments": [row.model_dump(mode="json") for row in judgments],
        "responses": [row.model_dump(mode="json") for row in runner.responses],
        "results": [row.model_dump(mode="json") for row in results],
        "policy": policy,
        "bound_decisions": bound_decisions,
    }


def test_bridge_canary_binds_abstention_authoritative_guard_identity(
    tmp_path: Path,
) -> None:
    import copy

    fixture = _mixed_prompt_proxy_fixture(tmp_path)
    validate = fixture["namespace"][
        "validate_prompt_proxy_abstention_guard_identity"
    ]
    abstention = next(
        row
        for row in fixture["judgments"]
        if row["raw"].get("approximate_decision_status") == "abstained"
    )
    validate(
        abstention,
        expected_guard=fixture["guard_model"],
        expected_revision=fixture["guard_revision"],
    )

    mutations = (
        ("judge_model", "fixture/wrong-guard"),
        ("model_revision", "0" * 40),
        ("model_identity", "fixture/wrong-guard@" + "0" * 40),
    )
    for field, value in mutations:
        changed = copy.deepcopy(abstention)
        changed["raw"][field] = value
        with pytest.raises(ValueError, match="exact selected Guard"):
            validate(
                changed,
                expected_guard=fixture["guard_model"],
                expected_revision=fixture["guard_revision"],
            )


def test_bridge_canary_recomputes_mixed_proxy_aggregate_buckets(
    tmp_path: Path,
) -> None:
    import copy

    fixture = _mixed_prompt_proxy_fixture(tmp_path)
    validate = fixture["namespace"]["validate_prompt_proxy_aggregate_bindings"]
    approximate_results = [
        row
        for row in fixture["results"]
        if row["metric"].startswith("approximate_")
    ]
    common = {
        "bound_decisions": fixture["bound_decisions"],
        "responses": fixture["responses"],
        "group_keys": ["source"],
        "required_metric": fixture["required_metric"],
        "supplementary_policy": fixture["policy"],
    }
    validated = validate(results=approximate_results, **common)
    assert len(validated) == 2
    assert len(fixture["bound_decisions"]) == 3
    assert sum(
        row["raw"].get("approximate_decision_status") == "abstained"
        for row in fixture["judgments"]
    ) == 1

    with pytest.raises(ValueError, match="bucket inventory differs"):
        validate(results=approximate_results[:-1], **common)
    with pytest.raises(ValueError, match="bucket is duplicated"):
        validate(
            results=[*approximate_results, copy.deepcopy(approximate_results[0])],
            **common,
        )

    changed = copy.deepcopy(approximate_results)
    one_decision_result = next(row for row in changed if row["n"] == 1)
    assert one_decision_result["value"] == 1.0
    one_decision_result["value"] = 0.0
    with pytest.raises(ValueError, match="estimate or support differs"):
        validate(results=changed, **common)

    changed = copy.deepcopy(approximate_results)
    next(row for row in changed if row["n"] == 2)["n"] = 1
    with pytest.raises(ValueError, match="EvalResult.n"):
        validate(results=changed, **common)

    changed = copy.deepcopy(approximate_results)
    two_decision_result = next(row for row in changed if row["n"] == 2)
    two_decision_result["n"] = 1
    nested = two_decision_result["provenance"]["approximate_security"]
    nested["n_supporting_decisions"] = 1
    nested["n_result_units"] = 1
    with pytest.raises(ValueError, match="estimate or support differs"):
        validate(results=changed, **common)

    changed = copy.deepcopy(approximate_results)
    nested = changed[0]["provenance"]["approximate_security"]
    nested["reliability_score"] = 0.0
    with pytest.raises(ValueError, match="does not match its exact decisions"):
        validate(results=changed, **common)


def test_gate5_revalidates_the_bounded_harmbench_attacker_config(
    tmp_path: Path,
) -> None:
    namespace = _rendered_gate5_namespace(tmp_path)

    def make_config(name: str, replay_payload: bytes) -> tuple[Path, str, dict[str, str]]:
        replay = tmp_path / f"{name}.replay.json"
        replay.write_bytes(replay_payload)
        replay_sha = hashlib.sha256(replay_payload).hexdigest()
        config = tmp_path / f"{name}.attacker.json"
        config.write_text(
            json.dumps(
                {
                    "harmbench": {
                        "methods": ["DirectRequest"],
                        "experiment": "llama2_7b",
                        "upstream_revision": "a" * 40,
                        "replay_artifact": str(replay.resolve()),
                        "replay_artifact_sha256": replay_sha,
                    }
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
        _loaded, artifact = namespace["_load_attacker_config"](
            str(config.resolve()), ["harmbench"], config_sha
        )
        assert artifact is not None
        identity = {
            "normalized_selected_sha256": artifact["normalized_selected_sha256"]
        }
        return config.resolve(), config_sha, identity

    bounded, bounded_sha, bounded_identity = make_config(
        "bounded", b'{"selection":{"limit":50}}\n'
    )
    canary, canary_sha, canary_identity = make_config(
        "canary", b'{"selection":{"limit":1}}\n'
    )
    assert bounded_identity != canary_identity

    validate = namespace["validate_bounded_harmbench_attacker_config"]
    assert validate(
        path_value=str(bounded),
        sha_value=bounded_sha,
        expected_identity=bounded_identity,
    ) == bounded
    gate5_error = namespace["Gate5Error"]
    with pytest.raises(gate5_error, match="does not match projection evidence"):
        validate(
            path_value=str(canary),
            sha_value=canary_sha,
            expected_identity=bounded_identity,
        )
    with pytest.raises(gate5_error, match="SHA differs"):
        validate(
            path_value=str(bounded),
            sha_value="0" * 64,
            expected_identity=bounded_identity,
        )


def test_gate5_promoter_reads_rr_rich_descriptors_without_stripping_identity(
    tmp_path: Path,
) -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_promote_gate5.sh.in"
    ).read_text(encoding="utf-8")
    block = template[
        template.index("def validate_rr_projection(") :
        template.index("def validate_rr_terminal_row(")
    ]
    required = (
        '"projection_artifact": {"path", "file", "sha256", "bytes"}',
        '"request_envelope_artifact": {',
        '\n            descriptor_path(item, f"{lane} RR {name}")',
        "projection_path = descriptor_path(",
        "eligibility_path = exact_descriptor_path(",
        "envelope_path = descriptor_path(",
    )
    _assert_source_contract(block, required)

    for reverted in (
        block.replace(
            'descriptor_path(item, f"{lane} RR {name}")',
            'exact_descriptor_path(item, f"{lane} RR {name}")',
            1,
        ),
        block.replace(
            "projection_path = descriptor_path(",
            "projection_path = exact_descriptor_path(",
            1,
        ),
    ):
        with pytest.raises(AssertionError):
            _assert_source_contract(reverted, required)

    namespace = _rendered_gate5_promoter_namespace(tmp_path)
    promotion_error = namespace["PromotionError"]
    calls: list[tuple[str, set[str]]] = []

    def descriptor_path(value: object, label: str) -> Path:
        assert isinstance(value, dict)
        calls.append((label, set(value)))
        return Path(str(value["path"]))

    def exact_descriptor_path(value: object, label: str) -> Path:
        assert isinstance(value, dict)
        if set(value) != {"path", "sha256", "bytes"}:
            raise promotion_error(f"{label} descriptor fields changed")
        calls.append((label, set(value)))
        return Path(str(value["path"]))

    projection_id = "lane-projection-" + "1" * 24
    eligibility_id = "eligibility-" + "2" * 24
    envelope_id = "request-envelope-" + "3" * 24
    projection_descriptor = {
        "path": str((tmp_path / f"{projection_id}.lane-projection.json").absolute()),
        "file": f"{projection_id}.lane-projection.json",
        "sha256": "4" * 64,
        "bytes": 10,
    }
    eligibility_descriptor = {
        "path": str((tmp_path / f"{eligibility_id}.eligibility.json").absolute()),
        "sha256": "5" * 64,
        "bytes": 11,
    }
    envelope_descriptor = {
        "path": str((tmp_path / f"{envelope_id}.request-envelope.json").absolute()),
        "envelope_id": envelope_id,
        "file": f"{envelope_id}.request-envelope.json",
        "sha256": "6" * 64,
        "bytes": 12,
    }
    projected_calls = {
        "trajectories": 1,
        "target_calls": 1,
        "model_judge_calls": 0,
        "local_guardrail_evaluations": 0,
        "http_attempts": 0,
    }
    retained_projection = {
        "projection_id": projection_id,
        "selection": {},
        "call_projection": {
            "trajectories": 1,
            "target_calls": 1,
            "judge_calls": 0,
            "local_guardrail_evaluations": 0,
            "http_attempts": 0,
        },
    }
    namespace.update({
        "descriptor_path": descriptor_path,
        "exact_descriptor_path": exact_descriptor_path,
        "load_stable_lane_projection_file": lambda *_args: (
            retained_projection,
            {key: projection_descriptor[key] for key in ("file", "sha256", "bytes")},
        ),
        "load_eligibility_artifact": lambda *_args: (
            {"plan_id": eligibility_id},
            {key: eligibility_descriptor[key] for key in ("sha256", "bytes")},
        ),
        "load_stable_request_envelope_file": lambda *_args: (
            {"envelope_id": envelope_id},
            {key: envelope_descriptor[key] for key in ("envelope_id", "file", "sha256", "bytes")},
        ),
        "validate_lane_projection_binding": lambda *_args, **_kwargs: None,
        "validate_eligibility_envelope_binding": lambda *_args, **_kwargs: None,
        "validate_rr_projection_lane": lambda *_args, **_kwargs: None,
    })
    validate = namespace["validate_rr_projection"]
    assert callable(validate)
    assert validate(
        {
            "projection_id": projection_id,
            "projection_artifact": projection_descriptor,
            "eligibility_plan_id": eligibility_id,
            "eligibility_artifact": eligibility_descriptor,
            "request_envelope_id": envelope_id,
            "request_envelope_artifact": envelope_descriptor,
            "selection": {},
            "projected_calls": projected_calls,
        },
        lane="local-llava-rr-text-full",
        validate_files=True,
    ) == ("4" * 64, 10)
    assert all(
        fields >= {"path", "sha256", "bytes"}
        for _label, fields in calls
    )


def test_gate5_accepts_exact_prompt_proxy_guard_abstention_without_results(
    tmp_path: Path,
) -> None:
    import copy

    namespace = _rendered_gate5_namespace(tmp_path)
    metric = namespace["PROMPT_PROXY_METRIC"]
    model = namespace["EXPECTED_SCORE_GUARD"]
    revision = namespace["EXPECTED_SCORE_GUARD_REVISION"]
    attempt_id = "attempt-prompt-proxy-abstention"
    policy = {
        "stage_queried": True,
        "policy_evaluation_status": "approximate_common_security_proxy",
        "metric_authority": "supplementary_non_authoritative",
        "required_metric": metric,
    }
    judgment = {
        "attempt_id": attempt_id,
        "judge": "guardrail",
        "label": "not_applicable",
        "score": 0.0,
        "raw": {
            **policy,
            "expected_behavior": "safe_answer",
            "policy_evaluable_turn": True,
            "common_metrics_eligible": False,
            "cascade_stage": 1,
            "cascade_role": "authoritative",
            "cascade_confident": True,
            "confidence": 0.0,
            "parsed": True,
            "unsafe": False,
            "guardrail_queried": True,
            "over_refusal_expressible": False,
            "automated_decision_status": "abstained",
            "approximate_decision_status": "abstained",
            "abstention_reason": (
                "guardrail_safe_cannot_adjudicate_benign_over_refusal"
            ),
            "approximate_security_decision": None,
            "approximate_rubric_stage_binding": None,
            "model": "fixture-target",
            "judge_model": model,
            "model_revision": revision,
            "model_identity": f"{model}@{revision}",
            "source_evaluation": {
                "family": metric,
                "implemented": False,
                "valid": False,
            },
        },
    }
    trails = [
        {
            **policy,
            "attempt_id": attempt_id,
            "stage": 0,
            "judge": "rules",
            "cascade_role": "shadow",
            "cascade_confident": False,
        },
        {
            **policy,
            "attempt_id": attempt_id,
            "stage": 1,
            "judge": "guardrail",
            "cascade_role": "authoritative",
            "cascade_confident": True,
            "confidence": 0.0,
            "label": "not_applicable",
            "score": 0.0,
            "parsed": True,
            "guardrail_unsafe": False,
            "guardrail_queried": True,
            "over_refusal_expressible": False,
            "automated_decision_status": "abstained",
            "abstention_reason": (
                "guardrail_safe_cannot_adjudicate_benign_over_refusal"
            ),
            "judge_model": model,
            "judge_model_revision": revision,
            "judge_model_identity": f"{model}@{revision}",
        },
    ]
    rows = {"judgments": [judgment], "trails": trails, "results": []}
    (tmp_path / "cell.complete.json").write_text("{}\n", encoding="utf-8")
    namespace["read_strict_json"] = lambda _path: {}
    namespace["_canary_artifact_rows"] = (
        lambda _root, _marker, kind, *, label: copy.deepcopy(rows[kind])
    )
    validate = namespace["validate_prompt_proxy_artifacts"]
    summary = validate(tmp_path, label="test")
    assert summary["metrics"] == []
    assert summary["evaluable"] == 1
    assert summary["decisions"] == 0
    assert summary["abstentions"] == 1
    assert summary["decision_coverage"] == 0.0
    assert summary["aggregate_results"] == 0
    assert summary["selected_judges"] == []

    rows["results"] = [{"metric": "approximate_over_refusal_rate"}]
    with pytest.raises(
        namespace["Gate5Error"], match="abstained prompt proxy retained metric results"
    ):
        validate(tmp_path, label="test")
    rows["results"] = []
    rows["judgments"][0]["raw"]["judge_model"] = "fixture/wrong-guard"
    with pytest.raises(namespace["Gate5Error"], match="abstention is not exact"):
        validate(tmp_path, label="test")
    rows["judgments"][0]["raw"]["judge_model"] = model
    rows["judgments"][0]["raw"]["model_revision"] = "0" * 40
    with pytest.raises(namespace["Gate5Error"], match="abstention is not exact"):
        validate(tmp_path, label="test")
    rows["judgments"][0]["raw"]["model_revision"] = revision
    rows["judgments"][0]["raw"]["model_identity"] = (
        f"fixture/wrong-guard@{'0' * 40}"
    )
    with pytest.raises(namespace["Gate5Error"], match="abstention is not exact"):
        validate(tmp_path, label="test")
    rows["judgments"][0]["raw"]["model_identity"] = f"{model}@{revision}"
    rows["judgments"][0]["raw"]["confidence"] = False
    with pytest.raises(namespace["Gate5Error"], match="abstention is not exact"):
        validate(tmp_path, label="test")
    rows["judgments"][0]["raw"]["confidence"] = 0.0
    rows["trails"][1]["confidence"] = 0.1
    with pytest.raises(
        namespace["Gate5Error"], match="terminal Guard N/A disposition"
    ):
        validate(tmp_path, label="test")
    rows["trails"][1]["confidence"] = 0.0
    rows["trails"][0]["cascade_role"] = "authoritative"
    rows["trails"][0]["cascade_confident"] = True
    with pytest.raises(namespace["Gate5Error"], match="lacks one authority"):
        validate(tmp_path, label="test")


def test_phase6_prompt_proxy_selftest_covers_exact_guard_abstention(
    tmp_path: Path,
) -> None:
    namespace = _rendered_phase6_extended_namespace(tmp_path)
    value = namespace["selected_judge_contract_self_test"]()
    assert value["status"] == "passed"
    assert {
        "proxy-decision-missing-result",
        "proxy-abstention-invented-summary-result",
        "proxy-abstention-wrong-coverage",
        "proxy-abstention-integer-coverage",
        "proxy-abstention-source-evaluator-claim",
        "proxy-abstention-wrong-judge-model",
        "proxy-abstention-wrong-judge-revision",
        "proxy-abstention-wrong-judge-identity",
        "proxy-abstention-multiple-authorities",
        "proxy-abstention-boolean-stage",
        "proxy-abstention-confident-shadow",
        "proxy-abstention-boolean-trail-confidence",
        "proxy-abstention-nonzero-trail-confidence",
        "proxy-abstention-boolean-judgment-confidence",
        "proxy-abstention-nonzero-judgment-confidence",
        "proxy-abstention-invented-result",
    } <= set(value["rejected_cases"])


def test_gate5_relationship_helpers_reject_coherent_mutations(
    tmp_path: Path,
) -> None:
    namespace = _rendered_gate5_namespace(tmp_path)
    gate5_error = namespace["Gate5Error"]

    validate_source = namespace["validate_common_source_evaluator"]
    common_source = {
        "status": "not_applicable",
        "required_records": 0,
        "observed_records": 0,
        "valid_records": 0,
    }
    proxy_source = {
        "status": "not_exercised",
        "required_records": 1,
        "observed_records": 0,
        "valid_records": 0,
    }
    validate_source(common_source, arm="strongreject_official", label="test")
    validate_source(
        proxy_source, arm="cyberseceval_prompt_injection", label="test"
    )
    with pytest.raises(gate5_error, match="unexpectedly requires"):
        validate_source(proxy_source, arm="strongreject_official", label="test")
    with pytest.raises(gate5_error, match="required-but-unimplemented"):
        validate_source(
            common_source, arm="cyberseceval_prompt_injection", label="test"
        )

    def audit(
        *,
        limit: int,
        clusters: list[str],
        rows: list[str],
        selected_digest: str,
        full_digest: str = "f" * 64,
    ) -> dict[str, object]:
        return {
            "converter": "test-converter",
            "full_converted_corpus_sha256": full_digest,
            "selected_converted_corpus_sha256": selected_digest,
            "total_records": 3,
            "selected_records": len(rows),
            "selected_ids": rows,
            "total_clusters": 3,
            "selected_clusters": len(clusters),
            "total_cluster_ids": ["cluster-1", "cluster-2", "cluster-3"],
            "selected_cluster_ids": clusters,
            "sample_seed": 0,
            "limit": limit,
            "selection_method": "seeded_nested_source_cluster_prefix_v1",
        }

    arm_from_audit = namespace["projection_arm_from_audit"]
    binding_from_audit = namespace["sampling_binding_from_audit"]
    canonical_digest = namespace["canonical_json_sha256"]
    validate_sampling = namespace["validate_sampling_relationship_evidence"]

    def workload(value: dict[str, object]) -> dict[str, object]:
        clusters = sorted(value["selected_cluster_ids"])
        rows = sorted(value["selected_ids"])
        return {
            "selected_clusters": len(clusters),
            "selected_cluster_ids": clusters,
            "selected_cluster_ids_sha256": canonical_digest(clusters),
            "selected_rows": len(rows),
            "selected_row_ids": rows,
            "selected_row_ids_sha256": canonical_digest(rows),
        }

    bounded_audit = audit(
        limit=2,
        clusters=["cluster-1", "cluster-2"],
        rows=["row-1", "row-2"],
        selected_digest="b" * 64,
    )
    canary_audit = audit(
        limit=1,
        clusters=["cluster-1"],
        rows=["row-1"],
        selected_digest="c" * 64,
    )

    def validate_pair(canary_value: dict[str, object]) -> None:
        validate_sampling(
            lane="test-lane",
            arm="test-arm",
            expected_limit=2,
            preliminary_arm=arm_from_audit(
                bounded_audit, logical_source_arm="test-arm"
            ),
            preliminary_binding=binding_from_audit(bounded_audit),
            canary_arm=arm_from_audit(
                canary_value, logical_source_arm="test-arm"
            ),
            canary_binding=binding_from_audit(canary_value),
            bounded_audit=bounded_audit,
            canary_audit=canary_value,
            canary_workload=workload(canary_value),
        )

    validate_pair(canary_audit)
    assert (
        bounded_audit["selected_converted_corpus_sha256"]
        != canary_audit["selected_converted_corpus_sha256"]
    )
    outside_sample = audit(
        limit=1,
        clusters=["cluster-3"],
        rows=["row-3"],
        selected_digest="d" * 64,
    )
    with pytest.raises(gate5_error, match="not nested"):
        validate_pair(outside_sample)
    different_universe = audit(
        limit=1,
        clusters=["cluster-1"],
        rows=["row-1"],
        selected_digest="c" * 64,
        full_digest="e" * 64,
    )
    with pytest.raises(gate5_error, match="source universes differ"):
        validate_pair(different_universe)

    shared = {
        "source_conformance": {"sha256": "9" * 64, "bytes": 1},
        "engine_runtime_config": None,
        "api_config": None,
        "local_config": {"normalized_selected_sha256": "8" * 64},
    }

    def selected_configs(source: str, attacker: object) -> dict[str, object]:
        return {
            "source_config": {"normalized_selected_sha256": source},
            "attacker_config": attacker,
            **shared,
        }

    validate_configs = namespace["validate_selected_config_relationship"]
    bounded_values = {
        "selected_config_identities": selected_configs("1" * 64, None)
    }
    canary_values = {
        "selected_config_identities": selected_configs("2" * 64, None)
    }
    validate_configs(
        lane="test-lane",
        preliminary_values=bounded_values,
        canary_values=canary_values,
        preliminary_source_identity={"normalized_selected_sha256": "1" * 64},
        canary_source_identity={"normalized_selected_sha256": "2" * 64},
    )
    changed_shared_config = {
        "selected_config_identities": {
            **selected_configs("2" * 64, None),
            "local_config": {"normalized_selected_sha256": "7" * 64},
        }
    }
    with pytest.raises(gate5_error, match="local_config identity differs"):
        validate_configs(
            lane="test-lane",
            preliminary_values=bounded_values,
            canary_values=changed_shared_config,
            preliminary_source_identity={"normalized_selected_sha256": "1" * 64},
            canary_source_identity={"normalized_selected_sha256": "2" * 64},
        )

    bounded_attacker = {"normalized_selected_sha256": "3" * 64}
    canary_attacker = {"normalized_selected_sha256": "4" * 64}
    harm_bounded = {
        "selected_config_identities": selected_configs(
            "1" * 64, bounded_attacker
        )
    }
    harm_canary = {
        "selected_config_identities": selected_configs("2" * 64, canary_attacker)
    }
    validate_configs(
        lane="harmbench-replay",
        preliminary_values=harm_bounded,
        canary_values=harm_canary,
        preliminary_source_identity={"normalized_selected_sha256": "1" * 64},
        canary_source_identity={"normalized_selected_sha256": "2" * 64},
    )
    unregenerated = {
        "selected_config_identities": selected_configs(
            "2" * 64, bounded_attacker
        )
    }
    with pytest.raises(gate5_error, match="were not regenerated"):
        validate_configs(
            lane="harmbench-replay",
            preliminary_values=harm_bounded,
            canary_values=unregenerated,
            preliminary_source_identity={"normalized_selected_sha256": "1" * 64},
            canary_source_identity={"normalized_selected_sha256": "2" * 64},
        )


def _assert_source_contract(source: str, required: tuple[str, ...]) -> None:
    for snippet in required:
        assert snippet in source


@pytest.mark.parametrize(
    ("filename", "required", "mutations"),
    (
        (
            "phase5_core_attest_canary.sh.in",
            (
                '"requested_target_keys": [expected_spec]',
                'expected_runtime = f"{expected_spec}@{revision}"',
                'expected_runtime += "+guard"',
                '"models": [expected_runtime]',
                'set(observed_local_configs) != {expected_runtime}',
                'observed_local_configs[expected_runtime]',
                'condition.get("requested_model_spec") != expected_runtime',
                'condition.get("resolved_target") != expected_runtime',
                'target_snapshot.get("target") != expected_runtime',
            ),
            (
                ('"models": [expected_runtime]', '"models": [expected_spec]'),
                ('expected_runtime += "+guard"', 'expected_runtime += ""'),
            ),
        ),
        (
            "phase5_ollama_workflow.sh.in",
            (
                '"requested_target_keys": [expected_spec]',
                'expected_runtime = expected_spec + "@sha256:" + digest',
                '"models": [expected_runtime]',
                'expected_runtime: local_config[expected_spec]',
                'condition.get("requested_model_spec") != expected_runtime',
                'condition.get("resolved_target") != expected_runtime',
                'target_snapshot.get("target") != expected_runtime',
            ),
            (
                ('"models": [expected_runtime]', '"models": [expected_spec]'),
                (
                    'expected_runtime: local_config[expected_spec]',
                    'expected_spec: local_config[expected_spec]',
                ),
            ),
        ),
        (
            "phase6_core_measured.sh.in",
            (
                'expected_runtime = f"{spec[\'target\'][\'spec\']}@'
                '{spec[\'target\'][\'revision\']}"',
                'expected_runtime += "+guard"',
                'grid_request.get("models") != [expected_runtime]',
                'set(local_configs) != {expected_runtime}',
                'local_configs[expected_runtime]',
            ),
            (
                (
                    'grid_request.get("models") != [expected_runtime]',
                    'grid_request.get("models") != [spec["target"]["spec"]]',
                ),
                ('expected_runtime += "+guard"', 'expected_runtime += ""'),
            ),
        ),
        (
            "phase6_extended_measured.sh.in",
            (
                'if spec["family"] == "ollama":',
                'f"{spec[\'target\'][\'spec\']}@sha256:'
                '{spec[\'target\'][\'digest\']}"',
                'f"{spec[\'target\'][\'spec\']}@'
                '{spec[\'target\'][\'revision\']}"',
                'grid_request.get("models") != [expected_runtime]',
            ),
            ((
                'grid_request.get("models") != [expected_runtime]',
                'grid_request.get("models") != [spec["target"]["spec"]]',
            ),),
        ),
    ),
)
def test_campaign_validators_use_canonical_runtime_target_identities(
    filename: str,
    required: tuple[str, ...],
    mutations: tuple[tuple[str, str], ...],
) -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / filename
    ).read_text(encoding="utf-8")
    _assert_source_contract(source, required)
    for original, replacement in mutations:
        changed = source.replace(original, replacement, 1)
        assert changed != source
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)


@pytest.mark.parametrize(
    ("filename", "completed_expression"),
    (
        (
            "phase5_core_attest_canary.sh.in",
            'row["workload"]["completed_judgments"]',
        ),
        (
            "phase5_ollama_workflow.sh.in",
            'workload["completed_judgments"]',
        ),
        (
            "phase5_finalize_gate5.sh.in",
            'retained["workload"]["completed_judgments"]',
        ),
    ),
)
def test_classification_canaries_preserve_invalid_source_predictions(
    filename: str,
    completed_expression: str,
) -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / filename
    ).read_text(encoding="utf-8")
    required = (
        'source["required_records"] != source["observed_records"]',
        f'source["observed_records"] != {completed_expression}',
        'source["valid_records"] < 0',
        'source["valid_records"] > source["observed_records"]',
    )
    _assert_source_contract(source, required)

    restrictive_mutation = source.replace(
        'source["valid_records"] < 0',
        'source["valid_records"] <= 0',
        1,
    )
    assert restrictive_mutation != source
    with pytest.raises(AssertionError):
        _assert_source_contract(restrictive_mutation, required)


def test_ollama_canaries_allow_completed_zero_decision_observations() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_ollama_workflow.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        'if not isinstance(support.get("decision_coverage"), (int, float)):',
        'raise SystemExit("canary lacks numeric decision coverage")',
        'item.get("guardrail_queried") is not True',
        'item.get("judge_model_identity") != f"{guard_model}@{guard_revision}"',
    )

    def assert_contract(value: str) -> None:
        _assert_source_contract(value, required)
        assert "static canary lacks decided support" not in value
        assert 'support.get("decided", 0) <= 0' not in value

    assert_contract(source)
    restrictive_mutation = source.replace(
        "print(\n    summary[\"canary_id\"],",
        'if support.get("decided", 0) <= 0:\n'
        '    raise SystemExit("static canary lacks decided support")\n'
        "print(\n    summary[\"canary_id\"],",
        1,
    )
    assert restrictive_mutation != source
    with pytest.raises(AssertionError):
        assert_contract(restrictive_mutation)


def test_ollama_nonzero_canary_failures_are_not_converted_to_old_terminals() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_ollama_workflow.sh.in"
    ).read_text(encoding="utf-8")
    _, canary_tail = source.split("run_canary_lane() {", 1)
    canary_body, remainder = canary_tail.split("\n}\n\nsource_status_row()", 1)
    canary_required = (
        "Runner 2.24 retains nonempty length-capped text",
        "successful empty completion as model_nonresponse",
        'if (( runner_rc != 0 )); then',
        'return "$runner_rc"',
        '"$successful_target_generations" | tee -a "$CANARY_STATUS"',
    )
    remainder_required = ('row["disposition"] != "runnable"',)

    def assert_canary_contract(value: str) -> None:
        _assert_source_contract(value, canary_required)

    assert_canary_contract(canary_body)
    _assert_source_contract(remainder, remainder_required)
    assert "experiments.local_campaign.ollama_static_terminal classify" not in canary_body
    assert "target-runtime-terminal" not in canary_body

    changed = canary_body.replace('return "$runner_rc"', "return 0", 1)
    assert changed != canary_body
    with pytest.raises(AssertionError):
        assert_canary_contract(changed)

    assert "terminal_lanes" not in remainder


def _assert_completion_bound_guard_query_contract(
    template: str,
    *,
    summary_name: str,
    adaptive: bool,
    typed_nonresponse: bool,
) -> None:
    assert "completion_payload = stable_payload(completion_path" in template
    assert (
        'completion_marker = strict_json_loads(completion_payload.decode("utf-8"))'
        in template
    )
    assert "def completion_rows(kind: str)" in template
    assert (
        'set(descriptor) != {\n        "file", "sha256", "bytes", "records"\n    }'
        in template
    )
    assert (
        'hashlib.sha256(payload).hexdigest() != descriptor.get("sha256")'
        in template
    )
    assert 'len(rows) != descriptor.get("records")' in template
    assert (
        f'{summary_name}["bindings"]["completion_artifact"] != completion_descriptor'
        in template
    )

    guard_contract = template.split("    guard_trails = [", 1)[1].split(
        '        raise SystemExit(\n            "', 1
    )[0]
    assert 'completion_rows("trails")' in guard_contract
    if adaptive:
        stage_contract = template.split(
            "    for stage_index, judge_name in ((0, \"rules\"), (1, \"guardrail\")):",
            1,
        )[1].split("    guard_trails = [", 1)[0]
        assert (
            'sum(item["queried_records"] for item in stage_rows) != evaluable'
            in stage_contract
        )
        assert (
            'sum(item["not_queried_records"] for item in stage_rows)\n'
            "            != completed - evaluable"
            in stage_contract
        )
        assert "len(queried_guard_trails) != evaluable" in guard_contract
        assert (
            "len(unqueried_guard_trails) != completed - evaluable"
            in guard_contract
        )
        assert guard_contract.count('item.get("stage_queried") is True') == 1
        assert guard_contract.count('item.get("stage_queried") is False') == 1
        assert guard_contract.count(
            'item.get("guardrail_queried") is not True'
        ) == 1
        assert guard_contract.count(
            'item.get("guardrail_queried") is not None'
        ) == 1
        assert 'item.get("policy_evaluation_status") != "not_evaluable"' in (
            guard_contract
        )
    elif typed_nonresponse:
        stage_contract = template.split(
            '    queried = completed - len(nonresponse_ids)', 1
        )[1].split("    guard_trails = [", 1)[0]
        assert "validate_static_canary_stage_support(" in stage_contract
        assert "completed=completed" in stage_contract
        assert "nonresponses=len(nonresponse_ids)" in stage_contract
        assert "len(queried_guard_trails) != queried" in guard_contract
        assert (
            "len(unqueried_guard_trails) != len(nonresponse_ids)"
            in guard_contract
        )
        assert (
            '{item.get("attempt_id") for item in unqueried_guard_trails}\n'
            "        != nonresponse_ids"
        ) in guard_contract
        assert guard_contract.count('item.get("stage_queried") is True') == 1
        assert guard_contract.count('item.get("stage_queried") is False') == 1
        assert guard_contract.count(
            'item.get("guardrail_queried") is not True'
        ) == 1
        assert guard_contract.count(
            'item.get("guardrail_queried") is not None'
        ) == 1
        assert 'item.get("policy_evaluation_status") != "model_nonresponse"' in (
            guard_contract
        )
    else:
        assert guard_contract.count('item.get("stage_queried") is not True') == 1
        assert guard_contract.count(
            'item.get("guardrail_queried") is not True'
        ) == 1
    assert 'item.get("judge_model") != ' in guard_contract
    assert 'item.get("judge_model_revision") != ' in guard_contract
    assert 'item.get("judge_model_identity")' in guard_contract


@pytest.mark.parametrize(
    ("filename", "summary_name", "adaptive", "typed_nonresponse"),
    [
        ("phase5_core_attest_canary.sh.in", "row", True, False),
        ("phase5_ollama_workflow.sh.in", "summary", False, True),
    ],
)
def test_canaries_prove_a_completion_bound_guard_query(
    filename: str,
    summary_name: str,
    adaptive: bool,
    typed_nonresponse: bool,
) -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / filename
    ).read_text(encoding="utf-8")
    _assert_completion_bound_guard_query_contract(
        template,
        summary_name=summary_name,
        adaptive=adaptive,
        typed_nonresponse=typed_nonresponse,
    )
    if typed_nonresponse:
        function = template.split("canary_fields() {", 1)[1].split(
            "\n}\n\nrun_canary_lane()", 1
        )[0]
        match = re.search(r"<<'PY'\n(.*?)\nPY(?:\n|$)", function, re.DOTALL)
        assert match is not None
        compile(match.group(1), "phase5_ollama_canary_fields.py", "exec")

    guard_start = template.index("    guard_trails = [")
    query_start = template.index(
        'item.get("guardrail_queried") is not True', guard_start
    )
    query_end = query_start + len(
        'item.get("guardrail_queried") is not True'
    )
    query_mutation = (
        template[:query_start]
        + 'item.get("stage_queried") is not True'
        + template[query_end:]
    )
    assert query_mutation != template
    with pytest.raises(AssertionError):
        _assert_completion_bound_guard_query_contract(
            query_mutation,
            summary_name=summary_name,
            adaptive=adaptive,
            typed_nonresponse=typed_nonresponse,
        )

    if adaptive:
        stage_denominator_mutation = template.replace(
            'sum(item["queried_records"] for item in stage_rows) != evaluable',
            'sum(item["queried_records"] for item in stage_rows) != completed',
            1,
        )
        assert stage_denominator_mutation != template
        with pytest.raises(AssertionError):
            _assert_completion_bound_guard_query_contract(
                stage_denominator_mutation,
                summary_name=summary_name,
                adaptive=adaptive,
                typed_nonresponse=typed_nonresponse,
            )

        completion_denominator_mutation = template.replace(
            "len(queried_guard_trails) != evaluable",
            "len(queried_guard_trails) != completed",
            1,
        )
        assert completion_denominator_mutation != template
        with pytest.raises(AssertionError):
            _assert_completion_bound_guard_query_contract(
                completion_denominator_mutation,
                summary_name=summary_name,
                adaptive=adaptive,
                typed_nonresponse=typed_nonresponse,
            )

    if typed_nonresponse:
        reachability_mutation = template.replace(
            "validate_static_canary_stage_support(",
            "validate_static_canary_stage_support_disabled(",
            1,
        )
        assert reachability_mutation != template
        with pytest.raises(AssertionError):
            _assert_completion_bound_guard_query_contract(
                reachability_mutation,
                summary_name=summary_name,
                adaptive=adaptive,
                typed_nonresponse=typed_nonresponse,
            )
        completion_denominator_mutation = template.replace(
            "len(queried_guard_trails) != queried",
            "len(queried_guard_trails) != completed",
            1,
        )
        assert completion_denominator_mutation != template
        with pytest.raises(AssertionError):
            _assert_completion_bound_guard_query_contract(
                completion_denominator_mutation,
                summary_name=summary_name,
                adaptive=adaptive,
                typed_nonresponse=typed_nonresponse,
            )

    binding_mutation = template.replace(
        f'{summary_name}["bindings"]["completion_artifact"] != completion_descriptor',
        "completion_descriptor != completion_descriptor",
        1,
    )
    assert binding_mutation != template
    with pytest.raises(AssertionError):
        _assert_completion_bound_guard_query_contract(
            binding_mutation,
            summary_name=summary_name,
            adaptive=adaptive,
            typed_nonresponse=typed_nonresponse,
        )


def test_phase6_uses_the_approved_lane_wall_ceiling_and_reaps_timed_out_trees() -> None:
    templates = (
        Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    )
    gate5 = (templates / "phase5_finalize_gate5.sh.in").read_text(encoding="utf-8")
    core = (templates / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    sequence = (templates / "phase6_sequence.sh.in").read_text(encoding="utf-8")

    gate5_required = (
        "MEASURED_LANE_WALL_TIME_SECONDS = 86_400",
        '"measured_lane_wall_time_seconds": MEASURED_LANE_WALL_TIME_SECONDS',
        '"measured_lane_wall_time_semantics":',
        '"controller_completion_ceiling_distinct_from_call_start_admission_window"',
        '"measured_lane_wall_time_seconds": MEASURED_LANE_WALL_TIME_SECONDS',
    )
    _assert_source_contract(gate5, gate5_required)
    core_required = (
        "wait_lane_with_ceiling() {",
        'kill -TERM -- "-$child"',
        'kill -KILL -- "-$child"',
        'wait "$child"',
        "return 124",
        'wait_lane_with_ceiling "$active_child_pid" "$controller_lane"',
        "for spec_path in \"${SPEC_FILES[@]}\"; do",
        "aggregate_lane_rc=1",
    )
    _assert_source_contract(core, core_required)
    extended_required = (
        'if os.name != "posix" or not hasattr(signal, "setitimer"):',
        "signal.setitimer(signal.ITIMER_REAL, wall_time)",
        "signal.setitimer(signal.ITIMER_REAL, 0)",
        "start_new_session=True",
        "os.killpg(process.pid, signal.SIGTERM)",
        "os.killpg(process.pid, signal.SIGKILL)",
        "process.wait(timeout=self.remaining_lane_time(lane))",
        "for spec_path in spec_paths:",
        "continue",
        'wrong_wall_time[failed_lane]["approved_wall_time_seconds"] = 86_401',
        'must_fail("wall-time-ceiling", mutated_failures=wrong_wall_time)',
    )
    _assert_source_contract(extended, extended_required)
    sequence_required = (
        'GATE5_LANE_WALL_TIME_SECONDS="${gate5_values[4]}"',
        'test "$GATE5_LANE_WALL_TIME_SECONDS" = \'86400\'',
        'test "${#gate5_final[@]}" -eq 5',
        'test "${gate5_final[4]}" = "$GATE5_LANE_WALL_TIME_SECONDS"',
        "controller_ceiling=$((GATE5_LANE_WALL_TIME_SECONDS * (lane_count + 1)))",
        "controller-wall-time-exceeded",
        'tmux -L "$socket" kill-session -t "$session"',
    )
    _assert_source_contract(sequence, sequence_required)

    for source, required, original, replacement in (
        (
            gate5,
            gate5_required,
            "MEASURED_LANE_WALL_TIME_SECONDS = 86_400",
            "MEASURED_LANE_WALL_TIME_SECONDS = 86_401",
        ),
        (core, core_required, 'kill -KILL -- "-$child"', ":"),
        (
            extended,
            extended_required,
            "os.killpg(process.pid, signal.SIGKILL)",
            "process.kill()",
        ),
        (
            extended,
            extended_required,
            'wrong_wall_time[failed_lane]["approved_wall_time_seconds"] = 86_401',
            'wrong_wall_time[failed_lane]["approved_wall_time_seconds"] = 86_400',
        ),
        (
            sequence,
            sequence_required,
            'test "$GATE5_LANE_WALL_TIME_SECONDS" = \'86400\'',
            'test "$GATE5_LANE_WALL_TIME_SECONDS" = \'86401\'',
        ),
        (
            sequence,
            sequence_required,
            'test "${#gate5_final[@]}" -eq 5',
            'test "${#gate5_final[@]}" -eq 4',
        ),
        (
            sequence,
            sequence_required,
            'test "${gate5_final[4]}" = "$GATE5_LANE_WALL_TIME_SECONDS"',
            ':',
        ),
    ):
        changed = source.replace(original, replacement, 1)
        assert changed != source
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)


def test_phase6_pre_runner_failures_are_typed_non_evidence_and_phase7_required() -> None:
    templates = (
        Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    )
    core = (templates / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    phase7 = (templates / "phase7_analysis.py.in").read_text(encoding="utf-8")

    producer_required = (
        '"schema": "ura-phase6-pre-runner-failure/1"',
        '"artifact_role": "controller_pre_runner_failure_not_runner_artifact"',
        '"runner_artifact": False',
        '"evidence_eligible": False',
        '"runner_lifecycle_artifact_count": 0',
    )
    for producer in (core, extended):
        _assert_source_contract(producer, producer_required)
    phase7_required = (
        "def validate_pre_runner_failure_artifact(",
        'marker.get("schema") != "ura-phase6-pre-runner-failure/1"',
        'marker.get("runner_artifact") is not False',
        'marker.get("evidence_eligible") is not False',
        'f"{lane}: failed lifecycle Runner root is absent"',
        'if pre_runner_failures != 1:',
        'return "pre_runner_failure_no_request_artifact"',
        '"lifecycle-pre-runner-without-typed-artifact"',
    )
    _assert_source_contract(phase7, phase7_required)

    changed = phase7.replace(
        'f"{lane}: failed lifecycle Runner root is absent"',
        "continue",
        1,
    )
    assert changed != phase7
    with pytest.raises(AssertionError):
        _assert_source_contract(changed, phase7_required)


def test_phase6_extended_publishes_only_the_frozen_three_field_descriptor() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_extended_measured.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        'def frozen_descriptor(path: Path) -> dict[str, Any]:',
        '"path": value["path"],',
        '"sha256": value["sha256"],',
        '"bytes": value["bytes"],',
        'descriptor_fields = {"path", "sha256", "bytes"}',
        'extra_descriptor_field[failed_lane]["lane_spec"]["file"]',
        '"frozen-descriptor-rejects-extra-file-field"',
        "lane: frozen_descriptor(lane_failures[lane]) for lane in failed",
    )
    _assert_source_contract(source, required)
    changed = source.replace(
        'descriptor_fields = {"path", "sha256", "bytes"}',
        'descriptor_fields = {"path", "file", "sha256", "bytes"}',
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        _assert_source_contract(changed, required)


def test_phase6_external_measured_rows_are_one_per_runner_invocation() -> None:
    templates = (
        Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    )
    core = (templates / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    core_required = (
        'invocation_token="$(date -u +%s%N)-$$"',
        'job_id="external-p6c-${ATTEMPT_TAG}-${invocation}-${invocation_token}-${lane}"',
        'external_measured_run "$LANE" runner-resume',
        'external_measured_run "$LANE" measured-run',
        "experiments.rig_web_app.external_measured start",
        "experiments.rig_web_app.external_measured terminal",
        'session="ura-p6c-job-${ATTEMPT_TAG}-${invocation_token}"',
        'tmux -L "$socket" new-session -d -s "$session"',
        "external_measured_terminal() {",
        "timeout --signal=TERM --kill-after=30s 30s",
        '--argv "$@"',
    )
    extended_required = (
        'invocation_token = f"{time.time_ns()}-{os.getpid()}"',
        'f"external-p6e-{self.attempt_tag}-{stage}-"',
        'lane, "runner-resume", runner_argv,',
        'lane, "measured-run", runner_argv,',
        '"experiments.rig_web_app.external_measured", "start"',
        '"experiments.rig_web_app.external_measured", "terminal"',
        'session = f"ura-p6e-job-{self.attempt_tag}-{invocation_token}"',
        '"tmux", "-L", socket, "new-session", "-d", "-s", session,',
        "def external_session_running(",
        "timeout=min(5.0, self.remaining_lane_time(lane))",
        '"--argv", *argv,',
    )
    _assert_source_contract(core, core_required)
    _assert_source_contract(extended, extended_required)
    for source, required, original in (
        (core, core_required, 'invocation_token="$(date -u +%s%N)-$$"'),
        (
            extended,
            extended_required,
            'invocation_token = f"{time.time_ns()}-{os.getpid()}"',
        ),
    ):
        changed = source.replace(original, 'invocation_token = "fixed"', 1)
        assert changed != source
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)


def test_phase6_external_measured_lifecycle_is_exact_and_signal_safe() -> None:
    templates = (
        Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    )
    core = (templates / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )

    core_function = core.split("external_measured_run() {", 1)[1].split(
        "\n}\n\nwait_lane_with_ceiling()", 1
    )[0]
    core_start = core_function.index(
        "experiments.rig_web_app.external_measured start"
    )
    assert core_function.index('active_external_job_id="$job_id"') < core_start
    assert core_function.index('active_external_tmux_socket="$socket"') < core_start
    assert core_function.index('active_external_tmux_session="$session"') < core_start
    assert core_start < core_function.index(
        'tmux -L "$socket" new-session -d -s "$session"'
    )
    assert core_function.index("external_measured_terminal") < core_function.index(
        'active_external_job_id=\'\''
    )
    assert core_function.index('if (( runner_rc != 0 )); then') < core_function.index(
        'if (( terminal_rc != 0 )); then'
    )

    extended_function = extended.split("    def run_measured(", 1)[1].split(
        "\n    def record_failure(", 1
    )[0]
    extended_try = extended_function.index("        try:\n")
    extended_start = extended_function.index(
        '"experiments.rig_web_app.external_measured", "start"'
    )
    extended_launch = extended_function.index(
        '"tmux", "-L", socket, "new-session", "-d", "-s", session,'
    )
    assert extended_try < extended_start < extended_launch
    assert extended_function.index("runner_error: BaseException | None = None") < (
        extended_try
    )
    assert extended_function.index("self.terminal_external_measured(") > extended_launch
    assert extended_function.index("if runner_error is not None:") < (
        extended_function.index("if terminal_error is not None:", extended_launch)
    )

    mutations = (
        (
            core,
            (
                'active_external_job_id="$job_id"',
                'session="ura-p6c-job-${ATTEMPT_TAG}-${invocation_token}"',
                "timeout --signal=TERM --kill-after=30s 30s",
            ),
            'session="ura-p6c-job-${ATTEMPT_TAG}-${invocation_token}"',
            'session="ura-phase6-core-${ATTEMPT_TAG}"',
        ),
        (
            extended,
            (
                'session = f"ura-p6e-job-{self.attempt_tag}-{invocation_token}"',
                "runner_error: BaseException | None = None\n        runner_exit_code = 1\n        try:",
                "timeout=min(5.0, self.remaining_lane_time(lane))",
            ),
            'session = f"ura-p6e-job-{self.attempt_tag}-{invocation_token}"',
            'session = f"ura-phase6-extended-{self.attempt_tag}"',
        ),
    )
    for source, required, original, replacement in mutations:
        _assert_source_contract(source, required)
        changed = source.replace(original, replacement, 1)
        assert changed != source
        with pytest.raises(AssertionError):
            _assert_source_contract(changed, required)


def test_phase6_gate5_wait_uses_the_declared_controller_hard_stop() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        "CONTROL_HARD_STOP_HOURS=720",
        '--hard-stop-hours "$CONTROL_HARD_STOP_HOURS"',
        "CONTROL_HARD_STOP_DEADLINE=$((SECONDS + CONTROL_HARD_STOP_HOURS * 3600))",
        "if (( SECONDS >= CONTROL_HARD_STOP_DEADLINE )); then",
        "exit 124",
    )
    _assert_source_contract(source, required)
    changed = source.replace(
        "CONTROL_HARD_STOP_HOURS * 3600",
        "90 * 24 * 3600",
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        _assert_source_contract(changed, required)


@pytest.mark.parametrize(
    ("controller", "hard_stop_hours", "waits"),
    (
        (
            "phase5_sequence_after_core.sh",
            24,
            (
                (
                    'while tmux -L "$socket" has-session -t "$session" '
                    "2>/dev/null; do",
                    'controller_hard_stop_check "$step" "$socket" "$session"',
                    True,
                ),
            ),
        ),
        (
            "gate5_after_phase5_sequence.sh",
            24,
            (
                (
                    'while tmux -L "$PHASE5_SEQUENCE_SOCKET" has-session -t '
                    '"$PHASE5_SEQUENCE_SESSION" 2>/dev/null; do',
                    "controller_hard_stop_check await-phase5",
                    False,
                ),
                (
                    'while tmux -L "$FINALIZER_SOCKET" has-session -t '
                    '"$FINALIZER_SESSION" 2>/dev/null; do',
                    'controller_hard_stop_check finalize-gate5 '
                    '"$FINALIZER_SOCKET" "$FINALIZER_SESSION"',
                    True,
                ),
            ),
        ),
        (
            "phase7_after_phase6_sequence.sh",
            720,
            (
                (
                    "phase6_terminal_seen='no'\nwhile true; do",
                    "controller_hard_stop_check await-phase6",
                    False,
                ),
                (
                    'while tmux -L "$PHASE7_SOCKET" has-session -t '
                    '"$PHASE7_SESSION" 2>/dev/null; do',
                    'controller_hard_stop_check run-analysis '
                    '"$PHASE7_SOCKET" "$PHASE7_SESSION"',
                    True,
                ),
            ),
        ),
    ),
)
def test_controller_waits_enforce_their_declared_global_hard_stop(
    tmp_path: Path,
    controller: str,
    hard_stop_hours: int,
    waits: tuple[tuple[str, str, bool], ...],
) -> None:
    import re

    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    source = (output / controller).read_text(encoding="utf-8")

    required = (
        f"CONTROL_HARD_STOP_HOURS={hard_stop_hours}",
        f'test "$CONTROL_HARD_STOP_HOURS" = \'{hard_stop_hours}\'',
        "CONTROL_HARD_STOP_DEADLINE=$((SECONDS + "
        "CONTROL_HARD_STOP_HOURS * 3600))",
        '--hard-stop-hours "$CONTROL_HARD_STOP_HOURS"',
        "controller_hard_stop_check() {",
        'local wait_label="$1" owned_socket="${2:-}" owned_session="${3:-}"',
        "if (( SECONDS >= CONTROL_HARD_STOP_DEADLINE )); then",
        'CONTROL_FAILURE_DETAIL="controller_hard_stop_exceeded_wait_'
        '${wait_label}_hours_${CONTROL_HARD_STOP_HOURS}"',
        "CONTROLLER_HARD_STOP_EXCEEDED=1 WAIT=%s HOURS=%s",
        'failure_detail="$CONTROL_FAILURE_DETAIL"',
        'console_event task_end "$task" failed "$failure_detail"',
        'console_event campaign_end bootstrap "$status" '
        '"local_campaign_${failure_detail}"',
        'tmux -L "$owned_socket" kill-session -t "$owned_session"',
        "exit 124",
    )

    def assert_contract(value: str) -> None:
        _assert_source_contract(value, required)
        deadline = value.index("CONTROL_HARD_STOP_DEADLINE=$((SECONDS + ")
        registration = value.index(
            "-m experiments.local_campaign.console_events start"
        )
        assert deadline < registration
        owned_probe = (
            'if tmux -L "$owned_socket" has-session -t '
            '"$owned_session" 2>/dev/null; then'
        )
        assert value.count(owned_probe) == 2
        assert value.count(
            'tmux -L "$owned_socket" kill-session -t "$owned_session"'
        ) == 1
        assert value.count("exit 124") == 3
        for loop_start, check, owns_session in waits:
            start = value.index(loop_start)
            terminal = re.search(r"\n[ \t]*done", value[start:])
            assert terminal is not None
            end = start + terminal.end()
            loop = value[start:end]
            _assert_source_contract(loop, (check, "sleep 30"))
            assert len(
                re.findall(rf"(?m)^[ \t]*{re.escape(check)}$", value)
            ) == 3
            if not owns_session:
                assert not re.search(
                    rf"(?m)^[ \t]*{re.escape(check)}[ \t]+\S+", value
                )

    assert_contract(source)

    for original, replacement in (
        ("CONTROL_HARD_STOP_HOURS * 3600", "365 * 24 * 3600"),
        ("exit 124", "exit 1"),
        (
            '--hard-stop-hours "$CONTROL_HARD_STOP_HOURS"',
            f"--hard-stop-hours {hard_stop_hours}",
        ),
        (
            'tmux -L "$owned_socket" kill-session -t "$owned_session"',
            ":",
        ),
        (
            'console_event task_end "$task" failed "$failure_detail"',
            'console_event task_end "$task" failed "controller_exit_$rc"',
        ),
        (
            'console_event campaign_end bootstrap "$status" '
            '"local_campaign_${failure_detail}"',
            'console_event campaign_end bootstrap "$status" '
            '"local_campaign_controller_exit_$rc"',
        ),
    ):
        changed = source.replace(original, replacement, 1)
        assert changed != source
        with pytest.raises(AssertionError):
            assert_contract(changed)

    for loop_start, check, _owns_session in waits:
        start = source.index(loop_start)
        terminal = re.search(r"\n[ \t]*done", source[start:])
        assert terminal is not None
        end = start + terminal.end()
        loop = source[start:end]
        changed_loop = loop.replace(check, ":", 1)
        assert changed_loop != loop
        changed = source[:start] + changed_loop + source[end:]
        assert changed != source
        with pytest.raises(AssertionError):
            assert_contract(changed)


def test_phase7_watcher_waits_through_phase6_pre_session_validation() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_after_phase6_sequence.sh.in"
    ).read_text(encoding="utf-8")
    required = (
        "phase6_terminal_seen='no'",
        "while true; do",
        'if tmux -L "$PHASE6_SOCKET" has-session -t "$PHASE6_SESSION" 2>/dev/null; then',
        'if [[ -f "$PHASE6_ROOT/.exit" && ! -L "$PHASE6_ROOT/.exit" ]]; then',
        "phase6_terminal_seen='yes'",
        'test "$phase6_terminal_seen" = \'yes\'',
    )

    def assert_wait_contract(candidate: str) -> None:
        _assert_source_contract(candidate, required)

    assert_wait_contract(source)
    reverted = source.replace(
        "phase6_terminal_seen='no'\nwhile true; do",
        'while tmux -L "$PHASE6_SOCKET" has-session -t '
        '"$PHASE6_SESSION" 2>/dev/null; do',
        1,
    )
    with pytest.raises(AssertionError):
        assert_wait_contract(reverted)


def _controller_test_bash() -> str:
    if sys.platform == "win32":
        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        if git_bash.is_file():
            return str(git_bash)
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    return bash


def _controller_test_posix_path(path: Path) -> str:
    resolved = path.resolve()
    if sys.platform != "win32":
        return str(resolved)
    drive = resolved.drive.rstrip(":").lower()
    tail = resolved.as_posix().split(":", 1)[1].lstrip("/")
    return f"/{drive}/{tail}"


def _shell_function(source: str, name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index("\n}\n", start) + 3
    return source[start:end]


@pytest.mark.parametrize(
    ("controller", "hard_stop_hours", "wait_label", "owns_session"),
    (
        ("phase5_sequence_after_core.sh", 24, "core-projections", True),
        ("gate5_after_phase5_sequence.sh", 24, "await-phase5", False),
        ("gate5_after_phase5_sequence.sh", 24, "finalize-gate5", True),
        ("phase7_after_phase6_sequence.sh", 720, "await-phase6", False),
        ("phase7_after_phase6_sequence.sh", 720, "run-analysis", True),
    ),
)
def test_controller_hard_stop_terminates_only_owned_session_and_records_reason(
    tmp_path: Path,
    controller: str,
    hard_stop_hours: int,
    wait_label: str,
    owns_session: bool,
) -> None:
    bindings = _bindings(tmp_path / "bindings.json")
    output = tmp_path / "workspace"
    render_controller_set(bindings, output)
    source = (output / controller).read_text(encoding="utf-8")
    finish = _shell_function(source, "controller_finish")
    hard_stop = _shell_function(source, "controller_hard_stop_check")

    state = tmp_path / "tmux-state"
    calls = tmp_path / "tmux-calls"
    events = tmp_path / "events"
    harness = tmp_path / "hard-stop-harness.sh"
    state.write_bytes(
        b"upstream-socket|upstream-session\nowned-socket|owned-session\n"
    )
    calls.write_bytes(b"")
    events.write_bytes(b"")
    owned_arguments = " owned-socket owned-session" if owns_session else ""
    harness.write_bytes(
        f"""set -eu
tmux() {{
  local socket action session entry
  test "$1" = '-L'
  socket="$2"
  action="$3"
  test "$4" = '-t'
  session="$5"
  printf '%s|%s|%s\\n' "$action" "$socket" "$session" >> "$TMUX_CALLS"
  case "$action" in
    has-session)
      while IFS= read -r entry; do
        if [ "$entry" = "$socket|$session" ]; then
          return 0
        fi
      done < "$TMUX_STATE"
      return 1
      ;;
    kill-session)
      : > "$TMUX_STATE.next"
      while IFS= read -r entry; do
        if [ "$entry" != "$socket|$session" ]; then
          printf '%s\\n' "$entry" >> "$TMUX_STATE.next"
        fi
      done < "$TMUX_STATE"
      mv -- "$TMUX_STATE.next" "$TMUX_STATE"
      ;;
    *) return 2 ;;
  esac
}}
console_event() {{
  printf '%s|%s|%s|%s\\n' "$1" "$2" "$3" "$4" >> "$EVENTS"
}}
CONTROL_TASKS=({wait_label} next-task)
CONTROL_TASK_INDEX=0
CONTROL_ACTIVE_TASK={wait_label}
CONTROL_FAILURE_DETAIL=''
CONSOLE_CAMPAIGN_STARTED=1
CONTROL_HARD_STOP_HOURS={hard_stop_hours}
CONTROL_HARD_STOP_DEADLINE=0
{finish}{hard_stop}trap 'rc=$?; trap - EXIT; controller_finish "$rc"' EXIT
controller_hard_stop_check {wait_label}{owned_arguments}
""".encode("ascii")
    )

    result = subprocess.run(
        [
            _controller_test_bash(),
            "-c",
            'TMUX_STATE="$1"; TMUX_CALLS="$2"; EVENTS="$3"; '
            'export TMUX_STATE TMUX_CALLS EVENTS; source "$4"',
            "--",
            _controller_test_posix_path(state),
            _controller_test_posix_path(calls),
            _controller_test_posix_path(events),
            _controller_test_posix_path(harness),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    reason = (
        f"controller_hard_stop_exceeded_wait_{wait_label}_hours_"
        f"{hard_stop_hours}"
    )
    assert result.returncode == 124, result.stderr
    assert (
        f"CONTROLLER_HARD_STOP_EXCEEDED=1 WAIT={wait_label} "
        f"HOURS={hard_stop_hours}"
    ) in result.stderr
    assert events.read_text(encoding="ascii").splitlines() == [
        f"task_end|{wait_label}|failed|{reason}",
        f"task_skip|next-task|skipped|not_reached_after_{reason}",
        f"campaign_end|bootstrap|failed|local_campaign_{reason}",
    ]
    remaining = state.read_text(encoding="ascii").splitlines()
    recorded_calls = calls.read_text(encoding="ascii").splitlines()
    assert "upstream-socket|upstream-session" in remaining
    if owns_session:
        assert "owned-socket|owned-session" not in remaining
        assert recorded_calls == [
            "has-session|owned-socket|owned-session",
            "kill-session|owned-socket|owned-session",
            "has-session|owned-socket|owned-session",
        ]
    else:
        assert "owned-socket|owned-session" in remaining
        assert recorded_calls == []


def test_controller_hard_stop_documentation_matches_owned_session_semantics() -> None:
    root = Path(__file__).parents[2]
    documents = (
        root / "experiments" / "LOCAL_CAMPAIGN_PLAN.md",
        root / "experiments" / "RUN_AND_RETURN.md",
        root / "experiments" / "local_campaign" / "README.md",
    )
    required = (
        "The Phase 5 and Gate 5 orchestration controllers enforce a 24-hour "
        "global\ncontroller deadline, and the Phase 7 watcher enforces 720 hours.",
        "controller records exit 124 and the exact wait/hours reason in task and "
        "campaign\nevents.",
        "It terminates and confirms absence of only an exact tmux session it\n"
        "launched and owns;",
        "awaiting upstream Phase 5\nor Phase 6 never terminates that upstream session.",
    )

    def assert_contract(value: str) -> None:
        _assert_source_contract(value, required)

    for path in documents:
        source = path.read_text(encoding="utf-8")
        assert_contract(source)
        for original, replacement in (
            ("records exit 124", "records a generic failure"),
            ("only an exact tmux session", "every tmux session"),
            ("never terminates that upstream session", "terminates the upstream session"),
        ):
            changed = source.replace(original, replacement, 1)
            assert changed != source
            with pytest.raises(AssertionError):
                assert_contract(changed)


def test_length_capped_output_documentation_matches_runner_policy() -> None:
    root = Path(__file__).parents[2]
    documents = (
        root / "README.md",
        root / "experiments" / "LOCAL_CAMPAIGN_PLAN.md",
        root / "experiments" / "RUN_AND_RETURN.md",
        root / "experiments" / "local_campaign" / "README.md",
    )

    def assert_contract(value: str) -> None:
        flattened = " ".join(value.split())
        assert "length-capped" in flattened
        assert "selected evaluator" in flattened
        assert "keeps rejecting every" not in flattened.lower()
        assert "length-capped prefixes are not responses" not in flattened
        assert "finish_reason='length' incomplete result" not in flattened

    for path in documents:
        source = path.read_text(encoding="utf-8")
        assert_contract(source)
        changed = source.replace("selected evaluator", "terminal classifier")
        assert changed != source
        with pytest.raises(AssertionError):
            assert_contract(changed)

    plan = " ".join(
        (root / "experiments" / "LOCAL_CAMPAIGN_PLAN.md")
        .read_text(encoding="utf-8")
        .split()
    )
    assert "Only the four affected GraySwan identities" in plan
    assert (
        "separate additive Ollama amendment replaces the superseded RWKV tasks"
        in plan
    )
    assert "local-llava-rr-text-primary-100" in plan
    assert "local-llava-rr-image-primary-100" in plan
    assert "match the corresponding LLaVA-base rows" in plan

    runbook = " ".join(
        (root / "experiments" / "RUN_AND_RETURN.md")
        .read_text(encoding="utf-8")
        .split()
    )
    assert "Do not invoke `paired_compare` for the current LLaVA base/RR plan" not in runbook
    assert (
        "only when the GraySwan RR Gate 5 amendment admits all four bounded RR identities"
        in runbook
    )


def test_local_campaign_plan_documents_bounded_controls_and_gate7() -> None:
    plan = (
        Path(__file__).parents[2] / "experiments" / "LOCAL_CAMPAIGN_PLAN.md"
    ).read_text(encoding="utf-8")
    required = (
        "outer population selector",
        "`--max-queries` and `--max-turns`",
        "The bounded HarmBench preparation is fixed to `DirectRequest`, "
        "experiment `llama2_7b`, one case per method, limit 50, sample seed 0",
        "`pair_limit` uses 0 for all verified manifest pairs and a positive value "
        "for `ordered_prefix_v1`",
        "NanoGCG accepts one attributable precomputed suffix and has no invented "
        "quantity selector",
        "The aggregate is `complete` or `complete_with_failures` according to that "
        "exact terminal partition",
        "a typed failure never becomes `measured_complete` and never prevents later "
        "independent lanes from being attempted",
        "Gate 7: the complete Phase 6 terminal inventory validates as `complete` or "
        "`complete_with_failures`",
        "at least one scheduled Runner lane is `measured_complete`",
        "Level-1 retains every representable Runner/request lifecycle",
        "If no measured Runner lane completes",
    )

    def assert_contract(value: str) -> None:
        flattened = " ".join(value.split())
        for item in required:
            assert item in flattened

    assert_contract(plan)
    for original, replacement in (
        ("complete_with_failures", "complete_without_failure_inventory"),
        ("at least one scheduled Runner lane", "zero scheduled Runner lanes"),
        ("ordered_prefix_v1", "random_pair_sample"),
    ):
        changed = plan.replace(original, replacement)
        assert changed != plan
        with pytest.raises(AssertionError):
            assert_contract(changed)


def test_phase7_retained_extended_root_collisions_are_registry_only() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    required = (
        "RETAINED_EXTENDED_LANE_PARENT_FAILURE_COMMIT",
        "RETAINED_EXTENDED_MARKERLESS_FAILURE_LANES",
        "unowned measured output root already exists:",
        "if retained_lane_parent_failures:",
        "if lane in retained_extended_collision_lanes:",
        "pre_runner_failure_artifacts.append(descriptor(failure_path))",
    )

    def assert_contract(value: str) -> None:
        _assert_source_contract(value, required)
        retained_branch = value.split(
            "if retained_lane_parent_failures:", 1
        )[1].split("critical_paths = [", 1)[0]
        assert "continue" in retained_branch
        assert "rglob" not in retained_branch

    assert_contract(source)
    for original, replacement in (
        (
            "if retained_lane_parent_failures:",
            "if False and retained_lane_parent_failures:",
        ),
        (
            "pre_runner_failure_artifacts.append(descriptor(failure_path))",
            "pre_runner_failure_artifacts.clear()",
        ),
    ):
        changed = source.replace(original, replacement, 1)
        assert changed != source
        with pytest.raises(AssertionError):
            assert_contract(changed)


def test_phase6_native_accepts_the_exact_bounded_gate5_policy() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_native_diagnostics.sh.in"
    ).read_text(encoding="utf-8")

    def assert_contract(value: str) -> None:
        assert value.count("expected_population_tiers = {") == 2
        assert value.count(
            'policy.get("population_tiers") != expected_population_tiers'
        ) == 2
        assert value.count(
            'policy.get("measured_lane_wall_time_seconds") != 86_400'
        ) == 2
        assert value.count(
            '"controller_completion_ceiling_distinct_from_call_start_admission_window"'
        ) == 2
        assert value.count('"seeded_nested_source_cluster_prefix_v1"') == 4

    assert_contract(source)
    changed = source.replace(
        'policy.get("measured_lane_wall_time_seconds") != 86_400',
        'policy.get("measured_lane_wall_time_seconds") != 86_401',
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        assert_contract(changed)


def test_phase6_native_validates_rr_against_the_gate5_revision() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_native_diagnostics.sh.in"
    ).read_text(encoding="utf-8")

    def assert_contract(value: str) -> None:
        assert value.count(
            'bindings.get("classification_project_commit") != classification_commit'
        ) == 2
        assert value.count("classification_commit=gate5_expected_commit") == 2
        assert value.count("classification_commit=historical_commit") == 3
        assert "classification_project_commit\") != expected_commit" not in value
        assert "classification_project_commit\") != EXPECTED_COMMIT" not in value

    assert_contract(source)
    changed = source.replace(
        'bindings.get("classification_project_commit") != classification_commit',
        'bindings.get("classification_project_commit") != expected_commit',
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        assert_contract(changed)


def test_phase6_native_preserves_the_gate5_promotion_delta() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_native_diagnostics.sh.in"
    ).read_text(encoding="utf-8")

    def assert_contract(value: str) -> None:
        assert value.count(
            'manifest_row["disposition"] != "runnable"'
        ) == 2
        assert value.count("terminal manifest/RUNNOTE row differs") == 2
        assert value.count(
            "covered manifest and RUNNOTE conditional inventory differ"
        ) == 2
        assert "if note_rows != manifest_rows:" not in value

    assert_contract(source)
    changed = source.replace(
        'manifest_row["disposition"] != "runnable"',
        'manifest_row["disposition"] == "runnable"',
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        assert_contract(changed)


def test_phase6_native_launch_uses_the_canonical_project_receipt_path() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_native_diagnostics.sh.in"
    ).read_text(encoding="utf-8")

    canonical_check = (
        'project_revision.get("path")\n'
        '    != str(project_revision_path.resolve(strict=True))'
    )

    def assert_contract(value: str) -> None:
        assert value.count(canonical_check) == 2
        assert (
            'project_revision.get("path") != str(project_revision_path)'
            not in value
        )

    assert_contract(source)
    changed = source.replace(
        canonical_check,
        'project_revision.get("path") != str(project_revision_path)',
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        assert_contract(changed)


def test_phase6_native_launch_metadata_canonicalizes_the_project_receipt() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase6_native_diagnostics.sh.in"
    ).read_text(encoding="utf-8")

    canonical_assignment = (
        "project_revision = "
        "desc(Path(project_revision_value).resolve(strict=True))"
    )

    def assert_contract(value: str) -> None:
        assert value.count(canonical_assignment) == 1
        assert "project_revision = desc(project_revision_value)" not in value

    assert_contract(source)
    changed = source.replace(
        canonical_assignment,
        "project_revision = desc(project_revision_value)",
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        assert_contract(changed)


def test_local_call_controllers_gate_targets_on_readiness_receipts() -> None:
    templates = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
    )
    core = (templates / "phase6_core_measured.sh.in").read_text(encoding="utf-8")
    extended = (templates / "phase6_extended_measured.sh.in").read_text(
        encoding="utf-8"
    )
    core_canary = (templates / "phase5_core_attest_canary.sh.in").read_text(
        encoding="utf-8"
    )
    bridge_canary = (templates / "phase5_bridge_attest_canary.sh.in").read_text(
        encoding="utf-8"
    )
    core_recovery = (templates / "phase6_core_length_recovery.py.in").read_text(
        encoding="utf-8"
    )
    rr_amendment = (templates / "phase6_seven_output_policy.py.in").read_text(
        encoding="utf-8"
    )

    def assert_contract(value: str) -> None:
        assert '${URA_LOCAL_MODEL_READINESS_ROOT:?set ' in value
        assert value.count('-m experiments.local_model_readiness \\\n') == 1
        assert value.count('--validate "$readiness"') == 1
        assert value.count("--expected-spec") == 1

    assert_contract(core)
    assert "qwen3-vl-8b\tvllm:Qwen/Qwen3-VL-8B-Instruct" in core
    assert "llava-base\tvllm:llava-hf/llava-v1.6-mistral-7b-hf" in core
    assert "llava-rr\tvllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR" in core

    assert_contract(extended)
    assert "qwen3-vl-8b vllm:Qwen/Qwen3-VL-8B-Instruct" in extended
    assert (
        "from experiments.local_campaign.current_ollama import "
        "CURRENT_OLLAMA_MODELS"
    ) in extended

    assert_contract(core_canary)
    assert "qwen3-vl-8b\tvllm:Qwen/Qwen3-VL-8B-Instruct" in core_canary
    assert "llava-base\tvllm:llava-hf/llava-v1.6-mistral-7b-hf" in core_canary
    assert "llava-rr\tvllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR" in core_canary

    assert_contract(bridge_canary)
    assert (
        "--expected-spec 'vllm:Qwen/Qwen3-VL-8B-Instruct'"
        in bridge_canary
    )

    for source in (core, extended, core_canary, bridge_canary):
        changed = source.replace('--validate "$readiness"', '--inspect "$readiness"', 1)
        assert changed != source
        with pytest.raises(AssertionError):
            assert_contract(changed)

    def assert_recovery_contract(value: str) -> None:
        assert 'os.environ.get("URA_LOCAL_MODEL_READINESS_ROOT")' in value
        assert '"experiments.local_model_readiness"' in value
        assert '("qwen3-vl-8b", "vllm:Qwen/Qwen3-VL-8B-Instruct")' in value
        assert (
            '("llava-base", "vllm:llava-hf/llava-v1.6-mistral-7b-hf")'
            in value
        )
        assert (
            "validate_specs_contract(module, all_specs)\n"
            "    validate_local_readiness()"
        ) in value

    assert_recovery_contract(core_recovery)
    changed_recovery = core_recovery.replace(
        "    validate_local_readiness()\n",
        "",
        1,
    )
    assert changed_recovery != core_recovery
    with pytest.raises(AssertionError):
        assert_recovery_contract(changed_recovery)

    def assert_rr_amendment_contract(value: str) -> None:
        assert 'os.environ.get("URA_LOCAL_MODEL_READINESS_ROOT")' in value
        assert '"experiments.local_model_readiness"' in value
        assert 'label = "llava-rr"' in value
        assert '"--expected-spec",\n            RR_SPEC,' in value
        assert (
            "validate_specs_contract(module, specs)\n"
            "    validate_local_readiness()"
        ) in value

    assert_rr_amendment_contract(rr_amendment)
    changed_rr = rr_amendment.replace("    validate_local_readiness()\n", "", 1)
    assert changed_rr != rr_amendment
    with pytest.raises(AssertionError):
        assert_rr_amendment_contract(changed_rr)


def test_vllm_stability_phase6_schedules_only_missing_runner_225_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    historical = {
        "schema": "ura-phase6-failed-lane-recovery-completion/1",
        "status": "complete_with_failures",
        "expected_commit": recovery.HISTORICAL_COMMIT,
        "lane_terminal_states": dict(recovery.EXPECTED_STATES),
        "lane_results": {lane: {} for lane in recovery.COMPLETED_LANES},
        "lane_failures": {
            lane: {}
            for lane in recovery.PRE_RUNNER_LANES | {recovery.PARTIAL_LANE}
        },
        "unrelated_passed_work_repeated": False,
        "paid_provider_calls": 0,
    }
    recovery.validate_historical_completion(historical)

    def spec(lane: str, corpora: list[str], counts: list[int]) -> dict[str, object]:
        return {
            "lane_id": lane,
            "expected_corpora": corpora,
            "approved_caps": {"target_calls": sum(counts)},
            "_arms": {
                corpus: {
                    "logical_source_arm": corpus,
                    "selected_records": count,
                }
                for corpus, count in zip(corpora, counts)
            },
            "base_argv": [
                "--project-revision",
                "/old/receipt.json",
                "--project-revision-sha256",
                "a" * 64,
                "--corpora",
                ",".join(corpora),
            ],
        }

    specs = {
        "local-qwen3-vl-image-primary-100": spec(
            "local-qwen3-vl-image-primary-100", ["qwen_image"], [12]
        ),
        "gptgeochat-qwen3-vl": spec(
            "gptgeochat-qwen3-vl", ["gptgeochat_release"], [20]
        ),
        "local-llava-base-image-primary-100": spec(
            "local-llava-base-image-primary-100", ["llava_image"], [11]
        ),
        recovery.PARTIAL_LANE: spec(
            recovery.PARTIAL_LANE,
            list(recovery.TEXT_SUFFIX_CORPORA),
            [1854, 450, 100, 450],
        ),
    }
    monkeypatch.setattr(recovery, "_projection_arms", lambda row: row["_arms"])
    monkeypatch.setattr(
        recovery,
        "_airbench_recovery",
        lambda completion, row: (
            {
                "schema": recovery.PREFIX_SCHEMA,
                "corpus": "airbench_full",
                "completed_prefix_count": 1039,
                "selected_datapoint_ids_sha256": "b" * 64,
                "completed_prefix_ids_sha256": "c" * 64,
                "remaining_datapoint_ids_sha256": "d" * 64,
            },
            Path("/retained/old-text-root"),
        ),
    )

    units, _old_root = recovery.build_units(historical, specs)

    assert [unit.unit_id for unit in units] == [
        "vllm-stability-qwen3-vl-image-primary-100",
        "vllm-stability-gptgeochat-qwen3-vl",
        "vllm-stability-llava-base-image-primary-100",
        "vllm-stability-llava-base-airbench-suffix",
        "vllm-stability-llava-base-xstest-full",
        "vllm-stability-llava-base-simplesafetytests-full",
        "vllm-stability-llava-base-decodingtrust-stereotype",
    ]
    assert not ({unit.source_lane for unit in units} & recovery.COMPLETED_LANES)
    assert units[3].selected_records == 815
    assert sum(unit.selected_records for unit in units[3:]) == 1815

    argv = recovery._base_argv(
        units[3],
        project_revision=Path("/new/receipt.json"),
        project_revision_sha256="e" * 64,
    )
    assert recovery._option(argv, "--target-answer-retries") == "1"
    assert recovery._option(argv, "--corpora") == "airbench_full"
    with_recovery = [
        *argv,
        "--recovery-completed-prefix",
        "/prefix.json",
        "--recovery-completed-prefix-sha256",
        "f" * 64,
    ]
    assert recovery._without_recovery_selection(with_recovery) == argv

    historical["lane_terminal_states"]["local-qwen3-vl-text-primary-100"] = (
        "failed"
    )
    with pytest.raises(ValueError, match="terminal partition changed"):
        recovery.validate_historical_completion(historical)


def test_vllm_stability_preflight_omits_measured_attestation_scope() -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    base = ["--corpora", "synth", "--limit", "100"]
    attestation = {"path": "/attestation.json", "sha256": "a" * 64}
    preflight = recovery._runtime_args(
        base,
        out=Path("/preflight"),
        scope="scope-fixture",
        attestation=attestation,
        target_cap=200,
        preflight=True,
    )
    measured = recovery._runtime_args(
        base,
        out=Path("/measured"),
        scope="scope-fixture",
        attestation=attestation,
        target_cap=200,
    )

    assert "--preflight-only" in preflight
    assert "--execution-scope-id" not in preflight
    assert not any(item.startswith("--live-attestation") for item in preflight)
    assert "--preflight-only" not in measured
    assert recovery._option(measured, "--execution-scope-id") == "scope-fixture"
    assert recovery._option(measured, "--live-attestation") == "/attestation.json"
    assert recovery._option(measured, "--live-attestation-sha256") == "a" * 64
    assert recovery._option(measured, "--live-attestation-max-age-hours") == "24"


def test_vllm_stability_phase6_reads_retained_projection_descriptor(
    tmp_path: Path,
) -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    projection = tmp_path / "lane-projection-retained.lane-projection.json"
    payload = json.dumps({
        "selection": {
            "arms": [{
                "logical_source_arm": "airbench_full",
                "selected_records": 1854,
            }],
        },
    }).encode("utf-8")
    projection.write_bytes(payload)
    descriptor = {
        "path": str(projection),
        "file": projection.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }

    assert recovery._projection_arms({
        "lane_id": "local-llava-base-text-primary-100",
        "gate5": {"final_projection": descriptor},
    })["airbench_full"]["selected_records"] == 1854

    with pytest.raises(ValueError, match="filename does not match"):
        recovery._projection_arms({
            "lane_id": "local-llava-base-text-primary-100",
            "gate5": {
                "final_projection": {**descriptor, "file": "different.json"},
            },
        })


def test_vllm_child_jobs_bind_the_formal_gate5_manifest_digest() -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    digest = "a" * 64
    spec = {"lane_id": "lane-fixture", "gate5": {"manifest_sha256": digest}}
    assert recovery._gate5_manifest_sha256(spec) == digest

    with pytest.raises(ValueError, match="Gate 5 manifest digest changed"):
        recovery._gate5_manifest_sha256({"lane_id": "lane-fixture", "gate5": {}})

    stability_source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "vllm_stability_phase6.py"
    ).read_text(encoding="utf-8")
    input_recovery_source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "vllm_input_recovery_phase6.py"
    ).read_text(encoding="utf-8")
    assert stability_source.count(
        "admission_sha256=_gate5_manifest_sha256(unit.spec),"
    ) == 1
    assert input_recovery_source.count(
        "admission_sha256=_gate5_manifest_sha256(unit.spec),"
    ) == 1
    assert "admission_sha256=args.historical_completion_sha256" not in stability_source
    assert "admission_sha256=args.failed_completion_sha256" not in input_recovery_source


def test_vllm_stability_phase6_registers_its_tmux_job_lifecycle() -> None:
    source = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "vllm_stability_phase6.py"
    ).read_text(encoding="utf-8")

    assert source.count("start_child_controller(") == 1
    assert source.count("publish_target_execution(") == 1
    assert source.count("finish_child_controller(") == 1
    assert 'evidence_class="measured_local_vllm_stability"' in source
    assert "tmux_socket=args.tmux_socket" in source
    assert "tmux_session=args.tmux_session" in source
    assert 'parser.add_argument("--tmux-session", required=True)' in source


def test_external_measured_docs_match_owning_session_semantics() -> None:
    root = Path(__file__).parents[2]
    documents = (
        root / "README.md",
        root / "experiments" / "RUN_AND_RETURN.md",
        root / "experiments" / "LOCAL_CAMPAIGN_PLAN.md",
    )

    def assert_contract(value: str) -> None:
        flattened = " ".join(value.split())
        assert "exact owning tmux socket/session" in flattened
        assert "synchronously owns the child" in flattened
        assert "separately launched child names its child-specific session" in flattened
        assert "rather than the parent controller" not in flattened
        assert "not the longer-lived parent controller" not in flattened

    for path in documents:
        source = path.read_text(encoding="utf-8")
        assert_contract(source)
        changed = source.replace("exact owning tmux", "unique private tmux", 1)
        assert changed != source
        with pytest.raises(AssertionError):
            assert_contract(changed)


def test_vllm_stability_run_unit_registers_measured_child_before_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery
    from experiments.rig_web_app.external_measured import (
        load_external_measured_job,
    )

    work_root = tmp_path / "work"
    control_root = work_root / "runs" / "engineering" / "phase6-child-jobs"
    (control_root / "units").mkdir(parents=True)
    (work_root / "runs" / "thesis" / "runner").mkdir(parents=True)
    unit = recovery.Unit(
        unit_id="vllm-child-fixture",
        source_lane="source-fixture",
        corpus="corpus-fixture",
        spec={},
        selected_records=1,
    )

    monkeypatch.setattr(recovery, "_base_argv", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        recovery,
        "_derive_attestation",
        lambda *args, **kwargs: {"path": "/attestation", "sha256": "a" * 64},
    )
    monkeypatch.setattr(
        recovery,
        "_runtime_args",
        lambda base, *, out, **kwargs: ["--out", str(out)],
    )
    monkeypatch.setattr(recovery, "_acquisition_args", lambda *args, **kwargs: [])

    def fake_run(
        argv: Sequence[str],
        *,
        log: Path,
        timeout: int,
        allow_failure: bool = False,
    ) -> int:
        del argv, timeout
        log.write_text("ok\n", encoding="utf-8")
        if log.name == "canary.run.log":
            canary_root = log.parent / "canary"
            canary_root.mkdir()
            (canary_root / "eligibility-fixture.eligibility.json").write_text(
                "{}\n", encoding="utf-8"
            )
        if log.name == "preflight.run.log":
            preflight_root = log.parent / "preflight"
            preflight_root.mkdir()
            (preflight_root / "lane-projection-fixture.lane-projection.json").write_text(
                "{}\n", encoding="utf-8"
            )
        if log.name == "measured.run.log":
            running = load_external_measured_job(
                work_root / "runs",
                recovery._external_job_id(control_root, unit.unit_id),
                probe_session=False,
            )
            assert running is not None
            assert running.state == "running"
            assert running.exit_code is None
        return 0 if allow_failure else 0

    monkeypatch.setattr(recovery, "_run", fake_run)

    def fake_level1_counts(*, lane_root: Path, **kwargs: object) -> tuple[int, int, int]:
        del kwargs
        (lane_root / "level1.json").write_text("{}\n", encoding="utf-8")
        return 1, 1, 0

    monkeypatch.setattr(recovery, "_level1_counts", fake_level1_counts)

    result = recovery._run_unit(
        unit,
        python=Path("/fixture/python"),
        work_root=work_root,
        control_root=control_root,
        project_revision=Path("/fixture/revision.json"),
        project_revision_sha256="b" * 64,
        scope="scope-fixture",
        recovery_path=None,
        recovery_sha256=None,
        expected_commit="c" * 40,
        framework_lock_id="d" * 64,
        admission_sha256="e" * 64,
        tmux_socket="ura-fixture",
        tmux_session="ura-fixture",
    )

    job = load_external_measured_job(
        work_root / "runs",
        recovery._external_job_id(control_root, unit.unit_id),
        probe_session=False,
    )
    assert result["status"] == "complete"
    assert job is not None
    assert job.state == "complete"
    assert job.exit_code == 0
    assert job.out_dir == (
        work_root
        / "runs"
        / "thesis"
        / "runner"
        / unit.unit_id
        / control_root.name
    )


def test_vllm_stability_attestation_probe_uses_local_guardrail() -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    unit = recovery.Unit(
        unit_id="probe-fixture",
        source_lane="local-llava-base-image-primary-100",
        corpus=None,
        spec={"modality": "image"},
        selected_records=1,
    )
    base = [
        "--project-revision", "/revision.json",
        "--project-revision-sha256", "a" * 64,
        "--local", "vllm:llava-hf/llava-v1.6-mistral-7b-hf",
        "--local-config", "/local.json",
        "--local-config-sha256", "b" * 64,
        "--source-config", "/source.json",
        "--source-config-sha256", "c" * 64,
        "--source-conformance", "/conformance.json",
        "--source-conformance-sha256", "d" * 64,
        "--group", "model,source",
    ]

    argv = recovery._probe_args(
        unit,
        base=base,
        out=Path("/probe"),
        scope="scope-fixture",
    )

    assert recovery._option(argv, "--judges") == "rules,guardrail"
    assert recovery._option(argv, "--guardrail-model") == (
        "meta-llama/Llama-Guard-3-8B"
    )
    assert recovery._option(argv, "--guardrail-device") == "cuda:1"


def test_vllm_stability_phase6_accepts_standard_venv_python_symlink(
    tmp_path: Path,
) -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    project = tmp_path / "project"
    binary = project / ".venv" / "bin" / "python3"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    python = binary.parent / "python"
    python.symlink_to(binary.name)

    assert recovery._project_python(project, python) == python

    with pytest.raises(ValueError, match="project virtual environment"):
        recovery._project_python(project, binary)


def test_vllm_stability_completion_is_one_separate_runner_225_stratum(
    tmp_path: Path,
) -> None:
    from experiments.local_campaign import vllm_stability_phase6 as recovery

    runner_root = tmp_path / "runs" / "thesis" / "runner"
    control_root = (
        tmp_path / "runs" / "engineering" / "phase6-vllm-stability-fixture"
    )
    runner_root.mkdir(parents=True)
    (control_root / "units").mkdir(parents=True)
    historical = tmp_path / "historical-completion.json"
    historical.write_text("{}\n", encoding="utf-8")
    revision_sha = "e" * 64
    source_sha = "f" * 64
    results: dict[str, object] = {}
    selected_total = 0
    for unit_id, source_lane, corpus, selected_records in recovery.UNIT_LAYOUT:
        selected_total += selected_records
        unit_root = control_root / "units" / unit_id
        result_root = runner_root / unit_id / control_root.name
        unit_root.mkdir()
        result_root.mkdir(parents=True)
        (result_root / f"{unit_id}.grid.json").write_text("{}\n", encoding="utf-8")
        (result_root / f"{unit_id}.request-envelope.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (result_root / f"eligibility-{unit_id}.eligibility.json").write_text(
            "{}\n", encoding="utf-8"
        )
        (result_root / f"{unit_id}.complete.json").write_text(
            "{}\n", encoding="utf-8"
        )
        state = {
            "schema": "ura-vllm-stability-phase6-unit-state/1",
            "unit_id": unit_id,
            "source_lane": source_lane,
            "corpus": corpus,
            "selected_records": selected_records,
            "target_answer_retries": 1,
            "target_call_cap": selected_records * 2,
            "attestation": {},
            "projection": {},
            "result_root": str(result_root),
            "runner_argv": [
                "--project-revision-sha256",
                revision_sha,
                "--source-conformance-sha256",
                source_sha,
                "--target-answer-retries",
                "1",
            ],
        }
        state_path = unit_root / "state.json"
        state_path.write_text(json.dumps(state) + "\n", encoding="utf-8")
        level1_path = unit_root / "level1.json"
        level1_path.write_text("{}\n", encoding="utf-8")
        results[unit_id] = {
            "status": "complete",
            "unit_id": unit_id,
            "source_lane": source_lane,
            "corpus": corpus,
            "selected_records": selected_records,
            "target_answer_retries": 1,
            "target_call_cap": selected_records * 2,
            "target_attempts": selected_records,
            "successful_target_generations": selected_records,
            "missing_responses": 0,
            "result_root": str(result_root),
            "state": recovery._descriptor(state_path, label=f"{unit_id} state"),
            "level1": recovery._descriptor(
                level1_path, label=f"{unit_id} Level 1 evidence"
            ),
        }
    completion = {
        "schema": recovery.SCHEMA,
        "status": "complete",
        "controller_exit_code": 0,
        "completed_at_utc": "2026-08-31T00:00:00Z",
        "expected_commit": "a" * 40,
        "runner_code_version": "ura-runner/2.25",
        "target_answer_retries": 1,
        "historical_completion": recovery._descriptor(
            historical, label="historical completion"
        ),
        "historical_completed_lanes_excluded": sorted(recovery.COMPLETED_LANES),
        "unit_order": [row[0] for row in recovery.UNIT_LAYOUT],
        "unit_results": results,
        "unit_failures": {},
        "target_execution": {
            "target_attempts": selected_total,
            "successful_target_generations": selected_total,
            "missing_responses": 0,
        },
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_output_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    completion_path = control_root / "completion.json"
    completion_path.write_text(json.dumps(completion) + "\n", encoding="utf-8")

    view = recovery.validate_completion(completion_path, runner_root=runner_root)

    assert view["runner_code_version"] == "ura-runner/2.25"
    assert view["output_policy_stratum"] == (
        "provider_neutral_retry_1_retain_failed_output"
    )
    assert view["metric_lane_order"] == [row[0] for row in recovery.UNIT_LAYOUT]
    assert len(view["metric_grids"]) == len(recovery.UNIT_LAYOUT)
    assert len(view["metric_eligibility_plans"]) == len(recovery.UNIT_LAYOUT)
    assert len(view["metric_completion_markers"]) == len(recovery.UNIT_LAYOUT)
    assert view["revision_strata"] == {
        revision_sha: [row[0] for row in recovery.UNIT_LAYOUT]
    }
    assert view["target_execution"]["target_attempts"] == 7199
    assert view["cross_output_policy_pooling_permitted"] is False

    completion["cross_output_policy_pooling_permitted"] = True
    completion_path.write_text(json.dumps(completion) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="completion contract changed"):
        recovery.validate_completion(completion_path, runner_root=runner_root)
