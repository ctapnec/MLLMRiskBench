from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType
from typing import Sequence

import pytest

from experiments.local_campaign.console_events import main as console_main
from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    CONTROLLERS,
    DERIVED_BINDINGS,
    render_controller_set,
)
from experiments.rig_web_app.campaigns import load_engineering_campaign
from experiments.rig_web import RigWebApp


TEMPLATE = (
    Path(__file__).parents[2]
    / "experiments"
    / "local_campaign"
    / "templates"
    / "phase8_human_audit.py.in"
)


def _template_tokens() -> set[str]:
    templates = TEMPLATE.parent
    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    return {
        match
        for controller in CONTROLLERS
        for match in token.findall(
            (templates / controller.template).read_text(encoding="utf-8")
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
def phase8_jobs(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    root = tmp_path_factory.mktemp("phase8-jobs")
    output = root / "rendered"
    render_controller_set(_bindings(root / "bindings.json"), output)
    path = output / "phase8_human_audit.py"
    spec = importlib.util.spec_from_file_location("phase8_jobs_test_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _source_contract(source: str) -> None:
    required = (
        'CONSOLE_EVIDENCE_CLASS = "local_campaign_control"',
        'LAUNCH_SCHEMA = "ura-phase8-human-audit-launch/2"',
        "CONSOLE_HARD_STOP_HOURS = 24",
        'CONSOLE_TASK = "machine-preparation"',
        "TMUX_COMMAND_TIMEOUT_SECONDS = 15",
        'return f"phase8-human-audit-{authorized_sha[:16]}-{attempt_name}"',
        'launch_path = attempt / "launch.json"',
        'JOBS_ARTIFACT_LINKS_SCHEMA = "ura-engineering-campaign-artifact-links/1"',
        'JOBS_ARTIFACT_LINKS_FILE = "artifact-links.json"',
        "jobs_artifact_links = _publish_jobs_artifact_links(",
        '"artifact_links": jobs_artifact_links',
        "_validate_jobs_artifact_links(",
        '("-L", socket, "new-session", "-d", "-s", session, command)',
        "def _record_registered_launch_failure(",
        '"thesis_empirical_evidence": False',
        '"hosted_calls_allowed": False',
        '"planned_tasks": [CONSOLE_TASK]',
        '"tmux_socket": socket',
        '"tmux_session": session',
        "console_event task_start {CONSOLE_TASK} running machine_preparation_started",
        "console_event task_end {CONSOLE_TASK} passed machine_preparation_complete",
        "console_event campaign_end bootstrap blocked human_only",
        "console_event task_end {CONSOLE_TASK} failed machine_preparation_failed",
        "console_event campaign_end bootstrap failed machine_preparation_failed",
        'detail="tmux_launch_failed"',
        '"JOBS_CONTROL_ROOT={registration_root}"',
    )
    for fragment in required:
        assert fragment in source

    launch = source.split("def seal_and_launch(", 1)[1].split(
        "\ndef execute_entry(", 1
    )[0]
    jobs_registration = launch.split('"jobs_registration": {', 1)[1].split(
        "\n        },", 1
    )[0]
    assert '"thesis_empirical_evidence": False' in jobs_registration
    assert '"hosted_calls_allowed": False' in jobs_registration
    assert '"tmux_socket_name": socket' in jobs_registration
    assert '"tmux_session_name": session' in jobs_registration
    attempt_allocation = launch.index("attempt = _new_attempt_root(attempts)")
    registration_root = launch.index("registration_root = _console_registration_root(")
    attempt_launch = launch.index('launch_path = attempt / "launch.json"')
    assert "_ensure_console_registration(" in launch
    registration = launch.index("_ensure_console_registration(")
    tmux_probe = launch.index("_require_registered_tmux_session_absent(")
    tmux_launch = launch.index("_launch_registered_tmux_session(")
    assert (
        attempt_allocation
        < registration_root
        < attempt_launch
        < registration
        < tmux_probe
        < tmux_launch
    )

    tmux = source.split("def _run_tmux(", 1)[1].split("\ndef make_runner(", 1)[0]
    assert "timeout=TMUX_COMMAND_TIMEOUT_SECONDS" in tmux
    assert "except subprocess.TimeoutExpired as exc:" in tmux
    assert "except OSError as exc:" in tmux
    probe = tmux.split("def _tmux_session_is_active(", 1)[1].split(
        "\ndef _start_tmux_session(", 1
    )[0]
    assert "if completed.returncode == 0:" in probe
    assert "if completed.returncode == 1:" in probe
    assert "failed with exit code" in probe
    launch_failure = tmux.split("def _launch_registered_tmux_session(", 1)[1]
    assert "_record_registered_launch_failure(" in launch_failure
    assert launch_failure.index("_record_registered_launch_failure(") < launch_failure.index(
        'raise Phase8Error("tmux could not launch'
    )

    runner = source.split("def make_runner(", 1)[1].split(
        "\ndef seal_and_launch(", 1
    )[0]
    task_start = runner.index("console_event task_start {CONSOLE_TASK}")
    payload = runner.index('env -i {env_tokens} TMUX="$TMUX" {command}')
    assert task_start < payload
    assert "trap finish EXIT" in runner
    assert "trap 'exit 129' HUP" in runner
    assert "trap 'exit 130' INT" in runner
    assert "trap 'exit 143' TERM" in runner
    finish = runner.split("finish() {{", 1)[1].split("\n}}\ntrap finish EXIT", 1)[0]
    task_pass = "console_event task_end {CONSOLE_TASK} passed"
    campaign_blocked = "console_event campaign_end bootstrap blocked human_only"
    task_fail = "console_event task_end {CONSOLE_TASK} failed"
    campaign_fail = "console_event campaign_end bootstrap failed"
    assert task_pass in finish
    assert campaign_blocked in finish
    assert task_fail in finish
    assert campaign_fail in finish
    assert finish.index(task_pass) < finish.index(campaign_blocked)
    assert finish.index(task_fail) < finish.rindex(campaign_fail)
    assert "task_pass_rc=$?" in finish
    assert "if (( task_pass_rc != 0 )); then" in finish
    task_pass_failure = finish.split("if (( task_pass_rc != 0 )); then", 1)[1].split(
        "\n    else", 1
    )[0]
    assert "console_terminal_publication_failed" in task_pass_failure
    assert campaign_blocked not in task_pass_failure
    task_pass_success = finish.split("\n    else", 1)[1]
    assert campaign_blocked in task_pass_success

    executor = source.split("def execute_preparation(", 1)[1].split(
        "\ndef _mkdir_or_check(", 1
    )[0]
    assert 'attempt_root / "launch.json"' in executor
    assert "_console_campaign_id(authorized_sha, attempt_root.name)" in executor
    assert '"jobs_registration",' in executor
    assert 'if launch.get("jobs_registration") != {' in executor
    assert '"artifact_links": jobs_artifact_links' in executor
    assert 'raise Phase8Error("Phase 8 launch Jobs binding differs")' in executor


def test_phase8_machine_preparation_is_a_terminal_jobs_campaign() -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    _source_contract(source)


@pytest.mark.parametrize(
    ("original", "replacement"),
    (
        (
            'return f"phase8-human-audit-{authorized_sha[:16]}-{attempt_name}"',
            'return f"phase8-human-audit-{authorized_sha[:16]}"',
        ),
        ("    _ensure_console_registration(\n", "    _registration_removed(\n"),
        (
            "console_event campaign_end bootstrap blocked human_only",
            "console_event campaign_end bootstrap passed human_only",
        ),
        (
            "console_event campaign_end bootstrap blocked human_only",
            "console_event campaign_end bootstrap blocked machine_only",
        ),
        (
            "if (( task_pass_rc != 0 )); then",
            "if (( task_pass_rc == 0 )); then",
        ),
        (
            'if launch.get("jobs_registration") != {',
            'if launch.get("jobs_registration") == {',
        ),
        (
            "def _record_registered_launch_failure(\n",
            "def _terminal_publication_removed(\n",
        ),
        (
            '"hosted_calls_allowed": False',
            '"hosted_calls_allowed": True',
        ),
        (
            '("-L", socket, "new-session", "-d", "-s", session, command)',
            '("new-session", "-d", "-s", session, command)',
        ),
        (
            "timeout=TMUX_COMMAND_TIMEOUT_SECONDS",
            "timeout=None",
        ),
        (
            "if completed.returncode == 1:",
            "if completed.returncode != 1:",
        ),
        (
            'launch_path = attempt / "launch.json"',
            'launch_path = control / "launch.json"',
        ),
        (
            "jobs_artifact_links = _publish_jobs_artifact_links(\n",
            "jobs_artifact_links = _unbound_artifact_links(\n",
        ),
    ),
)
def test_phase8_jobs_contract_rejects_lifecycle_mutations(
    original: str, replacement: str
) -> None:
    source = TEMPLATE.read_text(encoding="utf-8")
    if original == '"hosted_calls_allowed": False':
        jobs_registration = source.index('"jobs_registration": {')
        mutation_at = source.index(original, jobs_registration)
        changed = source[:mutation_at] + replacement + source[mutation_at + len(original) :]
    else:
        changed = source.replace(original, replacement, 1)
    assert changed != source
    with pytest.raises(AssertionError):
        _source_contract(changed)


def _use_real_console_cli(
    monkeypatch: pytest.MonkeyPatch, phase8_jobs: ModuleType
) -> None:
    def run(
        *, project: Path, arguments: Sequence[str], label: str
    ) -> None:
        del project, label
        assert console_main(list(arguments)) == 0

    monkeypatch.setattr(phase8_jobs, "_run_console_cli", run)


def _new_registered_attempt(
    phase8_jobs: ModuleType,
    *,
    work: Path,
    attempts: Path,
    authorized_sha: str,
) -> tuple[Path, Path]:
    attempt = phase8_jobs._new_attempt_root(attempts)
    registration = phase8_jobs._console_registration_root(
        work, authorized_sha, attempt.name
    )
    phase8_jobs._ensure_console_registration(
        project=Path.cwd(),
        work=work,
        registration_root=registration,
        socket="ura-phase8-test",
        session="ura-phase8-test",
    )
    return attempt, registration


def _phase8_artifact_layout(
    phase8_jobs: ModuleType,
    *,
    tmp_path: Path,
    authorized_sha: str,
) -> tuple[Path, Path, Path, Path, Path]:
    work = tmp_path / "work"
    results = work / "runs"
    (results / "engineering").mkdir(parents=True)
    base = results / "thesis" / "human-audit" / f"phase8-{authorized_sha[:16]}"
    attempts = base / "control" / "attempts"
    attempts.mkdir(parents=True)
    attempt = phase8_jobs._new_attempt_root(attempts)
    registration = phase8_jobs._console_registration_root(
        work, authorized_sha, attempt.name
    )
    return work, base / "control", attempt, base / "prepared", registration


def test_phase8_jobs_reverse_descriptor_is_create_only_and_exact(
    phase8_jobs: ModuleType,
    tmp_path: Path,
) -> None:
    authorized_sha = "d" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )

    published = phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    path = registration / phase8_jobs.JOBS_ARTIFACT_LINKS_FILE
    value = json.loads(path.read_text(encoding="utf-8"))
    relative_base = f"thesis/human-audit/phase8-{authorized_sha[:16]}"
    assert value == {
        "schema": phase8_jobs.JOBS_ARTIFACT_LINKS_SCHEMA,
        "campaign_id": registration.name,
        "links": [
            {
                "label": "Control files",
                "path": f"{relative_base}/control",
                "kind": "directory",
                "required": True,
            },
            {
                "label": "Exact attempt files",
                "path": f"{relative_base}/control/attempts/{attempt.name}",
                "kind": "directory",
                "required": True,
            },
            {
                "label": "Prepared output",
                "path": f"{relative_base}/prepared",
                "kind": "directory",
                "required": False,
            },
        ],
    }
    assert phase8_jobs._validate_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    ) == published
    hardlink = tmp_path / "artifact-links-hardlink.json"
    os.link(path, hardlink)
    with pytest.raises(phase8_jobs.Phase8Error, match="not create-only"):
        phase8_jobs._validate_jobs_artifact_links(
            work=work,
            registration_root=registration,
            authorized_sha=authorized_sha,
            control_root=control,
            attempt_root=attempt,
            final_root=prepared,
        )
    with pytest.raises(FileExistsError):
        phase8_jobs._publish_jobs_artifact_links(
            work=work,
            registration_root=registration,
            authorized_sha=authorized_sha,
            control_root=control,
            attempt_root=attempt,
            final_root=prepared,
        )


@pytest.mark.parametrize("mutation", ("label", "path", "required", "order"))
def test_phase8_jobs_revalidation_rejects_generic_valid_descriptor_drift(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    mutation: str,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    authorized_sha = "7" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )
    phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    descriptor = registration / phase8_jobs.JOBS_ARTIFACT_LINKS_FILE
    value = json.loads(descriptor.read_text(encoding="utf-8"))
    links = value["links"]
    if mutation == "label":
        links[1]["label"] = "Attempt artifacts"
    elif mutation == "path":
        links[1]["path"] = control.joinpath("attempts").relative_to(
            work / "runs"
        ).as_posix()
    elif mutation == "required":
        links[1]["required"] = False
    else:
        assert mutation == "order"
        links[0], links[1] = links[1], links[0]
    _write_payload = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"
    descriptor.write_bytes(_write_payload)

    generic_links, generic_error = campaigns_module._engineering_artifact_links(
        registration,
        marker_campaign_id=registration.name,
    )
    assert generic_error == ""
    assert generic_links
    with pytest.raises(phase8_jobs.Phase8Error, match="descriptor differs"):
        phase8_jobs._validate_jobs_artifact_links(
            work=work,
            registration_root=registration,
            authorized_sha=authorized_sha,
            control_root=control,
            attempt_root=attempt,
            final_root=prepared,
        )


def test_phase8_jobs_revalidation_rejects_missing_descriptor(
    phase8_jobs: ModuleType,
    tmp_path: Path,
) -> None:
    authorized_sha = "6" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )
    phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    (registration / phase8_jobs.JOBS_ARTIFACT_LINKS_FILE).unlink()

    with pytest.raises(phase8_jobs.Phase8Error, match="cannot be opened safely"):
        phase8_jobs._validate_jobs_artifact_links(
            work=work,
            registration_root=registration,
            authorized_sha=authorized_sha,
            control_root=control,
            attempt_root=attempt,
            final_root=prepared,
        )


def test_phase8_jobs_page_links_exact_control_attempt_and_prepared_artifacts(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    _use_real_console_cli(monkeypatch, phase8_jobs)
    authorized_sha = "e" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )
    phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    phase8_jobs._ensure_console_registration(
        project=Path.cwd(),
        work=work,
        registration_root=registration,
        socket="ura-phase8-test",
        session="ura-phase8-test",
    )
    for name, payload in (
        ("launch.json", "{}\n"),
        ("controller.log", "controller\n"),
        (".exit", "0\n"),
    ):
        (attempt / name).write_text(payload, encoding="utf-8")
    app = RigWebApp(
        results_root=work / "runs",
        state_dir=tmp_path / "state",
        gpu_hardware={},
        system_hardware={},
    )
    try:
        waiting = app.handle(
            "GET", f"/jobs/campaign/{registration.name}"
        )[2].decode("utf-8")
        assert "Related retained artifacts" in waiting
        assert "Prepared output" not in waiting

        prepared.mkdir()
        for name in (
            "machine-preparation-terminal.json",
            "artifact-inventory.json",
            "human-only-blocker.json",
        ):
            (prepared / name).write_text("{}\n", encoding="utf-8")
        status, _content_type, body = app.handle(
            "GET", f"/jobs/campaign/{registration.name}"
        )
        assert status == 200
        page = body.decode("utf-8")
        relative_base = f"thesis/human-audit/phase8-{authorized_sha[:16]}"
        attempt_relative = f"{relative_base}/control/attempts/{attempt.name}"
        expected_links = (
            f"engineering/{registration.name}/artifact-links.json",
            f"{relative_base}/control",
            attempt_relative,
            f"{relative_base}/prepared",
        )
        assert "Related retained artifacts" in page
        assert "Prepared output" in page
        for relative in expected_links:
            assert f"/artifacts?path={relative}" in page
            artifact_status, _artifact_type, _artifact_body = app.handle(
                "GET", f"/artifacts?path={relative}"
            )
            assert artifact_status == 200
        attempt_status, _attempt_type, attempt_body = app.handle(
            "GET", f"/artifacts?path={attempt_relative}"
        )
        assert attempt_status == 200
        attempt_page = attempt_body.decode("utf-8")
        for name in ("launch.json", "controller.log", ".exit"):
            relative = f"{attempt_relative}/{name}"
            assert f"/artifacts?path={relative}" in attempt_page
            assert app.handle("GET", f"/artifacts?path={relative}")[0] == 200
        prepared_relative = f"{relative_base}/prepared"
        prepared_page = app.handle(
            "GET", f"/artifacts?path={prepared_relative}"
        )[2].decode("utf-8")
        assert "machine-preparation-terminal.json" in prepared_page
    finally:
        app.close()


@pytest.mark.parametrize("mutation", ("tampered_identity", "out_of_root", "hardlink"))
def test_phase8_jobs_page_rejects_tampered_artifact_root_descriptor(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    _use_real_console_cli(monkeypatch, phase8_jobs)
    authorized_sha = "f" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )
    phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    phase8_jobs._ensure_console_registration(
        project=Path.cwd(),
        work=work,
        registration_root=registration,
        socket="ura-phase8-test",
        session="ura-phase8-test",
    )
    descriptor = registration / phase8_jobs.JOBS_ARTIFACT_LINKS_FILE
    if mutation == "hardlink":
        os.link(descriptor, tmp_path / "descriptor-hardlink.json")
    else:
        value = json.loads(descriptor.read_text(encoding="utf-8"))
        if mutation == "tampered_identity":
            value["campaign_id"] = "phase8-human-audit-tampered"
        else:
            value["links"][1]["path"] = "../outside-phase8"
        descriptor.write_text(json.dumps(value), encoding="utf-8")

    app = RigWebApp(
        results_root=work / "runs",
        state_dir=tmp_path / "state",
        gpu_hardware={},
        system_hardware={},
    )
    try:
        status, _content_type, body = app.handle(
            "GET", f"/jobs/campaign/{registration.name}"
        )
        assert status == 200
        page = body.decode("utf-8")
        assert "Engineering artifact-link descriptor is invalid." in page
        assert "Exact attempt files" not in page
        assert "Prepared output" not in page
        assert "outside-phase8" not in page
        escaped_status, _escaped_type, _escaped_body = app.handle(
            "GET", "/artifacts?path=../outside-phase8"
        )
        assert escaped_status == 400
    finally:
        app.close()


@pytest.mark.skipif(os.name == "nt", reason="open-file replacement is POSIX-only")
def test_phase8_jobs_page_rejects_descriptor_replaced_during_read(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    _use_real_console_cli(monkeypatch, phase8_jobs)
    authorized_sha = "8" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )
    phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    phase8_jobs._ensure_console_registration(
        project=Path.cwd(),
        work=work,
        registration_root=registration,
        socket="ura-phase8-test",
        session="ura-phase8-test",
    )
    descriptor = registration / phase8_jobs.JOBS_ARTIFACT_LINKS_FILE
    replacement = registration / "replacement.json"
    replacement.write_bytes(descriptor.read_bytes())
    real_read = campaigns_module.os.read
    replaced = False

    def replace_after_read(fd: int, count: int) -> bytes:
        nonlocal replaced
        payload = real_read(fd, count)
        if not replaced:
            replaced = True
            os.replace(replacement, descriptor)
        return payload

    monkeypatch.setattr(campaigns_module.os, "read", replace_after_read)
    campaign = load_engineering_campaign(work / "runs", registration.name)
    assert campaign is not None
    assert replaced
    assert campaign.artifact_links == ()
    assert campaign.artifact_link_error == (
        "Engineering artifact-link descriptor is invalid."
    )


@pytest.mark.skipif(os.name == "nt", reason="directory symlink alias is POSIX-only")
def test_phase8_jobs_page_rejects_intermediate_component_alias(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    _use_real_console_cli(monkeypatch, phase8_jobs)
    authorized_sha = "9" * 64
    work, control, attempt, prepared, registration = _phase8_artifact_layout(
        phase8_jobs, tmp_path=tmp_path, authorized_sha=authorized_sha
    )
    phase8_jobs._publish_jobs_artifact_links(
        work=work,
        registration_root=registration,
        authorized_sha=authorized_sha,
        control_root=control,
        attempt_root=attempt,
        final_root=prepared,
    )
    phase8_jobs._ensure_console_registration(
        project=Path.cwd(),
        work=work,
        registration_root=registration,
        socket="ura-phase8-test",
        session="ura-phase8-test",
    )
    attempts = control / "attempts"
    alias_target = work / "runs" / "aliased-phase8-attempts"
    attempts.rename(alias_target)
    attempts.symlink_to(alias_target, target_is_directory=True)

    app = RigWebApp(
        results_root=work / "runs",
        state_dir=tmp_path / "state",
        gpu_hardware={},
        system_hardware={},
    )
    try:
        status, _content_type, body = app.handle(
            "GET", f"/jobs/campaign/{registration.name}"
        )
        assert status == 200
        page = body.decode("utf-8")
        assert "Engineering artifact-link descriptor is invalid." in page
        assert "Exact attempt files" not in page
        assert "aliased-phase8-attempts" not in page
    finally:
        app.close()


def test_phase8_retry_creates_a_new_visible_running_jobs_attempt(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    _use_real_console_cli(monkeypatch, phase8_jobs)
    work = tmp_path / "work"
    engineering = work / "runs" / "engineering"
    engineering.mkdir(parents=True)
    attempts = tmp_path / "phase8" / "control" / "attempts"
    attempts.mkdir(parents=True)
    authorized_sha = "a" * 64

    first_attempt, first_registration = _new_registered_attempt(
        phase8_jobs,
        work=work,
        attempts=attempts,
        authorized_sha=authorized_sha,
    )
    phase8_jobs._record_registered_launch_failure(
        project=Path.cwd(),
        work=work,
        registration_root=first_registration,
        attempt=first_attempt,
        error_type="tmux_launch_infrastructure_failed",
        detail="tmux_launch_failed",
        returncode=None,
    )
    first = load_engineering_campaign(work / "runs", first_registration.name)
    assert first is not None
    assert first.state == "failed"

    second_attempt, second_registration = _new_registered_attempt(
        phase8_jobs,
        work=work,
        attempts=attempts,
        authorized_sha=authorized_sha,
    )
    second = load_engineering_campaign(work / "runs", second_registration.name)
    assert second is not None
    assert second.state == "running"
    assert second.active_tasks == ()
    assert first_attempt != second_attempt
    assert first_registration != second_registration
    assert first_registration.parent == engineering.resolve()
    assert second_registration.parent == engineering.resolve()
    assert first_registration.name.endswith(first_attempt.name)
    assert second_registration.name.endswith(second_attempt.name)
    second_events = (second_registration / "task-log.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(second_events) == 1
    assert json.loads(second_events[0])["event"] == "campaign_start"


def test_phase8_tmux_probe_distinguishes_absent_from_infrastructure_error(
    phase8_jobs: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def completed(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, "", "")

    monkeypatch.setattr(phase8_jobs.subprocess, "run", completed)
    assert phase8_jobs._tmux_session_is_active("socket", "session") is False
    command, kwargs = calls[-1]
    assert command == ["tmux", "-L", "socket", "has-session", "-t", "session"]
    assert kwargs["timeout"] == phase8_jobs.TMUX_COMMAND_TIMEOUT_SECONDS

    def infrastructure_error(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        del kwargs
        return subprocess.CompletedProcess(command, 2, "", "")

    monkeypatch.setattr(phase8_jobs.subprocess, "run", infrastructure_error)
    with pytest.raises(phase8_jobs.Phase8Error, match="exit code 2"):
        phase8_jobs._tmux_session_is_active("socket", "session")


def test_phase8_registered_tmux_infrastructure_failures_are_terminal(
    phase8_jobs: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: False for spec in specs},
    )
    _use_real_console_cli(monkeypatch, phase8_jobs)
    work = tmp_path / "work"
    (work / "runs" / "engineering").mkdir(parents=True)
    attempts = tmp_path / "phase8" / "control" / "attempts"
    attempts.mkdir(parents=True)

    probe_attempt, probe_registration = _new_registered_attempt(
        phase8_jobs,
        work=work,
        attempts=attempts,
        authorized_sha="b" * 64,
    )

    def probe_os_error(command: list[str], **kwargs: object) -> None:
        del command, kwargs
        raise OSError("tmux unavailable")

    monkeypatch.setattr(phase8_jobs.subprocess, "run", probe_os_error)
    with pytest.raises(
        phase8_jobs.Phase8Error, match="session state could not be determined"
    ):
        phase8_jobs._require_registered_tmux_session_absent(
            project=Path.cwd(),
            work=work,
            registration_root=probe_registration,
            attempt=probe_attempt,
            socket="ura-phase8-test",
            session="ura-phase8-test",
        )
    probe = load_engineering_campaign(work / "runs", probe_registration.name)
    assert probe is not None
    assert probe.state == "failed"
    assert json.loads(
        (probe_attempt / "launch-failure.json").read_text(encoding="utf-8")
    )["error_type"] == "tmux_session_probe_failed"

    launch_attempt, launch_registration = _new_registered_attempt(
        phase8_jobs,
        work=work,
        attempts=attempts,
        authorized_sha="c" * 64,
    )

    def launch_timeout(command: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(phase8_jobs.subprocess, "run", launch_timeout)
    with pytest.raises(
        phase8_jobs.Phase8Error, match="could not launch the authorized controller"
    ):
        phase8_jobs._launch_registered_tmux_session(
            project=Path.cwd(),
            work=work,
            registration_root=launch_registration,
            attempt=launch_attempt,
            socket="ura-phase8-test",
            session="ura-phase8-test",
            command="exec /bin/true",
        )
    launch = load_engineering_campaign(work / "runs", launch_registration.name)
    assert launch is not None
    assert launch.state == "failed"
    assert json.loads(
        (launch_attempt / "launch-failure.json").read_text(encoding="utf-8")
    )["error_type"] == "tmux_launch_infrastructure_failed"


def test_phase8_jobs_operator_guide_describes_the_visible_terminal() -> None:
    guide = (
        TEMPLATE.with_name("phase8_human_audit.README.md.in")
    ).read_text(encoding="ascii")
    assert (
        "phase8-human-audit-<authorized-input-SHA-prefix>-attempt-<UTC>-<PID>"
        "[-<sequence>]" in guide
    )
    assert (
        "Each invocation creates a new attempt directory and direct Jobs campaign"
        in guide
    )
    assert "<control>/attempts/attempt-.../launch.json" in guide
    assert "create-only generic `artifact-links.json`" in guide
    assert "prepared root after that root is published" in " ".join(guide.split())
    assert "without reopening terminal history" in guide
    assert "terminal `blocked` with detail `human_only`" in guide
    assert "tmux-launch error is terminal `failed`" in guide
    assert (
        "it forbids hosted calls and is not thesis empirical evidence"
        in " ".join(guide.split())
    )


def test_phase8_operator_guide_self_test_uses_deployed_checkout() -> None:
    guide = TEMPLATE.with_name("phase8_human_audit.README.md.in").read_text(
        encoding="ascii"
    )
    assert (
        "```bash\n"
        "cd /home/ura/MLLMRiskBench\n"
        "bash ~/.ura-controller-active/phase8_human_audit.sh --self-test\n"
        "```"
    ) in guide


def test_phase8_operator_guide_documents_non_fabricated_ethics_contract() -> None:
    guide = TEMPLATE.with_name("phase8_human_audit.README.md.in").read_text(
        encoding="ascii"
    )
    assert "intentionally non-runnable shape template" in guide
    block = guide.split("```json\n", 1)[1].split("\n```", 1)[0]
    template = json.loads(block)
    assert tuple(template) == (
        "schema",
        "status",
        "determination_id",
        "decided_at_utc",
        "responsible_party",
        "scope",
        "sensitive_content_acknowledged",
        "preparation_authorized",
        "human_labeling_authorized",
        "details",
    )
    assert tuple(template["scope"]) == (
        "expected_commit",
        "framework_lock_id",
        "runner_root",
        "common_frame",
        "source_task_frame",
    )
    assert template["schema"] == "ura-human-audit-ethics-determination/1"
    assert template["status"] == "OPERATOR_MUST_CHOOSE_ALLOWED_STATUS"
    assert template["scope"]["expected_commit"] == "@@EXPECTED_COMMIT@@"
    assert (
        template["scope"]["framework_lock_id"]
        == "@@FRAMEWORK_LOCK_SHA256@@"
    )
    assert template["details"] == {}
    for value in (
        *(
            template[field]
            for field in (
                "status",
                "determination_id",
                "decided_at_utc",
                "responsible_party",
                "sensitive_content_acknowledged",
                "preparation_authorized",
                "human_labeling_authorized",
            )
        ),
        template["scope"]["runner_root"],
        template["scope"]["common_frame"],
        template["scope"]["source_task_frame"],
    ):
        assert isinstance(value, str) and value.startswith("OPERATOR_MUST_")
    normalized = " ".join(guide.split())
    for fragment in (
        "`status` must be exactly one of `approved`, `exempt`, "
        "`not_human_subjects`, or `authorized`",
        "JSON boolean `true` for both `common_frame` and `source_task_frame`",
        "acknowledgement and preparation-authorization fields must also be "
        "JSON boolean `true`",
        "`human_labeling_authorized` must be a JSON boolean",
    ):
        assert fragment in normalized
