from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from experiments.local_campaign import console_events as console_events_module
from experiments.local_campaign.console_events import (
    ConsoleEventError,
    append_event,
    finish_child_controller,
    main as console_main,
    publish_target_execution,
    start_campaign,
    start_child_controller,
)
from experiments.rig_web_app.campaigns import load_engineering_campaign
from experiments.rig_web_app.app import RigWebApp


_TEMPLATES = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    work = tmp_path / "work"
    control = work / "runs" / "engineering" / "phase5-sequence-20260823T120000Z"
    control.mkdir(parents=True)
    return work, control


def _start_target_controller(work: Path, control: Path) -> None:
    start_child_controller(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        tmux_socket="ura-model-controller",
        tmux_session="ura-model-controller",
        target_execution=True,
    )


def test_tmux_controller_registration_is_visible_and_reaches_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    work, control = _roots(tmp_path)
    start_campaign(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        planned_tasks=("projection", "canary"),
        tmux_socket="ura-phase5-sequence",
        tmux_session="ura-phase5-sequence",
        at="2026-08-23T12:00:00Z",
    )
    append_event(
        work_root=work,
        control_root=control,
        event="task_start",
        task="projection",
        status="running",
        detail="projection-root",
        at="2026-08-23T12:00:01Z",
    )
    running = load_engineering_campaign(work / "runs", control.name)
    assert running is not None
    assert running.state == "running"
    assert running.active_tasks == ("projection",)
    assert running.pending_tasks == 1

    append_event(
        work_root=work,
        control_root=control,
        event="task_end",
        task="projection",
        status="passed",
        detail="projection-root",
        at="2026-08-23T12:00:02Z",
    )
    append_event(
        work_root=work,
        control_root=control,
        event="task_skip",
        task="canary",
        status="skipped",
        detail="not_reached",
        at="2026-08-23T12:00:03Z",
    )
    append_event(
        work_root=work,
        control_root=control,
        event="campaign_end",
        task="bootstrap",
        status="failed",
        detail="controller_exit=1",
        at="2026-08-23T12:00:04Z",
    )
    terminal = load_engineering_campaign(work / "runs", control.name)
    assert terminal is not None
    assert terminal.state == "failed"
    assert terminal.succeeded_tasks == 1
    assert terminal.skipped_tasks == 1
    assert terminal.active_tasks == ()
    assert terminal.pending_tasks == 0


def test_child_controller_uses_native_jobs_index_and_detail_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    work, control = _roots(tmp_path)
    assert (
        console_main(
            [
                "child-start",
                "--work-root",
                str(work),
                "--control-root",
                str(control),
                "--campaign-id",
                control.name,
                "--release-commit",
                "a" * 40,
                "--evidence-class",
                "local_campaign_control",
                "--hard-stop-hours",
                "24",
                "--tmux-socket",
                "ura-child-controller",
                "--tmux-session",
                "ura-child-controller",
                "--at",
                "2026-08-23T12:00:00Z",
            ]
        )
        == 0
    )
    initial_rows = [
        json.loads(line)
        for line in (control / "task-log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [row["event"] for row in initial_rows] == [
        "campaign_start",
        "task_start",
    ]

    app = RigWebApp(
        results_root=work / "runs",
        state_dir=tmp_path / "state",
    )
    jobs = app.handle("GET", "/jobs")
    detail = app.handle("GET", f"/jobs/campaign/{control.name}")
    assert jobs[0] == 200
    assert f"/jobs/campaign/{control.name}" in jobs[2].decode("utf-8")
    assert detail[0] == 200
    assert "controller" in detail[2].decode("utf-8")
    assert (
        console_main(
            [
                "child-finish",
                "--work-root",
                str(work),
                "--control-root",
                str(control),
                "--exit-code",
                "0",
                "--at",
                "2026-08-23T12:00:01Z",
            ]
        )
        == 0
    )
    terminal = load_engineering_campaign(work / "runs", control.name)
    assert terminal is not None
    assert terminal.state == "complete"
    assert terminal.status_tag == "passed"
    marker = json.loads((control / "ENGINEERING_ONLY.json").read_text(encoding="utf-8"))
    assert marker["model_tasks"] == []
    assert terminal.task_outcomes == (("controller", "passed", "support"),)
    assert "model tasks: not applicable - support only" in terminal.progress
    assert "model execution: not applicable - support only" in terminal.progress
    terminal_jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    terminal_detail = app.handle(
        "GET", f"/jobs/campaign/{control.name}"
    )[2].decode("utf-8")
    terminal_stats = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "<td>support only</td><td>not applicable - support only</td>" in terminal_jobs
    assert (
        "<tr><td>Declared model tasks</td><td>support only</td></tr>"
        in terminal_detail
    )
    assert (
        "<tr><td>Reported model execution</td><td>"
        "not applicable - support only</td></tr>"
        in terminal_detail
    )
    stats_card = terminal_stats.split(f">{control.name}</a>", 1)[1].split(
        "</article>", 1
    )[0]
    assert (
        "<dt>Reported calls</dt><dd>not applicable - support only "
        "(operational self-report)</dd>"
        in stats_card
    )
    app.close()


def test_target_capable_child_reports_target_only_calls_without_analysis_charts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    work, control = _roots(tmp_path)
    _start_target_controller(work, control)
    marker = json.loads((control / "ENGINEERING_ONLY.json").read_text(encoding="utf-8"))
    assert marker["model_tasks"] == ["controller"]
    assert marker["model_execution_scope"] == "target_only_mixed_controller"
    assert (
        console_main(
            [
                "target-execution",
                "--work-root",
                str(work),
                "--control-root",
                str(control),
                "--target-attempts",
                "7",
                "--successful-target-generations",
                "5",
            ]
        )
        == 0
    )
    finish_child_controller(
        work_root=work,
        control_root=control,
        exit_code=0,
    )

    terminal = load_engineering_campaign(work / "runs", control.name)
    assert terminal is not None
    assert terminal.task_outcomes == (("controller", "passed", "mixed"),)
    assert terminal.model_execution_scope == "target_only_mixed_controller"
    assert terminal.model_attempted_calls == 7
    assert terminal.model_successful_generations == 5
    assert terminal.model_execution_error == ""
    assert "target-capable mixed controller:" in terminal.progress

    app = RigWebApp(results_root=work / "runs", state_dir=tmp_path / "state")
    jobs_html = app.handle("GET", "/jobs")[2].decode("utf-8")
    assert "target-capable mixed controller" in jobs_html
    assert "5/7 target calls returned successfully" in jobs_html
    detail_html = app.handle("GET", f"/jobs/campaign/{control.name}")[2].decode("utf-8")
    assert "Target-capable mixed controller" in detail_html
    assert "Reported target execution" in detail_html
    assert "guard, defense, attacker, and framework-model roles" in detail_html
    stats_html = app.handle("GET", "/stats")[2].decode("utf-8")
    card = stats_html.split(f">{control.name}</a>", 1)[1].split("</article>", 1)[0]
    assert "Reported target attempts" in card
    assert "7 (operational self-report)" in card
    assert "stats-detail-trigger" not in card
    app.close()


def test_target_execution_publication_is_create_only(tmp_path: Path) -> None:
    work, control = _roots(tmp_path)
    _start_target_controller(work, control)
    kwargs = {
        "work_root": work,
        "control_root": control,
        "target_attempts": 2,
        "successful_target_generations": 1,
    }
    publish_target_execution(**kwargs)
    row = json.loads((control / "model-execution.jsonl").read_text(encoding="utf-8"))
    assert row["execution_role"] == "target"
    retained = (control / "model-execution.jsonl").read_bytes()
    with pytest.raises(ConsoleEventError, match="create-only"):
        publish_target_execution(**kwargs)
    assert (control / "model-execution.jsonl").read_bytes() == retained


def test_target_scope_rejects_an_execution_row_without_target_role(
    tmp_path: Path,
) -> None:
    work, control = _roots(tmp_path)
    _start_target_controller(work, control)
    (control / "model-execution.jsonl").write_text(
        json.dumps({
            "attempted_calls": 1,
            "event": "model_execution",
            "successful_generations": 1,
            "task": "controller",
        })
        + "\n",
        encoding="utf-8",
    )

    observed = load_engineering_campaign(work / "runs", control.name)
    assert observed is not None
    assert observed.model_attempted_calls is None
    assert observed.model_execution_error == (
        "target execution event lacks execution_role=target"
    )


def test_legacy_model_scope_rejects_a_target_execution_role(tmp_path: Path) -> None:
    work, control = _roots(tmp_path)
    start_campaign(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        planned_tasks=("controller",),
        tmux_socket="ura-model-controller",
        tmux_session="ura-model-controller",
        model_tasks=("controller",),
        initial_running_tasks=("controller",),
    )
    (control / "model-execution.jsonl").write_text(
        json.dumps({
            "attempted_calls": 1,
            "event": "model_execution",
            "execution_role": "target",
            "successful_generations": 1,
            "task": "controller",
        })
        + "\n",
        encoding="utf-8",
    )

    observed = load_engineering_campaign(work / "runs", control.name)
    assert observed is not None
    assert observed.model_attempted_calls is None
    assert observed.model_execution_error == (
        "execution_role requires a declared model_execution_scope"
    )


def test_invalid_execution_scope_cannot_downgrade_to_a_legacy_report(
    tmp_path: Path,
) -> None:
    work, control = _roots(tmp_path)
    start_campaign(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        planned_tasks=("controller",),
        tmux_socket="ura-model-controller",
        tmux_session="ura-model-controller",
        model_tasks=("controller",),
        initial_running_tasks=("controller",),
    )
    marker_path = control / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["model_execution_scope"] = "unsupported_scope"
    marker_path.write_text(json.dumps(marker) + "\n", encoding="utf-8")
    (control / "model-execution.jsonl").write_text(
        json.dumps({
            "attempted_calls": 1,
            "event": "model_execution",
            "successful_generations": 1,
            "task": "controller",
        })
        + "\n",
        encoding="utf-8",
    )

    observed = load_engineering_campaign(work / "runs", control.name)
    assert observed is not None
    assert observed.model_tasks is None
    assert observed.model_attempted_calls is None
    assert observed.model_declaration_error == "unsupported model_execution_scope"
    assert observed.model_execution_error == (
        "model execution log requires a valid model_tasks declaration"
    )
    assert observed.task_outcomes == (("controller", "running", "unclassified"),)


def test_target_execution_scope_rejects_a_multi_task_controller(tmp_path: Path) -> None:
    work, control = _roots(tmp_path)
    with pytest.raises(ConsoleEventError, match="one mixed controller task"):
        start_campaign(
            work_root=work,
            control_root=control,
            campaign_id=control.name,
            release_commit="a" * 40,
            evidence_class="local_campaign_control",
            hard_stop_hours=24,
            planned_tasks=("controller", "postprocess"),
            tmux_socket="ura-model-controller",
            tmux_session="ura-model-controller",
            model_tasks=("controller", "postprocess"),
            model_execution_scope="target_only_mixed_controller",
        )
    assert not (control / "ENGINEERING_ONLY.json").exists()


def test_target_controller_without_complete_accounting_remains_not_reported(
    tmp_path: Path,
) -> None:
    work, control = _roots(tmp_path)
    _start_target_controller(work, control)
    finish_child_controller(work_root=work, control_root=control, exit_code=0)

    observed = load_engineering_campaign(work / "runs", control.name)
    assert observed is not None
    assert observed.model_attempted_calls is None
    assert observed.model_execution_error == ""
    assert "target execution: not reported" in observed.progress


def test_child_start_marker_failure_removes_complete_initial_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work, control = _roots(tmp_path)
    write_create_only = console_events_module._write_create_only

    def fail_marker(path: Path, payload: bytes) -> tuple[int, int]:
        if path.name == "ENGINEERING_ONLY.json":
            raise ConsoleEventError("injected marker failure")
        return write_create_only(path, payload)

    monkeypatch.setattr(console_events_module, "_write_create_only", fail_marker)
    with pytest.raises(ConsoleEventError, match="injected marker failure"):
        start_child_controller(
            work_root=work,
            control_root=control,
            campaign_id=control.name,
            release_commit="a" * 40,
            evidence_class="local_campaign_control",
            hard_stop_hours=24,
            tmux_socket="ura-child-controller",
            tmux_session="ura-child-controller",
        )

    assert not (control / "ENGINEERING_ONLY.json").exists()
    assert not (control / "task-log.jsonl").exists()


def test_child_finish_appends_one_complete_terminal_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work, control = _roots(tmp_path)
    start_child_controller(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        tmux_socket="ura-child-controller",
        tmux_session="ura-child-controller",
    )
    append = console_events_module._append
    payloads: list[bytes] = []

    def record_append(path: Path, payload: bytes) -> None:
        payloads.append(payload)
        append(path, payload)

    monkeypatch.setattr(console_events_module, "_append", record_append)
    finish_child_controller(work_root=work, control_root=control, exit_code=1)

    assert len(payloads) == 1
    terminal_rows = [json.loads(line) for line in payloads[0].splitlines()]
    assert [row["event"] for row in terminal_rows] == ["task_end", "campaign_end"]
    assert {row["status"] for row in terminal_rows} == {"failed"}


def test_child_finish_append_failure_leaves_lifecycle_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work, control = _roots(tmp_path)
    start_child_controller(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        tmux_socket="ura-child-controller",
        tmux_session="ura-child-controller",
    )
    task_log = control / "task-log.jsonl"
    before = task_log.read_bytes()

    def fail_append(_path: Path, _payload: bytes) -> None:
        raise ConsoleEventError("injected terminal append failure")

    monkeypatch.setattr(console_events_module, "_append", fail_append)
    with pytest.raises(ConsoleEventError, match="injected terminal append failure"):
        finish_child_controller(work_root=work, control_root=control, exit_code=1)

    assert task_log.read_bytes() == before


def test_resumable_controller_cannot_rebind_create_only_session_identity(
    tmp_path: Path,
) -> None:
    work, control = _roots(tmp_path)
    start_child_controller(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        tmux_socket="ura-attempt-one",
        tmux_session="ura-attempt-one",
    )
    finish_child_controller(work_root=work, control_root=control, exit_code=130)
    retained_marker = (control / "ENGINEERING_ONLY.json").read_bytes()
    retained_log = (control / "task-log.jsonl").read_bytes()

    with pytest.raises(ConsoleEventError, match="create-only"):
        start_child_controller(
            work_root=work,
            control_root=control,
            campaign_id=control.name,
            release_commit="a" * 40,
            evidence_class="local_campaign_control",
            hard_stop_hours=24,
            tmux_socket="ura-attempt-two",
            tmux_session="ura-attempt-two",
        )

    marker = json.loads(retained_marker)
    assert marker["tmux_session"] == "ura-attempt-one"
    assert (control / "ENGINEERING_ONLY.json").read_bytes() == retained_marker
    assert (control / "task-log.jsonl").read_bytes() == retained_log
    terminal = load_engineering_campaign(work / "runs", control.name)
    assert terminal is not None
    assert terminal.state == "failed"


@pytest.mark.parametrize("exit_code", (-1, 256, True))
def test_child_controller_terminal_rejects_invalid_exit_code(
    tmp_path: Path,
    exit_code: int,
) -> None:
    work, control = _roots(tmp_path)
    start_child_controller(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        tmux_socket="ura-child-controller",
        tmux_session="ura-child-controller",
    )
    before = (control / "task-log.jsonl").read_bytes()

    with pytest.raises(ConsoleEventError, match="exit code"):
        finish_child_controller(
            work_root=work,
            control_root=control,
            exit_code=exit_code,
        )

    assert (control / "task-log.jsonl").read_bytes() == before


@pytest.mark.parametrize("spoof", ("outside", "campaign_id"))
def test_child_controller_registration_preserves_native_root_ownership(
    tmp_path: Path,
    spoof: str,
) -> None:
    work, control = _roots(tmp_path)
    campaign_id = control.name
    if spoof == "outside":
        control = work / "runs" / "thesis" / control.name
        control.mkdir(parents=True)
    else:
        campaign_id = "spoofed-child"

    with pytest.raises(ConsoleEventError, match="direct engineering|must equal"):
        start_child_controller(
            work_root=work,
            control_root=control,
            campaign_id=campaign_id,
            release_commit="a" * 40,
            evidence_class="local_campaign_control",
            hard_stop_hours=24,
            tmux_socket="ura-child-controller",
            tmux_session="ura-child-controller",
        )

    assert not (control / "ENGINEERING_ONLY.json").exists()
    assert not (control / "task-log.jsonl").exists()


def test_human_only_campaign_is_terminal_blocked_not_running(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: False for spec in specs},
    )
    work, control = _roots(tmp_path)
    start_campaign(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="a" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        planned_tasks=("machine-preparation",),
        tmux_socket="ura-phase8-human-audit",
        tmux_session="ura-phase8-human-audit",
        at="2026-08-23T12:00:00Z",
    )
    append_event(
        work_root=work,
        control_root=control,
        event="task_start",
        task="machine-preparation",
        status="running",
        detail="prepared-rating-forms",
        at="2026-08-23T12:00:01Z",
    )
    append_event(
        work_root=work,
        control_root=control,
        event="task_end",
        task="machine-preparation",
        status="passed",
        detail="prepared-rating-forms",
        at="2026-08-23T12:00:02Z",
    )
    append_event(
        work_root=work,
        control_root=control,
        event="campaign_end",
        task="bootstrap",
        status="blocked",
        detail="human_only",
        at="2026-08-23T12:00:03Z",
    )

    terminal = load_engineering_campaign(work / "runs", control.name)
    assert terminal is not None
    assert terminal.state == "failed"
    assert terminal.display_state == "blocked"
    assert terminal.state_detail == "human_only"
    assert terminal.succeeded_tasks == 1
    assert terminal.active_tasks == ()
    assert terminal.pending_tasks == 0


def test_registration_is_create_only_and_cannot_escape_engineering(tmp_path: Path) -> None:
    work, control = _roots(tmp_path)
    kwargs = {
        "work_root": work,
        "control_root": control,
        "campaign_id": control.name,
        "release_commit": "b" * 40,
        "evidence_class": "local_campaign_control",
        "hard_stop_hours": 24,
        "planned_tasks": ("canary",),
        "tmux_socket": "ura-gate5-sequence",
        "tmux_session": "ura-gate5-sequence",
        "at": "2026-08-23T12:00:00Z",
    }
    start_campaign(**kwargs)
    with pytest.raises(ConsoleEventError, match="create-only"):
        start_campaign(**kwargs)

    outside = work / "runs" / "thesis" / "not-engineering"
    outside.mkdir(parents=True)
    with pytest.raises(ConsoleEventError, match="direct engineering"):
        start_campaign(**{**kwargs, "control_root": outside, "campaign_id": outside.name})


def test_marker_create_failure_removes_only_the_new_task_log(tmp_path: Path) -> None:
    work, control = _roots(tmp_path)
    marker = control / "ENGINEERING_ONLY.json"
    retained = b"pre-existing-marker\n"
    marker.write_bytes(retained)
    kwargs = {
        "work_root": work,
        "control_root": control,
        "campaign_id": control.name,
        "release_commit": "d" * 40,
        "evidence_class": "local_campaign_control",
        "hard_stop_hours": 24,
        "planned_tasks": ("canary",),
        "tmux_socket": "ura-phase5-sequence",
        "tmux_session": "ura-phase5-sequence",
        "at": "2026-08-23T12:00:00Z",
    }

    with pytest.raises(ConsoleEventError, match="create-only"):
        start_campaign(**kwargs)

    assert marker.read_bytes() == retained
    assert not (control / "task-log.jsonl").exists()

    marker.unlink()
    start_campaign(**kwargs)
    assert marker.is_file()
    assert (control / "task-log.jsonl").is_file()


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("tmux_socket", "-unsafe"),
        ("tmux_session", "contains/slash"),
        ("tmux_session", "x" * 129),
    ),
)
def test_registration_rejects_unsafe_named_session_identity(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    work, control = _roots(tmp_path)
    kwargs = {
        "work_root": work,
        "control_root": control,
        "campaign_id": control.name,
        "release_commit": "f" * 40,
        "evidence_class": "local_campaign_control",
        "hard_stop_hours": 24,
        "planned_tasks": ("canary",),
        "tmux_socket": "ura-phase5-sequence",
        "tmux_session": "ura-phase5-sequence",
    }
    kwargs[field] = value

    with pytest.raises(ConsoleEventError, match="safe named-session tokens"):
        start_campaign(**kwargs)

    assert not (control / "task-log.jsonl").exists()
    assert not (control / "ENGINEERING_ONLY.json").exists()


@pytest.mark.parametrize("linked_name", ("ENGINEERING_ONLY.json", "task-log.jsonl"))
def test_event_rejects_hard_linked_registration_files(
    tmp_path: Path,
    linked_name: str,
) -> None:
    work, control = _roots(tmp_path)
    start_campaign(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="e" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        planned_tasks=("canary",),
        tmux_socket="ura-phase5-sequence",
        tmux_session="ura-phase5-sequence",
        at="2026-08-23T12:00:00Z",
    )
    source = control / linked_name
    outside_link = work / f"outside-{linked_name}"
    try:
        os.link(source, outside_link)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    before = source.read_bytes()

    with pytest.raises(ConsoleEventError, match="exactly one hard link"):
        append_event(
            work_root=work,
            control_root=control,
            event="task_start",
            task="canary",
            status="running",
            detail="must-not-append",
        )

    assert source.read_bytes() == before
    assert outside_link.read_bytes() == before


def test_registration_marker_is_non_empirical_and_hosted_calls_are_disabled(
    tmp_path: Path,
) -> None:
    work, control = _roots(tmp_path)
    start_campaign(
        work_root=work,
        control_root=control,
        campaign_id=control.name,
        release_commit="c" * 40,
        evidence_class="local_campaign_control",
        hard_stop_hours=24,
        planned_tasks=("canary",),
        tmux_socket="ura-phase5-sequence",
        tmux_session="ura-phase5-sequence",
        at="2026-08-23T12:00:00Z",
    )
    marker = json.loads((control / "ENGINEERING_ONLY.json").read_text(encoding="utf-8"))
    assert marker["thesis_empirical_evidence"] is False
    assert marker["hosted_calls_allowed"] is False
    assert marker["planned_tasks"] == ["canary"]
    assert marker["tmux_socket"] == "ura-phase5-sequence"
    assert marker["tmux_session"] == "ura-phase5-sequence"

    with pytest.raises(ConsoleEventError, match="declared campaign plan"):
        append_event(
            work_root=work,
            control_root=control,
            event="task_start",
            task="undeclared",
            status="running",
            detail="",
        )
    with pytest.raises(ConsoleEventError, match="lifecycle event"):
        append_event(
            work_root=work,
            control_root=control,
            event="task_start",
            task="canary",
            status="passed",
            detail="",
        )


@pytest.mark.parametrize(
    ("template_name", "tmux_identity"),
    (
        (
            "phase5_sequence_after_core.sh.in",
            "ura-phase5-sequence-@@COMMIT_SHORT@@",
        ),
        (
            "gate5_after_phase5_sequence.sh.in",
            "ura-gate5-after-phase5-@@COMMIT_SHORT@@",
        ),
        (
            "phase7_after_phase6_sequence.sh.in",
            "ura-phase7-after-phase6-@@COMMIT_SHORT@@",
        ),
    ),
)
def test_controller_template_registers_identity_and_publishes_exit_before_terminal(
    template_name: str,
    tmux_identity: str,
) -> None:
    source = (_TEMPLATES / template_name).read_text(encoding="utf-8")
    assert source.count(f"--tmux-socket {tmux_identity}") == 1
    assert source.count(f"--tmux-session {tmux_identity}") == 1
    finish = source.split("\nfinish() {", 1)[1].split("\n}\ntrap finish EXIT", 1)[0]
    marker_publication = finish.index('mv -- "$EXIT_TMP" "$EXIT_MARKER"')
    terminal_publication = finish.index('controller_finish "$rc"')
    assert marker_publication < terminal_publication < finish.index('exit "$rc"')
    assert "rc=$?" in finish
    assert "trap - EXIT" in finish
    assert "console event failed: task_end" in source
    assert "console event failed: task_skip" in source
    assert "console event failed: campaign_end" in source
