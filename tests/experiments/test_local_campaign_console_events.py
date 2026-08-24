from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from experiments.local_campaign.console_events import (
    ConsoleEventError,
    append_event,
    start_campaign,
)
from experiments.rig_web_app.campaigns import load_engineering_campaign


_TEMPLATES = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    work = tmp_path / "work"
    control = work / "runs" / "engineering" / "phase5-sequence-20260823T120000Z"
    control.mkdir(parents=True)
    return work, control


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
