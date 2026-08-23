"""Bounded exact named-session liveness for external campaign rows."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app import campaigns as campaigns_module
from experiments.rig_web_app.campaigns import (
    load_engineering_campaign,
    scan_engineering_campaigns,
)


def _timestamp(value: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))


def _engineering_campaign(
    results: Path,
    route: str,
    *,
    started_at: float,
    session_fields: bool,
    terminal: bool = False,
    hard_stop_hours: int = 24,
) -> Path:
    directory = results / "engineering" / route
    directory.mkdir(parents=True)
    marker = {
        "schema": "ura-engineering-campaign/1",
        "campaign_id": route,
        "release_commit": "a" * 40,
        "evidence_class": "external_controller",
        "thesis_empirical_evidence": False,
        "hosted_calls_allowed": False,
        "hard_stop_hours": hard_stop_hours,
        "started_at": _timestamp(started_at),
        "planned_tasks": ["measured"],
    }
    if session_fields:
        marker.update(
            {
                "tmux_socket": f"ura-socket-{route}",
                "tmux_session": f"ura-session-{route}",
            }
        )
    (directory / "ENGINEERING_ONLY.json").write_text(
        json.dumps(marker) + "\n",
        encoding="utf-8",
    )
    events = [
        {
            "at": _timestamp(started_at),
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
            "detail": "external_controller",
        },
        {
            "at": _timestamp(started_at + 1),
            "event": "task_start",
            "task": "measured",
            "status": "running",
            "detail": "measured_started",
        },
    ]
    if terminal:
        events.extend(
            [
                {
                    "at": _timestamp(started_at + 2),
                    "event": "task_end",
                    "task": "measured",
                    "status": "passed",
                    "detail": "measured_complete",
                },
                {
                    "at": _timestamp(started_at + 3),
                    "event": "campaign_end",
                    "task": "bootstrap",
                    "status": "passed",
                    "detail": "external_controller_exit_0",
                },
            ]
        )
    (directory / "task-log.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    return directory


def test_dead_named_session_is_orphaned_but_terminal_legacy_route_survives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "runs"
    started = time.time() - 120
    dead_route = "controller-sequence-dead"
    _engineering_campaign(
        results,
        dead_route,
        started_at=started,
        session_fields=True,
    )
    missing_route = "controller-sequence-missing-session"
    _engineering_campaign(
        results,
        missing_route,
        started_at=started,
        session_fields=False,
    )
    legacy_route = "controller-sequence-terminal-legacy"
    _engineering_campaign(
        results,
        legacy_route,
        started_at=started,
        session_fields=False,
        terminal=True,
    )
    campaigns_module._clear_named_session_liveness_cache()
    probes: list[list[str]] = []

    monkeypatch.setattr(
        campaigns_module.shutil,
        "which",
        lambda name, *, path=None: "/usr/bin/tmux" if name == "tmux" else None,
    )

    def run(argv: list[str], **_kwargs: object) -> object:
        probes.append(argv)
        return subprocess.CompletedProcess(argv, 1)

    monkeypatch.setattr(campaigns_module.subprocess, "run", run)
    dead = load_engineering_campaign(results, dead_route)
    missing = load_engineering_campaign(results, missing_route)
    terminal = load_engineering_campaign(results, legacy_route)
    campaigns_module._clear_named_session_liveness_cache()

    assert dead is not None
    assert dead.state == "orphaned"
    assert "engineering campaign named session is no longer live" in dead.state_detail
    assert dead.active_tasks == ()
    assert probes == [
        [
            "/usr/bin/tmux",
            "-L",
            f"ura-socket-{dead_route}",
            "has-session",
            "-t",
            f"ura-session-{dead_route}",
        ]
    ]
    assert missing is not None and missing.state == "running"
    assert missing.named_session_liveness_verified is False
    assert terminal is not None
    assert terminal.state == "complete" and terminal.status_tag == "passed"
    assert terminal.state_detail == "external_controller_exit_0"


def test_campaign_scan_probes_unique_sessions_concurrently_and_uses_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "runs"
    started = time.time() - 120
    count = 12
    for index in range(count):
        _engineering_campaign(
            results,
            f"controller-sequence-{index:02d}",
            started_at=started + index,
            session_fields=True,
        )
    campaigns_module._clear_named_session_liveness_cache()
    monkeypatch.setattr(
        campaigns_module.shutil,
        "which",
        lambda name, *, path=None: "/usr/bin/tmux" if name == "tmux" else None,
    )
    lock = threading.Lock()
    active = 0
    maximum_active = 0
    calls = 0

    def probe(
        _spec: object,
        *,
        tmux: str | None,
        screen: str | None,
    ) -> bool:
        nonlocal active, maximum_active, calls
        assert tmux == "/usr/bin/tmux" and screen is None
        with lock:
            active += 1
            calls += 1
            maximum_active = max(maximum_active, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return True

    monkeypatch.setattr(campaigns_module, "_probe_one_named_session", probe)
    first, first_notice = scan_engineering_campaigns(results)
    second, second_notice = scan_engineering_campaigns(results)
    campaigns_module._clear_named_session_liveness_cache()

    assert first_notice == second_notice == ""
    assert len(first) == len(second) == count
    assert all(campaign.state == "running" for campaign in first + second)
    assert calls == count
    # Mutation proof for the prior serial loop: one-worker/session-at-a-time
    # probing cannot satisfy this observed overlap.
    assert maximum_active >= 4


@pytest.mark.parametrize(
    ("probe_result", "expected_state", "detail_fragment"),
    (
        (True, "running", "hard stop exceeded"),
        (None, "unknown", "liveness is unavailable"),
    ),
)
def test_hard_stop_fallback_never_overrides_exact_live_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    probe_result: bool | None,
    expected_state: str,
    detail_fragment: str,
) -> None:
    results = tmp_path / "runs"
    route = "controller-sequence-overdue"
    _engineering_campaign(
        results,
        route,
        started_at=time.time() - 2 * 3600,
        session_fields=True,
        hard_stop_hours=1,
    )
    campaigns_module._clear_named_session_liveness_cache()
    monkeypatch.setattr(
        campaigns_module.shutil,
        "which",
        lambda name, *, path=None: "/usr/bin/tmux" if name == "tmux" else None,
    )
    monkeypatch.setattr(
        campaigns_module,
        "_probe_one_named_session",
        lambda _spec, *, tmux, screen: probe_result,
    )
    observed = load_engineering_campaign(results, route)
    campaigns_module._clear_named_session_liveness_cache()

    assert observed is not None and observed.state == expected_state
    assert detail_fragment in observed.state_detail
    if probe_result is True:
        assert observed.active_tasks == ("measured",)
        assert observed.status_tag == "running"
    else:
        assert observed.active_tasks == ("measured",)
        assert observed.status_tag == "unknown"


def test_jobs_date_window_pins_exact_live_old_controller_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "runs"
    now = time.time()
    old = now - 8 * 86400
    live_route = "controller-sequence-old-live"
    terminal_route = "controller-sequence-old-terminal"
    _engineering_campaign(
        results,
        live_route,
        started_at=old,
        session_fields=True,
        hard_stop_hours=720,
    )
    _engineering_campaign(
        results,
        terminal_route,
        started_at=old + 1,
        session_fields=False,
        terminal=True,
        hard_stop_hours=720,
    )
    campaigns_module._clear_named_session_liveness_cache()
    monkeypatch.setattr(
        campaigns_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    try:
        body = app.handle(
            "GET",
            f"/jobs?from_ms={int((now - 7 * 86400) * 1000)}"
            f"&to_ms={int((now + 1) * 1000)}",
        )[2].decode("utf-8")
    finally:
        app.close()
        campaigns_module._clear_named_session_liveness_cache()

    assert live_route in body
    assert terminal_route not in body
    live_at = body.index(live_route)
    live_row = body[body.rfind("<tr", 0, live_at) : body.find("</tr>", live_at)]
    assert "data-live-window-pin='true'" in live_row
    assert "currently live row remains visible" in body
    assert "Terminal history still obeys the selected dates" in body


def test_jobs_pins_exact_live_controller_behind_recent_directory_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "runs"
    now = time.time()
    old = now - 8 * 86400
    live_route = "controller-sequence-old-live-beyond-cap"
    terminal_route = "controller-sequence-old-terminal-beyond-cap"
    live_directory = _engineering_campaign(
        results,
        live_route,
        started_at=old,
        session_fields=True,
        hard_stop_hours=720,
    )
    terminal_directory = _engineering_campaign(
        results,
        terminal_route,
        started_at=old + 1,
        session_fields=True,
        terminal=True,
        hard_stop_hours=720,
    )
    os.utime(live_directory, (old, old))
    os.utime(terminal_directory, (old + 1, old + 1))

    # More than one complete display page of newer retained directories keeps
    # both old controllers outside the ordinary recent-directory selection.
    for index in range(campaigns_module._MAX_CAMPAIGNS + 2):
        directory = _engineering_campaign(
            results,
            f"controller-sequence-newer-terminal-{index:02d}",
            started_at=now - 120 + index,
            session_fields=False,
            terminal=True,
            hard_stop_hours=720,
        )
        directory_time = now - 120 + index
        os.utime(directory, (directory_time, directory_time))

    probed_routes: list[str] = []

    def exact_liveness(
        specs: list[campaigns_module._NamedSessionSpec],
    ) -> dict[campaigns_module._NamedSessionSpec, bool | None]:
        probed_routes.extend(spec.directory.name for spec in specs)
        return {spec: spec.directory.name == live_route for spec in specs}

    campaigns_module._clear_named_session_liveness_cache()
    monkeypatch.setattr(campaigns_module, "_named_session_liveness", exact_liveness)
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    try:
        body = app.handle(
            "GET",
            f"/jobs?from_ms={int((now - 7 * 86400) * 1000)}"
            f"&to_ms={int((now + 1) * 1000)}",
        )[2].decode("utf-8")
    finally:
        app.close()
        campaigns_module._clear_named_session_liveness_cache()

    # Mutation proof: limiting exact-session reconciliation to the newest 20
    # directories omits this route and fails both the probe and row assertions.
    assert probed_routes == [live_route]
    assert live_route in body
    live_at = body.index(live_route)
    live_row = body[body.rfind("<tr", 0, live_at) : body.find("</tr>", live_at)]
    assert "data-live-window-pin='true'" in live_row

    # A terminal controller never receives the live exception, even though it
    # also carries a syntactically valid exact-session identity.
    assert terminal_route not in body
