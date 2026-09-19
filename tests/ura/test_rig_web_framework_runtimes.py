"""Rig Web's typed, non-job wrapper around the framework runtime installer."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app.framework_runtimes import (
    DispatchResult,
    FrameworkRuntimeConflict,
    FrameworkRuntimeLaunch,
    FrameworkRuntimeRow,
    FrameworkRuntimeService,
    FrameworkRuntimeSnapshot,
    RuntimeAttempt,
)
from experiments.rig_web_app.server import _parse_form_payload


class _FakeRuntimeService:
    def __init__(self, snapshot: FrameworkRuntimeSnapshot) -> None:
        self.value = snapshot
        self.calls: list[tuple[str, str]] = []
        self.failure: Exception | None = None

    def snapshot(self) -> FrameworkRuntimeSnapshot:
        return self.value

    def launch(self, framework: str, action: str) -> FrameworkRuntimeLaunch:
        self.calls.append((framework, action))
        if self.failure is not None:
            raise self.failure
        return FrameworkRuntimeLaunch("tmux", "ura-framework-install-test", self.value.campaign_route_id)


def _snapshot() -> FrameworkRuntimeSnapshot:
    return FrameworkRuntimeSnapshot(
        available=True,
        message="",
        lock_id="a" * 64,
        campaign_route_id="framework-runtime-aaaaaaaaaaaa",
        campaign_state="complete",
        campaign_status_tag="partial",
        rows=(
            FrameworkRuntimeRow(
                "deepteam",
                "DeepTeam",
                "1.0.7",
                "python",
                "runner bridge",
                "install",
                None,
            ),
            FrameworkRuntimeRow(
                "pyrit",
                "PyRIT",
                "0.14.0",
                "python",
                "runner bridge",
                "verify",
                RuntimeAttempt("verify", "passed", "2026-08-18T18:00:00Z", "verified"),
            ),
            FrameworkRuntimeRow(
                "h4rm3l",
                "h4rm3l",
                "0.2.4",
                "python",
                "runner bridge",
                "resume",
                RuntimeAttempt("install", "failed", "2026-08-18T17:00:00Z", "InstallerError"),
            ),
            FrameworkRuntimeRow(
                "blocked",
                "Blocked example",
                "1.0.0",
                "python",
                "tool runtime",
                "blocked-existing-unverified",
                None,
            ),
        ),
    )


def _app(tmp_path: Path, service: _FakeRuntimeService) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir()
    return RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        framework_runtime_service=service,
        gpu_hardware={"available": False, "gpus": [], "gpu_count": 0},
        system_hardware={"cpu_model": "test", "total_ram_gib": 8, "platform": "test"},
    )


def test_capture_binding_paths_follow_the_checked_in_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    experiments = repo / "experiments"
    experiments.mkdir(parents=True)
    lock_path = experiments / "framework_runtime_lock.json"
    lock_path.write_text("{}\n", encoding="utf-8")
    results = tmp_path / "runs"
    results.mkdir()
    monkeypatch.setattr(
        "experiments.rig_web_app.framework_runtimes.load_lock",
        lambda path: {"lock_id": "a" * 64} if path == lock_path else None,
    )
    service = FrameworkRuntimeService(
        repo_root=repo,
        results_root=results,
        state_dir=tmp_path / "state",
    )

    assert service.capture_binding_paths() == (
        lock_path,
        tmp_path / "framework-venvs",
        results / "engineering" / "framework-runtime-aaaaaaaaaaaa",
    )


def test_runtime_tab_is_outside_builder_and_has_one_action_per_row(tmp_path: Path) -> None:
    service = _FakeRuntimeService(_snapshot())
    app = _app(tmp_path, service)
    try:
        status, _content_type, body = app.handle("GET", "/build")
    finally:
        app.close()
    assert status == 200
    page = body.decode("utf-8")
    general = page.index("data-page-panel='build-general'")
    runtimes = page.index("data-page-panel='build-runtimes'")
    builder = page.index("<form method='post' action='/build/review' id='builder'>")
    pipeline = page.index("data-page-panel='build-pipeline'")
    assert general < runtimes < builder < pipeline
    runtime_html = page[runtimes:builder]
    assert runtime_html.count("action='/build/framework-runtimes'") == 3
    assert runtime_html.count("name='framework'") == 3
    assert runtime_html.count("name='action'") == 3
    assert "type='checkbox'" not in runtime_html
    assert "<select" not in runtime_html
    assert "Published receipt present" in runtime_html
    assert "Last full verification passed" in runtime_html
    assert "Current bytes are not implicitly rehashed" in runtime_html
    assert "Conflicting unverified path" in runtime_html
    assert "manual repair required" in runtime_html
    assert len(set(
        part.split("'", 1)[0]
        for part in runtime_html.split("id='framework-runtime-action-")[1:]
    )) == 3
    assert str(tmp_path) not in runtime_html


def test_runtime_post_is_exact_and_does_not_create_console_job(tmp_path: Path) -> None:
    service = _FakeRuntimeService(_snapshot())
    app = _app(tmp_path, service)
    try:
        status, location, body = app.handle(
            "POST",
            "/build/framework-runtimes",
            {"framework": "deepteam", "action": "install"},
        )
        assert (status, body) == (303, b"")
        assert location == "/build?framework_runtime_state=launched#build-runtimes"
        assert service.calls == [("deepteam", "install")]
        assert app.jobs == {}

        for malformed in (
            {},
            {"framework": "deepteam"},
            {"framework": "deepteam", "action": "install", "path": "/tmp/x"},
            {"framework": "deepteam", "action": "shell"},
            {"framework": "deepteam", "action": "adopt"},
            {"framework": "../deepteam", "action": "install"},
        ):
            rejected, _kind, rejected_body = app.handle(
                "POST", "/build/framework-runtimes", malformed
            )
            assert rejected == 400
            assert b"Runtime action was not launched" in rejected_body
        assert service.calls == [("deepteam", "install")]
        assert app.jobs == {}
    finally:
        app.close()


def test_stale_running_event_does_not_override_the_current_plan(tmp_path: Path) -> None:
    snapshot = _snapshot()
    rows = list(snapshot.rows)
    rows[0] = replace(
        rows[0],
        latest=RuntimeAttempt("install", "running", "2026-08-18T19:00:00Z", ""),
    )
    service = _FakeRuntimeService(
        replace(
            snapshot,
            campaign_state="running",
            campaign_status_tag="running",
            rows=tuple(rows),
        )
    )
    app = _app(tmp_path, service)
    try:
        status, _kind, body = app.handle("GET", "/build#build-runtimes")
    finally:
        app.close()
    assert status == 200
    runtime_html = body.decode("utf-8").split("data-page-panel='build-runtimes'", 1)[1]
    runtime_html = runtime_html.split("<form method='post' action='/build' id='builder'>", 1)[0]
    assert runtime_html.count("action='/build/framework-runtimes'") == 3
    assert "Install running" in runtime_html
    assert "retained task log has no terminal event" in runtime_html
    assert "dispatch safely rejoins an identical live named session" in runtime_html


@pytest.mark.parametrize(
    ("campaign_state", "campaign_status", "expected_tone"),
    (
        ("orphaned", "orphaned", "amber"),
        ("unknown", "unknown", "amber"),
        ("failed", "failed", "red"),
        ("complete", "partial", "amber"),
    ),
)
def test_reconciled_campaign_state_overrides_stale_running_runtime_event(
    tmp_path: Path,
    campaign_state: str,
    campaign_status: str,
    expected_tone: str,
) -> None:
    snapshot = _snapshot()
    rows = list(snapshot.rows)
    rows[0] = replace(
        rows[0],
        latest=RuntimeAttempt("install", "running", "2026-08-18T19:00:00Z", ""),
    )
    service = _FakeRuntimeService(
        replace(
            snapshot,
            campaign_state=campaign_state,
            campaign_status_tag=campaign_status,
            rows=tuple(rows),
        )
    )
    app = _app(tmp_path, service)
    try:
        status, _kind, body = app.handle("GET", "/build#build-runtimes")
    finally:
        app.close()

    assert status == 200
    runtime_html = body.decode("utf-8").split(
        "data-page-panel='build-runtimes'", 1
    )[1]
    runtime_html = runtime_html.split(
        "<form method='post' action='/build' id='builder'>", 1
    )[0]
    assert "Install running" not in runtime_html
    assert (
        f"<span class='badge {expected_tone}'>Install {campaign_status}</span>"
        in runtime_html
    )
    assert "this action is not reported as live" in runtime_html
    assert "The exact current plan remains authoritative" in runtime_html


def test_service_dispatches_current_plan_despite_stale_running_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    (repo / "experiments" / "framework_runtime_installer.py").write_text(
        "# test\n", encoding="utf-8"
    )
    (repo / "experiments" / "framework_runtime_lock.json").write_text(
        "{}\n", encoding="utf-8"
    )
    results = tmp_path / "runs"
    results.mkdir()
    app_python = tmp_path / "app-python"
    base_python = tmp_path / "base-python"
    app_python.write_bytes(b"python")
    base_python.write_bytes(b"python")
    dispatched = 0

    def dispatch(_argv, _environment, _cwd):
        nonlocal dispatched
        dispatched += 1
        return DispatchResult(
            0,
            json.dumps({
                "schema": "ura-framework-runtime-session/1",
                "launcher": "tmux",
                "session_name": "ura-framework-install-stale",
                "attach_command": "tmux attach -t ura-framework-install-stale",
                "log": "sessions/stale.log",
                "exit_marker": "sessions/stale.exit",
                "status": "running",
            }),
            "",
        )

    service = FrameworkRuntimeService(
        repo_root=repo,
        results_root=results,
        state_dir=tmp_path / "state",
        dispatcher=dispatch,
        app_python=app_python,
        base_python=base_python,
    )
    stale = FrameworkRuntimeSnapshot(
        available=True,
        message="",
        lock_id="d" * 64,
        campaign_route_id="framework-runtime-dddddddddddd",
        campaign_state="running",
        campaign_status_tag="running",
        rows=(FrameworkRuntimeRow(
            "deepteam",
            "DeepTeam",
            "1.0.7",
            "python",
            "runner bridge",
            "install",
            RuntimeAttempt("install", "running", "2026-08-18T18:00:00Z", ""),
        ),),
    )
    monkeypatch.setattr(service, "snapshot", lambda: stale)
    launched = service.launch("deepteam", "install")
    assert launched.session_name == "ura-framework-install-stale"
    assert dispatched == 1


def test_runtime_post_reports_stale_plan_without_launching_job(tmp_path: Path) -> None:
    service = _FakeRuntimeService(_snapshot())
    service.failure = FrameworkRuntimeConflict(
        "the current plan requires verify, not install"
    )
    app = _app(tmp_path, service)
    try:
        status, _kind, body = app.handle(
            "POST",
            "/build/framework-runtimes",
            {"framework": "pyrit", "action": "install"},
        )
        assert status == 409
        assert b"current plan requires verify" in body
        assert b"data-default-tab='build-runtimes'" in body
        assert app.jobs == {}
    finally:
        app.close()


def test_http_parser_rejects_duplicate_runtime_meanings() -> None:
    with pytest.raises(ValueError, match="duplicate URL-encoded form field name"):
        _parse_form_payload(b"framework=deepteam&framework=pyrit&action=install")


def test_service_dispatches_fixed_paths_and_credential_free_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import framework_runtimes as module

    repo = tmp_path / "checkout"
    (repo / "experiments").mkdir(parents=True)
    installer = repo / "experiments" / "framework_runtime_installer.py"
    lock_path = repo / "experiments" / "framework_runtime_lock.json"
    installer.write_text("# test installer\n", encoding="utf-8")
    lock_path.write_text("{}\n", encoding="utf-8")
    results = tmp_path / "work" / "runs"
    results.mkdir(parents=True)
    state = tmp_path / "web-state"
    state.mkdir()
    app_python = tmp_path / "app-python"
    base_python = tmp_path / "base-python"
    app_python.write_bytes(b"python")
    base_python.write_bytes(b"python")
    lock = {
        "lock_id": "b" * 64,
        "frameworks": [
            {
                "name": "deepteam",
                "canonical_name": "DeepTeam",
                "version": "1.0.7",
                "runtime": "python",
                "kind": "runner bridge",
            }
        ],
    }
    monkeypatch.setattr(module, "load_lock", lambda _path: lock)
    monkeypatch.setattr(module, "select_frameworks", lambda value, _only: value["frameworks"])
    monkeypatch.setattr(
        module,
        "plan",
        lambda _lock, _layout, _entries: {
            "actions": [{"framework": "deepteam", "action": "install"}]
        },
    )
    captured: dict[str, object] = {}

    def dispatch(argv, environment, cwd):
        captured.update(argv=list(argv), environment=dict(environment), cwd=cwd)
        return DispatchResult(
            0,
            json.dumps({
                "schema": "ura-framework-runtime-session/1",
                "launcher": "tmux",
                "session_name": "ura-framework-install-test",
                "attach_command": "tmux attach -t ura-framework-install-test",
                "log": "sessions/test.log",
                "exit_marker": "sessions/test.exit",
                "status": "running",
            }),
            "",
        )

    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setenv("HF_TOKEN", "must-not-pass")
    monkeypatch.setenv("TMUX", "must-not-inherit-parent-session")
    monkeypatch.setenv("STY", "must-not-inherit-screen")
    service = FrameworkRuntimeService(
        repo_root=repo,
        results_root=results,
        state_dir=state,
        dispatcher=dispatch,
        app_python=app_python,
        base_python=base_python,
    )
    launched = service.launch("deepteam", "install")
    assert launched == FrameworkRuntimeLaunch(
        "tmux", "ura-framework-install-test", "framework-runtime-bbbbbbbbbbbb"
    )
    argv = captured["argv"]
    assert argv[:4] == [str(app_python.resolve()), "-I", "-B", str(installer.resolve())]
    assert argv[4] == "install"
    assert argv[argv.index("--env-root") + 1] == str(results.parent / "framework-venvs")
    assert argv[argv.index("--state-root") + 1] == str(
        results / "engineering" / "framework-runtime-bbbbbbbbbbbb"
    )
    assert argv[argv.index("--only") + 1] == "deepteam"
    assert argv[argv.index("--python") + 1] == str(base_python.resolve())
    assert captured["cwd"] == repo
    environment = captured["environment"]
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PIP_CONFIG_FILE",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_NO_INPUT",
        "PYTHONDONTWRITEBYTECODE",
    }
    assert "must-not-pass" not in json.dumps(environment)
    assert "TMUX" not in environment and "STY" not in environment


def test_service_requires_current_plan_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import framework_runtimes as module

    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    (repo / "experiments" / "framework_runtime_installer.py").write_text(
        "# test\n", encoding="utf-8"
    )
    (repo / "experiments" / "framework_runtime_lock.json").write_text("{}", encoding="utf-8")
    results = tmp_path / "runs"
    results.mkdir()
    lock = {
        "lock_id": "c" * 64,
        "frameworks": [{
            "name": "pyrit",
            "canonical_name": "PyRIT",
            "version": "0.14.0",
            "runtime": "python",
            "kind": "runner bridge",
        }],
    }
    monkeypatch.setattr(module, "load_lock", lambda _path: lock)
    monkeypatch.setattr(module, "select_frameworks", lambda value, _only: value["frameworks"])
    monkeypatch.setattr(
        module,
        "plan",
        lambda *_args: {"actions": [{"framework": "pyrit", "action": "verify"}]},
    )
    dispatched = False

    def dispatch(_argv, _environment, _cwd):
        nonlocal dispatched
        dispatched = True
        raise AssertionError("must not dispatch a stale action")

    service = FrameworkRuntimeService(
        repo_root=repo,
        results_root=results,
        state_dir=tmp_path / "state",
        dispatcher=dispatch,
    )
    with pytest.raises(FrameworkRuntimeConflict, match="requires verify"):
        service.launch("pyrit", "install")
    assert dispatched is False


def test_installer_campaign_is_visible_in_jobs_and_stats(tmp_path: Path) -> None:
    service = _FakeRuntimeService(_snapshot())
    app = _app(tmp_path, service)
    campaign = app.results_root / "engineering" / service.value.campaign_route_id
    campaign.mkdir(parents=True)
    (campaign / "ENGINEERING_ONLY.json").write_text(
        json.dumps({
            "schema": "ura-engineering-campaign/1",
            "campaign_id": service.value.campaign_route_id,
            "evidence_class": "framework_runtime_setup",
            "thesis_empirical_evidence": False,
            "hosted_calls_allowed": False,
            "target_call_cap": 0,
            "hard_stop_hours": 168,
            "started_at": "2026-08-18T18:00:00Z",
            "planned_tasks": ["framework-runtime-deepteam"],
            "model_tasks": [],
            "runtime_lock_id": "a" * 64,
        })
        + "\n",
        encoding="utf-8",
    )
    events = (
        {"at": "2026-08-18T18:00:00Z", "event": "campaign_start", "task": "bootstrap", "status": "running"},
        {"at": "2026-08-18T18:00:01Z", "event": "task_start", "task": "framework-runtime-deepteam", "status": "running", "detail": "install"},
        {"at": "2026-08-18T18:00:02Z", "event": "task_end", "task": "framework-runtime-deepteam", "status": "passed", "detail": "installed"},
        {"at": "2026-08-18T18:00:03Z", "event": "campaign_end", "task": "bootstrap", "status": "passed", "detail": "framework-runtime-installer"},
    )
    (campaign / "task-log.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in events), encoding="utf-8"
    )
    try:
        jobs_status, _kind, jobs = app.handle(
            "GET", "/jobs?from=2026-08-18T00:00:00&to=2026-08-19T00:00:00"
        )
        stats_status, _kind, stats = app.handle("GET", "/stats?view=legacy")
    finally:
        app.close()
    assert jobs_status == stats_status == 200
    assert service.value.campaign_route_id.encode() in jobs
    assert b"engineering campaign" in jobs
    assert service.value.campaign_route_id.encode() in stats
    assert b"engineering / non-thesis" in stats


@pytest.mark.parametrize(
    ("session_returncode", "age_hours", "expected_state", "expected_tone", "detail_fragment"),
    (
        (0, 1, "running", "blue", ""),
        (1, 1, "orphaned", "amber", "named session is no longer live"),
        (0, 169, "running", "blue", "hard stop exceeded"),
    ),
)
def test_installer_campaign_uses_its_exact_named_session_liveness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session_returncode: int,
    age_hours: int,
    expected_state: str,
    expected_tone: str,
    detail_fragment: str,
) -> None:
    from experiments.rig_web_app import campaigns as campaigns_module

    service = _FakeRuntimeService(_snapshot())
    app = _app(tmp_path, service)
    lock_id = "b" * 64
    route = f"framework-runtime-{lock_id[:12]}"
    campaign = app.results_root / "engineering" / route
    sessions = campaign / "sessions"
    sessions.mkdir(parents=True)
    started_epoch = time.time() - age_hours * 3600

    def timestamp(value: float) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value))

    (campaign / "ENGINEERING_ONLY.json").write_text(
        json.dumps({
            "schema": "ura-engineering-campaign/1",
            "campaign_id": route,
            "evidence_class": "framework_runtime_setup",
            "thesis_empirical_evidence": False,
            "hosted_calls_allowed": False,
            "target_call_cap": 0,
            "hard_stop_hours": 168,
            "started_at": timestamp(started_epoch),
            "planned_tasks": ["framework-runtime-autodan"],
            "model_tasks": [],
            "runtime_lock_id": lock_id,
        })
        + "\n",
        encoding="utf-8",
    )
    (campaign / "task-log.jsonl").write_text(
        "".join(
            json.dumps(row) + "\n"
            for row in (
                {
                    "at": timestamp(started_epoch),
                    "event": "campaign_start",
                    "task": "bootstrap",
                    "status": "running",
                },
                {
                    "at": timestamp(started_epoch + 1),
                    "event": "task_start",
                    "task": "framework-runtime-autodan",
                    "status": "running",
                    "detail": "install",
                },
            )
        ),
        encoding="utf-8",
    )
    session = "ura-framework-install-bbbbbbbb-e90e4460-433f927906"
    log = sessions / f"{session}.log"
    log.write_text("[command] executable=python argc=17 cwd=default\n", encoding="utf-8")
    (sessions / f"{session}.home").mkdir()
    os.utime(log, (started_epoch - 1, started_epoch - 1))

    probes: list[list[str]] = []

    def which(name: str, *, path: str | None = None) -> str | None:
        assert path == os.defpath
        return "/usr/bin/tmux" if name == "tmux" else None

    def run(argv: list[str], **_kwargs: object) -> object:
        probes.append(argv)
        return campaigns_module.subprocess.CompletedProcess(argv, session_returncode)

    monkeypatch.setattr(campaigns_module.shutil, "which", which)
    monkeypatch.setattr(campaigns_module.subprocess, "run", run)
    try:
        observed = app._engineering_campaign(route)
        assert observed is not None
        jobs = app.handle(
            "GET",
            f"/jobs?from_ms={int((started_epoch - 10) * 1000)}"
            f"&to_ms={int((time.time() + 10) * 1000)}",
        )[2].decode("utf-8")
        detail = app.handle("GET", f"/jobs/campaign/{route}")[2].decode("utf-8")
    finally:
        app.close()

    socket = f"ura-fw-{hashlib.sha256(session.encode('ascii')).hexdigest()[:16]}"
    assert probes
    assert all(
        probe == ["/usr/bin/tmux", "-L", socket, "has-session", "-t", session]
        for probe in probes
    )
    assert observed.state == expected_state
    assert observed.status_tag == expected_state
    assert f"<span class='badge {expected_tone}'>{expected_state}</span>" in jobs
    assert f"<span class='dot {expected_tone}'></span>{expected_state}" in detail
    if expected_state == "orphaned":
        assert observed.active_tasks == ()
        assert observed.task_outcomes == (
            ("framework-runtime-autodan", "interrupted", "support"),
        )
    else:
        assert observed.active_tasks == ("framework-runtime-autodan",)
    if detail_fragment:
        assert detail_fragment in observed.state_detail
        assert detail_fragment in detail
    else:
        assert observed.state_detail == ""


def test_installer_campaign_observes_newer_adopt_session_not_prior_verify(
    tmp_path: Path,
) -> None:
    from experiments.rig_web_app.campaigns import _framework_named_session_spec

    lock_id = "c" * 64
    route = f"framework-runtime-{lock_id[:12]}"
    campaign = tmp_path / route
    sessions = campaign / "sessions"
    sessions.mkdir(parents=True)
    started_epoch = time.time() - 60
    prior = "ura-framework-verify-cccccccc-e90e4460-1111111111"
    current = "ura-framework-adopt-cccccccc-e90e4460-2222222222"
    for session, modified in (
        (prior, started_epoch + 1),
        (current, started_epoch + 2),
    ):
        log = sessions / f"{session}.log"
        log.write_text(
            "[command] executable=python argc=17 cwd=default\n", encoding="utf-8"
        )
        (sessions / f"{session}.home").mkdir()
        os.utime(log, (modified, modified))

    observed = _framework_named_session_spec(
        campaign,
        {
            "campaign_id": route,
            "evidence_class": "framework_runtime_setup",
            "model_tasks": [],
            "runtime_lock_id": lock_id,
            "target_call_cap": 0,
        },
        started_at=started_epoch,
    )
    socket = f"ura-fw-{hashlib.sha256(current.encode('ascii')).hexdigest()[:16]}"
    assert observed is not None
    assert (observed.launcher, observed.socket, observed.session) == (
        "auto",
        socket,
        current,
    )


def test_adopt_task_completion_replaces_prior_verify_but_is_not_launchable(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "campaign"
    state_root.mkdir()
    events = (
        {
            "at": "2026-08-20T10:00:00Z",
            "event": "task_start",
            "task": "framework-runtime-pyrit",
            "status": "running",
            "detail": "verify",
        },
        {
            "at": "2026-08-20T10:00:01Z",
            "event": "task_end",
            "task": "framework-runtime-pyrit",
            "status": "passed",
            "detail": "verified",
        },
        {
            "at": "2026-08-20T10:01:00Z",
            "event": "task_start",
            "task": "framework-runtime-pyrit",
            "status": "running",
            "detail": "adopt",
        },
        {
            "at": "2026-08-20T10:01:01Z",
            "event": "task_end",
            "task": "framework-runtime-pyrit",
            "status": "passed",
            "detail": "adopted-verified",
        },
    )
    (state_root / "task-log.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in events), encoding="utf-8"
    )
    latest = FrameworkRuntimeService._latest_attempts(state_root)
    assert latest == {
        "pyrit": RuntimeAttempt(
            "adopt", "passed", "2026-08-20T10:01:01Z", "adopted-verified"
        )
    }

    service = _FakeRuntimeService(
        replace(
            _snapshot(),
            rows=(replace(_snapshot().rows[1], latest=latest["pyrit"]),),
        )
    )
    app = _app(tmp_path, service)
    try:
        status, _kind, body = app.handle("GET", "/build#build-runtimes")
        rejected, _kind, rejected_body = app.handle(
            "POST",
            "/build/framework-runtimes",
            {"framework": "pyrit", "action": "adopt"},
        )
    finally:
        app.close()

    runtime_html = body.decode("utf-8").split(
        "data-page-panel='build-runtimes'", 1
    )[1]
    runtime_html = runtime_html.split(
        "<form method='post' action='/build' id='builder'>", 1
    )[0]
    assert status == 200
    assert "Runtime adoption and verification passed" in runtime_html
    assert "name='action' value='verify'" in runtime_html
    assert "name='action' value='adopt'" not in runtime_html
    assert rejected == 400
    assert b"Runtime action was not launched" in rejected_body
    assert service.calls == []


# --------------------------------------------------------------------------- #
# Integration: the REAL checked-in lock + the real installer plan() + a real
# retained task-log.jsonl, on a temporary empty env-root/state-root (plan only;
# nothing is installed).
# --------------------------------------------------------------------------- #


def _real_lock() -> tuple[Path, dict]:
    from experiments.framework_runtime_installer import DEFAULT_LOCK, load_lock

    return Path(__file__).resolve().parents[2], load_lock(DEFAULT_LOCK)


def test_snapshot_plans_every_real_lock_entry_and_parses_the_retained_task_log(
    tmp_path: Path,
) -> None:
    repo, lock = _real_lock()
    lock_id = lock["lock_id"]
    route = f"framework-runtime-{lock_id[:12]}"
    results = tmp_path / "work" / "runs"
    results.mkdir(parents=True)
    state_root = results / "engineering" / route
    state_root.mkdir(parents=True)
    events = (
        {"at": "2026-08-20T10:00:00Z", "event": "campaign_start", "task": "bootstrap", "status": "running", "detail": "framework-runtime-install"},
        {"at": "2026-08-20T10:00:01Z", "event": "task_start", "task": "framework-runtime-pyrit", "status": "running", "detail": "install"},
        {"at": "2026-08-20T10:05:00Z", "event": "task_end", "task": "framework-runtime-pyrit", "status": "passed", "detail": "installed"},
        {"at": "2026-08-20T10:05:01Z", "event": "task_start", "task": "framework-runtime-garak", "status": "running", "detail": "install"},
        {"at": "2026-08-20T10:06:00Z", "event": "task_end", "task": "framework-runtime-garak", "status": "failed", "detail": "InstallerError"},
        {"at": "2026-08-20T10:06:01Z", "event": "task_start", "task": "framework-runtime-deepteam", "status": "running", "detail": "verify"},
        # ignored: not an installer task, an unsafe framework token, a non-action detail
        {"at": "2026-08-20T10:06:02Z", "event": "task_start", "task": "native-demo", "status": "running", "detail": "install"},
        {"at": "2026-08-20T10:06:03Z", "event": "task_start", "task": "framework-runtime-../evil", "status": "running", "detail": "install"},
        {"at": "2026-08-20T10:06:04Z", "event": "task_start", "task": "framework-runtime-spikee", "status": "running", "detail": "shell"},
    )
    partial = '{"at":"2026-08-20T10:07:00Z","event":"task_end","task":"framework-runtime-deepteam","status":"passed"'
    (state_root / "task-log.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in events) + partial, encoding="utf-8"
    )
    service = FrameworkRuntimeService(
        repo_root=repo, results_root=results, state_dir=tmp_path / "state"
    )
    snapshot = service.snapshot()
    assert snapshot.available, snapshot.message
    assert snapshot.lock_id == lock_id
    assert snapshot.campaign_route_id == route
    assert (snapshot.campaign_state, snapshot.campaign_status_tag) == ("idle", "not started")
    assert [row.framework for row in snapshot.rows] == [entry["name"] for entry in lock["frameworks"]]
    assert len(snapshot.rows) == 16
    assert all(row.plan_action == "install" for row in snapshot.rows)
    assert {row.runtime for row in snapshot.rows} == {"python", "node"}
    latest = {row.framework: row.latest for row in snapshot.rows}
    assert latest["pyrit"] == RuntimeAttempt("install", "passed", "2026-08-20T10:05:00Z", "installed")
    assert latest["garak"] == RuntimeAttempt("install", "failed", "2026-08-20T10:06:00Z", "InstallerError")
    # the partial trailing line is not a terminal event
    assert latest["deepteam"] == RuntimeAttempt("verify", "running", "2026-08-20T10:06:01Z", "")
    assert latest["spikee"] is None
    assert all(latest[name] is None for name in ("h4rm3l", "promptfoo", "harmbench"))
    assert str(tmp_path) not in json.dumps([row.__dict__ for row in snapshot.rows], default=str)

    # the web gate rests on that real plan: a non-current action is refused ...
    with pytest.raises(FrameworkRuntimeConflict, match="requires install, not verify"):
        service.launch("pyrit", "verify")

    # ... and the current one is dispatched with the real lock and derived roots
    captured: dict[str, object] = {}

    def dispatch(argv, environment, cwd):
        captured.update(argv=list(argv), environment=dict(environment), cwd=cwd)
        return DispatchResult(
            0,
            json.dumps({
                "schema": "ura-framework-runtime-session/1",
                "launcher": "tmux",
                "session_name": "ura-framework-install-real",
                "attach_command": "tmux -L x attach -t ura-framework-install-real",
                "log": "sessions/ura-framework-install-real.log",
                "exit_marker": "sessions/ura-framework-install-real.exit",
                "status": "running",
            }),
            "",
        )

    dispatching = FrameworkRuntimeService(
        repo_root=repo,
        results_root=results,
        state_dir=tmp_path / "state",
        dispatcher=dispatch,
        app_python=Path(sys.executable),
        base_python=Path(sys.executable),
    )
    launched = dispatching.launch("promptfoo", "install")
    assert launched == FrameworkRuntimeLaunch("tmux", "ura-framework-install-real", route)
    argv = captured["argv"]
    assert argv[4] == "install"
    assert argv[argv.index("--lock") + 1] == str(
        (repo / "experiments" / "framework_runtime_lock.json").resolve()
    )
    assert argv[argv.index("--env-root") + 1] == str(results.resolve().parent / "framework-venvs")
    assert argv[argv.index("--state-root") + 1] == str(results.resolve() / "engineering" / route)
    assert argv[argv.index("--only") + 1] == "promptfoo"
    assert "--python" not in argv  # Promptfoo and T3MP3ST are Node runtimes
    assert captured["cwd"] == repo


def test_snapshot_ignores_an_oversized_or_linked_task_log(tmp_path: Path) -> None:
    repo, lock = _real_lock()
    route = f"framework-runtime-{lock['lock_id'][:12]}"
    results = tmp_path / "work" / "runs"
    state_root = results / "engineering" / route
    state_root.mkdir(parents=True)
    event = json.dumps({
        "at": "2026-08-20T10:00:01Z",
        "event": "task_start",
        "task": "framework-runtime-pyrit",
        "status": "running",
        "detail": "install",
    }) + "\n"
    log = state_root / "task-log.jsonl"
    log.write_text(event * (512 * 1024 // len(event) + 2), encoding="utf-8")
    assert log.stat().st_size > 512 * 1024
    service = FrameworkRuntimeService(
        repo_root=repo, results_root=results, state_dir=tmp_path / "state"
    )
    snapshot = service.snapshot()
    assert snapshot.available
    assert all(row.latest is None for row in snapshot.rows)
    assert all(row.plan_action == "install" for row in snapshot.rows)

    log.unlink()
    external = tmp_path / "external.jsonl"
    external.write_text(event, encoding="utf-8")
    if not hasattr(os, "symlink"):
        return
    try:
        log.symlink_to(external)
    except OSError:
        return
    linked = service.snapshot()
    assert linked.available
    assert all(row.latest is None for row in linked.rows)
