"""Rig Web's typed, non-job wrapper around the framework runtime installer."""

from __future__ import annotations

import json
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
    builder = page.index("<form method='post' action='/build' id='builder'>")
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
        stats_status, _kind, stats = app.handle("GET", "/stats")
    finally:
        app.close()
    assert jobs_status == stats_status == 200
    assert service.value.campaign_route_id.encode() in jobs
    assert b"engineering campaign" in jobs
    assert service.value.campaign_route_id.encode() in stats
    assert b"engineering / non-thesis" in stats
