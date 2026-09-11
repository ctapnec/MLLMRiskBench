"""Campaign ownership extends Build; it never creates a second builder."""

from __future__ import annotations

import json
import sqlite3
from html.parser import HTMLParser
from pathlib import Path

import pytest

from experiments.rig_web import Command, ConsoleDB, Job, RigWebApp


def _app(tmp_path: Path) -> RigWebApp:
    return RigWebApp(results_root=tmp_path / "runs", state_dir=tmp_path / "state", repo_root=tmp_path)


def test_workspace_migration_restart_and_reindex_preserve_explicit_ownership(tmp_path):
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as old:
        old.execute("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT)")
        old.execute("INSERT INTO meta VALUES('schema_version','4')")
    db = ConsoleDB(path)
    campaign = db.create_workspace("Local campaign", "local")
    db.attach_workspace_member(campaign, "external", "honest-tmux-origin", "collection")
    db.attach_workspace_member(campaign, "external", "honest-tmux-origin", "collection")
    assert db.reindex([], [])
    db.close()
    db = ConsoleDB(path)
    try:
        assert db.workspace(campaign)["name"] == "Local campaign"
        members = db.workspace_activity(campaign)
        assert len(members) == 1
        assert members[0]["member_kind"] == "external"
        assert members[0]["started_at"] is None  # registration is not a fake start
        assert db.load_jobs() == []
    finally:
        db.close()


def test_activity_cannot_silently_move_campaign_or_role(tmp_path):
    db = ConsoleDB(tmp_path / "state.db")
    try:
        a, b = (db.create_workspace(name, "api") for name in ("A", "B"))
        db.attach_workspace_member(a, "job", "j1", "collection")
        with pytest.raises(ValueError, match="already belongs"):
            db.attach_workspace_member(b, "job", "j1", "collection")
        with pytest.raises(ValueError, match="already belongs"):
            db.attach_workspace_member(a, "job", "j1", "judging")
        assert db.workspace_for_job("j1") == a
    finally:
        db.close()


class _Tags(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.tags = []
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def test_create_returns_to_existing_build_and_selector_belongs_to_its_form(tmp_path):
    app = _app(tmp_path)
    try:
        code, location, _ = app.handle("POST", "/campaigns", {"name": "API comparison", "kind": "api"})
        assert code == 303
        assert location.startswith("/build?campaign_id=")
        campaign = location.split("=", 1)[1]
        page = app.handle("GET", location)[2].decode()
        tags = _Tags(page).tags
        selectors = [attrs for tag, attrs in tags if tag == "select" and attrs.get("name") == "campaign_id"]
        assert selectors == [{"name": "campaign_id", "form": "builder"}]
        assert any(tag == "form" and attrs.get("id") == "builder" and attrs.get("action") == "/build" for tag, attrs in tags)
        assert f"value='{campaign}' selected" in page
        workspace = app.handle("GET", "/campaigns/" + campaign)[2].decode()
        assert "Configure in Build" in workspace
        assert "name='api'" not in workspace
        assert "Totals are unknown, not zero" in workspace
    finally:
        app.close()


def test_create_page_is_neutral_and_does_not_repeat_model_type_selection(tmp_path):
    app = _app(tmp_path)
    try:
        existing = app.db.create_workspace("API campaign", "api")
        code, _, body = app.handle("GET", "/campaigns/new")
        page = body.decode()
        assert code == 200
        assert "<h1>Create campaign</h1>" in page
        assert "API campaign" not in page
        assert "name='kind'" not in page
        assert "name='campaign_id'" not in page
        assert "action='/campaigns'" in page
        assert "class='card campaign-create-card'" in page
        assert "class='campaign-create-form'" in page
        assert "class='campaign-actions'" in page
        code, location, _ = app.handle("POST", "/campaigns", {
            "name": "Fresh comparison", "creation_flow": "name_then_build"})
        assert code == 303 and location.endswith("#build-general")
        new = location.split("=", 1)[1].split("#", 1)[0]
        assert new != existing
        assert app.db.workspace(new)["name"] == "Fresh comparison"
        assert app.db.workspace(new)["kind"] == "mixed"
        assert app.db.workspace(existing)["name"] == "API campaign"
        assert app.db.workspace_activity(new) == []
        assert app.db.load_jobs() == []
    finally:
        app.close()


def test_campaign_ownership_selector_links_to_separate_creation(tmp_path):
    app = _app(tmp_path)
    try:
        campaign = app.db.create_workspace("API campaign", "api")
        for selected in ("", campaign):
            page = app._campaign_selector(selected, form_id="builder")
            assert "Save under campaign" in page
            assert "No campaign - standalone job" in page
            assert "href='/campaigns/new'" in page
            assert "href='/campaigns#new-campaign'" not in page
            assert "Choose models in Build" in page
        index = app.handle("GET", "/campaigns")[2].decode()
        assert "API campaign" in index
        assert "name='kind'" not in index
        assert "action='/campaigns'" not in index
        assert "API campaign</p>" not in index
        assert "class='campaign-grid'" in index
    finally:
        app.close()


def test_review_ticket_keeps_campaign_despite_another_tab(tmp_path):
    app = _app(tmp_path)
    try:
        a, b = (app.db.create_workspace(name, "local") for name in ("A", "B"))
        params = {"mode": "dry_run", "campaign_id": a}
        token = app._new_launch_ticket(params)
        app.handle("GET", "/build?campaign_id=" + b)
        reviewed, _snapshot = app._consume_launch_ticket(token, purpose="build")
        assert reviewed["campaign_id"] == a
        without_owner = {k: v for k, v in params.items() if k != "campaign_id"}
        assert app._projection_params(params) == app._projection_params(without_owner)
        assert app._builder_params(params)["campaign_id"] == a
    finally:
        app.close()


def test_generic_launch_ownership_commits_before_process_without_cli_flag(tmp_path, monkeypatch):
    app = _app(tmp_path)
    app.commands["diagnostic"] = Command("diagnostic", "diagnostic", "test", ())
    campaign = app.db.create_workspace("Local campaign", "local")
    launched = []

    class Process:
        pid = 987654321

        def poll(self):
            return 0

    def popen(argv, **kwargs):
        members = app.db.workspace_activity(campaign)
        assert len(members) == 1, "ownership must commit before Popen"
        assert campaign not in argv
        assert "--campaign-id" not in argv
        launched.append(argv)
        return Process()

    monkeypatch.setattr("experiments.rig_web_app.lifecycle.subprocess.Popen", popen)
    try:
        status, location, _ = app.handle("POST", "/jobs", {"command": "diagnostic", "campaign_id": campaign})
        assert status == 303
        job_id = location.rsplit("/", 1)[1]
        assert len(launched) == 1
        assert app.db.workspace_for_job(job_id) == campaign
        command = json.loads((app.state_dir / job_id / "command.json").read_text())
        assert command["campaign_id"] == campaign
        assert app.db.load_job(job_id) is not None
    finally:
        app.close()


def test_unknown_campaign_never_launches(tmp_path, monkeypatch):
    app = _app(tmp_path)
    monkeypatch.setattr("experiments.rig_web_app.lifecycle.subprocess.Popen", lambda *a, **k: pytest.fail("must not launch"))
    try:
        with pytest.raises(ValueError, match="Campaign is unavailable"):
            app.start_job("rig_check", {}, campaign_id="a" * 32)
        assert not app.jobs
    finally:
        app.close()


def test_activity_is_paginated_and_keeps_failed_process_status(tmp_path):
    app = _app(tmp_path)
    try:
        campaign = app.db.create_workspace("API", "api")
        for n in range(52):
            job = Job(job_id=f"j-{n}", command="run_matrix", argv=[], directory=app.state_dir / str(n), restored_state="failed", restored_exit=1)
            app.db.upsert_job(job)
            app.db.attach_workspace_member(campaign, "job", job.job_id, "collection")
        page = app.handle("GET", f"/campaigns/{campaign}?section=activity")[2].decode()
        assert page.count("<td>failed</td>") == 50
        assert "Next</a>" in page
        next_page = app.handle("GET", f"/campaigns/{campaign}?section=activity&page=1")[2].decode()
        assert next_page.count("<td>failed</td>") == 2
        assert "Previous</a>" in next_page
    finally:
        app.close()


def test_workspace_html_escapes_operator_names(tmp_path):
    app = _app(tmp_path)
    try:
        campaign = app.db.create_workspace("<script>not markup</script>", "mixed")
        page = app.handle("GET", "/campaigns/" + campaign)[2].decode()
        assert "<script>not markup" not in page
        assert "&lt;script&gt;not markup" in page
    finally:
        app.close()
