"""One Build editor, persistent campaign definitions, separate execution scopes."""

import time

import pytest

from experiments.rig_web import Job, RigWebApp


def app_at(tmp_path):
    return RigWebApp(results_root=tmp_path / "runs", state_dir=tmp_path / "state", repo_root=tmp_path)


def test_save_reopen_campaign_keeps_pipeline_and_never_launches(tmp_path, monkeypatch):
    app = app_at(tmp_path)
    monkeypatch.setattr(app, "start_job", lambda *a, **k: pytest.fail("draft must not execute"))
    fields = {"work_kind": "campaign", "campaign_name": "Matched comparison", "mode": "dry_run",
        "local": "ollama:model-a,ollama:model-b", "corpora": "advbench_harmful,xstest_full",
        "attackers": "replay", "judges": "rules,llm", "judge_model": "mock", "seeds": "0,1",
        "limit": "10", "sample_seed": "7", "target_answer_retries": "1", "out": "runs/comparison"}
    try:
        code, location, _ = app.handle("POST", "/build/save", fields)
        assert code == 303
        campaign = location.split("/campaigns/")[1].split("?")[0]
        saved = app.db.workspace_definition(campaign)
        assert saved == {**{k: v for k, v in fields.items() if k != "campaign_name"}, "campaign_id": campaign}
        assert not app.jobs and app.db.workspace_activity(campaign) == []
        page = app.handle("GET", "/build?campaign_id=" + campaign)[2].decode()
        assert '"ollama:model-a", "ollama:model-b"' in page
        assert "value='0,1'" in page and "value='7'" in page
        assert "data-tab-key='build-" + campaign in page
        assert "Matched comparison" in page
        assert app.db.reindex([], [])
    finally:
        app.close()
    app = app_at(tmp_path)
    try:
        assert app.db.workspace_definition(campaign) == saved
    finally:
        app.close()


def test_editing_draft_does_not_change_reviewed_launch_or_projection(tmp_path):
    app = app_at(tmp_path)
    try:
        old = app._save_build_campaign(app._builder_params({"work_kind": "campaign", "campaign_name": "A",
            "mode": "dry_run", "seeds": "0", "corpora": "advbench_harmful"}))
        token = app._new_launch_ticket(old)
        app._save_build_campaign({**old, "seeds": "17"})
        reviewed, _ = app._consume_launch_ticket(token)
        assert reviewed["seeds"] == "0"
        assert app.db.workspace_definition(old["campaign_id"])["seeds"] == "17"
        single = app._builder_params({**old, "work_kind": "run", "campaign_name": "Ignored"})
        assert "campaign_id" not in single and "campaign_name" not in single
        assert app._projection_params(old) == app._projection_params(single)
        code, _, _ = app.handle("POST", "/build/save", single)
        assert code == 400
        assert len(app.db.workspaces()) == 1
    finally:
        app.close()


def test_edit_review_restores_single_run_without_launching(tmp_path, monkeypatch):
    app = app_at(tmp_path)
    monkeypatch.setattr(app, "start_job", lambda *a, **k: pytest.fail("edit must not execute"))
    try:
        fields = {"work_kind": "run", "mode": "dry_run", "limit": "13", "seeds": "2,3"}
        ticket = app._new_launch_ticket(fields, purpose="build-edit")
        code, _, page = app.handle("POST", "/build/edit", {"edit_ticket": ticket})
        assert code == 200 and b"value='13'" in page and b"value='2,3'" in page
        assert app.db.workspaces() == []
        assert app.handle("POST", "/build/edit", {"edit_ticket": ticket})[0] == 400
    finally:
        app.close()


def test_jobs_filter_actual_campaign_membership_not_model_provider(tmp_path, monkeypatch):
    app = app_at(tmp_path)
    campaign = app.db.create_workspace("Local and API", "mixed")
    jobs = []
    for name, command in (("campaign-run", "run_matrix"), ("single-run", "run_matrix"), ("installation", "framework_runtimes")):
        job = Job(job_id=name, command=command, argv=[], directory=app.state_dir / name,
            started_at=time.time(), restored_state="passed", restored_exit=0)
        app.db.upsert_job(job)
        jobs.append(job)
    app.db.attach_workspace_member(campaign, "job", "campaign-run", "collection")
    monkeypatch.setattr(app, "_reconcile", lambda: None)
    monkeypatch.setattr(app, "_jobs_for_history_window", lambda *a, **k: (jobs, False))
    monkeypatch.setattr(app, "_engineering_campaign_scan", lambda **k: ([], ""))
    monkeypatch.setattr(app, "_external_measured_job_scan", lambda: ([], ""))
    try:
        standalone = app.handle("GET", "/jobs?view=standalone")[2].decode()
        assert "href='/jobs/single-run'" in standalone
        assert "href='/jobs/campaign-run'" not in standalone and "href='/jobs/installation'" not in standalone
        owned = app.handle("GET", "/jobs?campaign_id=" + campaign)[2].decode()
        assert "href='/jobs/campaign-run'" in owned
        assert "href='/jobs/single-run'" not in owned
        assert "Local and API" in owned
        index = app.handle("GET", "/jobs?view=campaigns")[2].decode()
        assert "Local and API" in index and "Build a campaign" in index
    finally:
        app.close()


def test_standalone_stats_filters_before_pagination_and_keeps_deep_links(tmp_path):
    app = app_at(tmp_path)
    campaign = app.db.create_workspace("Many runs", "mixed")
    try:
        with app.db._lock, app.db._conn:
            for index in range(60):
                app.db._conn.execute(
                    "INSERT INTO runs(job_id,kind,command,state,created_at) VALUES(?,?,?,?,?)",
                    (f"run-{index}", "measured", "run_matrix", "passed", index))
        for index in range(1, 60):
            app.db.attach_workspace_member(campaign, "job", f"run-{index}", "collection")
        assert [r["job_id"] for r in app.db.standalone_runs()] == ["run-0"]
        page = app.handle("GET", "/stats?view=standalone")[2].decode()
        assert "href='/stats/job/run-0'" in page
        assert "href='/stats/job/run-59'" not in page
        assert "Standalone runs" in page and "Earlier reports" in page
        assert b"Many runs" in app.handle("GET", "/stats")[2]
        assert b"Build a single run" in app.handle("GET", "/campaigns")[2]
    finally:
        app.close()
