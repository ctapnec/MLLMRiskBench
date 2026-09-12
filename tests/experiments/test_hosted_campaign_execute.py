"""Reusable collection and typed UI command, without target generation."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments import hosted_campaign_execute as subject
from experiments.rig_web_app.catalog import COMMANDS, build_argv
from experiments.rig_web_app.workspace_store import activity_role


def test_shared_source_is_read_once_and_selection_is_not_changed(tmp_path, monkeypatch):
    programs = []
    for provider in ("openai", "google"):
        path = tmp_path / (provider + ".json")
        raw = json.dumps(dict(target=provider + ":test", provider=provider,
            results_root="same-results", runner_view="same-view", rr_analysis_root="same-rr",
            sources={"historical_result": "same-history"})).encode()
        path.write_bytes(raw)
        programs.append((path, hashlib.sha256(raw).hexdigest()))
    calls, dispatched = [], []
    monkeypatch.setattr(subject.retained, "_validated_checkout", lambda *_: None)
    monkeypatch.setattr(subject, "AttemptBudget", lambda *_: object())
    monkeypatch.setattr(subject.retained, "_validated_local_cells", lambda value: calls.append(value) or object())
    def admitted(value, budget, *, local_context):
        return [SimpleNamespace(requests={value["target"]: {"call_id": value["target"]}})]
    monkeypatch.setattr(subject.retained, "_validated_jobs", admitted)
    def dispatch(jobs, **kwargs):
        dispatched.append((jobs, kwargs))
        kwargs["on_progress"]({"jobs": [{"status": "running"}]})
        return [{"status": "collected"} for _ in jobs]
    monkeypatch.setattr(subject, "dispatch_admitted", dispatch)
    result = subject.collect_campaign(programs=programs, budget_root=tmp_path,
        budget_plan_sha256="a" * 64, project_root=tmp_path, expected_commit="b" * 40,
        out=tmp_path / "collection")
    assert len(calls) == 1 and len(dispatched[0][0]) == 2
    assert dispatched[0][1]["workers_per_provider"] == 2
    assert dispatched[0][1]["responses_only"] is True
    assert result["status"] == "responses_collected_awaiting_judging"
    assert result["assigned_target_inputs"] == 2 and result["selection_changed"] is False
    assert json.loads((tmp_path / "collection/result.json").read_text()) == result


def test_program_digest_failure_cannot_create_a_job_or_dispatch(tmp_path, monkeypatch):
    source = tmp_path / "program.json"
    source.write_text('{}')
    monkeypatch.setattr(subject.retained, "_validated_checkout", lambda *_: None)
    monkeypatch.setattr(subject, "AttemptBudget", lambda *_: object())
    monkeypatch.setattr(subject, "dispatch_admitted", lambda *a, **k: pytest.fail("dispatcher reached"))
    with pytest.raises(ValueError):
        subject.collect_campaign(programs=[(source, "a" * 64)], budget_root=tmp_path,
            budget_plan_sha256="b" * 64, project_root=tmp_path, expected_commit="c" * 40,
            out=tmp_path / "never")
    assert not (tmp_path / "never").exists()


def test_ui_command_preserves_program_pairing_parallelism_and_campaign_role(tmp_path, monkeypatch):
    values = {"--program": str(tmp_path / "first.json"), "--program#1": str(tmp_path / "second.json"),
        "--program-sha256": "a" * 64, "--program-sha256#1": "b" * 64,
        "--budget-root": str(tmp_path), "--budget-plan-sha256": "c" * 64,
        "--project-root": str(tmp_path), "--expected-commit": "d" * 40,
        "--out": str(tmp_path / "out"), "--workers-per-provider": "2"}
    argv = build_argv("hosted_campaign_execute", values)
    marker = argv.index("experiments.hosted_campaign_execute") + 1
    observed = []
    monkeypatch.setattr(subject, "collect_campaign", lambda **kwargs: observed.append(kwargs)
        or {"status": "responses_collected_awaiting_judging"})
    assert subject.main(argv[marker:]) == 0
    assert observed[0]["programs"] == [(Path(values["--program"]), "a" * 64),
        (Path(values["--program#1"]), "b" * 64)]
    assert observed[0]["workers_per_provider"] == 2
    assert activity_role("hosted_campaign_execute") == "collection"
    assert "--verify-artifact-sha256" not in argv


def test_ui_environment_uses_each_selected_program_not_all_provider_keys(tmp_path):
    from experiments.rig_web_app.lifecycle import LifecycleMixin

    seen, documents = [], []
    def read(path, digest):
        documents.append((path, digest))
        return {"jobs": [{"argv": ["--api", path, "--out", "/tmp/unused"]}]}
    fake = SimpleNamespace(commands=COMMANDS, _MATRIX_BASE_ENV={"BASE"},
        _MATRIX_OPTIONAL_ENV={"OPTIONAL"}, _MATRIX_RECEIPT_ENV={"RECEIPT"},
        _strict_config_document=read,
        _selected_matrix_environment_names=lambda values: seen.append(values) or {values["--api"] + "_KEY"},
        _selected_child_environment=lambda allowed: allowed)
    values = {"--program": "openai", "--program#1": "google",
        "--program-sha256": "a" * 64, "--program-sha256#1": "b" * 64}
    allowed = LifecycleMixin._generic_child_environment(fake, "hosted_campaign_execute", values)
    assert allowed == {"BASE", "OPTIONAL", "RECEIPT", "openai_KEY", "google_KEY"}
    assert documents == [("openai", "a" * 64), ("google", "b" * 64)]
    assert [item["--api"] for item in seen] == ["openai", "google"]
    del values["--program-sha256#1"]
    with pytest.raises(ValueError, match="matching digest"):
        LifecycleMixin._generic_child_environment(fake, "hosted_campaign_execute", values)


def test_owned_collection_publishes_pending_progress_and_terminal_without_judging(tmp_path, monkeypatch):
    from experiments.rig_web_app.storage import ConsoleDB
    from experiments.rig_web_app import workspace_import

    db_path = tmp_path / "console.db"
    db = ConsoleDB(db_path)
    campaign = db.create_workspace("Prepared API", "api")
    db.close()
    path = tmp_path / "program.json"
    raw = json.dumps(dict(target="openai:model", sources={})).encode()
    path.write_bytes(raw)
    monkeypatch.setattr(subject.retained, "_validated_checkout", lambda *_: None)
    monkeypatch.setattr(subject, "AttemptBudget", lambda *_: object())
    monkeypatch.setattr(subject.retained, "_validated_local_cells", lambda *_: object())
    job = SimpleNamespace(requests={"a":dict(call_id="a")},
        attacker=SimpleNamespace(_retained={"plan":{"selected":[{"input_identity_sha256":"a"}]}}))
    monkeypatch.setattr(subject.retained, "_validated_jobs", lambda *a, **k: [job])
    observed = []

    class Publisher:
        def __init__(self, database, workspace, **kwargs):
            assert workspace == campaign and database.workspace(campaign)["name"] == "Prepared API"
            assert kwargs["selections"] == [[{"input_identity_sha256":"a"}]]

        def refresh(self, progress):
            observed.append(progress["jobs"][0]["status"])
            return dict(status="published")

    monkeypatch.setattr(workspace_import, "HostedWorkspacePublication", Publisher)
    def dispatch(_admitted, **kwargs):
        kwargs["on_progress"](dict(jobs=[dict(program=0, job=0, status="running")]))
        return [dict(program=0, job=0, status="collected")]
    monkeypatch.setattr(subject, "dispatch_admitted", dispatch)
    result = subject.collect_campaign(programs=[(path,hashlib.sha256(raw).hexdigest())],
        budget_root=tmp_path, budget_plan_sha256="a"*64, project_root=tmp_path,
        expected_commit="b"*40, out=tmp_path/"out", workspace_id=campaign, console_db=db_path)
    assert observed == ["pending", "running", "collected"]
    assert result["publication"]["status"] == "published"
    assert result["judgments"] == "not_executed_by_collection"


def test_cli_publication_binding_matches_owned_console_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("URA_CAMPAIGN_WORKSPACE_ID", "selected-workspace")
    monkeypatch.setenv("URA_CAMPAIGN_CONSOLE_DB", str(tmp_path/"console.db"))
    observed = []
    monkeypatch.setattr(subject, "collect_campaign", lambda **kwargs: observed.append(kwargs)
        or {"status":"responses_collected_awaiting_judging"})
    subject.main(["--program",str(tmp_path/"p"),"--program-sha256","a"*64,
        "--budget-root",str(tmp_path),"--budget-plan-sha256","b"*64,
        "--project-root",str(tmp_path),"--expected-commit","c"*40,"--out",str(tmp_path/"out")])
    assert observed[0]["workspace_id"] == "selected-workspace"
    assert observed[0]["console_db"] == tmp_path/"console.db"
