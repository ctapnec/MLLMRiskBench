"""WEB-001 rig console contracts: allowlist, containment, jobs, rendering."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from experiments.rig_web import (
    RigWebApp,
    build_argv,
    evidence_badges,
)


def _app(tmp_path: Path) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir()
    counter = iter(range(1, 1000))
    return RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        job_id_factory=lambda: f"job-{next(counter):04d}",
    )


def test_command_construction_is_typed_and_allowlisted() -> None:
    argv = build_argv("level1_evidence", {
        "--eligibility": "runs/a/eligibility.json",
        "--results": "runs/a",
        "--out-json": "runs/a/l1.json",
        "--out-csv": "runs/a/l1.csv",
    })
    assert argv[:3] == [sys.executable, "-m", "experiments.level1_evidence"]
    assert argv[3:] == [
        "--eligibility", "runs/a/eligibility.json",
        "--results", "runs/a",
        "--out-json", "runs/a/l1.json",
        "--out-csv", "runs/a/l1.csv",
    ]

    with pytest.raises(ValueError, match="unknown command"):
        build_argv("rm", {})
    with pytest.raises(ValueError, match="unknown parameter"):
        build_argv("level1_evidence", {"--exec": "evil"})
    with pytest.raises(ValueError):
        build_argv("run_matrix", {"--limit": "12; rm -rf /"})
    # Flag parameters never smuggle values.
    with pytest.raises(ValueError, match="checkbox flag"):
        build_argv("run_matrix", {"--dry-run": "--models evil"})
    # An empty form for a command still produces only the module invocation.
    assert build_argv("figures", {}) == [sys.executable, "-m", "experiments.figures"]
    # The UI selftest can never construct a bare rig_web invocation (which
    # would start a nested console server): its sleep value is required.
    with pytest.raises(ValueError, match="requires --selftest-sleep"):
        build_argv("webui_selftest", {})
    # The operator start sequence is reachable from the console: the receipt
    # scaffold/validation command is allowlisted.
    argv = build_argv("source_conformance", {
        "--scaffold": "on",
        "--arm": "strongreject_official",
        "--source-config": "experiments/source-instances.json",
        "--out": "runs/thesis/receipt.scaffold.json",
    })
    assert argv[2] == "experiments.source_conformance"
    assert "--scaffold" in argv and "--arm" in argv


def test_artifact_paths_are_contained(tmp_path: Path) -> None:
    app = _app(tmp_path)
    (app.results_root / "inner").mkdir()
    (app.results_root / "inner" / "a.json").write_text("{}", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("secret", encoding="utf-8")

    status, _, _ = app.handle("GET", "/artifacts?path=inner/a.json")
    assert status == 200
    for escape in (
        "../outside.txt",
        "..%2Foutside.txt",
        "inner/../../outside.txt",
        "/etc/passwd",
        "C:/Windows/win.ini",
    ):
        status, _, body = app.handle("GET", f"/artifacts?path={escape}")
        assert status in {400, 404}, escape
        assert b"secret" not in body


def test_job_lifecycle_start_monitor_stop(tmp_path: Path) -> None:
    app = _app(tmp_path)
    job = app.start_job("webui_selftest", {"--selftest-sleep": "30"})
    assert job.state() == "running"
    status, _, body = app.handle("GET", f"/jobs/{job.job_id}")
    assert status == 200
    assert b"running" in body
    app.handle("POST", f"/jobs/{job.job_id}/stop")
    deadline = time.time() + 15
    while job.state() == "running" and time.time() < deadline:
        time.sleep(0.1)
    assert job.state() in {"failed", "complete"}
    assert (job.directory / "command.json").exists()

    quick = app.start_job("webui_selftest", {"--selftest-sleep": "0"})
    deadline = time.time() + 30
    while quick.state() == "running" and time.time() < deadline:
        time.sleep(0.1)
    assert quick.state() == "complete"
    log_status, _, log_body = app.handle(
        "GET", f"/jobs/{quick.job_id}/log?stream=stdout"
    )
    assert log_status == 200
    assert b"selftest complete" in log_body


def test_failed_job_displays_failure_and_stderr(tmp_path: Path) -> None:
    app = _app(tmp_path)
    # A real allowlisted CLI with a missing input fails fast and nonzero.
    job = app.start_job("level1_evidence", {
        "--eligibility": str(tmp_path / "missing.json"),
        "--results": str(tmp_path / "missing"),
        "--out-json": str(tmp_path / "out.json"),
        "--out-csv": str(tmp_path / "out.csv"),
    })
    deadline = time.time() + 60
    while job.state() == "running" and time.time() < deadline:
        time.sleep(0.2)
    assert job.state() == "failed"
    status, _, body = app.handle("GET", f"/jobs/{job.job_id}")
    assert status == 200
    assert b"Failure" in body
    assert b"exited with code" in body
    stderr_tail = (job.directory / "stderr.log").read_bytes()
    assert stderr_tail  # the CLI's own message is preserved verbatim


def test_artifact_rendering_shows_evidence_badges(tmp_path: Path) -> None:
    app = _app(tmp_path)
    (app.results_root / "level1.json").write_text(json.dumps({
        "schema_version": "ura-level1-evidence/2",
        "scope": {
            "evidence_kind": "diagnostic_dry_run",
            "empirical_validity_established": False,
        },
        "counts": {"planning_strata": {"structural_not_applicable": 2}},
    }), encoding="utf-8")
    (app.results_root / "table.csv").write_text(
        "metric,value\nASR,1.0\n", encoding="utf-8"
    )
    status, content_type, body = app.handle("GET", "/artifacts?path=level1.json")
    assert status == 200 and "text/html" in content_type
    text = body.decode("utf-8")
    assert "diagnostic dry-run" in text
    assert "no empirical validity" in text
    assert "structural N/A: 2" in text

    status, _, body = app.handle("GET", "/artifacts?path=table.csv")
    assert status == 200
    assert b"<table>" in body and b"ASR" in body

    status, _, body = app.handle("GET", "/artifacts?path=")
    assert status == 200
    assert b"level1.json" in body


def test_badges_distinguish_measured_and_canary() -> None:
    assert ("measured run", "blue") in evidence_badges(
        {"scope": {"evidence_kind": "measured_run"}}
    )
    badges = evidence_badges({
        "evidence_class": "synthetic_offline",
        "campaign_authorized": False,
    })
    assert ("synthetic offline", "amber") in badges
    assert ("campaign not authorized", "gray") in badges


def test_console_covers_every_runbook_cli() -> None:
    # The console and the CLI are two interfaces to the same operations: every
    # experiments module the runbook invokes must be allowlisted (rig_web
    # itself excepted - the console does not launch itself).
    import re

    from experiments.rig_web import COMMANDS

    runbook = (
        Path(__file__).resolve().parents[2]
        / "experiments" / "RUN_AND_RETURN.md"
    ).read_text(encoding="utf-8")
    used = set(re.findall(r"python -m experiments\.([a-z0-9_]+)", runbook))
    used.discard("rig_web")
    allowlisted = {entry.module.split(".", 1)[1] for entry in COMMANDS.values()}
    missing = sorted(used - allowlisted)
    assert not missing, f"runbook CLIs missing from the console allowlist: {missing}"


def test_command_groups_partition_the_allowlist_exactly() -> None:
    # WEB-002 grouping is presentation only: every allowlisted command sits in
    # exactly one group, and no group names an unknown command.  A partition
    # failure would silently hide a command from the Run page groups.
    from experiments.rig_web import COMMAND_GROUPS, COMMANDS

    named = [name for _, _, _, names in COMMAND_GROUPS for name in names]
    assert len(named) == len(set(named)), "command grouped twice"
    assert set(named) == set(COMMANDS), (
        sorted(set(named) ^ set(COMMANDS))
    )


def test_dashboard_shows_presence_only_pipeline(tmp_path: Path) -> None:
    # The dashboard pipeline counts retained files by name only and says so;
    # it must never label presence as validity or authorization.
    app = _app(tmp_path)
    receipts = app.results_root / "thesis" / "project-revision"
    receipts.mkdir(parents=True)
    (receipts / "project-revision-abc.project-revision.json").write_text(
        "{}", encoding="utf-8"
    )
    status, _, body = app.handle("GET", "/")
    assert status == 200
    text = body.decode("utf-8")
    assert "Revision receipt" in text
    assert "1 file" in text
    assert "presence never asserts validity" in text
    # Grouped Run page renders every command exactly once as a form.
    status, _, run_body = app.handle("GET", "/commands")
    assert status == 200
    run_text = run_body.decode("utf-8")
    from experiments.rig_web import COMMANDS

    for name in COMMANDS:
        assert run_text.count(
            f"<input type='hidden' name='command' value='{name}'>"
        ) == 1


def test_artifact_pages_render_breadcrumbs(tmp_path: Path) -> None:
    app = _app(tmp_path)
    inner = app.results_root / "thesis" / "level1"
    inner.mkdir(parents=True)
    (inner / "evidence.json").write_text("{}", encoding="utf-8")
    status, _, body = app.handle(
        "GET", "/artifacts?path=thesis/level1/evidence.json"
    )
    assert status == 200
    text = body.decode("utf-8")
    assert "crumbs" in text
    assert "/artifacts?path=thesis" in text
    assert "/artifacts?path=thesis/level1" in text
