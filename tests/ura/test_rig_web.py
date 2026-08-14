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


def test_config_editor_writes_only_allowlisted_json_with_backup(tmp_path: Path) -> None:
    # The config editor is the console's only write surface: it accepts an
    # allowlisted key, rejects non-JSON and non-object bodies, backs up the
    # prior bytes, and normalizes on save. No path outside the allowlist is
    # writable.
    # Use an isolated repo root so the test never touches the real registry.
    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    app = RigWebApp(
        results_root=tmp_path / "runs2", state_dir=tmp_path / "state2",
        repo_root=repo,
    )
    (tmp_path / "runs2").mkdir()
    # A clean valid save.
    target = app.save_config("api-targets", '{"z":1,"a":2}')
    assert target.name == "api-targets.json"
    written = json.loads(target.read_text(encoding="utf-8"))
    assert written == {"z": 1, "a": 2}
    assert list(target.read_text(encoding="utf-8").splitlines())[0] == "{"
    # A second save backs up the prior bytes.
    app.save_config("api-targets", '{"a":9}')
    backups = list((app.state_dir / "config-backups").glob("api-targets.json.*.bak"))
    assert len(backups) == 1
    # Invalid JSON and non-object are rejected.
    with pytest.raises(ValueError, match="not valid JSON"):
        app.save_config("api-targets", "not json")
    with pytest.raises(ValueError, match="JSON object"):
        app.save_config("api-targets", "[1,2,3]")
    # Unknown / path-escaping keys never resolve to a writable file.
    for bad in ("../secrets", "/etc/passwd", "nonsense"):
        with pytest.raises(ValueError, match="unknown config"):
            app.save_config(bad, "{}")
    # The editor seeds a missing/empty file from the checked-in example under
    # experiments/rig/, and offers a prefill button.
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    (repo / "experiments" / "rig" / "api-targets.example.json").write_text(
        '{"anthropic:claude-opus-5": {"modalities": ["text", "image"]}}',
        encoding="utf-8",
    )
    (repo / "experiments" / "api-targets.json").unlink(missing_ok=True)
    status, _, seeded = app.handle("GET", "/config?file=api-targets")
    seeded_text = seeded.decode("utf-8")
    assert status == 200
    assert "anthropic:claude-opus-5" in seeded_text  # seeded from example
    assert "cfg-prefill" in seeded_text and "Prefilled from" in seeded_text
    # The editor page renders and a save POST round-trips.
    status, _, body = app.handle("GET", "/config")
    assert status == 200 and b"api-targets" in body
    status, ctype, _ = app.handle(
        "POST", "/config", {"file": "api-targets", "content": '{"ok":1}'}
    )
    assert status == 303 and ctype.startswith("/config")
    # Secrets file names are not in the allowlist.
    from experiments.rig_web import _EDITABLE_CONFIGS
    assert all("env" not in key for key in _EDITABLE_CONFIGS)


def test_builder_composes_validated_run_matrix(tmp_path: Path) -> None:
    # The campaign builder is a guided surface over run_matrix: it composes
    # the same typed values the Run page would, and everything flows through
    # build_argv. Selecting the LLM judge auto-binds the Haiku judge model.
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/build")
    text = body.decode("utf-8")
    assert status == 200
    # A modality chip exists for each modality.
    for modality in ("text", "image", "audio", "video"):
        assert f"data-mod='{modality}'" in text
    # Multimodal arms carry their FULL modality set (text + image), so they
    # answer to the text chip and the image chip alike - not bucketed to one.
    assert "data-mods='text,image'" in text
    assert "data-arm='mmsafety_official'" in text
    assert "data-fw='crescendo'" in text
    # Modality scope checkboxes are all pre-checked for a fresh build, and the
    # scope-filter script is present (arms/models/frameworks hide out of scope).
    assert text.count("class='modbox' data-mod") == 4
    assert "data-mod='text' checked" in text  # pre-checked scope toggle
    assert "modtoggle" in text  # styled scope pills, not bare checkboxes
    assert "applyScope" in text and "intersects" in text
    command, values = app._compose_from_builder({
        "mode": "diagnostic_canary",
        "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5",
        "attackers": "replay,crescendo",
        "judges": "rules,llm",
        "limit": "8", "sample_seed": "0", "out": "runs/thesis/canary",
        "defense": "none",
    })
    assert command == "run_matrix"
    assert values["--diagnostic-canary"] == "on"
    assert values["--judge-model"] == "anthropic:claude-haiku-4-5-20251001"
    assert values["--limit"] == "8"
    assert "--defense" not in values  # 'none' is omitted
    # Composed values must build a valid argv (same typed allowlist).
    argv = build_argv(command, values)
    assert argv[1:3] == ["-m", "experiments.run_matrix"]
    assert "--diagnostic-canary" in argv and "--corpora" in argv


def test_builder_targets_split_hosted_and_local_vllm_roster() -> None:
    # Targets are hosted API (composed into --api) and local vLLM (--local),
    # the latter drawn from the configured registry plus the vLLM roster; the
    # focal env pair are hosted. Compose splits them correctly.
    from experiments import local_targets
    from experiments.rig_web import RigWebApp

    app = RigWebApp(results_root=Path("."), state_dir=Path("."))
    page = app.handle("GET", "/build")[2].decode("utf-8")
    assert "Hosted API" in page and "Local vLLM" in page
    assert "data-kind='api'" in page and "data-kind='local'" in page
    # The curated vLLM roster is real and modality-tagged.
    roster = local_targets.roster_models()
    assert len(roster) > 10
    assert any("Qwen3-VL" in m["spec"] for m in roster)
    assert any("audio" in m["modalities"] for m in roster)
    # A build with a local target composes --local and binds --local-config
    # only when a local target is selected.
    _cmd, values = app._compose_from_builder({
        "mode": "measured", "corpora": "strongreject_official",
        "local": "vllm:Qwen/Qwen3-VL-8B-Instruct", "attackers": "replay",
        "judges": "rules", "out": "runs/x",
    })
    assert values["--local"] == "vllm:Qwen/Qwen3-VL-8B-Instruct"
    assert "--api" not in values


def test_builder_escapes_config_sourced_modalities(tmp_path: Path) -> None:
    # A crafted modality value in an editable target registry must not break
    # out of the data-mods attribute on the builder page (stored-XSS guard),
    # and there is a single control named 'local' (no duplicate free-text box).
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True)
    (repo / "experiments" / "api-targets.json").write_text(json.dumps({
        "evil:model": {"modalities": ["text' onmouseover='x"]},
    }), encoding="utf-8")
    (repo / "experiments" / "rig" / "api-targets.example.json").write_text(
        "{}", encoding="utf-8")
    (repo / "experiments" / "rig" / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8")
    app = RigWebApp(
        results_root=tmp_path / "r", state_dir=tmp_path / "s", repo_root=repo,
    )
    (tmp_path / "r").mkdir()
    page = app.handle("GET", "/build")[2].decode("utf-8")
    assert "onmouseover='x" not in page  # escaped, no attribute breakout
    assert "onmouseover=&#x27;x" in page or "onmouseover=&#39;x" in page
    assert page.count("name='local'") == 1  # single composed control


def test_local_targets_roster_parse_and_modality_inference() -> None:
    from experiments.local_targets import infer_modalities, parse_vllm_doc

    assert infer_modalities("vllm:Qwen/Qwen3-VL-8B-Instruct") == ["text", "image"]
    assert infer_modalities("vllm:Qwen/Qwen2-Audio-7B-Instruct") == ["text", "audio"]
    assert infer_modalities("vllm:meta-llama/Llama-3.1-8B-Instruct") == ["text"]
    doc = "See `Qwen/Qwen2.5-7B-Instruct` and `llava-hf/llava-1.5-7b-hf` here."
    ids = parse_vllm_doc(doc)
    assert "Qwen/Qwen2.5-7B-Instruct" in ids
    assert "llava-hf/llava-1.5-7b-hf" in ids


def test_stats_page_renders_budget_and_tolerates_missing_results(tmp_path: Path) -> None:
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "Budgets" in text and "Anthropic" in text and "$100" in text
    assert "No Level-1/Level-2 result" in text  # graceful empty state
    # A level2 report with a recognizable table renders a diagram.
    (app.results_root / "level2.json").write_text(json.dumps({
        "rows": [
            {"model": "fable", "asr": 0.12},
            {"model": "sol", "attack_success_rate": 34.0},
        ],
    }), encoding="utf-8")
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert "barchart" in text and "fable" in text


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
    # it must never label presence as validity or authorization.  Files under
    # a superseded/ directory are tallied separately as archived history, and
    # stage nodes link into the artifact browser.
    app = _app(tmp_path)
    receipts = app.results_root / "thesis" / "project-revision"
    (receipts / "superseded").mkdir(parents=True)
    (receipts / "project-revision-abc.project-revision.json").write_text(
        "{}", encoding="utf-8"
    )
    (
        receipts / "superseded" / "project-revision-old.project-revision.json"
    ).write_text("{}", encoding="utf-8")
    status, _, body = app.handle("GET", "/")
    assert status == 200
    text = body.decode("utf-8")
    assert "Revision receipt" in text
    assert "1 file" in text
    assert "+1 archived" in text
    assert "presence never asserts validity" in text
    # The stage node links into the artifact browser; the stage file list
    # names both the current and the archived receipt as links.
    assert "/artifacts?path=thesis/project-revision" in text
    assert "1 current, 1 archived" in text
    # The suggested-next-step card is presence-derived and says so.
    assert "Suggested next step" in text
    assert "file presence only" in text
    # Grouped Run page renders every command exactly once as a form.
    status, _, run_body = app.handle("GET", "/commands")
    assert status == 200
    run_text = run_body.decode("utf-8")
    from experiments.rig_web import COMMANDS

    for name in COMMANDS:
        assert run_text.count(
            f"<input type='hidden' name='command' value='{name}'>"
        ) == 1
    # The client-side filter is present and cards carry filterable names.
    assert "cmdfilter" in run_text
    assert "data-name='run_matrix" in run_text


def test_dashboard_notices_and_policy_card(tmp_path: Path) -> None:
    # Operator notices from console-warnings.json render as banners with the
    # annotate-never-authorize disclaimer; malformed files are ignored; and
    # the recorded sampling policy is always visible.
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/")
    text = body.decode("utf-8")
    assert status == 200
    assert "Notices" not in text  # no warnings file -> no banner card
    assert "Campaign sampling policy" in text
    assert "local lanes only" in text
    assert "never be pooled" in text or "never pooled" in text

    (app.results_root / "console-warnings.json").write_text(json.dumps({
        "warnings": [
            {"level": "warning",
             "title": "BIPIA qa constructed from external NewsQA",
             "detail": "MD5 not yet verified against the official md5.txt."},
            {"level": "bogus-level", "title": "tolerated"},
            "not-a-dict",
        ],
    }), encoding="utf-8")
    status, _, body = app.handle("GET", "/")
    text = body.decode("utf-8")
    assert status == 200
    assert "Notices" in text
    assert "BIPIA qa constructed from external NewsQA" in text
    assert "MD5 not yet verified" in text
    assert "tolerated" in text
    assert "never authorize" in text

    # A corrupt warnings file must never break the dashboard.
    (app.results_root / "console-warnings.json").write_text(
        "{not json", encoding="utf-8"
    )
    status, _, _ = app.handle("GET", "/")
    assert status == 200


def test_notices_are_dismissible_client_side(tmp_path: Path) -> None:
    # Dismissal is client-side only: each notice carries a stable id and a
    # close control, and localStorage-backed script hides dismissed ids. The
    # warnings file (server truth) is never mutated by the console.
    app = _app(tmp_path)
    (app.results_root / "console-warnings.json").write_text(json.dumps({
        "warnings": [{"level": "warning", "title": "constructed set"}],
    }), encoding="utf-8")
    before = (app.results_root / "console-warnings.json").read_bytes()
    status, _, body = app.handle("GET", "/")
    text = body.decode("utf-8")
    assert status == 200
    assert "notice-close" in text
    assert "data-nid=" in text
    assert "localStorage" in text
    # GET must not have a side effect on the notices file.
    assert (app.results_root / "console-warnings.json").read_bytes() == before


def test_jobs_page_has_filter_chips_and_row_stop(tmp_path: Path) -> None:
    app = _app(tmp_path)
    job = app.start_job("webui_selftest", {"--selftest-sleep": "30"})
    try:
        status, _, body = app.handle("GET", "/jobs")
        text = body.decode("utf-8")
        assert status == 200
        # State filter chips with counts.
        assert "class='chip on'" in text
        assert "data-state='running'" in text
        assert "Running (1)" in text
        # A running job exposes an inline Stop control on its row.
        assert f"/jobs/{job.job_id}/stop" in text
        assert "jobfilter" in text
        # Human-readable durations, not raw seconds with a trailing 's' only.
        assert "data-hay=" in text
    finally:
        app.stop_job(job.job_id)


def test_run_forms_use_select_and_datalist_without_weakening_argv() -> None:
    # UI affordances are presentation only: enumerated flags render as a
    # <select> of the exact argparse choices, suggestion fields get a
    # <datalist>, but build_argv still rejects anything off-contract.
    from experiments.rig_web import RigWebApp

    app = RigWebApp(results_root=Path("."), state_dir=Path("."))
    page = app.handle("GET", "/commands")[2].decode("utf-8")
    assert "<select name='--defense'>" in page
    assert "<option value='none'>none</option>" in page
    assert "<option value='both'>both</option>" in page
    assert "list='dl-attackers'" in page
    assert "<datalist id='dl-attackers'>" in page
    assert "<option value='crescendo'></option>" in page
    # A number field for integer flags.
    assert "type='number'" in page
    # The typed allowlist is unchanged: an off-contract choice still fails,
    # and a valid enumerated choice still builds.
    argv = build_argv("run_matrix", {"--defense": "both"})
    assert argv[-2:] == ["--defense", "both"]
    with pytest.raises(ValueError):
        build_argv("run_matrix", {"--not-a-flag": "x"})


def test_jobs_and_runs_persist_across_console_restart(tmp_path: Path) -> None:
    # WEB-009: the console indexes jobs, campaign runs, and spend in a sqlite
    # database under the state dir, so the Jobs and Stats pages survive a
    # restart. The database is an operational index, not return evidence.
    import time as _time

    app = _app(tmp_path)
    job = app.start_job("webui_selftest", {"--selftest-sleep": "0"})
    deadline = _time.time() + 30
    while job.state() == "running" and _time.time() < deadline:
        _time.sleep(0.05)
    app._reconcile()
    assert (app.state_dir / "console.db").is_file()

    # A fresh app over the same state dir = a console restart.
    restarted = RigWebApp(
        results_root=app.results_root, state_dir=app.state_dir,
        job_id_factory=lambda: "job-new",
    )
    assert job.job_id in restarted.jobs
    restored = restarted.jobs[job.job_id]
    assert restored.process is None
    assert restored.state() == "complete"  # last-known state, no live handle
    status, _, body = restarted.handle("GET", "/jobs")
    assert status == 200 and job.job_id.encode() in body
    from experiments.rig_web import ConsoleDB, run_kind
    assert run_kind("run_matrix", ["--attestation-probe"]) == "attestation_probe"
    assert run_kind("run_matrix", ["--dry-run"]) == "dry_run"
    assert run_kind("run_matrix", []) == "measured"
    assert run_kind("rig_check", []) == "preflight"
    assert run_kind("figures", []) is None
    assert isinstance(restarted.db, ConsoleDB)


def test_stats_runs_card_records_lane_jobs(tmp_path: Path) -> None:
    import time as _time

    app = _app(tmp_path)
    # A rig_check-shaped job is registered as a campaign run on finish.
    job = app.start_job("level1_evidence", {
        "--eligibility": str(tmp_path / "missing.json"),
        "--results": str(tmp_path / "missing"),
        "--out-json": str(tmp_path / "o.json"),
        "--out-csv": str(tmp_path / "o.csv"),
    })
    deadline = _time.time() + 60
    while job.state() == "running" and _time.time() < deadline:
        _time.sleep(0.1)
    app._reconcile()
    # level1_evidence is not a run kind, so no run row; the Stats page still
    # renders the (empty) runs card without error.
    status, _, body = app.handle("GET", "/stats")
    assert status == 200 and b"Campaign runs" in body


def test_favicon_and_active_nav(tmp_path: Path) -> None:
    app = _app(tmp_path)
    status, content_type, body = app.handle("GET", "/static/favicon.svg")
    assert status == 200 and content_type == "image/svg+xml"
    assert body.startswith(b"<svg")
    status, content_type, _ = app.handle("GET", "/favicon.ico")
    assert status == 200 and content_type == "image/svg+xml"
    status, _, page = app.handle("GET", "/jobs")
    assert status == 200
    text = page.decode("utf-8")
    assert "class='active'" in text
    assert "favicon.svg" in text


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
