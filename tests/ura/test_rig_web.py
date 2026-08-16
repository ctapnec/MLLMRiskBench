"""WEB-002 campaign builder and console contracts.

Allowlist and containment, CLI/UI interface parity against the real module
parsers, mode-specific builder validation, sqlite reliability (restart,
migration, corruption, reindex), process-tree lifecycle, real Level-1/Level-2
rendering from producer-generated artifacts, and recorded-usage cost
accounting.  Every app instance uses temporary state and results directories
so the checkout is never dirtied.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import sqlite3
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from experiments import level1_evidence as level1_cli
from experiments import level2_report as level2_cli
from experiments import live_attestation as live_attestation_cli
from experiments import rig_check
from experiments.rig_web import (
    _LEVEL2_ROW_FIELDS,
    _MATRIX_PARAMS,
    Command,
    ConsoleDB,
    Job,
    RigWebApp,
    _tokens_by_category,
    _validate_report_document,
    build_argv,
    collect_usage,
    compute_costs,
    evidence_badges,
    rate_for,
    reconcile_pricing_ownership,
    run_kind,
    usage_rows_from_marker,
)
from ura.data_models import DialogTurn, Response
from ura.targets.base import BaseTarget


def _app(tmp_path: Path) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    counter = iter(range(1, 1000))
    return RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        job_id_factory=lambda: f"job-{next(counter):04d}",
    )


def _isolated_app(tmp_path: Path) -> RigWebApp:
    """An app whose repo root is ALSO isolated (registry/pricing reads)."""

    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    return RigWebApp(
        results_root=results, state_dir=tmp_path / "state", repo_root=repo,
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
    with pytest.raises(ValueError, match="must be one of"):
        build_argv("run_matrix", {"--defense": "invented"})
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


def test_fresh_results_root_renders_empty_artifact_browser(tmp_path: Path) -> None:
    results = tmp_path / "not-created-yet" / "results"
    assert not results.exists()
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=Path(__file__).resolve().parents[2],
    )
    try:
        status, _, body = app.handle("GET", "/artifacts")
        assert status == 200
        assert results.is_dir()
        assert "Empty directory." in body.decode("utf-8")
    finally:
        app.close()


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


def test_close_detaches_running_job_without_killing_it(tmp_path: Path) -> None:
    app = _app(tmp_path)
    job = app.start_job("webui_selftest", {"--selftest-sleep": "30"})
    assert job.process is not None and job.process.poll() is None
    db_path = app.db.path

    app.close()
    try:
        # Console shutdown releases its handles but must not silently stop the
        # experiment; a later console will honestly restore it as orphaned.
        time.sleep(0.2)
        assert job.process.poll() is None
        with sqlite3.connect(db_path) as conn:
            assert conn.execute(
                "SELECT state, exit_code FROM jobs WHERE job_id = ?",
                (job.job_id,),
            ).fetchone() == ("running", None)
    finally:
        if job.process.poll() is None:
            job.process.kill()
        job.process.wait(timeout=10)


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


def test_builder_page_renders_full_surface(tmp_path: Path) -> None:
    # The builder page carries the complete lane surface: modality wizard,
    # receipts, scope + repeatable attestation rows, sampling, call ceilings,
    # local serving, and output.
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/build")
    text = body.decode("utf-8")
    assert status == 200
    for modality in ("text", "image", "audio", "video"):
        assert f"data-mod='{modality}'" in text
    assert "data-mods='text,image'" in text
    assert "data-arm='mmsafety_official'" in text
    assert "data-fw='crescendo'" in text
    assert "data-judge='guardrail'" in text  # the guardrail judge option
    assert text.count("class='modbox' data-mod") == 4
    assert "data-mod='text' checked" in text
    assert "modtoggle" in text
    assert "applyScope" in text and "intersects" in text
    # Every material Runner control is present.
    for field in (
        "name='project_revision'", "name='project_revision_sha'",
        "name='source_conformance'", "name='source_conformance_sha'",
        "name='scope'", "name='max_age'", "name='att_path1'",
        "name='att_sha1'", "name='seeds'", "name='max_queries'",
        "name='max_turns'", "name='cap_target'", "name='cap_judge'",
        "name='cap_http'", "name='deadline'", "name='dtype'",
        "name='quantization'", "name='judge_model'", "name='defense_guard'",
        "name='canary_dry'",
        # Scoring and defense guardrail inputs (model/revision/device each).
        "name='guardrail_model'", "name='guardrail_revision'",
        "name='guardrail_device'", "name='defense_guardrail_model'",
        "name='defense_guardrail_revision'", "name='defense_guardrail_device'",
    ):
        assert field in text, field
    assert "addatt" in text  # repeatable receipt rows


def test_attacker_registry_parity_and_full_inventory() -> None:
    # The console's attacker mirror must equal the maintained engines registry
    # (all 20), so the builder can never silently omit an engine.
    import sys
    sys.path.insert(0, "src")
    from ura.adapters.engines import ATTACKER_NAMES
    from experiments.rig_web import (
        _ATTACKER_NAMES, _ARM_CATALOG, _INELIGIBLE_ARMS, _FRAMEWORKS,
    )
    assert _ATTACKER_NAMES == ATTACKER_NAMES
    assert len(_FRAMEWORKS) == 20
    assert len(_ARM_CATALOG) == 39  # all maintained source arms
    # 15 common-metric-ineligible arms with NO implemented source evaluator
    # (shown disabled). rjudge/gptgeochat are NOT here: their exact source
    # evaluators ARE implemented, so run_matrix scores them as source-metric
    # lanes - they are runnable, not disabled.
    assert len(_INELIGIBLE_ARMS) == 15
    assert {
        "cyberseceval_prompt_injection",
        "mllmguard_hallucination",
        "mllmguard_position_swapping",
        "mllmguard_noise_injection",
        "agentharm_harmful",
    } <= _INELIGIBLE_ARMS
    assert "rjudge_release" not in _INELIGIBLE_ARMS
    assert "gptgeochat_release" not in _INELIGIBLE_ARMS
    # The source-metric arm set mirrors the implemented-evaluator registry
    # exactly, so the console never claims a scored lane the runtime does not
    # implement (nor disables one it does).
    from experiments.rig_web import _SOURCE_METRIC_ARMS
    from ura.source_metrics import _IMPLEMENTED_SOURCE_EVALUATORS
    assert {metric for _a, (metric, _atk) in _SOURCE_METRIC_ARMS.items()} == {
        metric for _src, metric in _IMPLEMENTED_SOURCE_EVALUATORS
    }


def test_builder_lists_all_arms_and_only_campaign_attackers(tmp_path: Path) -> None:
    from experiments.rig_web import (
        _ARM_CATALOG,
        _ATTACKER_NAMES,
        _BUILDER_OMITTED_ATTACKERS,
        _INELIGIBLE_ARMS,
    )
    app = _app(tmp_path)
    try:
        _s, _c, body = app.handle("GET", "/build")
        text = body.decode("utf-8")
        for arm, _mods, _reason in _ARM_CATALOG:
            assert f"data-arm='{arm}'" in text, arm  # every arm visible
        for attacker in set(_ATTACKER_NAMES) - _BUILDER_OMITTED_ATTACKERS:
            assert f"data-fw='{attacker}'" in text, attacker
        for attacker in _BUILDER_OMITTED_ATTACKERS:
            assert f"data-fw='{attacker}'" not in text, attacker
        # Ineligible arms are selectable so the server can return their exact
        # fail-closed reason; the repeated reason is compacted into a tooltip.
        # The two source-metric arms are selectable because they do run.
        for arm in _INELIGIBLE_ARMS:
            marker = f"data-arm='{arm}'"
            at = text.index(marker)
            input_tag = text[text.rfind("<input", 0, at):text.find(">", at)]
            assert "disabled" not in input_tag
        assert "source-specific metric - not yet runnable (evaluator not integrated)" in text
        assert "source-specific metric - runnable (replay attacker only)" in text
        assert "badge gray tip" in text and "no evaluator" in text
        assert "badge amber tip" in text and "source-metric" in text
        assert "data-arm='rjudge_release'" in text
        assert "data-arm='gptgeochat_release'" in text
        # native_import remains the real action for the native-only ENGINES.
        assert "native_import" in text
        from experiments.rig_web import _NATIVE_ONLY_ATTACKERS
        assert "native-only" in text  # native-artifact attackers badged
        for attacker in _NATIVE_ONLY_ATTACKERS:
            assert f"data-fw='{attacker}'" in text  # still visible, disabled
    finally:
        app.close()


def test_t3mp3st_is_selectable_and_requires_a_validated_capture_bundle(
    tmp_path: Path,
) -> None:
    from experiments.rig_web import _SUGGEST_STATIC

    repo = tmp_path / "repo"
    results = repo / "runs"
    results.mkdir(parents=True)
    app = RigWebApp(
        results_root=results, state_dir=results / "state", repo_root=repo,
    )
    started = len(app.jobs)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        assert "data-fw='t3mp3st'" in page
        assert "prepare + replay" in page
        assert "t3mp3st" in _SUGGEST_STATIC["attackers"]

        _status, _content_type, body = app.handle("POST", "/build", {
            "mode": "dry_run",
            "corpora": "strongreject_official",
            "attackers": "t3mp3st",
            "judges": "rules",
            "out": "runs/t3-forged",
            "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "T3MP3ST plan bundle path is required" in text
        assert len(app.jobs) == started
    finally:
        app.close()


def test_harmbench_is_selectable_and_requires_its_generated_capture_config(
    tmp_path: Path,
) -> None:
    from experiments.rig_web import _SUGGEST_STATIC

    app = _app(tmp_path)
    started = len(app.jobs)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        assert "data-fw='harmbench'" in page
        assert "data-arm='harmbench_text'" in page
        assert "data-arm='harmbench_multimodal'" in page
        assert "harmbench" in _SUGGEST_STATIC["attackers"]

        _status, _content_type, body = app.handle("POST", "/build", {
            "mode": "dry_run",
            "corpora": "strongreject_official",
            "attackers": "harmbench",
            "judges": "rules",
            "out": "runs/harmbench-forged",
            "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "HarmBench capture config path is required" in text
        assert len(app.jobs) == started
    finally:
        app.close()


def test_prepared_attack_configs_are_verified_and_materialized_portably(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    (repo / "experiments" / "api-targets.json").write_text(json.dumps({
        "openai:test-model": {"modalities": ["text"]},
    }), encoding="utf-8")
    results = repo / "runs"
    results.mkdir()
    app = RigWebApp(
        results_root=results, state_dir=results / "state", repo_root=repo,
    )
    try:
        t3_bundle = results / "t3-bundle.json"
        t3_bundle.write_text(json.dumps({
            "format_version": "ura-t3mp3st-plan-bundle/1",
            "upstream_revision": "a" * 40,
            "source_provider": "openai",
            "source_model": "source-model",
            "corpus": {"sha256": "b" * 64, "records": 1},
            "entries": [],
        }), encoding="utf-8")
        t3_sha = hashlib.sha256(t3_bundle.read_bytes()).hexdigest()
        t3_params = {
            "mode": "dry_run", "corpora": "strongreject_official",
            "attackers": "t3mp3st", "judges": "rules", "seeds": "0",
            "out": "runs/t3", "t3_artifact": str(t3_bundle),
            "t3_artifact_sha": t3_sha,
        }
        assert app._validate_builder(t3_params) == {}
        generated = app._materialize_prepared_attacker_config(t3_params)
        assert generated is not None
        t3_config = json.loads(generated.read_text(encoding="utf-8"))["t3mp3st"]
        assert t3_config == {
            "upstream_revision": "a" * 40,
            "source_provider": "openai",
            "source_model": "source-model",
            "response_artifact": "runs/t3-bundle.json",
            "response_artifact_sha256": t3_sha,
        }

        harm_artifact = results / "harmbench-capture.json"
        harm_artifact.write_text(json.dumps({
            "format_version": "ura-harmbench-transfer-replay/1",
            "upstream_revision": "c" * 40,
            "experiment": "llama2_7b",
            "methods": ["PEZ", "PAP-top5"],
            "cases_per_method": 2,
            "selection": {
                "corpus_name": "harmbench_text", "limit": 1, "sample_seed": 7,
            },
            "source_artifact": {}, "source_requests": [], "cases": [],
            "content_sha256": "d" * 64,
        }), encoding="utf-8")
        harm_sha = hashlib.sha256(harm_artifact.read_bytes()).hexdigest()
        harm_config = results / "harmbench-attackers.json"
        harm_config.write_text(json.dumps({"harmbench": {
            "methods": ["PEZ", "PAP-top5"],
            "experiment": "llama2_7b",
            "upstream_revision": "c" * 40,
            "replay_artifact": str(harm_artifact),
            "replay_artifact_sha256": harm_sha,
        }}), encoding="utf-8")
        harm_params = {
            "mode": "dry_run", "corpora": "harmbench_text",
            "attackers": "harmbench", "judges": "rules", "seeds": "0",
            "sample_seed": "7", "limit": "1", "max_queries": "4",
            "max_turns": "4", "out": "runs/harm",
            "harm_config": str(harm_config),
        }
        assert app._validate_builder(harm_params) == {}
        generated = app._materialize_prepared_attacker_config(harm_params)
        assert generated is not None
        emitted = json.loads(generated.read_text(encoding="utf-8"))["harmbench"]
        assert emitted["replay_artifact"] == "runs/harmbench-capture.json"
        assert emitted["replay_artifact_sha256"] == harm_sha

        inadequate = {**harm_params, "max_queries": "3", "max_turns": "2"}
        errors = app._validate_builder(inadequate)
        assert "at least 4 queries" in errors["max_queries"]
        assert "at least 4 turns" in errors["max_turns"]

        started: list[tuple[str, dict[str, str], dict[str, str]]] = []

        def fake_start(command, values, *, builder_params=None, **_kwargs):
            started.append((command, dict(values), dict(builder_params or {})))
            return Job(
                job_id=f"replay-{len(started)}", command=command,
                argv=build_argv(command, values), directory=results / "state" / "fake",
                process=None, restored_state="complete", restored_exit=0,
            )

        monkeypatch.setattr(app, "start_job", fake_start)
        monkeypatch.setattr(
            app, "_read_lane_projection",
            lambda _params: ({"target_calls": 1, "judge_calls": 0,
                              "http_attempts": 1}, ""),
        )
        common = {
            "confirm": "yes", "mode": "measured", "api": "openai:test-model",
            "judges": "rules", "seeds": "0", "limit": "1",
            "cap_target": "10", "cap_judge": "10", "cap_http": "10",
            "deadline": "600", "scope": "scope-1", "max_age": "24",
            "att_path1": "runs/att.json", "att_sha1": "1" * 64,
            "project_revision": "runs/project.json",
            "project_revision_sha": "2" * 64,
            "source_conformance": "runs/source.json",
            "source_conformance_sha": "3" * 64,
        }
        status, location, _ = app.handle("POST", "/build", {
            **common, "corpora": "strongreject_official",
            "attackers": "t3mp3st", "sample_seed": "0",
            "max_queries": "1", "max_turns": "1", "out": "runs/t3-measured",
            "t3_artifact": str(t3_bundle), "t3_artifact_sha": t3_sha,
        })
        assert status == 303 and location == "/jobs/replay-1"
        command, values, _params = started[-1]
        assert command == "run_matrix" and values["--attackers"] == "t3mp3st"
        generated_path = Path(values["--attacker-config"])
        generated_doc = json.loads(generated_path.read_text(encoding="utf-8"))
        assert generated_doc["t3mp3st"]["response_artifact"] == "runs/t3-bundle.json"
        run_matrix.build_parser().parse_args(build_argv(command, values)[3:])

        status, location, _ = app.handle("POST", "/build", {
            **common, "corpora": "harmbench_text", "attackers": "harmbench",
            "sample_seed": "7", "max_queries": "4", "max_turns": "4",
            "out": "runs/harm-measured", "harm_config": str(harm_config),
        })
        assert status == 303 and location == "/jobs/replay-2"
        command, values, _params = started[-1]
        assert command == "run_matrix" and values["--attackers"] == "harmbench"
        generated_path = Path(values["--attacker-config"])
        generated_doc = json.loads(generated_path.read_text(encoding="utf-8"))
        assert generated_doc["harmbench"]["replay_artifact"] == (
            "runs/harmbench-capture.json"
        )
        run_matrix.build_parser().parse_args(build_argv(command, values)[3:])
    finally:
        app.close()


def test_prepared_capture_forms_validate_preview_and_start_exact_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    results = repo / "runs"
    results.mkdir(parents=True)
    checkout = tmp_path / "HarmBench"
    checkout.mkdir()
    source = tmp_path / "behaviors.csv"
    source.write_text("BehaviorID,Behavior\n1,test\n", encoding="utf-8")
    app = RigWebApp(
        results_root=results, state_dir=results / "state", repo_root=repo,
    )
    captured: list[tuple[str, dict[str, str]]] = []

    def fake_start(command, values, **_kwargs):
        captured.append((command, dict(values)))
        return Job(
            job_id="capture-job", command=command,
            argv=build_argv(command, values), directory=results / "state" / "fake",
            process=None, restored_state="complete", restored_exit=0,
        )

    monkeypatch.setattr(app, "start_job", fake_start)
    try:
        t3_form = {
            "t3cap_corpus": "strongreject_official", "t3cap_limit": "1",
            "t3cap_sample_seed": "0",
            "t3cap_endpoint": "http://127.0.0.1:3333/api/general/plan",
            "t3cap_revision": "a" * 40, "t3cap_provider": "openai",
            "t3cap_model": "source-model", "t3cap_timeout": "120",
            "t3cap_out": str(results / "t3-captures"),
        }
        status, _, body = app.handle("POST", "/build/t3mp3st/capture", t3_form)
        text = body.decode("utf-8")
        assert status == 200 and not captured
        assert "Out-of-band paid/compute step" in text
        assert "experiments.capture_t3mp3st" in text
        status, location, _ = app.handle(
            "POST", "/build/t3mp3st/capture", {**t3_form, "confirm": "yes"},
        )
        assert status == 303 and location == "/jobs/capture-job"
        assert captured[-1][0] == "capture_t3mp3st"
        assert captured[-1][1]["--out"] == str(results / "t3-captures")

        harm_form = {
            "hcap_repo": str(checkout), "hcap_revision": "b" * 40,
            "hcap_source": str(source), "hcap_corpus": "harmbench_text",
            "hcap_methods": "PEZ,PAP-top5", "hcap_experiment": "llama2_7b",
            "hcap_limit": "1", "hcap_sample_seed": "0", "hcap_cases": "1",
            "hcap_artifact_out": str(results / "harm" / "capture.json"),
            "hcap_config_out": str(results / "harm" / "attackers.json"),
        }
        status, _, body = app.handle("POST", "/build/harmbench/prepare", harm_form)
        assert status == 200 and "experiments.harmbench_capture" in body.decode()
        status, location, _ = app.handle(
            "POST", "/build/harmbench/prepare", {**harm_form, "confirm": "yes"},
        )
        assert status == 303 and location == "/jobs/capture-job"
        command, values = captured[-1]
        assert command == "harmbench_capture"
        assert [values["--method"], values["--method#1"]] == ["PEZ", "PAP-top5"]

        status, _, _ = app.handle("POST", "/jobs", {
            "command": "capture_t3mp3st", "--out": str(results / "forged"),
        })
        assert status == 400
    finally:
        app.close()


def test_native_only_note_is_a_tooltip_not_repeated_inline(tmp_path: Path) -> None:
    # The identical native_import explanation lives in ONE tooltip per
    # native-only framework badge, not repeated inline under every one.
    from experiments.rig_web import _NATIVE_ONLY_ATTACKERS
    app = _app(tmp_path)
    try:
        _s, _c, body = app.handle("GET", "/build")
        text = body.decode("utf-8")
        assert "badge gray tip" in text          # focusable tooltip trigger
        assert "class='tiptext'>" in text        # the note lives in a tooltip
        assert "native_import" in text
        # Exactly one native explanation per native-only framework. Other
        # compact builder badges may independently use the same tooltip class.
        assert text.count("native-artifact integration; run_matrix") == len(
            _NATIVE_ONLY_ATTACKERS
        )
    finally:
        app.close()


def test_modality_shown_as_icons_not_word_tags(tmp_path: Path) -> None:
    # Modalities render as colored accessible icon chips, not TEXT/IMAGE word
    # tags, clustered right of the name in a flex header (not trailing it).
    from experiments.rig_web import _mod_icon
    glyph = _mod_icon("text")
    assert "class='modicon m-text'" in glyph  # per-modality colored chip
    assert "title='text'" in glyph and "aria-label='text'" in glyph
    assert "<svg" in glyph  # an icon, not a word
    assert "class='modicon m-video'" in _mod_icon("video")
    app = _app(tmp_path)
    try:
        _s, _c, body = app.handle("GET", "/build")
        text = body.decode("utf-8")
        assert "class='modicon m-" in text  # arm/target modalities use chips
        assert "class='armhead'" in text  # name left, chip cluster right
        assert "class='modset'" in text
        assert "class='fieldcell'" in text  # bottom-aligned field cells
        _s2, _c2, css_body = app.handle("GET", "/static/style.css")
        css = css_body.decode("utf-8")
        # The per-modality chip colors are themed (light + dark definitions).
        assert css.count("--m-text:") == 2 and ".modicon.m-video" in css
        # Field cells bottom-align their inputs across a row (labels grow).
        assert ".fieldcell .fieldlabel { flex:1 0 auto; }" in css
        # Selects are custom-styled everywhere (no generic browser chrome):
        # appearance reset + themed chevron (light and dark), hover and focus.
        assert "select { appearance:none;" in css
        assert css.count("--chevron:url(") == 2  # light + dark chevron
        assert "background-image:var(--chevron)" in css
        assert "select:hover" in css and "select:focus" in css
        # The sticky Compose & review bar is a solid panel - content must not
        # bleed through a fade-to-transparent gradient while scrolling.
        assert "to top, var(--bg), transparent" not in css
        assert ".buildbar { position:sticky" in css
        # Checkboxes and radios are custom-styled console-wide (no generic
        # browser chrome): appearance reset, checked/disabled/focus states.
        assert "input[type=checkbox], input[type=radio] { appearance:none;" in css
        assert "input[type=checkbox]:checked::before" in css  # drawn checkmark
        assert "input[type=radio]:checked::before" in css  # drawn dot
        assert "input[type=checkbox]:disabled" in css
        assert "input[type=checkbox]:focus-visible" in css
    finally:
        app.close()


def test_native_only_attacker_rejected_and_classified() -> None:
    # The native-only classification must match the harness registry, and a
    # native-only attacker in a common-runner lane is rejected before Popen.
    import sys
    sys.path.insert(0, "src")
    from ura.adapters.engines import ATTACKER_NAMES, get_attacker
    from experiments.rig_web import _NATIVE_ONLY_ATTACKERS
    actual_native = {
        name for name in ATTACKER_NAMES
        if getattr(get_attacker(name), "runner_replay_eligible", True) is False
    }
    assert _NATIVE_ONLY_ATTACKERS == actual_native


def test_native_only_attacker_rejected_server_side(tmp_path: Path) -> None:
    app = _app(tmp_path)
    started = len(app.jobs)
    try:
        _s, _c, body = app.handle("POST", "/build", {
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "garak",
            "judges": "rules", "out": "runs/n", "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "native-artifact" in text and "native_import" in text
        assert len(app.jobs) == started  # no Popen
    finally:
        app.close()


def test_agentic_arm_rejected_server_side(tmp_path: Path) -> None:
    import html as html_lib

    from experiments.rig_web import _INELIGIBLE_REASONS

    app = _app(tmp_path)
    started = len(app.jobs)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        marker = "data-arm='agentharm_harmful'"
        at = page.index(marker)
        input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
        assert "disabled" not in input_tag  # operator can choose the row
        assert "no evaluator" in page and "badge gray tip" in page
        reason = html_lib.escape(_INELIGIBLE_REASONS["agentharm_harmful"])
        row = page[page.rfind("<label", 0, at):page.find("</label>", at)]
        assert row.count(reason) == 1  # one custom tooltip, no title duplicate
        badge_at = page.index("<span class='badge gray tip'", at)
        badge_tag = page[badge_at:page.find(">", badge_at)]
        assert "title=" not in badge_tag
        _s, _c, body = app.handle("POST", "/build", {
            "mode": "dry_run", "corpora": "agentharm_harmful",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "out": "runs/a", "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "common-metric-ineligible" in text
        assert "not a native_import target" in text  # honest: NOT the fix path
        assert len(app.jobs) == started  # no Popen
        # A source-specific-metric arm (not agentic) is also rejected.
        _s2, _c2, body2 = app.handle("POST", "/build", {
            "mode": "dry_run", "corpora": "cyberseceval_prompt_injection",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "out": "runs/a2", "seeds": "0",
        })
        assert "common-metric-ineligible" in body2.decode("utf-8")
        assert len(app.jobs) == started
        for arm in (
            "mllmguard_position_swapping",
            "mllmguard_noise_injection",
        ):
            errors = app._validate_builder({
                "mode": "dry_run", "corpora": arm,
                "api": "anthropic:claude-opus-5", "attackers": "replay",
                "judges": "rules", "out": f"runs/{arm}", "seeds": "0",
            })
            assert "truthfulness" in errors.get("corpora", "")
    finally:
        app.close()


def test_source_metric_arm_runnable_and_replay_guarded(tmp_path: Path) -> None:
    # rjudge/gptgeochat have common_metrics_eligible=False but their exact
    # source evaluators ARE implemented, so run_matrix scores them as
    # source-metric lanes (replay only).  The builder must NOT reject them as
    # ineligible, and must require the replay attacker their converter declares.
    app = _app(tmp_path)
    try:
        # replay selected -> no ineligible error, no source-metric guard error.
        errors = app._validate_builder({
            "mode": "dry_run", "corpora": "rjudge_release",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "out": "runs/sm", "seeds": "0",
        })
        assert "corpora" not in errors  # NOT rejected as ineligible
        assert "attackers" not in errors  # replay satisfies the source metric
        # A non-replay attacker alone -> the source-metric guard rejects it
        # (the arm would produce no scored cell), naming the required metric.
        errors2 = app._validate_builder({
            "mode": "dry_run", "corpora": "rjudge_release",
            "api": "anthropic:claude-opus-5", "attackers": "crescendo",
            "judges": "rules", "out": "runs/sm2", "seeds": "0",
        })
        assert "rjudge_safety_judgment" in errors2.get("attackers", "")
        assert "unscored cells" in errors2["attackers"]
        # gptgeochat_release is likewise runnable (not ineligible).
        errors3 = app._validate_builder({
            "mode": "dry_run", "corpora": "gptgeochat_release",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "out": "runs/sm3", "seeds": "0",
        })
        assert "corpora" not in errors3
        mixed = app._validate_builder({
            "mode": "dry_run", "corpora": "rjudge_release",
            "api": "anthropic:claude-opus-5",
            "attackers": "replay,crescendo", "judges": "rules",
            "out": "runs/sm4", "seeds": "0",
        })
        assert "unscored cells" in mixed.get("attackers", "")
    finally:
        app.close()


def test_lane_projection_reads_grand_totals_not_per_attacker(tmp_path: Path) -> None:
    # The no-call preview must gate Start on the GRAND-TOTAL projected call
    # bounds, never a single attacker's smaller per-attacker sub-totals (the
    # projection nests both).  Reading the last per-attacker node would
    # understate the ceiling and enable Start below the true bound.
    app = _isolated_app(tmp_path)
    planning_params = {
        "mode": "measured", "out": "runs/measured", "corpora": "synth",
        "attackers": "replay,crescendo", "judges": "rules",
        "cap_target": "9999", "cap_judge": "9999", "cap_http": "9999",
    }
    proj_dir = app._preflight_output_dir(planning_params)
    assert rig_check.main([
        "--dry-run", "--attackers", "replay,crescendo", "--judges", "rules",
        "--corpora", "synth", "--limit", "2", "--seeds", "0",
        "--max-queries", "4", "--max-turns", "4", "--out", str(proj_dir),
    ]) == 0
    projection_path = next(proj_dir.glob("*.lane-projection.json"))
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    job_dir = tmp_path / "preflight-job"
    job_dir.mkdir()
    (job_dir / "stdout.log").write_text(
        "prospective no-call lane projection written: "
        + json.dumps({"artifact": projection_path.name}) + "\n",
        encoding="utf-8",
    )
    (job_dir / "stderr.log").write_text("", encoding="utf-8")
    app.jobs["preflight"] = Job(
        job_id="preflight", command="run_matrix",
        argv=["python", "-m", "experiments.run_matrix", "--preflight-only",
              "--out", str(proj_dir)],
        directory=job_dir, process=None, builder_params=planning_params,
        restored_state="complete", restored_exit=0,
    )
    # RUN_AND_RETURN permits replacing the provisional planning caps with the
    # exact printed totals. That cap-only change must reuse this same validated
    # projection instead of forcing a redundant second preflight.
    exact_params = {
        **planning_params,
        "cap_target": str(projection["call_projection"]["target_calls"]),
        "cap_judge": str(projection["call_projection"]["judge_calls"]),
        "cap_http": str(projection["call_projection"]["http_attempts"]),
    }
    assert app._preflight_output_dir(exact_params) == proj_dir
    found, why = app._read_lane_projection(exact_params)
    assert why == ""
    assert found == {
        key: projection["call_projection"][key]
        for key in ("target_calls", "judge_calls", "http_attempts")
    }
    # Every grid-defining field remains exact.
    changed_grid = {**exact_params, "attackers": "replay"}
    assert app._read_lane_projection(changed_grid)[0] is None
    app.close()


def test_exact_modality_admission_before_popen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A target that serves only text cannot run a text+image arm - complete
    # exact modality, not "shares any" - and it is rejected on the form.
    app = _app(tmp_path)
    started = len(app.jobs)
    monkeypatch.setattr(
        app, "_model_options",
        lambda: [("prov:textonly", "textonly", ("text",), "api")],
    )
    try:
        _s, _c, body = app.handle("POST", "/build", {
            "mode": "dry_run", "corpora": "mmsafety_official",
            "api": "prov:textonly", "attackers": "replay",
            "judges": "rules", "out": "runs/m", "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "requires all of" in text and "mmsafety_official" in text
        assert len(app.jobs) == started
        # A compatible target (serves image) is admitted: no modality error.
        errors = app._validate_builder({
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "prov:textonly", "attackers": "replay",
            "judges": "rules", "out": "runs/m", "seeds": "0",
        })
        assert "models" not in errors  # text arm on a text target is fine
    finally:
        app.close()


def test_guardrail_separation_and_wiring(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        # Same model for scoring + defense guard is rejected (a guard must not
        # grade its own output).
        errors = app._validate_builder({
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules,guardrail", "defense": "output",
            "defense_guard": "guardrail", "guardrail_model": "vllm:guard",
            "defense_guardrail_model": "vllm:guard", "out": "runs/g", "seeds": "0",
        })
        assert "defense_guardrail_model" in errors
        assert "distinct" in errors["defense_guardrail_model"]
        # The guardrail judge requires a scoring guardrail model.
        errors = app._validate_builder({
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "guardrail", "out": "runs/g", "seeds": "0",
        })
        assert "guardrail_model" in errors
        assert "guardrail_revision" in errors
        defense_missing = app._validate_builder({
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "defense": "output",
            "defense_guard": "guardrail",
            "defense_guardrail_model": "vllm:defender",
            "out": "runs/g", "seeds": "0",
        })
        assert "defense_guardrail_revision" in defense_missing
        assert "defense_guardrail_device" in defense_missing
        # Distinct guards + models wire the separate flags.
        _cmd, values, _p = app._compose_from_builder({
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules,guardrail", "defense": "output",
            "defense_guard": "guardrail", "guardrail_model": "vllm:scorer",
            "guardrail_device": "cuda:0", "defense_guardrail_model": "vllm:defender",
            "out": "runs/g", "seeds": "0",
        })
        assert values["--guardrail-model"] == "vllm:scorer"
        assert values["--guardrail-device"] == "cuda:0"
        assert values["--defense-guardrail-model"] == "vllm:defender"
    finally:
        app.close()


def test_builder_ordinary_dry_run_synth(tmp_path: Path) -> None:
    # An ordinary --dry-run --corpora synth lane (not the diagnostic canary):
    # the builder offers a synth corpus and composes an offline dry run.
    app = _app(tmp_path)
    try:
        _s, _c, body = app.handle("GET", "/build")
        assert "data-arm='synth'" in body.decode("utf-8")  # synth is selectable
        _cmd, values, _p = app._compose_from_builder({
            "mode": "dry_run", "corpora": "synth", "api": "anthropic:claude-opus-5",
            "attackers": "replay", "judges": "rules", "out": "runs/s", "seeds": "0",
        })
        assert values["--dry-run"] == "on"
        assert values["--corpora"] == "synth"
        # No admission receipts leak into an offline lane.
        assert "--source-conformance" not in values
        errors = app._validate_builder({
            "mode": "dry_run", "corpora": "synth", "api": "anthropic:claude-opus-5",
            "attackers": "replay", "judges": "rules", "out": "runs/s", "seeds": "0",
        })
        assert errors == {}
    finally:
        app.close()


def test_no_call_projection_gates_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The preview reads the no-call preflight's lane-projection and blocks Start
    # when an entered ceiling is below the projected required upper bound.
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True)
    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(
        results_root=results, state_dir=tmp_path / "state", repo_root=repo,
    )
    try:
        out_rel = "runs/grid1"
        monkeypatch.setattr(
            app, "_read_lane_projection",
            lambda _params: ({"target_calls": 100, "judge_calls": 50,
                              "http_attempts": 300}, ""),
        )
        # Under-provisioned ceilings block Start.
        html_out, ok = app._ceilings_card({
            "out": out_rel, "cap_target": "50", "cap_judge": "50",
            "cap_http": "300",
        })
        assert ok is False and "below required" in html_out
        # Sufficient ceilings pass.
        html_out, ok = app._ceilings_card({
            "out": out_rel, "cap_target": "100", "cap_judge": "50",
            "cap_http": "300",
        })
        assert ok is True and "covers" in html_out
        # No exact projection yet -> Start remains blocked.
        monkeypatch.setattr(
            app, "_read_lane_projection", lambda _params: (None, "run preflight"),
        )
        _html, ok = app._ceilings_card({"out": "runs/empty"})
        assert ok is False
    finally:
        app.close()


def test_builder_preflight_strips_live_fields_and_uses_dedicated_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(tmp_path / "p.json"))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", "a" * 64)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "s.json"))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "b" * 64)
    app = _app(tmp_path)
    captured: dict[str, object] = {}

    def fake_start(command, values, *, builder_params=None, **_kwargs):
        captured.update(command=command, values=dict(values), params=builder_params)
        return Job(
            job_id="preflight", command=command, argv=build_argv(command, values),
            directory=tmp_path / "fake-job", process=None,
            builder_params=dict(builder_params or {}), restored_state="complete",
            restored_exit=0,
        )

    monkeypatch.setattr(app, "start_job", fake_start)
    measured_out = "runs/measured-lane"
    status, location, _ = app.handle("POST", "/build", {
        "preflight_only": "yes", "mode": "measured",
        "corpora": "strongreject_official", "api": "anthropic:claude-opus-5",
        "attackers": "replay", "judges": "rules", "limit": "1",
        "sample_seed": "0", "seeds": "0", "scope": "scope-1",
        "max_age": "24", "att_path1": "runs/att.json",
        "att_sha1": "c" * 64, "cap_target": "10", "cap_judge": "10",
        "cap_http": "30", "deadline": "600", "out": measured_out,
    })
    assert status == 303 and location == "/jobs/preflight"
    values = captured["values"]
    assert values["--preflight-only"] == "on"
    assert "--execution-scope-id" not in values
    assert "--live-attestation-max-age-hours" not in values
    assert not any(key.startswith("--live-attestation") for key in values)
    preflight_out = Path(values["--out"])
    assert preflight_out != Path(measured_out)
    assert preflight_out.is_relative_to(app.results_root / "preflight")
    assert captured["params"]["out"] == measured_out
    app.close()


def test_local_targets_repo_root_parity() -> None:
    from experiments.rig_web import build_argv
    argv = build_argv("local_targets", {"--repo-root": "/some/repo", "--refresh": "on"})
    assert "--repo-root" in argv and "/some/repo" in argv


def test_builder_mode_validation_rejects_before_subprocess(tmp_path: Path) -> None:
    # Mode-specific validation runs BEFORE any subprocess exists.  The old
    # console accepted a diagnostic canary with --limit 8; that is now a
    # field-level rejection (a canary is exactly one whole source cluster).
    app = _app(tmp_path)
    started = len(app.jobs)
    status, _, body = app.handle("POST", "/build", {
        "mode": "diagnostic_canary", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules,llm", "limit": "8", "sample_seed": "0",
        "out": "runs/thesis/canary", "seeds": "0",
    })
    text = body.decode("utf-8")
    assert status == 200
    assert "exactly --limit 1" in text
    assert "fielderr" in text  # rendered next to the control
    assert len(app.jobs) == started  # nothing composed or executed

    # Attestation probe: shape constraints are all enforced.
    status, _, body = app.handle("POST", "/build", {
        "mode": "attestation_probe", "corpora": "a,b",
        "api": "x,y", "attackers": "replay,crescendo", "judges": "rules",
        "limit": "3", "out": "runs/p", "seeds": "0,1", "defense": "input",
        "max_queries": "2", "max_turns": "2",
    })
    text = body.decode("utf-8")
    assert status == 200 and len(app.jobs) == started
    for message in (
        "exactly one target", "exactly one corpus",
        "exactly the replay attacker", "exactly one seed",
        "defense none", "--limit 1 or 2",
    ):
        assert message in text, message

    # A dry canary is composed as offline-synthetic (corpora synth, targets
    # dropped) rather than rejected, so a submission with an arm/target still
    # selected validates and starts a job.  A too-large limit is still caught.
    status, _, body = app.handle("POST", "/build", {
        "mode": "diagnostic_canary", "canary_dry": "on",
        "corpora": "strongreject_official", "api": "anthropic:claude-opus-5",
        "attackers": "replay", "judges": "rules", "limit": "8",
        "out": "runs/c", "seeds": "0",
    })
    text = body.decode("utf-8")
    assert status == 200 and len(app.jobs) == started
    assert "exactly --limit 1" in text

    # Measured execution requires receipts, scope, age, attestations, caps.
    status, _, body = app.handle("POST", "/build", {
        "mode": "measured", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "out": "runs/m", "seeds": "0",
    })
    text = body.decode("utf-8")
    assert status == 200 and len(app.jobs) == started
    for field in ("scope", "max_age", "att", "cap_target", "cap_judge",
                  "cap_http", "deadline", "limit", "project_revision"):
        assert f"<strong>{field}</strong>" in text, field


def test_builder_dry_run_composes_and_starts(tmp_path: Path) -> None:
    # The ordinary synthetic dry run and the typed synthetic diagnostic
    # canary both compose a valid no-provider command and start directly.
    app = _app(tmp_path)
    command, values, params = app._compose_from_builder({
        "mode": "dry_run", "corpora": "synth", "attackers": "replay",
        "judges": "rules,llm", "judge_model": "mock", "out": "runs/dry",
        "seeds": "0", "limit": "2",
    })
    assert command == "run_matrix"
    assert values["--dry-run"] == "on"
    assert values["--judge-model"] == "mock"
    assert params["mode"] == "dry_run"
    argv = build_argv(command, values)
    assert argv[1:3] == ["-m", "experiments.run_matrix"]
    # The composed argv parses with the REAL run_matrix parser.
    parsed = run_matrix.build_parser().parse_args(argv[3:])
    assert parsed.dry_run is True and parsed.corpora == "synth"

    command, values, _params = app._compose_from_builder({
        "mode": "diagnostic_canary", "canary_dry": "on", "corpora": "synth",
        "attackers": "replay", "judges": "rules", "limit": "1",
        "out": "runs/c", "seeds": "0",
    })
    assert values["--diagnostic-canary"] == "on"
    assert values["--dry-run"] == "on"
    parsed = run_matrix.build_parser().parse_args(
        build_argv(command, values)[3:]
    )
    assert parsed.diagnostic_canary is True and parsed.dry_run is True
    # Dry composition never leaks env receipts into the offline command.
    assert "--project-revision" not in build_argv(command, values)

    status, location, _ = app.handle("POST", "/build", {
        "mode": "dry_run", "corpora": "synth", "attackers": "replay",
        "judges": "rules", "out": "runs/dry", "seeds": "0",
    })
    assert status == 303 and location.startswith("/jobs/")
    app.stop_job(location.rsplit("/", 1)[1])
    app.close()


def test_builder_paid_modes_preview_exact_argv_then_confirm(
    tmp_path: Path, monkeypatch,
) -> None:
    # A non-dry lane never starts on first submit: the exact complete argv
    # and the call ceilings are shown for confirmation first.
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(tmp_path / "r.json"))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", "a" * 64)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "s.json"))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "b" * 64)
    app = _app(tmp_path)
    monkeypatch.setattr(
        app, "_read_lane_projection",
        lambda _params: ({"target_calls": 4, "judge_calls": 4,
                          "http_attempts": 12}, ""),
    )
    form = {
        "mode": "attestation_probe", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "limit": "1", "seeds": "0", "sample_seed": "0",
        "scope": "acct-scope-1", "max_queries": "1", "max_turns": "1",
        "cap_target": "4", "cap_judge": "4", "cap_http": "12",
        "deadline": "600", "out": "runs/probe",
    }
    started = len(app.jobs)
    status, _, body = app.handle("POST", "/build", form)
    text = body.decode("utf-8")
    assert status == 200 and len(app.jobs) == started  # preview, no job
    assert "Confirm paid execution" in text
    assert "--attestation-probe" in text
    assert "--max-total-target-calls" in text and ">4<" in text
    assert "spends real money" in text
    # The confirmation re-submits the identical parameters plus confirm=yes.
    assert "name='confirm' value='yes'" in text
    form["confirm"] = "yes"
    status, location, _ = app.handle("POST", "/build", form)
    assert status == 303 and len(app.jobs) == started + 1
    job = app.jobs[location.rsplit("/", 1)[1]]
    assert "--attestation-probe" in job.argv
    assert job.builder_params and job.builder_params["mode"] == "attestation_probe"
    # The probe argv parses with the real parser.
    run_matrix.build_parser().parse_args(job.argv[3:])
    app.stop_job(job.job_id)
    app.close()


def test_builder_targets_split_hosted_and_local_vllm_roster(tmp_path: Path) -> None:
    # Targets are hosted API (composed into --api) and local vLLM (--local),
    # the latter drawn from the configured registry plus the vLLM roster; the
    # focal env pair are hosted. Compose splits them correctly.  The app runs
    # over temporary state so the checkout is never touched.
    from experiments import local_targets

    app = _app(tmp_path)
    page = app.handle("GET", "/build")[2].decode("utf-8")
    assert "Hosted API" in page and "Local vLLM" in page
    assert "data-kind='api'" in page and "data-kind='local'" in page
    # The curated vLLM roster is real and modality-tagged.
    roster = local_targets.roster_models(include_unfit=True)
    assert len(roster) > 10
    assert any("audio" in m["modalities"] for m in roster)
    # A build with a local target composes --local and binds --local-config
    # only when a local target is selected.
    _cmd, values, _params = app._compose_from_builder({
        "mode": "measured", "corpora": "strongreject_official",
        "local": "vllm:Qwen/Qwen3-VL-8B-Instruct", "attackers": "replay",
        "judges": "rules", "out": "runs/x",
    })
    assert values["--local"] == "vllm:Qwen/Qwen3-VL-8B-Instruct"
    assert "--api" not in values
    app.close()


def test_dashboard_and_builder_show_startup_system_and_gpu_hardware(
    tmp_path: Path,
) -> None:
    gpu_hardware = {
        "available": True,
        "source": "nvidia-smi",
        "gpu_count": 2,
        "aggregate_vram_gib": 47.98,
        "max_gpu_vram_gib": 23.99,
        "gpus": [
            {
                "index": index,
                "name": "NVIDIA RTX 4090",
                "memory_total_mib": 24564,
                "vram_gib": 23.99,
                "compute_capability": "8.9",
                "pci_bus_id": f"00000000:{index + 1:02X}:00.0",
                "driver_version": "610.57.04",
            }
            for index in range(2)
        ],
    }
    system_hardware = {
        "available": True,
        "platform": "Linux-6.8.0-x86_64",
        "cpu_model": "AMD Ryzen Threadripper TEST",
        "logical_cpu_count": 64,
        "physical_cpu_count": 32,
        "total_ram_bytes": 128 * 1024 ** 3,
        "total_ram_gib": 128.0,
    }
    app = RigWebApp(
        results_root=tmp_path / "runs", state_dir=tmp_path / "state",
        gpu_hardware=gpu_hardware, system_hardware=system_hardware,
    )
    dashboard = app.handle("GET", "/")[2].decode("utf-8")
    builder = app.handle("GET", "/build")[2].decode("utf-8")

    assert "Rig hardware" in dashboard
    for expected in (
        "Linux-6.8.0-x86_64", "AMD Ryzen Threadripper TEST",
        "32 physical / 64 logical", "128.0 GiB", "NVIDIA RTX 4090",
        "23.99 GiB VRAM", "SM 8.9", "PCI 00000000:01:00.0",
        "driver 610.57.04", "47.98 GiB",
    ):
        assert expected in dashboard
    assert "Local hardware" in builder
    assert "GPU 0 - NVIDIA RTX 4090" in dashboard
    assert "AMD Ryzen Threadripper TEST" in builder
    assert "128.0 GiB RAM" in builder
    assert "NVIDIA RTX 4090" in builder
    app.close()


def test_builder_model_filters_and_quantization_warning_are_rendered(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "api-targets.example.json").write_text(json.dumps({
        "anthropic:claude-test": {"modalities": ["text"]},
        "openai:gpt-test": {"modalities": ["text", "image"]},
    }), encoding="utf-8")
    local_checkpoint = f"vllm:{(tmp_path / 'checkpoint').resolve()}"
    (rig / "local-targets.example.json").write_text(json.dumps({
        local_checkpoint: {
            "digest": "6" * 64, "modalities": ["text"],
            "parameter_count_b": 7,
        },
    }), encoding="utf-8")
    (rig / "vllm-roster.example.json").write_text(json.dumps({
        "vllm_version": "0.test",
        "models": {
            "vllm:org/Tiny-10M": {
                "revision": "1" * 40, "modalities": ["text"],
                "parameter_count_b": 0.01,
            },
            "vllm:org/Model-70B": {
                "revision": "2" * 40, "modalities": ["text"],
                "parameter_count_b": 70,
                "quantization": "bitsandbytes",
            },
            "vllm:org/Model-30B": {
                "revision": "7" * 40, "modalities": ["text"],
                "parameter_count_b": 30,
            },
            "vllm:org/Model-34B": {
                "revision": "9" * 40, "modalities": ["text"],
                "parameter_count_b": 34,
            },
            "vllm:org/Override-7B": {
                "revision": "8" * 40, "modalities": ["text"],
                "parameter_count_b": 7, "quantization": "gptq",
            },
            "vllm:org/Lower-7B": {
                "revision": "OPERATOR_TODO", "modalities": ["text"],
                "parameter_count_b": 7,
            },
            "vllm:org/Audio-7B": {
                "revision": "4" * 40, "modalities": ["text", "audio"],
                "parameter_count_b": 7,
            },
            "vllm:org/DigestOnly-7B": {
                "digest": "5" * 64, "modalities": ["text"],
                "parameter_count_b": 7,
            },
            "vllm:org/Huge-4T": {
                "revision": "3" * 40, "modalities": ["text"],
                "parameter_count_b": 4000,
            },
            "vllm:org/Unknown": {
                "revision": "4" * 40, "modalities": ["text"],
            },
        },
    }), encoding="utf-8")
    gpu_hardware = {
        "available": True, "source": "nvidia-smi", "gpu_count": 2,
        "aggregate_vram_gib": 47.98, "max_gpu_vram_gib": 23.99,
        "gpus": [
            {"index": index, "name": "RTX 4090", "vram_gib": 23.99,
             "memory_total_mib": 24564, "compute_capability": "8.9"}
            for index in range(2)
        ],
    }
    app = RigWebApp(
        results_root=tmp_path / "runs", state_dir=tmp_path / "state",
        repo_root=repo, gpu_hardware=gpu_hardware,
        system_hardware={"available": False, "platform": "test",
                         "cpu_model": "test", "logical_cpu_count": None,
                         "physical_cpu_count": None, "total_ram_bytes": None,
                         "total_ram_gib": None},
    )
    page = app.handle("GET", "/build")[2].decode("utf-8")

    assert "id='api-provider-filter'" in page
    assert "<option value='all' selected>All</option>" in page
    assert "data-provider='anthropic'" in page
    assert "data-provider='openai'" in page
    assert "id='local-name-filter'" in page
    assert "id='local-param-range' type='range' min='0.01' max='3000'" in page
    assert "id='local-param-number' type='number' min='0.01' max='3000'" in page
    assert "id='local-compatible-filter' checked" in page
    assert "id='local-unknown-filter'" in page
    unknown_filter_at = page.index("id='local-unknown-filter'")
    unknown_filter_tag = page[
        page.rfind("<input", 0, unknown_filter_at):page.find(">", unknown_filter_at)
    ]
    assert "checked" not in unknown_filter_tag
    assert "Include unknown fit" in page
    assert "Live runs require an explicit per-model precision" in page
    assert "Automatic 16/8/4-bit fit" in page
    assert "automatically selected 16-, 8-, or 4-bit precision" in page
    assert "<option value='none'>16-bit (BF16/FP16)</option>" in page
    assert "<option value='fp8'>8-bit FP8</option>" in page
    assert "Compatible with this rigincludes" not in page
    assert "data-name='vllm:org/Model-70B'" in page
    assert "data-params-b='70'" in page
    assert "data-compatible='true'" in page
    assert "badge green precision-badge precision-16" in page
    assert "badge blue precision-badge precision-8" in page
    assert "8-bit FP8 required" in page
    assert "badge amber precision-badge precision-4" in page
    assert "4-bit BitsAndBytes required" in page
    assert "4-bit GPTQ override" in page
    assert "name.indexOf(query)!==-1" in page  # literal substring, no fuzzy match
    assert "params<=max" in page and "compatOk" in page  # combinative filters
    assert "includeUnknown" in page
    assert "fit==='true'||(fit==='false'&&!compatible)||" in page
    assert "(fit==='unknown'&&includeUnknown)" in page
    assert "fit unknown" in page
    assert "selected · fit unknown" in page  # live badge update for explicit choice
    assert "A presentation filter never changes a selected target" in page
    unknown = "vllm:org/Unknown"
    unknown_at = page.index(f"data-model='{unknown}'")
    unknown_input = page[
        page.rfind("<input", 0, unknown_at):page.find(">", unknown_at)
    ]
    assert "disabled" not in unknown_input
    assert "data-compatible='unknown'" in page[
        page.rfind("<div class='modelrow'", 0, unknown_at):unknown_at
    ]
    unknown_row = page[
        page.rfind("<div class='modelrow'", 0, unknown_at):
        page.find("</div>", unknown_at)
    ]
    assert "badge gray precision-badge precision-unknown" in unknown_row
    assert "<span class='precision-label'>fit unknown</span>" in unknown_row
    unknown_tooltip = (
        "The operator must choose a per-model precision before a live run."
    )
    assert unknown_row.count(unknown_tooltip) == 1
    unknown_badge_at = unknown_row.index(
        "<span class='badge gray precision-badge precision-unknown tip'"
    )
    unknown_badge_tag = unknown_row[
        unknown_badge_at:unknown_row.find(">", unknown_badge_at)
    ]
    assert "tabindex='0'" in unknown_badge_tag
    assert "title=" not in unknown_badge_tag
    assert "label.textContent=value==='auto'?'fit unknown'" in page
    assert "badge.textContent" not in page
    assert "16-bit fit unknown" not in unknown_row

    # Rendering, validation, and generated execution config share one
    # precedence: per-model selection, then the submitted global default.
    model_34b = "vllm:org/Model-34B"
    global_none_page = app._build_page(prefill={
        "quantization": "none", f"quantization::{model_34b}": "auto",
    }).decode("utf-8")
    model_34b_at = global_none_page.index(f"data-model='{model_34b}'")
    model_34b_row = global_none_page[
        global_none_page.rfind("<div class='modelrow'", 0, model_34b_at):
        global_none_page.find("<div class='modelrow'", model_34b_at)
    ]
    assert "data-compatible='false'" in model_34b_row
    assert "16-bit does not fit" in model_34b_row

    tiny = "vllm:org/Tiny-10M"
    global_bnb_page = app._build_page(prefill={
        "quantization": "bitsandbytes", f"quantization::{tiny}": "auto",
    }).decode("utf-8")
    tiny_at = global_bnb_page.index(f"data-model='{tiny}'")
    tiny_row = global_bnb_page[
        global_bnb_page.rfind("<div class='modelrow'", 0, tiny_at):
        global_bnb_page.find("<div class='modelrow'", tiny_at)
    ]
    assert "data-compatible='true'" in tiny_row
    assert "4-bit BitsAndBytes override" in tiny_row

    per_model_page = app._build_page(prefill={
        "quantization": "bitsandbytes", f"quantization::{tiny}": "none",
    }).decode("utf-8")
    tiny_at = per_model_page.index(f"data-model='{tiny}'")
    tiny_row = per_model_page[
        per_model_page.rfind("<div class='modelrow'", 0, tiny_at):
        per_model_page.find("<div class='modelrow'", tiny_at)
    ]
    assert "16-bit override" in tiny_row

    incompatible = "vllm:org/Huge-4T"
    incompatible_at = page.index(f"data-model='{incompatible}'")
    incompatible_input = page[
        page.rfind("<input", 0, incompatible_at):page.find(">", incompatible_at)
    ]
    assert "disabled" in incompatible_input
    audio = "vllm:org/Audio-7B"
    audio_at = page.index(f"data-name='{audio}'")
    audio_row = page[page.rfind("<div class='modelrow'", 0, audio_at):
                     page.find("</div>", audio_at)]
    assert "data-mods='text'" in audio_row and "data-mods='text,audio'" not in audio_row
    audio_config = json.loads(
        app._materialize_selected_local_config([audio]).read_text(encoding="utf-8")
    )
    assert audio_config[audio]["modalities"] == ["text"]
    audio_errors = app._validate_builder({
        "mode": "dry_run", "corpora": "jalmbench_audio", "local": audio,
        "attackers": "replay", "judges": "rules", "out": "runs/audio",
    })
    assert "serves ['text']" in audio_errors["models"]
    assert "requires all of ['audio', 'text']" in audio_errors["models"]
    # A lower, compatible roster row remains a standard labelled radio even
    # before its live revision is pinned; its quantization control is separate
    # from the checkbox label, so neither control captures the other's clicks.
    lower = "vllm:org/Lower-7B"
    marker = f"data-model='{lower}'"
    at = page.index(marker)
    input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
    assert "type='radio'" in input_tag and "name='local_choice'" in input_tag
    assert "disabled" not in input_tag
    id_start = input_tag.index("id='") + len("id='")
    control_id = input_tag[id_start:input_tag.index("'", id_start)]
    row_start = page.rfind("<div class='modelrow'", 0, at)
    quant_at = page.index(f"name='quantization::{lower}'", at)
    assert f"for='{control_id}'" in page[row_start:at]
    assert "</label><div class='modelquant'>" in page[at:quant_at]
    quant_tag = page[page.rfind("<select", at, quant_at):page.find(">", quant_at)]
    assert "disabled" not in quant_tag
    # Filter controls have no server-side campaign fields. A submitted target
    # remains authoritative and composes through the normal validated path.
    assert "name='api-provider-filter'" not in page
    _command, values, _params = app._compose_from_builder({
        "mode": "measured", "corpora": "synth", "api": "openai:gpt-test",
        "attackers": "replay", "judges": "rules", "out": "runs/filter-test",
    })
    assert values["--api"] == "openai:gpt-test"
    _command, values, _params = app._compose_from_builder({
        "mode": "dry_run", "corpora": "synth", "local": lower,
        "attackers": "replay", "judges": "rules",
        "limit": "1", "seeds": "0", "max_queries": "1", "max_turns": "1",
        "out": str(tmp_path / "lower-row"),
    })
    assert "--local" not in values and "--local-config" not in values
    dry_errors = app._validate_builder(_params)
    assert "models" not in dry_errors
    assert run_matrix.main(build_argv("run_matrix", values)[3:]) == 0
    live_errors = app._validate_builder({
        **_params, "mode": "measured",
    })
    assert "hub vLLM targets require a 40-64 hex revision" in live_errors["models"]
    digest_only_errors = app._validate_builder({
        **_params, "mode": "measured", "local": "vllm:org/DigestOnly-7B",
    })
    assert "hub vLLM targets require a 40-64 hex revision" in (
        digest_only_errors["models"]
    )
    checkpoint_errors = app._validate_builder({
        **_params, "mode": "measured", "local": local_checkpoint,
    })
    assert "models" not in checkpoint_errors
    unknown_errors = app._validate_builder({
        **_params, "mode": "measured", "local": unknown,
    })
    assert "explicit per-model precision" in unknown_errors["models"]
    explicit_unknown_params = {
        **_params, "mode": "measured", "local": unknown,
        f"quantization::{unknown}": "fp8",
    }
    explicit_unknown_errors = app._validate_builder(explicit_unknown_params)
    assert "models" not in explicit_unknown_errors
    explicit_unknown_config = json.loads(
        app._materialize_selected_local_config(
            [unknown], quantization_overrides={unknown: "fp8"},
        ).read_text(encoding="utf-8")
    )
    assert explicit_unknown_config[unknown]["quantization"] == "fp8"
    assert explicit_unknown_config[unknown]["allow_unknown_fit"] is True
    auto_unknown_config = json.loads(
        app._materialize_selected_local_config(
            [unknown], quantization_overrides={unknown: "auto"},
        ).read_text(encoding="utf-8")
    )
    assert "allow_unknown_fit" not in auto_unknown_config[unknown]

    global_none_errors = app._validate_builder({
        **_params, "mode": "measured", "local": model_34b,
        "quantization": "none", f"quantization::{model_34b}": "auto",
    })
    assert "known incompatible" in global_none_errors["models"]
    global_none_config = json.loads(
        app._materialize_selected_local_config(
            [model_34b], default_quantization="none",
            quantization_overrides={model_34b: "auto"},
        ).read_text(encoding="utf-8")
    )
    assert global_none_config[model_34b]["quantization"] == "none"

    global_bnb_errors = app._validate_builder({
        **_params, "mode": "measured", "local": tiny,
        "quantization": "bitsandbytes", f"quantization::{tiny}": "auto",
    })
    assert "models" not in global_bnb_errors
    global_bnb_config = json.loads(
        app._materialize_selected_local_config(
            [tiny], default_quantization="bitsandbytes",
            quantization_overrides={tiny: "auto"},
        ).read_text(encoding="utf-8")
    )
    assert global_bnb_config[tiny]["quantization"] == "bitsandbytes"
    per_model_config = json.loads(
        app._materialize_selected_local_config(
            [tiny], default_quantization="bitsandbytes",
            quantization_overrides={tiny: "none"},
        ).read_text(encoding="utf-8")
    )
    assert per_model_config[tiny]["quantization"] == "none"
    incompatible_errors = app._validate_builder({
        **_params, "mode": "measured", "local": incompatible,
    })
    assert "known incompatible" in incompatible_errors["models"]
    app.close()


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
    # Budgets render from the editable config (ledger defaults as fallback)
    # and an empty results root degrades gracefully.  Charts come ONLY from
    # schema-valid producer artifacts (see the real Level-1/Level-2 tests);
    # an unrecognized ad-hoc JSON shape renders nothing.
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "Budgets" in text and "Anthropic" in text and "$100" in text
    assert "No Level-1/Level-2 report" in text  # graceful empty state
    # A fake rows/asr table is NOT a Level-2 report and must not chart.
    (app.results_root / "level2.json").write_text(json.dumps({
        "rows": [{"model": "fable", "asr": 0.12}],
    }), encoding="utf-8")
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "barchart" not in text
    assert "No Level-1/Level-2 report" in text
    app.close()


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
        if name in {"capture_t3mp3st", "harmbench_capture"}:
            # These two commands link to the semantically validated Build
            # workflows instead of exposing a generic form that could bypass
            # their pre-subprocess checks.
            assert run_text.count(f"data-name='{name}'") == 1
            assert "/build#prepared-workflows" in run_text
        else:
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


def test_run_forms_use_select_and_datalist_without_weakening_argv(
    tmp_path: Path,
) -> None:
    # UI affordances are presentation only: enumerated flags render as a
    # <select> of the exact argparse choices, suggestion fields get a
    # <datalist>, but build_argv still rejects anything off-contract.
    app = _app(tmp_path)
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
    from experiments.rig_web import ConsoleDB
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


# -- CLI/UI interface parity against the REAL module parsers ----------------


def _captured_parser(module, probe_argv: list[str]) -> argparse.ArgumentParser:
    """The actual ArgumentParser a CLI's main() builds, without running it."""

    holder: dict[str, argparse.ArgumentParser] = {}

    class _Captured(Exception):
        pass

    original = argparse.ArgumentParser.parse_args

    def capture(self, args=None, namespace=None):  # noqa: ANN001
        holder["parser"] = self
        raise _Captured

    argparse.ArgumentParser.parse_args = capture
    try:
        try:
            module.main(probe_argv)
        except _Captured:
            pass
    finally:
        argparse.ArgumentParser.parse_args = original
    assert "parser" in holder, f"{module.__name__} built no parser"
    return holder["parser"]


def _parser_options(parser: argparse.ArgumentParser) -> set[str]:
    return {
        option
        for action in parser._actions  # noqa: SLF001 - introspection in tests
        for option in action.option_strings
        if option.startswith("--")
    }


def test_matrix_params_match_real_run_matrix_parser_exactly() -> None:
    # The console's run_matrix/rig_check surface is one-to-one with the real
    # parser: no phantom UI flag (the old --models bug) and no missing CLI
    # option.  --help is the only exclusion.
    real = _parser_options(run_matrix.build_parser()) - {"--help"}
    ui = {param.flag for param in _MATRIX_PARAMS}
    assert ui - real == set(), f"UI flags absent from run_matrix: {ui - real}"
    assert real - ui == set(), f"run_matrix flags absent from the UI: {real - ui}"


def test_every_ui_command_parses_with_its_real_module_parser() -> None:
    # For every allowlisted command, a fully-populated form must produce an
    # argv the REAL module parser accepts.  Merely comparing option names
    # would miss type and choice mismatches.
    import importlib

    from experiments.rig_web import COMMANDS

    # Curated full forms; mutually-exclusive alternatives are exercised as
    # separate variants.  Values satisfy argparse types/choices only (no
    # module logic runs).
    forms: dict[str, list[dict[str, str]]] = {
        "project_revision": [
            {"--expected-revision": "a" * 40, "--out": "runs/pr"},
            {"--validate": "runs/pr/x.json", "--sha256": "b" * 64},
        ],
        "source_conformance": [{
            "--scaffold": "on", "--arm": "strongreject_official",
            "--observation": "strongreject_official=runs/obs",
            "--out": "runs/sc.json", "--source-config": "experiments/s.json",
        }],
        "capture_t3mp3st": [{
            "--corpus": "strongreject_official",
            "--source-config": "experiments/s.json", "--limit": "1",
            "--sample-seed": "0",
            "--endpoint": "http://127.0.0.1:3333/api/general/plan",
            "--upstream-revision": "a" * 40, "--source-provider": "openai",
            "--source-model": "source-model", "--timeout-seconds": "120",
            "--out": "runs/t3",
        }],
        "harmbench_capture": [{
            "--repo": "/data/HarmBench", "--revision": "a" * 40,
            "--source": "/data/harmbench.csv", "--corpus-name": "harmbench_text",
            "--method": "PEZ", "--method#1": "PAP-top5",
            "--experiment": "llama2_7b", "--limit": "1",
            "--sample-seed": "0", "--cases-per-method": "1",
            "--artifact-out": "runs/harm/capture.json",
            "--attacker-config-out": "runs/harm/attackers.json",
            "--python": "/usr/bin/python", "--credential-env": "HF_TOKEN",
            "--timeout-seconds": "600",
        }],
        "rig_check": [],  # forwards the run_matrix surface (asserted above)
        "run_matrix": [{
            "--dry-run": "on", "--corpora": "synth", "--attackers": "replay",
            "--judges": "rules", "--judge-model": "mock", "--limit": "2",
            "--sample-seed": "0", "--seeds": "0", "--max-queries": "1",
            "--max-turns": "1", "--group": "model,source",
            "--defense": "both", "--defense-guard": "guardrail",
            "--guardrail-model": "m", "--guardrail-revision": "c" * 40,
            "--guardrail-device": "cpu", "--defense-guardrail-model": "n",
            "--defense-guardrail-revision": "d" * 40,
            "--defense-guardrail-device": "cpu", "--quantization": "awq",
            "--dtype": "bfloat16", "--max-total-target-calls": "10",
            "--max-total-judge-calls": "10", "--max-total-http-attempts": "30",
            "--deadline-seconds": "600", "--lock-stale-seconds": "60",
            "--execution-scope-id": "scope-1",
            "--live-attestation#1": "runs/a.json",
            "--live-attestation-sha256#1": "e" * 64,
            "--live-attestation#2": "runs/b.json",
            "--live-attestation-sha256#2": "f" * 64,
            "--live-attestation-max-age-hours": "24",
            "--project-revision": "runs/pr.json",
            "--project-revision-sha256": "a" * 64,
            "--source-conformance": "runs/sc.json",
            "--source-conformance-sha256": "b" * 64,
            "--models": "claude", "--api-config": "experiments/a.json",
            "--local-config": "experiments/l.json",
            "--source-config": "experiments/s.json",
            "--attacker-config": "experiments/atk.json",
            "--reset-open-circuits": "on", "--preflight-only": "on",
            "--out": "runs/exp",
        }],
        "live_attestation": [
            {"--probe-root": "runs/probe", "--execution-scope-id": "s",
             "--out": "runs/att.json"},
            {"--validate": "runs/att.json", "--sha256": "a" * 64},
        ],
        "lane_canary": [{
            "--results": "runs/c", "--eligibility": "runs/c/e.json",
            "--out-dir": "runs/c/out",
        }],
        "level1_evidence": [{
            "--eligibility": "runs/a/e.json", "--eligibility#1": "runs/b/e.json",
            "--results": "runs/a", "--results#1": "runs/b",
            "--live-attestation": "runs/att.json",
            "--live-attestation-sha256": "a" * 64,
            "--out-json": "runs/l1.json", "--out-csv": "runs/l1.csv",
        }],
        "suite_summary": [{
            "--results": "runs/a", "--native": "runs/n.json",
            "--eligibility": "runs/a/e.json",
            "--source-config": "experiments/s.json", "--out": "runs/suite",
        }],
        "level2_report": [{
            "--results": "runs/a", "--results#1": "runs/b",
            "--native": "runs/n.json", "--out-json": "runs/l2.json",
            "--out-csv": "runs/l2.csv", "--out-md": "runs/l2.md",
        }],
        "human_audit": [
            {"--results": "runs/a", "--prepare": "40",
             "--acknowledge-sensitive-content": "on",
             "--output": "runs/a/audit.csv", "--seed": "1"},
            {"--results": "runs/a", "--labels": "runs/a/labels.csv",
             "--allow-single-rater": "on", "--bootstrap-resamples": "100",
             "--alpha": "0.05", "--seed": "0"},
            {"--results": "runs/a", "--prepare-source-task": "10",
             "--acknowledge-sensitive-content": "on"},
            {"--results": "runs/a", "--source-task-labels": "runs/a/s.csv"},
        ],
        "figures": [
            {"--synth": "on", "--out": "runs/figs"},
            {"--results": "runs/a", "--left-model": "l", "--right-model": "r",
             "--human-audit": "runs/a/h.json", "--human-audit-sha256": "a" * 64,
             "--strongreject-corpus": "strongreject_official",
             "--mmsafety-corpus": "mmsafety_official",
             "--mossbench-corpus": "mossbench_official",
             "--bootstrap": "100", "--seed": "0", "--out": "runs/figs"},
        ],
        "paired_compare": [{
            "--results": "runs/a", "--left-model": "l", "--right-model": "l",
            "--left-defense": "none", "--right-defense": "none",
            "--attacker": "replay", "--right-attacker": "crescendo",
            "--corpus": "strongreject_official", "--mode": "auto",
            "--bootstrap": "100", "--seed": "0", "--permutations": "100",
            "--alpha": "0.05", "--assume-exchangeable": "on",
            "--output": "runs/pc.json",
        }],
        "judge_sensitivity": [{
            "--results": "runs/a", "--attacker": "replay",
            "--corpus": "strongreject_official", "--output": "runs/js.json",
        }],
        "kappa": [{
            "--results": "runs/a", "--attacker": "replay",
            "--corpus": "strongreject_official",
        }],
        "transfer_matrix": [{
            "--results": "runs/a", "--attacker": "replay",
            "--corpus": "strongreject_official",
            "--minimum-unique-clusters": "2", "--bootstrap": "100",
            "--seed": "0", "--alpha": "0.05",
        }],
        "export_jalmbench": [{
            "--source": "runs/src", "--max-records": "10",
            "--max-total-bytes": "1000", "--out": "runs/out",
        }],
        "export_vlsbench": [{
            "--source": "runs/src", "--max-records": "10",
            "--max-total-bytes": "1000", "--out": "runs/out",
        }],
        "native_import": [
            {"--config": "runs/cfg.json", "--out": "runs/out"},
            {"--validate": "runs/native.json"},
        ],
        "syn_compat": [
            {"--generate": "on", "--out": "runs/syn", "--seed": "0",
             "--perturbations-per-template": "2"},
            {"--check": "on", "--cases": "runs/syn/cases.jsonl",
             "--metadata": "runs/syn/meta.json"},
            {"--evaluate": "on", "--cases": "runs/syn/cases.jsonl",
             "--metadata": "runs/syn/meta.json", "--out": "runs/syn/out"},
        ],
        "local_targets": [{"--refresh": "on", "--vllm-version": "0.27.1"}],
        "webui_selftest": [{"--selftest-sleep": "0"}],
    }
    assert set(forms) == set(COMMANDS), (
        sorted(set(forms) ^ set(COMMANDS))
    )
    for name, entry in COMMANDS.items():
        if name == "rig_check":
            continue  # pure argv forwarder to run_matrix (covered above)
        module = importlib.import_module(entry.module)
        if entry.module == "experiments.run_matrix":
            parser = run_matrix.build_parser()
        else:
            parser = _captured_parser(module, ["--nonexistent-probe"])
        real_options = _parser_options(parser)
        for param in entry.params:
            assert param.flag in real_options, (
                f"{name}: UI offers {param.flag} but "
                f"{entry.module} does not define it"
            )
        for form in forms[name]:
            argv = build_argv(name, form)
            assert argv[2] == entry.module
            # The REAL parser must accept the generated vector.
            parser.parse_args(argv[3:])


def test_models_flag_resolves_registries_and_rejects_unknown(
    tmp_path: Path,
) -> None:
    api_cfg = tmp_path / "api.json"
    api_cfg.write_text(json.dumps({
        "anthropic:claude-haiku-4-5-20251001": {"modalities": ["text"]},
    }), encoding="utf-8")
    local_cfg = tmp_path / "local.json"
    local_cfg.write_text(json.dumps({
        "vllm:org/model": {"revision": "a" * 40, "modalities": ["text"]},
    }), encoding="utf-8")
    api, local = run_matrix._resolve_model_selection(
        ["anthropic:claude-haiku-4-5-20251001", "vllm:org/model"],
        api_cfg, local_cfg,
    )
    assert api == ["anthropic:claude-haiku-4-5-20251001"]
    assert local == ["vllm:org/model"]
    with pytest.raises(ValueError, match="unknown model"):
        run_matrix._resolve_model_selection(["nope"], api_cfg, local_cfg)
    with pytest.raises(ValueError, match="closest registry entries"):
        run_matrix._resolve_model_selection(
            ["anthropic:claude-haiku"], api_cfg, local_cfg,
        )
    local_cfg.write_text(json.dumps({
        "anthropic:claude-haiku-4-5-20251001": {},
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="ambiguous model"):
        run_matrix._resolve_model_selection(
            ["anthropic:claude-haiku-4-5-20251001"], api_cfg, local_cfg,
        )
    # Mutual exclusion with explicit --api/--local is a parse-time error.
    with pytest.raises(SystemExit):
        run_matrix.main([
            "--dry-run", "--models", "x", "--api", "y",
            "--api-config", str(api_cfg), "--out", str(tmp_path / "o"),
        ])
    # An unknown name is rejected before anything runs.
    with pytest.raises(SystemExit):
        run_matrix.main([
            "--dry-run", "--models", "nope", "--api-config", str(api_cfg),
            "--out", str(tmp_path / "o"),
        ])
    # rig_check forwards the same surface, so --models works there too.
    with pytest.raises(SystemExit):
        rig_check.main([
            "--dry-run", "--models", "nope", "--api-config", str(api_cfg),
            "--out", str(tmp_path / "rc"),
        ])


def test_models_flag_runs_an_offline_dry_lane(tmp_path: Path) -> None:
    # End to end: --models resolves through the hosted registry and the dry
    # lane completes offline (dry-run swaps in MockTarget; resolution and
    # every gate still ran).
    api_cfg = tmp_path / "api.json"
    api_cfg.write_text(json.dumps({
        "anthropic:claude-haiku-4-5-20251001": {"modalities": ["text"]},
    }), encoding="utf-8")
    assert run_matrix.main([
        "--dry-run", "--models", "anthropic:claude-haiku-4-5-20251001",
        "--api-config", str(api_cfg), "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1",
        "--out", str(tmp_path / "dry"),
    ]) == 0


def _probe_receipt(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> tuple[Path, str]:
    """A REAL ura-live-attestation/2 receipt from an offline probe run."""

    local_revision = "a" * 40
    spec = "vllm:fixture/local-model"

    class _StableLocalTarget(BaseTarget):
        name = f"{spec}@{local_revision}"
        modality_support = ("text",)
        max_transport_attempts_per_call = 0

        def generate(self, dialog, *, seed=None):  # noqa: ANN001
            return Response(
                attempt_id="target-placeholder",
                target=self.name,
                output_turns=[
                    DialogTurn(role="assistant", content="I cannot help."),
                ],
                raw={
                    "sampling_control": "seeded",
                    "resolved_model": "fixture/local-model",
                    "model_revision": local_revision,
                },
            )

    local_config = tmp_path / "local-targets.json"
    local_config.write_text(json.dumps({spec: {
        "revision": local_revision, "modalities": ["text"],
        "tensor_parallel_size": 1, "gpu_memory_utilization": 0.5,
        "max_tokens": 64,
    }}), encoding="utf-8")
    monkeypatch.setattr(
        run_matrix, "build_target", lambda *_a, **_kw: _StableLocalTarget()
    )
    probe_root = tmp_path / "probe"
    assert run_matrix.main([
        "--local", spec, "--local-config", str(local_config),
        "--attackers", "replay", "--judges", "rules", "--corpora", "synth",
        "--limit", "1", "--max-queries", "1", "--max-turns", "1",
        "--max-total-target-calls", "100000",
        "--max-total-judge-calls", "100000",
        "--max-total-http-attempts", "100000", "--deadline-seconds", "3600",
        *project_revision_args,
        "--attestation-probe", "--execution-scope-id", "webtest-scope",
        "--out", str(probe_root),
    ]) == 0
    receipt = tmp_path / "receipt.live-attestation.json"
    assert live_attestation_cli.main([
        "--probe-root", str(probe_root),
        "--execution-scope-id", "webtest-scope", "--out", str(receipt),
    ]) == 0
    return receipt, hashlib.sha256(receipt.read_bytes()).hexdigest()


def test_live_attestation_validate_revalidates_and_fails_closed(
    tmp_path: Path, monkeypatch, project_revision_args, capsys,
) -> None:
    receipt, sha = _probe_receipt(tmp_path, monkeypatch, project_revision_args)
    assert live_attestation_cli.main([
        "--validate", str(receipt), "--sha256", sha,
    ]) == 0
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert out["status"] == "attestation_validated"
    assert out["records"] >= 1 and out["sha256"] == sha
    # A wrong digest fails closed.
    assert live_attestation_cli.main([
        "--validate", str(receipt), "--sha256", "0" * 64,
    ]) == 1
    # Tampered bytes fail closed even with a recomputed digest (the strict
    # loader revalidates the manifest content, not just the hash).
    tampered = tmp_path / "tampered.json"
    doc = json.loads(receipt.read_text(encoding="utf-8"))
    doc["status"] = "definitely-not-complete"
    tampered.write_text(json.dumps(doc), encoding="utf-8")
    bad_sha = hashlib.sha256(tampered.read_bytes()).hexdigest()
    assert live_attestation_cli.main([
        "--validate", str(tampered), "--sha256", bad_sha,
    ]) == 1
    # Mode mixing is rejected.
    with pytest.raises(SystemExit):
        live_attestation_cli.main(["--validate", str(receipt)])
    with pytest.raises(SystemExit):
        live_attestation_cli.main([
            "--validate", str(receipt), "--sha256", sha,
            "--probe-root", str(tmp_path),
        ])


# -- recorded usage and calculated cost -------------------------------------


def _artifact_descriptor(path: Path) -> dict[str, object]:
    lines = [
        line for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return {
        "file": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "bytes": path.stat().st_size,
        "records": len(lines),
    }


def _write_marker_fixture(cell_dir: Path, stem: str = "cell-a") -> Path:
    cell_dir.mkdir(parents=True, exist_ok=True)
    responses = cell_dir / f"{stem}.responses.jsonl"
    responses.write_text("\n".join([
        json.dumps({
            "target": "anthropic-fable:claude-fable-5",
            "tokens": {"input": 1200, "output": 300, "total": 1500,
                       "uncached_input": 1000, "cached_input": 150,
                       "cache_write_input": 50},
            "raw": {
                "provider": "anthropic",
                "resolved_model": "claude-fable-5",
                "provider_usage": {
                    "input_tokens": 1000, "output_tokens": 300,
                    "cache_read_input_tokens": 150,
                    "cache_creation_input_tokens": 50,
                    "output_tokens_details": {"thinking_tokens": 120},
                },
            },
        }),
        # A local response with prompt/completion keys and no provider.
        json.dumps({
            "target": "vllm:org/model",
            "tokens": {"prompt": 70, "completion": 30, "total": 100},
            "raw": {},
        }),
        # A response that recorded no token usage at all -> missing, not 0.
        json.dumps({"target": "anthropic-fable:claude-fable-5",
                    "raw": {"provider": "anthropic",
                            "resolved_model": "claude-fable-5"}}),
    ]) + "\n", encoding="utf-8")
    trails = cell_dir / f"{stem}.trails.jsonl"
    trails.write_text("\n".join([
        json.dumps({"raw": {
            "judge_model": "anthropic:claude-haiku-4-5-20251001",
            "judge_call": {
                "provider": "anthropic",
                "provider_resolved_model": "claude-haiku-4-5-20251001",
                "tokens": {"input": 500, "output": 20, "total": 520},
                "sampling_control": "seeded",
            },
        }}),
        # Provider refusal: no call was made or billed -> excluded.
        json.dumps({"raw": {"judge_call": {
            "provider": "anthropic",
            "tokens": {"input": None, "output": None},
            "sampling_control": "not_queried_provider_refusal",
        }}}),
        # A rules-only stage with no judge call at all.
        json.dumps({"raw": {}}),
    ]) + "\n", encoding="utf-8")
    marker = cell_dir / f"{stem}.complete.json"
    marker.write_text(json.dumps({
        "status": "complete", "format_version": 2, "run_id": f"run-{stem}",
        "artifacts": {
            "responses": _artifact_descriptor(responses),
            "trails": _artifact_descriptor(trails),
        },
    }), encoding="utf-8")
    return marker


def test_failed_cell_usage_accounted_operationally_not_scientifically(
    tmp_path: Path,
) -> None:
    from experiments.rig_web import failed_cell_usage_rows

    root = tmp_path / "results"
    cell = root / "failed"
    cell.mkdir(parents=True)
    # Durable partial responses/trails a failed cell leaves behind.
    (cell / "cell-f.responses.jsonl").write_text(
        json.dumps({
            "target": "anthropic:claude-opus-5",
            "tokens": {"input": 1000, "output": 200},
            "raw": {"provider": "anthropic", "resolved_model": "claude-opus-5"},
        }) + "\n", encoding="utf-8",
    )
    (cell / "cell-f.trails.jsonl").write_text(
        json.dumps({"raw": {"judge_call": {
            "provider": "anthropic",
            "provider_resolved_model": "claude-haiku-4-5-20251001",
            "tokens": {"input": 300, "output": 10},
            "sampling_control": "seeded",
        }}}) + "\n", encoding="utf-8",
    )
    (cell / "cell-f.error.json").write_text(json.dumps({
        "status": "error", "run_id": "run-f", "completed_attempts": 3,
    }), encoding="utf-8")
    # A second failed provider call with no token detail retains its exact,
    # bounded logical-call audit.  completed_attempts is a different unit and
    # must never be relabelled as a provider-call count.
    reserved = root / "reserved"
    reserved.mkdir()
    (reserved / "cell-r.error.json").write_text(json.dumps({
        "status": "error", "run_id": "run-r", "completed_attempts": 5,
        "target": "anthropic:claude-opus-5",
        "call_audit": {
            "logical_call_count": 1, "transport_attempt_count": 1,
            "provider": "anthropic", "operation": "generate",
        },
    }), encoding="utf-8")
    unaudited = root / "unaudited"
    unaudited.mkdir()
    (unaudited / "cell-u.error.json").write_text(json.dumps({
        "status": "error", "run_id": "run-u", "completed_attempts": 9,
    }), encoding="utf-8")

    rows = failed_cell_usage_rows(root)
    by_role_cat = {(r["role"], r["provider"], r["category"]): r["amount"] for r in rows}
    # Observable paid work is accounted under the distinct *_failed roles.
    assert by_role_cat[("target_failed", "anthropic", "input")] == 1000
    assert by_role_cat[("judge_failed", "anthropic", "input")] == 300
    # No completion-marker role appears (kept out of scientific results).
    assert not any(r["role"] in {"target", "judge"} for r in rows)
    # The token-less failed cell surfaces reserved-call exposure, never zero.
    assert by_role_cat[("reserved", "anthropic", "calls")] == 1
    assert by_role_cat[("reserved", "anthropic", "missing_tokens")] == 1
    assert not any(
        row["role"] == "reserved" and row["amount"] == 9 for row in rows
    )


def test_spend_card_fresh_index_shows_unknown_not_zero(tmp_path: Path) -> None:
    # Retained artifacts under the results root + an empty index must render as
    # UNKNOWN/not-indexed, never as a fabricated $0.0000 spend.
    app = _app(tmp_path)
    try:
        _write_marker_fixture(app.results_root / "lane")
        card = app._spend_card()
        assert "not indexed" in card.lower()
        assert "unknown, not zero" in card
        assert "$0.0000" not in card  # no fabricated zero anywhere on the card
    finally:
        app.close()


def test_usage_accounting_follows_completion_marker_lineage(
    tmp_path: Path,
) -> None:
    root = tmp_path / "results"
    marker = _write_marker_fixture(root / "lane")
    # An orphan responses file (no marker) is never counted.
    (root / "orphan").mkdir(parents=True)
    (root / "orphan" / "cell-x.responses.jsonl").write_text(
        json.dumps({"target": "anthropic:m",
                    "tokens": {"input": 999999, "output": 999999}}) + "\n",
        encoding="utf-8",
    )
    # An errored cell is skipped even though its marker exists.
    err_dir = root / "errored"
    _write_marker_fixture(err_dir, stem="cell-e")
    (err_dir / "cell-e.error.json").write_text("{}", encoding="utf-8")
    # Checkpoints are transient and never counted.
    (root / "lane" / "cell-a.responses.checkpoint.jsonl").write_text(
        json.dumps({"tokens": {"input": 5}}) + "\n", encoding="utf-8",
    )

    rows, stats = collect_usage(root, verify_sha=True)
    assert stats["markers"] == 1
    assert stats["skipped_error"] == 1
    # Two excluded response files are reported: the true orphan AND the
    # errored cell's partial snapshot (its marker was skipped, so its
    # responses are not completion-bound either).
    assert stats["orphan_responses"] == 2
    tally = {
        (row["role"], row["provider"], row["model"], row["category"]):
            row["amount"]
        for row in rows
    }
    # Target usage: provider_usage detail wins (input excludes cache).
    assert tally[("target", "anthropic", "claude-fable-5", "input")] == 1000
    assert tally[("target", "anthropic", "claude-fable-5", "output")] == 300
    assert tally[("target", "anthropic", "claude-fable-5", "cache_read")] == 150
    assert tally[("target", "anthropic", "claude-fable-5", "cache_write")] == 50
    assert tally[("target", "anthropic", "claude-fable-5", "reasoning")] == 120
    assert tally[("target", "anthropic", "claude-fable-5", "calls")] == 2
    assert tally[("target", "anthropic", "claude-fable-5", "missing_tokens")] == 1
    # Local rows normalize prompt/completion and derive the vllm provider.
    assert tally[("target", "vllm", "vllm:org/model", "input")] == 70
    assert tally[("target", "vllm", "vllm:org/model", "output")] == 30
    # Judge usage from trails; the provider-refusal row is excluded.
    judge_key = ("judge", "anthropic", "claude-haiku-4-5-20251001", "calls")
    assert tally[judge_key] == 1
    assert tally[("judge", "anthropic", "claude-haiku-4-5-20251001",
                  "input")] == 500
    # Lineage is enforced: a size change after completion fails closed.
    responses = marker.parent / "cell-a.responses.jsonl"
    responses.write_text(
        responses.read_text(encoding="utf-8") + "\n", encoding="utf-8"
    )
    doc = json.loads(marker.read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="byte size changed"):
        usage_rows_from_marker(marker, doc)


def test_costs_from_pricing_are_exact_or_na_never_zero() -> None:
    pricing = {"providers": {"anthropic": {"models": {
        "claude-haiku-4-5-20251001": {"rates": [
            {"effective_date": "2026-01-01", "currency": "USD",
             "per_million_tokens": {"input": 1.0, "output": 5.0}},
            {"effective_date": "2026-08-01", "currency": "USD",
             "per_million_tokens": {"input": 2.0, "output": 10.0,
                                    "cache_read": 0.2}},
            {"effective_date": "2099-01-01", "currency": "USD",
             "per_million_tokens": {"input": 99.0, "output": 99.0}},
        ]},
    }}}}
    # The newest effective rate on-or-before the run date wins (never future).
    rate, _ = rate_for(
        pricing, "anthropic", "claude-haiku-4-5-20251001", on_date="2026-08-16",
    )
    assert rate["effective_date"] == "2026-08-01"
    rows = compute_costs({
        ("judge", "anthropic", "claude-haiku-4-5-20251001", "2026-08-16"): {
            "calls": 4, "input": 1_000_000, "output": 200_000,
            "cache_read": 500_000,
        },
    }, pricing)
    assert rows[0]["cost"] == pytest.approx(2.0 + 2.0 + 0.1)
    assert rows[0]["effective_date"] == "2026-08-01"
    # HISTORICAL pricing: a run dated before the price change is priced at the
    # rate effective THEN (2026-01-01: input 1.0), not today's 2026-08-01 rate.
    rows = compute_costs({
        ("target", "anthropic", "claude-haiku-4-5-20251001", "2026-05-01"): {
            "calls": 1, "input": 1_000_000, "output": 1_000_000,
        },
    }, pricing)
    assert rows[0]["cost"] == pytest.approx(1.0 + 5.0)
    assert rows[0]["effective_date"] == "2026-01-01"
    # Reasoning tokens are a subset of output (billed as output by the
    # provider): they never void a row that input+output fully price.
    rows = compute_costs({
        ("target", "anthropic", "claude-haiku-4-5-20251001", "2026-08-16"): {
            "calls": 1, "input": 10, "output": 5, "reasoning": 7,
        },
    }, pricing)
    assert rows[0]["cost"] == pytest.approx(10 / 1e6 * 2 + 5 / 1e6 * 10)
    assert rows[0]["missing"] == []
    # A PRICED category (cache_write) with tokens but no rate -> N/A, never 0.
    rows = compute_costs({
        ("target", "anthropic", "claude-haiku-4-5-20251001", "2026-08-16"): {
            "calls": 1, "input": 10, "output": 5, "cache_write": 7,
        },
    }, pricing)
    assert rows[0]["cost"] is None
    assert any("cache_write" in item for item in rows[0]["missing"])
    # Unpriced model -> N/A with the missing entry named.
    rows = compute_costs(
        {("target", "openai", "gpt-x", "2026-08-16"): {"calls": 1, "input": 10}},
        pricing,
    )
    assert rows[0]["cost"] is None and rows[0]["missing"]
    # Local serving is not billable (never a fabricated $0 API cost).
    rows = compute_costs(
        {("target", "vllm", "org/m", "2026-08-16"): {"calls": 2, "input": 100}},
        pricing,
    )
    assert rows[0]["billable"] is False and rows[0]["cost"] is None
    # Calls whose usage went unrecorded surface as missing, blocking a cost.
    rows = compute_costs({
        ("target", "anthropic", "claude-haiku-4-5-20251001", "2026-08-16"): {
            "calls": 2, "input": 10, "output": 5, "missing_tokens": 1,
        },
    }, pricing)
    assert rows[0]["cost"] is None
    assert any("incomplete token usage" in item for item in rows[0]["missing"])


def test_compute_costs_rejects_invalid_pricing_values() -> None:
    # Booleans, NaN, infinity, and negatives are not valid prices -> N/A.
    for bad in (True, float("nan"), float("inf"), -1.0):
        pricing = {"providers": {"anthropic": {"models": {"m": {"rates": [
            {"effective_date": "2026-01-01", "currency": "USD",
             "per_million_tokens": {"input": bad, "output": 5.0}}]}}}}}
        rows = compute_costs(
            {("target", "anthropic", "m", "2026-08-16"): {"calls": 1, "input": 10,
                                                          "output": 5}},
            pricing,
        )
        assert rows[0]["cost"] is None, bad
        assert rows[0]["missing"]


def test_costs_fail_closed_on_partial_or_malformed_token_usage() -> None:
    pricing = {"providers": {"anthropic": {"models": {"m": {"rates": [{
        "effective_date": "2026-01-01", "currency": "USD",
        "per_million_tokens": {"input": 1.0, "output": 2.0},
    }]}}}}}
    rows = compute_costs(
        {("target", "anthropic", "m", "2026-08-16"): {
            "calls": 1, "input": 10,
        }},
        pricing,
    )
    assert rows[0]["cost"] is None
    assert any("incomplete input/output" in why for why in rows[0]["missing"])

    # bool is not a token count, and an impossible cache > gross input must not
    # be clamped into a plausible-looking zero-cost ordinary-input category.
    assert "input" not in _tokens_by_category(
        {"input": True, "output": 2}, None,
    )
    assert "input" not in _tokens_by_category(
        {"input": 10, "output": 2, "cached_input": 11}, None,
    )


def test_costs_require_historical_date_and_valid_currency() -> None:
    pricing = {"providers": {"anthropic": {"models": {"m": {"rates": [{
        "effective_date": "2026-01-01", "currency": "usd",
        "per_million_tokens": {"input": 1.0, "output": 2.0},
    }]}}}}}
    usage = {("target", "anthropic", "m", "2026-08-16"): {
        "calls": 1, "input": 10, "output": 2,
    }}
    row = compute_costs(usage, pricing)[0]
    assert row["currency"] == "USD" and row["cost"] is not None

    unknown_date = {
        ("target", "anthropic", "m", ""): {"calls": 1, "input": 10, "output": 2}
    }
    row = compute_costs(unknown_date, pricing)[0]
    assert row["cost"] is None
    assert any("historical usage" in why for why in row["missing"])

    pricing["providers"]["anthropic"]["models"]["m"]["rates"][0]["currency"] = True
    row = compute_costs(usage, pricing)[0]
    assert row["cost"] is None
    assert any("currency" in why for why in row["missing"])


def test_compute_costs_never_sums_mixed_currencies() -> None:
    # Two runs of the same model priced in different currencies must NOT be
    # summed into one USD figure: cost is N/A with per-currency subtotals.
    pricing = {"providers": {"anthropic": {"models": {"m": {"rates": [
        {"effective_date": "2026-01-01", "currency": "USD",
         "per_million_tokens": {"input": 1.0, "output": 1.0}},
        {"effective_date": "2026-06-01", "currency": "EUR",
         "per_million_tokens": {"input": 2.0, "output": 2.0}},
    ]}}}}}
    rows = compute_costs({
        ("target", "anthropic", "m", "2026-03-01"): {"calls": 1, "input": 1_000_000,
                                                     "output": 0},
        ("target", "anthropic", "m", "2026-07-01"): {"calls": 1, "input": 1_000_000,
                                                     "output": 0},
    }, pricing)
    assert rows[0]["cost"] is None
    assert rows[0]["currency"] == "mixed"
    assert rows[0]["by_currency"] == {"EUR": 2.0, "USD": 1.0}


def test_reindex_rebuilds_usage_and_spend_card_renders(tmp_path: Path) -> None:
    app = _isolated_app(tmp_path)
    _write_marker_fixture(app.results_root / "lane")
    (app.repo_root / "experiments" / "pricing.json").write_text(json.dumps({
        "providers": {"anthropic": {"models": {
            "claude-fable-5": {"rates": [{
                "effective_date": "2026-01-01", "currency": "USD",
                "per_million_tokens": {"input": 2.0, "output": 10.0,
                                       "cache_read": 0.2, "cache_write": 2.5,
                                       "reasoning": 10.0},
            }]},
            "claude-haiku-4-5-20251001": {"rates": [{
                "effective_date": "2026-01-01", "currency": "USD",
                "per_million_tokens": {"input": 1.0, "output": 5.0},
            }]},
        }}},
    }), encoding="utf-8")
    status, location, _ = app.handle("POST", "/db/reindex", {})
    assert status == 303 and location.startswith("/?reindexed=")
    totals = app.db.usage_totals()
    assert totals is not None
    fable = next(k for k in totals
                 if k[:3] == ("target", "anthropic", "claude-fable-5"))
    assert totals[fable]["input"] == 1000
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    # The judge cost is computable; the Fable row is N/A because one call
    # recorded no tokens (missing, never zero) - both render distinctly.
    assert "claude-haiku-4-5-20251001" in text
    assert "$0.0006" in text  # 500 in @ $1/M + 20 out @ $5/M
    assert "N/A" in text and "incomplete token usage" in text
    assert "local (not billed)" in text
    # The dashboard reports the reindex outcome and database health.
    status, _, dash = app.handle("GET", f"/?reindexed={location.split('=', 1)[1]}")
    dtext = dash.decode("utf-8")
    assert "Reindex completed" in dtext
    assert "Console database" in dtext and "healthy" in dtext
    app.close()


def test_budget_never_sums_or_mislabels_mixed_currencies(tmp_path: Path) -> None:
    # A provider priced in two currencies must NOT be summed into one figure or
    # mislabelled USD in the budget rollup: it shows per-currency subtotals and
    # a mixed-currency Remaining of N/A.  A budget whose provider has no
    # recorded usage shows "no recorded usage", never a fabricated $0.
    app = _isolated_app(tmp_path)
    cell = app.results_root / "lane"
    cell.mkdir(parents=True, exist_ok=True)
    responses = cell / "cell.responses.jsonl"
    responses.write_text(json.dumps({
        "target": "anthropic-fable:claude-fable-5",
        "tokens": {"input": 1000, "output": 300, "total": 1300,
                   "uncached_input": 1000},
        "raw": {"provider": "anthropic", "resolved_model": "claude-fable-5",
                "provider_usage": {"input_tokens": 1000, "output_tokens": 300}},
    }) + "\n", encoding="utf-8")
    trails = cell / "cell.trails.jsonl"
    trails.write_text(json.dumps({"raw": {
        "judge_model": "anthropic:claude-haiku-4-5-20251001",
        "judge_call": {"provider": "anthropic",
                       "provider_resolved_model": "claude-haiku-4-5-20251001",
                       "tokens": {"input": 500, "output": 20, "total": 520},
                       "sampling_control": "seeded"}}}) + "\n", encoding="utf-8")
    marker = cell / "cell.complete.json"
    marker.write_text(json.dumps({
        "status": "complete", "format_version": 2, "run_id": "run-cell",
        "artifacts": {"responses": _artifact_descriptor(responses),
                      "trails": _artifact_descriptor(trails)},
    }), encoding="utf-8")
    # fable priced in EUR, haiku in USD - the SAME provider, two currencies.
    (app.repo_root / "experiments" / "pricing.json").write_text(json.dumps({
        "providers": {"anthropic": {"models": {
            "claude-fable-5": {"rates": [{
                "effective_date": "2026-01-01", "currency": "EUR",
                "per_million_tokens": {"input": 2.0, "output": 10.0}}]},
            "claude-haiku-4-5-20251001": {"rates": [{
                "effective_date": "2026-01-01", "currency": "USD",
                "per_million_tokens": {"input": 1.0, "output": 5.0}}]},
        }}}}), encoding="utf-8")
    # Two budgets: Anthropic (has mixed-currency usage) and DeepSeek (none).
    (app.repo_root / "experiments" / "budgets.json").write_text(json.dumps({
        "providers": [
            {"name": "Anthropic", "prepaid": "$100", "match": "anthropic",
             "funds": "prepaid"},
            {"name": "DeepSeek", "prepaid": "$50", "match": "deepseek",
             "funds": "prepaid"},
        ],
    }), encoding="utf-8")
    app.handle("POST", "/db/reindex", {})
    _s, _c, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    # Anthropic: per-currency subtotals, never one summed USD figure.
    assert "mixed currencies (not summed)" in text
    assert "mixed currencies - cannot net" in text  # Remaining N/A
    # DeepSeek: real absence, not a fabricated $0.
    assert "no recorded usage" in text
    app.close()


def test_usd_prepaid_balance_is_not_subtracted_from_non_usd_spend(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    app._usage_cost_rows = lambda: ([{
        "role": "target", "provider": "anthropic", "model": "m",
        "calls": 1, "missing_tokens": 0,
        "tokens": {name: 0 for name in (
            "input", "output", "cache_read", "cache_write", "reasoning",
        )},
        "billable": True, "cost": 10.0, "currency": "EUR",
        "by_currency": {"EUR": 10.0}, "missing": [],
        "effective_date": "2026-01-01", "auto_fetched": False,
    }], "")
    app._budgets = lambda: [("Anthropic", "$100", "anthropic", "test")]
    try:
        card = app._spend_card()
        assert "prepaid balance is USD" in card
        assert "no currency conversion recorded" in card
        assert "EUR 90.0000" not in card
    finally:
        app.close()


# -- sqlite reliability ------------------------------------------------------


def test_terminal_state_commits_in_one_transaction(tmp_path: Path) -> None:
    # run_recorded flips only after the transactional commit; a failing
    # database leaves it False so the write retries on the next reconcile.
    app = _app(tmp_path)
    job = app.start_job("webui_selftest", {"--selftest-sleep": "0"})
    deadline = time.time() + 30
    while job.state() == "running" and time.time() < deadline:
        time.sleep(0.05)
    # Sabotage the database, reconcile: the flag must stay False.
    real_record = app.db.record_terminal
    app.db.record_terminal = lambda *_a, **_kw: False
    app._reconcile()
    assert job.run_recorded is False
    app.db.record_terminal = real_record
    app._reconcile()
    assert job.run_recorded is True
    # Log handles were closed at terminal reconcile.
    assert job.stdout_handle.closed and job.stderr_handle.closed
    app.close()


def test_v1_database_migrates_preserving_history(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    conn = sqlite3.connect(state / "console.db")
    conn.executescript(
        """
        CREATE TABLE jobs (job_id TEXT PRIMARY KEY, command TEXT, argv TEXT,
            directory TEXT, state TEXT, exit_code INTEGER, started_at REAL,
            ended_at REAL, updated_at REAL);
        CREATE TABLE runs (run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT, kind TEXT, command TEXT, out_dir TEXT, pin TEXT,
            state TEXT, exit_code INTEGER, created_at REAL, UNIQUE(job_id));
        CREATE TABLE spend (id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT, provider TEXT, calls INTEGER, input_tokens INTEGER,
            output_tokens INTEGER, recorded_at REAL, UNIQUE(job_id, provider));
        INSERT INTO jobs VALUES ('job-v1', 'run_matrix', '["--dry-run"]',
            'dir', 'running', NULL, 1.0, NULL, 1.0);
        INSERT INTO runs (job_id, kind, command, out_dir, pin, state,
            exit_code, created_at) VALUES ('job-v1', 'dry_run', 'run_matrix',
            'runs/x', 'abc', 'complete', 0, 1.0);
        """
    )
    conn.commit()
    conn.close()
    db = ConsoleDB(state / "console.db")
    health = db.health()
    assert health["healthy"] and health["schema_version"] == 3
    runs = db.list_runs()
    assert runs is not None and runs[0]["job_id"] == "job-v1"
    db.close()
    # The app restores the v1 job and persists its orphaned state.
    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(results_root=results, state_dir=state)
    assert app.jobs["job-v1"].state() == "orphaned"
    rows = app.db.load_jobs()
    assert rows is not None and str(rows[0]["state"]) == "orphaned"
    app.close()


def test_corrupt_database_is_visible_never_silent_empty(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / "console.db").write_bytes(b"not a sqlite file at all")
    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(results_root=results, state_dir=state)
    health = app.db.health()
    assert health["healthy"] is False and health["last_error"]
    # History readers return None (unknown), never a fabricated empty list.
    assert app.db.load_jobs() is None
    assert app.db.usage_totals() is None
    # Every page still renders, with the failure visible.
    for path in ("/", "/jobs", "/stats"):
        status, _, body = app.handle("GET", path)
        text = body.decode("utf-8")
        assert status == 200, path
        assert "Console database" in text or "Unavailable" in text or \
            "unavailable" in text, path
    # Jobs still start and stop with a broken database.
    job = app.start_job("webui_selftest", {"--selftest-sleep": "30"})
    assert job.state() == "running"
    app.stop_job(job.job_id)
    app.close()


# -- real Level-1 / Level-2 rendering ---------------------------------------


def test_stats_renders_real_level1_evidence(tmp_path: Path) -> None:
    # The Level-1 card renders the REAL producer's document: run the actual
    # dry-run grid and the actual level1_evidence CLI, then render.
    app = _app(tmp_path)
    grid_root = tmp_path / "grid"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "2", "--seeds", "0",
        "--attackers", "replay", "--judges", "rules,llm",
        "--judge-model", "mock", "--max-queries", "1", "--max-turns", "1",
        "--out", str(grid_root),
    ]) == 0
    eligibility = next(grid_root.glob("eligibility-*.eligibility.json"))
    level1_dir = app.results_root / "thesis" / "level1"
    level1_dir.mkdir(parents=True)
    assert level1_cli.main([
        "--eligibility", str(eligibility), "--results", str(grid_root),
        "--out-json", str(level1_dir / "level1.json"),
        "--out-csv", str(level1_dir / "level1.csv"),
    ]) == 0
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "diagnostic dry-run" in text  # the distinct diagnostic state
    assert "Planning strata" in text and "Judgment records" in text
    assert "structural not applicable" in text
    assert "null (by design)" in text  # attempted stays null, shown as such
    app.close()


def test_stats_page_survives_malformed_level1_count(tmp_path: Path) -> None:
    # A schema-labelled artifact with a non-integer count must not receive a
    # measured badge merely because its schema_version string looks right.
    app = _app(tmp_path)
    bad = app.results_root / "thesis" / "level1"
    bad.mkdir(parents=True)
    (bad / "level1.json").write_text(json.dumps({
        "schema_version": "ura-level1-evidence/2",
        "scope": {"evidence_kind": "measured_run"},
        "counts": {
            "execution_units": {"unit": "cells",
                                "attempted": {"weird": "nested-object"}},
        },
    }), encoding="utf-8")
    status, _, body = app.handle("GET", "/stats")
    assert status == 200  # the page did not crash
    text = body.decode("utf-8")
    assert "badge red'>invalid" in text
    assert "Not rendered" in text
    assert "badge blue'>measured" not in text
    app.close()


def test_level1_validation_rejects_inconsistent_judgment_counts() -> None:
    base = {
        "unit": "judgment_record", "completed": 2, "evaluable": 2,
        "decided": 1, "abstained": 1, "non_evaluable": 0, "included": None,
    }

    def document(judgments: dict[str, object]) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": "ura-level1-evidence/2",
            "status": "validated_unit_qualified_lifecycle_inventory",
            "scope": {
                "evidence_kind": "measured_run",
                "contains_diagnostic_dry_run": False,
                "empirical_validity_established": False,
            },
            "counts": {
                "prospective_request_units": None,
                "planning_strata": {"unit": "planning_stratum", "observed": 1},
                "execution_units": {"unit": "execution_unit", "completed": 1},
                "judgment_records": judgments,
                "request_level_errors": {
                    "unit": "request_error_artifact", "observed": 0,
                },
            },
        }
        material = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        result["evidence_id"] = "level1-" + hashlib.sha256(material).hexdigest()[:24]
        return result

    _validate_report_document("level1", document(dict(base)))
    with pytest.raises(ValueError, match="decision counts do not reconcile"):
        _validate_report_document(
            "level1", document({**base, "completed": 3})
        )
    with pytest.raises(ValueError, match="evaluable judgment counts do not reconcile"):
        _validate_report_document(
            "level1", document({**base, "evaluable": 1})
        )


def test_stats_renders_real_level2_report(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    # The Level-2 card renders the REAL producer's document from a measured
    # cohort (offline stable local target + probe + receipt + measured grid).
    receipt, sha = _probe_receipt(tmp_path, monkeypatch, project_revision_args)
    root = tmp_path / "measured"
    assert run_matrix.main([
        "--local", "vllm:fixture/local-model",
        "--local-config", str(tmp_path / "local-targets.json"),
        "--attackers", "replay", "--judges", "rules", "--corpora", "synth",
        "--limit", "1", "--max-queries", "1", "--max-turns", "1",
        "--max-total-target-calls", "100000",
        "--max-total-judge-calls", "100000",
        "--max-total-http-attempts", "100000", "--deadline-seconds", "3600",
        *project_revision_args,
        "--execution-scope-id", "webtest-scope",
        "--live-attestation", str(receipt),
        "--live-attestation-sha256", sha,
        "--live-attestation-max-age-hours", "1",
        "--out", str(root),
    ]) == 0
    app = _app(tmp_path)
    level2_dir = app.results_root / "thesis" / "level2"
    level2_dir.mkdir(parents=True)
    assert level2_cli.main([
        "--results", str(root),
        "--out-json", str(level2_dir / "level2.json"),
        "--out-csv", str(level2_dir / "level2.csv"),
        "--out-md", str(level2_dir / "level2.md"),
    ]) == 0
    report = json.loads(
        (level2_dir / "level2.json").read_text(encoding="utf-8")
    )
    assert report["schema_version"] == "ura-level2-report/1"
    metrics = {row["metric"] for row in report["common"]["estimates"]}
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "measured" in text  # the distinct measured state
    for metric in metrics:
        assert f">{metric} <" in text or metric in text  # one section per metric
    # Real fields, not invented ones.
    assert "model_spec" in text and "corpus_arm" in text
    assert "n_records" in text and "n_clusters" in text
    assert "decided/completed" in text
    assert "never combined" in text or "no universal safety score" in text
    app.close()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"ci_low": True}, "CI endpoints are not finite numbers"),
        ({"ci_high": "0.75"}, "CI endpoints are not finite numbers"),
        ({"ci_low": None}, "CI endpoints must be paired"),
        ({"ci_low": 0.8, "ci_high": 0.7}, "CI endpoints are reversed"),
        ({"ci_low": 0.6, "ci_high": 0.7}, "outside its CI"),
        ({"n_records": True}, "n_records is not a nonnegative count"),
        ({"n_clusters": -1}, "n_clusters is not a nonnegative count"),
    ],
)
def test_level2_validation_rejects_malformed_ci_and_sample_sizes(
    mutation: dict[str, object], message: str,
) -> None:
    row = {field: None for field in _LEVEL2_ROW_FIELDS}
    row.update({
        "run_id": "run-1", "corpus_arm": "arm", "model_spec": "api:model",
        "resolved_model": "model", "source": "source", "risk_category": "risk",
        "effective_modality": "text", "expected_behavior": "refuse",
        "attacker": "replay", "defense": "none", "semantic_family": "safety",
        "metric": "ASR", "value": 0.5, "ci_low": 0.25, "ci_high": 0.75,
        "n_records": 1, "n_clusters": 1, "judgments_completed": 1,
        "judgments_evaluable": 1, "judgments_decided": 1,
        "judgments_abstained": 0, "judgments_non_evaluable": 0,
        "cross_stratum_pooling_permitted": False,
    })

    def document(estimate: dict[str, object]) -> dict[str, object]:
        result: dict[str, object] = {
            "schema_version": "ura-level2-report/1",
            "status": "deterministic_compatible_stratum_export",
            "empirical_validity_established": False,
            "pooling_policy": {
                "universal_safety_score_defined": False,
                "cross_stratum_pooling_permitted": False,
                "native_scale_pooling_permitted": False,
            },
            "common": {"n_estimate_rows": 1, "estimates": [estimate]},
        }
        material = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        result["report_id"] = "level2-" + hashlib.sha256(material).hexdigest()[:24]
        return result

    _validate_report_document("level2", document(dict(row)))
    row.update(mutation)
    with pytest.raises(ValueError, match=message):
        _validate_report_document("level2", document(row))


# -- process lifecycle -------------------------------------------------------


def test_stop_kills_the_complete_child_process_tree(tmp_path: Path) -> None:
    # A stopped job must take its grandchildren with it: the job module
    # spawns a heartbeat-writing child; after stop, the heartbeat must go
    # quiet and the log handles must be closed.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "spawner.py").write_text(
        "import subprocess, sys\n"
        "code = (\"import time, pathlib\\n\"\n"
        "        \"p = pathlib.Path('heartbeat.txt')\\n\"\n"
        "        \"while True:\\n\"\n"
        "        \"    p.write_text(str(time.time()))\\n\"\n"
        "        \"    time.sleep(0.2)\\n\")\n"
        "child = subprocess.Popen([sys.executable, '-c', code])\n"
        "child.wait()\n",
        encoding="utf-8",
    )
    results = tmp_path / "runs"
    results.mkdir()
    commands = {"spawner": Command("spawner", "spawner", "tree test", ())}
    app = RigWebApp(
        results_root=results, state_dir=tmp_path / "state",
        repo_root=repo, commands=commands,
    )
    job = app.start_job("spawner", {})
    heartbeat = repo / "heartbeat.txt"
    deadline = time.time() + 30
    while not heartbeat.exists() and time.time() < deadline:
        time.sleep(0.1)
    assert heartbeat.exists(), "grandchild never started"
    app.stop_job(job.job_id)
    assert job.state() in {"failed", "complete"}
    assert job.stdout_handle.closed and job.stderr_handle.closed
    time.sleep(1.0)  # allow any survivor to write again
    snapshot = heartbeat.read_text(encoding="utf-8")
    time.sleep(1.2)
    assert heartbeat.read_text(encoding="utf-8") == snapshot, (
        "grandchild survived the stop - the process tree was not terminated"
    )
    app.close()


def test_stop_tree_repeatable_no_survivors(tmp_path: Path) -> None:
    # Repeated start/stop cycles must each fully terminate the tree, leaving no
    # surviving heartbeat writer between iterations.
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "spawner.py").write_text(
        "import subprocess, sys\n"
        "code = (\"import time, pathlib\\n\"\n"
        "        \"p = pathlib.Path('heartbeat.txt')\\n\"\n"
        "        \"while True:\\n\"\n"
        "        \"    p.write_text(str(time.time()))\\n\"\n"
        "        \"    time.sleep(0.2)\\n\")\n"
        "child = subprocess.Popen([sys.executable, '-c', code])\n"
        "child.wait()\n",
        encoding="utf-8",
    )
    results = tmp_path / "runs"
    results.mkdir()
    commands = {"spawner": Command("spawner", "spawner", "tree test", ())}
    app = RigWebApp(
        results_root=results, state_dir=tmp_path / "state",
        repo_root=repo, commands=commands,
    )
    heartbeat = repo / "heartbeat.txt"
    try:
        for _ in range(3):
            if heartbeat.exists():
                heartbeat.unlink()
            job = app.start_job("spawner", {})
            deadline = time.time() + 30
            while not heartbeat.exists() and time.time() < deadline:
                time.sleep(0.1)
            assert heartbeat.exists(), "grandchild never started"
            app.stop_job(job.job_id)
            assert job.stop_error is None, job.stop_error
            time.sleep(1.0)
            snapshot = heartbeat.read_text(encoding="utf-8")
            time.sleep(1.2)
            assert heartbeat.read_text(encoding="utf-8") == snapshot, (
                "grandchild survived a stop iteration"
            )
    finally:
        app.close()


def test_posix_stop_sigkills_group_even_if_driver_exits_gracefully(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # POSIX Stop must escalate SIGKILL to the whole process GROUP after the
    # grace period even when the driver exited gracefully within it (a child
    # that caught SIGTERM would otherwise keep spending).  The group id is
    # captured while the driver is alive, so a reaped driver cannot orphan it.
    import os as _os
    import signal as _signal
    monkeypatch.setattr(_signal, "SIGKILL", 9, raising=False)  # absent on Windows
    app = _app(tmp_path)
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(_os, "getpgid", lambda pid: 4242, raising=False)
    monkeypatch.setattr(
        _os, "killpg", lambda pgid, sig: signals.append((pgid, sig)),
        raising=False,
    )

    class _GracefulDriver:
        pid = 5150

        def poll(self):
            return 0  # already exited (graceful) at verification time

        def wait(self, timeout=None):
            return 0  # exits within the SIGTERM grace: no TimeoutExpired

        def send_signal(self, sig):
            signals.append((-1, sig))  # driver-only fallback marker

    job = Job(job_id="grace", command="x", argv=[], directory=tmp_path,
              process=_GracefulDriver())
    app._terminate_tree_posix(job, job.process)
    # SIGKILL reached the captured GROUP id, not merely the exited driver.
    assert (4242, _signal.SIGKILL) in signals
    assert (4242, _signal.SIGTERM) in signals
    assert not any(pg == -1 for pg, _s in signals)  # never the driver-only path
    assert job.stop_error is None  # confirmed stopped
    app.close()


def test_stop_error_surfaced_when_tree_cannot_be_confirmed(tmp_path: Path) -> None:
    # A process that refuses to die must NOT report a successful stop: the job
    # carries an explicit stop_error the UI renders.
    app = _app(tmp_path)

    class _Undying:
        pid = 424242

        def poll(self):
            return None  # never terminates

        def wait(self, timeout=None):
            import subprocess as _sp
            raise _sp.TimeoutExpired("cmd", timeout)

        def kill(self):
            pass

        def send_signal(self, sig):
            pass

    job = Job(
        job_id="stuck", command="spawner", argv=[], directory=tmp_path,
        process=_Undying(),
    )
    app._terminate_tree(job)
    assert job.stop_error is not None
    assert "could not be confirmed" in job.stop_error
    page = app._job_page(job).decode("utf-8")
    assert "Stop could not be confirmed" in page
    app.close()


def test_http_post_body_limit_enforced(tmp_path: Path) -> None:
    from experiments.rig_web import _make_server

    app = _app(tmp_path)
    server = _make_server(app, "127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        oversized = "content=" + "x" * (3 * 1024 * 1024)
        connection.request("POST", "/config", body=oversized, headers={
            "Content-Type": "application/x-www-form-urlencoded",
        })
        assert connection.getresponse().status == 413
        connection.close()
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        connection.request("GET", "/")
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        app.close()


# -- regression tests for the WEB-002 adversarial-review findings -----------


def test_dry_lane_never_composes_a_real_hosted_judge(tmp_path: Path) -> None:
    # HIGH: a dry-run lane (and dry canary) with the LLM judge selected must
    # grade with the offline mock LLM, never a real metered hosted judge - a
    # "no calls, no spend" mode must not issue paid Haiku calls.
    app = _app(tmp_path)
    for mode, extra in (
        ("dry_run", {"corpora": "synth"}),
        ("diagnostic_canary", {"canary_dry": "on", "limit": "1"}),
    ):
        _cmd, values, _params = app._compose_from_builder({
            "mode": mode, "attackers": "replay", "judges": "rules,llm",
            "judge_model": "anthropic:claude-haiku-4-5-20251001",
            "out": "runs/d", "seeds": "0", **extra,
        })
        assert values["--dry-run"] == "on"
        assert values["--judge-model"] == "mock", (mode, values)
    app.close()


def test_dry_lane_child_env_scrubs_receipt_vars(tmp_path: Path, monkeypatch) -> None:
    # MED: dry stripping is not argv-only - the child is launched with the
    # campaign receipt env vars removed, so an offline lane cannot be failed
    # (or admitted) by an inherited receipt and its argv is self-contained.
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(tmp_path / "r.json"))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", "a" * 64)
    app = _app(tmp_path)
    captured: dict[str, object] = {}
    import subprocess as _sp

    real_popen = _sp.Popen

    def spy(argv, **kwargs):  # noqa: ANN001
        captured["env"] = kwargs.get("env")
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(_sp, "Popen", spy)
    job = app.start_job(
        "webui_selftest", {"--selftest-sleep": "0"}, scrub_receipt_env=True,
    )
    env = captured["env"]
    assert env is not None
    assert "URA_PROJECT_REVISION_MANIFEST" not in env
    assert "URA_PROJECT_REVISION_SHA256" not in env
    deadline = time.time() + 20
    while job.state() == "running" and time.time() < deadline:
        time.sleep(0.05)
    app.close()


def test_openai_cached_input_not_double_billed() -> None:
    # HIGH: OpenAI input_tokens is cache-inclusive; the reported cache read
    # must be netted out of input so it is not charged at the input rate AND
    # the cache rate.
    cats = _tokens_by_category(
        {"input": 100000, "output": 5000, "total": 105000},
        {"input_tokens": 100000, "output_tokens": 5000,
         "input_tokens_details": {"cached_tokens": 80000}},
    )
    assert cats["input"] == 20000 and cats["cache_read"] == 80000
    pricing = {"providers": {"openai": {"models": {"gpt-x": {"rates": [{
        "effective_date": "2026-01-01", "currency": "USD",
        "per_million_tokens": {"input": 2.5, "output": 10.0, "cache_read": 1.25},
    }]}}}}}
    rows = compute_costs(
        {("target", "openai", "gpt-x", "2026-08-16"): {"calls": 1, **cats}},
        pricing,
    )
    # 20000*2.5/M + 5000*10/M + 80000*1.25/M, NOT 100000*2.5 + 80000*1.25.
    assert rows[0]["cost"] == pytest.approx(0.05 + 0.05 + 0.1)
    # Fable's uncached_input is already net and must not be re-subtracted.
    fable = _tokens_by_category(
        {"input": 1200, "output": 300, "uncached_input": 1000,
         "cached_input": 150, "cache_write_input": 50},
        {"input_tokens": 1000, "output_tokens": 300,
         "cache_read_input_tokens": 150, "cache_creation_input_tokens": 50},
    )
    assert fable["input"] == 1000 and fable["cache_read"] == 150


def test_judge_cached_input_not_double_billed() -> None:
    # The judge trail's normalized tokens report input INCLUSIVE of cached_input.
    # {input: 100000, cached_input: 80000} must be 20,000 ordinary input plus
    # 80,000 cache-read, never 180,000 billed tokens.
    cats = _tokens_by_category({"input": 100000, "cached_input": 80000}, None)
    assert cats["input"] == 20000
    assert cats["cache_read"] == 80000


def test_reasoning_tokens_are_displayed_not_separately_billed() -> None:
    # HIGH: thinking/reasoning tokens are a subset of output; they must not
    # void the cost when unpriced, nor be billed a second time when priced.
    cats = _tokens_by_category(
        {"input": 1000, "output": 300},
        {"input_tokens": 1000, "output_tokens": 300,
         "output_tokens_details": {"thinking_tokens": 120}},
    )
    assert cats["reasoning"] == 120 and cats["output"] == 300
    pricing = {"providers": {"anthropic": {"models": {"m": {"rates": [{
        "effective_date": "2026-01-01", "currency": "USD",
        "per_million_tokens": {"input": 2.0, "output": 10.0},
    }]}}}}}
    rows = compute_costs(
        {("target", "anthropic", "m", "2026-08-16"): {"calls": 1, **cats}},
        pricing,
    )
    # Fully computable from input+output even though no reasoning rate exists.
    assert rows[0]["cost"] == pytest.approx(1000 / 1e6 * 2 + 300 / 1e6 * 10)
    assert rows[0]["missing"] == []


def test_rate_for_rejects_non_iso_effective_date() -> None:
    bad = {"providers": {"anthropic": {"models": {"m": {"rates": [{
        "effective_date": "2026-8-1", "currency": "USD",
        "per_million_tokens": {"input": 1.0},
    }]}}}}}
    rate, why = rate_for(bad, "anthropic", "m")
    assert rate is None and "ISO" in why

    bad["providers"]["anthropic"]["models"]["m"]["rates"][0][
        "effective_date"
    ] = "2026-02-30"
    rate, why = rate_for(bad, "anthropic", "m")
    assert rate is None and "ISO" in why


def test_builder_probe_auto_fixes_one_query_one_turn(tmp_path: Path) -> None:
    # MED parity: a probe is one query/one turn by definition; the builder
    # composes them so the argv matches the shape run_matrix enforces (rather
    # than inheriting the driver default of 4 and dying at the CLI).
    app = _app(tmp_path)
    _cmd, values, _params = app._compose_from_builder({
        "mode": "attestation_probe", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "limit": "1", "seeds": "0", "scope": "s",
        "out": "runs/p",
    })
    assert values["--max-queries"] == "1" and values["--max-turns"] == "1"
    app.close()


def test_builder_dry_canary_composes_synth_and_validates(tmp_path: Path) -> None:
    # MED: the advertised dry synthetic canary must be composable from the
    # real form (which has no synth arm checkbox): compose forces --corpora
    # synth and drops targets, and validation requires no arm selection.
    app = _app(tmp_path)
    form = {
        "mode": "diagnostic_canary", "canary_dry": "on", "attackers": "replay",
        "judges": "rules", "limit": "1", "seeds": "0", "out": "runs/c",
        "api": "anthropic:claude-opus-5",  # should be dropped for a dry canary
    }
    assert app._validate_builder(form) == {}
    _cmd, values, _params = app._compose_from_builder(form)
    assert values["--corpora"] == "synth"
    assert "--api" not in values and values["--dry-run"] == "on"
    run_matrix.build_parser().parse_args(build_argv(_cmd, values)[3:])
    app.close()


def test_builder_hosted_measured_rejects_limit_zero(tmp_path: Path, monkeypatch) -> None:
    # MED: a hosted paid measured lane must carry a positive pre-registered
    # --limit; 0 ("all clusters") defeats the sampling policy and is rejected.
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(tmp_path / "r"))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", "a" * 64)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "s"))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "b" * 64)
    app = _app(tmp_path)
    base = {
        "mode": "measured", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "out": "runs/m", "seeds": "0", "sample_seed": "0",
        "scope": "sc", "max_age": "24", "att_path1": "a.json",
        "att_sha1": "c" * 64, "cap_target": "4", "cap_judge": "4",
        "cap_http": "12", "deadline": "600",
    }
    assert "limit" in app._validate_builder({**base, "limit": "0"})
    assert "limit" in app._validate_builder({**base, "limit": "-1"})
    assert "limit" not in app._validate_builder({**base, "limit": "5"})
    app.close()


def test_builder_measured_argv_is_self_contained_from_env(
    tmp_path: Path, monkeypatch,
) -> None:
    # MED: a measured lane admitted via campaign-env receipts must compose
    # those receipts into the argv, so the retained "Exact command" reproduces
    # the same admission in a clean shell.
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(tmp_path / "r.json"))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", "a" * 64)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(tmp_path / "s.json"))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", "b" * 64)
    app = _app(tmp_path)
    _cmd, values, _params = app._compose_from_builder({
        "mode": "measured", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "out": "runs/m", "seeds": "0", "sample_seed": "0",
        "scope": "sc", "max_age": "24", "att_path1": "a.json",
        "att_sha1": "c" * 64, "cap_target": "4", "cap_judge": "4",
        "cap_http": "12", "deadline": "600", "limit": "5",
    })
    assert values["--project-revision"] == str(tmp_path / "r.json")
    assert values["--project-revision-sha256"] == "a" * 64
    assert values["--source-conformance"] == str(tmp_path / "s.json")
    app.close()


def test_builder_rejects_bad_seeds_and_whitespace_scope(tmp_path: Path) -> None:
    app = _app(tmp_path)
    assert "seeds" in app._validate_builder({
        "mode": "dry_run", "corpora": "synth", "attackers": "replay",
        "out": "runs/d", "seeds": "0,0",
    })
    assert "seeds" in app._validate_builder({
        "mode": "dry_run", "corpora": "synth", "attackers": "replay",
        "out": "runs/d", "seeds": "abc",
    })
    assert "scope" in app._validate_builder({
        "mode": "dry_run", "corpora": "synth", "attackers": "replay",
        "out": "runs/d", "seeds": "0", "scope": "bad scope",
    })
    app.close()


def test_reindexed_query_param_is_html_escaped(tmp_path: Path) -> None:
    # HIGH XSS: the reindexed summary comes from the URL query string and must
    # be html-escaped before entering the dashboard notice.
    app = _app(tmp_path)
    payload = json.dumps({
        "ok": True, "usage_rows": 0, "markers": 0, "reports": 0, "roots": 1,
        "x": "<img src=x onerror=alert(1)>",
    })
    from urllib.parse import quote as _q

    status, _, body = app.handle("GET", f"/?reindexed={_q(payload)}")
    text = body.decode("utf-8")
    assert status == 200
    assert "<img src=x onerror=alert(1)>" not in text
    assert "&lt;img src=x onerror=alert(1)&gt;" in text
    app.close()


def test_level2_render_escapes_artifact_numeric_fields(tmp_path: Path) -> None:
    # LOW XSS hardening: n_records/n_clusters from the artifact are escaped.
    app = _app(tmp_path)
    doc = {
        "schema_version": "ura-level2-report/1",
        "common": {"n_estimate_rows": 1, "estimates": [{
            "metric": "ASR", "model_spec": "m", "corpus_arm": "a",
            "attacker": "replay", "defense": "none", "value": 0.5,
            "n_records": "<b>10</b>", "n_clusters": "<i>3</i>",
            "semantic_family": "unsafe_response_rate", "polarity": "higher_adverse",
        }]},
    }
    text = app._render_level2("l2.json", doc)
    assert "<b>10</b>" not in text and "&lt;b&gt;10&lt;/b&gt;" in text
    app.close()


def test_level2_incompatible_populations_charted_separately(tmp_path: Path) -> None:
    # The SAME metric in two incompatible populations must render as two
    # separate stratum sections, never pooled or labelled by the first row.
    app = _app(tmp_path)
    try:
        doc = {"schema_version": "ura-level2-report/1", "common": {"estimates": [
            {"metric": "ASR", "model_spec": "m", "value": 0.5,
             "semantic_family": "unsafe_response_rate",
             "population": "single_turn", "source": "s1"},
            {"metric": "ASR", "model_spec": "m", "value": 0.9,
             "semantic_family": "unsafe_response_rate",
             "population": "multi_turn", "source": "s1"},
        ]}}
        html_out = app._render_level2("l2.json", doc)
        assert html_out.count("<h3>") == 2  # two separate stratum sections
        assert "population=single_turn" in html_out
        assert "population=multi_turn" in html_out
    finally:
        app.close()


@pytest.mark.parametrize(
    ("field", "left", "right"),
    [
        ("run_id", "run-a", "run-b"),
        ("resolved_model", "model-a", "model-b"),
        ("source_policy_sha256", "a" * 64, "b" * 64),
        ("defense_guardrail_revision", "guard-a", "guard-b"),
        ("ordered_judges", ["rules"], ["rules", "llm"]),
        ("sample_seed", 0, 1),
        ("limit", 8, 16),
        ("horizon_turns", 1, 4),
    ],
)
def test_level2_full_contract_axes_define_separate_charts(
    tmp_path: Path, field: str, left: object, right: object,
) -> None:
    app = _app(tmp_path)
    try:
        base = {
            "metric": "ASR", "semantic_family": "unsafe_response_rate",
            "model_spec": "api:m", "resolved_model": "m", "source": "s",
            "population": "single_turn", "value": 0.5,
        }
        first = {**base, field: left}
        second = {**base, field: right}
        out = app._render_level2(
            "l2.json", {"common": {"estimates": [first, second]}},
        )
        assert out.count("<h3>") == 2, field
    finally:
        app.close()


def test_level2_no_silent_truncation(tmp_path: Path) -> None:
    # 50 rows in one stratum: the chart states "showing 40 of 50" and every
    # one of the 50 rows appears in the table (nothing silently dropped).
    app = _app(tmp_path)
    try:
        estimates = [
            {"metric": "ASR", "model_spec": "m", "value": 0.1,
             "semantic_family": "unsafe_response_rate", "population": "p",
             "source": "s", "n_records": i}
            for i in range(50)
        ]
        doc = {"schema_version": "ura-level2-report/1",
               "common": {"estimates": estimates}}
        html_out = app._render_level2("l2.json", doc)
        assert "40 of 50" in html_out  # explicit "showing X of N" for the chart
        # One header plus all 50 data rows: the table is never truncated.
        assert html_out.count("<tr>") == 51
    finally:
        app.close()


def test_level1_unknown_scope_is_not_measured(tmp_path: Path) -> None:
    app = _app(tmp_path)
    try:
        # Missing/unknown evidence kind -> unknown/invalid, never measured.
        for scope in ({}, {"evidence_kind": "garbage"}):
            out = app._render_level1("l1.json", {"scope": scope, "counts": {}})
            assert "unknown/invalid evidence kind" in out
            assert ">measured<" not in out
        # The exact measured kind still maps to measured; diagnostic stays.
        measured = app._render_level1(
            "l1.json", {"scope": {"evidence_kind": "measured_run"}, "counts": {}},
        )
        assert "badge blue'>measured" in measured
        diag = app._render_level1(
            "l1.json",
            {"scope": {"evidence_kind": "diagnostic_dry_run"}, "counts": {}},
        )
        assert "diagnostic dry-run" in diag
    finally:
        app.close()


def test_http_rejects_negative_and_nonnumeric_content_length(tmp_path: Path) -> None:
    # MED: a spoofed negative or non-numeric Content-Length must be rejected,
    # never fall through to an unbounded rfile.read(-1).
    from experiments.rig_web import _make_server

    app = _app(tmp_path)
    server = _make_server(app, "127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        import socket

        def raw_post(content_length: str) -> int:
            conn = socket.create_connection(("127.0.0.1", port), timeout=10)
            body = b"content=x"
            conn.sendall(
                b"POST /config HTTP/1.1\r\nHost: localhost\r\n"
                + f"Content-Length: {content_length}\r\n".encode()
                + b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                + body
            )
            data = conn.recv(4096)
            conn.close()
            return int(data.split()[1])

        assert raw_post("-1") == 400
        assert raw_post("not-a-number") == 400
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/")
        assert conn.getresponse().status == 200
        conn.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        app.close()


def test_stranded_runs_v1_is_recovered_on_open(tmp_path: Path) -> None:
    # HIGH: an interrupted v1->v2 migration can leave data in runs_v1 beside an
    # empty v2 runs. The next open must recover it, not silently lose it.
    state = tmp_path / "state"
    state.mkdir()
    conn = sqlite3.connect(state / "console.db")
    conn.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE runs (job_id TEXT PRIMARY KEY, kind TEXT, command TEXT,
            out_dir TEXT, pin TEXT, state TEXT, exit_code INTEGER,
            created_at REAL);
        CREATE TABLE runs_v1 (job_id TEXT, kind TEXT, command TEXT,
            out_dir TEXT, pin TEXT, state TEXT, exit_code INTEGER,
            created_at REAL);
        INSERT INTO runs_v1 VALUES ('job-strand', 'measured', 'run_matrix',
            'runs/x', 'pin', 'complete', 0, 1.0);
        """
    )
    conn.commit()
    conn.close()
    db = ConsoleDB(state / "console.db")
    assert db.health()["healthy"]
    runs = db.list_runs()
    assert runs is not None and runs[0]["job_id"] == "job-strand"
    tables = {
        str(row[0]) for row in (db._query(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ) or [])
    }
    assert "runs_v1" not in tables
    db.close()


def test_consoledb_close_is_thread_safe(tmp_path: Path) -> None:
    # MED: accessors check the connection inside the lock, and close() detaches
    # it under the lock, so a concurrent close never raises into a caller.
    app = _app(tmp_path)
    errors: list[str] = []

    def hammer() -> None:
        for _ in range(1500):
            try:
                app.db.load_jobs()
                app.db.usage_totals()
                app.db.list_runs()
            except Exception as exc:  # noqa: BLE001 - the whole point is none escape
                errors.append(repr(exc))

    threads = [threading.Thread(target=hammer) for _ in range(4)]
    for thread in threads:
        thread.start()
    time.sleep(0.02)
    app.db.close()
    for thread in threads:
        thread.join()
    assert not errors, errors[:3]
    # After close, history reads as unknown (None), never a fabricated empty.
    assert app.db.load_jobs() is None


def test_reindex_preserves_usage_from_out_of_root_dirs(tmp_path: Path) -> None:
    # MED/HIGH: reindex scans the results root AND every recorded run out_dir,
    # so usage a job recorded from an --out outside the results root is not
    # silently deleted by a rebuild.
    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    results = tmp_path / "results"
    results.mkdir()
    app = RigWebApp(results_root=results, state_dir=tmp_path / "state", repo_root=repo)
    _write_marker_fixture(repo / "scratch-out", stem="cell-out")

    class _Job:
        job_id = "j-out"
        command = "run_matrix"
        argv = ["--out", "scratch-out"]
        builder_params = None
        directory = repo
        pin = "p"
        failure = None
        started_at = 1.0
        ended_at = 2.0

        def state(self) -> str:
            return "complete"

        def exit_code(self) -> int:
            return 0

    assert app.db.record_terminal(_Job(), "p", [], state="complete", exit_code=0)
    summary = app.reindex_all()
    assert summary["roots"] >= 2
    totals = app.db.usage_totals()
    assert totals is not None
    assert any(k[:3] == ("target", "anthropic", "claude-fable-5") for k in totals)
    app.close()


def test_headless_reindex_and_usage_report_cli(tmp_path: Path, capsys) -> None:
    # The console's bookkeeping is reachable through the CLI too.
    from experiments import rig_web

    results = tmp_path / "runs"
    results.mkdir()
    _write_marker_fixture(results / "lane")
    state = tmp_path / "state"
    assert rig_web.main([
        "--results-root", str(results), "--state-dir", str(state), "--reindex",
    ]) == 0
    reindex_out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert reindex_out["ok"] and reindex_out["usage_rows"] >= 1
    assert rig_web.main([
        "--results-root", str(results), "--state-dir", str(state),
        "--usage-report",
    ]) == 0
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report["schema"] == "ura-console-usage-report/1"
    assert any(row["provider"] == "anthropic" for row in report["rows"])


def test_source_conformance_multi_arm_is_composable() -> None:
    # MED parity: --arm/--observation are action=append on the CLI, so the
    # console offers them as repeatable rows and can build a multi-arm scaffold.
    argv = build_argv("source_conformance", {
        "--scaffold": "on",
        "--arm": "strongreject_official",
        "--arm#1": "advbench_harmful",
        "--observation": "strongreject_official=runs/o1",
        "--observation#1": "advbench_harmful=runs/o2",
        "--source-config": "experiments/source-instances.json",
        "--out": "runs/sc.json",
    })
    assert argv.count("--arm") == 2 and argv.count("--observation") == 2
    assert argv.index("strongreject_official") < argv.index("advbench_harmful")


# -- provider secrets (presence + write-only; values never rendered) -------


@pytest.fixture
def clean_secret_env():
    """Isolate the managed secret env vars: start empty, restore on teardown.

    set_secret mutates os.environ directly (so newly launched jobs inherit the
    key), which pytest's monkeypatch does not track, so we snapshot and restore
    the exact vars ourselves to avoid leaking test keys into the session.
    """

    names = list(RigWebApp._SECRET_NAMES)
    saved = {name: os.environ.get(name) for name in names}
    for name in names:
        os.environ.pop(name, None)
    try:
        yield
    finally:
        for name in names:
            if saved[name] is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = saved[name]


def _secrets_app(tmp_path: Path) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    return RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        env_file=tmp_path / "secrets" / ".ura_env",
    )


def test_set_secret_writes_file_and_environ_never_returns_value(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    secret = "sk-ant-THISVALUE-abcd1234"
    result = app.set_secret("ANTHROPIC_API_KEY", secret)
    assert result is None  # write-only: the call never hands the value back

    # Written to the env file as an export line, and the file is 0600.
    text = app.env_file.read_text(encoding="utf-8")
    assert f"export ANTHROPIC_API_KEY='{secret}'" in text
    if os.name == "posix":
        mode = stat.S_IMODE(app.env_file.stat().st_mode)
        assert mode == 0o600
    # Mirrored into the process so freshly launched jobs inherit it.
    assert os.environ["ANTHROPIC_API_KEY"] == secret


def test_secret_status_masks_value(tmp_path: Path, clean_secret_env) -> None:
    app = _secrets_app(tmp_path)
    app.set_secret("OPENAI_API_KEY", "sk-openai-SECRETVALUE-wxyz9876")
    rows = {row["name"]: row for row in app.secret_status()}
    openai = rows["OPENAI_API_KEY"]
    assert openai["present"] is True
    # Only a last-4 hint is exposed, never the value.
    assert openai["hint"] == "set - ....9876"
    assert "SECRETVALUE" not in json.dumps(rows)
    # A key that was never set reports absent.
    assert rows["DEEPSEEK_API_KEY"]["present"] is False
    assert rows["DEEPSEEK_API_KEY"]["hint"] == "not set"


def test_secrets_page_never_renders_the_value(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    app.set_secret("MOONSHOT_API_KEY", "sk-moon-RAWSECRET-lmno4321")
    _status, _ctype, body = app.handle("GET", "/config/secrets")
    page = body.decode("utf-8")
    assert "RAWSECRET" not in page
    assert "....4321" in page  # the masked hint is what shows
    # The input is a password field with no prefilled value attribute.
    assert "type='password'" in page


def test_set_secret_rejects_bad_input(tmp_path: Path, clean_secret_env) -> None:
    app = _secrets_app(tmp_path)
    with pytest.raises(ValueError, match="unknown secret"):
        app.set_secret("NOT_A_KEY", "x")
    with pytest.raises(ValueError, match="must not be empty"):
        app.set_secret("ANTHROPIC_API_KEY", "   ")
    with pytest.raises(ValueError, match="single line"):
        app.set_secret("ANTHROPIC_API_KEY", "line1\nline2")
    with pytest.raises(ValueError, match="implausibly long"):
        app.set_secret("ANTHROPIC_API_KEY", "x" * 5000)
    # A single quote would break out of the 'export NAME=...' quoting when the
    # env file is sourced (shell injection); reject it fail-closed.
    with pytest.raises(ValueError, match="single quote"):
        app.set_secret("ANTHROPIC_API_KEY", "abc'; echo pwned; x='def")
    with pytest.raises(ValueError, match="control character"):
        app.set_secret("ANTHROPIC_API_KEY", "abc\x00def")
    # A Unicode line/paragraph separator (U+0085/U+2028/U+2029) passes an
    # ord<0x20 control-char check but str.splitlines() splits on it, so a stored
    # key would be torn apart on the next read-modify-write; reject it too.
    for sep in ("\x85", "\u2028", "\u2029"):
        with pytest.raises(ValueError, match="single line"):
            app.set_secret("ANTHROPIC_API_KEY", f"abc{sep}def")


def test_set_secret_written_line_is_shell_safe(
    tmp_path: Path, clean_secret_env,
) -> None:
    # A stored key round-trips through the env file with exactly one token: the
    # sourced line must define only NAME=<value>, never a second command.
    import shlex

    app = _secrets_app(tmp_path)
    app.set_secret("ANTHROPIC_API_KEY", "sk-ant-Aa0_-.+/=~value")
    tokens = shlex.split(app.env_file.read_text(encoding="utf-8"))
    assert tokens == ["export", "ANTHROPIC_API_KEY=sk-ant-Aa0_-.+/=~value"]


def test_set_secret_rotate_replaces_without_duplicate(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    app.set_secret("ANTHROPIC_API_KEY", "sk-ant-FIRST-0001")
    app.set_secret("ANTHROPIC_API_KEY", "sk-ant-SECOND-0002")
    text = app.env_file.read_text(encoding="utf-8")
    assert text.count("export ANTHROPIC_API_KEY=") == 1
    assert "SECOND" in text and "FIRST" not in text
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-SECOND-0002"


def test_clear_secret_removes_from_file_and_environ(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    app.set_secret("DEEPSEEK_API_KEY", "sk-deepseek-GONE-5555")
    app.clear_secret("DEEPSEEK_API_KEY")
    text = app.env_file.read_text(encoding="utf-8")
    assert "DEEPSEEK_API_KEY" not in text
    assert "DEEPSEEK_API_KEY" not in os.environ
    with pytest.raises(ValueError, match="unknown secret"):
        app.clear_secret("NOT_A_KEY")


def test_post_secrets_set_redirects_without_leaking_value(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    secret = "sk-ant-POSTED-9999"
    status, location, _ = app.handle("POST", "/config/secrets", {
        "name": "ANTHROPIC_API_KEY", "action": "set", "value": secret,
    })
    assert status == 303
    # The value must never appear in the redirect target.
    assert secret not in location
    assert "9999" not in location
    assert location.startswith("/config/secrets?saved=ANTHROPIC_API_KEY")
    assert os.environ["ANTHROPIC_API_KEY"] == secret


def test_post_secrets_clear_removes_key(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    app.set_secret("OPENAI_API_KEY", "sk-openai-CLEARME-1111")
    status, location, _ = app.handle("POST", "/config/secrets", {
        "name": "OPENAI_API_KEY", "action": "clear",
    })
    assert status == 303
    assert "OPENAI_API_KEY" not in os.environ


def test_post_secrets_invalid_shows_error_not_500(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    status, ctype, body = app.handle("POST", "/config/secrets", {
        "name": "ANTHROPIC_API_KEY", "action": "set", "value": "",
    })
    assert status == 200  # rendered form with an inline error, not a crash
    assert "must not be empty" in body.decode("utf-8")


def test_set_secret_write_fault_raises_valueerror(
    tmp_path: Path, clean_secret_env, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _secrets_app(tmp_path)

    def failing_replace(src, dst, *args, **kwargs):
        raise PermissionError("read-only secrets file")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(ValueError, match="could not write the secrets file"):
        app.set_secret("ANTHROPIC_API_KEY", "sk-ant-value")


def test_post_secrets_write_fault_shows_error_not_500(
    tmp_path: Path, clean_secret_env, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A filesystem write fault must render the "Not saved" page, not 500.
    app = _secrets_app(tmp_path)

    def failing_replace(src, dst, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", failing_replace)
    status, _ctype, body = app.handle("POST", "/config/secrets", {
        "name": "ANTHROPIC_API_KEY", "action": "set", "value": "sk-ant-value",
    })
    assert status == 200
    assert "could not write the secrets file" in body.decode("utf-8")


def test_set_secret_writes_lf_line_endings(tmp_path: Path, clean_secret_env) -> None:
    # The env file is sourced by a POSIX shell; a stray CR would ride into the
    # key value and 401 every call.  It must be LF-only on any platform.
    app = _secrets_app(tmp_path)
    app.set_secret("ANTHROPIC_API_KEY", "sk-ant-lf")
    raw = app.env_file.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"'\n")


def test_clear_secret_unreadable_file_fails_closed(
    tmp_path: Path, clean_secret_env, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If the file is present but unreadable, Clear must NOT report success while
    # the key survives on disk (it would resurrect on the next source).
    app = _secrets_app(tmp_path)
    app.set_secret("OPENAI_API_KEY", "sk-openai-keep")
    original = Path.read_text

    def failing(self, *args, **kwargs):
        if self.name == ".ura_env":
            raise PermissionError("share-locked")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing)
    with pytest.raises(ValueError, match="could not read the secrets file"):
        app.clear_secret("OPENAI_API_KEY")
    monkeypatch.undo()
    assert "OPENAI_API_KEY" in app.env_file.read_text(encoding="utf-8")  # still on disk
    assert os.environ.get("OPENAI_API_KEY") == "sk-openai-keep"  # not falsely popped


def test_set_secret_unreadable_file_does_not_clobber_other_keys(
    tmp_path: Path, clean_secret_env, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _secrets_app(tmp_path)
    app.set_secret("GEMINI_API_KEY", "sk-gem-keep")
    original = Path.read_text

    def failing(self, *args, **kwargs):
        if self.name == ".ura_env":
            raise PermissionError("share-locked")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", failing)
    with pytest.raises(ValueError, match="could not read the secrets file"):
        app.set_secret("ANTHROPIC_API_KEY", "sk-ant-new")
    monkeypatch.undo()
    assert "GEMINI_API_KEY" in app.env_file.read_text(encoding="utf-8")


def test_set_secret_is_serialized_by_secret_lock(
    tmp_path: Path, clean_secret_env,
) -> None:
    app = _secrets_app(tmp_path)
    done: list[bool] = []

    def setter() -> None:
        app.set_secret("ANTHROPIC_API_KEY", "sk-ant-x")
        done.append(True)

    with app._secret_lock:
        worker = threading.Thread(target=setter)
        worker.start()
        worker.join(timeout=0.3)
        assert not done  # blocked while the lock is held
    worker.join(timeout=3)
    assert done == [True]


def test_pricing_fetch_banner_reports_zero_match_provider() -> None:
    # A machine-readable provider that fetched but matched no models must still
    # appear in the banner, not vanish silently.
    summary = {
        "rates_written": 0,
        "providers": {
            "anthropic": {
                "url": "https://a", "matched": [], "unmatched": ["claude-x"],
                "note": "",
            },
        },
    }
    banner = RigWebApp._pricing_fetch_banner(json.dumps(summary))
    assert "anthropic" in banner
    assert "matched 0 of 1 model" in banner


def test_set_secret_atomic_write_preserves_prior_file_on_fault(
    tmp_path: Path, clean_secret_env, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A mid-write fault must leave the PRIOR secrets file intact (atomic), not
    # an empty/truncated file, and no stray .tmp behind.
    app = _secrets_app(tmp_path)
    app.set_secret("ANTHROPIC_API_KEY", "sk-ant-FIRST")
    before = app.env_file.read_text(encoding="utf-8")

    def failing_replace(src, dst, *args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(ValueError):
        app.set_secret("OPENAI_API_KEY", "sk-openai-SECOND")
    monkeypatch.undo()
    assert app.env_file.read_text(encoding="utf-8") == before  # prior file intact
    assert not app.env_file.with_name(app.env_file.name + ".tmp").exists()


def test_rate_for_same_date_operator_beats_auto_any_order() -> None:
    # The billing resolver must bill at the operator's same-date rate, never the
    # auto-fetched one, regardless of which entry is first in the list.
    auto = {
        "effective_date": "2026-08-16", "currency": "USD",
        "per_million_tokens": {"input": 1.4, "output": 4.4}, "auto_fetched": True,
    }
    operator = {
        "effective_date": "2026-08-16", "currency": "USD",
        "per_million_tokens": {"input": 9.99, "output": 9.99},
    }
    for order in ([auto, operator], [operator, auto]):
        pricing = {"providers": {"glm": {"models": {"glm-5.2": {"rates": order}}}}}
        rate, why = rate_for(pricing, "glm", "glm-5.2", on_date="2026-08-16")
        assert why == ""
        assert rate["per_million_tokens"]["input"] == 9.99


def _auto_rate(inp: float, out: float, date: str = "2026-08-16") -> dict:
    return {
        "effective_date": date, "currency": "USD",
        "per_million_tokens": {"input": inp, "output": out},
        "auto_fetched": True, "source_url": "https://z/pricing", "fetched_at": date,
    }


def test_reconcile_pricing_ownership_deauthes_edited_rate() -> None:
    current = {"providers": {"glm": {"models": {"glm-5.2": {
        "rates": [_auto_rate(1.4, 4.4)]}}}}}
    # Operator corrected input to 9.99 in place, keeping the auto flags.
    edited = _auto_rate(1.4, 4.4)
    edited["per_million_tokens"]["input"] = 9.99
    submitted = {"providers": {"glm": {"models": {"glm-5.2": {
        "rates": [edited]}}}}}
    reconcile_pricing_ownership(submitted, current)
    rate = submitted["providers"]["glm"]["models"]["glm-5.2"]["rates"][0]
    assert "auto_fetched" not in rate
    assert "source_url" not in rate and "fetched_at" not in rate
    assert rate["per_million_tokens"]["input"] == 9.99


def test_reconcile_pricing_ownership_keeps_untouched_rate() -> None:
    current = {"providers": {"glm": {"models": {"glm-5.2": {
        "rates": [_auto_rate(1.4, 4.4)]}}}}}
    submitted = {"providers": {"glm": {"models": {"glm-5.2": {
        "rates": [_auto_rate(1.4, 4.4)]}}}}}
    reconcile_pricing_ownership(submitted, current)
    rate = submitted["providers"]["glm"]["models"]["glm-5.2"]["rates"][0]
    assert rate.get("auto_fetched") is True  # unchanged: provenance retained


def test_edited_fetched_rate_survives_refetch(tmp_path: Path) -> None:
    # End to end: an in-place correction of an auto rate (via the config editor)
    # must not be reverted by the next fetch.
    from experiments import pricing_fetch

    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    pricing_path = repo / "experiments" / "pricing.json"
    pricing_path.write_text(
        json.dumps({"providers": {"glm": {"models": {"glm-5.2": {
            "rates": [_auto_rate(1.4, 4.4)]}}}}}),
        encoding="utf-8",
    )
    (repo / "experiments" / "pricing-sources.json").write_text(
        json.dumps({"providers": {"glm": {"url": "https://z/pricing"}}}),
        encoding="utf-8",
    )
    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(
        results_root=results, state_dir=tmp_path / "state", repo_root=repo,
    )
    # Operator edits the fetched rate's input to 9.99 in place and saves.
    edited = _auto_rate(1.4, 4.4)
    edited["per_million_tokens"]["input"] = 9.99
    content = json.dumps({"providers": {"glm": {"models": {"glm-5.2": {
        "rates": [edited]}}}}})
    app.save_config("pricing", content)
    saved = json.loads(pricing_path.read_text("utf-8"))
    rate = saved["providers"]["glm"]["models"]["glm-5.2"]["rates"][0]
    assert "auto_fetched" not in rate  # de-authed on save

    # A re-fetch on the same date must not revert the correction.
    glm_html = (Path(__file__).parent / "fixtures" / "pricing" / "glm.html").read_text(
        "utf-8"
    )
    summary = pricing_fetch.fetch_pricing(
        repo, today="2026-08-16", fetcher=lambda url: glm_html,
    )
    assert summary["rates_written"] == 0
    final = json.loads(pricing_path.read_text("utf-8"))
    effective = pricing_fetch._current_effective(
        final["providers"]["glm"]["models"]["glm-5.2"], "2026-08-16",
    )
    assert effective["per_million_tokens"]["input"] == 9.99


def test_rate_for_skips_null_placeholder_and_bills_earlier_operator_rate() -> None:
    # A later-dated all-null placeholder must not shadow an operator's earlier
    # real rate: the billed figure is the operator's, not N/A.
    operator = {
        "effective_date": "2026-08-10", "currency": "USD",
        "per_million_tokens": {"input": 9.99, "output": 9.99},
    }
    placeholder = {
        "effective_date": "2026-08-16", "currency": "USD",
        "per_million_tokens": {"input": None, "output": None},
    }
    pricing = {"providers": {"glm": {"models": {"glm-5.2": {
        "rates": [operator, placeholder]}}}}}
    rate, why = rate_for(pricing, "glm", "glm-5.2", on_date="2026-08-16")
    assert why == ""
    assert rate["per_million_tokens"]["input"] == 9.99


def test_pricing_save_is_serialized_by_pricing_lock(tmp_path: Path) -> None:
    # The pricing config editor and the pricing fetcher both rewrite
    # pricing.json; save_config("pricing") must take the shared pricing lock so
    # a save cannot interleave with (and be lost by) a concurrent fetch.
    app = _isolated_app(tmp_path)
    content = json.dumps({"schema": "ura-console-pricing/1", "providers": {}})
    done: list[bool] = []

    def saver() -> None:
        app.save_config("pricing", content)
        done.append(True)

    with app._pricing_lock:
        worker = threading.Thread(target=saver)
        worker.start()
        worker.join(timeout=0.3)
        assert not done  # blocked while the lock is held here
    worker.join(timeout=3)
    assert done == [True]  # proceeds once the lock is released


def test_busy_overlay_present_and_fetch_opts_in(tmp_path: Path) -> None:
    # Slow POSTs (the pricing fetch) show a modal spinner and cannot double
    # submit: the shell carries the overlay and the fetch form opts in.
    app = _isolated_app(tmp_path)
    _status, _ctype, body = app.handle("GET", "/config?file=pricing")
    page = body.decode("utf-8")
    assert "id='busy-overlay'" in page
    assert "data-busy='Fetching provider pricing pages" in page
    # Every rendered page carries the overlay wiring (the shell).
    _s, _c, home = app.handle("GET", "/")
    assert "id='busy-overlay'" in home.decode("utf-8")


def test_pricing_fetch_route_delegates_and_redirects(tmp_path: Path) -> None:
    # POST /pricing/fetch runs the fetcher over the isolated repo and redirects
    # to the config page with a summary; no network is touched because the
    # isolated repo has no sources file (empty providers).
    repo = tmp_path / "repo"
    (repo / "experiments" / "rig").mkdir(parents=True, exist_ok=True)
    (repo / "experiments" / "pricing.json").write_text(
        json.dumps({"providers": {}}), encoding="utf-8",
    )
    (repo / "experiments" / "pricing-sources.json").write_text(
        json.dumps({"providers": {}}), encoding="utf-8",
    )
    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(
        results_root=results, state_dir=tmp_path / "state", repo_root=repo,
    )
    status, location, _ = app.handle("POST", "/pricing/fetch", {})
    assert status == 303
    assert location.startswith("/config?file=pricing&fetched=")
