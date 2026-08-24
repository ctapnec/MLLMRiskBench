"""Campaign-first Stats page, lazy detail, and derived-index boundaries."""

from __future__ import annotations

import hashlib
import http.client
import json
import sqlite3
import threading
import time
from html.parser import HTMLParser
from pathlib import Path

from experiments.rig_web import Job, RigWebApp, _LEVEL2_ROW_FIELDS, collect_reports
from experiments.rig_web_app.server import _make_server


class _HrefCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        href = dict(attrs).get("href")
        if href:
            self.hrefs.append(href)


def _app(tmp_path: Path) -> RigWebApp:
    return RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
    )


def _descriptor(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "file": path.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "records": 1,
    }


def _write_completed_cell(root: Path, *, run_id: str, target: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    responses = root / "cell.responses.jsonl"
    responses.write_text(
        json.dumps(
            {
                "target": target,
                "tokens": {"input": 11, "output": 7, "total": 18},
                "raw": {"provider": "mock", "resolved_model": target},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    trails = root / "cell.trails.jsonl"
    trails.write_text(
        json.dumps(
            {
                "raw": {
                    "judge_model": "mock-judge",
                    "judge_call": {
                        "provider": "mock",
                        "provider_resolved_model": "mock-judge",
                        "sampling_control": "seeded",
                        "tokens": {"input": 5, "output": 2, "total": 7},
                    },
                }
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "cell.complete.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "format_version": 2,
                "run_id": run_id,
                "completed_at": time.time(),
                "artifacts": {
                    "responses": _descriptor(responses),
                    "trails": _descriptor(trails),
                },
            }
        ),
        encoding="utf-8",
    )


def _record_run(
    app: RigWebApp,
    tmp_path: Path,
    *,
    job_id: str,
    out: Path,
    extra: list[str],
) -> Job:
    job = Job(
        job_id=job_id,
        command="run_matrix",
        argv=[*extra, "--out", str(out)],
        directory=tmp_path / "jobs" / job_id,
        process=None,
        restored_state="complete",
        restored_exit=0,
        started_at=time.time(),
        ended_at=time.time(),
    )
    app.jobs[job_id] = job
    assert app.db.record_terminal(
        job,
        "a" * 40,
        [],
        state="complete",
        exit_code=0,
    )
    return job


def _record_running_job(
    app: RigWebApp,
    tmp_path: Path,
    *,
    job_id: str,
    command: str = "run_matrix",
    extra: list[str] | None = None,
    started_at: float | None = None,
) -> Job:
    job = Job(
        job_id=job_id,
        command=command,
        argv=list(extra or []),
        directory=tmp_path / "jobs" / job_id,
        process=None,
        restored_state="running",
        restored_exit=None,
        started_at=time.time() if started_at is None else started_at,
    )
    app.jobs[job_id] = job
    assert app.db.upsert_job(job, state="running", exit_code=None)
    return job


def _write_level2(path: Path, *, run_id: str, model: str, metric: str) -> None:
    row = {field: None for field in _LEVEL2_ROW_FIELDS}
    row.update(
        {
            "run_id": run_id,
            "corpus_arm": "strongreject_official",
            "model_spec": model,
            "resolved_model": model,
            "source": "strongreject",
            "risk_category": "harm",
            "effective_modality": "text",
            "expected_behavior": "refuse",
            "attacker": "deepteam",
            "defense": "none",
            "semantic_family": "safety",
            "metric": metric,
            "metric_authority": "authoritative_or_source_native",
            "value": 0.5,
            "ci_low": 0.25,
            "ci_high": 0.75,
            "n_records": 1,
            "n_clusters": 1,
            "judgments_completed": 1,
            "judgments_evaluable": 1,
            "judgments_decided": 1,
            "judgments_abstained": 0,
            "judgments_non_evaluable": 0,
            "cross_stratum_pooling_permitted": False,
        }
    )
    report: dict[str, object] = {
        "schema_version": "ura-level2-report/1",
        "status": "deterministic_compatible_stratum_export",
        "empirical_validity_established": False,
        "pooling_policy": {
            "universal_safety_score_defined": False,
            "cross_stratum_pooling_permitted": False,
            "native_scale_pooling_permitted": False,
        },
        "common": {"n_estimate_rows": 1, "estimates": [row]},
    }
    material = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    report["report_id"] = "level2-" + hashlib.sha256(material).hexdigest()[:24]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")


def _write_empty_level2(path: Path) -> None:
    report: dict[str, object] = {
        "schema_version": "ura-level2-report/1",
        "status": "deterministic_compatible_stratum_export",
        "empirical_validity_established": False,
        "pooling_policy": {
            "universal_safety_score_defined": False,
            "cross_stratum_pooling_permitted": False,
            "native_scale_pooling_permitted": False,
        },
        "common": {"n_estimate_rows": 0, "estimates": []},
    }
    material = json.dumps(
        report,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    report["report_id"] = "level2-" + hashlib.sha256(material).hexdigest()[:24]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")


def _write_engineering_campaign(
    app: RigWebApp,
    *,
    campaign_id: str,
    started_at: float,
) -> Path:
    root = app.results_root / "engineering" / campaign_id
    root.mkdir(parents=True)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at))
    (root / "ENGINEERING_ONLY.json").write_text(
        json.dumps(
            {
                "schema": "ura-engineering-campaign/1",
                "campaign_id": campaign_id,
                "release_commit": "1" * 40,
                "evidence_class": "engineering_test",
                "thesis_empirical_evidence": False,
                "hosted_calls_allowed": False,
                "hard_stop_hours": 1,
                "started_at": stamp,
                "planned_tasks": ["inspect"],
            }
        ),
        encoding="utf-8",
    )
    events = (
        {
            "at": stamp,
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
            "detail": "started",
        },
        {
            "at": stamp,
            "event": "campaign_end",
            "task": "bootstrap",
            "status": "passed",
            "detail": "complete",
        },
    )
    (root / "task-log.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )
    return root


def _record_analysis_job(
    app: RigWebApp,
    tmp_path: Path,
    *,
    job_id: str,
    results: Path,
    report: Path,
    state: str = "complete",
    exit_code: int | None = 0,
) -> None:
    job = Job(
        job_id=job_id,
        command="level2_report",
        argv=["--results", str(results), "--out-json", str(report)],
        directory=tmp_path / "jobs" / job_id,
        process=None,
        restored_state=state,
        restored_exit=exit_code,
    )
    app.jobs[job_id] = job
    assert app.db.upsert_job(job, state=state, exit_code=exit_code)


def test_stats_lists_real_jobs_with_distinct_authority_and_one_lazy_modal(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    measured = app.results_root / "thesis" / "measured"
    _write_completed_cell(measured, run_id="run-measured", target="model-measured")
    _record_run(
        app,
        tmp_path,
        job_id="job-measured",
        out=measured,
        extra=[
            "--api",
            "openai:model-measured",
            "--attackers",
            "deepteam",
            "--corpora",
            "strongreject_official",
        ],
    )
    _record_run(
        app,
        tmp_path,
        job_id="job-synthetic",
        out=app.results_root / "synthetic",
        extra=["--api", "mock", "--corpora", "synth"],
    )
    _record_run(
        app,
        tmp_path,
        job_id="job-diagnostic",
        out=app.results_root / "diagnostic",
        extra=["--diagnostic-canary", "--api", "mock"],
    )
    _record_run(
        app,
        tmp_path,
        job_id="job-preflight",
        out=app.results_root / "preflight",
        extra=["--preflight-only"],
    )

    text = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "data-authority='thesis-measured'" in text
    assert "data-authority='synthetic'" in text
    assert "data-authority='diagnostic'" in text
    assert "data-authority='preflight'" in text
    assert "model-measured" in text and "deepteam" in text
    assert "strongreject_official" in text
    assert "1 target / 1 judge" in text and "16 input / 9 output" in text
    for label in ("Target", "Framework", "Corpus", "Started", "Ended", "Cost", "Results"):
        assert f"<dt>{label}</dt>" in text
    assert "local / not billed" in text and "1 complete cell" in text
    assert text.count("id='campaign-stats-modal'") == 1
    assert text.count("data-stats-job=") == 4
    assert text.count("Statistics details") == 4
    for job_id in ("job-measured", "job-synthetic", "job-diagnostic", "job-preflight"):
        card = text.split(f"data-job-id='{job_id}'", 1)[1].split("</article>", 1)[0]
        assert "Statistics details" in card
        assert "Statistics &amp; diagrams" not in card
    assert "fetch(trigger.href" in text
    assert "aria-haspopup='dialog'" in text
    assert "event.key==='Escape'" in text and "last.focus()" in text
    assert "class='barchart'" not in text
    # A real href is the complete no-JS fallback; it is not an inert hash.
    assert "href='/stats/job/job-measured'" in text
    app.close()


def test_stats_lists_external_campaigns_first_with_resolvable_detail_and_artifacts(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign_id = "external-campaign-newer"
    _write_engineering_campaign(
        app,
        campaign_id=campaign_id,
        started_at=time.time() + 60,
    )
    _record_run(
        app,
        tmp_path,
        job_id="job-older-diagnostic",
        out=app.results_root / "diagnostic-old",
        extra=["--diagnostic-canary", "--api", "mock"],
    )

    text = app.handle("GET", "/stats")[2].decode("utf-8")
    campaign_card = text.index(f"/jobs/campaign/{campaign_id}")
    console_heading = text.index("<h2>Console run attempts</h2>")
    console_card = text.index("data-job-id='job-older-diagnostic'")
    assert campaign_card < console_heading < console_card

    detail_href = f"/jobs/campaign/{campaign_id}"
    artifact_href = f"/artifacts?path=engineering/{campaign_id}"
    assert f"href='{detail_href}'" in text
    assert f"href='{artifact_href}'" in text
    assert app.handle("GET", detail_href)[0] == 200
    assert app.handle("GET", artifact_href)[0] == 200
    app.close()


def test_stats_cta_promises_diagrams_only_for_chart_renderable_bound_report(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    chart_root = app.results_root / "thesis" / "chart"
    table_root = app.results_root / "thesis" / "table-only"
    for job_id, root in (("job-chart", chart_root), ("job-table", table_root)):
        root.mkdir(parents=True)
        _record_run(
            app,
            tmp_path,
            job_id=job_id,
            out=root,
            extra=["--api", "openai:model", "--corpora", "strongreject_official"],
        )

    chart_report = app.results_root / "thesis" / "analysis" / "chart.json"
    table_report = app.results_root / "thesis" / "analysis" / "table.json"
    _write_level2(
        chart_report,
        run_id="run-chart",
        model="model",
        metric="chart_metric",
    )
    _write_empty_level2(table_report)
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-chart",
        results=chart_root,
        report=chart_report,
    )
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-table",
        results=table_root,
        report=table_report,
    )

    index = app.handle("GET", "/stats")[2].decode("utf-8")
    chart_card = index.split("data-job-id='job-chart'", 1)[1].split("</article>", 1)[0]
    table_card = index.split("data-job-id='job-table'", 1)[1].split("</article>", 1)[0]
    assert "Statistics &amp; diagrams" in chart_card
    assert "Statistics details" not in chart_card
    assert "Statistics details" in table_card
    assert "Statistics &amp; diagrams" not in table_card
    assert "class='barchart'" not in index

    chart_detail = app.handle("GET", "/stats/job/job-chart?fragment=1")[2].decode("utf-8")
    table_detail = app.handle("GET", "/stats/job/job-table?fragment=1")[2].decode("utf-8")
    assert "class='barchart'" in chart_detail
    assert "class='barchart'" not in table_detail
    assert "Validated Level-2 report with no common estimate rows" in table_detail
    app.close()


def test_lazy_job_detail_binds_only_the_selected_job_report(tmp_path: Path) -> None:
    app = _app(tmp_path)
    root_a = app.results_root / "thesis" / "a"
    root_b = app.results_root / "thesis" / "b"
    _write_completed_cell(root_a, run_id="run-a", target="target-a")
    _write_completed_cell(root_b, run_id="run-b", target="target-b")
    for suffix, root in (("a", root_a), ("b", root_b)):
        _record_run(
            app,
            tmp_path,
            job_id=f"job-{suffix}",
            out=root,
            extra=[
                "--api",
                f"openai:target-{suffix}",
                "--corpora",
                "strongreject_official",
            ],
        )
        report = app.results_root / "thesis" / "analysis" / f"{suffix}.json"
        _write_level2(
            report,
            run_id=f"run-{suffix}",
            model=f"target-{suffix}",
            metric=f"metric_{suffix}",
        )
        _record_analysis_job(
            app,
            tmp_path,
            job_id=f"analysis-{suffix}",
            results=root,
            report=report,
        )

    index = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "metric_a" not in index and "metric_b" not in index
    assert "class='barchart'" not in index
    status, content_type, fragment = app.handle("GET", "/stats/job/job-a?fragment=1")
    detail = fragment.decode("utf-8")
    assert status == 200 and content_type == "text/html; charset=utf-8"
    assert "metric_a" in detail and "target-a" in detail
    assert "metric_b" not in detail and "target-b" not in detail
    assert detail.count("class='barchart'") == 1
    assert "/artifacts?path=thesis/analysis/a.json" in detail
    assert "<!doctype html>" not in detail
    full = app.handle("GET", "/stats/job/job-a")[2].decode("utf-8")
    assert "<!doctype html>" in full and "Back to campaign statistics" in full
    app.close()


def test_missing_and_malformed_job_evidence_fails_closed(tmp_path: Path) -> None:
    app = _app(tmp_path)
    missing = app.results_root / "thesis" / "missing"
    _record_run(
        app,
        tmp_path,
        job_id="job-missing",
        out=missing,
        extra=["--api", "openai:missing", "--corpora", "strongreject_official"],
    )
    malformed = app.results_root / "thesis" / "malformed"
    malformed.mkdir(parents=True)
    (malformed / "bad.complete.json").write_text("{}", encoding="utf-8")
    _record_run(
        app,
        tmp_path,
        job_id="job-malformed",
        out=malformed,
        extra=["--api", "openai:bad", "--corpora", "strongreject_official"],
    )
    bad_report = app.results_root / "thesis" / "analysis" / "bad.json"
    bad_report.parent.mkdir(parents=True)
    bad_report.write_text('{"schema_version":"ura-level2-report/1"}', encoding="utf-8")
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-bad",
        results=malformed,
        report=bad_report,
    )

    missing_detail = app.handle("GET", "/stats/job/job-missing?fragment=1")[2].decode("utf-8")
    assert "Evidence not established" in missing_detail
    assert "No completion-bound model usage" in missing_detail
    malformed_detail = app.handle("GET", "/stats/job/job-malformed?fragment=1")[2].decode("utf-8")
    assert "Evidence incomplete / invalid" in malformed_detail
    assert "1 invalid/unreadable" in malformed_detail
    assert "badge red'>invalid" in malformed_detail
    assert "class='barchart'" not in malformed_detail
    assert app.handle("GET", "/stats/job/not/typed")[0] == 404
    app.close()


def test_engineering_fixture_rows_are_hidden_then_pruned_by_safe_reindex(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    contaminated = app.results_root / "engineering" / "campaign" / "tmp" / "pytest"
    contaminated.mkdir(parents=True)
    report = contaminated / "fixture.json"
    _write_level2(report, run_id="fixture", model="fixture-model", metric="fixture_metric")
    app.db.reindex(
        [
            {
                "marker_sha": "b" * 64,
                "role": "target",
                "provider": "mock",
                "model": "fixture-model",
                "category": "calls",
                "amount": 999,
                "run_id": "fixture",
                "out_dir": str(contaminated),
                "usage_date": "2026-08-18",
                "recorded_at": time.time(),
            }
        ],
        [
            {
                "path": "engineering/campaign/tmp/pytest/fixture.json",
                "schema": "ura-level2-report/1",
                "kind": "level2",
                "sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                "bytes": report.stat().st_size,
                "mtime": report.stat().st_mtime,
                "recorded_at": time.time(),
            }
        ],
    )
    assert app.db.list_reports() == []
    assert app.db.usage_totals() == {}
    text = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "fixture_metric" not in text and "fixture-model" not in text

    summary = app.reindex_all()
    assert summary["ok"] is True and summary["reports"] == 0
    with sqlite3.connect(app.state_dir / "console.db") as conn:
        assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM usage").fetchone()[0] == 0
    app.close()


def test_explicit_engineering_boundary_blocks_ordinary_in_root_lane(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    lane = app.results_root / "custom-retained-lane"
    _write_completed_cell(
        lane,
        run_id="run-engineering-boundary",
        target="engineering-model",
    )
    (lane / "ENGINEERING_ONLY.json").write_text("{}", encoding="utf-8")
    _record_run(
        app,
        tmp_path,
        job_id="job-engineering-boundary",
        out=lane,
        extra=[
            "--api",
            "openai:engineering-model",
            "--attackers",
            "deepteam",
            "--corpora",
            "strongreject_official",
        ],
    )
    report = lane / "level2.json"
    _write_level2(
        report,
        run_id="run-engineering-boundary",
        model="engineering-model",
        metric="engineering_only_metric",
    )
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-engineering-boundary",
        results=lane,
        report=report,
    )

    index = app.handle("GET", "/stats")[2].decode("utf-8")
    card = index.split("data-job-id='job-engineering-boundary'", 1)[1].split(
        "</article>", 1
    )[0]
    assert "data-authority='engineering'" in card
    assert "engineering / non-thesis" in card
    assert "0 target / 0 judge" in card
    assert "0 complete cells" in card
    assert "engineering_only_metric" not in index

    detail = app.handle(
        "GET", "/stats/job/job-engineering-boundary?fragment=1"
    )[2].decode("utf-8")
    assert "No completion-bound model usage" in detail
    assert "0 complete cells" in detail
    assert "engineering_only_metric" not in detail
    assert "class='barchart'" not in detail

    summary = app.reindex_all()
    assert summary["ok"] is True
    assert summary["roots"] == 0
    assert summary["markers"] == 0
    assert summary["usage_rows"] == 0
    assert summary["reports"] == 0
    assert app.db.usage_totals() == {}
    app.close()


def test_unlinked_panel_rejects_suite_and_canary_schemas(tmp_path: Path) -> None:
    app = _app(tmp_path)
    suite = app.results_root / "misc" / "suite.json"
    canary = app.results_root / "misc" / "canary.json"
    suite.parent.mkdir(parents=True)
    suite.write_text(
        json.dumps({"schema_version": "ura-suite-evidence/1"}),
        encoding="utf-8",
    )
    canary.write_text(
        json.dumps({"schema_version": "ura-lane-canary/1"}),
        encoding="utf-8",
    )

    assert {row["kind"] for row in collect_reports(app.results_root)} == {
        "suite",
        "canary",
    }
    assert app._report_index() == []
    assert app.db.reindex(
        [],
        [
            {
                "path": path.relative_to(app.results_root).as_posix(),
                "schema": schema,
                "kind": kind,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "bytes": path.stat().st_size,
                "mtime": path.stat().st_mtime,
                "recorded_at": time.time(),
            }
            for path, schema, kind in (
                (suite, "ura-suite-evidence/1", "suite"),
                (canary, "ura-lane-canary/1", "canary"),
            )
        ],
    )
    assert app._report_index() == []
    text = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "misc/suite.json" not in text
    assert "misc/canary.json" not in text
    for path, kind in (("misc/suite.json", "suite"), ("misc/canary.json", "canary")):
        badge = app._stats_report_index_badge({"path": path, "kind": kind})
        assert "unsupported kind" in badge
        assert "badge green" not in badge
    app.close()


def test_stats_campaign_index_is_paginated_with_all_jobs_reachable(tmp_path: Path) -> None:
    app = _app(tmp_path)
    for index in range(26):
        _record_run(
            app,
            tmp_path,
            job_id=f"job-{index:02d}",
            out=app.results_root / f"lane-{index:02d}",
            extra=["--preflight-only"],
        )
    first = app.handle("GET", "/stats")[2].decode("utf-8")
    second = app.handle("GET", "/stats?page=2")[2].decode("utf-8")
    assert first.count("data-stats-job=") == 24
    assert "href='/stats?page=2'>Older</a>" in first
    assert second.count("data-stats-job=") == 2
    assert "href='/stats?page=1'>Newer</a>" in second
    assert "Page 2" in second
    app.close()


def test_stats_includes_active_run_kind_job_in_card_and_detail_only(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    _record_running_job(
        app,
        tmp_path,
        job_id="job-running-measured",
        extra=[
            "--api",
            "openai:running-model",
            "--attackers",
            "deepteam",
            "--corpora",
            "strongreject_official",
            "--out",
            str(app.results_root / "active"),
        ],
    )
    for job_id, command in (
        ("job-console-support", "ollama_pull"),
        ("job-native-support", "native_import"),
        ("job-framework-support", "framework_runtime_installer"),
    ):
        _record_running_job(
            app,
            tmp_path,
            job_id=job_id,
            command=command,
            extra=["support-only"],
        )

    status, _headers, body = app.handle("GET", "/stats")
    assert status == 200
    index = body.decode("utf-8")
    card = index.split("data-job-id='job-running-measured'", 1)[1].split(
        "</article>", 1
    )[0]
    assert "<span class='badge blue'>running</span>" in card
    assert "<dt>Ended</dt><dd>running / not recorded</dd>" in card
    assert "data-authority='measured-incomplete'" in card
    assert "running-model" in card and "deepteam" in card
    for job_id in (
        "job-console-support",
        "job-native-support",
        "job-framework-support",
    ):
        assert job_id not in index

    status, _headers, body = app.handle(
        "GET", "/stats/job/job-running-measured?fragment=1"
    )
    assert status == 200
    detail = body.decode("utf-8")
    assert "Campaign status" in detail
    assert "<span class='badge blue'>running</span>" in detail
    assert "Open full job record" in detail
    for job_id in (
        "job-console-support",
        "job-native-support",
        "job-framework-support",
    ):
        assert app.handle("GET", f"/stats/job/{job_id}")[0] == 404
    app.close()


def test_stats_orphaned_run_without_end_time_never_says_running(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    output = app.results_root / "diagnostic-orphaned"
    _write_completed_cell(output, run_id="run-orphaned", target="mock")
    _record_running_job(
        app,
        tmp_path,
        job_id="job-orphaned",
        extra=["--dry-run", "--api", "mock", "--out", str(output)],
    )
    app.close()

    restarted = _app(tmp_path)
    index = restarted.handle("GET", "/stats")[2].decode("utf-8")
    card = index.split("data-job-id='job-orphaned'", 1)[1].split(
        "</article>", 1
    )[0]
    assert "<span class='badge amber'>orphaned</span>" in card
    assert "<dt>Ended</dt><dd>not recorded</dd>" in card
    assert "<dt>Ended</dt><dd>running / not recorded</dd>" not in card
    restarted.close()


def test_stats_active_job_participates_in_pagination_and_run_row_wins(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    for index in range(24):
        _record_run(
            app,
            tmp_path,
            job_id=f"job-terminal-{index:02d}",
            out=app.results_root / f"terminal-{index:02d}",
            extra=["--preflight-only"],
        )
    _record_running_job(
        app,
        tmp_path,
        job_id="job-active-newest",
        extra=["--preflight-only", "--out", str(app.results_root / "active-newest")],
        started_at=time.time() + 60,
    )

    first = app.handle("GET", "/stats")[2].decode("utf-8")
    second = app.handle("GET", "/stats?page=2")[2].decode("utf-8")
    assert first.count("data-stats-job=") == 24
    assert "job-active-newest" in first and "job-active-newest" not in second
    assert second.count("data-stats-job=") == 1

    terminal = app.jobs.pop("job-terminal-00")
    stale = Job(
        job_id=terminal.job_id,
        command=terminal.command,
        argv=list(terminal.argv),
        directory=terminal.directory,
        process=None,
        restored_state="running",
        restored_exit=None,
        started_at=terminal.started_at,
    )
    assert app.db.upsert_job(stale, state="running", exit_code=None)
    detail = app.handle(
        "GET", "/stats/job/job-terminal-00?fragment=1"
    )[2].decode("utf-8")
    assert "<span class='badge green'>passed</span>" in detail
    assert "<span class='badge blue'>running</span>" not in detail
    app.close()


def test_stats_recovers_db_only_report_producer_after_restart(tmp_path: Path) -> None:
    app = _app(tmp_path)
    run_root = app.results_root / "thesis" / "restart"
    _write_completed_cell(run_root, run_id="run-restart", target="target-restart")
    _record_run(
        app,
        tmp_path,
        job_id="job-restart",
        out=run_root,
        extra=["--api", "openai:target-restart", "--corpora", "strongreject_official"],
    )
    report = app.results_root / "thesis" / "analysis" / "restart.json"
    _write_level2(
        report,
        run_id="run-restart",
        model="target-restart",
        metric="metric_restart",
    )
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-restart",
        results=run_root,
        report=report,
    )
    app.close()

    restarted = _app(tmp_path)
    # The process cache is deliberately incomplete; retained SQLite history is
    # the ownership source after restart/eviction.
    restarted.jobs.pop("analysis-restart", None)
    detail = restarted.handle("GET", "/stats/job/job-restart?fragment=1")[2].decode("utf-8")
    assert "metric_restart" in detail
    assert "/artifacts?path=thesis/analysis/restart.json" in detail
    summary = restarted.reindex_all()
    assert summary["ok"] is True and summary["reports"] == 1
    restarted.close()


def test_stats_scans_exact_external_run_but_never_links_unowned_report(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    # A workstation parent name is not an evidence boundary.  This exact run
    # remains valid even though the absolute path contains ``pytest-*``.
    external = tmp_path / "pytest-legitimate-parent" / "external-owned-run"
    _write_completed_cell(external, run_id="run-external", target="external-model")
    _record_run(
        app,
        tmp_path,
        job_id="job-external",
        out=external,
        extra=["--api", "openai:external-model", "--corpora", "strongreject_official"],
    )
    unowned = tmp_path / "stale-unowned-results"
    unowned.mkdir()
    stale_report = tmp_path / "stale-unowned-report.json"
    _write_level2(
        stale_report,
        run_id="run-stale",
        model="stale-model",
        metric="stale_metric",
    )
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-stale",
        results=unowned,
        report=stale_report,
    )

    index = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "job-external" in index and "1 target / 1 judge" in index
    assert "data-authority='thesis-measured'" in index
    detail = app.handle("GET", "/stats/job/job-external?fragment=1")[2].decode("utf-8")
    assert "external-model" in detail
    assert "1 complete cell" in detail
    assert "Browse exact output artifacts" not in detail
    assert "stale_metric" not in detail

    # Headless operational accounting preserves an exact externally owned run,
    # while the unowned external report is never admitted to the report index.
    summary = app.reindex_all()
    assert summary["ok"] is True
    assert summary["markers"] == 1 and summary["reports"] == 0
    assert app.db.list_reports() == []
    assert app.db.usage_totals()
    app.close()


def test_stats_renders_owned_external_report_without_unresolvable_links(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    external = tmp_path / "external-retained" / "campaign"
    _write_completed_cell(external, run_id="run-external-report", target="external-model")
    _record_run(
        app,
        tmp_path,
        job_id="job-external-report",
        out=external,
        extra=["--api", "openai:external-model", "--corpora", "strongreject_official"],
    )
    report = tmp_path / "external-retained" / "analysis" / "level2.json"
    _write_level2(
        report,
        run_id="run-external-report",
        model="external-model",
        metric="external_owned_metric",
    )
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-external-report",
        results=external,
        report=report,
    )

    detail = app.handle(
        "GET", "/stats/job/job-external-report?fragment=1"
    )[2].decode("utf-8")
    assert "external_owned_metric" in detail
    assert detail.count("class='barchart'") == 1
    assert "level2.json" in detail
    assert "outside the configured artifact root" in detail
    assert "/artifacts?path=" not in detail
    assert str(tmp_path) not in detail
    assert app._stats_owned_report_paths() == set()
    app.close()


def test_stats_rejects_reports_from_nonterminal_analysis_jobs(tmp_path: Path) -> None:
    app = _app(tmp_path)
    run_root = app.results_root / "thesis" / "producer-state"
    _write_completed_cell(run_root, run_id="run-producer-state", target="target")
    _record_run(
        app,
        tmp_path,
        job_id="job-producer-state",
        out=run_root,
        extra=["--api", "openai:target", "--corpora", "strongreject_official"],
    )
    for state, exit_code in (("failed", 1), ("running", None)):
        report = app.results_root / "thesis" / "analysis" / f"{state}.json"
        _write_level2(
            report,
            run_id="run-producer-state",
            model="target",
            metric=f"stale_{state}_metric",
        )
        _record_analysis_job(
            app,
            tmp_path,
            job_id=f"analysis-{state}",
            results=run_root,
            report=report,
            state=state,
            exit_code=exit_code,
        )

    detail = app.handle(
        "GET", "/stats/job/job-producer-state?fragment=1"
    )[2].decode("utf-8")
    assert "stale_failed_metric" not in detail
    assert "stale_running_metric" not in detail
    assert "class='barchart'" not in detail
    assert "No validated Level-1/Level-2 analysis job" in detail
    app.close()

    restarted = _app(tmp_path)
    detail = restarted.handle(
        "GET", "/stats/job/job-producer-state?fragment=1"
    )[2].decode("utf-8")
    assert "stale_failed_metric" not in detail
    assert "stale_running_metric" not in detail
    assert "class='barchart'" not in detail
    restarted.close()


def test_stats_real_http_navigation_resolves_retained_job_and_artifact_links(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    run_root = app.results_root / "thesis" / "http"
    _write_completed_cell(run_root, run_id="run-http", target="http-model")
    _record_run(
        app,
        tmp_path,
        job_id="job-http",
        out=run_root,
        extra=["--api", "openai:http-model", "--corpora", "strongreject_official"],
    )
    report = app.results_root / "thesis" / "analysis" / "http.json"
    _write_level2(report, run_id="run-http", model="http-model", metric="http_metric")
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-http",
        results=run_root,
        report=report,
    )
    unlinked = app.results_root / "misc" / "unlinked.json"
    _write_level2(
        unlinked,
        run_id="unlinked-run",
        model="unlinked-model",
        metric="global_unlinked_metric",
    )
    app.close()

    restarted = _app(tmp_path)
    server = _make_server(restarted, "127.0.0.1", 0)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def get(path: str) -> tuple[int, str, str]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return (
                response.status,
                response.getheader("Content-Type", ""),
                response.read().decode("utf-8"),
            )
        finally:
            connection.close()

    try:
        status, content_type, index = get("/stats")
        assert status == 200 and content_type == "text/html; charset=utf-8"
        assert "job-http" in index and "1 target / 1 judge" in index
        assert "http_metric" not in index and "global_unlinked_metric" not in index
        assert "class='barchart'" not in index
        campaign_panel = index.split("data-page-panel='stats-campaigns'", 1)[1].split(
            "data-page-panel='stats-operational'", 1
        )[0]
        assert "Calculated spend" not in campaign_panel
        assert "Unlinked report artifacts" not in campaign_panel
        assert "misc/unlinked.json" not in campaign_panel
        assert "misc/unlinked.json" in index

        status, _, fragment = get("/stats/job/job-http?fragment=1")
        assert status == 200 and "<!doctype html>" not in fragment
        assert "http_metric" in fragment and "class='barchart'" in fragment
        status, _, standalone = get("/stats/job/job-http")
        assert status == 200 and "<!doctype html>" in standalone

        parser = _HrefCollector()
        parser.feed(standalone)
        relevant = {
            href
            for href in parser.hrefs
            if href == "/jobs/job-http" or href.startswith("/artifacts?path=")
        }
        assert "/jobs/job-http" in relevant
        assert any(href.startswith("/artifacts?path=") for href in relevant)
        for href in relevant:
            assert get(href)[0] == 200, href
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        restarted.close()


def test_nested_run_usage_and_report_have_one_most_specific_owner(tmp_path: Path) -> None:
    app = _app(tmp_path)
    parent = app.results_root / "thesis" / "nested"
    child = parent / "child"
    parent.mkdir(parents=True)
    child.mkdir()
    _write_completed_cell(child, run_id="run-child", target="child")
    _record_run(
        app,
        tmp_path,
        job_id="job-parent",
        out=parent,
        extra=["--api", "openai:parent", "--corpora", "strongreject_official"],
    )
    _record_run(
        app,
        tmp_path,
        job_id="job-child",
        out=child,
        extra=["--api", "openai:child", "--corpora", "strongreject_official"],
    )
    report = app.results_root / "thesis" / "analysis" / "nested-child.json"
    _write_level2(
        report,
        run_id="run-child",
        model="child",
        metric="child_only_metric",
    )
    _record_analysis_job(
        app,
        tmp_path,
        job_id="analysis-child",
        results=child,
        report=report,
    )

    parent_detail = app.handle("GET", "/stats/job/job-parent?fragment=1")[2].decode("utf-8")
    child_detail = app.handle("GET", "/stats/job/job-child?fragment=1")[2].decode("utf-8")
    assert "child_only_metric" not in parent_detail
    assert "child_only_metric" in child_detail
    assert child_detail.count("child_only_metric") >= 1
    assert "No completion-bound model usage" in parent_detail
    assert "0 complete cells" in parent_detail
    assert "child" in child_detail and "1 complete cell" in child_detail
    index = app.handle("GET", "/stats")[2].decode("utf-8")
    parent_card = index.split("data-job-id='job-parent'", 1)[1].split(
        "</article>", 1
    )[0]
    child_card = index.split("data-job-id='job-child'", 1)[1].split(
        "</article>", 1
    )[0]
    assert "data-authority='measured-incomplete'" in parent_card
    assert "0 target / 0 judge" in parent_card
    assert "data-authority='thesis-measured'" in child_card
    assert "1 target / 1 judge" in child_card
    assert app._stats_owned_report_paths() == {"thesis/analysis/nested-child.json"}
    summary = app.reindex_all()
    assert summary["ok"] is True and summary["reports"] == 1
    assert summary["markers"] == 1
    app.close()
