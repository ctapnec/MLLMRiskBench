"""Explicit external measured-job registration and Rig Web projection."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

import pytest

from experiments.rig_web import RigWebApp
from experiments.rig_web_app import campaigns as campaigns_module
from experiments.rig_web_app import dashboard as dashboard_module
from experiments.rig_web_app import external_measured as external_module
from experiments.rig_web_app.artifacts import Job
from experiments.rig_web_app.external_measured import (
    REGISTRY_DIRECTORY,
    REGISTRATION_SCHEMA,
    TERMINAL_SCHEMA,
    load_external_measured_job,
    main,
    register_external_measured_start,
    register_external_measured_terminal,
    scan_external_measured_jobs,
)


COMMIT = "a" * 40
FRAMEWORK_LOCK = "b" * 64
ADMISSION = "c" * 64


def test_external_measured_v2_storage_contract_is_literal() -> None:
    assert REGISTRY_DIRECTORY == "external-measured-jobs-v2"
    assert REGISTRATION_SCHEMA == "ura-external-measured-job/2"
    assert TERMINAL_SCHEMA == "ura-external-measured-job-terminal/1"


def _roots(tmp_path: Path, lane: str = "lane") -> tuple[Path, Path]:
    results = tmp_path / "runs"
    output = results / "thesis" / "runner" / lane
    output.mkdir(parents=True)
    return results, output


def _argv(output: Path) -> list[str]:
    return [
        "--local",
        "vllm:model@revision",
        "--attackers",
        "deepteam",
        "--corpora",
        "strongreject_official",
        "--out",
        str(output.resolve()),
    ]


def _register(
    results: Path,
    output: Path,
    *,
    job_id: str = "external-measured-example",
    started_at: float | None = None,
    tmux_socket: str = "ura-external-socket",
    tmux_session: str = "ura-external-session",
) -> Path:
    return register_external_measured_start(
        results,
        job_id=job_id,
        command="run_matrix",
        run_kind_name="measured",
        sanitized_argv=_argv(output),
        out_dir=output.resolve(),
        expected_commit=COMMIT,
        framework_lock_id=FRAMEWORK_LOCK,
        admission_sha256=ADMISSION,
        tmux_socket=tmux_socket,
        tmux_session=tmux_session,
        started_at=started_at,
    )


def _descriptor(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "file": path.name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "records": 1,
    }


def _write_completed_cell(root: Path) -> None:
    responses = root / "cell.responses.jsonl"
    responses.write_text(
        json.dumps(
            {
                "target": "external-model",
                "tokens": {"input": 11, "output": 7, "total": 18},
                "raw": {"provider": "mock", "resolved_model": "external-model"},
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
                "run_id": "external-run",
                "completed_at": time.time(),
                "artifacts": {
                    "responses": _descriptor(responses),
                    "trails": _descriptor(trails),
                },
            }
        ),
        encoding="utf-8",
    )


def test_create_only_api_and_cli_preserve_exact_operational_identity(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    results, output = _roots(tmp_path)
    started = time.time()
    registration_path = _register(results, output, started_at=started)
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    assert registration["schema"] == REGISTRATION_SCHEMA
    assert registration["event"] == "start"
    assert registration["sanitized_argv"] == _argv(output)
    assert registration["out_dir"] == str(output.resolve())
    assert registration["expected_commit"] == COMMIT
    assert registration["framework_lock_id"] == FRAMEWORK_LOCK
    assert registration["admission_sha256"] == ADMISSION
    assert registration["registration_authority"] == "operational_only"
    assert registration["thesis_empirical_evidence"] is False

    with pytest.raises(FileExistsError):
        _register(results, output, started_at=started)
    terminal_path = register_external_measured_terminal(
        results,
        job_id="external-measured-example",
        exit_code=0,
        ended_at=started + 1,
    )
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    assert terminal == {
        "schema": TERMINAL_SCHEMA,
        "event": "terminal",
        "job_id": "external-measured-example",
        "ended_at": started + 1,
        "state": "complete",
        "exit_code": 0,
    }
    with pytest.raises(FileExistsError):
        register_external_measured_terminal(
            results,
            job_id="external-measured-example",
            exit_code=0,
            ended_at=started + 2,
        )

    cli_results, cli_output = _roots(tmp_path, "cli-lane")
    assert cli_results == results
    cli_job = "external-measured-cli-lane"
    assert main(
        [
            "start",
            "--results-root",
            str(results),
            "--job-id",
            cli_job,
            "--out-dir",
            str(cli_output.resolve()),
            "--expected-commit",
            COMMIT,
            "--framework-lock-id",
            FRAMEWORK_LOCK,
            "--admission-sha256",
            ADMISSION,
            "--tmux-socket",
            "ura-cli-socket",
            "--tmux-session",
            "ura-cli-session",
            "--argv",
            *_argv(cli_output),
        ]
    ) == 0
    assert main(
        [
            "terminal",
            "--results-root",
            str(results),
            "--job-id",
            cli_job,
            "--exit-code",
            "7",
        ]
    ) == 0
    assert "registration.json" in capsys.readouterr().out
    cli_record = load_external_measured_job(results, cli_job, probe_session=False)
    assert cli_record is not None
    assert (cli_record.state, cli_record.exit_code) == ("failed", 7)


def test_failed_measured_invocation_and_resume_keep_distinct_resolvable_rows(
    tmp_path: Path,
) -> None:
    results, output = _roots(tmp_path)
    first_job = "external-p6e-attempt-measured-run-1000-41-lane"
    resume_job = "external-p6e-attempt-runner-resume-2000-41-lane"

    _register(results, output, job_id=first_job, started_at=1000.0)
    register_external_measured_terminal(
        results, job_id=first_job, exit_code=7, ended_at=1001.0
    )
    _register(results, output, job_id=resume_job, started_at=2000.0)
    register_external_measured_terminal(
        results, job_id=resume_job, exit_code=0, ended_at=2001.0
    )

    first = load_external_measured_job(results, first_job, probe_session=False)
    resumed = load_external_measured_job(results, resume_job, probe_session=False)
    assert first is not None and (first.state, first.exit_code) == ("failed", 7)
    assert resumed is not None and (resumed.state, resumed.exit_code) == (
        "complete",
        0,
    )
    assert first.out_dir == resumed.out_dir == output.resolve()


def test_scanner_rejects_mutated_identity_escape_secret_and_nonregular_rows(
    tmp_path: Path,
) -> None:
    results, output = _roots(tmp_path)
    registration_path = _register(results, output)
    job_id = "external-measured-example"
    assert load_external_measured_job(results, job_id, probe_session=False) is not None

    # Mutation proof: a changed digest makes the otherwise complete row
    # unresolvable instead of turning the mutated argv into UI authority.
    document = json.loads(registration_path.read_text(encoding="utf-8"))
    document["argv_sha256"] = "0" * 64
    registration_path.write_text(json.dumps(document), encoding="utf-8")
    assert load_external_measured_job(results, job_id, probe_session=False) is None
    assert scan_external_measured_jobs(results, probe_session=False)[0] == []

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="escapes"):
        register_external_measured_start(
            results,
            job_id="external-measured-outside",
            command="run_matrix",
            run_kind_name="measured",
            sanitized_argv=["--out", str(outside.resolve())],
            out_dir=outside.resolve(),
            expected_commit=COMMIT,
            framework_lock_id=FRAMEWORK_LOCK,
            admission_sha256=ADMISSION,
            tmux_socket="ura-outside",
            tmux_session="ura-outside",
        )
    secret_output = results / "thesis" / "runner" / "secret"
    secret_output.mkdir()
    with pytest.raises(ValueError, match="secret-bearing"):
        register_external_measured_start(
            results,
            job_id="external-measured-secret",
            command="run_matrix",
            run_kind_name="measured",
            sanitized_argv=[
                "--token",
                "do-not-store",
                "--out",
                str(secret_output.resolve()),
            ],
            out_dir=secret_output.resolve(),
            expected_commit=COMMIT,
            framework_lock_id=FRAMEWORK_LOCK,
            admission_sha256=ADMISSION,
            tmux_socket="ura-secret",
            tmux_session="ura-secret",
        )

    registry = results / "external-measured-jobs-v2"
    unsafe = registry / "external-measured-nonregular"
    unsafe.mkdir()
    (unsafe / "registration.json").mkdir()
    jobs, _notice = scan_external_measured_jobs(results, probe_session=False)
    assert all(job.job_id != unsafe.name for job in jobs)


def test_extreme_epochs_are_rejected_by_writer_reader_and_scan_window(
    tmp_path: Path,
) -> None:
    results, output = _roots(tmp_path)
    with pytest.raises(ValueError, match="supported UTC datetime range"):
        _register(results, output, started_at=1e300)

    registration_path = _register(results, output, started_at=time.time())
    with pytest.raises(ValueError, match="supported UTC datetime range"):
        register_external_measured_terminal(
            results,
            job_id="external-measured-example",
            exit_code=0,
            ended_at=1e300,
        )
    assert not registration_path.with_name("terminal.json").exists()
    with pytest.raises(ValueError, match="supported UTC datetime range"):
        scan_external_measured_jobs(
            results,
            started_from=0,
            started_to=1e300,
            probe_session=False,
        )

    # Mutation proof: finite JSON numbers outside the rendering contract do
    # not become UI timestamps when an immutable registration is corrupted.
    document = json.loads(registration_path.read_text(encoding="utf-8"))
    document["started_at"] = 1e300
    registration_path.write_text(json.dumps(document), encoding="utf-8")
    assert load_external_measured_job(
        results,
        "external-measured-example",
        probe_session=False,
    ) is None


@pytest.mark.parametrize(
    "secret_option",
    [
        "--api-key=do-not-store",
        "--hf_token=do-not-store",
        "--password=do-not-store",
        "--clientSecret=do-not-store",
        "--AUTH=do-not-store",
        "--credentials=do-not-store",
    ],
)
def test_secret_option_name_equals_forms_are_rejected(
    tmp_path: Path,
    secret_option: str,
) -> None:
    results, output = _roots(tmp_path)
    with pytest.raises(ValueError, match="secret-bearing"):
        register_external_measured_start(
            results,
            job_id="external-measured-secret-equals",
            command="run_matrix",
            run_kind_name="measured",
            sanitized_argv=[*_argv(output), secret_option],
            out_dir=output.resolve(),
            expected_commit=COMMIT,
            framework_lock_id=FRAMEWORK_LOCK,
            admission_sha256=ADMISSION,
            tmux_socket="ura-secret-equals",
            tmux_session="ura-secret-equals",
        )


def test_secret_name_detection_does_not_reject_legitimate_option_words(
    tmp_path: Path,
) -> None:
    results, output = _roots(tmp_path)
    legitimate = [
        "--tokenizer",
        "local-tokenizer",
        "--keyframe-rate=24",
        "--secretary-mode",
        "off",
        "--authored-by=operator",
        "--credentialed-mode",
        "off",
    ]
    path = register_external_measured_start(
        results,
        job_id="external-measured-legitimate-options",
        command="run_matrix",
        run_kind_name="measured",
        sanitized_argv=[*_argv(output), *legitimate],
        out_dir=output.resolve(),
        expected_commit=COMMIT,
        framework_lock_id=FRAMEWORK_LOCK,
        admission_sha256=ADMISSION,
        tmux_socket="ura-legitimate-options",
        tmux_session="ura-legitimate-options",
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["sanitized_argv"][-len(legitimate) :] == legitimate


def test_scanner_accepts_only_the_configured_results_root_symlink(
    tmp_path: Path,
) -> None:
    results, output = _roots(tmp_path)
    _register(results, output)
    configured = tmp_path / "configured-runs"
    try:
        configured.symlink_to(results, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    observed = load_external_measured_job(
        configured,
        "external-measured-example",
        probe_session=False,
    )
    assert observed is not None and observed.out_dir == output.resolve()


def test_failed_start_cleans_only_its_new_empty_registration_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, output = _roots(tmp_path)

    def fail_write(_path: Path, _document: dict[str, object]) -> Path:
        raise OSError("injected create failure")

    monkeypatch.setattr(external_module, "_write_create_only", fail_write)
    with pytest.raises(OSError, match="injected"):
        _register(results, output)
    registration_dir = (
        results / "external-measured-jobs-v2" / "external-measured-example"
    )
    assert not registration_dir.exists()
    assert (results / "external-measured-jobs-v2").is_dir()


def test_interrupted_terminal_publication_leaves_no_partial_final_and_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, output = _roots(tmp_path)
    _register(results, output, started_at=time.time() - 1)
    registration_dir = (
        results / "external-measured-jobs-v2" / "external-measured-example"
    )
    terminal = registration_dir / "terminal.json"
    real_publish = external_module._publish_create_only
    observed_private_files: list[Path] = []

    def interrupt_publication(temporary: Path, final: Path) -> None:
        assert final == terminal
        assert not final.exists()
        payload = temporary.read_bytes()
        assert payload.endswith(b"\n")
        assert json.loads(payload)["schema"] == TERMINAL_SCHEMA
        observed_private_files.append(temporary)
        raise OSError("injected publication interruption")

    monkeypatch.setattr(
        external_module,
        "_publish_create_only",
        interrupt_publication,
    )
    with pytest.raises(OSError, match="injected publication interruption"):
        register_external_measured_terminal(
            results,
            job_id="external-measured-example",
            exit_code=0,
        )
    assert observed_private_files
    assert not terminal.exists()
    assert not list(registration_dir.glob(".terminal.json.*.tmp"))

    monkeypatch.setattr(external_module, "_publish_create_only", real_publish)
    published = register_external_measured_terminal(
        results,
        job_id="external-measured-example",
        exit_code=0,
    )
    assert published == terminal
    loaded = load_external_measured_job(
        results,
        "external-measured-example",
        probe_session=False,
    )
    assert loaded is not None and loaded.state == "complete"


def test_hard_linked_registration_is_not_scanner_authority(tmp_path: Path) -> None:
    results, output = _roots(tmp_path)
    registration = _register(results, output)
    outside_link = tmp_path / "registration-outside-link.json"
    os.link(registration, outside_link)
    assert registration.stat().st_nlink == 2
    assert load_external_measured_job(
        results,
        "external-measured-example",
        probe_session=False,
    ) is None
    assert scan_external_measured_jobs(results, probe_session=False)[0] == []

    _same_results, terminal_output = _roots(tmp_path, "terminal-hardlink")
    terminal_job = "external-measured-terminal-hardlink"
    _register(results, terminal_output, job_id=terminal_job)
    terminal = register_external_measured_terminal(
        results,
        job_id=terminal_job,
        exit_code=0,
    )
    os.link(terminal, tmp_path / "terminal-outside-link.json")
    assert terminal.stat().st_nlink == 2
    assert load_external_measured_job(
        results,
        terminal_job,
        probe_session=False,
    ) is None


def test_external_scan_batches_and_caches_running_session_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "runs"
    started = time.time() - 120
    count = 12
    for index in range(count):
        _same_results, output = _roots(tmp_path, f"batch-{index:02d}")
        _register(
            results,
            output,
            job_id=f"external-measured-batch-{index:02d}",
            started_at=started + index,
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
    first, first_notice = scan_external_measured_jobs(results)
    second, second_notice = scan_external_measured_jobs(results)
    campaigns_module._clear_named_session_liveness_cache()

    assert first_notice == second_notice == ""
    assert len(first) == len(second) == count
    assert all(job.state == "running" for job in first + second)
    assert calls == count
    assert maximum_active >= 4


def test_unavailable_named_session_liveness_is_explicitly_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, output = _roots(tmp_path)
    _register(results, output, started_at=time.time() - 120)

    def unavailable(specs: list[object]) -> dict[object, None]:
        return {spec: None for spec in specs}

    monkeypatch.setattr(external_module, "_named_session_liveness", unavailable)
    job = load_external_measured_job(results, "external-measured-example")
    assert job is not None
    assert job.state == "unknown"
    assert "liveness is unavailable" in job.state_detail
    assert "running state is not asserted" in job.state_detail


def test_external_scan_caps_probes_and_discloses_every_unprobed_running_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "runs"
    count = external_module._MAX_RUNNING_SESSION_PROBES + 7
    started = time.time() - count - 120
    for index in range(count):
        _same_results, output = _roots(tmp_path, f"bounded-{index:02d}")
        _register(
            results,
            output,
            job_id=f"external-measured-bounded-{index:02d}",
            started_at=started + index,
        )

    observed_batches: list[list[object]] = []

    def observed_live(specs: list[object]) -> dict[object, bool]:
        observed_batches.append(list(specs))
        return {spec: True for spec in specs}

    monkeypatch.setattr(external_module, "_named_session_liveness", observed_live)
    jobs, notice = scan_external_measured_jobs(results)

    assert len(observed_batches) == 1
    assert len(observed_batches[0]) == external_module._MAX_RUNNING_SESSION_PROBES
    running = [job for job in jobs if job.state == "running"]
    unprobed = [job for job in jobs if job.state == "unknown"]
    assert len(running) == external_module._MAX_RUNNING_SESSION_PROBES
    assert len(unprobed) == 7
    assert all("bounded scan limit" in job.state_detail for job in unprobed)
    assert all("running state is not asserted" in job.state_detail for job in unprobed)
    assert "7 additional running registrations were not probed" in notice
    assert "shown as unknown" in notice


def test_external_scan_cache_is_keyed_bounded_and_invalidated_by_writers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, output = _roots(tmp_path)
    external_module._clear_external_measured_scan_cache()

    # An empty snapshot must not hide a start written during its short TTL.
    assert scan_external_measured_jobs(results, probe_session=False)[0] == []
    _register(results, output, started_at=time.time() - 120)

    real_load = external_module._load_registration
    loads = 0

    def counted_load(
        results_root: Path,
        registration_dir: Path,
    ) -> external_module.ExternalMeasuredJob | None:
        nonlocal loads
        loads += 1
        return real_load(results_root, registration_dir)

    monkeypatch.setattr(external_module, "_load_registration", counted_load)
    first, _notice = scan_external_measured_jobs(results, probe_session=False)
    second, _notice = scan_external_measured_jobs(results, probe_session=False)
    assert len(first) == len(second) == 1
    assert loads == 1

    # Window and probe mode are independent cache identities.
    windowed, _notice = scan_external_measured_jobs(
        results,
        started_from=0,
        started_to=external_module._MAX_SUPPORTED_EPOCH,
        probe_session=False,
    )
    assert len(windowed) == 1 and loads == 2
    monkeypatch.setattr(
        external_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )
    live, _notice = scan_external_measured_jobs(results, probe_session=True)
    assert len(live) == 1 and live[0].state == "running" and loads == 3

    register_external_measured_terminal(
        results,
        job_id="external-measured-example",
        exit_code=0,
    )
    after_terminal_load = loads
    terminal, _notice = scan_external_measured_jobs(results, probe_session=False)
    assert len(terminal) == 1 and terminal[0].state == "complete"
    assert loads == after_terminal_load + 1

    for index in range(external_module._MAX_SCAN_CACHE_ENTRIES + 5):
        scan_external_measured_jobs(
            results,
            started_from=float(index),
            started_to=external_module._MAX_SUPPORTED_EPOCH,
            probe_session=False,
        )
    assert len(external_module._SCAN_CACHE) == external_module._MAX_SCAN_CACHE_ENTRIES
    external_module._clear_external_measured_scan_cache()


def test_jobs_and_stats_merge_external_read_only_job_without_database_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, output = _roots(tmp_path)
    _write_completed_cell(output)
    started = time.time() - 1
    _register(results, output, started_at=started)
    register_external_measured_terminal(
        results,
        job_id="external-measured-example",
        exit_code=0,
        ended_at=started + 0.5,
    )
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
    )

    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    row = jobs.split("external-measured-example", 1)[1].split("</tr>", 1)[0]
    assert "external / read-only" in row
    assert "model campaign" in row and "verify artifacts" in row
    assert "action='/jobs/external/external-measured-example/stop'" not in row
    detail_status, _headers, detail_body = app.handle(
        "GET", "/jobs/external/external-measured-example"
    )
    assert detail_status == 200
    detail = detail_body.decode("utf-8")
    assert "Externally owned, read-only measured job" in detail
    assert "tmux -L ura-external-socket attach -t ura-external-session" in detail
    assert "Browse exact output artifacts" in detail
    assert "Stop job" not in detail
    assert app.handle(
        "POST", "/jobs/external/external-measured-example/stop"
    )[0] == 405
    assert app.db.load_job("external-measured-example") is None
    assert app.db.load_run("external-measured-example") is None

    observed: list[tuple[Path, bool]] = []
    real_collect = dashboard_module.collect_usage

    def collect_spy(root: Path, **kwargs: object) -> tuple[list[dict], dict]:
        observed.append((root, kwargs.get("verify_sha") is True))
        return real_collect(root, **kwargs)

    monkeypatch.setattr(dashboard_module, "collect_usage", collect_spy)
    stats = app.handle("GET", "/stats")[2].decode("utf-8")
    card = stats.split("data-job-id='external-measured-example'", 1)[1].split(
        "</article>", 1
    )[0]
    assert "data-authority='external-operational'" in stats
    assert "external operational record / non-thesis" in card
    assert "data-authority='thesis-measured'" not in card
    assert "external / read-only" in card
    assert "1 target / 1 judge" in card
    assert "href='/jobs/external/external-measured-example'" in card
    assert observed and all(root == output.resolve() and verified for root, verified in observed)
    stats_detail = app.handle(
        "GET", "/stats/job/external-measured-example?fragment=1"
    )[2].decode("utf-8")
    assert "1 complete cell" in stats_detail
    assert "href='/jobs/external/external-measured-example'" in stats_detail

    # The operational registry is a derived-scan boundary and never becomes
    # a report or scientific usage source during reindex.
    reindexed = app.reindex_all()
    assert reindexed["ok"] is True
    assert app.db.load_job("external-measured-example") is None
    assert app.db.load_run("external-measured-example") is None
    app.close()


def test_stats_exact_external_detail_bypasses_truncated_list_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, output = _roots(tmp_path, "beyond-prefix")
    job_id = "external-measured-beyond-prefix"
    started = time.time() - 1
    _register(results, output, job_id=job_id, started_at=started)
    register_external_measured_terminal(
        results,
        job_id=job_id,
        exit_code=0,
        ended_at=started + 0.5,
    )
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    monkeypatch.setattr(
        app,
        "_external_measured_job_scan",
        lambda **_kwargs: ([], "External measured registry scan stopped after 2000 entries."),
    )
    try:
        index = app.handle("GET", "/stats")[2].decode("utf-8")
        status, _headers, detail = app.handle(
            "GET", f"/stats/job/{job_id}?fragment=1"
        )
    finally:
        app.close()

    assert "External measured registry scan stopped after 2000 entries." in index
    assert status == 200
    assert job_id in detail.decode("utf-8")


def test_jobs_date_window_pins_live_console_and_external_rows_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, live_output = _roots(tmp_path, "old-live")
    _same_results, terminal_output = _roots(tmp_path, "old-terminal")
    now = time.time()
    old = now - 8 * 86400
    live_external = "external-measured-old-live"
    terminal_external = "external-measured-old-terminal"
    _register(
        results,
        live_output,
        job_id=live_external,
        started_at=old,
        tmux_session="ura-external-old-live",
    )
    _register(
        results,
        terminal_output,
        job_id=terminal_external,
        started_at=old + 1,
        tmux_session="ura-external-old-terminal",
    )
    register_external_measured_terminal(
        results,
        job_id=terminal_external,
        exit_code=0,
        ended_at=old + 2,
    )
    monkeypatch.setattr(
        external_module,
        "_named_session_liveness",
        lambda specs: {spec: True for spec in specs},
    )

    class LiveProcess:
        @staticmethod
        def poll() -> None:
            return None

    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    live_console = "job-console-old-live"
    terminal_console = "job-console-old-terminal"
    app.jobs[live_console] = Job(
        job_id=live_console,
        command="webui_selftest",
        argv=[],
        directory=tmp_path / live_console,
        process=LiveProcess(),  # type: ignore[arg-type]
        started_at=old,
    )
    app.jobs[terminal_console] = Job(
        job_id=terminal_console,
        command="webui_selftest",
        argv=[],
        directory=tmp_path / terminal_console,
        process=None,
        started_at=old + 1,
        ended_at=old + 2,
        restored_state="complete",
        restored_exit=0,
    )
    try:
        body = app.handle(
            "GET",
            f"/jobs?from_ms={int((now - 7 * 86400) * 1000)}"
            f"&to_ms={int((now + 1) * 1000)}",
        )[2].decode("utf-8")
    finally:
        app.close()

    assert live_console in body and live_external in body
    assert terminal_console not in body and terminal_external not in body
    assert body.count("data-live-window-pin='true'") == 2
    assert "livePinned||(Number.isFinite(started)" in body
    assert "currently live rows remain visible" in body
    assert "Terminal history still obeys the selected dates" in body
