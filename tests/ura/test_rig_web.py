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
import copy
import hashlib
import http.client
import json
import os
import re
import shutil
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
from experiments.rig_web_app.ollama_service import (
    DEFAULT_OLLAMA_URL,
    OllamaService,
)
from experiments import rig_check
from experiments.rig_web import (
    _LEVEL2_ROW_FIELDS,
    _MATRIX_PARAMS,
    Command,
    ConsoleDB,
    Job,
    RigWebApp,
    _tokens_by_category,
    _judge_row_usage,
    _response_identity,
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
from ura.approximate_metrics import (
    ApproximateMetricProvenance,
    supplementary_metric_policy,
)
from ura.model_acquisition import (
    build_receipt as build_model_acquisition_receipt,
    build_upstream_manifest,
    write_document_create_only,
)
from ura.sampling import (
    DEFAULT_SAMPLING_POLICY,
    SOURCE_ORDER_CLUSTER_PREFIX,
)
from ura.targets.api import MockTarget
from ura.targets.base import BaseTarget
from ura.adapters import _engine_runtime as engine_runtime


class _EmptyOllamaAPI:
    """A reachable Ollama daemon that serves no models.

    The rig runs a real Ollama daemon and the workstation does not, so any
    builder assertion about Ollama candidates is host-dependent unless the
    daemon is injected. This keeps that surface deterministic on both.
    """

    timeout = 0.5
    base_url = DEFAULT_OLLAMA_URL

    def tags(self, *, timeout=None):
        del timeout
        return {"models": []}

    def ps(self, *, timeout=None):
        del timeout
        return {"models": []}


def _app(tmp_path: Path, *, ollama_service=None) -> RigWebApp:
    results = tmp_path / "runs"
    results.mkdir(exist_ok=True)
    counter = iter(range(1, 1000))
    return RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        job_id_factory=lambda: f"job-{next(counter):04d}",
        ollama_service=ollama_service,
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


def _operator_registry_app(tmp_path: Path) -> RigWebApp:
    """An isolated app with executable hosted and source registries.

    Real source arms intentionally never fall back to the checked-in example
    at execution time.  Builder unit tests that exercise those arms therefore
    install an explicit operator registry in their private repository instead
    of weakening that fail-closed boundary or writing into the checkout.
    """

    app = _isolated_app(tmp_path)
    checkout = Path(__file__).resolve().parents[2]
    copies = (
        (
            checkout / "experiments" / "rig" / "api-targets.example.json",
            app.repo_root / "experiments" / "rig" / "api-targets.example.json",
        ),
        (
            checkout / "experiments" / "rig" / "source-instances.example.json",
            app.repo_root / "experiments" / "source-instances.json",
        ),
    )
    for source, destination in copies:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes())
    return app


def _engine_runtime_config(
    tmp_path: Path,
    *engines: str,
) -> tuple[Path, str, dict[str, str]]:
    """Create a structurally valid private runtime config without networking."""

    entries: dict[str, object] = {}
    interpreters: dict[str, str] = {}
    for index, engine in enumerate(engines, start=1):
        root = tmp_path / "operator-private-runtimes" / engine
        binary_dir = root / ("Scripts" if os.name == "nt" else "bin")
        binary_dir.mkdir(parents=True)
        interpreter = binary_dir / ("python.exe" if os.name == "nt" else "python")
        shutil.copy2(sys.executable, interpreter)
        if os.name != "nt":
            interpreter.chmod(0o700)
        requirement = engine_runtime.ENGINE_RUNTIME_REQUIREMENTS[engine]
        digit = str(index % 10)
        receipt: dict[str, object] = {
            "schema": engine_runtime.ENGINE_RUNTIME_RECEIPT_SCHEMA,
            "engine": engine,
            "distribution": requirement.distribution,
            "version": requirement.version,
            "python": {
                "implementation": "cpython",
                "version": "3.12.10",
                "cache_tag": "cpython-312",
                "executable_sha256": digit * 64,
                "executable_bytes": 10,
            },
            "pyvenv_cfg_sha256": "2" * 64,
            "package_tree_sha256": "3" * 64,
            "package_files": 2,
            "package_bytes": 20,
            "inventory_sha256": "4" * 64,
            "environment_tree_sha256": digit * 64,
            "environment_files": 7,
            "environment_bytes": 70,
        }
        receipt["runtime_id"] = (
            "engine-runtime-" + engine_runtime._sha256_json(receipt)[:24]
        )
        entries[engine] = {
            "interpreter": str(interpreter.resolve()),
            "receipt": receipt,
        }
        interpreters[engine] = str(interpreter.resolve())
    payload = json.dumps(
        {
            "schema": engine_runtime.ENGINE_RUNTIME_CONFIG_SCHEMA,
            "runtimes": entries,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    path = tmp_path / "operator-engine-runtimes.json"
    path.write_bytes(payload)
    return path, hashlib.sha256(payload).hexdigest(), interpreters


def _opening_tag(document: str, marker: str) -> str:
    """Return the opening HTML tag containing *marker*."""

    marker_at = document.index(marker)
    start = document.rfind("<", 0, marker_at)
    return document[start:document.index(">", marker_at) + 1]


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
    assert build_argv("run_matrix", {
        "--sampling-policy": SOURCE_ORDER_CLUSTER_PREFIX,
    })[-2:] == ["--sampling-policy", SOURCE_ORDER_CLUSTER_PREFIX]
    with pytest.raises(ValueError, match="must be one of"):
        build_argv("run_matrix", {"--sampling-policy": "ignored-policy-mutant"})


def test_run_matrix_can_launch_only_through_validated_builder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    launches: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        app,
        "start_job",
        lambda *args, **kwargs: launches.append((args, kwargs)),
    )
    try:
        commands_page = app._commands_page().decode("utf-8")
        assert "data-name='run_matrix'" not in commands_page
        assert "name='command' value='run_matrix'" not in commands_page

        status, _content_type, body = app.handle(
            "POST",
            "/jobs",
            {
                "command": "run_matrix",
                "--api": "anthropic:target",
                "--judges": "llm",
                "--judge-model": "anthropic:judge",
                "--max-total-target-calls": "999",
                "--max-total-judge-calls": "999",
            },
        )
        assert status == 400
        assert b"validated Build workflow" in body
        assert launches == []
    finally:
        app.close()
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


def test_builder_engine_runtime_config_is_exactly_selected_or_rejected(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    config, digest, _interpreters = _engine_runtime_config(
        tmp_path,
        "pyrit",
        "deepteam",
    )
    base = {
        "mode": "dry_run",
        "corpora": "synth",
        "judges": "rules",
        "out": "runs/runtime-builder-validation",
    }
    try:
        missing = app._validate_builder({**base, "attackers": "pyrit"})
        assert "engine_runtime_config" in missing
        assert "requires a path and exact SHA-256" in missing["engine_runtime_config"]

        unused = app._validate_builder({
            **base,
            "attackers": "replay",
            "engine_runtime_config": str(config),
            "engine_runtime_config_sha": digest,
        })
        assert "engine_runtime_config" in unused
        assert "allowed only when" in unused["engine_runtime_config"]

        extra = app._validate_builder({
            **base,
            "attackers": "pyrit",
            "engine_runtime_config": str(config),
            "engine_runtime_config_sha": digest,
        })
        assert "engine_runtime_config" in extra
        assert "exactly the selected" in extra["engine_runtime_config"]
    finally:
        app.close()


def test_engine_runtime_config_is_ticket_bound_private_and_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    config, digest, interpreters = _engine_runtime_config(tmp_path, "pyrit")
    params = {
        "mode": "dry_run",
        "corpora": "synth",
        "attackers": "pyrit",
        "judges": "rules",
        "seeds": "0",
        "out": "runs/private-engine-runtime",
        "engine_runtime_config": str(config),
        "engine_runtime_config_sha": digest,
    }
    reviewed, snapshot, _snapshot_digest = app._capture_execution_config_snapshot(
        params
    )
    assert snapshot["engine_runtime_config"] == config.read_bytes()
    command, values, rebound = app._compose_from_builder(
        reviewed,
        execution_snapshot=snapshot,
    )
    transient = Path(values["--engine-runtime-config"])
    assert transient.parent == app.state_dir / ".private-engine-runtime-configs"
    assert transient.read_bytes() == snapshot["engine_runtime_config"]

    launched: dict[str, object] = {}

    class FakeProcess:
        pid = 4243
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    process = FakeProcess()

    def fake_popen(argv, **kwargs):
        launched["argv"] = list(argv)
        launched["env"] = dict(kwargs.get("env") or {})
        return process

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    try:
        preview = app._preview_page(command, values, rebound).decode("utf-8")
        assert "private-engine-runtime-config@sha256:" in preview
        assert str(config) not in preview and str(transient) not in preview
        assert all(value not in preview for value in interpreters.values())
        job = app.start_job(
            command,
            values,
            builder_params=rebound,
            execution_snapshot=snapshot,
        )
        assert str(transient) in launched["argv"]
        assert launched["env"][
            "URA_PRIVATE_TRANSIENT_ENGINE_RUNTIME_CONFIG"
        ] == str(transient.resolve())
        retained = json.dumps({
            "argv": job.argv,
            "builder_params": job.builder_params,
            "command": json.loads(
                (job.directory / "command.json").read_text(encoding="utf-8")
            ),
        }, sort_keys=True)
        for private_value in (
            str(config),
            str(transient),
            *interpreters.values(),
        ):
            assert private_value not in retained
        assert "private-engine-runtime-config@sha256:" in retained
        assert "ura-engine-runtime-selection-identity/1" not in retained

        process.returncode = 0
        app._reconcile()
        assert not transient.exists()
    finally:
        app.close()


def test_engine_runtime_private_config_is_consumed_and_restart_state_is_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    config, digest, interpreters = _engine_runtime_config(tmp_path, "pyrit")
    params = {
        "mode": "dry_run",
        "corpora": "synth",
        "attackers": "pyrit",
        "judges": "rules",
        "seeds": "0",
        "out": "runs/private-engine-runtime-restart",
        "engine_runtime_config": str(config),
        "engine_runtime_config_sha": digest,
    }
    reviewed, snapshot, _snapshot_digest = app._capture_execution_config_snapshot(
        params
    )
    command, values, rebound = app._compose_from_builder(
        reviewed,
        execution_snapshot=snapshot,
    )
    transient = Path(values["--engine-runtime-config"])

    class FakeProcess:
        pid = 4244
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(
        lifecycle_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FakeProcess(),
    )
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    restarted: RigWebApp | None = None
    app_closed = False
    try:
        job = app.start_job(
            command,
            values,
            builder_params=rebound,
            execution_snapshot=snapshot,
        )
        monkeypatch.setenv(
            "URA_PRIVATE_TRANSIENT_ENGINE_RUNTIME_CONFIG",
            str(transient.resolve()),
        )
        selection, artifact = run_matrix._load_engine_runtime_config(
            str(transient),
            ["pyrit"],
            digest,
        )
        assert selection is not None
        assert artifact == {
            "file": f"private-engine-runtime-config@sha256:{digest}",
            "sha256": digest,
            "bytes": len(snapshot["engine_runtime_config"]),
            "normalized_selected_sha256": run_matrix._sha256_json(
                selection.identity_descriptor()
            ),
        }
        assert not transient.exists()

        app.close()
        app_closed = True
        restarted = _app(tmp_path)
        restored = restarted.jobs[job.job_id]
        assert restored.state() == "orphaned"
        retained = json.dumps(
            {
                "argv": restored.argv,
                "builder_params": restored.builder_params,
                "command": json.loads(
                    (restored.directory / "command.json").read_text(
                        encoding="utf-8"
                    )
                ),
            },
            sort_keys=True,
        )
        assert f"private-engine-runtime-config@sha256:{digest}" in retained
        for private_value in (str(config), str(transient), *interpreters.values()):
            assert private_value not in retained
    finally:
        if restarted is not None:
            restarted.close()
        elif not app_closed:
            app.close()


def test_engine_runtime_transient_tamper_fails_before_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    config, digest, _interpreters = _engine_runtime_config(tmp_path, "pyrit")
    params = {
        "mode": "dry_run",
        "corpora": "synth",
        "attackers": "pyrit",
        "judges": "rules",
        "out": "runs/runtime-tamper",
        "engine_runtime_config": str(config),
        "engine_runtime_config_sha": digest,
    }
    reviewed, snapshot, _snapshot_digest = app._capture_execution_config_snapshot(
        params
    )
    command, values, rebound = app._compose_from_builder(
        reviewed,
        execution_snapshot=snapshot,
    )
    transient = Path(values["--engine-runtime-config"])
    raw = transient.read_bytes()
    transient.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    popen_calls: list[object] = []
    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(
        lifecycle_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: popen_calls.append(object()),
    )
    try:
        with pytest.raises(ValueError, match="SHA-256"):
            app.start_job(
                command,
                values,
                builder_params=rebound,
                execution_snapshot=snapshot,
            )
        assert popen_calls == []
        assert not transient.exists()
        assert app.jobs == {}
    finally:
        app.close()


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


@pytest.mark.parametrize("local_role", ["target", "judge"])
def test_explicit_local_path_is_launch_only_not_durable_console_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    local_role: str,
) -> None:
    """Raw checkpoint locators reach Popen but no retained console surface."""

    app = _app(tmp_path)
    checkpoint = (tmp_path / "operator-private" / local_role / "checkpoint").resolve()
    spec = f"vllm:{checkpoint}"
    digest = ("ab" if local_role == "target" else "cd") * 32
    selected = {
        spec: {
            "digest": digest,
            "modalities": ["text"],
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.9,
            "parameter_count_b": 1,
            "quantization": "none",
            "_execution_profile": {
                "generation_tokens": 4096,
                "local_execution": {
                    "gpu_memory_utilization": 0.9,
                    "max_model_len": -1,
                    "tensor_parallel_size": 1,
                },
                "request_timeout_seconds": 120.0,
            },
        }
    }
    monkeypatch.setattr(
        app,
        "_local_entry_catalog",
        lambda: (selected, set(selected)),
    )
    payload = app._selected_local_config_payload(
        [spec],
        quantization_overrides={spec: "none"},
        require_live_ollama=True,
    )
    payload_digest = hashlib.sha256(payload).hexdigest()
    private_dir = app.state_dir / ".private-local-configs"
    private_dir.mkdir(parents=True)
    local_config = private_dir / f"selected-{payload_digest[:24]}-0123456789abcdef.json"
    local_config.write_bytes(payload)

    values = {
        "--local-config": str(local_config),
        "--local-config-sha256": payload_digest,
        "--judges": "rules,llm",
        "--out": f"runs/{local_role}-path-boundary",
    }
    params = {
        "mode": "measured",
        "judges": "rules,llm",
        "out": values["--out"],
        f"quantization::{spec}": "none",
    }
    if local_role == "target":
        values["--local"] = spec
        params["local"] = spec
    else:
        values["--api"] = "mock"
        values["--judge-model"] = spec
        params["api"] = "mock"
        params["judge_model"] = spec
    _identities, _private_path, durable_digest = app._local_config_projection(
        values
    )
    assert durable_digest is not None
    params["_local_config_snapshot_sha256"] = durable_digest

    launched: dict[str, object] = {}

    class FakeProcess:
        pid = 4242
        returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

    fake_process = FakeProcess()

    def fake_popen(argv, **kwargs):
        launched["argv"] = list(argv)
        launched["env"] = dict(kwargs.get("env") or {})
        return fake_process

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    try:
        identity = f"vllm:local-checkpoint@sha256:{digest}"
        preview = app._preview_page("run_matrix", values, params).decode("utf-8")
        assert str(checkpoint) not in preview and spec not in preview
        assert identity in preview
        ticket_match = re.search(
            r"name='launch_ticket' value='([^']+)'", preview
        )
        assert ticket_match is not None
        ticket_params = app._launch_ticket_params(ticket_match.group(1))
        assert ticket_params is not None
        assert spec in ticket_params.values()

        job = app.start_job("run_matrix", values, builder_params=params)

        # Execution parity: the child receives the exact real locator/config.
        assert spec in launched["argv"]
        assert str(local_config) in launched["argv"]
        assert launched["env"]["URA_PRIVATE_TRANSIENT_LOCAL_CONFIG"] == str(
            local_config.resolve()
        )
        assert local_config.is_file()

        # Retention parity: every durable/rendered projection is content-only.
        retained_job = json.dumps(
            {"argv": job.argv, "builder_params": job.builder_params},
            sort_keys=True,
        )
        assert str(checkpoint) not in retained_job and spec not in retained_job
        assert identity in retained_job
        assert f"quantization::{identity}" in (job.builder_params or {})
        assert "private-local-config@sha256:" in retained_job

        command_doc = (job.directory / "command.json").read_text(encoding="utf-8")
        assert str(checkpoint) not in command_doc and spec not in command_doc
        assert identity in command_doc
        with sqlite3.connect(app.state_dir / "console.db") as conn:
            db_argv, db_params = conn.execute(
                "SELECT argv, builder_params FROM jobs WHERE job_id = ?",
                (job.job_id,),
            ).fetchone()
        retained_db = f"{db_argv}\n{db_params}"
        assert str(checkpoint) not in retained_db and spec not in retained_db
        assert identity in retained_db
        status, _, body = app.handle("GET", f"/jobs/{job.job_id}")
        assert status == 200
        assert str(checkpoint) not in body.decode("utf-8")
        assert identity in body.decode("utf-8")

        # A child that exits before consuming the one-shot input is still
        # cleaned by lifecycle reconciliation.
        fake_process.returncode = 0
        app._reconcile()
        assert not local_config.exists()
        app.close()

        restored = _app(tmp_path)
        try:
            restored_job = restored.jobs[job.job_id]
            restored_text = json.dumps({
                "argv": restored_job.argv,
                "builder_params": restored_job.builder_params,
            })
            assert str(checkpoint) not in restored_text and spec not in restored_text
            assert identity in restored_text
            assert run_kind(restored_job.command, restored_job.argv) == "measured"
        finally:
            restored.close()
    finally:
        if app.db.healthy:
            app.close()


def test_duplicate_local_config_is_rejected_before_job_or_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    checkpoint = (tmp_path / "operator-private" / "checkpoint").resolve()
    spec = f"vllm:{checkpoint}"
    encoded_spec = json.dumps(spec)
    raw = (
        "{" + encoded_spec + ':{"digest":"' + "a" * 64 + '"},'
        + encoded_spec + ':{"digest":"' + "b" * 64 + '"}}'
    )
    local_config = tmp_path / "ambiguous-local-targets.json"
    local_config.write_text(raw, encoding="utf-8")
    values = {
        "--dry-run": "on",
        "--local": spec,
        "--local-config": str(local_config),
        "--local-config-sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "--out": "runs/ambiguous-local-config",
    }
    popen_calls: list[object] = []

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(
        lifecycle_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: popen_calls.append(object()),
    )
    before_jobs = set(app.jobs)
    before_directories = set(app.state_dir.glob("job-*"))
    with pytest.raises(ValueError, match="JSON object"):
        app.start_job("run_matrix", values)

    assert popen_calls == []
    assert set(app.jobs) == before_jobs
    assert set(app.state_dir.glob("job-*")) == before_directories
    assert local_config.read_text(encoding="utf-8") == raw
    with sqlite3.connect(app.state_dir / "console.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
    app.close()


@pytest.mark.parametrize(
    ("argv", "builder_params"),
    [
        (["python", "--local", "vllm:/operator-private/target"], None),
        (
            ["python", "--judge-model", "vllm:/operator-private/judge"],
            {"judge_model": "vllm:/operator-private/judge"},
        ),
    ],
)
def test_storage_rejects_unprojected_explicit_local_paths(
    tmp_path: Path,
    argv: list[str],
    builder_params: dict[str, str] | None,
) -> None:
    db = ConsoleDB(tmp_path / "console.db")
    job = Job(
        job_id="unsafe-path",
        command="run_matrix",
        argv=argv,
        builder_params=builder_params,
        directory=tmp_path / "job",
        process=None,
        restored_state="failed",
        restored_exit=1,
    )
    try:
        with pytest.raises(ValueError, match="refusing to persist"):
            db.upsert_job(job)
    finally:
        db.close()


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


def test_job_detail_lookup_reconciles_detached_log_publication(tmp_path: Path) -> None:
    app = _app(tmp_path)
    directory = app.state_dir / "delayed-log"
    directory.mkdir()
    (directory / "stdout.log").write_bytes(b"")
    stderr = directory / "stderr.log"
    stderr.write_bytes(b"")

    class _TerminalProcess:
        @staticmethod
        def poll() -> int:
            return 2

    class _DelayedLogWorker:
        @staticmethod
        def wait(*, timeout: float) -> int:
            assert timeout == 1.0
            stderr.write_bytes(b"delayed authoritative failure\n")
            return 0

    job = Job(
        job_id="delayed-log",
        command="level1_evidence",
        argv=[],
        directory=directory,
        process=_TerminalProcess(),
    )
    app.jobs[job.job_id] = job
    app._log_capture_workers[job.job_id] = (_DelayedLogWorker(),)

    assert app._job_for_id(job.job_id) is job
    assert job.run_recorded is True
    assert job.failure == "delayed authoritative failure"
    assert stderr.read_bytes() == b"delayed authoritative failure\n"


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


def test_console_covers_runbook_clis_except_private_typed_controllers() -> None:
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
    private_typed_controllers = {
        "engine_runtime_config",
        "framework_runtime_installer",
        # Workstation-only commit/receipt binding and deterministic release
        # rendering. Generated controllers run on the rig, but this source
        # packaging operation must not be exposed as a Rig Web command.
        "local_campaign",
    }
    assert not (private_typed_controllers & allowlisted)
    missing = sorted(used - allowlisted - private_typed_controllers)
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


def test_config_editor_rejects_duplicate_content_without_writing(
    tmp_path: Path,
) -> None:
    app = _isolated_app(tmp_path)
    target = app.repo_root / "experiments" / "api-targets.json"
    ambiguous = '{"api:model":{"modalities":["text"]},' \
        '"api:model":{"modalities":["image"]}}'

    with pytest.raises(ValueError, match="duplicate JSON object key"):
        app.save_config("api-targets", ambiguous)

    assert not target.exists()
    assert not (app.state_dir / "config-backups").exists()
    app.close()


def test_pricing_editor_preserves_ambiguous_on_disk_table(tmp_path: Path) -> None:
    app = _isolated_app(tmp_path)
    pricing_path = app.repo_root / "experiments" / "pricing.json"
    ambiguous = '{"providers":{"glm":{}},"providers":{"anthropic":{}}}'
    pricing_path.write_text(ambiguous, encoding="utf-8")
    prior = pricing_path.read_bytes()

    with pytest.raises(ValueError, match="existing pricing config is not strict JSON"):
        app.save_config("pricing", '{"providers":{}}')

    assert pricing_path.read_bytes() == prior
    backups = app.state_dir / "config-backups"
    assert not backups.exists() or list(backups.iterdir()) == []
    app.close()


def test_builder_page_renders_full_surface(tmp_path: Path) -> None:
    # The builder page carries the complete lane surface: modality wizard,
    # receipts, scope + repeatable attestation rows, sampling, call ceilings,
    # local serving, and output.
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/build")
    text = body.decode("utf-8")
    assert status == 200
    for modality in ("text", "image", "audio", "video", "tool"):
        assert f"data-mod='{modality}'" in text
    assert "data-mods='text,image'" in text
    assert "data-arm='mmsafety_official'" in text
    assert "data-fw='crescendo'" in text
    assert "data-judge='guardrail'" in text  # the guardrail judge option
    assert text.count("class='modbox' data-mod") == 5
    assert "data-mod='text' checked" in text
    assert "modtoggle" in text
    assert "applyScope" in text and "intersects" in text
    # Every material Runner control is present.
    for field in (
        "name='project_revision'", "name='project_revision_sha'",
        "name='source_conformance'", "name='source_conformance_sha'",
        "name='scope'", "name='max_age'", "name='att_path1'",
        "name='att_sha1'", "name='seeds'", "name='max_queries'",
        "name='max_turns'", "name='target_answer_retries'",
        "name='cap_target'", "name='cap_judge'",
        "name='cap_http'", "name='local_budget_hours'", "name='deadline'",
        "name='limit'", "name='sample_seed'", "name='sampling_policy'",
        "name='dtype'",
        "name='quantization'", "name='judge_model'", "name='defense_guard'",
        "name='canary_dry'", "name='approximate_common_metrics'",
        # Scoring and defense guardrail inputs (model/revision/device each).
        "name='guardrail_model'", "name='guardrail_revision'",
        "name='guardrail_device'", "name='defense_guardrail_model'",
        "name='defense_guardrail_revision'", "name='defense_guardrail_device'",
    ):
        assert field in text, field
    assert "id='sample-limit-range'" in text
    assert "id='prepared-ideator'" in text
    assert "addatt" in text  # repeatable receipt rows
    assert "first failed output stops the paid grid" in text
    assert "hosted transport permits three retries only for retryable HTTP status errors" in text


def test_attacker_registry_parity_and_full_inventory() -> None:
    # The console's attacker mirror must equal the maintained engines registry
    # (all 20), so the builder can never silently omit an engine.
    import sys
    sys.path.insert(0, "src")
    from ura.adapters.engines import ATTACKER_NAMES
    from experiments.rig_web import (
        _ATTACKER_NAMES, _ARM_CATALOG, _INELIGIBLE_ARMS, _FRAMEWORKS,
        _SOURCE_METRIC_ARMS,
    )
    assert _ATTACKER_NAMES == ATTACKER_NAMES
    assert len(_FRAMEWORKS) == 20
    assert len(_ARM_CATALOG) == 45  # all maintained source arms
    # The 45 arms partition into 28 common-metric lanes + 2 source-metric lanes
    # + 15 conversion-only arms (no default scored admission).
    # 15 common-metric-ineligible arms with NO implemented source evaluator
    # (shown disabled). rjudge/gptgeochat are NOT here: their exact source
    # evaluators ARE implemented, so run_matrix scores them as source-metric
    # lanes - they are runnable, not disabled.
    assert len(_INELIGIBLE_ARMS) == 15
    assert len(_SOURCE_METRIC_ARMS) == 2
    common_arms = [
        arm
        for arm, _mods, reason in _ARM_CATALOG
        if not reason and arm not in _SOURCE_METRIC_ARMS
    ]
    assert len(common_arms) == 28
    assert len(common_arms) + len(_SOURCE_METRIC_ARMS) + len(_INELIGIBLE_ARMS) == 45
    # holisafe_full is a scored common image arm: its unsafe rows carry a
    # composed judge reference and its benign SSS rows are response-only.
    assert "holisafe_full" in common_arms
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
    from ura.source_metrics import _IMPLEMENTED_SOURCE_EVALUATORS
    assert {metric for _a, (metric, _atk) in _SOURCE_METRIC_ARMS.items()} == {
        metric for _src, metric in _IMPLEMENTED_SOURCE_EVALUATORS
    }


def test_builder_lists_all_arms_and_only_campaign_attackers(tmp_path: Path) -> None:
    from experiments.rig_web import (
        _ARM_CATALOG,
        _ATTACKER_NAMES,
        _BUILDER_OMITTED_ATTACKERS,
    )
    app = _app(tmp_path)
    try:
        _s, _c, body = app.handle("GET", "/build")
        text = body.decode("utf-8")
        catalog_arms = {arm for arm, _mods, _reason in _ARM_CATALOG}
        for arm, _mods, _reason in _ARM_CATALOG:
            assert f"data-arm='{arm}'" in text, arm  # every arm visible
        source_dispositions = app._source_conformance_arm_dispositions({})
        blocked_arms = {
            arm
            for arm, (disposition, _reason) in source_dispositions.items()
            if disposition == "blocked"
        }
        admitted_arms = {
            arm
            for arm, (disposition, _reason) in source_dispositions.items()
            if disposition == "admitted"
        }
        disabled_arms = set()
        for arm, _mods, _reason in _ARM_CATALOG:
            marker = f"data-arm='{arm}'"
            at = text.index(marker)
            input_tag = text[text.rfind("<input", 0, at):text.find(">", at)]
            if "disabled" in input_tag:
                disabled_arms.add(arm)
        assert disabled_arms == blocked_arms
        assert admitted_arms <= catalog_arms
        assert admitted_arms.isdisjoint(disabled_arms)
        for attacker in set(_ATTACKER_NAMES) - _BUILDER_OMITTED_ATTACKERS:
            assert f"data-fw='{attacker}'" in text, attacker
        for attacker in _BUILDER_OMITTED_ATTACKERS:
            assert f"data-fw='{attacker}'" not in text, attacker
        # Receipt-admitted ineligible arms remain selectable so the server can
        # return their exact fail-closed reason; only receipt-blocked arms are
        # disabled. The source-metric arms are selectable because they do run.
        assert "source-specific metric - approximate proxy available (evaluator not integrated)" in text
        assert "source-specific metric - runnable (replay attacker only)" in text
        assert "badge amber tip" in text and "approximate opt-in" in text
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


def test_builder_disables_and_rejects_source_receipt_blocked_arm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "source-conformance.json"
    receipt.write_text(
        json.dumps({
            "schema": "ura-source-conformance/1",
            "claim_scope": "acquisition_and_conversion_traceability_only",
            "arms": [{
                "arm_id": "bipia_test_qa",
                "converter": "bipia",
                "path_env": "URA_BIPIA_TEST_QA_PATH",
                "source_label": "BIPIA test QA",
                "split": "official-test",
                "disposition": "blocked",
                "reason": "licensed NewsQA base is unavailable",
                "upstream_uri": None,
                "requested_revision": None,
                "observed_revision": None,
                "consumed_input": None,
                "components": [],
                "operator_decision": None,
                "raw_records": None,
                "semantic_review": None,
            }],
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(receipt))
    monkeypatch.setenv(
        "URA_SOURCE_CONFORMANCE_SHA256",
        hashlib.sha256(receipt.read_bytes()).hexdigest(),
    )
    app = _operator_registry_app(tmp_path)
    started = len(app.jobs)
    params = {
        "mode": "dry_run",
        "corpora": "bipia_test_qa",
        "attackers": "replay",
        "judges": "rules",
        "out": "runs/blocked-bipia",
        "seeds": "0",
        "approximate_common_metrics": "on",
    }
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        marker = "data-arm='bipia_test_qa'"
        at = page.index(marker)
        input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
        row = page[page.rfind("<label", 0, at):page.find("</label>", at)]
        assert "disabled" in input_tag
        assert "blocked by source receipt" in row
        assert "licensed NewsQA base is unavailable" in row

        errors = app._validate_builder(params)
        assert "blocked by the bound source receipt" in errors["corpora"]
        status, _headers, body = app.handle("POST", "/build", params)
        assert status == 200
        assert b"blocked by the bound source receipt" in body
        assert len(app.jobs) == started

        # Reverse proof: this is receipt-driven, not a hard-coded BIPIA ban.
        monkeypatch.delenv("URA_SOURCE_CONFORMANCE_MANIFEST")
        monkeypatch.delenv("URA_SOURCE_CONFORMANCE_SHA256")
        unbound_page = app.handle("GET", "/build")[2].decode("utf-8")
        at = unbound_page.index(marker)
        unbound_input = unbound_page[
            unbound_page.rfind("<input", 0, at):unbound_page.find(">", at)
        ]
        assert "disabled" not in unbound_input
        assert "corpora" not in app._validate_builder(params)
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
        t3_row = page[page.index("data-fw='t3mp3st'"):]
        t3_row = t3_row[:t3_row.index("</label>")]
        assert "capture + replay" in t3_row
        assert "prepare + replay" not in t3_row
        assert "prepared-framework-badge" in t3_row
        assert "t3mp3st" in _SUGGEST_STATIC["attackers"]
        checkbox = _opening_tag(page, "data-fw='t3mp3st'")
        panel = _opening_tag(page, "id='prepared-t3mp3st'")
        assert "aria-controls='prepared-t3mp3st'" in checkbox
        assert "aria-expanded='false'" in checkbox and " checked" not in checkbox
        assert " hidden" in panel and "aria-hidden='true'" in panel

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
        checkbox = _opening_tag(text, "data-fw='t3mp3st'")
        panel = _opening_tag(text, "id='prepared-t3mp3st'")
        assert " checked" in checkbox and "aria-expanded='true'" in checkbox
        assert " hidden" not in panel and "aria-hidden='false'" in panel
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
        harm_row = page[page.index("data-fw='harmbench'"):]
        harm_row = harm_row[:harm_row.index("</label>")]
        assert "prepare + replay" in harm_row
        assert "capture + replay" not in harm_row
        assert "prepared-framework-badge" in harm_row
        checkbox = _opening_tag(page, "data-fw='harmbench'")
        panel = _opening_tag(page, "id='prepared-harmbench'")
        assert "aria-controls='prepared-harmbench'" in checkbox
        assert "aria-expanded='false'" in checkbox and " checked" not in checkbox
        assert " hidden" in panel and "aria-hidden='true'" in panel

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
        checkbox = _opening_tag(text, "data-fw='harmbench'")
        panel = _opening_tag(text, "id='prepared-harmbench'")
        assert " checked" in checkbox and "aria-expanded='true'" in checkbox
        assert " hidden" not in panel and "aria-hidden='false'" in panel
        assert len(app.jobs) == started
    finally:
        app.close()


def test_prepared_workflows_live_under_attack_frameworks_without_nested_forms(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        builder_at = page.index("<form method='post' action='/build' id='builder'>")
        frameworks_at = page.index("Attack frameworks")
        workflows_at = page.index("id='prepared-workflows'")
        assert builder_at < frameworks_at < workflows_at
        # Ollama lifecycle/pull controls and the one-action-per-runtime controls
        # are deliberately separate forms before the campaign builder. They
        # must never become nested in that form.
        before_builder = page[:builder_at]
        runtime_actions = before_builder.count(
            "action='/build/framework-runtimes'"
        )
        assert runtime_actions == 16
        assert before_builder.count("<form ") == 4 + runtime_actions
        assert before_builder.count("</form>") == 4 + runtime_actions
        assert page[builder_at:].count("<form ") == 1
        assert "Prepared attack workflows" not in page
        assert (
            "formaction='/build/t3mp3st/capture' formmethod='post'" in page
        )
        assert (
            "formaction='/build/harmbench/prepare' formmethod='post'" in page
        )
        assert "panel.hidden=!visible" in page
        assert "panel.setAttribute('aria-hidden'" in page
        assert "box.setAttribute('aria-expanded'" in page

        _status, _content_type, css_body = app.handle("GET", "/static/style.css")
        css = css_body.decode("utf-8")
        assert ".prepared-workflows { border-top:1px solid var(--line);" in css
        assert "padding-top:1rem;" in css
        assert ".workflow-panel { border:1px solid var(--line);" in css
        assert "align-content:start; gap:.9rem;" in css
        assert ".workflow-step { display:grid; gap:.7rem; padding:.8rem;" in css
        assert ".workflow-panel details {" in css and "padding:.65rem;" in css
        assert ".workflow-actions {" in css and "gap:.65rem;" in css
        assert ".check .prepared-framework-badge {" in css
        assert "margin:.18rem 0 .05rem .55rem;" in css
        assert "padding:.12rem .65rem; gap:.3rem;" in css
        assert "@media (max-width:400px) {" in css
        assert (
            ".workflow-grid, .workflow-panel .cols { "
            "grid-template-columns:minmax(0,1fr); }" in css
        )
        assert (
            ".prepared-workflows, .workflow-panel, .workflow-step {" in css
            and "min-width:0; max-width:100%;" in css
        )

        _command, _values, params = app._compose_from_builder({
            "mode": "dry_run", "corpora": "synth", "attackers": "replay",
            "judges": "rules", "out": "runs/dry", "seeds": "0",
            "t3cap_model": "not-a-campaign-field",
            "hcap_repo": "not-a-campaign-field",
            "t3_artifact": "runs/stale-t3.json",
            "t3_artifact_sha": "a" * 64,
            "harm_config": "runs/stale-harm.json",
        })
        assert "t3cap_model" not in params and "hcap_repo" not in params
        assert "t3_artifact" not in params and "t3_artifact_sha" not in params
        assert "harm_config" not in params
        projection = app._projection_params({
            **params, "t3cap_model": "ignored", "hcap_repo": "ignored",
            "t3_artifact": "runs/stale-t3.json",
            "t3_artifact_sha": "a" * 64,
            "harm_config": "runs/stale-harm.json",
        })
        assert "t3cap_model" not in projection and "hcap_repo" not in projection
        assert "t3_artifact" not in projection and "harm_config" not in projection

        selected = app._builder_params({
            "mode": "dry_run", "corpora": "synth",
            "attackers": "t3mp3st,harmbench", "judges": "rules",
            "out": "runs/dry", "seeds": "0",
            "t3_artifact": "runs/selected-t3.json",
            "t3_artifact_sha": "b" * 64,
            "harm_config": "runs/selected-harm.json",
        })
        assert selected["t3_artifact"] == "runs/selected-t3.json"
        assert selected["harm_config"] == "runs/selected-harm.json"
        selected_projection = app._projection_params(selected)
        assert selected_projection["t3_artifact"] == (
            "private-t3mp3st-artifact@sha256:" + "b" * 64
        )
        assert selected_projection["harm_config"] == "private-harmbench-config"
    finally:
        app.close()


def test_prepared_attack_configs_are_verified_and_materialized_for_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    (repo / "experiments" / "api-targets.json").write_text(json.dumps({
        "openai:test-model": {
            "modalities": ["text"], "max_tokens": 64, "temperature": 0.0,
        },
    }), encoding="utf-8")
    (repo / "experiments" / "source-instances.json").write_text(json.dumps({
        "strongreject_official": {
            "converter": "strongreject",
            "path_env": "URA_STRONGREJECT_OFFICIAL_PATH",
        },
        "harmbench_text": {
            "converter": "harmbench",
            "path_env": "URA_HARMBENCH_TEXT_PATH",
        },
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
            "response_artifact": str(t3_bundle.resolve()),
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
        assert emitted["replay_artifact"] == str(harm_artifact.resolve())
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
            "mode": "measured", "api": "openai:test-model",
            "judges": "rules", "seeds": "0", "limit": "1",
            "cap_target": "10", "cap_judge": "10", "cap_http": "10",
            "deadline": "600", "scope": "scope-1", "max_age": "24",
            "att_path1": "runs/att.json", "att_sha1": "",
            "project_revision": "runs/project.json",
            "project_revision_sha": "",
            "source_conformance": str(results / "source.json"),
            "source_conformance_sha": "",
        }
        attestation_receipt = results / "att.json"
        attestation_receipt.write_text(
            '{"schema":"fixture-attestation"}\n', encoding="utf-8"
        )
        project_receipt = results / "project.json"
        project_receipt.write_text(
            '{"schema":"fixture-project"}\n', encoding="utf-8"
        )
        source_receipt = results / "source.json"
        source_receipt.write_text('{"schema":"fixture"}\n', encoding="utf-8")
        common["att_sha1"] = hashlib.sha256(
            attestation_receipt.read_bytes()
        ).hexdigest()
        common["project_revision_sha"] = hashlib.sha256(
            project_receipt.read_bytes()
        ).hexdigest()
        common["source_conformance_sha"] = hashlib.sha256(
            source_receipt.read_bytes()
        ).hexdigest()
        status, _, body = app.handle("POST", "/build", {
            **common, "corpora": "strongreject_official",
            "attackers": "t3mp3st", "sample_seed": "0",
            "max_queries": "1", "max_turns": "1", "out": "runs/t3-measured",
            "t3_artifact": str(t3_bundle), "t3_artifact_sha": t3_sha,
        })
        assert status == 200
        ticket = re.search(
            rb"name='launch_ticket' value='([^']+)'",
            body,
        )
        assert ticket is not None
        status, location, _ = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": ticket.group(1).decode("ascii"),
        })
        assert status == 303 and location == "/jobs/replay-1"
        command, values, _params = started[-1]
        assert command == "run_matrix" and values["--attackers"] == "t3mp3st"
        generated_path = Path(values["--attacker-config"])
        generated_doc = json.loads(generated_path.read_text(encoding="utf-8"))
        held_t3 = Path(generated_doc["t3mp3st"]["response_artifact"])
        assert held_t3 != t3_bundle.resolve()
        assert held_t3.parent.name == ".private-attacker-artifacts"
        assert held_t3.read_bytes() == t3_bundle.read_bytes()
        assert generated_doc["t3mp3st"]["response_artifact_sha256"] == t3_sha
        run_matrix.build_parser().parse_args(build_argv(command, values)[3:])

        status, _, body = app.handle("POST", "/build", {
            **common, "corpora": "harmbench_text", "attackers": "harmbench",
            "sample_seed": "7", "max_queries": "4", "max_turns": "4",
            "out": "runs/harm-measured", "harm_config": str(harm_config),
        })
        assert status == 200
        ticket = re.search(
            rb"name='launch_ticket' value='([^']+)'",
            body,
        )
        assert ticket is not None
        status, location, _ = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": ticket.group(1).decode("ascii"),
        })
        assert status == 303 and location == "/jobs/replay-2"
        command, values, _params = started[-1]
        assert command == "run_matrix" and values["--attackers"] == "harmbench"
        generated_path = Path(values["--attacker-config"])
        generated_doc = json.loads(generated_path.read_text(encoding="utf-8"))
        held_harm = Path(generated_doc["harmbench"]["replay_artifact"])
        assert held_harm != harm_artifact.resolve()
        assert held_harm.parent.name == ".private-attacker-artifacts"
        assert held_harm.read_bytes() == harm_artifact.read_bytes()
        assert generated_doc["harmbench"]["replay_artifact_sha256"] == harm_sha
        run_matrix.build_parser().parse_args(build_argv(command, values)[3:])
    finally:
        app.close()


def test_prepared_attack_configs_use_canonical_paths_with_symlinked_results_root(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "experiments").mkdir(parents=True)
    (repo / "experiments" / "api-targets.json").write_text(
        json.dumps({"openai:test-model": {"modalities": ["text"]}}),
        encoding="utf-8",
    )
    real_results = tmp_path / "data-disk" / "runs"
    real_results.mkdir(parents=True)
    results = repo / "runs"
    try:
        results.symlink_to(real_results, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create directory symlinks")

    app = RigWebApp(
        results_root=results,
        state_dir=results / "state",
        repo_root=repo,
    )
    try:
        t3_bundle = results / "t3-bundle.json"
        t3_bundle.write_text(
            json.dumps({
                "format_version": "ura-t3mp3st-plan-bundle/1",
                "upstream_revision": "a" * 40,
                "source_provider": "local",
                "source_model": "planner",
            }),
            encoding="utf-8",
        )
        t3_sha = hashlib.sha256(t3_bundle.read_bytes()).hexdigest()

        harm_bundle = results / "harmbench-capture.json"
        harm_bundle.write_text(
            json.dumps({
                "format_version": "ura-harmbench-transfer-replay/1",
                "upstream_revision": "b" * 40,
                "experiment": "fixture-model",
                "methods": ["PEZ"],
            }),
            encoding="utf-8",
        )
        harm_sha = hashlib.sha256(harm_bundle.read_bytes()).hexdigest()
        harm_config = results / "harmbench-attackers.json"
        harm_config.write_text(
            json.dumps({"harmbench": {
                "methods": ["PEZ"],
                "experiment": "fixture-model",
                "upstream_revision": "b" * 40,
                "replay_artifact": str(harm_bundle),
                "replay_artifact_sha256": harm_sha,
            }}),
            encoding="utf-8",
        )

        generated = app._materialize_prepared_attacker_config({
            "attackers": "t3mp3st,harmbench",
            "t3_artifact": str(t3_bundle),
            "t3_artifact_sha": t3_sha,
            "harm_config": str(harm_config),
        })
        assert generated is not None
        document = json.loads(generated.read_text(encoding="utf-8"))
        assert document["t3mp3st"]["response_artifact"] == str(
            t3_bundle.resolve(strict=True)
        )
        assert document["harmbench"]["replay_artifact"] == str(
            harm_bundle.resolve(strict=True)
        )

        operational, _ = run_matrix._load_attacker_config(
            str(generated), ["t3mp3st", "harmbench"]
        )
        portable = run_matrix._portable_attacker_configs(operational)
        assert "response_artifact" not in portable["t3mp3st"]
        assert "replay_artifact" not in portable["harmbench"]
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
    framework_lock = repo / "experiments" / "framework_runtime_lock.json"
    framework_env = tmp_path / "framework-venvs"
    framework_state = results / "engineering" / "framework-runtime-fixture"
    monkeypatch.setattr(
        app.framework_runtimes,
        "capture_binding_paths",
        lambda: (framework_lock, framework_env, framework_state),
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
        status, _, body = app.handle("POST", "/build/t3mp3st/capture", {
            **t3_form, "t3cap_revision": "not-a-commit",
            "t3cap_limit": "",
            "corpora": "unrelated-builder-value",
        })
        text = body.decode("utf-8")
        checkbox = _opening_tag(text, "data-fw='t3mp3st'")
        panel = _opening_tag(text, "id='prepared-t3mp3st'")
        assert status == 200 and "must be an exact 40-hex commit" in text
        assert " checked" in checkbox and "aria-expanded='true'" in checkbox
        assert " hidden" not in panel and "aria-hidden='false'" in panel
        assert "value='1'" not in _opening_tag(text, "name='t3cap_limit'")
        assert "unrelated-builder-value" not in text

        status, _, body = app.handle("POST", "/build/t3mp3st/capture", {
            **t3_form, "corpora": "unrelated-builder-value",
        })
        text = body.decode("utf-8")
        assert status == 200 and not captured
        assert "Out-of-band paid/compute step" in text
        assert "experiments.capture_t3mp3st" in text
        assert "unrelated-builder-value" not in text
        ticket_match = re.search(
            r"name='launch_ticket' value='([^']+)'",
            text,
        )
        assert ticket_match is not None

        # Full parameters plus confirm=yes are not a confirmation capability.
        no_ticket = app.handle(
            "POST", "/build/t3mp3st/capture", {**t3_form, "confirm": "yes"},
        )
        assert no_ticket[0] == 200 and not captured
        assert b"confirmation expired or was changed" in no_ticket[2]

        status, location, _ = app.handle(
            "POST",
            "/build/t3mp3st/capture",
            {
                "launch_ticket": ticket_match.group(1),
                "confirm": "yes",
            },
        )
        assert status == 303 and location == "/jobs/capture-job"
        assert captured[-1][0] == "capture_t3mp3st"
        assert captured[-1][1]["--out"] == str(results / "t3-captures")
        assert captured[-1][1]["--framework-lock"] == str(framework_lock)
        assert captured[-1][1]["--framework-env-root"] == str(framework_env)
        assert captured[-1][1]["--framework-state-root"] == str(framework_state)
        replayed = app.handle(
            "POST",
            "/build/t3mp3st/capture",
            {
                "launch_ticket": ticket_match.group(1),
                "confirm": "yes",
            },
        )
        assert replayed[0] == 200 and len(captured) == 1

        # A changed confirmation burns its ticket before rejection.
        tamper_preview = app.handle(
            "POST", "/build/t3mp3st/capture", t3_form,
        )[2].decode("utf-8")
        tamper_ticket = re.search(
            r"name='launch_ticket' value='([^']+)'",
            tamper_preview,
        )
        assert tamper_ticket is not None
        tampered = app.handle(
            "POST",
            "/build/t3mp3st/capture",
            {
                "launch_ticket": tamper_ticket.group(1),
                "confirm": "yes",
                "t3cap_model": "changed-model",
            },
        )
        burned = app.handle(
            "POST",
            "/build/t3mp3st/capture",
            {
                "launch_ticket": tamper_ticket.group(1),
                "confirm": "yes",
            },
        )
        assert tampered[0] == burned[0] == 200 and len(captured) == 1

        harm_form = {
            "hcap_repo": str(checkout), "hcap_revision": "b" * 40,
            "hcap_source": str(source), "hcap_corpus": "harmbench_text",
            "hcap_methods": "PEZ,PAP-top5", "hcap_experiment": "llama2_7b",
            "hcap_limit": "1", "hcap_sample_seed": "0", "hcap_cases": "1",
            "hcap_artifact_out": str(results / "harm" / "capture.json"),
            "hcap_config_out": str(results / "harm" / "attackers.json"),
        }
        status, _, body = app.handle("POST", "/build/harmbench/prepare", {
            **harm_form, "hcap_revision": "not-a-commit",
            "hcap_experiment": "",
            "judges": "unrelated-builder-value",
        })
        text = body.decode("utf-8")
        checkbox = _opening_tag(text, "data-fw='harmbench'")
        panel = _opening_tag(text, "id='prepared-harmbench'")
        assert status == 200 and "must be an exact 40-hex commit" in text
        assert " checked" in checkbox and "aria-expanded='true'" in checkbox
        assert " hidden" not in panel and "aria-hidden='false'" in panel
        assert "value='llama2_7b'" not in _opening_tag(
            text, "name='hcap_experiment'",
        )
        assert "unrelated-builder-value" not in text

        status, _, body = app.handle("POST", "/build/harmbench/prepare", harm_form)
        harm_preview = body.decode()
        assert status == 200 and "experiments.harmbench_capture" in harm_preview
        harm_ticket = re.search(
            r"name='launch_ticket' value='([^']+)'",
            harm_preview,
        )
        assert harm_ticket is not None
        harm_no_ticket = app.handle(
            "POST", "/build/harmbench/prepare", {**harm_form, "confirm": "yes"},
        )
        assert harm_no_ticket[0] == 200 and len(captured) == 1
        status, location, _ = app.handle(
            "POST",
            "/build/harmbench/prepare",
            {
                "launch_ticket": harm_ticket.group(1),
                "confirm": "yes",
            },
        )
        assert status == 303 and location == "/jobs/capture-job"
        command, values = captured[-1]
        assert command == "harmbench_capture"
        assert [values["--method"], values["--method#1"]] == ["PEZ", "PAP-top5"]
        harm_replay = app.handle(
            "POST",
            "/build/harmbench/prepare",
            {
                "launch_ticket": harm_ticket.group(1),
                "confirm": "yes",
            },
        )
        assert harm_replay[0] == 200 and len(captured) == 2

        status, _, _ = app.handle("POST", "/jobs", {
            "command": "capture_t3mp3st", "--out": str(results / "forged"),
        })
        assert status == 400
    finally:
        app.close()


def test_prepared_capture_forms_accept_canonical_symlinked_results_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    real_results = tmp_path / "data-disk" / "runs"
    real_results.mkdir(parents=True)
    results = repo / "runs"
    try:
        results.symlink_to(real_results, target_is_directory=True)
    except OSError:
        pytest.skip("this account cannot create directory symlinks")

    checkout = tmp_path / "HarmBench"
    checkout.mkdir()
    source = tmp_path / "behaviors.csv"
    source.write_text("BehaviorID,Behavior\n1,test\n", encoding="utf-8")
    app = RigWebApp(
        results_root=results,
        state_dir=results / "state",
        repo_root=repo,
    )
    monkeypatch.setattr(
        app.framework_runtimes,
        "capture_binding_paths",
        lambda: (
            repo / "experiments" / "framework_runtime_lock.json",
            tmp_path / "framework-venvs",
            real_results / "engineering" / "framework-runtime-fixture",
        ),
    )
    try:
        status, _, body = app.handle("POST", "/build/t3mp3st/capture", {
            "t3cap_corpus": "strongreject_official",
            "t3cap_limit": "1",
            "t3cap_sample_seed": "0",
            "t3cap_endpoint": "http://127.0.0.1:3333/api/general/plan",
            "t3cap_revision": "a" * 40,
            "t3cap_provider": "local",
            "t3cap_model": "source-model",
            "t3cap_timeout": "120",
            "t3cap_out": "runs/t3-captures",
        })
        text = body.decode("utf-8")
        assert status == 200 and "Review T3MP3ST capture" in text
        assert str((real_results / "t3-captures").resolve()) in text

        status, _, body = app.handle("POST", "/build/harmbench/prepare", {
            "hcap_repo": str(checkout),
            "hcap_revision": "b" * 40,
            "hcap_source": str(source),
            "hcap_corpus": "harmbench_text",
            "hcap_methods": "DirectRequest",
            "hcap_experiment": "llama2_7b",
            "hcap_limit": "1",
            "hcap_sample_seed": "0",
            "hcap_cases": "1",
            "hcap_artifact_out": "runs/harm/capture.json",
            "hcap_config_out": "runs/harm/attackers.json",
        })
        text = body.decode("utf-8")
        assert status == 200 and "Review HarmBench prepare" in text
        assert str((real_results / "harm" / "capture.json").resolve()) in text
        assert str((real_results / "harm" / "attackers.json").resolve()) in text
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
    from ura.adapters.engines import (
        ATTACKER_NAMES,
        attacker_runner_replay_eligible,
    )
    from experiments.rig_web import _NATIVE_ONLY_ATTACKERS
    actual_native = {
        name for name in ATTACKER_NAMES
        if attacker_runner_replay_eligible(name) is False
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


def test_ineligible_arm_requires_explicit_approximate_metrics_opt_in(
    tmp_path: Path,
) -> None:
    import html as html_lib

    from experiments.rig_web import _INELIGIBLE_REASONS

    app = _operator_registry_app(tmp_path)
    started = len(app.jobs)
    try:
        page = app.handle("GET", "/build")[2].decode("utf-8")
        marker = "data-arm='agentharm_harmful'"
        at = page.index(marker)
        input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
        assert "disabled" not in input_tag  # operator can choose the row
        assert "approximate opt-in" in page and "badge amber tip" in page
        reason = html_lib.escape(_INELIGIBLE_REASONS["agentharm_harmful"])
        row = page[page.rfind("<label", 0, at):page.find("</label>", at)]
        assert row.count(reason) == 1  # one custom tooltip, no title duplicate
        badge_at = page.index("<span class='badge amber tip'", at)
        badge_tag = page[badge_at:page.find(">", badge_at)]
        assert "title=" not in badge_tag
        _s, _c, body = app.handle("POST", "/build", {
            "mode": "dry_run", "corpora": "agentharm_harmful",
            "api": "anthropic:claude-opus-5", "attackers": "replay",
            "judges": "rules", "out": "runs/a", "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "common-metric-ineligible" in text
        assert "Select the explicit approximate" in text
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
            assert "truthfulness" in errors.get(
                "approximate_common_metrics", ""
            )

        enabled = {
            "mode": "dry_run",
            "corpora": "cyberseceval_prompt_injection",
            "attackers": "replay",
            "judges": "rules",
            "out": "runs/approximate",
            "seeds": "0",
            "approximate_common_metrics": "on",
        }
        errors = app._validate_builder(enabled)
        assert "approximate_common_metrics" not in errors
        assert "corpora" not in errors
        command, values, params = app._compose_from_builder(enabled)
        assert params["approximate_common_metrics"] == "on"
        assert values["--approximate-common-metrics"] == "on"
        assert "--approximate-common-metrics" in build_argv(command, values)

        _command, default_values, _params = app._compose_from_builder({
            **enabled,
            "corpora": "strongreject_official",
            "approximate_common_metrics": "",
        })
        assert "--approximate-common-metrics" not in default_values

        checked_page = app._build_page(enabled).decode("utf-8")
        checkbox = _opening_tag(
            checked_page, "name='approximate_common_metrics'"
        )
        assert " checked" in checkbox
        assert "Non-authoritative" in checked_page
        assert "not probability or accuracy" in checked_page

        tool_errors = app._validate_builder({
            **enabled,
            "corpora": "agentharm_harmful",
        })
        assert "text+tool source construct" in tool_errors["corpora"]
        assert "fail-closed" in tool_errors["corpora"]
        assert app._validate_builder({
            **enabled,
            "corpora": "injecagent_direct_harm_base",
        })["corpora"].startswith("arm injecagent_direct_harm_base converts")
    finally:
        app.close()


def test_source_metric_arm_runnable_and_replay_guarded(tmp_path: Path) -> None:
    # rjudge/gptgeochat have common_metrics_eligible=False but their exact
    # source evaluators ARE implemented, so run_matrix scores them as
    # source-metric lanes (replay only).  The builder must NOT reject them as
    # ineligible, and must require the replay attacker their converter declares.
    app = _operator_registry_app(tmp_path)
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
    assert found is not None
    assert found["call_projection"] == {
        key: projection["call_projection"][key]
        for key in ("target_calls", "judge_calls", "http_attempts")
    }
    assert found["arms"] == [
        {
            key: arm[key]
            for key in (
                "logical_source_arm",
                "total_records",
                "selected_records",
                "total_clusters",
                "selected_clusters",
                "limit",
                "sample_seed",
            )
        }
        for arm in projection["selection"]["arms"]
    ]
    # Every grid-defining field remains exact.
    changed_grid = {**exact_params, "attackers": "replay"}
    assert app._read_lane_projection(changed_grid)[0] is None
    app.close()


def test_exact_modality_admission_before_popen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A target that serves only text cannot run a text+image arm - complete
    # exact modality, not "shares any" - and it is rejected on the form.
    app = _operator_registry_app(tmp_path)
    started = len(app.jobs)
    api_registry = (
        app.repo_root / "experiments" / "rig" / "api-targets.example.json"
    )
    api_document = json.loads(api_registry.read_text(encoding="utf-8"))
    api_document["anthropic:textonly"] = {
        "modalities": ["text"],
        "max_tokens": 64,
        "temperature": 0.0,
    }
    api_registry.write_text(json.dumps(api_document), encoding="utf-8")
    monkeypatch.setattr(
        app, "_model_options",
        lambda: [("anthropic:textonly", "textonly", ("text",), "api")],
    )
    try:
        _s, _c, body = app.handle("POST", "/build", {
            "mode": "dry_run", "corpora": "mmsafety_official",
            "api": "anthropic:textonly", "attackers": "replay",
            "judges": "rules", "out": "runs/m", "seeds": "0",
        })
        text = body.decode("utf-8")
        assert "requires all of" in text and "mmsafety_official" in text
        assert len(app.jobs) == started
        # A compatible target (serves image) is admitted: no modality error.
        errors = app._validate_builder({
            "mode": "dry_run", "corpora": "strongreject_official",
            "api": "anthropic:textonly", "attackers": "replay",
            "judges": "rules", "out": "runs/m", "seeds": "0",
        })
        assert "models" not in errors  # text arm on a text target is fine
    finally:
        app.close()


def test_guardrail_separation_and_wiring(tmp_path: Path) -> None:
    app = _operator_registry_app(tmp_path)
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
            "guardrail_revision": "d" * 40, "guardrail_device": "cuda:0",
            "defense_guardrail_model": "vllm:defender",
            "defense_guardrail_revision": "e" * 40,
            "defense_guardrail_device": "cuda:1",
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
    project_receipt = tmp_path / "p.json"
    source_receipt = tmp_path / "s.json"
    project_receipt.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    source_receipt.write_text('{"schema":"fixture-source"}\n', encoding="utf-8")
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project_receipt))
    monkeypatch.setenv(
        "URA_PROJECT_REVISION_SHA256",
        hashlib.sha256(project_receipt.read_bytes()).hexdigest(),
    )
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(source_receipt))
    monkeypatch.setenv(
        "URA_SOURCE_CONFORMANCE_SHA256",
        hashlib.sha256(source_receipt.read_bytes()).hexdigest(),
    )
    app = _operator_registry_app(tmp_path)
    attestation_receipt = tmp_path / "att.json"
    attestation_receipt.write_text(
        '{"schema":"fixture-attestation"}\n', encoding="utf-8"
    )
    attestation_sha = hashlib.sha256(attestation_receipt.read_bytes()).hexdigest()
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
        "max_age": "24", "att_path1": str(attestation_receipt),
        "att_sha1": attestation_sha, "cap_target": "10", "cap_judge": "10",
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


def test_builder_preflight_consumes_private_project_receipt_and_makes_no_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    project_revision_args,
) -> None:
    """A Builder-held receipt keeps its canonical persisted filename.

    The web process deliberately gives the child a randomized, path-private,
    read-once file.  That transport basename must not leak into the typed
    project-revision binding, whose filename is fixed by the receipt id.
    """

    app = _operator_registry_app(tmp_path)
    receipt_path = Path(project_revision_args.values[1])
    receipt_sha256 = project_revision_args.values[3]
    form = {
        "mode": "attestation_probe",
        "corpora": "synth",
        "api": "anthropic:claude-haiku-4-5-20251001",
        "attackers": "replay",
        "judges": "rules",
        "defense": "none",
        "limit": "1",
        "sample_seed": "0",
        "seeds": "0",
        "scope": "fixture-scope",
        "max_queries": "1",
        "max_turns": "1",
        "cap_target": "1",
        "cap_judge": "1",
        "cap_http": "3",
        "deadline": "900",
        "project_revision": str(receipt_path),
        "project_revision_sha": receipt_sha256,
        "out": str(app.results_root / "paid-probe"),
    }
    assert app._validate_builder(form) == {}
    command, values, _params = app._compose_from_builder(form)
    assert values["--target-answer-retries"] == "0"
    private_revision = Path(values["--project-revision"])
    assert private_revision != receipt_path
    assert private_revision.parent.name == ".private-project-revision"
    assert private_revision.read_bytes() == receipt_path.read_bytes()

    for flag, marker in (
        ("--api-config", "URA_PRIVATE_TRANSIENT_API_CONFIG"),
        ("--source-config", "URA_PRIVATE_TRANSIENT_SOURCE_CONFIG"),
        (
            "--project-revision",
            "URA_PRIVATE_TRANSIENT_PROJECT_REVISION",
        ),
    ):
        if flag in values:
            monkeypatch.setenv(marker, values[flag])

    generation_calls = 0

    class NoGenerationTarget(MockTarget):
        def generate(self, *_args, **_kwargs):
            nonlocal generation_calls
            generation_calls += 1
            raise AssertionError("a no-call preflight invoked target generation")

    monkeypatch.setattr(
        run_matrix,
        "build_target",
        lambda *_args, **_kwargs: NoGenerationTarget(
            "anthropic:claude-haiku-4-5-20251001"
        ),
    )
    preflight_out = app.results_root / "preflight" / "private-revision"
    preflight_values = app._builder_preflight_values(
        values,
        output=preflight_out,
    )
    assert run_matrix.main(build_argv(command, preflight_values)[3:]) == 0
    assert generation_calls == 0
    assert not private_revision.exists()

    revision_id = project_revision_args.binding["revision_id"]
    retained = preflight_out / f"{revision_id}.project-revision.json"
    assert retained.read_bytes() == receipt_path.read_bytes()
    projection = next(preflight_out.glob("*.lane-projection.json"))
    assert projection.is_file()
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
        "mode": "measured", "corpora": "synth",
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
    project_receipt = tmp_path / "r.json"
    project_receipt.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    project_sha = hashlib.sha256(project_receipt.read_bytes()).hexdigest()
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project_receipt))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", project_sha)
    app = _app(tmp_path)
    monkeypatch.setattr(
        app, "_read_lane_projection",
        lambda _params: ({"target_calls": 4, "judge_calls": 4,
                          "http_attempts": 12}, ""),
    )
    form = {
        "mode": "attestation_probe", "corpora": "synth",
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
    # The confirmation submits only its opaque, one-shot exact-parameter ticket.
    assert "name='confirm' value='yes'" in text
    ticket_match = re.search(r"name='launch_ticket' value='([^']+)'", text)
    assert ticket_match is not None
    status, location, _ = app.handle("POST", "/build", {
        "confirm": "yes",
        "launch_ticket": ticket_match.group(1),
    })
    assert status == 303 and len(app.jobs) == started + 1
    job = app.jobs[location.rsplit("/", 1)[1]]
    assert "--attestation-probe" in job.argv
    assert job.builder_params and job.builder_params["mode"] == "attestation_probe"
    # The probe argv parses with the real parser.
    run_matrix.build_parser().parse_args(job.argv[3:])
    app.stop_job(job.job_id)
    app.close()


def test_paid_launch_ticket_is_atomic_one_shot_under_concurrent_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_receipt = tmp_path / "r.json"
    project_receipt.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    project_sha = hashlib.sha256(project_receipt.read_bytes()).hexdigest()
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project_receipt))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", project_sha)
    app = _app(tmp_path)
    monkeypatch.setattr(
        app,
        "_read_lane_projection",
        lambda _params: (
            {"target_calls": 4, "judge_calls": 4, "http_attempts": 12},
            "",
        ),
    )
    params = {
        "mode": "attestation_probe",
        "corpora": "synth",
        "api": "anthropic:claude-opus-5",
        "attackers": "replay",
        "judges": "rules",
        "limit": "1",
        "sample_seed": "0",
        "seeds": "0",
        "scope": "atomic-ticket-scope",
        "max_queries": "1",
        "max_turns": "1",
        "cap_target": "4",
        "cap_judge": "4",
        "cap_http": "12",
        "deadline": "600",
        "project_revision": str(project_receipt),
        "project_revision_sha": project_sha,
        "out": "runs/atomic-ticket",
    }
    popen_calls: list[list[str]] = []

    class FakeProcess:
        pid = 5252

        @staticmethod
        def poll() -> None:
            return None

    def fake_popen(argv, **_kwargs):
        popen_calls.append(list(argv))
        return FakeProcess()

    import experiments.rig_web_app.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(lifecycle_module, "_win_managed_job", lambda: None)
    no_ticket = app.handle(
        "POST",
        "/build",
        {**params, "confirm": "yes"},
    )
    assert no_ticket[0] == 200
    assert b"confirmation expired or was changed" in no_ticket[2]
    assert popen_calls == []

    ticket = app._new_launch_ticket(params)
    barrier = threading.Barrier(3)
    responses: list[tuple[int, str, bytes]] = []

    def replay() -> None:
        barrier.wait()
        responses.append(app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": ticket,
        }))

    threads = [threading.Thread(target=replay) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=30)

    try:
        assert all(not thread.is_alive() for thread in threads)
        assert sorted(response[0] for response in responses) == [200, 303]
        assert len(popen_calls) == 1
        rejected = next(response for response in responses if response[0] == 200)
        assert b"confirmation expired or was changed" in rejected[2]

        # A changed POST consumes its capability before it is rejected, so a
        # later clean replay cannot recover or launch it.
        changed_ticket = app._new_launch_ticket(params)
        changed = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": changed_ticket,
            "mode": "dry_run",
        })
        replayed = app.handle("POST", "/build", {
            "confirm": "yes",
            "launch_ticket": changed_ticket,
        })
        assert changed[0] == replayed[0] == 200
        assert b"confirmation expired or was changed" in changed[2]
        assert b"confirmation expired or was changed" in replayed[2]
        assert len(popen_calls) == 1
    finally:
        app.close()


def test_builder_targets_split_hosted_and_local_vllm_roster(tmp_path: Path) -> None:
    # Targets are hosted API (composed into --api) and local vLLM (--local),
    # the latter drawn from the configured registry plus the vLLM roster; the
    # focal env pair are hosted. Compose splits them correctly.  The app runs
    # over temporary state so the checkout is never touched.
    from experiments import local_targets

    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    app = _app(
        tmp_path,
        ollama_service=OllamaService(state, api=_EmptyOllamaAPI()),
    )
    page = app.handle("GET", "/build")[2].decode("utf-8")
    assert "Hosted API" in page and "Local vLLM" in page
    assert "Local Ollama (local daemon)" in page
    # Deterministic: the injected daemon serves no models, so the builder
    # reports no candidate regardless of any daemon on the host.
    assert "No exact Ollama candidate is available" in page
    assert "stable tag/digest inventory plus explicit show capabilities" in page
    assert "data-kind='api'" in page and "data-kind='local'" in page
    # The curated vLLM roster is real and modality-tagged.
    roster = local_targets.roster_models(include_unfit=True)
    assert len(roster) > 10
    assert any("audio" in m["modalities"] for m in roster)
    spec = "vllm:Qwen/Qwen3-VL-8B-Instruct"
    catalog, explicit = app._local_entry_catalog()
    entry = catalog[spec]
    tensor_parallel_size = entry.get("tensor_parallel_size", 2)
    gpu_memory_utilization = entry.get("gpu_memory_utilization", 0.9)
    entry.update({"max_model_len": -1, "max_tokens": 4096, "timeout": 120.0})
    entry["_execution_profile"] = {
        "generation_tokens": 4096,
        "local_execution": {
            "gpu_memory_utilization": gpu_memory_utilization,
            "max_model_len": -1,
            "tensor_parallel_size": tensor_parallel_size,
        },
        "request_timeout_seconds": 120.0,
    }
    app._local_entry_catalog = lambda: (catalog, explicit)  # type: ignore[method-assign]
    # A build with a local target composes --local and binds --local-config
    # only when a local target is selected.
    _cmd, values, _params = app._compose_from_builder({
        "mode": "measured", "corpora": "synth",
        "local": spec, "attackers": "replay",
        "judges": "rules", "out": "runs/x",
    })
    assert values["--local"] == spec
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
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "api-targets.example.json").write_text(json.dumps({
        "anthropic:claude-test": {
            "modalities": ["text"], "max_tokens": 64, "temperature": 0.0,
        },
        "openai:gpt-test": {
            "modalities": ["text", "image"],
            "max_tokens": 64,
            "temperature": 0.0,
        },
    }), encoding="utf-8")
    local_checkpoint = f"vllm:{(tmp_path / 'checkpoint').resolve()}"
    ollama_spec = "ollama:fixture:latest"
    (rig / "local-targets.example.json").write_text(json.dumps({
        local_checkpoint: {
            "digest": "6" * 64, "modalities": ["text"],
            "parameter_count_b": 7,
        },
        ollama_spec: {
            "digest": "A" * 64, "modalities": ["text"],
        },
    }), encoding="utf-8")
    (rig / "vllm-roster.example.json").write_text(json.dumps({
        "vllm_version": "0.test",
        "models": {
            "vllm:org/Tiny-10M": {
                "revision": "A" * 40, "modalities": ["text"],
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
    evidence = repo / "profile-readiness.json"
    evidence.write_text("{}\n", encoding="utf-8")
    configured_entries = json.loads(
        (rig / "local-targets.example.json").read_text(encoding="utf-8")
    )
    roster_entries = json.loads(
        (rig / "vllm-roster.example.json").read_text(encoding="utf-8")
    )["models"]
    profiles: dict[str, object] = {}
    for spec, entry in {**roster_entries, **configured_entries}.items():
        identity_key = "revision" if "revision" in entry else "digest"
        identity = entry.get(identity_key)
        modalities = entry.get("modalities")
        if (
            not isinstance(identity, str)
            or re.fullmatch(r"[0-9a-fA-F]{40,64}", identity) is None
            or not isinstance(modalities, list)
            or "text" not in modalities
        ):
            continue
        profiles[spec] = {
            "generation_tokens": 4096,
            "identity": {identity_key: identity.lower()},
            "local_execution": (
                {
                    "gpu_memory_utilization": entry.get(
                        "gpu_memory_utilization", 0.9
                    ),
                    "max_model_len": -1,
                    "tensor_parallel_size": (
                        entry.get("tensor_parallel_size")
                        if entry.get("tensor_parallel_size") in {1, 2}
                        else 1
                    ),
                }
                if spec.startswith("vllm:")
                else {"num_ctx": "fit", "think": entry.get("think", False)}
            ),
            "modalities": list(modalities),
            "readiness": {
                "path": str(evidence.resolve()),
                "sha256": "b" * 64,
                "readiness_id": "c" * 64,
            },
            "request_timeout_seconds": 120.0,
        }
    (repo / "experiments" / "local-model-profiles.json").write_text(
        json.dumps({
            "schema": "ura-local-model-execution-profiles/3",
            "models": profiles,
        }),
        encoding="utf-8",
    )
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
    assert "var paramsOk=Number.isFinite(params)?params<=max:includeUnknown;" in page
    assert "max>=3000" not in page
    assert "kind==='local'&&backend==='vllm'" in page
    assert "data-backend='vllm'" in page
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

    assert "Local Ollama (local daemon)" in page
    ollama_at = page.index(f"data-model='{ollama_spec}'")
    ollama_row = page[
        page.rfind("<div class='modelrow'", 0, ollama_at):
        page.find("</div>", ollama_at) + len("</div>")
    ]
    assert "data-backend='ollama'" in ollama_row
    assert "digest pinned" in ollama_row
    assert "precision is fixed by the pulled Ollama artifact" in ollama_row
    assert "automatic maximum GPU-fit context / output cap 4,096 tokens" in ollama_row
    assert "thinking disabled" in ollama_row
    assert "data-compatible" not in ollama_row
    assert "data-params-b" not in ollama_row
    assert "precision-badge" not in ollama_row
    assert "modelquant" not in ollama_row
    assert f"quantization::{ollama_spec}" not in page
    ollama_config_path = app._materialize_selected_local_config([ollama_spec])
    ollama_config = json.loads(ollama_config_path.read_text(encoding="utf-8"))
    assert ollama_config == {
        ollama_spec: {
            "digest": "a" * 64,
            "modalities": ["text"],
            "num_ctx": "fit",
            "num_predict": 4096,
            "think": False,
            "timeout": 120.0,
        }
    }
    from experiments.rig_web_app.ollama_service import OllamaService  # noqa: PLC0415

    monkeypatch.setattr(
        OllamaService,
        "roster",
        lambda _self, _entries, *, force=False: {
            "available": True,
            "models": [
                {
                    "spec": ollama_spec,
                    "digest": "a" * 64,
                    "modalities": ["text"],
                }
            ],
            "excluded": [],
        },
    )
    loaded_ollama, _artifact = run_matrix._load_local_config(
        str(ollama_config_path), [ollama_spec]
    )
    ollama_target = run_matrix.build_target(
        ollama_spec, local_identity=loaded_ollama[ollama_spec]
    )
    assert ollama_target.__class__.__name__ == "OllamaTarget"
    assert ollama_target.num_ctx == "fit"
    assert "num_ctx" not in ollama_target._sampling_options()
    assert ollama_target._sampling_options()["num_predict"] == 4096

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
    # An unpinned and therefore unprofiled roster row remains visible but is
    # disabled; its quantization control is still separate from the radio.
    lower = "vllm:org/Lower-7B"
    marker = f"data-model='{lower}'"
    at = page.index(marker)
    input_tag = page[page.rfind("<input", 0, at):page.find(">", at)]
    assert "type='radio'" in input_tag and "name='local_choice'" in input_tag
    assert "disabled" in input_tag
    assert "readiness required" in page[
        page.rfind("<div class='modelrow'", 0, at):page.find("</div>", at)
    ]
    id_start = input_tag.index("id='") + len("id='")
    control_id = input_tag[id_start:input_tag.index("'", id_start)]
    row_start = page.rfind("<div class='modelrow'", 0, at)
    quant_at = page.index(f"name='quantization::{lower}'", at)
    assert f"for='{control_id}'" in page[row_start:at]
    assert "</label><div class='modelquant'>" in page[at:quant_at]
    quant_tag = page[page.rfind("<select", at, quant_at):page.find(">", quant_at)]
    assert "disabled" in quant_tag
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

    invalid_override = {
        **_params,
        "mode": "measured",
        "local": tiny,
        f"quantization::{tiny}": "bogus",
    }
    invalid_override_errors = app._validate_builder(invalid_override)
    assert "per-model quantization must be auto, none, fp8" in (
        invalid_override_errors["models"]
    )
    jobs_before = set(app.jobs)
    invalid_status, _, invalid_body = app.handle("POST", "/build", invalid_override)
    assert invalid_status == 200
    assert "per-model quantization must be auto, none, fp8" in (
        invalid_body.decode("utf-8")
    )
    assert set(app.jobs) == jobs_before

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
    assert global_bnb_config[tiny]["revision"] == "a" * 40
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


@pytest.mark.parametrize(
    ("spec", "entry", "message"),
    [
        (
            "ollama:broken:latest",
            {"digest": "a" * 64, "modalities": [{}]},
            "requires unique declared text[/image] modalities",
        ),
        (
            "ollama:audio-only:latest",
            {"digest": "a" * 64, "modalities": ["audio"]},
            "requires unique declared text[/image] modalities",
        ),
        (
            "vllm:org/Broken-Modalities",
            {"revision": "b" * 40, "modalities": [{}], "parameter_count_b": 1},
            "requires unique declared text[/image] modalities",
        ),
        (
            "vllm:org/Audio-Only",
            {"revision": "b" * 40, "modalities": ["audio"], "parameter_count_b": 1},
            "requires unique declared text[/image] modalities",
        ),
        (
            "vllm:org/Broken-Utilization",
            {
                "revision": "c" * 40,
                "modalities": ["text"],
                "parameter_count_b": 1,
                "gpu_memory_utilization": 1.0,
            },
            "gpu_memory_utilization must be in [0.1, 0.95]",
        ),
        (
            "vllm:org/Broken-Quantization",
            {
                "revision": "d" * 40,
                "modalities": ["text"],
                "parameter_count_b": 1,
                "quantization": "bogus",
            },
            "configured quantization must be auto, none, fp8",
        ),
    ],
)
def test_builder_rejects_malformed_local_runtime_config_before_job(
    tmp_path: Path,
    spec: str,
    entry: dict[str, object],
    message: str,
) -> None:
    repo = tmp_path / "repo"
    rig = repo / "experiments" / "rig"
    rig.mkdir(parents=True)
    (rig / "api-targets.example.json").write_text("{}", encoding="utf-8")
    (rig / "local-targets.example.json").write_text(
        json.dumps({spec: entry}), encoding="utf-8"
    )
    (rig / "vllm-roster.example.json").write_text(
        json.dumps({"models": {}}), encoding="utf-8"
    )
    app = RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=repo,
    )

    status, _, body = app.handle("GET", "/build")
    page = body.decode("utf-8")
    assert status == 200 and spec in page
    assert "invalid local config" in page
    assert message in page

    params = {"mode": "measured", "local": spec}
    errors = app._validate_builder(params)
    assert message in errors["models"]
    jobs_before = set(app.jobs)
    status, _, body = app.handle("POST", "/build", params)
    assert status == 200 and message in body.decode("utf-8")
    assert set(app.jobs) == jobs_before
    with pytest.raises(ValueError, match=re.escape(message)):
        app._materialize_selected_local_config([spec])
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
    # Budget tracking remains available without inventing a funded campaign,
    # and an empty results root degrades gracefully. Charts come ONLY from
    # schema-valid producer artifacts (see the real Level-1/Level-2 tests);
    # an unrecognized ad-hoc JSON shape renders nothing.
    app = _isolated_app(tmp_path)
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "Budgets" in text and "/config?file=budgets" in text
    assert "Anthropic" not in text and "$100" not in text
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

    # These controller commands are reachable only through validated Build
    # actions, never a generic raw-argv form.
    internal = {"model_acquire", "ollama_pull", "run_matrix"}
    named = [name for _, _, _, names in COMMAND_GROUPS for name in names]
    assert len(named) == len(set(named)), "command grouped twice"
    assert set(named) == set(COMMANDS) - internal, (
        sorted(set(named) ^ (set(COMMANDS) - internal))
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
    # names both the non-archived and archived receipt as links.
    assert "/artifacts?path=thesis/project-revision" in text
    assert "1 non-archived, 1 archived" in text
    assert "filesystem placement only" in text
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
        elif name in {"model_acquire", "ollama_pull", "run_matrix"}:
            # Pull and measured matrix execution require their validated
            # Build controller, not a raw generic argv form.
            assert f"name='command' value='{name}'" not in run_text
        else:
            assert run_text.count(
                f"<input type='hidden' name='command' value='{name}'>"
            ) == 1
    # The client-side filter is present and cards carry filterable names.
    assert "cmdfilter" in run_text
    assert "data-name='run_matrix'" not in run_text


def test_dashboard_notices_do_not_depend_on_campaign_policy(tmp_path: Path) -> None:
    # Operator notices from console-warnings.json render as banners with the
    # annotate-never-authorize disclaimer, and malformed files are ignored.
    app = _app(tmp_path)
    status, _, body = app.handle("GET", "/")
    text = body.decode("utf-8")
    assert status == 200
    assert "Notices" not in text  # no warnings file -> no banner card
    assert "Campaign sampling policy" not in text

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
        assert "Running (<span class='chip-count'>1</span>)" in text
        assert "id='job-from' type='datetime-local'" in text
        assert "id='job-to' type='datetime-local'" in text
        assert "data-started='" in text
        assert "<th>Work</th><th>Execution</th><th>State</th>" in text
        assert "tool / validation" in text and "not applicable" in text
        assert "class='job-started' data-epoch-ms='" in text
        assert " UTC</time>" in text
        assert "var now=Date.now()" in text
        assert "localValue(now-7*86400000)" in text
        assert "localValue(now)" in text
        assert "out.textContent=localStamp(ms)" in text
        assert "var explicitFrom=params.has('from')" in text
        assert "var explicitTo=params.has('to')" in text
        assert "if(explicitFrom&&Number.isFinite(fromMs))" in text
        assert "if(explicitTo&&Number.isFinite(toMs))" in text
        assert "url.searchParams.delete('from')" in text
        assert "url.searchParams.delete('to')" in text
        assert "url.searchParams.set('from_ms',String(fromMs))" in text
        assert "url.searchParams.set('to_ms',String(toMs))" in text
        assert "syncFilters();location.reload()" in text
        assert "fromBox.addEventListener('change',function(){explicitFrom=true" in text
        assert "toBox.addEventListener('change',function(){explicitTo=true" in text
        # The default seven-day window remains implicit. Initial sync and the
        # five-second running-job reload therefore recalculate `to=now` instead
        # of freezing the first-render timestamp in the URL. Only a user's
        # date-control change promotes either bound to an explicit filter.
        assert text.count("explicitFrom=true") == 1
        assert text.count("explicitTo=true") == 1
        assert "else{url.searchParams.delete('from');url.searchParams.delete('from_ms');}" in text
        assert "else{url.searchParams.delete('to');url.searchParams.delete('to_ms');}" in text
        assert "state=params.get('state')||''" in text
        assert "box.value=params.get('q')" in text
        assert "url.searchParams.set('state',state)" in text
        assert "url.searchParams.set('q',box?box.value:'')" in text
        assert "function upperBound(box,fallback)" in text
        assert "value+=box.value.length===16?59999:999" in text
        # A running job exposes an inline Stop control on its row.
        assert f"/jobs/{job.job_id}/stop" in text
        assert "jobfilter" in text
        # Human-readable durations, not raw seconds with a trailing 's' only.
        assert "data-hay=" in text
    finally:
        app.stop_job(job.job_id)


def test_jobs_truthfully_labels_no_call_and_preparation_modes(tmp_path: Path) -> None:
    app = _app(tmp_path)
    fixtures = {
        "preflight-only": ["--preflight-only"],
        "dry-canary": ["--diagnostic-canary", "--dry-run"],
        "harm-direct": ["--method", "DirectRequest"],
        "harm-optimizer": ["--method", "PEZ"],
    }
    for job_id, argv in fixtures.items():
        command = "harmbench_capture" if job_id.startswith("harm-") else "run_matrix"
        app.jobs[job_id] = Job(
            job_id=job_id,
            command=command,
            argv=argv,
            directory=tmp_path / job_id,
            process=None,
            restored_state="complete",
            restored_exit=0,
        )

    text = app.handle("GET", "/jobs")[2].decode("utf-8")

    def row(job_id: str) -> str:
        start = text.index(f"/jobs/{job_id}")
        return text[text.rfind("<tr", 0, start):text.find("</tr>", start)]

    assert "preflight" in row("preflight-only")
    assert "no model call" in row("preflight-only")
    assert "offline dry run" in row("dry-canary")
    assert "no model call" in row("dry-canary")
    assert "preparation" in row("harm-direct")
    assert "no model call" in row("harm-direct")
    assert "preparation" in row("harm-optimizer")
    assert "verify capture artifact" in row("harm-optimizer")
    app.close()


def test_jobs_date_window_queries_persisted_history_beyond_restore_cache(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    db = ConsoleDB(state / "console.db")
    base = 1_700_000_000.0
    for index in range(501):
        job = Job(
            job_id=f"job-history-{index:04d}",
            command="webui_selftest",
            argv=[],
            directory=state / f"job-history-{index:04d}",
            process=None,
            started_at=base + index,
            ended_at=base + index + 0.5,
            restored_state="complete",
            restored_exit=0,
        )
        assert db.upsert_job(job, state="complete", exit_code=0)
    db.close()

    results = tmp_path / "runs"
    results.mkdir()
    app = RigWebApp(results_root=results, state_dir=state)
    try:
        assert len(app.jobs) == 500
        assert "job-history-0000" not in app.jobs
        status, _, body = app.handle(
            "GET",
            "/jobs?from_ms=1699999999000&to_ms=1700000000500",
        )
        text = body.decode("utf-8")
        assert status == 200
        assert "job-history-0000" in text
        assert "job-history-0500" not in text
        detail = app.handle("GET", "/jobs/job-history-0000")
        assert detail[0] == 200
    finally:
        app.close()


def test_jobs_date_filter_uses_browser_timezone_not_server_timezone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import pages as pages_module

    app = _app(tmp_path)
    app.jobs["dated-job"] = Job(
        job_id="dated-job",
        command="webui_selftest",
        argv=[],
        directory=tmp_path / "dated-job",
        process=None,
        started_at=1_700_000_000.0,
        restored_state="complete",
        restored_exit=0,
    )

    def reject_server_localtime(*_args: object) -> object:
        raise AssertionError("Jobs must not format filter timestamps in server local time")

    monkeypatch.setattr(pages_module.time, "localtime", reject_server_localtime)
    text = app.handle(
        "GET",
        "/jobs?from_ms=1699999999000&to_ms=1700000001000",
    )[2].decode("utf-8")
    assert "2023-11-14 22:13:20 UTC" in text
    assert "new Date(ms)" in text
    assert "date.getFullYear()" in text and "date.getHours()" in text
    assert "params.has('from')" in text and "params.has('to')" in text
    app.close()


def _write_external_engineering_campaign(results: Path) -> Path:
    campaign = results / "engineering" / "local-only-20260817T000000Z"
    campaign.mkdir(parents=True)
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (campaign / "ENGINEERING_ONLY.json").write_text(json.dumps({
        "schema": "ura-engineering-campaign/1",
        "campaign_id": "local-only-20260817T000000Z",
        "release_commit": "a" * 40,
        "evidence_class": "engineering_stress",
        "thesis_empirical_evidence": False,
        "hosted_calls_allowed": False,
        "target_call_cap": 10,
        "hard_stop_hours": 23,
        "started_at": started_at,
    }), encoding="utf-8")
    (campaign / "task-log.jsonl").write_text("\n".join((
        json.dumps({
            "at": "2026-08-17T00:00:00Z", "event": "campaign_start",
            "task": "bootstrap", "status": "running", "detail": "local-only",
        }),
        json.dumps({
            "at": "2026-08-17T00:00:01Z", "event": "task_start",
            "task": "download-model", "status": "running", "detail": "download",
        }),
    )) + "\n", encoding="utf-8")
    (campaign / "stage2-task-log.jsonl").write_text(json.dumps({
        "at": "2026-08-17T00:00:02Z", "event": "campaign_start",
        "task": "stage2", "status": "running", "detail": "waiting_for_bootstrap",
    }) + "\n", encoding="utf-8")
    return campaign


def test_jobs_date_window_filters_campaign_markers_before_recent_cap(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    engineering = app.results_root / "engineering"
    engineering.mkdir()
    for index in range(21):
        campaign_id = f"campaign-{index:02d}"
        directory = engineering / campaign_id
        directory.mkdir()
        started_at = (
            "2000-01-01T00:00:00Z"
            if index == 0
            else f"2026-08-17T00:00:{index:02d}Z"
        )
        (directory / "ENGINEERING_ONLY.json").write_text(
            json.dumps({
                "schema": "ura-engineering-campaign/1",
                "campaign_id": campaign_id,
                "release_commit": "a" * 40,
                "evidence_class": "engineering_stress",
                "thesis_empirical_evidence": False,
                "hosted_calls_allowed": False,
                "target_call_cap": 1,
                "started_at": started_at,
            }),
            encoding="utf-8",
        )
        (directory / "task-log.jsonl").write_text(
            json.dumps({
                "at": started_at,
                "event": "campaign_start",
                "task": "bootstrap",
                "status": "running",
                "detail": campaign_id,
            }) + "\n",
            encoding="utf-8",
        )
        os.utime(directory, (1_700_000_000 + index, 1_700_000_000 + index))

    recent, notice = app._engineering_campaign_scan()
    assert len(recent) == 20
    assert all(item.campaign_id != "campaign-00" for item in recent)
    assert "1 additional retained engineering campaign was omitted" in notice

    status, _, body = app.handle(
        "GET",
        "/jobs?from_ms=946684799000&to_ms=946684801000",
    )
    text = body.decode("utf-8")
    assert status == 200
    assert "campaign-00" in text
    assert "campaign-20" not in text
    assert "1 additional retained engineering campaign was omitted" not in text
    app.close()


def test_dashboard_names_and_lists_the_bound_source_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    thesis = app.results_root / "thesis"
    thesis.mkdir(parents=True, exist_ok=True)
    historical = thesis / "source-conformance.json"
    historical.write_text("{}", encoding="utf-8")
    current = thesis / "source-conformance-current-45arm.json"
    current.write_text('{"schema":"fixture-current"}', encoding="utf-8")
    current_sha = hashlib.sha256(current.read_bytes()).hexdigest()
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(current))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", current_sha)

    status, _, body = app.handle("GET", "/")
    assert status == 200
    text = body.decode("utf-8")
    assert "Source receipts: 2 non-archived" in text
    assert "thesis/source-conformance-current-45arm.json" in text
    assert "thesis/source-conformance.json" in text
    assert "Source receipt" in text
    assert "Source receipt SHA-256" in text
    assert current_sha in text
    app.close()


def test_stats_campaign_cap_ignores_newer_non_campaign_directories(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    engineering = app.results_root / "engineering"
    engineering.mkdir()
    for index in range(20):
        campaign_id = f"campaign-valid-{index:02d}"
        directory = engineering / campaign_id
        directory.mkdir()
        started_at = f"2026-08-17T00:00:{index:02d}Z"
        (directory / "ENGINEERING_ONLY.json").write_text(
            json.dumps({
                "schema": "ura-engineering-campaign/1",
                "campaign_id": campaign_id,
                "release_commit": "a" * 40,
                "evidence_class": "engineering_stress",
                "thesis_empirical_evidence": False,
                "hosted_calls_allowed": False,
                "target_call_cap": 1,
                "started_at": started_at,
            }),
            encoding="utf-8",
        )
        (directory / "task-log.jsonl").write_text(
            json.dumps({
                "at": started_at,
                "event": "campaign_start",
                "task": "bootstrap",
                "status": "running",
                "detail": campaign_id,
            }) + "\n",
            encoding="utf-8",
        )
        os.utime(directory, (1_700_000_000 + index, 1_700_000_000 + index))

    ordinary = engineering / "repin-newer-not-a-campaign"
    ordinary.mkdir()
    os.utime(ordinary, (1_800_000_000, 1_800_000_000))

    recent, notice = app._engineering_campaign_scan()
    assert len(recent) == 20
    assert {item.campaign_id for item in recent} == {
        f"campaign-valid-{index:02d}" for index in range(20)
    }
    assert notice == ""
    app.close()


def test_jobs_lists_external_engineering_campaign_read_only(tmp_path: Path) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    with (campaign / "task-log.jsonl").open("a", encoding="utf-8") as handle:
        # A retried task is one task in progress, not two completed tasks.
        for status in ("failed", "passed"):
            handle.write(json.dumps({
                "at": "2026-08-17T00:00:01Z", "event": "task_end",
                "task": "download-model", "status": status, "detail": status,
            }) + "\n")

    status, _, body = app.handle("GET", "/jobs")
    text = body.decode("utf-8")
    assert status == 200
    assert "All (<span class='chip-count'>1</span>)" in text
    assert "Unknown (<span class='chip-count'>1</span>)" in text
    assert "Running (<span class='chip-count'>1</span>)" not in text
    assert "local-only-20260817T000000Z" in text
    assert "engineering campaign" in text and "external" in text
    assert "task processes: 1 succeeded; 0 failed; 0 skipped; 0 active" in text
    assert "task processes: 2 succeeded" not in text
    assert "pending: not declared" in text
    assert "model work undeclared" in text and "not reported" in text
    assert "(last recorded)" not in text
    assert "/jobs/campaign/local-only-20260817T000000Z" in text
    assert "/jobs/campaign/local-only-20260817T000000Z/stop" not in text

    # Discovery is a filesystem-backed read-only view. It neither fabricates
    # subprocess ownership nor inserts engineering work into the job/run DB.
    assert app.jobs == {}
    assert app.db.health()["counts"]["jobs"] == 0
    assert app.db.list_runs() == []

    status, _, detail = app.handle(
        "GET", "/jobs/campaign/local-only-20260817T000000Z"
    )
    detail_text = detail.decode("utf-8")
    assert status == 200
    assert "Externally managed engineering work" in detail_text
    assert "not thesis empirical evidence" in detail_text
    assert "Hosted calls allowed</td><td>no" in detail_text
    assert "Browse all retained campaign files" in detail_text
    assert "stream=bootstrap" in detail_text and "stream=stage2" in detail_text
    assert "/stop" not in detail_text

    status, content_type, log = app.handle(
        "GET",
        "/jobs/campaign/local-only-20260817T000000Z/log?stream=stage2",
    )
    assert status == 200 and content_type.startswith("text/plain")
    assert b"waiting_for_bootstrap" in log
    status, _, message = app.handle(
        "POST", "/jobs/campaign/local-only-20260817T000000Z/stop"
    )
    assert status == 405 and b"read-only" in message
    assert campaign.is_dir()
    app.close()


@pytest.mark.parametrize(
    "terminal_status",
    ["passed_with_optional_failures", "complete_with_optional_failures"],
)
def test_external_campaign_task_failures_do_not_override_passing_terminal(
    tmp_path: Path,
    terminal_status: str,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["download-model", "optional-probe"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    with (campaign / "stage2-task-log.jsonl").open("a", encoding="utf-8") as handle:
        for event in (
            {
                "at": "2026-08-17T00:00:03Z", "event": "task_end",
                "task": "download-model", "status": "passed", "detail": "done",
            },
            {
                "at": "2026-08-17T00:00:04Z", "event": "task_start",
                "task": "optional-probe", "status": "running", "detail": "probe",
            },
            {
                "at": "2026-08-17T00:00:05Z", "event": "task_end",
                "task": "optional-probe", "status": "failed", "detail": "optional",
            },
            {
                "at": "2026-08-17T00:00:06Z", "event": "campaign_end",
                "task": "stage2", "status": terminal_status,
                "detail": "optional_probe_failed",
            },
        ):
            handle.write(json.dumps(event) + "\n")

    observed = app._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert observed.state == "complete" and observed.display_state == terminal_status
    assert observed.succeeded_tasks == 1 and observed.failed_tasks == 1
    assert observed.skipped_tasks == 0
    assert observed.active_tasks == () and observed.pending_tasks == 0
    assert observed.status_tag == "partial"

    status, _, body = app.handle("GET", "/jobs")
    text = body.decode("utf-8")
    assert status == 200
    assert "Partial (<span class='chip-count'>1</span>)" in text
    assert "(last recorded)" not in text
    assert "task processes: 1 succeeded; 1 failed; 0 skipped; 0 active" in text
    assert "pending: 0" in text
    assert f"campaign terminal: {terminal_status} - optional_probe_failed" in text

    dashboard = app.handle("GET", "/")[2].decode("utf-8")
    assert "<span class='value'><span class='dot red'></span>0</span>" in dashboard
    assert "Failed jobs" not in dashboard
    assert "<span class='value'><span class='dot amber'></span>1</span>" in dashboard
    assert "Partial campaigns" in dashboard
    assert "1 succeeded; 1 failed; 0 skipped; 0 pending" in dashboard
    assert app.db.health()["counts"]["jobs"] == 0
    app.close()


def test_external_campaign_reports_skipped_tasks_separately(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = [
        "download-model",
        "optional-probe",
        "not-reached",
        "never-started",
    ]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    with (campaign / "stage2-task-log.jsonl").open("a", encoding="utf-8") as handle:
        for event in (
            {
                "at": "2026-08-17T00:00:03Z",
                "event": "task_end",
                "task": "download-model",
                "status": "passed",
                "detail": "done",
            },
            {
                "at": "2026-08-17T00:00:04Z",
                "event": "task_end",
                "task": "optional-probe",
                "status": "failed",
                "detail": "optional",
            },
            {
                "at": "2026-08-17T00:00:05Z",
                "event": "task_skip",
                "task": "not-reached",
                "status": "skipped",
                "detail": "not_reached_in_bounded_wave",
            },
            {
                "at": "2026-08-17T00:00:06Z",
                "event": "campaign_end",
                "task": "stage2",
                "status": "passed_with_optional_failures",
                "detail": "bounded_wave_complete",
            },
        ):
            handle.write(json.dumps(event) + "\n")

    observed = app._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert observed.state == "complete"
    assert observed.succeeded_tasks == 1
    assert observed.failed_tasks == 1
    assert observed.skipped_tasks == 1
    assert observed.active_tasks == ()
    assert observed.pending_tasks == 1
    assert observed.completed_tasks == 3
    assert (
        observed.succeeded_tasks
        + observed.failed_tasks
        + observed.skipped_tasks
        + len(observed.active_tasks)
        + (observed.pending_tasks or 0)
        == 4
    )

    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    detail = app.handle(
        "GET", "/jobs/campaign/local-only-20260817T000000Z"
    )[2].decode("utf-8")
    expected = "task processes: 1 succeeded; 1 failed; 1 skipped; 0 active; pending: 1"
    assert expected in jobs
    assert expected in detail
    app.close()


def test_external_campaign_separates_process_results_from_model_execution(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["setup", "model-probe"]
    marker["model_tasks"] = ["model-probe"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (campaign / "task-log.jsonl").write_text(
        json.dumps({
            "at": "2026-08-17T00:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
        }) + "\n",
        encoding="utf-8",
    )
    (campaign / "stage2-task-log.jsonl").write_text(
        "\n".join(json.dumps(event) for event in (
            {
                "at": "2026-08-17T00:00:01Z",
                "event": "campaign_start",
                "task": "stage2",
                "status": "running",
            },
            {
                "at": "2026-08-17T00:00:02Z",
                "event": "task_end",
                "task": "setup",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:03Z",
                "event": "task_end",
                "task": "model-probe",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:04Z",
                "event": "campaign_end",
                "task": "stage2",
                "status": "passed",
            },
        )) + "\n",
        encoding="utf-8",
    )

    observed = app._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert observed.status_tag == "passed"
    assert observed.task_outcomes == (
        ("setup", "passed", "support"),
        ("model-probe", "passed", "model"),
    )
    assert observed.model_succeeded_tasks == 1
    assert observed.model_attempted_calls is None
    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    detail = app.handle(
        "GET", "/jobs/campaign/local-only-20260817T000000Z"
    )[2].decode("utf-8")
    assert "model + support" in jobs and "not reported" in jobs
    assert "model execution: not reported" in jobs
    assert "A passed support task proves only that its command exited successfully" in detail
    assert "<td>support</td><td>passed</td>" in detail
    assert "<td>model</td><td>passed</td>" in detail

    (campaign / "model-execution.jsonl").write_text(
        json.dumps({
            "event": "model_execution",
            "task": "model-probe",
            "attempted_calls": 1,
            "successful_generations": 1,
        }) + "\n",
        encoding="utf-8",
    )
    confirmed = app._engineering_campaign("local-only-20260817T000000Z")
    assert confirmed is not None
    assert confirmed.model_attempted_calls == 1
    assert confirmed.model_successful_generations == 1
    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    assert "1/1 reported successful" in jobs
    assert "model execution report: 1 successful generation(s) from 1 attempt(s)" in jobs
    app.close()


def test_external_campaign_duplicate_status_and_execution_counts_fail_closed(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["model-probe"]
    marker["model_tasks"] = ["model-probe"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (campaign / "task-log.jsonl").write_text(
        json.dumps({
            "at": "2026-08-17T00:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
        }) + "\n",
        encoding="utf-8",
    )
    (campaign / "stage2-task-log.jsonl").write_text(
        "\n".join((
            json.dumps({
                "at": "2026-08-17T00:00:01Z",
                "event": "campaign_start",
                "task": "stage2",
                "status": "running",
            }),
            json.dumps({
                "at": "2026-08-17T00:00:02Z",
                "event": "task_end",
                "task": "model-probe",
                "status": "passed",
            }),
            # A last-wins decoder would call this a passed campaign.
            '{"at":"2026-08-17T00:00:03Z","event":"campaign_end",'
            '"task":"stage2","status":"failed","status":"passed"}',
        )) + "\n",
        encoding="utf-8",
    )

    ambiguous_status = app._engineering_campaign("local-only-20260817T000000Z")
    assert ambiguous_status is not None
    assert ambiguous_status.state == "unknown"
    assert ambiguous_status.status_tag == "unknown"
    assert "activity status unavailable: malformed JSON event" in (
        ambiguous_status.progress
    )

    # Restore an unambiguous terminal process record, then make the separate
    # execution-evidence stream ambiguous. It must not become a 1/1 claim.
    (campaign / "stage2-task-log.jsonl").write_text(
        "\n".join(json.dumps(event) for event in (
            {
                "at": "2026-08-17T00:00:01Z",
                "event": "campaign_start",
                "task": "stage2",
                "status": "running",
            },
            {
                "at": "2026-08-17T00:00:02Z",
                "event": "task_end",
                "task": "model-probe",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:03Z",
                "event": "campaign_end",
                "task": "stage2",
                "status": "passed",
            },
        )) + "\n",
        encoding="utf-8",
    )
    (campaign / "model-execution.jsonl").write_text(
        '{"event":"model_execution","task":"model-probe",'
        '"attempted_calls":0,"attempted_calls":1,'
        '"successful_generations":1}\n',
        encoding="utf-8",
    )
    ambiguous_execution = app._engineering_campaign(
        "local-only-20260817T000000Z"
    )
    assert ambiguous_execution is not None
    assert ambiguous_execution.model_attempted_calls is None
    assert ambiguous_execution.model_successful_generations is None
    assert ambiguous_execution.model_execution_error == "malformed JSON event"
    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    assert "1/1 reported successful" not in jobs
    assert "model execution report invalid: malformed JSON event" in jobs
    app.close()


def test_external_campaign_rejects_ambiguous_marker_json(tmp_path: Path) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    raw = marker_path.read_text(encoding="utf-8")
    field = '"hosted_calls_allowed": false'
    assert raw.count(field) == 1
    marker_path.write_text(
        raw.replace(
            field,
            '"hosted_calls_allowed": true, ' + field,
            1,
        ),
        encoding="utf-8",
    )

    assert app._engineering_campaign("local-only-20260817T000000Z") is None
    app.close()


def test_external_campaign_rejects_invalid_model_execution_claims(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["setup"]
    marker["model_tasks"] = ["undeclared-task"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (campaign / "model-execution.jsonl").write_text(
        json.dumps({
            "event": "model_execution",
            "task": "setup",
            "attempted_calls": 1,
            "successful_generations": 1,
        }) + "\n",
        encoding="utf-8",
    )

    observed = app._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert "not in planned_tasks" in observed.model_declaration_error
    assert observed.model_attempted_calls is None
    assert "requires a valid model_tasks declaration" in observed.model_execution_error
    assert ("setup", "pending", "unclassified") in observed.task_outcomes
    jobs = app.handle("GET", "/jobs")[2].decode("utf-8")
    assert "model work undeclared" in jobs and "report invalid" in jobs
    app.close()


@pytest.mark.parametrize("task_status", ["skipped", None])
def test_external_campaign_rejects_model_calls_for_unexecuted_tasks(
    tmp_path: Path,
    task_status: str | None,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["model-probe"]
    marker["model_tasks"] = ["model-probe"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (campaign / "task-log.jsonl").write_text(
        json.dumps({
            "at": "2026-08-17T00:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
        }) + "\n",
        encoding="utf-8",
    )
    events = [{
        "at": "2026-08-17T00:00:03Z",
        "event": "campaign_end",
        "task": "stage2",
        "status": "passed",
    }]
    if task_status is not None:
        events.insert(0, {
            "at": "2026-08-17T00:00:02Z",
            "event": "task_skip",
            "task": "model-probe",
            "status": task_status,
        })
    with (campaign / "stage2-task-log.jsonl").open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    (campaign / "model-execution.jsonl").write_text(
        json.dumps({
            "event": "model_execution",
            "task": "model-probe",
            "attempted_calls": 1,
            "successful_generations": 1,
        }) + "\n",
        encoding="utf-8",
    )

    observed = app._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert observed.status_tag == "partial"
    assert observed.failed_tasks == 0
    assert observed.pending_tasks == (1 if task_status is None else 0)
    assert observed.model_attempted_calls is None
    assert "contradicts a pending or skipped task" in observed.model_execution_error

    (campaign / "model-execution.jsonl").write_text(
        json.dumps({
            "event": "model_execution",
            "task": "model-probe",
            "attempted_calls": 0,
            "successful_generations": 0,
        }) + "\n",
        encoding="utf-8",
    )
    zero_report = app._engineering_campaign("local-only-20260817T000000Z")
    assert zero_report is not None
    assert zero_report.model_execution_error == ""
    assert zero_report.model_attempted_calls == 0
    assert zero_report.model_successful_generations == 0
    app.close()


def test_external_campaign_model_execution_report_requires_exact_task_coverage(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["model-a", "model-b"]
    marker["model_tasks"] = ["model-a", "model-b"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (campaign / "task-log.jsonl").write_text(
        json.dumps({
            "at": "2026-08-17T00:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
        }) + "\n",
        encoding="utf-8",
    )
    (campaign / "stage2-task-log.jsonl").write_text(
        "\n".join(json.dumps(event) for event in (
            {
                "at": "2026-08-17T00:00:01Z",
                "event": "campaign_start",
                "task": "stage2",
                "status": "running",
            },
            {
                "at": "2026-08-17T00:00:02Z",
                "event": "task_end",
                "task": "model-a",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:03Z",
                "event": "task_end",
                "task": "model-b",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:04Z",
                "event": "campaign_end",
                "task": "stage2",
                "status": "passed",
            },
        )) + "\n",
        encoding="utf-8",
    )
    report = campaign / "model-execution.jsonl"
    duplicate_rows = [
        {
            "event": "model_execution",
            "task": task,
            "attempted_calls": 1,
            "successful_generations": 1,
        }
        for task in ("model-a", "model-a", "model-b")
    ]
    report.write_text(
        "\n".join(json.dumps(row) for row in duplicate_rows) + "\n",
        encoding="utf-8",
    )
    duplicate = app._engineering_campaign("local-only-20260817T000000Z")
    assert duplicate is not None
    assert duplicate.model_attempted_calls is None
    assert "duplicates a task" in duplicate.model_execution_error

    report.write_text(json.dumps(duplicate_rows[0]) + "\n", encoding="utf-8")
    missing = app._engineering_campaign("local-only-20260817T000000Z")
    assert missing is not None
    assert missing.model_attempted_calls is None
    assert "omits declared model task(s): model-b" in missing.model_execution_error
    assert "model only" in app.handle("GET", "/jobs")[2].decode("utf-8")
    detail = app.handle(
        "GET", "/jobs/campaign/local-only-20260817T000000Z"
    )[2].decode("utf-8")
    assert "report invalid: terminal model execution report omits" in detail
    app.close()


def test_external_campaign_surfaces_unplanned_work_without_inventing_a_plan(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["setup"]
    marker["model_tasks"] = []
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    (campaign / "task-log.jsonl").write_text(
        json.dumps({
            "at": "2026-08-17T00:00:00Z",
            "event": "campaign_start",
            "task": "bootstrap",
            "status": "running",
        }) + "\n",
        encoding="utf-8",
    )
    (campaign / "stage2-task-log.jsonl").write_text(
        "\n".join(json.dumps(event) for event in (
            {
                "at": "2026-08-17T00:00:01Z",
                "event": "campaign_start",
                "task": "stage2",
                "status": "running",
            },
            {
                "at": "2026-08-17T00:00:02Z",
                "event": "task_end",
                "task": "setup",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:03Z",
                "event": "task_end",
                "task": "model-call-extra",
                "status": "passed",
            },
            {
                "at": "2026-08-17T00:00:04Z",
                "event": "campaign_end",
                "task": "stage2",
                "status": "passed",
            },
        )) + "\n",
        encoding="utf-8",
    )

    planned = app._engineering_campaign("local-only-20260817T000000Z")
    assert planned is not None
    assert planned.status_tag == "partial"
    assert planned.unplanned_tasks == ("model-call-extra",)
    assert planned.task_outcomes == (
        ("setup", "passed", "support"),
        ("model-call-extra", "passed", "unplanned"),
    )
    assert "support only + unplanned" in app.handle("GET", "/jobs")[2].decode(
        "utf-8"
    )

    marker.pop("planned_tasks")
    marker.pop("model_tasks")
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    unknown_plan = app._engineering_campaign("local-only-20260817T000000Z")
    assert unknown_plan is not None
    assert unknown_plan.status_tag == "passed"
    assert unknown_plan.pending_tasks is None
    assert unknown_plan.unplanned_tasks == ()
    assert all(role == "unclassified" for _task, _status, role in unknown_plan.task_outcomes)
    app.close()


def test_external_campaign_phase_ties_use_append_order(tmp_path: Path) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    stage2 = campaign / "stage2-task-log.jsonl"
    with stage2.open("a", encoding="utf-8") as handle:
        for event in (
            {
                "at": "2026-08-17T00:00:02Z", "event": "campaign_stop",
                "task": "stage2", "status": "blocked", "detail": "first_attempt",
            },
            {
                "at": "2026-08-17T00:00:02Z", "event": "campaign_start",
                "task": "stage2", "status": "running", "detail": "retry",
            },
        ):
            handle.write(json.dumps(event) + "\n")

    retried = app._engineering_campaign("local-only-20260817T000000Z")
    assert retried is not None
    # The later same-timestamp start wins. Because this legacy fixture has no
    # verifiable named session, liveness reconciliation then reports unknown.
    assert retried.state == "unknown" and retried.display_state == "unknown"
    assert "running state cannot be verified" in retried.state_detail

    with stage2.open("a", encoding="utf-8") as handle:
        for status in ("failed", "passed"):
            handle.write(json.dumps({
                "at": "2026-08-17T00:00:02Z", "event": "campaign_end",
                "task": "stage2", "status": status, "detail": status,
            }) + "\n")

    corrected = app._engineering_campaign("local-only-20260817T000000Z")
    assert corrected is not None
    assert corrected.state == "complete" and corrected.display_state == "passed"
    assert corrected.state_detail == "passed"
    app.close()


def test_external_campaign_survives_restart_and_reads_terminal_log(tmp_path: Path) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["planned_tasks"] = ["download-model", "never-started"]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    app.close()

    with (campaign / "stage2-task-log.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({
            "at": "2026-08-17T00:01:00Z", "event": "campaign_end",
            "task": "stage2", "status": "passed", "detail": "done",
        }) + "\n")
    restarted = RigWebApp(
        results_root=tmp_path / "runs", state_dir=tmp_path / "state",
    )
    status, _, body = restarted.handle("GET", "/jobs")
    text = body.decode("utf-8")
    assert status == 200
    assert "All (<span class='chip-count'>1</span>)" in text
    assert "Partial (<span class='chip-count'>1</span>)" in text
    assert "local-only-20260817T000000Z" in text
    assert "last recorded active" not in text
    assert "0 active" in text
    assert "task processes: 0 succeeded; 1 failed; 0 skipped; 0 active" in text
    assert "pending: 1" in text
    assert "1 interrupted without a terminal task event" in text
    observed = restarted._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert (
        observed.succeeded_tasks
        + observed.failed_tasks
        + observed.skipped_tasks
        + len(observed.active_tasks)
        + (
            observed.pending_tasks or 0
        )
        == 2
    )
    assert restarted.jobs == {}
    assert restarted.db.health()["counts"]["jobs"] == 0
    restarted.close()


def test_external_campaign_malformed_and_oversized_logs_do_not_break_jobs(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    (campaign / "task-log.jsonl").write_bytes(b"x" * (512 * 1024 + 1))

    malformed = app.results_root / "engineering" / "malformed"
    malformed.mkdir()
    (malformed / "ENGINEERING_ONLY.json").write_bytes(b"\xff\xfeinvalid")
    deep = app.results_root / "engineering" / "deep-json"
    deep.mkdir()
    (deep / "ENGINEERING_ONLY.json").write_bytes(b"[" * 2000 + b"]" * 2000)

    status, _, body = app.handle("GET", "/jobs")
    text = body.decode("utf-8")
    assert status == 200
    assert "All (<span class='chip-count'>1</span>)" in text
    assert "local-only-20260817T000000Z" in text
    assert "<span class='badge gray'>unknown</span>" in text
    assert "(last recorded)" not in text
    assert "activity status unavailable" in text
    assert "0 tasks finished" not in text
    assert "malformed" not in text and "deep-json" not in text
    app.close()


def test_external_campaign_rejects_symlink_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    _write_external_engineering_campaign(outside)
    app = _app(tmp_path)
    link = app.results_root / "engineering"
    try:
        link.symlink_to(outside / "engineering", target_is_directory=True)
    except OSError:
        app.close()
        pytest.skip("directory symlinks are not available")
    status, _, body = app.handle("GET", "/jobs")
    assert status == 200 and b"All (<span class='chip-count'>0</span>)" in body
    app.close()


def test_external_campaign_log_endpoint_reads_only_bounded_tail(tmp_path: Path) -> None:
    # A normal campaign log endpoint reads only the configured tail, even
    # when the retained activity file is larger.
    normal_results = tmp_path / "normal-runs"
    normal_results.mkdir()
    normal = _write_external_engineering_campaign(normal_results)
    event = json.dumps({
        "at": "2026-08-17T00:00:01Z", "event": "task_start",
        "task": "download-model", "status": "running", "detail": "x",
    }).encode("utf-8") + b"\n"
    (normal / "task-log.jsonl").write_bytes(event * 600)
    normal_app = RigWebApp(
        results_root=normal_results, state_dir=tmp_path / "normal-state",
    )
    status, _, log = normal_app.handle(
        "GET", "/jobs/campaign/local-only-20260817T000000Z/log?stream=bootstrap"
    )
    assert status == 200 and len(log) == 64 * 1024
    normal_app.close()


def test_non_campaign_directories_do_not_consume_campaign_scan_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaign_index

    app = _app(tmp_path)
    engineering = app.results_root / "engineering"
    engineering.mkdir()
    for index in range(4):
        (engineering / f"junk-{index}").mkdir()
    monkeypatch.setattr(campaign_index, "_MAX_DIRECTORY_ENTRIES", 3)

    status, _, body = app.handle("GET", "/jobs")
    text = body.decode("utf-8")
    assert status == 200 and "All (<span class='chip-count'>0</span>)" in text
    assert "scan stopped" not in text
    app.close()


def test_external_campaign_marker_scan_cap_is_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from experiments.rig_web_app import campaigns as campaign_index

    app = _app(tmp_path)
    engineering = app.results_root / "engineering"
    engineering.mkdir()
    for index in range(4):
        campaign_id = f"campaign-cap-{index}"
        directory = engineering / campaign_id
        directory.mkdir()
        started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (directory / "ENGINEERING_ONLY.json").write_text(
            json.dumps({
                "schema": "ura-engineering-campaign/1",
                "campaign_id": campaign_id,
                "release_commit": "a" * 40,
                "evidence_class": "engineering_stress",
                "thesis_empirical_evidence": False,
                "hosted_calls_allowed": False,
                "started_at": started_at,
            }),
            encoding="utf-8",
        )
        (directory / "task-log.jsonl").write_text(
            "\n".join((
                json.dumps({
                    "at": started_at,
                    "event": "campaign_start",
                    "task": "bootstrap",
                    "status": "running",
                    "detail": campaign_id,
                }),
                json.dumps({
                    "at": started_at,
                    "event": "campaign_end",
                    "task": "bootstrap",
                    "status": "passed",
                    "detail": campaign_id,
                }),
            ))
            + "\n",
            encoding="utf-8",
        )
    monkeypatch.setattr(campaign_index, "_MAX_DIRECTORY_ENTRIES", 3)

    status, _, body = app.handle("GET", "/jobs")
    text = body.decode("utf-8")
    assert status == 200 and "All (<span class='chip-count'>3</span>)" in text
    assert "scan stopped after 3 validated campaign markers" in text
    assert "later matching campaigns were not inspected" in text
    app.close()


def test_dashboard_lists_external_indeterminate_and_failed_campaigns(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    campaign = _write_external_engineering_campaign(app.results_root)
    marker_path = campaign / "ENGINEERING_ONLY.json"
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["campaign_id"] = "<img src=x onerror=alert(1)>"
    marker["planned_tasks"] = [
        "download-model", "optional-probe", "never-started",
    ]
    marker_path.write_text(json.dumps(marker), encoding="utf-8")

    status, _, body = app.handle("GET", "/")
    running = body.decode("utf-8")
    assert status == 200
    assert "jobs (console + external)" in running
    assert running.count(
        "<span class='value'><span class='dot blue'></span>0</span>"
    ) == 2
    assert running.count(
        "<span class='value'><span class='dot red'></span>0</span>"
    ) == 2
    assert "<span class='value'><span class='dot amber'></span>1</span>" in running
    assert "running (external task-log report)" in running
    assert "External running state is a task-log report" not in running
    assert "Needs attention" in running and "external, unknown" in running
    assert "/jobs/campaign/local-only-20260817T000000Z" in running
    assert "<img src=x onerror=alert(1)>" not in running
    assert "&lt;img src=x onerror=alert(1)&gt;" in running

    with (campaign / "stage2-task-log.jsonl").open("a", encoding="utf-8") as handle:
        for event in (
            {
                "at": "2026-08-17T00:00:03Z", "event": "task_end",
                "task": "download-model", "status": "passed", "detail": "done",
            },
            {
                "at": "2026-08-17T00:00:04Z", "event": "task_end",
                "task": "optional-probe", "status": "failed", "detail": "optional",
            },
            {
                "at": "2026-08-17T00:01:00Z", "event": "campaign_stop",
                "task": "stage2", "status": "blocked", "detail": "wrong_release",
            },
        ):
            handle.write(json.dumps(event) + "\n")
    status, _, body = app.handle("GET", "/")
    failed = body.decode("utf-8")
    assert status == 200
    assert "<span class='value'><span class='dot blue'></span>0</span>" in failed
    assert "<span class='value'><span class='dot red'></span>1</span>" in failed
    assert "Needs attention" in failed and "external, blocked" in failed
    assert "wrong_release" in failed
    assert "/jobs/campaign/local-only-20260817T000000Z" in failed
    assert "/jobs/campaign/local-only-20260817T000000Z/stop" not in failed
    assert "setTimeout(function(){location.reload();}, 10000);" not in failed

    status, _, body = app.handle("GET", "/jobs")
    jobs = body.decode("utf-8")
    assert status == 200 and "Blocked (<span class='chip-count'>1</span>)" in jobs
    assert "<span class='badge red'>blocked</span>" in jobs
    assert "(last recorded)" not in jobs
    assert "task processes: 1 succeeded; 1 failed; 0 skipped; 0 active" in jobs
    assert "pending: 1" in jobs
    assert "campaign terminal: blocked - wrong_release" in jobs

    observed = app._engineering_campaign("local-only-20260817T000000Z")
    assert observed is not None
    assert observed.state == "failed" and observed.display_state == "blocked"
    assert observed.state_detail == "wrong_release"
    assert observed.pending_tasks == 1
    app.close()


def test_dashboard_samples_each_console_job_state_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)

    class FlippingJob:
        job_id = "flipping-job"
        command = "webui_selftest"
        started_at = 1.0
        calls = 0

        def state(self) -> str:
            self.calls += 1
            return "running" if self.calls == 1 else "failed"

        @staticmethod
        def runtime_seconds() -> float:
            return 1.0

    job = FlippingJob()
    app.jobs[job.job_id] = job  # type: ignore[assignment]
    monkeypatch.setattr(app, "_reconcile", lambda: None)
    status, _, body = app.handle("GET", "/")
    text = body.decode("utf-8")
    assert status == 200 and job.calls == 1
    assert "running (console-owned)" in text and "flipping-job" in text
    assert "Needs attention" not in text
    app.jobs.clear()
    app.close()


def test_dashboard_surfaces_indeterminate_console_jobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)

    class RestoredJob:
        command = "run_matrix"
        started_at = 1.0

        def __init__(self, job_id: str, restored_state: str) -> None:
            self.job_id = job_id
            self.restored_state = restored_state

        def state(self) -> str:
            return self.restored_state

        @staticmethod
        def runtime_seconds() -> float:
            return 1.0

    for state in ("orphaned", "unknown"):
        job = RestoredJob(f"console-{state}", state)
        app.jobs[job.job_id] = job  # type: ignore[assignment]
    monkeypatch.setattr(app, "_reconcile", lambda: None)
    text = app.handle("GET", "/")[2].decode("utf-8")
    assert "orphaned / unknown" in text
    assert "Needs attention" in text
    assert "console-orphaned" in text and "console-unknown" in text
    assert "<span class='badge amber'>orphaned</span>" in text
    assert "<span class='badge amber'>unknown</span>" in text
    app.jobs.clear()
    app.close()


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
    assert "<select name='--sampling-policy'>" in page
    assert f"<option value='{DEFAULT_SAMPLING_POLICY}'>" in page
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
    assert run_kind("run_matrix", ["--preflight-only"]) == "preflight"
    assert run_kind(
        "run_matrix", ["--preflight-only", "--model-acquisition-plan-only"]
    ) == "acquisition_plan"
    assert run_kind(
        "run_matrix", ["--diagnostic-canary", "--dry-run"]
    ) == "dry_run"
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
    assert status == 200 and b"Model campaign runs" in body


def test_stats_corrects_stale_no_call_run_kind_from_persisted_argv(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    job = Job(
        job_id="dry-diagnostic",
        command="run_matrix",
        argv=["--diagnostic-canary", "--dry-run", "--out", "runs/dry"],
        directory=tmp_path / "dry-diagnostic",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[job.job_id] = job
    assert app.db.record_terminal(
        job,
        "a" * 40,
        [],
        state="complete",
        exit_code=0,
    )
    # Simulate a row written before no-call precedence was corrected. The Jobs
    # argv remains the authoritative operational classification source.
    with sqlite3.connect(app.state_dir / "console.db") as conn:
        conn.execute(
            "UPDATE runs SET kind='diagnostic_canary' WHERE job_id=?",
            (job.job_id,),
        )

    text = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "offline dry run - no model call" in text
    assert "diagnostic model-capable run" not in text
    assert "Passed means the CLI exited with status 0" in text
    app.close()


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
    # The Builder's run_matrix surface is one-to-one with the real parser: no
    # phantom UI flag (the old --models bug) and no missing CLI option. --help
    # is the only exclusion. rig_check forwards the same parser but always adds
    # --preflight-only, so its generic form omits the standalone-dry-only row
    # exclusion that can never be valid there.
    from experiments.rig_web import COMMANDS

    real = _parser_options(run_matrix.build_parser()) - {"--help"}
    ui = {param.flag for param in _MATRIX_PARAMS}
    assert ui - real == set(), f"UI flags absent from run_matrix: {ui - real}"
    assert real - ui == set(), f"run_matrix flags absent from the UI: {real - ui}"
    rig_check_ui = {param.flag for param in COMMANDS["rig_check"].params}
    assert rig_check_ui == ui - {"--exclude-tool-conditioned"}


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
        "rig_check": [],  # forwards the valid preflight subset (asserted above)
        "run_matrix": [{
            "--dry-run": "on", "--corpora": "synth", "--attackers": "replay",
            "--judges": "rules", "--judge-model": "mock", "--limit": "2",
            "--approximate-common-metrics": "on",
            "--sample-seed": "0", "--seeds": "0", "--max-queries": "1",
            "--max-turns": "1", "--group": "model,source",
            "--target-answer-retries": "1",
            "--recovery-completed-prefix": "runs/recovery-prefix.json",
            "--recovery-completed-prefix-sha256": "9" * 64,
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
             "--acknowledge-sensitive-content": "on"},
            {"--results": "runs/a", "--labels": "runs/a/exploratory.csv",
             "--allow-single-rater": "on",
             "--output": "runs/analysis/exploratory.json"},
            {"--results": "runs/a", "--labels": "runs/a/labels.csv",
             "--prepared-rating-form": "runs/prepared/common.csv",
             "--prepared-rating-form-sha256": "a" * 64,
             "--output": "runs/analysis/human_audit.json",
             "--bootstrap-resamples": "100", "--alpha": "0.05", "--seed": "0"},
            {"--results": "runs/a", "--prepare-source-task": "10",
             "--acknowledge-sensitive-content": "on",
             "--output": "runs/a/source-task.csv"},
            {"--results": "runs/a", "--source-task-labels": "runs/a/s.csv",
             "--prepared-rating-form": "runs/prepared/source.csv",
             "--prepared-rating-form-sha256": "b" * 64,
             "--output": "runs/analysis/source_task_audit.json"},
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
        "export_aggregators": [{"--source": "all", "--out-root": "runs/corpora"}],
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
        "local_model_readiness": [{
            "--validate": "runs/readiness.json",
            "--sha256": "a" * 64,
            "--expected-spec": "vllm:org/model",
        }],
        "hosted_campaign_budget": [{
            "--api-config": "experiments/api.json",
            "--api-config-sha256": "a" * 64,
            "--pricing-config": "experiments/pricing.json",
            "--pricing-config-sha256": "b" * 64,
            "--budgets": "runs/budgets.json",
            "--budgets-sha256": "c" * 64,
            "--pricing-as-of": "2026-09-04",
            "--out": "runs/hosted-budget.json",
        }],
        "retained_response_judge_pair": [{
            "--local-runner-view": "runs/local",
            "--hosted-runner-view": "runs/hosted",
            "--source-receipt": "runs/source.json",
            "--source-receipt-sha256": "a" * 64,
            "--judge-model": "anthropic:claude-haiku-fixture",
            "--api-config-sha256": "b" * 64,
            "--pricing-config": "experiments/pricing.json",
            "--pricing-config-sha256": "c" * 64,
            "--pricing-as-of": "2026-09-04",
            "--pair-limit": "10",
            "--sample-seed": "0",
            "--max-cost-microusd": "1000000",
            "--ack-hosted-judge-data-transfer": "on",
            "--out": "runs/judge-pair-plan.json",
        }],
        "retained_response_judge_pair_execute": [{
            "--plan": "runs/judge-pair-plan.json",
            "--local-runner-view": "runs/local",
            "--hosted-runner-view": "runs/hosted",
            "--source-receipt": "runs/source.json",
            "--api-config": "experiments/api.json",
            "--pricing-config": "experiments/pricing.json",
            "--out": "runs/judge-pair-results",
            "--ack-paid-execution": "on",
        }],
        "webui_selftest": [{"--selftest-sleep": "0"}],
    }
    # Typed controller commands with dedicated workflows; never generic forms.
    internal = {"model_acquire", "ollama_pull"}
    assert set(forms) == set(COMMANDS) - internal, (
        sorted(set(forms) ^ (set(COMMANDS) - internal))
    )
    for name, entry in COMMANDS.items():
        if name in internal:
            continue
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


def test_human_audit_ui_matches_exploratory_and_bound_analysis_contract() -> None:
    labels = {
        "--results": "runs/runner-view",
        "--labels": "runs/labels/common.csv",
        "--output": "runs/analysis/human_audit.json",
    }
    exploratory = build_argv(
        "human_audit", {**labels, "--allow-single-rater": "on"}
    )
    assert "--allow-single-rater" in exploratory
    assert "--prepared-rating-form" not in exploratory
    with pytest.raises(ValueError, match="64 lowercase hex"):
        build_argv(
            "human_audit",
            {
                **labels,
                "--prepared-rating-form": "runs/prepared/common.csv",
                "--prepared-rating-form-sha256": "ABC",
            },
        )

    argv = build_argv(
        "human_audit",
        {
            **labels,
            "--prepared-rating-form": "runs/prepared/common.csv",
            "--prepared-rating-form-sha256": "a" * 64,
        },
    )
    assert "--allow-single-rater" not in argv
    assert argv[-6:] == [
        "--prepared-rating-form",
        "runs/prepared/common.csv",
        "--prepared-rating-form-sha256",
        "a" * 64,
        "--output",
        "runs/analysis/human_audit.json",
    ]

    preparation = {
        "--results": "runs/runner-view",
        "--prepare": "20",
        "--acknowledge-sensitive-content": "on",
    }
    preparation_argv = build_argv("human_audit", preparation)
    assert "--output" not in preparation_argv
    for flag, value in (
        ("--allow-single-rater", "on"),
        ("--bootstrap-resamples", "100"),
        ("--alpha", "0.05"),
        ("--seed", "0"),
    ):
        with pytest.raises(ValueError, match="deterministic and seedless"):
            build_argv("human_audit", {**preparation, flag: value})

    with pytest.raises(ValueError, match="explicit external --output"):
        build_argv(
            "human_audit",
            {"--results": "runs/runner-view", "--labels": "runs/labels.csv"},
        )
    with pytest.raises(ValueError, match="must be provided together"):
        build_argv(
            "human_audit",
            {
                **labels,
                "--prepared-rating-form": "runs/prepared/common.csv",
            },
        )


def test_human_audit_command_form_hides_analysis_controls_during_preparation(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        page = app._commands_page().decode("utf-8")
    finally:
        app.close()
    marker = "<input type='hidden' name='command' value='human_audit'>"
    marker_at = page.index(marker)
    card = page[page.rfind("<details", 0, marker_at):page.index("</details>", marker_at)]
    for flag in (
        "--prepared-rating-form",
        "--prepared-rating-form-sha256",
        "--bootstrap-resamples",
        "--alpha",
        "--seed",
        "--allow-single-rater",
    ):
        opening = _opening_tag(card, f"name='{flag}'")
        input_at = card.index(opening)
        field = card[card.rfind("<label", 0, input_at):input_at + len(opening)]
        assert "data-human-audit-scope='analysis'" in field
    assert "function syncHumanAudit(form)" in page
    assert "control.disabled=!visible" in page


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
            "--target-answer-retries", "0",
            "--out", str(tmp_path / "dry"),
    ]) == 0


def _sealed_web_model_acquisition_args(
    tmp_path: Path,
    planned_args: list[str],
) -> list[str]:
    """Build one exact offline managed-model receipt for a Web fixture."""

    plan_directory = (tmp_path / "plans").resolve()
    plan_directory.mkdir(parents=True)
    assert run_matrix.main([
        *planned_args,
        "--model-acquisition-plan-only",
        "--model-acquisition-plan-dir",
        str(plan_directory),
    ]) == 0
    plan_path = next(plan_directory.glob("*.plan.json"))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    store = (tmp_path / "store").resolve()
    store.mkdir()
    snapshots: dict[str, Path] = {}
    manifests: dict[str, dict[str, object]] = {}
    for index, resource in enumerate(plan["resources"]):
        resource_root = store / resource["resource_id"]
        snapshot = resource_root / "snapshot"
        snapshot.mkdir(parents=True)
        content = (
            json.dumps(
                {
                    "fixture": index,
                    "repo": resource["repo_id"],
                    "revision": resource["revision"],
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        (snapshot / "config.json").write_bytes(content)
        blob_id = hashlib.sha1(  # noqa: S324 - Git protocol blob identity
            f"blob {len(content)}\0".encode("ascii") + content
        ).hexdigest()
        manifest = build_upstream_manifest(
            resource["repo_id"],
            resource["revision"],
            [{
                "path": "config.json",
                "size": len(content),
                "blob_id": blob_id,
                "lfs_sha256": None,
            }],
        )
        write_document_create_only(
            resource_root.resolve(),
            manifest,
            identifier=manifest["manifest_id"],
            suffix="upstream-manifest.json",
        )
        snapshots[resource["resource_id"]] = snapshot
        manifests[resource["resource_id"]] = manifest
    receipt = build_model_acquisition_receipt(
        plan,
        snapshots=snapshots,
        manifests=manifests,
    )
    receipt_path, receipt_sha = write_document_create_only(
        (tmp_path / "receipts").resolve(),
        receipt,
        identifier=receipt["receipt_id"],
        suffix="receipt.json",
    )
    return [
        "--model-acquisition-plan",
        str(plan_path),
        "--model-acquisition-plan-sha256",
        hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        "--model-acquisition-receipt",
        str(receipt_path),
        "--model-acquisition-receipt-sha256",
        receipt_sha,
        "--model-acquisition-store",
        str(store),
    ]


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
    readiness = tmp_path / "fixture.readiness.json"
    readiness.write_text("{}\n", encoding="utf-8")
    profile_registry = tmp_path / "local-model-profiles.json"
    profile_registry.write_text(json.dumps({
        "schema": "ura-local-model-execution-profiles/3",
        "models": {spec: {
            "generation_tokens": 64,
            "identity": {"revision": local_revision},
            "local_execution": {
                "gpu_memory_utilization": 0.5,
                "max_model_len": -1,
                "tensor_parallel_size": 1,
            },
            "modalities": ["text"],
            "readiness": {
                "path": str(readiness.resolve()),
                "sha256": "c" * 64,
                "readiness_id": "d" * 64,
            },
            "request_timeout_seconds": 120.0,
        }},
    }), encoding="utf-8")
    monkeypatch.setenv("URA_LOCAL_MODEL_PROFILE_REGISTRY", str(profile_registry))
    monkeypatch.setattr(
        run_matrix, "build_target", lambda *_a, **_kw: _StableLocalTarget()
    )
    probe_root = tmp_path / "probe"
    probe_args = [
        "--local", spec, "--local-config", str(local_config),
        "--attackers", "replay", "--judges", "rules", "--corpora", "synth",
        "--limit", "1", "--max-queries", "1", "--max-turns", "1",
        "--max-total-target-calls", "100000",
        "--max-total-judge-calls", "100000",
        "--max-total-http-attempts", "100000", "--deadline-seconds", "3600",
        *project_revision_args,
        "--attestation-probe", "--execution-scope-id", "webtest-scope",
        "--out", str(probe_root),
    ]
    acquisition_args = _sealed_web_model_acquisition_args(
        tmp_path / "probe-model-acquisition",
        probe_args,
    )
    assert run_matrix.main([*probe_args, *acquisition_args]) == 0
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


def test_usage_index_rejects_duplicate_marker_and_response_fields(
    tmp_path: Path,
) -> None:
    duplicate_marker = _write_marker_fixture(tmp_path / "marker", stem="ambiguous")
    marker_raw = duplicate_marker.read_text(encoding="utf-8")
    marker_field = '"status": "complete"'
    assert marker_raw.count(marker_field) == 1
    duplicate_marker.write_text(
        marker_raw.replace(
            marker_field,
            '"status": "error", ' + marker_field,
            1,
        ),
        encoding="utf-8",
    )
    rows, stats = collect_usage(duplicate_marker.parent, verify_sha=True)
    assert rows == []
    assert stats["markers"] == 0
    assert stats["skipped_invalid"] == 1

    duplicate_response = _write_marker_fixture(
        tmp_path / "response", stem="ambiguous"
    )
    response_path = duplicate_response.parent / "ambiguous.responses.jsonl"
    response_raw = response_path.read_text(encoding="utf-8")
    response_field = '"resolved_model": "claude-fable-5"'
    assert response_raw.count(response_field) == 2
    response_path.write_text(
        response_raw.replace(
            response_field,
            '"resolved_model": "invented", ' + response_field,
            1,
        ),
        encoding="utf-8",
    )
    marker_doc = json.loads(duplicate_response.read_text(encoding="utf-8"))
    marker_doc["artifacts"]["responses"] = _artifact_descriptor(response_path)
    duplicate_response.write_text(json.dumps(marker_doc), encoding="utf-8")

    rows, stats = collect_usage(duplicate_response.parent, verify_sha=True)
    assert rows == []
    assert stats["markers"] == 1
    assert stats["unreadable_artifacts"] == 1


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


@pytest.mark.parametrize(
    ("alias", "canonical"),
    (
        ("zhipu", "glm"),
        ("moonshot", "kimi"),
        ("dashscope", "qwen"),
        ("alibaba", "qwen"),
        ("bytedance", "doubao"),
    ),
)
def test_provider_alias_usage_and_cost_are_canonicalized(
    alias: str, canonical: str,
) -> None:
    pricing = {"providers": {canonical: {"models": {"served-model": {"rates": [{
        "effective_date": "2026-01-01",
        "currency": "USD",
        "per_million_tokens": {"input": 1.0, "output": 2.0},
    }]}}}}}
    assert _response_identity({
        "target": f"{alias}:requested",
        "raw": {"provider": alias, "resolved_model": "served-model"},
    }) == (canonical, "served-model")
    judged = _judge_row_usage({
        "raw": {
            "judge_model": f"{alias}:requested",
            "judge_call": {
                "provider": alias,
                "provider_resolved_model": "served-model",
                "tokens": {"input": 1_000_000, "output": 1_000_000},
            },
        },
    })
    assert judged is not None and judged[:2] == (canonical, "served-model")
    rows = compute_costs({
        ("target", alias, "served-model", "2026-08-18"): {
            "calls": 1, "input": 1_000_000, "output": 1_000_000,
        },
        ("judge", alias, "served-model", "2026-08-18"): {
            "calls": 1, "input": 1_000_000, "output": 1_000_000,
        },
    }, pricing)
    assert {row["provider"] for row in rows} == {canonical}
    assert all(row["cost"] == pytest.approx(3.0) for row in rows)


def test_overview_never_fabricates_or_cross_sums_currency_spend(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    base = {
        "role": "target", "provider": "fixture", "model": "m",
        "billable": True, "missing": [], "cost": 1.0,
    }
    try:
        app._usage_cost_rows = lambda: ([], "")
        empty = app._overview().decode("utf-8")
        assert "no recorded billable usage" in empty
        assert "$0.0000" not in empty

        app._usage_cost_rows = lambda: ([{
            **base, "currency": "EUR", "by_currency": {"EUR": 2.0},
            "cost": 2.0,
        }], "")
        single = app._overview().decode("utf-8")
        assert "EUR 2.0000" in single
        assert "$2.0000" not in single

        app._usage_cost_rows = lambda: ([
            {**base, "currency": "USD", "by_currency": {"USD": 1.0}},
            {**base, "currency": "EUR", "by_currency": {"EUR": 2.0}, "cost": 2.0},
        ], "")
        mixed = app._overview().decode("utf-8")
        assert "mixed currencies; not summed" in mixed
        assert "$1.0000" in mixed and "EUR 2.0000" in mixed
        assert "$3.0000" not in mixed
    finally:
        app.close()


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
    lane = app.results_root / "lane"
    _write_marker_fixture(lane)
    job = Job(
        job_id="job-owned-reindex",
        command="run_matrix",
        argv=["--diagnostic-canary", "--out", str(lane)],
        directory=tmp_path / "job-owned-reindex",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[job.job_id] = job
    assert app.db.record_terminal(job, "a" * 40, [], state="complete", exit_code=0)
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
    job = Job(
        job_id="job-owned-budget",
        command="run_matrix",
        argv=["--diagnostic-canary", "--out", str(cell)],
        directory=tmp_path / "job-owned-budget",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[job.job_id] = job
    assert app.db.record_terminal(job, "a" * 40, [], state="complete", exit_code=0)
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
    assert health["healthy"] and health["schema_version"] == 4
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
    dashboard = app.handle("GET", "/")[2].decode("utf-8")
    assert "Needs attention" in dashboard and "job-v1" in dashboard
    assert "<span class='badge amber'>orphaned</span>" in dashboard
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
    grid_root = app.results_root / "thesis" / "grid"
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
    run_job = Job(
        job_id="job-level1-grid",
        command="run_matrix",
        argv=["--dry-run", "--corpora", "synth", "--out", str(grid_root)],
        directory=tmp_path / "job-level1-grid",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[run_job.job_id] = run_job
    assert app.db.record_terminal(
        run_job, "a" * 40, [], state="complete", exit_code=0,
    )
    analysis_job = Job(
        job_id="job-level1-analysis",
        command="level1_evidence",
        argv=[
            "--results", str(grid_root),
            "--out-json", str(level1_dir / "level1.json"),
        ],
        directory=tmp_path / "job-level1-analysis",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[analysis_job.job_id] = analysis_job
    assert app.db.upsert_job(analysis_job, state="complete", exit_code=0)
    status, _, body = app.handle(
        "GET", "/stats/job/job-level1-grid?fragment=1",
    )
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
    assert "badge red" in text and ">invalid</span>" in text
    assert "class='barchart'" not in text
    assert "badge blue'>measured" not in text
    app.close()


def test_stats_terminal_inventory_is_generic_and_data_driven(
    tmp_path: Path,
) -> None:
    keys = ["batch alpha:item-1", "batch beta:item-2"]
    document = {
        "schema": "example-campaign-terminal-inventory/3",
        "status": "complete_with_failures",
        "cohort_order": ["batch alpha", "batch beta"],
        "cohort_counts": {"batch alpha": 1, "batch beta": 1},
        "row_order": keys,
        "rows": [
            {
                "key": keys[0],
                "cohort": "batch alpha",
                "logical_id": "item-1",
                "terminal_state": "finished",
                "failure": False,
                "project_revision_stratum": "release-a",
                "source_conformance_stratum": "source-a",
                "evidence": {"artifact": "one"},
            },
            {
                "key": keys[1],
                "cohort": "batch beta",
                "logical_id": "item-2",
                "terminal_state": "ended with issue",
                "failure": True,
                "project_revision_stratum": "release-b",
                "source_conformance_stratum": "source-b",
                "evidence": {"artifact": "two"},
            },
        ],
        "failure_rows": [keys[1]],
        "project_revision_strata": {
            "release-a": [keys[0]],
            "release-b": [keys[1]],
        },
        "source_conformance_strata": {
            "source-a": [keys[0]],
            "source-b": [keys[1]],
        },
        "all_rows_terminal": True,
        "cross_revision_pooling_permitted": True,
        "cross_source_pooling_permitted": False,
        "accounting": {"target_calls": 2},
    }
    _validate_report_document("terminal_inventory", document)

    app = _app(tmp_path)
    report = app.results_root / "analysis" / "generic-terminal.json"
    report.parent.mkdir()
    report.write_text(json.dumps(document) + "\n", encoding="utf-8")
    try:
        card = app._stats_report_card(
            {
                "path": "analysis/generic-terminal.json",
                "display_name": "generic-terminal.json",
                "kind": "terminal_inventory",
            }
        )
    finally:
        app.close()
    assert "Campaign terminal rows" in card
    assert "batch alpha" in card and "batch beta" in card
    assert "finished" in card and "ended with issue" in card
    assert "release-a" in card and "source-b" in card
    assert "cross-revision pooling as <strong>permitted</strong>" in card
    assert "cross-source pooling as <strong>not permitted</strong>" in card
    assert card.count("class='barchart'") == 3
    assert "href='/artifacts?path=analysis/generic-terminal.json'" in card

    invalid = copy.deepcopy(document)
    invalid["cohort_counts"]["batch alpha"] = 2
    with pytest.raises(ValueError, match="cohort counts"):
        _validate_report_document("terminal_inventory", invalid)


def test_stats_never_indexes_last_wins_duplicate_report_authority(
    tmp_path: Path,
) -> None:
    """Outer-valid report IDs cannot bless ambiguous raw JSON fields."""

    app = _app(tmp_path)

    level1: dict[str, object] = {
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
            "judgment_records": {
                "unit": "judgment_record",
                "completed": 1,
                "evaluable": 1,
                "decided": 1,
                "abstained": 0,
                "non_evaluable": 0,
                "included": None,
            },
            "request_level_errors": {
                "unit": "request_error_artifact",
                "observed": 0,
            },
        },
    }
    material = json.dumps(
        level1,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    level1["evidence_id"] = "level1-" + hashlib.sha256(material).hexdigest()[:24]
    raw_level1 = json.dumps(level1, indent=2, sort_keys=True)
    status_field = '"status": "validated_unit_qualified_lifecycle_inventory"'
    assert raw_level1.count(status_field) == 1
    raw_level1 = raw_level1.replace(
        status_field,
        '"status": "unvalidated_stub",\n  ' + status_field,
        1,
    )
    # The vulnerable last-wins interpretation still has a valid content ID.
    _validate_report_document("level1", json.loads(raw_level1))

    row = {field: None for field in _LEVEL2_ROW_FIELDS}
    row.update({
        "run_id": "run-1",
        "corpus_arm": "arm",
        "model_spec": "api:model",
        "resolved_model": "model",
        "source": "source",
        "risk_category": "risk",
        "effective_modality": "text",
        "expected_behavior": "refuse",
        "attacker": "replay",
        "defense": "none",
        "semantic_family": "safety",
        "metric": "ASR",
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
    })
    level2: dict[str, object] = {
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
        level2,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    level2["report_id"] = "level2-" + hashlib.sha256(material).hexdigest()[:24]
    raw_level2 = json.dumps(level2, indent=2, sort_keys=True)
    authority_field = '"metric_authority": "authoritative_or_source_native"'
    assert raw_level2.count(authority_field) == 1
    raw_level2 = raw_level2.replace(
        authority_field,
        '"metric_authority": "supplementary_non_authoritative",\n        '
        + authority_field,
        1,
    )
    _validate_report_document("level2", json.loads(raw_level2))

    level1_path = app.results_root / "thesis" / "level1" / "ambiguous-level1.json"
    level2_path = app.results_root / "thesis" / "level2" / "ambiguous-level2.json"
    level1_path.parent.mkdir(parents=True)
    level2_path.parent.mkdir(parents=True)
    level1_path.write_text(raw_level1, encoding="utf-8")
    level2_path.write_text(raw_level2, encoding="utf-8")

    assert app._report_index() == []
    status, _, body = app.handle("GET", "/stats")
    text = body.decode("utf-8")
    assert status == 200
    assert "ambiguous-level1.json" not in text
    assert "ambiguous-level2.json" not in text
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


def test_level1_validation_separates_and_reconciles_proxy_counts() -> None:
    def document(*, proxy_decided: int) -> dict[str, object]:
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
                "judgment_records": {
                    "unit": "judgment_record",
                    "completed": 1,
                    "evaluable": 1,
                    "decided": 0,
                    "abstained": 1,
                    "non_evaluable": 0,
                    "included": None,
                },
                "approximate_proxy_judgment_records": {
                    "unit": "supplementary_approximate_judgment_record",
                    "evaluable": 1,
                    "decided": proxy_decided,
                    "abstained": 0,
                    "included": None,
                },
                "request_level_errors": {
                    "unit": "request_error_artifact",
                    "observed": 0,
                },
            },
            "planning_strata": [{
                "approximate_proxy_evaluable_judgment_records": 1,
                "approximate_proxy_decided_judgment_records": 1,
                "approximate_proxy_abstained_judgment_records": 0,
            }],
        }
        material = json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        result["evidence_id"] = "level1-" + hashlib.sha256(material).hexdigest()[:24]
        return result

    _validate_report_document("level1", document(proxy_decided=1))
    with pytest.raises(ValueError, match="proxy decision counts do not reconcile"):
        _validate_report_document("level1", document(proxy_decided=0))


def test_stats_renders_real_level2_report(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    # The Level-2 card renders the REAL producer's document from a measured
    # cohort (offline stable local target + probe + receipt + measured grid).
    receipt, sha = _probe_receipt(tmp_path, monkeypatch, project_revision_args)
    app = _app(tmp_path)
    root = app.results_root / "thesis" / "measured"
    measured_args = [
        "--local", "vllm:fixture/local-model",
        "--local-config", str(tmp_path / "local-targets.json"),
        "--attackers", "replay", "--judges", "rules", "--corpora", "synth",
        "--limit", "1", "--sample-seed", "0",
        "--max-queries", "1", "--max-turns", "1",
        "--max-total-target-calls", "100000",
        "--max-total-judge-calls", "100000",
        "--max-total-http-attempts", "100000", "--deadline-seconds", "3600",
        *project_revision_args,
        "--execution-scope-id", "webtest-scope",
        "--live-attestation", str(receipt),
        "--live-attestation-sha256", sha,
        "--live-attestation-max-age-hours", "1",
        "--out", str(root),
    ]
    acquisition_args = _sealed_web_model_acquisition_args(
        tmp_path / "measured-model-acquisition",
        measured_args,
    )
    assert run_matrix.main([*measured_args, *acquisition_args]) == 0
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
    run_job = Job(
        job_id="job-level2-grid",
        command="run_matrix",
        argv=[
            "--local", "vllm:fixture/local-model",
            "--corpora", "synth",
            "--out", str(root),
        ],
        directory=tmp_path / "job-level2-grid",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[run_job.job_id] = run_job
    assert app.db.record_terminal(
        run_job, "a" * 40, [], state="complete", exit_code=0,
    )
    analysis_job = Job(
        job_id="job-level2-analysis",
        command="level2_report",
        argv=[
            "--results", str(root),
            "--out-json", str(level2_dir / "level2.json"),
        ],
        directory=tmp_path / "job-level2-analysis",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[analysis_job.job_id] = analysis_job
    assert app.db.upsert_job(analysis_job, state="complete", exit_code=0)
    index = app.handle("GET", "/stats")[2].decode("utf-8")
    assert "class='barchart'" not in index
    status, _, body = app.handle(
        "GET", "/stats/job/job-level2-grid?fragment=1",
    )
    text = body.decode("utf-8")
    assert status == 200
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
        ({"sampling_policy": None}, "sampling policy is unsupported"),
        ({"sampling_policy": "unknown-policy"}, "sampling policy is unsupported"),
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
        "metric_authority": "authoritative_or_source_native",
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
    explicit_policy = {**row, "sampling_policy": SOURCE_ORDER_CLUSTER_PREFIX}
    _validate_report_document("level2", document(explicit_policy))
    row.update(mutation)
    with pytest.raises(ValueError, match=message):
        _validate_report_document("level2", document(row))


def test_level2_approximate_contract_is_strict_and_visibly_warned(
    tmp_path: Path,
) -> None:
    proxy = ApproximateMetricProvenance(
        warning_tag="warning_synthetic_approximate",
        evidence_class="synthetic",
        source_required_metric="fixture_source_metric",
        source_evaluator_implemented=False,
        supplementary_metric_policy=supplementary_metric_policy("synthetic"),
        declared_target_evidence_classes=["measured"],
        target_evidence_classes=["synthetic"],
        n_synthetic_response_decisions=0,
        reliability_score=0.08,
        reliability_mean=0.08,
        metric_name="ASR",
        n_supporting_decisions=1,
        result_count_unit="supporting_decision",
        n_result_units=1,
        contribution_role="selected",
        selected_judges=["rules"],
        judge_kinds=["rules"],
        judge_models=[],
        judge_model_identities=[],
        judge_model_identity_types=[],
        judge_identity_kinds=["not_applicable"],
        n_model_queried_decisions=0,
        evidence_scopes=["response_only"],
        n_source_reference_context_used=0,
        limitations=["fixture construct mismatch"],
    ).model_dump(mode="json")
    row = {field: None for field in _LEVEL2_ROW_FIELDS}
    row.update({
        "run_id": "run-1",
        "corpus_arm": "arm",
        "model_spec": "mock",
        "resolved_model": "mock",
        "source": "source",
        "risk_category": "risk",
        "effective_modality": "text",
        "expected_behavior": "refuse",
        "attacker": "replay",
        "defense": "none",
        "ordered_judges": ["rules"],
        "seeds": [0],
        "semantic_family": "approximate_unsafe_response_rate",
        "metric": "approximate_ASR",
        "endpoint_status": "approximate_common_proxy",
        "metric_authority": "supplementary_non_authoritative",
        "warning_tag": "warning_synthetic_approximate",
        "evidence_class": "synthetic",
        "reliability_score": 0.08,
        "reliability_kind": "uncalibrated_heuristic_indicator_not_probability",
        "approximate_provenance": proxy,
        "approximate_model_query_count": 0,
        "approximate_source_reference_use_count": 0,
        "polarity": "higher_adverse",
        "value": 0.5,
        "ci_low": 0.25,
        "ci_high": 0.75,
        "n_records": 1,
        "n_clusters": 1,
        "execution_modes": ["direct_prompt"],
        "judgments_completed": 1,
        "judgments_evaluable": 1,
        "judgments_decided": 1,
        "judgments_abstained": 0,
        "judgments_non_evaluable": 0,
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
            result,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        result["report_id"] = "level2-" + hashlib.sha256(material).hexdigest()[:24]
        return result

    valid = document(dict(row))
    _validate_report_document("level2", valid)
    app = _app(tmp_path)
    try:
        rendered = app._render_level2("approximate.json", valid)
    finally:
        app.close()
    assert "synthetic + approximate" in rendered
    assert "contains supplementary proxies" in rendered
    assert "heuristic (not probability)" in rendered

    for mutation in (
        {"warning_tag": None},
        {"evidence_class": "measured"},
        {"metric_authority": "authoritative_or_source_native"},
        {"approximate_provenance": {}},
        {"approximate_model_query_count": 1},
        {"approximate_source_reference_use_count": 1},
    ):
        invalid_row = {**row, **mutation}
        with pytest.raises(ValueError):
            _validate_report_document("level2", document(invalid_row))

    detached_support = copy.deepcopy(proxy)
    detached_support["n_supporting_decisions"] = 99
    with pytest.raises(ValueError, match="supporting decisions"):
        _validate_report_document(
            "level2",
            document({**row, "approximate_provenance": detached_support}),
        )


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


def test_http_rejects_duplicate_and_malformed_form_keys_before_dispatch(
    tmp_path: Path,
) -> None:
    from experiments.rig_web import _make_server

    app = _app(tmp_path)
    server = _make_server(app, "127.0.0.1", 0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for payload in (
            "confirm=yes&confirm=yes&launch_ticket=forged",
            "judge_model=openai%3Afirst&judge_model=vllm%3AC%3A%5Cprivate",
            "confirm=yes&bad%ZZ=value",
            "confirm=yes&bare-field",
        ):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            connection.request(
                "POST",
                "/build",
                body=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = connection.getresponse()
            body = response.read()
            connection.close()
            assert response.status == 400
            assert b"invalid or duplicate" in body
        assert app.jobs == {}
        assert app.db.health()["counts"]["jobs"] == 0
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
    app = _operator_registry_app(tmp_path)
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
    # synth and drops targets, and validation requires no arm selection.  Run
    # the exact source-config-bound argv emitted by the operator UI so the
    # offline LLM judge's planned/realized identity remains covered end to end.
    app = _operator_registry_app(tmp_path)
    form = {
        "mode": "diagnostic_canary", "canary_dry": "on", "attackers": "replay",
        "judges": "rules,llm", "judge_model": "anthropic:claude-opus-5",
        "limit": "1", "seeds": "0", "max_queries": "1", "max_turns": "1",
        "out": str(app.results_root / "c"),
        "api": "anthropic:claude-opus-5",  # should be dropped for a dry canary
    }
    assert app._validate_builder(form) == {}
    _cmd, values, _params = app._compose_from_builder(form)
    assert values["--corpora"] == "synth"
    assert "--api" not in values and values["--dry-run"] == "on"
    assert values["--judge-model"] == "mock"
    assert "--source-config" in values and "--source-config-sha256" in values
    argv = build_argv(_cmd, values)[3:]
    run_matrix.build_parser().parse_args(argv)
    assert run_matrix.main(argv) == 0
    app.close()


def test_builder_hosted_measured_requires_explicit_bounded_or_full_limit(
    tmp_path: Path, monkeypatch,
) -> None:
    # A blank paid limit is never silently expanded. An explicit 0 selects the
    # complete arm, but still passes through projection, cap and approval gates.
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
    blank = dict(base)
    blank.pop("sample_seed")
    assert "limit" in app._validate_builder(blank)
    assert "limit" in app._validate_builder({**base, "limit": "-1"})
    full = {**base, "limit": "0"}
    full.pop("sample_seed")
    full_errors = app._validate_builder(full)
    assert "limit" not in full_errors and "sample_seed" not in full_errors
    assert "limit" not in app._validate_builder({**base, "limit": "5"})
    app.close()


def test_builder_measured_argv_is_self_contained_from_env(
    tmp_path: Path, monkeypatch,
) -> None:
    # MED: a measured lane admitted via campaign-env receipts must compose
    # those receipts into the argv, so the retained "Exact command" reproduces
    # the same admission in a clean shell.
    project_receipt = tmp_path / "r.json"
    source_receipt = tmp_path / "s.json"
    project_receipt.write_text('{"schema":"fixture-project"}\n', encoding="utf-8")
    source_receipt.write_text('{"schema":"fixture-source"}\n', encoding="utf-8")
    project_sha = hashlib.sha256(project_receipt.read_bytes()).hexdigest()
    source_sha = hashlib.sha256(source_receipt.read_bytes()).hexdigest()
    monkeypatch.setenv("URA_PROJECT_REVISION_MANIFEST", str(project_receipt))
    monkeypatch.setenv("URA_PROJECT_REVISION_SHA256", project_sha)
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_MANIFEST", str(source_receipt))
    monkeypatch.setenv("URA_SOURCE_CONFORMANCE_SHA256", source_sha)
    app = _operator_registry_app(tmp_path)
    attestation_receipt = tmp_path / "a.json"
    attestation_receipt.write_text(
        '{"schema":"fixture-attestation"}\n', encoding="utf-8"
    )
    attestation_sha = hashlib.sha256(attestation_receipt.read_bytes()).hexdigest()
    _cmd, values, _params = app._compose_from_builder({
        "mode": "measured", "corpora": "strongreject_official",
        "api": "anthropic:claude-opus-5", "attackers": "replay",
        "judges": "rules", "out": "runs/m", "seeds": "0", "sample_seed": "0",
        "scope": "sc", "max_age": "24", "att_path1": str(attestation_receipt),
        "att_sha1": attestation_sha, "cap_target": "4", "cap_judge": "4",
        "cap_http": "12", "deadline": "600", "limit": "5",
    })
    private_project_receipt = Path(values["--project-revision"])
    assert private_project_receipt != project_receipt
    assert private_project_receipt.parent.name == ".private-project-revision"
    assert private_project_receipt.read_bytes() == project_receipt.read_bytes()
    assert values["--project-revision-sha256"] == project_sha
    private_source_receipt = Path(values["--source-conformance"])
    assert private_source_receipt != source_receipt
    assert private_source_receipt.parent.name == ".private-source-conformance"
    assert hashlib.sha256(private_source_receipt.read_bytes()).hexdigest() == source_sha
    assert values["--source-conformance-sha256"] == source_sha
    private_attestation = Path(values["--live-attestation#1"])
    assert private_attestation != attestation_receipt
    assert private_attestation.parent.name == ".private-live-attestations"
    assert private_attestation.read_bytes() == attestation_receipt.read_bytes()
    assert values["--live-attestation-sha256#1"] == attestation_sha
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
        ("sampling_policy", "seeded", "source-order"),
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
                f"POST /config HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
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
    # Reindex scans each exact recorded run out_dir (including an out-of-root
    # one), never the generic results root, so copied fixtures cannot leak in.
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
    restored = app.db.load_jobs()
    assert restored is not None and restored[0]["activity"] is None
    summary = app.reindex_all()
    assert summary["roots"] == 1
    totals = app.db.usage_totals()
    assert totals is not None
    assert any(k[:3] == ("target", "anthropic", "claude-fable-5") for k in totals)
    app.close()


def test_headless_reindex_and_usage_report_cli(tmp_path: Path, capsys) -> None:
    # The console's bookkeeping is reachable through the CLI too.
    from experiments import rig_web

    results = tmp_path / "runs"
    results.mkdir()
    lane = results / "lane"
    _write_marker_fixture(lane)
    state = tmp_path / "state"
    seeded = ConsoleDB(state / "console.db")
    owned = Job(
        job_id="job-headless-owned",
        command="run_matrix",
        argv=["--diagnostic-canary", "--out", str(lane)],
        directory=tmp_path / "job-headless-owned",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    assert seeded.record_terminal(
        owned, "a" * 40, [], state="complete", exit_code=0,
    )
    seeded.close()
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


def test_pricing_fetch_banner_reports_added_roster_models() -> None:
    summary = {
        "rates_written": 3,
        "models_added": [
            "anthropic:claude-opus-5",
            "anthropic:claude-sonnet-5",
            "openai:gpt-5.6-terra",
        ],
        "providers": {},
    }

    banner = RigWebApp._pricing_fetch_banner(json.dumps(summary))

    assert "3 rate(s) written" in banner
    assert "Added 3 missing current-roster model(s)" in banner


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
