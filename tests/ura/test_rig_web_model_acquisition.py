from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from experiments.model_acquire import ActivityReporter
from experiments.rig_web import Job, RigWebApp, build_argv, run_kind
from ura.model_acquisition import (
    build_plan,
    build_receipt,
    build_upstream_manifest,
    hub_requirement,
    write_document_create_only,
)


def _app(tmp_path: Path) -> RigWebApp:
    return RigWebApp(
        results_root=tmp_path / "runs",
        state_dir=tmp_path / "state",
        repo_root=Path(__file__).resolve().parents[2],
        gpu_hardware={"available": False, "gpu_count": 0, "gpus": []},
        system_hardware={"available": False},
        job_id_factory=iter((f"job-{index:04d}" for index in range(1, 100))).__next__,
    )


def test_build_modes_do_not_describe_local_inference_as_paid(tmp_path):
    app = _app(tmp_path)
    try:
        page = app._build_page().decode()
        assert "Attestation probe (one real call per model; usage baseline)" in page
        assert "Diagnostic canary (small live slice; observed usage only)" in page
        assert "Measured lane (real calls; produces campaign evidence)" in page
        assert "one paid call per model" not in page
        assert "small paid slice" not in page
        assert "Measured lane (paid;" not in page
    finally:
        app.close()


def test_local_matrix_child_preserves_profile_registry_and_blas_bound(tmp_path, monkeypatch):
    registry = tmp_path / "operator-local-model-profiles.json"
    monkeypatch.setenv("URA_LOCAL_MODEL_PROFILE_REGISTRY", str(registry))
    monkeypatch.setenv("OPENBLAS_NUM_THREADS", "2")
    monkeypatch.setenv("HF_TOKEN", "not-for-this-child")
    monkeypatch.setenv("OPENAI_API_KEY", "unselected-provider")
    app = _app(tmp_path)
    try:
        child = app._run_matrix_child_environment(
            {"--local": "vllm:Qwen/Qwen3-VL-8B-Instruct", "--corpora": "xstest_full"},
            scrub_receipt_env=False,
        )
        assert child["URA_LOCAL_MODEL_PROFILE_REGISTRY"] == str(registry)
        assert child["OPENBLAS_NUM_THREADS"] == "2"
        assert "HF_TOKEN" not in child
        assert "OPENAI_API_KEY" not in child
    finally:
        app.close()


def test_ui_acquisition_reuses_configured_store_without_redirecting_old_work(tmp_path, monkeypatch):
    installed = tmp_path / "installed-models"
    installed.mkdir()
    sentinel = installed / "existing-model.bin"
    sentinel.write_bytes(b"existing model content")
    monkeypatch.setenv("URA_MODEL_STORE", str(installed))
    app = _app(tmp_path)
    try:
        first = app._new_model_acquisition_workflow_paths("a" * 32)
        assert first["store"] == installed
        replacement = tmp_path / "other-installed-models"
        replacement.mkdir()
        monkeypatch.setenv("URA_MODEL_STORE", str(replacement))
        restored = app._new_model_acquisition_workflow_paths("a" * 32, restoring=True)
        assert restored["store"] == installed
        assert sentinel.read_bytes() == b"existing model content"
        fresh = app._new_model_acquisition_workflow_paths("b" * 32)
        assert fresh["store"] == replacement
        legacy = app._new_model_acquisition_workflow_paths("c" * 32, restoring=True)
        assert legacy["store"] == app.state_dir.resolve() / ".managed-model-store"
    finally:
        app.close()


@pytest.mark.parametrize("full_sha", [False, True])
def test_builder_full_model_sha_is_optional_and_composes_real_cli(tmp_path, full_sha):
    from experiments import model_acquire, run_matrix

    app = _app(tmp_path)
    try:
        form = {"mode": "dry_run", "corpora": "synth", "attackers": "replay",
                "judges": "rules", "out": "runs/sha-option"}
        if full_sha:
            form["verify_model_sha256"] = "on"
        command, values, params = app._compose_from_builder(form)
        argv = build_argv(command, values)
        assert ("--verify-model-sha256" in argv) is full_sha
        assert run_matrix.build_parser().parse_args(
            ["--verify-model-sha256"] if full_sha else []).verify_model_sha256 is full_sha
        assert model_acquire._parser().parse_args(
            ["--verify-model-sha256"] if full_sha else []).verify_model_sha256 is full_sha
        assert params.get("verify_model_sha256", "") == ("on" if full_sha else "")
        page = app._build_page(prefill=form).decode()
        assert ("name='verify_model_sha256' checked" in page) is full_sha
        assert "Full model SHA verification (slow, optional)" in page
        assert "Off by default" in page
    finally:
        app.close()


def _write_workflow_documents(
    workflow: dict[str, object],
) -> tuple[Path, Path]:
    revision = "a" * 40
    plan = build_plan(
        [hub_requirement("vllm_target", "Org/Fixture", revision)],
        bindings={"local_config_sha256": "b" * 64},
    )
    plan_path, _plan_sha = write_document_create_only(
        Path(workflow["plan_dir"]),
        plan,
        identifier=plan["plan_id"],
        suffix="plan.json",
    )
    return plan_path, _write_workflow_receipt(workflow, plan)


def _write_workflow_receipt(
    workflow: dict[str, object],
    plan: dict[str, object],
) -> Path:
    resource = plan["resources"][0]
    revision = str(resource["revision"])
    resource_root = Path(workflow["store"]) / resource["resource_id"]
    snapshot = resource_root / "snapshot"
    snapshot.mkdir(parents=True)
    content = b'{"model_type":"fixture"}\n'
    (snapshot / "config.json").write_bytes(content)
    blob_id = hashlib.sha1(  # noqa: S324 - Git protocol identity
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()
    manifest = build_upstream_manifest(
        str(resource["repo_id"]),
        revision,
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
    receipt = build_receipt(
        plan,
        snapshots={resource["resource_id"]: snapshot},
        manifests={resource["resource_id"]: manifest},
    )
    receipt_path, _receipt_sha = write_document_create_only(
        Path(workflow["receipts_dir"]),
        receipt,
        identifier=receipt["receipt_id"],
        suffix="receipt.json",
    )
    return receipt_path


def test_model_acquisition_is_controller_only_and_truthfully_classified(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        assert run_kind(
            "run_matrix",
            ["--preflight-only", "--model-acquisition-plan-only"],
        ) == "acquisition_plan"
        page = app.handle("GET", "/commands")[2].decode("utf-8")
        assert "name='command' value='model_acquire'" not in page
        rejected = app.handle(
            "POST",
            "/jobs",
            {"command": "model_acquire", "--plan": "private"},
        )
        assert rejected[0] == 400

        planning = Job(
            "plan-job",
            "run_matrix",
            ["python", "-m", "experiments.run_matrix", "--model-acquisition-plan-only"],
            tmp_path / "plan-job",
            process=None,
            restored_state="complete",
            restored_exit=0,
        )
        acquisition = Job(
            "acquire-job",
            "model_acquire",
            ["python", "-m", "experiments.model_acquire"],
            tmp_path / "acquire-job",
            process=None,
            restored_state="complete",
            restored_exit=0,
        )
        assert app._job_work_label(planning) == "acquisition plan"
        assert app._job_execution_label(planning) == "no model call"
        assert app._job_work_label(acquisition) == "model acquisition"
        assert app._job_execution_label(acquisition) == "no model call"
    finally:
        app.close()


def test_nanogcg_builder_allows_only_exact_precomputed_suffix_replay(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    try:
        replay = app._prepared_attacker_entries({
            "attackers": "nanogcg",
            "nanogcg_suffix": " !fixture!",
            "nanogcg_suffix_source": "retained-run:fixture",
        })
        assert replay == {
            "nanogcg": {
                "suffix": "!fixture!",
                "suffix_source": "retained-run:fixture",
            }
        }
        with pytest.raises(ValueError, match="live nanoGCG optimization is disabled"):
            app._prepared_attacker_entries({
                "attackers": "nanogcg",
                "nanogcg_model_id": "Org/Surrogate",
                "nanogcg_model_revision": "a" * 40,
                "nanogcg_suffix": "suffix",
                "nanogcg_suffix_source": "fixture",
            })
        with pytest.raises(ValueError, match="exact precomputed suffix"):
            app._prepared_attacker_entries({"attackers": "nanogcg"})
        page = app.handle("GET", "/build")[2].decode("utf-8")
        for field in ("nanogcg_suffix", "nanogcg_suffix_source"):
            assert f"name='{field}'" in page
        assert "name='nanogcg_model_id'" not in page
        assert "name='nanogcg_model_revision'" not in page
        assert "Live NanoGCG optimization is disabled" in page

        status, _content_type, body = app.handle(
            "POST",
            "/build",
            {
                "mode": "dry_run",
                "corpora": "synth",
                "attackers": "nanogcg",
                "judges": "rules",
                "out": "runs/nanogcg-live-must-not-launch",
                "nanogcg_model_id": "Org/Surrogate",
                "nanogcg_model_revision": "a" * 40,
            },
        )
        rendered = body.decode("utf-8")
        assert status == 200
        assert "live nanogcg optimization is disabled" in rendered.lower()
        assert app.jobs == {}
        assert not (app.state_dir / ".private-attacker-configs").exists()
    finally:
        app.close()


def test_acquisition_child_env_is_minimal_and_activity_is_authenticated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    token = "b" * 64
    event = (tmp_path / "state" / "private-activity.json").resolve()
    job = Job(
        "job-activity",
        "model_acquire",
        ["python", "-m", "experiments.model_acquire"],
        tmp_path / "state" / "job-activity",
        process=None,
        restored_state="running",
    )
    try:
        monkeypatch.setenv("HF_TOKEN", "hf-secret-fixture")
        monkeypatch.setenv("HUGGING_FACE_HUB_TOKEN", "must-not-forward")
        monkeypatch.setenv("OPENAI_API_KEY", "must-not-forward")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-forward")
        monkeypatch.setenv("HTTPS_PROXY", "must-not-forward")
        child = app._model_acquire_child_environment(activity_token=token)
        assert child["HF_TOKEN"] == "hf-secret-fixture"
        assert child["URA_MODEL_ACQUISITION_ACTIVITY_TOKEN"] == token
        for forbidden in (
            "HUGGING_FACE_HUB_TOKEN",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "HTTPS_PROXY",
        ):
            assert forbidden not in child

        app._model_acquisition_activity[job.job_id] = {
            "path": event,
            "sequence": 0,
            "token": token,
        }
        # A cache hit/import produces no event and therefore no badge.
        app._refresh_model_acquisition_activity(job)
        assert job.activity is None

        reporter = ActivityReporter(path=event, job_id=job.job_id, token=token)
        reporter(True)
        app._refresh_model_acquisition_activity(job)
        assert job.activity == "model_download"

        tampered = json.loads(event.read_text(encoding="utf-8"))
        tampered["activity"] = None
        event.write_text(json.dumps(tampered), encoding="utf-8")
        app._refresh_model_acquisition_activity(job)
        assert job.activity == "model_download"

        reporter(False)
        app._refresh_model_acquisition_activity(job)
        assert job.activity is None
        app._clear_model_acquisition_activity(job)
        assert not event.exists()
    finally:
        app.close()


def test_hf_token_is_write_only_and_presence_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    app.env_file = tmp_path / "secrets" / ".ura_env"
    token = "hf_private_fixture_1234567890"
    legacy_token = "hf_legacy_must_be_scrubbed"
    app.env_file.parent.mkdir(parents=True)
    app.env_file.write_text(
        "export OPENAI_API_KEY='keep-provider-key'\n"
        f"export HF_TOKEN='{legacy_token}'\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("HF_TOKEN", raising=False)
    try:
        assert app.set_secret("HF_TOKEN", token) is None
        persisted = app.env_file.read_text(encoding="utf-8")
        assert "OPENAI_API_KEY='keep-provider-key'" in persisted
        assert "HF_TOKEN" not in persisted
        assert token not in persisted
        assert legacy_token not in persisted
        row = next(
            item for item in app.secret_status() if item["name"] == "HF_TOKEN"
        )
        assert row["present"] is True
        assert row["hint"] == "set"
        page = app.handle("GET", "/config/secrets")[2].decode("utf-8")
        assert token not in page
        assert token[-4:] not in page
        assert "Hugging Face access is process-only" in page
        app.clear_secret("HF_TOKEN")
        assert "HF_TOKEN" not in os.environ
        assert "OPENAI_API_KEY='keep-provider-key'" in app.env_file.read_text(
            encoding="utf-8"
        )
    finally:
        monkeypatch.delenv("HF_TOKEN", raising=False)
        app.close()


def test_private_acquisition_readers_reject_links_bounds_and_unresolved_paths(
    tmp_path: Path,
) -> None:
    app = _app(tmp_path)
    private = (tmp_path / "state" / "private-reader").resolve()
    private.mkdir()
    document = private / "event.json"
    document.write_bytes(b"{}")
    alias = private / "event-alias.json"
    os.link(document, alias)
    try:
        with pytest.raises(ValueError, match="bounded regular file"):
            app._bounded_private_bytes(
                document,
                max_bytes=16 * 1024,
                label="private event",
            )
        alias.unlink()
        document.write_bytes(b"x" * (16 * 1024 + 1))
        with pytest.raises(ValueError, match="bounded regular file"):
            app._bounded_private_bytes(
                document,
                max_bytes=16 * 1024,
                label="private event",
            )
        unresolved = tmp_path / "state" / ".." / "must-not-create"
        with pytest.raises(ValueError, match="already be a resolved path"):
            app._prepare_private_acquisition_directory(
                unresolved,
                label="private workflow",
            )
        assert not (tmp_path / "must-not-create").exists()
    finally:
        app.close()


def test_reviewed_builder_stage_creates_only_a_plan_job_before_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    captured: dict[str, object] = {}
    params = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "guardrail",
        "guardrail_model": "meta-llama/Llama-Guard-3-8B",
        "guardrail_revision": "c" * 40,
        "out": "runs/measured",
        "_model_acquisition_next": "preflight",
    }

    monkeypatch.setattr(app, "_validate_builder", lambda _params: {})

    def fake_start(command, values, *, builder_params=None, **kwargs):
        captured.update(
            command=command,
            values=dict(values),
            builder_params=dict(builder_params or {}),
            kwargs=kwargs,
        )
        job_id = str(kwargs["reserved_job_id"])
        return Job(
            job_id,
            command,
            build_argv(command, values),
            tmp_path / "state" / job_id,
            process=None,
            restored_state="running",
        )

    monkeypatch.setattr(app, "start_job", fake_start)
    try:
        job = app._start_model_acquisition_plan(params)
        assert job.job_id.startswith("job-")
        assert captured["command"] == "run_matrix"
        values = captured["values"]
        assert isinstance(values, dict)
        assert values["--model-acquisition-plan-only"] == "on"
        assert "--model-acquisition-binding-sha256" not in values
        assert values["--preflight-only"] == "on"
        assert "--model-acquisition-plan" not in values
        assert "--model-acquisition-receipt" not in values
        assert set(app._model_acquisition_workflows) == {job.job_id}
        assert build_argv("run_matrix", values)
    finally:
        app.close()


def test_measured_acquisition_plan_rechecks_exact_preflight_caps_before_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    starts: list[object] = []
    params = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "guardrail",
        "guardrail_model": "meta-llama/Llama-Guard-3-8B",
        "guardrail_revision": "c" * 40,
        "out": "runs/measured",
        "_model_acquisition_next": "run",
    }
    monkeypatch.setattr(app, "_validate_builder", lambda _params: {})
    monkeypatch.setattr(app, "_ceilings_card", lambda _params: ("", False))
    monkeypatch.setattr(
        app,
        "_materialize_prepared_attacker_config",
        lambda _params: pytest.fail("must reject before materialization"),
    )
    monkeypatch.setattr(
        app,
        "start_job",
        lambda *_args, **_kwargs: starts.append((_args, _kwargs)),
    )
    try:
        with pytest.raises(ValueError, match="call ceilings"):
            app._start_model_acquisition_plan(params)
        assert starts == []
        assert not (app.state_dir / ".private-model-acquisition").exists()
    finally:
        app.close()


def test_builder_hub_preflight_starts_plan_not_unreceipted_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(tmp_path)
    params = {
        "mode": "measured",
        "corpora": "synth",
        "attackers": "nanogcg",
        "judges": "rules",
        "out": "runs/preflight",
    }
    planned: list[dict[str, str]] = []
    direct_starts: list[object] = []
    monkeypatch.setattr(app, "_builder_params", lambda _data: dict(params))
    monkeypatch.setattr(app, "_runtime_builder_params", lambda value: dict(value))
    monkeypatch.setattr(app, "_validate_builder", lambda _params: {})
    monkeypatch.setattr(
        app,
        "_compose_from_builder",
        lambda value, **_kwargs: (
            "run_matrix",
            {"--out": value["out"]},
            dict(value),
        ),
    )
    monkeypatch.setattr(
        app,
        "_materialize_prepared_attacker_config",
        lambda _params, **_kwargs: None,
    )
    monkeypatch.setattr(
        app,
        "_builder_model_acquisition_required",
        lambda _params: True,
    )

    def fake_plan(value, **_kwargs):
        planned.append(dict(value))
        return Job(
            "job-plan",
            "run_matrix",
            ["python", "-m", "experiments.run_matrix"],
            tmp_path / "state" / "job-plan",
            process=None,
            restored_state="running",
        )

    monkeypatch.setattr(app, "_start_model_acquisition_plan", fake_plan)
    monkeypatch.setattr(
        app,
        "start_job",
        lambda *_args, **_kwargs: direct_starts.append((_args, _kwargs)),
    )
    try:
        status, location, _body = app.handle(
            "POST",
            "/build",
            {"preflight_only": "yes"},
        )
        assert (status, location) == (303, "/jobs/job-plan")
        assert planned == [{**params, "_model_acquisition_next": "preflight"}]
        assert direct_starts == []
    finally:
        app.close()


@pytest.mark.parametrize("full_sha", [False, True])
def test_reviewed_plan_download_and_receipted_run_are_one_shot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    full_sha: bool,
) -> None:
    app = _app(tmp_path)
    workflow_id = "f" * 32
    paths = app._new_model_acquisition_workflow_paths(workflow_id)
    params, snapshot, _snapshot_sha256 = app._capture_execution_config_snapshot({
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
        "out": "runs/measured",
        "campaign_id": "a" * 32,
        "verify_model_sha256": "on" if full_sha else "",
    })
    params = app._bind_execution_config_bundle_identity(params)
    bundle = params["_execution_config_bundle_sha256"]
    workflow: dict[str, object] = {
        "acquisition_job_id": "",
        "consumed": False,
        "execution_config_bundle_sha256": bundle,
        "execution_snapshot": snapshot,
        "next_stage": "run",
        "params": params,
        "workflow_id": workflow_id,
        **paths,
    }
    plan_path, receipt_path = _write_workflow_documents(workflow)
    plan_job = Job(
        "job-plan",
        "run_matrix",
        [
            "python",
            "-m",
            "experiments.run_matrix",
            "--model-acquisition-plan-only",
        ],
        tmp_path / "state" / "job-plan",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    app.jobs[plan_job.job_id] = plan_job
    workflow["plan_job_id"] = plan_job.job_id
    app._model_acquisition_workflows[plan_job.job_id] = workflow
    monkeypatch.setattr(app, "_validate_builder", lambda _params: {})
    monkeypatch.setattr(
        app,
        "_compose_from_builder",
        lambda params, **_kwargs: (
            "run_matrix",
            {"--out": "runs/measured"},
            dict(params),
        ),
    )
    monkeypatch.setattr(
        app,
        "_materialize_prepared_attacker_config",
        lambda _params, **_kwargs: None,
    )
    monkeypatch.setattr(app, "_ceilings_card", lambda _params: ("", True))
    launches: list[tuple[str, dict[str, str], dict[str, object]]] = []

    def fake_start(command, values, **kwargs):
        launches.append((command, dict(values), dict(kwargs)))
        job_id = str(kwargs.get("reserved_job_id") or "job-run")
        job = Job(
            job_id,
            command,
            build_argv(command, values),
            tmp_path / "state" / job_id,
            process=None,
            restored_state="complete",
            restored_exit=0,
        )
        app.jobs[job_id] = job
        return job

    monkeypatch.setattr(app, "start_job", fake_start)
    try:
        acquisition = app._start_model_acquisition_download(plan_job.job_id)
        assert launches[0][0] == "model_acquire"
        acquire_values = launches[0][1]
        assert (acquire_values.get("--verify-model-sha256") == "on") is full_sha
        assert acquire_values["--plan"] == str(plan_path)
        assert acquire_values["--activity-job-id"] == acquisition.job_id
        assert launches[0][2]["reserved_job_id"] == acquisition.job_id
        assert launches[0][2]["builder_params"]["campaign_id"] == "a" * 32
        assert "--receipt" not in acquire_values

        measured = app._start_model_acquisition_run(acquisition.job_id)
        assert measured.job_id == "job-run"
        run_values = launches[1][1]
        assert run_values["--model-acquisition-plan"] == str(plan_path)
        assert run_values["--model-acquisition-receipt"] == str(receipt_path)
        assert run_values["--model-acquisition-store"] == str(workflow["store"])
        assert "--model-acquisition-binding-sha256" not in run_values
        assert build_argv("run_matrix", run_values)
        assert workflow["consumed"] is True
        with pytest.raises(ValueError, match="unavailable"):
            app._start_model_acquisition_run(acquisition.job_id)
        assert len(launches) == 2
    finally:
        app.close()


def test_private_acquisition_workflow_recovers_activity_and_run_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed = tmp_path / "installed-models"
    installed.mkdir()
    monkeypatch.setenv("URA_MODEL_STORE", str(installed))
    app = _app(tmp_path)
    workflow_id = "e" * 32
    paths = app._new_model_acquisition_workflow_paths(workflow_id)
    params, snapshot, _snapshot_sha256 = app._capture_execution_config_snapshot({
        "mode": "measured",
        "corpora": "synth",
        "attackers": "replay",
        "judges": "rules",
        "out": "runs/restarted-measured",
    })
    params = app._bind_execution_config_bundle_identity(params)
    plan = build_plan(
        [hub_requirement("vllm_target", "Org/Fixture", "a" * 40)],
        bindings={"local_config_sha256": "b" * 64},
    )
    plan_path, _plan_sha = write_document_create_only(
        Path(paths["plan_dir"]),
        plan,
        identifier=plan["plan_id"],
        suffix="plan.json",
    )
    plan_job = Job(
        "job-restart-plan",
        "run_matrix",
        [
            "python",
            "-m",
            "experiments.run_matrix",
            "--model-acquisition-plan-only",
        ],
        tmp_path / "state" / "job-restart-plan",
        process=None,
        restored_state="complete",
        restored_exit=0,
    )
    acquisition_job = Job(
        "job-restart-acquire",
        "model_acquire",
        ["python", "-m", "experiments.model_acquire"],
        tmp_path / "state" / "job-restart-acquire",
        process=None,
        restored_state="running",
    )
    workflow: dict[str, object] = {
        "acquisition_job_id": acquisition_job.job_id,
        "consumed": False,
        "execution_config_bundle_sha256": params[
            "_execution_config_bundle_sha256"
        ],
        "execution_snapshot": snapshot,
        "next_stage": "run",
        "params": params,
        "plan_job_id": plan_job.job_id,
        "workflow_id": workflow_id,
        **paths,
    }
    token = "d" * 64
    app.jobs[plan_job.job_id] = plan_job
    app.jobs[acquisition_job.job_id] = acquisition_job
    app.db.upsert_job(plan_job, state="complete", exit_code=0)
    app.db.upsert_job(acquisition_job, state="running", exit_code=None)
    app._model_acquisition_workflows[plan_job.job_id] = workflow
    app._model_acquisition_workflows[acquisition_job.job_id] = workflow
    app._persist_model_acquisition_workflow(workflow)
    app._write_workflow_activity_token(workflow, token)
    reporter = ActivityReporter(
        path=paths["activity_event"],
        job_id=acquisition_job.job_id,
        token=token,
    )
    reporter(True)
    app.close()

    moved_environment = tmp_path / "later-model-store"
    moved_environment.mkdir()
    monkeypatch.setenv("URA_MODEL_STORE", str(moved_environment))
    restarted = _app(tmp_path)
    try:
        recovered = restarted.jobs[acquisition_job.job_id]
        assert recovered.state() == "orphaned"
        assert recovered.activity == "model_download"
        assert paths["activity_event"].exists()
        assert restarted._model_acquisition_workflows[acquisition_job.job_id]["store"] == installed
        assert restarted._workflow_execution_snapshot(
            restarted._model_acquisition_workflows[acquisition_job.job_id]
        ) == snapshot

        receipt_path = _write_workflow_receipt(
            restarted._model_acquisition_workflows[acquisition_job.job_id],
            plan,
        )
        restarted._reconcile()
        assert recovered.state() == "complete"
        assert recovered.activity is None
        assert not paths["activity_event"].exists()
        assert not (
            Path(paths["root"]) / "activity-token.txt"
        ).exists()

        monkeypatch.setattr(
            restarted,
            "_compose_from_builder",
            lambda value, **_kwargs: (
                "run_matrix",
                {"--out": "runs/restarted-measured"},
                dict(value),
            ),
        )
        monkeypatch.setattr(
            restarted,
            "_materialize_prepared_attacker_config",
            lambda _params, **_kwargs: None,
        )
        monkeypatch.setattr(restarted, "_ceilings_card", lambda _params: ("", True))

        def fake_start(command, values, **_kwargs):
            assert build_argv(command, values)
            return Job(
                "job-restarted-run",
                command,
                build_argv(command, values),
                tmp_path / "state" / "job-restarted-run",
                process=None,
                restored_state="complete",
                restored_exit=0,
            )

        monkeypatch.setattr(restarted, "start_job", fake_start)
        final = restarted._start_model_acquisition_run(acquisition_job.job_id)
        assert final.job_id == "job-restarted-run"
        assert receipt_path.exists() and plan_path.exists()
        assert restarted._model_acquisition_workflows[
            acquisition_job.job_id
        ]["consumed"] is True
    finally:
        restarted.close()

    final_restart = _app(tmp_path)
    try:
        restored_workflow = final_restart._model_acquisition_workflows[
            acquisition_job.job_id
        ]
        assert restored_workflow["consumed"] is True
        assert all(
            not Path(str(value)).is_absolute()
            for key, value in restored_workflow["params"].items()
            if key.startswith(("att_path", "project_revision", "source_conformance"))
        )
    finally:
        final_restart.close()


def test_acquisition_route_enforces_purpose_bound_one_shot_ticket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Route-level coverage of the sealed /build/model-acquisition/* gate: the
    # purpose-bound one-shot ticket, extra-field rejection, and per-stage
    # parameter check, none of which the internal-method tests exercise.
    app = _app(tmp_path)
    downloads: list[str] = []

    def fake_download(plan_job_id: str) -> Job:
        downloads.append(plan_job_id)
        job = Job(
            "job-acq",
            "model_acquire",
            ["python", "-m", "experiments.model_acquire"],
            tmp_path / "state" / "job-acq",
            process=None,
            restored_state="running",
        )
        app.jobs[job.job_id] = job
        return job

    monkeypatch.setattr(app, "_start_model_acquisition_download", fake_download)
    try:
        # A correct-purpose ticket with exactly {plan_job_id} launches once.
        ticket = app._new_launch_ticket(
            {"plan_job_id": "job-plan"}, purpose="acquisition_download"
        )
        status, location, _ = app.handle(
            "POST", "/build/model-acquisition/acquire", {"launch_ticket": ticket}
        )
        assert (status, location) == (303, "/jobs/job-acq")
        assert downloads == ["job-plan"]

        # The ticket is one-shot: replay is rejected without a second launch.
        replay_status, _replay_location, replay_body = app.handle(
            "POST", "/build/model-acquisition/acquire", {"launch_ticket": ticket}
        )
        assert replay_status == 200
        assert b"sealed acquisition authorization expired" in replay_body
        assert downloads == ["job-plan"]

        # A ticket minted for a different stage purpose is refused on /acquire.
        wrong_purpose = app._new_launch_ticket(
            {"acquisition_job_id": "job-acq"}, purpose="acquisition_run"
        )
        wrong_status, _wl, _wb = app.handle(
            "POST", "/build/model-acquisition/acquire",
            {"launch_ticket": wrong_purpose},
        )
        assert wrong_status == 200
        assert downloads == ["job-plan"]

        # Any extra form field burns the authorization instead of launching.
        extra_ticket = app._new_launch_ticket(
            {"plan_job_id": "job-plan"}, purpose="acquisition_download"
        )
        extra_status, _el, _eb = app.handle(
            "POST", "/build/model-acquisition/acquire",
            {"launch_ticket": extra_ticket, "smuggled": "1"},
        )
        assert extra_status == 200
        assert downloads == ["job-plan"]
    finally:
        app.close()
