from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import ura.model_acquisition as acquisition_module

from experiments.model_acquire import (
    ActivityReporter,
    HuggingFaceBackend,
    _ResourceLock,
    _safe_remove_partial,
    _safe_worker_environment,
    acquire,
    main as acquire_main,
    validate_activity_event,
)
from ura.model_acquisition import (
    MAX_DOCUMENT_BYTES,
    ModelAcquisitionError,
    build_plan,
    build_receipt,
    build_upstream_manifest,
    guardrail_requirement,
    hub_requirement,
    nanogcg_requirement,
    plan_sha256,
    validate_plan,
    validate_receipt,
    verify_receipt_snapshots,
    vllm_requirement,
    write_document_create_only,
    seal_snapshot,
)


REVISION = "a" * 40
BINDINGS = {
    "attacker_config_sha256": "b" * 64,
    "local_config_sha256": "c" * 64,
}


def _git_blob_id(content: bytes) -> str:
    return hashlib.sha1(  # noqa: S324 - this is Git's defined blob identifier
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()


def _fixture_plan() -> dict:
    return build_plan(
        [
            hub_requirement("vllm_target", "Org/Model", REVISION),
            hub_requirement("llm_judge", "Org/Model", REVISION),
        ],
        bindings=BINDINGS,
    )


def _fixture_snapshot(tmp_path: Path) -> tuple[dict, dict, Path, Path]:
    plan = _fixture_plan()
    resource = plan["resources"][0]
    resource_root = tmp_path / "store" / resource["resource_id"]
    snapshot = resource_root / "snapshot"
    snapshot.mkdir(parents=True)
    config = b'{"model_type":"fixture"}\n'
    weight = b"fixture-weights"
    (snapshot / "config.json").write_bytes(config)
    (snapshot / "model.safetensors").write_bytes(weight)
    manifest = build_upstream_manifest(
        "Org/Model",
        REVISION,
        [
            {
                "path": "config.json",
                "size": len(config),
                "blob_id": _git_blob_id(config),
                "lfs_sha256": None,
            },
            {
                "path": "model.safetensors",
                "size": len(weight),
                "blob_id": "d" * 40,
                "lfs_sha256": hashlib.sha256(weight).hexdigest(),
            },
        ],
    )
    write_document_create_only(
        resource_root.resolve(),
        manifest,
        identifier=manifest["manifest_id"],
        suffix="upstream-manifest.json",
    )
    return plan, manifest, snapshot, resource_root


def _manifest_files() -> tuple[dict, dict[str, bytes]]:
    files = {
        "config.json": b'{"model_type":"fixture"}\n',
        "weights/model.safetensors": b"fixture-weights",
    }
    manifest = build_upstream_manifest(
        "Org/Model",
        REVISION,
        [
            {
                "path": "config.json",
                "size": len(files["config.json"]),
                "blob_id": _git_blob_id(files["config.json"]),
                "lfs_sha256": None,
            },
            {
                "path": "weights/model.safetensors",
                "size": len(files["weights/model.safetensors"]),
                "blob_id": "d" * 40,
                "lfs_sha256": hashlib.sha256(
                    files["weights/model.safetensors"]
                ).hexdigest(),
            },
        ],
    )
    return manifest, files


@pytest.mark.parametrize(
    "filename",
    [
        "weights:model.bin",
        "CON",
        "aux.json",
        "folder/NUL.txt",
        "trailing-dot.",
        "trailing-space ",
        "question?.json",
    ],
)
def test_upstream_manifest_rejects_portably_invalid_filename(
    filename: str,
) -> None:
    with pytest.raises(ModelAcquisitionError, match="portable|invalid"):
        build_upstream_manifest(
            "Org/Model",
            REVISION,
            [{
                "path": filename,
                "size": 1,
                "blob_id": _git_blob_id(b"x"),
                "lfs_sha256": None,
            }],
        )


def test_upstream_manifest_rejects_casefold_path_collision() -> None:
    with pytest.raises(ModelAcquisitionError, match="portable path collision"):
        build_upstream_manifest(
            "Org/Model",
            REVISION,
            [
                {
                    "path": "Config.json",
                    "size": 1,
                    "blob_id": _git_blob_id(b"a"),
                    "lfs_sha256": None,
                },
                {
                    "path": "config.json",
                    "size": 1,
                    "blob_id": _git_blob_id(b"b"),
                    "lfs_sha256": None,
                },
            ],
        )


class _FakeBackend:
    def __init__(
        self,
        root: Path,
        *,
        cached: bool,
        fail_download: bool = False,
    ) -> None:
        self.root = root
        self.manifest, self.files = _manifest_files()
        self.cached = cached
        self.fail_download = fail_download
        self.download_calls: list[str] = []
        self.manifest_calls = 0
        for filename, content in self.files.items():
            path = self.root / "cache" / Path(*filename.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def fetch_manifest(self, repo_id, revision, *, deadline, cancelled):  # noqa: ANN001
        del deadline, cancelled
        self.manifest_calls += 1
        assert (repo_id, revision) == ("Org/Model", REVISION)
        return self.manifest

    def cached_file(self, repo_id, revision, filename):  # noqa: ANN001
        assert (repo_id, revision) == ("Org/Model", REVISION)
        if not self.cached:
            return None
        return self.root / "cache" / Path(*filename.split("/"))

    def download_file(
        self, repo_id, revision, filename, *, deadline, cancelled  # noqa: ANN001
    ):
        del deadline, cancelled
        assert (repo_id, revision) == ("Org/Model", REVISION)
        self.download_calls.append(filename)
        if self.fail_download:
            raise RuntimeError("injected download failure")
        return self.root / "cache" / Path(*filename.split("/"))


class _PartialCacheBackend(_FakeBackend):
    def cached_file(self, repo_id, revision, filename):  # noqa: ANN001
        assert (repo_id, revision) == ("Org/Model", REVISION)
        if filename == "config.json":
            return self.root / "cache" / "config.json"
        return None


def test_plan_merges_roles_and_binds_complete_repository_policy() -> None:
    plan = _fixture_plan()
    assert plan["resources"] == [
        {
            "file_policy": "complete_repository_snapshot",
            "repo_id": "Org/Model",
            "resource_id": plan["resources"][0]["resource_id"],
            "revision": REVISION,
            "roles": ["llm_judge", "vllm_target"],
        }
    ]
    assert validate_plan(plan) == plan
    assert len(plan_sha256(plan)) == 64


@pytest.mark.parametrize("revision", ["main", "abc1234", "A" * 40, "a" * 39])
def test_every_hub_consumer_rejects_a_non_exact_commit(revision: str) -> None:
    with pytest.raises(ModelAcquisitionError, match="40-64 lowercase hex"):
        hub_requirement("guardrail_judge", "Org/Model", revision)


def test_consumer_projection_covers_all_roles_and_real_exceptions() -> None:
    assert vllm_requirement(
        "vllm:Org/Target", REVISION, role="vllm_target"
    ).role == "vllm_target"
    assert vllm_requirement(
        "vllm:Org/Judge", REVISION, role="llm_judge"
    ).role == "llm_judge"
    assert (
        vllm_requirement(
            "vllm:C:/models/checkpoint",
            None,
            role="vllm_target",
            explicit_local_path=True,
        )
        is None
    )
    assert guardrail_requirement("Org/Guard", REVISION, defense=False).role == (
        "guardrail_judge"
    )
    assert guardrail_requirement("Org/Guard", REVISION, defense=True).role == (
        "defense_guardrail"
    )
    assert nanogcg_requirement(
        {"model_id": "Org/Surrogate", "model_revision": REVISION}
    ).role == "nanogcg_surrogate"
    assert nanogcg_requirement({"suffix": "already optimized"}) is None


@pytest.mark.parametrize(
    "repo_id",
    ["C:/models/checkpoint", "../Model", "https://huggingface.co/Org/Model", "Org\\Model"],
)
def test_guardrail_and_nanogcg_paths_cannot_bypass_hub_identity(repo_id: str) -> None:
    with pytest.raises(ModelAcquisitionError):
        guardrail_requirement(repo_id, REVISION, defense=False)


def test_receipt_round_trip_proves_full_manifest_and_cache_hit(tmp_path: Path) -> None:
    plan, manifest, snapshot, _resource_root = _fixture_snapshot(tmp_path)
    resource_id = plan["resources"][0]["resource_id"]
    receipt = build_receipt(
        plan,
        snapshots={resource_id: snapshot},
        manifests={resource_id: manifest},
        completed_at=dt.datetime(2026, 8, 18, tzinfo=dt.timezone.utc),
    )
    assert validate_receipt(receipt, plan=plan) == receipt
    resolved = verify_receipt_snapshots(
        plan,
        receipt,
        managed_store=(tmp_path / "store").resolve(),
    )
    assert resolved == {resource_id: snapshot.resolve()}
def test_partial_hf_cache_cannot_be_sealed_as_complete(tmp_path: Path) -> None:
    plan, manifest, snapshot, _resource_root = _fixture_snapshot(tmp_path)
    (snapshot / "model.safetensors").unlink()
    resource_id = plan["resources"][0]["resource_id"]
    with pytest.raises(ModelAcquisitionError, match="complete upstream manifest"):
        build_receipt(
            plan,
            snapshots={resource_id: snapshot},
            manifests={resource_id: manifest},
        )


def test_receipt_detects_same_size_tamper_with_restored_mtime(tmp_path: Path) -> None:
    plan, manifest, snapshot, _resource_root = _fixture_snapshot(tmp_path)
    resource_id = plan["resources"][0]["resource_id"]
    receipt = build_receipt(
        plan,
        snapshots={resource_id: snapshot},
        manifests={resource_id: manifest},
    )
    weight_path = snapshot / "model.safetensors"
    original = weight_path.stat()
    weight_path.write_bytes(b"changed-weights")
    os.utime(weight_path, ns=(original.st_atime_ns, original.st_mtime_ns))
    with pytest.raises(ModelAcquisitionError, match="changed after acquisition"):
        verify_receipt_snapshots(
            plan,
            receipt,
            managed_store=(tmp_path / "store").resolve(),
        )


def test_receipt_is_bound_to_exact_config_digest(tmp_path: Path) -> None:
    plan, manifest, snapshot, _resource_root = _fixture_snapshot(tmp_path)
    resource_id = plan["resources"][0]["resource_id"]
    receipt = build_receipt(
        plan,
        snapshots={resource_id: snapshot},
        manifests={resource_id: manifest},
    )
    changed_plan = build_plan(
        [hub_requirement("vllm_target", "Org/Model", REVISION)],
        bindings={**BINDINGS, "local_config_sha256": "e" * 64},
    )
    with pytest.raises(ModelAcquisitionError, match="another plan"):
        validate_receipt(receipt, plan=changed_plan)


def test_create_only_document_refuses_conflicting_content(tmp_path: Path) -> None:
    plan = _fixture_plan()
    path, digest = write_document_create_only(
        tmp_path.resolve(),
        plan,
        identifier=plan["plan_id"],
        suffix="plan.json",
    )
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_text(json.dumps({"tampered": True}), encoding="utf-8")
    with pytest.raises(ModelAcquisitionError, match="already differs"):
        write_document_create_only(
            tmp_path.resolve(),
            plan,
            identifier=plan["plan_id"],
            suffix="plan.json",
        )


def test_create_only_document_rejects_precreated_hardlink_and_huge_file(
    tmp_path: Path,
) -> None:
    plan = _fixture_plan()
    target = tmp_path / f"{plan['plan_id']}.plan.json"
    external = tmp_path / "external-document"
    external.write_bytes(b"sentinel")
    os.link(external, target)
    with pytest.raises(ModelAcquisitionError, match="contained regular"):
        write_document_create_only(
            tmp_path.resolve(),
            plan,
            identifier=plan["plan_id"],
            suffix="plan.json",
        )
    assert external.read_bytes() == b"sentinel"

    target.unlink()
    target.write_bytes(b"x" * (acquisition_module.MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(ModelAcquisitionError, match="contained regular"):
        write_document_create_only(
            tmp_path.resolve(),
            plan,
            identifier=plan["plan_id"],
            suffix="plan.json",
        )


def test_create_only_document_rejects_concurrent_hardlink_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _fixture_plan()
    external = tmp_path / "external-race-document"
    external.write_bytes(b"must-survive")
    original_link = acquisition_module.os.link

    def race_link(source, target, *, follow_symlinks=True):  # noqa: ANN001
        del source, follow_symlinks
        original_link(external, target)
        raise FileExistsError(str(target))

    monkeypatch.setattr(acquisition_module.os, "link", race_link)
    with pytest.raises(ModelAcquisitionError, match="contained regular"):
        write_document_create_only(
            tmp_path.resolve(),
            plan,
            identifier=plan["plan_id"],
            suffix="plan.json",
        )
    assert external.read_bytes() == b"must-survive"


def test_missing_files_set_activity_only_around_real_download(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False)
    transitions: list[bool] = []
    result = acquire(
        plan,
        store=(tmp_path / "store").resolve(),
        receipts_dir=(tmp_path / "receipts").resolve(),
        max_download_bytes=1024,
        min_free_bytes=128,
        deadline_seconds=30,
        backend=backend,
        activity=transitions.append,
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )
    assert transitions == [True, False]
    assert backend.download_calls == ["config.json", "weights/model.safetensors"]
    assert result.downloaded_bytes == sum(len(content) for content in backend.files.values())
    assert result.receipt_path.is_file()
    resource_id = plan["resources"][0]["resource_id"]
    assert verify_receipt_snapshots(
        plan,
        json.loads(result.receipt_path.read_text(encoding="utf-8")),
        managed_store=(tmp_path / "store").resolve(),
    )[resource_id].is_dir()


def test_unreceipted_complete_cache_import_has_no_download_activity(
    tmp_path: Path,
) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=True)
    transitions: list[bool] = []
    result = acquire(
        plan,
        store=(tmp_path / "store").resolve(),
        receipts_dir=(tmp_path / "receipts").resolve(),
        max_download_bytes=0,
        min_free_bytes=128,
        deadline_seconds=30,
        backend=backend,
        activity=transitions.append,
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )
    assert transitions == []
    assert backend.download_calls == []
    assert result.downloaded_bytes == 0

    # The promoted asset is an independent byte copy, not a symlink/hardlink
    # into the mutable/garbage-collectable Hugging Face transport cache.
    for source in (tmp_path / "cache").rglob("*"):
        if source.is_file():
            source.unlink()
    receipt = json.loads(result.receipt_path.read_text(encoding="utf-8"))
    verify_receipt_snapshots(
        plan,
        receipt,
        managed_store=(tmp_path / "store").resolve(),
    )


def test_partial_cache_marks_only_the_missing_file_as_download(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _PartialCacheBackend(tmp_path, cached=True)
    transitions: list[bool] = []
    result = acquire(
        plan,
        store=(tmp_path / "store").resolve(),
        receipts_dir=(tmp_path / "receipts").resolve(),
        max_download_bytes=1024,
        min_free_bytes=0,
        deadline_seconds=30,
        backend=backend,
        activity=transitions.append,
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )
    assert transitions == [True, False]
    assert backend.download_calls == ["weights/model.safetensors"]
    assert result.downloaded_bytes == len(backend.files["weights/model.safetensors"])


def test_receipted_managed_cache_hit_never_calls_hub_or_sets_activity(
    tmp_path: Path,
) -> None:
    plan = _fixture_plan()
    first = _FakeBackend(tmp_path, cached=True)
    acquire(
        plan,
        store=(tmp_path / "store").resolve(),
        receipts_dir=(tmp_path / "receipts-a").resolve(),
        max_download_bytes=0,
        min_free_bytes=0,
        deadline_seconds=30,
        backend=first,
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )

    class _NoHubBackend:
        def __getattribute__(self, name):  # noqa: ANN001
            if name.startswith("_"):
                return object.__getattribute__(self, name)
            raise AssertionError("managed cache hit must not touch the Hub backend")

    transitions: list[bool] = []
    result = acquire(
        plan,
        store=(tmp_path / "store").resolve(),
        receipts_dir=(tmp_path / "receipts-b").resolve(),
        max_download_bytes=0,
        min_free_bytes=0,
        deadline_seconds=30,
        backend=_NoHubBackend(),
        activity=transitions.append,
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )
    assert transitions == []
    assert result.downloaded_bytes == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
@pytest.mark.parametrize("boundary", ["resource", "snapshot"])
def test_acquire_cache_hit_rejects_external_junction_before_hub_skip(
    tmp_path: Path,
    boundary: str,
) -> None:
    plan = _fixture_plan()
    store = (tmp_path / "store").resolve()
    acquire(
        plan,
        store=store,
        receipts_dir=(tmp_path / "receipts-a").resolve(),
        max_download_bytes=0,
        min_free_bytes=0,
        deadline_seconds=30,
        backend=_FakeBackend(tmp_path, cached=True),
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )
    resource_root = store / plan["resources"][0]["resource_id"]
    attacked = resource_root if boundary == "resource" else resource_root / "snapshot"
    external = tmp_path / f"external-{boundary}"
    attacked.rename(external)
    sentinel = (
        external / "snapshot" / "config.json"
        if boundary == "resource"
        else external / "config.json"
    )
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(attacked), str(external)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0 or not attacked.is_junction():
        pytest.skip("Windows junction creation is unavailable")

    class _NoHubBackend:
        def __getattribute__(self, name):  # noqa: ANN001
            if name.startswith("_"):
                return object.__getattribute__(self, name)
            raise AssertionError("unsafe cache path must fail before touching Hub")

    try:
        with pytest.raises(ModelAcquisitionError, match="junction|non-link|direct"):
            acquire(
                plan,
                store=store,
                receipts_dir=(tmp_path / "receipts-b").resolve(),
                max_download_bytes=0,
                min_free_bytes=0,
                deadline_seconds=30,
                backend=_NoHubBackend(),
                disk_usage=lambda _path: SimpleNamespace(free=10**9),
            )
        assert sentinel.is_file()
    finally:
        os.rmdir(attacked)


def test_acquire_cache_hit_rejects_multiply_linked_manifest(
    tmp_path: Path,
) -> None:
    plan = _fixture_plan()
    store = (tmp_path / "store").resolve()
    acquire(
        plan,
        store=store,
        receipts_dir=(tmp_path / "receipts-a").resolve(),
        max_download_bytes=0,
        min_free_bytes=0,
        deadline_seconds=30,
        backend=_FakeBackend(tmp_path, cached=True),
        disk_usage=lambda _path: SimpleNamespace(free=10**9),
    )
    resource_root = store / plan["resources"][0]["resource_id"]
    manifest = next(resource_root.glob("*.upstream-manifest.json"))
    payload = manifest.read_bytes()
    manifest.unlink()
    external = tmp_path / "external-manifest"
    external.write_bytes(payload)
    os.link(external, manifest)

    with pytest.raises(ModelAcquisitionError, match="contained regular"):
        acquire(
            plan,
            store=store,
            receipts_dir=(tmp_path / "receipts-b").resolve(),
            max_download_bytes=0,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=_FakeBackend(tmp_path, cached=True),
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert external.read_bytes() == payload


def test_download_failure_clears_activity_and_partial_tree(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False, fail_download=True)
    transitions: list[bool] = []
    store = (tmp_path / "store").resolve()
    with pytest.raises(RuntimeError, match="injected download failure"):
        acquire(
            plan,
            store=store,
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=1024,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=backend,
            activity=transitions.append,
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert transitions == [True, False]
    assert not list(store.glob("*.partial"))
    assert not (store / plan["resources"][0]["resource_id"]).exists()


def test_download_cap_fails_before_activity_or_download(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False)
    transitions: list[bool] = []
    with pytest.raises(ModelAcquisitionError, match="max-download-bytes"):
        acquire(
            plan,
            store=(tmp_path / "store").resolve(),
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=1,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=backend,
            activity=transitions.append,
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert transitions == []
    assert backend.download_calls == []


def test_disk_headroom_fails_before_staging_or_activity(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False)
    transitions: list[bool] = []
    with pytest.raises(ModelAcquisitionError, match="insufficient disk"):
        acquire(
            plan,
            store=(tmp_path / "store").resolve(),
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=1024,
            min_free_bytes=1000,
            deadline_seconds=30,
            backend=backend,
            activity=transitions.append,
            disk_usage=lambda _path: SimpleNamespace(free=1001),
        )
    assert transitions == []


def test_activity_event_is_authenticated_job_bound_and_ordered(tmp_path: Path) -> None:
    token = "f" * 64
    event_path = (tmp_path / "activity.json").resolve()
    reporter = ActivityReporter(path=event_path, job_id="job-123", token=token)
    reporter(True)
    start = json.loads(event_path.read_text(encoding="utf-8"))
    assert validate_activity_event(
        start, job_id="job-123", token=token, minimum_sequence=0
    )["activity"] == "model_download"
    reporter(False)
    end = json.loads(event_path.read_text(encoding="utf-8"))
    assert validate_activity_event(
        end, job_id="job-123", token=token, minimum_sequence=1
    )["activity"] is None
    end["activity"] = "model_download"
    with pytest.raises(ModelAcquisitionError, match="transition|authentication"):
        validate_activity_event(end, job_id="job-123", token=token, minimum_sequence=1)


def test_activity_event_rejects_malformed_timestamp(tmp_path: Path) -> None:
    token = "f" * 64
    event_path = (tmp_path / "activity.json").resolve()
    reporter = ActivityReporter(path=event_path, job_id="job-123", token=token)
    reporter(True)
    event = json.loads(event_path.read_text(encoding="utf-8"))
    event["at"] = "not-a-time"
    body = {key: value for key, value in event.items() if key != "hmac_sha256"}
    event["hmac_sha256"] = hmac.new(
        bytes.fromhex(token),
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    with pytest.raises(ModelAcquisitionError, match="timestamp"):
        validate_activity_event(event, job_id="job-123", token=token, minimum_sequence=0)


def test_token_bearing_worker_environment_drops_unrelated_secrets_and_pythonpath(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HF_TOKEN", "hf_fixture")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "do-not-forward")
    monkeypatch.setenv("OPENAI_API_KEY", "do-not-forward")
    monkeypatch.setenv("PYTHONPATH", "C:/attacker-controlled")
    monkeypatch.setenv("HF_ENDPOINT", "https://attacker.example")
    monkeypatch.setenv("HTTPS_PROXY", "https://user:secret@proxy.example")
    monkeypatch.setenv("HF_HUB_DISABLE_XET", "1")
    environment = _safe_worker_environment()
    assert environment["HF_TOKEN"] == "hf_fixture"
    assert environment["HF_HUB_DISABLE_XET"] == "1"
    assert "ANTHROPIC_API_KEY" not in environment
    assert "OPENAI_API_KEY" not in environment
    assert "PYTHONPATH" not in environment
    assert "HF_ENDPOINT" not in environment
    assert "HTTPS_PROXY" not in environment


def test_non_lfs_git_blob_identity_must_be_sha1_width() -> None:
    with pytest.raises(ModelAcquisitionError, match="blob identity"):
        build_upstream_manifest(
            "Org/Model",
            REVISION,
            [
                {
                    "path": "config.json",
                    "size": 1,
                    "blob_id": "d" * 64,
                    "lfs_sha256": None,
                }
            ],
        )


def test_managed_snapshot_rejects_hardlinks_to_external_cache(tmp_path: Path) -> None:
    plan, manifest, snapshot, _resource_root = _fixture_snapshot(tmp_path)
    source = tmp_path / "external-cache-file"
    source.write_bytes(b"fixture-weights")
    target = snapshot / "model.safetensors"
    target.unlink()
    os.link(source, target)
    resource_id = plan["resources"][0]["resource_id"]
    with pytest.raises(ModelAcquisitionError, match="regular file"):
        build_receipt(
            plan,
            snapshots={resource_id: snapshot},
            manifests={resource_id: manifest},
        )


def test_deadline_before_manifest_has_no_activity_or_staging(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False)
    moments = iter((0.0, 2.0))
    transitions: list[bool] = []
    with pytest.raises(TimeoutError, match="hard deadline"):
        acquire(
            plan,
            store=(tmp_path / "store").resolve(),
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=1024,
            min_free_bytes=0,
            deadline_seconds=1,
            backend=backend,
            activity=transitions.append,
            monotonic=lambda: next(moments),
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert transitions == []
    assert backend.manifest_calls == 0


def test_cancel_during_copy_cleans_partial_and_never_promotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=True)

    def cancelled_copy(*args, **kwargs):  # noqa: ANN002, ANN003
        del args, kwargs
        raise InterruptedError("cancelled during copy")

    monkeypatch.setattr("experiments.model_acquire._copy_cached_file", cancelled_copy)
    store = (tmp_path / "store").resolve()
    with pytest.raises(InterruptedError, match="during copy"):
        acquire(
            plan,
            store=store,
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=0,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=backend,
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert not (store / plan["resources"][0]["resource_id"]).exists()
    assert not list(store.glob("*.partial"))


def test_cancel_during_seal_cleans_partial_and_never_promotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=True)

    def cancelled_seal(*args, **kwargs):  # noqa: ANN002, ANN003
        del args, kwargs
        raise InterruptedError("cancelled during seal")

    monkeypatch.setattr("experiments.model_acquire.seal_snapshot", cancelled_seal)
    store = (tmp_path / "store").resolve()
    with pytest.raises(InterruptedError, match="during seal"):
        acquire(
            plan,
            store=store,
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=0,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=backend,
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert not (store / plan["resources"][0]["resource_id"]).exists()


def test_wrong_revision_manifest_fails_before_activity(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False)
    backend.manifest = build_upstream_manifest(
        "Org/Model",
        "e" * 40,
        backend.manifest["files"],
    )
    transitions: list[bool] = []
    with pytest.raises(ModelAcquisitionError, match="different resource"):
        acquire(
            plan,
            store=(tmp_path / "store").resolve(),
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=1024,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=backend,
            activity=transitions.append,
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert transitions == []


def test_wrong_downloaded_bytes_fail_before_promotion(tmp_path: Path) -> None:
    plan = _fixture_plan()
    backend = _FakeBackend(tmp_path, cached=False)
    (tmp_path / "cache" / "weights" / "model.safetensors").write_bytes(
        b"corrupt-weights"
    )
    store = (tmp_path / "store").resolve()
    transitions: list[bool] = []
    with pytest.raises(ModelAcquisitionError, match="LFS content"):
        acquire(
            plan,
            store=store,
            receipts_dir=(tmp_path / "receipts").resolve(),
            max_download_bytes=1024,
            min_free_bytes=0,
            deadline_seconds=30,
            backend=backend,
            activity=transitions.append,
            disk_usage=lambda _path: SimpleNamespace(free=10**9),
        )
    assert transitions == [True, False]
    assert not (store / plan["resources"][0]["resource_id"]).exists()


def test_manifest_rejects_traversal_before_any_filesystem_use() -> None:
    with pytest.raises(ModelAcquisitionError, match="filename"):
        build_upstream_manifest(
            "Org/Model",
            REVISION,
            [
                {
                    "path": "../outside",
                    "size": 1,
                    "blob_id": "d" * 40,
                    "lfs_sha256": None,
                }
            ],
        )


def test_post_enumeration_symlink_swap_cannot_hash_outside_store(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    inside = snapshot / "config.json"
    inside.write_bytes(b"inside")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    calls = 0

    def swap_after_enumeration() -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            inside.unlink()
            try:
                inside.symlink_to(outside)
            except OSError:
                pytest.skip("file symlinks require unavailable Windows privilege")
        return False

    with pytest.raises(ModelAcquisitionError, match="outside|special"):
        seal_snapshot(snapshot.resolve(), cancelled=swap_after_enumeration)


def test_resource_lock_rejects_concurrent_owner(tmp_path: Path) -> None:
    # Use a plain fixed child path; _ResourceLock validates the lock operation,
    # while acquire itself owns the resource-id filename grammar.
    lock_path = tmp_path / ".resource.lock"
    with _ResourceLock(lock_path):
        with pytest.raises(ModelAcquisitionError, match="another acquisition"):
            with _ResourceLock(lock_path):
                raise AssertionError("second owner unexpectedly acquired the lock")


def test_resource_lock_rejects_multiply_linked_external_file(tmp_path: Path) -> None:
    external = tmp_path / "external-lock-target"
    external.write_bytes(b"sentinel")
    lock_path = tmp_path / ".resource.lock"
    os.link(external, lock_path)

    with pytest.raises(ModelAcquisitionError, match="unsafe|changed"):
        with _ResourceLock(lock_path):
            raise AssertionError("multiply-linked lock unexpectedly opened")

    assert external.read_bytes() == b"sentinel"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_partial_cleanup_refuses_replaced_junction_without_deleting_target(
    tmp_path: Path,
) -> None:
    store = (tmp_path / "store").resolve()
    store.mkdir()
    partial = store / (".hf-" + "a" * 32 + "." + "b" * 32 + ".partial")
    partial.mkdir()
    initial = partial.lstat()
    expected_identity = (initial.st_dev, initial.st_ino, initial.st_mode)
    partial.rmdir()
    external = (tmp_path / "external-cleanup-target").resolve()
    external.mkdir()
    sentinel = external / "must-survive.txt"
    sentinel.write_text("keep", encoding="utf-8")
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(partial), str(external)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0 or not partial.is_junction():
        pytest.skip("Windows junction creation is unavailable")
    try:
        with pytest.raises(ModelAcquisitionError, match="replaced"):
            _safe_remove_partial(
                partial,
                store=store,
                expected_identity=expected_identity,
            )
        assert sentinel.read_text(encoding="utf-8") == "keep"
    finally:
        os.rmdir(partial)


def test_hung_worker_is_terminated_on_cancellation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _HungProcess:
        returncode = None

        def __init__(self) -> None:
            self.terminated = False
            self.killed = False

        def poll(self):  # noqa: ANN201
            return self.returncode

        def terminate(self) -> None:
            self.terminated = True
            self.returncode = -15

        def wait(self, timeout=None):  # noqa: ANN001, ANN201
            del timeout
            return self.returncode

        def kill(self) -> None:
            self.killed = True
            self.returncode = -9

    process = _HungProcess()
    monkeypatch.setattr("experiments.model_acquire.subprocess.Popen", lambda *a, **k: process)
    backend = HuggingFaceBackend(transport_cache=(tmp_path / "transport").resolve())
    with pytest.raises(InterruptedError, match="cancelled"):
        backend._worker([], deadline=time.monotonic() + 30, cancelled=lambda: True)
    assert process.terminated is True


def test_manifest_worker_same_size_swap_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = HuggingFaceBackend(transport_cache=(tmp_path / "transport-race").resolve())
    content = b"fixture"
    manifest_a = build_upstream_manifest(
        "Org/Model",
        REVISION,
        [{
            "path": "a.bin",
            "size": len(content),
            "blob_id": _git_blob_id(content),
            "lfs_sha256": None,
        }],
    )
    manifest_b = build_upstream_manifest(
        "Org/Model",
        REVISION,
        [{
            "path": "b.bin",
            "size": len(content),
            "blob_id": _git_blob_id(content),
            "lfs_sha256": None,
        }],
    )
    raw_a = json.dumps(
        manifest_a, sort_keys=True, separators=(",", ":")
    ).encode() + b"\n"
    raw_b = json.dumps(
        manifest_b, sort_keys=True, separators=(",", ":")
    ).encode() + b"\n"
    assert len(raw_a) == len(raw_b)
    target: list[Path] = []

    def fake_worker(arguments, **_kwargs):  # noqa: ANN001
        output = Path(arguments[arguments.index("--worker-output") + 1])
        output.write_bytes(raw_a)
        target.append(output)

    original_resolve = Path.resolve
    swapped = False

    def swap_before_open(path: Path, *args, **kwargs):  # noqa: ANN002, ANN003
        nonlocal swapped
        if target and path == target[0] and not swapped:
            forged = path.with_name(".forged-worker-manifest.json")
            forged.write_bytes(raw_b)
            os.replace(forged, path)
            swapped = True
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(backend, "_worker", fake_worker)
    monkeypatch.setattr(Path, "resolve", swap_before_open)
    with pytest.raises(ModelAcquisitionError, match="changed while it was opened"):
        backend.fetch_manifest(
            "Org/Model",
            REVISION,
            deadline=time.monotonic() + 30,
            cancelled=lambda: False,
        )
    assert swapped is True
    assert target and not target[0].exists()


@pytest.mark.parametrize("unsafe_kind", ["hardlink", "symlink", "oversize"])
def test_manifest_worker_rejects_unsafe_output_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    backend = HuggingFaceBackend(
        transport_cache=(tmp_path / f"transport-{unsafe_kind}").resolve()
    )
    manifest = build_upstream_manifest(
        "Org/Model",
        REVISION,
        [{
            "path": "model.bin",
            "size": 1,
            "blob_id": _git_blob_id(b"x"),
            "lfs_sha256": None,
        }],
    )
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    target: list[Path] = []

    def fake_worker(arguments, **_kwargs):  # noqa: ANN001
        output = Path(arguments[arguments.index("--worker-output") + 1])
        target.append(output)
        external = tmp_path / f"external-{unsafe_kind}.json"
        if unsafe_kind == "oversize":
            output.write_bytes(b"x" * (MAX_DOCUMENT_BYTES + 1))
        else:
            external.write_bytes(raw)
            try:
                if unsafe_kind == "hardlink":
                    os.link(external, output)
                else:
                    os.symlink(external, output)
            except OSError:
                pytest.skip(f"{unsafe_kind} creation is unavailable")

    monkeypatch.setattr(backend, "_worker", fake_worker)
    with pytest.raises(ModelAcquisitionError, match="contained regular file"):
        backend.fetch_manifest(
            "Org/Model",
            REVISION,
            deadline=time.monotonic() + 30,
            cancelled=lambda: False,
        )
    assert target and not target[0].exists()


def test_activity_start_is_stale_after_end_sequence(tmp_path: Path) -> None:
    token = "f" * 64
    event_path = (tmp_path / "activity.json").resolve()
    reporter = ActivityReporter(path=event_path, job_id="job-123", token=token)
    reporter(True)
    start = json.loads(event_path.read_text(encoding="utf-8"))
    reporter(False)
    end = json.loads(event_path.read_text(encoding="utf-8"))
    assert end["download_observed"] is True
    validate_activity_event(end, job_id="job-123", token=token, minimum_sequence=1)
    with pytest.raises(ModelAcquisitionError, match="stale"):
        validate_activity_event(start, job_id="job-123", token=token, minimum_sequence=2)


def test_cli_rejects_plan_sha_mismatch_before_backend_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _fixture_plan()
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")

    def backend_must_not_construct(*args, **kwargs):  # noqa: ANN002, ANN003
        del args, kwargs
        raise AssertionError("backend constructed before exact plan SHA validation")

    monkeypatch.setattr("experiments.model_acquire.HuggingFaceBackend", backend_must_not_construct)
    assert acquire_main(
        [
            "--plan",
            str(plan_path),
            "--plan-sha256",
            "f" * 64,
            "--store",
            str((tmp_path / "store").resolve()),
            "--receipts-dir",
            str((tmp_path / "receipts").resolve()),
            "--transport-cache",
            str((tmp_path / "transport").resolve()),
            "--max-download-bytes",
            "1",
            "--min-free-bytes",
            "0",
            "--deadline-seconds",
            "30",
        ]
    ) == 1


def _sealed_fixture_for_containment(tmp_path: Path) -> tuple[dict, dict, Path, Path]:
    plan, manifest, snapshot, resource_root = _fixture_snapshot(tmp_path)
    resource_id = plan["resources"][0]["resource_id"]
    receipt = build_receipt(
        plan,
        snapshots={resource_id: snapshot},
        manifests={resource_id: manifest},
    )
    return plan, receipt, resource_root, snapshot


def test_receipt_rejects_external_resource_root_directory_symlink(tmp_path: Path) -> None:
    plan, receipt, resource_root, _snapshot = _sealed_fixture_for_containment(tmp_path)
    store = (tmp_path / "store").resolve()
    external = tmp_path / "external-resource"
    resource_root.rename(external)
    try:
        resource_root.symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks require unavailable Windows privilege")
    try:
        with pytest.raises(ModelAcquisitionError, match="non-link|junction|direct store"):
            verify_receipt_snapshots(plan, receipt, managed_store=store)
    finally:
        resource_root.unlink(missing_ok=True)


def test_receipt_rejects_external_snapshot_directory_symlink(tmp_path: Path) -> None:
    plan, receipt, resource_root, snapshot = _sealed_fixture_for_containment(tmp_path)
    external = tmp_path / "external-snapshot"
    snapshot.rename(external)
    try:
        snapshot.symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks require unavailable Windows privilege")
    try:
        with pytest.raises(ModelAcquisitionError, match="non-link|junction|direct store"):
            verify_receipt_snapshots(
                plan,
                receipt,
                managed_store=(tmp_path / "store").resolve(),
            )
    finally:
        snapshot.unlink(missing_ok=True)


def test_receipt_rejects_external_manifest_file_symlink(tmp_path: Path) -> None:
    plan, receipt, resource_root, _snapshot = _sealed_fixture_for_containment(tmp_path)
    manifest_path = next(resource_root.glob("*.upstream-manifest.json"))
    external = tmp_path / "external-manifest.json"
    external.write_bytes(manifest_path.read_bytes())
    manifest_path.unlink()
    try:
        manifest_path.symlink_to(external)
    except OSError:
        pytest.skip("file symlinks require unavailable Windows privilege")
    try:
        with pytest.raises(ModelAcquisitionError, match="contained regular|outside"):
            verify_receipt_snapshots(
                plan,
                receipt,
                managed_store=(tmp_path / "store").resolve(),
            )
    finally:
        manifest_path.unlink(missing_ok=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction regression")
def test_receipt_rejects_external_resource_root_junction(tmp_path: Path) -> None:
    plan, receipt, resource_root, _snapshot = _sealed_fixture_for_containment(tmp_path)
    store = (tmp_path / "store").resolve()
    external = tmp_path / "external-junction-resource"
    resource_root.rename(external)
    created = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(resource_root), str(external)],
        check=False,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0 or not resource_root.is_junction():
        pytest.skip("Windows junction creation is unavailable")
    try:
        with pytest.raises(ModelAcquisitionError, match="non-link|junction|direct store"):
            verify_receipt_snapshots(plan, receipt, managed_store=store)
    finally:
        os.rmdir(resource_root)
