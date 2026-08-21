from __future__ import annotations

import hashlib
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from experiments import framework_runtime_installer as installer


LOCK_PATH = Path(installer.__file__).with_name("framework_runtime_lock.json")


def _minimal_lock() -> dict[str, Any]:
    return {"lock_id": "a" * 64, "frameworks": [{"name": "pyrit"}, {"name": "garak"}]}


def test_repository_lock_is_strict_and_covers_all_registered_attackers() -> None:
    lock = installer.load_lock(LOCK_PATH)
    assert lock["schema"] == "ura-framework-runtime-lock/1"
    assert len(lock["frameworks"]) == 15
    assert {entry["name"] for entry in lock["frameworks"]} == {
        "agentdojo",
        "asb",
        "autodan",
        "deepteam",
        "easyjailbreak",
        "fuzzyai",
        "garak",
        "giskard",
        "h4rm3l",
        "harmbench",
        "nanogcg",
        "petri",
        "promptfoo",
        "pyrit",
        "spikee",
    }
    assert len(lock["coverage"]) == 20
    assert {row["attacker"] for row in lock["coverage"]} == {
        "agentdojo",
        "asb",
        "autodan",
        "crescendo",
        "deepteam",
        "easyjailbreak",
        "fuzzyai",
        "garak",
        "giskard",
        "h4rm3l",
        "harmbench",
        "ideator",
        "nanogcg",
        "petri",
        "promptfoo",
        "purplellama",
        "pyrit",
        "replay",
        "spikee",
        "t3mp3st",
    }


def test_lock_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    raw = LOCK_PATH.read_text(encoding="utf-8")
    duplicate = '{"schema":"duplicate",' + raw[1:]
    path = tmp_path / "duplicate.json"
    path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(installer.InstallerError, match="duplicate JSON object key"):
        installer.load_lock(path)


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (
            lambda lock: lock["frameworks"][0]["install"].__setitem__("surprise", True),
            "keys are invalid",
        ),
        (
            lambda lock: lock["frameworks"][0]["source"].__setitem__("surprise", True)
            if lock["frameworks"][0]["source"]
            else lock["frameworks"][5]["source"].__setitem__("surprise", True),
            "keys are invalid",
        ),
        (lambda lock: lock["frameworks"][0]["smoke"].pop("mode"), "keys are invalid"),
        (lambda lock: lock["policy"].__setitem__("surprise", True), "keys are invalid"),
        (lambda lock: lock["frameworks"][0].__setitem__("artifacts", {}), "must be a list"),
        (
            lambda lock: lock["frameworks"][0]["smoke"].__setitem__(
                "mode", "cli-version"
            ),
            "mode must be import",
        ),
        (
            lambda lock: lock["frameworks"][0]["smoke"]["environment"].__setitem__(
                "OPENAI_API_KEY", "forbidden"
            ),
            "credential key",
        ),
        (
            lambda lock: lock["coverage"][0].__setitem__("attacker", "not-registered"),
            "20 registered attackers",
        ),
    ],
)
def test_lock_rejects_unknown_or_missing_nested_fields(
    tmp_path: Path, mutation: Any, error: str
) -> None:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    mutation(lock)
    path = tmp_path / "mutated.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(installer.InstallerError, match=error):
        installer.load_lock(path)


def test_every_python_dependency_is_exact_and_hashed() -> None:
    lock = installer.load_lock(LOCK_PATH)
    for entry in lock["frameworks"]:
        if entry["runtime"] != "python":
            continue
        rows = installer._logical_requirements(entry["dependencies"]["requirements"])
        assert len(rows) == entry["dependencies"]["package_count"]
        assert all("--hash=sha256:" in row for row in rows)


# "pip wheel --no-build-isolation" forbids pip from fetching a PEP 518 build
# backend, so every backend the locked sources declare -- and everything that
# backend itself imports -- has to sit inside the framework's own hashed
# requirement set. These tables are the offline, network-free record of what
# each pinned pyproject.toml (or bare setup.py) declares; the versions are
# never restated here, they are read back out of the lock.
_BACKEND_DISTRIBUTIONS = {
    "flit_core.buildapi": "flit-core",
    "hatchling.build": "hatchling",
    "pdm.backend": "pdm-backend",
    "poetry.core.masonry.api": "poetry-core",
    "setuptools.build_meta": "setuptools",
    "setuptools.build_meta:__legacy__": "setuptools",
}

# Distributions each build backend imports while building a wheel.
_BACKEND_IMPORTS = {
    "flit-core": (),
    "hatch-vcs": ("hatchling", "setuptools-scm"),
    "hatchling": ("packaging", "pathspec", "pluggy", "tomlkit", "trove-classifiers"),
    "packaging": (),
    "pathspec": (),
    "pluggy": (),
    "poetry-core": (),
    "setuptools": (),
    "setuptools-scm": ("packaging", "setuptools", "vcs-versioning"),
    "tomlkit": (),
    "trove-classifiers": (),
    "vcs-versioning": ("packaging",),
    "wheel": ("packaging",),
}

# Framework -> (build-backend declared at the pinned commit, other build
# requires that pyproject.toml lists). easyjailbreak ships a bare setup.py at
# its pinned commit, so pip falls back to the legacy setuptools backend.
_SOURCE_BUILD_BACKENDS = {
    "agentdojo": ("hatchling.build", ()),
    "easyjailbreak": ("setuptools.build_meta:__legacy__", ()),
    "fuzzyai": ("poetry.core.masonry.api", ("setuptools", "wheel")),
    "garak": ("flit_core.buildapi", ()),
    "petri": ("hatchling.build", ("hatch-vcs",)),
}


def _pinned_distributions(entry: dict[str, Any]) -> dict[str, str]:
    pinned: dict[str, str] = {}
    for row in installer._logical_requirements(entry["dependencies"]["requirements"]):
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)", row)
        if match:
            pinned[installer._canonical_name(match.group(1))] = match.group(2)
    return pinned


def test_no_build_isolation_frameworks_pin_their_declared_build_backend() -> None:
    lock = installer.load_lock(LOCK_PATH)
    unisolated = {
        entry["name"]
        for entry in lock["frameworks"]
        if any("--no-build-isolation" in command for command in entry["install"]["commands"])
    }
    # a newly source-built framework must register its backend here, offline
    assert unisolated == set(_SOURCE_BUILD_BACKENDS)
    for entry in lock["frameworks"]:
        if entry["name"] not in unisolated:
            continue
        backend, extra_requires = _SOURCE_BUILD_BACKENDS[entry["name"]]
        assert backend in _BACKEND_DISTRIBUTIONS, backend
        pinned = _pinned_distributions(entry)
        inventory = set(entry["expected_inventory"]["distributions"])
        pending = [_BACKEND_DISTRIBUTIONS[backend], *extra_requires]
        checked: set[str] = set()
        while pending:
            distribution = pending.pop()
            if distribution in checked:
                continue
            checked.add(distribution)
            assert distribution in pinned, (
                f"{entry['name']} builds with --no-build-isolation but its hashed "
                f"requirements lack {distribution!r}, needed for build backend {backend!r}"
            )
            assert f"{distribution}=={pinned[distribution]}" in inventory, (
                f"{entry['name']} expected inventory omits the pinned {distribution}"
            )
            imports = _BACKEND_IMPORTS.get(distribution)
            assert imports is not None, f"unknown build dependency {distribution!r}"
            pending.extend(imports)


def test_promptfoo_lock_has_integrity_for_every_resolved_registry_package() -> None:
    lock = installer.load_lock(LOCK_PATH)
    promptfoo = next(entry for entry in lock["frameworks"] if entry["name"] == "promptfoo")
    packages = promptfoo["dependencies"]["npm_lock"]["packages"]
    assert all(not item.get("resolved") or item.get("integrity") for item in packages.values())


class _Response:
    def __init__(self, payload: bytes, headers: dict[str, str] | None = None):
        self.payload = payload
        self.headers = headers or {}
        self.calls = 0

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _size: int) -> bytes:
        self.calls += 1
        if self.calls == 1:
            return self.payload
        return b""


def test_download_stops_before_writing_beyond_locked_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = _Response(b"abcdefgh")

    class _Opener:
        def open(self, *_args: object, **_kwargs: object) -> _Response:
            return response

    monkeypatch.setattr(installer.urllib.request, "build_opener", lambda *_args: _Opener())
    artifact = {
        "url": "https://example.invalid/a.whl",
        "filename": "a.whl",
        "sha256": hashlib.sha256(b"abcd").hexdigest(),
        "size": 4,
    }
    destination = tmp_path / "a.whl"
    with pytest.raises(installer.InstallerError, match="exceeds locked size"):
        installer._download(artifact, destination)
    assert response.calls == 1
    assert not destination.exists()
    assert not (tmp_path / "a.whl.partial").exists()


def test_download_rejects_content_length_before_streaming(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = _Response(b"abcd", {"Content-Length": "8"})

    class _Opener:
        def open(self, *_args: object, **_kwargs: object) -> _Response:
            return response

    monkeypatch.setattr(installer.urllib.request, "build_opener", lambda *_args: _Opener())
    artifact = {
        "url": "https://example.invalid/a.whl",
        "filename": "a.whl",
        "sha256": hashlib.sha256(b"abcd").hexdigest(),
        "size": 4,
    }
    with pytest.raises(installer.InstallerError, match="size mismatch"):
        installer._download(artifact, tmp_path / "a.whl")
    assert response.calls == 0


def test_download_rejects_hardlinked_destination_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    external = tmp_path / "external"
    external.write_bytes(b"outside")
    destination = tmp_path / "artifact.bin"
    os.link(external, destination)
    monkeypatch.setattr(
        installer.urllib.request,
        "build_opener",
        lambda *_args: (_ for _ in ()).throw(AssertionError("network must not open")),
    )
    artifact = {
        "url": "https://example.invalid/artifact.bin",
        "filename": "artifact.bin",
        "sha256": hashlib.sha256(b"expected").hexdigest(),
        "size": len(b"expected"),
    }
    with pytest.raises(installer.InstallerError, match="unsafe managed file"):
        installer._download(artifact, destination)
    assert external.read_bytes() == b"outside"


def test_git_lfs_receives_explicit_owned_artifact_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    target = root / "source" / "demo"
    (target / ".git").mkdir(parents=True)
    commit = "1" * 40
    tree = "2" * 40
    archive = "3" * 64
    source = {
        "kind": "git",
        "url": "https://example.invalid/demo.git",
        "commit": commit,
        "tree": tree,
        "archive_sha256": archive,
        "git_lfs_required": True,
    }
    calls: list[list[str]] = []

    class _Runner:
        def run(self, argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            command = [str(item) for item in argv]
            calls.append(command)
            if command[1:4] == ["remote", "get-url", "origin"]:
                return subprocess.CompletedProcess(command, 0, source["url"] + "\n", "")
            if command[1:3] == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(command, 0, commit + "\n", "")
            if command[1:3] == ["rev-parse", "HEAD^{tree}"]:
                return subprocess.CompletedProcess(command, 0, tree + "\n", "")
            if command[1:3] == ["grep", "-Il"]:
                return subprocess.CompletedProcess(command, 0, "weights.bin\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")

    seen: list[Path] = []
    monkeypatch.setattr(installer, "_git_archive_sha", lambda *_args: archive)
    monkeypatch.setattr(
        installer,
        "_run_git_lfs",
        lambda _spec, _source, artifact_root, _runner: seen.append(artifact_root),
    )
    installer._checkout_git_source(
        source,
        target,
        root,
        _Runner(),  # type: ignore[arg-type]
        {"git_lfs": {"required": True}},
        "demo",
    )
    assert seen == [root]
    assert ["git", "clean", "-ffdx"] in calls


@pytest.mark.skipif(shutil.which("git") is None, reason="git is unavailable")
def test_git_resume_removes_untracked_shadow_file(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    subprocess.run(["git", "init", str(upstream)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(upstream), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(upstream), "config", "user.name", "test"], check=True)
    subprocess.run(["git", "-C", str(upstream), "config", "core.autocrlf", "false"], check=True)
    (upstream / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(upstream), "add", "module.py"], check=True)
    subprocess.run(["git", "-C", str(upstream), "commit", "-m", "fixture"], check=True, capture_output=True)
    commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD^{tree}"], text=True).strip()
    archive_bytes = subprocess.check_output(["git", "-C", str(upstream), "archive", "--format=tar", "HEAD"])
    source = {
        "url": str(upstream),
        "commit": commit,
        "tree": tree,
        "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "git_lfs_required": False,
    }
    root = tmp_path / "store"
    root.mkdir()
    runner = installer.CommandRunner(tmp_path / "git.log", root, redact_paths=[tmp_path])
    target = root / "source" / "demo"
    installer._checkout_git_source(source, target, root, runner, {"git_lfs": {"required": False}}, "demo")
    shadow = target / "shadow.py"
    shadow.write_text("VALUE = 'untracked'\n", encoding="utf-8")
    installer._checkout_git_source(source, target, root, runner, {"git_lfs": {"required": False}}, "demo")
    assert not shadow.exists()


def test_interrupted_wheel_is_cleanly_rebuilt(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    stale = wheel_dir / "stale.whl"
    stale.write_bytes(b"stale")

    class _Runner:
        def run(self, _argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            assert not stale.exists()
            (wheel_dir / "fresh.whl").write_bytes(b"fresh")
            return subprocess.CompletedProcess([], 0, "", "")

    # The source directory has no pyproject.toml, so no version is declared.
    wheel = installer._build_source_wheel(
        Path("python"), tmp_path / "source", wheel_dir, _Runner(), "demo", {}  # type: ignore[arg-type]
    )
    assert wheel.name == "fresh.whl"


def test_resume_cleanup_removes_stale_venv_and_node_runtime_files(tmp_path: Path) -> None:
    store = tmp_path / "store"
    store.mkdir()
    (store / installer.STATE_NAME).write_text("{}", encoding="utf-8")
    (store / "bin").mkdir()
    (store / "bin" / "shadow").write_text("stale", encoding="utf-8")
    (store / "runtime").mkdir()
    (store / "runtime" / "shadow").write_text("stale", encoding="utf-8")
    installer._clear_owned_store(store, preserve={installer.STATE_NAME})
    assert (store / installer.STATE_NAME).is_file()
    assert not (store / "bin").exists()
    assert not (store / "runtime").exists()
    (store / "runtime").mkdir()
    (store / "runtime" / "shadow").write_text("stale", encoding="utf-8")
    installer._remove_owned_path(store, store / "runtime")
    assert not (store / "runtime").exists()


@pytest.mark.skipif(os.name == "nt", reason="runtime aliases target Linux")
def test_stable_alias_preserves_console_script_and_bridge_root(tmp_path: Path) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    layout.store_root.mkdir(parents=True)
    store = layout.store("demo", "a" * 64)
    subprocess.run([sys.executable, "-m", "venv", "--copies", str(store)], check=True)
    site_packages = (
        store
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    package = site_packages / "pyrit"
    metadata = site_packages / "pyrit-0.14.0.dist-info"
    package.mkdir()
    metadata.mkdir()
    (package / "__init__.py").write_text("__version__ = '0.14.0'\n", encoding="utf-8")
    (metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: pyrit\nVersion: 0.14.0\n", encoding="utf-8"
    )
    (metadata / "RECORD").write_text(
        "pyrit/__init__.py,,\n"
        "pyrit-0.14.0.dist-info/METADATA,,\n"
        "pyrit-0.14.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    installer._publish_alias(layout, "demo", store)
    alias = layout.final("demo")
    result = subprocess.run([str(alias / "bin" / "pip"), "--version"], capture_output=True, text=True)
    assert result.returncode == 0
    assert str(store) in (store / "bin" / "pip").read_text(encoding="utf-8").splitlines()[0]
    assert installer._content_seal(alias) == installer._content_seal(store)
    from ura.adapters._engine_runtime import _resolve_interpreter

    configured, _resolved = _resolve_interpreter(
        str(alias / "bin" / "python"), label="demo"
    )
    assert configured.parent.resolve(strict=True).parent == store
    entry = {"runtime": "python", "env_slug": "demo"}
    lock = {"lock_id": "a" * 64}
    canonical = installer.canonical_python_interpreter(entry, lock, layout)
    assert canonical.parent.parent == store
    from ura.adapters._engine_runtime import inspect_engine_runtime

    receipt = inspect_engine_runtime(canonical, "pyrit", timeout_seconds=60)
    assert receipt["engine"] == "pyrit"
    assert receipt["version"] == "0.14.0"

    replacement = layout.store("demo", "b" * 64)
    shutil.copytree(store, replacement, symlinks=True)
    installer._publish_alias(layout, "demo", replacement)
    assert alias.resolve(strict=True) == replacement.resolve(strict=True)
    assert installer._managed_alias_target(layout, "demo") == replacement.resolve(strict=True)
    assert store.is_dir()


def test_content_seal_detects_non_bytecode_tampering(tmp_path: Path) -> None:
    (tmp_path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    seal = installer._content_seal(tmp_path)
    assert seal["schema"] == "ura-framework-runtime-content-seal/2"
    receipt = {"content_seal": seal}
    installer._verify_content_seal(tmp_path, receipt, "demo")
    (tmp_path / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(installer.InstallerError, match="content seal mismatch"):
        installer._verify_content_seal(tmp_path, receipt, "demo")


def test_content_seal_detects_nested_sourceless_bytecode_tampering(
    tmp_path: Path,
) -> None:
    package = tmp_path / "demo"
    package.mkdir()
    source = package / "payload.py"
    bytecode = package / "payload.pyc"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    source.unlink()
    seal = installer._content_seal(tmp_path)
    receipt = {"content_seal": seal}

    source.write_text("VALUE = 2\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    source.unlink()

    with pytest.raises(installer.InstallerError, match="content seal mismatch"):
        installer._verify_content_seal(tmp_path, receipt, "demo")


def test_node_inventory_is_derived_from_installed_packages_and_detects_extra(
    tmp_path: Path,
) -> None:
    package = tmp_path / "node_modules" / "demo"
    package.mkdir(parents=True)
    (package / "package.json").write_text(
        json.dumps({"name": "demo", "version": "1.2.3"}), encoding="utf-8"
    )
    rows, digest = installer._node_installed_inventory(tmp_path)
    assert rows == ["node_modules/demo|demo==1.2.3"]
    extra = tmp_path / "node_modules" / "extra"
    extra.mkdir()
    (extra / "package.json").write_text(
        json.dumps({"name": "extra", "version": "4.5.6"}), encoding="utf-8"
    )
    new_rows, new_digest = installer._node_installed_inventory(tmp_path)
    assert len(new_rows) == 2
    assert new_digest != digest


def test_existing_receipt_never_skips_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entry = {"name": "demo", "env_slug": "demo"}
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    receipt = {
        "schema": "ura-framework-runtime-receipt/1",
        "lock_id": lock["lock_id"],
        "framework": "demo",
        "env_slug": "demo",
        "content_seal": {"schema": installer.CONTENT_SEAL_SCHEMA},
        "status": "passed",
    }
    monkeypatch.setattr(installer, "_alias_points_to", lambda *_args: True)
    monkeypatch.setattr(installer, "_read_receipt", lambda *_args: receipt)
    monkeypatch.setattr(
        installer,
        "_verify_published",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            installer.InstallerError("installed content seal mismatch")
        ),
    )
    with pytest.raises(installer.InstallerError, match="content seal mismatch"):
        installer.install_one(entry, lock, layout, resume=False)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_cross_process_lock_rejects_symlink_without_mutating_target(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.write_bytes(b"external")
    state = tmp_path / "state"
    state.mkdir()
    lock = state / "framework-runtime-installer.lock"
    try:
        lock.symlink_to(external)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(installer.InstallerError):
        with installer.CrossProcessLock(lock):
            pass
    assert external.read_bytes() == b"external"


def test_cross_process_lock_rejects_hardlink_without_mutating_target(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.write_bytes(b"external")
    state = tmp_path / "state"
    state.mkdir()
    lock = state / "framework-runtime-installer.lock"
    os.link(external, lock)
    with pytest.raises(installer.InstallerError):
        with installer.CrossProcessLock(lock):
            pass
    assert external.read_bytes() == b"external"


def test_state_and_campaign_writes_reject_links(tmp_path: Path) -> None:
    store = tmp_path / "store"
    store.mkdir()
    external = tmp_path / "external"
    external.write_bytes(b"external")
    state_path = store / installer.STATE_NAME
    os.link(external, state_path)
    with pytest.raises(installer.InstallerError):
        installer._write_state(store, {"completed": []})
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    os.link(external, campaign / "task-log.jsonl")
    with pytest.raises(installer.InstallerError):
        installer._append_campaign_event(
            campaign, {"event": "campaign_start", "task": "bootstrap", "status": "running"}
        )
    marker_source = tmp_path / "marker-source"
    installer._ensure_campaign(marker_source, _minimal_lock())
    marker_target = tmp_path / "marker-target"
    marker_target.mkdir()
    os.link(
        marker_source / "ENGINEERING_ONLY.json",
        marker_target / "ENGINEERING_ONLY.json",
    )
    marker_before = (marker_source / "ENGINEERING_ONLY.json").read_bytes()
    with pytest.raises(installer.InstallerError):
        installer._ensure_campaign(marker_target, _minimal_lock())
    assert (marker_source / "ENGINEERING_ONLY.json").read_bytes() == marker_before
    assert external.read_bytes() == b"external"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_state_and_campaign_writes_reject_symlinks(tmp_path: Path) -> None:
    external = tmp_path / "external"
    external.write_bytes(b"external")
    store = tmp_path / "store"
    store.mkdir()
    campaign = tmp_path / "campaign"
    campaign.mkdir()
    marker_source = tmp_path / "marker-source"
    installer._ensure_campaign(marker_source, _minimal_lock())
    try:
        (store / installer.STATE_NAME).symlink_to(external)
        (campaign / "task-log.jsonl").symlink_to(external)
        (campaign / "ENGINEERING_ONLY.json").symlink_to(
            marker_source / "ENGINEERING_ONLY.json"
        )
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(installer.InstallerError):
        installer._write_state(store, {"completed": []})
    with pytest.raises(installer.InstallerError):
        installer._append_campaign_event(
            campaign, {"event": "campaign_start", "task": "bootstrap", "status": "running"}
        )
    with pytest.raises(installer.InstallerError):
        installer._ensure_campaign(campaign, _minimal_lock())
    assert external.read_bytes() == b"external"


def test_command_logs_redact_normal_error_and_cross_chunk_paths(tmp_path: Path) -> None:
    private_root = tmp_path / "sentinel-private-root"
    private_root.mkdir()
    log = tmp_path / "logs" / "command.log"
    runner = installer.CommandRunner(log, private_root, redact_paths=[private_root])
    prefix = 65536 - max(1, len(str(private_root)) // 2)
    code = (
        "import sys; p=" + repr(str(private_root)) + ";"
        f"sys.stdout.write('x'*{prefix}+p+'\\n'+p+'\\n');"
        "sys.stderr.write('error '+p+'\\n');sys.exit(3)"
    )
    runner.run([sys.executable, "-c", code], allowed_returncodes=(3,))
    payload = log.read_text(encoding="utf-8", errors="replace")
    assert str(private_root) not in payload
    assert "error " in payload


def test_command_log_has_a_hard_byte_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "logs" / "command.log"
    monkeypatch.setattr(installer, "MAX_COMMAND_LOG_BYTES", 1024)
    runner = installer.CommandRunner(log, tmp_path)
    runner.run([sys.executable, "-c", "print('x'*10000)"])
    assert log.stat().st_size <= 1024


@pytest.mark.skipif(os.name == "nt", reason="process-group regression targets Linux")
def test_command_timeout_kills_descendant_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    runner = installer.CommandRunner(tmp_path / "command.log", tmp_path)
    child = f"import time,pathlib;time.sleep(2);pathlib.Path({str(marker)!r}).write_text('bad')"
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);time.sleep(30)"
    )
    with pytest.raises(installer.InstallerError, match="timed out"):
        runner.run([sys.executable, "-c", parent], timeout=1)
    time.sleep(2.5)
    assert not marker.exists()


def test_session_launcher_strips_ambient_credentials_and_binds_invocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs-a", tmp_path / "state-a")
    calls: list[tuple[list[str], dict[str, str] | None]] = []

    def fake_run(argv: Any, **kwargs: Any) -> subprocess.CompletedProcess[Any]:
        command = [str(item) for item in argv]
        calls.append((command, kwargs.get("env")))
        return subprocess.CompletedProcess(command, 1 if "has-session" in command else 0, b"", b"")

    monkeypatch.setenv("OPENAI_API_KEY", "hostile-secret")
    monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/bin/tmux" if name == "tmux" else None)
    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    result = installer._launch_session("install", lock, layout, ["pyrit"], Path(sys.executable))
    assert result["launcher"] == "tmux"
    assert all("OPENAI_API_KEY" not in (env or {}) for _command, env in calls)
    launch = next(command for command, _env in calls if "new-session" in command)
    probe = next(command for command, _env in calls if "has-session" in command)
    socket_name = installer._tmux_socket_name(result["session_name"])
    assert launch[1:3] == ["-L", socket_name]
    assert probe[1:3] == ["-L", socket_name]
    assert result["attach_command"].startswith(f"tmux -L {socket_name} attach -t ")
    assert "env" in launch and "-i" in launch
    assert any(item.startswith("URA_FRAMEWORK_NAMED_SESSION=") for item in launch)
    assert "__session_wrapper" in launch
    assert "--session-name-proof" in launch
    other = installer.Layout(tmp_path / "envs-b", tmp_path / "state-b")
    assert installer._session_name("install", lock["lock_id"], ["pyrit"], layout, Path(sys.executable)) != installer._session_name(
        "install", lock["lock_id"], ["pyrit"], other, Path(sys.executable)
    )


def test_screen_launcher_does_not_duplicate_live_named_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    session = installer._session_name("verify", lock["lock_id"], None, layout, None)
    calls: list[list[str]] = []

    def fake_run(argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in argv]
        calls.append(command)
        if command[-1] == "-ls":
            return subprocess.CompletedProcess(command, 0, f"  1234.{session}  (Detached)\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/bin/screen" if name == "screen" else None)
    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    result = installer._launch_session("verify", lock, layout, None, None)
    assert result["launcher"] == "screen"
    assert not any("-DmS" in command for command in calls)


def test_screen_launcher_does_not_treat_dead_socket_as_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    session = installer._session_name("verify", lock["lock_id"], None, layout, None)
    calls: list[list[str]] = []

    def fake_run(argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in argv]
        calls.append(command)
        if command[-1] == "-ls":
            return subprocess.CompletedProcess(
                command, 0, f"  1234.{session}  (Dead ???)\n", ""
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(
        installer.shutil,
        "which",
        lambda name: "/usr/bin/screen" if name == "screen" else None,
    )
    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    result = installer._launch_session("verify", lock, layout, None, None)
    assert result["launcher"] == "screen"
    assert any("-DmS" in command for command in calls)


def test_session_relaunch_clears_stale_exit_but_live_session_preserves_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    session = installer._session_name("install", lock["lock_id"], None, layout, None)
    sessions = layout.state_root / "sessions"
    sessions.mkdir(parents=True)
    marker = sessions / f"{session}.exit"
    log = sessions / f"{session}.log"
    marker.write_text("0\n", encoding="utf-8")
    log.write_text("stale transcript\n", encoding="utf-8")
    live = False

    def fake_run(argv: Any, **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        command = [str(item) for item in argv]
        return subprocess.CompletedProcess(command, 0 if live and "has-session" in command else 1 if "has-session" in command else 0, b"", b"")

    monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/bin/tmux" if name == "tmux" else None)
    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    installer._launch_session("install", lock, layout, None, None)
    assert not marker.exists()
    assert log.read_bytes() == b""
    marker.write_text("0\n", encoding="utf-8")
    log.write_text("live transcript\n", encoding="utf-8")
    live = True
    installer._launch_session("install", lock, layout, None, None)
    assert marker.read_text(encoding="utf-8") == "0\n"
    assert log.read_text(encoding="utf-8") == "live transcript\n"


def test_session_wrapper_bounds_transcript_and_records_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    session = "ura-framework-test"
    log = sessions / f"{session}.log"
    marker = sessions / f"{session}.exit"
    home = sessions / f"{session}.home"
    home.mkdir()
    log.write_bytes(b"")
    monkeypatch.setattr(installer, "MAX_COMMAND_LOG_BYTES", 1024)
    result = installer._session_wrapper_main(
        [
            "--log",
            str(log),
            "--marker",
            str(marker),
            "--home",
            str(home),
            "--session",
            session,
            "--redact",
            str(tmp_path),
            "--",
            sys.executable,
            "-c",
            "print('x' * 10000)",
        ]
    )
    assert result == 0
    assert marker.read_text(encoding="utf-8") == "0\n"
    assert log.stat().st_size <= 1024
    assert str(tmp_path) not in log.read_text(encoding="utf-8", errors="replace")


def test_named_session_proof_survives_sanitized_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    expected = installer._session_name("verify", lock["lock_id"], ["pyrit"], layout, None)
    args = installer.argparse.Namespace(
        command="verify", python=None, session_name_proof=expected
    )
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.delenv("STY", raising=False)
    monkeypatch.setenv("URA_FRAMEWORK_NAMED_SESSION", expected)
    assert installer._inside_session(args, lock, layout, ["pyrit"])


@pytest.mark.parametrize("ambient_marker", ["TMUX", "STY"])
def test_ambient_session_marker_still_dispatches_owned_named_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ambient_marker: str
) -> None:
    lock = {"lock_id": "a" * 64}
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    args = installer.argparse.Namespace(
        command="verify",
        python=None,
        session_name_proof=None,
        session_policy="auto",
    )
    monkeypatch.setenv(ambient_marker, "unowned-session")
    monkeypatch.delenv("URA_FRAMEWORK_NAMED_SESSION", raising=False)
    expected = {"status": "running", "session_name": "owned"}
    monkeypatch.setattr(installer, "_launch_session", lambda *_args: expected)
    assert not installer._inside_session(args, lock, layout, ["pyrit"])
    assert installer._maybe_session(args, lock, layout, ["pyrit"]) == expected


@pytest.mark.skipif(os.name == "nt", reason="named-session integration targets Linux")
def test_actual_auto_session_records_inner_failure_without_recursing(tmp_path: Path) -> None:
    if not (shutil.which("tmux") or shutil.which("screen")):
        pytest.skip("tmux/screen unavailable")
    env_root = tmp_path / "envs"
    state_root = tmp_path / "state"
    environment = dict(os.environ)
    environment.pop("TMUX", None)
    environment.pop("STY", None)
    environment["OPENAI_API_KEY"] = "hostile-session-sentinel"
    result = subprocess.run(
        [
            sys.executable,
            str(Path(installer.__file__).resolve()),
            "verify",
            "--lock",
            str(LOCK_PATH),
            "--env-root",
            str(env_root),
            "--state-root",
            str(state_root),
            "--only",
            "pyrit",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    launched = json.loads(result.stdout)
    assert launched["status"] == "running"
    if launched["launcher"] == "tmux":
        socket_name = installer._tmux_socket_name(launched["session_name"])
        assert launched["attach_command"] == (
            f"tmux -L {socket_name} attach -t {launched['session_name']}"
        )
    marker = state_root / launched["exit_marker"]
    deadline = time.monotonic() + 30
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert marker.read_text(encoding="utf-8").strip() == "2"
    log = (state_root / launched["log"]).read_text(encoding="utf-8", errors="replace")
    assert "hostile-session-sentinel" not in log
    assert str(tmp_path) not in log
    events = (state_root / "task-log.jsonl").read_text(encoding="utf-8").splitlines()
    assert sum(json.loads(line)["event"] == "campaign_start" for line in events) == 1
    assert json.loads(events[-1])["event"] == "campaign_end"
    assert json.loads(events[-1])["status"] == "failed"


def test_bad_python_identity_still_creates_terminal_ui_campaign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_root = tmp_path / "envs"
    state_root = tmp_path / "framework-runtime-test"
    bad_python = tmp_path / "bad-python"
    bad_python.write_bytes(b"not python")
    monkeypatch.setenv("URA_FRAMEWORK_INSTALLER_TESTING", "1")
    result = installer.main(
        [
            "verify",
            "--lock",
            str(LOCK_PATH),
            "--env-root",
            str(env_root),
            "--state-root",
            str(state_root),
            "--python",
            str(bad_python),
            "--only",
            "pyrit",
            "--session-policy",
            "off",
        ]
    )
    assert result == 2
    assert (state_root / "ENGINEERING_ONLY.json").is_file()
    events = [
        json.loads(line)
        for line in (state_root / "task-log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[0]["event"] == "campaign_start"
    assert events[-1]["event"] == "campaign_end"
    assert events[-1]["status"] == "failed"


def test_engineering_campaign_is_jobs_compatible_and_path_free(tmp_path: Path) -> None:
    campaign = tmp_path / "campaign"
    lock = _minimal_lock()
    installer._ensure_campaign(campaign, lock)
    installer._append_campaign_event(
        campaign,
        {"event": "campaign_start", "task": "bootstrap", "status": "running", "detail": "install"},
    )
    installer._append_campaign_event(
        campaign,
        {"event": "task_start", "task": "framework-runtime-pyrit", "status": "running"},
    )
    installer._append_campaign_event(
        campaign,
        {"event": "task_end", "task": "framework-runtime-pyrit", "status": "passed"},
    )
    installer._append_campaign_event(
        campaign,
        {"event": "campaign_end", "task": "bootstrap", "status": "passed"},
    )
    marker = (campaign / "ENGINEERING_ONLY.json").read_text(encoding="utf-8")
    task_log = (campaign / "task-log.jsonl").read_text(encoding="utf-8")
    assert str(tmp_path) not in marker + task_log
    assert json.loads(marker)["hard_stop_hours"] * 60 * 60 == installer.MAX_SESSION_SECONDS
    from experiments.rig_web_app.campaigns import _load_campaign

    observed = _load_campaign(campaign)
    assert observed is not None
    assert observed.state == "complete"
    assert observed.model_tasks == ()


def test_plan_only_selects_requested_framework(tmp_path: Path) -> None:
    lock = installer.load_lock(LOCK_PATH)
    selected = installer.select_frameworks(lock, ["PyRIT"])
    assert [entry["name"] for entry in selected] == ["pyrit"]
    result = installer.plan(lock, installer.Layout(tmp_path / "envs", tmp_path / "state"), selected)
    assert result["actions"] == [
        {"framework": "pyrit", "env_slug": "pyrit-0.14.0-py312", "action": "install"}
    ]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_new_lock_migrates_old_seal_receipt_to_new_store(tmp_path: Path) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    layout.store_root.mkdir(parents=True)
    old_lock_id = "a" * 64
    new_lock_id = "b" * 64
    entry = {
        "name": "pyrit",
        "version": "0.14.0",
        "env_slug": "pyrit-0.14.0-py312",
        "runtime": "python",
    }
    old_store = layout.store(entry["env_slug"], old_lock_id)
    old_store.mkdir()
    old_receipt = installer._receipt(
        entry,
        {"lock_id": old_lock_id},
        {"inventory_sha256": "c" * 64, "distribution_count": 1},
        {
            "schema": "ura-framework-runtime-content-seal/1",
            "sha256": "d" * 64,
            "file_count": 0,
            "byte_count": 0,
        },
    )
    (old_store / installer.RECEIPT_NAME).write_bytes(installer._canonical_json(old_receipt))
    try:
        installer._publish_alias(layout, entry["env_slug"], old_store)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    new_store = layout.store(entry["env_slug"], new_lock_id)
    assert new_store != old_store
    assert not installer._receipt_matches(old_receipt, entry, old_lock_id)
    result = installer.plan({"lock_id": new_lock_id}, layout, [entry])

    assert result["actions"] == [
        {
            "framework": "pyrit",
            "env_slug": "pyrit-0.14.0-py312",
            "action": "install",
        }
    ]
    assert old_store.is_dir()
    assert not new_store.exists()


# --------------------------------------------------------------------------- #
# Fail-closed guards on the sealed runtime path (install_one / verify_one /
# _verify_published / _publish_alias / CLI), each on a real temp Layout.
# --------------------------------------------------------------------------- #

_GUARD_ENTRY = {
    "name": "pyrit",
    "version": "0.14.0",
    "env_slug": "pyrit-0.14.0-py312",
    "runtime": "python",
}
_GUARD_LOCK = {"lock_id": "a" * 64}


def _publish_or_skip(layout: installer.Layout, slug: str, store: Path) -> None:
    try:
        installer._publish_alias(layout, slug, store)
    except OSError:
        pytest.skip("symlink creation is unavailable")


def test_install_refuses_unverified_existing_environment_and_plan_reports_blocked(
    tmp_path: Path,
) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    layout.store_root.mkdir(parents=True)
    final = layout.final(_GUARD_ENTRY["env_slug"])
    (final / "bin").mkdir(parents=True)  # an unmanaged, hand-made environment
    (final / "bin" / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    with pytest.raises(
        installer.InstallerError, match="refusing to replace unverified existing environment"
    ):
        installer.install_one(_GUARD_ENTRY, _GUARD_LOCK, layout, resume=False)
    with pytest.raises(
        installer.InstallerError, match="refusing to replace unverified existing environment"
    ):
        installer.install_one(_GUARD_ENTRY, _GUARD_LOCK, layout, resume=True)
    assert installer.plan(_GUARD_LOCK, layout, [_GUARD_ENTRY])["actions"] == [
        {
            "framework": "pyrit",
            "env_slug": "pyrit-0.14.0-py312",
            "action": "blocked-existing-unverified",
        }
    ]
    assert (final / "bin" / "python").is_file()  # never touched
    assert not layout.store(_GUARD_ENTRY["env_slug"], _GUARD_LOCK["lock_id"]).exists()


def test_install_requires_resume_for_existing_staging_and_rejects_foreign_staging_lock(
    tmp_path: Path,
) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    store = layout.store(_GUARD_ENTRY["env_slug"], _GUARD_LOCK["lock_id"])
    store.mkdir(parents=True)
    with pytest.raises(installer.InstallerError, match="staging exists for pyrit; use resume"):
        installer.install_one(_GUARD_ENTRY, _GUARD_LOCK, layout, resume=False)
    assert installer.plan(_GUARD_LOCK, layout, [_GUARD_ENTRY])["actions"][0]["action"] == "resume"
    installer._write_state(store, {"lock_id": "b" * 64, "completed": []})
    with pytest.raises(installer.InstallerError, match="staging lock mismatch for pyrit"):
        installer.install_one(_GUARD_ENTRY, _GUARD_LOCK, layout, resume=True)
    # the foreign staging state is left in place for inspection
    assert installer._read_state(store)["lock_id"] == "b" * 64
    assert not layout.final(_GUARD_ENTRY["env_slug"]).exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_verify_requires_published_alias_and_matching_receipt(tmp_path: Path) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    store = layout.store(_GUARD_ENTRY["env_slug"], _GUARD_LOCK["lock_id"])
    store.mkdir(parents=True)
    with pytest.raises(installer.InstallerError, match="valid runtime alias not found for pyrit"):
        installer.verify_one(_GUARD_ENTRY, _GUARD_LOCK, layout)
    _publish_or_skip(layout, _GUARD_ENTRY["env_slug"], store)
    with pytest.raises(installer.InstallerError, match="valid receipt not found for pyrit"):
        installer.verify_one(_GUARD_ENTRY, _GUARD_LOCK, layout)
    foreign = installer._receipt(
        _GUARD_ENTRY,
        {"lock_id": "b" * 64},
        {"inventory_sha256": "c" * 64, "distribution_count": 1},
        {
            "schema": installer.CONTENT_SEAL_SCHEMA,
            "sha256": "d" * 64,
            "file_count": 0,
            "byte_count": 0,
        },
    )
    (store / installer.RECEIPT_NAME).write_bytes(installer._canonical_json(foreign))
    with pytest.raises(installer.InstallerError, match="valid receipt not found for pyrit"):
        installer.verify_one(_GUARD_ENTRY, _GUARD_LOCK, layout)
    # a published alias whose store lacks the interpreter is not a usable runtime
    with pytest.raises(installer.InstallerError, match="runtime interpreter is missing"):
        installer.canonical_python_interpreter(_GUARD_ENTRY, _GUARD_LOCK, layout)


def test_verify_published_rejects_inventory_drift_before_the_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    final = layout.final(_GUARD_ENTRY["env_slug"])
    final.mkdir(parents=True)
    monkeypatch.setattr(
        installer,
        "_verify_runtime",
        lambda _entry, _env_dir, _runner: {"inventory_sha256": "e" * 64, "distribution_count": 1},
    )
    monkeypatch.setattr(
        installer,
        "_verify_content_seal",
        lambda *_args, **_kwargs: pytest.fail("seal must not be consulted after an inventory mismatch"),
    )
    receipt = {"inventory_sha256": "c" * 64}
    with pytest.raises(installer.InstallerError, match="receipt inventory mismatch for pyrit"):
        installer._verify_published(
            _GUARD_ENTRY, _GUARD_LOCK, layout, final, receipt, log_prefix="verify-"
        )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink unavailable")
def test_publish_alias_refuses_foreign_alias_or_directory(tmp_path: Path) -> None:
    layout = installer.Layout(tmp_path / "envs", tmp_path / "state")
    store = layout.store(_GUARD_ENTRY["env_slug"], _GUARD_LOCK["lock_id"])
    store.mkdir(parents=True)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    final = layout.final(_GUARD_ENTRY["env_slug"])
    try:
        os.symlink(foreign, final, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(
        installer.InstallerError, match="refusing to replace existing runtime alias: pyrit"
    ):
        installer._publish_alias(layout, _GUARD_ENTRY["env_slug"], store)
    assert final.resolve() == foreign.resolve()  # the foreign link is untouched
    final.unlink()
    final.mkdir()
    with pytest.raises(
        installer.InstallerError, match="refusing to replace existing runtime alias: pyrit"
    ):
        installer._publish_alias(layout, _GUARD_ENTRY["env_slug"], store)
    assert final.is_dir() and not final.is_symlink()


def test_cli_requires_python_for_python_runtimes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("URA_FRAMEWORK_INSTALLER_TESTING", "1")
    # main() only sets the process-wide interpreter when --python is given, so
    # start from the pristine module state regardless of earlier tests.
    monkeypatch.setattr(installer, "_ACTIVE_PYTHON", None)
    result = installer.main(
        [
            "verify",
            "--lock",
            str(LOCK_PATH),
            "--env-root",
            str(tmp_path / "envs"),
            "--state-root",
            str(tmp_path / "state"),
            "--only",
            "pyrit",
            "--session-policy",
            "off",
        ]
    )
    assert result == 2
    failure = json.loads(capsys.readouterr().err.strip())
    assert failure == {"status": "failed", "error": "--python is required for Python runtimes"}
    events = [
        json.loads(line)
        for line in (tmp_path / "state" / "task-log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events[-1]["event"] == "campaign_end" and events[-1]["status"] == "failed"


# --------------------------------------------------------------------------- #
# distro/install.sh wiring to this installer (bash; a stub venv python
# intercepts the installer module and passes everything else through to the
# real interpreter).
# --------------------------------------------------------------------------- #

DISTRO_INSTALL = Path(installer.__file__).resolve().parents[1] / "distro" / "install.sh"
DISTRO_REPIN = Path(installer.__file__).resolve().parents[1] / "distro" / "repin.sh"
EXAMPLE_REGISTRY = (
    Path(installer.__file__).resolve().parents[1]
    / "experiments"
    / "rig"
    / "source-instances.example.json"
)

_STUB_PYTHON = r"""#!/usr/bin/env bash
# Stub venv python for distro/install.sh tests: intercept the framework
# runtime installer module (record argv, emulate the session contract),
# pass every other invocation through to the real interpreter.
if [ "${1:-}" = "-m" ] && [ "${2:-}" = "experiments.framework_runtime_installer" ]; then
  shift 2
  { printf '%s\n' "$@"; printf -- '--END--\n'; } >> "__CALLS__"
  command=$1
  state_root=""
  while [ $# -gt 0 ]; do
    case "$1" in --state-root) state_root=$2; shift 2 ;; *) shift ;; esac
  done
  case "$command" in
    plan)
      echo '{"schema":"ura-framework-runtime-plan/1","lock_id":"stub","actions":[]}'
      exit 0 ;;
    install|verify)
      name="ura-framework-$command-stub"
      mkdir -p "$state_root/sessions"
      printf '%s\n' "${URA_STUB_EXIT_RC:-0}" > "$state_root/sessions/$name.exit"
      printf 'stub %s transcript\n' "$command" > "$state_root/sessions/$name.log"
      printf '{"schema":"ura-framework-runtime-session/1","launcher":"tmux","session_name":"%s","attach_command":"tmux -L stub attach -t %s","log":"sessions/%s.log","exit_marker":"sessions/%s.exit","status":"running"}\n' "$name" "$name" "$name" "$name"
      exit 0 ;;
  esac
  echo '{"status":"failed","error":"stub: unsupported command"}' >&2
  exit 2
fi
exec "__REAL__" "$@"
"""


def _bash_or_skip() -> str:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    probe = subprocess.run([bash, "-c", "printf ok"], capture_output=True, text=True, check=False)
    if probe.returncode != 0 or probe.stdout != "ok":
        pytest.skip("bash is not usable")
    return bash


class _DistroSandbox:
    """Temp HOME / URA_DATA / URA_ROOT for driving distro/install.sh phases."""

    def __init__(self, tmp_path: Path, *, with_venv: bool = True) -> None:
        self.bash = _bash_or_skip()
        self.home = tmp_path / "home"
        self.data = tmp_path / "data"
        self.root = tmp_path / "repo"
        self.stub_bin = tmp_path / "stub-bin"
        self.calls = tmp_path / "installer-calls.log"
        for directory in (self.home, self.data, self.stub_bin, self.root / "experiments" / "rig"):
            directory.mkdir(parents=True)
        shutil.copy(LOCK_PATH, self.root / "experiments" / "framework_runtime_lock.json")
        shutil.copy(EXAMPLE_REGISTRY, self.root / "experiments" / "rig" / "source-instances.example.json")
        tmux = self.stub_bin / "tmux"
        tmux.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        tmux.chmod(0o755)
        if with_venv:
            python = self.root / ".venv" / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text(
                _STUB_PYTHON.replace("__CALLS__", self.calls.as_posix()).replace(
                    "__REAL__", Path(sys.executable).as_posix()
                ),
                encoding="utf-8",
            )
            python.chmod(0o755)

    def run(self, *phases: str, **extra_env: str) -> subprocess.CompletedProcess[str]:
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("URA_") and key not in {"HF_TOKEN", "HOME"}
        }
        env.update(
            HOME=self.home.as_posix(),
            URA_DATA=self.data.as_posix(),
            URA_ROOT=self.root.as_posix(),
            URA_PYTHON=Path(sys.executable).as_posix(),
            PATH=str(self.stub_bin) + os.pathsep + os.environ.get("PATH", ""),
        )
        env.update(extra_env)
        return subprocess.run(
            [self.bash, str(DISTRO_INSTALL), *phases],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(self.root),
            timeout=180,
            check=False,
        )

    def installer_calls(self) -> list[list[str]]:
        if not self.calls.is_file():
            return []
        blocks = self.calls.read_text(encoding="utf-8").split("--END--\n")
        return [block.splitlines() for block in blocks if block.strip()]


def test_distro_runtimes_phase_passes_lock_roots_and_python_then_verifies(tmp_path: Path) -> None:
    sandbox = _DistroSandbox(tmp_path)
    result = sandbox.run("runtimes")
    assert result.returncode == 0, result.stdout + result.stderr
    lock_id = json.loads(LOCK_PATH.read_text(encoding="utf-8"))["lock_id"]
    lock = (sandbox.root / "experiments" / "framework_runtime_lock.json").as_posix()
    env_root = f"{sandbox.data.as_posix()}/framework-venvs"
    state_root = f"{sandbox.data.as_posix()}/runs/engineering/framework-runtime-{lock_id[:12]}"
    calls = sandbox.installer_calls()
    assert [call[0] for call in calls] == ["plan", "install", "verify"]
    assert calls[0] == ["plan", "--lock", lock, "--env-root", env_root, "--state-root", state_root]
    for call in calls[1:]:
        assert call[1:7] == ["--lock", lock, "--env-root", env_root, "--state-root", state_root]
        assert call[7] == "--python" and len(call) == 9
        assert Path(call[8]).name.startswith("python")
        assert "--session-policy" not in call
    logs = sandbox.data / "acquire-logs"
    assert (logs / "runtimes-install.status").read_text(encoding="utf-8").strip() == "OK"
    assert (logs / "runtimes-verify.status").read_text(encoding="utf-8").strip() == "OK"
    assert (logs / "runtimes-install.done").exists() and (logs / "runtimes-verify.done").exists()
    assert "[ok]   runtimes-install" in result.stdout
    assert "[ok]   runtimes-verify" in result.stdout
    install_log = (logs / "runtimes-install.log").read_text(encoding="utf-8")
    assert "session ura-framework-install-stub exit 0" in install_log
    assert "stub install transcript" in install_log
    assert "[warn] framework runtimes need" not in result.stdout


def test_distro_runtimes_phase_ledgers_a_failed_session_and_skips_verify(tmp_path: Path) -> None:
    sandbox = _DistroSandbox(tmp_path)
    result = sandbox.run("runtimes", URA_STUB_EXIT_RC="2")
    assert result.returncode != 0
    assert [call[0] for call in sandbox.installer_calls()] == ["plan", "install"]
    logs = sandbox.data / "acquire-logs"
    assert (logs / "runtimes-install.status").read_text(encoding="utf-8").strip() == "FAIL:2"
    assert not (logs / "runtimes-install.done").exists()
    assert not (logs / "runtimes-verify.status").exists()
    assert "[FAIL] runtimes-install" in result.stdout
    assert "runtimes-verify skipped" in result.stdout
    assert "FAILED this run" in result.stdout


def test_distro_prereqs_fail_closed_without_a_cpython_312_or_313_interpreter(tmp_path: Path) -> None:
    sandbox = _DistroSandbox(tmp_path, with_venv=False)
    bad = sandbox.stub_bin / "old-python"
    bad.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")  # fails the version probe
    bad.chmod(0o755)
    result = sandbox.run("summary", URA_PYTHON=bad.as_posix())
    assert result.returncode == 3, result.stdout + result.stderr
    assert f"[FAIL] URA_PYTHON={bad.as_posix()} is not a CPython >=3.12,<3.14 interpreter" in result.stderr
    assert "set URA_PYTHON=/path/to/python3.12" in result.stdout
    assert "distro/install.sh: done" not in result.stdout  # no phase ran
    assert not (sandbox.root / ".venv").exists()


def test_distro_locators_seed_registry_from_example_and_bind_repo_interpreter(tmp_path: Path) -> None:
    sandbox = _DistroSandbox(tmp_path)
    example = json.loads(EXAMPLE_REGISTRY.read_text(encoding="utf-8"))
    aggregator_keys = (
        "saladbench_base", "airbench_full", "xstest_full",
        "simplesafetytests_full", "decodingtrust_stereotype", "holisafe_full",
    )
    registry_path = sandbox.root / "experiments" / "source-instances.json"

    first = sandbox.run("locators")
    assert first.returncode == 0, first.stdout + first.stderr
    assert json.loads(registry_path.read_text(encoding="utf-8")) == example
    assert f"source-instances.json arms: {len(example)} (seeded from the example)" in first.stdout
    campaign_env = (sandbox.home / ".ura_campaign_env").read_text(encoding="utf-8")
    assert f'export URA_REPO="{sandbox.root.as_posix()}"\n' in campaign_env
    assert 'export URA_PY="$URA_REPO/.venv/bin/python"\n' in campaign_env
    assert "# --- URA source locators (distro/install.sh) ---" in campaign_env
    assert f'export URA_CORPORA="{sandbox.data.as_posix()}/corpora"' in campaign_env
    assert "MISSING URA_BIPIA_TEST_QA_PATH" in first.stdout
    assert "(blocked: licensed NewsQA base" in first.stdout

    # Drifted labels (the old hand-written literals) are reconciled to the
    # example, a missing aggregator arm is added, and operator keys survive.
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    registry["xstest_full"]["source_label"] = "XSTest exaggerated-safety (aggregator)"
    del registry["holisafe_full"]
    registry["custom_arm"] = {"converter": "xstest", "path_env": "URA_CUSTOM_PATH",
                              "source_label": "operator arm", "split": "x"}
    registry_path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")
    second = sandbox.run("locators")
    assert second.returncode == 0, second.stdout + second.stderr
    assert "reconciled xstest_full" in second.stdout
    assert "added holisafe_full" in second.stdout
    merged = json.loads(registry_path.read_text(encoding="utf-8"))
    assert {key: merged[key] for key in aggregator_keys} == {key: example[key] for key in aggregator_keys}
    assert merged["custom_arm"] == registry["custom_arm"]
    assert "(aggregator)" not in json.dumps(merged)
    # the interpreter bindings and the locator block are appended exactly once
    campaign_env = (sandbox.home / ".ura_campaign_env").read_text(encoding="utf-8")
    assert campaign_env.count("export URA_REPO=") == 1
    assert campaign_env.count("export URA_PY=") == 1
    assert campaign_env.count("# --- URA source locators") == 1


def test_distro_installer_sources_canonical_ura_env_last() -> None:
    text = DISTRO_INSTALL.read_text(encoding="utf-8")
    assert 'SECRETS_ENV="$HOME/.ura_env"' in text
    assert 'SECRETS_LEGACY="$HOME/.ura_secrets"' in text
    # top-level sourcing: legacy first, canonical last (wins)
    top_legacy = text.index('[ -f "$SECRETS_LEGACY" ] && source "$SECRETS_LEGACY"')
    top_env = text.index('[ -f "$SECRETS_ENV" ] && source "$SECRETS_ENV"')
    assert top_legacy < top_env
    # the generated console launcher keeps the same order
    launcher = text[text.index('cat > "$URA_DATA/console-launch.sh"'):text.index("\nLAUNCH\n")]
    assert launcher.index("$SECRETS_LEGACY") < launcher.index("$SECRETS_ENV")
    assert '.ura_env" ] && source' not in text.replace("$SECRETS_ENV", "")
    # prereqs never adopt the system python3 blindly and the venv is built with
    # the resolved interpreter; the runtimes phase uses the venv's base
    assert '"$URA_PYTHON" -m venv "$VENV"' in text
    assert "python3 -m venv" not in text
    assert "sys._base_executable" in text
    assert '|| echo "  [warn] framework runtimes need' not in text
    # ollama is pinned and checksum-verified against the release's own list
    assert "OLLAMA_VERSION=0.32.13" in text
    assert re.search(r"OLLAMA_SHA256=[0-9a-f]{64}", text)
    assert "sha256sum.txt" in text and "ollama.com/download" not in text
    # the console relaunch kills consoles by the anchored module invocation only
    assert "pkill -f -- '-m experiments\\.rig_web( |$)'" in text
    assert "pkill -f 'experiments.rig_web'" not in text
    # the runtimes phase names the missing venv instead of an unreadable lock
    assert "runtimes-plan (venv missing:" in text
    assert text.index("runtimes-plan (venv missing:") < text.index("runtimes-plan (cannot read")


def test_distro_runtimes_phase_fails_closed_without_the_venv(tmp_path: Path) -> None:
    sandbox = _DistroSandbox(tmp_path, with_venv=False)
    result = sandbox.run("runtimes")
    assert result.returncode != 0, result.stdout + result.stderr
    venv_python = (sandbox.root / ".venv" / "bin" / "python").as_posix()
    assert f"[FAIL] runtimes-plan (venv missing: {venv_python} - run distro/install.sh deps first)" in result.stdout
    assert "cannot read" not in result.stdout
    assert "FAILED this run" in result.stdout
    assert sandbox.installer_calls() == []
    assert not (sandbox.data / "acquire-logs" / "runtimes-install.status").exists()


def test_distro_prereqs_report_an_ignored_ura_python_when_the_venv_is_adopted(tmp_path: Path) -> None:
    sandbox = _DistroSandbox(tmp_path)
    # a second, valid CPython entry point that is NOT the venv's base interpreter
    other = sandbox.stub_bin / "other-python"
    other.write_text(
        f'#!/usr/bin/env bash\nexec "{Path(sys.executable).as_posix()}" "$@"\n', encoding="utf-8"
    )
    other.chmod(0o755)
    venv = (sandbox.root / ".venv").as_posix()

    ignored = sandbox.run("summary", URA_PYTHON=other.as_posix())
    assert f"[warn] URA_PYTHON={other.as_posix()} ignored: existing {venv} (base " in ignored.stdout
    assert "is adopted" in ignored.stdout
    assert "[FAIL]" not in ignored.stdout + ignored.stderr

    base = getattr(sys, "_base_executable", sys.executable)
    adopted = sandbox.run("summary", URA_PYTHON=Path(base).as_posix())
    assert "ignored: existing" not in adopted.stdout
    assert "[FAIL]" not in adopted.stdout + adopted.stderr


def test_distro_repin_script_is_fail_closed_and_sources_canonical_ura_env_last() -> None:
    bash = _bash_or_skip()
    syntax = subprocess.run([bash, "-n", str(DISTRO_REPIN)], capture_output=True, text=True, check=False)
    assert syntax.returncode == 0, syntax.stderr
    text = DISTRO_REPIN.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    # the expected commit is a full 40-hex id, checked before anything runs
    assert '[[ "$REF_EXPECTED" =~ ^[0-9a-f]{40}$ ]] ||' in text
    # hygiene (anchored module invocations) precedes the clean-env gate
    run_matrix_kill = text.index("pkill -f -- '-m experiments\\.run_matrix( |$)'")
    rig_web_kill = text.index("pkill -f -- '-m experiments\\.rig_web( |$)'")
    gate = text.index("-m pytest -q -p no:cacheprovider")
    assert run_matrix_kill < gate and rig_web_kill < gate
    assert "pkill -f 'experiments." not in text
    # the scrub unsets every URA_* name, digits included
    assert "grep -oE '^URA_[A-Za-z0-9_]+'" in text
    assert "^URA_[A-Z_]+" not in text
    # secrets: legacy ~/.ura_secrets first, canonical ~/.ura_env last (wins),
    # both in the top-level block and in the detached console child
    child_start = text.index("setsid bash -c '")
    top, child = text[:child_start], text[child_start:]
    for block in (top, child):
        legacy = block.index('[ -f "$HOME/.ura_secrets" ] && source "$HOME/.ura_secrets"')
        canonical = block.index('[ -f "$HOME/.ura_env" ] && source "$HOME/.ura_env"')
        assert legacy < canonical
    # the console child carries the same login env as install.sh's launcher
    profile = child.index("[ -f /etc/profile ] && source /etc/profile")
    home_profile = child.index('[ -f "$HOME/.profile" ] && source "$HOME/.profile"')
    assert profile < home_profile < child.index('[ -f "$HOME/.ura_secrets" ]')
    # receipt validation and the source-receipt revalidation abort explicitly
    # (a failure on the left of '&&' would not trip errexit)
    assert '--validate "$MANIFEST" --sha256 "$SHA" >/dev/null \\\n  || { echo "revision receipt INVALID' in text
    assert '>/dev/null && echo "revision receipt valid"' not in text
    assert '|| { echo "source receipt: NOT VALID' in text and "exit 1; }" in text[text.index("source receipt: NOT VALID"):]
    # the executing copy is compared with the deployed commit's distro/repin.sh
    assert 'git cat-file -e "$REF:distro/repin.sh"' in text
    assert 'git show "$REF:distro/repin.sh" | cmp -s - "$0"' in text


# Petri's released pyproject.toml, reduced to the fields that decide the
# version: the project name, a dynamic version, and the hatch-vcs backend that
# reads it from tags the pinned depth-1 checkout does not have.
_PETRI_PYPROJECT = """
[project]
name = "inspect_petri"
dynamic = ["version"]
requires-python = ">=3.12"

[build-system]
requires = ["hatchling", "hatch-vcs"]
build-backend = "hatchling.build"

[tool.hatch.version]
source = "vcs"

[tool.hatch.version.raw-options]
local_scheme = "no-local-version"
"""


def _petri_entry(distributions: list[str]) -> dict:
    return {
        "name": "petri",
        "expected_inventory": {"distributions": distributions, "sha256": "x" * 64},
    }


def test_vcs_versioned_source_build_declares_the_locked_version(tmp_path: Path) -> None:
    # git describe at the pinned commit yields 3.0.11-14-g1f41e29, which
    # setuptools-scm renders as 3.0.12.dev14 under this project's schemes. The
    # depth-1 checkout carries no tags at all, so the backend would silently
    # fall back to a placeholder and the install would disagree with the lock.
    (tmp_path / "pyproject.toml").write_text(_PETRI_PYPROJECT, encoding="utf-8")
    entry = _petri_entry(["inspect-petri==3.0.12.dev14", "anyio==4.13.0"])
    assert installer._vcs_pretend_version(tmp_path, entry, "petri") == {
        "SETUPTOOLS_SCM_PRETEND_VERSION": "3.0.12.dev14",
        "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_INSPECT_PETRI": "3.0.12.dev14",
    }


def test_vcs_version_pinning_only_applies_where_it_is_needed(tmp_path: Path) -> None:
    entry = _petri_entry(["inspect-petri==3.0.12.dev14"])

    # No pyproject at all, e.g. a plain setup.py source.
    assert installer._vcs_pretend_version(tmp_path, entry, "petri") == {}

    # A static version needs no help even with hatch-vcs present.
    static = _PETRI_PYPROJECT.replace('dynamic = ["version"]', 'version = "1.2.3"')
    (tmp_path / "pyproject.toml").write_text(static, encoding="utf-8")
    assert installer._vcs_pretend_version(tmp_path, entry, "petri") == {}

    # A dynamic version from a NON-VCS backend is read from the source itself,
    # so the checkout can compute it and nothing is declared.
    other = _PETRI_PYPROJECT.replace(
        'requires = ["hatchling", "hatch-vcs"]', 'requires = ["hatchling"]'
    )
    (tmp_path / "pyproject.toml").write_text(other, encoding="utf-8")
    assert installer._vcs_pretend_version(tmp_path, entry, "petri") == {}

    # setuptools-scm is recognised the same way, including a pinned requirement.
    scm = _PETRI_PYPROJECT.replace(
        'requires = ["hatchling", "hatch-vcs"]', 'requires = ["setuptools", "setuptools_scm>=8"]'
    )
    (tmp_path / "pyproject.toml").write_text(scm, encoding="utf-8")
    assert installer._vcs_pretend_version(tmp_path, entry, "petri") == {
        "SETUPTOOLS_SCM_PRETEND_VERSION": "3.0.12.dev14",
        "SETUPTOOLS_SCM_PRETEND_VERSION_FOR_INSPECT_PETRI": "3.0.12.dev14",
    }


def test_vcs_version_pinning_fails_closed_without_a_locked_version(tmp_path: Path) -> None:
    # Guessing here would install a distribution the lock never described.
    (tmp_path / "pyproject.toml").write_text(_PETRI_PYPROJECT, encoding="utf-8")
    entry = _petri_entry(["anyio==4.13.0"])
    with pytest.raises(installer.InstallerError, match="lock records no version"):
        installer._vcs_pretend_version(tmp_path, entry, "petri")


def _npm_tree_with_optional_peer(invalid: str) -> dict:
    return {
        "problems": ["invalid: gcp-metadata@8.1.4 /store/node_modules/gcp-metadata"],
        "dependencies": {
            "promptfoo": {
                "version": "0.121.15",
                "dependencies": {
                    # npm ls --all repeats a deduplicated node at every path it
                    # is reachable from, so one problem surfaces twice here.
                    "natural": {"dependencies": {
                        "gcp-metadata": {"version": "8.1.4", "invalid": invalid},
                    }},
                    "googleapis-common": {"dependencies": {
                        "gcp-metadata": {"version": "8.1.4", "invalid": invalid},
                    }},
                },
            },
        },
    }


def _write_requirer(env_dir: Path, relative: str, *, optional: bool) -> None:
    package = env_dir / relative
    package.mkdir(parents=True, exist_ok=True)
    manifest = {
        "name": "mongodb",
        "version": "7.5.0",
        "peerDependencies": {"gcp-metadata": "^7.0.1"},
    }
    if optional:
        manifest["peerDependenciesMeta"] = {"gcp-metadata": {"optional": True}}
    (package / "package.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_npm_verification_tolerates_only_an_unsatisfied_optional_peer(
    tmp_path: Path,
) -> None:
    # promptfoo's real tree: mongodb declares gcp-metadata as an OPTIONAL peer
    # (peerDependenciesMeta.optional), npm therefore does not nest a 7.x copy,
    # the hoisted 8.1.4 does not satisfy ^7.0.1, and npm ls exits 1. An optional
    # peer is allowed to be unsatisfied, so this must verify - and be recorded,
    # not hidden.
    relative = "node_modules/mongoose/node_modules/mongodb"
    invalid = f'"^7.0.1" from {relative}'
    _write_requirer(tmp_path, relative, optional=True)
    tolerated = installer._validate_npm_ls_output(
        json.dumps(_npm_tree_with_optional_peer(invalid)),
        {"name": "promptfoo"},
        tmp_path,
        # npm reports ELSPROBLEMS and exits 1 for this tree; a fixture that
        # passed zero here would model a shape npm never produces.
        returncode=1,
    )
    assert tolerated == [f"gcp-metadata ^7.0.1 optional peer of {relative}"]


def test_npm_verification_still_fails_on_a_required_peer_or_other_problem(
    tmp_path: Path,
) -> None:
    relative = "node_modules/mongoose/node_modules/mongodb"
    invalid = f'"^7.0.1" from {relative}'
    tree = _npm_tree_with_optional_peer(invalid)

    # The same shape with a REQUIRED peer must stay fatal.
    _write_requirer(tmp_path, relative, optional=False)
    with pytest.raises(installer.InstallerError, match="dependency problems"):
        installer._validate_npm_ls_output(
            json.dumps(tree), {"name": "promptfoo"}, tmp_path, returncode=1
        )

    # So must a requirer whose manifest cannot be read at all.
    shutil.rmtree(tmp_path / "node_modules")
    with pytest.raises(installer.InstallerError, match="dependency problems"):
        installer._validate_npm_ls_output(
            json.dumps(tree), {"name": "promptfoo"}, tmp_path, returncode=1
        )

    # And any problem that is not an invalid resolution, even mixed with one
    # that would otherwise be tolerated.
    _write_requirer(tmp_path, relative, optional=True)
    mixed = _npm_tree_with_optional_peer(invalid)
    mixed["problems"] = mixed["problems"] + [
        "extraneous: junk@1.0.0 /store/node_modules/junk"
    ]
    with pytest.raises(installer.InstallerError, match="dependency problems"):
        installer._validate_npm_ls_output(
            json.dumps(mixed), {"name": "promptfoo"}, tmp_path, returncode=1
        )

    missing = {
        "problems": ["missing: left-pad@1.0.0, required by promptfoo"],
        "dependencies": {"promptfoo": {"version": "0.121.15"}},
    }
    with pytest.raises(installer.InstallerError, match="dependency problems"):
        installer._validate_npm_ls_output(
            json.dumps(missing), {"name": "promptfoo"}, tmp_path, returncode=1
        )


def test_npm_verification_requires_the_exit_code_to_agree_with_the_tree(
    tmp_path: Path,
) -> None:
    # The exit code alone cannot distinguish a broken tree from an unsatisfied
    # optional peer, so the tree is the authority - but the two signals must
    # still agree, or something is being reported that the tree does not show.
    relative = "node_modules/mongoose/node_modules/mongodb"
    invalid = f'"^7.0.1" from {relative}'
    _write_requirer(tmp_path, relative, optional=True)

    clean = {"dependencies": {"promptfoo": {"version": "0.121.15"}}}
    with pytest.raises(installer.InstallerError, match="no tolerable cause"):
        installer._validate_npm_ls_output(
            json.dumps(clean), {"name": "promptfoo"}, tmp_path, returncode=1
        )

    with pytest.raises(installer.InstallerError, match="exited zero"):
        installer._validate_npm_ls_output(
            json.dumps(_npm_tree_with_optional_peer(invalid)),
            {"name": "promptfoo"},
            tmp_path,
            returncode=0,
        )

    # A clean tree with a zero exit remains the ordinary passing case.
    assert (
        installer._validate_npm_ls_output(
            json.dumps(clean), {"name": "promptfoo"}, tmp_path, returncode=0
        )
        == []
    )


class _RecordingRunner:
    """A CommandRunner stand-in that replays canned results for _verify_node."""

    def __init__(self, npm_returncode: int, tree: dict) -> None:
        self.npm_returncode = npm_returncode
        self.tree = tree
        self.calls: list[dict[str, Any]] = []

    def run(self, argv, **kwargs):  # noqa: ANN001, ANN003 - test double
        command = [str(item) for item in argv]
        self.calls.append({"argv": command, "kwargs": kwargs})
        if len(command) == 2 and command[-1] == "--version":
            # the node probe is [node, --version]; the CLI smoke is [node, cli, --version]
            return subprocess.CompletedProcess(command, 0, stdout="v24.16.0", stderr="")
        if "ls" in command:
            allowed = kwargs.get("allowed_returncodes", (0,))
            if self.npm_returncode not in allowed:
                # exactly what the real runner does, and what made the
                # tolerated-peer classification unreachable in the campaign.
                raise installer.InstallerError(
                    f"npm command failed with exit code {self.npm_returncode}"
                )
            return subprocess.CompletedProcess(
                command, self.npm_returncode, stdout=json.dumps(self.tree), stderr=""
            )
        return subprocess.CompletedProcess(command, 0, stdout="0.121.15", stderr="")


def test_verify_node_completes_when_npm_ls_exits_on_a_tolerated_optional_peer(
    tmp_path: Path,
) -> None:
    # Regression for the campaign failure: the classification of a tolerable
    # optional peer was correct but unreachable, because npm ls exits 1 for any
    # reported problem and the command gate rejected that exit code first. This
    # drives the whole node verification, so the gate is covered too.
    relative = "node_modules/mongoose/node_modules/mongodb"
    invalid = f'"^7.0.1" from {relative}'
    _write_requirer(tmp_path, relative, optional=True)
    package = tmp_path / "node_modules" / "promptfoo"
    package.mkdir(parents=True, exist_ok=True)
    (package / "package.json").write_text(
        json.dumps({"name": "promptfoo", "version": "0.121.15"}), encoding="utf-8"
    )
    rows, digest = installer._node_installed_inventory(tmp_path)
    entry = {
        "name": "promptfoo",
        "install": {"node_runtime_dir": "node-v24.16.0", "node_version": "24.16.0"},
        "smoke": {
            "relative_cli": "node_modules/promptfoo/dist/src/main.js",
            "args": ["--version"],
            "expected_version": "0.121.15",
        },
        "expected_inventory": {
            "packages": rows,
            "package_count": len(rows),
            "sha256": digest,
        },
    }
    runner = _RecordingRunner(1, _npm_tree_with_optional_peer(invalid))
    receipt = installer._verify_node(entry, tmp_path, runner)
    assert receipt["tolerated_optional_peers"] == [
        f"gcp-metadata ^7.0.1 optional peer of {relative}"
    ]
    assert receipt["distribution_count"] == len(rows)

    # The gate really is what permits it: with the default allowance the same
    # tree fails exactly as it did on the rig.
    ls_call = next(call for call in runner.calls if "ls" in call["argv"])
    assert 1 in ls_call["kwargs"]["allowed_returncodes"]
    strict = _RecordingRunner(1, _npm_tree_with_optional_peer(invalid))
    strict.run = lambda argv, **kwargs: _RecordingRunner.run(  # type: ignore[method-assign]
        strict, argv, **{**kwargs, "allowed_returncodes": (0,)}
    )
    with pytest.raises(installer.InstallerError, match="exit code 1"):
        installer._verify_node(entry, tmp_path, strict)
