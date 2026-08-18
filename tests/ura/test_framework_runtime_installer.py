from __future__ import annotations

import hashlib
import json
import os
import py_compile
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

    wheel = installer._build_source_wheel(
        Path("python"), tmp_path / "source", wheel_dir, _Runner(), "demo"  # type: ignore[arg-type]
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
    installer._publish_alias(layout, entry["env_slug"], old_store)

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
