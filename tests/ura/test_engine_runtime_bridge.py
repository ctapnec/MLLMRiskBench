from __future__ import annotations

import hashlib
import io
import json
import os
import py_compile
import shutil
import signal
import subprocess
import sys
import time
import venv
from pathlib import Path

import pytest

from experiments import run_matrix
from ura.adapters import _engine_runtime as runtime
from ura.adapters import _engine_worker as worker
from ura.adapters._engine_common import ExternalEngineError
from ura.adapters.engines import get_attacker


def _receipt(engine: str, *, environment_digest: str = "8" * 64) -> dict:
    requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS[engine]
    value = {
        "schema": runtime.ENGINE_RUNTIME_RECEIPT_SCHEMA,
        "engine": engine,
        "distribution": requirement.distribution,
        "version": requirement.version,
        "python": {
            "implementation": "cpython",
            "version": "3.12.10",
            "cache_tag": "cpython-312",
            "executable_sha256": "1" * 64,
            "executable_bytes": 10,
        },
        "pyvenv_cfg_sha256": "2" * 64,
        "package_tree_sha256": "3" * 64,
        "package_files": 2,
        "package_bytes": 20,
        "inventory_sha256": "4" * 64,
        "environment_tree_sha256": environment_digest,
        "environment_files": 7,
        "environment_bytes": 70,
    }
    value["runtime_id"] = f"engine-runtime-{runtime._sha256_json(value)[:24]}"
    return value


def _interpreter(root: Path) -> Path:
    bindir = root / ("Scripts" if os.name == "nt" else "bin")
    bindir.mkdir(parents=True)
    target = bindir / ("python.exe" if os.name == "nt" else "python")
    shutil.copy2(sys.executable, target)
    if os.name != "nt":
        target.chmod(0o700)
    return target


def _config(entries: dict[str, tuple[Path, dict]]) -> bytes:
    return json.dumps({
        "schema": runtime.ENGINE_RUNTIME_CONFIG_SCHEMA,
        "runtimes": {
            name: {"interpreter": str(path), "receipt": receipt}
            for name, (path, receipt) in entries.items()
        },
    }, sort_keys=True).encode()


def _stub_engine_venv(
    root: Path,
    *,
    sentinel_root: Path,
) -> tuple[Path, Path, Path, Path, Path]:
    """Build a real minimal h4rm3l venv without invoking pip or the network."""

    venv.EnvBuilder(with_pip=False, symlinks=False).create(root)
    interpreter = root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    site_packages = (
        root / "Lib" / "site-packages"
        if os.name == "nt"
        else root
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    pth_sentinel = sentinel_root / "pth-executed.txt"
    sitecustomize_sentinel = sentinel_root / "sitecustomize-executed.txt"
    import_sentinel = sentinel_root / "framework-imported.txt"
    package = site_packages / "h4rm3l"
    dist_info = site_packages / "h4rm3l-0.2.4.dist-info"
    package.mkdir()
    dist_info.mkdir()
    (package / "__init__.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(import_sentinel)!r}).write_text('imported', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (package / "decorators.py").write_text(
        "def style_injection_attack(seed):\n    return 'stub::' + seed\n",
        encoding="utf-8",
    )
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: h4rm3l\nVersion: 0.2.4\n",
        encoding="utf-8",
    )
    (dist_info / "RECORD").write_text(
        "h4rm3l/__init__.py,,\n"
        "h4rm3l/decorators.py,,\n"
        "h4rm3l-0.2.4.dist-info/METADATA,,\n"
        "h4rm3l-0.2.4.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    (site_packages / "rogue.pth").write_text(
        "import pathlib; "
        f"pathlib.Path({str(pth_sentinel)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    (site_packages / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sitecustomize_sentinel)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    return (
        interpreter,
        site_packages,
        pth_sentinel,
        sitecustomize_sentinel,
        import_sentinel,
    )


def test_runtime_projection_is_path_free_and_relocation_stable(tmp_path: Path) -> None:
    first = _interpreter(tmp_path / "private-a")
    second = _interpreter(tmp_path / "private-b")
    receipt = _receipt("pyrit")
    selected_a = runtime.parse_engine_runtime_config(
        _config({"pyrit": (first, receipt)}), selected_attackers=["pyrit"]
    )
    selected_b = runtime.parse_engine_runtime_config(
        _config({"pyrit": (second, receipt)}), selected_attackers=["pyrit"]
    )
    projection_a = selected_a.public_descriptor()
    projection_b = selected_b.public_descriptor()
    assert projection_a == projection_b
    encoded = json.dumps(projection_a, sort_keys=True)
    assert str(first) not in encoded
    assert str(second) not in encoded
    assert "interpreter" not in encoded.lower()


@pytest.mark.skipif(os.name == "nt", reason="directory symlink publication is POSIX-only")
def test_runtime_config_canonicalizes_installer_directory_alias(tmp_path: Path) -> None:
    store = tmp_path / ".store" / "pyrit-lock-id"
    interpreter = _interpreter(store)
    interpreter.unlink()
    interpreter.symlink_to(Path(sys.executable))
    alias = tmp_path / "pyrit"
    alias.symlink_to(Path(".store") / store.name, target_is_directory=True)
    supplied = alias / "bin" / "python"

    selection = runtime.parse_engine_runtime_config(
        _config({"pyrit": (supplied, _receipt("pyrit"))}),
        selected_attackers=["pyrit"],
    )

    selected = selection.runtimes["pyrit"]
    assert selected._interpreter == interpreter
    assert selected._interpreter.is_symlink()
    assert selected._resolved_interpreter == Path(sys.executable).resolve(strict=True)
    assert not selected._interpreter.parent.parent.is_symlink()
    assert str(tmp_path) not in json.dumps(selection.public_descriptor(), sort_keys=True)

    second_alias = tmp_path / "deepteam"
    second_alias.symlink_to(Path(".store") / store.name, target_is_directory=True)
    with pytest.raises(ValueError, match="share one interpreter"):
        runtime.parse_engine_runtime_config(
            _config({
                "pyrit": (supplied, _receipt("pyrit")),
                "deepteam": (
                    second_alias / "bin" / "python",
                    _receipt("deepteam"),
                ),
            }),
            selected_attackers=["pyrit", "deepteam"],
        )


def test_runtime_config_rejects_duplicate_json_key(tmp_path: Path) -> None:
    interpreter = _interpreter(tmp_path / "venv")
    entry = json.dumps({
        "interpreter": str(interpreter),
        "receipt": _receipt("pyrit"),
    })
    raw = (
        '{"schema":"ura-engine-runtime-config/1","runtimes":'
        f'{{"pyrit":{entry},"pyrit":{entry}}}}}'
    ).encode()
    with pytest.raises(ValueError, match="strict JSON"):
        runtime.parse_engine_runtime_config(raw, selected_attackers=["pyrit"])


def test_runtime_config_rejects_supported_but_unselected_engine(
    tmp_path: Path,
) -> None:
    interpreter = _interpreter(tmp_path / "pyrit-venv")
    raw = json.dumps({
        "schema": runtime.ENGINE_RUNTIME_CONFIG_SCHEMA,
        "runtimes": {
            "pyrit": {
                "interpreter": str(interpreter),
                "receipt": _receipt("pyrit"),
            },
            "deepteam": "malformed-but-must-not-be-ignored",
        },
    }).encode()
    with pytest.raises(ValueError, match="unselected engines: deepteam"):
        runtime.parse_engine_runtime_config(raw, selected_attackers=["pyrit"])

    config = tmp_path / "engine-runtimes.json"
    config.write_bytes(raw)
    with pytest.raises(ValueError, match="unselected engines: deepteam"):
        run_matrix._load_engine_runtime_config(
            str(config),
            ["pyrit"],
            hashlib.sha256(raw).hexdigest(),
        )


def test_runtime_config_is_rejected_when_no_runtime_attacker_is_selected(
    tmp_path: Path,
) -> None:
    raw = json.dumps({
        "schema": runtime.ENGINE_RUNTIME_CONFIG_SCHEMA,
        "runtimes": {},
    }).encode()
    with pytest.raises(ValueError, match="not allowed without a selected"):
        runtime.parse_engine_runtime_config(raw, selected_attackers=["replay"])

    config = tmp_path / "unused-engine-runtimes.json"
    config.write_bytes(raw)
    with pytest.raises(ValueError, match="not allowed without a selected"):
        run_matrix._load_engine_runtime_config(
            str(config),
            ["replay"],
            hashlib.sha256(raw).hexdigest(),
        )


def test_runtime_config_rejects_runner_and_shared_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = _interpreter(tmp_path / "venv")
    venv_root = interpreter.parent.resolve().parent
    monkeypatch.setattr(runtime.sys, "prefix", str(venv_root))
    with pytest.raises(ValueError, match="must not reuse the Runner"):
        runtime.parse_engine_runtime_config(
            _config({"pyrit": (interpreter, _receipt("pyrit"))}),
            selected_attackers=["pyrit"],
        )

    monkeypatch.setattr(runtime.sys, "prefix", str(tmp_path))
    with pytest.raises(ValueError, match="share one interpreter"):
        runtime.parse_engine_runtime_config(
            _config({
                "pyrit": (interpreter, _receipt("pyrit")),
                "deepteam": (interpreter, _receipt("deepteam")),
            }),
            selected_attackers=["pyrit", "deepteam"],
        )


@pytest.mark.parametrize("engine", sorted(runtime.RUNTIME_REQUIRED_ATTACKERS))
def test_central_registry_rejects_missing_runtime(engine: str) -> None:
    with pytest.raises(RuntimeError, match="live-admitted explicit virtual environment"):
        get_attacker(engine)


def test_child_environment_has_no_ambient_path_or_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    interpreter = _interpreter(tmp_path / "venv")
    monkeypatch.setenv("PATH", str(tmp_path / "ambient-bin"))
    monkeypatch.setenv("OPENAI_API_KEY", "never-forward-this")
    child = runtime._minimal_child_environment(tmp_path / "private-home", interpreter)
    assert child["PATH"] == str(interpreter.parent)
    assert "OPENAI_API_KEY" not in child
    assert str(tmp_path / "ambient-bin") not in child.values()


class _Distribution:
    def __init__(self, prefix: Path, name: str, version: str, files: list[str]) -> None:
        self._prefix = prefix
        self.metadata = {"Name": name}
        self.version = version
        self.files = files

    def locate_file(self, item: object) -> Path:
        return self._prefix / os.fspath(item)


def test_dependency_same_version_content_mutation_changes_environment_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    primary_file = tmp_path / "lib" / "pyrit.py"
    primary_record = tmp_path / "lib" / "pyrit.dist-info" / "RECORD"
    dependency_file = tmp_path / "lib" / "dependency.py"
    dependency_record = tmp_path / "lib" / "dependency.dist-info" / "RECORD"
    for path, content in (
        (primary_file, "primary"),
        (primary_record, "primary-record"),
        (dependency_file, "before"),
        (dependency_record, "dependency-record"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    distributions = [
        _Distribution(
            tmp_path,
            "pyrit",
            "0.14.0",
            ["lib/pyrit.py", "lib/pyrit.dist-info/RECORD"],
        ),
        _Distribution(
            tmp_path,
            "dependency",
            "1.2.3",
            ["lib/dependency.py", "lib/dependency.dist-info/RECORD"],
        ),
    ]
    monkeypatch.setattr(
        worker.metadata, "distributions", lambda **_kwargs: distributions
    )
    before = worker._environment_identity(
        "pyrit", prefix=tmp_path, site_packages=tmp_path / "lib"
    )
    dependency_file.write_text("after!", encoding="utf-8")  # same byte count
    after = worker._environment_identity(
        "pyrit", prefix=tmp_path, site_packages=tmp_path / "lib"
    )
    assert before["inventory_sha256"] == after["inventory_sha256"]
    assert before["environment_tree_sha256"] != after["environment_tree_sha256"]


def test_nested_sourceless_bytecode_changes_environment_identity(
    tmp_path: Path,
) -> None:
    site_packages = tmp_path / "site-packages"
    package = site_packages / "demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    source = package / "payload.py"
    bytecode = package / "payload.pyc"

    source.write_text("VALUE = 1\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    source.unlink()
    before = worker._site_packages_tree(site_packages)

    source.write_text("VALUE = 2\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    source.unlink()
    after = worker._site_packages_tree(site_packages)

    assert before[1:] == after[1:]
    assert before[0] != after[0]


def test_worker_rejects_another_registered_framework_in_same_venv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_packages = tmp_path / "lib"
    for relative in (
        "pyrit.py",
        "pyrit.dist-info/RECORD",
        "deepteam.py",
        "deepteam.dist-info/RECORD",
    ):
        path = site_packages / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative, encoding="utf-8")
    distributions = [
        _Distribution(
            site_packages,
            "pyrit",
            "0.14.0",
            ["pyrit.py", "pyrit.dist-info/RECORD"],
        ),
        _Distribution(
            site_packages,
            "deepteam",
            "1.0.7",
            ["deepteam.py", "deepteam.dist-info/RECORD"],
        ),
    ]
    monkeypatch.setattr(
        worker.metadata, "distributions", lambda **_kwargs: distributions
    )

    with pytest.raises(ValueError, match="another registered framework"):
        worker._environment_identity(
            "pyrit", prefix=tmp_path, site_packages=site_packages
        )


def test_worker_never_executes_pth_or_sitecustomize_before_receipt(
    tmp_path: Path,
) -> None:
    (
        interpreter,
        _site_packages,
        pth_sentinel,
        sitecustomize_sentinel,
        import_sentinel,
    ) = _stub_engine_venv(tmp_path / "venv", sentinel_root=tmp_path)

    receipt = runtime.inspect_engine_runtime(interpreter, "h4rm3l")

    assert receipt["engine"] == "h4rm3l"
    assert not pth_sentinel.exists()
    assert not sitecustomize_sentinel.exists()
    assert not import_sentinel.exists()


def test_untracked_site_file_drifts_before_framework_operation(
    tmp_path: Path,
) -> None:
    (
        interpreter,
        site_packages,
        pth_sentinel,
        sitecustomize_sentinel,
        import_sentinel,
    ) = _stub_engine_venv(tmp_path / "venv", sentinel_root=tmp_path)
    approved = runtime.inspect_engine_runtime(interpreter, "h4rm3l")
    (site_packages / "untracked_shadow.py").write_text(
        "SHADOWED = True\n", encoding="utf-8"
    )
    selected = runtime.parse_engine_runtime_config(
        _config({"h4rm3l": (interpreter, approved)}),
        selected_attackers=["h4rm3l"],
    )

    with pytest.raises(ExternalEngineError, match="identity drifted"):
        selected.admit()

    assert not pth_sentinel.exists()
    assert not sitecustomize_sentinel.exists()
    assert not import_sentinel.exists()


def test_worker_rechecks_runtime_identity_after_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_path = (tmp_path / "request.json").resolve()
    response_path = (tmp_path / "response.json").resolve()
    bridge_sha256 = hashlib.sha256(Path(worker.__file__).read_bytes()).hexdigest()
    request_path.write_text(json.dumps({
        "schema": worker.REQUEST_SCHEMA,
        "engine": "pyrit",
        "distribution": "pyrit",
        "expected_version": "0.14.0",
        "bridge_sha256": bridge_sha256,
        "operation": "inspect",
        "payload": {},
    }), encoding="utf-8")
    observed = iter(({"identity": "before"}, {"identity": "after"}))
    monkeypatch.setattr(
        worker, "_observe_receipt", lambda *_args, **_kwargs: next(observed)
    )
    monkeypatch.setattr(
        worker,
        "_runtime_layout",
        lambda: (tmp_path, tmp_path, request_path),
    )
    assert worker.main([
        "--request", str(request_path), "--response", str(response_path)
    ]) == 0
    response = json.loads(response_path.read_text(encoding="utf-8"))
    assert response["status"] == "error"
    assert response["error"]["phase"] == "identity"
    assert response["error"]["type"] == "RuntimeError"


def test_persistent_worker_hashes_once_at_open_and_once_at_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bridge_sha256 = hashlib.sha256(Path(worker.__file__).read_bytes()).hexdigest()
    (tmp_path / "session.json").write_text(json.dumps({
        "schema": worker.SESSION_CONFIG_SCHEMA,
        "engine": "pyrit",
        "distribution": "pyrit",
        "expected_version": "0.14.0",
        "bridge_sha256": bridge_sha256,
    }), encoding="utf-8")
    for sequence, seed in ((1, "one"), (2, "two")):
        (tmp_path / f"request-{sequence:08d}.json").write_text(json.dumps({
            "schema": worker.REQUEST_SCHEMA,
            "engine": "pyrit",
            "distribution": "pyrit",
            "expected_version": "0.14.0",
            "bridge_sha256": bridge_sha256,
            "operation": "pyrit.convert",
            "payload": {"converters": ["Base64Converter"], "seed": seed},
        }), encoding="utf-8")

    observations = 0
    executions = 0

    def observe(*_args: object, **_kwargs: object) -> dict:
        nonlocal observations
        observations += 1
        return _receipt("pyrit")

    def execute(*_args: object) -> tuple[dict, list[dict]]:
        nonlocal executions
        executions += 1
        return {"text": "transformed"}, []

    class _Input:
        buffer = io.BytesIO(b"RUN 00000001\nRUN 00000002\nCLOSE\n")

    monkeypatch.setattr(worker, "_observe_receipt", observe)
    monkeypatch.setattr(worker, "_execute", execute)
    monkeypatch.setattr(
        worker,
        "_runtime_layout",
        lambda: (tmp_path, tmp_path, tmp_path / "pyvenv.cfg"),
    )
    monkeypatch.setattr(worker, "_activate_framework_imports", lambda *_args: None)
    monkeypatch.setattr(worker.sys, "stdin", _Input())
    assert worker._session_main(str(tmp_path.resolve())) == 0
    assert executions == 2
    assert observations == 2


def test_runtime_reuses_one_session_for_multiple_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _Session:
        def __init__(self, **_kwargs: object) -> None:
            events.append("open")

        def execute(
            self, operation: str, payload: object, *, timeout_seconds: object
        ) -> runtime.EngineExecution:
            events.append(f"execute:{operation}")
            return runtime.EngineExecution(
                result={"text": "transformed"},
                artifacts={},
                request_sha256="a" * 64,
                runtime={},
            )

        def close(self, *, timeout_seconds: object = None) -> None:
            events.append("close")

        def abort(self) -> None:
            events.append("abort")

    monkeypatch.setattr(runtime, "_PersistentEngineSession", _Session)
    requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["pyrit"]
    selected = runtime.EngineRuntime(
        requirement=requirement,
        interpreter=Path(sys.executable),
        resolved_interpreter=Path(sys.executable).resolve(),
        receipt=_receipt("pyrit"),
    )
    selected.admit()
    selected.admit()
    selected.execute(requirement.operation, {"seed": "one"})
    selected.execute(requirement.operation, {"seed": "two"})
    selected.close()
    assert events == [
        "open",
        "execute:pyrit.convert",
        "execute:pyrit.convert",
        "close",
    ]


def test_runtime_identity_excludes_mutable_lifecycle_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Session:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def close(self, *, timeout_seconds: object = None) -> None:
            pass

        def abort(self) -> None:
            pass

    monkeypatch.setattr(runtime, "_PersistentEngineSession", _Session)
    requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["pyrit"]
    selected = runtime.EngineRuntime(
        requirement=requirement,
        interpreter=Path(sys.executable),
        resolved_interpreter=Path(sys.executable).resolve(),
        receipt=_receipt("pyrit"),
    )
    configured = selected.identity_descriptor()
    selected.admit()
    verified = selected.identity_descriptor()
    selected.close()
    closed = selected.identity_descriptor()
    assert configured == verified == closed
    assert "status" not in json.dumps(closed, sort_keys=True)


def test_runtime_abort_clears_admission_even_when_tree_cleanup_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Session:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def abort(self) -> None:
            raise ExternalEngineError("fixture tree cleanup failure")

    monkeypatch.setattr(runtime, "_PersistentEngineSession", _Session)
    requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["pyrit"]
    selected = runtime.EngineRuntime(
        requirement=requirement,
        interpreter=Path(sys.executable),
        resolved_interpreter=Path(sys.executable).resolve(),
        receipt=_receipt("pyrit"),
    )
    selected.admit()
    with pytest.raises(ExternalEngineError, match="fixture tree cleanup failure"):
        selected.abort()
    assert selected.admitted is False
    assert selected.public_descriptor()["status"] == "configured"
    with pytest.raises(ExternalEngineError, match="has not passed live admission"):
        selected.execute(requirement.operation, {})


def test_selection_abort_attempts_every_runtime_after_one_cleanup_failure() -> None:
    events: list[str] = []

    class _Runtime:
        def __init__(self, name: str, *, fail: bool = False) -> None:
            self.name = name
            self.fail = fail

        def abort(self) -> None:
            events.append(self.name)
            if self.fail:
                raise RuntimeError(f"{self.name} fixture failure")

    selected = runtime.EngineRuntimeSelection({
        "deepteam": _Runtime("deepteam"),  # type: ignore[arg-type]
        "pyrit": _Runtime("pyrit", fail=True),  # type: ignore[arg-type]
    })
    with pytest.raises(ExternalEngineError, match="could not be confirmed terminated"):
        selected.abort()
    assert events == ["pyrit", "deepteam"]


def test_selection_admission_failure_aborts_every_previously_admitted_runtime() -> None:
    events: list[str] = []

    class _Runtime:
        def __init__(
            self,
            name: str,
            *,
            fail_admit: bool = False,
            fail_abort: bool = False,
        ) -> None:
            self.name = name
            self.fail_admit = fail_admit
            self.fail_abort = fail_abort

        def admit(self) -> None:
            events.append(f"admit:{self.name}")
            if self.fail_admit:
                raise RuntimeError(f"{self.name} admission failure")

        def abort(self) -> None:
            events.append(f"abort:{self.name}")
            if self.fail_abort:
                raise RuntimeError(f"{self.name} cleanup failure")

    selected = runtime.EngineRuntimeSelection({
        "deepteam": _Runtime("deepteam"),  # type: ignore[arg-type]
        "h4rm3l": _Runtime("h4rm3l", fail_abort=True),  # type: ignore[arg-type]
        "pyrit": _Runtime("pyrit", fail_admit=True),  # type: ignore[arg-type]
    })
    with pytest.raises(
        ExternalEngineError,
        match="admission failed.*could not be confirmed terminated",
    ):
        selected.admit()
    assert events == [
        "admit:deepteam",
        "admit:h4rm3l",
        "admit:pyrit",
        "abort:h4rm3l",
        "abort:deepteam",
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object parent-death binding")
def test_windows_worker_job_kills_child_tree_when_owner_handle_closes() -> None:
    process = subprocess.Popen(  # noqa: S603 - fixed local interpreter fixture
        [sys.executable, "-I", "-S", "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    job = runtime._win_create_job()
    try:
        assert job is not None
        assert runtime._win_assign_job(job, process)
        runtime._win_close_handle(job)
        job = None
        process.wait(timeout=5)
        assert process.poll() is not None
    finally:
        runtime._win_close_handle(job)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def test_timeout_terminates_the_complete_worker_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Process:
        returncode = None

        @staticmethod
        def poll() -> None:
            return None

    session = object.__new__(runtime._PersistentEngineSession)
    session._requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["pyrit"]
    session._process = _Process()
    events: list[str] = []
    monkeypatch.setattr(session, "_terminate_process", lambda: events.append("tree"))
    with pytest.raises(ExternalEngineError, match="timed out"):
        session._wait_signal(
            tmp_path / "never-created.done", timeout=0, phase="operation 1"
        )
    assert events == ["tree"]


def test_cleanup_terminates_group_even_after_worker_leader_exits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Process:
        pid = 12345
        stdin = None

        @staticmethod
        def poll() -> int:
            return 0

        @staticmethod
        def wait(*, timeout: float) -> int:
            assert timeout == 5
            return 0

    session = object.__new__(runtime._PersistentEngineSession)
    session._requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["pyrit"]
    session._process = _Process()
    events: list[object] = []
    if os.name == "nt":
        job = object()
        session._windows_job = job
        session._process_group_id = None
        monkeypatch.setattr(
            runtime, "_win_terminate_job", lambda value: events.append(value) or True
        )
        monkeypatch.setattr(
            runtime, "_win_close_handle", lambda value: events.append(("close", value))
        )
        session._terminate_process()
        assert events == [job, ("close", job)]
    else:
        session._windows_job = None
        session._process_group_id = 12345
        monkeypatch.setattr(
            runtime.os, "killpg", lambda pgid, sig: events.append((pgid, sig))
        )
        session._terminate_process()
        assert len(events) == 1 and events[0][0] == 12345


@pytest.mark.skipif(os.name != "posix", reason="POSIX parent-liveness pipe")
def test_parent_guard_eof_terminates_worker_session_and_descendant(
    tmp_path: Path,
) -> None:
    read_fd, write_fd = os.pipe()
    pid_path = tmp_path / "descendant.pid"
    code = (
        "import importlib.util,os,sys,time\n"
        # Load the worker straight from its FILE, exactly as production does
        # (_engine_runtime spawns "-I -S -B <path>/_engine_worker.py").
        # Importing ura.adapters._engine_worker instead executes
        # ura/__init__.py and pulls in pydantic, which -S makes unimportable,
        # so the package import failed on the rig while production was fine.
        "spec = importlib.util.spec_from_file_location(\n"
        "    '_engine_worker',\n"
        "    os.path.join(os.getcwd(), 'src', 'ura', 'adapters',\n"
        "                 '_engine_worker.py'),\n"
        ")\n"
        "worker = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(worker)\n"
        "worker._start_parent_guard(int(sys.argv[1]))\n"
        "child=os.fork()\n"
        "if child == 0:\n"
        "    while True: time.sleep(1)\n"
        "open(sys.argv[2], 'w', encoding='ascii').write(str(child))\n"
        "while True: time.sleep(1)\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-I", "-S", "-B", "-c", code, str(read_fd), str(pid_path)],
        cwd=Path(__file__).resolve().parents[2],
        pass_fds=(read_fd,),
        start_new_session=True,
        close_fds=True,
    )
    os.close(read_fd)
    descendant = 0
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not pid_path.exists():
            time.sleep(0.01)
        assert pid_path.exists()
        descendant = int(pid_path.read_text(encoding="ascii"))
        os.close(write_fd)
        write_fd = -1
        assert process.wait(timeout=10) != 0
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(descendant, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        else:
            pytest.fail("parent guard left its worker descendant alive")
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


@pytest.mark.skipif(os.name != "posix", reason="POSIX SIGTERM lifecycle")
def test_run_matrix_sigterm_aborts_active_engine_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _Selection:
        def abort(self) -> None:
            events.append("abort")

    def terminate_during_run(_argv: object) -> int:
        run_matrix._ACTIVE_ENGINE_RUNTIME_SELECTION = _Selection()
        os.kill(os.getpid(), signal.SIGTERM)
        return 0  # pragma: no cover - signal handler raises first

    monkeypatch.setattr(run_matrix, "_main", terminate_during_run)
    assert run_matrix.main([]) == 128 + signal.SIGTERM
    assert events == ["abort"]
    assert run_matrix._ACTIVE_ENGINE_RUNTIME_SELECTION is None


def _runtime_identity(engine: str = "pyrit") -> dict:
    return {
        "schema": runtime.ENGINE_RUNTIME_IDENTITY_SCHEMA,
        "bridge_sha256": "5" * 64,
        "receipt": _receipt(engine),
    }


def _runtime_close(engine: str = "pyrit") -> dict:
    return {
        "schema": runtime.ENGINE_RUNTIME_EXECUTION_SCHEMA,
        "status": "closed_verified",
        "bridge_sha256": "5" * 64,
        "receipt": _receipt(engine),
    }


@pytest.mark.parametrize("mutation", [
    "missing",
    "status",
    "bridge",
    "receipt",
    "selection",
    "extra",
])
def test_completion_runtime_close_mutations_fail_closed(mutation: str) -> None:
    marker: dict[str, object] = {"engine_runtime_close": _runtime_close()}
    if mutation == "missing":
        marker.pop("engine_runtime_close")
    elif mutation == "status":
        marker["engine_runtime_close"]["status"] = "verified"
    elif mutation == "bridge":
        marker["engine_runtime_close"]["bridge_sha256"] = "6" * 64
    elif mutation == "receipt":
        marker["engine_runtime_close"]["receipt"] = _receipt(
            "pyrit", environment_digest="9" * 64
        )
    elif mutation == "selection":
        marker["engine_runtime_close"] = {
            "schema": runtime.ENGINE_RUNTIME_SELECTION_SCHEMA,
            "runtimes": [_runtime_close()],
            "selection_sha256": "7" * 64,
        }
    else:
        marker["engine_runtime_close"]["extra"] = [_runtime_close("deepteam")]
    with pytest.raises(ValueError):
        run_matrix._validate_completion_engine_runtime_close(
            marker,
            {"engine_runtime": _runtime_identity()},
        )


def test_completion_runtime_close_accepts_exact_binding_and_ignores_replay() -> None:
    close = _runtime_close()
    assert run_matrix._validate_completion_engine_runtime_close(
        {"engine_runtime_close": close},
        {"engine_runtime": _runtime_identity()},
    ) == close
    replay = {
        "engine_runtime": {
            "schema": "ura-engine-runtime-not-required/1",
            "framework_execution": "not_invoked",
        }
    }
    assert run_matrix._validate_completion_engine_runtime_close({}, replay) is None
    with pytest.raises(ValueError, match="unexpected"):
        run_matrix._validate_completion_engine_runtime_close(
            {"engine_runtime_close": close}, replay
        )


def test_worker_rejects_link_request(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    request = tmp_path / "request.json"
    try:
        request.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    assert worker.main([
        "--request", str(request.absolute()),
        "--response", str((tmp_path / "response.json").resolve()),
    ]) == 2


def test_worker_json_depth_is_bounded() -> None:
    raw = ("[" * 34 + "0" + "]" * 34).encode()
    with pytest.raises(ValueError, match="fixed bounds"):
        worker._strict_json_loads(raw, max_depth=32)


def test_stable_read_rejects_same_size_open_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "artifact.bin"
    target.write_bytes(b"before")
    original_open = worker.os.open
    changed = False

    def racing_open(path: object, flags: int, *args: object) -> int:
        nonlocal changed
        if not changed and Path(path) == target:
            changed = True
            before = target.stat()
            target.write_bytes(b"after!")
            os.utime(
                target,
                ns=(before.st_atime_ns, before.st_mtime_ns + 10_000_000_000),
            )
        return original_open(path, flags, *args)

    monkeypatch.setattr(worker.os, "open", racing_open)
    with pytest.raises(ValueError, match="changed while opening"):
        worker._read_regular_file(target, maximum=64)


def _mock_worker_response(
    monkeypatch: pytest.MonkeyPatch,
    *,
    engine: str,
    receipt: dict,
    artifact_items: list[dict] | None = None,
    artifact_payloads: dict[str, bytes] | None = None,
) -> None:
    def fake_run(command: list[str], **_kwargs: object) -> None:
        request_path = Path(command[command.index("--request") + 1])
        response_path = Path(command[command.index("--response") + 1])
        request_bytes = request_path.read_bytes()
        workspace = request_path.parent
        for name, payload in (artifact_payloads or {}).items():
            (workspace / name).write_bytes(payload)
        response_path.write_text(json.dumps({
            "schema": runtime.ENGINE_BRIDGE_RESPONSE_SCHEMA,
            "status": "ok",
            "engine": engine,
            "operation": runtime.ENGINE_RUNTIME_REQUIREMENTS[engine].operation,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "receipt": receipt,
            "result": {},
            "artifacts": artifact_items or [],
            "error": None,
        }), encoding="utf-8")

    monkeypatch.setattr(runtime, "run_engine_command", fake_run)


def test_parent_rejects_path_artifact_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _receipt("spikee")
    _mock_worker_response(
        monkeypatch,
        engine="spikee",
        receipt=receipt,
        artifact_items=[{"file": "../escape", "sha256": "0" * 64, "bytes": 1}],
    )
    requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["spikee"]
    with pytest.raises(ExternalEngineError, match="artifact name"):
        runtime._invoke_worker(
            interpreter=Path(sys.executable),
            resolved_interpreter=Path(sys.executable).resolve(),
            requirement=requirement,
            operation=requirement.operation,
            payload={},
            expected_receipt=receipt,
            timeout_seconds=1,
        )


def test_parent_rejects_runtime_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = _receipt("pyrit")
    observed = _receipt("pyrit", environment_digest="9" * 64)
    _mock_worker_response(monkeypatch, engine="pyrit", receipt=observed)
    requirement = runtime.ENGINE_RUNTIME_REQUIREMENTS["pyrit"]
    with pytest.raises(ExternalEngineError, match="differs from its approved receipt"):
        runtime._invoke_worker(
            interpreter=Path(sys.executable),
            resolved_interpreter=Path(sys.executable).resolve(),
            requirement=requirement,
            operation=requirement.operation,
            payload={},
            expected_receipt=approved,
            timeout_seconds=1,
        )


def test_run_matrix_missing_runtime_fails_before_component_construction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> object:
        calls.append("constructed")
        raise AssertionError("component construction must remain zero-call")

    monkeypatch.setattr(run_matrix, "get_attacker", forbidden)
    monkeypatch.setattr(run_matrix, "build_target", forbidden)
    assert run_matrix.main([
        "--dry-run",
        "--attackers", "pyrit",
        "--judges", "rules",
        "--corpora", "synth",
        "--limit", "1",
        "--out", str(tmp_path / "run"),
    ]) == 1
    assert calls == []


@pytest.mark.parametrize(
    ("path_value", "digest"),
    [("private.json", ""), ("", "8" * 64)],
)
def test_run_matrix_engine_runtime_config_requires_paired_digest(
    path_value: str,
    digest: str,
) -> None:
    with pytest.raises(ValueError, match="must be provided together"):
        run_matrix._load_engine_runtime_config(
            path_value,
            ["pyrit"],
            digest,
        )


def test_run_matrix_reuses_runtime_and_publishes_only_after_closing_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private_locator = str(tmp_path / "operator-private" / "pyrit-python.exe")
    events: list[str] = []

    class _Runtime:
        engine = "pyrit"
        admitted = True
        status = "verified"

        def public_descriptor(self) -> dict:
            return {
                "schema": runtime.ENGINE_RUNTIME_EXECUTION_SCHEMA,
                "status": self.status,
                "bridge_sha256": "5" * 64,
                "receipt": _receipt("pyrit"),
            }

        def execute(
            self, operation: str, payload: dict, **_kwargs: object
        ) -> runtime.EngineExecution:
            events.append("execute")
            assert operation == "pyrit.convert"
            return runtime.EngineExecution(
                result={"text": "isolated::" + str(payload["seed"])},
                artifacts={},
                request_sha256="6" * 64,
                runtime=self.public_descriptor(),
            )

    engine = _Runtime()

    class _Selection:
        def admit(self) -> dict:
            events.append("admit")
            return self.public_descriptor()

        def runtime_for(self, name: str) -> _Runtime:
            assert name == "pyrit"
            return engine

        def public_descriptor(self) -> dict:
            runtimes = [engine.public_descriptor()]
            identity_body = {
                "schema": runtime.ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
                "runtimes": [
                    runtime.engine_runtime_identity_descriptor(item)
                    for item in runtimes
                ],
            }
            return {
                "schema": runtime.ENGINE_RUNTIME_SELECTION_SCHEMA,
                "runtimes": runtimes,
                "selection_sha256": runtime._sha256_json(identity_body),
            }

        def identity_descriptor(self) -> dict:
            return runtime.engine_runtime_selection_identity_descriptor(
                self.public_descriptor()
            )

        def close(self) -> dict:
            events.append("close")
            engine.status = "closed_verified"
            return self.public_descriptor()

        def abort(self) -> None:
            events.append("abort")

    artifact = {
        "file": "private-engine-runtime-config@sha256:" + "8" * 64,
        "sha256": "8" * 64,
        "bytes": 100,
        "normalized_selected_sha256": "9" * 64,
    }
    monkeypatch.setattr(
        run_matrix,
        "_load_engine_runtime_config",
        lambda *_args, **_kwargs: (_Selection(), artifact),
    )
    out = tmp_path / "run"
    assert run_matrix.main([
        "--dry-run",
        "--attackers", "pyrit",
        "--engine-runtime-config", private_locator,
        "--engine-runtime-config-sha256", "8" * 64,
        "--judges", "rules",
        "--corpora", "synth",
        "--limit", "1",
        "--max-queries", "1",
        "--max-turns", "1",
        "--out", str(out),
    ]) == 0
    assert events == ["admit", "execute", "close"]
    assert not list(out.glob(".*.pending-*"))
    assert list(out.glob("*.complete.json"))
    grid = json.loads(next(out.glob("*.grid.json")).read_text(encoding="utf-8"))
    assert grid["status"] == "complete"
    assert grid["engine_runtime_close"]["runtimes"][0]["status"] == (
        "closed_verified"
    )
    completion = json.loads(
        next(out.glob("*.complete.json")).read_text(encoding="utf-8")
    )
    assert completion["engine_runtime_close"]["status"] == "closed_verified"
    assert set(completion["engine_runtime_close"]) == {
        "schema", "status", "bridge_sha256", "receipt"
    }
    assert private_locator not in json.dumps(grid, sort_keys=True)

    from experiments.level1_evidence import (  # noqa: PLC0415
        _load_results,
        _plan_artifact,
    )

    plan = _plan_artifact(next(out.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([out], {plan[0]["plan_id"]: plan})
    assert errors == []
    assert next(iter(grids.values()))["cells"]

    completion.pop("engine_runtime_close")
    next(out.glob("*.complete.json")).write_text(
        json.dumps(completion), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="engine runtime"):
        _load_results([out], {plan[0]["plan_id"]: plan})


def test_new_runtime_session_never_reuses_prior_unsealed_cell_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invocation = 0
    executions: list[int] = []
    checkpoint_reads: list[tuple[int, bool]] = []
    response_checkpoint_reads: list[tuple[int, bool]] = []

    class _Runtime:
        engine = "pyrit"
        admitted = True

        def __init__(self, sequence: int) -> None:
            self.sequence = sequence
            self.status = "verified"

        def public_descriptor(self) -> dict:
            return {
                "schema": runtime.ENGINE_RUNTIME_EXECUTION_SCHEMA,
                "status": self.status,
                "bridge_sha256": "5" * 64,
                "receipt": _receipt("pyrit"),
            }

        def execute(
            self, operation: str, payload: dict, **_kwargs: object
        ) -> runtime.EngineExecution:
            executions.append(self.sequence)
            return runtime.EngineExecution(
                result={"text": f"session-{self.sequence}::{payload['seed']}"},
                artifacts={},
                request_sha256=str(self.sequence) * 64,
                runtime=self.public_descriptor(),
            )

    class _Selection:
        def __init__(self, sequence: int) -> None:
            self.sequence = sequence
            self.engine = _Runtime(sequence)

        def admit(self) -> dict:
            return self.public_descriptor()

        def runtime_for(self, name: str) -> _Runtime:
            assert name == "pyrit"
            return self.engine

        def public_descriptor(self) -> dict:
            runtimes = [self.engine.public_descriptor()]
            identity_body = {
                "schema": runtime.ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
                "runtimes": [
                    runtime.engine_runtime_identity_descriptor(item)
                    for item in runtimes
                ],
            }
            return {
                "schema": runtime.ENGINE_RUNTIME_SELECTION_SCHEMA,
                "runtimes": runtimes,
                "selection_sha256": runtime._sha256_json(identity_body),
            }

        def identity_descriptor(self) -> dict:
            return runtime.engine_runtime_selection_identity_descriptor(
                self.public_descriptor()
            )

        def close(self) -> dict:
            if self.sequence == 1:
                raise RuntimeError("fixture closing seal failure")
            self.engine.status = "closed_verified"
            return self.public_descriptor()

        def abort(self) -> None:
            pass

    artifact = {
        "file": "private-engine-runtime-config@sha256:" + "8" * 64,
        "sha256": "8" * 64,
        "bytes": 100,
        "normalized_selected_sha256": "9" * 64,
    }

    def select(*_args: object, **_kwargs: object) -> tuple[_Selection, dict]:
        nonlocal invocation
        invocation += 1
        return _Selection(invocation), artifact

    original_checkpoint = run_matrix.Runner.load_checkpoint
    original_response_checkpoint = run_matrix.Runner.load_response_checkpoint

    def load_checkpoint(path: Path, *, expected_run_id: str):
        checkpoint_reads.append((invocation, path.exists()))
        return original_checkpoint(path, expected_run_id=expected_run_id)

    def load_response_checkpoint(path: Path, *, expected_run_id: str):
        response_checkpoint_reads.append((invocation, path.exists()))
        return original_response_checkpoint(path, expected_run_id=expected_run_id)

    monkeypatch.setattr(run_matrix, "_load_engine_runtime_config", select)
    monkeypatch.setattr(run_matrix.Runner, "load_checkpoint", load_checkpoint)
    monkeypatch.setattr(
        run_matrix.Runner,
        "load_response_checkpoint",
        load_response_checkpoint,
    )
    out = tmp_path / "unsealed-retry"
    argv = [
        "--dry-run",
        "--attackers", "pyrit",
        "--engine-runtime-config", str(tmp_path / "private.json"),
        "--engine-runtime-config-sha256", "8" * 64,
        "--judges", "rules",
        "--corpora", "synth",
        "--limit", "1",
        "--max-queries", "1",
        "--max-turns", "1",
        "--out", str(out),
    ]

    assert run_matrix.main(argv) == 1
    assert not list(out.glob("*.complete.json"))
    assert not list(out.glob("*.checkpoint.jsonl"))
    assert not list(out.glob("*.responses.checkpoint.jsonl"))
    assert not list(out.glob("*.attempts.jsonl"))
    assert not list(out.glob("*.responses.jsonl"))
    assert not list(out.glob("*.results.jsonl"))
    assert not list(out.glob("*.manifest.json"))
    assert not list(out.glob(".*.pending-*"))

    assert run_matrix.main(argv) == 0
    assert executions == [1, 2]
    assert checkpoint_reads == [(1, False), (2, False)]
    assert response_checkpoint_reads == [(1, False), (2, False)]
    assert len(list(out.glob("*.complete.json"))) == 1


def test_abrupt_running_runtime_cell_state_is_discarded_before_resume(
    tmp_path: Path,
) -> None:
    stem = "fixture-runtime-cell"
    paths = {
        "attempts": tmp_path / f"{stem}.attempts.jsonl",
        "responses": tmp_path / f"{stem}.responses.jsonl",
        "judgments": tmp_path / f"{stem}.jsonl",
        "trails": tmp_path / f"{stem}.trails.jsonl",
        "results": tmp_path / f"{stem}.results.jsonl",
        "manifest": tmp_path / f"{stem}.manifest.json",
        "checkpoint": tmp_path / f"{stem}.checkpoint.jsonl",
        "response_checkpoint": tmp_path / f"{stem}.responses.checkpoint.jsonl",
        "complete": tmp_path / f"{stem}.complete.json",
        "error": tmp_path / f"{stem}.error.json",
    }
    for name, path in paths.items():
        if name != "complete":
            path.write_text("stale-unsealed\n", encoding="utf-8")
    pending = tmp_path / f".{paths['complete'].name}.pending-123"
    pending.write_text("stale-pending\n", encoding="utf-8")

    removed = run_matrix._discard_unsealed_engine_cell_state(paths)

    assert paths["error"].exists()
    assert not pending.exists()
    assert set(removed) == {
        path.name
        for name, path in paths.items()
        if name not in {"complete", "error"}
    } | {pending.name}
    assert all(
        not path.exists()
        for name, path in paths.items()
        if name not in {"complete", "error"}
    )
