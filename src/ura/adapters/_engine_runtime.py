"""Private, content-addressed runtimes for Runner-safe third-party engines.

The scientific attacker configuration deliberately does not contain a virtual
environment path.  An operator supplies one separately content-addressed
``ura-engine-runtime-config/1`` document.  Its interpreter locators remain
private operational state; manifests receive only the live-verified, path-free
receipt returned by the selected interpreter.

This bridge is process isolation, not a security sandbox.  It removes ambient
credentials and runtime-injection variables, uses a fixed stdlib worker and a
bounded artifact protocol, but the child still has the invoking account's
filesystem and network privileges.  Hostile engines still require an external
container/VM/account boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..strict_json import strict_json_loads
from ._engine_common import ExternalEngineError, _resolve_timeout, run_engine_command


ENGINE_RUNTIME_CONFIG_SCHEMA = "ura-engine-runtime-config/1"
ENGINE_RUNTIME_RECEIPT_SCHEMA = "ura-engine-runtime-receipt/1"
ENGINE_RUNTIME_EXECUTION_SCHEMA = "ura-engine-runtime-execution/1"
ENGINE_RUNTIME_IDENTITY_SCHEMA = "ura-engine-runtime-identity/1"
ENGINE_RUNTIME_SELECTION_SCHEMA = "ura-engine-runtime-selection/1"
ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA = "ura-engine-runtime-selection-identity/1"
ENGINE_BRIDGE_REQUEST_SCHEMA = "ura-engine-bridge-request/1"
ENGINE_BRIDGE_RESPONSE_SCHEMA = "ura-engine-bridge-response/1"
ENGINE_SESSION_CONFIG_SCHEMA = "ura-engine-runtime-session-config/1"
ENGINE_SESSION_CLOSE_SCHEMA = "ura-engine-runtime-session-close/1"

_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_ARTIFACTS = 4
_HEX64 = re.compile(r"[0-9a-f]{64}")
_RUNTIME_ID = re.compile(r"engine-runtime-[0-9a-f]{24}")
_ERROR_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}")
_EXPECTED_ARTIFACTS = {
    "inspect": frozenset(),
    "pyrit.convert": frozenset(),
    "deepteam.enhance": frozenset(),
    "h4rm3l.render": frozenset(),
    "spikee.generate": frozenset({"spikee-dataset.jsonl"}),
}


@dataclass(frozen=True)
class EngineRuntimeRequirement:
    engine: str
    distribution: str
    version: str
    operation: str


ENGINE_RUNTIME_REQUIREMENTS: dict[str, EngineRuntimeRequirement] = {
    "pyrit": EngineRuntimeRequirement(
        "pyrit", "pyrit", "0.14.0", "pyrit.convert"
    ),
    "deepteam": EngineRuntimeRequirement(
        "deepteam", "deepteam", "1.0.7", "deepteam.enhance"
    ),
    "h4rm3l": EngineRuntimeRequirement(
        "h4rm3l", "h4rm3l", "0.2.4", "h4rm3l.render"
    ),
    "spikee": EngineRuntimeRequirement(
        "spikee", "spikee", "0.9.1", "spikee.generate"
    ),
}
RUNTIME_REQUIRED_ATTACKERS = frozenset(ENGINE_RUNTIME_REQUIREMENTS)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _full_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ValueError(f"{label} must be exactly 64 lowercase hex characters")
    return value


def _positive_int(value: object, *, label: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} exceeds its supported bound")
    return value


def validate_engine_runtime_receipt(
    value: object,
    *,
    requirement: EngineRuntimeRequirement | None = None,
) -> dict[str, Any]:
    """Validate and return one canonical path-free live-runtime receipt."""

    if not isinstance(value, dict) or set(value) != {
        "schema",
        "runtime_id",
        "engine",
        "distribution",
        "version",
        "python",
        "pyvenv_cfg_sha256",
        "package_tree_sha256",
        "package_files",
        "package_bytes",
        "inventory_sha256",
        "environment_tree_sha256",
        "environment_files",
        "environment_bytes",
    }:
        raise ValueError("engine runtime receipt has invalid fields")
    if value.get("schema") != ENGINE_RUNTIME_RECEIPT_SCHEMA:
        raise ValueError("engine runtime receipt schema is unsupported")
    engine = value.get("engine")
    distribution = value.get("distribution")
    version = value.get("version")
    runtime_id = value.get("runtime_id")
    if (
        not isinstance(engine, str)
        or engine not in ENGINE_RUNTIME_REQUIREMENTS
        or not isinstance(distribution, str)
        or not distribution.strip()
        or not isinstance(version, str)
        or not version.strip()
        or not isinstance(runtime_id, str)
        or _RUNTIME_ID.fullmatch(runtime_id) is None
    ):
        raise ValueError("engine runtime receipt identity is invalid")
    expected = requirement or ENGINE_RUNTIME_REQUIREMENTS[engine]
    if (
        engine != expected.engine
        or distribution != expected.distribution
        or version != expected.version
    ):
        raise ValueError(
            f"{expected.engine} runtime must be {expected.distribution}=="
            f"{expected.version}"
        )
    python = value.get("python")
    if not isinstance(python, dict) or set(python) != {
        "implementation",
        "version",
        "cache_tag",
        "executable_sha256",
        "executable_bytes",
    }:
        raise ValueError("engine runtime Python identity is invalid")
    for field in ("implementation", "version", "cache_tag"):
        if not isinstance(python.get(field), str) or not python[field].strip():
            raise ValueError(f"engine runtime Python {field} is invalid")
    _full_digest(python.get("executable_sha256"), label="interpreter SHA-256")
    _positive_int(
        python.get("executable_bytes"),
        label="interpreter byte count",
        maximum=1024 * 1024 * 1024,
    )
    for field in (
        "pyvenv_cfg_sha256",
        "package_tree_sha256",
        "inventory_sha256",
        "environment_tree_sha256",
    ):
        _full_digest(value.get(field), label=field.replace("_", " "))
    _positive_int(
        value.get("package_files"),
        label="package file count",
        maximum=100_000,
    )
    _positive_int(
        value.get("package_bytes"),
        label="package byte count",
        maximum=16 * 1024 * 1024 * 1024,
    )
    _positive_int(
        value.get("environment_files"),
        label="environment file count",
        maximum=1_000_000,
    )
    _positive_int(
        value.get("environment_bytes"),
        label="environment byte count",
        maximum=64 * 1024 * 1024 * 1024,
    )
    identity = {key: item for key, item in value.items() if key != "runtime_id"}
    expected_id = f"engine-runtime-{_sha256_json(identity)[:24]}"
    if not secrets.compare_digest(runtime_id, expected_id):
        raise ValueError("engine runtime receipt id does not match its content")
    return json.loads(_canonical_json_bytes(value))


def validate_engine_runtime_execution_descriptor(
    value: object,
    *,
    required_status: str | None = None,
) -> dict[str, Any]:
    """Validate one path-free runtime observation, including its live status."""

    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "bridge_sha256",
        "receipt",
    }:
        raise ValueError("engine runtime execution descriptor has invalid fields")
    if value.get("schema") != ENGINE_RUNTIME_EXECUTION_SCHEMA:
        raise ValueError("engine runtime execution descriptor schema is unsupported")
    status = value.get("status")
    if status not in {"configured", "verified", "closed_verified"}:
        raise ValueError("engine runtime execution status is invalid")
    if required_status is not None and status != required_status:
        raise ValueError(
            f"engine runtime execution status must be {required_status!r}"
        )
    _full_digest(value.get("bridge_sha256"), label="engine bridge SHA-256")
    receipt = validate_engine_runtime_receipt(value.get("receipt"))
    return {
        "schema": ENGINE_RUNTIME_EXECUTION_SCHEMA,
        "status": status,
        "bridge_sha256": value["bridge_sha256"],
        "receipt": receipt,
    }


def validate_engine_runtime_identity_descriptor(value: object) -> dict[str, Any]:
    """Validate the immutable receipt/bridge identity used by scientific IDs."""

    if not isinstance(value, dict) or set(value) != {
        "schema",
        "bridge_sha256",
        "receipt",
    }:
        raise ValueError("engine runtime identity descriptor has invalid fields")
    if value.get("schema") != ENGINE_RUNTIME_IDENTITY_SCHEMA:
        raise ValueError("engine runtime identity descriptor schema is unsupported")
    _full_digest(value.get("bridge_sha256"), label="engine bridge SHA-256")
    receipt = validate_engine_runtime_receipt(value.get("receipt"))
    return {
        "schema": ENGINE_RUNTIME_IDENTITY_SCHEMA,
        "bridge_sha256": value["bridge_sha256"],
        "receipt": receipt,
    }


def engine_runtime_identity_descriptor(value: object) -> dict[str, Any]:
    """Project a mutable live observation to stable scientific identity."""

    execution = validate_engine_runtime_execution_descriptor(value)
    return {
        "schema": ENGINE_RUNTIME_IDENTITY_SCHEMA,
        "bridge_sha256": execution["bridge_sha256"],
        "receipt": execution["receipt"],
    }


def engine_runtime_selection_identity_descriptor(value: object) -> dict[str, Any]:
    """Project a strict selection observation to status-free stable identity."""

    selection = validate_engine_runtime_selection_descriptor(value)
    body = {
        "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
        "runtimes": [
            engine_runtime_identity_descriptor(item)
            for item in selection["runtimes"]
        ],
    }
    return {**body, "selection_sha256": _sha256_json(body)}


def validate_engine_runtime_selection_descriptor(
    value: object,
    *,
    required_status: str | None = None,
) -> dict[str, Any]:
    """Validate an exact, duplicate-free selection observation."""

    if not isinstance(value, dict) or set(value) != {
        "schema",
        "runtimes",
        "selection_sha256",
    }:
        raise ValueError("engine runtime selection descriptor has invalid fields")
    if value.get("schema") != ENGINE_RUNTIME_SELECTION_SCHEMA:
        raise ValueError("engine runtime selection descriptor schema is unsupported")
    runtimes = value.get("runtimes")
    if not isinstance(runtimes, list) or not 0 < len(runtimes) <= len(
        ENGINE_RUNTIME_REQUIREMENTS
    ):
        raise ValueError("engine runtime selection inventory is invalid")
    normalized = [
        validate_engine_runtime_execution_descriptor(
            item, required_status=required_status
        )
        for item in runtimes
    ]
    engines = [str(item["receipt"]["engine"]) for item in normalized]
    if engines != sorted(engines) or len(set(engines)) != len(engines):
        raise ValueError("engine runtime selection is unsorted or contains duplicates")
    identity_body = {
        "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
        "runtimes": [engine_runtime_identity_descriptor(item) for item in normalized],
    }
    expected_sha256 = _sha256_json(identity_body)
    if not isinstance(value.get("selection_sha256"), str) or not secrets.compare_digest(
        value["selection_sha256"], expected_sha256
    ):
        raise ValueError("engine runtime selection digest does not match its identity")
    return {
        "schema": ENGINE_RUNTIME_SELECTION_SCHEMA,
        "runtimes": normalized,
        "selection_sha256": expected_sha256,
    }


def validate_engine_runtime_selection_identity_descriptor(
    value: object,
) -> dict[str, Any]:
    """Validate a status-free selection used in a manifest or grid identity."""

    if not isinstance(value, dict) or set(value) != {
        "schema",
        "runtimes",
        "selection_sha256",
    }:
        raise ValueError("engine runtime selection identity has invalid fields")
    if value.get("schema") != ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA:
        raise ValueError("engine runtime selection identity schema is unsupported")
    runtimes = value.get("runtimes")
    if not isinstance(runtimes, list) or not 0 < len(runtimes) <= len(
        ENGINE_RUNTIME_REQUIREMENTS
    ):
        raise ValueError("engine runtime selection identity inventory is invalid")
    normalized = [validate_engine_runtime_identity_descriptor(item) for item in runtimes]
    engines = [str(item["receipt"]["engine"]) for item in normalized]
    if engines != sorted(engines) or len(set(engines)) != len(engines):
        raise ValueError(
            "engine runtime selection identity is unsorted or contains duplicates"
        )
    body = {
        "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
        "runtimes": normalized,
    }
    expected_sha256 = _sha256_json(body)
    if not isinstance(value.get("selection_sha256"), str) or not secrets.compare_digest(
        value["selection_sha256"], expected_sha256
    ):
        raise ValueError("engine runtime selection identity digest is invalid")
    return {**body, "selection_sha256": expected_sha256}


def _resolve_interpreter(value: object, *, label: str) -> tuple[Path, Path]:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise ValueError(f"{label} must be a non-blank absolute interpreter path")
    supplied = Path(value).expanduser()
    if not supplied.is_absolute():
        raise ValueError(f"{label} must be an absolute interpreter path")
    try:
        # Installer publications use a stable operator-facing directory alias
        # whose target is the content-addressed store.  Canonicalize directory
        # components so the worker starts inside that real, non-symlinked venv,
        # while deliberately preserving the final ``bin/python`` entry: a
        # conventional venv may itself implement that entry as a symlink to its
        # base executable.
        configured = supplied.parent.resolve(strict=True) / supplied.name
        visible = configured.lstat()
        resolved = configured.resolve(strict=True)
        target = resolved.stat()
    except OSError as exc:
        raise ValueError(f"{label} cannot be inspected") from exc
    # A venv's python entry point is commonly a symlink to the base executable,
    # so the final symlink is allowed.  Both the configured entry and resolved
    # target must nevertheless be file-like and the live worker must prove it is
    # running with a distinct virtual-environment prefix.
    if not (stat.S_ISREG(visible.st_mode) or stat.S_ISLNK(visible.st_mode)):
        raise ValueError(f"{label} is not a regular file or venv interpreter link")
    if not stat.S_ISREG(target.st_mode):
        raise ValueError(f"{label} does not resolve to a regular executable")
    if os.name != "nt" and not os.access(configured, os.X_OK):
        raise ValueError(f"{label} is not executable")
    return configured, resolved


@dataclass(frozen=True)
class EngineExecution:
    result: Any
    artifacts: Mapping[str, bytes]
    request_sha256: str
    runtime: Mapping[str, Any]


def _win_create_job() -> Any:
    """Create a parent-death-bound Job for one engine worker tree."""

    if os.name != "nt":
        return None
    handle: Any = None
    kernel32: Any = None
    try:
        import ctypes  # noqa: PLC0415 - Windows-only stdlib boundary
        from ctypes import wintypes  # noqa: PLC0415 - Windows-only stdlib boundary

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class _BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimitInformation),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None
        information = _ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x00002000
        configured = kernel32.SetInformationJobObject(
            handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        if not configured:
            kernel32.CloseHandle(handle)
            return None
        return handle
    except Exception:  # noqa: BLE001 - admission rejects an unavailable job
        if handle and kernel32 is not None:
            try:
                kernel32.CloseHandle(handle)
            except Exception:  # noqa: BLE001 - best effort on setup failure
                pass
        return None


def _win_assign_job(handle: Any, process: subprocess.Popen[bytes]) -> bool:
    if handle is None or os.name != "nt":
        return False
    try:
        import ctypes  # noqa: PLC0415 - Windows-only stdlib boundary

        return bool(
            ctypes.WinDLL("kernel32", use_last_error=True).AssignProcessToJobObject(
                handle, int(process._handle)
            )
        )
    except Exception:  # noqa: BLE001 - caller fails admission closed
        return False


def _win_terminate_job(handle: Any) -> bool:
    if handle is None or os.name != "nt":
        return False
    try:
        import ctypes  # noqa: PLC0415 - Windows-only stdlib boundary

        return bool(
            ctypes.WinDLL("kernel32", use_last_error=True).TerminateJobObject(
                handle, 1
            )
        )
    except Exception:  # noqa: BLE001 - caller reports cleanup failure
        return False


def _win_wait_job_empty(handle: Any, *, timeout_seconds: float) -> bool:
    """Wait until a terminated Job has released every process and its CWD."""

    if handle is None or os.name != "nt" or timeout_seconds <= 0:
        return False
    try:
        import ctypes  # noqa: PLC0415 - Windows-only stdlib boundary
        from ctypes import wintypes  # noqa: PLC0415 - Windows-only stdlib boundary

        class _BasicAccountingInformation(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        query = ctypes.WinDLL(
            "kernel32", use_last_error=True
        ).QueryInformationJobObject
        query.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        query.restype = wintypes.BOOL
        deadline = time.monotonic() + timeout_seconds
        while True:
            information = _BasicAccountingInformation()
            if not query(
                handle,
                1,  # JobObjectBasicAccountingInformation
                ctypes.byref(information),
                ctypes.sizeof(information),
                None,
            ):
                return False
            if information.ActiveProcesses == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
    except Exception:  # noqa: BLE001 - caller reports cleanup failure
        return False


def _win_close_handle(handle: Any) -> None:
    if handle is None or os.name != "nt":
        return
    try:
        import ctypes  # noqa: PLC0415 - Windows-only stdlib boundary

        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
    except Exception:  # noqa: BLE001 - best effort after termination
        pass


def _signal_publish_in_progress(path: Path, *, worker_pid: int) -> bool:
    """Recognize, but never accept, the worker's atomic-link publish window."""

    if worker_pid <= 0:
        return False
    temporary = path.with_name(f".{path.name}.{worker_pid}.partial")
    try:
        marker = path.lstat()
        staged = temporary.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(marker.st_mode)
        and stat.S_ISREG(staged.st_mode)
        and marker.st_nlink == 2
        and staged.st_nlink == 2
        and marker.st_size == 1
        and staged.st_size == 1
        and (marker.st_dev, marker.st_ino, marker.st_mtime_ns)
        == (staged.st_dev, staged.st_ino, staged.st_mtime_ns)
    )


class _PersistentEngineSession:
    """One sealed worker process reused for every operation in a matrix run."""

    def __init__(
        self,
        *,
        interpreter: Path,
        resolved_interpreter: Path,
        requirement: EngineRuntimeRequirement,
        expected_receipt: Mapping[str, Any],
        bridge_sha256: str,
        timeout_seconds: float | None,
    ) -> None:
        self._interpreter = interpreter
        self._resolved_interpreter = resolved_interpreter
        self._requirement = requirement
        self._expected_receipt = dict(expected_receipt)
        self._bridge_sha256 = bridge_sha256
        self._default_timeout = _resolve_timeout(timeout_seconds)
        self._temporary = tempfile.TemporaryDirectory(
            prefix=f"ura-engine-session-{requirement.engine}-"
        )
        self._workspace = Path(self._temporary.name).resolve(strict=True)
        self._process: subprocess.Popen[bytes] | None = None
        self._process_group_id: int | None = None
        self._parent_guard_write: int | None = None
        self._windows_job: Any = None
        self._sequence = 1
        self._closed = False
        try:
            os.chmod(self._workspace, 0o700)
        except OSError:
            pass
        try:
            self._open()
        except BaseException:
            self.abort()
            raise

    def _open(self) -> None:
        worker = Path(__file__).with_name("_engine_worker.py").resolve(strict=True)
        config = {
            "schema": ENGINE_SESSION_CONFIG_SCHEMA,
            "engine": self._requirement.engine,
            "distribution": self._requirement.distribution,
            "expected_version": self._requirement.version,
            "bridge_sha256": self._bridge_sha256,
        }
        config_bytes = _canonical_json_bytes(config)
        _write_create_only(self._workspace / "session.json", config_bytes)
        child_environment = _minimal_child_environment(
            self._workspace, self._interpreter
        )
        creation_flags = 0
        popen_options: dict[str, object] = {}
        parent_guard_read: int | None = None
        if os.name == "nt":
            creation_flags = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
            self._windows_job = _win_create_job()
            if self._windows_job is None:
                raise ExternalEngineError(
                    f"{self._requirement.engine} isolated runtime could not create "
                    "a Windows process-tree job"
                )
        else:
            popen_options["start_new_session"] = True
            parent_guard_read, parent_guard_write = os.pipe()
            os.set_inheritable(parent_guard_read, True)
            os.set_inheritable(parent_guard_write, False)
            self._parent_guard_write = parent_guard_write
            popen_options["pass_fds"] = (parent_guard_read,)
        worker_argv = [
            str(self._interpreter),
            "-I",
            "-S",
            "-B",
            str(worker),
            "--session",
            str(self._workspace),
        ]
        if parent_guard_read is not None:
            worker_argv.extend(["--parent-guard-fd", str(parent_guard_read)])
        try:
            self._process = subprocess.Popen(
                worker_argv,
                cwd=self._workspace,
                env=child_environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                close_fds=True,
                creationflags=creation_flags,
                **popen_options,
            )
        except OSError as exc:
            if self._parent_guard_write is not None:
                os.close(self._parent_guard_write)
                self._parent_guard_write = None
            _win_close_handle(self._windows_job)
            self._windows_job = None
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime session could not start "
                f"({type(exc).__name__})"
            ) from exc
        finally:
            if parent_guard_read is not None:
                os.close(parent_guard_read)
        if os.name == "nt":
            if not _win_assign_job(self._windows_job, self._process):
                try:
                    self._process.kill()
                    self._process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                _win_close_handle(self._windows_job)
                self._windows_job = None
                self._process = None
                raise ExternalEngineError(
                    f"{self._requirement.engine} isolated runtime could not bind "
                    "its Windows process-tree job"
                )
        else:
            # start_new_session makes the worker PID the stable process-group id.
            self._process_group_id = self._process.pid
        self._wait_signal(
            self._workspace / "ready.done",
            timeout=self._default_timeout,
            phase="admission",
        )
        raw = _read_stable_file(
            self._workspace / "ready.json",
            label=f"{self._requirement.engine} session admission response",
            max_bytes=_MAX_RESPONSE_BYTES,
        )
        response = self._decode_response(
            raw,
            operation="session.open",
            request_sha256=hashlib.sha256(config_bytes).hexdigest(),
            artifact_root=None,
            expected_artifacts=frozenset(),
        )
        if response.result != {"session": "open"}:
            raise ExternalEngineError(
                f"{self._requirement.engine} session admission result is invalid"
            )

    def _wait_signal(self, path: Path, *, timeout: float, phase: str) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if path.exists():
                process = self._process
                if process is None or not _signal_publish_in_progress(
                    path, worker_pid=process.pid
                ):
                    _read_stable_file(
                        path,
                        label=f"{self._requirement.engine} session {phase} signal",
                        max_bytes=1,
                    )
                    return
            process = self._process
            if process is None or process.poll() is not None:
                status = None if process is None else process.returncode
                raise ExternalEngineError(
                    f"{self._requirement.engine} isolated runtime session exited "
                    f"during {phase} (status {status})"
                )
            if time.monotonic() >= deadline:
                self._terminate_process()
                raise ExternalEngineError(
                    f"{self._requirement.engine} isolated runtime session timed out "
                    f"during {phase}"
                )
            time.sleep(0.01)

    def _send(self, value: bytes) -> None:
        process = self._process
        if process is None or process.poll() is not None or process.stdin is None:
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime session is unavailable"
            )
        try:
            process.stdin.write(value)
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime session control failed"
            ) from exc

    def execute(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        timeout_seconds: float | None,
    ) -> EngineExecution:
        if self._closed:
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime session is closed"
            )
        sequence = self._sequence
        if sequence > 99_999_999:
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime request bound exceeded"
            )
        token = f"{sequence:08d}"
        request_path = self._workspace / f"request-{token}.json"
        response_path = self._workspace / f"response-{token}.json"
        response_done = self._workspace / f"response-{token}.done"
        artifact_root = self._workspace / f"operation-{token}"
        request = {
            "schema": ENGINE_BRIDGE_REQUEST_SCHEMA,
            "engine": self._requirement.engine,
            "distribution": self._requirement.distribution,
            "expected_version": self._requirement.version,
            "bridge_sha256": self._bridge_sha256,
            "operation": operation,
            "payload": dict(payload),
        }
        request_bytes = _canonical_json_bytes(request)
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        _write_create_only(request_path, request_bytes)
        try:
            self._send(f"RUN {token}\n".encode("ascii"))
            self._wait_signal(
                response_done,
                timeout=_resolve_timeout(timeout_seconds)
                if timeout_seconds is not None
                else self._default_timeout,
                phase=f"operation {sequence}",
            )
            raw = _read_stable_file(
                response_path,
                label=f"{self._requirement.engine} session operation response",
                max_bytes=_MAX_RESPONSE_BYTES,
            )
            return self._decode_response(
                raw,
                operation=operation,
                request_sha256=request_sha256,
                artifact_root=artifact_root,
                expected_artifacts=_EXPECTED_ARTIFACTS[operation],
            )
        finally:
            self._sequence += 1
            self._cleanup_operation(
                request_path, response_path, response_done, artifact_root
            )

    def _decode_response(
        self,
        raw: bytes,
        *,
        operation: str,
        request_sha256: str,
        artifact_root: Path | None,
        expected_artifacts: frozenset[str],
    ) -> EngineExecution:
        try:
            response = strict_json_loads(raw, max_nodes=2_000_000, max_depth=32)
        except (UnicodeError, ValueError) as exc:
            raise ExternalEngineError(
                f"{self._requirement.engine} session returned invalid strict JSON"
            ) from exc
        if not isinstance(response, dict) or set(response) != {
            "schema",
            "status",
            "engine",
            "operation",
            "request_sha256",
            "receipt",
            "result",
            "artifacts",
            "error",
        }:
            raise ExternalEngineError(
                f"{self._requirement.engine} session response fields are invalid"
            )
        if (
            response.get("schema") != ENGINE_BRIDGE_RESPONSE_SCHEMA
            or response.get("engine") != self._requirement.engine
            or response.get("operation") != operation
            or response.get("request_sha256") != request_sha256
        ):
            raise ExternalEngineError(
                f"{self._requirement.engine} session response identity is invalid"
            )
        receipt = validate_engine_runtime_receipt(
            response.get("receipt"), requirement=self._requirement
        )
        if not secrets.compare_digest(
            _canonical_json_bytes(receipt),
            _canonical_json_bytes(self._expected_receipt),
        ):
            raise ExternalEngineError(
                f"{self._requirement.engine} session runtime identity drifted"
            )
        if response.get("status") != "ok":
            error = response.get("error")
            error_type = error.get("type") if isinstance(error, dict) else None
            phase = error.get("phase") if isinstance(error, dict) else None
            if not isinstance(error_type, str) or _ERROR_TYPE.fullmatch(error_type) is None:
                error_type = "ExternalEngineFailure"
            if phase not in {"identity", "execution", "artifact"}:
                phase = "execution"
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime failed during {phase} "
                f"({error_type})"
            )
        if response.get("error") is not None:
            raise ExternalEngineError(
                f"{self._requirement.engine} successful session response is inconsistent"
            )
        descriptors = response.get("artifacts")
        if not isinstance(descriptors, list) or len(descriptors) > _MAX_ARTIFACTS:
            raise ExternalEngineError(
                f"{self._requirement.engine} session artifact inventory is invalid"
            )
        artifacts: dict[str, bytes] = {}
        for item in descriptors:
            if not isinstance(item, dict) or set(item) != {"file", "sha256", "bytes"}:
                raise ExternalEngineError(
                    f"{self._requirement.engine} session artifact descriptor is invalid"
                )
            filename = item.get("file")
            if (
                artifact_root is None
                or not isinstance(filename, str)
                or not filename
                or Path(filename).name != filename
                or filename in artifacts
            ):
                raise ExternalEngineError(
                    f"{self._requirement.engine} session artifact name is invalid"
                )
            digest = _full_digest(item.get("sha256"), label="session artifact SHA-256")
            size = _positive_int(
                item.get("bytes"),
                label="session artifact byte count",
                maximum=_MAX_ARTIFACT_BYTES,
            )
            artifact = _read_stable_file(
                artifact_root / filename,
                label=f"{self._requirement.engine} session artifact",
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
            if len(artifact) != size or not secrets.compare_digest(
                hashlib.sha256(artifact).hexdigest(), digest
            ):
                raise ExternalEngineError(
                    f"{self._requirement.engine} session artifact identity is invalid"
                )
            artifacts[filename] = artifact
        if set(artifacts) != expected_artifacts:
            raise ExternalEngineError(
                f"{self._requirement.engine} session artifact inventory is not fixed"
            )
        return EngineExecution(
            result=response.get("result"),
            artifacts=artifacts,
            request_sha256=request_sha256,
            runtime={
                "schema": ENGINE_RUNTIME_EXECUTION_SCHEMA,
                "status": "verified",
                "bridge_sha256": self._bridge_sha256,
                "receipt": receipt,
            },
        )

    def _cleanup_operation(self, *paths: Path) -> None:
        for path in paths:
            try:
                if path == paths[-1] and path.exists():
                    if path.is_symlink() or path.is_junction() or not path.is_dir():
                        raise ExternalEngineError(
                            f"{self._requirement.engine} operation workspace is invalid"
                        )
                    shutil.rmtree(path)
                elif path.exists():
                    path.unlink()
            except OSError as exc:
                raise ExternalEngineError(
                    f"{self._requirement.engine} private session cleanup failed"
                ) from exc

    def close(self, *, timeout_seconds: float | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        failure: BaseException | None = None
        try:
            self._send(b"CLOSE\n")
            timeout = (
                _resolve_timeout(timeout_seconds)
                if timeout_seconds is not None
                else self._default_timeout
            )
            self._wait_signal(
                self._workspace / "close.done", timeout=timeout, phase="close seal"
            )
            raw = _read_stable_file(
                self._workspace / "close.json",
                label=f"{self._requirement.engine} session close response",
                max_bytes=_MAX_RESPONSE_BYTES,
            )
            close = strict_json_loads(raw, max_nodes=100_000, max_depth=16)
            if not isinstance(close, dict) or set(close) != {
                "schema",
                "status",
                "engine",
                "initial_runtime_id",
                "final_receipt",
                "error",
            }:
                raise ExternalEngineError(
                    f"{self._requirement.engine} close receipt fields are invalid"
                )
            final_receipt = (
                validate_engine_runtime_receipt(
                    close.get("final_receipt"), requirement=self._requirement
                )
                if close.get("final_receipt") is not None
                else None
            )
            if (
                close.get("schema") != ENGINE_SESSION_CLOSE_SCHEMA
                or close.get("engine") != self._requirement.engine
                or close.get("initial_runtime_id")
                != self._expected_receipt["runtime_id"]
                or close.get("status") != "ok"
                or close.get("error") is not None
                or final_receipt is None
                or not secrets.compare_digest(
                    _canonical_json_bytes(final_receipt),
                    _canonical_json_bytes(self._expected_receipt),
                )
            ):
                raise ExternalEngineError(
                    f"{self._requirement.engine} runtime failed its closing identity seal"
                )
            process = self._process
            if process is None or process.wait(timeout=timeout) != 0:
                raise ExternalEngineError(
                    f"{self._requirement.engine} runtime session did not close cleanly"
                )
        except BaseException as exc:
            failure = exc
        finally:
            try:
                self._terminate_process()
            except BaseException as exc:
                if failure is None:
                    failure = exc
            try:
                self._temporary.cleanup()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure

    def _terminate_process(self) -> None:
        process = self._process
        self._process = None
        process_group_id = self._process_group_id
        self._process_group_id = None
        windows_job = self._windows_job
        self._windows_job = None
        parent_guard_write = getattr(self, "_parent_guard_write", None)
        self._parent_guard_write = None
        if process is not None and process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if parent_guard_write is not None:
            try:
                os.close(parent_guard_write)
            except OSError:
                pass
        group_failure = False
        if os.name == "nt":
            if windows_job is not None:
                group_failure = not _win_terminate_job(windows_job)
            elif process is not None:
                group_failure = True
        elif process_group_id is not None:
            try:
                import signal  # noqa: PLC0415 - POSIX-only

                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                group_failure = True
        if process is not None:
            if process.poll() is None and group_failure:
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                group_failure = True
        if os.name == "nt" and windows_job is not None:
            try:
                if not _win_wait_job_empty(windows_job, timeout_seconds=5):
                    group_failure = True
            finally:
                _win_close_handle(windows_job)
        if group_failure:
            raise ExternalEngineError(
                f"{self._requirement.engine} isolated runtime process tree could "
                "not be confirmed terminated"
            )

    def abort(self) -> None:
        if self._closed:
            return
        self._closed = True
        failure: BaseException | None = None
        try:
            self._terminate_process()
        except BaseException as exc:
            failure = exc
        try:
            self._temporary.cleanup()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            raise failure


class EngineRuntime:
    """One admitted explicit venv; interpreter paths never enter public state."""

    def __init__(
        self,
        *,
        requirement: EngineRuntimeRequirement,
        interpreter: Path,
        resolved_interpreter: Path,
        receipt: Mapping[str, Any],
    ) -> None:
        self.engine = requirement.engine
        self._requirement = requirement
        self._interpreter = interpreter
        self._resolved_interpreter = resolved_interpreter
        self._receipt = validate_engine_runtime_receipt(
            dict(receipt), requirement=requirement
        )
        self._bridge_sha256 = _bridge_sha256()
        self._admitted = False
        self._closed_verified = False
        self._session: _PersistentEngineSession | None = None

    @property
    def admitted(self) -> bool:
        return self._admitted

    @property
    def runtime_id(self) -> str:
        return str(self._receipt["runtime_id"])

    def public_descriptor(self) -> dict[str, Any]:
        status = "configured"
        if self._closed_verified:
            status = "closed_verified"
        elif self._admitted:
            status = "verified"
        return {
            "schema": ENGINE_RUNTIME_EXECUTION_SCHEMA,
            "status": status,
            "bridge_sha256": self._bridge_sha256,
            "receipt": json.loads(_canonical_json_bytes(self._receipt)),
        }

    def identity_descriptor(self) -> dict[str, Any]:
        """Return only immutable scientific identity, never lifecycle status."""

        return engine_runtime_identity_descriptor(self.public_descriptor())

    def admit(self, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        if self._session is not None:
            return self.public_descriptor()
        if self._closed_verified:
            raise ExternalEngineError(
                f"{self.engine} engine runtime cannot reopen after its closing seal"
            )
        self._session = _PersistentEngineSession(
            interpreter=self._interpreter,
            resolved_interpreter=self._resolved_interpreter,
            requirement=self._requirement,
            expected_receipt=self._receipt,
            bridge_sha256=self._bridge_sha256,
            timeout_seconds=timeout_seconds,
        )
        self._admitted = True
        return self.public_descriptor()

    def execute(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        timeout_seconds: float | None = None,
    ) -> EngineExecution:
        if not self._admitted:
            raise ExternalEngineError(
                f"{self.engine} engine runtime has not passed live admission"
            )
        if operation != self._requirement.operation:
            raise ValueError(
                f"{self.engine} runtime cannot execute operation {operation!r}"
            )
        if self._session is None:
            raise ExternalEngineError(
                f"{self.engine} engine runtime session is unavailable"
            )
        return self._session.execute(
            operation, dict(payload), timeout_seconds=timeout_seconds
        )

    def close(self, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        session = self._session
        if session is None:
            if self._closed_verified:
                return self.public_descriptor()
            raise ExternalEngineError(
                f"{self.engine} engine runtime has no admitted session to close"
            )
        try:
            session.close(timeout_seconds=timeout_seconds)
        finally:
            self._session = None
            self._admitted = False
        self._closed_verified = True
        return self.public_descriptor()

    def abort(self) -> None:
        session = self._session
        self._session = None
        self._admitted = False
        if session is not None:
            session.abort()

    def _invoke(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        timeout_seconds: float | None,
        compare_receipt: bool,
    ) -> EngineExecution:
        return _invoke_worker(
            interpreter=self._interpreter,
            resolved_interpreter=self._resolved_interpreter,
            requirement=self._requirement,
            operation=operation,
            payload=payload,
            expected_receipt=self._receipt if compare_receipt else None,
            timeout_seconds=timeout_seconds,
        )


class EngineRuntimeSelection:
    """Selected runtime handles plus their location-independent identity."""

    def __init__(self, runtimes: Mapping[str, EngineRuntime]) -> None:
        self.runtimes = dict(sorted(runtimes.items()))

    def runtime_for(self, engine: str) -> EngineRuntime:
        try:
            runtime = self.runtimes[engine]
        except KeyError as exc:
            raise RuntimeError(
                f"selected third-party attacker {engine!r} has no admitted explicit venv"
            ) from exc
        if not runtime.admitted:
            raise RuntimeError(
                f"selected third-party attacker {engine!r} runtime is not admitted"
            )
        return runtime

    def admit(self) -> dict[str, Any]:
        admitted: list[EngineRuntime] = []
        try:
            for runtime in self.runtimes.values():
                runtime.admit()
                admitted.append(runtime)
        except BaseException as admission_failure:
            cleanup_failures: list[BaseException] = []
            for runtime in reversed(admitted):
                try:
                    runtime.abort()
                except BaseException as exc:
                    cleanup_failures.append(exc)
            if cleanup_failures:
                raise ExternalEngineError(
                    "isolated engine admission failed and one or more admitted "
                    "runtime trees could not be confirmed terminated: "
                    + ", ".join(type(exc).__name__ for exc in cleanup_failures)
                ) from admission_failure
            raise
        return self.public_descriptor()

    def close(self) -> dict[str, Any]:
        failures: list[BaseException] = []
        for runtime in reversed(tuple(self.runtimes.values())):
            try:
                runtime.close()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise ExternalEngineError(
                "one or more isolated engine runtimes failed their closing seal: "
                + ", ".join(type(exc).__name__ for exc in failures)
            ) from failures[0]
        return self.public_descriptor()

    def abort(self) -> None:
        failures: list[BaseException] = []
        for runtime in reversed(tuple(self.runtimes.values())):
            try:
                runtime.abort()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise ExternalEngineError(
                "one or more isolated engine runtime trees could not be confirmed "
                "terminated: "
                + ", ".join(type(exc).__name__ for exc in failures)
            ) from failures[0]

    def public_descriptor(self) -> dict[str, Any]:
        receipts = [
            runtime.public_descriptor() for runtime in self.runtimes.values()
        ]
        body = {
            "schema": ENGINE_RUNTIME_SELECTION_SCHEMA,
            "runtimes": receipts,
        }
        identity_body = {
            "schema": ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA,
            "runtimes": [runtime.identity_descriptor() for runtime in self.runtimes.values()],
        }
        return {
            **body,
            "selection_sha256": _sha256_json(identity_body),
        }

    def identity_descriptor(self) -> dict[str, Any]:
        return engine_runtime_selection_identity_descriptor(self.public_descriptor())


def parse_engine_runtime_config(
    raw: bytes,
    *,
    selected_attackers: list[str] | tuple[str, ...],
) -> EngineRuntimeSelection:
    """Parse private config bytes and select only required third-party runtimes."""

    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_CONFIG_BYTES:
        raise ValueError("engine runtime config must be a non-empty file no larger than 4 MiB")
    try:
        value = strict_json_loads(raw, max_nodes=100_000, max_depth=16)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("engine runtime config is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "runtimes"}:
        raise ValueError("engine runtime config has invalid root fields")
    if value.get("schema") != ENGINE_RUNTIME_CONFIG_SCHEMA:
        raise ValueError("engine runtime config schema is unsupported")
    configured = value.get("runtimes")
    if not isinstance(configured, dict):
        raise ValueError("engine runtime config runtimes must be an object")
    required = sorted(
        set(name.strip().lower() for name in selected_attackers)
        & RUNTIME_REQUIRED_ATTACKERS
    )
    if not required:
        raise ValueError(
            "engine runtime config is not allowed without a selected "
            "third-party attacker"
        )
    configured_names = set(configured)
    required_names = set(required)
    missing = sorted(required_names - configured_names)
    if missing:
        raise ValueError(
            "selected third-party attackers lack explicit venv runtimes: "
            + ", ".join(missing)
        )
    unknown = sorted(configured_names - RUNTIME_REQUIRED_ATTACKERS)
    if unknown:
        raise ValueError(
            "engine runtime config contains unsupported engines: " + ", ".join(unknown)
        )
    unselected = sorted(configured_names - required_names)
    if unselected:
        raise ValueError(
            "engine runtime config contains unselected engines: "
            + ", ".join(unselected)
        )

    selected: dict[str, EngineRuntime] = {}
    venv_roots: dict[Path, str] = {}
    for engine in required:
        entry = configured[engine]
        if not isinstance(entry, dict) or set(entry) != {"interpreter", "receipt"}:
            raise ValueError(f"engine runtime entry {engine!r} has invalid fields")
        requirement = ENGINE_RUNTIME_REQUIREMENTS[engine]
        receipt = validate_engine_runtime_receipt(
            entry["receipt"], requirement=requirement
        )
        interpreter, resolved = _resolve_interpreter(
            entry["interpreter"], label=f"{engine} interpreter"
        )
        venv_root = interpreter.parent.resolve(strict=True).parent
        if venv_root == Path(sys.prefix).resolve(strict=True):
            raise ValueError(
                f"{engine} runtime must not reuse the Runner virtual environment"
            )
        previous = venv_roots.setdefault(venv_root, engine)
        if previous != engine:
            raise ValueError(
                f"third-party engines {previous!r} and {engine!r} share one interpreter; "
                "each framework requires its own venv"
            )
        selected[engine] = EngineRuntime(
            requirement=requirement,
            interpreter=interpreter,
            resolved_interpreter=resolved,
            receipt=receipt,
        )
    return EngineRuntimeSelection(selected)


def require_admitted_engine_runtime(runtime: object, engine: str) -> object:
    """Validate the private handle contract used by adapter constructors.

    ``run_matrix`` supplies :class:`EngineRuntime`.  Duck typing is retained for
    deterministic unit fixtures; attacker JSON cannot construct Python objects,
    so this does not widen the configuration trust boundary.
    """

    if (
        runtime is None
        or getattr(runtime, "engine", None) != engine
        or getattr(runtime, "admitted", None) is not True
        or not callable(getattr(runtime, "execute", None))
        or not callable(getattr(runtime, "public_descriptor", None))
    ):
        raise RuntimeError(
            f"{engine} requires its own live-admitted explicit virtual environment"
        )
    descriptor = runtime.public_descriptor()
    encoded = _canonical_json_bytes(descriptor)
    # Defensive path/privacy check for test doubles and future handle types.
    lowered = encoded.lower()
    if b'"interpreter"' in lowered or b'"path"' in lowered or b'"prefix"' in lowered:
        raise ValueError(f"{engine} runtime public descriptor contains a private locator")
    return runtime


def inspect_engine_runtime(
    interpreter: str | os.PathLike[str],
    engine: str,
    *,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """Provisioning helper: observe a path-free receipt from one explicit venv."""

    requirement = ENGINE_RUNTIME_REQUIREMENTS.get(engine)
    if requirement is None:
        raise ValueError(f"unsupported engine runtime {engine!r}")
    configured, resolved = _resolve_interpreter(
        os.fspath(interpreter), label=f"{engine} interpreter"
    )
    execution = _invoke_worker(
        interpreter=configured,
        resolved_interpreter=resolved,
        requirement=requirement,
        operation="inspect",
        payload={},
        expected_receipt=None,
        timeout_seconds=timeout_seconds,
    )
    receipt = execution.runtime.get("receipt")
    if not isinstance(receipt, Mapping):
        raise ExternalEngineError(f"{engine} inspection returned no runtime receipt")
    return dict(receipt)


def _minimal_child_environment(
    private_home: Path, interpreter: Path
) -> dict[str, str]:
    allowed = {
        "CUDA_DEVICE_ORDER",
        "CUDA_VISIBLE_DEVICES",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "NVIDIA_DRIVER_CAPABILITIES",
        "NVIDIA_VISIBLE_DEVICES",
        "PATHEXT",
        "SYSTEMROOT",
        "TZ",
        "WINDIR",
    }
    source = {name.upper(): value for name, value in os.environ.items()}
    environment = {
        name: source[name]
        for name in sorted(allowed)
        if name in source and "\0" not in source[name] and len(source[name]) <= 32 * 1024
    }
    private = str(private_home)
    environment.update({
        # The only command-search location is the selected venv itself.  The
        # bridge invokes Python by absolute path and never resolves an engine
        # binary through ambient PATH.
        "PATH": str(interpreter.parent),
        "HOME": private,
        "USERPROFILE": private,
        "TMP": private,
        "TEMP": private,
        "TMPDIR": private,
        "XDG_CACHE_HOME": private,
        "PYTHONUNBUFFERED": "1",
    })
    return environment


def _write_create_only(path: Path, payload: bytes) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bridge_sha256() -> str:
    worker = Path(__file__).with_name("_engine_worker.py").resolve(strict=True)
    raw = _read_stable_file(
        worker,
        label="engine bridge worker",
        max_bytes=4 * 1024 * 1024,
    )
    return hashlib.sha256(raw).hexdigest()


def _read_stable_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= max_bytes
        ):
            raise ExternalEngineError(f"{label} is not one bounded regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise ExternalEngineError(f"{label} changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
        final = path.lstat()
        if (
            len(raw) != opened.st_size
            or len(raw) > max_bytes
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            or (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise ExternalEngineError(f"{label} changed while it was read")
        return raw
    except OSError as exc:
        raise ExternalEngineError(f"{label} could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _invoke_worker(
    *,
    interpreter: Path,
    resolved_interpreter: Path,
    requirement: EngineRuntimeRequirement,
    operation: str,
    payload: Mapping[str, Any],
    expected_receipt: Mapping[str, Any] | None,
    timeout_seconds: float | None,
) -> EngineExecution:
    worker = Path(__file__).with_name("_engine_worker.py").resolve(strict=True)
    bridge_sha256 = _bridge_sha256()
    with tempfile.TemporaryDirectory(prefix=f"ura-engine-{requirement.engine}-") as tmp:
        workspace = Path(tmp).resolve(strict=True)
        try:
            os.chmod(workspace, 0o700)
        except OSError:
            pass
        request_path = workspace / "request.json"
        response_path = workspace / "response.json"
        request = {
            "schema": ENGINE_BRIDGE_REQUEST_SCHEMA,
            "engine": requirement.engine,
            "distribution": requirement.distribution,
            "expected_version": requirement.version,
            "bridge_sha256": bridge_sha256,
            "operation": operation,
            "payload": dict(payload),
        }
        request_bytes = _canonical_json_bytes(request)
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        _write_create_only(request_path, request_bytes)
        private_values = (
            str(interpreter),
            str(resolved_interpreter),
            str(worker),
            str(workspace),
            str(request_path),
            str(response_path),
        )
        child_environment = _minimal_child_environment(workspace, interpreter)
        run_engine_command(
            [
                str(interpreter),
                "-I",
                "-S",
                "-B",
                str(worker),
                "--request",
                str(request_path),
                "--response",
                str(response_path),
            ],
            feature=f"{requirement.engine} isolated runtime bridge",
            cwd=workspace,
            env_overrides=child_environment,
            inherit_environment=False,
            redact_values=(*private_values, *child_environment.values()),
            timeout_seconds=timeout_seconds,
        )
        raw_response = _read_stable_file(
            response_path,
            label=f"{requirement.engine} bridge response",
            max_bytes=_MAX_RESPONSE_BYTES,
        )
        try:
            response = strict_json_loads(raw_response, max_nodes=2_000_000, max_depth=32)
        except (UnicodeError, ValueError) as exc:
            raise ExternalEngineError(
                f"{requirement.engine} bridge returned invalid strict JSON"
            ) from exc
        if not isinstance(response, dict) or set(response) != {
            "schema",
            "status",
            "engine",
            "operation",
            "request_sha256",
            "receipt",
            "result",
            "artifacts",
            "error",
        }:
            raise ExternalEngineError(
                f"{requirement.engine} bridge response fields are invalid"
            )
        if (
            response.get("schema") != ENGINE_BRIDGE_RESPONSE_SCHEMA
            or response.get("engine") != requirement.engine
            or response.get("operation") != operation
            or response.get("request_sha256") != request_sha256
        ):
            raise ExternalEngineError(
                f"{requirement.engine} bridge response identity is invalid"
            )
        receipt_value = response.get("receipt")
        receipt = (
            validate_engine_runtime_receipt(
                receipt_value, requirement=requirement
            )
            if receipt_value is not None
            else None
        )
        if expected_receipt is not None and (
            receipt is None
            or not secrets.compare_digest(
                _canonical_json_bytes(receipt),
                _canonical_json_bytes(dict(expected_receipt)),
            )
        ):
            raise ExternalEngineError(
                f"{requirement.engine} live runtime identity differs from its approved receipt"
            )
        if response.get("status") != "ok":
            error = response.get("error")
            error_type = error.get("type") if isinstance(error, dict) else None
            phase = error.get("phase") if isinstance(error, dict) else None
            if not isinstance(error_type, str) or _ERROR_TYPE.fullmatch(error_type) is None:
                error_type = "ExternalEngineFailure"
            if phase not in {"identity", "execution", "artifact"}:
                phase = "execution"
            raise ExternalEngineError(
                f"{requirement.engine} isolated runtime failed during {phase} "
                f"({error_type})"
            )
        if response.get("error") is not None or receipt is None:
            raise ExternalEngineError(
                f"{requirement.engine} successful bridge response is inconsistent"
            )
        artifacts_value = response.get("artifacts")
        if not isinstance(artifacts_value, list) or len(artifacts_value) > _MAX_ARTIFACTS:
            raise ExternalEngineError(
                f"{requirement.engine} bridge artifact inventory is invalid"
            )
        artifacts: dict[str, bytes] = {}
        for item in artifacts_value:
            if not isinstance(item, dict) or set(item) != {"file", "sha256", "bytes"}:
                raise ExternalEngineError(
                    f"{requirement.engine} bridge artifact descriptor is invalid"
                )
            filename = item.get("file")
            if (
                not isinstance(filename, str)
                or not filename
                or Path(filename).name != filename
                or filename in artifacts
            ):
                raise ExternalEngineError(
                    f"{requirement.engine} bridge artifact name is invalid"
                )
            digest = _full_digest(item.get("sha256"), label="bridge artifact SHA-256")
            size = _positive_int(
                item.get("bytes"),
                label="bridge artifact byte count",
                maximum=_MAX_ARTIFACT_BYTES,
            )
            artifact_bytes = _read_stable_file(
                workspace / filename,
                label=f"{requirement.engine} bridge artifact",
                max_bytes=_MAX_ARTIFACT_BYTES,
            )
            if len(artifact_bytes) != size or not secrets.compare_digest(
                hashlib.sha256(artifact_bytes).hexdigest(), digest
            ):
                raise ExternalEngineError(
                    f"{requirement.engine} bridge artifact identity is invalid"
                )
            artifacts[filename] = artifact_bytes
        expected_artifacts = _EXPECTED_ARTIFACTS.get(operation)
        if expected_artifacts is None or set(artifacts) != expected_artifacts:
            raise ExternalEngineError(
                f"{requirement.engine} bridge artifact inventory is not fixed for "
                f"{operation}"
            )
        return EngineExecution(
            result=response.get("result"),
            artifacts=artifacts,
            request_sha256=request_sha256,
            runtime={
                "schema": ENGINE_RUNTIME_EXECUTION_SCHEMA,
                "status": "verified",
                "bridge_sha256": bridge_sha256,
                "receipt": receipt,
            },
        )


__all__ = [
    "ENGINE_BRIDGE_REQUEST_SCHEMA",
    "ENGINE_BRIDGE_RESPONSE_SCHEMA",
    "ENGINE_RUNTIME_CONFIG_SCHEMA",
    "ENGINE_RUNTIME_EXECUTION_SCHEMA",
    "ENGINE_RUNTIME_IDENTITY_SCHEMA",
    "ENGINE_RUNTIME_RECEIPT_SCHEMA",
    "ENGINE_RUNTIME_REQUIREMENTS",
    "ENGINE_RUNTIME_SELECTION_IDENTITY_SCHEMA",
    "ENGINE_RUNTIME_SELECTION_SCHEMA",
    "RUNTIME_REQUIRED_ATTACKERS",
    "EngineExecution",
    "EngineRuntime",
    "EngineRuntimeRequirement",
    "EngineRuntimeSelection",
    "inspect_engine_runtime",
    "engine_runtime_identity_descriptor",
    "engine_runtime_selection_identity_descriptor",
    "parse_engine_runtime_config",
    "require_admitted_engine_runtime",
    "validate_engine_runtime_execution_descriptor",
    "validate_engine_runtime_identity_descriptor",
    "validate_engine_runtime_receipt",
    "validate_engine_runtime_selection_descriptor",
    "validate_engine_runtime_selection_identity_descriptor",
]
