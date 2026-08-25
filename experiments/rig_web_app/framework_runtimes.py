"""Typed Rig Web control surface for the isolated framework installer.

The long-running owner remains ``experiments.framework_runtime_installer``.  This
module only derives a read-only plan and dispatches one exact, lock-selected
framework/action into the installer's named tmux/screen session.  It deliberately
does not create a console ``Job``: retained engineering-campaign events are the
single Jobs/Stats record for this operational work.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from experiments.framework_runtime_installer import (
    DEFAULT_LOCK,
    InstallerError,
    Layout,
    load_lock,
    plan,
    select_frameworks,
)
from ura.strict_json import strict_json_loads

from .campaigns import load_engineering_campaign


_UI_ACTIONS = {"install", "resume", "verify"}
_OBSERVED_ACTIONS = _UI_ACTIONS | {"adopt"}
_PLAN_ACTIONS = _UI_ACTIONS | {"blocked-existing-unverified"}
_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z")
_MAX_DISPATCH_OUTPUT = 64 * 1024
_MAX_EVENT_LOG = 512 * 1024


class FrameworkRuntimeError(RuntimeError):
    """An unavailable, malformed, or rejected runtime-installer operation."""


class FrameworkRuntimeConflict(FrameworkRuntimeError):
    """The submitted action no longer matches the current exact plan."""


@dataclass(frozen=True)
class RuntimeAttempt:
    action: str
    status: str
    at: str
    detail: str


@dataclass(frozen=True)
class FrameworkRuntimeRow:
    framework: str
    display_name: str
    version: str
    runtime: str
    kind: str
    plan_action: str
    latest: RuntimeAttempt | None


@dataclass(frozen=True)
class FrameworkRuntimeSnapshot:
    available: bool
    message: str
    lock_id: str
    campaign_route_id: str
    campaign_state: str
    campaign_status_tag: str
    rows: tuple[FrameworkRuntimeRow, ...]


@dataclass(frozen=True)
class FrameworkRuntimeLaunch:
    launcher: str
    session_name: str
    campaign_route_id: str


@dataclass(frozen=True)
class DispatchResult:
    returncode: int
    stdout: str
    stderr: str


Dispatcher = Callable[[Sequence[str], Mapping[str, str], Path], DispatchResult]


def _default_dispatch(
    argv: Sequence[str],
    environment: Mapping[str, str],
    cwd: Path,
) -> DispatchResult:
    completed = subprocess.run(  # noqa: S603 - exact installer argv, never a shell
        list(argv),
        cwd=cwd,
        env=dict(environment),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=20,
        check=False,
    )
    return DispatchResult(completed.returncode, completed.stdout, completed.stderr)


class FrameworkRuntimeService:
    """Read the checked-in lock and launch one exact installer operation."""

    def __init__(
        self,
        *,
        repo_root: Path,
        results_root: Path,
        state_dir: Path,
        dispatcher: Dispatcher | None = None,
        app_python: Path | None = None,
        base_python: Path | None = None,
    ) -> None:
        self.repo_root = repo_root.resolve(strict=True)
        self.results_root = results_root.resolve(strict=True)
        self.state_dir = Path(os.path.abspath(state_dir))
        self.lock_path = self.repo_root / "experiments" / DEFAULT_LOCK.name
        self.installer_path = (
            self.repo_root / "experiments" / "framework_runtime_installer.py"
        )
        self.env_root = self.results_root.parent / "framework-venvs"
        self._dispatcher = dispatcher or _default_dispatch
        self._app_python = app_python or Path(sys.executable)
        derived_base = getattr(sys, "_base_executable", None) or sys.executable
        self._base_python = base_python or Path(derived_base)

    @staticmethod
    def _campaign_route(lock_id: str) -> str:
        return f"framework-runtime-{lock_id[:12]}"

    def _layout(self, lock_id: str) -> Layout:
        route = self._campaign_route(lock_id)
        return Layout(
            self.env_root,
            self.results_root / "engineering" / route,
        )

    def capture_binding_paths(self) -> tuple[Path, Path, Path]:
        """Return the checked-in lock and its exact managed runtime roots."""

        lock = load_lock(self.lock_path)
        layout = self._layout(lock["lock_id"])
        return self.lock_path, layout.env_root, layout.state_root

    @staticmethod
    def _public_error(error: BaseException) -> str:
        if isinstance(error, InstallerError):
            message = str(error).strip()
            if message and not any(character in message for character in ("/", "\\", "\0")):
                return message[:500]
        return "The checked-in framework runtime lock or retained state is unavailable."

    @staticmethod
    def _latest_attempts(state_root: Path) -> dict[str, RuntimeAttempt]:
        """Read only complete, strict task-log lines from the fixed campaign root."""

        path = state_root / "task-log.jsonl"
        try:
            if path.is_symlink():
                return {}
            resolved = path.resolve(strict=True)
            root = state_root.resolve(strict=True)
            metadata = resolved.stat()
            if (
                resolved.parent != root
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size > _MAX_EVENT_LOG
            ):
                return {}
            data = resolved.read_bytes()
        except OSError:
            return {}
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            return {}
        lines = text.splitlines()
        if data and not data.endswith(b"\n"):
            lines = lines[:-1]
        attempts: dict[str, RuntimeAttempt] = {}
        for line in lines:
            try:
                event = strict_json_loads(line)
            except (TypeError, ValueError, RecursionError):
                return {}
            if not isinstance(event, dict):
                return {}
            task = event.get("task")
            if not isinstance(task, str) or not task.startswith("framework-runtime-"):
                continue
            framework = task.removeprefix("framework-runtime-")
            if _SAFE_TOKEN.fullmatch(framework) is None:
                continue
            at = event.get("at") if isinstance(event.get("at"), str) else ""
            detail = event.get("detail") if isinstance(event.get("detail"), str) else ""
            detail = detail if _SAFE_TOKEN.fullmatch(detail) else ""
            if event.get("event") == "task_start" and detail in _OBSERVED_ACTIONS:
                attempts[framework] = RuntimeAttempt(detail, "running", at[:40], "")
            elif event.get("event") == "task_end":
                previous = attempts.get(framework)
                status = str(event.get("status") or "failed").strip().lower()
                status = status if status in {"passed", "failed"} else "failed"
                attempts[framework] = RuntimeAttempt(
                    previous.action if previous is not None else "",
                    status,
                    at[:40],
                    detail,
                )
        return attempts

    def snapshot(self) -> FrameworkRuntimeSnapshot:
        try:
            lock = load_lock(self.lock_path)
            entries = select_frameworks(lock, None)
            layout = self._layout(lock["lock_id"])
            planned = plan(lock, layout, entries)
            actions = {
                str(row["framework"]): str(row["action"])
                for row in planned["actions"]
                if isinstance(row, dict)
            }
            if set(actions) != {str(entry["name"]) for entry in entries} or any(
                action not in _PLAN_ACTIONS for action in actions.values()
            ):
                raise FrameworkRuntimeError("installer plan is incomplete")
            latest = self._latest_attempts(layout.state_root)
            rows = tuple(
                FrameworkRuntimeRow(
                    framework=str(entry["name"]),
                    display_name=str(entry.get("canonical_name") or entry["name"]),
                    version=str(entry.get("version") or ""),
                    runtime=str(entry["runtime"]),
                    kind=str(entry.get("kind") or "isolated runtime"),
                    plan_action=actions[str(entry["name"])],
                    latest=latest.get(str(entry["name"])),
                )
                for entry in entries
            )
            route = self._campaign_route(lock["lock_id"])
            campaign = load_engineering_campaign(self.results_root, route)
            return FrameworkRuntimeSnapshot(
                available=True,
                message="",
                lock_id=str(lock["lock_id"]),
                campaign_route_id=route,
                campaign_state=campaign.state if campaign is not None else "idle",
                campaign_status_tag=(
                    campaign.status_tag if campaign is not None else "not started"
                ),
                rows=rows,
            )
        except (FrameworkRuntimeError, InstallerError, OSError, TypeError, ValueError) as exc:
            return FrameworkRuntimeSnapshot(
                available=False,
                message=self._public_error(exc),
                lock_id="",
                campaign_route_id="",
                campaign_state="unavailable",
                campaign_status_tag="unavailable",
                rows=(),
            )

    @staticmethod
    def _exact_path(path: Path, label: str) -> Path:
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise FrameworkRuntimeError(f"{label} is unavailable") from exc
        if not resolved.is_file():
            raise FrameworkRuntimeError(f"{label} is unavailable")
        return resolved

    def launch(self, framework: str, action: str) -> FrameworkRuntimeLaunch:
        if _SAFE_TOKEN.fullmatch(framework) is None or action not in _UI_ACTIONS:
            raise FrameworkRuntimeError("unsupported framework runtime action")
        snapshot = self.snapshot()
        if not snapshot.available:
            raise FrameworkRuntimeError(snapshot.message)
        row = next((item for item in snapshot.rows if item.framework == framework), None)
        if row is None:
            raise FrameworkRuntimeConflict("framework is absent from the current runtime lock")
        if row.plan_action != action:
            raise FrameworkRuntimeConflict(
                f"the current plan requires {row.plan_action}, not {action}"
            )

        app_python = self._exact_path(self._app_python, "application Python")
        installer = self._exact_path(self.installer_path, "framework runtime installer")
        lock_path = self._exact_path(self.lock_path, "framework runtime lock")
        state_root = self.results_root / "engineering" / snapshot.campaign_route_id
        argv = [
            str(app_python),
            "-I",
            "-B",
            str(installer),
            action,
            "--lock",
            str(lock_path),
            "--env-root",
            str(self.env_root),
            "--state-root",
            str(state_root),
            "--only",
            framework,
            "--session-policy",
            "auto",
        ]
        if row.runtime == "python":
            argv.extend(
                ["--python", str(self._exact_path(self._base_python, "base Python"))]
            )
        environment = {
            "HOME": str(self.state_dir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INPUT": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            dispatched = self._dispatcher(argv, environment, self.repo_root)
        except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
            raise FrameworkRuntimeError("could not launch the named runtime session") from exc
        if (
            len(dispatched.stdout.encode("utf-8")) > _MAX_DISPATCH_OUTPUT
            or len(dispatched.stderr.encode("utf-8")) > _MAX_DISPATCH_OUTPUT
        ):
            raise FrameworkRuntimeError("installer dispatcher returned an oversized response")
        if dispatched.returncode != 0:
            message = "framework runtime launch was rejected"
            try:
                failure = strict_json_loads(dispatched.stderr.strip())
                candidate = failure.get("error") if isinstance(failure, dict) else None
                if (
                    isinstance(candidate, str)
                    and candidate
                    and not any(character in candidate for character in ("/", "\\", "\0"))
                ):
                    message = candidate[:500]
            except (TypeError, ValueError, RecursionError):
                pass
            raise FrameworkRuntimeError(message)
        try:
            response = strict_json_loads(dispatched.stdout.strip())
        except (TypeError, ValueError, RecursionError) as exc:
            raise FrameworkRuntimeError("installer dispatcher returned invalid JSON") from exc
        expected = {
            "schema",
            "launcher",
            "session_name",
            "attach_command",
            "log",
            "exit_marker",
            "status",
        }
        if (
            not isinstance(response, dict)
            or set(response) != expected
            or response.get("schema") != "ura-framework-runtime-session/1"
            or response.get("launcher") not in {"tmux", "screen"}
            or response.get("status") != "running"
            or not isinstance(response.get("session_name"), str)
            or _SAFE_TOKEN.fullmatch(response["session_name"]) is None
        ):
            raise FrameworkRuntimeError("installer dispatcher returned an invalid session")
        return FrameworkRuntimeLaunch(
            launcher=str(response["launcher"]),
            session_name=str(response["session_name"]),
            campaign_route_id=snapshot.campaign_route_id,
        )


def runtime_action_form(data: Mapping[str, str]) -> tuple[str, str]:
    """Validate the entire two-field UI form without accepting duplicate meanings."""

    if set(data) != {"framework", "action"}:
        raise FrameworkRuntimeError("runtime action requires exactly framework and action")
    framework = data["framework"]
    action = data["action"]
    if _SAFE_TOKEN.fullmatch(framework) is None or action not in _UI_ACTIONS:
        raise FrameworkRuntimeError("unsupported framework runtime action")
    return framework, action
