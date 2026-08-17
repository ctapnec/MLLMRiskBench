"""Application initialization, job lifecycle, and request routing."""

from __future__ import annotations

import html
import json
import os
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, urlparse

from .catalog import _REPO_ROOT, _LOG_TAIL_BYTES, Command, COMMANDS, build_argv

from .ui import _STYLE, _FAVICON_SVG, _page

from .artifacts import (
    Job,
    run_kind,
    _argv_out_dir,
    _win_managed_job,
    _win_assign_job,
    _win_close_handle,
    _win_terminate_job,
    collect_usage,
)

from .reports import collect_reports

from .storage import ConsoleDB
from .campaigns import (
    EngineeringCampaign,
    load_engineering_campaign,
    scan_engineering_campaigns,
)


class LifecycleMixin:
    """Socket-free request core; the HTTP layer only delegates here."""

    def __init__(
        self,
        *,
        results_root: Path,
        state_dir: Path,
        repo_root: Path = _REPO_ROOT,
        commands: Mapping[str, Command] | None = None,
        job_id_factory: Callable[[], str] | None = None,
        env_file: Path | None = None,
        gpu_hardware: Mapping[str, Any] | None = None,
        system_hardware: Mapping[str, Any] | None = None,
    ) -> None:
        self.results_root = results_root
        self.state_dir = state_dir
        self.repo_root = repo_root
        from experiments.local_targets import (  # noqa: PLC0415
            startup_gpu_hardware,
            startup_system_hardware,
        )

        self.gpu_hardware = json.loads(
            json.dumps(gpu_hardware if gpu_hardware is not None else startup_gpu_hardware())
        )
        self.system_hardware = json.loads(
            json.dumps(
                system_hardware if system_hardware is not None else startup_system_hardware()
            )
        )
        # A first launch commonly points at a results directory that has not
        # been populated yet.  Make that valid empty state concrete so the
        # artifact browser renders "Empty directory" instead of returning 404.
        self.results_root.mkdir(parents=True, exist_ok=True)
        #: The 600-mode operator secrets file (rig ~/.ura_env). Keys are
        #: written here and mirrored into os.environ; their values are never
        #: read back into a page, logged, or stored in the database.
        self.env_file = env_file if env_file is not None else Path.home() / ".ura_env"
        self.commands = dict(COMMANDS if commands is None else commands)
        self.jobs: dict[str, Job] = {}
        #: The one application lock protecting shared job state (the HTTP
        #: server is multi-threaded; every start/stop/reconcile holds it).
        self._app_lock = threading.RLock()
        #: Serializes read-modify-write of experiments/pricing.json across the
        #: multi-threaded server: the pricing config editor (save_config) and
        #: the pricing fetcher (fetch_pricing) both rewrite that file, and the
        #: fetch does seconds of network I/O between its read and its write, so
        #: without this an overlapping operator save would be silently lost.
        self._pricing_lock = threading.Lock()
        #: Serializes read-modify-write of the operator secrets file so two
        #: concurrent set/clear requests cannot each snapshot the prior file and
        #: drop the other's key on the losing os.replace.
        self._secret_lock = threading.Lock()
        self._job_id_factory = job_id_factory or (lambda: f"job-{secrets.token_hex(6)}")
        self.db = ConsoleDB(state_dir / "console.db")
        self._restore_jobs()
        self._recover_unrecorded_runs()

    def close(self) -> None:
        """Release the database cleanly; running jobs stay detached."""

        with self._app_lock:
            self._reconcile_locked()
            for job in self.jobs.values():
                self._close_handles(job)
            self.db.close()

    def _restore_jobs(self) -> None:
        """Repopulate the Jobs page from prior sessions (read-only handles).

        A restored job's live process handle is gone, so it shows its stored
        state; a job left 'running' when a prior console exited is surfaced
        as 'orphaned' (its detached process may still be alive, but this
        console cannot poll or stop it) and that orphaned state is persisted
        so it survives further restarts.
        """

        rows = self.db.load_jobs()
        if rows is None:
            return
        for row in rows:
            job_id = str(row["job_id"])
            if job_id in self.jobs:
                continue
            stored = str(row["state"] or "unknown")
            restored = "orphaned" if stored == "running" else stored
            try:
                argv = json.loads(row["argv"]) if row["argv"] else []
            except (ValueError, TypeError):
                argv = []
            try:
                params = json.loads(row["builder_params"]) if row["builder_params"] else None
            except (ValueError, TypeError):
                params = None
            job = Job(
                job_id=job_id,
                command=str(row["command"] or ""),
                argv=argv,
                directory=Path(str(row["directory"] or self.state_dir / job_id)),
                process=None,
                started_at=float(row["started_at"] or 0.0),
                ended_at=(float(row["ended_at"]) if row["ended_at"] else None),
                builder_params=params if isinstance(params, dict) else None,
                pin=str(row["pin"] or ""),
                failure=(str(row["failure"]) if row["failure"] else None),
                restored_state=restored,
                restored_exit=(int(row["exit_code"]) if row["exit_code"] is not None else None),
                run_recorded=True,
            )
            self.jobs[job_id] = job
            if restored == "orphaned" and stored != "orphaned":
                self.db.upsert_job(job)  # persist orphaned across restarts

    def _recover_unrecorded_runs(self) -> None:
        """Record runs whose console died before their terminal commit.

        A run-kind job started in a prior session that finished (or whose
        record_terminal never committed) leaves no runs-registry row.  On the
        next startup its detached process is gone, so ``_reconcile_locked``
        (which skips process-less jobs) can never record it.  Here, for every
        restored run-kind job with no runs row, if its output directory holds
        completed markers or its stored state is terminal, record the run and
        its recorded usage once - so an interrupted run is never permanently
        lost from the registry.
        """

        runs = self.db.list_runs()
        if runs is None:
            return
        recorded = {str(row["job_id"]) for row in runs}
        pin = os.environ.get("REF_URA", "")
        for job in self.jobs.values():
            if job.process is not None:
                continue
            if job.job_id in recorded:
                continue
            if run_kind(job.command, job.argv) is None:
                continue
            out_dir = _argv_out_dir(job.argv)
            usage_rows: list[dict[str, Any]] = []
            markers = 0
            if out_dir:
                try:
                    # Startup recovery verifies artifact digests, exactly as
                    # reindex does, so a tampered/changed artifact is not
                    # silently counted.
                    usage_rows, stats = collect_usage(self.repo_root / out_dir, verify_sha=True)
                    markers = stats.get("markers", 0)
                except OSError:
                    usage_rows, markers = [], 0
            terminal = (job.restored_state or "") in {"complete", "failed"}
            if markers or terminal:
                self.db.record_terminal(job, job.pin or pin, usage_rows)

    @staticmethod
    def _close_handles(job: Job) -> None:
        for handle in (job.stdout_handle, job.stderr_handle):
            if handle is not None and not getattr(handle, "closed", True):
                try:
                    handle.close()
                except OSError:
                    pass
        # Releasing a plain Job Object handle never terminates a live process;
        # this is what lets close() detach running jobs honestly.
        if job.job_handle is not None:
            _win_close_handle(job.job_handle)
            job.job_handle = None

    def _reconcile(self) -> None:
        with self._app_lock:
            self._reconcile_locked()

    def _reconcile_locked(self) -> None:
        """Persist live-job state; commit terminal state + usage in one txn.

        ``run_recorded`` flips only after the database transaction commits,
        so an interrupted write is retried on the next reconcile instead of
        being lost.
        """

        pin = os.environ.get("REF_URA", "")
        for job in self.jobs.values():
            if job.process is None:
                continue
            # Sample the terminal state once; pass it through so the upsert and
            # the run/usage transaction cannot disagree if the process exits
            # between polls.
            code = job.process.poll()
            if code is None:
                self.db.upsert_job(job, state="running", exit_code=None)
                continue
            state = "complete" if code == 0 else "failed"
            if job.ended_at is None:
                job.ended_at = time.time()
            if job.run_recorded:
                continue
            self._close_handles(job)
            job.pin = job.pin or pin
            if state == "failed" and job.failure is None:
                tail = self._log_tail(job, "stderr").strip()
                job.failure = tail[-500:] if tail else f"exit {code}"
            usage_rows: list[dict[str, Any]] = []
            out_dir = _argv_out_dir(job.argv)
            if out_dir and run_kind(job.command, job.argv) is not None:
                try:
                    # Normal completion indexing verifies artifact digests too.
                    usage_rows, _stats = collect_usage(self.repo_root / out_dir, verify_sha=True)
                except OSError:
                    usage_rows = []
            if self.db.record_terminal(job, job.pin, usage_rows, state=state, exit_code=code):
                job.run_recorded = True

    # -- job lifecycle -----------------------------------------------------

    #: Receipt env vars a dry lane must not inherit, so an offline command is
    #: genuinely offline and self-contained (its argv carries no receipts and
    #: the environment cannot re-inject them).
    _DRY_SCRUB_ENV = (
        "URA_PROJECT_REVISION_MANIFEST",
        "URA_PROJECT_REVISION_SHA256",
        "URA_SOURCE_CONFORMANCE_MANIFEST",
        "URA_SOURCE_CONFORMANCE_SHA256",
    )

    def start_job(
        self,
        command: str,
        values: Mapping[str, str],
        *,
        builder_params: Mapping[str, str] | None = None,
        scrub_receipt_env: bool = False,
    ) -> Job:
        argv = build_argv(command, values, commands=self.commands)
        with self._app_lock:
            job_id = self._job_id_factory()
            directory = self.state_dir / job_id
            directory.mkdir(parents=True, exist_ok=False)
            (directory / "command.json").write_text(
                json.dumps(
                    {
                        "job_id": job_id,
                        "command": command,
                        "argv": argv,
                    },
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            stdout_handle = (directory / "stdout.log").open("wb")
            stderr_handle = (directory / "stderr.log").open("wb")
            # Each job gets its own process group/session so a stop can
            # terminate the complete child tree, not just the Python driver.
            popen_kwargs: dict[str, Any] = {}
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["start_new_session"] = True
            if scrub_receipt_env:
                child_env = dict(os.environ)
                for name in self._DRY_SCRUB_ENV:
                    child_env.pop(name, None)
                popen_kwargs["env"] = child_env
            try:
                process = subprocess.Popen(  # noqa: S603 - allowlisted argv, shell=False
                    argv,
                    cwd=self.repo_root,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    shell=False,
                    **popen_kwargs,
                )
            except OSError:
                stdout_handle.close()
                stderr_handle.close()
                raise
            # Windows: assign the driver to a managed job so explicit Stop can
            # reliably take the whole tree even if taskkill later fails.
            job_handle = _win_managed_job()
            if job_handle is not None and not _win_assign_job(job_handle, process):
                _win_close_handle(job_handle)
                job_handle = None
            job = Job(
                job_id=job_id,
                command=command,
                argv=argv,
                directory=directory,
                process=process,
                stdout_handle=stdout_handle,
                stderr_handle=stderr_handle,
                builder_params=dict(builder_params) if builder_params else None,
                pin=os.environ.get("REF_URA", ""),
                job_handle=job_handle,
            )
            self.jobs[job_id] = job
            self.db.upsert_job(job)
            return job

    def _terminate_tree(self, job: Job) -> None:
        """Stop the job's complete child-process tree, then the driver.

        Never fatal to the request thread, but never reports a false success:
        if the tree cannot be confirmed stopped, ``job.stop_error`` is set so
        the UI shows an explicit stop failure.  POSIX signals the process group
        (SIGTERM then, on timeout, SIGKILL, regardless of whether the driver
        exited).  Windows runs ``taskkill /T /F`` and CHECKS its return code;
        if that does not confirm the tree is gone, it terminates the job's
        Job Object (a reliable whole-tree kill) rather than killing only the
        direct parent.
        """

        process = job.process
        if process is None or process.poll() is not None:
            self._release_job_handle(job)
            return
        if os.name == "nt":
            self._terminate_tree_windows(job, process)
        else:
            self._terminate_tree_posix(job, process)

    def _terminate_tree_posix(self, job: Job, process: subprocess.Popen) -> None:
        import signal  # noqa: PLC0415 - POSIX-only path

        # Capture the process-group id WHILE the driver is alive: once it exits
        # and is reaped, os.getpgid(pid) raises ESRCH and any surviving group
        # member could no longer be addressed.
        try:
            pgid: int | None = os.getpgid(process.pid)
        except (OSError, ProcessLookupError):
            pgid = None
        self._signal_group(process, signal.SIGTERM, pgid)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # Escalate to the whole group UNCONDITIONALLY after the grace period,
        # using the captured pgid so a child that caught SIGTERM (to finish a
        # paid call) or a driver that already exited is still force-killed, not
        # left spending.  SIGKILL to an already-empty group is a harmless no-op.
        self._signal_group(process, signal.SIGKILL, pgid)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if process.poll() is None:
            job.stop_error = (
                "stop could not be confirmed: SIGTERM and SIGKILL to the "
                f"process group did not terminate PID {process.pid}"
            )
        else:
            job.stop_error = None  # a prior unconfirmed stop is now resolved
            self._release_job_handle(job)

    def _terminate_tree_windows(self, job: Job, process: subprocess.Popen) -> None:
        # 1. taskkill /T /F walks the live tree.  Return code 0 == killed,
        #    128 == PID not found (already gone); anything else is a FAILURE
        #    and must not be treated as success.
        taskkill_ok = False
        try:
            result = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                capture_output=True,
                shell=False,
                check=False,
            )
            taskkill_ok = result.returncode in (0, 128)
        except OSError:
            taskkill_ok = False  # taskkill.exe unavailable
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # 2. If taskkill did not confirm, or the driver is still alive, fall
        #    back to TerminateJobObject (the whole tree, not just the parent).
        if not taskkill_ok or process.poll() is None:
            if job.job_handle is not None:
                _win_terminate_job(job.job_handle)
                _win_close_handle(job.job_handle)
                job.job_handle = None
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        # 3. Verify.  If the driver is still alive we could not confirm the
        #    tree stopped - surface it, do not report a false success.
        if process.poll() is None:
            job.stop_error = (
                "stop could not be confirmed: taskkill and the job-object "
                f"fallback did not terminate PID {process.pid}; the process "
                "tree may still be running"
            )
        else:
            job.stop_error = None  # a prior unconfirmed stop is now resolved
            self._release_job_handle(job)

    @staticmethod
    def _release_job_handle(job: Job) -> None:
        # Closing the plain managed-job handle just frees it; explicit Stop
        # uses TerminateJobObject before reaching this release path.
        if job.job_handle is not None:
            _win_close_handle(job.job_handle)
            job.job_handle = None

    @staticmethod
    def _signal_group(
        process: subprocess.Popen,
        sig: int,
        pgid: int | None = None,
    ) -> None:
        """Signal the job's process group, falling back to the driver.

        ``pgid`` may be captured while the driver is still alive and passed in:
        once the driver exits and is reaped, ``os.getpgid(pid)`` raises ESRCH
        and a surviving group member could no longer be addressed.
        """

        try:
            os.killpg(pgid if pgid is not None else os.getpgid(process.pid), sig)
        except (OSError, ProcessLookupError):
            try:
                process.send_signal(sig)
            except (OSError, ProcessLookupError, ValueError):
                pass

    def stop_job(self, job_id: str) -> Job:
        with self._app_lock:
            job = self.jobs.get(job_id)
            if job is None:
                raise KeyError(f"unknown job {job_id!r}")
            self._terminate_tree(job)
            # Reconcile the terminal state now: close the log handles and
            # commit job + run + usage in one transaction.
            self._reconcile_locked()
            return job

    def reindex_all(self) -> dict[str, Any]:
        """Rebuild the derived usage and report indexes from retained artifacts.

        Serialized with reconcile/start/stop under the application lock so it
        cannot delete a usage row another thread is committing.  It scans the
        results root AND every output directory recorded in the runs registry
        (a lane's --out may legitimately point outside the results root), so a
        rebuild never silently drops usage that reconcile recorded from such a
        directory.
        """

        with self._app_lock:
            roots: dict[str, Path] = {str(self.results_root.resolve()): self.results_root}
            runs = self.db.list_runs() or []
            for row in runs:
                out = str(row["out_dir"] or "").strip()
                if not out:
                    continue
                candidate = self.repo_root / out
                roots.setdefault(str(candidate.resolve()), candidate)
            usage_rows: list[dict[str, Any]] = []
            merged = {
                "markers": 0,
                "skipped_error": 0,
                "skipped_invalid": 0,
                "orphan_responses": 0,
                "truncated": 0,
                "unreadable_artifacts": 0,
            }
            seen: set[tuple[str, str, str, str, str]] = set()
            for root in roots.values():
                if not root.exists():
                    continue
                rows, stats = collect_usage(root, verify_sha=True)
                for key in merged:
                    merged[key] += int(stats.get(key, 0))
                for entry in rows:
                    dedup = (
                        entry["marker_sha"],
                        entry["role"],
                        entry["provider"],
                        entry["model"],
                        entry["category"],
                    )
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    usage_rows.append(entry)
            report_rows = collect_reports(self.results_root)
            ok = self.db.reindex(usage_rows, report_rows)
            return {
                "ok": ok,
                "roots": len(roots),
                "usage_rows": len(usage_rows),
                "reports": len(report_rows),
                **merged,
            }

    def _log_tail(self, job: Job, stream: str) -> str:
        path = job.directory / f"{stream}.log"
        if not path.exists():
            return ""
        data = path.read_bytes()
        return data[-_LOG_TAIL_BYTES:].decode("utf-8", errors="replace")

    def _engineering_campaigns(self) -> list[EngineeringCampaign]:
        """Discover external engineering work from its retained task logs."""

        campaigns, _notice = self._engineering_campaign_scan()
        return campaigns

    def _engineering_campaign_scan(self) -> tuple[list[EngineeringCampaign], str]:
        return scan_engineering_campaigns(self.results_root)

    def _engineering_campaign(self, route_id: str) -> EngineeringCampaign | None:
        return load_engineering_campaign(self.results_root, route_id)

    @staticmethod
    def _engineering_log_tail(campaign: EngineeringCampaign, stream: str) -> str | None:
        path = next((path for key, _label, path in campaign.logs if key == stream), None)
        if path is None:
            return None
        try:
            if path.is_symlink():
                return None
            resolved = path.resolve(strict=True)
            if resolved.parent != campaign.directory or not resolved.is_file():
                return None
            with resolved.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - _LOG_TAIL_BYTES))
                data = handle.read(_LOG_TAIL_BYTES)
        except OSError:
            return ""
        return data[-_LOG_TAIL_BYTES:].decode("utf-8", errors="replace")

    # -- request handling --------------------------------------------------

    def handle(
        self,
        method: str,
        target: str,
        form: Mapping[str, str] | None = None,
    ) -> tuple[int, str, bytes]:
        parsed = urlparse(target)
        path = parsed.path
        query = {key: values[0] for key, values in parse_qs(parsed.query).items() if values}
        try:
            if method == "GET" and path == "/":
                return (
                    200,
                    "text/html; charset=utf-8",
                    self._overview(
                        query.get("reindexed", ""),
                    ),
                )
            if method == "GET" and path == "/static/style.css":
                return 200, "text/css; charset=utf-8", _STYLE.encode("utf-8")
            if method == "GET" and path in {"/static/favicon.svg", "/favicon.ico"}:
                return 200, "image/svg+xml", _FAVICON_SVG
            if method == "GET" and path == "/commands":
                return 200, "text/html; charset=utf-8", self._commands_page()
            if method == "POST" and path == "/jobs":
                data = dict(form or {})
                command = data.pop("command", "")
                if command in {"capture_t3mp3st", "harmbench_capture"}:
                    return (
                        400,
                        "text/plain; charset=utf-8",
                        b"use the validated Capture/Prepare forms on /build",
                    )
                job = self.start_job(command, data)
                return 303, f"/jobs/{job.job_id}", b""
            if method == "GET" and path == "/jobs":
                return 200, "text/html; charset=utf-8", self._jobs_page()
            if method == "GET" and path.startswith("/jobs/campaign/"):
                relative = path.removeprefix("/jobs/campaign/")
                is_log = relative.endswith("/log")
                route_id = relative.removesuffix("/log") if is_log else relative
                if not route_id or "/" in route_id:
                    return 404, "text/plain; charset=utf-8", b"unknown campaign"
                campaign = self._engineering_campaign(route_id)
                if campaign is None:
                    return 404, "text/plain; charset=utf-8", b"unknown campaign"
                if is_log:
                    stream = query.get("stream", "bootstrap")
                    text = self._engineering_log_tail(campaign, stream)
                    if text is None:
                        return 400, "text/plain; charset=utf-8", b"unknown campaign log"
                    return 200, "text/plain; charset=utf-8", text.encode("utf-8")
                return 200, "text/html; charset=utf-8", self._campaign_page(campaign)
            if method == "GET" and path.startswith("/jobs/") and path.endswith("/log"):
                job_id = path.split("/")[2]
                job = self.jobs.get(job_id)
                if job is None:
                    return 404, "text/plain; charset=utf-8", b"unknown job"
                stream = query.get("stream", "stdout")
                if stream not in {"stdout", "stderr"}:
                    return 400, "text/plain; charset=utf-8", b"unknown stream"
                text = self._log_tail(job, stream)
                return 200, "text/plain; charset=utf-8", text.encode("utf-8")
            if method == "GET" and path.startswith("/jobs/"):
                job_id = path.split("/")[2]
                job = self.jobs.get(job_id)
                if job is None:
                    return 404, "text/plain; charset=utf-8", b"unknown job"
                return 200, "text/html; charset=utf-8", self._job_page(job)
            if method == "POST" and path.startswith("/jobs/") and path.endswith("/stop"):
                if path.startswith("/jobs/campaign/"):
                    return (
                        405,
                        "text/plain; charset=utf-8",
                        b"external campaigns are read-only and are not owned by this console",
                    )
                job_id = path.split("/")[2]
                self.stop_job(job_id)
                return 303, f"/jobs/{job_id}", b""
            if method == "GET" and path == "/stats":
                return 200, "text/html; charset=utf-8", self._stats_page()
            if method == "GET" and path == "/build":
                return 200, "text/html; charset=utf-8", self._build_page()
            if method == "POST" and path == "/build/t3mp3st/capture":
                return self._handle_capture("t3mp3st", dict(form or {}))
            if method == "POST" and path == "/build/harmbench/prepare":
                return self._handle_capture("harmbench", dict(form or {}))
            if method == "POST" and path == "/build":
                data = dict(form or {})
                confirmed = data.pop("confirm", "") == "yes"
                preflight_only = data.pop("preflight_only", "") == "yes"
                params = self._builder_params(data)
                errors = self._validate_builder(params)
                if errors:
                    # Reject before any subprocess exists; re-render with
                    # field-level errors and the operator's selections kept.
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._build_page(
                            prefill=params,
                            errors=errors,
                        ),
                    )
                try:
                    command, values, params = self._compose_from_builder(params)
                except ValueError as exc:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._build_page(
                            prefill=params,
                            errors={"models": str(exc)},
                        ),
                    )
                try:
                    attacker_config = self._materialize_prepared_attacker_config(
                        params,
                    )
                except ValueError as exc:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._build_page(
                            prefill=params,
                            errors={"attackers": str(exc)},
                        ),
                    )
                if attacker_config is not None:
                    values["--attacker-config"] = str(attacker_config)
                if preflight_only:
                    # No-call projection: run the SAME grid with
                    # --preflight-only (the CLI makes NO generation calls); it
                    # writes the lane-projection the preview then reads.  Live
                    # attestation is intentionally absent: run_matrix forbids
                    # scope/attestation inputs in preflight-only mode.
                    proj_values = {
                        flag: value
                        for flag, value in values.items()
                        if flag
                        not in (
                            "--dry-run",
                            "--diagnostic-canary",
                            "--attestation-probe",
                            "--execution-scope-id",
                            "--live-attestation-max-age-hours",
                        )
                        and not flag.startswith("--live-attestation#")
                        and not flag.startswith("--live-attestation-sha256#")
                    }
                    proj_values["--preflight-only"] = "on"
                    # Prospective eligibility/projection artifacts must not
                    # share the measured lane's output tree: downstream
                    # cohort scans treat that tree as measurement input.
                    proj_values["--out"] = str(self._preflight_output_dir(params))
                    job = self.start_job(
                        command,
                        proj_values,
                        builder_params=params,
                    )
                    return 303, f"/jobs/{job.job_id}", b""
                mode = params.get("mode", "measured")
                spends_money = not (
                    mode == "dry_run"
                    or (mode == "diagnostic_canary" and params.get("canary_dry") == "on")
                )
                if spends_money and not confirmed:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._preview_page(
                            command,
                            values,
                            params,
                        ),
                    )
                if spends_money:
                    _card, caps_ok = self._ceilings_card(params)
                    if not caps_ok:
                        # Confirmation is never trusted as a bypass: a stale
                        # browser form or direct POST must still present an
                        # exact valid preflight whose calculated bounds fit.
                        return (
                            200,
                            "text/html; charset=utf-8",
                            self._preview_page(
                                command,
                                values,
                                params,
                            ),
                        )
                job = self.start_job(
                    command,
                    values,
                    builder_params=params,
                    scrub_receipt_env=("--dry-run" in values),
                )
                return 303, f"/jobs/{job.job_id}", b""
            if method == "POST" and path == "/db/reindex":
                summary = self.reindex_all()
                return 303, f"/?reindexed={quote(json.dumps(summary, sort_keys=True))}", b""
            if method == "GET" and path == "/config/secrets":
                return (
                    200,
                    "text/html; charset=utf-8",
                    self._secrets_page(
                        saved=query.get("saved", ""),
                    ),
                )
            if method == "POST" and path == "/config/secrets":
                data = dict(form or {})
                name = data.get("name", "")
                action = data.get("action", "set")
                try:
                    if action == "clear":
                        self.clear_secret(name)
                    else:
                        # The value is consumed here and never returned in any
                        # response, redirect, or log.
                        self.set_secret(name, data.get("value", ""))
                except ValueError as exc:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._secrets_page(
                            error=str(exc),
                        ),
                    )
                return 303, f"/config/secrets?saved={quote(name)}", b""
            if method == "POST" and path == "/pricing/fetch":
                summary = self.fetch_pricing()
                note = quote(json.dumps(summary, sort_keys=True))
                return 303, f"/config?file=pricing&fetched={note}", b""
            if method == "GET" and path == "/config":
                return (
                    200,
                    "text/html; charset=utf-8",
                    self._config_page(
                        query.get("file", ""),
                        query.get("saved", ""),
                        fetched=query.get("fetched", ""),
                    ),
                )
            if method == "POST" and path == "/config":
                data = dict(form or {})
                key = data.get("file", "")
                content = data.get("content", "")
                try:
                    self.save_config(key, content)
                except ValueError as exc:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._config_page(
                            key,
                            "",
                            error=str(exc),
                            draft=content,
                        ),
                    )
                return 303, f"/config?file={quote(key)}&saved=1", b""
            if method == "GET" and path == "/artifacts":
                return self._artifacts(query.get("path", ""))
            return 404, "text/plain; charset=utf-8", b"not found"
        except (KeyError, ValueError) as exc:
            body = _page(
                "Request rejected",
                "<div class='card'><h1>Request rejected</h1>"
                f"<pre>{html.escape(str(exc))}</pre></div>",
            )
            return 400, "text/html; charset=utf-8", body
