"""Application initialization, job lifecycle, and request routing."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, urlparse

from ura.strict_json import strict_json_loads
from ura.adapters._engine_runtime import RUNTIME_REQUIRED_ATTACKERS

from .catalog import _REPO_ROOT, _LOG_TAIL_BYTES, Command, COMMANDS, build_argv

from .ui import _STYLE, _FAVICON_SVG, _page

from .artifacts import (
    Job,
    assert_durable_job_state_path_free,
    run_kind,
    _argv_out_dir,
    _win_managed_job,
    _win_assign_job,
    _win_close_handle,
    _win_terminate_job,
    collect_usage,
    derived_path_quarantined,
)

from .reports import collect_report_file
from .log_supervisor import (
    bounded_log_write as _supervisor_bounded_log_write,
    capture_stream as _supervisor_capture_stream,
    redact_stream_prefix as _supervisor_redact_stream_prefix,
    start_detached_redactors,
)

from .storage import ConsoleDB
from .ollama_service import OllamaError, OllamaService, validate_ollama_tag
from .framework_runtimes import (
    FrameworkRuntimeConflict,
    FrameworkRuntimeError,
    FrameworkRuntimeService,
    runtime_action_form,
)
from .campaigns import (
    EngineeringCampaign,
    load_engineering_campaign,
    scan_engineering_campaigns,
)
from .external_measured import (
    ExternalMeasuredJob,
    load_external_measured_job,
    scan_external_measured_jobs,
)


_PRIVATE_LOCAL_CONFIG_ENV = "URA_PRIVATE_TRANSIENT_LOCAL_CONFIG"
_PRIVATE_API_CONFIG_ENV = "URA_PRIVATE_TRANSIENT_API_CONFIG"
_PRIVATE_SOURCE_CONFIG_ENV = "URA_PRIVATE_TRANSIENT_SOURCE_CONFIG"
_PRIVATE_ATTACKER_CONFIG_ENV = "URA_PRIVATE_TRANSIENT_ATTACKER_CONFIG"
_PRIVATE_ENGINE_RUNTIME_CONFIG_ENV = "URA_PRIVATE_TRANSIENT_ENGINE_RUNTIME_CONFIG"
_PRIVATE_PROJECT_REVISION_ENV = "URA_PRIVATE_TRANSIENT_PROJECT_REVISION"
_PRIVATE_SOURCE_CONFORMANCE_ENV = "URA_PRIVATE_TRANSIENT_SOURCE_CONFORMANCE"
_PRIVATE_LIVE_ATTESTATION_ENV_PREFIX = "URA_PRIVATE_TRANSIENT_LIVE_ATTESTATION_"
_PRIVATE_LOCAL_CONFIG_DIRS = ("generated-local-configs", ".private-local-configs")
_LAUNCH_TICKET_TTL_SECONDS = 30 * 60
_MAX_DURABLE_JOB_LOG_BYTES = 16 * 1024 * 1024
_LOG_PIPE_READ_BYTES = 64 * 1024
_LOG_TRUNCATED_MARKER = b"\n[durable job log truncated at the configured byte limit]\n"
_MODEL_ACQUISITION_ACTIVITY_TOKEN_ENV = "URA_MODEL_ACQUISITION_ACTIVITY_TOKEN"
_MODEL_ACQUISITION_MAX_DOWNLOAD_BYTES = 2 * 1024**4
_MODEL_ACQUISITION_MIN_FREE_BYTES = 20 * 1024**3
_MODEL_ACQUISITION_DEADLINE_SECONDS = 24 * 60 * 60
_MODEL_ACQUISITION_WORKFLOW_SCHEMA = "ura-rig-web-acquisition-workflow/1"
_MODEL_ACQUISITION_WORKFLOW_BYTES = 256 * 1024
_MODEL_ACQUISITION_SNAPSHOT_BYTES = 256 * 1024 * 1024
_MODEL_ACQUISITION_TOKEN_FILE = "activity-token.txt"


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
        ollama_service: OllamaService | None = None,
        framework_runtime_service: FrameworkRuntimeService | None = None,
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
        # Paid-run confirmation pages retain only an opaque ticket. The raw
        # builder values (which may contain an operator-local checkpoint path)
        # live in process memory for a short time and are never serialized into
        # HTML, command receipts, Job objects, or SQLite.
        self._launch_tickets: dict[
            str,
            tuple[float, str, dict[str, str], dict[str, bytes]],
        ] = {}
        # Generated local configs contain the raw execution locator. Track the
        # config only while its child is starting so an early child failure or
        # stop still removes it; run_matrix normally unlinks it immediately
        # after its bounded startup read.
        self._transient_local_configs: dict[str, Path] = {}
        self._transient_api_configs: dict[str, Path] = {}
        self._transient_source_configs: dict[str, Path] = {}
        self._transient_attacker_configs: dict[str, Path] = {}
        self._transient_evidence_files: dict[str, tuple[Path, ...]] = {}
        # Every child writes into detached redactor processes.  The console
        # never owns a PIPE reader, so a running child can survive a console
        # close/restart without blocking shutdown or losing its log consumer.
        self._log_capture_workers: dict[str, tuple[Any, ...]] = {}
        # The staged acquisition controller is intentionally memory-only.
        # Private plan/receipt/store/event locators and opaque capabilities
        # never enter Job, SQLite, command.json, Builder parameters, or HTML.
        self._model_acquisition_workflows: dict[str, dict[str, Any]] = {}
        self._model_acquisition_activity: dict[str, dict[str, Any]] = {}
        self.ollama = ollama_service or OllamaService(state_dir)
        self.framework_runtimes = framework_runtime_service or FrameworkRuntimeService(
            repo_root=self.repo_root,
            results_root=self.results_root,
            state_dir=self.state_dir,
        )
        self.db = ConsoleDB(state_dir / "console.db", repo_root=self.repo_root)
        self._restore_jobs()
        self._restore_model_acquisition_workflows()
        self._recover_unrecorded_runs()

    def close(self) -> None:
        """Release the database cleanly; running jobs stay detached."""

        # Unlike experiment jobs, a daemon started by this console is an
        # owned service and must not be orphaned on a clean console shutdown.
        # OllamaService.close() never touches an endpoint it did not start.
        self.ollama.close()
        with self._app_lock:
            if hasattr(self, '_human_reviews'):
                self._human_reviews.close()
            self._reconcile_locked()
            for job in self.jobs.values():
                if job.process is None or job.process.poll() is not None:
                    self._finish_log_capture(job.job_id, timeout=0.1)
                self._close_handles(job)
            # Live supervisors are independent children and retain the only
            # read ends. Dropping these controller handles is an honest detach,
            # not a signal or a wait on the measured child.
            self._log_capture_workers.clear()
            # A private acquisition event belongs to its still-running child;
            # preserve it so a restarted console can recover truthful activity.
            self._model_acquisition_activity.clear()
            self.db.close()

    def _job_from_db_row(self, row: Any) -> tuple[Job, str]:
        """Hydrate one path-sanitized persisted Job without a process handle."""

        job_id = str(row["job_id"])
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
        return (
            Job(
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
                activity=(
                    str(row["activity"])
                    if "activity" in row.keys()
                    and row["activity"] == "model_download"
                    else None
                ),
                restored_state=restored,
                restored_exit=(
                    int(row["exit_code"])
                    if row["exit_code"] is not None
                    else None
                ),
                run_recorded=stored not in {"running", "orphaned"},
            ),
            stored,
        )

    def _restore_jobs(self) -> None:
        """Repopulate the recent live cache from prior sessions."""

        rows = self.db.load_jobs()
        if rows is None:
            return
        for row in rows:
            job_id = str(row["job_id"])
            if job_id in self.jobs:
                continue
            job, stored = self._job_from_db_row(row)
            self.jobs[job_id] = job
            self._restore_job_execution(job)
            if job.restored_state == "orphaned" and stored != "orphaned":
                self.db.upsert_job(job)  # persist orphaned across restarts

    def _restore_job_execution(self, job: Job) -> None:
        """Recover process ownership or a command's durable terminal result."""
        from .job_runtime import RecoveredProcess, read_state
        record = read_state(job.directory)
        if record and record.get("supervisor"):
            job.process = RecoveredProcess(job.directory, record)
            job.ended_at = record.get("ended_at") or job.ended_at
            return
        try:
            launch = json.loads((job.directory / "command.json").read_text())
        except (OSError, ValueError):
            launch = {}
        if launch.get("supervised") and job.restored_state in {"orphaned", "unknown"}:
            job.restored_state = "interrupted"
            job.restored_exit = None
            job.failure = "Console launch was interrupted before its durable process handshake. No automatic relaunch was made."
            job.ended_at = job.ended_at or time.time()
            self.db.upsert_job(job)
            return
        # Older hosted collections predate the supervisor. Their final result
        # is a CLI-owned terminal contract, not a guessed log sentinel.
        if job.command != "hosted_campaign_execute" or job.restored_state not in {"orphaned", "unknown"}:
            return
        out = _argv_out_dir(job.argv)
        if not out:
            return
        result_path = self.repo_root / out / "result.json"
        try:
            result = json.loads(result_path.read_text())
            status = result.get("status")
            if status not in {"responses_collected_awaiting_judging", "collection_needs_continuation"}:
                return
            rows = result.get("jobs")
            if not isinstance(rows, list) or not rows:
                return
            complete = all(row.get("status") == "collected" for row in rows)
            if complete != (status == "responses_collected_awaiting_judging"):
                return
            job.restored_state = "complete" if complete else "failed"
            # This is the command's documented result-to-exit mapping.
            job.restored_exit = 0 if complete else 1
            job.ended_at = result_path.stat().st_mtime
            if not complete:
                tail = self._log_tail(job, "stderr").strip()
                job.failure = tail[-500:] if tail else "Collection needs continuation; retained outputs are preserved."
            self.db.upsert_job(job)
        except (OSError, ValueError, TypeError, AttributeError):
            return

    def _jobs_for_history_window(
        self,
        started_from: float,
        started_to: float,
        *,
        limit: int,
    ) -> tuple[list[Job], bool]:
        """Load the selected Jobs history directly from SQLite.

        ``self.jobs`` is only the recent/live process cache. It must never be
        mistaken for the complete history behind an explicit date filter.
        """

        rows = self.db.load_jobs_between(
            started_from,
            started_to,
            limit=limit + 1,
        )
        if rows is None:
            fallback = [
                job
                for job in self.jobs.values()
                if started_from <= job.started_at <= started_to
            ]
            return sorted(fallback, key=lambda job: job.started_at, reverse=True), False
        truncated = len(rows) > limit
        selected: dict[str, Job] = {}
        for row in rows[:limit]:
            job_id = str(row["job_id"])
            if job_id in self.jobs:
                selected[job_id] = self.jobs[job_id]
            else:
                selected[job_id] = self._job_from_db_row(row)[0]
        # Include a newly started in-memory job even if its first SQLite write
        # was unavailable; the database health banner remains authoritative.
        for job_id, job in self.jobs.items():
            if started_from <= job.started_at <= started_to:
                selected.setdefault(job_id, job)
        return (
            sorted(selected.values(), key=lambda job: job.started_at, reverse=True),
            truncated,
        )

    def _job_for_id(self, job_id: str) -> Job | None:
        # Detail and log routes must publish the same reconciled lifecycle as
        # the Jobs list. In particular, wait for detached log redactors before
        # exposing a terminal state and its retained stderr.
        self._reconcile()
        job = self.jobs.get(job_id)
        if job is not None:
            if job.process is not None and job.state() != "running" and not job.run_recorded:
                self._reconcile()
            return job
        row = self.db.load_job(job_id)
        if row is None:
            return None
        job = self._job_from_db_row(row)[0]
        self._restore_job_execution(job)
        self.jobs[job_id] = job
        return job

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
                    # Routine recovery checks descriptors and accounting. Full
                    # file hashing is an explicit reindex option, not a page cost.
                    usage_rows, stats = collect_usage(self.repo_root / out_dir)
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

    def _reconcile_restored_model_acquisition(self, job: Job) -> None:
        """Project strict plan/receipt facts onto one detached restored row."""

        workflow = self._model_acquisition_workflows.get(job.job_id)
        if workflow is None or job.process is not None:
            return
        if run_kind(job.command, job.argv) == "acquisition_plan":
            if job.state() != "orphaned":
                return
            try:
                self._workflow_plan(workflow)
            except (OSError, TypeError, ValueError):
                return
            job.restored_state = "complete"
            job.restored_exit = 0
            job.ended_at = job.ended_at or time.time()
            self.db.upsert_job(job, state="complete", exit_code=0)
            return
        if job.command != "model_acquire" or job.state() != "orphaned":
            return
        self._refresh_model_acquisition_activity(job)
        try:
            _plan_path, _plan_sha256, plan = self._workflow_plan(workflow)
            self._workflow_receipt(workflow, plan=plan)
        except (OSError, TypeError, ValueError):
            # No receipt is an explicitly unknown detached outcome, not proof
            # of failure. Activity remains authenticated and truthful meanwhile.
            self.db.upsert_job(job, state="orphaned", exit_code=None)
            return
        job.restored_state = "complete"
        job.restored_exit = 0
        job.ended_at = job.ended_at or time.time()
        self._clear_model_acquisition_activity(job)
        self.db.upsert_job(job, state="complete", exit_code=0)

    def _reconcile_locked(self) -> None:
        """Persist live-job state; commit terminal state + usage in one txn.

        ``run_recorded`` flips only after the database transaction commits,
        so an interrupted write is retried on the next reconcile instead of
        being lost.
        """

        pin = os.environ.get("REF_URA", "")
        automatic_ollama_readiness: list[Job] = []
        for job in list(self.jobs.values()):
            if job.process is None:
                self._reconcile_restored_model_acquisition(job)
                continue
            # Sample the terminal state once; pass it through so the upsert and
            # the run/usage transaction cannot disagree if the process exits
            # between polls.
            code = job.process.poll()
            job.exit_code()  # Observes a missing supervisor completion record.
            if code is None:
                if job.command == "model_acquire":
                    self._refresh_model_acquisition_activity(job)
                self.db.upsert_job(job, state="running", exit_code=None)
                continue
            if job.run_recorded:
                if job.command == "ollama_pull" and code == 0:
                    automatic_ollama_readiness.append(job)
                continue
            interrupted = bool(getattr(job.process, "interrupted", False))
            stopped = interrupted and (job.directory / "stop-request.json").exists()
            state = "stopped" if stopped else "interrupted" if interrupted else "complete" if code == 0 else "failed"
            if interrupted:
                code = None
                job.failure = ("Execution stopped by operator request. No child exit code was retained; saved outputs are preserved."
                               if stopped else "Execution process disappeared without a terminal record. Saved outputs are preserved; review before continuing.")
            from .job_runtime import read_state
            execution = getattr(job.process, "terminal", None) or read_state(job.directory)
            if execution and execution.get("ended_at"):
                job.ended_at = execution["ended_at"]
                code = execution["exit_code"]
            if job.ended_at is None:
                job.ended_at = time.time()
            self._finish_log_capture(job.job_id)
            self._close_handles(job)
            self._unlink_transient_local_config(
                self._transient_local_configs.pop(job.job_id, None)
            )
            self._unlink_transient_local_config(
                self._transient_api_configs.pop(job.job_id, None)
            )
            self._unlink_transient_local_config(
                self._transient_source_configs.pop(job.job_id, None)
            )
            self._unlink_transient_local_config(
                self._transient_attacker_configs.pop(job.job_id, None)
            )
            for path in self._transient_evidence_files.pop(job.job_id, ()):
                self._unlink_transient_local_config(path)
            if job.command == "ollama_pull":
                self.ollama.invalidate_roster()
                job.activity = None
            elif job.command == "model_acquire":
                self._clear_model_acquisition_activity(job)
            job.pin = job.pin or pin
            if state == "failed" and job.failure is None:
                tail = self._log_tail(job, "stderr").strip()
                job.failure = tail[-500:] if tail else f"exit {code}"
            usage_rows: list[dict[str, Any]] = []
            out_dir = _argv_out_dir(job.argv)
            if out_dir and run_kind(job.command, job.argv) is not None:
                try:
                    # Normal completion indexing verifies artifact digests too.
                    usage_rows, _stats = collect_usage(self.repo_root / out_dir)
                except OSError:
                    usage_rows = []
            if self.db.record_terminal(job, job.pin, usage_rows, state=state, exit_code=code):
                job.run_recorded = True
                if job.command == "ollama_pull" and code == 0:
                    automatic_ollama_readiness.append(job)
        for parent in automatic_ollama_readiness:
            try:
                self._start_automatic_ollama_readiness(parent)
            except (OllamaError, OSError, TypeError, ValueError):
                # Discovery can be temporarily unavailable immediately after a
                # pull. A later reconciliation retries this idempotent handoff.
                continue

    def _start_automatic_ollama_readiness(self, parent: Job) -> Job | None:
        """Start exactly one readiness job after one successful Ollama pull."""

        params = parent.builder_params or {}
        tag = validate_ollama_tag(str(params.get("ollama_model", "")))
        for existing in self.jobs.values():
            existing_params = existing.builder_params or {}
            if existing_params.get("readiness_parent_job_id") == parent.job_id:
                return existing
        roster = self.ollama.roster({}, force=True)
        rows = roster.get("models")
        if roster.get("available") is not True or not isinstance(rows, list):
            raise ValueError("Ollama readiness discovery is unavailable")
        matches = [
            row
            for row in rows
            if isinstance(row, Mapping) and row.get("tag") == tag
        ]
        if len(matches) != 1:
            raise ValueError("pulled Ollama model is absent or ambiguous in discovery")
        row = matches[0]
        spec = str(row.get("spec", ""))
        digest = str(row.get("digest", "")).lower()
        modalities = row.get("modalities")
        if (
            spec != f"ollama:{tag}"
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(modalities, list)
            or not modalities
            or "text" not in modalities
            or any(item not in {"text", "image"} for item in modalities)
        ):
            raise ValueError("pulled Ollama discovery identity is invalid")
        config = {
            spec: {
                "digest": digest,
                "modalities": list(modalities),
                "num_ctx": "fit",
                "think": self._default_ollama_think(
                    spec, row.get("capabilities")
                ),
            }
        }
        payload = (
            json.dumps(
                config,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        root = self.results_root.resolve() / "local-model-readiness" / parent.job_id
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        config_path = root / "local-config.json"
        if config_path.exists():
            if config_path.is_symlink() or config_path.read_bytes() != payload:
                raise ValueError("automatic Ollama readiness config changed")
        else:
            with config_path.open("xb") as handle:
                handle.write(payload)
        from experiments.local_model_profiles import registry_path  # noqa: PLC0415

        return self.start_job(
            "local_model_readiness",
            {
                "--local": spec,
                "--local-config": str(config_path),
                "--local-config-sha256": hashlib.sha256(payload).hexdigest(),
                "--out": str(root / "readiness.json"),
                "--profile-registry": str(registry_path(self.repo_root)),
            },
            builder_params={
                "local": spec,
                "readiness_parent_job_id": parent.job_id,
                "readiness_trigger": "successful_ollama_pull",
            },
            campaign_id=self.db.workspace_for_job(parent.job_id),
        )

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

    @staticmethod
    def _project_local_specs(
        values: Mapping[str, str],
        identities: Mapping[str, str],
    ) -> dict[str, str]:
        """Replace only model-selector fields with their durable identities."""

        projected = {str(key): str(value) for key, value in values.items()}
        for field in ("local", "--local"):
            if field not in projected:
                continue
            projected_specs = [
                identities.get(item.strip(), item.strip())
                for item in projected[field].split(",")
                if item.strip()
            ]
            if len(projected_specs) != len(set(projected_specs)):
                raise ValueError(
                    "local model selections collapse to a duplicate content identity"
                )
            projected[field] = ",".join(projected_specs)
        for field in ("judge_model", "--judge-model"):
            if field in projected:
                value = projected[field].strip()
                projected[field] = identities.get(value, value)
        for key in tuple(projected):
            if not key.startswith("quantization::"):
                continue
            spec = key.removeprefix("quantization::")
            durable_spec = identities.get(spec, spec)
            if durable_spec == spec:
                continue
            value = projected.pop(key)
            durable_key = f"quantization::{durable_spec}"
            if durable_key in projected:
                raise ValueError(
                    "per-model precision fields collapse to a duplicate content identity"
                )
            projected[durable_key] = value
        return projected

    def _catalog_local_identities(self) -> dict[str, str]:
        """Map configured explicit paths to their content-only identities."""

        try:
            from experiments.local_targets import (  # noqa: PLC0415
                load_roster,
                _models_map,
            )

            catalog = {
                str(spec): dict(entry)
                for spec, entry in _models_map(load_roster(self.repo_root)).items()
                if isinstance(entry, dict)
            }
            configured = self._load_registry(
                "local-targets.json", "rig/local-targets.example.json"
            )
            catalog.update({
                str(spec): dict(entry)
                for spec, entry in configured.items()
                if isinstance(entry, dict)
            })
        except (OSError, TypeError, ValueError):
            return {}
        from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

        identities: dict[str, str] = {}
        for spec, entry in catalog.items():
            backend, separator, model = str(spec).partition(":")
            if separator != ":" or backend.lower() != "vllm":
                continue
            if not _is_explicit_local_path(model):
                continue
            digest = entry.get("digest") if isinstance(entry, Mapping) else None
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-fA-F]{64}", digest):
                identities[str(spec)] = (
                    f"vllm:local-checkpoint@sha256:{digest.lower()}"
                )
        return identities

    def _durable_builder_params(
        self,
        params: Mapping[str, str],
        identities: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        """Return builder state safe for HTML, Job objects, and SQLite."""

        # Selected-config identities are authoritative for this launch, while
        # the full configured catalog is still needed to project inactive judge
        # state and unselected per-model precision controls submitted by the
        # browser.  Passing only the selected subset would retain those paths.
        durable_identities = self._catalog_local_identities()
        if identities:
            durable_identities.update(identities)
        projected = self._project_local_specs(params, durable_identities)

        def bind_path(field: str, label: str, digest_field: str) -> None:
            if not projected.get(field):
                return
            digest = str(projected.get(digest_field, "")).strip().lower()
            projected[field] = (
                f"{label}@sha256:{digest}"
                if re.fullmatch(r"[0-9a-f]{64}", digest)
                else label
            )

        bind_path("project_revision", "private-project-revision", "project_revision_sha")
        bind_path(
            "source_conformance",
            "private-source-conformance",
            "source_conformance_sha",
        )
        bind_path("t3_artifact", "private-t3mp3st-artifact", "t3_artifact_sha")
        bind_path(
            "ideator_manifest",
            "private-ideator-seed-pair-manifest",
            "ideator_manifest_sha",
        )
        bind_path(
            "engine_runtime_config",
            "private-engine-runtime-config",
            "engine_runtime_config_sha",
        )
        if projected.get("harm_config"):
            digest = str(
                projected.get("_attacker_config_snapshot_sha256", "")
            ).strip().lower()
            projected["harm_config"] = (
                f"private-harmbench-config@sha256:{digest}"
                if re.fullmatch(r"[0-9a-f]{64}", digest)
                else "private-harmbench-config"
            )
        for index in range(1, 13):
            bind_path(
                f"att_path{index}",
                "private-live-attestation",
                f"att_sha{index}",
            )
        return projected

    def _runtime_builder_params(self, params: Mapping[str, str]) -> dict[str, str]:
        """Resolve a durable job-page identity back to one configured locator.

        This is used only when an operator reopens a retained job in the
        builder. Ambiguous duplicate digest rows are deliberately left
        unresolved so normal builder validation rejects them instead of
        silently choosing a different checkpoint path.
        """

        forward = self._catalog_local_identities()
        candidates: dict[str, list[str]] = {}
        for runtime_spec, identity in forward.items():
            candidates.setdefault(identity, []).append(runtime_spec)
        inverse = {
            identity: runtime_specs[0]
            for identity, runtime_specs in candidates.items()
            if len(runtime_specs) == 1
        }
        runtime = self._project_local_specs(params, inverse)
        for field, digest_field, label, path_env, digest_env in (
            ("source_conformance", "source_conformance_sha", "private-source-conformance",
             "URA_SOURCE_CONFORMANCE_MANIFEST", "URA_SOURCE_CONFORMANCE_SHA256"),
            ("project_revision", "project_revision_sha", "private-project-revision",
             "URA_PROJECT_REVISION_MANIFEST", "URA_PROJECT_REVISION_SHA256"),
        ):
            digest = str(runtime.get(digest_field, "")).strip().lower()
            configured_digest = os.environ.get(digest_env, "").strip().lower()
            configured_path = os.environ.get(path_env, "").strip()
            if (
                re.fullmatch(r"[0-9a-f]{64}", digest)
                and runtime.get(field) == f"{label}@sha256:{digest}"
                and digest == configured_digest
                and configured_path
            ):
                # Reopen the same receipt, never substitute a changed one.
                # Normal composition still validates its actual file content.
                runtime[field] = configured_path
        receipt_fields = {
            "source_conformance": ("source_conformance_sha", "private-source-conformance"),
            "project_revision": ("project_revision_sha", "private-project-revision"),
            **{f"att_path{index}": (f"att_sha{index}", "private-live-attestation")
               for index in range(1, self._MAX_ATT_ROWS + 1)},
        }
        unresolved = {
            field: (label, str(runtime.get(digest_field, "")).strip().lower())
            for field, (digest_field, label) in receipt_fields.items()
            if str(runtime.get(field, "")).startswith(label + "@sha256:")
        }
        if unresolved:
            # Reuse the already retained small receipt files, not the consumed
            # one-shot copies. This also works for standalone acquired jobs.
            candidates: dict[tuple[str, str], str] = {}
            bundle = runtime.get("_execution_config_bundle_sha256", "")
            if re.fullmatch(r"[0-9a-f]{64}", bundle):
                for workflow in self._model_acquisition_workflows.values():
                    if workflow.get("execution_config_bundle_sha256") != bundle:
                        continue
                    for name, entry in workflow.get("snapshot_manifest", {}).items():
                        label = {"source_conformance": "private-source-conformance",
                                 "project_revision": "private-project-revision"}.get(name)
                        if re.fullmatch(r"live_attestation_\d{2}", name):
                            label = "private-live-attestation"
                        if label:
                            candidates.setdefault((label, entry["sha256"]), str(
                                Path(workflow["root"]) / f"snapshot-{name}.bin"
                            ))
            owner = runtime.get("campaign_id", "")
            if owner:
                definition = self.db.workspace_definition(owner)
                for field, (digest_field, label) in receipt_fields.items():
                    path = definition.get(field, "")
                    digest = definition.get(digest_field, "").strip().lower()
                    if path and not path.startswith(label):
                        candidates.setdefault((label, digest), path)
            for field, (label, digest) in unresolved.items():
                if (re.fullmatch(r"[0-9a-f]{64}", digest)
                        and runtime[field] == f"{label}@sha256:{digest}"
                        and (label, digest) in candidates):
                    # Composition still checks the bytes, route and revision.
                    runtime[field] = candidates[(label, digest)]
        return runtime

    def _local_config_projection(
        self,
        values: Mapping[str, str],
    ) -> tuple[dict[str, str], Path | None, str | None]:
        """Read one selected config and derive path-free selected identities.

        The config itself remains the runtime authority. This read is only for
        producing the durable console projection; it never changes the raw
        values passed to the child.
        """

        path_value = str(values.get("--local-config", "")).strip()
        selected = [
            item.strip()
            for item in str(values.get("--local", "")).split(",")
            if item.strip()
        ]
        judge = str(values.get("--judge-model", "")).strip()
        if judge.startswith(("vllm:", "ollama:")) and judge not in selected:
            selected.append(judge)
        if not selected:
            return {}, None, None
        from ura.targets.local import _is_explicit_local_path  # noqa: PLC0415

        explicit = [
            spec
            for spec in selected
            if spec.startswith("vllm:")
            and _is_explicit_local_path(spec.split(":", 1)[1])
        ]
        if not path_value:
            if explicit:
                raise ValueError(
                    "an explicit local checkpoint requires a digest-bearing "
                    "--local-config before its job can be retained"
                )
            return {}, None, None
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        if candidate.is_symlink():
            raise ValueError("--local-config must not be a symlink")
        try:
            path = candidate.resolve(strict=True)
            size = path.stat().st_size
            if not path.is_file() or size <= 0 or size > 1024 * 1024:
                raise ValueError("--local-config must be a regular <=1 MiB JSON file")
            payload = path.read_bytes()
        except OSError as exc:
            if explicit:
                raise ValueError(
                    "the digest-bearing --local-config must be readable before "
                    "an explicit checkpoint job can be retained"
                ) from exc
            return {}, None, None
        if len(payload) != size:
            raise ValueError("--local-config changed while its identity was read")
        try:
            document = strict_json_loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise ValueError("--local-config must contain a JSON object") from exc
        if not isinstance(document, dict):
            raise ValueError("--local-config must contain a JSON object")
        identities: dict[str, str] = {}
        for spec in explicit:
            entry = document.get(spec)
            digest = entry.get("digest") if isinstance(entry, dict) else None
            if not isinstance(digest, str) or re.fullmatch(
                r"[0-9a-fA-F]{64}", digest
            ) is None:
                raise ValueError(
                    "an explicit local checkpoint requires a 64-hex content "
                    "digest before its job can be retained"
                )
            identities[spec] = f"vllm:local-checkpoint@sha256:{digest.lower()}"
        private_path = self._private_local_config_path(values)
        durable_document = {
            identities.get(str(spec), str(spec)): entry
            for spec, entry in document.items()
        }
        if len(durable_document) != len(document):
            raise ValueError(
                "selected local configs collapse to a duplicate content identity"
            )
        durable_payload = (
            json.dumps(
                durable_document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        return identities, private_path, hashlib.sha256(durable_payload).hexdigest()

    def _private_local_config_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        """Resolve only a console-generated one-shot config path."""

        path_value = str(values.get("--local-config", "")).strip()
        if not path_value:
            return None
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = self.repo_root / candidate
        if candidate.is_symlink():
            return None
        try:
            path = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            return None
        private_roots = {
            root.resolve()
            for directory in _PRIVATE_LOCAL_CONFIG_DIRS
            if not (root := self.state_dir / directory).is_symlink()
        }
        if (
            path.parent not in private_roots
            or re.fullmatch(
                r"selected-[0-9a-f]{24}(?:-[0-9a-f]{16})?\.json",
                path.name,
            )
            is None
        ):
            return None
        return path

    def _private_api_config_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        """Resolve only a console-generated read-once hosted config path."""

        path_value = str(values.get("--api-config", "")).strip()
        if not path_value:
            return None
        candidate = Path(path_value).expanduser()
        if candidate.is_symlink():
            return None
        try:
            path = candidate.resolve(strict=False)
            private_root = (self.state_dir / ".private-api-configs").resolve()
        except (OSError, RuntimeError):
            return None
        if (
            path.parent != private_root
            or re.fullmatch(
                r"selected-api-[0-9a-f]{24}-[0-9a-f]{16}\.json",
                path.name,
            )
            is None
        ):
            return None
        return path

    def _private_selected_config_path(
        self,
        values: Mapping[str, str],
        *,
        flag: str,
        directory_name: str,
        filename_prefix: str,
    ) -> Path | None:
        path_value = str(values.get(flag, "")).strip()
        if not path_value:
            return None
        candidate = Path(path_value).expanduser()
        if candidate.is_symlink():
            return None
        try:
            path = candidate.resolve(strict=False)
            private_root = (self.state_dir / directory_name).resolve()
        except (OSError, RuntimeError):
            return None
        if (
            path.parent != private_root
            or re.fullmatch(
                rf"selected-{re.escape(filename_prefix)}-[0-9a-f]{{24}}-"
                r"[0-9a-f]{16}\.json",
                path.name,
            )
            is None
        ):
            return None
        return path

    def _private_source_config_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        return self._private_selected_config_path(
            values,
            flag="--source-config",
            directory_name=".private-source-configs",
            filename_prefix="source",
        )

    def _private_attacker_config_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        return self._private_selected_config_path(
            values,
            flag="--attacker-config",
            directory_name=".private-attacker-configs",
            filename_prefix="attacker",
        )

    def _private_engine_runtime_config_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        return self._private_selected_config_path(
            values,
            flag="--engine-runtime-config",
            directory_name=".private-engine-runtime-configs",
            filename_prefix="engine-runtime",
        )

    def _private_source_conformance_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        return self._private_selected_config_path(
            values,
            flag="--source-conformance",
            directory_name=".private-source-conformance",
            filename_prefix="source-conformance",
        )

    def _private_project_revision_path(
        self, values: Mapping[str, str]
    ) -> Path | None:
        return self._private_selected_config_path(
            values,
            flag="--project-revision",
            directory_name=".private-project-revision",
            filename_prefix="project-revision",
        )

    def _private_live_attestation_paths(
        self, values: Mapping[str, str]
    ) -> tuple[tuple[str, str, Path], ...]:
        selected: list[tuple[str, str, Path]] = []
        for key in sorted(values):
            match = re.fullmatch(r"--live-attestation#([1-9]|1[0-2])", str(key))
            if match is None:
                continue
            index = int(match.group(1))
            path_value = str(values.get(key, "")).strip()
            if not path_value:
                continue
            candidate = Path(path_value).expanduser()
            if candidate.is_symlink() or candidate.is_junction():
                continue
            try:
                path = candidate.resolve(strict=False)
                root = (self.state_dir / ".private-live-attestations").resolve()
            except (OSError, RuntimeError):
                continue
            if (
                path.parent != root
                or re.fullmatch(
                    rf"selected-live-attestation-{index:02d}-[0-9a-f]{{24}}-"
                    r"[0-9a-f]{16}\.json",
                    path.name,
                )
                is None
            ):
                continue
            digest_key = f"--live-attestation-sha256#{index}"
            selected.append((str(key), digest_key, path))
        return tuple(selected)

    def _private_attacker_artifact_paths(
        self, values: Mapping[str, str]
    ) -> tuple[Path, ...]:
        config = self._private_attacker_config_path(values)
        if config is None or not config.exists():
            return ()
        try:
            document = self._strict_config_document(
                str(config),
                str(values.get("--attacker-config-sha256", "")),
            )
        except (OSError, TypeError, ValueError):
            return ()
        root = (self.state_dir / ".private-attacker-artifacts").resolve()
        found: list[Path] = []
        for entry in document.values():
            if not isinstance(entry, Mapping):
                continue
            for field in ("response_artifact", "replay_artifact"):
                raw = entry.get(field)
                if not isinstance(raw, str):
                    continue
                candidate = Path(raw).expanduser()
                if candidate.is_symlink() or candidate.is_junction():
                    continue
                try:
                    path = candidate.resolve(strict=False)
                except (OSError, RuntimeError):
                    continue
                if path.parent == root and re.fullmatch(
                    r"selected-(?:t3mp3st|harmbench)-artifact-[0-9a-f]{24}-"
                    r"[0-9a-f]{16}\.json",
                    path.name,
                ):
                    found.append(path)
            seed_pairs = entry.get("seed_pairs")
            if isinstance(seed_pairs, list):
                for pair in seed_pairs:
                    if (
                        not isinstance(pair, list)
                        or len(pair) != 2
                        or not isinstance(pair[1], str)
                    ):
                        continue
                    candidate = Path(pair[1]).expanduser()
                    if candidate.is_symlink() or candidate.is_junction():
                        continue
                    try:
                        path = candidate.resolve(strict=False)
                    except (OSError, RuntimeError):
                        continue
                    if path.parent == root and re.fullmatch(
                        r"selected-ideator-image-[0-9]{4}-[0-9a-f]{24}-"
                        r"[0-9a-f]{16}\.json",
                        path.name,
                    ):
                        found.append(path)
        return tuple(found)

    def _private_evidence_paths(
        self, values: Mapping[str, str]
    ) -> tuple[Path, ...]:
        paths = [
            path
            for path in (
                self._private_engine_runtime_config_path(values),
                self._private_source_conformance_path(values),
                self._private_project_revision_path(values),
            )
            if path is not None
        ]
        paths.extend(path for _flag, _digest, path in self._private_live_attestation_paths(values))
        paths.extend(self._private_attacker_artifact_paths(values))
        return tuple(dict.fromkeys(paths))

    def _durable_launch_state(
        self,
        command: str,
        values: Mapping[str, str],
        builder_params: Mapping[str, str] | None,
    ) -> tuple[
        list[str],
        dict[str, str] | None,
        Path | None,
        Path | None,
        Path | None,
        Path | None,
        Path | None,
        tuple[Path, ...],
    ]:
        """Build the retained command without changing the execution command."""

        if command != "run_matrix":
            durable_values = self._project_private_runtime_locators(
                command, values
            )
            return (
                build_argv(command, durable_values, commands=self.commands),
                self._durable_builder_params(builder_params) if builder_params else None,
                None,
                None,
                None,
                None,
                None,
                (),
            )
        identities, private_config, config_digest = self._local_config_projection(values)
        if private_config is not None:
            raw_digest = str(values.get("--local-config-sha256", "")).strip()
            if re.fullmatch(r"[0-9a-f]{64}", raw_digest) is None:
                raise ValueError(
                    "private --local-config requires an exact lowercase byte SHA-256"
                )
            if builder_params is None or (
                builder_params.get("_local_config_snapshot_sha256", "")
                != config_digest
            ):
                raise ValueError(
                    "selected local config differs from the reviewed snapshot"
                )
        durable_values = self._project_local_specs(values, identities)
        if private_config is not None and config_digest is not None:
            durable_values["--local-config"] = (
                f"private-local-config@sha256:{config_digest}"
            )
        private_api_config = self._private_api_config_path(values)
        if private_api_config is not None:
            api_digest = str(values.get("--api-config-sha256", "")).strip()
            if re.fullmatch(r"[0-9a-f]{64}", api_digest) is None:
                raise ValueError(
                    "private --api-config requires an exact lowercase SHA-256"
                )
            durable_values["--api-config"] = (
                f"private-api-config@sha256:{api_digest}"
            )
        private_source_config = self._private_source_config_path(values)
        if private_source_config is not None:
            source_digest = str(values.get("--source-config-sha256", "")).strip()
            if re.fullmatch(r"[0-9a-f]{64}", source_digest) is None:
                raise ValueError(
                    "private --source-config requires an exact lowercase SHA-256"
                )
            durable_values["--source-config"] = (
                f"private-source-config@sha256:{source_digest}"
            )
        private_attacker_config = self._private_attacker_config_path(values)
        if private_attacker_config is not None:
            attacker_digest = str(
                values.get("--attacker-config-sha256", "")
            ).strip()
            if re.fullmatch(r"[0-9a-f]{64}", attacker_digest) is None:
                raise ValueError(
                    "private --attacker-config requires an exact lowercase SHA-256"
                )
            durable_values["--attacker-config"] = (
                f"private-attacker-config@sha256:{attacker_digest}"
            )
        selected_runtime_attackers = sorted(
            {
                item.strip().lower()
                for item in str(values.get("--attackers", "")).split(",")
                if item.strip()
            }
            & RUNTIME_REQUIRED_ATTACKERS
        )
        private_engine_runtime_config = (
            self._private_engine_runtime_config_path(values)
        )
        if selected_runtime_attackers:
            if private_engine_runtime_config is None or builder_params is None:
                raise ValueError(
                    "selected third-party frameworks require a reviewed private "
                    "engine runtime config"
                )
            engine_digest = str(
                values.get("--engine-runtime-config-sha256", "")
            ).strip()
            if re.fullmatch(r"[0-9a-f]{64}", engine_digest) is None:
                raise ValueError(
                    "private --engine-runtime-config requires an exact lowercase "
                    "SHA-256"
                )
            runtime_params = {
                key: str(value) for key, value in builder_params.items()
            }
            runtime_params["attackers"] = ",".join(selected_runtime_attackers)
            runtime_params["engine_runtime_config"] = str(
                private_engine_runtime_config
            )
            runtime_params["engine_runtime_config_sha"] = engine_digest
            _projection, runtime_binding, _raw, _actual = (
                self._selected_engine_runtime_config_snapshot(runtime_params)
            )
            if runtime_binding != str(
                builder_params.get("_engine_runtime_config_snapshot_sha256", "")
            ):
                raise ValueError(
                    "selected engine runtime config differs from the reviewed snapshot"
                )
            durable_values["--engine-runtime-config"] = (
                f"private-engine-runtime-config@sha256:{engine_digest}"
            )
        elif values.get("--engine-runtime-config"):
            raise ValueError(
                "engine runtime config is not allowed without a selected "
                "third-party framework"
            )
        private_source_conformance = self._private_source_conformance_path(values)
        if private_source_conformance is not None:
            conformance_digest = str(
                values.get("--source-conformance-sha256", "")
            ).strip()
            if re.fullmatch(r"[0-9a-f]{64}", conformance_digest) is None:
                raise ValueError(
                    "private --source-conformance requires an exact lowercase SHA-256"
                )
            durable_values["--source-conformance"] = (
                f"private-source-conformance@sha256:{conformance_digest}"
            )
        private_project_revision = self._private_project_revision_path(values)
        if private_project_revision is not None:
            revision_digest = str(
                values.get("--project-revision-sha256", "")
            ).strip()
            if re.fullmatch(r"[0-9a-f]{64}", revision_digest) is None:
                raise ValueError(
                    "private --project-revision requires an exact lowercase SHA-256"
                )
            durable_values["--project-revision"] = (
                f"private-project-revision@sha256:{revision_digest}"
            )
        for path_flag, digest_flag, _path in self._private_live_attestation_paths(
            values
        ):
            attestation_digest = str(values.get(digest_flag, "")).strip()
            if re.fullmatch(r"[0-9a-f]{64}", attestation_digest) is None:
                raise ValueError(
                    "private --live-attestation requires an exact lowercase SHA-256"
                )
            durable_values[path_flag] = (
                f"private-live-attestation@sha256:{attestation_digest}"
            )
        durable_values = self._project_private_runtime_locators(
            command, durable_values
        )
        durable_params = (
            self._durable_builder_params(builder_params, identities)
            if builder_params
            else None
        )
        return (
            build_argv(command, durable_values, commands=self.commands),
            durable_params,
            private_config,
            private_api_config,
            private_source_config,
            private_attacker_config,
            private_source_conformance,
            self._private_evidence_paths(values),
        )

    @staticmethod
    def _project_private_runtime_locators(
        command: str,
        values: Mapping[str, str],
    ) -> dict[str, str]:
        """Replace controller/acquisition paths with typed durable identities."""

        projected = {str(key): str(value) for key, value in values.items()}
        if command == "run_matrix":
            bindings = (
                (
                    "--model-acquisition-plan",
                    "--model-acquisition-plan-sha256",
                    "private-model-acquisition-plan",
                ),
                (
                    "--model-acquisition-receipt",
                    "--model-acquisition-receipt-sha256",
                    "private-model-acquisition-receipt",
                ),
            )
            opaque = {
                "--model-acquisition-plan-dir": (
                    "private-model-acquisition-plan-dir"
                ),
                "--model-acquisition-store": "private-model-acquisition-store",
            }
        elif command == "model_acquire":
            bindings = (("--plan", "--plan-sha256", "private-acquisition-plan"),)
            opaque = {
                "--store": "private-model-acquisition-store",
                "--receipts-dir": "private-model-acquisition-receipts",
                "--transport-cache": "private-model-acquisition-transport-cache",
                "--activity-event": "private-model-acquisition-activity-event",
            }
        else:
            return projected
        for path_flag, digest_flag, label in bindings:
            if not projected.get(path_flag):
                continue
            digest = projected.get(digest_flag, "").strip().lower()
            projected[path_flag] = (
                f"{label}@sha256:{digest}"
                if re.fullmatch(r"[0-9a-f]{64}", digest)
                else label
            )
        for flag, label in opaque.items():
            if projected.get(flag):
                projected[flag] = label
        return projected

    def _new_launch_ticket(
        self,
        params: Mapping[str, str],
        *,
        purpose: str = "build",
        execution_snapshot: Mapping[str, bytes] | None = None,
    ) -> str:
        """Keep exact confirmation inputs in bounded, expiring process memory."""

        if not re.fullmatch(r"[a-z][a-z0-9:_-]{0,63}", purpose):
            raise ValueError("invalid launch-ticket purpose")

        raw_params = dict(params)
        acquisition_next = raw_params.pop("_model_acquisition_next", "")
        snapshot: dict[str, bytes] = {}
        if purpose in {"build", "acquisition_plan"}:
            if execution_snapshot is None:
                bound_params, snapshot, _snapshot_sha256 = (
                    self._capture_execution_config_snapshot(raw_params)
                )
            else:
                bound_params = {key: str(value) for key, value in raw_params.items()}
                snapshot = self._validate_execution_snapshot(
                    bound_params,
                    execution_snapshot,
                )
            bound_params = self._bind_execution_config_bundle_identity(bound_params)
        else:
            if execution_snapshot:
                raise ValueError("this launch-ticket purpose cannot carry execution bytes")
            bound_params = raw_params
        if purpose == "acquisition_plan":
            if acquisition_next not in {"preflight", "run"}:
                raise ValueError("model acquisition ticket lacks an exact next stage")
            bound_params["_model_acquisition_next"] = acquisition_next
        elif acquisition_next:
            raise ValueError("model acquisition stage marker is invalid for this ticket")
        now = time.time()
        with self._app_lock:
            self._launch_tickets = {
                token: item
                for token, item in self._launch_tickets.items()
                if now - item[0] <= _LAUNCH_TICKET_TTL_SECONDS
            }
            while len(self._launch_tickets) >= 128:
                oldest = min(
                    self._launch_tickets,
                    key=lambda token: self._launch_tickets[token][0],
                )
                self._launch_tickets.pop(oldest, None)
            token = secrets.token_urlsafe(32)
            self._launch_tickets[token] = (
                now,
                purpose,
                dict(bound_params),
                dict(snapshot),
            )
            return token

    def _consume_launch_ticket(
        self,
        token: str,
        *,
        purpose: str = "build",
    ) -> tuple[dict[str, str], dict[str, bytes]] | None:
        """Consume and revalidate one exact ticket plus its held byte snapshot."""

        if not token:
            return None
        now = time.time()
        with self._app_lock:
            item = self._launch_tickets.pop(token, None)
            if item is None or now - item[0] > _LAUNCH_TICKET_TTL_SECONDS:
                return None
            if item[1] != purpose:
                return None
            params = dict(item[2])
            snapshot = dict(item[3])
        if purpose in {"build", "acquisition_plan"}:
            try:
                rebound, _current, _digest = self._capture_execution_config_snapshot(
                    params
                )
                self._validate_execution_snapshot(rebound, snapshot)
                rebound = self._bind_execution_config_bundle_identity(rebound)
            except (KeyError, OSError, TypeError, ValueError):
                return None
            return rebound, snapshot
        return params, snapshot

    def _launch_ticket_params(
        self,
        token: str,
        *,
        purpose: str = "build",
    ) -> dict[str, str] | None:
        """Atomically consume one unexpired exact confirmation input."""

        consumed = self._consume_launch_ticket(token, purpose=purpose)
        return consumed[0] if consumed is not None else None

    @staticmethod
    def _unlink_transient_local_config(path: Path | None) -> None:
        if path is None:
            return
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def _discard_unlaunched_local_config(self, values: Mapping[str, str]) -> None:
        """Remove one-shot generated configs when no child was launched."""

        evidence_paths = self._private_evidence_paths(values)
        self._unlink_transient_local_config(self._private_local_config_path(values))
        self._unlink_transient_local_config(self._private_api_config_path(values))
        self._unlink_transient_local_config(self._private_source_config_path(values))
        self._unlink_transient_local_config(self._private_attacker_config_path(values))
        self._unlink_transient_local_config(
            self._private_source_conformance_path(values)
        )
        for path in evidence_paths:
            self._unlink_transient_local_config(path)

    _MATRIX_BASE_ENV = frozenset({
        "APPDATA",
        "COMSPEC",
        "CUDA_DEVICE_ORDER",
        "CUDA_HOME",
        "CUDA_PATH",
        "CUDA_VISIBLE_DEVICES",
        "HF_HOME",
        "HF_HUB_CACHE",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LD_LIBRARY_PATH",
        "LOCALAPPDATA",
        "MKL_NUM_THREADS",
        "NVIDIA_DRIVER_CAPABILITIES",
        "NVIDIA_VISIBLE_DEVICES",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "PATH",
        "PATHEXT",
        "PROGRAMDATA",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TOKENIZERS_PARALLELISM",
        "TORCH_HOME",
        "TRANSFORMERS_CACHE",
        "TZ",
        "USERPROFILE",
        "WINDIR",
        "XDG_CACHE_HOME",
    })
    _PROVIDER_CHILD_ENV = {
        "anthropic": ("ANTHROPIC_API_KEY",),
        "openai": ("OPENAI_API_KEY",),
        "google": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "deepseek": ("DEEPSEEK_API_KEY",),
        "glm": ("ZHIPU_API_KEY",),
        "kimi": ("MOONSHOT_API_KEY",),
        "qwen": ("DASHSCOPE_API_KEY",),
        "doubao": ("ARK_API_KEY",),
    }
    #: Non-secret operator bounds the CLI reads from its own environment.
    #: ``URA_ENGINE_TIMEOUT_SECONDS`` is the only bound on an isolated-runtime
    #: bridge call: run_matrix exposes no flag for it, every bridge and both
    #: engine seals resolve it from the environment, and it is range-validated
    #: on read. Dropping it silently pinned every console bridge lane to the
    #: 300 s default while the same lane honoured the operator's bound from the
    #: CLI, so the two surfaces ran different lanes under one name.
    _MATRIX_OPTIONAL_ENV = frozenset({
        "URA_MEDIA_ROOTS",
        "URA_ENGINE_TIMEOUT_SECONDS",
        # Build and its Runner child must resolve the same already-approved
        # local profiles; omission falls back to an unrelated repository file.
        "URA_LOCAL_MODEL_PROFILE_REGISTRY",
    })
    #: Non-secret receipt locators the CLI reads as argparse defaults
    #: (run_matrix/rig_check --project-revision / --source-conformance and their
    #: SHA-256 pairs).  Forwarded to a NON-dry matrix child when set in the
    #: console process so a Run-page rig_check with blank receipt fields admits
    #: exactly like the same command in the exported campaign shell; dry lanes
    #: still launch with them scrubbed (``_DRY_SCRUB_ENV``).
    _MATRIX_RECEIPT_ENV = frozenset({
        "URA_PROJECT_REVISION_MANIFEST",
        "URA_PROJECT_REVISION_SHA256",
        "URA_SOURCE_CONFORMANCE_MANIFEST",
        "URA_SOURCE_CONFORMANCE_SHA256",
    })

    def _strict_config_document(
        self,
        path_value: str,
        expected_sha256: str = "",
    ) -> dict[str, object]:
        path = Path(path_value).expanduser().resolve(strict=True)
        raw = self._bounded_private_bytes(
            path,
            max_bytes=1024 * 1024,
            label="selected child config",
        )
        expected = str(expected_sha256).strip().lower()
        if expected:
            if re.fullmatch(r"[0-9a-f]{64}", expected) is None:
                raise ValueError("selected child config SHA-256 must be exact lowercase hex")
            if not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), expected):
                raise ValueError("selected child config SHA-256 does not match")
        value = strict_json_loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("selected child config must contain a JSON object")
        return value

    def _declared_matrix_environment(
        self,
        values: Mapping[str, str],
    ) -> set[str]:
        """Return exact API/source/attacker env names selected by this lane."""

        declared: set[str] = set()
        api_path = str(values.get("--api-config", "")).strip()
        if api_path:
            document = self._strict_config_document(
                api_path,
                str(values.get("--api-config-sha256", "")),
            )
            selected_api = {
                item.strip()
                for item in str(values.get("--api", "")).split(",")
                if item.strip()
            }
            judge_model = str(values.get("--judge-model", "")).strip()
            if judge_model and not judge_model.startswith(("vllm:", "ollama:")):
                selected_api.add(judge_model)
            for spec in selected_api:
                entry = document.get(spec)
                if not isinstance(entry, Mapping):
                    continue
                key_env = entry.get("key_env")
                if isinstance(key_env, str) and re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", key_env
                ):
                    declared.add(key_env)
        source_path = str(values.get("--source-config", "")).strip()
        if source_path:
            document = self._strict_config_document(
                source_path,
                str(values.get("--source-config-sha256", "")),
            )
            selected = {
                item.strip()
                for item in str(values.get("--corpora", "")).split(",")
                if item.strip()
            }
            for arm in selected:
                entry = document.get(arm)
                if not isinstance(entry, Mapping):
                    continue
                path_env = entry.get("path_env")
                if isinstance(path_env, str) and re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", path_env
                ):
                    declared.add(path_env)
        attacker_path = str(values.get("--attacker-config", "")).strip()
        if attacker_path:
            document = self._strict_config_document(
                attacker_path,
                str(values.get("--attacker-config-sha256", "")),
            )

            def collect(node: object) -> None:
                if isinstance(node, Mapping):
                    for key, child in node.items():
                        if key == "credential_env":
                            names = child if isinstance(child, list) else [child]
                            for name in names:
                                if not isinstance(name, str) or re.fullmatch(
                                    r"[A-Za-z_][A-Za-z0-9_]*", name
                                ) is None:
                                    raise ValueError(
                                        "attacker credential_env must name explicit "
                                        "environment variables"
                                    )
                                declared.add(name)
                        else:
                            collect(child)
                elif isinstance(node, list):
                    for child in node:
                        collect(child)

            selected_attackers = {
                item.strip()
                for item in str(values.get("--attackers", "")).split(",")
                if item.strip()
            }
            for attacker in selected_attackers:
                entry = document.get(attacker)
                if entry is not None:
                    collect(entry)
        return declared

    def _selected_matrix_environment_names(
        self,
        values: Mapping[str, str],
    ) -> set[str]:
        selected_names = self._declared_matrix_environment(values)
        configured_key_env: dict[str, str] = {}
        api_path = str(values.get("--api-config", "")).strip()
        if api_path:
            document = self._strict_config_document(
                api_path,
                str(values.get("--api-config-sha256", "")),
            )
            for raw_spec, entry in document.items():
                if not isinstance(raw_spec, str) or not isinstance(entry, Mapping):
                    continue
                key_env = entry.get("key_env")
                if isinstance(key_env, str) and re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", key_env
                ):
                    configured_key_env[raw_spec] = key_env
        selected_specs = {
            item.strip()
            for flag in ("--models", "--api")
            for item in str(values.get(flag, "")).split(",")
            if item.strip()
        }
        judges = {
            item.strip()
            for item in str(values.get("--judges", "")).split(",")
            if item.strip()
        }
        judge_model = str(values.get("--judge-model", "")).strip()
        if (
            "llm" in judges
            and judge_model
            and judge_model != "mock"
            and not judge_model.startswith(("vllm:", "ollama:"))
        ):
            selected_specs.add(judge_model)
        if selected_specs:
            from ura.targets.api import (  # noqa: PLC0415
                canonical_api_target_identity,
            )

            for spec in selected_specs:
                if spec in configured_key_env:
                    selected_names.add(configured_key_env[spec])
                    continue
                try:
                    provider, _model = canonical_api_target_identity(spec)
                except (KeyError, ValueError):
                    continue
                selected_names.update(self._PROVIDER_CHILD_ENV.get(provider, ()))
        return selected_names

    def _run_matrix_child_environment(
        self,
        values: Mapping[str, str],
        *,
        scrub_receipt_env: bool,
    ) -> dict[str, str]:
        """Least-privilege environment for the measured Python driver."""

        allowed = set(self._MATRIX_BASE_ENV) | set(self._MATRIX_OPTIONAL_ENV)
        if not scrub_receipt_env:
            # Build folds these receipt locators into the argv; the generic
            # rig_check Run form relies on the CLI's env defaults exactly as
            # the documented campaign shell does.  A dry lane never sees them.
            allowed.update(self._MATRIX_RECEIPT_ENV)
        allowed.update(self._selected_matrix_environment_names(values))
        # CUDA installations commonly expose a versioned CUDA_PATH_Vx_y key.
        allowed.update(
            name
            for name in os.environ
            if re.fullmatch(r"CUDA_PATH_V\d+_\d+", name.upper())
        )
        return self._selected_child_environment(allowed)

    @staticmethod
    def _selected_child_environment(allowed: set[str]) -> dict[str, str]:
        source_by_upper = {name.upper(): value for name, value in os.environ.items()}
        child: dict[str, str] = {}
        for requested in sorted(allowed):
            found = source_by_upper.get(requested.upper())
            if (
                isinstance(found, str)
                and "\0" not in found
                and len(found) <= 32 * 1024
            ):
                # Preserve the declared spelling on POSIX; Windows treats keys
                # case-insensitively but likewise receives one unique entry.
                child[requested] = found
        child["PYTHONUNBUFFERED"] = "1"
        return child

    def _generic_child_environment(
        self,
        command: str,
        values: Mapping[str, str],
    ) -> dict[str, str]:
        """Minimal environment for every non-matrix allowlisted command."""

        allowed = set(self._MATRIX_BASE_ENV)
        if command in {"hosted_retained_inputs", "hosted_selected_replays",
                       "retained_judge_inventory", "retained_inventory_judge_items",
                       "retained_inventory_judging", "retained_response_judge_pair",
                       "retained_response_judge_pair_execute"}:
            # Original conversion needs the operator-configured corpus locators,
            # not provider keys or the contents of the credentials file.
            sources = self._load_registry("source-instances.json", "rig/source-instances.example.json")
            for source in sources.values():
                name = source.get("path_env") if isinstance(source, Mapping) else None
                if isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    allowed.add(name)
            allowed.add("URA_MEDIA_ROOTS")
        # Offline request construction also needs the configured image roots.
        # Counting permission controls provider keys, not local media access.
        if command == "hosted_campaign_prepare":
            allowed.add("URA_MEDIA_ROOTS")
        if command == "hosted_campaign_prepare" and values.get("--allow-network-counts") in {"on", "true", "1", "yes"}:
            request = self._strict_config_document(str(values.get("--request", "")),
                str(values.get("--request-sha256", "")))
            api = request["sources"]["api_config"]
            allowed.update(self._selected_matrix_environment_names({
                "--api": ",".join(route["target"] for route in request["routes"]),
                "--api-config": api["path"], "--api-config-sha256": api["sha256"],
            }))
        if command in {"hosted_campaign_execute", "retained_native_judge_prepare", "hosted_program_runtime"}:
            from .catalog import _param_values

            if command == "hosted_campaign_execute":
                allowed.add("URA_MODEL_STORE")

            parameters = {parameter.flag: parameter for parameter in self.commands[command].params}
            paths = _param_values(parameters["--program"], values)
            digests = _param_values(parameters["--program-sha256"], values)
            if len(paths) != len(digests):
                raise ValueError("Each selected hosted program needs its matching digest")
            for path, digest in zip(paths, digests):
                program = self._strict_config_document(path, digest)
                for job in program["jobs"]:
                    argv = job["argv"]
                    selected = {flag: argv[index + 1] for index, flag in enumerate(argv[:-1])
                        if flag.startswith("--") and not argv[index + 1].startswith("--")}
                    if command in {"retained_native_judge_prepare", "hosted_program_runtime"}:
                        # Source locators are needed, provider/capture credentials
                        # are not: this command constructs no callable target.
                        selected = {key:value for key,value in selected.items()
                            if key in {"--source-config", "--source-config-sha256", "--corpora"}}
                        allowed.update(self._declared_matrix_environment(selected))
                    else:
                        allowed.update(self._selected_matrix_environment_names(selected))
            allowed.update(self._MATRIX_OPTIONAL_ENV)
            allowed.update(self._MATRIX_RECEIPT_ENV)
        if command == "retained_native_judge_execute":
            prepared = self._strict_config_document(str(values.get("--preparation", "")),
                str(values.get("--preparation-sha256", "")))
            for source in prepared["units"]:
                argv = source["runner_argv"]
                selected = {flag:argv[index+1] for index,flag in enumerate(argv[:-1])
                    if flag in {"--source-config", "--source-config-sha256", "--corpora"}}
                allowed.update(self._declared_matrix_environment(selected))
            allowed.update(self._MATRIX_OPTIONAL_ENV)
            allowed.update(self._MATRIX_RECEIPT_ENV)
        if command == "retained_inventory_judging":
            from experiments.hosted_retained_inputs import _descriptor
            if values.get('--execute'):
                ready = self._strict_config_document(str(Path(str(values['--preparation'])) / 'result.json'))
                request = ready['request']
                model, api_path, api_sha = request['judge_model'], request['api']['path'], request['api']['sha256']
            else:
                model, api_path = str(values.get('--judge-model', '')), str(values.get('--api-config', ''))
                api_sha = _descriptor(Path(api_path))['sha256']
            allowed.update(self._selected_matrix_environment_names({
                '--judges': 'llm', '--judge-model': model, '--api-config': api_path, '--api-config-sha256': api_sha}))
            allowed.update(self._MATRIX_OPTIONAL_ENV)
        if command == "retained_response_judge_pair_execute":
            plan = self._strict_config_document(str(values.get("--plan", "")))
            condition = plan.get("judge_condition")
            if not isinstance(condition, Mapping) or not isinstance(condition.get("model"), str):
                raise ValueError("retained judging plan must identify its judge model")
            allowed.update(self._selected_matrix_environment_names({
                "--judges": "llm", "--judge-model": condition["model"],
                "--api-config": str(values.get("--api-config", "")),
                "--api-config-sha256": str(condition.get("api_config_sha256", "")),
            }))
            allowed.update(self._MATRIX_OPTIONAL_ENV)
        if command == "harmbench_capture":
            # The capture drives the same isolated runtime and resolves the
            # same environment bound when no --timeout-seconds is given.
            allowed.add("URA_ENGINE_TIMEOUT_SECONDS")
            for key, value in values.items():
                if not re.fullmatch(r"--credential-env(?:#\d+)?", str(key)):
                    continue
                name = str(value).strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
                    raise ValueError("HarmBench credential env names must be explicit")
                allowed.add(name)
        if command in {"capture_t3mp3st", "source_conformance"}:
            source_path = str(values.get("--source-config", "")).strip()
            if source_path:
                document = self._strict_config_document(source_path)
                if command == "capture_t3mp3st":
                    selected = {str(values.get("--corpus", "")).strip()}
                elif str(values.get("--manifest", "")).strip():
                    # A receipt VALIDATION names no --arm: it verifies every
                    # admitted arm in the receipt, so it needs every arm's
                    # locator. Forwarding only the arms named on the command
                    # line left validation able to see none of them, so the
                    # console could only ever refuse a receipt the CLI
                    # validates, naming a variable its own parent process
                    # holds. The set is bounded by the operator's own
                    # source-config document.
                    selected = {str(arm) for arm in document}
                else:
                    selected = {
                        str(value).strip()
                        for key, value in values.items()
                        if re.fullmatch(r"--arm(?:#\d+)?", str(key))
                    }
                for arm in selected - {""}:
                    entry = document.get(arm)
                    path_env = entry.get("path_env") if isinstance(entry, Mapping) else None
                    if isinstance(path_env, str) and re.fullmatch(
                        r"[A-Za-z_][A-Za-z0-9_]*", path_env
                    ):
                        allowed.add(path_env)
        child = self._selected_child_environment(allowed)
        # A console may dispatch from a different checkout than the editable
        # installation of its Python interpreter. Honor the selected project.
        child["PYTHONPATH"] = os.pathsep.join((str(self.repo_root.resolve()),
                                              str(self.repo_root.resolve() / "src")))
        if command == "export_aggregators":
            # The aggregator export is the second acquisition child: the gated
            # DecodingTrust/HoliSafe sources read HF_TOKEN from their own
            # environment exactly as the documented campaign shell exports it.
            # Mirror the sealed model_acquire exception (process-memory token,
            # forwarded only when set); no other generic command receives it.
            token = os.environ.get("HF_TOKEN", "").strip()
            if token:
                child["HF_TOKEN"] = token
        return child

    _PRIVATE_LOG_LOCATOR_FLAGS = frozenset({
        "--api-config",
        "--attacker-config",
        "--engine-runtime-config",
        "--local-config",
        "--project-revision",
        "--source-config",
        "--source-conformance",
        "--model-acquisition-plan-dir",
        "--model-acquisition-plan",
        "--model-acquisition-receipt",
        "--model-acquisition-store",
        "--plan",
        "--store",
        "--receipts-dir",
        "--transport-cache",
        "--activity-event",
    })
    _LOG_SECRET_ENV_NAMES = frozenset({
        "ANTHROPIC_API_KEY",
        "ARK_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DASHSCOPE_API_KEY",
        "DEEPSEEK_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "HF_TOKEN",
        "HUGGING_FACE_HUB_TOKEN",
        "URA_MODEL_ACQUISITION_ACTIVITY_TOKEN",
        "MOONSHOT_API_KEY",
        "OPENAI_API_KEY",
        "ZHIPU_API_KEY",
    })

    @staticmethod
    def _locator_text_variants(raw: str) -> set[str]:
        """Represent one private locator as shells/JSON commonly print it."""

        value = str(raw).strip()
        if not value:
            return set()
        variants = {value, value.replace("\\", "/"), value.replace("/", "\\")}
        try:
            path = Path(value).expanduser()
            resolved = str(path.resolve(strict=False))
        except (OSError, RuntimeError, ValueError):
            resolved = ""
        if resolved:
            variants.update({
                resolved,
                resolved.replace("\\", "/"),
                resolved.replace("/", "\\"),
            })
            try:
                variants.add(Path(resolved).as_uri())
            except ValueError:
                pass
        for item in tuple(variants):
            # JSON and repr-style diagnostics double the native backslash.
            variants.add(item.replace("\\", "\\\\"))
            # Native loaders may normalize locator casing (including Unicode
            # path components) before logging. Include those exact spellings;
            # the byte-stream matcher additionally handles ASCII case changes.
            variants.update({item.lower(), item.upper(), item.casefold()})
        return {item for item in variants if item}

    @staticmethod
    def _looks_like_private_locator(value: str, *, key: str = "") -> bool:
        lowered_key = key.casefold()
        if value.startswith(("http://", "https://", "file://", "vllm:")):
            return True
        if Path(value).is_absolute() or re.match(r"^[A-Za-z]:[\\/]", value):
            return True
        return any(
            marker in lowered_key
            for marker in (
                "artifact",
                "base_url",
                "cache",
                "config",
                "endpoint",
                "path",
                "plan",
                "receipt",
                "store",
            )
        )

    def _private_strings_from_config(
        self,
        path_value: str,
        expected_sha256: str = "",
    ) -> set[str]:
        """Collect path/endpoint/env provenance which a child could echo."""

        document = self._strict_config_document(path_value, expected_sha256)
        found: set[str] = set()

        def walk(node: object, *, key: str = "") -> None:
            if isinstance(node, Mapping):
                for child_key, child in node.items():
                    child_name = str(child_key)
                    if self._looks_like_private_locator(child_name, key=key):
                        found.update(self._locator_text_variants(child_name))
                    walk(child, key=child_name)
                return
            if isinstance(node, list):
                for child in node:
                    walk(child, key=key)
                return
            if isinstance(node, str):
                if key in {"credential_env", "key_env"}:
                    found.add(node)
                    secret = os.environ.get(node)
                    if secret and len(secret) >= 4:
                        found.add(secret)
                if self._looks_like_private_locator(node, key=key):
                    found.update(self._locator_text_variants(node))

        walk(document)
        return found

    def _durable_log_redactions(
        self,
        command: str,
        values: Mapping[str, str],
        child_env: Mapping[str, str] | None,
    ) -> tuple[bytes, ...]:
        """Build an in-memory-only exact redaction set for one child."""

        strings: set[str] = set()
        for flag in self._PRIVATE_LOG_LOCATOR_FLAGS:
            raw = str(values.get(flag, "")).strip()
            if raw:
                strings.update(self._locator_text_variants(raw))
        for key, raw_value in values.items():
            if re.fullmatch(r"--live-attestation#(?:[1-9]|1[0-2])", str(key)):
                strings.update(self._locator_text_variants(str(raw_value)))
        for flag in (
            "--api-config",
            "--attacker-config",
            "--engine-runtime-config",
            "--local-config",
            "--source-config",
        ):
            raw = str(values.get(flag, "")).strip()
            if not raw:
                continue
            try:
                strings.update(self._private_strings_from_config(
                    raw,
                    str(values.get(f"{flag}-sha256", "")),
                ))
            except (OSError, TypeError, ValueError):
                # Config admission remains authoritative elsewhere.  Failure
                # to inspect for EXTRA redactions must not erase the exact argv
                # locator patterns already collected above.
                pass
        secret_names = set(self._LOG_SECRET_ENV_NAMES)
        if command == "run_matrix":
            secret_names.update(self._selected_matrix_environment_names(values))
        for name in secret_names:
            value = (child_env or {}).get(name)
            if isinstance(value, str) and len(value) >= 4:
                strings.add(value)
        for name, value in (child_env or {}).items():
            if not isinstance(value, str) or not value:
                continue
            if self._looks_like_private_locator(value, key=str(name)):
                strings.update(self._locator_text_variants(value))
            if "PATH" in str(name).upper():
                separators = {os.pathsep, ";"}
                components = {value}
                for separator in separators:
                    components = {
                        part
                        for candidate in components
                        for part in candidate.split(separator)
                        if part
                    }
                for component in components:
                    if Path(component).is_absolute() or re.match(
                        r"^[A-Za-z]:[\\/]", component
                    ):
                        strings.update(self._locator_text_variants(component))
        encoded: set[bytes] = set()
        for value in strings:
            for encoding in ("utf-8", os.device_encoding(0) or "utf-8"):
                try:
                    item = value.encode(encoding)
                except (LookupError, UnicodeEncodeError):
                    continue
                if item:
                    encoded.add(item)
        return tuple(sorted(encoded, key=lambda item: (-len(item), item)))

    @staticmethod
    def _redact_stream_prefix(
        data: bytes,
        patterns: tuple[bytes, ...],
        *,
        eof: bool,
    ) -> tuple[bytes, bytes]:
        """Redact a safe prefix while retaining any cross-chunk match tail."""
        return _supervisor_redact_stream_prefix(data, patterns, eof=eof)

    @staticmethod
    def _bounded_log_write(
        sink: Any,
        payload: bytes,
        *,
        written: int,
        truncated: bool,
    ) -> tuple[int, bool]:
        return _supervisor_bounded_log_write(
            sink,
            payload,
            written=written,
            truncated=truncated,
            max_bytes=_MAX_DURABLE_JOB_LOG_BYTES,
        )

    @classmethod
    def _capture_redacted_pipe(
        cls,
        source: Any,
        sink: Any,
        patterns: tuple[bytes, ...],
    ) -> None:
        try:
            _supervisor_capture_stream(
                source,
                sink,
                patterns,
                max_bytes=_MAX_DURABLE_JOB_LOG_BYTES,
            )
        except (OSError, ValueError):
            pass
        finally:
            try:
                source.close()
            except (AttributeError, OSError, ValueError):
                pass

    def _start_log_capture(
        self,
        job_id: str,
        stdout_path: Path,
        stderr_path: Path,
        patterns: tuple[bytes, ...],
        child_env: Mapping[str, str],
    ) -> tuple[Any, Any]:
        writers, workers = start_detached_redactors(
            stdout_path=stdout_path.resolve(strict=True),
            stderr_path=stderr_path.resolve(strict=True),
            patterns=patterns,
            base_env=child_env,
            cwd=self.repo_root.resolve(strict=True),
        )
        self._log_capture_workers[job_id] = workers
        return writers

    def _finish_log_capture(self, job_id: str, *, timeout: float = 1.0) -> None:
        workers = self._log_capture_workers.pop(job_id, ())
        for process in workers:
            try:
                process.wait(timeout=timeout)
            except (AttributeError, OSError, subprocess.TimeoutExpired, ValueError):
                pass

    @staticmethod
    def _builder_preflight_values(
        values: Mapping[str, str],
        *,
        output: Path,
    ) -> dict[str, str]:
        """Project one reviewed lane into its exact no-call preflight shape."""

        projected = {
            flag: value
            for flag, value in values.items()
            if flag
            not in {
                "--dry-run",
                "--diagnostic-canary",
                "--attestation-probe",
                # The projected child is always --preflight-only. A stale
                # reviewed value must not carry the standalone-dry-only row
                # exclusion across that purpose boundary.
                "--exclude-tool-conditioned",
                "--ack-hosted-judge-data-transfer",
                "--execution-scope-id",
                "--live-attestation-max-age-hours",
                # A no-call projection must never clear durable circuit state;
                # the reset belongs to the measured resume only.
                "--reset-open-circuits",
            }
            and not flag.startswith("--live-attestation#")
            and not flag.startswith("--live-attestation-sha256#")
        }
        projected["--preflight-only"] = "on"
        projected["--out"] = str(output)
        return projected

    @staticmethod
    def _prepare_private_acquisition_directory(path: Path, *, label: str) -> Path:
        if not path.is_absolute() or path.is_symlink() or path.is_junction():
            raise ValueError(f"{label} must be an absolute non-link directory")
        try:
            prospective = path.resolve(strict=False)
        except OSError as exc:
            raise ValueError(f"{label} cannot be resolved safely") from exc
        if prospective != path:
            raise ValueError(f"{label} must already be a resolved path")
        path.mkdir(parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
        info = path.lstat()
        if (
            resolved != path
            or path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise ValueError(f"{label} must be one resolved directory")
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        return path

    def _new_model_acquisition_workflow_paths(
        self,
        workflow_id: str,
        *,
        restoring: bool = False,
    ) -> dict[str, Path]:
        root = self._prepare_private_acquisition_directory(
            (self.state_dir.resolve() / ".private-model-acquisition" / workflow_id),
            label="private model-acquisition workflow directory",
        )
        plan_dir = self._prepare_private_acquisition_directory(
            root / "plans",
            label="private model-acquisition plan directory",
        )
        receipts_dir = self._prepare_private_acquisition_directory(
            root / "receipts",
            label="private model-acquisition receipt directory",
        )
        # Reuse the operator's installed store. Retain the resolved locator
        # privately so a later environment change cannot redirect this job.
        # Older workflows without a locator keep their original UI-only store.
        locator = root / "model-store.json"
        if locator.exists() or locator.is_symlink():
            stored = strict_json_loads(self._bounded_private_bytes(
                locator, max_bytes=16 * 1024, label="model store locator",
            ).decode("utf-8"))
            if not isinstance(stored, str):
                raise ValueError("model store locator must contain a path")
            store = Path(stored)
            if not store.is_absolute() or not store.is_dir() or store.resolve(strict=True) != store:
                raise ValueError("retained model store is unavailable or unresolved")
        else:
            configured = "" if restoring else os.environ.get("URA_MODEL_STORE", "").strip()
            if configured:
                store = Path(configured).expanduser().resolve(strict=True)
                if not store.is_dir():
                    raise ValueError("configured model store must be an existing directory")
            else:
                store = self._prepare_private_acquisition_directory(
                    self.state_dir.resolve() / ".managed-model-store",
                    label="managed model store",
                )
            self._write_private_workflow_file(locator, (json.dumps(str(store)) + "\n").encode("utf-8"))
        plan_output = self._prepare_private_acquisition_directory(
            self.results_root.resolve() / ".acquisition-planning" / workflow_id,
            label="acquisition planning output directory",
        )
        return {
            "root": root,
            "plan_dir": plan_dir,
            "receipts_dir": receipts_dir,
            "store": store,
            "transport_cache": store / ".transport-cache",
            "activity_event": root / "activity.json",
            "plan_output": plan_output,
        }

    @staticmethod
    def _workflow_component_name(name: str) -> str:
        allowed = {
            "api_config",
            "attacker_config",
            "engine_runtime_config",
            "local_config",
            "project_revision",
            "source_config",
            "source_conformance",
        }
        if name in allowed or re.fullmatch(
            r"(?:live_attestation_\d{2}|attacker_artifact_(?:t3mp3st|harmbench))",
            name,
        ):
            return name
        raise ValueError("private workflow snapshot component is unsupported")

    def _write_private_workflow_file(self, path: Path, payload: bytes) -> None:
        """Atomically replace one operator-private direct child."""

        if not path.is_absolute() or not payload:
            raise ValueError("private workflow file input is invalid")
        parent = path.parent
        parent_info = parent.lstat()
        if (
            parent.is_symlink()
            or parent.is_junction()
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent.resolve(strict=True) != parent
        ):
            raise ValueError("private workflow file parent is unsafe")
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(existing.st_mode)
            or existing.st_nlink != 1
            or path.resolve(strict=True) != path
        ):
            raise ValueError("private workflow file target is unsafe")
        temporary = parent / f".{path.name}.{secrets.token_hex(16)}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = None
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            raise ValueError("private workflow file cannot be written safely") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def _persist_model_acquisition_workflow(
        self,
        workflow: dict[str, Any],
    ) -> None:
        """Persist only path-free workflow identity plus private exact bytes."""

        workflow_id = str(workflow.get("workflow_id", ""))
        if re.fullmatch(r"[0-9a-f]{32}", workflow_id) is None:
            raise ValueError("private workflow id is invalid")
        root = Path(workflow["root"])
        if root.name != workflow_id:
            raise ValueError("private workflow root does not match its id")
        snapshot = self._workflow_execution_snapshot(workflow)
        manifest: dict[str, dict[str, object]] = {}
        for raw_name, payload in sorted(snapshot.items()):
            name = self._workflow_component_name(raw_name)
            if not 0 < len(payload) <= _MODEL_ACQUISITION_SNAPSHOT_BYTES:
                raise ValueError("private workflow snapshot component is oversized")
            path = root / f"snapshot-{name}.bin"
            try:
                existing = self._bounded_private_bytes(
                    path,
                    max_bytes=_MODEL_ACQUISITION_SNAPSHOT_BYTES,
                    label="private workflow snapshot component",
                )
            except ValueError:
                if path.exists() or path.is_symlink() or path.is_junction():
                    raise
                try:
                    with path.open("xb") as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass
                except OSError as exc:
                    path.unlink(missing_ok=True)
                    raise ValueError(
                        "private workflow snapshot cannot be persisted"
                    ) from exc
            else:
                if existing != payload:
                    raise ValueError("private workflow snapshot bytes changed")
            manifest[name] = {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        params = self._durable_builder_params(workflow["params"])
        assert_durable_job_state_path_free([], params)
        snapshot_sha256 = str(params.get("_execution_snapshot_sha256", ""))
        bundle_sha256 = str(
            workflow.get("execution_config_bundle_sha256", "")
        )
        if (
            re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256) is None
            or re.fullmatch(r"[0-9a-f]{64}", bundle_sha256) is None
            or params.get("_execution_config_bundle_sha256") != bundle_sha256
        ):
            raise ValueError("private workflow execution identity is invalid")
        document = {
            "acquisition_job_id": str(workflow.get("acquisition_job_id", "")),
            "consumed": workflow.get("consumed") is True,
            "execution_config_bundle_sha256": bundle_sha256,
            "execution_snapshot_sha256": snapshot_sha256,
            "next_stage": str(workflow.get("next_stage", "")),
            "params": params,
            "plan_job_id": str(workflow.get("plan_job_id", "")),
            "schema": _MODEL_ACQUISITION_WORKFLOW_SCHEMA,
            "snapshot_manifest": manifest,
            "workflow_id": workflow_id,
        }
        if document["next_stage"] not in {"preflight", "run"}:
            raise ValueError("private workflow next stage is invalid")
        for field in ("plan_job_id", "acquisition_job_id"):
            value = str(document[field])
            if value and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value
            ) is None:
                raise ValueError("private workflow job id is invalid")
        raw = (
            json.dumps(
                document,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(raw) > _MODEL_ACQUISITION_WORKFLOW_BYTES:
            raise ValueError("private workflow metadata is oversized")
        self._write_private_workflow_file(root / "workflow.json", raw)
        workflow["snapshot_manifest"] = manifest

    def _workflow_execution_snapshot(
        self,
        workflow: Mapping[str, Any],
    ) -> dict[str, bytes]:
        """Load and verify exact controller-held bytes for one workflow."""

        params = workflow.get("params")
        if not isinstance(params, Mapping):
            raise ValueError("private workflow parameters are invalid")
        held = workflow.get("execution_snapshot")
        if isinstance(held, Mapping):
            return self._validate_execution_snapshot(params, held)
        root = Path(workflow["root"])
        manifest = workflow.get("snapshot_manifest")
        if not isinstance(manifest, Mapping) or not manifest:
            raise ValueError("private workflow snapshot manifest is missing")
        snapshot: dict[str, bytes] = {}
        for raw_name, raw_row in sorted(manifest.items()):
            name = self._workflow_component_name(str(raw_name))
            if not isinstance(raw_row, Mapping) or set(raw_row) != {
                "bytes",
                "sha256",
            }:
                raise ValueError("private workflow snapshot row is invalid")
            size = raw_row.get("bytes")
            digest = raw_row.get("sha256")
            if (
                isinstance(size, bool)
                or not isinstance(size, int)
                or not 0 < size <= _MODEL_ACQUISITION_SNAPSHOT_BYTES
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("private workflow snapshot row is invalid")
            payload = self._bounded_private_bytes(
                root / f"snapshot-{name}.bin",
                max_bytes=size,
                label="private workflow snapshot component",
            )
            if len(payload) != size or not secrets.compare_digest(
                hashlib.sha256(payload).hexdigest(), digest
            ):
                raise ValueError("private workflow snapshot component changed")
            snapshot[name] = payload
        return self._validate_execution_snapshot(params, snapshot)

    @staticmethod
    def _workflow_activity_token_path(workflow: Mapping[str, Any]) -> Path:
        return Path(workflow["root"]) / _MODEL_ACQUISITION_TOKEN_FILE

    def _write_workflow_activity_token(
        self,
        workflow: Mapping[str, Any],
        token: str,
    ) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", token) is None:
            raise ValueError("private workflow activity token is invalid")
        self._write_private_workflow_file(
            self._workflow_activity_token_path(workflow),
            token.encode("ascii"),
        )

    def _read_workflow_activity_token(
        self,
        workflow: Mapping[str, Any],
    ) -> str | None:
        path = self._workflow_activity_token_path(workflow)
        try:
            raw = self._bounded_private_bytes(
                path,
                max_bytes=64,
                label="private workflow activity token",
            )
        except ValueError:
            return None
        try:
            token = raw.decode("ascii")
        except UnicodeError:
            return None
        return token if re.fullmatch(r"[0-9a-f]{64}", token) else None

    def _unlink_workflow_activity_token(
        self,
        workflow: Mapping[str, Any] | None,
    ) -> None:
        if workflow is None:
            return
        self._unlink_transient_local_config(
            self._workflow_activity_token_path(workflow)
        )

    def _restore_model_acquisition_workflows(self) -> None:
        """Recover strict private staged workflows after a console restart."""

        base = self.state_dir.resolve() / ".private-model-acquisition"
        if not base.exists():
            return
        try:
            base_info = base.lstat()
            if (
                base.is_symlink()
                or base.is_junction()
                or not stat.S_ISDIR(base_info.st_mode)
                or base.resolve(strict=True) != base
            ):
                return
            roots = tuple(base.iterdir())
        except OSError:
            return
        for root in roots:
            try:
                info = root.lstat()
                if (
                    re.fullmatch(r"[0-9a-f]{32}", root.name) is None
                    or root.is_symlink()
                    or root.is_junction()
                    or not stat.S_ISDIR(info.st_mode)
                    or root.resolve(strict=True) != root
                ):
                    continue
                raw = self._bounded_private_bytes(
                    root / "workflow.json",
                    max_bytes=_MODEL_ACQUISITION_WORKFLOW_BYTES,
                    label="private acquisition workflow metadata",
                )
                document = strict_json_loads(raw.decode("utf-8"))
                if not isinstance(document, dict) or set(document) != {
                    "acquisition_job_id",
                    "consumed",
                    "execution_config_bundle_sha256",
                    "execution_snapshot_sha256",
                    "next_stage",
                    "params",
                    "plan_job_id",
                    "schema",
                    "snapshot_manifest",
                    "workflow_id",
                }:
                    continue
                if (
                    document.get("schema") != _MODEL_ACQUISITION_WORKFLOW_SCHEMA
                    or document.get("workflow_id") != root.name
                    or document.get("next_stage") not in {"preflight", "run"}
                    or not isinstance(document.get("consumed"), bool)
                    or not isinstance(document.get("params"), dict)
                    or not all(
                        isinstance(key, str) and isinstance(value, str)
                        for key, value in document["params"].items()
                    )
                ):
                    continue
                params = dict(document["params"])
                if (
                    params.get("_execution_snapshot_sha256")
                    != document.get("execution_snapshot_sha256")
                    or params.get("_execution_config_bundle_sha256")
                    != document.get("execution_config_bundle_sha256")
                ):
                    continue
                assert_durable_job_state_path_free([], params)
                plan_job_id = str(document.get("plan_job_id", ""))
                acquisition_job_id = str(document.get("acquisition_job_id", ""))
                if (
                    re.fullmatch(
                        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", plan_job_id
                    )
                    is None
                    or (
                        acquisition_job_id
                        and re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",
                            acquisition_job_id,
                        )
                        is None
                    )
                ):
                    continue
                paths = self._new_model_acquisition_workflow_paths(root.name, restoring=True)
                workflow: dict[str, Any] = {
                    "acquisition_job_id": acquisition_job_id,
                    "consumed": bool(document["consumed"]),
                    "execution_config_bundle_sha256": str(
                        document["execution_config_bundle_sha256"]
                    ),
                    "next_stage": str(document["next_stage"]),
                    "params": params,
                    "plan_job_id": plan_job_id,
                    "snapshot_manifest": document["snapshot_manifest"],
                    "workflow_id": root.name,
                    **paths,
                }
                self._workflow_execution_snapshot(workflow)
                plan_job = self.jobs.get(plan_job_id)
                if plan_job is None or run_kind(plan_job.command, plan_job.argv) != (
                    "acquisition_plan"
                ):
                    continue
                self._model_acquisition_workflows[plan_job_id] = workflow
                if plan_job.state() == "orphaned":
                    try:
                        self._workflow_plan(workflow)
                    except (OSError, TypeError, ValueError):
                        pass
                    else:
                        plan_job.restored_state = "complete"
                        plan_job.restored_exit = 0
                        plan_job.ended_at = plan_job.ended_at or time.time()
                        self.db.upsert_job(plan_job, state="complete", exit_code=0)
                if acquisition_job_id:
                    acquisition_job = self.jobs.get(acquisition_job_id)
                    if acquisition_job is None or acquisition_job.command != "model_acquire":
                        continue
                    self._model_acquisition_workflows[acquisition_job_id] = workflow
                    token = self._read_workflow_activity_token(workflow)
                    if token is not None and acquisition_job.state() == "orphaned":
                        self._model_acquisition_activity[acquisition_job_id] = {
                            "path": Path(workflow["activity_event"]),
                            "sequence": 0,
                            "token": token,
                        }
                    self._reconcile_restored_model_acquisition(acquisition_job)
            except (OSError, TypeError, UnicodeError, ValueError):
                continue

    @staticmethod
    def _bounded_private_bytes(
        path: Path,
        *,
        max_bytes: int,
        label: str,
    ) -> bytes:
        """Read one private direct-child file without link/race traversal."""

        if not path.is_absolute() or max_bytes <= 0:
            raise ValueError(f"{label} path or byte bound is invalid")
        parent = path.parent
        descriptor: int | None = None
        try:
            parent_info = parent.lstat()
            if (
                parent.is_symlink()
                or parent.is_junction()
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent.resolve(strict=True) != parent
            ):
                raise ValueError(f"{label} parent must be a resolved non-link directory")
            info = path.lstat()
            if (
                path.is_symlink()
                or path.is_junction()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or not 0 < info.st_size <= max_bytes
            ):
                raise ValueError(f"{label} must be one bounded regular file")
            resolved = path.resolve(strict=True)
            if resolved != path or resolved.parent != parent:
                raise ValueError(f"{label} resolves outside its private directory")
            flags = (
                os.O_RDONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_size != info.st_size
                or (opened.st_dev, opened.st_ino, opened.st_mode)
                != (info.st_dev, info.st_ino, info.st_mode)
            ):
                raise ValueError(f"{label} changed while being opened")
            with os.fdopen(descriptor, "rb", closefd=True) as stream:
                descriptor = None
                raw = stream.read(max_bytes + 1)
                after = os.fstat(stream.fileno())
            if (
                len(raw) != info.st_size
                or (after.st_dev, after.st_ino, after.st_mode, after.st_size)
                != (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size)
            ):
                raise ValueError(f"{label} changed while being read")
            return raw
        except OSError as exc:
            raise ValueError(f"{label} cannot be read safely") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @classmethod
    def _bounded_private_document(cls, path: Path) -> tuple[bytes, str]:
        from ura.model_acquisition import MAX_DOCUMENT_BYTES  # noqa: PLC0415

        raw = cls._bounded_private_bytes(
            path,
            max_bytes=MAX_DOCUMENT_BYTES,
            label="private acquisition document",
        )
        return raw, hashlib.sha256(raw).hexdigest()

    def _workflow_plan(
        self,
        workflow: Mapping[str, Any],
    ) -> tuple[Path, str, dict[str, Any]]:
        from ura.model_acquisition import load_plan  # noqa: PLC0415

        plan_dir = Path(workflow["plan_dir"])
        candidates = sorted(plan_dir.glob("acquisition-plan-*.plan.json"))
        if len(candidates) != 1:
            raise ValueError("reviewed acquisition plan is missing or ambiguous")
        path = candidates[0]
        _raw, digest = self._bounded_private_document(path)
        plan = load_plan(path, expected_sha256=digest)
        return path, digest, plan

    def _workflow_receipt(
        self,
        workflow: Mapping[str, Any],
        *,
        plan: Mapping[str, Any],
    ) -> tuple[Path, str, dict[str, Any]]:
        from ura.model_acquisition import load_receipt  # noqa: PLC0415

        receipts_dir = Path(workflow["receipts_dir"])
        candidates = sorted(receipts_dir.glob("acquisition-receipt-*.receipt.json"))
        if len(candidates) != 1:
            raise ValueError("model acquisition receipt is missing or ambiguous")
        path = candidates[0]
        _raw, digest = self._bounded_private_document(path)
        receipt = load_receipt(path, expected_sha256=digest, plan=plan)
        return path, digest, receipt

    def _compose_model_acquisition_lane(
        self,
        workflow: Mapping[str, Any],
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        params = {str(key): str(value) for key, value in workflow["params"].items()}
        execution_snapshot = self._workflow_execution_snapshot(workflow)
        # The initial controller validates the complete raw form. A restored
        # workflow intentionally retains only typed digest locators, which must
        # not be resolved through mutable registries again; its exact snapshot
        # validation above is the continuity authority.
        if isinstance(workflow.get("execution_snapshot"), Mapping):
            errors = self._validate_builder(params)
            if errors:
                raise ValueError(
                    "reviewed Builder lane is no longer admissible: "
                    + "; ".join(
                        f"{key}: {value}" for key, value in sorted(errors.items())
                    )
                )
        command, values, rebound = self._compose_from_builder(
            params,
            execution_snapshot=execution_snapshot,
        )
        try:
            attacker_config = self._materialize_prepared_attacker_config(
                rebound,
                snapshot_payload=execution_snapshot.get("attacker_config"),
                artifact_snapshots=execution_snapshot,
            )
            if attacker_config is not None:
                values["--attacker-config"] = str(attacker_config)
                values["--attacker-config-sha256"] = hashlib.sha256(
                    attacker_config.read_bytes()
                ).hexdigest()
            if rebound.get("_execution_config_bundle_sha256") != workflow.get(
                "execution_config_bundle_sha256"
            ):
                raise ValueError(
                    "selected execution config changed after acquisition review"
                )
            return command, values, rebound
        except BaseException:
            self._discard_unlaunched_local_config(values)
            raise

    def _model_acquire_child_environment(self, *, activity_token: str) -> dict[str, str]:
        """Minimal controller environment: one optional HF token, no provider keys."""

        allowed = {
            "APPDATA",
            "COMSPEC",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOCALAPPDATA",
            "PATH",
            "PATHEXT",
            "PROGRAMDATA",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
            "VIRTUAL_ENV",
            "WINDIR",
        }
        by_upper = {name.upper(): value for name, value in os.environ.items()}
        child = {
            name: by_upper[name]
            for name in sorted(allowed)
            if name in by_upper
            and isinstance(by_upper[name], str)
            and "\0" not in by_upper[name]
            and len(by_upper[name]) <= 8192
        }
        token = os.environ.get("HF_TOKEN", "").strip()
        if token:
            child["HF_TOKEN"] = token
        child[_MODEL_ACQUISITION_ACTIVITY_TOKEN_ENV] = activity_token
        child["PYTHONUNBUFFERED"] = "1"
        return child

    @staticmethod
    def _unlink_private_activity_event(path_value: object) -> None:
        if not isinstance(path_value, Path):
            return
        try:
            path_value.unlink(missing_ok=True)
        except OSError:
            pass

    def _clear_model_acquisition_activity(self, job: Job) -> None:
        state = self._model_acquisition_activity.pop(job.job_id, None)
        if state is not None:
            self._unlink_private_activity_event(state.get("path"))
        self._unlink_workflow_activity_token(
            self._model_acquisition_workflows.get(job.job_id)
        )
        job.activity = None

    def _refresh_model_acquisition_activity(self, job: Job) -> None:
        state = self._model_acquisition_activity.get(job.job_id)
        if state is None:
            return
        path = state.get("path")
        if not isinstance(path, Path):
            return
        try:
            raw = self._bounded_private_bytes(
                path,
                max_bytes=16 * 1024,
                label="private acquisition activity event",
            )
            value = strict_json_loads(raw.decode("utf-8"))
            from experiments.model_acquire import (  # noqa: PLC0415
                validate_activity_event,
            )

            event = validate_activity_event(
                value,
                job_id=job.job_id,
                token=str(state["token"]),
                minimum_sequence=int(state.get("sequence", 0)),
            )
        except (OSError, TypeError, UnicodeError, ValueError):
            return
        state["sequence"] = int(event["sequence"])
        job.activity = (
            "model_download" if event["state"] == "start" else None
        )

    def _start_model_acquisition_plan(
        self,
        ticket_params: Mapping[str, str],
        *,
        execution_snapshot: Mapping[str, bytes] | None = None,
    ) -> Job:
        params = {str(key): str(value) for key, value in ticket_params.items()}
        next_stage = params.pop("_model_acquisition_next", "")
        if next_stage not in {"preflight", "run"}:
            raise ValueError("reviewed model-acquisition stage is invalid")
        errors = self._validate_builder(params)
        if errors:
            raise ValueError("reviewed Builder lane is no longer admissible")
        if execution_snapshot:
            snapshot = self._validate_execution_snapshot(params, execution_snapshot)
        else:
            params, snapshot, _snapshot_sha256 = (
                self._capture_execution_config_snapshot(params)
            )
        command, values, rebound = self._compose_from_builder(
            params,
            execution_snapshot=snapshot,
        )
        try:
            if next_stage == "run":
                _card, caps_ok = self._ceilings_card(rebound)
                if not caps_ok:
                    raise ValueError(
                        "the reviewed call ceilings no longer cover an exact "
                        "preflight"
                    )
            attacker_config = self._materialize_prepared_attacker_config(
                rebound,
                snapshot_payload=snapshot.get("attacker_config"),
                artifact_snapshots=snapshot,
            )
            if attacker_config is not None:
                values["--attacker-config"] = str(attacker_config)
                values["--attacker-config-sha256"] = hashlib.sha256(
                    attacker_config.read_bytes()
                ).hexdigest()
            if not self._builder_model_acquisition_required(rebound):
                raise ValueError("the reviewed lane does not require Hub acquisition")
            workflow_id = secrets.token_hex(16)
            paths = self._new_model_acquisition_workflow_paths(workflow_id)
            final_values = (
                self._builder_preflight_values(
                    values,
                    output=self._preflight_output_dir(rebound),
                )
                if next_stage == "preflight"
                else dict(values)
            )
            plan_values = dict(final_values)
            plan_values["--model-acquisition-plan-only"] = "on"
            plan_values["--model-acquisition-plan-dir"] = str(paths["plan_dir"])
            plan_values["--out"] = str(paths["plan_output"])
            plan_job_id = self._job_id_factory()
            workflow: dict[str, Any] = {
                "acquisition_job_id": "",
                "consumed": False,
                "execution_config_bundle_sha256": rebound[
                    "_execution_config_bundle_sha256"
                ],
                "next_stage": next_stage,
                "params": dict(rebound),
                "execution_snapshot": dict(snapshot),
                "plan_job_id": plan_job_id,
                "workflow_id": workflow_id,
                **paths,
            }
            # Persist the exact reviewed bytes and reserved job identity before
            # the child exists, closing the console-crash gap between Popen and
            # workflow registration.
            self._persist_model_acquisition_workflow(workflow)
            job = self.start_job(
                command,
                plan_values,
                builder_params=rebound,
                reserved_job_id=plan_job_id,
                execution_snapshot=snapshot,
            )
        except BaseException:
            self._discard_unlaunched_local_config(values)
            raise
        if job.job_id != workflow["plan_job_id"]:
            workflow["plan_job_id"] = job.job_id
            self._persist_model_acquisition_workflow(workflow)
        self._model_acquisition_workflows[job.job_id] = workflow
        return job

    def _start_model_acquisition_download(self, plan_job_id: str) -> Job:
        workflow = self._model_acquisition_workflows.get(plan_job_id)
        plan_job = self.jobs.get(plan_job_id)
        if (
            workflow is None
            or plan_job is None
            or plan_job.command != "run_matrix"
            or run_kind(plan_job.command, plan_job.argv) != "acquisition_plan"
            or plan_job.state() != "complete"
        ):
            raise ValueError("reviewed acquisition plan job is unavailable")
        prior_acquisition_id = str(workflow.get("acquisition_job_id", ""))
        if prior_acquisition_id:
            prior = self.jobs.get(prior_acquisition_id)
            if prior is None or prior.state() != "failed":
                raise ValueError("this reviewed acquisition plan was already launched")
        _command, values, _rebound = self._compose_model_acquisition_lane(workflow)
        self._discard_unlaunched_local_config(values)
        plan_path, plan_sha256, _plan = self._workflow_plan(workflow)
        activity_event = Path(workflow["activity_event"])
        self._unlink_private_activity_event(activity_event)
        job_id = self._job_id_factory()
        activity_token = secrets.token_hex(32)
        acquire_values = {
            "--plan": str(plan_path),
            "--plan-sha256": plan_sha256,
            "--store": str(workflow["store"]),
            "--receipts-dir": str(workflow["receipts_dir"]),
            "--transport-cache": str(workflow["transport_cache"]),
            "--max-download-bytes": str(_MODEL_ACQUISITION_MAX_DOWNLOAD_BYTES),
            "--min-free-bytes": str(_MODEL_ACQUISITION_MIN_FREE_BYTES),
            "--deadline-seconds": str(_MODEL_ACQUISITION_DEADLINE_SECONDS),
            "--activity-event": str(activity_event),
            "--activity-job-id": job_id,
        }
        if _rebound.get("verify_model_sha256") == "on":
            acquire_values["--verify-model-sha256"] = "on"
        workflow["acquisition_job_id"] = job_id
        self._persist_model_acquisition_workflow(workflow)
        self._write_workflow_activity_token(workflow, activity_token)
        try:
            job = self.start_job(
                "model_acquire",
                acquire_values,
                builder_params=workflow["params"],
                execution_snapshot=self._workflow_execution_snapshot(workflow),
                reserved_job_id=job_id,
                model_acquisition_activity_token=activity_token,
            )
        except BaseException:
            workflow["acquisition_job_id"] = prior_acquisition_id
            self._persist_model_acquisition_workflow(workflow)
            self._unlink_workflow_activity_token(workflow)
            raise
        self._model_acquisition_workflows[job.job_id] = workflow
        return job

    def _start_model_acquisition_run(self, acquisition_job_id: str) -> Job:
        workflow = self._model_acquisition_workflows.get(acquisition_job_id)
        acquisition_job = self.jobs.get(acquisition_job_id)
        if (
            workflow is None
            or acquisition_job is None
            or acquisition_job.command != "model_acquire"
            or acquisition_job.state() != "complete"
            or workflow.get("consumed") is True
        ):
            raise ValueError("completed model acquisition is unavailable")
        plan_path, plan_sha256, plan = self._workflow_plan(workflow)
        receipt_path, receipt_sha256, _receipt = self._workflow_receipt(
            workflow,
            plan=plan,
        )
        command, values, rebound = self._compose_model_acquisition_lane(workflow)
        if workflow["next_stage"] == "preflight":
            values = self._builder_preflight_values(
                values,
                output=self._preflight_output_dir(rebound),
            )
        elif workflow["next_stage"] == "run":
            _card, caps_ok = self._ceilings_card(rebound)
            if not caps_ok:
                self._discard_unlaunched_local_config(values)
                raise ValueError(
                    "the reviewed call ceilings no longer cover an exact preflight"
                )
        else:  # pragma: no cover - created only by the exact controller above
            self._discard_unlaunched_local_config(values)
            raise ValueError("model acquisition has an invalid terminal stage")
        values.update({
            "--model-acquisition-plan": str(plan_path),
            "--model-acquisition-plan-sha256": plan_sha256,
            "--model-acquisition-receipt": str(receipt_path),
            "--model-acquisition-receipt-sha256": receipt_sha256,
            "--model-acquisition-store": str(workflow["store"]),
        })
        workflow["consumed"] = True
        self._persist_model_acquisition_workflow(workflow)
        try:
            job = self.start_job(
                command,
                values,
                builder_params=rebound,
                execution_snapshot=self._workflow_execution_snapshot(workflow),
            )
        except BaseException:
            workflow["consumed"] = False
            self._persist_model_acquisition_workflow(workflow)
            raise
        return job

    def _model_acquisition_job_actions(self, job: Job) -> str:
        """Render only public stage facts plus a fresh opaque one-shot action."""

        workflow = self._model_acquisition_workflows.get(job.job_id)
        if workflow is None:
            return ""
        state = job.state()
        if (
            run_kind(job.command, job.argv) == "acquisition_plan"
            and state == "complete"
            and not workflow.get("acquisition_job_id")
        ):
            try:
                _path, _digest, plan = self._workflow_plan(workflow)
            except (OSError, TypeError, ValueError):
                return (
                    "<div class='notice red'><strong>The private acquisition plan "
                    "is missing or invalid.</strong> Review the lane again.</div>"
                )
            resources = "".join(
                "<li><code>"
                + html.escape(str(resource["repo_id"]))
                + "@"
                + html.escape(str(resource["revision"]))
                + "</code> - "
                + html.escape(", ".join(str(role) for role in resource["roles"]))
                + "</li>"
                for resource in plan["resources"]
            )
            ticket = self._new_launch_ticket(
                {"plan_job_id": job.job_id},
                purpose="acquisition_download",
            )
            return (
                "<div class='card'><h2>Reviewed sealed acquisition plan</h2>"
                "<p class='note'>Public repository identities and immutable commits "
                "are shown below. The dedicated controller verifies cache bytes and "
                "downloads only confirmed missing files.</p><ul>"
                + resources
                + "</ul><form method='post' "
                "action='/build/model-acquisition/acquire'>"
                "<input type='hidden' name='launch_ticket' value='"
                + html.escape(ticket)
                + "'><button type='submit'>Acquire sealed models</button></form></div>"
            )
        if job.command == "model_acquire" and state == "complete":
            try:
                _plan_path, _plan_sha, plan = self._workflow_plan(workflow)
                self._workflow_receipt(workflow, plan=plan)
            except (OSError, TypeError, ValueError):
                return (
                    "<div class='notice red'><strong>The acquisition receipt is "
                    "missing or invalid.</strong> Review the lane again.</div>"
                )
            if workflow.get("consumed") is True:
                return (
                    "<div class='notice green'><strong>The sealed acquisition was "
                    "consumed by its reviewed run.</strong></div>"
                )
            ticket = self._new_launch_ticket(
                {"acquisition_job_id": job.job_id},
                purpose="acquisition_run",
            )
            label = (
                "Start no-call preflight"
                if workflow["next_stage"] == "preflight"
                else "Start reviewed measured job"
            )
            return (
                "<div class='card'><h2>Verified model acquisition receipt</h2>"
                "<p class='note'>The next process receives the exact plan, receipt, "
                "and managed-store locator in memory and runs with Hugging Face "
                "offline/local-only policy. No Hub token is forwarded.</p>"
                "<form method='post' action='/build/model-acquisition/run'>"
                "<input type='hidden' name='launch_ticket' value='"
                + html.escape(ticket)
                + "'><button type='submit'>"
                + html.escape(label)
                + "</button></form></div>"
            )
        if job.command == "model_acquire" and state == "failed":
            ticket = self._new_launch_ticket(
                {"plan_job_id": str(workflow["plan_job_id"])},
                purpose="acquisition_download",
            )
            return (
                "<div class='card'><h2>Acquisition failed</h2>"
                "<p class='note'>After correcting credentials, storage, or network "
                "access, retry the same immutable reviewed plan.</p>"
                "<form method='post' action='/build/model-acquisition/acquire'>"
                "<input type='hidden' name='launch_ticket' value='"
                + html.escape(ticket)
                + "'><button type='submit'>Retry acquisition</button></form></div>"
            )
        return ""

    def _coreutils_timeout_executable(self) -> str | None:
        """Return the detached POSIX wall-time controller available to this host."""

        if os.name == "nt":
            return None
        return shutil.which("timeout")

    def _wrap_local_measured_wall_time(
        self,
        command: str,
        values: Mapping[str, str],
        builder_params: Mapping[str, str] | None,
        launch_argv: list[str],
    ) -> tuple[list[str], int | None]:
        """Wrap only a final measured all-local Runner process.

        Runner's deadline is deliberately a call-start admission gate. The
        Builder's optional whole-hour ceiling instead belongs to a detached
        process supervisor, so it remains effective if the console restarts and
        can terminate an already admitted model call.
        """

        if command != "run_matrix" or builder_params is None:
            return launch_argv, None
        raw_hours = str(builder_params.get("local_budget_hours", "")).strip()
        if not raw_hours:
            return launch_argv, None
        if any(
            str(values.get(flag, "")) == "on"
            for flag in (
                "--dry-run",
                "--preflight-only",
                "--model-acquisition-plan-only",
            )
        ):
            return launch_argv, None
        if re.fullmatch(r"[1-9][0-9]*", raw_hours) is None:
            raise ValueError("local process wall-time hours must be a positive integer")
        mode = str(builder_params.get("mode", "measured")).strip() or "measured"
        local = self._split_list(str(builder_params.get("local", "")))
        api = self._split_list(str(builder_params.get("api", "")))
        judges = self._split_list(str(builder_params.get("judges", "")))
        judge_model = str(builder_params.get("judge_model", "")).strip()
        hosted_judge = (
            "llm" in judges
            and judge_model not in {"", "mock"}
            and not judge_model.startswith(("vllm:", "ollama:"))
        )
        if mode != "measured" or not local or api or hosted_judge:
            raise ValueError(
                "local process wall-time cap requires a final measured all-local lane"
            )
        timeout_executable = self._coreutils_timeout_executable()
        if not timeout_executable:
            raise ValueError(
                "local process wall-time cap requires GNU coreutils timeout on this host"
            )
        seconds = int(raw_hours) * 3600
        return [
            timeout_executable,
            "--verbose",
            "--signal=TERM",
            "--kill-after=10s",
            f"{seconds}s",
            *launch_argv,
        ], seconds

    def start_job(
        self,
        command: str,
        values: Mapping[str, str],
        *,
        builder_params: Mapping[str, str] | None = None,
        scrub_receipt_env: bool = False,
        activity: str | None = None,
        reserved_job_id: str | None = None,
        model_acquisition_activity_token: str | None = None,
        execution_snapshot: Mapping[str, bytes] | None = None,
        campaign_id: str = "",
    ) -> Job:
        bound_campaign = str((builder_params or {}).get("campaign_id", ""))
        if campaign_id and bound_campaign and campaign_id != bound_campaign:
            raise ValueError("Campaign differs from the reviewed Build launch")
        campaign_id = campaign_id or bound_campaign
        if campaign_id:
            self.db.require_workspace(campaign_id)
        if activity not in {None, "model_download"}:
            raise ValueError("unsupported job activity")
        if activity == "model_download" and command != "ollama_pull":
            raise ValueError("model_download activity is reserved for ollama_pull jobs")
        if command == "model_acquire":
            if (
                not isinstance(model_acquisition_activity_token, str)
                or re.fullmatch(r"[0-9a-f]{64}", model_acquisition_activity_token)
                is None
                or reserved_job_id is None
            ):
                raise ValueError(
                    "model_acquire requires a reserved job id and private activity token"
                )
            acquisition_event_path = Path(str(values.get("--activity-event", "")))
            if not acquisition_event_path.is_absolute():
                raise ValueError("model acquisition activity event must be absolute")
        elif reserved_job_id is not None:
            if (
                model_acquisition_activity_token is not None
                or command != "run_matrix"
                or str(values.get("--model-acquisition-plan-only", "")) != "on"
            ):
                raise ValueError(
                    "reserved job ids are limited to private acquisition stages"
                )
            acquisition_event_path = None
        elif model_acquisition_activity_token is not None:
            raise ValueError("reserved acquisition launch inputs are command-specific")
        else:
            acquisition_event_path = None
        # Re-read and re-normalize the exact selected hosted registry before a
        # job id, directory, retained Job, or child can exist.  This is a final
        # defense against edits after preview/ticket consumption; the bound
        # digest makes any drift fail closed and require a new review.
        if builder_params is not None:
            try:
                if execution_snapshot:
                    self._validate_execution_snapshot(
                        builder_params,
                        execution_snapshot,
                    )
                    builder_params = self._bind_execution_config_bundle_identity(
                        builder_params
                    )
                else:
                    builder_params = self._bind_execution_config_bundle_identity(
                        self._bind_selected_execution_config_identity(builder_params)
                    )
            except (KeyError, OSError, TypeError, ValueError):
                self._discard_unlaunched_local_config(values)
                raise
        # Keep execution and retention deliberately separate: the raw argv is
        # needed by vLLM to open an explicit checkpoint, but it must never
        # become durable console state. Both vectors pass the same typed
        # allowlist and differ only in content-identity projection.
        try:
            launch_argv = build_argv(command, values, commands=self.commands)
            (
                argv,
                retained_params,
                transient_config,
                transient_api_config,
                transient_source_config,
                transient_attacker_config,
                transient_source_conformance,
                transient_evidence_files,
            ) = self._durable_launch_state(
                command, values, builder_params
            )
            launch_argv, controller_wall_time_seconds = (
                self._wrap_local_measured_wall_time(
                    command,
                    values,
                    builder_params,
                    launch_argv,
                )
            )
            # This is the exact SQLite path-privacy boundary and must run before
            # a subprocess, job directory, or in-memory Job can exist.
            assert_durable_job_state_path_free(argv, retained_params)
        except (OSError, TypeError, ValueError):
            self._discard_unlaunched_local_config(values)
            raise
        explicit_matrix_env = command in {"run_matrix", "rig_check"}
        explicit_acquisition_env = command == "model_acquire"
        try:
            child_env = (
                self._run_matrix_child_environment(
                    values,
                    scrub_receipt_env=scrub_receipt_env,
                )
                if explicit_matrix_env
                else self._model_acquire_child_environment(
                    activity_token=str(model_acquisition_activity_token)
                )
                if explicit_acquisition_env
                else self._generic_child_environment(command, values)
            )
            # Never inherit another launch's one-shot deletion marker.
            child_env.pop(_PRIVATE_LOCAL_CONFIG_ENV, None)
            child_env.pop(_PRIVATE_API_CONFIG_ENV, None)
            child_env.pop(_PRIVATE_SOURCE_CONFIG_ENV, None)
            child_env.pop(_PRIVATE_ATTACKER_CONFIG_ENV, None)
            child_env.pop(_PRIVATE_ENGINE_RUNTIME_CONFIG_ENV, None)
            child_env.pop(_PRIVATE_PROJECT_REVISION_ENV, None)
            child_env.pop(_PRIVATE_SOURCE_CONFORMANCE_ENV, None)
            for index in range(1, 13):
                child_env.pop(
                    f"{_PRIVATE_LIVE_ATTESTATION_ENV_PREFIX}{index:02d}",
                    None,
                )
            if scrub_receipt_env:
                for name in self._DRY_SCRUB_ENV:
                    child_env.pop(name, None)
            # The selected campaign owner binds this child's derived index.
            # Standalone launches must not inherit another campaign's binding.
            child_env.pop("URA_CAMPAIGN_WORKSPACE_ID", None)
            child_env.pop("URA_CAMPAIGN_CONSOLE_DB", None)
            if command in {"hosted_campaign_execute", "run_matrix", "retained_response_judge_pair_execute",
                           "retained_native_judge_execute", "retained_inventory_judging"} and campaign_id:
                child_env["URA_CAMPAIGN_WORKSPACE_ID"] = campaign_id
                child_env["URA_CAMPAIGN_CONSOLE_DB"] = str(self.db.path.resolve())
            if transient_config is not None:
                child_env[_PRIVATE_LOCAL_CONFIG_ENV] = str(transient_config)
            if transient_api_config is not None:
                child_env[_PRIVATE_API_CONFIG_ENV] = str(transient_api_config)
            if transient_source_config is not None:
                child_env[_PRIVATE_SOURCE_CONFIG_ENV] = str(transient_source_config)
            if transient_attacker_config is not None:
                child_env[_PRIVATE_ATTACKER_CONFIG_ENV] = str(transient_attacker_config)
            private_engine_runtime_config = (
                self._private_engine_runtime_config_path(values)
            )
            if private_engine_runtime_config is not None:
                child_env[_PRIVATE_ENGINE_RUNTIME_CONFIG_ENV] = str(
                    private_engine_runtime_config
                )
            if transient_source_conformance is not None:
                child_env[_PRIVATE_SOURCE_CONFORMANCE_ENV] = str(
                    transient_source_conformance
                )
            private_project_revision = self._private_project_revision_path(values)
            if private_project_revision is not None:
                child_env[_PRIVATE_PROJECT_REVISION_ENV] = str(
                    private_project_revision
                )
            for path_flag, _digest_flag, path in self._private_live_attestation_paths(
                values
            ):
                index = int(path_flag.rsplit("#", 1)[1])
                child_env[
                    f"{_PRIVATE_LIVE_ATTESTATION_ENV_PREFIX}{index:02d}"
                ] = str(path)
        except (OSError, TypeError, ValueError):
            self._discard_unlaunched_local_config(values)
            raise
        capture_logs = True
        try:
            redactions = (
                self._durable_log_redactions(command, values, child_env)
                if capture_logs
                else ()
            )
        except (OSError, TypeError, ValueError):
            self._discard_unlaunched_local_config(values)
            raise
        with self._app_lock:
            job_id = reserved_job_id or self._job_id_factory()
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_id)
                is None
                or job_id in self.jobs
            ):
                raise ValueError("generated job id is invalid or already in use")
            directory = self.state_dir / job_id
            directory.mkdir(parents=True, exist_ok=False)
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass
            command_document: dict[str, object] = {
                "job_id": job_id,
                "command": command,
                "argv": argv,
                "supervised": os.name == "posix",
            }
            if campaign_id:
                from .workspace_store import activity_role  # noqa: PLC0415

                # Commit ownership before a process can make a call. A failed
                # launch leaves an honest unresolved activity, never an
                # unowned paid worker or a fabricated successful job.
                self.db.attach_workspace_member(
                    campaign_id, "job", job_id, activity_role(command)
                )
                command_document["campaign_id"] = campaign_id
            if controller_wall_time_seconds is not None:
                command_document["controller_wall_time_seconds"] = (
                    controller_wall_time_seconds
                )
            (directory / "command.json").write_text(
                json.dumps(command_document, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            stdout_handle = (directory / "stdout.log").open("wb")
            stderr_handle = (directory / "stderr.log").open("wb")
            for log_path in (directory / "stdout.log", directory / "stderr.log"):
                try:
                    os.chmod(log_path, 0o600)
                except OSError:
                    pass
            # Each job gets its own process group/session so a stop can
            # terminate the complete child tree, not just the Python driver.
            popen_kwargs: dict[str, Any] = {}
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                popen_kwargs["start_new_session"] = True
            popen_kwargs["env"] = child_env
            log_writers: tuple[Any, Any] | None = None
            lease = None
            job = None
            try:
                from .job_runtime import repository_lease, supervisor_argv, process_identity, write_state
                lease = repository_lease(self.repo_root)
                if os.name == "posix":
                    launch_argv = supervisor_argv(directory, launch_argv, lease.fileno() if lease else None)
                    if lease:
                        popen_kwargs["pass_fds"] = (lease.fileno(),)
                job = Job(job_id=job_id, command=command, argv=argv, directory=directory,
                    stdout_handle=stdout_handle, stderr_handle=stderr_handle,
                    builder_params=retained_params, pin=os.environ.get("REF_URA", ""),
                    activity=activity, restored_state="running")
                self.jobs[job_id] = job
                if not self.db.upsert_job(job):
                    raise OSError("Could not retain job identity before process launch")
                if capture_logs:
                    log_writers = self._start_log_capture(
                        job_id,
                        directory / "stdout.log",
                        directory / "stderr.log",
                        redactions,
                        child_env,
                    )
                process = subprocess.Popen(  # noqa: S603 - allowlisted argv, shell=False
                    launch_argv,
                    cwd=self.repo_root,
                    stdin=subprocess.DEVNULL,
                    stdout=(log_writers[0] if log_writers else stdout_handle),
                    stderr=(log_writers[1] if log_writers else stderr_handle),
                    shell=False,
                    **popen_kwargs,
                )
                job.process = process
                identity = process_identity(process.pid) if os.name == "posix" else None
                if identity:
                    write_state(directory, dict(job_id=job_id, state="running", supervisor=identity,
                        started_at=job.started_at, exit_code=None), "execution-start.json")
            except (OSError, ValueError):
                if job is not None and job.process is None:
                    job.restored_state = "failed"
                    job.failure = "Job launch did not complete; inspect retained logs before retrying."
                    job.ended_at = time.time()
                    self.db.upsert_job(job)
                if log_writers is not None:
                    for writer in log_writers:
                        try:
                            writer.close()
                        except (AttributeError, OSError, ValueError):
                            pass
                self._finish_log_capture(job_id)
                stdout_handle.close()
                stderr_handle.close()
                self._unlink_transient_local_config(transient_config)
                self._unlink_transient_local_config(transient_api_config)
                self._unlink_transient_local_config(transient_source_config)
                self._unlink_transient_local_config(transient_attacker_config)
                self._unlink_transient_local_config(transient_source_conformance)
                for path in transient_evidence_files:
                    self._unlink_transient_local_config(path)
                raise
            finally:
                if lease is not None:
                    lease.close()
                # The child now owns duplicate write handles.  Closing the
                # controller copies lets the detached redactors observe EOF
                # when that child exits, even after this console has closed.
                if log_writers is not None:
                    for writer in log_writers:
                        try:
                            writer.close()
                        except (AttributeError, OSError, ValueError):
                            pass
            # Windows: assign the driver to a managed job so explicit Stop can
            # reliably take the whole tree even if taskkill later fails.
            job_handle = _win_managed_job()
            if job_handle is not None and not _win_assign_job(job_handle, process):
                _win_close_handle(job_handle)
                job_handle = None
            assert job is not None
            job.process = process
            job.restored_state = None
            job.job_handle = job_handle
            if transient_config is not None:
                self._transient_local_configs[job_id] = transient_config
            if transient_api_config is not None:
                self._transient_api_configs[job_id] = transient_api_config
            if transient_source_config is not None:
                self._transient_source_configs[job_id] = transient_source_config
            if transient_attacker_config is not None:
                self._transient_attacker_configs[job_id] = transient_attacker_config
            if transient_evidence_files:
                self._transient_evidence_files[job_id] = transient_evidence_files
            if command == "model_acquire":
                self._model_acquisition_activity[job_id] = {
                    "path": acquisition_event_path,
                    "sequence": 0,
                    "token": str(model_acquisition_activity_token),
                }
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
        from .job_runtime import write_state
        write_state(job.directory, dict(job_id=job.job_id, requested_at=time.time()), "stop-request.json")
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
            pgid: int | None = process.process_group() if hasattr(process, "process_group") else os.getpgid(process.pid)
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
            if hasattr(process, "process_group") and pgid is None:
                process.send_signal(sig)
                return
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
            acquisition_event = None
            if job.command == "model_acquire":
                acquisition_state = self._model_acquisition_activity.get(job.job_id)
                acquisition_event = (
                    acquisition_state.get("path")
                    if acquisition_state is not None
                    else None
                )
                self._clear_model_acquisition_activity(job)
            self._terminate_tree(job)
            self._unlink_private_activity_event(acquisition_event)
            # Reconcile the terminal state now: close the log handles and
            # commit job + run + usage in one transaction.
            self._reconcile_locked()
            return job

    def reindex_all(self, *, verify_sha: bool = False) -> dict[str, Any]:
        """Rebuild the derived usage and report indexes from retained artifacts.

        Serialized with reconcile/start/stop under the application lock so it
        cannot delete a usage row another thread is committing.  It scans only
        exact output directories owned by retained run records (a lane's
        ``--out`` may legitimately point outside the results root) and indexes
        only exact ``--out-json`` files owned by retained analysis Jobs.  A
        recursive results-root scan would import copied pytest/engineering
        fixtures that merely resemble campaign evidence.
        """

        from ura.artifact_checks import artifact_verification

        with self._app_lock, artifact_verification(verify_sha256=verify_sha):
            roots: dict[str, Path] = {}
            runs = self.db.list_run_owners(limit=10_001)
            report_jobs = self.db.load_report_jobs(limit=10_001)
            if (
                runs is None
                or report_jobs is None
                or len(runs) > 10_000
                or len(report_jobs) > 10_000
            ):
                return {
                    "ok": False,
                    "roots": 0,
                    "usage_rows": 0,
                    "reports": 0,
                    "markers": 0,
                    "skipped_error": 0,
                    "skipped_invalid": 0,
                    "orphan_responses": 0,
                    "truncated": 1,
                    "unreadable_artifacts": 0,
                    "error": "retained ownership registry unavailable or over limit",
                }
            for row in runs:
                out = str(row["out_dir"] or "").strip()
                if not out:
                    continue
                candidate = self.repo_root / out
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    continue
                if resolved.is_dir() and not derived_path_quarantined(
                    resolved,
                    self.results_root,
                ):
                    roots.setdefault(str(resolved), resolved)
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
            owned_roots = tuple(roots.values())
            for root in owned_roots:
                if not root.exists():
                    continue
                excluded_roots = []
                for candidate in owned_roots:
                    if candidate == root:
                        continue
                    try:
                        candidate.relative_to(root)
                    except ValueError:
                        continue
                    excluded_roots.append(candidate)
                rows, stats = collect_usage(
                    root,
                    verify_sha=verify_sha,
                    excluded_roots=tuple(excluded_roots),
                )
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
            report_rows: list[dict[str, Any]] = []
            seen_report_paths: set[str] = set()
            # DashboardMixin resolves live + DB-only producers against the
            # complete bounded run registry and selects one unique deepest
            # owner.  Reindex consumes that same ownership decision so restart
            # cannot widen discovery or resurrect stale recursive fixtures.
            for binding in self._stats_report_bindings():
                relative = str(binding["path"])
                if relative in seen_report_paths:
                    continue
                report = collect_report_file(
                    self.results_root,
                    self.results_root / relative,
                )
                if report is not None:
                    report_rows.append(report)
                    seen_report_paths.add(relative)
            ok = self.db.reindex(usage_rows, report_rows)
            return {
                "ok": ok,
                "roots": len(roots),
                "usage_rows": len(usage_rows),
                "reports": len(report_rows),
                "artifact_verification": "sha256" if verify_sha else "metadata_and_records",
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

    def _engineering_campaign_scan(
        self,
        *,
        started_from: float | None = None,
        started_to: float | None = None,
    ) -> tuple[list[EngineeringCampaign], str]:
        return scan_engineering_campaigns(
            self.results_root,
            started_from=started_from,
            started_to=started_to,
        )

    def _engineering_campaign(self, route_id: str) -> EngineeringCampaign | None:
        return load_engineering_campaign(self.results_root, route_id)

    def _external_measured_job_scan(
        self,
        *,
        started_from: float | None = None,
        started_to: float | None = None,
    ) -> tuple[list[ExternalMeasuredJob], str]:
        return scan_external_measured_jobs(
            self.results_root,
            started_from=started_from,
            started_to=started_to,
        )

    def _external_measured_job(self, job_id: str) -> ExternalMeasuredJob | None:
        return load_external_measured_job(self.results_root, job_id)

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
            if path == '/human-evaluation' or path.startswith(('/human-evaluation/', '/review/')):
                return self._human_route(method, path, query, dict(form or {}))
            if method == "GET" and path == "/campaigns":
                return 200, "text/html; charset=utf-8", self._workspaces_page()
            if method == "GET" and path == "/campaigns/new":
                return 303, "/build?work_kind=campaign#build-general", b""
            if method == "POST" and path == "/campaigns":
                data = dict(form or {})
                campaign_id = self.db.create_workspace(data.get("name", ""), data.get("kind", "mixed"))
                section = "#build-general" if data.get("creation_flow") == "name_then_build" else ""
                return 303, f"/build?campaign_id={campaign_id}{section}", b""
            if method == "GET" and path.startswith("/campaigns/"):
                parts = path.removeprefix("/campaigns/").split("/")
                if len(parts) == 3 and parts[1] == "figures":
                    return self._workspace_export(parts[0], parts[2], query)
                return 200, "text/html; charset=utf-8", self._workspace_page(
                    path.removeprefix("/campaigns/"), query
                )
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
                return 200, "text/html; charset=utf-8", self._commands_page(query.get("campaign_id", ""))
            if method == "GET" and path == "/ollama/status":
                return (
                    200,
                    "application/json; charset=utf-8",
                    (
                        json.dumps(self.ollama.status(), sort_keys=True, separators=(",", ":"))
                        + "\n"
                    ).encode("utf-8"),
                )
            if method == "POST" and path in {"/ollama/start", "/ollama/stop"}:
                try:
                    status = (
                        self.ollama.start()
                        if path.endswith("/start")
                        else self.ollama.stop()
                    )
                except (OllamaError, OSError, ValueError) as exc:
                    return 303, f"/build?ollama_error={quote(str(exc))}", b""
                return 303, f"/build?ollama_state={quote(str(status['state']))}", b""
            if method == "POST" and path == "/ollama/pull":
                data = dict(form or {})
                try:
                    model = validate_ollama_tag(data.get("model", ""))
                    if self.ollama.status().get("api_reachable") is not True:
                        raise ValueError("Ollama loopback daemon is not running")
                    storage = self.ollama.validate_pull_storage()
                    models_path = storage.get("models_path")
                    base_url = storage.get("base_url")
                    owned_pid = storage.get("owned_pid")
                    owned_process_identity = storage.get("owned_process_identity")
                    if (
                        not isinstance(models_path, str)
                        or not models_path
                        or not isinstance(base_url, str)
                        or not base_url
                    ):
                        raise ValueError("owned Ollama storage contract is incomplete")
                    if (
                        isinstance(owned_pid, bool)
                        or not isinstance(owned_pid, int)
                        or owned_pid <= 0
                        or not isinstance(owned_process_identity, str)
                        or not owned_process_identity
                    ):
                        raise ValueError("owned Ollama process contract is incomplete")
                    self.ollama.invalidate_roster()
                    job = self.start_job(
                        "ollama_pull",
                        {
                            "--model": model,
                            "--base-url": base_url,
                            "--models-path": models_path,
                            "--owned-pid": str(owned_pid),
                            "--owned-process-identity": owned_process_identity,
                            "--timeout-seconds": "120",
                        },
                        builder_params={"ollama_model": model},
                        campaign_id=data.get("campaign_id", ""),
                        activity="model_download",
                    )
                except (OllamaError, OSError, ValueError) as exc:
                    return 303, f"/build?ollama_error={quote(str(exc))}", b""
                return 303, f"/jobs/{job.job_id}", b""
            if method == "POST" and path == "/jobs":
                data = dict(form or {})
                command = data.pop("command", "")
                campaign_id = data.pop("campaign_id", "")
                if command in {
                    "run_matrix",
                    "model_acquire",
                    "capture_t3mp3st",
                    "harmbench_capture",
                    "ollama_pull",
                }:
                    return (
                        400,
                        "text/plain; charset=utf-8",
                        b"use the validated Build workflow for this command",
                    )
                # A dry preflight from the generic Run form launches with the
                # campaign receipt env scrubbed exactly like a Build dry lane
                # (an offline lane is never admitted or failed by an inherited
                # receipt); a non-dry rig_check inherits the exported receipt
                # locators the CLI reads as its argparse defaults.
                job = self.start_job(
                    command,
                    data,
                    scrub_receipt_env=(command == "rig_check" and "--dry-run" in data),
                    campaign_id=campaign_id,
                )
                return 303, f"/jobs/{job.job_id}", b""
            if method == "GET" and path == "/jobs":
                return 200, "text/html; charset=utf-8", self._jobs_page(query)
            if method == "POST" and path.startswith("/jobs/external/") and path.endswith(
                "/stop"
            ):
                return (
                    405,
                    "text/plain; charset=utf-8",
                    b"external measured jobs are read-only and are not owned by this console",
                )
            if method == "GET" and path.startswith("/jobs/external/"):
                job_id = path.removeprefix("/jobs/external/")
                if not job_id or "/" in job_id:
                    return 404, "text/plain; charset=utf-8", b"unknown external job"
                external_job = self._external_measured_job(job_id)
                if external_job is None:
                    return 404, "text/plain; charset=utf-8", b"unknown external job"
                return (
                    200,
                    "text/html; charset=utf-8",
                    self._external_measured_job_page(external_job),
                )
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
                job = self._job_for_id(job_id)
                if job is None:
                    return 404, "text/plain; charset=utf-8", b"unknown job"
                stream = query.get("stream", "stdout")
                if stream not in {"stdout", "stderr"}:
                    return 400, "text/plain; charset=utf-8", b"unknown stream"
                text = self._log_tail(job, stream)
                return 200, "text/plain; charset=utf-8", text.encode("utf-8")
            if method == "GET" and path.startswith("/jobs/"):
                job_id = path.split("/")[2]
                job = self._job_for_id(job_id)
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
            if method == "GET" and path.startswith("/stats/job/"):
                job_id = path.removeprefix("/stats/job/")
                if not job_id or "/" in job_id:
                    return 404, "text/plain; charset=utf-8", b"unknown campaign job"
                detail = self._stats_job_detail_page(
                    job_id,
                    fragment=query.get("fragment") == "1",
                    report=query.get("report"),
                    detail_section=query.get("detail_section", "overview"),
                    detail_page=query.get("detail_page", "0"),
                )
                if detail is None:
                    return 404, "text/plain; charset=utf-8", b"unknown campaign job"
                return 200, "text/html; charset=utf-8", detail
            if method == "GET" and path == "/stats":
                if query.get("view") == "standalone":
                    return 200, "text/html; charset=utf-8", self._standalone_results_page(query)
                if query.get("view") != "legacy":
                    return 200, "text/html; charset=utf-8", self._workspaces_page(context="stats")
                return 200, "text/html; charset=utf-8", self._stats_page(query)
            if method == "GET" and path == "/build":
                campaign_id = query.get("campaign_id", "")
                prefill = self.db.workspace_definition(campaign_id) if campaign_id else {}
                prefill.update(campaign_id=campaign_id,
                    work_kind=query.get("work_kind", "campaign" if campaign_id else "run"))
                return (
                    200,
                    "text/html; charset=utf-8",
                    self._build_page(
                        prefill=prefill,
                        ollama_state=query.get("ollama_state", ""),
                        ollama_error=query.get("ollama_error", ""),
                        framework_runtime_state=query.get(
                            "framework_runtime_state", ""
                        ),
                    ),
                )
            if method == "POST" and path == "/build/save":
                params = self._builder_params(form or {})
                if params.get("work_kind") != "campaign" and not params.get("campaign_id"):
                    raise ValueError("Select Campaign to save a campaign definition")
                params = self._save_build_campaign(params)
                return 303, "/campaigns/" + params["campaign_id"] + "?section=definition", b""
            if method == "POST" and path in {"/build/source-runs", "/build/prepare-inputs"}:
                from .builder_sources import prepare_selected_inputs
                params = self._builder_params(form or {})
                if path == "/build/source-runs":
                    return 200, "text/html; charset=utf-8", self._build_page(prefill=params)
                job = prepare_selected_inputs(self, params)
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/forecast-matched":
                from .builder_budget import prepare_budget
                job = prepare_budget(self, self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/prepare-replays":
                from .builder_replays import prepare_replays
                job = prepare_replays(self, self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/prepare-programs":
                from .builder_programs import prepare_programs
                from ura.guardrail_setup import GuardrailSetupError
                params = self._builder_params(form or {})
                try:
                    job = prepare_programs(self, params)
                except GuardrailSetupError as exc:
                    return 400, "text/html; charset=utf-8", self._build_page(
                        prefill=params,errors={'guardrail_model':str(exc)})
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/review-collection":
                from .builder_collection import collection_review
                return 200, "text/html; charset=utf-8", collection_review(self,self._builder_params(form or {}))
            if method == "POST" and path == "/build/collect-prepared":
                from .builder_collection import collect_prepared
                job = collect_prepared(self,form or {})
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/prepare-native-judging":
                from .builder_native_judging import prepare_native_judging
                job = prepare_native_judging(self,self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/review-native-judging":
                from .builder_native_judging import native_judging_review
                return 200, "text/html; charset=utf-8", native_judging_review(self,self._builder_params(form or {}))
            if method == "POST" and path == "/build/judge-retained-local":
                from .builder_native_judging import judge_retained_local
                job = judge_retained_local(self,form or {})
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/prepare-haiku-judging":
                from .builder_haiku_judging import prepare_haiku_judging
                job = prepare_haiku_judging(self,self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/prepare-judging-inventory":
                from .builder_judging_inventory import prepare_judging_inventory
                job = prepare_judging_inventory(self,self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/review-judging-inventory":
                from .builder_judging_inventory import judging_inventory_review
                return 200, "text/html; charset=utf-8", judging_inventory_review(self,self._builder_params(form or {}))
            if method == "POST" and path == "/build/prepare-inventory-judging":
                from .builder_judging_inventory import prepare_inventory_judging
                job = prepare_inventory_judging(self,self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/review-inventory-judging":
                from .builder_judging_inventory import inventory_judging_review
                return 200, "text/html; charset=utf-8", inventory_judging_review(self,self._builder_params(form or {}))
            if method == "POST" and path == "/build/prepare-inventory-haiku":
                from .builder_inventory_execution import prepare
                job = prepare(self, self._builder_params(form or {}))
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/review-inventory-haiku":
                from .builder_inventory_execution import review
                return 200, "text/html; charset=utf-8", review(self, self._builder_params(form or {}))
            if method == "POST" and path == "/build/execute-inventory-haiku":
                from .builder_inventory_execution import launch
                job = launch(self, form or {})
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/review-haiku-judging":
                from .builder_haiku_judging import haiku_judging_review
                return 200, "text/html; charset=utf-8", haiku_judging_review(self,self._builder_params(form or {}))
            if method == "POST" and path == "/build/judge-retained-haiku":
                from .builder_haiku_judging import judge_retained_haiku
                job = judge_retained_haiku(self,form or {})
                return 303, "/jobs/" + job.job_id, b""
            if method == "POST" and path == "/build/edit":
                ticket = self._consume_launch_ticket((form or {}).get("edit_ticket", ""), purpose="build-edit")
                if ticket is None:
                    raise ValueError("This edit link expired; reopen the saved campaign in Build")
                return 200, "text/html; charset=utf-8", self._build_page(prefill=ticket[0])
            if method == "POST" and path == "/build/framework-runtimes":
                try:
                    framework, action = runtime_action_form(dict(form or {}))
                except FrameworkRuntimeError as exc:
                    return (
                        400,
                        "text/html; charset=utf-8",
                        self._build_page(framework_runtime_error=str(exc)),
                    )
                try:
                    self.framework_runtimes.launch(framework, action)
                except FrameworkRuntimeConflict as exc:
                    return (
                        409,
                        "text/html; charset=utf-8",
                        self._build_page(framework_runtime_error=str(exc)),
                    )
                except FrameworkRuntimeError as exc:
                    return (
                        503,
                        "text/html; charset=utf-8",
                        self._build_page(framework_runtime_error=str(exc)),
                    )
                return 303, "/build?framework_runtime_state=launched#build-runtimes", b""
            if method == "POST" and path == "/build/t3mp3st/capture":
                return self._handle_capture("t3mp3st", dict(form or {}))
            if method == "POST" and path == "/build/harmbench/prepare":
                return self._handle_capture("harmbench", dict(form or {}))
            if method == "POST" and path.startswith("/build/model-acquisition/"):
                data = dict(form or {})
                launch_ticket = data.pop("launch_ticket", "")
                stage = path.removeprefix("/build/model-acquisition/")
                purpose = {
                    "plan": "acquisition_plan",
                    "acquire": "acquisition_download",
                    "run": "acquisition_run",
                }.get(stage)
                ticket_payload = (
                    self._consume_launch_ticket(launch_ticket, purpose=purpose)
                    if purpose is not None and launch_ticket
                    else None
                )
                if data or ticket_payload is None:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._build_page(errors={
                            "models": (
                                "the sealed acquisition authorization expired or "
                                "changed; review the lane again"
                            )
                        }),
                    )
                try:
                    ticket_params, execution_snapshot = ticket_payload
                    if stage == "plan":
                        job = self._start_model_acquisition_plan(
                            ticket_params,
                            execution_snapshot=execution_snapshot,
                        )
                    elif stage == "acquire" and set(ticket_params) == {"plan_job_id"}:
                        job = self._start_model_acquisition_download(
                            ticket_params["plan_job_id"]
                        )
                    elif stage == "run" and set(ticket_params) == {
                        "acquisition_job_id"
                    }:
                        job = self._start_model_acquisition_run(
                            ticket_params["acquisition_job_id"]
                        )
                    else:
                        raise ValueError("invalid acquisition stage authorization")
                except (KeyError, OSError, TypeError, ValueError):
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._build_page(errors={
                            "models": (
                                "the sealed acquisition stage failed admission; "
                                "review the lane and its immutable inputs again"
                            )
                        }),
                    )
                return 303, f"/jobs/{job.job_id}", b""
            if method == "POST" and path in {"/build", "/build/review"}:
                data = dict(form or {})
                confirm_value = data.pop("confirm", "")
                preflight_value = data.pop("preflight_only", "")
                launch_ticket = data.pop("launch_ticket", "")

                def confirmation_error() -> tuple[int, str, bytes]:
                    return (
                        200,
                        "text/html; charset=utf-8",
                        self._build_page(
                            errors={
                                "models": (
                                    "the confirmation expired or was changed; "
                                    "review the lane again"
                                )
                            },
                        ),
                    )

                if launch_ticket or confirm_value:
                    # Consume before inspecting changed fields: a tampered,
                    # incomplete, cross-route, or replayed confirmation burns
                    # the capability exactly once and can never launch later.
                    ticket_payload = (
                        self._consume_launch_ticket(
                            launch_ticket,
                            purpose="build",
                        )
                        if launch_ticket
                        else None
                    )
                    if (
                        confirm_value != "yes"
                        or preflight_value not in {"", "yes"}
                        or ticket_payload is None
                        or data
                    ):
                        return confirmation_error()
                    ticket_params, execution_snapshot = ticket_payload
                    params = ticket_params
                    confirmed = True
                    preflight_only = preflight_value == "yes"
                else:
                    if preflight_value not in {"", "yes"}:
                        return confirmation_error()
                    confirmed = False
                    execution_snapshot = {}
                    preflight_only = preflight_value == "yes"
                    # A retained job contains digest identities, not raw local
                    # paths. Resolve those identities from the current private
                    # registry only for this in-memory validation/composition.
                    try:
                        params = self._runtime_builder_params(
                            self._builder_params(data)
                        )
                    except ValueError:
                        return (
                            200,
                            "text/html; charset=utf-8",
                            self._build_page(
                                errors={
                                    "models": (
                                        "the builder request contains unsupported "
                                        "or malformed fields; review the lane again"
                                    )
                                },
                            ),
                        )
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
                if not confirmed:
                    params = self._save_build_campaign(params)
                try:
                    command, values, params = self._compose_from_builder(
                        params,
                        execution_snapshot=execution_snapshot,
                    )
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
                        snapshot_payload=execution_snapshot.get("attacker_config"),
                        artifact_snapshots=execution_snapshot,
                    )
                except ValueError as exc:
                    self._discard_unlaunched_local_config(values)
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
                    values["--attacker-config-sha256"] = hashlib.sha256(
                        attacker_config.read_bytes()
                    ).hexdigest()
                if preflight_only:
                    # No-call projection: run the SAME grid with
                    # --preflight-only (the CLI makes NO generation calls); it
                    # writes the lane-projection the preview then reads.  Live
                    # attestation is intentionally absent: run_matrix forbids
                    # scope/attestation inputs in preflight-only mode.
                    # Prospective eligibility/projection artifacts must not
                    # share the measured lane's output tree: downstream
                    # cohort scans treat that tree as measurement input.
                    if self._builder_model_acquisition_required(params):
                        # Planning is itself no-call and creates the explicit,
                        # reviewable acquisition stage.  The later download
                        # still needs its own purpose-bound one-shot ticket;
                        # never launch a Hub preflight that lacks a receipt.
                        self._discard_unlaunched_local_config(values)
                        job = self._start_model_acquisition_plan({
                            **params,
                            "_model_acquisition_next": "preflight",
                        }, execution_snapshot=execution_snapshot)
                    else:
                        proj_values = self._builder_preflight_values(
                            values,
                            output=self._preflight_output_dir(params),
                        )
                        job = self.start_job(
                            command,
                            proj_values,
                            builder_params=params,
                            execution_snapshot=execution_snapshot,
                        )
                    return 303, f"/jobs/{job.job_id}", b""
                mode = params.get("mode", "measured")
                spends_money = not (
                    mode == "dry_run"
                    or (mode == "diagnostic_canary" and params.get("canary_dry") == "on")
                )
                if (spends_money or path == "/build/review") and not confirmed:
                    try:
                        page = self._preview_page(
                            command,
                            values,
                            params,
                        )
                    finally:
                        self._discard_unlaunched_local_config(values)
                    return 200, "text/html; charset=utf-8", page
                if spends_money:
                    _card, caps_ok = self._ceilings_card(params)
                    if not caps_ok:
                        # Confirmation is never trusted as a bypass: a stale
                        # browser form or direct POST must still present an
                        # exact valid preflight whose calculated bounds fit.
                        try:
                            page = self._preview_page(
                                command,
                                values,
                                params,
                            )
                        finally:
                            self._discard_unlaunched_local_config(values)
                        return 200, "text/html; charset=utf-8", page
                job = self.start_job(
                    command,
                    values,
                    builder_params=params,
                    scrub_receipt_env=("--dry-run" in values),
                    execution_snapshot=execution_snapshot,
                )
                return 303, f"/jobs/{job.job_id}", b""
            if method == "POST" and path == "/db/reindex":
                summary = self.reindex_all(verify_sha=(form or {}).get("verify_artifact_sha256") == "on")
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
