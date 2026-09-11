"""SQLite operational state for the rig console."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from .workspace_store import WorkspaceStoreMixin
from .workspace_results import WorkspaceResultsMixin
from .workspace_costs import WorkspaceCostsMixin


from .artifacts import (
    Job,
    assert_durable_job_state_path_free,
    derived_index_path_quarantined,
    run_kind,
    _argv_out_dir,
)


class ConsoleDB(WorkspaceStoreMixin, WorkspaceResultsMixin, WorkspaceCostsMixin):
    """Durable operational database for the console.

    Stdlib sqlite under the state directory: jobs (with their durable argv
    identities and builder parameters), the campaign-run registry, per-artifact
    token usage, and the report/artifact index.  Operational state only - the
    validated filesystem artifacts remain the scientific authority.

    Every access is serialized by one lock (the HTTP server is
    multi-threaded).  Terminal job state, its run row, and its usage rows
    commit in a single transaction; callers flip their ``run_recorded`` flag
    only after that commit returns success.  A database fault never raises
    into a page, but it is never silent either: ``last_error`` and
    ``healthy`` feed a visible banner, and history readers return None (an
    unknown, shown as such) rather than a fabricated empty history.
    """

    SCHEMA_VERSION = 8

    def __init__(self, path: Path, *, repo_root: Path | None = None) -> None:
        self.path = path
        self.repo_root = repo_root if repo_root is not None else Path.cwd()
        self._lock = threading.Lock()
        self.healthy = False
        self.last_error = ""
        self._conn: sqlite3.Connection | None = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            check = self._conn.execute("PRAGMA quick_check").fetchone()
            if check is None or str(check[0]).lower() != "ok":
                raise sqlite3.DatabaseError(
                    f"integrity check failed: {check[0] if check else 'no result'}"
                )
            self._migrate()
            self.healthy = True
        except sqlite3.Error as exc:
            self.last_error = f"database open failed: {exc}"
            try:
                if self._conn is not None:
                    self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # -- schema ------------------------------------------------------------

    def _migrate(self) -> None:
        assert self._conn is not None
        # sqlite3's legacy isolation mode autocommits DDL, so a `with
        # self._conn` block does not make CREATE/ALTER/DROP atomic with the
        # DML.  Recover any table stranded by an interrupted prior migration
        # first (idempotent), then apply the current schema.
        self._recover_stranded_runs()
        with self._conn:  # one transaction
            tables = {
                str(row[0])
                for row in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            self._conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
            if "jobs" in tables:
                existing = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(jobs)")}
                for column, kind in (
                    ("builder_params", "TEXT"),
                    ("run_kind", "TEXT"),
                    ("out_dir", "TEXT"),
                    ("pin", "TEXT"),
                    ("failure", "TEXT"),
                    ("activity", "TEXT"),
                ):
                    if column not in existing:
                        self._conn.execute(f"ALTER TABLE jobs ADD COLUMN {column} {kind}")
            else:
                self._conn.execute(
                    """
                    CREATE TABLE jobs (
                        job_id TEXT PRIMARY KEY, command TEXT, argv TEXT,
                        directory TEXT, state TEXT, exit_code INTEGER,
                        started_at REAL, ended_at REAL, updated_at REAL,
                        builder_params TEXT, run_kind TEXT, out_dir TEXT,
                        pin TEXT, failure TEXT, activity TEXT
                    )
                    """
                )
            if "runs" in tables:
                columns = [str(row[1]) for row in self._conn.execute("PRAGMA table_info(runs)")]
                if "run_id" in columns:  # v1 shape with an autoincrement id
                    self._conn.execute("ALTER TABLE runs RENAME TO runs_v1")
                    self._create_runs()
                    self._conn.execute(
                        "INSERT OR IGNORE INTO runs(job_id,kind,command,"
                        "out_dir,pin,state,exit_code,created_at) "
                        "SELECT job_id,kind,command,out_dir,pin,state,"
                        "exit_code,created_at FROM runs_v1"
                    )
                    self._conn.execute("DROP TABLE runs_v1")
            else:
                self._create_runs()
            self._conn.execute("DROP TABLE IF EXISTS spend")  # v1, rebuilt as usage
            # ``usage`` is derived state (reindex/reconcile rebuild it from the
            # retained artifacts), so when the schema lacks the completion-date
            # column we drop and recreate it rather than a data-preserving
            # migration - the next reconcile/reindex repopulates usage_date from
            # the markers, so an old run is repriced at its own date, not today.
            if "usage" in tables:
                usage_cols = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(usage)")}
                if "usage_date" not in usage_cols:
                    self._conn.execute("DROP TABLE usage")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS usage (
                    marker_sha TEXT, role TEXT, provider TEXT, model TEXT,
                    category TEXT, amount INTEGER, run_id TEXT, out_dir TEXT,
                    usage_date TEXT, recorded_at REAL,
                    PRIMARY KEY (marker_sha, role, provider, model, category)
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    path TEXT PRIMARY KEY, schema TEXT, kind TEXT,
                    sha256 TEXT, bytes INTEGER, mtime REAL, recorded_at REAL
                )
                """
            )
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(self.SCHEMA_VERSION),),
            )
            self._create_workspaces()
            self._create_workspace_results()
            self._create_workspace_costs()

    def _create_runs(self) -> None:
        assert self._conn is not None
        self._conn.execute(
            """
            CREATE TABLE runs (
                job_id TEXT PRIMARY KEY, kind TEXT, command TEXT,
                out_dir TEXT, pin TEXT, state TEXT, exit_code INTEGER,
                created_at REAL
            )
            """
        )

    def _recover_stranded_runs(self) -> None:
        """Complete a v1->v2 runs migration interrupted after the DDL committed.

        Because DDL autocommits under sqlite3's legacy isolation, a crash or
        error between ``ALTER TABLE runs RENAME TO runs_v1`` and the row copy
        can leave a populated ``runs_v1`` beside an empty v2 ``runs``.  On the
        next open the normal migration would see the new-shape ``runs`` and
        never look at ``runs_v1``, silently losing the history.  This finishes
        the copy idempotently before anything else runs.
        """

        assert self._conn is not None
        tables = {
            str(row[0])
            for row in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "runs_v1" not in tables:
            return
        with self._conn:
            if "runs" not in tables:
                self._create_runs()
            else:
                columns = [str(row[1]) for row in self._conn.execute("PRAGMA table_info(runs)")]
                if "run_id" in columns:  # v1-shaped; replace with the v2 shape
                    self._conn.execute("DROP TABLE runs")
                    self._create_runs()
            self._conn.execute(
                "INSERT OR IGNORE INTO runs(job_id,kind,command,out_dir,pin,"
                "state,exit_code,created_at) SELECT job_id,kind,command,"
                "out_dir,pin,state,exit_code,created_at FROM runs_v1"
            )
            self._conn.execute("DROP TABLE runs_v1")

    # -- plumbing ----------------------------------------------------------

    def _fail(self, exc: sqlite3.Error) -> None:
        self.last_error = str(exc)
        self.healthy = False

    def _job_row(
        self,
        job: "Job",
        state: str | None = None,
        exit_code: int | None = None,
    ) -> tuple:
        # A caller that already sampled the job's state passes it in, so the
        # persisted row cannot disagree with the branch decision (avoids a
        # terminal row being written by a "running" upsert if the process
        # exits between two polls).
        resolved_state = state if state is not None else job.state()
        resolved_exit = exit_code if state is not None else job.exit_code()
        # Lifecycle runs this exact boundary before Popen. Keep the redundant
        # persistence check so a future alternate caller still fails closed.
        assert_durable_job_state_path_free(job.argv, job.builder_params)
        return (
            job.job_id,
            job.command,
            json.dumps(job.argv),
            json.dumps(job.builder_params) if job.builder_params else None,
            str(job.directory),
            resolved_state,
            resolved_exit,
            job.started_at,
            job.ended_at,
            time.time(),
            run_kind(job.command, job.argv),
            _argv_out_dir(job.argv),
            job.pin,
            job.failure,
            getattr(job, "activity", None),
        )

    _JOB_UPSERT = (
        "INSERT INTO jobs(job_id,command,argv,builder_params,directory,state,"
        "exit_code,started_at,ended_at,updated_at,run_kind,out_dir,pin,failure,activity)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(job_id) DO UPDATE SET state=excluded.state,"
        "exit_code=excluded.exit_code,ended_at=excluded.ended_at,"
        "updated_at=excluded.updated_at,failure=excluded.failure,"
        "activity=excluded.activity"
    )

    def upsert_job(
        self,
        job: "Job",
        *,
        state: str | None = None,
        exit_code: int | None = None,
    ) -> bool:
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    self._conn.execute(self._JOB_UPSERT, self._job_row(job, state, exit_code))
                return True
            except sqlite3.Error as exc:
                self._fail(exc)
                return False

    def record_terminal(
        self,
        job: "Job",
        pin: str,
        usage_rows: list[dict[str, Any]],
        *,
        state: str | None = None,
        exit_code: int | None = None,
    ) -> bool:
        """Commit a job's terminal state, run row, and usage in ONE txn."""

        kind = run_kind(job.command, job.argv)
        resolved_state = state if state is not None else job.state()
        resolved_exit = exit_code if state is not None else job.exit_code()
        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    self._conn.execute(self._JOB_UPSERT, self._job_row(job, state, exit_code))
                    if kind is not None:
                        self._conn.execute(
                            "INSERT INTO runs(job_id,kind,command,out_dir,pin,"
                            "state,exit_code,created_at) VALUES(?,?,?,?,?,?,?,?) "
                            "ON CONFLICT(job_id) DO UPDATE SET "
                            "kind=excluded.kind,command=excluded.command,"
                            "state=excluded.state,exit_code=excluded.exit_code,"
                            "out_dir=excluded.out_dir,pin=excluded.pin",
                            (
                                job.job_id,
                                kind,
                                job.command,
                                _argv_out_dir(job.argv),
                                pin,
                                resolved_state,
                                resolved_exit,
                                time.time(),
                            ),
                        )
                    self._insert_usage_rows(usage_rows)
                return True
            except sqlite3.Error as exc:
                self._fail(exc)
                return False

    def _insert_usage_rows(self, usage_rows: list[dict[str, Any]]) -> None:
        assert self._conn is not None
        for row in usage_rows:
            self._conn.execute(
                "INSERT INTO usage(marker_sha,role,provider,model,category,"
                "amount,run_id,out_dir,usage_date,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(marker_sha,role,provider,model,category) "
                "DO UPDATE SET amount=excluded.amount,"
                "usage_date=excluded.usage_date,"
                "recorded_at=excluded.recorded_at",
                (
                    row["marker_sha"],
                    row["role"],
                    row["provider"],
                    row["model"],
                    row["category"],
                    row["amount"],
                    row["run_id"],
                    row["out_dir"],
                    row.get("usage_date", ""),
                    row["recorded_at"],
                ),
            )

    def reindex(
        self,
        usage_rows: list[dict[str, Any]],
        report_rows: list[dict[str, Any]],
    ) -> bool:
        """Rebuild the derived usage and report indexes in one transaction."""

        with self._lock:
            if self._conn is None:
                return False
            try:
                with self._conn:
                    self._conn.execute("DELETE FROM usage")
                    self._conn.execute("DELETE FROM reports")
                    self._insert_usage_rows(usage_rows)
                    for row in report_rows:
                        self._conn.execute(
                            "INSERT INTO reports(path,schema,kind,sha256,bytes,"
                            "mtime,recorded_at) VALUES(?,?,?,?,?,?,?) "
                            "ON CONFLICT(path) DO UPDATE SET "
                            "schema=excluded.schema,kind=excluded.kind,"
                            "sha256=excluded.sha256,bytes=excluded.bytes,"
                            "mtime=excluded.mtime,recorded_at=excluded.recorded_at",
                            (
                                row["path"],
                                row["schema"],
                                row["kind"],
                                row["sha256"],
                                row["bytes"],
                                row["mtime"],
                                row["recorded_at"],
                            ),
                        )
                return True
            except sqlite3.Error as exc:
                self._fail(exc)
                return False

    def _query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row] | None:
        """None on failure - an unknown history, never a fabricated empty one."""

        with self._lock:
            if self._conn is None:
                return None
            try:
                return list(self._conn.execute(sql, params))
            except sqlite3.Error as exc:
                self._fail(exc)
                return None

    def load_jobs(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM jobs ORDER BY started_at DESC LIMIT 500")

    def load_jobs_between(
        self,
        started_from: float,
        started_to: float,
        *,
        limit: int,
    ) -> list[sqlite3.Row] | None:
        """Return persisted jobs in an inclusive start-time window.

        The caller requests one row beyond its display limit so it can disclose
        truncation rather than silently pretending the in-memory restore cache
        is the complete history.
        """

        if (
            isinstance(started_from, bool)
            or isinstance(started_to, bool)
            or not isinstance(started_from, (int, float))
            or not isinstance(started_to, (int, float))
            or started_from > started_to
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or limit <= 0
        ):
            raise ValueError("invalid Jobs history window")
        return self._query(
            "SELECT * FROM jobs WHERE started_at >= ? AND started_at <= ? "
            "ORDER BY started_at DESC, job_id DESC LIMIT ?",
            (float(started_from), float(started_to), limit),
        )

    def load_job(self, job_id: str) -> sqlite3.Row | None:
        if not isinstance(job_id, str) or not job_id:
            return None
        rows = self._query("SELECT * FROM jobs WHERE job_id = ? LIMIT 1", (job_id,))
        return rows[0] if rows else None

    def load_report_jobs(self, *, limit: int) -> list[sqlite3.Row] | None:
        """Bounded retained Level-1/2 Jobs for report ownership recovery."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 10_001
        ):
            raise ValueError("invalid report-job limit")
        return self._query(
            "SELECT job_id, command, argv, state, exit_code FROM jobs "
            "WHERE command IN ('level1_evidence','level2_report') "
            "ORDER BY started_at DESC, job_id DESC LIMIT ?",
            (limit,),
        )

    def list_runs(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM runs ORDER BY created_at DESC LIMIT 500")

    def list_runs_page(self, *, limit: int, offset: int) -> list[sqlite3.Row] | None:
        """A bounded page of retained campaign-run rows."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise ValueError("invalid campaign-run page")
        return self._query(
            "SELECT * FROM runs ORDER BY created_at DESC, job_id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    _CAMPAIGN_ROWS = (
        "SELECT job_id,kind,command,out_dir,pin,state,exit_code,created_at,"
        "record_source,source_priority FROM ("
        "SELECT job_id,kind,command,out_dir,pin,state,exit_code,created_at,"
        "'run' AS record_source,0 AS source_priority FROM runs UNION ALL "
        "SELECT jobs.job_id,jobs.run_kind AS kind,jobs.command,jobs.out_dir,"
        "jobs.pin,jobs.state,jobs.exit_code,jobs.started_at AS created_at,"
        "'active_job' AS record_source,1 AS source_priority FROM jobs "
        "WHERE jobs.run_kind IS NOT NULL AND jobs.state='running' AND NOT EXISTS ("
        "SELECT 1 FROM runs WHERE runs.job_id=jobs.job_id))"
    )

    def list_campaigns_page(self, *, limit: int, offset: int) -> list[sqlite3.Row] | None:
        """Page terminal runs plus active run-kind Jobs, with run precedence."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 100
            or isinstance(offset, bool)
            or not isinstance(offset, int)
            or offset < 0
        ):
            raise ValueError("invalid campaign page")
        return self._query(
            self._CAMPAIGN_ROWS
            + " ORDER BY created_at DESC,job_id DESC,source_priority ASC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    def load_campaign(self, job_id: str) -> sqlite3.Row | None:
        """One terminal run, or its active run-kind Job before termination."""

        if not isinstance(job_id, str) or not job_id:
            return None
        rows = self._query(
            "SELECT job_id,kind,command,out_dir,pin,state,exit_code,created_at,"
            "record_source,source_priority FROM ("
            + self._CAMPAIGN_ROWS
            + ") WHERE job_id=? ORDER BY source_priority ASC LIMIT 1",
            (job_id,),
        )
        return rows[0] if rows else None

    def load_run(self, job_id: str) -> sqlite3.Row | None:
        if not isinstance(job_id, str) or not job_id:
            return None
        rows = self._query("SELECT * FROM runs WHERE job_id = ? LIMIT 1", (job_id,))
        return rows[0] if rows else None

    def list_run_owners(self, *, limit: int) -> list[sqlite3.Row] | None:
        """Bounded canonical-output ownership inputs for report association."""

        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 10_001
        ):
            raise ValueError("invalid run-owner limit")
        return self._query(
            "SELECT job_id, out_dir FROM runs "
            "ORDER BY created_at DESC, job_id DESC LIMIT ?",
            (limit,),
        )

    def list_reports(self) -> list[sqlite3.Row] | None:
        rows = self._query("SELECT * FROM reports ORDER BY mtime DESC LIMIT 500")
        if rows is None:
            return None
        # Rows from an older, overly broad reindex remain non-authoritative
        # derived state.  Hide them immediately; the next reindex deletes and
        # rebuilds the table using the matching discovery boundary.
        return [
            row
            for row in rows
            if not derived_index_path_quarantined(str(row["path"] or ""))
        ]

    def usage_totals(
        self,
    ) -> dict[tuple[str, str, str, str], dict[str, int]] | None:
        # Grouped by usage_date as well, so compute_costs can price each run at
        # the rate effective on ITS completion date, not today's.
        rows = self._query(
            "SELECT role, provider, model, category, amount, out_dir, "
            "COALESCE(usage_date,'') AS usage_date FROM usage"
        )
        if rows is None:
            return None
        run_rows = self._query("SELECT out_dir FROM runs LIMIT 10001")
        owned_roots: list[Path] = []
        if run_rows is not None and len(run_rows) <= 10_000:
            for run_row in run_rows:
                value = str(run_row["out_dir"] or "").strip()
                if not value:
                    continue
                try:
                    candidate = Path(value).expanduser()
                    if not candidate.is_absolute():
                        candidate = self.repo_root / candidate
                    owned_roots.append(candidate.resolve(strict=False))
                except (OSError, RuntimeError):
                    continue

        def quarantined_locator(value: str) -> bool:
            try:
                locator = Path(value).expanduser().resolve(strict=False)
            except (OSError, RuntimeError):
                return derived_index_path_quarantined(value)
            matching: list[Path] = []
            for root in owned_roots:
                try:
                    locator.relative_to(root)
                except ValueError:
                    continue
                matching.append(root)
            if not matching:
                return derived_index_path_quarantined(value)
            owner = max(matching, key=lambda root: len(root.parts))
            relative = locator.relative_to(owner).as_posix()
            return derived_index_path_quarantined(relative)

        totals: dict[tuple[str, str, str, str], dict[str, int]] = {}
        for row in rows:
            if quarantined_locator(str(row["out_dir"] or "")):
                continue
            key = (
                str(row["role"]),
                str(row["provider"]),
                str(row["model"]),
                str(row["usage_date"] or ""),
            )
            category = str(row["category"])
            amount = int(row["amount"] or 0)
            bucket = totals.setdefault(key, {})
            bucket[category] = bucket.get(category, 0) + amount
        return totals

    def health(self) -> dict[str, Any]:
        counts: dict[str, Any] = {}
        if self._conn is not None and self.healthy:
            for table in ("jobs", "runs", "usage", "reports"):
                rows = self._query(f"SELECT COUNT(*) AS n FROM {table}")  # noqa: S608 - fixed table names
                counts[table] = int(rows[0]["n"]) if rows else None
        return {
            "healthy": self.healthy,
            "schema_version": self.SCHEMA_VERSION,
            "path": str(self.path),
            "last_error": self.last_error,
            "counts": counts,
        }

    def close(self) -> None:
        # Detach the connection under the lock so no in-flight accessor (which
        # checks self._conn inside the same lock) can operate on a closed
        # handle, then close outside the lock.
        with self._lock:
            conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error as exc:
                self._fail(exc)
