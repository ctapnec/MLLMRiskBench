"""SQLite operational state for the rig console."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


from .artifacts import Job, run_kind, _argv_out_dir


class ConsoleDB:
    """Durable operational database for the console.

    Stdlib sqlite under the state directory: jobs (with their exact argv and
    builder parameters), the campaign-run registry, recorded per-artifact
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

    SCHEMA_VERSION = 3

    def __init__(self, path: Path) -> None:
        self.path = path
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
                        pin TEXT, failure TEXT
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
        )

    _JOB_UPSERT = (
        "INSERT INTO jobs(job_id,command,argv,builder_params,directory,state,"
        "exit_code,started_at,ended_at,updated_at,run_kind,out_dir,pin,failure)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(job_id) DO UPDATE SET state=excluded.state,"
        "exit_code=excluded.exit_code,ended_at=excluded.ended_at,"
        "updated_at=excluded.updated_at,failure=excluded.failure"
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

    def list_runs(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM runs ORDER BY created_at DESC LIMIT 500")

    def list_reports(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM reports ORDER BY mtime DESC LIMIT 500")

    def usage_totals(
        self,
    ) -> dict[tuple[str, str, str, str], dict[str, int]] | None:
        # Grouped by usage_date as well, so compute_costs can price each run at
        # the rate effective on ITS completion date, not today's.
        rows = self._query(
            "SELECT role, provider, model, category, "
            "COALESCE(usage_date,'') AS usage_date, SUM(amount) AS total "
            "FROM usage GROUP BY role, provider, model, usage_date, category"
        )
        if rows is None:
            return None
        totals: dict[tuple[str, str, str, str], dict[str, int]] = {}
        for row in rows:
            key = (
                str(row["role"]),
                str(row["provider"]),
                str(row["model"]),
                str(row["usage_date"] or ""),
            )
            totals.setdefault(key, {})[str(row["category"])] = int(row["total"] or 0)
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
