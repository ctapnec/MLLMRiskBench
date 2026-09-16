"""Small campaign ownership index, independent of worker/process lifetimes."""

from __future__ import annotations

import re
import json
import sqlite3
import time
import uuid


class WorkspaceStoreMixin:
    def _create_workspaces(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaigns ("
            "campaign_id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, "
            "created_at REAL NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_members ("
            "member_kind TEXT NOT NULL, member_id TEXT NOT NULL, "
            "campaign_id TEXT NOT NULL, role TEXT NOT NULL, registered_at REAL NOT NULL, "
            "PRIMARY KEY(member_kind, member_id))"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS campaign_members_owner "
            "ON campaign_members(campaign_id, registered_at)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_definitions ("
            "campaign_id TEXT PRIMARY KEY, builder_params TEXT NOT NULL, updated_at REAL NOT NULL)"
        )

    def save_workspace_definition(self, campaign_id: str, params: dict[str, str]) -> None:
        """Save an editable definition; launched jobs keep their own snapshots."""
        self.require_workspace(campaign_id)
        if params.get("campaign_id") != campaign_id or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in params.items()
        ):
            raise ValueError("Invalid campaign definition")
        with self._lock:
            if self._conn is None:
                raise ValueError("Campaign database is unavailable")
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO campaign_definitions VALUES(?,?,?) "
                        "ON CONFLICT(campaign_id) DO UPDATE SET "
                        "builder_params=excluded.builder_params,updated_at=excluded.updated_at",
                        (campaign_id, json.dumps(params, sort_keys=True), time.time()),
                    )
            except sqlite3.Error as exc:
                self._fail(exc)
                raise ValueError("Campaign definition could not be saved") from exc

    def workspace_definition(self, campaign_id: str) -> dict[str, str]:
        self.require_workspace(campaign_id)
        rows = self._query(
            "SELECT builder_params FROM campaign_definitions WHERE campaign_id=?", (campaign_id,)
        )
        if rows is None:
            raise ValueError("Campaign definition index unavailable")
        return json.loads(rows[0]["builder_params"]) if rows else {}

    def workspace_member_owners(self, members: list[tuple[str, str]]) -> dict[tuple[str, str], str]:
        owners = {}
        # Query only the displayed records, not every historical campaign row.
        for offset in range(0, len(members), 200):
            chunk = members[offset:offset + 200]
            rows = self._query(
                "SELECT member_kind,member_id,campaign_id FROM campaign_members WHERE "
                + " OR ".join("(member_kind=? AND member_id=?)" for _ in chunk),
                tuple(value for pair in chunk for value in pair),
            )
            if rows is None:
                raise ValueError("Campaign ownership index unavailable")
            owners.update({(row["member_kind"], row["member_id"]): row["campaign_id"] for row in rows})
        return owners

    def standalone_runs(self, *, offset: int = 0) -> list[sqlite3.Row] | None:
        if offset < 0:
            raise ValueError("Invalid standalone results page")
        return self._query(
            "SELECT r.* FROM (" + self._CAMPAIGN_ROWS + ") r WHERE NOT EXISTS ("
            "SELECT 1 FROM campaign_members m WHERE m.member_kind IN ('job','external') "
            "AND m.member_id=r.job_id) ORDER BY r.created_at DESC,r.job_id LIMIT 51 OFFSET ?",
            (offset,),
        )

    def create_workspace(self, name: str, kind: str) -> str:
        name = name.strip()
        if not name or len(name) > 120 or any(ord(c) < 32 for c in name):
            raise ValueError("Campaign name must contain 1-120 printable characters")
        if kind not in {"local", "api", "mixed"}:
            raise ValueError("Choose a local, API or mixed campaign")
        campaign_id = uuid.uuid4().hex
        with self._lock:
            if self._conn is None:
                raise ValueError("Campaign database is unavailable")
            try:
                with self._conn:
                    self._conn.execute(
                        "INSERT INTO campaigns VALUES(?,?,?,?)",
                        (campaign_id, name, kind, time.time()),
                    )
            except sqlite3.Error as exc:
                self._fail(exc)
                raise ValueError("Campaign could not be saved") from exc
        return campaign_id

    def workspace(self, campaign_id: str) -> sqlite3.Row | None:
        rows = self._query("SELECT * FROM campaigns WHERE campaign_id=?", (campaign_id,))
        return rows[0] if rows else None

    def require_workspace(self, campaign_id: str) -> None:
        if re.fullmatch(r"[0-9a-f]{32}", campaign_id) is None or not self.workspace(campaign_id):
            raise ValueError("Campaign is unavailable; select it again in Build")

    def workspaces(self) -> list[sqlite3.Row] | None:
        return self._query("SELECT * FROM campaigns ORDER BY created_at DESC, campaign_id")

    def workspace_for_job(self, job_id: str) -> str:
        rows = self._query(
            "SELECT campaign_id FROM campaign_members WHERE member_kind='job' AND member_id=?",
            (job_id,),
        )
        return str(rows[0]["campaign_id"]) if rows else ""

    def completed_workspace_transport_jobs(self, campaign_id: str):
        """Bounded campaign-local lookup, not a scan of historical artifacts."""
        if campaign_id:
            self.require_workspace(campaign_id)
        else:
            return self._query(
                "SELECT j.job_id,j.argv FROM jobs j WHERE j.command='live_attestation' "
                "AND j.state='complete' AND j.exit_code=0 AND NOT EXISTS "
                "(SELECT 1 FROM campaign_members m WHERE m.member_kind='job' AND m.member_id=j.job_id) "
                "ORDER BY j.started_at DESC,j.job_id DESC LIMIT 100", ())
        return self._query(
            "SELECT j.job_id,j.argv FROM jobs j JOIN campaign_members m "
            "ON m.member_kind='job' AND m.member_id=j.job_id "
            "WHERE m.campaign_id=? AND j.command='live_attestation' "
            "AND j.state='complete' AND j.exit_code=0 "
            "ORDER BY j.started_at DESC,j.job_id DESC LIMIT 100", (campaign_id,))

    def completed_probe_jobs(self, campaign_id: str = ''):
        where = " AND m.campaign_id=?" if campaign_id else ""
        return self._query(
            "SELECT j.job_id,j.builder_params,j.out_dir,m.campaign_id,c.name AS campaign_name "
            "FROM jobs j LEFT JOIN campaign_members m ON m.member_kind='job' AND m.member_id=j.job_id "
            "LEFT JOIN campaigns c ON c.campaign_id=m.campaign_id "
            "WHERE j.command='run_matrix' AND j.run_kind='attestation_probe' "
            "AND j.state='complete' AND j.exit_code=0" + where +
            " ORDER BY j.started_at DESC,j.job_id DESC LIMIT 100", (campaign_id,) if campaign_id else ())

    def automatic_output_attempts(self, base: str):
        """Exact generated-directory family, excluding no-call preparation."""
        prefix = base + '-attempt-'
        return self._query(
            "SELECT DISTINCT out_dir,state FROM jobs WHERE command='run_matrix' "
            "AND run_kind NOT IN ('acquisition_plan','preflight') "
            "AND (out_dir=? OR substr(out_dir,1,?)=?)",
            (base, len(prefix), prefix))

    def attach_workspace_member(
        self, campaign_id: str, member_kind: str, member_id: str, role: str
    ) -> None:
        """Idempotent explicit ownership; never move an existing task implicitly.

        External records are references, not fabricated console Job rows. Shared
        publications must be split by output ownership before they are attached.
        """
        self.require_workspace(campaign_id)
        if member_kind not in {"job", "external", "controller", "analysis", "budget"}:
            raise ValueError("Unsupported campaign member kind")
        if not member_id or len(member_id) > 4096 or any(ord(c) < 32 for c in member_id):
            raise ValueError("Invalid campaign member")
        if role not in {"preparation", "collection", "judging", "analysis", "budget"}:
            raise ValueError("Unsupported campaign activity role")
        with self._lock:
            if self._conn is None:
                raise ValueError("Campaign database is unavailable")
            try:
                with self._conn:
                    existing = self._conn.execute(
                        "SELECT campaign_id,role FROM campaign_members "
                        "WHERE member_kind=? AND member_id=?", (member_kind, member_id),
                    ).fetchone()
                    if existing and (existing["campaign_id"], existing["role"]) != (campaign_id, role):
                        raise ValueError("This activity already belongs to another campaign or role")
                    self._conn.execute(
                        "INSERT OR IGNORE INTO campaign_members VALUES(?,?,?,?,?)",
                        (member_kind, member_id, campaign_id, role, time.time()),
                    )
            except sqlite3.Error as exc:
                self._fail(exc)
                raise ValueError("Campaign ownership could not be saved") from exc

    def workspace_activity(self, campaign_id: str, *, offset: int = 0) -> list[sqlite3.Row] | None:
        if offset < 0:
            raise ValueError("Invalid activity page")
        return self._query(
            "SELECT m.*,j.command,j.state,j.started_at,j.ended_at,j.exit_code "
            "FROM campaign_members m LEFT JOIN jobs j "
            "ON m.member_kind='job' AND j.job_id=m.member_id "
            "WHERE m.campaign_id=? ORDER BY m.registered_at DESC,m.member_id LIMIT 51 OFFSET ?",
            (campaign_id, offset),
        )


def activity_role(command: str) -> str:
    if command in {"run_matrix", "hosted_retained_execute", "hosted_campaign_execute"}:
        return "collection"
    if command in {"retained_response_judge_pair", "retained_response_judge_pair_execute", "retained_native_judge_execute",
                   "retained_inventory_judging"}:
        return "judging"
    if command in {"level1_evidence", "level2_report", "figures"}:
        return "analysis"
    if command == "hosted_campaign_budget":
        return "budget"
    return "preparation"
