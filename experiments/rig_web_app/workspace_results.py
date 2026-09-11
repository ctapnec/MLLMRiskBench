"""Compact, explicitly selected result references for campaign presentation.

Publishers supply the retained assignment and response identities. Page reads
never reopen a corpus, reconstruct a campaign or choose the newest/best answer.
"""

from __future__ import annotations

import json
import sqlite3
import time


class WorkspaceResultsMixin:
    def _create_workspace_results(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_assignments ("
            "campaign_id TEXT NOT NULL, assignment_id TEXT NOT NULL, model TEXT NOT NULL, "
            "input_id TEXT NOT NULL, condition_id TEXT NOT NULL, modality TEXT NOT NULL, "
            "framework TEXT NOT NULL, corpus TEXT NOT NULL, response_id TEXT, "
            "updated_at REAL NOT NULL, PRIMARY KEY(campaign_id,assignment_id))"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS campaign_assignments_model "
            "ON campaign_assignments(campaign_id,model,modality)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_responses ("
            "campaign_id TEXT NOT NULL, response_id TEXT NOT NULL, assignment_id TEXT NOT NULL, condition_id TEXT NOT NULL, "
            "outcome TEXT NOT NULL, truncated INTEGER, details TEXT NOT NULL, "
            "PRIMARY KEY(campaign_id,response_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_judgments ("
            "campaign_id TEXT NOT NULL, response_id TEXT NOT NULL, judge_id TEXT NOT NULL, "
            "status TEXT NOT NULL, label TEXT, source_ref TEXT NOT NULL, "
            "PRIMARY KEY(campaign_id,response_id,judge_id))"
        )

    def publish_workspace_results(self, campaign_id: str, *, assignments: list[dict],
                                  responses: list[dict], judgments: list[dict]) -> None:
        """One publication transaction, retaining historical response references.

        ``response_id`` on each assignment explicitly selects its displayed
        outcome (or None for pending). A publication cannot rename an existing
        assignment, mutate a retained response or attach a verdict by input ID.
        This index does not authorize calls or replace scientific validation.
        """
        self.require_workspace(campaign_id)

        def text(row, key):
            value = row[key]
            if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                raise ValueError(f"Invalid campaign result {key}")
            return value

        prepared_assignments, prepared_responses, prepared_judgments = [], [], []
        for row in assignments:
            identity = tuple(text(row, key) for key in (
                "assignment_id", "model", "input_id", "condition_id", "modality", "framework", "corpus"))
            selected = text(row, "response_id") if row.get("response_id") is not None else None
            prepared_assignments.append((campaign_id, *identity, selected, time.time()))
        for row in responses:
            if row.get("outcome") not in {"usable", "policy", "missing", "retry_pending"}:
                raise ValueError("Unknown campaign response outcome")
            if row.get("truncated") is not None and type(row["truncated"]) is not bool:
                raise ValueError("Truncation must be observed true/false or unknown")
            # Metadata only. Source payloads and images remain in their artifacts.
            details = {key: row.get(key) for key in (
                "source_ref", "context_tokens", "output_allowance", "input_tokens",
                "output_tokens", "reasoning_tokens", "finish_reason", "missing_category")}
            for key in ("context_tokens", "output_allowance", "input_tokens", "output_tokens", "reasoning_tokens"):
                if details[key] is not None and (type(details[key]) is not int or details[key] < 0):
                    raise ValueError("Token metadata must be reported counts or unknown")
            details["source_ref"] = text(row, "source_ref")
            payload = json.dumps(details, sort_keys=True, allow_nan=False)
            if len(payload) > 16384:
                raise ValueError("Response index metadata is too large")
            prepared_responses.append((campaign_id, text(row, "response_id"), text(row, "assignment_id"), text(row, "condition_id"),
                                       row["outcome"], row.get("truncated"), payload))
        for row in judgments:
            if row.get("status") not in {"valid", "invalid", "missing", "pending"}:
                raise ValueError("Unknown judgment status")
            label = text(row, "label") if row.get("label") is not None else None
            if row["status"] != "valid" and label is not None:
                raise ValueError("An invalid or pending verdict cannot carry a valid label")
            prepared_judgments.append((campaign_id, text(row, "response_id"), text(row, "judge_id"),
                                       row["status"], label, text(row, "source_ref")))
        with self._lock:
            if self._conn is None:
                raise ValueError("Campaign database is unavailable")
            try:
                with self._conn:
                    for row in prepared_assignments:
                        old = self._conn.execute(
                            "SELECT model,input_id,condition_id,modality,framework,corpus "
                            "FROM campaign_assignments WHERE campaign_id=? AND assignment_id=?", row[:2],
                        ).fetchone()
                        if old and tuple(old) != row[2:8]:
                            raise ValueError("Existing assignment identity changed")
                        self._conn.execute(
                            "INSERT INTO campaign_assignments VALUES(?,?,?,?,?,?,?,?,?,?) "
                            "ON CONFLICT(campaign_id,assignment_id) DO UPDATE SET "
                            "response_id=excluded.response_id,updated_at=excluded.updated_at", row,
                        )
                    for row in prepared_responses:
                        if not self._conn.execute(
                            "SELECT 1 FROM campaign_assignments WHERE campaign_id=? AND assignment_id=?",
                            (campaign_id, row[2]),
                        ).fetchone():
                            raise ValueError("Response has no campaign assignment")
                        old = self._conn.execute(
                            "SELECT * FROM campaign_responses WHERE campaign_id=? AND response_id=?", row[:2],
                        ).fetchone()
                        if old and tuple(old) != row:
                            raise ValueError("Retained response metadata changed; retain a separate condition")
                        self._conn.execute("INSERT OR IGNORE INTO campaign_responses VALUES(?,?,?,?,?,?,?)", row)
                    for row in prepared_assignments:
                        if row[8] is not None and not self._conn.execute(
                            "SELECT 1 FROM campaign_responses WHERE campaign_id=? AND response_id=? AND assignment_id=?",
                            (campaign_id, row[8], row[1]),
                        ).fetchone():
                            raise ValueError("Selected response does not belong to this assignment")
                    for row in prepared_judgments:
                        if not self._conn.execute(
                            "SELECT 1 FROM campaign_responses WHERE campaign_id=? AND response_id=?", row[:2],
                        ).fetchone():
                            raise ValueError("Judgment has no matching retained output")
                        old = self._conn.execute(
                            "SELECT * FROM campaign_judgments WHERE campaign_id=? AND response_id=? AND judge_id=?",
                            row[:3],
                        ).fetchone()
                        if old and old["status"] in {"valid", "invalid"} and tuple(old) != row:
                            raise ValueError("Retained judgment changed; use a distinct judge condition")
                        self._conn.execute(
                            "INSERT INTO campaign_judgments VALUES(?,?,?,?,?,?) "
                            "ON CONFLICT(campaign_id,response_id,judge_id) DO UPDATE SET "
                            "status=excluded.status,label=excluded.label,source_ref=excluded.source_ref", row,
                        )
            except sqlite3.Error as exc:
                self._fail(exc)
                raise ValueError("Campaign result index could not be saved") from exc

    def workspace_model_totals(self, campaign_id: str, *, offset: int = 0) -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT a.model,COUNT(*) AS assigned,COUNT(DISTINCT COALESCE(r.condition_id,a.condition_id)) AS conditions, "
            "SUM(r.outcome='usable') AS usable,SUM(r.outcome='policy') AS policy, "
            "SUM(r.outcome='missing') AS missing,SUM(r.outcome='retry_pending') AS retry_pending, "
            "SUM(r.truncated=1) AS truncated,SUM(r.truncated IS NULL AND r.response_id IS NOT NULL) AS truncation_unknown, "
            "SUM(r.response_id IS NULL) AS pending,MAX(a.updated_at) AS updated_at "
            "FROM campaign_assignments a LEFT JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "WHERE a.campaign_id=? GROUP BY a.model ORDER BY a.model LIMIT 26 OFFSET ?",
            (campaign_id, max(0, offset)),
        )

    def workspace_result_rows(self, campaign_id: str, *, offset: int = 0, model: str = "") -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT a.*,r.outcome,r.truncated,r.details,r.condition_id AS response_condition FROM campaign_assignments a "
            "LEFT JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "WHERE a.campaign_id=? AND (?='' OR a.model=?) "
            "ORDER BY a.model,a.assignment_id LIMIT 51 OFFSET ?", (campaign_id, model, model, max(0, offset)),
        )

    def workspace_judging_totals(self, campaign_id: str) -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT j.judge_id,j.status,COUNT(*) AS count FROM campaign_judgments j "
            "JOIN campaign_assignments a ON a.campaign_id=j.campaign_id AND a.response_id=j.response_id "
            "WHERE j.campaign_id=? GROUP BY j.judge_id,j.status ORDER BY j.judge_id,j.status",
            (campaign_id,),
        )
