"""Compact, explicitly selected result references for campaign presentation.

Publishers supply the retained assignment and response identities. Page reads
never reopen a corpus, reconstruct a campaign or choose the newest/best answer.
"""

from __future__ import annotations

import json
import sqlite3
import time

from experiments.retained_outcomes import LEGACY_POLICY_BASES


def canonical_response_source_ref(reference: str) -> str:
    """Comparison alias only, never the artifact locator shown to a reader."""
    path, separator, row = reference.rpartition(":")
    if separator and row.isdigit() and path.endswith(".responses.checkpoint.jsonl"):
        return path.removesuffix(".responses.checkpoint.jsonl") + ".responses.jsonl:" + row
    return reference


def _same_response_source(left: str, right: str) -> bool:
    if left == right:
        return True
    # Final export can reorder restored rows. Identity belongs to response_id,
    # not a line number shared by two different physical files.
    a, a_sep, a_row = left.rpartition(":")
    b, b_sep, b_row = right.rpartition(":")
    return bool(a_sep and b_sep and a_row.isdigit() and b_row.isdigit()
                and a != b
                and canonical_response_source_ref(a + ":1") == canonical_response_source_ref(b + ":1"))


def _same_judgment_source(left: str, right: str) -> bool:
    a, _, a_row = left.rpartition(":")
    b, _, b_row = right.rpartition(":")
    return left == right or bool(a_row.isdigit() and b_row.isdigit() and a != b
        and a.removesuffix(".checkpoint.jsonl").removesuffix(".jsonl")
        == b.removesuffix(".checkpoint.jsonl").removesuffix(".jsonl"))


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
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(campaign_assignments)")}
        if "evidence_class" not in columns:
            self._conn.execute(
                "ALTER TABLE campaign_assignments ADD COLUMN evidence_class TEXT NOT NULL DEFAULT 'unknown'"
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
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_input_progress ("
            "campaign_id TEXT NOT NULL, run_id TEXT NOT NULL, model TEXT NOT NULL, "
            "condition_id TEXT NOT NULL, evidence_class TEXT NOT NULL, planned INTEGER NOT NULL, "
            "reached INTEGER NOT NULL, updated_at REAL NOT NULL, PRIMARY KEY(campaign_id,run_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_recoveries (campaign_id TEXT NOT NULL, "
            "predecessor TEXT NOT NULL, successor TEXT NOT NULL, reason TEXT NOT NULL, evidence_ref TEXT NOT NULL, "
            "PRIMARY KEY(campaign_id,successor))"
        )

    def link_workspace_recovery(self, campaign_id: str, *, predecessor: str, successor: str,
                                reason: str, evidence_ref: str) -> None:
        """Annotate an explicit saved recovery, without selecting or rewriting outputs."""
        self.require_workspace(campaign_id)
        if predecessor == successor or any(not isinstance(v,str) or not v.strip() or len(v)>4096
                                            for v in (predecessor,successor,reason,evidence_ref)):
            raise ValueError('Recovery needs two distinct saved outputs and its evidence')
        with self._lock, self._conn:
            rows = self._conn.execute(
                'SELECT r.response_id,a.model,a.input_id,a.modality,a.framework,a.corpus,a.evidence_class '
                'FROM campaign_responses r JOIN campaign_assignments a '
                'ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id '
                'WHERE r.campaign_id=? AND r.response_id IN (?,?)',
                (campaign_id,predecessor,successor)).fetchall()
            if len(rows)!=2 or tuple(rows[0])[1:] != tuple(rows[1])[1:]:
                raise ValueError('Recovery must refer to the same model, input and task in this campaign')
            record=(campaign_id,predecessor,successor,reason,evidence_ref)
            old=self._conn.execute('SELECT * FROM campaign_recoveries WHERE campaign_id=? AND successor=?',
                                   (campaign_id,successor)).fetchone()
            if old and tuple(old)!=record: raise ValueError('Retained recovery link cannot be changed')
            if not old:self._conn.execute('INSERT INTO campaign_recoveries VALUES(?,?,?,?,?)',record)

    def workspace_recovery_rows(self, campaign_id: str, *, model: str='', condition: str='', offset: int=0):
        return self._query(
            'SELECT l.*,a.model,a.input_id,a.corpus,a.modality,p.outcome AS old_outcome,'
            's.outcome AS new_outcome,p.details AS old_details,s.details AS new_details,'
            'p.condition_id AS old_condition,s.condition_id AS new_condition '
            'FROM campaign_recoveries l JOIN campaign_responses p '
            'ON p.campaign_id=l.campaign_id AND p.response_id=l.predecessor '
            'JOIN campaign_responses s ON s.campaign_id=l.campaign_id AND s.response_id=l.successor '
            'JOIN campaign_assignments a ON a.campaign_id=s.campaign_id AND a.assignment_id=s.assignment_id '
            "WHERE l.campaign_id=? AND (?='' OR a.model=?) "
            "AND (?='' OR p.condition_id=? OR s.condition_id=?) ORDER BY a.model,l.successor LIMIT 51 OFFSET ?",
            (campaign_id,model,model,condition,condition,condition,max(0,offset)))

    def publish_workspace_inputs(self, campaign_id: str, *, run_id: str, model: str,
                                 condition_id: str, evidence_class: str, planned: int, reached: int) -> None:
        """Source rows per native run, not generated turns or finished assessments."""
        self.require_workspace(campaign_id)
        if any(not isinstance(value, str) or not value.strip() or len(value) > 4096
               for value in (run_id, model, condition_id)):
            raise ValueError("Invalid input-plan identity")
        if evidence_class not in {"measured", "diagnostic", "preflight", "unknown"}:
            raise ValueError("Input plan needs its evidence class")
        if type(planned) is not int or type(reached) is not int or not 0 <= reached <= planned:
            raise ValueError("Invalid planned/reached source-row counts")
        row = (campaign_id, run_id, model, condition_id, evidence_class, planned)
        with self._lock:
            if self._conn is None:
                raise ValueError("Campaign database is unavailable")
            with self._conn:
                old = self._conn.execute(
                    "SELECT * FROM campaign_input_progress WHERE campaign_id=? AND run_id=?", row[:2]
                ).fetchone()
                if old:
                    if tuple(old)[:6] != row:
                        raise ValueError("Native input plan changed; retain a separate run")
                    if old["reached"] >= reached:
                        return  # Resume can replay a smaller durable prefix while restoring.
                self._conn.execute(
                    "INSERT INTO campaign_input_progress VALUES(?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(campaign_id,run_id) DO UPDATE SET reached=excluded.reached,updated_at=excluded.updated_at",
                    (*row, reached, time.time()),
                )

    def workspace_input_totals(self, campaign_id: str, *, model: str = "", condition: str = "",
                               offset: int = 0) -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT model,evidence_class,COUNT(*) AS runs,SUM(planned) AS planned,SUM(reached) AS reached,"
            "MAX(updated_at) AS updated_at FROM campaign_input_progress "
            "WHERE campaign_id=? AND (?='' OR model=?) AND (?='' OR condition_id=?) "
            "GROUP BY model,evidence_class ORDER BY model,evidence_class LIMIT 26 OFFSET ?",
            (campaign_id, model, model, condition, condition, max(0, offset)),
        )

    def publish_workspace_results(self, campaign_id: str, *, assignments: list[dict],
                                  responses: list[dict], judgments: list[dict]) -> None:
        """One publication transaction, retaining historical response references.

        ``response_id`` on each assignment explicitly selects its displayed
        outcome (or None for a newly pending assignment). Replaying a source
        without an answer cannot clear an already selected retained answer.
        A publication cannot rename an existing
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
            if row.get("evidence_class") not in {"measured", "diagnostic", "preflight", "unknown"}:
                raise ValueError("Assignment needs its explicit evidence class")
            identity = tuple(text(row, key) for key in (
                "assignment_id", "model", "input_id", "condition_id", "modality", "framework", "corpus"))
            selected = text(row, "response_id") if row.get("response_id") is not None else None
            prepared_assignments.append((campaign_id, *identity, selected, time.time(), row["evidence_class"]))
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
                if key == "output_allowance" and type(details[key]) is int and details[key] == -1:
                    continue  # Retained local-provider native-maximum policy, not negative usage.
                if details[key] is not None and (type(details[key]) is not int or details[key] < 0):
                    raise ValueError("Token metadata must be reported counts or unknown")
            details["source_ref"] = text(row, "source_ref")
            if row.get("outcome_basis") is not None:
                if row["outcome"] != "policy" or row["outcome_basis"] not in LEGACY_POLICY_BASES:
                    raise ValueError("Unknown retained policy classification basis")
                details["outcome_basis"] = row["outcome_basis"]
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
                            "SELECT model,input_id,condition_id,modality,framework,corpus,evidence_class "
                            "FROM campaign_assignments WHERE campaign_id=? AND assignment_id=?", row[:2],
                        ).fetchone()
                        if old and tuple(old) != (*row[2:8], row[10]):
                            raise ValueError("Existing assignment identity changed")
                        self._conn.execute(
                            "INSERT INTO campaign_assignments VALUES(?,?,?,?,?,?,?,?,?,?,?) "
                            "ON CONFLICT(campaign_id,assignment_id) DO UPDATE SET "
                            "response_id=excluded.response_id,updated_at=excluded.updated_at "
                            "WHERE excluded.response_id IS NOT NULL "
                            "AND campaign_assignments.response_id IS NOT excluded.response_id", row,
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
                            previous = json.loads(old["details"])
                            current = json.loads(row[6])
                            if _same_response_source(previous["source_ref"], current["source_ref"]):
                                previous["source_ref"] = current["source_ref"]
                            correction = (old["outcome"] == "missing" and row[4] == "policy"
                                and current.get("outcome_basis") in LEGACY_POLICY_BASES)
                            if correction:
                                # The publisher resolved the native error code from
                                # the unchanged response, not from the prompt topic.
                                previous["outcome_basis"] = current["outcome_basis"]
                                previous["missing_category"] = None
                            comparable = (*tuple(old)[:4], "policy" if correction else old["outcome"],
                                old["truncated"], json.dumps(previous, sort_keys=True, allow_nan=False))
                            if comparable != row:
                                raise ValueError("Retained response metadata changed; retain a separate condition")
                            self._conn.execute(
                                "UPDATE campaign_responses SET outcome=?,details=? WHERE campaign_id=? AND response_id=?",
                                (row[4], row[6], row[0], row[1]),
                            )
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
                            if tuple(old)[:-1] != row[:-1] or not _same_judgment_source(old["source_ref"], row[-1]):
                                raise ValueError("Retained judgment changed; use a distinct judge condition")
                        self._conn.execute(
                            "INSERT INTO campaign_judgments VALUES(?,?,?,?,?,?) "
                            "ON CONFLICT(campaign_id,response_id,judge_id) DO UPDATE SET "
                            "status=excluded.status,label=excluded.label,source_ref=excluded.source_ref", row,
                        )
            except sqlite3.Error as exc:
                self._fail(exc)
                raise ValueError("Campaign result index could not be saved") from exc

    def workspace_result_models(self, campaign_id: str) -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT model FROM campaign_assignments WHERE campaign_id=? "
            "UNION SELECT model FROM campaign_input_progress WHERE campaign_id=? ORDER BY model",
            (campaign_id, campaign_id),
        )

    def workspace_result_conditions(self, campaign_id: str, *, model: str) -> list[sqlite3.Row] | None:
        """Settings for one selected model, read only from compact indexed metadata."""
        return self._query(
            "SELECT COALESCE(r.condition_id,a.condition_id) AS condition_id,COUNT(*) AS assigned, "
            "MIN(json_extract(r.details,'$.context_tokens')) AS context_min, "
            "MAX(json_extract(r.details,'$.context_tokens')) AS context_max, "
            "MIN(json_extract(r.details,'$.output_allowance')) AS output_min, "
            "MAX(json_extract(r.details,'$.output_allowance')) AS output_max, "
            "COUNT(json_extract(r.details,'$.context_tokens')) AS context_known, "
            "COUNT(json_extract(r.details,'$.output_allowance')) AS output_known "
            "FROM campaign_assignments a LEFT JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "WHERE a.campaign_id=? AND a.model=? GROUP BY COALESCE(r.condition_id,a.condition_id) "
            "ORDER BY condition_id", (campaign_id, model),
        )

    def workspace_model_totals(self, campaign_id: str, *, offset: int = 0,
                               model: str = "", condition: str = "") -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT a.model,a.evidence_class,COUNT(*) AS assigned,COUNT(DISTINCT COALESCE(r.condition_id,a.condition_id)) AS conditions, "
            "SUM(r.outcome='usable') AS usable,SUM(r.outcome='policy') AS policy, "
            "SUM(r.outcome='missing') AS missing,SUM(r.outcome='retry_pending') AS retry_pending, "
            "SUM(r.truncated=1 AND r.outcome!='retry_pending') AS truncated,"
            "SUM(r.truncated IS NULL AND r.response_id IS NOT NULL AND r.outcome!='retry_pending') AS truncation_unknown, "
            "SUM(r.response_id IS NULL) AS pending,MAX(a.updated_at) AS updated_at "
            "FROM campaign_assignments a LEFT JOIN campaign_responses r "
            "ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "WHERE a.campaign_id=? AND (?='' OR a.model=?) "
            "AND (?='' OR COALESCE(r.condition_id,a.condition_id)=?) "
            "GROUP BY a.model,a.evidence_class ORDER BY a.model,a.evidence_class LIMIT 26 OFFSET ?",
            (campaign_id, model, model, condition, condition, max(0, offset)),
        )

    def workspace_result_rows(self, campaign_id: str, *, offset: int = 0, model: str = "",
                              condition: str = "") -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT a.*,r.outcome,r.truncated,r.details,r.condition_id AS response_condition FROM campaign_assignments a "
            "LEFT JOIN campaign_responses r ON r.campaign_id=a.campaign_id AND r.response_id=a.response_id "
            "WHERE a.campaign_id=? AND (?='' OR a.model=?) "
            "AND (?='' OR COALESCE(r.condition_id,a.condition_id)=?) "
            "ORDER BY a.model,a.assignment_id LIMIT 51 OFFSET ?",
            (campaign_id, model, model, condition, condition, max(0, offset)),
        )

    def workspace_judging_totals(self, campaign_id: str, *, model: str = "",
                                condition: str = "") -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT j.judge_id,j.status,COUNT(*) AS count FROM campaign_judgments j "
            "JOIN campaign_responses r ON r.campaign_id=j.campaign_id AND r.response_id=j.response_id "
            "JOIN campaign_assignments a ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id "
            "AND a.response_id=r.response_id "
            "WHERE j.campaign_id=? AND (?='' OR a.model=?) AND (?='' OR r.condition_id=?) "
            "GROUP BY j.judge_id,j.status ORDER BY j.judge_id,j.status",
            (campaign_id, model, model, condition, condition),
        )

    def workspace_judgment_breakdown(self, campaign_id: str, *, offset: int = 0,
                                     model: str = "", condition: str = "") -> list[sqlite3.Row] | None:
        """Page complete label distributions, keeping scientific conditions separate."""
        return self._query(
            "WITH counts AS (SELECT a.model,a.evidence_class,r.condition_id,a.modality,a.framework,a.corpus,"
            "j.judge_id,j.status,j.label,COUNT(*) AS count FROM campaign_judgments j "
            "JOIN campaign_responses r ON r.campaign_id=j.campaign_id AND r.response_id=j.response_id "
            "JOIN campaign_assignments a ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id "
            "AND a.response_id=r.response_id "
            "WHERE j.campaign_id=? AND (?='' OR a.model=?) AND (?='' OR r.condition_id=?) "
            "GROUP BY a.model,a.evidence_class,r.condition_id,a.modality,a.framework,a.corpus,j.judge_id,j.status,j.label), "
            "ranked AS (SELECT *,DENSE_RANK() OVER (ORDER BY CASE WHEN evidence_class='measured' THEN 0 ELSE 1 END,"
            "model,evidence_class,condition_id,modality,framework,corpus,judge_id) "
            "AS group_number FROM counts) SELECT * FROM ranked WHERE group_number>? AND group_number<=? "
            "ORDER BY group_number,status,label",
            (campaign_id, model, model, condition, condition, max(0, offset), max(0, offset) + 13),
        )
