"""Output-owned cost references; page reads use SQLite, not result-file scans."""

from __future__ import annotations

import sqlite3
import time


class WorkspaceCostsMixin:
    def _create_workspace_costs(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS campaign_cost_attempts ("
            "call_id TEXT NOT NULL, attempt_number INTEGER NOT NULL, campaign_id TEXT NOT NULL, "
            "assignment_id TEXT NOT NULL, response_id TEXT, provider TEXT NOT NULL, model TEXT NOT NULL, "
            "role TEXT NOT NULL, state TEXT NOT NULL, cost_microusd INTEGER, exposure_microusd INTEGER, "
            "input_tokens INTEGER, output_tokens INTEGER, reasoning_tokens INTEGER, "
            "source_ref TEXT NOT NULL, updated_at REAL NOT NULL, PRIMARY KEY(call_id,attempt_number))"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS campaign_cost_owner ON campaign_cost_attempts(campaign_id,provider,model,role)"
        )

    def publish_workspace_costs(self, campaign_id: str, attempts: list[dict]) -> None:
        """Upsert physical attempts once, owned by the output being generated/judged.

        This is a derived index, not a budget reservation or an account balance.
        Unknown charges remain nullable. Local computation is not an API bill;
        this index does not estimate its electricity or hardware costs.
        """
        self.require_workspace(campaign_id)
        prepared = []
        for item in attempts:
            def text(key, *, optional=False):
                value = item.get(key)
                if value is None and optional:
                    return None
                if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                    raise ValueError(f"Invalid campaign cost {key}")
                return value

            number = item.get("attempt_number")
            if type(number) is not int or number < 1:
                raise ValueError("Physical attempt number must be positive")
            provider, role, state = text("provider"), text("role"), text("state")
            if role not in {"target", "judge"} or state not in {"reserved", "unknown", "bounded_unknown", "settled", "not_billed"}:
                raise ValueError("Unknown cost role or settlement state")
            counts = [item.get(key) for key in (
                "cost_microusd", "exposure_microusd", "input_tokens", "output_tokens", "reasoning_tokens")]
            if any(value is not None and (type(value) is not int or value < 0) for value in counts):
                raise ValueError("Cost and token values must be nonnegative integers or unknown")
            cost, exposure, *_ = counts
            if state in {"settled", "not_billed"}:
                if cost is None or exposure not in {None, 0}:
                    raise ValueError("Known cost needs an amount without unresolved exposure")
                counts[1] = 0
            elif cost is not None:
                raise ValueError("Unknown charge cannot carry a known cost")
            if state == "not_billed" and (provider != "local" or cost != 0):
                raise ValueError("Only local computation can be marked not API billed")
            if provider == "local" and state != "not_billed":
                raise ValueError("Local computation must not masquerade as a provider bill")
            response_id = text("response_id", optional=True)
            if role == "judge" and response_id is None:
                raise ValueError("Judging cost must identify the judged output")
            prepared.append((text("call_id"), number, campaign_id, text("assignment_id"), response_id,
                provider, text("model"), role, state, *counts, text("source_ref")))

        with self._lock:
            if self._conn is None:
                raise ValueError("Campaign database is unavailable")
            try:
                with self._conn:
                    for row in prepared:
                        if not self._conn.execute(
                            "SELECT 1 FROM campaign_assignments WHERE campaign_id=? AND assignment_id=?", row[2:4]
                        ).fetchone():
                            raise ValueError("Cost has no campaign assignment")
                        if row[4] is not None and not self._conn.execute(
                            "SELECT 1 FROM campaign_responses WHERE campaign_id=? AND assignment_id=? AND response_id=?",
                            row[2:5],
                        ).fetchone():
                            raise ValueError("Judged/generated output does not belong to this assignment")
                        old = self._conn.execute(
                            "SELECT * FROM campaign_cost_attempts WHERE call_id=? AND attempt_number=?", row[:2]
                        ).fetchone()
                        if old:
                            # One physical bill cannot be attributed to two outputs
                            # or campaigns merely because it appears in two reports.
                            identity = ("campaign_id", "assignment_id", "provider", "model", "role")
                            if tuple(old[key] for key in identity) != (row[2], row[3], row[5], row[6], row[7]):
                                raise ValueError("Physical attempt already belongs to another campaign, output or role")
                            if old["response_id"] is not None and old["response_id"] != row[4]:
                                raise ValueError("Physical attempt output attribution changed")
                            transitions = {"reserved": {"reserved", "unknown", "bounded_unknown", "settled"},
                                "unknown": {"unknown", "bounded_unknown", "settled"},
                                "bounded_unknown": {"bounded_unknown", "settled"},
                                "settled": {"settled"}, "not_billed": {"not_billed"}}
                            if row[8] not in transitions[old["state"]]:
                                raise ValueError("Cost publication would regress a retained settlement")
                            if old["cost_microusd"] is not None and old["cost_microusd"] != row[9]:
                                raise ValueError("Recorded settled cost changed")
                            for index, field in enumerate(("input_tokens", "output_tokens", "reasoning_tokens"), 11):
                                if old[field] is not None and old[field] != row[index]:
                                    raise ValueError("Reported physical-attempt token usage changed")
                            if tuple(old)[:14] == row[:14]:
                                continue  # A copied locator does not duplicate a bill or change freshness.
                        self._conn.execute(
                            "INSERT INTO campaign_cost_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                            "ON CONFLICT(call_id,attempt_number) DO UPDATE SET response_id=excluded.response_id,"
                            "state=excluded.state,cost_microusd=excluded.cost_microusd,exposure_microusd=excluded.exposure_microusd,"
                            "input_tokens=excluded.input_tokens,output_tokens=excluded.output_tokens,"
                            "reasoning_tokens=excluded.reasoning_tokens,source_ref=excluded.source_ref,updated_at=excluded.updated_at",
                            (*row, time.time()),
                        )
            except sqlite3.Error as exc:
                self._fail(exc)
                raise ValueError("Campaign cost index could not be saved") from exc

    def workspace_cost_totals(self, campaign_id: str, *, offset: int = 0) -> list[sqlite3.Row] | None:
        return self._query(
            "SELECT provider,model,role,COUNT(*) AS attempts,"
            "SUM(provider!='local') AS http_attempts,SUM(state='not_billed') AS local_evaluations,"
            "SUM(state='settled') AS settled_attempts,SUM(state IN ('unknown','bounded_unknown')) AS unknown_attempts,"
            "SUM(state='reserved') AS unsettled_attempts,SUM(cost_microusd) AS cost_microusd,"
            "SUM(exposure_microusd) AS exposure_microusd,"
            "SUM(state IN ('unknown','bounded_unknown','reserved') AND exposure_microusd IS NULL) AS unknown_exposure_count,"
            "SUM(input_tokens) AS input_tokens,SUM(input_tokens IS NULL) AS input_unknown,"
            "SUM(output_tokens) AS output_tokens,SUM(output_tokens IS NULL) AS output_unknown,"
            "SUM(reasoning_tokens) AS reasoning_tokens,SUM(reasoning_tokens IS NULL) AS reasoning_unknown,"
            "MAX(updated_at) AS updated_at FROM campaign_cost_attempts "
            "WHERE campaign_id=? GROUP BY provider,model,role ORDER BY provider,model,role LIMIT 26 OFFSET ?",
            (campaign_id, max(0, offset)),
        )
