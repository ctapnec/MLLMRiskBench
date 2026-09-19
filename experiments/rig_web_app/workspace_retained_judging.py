"""Publish durable retained-output judgments without issuing provider calls."""

from __future__ import annotations

from .i18n import text as _ui_text

import hashlib
import json
import sqlite3
import time
from pathlib import Path

from .storage import ConsoleDB
from .workspace_judgments import retained_judge_identity, retained_judge_rows


class RetainedJudgmentPublication:
    def __init__(
        self, *, database, campaign_ids, root, plan, shared_budget=None, shared_requests=None
    ):
        self.database, self.campaign_ids = database, tuple(dict.fromkeys(campaign_ids))
        self.root, self.plan = Path(root), plan
        self.shared_budget, self.shared_requests = shared_budget, shared_requests
        self.db, self.pending, self.published = None, {}, set()
        self.last_flush = 0.0

    def accept(self, artifact, path):
        self.pending[artifact["selection_index"]] = (str(path), artifact)
        # A resumed prefix is batched. Normal API latency usually allows each
        # new artifact through, without rescanning older judgment files.
        if time.monotonic() - self.last_flush >= 5:
            self.flush()

    def _owner(self, selected):
        response_id = selected["run_id"] + ":" + selected["attempt_id"]
        owners = self.db._query(
            "SELECT r.campaign_id,r.assignment_id,a.model FROM campaign_responses r "
            "JOIN campaign_assignments a ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id "
            "WHERE r.response_id=?",
            (response_id,),
        )
        owners = [row for row in (owners or []) if row["campaign_id"] in self.campaign_ids]
        if len(owners) != 1 or owners[0]["model"] != selected["exact_model"]:
            raise ValueError(
                _ui_text(
                    "workspace_retained_judging.retained_verdict_needs_one_exact_output_owner_in_the_selected_cam"
                )
            )
        return response_id, owners[0]["campaign_id"], owners[0]["assignment_id"]

    def _unshared(self, selected, artifact, reference, response_id, assignment_id):
        from experiments.retained_response_judge_execute import INVALID_JUDGMENT_SCHEMA

        invalid = artifact["schema"] == INVALID_JUDGMENT_SCHEMA
        judgment = dict(
            response_id=response_id,
            judge_id=retained_judge_identity(self.plan["judge_condition"]),
            status="invalid" if invalid else "valid",
            label=None if invalid else artifact["judgment"]["label"],
            source_ref=reference,
        )
        # Distinct executions of the same selection are distinct paid calls.
        key = str(self.root.resolve()) + ":" + selected["retained_row_sha256"]
        call_id = "retained-judge:" + hashlib.sha256(key.encode()).hexdigest()
        count = artifact["judgment"]["raw"]["judge_call"]["transport_attempt_count"]
        costs = []
        for number in range(1, count + 1):
            last = number == count
            cost = artifact["cost_microusd"] if last else None
            costs.append(
                dict(
                    call_id=call_id,
                    attempt_number=number,
                    assignment_id=assignment_id,
                    response_id=response_id,
                    provider="anthropic",
                    model=self.plan["judge_condition"]["model"],
                    role="judge",
                    state="settled" if cost is not None else "unknown",
                    cost_microusd=cost,
                    exposure_microusd=0 if cost is not None else None,
                    input_tokens=artifact["input_tokens"] if last else None,
                    output_tokens=artifact["output_tokens"] if last else None,
                    source_ref=reference,
                )
            )
        return dict(judgments=[judgment], costs=costs)

    def flush(self):
        from experiments.retained_response_judge_execute import _validate_artifact, _write_atomic

        error = None
        try:
            if self.db is None:
                self.db = ConsoleDB(Path(self.database))
            shared = None
            if self.pending and self.shared_budget is not None:
                # Read only the two exact budget files, once per publication
                # batch. No hashes, corpus reconstruction or spending mutation.
                budget_root = self.shared_budget.root
                shared = dict(
                    budget_plan=json.loads((budget_root / "plan.json").read_text()),
                    ledger=json.loads((budget_root / "ledger.json").read_text()),
                    ledger_path=str(budget_root / "ledger.json"),
                    shared_requests=self.shared_requests,
                )
            for index, (reference, artifact) in list(self.pending.items()):
                selected = self.plan["selected"][index]
                _validate_artifact(artifact, plan=self.plan, index=index, row=selected)
                response_id, campaign_id, assignment_id = self._owner(selected)
                if shared is not None:
                    rows = retained_judge_rows(
                        self.plan,
                        [(reference, artifact)],
                        output_assignments={response_id: assignment_id},
                        campaign_id=campaign_id,
                        **shared,
                    )
                else:
                    rows = self._unshared(selected, artifact, reference, response_id, assignment_id)
                self.db.publish_workspace_results(
                    campaign_id, assignments=[], responses=[], judgments=rows["judgments"]
                )
                self.db.publish_workspace_costs(campaign_id, rows["costs"])
                self.published.add(index)
                del self.pending[index]
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, sqlite3.Error) as exc:
            error = type(exc).__name__
            if self.db is not None:
                self.db.close()
                self.db = None
        self.last_flush = time.monotonic()
        try:
            _write_atomic(
                self.root / "publication.json",
                dict(
                    status="publication_pending" if self.pending or error else "published",
                    campaign_ids=self.campaign_ids,
                    published_judgments=len(self.published),
                    pending_judgments=len(self.pending),
                    error_type=error,
                    updated_at=time.time(),
                    cost_scope="physical_attempts_of_retained_judgments",
                ),
            )
        except OSError:
            pass

    def close(self):
        self.flush()
        if self.db is not None:
            self.db.close()
