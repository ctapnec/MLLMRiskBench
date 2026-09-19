"""Publish local post-hoc assessments against existing campaign answers."""

from __future__ import annotations

from .i18n import text as _ui_text

import hashlib
import json
from pathlib import Path
import sqlite3
import time

from .storage import ConsoleDB
from .workspace_judge_settings import local_settings


class NativeJudgmentPublication:
    def __init__(self, *, database, campaign_id, root):
        self.database, self.campaign_id, self.root = database, campaign_id, Path(root)
        self.db, self.pending, self.published = None, {}, set()
        self.last_flush = 0.0

    def accept(self, source, record, reference, revision, *, invalid=False):
        response = record["response"]
        condition = dict(config=source["judge_cascade"], scoring_revision=revision)
        judge = (
            "local-cascade-"
            + hashlib.sha256(json.dumps(condition, sort_keys=True).encode()).hexdigest()[:24]
        )
        key = (response["run_id"] + ":" + response["attempt_id"], judge)
        self.pending[key] = (source, record, reference, invalid, revision)
        if time.monotonic() - self.last_flush >= 5:
            self.flush()

    def flush(self):
        from experiments.retained_response_judge_execute import _write_atomic

        error = None
        try:
            if self.db is None:
                self.db = ConsoleDB(Path(self.database))
            for (identity, judge), (source, record, reference, invalid, revision) in list(
                self.pending.items()
            ):
                response = record["response"]
                owners = self.db._query(
                    "SELECT r.assignment_id,a.model FROM campaign_responses r "
                    "JOIN campaign_assignments a ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id "
                    "WHERE r.campaign_id=? AND r.response_id=?",
                    (self.campaign_id, identity),
                )
                if (
                    not owners
                    or len(owners) != 1
                    or owners[0]["model"] != source["target"]
                    or response["target"] != source["target"]
                    or response["run_id"] != source["run_id"]
                ):
                    raise ValueError(
                        _ui_text(
                            "workspace_native_judging.native_judgment_needs_its_exact_output_in_the_selected_campaign"
                        )
                    )
                value = None if invalid else record["judgment"]
                if value is not None and (
                    value["run_id"] != response["run_id"]
                    or value["attempt_id"] != response["attempt_id"]
                ):
                    raise ValueError(
                        _ui_text("workspace_native_judging.native_verdict_changed_its_saved_answer")
                    )
                missing = value is not None and value.get("raw", {}).get(
                    "policy_evaluation_status"
                ) in {"model_nonresponse", "target_input_incompatible"}
                row = dict(
                    response_id=identity,
                    judge_id=judge,
                    status="invalid" if invalid else "missing" if missing else "valid",
                    label=None if invalid or missing else value["label"],
                    source_ref=reference,
                    judge_settings=local_settings(source=source, revision=revision),
                )
                self.db.publish_workspace_results(
                    self.campaign_id, assignments=[], responses=[], judgments=[row]
                )
                if any(
                    stage.get("raw", {}).get("guardrail_queried") is True
                    for stage in record.get("trail", [])
                ):
                    self.db.publish_workspace_costs(
                        self.campaign_id,
                        [
                            dict(
                                call_id="local-scoring:" + judge + ":" + identity,
                                attempt_number=1,
                                assignment_id=owners[0]["assignment_id"],
                                response_id=identity,
                                provider="local",
                                model=source["judge_cascade"]["stages"][-1]["model_id"],
                                role="judge",
                                state="not_billed",
                                cost_microusd=0,
                                exposure_microusd=0,
                                source_ref=reference,
                            )
                        ],
                    )
                del self.pending[(identity, judge)]
                self.published.add((identity, judge))
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
                    status="publication_pending" if error or self.pending else "published",
                    campaign_id=self.campaign_id,
                    published_judgments=len(self.published),
                    pending_judgments=len(self.pending),
                    error_type=error,
                    updated_at=time.time(),
                ),
            )
        except OSError:
            pass

    def close(self):
        self.flush()
        if self.db is not None:
            self.db.close()
