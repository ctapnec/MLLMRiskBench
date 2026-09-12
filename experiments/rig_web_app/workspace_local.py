"""Publish native local checkpoints without changing Runner execution semantics."""

from __future__ import annotations

import json
import time
from pathlib import Path

from experiments.hosted_retained_inputs import _sha, retained_input_identity

from .storage import ConsoleDB
from .workspace_import import _jsonl, local_generation_condition, local_judge_condition, local_response_row


class LocalCheckpointPublication:
    def __init__(self, *, campaign_id, database, manifest, corpus, checkpoint, response_checkpoint):
        self.campaign_id, self.database = campaign_id, database
        self.manifest, self.run = manifest, manifest["config"]["run"]
        self.model, self.run_id = self.run["model_spec"], manifest["run_id"]
        self.condition, self.judge = local_generation_condition(self.run), local_judge_condition(self.run)
        self.metadata = {dp.id: dict(source=dp.source, risk_category=dp.risk_category,
            expected_behavior=dp.expected_behavior) for dp in corpus}
        self.paths = {"response": Path(response_checkpoint), "judgment": Path(checkpoint)}
        self.references, self.lines = {}, {}
        # One pass over the two exact checkpoint files at cell startup. No
        # directory traversal, source conversion or model-byte verification.
        for role, path in self.paths.items():
            self.references[role], self.lines[role] = {}, 0
            if path.exists():
                for number, row in _jsonl(path):
                    self.references[role][row["attempt"]["id"]] = f"{path}:{number}"
                    self.lines[role] = number
        self.pending, self.published, self.db = {}, set(), None
        self.status_path = self.paths["response"].with_suffix(".publication.json")

    def _rows(self, record, role):
        attempt, response = record["attempt"], record["response"]
        aid = attempt["id"]
        if (attempt["run_id"] != self.run_id or response["run_id"] != self.run_id
                or response["attempt_id"] != aid or attempt["target"] != self.model
                or response["target"] != self.model):
            raise ValueError("Local checkpoint publication ownership differs")
        choice = retained_input_identity(self.run, self.manifest["dataset_hashes"]["corpus"],
            attempt, self.metadata[attempt["datapoint_id"]])
        identity = self.run_id + ":" + aid
        evidence = {"measured_run": "measured", "diagnostic_canary": "diagnostic",
            "attestation_probe": "diagnostic", "preflight": "preflight"}.get(self.run.get("execution_purpose"), "unknown")
        assignment = dict(assignment_id="local-"+identity, model=self.model,
            input_id=_sha(choice), condition_id=self.condition, modality=choice["modality"],
            framework=choice["framework"], corpus=choice["corpus"], response_id=identity,
            evidence_class=evidence)
        reference = self.references["response"].get(aid, self.references[role][aid])
        judgments = []
        if role == "judgment":
            judgment = record["judgment"]
            if judgment["run_id"] != self.run_id or judgment["attempt_id"] != aid:
                raise ValueError("Local judgment does not belong to its output")
            missing = (judgment.get("raw") or {}).get("policy_evaluation_status") in {
                "model_nonresponse", "target_input_incompatible"}
            judgments.append(dict(response_id=identity, judge_id=self.judge,
                status="missing" if missing else "valid", label=None if missing else judgment["label"],
                source_ref=self.references["judgment"][aid]))
        return dict(assignments=[assignment], responses=[local_response_row(response, self.condition, reference)],
            judgments=judgments)

    def accept(self, record, role, *, restored=False):
        aid = record["attempt"]["id"]
        if not restored:
            self.lines[role] += 1
            self.references[role][aid] = f"{self.paths[role]}:{self.lines[role]}"
        self.pending[(aid, role)] = record
        self.flush()

    def flush(self):
        error = None
        try:
            if self.pending and self.db is None:
                self.db = ConsoleDB(Path(self.database))
            for key, record in list(self.pending.items()):
                self.db.publish_workspace_results(self.campaign_id, **self._rows(record, key[1]))
                self.published.add(key)
                del self.pending[key]
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            error = type(exc).__name__
            if self.db is not None:
                self.db.close()
                self.db = None
        status = dict(status="publication_pending" if self.pending else "published",
            campaign_id=self.campaign_id, run_id=self.run_id, published_records=len(self.published),
            pending_records=len(self.pending), error_type=error, updated_at=time.time())
        # Publication failure is not a generation failure. Its small retained
        # status is separate from the authoritative checkpoint and completion.
        try:
            temporary = self.status_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(status, sort_keys=True)+"\n", encoding="utf-8")
            temporary.replace(self.status_path)
        except OSError:
            pass

    def close(self):
        self.flush()
        if self.db is not None:
            self.db.close()


def run_with_workspace_publication(runner, corpus, *, campaign_id="", database=None,
                                   checkpoint, response_checkpoint, **kwargs):
    """Compose publication after existing durable callbacks; preserve resumes."""
    if not campaign_id or not kwargs["run_config"]["model_spec"].startswith(("ollama:", "vllm:")):
        return runner.run(corpus, **kwargs)
    try:
        publisher = LocalCheckpointPublication(campaign_id=campaign_id, database=database,
            manifest=kwargs["manifest"].model_dump(mode="json"), corpus=corpus,
            checkpoint=checkpoint, response_checkpoint=response_checkpoint)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        status = dict(status="publication_pending", campaign_id=campaign_id,
            error_type=type(exc).__name__, updated_at=time.time())
        try:
            Path(response_checkpoint).with_suffix(".publication.json").write_text(json.dumps(status)+"\n", encoding="utf-8")
        except OSError:
            pass
        return runner.run(corpus, **kwargs)
    try:
        full = kwargs.get("resume_records") or {}
        for aid, record in (kwargs.get("response_records") or {}).items():
            if aid not in full:
                publisher.accept(record, "response", restored=True)
        for record in full.values():
            publisher.accept(record, "judgment", restored=True)

        def after_durable(callback, role):
            if callback is None:
                return None
            def publish(record):
                callback(record)
                publisher.accept(record, role)
            return publish

        kwargs["on_response"] = after_durable(kwargs.get("on_response"), "response")
        kwargs["on_record"] = after_durable(kwargs.get("on_record"), "judgment")
        return runner.run(corpus, **kwargs)
    finally:
        publisher.close()
