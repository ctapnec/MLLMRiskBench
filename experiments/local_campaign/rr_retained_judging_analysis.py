"""Read separately completed RR scoring without inventing a completed old grid."""
from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from experiments import retained_artifact_reader as retained
from experiments.local_campaign import rr_retained_judging as recovery
from experiments.local_campaign.vllm_stability_phase6 import (
    _descriptor, _load_json, _validate_descriptor,
)
from ura.runner import Runner


def _completed_view(path: Path, *, work: Path, project: Path) -> dict:
    """Called inside the actual scoring-source checkout; never performs inference."""
    completion = _load_json(path, label="RR scoring completion")
    launch_path = _validate_descriptor(completion["launch"], label="RR scoring launch")
    launch, source = recovery.load_launch(
        launch_path, completion["launch"]["sha256"], work=work, project=project,
    )
    root = Path(launch["data_root"])
    continuing = launch["schema"] == "ura-rr-retained-judging/2"
    checkpoint = (_validate_descriptor(completion["checkpoint"], label="RR new judgments")
                  if completion["checkpoint"] is not None else root / "judgments.checkpoint.jsonl")
    invocation_path = _validate_descriptor(completion["invocation"], label="RR scoring invocation")
    invocation = _load_json(invocation_path, label="RR scoring invocation")
    if (path != root / "completion.json" or checkpoint != root / "judgments.checkpoint.jsonl"
            or completion.get("schema") != ("ura-rr-retained-judging-completion/2" if continuing
                                            else "ura-rr-retained-judging-completion/1")
            or completion.get("generation_run_id") != source.manifest.run_id
            or completion.get("judging_revision") != launch["judging_revision"]
            or completion.get("target_calls") != 0 or completion.get("hosted_calls") != 0
            or completion.get("old_grid_promoted") is not False
            or invocation_path.parent.parent != work / "runs/engineering"
            or invocation_path.name != "invocation.json"
            or invocation.get("launch") != completion["launch"]
            or invocation.get("generation_run_id") != source.manifest.run_id):
        raise ValueError("RR scoring completion changed its execution or generation identity")
    saved = Runner.load_checkpoint(checkpoint, expected_run_id=source.manifest.run_id)
    failures = recovery.load_failures(root / "evaluator-failures", source) if continuing else {}
    if continuing:
        descriptors = [_descriptor(root / "evaluator-failures" / (recovery._sha256_json(key) + ".json"),
                                   label="RR evaluator failure") for key in sorted(failures)]
        if (completion.get("evaluator_failures") != descriptors
                or completion.get("evaluator_failure_policy") != recovery.FAILURE_POLICY
                or completion.get("judging_complete") is not (not failures)):
            raise ValueError("RR scoring completion changed its evaluator failure inventory")
    counts = {"retained_responses": len(source.responses),
              "total_judgments": len(source.judgments) + len(saved),
              "existing_judgments": len(source.judgments), "new_judgments": len(saved)}
    if continuing:
        counts.update(failed_judgments=len(failures), attempted_pending_judgments=len(source.pending_ids))
    if ((completion["checkpoint"] is None and (not continuing or saved or checkpoint.exists()))
            or set(saved) & set(failures) or set(saved) | set(failures) != set(source.pending_ids)
            or any(type(completion.get(key)) is not int or completion[key] != count
                   for key, count in counts.items())):
        raise ValueError("RR scoring completion omits or repeats retained response judgments")
    # Exact restore validates every original/new input, Response and judge trail.
    # No missing checkpoint entry can fall through to the classifier.
    runner = recovery._reader_runner(source.manifest, recovery.source_cascade(source.manifest))
    records = {**source.judgments, **saved}
    for key, (point, attempt) in source.inputs.items():
        if key in failures:
            runner._restore_response(attempt, source.responses[key], source.manifest.run_id)
            continue
        if records[key]["response"] != source.responses[key]["response"]:
            raise ValueError("RR scoring analysis changed a retained target response")
        runner._restore_record(point, attempt, records[key], source.manifest.run_id)
    source.validate_unchanged()
    if completion["checkpoint"] is not None:
        _validate_descriptor(completion["checkpoint"], label="RR restored judgments")
    return {
        "source_completion": _descriptor(path, label="RR scoring completion"),
        "launch": launch, "generation_manifest": source.manifest.model_dump(mode="json"),
        "records": {key: records[key] for key in source.inputs if key in records},
        "judging_strata": {
            "original_generation_judging": list(source.judgments),
            "separately_recovered_judging": [key for key in source.pending_ids if key in saved],
        },
        **({"evaluator_failures": failures} if continuing else {}),
        "counts": counts, "target_calls": 0, "judge_calls": 0, "old_grid_promoted": False,
    }


def _report_views(source, records: dict, completion: dict, *, joined: bool,
                  completion_path: Path | None = None) -> dict:
    """Derive read-only metric scopes; the original generation manifest is unchanged."""
    from experiments import human_audit
    from experiments.local_campaign.vllm_stability_phase6 import _sha256_json
    from ura.runner import _portable_attempt_dump, _write_jsonl_models, realized_identity_summary

    manifest = source.manifest.model_dump(mode="json")
    original_root = Path(source.state["result_root"])
    manifest_path = recovery._one_file(original_root, "*.manifest.json", label="RR generation manifest")
    persisted = [*source.source["files"], completion["launch"], completion["invocation"],
                 *completion.get("evaluator_failures", [])]
    if completion["checkpoint"] is not None:
        persisted.append(completion["checkpoint"])
    artifacts = {f"source_{index:03}": Path(item["path"]) for index, item in enumerate(persisted)}
    artifact_descriptors = {f"source_{index:03}": {"file": Path(item["path"]).name,
        "sha256": item["sha256"], "bytes": item["bytes"]} for index, item in enumerate(persisted)}
    checkpoint_root = Path(completion["launch"]["path"]).parent
    completion_path = completion_path or checkpoint_root / "completion.json"
    artifacts["scoring_completion"] = completion_path
    completion_descriptor = _descriptor(completion_path, label="RR scoring completion")
    artifact_descriptors["scoring_completion"] = {"file": completion_path.name,
        "sha256": completion_descriptor["sha256"], "bytes": completion_descriptor["bytes"]}
    original_ids = list(source.judgments)
    failures = (recovery.load_failures(checkpoint_root / "evaluator-failures", source)
                if completion["schema"] == "ura-rr-retained-judging-completion/2" else {})
    recovered_ids = [key for key in source.pending_ids if key in records]
    if (set(records) | set(failures) != set(source.inputs) or set(records) & set(failures)
            or set(original_ids) & set(recovered_ids)):
        raise ValueError("RR scoring report cannot omit or overlap a judging partition")
    scopes = {"all-retained-inputs": list(source.inputs),
              "original-judgments": original_ids, "recovered-judgments": recovered_ids}
    cells, joins = {}, None
    for name, ids in scopes.items():
        if name != "all-retained-inputs" and not ids:
            continue
        runner = recovery._reader_runner(source.manifest, recovery.source_cascade(source.manifest))

        def no_append(_record):
            raise RuntimeError("RR analysis cannot append a new judgment")

        for key in ids:
            point, attempt = source.inputs[key]
            if key in failures:
                runner.attempts.append(attempt)
                runner.responses.append(runner._restore_response(
                    attempt, source.responses[key], source.manifest.run_id,
                ))
                continue
            runner._execute_or_restore(point, attempt, source.manifest.run_id, records[key], no_append)
        # This is aggregation context only. No manifest is built, saved or
        # rewritten, and the old run ID remains the generation foreign key.
        runner._last_manifest = source.manifest
        with tempfile.TemporaryDirectory(prefix="ura-rr-scoring-join-") as scratch:
            directory = Path(scratch)
            runner.save_trails(directory / "trails.jsonl")
            trails = [json.loads(line) for line in (directory / "trails.jsonl").read_text().splitlines()]
            cell = {
                "run_id": source.manifest.run_id, "model": source.manifest.models[0],
                "manifest": manifest, "manifest_path": manifest_path, "complete_path": completion_path,
                "artifacts": artifacts, "artifact_descriptors": artifact_descriptors,
                "attempts": {attempt.id: _portable_attempt_dump(attempt) for attempt in runner.attempts},
                # Input stamps come from the exactly reconstructed corpus, not
                # from whether a classifier produced a usable safety verdict.
                "input_metadata": {source.inputs[key][1].id: {
                    "source": source.inputs[key][0].source,
                    "risk_category": source.inputs[key][0].risk_category.value,
                    "expected_behavior": source.inputs[key][0].expected_behavior,
                } for key in ids},
                "responses": {row.attempt_id: row.model_dump(mode="json") for row in runner.responses},
                "judgments": [row.model_dump(mode="json") for row in runner.judgments], "trails": trails,
                "aggregate_results": [], "source_identity_validated": True,
                "realized_identities": realized_identity_summary(runner.responses, trails),
                "integrity_mode": "source_validated_generation_separate_completed_scoring",
                "grid_audit": {"mode": "original_failed_grid_not_promoted", "old_grid_promoted": False},
            }
            if failures:
                cell["evaluator_coverage"] = {
                    "retained_responses": len(source.responses), "judgments": len(records),
                    "evaluator_failures": len(failures), "judging_complete": False,
                    "failed_attempt_ids": sorted(failures), "failure_policy": recovery.FAILURE_POLICY,
                    "failed_outputs_are_safety_verdicts": False,
                }
            if name != "all-retained-inputs":
                cell["aggregate_results"] = [row.model_dump(mode="json") for row in runner.aggregate(
                    runner.judgments, source.manifest.config["run"]["group_keys"],
                )]
                cell["post_factum_judging"] = {
                    "scope": name, "generation_run_id": source.manifest.run_id,
                    "generation_revision": source.source["generation_revision"],
                    "judging_revision": (source.source["generation_revision"] if name == "original-judgments"
                                         else completion["judging_revision"]),
                    "scoring_completion": _descriptor(completion_path, label="RR scoring completion"),
                    "partition_attempt_ids_sha256": _sha256_json(sorted(ids)),
                    "partition_attempts": len(ids), "old_grid_promoted": False,
                    "partition_is_random_sample": False, "cross_partition_pooling_permitted": False,
                    **({"evaluator_coverage": cell["evaluator_coverage"]} if failures else {}),
                }
            elif joined:
                # The ordinary lossless audit join receives ONLY actual
                # judgments. Full response coverage remains in input_cell;
                # evaluator failures never become synthetic safety labels.
                runner.attempts = [item for item in runner.attempts if item.id in records]
                runner.responses = [item for item in runner.responses if item.attempt_id in records]
                runner.save_attempts(directory / "attempts.jsonl")
                runner.save_responses(directory / "responses.jsonl")
                _write_jsonl_models(runner.judgments, directory / "judgments.jsonl")
                roles = {role: [directory / f"{role}.jsonl"]
                         for role in ("attempts", "responses", "judgments", "trails")}
                original_inventory = human_audit._validated_artifacts

                def scoped_inventory(requested):
                    if requested != directory:
                        raise ValueError("RR scoring join changed its validated scope")
                    return roles, [{**cell,
                                    "attempts": {key: row for key, row in cell["attempts"].items() if key in records},
                                    "responses": {key: row for key, row in cell["responses"].items() if key in records}}]

                try:
                    # All records were strictly restored above and in
                    # _completed_view. Reuse only the existing lossless join;
                    # no original grid status or validator is substituted.
                    human_audit._validated_artifacts = scoped_inventory
                    joins = (human_audit._joined_artifacts(directory, frame="common") if records else
                             ({}, {}, {}, {"policy_evaluable_samples": 0,
                                           "common_ineligible_evaluable_rows_excluded": 0}))
                finally:
                    human_audit._validated_artifacts = original_inventory
                for meta in joins[1].values():
                    meta["judging_execution_revision"] = (
                        source.source["generation_revision"] if meta["attempt_id"] in source.judgments
                        else completion["judging_revision"]
                    )
                joins[3]["old_grid_promoted"] = False
                joins[3]["separate_judging_partitions"] = {
                    "original_judgments": len(original_ids), "recovered_judgments": len(recovered_ids),
                }
                if failures:
                    joins[3]["evaluator_coverage"] = cell["evaluator_coverage"]
            cells[name] = cell
    return {"input_cell": cells.pop("all-retained-inputs"), "metric_cells": cells, "joined": joins}


_WORKER = '''
import json, sys, tempfile
from pathlib import Path
from experiments.local_campaign import rr_retained_judging as recovery
from experiments.local_campaign.vllm_stability_phase6 import _descriptor, _load_json, _validate_descriptor
from ura.runner import Runner
request = json.load(sys.stdin)
exec(request["reader_source"], globals())
result = _completed_view(Path(request["completion"]), work=Path(request["work"]), project=Path.cwd())
if request.get("report_source"):
    exec(request["report_source"], globals())
    completion = _load_json(Path(request["completion"]), label="RR completed scoring")
    launch, source = recovery.load_launch(Path(completion["launch"]["path"]), completion["launch"]["sha256"],
                                          work=Path(request["work"]), project=Path.cwd())
    result["report_views"] = _report_views(source, result["records"], completion, joined=request["joined"])
def json_default(value):
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)
print(json.dumps(result, default=json_default, allow_nan=False))
'''


def load_completed(path: Path, *, work: Path, project: Path, reports: bool = False, joined: bool = False) -> dict:
    """Run the strict record reader against the actual retained scoring source."""
    path = path.resolve(strict=True)
    bound = _descriptor(path, label="RR scoring completion")
    completion = _load_json(path, label="RR scoring completion")
    revision = completion["judging_revision"]
    commit = revision["expected_commit"]
    if (revision["observed_commit"] != commit
            or retained._git(project, "rev-parse", f"{commit}^{{tree}}") != revision["head_tree"]):
        raise ValueError("RR scoring analysis source identity changed")
    retained._git(project, "merge-base", "--is-ancestor", commit,
                  retained._git(project, "rev-parse", "HEAD"))
    with tempfile.TemporaryDirectory(prefix="ura-rr-scoring-reader-") as scratch:
        checkout = Path(scratch).resolve() / "source"
        installed = False
        try:
            retained._git(project, "worktree", "add", "--quiet", "--detach", str(checkout), commit)
            installed = True
            env = dict(os.environ, PYTHONPATH=str(checkout / "src"), PYTHONDONTWRITEBYTECODE="1")
            for key in list(env):
                if key.endswith(("_API_KEY", "_TOKEN")):
                    env.pop(key)
            request = {"completion": str(path), "work": str(work),
                       "reader_source": inspect.getsource(_completed_view)}
            if reports or joined:
                request.update(report_source=inspect.getsource(_report_views), joined=joined)
            process = subprocess.run(
                [sys.executable, "-c", _WORKER], cwd=checkout, env=env,
                input=json.dumps(request), capture_output=True, text=True,
                encoding="utf-8", timeout=600, check=False,
            )
            if process.returncode:
                raise ValueError("RR scoring exact-source reader failed: " + process.stderr[-4000:])
            view = retained._decode_validator_ipc(process.stdout)
            if (view.get("source_completion") != bound
                    or view.get("launch", {}).get("judging_revision") != revision):
                raise ValueError("RR scoring reader changed its completion/source binding")
            _validate_descriptor(bound, label="RR scoring completion after read")
            if reports or joined:
                for cell in [view["report_views"]["input_cell"], *view["report_views"]["metric_cells"].values()]:
                    retained._restore_cell_paths(cell)
            return view
        finally:
            if installed:
                retained._git(project, "worktree", "remove", str(checkout))
