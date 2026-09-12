"""Resume local assessment of prepared saved API answers, with no target calls."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess

from experiments import retained_native_judge_prepare as sources
from experiments.hosted_campaign_budget import load_bound_json
from experiments.retained_response_judge_execute import _exclusive_lock, _write_atomic, _write_new
from ura.artifact_checks import artifact_verification_cli
from ura.data_models import Judgment
from ura.judges.base import JudgeCascade, JudgeCascadeDecisionError
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.model_acquisition import hub_requirement
from ura.model_acquisition_runtime import (
    ModelRequirementSet, admit_managed_model_runtime, build_runtime_selection,
    validate_public_selection_descriptor,
)
from ura.runner import ExternalCallFailure, Runner, _component_config, _sha256_json

FAILURE_SCHEMA = "ura-retained-native-judge-failure/1"


def original_judgments(source, reader, inputs, responses):
    """Read original verdicts once; do not relabel them as newly scored work."""
    directory = Path(source["out"])
    observed = {}
    for path in sorted(directory.glob("*.checkpoint.jsonl")):
        if path.name.endswith(".responses.checkpoint.jsonl"):
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            record = json.loads(line)
            key = record["attempt"]["id"]
            if key not in inputs or record["response"] != responses[key]["response"]:
                raise ValueError("Original judgment changed its saved answer")
            reader._restore_record(*inputs[key], record, source["run_id"])
            prior = observed.get(key)
            if prior is not None and prior[0] != record:
                raise ValueError("Original judgment checkpoints disagree")
            observed[key] = (record, f"{path}:{number}")
    for manifest in directory.glob("*.manifest.json"):
        path = manifest.with_name(manifest.name.removesuffix(".manifest.json")+".jsonl")
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            value = json.loads(line)
            judgment = Judgment.model_validate(value)
            key = judgment.attempt_id
            if key not in inputs or judgment.run_id != source["run_id"]:
                raise ValueError("Original final judgment has no saved answer")
            if key in observed:
                if observed[key][0]["judgment"] != value:
                    raise ValueError("Original final judgment differs from its checkpoint")
            else:
                observed[key] = (dict(judgment=value, response=responses[key]["response"]), f"{path}:{number}")
    return observed


def source_runtime(source, *, verify_model_sha256=False):
    """Reuse the admitted judge bytes; full model hashing is explicitly opt-in."""
    directory = Path(source["out"])
    grid = sources.read(next(directory.glob("*.grid.json")))
    acquisition = grid["request"]["model_acquisition"]
    selected = validate_public_selection_descriptor(acquisition["selection"])
    selection = build_runtime_selection(ModelRequirementSet(tuple(
        hub_requirement(role, resource["repo_id"], resource["revision"])
        for resource in selected["resources"] for role in resource["roles"]
    ), tuple(selected["exceptions"])), input_bindings=selected["input_bindings"])
    if selection.selection_sha256 != selected["selection_sha256"]:
        raise ValueError("Saved judge runtime selection differs")
    argv = source["runner_argv"]
    evidence = acquisition["evidence"]
    return admit_managed_model_runtime(selection=selection,
        plan_path=directory/evidence["plan"]["file"], plan_sha256=evidence["plan"]["sha256"],
        receipt_path=directory/evidence["receipt"]["file"], receipt_sha256=evidence["receipt"]["sha256"],
        managed_store=argv[argv.index("--model-acquisition-store")+1],
        verify_model_sha256=verify_model_sha256)[0]


def source_cascade(condition, runtime):
    rule_config, guard_config = condition["stages"]
    rule = RuleJudge()
    rule.escalate_below = rule_config["escalate_below"]
    guard = GuardrailJudge(model=guard_config["model_id"], revision=guard_config["revision"],
        device=guard_config["device"], max_new_tokens=guard_config["max_new_tokens"],
        escalate_below=guard_config["escalate_below"], model_runtime=runtime)
    result = JudgeCascade([rule, guard])
    if _component_config(result) != condition:
        raise ValueError("Retained local judging changed the selected cascade")
    return result


def validate_failure(value, source, inputs, responses):
    key = value["attempt_id"]
    if (value.get("schema") != FAILURE_SCHEMA or key not in inputs
            or value["generation_run_id"] != source["run_id"]
            or value["response"] != responses[key]["response"]):
        raise ValueError("Unscored assessment changed its saved answer")
    trail = [Judgment.model_validate(row) for row in value["trail"]]
    if (len(trail) != len(source["judge_cascade"]["stages"])
            or [row.judge for row in trail] != ["rules", "guardrail"]
            or any(row.attempt_id != key or row.run_id not in {None, source["run_id"]} for row in trail)
            or trail[-1].raw.get("parsed") is not False
            or trail[-1].raw.get("guardrail_queried") is not True):
        raise ValueError("Unscored assessment is not a retained unparsed guard output")
    return key


class CascadeCache:
    """Keep one unchanged judge resident across source jobs in this execution."""
    def __init__(self):
        self.condition, self.cascade = None, None

    def get(self, source, *, verify_model_sha256=False):
        if self.condition != source["judge_cascade"]:
            self.close()
            self.cascade = source_cascade(source["judge_cascade"], source_runtime(source,
                verify_model_sha256=verify_model_sha256))
            self.condition = source["judge_cascade"]
        return self.cascade

    def close(self):
        if self.cascade is not None:
            self.cascade.stages[1].close()
        self.condition, self.cascade = None, None


def score_unit(source, reader, inputs, responses, *, out, revision, publication=None,
               runtime_factory=source_runtime, verify_model_sha256=False, cascade_cache=None):
    if out.is_symlink() or out.resolve().is_relative_to(Path(source["out"]).resolve()):
        raise ValueError("New judging must not write inside its original generation directory")
    if set(inputs) != set(responses) or len(inputs) != source["assigned"]:
        raise ValueError("Retained scoring selection is incomplete")
    originals = original_judgments(source, reader, inputs, responses)
    out.mkdir(mode=0o700, exist_ok=True)
    checkpoint = out/"judgments.checkpoint.jsonl"
    saved = Runner.load_checkpoint(checkpoint, expected_run_id=source["run_id"])
    failures = {}
    for path in (out/"evaluator-failures").glob("*.json"):
        value = sources.read(path)
        key = validate_failure(value, source, inputs, responses)
        if key in failures:
            raise ValueError("Duplicate unscored assessment")
        failures[key] = (value, str(path))
    if ((set(saved) | set(failures)) & set(originals) or set(saved) & set(failures)
            or set(saved) - set(inputs)):
        raise ValueError("Judging continuation repeats or adds an output")
    # Check every retained record before the first new classifier call.
    for key, record in saved.items():
        if record["response"] != responses[key]["response"]:
            raise ValueError("Judging checkpoint changed its saved answer")
        reader._restore_record(*inputs[key], record, source["run_id"])
    lines = len(checkpoint.read_text().splitlines()) if checkpoint.exists() else 0
    if publication is not None:
        for record, reference in originals.values():
            publication.accept(source, record, reference, source["generation_project_revision"]["expected_commit"])
        for number, record in enumerate(saved.values(), 1):
            publication.accept(source, record, f"{checkpoint}:{number}", revision)
        for value, reference in failures.values():
            publication.accept(source, value, reference, revision, invalid=True)
    pending = [key for key in inputs if key not in originals and key not in saved and key not in failures]
    cascade = None
    newly_scored = 0
    try:
        if pending:
            cascade = (cascade_cache.get(source, verify_model_sha256=verify_model_sha256)
                if cascade_cache is not None else source_cascade(source["judge_cascade"], runtime_factory(source,
                    verify_model_sha256=verify_model_sha256)))
            reader.judge_cascade = cascade
        def checkpointed(record):
            nonlocal lines
            Runner.append_checkpoint(checkpoint, record)
            lines += 1
            saved[record["attempt"]["id"]] = record
            if publication is not None:
                publication.accept(source, record, f"{checkpoint}:{lines}", revision)
        for key in pending:
            try:
                reader._execute_or_restore(*inputs[key], source["run_id"], None, checkpointed,
                    response_record=responses[key])
                newly_scored += 1
            except ExternalCallFailure as exc:
                if exc.phase != "judge_call" or not isinstance(exc.__cause__, JudgeCascadeDecisionError):
                    raise
                value = dict(schema=FAILURE_SCHEMA, attempt_id=key, generation_run_id=source["run_id"],
                    response=responses[key]["response"], trail=[row.model_dump(mode="json") for row in exc.__cause__.trail])
                validate_failure(value, source, inputs, responses)
                failure_path = out/"evaluator-failures"/(_sha256_json(key)+".json")
                failure_path.parent.mkdir(exist_ok=True)
                _write_new(failure_path, value)
                failures[key] = (value, str(failure_path))
                if publication is not None:
                    publication.accept(source, value, str(failure_path), revision, invalid=True)
            _write_atomic(out/"progress.json", dict(stage="judging_saved_outputs", assigned=len(inputs),
                existing=len(originals), completed=len(saved), invalid=len(failures), target_calls=0, hosted_calls=0))
    finally:
        if cascade is not None and cascade_cache is None:
            cascade.stages[1].close()
    if len(originals)+len(saved)+len(failures) != len(inputs):
        raise ValueError("Native judging did not cover the exact selected outputs")
    result = dict(status="complete", source=source, run_id=source["run_id"], judging_revision=revision,
        existing_judgments=len(originals), completed_judgments=len(saved), invalid_judgments=len(failures),
        newly_scored_this_execution=newly_scored, target_calls=0, hosted_calls=0,
        checkpoint=str(checkpoint), original_artifacts_changed=False)
    _write_atomic(out/"result.json", result)
    return result


def execute(*, preparation, preparation_sha256, out, revision, workspace_id="", console_db=None,
            verify_model_sha256=False):
    if bool(workspace_id) != bool(console_db):
        raise ValueError("Supply both campaign owner and console database, or neither")
    prepared, descriptor = load_bound_json(preparation, preparation_sha256)
    if prepared["status"] not in {"prepared", "preparation_incomplete"} or not prepared["units"]:
        raise ValueError("Select a native judging source preparation with saved outputs")
    if not out.is_absolute() or out.parent.resolve(strict=True) != out.parent or out.is_symlink():
        raise ValueError("Native judging needs a resolved execution directory")
    if any(out.resolve().is_relative_to(Path(s["out"]).resolve()) for s in prepared["units"]):
        raise ValueError("Execution directory overlaps original generations")
    out.mkdir(mode=0o700, exist_ok=True)
    selection = dict(preparation=dict(path=str(preparation.resolve()), **descriptor),
        scoring_revision=revision, verify_model_sha256=verify_model_sha256)
    with _exclusive_lock(out), ExitStack() as stack:
        identity = out/"execution.json"
        if identity.exists():
            if sources.read(identity) != selection:
                raise ValueError("Resume must preserve its preparation and scoring revision")
        else:
            if any(path.name != "execution.lock" for path in out.iterdir()):
                raise ValueError("New native judging needs an unused execution directory")
            _write_new(identity, selection)
        publication = None
        cascade_cache = CascadeCache()
        stack.callback(cascade_cache.close)
        if workspace_id:
            from experiments.rig_web_app.workspace_native_judging import NativeJudgmentPublication
            publication = NativeJudgmentPublication(database=console_db, campaign_id=workspace_id, root=out)
            stack.callback(publication.close)
        completed, errors = [], []
        for number, expected in enumerate(prepared["units"], 1):
            unit = out/f"unit-{number:04d}"
            try:
                # Only reconstruct this explicitly selected job, once per execution.
                for entry in expected["files"]:
                    if sources.metadata(Path(entry["path"])) != entry:
                        raise ValueError("Prepared generation source changed")
                source, reader, inputs, responses = sources.load_program_job(Path(expected["program"]), expected["job"])
                if source != expected:
                    raise ValueError("Prepared source condition changed")
                completed.append(score_unit(source, reader, inputs, responses, out=unit, revision=revision,
                    publication=publication, verify_model_sha256=verify_model_sha256, cascade_cache=cascade_cache))
            except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
                unit.mkdir(mode=0o700, exist_ok=True)
                _write_atomic(unit/"error.json", dict(error_type=type(exc).__name__, message=str(exc)[:2000]))
                errors.append(dict(job=expected["job"], unit=str(unit), error_type=type(exc).__name__))
                # Keep completed checkpoints. Do not repeat one infrastructure
                # failure across every queued source/model load.
                break
        result = dict(status="continuation_required" if errors or prepared["failed"] else "complete",
            units=completed, errors=errors, unprepared_sources=prepared["failed"],
            target_calls=0, hosted_calls=0, original_artifacts_changed=False,
            completed_judgments=sum(item["completed_judgments"] for item in completed),
            invalid_judgments=sum(item["invalid_judgments"] for item in completed))
        _write_atomic(out/"result.json", result)
        return result


@artifact_verification_cli
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preparation", type=Path, required=True)
    parser.add_argument("--preparation-sha256", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workspace-id", default=os.environ.get("URA_CAMPAIGN_WORKSPACE_ID", ""))
    parser.add_argument("--console-db", type=Path, default=os.environ.get("URA_CAMPAIGN_CONSOLE_DB"))
    parser.add_argument("--verify-artifact-sha256", action="store_true")
    parser.add_argument("--verify-model-sha256", action="store_true")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parents[1]
    if subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"], text=True).strip():
        raise ValueError("Native judging must record a clean scoring checkout")
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    result = execute(preparation=args.preparation, preparation_sha256=args.preparation_sha256,
        out=args.out, revision=revision, workspace_id=args.workspace_id, console_db=args.console_db,
        verify_model_sha256=args.verify_model_sha256)
    print(json.dumps({key:value for key,value in result.items() if key != "units"}))
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
