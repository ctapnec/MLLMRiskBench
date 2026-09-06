"""Recover RR scoring with separate judging provenance and no target execution.

The original run ID remains a foreign key to its generation. A recovery never
rewrites that run's manifest, checkpoints, failed grid or completion state.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
from typing import Any

from experiments import figure_results, level1_evidence, retained_artifact_reader, run_matrix
from experiments.local_campaign import rr_parallel_campaign
from experiments.local_campaign.failed_output_recovery_phase6 import _durable_outcomes, _selected_rows
from experiments.local_campaign.vllm_stability_phase6 import (
    _descriptor, _load_json, _one_file, _option, _validate_descriptor,
)
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import Attempt, DataPoint, RunManifest
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.runner import GlobalCallBudget, Runner, _component_config, _portable_attempt_dump
from ura.targets.base import BaseTarget


class _NoTarget(BaseTarget):
    def __init__(self, manifest: RunManifest):
        self.name = manifest.models[0]
        self.modality_support = tuple(manifest.config["components"]["target"]["modality_support"])

    def generate(self, *_args, **_kwargs):
        raise RuntimeError("retained judging cannot execute a target")


@dataclass
class RetainedUnit:
    manifest: RunManifest
    state: dict[str, Any]
    source: dict[str, Any]
    runner: Runner
    inputs: dict[str, tuple[DataPoint, Attempt]]
    responses: dict[str, dict]
    judgments: dict[str, dict]

    @property
    def pending_ids(self) -> list[str]:
        return [key for key in self.inputs if key not in self.judgments]

    def validate_unchanged(self) -> None:
        for descriptor in self.source["files"]:
            _validate_descriptor(descriptor, label="retained judging source")


def _original_identity(manifest: RunManifest, path: Path, project: Path) -> dict:
    revision = figure_results._validate_source_identity(manifest, path)
    commit = revision["expected_commit"]
    git = retained_artifact_reader._git
    if revision["observed_commit"] != commit:
        raise ValueError("retained judging source commit changed")
    git(project, "merge-base", "--is-ancestor", commit, git(project, "rev-parse", "HEAD"))
    if git(project, "rev-parse", f"{commit}^{{tree}}") != revision["head_tree"]:
        raise ValueError("retained judging source tree changed")
    archive = subprocess.check_output([
        "git", "-C", str(project), "archive", "--format=tar", commit, "src/ura",
    ])
    digest = hashlib.sha256()
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        members = sorted((item for item in bundle.getmembers()
                          if item.isfile() and item.name.endswith(".py")), key=lambda item: item.name)
        for item in members:
            raw = bundle.extractfile(item).read()
            relative = item.name.removeprefix("src/ura/")
            digest.update(relative.encode() + b"\0" + str(len(raw)).encode() + b"\0"
                          + hashlib.sha256(raw).hexdigest().encode() + b"\n")
    driver = subprocess.check_output([
        "git", "-C", str(project), "show", commit + ":experiments/run_matrix.py",
    ])
    if (digest.hexdigest() != revision["harness_source_sha256"]
            or hashlib.sha256(driver).hexdigest() != revision["driver_source_sha256"]):
        raise ValueError("retained judging source does not match its actual Git bytes")
    config = manifest.config
    identity = {key: config[key] for key in (
        "budget", "components", "media_validation", "harness_source", "source_policy_inventory",
        "source_policy_inventory_sha256", "source_metric_plan", "supplementary_metric_policy",
        "attacker_input_plan", "attacker_input_plan_sha256",
    )}
    identity.update({key: getattr(manifest, key) for key in (
        "code_version", "schema_version", "dataset_hashes", "seeds", "models", "adapters", "judges", "env",
    )})
    identity["run_config"] = config["run"]
    if Runner._run_id(identity) != manifest.run_id:
        raise ValueError("retained judging generation run identity changed")
    return revision


def source_cascade(manifest: RunManifest, *, model_runtime=None) -> JudgeCascade:
    saved = manifest.config["components"]["judge_cascade"]
    stages = saved.get("stages", [])
    if manifest.judges != ["rules", "guardrail"] or len(stages) != 2:
        raise ValueError("RR retained judging requires its original rules/guardrail cascade")
    rule = RuleJudge()
    rule.escalate_below = stages[0]["escalate_below"]
    guard = stages[1]
    cascade = JudgeCascade([rule, GuardrailJudge(
        model=guard["model_id"], revision=guard["revision"], device=guard["device"],
        escalate_below=guard["escalate_below"], max_new_tokens=guard["max_new_tokens"],
        model_runtime=model_runtime,
    )])
    if _component_config(cascade) != saved:
        raise ValueError("RR retained judging changed the saved scoring configuration")
    return cascade


def _reader_runner(manifest: RunManifest, cascade: JudgeCascade, *, call_budget=None) -> Runner:
    run = manifest.config["run"]
    return Runner(
        ReplayAttacker(), _NoTarget(manifest), cascade,
        AttackBudget(**manifest.config["budget"]), manifest.seeds, call_budget=call_budget,
        expected_target_identity=run["expected_target_identity"],
        approximate_common_metrics=run["approximate_common_metrics"], execution_stage="judgments",
    )


def score_pending(source: RetainedUnit, cascade: JudgeCascade, *, checkpoint: Path) -> Runner:
    """Append only missing judgments; run IDs refer to the original generation.

    The caller binds this separate checkpoint to its actual judging revision.
    No Runner manifest or grid is constructed or promoted by this function.
    Original transport budgets were validated by load_source; local Guard does
    not use the Runner's hosted-transport budget, and no target can be called.
    """
    if _component_config(cascade) != source.manifest.config["components"]["judge_cascade"]:
        raise ValueError("RR retained judging changed the saved scoring configuration")
    if checkpoint.resolve().is_relative_to(Path(source.state["result_root"]).resolve()):
        raise ValueError("new judging cannot write inside the original generation root")
    if (set(source.inputs) != set(source.responses) or set(source.judgments) - set(source.inputs)
            or len(source.inputs) != source.state["selected_records"]):
        raise ValueError("RR judging source selection is no longer complete")
    source.validate_unchanged()
    saved = Runner.load_checkpoint(checkpoint, expected_run_id=source.manifest.run_id)
    if set(saved) - set(source.pending_ids):
        raise ValueError("RR judging checkpoint adds or repeats an original completed judgment")
    runner = _reader_runner(source.manifest, cascade)
    # Validate every saved new record before making another classifier call.
    for key, record in saved.items():
        point, attempt = source.inputs[key]
        if record["response"] != source.responses[key]["response"]:
            raise ValueError("RR judging checkpoint changed the original target response")
        runner._restore_record(point, attempt, record, source.manifest.run_id)
    for key, (point, attempt) in source.inputs.items():
        record = source.judgments.get(key, saved.get(key))
        runner._execute_or_restore(
            point, attempt, source.manifest.run_id, record,
            lambda value: Runner.append_checkpoint(checkpoint, value),
            response_record=source.responses[key],
        )
    source.validate_unchanged()
    if len(runner.judgments) != len(source.responses):
        raise ValueError("RR judging did not cover the exact retained response set")
    return runner


def load_source(state_path: Path, *, work: Path, project: Path) -> RetainedUnit:
    """Strictly reconstruct a terminal response-complete, partly judged RR unit."""
    state_path = state_path.resolve(strict=True)
    state = _load_json(state_path, label="RR retained judging state")
    control = state_path.parent.parent.parent
    unit = state_path.parent.name
    root = work / "runs/thesis/runner" / unit / control.name
    terminal_path = control / f"{unit}.terminal.json"
    terminal = _load_json(terminal_path, label="RR retained judging source terminal")
    if (state_path != control / "units" / unit / "state.json"
            or control.parent != work / "runs/engineering"
            or state.get("schema") != rr_parallel_campaign.STATE_SCHEMA
            or state.get("unit_id") != unit or state.get("result_root") != str(root)
            or root.is_symlink() or root.resolve(strict=True) != root
            or terminal.get("result") is not None or not terminal.get("failure")
            or list(root.glob("*.grid.lock")) or list(root.glob("*.cell.lock"))
            or list(root.glob("*.complete.json"))):
        raise ValueError("RR retained judging lacks its exact terminal failed source")
    files = [_descriptor(path, label="RR retained judging source") for path in
             [state_path, terminal_path, *sorted(path for path in root.iterdir() if path.is_file())]]
    manifest_path = _one_file(root, "*.manifest.json", label="RR retained judging manifest")
    manifest = RunManifest.model_validate(_load_json(manifest_path, label="RR retained manifest"), strict=True)
    revision = _original_identity(manifest, manifest_path, project)
    argv = state["runner_argv"]
    run = manifest.config["run"]
    if (manifest.adapters != ["replay"] or manifest.seeds != [0]
            or manifest.config["budget"] != {"max_queries": 1, "max_turns": 1, "seed": 0}
            or _option(argv, "--local") != rr_parallel_campaign.prior.RR_SPEC
            or run.get("defense") != "none" or run.get("dry_run") is not False):
        raise ValueError("RR retained judging cannot replace another generation treatment")
    grid_path = _one_file(root, "*.grid.json", label="RR retained judging grid")
    grid = _load_json(grid_path, label="RR retained judging grid")
    plan_path = _one_file(root, "*.eligibility.json", label="RR retained judging eligibility")
    artifact = level1_evidence._plan_artifact(plan_path)
    if (grid_path.name != grid["grid_id"] + ".grid.json"
            or level1_evidence._grid_id(grid) != grid["grid_id"]
            or run["grid_id"] != grid["grid_id"]
            or not level1_evidence._plan_descriptor_matches(grid["request"]["eligibility_plan"], artifact)):
        raise ValueError("RR retained judging source request/eligibility changed")
    level1_evidence._validate_grid_plan_bindings(grid["request"], artifact[0])
    level1_evidence._validate_grid_model_acquisition(grid["request"], evidence_root=root)
    response_path = _one_file(root, "*.responses.checkpoint.jsonl", label="RR retained responses")
    judgment_paths = [path for path in root.glob("*.checkpoint.jsonl") if path != response_path]
    if len(judgment_paths) != 1:
        raise ValueError("RR retained judging needs its exact partial judgment checkpoint")
    responses = Runner.load_response_checkpoint(response_path, expected_run_id=manifest.run_id)
    judgments = Runner.load_checkpoint(judgment_paths[0], expected_run_id=manifest.run_id)
    ledger = _load_json(_one_file(root, "*.budget.json", label="RR original budget"), label="RR original budget")
    run_matrix._response_checkpoint_budget_snapshots(root, ledger)
    run_matrix._checkpoint_budget_snapshots(root, ledger)
    # Reuse the final/checkpoint agreement check; partial exports are not a
    # license to regenerate their already-retained unjudged target responses.
    _durable_outcomes(root)
    attacker = ReplayAttacker()
    budget = AttackBudget(**manifest.config["budget"])
    runner = _reader_runner(manifest, source_cascade(manifest),
                            call_budget=GlobalCallBudget(budget_id=ledger["budget_id"]))
    corpora, _audit = _selected_rows(argv)
    corpus = [point for rows in corpora.values() for point in rows]
    contracts = runner._plan_attacker_input_contracts(corpus)
    prepared, media_hashes = runner._prepare_corpus(corpus)
    if (runner._dataset_hashes(prepared, media_hashes) != manifest.dataset_hashes
            or runner._attacker_input_plan_payload(contracts) != manifest.config["attacker_input_plan"]):
        raise ValueError("RR retained judging selected inputs or media changed")
    inputs = {}
    for point in prepared:
        generated = list(attacker.generate(point, budget))
        if len(generated) != 1:
            raise ValueError("RR retained judging selection is not one replay attempt per input")
        expected = runner._prepare_attempt(
            generated[0], dp=point, seed=0, logical_turn=0, run_id=manifest.run_id,
            corpus_hash=manifest.dataset_hashes["corpus"], stateful=False,
            input_contract=contracts[(point.id, 0)],
        )
        record = responses[expected.id]
        if (_portable_attempt_dump(expected) != record["attempt"]
                or runner._restore_response(expected, record, manifest.run_id).model_dump(mode="json") != record["response"]):
            raise ValueError("RR retained response is not its exact original input/output")
        if expected.id in judgments:
            if judgments[expected.id]["response"] != record["response"]:
                raise ValueError("RR original judgment changed its checkpointed target response")
            runner._restore_record(point, expected, judgments[expected.id], manifest.run_id)
        inputs[expected.id] = (point, expected)
    if (set(inputs) != set(responses) or set(judgments) - set(inputs)
            or len(inputs) != state["selected_records"] or len(judgments) >= len(inputs)):
        raise ValueError("RR retained judging requires all responses and an incomplete judgment subset")
    result = RetainedUnit(manifest, state, {
        "state": _descriptor(state_path, label="RR source state"), "files": files,
        "generation_revision": revision, "generation_run_id": manifest.run_id,
        "responses": len(responses), "existing_judgments": len(judgments),
        "pending_judgments": len(responses) - len(judgments), "old_grid_promoted": False,
    }, runner, inputs, responses, judgments)
    result.validate_unchanged()
    return result
