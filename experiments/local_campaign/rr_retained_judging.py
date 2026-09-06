"""Recover RR scoring with separate judging provenance and no target execution.

The original run ID remains a foreign key to its generation. A recovery never
rewrites that run's manifest, checkpoints, failed grid or completion state.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time
from typing import Any

from experiments import figure_results, level1_evidence, retained_artifact_reader, run_matrix
from experiments.local_campaign import rr_parallel_campaign
from experiments.local_campaign.console_events import finish_child_controller, start_child_controller
from experiments.local_campaign.failed_output_recovery_phase6 import _durable_outcomes, _selected_rows
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json, _descriptor, _load_json, _one_file, _option, _utc_now, _validate_descriptor,
)
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import Attempt, DataPoint, RunManifest
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.model_acquisition import hub_requirement
from ura.model_acquisition_runtime import (
    ModelRequirementSet, admit_managed_model_runtime, build_runtime_selection,
    validate_public_selection_descriptor,
)
from ura.project_revision import load_project_revision_file, project_revision_binding
from ura.runner import GlobalCallBudget, Runner, _component_config, _portable_attempt_dump
from ura.targets.base import BaseTarget

SCHEMA = "ura-rr-retained-judging/1"
COMPLETION_SCHEMA = "ura-rr-retained-judging-completion/1"


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


def _revision(path: Path, digest: str, project: Path) -> dict:
    receipt, descriptor = load_project_revision_file(
        path, digest, project / "experiments/run_matrix.py", recheck_checkout=True,
    )
    return project_revision_binding(receipt, descriptor)


def _runtime(source: RetainedUnit):
    root = Path(source.state["result_root"])
    grid = _load_json(_one_file(root, "*.grid.json", label="RR grid"), label="RR grid")
    selection = validate_public_selection_descriptor(grid["request"]["model_acquisition"]["selection"])
    runtime_selection = build_runtime_selection(
        ModelRequirementSet(tuple(
            hub_requirement(role, resource["repo_id"], resource["revision"])
            for resource in selection["resources"] for role in resource["roles"]
        ), tuple(selection["exceptions"])), input_bindings=selection["input_bindings"],
    )
    if runtime_selection.selection_sha256 != selection["selection_sha256"]:
        raise ValueError("RR retained judging runtime selection changed")
    argv = source.state["runner_argv"]
    return admit_managed_model_runtime(
        selection=runtime_selection,
        plan_path=_option(argv, "--model-acquisition-plan"),
        plan_sha256=_option(argv, "--model-acquisition-plan-sha256"),
        receipt_path=_option(argv, "--model-acquisition-receipt"),
        receipt_sha256=_option(argv, "--model-acquisition-receipt-sha256"),
        managed_store=_option(argv, "--model-acquisition-store"),
    )


def prepare(state_path: Path, *, work: Path, project: Path, out: Path,
            revision_path: Path, revision_sha256: str) -> dict:
    """Bind a new scoring execution without downloading or loading any model."""
    source = load_source(state_path, work=work, project=project)
    revision = _revision(revision_path, revision_sha256, project)
    _managed, runtime = _runtime(source)
    if (out != out.resolve() or out.parent != work / "runs/engineering"
            or out.exists()):
        raise ValueError("RR judging needs a new resolved engineering directory")
    launch = {
        "schema": SCHEMA, "created_at_utc": _utc_now(), "source": source.source,
        "judging_revision_file": _descriptor(revision_path, label="judging revision"),
        "judging_revision": revision, "model_runtime": runtime,
        "judge_cascade": source.manifest.config["components"]["judge_cascade"],
        "pending_ids": source.pending_ids, "data_root": str(out),
        "physical_gpu": "0", "target_calls": 0, "hosted_calls": 0,
        "wall_seconds": 3600, "old_grid_promoted": False,
    }
    out.mkdir()
    _create_json(out / "launch.json", launch)
    return launch


def load_launch(path: Path, digest: str, *, work: Path, project: Path):
    launch = rr_parallel_campaign._bound(path, digest, "RR retained judging launch")
    root = Path(launch["data_root"])
    if (launch.get("schema") != SCHEMA or root != root.resolve(strict=True)
            or root.parent != work / "runs/engineering" or path != root / "launch.json"
            or launch.get("target_calls") != 0 or launch.get("hosted_calls") != 0
            or launch.get("physical_gpu") != "0" or launch.get("wall_seconds") != 3600
            or launch.get("old_grid_promoted") is not False):
        raise ValueError("RR retained judging execution contract changed")
    descriptor = launch["judging_revision_file"]
    revision = _revision(_validate_descriptor(descriptor, label="judging revision"),
                         descriptor["sha256"], project)
    source_path = _validate_descriptor(launch["source"]["state"], label="RR source state")
    source = load_source(source_path, work=work, project=project)
    if (source.source != launch["source"] or source.pending_ids != launch["pending_ids"]
            or revision != launch["judging_revision"]
            or launch["judge_cascade"] != source.manifest.config["components"]["judge_cascade"]):
        raise ValueError("RR retained judging source or scoring binding changed")
    return launch, source


def _require_free_gpu() -> None:
    if os.environ.get("CUDA_VISIBLE_DEVICES") != "0":
        raise ValueError("RR retained judging requires physical GPU0 visibility only")
    uuid = subprocess.check_output([
        "nvidia-smi", "--id=0", "--query-gpu=uuid", "--format=csv,noheader",
    ], text=True).strip()
    owners = subprocess.check_output([
        "nvidia-smi", "--query-compute-apps=gpu_uuid,pid", "--format=csv,noheader",
    ], text=True)
    if not uuid or any(line.split(",")[0].strip() == uuid for line in owners.splitlines()):
        raise RuntimeError("GPU0 is occupied; retained judging will not overlap a worker")


def execute(path: Path, digest: str, *, work: Path, project: Path, control: Path,
            tmux_socket: str, tmux_session: str) -> dict:
    """Use a fresh Jobs invocation, with a resumable separate scoring checkpoint."""
    import fcntl

    launch, source = load_launch(path, digest, work=work, project=project)
    root = Path(launch["data_root"])
    if (control != control.resolve() or control.parent != work / "runs/engineering"
            or control.exists()):
        raise ValueError("RR judging invocation needs a new engineering control root")
    if (root / "completion.json").exists():
        raise ValueError("RR retained judging already completed; no calls permitted")
    # Kernel-owned lock releases after process death; the checkpoint survives.
    with (root / "execution.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _require_free_gpu()
        runtime, runtime_descriptor = _runtime(source)
        if runtime_descriptor != launch["model_runtime"]:
            raise ValueError("RR retained judging managed resource binding changed")
        cascade = source_cascade(source.manifest, model_runtime=runtime)
        control.mkdir()
        start_child_controller(
            work_root=work, control_root=control, campaign_id=control.name,
            release_commit=launch["judging_revision"]["expected_commit"],
            evidence_class="post_factum_local_judging", hard_stop_hours=1,
            tmux_socket=tmux_socket, tmux_session=tmux_session,
        )
        _create_json(control / "invocation.json", {
            "launch": _descriptor(path, label="judging launch"), "started_at_utc": _utc_now(),
            "generation_run_id": source.manifest.run_id,
        })
        exit_code = 1

        def interrupt(signum, _frame):
            raise InterruptedError(f"RR retained judging interrupted by signal {signum}")

        previous = {sig: signal.signal(sig, interrupt)
                    for sig in (signal.SIGALRM, signal.SIGTERM, signal.SIGINT)}
        signal.alarm(launch["wall_seconds"])
        try:
            checkpoint = root / "judgments.checkpoint.jsonl"
            scored = score_pending(source, cascade, checkpoint=checkpoint)
            # Recheck the actual scoring source before publishing its completion.
            load_launch(path, digest, work=work, project=project)
            completion = {
                "schema": COMPLETION_SCHEMA, "completed_at_utc": _utc_now(),
                "launch": _descriptor(path, label="judging launch"),
                "checkpoint": _descriptor(checkpoint, label="new judgments"),
                "invocation": _descriptor(control / "invocation.json", label="judging invocation"),
                "generation_run_id": source.manifest.run_id,
                "judging_revision": launch["judging_revision"],
                "retained_responses": len(source.responses), "total_judgments": len(scored.judgments),
                "existing_judgments": len(source.judgments), "new_judgments": len(source.pending_ids),
                "target_calls": 0, "hosted_calls": 0, "old_grid_promoted": False,
            }
            _create_json(root / "completion.json", completion)
            exit_code = 0
            return completion
        except Exception as exc:
            _create_json(control / "error.json", {
                "error": type(exc).__name__, "message": str(exc),
                **run_matrix._failed_judge_decision(exc),
            })
            raise
        finally:
            signal.alarm(0)
            try:
                cascade.stages[1].close()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
                finish_child_controller(work_root=work, control_root=control, exit_code=exit_code)


def _boundary_child(process: dict, worker: Path) -> dict | None:
    if len(process["children"]) != 1:
        return None
    child = rr_parallel_campaign._process(process["children"][0])
    if (child and "--diagnostic-canary" in child["argv"]
            and "experiments.run_matrix" in child["argv"]
            and any(str(worker) + "/" in arg for arg in child["argv"])):
        return child
    return None


def at_canary_boundary(source: RetainedUnit, controller_pid: int, action) -> int:
    """Pause only the scheduler; let its canary exit before exclusive scoring."""
    worker = Path(source.source["state"]["path"]).parents[2]
    parent = _load_json(worker / "launch.json", label="RR source worker")["parent"]
    parent_path = _validate_descriptor(parent, label="RR source parent")
    original = _load_json(parent_path, label="RR source parent")
    controller = rr_parallel_campaign._process(controller_pid)
    if (not controller or original["workers"]["0"] != str(worker)
            or "experiments.local_campaign.rr_parallel_campaign" not in controller["argv"]
            or "worker" not in controller["argv"] or _option(controller["argv"], "--gpu") != "0"
            or _option(controller["argv"], "--launch") != str(parent_path)
            or _option(controller["argv"], "--launch-sha256") != parent["sha256"]):
        raise ValueError("PID does not own the original GPU0 RR worker")

    def interrupt(signum, _frame):
        raise InterruptedError(f"RR judging boundary interrupted by signal {signum}")

    previous = {sig: signal.signal(sig, interrupt) for sig in (signal.SIGTERM, signal.SIGINT)}
    paused = False
    try:
        deadline = time.monotonic() + 86400
        while time.monotonic() < deadline:
            current = rr_parallel_campaign._process(controller_pid)
            if not current or current["start_ticks"] != controller["start_ticks"]:
                raise RuntimeError("original RR scheduler terminated before the scoring handoff")
            child = _boundary_child(current, worker)
            if child:
                # Recheck after STOP to close the canary-to-measured launch race.
                os.kill(controller_pid, signal.SIGSTOP)
                paused = True
                stopped = rr_parallel_campaign._process(controller_pid)
                if stopped and _boundary_child(stopped, worker) == child:
                    break
                os.kill(controller_pid, signal.SIGCONT)
                paused = False
            time.sleep(60)
        else:
            raise TimeoutError("no safe RR canary boundary within 24 hours")
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            current = rr_parallel_campaign._process(child["pid"])
            if (not current or current["start_ticks"] != child["start_ticks"]
                    or current["argv"] == [""]):
                break
            time.sleep(5)
        else:
            raise TimeoutError("RR canary did not exit within ten minutes")
        return action()
    finally:
        try:
            current = rr_parallel_campaign._process(controller_pid)
            if paused and current and current["start_ticks"] == controller["start_ticks"]:
                os.kill(controller_pid, signal.SIGCONT)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)


def wait_execute(args, kwargs) -> int:
    launch, source = load_launch(args.launch, args.launch_sha256, **kwargs)
    wait_root = args.control.with_name(args.control.name + "-wait")
    wait_root.mkdir()
    start_child_controller(
        work_root=kwargs["work"], control_root=wait_root, campaign_id=wait_root.name,
        release_commit=launch["judging_revision"]["expected_commit"],
        evidence_class="local_judging_gpu_handoff", hard_stop_hours=26,
        tmux_socket=args.tmux_socket, tmux_session=args.tmux_session,
    )
    exit_code = 1
    try:
        command = [sys.executable, "-m", "experiments.local_campaign.rr_retained_judging",
                   "--work", str(kwargs["work"]), "--project", str(kwargs["project"]),
                   "execute", "--launch", str(args.launch), "--launch-sha256", args.launch_sha256,
                   "--control", str(args.control), "--tmux-socket", args.tmux_socket,
                   "--tmux-session", args.tmux_session]

        def action():
            environment = dict(os.environ, CUDA_VISIBLE_DEVICES="0")
            # subprocess.run kills and waits for its own child on exceptions,
            # before the boundary's finally resumes the RR scheduler.
            return subprocess.run(command, cwd=kwargs["project"], env=environment,
                                  timeout=launch["wall_seconds"] + 180, check=False).returncode

        exit_code = at_canary_boundary(source, args.controller_pid, action)
        return exit_code
    finally:
        finish_child_controller(work_root=kwargs["work"], control_root=wait_root, exit_code=exit_code)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare_parser = actions.add_parser("prepare")
    prepare_parser.add_argument("--state", type=Path, required=True)
    prepare_parser.add_argument("--out", type=Path, required=True)
    prepare_parser.add_argument("--project-revision", type=Path, required=True)
    prepare_parser.add_argument("--project-revision-sha256", required=True)
    for action in ("validate", "execute", "wait-execute"):
        command = actions.add_parser(action)
        command.add_argument("--launch", type=Path, required=True)
        command.add_argument("--launch-sha256", required=True)
        if action in ("execute", "wait-execute"):
            command.add_argument("--control", type=Path, required=True)
            command.add_argument("--tmux-socket", required=True)
            command.add_argument("--tmux-session", required=True)
        if action == "wait-execute":
            command.add_argument("--controller-pid", type=int, required=True)
    args = parser.parse_args()
    kwargs = {"work": args.work.resolve(strict=True), "project": args.project.resolve(strict=True)}
    if args.action == "prepare":
        prepare(args.state, **kwargs, out=args.out, revision_path=args.project_revision,
                revision_sha256=args.project_revision_sha256)
    elif args.action == "validate":
        load_launch(args.launch, args.launch_sha256, **kwargs)
    elif args.action == "wait-execute":
        raise SystemExit(wait_execute(args, kwargs))
    else:
        execute(args.launch, args.launch_sha256, **kwargs, control=args.control,
                tmux_socket=args.tmux_socket, tmux_session=args.tmux_session)


if __name__ == "__main__":
    main()
