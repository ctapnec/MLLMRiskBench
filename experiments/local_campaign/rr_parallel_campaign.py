"""Plan-owned two-GPU continuation of the exact retained RR population.

This is deliberately TP1-only. Models requiring two GPUs must run exclusively,
not through this controller. Interrupted source grids are never promoted.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import os
from pathlib import Path
import subprocess
from typing import Sequence

from experiments.local_campaign import rr_profiled_phase6 as prior
from experiments.local_campaign.failed_output_recovery_phase6 import _jsonl
from experiments.local_campaign.console_events import (
    finish_child_controller, publish_target_execution, start_child_controller,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit, _base_argv, _create_json, _framework_lock_id, _load_json, _option,
    _project_python, _replace_option, _run_unit, _sha256_json, _utc_now,
    _validate_descriptor,
)
from ura.data_models import Judgment

SCHEMA = "ura-rr-parallel-campaign/1"
SNAPSHOT_SCHEMA = "ura-rr-interrupted-prefix/1"
OBSERVATION_SCHEMA = "ura-rr-process-observation/1"
STATE_SCHEMA = "ura-rr-parallel-unit-state/1"
RETRY_SCHEMA = "ura-rr-parallel-template-retry/1"
_ROLE_ERROR = "Conversation roles must alternate user/assistant/user/assistant/..."
MODULE = "experiments.local_campaign.rr_parallel_campaign"
OUTCOMES = {"usable_first_response", "recovered_after_retry", "failed_output", "input_incompatible"}


def _bound(path: Path, digest: str, label: str) -> dict:
    descriptor = prior._descriptor(path, label=label)
    if descriptor["sha256"] != digest:
        raise ValueError(f"{label} bytes changed")
    return _load_json(path, label=label)


def _process(pid: int) -> dict | None:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("process ID must be a positive integer")
    root = Path(f"/proc/{pid}")
    try:
        stat = (root / "stat").read_text().rsplit(")", 1)[1].split()
        argv = (root / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
        children = [int(value) for value in (root / f"task/{pid}/children").read_text().split()]
    except FileNotFoundError:
        return None
    return {"pid": pid, "start_ticks": int(stat[19]), "argv": argv, "children": children}


def observe(prior_root: Path, controller_pid: int) -> dict:
    root = prior_root.resolve(strict=True)
    process = _process(controller_pid)
    if (process is None or str(root) not in process["argv"]
            or "experiments.local_campaign.rr_profiled_phase6" not in process["argv"]):
        raise ValueError("PID is not the exact original RR controller")
    pending, seen, processes = [controller_pid], set(), []
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        value = _process(pid)
        if value is not None:
            processes.append(value)
            pending.extend(value["children"])
    return {"schema": OBSERVATION_SCHEMA, "observed_at_utc": _utc_now(),
            "prior_root": str(root), "controller_pid": controller_pid,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "launch": prior._descriptor(root / "launch.json", label="RR launch"),
            "processes": sorted(processes, key=lambda item: item["pid"])}


def _require_stopped(observation: dict, result_roots: Sequence[Path]) -> None:
    root = str(observation["prior_root"])
    processes = observation.get("processes")
    if (observation.get("schema") != OBSERVATION_SCHEMA or not isinstance(processes, list)
            or not processes or observation.get("controller_pid") not in {p.get("pid") for p in processes}
            or len(processes) != len({p.get("pid") for p in processes})):
        raise ValueError("RR interruption lacks its exact process observation")
    for item in processes:
        if (type(item.get("start_ticks")) is not int or item["start_ticks"] <= 0
                or not isinstance(item.get("argv"), list) or _process(item["pid"]) is not None):
            raise ValueError("a bound RR process is still present or its identity changed")
    # Check exact argv tokens, not a pgrep pattern that can match its own shell.
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            argv = (directory / "cmdline").read_bytes().split(b"\0")
        except FileNotFoundError:
            continue
        if root.encode() in argv:
            raise ValueError("an RR controller with the original root is still live")
    for result_root in result_roots:
        for lock in result_root.glob("*.lock"):
            value = _load_json(lock, label="retained RR lock")
            if _process(value.get("pid")) is not None:
                raise ValueError("a retained RR result lock still has a live owner")


def _population(launch: dict) -> tuple[dict, dict]:
    if (launch.get("schema") != prior.SCHEMA or launch.get("planned_unique_rows") != 7606
            or launch.get("unit_order") != [lane for lane, _ in prior.LAYOUT]
            or set(launch.get("units", {})) != set(dict(prior.LAYOUT))
            or launch.get("target_answer_retries") != 1 or launch.get("paid_provider_calls") != 0):
        raise ValueError("original RR population contract changed")
    revision_path = _validate_descriptor(launch["project_revision"], label="original RR project revision")
    revision = _load_json(revision_path, label="original RR project revision")
    if any(revision.get("repository", {}).get(key) != launch.get("expected_commit")
           for key in ("expected_commit", "observed_commit")):
        raise ValueError("original RR source revision changed")
    selected, specifications = {}, {}
    for lane, count in prior.LAYOUT:
        evidence = launch["units"][lane]
        path = _validate_descriptor(evidence["source_specification"], label="RR specification")
        spec = _load_json(path, label="RR specification")
        argv = spec["base_argv"]
        config_path = _validate_descriptor(evidence["local_config"], label="RR execution profile")
        config = _load_json(config_path, label="RR execution profile")[prior.RR_SPEC]
        if (spec.get("lane_id") != lane or _option(argv, "--local") != prior.RR_SPEC
                or _option(argv, "--limit") != "100" or _option(argv, "--seeds") != "0"
                or _option(argv, "--sample-seed") != "0" or _option(argv, "--attackers") != "replay"
                or spec.get("target", {}).get("revision") != prior.RR_REVISION
                or config.get("revision") != prior.RR_REVISION or config.get("max_tokens") != 4096
                or config.get("tensor_parallel_size") != 1):
            raise ValueError("RR source selection or 4096-token TP1 profile changed")
        rows, _audit = prior._selected_rows(argv)
        selected[lane] = {arm: [row.id for row in items] for arm, items in rows.items()}
        prior.checkpoint_selection(selected[lane], [])
        if sum(map(len, selected[lane].values())) != count:
            raise ValueError("RR source cardinality changed")
        specifications[lane] = spec
    return selected, specifications


def inspect_prefix(observation: dict, *, runner_root: Path) -> dict:
    root = Path(observation["prior_root"])
    launch_path = _validate_descriptor(observation["launch"], label="observed RR launch")
    if launch_path != root / "launch.json" or (root / "completion.json").exists():
        raise ValueError("source is not the observed interrupted RR controller")
    launch = _load_json(launch_path, label="observed RR launch")
    selected, specs = _population(launch)
    result_roots = [runner_root / lane / root.name for lane, _ in prior.LAYOUT]
    _require_stopped(observation, result_roots)
    lanes = {}
    for (lane, _count), result_root in zip(prior.LAYOUT, result_roots, strict=True):
        state_path = root / "units" / lane / "state.json"
        files = sorted(result_root.rglob("*")) if result_root.exists() else []
        if any(path.is_symlink() for path in files):
            raise ValueError("RR interrupted raw files contain a symlink")
        files = [path for path in files if path.is_file()]
        outcomes, attempts, judged = {}, {}, set()
        if any(path.name.endswith((".responses.jsonl", ".responses.checkpoint.jsonl")) for path in files):
            attempts, outcomes, _a, _r = prior._durable_outcomes(result_root)
        # Bind existing closed-cell judgments without promoting the unfinished
        # parent grid. Final metric admission still validates their source code.
        for marker_path in result_root.glob("*.complete.json"):
            marker = _load_json(marker_path, label="RR retained cell marker")
            artifact = marker.get("artifacts", {}).get("judgments")
            if not isinstance(artifact, dict) or Path(str(artifact.get("file"))).name != artifact.get("file"):
                raise ValueError("RR retained judgment descriptor changed")
            judgment_path = result_root / artifact["file"]
            observed = prior._descriptor(judgment_path, label="RR retained judgments")
            if any(observed[key] != artifact.get(key) for key in ("sha256", "bytes")):
                raise ValueError("RR retained judgments no longer match their cell marker")
            for row in _jsonl(judgment_path, label="RR retained judgments"):
                judgment = Judgment.model_validate(row)
                if judgment.attempt_id not in attempts:
                    raise ValueError("RR retained judgment has no matching response")
                judged.add(attempts[judgment.attempt_id])
        prior.checkpoint_selection(selected[lane], list(outcomes))
        if not set(outcomes.values()) <= OUTCOMES:
            raise ValueError("RR interrupted outcome status changed")
        state = None
        if state_path.exists():
            state = _load_json(state_path, label="RR interrupted state")
            config = launch["units"][lane]["local_config"]
            base = _replace_option(specs[lane]["base_argv"], "--local-config", config["path"])
            base = _replace_option(base, "--local-config-sha256", config["sha256"])
            revision = launch["project_revision"]
            _validate_descriptor(revision, label="original RR project revision")
            base = _base_argv(Unit(lane, lane, None, {"base_argv": base}, dict(prior.LAYOUT)[lane]),
                              project_revision=Path(revision["path"]), project_revision_sha256=revision["sha256"])
            if (state.get("schema") != prior.STATE_SCHEMA or state.get("unit_id") != lane
                    or state.get("source_lane") != lane or state.get("corpus") is not None
                    or state.get("result_root") != str(result_root)
                    or state.get("runner_argv", [])[:len(base)] != base
                    or state.get("selected_records") != dict(prior.LAYOUT)[lane]):
                raise ValueError("RR interrupted state differs from its original request")
        elif outcomes:
            raise ValueError("RR interrupted responses lack their measured state")
        lanes[lane] = {"result_root": str(result_root), "outcomes": outcomes,
                       "state": prior._descriptor(state_path, label="RR state") if state else None,
                       "raw_files": [prior._descriptor(path, label="RR retained raw file") for path in files],
                       "retained_response_ids": sorted(outcomes),
                       "retained_judgment_ids": sorted(judged),
                       "post_factum_judging_required_ids": sorted(set(outcomes) - judged),
                       "retained_judgments_require_source_validation": True,
                       "old_grid_promoted": False}
    _require_stopped(observation, result_roots)
    return {"schema": SNAPSHOT_SCHEMA, "status": "interrupted_prefix_only",
            "launch": observation["launch"], "observation": observation, "lanes": lanes,
            "selected_ids": selected, "selected_ids_sha256": _sha256_json(selected),
            "planned_unique_rows": 7606, "retained_response_count": sum(len(v["outcomes"]) for v in lanes.values()),
            "judging_complete": False, "old_grid_promoted": False, "paid_provider_calls": 0}


def partition_units(units: Sequence[Unit], selected: dict, retained: dict) -> tuple[list[Unit], dict]:
    result, selectors = [], {}
    for unit in units:
        original = selected[unit.source_lane]
        completed = list(retained[unit.source_lane]["outcomes"])
        selector, _count = prior.checkpoint_selection(original, completed)
        for arm, entry in selector["corpora"].items():
            unit_id = f"rr-{unit.source_lane}-{_sha256_json(arm)[:16]}"
            count = len(original[arm]) - entry["completed_record_count"]
            recovery = ({"schema": selector["schema"], "corpora": {arm: entry}}
                        if entry["completed_record_count"] else None)
            result.append(replace(unit, unit_id=unit_id, corpus=arm, selected_records=count, recovery=recovery))
            if recovery:
                selectors[unit_id] = recovery
    return result, selectors


def balanced_queues(units: Sequence[Unit]) -> dict[str, list[str]]:
    queues: dict[str, list[str]] = {"0": [], "1": []}
    sizes = {"0": 0, "1": 0}
    if len({unit.unit_id for unit in units}) != len(units):
        raise ValueError("parallel RR unit identity is duplicated")
    for unit in sorted(units, key=lambda value: (-value.selected_records, value.unit_id)):
        gpu = min(sizes, key=lambda key: (sizes[key], key))
        queues[gpu].append(unit.unit_id)
        sizes[gpu] += unit.selected_records
    return queues


def _worker_units(launch: dict, gpu: str) -> list[Unit]:
    units = [Unit(**item) for item in launch["units"]]
    if (launch.get("schema") != SCHEMA or launch.get("max_tokens") != 4096
            or launch.get("tensor_parallel_size") != 1
            or gpu not in {"0", "1"} or os.environ.get("CUDA_VISIBLE_DEVICES") != gpu
            or launch["queues"] != balanced_queues(units)):
        raise ValueError("parallel RR worker GPU or deterministic queue changed")
    by_id = {unit.unit_id: unit for unit in units}
    return [by_id[key] for key in launch["queues"][gpu]]


def coverage(launch: dict, *, replacement_roots: dict[str, Path] | None = None) -> dict:
    snapshot_path = _validate_descriptor(launch["interruption"], label="RR interrupted prefix")
    snapshot = _load_json(snapshot_path, label="RR interrupted prefix")
    work = Path(launch["work_root"])
    seen = {lane: set(item["outcomes"]) for lane, item in snapshot["lanes"].items()}
    replacement_roots = replacement_roots or {}
    if set(replacement_roots) - {unit["unit_id"] for unit in launch["units"]}:
        raise ValueError("RR coverage replacement is outside the original unit selection")
    segments = []
    for gpu, queue in launch["queues"].items():
        worker_root = Path(launch["workers"][gpu])
        by_id = {item["unit_id"]: item for item in launch["units"]}
        for unit_id in queue:
            unit = by_id[unit_id]
            lane, arm = unit["source_lane"], unit["corpus"]
            result_root = work / "runs/thesis/runner" / unit_id / worker_root.name
            result_root = replacement_roots.get(unit_id, result_root)
            outcomes = {}
            if list(result_root.glob("*.responses*.jsonl")):
                _attempts, outcomes, _af, _rf = prior._durable_outcomes(result_root)
            allowed = set(snapshot["selected_ids"][lane][arm]) - set(snapshot["lanes"][lane]["outcomes"])
            if not set(outcomes) <= allowed or set(outcomes) & seen[lane]:
                raise ValueError("parallel RR repeated a retained response or produced an unselected input")
            seen[lane].update(outcomes)
            segments.append({"unit_id": unit_id, "source_lane": lane, "corpus": arm,
                             "physical_gpu": gpu, "result_root": str(result_root),
                             "retained_responses": len(outcomes), "selected_records": unit["selected_records"],
                             "input_ids_sha256": _sha256_json(sorted(outcomes))})
    expected = {lane: {item for ids in arms.values() for item in ids}
                for lane, arms in snapshot["selected_ids"].items()}
    return {"complete": seen == expected, "expected_inputs": sum(map(len, expected.values())),
            "retained_inputs": sum(map(len, seen.values())), "repeated_responses": 0,
            "source_prefix_responses": snapshot["retained_response_count"], "segments": segments,
            "prefix_judging_required": sum(len(item["post_factum_judging_required_ids"])
                                           for item in snapshot["lanes"].values()),
            "old_grid_promoted": False, "prior_prefix_judging_complete": False}


def worker(launch_path: Path, digest: str, gpu: str) -> int:
    launch = _bound(launch_path, digest, "parallel RR launch")
    units = _worker_units(launch, gpu)
    root = Path(launch["workers"][gpu])
    root.mkdir(mode=0o700)
    work = Path(launch["work_root"])
    project = Path(launch["project_root"])
    python = _project_python(project, project / ".venv/bin/python")
    revision = launch["project_revision"]
    _validate_descriptor(revision, label="parallel RR project revision")
    _create_json(root / "launch.json", {"schema": SCHEMA, "parent": prior._descriptor(launch_path, label="parallel RR launch"),
                                      "physical_gpu": gpu, "unit_order": [u.unit_id for u in units]})
    start_child_controller(work_root=work, control_root=root, campaign_id=root.name,
                           release_commit=launch["expected_commit"], evidence_class="measured_parallel_rr",
                           hard_stop_hours=168, tmux_socket=launch["tmux_socket"], tmux_session=launch["tmux_session"],
                           target_execution=True)
    results, failures = {}, {}
    for unit in units:
        recovery = launch["selectors"].get(unit.unit_id)
        try:
            results[unit.unit_id] = _run_unit(
                unit, python=python, work_root=work, control_root=root,
                project_revision=Path(revision["path"]), project_revision_sha256=revision["sha256"],
                scope=launch["execution_scope_id"] + f"-gpu{gpu}",
                recovery_path=Path(recovery["path"]) if recovery else None,
                recovery_sha256=recovery["sha256"] if recovery else None,
                expected_commit=launch["expected_commit"], framework_lock_id=_framework_lock_id(),
                admission_sha256=digest, tmux_socket=launch["tmux_socket"], tmux_session=launch["tmux_session"],
                state_schema=STATE_SCHEMA, measured_wall_time_seconds=259200,
                live_attestation_max_age_hours=96, scoring_device="cuda:0",
            )
        except Exception as exc:
            failures[unit.unit_id] = {"error_type": type(exc).__name__, "error": str(exc)}
        _create_json(root / f"{unit.unit_id}.terminal.json", {
            "result": results.get(unit.unit_id), "failure": failures.get(unit.unit_id)})
    attempts = successful = 0
    for unit in units:
        result_root = work / "runs/thesis/runner" / unit.unit_id / root.name
        if list(result_root.glob("*.responses*.jsonl")):
            _a, outcomes, _af, _rf = prior._durable_outcomes(result_root)
            attempts += len(outcomes)
            successful += sum(v in {"usable_first_response", "recovered_after_retry"} for v in outcomes.values())
    _create_json(root / "completion.json", {"schema": SCHEMA, "status": "complete_with_failures" if failures else "complete",
                                          "launch": prior._descriptor(root / "launch.json", label="RR worker launch"),
                                          "physical_gpu": gpu, "results": results, "failures": failures,
                                          "target_attempts": attempts, "successful_generations": successful})
    publish_target_execution(work_root=work, control_root=root, target_attempts=attempts,
                             successful_target_generations=successful)
    finish_child_controller(work_root=work, control_root=root, exit_code=int(bool(failures)))
    return int(bool(failures))


def _require_worker_stopped(launch_path: Path, launch: dict, gpu: str) -> None:
    """Check exact original worker/output tokens, never signal any process."""
    outputs = {str(Path(launch["work_root"]) / "runs/thesis/runner" / key /
                   Path(launch["workers"][gpu]).name) for key in launch["queues"][gpu]}
    old_units = Path(launch["workers"][gpu]) / "units"
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit() or int(directory.name) == os.getpid():
            continue
        try:
            if directory.stat().st_uid != os.getuid():
                continue
            argv = (directory / "cmdline").read_bytes().decode().rstrip("\0").split("\0")
        except FileNotFoundError:
            continue
        if (outputs.intersection(argv) or any(Path(token).is_absolute() and Path(token).is_relative_to(old_units) for token in argv)
                or (MODULE in argv and "worker" in argv
                and str(launch_path) in argv and _option(argv, "--gpu") == gpu)):
            raise ValueError("original RR worker or one of its measured children is still live")


def template_retry_selection(launch_path: Path, worker_path: Path, gpu: str) -> tuple[dict, list[Unit], dict]:
    """Qualify only terminal, pre-measured legacy-template failures."""
    launch = _load_json(launch_path, label="original parallel launch")
    units = [Unit(**item) for item in launch["units"]]
    if (launch.get("schema") != SCHEMA or launch.get("original_population") != 7606
            or launch.get("max_tokens") != 4096 or launch.get("tensor_parallel_size") != 1
            or launch.get("target_answer_retries") != 1 or gpu not in {"0", "1"}
            or launch["queues"] != balanced_queues(units)):
        raise ValueError("RR retry original selection or 4096-token TP1 policy changed")
    worker_root = launch_path.parent.with_name(launch_path.parent.name + f"-gpu{gpu}")
    worker = _load_json(worker_path, label="original RR worker completion")
    original = prior._descriptor(launch_path, label="original parallel launch")
    worker_launch = _load_json(_validate_descriptor(worker["launch"], label="original worker launch"), label="original worker launch")
    queue = launch["queues"][gpu]
    failures, results = worker.get("failures", {}), worker.get("results", {})
    if (Path(launch["workers"][gpu]) != worker_root or worker_path != worker_root / "completion.json"
            or worker.get("schema") != SCHEMA or worker.get("status") != "complete_with_failures"
            or worker.get("physical_gpu") != gpu or not failures or set(failures) & set(results)
            or set(failures) | set(results) != set(queue)
            or worker_launch != {"schema": SCHEMA, "parent": original, "physical_gpu": gpu, "unit_order": queue}
            or Path(worker["launch"]["path"]) != worker_root / "launch.json"):
        raise ValueError("RR retry requires its exact terminal failed worker")
    _require_worker_stopped(launch_path, launch, gpu)
    snapshot = _load_json(_validate_descriptor(launch["interruption"], label="RR prefix"), label="RR prefix")
    if snapshot["selected_ids_sha256"] != _sha256_json(snapshot["selected_ids"]):
        raise ValueError("RR retry original input IDs changed")
    selected, evidence = [], {}
    for unit in units:
        if unit.unit_id not in failures:
            continue
        unit_root = worker_root / "units" / unit.unit_id
        terminal = worker_root / f"{unit.unit_id}.terminal.json"
        if _load_json(terminal, label="original unit failure") != {"result": None, "failure": failures[unit.unit_id]}:
            raise ValueError("RR retry changed its bound unit failure")
        errors = sorted((unit_root / "canary").glob("*.error.json"))
        if len(errors) != 1:
            continue
        error = _load_json(errors[0], label="original canary error")
        if not (error.get("exception_type") == "ExternalCallFailure"
                and str(error.get("message", "")).endswith(_ROLE_ERROR)):
            continue
        old_result = Path(launch["work_root"]) / "runs/thesis/runner" / unit.unit_id / worker_root.name
        if ((unit_root / "state.json").exists() or any(path.stat().st_size for path in old_result.glob("*.responses*.jsonl"))
                or error.get("completed_attempts") != 0 or error.get("corpus") != unit.corpus):
            raise ValueError("RR template retry requires zero original measured responses and no measured state")
        if error.get("model_spec") not in {prior.RR_SPEC, f"{prior.RR_SPEC}@{prior.RR_REVISION}"}:
            raise ValueError("RR template retry canary model identity differs from the pinned target")
        base = unit.spec["base_argv"]
        config = _bound(Path(_option(base, "--local-config")), _option(base, "--local-config-sha256"), "RR retry model config")[prior.RR_SPEC]
        rows, _audit = prior._selected_rows(_replace_option(base, "--corpora", unit.corpus))
        expected = snapshot["selected_ids"][unit.source_lane][unit.corpus]
        completed = set(snapshot["lanes"][unit.source_lane]["outcomes"])
        selector, _count = prior.checkpoint_selection(snapshot["selected_ids"][unit.source_lane], list(completed))
        entry = selector["corpora"][unit.corpus]
        recovery = {"schema": selector["schema"], "corpora": {unit.corpus: entry}} if entry["completed_record_count"] else None
        bound_selector = launch["selectors"].get(unit.unit_id)
        if (config.get("max_tokens") != 4096 or config.get("tensor_parallel_size") != 1
                or config.get("revision") != prior.RR_REVISION or _option(base, "--local") != prior.RR_SPEC
                or _option(base, "--limit") != "100" or _option(base, "--sample-seed") != "0"
                or _option(base, "--seeds") != "0" or _option(base, "--attackers") != "replay"
                or set(rows) != {unit.corpus} or [row.id for row in rows[unit.corpus]] != expected
                or unit.selected_records != len(set(expected) - completed) or unit.recovery != recovery
                or (bound_selector is not None) != (recovery is not None)):
            raise ValueError("RR retry changed original model settings, selector or input IDs")
        if bound_selector and _load_json(_validate_descriptor(bound_selector, label="RR retry selector"), label="RR retry selector") != recovery:
            raise ValueError("RR retry original selector bytes changed")
        selected.append(unit)
        files = [terminal, errors[0], unit_root / "canary.run.log"]
        files.extend(sorted((unit_root / "canary").glob("*.grid.json")))
        evidence[unit.unit_id] = {"failure": failures[unit.unit_id],
            "artifacts": [prior._descriptor(path, label="RR original failure artifact") for path in files],
            "remaining_ids_sha256": _sha256_json([key for key in expected if key not in completed])}
    if not selected:
        raise ValueError("terminal RR worker has no qualified zero-measured template failures")
    return launch, selected, evidence


def retry(args: argparse.Namespace) -> int:
    launch_path = _validate_descriptor(prior._descriptor(args.launch, label="original RR launch"), label="original RR launch")
    _bound(launch_path, args.launch_sha256, "original RR launch")
    worker_path = _validate_descriptor(prior._descriptor(args.worker_completion, label="original RR worker"), label="original RR worker")
    _bound(worker_path, args.worker_completion_sha256, "original RR worker")
    launch, units, failures = template_retry_selection(launch_path, worker_path, args.gpu)
    _worker_units(launch, args.gpu)  # Same single-visible-physical-GPU guard.
    work, project = Path(launch["work_root"]).resolve(strict=True), args.project_root.resolve(strict=True)
    python = _project_python(project, project / ".venv/bin/python")
    revision = prior._descriptor(args.project_revision, label="RR retry project revision")
    receipt = _bound(args.project_revision, args.project_revision_sha256, "RR retry project revision")
    if any(receipt.get("repository", {}).get(key) != args.expected_commit for key in ("expected_commit", "observed_commit")):
        raise ValueError("RR retry source revision changed")
    root = args.control_root
    if not root.is_absolute() or root.exists() or root.is_symlink() or root.parent != work / "runs/engineering":
        raise ValueError("RR template retry needs a fresh canonical engineering root")
    for unit in units:
        if any(path.stat().st_size for path in (work / "runs/thesis/runner" / unit.unit_id).glob("*/*.responses*.jsonl")):
            raise ValueError("RR retry found measured responses; use checkpoint continuation, never repeat them")
    root.mkdir(mode=0o700)
    admission = {"schema": RETRY_SCHEMA, "original_launch": prior._descriptor(launch_path, label="RR launch"),
                 "original_worker_completion": prior._descriptor(worker_path, label="RR worker"), "physical_gpu": args.gpu,
                 "project_revision": revision, "expected_commit": args.expected_commit, "project_root": str(project),
                 "work_root": str(work), "units": [asdict(unit) for unit in units], "failure_evidence": failures,
                 "execution_scope_id": args.execution_scope_id, "tmux_socket": args.tmux_socket, "tmux_session": args.tmux_session}
    _create_json(root / "launch.json", admission)
    descriptor = prior._descriptor(root / "launch.json", label="RR retry launch")
    start_child_controller(work_root=work, control_root=root, campaign_id=root.name, release_commit=args.expected_commit,
                           evidence_class="measured_rr_template_retry", hard_stop_hours=168,
                           tmux_socket=args.tmux_socket, tmux_session=args.tmux_session, target_execution=True)
    results, failed = {}, {}
    for unit in units:
        selector = launch["selectors"].get(unit.unit_id)
        try:
            results[unit.unit_id] = _run_unit(unit, python=python, work_root=work, control_root=root,
                project_revision=args.project_revision, project_revision_sha256=revision["sha256"], scope=args.execution_scope_id,
                recovery_path=Path(selector["path"]) if selector else None, recovery_sha256=selector["sha256"] if selector else None,
                expected_commit=args.expected_commit, framework_lock_id=_framework_lock_id(), admission_sha256=descriptor["sha256"],
                tmux_socket=args.tmux_socket, tmux_session=args.tmux_session, state_schema=STATE_SCHEMA,
                measured_wall_time_seconds=259200, live_attestation_max_age_hours=96, scoring_device="cuda:0")
        except Exception as exc:
            failed[unit.unit_id] = {"error_type": type(exc).__name__, "error": str(exc)}
        _create_json(root / f"{unit.unit_id}.terminal.json", {"result": results.get(unit.unit_id), "failure": failed.get(unit.unit_id)})
    attempts = successful = 0
    for unit in units:
        result_root = work / "runs/thesis/runner" / unit.unit_id / root.name
        if list(result_root.glob("*.responses*.jsonl")):
            _a, outcomes, _af, _rf = prior._durable_outcomes(result_root)
            attempts += len(outcomes)
            successful += sum(value in {"usable_first_response", "recovered_after_retry"} for value in outcomes.values())
    _create_json(root / "completion.json", {**admission, "launch": descriptor,
        "status": "complete_with_failures" if failed else "complete", "results": results, "failures": failed,
        "target_attempts": attempts, "successful_generations": successful})
    publish_target_execution(work_root=work, control_root=root, target_attempts=attempts, successful_target_generations=successful)
    finish_child_controller(work_root=work, control_root=root, exit_code=int(bool(failed)))
    return int(bool(failed))


def run(args: argparse.Namespace) -> int:
    project = args.project_root.resolve(strict=True)
    work = args.work_root.resolve(strict=True)
    python = _project_python(project, project / ".venv/bin/python")
    root = args.control_root
    if not root.is_absolute() or root.exists() or root.is_symlink() or root.parent != work / "runs/engineering":
        raise ValueError("parallel RR requires a fresh canonical engineering root")
    snapshot = _bound(args.interruption, args.interruption_sha256, "RR interrupted prefix")
    if snapshot != inspect_prefix(snapshot["observation"], runner_root=work / "runs/thesis/runner"):
        raise ValueError("RR interrupted prefix changed")
    revision = prior._descriptor(args.project_revision, label="parallel RR project revision")
    value = _bound(args.project_revision, args.project_revision_sha256, "parallel RR project revision")
    if any(value.get("repository", {}).get(key) != args.expected_commit for key in ("expected_commit", "observed_commit")):
        raise ValueError("parallel RR source revision changed")
    root.mkdir(mode=0o700)
    (root / "configs").mkdir()
    (root / "inputs").mkdir()
    units, evidence = prior.configure_units(args.source_spec_root, root, args.profile_registry)
    old_launch = _load_json(Path(snapshot["launch"]["path"]), label="interrupted RR launch")
    for lane, _ in prior.LAYOUT:
        current = _load_json(Path(evidence[lane]["local_config"]["path"]), label="new RR config")
        old = _load_json(Path(old_launch["units"][lane]["local_config"]["path"]), label="original RR config")
        if (current != old or current[prior.RR_SPEC].get("max_tokens") != 4096
                or current[prior.RR_SPEC].get("tensor_parallel_size") != 1
                or evidence[lane]["source_specification"] != old_launch["units"][lane]["source_specification"]):
            raise ValueError("parallel RR changed the source selection or admitted 4096-token TP1 profile")
    units, selectors = partition_units(units, snapshot["selected_ids"], snapshot["lanes"])
    if sum(u.selected_records for u in units) + snapshot["retained_response_count"] != 7606:
        raise ValueError("parallel RR population does not cover all 7606 inputs")
    for unit in units:
        if any((work / "runs/thesis/runner" / unit.unit_id).rglob("*.responses*.jsonl")):
            raise ValueError("parallel RR unit already has measured responses; checkpoint continuation is required")
    selector_files = {}
    for key, selector in selectors.items():
        path = root / "inputs" / f"{key}.json"
        _create_json(path, selector)
        selector_files[key] = prior._descriptor(path, label="RR positive-count selector")
    launch = {"schema": SCHEMA, "status": "running", "created_at_utc": _utc_now(),
              "expected_commit": args.expected_commit, "project_revision": revision,
              "project_root": str(project), "work_root": str(work),
              "interruption": prior._descriptor(args.interruption, label="RR interrupted prefix"),
              "original_population": 7606, "retained_response_count": snapshot["retained_response_count"],
              "remaining_response_count": sum(u.selected_records for u in units),
              "units": [asdict(u) for u in units], "selectors": selector_files, "queues": balanced_queues(units),
              "workers": {gpu: str(root.with_name(root.name + f"-gpu{gpu}")) for gpu in ("0", "1")},
              "execution_scope_id": args.execution_scope_id, "tmux_socket": args.tmux_socket,
              "tmux_session": args.tmux_session, "target_answer_retries": 1,
              "max_tokens": 4096, "tensor_parallel_size": 1, "old_grid_promoted": False,
              "prior_prefix_judging_complete": False, "cross_condition_pooling_permitted": False}
    path = root / "launch.json"
    _create_json(path, launch)
    digest = prior._descriptor(path, label="parallel RR launch")["sha256"]
    processes = {}
    for gpu in ("0", "1"):
        env = {**os.environ, "CUDA_VISIBLE_DEVICES": gpu, "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
        with (root / f"gpu{gpu}.log").open("xb") as log:
            processes[gpu] = subprocess.Popen([str(python), "-m", MODULE, "worker", "--launch", str(path),
                                               "--launch-sha256", digest, "--gpu", gpu], cwd=project, env=env,
                                              stdout=log, stderr=subprocess.STDOUT)
    exits = {gpu: process.wait() for gpu, process in processes.items()}
    accounted = coverage(launch)
    failed = any(exits.values()) or not accounted["complete"]
    _create_json(root / "completion.json", {**launch, "launch": prior._descriptor(path, label="parallel RR launch"),
                                          "status": "complete_with_failures" if failed else "responses_complete_pending_prefix_validation",
                                          "coverage": accounted,
                                          "worker_exit_codes": exits, "completed_at_utc": _utc_now(),
                                          "worker_completions": {gpu: prior._descriptor(Path(launch["workers"][gpu]) / "completion.json", label="RR worker completion")
                                                                 for gpu in exits if (Path(launch["workers"][gpu]) / "completion.json").is_file()}})
    return int(failed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    obs = commands.add_parser("observe")
    obs.add_argument("--prior-root", type=Path, required=True)
    obs.add_argument("--controller-pid", type=int, required=True)
    obs.add_argument("--out", type=Path, required=True)
    snap = commands.add_parser("snapshot")
    for name in ("observation", "runner-root", "out"):
        snap.add_argument(f"--{name}", type=Path, required=True)
    snap.add_argument("--observation-sha256", required=True)
    child = commands.add_parser("worker")
    child.add_argument("--launch", type=Path, required=True)
    child.add_argument("--launch-sha256", required=True)
    child.add_argument("--gpu", choices=("0", "1"), required=True)
    again = commands.add_parser("retry")
    for name in ("launch", "worker-completion", "project-root", "project-revision", "control-root"):
        again.add_argument(f"--{name}", type=Path, required=True)
    for name in ("launch-sha256", "worker-completion-sha256", "project-revision-sha256", "expected-commit",
                 "execution-scope-id", "tmux-socket", "tmux-session"):
        again.add_argument(f"--{name}", required=True)
    again.add_argument("--gpu", choices=("0", "1"), required=True)
    parent = commands.add_parser("run")
    for name in ("project-root", "work-root", "control-root", "project-revision", "source-spec-root", "profile-registry", "interruption"):
        parent.add_argument(f"--{name}", type=Path, required=True)
    for name in ("project-revision-sha256", "expected-commit", "execution-scope-id", "interruption-sha256", "tmux-socket", "tmux-session"):
        parent.add_argument(f"--{name}", required=True)
    args = parser.parse_args(argv)
    if args.command == "observe":
        _create_json(args.out, observe(args.prior_root, args.controller_pid))
        return 0
    if args.command == "snapshot":
        observation = _bound(args.observation, args.observation_sha256, "RR process observation")
        _create_json(args.out, inspect_prefix(observation, runner_root=args.runner_root))
        return 0
    if args.command == "worker":
        return worker(args.launch, args.launch_sha256, args.gpu)
    if args.command == "retry":
        return retry(args)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
