"""Resume the interrupted hardware-fit tail under a finite output profile.

The prior controller is immutable evidence of a bad execution condition: an
omitted vLLM output cap allowed LLaVA to spend its full 32,768-token context on
individual answers. This successor retains completed metric units, excludes
the one usable durable row in the interrupted unit, and runs only the failed,
length-ended, or never-attempted rows plus later unstarted units.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments import run_matrix
from experiments.local_model_profiles import apply_profile
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import _descriptor, _stable_file
from experiments.local_campaign.current_ollama_phase6 import _counts_from_level1
from experiments.local_campaign.failed_output_recovery_phase6 import (
    _durable_outcomes,
    _selected_rows,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    STATE_SCHEMA as PRIOR_STATE_SCHEMA,
    _unit_order,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    configure_units,
    load_inventory,
)
from experiments.local_campaign.local_truncation_recovery_phase6 import (
    build_truncation_selection,
    length_ended_datapoint_ids,
)
from experiments.local_campaign.vllm_context_recovery_phase6 import _response_rows
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _external_job_id,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _utc_now,
)
from experiments.rig_web_app.external_measured import register_external_measured_terminal
from ura.runner import CODE_VERSION
from ura.targets.local import DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS


SCHEMA = "ura-local-bounded-output-continuation-phase6/1"
LAUNCH_SCHEMA = "ura-local-bounded-output-continuation-phase6-launch/1"
SNAPSHOT_SCHEMA = "ura-local-bounded-output-prior-interruption/1"
STATE_SCHEMA = "ura-local-bounded-output-continuation-phase6-unit-state/1"
AMENDMENT_SCHEMA = "ura-gate5-local-bounded-output-continuation/1"
PRIOR_ROOT_SCHEMA = "ura-local-truncation-recovery-phase6-continuation-launch/1"
EXPECTED_UNIT_COUNT = 25
FIRST_RECOVERY_INDEX = 21
PARTIAL_INDEX = 22
EXPECTED_PARTIAL_SELECTED = 64
EXPECTED_DURABLE = 36
EXPECTED_FAILED = 14
EXPECTED_LENGTH = 21
EXPECTED_USABLE = 1
EXPECTED_RECOVERY_ROWS = 170
EXPECTED_TOTAL_ROWS = 4_463
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def bounded_local_config(
    config: Mapping[str, Any],
    *,
    spec: str,
    generation_tokens: int,
    timeout: float,
) -> dict[str, Any]:
    """Keep hardware-fit context while applying the readiness output bound."""

    if set(config) != {spec} or not isinstance(config[spec], dict):
        raise ValueError("bounded-output config changed identity")
    entry = dict(config[spec])
    if spec.startswith("vllm:"):
        if entry.get("max_model_len") != -1:
            raise ValueError("bounded vLLM recovery lost hardware-fit context")
        entry["max_tokens"] = generation_tokens
    elif spec.startswith("ollama:"):
        if entry.get("num_ctx") != "fit":
            raise ValueError("bounded Ollama recovery lost hardware-fit context")
        entry["num_predict"] = generation_tokens
    else:
        raise ValueError("bounded-output recovery supports only local providers")
    entry["timeout"] = timeout
    return {spec: entry}


def _canonical_campaign(path: Path, *, label: str) -> Path:
    result = path.resolve(strict=True)
    if result.is_symlink() or result.parent.name != "engineering":
        raise ValueError(f"{label} is not one canonical engineering campaign")
    return result


def _completed_result(
    *, unit_id: str, item: Mapping[str, Any], prior_root: Path
) -> dict[str, Any]:
    state_path = prior_root / "units" / unit_id / "state.json"
    level1_path = prior_root / "units" / unit_id / "level1.json"
    state = _load_json(state_path, label=f"{unit_id} retained state")
    selected = int(state.get("selected_records", 0))
    attempted, successful, missing = _counts_from_level1(
        _load_json(level1_path, label=f"{unit_id} retained Level 1")
    )
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
        or state.get("source_lane") != item.get("source_lane")
        or selected < 1
        or attempted != selected
    ):
        raise ValueError(f"{unit_id} retained completion changed")
    return {
        "attempted": attempted,
        "level1": _descriptor(level1_path, label=f"{unit_id} retained Level 1"),
        "missing": missing,
        "result_root": state["result_root"],
        "selected_records": selected,
        "state": _descriptor(state_path, label=f"{unit_id} retained state"),
        "successful": successful,
    }


def _partial_selector(
    *, item: Mapping[str, Any], unit_id: str, prior_root: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    state_path = prior_root / "units" / unit_id / "state.json"
    state = _load_json(state_path, label="bounded-output interrupted state")
    argv = state.get("runner_argv")
    if (
        state.get("schema") != PRIOR_STATE_SCHEMA
        or state.get("unit_id") != unit_id
        or state.get("selected_records") != EXPECTED_PARTIAL_SELECTED
        or not isinstance(argv, list)
        or any(not isinstance(value, str) for value in argv)
    ):
        raise ValueError("bounded-output interrupted state changed")
    result_root = Path(str(state.get("result_root", ""))).resolve(strict=True)
    attempts, outcomes, attempt_files, response_files = _durable_outcomes(result_root)
    responses = _response_rows(result_root)
    selected_rows, audits = _selected_rows(argv)
    prior_selector, _binding = run_matrix.load_recovery_completed_prefix(
        _option(argv, "--recovery-completed-prefix"),
        _option(argv, "--recovery-completed-prefix-sha256"),
    )
    if prior_selector is None:
        raise ValueError("interrupted bounded-output unit lost its selector")
    eligible_rows: dict[str, list[Any]] = {}
    for corpus, rows in selected_rows.items():
        eligible_rows[corpus], _audit = run_matrix.apply_recovery_completed_prefix(
            corpus, rows, audits[corpus], prior_selector
        )
    selected_ids = {
        corpus: [row.id for row in rows] for corpus, rows in selected_rows.items()
    }
    eligible_ids = {
        corpus: [row.id for row in rows] for corpus, rows in eligible_rows.items()
    }
    length_ids = length_ended_datapoint_ids(attempts=attempts, responses=responses)
    selector, summary = build_truncation_selection(
        selected_ids=selected_ids,
        eligible_ids=eligible_ids,
        outcomes=outcomes,
        length_ended_ids=length_ids,
    )
    failed = sum(value == "failed_output" for value in outcomes.values())
    usable = len(outcomes) - failed - len(length_ids)
    if (
        len(outcomes) != EXPECTED_DURABLE
        or failed != EXPECTED_FAILED
        or len(length_ids) != EXPECTED_LENGTH
        or usable != EXPECTED_USABLE
        or summary.get("recovery_records") != EXPECTED_PARTIAL_SELECTED - EXPECTED_USABLE
    ):
        raise ValueError("interrupted output-condition partition changed")
    return selector, {
        "attempt_files": [
            _descriptor(path, label="interrupted bounded-output attempts")
            for path in attempt_files
        ],
        "durable_rows": len(outcomes),
        "failed_output_rows": failed,
        "length_ended_rows": len(length_ids),
        "never_attempted_rows": EXPECTED_PARTIAL_SELECTED - len(outcomes),
        "result_root": str(result_root),
        "response_files": [
            _descriptor(path, label="interrupted bounded-output responses")
            for path in response_files
        ],
        "state": _descriptor(state_path, label="interrupted bounded-output state"),
        "usable_rows_excluded": usable,
    }


def inspect_prior(
    *,
    prior_root: Path,
    inventory: Mapping[str, Any],
    runner_root: Path,
    profile_registry: Path,
) -> dict[str, Any]:
    order = _unit_order(inventory)
    if (
        len(order) != EXPECTED_UNIT_COUNT
        or sum(int(item["summary"]["recovery_records"]) for item in inventory["units"])
        != EXPECTED_TOTAL_ROWS
        or (prior_root / "completion.json").exists()
    ):
        raise ValueError("prior bounded-output campaign shape changed")
    launch_path = prior_root / "launch.json"
    launch = _load_json(launch_path, label="prior bounded-output launch")
    if (
        launch.get("schema") != PRIOR_ROOT_SCHEMA
        or launch.get("unit_order") != order[2:]
        or launch.get("target_answer_retries") != 1
        or launch.get("no_completed_rows_repeated") is not True
    ):
        raise ValueError("prior bounded-output launch changed")
    retained: dict[str, dict[str, Any]] = {}
    for index in range(2, 20):
        unit_id = order[index]
        retained[unit_id] = _completed_result(
            unit_id=unit_id,
            item=inventory["units"][index],
            prior_root=prior_root,
        )
    for index in (20, 22, 23, 24):
        unit_id = order[index]
        if (
            (prior_root / "units" / unit_id / "state.json").exists()
            or (runner_root / unit_id / prior_root.name).exists()
        ):
            raise ValueError(f"{unit_id} is not an unstarted prior unit")
    partial_id = order[PARTIAL_INDEX - 1]
    selector, partial = _partial_selector(
        item=inventory["units"][PARTIAL_INDEX - 1],
        unit_id=partial_id,
        prior_root=prior_root,
    )
    items: list[dict[str, Any]] = []
    for index in range(FIRST_RECOVERY_INDEX - 1, EXPECTED_UNIT_COUNT):
        copied = dict(inventory["units"][index])
        copied["summary"] = dict(copied["summary"])
        spec = str(copied["local_spec"])
        unprofiled = dict(copied["hardware_fit_local_config"][spec])
        unprofiled.pop("max_tokens", None)
        unprofiled.pop("num_predict", None)
        unprofiled.pop("timeout", None)
        profiled, profile = apply_profile(
            spec, unprofiled, path=profile_registry
        )
        if profile is None:
            raise ValueError(f"bounded-output recovery requires a profile for {spec!r}")
        generation_field = "max_tokens" if spec.startswith("vllm:") else "num_predict"
        copied["hardware_fit_local_config"] = bounded_local_config(
            copied["hardware_fit_local_config"],
            spec=spec,
            generation_tokens=int(profiled[generation_field]),
            timeout=float(profiled["timeout"]),
        )
        if index == PARTIAL_INDEX - 1:
            copied["recovery_selection"] = selector
            copied["summary"]["recovery_records"] = EXPECTED_PARTIAL_SELECTED - EXPECTED_USABLE
        items.append(copied)
    rows = sum(int(item["summary"]["recovery_records"]) for item in items)
    if rows != EXPECTED_RECOVERY_ROWS:
        raise ValueError("bounded-output continuation row total changed")
    return {
        "launch": _descriptor(launch_path, label="prior bounded-output launch"),
        "order": order,
        "partial": partial,
        "recovery_inventory": {"units": items},
        "retained_results": retained,
        "retained_successful_generations": sum(
            item["successful"] for item in retained.values()
        ),
        "retained_target_attempts": sum(item["attempted"] for item in retained.values()),
    }


def run(args: argparse.Namespace) -> int:
    if _HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    if Path(f"/proc/{args.interrupted_controller_pid}").exists():
        raise ValueError("interrupted controller process is still alive")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = (work_root / "runs/thesis/runner").resolve(strict=True)
    prior_root = _canonical_campaign(args.prior_continuation_root, label="prior root")
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh bounded-output continuation root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("bounded-output root must be one direct engineering campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(_stable_file(project_revision, label="project revision")).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    inventory_path = args.inventory.resolve(strict=True)
    inventory = load_inventory(inventory_path, args.inventory_sha256)
    profile_source = args.profile_registry.resolve(strict=True)
    profile_bytes = _stable_file(profile_source, label="local-model profile registry")
    inspected = inspect_prior(
        prior_root=prior_root,
        inventory=inventory,
        runner_root=runner_root,
        profile_registry=profile_source,
    )

    control_root.mkdir(mode=0o700)
    for name in ("units", "inputs", "configs"):
        (control_root / name).mkdir(mode=0o700)
    profile_snapshot = control_root / "inputs/local-model-profiles.json"
    with profile_snapshot.open("xb") as handle:
        handle.write(profile_bytes)
    marker_path = prior_root / "interruption.json"
    if marker_path.exists() or (prior_root / ".exit").exists():
        raise FileExistsError("prior bounded-output terminal marker already exists")
    marker = {
        "schema": "ura-local-hardware-fit-continuation-interrupted/1",
        "status": "interrupted",
        "reason": "unbounded_generation_output_policy",
        "exit_code": 125,
        "interrupted_at_utc": _utc_now(),
        "durable_partial_rows": EXPECTED_DURABLE,
        "successful_rows_repeated": 0,
    }
    _create_json(marker_path, marker)
    with (prior_root / ".exit").open("xb") as handle:
        handle.write(b"125\n")
    register_external_measured_terminal(
        work_root / "runs",
        job_id=_external_job_id(prior_root, inspected["order"][PARTIAL_INDEX - 1]),
        exit_code=125,
    )
    publish_target_execution(
        work_root=work_root,
        control_root=prior_root,
        target_attempts=int(inspected["retained_target_attempts"]) + EXPECTED_DURABLE,
        successful_target_generations=(
            int(inspected["retained_successful_generations"])
            + EXPECTED_DURABLE
            - EXPECTED_FAILED
        ),
    )
    finish_child_controller(work_root=work_root, control_root=prior_root, exit_code=125)

    configured = configure_units(
        inspected["recovery_inventory"],
        control_root=control_root,
        start_index=FIRST_RECOVERY_INDEX,
    )
    recovery_order = [unit.unit_id for unit, _path, _sha in configured]
    if recovery_order != inspected["order"][FIRST_RECOVERY_INDEX - 1 :]:
        raise ValueError("bounded-output continuation unit order changed")
    generation_by_model: dict[str, int] = {}
    deadline_by_model: dict[str, float] = {}
    for item in inspected["recovery_inventory"]["units"]:
        spec = str(item["local_spec"])
        entry = item["hardware_fit_local_config"][spec]
        field = "max_tokens" if spec.startswith("vllm:") else "num_predict"
        generation_by_model[spec] = int(entry[field])
        deadline_by_model[spec] = float(entry["timeout"])
    amendment = {
        "schema": AMENDMENT_SCHEMA,
        "approved_scope": "failed_length_ended_and_never_attempted_rows_only",
        "generation_tokens_by_model": dict(sorted(generation_by_model.items())),
        "per_request_deadline_seconds_by_model": dict(
            sorted(deadline_by_model.items())
        ),
        "profile_registry": _descriptor(
            profile_snapshot, label="local-model profile registry"
        ),
        "selected_records": EXPECTED_RECOVERY_ROWS,
        "target_answer_retries": 1,
        "max_total_target_calls": EXPECTED_RECOVERY_ROWS * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "per_unit_deadline_seconds": 86_400,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
    }
    amendment_path = control_root / "gate5-bounded-output-amendment.json"
    _create_json(amendment_path, amendment)
    amendment_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "created_at_utc": _utc_now(),
        "prior_root": str(prior_root),
        "prior_launch": inspected["launch"],
        "prior_marker": _descriptor(marker_path, label="prior interruption marker"),
        "partial": inspected["partial"],
        "retained_results": inspected["retained_results"],
    }
    snapshot_path = control_root / "prior-interruption.json"
    _create_json(snapshot_path, snapshot)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "project_revision": _descriptor(project_revision, label="project revision"),
        "inventory": _descriptor(inventory_path, label="hardware-fit inventory"),
        "prior_interruption": _descriptor(snapshot_path, label="prior interruption"),
        "gate5_amendment": _descriptor(amendment_path, label="Gate 5 amendment"),
        "profile_registry": _descriptor(
            profile_snapshot, label="local-model profile registry"
        ),
        "unit_order": recovery_order,
        "selected_records": EXPECTED_RECOVERY_ROWS,
        "target_answer_retries": 1,
        "no_valid_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_bounded_output_continuation",
        hard_stop_hours=168,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    attempts = successful = missing = 0
    for unit, selector_path, selector_sha in configured:
        try:
            result = _run_unit(
                unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=project_revision,
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=selector_path,
                recovery_sha256=selector_sha,
                expected_commit=args.expected_commit,
                framework_lock_id=_framework_lock_id(),
                admission_sha256=amendment_sha,
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
                state_schema=STATE_SCHEMA,
            )
            results[unit.unit_id] = result
            attempts += int(result["target_attempts"])
            successful += int(result["successful_target_generations"])
            missing += int(result["missing_responses"])
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            failures[unit.unit_id] = {
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
            }
    completion = {
        "schema": SCHEMA,
        "status": "complete" if not failures else "complete_with_failures",
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "prior_interruption": launch["prior_interruption"],
        "inventory": launch["inventory"],
        "gate5_amendment": launch["gate5_amendment"],
        "unit_order": recovery_order,
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempts,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "selected_records": EXPECTED_RECOVERY_ROWS,
        "successful_rows_repeated": 0,
        "historical_rows_mutated": False,
        "cross_output_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    completion_path = control_root / "completion.json"
    _create_json(completion_path, completion)
    exit_code = int(completion["controller_exit_code"])
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{exit_code}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=attempts,
        successful_target_generations=successful,
    )
    finish_child_controller(work_root=work_root, control_root=control_root, exit_code=exit_code)
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-continuation-root", type=Path, required=True)
    parser.add_argument("--interrupted-controller-pid", type=int, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--profile-registry", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--project-revision", type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", default="default")
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.interrupted_controller_pid < 2:
        raise ValueError("interrupted controller PID is invalid")
    if _HEX64.fullmatch(args.inventory_sha256) is None:
        raise ValueError("inventory SHA-256 is invalid")
    if _HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
