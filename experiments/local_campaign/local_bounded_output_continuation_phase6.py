"""Resume the interrupted hardware-fit tail under a finite output profile.

The original controller is immutable evidence of a bad execution condition: an
omitted vLLM output cap allowed LLaVA to spend its full 32,768-token context on
individual answers. A stopped successor then exercised an unprofiled
25,000-token cap, reserved one target call and produced no durable measured row.
This successor validates both roots, retains completed metric units, excludes
the one usable durable row in the original interrupted unit, and runs only the
remaining 170 identities under measured per-model profiles.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments import run_matrix
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
    SNAPSHOT_SCHEMA as PRIOR_SNAPSHOT_SCHEMA,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    STATE_SCHEMA as PRIOR_STATE_SCHEMA,
)
from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
    _unit_order,
)
from experiments.local_campaign.local_truncation_recovery_execution_phase6 import (
    STATE_SCHEMA as BASE_STATE_SCHEMA,
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
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _external_job_id,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _utc_now,
    _validate_descriptor,
)
from experiments.local_model_profiles import apply_profile
from experiments.rig_web_app.external_measured import load_external_measured_job
from ura.runner import CODE_VERSION

SCHEMA = "ura-local-bounded-output-continuation-phase6/3"
LAUNCH_SCHEMA = "ura-local-bounded-output-continuation-phase6-launch/2"
SNAPSHOT_SCHEMA = "ura-local-bounded-output-prior-interruption/2"
STATE_SCHEMA = "ura-local-bounded-output-continuation-phase6-unit-state/2"
AMENDMENT_SCHEMA = "ura-gate5-local-bounded-output-continuation/2"
PRIOR_ROOT_SCHEMA = "ura-local-truncation-recovery-phase6-continuation-launch/1"
INVALID_LAUNCH_SCHEMA = "ura-local-bounded-output-continuation-phase6-launch/1"
INVALID_SNAPSHOT_SCHEMA = "ura-local-bounded-output-prior-interruption/1"
INVALID_STATE_SCHEMA = "ura-local-bounded-output-continuation-phase6-unit-state/1"
INVALID_RUNNER_VERSION = "ura-runner/2.30"
INVALID_EXPECTED_COMMIT = "24a6bb8268cde80709515dc7c5a202db59de5a40"
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


def _validate_prior_terminal(prior_root: Path) -> dict[str, Any]:
    marker_path = prior_root / "interruption.json"
    marker = _load_json(marker_path, label="prior bounded-output interruption marker")
    if (
        set(marker)
        != {
            "schema",
            "status",
            "reason",
            "exit_code",
            "interrupted_at_utc",
            "durable_partial_rows",
            "successful_rows_repeated",
        }
        or marker.get("schema") != "ura-local-hardware-fit-continuation-interrupted/1"
        or marker.get("status") != "interrupted"
        or marker.get("reason") != "unbounded_generation_output_policy"
        or marker.get("exit_code") != 125
        or not isinstance(marker.get("interrupted_at_utc"), str)
        or marker.get("durable_partial_rows") != EXPECTED_DURABLE
        or marker.get("successful_rows_repeated") != 0
        or _stable_file(prior_root / ".exit", label="prior bounded-output exit") != b"125\n"
        or (prior_root / "completion.json").exists()
    ):
        raise ValueError("prior bounded-output terminal changed")
    return _descriptor(marker_path, label="prior bounded-output interruption marker")


def _one_file(root: Path, pattern: str, *, label: str) -> Path:
    paths = sorted(root.glob(pattern))
    if len(paths) != 1:
        raise ValueError(f"{label} did not resolve exactly one file")
    return paths[0]


def _validate_invalid_result_root(result_root: Path) -> dict[str, Any]:
    """Prove the abandoned condition produced no durable measured response."""

    empty_files = {
        label: _one_file(result_root, pattern, label=label)
        for label, pattern in {
            "attempts": "*.attempts.jsonl",
            "responses": "*.responses.jsonl",
            "results": "*.results.jsonl",
            "trails": "*.trails.jsonl",
        }.items()
    }
    if any(_stable_file(path, label=f"invalid-condition {label}") for label, path in empty_files.items()):
        raise ValueError("invalid output condition unexpectedly produced a durable row")
    if list(result_root.glob("*.complete.json")):
        raise ValueError("invalid output condition unexpectedly completed")
    manifest_path = _one_file(result_root, "*.manifest.json", label="invalid-condition manifest")
    manifest = _load_json(manifest_path, label="invalid-condition manifest")
    target = manifest.get("config", {}).get("components", {}).get("target", {})
    if (
        manifest.get("code_version") != INVALID_RUNNER_VERSION
        or manifest.get("n_datapoints") != 3
        or manifest.get("n_attempts") != 0
        or not isinstance(target, dict)
        or target.get("max_model_len") != -1
        or target.get("max_tokens") != 25_000
        or target.get("timeout") != 120.0
    ):
        raise ValueError("invalid output-condition manifest changed")
    error_path = _one_file(result_root, "*.error.json", label="invalid-condition error")
    error = _load_json(error_path, label="invalid-condition error")
    budget = error.get("call_budget_snapshot")
    message = error.get("message")
    if (
        error.get("status") != "error"
        or error.get("exception_type") != "ExternalCallFailure"
        or error.get("execution_started") is not True
        or error.get("completed_attempts") != 0
        or not isinstance(budget, dict)
        or budget.get("target_calls") != 1
        or budget.get("judge_calls") != 0
        or budget.get("http_attempts") != 0
        or budget.get("max_target_calls") != 6
        or not isinstance(message, str)
        or "generation exceeded the configured hard 120s deadline" not in message
    ):
        raise ValueError("invalid output-condition failure changed")
    return {
        "error": _descriptor(error_path, label="invalid-condition error"),
        "manifest": _descriptor(manifest_path, label="invalid-condition manifest"),
        "measured_target_attempts": 1,
        "durable_measured_rows": 0,
    }


def inspect_invalid_condition(
    *,
    invalid_root: Path,
    prior_root: Path,
    inventory: Mapping[str, Any],
    runner_root: Path,
    work_root: Path,
) -> dict[str, Any]:
    """Validate the stopped 25,000-token attempt before superseding it."""

    order = _unit_order(inventory)
    if any(
        (invalid_root / name).exists()
        for name in ("completion.json", "interruption.json", ".exit")
    ):
        raise ValueError("invalid output-condition controller is already terminal")
    launch_path = invalid_root / "launch.json"
    launch = _load_json(launch_path, label="invalid output-condition launch")
    inventory_descriptor = launch.get("inventory")
    if not isinstance(inventory_descriptor, dict):
        raise ValueError("invalid output-condition launch changed")
    invalid_inventory_path = _validate_descriptor(
        inventory_descriptor, label="invalid output-condition inventory"
    )
    if _load_json(invalid_inventory_path, label="invalid output-condition inventory") != inventory:
        raise ValueError("invalid output-condition inventory changed")
    prior_snapshot_path = _validate_descriptor(
        launch.get("prior_interruption"), label="invalid output-condition prior snapshot"
    )
    prior_snapshot = _load_json(
        prior_snapshot_path, label="invalid output-condition prior snapshot"
    )
    if (
        launch.get("schema") != INVALID_LAUNCH_SCHEMA
        or launch.get("expected_commit") != INVALID_EXPECTED_COMMIT
        or launch.get("runner_code_version") != INVALID_RUNNER_VERSION
        or launch.get("unit_order") != order[FIRST_RECOVERY_INDEX - 1 :]
        or launch.get("selected_records") != EXPECTED_RECOVERY_ROWS
        or launch.get("target_answer_retries") != 1
        or launch.get("no_valid_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
        or prior_snapshot_path != invalid_root / "prior-interruption.json"
        or prior_snapshot.get("schema") != INVALID_SNAPSHOT_SCHEMA
        or prior_snapshot.get("prior_root") != str(prior_root)
    ):
        raise ValueError("invalid output-condition launch changed")
    state_paths = sorted(invalid_root.glob("units/*/state.json"))
    first_id = order[FIRST_RECOVERY_INDEX - 1]
    state_path = invalid_root / "units" / first_id / "state.json"
    if state_paths != [state_path]:
        raise ValueError("invalid output-condition measured-state partition changed")
    state = _load_json(state_path, label="invalid output-condition measured state")
    result_root = Path(str(state.get("result_root", ""))).resolve(strict=True)
    expected_result_root = (runner_root / first_id / invalid_root.name).resolve(strict=True)
    if (
        state.get("schema") != INVALID_STATE_SCHEMA
        or state.get("unit_id") != first_id
        or state.get("source_lane")
        != inventory["units"][FIRST_RECOVERY_INDEX - 1].get("source_lane")
        or state.get("selected_records") != 3
        or state.get("target_answer_retries") != 1
        or state.get("target_call_cap") != 6
        or result_root != expected_result_root
    ):
        raise ValueError("invalid output-condition measured state changed")
    for unit_id in order[FIRST_RECOVERY_INDEX:]:
        if (runner_root / unit_id / invalid_root.name).exists():
            raise ValueError(f"{unit_id} unexpectedly has an invalid-condition measured root")
    measured = _validate_invalid_result_root(result_root)
    job = load_external_measured_job(
        work_root / "runs", _external_job_id(invalid_root, first_id), probe_session=False
    )
    if (
        job is None
        or job.state != "failed"
        or job.exit_code != 1
        or job.expected_commit != INVALID_EXPECTED_COMMIT
        or job.out_dir != result_root
    ):
        raise ValueError("invalid output-condition external job terminal changed")
    return {
        **measured,
        "external_terminal": _descriptor(
            job.registration_dir / "terminal.json", label="invalid-condition external terminal"
        ),
        "launch": _descriptor(launch_path, label="invalid output-condition launch"),
        "root": str(invalid_root),
        "state": _descriptor(state_path, label="invalid output-condition measured state"),
    }


def _validate_invalid_snapshot(value: object) -> Path:
    if not isinstance(value, dict) or set(value) != {
        "durable_measured_rows",
        "error",
        "external_terminal",
        "launch",
        "manifest",
        "marker",
        "measured_target_attempts",
        "root",
        "state",
    }:
        raise ValueError("invalid output-condition snapshot changed")
    root = Path(str(value.get("root", ""))).resolve(strict=True)
    if root.is_symlink() or root.parent.name != "engineering":
        raise ValueError("invalid output-condition snapshot root changed")
    launch_path = _validate_descriptor(value["launch"], label="invalid-condition launch")
    state_path = _validate_descriptor(value["state"], label="invalid-condition state")
    marker_path = _validate_descriptor(value["marker"], label="invalid-condition marker")
    _validate_descriptor(value["error"], label="invalid-condition error")
    _validate_descriptor(value["manifest"], label="invalid-condition manifest")
    _validate_descriptor(value["external_terminal"], label="invalid-condition terminal")
    marker = _load_json(marker_path, label="invalid-condition marker")
    if (
        launch_path != root / "launch.json"
        or state_path.parent.parent.parent != root
        or marker_path != root / "interruption.json"
        or value.get("measured_target_attempts") != 1
        or value.get("durable_measured_rows") != 0
        or set(marker)
        != {
            "schema",
            "status",
            "reason",
            "exit_code",
            "interrupted_at_utc",
            "measured_target_attempts",
            "durable_measured_rows",
            "successful_rows_repeated",
        }
        or marker.get("schema")
        != "ura-local-bounded-output-invalid-condition-interrupted/1"
        or marker.get("status") != "interrupted"
        or marker.get("reason") != "unexercised_readiness_profile"
        or marker.get("exit_code") != 125
        or marker.get("measured_target_attempts") != 1
        or marker.get("durable_measured_rows") != 0
        or marker.get("successful_rows_repeated") != 0
        or not isinstance(marker.get("interrupted_at_utc"), str)
        or _stable_file(root / ".exit", label="invalid-condition exit") != b"125\n"
        or (root / "completion.json").exists()
    ):
        raise ValueError("invalid output-condition terminal snapshot changed")
    return root


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


def _completed_result(*, unit_id: str, item: Mapping[str, Any], prior_root: Path) -> dict[str, Any]:
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
    selected_ids = {corpus: [row.id for row in rows] for corpus, rows in selected_rows.items()}
    eligible_ids = {corpus: [row.id for row in rows] for corpus, rows in eligible_rows.items()}
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
            _descriptor(path, label="interrupted bounded-output attempts") for path in attempt_files
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
        if (prior_root / "units" / unit_id / "state.json").exists() or (
            runner_root / unit_id / prior_root.name
        ).exists():
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
        profiled, profile = apply_profile(spec, unprofiled, path=profile_registry)
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
        "retained_successful_generations": sum(item["successful"] for item in retained.values()),
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
    invalid_root = _canonical_campaign(
        args.invalid_condition_root, label="invalid output-condition root"
    )
    if invalid_root == prior_root:
        raise ValueError("invalid output-condition root must differ from the prior root")
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh bounded-output continuation root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("bounded-output root must be one direct engineering campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if (
        hashlib.sha256(_stable_file(project_revision, label="project revision")).hexdigest()
        != args.project_revision_sha256
    ):
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
    prior_marker = _validate_prior_terminal(prior_root)
    invalid = inspect_invalid_condition(
        invalid_root=invalid_root,
        prior_root=prior_root,
        inventory=inventory,
        runner_root=runner_root,
        work_root=work_root,
    )

    control_root.mkdir(mode=0o700)
    for name in ("units", "inputs", "configs"):
        (control_root / name).mkdir(mode=0o700)
    profile_snapshot = control_root / "inputs/local-model-profiles.json"
    with profile_snapshot.open("xb") as handle:
        handle.write(profile_bytes)
    marker_path = invalid_root / "interruption.json"
    marker = {
        "schema": "ura-local-bounded-output-invalid-condition-interrupted/1",
        "status": "interrupted",
        "reason": "unexercised_readiness_profile",
        "exit_code": 125,
        "interrupted_at_utc": _utc_now(),
        "measured_target_attempts": invalid["measured_target_attempts"],
        "durable_measured_rows": invalid["durable_measured_rows"],
        "successful_rows_repeated": 0,
    }
    _create_json(marker_path, marker)
    with (invalid_root / ".exit").open("xb") as handle:
        handle.write(b"125\n")
    publish_target_execution(
        work_root=work_root,
        control_root=invalid_root,
        target_attempts=int(invalid["measured_target_attempts"]),
        successful_target_generations=0,
    )
    finish_child_controller(work_root=work_root, control_root=invalid_root, exit_code=125)

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
        "per_request_deadline_seconds_by_model": dict(sorted(deadline_by_model.items())),
        "profile_registry": _descriptor(profile_snapshot, label="local-model profile registry"),
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
        "prior_marker": prior_marker,
        "invalid_condition_attempt": {
            **invalid,
            "marker": _descriptor(marker_path, label="invalid-condition interruption marker"),
        },
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
        "profile_registry": _descriptor(profile_snapshot, label="local-model profile registry"),
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
        "target_answer_retries": 1,
        "prior_interruption": launch["prior_interruption"],
        "inventory": launch["inventory"],
        "gate5_amendment": launch["gate5_amendment"],
        "profile_registry": launch["profile_registry"],
        "launch": _descriptor(control_root / "launch.json", label="bounded-output launch"),
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


def validate_alignment_prerequisite(completion_path: Path, *, runner_root: Path) -> dict[str, Any]:
    """Validate the bounded continuation and expose its retained DeepSeek unit."""

    resolved = completion_path.resolve(strict=True)
    control_root = resolved.parent
    completion = _load_json(resolved, label="bounded-output completion")
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "prior_interruption",
        "inventory",
        "gate5_amendment",
        "profile_registry",
        "launch",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "selected_records",
        "successful_rows_repeated",
        "historical_rows_mutated",
        "cross_output_policy_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or _HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != CODE_VERSION
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_failures") != {}
        or completion.get("selected_records") != EXPECTED_RECOVERY_ROWS
        or completion.get("successful_rows_repeated") != 0
        or completion.get("historical_rows_mutated") is not False
        or completion.get("cross_output_policy_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("bounded-output completion contract changed")
    launch_path = _validate_descriptor(completion["launch"], label="bounded-output launch")
    profile_path = _validate_descriptor(
        completion["profile_registry"], label="local-model profile registry"
    )
    launch = _load_json(launch_path, label="bounded-output launch")
    if (
        launch_path != control_root / "launch.json"
        or profile_path != control_root / "inputs/local-model-profiles.json"
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("profile_registry") != completion["profile_registry"]
        or launch.get("inventory") != completion["inventory"]
        or launch.get("prior_interruption") != completion["prior_interruption"]
        or launch.get("gate5_amendment") != completion["gate5_amendment"]
        or launch.get("unit_order") != completion["unit_order"]
        or launch.get("selected_records") != EXPECTED_RECOVERY_ROWS
        or launch.get("target_answer_retries") != 1
        or launch.get("no_valid_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
    ):
        raise ValueError("bounded-output launch contract changed")
    inventory_path = _validate_descriptor(completion["inventory"], label="bounded-output inventory")
    inventory = load_inventory(inventory_path, str(completion["inventory"].get("sha256", "")))
    order = _unit_order(inventory)
    recovery_order = order[FIRST_RECOVERY_INDEX - 1 :]
    results = completion.get("unit_results")
    if (
        len(order) != EXPECTED_UNIT_COUNT
        or completion.get("unit_order") != recovery_order
        or not isinstance(results, dict)
        or set(results) != set(recovery_order)
    ):
        raise ValueError("bounded-output recovery inventory changed")
    completion_descriptor = _descriptor(resolved, label="bounded-output completion")
    successful = missing = 0
    for index, unit_id in enumerate(recovery_order, start=FIRST_RECOVERY_INDEX - 1):
        item = inventory["units"][index]
        selected = int(item["summary"]["recovery_records"])
        if index == PARTIAL_INDEX - 1:
            selected -= EXPECTED_USABLE
        recovery_corpora = item["recovery_selection"]["corpora"]
        corpus = next(iter(recovery_corpora)) if len(recovery_corpora) == 1 else None
        validated = _validate_metric_result(
            results[unit_id],
            logical_lane=unit_id,
            physical_unit=unit_id,
            source_lane=str(item["source_lane"]),
            corpus=corpus,
            selected_records=selected,
            runner_root=runner_root.resolve(strict=True),
            control_root=control_root,
            state_schema=STATE_SCHEMA,
            completion=completion_descriptor,
        )
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    if completion.get("target_execution") != {
        "target_attempts": EXPECTED_RECOVERY_ROWS,
        "successful_target_generations": successful,
        "missing_responses": missing,
    }:
        raise ValueError("bounded-output recovery accounting changed")

    snapshot_path = _validate_descriptor(
        completion["prior_interruption"], label="bounded-output interruption"
    )
    snapshot = _load_json(snapshot_path, label="bounded-output interruption")
    if (
        snapshot_path != control_root / "prior-interruption.json"
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or snapshot.get("prior_root") is None
        or set(snapshot)
        != {
            "schema",
            "created_at_utc",
            "prior_root",
            "prior_launch",
            "prior_marker",
            "invalid_condition_attempt",
            "partial",
            "retained_results",
        }
    ):
        raise ValueError("bounded-output interruption changed")
    _validate_invalid_snapshot(snapshot["invalid_condition_attempt"])
    prior_root = Path(str(snapshot["prior_root"])).resolve(strict=True)
    if snapshot["prior_marker"] != _validate_prior_terminal(prior_root):
        raise ValueError("prior bounded-output terminal descriptor changed")
    prior_launch_path = _validate_descriptor(
        snapshot.get("prior_launch"), label="interrupted continuation launch"
    )
    if prior_launch_path != prior_root / "launch.json":
        raise ValueError("interrupted continuation launch placement changed")
    prior_launch = _load_json(prior_launch_path, label="interrupted continuation launch")
    retained_snapshot_path = _validate_descriptor(
        prior_launch.get("prior_interruption"), label="retained hardware-fit snapshot"
    )
    retained_snapshot = _load_json(retained_snapshot_path, label="retained hardware-fit snapshot")
    retained = retained_snapshot.get("retained_results")
    if (
        retained_snapshot.get("schema") != PRIOR_SNAPSHOT_SCHEMA
        or retained_snapshot.get("order") != order
        or not isinstance(retained, dict)
        or set(retained) != set(order[:2])
    ):
        raise ValueError("retained hardware-fit snapshot changed")
    deepseek_id = order[0]
    deepseek_item = inventory["units"][0]
    retained_control_root = Path(str(retained_snapshot.get("prior_control_root", ""))).resolve(
        strict=True
    )
    recovery_corpora = deepseek_item["recovery_selection"]["corpora"]
    corpus = next(iter(recovery_corpora)) if len(recovery_corpora) == 1 else None
    deepseek = _validate_metric_result(
        retained[deepseek_id],
        logical_lane=deepseek_id,
        physical_unit=deepseek_id,
        source_lane=str(deepseek_item["source_lane"]),
        corpus=corpus,
        selected_records=int(deepseek_item["summary"]["recovery_records"]),
        runner_root=runner_root.resolve(strict=True),
        control_root=retained_control_root,
        state_schema=BASE_STATE_SCHEMA,
        completion=_descriptor(retained_snapshot_path, label="retained hardware-fit snapshot"),
    )
    return {
        "completion": completion_descriptor,
        "deepseek_id": deepseek_id,
        "deepseek_result": retained[deepseek_id],
        "deepseek_revision": str(deepseek["revision"]),
        "inventory": inventory,
        "unit_order": order,
    }


def validate_completion(completion_path: Path, *, runner_root: Path) -> dict[str, Any]:
    """Validate all final row strata for Phase 7 without pooling them."""

    prerequisite = validate_alignment_prerequisite(completion_path, runner_root=runner_root)
    resolved = completion_path.resolve(strict=True)
    control_root = resolved.parent
    completion = _load_json(resolved, label="bounded-output completion")
    inventory = prerequisite["inventory"]
    order = prerequisite["unit_order"]
    completion_descriptor = prerequisite["completion"]
    snapshot_path = _validate_descriptor(
        completion["prior_interruption"], label="bounded-output interruption"
    )
    snapshot = _load_json(snapshot_path, label="bounded-output interruption")
    prior_root = Path(str(snapshot["prior_root"])).resolve(strict=True)
    prior_launch_path = _validate_descriptor(
        snapshot["prior_launch"], label="interrupted continuation launch"
    )
    prior_launch = _load_json(prior_launch_path, label="interrupted continuation launch")
    retained_snapshot_path = _validate_descriptor(
        prior_launch["prior_interruption"], label="retained hardware-fit snapshot"
    )
    retained_snapshot = _load_json(retained_snapshot_path, label="retained hardware-fit snapshot")
    base_root = Path(str(retained_snapshot["prior_control_root"])).resolve(strict=True)
    base_results = retained_snapshot["retained_results"]
    middle_results = snapshot.get("retained_results")
    final_results = completion["unit_results"]
    if (
        not isinstance(middle_results, dict)
        or set(middle_results) != set(order[2:20])
        or set(final_results) != set(order[20:])
    ):
        raise ValueError("bounded-output retained result partition changed")

    terminal_states: dict[str, str] = {}
    lifecycle_roots: dict[str, str] = {}
    lifecycle_evidence: dict[str, dict[str, object]] = {}
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility: list[dict[str, object]] = []
    metric_markers: list[dict[str, object]] = []
    metric_revisions: dict[str, str] = {}
    sources: set[str] = set()
    successful = missing = selected_total = 0
    for index, (unit_id, item) in enumerate(zip(order, inventory["units"], strict=True)):
        if index < 2:
            result = base_results[unit_id]
            physical_root = base_root
            state_schema = BASE_STATE_SCHEMA
            evidence_completion = _descriptor(
                retained_snapshot_path, label="retained hardware-fit snapshot"
            )
        elif index < 20:
            result = middle_results[unit_id]
            physical_root = prior_root
            state_schema = PRIOR_STATE_SCHEMA
            evidence_completion = _descriptor(snapshot_path, label="bounded-output interruption")
        else:
            result = final_results[unit_id]
            physical_root = control_root
            state_schema = STATE_SCHEMA
            evidence_completion = completion_descriptor
        selected = int(item["summary"]["recovery_records"])
        if index == PARTIAL_INDEX - 1:
            selected -= EXPECTED_USABLE
        recovery_corpora = item["recovery_selection"]["corpora"]
        corpus = next(iter(recovery_corpora)) if len(recovery_corpora) == 1 else None
        validated = _validate_metric_result(
            result,
            logical_lane=unit_id,
            physical_unit=unit_id,
            source_lane=str(item["source_lane"]),
            corpus=corpus,
            selected_records=selected,
            runner_root=runner_root.resolve(strict=True),
            control_root=physical_root,
            state_schema=state_schema,
            completion=evidence_completion,
        )
        terminal_states[unit_id] = "measured_complete"
        lifecycle_roots[unit_id] = str(validated["root"])
        evidence = dict(validated["evidence"])
        if index == PARTIAL_INDEX - 1:
            evidence["interrupted_usable_row"] = dict(snapshot["partial"])
        lifecycle_evidence[unit_id] = evidence
        metric_roots[unit_id] = str(validated["root"])
        metric_evidence[unit_id] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_eligibility.append(dict(validated["eligibility_plan"]))
        metric_markers.extend(validated["completion_markers"])
        metric_revisions[unit_id] = str(validated["revision"])
        sources.add(str(validated["source"]))
        selected_total += selected
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    selected_total += EXPECTED_USABLE
    successful += EXPECTED_USABLE
    if (
        selected_total != EXPECTED_TOTAL_ROWS
        or successful + missing != EXPECTED_TOTAL_ROWS
        or len(sources) != 1
    ):
        raise ValueError("bounded-output final population accounting changed")
    revision_strata: dict[str, list[str]] = {}
    for lane, revision in metric_revisions.items():
        revision_strata.setdefault(revision, []).append(lane)
    partial_id = order[PARTIAL_INDEX - 1]
    return {
        "completion": completion_descriptor,
        "inventory": dict(completion["inventory"]),
        "runner_code_version": "mixed",
        "output_policy_stratum": "mixed_retained_and_profiled_response_allowance",
        "unit_order": order,
        "terminal_states": terminal_states,
        "lifecycle_roots": lifecycle_roots,
        "lifecycle_evidence": lifecycle_evidence,
        "lifecycle_revision_strata": dict(revision_strata),
        "lifecycle_project_revision_receipt_sha256": dict(metric_revisions),
        "metric_lane_order": list(order),
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility,
        "metric_completion_markers": metric_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": metric_revisions,
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": {
            "target_attempts": EXPECTED_TOTAL_ROWS,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "planned_unique_rows": EXPECTED_TOTAL_ROWS,
        "population_segments": {
            partial_id: {
                "profiled_rows": EXPECTED_PARTIAL_SELECTED - EXPECTED_USABLE,
                "retained_usable_rows": EXPECTED_USABLE,
                "security_metric_pooling_permitted": False,
            }
        },
        "successful_rows_repeated": 0,
        "cross_condition_pooling_permitted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prior-continuation-root", type=Path, required=True)
    parser.add_argument("--invalid-condition-root", type=Path, required=True)
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
