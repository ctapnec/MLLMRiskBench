"""Rerun only GPTGeoChat rows rejected by the old vLLM context cap.

The retained 12,288-token condition stays immutable. This controller verifies
its typed context-limit outcomes, builds an exact completed-ID selector, and
runs only those rows with native model context and the local maximum output.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments import run_matrix
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import _descriptor, _stable_file
from experiments.local_campaign.failed_output_recovery_phase6 import (
    _active_jsonl,
    _durable_outcomes,
    _jsonl,
    _selected_rows,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    CORPUS,
    RECOVERY_UNIT as INPUT_RECOVERY_UNIT,
    SOURCE_LANE,
    _validate_metric_result,
    validate_failed_completion,
    validate_phase7_completion as validate_input_recovery,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit,
    _create_json,
    _framework_lock_id,
    _historical_specs,
    _load_json,
    _option,
    _project_python,
    _replace_option,
    _run_unit,
    _sha256_json,
    _utc_now,
    _validate_descriptor,
)
from ura.data_models import Response
from ura.runner import CODE_VERSION, Runner


SCHEMA = "ura-vllm-context-recovery-phase6/1"
LAUNCH_SCHEMA = "ura-vllm-context-recovery-phase6-launch/1"
STATE_SCHEMA = "ura-vllm-context-recovery-phase6-unit-state/1"
UNIT_ID = "vllm-context-recovery-gptgeochat-qwen3-vl-native-max"
SELECTED_RECORDS = 2020
CONTEXT_RECOVERY_RECORDS = 230
OLD_MAX_MODEL_LEN = 12288
NEW_MAX_MODEL_LEN = None
NEW_MAX_TOKENS = None
EXPECTED_PROMPT_MIN = 12290
EXPECTED_PROMPT_MAX = 16705
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CONTEXT_REASON = re.compile(
    r"^vLLM prompt length ([0-9]+) exceeds admitted context limit ([0-9]+)$"
)


def build_context_selection(
    *,
    selected_ids: Mapping[str, Sequence[str]],
    eligible_ids: Mapping[str, Sequence[str]],
    outcomes: Mapping[str, str],
    expected_context_rows: int = CONTEXT_RECOVERY_RECORDS,
) -> tuple[dict[str, object], dict[str, int]]:
    """Exclude every row except a typed input-incompatible prior outcome."""

    if set(selected_ids) != {CORPUS} or set(eligible_ids) != {CORPUS}:
        raise ValueError("GPTGeoChat context recovery corpus inventory changed")
    selected = list(selected_ids[CORPUS])
    eligible = list(eligible_ids[CORPUS])
    if (
        len(selected) != SELECTED_RECORDS
        or len(set(selected)) != len(selected)
        or len(set(eligible)) != len(eligible)
        or not set(eligible).issubset(selected)
        or set(outcomes) != set(eligible)
    ):
        raise ValueError("GPTGeoChat context recovery identity inventory changed")
    allowed = {
        "usable_first_response",
        "recovered_after_retry",
        "failed_output",
        "input_incompatible",
    }
    if any(value not in allowed for value in outcomes.values()):
        raise ValueError("GPTGeoChat context recovery outcome is unsupported")
    remaining = [
        identifier for identifier in selected if outcomes.get(identifier) == "input_incompatible"
    ]
    if len(remaining) != expected_context_rows:
        raise ValueError(
            "GPTGeoChat context recovery does not contain the exact typed "
            f"population: {len(remaining)} != {expected_context_rows}"
        )
    completed = sorted(set(selected) - set(remaining))
    selector = {
        "schema": "ura-recovery-completed-selection/1",
        "corpora": {
            CORPUS: {
                "completed_record_count": len(completed),
                "selected_datapoint_ids_sha256": _sha256_json(selected),
                "completed_datapoint_ids": completed,
                "completed_datapoint_ids_sha256": _sha256_json(completed),
                "remaining_datapoint_ids_sha256": _sha256_json(remaining),
            }
        },
    }
    return selector, {
        "selected_records": len(selected),
        "prior_eligible_records": len(eligible),
        "completed_records_excluded": len(completed),
        "context_recovery_records": len(remaining),
    }


def with_larger_context(config: Mapping[str, Any]) -> dict[str, Any]:
    """Use native engine context and maximum output in one vLLM config."""

    if len(config) != 1:
        raise ValueError("Qwen context recovery config must contain one model")
    spec, value = next(iter(config.items()))
    if not isinstance(spec, str) or not spec.startswith("vllm:") or not isinstance(value, dict):
        raise ValueError("Qwen context recovery config identity changed")
    if value.get("max_model_len") != OLD_MAX_MODEL_LEN:
        raise ValueError("Qwen old admitted context changed")
    if value.get("max_tokens") != 4096:
        raise ValueError("Qwen completion allowance changed")
    updated = dict(value)
    updated.pop("max_model_len")
    updated.pop("max_tokens")
    return {spec: updated}


def _response_rows(result_root: Path) -> list[Response]:
    rows: list[Response] = []
    for path in _active_jsonl(result_root, "responses"):
        if path.name.endswith(".responses.checkpoint.jsonl"):
            rows.extend(
                Response.model_validate(record.get("response"))
                for record in Runner.load_response_checkpoint(path).values()
            )
        else:
            rows.extend(
                Response.model_validate(row)
                for row in _jsonl(path, label="GPTGeoChat recovery responses")
            )
    return rows


def _derive_context_selector(
    state_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    state = _load_json(state_path, label="GPTGeoChat input-recovery state")
    argv = state.get("runner_argv")
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        raise ValueError("GPTGeoChat input-recovery argv changed")
    selected_rows, audits = _selected_rows(argv)
    old_path = _option(argv, "--recovery-completed-prefix")
    old_sha = _option(argv, "--recovery-completed-prefix-sha256")
    old_recovery, _binding = run_matrix.load_recovery_completed_prefix(old_path, old_sha)
    if old_recovery is None:
        raise ValueError("GPTGeoChat input recovery lacks its prior selector")
    eligible_rows: dict[str, list[Any]] = {}
    for corpus, rows in selected_rows.items():
        eligible, _audit = run_matrix.apply_recovery_completed_prefix(
            corpus, rows, audits[corpus], old_recovery
        )
        eligible_rows[corpus] = eligible

    result_root = Path(str(state.get("result_root", "")))
    if (
        not result_root.is_absolute()
        or result_root.is_symlink()
        or result_root.resolve(strict=True) != result_root
    ):
        raise ValueError("GPTGeoChat input-recovery result root changed")
    attempts, outcomes, attempt_files, response_files = _durable_outcomes(result_root)
    selected_ids = {corpus: [row.id for row in rows] for corpus, rows in selected_rows.items()}
    eligible_ids = {corpus: [row.id for row in rows] for corpus, rows in eligible_rows.items()}
    selector, summary = build_context_selection(
        selected_ids=selected_ids,
        eligible_ids=eligible_ids,
        outcomes=outcomes,
    )

    context_ids = {
        identifier for identifier, value in outcomes.items() if value == "input_incompatible"
    }
    lengths: list[int] = []
    seen: set[str] = set()
    for response in _response_rows(result_root):
        datapoint_id = attempts.get(response.attempt_id)
        if datapoint_id not in context_ids:
            continue
        raw = response.raw
        match = CONTEXT_REASON.fullmatch(str(raw.get("target_input_reason", "")))
        if (
            raw.get("target_input_status") != "incompatible"
            or raw.get("target_input_category") != "context_limit_exceeded"
            or raw.get("target_input_error_type") != "LocalTargetInputError"
            or match is None
            or int(match.group(2)) != OLD_MAX_MODEL_LEN
            or datapoint_id in seen
        ):
            raise ValueError("GPTGeoChat typed context-limit evidence changed")
        seen.add(datapoint_id)
        lengths.append(int(match.group(1)))
    if (
        seen != context_ids
        or min(lengths, default=0) != EXPECTED_PROMPT_MIN
        or max(lengths, default=0) != EXPECTED_PROMPT_MAX
    ):
        raise ValueError("GPTGeoChat context-limit population bounds changed")
    snapshot = {
        "source_state": _descriptor(state_path, label="GPTGeoChat input-recovery state"),
        "result_root": str(result_root),
        "attempt_files": [_descriptor(path, label="GPTGeoChat attempts") for path in attempt_files],
        "response_files": [
            _descriptor(path, label="GPTGeoChat responses") for path in response_files
        ],
        "outcome_counts": dict(sorted(Counter(outcomes.values()).items())),
        "summary": summary,
        "prompt_tokens": {
            "minimum": min(lengths),
            "maximum": max(lengths),
            "old_admitted_context": OLD_MAX_MODEL_LEN,
            "new_admitted_context": NEW_MAX_MODEL_LEN,
            "completion_allowance": NEW_MAX_TOKENS,
        },
    }
    return selector, snapshot


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the exact larger-context condition for Phase 7."""

    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    value = _load_json(completion_path, label="vLLM context-recovery completion")
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "input_recovery_completion",
        "recovery_selection",
        "context_config",
        "gate5_amendment",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "no_completed_rows_repeated",
        "cross_context_condition_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(value) != fields
        or value.get("schema") != SCHEMA
        or value.get("status") != "complete"
        or value.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(value.get("expected_commit", ""))) is None
        or value.get("runner_code_version") != CODE_VERSION
        or value.get("target_answer_retries") != 1
        or value.get("unit_order") != [UNIT_ID]
        or value.get("unit_failures") != {}
        or value.get("no_completed_rows_repeated") is not True
        or value.get("cross_context_condition_pooling_permitted") is not False
        or value.get("paid_provider_calls") != 0
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            str(value.get("completed_at_utc", "")),
        )
        is None
    ):
        raise ValueError("vLLM context-recovery completion contract changed")
    control_root = completion_path.parent
    if (
        control_root.is_symlink()
        or control_root.resolve(strict=True) != control_root
        or control_root.parent.name != "engineering"
    ):
        raise ValueError("vLLM context-recovery control root changed")

    input_path = _validate_descriptor(
        value.get("input_recovery_completion"),
        label="vLLM input-recovery completion",
    )
    input_view = validate_input_recovery(input_path, runner_root=runner_root)
    retained = _load_json(input_path, label="vLLM input-recovery completion")
    retained_results = retained.get("unit_results")
    if not isinstance(retained_results, dict) or set(retained_results) != {INPUT_RECOVERY_UNIT}:
        raise ValueError("vLLM input-recovery result inventory changed")
    state_path = _validate_descriptor(
        retained_results[INPUT_RECOVERY_UNIT].get("state"),
        label="vLLM input-recovery state",
    )
    expected_selector, snapshot = _derive_context_selector(state_path)
    selector_path = _validate_descriptor(
        value.get("recovery_selection"), label="vLLM context selector"
    )
    config_path = _validate_descriptor(
        value.get("context_config"), label="vLLM larger-context config"
    )
    amendment_path = _validate_descriptor(
        value.get("gate5_amendment"), label="vLLM context Gate 5 amendment"
    )
    if (
        selector_path != control_root / "inputs/gptgeochat-context-incompatible.json"
        or config_path != control_root / "configs/qwen3-vl-native-max.json"
        or amendment_path != control_root / "gate5-context-amendment.json"
        or _load_json(selector_path, label="vLLM context selector") != expected_selector
    ):
        raise ValueError("vLLM context-recovery bound artifact changed")

    source_state = _load_json(state_path, label="vLLM input-recovery state")
    source_argv = source_state.get("runner_argv")
    if not isinstance(source_argv, list) or any(not isinstance(item, str) for item in source_argv):
        raise ValueError("vLLM input-recovery argv changed")
    old_config_path = Path(_option(source_argv, "--local-config"))
    old_config_sha = _option(source_argv, "--local-config-sha256")
    old_payload = _stable_file(old_config_path, label="old Qwen local config")
    if hashlib.sha256(old_payload).hexdigest() != old_config_sha:
        raise ValueError("old Qwen local config digest changed")
    if _load_json(config_path, label="larger-context config") != with_larger_context(
        json.loads(old_payload.decode("utf-8"))
    ):
        raise ValueError("native-max config changed beyond context/output policy")
    amendment = _load_json(amendment_path, label="vLLM context Gate 5 amendment")
    if amendment != {
        "schema": "ura-gate5-corrective-context-amendment/1",
        "approved_scope": "exact_retained_typed_context_limit_population",
        "input_recovery_completion": value["input_recovery_completion"],
        "recovery_selection": value["recovery_selection"],
        "context_config": value["context_config"],
        "selected_records": CONTEXT_RECOVERY_RECORDS,
        "target_answer_retries": 1,
        "max_total_target_calls": CONTEXT_RECOVERY_RECORDS * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "deadline_seconds": 86400,
        "old_max_model_len": OLD_MAX_MODEL_LEN,
        "new_max_model_len": NEW_MAX_MODEL_LEN,
        "old_max_tokens": 4_096,
        "new_max_tokens": NEW_MAX_TOKENS,
        "prompt_token_minimum": EXPECTED_PROMPT_MIN,
        "prompt_token_maximum": EXPECTED_PROMPT_MAX,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
        "cross_context_condition_pooling_permitted": False,
    }:
        raise ValueError("vLLM context Gate 5 amendment changed")

    results = value.get("unit_results")
    if not isinstance(results, dict) or set(results) != {UNIT_ID}:
        raise ValueError("vLLM context-recovery result inventory changed")
    completion_descriptor = _descriptor(completion_path, label="vLLM context-recovery completion")
    validated = _validate_metric_result(
        results[UNIT_ID],
        logical_lane=UNIT_ID,
        physical_unit=UNIT_ID,
        source_lane=SOURCE_LANE,
        corpus=CORPUS,
        selected_records=CONTEXT_RECOVERY_RECORDS,
        runner_root=runner_root,
        control_root=control_root,
        state_schema=STATE_SCHEMA,
        completion=completion_descriptor,
    )
    measured_state = _load_json(
        _validate_descriptor(results[UNIT_ID]["state"], label="context state"),
        label="vLLM context-recovery state",
    )
    measured_argv = measured_state["runner_argv"]
    if (
        _option(measured_argv, "--recovery-completed-prefix") != str(selector_path)
        or _option(measured_argv, "--recovery-completed-prefix-sha256")
        != str(value["recovery_selection"]["sha256"])
        or _option(measured_argv, "--local-config") != str(config_path)
        or _option(measured_argv, "--local-config-sha256") != str(value["context_config"]["sha256"])
    ):
        raise ValueError("vLLM context-recovery measured binding changed")
    target_execution = {
        "target_attempts": CONTEXT_RECOVERY_RECORDS,
        "successful_target_generations": validated["successful"],
        "missing_responses": validated["missing"],
    }
    if value.get("target_execution") != target_execution:
        raise ValueError("vLLM context-recovery target accounting changed")
    revision = str(validated["revision"])
    source = str(validated["source"])
    return {
        "completion": completion_descriptor,
        "input_recovery_completion": dict(value["input_recovery_completion"]),
        "runner_code_version": CODE_VERSION,
        "unit_order": [UNIT_ID],
        "terminal_states": {UNIT_ID: "measured_complete"},
        "metric_lane_order": [UNIT_ID],
        "metric_roots": {UNIT_ID: str(validated["root"])},
        "metric_evidence": {UNIT_ID: dict(validated["evidence"])},
        "metric_grids": [dict(validated["grid"])],
        "metric_eligibility_plans": [dict(validated["eligibility_plan"])],
        "metric_completion_markers": list(validated["completion_markers"]),
        "revision_strata": {revision: [UNIT_ID]},
        "metric_project_revision_receipt_sha256": {UNIT_ID: revision},
        "project_revision_receipt_sha256": revision,
        "source_conformance_sha256": source,
        "target_execution": target_execution,
        "prior_input_recovery_output_accounting": {
            "target_attempts": 1645,
            "successful_target_generations": snapshot["outcome_counts"].get(
                "usable_first_response", 0
            ),
            "missing_responses": snapshot["outcome_counts"].get("input_incompatible", 0),
        },
        "population_coverage": {
            "original_selected_records": SELECTED_RECORDS,
            "context_recovery_records": CONTEXT_RECOVERY_RECORDS,
            "successful_rows_repeated": 0,
        },
        "cross_context_condition_pooling_permitted": False,
        "input_recovery_view": input_view,
    }


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh vLLM context-recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("control root must be a direct engineering campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if (
        hashlib.sha256(_stable_file(project_revision, label="project revision")).hexdigest()
        != args.project_revision_sha256
    ):
        raise ValueError("project revision digest changed")
    input_completion = args.input_recovery_completion.resolve(strict=True)
    payload = _stable_file(input_completion, label="vLLM input-recovery completion")
    if hashlib.sha256(payload).hexdigest() != args.input_recovery_completion_sha256:
        raise ValueError("vLLM input-recovery completion digest changed")
    validate_input_recovery(input_completion, runner_root=work_root / "runs/thesis/runner")
    retained = json.loads(payload.decode("utf-8"))
    failed_path = _validate_descriptor(
        retained.get("failed_completion"), label="vLLM failed completion"
    )
    failed, _failed_root = validate_failed_completion(
        failed_path, str(retained["failed_completion"]["sha256"])
    )
    historical_path = _validate_descriptor(
        failed.get("historical_completion"), label="historical vLLM completion"
    )
    specs = _historical_specs(_load_json(historical_path, label="historical vLLM completion"))
    results = retained.get("unit_results")
    if not isinstance(results, dict) or set(results) != {INPUT_RECOVERY_UNIT}:
        raise ValueError("vLLM input-recovery result inventory changed")
    state_path = _validate_descriptor(
        results[INPUT_RECOVERY_UNIT].get("state"), label="input-recovery state"
    )

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    (control_root / "configs").mkdir(mode=0o700)
    selector, snapshot = _derive_context_selector(state_path)
    selector_path = control_root / "inputs/gptgeochat-context-incompatible.json"
    _create_json(selector_path, selector)
    selector_sha = hashlib.sha256(selector_path.read_bytes()).hexdigest()
    source_argv = _load_json(state_path, label="input-recovery state")["runner_argv"]
    old_config_path = Path(_option(source_argv, "--local-config"))
    old_config_sha = _option(source_argv, "--local-config-sha256")
    old_config_payload = _stable_file(old_config_path, label="old Qwen local config")
    if hashlib.sha256(old_config_payload).hexdigest() != old_config_sha:
        raise ValueError("old Qwen local config digest changed")
    new_config = with_larger_context(json.loads(old_config_payload.decode("utf-8")))
    config_path = control_root / "configs/qwen3-vl-native-max.json"
    _create_json(config_path, new_config)
    config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()

    base = list(specs[SOURCE_LANE]["base_argv"])
    base = _replace_option(base, "--local-config", str(config_path))
    base = _replace_option(base, "--local-config-sha256", config_sha)
    spec = dict(specs[SOURCE_LANE])
    spec["base_argv"] = base
    spec["lane_id"] = UNIT_ID
    spec["selected_records"] = CONTEXT_RECOVERY_RECORDS
    unit = Unit(
        UNIT_ID,
        SOURCE_LANE,
        CORPUS,
        spec,
        CONTEXT_RECOVERY_RECORDS,
        selector,
    )
    amendment = {
        "schema": "ura-gate5-corrective-context-amendment/1",
        "approved_scope": "exact_retained_typed_context_limit_population",
        "input_recovery_completion": _descriptor(
            input_completion, label="vLLM input-recovery completion"
        ),
        "recovery_selection": _descriptor(selector_path, label="context selector"),
        "context_config": _descriptor(config_path, label="larger-context config"),
        "selected_records": CONTEXT_RECOVERY_RECORDS,
        "target_answer_retries": 1,
        "max_total_target_calls": CONTEXT_RECOVERY_RECORDS * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "deadline_seconds": 86400,
        "old_max_model_len": OLD_MAX_MODEL_LEN,
        "new_max_model_len": NEW_MAX_MODEL_LEN,
        "old_max_tokens": 4_096,
        "new_max_tokens": NEW_MAX_TOKENS,
        "prompt_token_minimum": EXPECTED_PROMPT_MIN,
        "prompt_token_maximum": EXPECTED_PROMPT_MAX,
        "successful_rows_repeated": 0,
        "paid_provider_calls": 0,
        "cross_context_condition_pooling_permitted": False,
    }
    amendment_path = control_root / "gate5-context-amendment.json"
    _create_json(amendment_path, amendment)
    amendment_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "input_recovery_completion": amendment["input_recovery_completion"],
        "input_snapshot": snapshot,
        "recovery_selection": amendment["recovery_selection"],
        "context_config": amendment["context_config"],
        "gate5_amendment": _descriptor(amendment_path, label="Gate 5 amendment"),
        "unit_order": [UNIT_ID],
        "no_completed_rows_repeated": True,
        "cross_context_condition_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_vllm_context_recovery",
        hard_stop_hours=168,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    results_out: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    try:
        results_out[UNIT_ID] = _run_unit(
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
    except (
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        failures[UNIT_ID] = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc)[:4000],
        }
    result = results_out.get(UNIT_ID, {})
    attempted = int(result.get("target_attempts", 0))
    successful = int(result.get("successful_target_generations", 0))
    missing = int(result.get("missing_responses", 0))
    completion = {
        "schema": SCHEMA,
        "status": "complete" if not failures else "complete_with_failures",
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "input_recovery_completion": launch["input_recovery_completion"],
        "recovery_selection": launch["recovery_selection"],
        "context_config": launch["context_config"],
        "gate5_amendment": launch["gate5_amendment"],
        "unit_order": [UNIT_ID],
        "unit_results": results_out,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "no_completed_rows_repeated": True,
        "cross_context_condition_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "completion.json", completion)
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{completion['controller_exit_code']}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=attempted,
        successful_target_generations=successful,
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=int(completion["controller_exit_code"]),
    )
    return int(completion["controller_exit_code"])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--project-revision", type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--input-recovery-completion", type=Path, required=True)
    parser.add_argument("--input-recovery-completion-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", required=True)
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    if HEX64.fullmatch(args.input_recovery_completion_sha256) is None:
        raise ValueError("input-recovery completion SHA-256 is invalid")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
