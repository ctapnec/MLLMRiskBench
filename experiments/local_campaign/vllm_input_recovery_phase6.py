"""Recover only the unfinished GPTGeoChat suffix after a context rejection.

The retained Runner 2.25 prefix remains immutable. This controller verifies that
prefix against the exact failed seven-unit campaign, excludes it with Runner's
content-bound recovery selector, and executes only the never-completed suffix
under Runner 2.26. Context-limit rejections become typed input-compatibility
missing responses; model-output failures retain the independent retry policy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _descriptor,
    _stable_file,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    COMPLETED_LANES,
    PREFIX_SCHEMA,
    UNIT_LAYOUT,
    Unit,
    _create_json,
    _historical_specs,
    _load_json,
    _project_python,
    _run_unit,
    _sha256_json,
    _utc_now,
    _validate_descriptor,
    validate_historical_completion,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-vllm-input-recovery-phase6/1"
FAILED_SCHEMA = "ura-vllm-stability-phase6/1"
FAILED_COMMIT = "bd2faf4e98febfdda01e99bdd6042673f7564bc8"
FAILED_UNIT = "vllm-stability-gptgeochat-qwen3-vl"
SOURCE_LANE = "gptgeochat-qwen3-vl"
CORPUS = "gptgeochat_release"
SELECTED_RECORDS = 2020
COMPLETED_PREFIX_RECORDS = 375
RECOVERY_RECORDS = SELECTED_RECORDS - COMPLETED_PREFIX_RECORDS
RECOVERY_UNIT = "vllm-input-recovery-gptgeochat-qwen3-vl-suffix"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_root(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{label} is not an absolute path")
    path = Path(value)
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical existing path")
    return path


def _one_file(root: Path, pattern: str, *, label: str) -> Path:
    matches = sorted(root.glob(pattern))
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError(f"{label} requires exactly one {pattern}")
    return matches[0]


def _one_full_checkpoint(root: Path) -> Path:
    matches = [
        path
        for path in sorted(root.glob(f"{CORPUS}--*.checkpoint.jsonl"))
        if not path.name.endswith(".responses.checkpoint.jsonl")
    ]
    if len(matches) != 1 or matches[0].is_symlink() or not matches[0].is_file():
        raise ValueError("failed GPTGeoChat requires exactly one full checkpoint")
    return matches[0]


def _jsonl_rows(path: Path, *, label: str) -> list[Mapping[str, Any]]:
    rows: list[Mapping[str, Any]] = []
    for raw in _stable_file(path, label=label).splitlines():
        if not raw:
            continue
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{label} contains a non-object row")
        rows.append(value)
    return rows


def validate_failed_completion(
    path: Path,
    expected_sha256: str,
) -> tuple[dict[str, Any], Path]:
    """Require the exact one-failure seven-unit terminal before recovery."""

    resolved = path.resolve(strict=True)
    payload = _stable_file(resolved, label="failed vLLM stability completion")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("failed vLLM stability completion digest changed")
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("failed vLLM stability completion is not one object")
    expected_fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "historical_completion",
        "historical_completed_lanes_excluded",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "model_stability_accounting",
        "no_completed_rows_repeated",
        "cross_output_policy_pooling_permitted",
        "paid_provider_calls",
    }
    expected_order = [row[0] for row in UNIT_LAYOUT]
    if (
        set(value) != expected_fields
        or value.get("schema") != FAILED_SCHEMA
        or value.get("status") != "complete_with_failures"
        or value.get("controller_exit_code") != 1
        or value.get("expected_commit") != FAILED_COMMIT
        or value.get("runner_code_version") != "ura-runner/2.25"
        or value.get("target_answer_retries") != 1
        or value.get("historical_completed_lanes_excluded")
        != sorted(COMPLETED_LANES)
        or value.get("unit_order") != expected_order
        or value.get("model_stability_accounting")
        != "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        or value.get("no_completed_rows_repeated") is not True
        or value.get("cross_output_policy_pooling_permitted") is not False
        or value.get("paid_provider_calls") != 0
    ):
        raise ValueError("failed vLLM stability completion contract changed")
    historical_path = _validate_descriptor(
        value.get("historical_completion"),
        label="failed campaign historical completion",
    )
    historical = _load_json(
        historical_path,
        label="failed campaign historical completion",
    )
    validate_historical_completion(historical)

    failures = value.get("unit_failures")
    results = value.get("unit_results")
    if not isinstance(failures, dict) or set(failures) != {FAILED_UNIT}:
        raise ValueError("failed campaign does not contain exactly the GPTGeoChat failure")
    failure = failures[FAILED_UNIT]
    if (
        not isinstance(failure, dict)
        or set(failure)
        != {
            "status",
            "unit_id",
            "source_lane",
            "corpus",
            "stage",
            "error_type",
            "error",
            "target_answer_retries",
        }
        or failure.get("status") != "failed"
        or failure.get("unit_id") != FAILED_UNIT
        or failure.get("source_lane") != SOURCE_LANE
        or failure.get("corpus") is not None
        or failure.get("stage") != "gate5_or_measured"
        or failure.get("target_answer_retries") != 1
    ):
        raise ValueError("GPTGeoChat failed-unit record changed")
    expected_results = {row[0]: row[3] for row in UNIT_LAYOUT if row[0] != FAILED_UNIT}
    if not isinstance(results, dict) or set(results) != set(expected_results):
        raise ValueError("failed campaign completed-unit inventory changed")
    attempted = successful = missing = 0
    for unit_id, selected in expected_results.items():
        result = results[unit_id]
        if (
            not isinstance(result, dict)
            or result.get("status") != "complete"
            or result.get("unit_id") != unit_id
            or result.get("selected_records") != selected
            or result.get("target_answer_retries") != 1
            or result.get("target_call_cap") != selected * 2
            or result.get("target_attempts") != selected
        ):
            raise ValueError(f"failed campaign completed unit {unit_id!r} changed")
        unit_successful = result.get("successful_target_generations")
        unit_missing = result.get("missing_responses")
        if (
            isinstance(unit_successful, bool)
            or not isinstance(unit_successful, int)
            or unit_successful < 0
            or isinstance(unit_missing, bool)
            or not isinstance(unit_missing, int)
            or unit_missing < 0
            or unit_successful + unit_missing != selected
        ):
            raise ValueError(f"failed campaign unit {unit_id!r} accounting changed")
        _validate_descriptor(result.get("state"), label=f"{unit_id} state")
        _validate_descriptor(result.get("level1"), label=f"{unit_id} Level 1")
        _canonical_root(result.get("result_root"), label=f"{unit_id} result root")
        attempted += selected
        successful += unit_successful
        missing += unit_missing
    if value.get("target_execution") != {
        "target_attempts": attempted,
        "successful_target_generations": successful,
        "missing_responses": missing,
    }:
        raise ValueError("failed campaign target-execution accounting changed")
    control_root = resolved.parent
    if (
        control_root.is_symlink()
        or control_root.resolve(strict=True) != control_root
        or control_root.parent.name != "engineering"
    ):
        raise ValueError("failed campaign control root is not canonical")
    return value, control_root


def build_recovery_prefix(
    failed_root: Path,
) -> tuple[dict[str, Any], Path]:
    """Bind the exact 375 durable rows and return the never-completed suffix."""

    state_path = failed_root / "units" / FAILED_UNIT / "state.json"
    state = _load_json(state_path, label="failed GPTGeoChat unit state")
    if (
        state.get("schema") != "ura-vllm-stability-phase6-unit-state/1"
        or state.get("unit_id") != FAILED_UNIT
        or state.get("source_lane") != SOURCE_LANE
        or state.get("corpus") is not None
        or state.get("selected_records") != SELECTED_RECORDS
        or state.get("target_answer_retries") != 1
        or state.get("target_call_cap") != SELECTED_RECORDS * 2
    ):
        raise ValueError("failed GPTGeoChat unit state changed")
    result_root = _canonical_root(
        state.get("result_root"),
        label="failed GPTGeoChat result root",
    )
    manifest_path = _one_file(
        result_root,
        f"{CORPUS}--*.manifest.json",
        label="failed GPTGeoChat manifest",
    )
    attempts_path = _one_file(
        result_root,
        f"{CORPUS}--*.attempts.jsonl",
        label="failed GPTGeoChat attempts",
    )
    response_checkpoint = _one_file(
        result_root,
        f"{CORPUS}--*.responses.checkpoint.jsonl",
        label="failed GPTGeoChat response checkpoint",
    )
    full_checkpoint = _one_full_checkpoint(result_root)
    manifest = _load_json(manifest_path, label="failed GPTGeoChat manifest")
    config = manifest.get("config")
    run = config.get("run") if isinstance(config, dict) else None
    audit = run.get("sampling_audit") if isinstance(run, dict) else None
    selected_ids = audit.get("selected_ids") if isinstance(audit, dict) else None
    if (
        not isinstance(selected_ids, list)
        or len(selected_ids) != SELECTED_RECORDS
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or len(set(selected_ids)) != SELECTED_RECORDS
    ):
        raise ValueError("failed GPTGeoChat selected identity inventory changed")
    attempt_rows = _jsonl_rows(attempts_path, label="failed GPTGeoChat attempts")
    completed_ids = [row.get("datapoint_id") for row in attempt_rows]
    if (
        len(completed_ids) != COMPLETED_PREFIX_RECORDS
        or any(not isinstance(item, str) or not item for item in completed_ids)
        or len(set(completed_ids)) != COMPLETED_PREFIX_RECORDS
        or completed_ids != selected_ids[:COMPLETED_PREFIX_RECORDS]
        or len(_jsonl_rows(response_checkpoint, label="GPTGeoChat responses"))
        != COMPLETED_PREFIX_RECORDS
        or len(_jsonl_rows(full_checkpoint, label="GPTGeoChat checkpoints"))
        != COMPLETED_PREFIX_RECORDS
    ):
        raise ValueError("failed GPTGeoChat durable rows are not the exact prefix")
    remaining_ids = selected_ids[COMPLETED_PREFIX_RECORDS:]
    return {
        "schema": PREFIX_SCHEMA,
        "corpus": CORPUS,
        "completed_prefix_count": COMPLETED_PREFIX_RECORDS,
        "selected_datapoint_ids_sha256": _sha256_json(selected_ids),
        "completed_prefix_ids_sha256": _sha256_json(completed_ids),
        "remaining_datapoint_ids_sha256": _sha256_json(remaining_ids),
    }, result_root


def run(args: argparse.Namespace) -> int:
    if CODE_VERSION != "ura-runner/2.26":
        raise ValueError("GPTGeoChat input recovery requires Runner 2.26")
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh GPTGeoChat recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("control root must be a direct engineering campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    failed, failed_root = validate_failed_completion(
        args.failed_completion,
        args.failed_completion_sha256,
    )
    prefix, old_result_root = build_recovery_prefix(failed_root)
    historical_path = _validate_descriptor(
        failed["historical_completion"],
        label="recovery historical completion",
    )
    historical = _load_json(historical_path, label="recovery historical completion")
    specs = _historical_specs(historical)
    unit = Unit(
        RECOVERY_UNIT,
        SOURCE_LANE,
        CORPUS,
        specs[SOURCE_LANE],
        RECOVERY_RECORDS,
        prefix,
    )

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    prefix_path = control_root / "inputs/gptgeochat-completed-prefix.json"
    _create_json(prefix_path, prefix)
    prefix_sha = hashlib.sha256(prefix_path.read_bytes()).hexdigest()
    launch = {
        "schema": "ura-vllm-input-recovery-phase6-launch/1",
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "failed_completion": _descriptor(
            args.failed_completion,
            label="failed vLLM stability completion",
        ),
        "retained_prefix_result_root": str(old_result_root),
        "recovery_selection": _descriptor(
            prefix_path,
            label="GPTGeoChat recovery prefix",
        ),
        "unit_order": [RECOVERY_UNIT],
        "no_completed_rows_repeated": True,
        "cross_runner_or_input_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_vllm_input_recovery",
        hard_stop_hours=168,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    try:
        results[RECOVERY_UNIT] = _run_unit(
            unit,
            python=python,
            work_root=work_root,
            control_root=control_root,
            project_revision=project_revision,
            project_revision_sha256=args.project_revision_sha256,
            scope=args.execution_scope_id,
            recovery_path=prefix_path,
            recovery_sha256=prefix_sha,
            state_schema="ura-vllm-input-recovery-phase6-unit-state/1",
        )
    except (
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        failures[RECOVERY_UNIT] = {
            "status": "failed",
            "error_type": type(exc).__name__,
            "error": str(exc)[:4000],
        }
    result = results.get(RECOVERY_UNIT, {})
    attempted = int(result.get("target_attempts", 0))
    successful = int(result.get("successful_target_generations", 0))
    missing = int(result.get("missing_responses", 0))
    status = "complete" if not failures else "complete_with_failures"
    completion = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "failed_completion": launch["failed_completion"],
        "recovery_selection": launch["recovery_selection"],
        "unit_order": [RECOVERY_UNIT],
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "input_compatibility_accounting": (
            "typed_missing_response_without_retry_or_policy_judge"
        ),
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_runner_or_input_policy_pooling_permitted": False,
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
    parser.add_argument("--failed-completion", type=Path, required=True)
    parser.add_argument("--failed-completion-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", required=True)
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    if HEX64.fullmatch(args.failed_completion_sha256) is None:
        raise ValueError("failed completion SHA-256 is invalid")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
