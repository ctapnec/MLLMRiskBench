"""Recover only failed Ollama population-alignment units.

The base completion and every successful unit remain immutable. This controller
accepts only the exact failed partition of that completion, proves that no failed
unit reached a measured state, and runs those units under the current revision.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import os
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
from experiments.local_campaign.current_ollama_population_alignment_phase6 import (
    ALIGNMENT_LANES,
    EXPECTED_EXTENSION_ROWS,
    RUNNER_CODE_VERSION,
    SCHEMA as BASE_SCHEMA,
    _validate_prefix_complete,
    build_alignment_units,
    hub_acquisition_required,
    validate_completion as validate_base_completion,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _run_unit,
    _validate_descriptor,
)
from ura.request_envelope import load_request_envelope_file


SCHEMA = "ura-current-ollama-population-alignment-recovery-phase6/1"
LAUNCH_SCHEMA = (
    "ura-current-ollama-population-alignment-recovery-phase6-launch/1"
)
UNIT_STATE_SCHEMA = (
    "ura-current-ollama-population-alignment-recovery-phase6-unit-state/1"
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _base_inputs(
    completion_path: Path,
    *,
    runner_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[Any]]:
    snapshot = validate_base_completion(
        completion_path,
        runner_root=runner_root,
        allow_incomplete=True,
    )
    completion = _load_json(
        completion_path, label="failed Ollama population-alignment completion"
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="failed Ollama alignment launch"
    )
    launch = _load_json(launch_path, label="failed Ollama alignment launch")
    gate5_path = _validate_descriptor(
        launch.get("gate5"), label="retained Ollama Gate 5"
    )
    stability_path = _validate_descriptor(
        launch.get("stability_completion"),
        label="retained Ollama stability completion",
    )
    gate5, _stability = _validate_prefix_complete(
        gate5_path=gate5_path,
        stability_path=stability_path,
        runner_root=runner_root,
    )
    units = list(build_alignment_units(gate5))
    if [item.unit.unit_id for item in units] != list(ALIGNMENT_LANES):
        raise ValueError("Ollama population-alignment recovery unit order changed")
    return snapshot, completion, launch, units


def _selected_failed_lanes(snapshot: Mapping[str, Any]) -> list[str]:
    terminal = snapshot.get("terminal_states")
    if not isinstance(terminal, dict):
        raise ValueError("failed alignment terminal states changed")
    selected = [lane for lane in ALIGNMENT_LANES if terminal.get(lane) == "failed"]
    if not selected:
        raise ValueError("Ollama population-alignment recovery is unnecessary")
    return selected


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = work_root / "runs/thesis/runner"
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh Ollama alignment-recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("alignment-recovery root must be one direct campaign")
    base_completion = args.base_completion.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(base_completion, label="failed alignment completion")
    ).hexdigest() != args.base_completion_sha256:
        raise ValueError("failed alignment completion digest changed")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(
        _stable_file(project_revision, label="project revision")
    ).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")
    snapshot, _base, _base_launch, units = _base_inputs(
        base_completion,
        runner_root=runner_root,
    )
    selected = _selected_failed_lanes(snapshot)
    by_lane = {item.unit.unit_id: item for item in units}

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "base_completion": _descriptor(
            base_completion, label="failed alignment completion"
        ),
        "project_revision": _descriptor(
            project_revision, label="recovery project revision"
        ),
        "unit_order": selected,
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    launch_path = control_root / "launch.json"
    _create_json(launch_path, launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_ollama_population_alignment_recovery",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for lane in selected:
        item = by_lane[lane]
        selector = base_completion.parent / "inputs" / f"{lane}.completed-selection.json"
        selector = selector.resolve(strict=True)
        selector_sha = hashlib.sha256(
            _stable_file(selector, label=f"{lane} recovery selection")
        ).hexdigest()
        try:
            results[lane] = _run_unit(
                item.unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=project_revision,
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=selector,
                recovery_sha256=selector_sha,
                expected_commit=args.expected_commit,
                framework_lock_id=_framework_lock_id(),
                admission_sha256=args.base_completion_sha256,
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
                state_schema=UNIT_STATE_SCHEMA,
                hub_acquisition_required=hub_acquisition_required(item.unit),
            )
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            failures[lane] = {
                "status": "failed",
                "unit_id": lane,
                "stage": "recovery_gate5_or_measured",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
                "target_answer_retries": 1,
            }
    attempts = sum(int(row["target_attempts"]) for row in results.values())
    successful = sum(
        int(row["successful_target_generations"]) for row in results.values()
    )
    missing = sum(int(row["missing_responses"]) for row in results.values())
    status = "complete" if not failures else "complete_with_failures"
    completion = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": RUNNER_CODE_VERSION,
        "target_answer_retries": 1,
        "base_completion": _descriptor(
            base_completion, label="failed alignment completion"
        ),
        "launch": _descriptor(launch_path, label="alignment recovery launch"),
        "unit_order": selected,
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempts,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "no_completed_rows_repeated": True,
        "cross_revision_pooling_permitted": False,
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
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=exit_code,
    )
    return exit_code


def validate_recovery_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    control_root = completion_path.parent
    completion = _load_json(
        completion_path, label="Ollama population-alignment recovery completion"
    )
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "base_completion",
        "launch",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "no_completed_rows_repeated",
        "cross_revision_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != RUNNER_CODE_VERSION
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_failures") != {}
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("Ollama population-alignment recovery completion changed")
    base_path = _validate_descriptor(
        completion.get("base_completion"), label="failed alignment completion"
    )
    launch_path = _validate_descriptor(
        completion.get("launch"), label="alignment recovery launch"
    )
    if launch_path != control_root / "launch.json":
        raise ValueError("alignment recovery launch placement changed")
    base_snapshot, _base, _base_launch, units = _base_inputs(
        base_path,
        runner_root=runner_root,
    )
    selected = _selected_failed_lanes(base_snapshot)
    if completion.get("unit_order") != selected:
        raise ValueError("alignment recovery selection changed")
    results = completion.get("unit_results")
    if not isinstance(results, dict) or set(results) != set(selected):
        raise ValueError("alignment recovery result inventory changed")
    launch = _load_json(launch_path, label="alignment recovery launch")
    launch_fields = {
        "schema",
        "started_at_utc",
        "expected_commit",
        "execution_scope_id",
        "target_answer_retries",
        "base_completion",
        "project_revision",
        "unit_order",
        "no_completed_rows_repeated",
        "paid_provider_calls",
    }
    if (
        set(launch) != launch_fields
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("expected_commit") != completion["expected_commit"]
        or launch.get("target_answer_retries") != 1
        or launch.get("base_completion") != completion["base_completion"]
        or launch.get("unit_order") != selected
        or launch.get("no_completed_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
    ):
        raise ValueError("alignment recovery launch changed")
    _validate_descriptor(
        launch.get("project_revision"), label="recovery project revision"
    )

    by_lane = {item.unit.unit_id: item for item in units}
    recovered_roots: dict[str, str] = {}
    recovered_evidence: dict[str, dict[str, object]] = {}
    recovered_grids: dict[str, dict[str, object]] = {}
    recovered_eligibility: dict[str, dict[str, object]] = {}
    recovered_markers: dict[str, list[dict[str, object]]] = {}
    recovery_revisions: dict[str, list[str]] = {}
    sources: set[str] = set()
    successful = 0
    missing = 0
    recovery_descriptor = _descriptor(
        completion_path, label="alignment recovery completion"
    )
    for lane in selected:
        item = by_lane[lane]
        selector = base_path.parent / "inputs" / f"{lane}.completed-selection.json"
        selector = selector.resolve(strict=True)
        selector_sha = hashlib.sha256(selector.read_bytes()).hexdigest()
        validated = _validate_metric_result(
            results[lane],
            logical_lane=lane,
            physical_unit=lane,
            source_lane=lane,
            corpus=None,
            selected_records=item.unit.selected_records,
            runner_root=runner_root,
            control_root=control_root,
            state_schema=UNIT_STATE_SCHEMA,
            completion=recovery_descriptor,
        )
        state_path = _validate_descriptor(
            results[lane]["state"], label=f"{lane} recovered state"
        )
        state = _load_json(state_path, label=f"{lane} recovered state")
        argv = state["runner_argv"]
        if (
            _option(argv, "--limit") != "100"
            or _option(argv, "--sample-seed") != "0"
            or _option(argv, "--target-answer-retries") != "1"
            or _option(argv, "--recovery-completed-prefix") != str(selector)
            or _option(argv, "--recovery-completed-prefix-sha256")
            != selector_sha
        ):
            raise ValueError(f"{lane}: recovered population argv changed")
        if (
            item.unit.spec["metric_mode"] != "static"
            and any(flag.startswith("--model-acquisition-") for flag in argv)
        ):
            raise ValueError(f"{lane}: local-only lane gained Hub acquisition")
        envelopes = sorted(Path(validated["root"]).glob("*.request-envelope.json"))
        if len(envelopes) != 1:
            raise ValueError(f"{lane}: recovered request-envelope inventory changed")
        envelope, _descriptor_value = load_request_envelope_file(envelopes[0])
        request = envelope["request"]
        if (
            envelope.get("schema") != "ura-request-envelope/6"
            or request.get("target_answer_retries") != 1
            or request.get("limit") != 100
            or request.get("recovery_selection", {}).get("schema")
            != "ura-recovery-completed-selection/1"
        ):
            raise ValueError(f"{lane}: recovered request binding changed")
        revision = str(validated["revision"])
        recovery_revisions.setdefault(revision, []).append(lane)
        sources.add(str(validated["source"]))
        recovered_roots[lane] = str(validated["root"])
        recovered_evidence[lane] = dict(validated["evidence"])
        recovered_grids[lane] = dict(validated["grid"])
        recovered_eligibility[lane] = dict(validated["eligibility_plan"])
        recovered_markers[lane] = list(validated["completion_markers"])
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    expected_recovery = sum(by_lane[lane].unit.selected_records for lane in selected)
    target_execution = completion.get("target_execution")
    if (
        target_execution
        != {
            "target_attempts": expected_recovery,
            "successful_target_generations": successful,
            "missing_responses": missing,
        }
        or successful + missing != expected_recovery
        or sources != {base_snapshot["source_conformance_sha256"]}
    ):
        raise ValueError("alignment recovery accounting changed")

    result = copy.deepcopy(base_snapshot)
    result["completion"] = recovery_descriptor
    result["terminal_states"] = {
        lane: "measured_complete" for lane in ALIGNMENT_LANES
    }
    result["metric_lane_order"] = list(ALIGNMENT_LANES)
    result["metric_roots"].update(recovered_roots)
    result["metric_evidence"].update(recovered_evidence)
    result["metric_grids"] = [
        (
            recovered_grids[lane]
            if lane in recovered_grids
            else next(
                item
                for item in base_snapshot["metric_grids"]
                if item["path"].startswith(base_snapshot["metric_roots"][lane] + "/")
            )
        )
        for lane in ALIGNMENT_LANES
    ]
    result["metric_eligibility_plans"] = [
        (
            recovered_eligibility[lane]
            if lane in recovered_eligibility
            else next(
                item
                for item in base_snapshot["metric_eligibility_plans"]
                if item["path"].startswith(base_snapshot["metric_roots"][lane] + "/")
            )
        )
        for lane in ALIGNMENT_LANES
    ]
    result["metric_completion_markers"] = [
        marker
        for lane in ALIGNMENT_LANES
        for marker in (
            recovered_markers[lane]
            if lane in recovered_markers
            else [
                item
                for item in base_snapshot["metric_completion_markers"]
                if item["path"].startswith(base_snapshot["metric_roots"][lane] + "/")
            ]
        )
    ]
    revision_strata = copy.deepcopy(base_snapshot["revision_strata"])
    for revision, lanes in recovery_revisions.items():
        revision_strata.setdefault(revision, []).extend(lanes)
    result["revision_strata"] = revision_strata
    result["project_revision_receipt_sha256"] = next(iter(recovery_revisions))
    result["target_execution"] = {
        "target_attempts": (
            int(base_snapshot["target_execution"]["target_attempts"])
            + expected_recovery
        ),
        "successful_target_generations": (
            int(base_snapshot["target_execution"]["successful_target_generations"])
            + successful
        ),
        "missing_responses": (
            int(base_snapshot["target_execution"]["missing_responses"]) + missing
        ),
    }
    if result["target_execution"]["target_attempts"] != EXPECTED_EXTENSION_ROWS:
        raise ValueError("combined population-alignment row count changed")
    result["no_completed_rows_repeated"] = True
    result["cross_revision_pooling_permitted"] = False
    return result


def validate_phase7_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    value = _load_json(completion_path, label="Phase 7 alignment completion")
    if value.get("schema") == BASE_SCHEMA:
        return validate_base_completion(completion_path, runner_root=runner_root)
    if value.get("schema") == SCHEMA:
        return validate_recovery_completion(completion_path, runner_root=runner_root)
    raise ValueError("unsupported Ollama population-alignment completion schema")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-completion", type=Path, required=True)
    parser.add_argument("--base-completion-sha256", required=True)
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
    try:
        return run(args)
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"Ollama alignment recovery failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
