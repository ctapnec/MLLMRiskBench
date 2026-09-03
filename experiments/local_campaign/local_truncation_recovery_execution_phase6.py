"""Run exact retained local truncation rows with automatic GPU-fit contexts.

The input inventory is structure-only and is re-derived from its bound source
states before execution. Each correction unit keeps the original selection and
semantics, changes only local context/output policy, and excludes every durable
row that does not require regeneration.
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
from experiments.local_campaign.current_ollama_gate5 import _descriptor, _stable_file
from experiments.local_campaign.local_truncation_recovery_phase6 import (
    CURRENT_LOCAL_SPECS,
    SCHEMA as INVENTORY_SCHEMA,
    derive_state_inventory,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit,
    _create_json,
    _framework_lock_id,
    _load_json,
    _option,
    _project_python,
    _replace_option,
    _run_unit,
    _utc_now,
    _validate_descriptor,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from ura.runner import CODE_VERSION


SCHEMA = "ura-local-truncation-recovery-phase6/2"
LAUNCH_SCHEMA = "ura-local-truncation-recovery-phase6-launch/2"
STATE_SCHEMA = "ura-local-truncation-recovery-phase6-unit-state/2"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the hardware-fit recovery as a separate Phase 7 stratum."""

    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    value = _load_json(completion_path, label="local hardware-fit completion")
    if value.get("schema") == "ura-local-hardware-fit-failed-unit-recovery-phase6/1":
        from experiments.local_campaign.local_hardware_fit_failed_unit_recovery_phase6 import (
            validate_completion as validate_failed_unit_recovery,
        )

        return validate_failed_unit_recovery(completion_path, runner_root=runner_root)
    if value.get("schema") == "ura-local-truncation-recovery-phase6-continuation/1":
        from experiments.local_campaign.local_truncation_recovery_continuation_phase6 import (
            validate_phase7_completion,
        )

        return validate_phase7_completion(completion_path, runner_root=runner_root)
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "inventory",
        "gate5_amendment",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "planned_unique_rows",
        "no_completed_rows_repeated",
        "cross_condition_pooling_permitted",
        "historical_rows_mutated",
        "paid_provider_calls",
    }
    results = value.get("unit_results")
    failures = value.get("unit_failures")
    if (
        set(value) != fields
        or value.get("schema") != SCHEMA
        or value.get("status")
        not in {"complete", "complete_with_failures"}
        or value.get("controller_exit_code")
        != (0 if value.get("status") == "complete" else 1)
        or HEX40.fullmatch(str(value.get("expected_commit", ""))) is None
        or value.get("runner_code_version") != CODE_VERSION
        or value.get("target_answer_retries") != 1
        or not isinstance(results, dict)
        or not isinstance(failures, dict)
        or bool(failures) != (value.get("status") == "complete_with_failures")
        or value.get("no_completed_rows_repeated") is not True
        or value.get("cross_condition_pooling_permitted") is not False
        or value.get("historical_rows_mutated") is not False
        or value.get("paid_provider_calls") != 0
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            str(value.get("completed_at_utc", "")),
        )
        is None
    ):
        raise ValueError("local hardware-fit completion contract changed")
    control_root = completion_path.parent
    if (
        control_root.is_symlink()
        or control_root.resolve(strict=True) != control_root
        or control_root.parent.name != "engineering"
    ):
        raise ValueError("local hardware-fit control root changed")

    inventory_path = _validate_descriptor(
        value.get("inventory"), label="local hardware-fit inventory"
    )
    inventory_descriptor = value["inventory"]
    if not isinstance(inventory_descriptor, dict):
        raise ValueError("local hardware-fit inventory descriptor changed")
    inventory = load_inventory(
        inventory_path,
        str(inventory_descriptor.get("sha256", "")),
    )
    inventory_units = inventory["units"]
    expected_order = [
        _safe_unit_id(index, item)
        for index, item in enumerate(inventory_units, 1)
    ]
    if (
        value.get("unit_order") != expected_order
        or set(results) & set(failures)
        or set(results) | set(failures) != set(expected_order)
        or list(results) != [unit_id for unit_id in expected_order if unit_id in results]
        or list(failures)
        != [unit_id for unit_id in expected_order if unit_id in failures]
    ):
        raise ValueError("local hardware-fit terminal unit partition changed")
    total_rows = sum(int(item["summary"]["recovery_records"]) for item in inventory_units)
    if value.get("planned_unique_rows") != total_rows:
        raise ValueError("local hardware-fit planned row count changed")

    amendment_path = _validate_descriptor(
        value.get("gate5_amendment"), label="local hardware-fit Gate 5 amendment"
    )
    expected_amendment = {
        "schema": "ura-gate5-local-hardware-fit-amendment/1",
        "approved_scope": "exact_retained_local_truncation_and_unfinished_rows",
        "inventory": dict(inventory_descriptor),
        "source_units": len(inventory_units),
        "selected_records": total_rows,
        "target_answer_retries": 1,
        "max_total_target_calls": total_rows * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "per_unit_deadline_seconds": 86400,
        "vllm_context_policy": "vllm_auto_fit_minus_one",
        "vllm_output_policy": "maximum_available_output",
        "ollama_context_policy": "largest_probed_native_fraction_fully_gpu_resident",
        "ollama_output_policy": "num_predict_minus_one",
        "successful_rows_repeated": 0,
        "historical_rows_mutated": False,
        "cross_condition_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    if (
        amendment_path
        != control_root / "gate5-local-hardware-fit-amendment.json"
        or _load_json(amendment_path, label="local hardware-fit Gate 5 amendment")
        != expected_amendment
    ):
        raise ValueError("local hardware-fit Gate 5 amendment changed")

    completion_descriptor = _descriptor(
        completion_path, label="local hardware-fit completion"
    )
    terminal_states: dict[str, str] = {}
    lifecycle_roots: dict[str, str | None] = {}
    lifecycle_evidence: dict[str, dict[str, object]] = {}
    lifecycle_revisions: dict[str, str] = {}
    metric_order: list[str] = []
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility: list[dict[str, object]] = []
    metric_markers: list[dict[str, object]] = []
    metric_revisions: dict[str, str] = {}
    sources: set[str] = set()
    total_successful = 0
    total_missing = 0

    for index, item in enumerate(inventory_units, 1):
        unit_id = expected_order[index - 1]
        recovery = item["recovery_selection"]
        corpora = recovery["corpora"]
        corpus = next(iter(corpora)) if len(corpora) == 1 else None
        selected_records = int(item["summary"]["recovery_records"])
        selector_path = control_root / "inputs" / f"{unit_id}.json"
        config_path = control_root / "configs" / f"{unit_id}.json"
        if (
            _load_json(selector_path, label=f"{unit_id} recovery selector")
            != recovery
            or _load_json(config_path, label=f"{unit_id} hardware-fit config")
            != item["hardware_fit_local_config"]
        ):
            raise ValueError(f"{unit_id} hardware-fit input changed")
        selector_sha = hashlib.sha256(selector_path.read_bytes()).hexdigest()
        config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()
        state_path = control_root / "units" / unit_id / "state.json"

        if unit_id in results:
            validated = _validate_metric_result(
                results[unit_id],
                logical_lane=unit_id,
                physical_unit=unit_id,
                source_lane=str(item["source_lane"]),
                corpus=corpus,
                selected_records=selected_records,
                runner_root=runner_root,
                control_root=control_root,
                state_schema=STATE_SCHEMA,
                completion=completion_descriptor,
            )
            state = _load_json(state_path, label=f"{unit_id} state")
            argv = state["runner_argv"]
            if (
                _option(argv, "--recovery-completed-prefix")
                != str(selector_path)
                or _option(argv, "--recovery-completed-prefix-sha256")
                != selector_sha
                or _option(argv, "--local-config") != str(config_path)
                or _option(argv, "--local-config-sha256") != config_sha
            ):
                raise ValueError(f"{unit_id} hardware-fit measured binding changed")
            terminal_states[unit_id] = "measured_complete"
            lifecycle_roots[unit_id] = str(validated["root"])
            lifecycle_evidence[unit_id] = dict(validated["evidence"])
            lifecycle_revisions[unit_id] = str(validated["revision"])
            metric_order.append(unit_id)
            metric_roots[unit_id] = str(validated["root"])
            metric_evidence[unit_id] = dict(validated["evidence"])
            metric_grids.append(dict(validated["grid"]))
            metric_eligibility.append(dict(validated["eligibility_plan"]))
            metric_markers.extend(validated["completion_markers"])
            metric_revisions[unit_id] = str(validated["revision"])
            sources.add(str(validated["source"]))
            total_successful += int(validated["successful"])
            total_missing += int(validated["missing"])
            continue

        failure = failures[unit_id]
        if (
            not isinstance(failure, dict)
            or set(failure) != {"status", "error_type", "error"}
            or failure.get("status") != "failed"
            or not isinstance(failure.get("error_type"), str)
            or not failure["error_type"]
            or not isinstance(failure.get("error"), str)
            or not failure["error"]
            or len(failure["error"]) > 4000
            or not state_path.is_file()
            or state_path.is_symlink()
        ):
            raise ValueError(f"{unit_id} failure evidence changed")
        state = _load_json(state_path, label=f"{unit_id} failed state")
        argv = state.get("runner_argv")
        result_root = Path(str(state.get("result_root", "")))
        expected_root = runner_root / unit_id / control_root.name
        if (
            state.get("schema") != STATE_SCHEMA
            or state.get("unit_id") != unit_id
            or state.get("selected_records") != selected_records
            or not isinstance(argv, list)
            or any(not isinstance(entry, str) for entry in argv)
            or _option(argv, "--recovery-completed-prefix") != str(selector_path)
            or _option(argv, "--recovery-completed-prefix-sha256") != selector_sha
            or _option(argv, "--local-config") != str(config_path)
            or _option(argv, "--local-config-sha256") != config_sha
            or result_root != expected_root
            or result_root.is_symlink()
            or not result_root.is_dir()
        ):
            raise ValueError(f"{unit_id} failed measured binding changed")
        revision = _option(argv, "--project-revision-sha256")
        source = _option(argv, "--source-conformance-sha256")
        if HEX64.fullmatch(revision) is None or HEX64.fullmatch(source) is None:
            raise ValueError(f"{unit_id} failed stratum changed")
        terminal_states[unit_id] = "failed"
        lifecycle_roots[unit_id] = str(result_root)
        lifecycle_evidence[unit_id] = {
            "completion": dict(completion_descriptor),
            "state": _descriptor(state_path, label=f"{unit_id} failed state"),
            "failure": dict(failure),
        }
        lifecycle_revisions[unit_id] = revision
        sources.add(source)

    target_execution = {
        "target_attempts": sum(
            int(result["target_attempts"]) for result in results.values()
        ),
        "successful_target_generations": total_successful,
        "missing_responses": total_missing,
    }
    if value.get("target_execution") != target_execution or len(sources) != 1:
        raise ValueError("local hardware-fit target accounting or source changed")
    revision_strata: dict[str, list[str]] = {}
    for unit_id in metric_order:
        revision_strata.setdefault(metric_revisions[unit_id], []).append(unit_id)
    lifecycle_revision_strata: dict[str, list[str]] = {}
    for unit_id in expected_order:
        lifecycle_revision_strata.setdefault(lifecycle_revisions[unit_id], []).append(
            unit_id
        )
    return {
        "completion": completion_descriptor,
        "inventory": dict(inventory_descriptor),
        "runner_code_version": CODE_VERSION,
        "output_policy_stratum": "hardware_fit_context_and_maximum_available_output",
        "unit_order": expected_order,
        "terminal_states": terminal_states,
        "lifecycle_roots": lifecycle_roots,
        "lifecycle_evidence": lifecycle_evidence,
        "lifecycle_revision_strata": lifecycle_revision_strata,
        "lifecycle_project_revision_receipt_sha256": lifecycle_revisions,
        "metric_lane_order": metric_order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility,
        "metric_completion_markers": metric_markers,
        "revision_strata": revision_strata,
        "metric_project_revision_receipt_sha256": metric_revisions,
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": target_execution,
        "planned_unique_rows": total_rows,
        "successful_rows_repeated": 0,
        "cross_condition_pooling_permitted": False,
    }


def load_inventory(path: Path, expected_sha256: str) -> dict[str, Any]:
    """Load and re-derive every bound inventory unit before target execution."""

    path = path.resolve(strict=True)
    payload = _stable_file(path, label="local truncation recovery inventory")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("local truncation recovery inventory digest changed")
    try:
        inventory = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("local truncation recovery inventory is not strict JSON") from exc
    if not isinstance(inventory, dict) or inventory.get("schema") != INVENTORY_SCHEMA:
        raise ValueError("local truncation recovery inventory schema changed")
    if (
        inventory.get("response_text_retained") is not False
        or inventory.get("historical_rows_mutated") is not False
        or inventory.get("retired_rwkv_rescheduled") is not False
        or inventory.get("paid_provider_calls") != 0
    ):
        raise ValueError("local truncation recovery inventory policy changed")
    units = inventory.get("units")
    order = inventory.get("unit_order")
    if (
        not isinstance(units, list)
        or not units
        or any(not isinstance(item, dict) for item in units)
        or not isinstance(order, list)
        or order != [item.get("source_result_root") for item in units]
        or len(order) != len(set(order))
    ):
        raise ValueError("local truncation recovery inventory order changed")
    for item in units:
        source = _validate_descriptor(
            item.get("source_state"), label="local truncation source state"
        )
        if derive_state_inventory(source) != item:
            raise ValueError("local truncation recovery source evidence changed")
    totals = inventory.get("totals")
    if not isinstance(totals, dict) or totals.get("source_units") != len(units):
        raise ValueError("local truncation recovery inventory totals changed")
    recovery_records = sum(int(item["summary"]["recovery_records"]) for item in units)
    if totals.get("recovery_records") != recovery_records:
        raise ValueError("local truncation recovery row total changed")
    return inventory


def _safe_unit_id(index: int, item: Mapping[str, Any]) -> str:
    source = item.get("source_unit_id")
    result_root = item.get("source_result_root")
    if not isinstance(source, str) or not isinstance(result_root, str):
        raise ValueError("local truncation recovery unit identity changed")
    slug = re.sub(r"[^a-z0-9]+", "-", source.lower()).strip("-")[:56]
    suffix = hashlib.sha256(result_root.encode("utf-8")).hexdigest()[:10]
    if not slug:
        raise ValueError("local truncation recovery unit identity is empty")
    return f"local-hardware-fit-{index:03d}-{slug}-{suffix}"


def configure_units(
    inventory: Mapping[str, Any], *, control_root: Path, start_index: int = 1
) -> list[tuple[Unit, Path, str]]:
    """Materialize exact selectors/configs and return executable units."""

    units = inventory.get("units")
    if not isinstance(units, list):
        raise ValueError("local truncation recovery units changed")
    if (
        isinstance(start_index, bool)
        or not isinstance(start_index, int)
        or start_index < 1
    ):
        raise ValueError("local truncation recovery start index is invalid")
    configured: list[tuple[Unit, Path, str]] = []
    identities: set[str] = set()
    for index, item in enumerate(units, start_index):
        if not isinstance(item, dict):
            raise ValueError("local truncation recovery unit changed")
        unit_id = _safe_unit_id(index, item)
        if unit_id in identities:
            raise ValueError("local truncation recovery unit identity is duplicated")
        identities.add(unit_id)
        spec = item.get("local_spec")
        base = item.get("base_argv")
        modality = item.get("modality")
        recovery = item.get("recovery_selection")
        config = item.get("hardware_fit_local_config")
        summary = item.get("summary")
        source_lane = item.get("source_lane")
        source_corpus = item.get("source_corpus")
        recovery_corpora = recovery.get("corpora") if isinstance(recovery, dict) else None
        if (
            spec not in CURRENT_LOCAL_SPECS
            or not isinstance(base, list)
            or any(not isinstance(value, str) for value in base)
            or _option(base, "--local") != spec
            or modality not in {"text", "image"}
            or not isinstance(recovery, dict)
            or recovery.get("schema") != "ura-recovery-completed-selection/1"
            or not isinstance(recovery_corpora, dict)
            or not recovery_corpora
            or not isinstance(config, dict)
            or not isinstance(summary, dict)
            or not isinstance(source_lane, str)
            or (source_corpus is not None and not isinstance(source_corpus, str))
        ):
            raise ValueError("local truncation recovery unit fields changed")
        selected_records = int(summary.get("recovery_records", 0))
        if selected_records < 1:
            raise ValueError("local truncation recovery unit has no selected rows")
        selector_path = control_root / "inputs" / f"{unit_id}.json"
        config_path = control_root / "configs" / f"{unit_id}.json"
        _create_json(selector_path, recovery)
        _create_json(config_path, config)
        selector_sha = hashlib.sha256(selector_path.read_bytes()).hexdigest()
        config_sha = hashlib.sha256(config_path.read_bytes()).hexdigest()
        corrected = _replace_option(base, "--local-config", str(config_path))
        corrected = _replace_option(corrected, "--local-config-sha256", config_sha)
        corrected = _replace_option(
            corrected, "--corpora", ",".join(str(name) for name in recovery_corpora)
        )
        execution_corpus = next(iter(recovery_corpora)) if len(recovery_corpora) == 1 else None
        unit = Unit(
            unit_id=unit_id,
            source_lane=source_lane,
            corpus=execution_corpus,
            spec={"base_argv": corrected, "modality": modality},
            selected_records=selected_records,
            recovery=recovery,
        )
        configured.append((unit, selector_path, selector_sha))
    return configured


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh local truncation recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("local truncation recovery root must be one direct campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if (
        hashlib.sha256(_stable_file(project_revision, label="project revision")).hexdigest()
        != args.project_revision_sha256
    ):
        raise ValueError("project revision digest changed")
    inventory_path = args.inventory.resolve(strict=True)
    inventory = load_inventory(inventory_path, args.inventory_sha256)

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    (control_root / "configs").mkdir(mode=0o700)
    units = configure_units(inventory, control_root=control_root)
    total_rows = sum(unit.selected_records for unit, _path, _sha in units)
    amendment = {
        "schema": "ura-gate5-local-hardware-fit-amendment/1",
        "approved_scope": "exact_retained_local_truncation_and_unfinished_rows",
        "inventory": _descriptor(inventory_path, label="local truncation inventory"),
        "source_units": len(units),
        "selected_records": total_rows,
        "target_answer_retries": 1,
        "max_total_target_calls": total_rows * 2,
        "max_total_judge_calls": 0,
        "max_total_http_attempts": 0,
        "per_unit_deadline_seconds": 86400,
        "vllm_context_policy": "vllm_auto_fit_minus_one",
        "vllm_output_policy": "maximum_available_output",
        "ollama_context_policy": "largest_probed_native_fraction_fully_gpu_resident",
        "ollama_output_policy": "num_predict_minus_one",
        "successful_rows_repeated": 0,
        "historical_rows_mutated": False,
        "cross_condition_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    amendment_path = control_root / "gate5-local-hardware-fit-amendment.json"
    _create_json(amendment_path, amendment)
    amendment_sha = hashlib.sha256(amendment_path.read_bytes()).hexdigest()
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "inventory": amendment["inventory"],
        "gate5_amendment": _descriptor(amendment_path, label="Gate 5 amendment"),
        "unit_order": [unit.unit_id for unit, _path, _sha in units],
        "selected_records": total_rows,
        "target_answer_retries": 1,
        "no_completed_rows_repeated": True,
        "cross_condition_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_hardware_fit_recovery",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for unit, selector_path, selector_sha in units:
        try:
            results[unit.unit_id] = _run_unit(
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
            failures[unit.unit_id] = {
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
            }
    attempted = sum(int(item.get("target_attempts", 0)) for item in results.values())
    successful = sum(
        int(item.get("successful_target_generations", 0)) for item in results.values()
    )
    missing = sum(int(item.get("missing_responses", 0)) for item in results.values())
    completion = {
        "schema": SCHEMA,
        "status": "complete" if not failures else "complete_with_failures",
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "inventory": launch["inventory"],
        "gate5_amendment": launch["gate5_amendment"],
        "unit_order": launch["unit_order"],
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "planned_unique_rows": total_rows,
        "no_completed_rows_repeated": True,
        "cross_condition_pooling_permitted": False,
        "historical_rows_mutated": False,
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
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", required=True)
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    if HEX64.fullmatch(args.inventory_sha256) is None:
        raise ValueError("inventory SHA-256 is invalid")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
