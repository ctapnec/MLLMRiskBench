"""Extend every comparable Ollama lane to the common limit-100 population.

The retained limit-50 cohort and its Runner 2.26 missing-row continuation remain
immutable. This controller validates that complete prefix, proves it is the
exact seed-0 prefix of each limit-100 selection, and runs only the non-overlap.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
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
from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_RUNNABLE_LANES,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _descriptor,
    _descriptor_file,
    _stable_file,
    validate_amendment,
)
from experiments.local_campaign.current_ollama_phase6 import (
    _counts_from_level1,
    _strict_object,
    validate_completion as validate_base_completion,
)
from experiments.local_campaign.current_ollama_stability_phase6 import (
    FAILED_LANES,
    validate_completion as validate_stability_completion,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    _validate_metric_result,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit,
    _create_json,
    _load_json,
    _option,
    _project_python,
    _replace_option,
    _run_unit,
    _sha256_json,
    _validate_descriptor,
)
from ura.request_envelope import load_request_envelope_file


SCHEMA = "ura-current-ollama-population-alignment-phase6/1"
LAUNCH_SCHEMA = "ura-current-ollama-population-alignment-phase6-launch/1"
CONTRACT_SCHEMA = "ura-current-ollama-population-alignment-contract/1"
UNIT_STATE_SCHEMA = (
    "ura-current-ollama-population-alignment-phase6-unit-state/1"
)
RUNNER_CODE_VERSION = "ura-runner/2.26"
EXPECTED_EXTENSION_ROWS = 11_600
EXPECTED_FULL_BY_MODE = {
    ("static", "text"): 3_854,
    ("static", "image"): 1_632,
    ("rjudge", "text"): 100,
    ("gptgeochat", "image"): 2_020,
}
EXPECTED_PREFIX_BY_MODE = {
    ("static", "text"): 1_945,
    ("static", "image"): 825,
    ("rjudge", "text"): 50,
    ("gptgeochat", "image"): 945,
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AlignmentUnit:
    unit: Unit
    old_lane: str
    full_records: int
    prefix_records: int
    by_corpus: Mapping[str, Mapping[str, int]]
    recovery: Mapping[str, Any]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def alignment_lane(old_lane: str) -> str:
    if old_lane.endswith("-text-primary-50"):
        return old_lane.removesuffix("-text-primary-50") + "-text-primary-100-extension"
    if old_lane.endswith("-image-primary-50"):
        return old_lane.removesuffix("-image-primary-50") + "-image-primary-100-extension"
    if old_lane.startswith("rjudge-ollama-"):
        return old_lane + "-primary-100-extension"
    if old_lane.startswith("gptgeochat-ollama-"):
        return old_lane + "-primary-100-extension"
    raise ValueError(f"{old_lane}: no population-alignment identity")


ALIGNMENT_LANES = tuple(
    alignment_lane(lane) for lane in CURRENT_OLLAMA_RUNNABLE_LANES
)


def _old_selected_corpora(spec: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    projection = spec.get("projection")
    root_value = projection.get("root") if isinstance(projection, dict) else None
    if not isinstance(root_value, str):
        raise ValueError(f"{spec.get('lane_id')}: old projection root changed")
    root = Path(root_value)
    if root.is_symlink() or root.resolve(strict=True) != root:
        raise ValueError(f"{spec.get('lane_id')}: old projection root is not canonical")
    paths = sorted(root.glob("eligibility-*.eligibility.json"))
    if len(paths) != 1:
        raise ValueError(f"{spec.get('lane_id')}: old eligibility inventory changed")
    eligibility = _load_json(paths[0], label="old Ollama eligibility")
    bindings = eligibility.get("bindings")
    selected = bindings.get("selected_corpora") if isinstance(bindings, dict) else None
    if not isinstance(selected, dict):
        raise ValueError(f"{spec.get('lane_id')}: old selected-corpus binding changed")
    result: dict[str, dict[str, Any]] = {}
    for corpus, item in selected.items():
        if not isinstance(corpus, str) or not isinstance(item, dict):
            raise ValueError("old selected-corpus row is malformed")
        result[corpus] = dict(item)
    return result


def _source_instances(
    gate5: Mapping[str, Any], arms: Sequence[str]
) -> dict[str, dict[str, object]]:
    descriptor = gate5.get("source_config")
    path = _descriptor_file(descriptor, label="Ollama source config")
    if not isinstance(descriptor, dict):
        raise ValueError("Ollama source-config descriptor changed")
    instances, _artifact = run_matrix._load_source_config(  # noqa: SLF001
        str(path), list(arms), str(descriptor["sha256"])
    )
    return instances


def _selected_100(
    gate5: Mapping[str, Any], specs: Sequence[Mapping[str, Any]]
) -> dict[str, tuple[list[Any], dict[str, object]]]:
    arms: set[str] = set()
    for spec in specs:
        selection = spec.get("selection")
        corpora = selection.get("corpora") if isinstance(selection, dict) else None
        if not isinstance(corpora, list):
            raise ValueError(f"{spec.get('lane_id')}: retained selection changed")
        arms.update(corpus for corpus in corpora if isinstance(corpus, str))
    ordered_arms = sorted(arms)
    instances = _source_instances(gate5, ordered_arms)
    return {
        corpus: run_matrix.load_corpus_with_audit(
            corpus,
            100,
            0,
            source_instance=instances[corpus],
        )
        for corpus in ordered_arms
    }


def _selected_50(
    gate5: Mapping[str, Any], specs: Sequence[Mapping[str, Any]]
) -> dict[str, tuple[list[Any], dict[str, object]]]:
    arms: set[str] = set()
    for spec in specs:
        selection = spec.get("selection")
        corpora = selection.get("corpora") if isinstance(selection, dict) else None
        if not isinstance(corpora, list):
            raise ValueError(f"{spec.get('lane_id')}: retained selection changed")
        arms.update(corpus for corpus in corpora if isinstance(corpus, str))
    ordered_arms = sorted(arms)
    instances = _source_instances(gate5, ordered_arms)
    return {
        corpus: run_matrix.load_corpus_with_audit(
            corpus,
            50,
            0,
            source_instance=instances[corpus],
        )
        for corpus in ordered_arms
    }


def build_alignment_units(gate5: Mapping[str, Any]) -> list[AlignmentUnit]:
    rows = gate5.get("lanes")
    if (
        not isinstance(rows, list)
        or [row.get("lane_id") for row in rows if isinstance(row, dict)]
        != list(CURRENT_OLLAMA_RUNNABLE_LANES)
    ):
        raise ValueError("Ollama alignment Gate 5 lane inventory changed")
    specs = [dict(row) for row in rows if isinstance(row, dict)]
    selected_100 = _selected_100(gate5, specs)
    selected_50 = _selected_50(gate5, specs)
    units: list[AlignmentUnit] = []
    for spec in specs:
        old_lane = str(spec["lane_id"])
        mode = str(spec.get("metric_mode"))
        modality = str(spec.get("modality"))
        mode_key = (mode, modality)
        if mode_key not in EXPECTED_FULL_BY_MODE:
            raise ValueError(f"{old_lane}: comparable mode changed")
        selection = spec.get("selection")
        corpora = selection.get("corpora") if isinstance(selection, dict) else None
        if (
            not isinstance(corpora, list)
            or not corpora
            or any(not isinstance(item, str) for item in corpora)
            or selection.get("limit") != 50
            or selection.get("sample_seed") != 0
        ):
            raise ValueError(f"{old_lane}: retained selection changed")
        old_selected = _old_selected_corpora(spec)
        if set(old_selected) != set(corpora):
            raise ValueError(f"{old_lane}: retained corpus inventory changed")
        recovery_corpora: dict[str, dict[str, object]] = {}
        population: dict[str, dict[str, int]] = {}
        extension_corpora: list[str] = []
        full_records = 0
        prefix_records = 0
        extension_records = 0
        for corpus in corpora:
            rows_100, audit_100 = selected_100[corpus]
            ids_100 = [row.id for row in rows_100]
            rows_50, audit_50 = selected_50[corpus]
            ids_50 = [row.id for row in rows_50]
            old = old_selected[corpus]
            old_count = old.get("selected_records")
            old_ids_sha = old.get("selected_datapoint_ids_sha256")
            if (
                isinstance(old_count, bool)
                or not isinstance(old_count, int)
                or old_count < 1
                or not isinstance(old_ids_sha, str)
                or HEX64.fullmatch(old_ids_sha) is None
                or old.get("limit") != 50
                or old.get("sample_seed") != 0
                or old.get("full_converted_corpus_sha256")
                != audit_100.get("full_converted_corpus_sha256")
                or audit_50.get("full_converted_corpus_sha256")
                != audit_100.get("full_converted_corpus_sha256")
                or old_count != len(ids_50)
                or _sha256_json(sorted(ids_50)) != old_ids_sha
                or len(set(ids_50)) != len(ids_50)
                or len(set(ids_100)) != len(ids_100)
                or not set(ids_50).issubset(ids_100)
            ):
                raise ValueError(f"{old_lane}/{corpus}: limit-50 prefix changed")
            completed_ids = sorted(ids_50)
            completed = set(completed_ids)
            remaining_ids = [item for item in ids_100 if item not in completed]
            delta = len(remaining_ids)
            full_records += len(ids_100)
            prefix_records += old_count
            extension_records += delta
            population[corpus] = {
                "limit_100_records": len(ids_100),
                "limit_50_prefix_records": old_count,
                "extension_records": delta,
            }
            if delta == 0:
                continue
            extension_corpora.append(corpus)
            recovery_corpora[corpus] = {
                "completed_record_count": old_count,
                "selected_datapoint_ids_sha256": _sha256_json(ids_100),
                "completed_datapoint_ids": completed_ids,
                "completed_datapoint_ids_sha256": old_ids_sha,
                "remaining_datapoint_ids_sha256": _sha256_json(remaining_ids),
            }
        if (
            full_records != EXPECTED_FULL_BY_MODE[mode_key]
            or prefix_records != EXPECTED_PREFIX_BY_MODE[mode_key]
            or extension_records != full_records - prefix_records
            or not extension_corpora
        ):
            raise ValueError(f"{old_lane}: population-alignment counts changed")
        lane = alignment_lane(old_lane)
        base = spec.get("base_argv")
        if not isinstance(base, list) or any(not isinstance(item, str) for item in base):
            raise ValueError(f"{old_lane}: base argv changed")
        base = _replace_option(base, "--limit", "100")
        base = _replace_option(base, "--sample-seed", "0")
        base = _replace_option(base, "--target-answer-retries", "1")
        base = _replace_option(base, "--corpora", ",".join(extension_corpora))
        aligned_spec = {
            **spec,
            "lane_id": lane,
            "base_argv": base,
            "selection": {
                **selection,
                "corpora": extension_corpora,
                "limit": 100,
                "sample_seed": 0,
            },
            "selected_records": extension_records,
        }
        recovery = {
            "schema": "ura-recovery-completed-selection/1",
            "corpora": recovery_corpora,
        }
        units.append(
            AlignmentUnit(
                unit=Unit(
                    unit_id=lane,
                    source_lane=lane,
                    corpus=None,
                    spec=aligned_spec,
                    selected_records=extension_records,
                    recovery=recovery,
                ),
                old_lane=old_lane,
                full_records=full_records,
                prefix_records=prefix_records,
                by_corpus=population,
                recovery=recovery,
            )
        )
    if (
        tuple(item.unit.unit_id for item in units) != ALIGNMENT_LANES
        or sum(item.unit.selected_records for item in units)
        != EXPECTED_EXTENSION_ROWS
    ):
        raise ValueError("Ollama population-alignment total changed")
    return units


def _validate_prefix_complete(
    *,
    gate5_path: Path,
    stability_path: Path,
    runner_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    gate5 = validate_amendment(gate5_path)
    stability = validate_stability_completion(
        stability_path, runner_root=runner_root
    )
    completion = _load_json(stability_path, label="Ollama stability completion")
    launch_path = _validate_descriptor(
        completion.get("launch"), label="Ollama stability launch"
    )
    launch = _load_json(launch_path, label="Ollama stability launch")
    if launch.get("gate5") != _descriptor(gate5_path, label="retained Ollama Gate 5"):
        raise ValueError("Ollama stability completion binds another Gate 5")
    base_path = _validate_descriptor(
        launch.get("base_completion"), label="retained Ollama base completion"
    )
    base = validate_base_completion(
        gate5_path=gate5_path,
        completion_path=base_path,
        runner_root=runner_root,
    )
    by_lane = {str(row["lane_id"]): row for row in gate5["lanes"]}
    stability_results = completion.get("unit_results")
    if not isinstance(stability_results, dict):
        raise ValueError("Ollama stability result inventory changed")
    for lane in CURRENT_OLLAMA_RUNNABLE_LANES:
        expected = int(by_lane[lane]["selected_records"])
        if lane in FAILED_LANES:
            recovered = sum(
                int(row["selected_records"])
                for row in stability_results.values()
                if isinstance(row, dict) and row.get("source_lane") == lane
            )
            durable = int(stability["historical_durable_rows"][lane])
            if base["terminal_states"][lane] != "failed" or durable + recovered != expected:
                raise ValueError(f"{lane}: retained prefix is incomplete")
        else:
            if base["terminal_states"][lane] != "measured_complete":
                raise ValueError(f"{lane}: retained prefix is not complete")
            level1_path = _descriptor_file(
                base["metric_evidence"][lane]["level1"],
                label=f"{lane} retained Level 1",
            )
            attempts, _successful, _missing = _counts_from_level1(
                _strict_object(level1_path, label=f"{lane} retained Level 1")
            )
            if attempts != expected:
                raise ValueError(f"{lane}: retained prefix row count changed")
    return gate5, stability


def _contract_row(
    item: AlignmentUnit, selector_path: Path
) -> dict[str, Any]:
    unit = item.unit
    return {
        "lane_id": unit.unit_id,
        "retained_prefix_lane_id": item.old_lane,
        "modality": unit.spec["modality"],
        "metric_mode": unit.spec["metric_mode"],
        "corpora": unit.spec["selection"]["corpora"],
        "limit": 100,
        "sample_seed": 0,
        "target_answer_retries": 1,
        "limit_100_records": item.full_records,
        "limit_50_prefix_records": item.prefix_records,
        "extension_records": unit.selected_records,
        "population_by_corpus": dict(item.by_corpus),
        "recovery_selection": _descriptor(
            selector_path, label=f"{unit.unit_id} recovery selection"
        ),
    }


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    control_root = completion_path.parent
    completion = _load_json(
        completion_path, label="Ollama population-alignment completion"
    )
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "launch",
        "population_contract",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "population_alignment",
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
        or completion.get("unit_order") != list(ALIGNMENT_LANES)
        or completion.get("unit_failures") != {}
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("Ollama population-alignment completion changed")
    launch_path = _validate_descriptor(
        completion.get("launch"), label="Ollama alignment launch"
    )
    contract_path = _validate_descriptor(
        completion.get("population_contract"), label="Ollama alignment contract"
    )
    if launch_path != control_root / "launch.json" or contract_path != (
        control_root / "population-contract.json"
    ):
        raise ValueError("Ollama alignment controller artifact placement changed")
    launch = _load_json(launch_path, label="Ollama alignment launch")
    if (
        launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("expected_commit") != completion["expected_commit"]
        or launch.get("target_answer_retries") != 1
        or launch.get("unit_order") != list(ALIGNMENT_LANES)
        or launch.get("extension_rows") != EXPECTED_EXTENSION_ROWS
        or launch.get("no_completed_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
    ):
        raise ValueError("Ollama population-alignment launch changed")
    gate5_path = _validate_descriptor(
        launch.get("gate5"), label="retained Ollama Gate 5"
    )
    stability_path = _validate_descriptor(
        launch.get("stability_completion"), label="Ollama stability completion"
    )
    gate5, _stability = _validate_prefix_complete(
        gate5_path=gate5_path,
        stability_path=stability_path,
        runner_root=runner_root,
    )
    contract = _load_json(contract_path, label="Ollama alignment contract")
    rows = contract.get("lanes")
    if (
        contract.get("schema") != CONTRACT_SCHEMA
        or contract.get("limit") != 100
        or contract.get("sample_seed") != 0
        or contract.get("target_answer_retries") != 1
        or contract.get("extension_rows") != EXPECTED_EXTENSION_ROWS
        or not isinstance(rows, list)
        or [row.get("lane_id") for row in rows if isinstance(row, dict)]
        != list(ALIGNMENT_LANES)
    ):
        raise ValueError("Ollama population-alignment contract changed")
    results = completion.get("unit_results")
    if not isinstance(results, dict) or list(results) != list(ALIGNMENT_LANES):
        raise ValueError("Ollama population-alignment results changed")
    revisions: set[str] = set()
    sources: set[str] = set()
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility: list[dict[str, object]] = []
    metric_markers: list[dict[str, object]] = []
    successful = 0
    missing = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Ollama population-alignment lane row changed")
        lane = str(row.get("lane_id"))
        if (
            row.get("limit") != 100
            or row.get("sample_seed") != 0
            or row.get("target_answer_retries") != 1
            or row.get("limit_100_records")
            != EXPECTED_FULL_BY_MODE[(row.get("metric_mode"), row.get("modality"))]
            or row.get("limit_50_prefix_records")
            != EXPECTED_PREFIX_BY_MODE[(row.get("metric_mode"), row.get("modality"))]
            or row.get("extension_records")
            != row.get("limit_100_records") - row.get("limit_50_prefix_records")
        ):
            raise ValueError(f"{lane}: population contract counts changed")
        selector_path = _validate_descriptor(
            row.get("recovery_selection"), label=f"{lane} recovery selection"
        )
        if selector_path != (
            control_root / "inputs" / f"{lane}.completed-selection.json"
        ):
            raise ValueError(f"{lane}: recovery selection placement changed")
        selector = _load_json(selector_path, label=f"{lane} recovery selection")
        if (
            selector.get("schema") != "ura-recovery-completed-selection/1"
            or set(selector.get("corpora", {})) != set(row.get("corpora", []))
        ):
            raise ValueError(f"{lane}: recovery selection changed")
        validated = _validate_metric_result(
            results[lane],
            logical_lane=lane,
            physical_unit=lane,
            source_lane=lane,
            corpus=None,
            selected_records=int(row["extension_records"]),
            runner_root=runner_root,
            control_root=control_root,
            state_schema=UNIT_STATE_SCHEMA,
            completion=completion["population_contract"],
        )
        state_path = _validate_descriptor(
            results[lane]["state"], label=f"{lane} measured state"
        )
        state = _load_json(state_path, label=f"{lane} measured state")
        argv = state["runner_argv"]
        selector_sha = hashlib.sha256(selector_path.read_bytes()).hexdigest()
        if (
            _option(argv, "--limit") != "100"
            or _option(argv, "--sample-seed") != "0"
            or _option(argv, "--target-answer-retries") != "1"
            or _option(argv, "--corpora") != ",".join(row["corpora"])
            or _option(argv, "--recovery-completed-prefix") != str(selector_path)
            or _option(argv, "--recovery-completed-prefix-sha256") != selector_sha
        ):
            raise ValueError(f"{lane}: measured population argv changed")
        envelopes = sorted(Path(validated["root"]).glob("*.request-envelope.json"))
        if len(envelopes) != 1:
            raise ValueError(f"{lane}: request-envelope inventory changed")
        envelope, _descriptor_value = load_request_envelope_file(envelopes[0])
        request = envelope["request"]
        if (
            envelope.get("schema") != "ura-request-envelope/6"
            or request.get("target_answer_retries") != 1
            or request.get("limit") != 100
            or set(request.get("logical_source_arms", [])) != set(row["corpora"])
            or request.get("recovery_selection", {}).get("schema")
            != "ura-recovery-completed-selection/1"
        ):
            raise ValueError(f"{lane}: request retry/recovery binding changed")
        revisions.add(str(validated["revision"]))
        sources.add(str(validated["source"]))
        metric_roots[lane] = str(validated["root"])
        metric_evidence[lane] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_eligibility.append(dict(validated["eligibility_plan"]))
        metric_markers.extend(validated["completion_markers"])
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    target_execution = completion.get("target_execution")
    if (
        target_execution
        != {
            "target_attempts": EXPECTED_EXTENSION_ROWS,
            "successful_target_generations": successful,
            "missing_responses": missing,
        }
        or successful + missing != EXPECTED_EXTENSION_ROWS
        or len(revisions) != 1
        or len(sources) != 1
        or completion.get("population_alignment")
        != {
            "limit_50_prefix_rows": 11_520,
            "limit_100_total_rows": 23_120,
            "extension_rows": EXPECTED_EXTENSION_ROWS,
        }
    ):
        raise ValueError("Ollama population-alignment accounting changed")
    return {
        "completion": _descriptor(
            completion_path, label="Ollama population-alignment completion"
        ),
        "runner_code_version": RUNNER_CODE_VERSION,
        "unit_order": list(ALIGNMENT_LANES),
        "terminal_states": {lane: "measured_complete" for lane in ALIGNMENT_LANES},
        "metric_lane_order": list(ALIGNMENT_LANES),
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility,
        "metric_completion_markers": metric_markers,
        "revision_strata": {next(iter(revisions)): list(ALIGNMENT_LANES)},
        "project_revision_receipt_sha256": next(iter(revisions)),
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": dict(target_execution),
        "population_alignment": dict(completion["population_alignment"]),
        "no_completed_rows_repeated": True,
        "cross_revision_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    runner_root = work_root / "runs/thesis/runner"
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh Ollama population-alignment root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("Ollama population-alignment root must be one direct campaign")
    for path, digest, label in (
        (args.gate5_amendment, args.gate5_amendment_sha256, "retained Gate 5"),
        (
            args.stability_completion,
            args.stability_completion_sha256,
            "Ollama stability completion",
        ),
        (args.project_revision, args.project_revision_sha256, "project revision"),
    ):
        payload = _stable_file(path.resolve(strict=True), label=label)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"{label} digest changed")
    gate5, _stability = _validate_prefix_complete(
        gate5_path=args.gate5_amendment,
        stability_path=args.stability_completion,
        runner_root=runner_root,
    )
    units = build_alignment_units(gate5)
    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    inputs = control_root / "inputs"
    inputs.mkdir(mode=0o700)
    contract_rows: list[dict[str, Any]] = []
    selectors: dict[str, tuple[Path, str]] = {}
    for item in units:
        lane = item.unit.unit_id
        path = inputs / f"{lane}.completed-selection.json"
        _create_json(path, item.recovery)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        selectors[lane] = (path, digest)
        contract_rows.append(_contract_row(item, path))
    contract = {
        "schema": CONTRACT_SCHEMA,
        "created_at_utc": _utc_now(),
        "limit": 100,
        "sample_seed": 0,
        "target_answer_retries": 1,
        "extension_rows": EXPECTED_EXTENSION_ROWS,
        "lanes": contract_rows,
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    contract_path = control_root / "population-contract.json"
    _create_json(contract_path, contract)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "gate5": _descriptor(args.gate5_amendment, label="retained Ollama Gate 5"),
        "stability_completion": _descriptor(
            args.stability_completion, label="Ollama stability completion"
        ),
        "population_contract": _descriptor(
            contract_path, label="Ollama population-alignment contract"
        ),
        "unit_order": list(ALIGNMENT_LANES),
        "extension_rows": EXPECTED_EXTENSION_ROWS,
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
        evidence_class="measured_local_ollama_population_alignment",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )
    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for item in units:
        unit = item.unit
        selector_path, selector_sha = selectors[unit.unit_id]
        try:
            results[unit.unit_id] = _run_unit(
                unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=args.project_revision.resolve(strict=True),
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=selector_path,
                recovery_sha256=selector_sha,
                state_schema=UNIT_STATE_SCHEMA,
            )
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
                "unit_id": unit.unit_id,
                "stage": "gate5_or_measured",
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
        "launch": _descriptor(launch_path, label="Ollama alignment launch"),
        "population_contract": _descriptor(
            contract_path, label="Ollama population-alignment contract"
        ),
        "unit_order": list(ALIGNMENT_LANES),
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempts,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "population_alignment": {
            "limit_50_prefix_rows": 11_520,
            "limit_100_total_rows": 23_120,
            "extension_rows": EXPECTED_EXTENSION_ROWS,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate5-amendment", type=Path, required=True)
    parser.add_argument("--gate5-amendment-sha256", required=True)
    parser.add_argument("--stability-completion", type=Path, required=True)
    parser.add_argument("--stability-completion-sha256", required=True)
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
        print(f"Ollama population alignment failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
