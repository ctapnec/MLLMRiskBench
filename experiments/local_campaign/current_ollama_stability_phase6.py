"""Run only the never-completed current-Ollama rows under Runner 2.26.

The retained Runner 2.24 cohort is immutable. Its exact-argv recovery remains
terminal evidence, but an open durable circuit prevents it from advancing. This
controller validates that zero-progress boundary, excludes every completed row,
and creates fresh per-corpus Runner 2.26 conditions for only the missing suffix
or never-started population.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
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
from experiments.local_campaign.current_ollama_gate5 import validate_amendment
from experiments.local_campaign.current_ollama_phase6 import (
    _descriptor,
    _load_json,
    _stable_file,
    validate_completion as validate_base_completion,
)
from experiments.local_campaign.resume_current_ollama_phase6 import (
    SCHEMA as FAILED_RECOVERY_SCHEMA,
    _checkpoint_records,
    _completed_records,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    PREFIX_SCHEMA,
    Unit,
    _canonical,
    _create_json,
    _framework_lock_id,
    _option,
    _project_python,
    _run_unit,
    _sha256_json,
    _validate_descriptor,
)


SCHEMA = "ura-current-ollama-stability-phase6/1"
UNIT_STATE_SCHEMA = "ura-current-ollama-stability-phase6-unit-state/1"
RUNNER_CODE_VERSION = "ura-runner/2.26"
FAILED_LANES = (
    "ollama-gemma4-12b-text-primary-50",
    "ollama-gemma4-12b-image-primary-50",
    "ollama-ministral3-14b-image-primary-50",
)
EXPECTED_DURABLE_COUNTS = {
    "ollama-gemma4-12b-text-primary-50": (450, 430),
    "ollama-gemma4-12b-image-primary-50": (501, 2),
    "ollama-ministral3-14b-image-primary-50": (501, 27),
}
EXPECTED_LAYOUT = (
    (
        "ollama-stability-gemma4-text-airbench-suffix",
        FAILED_LANES[0],
        "airbench_full",
        515,
        430,
    ),
    (
        "ollama-stability-gemma4-text-xstest-full",
        FAILED_LANES[0],
        "xstest_full",
        50,
        0,
    ),
    (
        "ollama-stability-gemma4-text-simplesafetytests-full",
        FAILED_LANES[0],
        "simplesafetytests_full",
        50,
        0,
    ),
    (
        "ollama-stability-gemma4-text-decodingtrust-stereotype",
        FAILED_LANES[0],
        "decodingtrust_stereotype",
        450,
        0,
    ),
    (
        "ollama-stability-gemma4-image-mllmguard-privacy-suffix",
        FAILED_LANES[1],
        "mllmguard_privacy",
        48,
        2,
    ),
    (
        "ollama-stability-gemma4-image-mllmguard-bias",
        FAILED_LANES[1],
        "mllmguard_bias",
        50,
        0,
    ),
    (
        "ollama-stability-gemma4-image-mllmguard-toxicity",
        FAILED_LANES[1],
        "mllmguard_toxicity",
        50,
        0,
    ),
    (
        "ollama-stability-gemma4-image-mllmguard-legality",
        FAILED_LANES[1],
        "mllmguard_legality",
        50,
        0,
    ),
    (
        "ollama-stability-gemma4-image-holisafe-full",
        FAILED_LANES[1],
        "holisafe_full",
        124,
        0,
    ),
    (
        "ollama-stability-ministral3-image-mllmguard-privacy-suffix",
        FAILED_LANES[2],
        "mllmguard_privacy",
        23,
        27,
    ),
    (
        "ollama-stability-ministral3-image-mllmguard-bias",
        FAILED_LANES[2],
        "mllmguard_bias",
        50,
        0,
    ),
    (
        "ollama-stability-ministral3-image-mllmguard-toxicity",
        FAILED_LANES[2],
        "mllmguard_toxicity",
        50,
        0,
    ),
    (
        "ollama-stability-ministral3-image-mllmguard-legality",
        FAILED_LANES[2],
        "mllmguard_legality",
        50,
        0,
    ),
    (
        "ollama-stability-ministral3-image-holisafe-full",
        FAILED_LANES[2],
        "holisafe_full",
        124,
        0,
    ),
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _input_json(path: Path, sha256: str, *, label: str) -> dict[str, Any]:
    if HEX64.fullmatch(sha256) is None:
        raise ValueError(f"{label} SHA-256 is invalid")
    payload = _stable_file(path, label=label)
    if hashlib.sha256(payload).hexdigest() != sha256:
        raise ValueError(f"{label} digest changed")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not one object")
    return value


def validate_failed_recovery(
    *,
    gate5_path: Path,
    base_completion: Path,
    recovery_completion: Path,
    runner_root: Path,
) -> dict[str, Any]:
    """Require the exact terminal, zero-progress old-Runner recovery."""

    base = validate_base_completion(
        gate5_path=gate5_path,
        completion_path=base_completion,
        runner_root=runner_root,
    )
    selected = tuple(
        lane for lane, state in base["terminal_states"].items() if state == "failed"
    )
    if selected != FAILED_LANES:
        raise ValueError("current Ollama failed-lane partition changed")
    gate5 = validate_amendment(gate5_path)
    control = recovery_completion.parent.resolve(strict=True)
    if (
        recovery_completion != control / "completion.json"
        or not control.name.startswith("phase6-current-ollama-recovery-r2-")
    ):
        raise ValueError("failed recovery completion path changed")
    value = _load_json(recovery_completion, label="failed current Ollama recovery")
    fields = {
        "schema",
        "status",
        "base_phase6",
        "gate5",
        "controller_source",
        "project_commit",
        "failed_lanes_selected",
        "recovered_lanes",
        "remaining_failed_lanes",
        "rows",
        "paid_provider_calls",
        "recovery_id",
    }
    if (
        set(value) != fields
        or value.get("schema") != FAILED_RECOVERY_SCHEMA
        or value.get("status") != "complete_with_failures"
        or value.get("base_phase6")
        != _descriptor(base_completion, label="base current Ollama Phase 6")
        or value.get("gate5") != _descriptor(gate5_path, label="current Ollama Gate 5")
        or value.get("project_commit") != gate5.get("project_commit")
        or value.get("failed_lanes_selected") != list(FAILED_LANES)
        or value.get("recovered_lanes") != 0
        or value.get("remaining_failed_lanes") != len(FAILED_LANES)
        or value.get("paid_provider_calls") != 0
        or _stable_file(control / ".exit", label="failed recovery exit") != b"1\n"
    ):
        raise ValueError("failed current Ollama recovery contract changed")
    _validate_descriptor(
        value.get("controller_source"), label="failed recovery controller source"
    )
    identity = dict(value)
    recovery_id = identity.pop("recovery_id", None)
    expected_id = (
        "current-ollama-recovery-"
        + hashlib.sha256(_canonical(identity)).hexdigest()[:24]
    )
    if recovery_id != expected_id:
        raise ValueError("failed recovery identity changed")
    rows = value.get("rows")
    if (
        not isinstance(rows, list)
        or [row.get("lane_id") if isinstance(row, dict) else None for row in rows]
        != list(FAILED_LANES)
    ):
        raise ValueError("failed recovery row inventory changed")
    row_fields = {
        "lane_id",
        "status",
        "initial_completed_responses",
        "initial_checkpointed_responses",
        "launches",
        "result_root",
        "target_attempts",
        "successful_target_generations",
        "missing_responses",
        "final_completed_responses",
        "final_checkpointed_responses",
    }
    for row in rows:
        if not isinstance(row, dict) or set(row) != row_fields:
            raise ValueError("failed recovery row fields changed")
        lane = str(row["lane_id"])
        completed, checkpointed = EXPECTED_DURABLE_COUNTS[lane]
        expected_root = Path(base["lifecycle"][lane]["result_root"])
        if (
            row.get("status") != "failed"
            or row.get("initial_completed_responses") != completed
            or row.get("initial_checkpointed_responses") != checkpointed
            or row.get("final_completed_responses") != completed
            or row.get("final_checkpointed_responses") != checkpointed
            or row.get("target_attempts") is not None
            or row.get("successful_target_generations") is not None
            or row.get("missing_responses") is not None
            or Path(str(row.get("result_root"))) != expected_root
        ):
            raise ValueError(f"{lane}: failed recovery accounting changed")
        launches = row.get("launches")
        if not isinstance(launches, list) or len(launches) != 10:
            raise ValueError(f"{lane}: failed recovery launch inventory changed")
        lane_root = control / "lanes" / lane
        for number, launch in enumerate(launches, start=1):
            if (
                not isinstance(launch, dict)
                or set(launch) != {"number", "returncode", "log"}
                or launch.get("number") != number
                or launch.get("returncode") == 0
            ):
                raise ValueError(f"{lane}: failed recovery launch changed")
            log = _validate_descriptor(
                launch.get("log"), label=f"{lane} failed recovery launch {number}"
            )
            if log != lane_root / f"resume-{number}.log":
                raise ValueError(f"{lane}: failed recovery launch path changed")
        if (
            _completed_records(expected_root) != completed
            or _checkpoint_records(expected_root) != checkpointed
        ):
            raise ValueError(f"{lane}: durable response counts changed")
    return {"base": base, "gate5": gate5, "recovery": value}


def _projection_counts(spec: Mapping[str, Any]) -> dict[str, int]:
    projection = spec.get("projection")
    root_raw = projection.get("root") if isinstance(projection, dict) else None
    if not isinstance(root_raw, str) or not root_raw.startswith("/"):
        raise ValueError(f"{spec.get('lane_id')}: projection root changed")
    root = Path(root_raw).resolve(strict=True)
    files = sorted(root.glob("lane-projection-*.lane-projection.json"))
    if len(files) != 1:
        raise ValueError(f"{spec.get('lane_id')}: projection inventory changed")
    value = _load_json(files[0], label=f"{spec.get('lane_id')} final projection")
    selection = value.get("selection")
    arms = selection.get("arms") if isinstance(selection, dict) else None
    if not isinstance(arms, list) or not arms:
        raise ValueError(f"{spec.get('lane_id')}: projection arms changed")
    result: dict[str, int] = {}
    for arm in arms:
        name = arm.get("logical_source_arm") if isinstance(arm, dict) else None
        count = arm.get("selected_records") if isinstance(arm, dict) else None
        if (
            not isinstance(name, str)
            or name in result
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
        ):
            raise ValueError(f"{spec.get('lane_id')}: projection arm changed")
        result[name] = count
    return result


def _corpus_state(
    *, corpus: str, selected_records: int, result_root: Path
) -> tuple[int, dict[str, Any] | None, bool]:
    manifests = sorted(result_root.glob(f"{corpus}--*.manifest.json"))
    attempts = sorted(result_root.glob(f"{corpus}--*.attempts.jsonl"))
    markers = sorted(result_root.glob(f"{corpus}--*.complete.json"))
    if not manifests and not attempts and not markers:
        return 0, None, False
    if len(manifests) != 1 or len(attempts) != 1 or len(markers) > 1:
        raise ValueError(f"{corpus}: historical artifact inventory changed")
    manifest = _load_json(manifests[0], label=f"{corpus} historical manifest")
    config = manifest.get("config")
    run = config.get("run") if isinstance(config, dict) else None
    audit = run.get("sampling_audit") if isinstance(run, dict) else None
    selected_ids = audit.get("selected_ids") if isinstance(audit, dict) else None
    if (
        not isinstance(selected_ids, list)
        or len(selected_ids) != selected_records
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or len(set(selected_ids)) != len(selected_ids)
    ):
        raise ValueError(f"{corpus}: historical selected identities changed")
    completed_ids: list[str] = []
    for raw in _stable_file(attempts[0], label=f"{corpus} historical attempts").splitlines():
        if not raw:
            continue
        row = json.loads(raw.decode("utf-8"))
        datapoint_id = row.get("datapoint_id") if isinstance(row, dict) else None
        if not isinstance(datapoint_id, str) or not datapoint_id:
            raise ValueError(f"{corpus}: historical attempt identity changed")
        completed_ids.append(datapoint_id)
    if (
        not completed_ids
        or len(set(completed_ids)) != len(completed_ids)
        or completed_ids != selected_ids[: len(completed_ids)]
        or len(completed_ids) > selected_records
    ):
        raise ValueError(f"{corpus}: historical rows are not one exact prefix")
    complete = bool(markers)
    if complete:
        marker = _load_json(markers[0], label=f"{corpus} historical completion")
        if (
            len(completed_ids) != selected_records
            or marker.get("n_responses") != selected_records
        ):
            raise ValueError(f"{corpus}: historical completion count changed")
        return selected_records, None, True
    if len(completed_ids) >= selected_records:
        raise ValueError(f"{corpus}: unsealed historical population is complete")
    remaining = selected_ids[len(completed_ids) :]
    recovery = {
        "schema": PREFIX_SCHEMA,
        "corpus": corpus,
        "completed_prefix_count": len(completed_ids),
        "selected_datapoint_ids_sha256": _sha256_json(selected_ids),
        "completed_prefix_ids_sha256": _sha256_json(completed_ids),
        "remaining_datapoint_ids_sha256": _sha256_json(remaining),
    }
    return len(completed_ids), recovery, False


def build_units(
    *, gate5: Mapping[str, Any], base: Mapping[str, Any]
) -> tuple[list[Unit], dict[str, int]]:
    specs = {
        str(row.get("lane_id")): row
        for row in gate5.get("lanes", [])
        if isinstance(row, dict) and row.get("lane_id") in FAILED_LANES
    }
    if tuple(specs) != FAILED_LANES:
        raise ValueError("current Ollama failed-lane Gate 5 inventory changed")
    layout_by_key = {
        (lane, corpus): (unit_id, remaining, prefix)
        for unit_id, lane, corpus, remaining, prefix in EXPECTED_LAYOUT
    }
    units: list[Unit] = []
    durable_by_lane: dict[str, int] = {}
    observed_layout: list[tuple[str, str, str, int, int]] = []
    for lane in FAILED_LANES:
        spec = specs[lane]
        counts = _projection_counts(spec)
        selection = spec.get("selection")
        corpora = selection.get("corpora") if isinstance(selection, dict) else None
        if not isinstance(corpora, list) or set(corpora) != set(counts):
            raise ValueError(f"{lane}: Gate 5 corpus inventory changed")
        result_root = Path(str(base["lifecycle"][lane]["result_root"])).resolve(
            strict=True
        )
        durable = 0
        for corpus in corpora:
            if not isinstance(corpus, str):
                raise ValueError(f"{lane}: Gate 5 corpus identity changed")
            completed, recovery, complete = _corpus_state(
                corpus=corpus,
                selected_records=counts[corpus],
                result_root=result_root,
            )
            durable += completed
            if complete:
                continue
            key = (lane, corpus)
            if key not in layout_by_key:
                raise ValueError(f"{lane}/{corpus}: unexpected incomplete population")
            unit_id, expected_remaining, expected_prefix = layout_by_key[key]
            remaining = counts[corpus] - completed
            observed_layout.append((unit_id, lane, corpus, remaining, completed))
            if remaining != expected_remaining or completed != expected_prefix:
                raise ValueError(f"{lane}/{corpus}: remaining population changed")
            units.append(
                Unit(
                    unit_id=unit_id,
                    source_lane=lane,
                    corpus=corpus,
                    spec=spec,
                    selected_records=remaining,
                    recovery=recovery,
                )
            )
        durable_by_lane[lane] = durable
    if tuple(observed_layout) != EXPECTED_LAYOUT:
        raise ValueError("current Ollama stability unit inventory changed")
    expected_durable = {
        lane: completed + checkpointed
        for lane, (completed, checkpointed) in EXPECTED_DURABLE_COUNTS.items()
    }
    if durable_by_lane != expected_durable:
        raise ValueError("current Ollama durable population changed")
    return units, durable_by_lane


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the exact all-complete Runner 2.26 Ollama continuation."""

    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    schema = _load_json(
        completion_path, label="current Ollama stability completion"
    ).get("schema")
    if schema == "ura-current-ollama-stability-continuation-phase6/1":
        from experiments.local_campaign.current_ollama_stability_continuation_phase6 import (
            validate_completion as validate_continuation,
        )

        return validate_continuation(completion_path, runner_root=runner_root)
    if schema == "ura-current-ollama-stability-canary-recovery-phase6/1":
        from experiments.local_campaign.current_ollama_stability_canary_recovery_phase6 import (
            validate_completion as validate_canary_recovery,
        )

        return validate_canary_recovery(completion_path, runner_root=runner_root)
    control_root = completion_path.parent
    completion = _load_json(
        completion_path, label="current Ollama stability completion"
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
        "unit_order",
        "unit_results",
        "unit_failures",
        "historical_durable_rows",
        "selected_missing_rows",
        "target_execution",
        "model_stability_accounting",
        "no_completed_rows_repeated",
        "cross_output_policy_pooling_permitted",
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
        or completion.get("model_stability_accounting")
        != "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        or completion.get("no_completed_rows_repeated") is not True
        or completion.get("cross_output_policy_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            str(completion.get("completed_at_utc", "")),
        )
        is None
    ):
        raise ValueError("current Ollama stability completion contract changed")

    launch_path = _validate_descriptor(
        completion.get("launch"), label="current Ollama stability launch"
    )
    if launch_path != control_root / "launch.json":
        raise ValueError("current Ollama stability launch placement changed")
    launch = _load_json(launch_path, label="current Ollama stability launch")
    launch_fields = {
        "schema",
        "started_at_utc",
        "expected_commit",
        "execution_scope_id",
        "target_answer_retries",
        "gate5",
        "base_completion",
        "failed_recovery_completion",
        "historical_durable_rows",
        "unit_order",
        "selected_missing_rows",
        "no_completed_rows_repeated",
        "paid_provider_calls",
    }
    if (
        set(launch) != launch_fields
        or launch.get("schema") != "ura-current-ollama-stability-phase6-launch/1"
        or launch.get("expected_commit") != completion.get("expected_commit")
        or launch.get("target_answer_retries") != 1
        or not isinstance(launch.get("execution_scope_id"), str)
        or not launch["execution_scope_id"].strip()
        or launch.get("no_completed_rows_repeated") is not True
        or launch.get("paid_provider_calls") != 0
    ):
        raise ValueError("current Ollama stability launch contract changed")
    gate5_path = _validate_descriptor(
        launch.get("gate5"), label="current Ollama stability Gate 5"
    )
    base_path = _validate_descriptor(
        launch.get("base_completion"),
        label="current Ollama stability base completion",
    )
    recovery_path = _validate_descriptor(
        launch.get("failed_recovery_completion"),
        label="current Ollama stability failed recovery",
    )
    historical = validate_failed_recovery(
        gate5_path=gate5_path,
        base_completion=base_path,
        recovery_completion=recovery_path,
        runner_root=runner_root,
    )
    units, durable = build_units(
        gate5=historical["gate5"], base=historical["base"]
    )
    expected_order = [unit.unit_id for unit in units]
    selected_by_unit = {unit.unit_id: unit.selected_records for unit in units}
    selected_total = sum(selected_by_unit.values())
    if (
        completion.get("unit_order") != expected_order
        or completion.get("historical_durable_rows") != durable
        or completion.get("selected_missing_rows") != selected_total
        or launch.get("unit_order") != expected_order
        or launch.get("historical_durable_rows") != durable
        or launch.get("selected_missing_rows") != selected_total
    ):
        raise ValueError("current Ollama stability population changed")

    results = completion.get("unit_results")
    if not isinstance(results, dict) or list(results) != expected_order:
        raise ValueError("current Ollama stability result inventory changed")
    result_fields = {
        "status",
        "unit_id",
        "source_lane",
        "corpus",
        "selected_records",
        "target_answer_retries",
        "target_call_cap",
        "target_attempts",
        "successful_target_generations",
        "missing_responses",
        "result_root",
        "state",
        "level1",
    }
    state_fields = {
        "schema",
        "unit_id",
        "source_lane",
        "corpus",
        "selected_records",
        "target_answer_retries",
        "target_call_cap",
        "attestation",
        "projection",
        "result_root",
        "runner_argv",
    }
    units_by_id = {unit.unit_id: unit for unit in units}
    revisions: set[str] = set()
    sources: set[str] = set()
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility_plans: list[dict[str, object]] = []
    metric_completion_markers: list[dict[str, object]] = []
    total_successful = 0
    total_missing = 0
    for unit_id in expected_order:
        unit = units_by_id[unit_id]
        selected = selected_by_unit[unit_id]
        result = results.get(unit_id)
        successful = result.get("successful_target_generations") if isinstance(result, dict) else None
        missing = result.get("missing_responses") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or set(result) != result_fields
            or result.get("status") != "complete"
            or result.get("unit_id") != unit_id
            or result.get("source_lane") != unit.source_lane
            or result.get("corpus") != unit.corpus
            or result.get("selected_records") != selected
            or result.get("target_answer_retries") != 1
            or result.get("target_call_cap") != selected * 2
            or result.get("target_attempts") != selected
            or isinstance(successful, bool)
            or not isinstance(successful, int)
            or successful < 0
            or isinstance(missing, bool)
            or not isinstance(missing, int)
            or missing < 0
            or successful + missing != selected
        ):
            raise ValueError(f"{unit_id}: stability result accounting changed")
        result_root = Path(str(result.get("result_root", "")))
        expected_root = runner_root / unit_id / control_root.name
        if (
            not result_root.is_absolute()
            or result_root.is_symlink()
            or result_root.resolve(strict=True) != expected_root
        ):
            raise ValueError(f"{unit_id}: stability result root changed")
        state_path = _validate_descriptor(result.get("state"), label=f"{unit_id} state")
        level1_path = _validate_descriptor(
            result.get("level1"), label=f"{unit_id} Level 1 evidence"
        )
        unit_root = control_root / "units" / unit_id
        if state_path != unit_root / "state.json" or level1_path != unit_root / "level1.json":
            raise ValueError(f"{unit_id}: controller artifact placement changed")
        state = _load_json(state_path, label=f"{unit_id} state")
        argv = state.get("runner_argv")
        if (
            set(state) != state_fields
            or state.get("schema") != UNIT_STATE_SCHEMA
            or state.get("unit_id") != unit_id
            or state.get("source_lane") != unit.source_lane
            or state.get("corpus") != unit.corpus
            or state.get("selected_records") != selected
            or state.get("target_answer_retries") != 1
            or state.get("target_call_cap") != selected * 2
            or state.get("result_root") != str(result_root)
            or not isinstance(argv, list)
            or any(not isinstance(item, str) for item in argv)
            or _option(argv, "--target-answer-retries") != "1"
            or _option(argv, "--corpora") != unit.corpus
        ):
            raise ValueError(f"{unit_id}: measured state changed")
        revision = _option(argv, "--project-revision-sha256")
        source = _option(argv, "--source-conformance-sha256")
        if HEX64.fullmatch(revision) is None or HEX64.fullmatch(source) is None:
            raise ValueError(f"{unit_id}: project/source stratum changed")
        grids = sorted(result_root.glob("*.grid.json"))
        envelopes = sorted(result_root.glob("*.request-envelope.json"))
        eligibility = sorted(result_root.glob("eligibility-*.eligibility.json"))
        markers = sorted(result_root.glob("*.complete.json"))
        if len(grids) != 1 or len(envelopes) != 1 or len(eligibility) != 1 or not markers:
            raise ValueError(f"{unit_id}: completed Runner artifact inventory changed")
        revisions.add(revision)
        sources.add(source)
        metric_roots[unit_id] = str(result_root)
        grid = _descriptor(grids[0], label=f"{unit_id} measured grid")
        plan = _descriptor(eligibility[0], label=f"{unit_id} eligibility plan")
        completion_markers = [
            _descriptor(marker, label=f"{unit_id} completion marker")
            for marker in markers
        ]
        metric_grids.append(grid)
        metric_eligibility_plans.append(plan)
        metric_completion_markers.extend(completion_markers)
        metric_evidence[unit_id] = {
            "grid": grid,
            "request_envelope": _descriptor(
                envelopes[0], label=f"{unit_id} request envelope"
            ),
            "eligibility_plan": plan,
            "completion_markers": completion_markers,
            "state": dict(result["state"]),
            "level1": dict(result["level1"]),
        }
        total_successful += successful
        total_missing += missing

    target_execution = completion.get("target_execution")
    if (
        not isinstance(target_execution, dict)
        or set(target_execution)
        != {"target_attempts", "successful_target_generations", "missing_responses"}
        or target_execution.get("target_attempts") != selected_total
        or target_execution.get("successful_target_generations") != total_successful
        or target_execution.get("missing_responses") != total_missing
        or len(revisions) != 1
        or len(sources) != 1
    ):
        raise ValueError("current Ollama stability aggregate accounting changed")
    return {
        "completion": _descriptor(
            completion_path, label="current Ollama stability completion"
        ),
        "runner_code_version": RUNNER_CODE_VERSION,
        "output_policy_stratum": "provider_neutral_retry_1_retain_failed_output",
        "unit_order": expected_order,
        "terminal_states": {unit_id: "measured_complete" for unit_id in expected_order},
        "metric_lane_order": expected_order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility_plans,
        "metric_completion_markers": metric_completion_markers,
        "revision_strata": {next(iter(revisions)): expected_order},
        "project_revision_receipt_sha256": next(iter(revisions)),
        "source_conformance_sha256": next(iter(sources)),
        "historical_durable_rows": durable,
        "target_execution": dict(target_execution),
        "cross_output_policy_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh current Ollama stability root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("current Ollama stability root must be one direct campaign")
    project_revision = args.project_revision.resolve(strict=True)
    _input_json(
        project_revision,
        args.project_revision_sha256,
        label="current project revision",
    )
    _input_json(
        args.gate5_amendment,
        args.gate5_amendment_sha256,
        label="current Ollama Gate 5 amendment",
    )
    _input_json(
        args.base_completion,
        args.base_completion_sha256,
        label="base current Ollama Phase 6 completion",
    )
    _input_json(
        args.failed_recovery_completion,
        args.failed_recovery_completion_sha256,
        label="failed current Ollama recovery completion",
    )
    validated = validate_failed_recovery(
        gate5_path=args.gate5_amendment,
        base_completion=args.base_completion,
        recovery_completion=args.failed_recovery_completion,
        runner_root=work_root / "runs/thesis/runner",
    )
    units, durable_by_lane = build_units(
        gate5=validated["gate5"], base=validated["base"]
    )

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    launch = {
        "schema": "ura-current-ollama-stability-phase6-launch/1",
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "gate5": _descriptor(args.gate5_amendment, label="current Ollama Gate 5"),
        "base_completion": _descriptor(
            args.base_completion, label="base current Ollama completion"
        ),
        "failed_recovery_completion": _descriptor(
            args.failed_recovery_completion, label="failed current Ollama recovery"
        ),
        "historical_durable_rows": durable_by_lane,
        "unit_order": [unit.unit_id for unit in units],
        "selected_missing_rows": sum(unit.selected_records for unit in units),
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_current_ollama_stability",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for unit in units:
        try:
            recovery_path = None
            recovery_sha = None
            if unit.recovery is not None:
                recovery_path = (
                    control_root / "inputs" / f"{unit.unit_id}.completed-prefix.json"
                )
                _create_json(recovery_path, unit.recovery)
                recovery_sha = hashlib.sha256(recovery_path.read_bytes()).hexdigest()
            results[unit.unit_id] = _run_unit(
                unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=project_revision,
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=recovery_path,
                recovery_sha256=recovery_sha,
                expected_commit=args.expected_commit,
                framework_lock_id=_framework_lock_id(),
                admission_sha256=args.gate5_amendment_sha256,
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
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
                "source_lane": unit.source_lane,
                "corpus": unit.corpus,
                "stage": "gate5_or_measured",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
                "target_answer_retries": 1,
            }
    attempted = sum(row["target_attempts"] for row in results.values())
    successful = sum(row["successful_target_generations"] for row in results.values())
    missing = sum(row["missing_responses"] for row in results.values())
    status = "complete" if not failures else "complete_with_failures"
    completion = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": RUNNER_CODE_VERSION,
        "target_answer_retries": 1,
        "launch": _descriptor(control_root / "launch.json", label="stability launch"),
        "unit_order": [unit.unit_id for unit in units],
        "unit_results": results,
        "unit_failures": failures,
        "historical_durable_rows": durable_by_lane,
        "selected_missing_rows": sum(unit.selected_records for unit in units),
        "target_execution": {
            "target_attempts": attempted,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_output_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "completion.json", completion)
    exit_code = int(completion["controller_exit_code"])
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{exit_code}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=attempted,
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
    parser.add_argument("--base-completion", type=Path, required=True)
    parser.add_argument("--base-completion-sha256", required=True)
    parser.add_argument("--failed-recovery-completion", type=Path, required=True)
    parser.add_argument("--failed-recovery-completion-sha256", required=True)
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
        print(f"current Ollama stability continuation failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
