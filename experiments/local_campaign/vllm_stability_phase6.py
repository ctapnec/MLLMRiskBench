"""Fresh Runner 2.25 vLLM completion after historical output failures.

The controller validates the retained Runner 2.24 terminal partition, excludes
its completed lanes, and creates fresh Runner 2.25 conditions only for three
pre-Runner failures plus the never-completed suffix of the partial LLaVA text
lane.  It never imports old checkpoints into the new output-policy stratum.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments.local_campaign.current_ollama_gate5 import (
    _canonical,
    _descriptor,
    _stable_file,
)
from experiments.local_campaign.current_ollama_phase6 import (
    _acquisition_args,
    _level1_counts,
    _run,
)
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.rig_web_app.external_measured import (
    register_external_measured_start,
    register_external_measured_terminal,
)


SCHEMA = "ura-vllm-stability-phase6/1"
PREFIX_SCHEMA = "ura-recovery-completed-prefix/1"
HISTORICAL_COMMIT = "73c5331c59d1192f3338170cfee374af5e03a07f"
COMPLETED_LANES = frozenset({
    "crescendo-qwen3-vl",
    "local-qwen3-vl-text-primary-100",
})
PRE_RUNNER_LANES = frozenset({
    "gptgeochat-qwen3-vl",
    "local-llava-base-image-primary-100",
    "local-qwen3-vl-image-primary-100",
})
PARTIAL_LANE = "local-llava-base-text-primary-100"
EXPECTED_STATES = {
    **{lane: "measured_complete" for lane in COMPLETED_LANES},
    **{lane: "failed" for lane in PRE_RUNNER_LANES},
    PARTIAL_LANE: "failed",
}
TEXT_SUFFIX_CORPORA = (
    "airbench_full",
    "xstest_full",
    "simplesafetytests_full",
    "decodingtrust_stereotype",
)
UNIT_LAYOUT = (
    (
        "vllm-stability-qwen3-vl-image-primary-100",
        "local-qwen3-vl-image-primary-100",
        None,
        1632,
    ),
    (
        "vllm-stability-gptgeochat-qwen3-vl",
        "gptgeochat-qwen3-vl",
        None,
        2020,
    ),
    (
        "vllm-stability-llava-base-image-primary-100",
        "local-llava-base-image-primary-100",
        None,
        1632,
    ),
    (
        "vllm-stability-llava-base-airbench-suffix",
        PARTIAL_LANE,
        "airbench_full",
        815,
    ),
    (
        "vllm-stability-llava-base-xstest-full",
        PARTIAL_LANE,
        "xstest_full",
        100,
    ),
    (
        "vllm-stability-llava-base-simplesafetytests-full",
        PARTIAL_LANE,
        "simplesafetytests_full",
        100,
    ),
    (
        "vllm-stability-llava-base-decodingtrust-stereotype",
        PARTIAL_LANE,
        "decodingtrust_stereotype",
        900,
    ),
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
ATTESTATION_PROBE_SEEDS = (0, 1, 2, 3, 4)


@dataclass(frozen=True)
class Unit:
    unit_id: str
    source_lane: str
    corpus: str | None
    spec: Mapping[str, Any]
    selected_records: int
    recovery: Mapping[str, Any] | None = None


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _framework_lock_id() -> str:
    value = os.environ.get("URA_FRAMEWORK_LOCK_ID", "")
    if HEX64.fullmatch(value) is None:
        raise ValueError("URA_FRAMEWORK_LOCK_ID must be one lowercase 64-hex digest")
    return value


def _external_job_id(control_root: Path, unit_id: str) -> str:
    token = hashlib.sha256(
        f"{control_root.name}\0{unit_id}".encode("utf-8")
    ).hexdigest()[:16]
    return f"external-{control_root.name[:40]}-{unit_id[:48]}-{token}"


def _project_python(project_root: Path, candidate: Path) -> Path:
    expected = project_root / ".venv/bin/python"
    if candidate != expected:
        raise ValueError("controller Python is not the project virtual environment")
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ValueError("controller Python is not one executable regular file")
    return candidate


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_stable_file(path, label=label).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not one JSON object")
    return value


def _sha256_json(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _create_json(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"create-only artifact already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        payload = _canonical(value)
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_descriptor(value: object, *, label: str) -> Path:
    fields = set(value) if isinstance(value, dict) else set()
    if fields not in (
        {"path", "sha256", "bytes"},
        {"path", "file", "sha256", "bytes"},
    ):
        raise ValueError(f"{label} is not one exact file descriptor")
    raw_path = value.get("path")
    digest = value.get("sha256")
    size = value.get("bytes")
    if (
        not isinstance(raw_path, str)
        or not raw_path.startswith("/")
        or not isinstance(digest, str)
        or HEX64.fullmatch(digest) is None
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size < 1
    ):
        raise ValueError(f"{label} descriptor fields are invalid")
    path = Path(raw_path)
    from ura.validation_cache import observe_validation_path
    observe_validation_path(path)
    if "file" in value and value.get("file") != path.name:
        raise ValueError(f"{label} descriptor filename does not match its path")
    from ura.artifact_checks import artifact_sha256_enabled
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical regular file")
    if path.stat().st_size != size or size > 64 * 1024 * 1024:
        raise ValueError(f"{label} content identity changed")
    if artifact_sha256_enabled():
        payload = _stable_file(path, label=label)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"{label} content identity changed")
    return path


def validate_historical_completion(value: Mapping[str, Any]) -> None:
    """Require the exact old terminal partition before selecting new work."""

    if (
        value.get("schema") != "ura-phase6-failed-lane-recovery-completion/1"
        or value.get("status") != "complete_with_failures"
        or value.get("expected_commit") != HISTORICAL_COMMIT
        or value.get("lane_terminal_states") != EXPECTED_STATES
        or set(value.get("lane_results", {})) != COMPLETED_LANES
        or set(value.get("lane_failures", {}))
        != PRE_RUNNER_LANES | {PARTIAL_LANE}
        or value.get("unrelated_passed_work_repeated") is not False
        or value.get("paid_provider_calls") != 0
    ):
        raise ValueError("historical vLLM terminal partition changed")


def _replace_option(argv: Sequence[str], flag: str, value: str) -> list[str]:
    result = list(argv)
    count = result.count(flag)
    if count == 0:
        result.extend((flag, value))
        return result
    if count != 1:
        raise ValueError(f"base argv has multiple {flag} options")
    index = result.index(flag)
    if index + 1 >= len(result):
        raise ValueError(f"base argv ends after {flag}")
    result[index + 1] = value
    return result


def _option(argv: Sequence[str], flag: str) -> str:
    if argv.count(flag) != 1:
        raise ValueError(f"base argv does not contain one {flag}")
    index = argv.index(flag)
    if index + 1 >= len(argv):
        raise ValueError(f"base argv ends after {flag}")
    return argv[index + 1]


def _projection_arms(spec: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    gate5 = spec.get("gate5")
    descriptor = gate5.get("final_projection") if isinstance(gate5, dict) else None
    path = _validate_descriptor(
        descriptor, label=f"{spec.get('lane_id')} historical projection"
    )
    projection = _load_json(path, label=f"{spec.get('lane_id')} projection")
    selection = projection.get("selection")
    arms = selection.get("arms") if isinstance(selection, dict) else None
    if not isinstance(arms, list) or not arms:
        raise ValueError("historical projection lacks selected source arms")
    result: dict[str, Mapping[str, Any]] = {}
    for row in arms:
        if not isinstance(row, dict):
            raise ValueError("historical projection arm is malformed")
        name = row.get("logical_source_arm")
        count = row.get("selected_records")
        if (
            not isinstance(name, str)
            or name in result
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
        ):
            raise ValueError("historical projection arm identity changed")
        result[name] = row
    return result


def _gate5_manifest_sha256(spec: Mapping[str, Any]) -> str:
    """Return the formal Gate 5 manifest digest bound by one lane spec."""

    gate5 = spec.get("gate5")
    digest = gate5.get("manifest_sha256") if isinstance(gate5, dict) else None
    if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
        raise ValueError(f"{spec.get('lane_id')} Gate 5 manifest digest changed")
    return digest


def _historical_specs(completion: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    specs: dict[str, dict[str, Any]] = {}
    failures = completion["lane_failures"]
    for lane in sorted(PRE_RUNNER_LANES | {PARTIAL_LANE}):
        failure_path = _validate_descriptor(
            failures[lane], label=f"{lane} historical failure"
        )
        failure = _load_json(failure_path, label=f"{lane} historical failure")
        if failure.get("lane_id") != lane or failure.get("status") != "failed":
            raise ValueError(f"{lane} historical failure identity changed")
        pre_runner = failure.get("pre_runner_failure")
        if (lane in PRE_RUNNER_LANES) != isinstance(pre_runner, dict):
            raise ValueError(f"{lane} pre-Runner classification changed")
        spec_path = _validate_descriptor(
            failure.get("lane_spec"), label=f"{lane} historical lane spec"
        )
        spec = _load_json(spec_path, label=f"{lane} historical lane spec")
        if spec.get("lane_id") != lane:
            raise ValueError(f"{lane} historical lane spec identity changed")
        specs[lane] = spec
    return specs


def _airbench_recovery(
    completion: Mapping[str, Any],
    spec: Mapping[str, Any],
) -> tuple[dict[str, Any], Path]:
    failure_path = _validate_descriptor(
        completion["lane_failures"][PARTIAL_LANE],
        label="partial LLaVA historical failure",
    )
    failure = _load_json(failure_path, label="partial LLaVA historical failure")
    state_path = _validate_descriptor(
        failure.get("exact_measured_argv"), label="partial LLaVA exact argv"
    )
    state = _load_json(state_path, label="partial LLaVA exact argv")
    result_root_raw = state.get("result_root")
    if not isinstance(result_root_raw, str) or not result_root_raw.startswith("/"):
        raise ValueError("partial LLaVA result root changed")
    result_root = Path(result_root_raw)
    if result_root.is_symlink() or result_root.resolve(strict=True) != result_root:
        raise ValueError("partial LLaVA result root is not canonical")
    manifests = sorted(result_root.glob("airbench_full--*.manifest.json"))
    attempts = sorted(result_root.glob("airbench_full--*.attempts.jsonl"))
    if len(manifests) != 1 or len(attempts) != 1:
        raise ValueError("partial LLaVA AirBench artifact inventory changed")
    manifest = _load_json(manifests[0], label="partial LLaVA AirBench manifest")
    config = manifest.get("config")
    run_config = config.get("run") if isinstance(config, dict) else None
    audit = run_config.get("sampling_audit") if isinstance(run_config, dict) else None
    selected_ids = audit.get("selected_ids") if isinstance(audit, dict) else None
    if (
        not isinstance(selected_ids, list)
        or not selected_ids
        or any(not isinstance(item, str) or not item for item in selected_ids)
        or len(set(selected_ids)) != len(selected_ids)
    ):
        raise ValueError("partial LLaVA AirBench selected identities changed")
    completed_ids: list[str] = []
    for raw in _stable_file(attempts[0], label="partial LLaVA AirBench attempts").splitlines():
        if not raw:
            continue
        row = json.loads(raw.decode("utf-8"))
        datapoint_id = row.get("datapoint_id") if isinstance(row, dict) else None
        if not isinstance(datapoint_id, str) or not datapoint_id:
            raise ValueError("partial LLaVA attempt lacks datapoint identity")
        completed_ids.append(datapoint_id)
    if (
        len(completed_ids) != 1039
        or len(set(completed_ids)) != len(completed_ids)
        or completed_ids != selected_ids[: len(completed_ids)]
        or len(selected_ids) != _projection_arms(spec)["airbench_full"][
            "selected_records"
        ]
    ):
        raise ValueError("partial LLaVA durable rows are not the exact selected prefix")
    remaining_ids = selected_ids[len(completed_ids) :]
    recovery = {
        "schema": PREFIX_SCHEMA,
        "corpus": "airbench_full",
        "completed_prefix_count": len(completed_ids),
        "selected_datapoint_ids_sha256": _sha256_json(selected_ids),
        "completed_prefix_ids_sha256": _sha256_json(completed_ids),
        "remaining_datapoint_ids_sha256": _sha256_json(remaining_ids),
    }
    return recovery, result_root


def validate_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the exact all-complete Runner 2.25 continuation for Phase 7."""

    completion_path = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    completion = _load_json(completion_path, label="vLLM stability completion")
    fields = {
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
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != "ura-runner/2.25"
        or completion.get("target_answer_retries") != 1
        or completion.get("historical_completed_lanes_excluded")
        != sorted(COMPLETED_LANES)
        or completion.get("unit_order") != expected_order
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
        raise ValueError("vLLM stability completion contract changed")
    _validate_descriptor(
        completion.get("historical_completion"),
        label="vLLM stability historical completion",
    )
    results = completion.get("unit_results")
    if not isinstance(results, dict) or list(results) != expected_order:
        raise ValueError("vLLM stability result inventory changed")

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
    control_root = completion_path.parent
    revisions: set[str] = set()
    sources: set[str] = set()
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility_plans: list[dict[str, object]] = []
    metric_completion_markers: list[dict[str, object]] = []
    total_successful = 0
    total_missing = 0
    for unit_id, source_lane, corpus, selected_records in UNIT_LAYOUT:
        result = results.get(unit_id)
        if not isinstance(result, dict) or set(result) != result_fields:
            raise ValueError(f"{unit_id} result contract changed")
        successful = result.get("successful_target_generations")
        missing = result.get("missing_responses")
        if (
            result.get("status") != "complete"
            or result.get("unit_id") != unit_id
            or result.get("source_lane") != source_lane
            or result.get("corpus") != corpus
            or result.get("selected_records") != selected_records
            or result.get("target_answer_retries") != 1
            or result.get("target_call_cap") != selected_records * 2
            or result.get("target_attempts") != selected_records
            or isinstance(successful, bool)
            or not isinstance(successful, int)
            or successful < 0
            or isinstance(missing, bool)
            or not isinstance(missing, int)
            or missing < 0
            or successful + missing != selected_records
        ):
            raise ValueError(f"{unit_id} result accounting changed")
        result_root = Path(str(result.get("result_root", "")))
        expected_root = runner_root / unit_id / control_root.name
        if (
            not result_root.is_absolute()
            or result_root.is_symlink()
            or result_root.resolve(strict=True) != expected_root
        ):
            raise ValueError(f"{unit_id} result root changed")
        state_path = _validate_descriptor(result.get("state"), label=f"{unit_id} state")
        level1_path = _validate_descriptor(
            result.get("level1"), label=f"{unit_id} Level 1 evidence"
        )
        expected_unit_root = control_root / "units" / unit_id
        if (
            state_path != expected_unit_root / "state.json"
            or level1_path != expected_unit_root / "level1.json"
        ):
            raise ValueError(f"{unit_id} controller artifact placement changed")
        grids = sorted(result_root.glob("*.grid.json"))
        envelopes = sorted(result_root.glob("*.request-envelope.json"))
        eligibility = sorted(result_root.glob("eligibility-*.eligibility.json"))
        markers = sorted(result_root.glob("*.complete.json"))
        if (
            len(grids) != 1
            or len(envelopes) != 1
            or len(eligibility) != 1
            or not markers
        ):
            raise ValueError(f"{unit_id} completed Runner artifact inventory changed")
        state = _load_json(state_path, label=f"{unit_id} state")
        argv = state.get("runner_argv")
        if (
            set(state) != state_fields
            or state.get("schema") != "ura-vllm-stability-phase6-unit-state/1"
            or state.get("unit_id") != unit_id
            or state.get("source_lane") != source_lane
            or state.get("corpus") != corpus
            or state.get("selected_records") != selected_records
            or state.get("target_answer_retries") != 1
            or state.get("target_call_cap") != selected_records * 2
            or state.get("result_root") != str(result_root)
            or not isinstance(argv, list)
            or any(not isinstance(item, str) for item in argv)
            or _option(argv, "--target-answer-retries") != "1"
        ):
            raise ValueError(f"{unit_id} measured state changed")
        revision = _option(argv, "--project-revision-sha256")
        source = _option(argv, "--source-conformance-sha256")
        if HEX64.fullmatch(revision) is None or HEX64.fullmatch(source) is None:
            raise ValueError(f"{unit_id} project/source stratum changed")
        revisions.add(revision)
        sources.add(source)
        metric_roots[unit_id] = str(result_root)
        metric_grids.append(_descriptor(grids[0], label=f"{unit_id} measured grid"))
        metric_eligibility_plans.append(
            _descriptor(eligibility[0], label=f"{unit_id} eligibility plan")
        )
        metric_completion_markers.extend(
            _descriptor(marker, label=f"{unit_id} completion marker")
            for marker in markers
        )
        metric_evidence[unit_id] = {
            "grid": metric_grids[-1],
            "request_envelope": _descriptor(
                envelopes[0], label=f"{unit_id} request envelope"
            ),
            "eligibility_plan": metric_eligibility_plans[-1],
            "completion_markers": metric_completion_markers[-len(markers):],
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
        or target_execution.get("target_attempts") != sum(row[3] for row in UNIT_LAYOUT)
        or target_execution.get("successful_target_generations") != total_successful
        or target_execution.get("missing_responses") != total_missing
        or len(revisions) != 1
        or len(sources) != 1
    ):
        raise ValueError("vLLM stability aggregate accounting or stratum changed")
    return {
        "completion": _descriptor(completion_path, label="vLLM stability completion"),
        "runner_code_version": "ura-runner/2.25",
        "output_policy_stratum": "provider_neutral_retry_1_retain_failed_output",
        "unit_order": expected_order,
        "terminal_states": {lane: "measured_complete" for lane in expected_order},
        "metric_lane_order": expected_order,
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility_plans,
        "metric_completion_markers": metric_completion_markers,
        "revision_strata": {next(iter(revisions)): expected_order},
        "project_revision_receipt_sha256": next(iter(revisions)),
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": dict(target_execution),
        "cross_output_policy_pooling_permitted": False,
    }


def build_units(
    completion: Mapping[str, Any],
    specs: Mapping[str, Mapping[str, Any]],
) -> tuple[list[Unit], Path]:
    """Build the exact new-condition inventory without touching completed rows."""

    units: list[Unit] = []
    for lane, unit_id in (
        (
            "local-qwen3-vl-image-primary-100",
            "vllm-stability-qwen3-vl-image-primary-100",
        ),
        ("gptgeochat-qwen3-vl", "vllm-stability-gptgeochat-qwen3-vl"),
        (
            "local-llava-base-image-primary-100",
            "vllm-stability-llava-base-image-primary-100",
        ),
    ):
        spec = specs[lane]
        arms = _projection_arms(spec)
        expected = spec.get("expected_corpora")
        if not isinstance(expected, list) or set(expected) != set(arms):
            raise ValueError(f"{lane} historical corpus inventory changed")
        selected_records = sum(int(arms[name]["selected_records"]) for name in expected)
        if spec.get("approved_caps", {}).get("target_calls") != selected_records:
            raise ValueError(f"{lane} historical target-call cap changed")
        units.append(Unit(unit_id, lane, None, spec, selected_records))

    text_spec = specs[PARTIAL_LANE]
    text_arms = _projection_arms(text_spec)
    recovery, old_text_root = _airbench_recovery(completion, text_spec)
    remaining = int(text_arms["airbench_full"]["selected_records"]) - int(
        recovery["completed_prefix_count"]
    )
    units.append(
        Unit(
            "vllm-stability-llava-base-airbench-suffix",
            PARTIAL_LANE,
            "airbench_full",
            text_spec,
            remaining,
            recovery,
        )
    )
    for corpus in TEXT_SUFFIX_CORPORA[1:]:
        units.append(
            Unit(
                f"vllm-stability-llava-base-{corpus.replace('_', '-')}",
                PARTIAL_LANE,
                corpus,
                text_spec,
                int(text_arms[corpus]["selected_records"]),
            )
        )
    if len(units) != 7 or any(unit.selected_records < 1 for unit in units):
        raise ValueError("vLLM continuation unit inventory changed")
    return units, old_text_root


def _base_argv(
    unit: Unit,
    *,
    project_revision: Path,
    project_revision_sha256: str,
) -> list[str]:
    raw = unit.spec.get("base_argv")
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ValueError(f"{unit.source_lane} base argv changed")
    argv = _replace_option(raw, "--project-revision", str(project_revision))
    argv = _replace_option(
        argv, "--project-revision-sha256", project_revision_sha256
    )
    argv = _replace_option(argv, "--target-answer-retries", "1")
    if unit.corpus is not None:
        argv = _replace_option(argv, "--corpora", unit.corpus)
    return argv


def _validate_execution_bounds(deadline_seconds: int, live_attestation_max_age_hours: float) -> None:
    if isinstance(deadline_seconds, bool) or not isinstance(deadline_seconds, int) or deadline_seconds <= 0:
        raise ValueError("measured wall time must be a positive integer number of seconds")
    if (isinstance(live_attestation_max_age_hours, bool)
            or not isinstance(live_attestation_max_age_hours, (int, float))
            or not 0 < live_attestation_max_age_hours <= 24 * 365
            or not math.isfinite(live_attestation_max_age_hours)):
        raise ValueError("live-attestation max age must be finite and in (0, 8760] hours")


def _runtime_args(
    base: Sequence[str],
    *,
    out: Path,
    scope: str,
    attestation: Mapping[str, Any],
    target_cap: int,
    preflight: bool = False,
    canary: bool = False,
    deadline_seconds: int = 86400,
    live_attestation_max_age_hours: float = 24,
) -> list[str]:
    _validate_execution_bounds(deadline_seconds, live_attestation_max_age_hours)
    argv = list(base)
    if canary:
        corpus = _option(argv, "--corpora").split(",", 1)[0]
        argv = _replace_option(argv, "--corpora", corpus)
        argv = _replace_option(argv, "--limit", "1")
        argv.append("--diagnostic-canary")
    if not preflight:
        argv.extend((
            "--execution-scope-id",
            scope,
            "--live-attestation",
            str(attestation["path"]),
            "--live-attestation-sha256",
            str(attestation["sha256"]),
            "--live-attestation-max-age-hours",
            str(live_attestation_max_age_hours),
        ))
    argv.extend((
        "--max-total-target-calls",
        str(target_cap),
        "--max-total-judge-calls",
        "0",
        "--max-total-http-attempts",
        "0",
        "--deadline-seconds",
        str(deadline_seconds),
        "--out",
        str(out),
    ))
    if preflight:
        argv.append("--preflight-only")
    return argv


def _without_recovery_selection(argv: Sequence[str]) -> list[str]:
    result: list[str] = []
    skip_value = False
    flags = {
        "--recovery-completed-prefix",
        "--recovery-completed-prefix-sha256",
    }
    for item in argv:
        if skip_value:
            skip_value = False
            continue
        if item in flags:
            skip_value = True
            continue
        result.append(item)
    if skip_value:
        raise ValueError("recovery selection flag lacks its value")
    return result


def _diagnostic_canary_target_cap(unit: Unit, measured_cap: int) -> int:
    """Cover one whole source cluster even when only a tiny suffix remains."""

    recovery = unit.recovery
    corpora = recovery.get("corpora") if isinstance(recovery, Mapping) else None
    if not isinstance(corpora, Mapping):
        return measured_cap
    completed = 0
    for value in corpora.values():
        if not isinstance(value, Mapping):
            raise ValueError("recovery corpus selection changed")
        count = value.get("completed_record_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("recovery corpus completed-record count changed")
        completed += count
    # The diagnostic removes the completed-row selector before applying
    # --limit 1. Its breaker must therefore cover a cluster drawn from the
    # full retained selection, while the measured breaker stays suffix-only.
    return max(measured_cap, (completed + unit.selected_records) * 2)


def _probe_args(
    unit: Unit,
    *,
    base: Sequence[str],
    out: Path,
    scope: str,
    sample_seed: int = 0,
) -> list[str]:
    base = list(base)
    modality = unit.spec.get("modality")
    if modality not in {"text", "image"}:
        raise ValueError(f"{unit.unit_id} modality changed")
    corpus = "synth" if modality == "text" else "figstep_full"
    argv = [
        "--attestation-probe",
        "--execution-scope-id",
        scope,
        "--project-revision",
        _option(base, "--project-revision"),
        "--project-revision-sha256",
        _option(base, "--project-revision-sha256"),
        "--local",
        _option(base, "--local"),
        "--local-config",
        _option(base, "--local-config"),
        "--local-config-sha256",
        _option(base, "--local-config-sha256"),
        "--attackers",
        "replay",
        "--judges",
        "rules,guardrail",
        "--guardrail-model",
        "meta-llama/Llama-Guard-3-8B",
        "--guardrail-revision",
        "7327bd9f6efbbe6101dc6cc4736302b3cbb6e425",
        "--guardrail-device",
        _option(base, "--guardrail-device") if "--guardrail-device" in base else "cuda:1",
        "--corpora",
        corpus,
    ]
    if modality == "image":
        for flag in (
            "--source-config",
            "--source-config-sha256",
            "--source-conformance",
            "--source-conformance-sha256",
        ):
            argv.extend((flag, _option(base, flag)))
    argv.extend((
        "--limit",
        "1",
        "--sample-seed",
        str(sample_seed),
        "--seeds",
        "0",
        "--max-queries",
        "1",
        "--max-turns",
        "1",
        "--target-answer-retries",
        "1",
        "--group",
        _option(base, "--group"),
        "--max-total-target-calls",
        "2",
        "--max-total-judge-calls",
        "0",
        "--max-total-http-attempts",
        "0",
        "--deadline-seconds",
        "3600",
        "--out",
        str(out),
    ))
    return argv


def _derive_attestation(
    unit: Unit,
    *,
    base: Sequence[str],
    python: Path,
    unit_root: Path,
    work_root: Path,
    scope: str,
) -> dict[str, Any]:
    root = work_root / "runs/thesis/attestation" / unit_root.parent.parent.name / unit.unit_id
    root.mkdir(parents=True, mode=0o700)
    failed_seeds: list[int] = []
    for sample_seed in ATTESTATION_PROBE_SEEDS:
        suffix = f"seed-{sample_seed}"
        probe_root = root / f"probe-{suffix}"
        probe_args = _probe_args(
            unit,
            base=base,
            out=probe_root,
            scope=scope,
            sample_seed=sample_seed,
        )
        acquisition_root = unit_root / f"probe-acquisition-{suffix}"
        acquisition_root.mkdir(mode=0o700)
        acquisition = _acquisition_args(
            probe_args,
            python=python,
            lane_root=acquisition_root,
            timeout=3600,
        )
        _run(
            (
                str(python),
                "-m",
                "experiments.run_matrix",
                *probe_args,
                *acquisition,
            ),
            log=unit_root / f"probe.{suffix}.run.log",
            timeout=3600,
        )
        receipt = root / f"{unit.unit_id}.{suffix}.live-attestation.json"
        derived = _run(
            (
                str(python),
                "-m",
                "experiments.live_attestation",
                "--probe-root",
                str(probe_root),
                "--execution-scope-id",
                scope,
                "--out",
                str(receipt),
            ),
            log=unit_root / f"probe.{suffix}.derive.log",
            timeout=600,
            allow_failure=True,
        )
        if derived != 0:
            failed_seeds.append(sample_seed)
            continue
        digest = hashlib.sha256(
            _stable_file(receipt, label="live attestation")
        ).hexdigest()
        _run(
            (
                str(python),
                "-m",
                "experiments.live_attestation",
                "--validate",
                str(receipt),
                "--sha256",
                digest,
            ),
            log=unit_root / f"probe.{suffix}.validate.log",
            timeout=600,
        )
        return {
            "path": str(receipt),
            "sha256": digest,
            "bytes": receipt.stat().st_size,
        }
    raise RuntimeError(
        "live attestation found no realized target identity across probe seeds "
        + ",".join(str(seed) for seed in failed_seeds)
    )


def _one_file(root: Path, pattern: str, *, label: str) -> Path:
    paths = sorted(root.glob(pattern))
    if len(paths) != 1 or paths[0].is_symlink() or not paths[0].is_file():
        raise ValueError(f"{label} requires one {pattern}")
    return paths[0]


def _run_unit(
    unit: Unit,
    *,
    python: Path,
    work_root: Path,
    control_root: Path,
    project_revision: Path,
    project_revision_sha256: str,
    scope: str,
    recovery_path: Path | None,
    recovery_sha256: str | None,
    expected_commit: str,
    framework_lock_id: str,
    admission_sha256: str,
    tmux_socket: str,
    tmux_session: str,
    state_schema: str = "ura-vllm-stability-phase6-unit-state/1",
    validated_canary_root: Path | None = None,
    hub_acquisition_required: bool = True,
    diagnostic_canary_target_cap: int | None = None,
    measured_wall_time_seconds: int = 86400,
    live_attestation_max_age_hours: float = 24,
    scoring_device: str | None = None,
) -> dict[str, Any]:
    _validate_execution_bounds(measured_wall_time_seconds, live_attestation_max_age_hours)
    if scoring_device is not None and (
        not isinstance(scoring_device, str)
        or re.fullmatch(r"cpu|cuda(?::[0-9]+)?|mps", scoring_device) is None
    ):
        raise ValueError("scoring device must be an explicit cpu, cuda[:index], or mps device")
    if diagnostic_canary_target_cap is not None and (
        isinstance(diagnostic_canary_target_cap, bool)
        or not isinstance(diagnostic_canary_target_cap, int)
        or diagnostic_canary_target_cap <= 0
    ):
        raise ValueError("diagnostic canary target cap must be a positive integer")
    unit_root = control_root / "units" / unit.unit_id
    unit_root.mkdir(parents=True, mode=0o700)
    base = _base_argv(
        unit,
        project_revision=project_revision,
        project_revision_sha256=project_revision_sha256,
    )
    if scoring_device is not None:
        base = _replace_option(base, "--guardrail-device", scoring_device)
    if unit.recovery is not None:
        if recovery_path is None or recovery_sha256 is None:
            raise ValueError("completed-prefix recovery artifact is missing")
        base.extend((
            "--recovery-completed-prefix",
            str(recovery_path),
            "--recovery-completed-prefix-sha256",
            recovery_sha256,
        ))
    target_cap = unit.selected_records * 2
    attestation = _derive_attestation(
        unit,
        base=base,
        python=python,
        unit_root=unit_root,
        work_root=work_root,
        scope=scope,
    )

    if validated_canary_root is None:
        canary_base = _without_recovery_selection(base)
        canary_root = unit_root / "canary"
        canary_args = _runtime_args(
            canary_base,
            out=canary_root,
            scope=scope,
            attestation=attestation,
            target_cap=(
                diagnostic_canary_target_cap
                if diagnostic_canary_target_cap is not None
                else _diagnostic_canary_target_cap(unit, target_cap)
            ),
            canary=True,
        )
        canary_acquisition_root = unit_root / "canary-acquisition"
        canary_acquisition_root.mkdir(mode=0o700)
        canary_acquisition = (
            _acquisition_args(
                canary_args,
                python=python,
                lane_root=canary_acquisition_root,
                timeout=86400,
            )
            if hub_acquisition_required
            else []
        )
        _run(
            (
                str(python),
                "-m",
                "experiments.run_matrix",
                *canary_args,
                *canary_acquisition,
            ),
            log=unit_root / "canary.run.log",
            timeout=86400,
        )
        canary_summary_root = canary_root
    else:
        canary_root = validated_canary_root.resolve(strict=True)
        if canary_root.is_symlink() or canary_root.parent.parent.name != "units":
            raise ValueError("reused diagnostic canary root changed")
        canary_summary_root = unit_root / "reused-canary-summary"
        canary_summary_root.mkdir(mode=0o700)
    eligibility = _one_file(
        canary_root, "eligibility-*.eligibility.json", label="diagnostic canary"
    )
    _run(
        (
            str(python),
            "-m",
            "experiments.lane_canary",
            "--results",
            str(canary_root),
            "--eligibility",
            str(eligibility),
            "--out-dir",
            str(canary_summary_root),
        ),
        log=unit_root / "canary.validate.log",
        timeout=3600,
    )

    preflight_root = unit_root / "preflight"
    preflight_args = _runtime_args(
        base,
        out=preflight_root,
        scope=scope,
        attestation=attestation,
        target_cap=target_cap,
        preflight=True,
        deadline_seconds=measured_wall_time_seconds,
        live_attestation_max_age_hours=live_attestation_max_age_hours,
    )
    preflight_acquisition_root = unit_root / "preflight-acquisition"
    preflight_acquisition_root.mkdir(mode=0o700)
    preflight_acquisition = (
        _acquisition_args(
            preflight_args,
            python=python,
            lane_root=preflight_acquisition_root,
            timeout=86400,
        )
        if hub_acquisition_required
        else []
    )
    _run(
        (
            str(python),
            "-m",
            "experiments.run_matrix",
            *preflight_args,
            *preflight_acquisition,
        ),
        log=unit_root / "preflight.run.log",
        timeout=86400,
    )
    projection = _one_file(
        preflight_root,
        "lane-projection-*.lane-projection.json",
        label="no-call projection",
    )

    result_root = (
        work_root / "runs/thesis/runner" / unit.unit_id / control_root.name
    )
    result_root.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if result_root.exists() or result_root.is_symlink():
        raise FileExistsError("measured result root is not fresh")
    measured_args = _runtime_args(
        base,
        out=result_root,
        scope=scope,
        attestation=attestation,
        target_cap=target_cap,
        deadline_seconds=measured_wall_time_seconds,
        live_attestation_max_age_hours=live_attestation_max_age_hours,
    )
    measured_acquisition_root = unit_root / "measured-acquisition"
    measured_acquisition_root.mkdir(mode=0o700)
    measured_acquisition = (
        _acquisition_args(
            measured_args,
            python=python,
            lane_root=measured_acquisition_root,
            timeout=86400,
        )
        if hub_acquisition_required
        else []
    )
    if result_root.is_symlink() or (
        result_root.exists() and not result_root.is_dir()
    ):
        raise FileExistsError("measured acquisition created an invalid result root")
    if not result_root.exists():
        result_root.mkdir(mode=0o700)
    state = {
        "schema": state_schema,
        "unit_id": unit.unit_id,
        "source_lane": unit.source_lane,
        "corpus": unit.corpus,
        "selected_records": unit.selected_records,
        "target_answer_retries": 1,
        "target_call_cap": target_cap,
        "attestation": attestation,
        "projection": _descriptor(projection, label="no-call projection"),
        "result_root": str(result_root),
        "runner_argv": [*measured_args, *measured_acquisition],
    }
    _create_json(unit_root / "state.json", state)
    job_id = _external_job_id(control_root, unit.unit_id)
    register_external_measured_start(
        work_root / "runs",
        job_id=job_id,
        command="run_matrix",
        run_kind_name="measured",
        sanitized_argv=state["runner_argv"],
        out_dir=result_root,
        expected_commit=expected_commit,
        framework_lock_id=framework_lock_id,
        admission_sha256=admission_sha256,
        tmux_socket=tmux_socket,
        tmux_session=tmux_session,
    )
    try:
        rc = _run(
            (
                str(python),
                "-m",
                "experiments.run_matrix",
                *state["runner_argv"],
            ),
            log=unit_root / "measured.run.log",
            timeout=measured_wall_time_seconds,
            allow_failure=True,
        )
    except BaseException as exc:
        try:
            register_external_measured_terminal(
                work_root / "runs", job_id=job_id, exit_code=125
            )
        except BaseException as terminal_exc:
            raise terminal_exc from exc
        raise
    terminal_rc = rc if isinstance(rc, int) and 0 <= rc <= 255 else 125
    register_external_measured_terminal(
        work_root / "runs", job_id=job_id, exit_code=terminal_rc
    )
    if rc:
        raise RuntimeError(f"Runner exited {rc}; see {unit_root / 'measured.run.log'}")
    attempted, successful, missing = _level1_counts(
        python=python,
        lane_root=unit_root,
        state=state,
        timeout=3600,
    )
    if attempted != unit.selected_records:
        raise ValueError(
            f"{unit.unit_id} completed {attempted}, expected {unit.selected_records} rows"
        )
    return {
        "status": "complete",
        "unit_id": unit.unit_id,
        "source_lane": unit.source_lane,
        "corpus": unit.corpus,
        "selected_records": unit.selected_records,
        "target_answer_retries": 1,
        "target_call_cap": target_cap,
        "target_attempts": attempted,
        "successful_target_generations": successful,
        "missing_responses": missing,
        "result_root": str(result_root),
        "state": _descriptor(unit_root / "state.json", label="unit state"),
        "level1": _descriptor(unit_root / "level1.json", label="Level 1 evidence"),
    }


def run(args: argparse.Namespace) -> int:
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh vLLM stability control root already exists")
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
    payload = _stable_file(
        args.historical_completion, label="historical vLLM completion"
    )
    if hashlib.sha256(payload).hexdigest() != args.historical_completion_sha256:
        raise ValueError("historical vLLM completion digest changed")
    completion = json.loads(payload.decode("utf-8"))
    if not isinstance(completion, dict):
        raise ValueError("historical vLLM completion is not one object")
    validate_historical_completion(completion)
    specs = _historical_specs(completion)
    units, old_text_root = build_units(completion, specs)

    control_root.mkdir(mode=0o700)
    (control_root / "units").mkdir(mode=0o700)
    (control_root / "inputs").mkdir(mode=0o700)
    prefix = next(unit.recovery for unit in units if unit.recovery is not None)
    prefix_path = control_root / "inputs/llava-airbench-completed-prefix.json"
    _create_json(prefix_path, prefix)
    prefix_sha = hashlib.sha256(prefix_path.read_bytes()).hexdigest()
    launch = {
        "schema": "ura-vllm-stability-phase6-launch/1",
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "historical_completion": _descriptor(
            args.historical_completion, label="historical vLLM completion"
        ),
        "historical_completed_lanes_excluded": sorted(COMPLETED_LANES),
        "historical_partial_result_root": str(old_text_root),
        "recovery_selection": _descriptor(
            prefix_path, label="AirBench recovery prefix"
        ),
        "unit_order": [unit.unit_id for unit in units],
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    _create_json(control_root / "launch.json", launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_vllm_stability",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    framework_lock_id = _framework_lock_id()
    for unit in units:
        try:
            results[unit.unit_id] = _run_unit(
                unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=project_revision,
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=prefix_path if unit.recovery is not None else None,
                recovery_sha256=prefix_sha if unit.recovery is not None else None,
                expected_commit=args.expected_commit,
                framework_lock_id=framework_lock_id,
                admission_sha256=_gate5_manifest_sha256(unit.spec),
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
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
                "unit_id": unit.unit_id,
                "source_lane": unit.source_lane,
                "corpus": unit.corpus,
                "stage": "gate5_or_measured",
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
                "target_answer_retries": 1,
            }
    attempted = sum(row["target_attempts"] for row in results.values())
    successful = sum(
        row["successful_target_generations"] for row in results.values()
    )
    missing = sum(row["missing_responses"] for row in results.values())
    status = "complete" if not failures else "complete_with_failures"
    completion_value = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": "ura-runner/2.25",
        "target_answer_retries": 1,
        "historical_completion": launch["historical_completion"],
        "historical_completed_lanes_excluded": sorted(COMPLETED_LANES),
        "unit_order": [unit.unit_id for unit in units],
        "unit_results": results,
        "unit_failures": failures,
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
    _create_json(control_root / "completion.json", completion_value)
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{completion_value['controller_exit_code']}\n".encode("ascii"))
    exit_code = int(completion_value["controller_exit_code"])
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--historical-completion", type=Path, required=True)
    parser.add_argument("--historical-completion-sha256", required=True)
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
    if HEX64.fullmatch(args.historical_completion_sha256) is None:
        raise ValueError("historical completion SHA-256 is invalid")
    if HEX64.fullmatch(args.project_revision_sha256) is None:
        raise ValueError("project revision SHA-256 is invalid")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
