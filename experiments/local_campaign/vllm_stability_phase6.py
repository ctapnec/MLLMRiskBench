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
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


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
    if "file" in value and value.get("file") != path.name:
        raise ValueError(f"{label} descriptor filename does not match its path")
    payload = _stable_file(path, label=label)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
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


def _runtime_args(
    base: Sequence[str],
    *,
    out: Path,
    scope: str,
    attestation: Mapping[str, Any],
    target_cap: int,
    preflight: bool = False,
    canary: bool = False,
) -> list[str]:
    argv = list(base)
    if canary:
        corpus = _option(argv, "--corpora").split(",", 1)[0]
        argv = _replace_option(argv, "--corpora", corpus)
        argv = _replace_option(argv, "--limit", "1")
        argv.append("--diagnostic-canary")
    argv.extend((
        "--execution-scope-id",
        scope,
        "--live-attestation",
        str(attestation["path"]),
        "--live-attestation-sha256",
        str(attestation["sha256"]),
        "--live-attestation-max-age-hours",
        "24",
        "--max-total-target-calls",
        str(target_cap),
        "--max-total-judge-calls",
        "0",
        "--max-total-http-attempts",
        "0",
        "--deadline-seconds",
        "86400",
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


def _probe_args(
    unit: Unit, *, base: Sequence[str], out: Path, scope: str
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
        "rules",
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
        "0",
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
    probe_root = root / "probe"
    probe_args = _probe_args(unit, base=base, out=probe_root, scope=scope)
    acquisition_root = unit_root / "probe-acquisition"
    acquisition_root.mkdir(mode=0o700)
    acquisition = _acquisition_args(
        probe_args,
        python=python,
        lane_root=acquisition_root,
        timeout=3600,
    )
    _run(
        (str(python), "-m", "experiments.run_matrix", *probe_args, *acquisition),
        log=unit_root / "probe.run.log",
        timeout=3600,
    )
    receipt = root / f"{unit.unit_id}.live-attestation.json"
    _run(
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
        log=unit_root / "probe.derive.log",
        timeout=600,
    )
    digest = hashlib.sha256(_stable_file(receipt, label="live attestation")).hexdigest()
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
        log=unit_root / "probe.validate.log",
        timeout=600,
    )
    return {"path": str(receipt), "sha256": digest, "bytes": receipt.stat().st_size}


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
) -> dict[str, Any]:
    unit_root = control_root / "units" / unit.unit_id
    unit_root.mkdir(parents=True, mode=0o700)
    base = _base_argv(
        unit,
        project_revision=project_revision,
        project_revision_sha256=project_revision_sha256,
    )
    if unit.recovery is not None:
        if recovery_path is None or recovery_sha256 is None:
            raise ValueError("AirBench recovery artifact is missing")
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

    canary_base = _without_recovery_selection(base)
    canary_root = unit_root / "canary"
    canary_args = _runtime_args(
        canary_base,
        out=canary_root,
        scope=scope,
        attestation=attestation,
        target_cap=target_cap,
        canary=True,
    )
    canary_acquisition_root = unit_root / "canary-acquisition"
    canary_acquisition_root.mkdir(mode=0o700)
    canary_acquisition = _acquisition_args(
        canary_args,
        python=python,
        lane_root=canary_acquisition_root,
        timeout=86400,
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
            str(canary_root),
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
    )
    preflight_acquisition_root = unit_root / "preflight-acquisition"
    preflight_acquisition_root.mkdir(mode=0o700)
    preflight_acquisition = _acquisition_args(
        preflight_args,
        python=python,
        lane_root=preflight_acquisition_root,
        timeout=86400,
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
    measured_args = _runtime_args(
        base,
        out=result_root,
        scope=scope,
        attestation=attestation,
        target_cap=target_cap,
    )
    measured_acquisition_root = unit_root / "measured-acquisition"
    measured_acquisition_root.mkdir(mode=0o700)
    measured_acquisition = _acquisition_args(
        measured_args,
        python=python,
        lane_root=measured_acquisition_root,
        timeout=86400,
    )
    state = {
        "schema": "ura-vllm-stability-phase6-unit-state/1",
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
    rc = _run(
        (
            str(python),
            "-m",
            "experiments.run_matrix",
            *state["runner_argv"],
        ),
        log=unit_root / "measured.run.log",
        timeout=86400,
        allow_failure=True,
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
    python = args.python.resolve(strict=True)
    if python != project_root / ".venv/bin/python":
        raise ValueError("controller Python is not the project virtual environment")
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

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
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
    return int(completion_value["controller_exit_code"])


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
