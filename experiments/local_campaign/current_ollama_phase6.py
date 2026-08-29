"""Run the additive measured Phase 6 cohort for the current Ollama roster."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence

from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_MODELS,
    CURRENT_OLLAMA_RUNNABLE_LANES,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _canonical,
    _descriptor,
    _stable_file,
    validate_amendment,
)
from experiments.local_targets import _models_map, load_roster
from experiments.rig_web_app.ollama_service import OllamaService
from ura.live_attestation import route_config_sha256


SCHEMA = "ura-current-ollama-phase6/1"
STATE_SCHEMA = "ura-current-ollama-phase6-lane-state/1"
FAILURE_SCHEMA = "ura-current-ollama-phase6-failure/1"
MAX_AGE_HOURS = "24"


def _canonical_dir(path: Path, *, label: str) -> Path:
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical directory")
    return path


def _create_json(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"artifact already exists: {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, _canonical(value))
        os.fsync(fd)
    finally:
        os.close(fd)


def _append_jsonl(path: Path, value: object) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, _canonical(value))
        os.fsync(fd)
    finally:
        os.close(fd)


def _retain_failure(
    *,
    lane: str,
    lane_root: Path,
    result_root: Path,
    gate5_path: Path,
    gate5_sha256: str,
    expected_commit: str,
    stage: str,
    error: BaseException,
) -> dict[str, object]:
    """Retain one typed failed lane in the thesis Runner tree."""

    created_root = False
    if result_root.exists() or result_root.is_symlink():
        _canonical_dir(result_root, label=f"{lane} failed result root")
    else:
        result_root.mkdir(mode=0o700)
        created_root = True
    state_path = lane_root / "state.json"
    state = (
        _descriptor(state_path, label=f"{lane} measured state")
        if state_path.exists() and not state_path.is_symlink()
        else None
    )
    runner_lifecycle_present = any(
        next(result_root.rglob(pattern), None) is not None
        for pattern in ("*.grid.json", "*.request-envelope.json")
    )
    failure_path = result_root / "current-ollama.failure.json"
    _create_json(
        failure_path,
        {
            "schema": FAILURE_SCHEMA,
            "status": "failed",
            "lane_id": lane,
            "project_commit": expected_commit,
            "stage": stage,
            "error_type": type(error).__name__,
            "error": str(error),
            "gate5": {"path": str(gate5_path), "sha256": gate5_sha256},
            "result_root": str(result_root),
            "result_root_created_for_failure": created_root,
            "runner_lifecycle_present": runner_lifecycle_present,
            "state": state,
            "target_attempts": None,
            "successful_target_generations": None,
            "missing_responses": None,
            "paid_provider_calls": 0,
        },
    )
    return _descriptor(failure_path, label=f"{lane} failure artifact")


def _load_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(_stable_file(path, label=label).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _arg_value(argv: Sequence[str], flag: str) -> str:
    if argv.count(flag) != 1:
        raise ValueError(f"exact argv does not contain one {flag}")
    index = argv.index(flag)
    if index + 1 >= len(argv):
        raise ValueError(f"exact argv ends after {flag}")
    return argv[index + 1]


def _run(
    argv: Sequence[str],
    *,
    log: Path,
    timeout: int,
    allow_failure: bool = False,
) -> int:
    if log.exists() or log.is_symlink():
        raise FileExistsError(f"subprocess log already exists: {log}")
    with log.open("xb") as handle:
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            if allow_failure:
                return 124
            raise RuntimeError(f"{Path(argv[0]).name} exceeded {timeout} seconds") from exc
    if completed.returncode and not allow_failure:
        raise RuntimeError(f"{Path(argv[0]).name} exited {completed.returncode}; see {log}")
    return completed.returncode


def _last_json(path: Path, *, required: set[str], label: str) -> dict[str, Any]:
    payload = _stable_file(path, label=label).decode("utf-8")
    for line in reversed(payload.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and required <= set(value):
            return value
    raise ValueError(f"{label} contains no expected result object")


def _validate_live_roster(project_root: Path) -> None:
    vllm = {
        str(spec): dict(config)
        for spec, config in _models_map(load_roster()).items()
        if str(spec).startswith("vllm:") and isinstance(config, dict)
    }
    roster = OllamaService(project_root).roster(vllm, force=True)
    if roster.get("available") is not True or roster.get("issues"):
        raise ValueError(f"current Ollama live roster is unavailable: {roster.get('issues')}")
    candidates = {
        row.get("spec"): row
        for row in roster.get("models", [])
        if isinstance(row, dict) and isinstance(row.get("spec"), str)
    }
    excluded = {row.get("spec") for row in roster.get("excluded", []) if isinstance(row, dict)}
    for model in CURRENT_OLLAMA_MODELS:
        row = candidates.get(model.spec)
        details = row.get("details") if isinstance(row, dict) else None
        if (
            model.spec in excluded
            or not isinstance(row, dict)
            or row.get("digest") != model.digest
            or row.get("modalities") != list(model.modalities)
            or not isinstance(details, dict)
            or details.get("quantization_level") != model.quantization
            or "completion" not in row.get("capabilities", [])
            or row.get("overlap_with")
        ):
            raise ValueError(f"{model.label}: exact live Ollama identity changed")


def _validate_attestation(
    path: Path,
    *,
    sha256: str,
    row: Mapping[str, Any],
    scope: str,
) -> None:
    value = _load_json(path, label=f"{row['lane_id']} live attestation")
    records = value.get("records")
    model = row["model"]
    modality = row["modality"]
    expected_modalities = ["text"] if modality == "text" else ["text", "image"]
    expected_kind = (
        "synthetic_live_transport_probe"
        if modality == "text"
        else "real_source_live_transport_probe"
    )
    if (
        hashlib.sha256(_stable_file(path, label="live attestation")).hexdigest() != sha256
        or value.get("schema") != "ura-live-attestation/2"
        or value.get("status") != "complete"
        or not isinstance(records, list)
        or len(records) != 1
    ):
        raise ValueError(f"{row['lane_id']}: live attestation is incomplete")
    record = records[0]
    if not isinstance(record, dict):
        raise ValueError(f"{row['lane_id']}: live-attestation record is malformed")
    identity = record.get("realized_target_identity", {})
    local_config = _load_json(
        Path(row["local_config"]["path"]), label=f"{row['lane_id']} local configuration"
    )
    expected_route = route_config_sha256(
        route_kind="local_runtime",
        requested_target_spec=model["spec"],
        resolved_target=record["resolved_target"],
        route_config=local_config[model["spec"]],
    )
    if (
        record.get("execution_scope_id") != scope
        or record.get("requested_target_spec") != model["spec"]
        or record.get("route_kind") != "local_runtime"
        or record.get("exact_input_modalities") != expected_modalities
        or identity.get("model_digest") != model["digest"]
        or identity.get("resolved_model") != model["spec"].removeprefix("ollama:")
        or record.get("probe", {}).get("evidence_kind") != expected_kind
        or record.get("route_config_sha256") != expected_route
    ):
        raise ValueError(f"{row['lane_id']}: live-attestation identity changed")


def _probe_args(
    row: Mapping[str, Any],
    *,
    scope: str,
    out: Path,
) -> list[str]:
    base = list(row["base_argv"])
    modality = row["modality"]
    arms = ["synth"] if modality == "text" else ["harmbench_multimodal"]
    result = [
        "--attestation-probe",
        "--execution-scope-id",
        scope,
        "--project-revision",
        _arg_value(base, "--project-revision"),
        "--project-revision-sha256",
        _arg_value(base, "--project-revision-sha256"),
        "--local",
        row["model"]["spec"],
        "--local-config",
        _arg_value(base, "--local-config"),
        "--local-config-sha256",
        _arg_value(base, "--local-config-sha256"),
        "--attackers",
        "replay",
        "--judges",
        "rules",
        "--corpora",
        ",".join(arms),
    ]
    if modality == "image":
        for flag in (
            "--source-config",
            "--source-config-sha256",
            "--source-conformance",
            "--source-conformance-sha256",
        ):
            result.extend((flag, _arg_value(base, flag)))
    result.extend(
        (
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
            "--group",
            _arg_value(base, "--group"),
            "--max-total-target-calls",
            "1",
            "--max-total-judge-calls",
            "0",
            "--max-total-http-attempts",
            "0",
            "--deadline-seconds",
            "3600",
            "--out",
            str(out),
        )
    )
    return result


def _acquisition_args(
    measured: Sequence[str],
    *,
    python: Path,
    lane_root: Path,
    timeout: int,
) -> list[str]:
    plan_root = lane_root / "measured-plan"
    receipts = lane_root / "receipts"
    plan_root.mkdir(mode=0o700)
    receipts.mkdir(mode=0o700)
    plan_log = lane_root / "measured.plan.log"
    _run(
        (
            str(python),
            "-m",
            "experiments.run_matrix",
            *measured,
            "--model-acquisition-plan-only",
            "--model-acquisition-plan-dir",
            str(plan_root),
        ),
        log=plan_log,
        timeout=timeout,
    )
    plan_result = _last_json(
        plan_log, required={"plan_id", "plan_sha256"}, label="measured acquisition plan"
    )
    plan = plan_root / f"{plan_result['plan_id']}.plan.json"
    plan_sha = str(plan_result["plan_sha256"])
    if hashlib.sha256(_stable_file(plan, label="measured plan")).hexdigest() != plan_sha:
        raise ValueError("measured acquisition plan digest changed")
    acquire_log = lane_root / "measured.acquire.log"
    _run(
        (
            str(python),
            "-m",
            "experiments.model_acquire",
            "--plan",
            str(plan),
            "--plan-sha256",
            plan_sha,
            "--store",
            os.environ["URA_MODEL_STORE"],
            "--receipts-dir",
            str(receipts),
            "--transport-cache",
            str(Path(os.environ["URA_MODEL_STORE"]) / ".transport-cache"),
            "--max-download-bytes",
            "0",
            "--min-free-bytes",
            "1099511627776",
            "--deadline-seconds",
            str(timeout),
        ),
        log=acquire_log,
        timeout=timeout,
    )
    receipt_result = _last_json(
        acquire_log,
        required={"receipt_id", "receipt_sha256", "downloaded_bytes"},
        label="measured acquisition receipt",
    )
    if receipt_result["downloaded_bytes"] != 0:
        raise ValueError("measured acquisition unexpectedly downloaded bytes")
    receipt = receipts / f"{receipt_result['receipt_id']}.receipt.json"
    receipt_sha = str(receipt_result["receipt_sha256"])
    if hashlib.sha256(_stable_file(receipt, label="measured receipt")).hexdigest() != receipt_sha:
        raise ValueError("measured acquisition receipt digest changed")
    return [
        "--model-acquisition-plan",
        str(plan),
        "--model-acquisition-plan-sha256",
        plan_sha,
        "--model-acquisition-receipt",
        str(receipt),
        "--model-acquisition-receipt-sha256",
        receipt_sha,
        "--model-acquisition-store",
        os.environ["URA_MODEL_STORE"],
    ]


def _build_state(
    row: Mapping[str, Any],
    *,
    python: Path,
    work_root: Path,
    control_root: Path,
    gate5_sha256: str,
    scope: str,
) -> dict[str, Any]:
    lane = str(row["lane_id"])
    lane_root = control_root / "lanes" / lane
    lane_root.mkdir(mode=0o700, parents=True)
    result_root = work_root / "runs" / "thesis" / "runner" / lane
    if result_root.exists() or result_root.is_symlink():
        raise FileExistsError(f"{lane}: measured result root already exists")
    attestation_parent = work_root / "runs" / "thesis" / "attestation" / control_root.name / lane
    attestation_parent.mkdir(mode=0o700, parents=True)
    probe_root = attestation_parent / "probe"
    probe_log = lane_root / "probe.run.log"
    _run(
        (
            str(python),
            "-m",
            "experiments.run_matrix",
            *_probe_args(row, scope=scope, out=probe_root),
        ),
        log=probe_log,
        timeout=3600,
    )
    attestation = attestation_parent / f"{lane}.live-attestation.json"
    attestation_log = lane_root / "probe.attestation.log"
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
            str(attestation),
        ),
        log=attestation_log,
        timeout=3600,
    )
    attestation_sha = hashlib.sha256(
        _stable_file(attestation, label=f"{lane} live attestation")
    ).hexdigest()
    validate_log = lane_root / "probe.attestation.validate.log"
    _run(
        (
            str(python),
            "-m",
            "experiments.live_attestation",
            "--validate",
            str(attestation),
            "--sha256",
            attestation_sha,
        ),
        log=validate_log,
        timeout=600,
    )
    _validate_attestation(attestation, sha256=attestation_sha, row=row, scope=scope)
    caps = row["approved_caps"]
    measured = [
        *row["base_argv"],
        "--execution-scope-id",
        scope,
        "--live-attestation-max-age-hours",
        MAX_AGE_HOURS,
        "--live-attestation",
        str(attestation),
        "--live-attestation-sha256",
        attestation_sha,
        "--max-total-target-calls",
        str(caps["target_calls"]),
        "--max-total-judge-calls",
        str(caps["model_judge_calls"]),
        "--max-total-http-attempts",
        str(caps["http_attempts"]),
        "--deadline-seconds",
        str(caps["deadline_seconds"]),
        "--out",
        str(result_root),
    ]
    if row["metric_mode"] == "static":
        measured.extend(
            _acquisition_args(
                measured,
                python=python,
                lane_root=lane_root,
                timeout=int(caps["deadline_seconds"]),
            )
        )
    state = {
        "schema": STATE_SCHEMA,
        "lane_id": lane,
        "gate5_sha256": gate5_sha256,
        "result_root": str(result_root),
        "attestation": _descriptor(attestation, label=f"{lane} live attestation"),
        "argv": measured,
    }
    _create_json(lane_root / "state.json", state)
    return state


def _load_state(path: Path, *, lane: str, gate5_sha256: str) -> dict[str, Any]:
    state = _load_json(path, label=f"{lane} measured state")
    if (
        state.get("schema") != STATE_SCHEMA
        or state.get("lane_id") != lane
        or state.get("gate5_sha256") != gate5_sha256
        or not isinstance(state.get("argv"), list)
        or any(not isinstance(item, str) for item in state["argv"])
        or _arg_value(state["argv"], "--out") != state.get("result_root")
    ):
        raise ValueError(f"{lane}: measured state changed")
    descriptor = state.get("attestation")
    if not isinstance(descriptor, dict):
        raise ValueError(f"{lane}: measured state lacks attestation")
    attestation = Path(str(descriptor.get("path")))
    if hashlib.sha256(
        _stable_file(attestation, label=f"{lane} state attestation")
    ).hexdigest() != descriptor.get("sha256"):
        raise ValueError(f"{lane}: state attestation changed")
    return state


def _level1_counts(
    *,
    python: Path,
    lane_root: Path,
    state: Mapping[str, Any],
    timeout: int,
) -> tuple[int, int, int]:
    result_root = Path(str(state["result_root"]))
    eligibility = sorted(result_root.glob("eligibility-*.eligibility.json"))
    if len(eligibility) != 1:
        raise ValueError("measured lane lacks one eligibility plan")
    output = lane_root / "level1.json"
    output_csv = lane_root / "level1.csv"
    if not output.exists():
        attestation = state["attestation"]
        _run(
            (
                str(python),
                "-m",
                "experiments.level1_evidence",
                "--eligibility",
                str(eligibility[0]),
                "--results",
                str(result_root),
                "--live-attestation",
                str(attestation["path"]),
                "--live-attestation-sha256",
                str(attestation["sha256"]),
                "--out-json",
                str(output),
                "--out-csv",
                str(output_csv),
            ),
            log=lane_root / "level1.log",
            timeout=timeout,
        )
    return _counts_from_level1(_load_json(output, label="measured Level 1 evidence"))


def _counts_from_level1(level1: Mapping[str, Any]) -> tuple[int, int, int]:
    counts = level1.get("counts", {}).get("judgment_records", {})
    attempted = counts.get("completed")
    missing = counts.get("missing_responses")
    if (
        isinstance(attempted, bool)
        or not isinstance(attempted, int)
        or isinstance(missing, bool)
        or not isinstance(missing, int)
        or attempted < 1
        or not 0 <= missing <= attempted
    ):
        raise ValueError("measured Level 1 target/missing-response counts changed")
    return attempted, attempted - missing, missing


def run(
    *,
    gate5_path: Path,
    control_root: Path,
    work_root: Path,
    project_root: Path,
    python: Path,
    expected_commit: str,
) -> int:
    control = _canonical_dir(control_root, label="Phase 6 current Ollama control root")
    work = _canonical_dir(work_root, label="campaign work root")
    project = _canonical_dir(project_root, label="project root")
    if control.parent != work / "runs" / "engineering":
        raise ValueError("Phase 6 current Ollama control root is outside engineering")
    gate5_payload = _stable_file(gate5_path, label="current Ollama Gate 5 amendment")
    gate5_sha = hashlib.sha256(gate5_payload).hexdigest()
    gate5 = validate_amendment(gate5_path, expected_commit=expected_commit)
    if gate5_path.parent != Path(str(gate5["control_root"])):
        raise ValueError("current Ollama Gate 5 amendment moved from its control root")
    exit_payload = _stable_file(
        gate5_path.parent / ".exit", label="current Ollama Phase 5 exit marker"
    )
    if exit_payload.decode("ascii").strip() != "0":
        raise ValueError("current Ollama Phase 5 does not have a zero exit marker")
    rows = gate5["lanes"]
    if [row["lane_id"] for row in rows] != list(CURRENT_OLLAMA_RUNNABLE_LANES):
        raise ValueError("current Ollama measured lane order changed")
    status_path = control / "lanes.jsonl"
    lane_root_parent = control / "lanes"
    lane_root_parent.mkdir(mode=0o700)
    total_attempts = 0
    total_successful = 0
    total_missing = 0
    failures = 0
    for lane, terminal in gate5["typed_terminal_lanes"].items():
        _append_jsonl(
            status_path,
            {
                "lane_id": lane,
                "status": terminal["disposition"],
                "reason_code": terminal["reason_code"],
                "reason": terminal["reason"],
                "target_attempts": 0,
                "successful_target_generations": 0,
                "missing_responses": 0,
            },
        )
    for row in rows:
        lane = row["lane_id"]
        lane_root = lane_root_parent / lane
        result_root = work / "runs" / "thesis" / "runner" / lane
        stage = "preflight"
        try:
            validate_amendment(gate5_path, expected_commit=expected_commit)
            _validate_live_roster(project)
            state_path = lane_root / "state.json"
            if state_path.exists():
                stage = "resume-state"
                state = _load_state(state_path, lane=lane, gate5_sha256=gate5_sha)
            else:
                stage = "fresh-attestation-and-plan"
                state = _build_state(
                    row,
                    python=python,
                    work_root=work,
                    control_root=control,
                    gate5_sha256=gate5_sha,
                    scope=os.environ["URA_EXECUTION_SCOPE_ID"],
                )
            stage = "measured-run"
            run_log = lane_root / "measured.run.log"
            if not run_log.exists():
                rc = _run(
                    (str(python), "-m", "experiments.run_matrix", *state["argv"]),
                    log=run_log,
                    timeout=int(row["approved_caps"]["wall_time_seconds"]),
                    allow_failure=True,
                )
                if rc:
                    raise RuntimeError(f"Runner exited {rc}; see {run_log}")
            stage = "level1-validation"
            attempts, successful, missing = _level1_counts(
                python=python,
                lane_root=lane_root,
                state=state,
                timeout=int(row["approved_caps"]["wall_time_seconds"]),
            )
            total_attempts += attempts
            total_successful += successful
            total_missing += missing
            _append_jsonl(
                status_path,
                {
                    "lane_id": lane,
                    "status": "complete",
                    "result_root": state["result_root"],
                    "level1": _descriptor(lane_root / "level1.json", label="Level 1"),
                    "target_attempts": attempts,
                    "successful_target_generations": successful,
                    "missing_responses": missing,
                },
            )
        except (
            KeyError,
            OSError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
            RuntimeError,
        ) as exc:
            failures += 1
            failure = _retain_failure(
                lane=lane,
                lane_root=lane_root,
                result_root=result_root,
                gate5_path=gate5_path,
                gate5_sha256=gate5_sha,
                expected_commit=expected_commit,
                stage=stage,
                error=exc,
            )
            _append_jsonl(
                status_path,
                {
                    "lane_id": lane,
                    "status": "failed",
                    "stage": stage,
                    "error": str(exc),
                    "result_root": str(result_root),
                    "failure": failure,
                    "target_attempts": None,
                    "successful_target_generations": None,
                    "missing_responses": None,
                },
            )
    counts_path = control / "target-execution.json"
    _create_json(
        counts_path,
        {
            "target_attempts": total_attempts,
            "successful_target_generations": total_successful,
            "missing_responses": total_missing,
            "accounting_scope": "completion_bound_level1_records",
        },
    )
    completion = {
        "schema": SCHEMA,
        "status": "complete" if failures == 0 else "complete_with_failures",
        "project_commit": expected_commit,
        "gate5": {
            "path": str(gate5_path),
            "sha256": gate5_sha,
        },
        "runnable_lanes": len(rows),
        "typed_terminal_lanes": len(gate5["typed_terminal_lanes"]),
        "completed_lanes": len(rows) - failures,
        "failed_lanes": failures,
        "target_execution": _load_json(counts_path, label="target execution counts"),
        "paid_provider_calls": 0,
        "status_rows": _descriptor(status_path, label="Phase 6 lane status"),
    }
    _create_json(control / "completion.json", completion)
    return 0 if failures == 0 else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gate5-amendment", type=Path, required=True)
    result.add_argument("--control-root", type=Path, required=True)
    result.add_argument("--work-root", type=Path, required=True)
    result.add_argument("--project-root", type=Path, required=True)
    result.add_argument("--python", type=Path, required=True)
    result.add_argument("--expected-commit", required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            gate5_path=args.gate5_amendment,
            control_root=args.control_root,
            work_root=args.work_root,
            project_root=args.project_root,
            python=args.python,
            expected_commit=args.expected_commit,
        )
    except (
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        print(f"current Ollama Phase 6 failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
