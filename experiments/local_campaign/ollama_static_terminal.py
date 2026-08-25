"""Campaign-only typed outcomes for unusable Ollama static-canary output."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Iterable, Mapping

from ura.strict_json import strict_json_loads

SCHEMA = "ura-phase5-ollama-static-canary-terminal/1"
DISPOSITION = "target_runtime_terminal"
REASON_CODE = "local_target_output_unusable"
REASON = (
    "The exact RWKV Ollama target reached the sealed generation cap during the "
    "selected static diagnostic canary. Runner rejected that incomplete attempt, so "
    "this campaign cohort does not schedule the static lane for measured execution. "
    "Earlier completed canary attempts remain diagnostic observations, and this is not "
    "a claim that the model or runtime is generally unusable. Its separate R-Judge lane "
    "remains runnable."
)
ERROR_PREFIX = "target_call failed (LocalTargetOutputError): "
ACCOUNTING_SEMANTICS = "durable_pre_call_logical_reservation_v1"
STATIC_LANE_MODELS: Mapping[str, tuple[str, str, str]] = MappingProxyType({
    "ollama-rwkv-g1d-0p4b-text-exploratory-50": (
        "rwkv-g1d-0p4b", "ollama:mollysama/rwkv-7-g1d:0.4b",
        "78e699bd71f0cef7ed8fb38a469088310af0ab07d678661980c6b8c7f130a7f8"),
    "ollama-rwkv-g1f-2p9b-text-exploratory-50": (
        "rwkv-g1f-2p9b", "ollama:mollysama/rwkv-7-g1f:2.9b",
        "7813f2283a135ef1264b8cec647b339d92fa7ecffafefeac61a2670b572f03f7"),
    "ollama-rwkv-g1g-1p5b-text-exploratory-50": (
        "rwkv-g1g-1p5b", "ollama:mollysama/rwkv-7-g1g:1.5b",
        "8ff95f43952c361048310b50a5c4b16f98d8f0642a87b536452e627224a0dddc"),
})
OLLAMA_STATIC_TERMINAL_SCHEMA = SCHEMA
OLLAMA_STATIC_TERMINAL_DISPOSITION = DISPOSITION
OLLAMA_STATIC_TERMINAL_REASON_CODE = REASON_CODE
OLLAMA_STATIC_TERMINAL_REASON = REASON
OLLAMA_STATIC_TERMINAL_LANES = tuple(STATIC_LANE_MODELS)
OLLAMA_STATIC_TERMINAL_MODELS = STATIC_LANE_MODELS
OLLAMA_STATIC_TERMINAL_VALUE = MappingProxyType(
    {"status": "TARGET_RUNTIME_TERMINAL", "value": None})


def inventory_counts(static_terminal_lanes: Iterable[str],
                     conditional_na_lanes: Iterable[str]) -> dict[str, object]:
    static_values, conditional_values = list(static_terminal_lanes), list(conditional_na_lanes)
    static, conditional = set(static_values), set(conditional_values)
    if len(static) != len(static_values) or not static <= set(STATIC_LANE_MODELS):
        raise ValueError("invalid or duplicate Ollama static terminal lane")
    if (len(conditional) != len(conditional_values)
            or conditional not in (set(), {"defense-local"})):
        raise ValueError("invalid or duplicate conditional-N/A lane")
    return {"runnable": 22 - len(static) - len(conditional),
            "typed_terminal": 24 + len(static) + len(conditional),
            "target_runtime_terminal": 4 + len(static),
            "conditional_na_lanes": sorted(conditional)}


def _read(path: Path, *, label: str, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    path, fd = Path(os.path.abspath(path)), None
    try:
        before = path.lstat()
        junction = getattr(path, "is_junction", lambda: False)()
        if (path.is_symlink() or junction or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or not 0 < before.st_size <= max_bytes):
            raise ValueError("not one bounded regular inode")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_mode)
        if ((opened.st_dev, opened.st_ino, opened.st_mode) != identity
                or opened.st_nlink != 1 or opened.st_size != before.st_size):
            raise ValueError("inode changed while opening")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            payload, after = handle.read(max_bytes + 1), os.fstat(handle.fileno())
        if (len(payload) != opened.st_size or len(payload) > max_bytes
                or (after.st_dev, after.st_ino, after.st_mode) != identity
                or after.st_nlink != 1 or after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns):
            raise ValueError("inode changed while reading")
        return payload
    except (OSError, ValueError) as exc:
        raise ValueError(f"{label} cannot be read safely: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _descriptor(path: Path, payload: bytes) -> dict[str, object]:
    return {"path": str(Path(os.path.abspath(path))),
            "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}


def descriptor_for(path: Path) -> dict[str, object]:
    return _descriptor(path, _read(path, label=Path(path).name))


def _descriptor_path(value: object) -> Path:
    if (not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}
            or not isinstance(value.get("path"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256"))) is None
            or type(value.get("bytes")) is not int or value["bytes"] <= 0):
        raise ValueError("invalid artifact descriptor")
    path = Path(value["path"])
    if (not path.is_absolute() or path != Path(os.path.abspath(path))
            or path.resolve(strict=True) != path):
        raise ValueError("artifact descriptor path is not resolved")
    return path


def validate_descriptor(value: object, *, parent: Path | None = None) -> tuple[Path, bytes]:
    path = _descriptor_path(value)
    if parent is not None and path.parent != Path(os.path.abspath(parent)):
        raise ValueError("artifact descriptor escaped its expected parent")
    payload = _read(path, label=path.name)
    if value != _descriptor(path, payload):
        raise ValueError("artifact descriptor identity changed")
    return path, payload


def _object(payload: bytes, label: str) -> dict[str, object]:
    try:
        value = strict_json_loads(payload.decode("utf-8"))
    except (UnicodeError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not a JSON object")
    return value


def _detail(message: object) -> dict[str, object]:
    if not isinstance(message, str) or not message.startswith(ERROR_PREFIX):
        raise ValueError("error is not a LocalTargetOutputError wrapper")
    local = message.removeprefix(ERROR_PREFIX)
    if local == "Ollama response is truncated or incomplete: 'length'":
        return {"kind": "finish_reason", "finish_reason": "length", "message": local}
    if local == "Ollama returned an empty completion":
        return {"kind": "empty_completion", "finish_reason": "stop", "message": local}
    raise ValueError("LocalTargetOutputError is not a model-output terminal")


def _error(path: Path, lane: str) -> tuple[dict[str, object], dict[str, object], bytes]:
    payload, model = _read(path, label="structured Runner error"), STATIC_LANE_MODELS[lane]
    value, runtime = _object(payload, "structured Runner error"), f"{model[1]}@sha256:{model[2]}"
    detail, snapshot = _detail(value.get("message")), value.get("call_budget_snapshot")
    calls = snapshot.get("target_calls") if isinstance(snapshot, dict) else None
    completed = value.get("completed_attempts")
    if (value.get("status") != "error" or value.get("exception_type") != "ExternalCallFailure"
            or value.get("phase") != "cell_execution_or_validation"
            or value.get("execution_started") is not True or value.get("corpus") != "airbench_full"
            or value.get("attacker") != "replay" or value.get("target") != runtime
            or value.get("model_spec") != runtime or value.get("call_audit") != {}
            or not isinstance(snapshot, dict) or snapshot.get("accounting_semantics") != ACCOUNTING_SEMANTICS
            or snapshot.get("budget_id") != value.get("grid_id")
            or re.fullmatch(r"grid-[0-9a-f]{24}", str(value.get("grid_id"))) is None
            or snapshot.get("max_target_calls") != 15 or snapshot.get("max_judge_calls") is not None
            or snapshot.get("max_http_attempts") is not None or snapshot.get("judge_calls") != 0
            or snapshot.get("http_attempts") != 0 or type(calls) is not int or not 1 <= calls <= 15
            or type(completed) is not int or completed != calls - 1):
        raise ValueError("structured error is outside the Ollama static output boundary")
    accounting = {"accounting_semantics": ACCOUNTING_SEMANTICS,
                  "budget_id": snapshot["budget_id"], "max_target_calls": 15,
                  "target_calls": calls, "completed_attempts": completed,
                  "model_judge_calls": 0, "http_attempts": 0}
    return detail, accounting, payload


def _value(lane: str, detail: dict[str, object], accounting: dict[str, object],
           error: dict[str, object], log: dict[str, object]) -> dict[str, object]:
    label, spec, digest = STATIC_LANE_MODELS[lane]
    return {"schema": SCHEMA, "status": "terminal", "disposition": DISPOSITION,
            "reason_code": REASON_CODE, "reason": REASON, "evidence_eligible": False,
            "lane_id": lane,
            "model": {"model_label": label, "requested_spec": spec,
                      "resolved_runtime": f"{spec}@sha256:{digest}", "digest": digest,
                      "transport": "ollama", "configured_num_predict": 512},
            "classification": {"category": REASON_CODE, "exception_type": "ExternalCallFailure",
                               "runner_phase": "cell_execution_or_validation",
                               "target_error_type": "LocalTargetOutputError",
                               "diagnostic_detail": detail, "returncode": 1},
            "call_accounting": accounting, "artifacts": {"error": error, "runner_log": log}}


def validate_terminal_artifact(path: Path, *, expected_lane: str | None = None,
                               expected_diagnostic_root: Path | None = None) -> dict[str, object]:
    artifact_path = Path(os.path.abspath(path))
    if artifact_path.parent.resolve(strict=True) != artifact_path.parent:
        raise ValueError("terminal artifact parent is not resolved")
    value = _object(_read(artifact_path, label="Ollama terminal artifact"), "Ollama terminal artifact")
    lane = value.get("lane_id")
    if lane not in STATIC_LANE_MODELS or (expected_lane is not None and lane != expected_lane):
        raise ValueError("terminal artifact names an unexpected lane")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"error", "runner_log"}:
        raise ValueError("terminal artifact descriptor inventory changed")
    error_path, error_payload = validate_descriptor(artifacts["error"])
    log_path, log_payload = validate_descriptor(artifacts["runner_log"], parent=artifact_path.parent)
    if (expected_diagnostic_root is not None
            and error_path.parent != Path(os.path.abspath(expected_diagnostic_root))):
        raise ValueError("terminal error escaped its diagnostic root")
    detail, accounting, _ = _error(error_path, lane)
    message = (ERROR_PREFIX + str(detail["message"])).encode()
    expected = _value(lane, detail, accounting, _descriptor(error_path, error_payload),
                      _descriptor(log_path, log_payload))
    if value != expected or message not in log_payload:
        raise ValueError("Ollama terminal artifact contract changed")
    return value


def classify(*, output: Path, runner_log: Path, diagnostic_root: Path, lane: str,
             runner_returncode: int) -> dict[str, object]:
    if lane not in STATIC_LANE_MODELS or runner_returncode != 1:
        raise ValueError("only an exact failed Ollama static canary can be classified")
    root, output, runner_log = map(lambda p: Path(os.path.abspath(p)),
                                   (diagnostic_root, output, runner_log))
    if (root.resolve(strict=True) != root or not root.is_dir() or root.is_symlink()
            or output.parent.resolve(strict=True) != output.parent
            or runner_log.parent != output.parent):
        raise ValueError("classifier paths are not exact resolved campaign paths")
    errors = sorted(root.glob("*.error.json"))
    if len(errors) != 1:
        raise ValueError(f"expected one structured Runner error, found {len(errors)}")
    detail, accounting, error_payload = _error(errors[0], lane)
    log_payload = _read(runner_log, label="Runner canary log")
    if (ERROR_PREFIX + str(detail["message"])).encode() not in log_payload:
        raise ValueError("Runner log does not contain the structured terminal error")
    value = _value(lane, detail, accounting, _descriptor(errors[0], error_payload),
                   _descriptor(runner_log, log_payload))
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(encoded):
            offset += os.write(fd, encoded[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    return validate_terminal_artifact(output, expected_lane=lane,
                                      expected_diagnostic_root=root)


def _candidate_rows(rows: Iterable[Mapping[str, object]], key: str) -> dict[str, Mapping[str, object]]:
    values = list(rows)
    by_lane = {str(row.get(key)): row for row in values}
    if len(values) != 3 or len(by_lane) != 3 or set(by_lane) != set(OLLAMA_STATIC_TERMINAL_LANES):
        raise ValueError("Ollama static row inventory changed")
    return by_lane


def validate_terminal_rows(rows: Iterable[Mapping[str, object]], *, label: str,
                           validate_artifact: bool = True,
                           error_type: type[BaseException] = ValueError) -> tuple[str, ...]:
    try:
        by_lane, terminals = _candidate_rows(rows, "lane"), []
        for lane, row in by_lane.items():
            model = STATIC_LANE_MODELS[lane]
            if ((row.get("model_label"), row.get("requested_spec"), row.get("digest")) != model
                    or row.get("metric_mode") != "static"):
                raise ValueError(f"{lane} model identity changed")
            if row.get("disposition") == "runnable":
                if any(row.get(k) for k in ("reason_code", "reason", "target_runtime_terminal_artifact")):
                    raise ValueError(f"{lane} runnable row retained terminal fields")
                continue
            if (row.get("disposition") != DISPOSITION or row.get("reason_code") != REASON_CODE
                    or row.get("reason") != REASON):
                raise ValueError(f"{lane} terminal disposition changed")
            artifact = row.get("target_runtime_terminal_artifact")
            if not isinstance(artifact, str) or not artifact:
                raise ValueError(f"{lane} lacks its terminal artifact")
            if validate_artifact:
                validate_terminal_artifact(Path(artifact), expected_lane=lane,
                    expected_diagnostic_root=Path(str(row.get("diagnostic_root"))))
            terminals.append(lane)
        return tuple(sorted(terminals))
    except Exception as exc:
        raise error_type(f"{label}: {exc}") from exc


def validate_gate5_terminal_rows(rows: Iterable[Mapping[str, object]], *, label: str,
                                 validate_artifact: bool = True,
                                 error_type: type[BaseException] = ValueError) -> tuple[str, ...]:
    try:
        by_lane, terminals, terminal_value = _candidate_rows(rows, "lane_id"), [], dict(OLLAMA_STATIC_TERMINAL_VALUE)
        for lane, row in by_lane.items():
            if row.get("disposition") == "runnable":
                continue
            projection, canary = row.get("projection"), row.get("canary")
            if (row.get("family") != "ollama" or row.get("disposition") != DISPOSITION
                    or row.get("reason_code") != REASON_CODE or row.get("reason") != REASON
                    or not isinstance(projection, dict) or projection.get("status") != "passed"
                    or not isinstance(canary, dict)
                    or {"status": canary.get("status"), "value": canary.get("value")} != terminal_value
                    or row.get("final_preflight") != terminal_value
                    or row.get("approved_caps") != terminal_value):
                raise ValueError(f"{lane} Gate 5 terminal identity changed")
            descriptor, accounting = canary.get("target_runtime_terminal_artifact"), canary.get("call_accounting")
            path = _descriptor_path(descriptor)
            if path.name != f"{lane}.target-runtime-terminal.json" or not isinstance(accounting, dict):
                raise ValueError(f"{lane} Gate 5 terminal descriptor/accounting changed")
            if validate_artifact:
                validate_descriptor(descriptor)
                if validate_terminal_artifact(path, expected_lane=lane)["call_accounting"] != accounting:
                    raise ValueError(f"{lane} Gate 5 row differs from terminal artifact")
            terminals.append(lane)
        return tuple(sorted(terminals))
    except Exception as exc:
        raise error_type(f"{label}: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    command = subs.add_parser("classify")
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--runner-log", type=Path, required=True)
    command.add_argument("--diagnostic-root", type=Path, required=True)
    command.add_argument("--lane", choices=OLLAMA_STATIC_TERMINAL_LANES, required=True)
    command.add_argument("--runner-returncode", type=int, required=True)
    args = parser.parse_args(argv)
    value = classify(output=args.output, runner_log=args.runner_log,
                     diagnostic_root=args.diagnostic_root, lane=args.lane,
                     runner_returncode=args.runner_returncode)
    print(value["disposition"], value["reason_code"], value["reason"], args.output, sep="\t")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
