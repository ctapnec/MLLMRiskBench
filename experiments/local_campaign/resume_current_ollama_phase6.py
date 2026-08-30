"""Resume only failed current-Ollama Phase 6 lanes from exact checkpoints.

This is a campaign controller, not a Runner feature. It preserves the original
request, run IDs, completion markers, checkpoints and call-budget ledger. A
successful cell is therefore skipped, and an interrupted cell resumes only the
attempts absent from its durable checkpoint.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Mapping, Sequence

from experiments.local_campaign.current_ollama_gate5 import (
    _canonical,
    _descriptor,
    _descriptor_file,
    _stable_file,
    validate_amendment,
)
from experiments.local_campaign.current_ollama_phase6 import (
    _arg_value,
    _canonical_dir,
    _counts_from_level1,
    _create_json,
    _level1_counts,
    _load_state,
    _strict_object,
    validate_completion,
)
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)


SCHEMA = "ura-current-ollama-phase6-recovery/1"
PHASE7_INPUT_SCHEMA = "ura-current-ollama-phase7-input/2"


def _wait_for_file(path: Path, *, wait_seconds: int, poll_seconds: int) -> None:
    deadline = time.monotonic() + wait_seconds
    while not path.exists():
        if path.is_symlink():
            raise ValueError("base Phase 6 completion must not be a symlink")
        if time.monotonic() >= deadline:
            raise TimeoutError("base Phase 6 completion did not appear before the deadline")
        time.sleep(poll_seconds)


def _tracked_checkout_commit(project_root: Path) -> str:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    changed = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if changed:
        raise ValueError("project checkout has tracked changes")
    return head


def _checkpoint_records(result_root: Path) -> int:
    total = 0
    for path in sorted(result_root.glob("*.checkpoint.jsonl")):
        if path.name.endswith(".responses.checkpoint.jsonl"):
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("lane checkpoint is not one regular file")
        payload = path.read_bytes()
        if payload and not payload.endswith(b"\n"):
            raise ValueError("lane checkpoint is not newline terminated")
        total += len(payload.splitlines())
    return total


def _completed_records(result_root: Path) -> int:
    total = 0
    for path in sorted(result_root.glob("*.complete.json")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("lane completion marker is not one regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
        count = value.get("n_responses") if isinstance(value, dict) else None
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ValueError("lane completion marker has an invalid response count")
        total += count
    return total


def _run_exact(
    *,
    python: Path,
    argv: Sequence[str],
    log: Path,
    timeout: int,
) -> int:
    if log.exists() or log.is_symlink():
        raise FileExistsError(f"recovery log already exists: {log}")
    with log.open("xb") as handle:
        try:
            completed = subprocess.run(
                [str(python), "-m", "experiments.run_matrix", *argv],
                check=False,
                stdout=handle,
                stderr=subprocess.STDOUT,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return 124
    return completed.returncode


def run(
    *,
    gate5_path: Path,
    base_completion: Path,
    runner_root: Path,
    control_root: Path,
    project_root: Path,
    python: Path,
    work_root: Path,
    tmux_socket: str,
    tmux_session: str,
    wait_seconds: int,
    poll_seconds: int,
    max_lane_launches: int,
) -> int:
    if wait_seconds < 1 or poll_seconds < 1 or poll_seconds > wait_seconds:
        raise ValueError("wait and poll seconds are invalid")
    if max_lane_launches < 1 or max_lane_launches > 10:
        raise ValueError("max lane launches must be in [1, 10]")
    controller_path = Path(__file__).resolve(strict=True)
    controller_source = _descriptor(controller_path, label="current Ollama recovery controller")
    _wait_for_file(base_completion, wait_seconds=wait_seconds, poll_seconds=poll_seconds)
    base = validate_completion(
        gate5_path=gate5_path,
        completion_path=base_completion,
        runner_root=runner_root,
    )
    gate5 = validate_amendment(gate5_path)
    expected_commit = str(gate5["project_commit"])
    project = _canonical_dir(project_root, label="project checkout")
    if _tracked_checkout_commit(project) != expected_commit:
        raise ValueError("project checkout differs from the failed Phase 6 revision")
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("recovery Python is not one executable regular file")
    runner = _canonical_dir(runner_root, label="thesis Runner root")
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("recovery control root must be create-only")
    control_root.mkdir(mode=0o700)
    (control_root / "lanes").mkdir(mode=0o700)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=expected_commit,
        evidence_class="measured_local_current_ollama_recovery",
        hard_stop_hours=336,
        tmux_socket=tmux_socket,
        tmux_session=tmux_session,
        target_execution=True,
    )

    failed_lanes = [lane for lane, state in base["terminal_states"].items() if state == "failed"]
    rows: list[dict[str, Any]] = []
    failures = 0
    gate5_sha256 = hashlib.sha256(gate5_path.read_bytes()).hexdigest()
    base_control = base_completion.parent
    for lane in failed_lanes:
        lane_root = control_root / "lanes" / lane
        lane_root.mkdir(mode=0o700)
        state = _load_state(
            base_control / "lanes" / lane / "state.json",
            lane=lane,
            gate5_sha256=gate5_sha256,
        )
        result_root = Path(str(state["result_root"]))
        if result_root.parent != runner or result_root.name != lane:
            raise ValueError(f"{lane}: result root differs from its lane identity")
        result_root = _canonical_dir(result_root, label=f"{lane} result root")
        before_completed = _completed_records(result_root)
        before_checkpointed = _checkpoint_records(result_root)
        timeout = int(_arg_value(state["argv"], "--deadline-seconds"))
        launches: list[dict[str, Any]] = []
        returncode = 1
        for number in range(1, max_lane_launches + 1):
            log = lane_root / f"resume-{number}.log"
            returncode = _run_exact(
                python=python,
                argv=state["argv"],
                log=log,
                timeout=timeout,
            )
            launches.append(
                {
                    "number": number,
                    "returncode": returncode,
                    "log": _descriptor(log, label=f"{lane} recovery launch {number}"),
                }
            )
            if returncode == 0:
                break
        row: dict[str, Any] = {
            "lane_id": lane,
            "status": "failed",
            "initial_completed_responses": before_completed,
            "initial_checkpointed_responses": before_checkpointed,
            "launches": launches,
            "result_root": str(result_root),
        }
        if returncode == 0:
            attempted, successful, missing = _level1_counts(
                python=python,
                lane_root=lane_root,
                state=state,
                timeout=timeout,
            )
            after_completed = _completed_records(result_root)
            after_checkpointed = _checkpoint_records(result_root)
            if after_completed != attempted or after_checkpointed != 0:
                raise ValueError(f"{lane}: recovery completion counts do not reconcile")
            row.update(
                {
                    "status": "complete",
                    "target_attempts": attempted,
                    "successful_target_generations": successful,
                    "missing_responses": missing,
                    "final_completed_responses": after_completed,
                    "final_checkpointed_responses": after_checkpointed,
                    "level1": _descriptor(
                        lane_root / "level1.json", label=f"{lane} recovery Level 1"
                    ),
                }
            )
        else:
            failures += 1
            row.update(
                {
                    "target_attempts": None,
                    "successful_target_generations": None,
                    "missing_responses": None,
                    "final_completed_responses": _completed_records(result_root),
                    "final_checkpointed_responses": _checkpoint_records(result_root),
                }
            )
        rows.append(row)

    body: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "complete" if failures == 0 else "complete_with_failures",
        "base_phase6": _descriptor(base_completion, label="base Phase 6 completion"),
        "gate5": _descriptor(gate5_path, label="current Ollama Gate 5 amendment"),
        "controller_source": controller_source,
        "project_commit": expected_commit,
        "failed_lanes_selected": failed_lanes,
        "recovered_lanes": sum(row["status"] == "complete" for row in rows),
        "remaining_failed_lanes": failures,
        "rows": rows,
        "paid_provider_calls": 0,
    }
    if (
        _descriptor(controller_path, label="current Ollama recovery controller")
        != controller_source
    ):
        raise ValueError("current Ollama recovery controller changed while running")
    body["recovery_id"] = (
        "current-ollama-recovery-" + hashlib.sha256(_canonical(body)).hexdigest()[:24]
    )
    _create_json(control_root / "completion.json", body)
    (control_root / ".exit").write_text("0\n" if failures == 0 else "1\n", encoding="ascii")
    exit_code = 0 if failures == 0 else 1
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=sum(
            row["target_attempts"] for row in rows if row["target_attempts"] is not None
        ),
        successful_target_generations=sum(
            row["successful_target_generations"]
            for row in rows
            if row["successful_target_generations"] is not None
        ),
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=exit_code,
    )
    return exit_code


def _nonnegative_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} is not a nonnegative integer")
    return value


def _validate_launches(value: object, *, lane: str, lane_root: Path) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 10:
        raise ValueError(f"{lane}: recovery launch inventory changed")
    launches: list[dict[str, Any]] = []
    for number, raw in enumerate(value, start=1):
        if not isinstance(raw, dict) or set(raw) != {"number", "returncode", "log"}:
            raise ValueError(f"{lane}: recovery launch fields changed")
        returncode = raw.get("returncode")
        if (
            raw.get("number") != number
            or isinstance(returncode, bool)
            or not isinstance(returncode, int)
        ):
            raise ValueError(f"{lane}: recovery launch sequence changed")
        log = _descriptor_file(raw.get("log"), label=f"{lane} recovery launch {number}")
        if log != lane_root / f"resume-{number}.log":
            raise ValueError(f"{lane}: recovery launch log path changed")
        launches.append(dict(raw))
    if launches[-1]["returncode"] != 0:
        raise ValueError(f"{lane}: recovery did not finish successfully")
    return launches


def _metric_artifacts(
    *, lane: str, result_root: Path
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
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
        raise ValueError(f"{lane}: recovered Runner artifact inventory changed")
    return (
        _descriptor(grids[0], label=f"{lane} recovered measured grid"),
        _descriptor(envelopes[0], label=f"{lane} recovered request envelope"),
        _descriptor(eligibility[0], label=f"{lane} recovered eligibility plan"),
        [_descriptor(marker, label=f"{lane} recovered completion marker") for marker in markers],
    )


def _recovered_metric_evidence(
    *,
    lane: str,
    result_root: Path,
    base_failure: Mapping[str, Any],
    recovery_descriptor: Mapping[str, Any],
    level1: Mapping[str, Any],
) -> dict[str, Any]:
    grid, envelope, eligibility, markers = _metric_artifacts(
        lane=lane, result_root=result_root
    )
    return {
        "base_failure": base_failure,
        "recovery_completion": recovery_descriptor,
        "grid": grid,
        "request_envelope": envelope,
        "eligibility_plan": eligibility,
        "completion_markers": markers,
        "level1": level1,
    }


def validate_recovery_completion(
    *,
    gate5_path: Path,
    base_completion: Path,
    recovery_completion: Path,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate one complete failed-lane recovery and overlay it for Phase 7."""

    base = validate_completion(
        gate5_path=gate5_path,
        completion_path=base_completion,
        runner_root=runner_root,
    )
    selected = [lane for lane, state in base["terminal_states"].items() if state == "failed"]
    if not selected:
        raise ValueError("current Ollama recovery is unnecessary for a complete base run")
    control = _canonical_dir(
        recovery_completion.parent, label="current Ollama Phase 6 recovery root"
    )
    if (
        not control.name.startswith("phase6-current-ollama-recovery-")
        or recovery_completion != control / "completion.json"
    ):
        raise ValueError("current Ollama recovery completion path changed")
    value = _strict_object(recovery_completion, label="current Ollama Phase 6 recovery completion")
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
    gate5 = validate_amendment(gate5_path)
    if (
        set(value) != fields
        or value.get("schema") != SCHEMA
        or value.get("status") != "complete"
        or value.get("base_phase6")
        != _descriptor(base_completion, label="base current Ollama Phase 6 completion")
        or value.get("gate5") != _descriptor(gate5_path, label="current Ollama Gate 5 amendment")
        or value.get("project_commit") != gate5.get("project_commit")
        or value.get("failed_lanes_selected") != selected
        or value.get("recovered_lanes") != len(selected)
        or value.get("remaining_failed_lanes") != 0
        or value.get("paid_provider_calls") != 0
    ):
        raise ValueError("current Ollama recovery completion contract changed")
    controller_source = _descriptor_file(
        value.get("controller_source"), label="current Ollama recovery controller"
    )
    if (
        _descriptor(controller_source, label="current Ollama recovery controller")
        != value["controller_source"]
    ):
        raise ValueError("current Ollama recovery controller identity changed")
    recovery_id = value.get("recovery_id")
    identity_body = dict(value)
    identity_body.pop("recovery_id")
    expected_recovery_id = (
        "current-ollama-recovery-" + hashlib.sha256(_canonical(identity_body)).hexdigest()[:24]
    )
    if recovery_id != expected_recovery_id:
        raise ValueError("current Ollama recovery identity changed")
    if _stable_file(control / ".exit", label="current Ollama recovery exit marker") != b"0\n":
        raise ValueError("current Ollama recovery exit marker is nonzero")

    rows = value.get("rows")
    if (
        not isinstance(rows, list)
        or len(rows) != len(selected)
        or [row.get("lane_id") if isinstance(row, Mapping) else None for row in rows] != selected
    ):
        raise ValueError("current Ollama recovery row inventory changed")
    recovered_rows: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            raise ValueError("current Ollama recovery row is not an object")
        lane = str(raw.get("lane_id"))
        expected_fields = {
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
            "level1",
        }
        if set(raw) != expected_fields or raw.get("status") != "complete":
            raise ValueError(f"{lane}: recovered row fields changed")
        result_root = Path(str(raw.get("result_root")))
        expected_root = Path(str(base["lifecycle"][lane]["result_root"]))
        if result_root != expected_root:
            raise ValueError(f"{lane}: recovered result root changed")
        result_root = _canonical_dir(result_root, label=f"{lane} recovered result root")
        initial_completed = _nonnegative_int(
            raw.get("initial_completed_responses"),
            label=f"{lane} initial completed responses",
        )
        initial_checkpointed = _nonnegative_int(
            raw.get("initial_checkpointed_responses"),
            label=f"{lane} initial checkpointed responses",
        )
        target_attempts = _nonnegative_int(
            raw.get("target_attempts"), label=f"{lane} recovered target attempts"
        )
        successful = _nonnegative_int(
            raw.get("successful_target_generations"),
            label=f"{lane} recovered successful generations",
        )
        missing = _nonnegative_int(
            raw.get("missing_responses"), label=f"{lane} recovered missing responses"
        )
        final_completed = _nonnegative_int(
            raw.get("final_completed_responses"),
            label=f"{lane} final completed responses",
        )
        final_checkpointed = _nonnegative_int(
            raw.get("final_checkpointed_responses"),
            label=f"{lane} final checkpointed responses",
        )
        if (
            target_attempts < 1
            or successful + missing != target_attempts
            or final_completed != target_attempts
            or final_checkpointed != 0
            or initial_completed + initial_checkpointed > target_attempts
            or _completed_records(result_root) != target_attempts
            or _checkpoint_records(result_root) != 0
        ):
            raise ValueError(f"{lane}: recovered response accounting changed")
        lane_root = control / "lanes" / lane
        lane_root = _canonical_dir(lane_root, label=f"{lane} recovery control root")
        _validate_launches(raw.get("launches"), lane=lane, lane_root=lane_root)
        level1_path = _descriptor_file(raw.get("level1"), label=f"{lane} recovered Level 1")
        if level1_path != lane_root / "level1.json":
            raise ValueError(f"{lane}: recovered Level 1 path changed")
        if _counts_from_level1(_strict_object(level1_path, label=f"{lane} recovered Level 1")) != (
            target_attempts,
            successful,
            missing,
        ):
            raise ValueError(f"{lane}: recovered Level 1 counts changed")
        recovered_rows[lane] = dict(raw)

    result = copy.deepcopy(base)
    result["schema"] = PHASE7_INPUT_SCHEMA
    recovery_descriptor = _descriptor(
        recovery_completion, label="current Ollama recovery completion"
    )
    result["recovery_completion"] = recovery_descriptor
    result["recovery_id"] = recovery_id
    for lane, row in recovered_rows.items():
        base_failure = result["lifecycle"][lane]["evidence"]
        evidence = _recovered_metric_evidence(
            lane=lane,
            result_root=_canonical_dir(
                Path(row["result_root"]), label=f"{lane} recovered result root"
            ),
            base_failure=base_failure,
            recovery_descriptor=recovery_descriptor,
            level1=row["level1"],
        )
        result["terminal_states"][lane] = "measured_complete"
        result["lifecycle"][lane] = {
            "state": "measured_complete",
            "result_root": row["result_root"],
            "runner_lifecycle_present": True,
            "evidence": evidence,
        }
        result["metric_roots"][lane] = row["result_root"]
        result["metric_evidence"][lane] = evidence
        result["excluded_from_metrics"].pop(lane)

    metric_lane_order = [lane for lane in result["lane_order"] if lane in result["metric_roots"]]
    metric_grids: list[dict[str, Any]] = []
    metric_eligibility: list[dict[str, Any]] = []
    metric_markers: list[dict[str, Any]] = []
    for lane in metric_lane_order:
        grid, _envelope, eligibility, markers = _metric_artifacts(
            lane=lane,
            result_root=_canonical_dir(
                Path(result["metric_roots"][lane]), label=f"{lane} metric result root"
            ),
        )
        metric_grids.append(grid)
        metric_eligibility.append(eligibility)
        metric_markers.extend(markers)
    result["metric_lane_order"] = metric_lane_order
    result["metric_grids"] = metric_grids
    result["metric_eligibility_plans"] = metric_eligibility
    result["metric_completion_markers"] = metric_markers
    result["revision_strata"] = {result["project_revision_receipt_sha256"]: metric_lane_order}
    result["target_execution"] = {
        "target_attempts": base["target_execution"]["target_attempts"]
        + sum(row["target_attempts"] for row in recovered_rows.values()),
        "successful_target_generations": base["target_execution"]["successful_target_generations"]
        + sum(row["successful_target_generations"] for row in recovered_rows.values()),
        "missing_responses": base["target_execution"]["missing_responses"]
        + sum(row["missing_responses"] for row in recovered_rows.values()),
        "accounting_scope": ("base_completion_plus_recovery_completion_bound_level1_records"),
    }
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gate5-amendment", type=Path, required=True)
    result.add_argument("--base-completion", type=Path, required=True)
    result.add_argument("--runner-root", type=Path, required=True)
    result.add_argument("--control-root", type=Path, required=True)
    result.add_argument("--project-root", type=Path, required=True)
    result.add_argument("--python", type=Path, required=True)
    result.add_argument("--work-root", type=Path, required=True)
    result.add_argument("--tmux-socket", default="default")
    result.add_argument("--tmux-session", required=True)
    result.add_argument("--wait-seconds", type=int, default=86_400)
    result.add_argument("--poll-seconds", type=int, default=60)
    result.add_argument("--max-lane-launches", type=int, default=1)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            gate5_path=args.gate5_amendment,
            base_completion=args.base_completion,
            runner_root=args.runner_root,
            control_root=args.control_root,
            project_root=args.project_root,
            python=args.python,
            work_root=args.work_root,
            tmux_socket=args.tmux_socket,
            tmux_session=args.tmux_session,
            wait_seconds=args.wait_seconds,
            poll_seconds=args.poll_seconds,
            max_lane_launches=args.max_lane_launches,
        )
    except (
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TimeoutError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"current Ollama Phase 6 recovery failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
