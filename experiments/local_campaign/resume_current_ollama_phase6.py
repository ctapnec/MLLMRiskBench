"""Resume only failed current-Ollama Phase 6 lanes from exact checkpoints.

This is a campaign controller, not a Runner feature. It preserves the original
request, run IDs, completion markers, checkpoints and call-budget ledger. A
successful cell is therefore skipped, and an interrupted cell resumes only the
attempts absent from its durable checkpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Sequence

from experiments.local_campaign.current_ollama_gate5 import (
    _canonical,
    _descriptor,
    validate_amendment,
)
from experiments.local_campaign.current_ollama_phase6 import (
    _arg_value,
    _canonical_dir,
    _create_json,
    _level1_counts,
    _load_state,
    validate_completion,
)


SCHEMA = "ura-current-ollama-phase6-recovery/1"


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
    *, python: Path, argv: Sequence[str], log: Path, timeout: int,
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
    wait_seconds: int,
    poll_seconds: int,
    max_lane_launches: int,
) -> int:
    if wait_seconds < 1 or poll_seconds < 1 or poll_seconds > wait_seconds:
        raise ValueError("wait and poll seconds are invalid")
    if max_lane_launches < 1 or max_lane_launches > 10:
        raise ValueError("max lane launches must be in [1, 10]")
    _wait_for_file(
        base_completion, wait_seconds=wait_seconds, poll_seconds=poll_seconds
    )
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
    if python.is_symlink() or not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("recovery Python is not one executable regular file")
    runner = _canonical_dir(runner_root, label="thesis Runner root")
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("recovery control root must be create-only")
    control_root.mkdir(mode=0o700)
    (control_root / "lanes").mkdir(mode=0o700)

    failed_lanes = [
        lane
        for lane, state in base["terminal_states"].items()
        if state == "failed"
    ]
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
            launches.append({
                "number": number,
                "returncode": returncode,
                "log": _descriptor(log, label=f"{lane} recovery launch {number}"),
            })
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
            row.update({
                "status": "complete",
                "target_attempts": attempted,
                "successful_target_generations": successful,
                "missing_responses": missing,
                "final_completed_responses": after_completed,
                "final_checkpointed_responses": after_checkpointed,
                "level1": _descriptor(
                    lane_root / "level1.json", label=f"{lane} recovery Level 1"
                ),
            })
        else:
            failures += 1
            row.update({
                "target_attempts": None,
                "successful_target_generations": None,
                "missing_responses": None,
                "final_completed_responses": _completed_records(result_root),
                "final_checkpointed_responses": _checkpoint_records(result_root),
            })
        rows.append(row)

    body: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "complete" if failures == 0 else "complete_with_failures",
        "base_phase6": _descriptor(base_completion, label="base Phase 6 completion"),
        "gate5": _descriptor(gate5_path, label="current Ollama Gate 5 amendment"),
        "project_commit": expected_commit,
        "failed_lanes_selected": failed_lanes,
        "recovered_lanes": sum(row["status"] == "complete" for row in rows),
        "remaining_failed_lanes": failures,
        "rows": rows,
        "paid_provider_calls": 0,
    }
    body["recovery_id"] = "current-ollama-recovery-" + hashlib.sha256(
        _canonical(body)
    ).hexdigest()[:24]
    _create_json(control_root / "completion.json", body)
    (control_root / ".exit").write_text(
        "0\n" if failures == 0 else "1\n", encoding="ascii"
    )
    return 0 if failures == 0 else 1


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--gate5-amendment", type=Path, required=True)
    result.add_argument("--base-completion", type=Path, required=True)
    result.add_argument("--runner-root", type=Path, required=True)
    result.add_argument("--control-root", type=Path, required=True)
    result.add_argument("--project-root", type=Path, required=True)
    result.add_argument("--python", type=Path, required=True)
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
