from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.local_campaign import vllm_input_recovery_phase6 as recovery


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _failed_prefix_fixture(tmp_path: Path) -> tuple[Path, list[str]]:
    failed_root = tmp_path.resolve() / "engineering" / "failed-controller"
    unit_root = failed_root / "units" / recovery.FAILED_UNIT
    result_root = tmp_path.resolve() / "runner" / recovery.FAILED_UNIT
    result_root.mkdir(parents=True)
    selected_ids = [f"gptgeochat:{index:04d}" for index in range(2020)]
    completed_ids = selected_ids[: recovery.COMPLETED_PREFIX_RECORDS]
    _write_json(
        unit_root / "state.json",
        {
            "schema": "ura-vllm-stability-phase6-unit-state/1",
            "unit_id": recovery.FAILED_UNIT,
            "source_lane": recovery.SOURCE_LANE,
            "corpus": None,
            "selected_records": recovery.SELECTED_RECORDS,
            "target_answer_retries": 1,
            "target_call_cap": recovery.SELECTED_RECORDS * 2,
            "result_root": str(result_root),
        },
    )
    stem = result_root / f"{recovery.CORPUS}--fixture"
    _write_json(
        stem.with_suffix(".manifest.json"),
        {
            "config": {
                "run": {
                    "sampling_audit": {
                        "selected_ids": selected_ids,
                    }
                }
            }
        },
    )
    _write_jsonl(
        stem.with_suffix(".attempts.jsonl"),
        [{"datapoint_id": identifier} for identifier in completed_ids],
    )
    checkpoint_rows = [
        {"attempt_id": f"attempt-{index}"}
        for index in range(recovery.COMPLETED_PREFIX_RECORDS)
    ]
    _write_jsonl(stem.with_suffix(".responses.checkpoint.jsonl"), checkpoint_rows)
    _write_jsonl(stem.with_suffix(".checkpoint.jsonl"), checkpoint_rows)
    return failed_root, selected_ids


def test_gptgeochat_recovery_binds_exact_completed_prefix(tmp_path: Path) -> None:
    failed_root, selected_ids = _failed_prefix_fixture(tmp_path)

    prefix, result_root = recovery.build_recovery_prefix(failed_root)

    completed_ids = selected_ids[: recovery.COMPLETED_PREFIX_RECORDS]
    remaining_ids = selected_ids[recovery.COMPLETED_PREFIX_RECORDS :]
    assert result_root.name == recovery.FAILED_UNIT
    assert recovery.RECOVERY_RECORDS == 1645
    assert prefix == {
        "schema": "ura-recovery-completed-prefix/1",
        "corpus": "gptgeochat_release",
        "completed_prefix_count": 375,
        "selected_datapoint_ids_sha256": recovery._sha256_json(selected_ids),
        "completed_prefix_ids_sha256": recovery._sha256_json(completed_ids),
        "remaining_datapoint_ids_sha256": recovery._sha256_json(remaining_ids),
    }


def test_gptgeochat_recovery_rejects_nonprefix_completed_rows(
    tmp_path: Path,
) -> None:
    failed_root, selected_ids = _failed_prefix_fixture(tmp_path)
    result_root = tmp_path.resolve() / "runner" / recovery.FAILED_UNIT
    attempts = next(result_root.glob(f"{recovery.CORPUS}--*.attempts.jsonl"))
    completed = selected_ids[: recovery.COMPLETED_PREFIX_RECORDS]
    completed[0], completed[1] = completed[1], completed[0]
    _write_jsonl(
        attempts,
        [{"datapoint_id": identifier} for identifier in completed],
    )

    with pytest.raises(ValueError, match="exact prefix"):
        recovery.build_recovery_prefix(failed_root)


def test_input_recovery_contract_is_one_runner_226_missing_only_unit() -> None:
    assert recovery.CODE_VERSION == "ura-runner/2.26"
    assert recovery.RECOVERY_UNIT == (
        "vllm-input-recovery-gptgeochat-qwen3-vl-suffix"
    )
    assert recovery.SELECTED_RECORDS == 2020
    assert recovery.COMPLETED_PREFIX_RECORDS == 375
    assert recovery.RECOVERY_RECORDS == 1645
    assert recovery.CORPUS == "gptgeochat_release"
    parser = recovery.build_parser()
    parsed = parser.parse_args([
        "--expected-commit",
        "a" * 40,
        "--project-root",
        "/project",
        "--python",
        "/project/.venv/bin/python",
        "--work-root",
        "/work",
        "--control-root",
        "/work/runs/engineering/recovery",
        "--project-revision",
        "/work/revision.json",
        "--project-revision-sha256",
        hashlib.sha256(b"revision").hexdigest(),
        "--failed-completion",
        "/work/failed/completion.json",
        "--failed-completion-sha256",
        hashlib.sha256(b"failed").hexdigest(),
        "--execution-scope-id",
        "scope",
        "--tmux-socket",
        "default",
        "--tmux-session",
        "recovery",
    ])
    assert parsed.failed_completion.name == "completion.json"
