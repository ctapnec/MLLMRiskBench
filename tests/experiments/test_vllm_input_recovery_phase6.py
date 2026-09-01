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
    assert recovery.RUNNER_CODE_VERSION == "ura-runner/2.26"
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


def test_phase7_view_excludes_failed_prefix_and_separates_recovery_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engineering = tmp_path.resolve() / "engineering"
    failed_root = engineering / "failed"
    recovery_root = engineering / "recovery"
    runner_root = tmp_path.resolve() / "runner"
    failed_prefix_root = runner_root / recovery.FAILED_UNIT / failed_root.name
    for path in (failed_root, recovery_root / "inputs", runner_root, failed_prefix_root):
        path.mkdir(parents=True, exist_ok=True)
    failed_completion_path = failed_root / "completion.json"
    _write_json(failed_completion_path, {"fixture": "failed"})
    expected_prefix = {
        "schema": recovery.PREFIX_SCHEMA,
        "corpus": recovery.CORPUS,
        "completed_prefix_count": recovery.COMPLETED_PREFIX_RECORDS,
        "selected_datapoint_ids_sha256": "1" * 64,
        "completed_prefix_ids_sha256": "2" * 64,
        "remaining_datapoint_ids_sha256": "3" * 64,
    }
    recovery_selection = recovery_root / "inputs/gptgeochat-completed-prefix.json"
    _write_json(recovery_selection, expected_prefix)
    recovery_state = recovery_root / "units" / recovery.RECOVERY_UNIT / "state.json"
    _write_json(
        recovery_state,
        {
            "runner_argv": [
                "--recovery-completed-prefix",
                str(recovery_selection),
                "--recovery-completed-prefix-sha256",
                recovery._descriptor(
                    recovery_selection, label="fixture recovery selection"
                )["sha256"],
            ]
        },
    )
    failed_results = {
        unit_id: {"fixture": unit_id}
        for unit_id, _source, _corpus, _selected in recovery.UNIT_LAYOUT
        if unit_id != recovery.FAILED_UNIT
    }
    recovery_result = {
        "state": recovery._descriptor(recovery_state, label="fixture recovery state")
    }
    recovery_completion = {
        "schema": recovery.SCHEMA,
        "status": "complete",
        "controller_exit_code": 0,
        "completed_at_utc": "2026-08-31T08:00:00Z",
        "expected_commit": "a" * 40,
        "runner_code_version": "ura-runner/2.26",
        "target_answer_retries": 1,
        "failed_completion": recovery._descriptor(
            failed_completion_path, label="fixture failed completion"
        ),
        "recovery_selection": recovery._descriptor(
            recovery_selection, label="fixture recovery selection"
        ),
        "unit_order": [recovery.RECOVERY_UNIT],
        "unit_results": {recovery.RECOVERY_UNIT: recovery_result},
        "unit_failures": {},
        "target_execution": {
            "target_attempts": recovery.RECOVERY_RECORDS,
            "successful_target_generations": recovery.RECOVERY_RECORDS,
            "missing_responses": 0,
        },
        "input_compatibility_accounting": (
            "typed_missing_response_without_retry_or_policy_judge"
        ),
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_runner_or_input_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    recovery_completion_path = recovery_root / "completion.json"
    _write_json(recovery_completion_path, recovery_completion)

    monkeypatch.setattr(
        recovery,
        "validate_failed_completion",
        lambda _path, _sha: ({"unit_results": failed_results}, failed_root),
    )
    monkeypatch.setattr(
        recovery,
        "build_recovery_prefix",
        lambda _root: (expected_prefix, failed_prefix_root),
    )

    def metric_result(_result: object, **kwargs: object) -> dict[str, object]:
        physical_unit = str(kwargs["physical_unit"])
        selected = int(kwargs["selected_records"])
        revision = "b" * 64 if physical_unit == recovery.RECOVERY_UNIT else "a" * 64
        return {
            "revision": revision,
            "source": "c" * 64,
            "root": str(runner_root / physical_unit / recovery_root.name),
            "evidence": {"physical_unit_id": physical_unit},
            "grid": {"path": f"/{physical_unit}.grid.json"},
            "eligibility_plan": {"path": f"/{physical_unit}.eligibility.json"},
            "completion_markers": [{"path": f"/{physical_unit}.complete.json"}],
            "successful": selected,
            "missing": 0,
        }

    monkeypatch.setattr(recovery, "_validate_metric_result", metric_result)

    view = recovery.validate_phase7_completion(
        recovery_completion_path,
        runner_root=runner_root,
    )

    assert view["failed_prefix_lifecycle"] == {
        "physical_unit_id": recovery.FAILED_UNIT,
        "durable_rows": 375,
        "result_root": str(failed_prefix_root),
        "included_in_metric_evidence": False,
        "pooling_with_recovery_permitted": False,
    }
    assert Path(view["metric_roots"][recovery.FAILED_UNIT]) == (
        runner_root / recovery.RECOVERY_UNIT / recovery_root.name
    )
    assert view["revision_strata"]["b" * 64] == [recovery.FAILED_UNIT]
    assert view["target_execution"] == {
        "target_attempts": 6824,
        "successful_target_generations": 6824,
        "missing_responses": 0,
    }
