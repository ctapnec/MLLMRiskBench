from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.local_campaign.ollama_static_terminal import (
    ACCOUNTING_SEMANTICS,
    DISPOSITION,
    ERROR_PREFIX,
    OLLAMA_STATIC_TERMINAL_LANES,
    OLLAMA_STATIC_TERMINAL_VALUE,
    REASON,
    REASON_CODE,
    STATIC_LANE_MODELS,
    classify,
    descriptor_for,
    inventory_counts,
    main,
    validate_gate5_terminal_rows,
    validate_terminal_artifact,
    validate_terminal_rows,
)


def _runner_case(
    tmp_path: Path,
    *,
    message: str,
    target_calls: int = 1,
) -> tuple[str, Path, Path, Path]:
    lane = OLLAMA_STATIC_TERMINAL_LANES[0]
    _label, spec, digest = STATIC_LANE_MODELS[lane]
    runtime = f"{spec}@sha256:{digest}"
    diagnostic = tmp_path / "run"
    control = tmp_path / "control"
    diagnostic.mkdir()
    control.mkdir()
    grid_id = "grid-" + "a" * 24
    error = {
        "status": "error",
        "exception_type": "ExternalCallFailure",
        "phase": "cell_execution_or_validation",
        "execution_started": True,
        "corpus": "airbench_full",
        "attacker": "replay",
        "target": runtime,
        "model_spec": runtime,
        "message": ERROR_PREFIX + message,
        "grid_id": grid_id,
        "completed_attempts": target_calls - 1,
        "call_audit": {},
        "call_budget_snapshot": {
            "accounting_semantics": ACCOUNTING_SEMANTICS,
            "budget_id": grid_id,
            "max_target_calls": 15,
            "max_judge_calls": None,
            "max_http_attempts": None,
            "target_calls": target_calls,
            "judge_calls": 0,
            "http_attempts": 0,
        },
    }
    (diagnostic / f"{grid_id}.error.json").write_text(
        json.dumps(error, sort_keys=True) + "\n", encoding="utf-8"
    )
    log = control / f"{lane}.canary.log"
    log.write_text(ERROR_PREFIX + message + "\n", encoding="utf-8")
    output = control / f"{lane}.target-runtime-terminal.json"
    return lane, diagnostic, log, output


@pytest.mark.parametrize(
    ("message", "kind", "finish_reason"),
    (
        (
            "Ollama response is truncated or incomplete: 'length'",
            "finish_reason",
            "length",
        ),
        ("Ollama returned an empty completion", "empty_completion", "stop"),
    ),
)
def test_exact_nonjudgeable_model_outputs_become_typed_lane_outcomes(
    tmp_path: Path, message: str, kind: str, finish_reason: str
) -> None:
    lane, diagnostic, log, output = _runner_case(
        tmp_path, message=message, target_calls=2
    )

    value = classify(
        output=output,
        runner_log=log,
        diagnostic_root=diagnostic,
        lane=lane,
        runner_returncode=1,
    )

    assert value["disposition"] == DISPOSITION
    assert value["reason_code"] == REASON_CODE
    detail = value["classification"]["diagnostic_detail"]
    assert detail["kind"] == kind
    assert detail["finish_reason"] == finish_reason
    assert value["call_accounting"]["target_calls"] == 2
    assert value["call_accounting"]["completed_attempts"] == 1
    assert validate_terminal_artifact(
        output, expected_lane=lane, expected_diagnostic_root=diagnostic
    ) == value


def test_classifier_cli_reports_attempted_and_successful_target_counts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lane, diagnostic, log, output = _runner_case(
        tmp_path,
        message="Ollama returned an empty completion",
        target_calls=9,
    )

    assert main([
        "classify",
        "--output", str(output),
        "--runner-log", str(log),
        "--diagnostic-root", str(diagnostic),
        "--lane", lane,
        "--runner-returncode", "1",
    ]) == 0

    fields = capsys.readouterr().out.rstrip("\n").split("\t")
    assert fields[-2:] == ["9", "8"]
    assert len(fields) == 6


@pytest.mark.parametrize(
    "message",
    (
        "Ollama returned unexpected model identity 'other'",
        "Ollama omitted valid prompt/completion token provenance",
        "Ollama returned an invalid loaded-model inventory",
        "could not obtain Ollama generation within the deadline",
        "Ollama response is truncated or incomplete: 'unknown'",
        "Ollama response is not an object",
        "Ollama response did not declare done=true",
        "Ollama response omitted its message object",
        "Ollama returned a non-assistant message",
    ),
)
def test_protocol_and_provenance_failures_are_not_model_output_outcomes(
    tmp_path: Path, message: str
) -> None:
    lane, diagnostic, log, output = _runner_case(tmp_path, message=message)

    with pytest.raises(ValueError, match="not a model-output terminal"):
        classify(
            output=output,
            runner_log=log,
            diagnostic_root=diagnostic,
            lane=lane,
            runner_returncode=1,
        )
    assert not output.exists()


def test_static_terminal_profiles_are_per_lane_and_defense_orthogonal() -> None:
    lanes = list(OLLAMA_STATIC_TERMINAL_LANES)
    for count in range(4):
        assert inventory_counts(lanes[:count], []) == {
            "runnable": 22 - count,
            "typed_terminal": 24 + count,
            "target_runtime_terminal": 4 + count,
            "conditional_na_lanes": [],
        }
        assert inventory_counts(lanes[:count], ["defense-local"]) == {
            "runnable": 21 - count,
            "typed_terminal": 25 + count,
            "target_runtime_terminal": 4 + count,
            "conditional_na_lanes": ["defense-local"],
        }

    with pytest.raises(ValueError, match="duplicate"):
        inventory_counts([lanes[0], lanes[0]], [])
    with pytest.raises(ValueError, match="conditional"):
        inventory_counts([], ["forged"])


def test_status_and_gate5_consumers_accept_only_the_exact_terminal_subset(
    tmp_path: Path,
) -> None:
    terminal_lane, diagnostic, log, output = _runner_case(
        tmp_path,
        message="Ollama response is truncated or incomplete: 'length'",
    )
    artifact = classify(
        output=output,
        runner_log=log,
        diagnostic_root=diagnostic,
        lane=terminal_lane,
        runner_returncode=1,
    )
    status_rows: list[dict[str, object]] = []
    gate5_rows: list[dict[str, object]] = []
    terminal_value = dict(OLLAMA_STATIC_TERMINAL_VALUE)
    for lane in OLLAMA_STATIC_TERMINAL_LANES:
        label, spec, digest = STATIC_LANE_MODELS[lane]
        is_terminal = lane == terminal_lane
        status_rows.append(
            {
                "lane": lane,
                "model_label": label,
                "requested_spec": spec,
                "digest": digest,
                "metric_mode": "static",
                "diagnostic_root": str(diagnostic),
                "disposition": DISPOSITION if is_terminal else "runnable",
                "reason_code": REASON_CODE if is_terminal else "",
                "reason": REASON if is_terminal else "",
                "target_runtime_terminal_artifact": str(output) if is_terminal else "",
            }
        )
        gate5_rows.append(
            {
                "lane_id": lane,
                "family": "ollama",
                "disposition": DISPOSITION if is_terminal else "runnable",
                "reason_code": REASON_CODE if is_terminal else None,
                "reason": REASON if is_terminal else None,
                "projection": {"status": "passed", "value": {"fixture": lane}},
                "canary": (
                    {
                        **terminal_value,
                        "target_runtime_terminal_artifact": descriptor_for(output),
                        "call_accounting": artifact["call_accounting"],
                    }
                    if is_terminal
                    else {"status": "passed"}
                ),
                "final_preflight": terminal_value if is_terminal else {"status": "passed"},
                "approved_caps": terminal_value if is_terminal else {"status": "approved"},
            }
        )

    assert validate_terminal_rows(status_rows, label="test") == (terminal_lane,)
    assert validate_gate5_terminal_rows(gate5_rows, label="test") == (terminal_lane,)

    gate5_rows[0]["reason_code"] = "forged"
    with pytest.raises(ValueError, match="terminal identity changed"):
        validate_gate5_terminal_rows(gate5_rows, label="test")
