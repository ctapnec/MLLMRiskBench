from __future__ import annotations

import copy

import pytest

from experiments.local_campaign.execution_accounting import (
    POPULATION_PLAN,
    build_execution_accounting,
    validate_execution_accounting,
)


def _cell(
    *,
    model: str,
    corpus: str,
    source: str,
    attempt_rows: list[tuple[str, str, int, str | None, int, str]],
) -> dict[str, object]:
    attempts: dict[str, object] = {}
    responses: dict[str, object] = {}
    judgments: list[dict[str, object]] = []
    for attempt_id, datapoint_id, turn, status, retries, judge in attempt_rows:
        attempts[attempt_id] = {
            "datapoint_id": datapoint_id,
            "seed": 0,
            "turn_index": turn,
        }
        raw: dict[str, object] = {}
        if status is not None:
            raw["model_stability_status"] = status
            raw["model_stability_retry_count"] = retries
        responses[attempt_id] = {"raw": raw}
        judgments.append(
            {
                "attempt_id": attempt_id,
                "judge": judge,
                "label": "not_applicable" if status == "failed_output" else "safe",
                "raw": {
                    "source": source,
                    "effective_modality": "image" if "gptgeo" in corpus else "text",
                    "risk_category": "safety",
                    "expected_behavior": "refuse",
                    "guardrail_queried": judge == "guardrail",
                },
            }
        )
    return {
        "model": model,
        "manifest": {
            "config": {
                "run": {
                    "project_revision": {"sha256": "a" * 64},
                    "corpus": corpus,
                    "attacker": "replay",
                },
                "components": {
                    "target": {
                        "name": model,
                        "num_ctx": 65_536,
                        "num_predict": -1,
                    }
                },
            }
        },
        "attempts": attempts,
        "responses": responses,
        "judgments": judgments,
    }


def _report() -> dict[str, object]:
    return build_execution_accounting(
        [
            _cell(
                model="ollama:deepseek-r1:32b@sha256:" + "b" * 64,
                corpus="airbench_full",
                source="airbench",
                attempt_rows=[
                    ("a0", "airbench:1", 0, "recovered_after_retry", 1, "guardrail"),
                    ("a1", "airbench:1", 1, "failed_output", 1, "guardrail"),
                ],
            ),
            _cell(
                model="vllm:Qwen/Qwen3-VL-8B-Instruct@sha256:" + "c" * 64,
                corpus="rjudge_release",
                source="rjudge",
                attempt_rows=[("b0", "rjudge:1", 0, None, 0, "rules")],
            ),
        ],
        generated_from={"runner_view": {"sha256": "d" * 64}},
    )


def test_execution_accounting_separates_inputs_calls_outputs_and_judges() -> None:
    report = _report()

    assert report["population_plan"] == POPULATION_PLAN
    assert report["status"] == "complete_with_missing_outputs"
    assert report["totals"] == {
        "selected_inputs": 2,
        "initial_target_calls": 3,
        "answer_retry_calls": 2,
        "successful_output_generations": 2,
        "retained_missing_outputs": 1,
        "local_rules_decisions": 0,
        "local_guardrail_calls": 2,
        "source_authoritative_decisions": 1,
        "common_local_judgments": 2,
        "haiku_judge_calls": 0,
    }
    common = next(row for row in report["rows"] if row["logical_arm"] == "airbench_full")
    assert common["selected_inputs"] == 1
    assert common["initial_target_calls"] == 2
    assert common["answer_retry_calls"] == 2
    assert common["successful_output_generations"] == 1
    assert common["retained_missing_outputs"] == 1
    assert common["target_provider"] == "ollama"
    source = next(row for row in report["rows"] if row["logical_arm"] == "rjudge_release")
    assert source["target_provider"] == "vllm"
    assert source["source_authoritative_decisions"] == 1
    assert source["common_local_judgments"] == 0


@pytest.mark.parametrize(
    "mutation",
    ("retry_total", "row_output", "haiku", "order", "identity"),
)
def test_execution_accounting_mutations_fail(mutation: str) -> None:
    report = copy.deepcopy(_report())
    if mutation == "retry_total":
        report["totals"]["answer_retry_calls"] += 1
    elif mutation == "row_output":
        report["rows"][0]["successful_output_generations"] += 1
    elif mutation == "haiku":
        report["rows"][0]["haiku_judge_calls"] = 1
    elif mutation == "order":
        report["row_order"].reverse()
    else:
        report["accounting_id"] = "execution-accounting-" + "0" * 24

    with pytest.raises(ValueError):
        validate_execution_accounting(report)
