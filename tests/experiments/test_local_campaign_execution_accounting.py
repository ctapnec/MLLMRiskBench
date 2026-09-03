from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

from experiments.local_campaign.execution_accounting import (
    POPULATION_PLAN,
    build_execution_accounting,
    validate_execution_accounting,
)
from experiments.rig_web import RigWebApp, _validate_report_document


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
        "local_guardrail_calls": 1,
        "source_authoritative_decisions": 1,
        "common_local_judgments": 1,
        "haiku_judge_calls": 0,
    }
    common = next(row for row in report["rows"] if row["logical_arm"] == "airbench_full")
    assert common["selected_inputs"] == 1
    assert common["initial_target_calls"] == 2
    assert common["answer_retry_calls"] == 2
    assert common["successful_output_generations"] == 1
    assert common["retained_missing_outputs"] == 1
    assert common["common_local_judgments"] == 1
    assert common["target_provider"] == "ollama"
    source = next(row for row in report["rows"] if row["logical_arm"] == "rjudge_release")
    assert source["target_provider"] == "vllm"
    assert source["source_authoritative_decisions"] == 1
    assert source["common_local_judgments"] == 0


@pytest.mark.parametrize(
    "mutation",
    ("retry_total", "row_output", "judge_overflow", "haiku", "order", "identity"),
)
def test_execution_accounting_mutations_fail(mutation: str) -> None:
    report = copy.deepcopy(_report())
    if mutation == "retry_total":
        report["totals"]["answer_retry_calls"] += 1
    elif mutation == "row_output":
        report["rows"][0]["successful_output_generations"] += 1
    elif mutation == "judge_overflow":
        report["rows"][0]["common_local_judgments"] += 1
    elif mutation == "haiku":
        report["rows"][0]["haiku_judge_calls"] = 1
    elif mutation == "order":
        report["row_order"].reverse()
    else:
        report["accounting_id"] = "execution-accounting-" + "0" * 24

    with pytest.raises(ValueError):
        validate_execution_accounting(report)


def test_execution_accounting_is_validated_and_rendered_as_quantitative_stats() -> None:
    report = _report()
    _validate_report_document("execution_accounting", report)
    app = object.__new__(RigWebApp)

    rendered = app._render_execution_accounting(
        "analysis/campaign-execution-accounting.json",
        report,
    )

    assert "Campaign execution accounting" in rendered
    assert "42,882" in rendered
    assert "8,680 source-authoritative" in rendered
    assert "34,202 common-judge-eligible" in rendered
    assert "Input to output funnel" in rendered
    assert "Calls by local provider" in rendered
    assert "Judge coverage" in rendered
    assert "Local provider / exact model" in rendered
    assert "Initial calls" in rendered
    assert "Missing outputs" in rendered
    assert "Haiku calls" in rendered
    assert "deepseek-r1:32b" in rendered
    assert "rjudge_release" in rendered
    assert (
        "href='/artifacts?path=analysis/campaign-execution-accounting.json'"
        in rendered
    )


def test_campaign_documents_separate_population_from_physical_call_forecast() -> None:
    root = Path(__file__).resolve().parents[2]
    plan = (root / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
        encoding="utf-8"
    )
    runbook = (root / "experiments" / "RUN_AND_RETURN.md").read_text(
        encoding="utf-8"
    )

    for document in (plan, runbook):
        prose = " ".join(document.split())
        assert "46,537 selected input identities" in prose
        assert "49,537 initial target calls" in prose
        assert "2,792 failed-output" in prose
        assert "230 larger-context" in prose
        assert "3,574 hardware-fit" in prose
        assert "59 prepared follow-on" in prose
        assert "889 hardware-fit" in prose
        for label, count in (
            ("Qwen3-VL", "12,506"),
            ("LLaVA-family conditions", "7,736"),
            ("Gemma 4", "11,076"),
            ("Ministral 3", "9,144"),
            ("DeepSeek-R1 Distill", "4,649"),
            ("GPT-OSS", "4,426"),
            ("replay", "44,928"),
            ("Crescendo", "2,800"),
            ("PyRIT", "150"),
            ("DeepTeam", "150"),
            ("h4rm3l", "600"),
            ("Spikee", "600"),
            ("PurpleLlama", "200"),
            ("HarmBench", "50"),
            ("T3MP3ST", "50"),
            ("NanoGCG", "1"),
            ("IDEATOR", "8"),
        ):
            assert re.search(
                rf"{re.escape(label)}(?: \|)? {re.escape(count)}", prose
            )
