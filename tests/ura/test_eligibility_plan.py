from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.suite_summary import _load_eligibility_plan, build_suite_summary
from ura.converters.synth import synth_corpus
from ura.eligibility import (
    build_eligibility_plan,
    eligibility_plan_id,
    summarize_eligibility_plans,
    validate_eligibility_plan,
)


class _Target:
    def __init__(self, name: str, modalities: tuple[str, ...]) -> None:
        self.name = name
        self.modality_support = modalities


def _plan() -> dict:
    return build_eligibility_plan(
        requested_targets=["vision-request", "text-request"],
        targets={
            "vision-request": _Target("vision-resolved", ("text", "image")),
            "text-request": _Target("text-resolved", ("text",)),
        },
        corpora={"logical-synth-arm": synth_corpus(2)},
        attackers=["replay"],
        bindings={"source_instances_sha256": "a" * 64},
        dry_run=True,
    )


def test_plan_retains_incompatible_target_source_modality_as_na() -> None:
    plan = _plan()

    assert plan["schema"] == "ura-eligibility-plan/1"
    assert plan["counts"] == {
        "cells_total": 4,
        "compatible_if_isolated": 3,
        "not_applicable": 1,
        "by_disposition": {
            "compatible_common_proxy_if_isolated": 2,
            "compatible_if_isolated_but_whole_arm_blocked": 1,
            "transport_blocked": 1,
        },
    }
    assert plan["execution"]["request_status"] == (
        "pending_whole_request_preflight"
    )
    assert plan["execution"]["units_blocked"] == 1
    blocked = [item for item in plan["items"] if item["status"] == "N/A"]
    assert len(blocked) == 1
    assert blocked[0]["requested_target_spec"] == "text-request"
    assert blocked[0]["logical_source_arm"] == "logical-synth-arm"
    assert blocked[0]["exact_modality_combination"] == ["text", "image"]
    assert blocked[0]["effective_modality"] is None
    assert blocked[0]["failed_gates"] == [{
        "gate": "target_transport",
        "reason": "target does not declare exact input combination text+image",
    }]
    assert validate_eligibility_plan(plan) is plan


def test_plan_records_source_evaluator_and_attacker_gates() -> None:
    point = synth_corpus(1)[0].model_copy(update={
        "source": "rjudge",
        "meta": {
            "common_metrics_eligible": False,
            "required_metric": "rjudge_safety_judgment",
            "source_metric_attackers": ["replay"],
            "execution_mode": "recorded_trace_classification",
        },
    })
    unavailable = point.model_copy(update={
        "id": "missing-evaluator",
        "source": "agentharm",
        "meta": {
            "common_metrics_eligible": False,
            "required_metric": "official_agentharm_tool_grading",
            "source_metric_runtime": "upstream_agentharm_environment",
            "source_metric_attackers": ["replay"],
            "execution_mode": "prompt_and_tool_requirements_only",
        },
    })

    plan = build_eligibility_plan(
        requested_targets=["target-request"],
        targets={"target-request": _Target("target-resolved", ("text",))},
        corpora={"classification": [point], "conversion-only": [unavailable]},
        attackers=["replay", "crescendo"],
    )

    by_key = {
        (item["logical_source_arm"], item["attacker"]): item
        for item in plan["items"]
    }
    assert by_key[("classification", "replay")]["status"] == (
        "compatible_if_isolated"
    )
    assert by_key[("classification", "replay")]["metric_mode"] == (
        "source_specific_evaluator"
    )
    assert by_key[("classification", "crescendo")]["disposition"] == (
        "attack_mode_incompatible"
    )
    conversion_only = by_key[("conversion-only", "replay")]
    assert conversion_only["status"] == "N/A"
    assert conversion_only["disposition"] == (
        "requires_source_native_runtime_or_evaluator"
    )
    assert {gate["gate"] for gate in conversion_only["failed_gates"]} == {
        "source_evaluator"
    }


def test_media_conditioned_common_metric_needs_reference_or_response_scope() -> None:
    physical = synth_corpus(2)[1]
    missing_reference = physical.model_copy(update={
        "meta": {"execution_mode": "direct_prompt"}
    })
    response_only = physical.model_copy(update={
        "id": "response-only-physical",
        "meta": {
            "execution_mode": "direct_prompt",
            "automated_metric_scope": "response_only",
        },
    })

    plan = build_eligibility_plan(
        requested_targets=["vision-request"],
        targets={
            "vision-request": _Target("vision-resolved", ("text", "image"))
        },
        corpora={
            "missing-reference": [missing_reference],
            "response-only": [response_only],
        },
        attackers=["replay"],
    )
    by_arm = {item["logical_source_arm"]: item for item in plan["items"]}

    blocked = by_arm["missing-reference"]
    assert blocked["status"] == "N/A"
    assert blocked["automated_metric_scope"] == "media_conditioned"
    assert blocked["automated_grading_mode"] == "unavailable"
    assert blocked["disposition"] == (
        "requires_substantive_automated_evaluator_or_reference"
    )
    assert blocked["failed_gates"][0]["gate"] == "automated_common_evaluator"

    admitted = by_arm["response-only"]
    assert admitted["status"] == "compatible_if_isolated"
    assert admitted["automated_metric_scope"] == "response_only"
    assert admitted["automated_grading_mode"] == "response_only_text_judge_proxy"


def test_suite_summary_validates_and_reports_eligibility_only(
    tmp_path: Path,
) -> None:
    path = tmp_path / "plan.eligibility.json"
    path.write_text(json.dumps(_plan()), encoding="utf-8")

    loaded = _load_eligibility_plan(path)
    summary = build_suite_summary([], [], eligibility_plans=[loaded])

    assert summary["runner"]["n_completed_cells"] == 0
    assert summary["native"]["n_native_runs"] == 0
    assert summary["eligibility"]["n_plans"] == 1
    assert summary["eligibility"]["compatible_if_isolated"] == 3
    assert summary["eligibility"]["not_applicable"] == 1
    assert summary["eligibility"]["plans"][0]["canonical_locator"] == path.name
    assert "not an independently runnable cell" in summary["eligibility"][
        "interpretation"
    ]


def test_eligibility_loader_rejects_tampered_self_identity(tmp_path: Path) -> None:
    plan = _plan()
    plan["items"][0]["status"] = "N/A"
    path = tmp_path / "tampered.eligibility.json"
    path.write_text(json.dumps(plan), encoding="utf-8")

    with pytest.raises(ValueError, match="plan_id/content mismatch"):
        _load_eligibility_plan(path)


def _refresh_plan_id(plan: dict) -> None:
    body = {key: value for key, value in plan.items() if key != "plan_id"}
    plan["plan_id"] = eligibility_plan_id(body)


def test_validator_recomputes_cell_ids_after_outer_hash_is_refreshed() -> None:
    plan = _plan()
    plan["items"][0]["cell_id"] = "eligibility-cell-" + "0" * 24
    _refresh_plan_id(plan)

    with pytest.raises(ValueError, match="cell_id/content mismatch"):
        validate_eligibility_plan(plan)


def test_validator_requires_complete_requested_cross_product() -> None:
    plan = _plan()
    removed = [
        item for item in plan["items"]
        if item["requested_target_spec"] == "text-request"
    ]
    plan["items"] = [
        item for item in plan["items"]
        if item["requested_target_spec"] != "text-request"
    ]
    plan["counts"]["cells_total"] -= len(removed)
    plan["counts"]["compatible_if_isolated"] -= sum(
        item["status"] == "compatible_if_isolated" for item in removed
    )
    plan["counts"]["not_applicable"] -= sum(
        item["status"] == "N/A" for item in removed
    )
    for item in removed:
        disposition = item["disposition"]
        plan["counts"]["by_disposition"][disposition] -= 1
        if plan["counts"]["by_disposition"][disposition] == 0:
            del plan["counts"]["by_disposition"][disposition]
    _refresh_plan_id(plan)

    with pytest.raises(ValueError, match="does not cover.*cross-product"):
        validate_eligibility_plan(plan)


def test_suite_rejects_same_request_binding_and_overlapping_cells() -> None:
    first = _plan()
    same_request_later_phase = build_eligibility_plan(
        requested_targets=["vision-request", "text-request"],
        targets={
            "vision-request": _Target("vision-resolved", ("text", "image")),
            "text-request": _Target("text-resolved", ("text",)),
        },
        corpora={"logical-synth-arm": synth_corpus(2)},
        attackers=["replay"],
        bindings={"source_instances_sha256": "a" * 64},
        global_failures=[{"gate": "late_preflight", "reason": "fixture"}],
        dry_run=True,
    )
    with pytest.raises(ValueError, match="share request binding"):
        summarize_eligibility_plans([
            (first, "1" * 64, "first.json"),
            (same_request_later_phase, "2" * 64, "second.json"),
        ])

    different_binding_same_cells = build_eligibility_plan(
        requested_targets=["vision-request", "text-request"],
        targets={
            "vision-request": _Target("vision-resolved", ("text", "image")),
            "text-request": _Target("text-resolved", ("text",)),
        },
        corpora={"logical-synth-arm": synth_corpus(2)},
        attackers=["replay"],
        bindings={"source_instances_sha256": "b" * 64},
        dry_run=True,
    )
    with pytest.raises(ValueError, match="share cell"):
        summarize_eligibility_plans([
            (first, "1" * 64, "first.json"),
            (different_binding_same_cells, "3" * 64, "third.json"),
        ])
