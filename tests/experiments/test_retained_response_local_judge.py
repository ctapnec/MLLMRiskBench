from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from experiments import retained_response_judge_pair as pair_subject
from experiments import retained_response_local_judge as planner
from experiments import retained_response_local_judge_execute as executor
from ura.data_models import Judgment


HEX_A = "a" * 64
HEX_B = "b" * 64
HAIKU = "anthropic:claude-haiku-4-5-20251001"
PRICING = {
    "pricing_config_sha256": HEX_A,
    "pricing_as_of": "2026-09-03",
    "pricing_effective_date": "2026-09-01",
    "pricing_currency": "USD",
    "input_microusd_per_token": 1,
    "output_microusd_per_token": 5,
}


def _candidate(index: int, *, cohort: str) -> dict:
    dimensions = {
        "exact_model": f"{cohort}:model-{index}",
        "framework": "replay",
        "corpus": f"corpus-{index}",
        "source": f"source-{index}",
        "modality": "image" if index % 2 else "text",
        "risk": "jailbreak",
        "expected_behavior": "refuse",
        "project_revision_sha256": HEX_A if cohort == "local" else HEX_B,
        "output_policy_sha256": HEX_B if cohort == "local" else HEX_A,
    }
    row = {
        "sample_key": f"{cohort}-sample-{index}",
        "run_id": f"{cohort}-run-{index}",
        "attempt_id": f"{cohort}-attempt-{index}",
        "datapoint_id": f"datapoint-{index}",
        "source_cluster_id": f"cluster-{index}",
        "requested_seed": 0,
        **dimensions,
        "prompt_sha256": pair_subject._sha({"prompt": index}),
        "response_sha256": pair_subject._sha(
            {"response": cohort, "index": index}
        ),
        "source_policy_id": "policy",
        "source_policy_version": "1",
        "media_references_sha256": pair_subject._sha({"media": index}),
    }
    row["retained_row_sha256"] = pair_subject._sha({"row": row})
    row["stratum_id"] = pair_subject._sha(dimensions)
    row["input_identity_sha256"] = pair_subject._sha(
        {field: row[field] for field in pair_subject._MATCH_IDENTITY_FIELDS}
    )
    return row


def _population(count: int) -> dict[str, int]:
    return {
        "validated_joined_rows": count,
        "eligible_usable_outputs": count,
        "excluded_missing_outputs": 0,
        "excluded_source_authoritative_rows": 0,
    }


def _pair_plan(
    count: int = 2, *, source_descriptor: dict[str, object] | None = None
) -> dict:
    local = [_candidate(index, cohort="local") for index in range(count)]
    hosted = [_candidate(index, cohort="hosted") for index in range(count)]
    return pair_subject.build_pair_plan(
        local,
        hosted,
        local_population_audit=_population(count),
        hosted_population_audit=_population(count),
        source_descriptor=source_descriptor
        or {"file": "source.json", "sha256": HEX_A, "bytes": 3},
        judge_model=HAIKU,
        api_config_sha256=HEX_B,
        pricing_condition=PRICING,
        limit=count,
    )


def _pair_descriptor(pair: dict) -> dict[str, object]:
    payload = pair_subject._canonical(pair)
    return {
        "file": "pair.json",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _resign(plan: dict) -> None:
    material = copy.deepcopy(plan)
    material.pop("plan_id")
    plan["plan_id"] = "retained-local-judge-plan-" + planner._sha(material)[:24]


def test_plan_selects_only_exact_hosted_haiku_pair_members() -> None:
    pair = _pair_plan(2)
    plan, runtime_selection = planner.build_plan(
        pair,
        pair_descriptor=_pair_descriptor(pair),
    )

    assert plan["selection"] == {
        "algorithm": planner.ALGORITHM,
        "cohort": "hosted",
        "selected_pairs": 2,
        "selected_outputs": 2,
        "same_rows_as_haiku": True,
        "outcome_dependent_extension_permitted": False,
    }
    assert [row["pair_id"] for row in plan["selected"]] == [
        row["pair_id"] for row in pair["selected"] if row["cohort"] == "hosted"
    ]
    assert plan["judge_condition"]["target_calls"] == 0
    assert plan["judge_condition"]["provider_calls"] == 0
    assert plan["judge_condition"]["http_attempts"] == 0
    assert plan["judge_condition"]["max_local_guardrail_calls"] == 2
    assert runtime_selection.requirements[0].role == "guardrail_judge"


def test_validator_rejects_a_resigned_change_to_matched_row_claim() -> None:
    pair = _pair_plan(1)
    plan, _ = planner.build_plan(pair, pair_descriptor=_pair_descriptor(pair))
    plan["selection"]["same_rows_as_haiku"] = False
    _resign(plan)

    with pytest.raises(ValueError, match="call or selection contract changed"):
        planner.validate_plan(plan)


class _ClosableStage:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeCascade:
    def __init__(self, *, fail_at: int | None = None) -> None:
        self.calls = 0
        self.fail_at = fail_at
        self.stages = [_ClosableStage(), _ClosableStage()]

    def judge(self, datapoint, response):  # noqa: ANN001, ANN201
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("simulated local judge failure")
        trail = [
            Judgment(
                attempt_id=response.attempt_id,
                judge="rules",
                label="violation",
                score=1.0,
                rationale="rule",
                raw={"confidence": 1.0},
            ),
            Judgment(
                attempt_id=response.attempt_id,
                judge="guardrail",
                label="violation",
                score=1.0,
                rationale="guard",
                raw={
                    "confidence": 0.9,
                    "guardrail_queried": True,
                    "parsed": True,
                    "unsafe": True,
                },
            ),
        ]
        return trail[0], trail


def _prepared(tmp_path: Path, *, count: int = 2) -> dict[str, Any]:
    source = tmp_path / "source.json"
    source.write_text("{}\n", encoding="utf-8")
    source_descriptor = {
        "file": source.name,
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "bytes": len(source.read_bytes()),
    }
    pair = _pair_plan(count, source_descriptor=source_descriptor)
    pair_payload = pair_subject._canonical(pair)
    pair_path = tmp_path / "pair.json"
    pair_path.write_bytes(pair_payload)
    descriptor = {
        "file": pair_path.name,
        "sha256": hashlib.sha256(pair_payload).hexdigest(),
        "bytes": len(pair_payload),
    }
    plan, _ = planner.build_plan(pair, pair_descriptor=descriptor)
    plan_path = tmp_path / "local-plan.json"
    plan_path.write_bytes(pair_subject._canonical(plan))
    items = []
    for row in pair["selected"]:
        items.append((row, f"prompt-{row['pair_id']}", f"response-{row['sample_key']}"))
    return {
        "pair": pair,
        "plan": plan,
        "plan_path": plan_path,
        "pair_plan_path": pair_path,
        "local_runner_view": tmp_path / "local-view",
        "hosted_runner_view": tmp_path / "hosted-view",
        "source_receipt": source,
        "model_acquisition_plan": tmp_path / "acquisition-plan.json",
        "model_acquisition_plan_sha256": HEX_A,
        "model_acquisition_receipt": tmp_path / "receipt.json",
        "model_acquisition_receipt_sha256": HEX_B,
        "model_acquisition_store": tmp_path / "store",
        "out": tmp_path / "out",
        "items": items,
    }


def _runtime_admitter_for(plan: dict):
    def admitter(**kwargs):  # noqa: ANN003, ANN202
        return object(), {
            "schema": "test-runtime",
            "selection_sha256": plan["model_acquisition"]["selection_sha256"],
        }

    return admitter


def _execute(prepared: dict, cascade: _FakeCascade) -> Path:
    keys = (
        "plan_path",
        "pair_plan_path",
        "local_runner_view",
        "hosted_runner_view",
        "source_receipt",
        "model_acquisition_plan",
        "model_acquisition_plan_sha256",
        "model_acquisition_receipt",
        "model_acquisition_receipt_sha256",
        "model_acquisition_store",
        "out",
    )
    return executor.execute(
        **{key: prepared[key] for key in keys},
        runtime_admitter=_runtime_admitter_for(prepared["plan"]),
        cascade_factory=lambda _condition, _runtime: cascade,
        selection_reconciler=lambda *_args: prepared["items"],
    )


def test_execution_scores_only_hosted_rows_and_makes_no_provider_call(
    tmp_path: Path,
) -> None:
    prepared = _prepared(tmp_path)
    cascade = _FakeCascade()

    completion_path = _execute(prepared, cascade)

    completion = json.loads(completion_path.read_text(encoding="utf-8"))
    assert cascade.calls == 2
    assert completion["selected_outputs"] == 2
    assert completion["rules_evaluations"] == 2
    assert completion["local_guardrail_calls"] == 2
    assert completion["target_calls"] == 0
    assert completion["provider_calls"] == 0
    assert completion["http_attempts"] == 0
    assert completion["same_rows_as_haiku"] is True
    artifacts = sorted((prepared["out"] / "judgments").glob("*.json"))
    assert len(artifacts) == 2
    assert all(
        json.loads(path.read_text(encoding="utf-8"))["sample_key"].startswith(
            "hosted-"
        )
        for path in artifacts
    )
    assert all(stage.closed for stage in cascade.stages)

    assert _execute(prepared, cascade) == completion_path
    assert cascade.calls == 2


def test_execution_resumes_after_last_durable_local_judgment(tmp_path: Path) -> None:
    prepared = _prepared(tmp_path, count=2)
    first = _FakeCascade(fail_at=2)

    with pytest.raises(RuntimeError, match="simulated local judge failure"):
        _execute(prepared, first)
    assert first.calls == 2
    assert len(list((prepared["out"] / "judgments").glob("*.json"))) == 1

    second = _FakeCascade()
    _execute(prepared, second)
    assert second.calls == 1
    ledger = json.loads(
        (prepared["out"] / "execution.json").read_text(encoding="utf-8")
    )
    assert ledger["completed_judgments"] == 2
    assert ledger["state"] == "complete"


def test_pair_plan_drift_fails_before_local_runtime_admission(tmp_path: Path) -> None:
    prepared = _prepared(tmp_path, count=1)
    prepared["pair_plan_path"].write_text("{}\n", encoding="utf-8")
    admitted = False

    def admitter(**kwargs):  # noqa: ANN003, ANN202
        nonlocal admitted
        admitted = True
        return _runtime_admitter_for(prepared["plan"])(**kwargs)

    with pytest.raises(ValueError, match="differs from the local judge plan"):
        executor.execute(
            **{
                key: prepared[key]
                for key in (
                    "plan_path",
                    "pair_plan_path",
                    "local_runner_view",
                    "hosted_runner_view",
                    "source_receipt",
                    "model_acquisition_plan",
                    "model_acquisition_plan_sha256",
                    "model_acquisition_receipt",
                    "model_acquisition_receipt_sha256",
                    "model_acquisition_store",
                    "out",
                )
            },
            runtime_admitter=admitter,
            cascade_factory=lambda _condition, _runtime: _FakeCascade(),
            selection_reconciler=lambda *_args: prepared["items"],
        )
    assert admitted is False
