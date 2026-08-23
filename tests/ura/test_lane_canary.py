from __future__ import annotations

import json
import copy
from pathlib import Path

import pytest

from experiments import lane_canary, run_matrix
from ura.lane_canary import (
    _source_evaluator_role,
    _stage_was_queried,
    validate_lane_canary_summary,
)
from ura.eligibility import canonical_json_sha256


def _produce_synthetic_canary(tmp_path: Path) -> tuple[Path, Path]:
    results = tmp_path / "diagnostic"
    assert run_matrix.main([
        "--diagnostic-canary", "--dry-run",
        "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--seeds", "17",
        "--max-queries", "1", "--max-turns", "1",
        "--out", str(results),
    ]) == 0
    return results, next(results.glob("*.eligibility.json"))


def test_synthetic_canary_to_strict_offline_summary(tmp_path: Path) -> None:
    results, eligibility = _produce_synthetic_canary(tmp_path)
    summaries = tmp_path / "summaries"

    assert lane_canary.main([
        "--results", str(results),
        "--eligibility", str(eligibility),
        "--out-dir", str(summaries),
    ]) == 0

    path = next(summaries.glob("lane-canary-*.lane-canary.json"))
    artifact = validate_lane_canary_summary(
        json.loads(path.read_text(encoding="utf-8"))
    )
    assert path.name == f"{artifact['canary_id']}.lane-canary.json"
    assert artifact["evidence_class"] == "synthetic_offline"
    assert artifact["workload"]["selected_clusters"] == 1
    assert artifact["workload"]["selected_rows"] >= 1
    assert artifact["limitations"]["campaign_authorized"] is False
    assert artifact["limitations"]["empirical_benchmark_evidence"] is False
    assert artifact["latency_observations"]["grid_observation_window"][
        "throughput_derived"
    ] is False
    assert artifact["latency_observations"]["end_to_end_throughput"] == (
        "CANNOT-VERIFY"
    )
    assert artifact["role_reachability"]["execution_roles"]["attacker"][
        "status"
    ] == "exercised"
    assert artifact["role_reachability"]["execution_roles"]["target"][
        "status"
    ] == "exercised"
    assert artifact["role_reachability"]["execution_roles"]["defense"][
        "status"
    ] == "not_applicable"

    # Identical evidence is idempotent and keeps one content-addressed artifact.
    assert lane_canary.main([
        "--results", str(results),
        "--eligibility", str(eligibility),
        "--out-dir", str(summaries),
    ]) == 0
    assert len(list(summaries.glob("lane-canary-*.lane-canary.json"))) == 1


def test_unimplemented_source_diagnostic_is_not_evaluator_execution() -> None:
    diagnostic = {
        "family": "cyberseceval_prompt_injection_judge_question",
        "implemented": False,
        "valid": False,
        "reason": "declared source-specific scorer/runtime is not implemented",
    }
    approximate = {
        "raw": {
            "common_metrics_eligible": False,
            "policy_evaluable_turn": True,
            "source_evaluation": diagnostic,
        }
    }
    assert _source_evaluator_role([approximate]) == {
        "status": "not_exercised",
        "required_records": 1,
        "observed_records": 0,
        "valid_records": 0,
    }

    common_proxy = {
        "raw": {
            "common_metrics_eligible": True,
            "policy_evaluable_turn": True,
            "source_evaluation": diagnostic,
        }
    }
    assert _source_evaluator_role([common_proxy]) == {
        "status": "not_applicable",
        "required_records": 0,
        "observed_records": 0,
        "valid_records": 0,
    }

    common_proxy["raw"]["source_evaluation"] = {
        "family": "diagnostic_only_common_row",
        "implemented": True,
        "valid": True,
    }
    assert _source_evaluator_role([common_proxy]) == {
        "status": "not_applicable",
        "required_records": 0,
        "observed_records": 0,
        "valid_records": 0,
    }

    implemented = {
        "raw": {
            "common_metrics_eligible": False,
            "policy_evaluable_turn": True,
            "source_evaluation": {
                "family": "rjudge_safety_judgment",
                "implemented": True,
                "valid": True,
            },
        }
    }
    assert _source_evaluator_role([implemented]) == {
        "status": "exercised",
        "required_records": 1,
        "observed_records": 1,
        "valid_records": 1,
    }


def test_guardrail_stage_requires_an_actual_model_query() -> None:
    assert _stage_was_queried({"stage_queried": True}, "rules") is True
    assert _stage_was_queried(
        {"stage_queried": True, "guardrail_queried": True}, "guardrail"
    ) is True
    assert _stage_was_queried(
        {"stage_queried": True, "guardrail_queried": False}, "guardrail"
    ) is False
    assert _stage_was_queried(
        {"stage_queried": False, "guardrail_queried": True}, "guardrail"
    ) is False


def test_lane_canary_rejects_tampered_projection_binding(tmp_path: Path) -> None:
    results, eligibility = _produce_synthetic_canary(tmp_path)
    projection = next(results.glob("lane-projection-*.json"))
    value = json.loads(projection.read_text(encoding="utf-8"))
    value["limitations"]["scientific_result_established"] = True
    projection.write_text(json.dumps(value), encoding="utf-8")

    assert lane_canary.main([
        "--results", str(results),
        "--eligibility", str(eligibility),
        "--out-dir", str(tmp_path / "summaries"),
    ]) == 1
    assert not list((tmp_path / "summaries").glob("*.lane-canary.json"))


def _with_content_id(value: dict[str, object]) -> dict[str, object]:
    body = {key: item for key, item in value.items() if key != "canary_id"}
    value["canary_id"] = "lane-canary-" + canonical_json_sha256(body)[:24]
    return value


def test_lane_canary_validator_rejects_nested_semantic_mutations(
    tmp_path: Path,
) -> None:
    results, eligibility = _produce_synthetic_canary(tmp_path)
    summary, _ = lane_canary.summarize_canary(
        results=results, eligibility_path=eligibility, out_dir=tmp_path / "summaries"
    )
    mutations = [
        ("binding", lambda item: item["bindings"]["grid_artifact"].update(bytes=1)),
        ("workload", lambda item: item["workload"].update(selected_rows=999)),
        ("storage", lambda item: item["artifact_storage"].update(core_artifact_bytes=1)),
        (
            "core records",
            lambda item: item["artifact_storage"]["core_by_role"]["attempts"].update(
                records=999
            ),
        ),
        (
            "latency",
            lambda item: item["latency_observations"]["grid_observation_window"].update(
                self_reported_wall_clock_seconds=999
            ),
        ),
        (
            "calls",
            lambda item: item["call_accounting"]["observed_transport_attempts"].update(
                reported_total=999
            ),
        ),
        (
            "roles",
            lambda item: item["role_reachability"]["stages"][0].update(
                queried_records=999
            ),
        ),
        (
            "defense reachability",
            lambda item: item["role_reachability"]["execution_roles"]["defense"].update(
                status="exercised", observed_stage_records={"input": 999}
            ),
        ),
        (
            "extra source identity",
            lambda item: item["condition"]["source_identity"].update(forged=True),
        ),
        (
            "project revision source drift",
            lambda item: item["condition"]["source_identity"][
                "project_revision"
            ].update(driver_source_sha256="9" * 64),
        ),
        (
            "extra latency field",
            lambda item: item["latency_observations"]["target"]["observations"][0].update(
                forged=True
            ),
        ),
    ]
    for _name, mutate in mutations:
        changed = copy.deepcopy(summary)
        mutate(changed)
        _with_content_id(changed)
        with pytest.raises(ValueError):
            validate_lane_canary_summary(changed)


def test_lane_canary_cli_rejects_valid_but_wrong_eligibility_condition(
    tmp_path: Path,
) -> None:
    results, eligibility = _produce_synthetic_canary(tmp_path)
    wrong = json.loads(eligibility.read_text(encoding="utf-8"))
    values = wrong["bindings"]["experiment_conditions"]["values"]
    values["max_turns"] = values["max_turns"] + 1
    wrong["bindings"]["experiment_conditions"]["condition_id"] = (
        "condition-" + canonical_json_sha256(values)[:24]
    )
    body = {key: item for key, item in wrong.items() if key != "plan_id"}
    wrong["plan_id"] = "eligibility-" + canonical_json_sha256(body)[:24]
    wrong_path = tmp_path / f"{wrong['plan_id']}.eligibility.json"
    wrong_path.write_text(json.dumps(wrong), encoding="utf-8")

    assert lane_canary.main([
        "--results", str(results), "--eligibility", str(wrong_path),
        "--out-dir", str(tmp_path / "wrong-summary"),
    ]) == 1


def test_lane_canary_rejects_cell_grid_condition_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, eligibility = _produce_synthetic_canary(tmp_path)
    cells = lane_canary._load_cells(results, _allow_diagnostic_canary=True)
    cells[0]["manifest"]["config"]["run"]["judge_names"] = ["forged"]
    monkeypatch.setattr(lane_canary, "_load_cells", lambda *_a, **_kw: cells)

    with pytest.raises(ValueError, match="exact run-condition mismatch"):
        lane_canary.summarize_canary(
            results=results,
            eligibility_path=eligibility,
            out_dir=tmp_path / "summaries",
        )
