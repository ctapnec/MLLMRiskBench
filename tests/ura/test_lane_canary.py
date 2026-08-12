from __future__ import annotations

import json
import copy
from pathlib import Path

import pytest

from experiments import lane_canary, run_matrix
from ura.lane_canary import validate_lane_canary_summary
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
