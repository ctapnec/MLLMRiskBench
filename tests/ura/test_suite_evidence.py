"""Focused contracts for broad-roster and source-native evidence entrypoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.native_import import CONFIG_SCHEMA, load_native_run, main as native_main
from experiments.suite_summary import _metric_family, build_suite_summary
from ura.adapters._engine_common import ExternalEngineOutputError
from ura.adapters._native_artifacts import (
    NativeEngineCase,
    NativeEngineRun,
    describe_artifact,
    json_sha256,
)


def _easyjailbreak_config(tmp_path: Path) -> tuple[Path, Path]:
    rows = [
        {
            "jailbreak_prompt": "Encoded instruction: {query}",
            "query": "harmful objective",
            "target_responses": ["native target output"],
            "eval_results": [1],
        },
        {
            "jailbreak_prompt": "Nested scenario: {query}",
            "query": "second objective",
            "target_responses": ["native refusal"],
            "eval_results": [False],
        },
    ]
    results = tmp_path / "attack_results.jsonl"
    results.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    config = tmp_path / "import.json"
    config.write_text(json.dumps({
        "schema_version": CONFIG_SCHEMA,
        "engine": "easyjailbreak",
        "adapter": {
            "recipe": "ReNeLLM",
            "attack_model": "provider/attacker",
            "target_model": "provider/target",
            "eval_model": "provider/evaluator",
        },
        "import": {
            "result_jsonl": results.name,
            "upstream_revision": "a" * 40,
            "expected_records": 2,
        },
    }), encoding="utf-8")
    return config, results


def test_native_import_dispatches_real_validator_and_detects_later_tampering(
    tmp_path: Path,
) -> None:
    config, results = _easyjailbreak_config(tmp_path)
    output = tmp_path / "normalized.json"

    assert native_main(["--config", str(config), "--out", str(output)]) == 0
    run, digest = load_native_run(output)
    assert run.engine == "easyjailbreak"
    assert len(run.cases) == 2
    assert len(digest) == 64
    assert run.common_metric_eligible is False

    results.write_text(results.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(
        ExternalEngineOutputError, match="no longer matches|blank record"
    ):
        load_native_run(output)


def test_native_envelope_cannot_fabricate_cases_over_unchanged_sources(
    tmp_path: Path,
) -> None:
    config, _ = _easyjailbreak_config(tmp_path)
    output = tmp_path / "normalized.json"
    assert native_main(["--config", str(config), "--out", str(output)]) == 0

    envelope = json.loads(output.read_text(encoding="utf-8"))
    envelope["run"]["cases"][0]["native_outcome"] = "fabricated"
    envelope["run"]["cases"][0]["native_scores"] = {"success": 999}
    envelope["run"]["native_aggregates"] = {"fabricated_rate": 1.0}
    output.write_text(json.dumps(envelope), encoding="utf-8")

    with pytest.raises(ExternalEngineOutputError, match="fresh import"):
        load_native_run(output)


def test_native_envelope_revalidates_after_tree_relocation(tmp_path: Path) -> None:
    rig_a = tmp_path / "rig-a"
    rig_a.mkdir()
    config, results = _easyjailbreak_config(rig_a)
    output = rig_a / "normalized.json"
    assert native_main(["--config", str(config), "--out", str(output)]) == 0

    rig_b = tmp_path / "rig-b"
    rig_b.mkdir()
    for path in (config, results, output):
        (rig_b / path.name).write_bytes(path.read_bytes())
    rig_a.rename(tmp_path / "rig-a-no-longer-at-recorded-path")

    run, _ = load_native_run(rig_b / "normalized.json")
    assert run.engine == "easyjailbreak"
    assert all(str(rig_b) in artifact.path for artifact in run.source_artifacts)


def _runner_cell() -> dict:
    base_raw = {
        "source": "strongreject",
        "source_policy_id": "strongreject-policy",
        "source_policy_version": "1",
        "source_policy": {"sha256": "b" * 64},
        "modality": "text",
        "effective_modality": "text",
        "risk_category": "jailbreak",
        "expected_behavior": "refuse",
        "common_metrics_eligible": True,
        "response_conditioned": False,
        "replayed_transcript": False,
        "strongreject_evaluated": True,
    }
    return {
        "run_id": "runner-1",
        "model": "provider/model-a",
        "manifest": {"config": {"run": {
            "model_spec": "api:provider:model-a",
            "corpus": "strongreject",
            "attacker": "replay",
            "defense": "none",
        }}},
        "judgments": [
            {"attempt_id": "a1", "label": "violation", "raw": {
                **base_raw, "datapoint_id": "p1", "source_cluster_id": "c1",
            }},
            {"attempt_id": "a2", "label": "refusal", "raw": {
                **base_raw, "datapoint_id": "p2", "source_cluster_id": "c2",
            }},
        ],
        "aggregate_results": [{
            "metric": "ASR",
            "value": 0.5,
            "ci_low": 0.0,
            "ci_high": 1.0,
            "n": 2,
            "group_by": {"model": "provider/model-a"},
            "provenance": {"population": "harmful_static_attempts"},
        }],
    }


def _native_run(tmp_path: Path) -> NativeEngineRun:
    artifact_path = tmp_path / "native.jsonl"
    source_record = {"outcome": "native_pass", "score": 7}
    artifact_path.write_text(json.dumps(source_record) + "\n", encoding="utf-8")
    artifact = describe_artifact(artifact_path, role="native_results", records=1)
    return NativeEngineRun(
        engine="petri",
        native_schema="inspect_petri/v3",
        native_run_id="petri-run",
        upstream_repository="https://example.invalid/inspect_petri",
        upstream_version="3.0.0",
        source_artifacts=[artifact],
        target_models=["provider/model-b"],
        cases=[NativeEngineCase(
            id="petri-case",
            source_run_id="petri-run",
            target_model="provider/model-b",
            attack_method="petri",
            original_input="audit objective",
            target_outputs=["native output"],
            native_outcome="native_scored",
            native_scores={"harmfulness": 7},
            source_artifact_role="native_results",
            source_record="record:1",
            source_record_sha256=json_sha256(source_record),
        )],
        native_aggregates={"harmfulness_mean_native_1_to_10": 7.0},
        measurement_semantics="Petri-native 1-10 judge dimensions",
    )


def test_suite_summary_keeps_common_strata_and_native_scales_separate(
    tmp_path: Path,
) -> None:
    native = _native_run(tmp_path)
    summary = build_suite_summary(
        [_runner_cell()],
        [(native, "c" * 64, "native/petri.json")],
    )

    assert summary["pooling_policy"]["universal_safety_score_defined"] is False
    assert summary["pooling_policy"]["heterogeneous_rate_pooling"] is False
    stratum = summary["runner"]["strata"][0]
    assert stratum["run_id"] == "runner-1"
    assert stratum["source"] == "strongreject"
    assert stratum["source_policy"]["policy_id"] == "strongreject-policy"
    assert stratum["effective_modality"] == "text"
    assert stratum["descriptive_common_endpoint"] == {
        "endpoint": "ASR",
        "n_event_records": 1,
        "n_records": 2,
        "n_source_clusters": 2,
        "value": 0.5,
        "weighting": "equal_source_prompt_intent_cluster",
        "uncertainty": None,
        "qualification": (
            "descriptive exact-stratum equal-cluster rate; no cross-stratum pooling"
        ),
    }
    native_summary = summary["native"]["runs"][0]
    assert native_summary["native_scale_pooling_permitted"] is False
    assert native_summary["native_aggregates"] == {
        "harmfulness_mean_native_1_to_10": 7.0
    }
    assert native_summary["target_strata"][0]["semantic_families"] == ["graded_risk"]


def test_suite_summary_never_pools_distinct_runner_identities() -> None:
    first = _runner_cell()
    second = _runner_cell()
    second["run_id"] = "runner-2"
    for row in second["judgments"]:
        row["attempt_id"] = f"second-{row['attempt_id']}"

    summary = build_suite_summary([first, second], [])

    assert len(summary["runner"]["strata"]) == 2
    assert {row["run_id"] for row in summary["runner"]["strata"]} == {
        "runner-1",
        "runner-2",
    }
    assert all(
        row["descriptive_common_endpoint"]["n_records"] == 2
        for row in summary["runner"]["strata"]
    )


def test_suite_summary_equal_weights_prompt_intent_clusters() -> None:
    cell = _runner_cell()
    duplicate_seed = json.loads(json.dumps(cell["judgments"][0]))
    duplicate_seed["attempt_id"] = "a1-seed-2"
    cell["judgments"].append(duplicate_seed)

    endpoint = build_suite_summary([cell], [])["runner"]["strata"][0][
        "descriptive_common_endpoint"
    ]

    assert endpoint["n_event_records"] == 2
    assert endpoint["n_records"] == 3
    assert endpoint["n_source_clusters"] == 2
    assert endpoint["value"] == 0.5
    assert endpoint["weighting"] == "equal_source_prompt_intent_cluster"


def test_suite_summary_exposes_missing_program_arms_and_native_projects() -> None:
    summary = build_suite_summary(
        [_runner_cell()],
        [],
        expected_source_arms={
            "strongreject": "strongreject",
            "mmsafety_official": "mmsafety",
        },
        source_inventory_artifact={"file": "sources.json", "sha256": "d" * 64},
    )

    coverage = summary["source_native_presence"]
    assert coverage["all_expected_entries_observed"] is False
    assert coverage["program_complete_claimed"] is False
    assert coverage["full_model_lane_coverage_claimed"] is False
    assert coverage["observed_source_arms"] == ["strongreject"]
    assert coverage["missing_source_arms"] == ["mmsafety_official"]
    assert "petri" in coverage["missing_native_projects"]
    assert "mossbench" in coverage["missing_converter_families"]
    assert coverage["source_inventory_artifact"]["sha256"] == "d" * 64


def test_suite_metric_ontology_does_not_overclaim_injection_goal_success() -> None:
    assert _metric_family("ISR") == "unsafe_response_rate"
    assert _metric_family("conversation_strongreject_max") == "graded_risk"
    assert _metric_family("kaplan_meier_survival") == "adaptive_compromise"
