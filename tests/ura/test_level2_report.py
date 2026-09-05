"""Level-2 exporter contracts: exact keys, no pooling, native separation."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import experiments.run_matrix as run_matrix
from experiments import level2_report
from experiments import live_attestation as live_attestation_cli
from experiments.native_import import CONFIG_SCHEMA, main as native_main
from ura.data_models import DialogTurn, Response
from ura.approximate_metrics import (
    aggregate_approximate_provenance,
    build_approximate_caller_binding,
    build_approximate_decision,
    build_approximate_trail_stage,
    supplementary_metric_policy,
)
from ura.data_models import DataPoint, Judgment, RiskCategory
from ura.targets.base import BaseTarget
from ura.targets.local import _tree_sha256


def test_level2_builder_rejects_cross_root_alias_arms_before_estimation() -> None:
    def cell(spec: str, provider: str) -> dict:
        return {
            "manifest": {"config": {"run": {
                "model_spec": spec,
                "corpus": "fixture-source",
                "attacker": "replay",
                "resolved_quantization": "none",
            }}},
            "realized_identities": {"target": {"snapshot": {
                "provider": provider,
                "resolved_model": "served-model",
            }}},
        }

    with pytest.raises(ValueError, match="distinct figure target arms"):
        level2_report.build_level2_report([
            cell("zhipu:alias-a", "zhipu"),
            cell("glm:alias-b", "glm"),
        ], [])


def test_level2_coverage_marks_retained_model_nonresponse_as_missing() -> None:
    cell = {
        "model": "fixture-model",
        "manifest": {"config": {}},
        "responses": {},
        "judgments": [{
            "attempt_id": "missing-response",
            "label": "not_applicable",
            "score": 0.0,
            "raw": {
                "source": "fixture-source",
                "risk_category": "legality",
                "effective_modality": "text",
                "planning_expected_behavior": "refuse",
                "attacker": "replay",
                "source_policy_id": "unversioned",
                "source_policy_version": "unversioned",
                "policy_evaluable_turn": True,
                "common_metrics_eligible": True,
                "policy_evaluation_status": "model_nonresponse",
                "planning_execution_mode": "static",
            },
        }],
    }

    coverage = next(iter(level2_report._coverage_by_bucket(cell).values()))

    assert coverage["source_judgments_completed"] == 1
    assert coverage["source_judgments_abstained"] == 1
    assert coverage["source_judgments_missing_responses"] == 1


class _StableLocalTarget(BaseTarget):
    modality_support = ("text",)
    max_transport_attempts_per_call = 0

    def __init__(self, digest: str) -> None:
        self.model = "local-checkpoint"
        self.revision = None
        self.model_digest = digest
        self.name = f"vllm:local-checkpoint@sha256:{digest}"

    def generate(self, dialog, *, seed=None):
        return Response(
            attempt_id="target-placeholder",
            target=self.name,
            output_turns=[
                DialogTurn(role="assistant", content="I cannot help."),
            ],
            raw={
                "sampling_control": "seeded",
                "backend": "vllm",
                "model": "local-checkpoint",
                "resolved_model": "local-checkpoint",
                "model_revision": None,
                "model_digest": self.model_digest,
            },
        )


def _finite_budget_args() -> list[str]:
    return [
        "--max-total-target-calls", "100000",
        "--max-total-judge-calls", "100000",
        "--max-total-http-attempts", "100000",
        "--deadline-seconds", "3600",
    ]


def _measured_cohort(
    tmp_path: Path,
    monkeypatch,
    project_revision_args,
    name: str,
    extra_args: list[str] | None = None,
) -> Path:
    checkpoint = (tmp_path / "fixture-local-model").resolve()
    checkpoint.mkdir(exist_ok=True)
    config_file = checkpoint / "config.json"
    if not config_file.exists():
        config_file.write_text('{"model_type":"fixture"}\n', encoding="utf-8")
    digest = _tree_sha256(checkpoint)
    requested_spec = f"vllm:{checkpoint}"
    local_config_path = tmp_path / "local-targets.json"
    if not local_config_path.exists():
        local_config_path.write_text(json.dumps({requested_spec: {
            "digest": digest,
            "modalities": ["text"],
            "tensor_parallel_size": 1,
            "gpu_memory_utilization": 0.5,
            "max_tokens": 64,
        }}), encoding="utf-8")
    monkeypatch.setattr(
        run_matrix, "build_target", lambda *_a, **_kw: _StableLocalTarget(digest)
    )
    common = [
        "--local", requested_spec,
        "--local-config", str(local_config_path),
        "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--sample-seed", "0",
        "--max-queries", "1", "--max-turns", "1",
        *_finite_budget_args(),
        *project_revision_args,
    ]
    receipt_path = tmp_path / "live-attestation.json"
    if not receipt_path.exists():
        probe_root = tmp_path / "probe"
        assert run_matrix.main([
            *common,
            "--attestation-probe", "--execution-scope-id", "level2-test-scope",
            "--out", str(probe_root),
        ]) == 0
        assert live_attestation_cli.main([
            "--probe-root", str(probe_root),
            "--execution-scope-id", "level2-test-scope",
            "--out", str(receipt_path),
        ]) == 0
    receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    root = tmp_path / name
    assert run_matrix.main([
        *common,
        *(extra_args or []),
        "--execution-scope-id", "level2-test-scope",
        "--live-attestation", str(receipt_path),
        "--live-attestation-sha256", receipt_sha256,
        "--live-attestation-max-age-hours", "1",
        "--out", str(root),
    ]) == 0
    return root


def _out_args(directory: Path) -> list[str]:
    return [
        "--out-json", str(directory / "l2.json"),
        "--out-csv", str(directory / "l2.csv"),
        "--out-md", str(directory / "l2.md"),
    ]


def test_level2_uses_source_and_proxy_decision_coverage_independently(
    monkeypatch,
) -> None:
    point = DataPoint(
        id="source:one",
        source="fixture-source",
        modalities=["text"],
        dialog_history=[DialogTurn(role="user", content="unsafe request")],
        payload_text="unsafe request",
        risk_category=RiskCategory.AGENTIC_MISUSE,
        expected_behavior="refuse",
        meta={
            "common_metrics_eligible": False,
            "required_metric": "fixture_source_metric",
        },
    )
    response = Response(
        attempt_id="a",
        target="fixture",
        output_turns=[DialogTurn(role="assistant", content="unsafe answer")],
    )
    selected = Judgment(
        attempt_id="a",
        judge="rules",
        label="violation",
        score=1.0,
        raw={
            "confidence": 0.8,
            "cascade_stage": 0,
            "cascade_role": "authoritative",
            "required_metric": "fixture_source_metric",
            "source_evaluation": {
                "family": "fixture_source_metric",
                "implemented": True,
                "valid": False,
            },
            "planning_exact_modality_combination": ["text"],
        },
    )
    policy = supplementary_metric_policy("measured")
    selected = selected.model_copy(update={
        "raw": {
            **selected.raw,
            "approximate_rubric_stage_binding": None,
            **build_approximate_caller_binding(
                datapoint=point,
                response=response,
                declared_target_evidence_class="measured",
                policy=policy,
            ),
        }
    })
    decision = build_approximate_decision(
        datapoint=point,
        response=response,
        selected=selected,
        trail=[selected],
        source_evaluator_implemented=True,
        evidence_class="measured",
        declared_target_evidence_class="measured",
        supplementary_policy=policy,
    )
    raw = {
        **selected.raw,
        "model": "fixture",
        "source": "fixture-source",
        "source_policy_id": "fixture-policy",
        "source_policy_version": "1",
        "source_policy": {"sha256": "a" * 64},
        "risk_category": "agentic_misuse",
        "risk": "agentic_misuse",
        "effective_modality": "text",
        "expected_behavior": "refuse",
        "planning_expected_behavior": "refuse",
        "attacker": "replay",
        "planning_execution_mode": "direct_prompt",
        "policy_evaluable_turn": True,
        "common_metrics_eligible": False,
        "cascade_confident": True,
        "parsed": True,
        "response_conditioned": False,
        "source_evaluation": {
            "family": "fixture_source_metric",
            "implemented": True,
            "valid": False,
        },
        "approximate_security_decision": decision.model_dump(mode="json"),
    }
    judgment = selected.model_copy(update={"raw": raw})
    proxy = aggregate_approximate_provenance(
        [judgment],
        metric="ASR",
        responses=[response],
        supplementary_policy=policy,
    )
    group_by = {
        "model": "fixture",
        "source": "fixture-source",
        "risk": "agentic_misuse",
        "effective_modality": "text",
        "expected_behavior": "refuse",
        "attacker": "replay",
        "source_policy_id": "fixture-policy",
        "source_policy_version": "1",
    }
    cell = {
        "run_id": "run-fixture",
        "model": "fixture",
        "manifest": {
            "judges": ["rules"],
            "seeds": [0],
            "config": {
                "run": {
                    "corpus": "fixture-arm",
                    "model_spec": "api:fixture",
                    "attacker": "replay",
                    "defense": "none",
                },
                "supplementary_metric_policy": policy,
            },
        },
        "responses": {"a": response.model_dump(mode="json")},
        "judgments": [judgment.model_dump(mode="json")],
        "trails": [{
            "attempt_id": "a",
            "stage": 0,
            "judge": "rules",
            "cascade_role": "authoritative",
            "label": "violation",
            "score": 1.0,
            "confidence": 0.8,
            "approximate_stage_binding": build_approximate_trail_stage(
                selected
            ).model_dump(mode="json"),
        }],
        "aggregate_results": [
            {
                "metric": "source_metric_implementation_coverage",
                "value": 1.0,
                "ci_low": 1.0,
                "ci_high": 1.0,
                "n": 1,
                "group_by": group_by,
                "provenance": {"population": "declared_records"},
            },
            {
                "metric": "approximate_ASR",
                "value": 1.0,
                "ci_low": 1.0,
                "ci_high": 1.0,
                "n": 1,
                "group_by": group_by,
                "provenance": {
                    "population": "harmful_static_attempts",
                    "approximate_security": proxy,
                },
            },
        ],
    }

    original_coverage = level2_report._coverage_by_bucket

    def with_proxy_abstention(value: dict) -> dict:
        coverage = original_coverage(value)
        record = next(iter(coverage.values()))
        record["approximate_judgments_completed"] += 1
        record["approximate_judgments_evaluable"] += 1
        record["approximate_judgments_abstained"] += 1
        return coverage

    monkeypatch.setattr(level2_report, "_coverage_by_bucket", with_proxy_abstention)
    rows = {row["metric"]: row for row in level2_report._estimate_rows(cell)}
    source = rows["source_metric_implementation_coverage"]
    approximate = rows["approximate_ASR"]
    assert source["judgments_decided"] == 0
    assert source["judgments_abstained"] == 1
    assert approximate["judgments_completed"] == 2
    assert approximate["judgments_decided"] == 1
    assert approximate["judgments_abstained"] == 1
    assert approximate["approximate_provenance"] == proxy
    assert approximate["warning_tag"] == "warning_approximate"
    assert approximate["approximate_model_query_count"] == 0
    assert approximate["approximate_source_reference_use_count"] == 0

    detached_trail = copy.deepcopy(cell)
    binding = detached_trail["trails"][0]["approximate_stage_binding"]
    binding["judge"] = "detached-rules"
    binding["binding_sha256"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in binding.items() if key != "binding_sha256"},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    detached_trail["trails"][0]["judge"] = "detached-rules"
    with pytest.raises(ValueError, match="completion-hashed retained trail"):
        level2_report._estimate_rows(detached_trail)

    detached = copy.deepcopy(cell)
    detached["aggregate_results"][1]["provenance"]["approximate_security"][
        "n_supporting_decisions"
    ] = 99
    with pytest.raises(ValueError, match="supporting decisions"):
        level2_report._estimate_rows(detached)

    detached_result_n = copy.deepcopy(cell)
    detached_result_n["aggregate_results"][1]["n"] = 99
    with pytest.raises(ValueError, match="metric-specific result-unit count"):
        level2_report._estimate_rows(detached_result_n)

    policy_downgrade = copy.deepcopy(cell)
    policy_downgrade["manifest"]["config"][
        "supplementary_metric_policy"
    ] = supplementary_metric_policy("synthetic")
    with pytest.raises(ValueError, match="manifest supplementary policy"):
        level2_report._estimate_rows(policy_downgrade)

    response_downgrade = copy.deepcopy(cell)
    response_downgrade["responses"]["a"]["raw"]["mock"] = True
    with pytest.raises(ValueError, match="completion-bound Response markers"):
        level2_report._estimate_rows(response_downgrade)


def test_exports_deterministic_compatible_tables(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    root = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-a"
    )
    out = tmp_path / "out"
    assert level2_report.main(["--results", str(root), *_out_args(out)]) == 0

    report = json.loads((out / "l2.json").read_text(encoding="utf-8"))
    assert report["schema_version"] == "ura-level2-report/2"
    assert report["empirical_validity_established"] is False
    assert report["pooling_policy"]["universal_safety_score_defined"] is False
    rows = report["common"]["estimates"]
    assert rows
    expected_target = (
        "vllm:local-checkpoint@sha256:"
        + _tree_sha256((tmp_path / "fixture-local-model").resolve())
    )
    for row in rows:
        assert row["run_id"]
        assert row["ordered_judges"] == ["rules"]
        assert row["resolved_model"] == expected_target
        assert row["source_policy_id"]
        assert row["cross_stratum_pooling_permitted"] is False
        assert row["polarity"] in {
            "higher_adverse", "higher_favorable", "source_defined",
        }
        assert row["judgments_completed"] >= row["judgments_decided"]
        assert row["judgments_missing_responses"] == 0
        assert (
            row["judgments_decided"]
            + row["judgments_abstained"]
            + row["judgments_non_evaluable"]
            == row["judgments_completed"]
        )
    header = (out / "l2.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",")[:4] == [
        "run_id", "corpus_arm", "model_spec", "resolved_model",
    ]
    assert "Level-2 compatible-family tables" in (
        out / "l2.md"
    ).read_text(encoding="utf-8")

    # A second export from identical inputs is byte-identical.
    out2 = tmp_path / "out2"
    assert level2_report.main(["--results", str(root), *_out_args(out2)]) == 0
    for stem in ("l2.json", "l2.csv", "l2.md"):
        assert (out / stem).read_bytes() == (out2 / stem).read_bytes()


def test_distinct_conditions_never_merge(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    root_a = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-a"
    )
    root_b = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-b",
        extra_args=["--sample-seed", "1"],
    )
    out_a = tmp_path / "out-a"
    out_b = tmp_path / "out-b"
    out_ab = tmp_path / "out-ab"
    assert level2_report.main(["--results", str(root_a), *_out_args(out_a)]) == 0
    assert level2_report.main(["--results", str(root_b), *_out_args(out_b)]) == 0
    assert level2_report.main([
        "--results", str(root_a), "--results", str(root_b), *_out_args(out_ab),
    ]) == 0
    rows_a = json.loads((out_a / "l2.json").read_text(encoding="utf-8"))[
        "common"]["estimates"]
    rows_b = json.loads((out_b / "l2.json").read_text(encoding="utf-8"))[
        "common"]["estimates"]
    rows_ab = json.loads((out_ab / "l2.json").read_text(encoding="utf-8"))[
        "common"]["estimates"]
    # Different run conditions stay distinct rows even when their group
    # buckets coincide; nothing merges and nothing is dropped.
    assert len(rows_ab) == len(rows_a) + len(rows_b)
    assert {row["run_id"] for row in rows_ab} == (
        {row["run_id"] for row in rows_a} | {row["run_id"] for row in rows_b}
    )

    # The same completed run supplied twice fails closed as a duplicate.
    out_dup = tmp_path / "out-dup"
    assert level2_report.main([
        "--results", str(root_a), "--results", str(root_a),
        *_out_args(out_dup),
    ]) == 1
    assert not (out_dup / "l2.json").exists()


def test_dry_run_cohort_is_rejected(tmp_path: Path) -> None:
    dry = tmp_path / "dry"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1", "--seeds", "0",
        "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(dry),
    ]) == 0
    out = tmp_path / "rejected"
    assert level2_report.main(["--results", str(dry), *_out_args(out)]) == 1
    assert not (out / "l2.json").exists()
    assert not (out / "l2.csv").exists()


def _easyjailbreak_envelope(tmp_path: Path) -> Path:
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
    envelope = tmp_path / "native-envelope.json"
    assert native_main(["--config", str(config), "--out", str(envelope)]) == 0
    return envelope


def test_native_runs_stay_on_their_own_scales(tmp_path: Path) -> None:
    envelope = _easyjailbreak_envelope(tmp_path)
    out = tmp_path / "native-out"
    assert level2_report.main(["--native", str(envelope), *_out_args(out)]) == 0
    report = json.loads((out / "l2.json").read_text(encoding="utf-8"))
    assert report["common"]["estimates"] == []
    native = report["native"]
    assert native["n_native_runs"] == 1
    assert native["runs"][0]["native_scale_pooling_permitted"] is False
    # Native evidence never enters the common estimate table.
    csv_text = (out / "l2.csv").read_text(encoding="utf-8")
    assert csv_text.count("\n") == 1
    assert "easyjailbreak" not in csv_text
    markdown = (out / "l2.md").read_text(encoding="utf-8")
    assert "Source-native evidence" in markdown
    assert "easyjailbreak" in markdown


def test_outputs_are_create_only(tmp_path: Path) -> None:
    envelope = _easyjailbreak_envelope(tmp_path)
    out = tmp_path / "existing"
    out.mkdir()
    (out / "l2.csv").write_text("occupied", encoding="utf-8")
    assert level2_report.main(["--native", str(envelope), *_out_args(out)]) == 1
    assert (out / "l2.csv").read_text(encoding="utf-8") == "occupied"
    assert not (out / "l2.json").exists()
    assert not (out / "l2.md").exists()


def test_survival_and_refinement_rows_export_distinctly(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    # Live crescendo cells emit kaplan_meier_survival rows whose group_by
    # carries a survival_turn refinement key; each refined row must export as
    # its own line instead of failing the grouping check or merging.
    root = _measured_cohort(
        tmp_path, monkeypatch, project_revision_args, "measured-crescendo",
        extra_args=["--attackers", "crescendo", "--max-turns", "2",
                    "--max-queries", "2"],
    )
    out = tmp_path / "out-crescendo"
    assert level2_report.main(["--results", str(root), *_out_args(out)]) == 0
    report = json.loads((out / "l2.json").read_text(encoding="utf-8"))
    rows = report["common"]["estimates"]
    survival = [r for r in rows if r["metric"] == "kaplan_meier_survival"]
    assert survival, [r["metric"] for r in rows]
    refinements = {r["group_refinements"] for r in survival}
    assert all(ref for ref in refinements)
    assert len(refinements) == len(survival)
    for row in survival:
        assert "survival_turn" in row["group_refinements"]
        assert row["execution_modes"] == ["direct_prompt"]


def test_coarser_grouping_fails_closed() -> None:
    from experiments.level2_report import _estimate_rows

    cell = {
        "run_id": "run-x",
        "model": "model-A",
        "manifest": {"config": {"run": {
            "corpus": "synth", "model_spec": "model-A", "defense": "none",
        }}, "judges": ["rules"], "seeds": [0]},
        "judgments": [],
        "aggregate_results": [{
            "metric": "ASR", "value": 1.0, "n": 1,
            "group_by": {"model": "model-A"},
            "provenance": {},
        }],
    }
    with pytest.raises(ValueError, match="safe default aggregation"):
        _estimate_rows(cell)


def test_markdown_cells_escape_pipes() -> None:
    from experiments.level2_report import _md_cell

    assert _md_cell("a|b") == r"a\|b"
    assert _md_cell("a\nb") == "a b"
    assert _md_cell("back\\slash|x") == r"back\\slash\|x"


def test_attestation_probe_roots_are_rejected_everywhere(
    tmp_path: Path, monkeypatch, project_revision_args,
) -> None:
    import experiments.suite_summary as suite_summary
    from experiments.figure_results import _load_cells
    from experiments.human_audit import _validated_artifacts

    _measured_cohort(tmp_path, monkeypatch, project_revision_args, "measured-a")
    probe_root = tmp_path / "probe"
    assert probe_root.is_dir()

    out = tmp_path / "probe-rejected"
    assert level2_report.main(["--results", str(probe_root), *_out_args(out)]) == 1
    assert not (out / "l2.json").exists()
    assert suite_summary.main([
        "--results", str(probe_root), "--out", str(tmp_path / "suite.json"),
    ]) == 1
    with pytest.raises(ValueError, match="probe is not measured"):
        _load_cells(probe_root)
    with pytest.raises(ValueError, match="probe is not measured"):
        _validated_artifacts(probe_root)


def _classification_cell(official: bool) -> dict:
    raw = {
        "source": "rjudge",
        "risk_category": "agentic_misuse",
        "effective_modality": "text",
        "planning_expected_behavior": "comply_safely",
        "attacker": "replay",
        "source_policy_id": "unversioned",
        "source_policy_version": "unversioned",
        "planning_execution_mode": "harness_response_evaluation",
        "policy_evaluable_turn": True,
        "common_metrics_eligible": False,
        "source_evaluation": {
            "valid": True, "official_evaluator_executed": official,
        },
    }
    return {
        "run_id": "run-cls",
        "model": "model-A",
        "manifest": {
            "config": {"run": {
                "corpus": "rjudge_official", "model_spec": "model-A",
                "defense": "none", "judge_model": None,
                "sample_seed": 0, "limit": 1,
            }},
            "judges": ["rules"], "seeds": [0],
        },
        "judgments": [{"label": "not_applicable", "raw": dict(raw)}],
        "aggregate_results": [{
            "metric": "rjudge_accuracy", "value": 1.0, "n": 1,
            "group_by": {
                "model": "model-A", "source": "rjudge",
                "risk": "agentic_misuse", "effective_modality": "text",
                "expected_behavior": "comply_safely", "attacker": "replay",
                "source_policy_id": "unversioned",
                "source_policy_version": "unversioned",
                "source_metric_family": "rjudge_safety_judgment",
            },
            "provenance": {"ci_method": None, "cluster_unit": None,
                           "n_clusters": 1, "population": "source_items"},
        }],
    }


def test_classification_rows_export_with_source_evaluator_status() -> None:
    from experiments.level2_report import _estimate_rows

    rows = _estimate_rows(_classification_cell(official=True))
    assert len(rows) == 1
    row = rows[0]
    assert row["semantic_family"] == "classification_quality"
    assert row["endpoint_status"] == "official_source_evaluator"
    assert "source_metric_family" in row["group_refinements"]

    rows = _estimate_rows(_classification_cell(official=False))
    assert rows[0]["endpoint_status"] == "source_specific_evaluator"


def test_level2_retains_explicit_sampling_policy() -> None:
    from experiments.level2_report import _csv_text, _estimate_rows
    from ura.sampling import SOURCE_ORDER_CLUSTER_PREFIX

    cell = _classification_cell(official=True)
    legacy_rows = _estimate_rows(cell)
    cell["manifest"]["config"]["run"]["sampling_policy"] = (
        SOURCE_ORDER_CLUSTER_PREFIX
    )
    explicit_rows = _estimate_rows(cell)

    assert "sampling_policy" not in legacy_rows[0]
    assert explicit_rows[0]["sampling_policy"] == SOURCE_ORDER_CLUSTER_PREFIX
    assert "sampling_policy" not in _csv_text(legacy_rows).splitlines()[0]
    assert "sampling_policy" in _csv_text(explicit_rows).splitlines()[0]
    mixed_csv = _csv_text([*legacy_rows, *explicit_rows]).splitlines()
    assert "sampling_policy" in mixed_csv[0]
    assert SOURCE_ORDER_CLUSTER_PREFIX not in mixed_csv[1]
    assert SOURCE_ORDER_CLUSTER_PREFIX in mixed_csv[2]


def test_phantom_aggregate_bucket_fails_closed() -> None:
    from experiments.level2_report import _estimate_rows

    cell = _classification_cell(official=True)
    cell["aggregate_results"][0]["group_by"]["attacker"] = "crescendo"
    with pytest.raises(ValueError, match="no completed judgment support"):
        _estimate_rows(cell)


def test_level2_rejects_detached_proxy_binding_without_proxy_rows() -> None:
    cell = _classification_cell(official=True)
    cell["trails"] = [{"approximate_stage_binding": {"detached": True}}]

    with pytest.raises(ValueError, match="detached approximate trail bindings"):
        level2_report._estimate_rows(cell)
