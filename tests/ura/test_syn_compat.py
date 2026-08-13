"""SYN-001/SYN-002 contracts: oracle authority, coverage, hygiene, baselines."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import syn_compat
from ura.compat_bundles import ALL_REASONS, evaluate_comparison
from ura.compat_linear import (
    assert_feature_hygiene,
    featurize,
    split_cases,
)
from ura.compat_synth import (
    coverage_report,
    generate_corpus,
    hand_authored_adversarial,
    templates,
)


def test_generated_corpus_covers_every_reason_and_rules_are_authoritative() -> None:
    cases, metadata = generate_corpus(seed=7, perturbations_per_template=3)
    report = coverage_report(cases)
    assert report["all_critical_reasons_covered"], report["missing_critical_reasons"]
    assert set(report["reason_counts"]) == set(ALL_REASONS)
    # The oracle is the label authority and the generator's intent agrees
    # with it on every generated case.
    for case in cases:
        verdict = evaluate_comparison(case)
        intended = metadata[case.case_id]["intended_label"]
        assert verdict["label"] == intended, (
            metadata[case.case_id]["template"], verdict,
        )
        for reason in metadata[case.case_id]["intended_reasons"]:
            assert reason in verdict["reasons"]
    # Determinism: same seed, same corpus.
    again, _ = generate_corpus(seed=7, perturbations_per_template=3)
    assert [case.case_id for case in cases] == [case.case_id for case in again]


def test_hand_authored_adversarial_cases_are_all_caught_by_rules() -> None:
    entries = hand_authored_adversarial()
    assert len(entries) >= 5
    for case, intended in entries:
        assert evaluate_comparison(case)["label"] == intended, case.case_id


def test_features_exclude_identity_and_split_metadata() -> None:
    cases, _ = generate_corpus(seed=11, perturbations_per_template=1)
    base = cases[0]
    features = featurize(base)
    assert_feature_hygiene(features)
    # Renaming every identifier leaves the feature vector unchanged.
    renamed = base.model_copy(update={
        "case_id": "case-renamed",
        "left": base.left.model_copy(update={
            "bundle_id": "bundle-renamed-left", "run_id": "run-renamed-left",
        }),
        "right": base.right.model_copy(update={
            "bundle_id": "bundle-renamed-right", "run_id": "run-renamed-right",
        }),
    })
    assert featurize(renamed) == features
    with pytest.raises(ValueError, match="leaks"):
        assert_feature_hygiene({"template=static": 1.0})


def test_split_holds_out_whole_templates_and_whole_families() -> None:
    cases, metadata = generate_corpus(seed=3, perturbations_per_template=2)
    split = split_cases(cases, metadata, seed=3)
    train_templates = {
        metadata[case.case_id]["template"] for case in split["train"]
    }
    test_templates = {
        metadata[case.case_id]["template"] for case in split["test"]
    }
    assert train_templates and test_templates
    assert not train_templates & test_templates
    train_benchmarks = {
        metadata[case.case_id]["benchmark_family"] for case in split["train"]
    }
    train_models = {
        metadata[case.case_id]["model_family"] for case in split["train"]
    }
    assert split["held_out_benchmark_family"] not in train_benchmarks
    assert split["held_out_model_family"] not in train_models
    assert split["renderer_axis"] == "not_applicable_no_rendering_used"


def test_cli_end_to_end_is_deterministic_and_scope_bounded(
    tmp_path: Path,
) -> None:
    pytest.importorskip("sklearn")
    cases_path = tmp_path / "cases.jsonl"
    metadata_path = tmp_path / "meta.json"
    assert syn_compat.main([
        "--generate", "--cases", str(cases_path),
        "--metadata", str(metadata_path),
        "--seed", "5", "--perturbations-per-template", "4",
    ]) == 0
    assert syn_compat.main([
        "--check", "--cases", str(cases_path),
        "--out", str(tmp_path / "coverage.json"),
    ]) == 0
    coverage = json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["all_critical_reasons_covered"] is True
    assert coverage["hand_authored_adversarial"]["rules_agreement"] == 1.0

    for name in ("report-a.json", "report-b.json"):
        assert syn_compat.main([
            "--evaluate", "--cases", str(cases_path),
            "--metadata", str(metadata_path),
            "--seed", "5", "--out", str(tmp_path / name),
        ]) == 0
    assert (
        (tmp_path / "report-a.json").read_bytes()
        == (tmp_path / "report-b.json").read_bytes()
    )
    report = json.loads((tmp_path / "report-a.json").read_text(encoding="utf-8"))
    assert report["label_source"] == "deterministic_rules_authoritative"
    assert "no real-world validity" in report["claim_scope"]
    for entry in report["models"].values():
        assert entry["invalid_comparison_recall"] is not None
        assert entry["macro_f1"] is not None
        assert entry["adversarial"]["n_cases"] >= 5
    logistic = report["models"]["logistic_regression"]
    assert "brier_score" in logistic["calibration"]
    assert logistic["ood"]["auroc"] is not None
    assert logistic["selective_prediction"]

    # Outputs are create-only.
    assert syn_compat.main([
        "--generate", "--cases", str(cases_path),
        "--metadata", str(metadata_path), "--seed", "5",
    ]) == 1


def test_check_fails_closed_when_a_reason_is_never_exercised(
    tmp_path: Path,
) -> None:
    cases, _ = generate_corpus(seed=9, perturbations_per_template=2)
    kept = [
        case for case in cases
        if "judge_or_served_model_mismatch"
        not in evaluate_comparison(case)["reasons"]
    ]
    cases_path = tmp_path / "cases.jsonl"
    cases_path.write_text("".join(
        json.dumps(case.model_dump(mode="json", by_alias=True), sort_keys=True)
        + "\n"
        for case in kept
    ), encoding="utf-8")
    assert syn_compat.main([
        "--check", "--cases", str(cases_path),
        "--out", str(tmp_path / "coverage.json"),
    ]) == 1
    report = json.loads((tmp_path / "coverage.json").read_text(encoding="utf-8"))
    assert "judge_or_served_model_mismatch" in report["missing_critical_reasons"]


def test_template_inventory_is_in_the_specified_pilot_range() -> None:
    inventory = templates()
    assert 20 <= len(inventory) <= 50
    names = [entry["template"] for entry in inventory]
    assert len(names) == len(set(names))
