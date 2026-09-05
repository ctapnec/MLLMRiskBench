from __future__ import annotations

import copy
import csv
import importlib.util
import json
from pathlib import Path

import pytest

from experiments import human_audit as subject
from experiments import retained_artifact_reader as reader


@pytest.fixture
def artifact_fixture():
    spec = importlib.util.spec_from_file_location(
        "human_audit_retained_fixtures",
        Path(__file__).with_name("test_postprocessing_regressions.py"),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _partition(joined, *, frame="common", run_id="run-1"):
    result = {"cells": [{"run_id": run_id}], "validator_commit": "a" * 40}
    if frame == "common":
        fingerprint = joined[3]["judge_configuration_binding"]["sha256"]
        result["joined_by_configuration"] = {fingerprint: joined}
    else:
        result["joined"] = joined
    return result


@pytest.mark.parametrize("frame", ["common", "source_task"])
def test_historical_cli_preparation_and_analysis_preserve_original_join(
    tmp_path, monkeypatch, artifact_fixture, frame,
):
    if frame == "common":
        artifact_fixture._write_human_artifacts(tmp_path)
    else:
        artifact_fixture._write_source_task_artifacts(tmp_path)
    joined = subject._joined_artifacts(tmp_path, frame=frame)
    partition = _partition(joined, frame=frame)
    calls = []

    def retained(root, **kwargs):
        assert root == tmp_path
        calls.append(kwargs)
        return [partition]

    monkeypatch.setattr(reader, "read_partitions", retained)
    monkeypatch.setattr(subject, "_joined_artifacts", lambda *a, **k:
                        pytest.fail("current-only join must not consume historical artifacts"))
    options = ["--historical-code-repository", str(tmp_path)]
    if frame == "common":
        options += ["--judge-configuration-sha256",
                    joined[3]["judge_configuration_binding"]["sha256"]]
    sample = tmp_path / "sample.csv"
    prepare = "--prepare" if frame == "common" else "--prepare-source-task"
    assert subject.main([
        "--results", str(tmp_path), prepare, "1", "--output", str(sample),
        "--acknowledge-sensitive-content", *options,
    ]) == 0
    with sample.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert rows and all(row["response"] for row in rows)
    form = tmp_path / "blank-two-rater.csv"
    digest = artifact_fixture._write_blank_two_rater_form(form, list(rows[0]), rows)
    if frame == "common":
        rated = artifact_fixture._rate_human_sample(rows)
    else:
        rated = [{**row, "rater_id": rater, "task_label": "unsafe",
                  "parse_status_label": "clean_single_label", "confidence": "5"}
                 for row in rows for rater in ("r1", "r2")]
    artifact_fixture._write_csv_rows(sample, list(rows[0]), rated)
    report = artifact_fixture._external_audit_report(tmp_path, "historical.json")
    labels = "--labels" if frame == "common" else "--source-task-labels"
    assert subject.main([
        "--results", str(tmp_path), labels, str(sample), "--output", str(report),
        "--prepared-rating-form", str(form), "--prepared-rating-form-sha256", digest,
        "--bootstrap-resamples", "20", *options,
    ]) == 0
    value = json.loads(report.read_text())
    if frame == "common":
        assert set(value["automated_vs_consensus"]) == set(joined[0])
        for judge, predictions in joined[0].items():
            pooled = value["automated_vs_consensus"][judge]["pooled_unweighted"]
            assert (pooled is not None) is bool(predictions)
            if predictions:
                assert sum(pooled["exact_label_confusion_diagnostic"].values()) == len(predictions)
        assert value["audit"]["artifacts"] == joined[3]
        assert value["schema_version"] == "ura-human-audit/1.2"
    else:
        assert value["artifact_audit"] == joined[3]
        assert value["schema_version"] == "ura-source-task-audit/2"
    assert calls == [{"joined": True, "frame": frame, "code_repository": tmp_path,
                      "separate_judge_configurations": frame == "common"}] * 2


def test_historical_join_keeps_predictions_and_missing_configuration_separate(
    tmp_path, monkeypatch, artifact_fixture,
):
    artifact_fixture._write_human_artifacts(tmp_path)
    original = subject._joined_artifacts(tmp_path)
    first = _partition(original)
    missing = list(copy.deepcopy(original))
    original_key = next(iter(missing[1]))
    missing_key = "run-missing|model-A|attempt-1"
    missing[1][missing_key] = {**missing[1].pop(original_key), "run_id": "run-missing"}
    missing[2][missing_key] = {**missing[2].pop(original_key), "run_id": "run-missing"}
    missing[0] = {judge: {} for judge in missing[0]}
    missing[3]["judge_configuration_binding"]["sha256"] = "b" * 64
    missing[3]["judge_configuration_binding"]["defining_fields"] = {"unobserved": True}
    missing[3]["cascade_authoritative_decided"] = 0
    missing[3]["cascade_authoritative_abstained"] = 1
    missing[3]["cascade_authoritative_decision_coverage"] = 0.0
    missing[3]["decided_shadow_predictions"] = 0
    second = _partition(missing, run_id="run-missing")
    monkeypatch.setattr(reader, "read_partitions", lambda *a, **k: [first, second])
    with pytest.raises(ValueError, match="cannot pool judge configurations"):
        subject._audit_artifacts(tmp_path, historical_code_repository=tmp_path)
    selected = subject._audit_artifacts(
        tmp_path, historical_code_repository=tmp_path,
        judge_configuration_sha256=original[3]["judge_configuration_binding"]["sha256"],
    )
    assert selected == original
    selected_missing = subject._audit_artifacts(
        tmp_path, historical_code_repository=tmp_path, judge_configuration_sha256="b" * 64,
    )
    assert selected_missing[0] == missing[0]
    assert set(selected_missing[1]) == {missing_key}
    assert selected_missing[3]["cascade_authoritative_decided"] == 0


def test_historical_audit_merges_only_same_contract_counters(tmp_path, artifact_fixture):
    artifact_fixture._write_human_artifacts(tmp_path)
    audit = subject._joined_artifacts(tmp_path)[3]
    merged = subject._merge_historical_audits([audit, copy.deepcopy(audit)])
    assert merged["attempts"] == 2 * audit["attempts"]
    assert merged["validated_common_eligible_cells"] == 2
    assert merged["judge_configuration_binding"]["validated_cells"] == 2
    assert merged["common_eligible_source_identity_validated"] is True
    assert merged["common_eligible_grid_accounting_modes"] == {"grid_accounted": 2}
    assert merged["cascade_authoritative_decision_coverage"] == audit["cascade_authoritative_decision_coverage"]
    different = copy.deepcopy(audit)
    different["judge_configuration_binding"]["sha256"] = "c" * 64
    with pytest.raises(ValueError, match="cannot pool judge configurations"):
        subject._merge_historical_audits([audit, different])


@pytest.mark.parametrize("mutation", ["duplicate-run", "duplicate-row", "wrong-frame", "orphan-prediction"])
def test_historical_join_rejects_invalid_partition_accounting(
    tmp_path, monkeypatch, artifact_fixture, mutation,
):
    artifact_fixture._write_human_artifacts(tmp_path)
    original = subject._joined_artifacts(tmp_path)
    first = _partition(original)
    changed = copy.deepcopy(first)
    if mutation != "duplicate-run":
        changed["cells"][0]["run_id"] = "other-run"
    partitions = [first, changed]
    if mutation == "wrong-frame":
        original[3]["frame"] = "source_task"
        partitions = [first]
    elif mutation == "orphan-prediction":
        original[0]["rules"]["unjoined"] = "violation"
        partitions = [first]
    monkeypatch.setattr(reader, "read_partitions", lambda *a, **k: partitions)
    with pytest.raises(ValueError, match="duplicate|frame differs|lossy"):
        subject._audit_artifacts(tmp_path, historical_code_repository=tmp_path)


@pytest.mark.parametrize("mode", ["--prepare-source-task", "--source-task-labels"])
def test_historical_cli_source_task_refuses_common_configuration_selector(tmp_path, mode):
    with pytest.raises(SystemExit) as failure:
        subject.main([
            "--results", str(tmp_path), mode, "1", "--historical-code-repository", str(tmp_path),
            "--judge-configuration-sha256", "a" * 64,
        ])
    assert failure.value.code == 2


@pytest.mark.parametrize("frame", ["common", "source_task"])
def test_default_human_audit_join_unchanged(tmp_path, monkeypatch, frame):
    calls = []
    expected = ({}, {}, {}, {})
    monkeypatch.setattr(subject, "_joined_artifacts", lambda *a, **k:
                        calls.append((a, k)) or expected)
    monkeypatch.setattr(reader, "read_partitions", lambda *a, **k: pytest.fail("historical opt-in absent"))
    assert subject._audit_artifacts(tmp_path, frame=frame) is expected
    assert calls == [((tmp_path,), {} if frame == "common" else {"frame": frame})]
