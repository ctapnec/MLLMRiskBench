from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

from experiments import human_audit, judge_sensitivity, kappa, retained_artifact_reader as reader, transfer_matrix


@pytest.fixture
def cells(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "historical_diagnostic_fixtures", Path(__file__).with_name("test_postprocessing_regressions.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = []
    for index, model in enumerate(("A", "B")):
        root = tmp_path / model
        root.mkdir()
        module._write_completed_cell(root, "cell", model=model, run_id=f"run-{index}", key="shared")
        module._configure_two_stage_sensitivity_fixture(root, "cell")
        selected = human_audit._validated_artifacts(root)[1][0]
        selected["stem"] = f"cell-{index}"
        selected["retained_source_validation"] = {"validator_commit": "a" * 40,
            "original_figure_grid_validation": "passed", "auxiliary_compatibility": None}
        result.append(selected)
    return result


@pytest.mark.parametrize("module", [judge_sensitivity, kappa, transfer_matrix])
def test_historical_cli_reuses_source_validated_cells_and_emits_provenance(tmp_path, cells, monkeypatch, module):
    calls = []
    def retained(root, *, code_repository):
        assert root == tmp_path and code_repository == tmp_path
        calls.append(True)
        return copy.deepcopy(cells)
    monkeypatch.setattr(module, "load_analysis_cells", retained)
    if module is transfer_matrix:
        monkeypatch.setattr(module, "_discover_facets", lambda *a: pytest.fail("current-only discovery"))
        monkeypatch.setattr(module, "_heatmap", lambda *a, **k: False)
        destination = tmp_path / "transfer"
        output = destination / "transfer_matrix.json"
        option = "--output-dir"
    else:
        monkeypatch.setattr(module, "_validated_artifacts", lambda *a: pytest.fail("current-only validation"))
        output = destination = tmp_path / (module.__name__.split(".")[-1] + ".json")
        option = "--output"
    assert module.main(["--results", str(tmp_path), "--historical-code-repository", str(tmp_path),
                        option, str(destination)]) == 0
    assert calls == [True]
    rendered = output.read_text()
    assert '"validator_commit": "' + "a" * 40 + '"' in rendered
    assert "retained_artifact_reader.py" in rendered


@pytest.mark.parametrize("module", [judge_sensitivity, kappa, transfer_matrix])
def test_historical_source_refusal_is_not_silently_retried_with_current_parser(tmp_path, monkeypatch, module):
    def refused(*a, **kw):
        raise ValueError("original source rejected changed artifact")
    monkeypatch.setattr(module, "load_analysis_cells", refused)
    output = "--output-dir" if module is transfer_matrix else "--output"
    assert module.main(["--results", str(tmp_path), "--historical-code-repository", str(tmp_path),
                        output, str(tmp_path / "never-created")]) == 1
    assert not (tmp_path / "never-created").exists()


@pytest.mark.parametrize("module", [kappa, transfer_matrix])
def test_historical_conditions_remain_separate_not_pooled(tmp_path, cells, monkeypatch, module):
    cells[1]["cohort_signature"] = "b" * 64
    monkeypatch.setattr(module, "load_analysis_cells", lambda *a, **kw: cells)
    load = module.load_trail_facets if module is kappa else module.load_facets
    result = load(tmp_path, historical_code_repository=tmp_path)
    assert len(result) == 2 and all(key.startswith("fixture__") for key in result)
    audits = [value[-1] for value in result.values()]
    assert {audit["cohort_signature"] for audit in audits} == {cell["cohort_signature"] for cell in cells}
    assert all(audit["completed_cells"] == 1 for audit in audits)
    if module is transfer_matrix:
        assert all(len(records) == 1 for records, _audit in result.values())
        with pytest.raises(ValueError, match="multiple exact cohorts"):
            module.load(tmp_path, historical_code_repository=tmp_path)
    else:
        monkeypatch.setattr(module, "_validated_artifacts", lambda *a: ({}, cells))
        with pytest.raises(ValueError, match="incompatible"):
            module.load_trail_facets(tmp_path)


@pytest.mark.parametrize("change", [None, "missing", "duplicate", "manifest", "artifacts", "signature", "source"])
def test_auxiliary_accessor_requires_exact_original_inventory(tmp_path, cells, monkeypatch, change):
    auxiliary = copy.deepcopy(cells)
    partition = {"cells": copy.deepcopy(cells), "analysis_cells": auxiliary, "validator_commit": "a" * 40}
    if change == "missing":
        auxiliary.pop()
    elif change == "duplicate":
        auxiliary[1] = copy.deepcopy(auxiliary[0])
    elif change == "manifest":
        auxiliary[0]["manifest"]["run_id"] = "changed"
    elif change == "artifacts":
        auxiliary[0]["artifacts"]["responses"] = tmp_path / "foreign"
    elif change == "signature":
        auxiliary[0].pop("cohort_signature")
    elif change == "source":
        auxiliary[0]["source_identity_validated"] = False
    def read(root, **kwargs):
        assert root == tmp_path
        assert kwargs == {"joined": True, "separate_judge_configurations": True, "code_repository": tmp_path}
        return [partition]
    monkeypatch.setattr(reader, "read_partitions", read)
    if change:
        with pytest.raises(ValueError):
            reader.load_analysis_cells(tmp_path, code_repository=tmp_path)
    else:
        result = reader.load_analysis_cells(tmp_path, code_repository=tmp_path)
        assert [cell["cohort_signature"] for cell in result] == [cell["cohort_signature"] for cell in cells]
        assert all(cell["retained_source_validation"]["validator_commit"] == "a" * 40 for cell in result)


def test_transfer_repeated_model_is_explicitly_unavailable_without_arbitrary_selection(tmp_path, cells, monkeypatch):
    repeated = copy.deepcopy(cells[0])
    repeated["run_id"] = "second-same-model"
    cells.append(repeated)
    monkeypatch.setattr(transfer_matrix, "load_analysis_cells", lambda *a, **kw: cells)
    # The ordinary row-accounting helper is tested by the real-shape tests;
    # isolate only the no-arbitrary-run-selection dispatch here.
    def account(selected, **kw):
        assert len(selected) == 1
        return {selected[0]["model"]: {}}, {"completed_cells": 1}
    monkeypatch.setattr(transfer_matrix, "_load_validated_cells", account)
    result = transfer_matrix.load_facets(tmp_path, historical_code_repository=tmp_path)
    assert len(result) == 3
    assert all(audit["comparison_unavailable_reason"] == "multiple_completed_runs_for_same_model_in_exact_cohort"
               for _records, audit in result.values())


def test_historical_transfer_still_checks_exact_attempt_judgment_lineage(tmp_path, cells, monkeypatch):
    cells[0]["judgments"][0]["raw"]["transfer_key"] = "changed"
    monkeypatch.setattr(transfer_matrix, "load_analysis_cells", lambda *a, **kw: cells)
    with pytest.raises(ValueError, match="Attempt/Judgment transfer_key mismatch"):
        transfer_matrix.load_facets(tmp_path, historical_code_repository=tmp_path)
