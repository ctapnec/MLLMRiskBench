from __future__ import annotations

import copy
import json

import pytest

from experiments import retained_response_judge as judge, retained_response_view as subject
from test_retained_response_judge import _mixed_configuration_partition


def _views(tmp_path, monkeypatch):
    sources, views = [], {}
    for prefix, model in (("base", "vllm:base"), ("rr", "vllm:defended"), ("retired", "ollama:retired")):
        root = tmp_path / prefix
        root.mkdir()
        sources.append(root)
        cells, metadata, judgments, audit = judge._joined_candidate_partitions([_mixed_configuration_partition()])
        for cell in cells:
            cell["run_id"] = prefix + "/" + cell["run_id"]
            cell["model"] = model
        for row in metadata.values():
            row["run_id"] = prefix + "/" + row["run_id"]
        views[root] = (cells, {prefix + "/" + key: row for key, row in metadata.items()},
                       {prefix + "/" + key: row for key, row in judgments.items()}, audit)
    monkeypatch.setattr(judge, "_read_native_view", lambda root: copy.deepcopy(views[root]))
    return sources, views


def test_composed_view_joins_defense_and_base_without_restoring_retired_candidates(tmp_path, monkeypatch):
    sources, views = _views(tmp_path, monkeypatch)
    before = copy.deepcopy(views)
    root = tmp_path / "scope"
    assert subject.main([*[arg for source in sources for arg in ("--source-view", str(source))],
                         "--model", "vllm:base", "--model", "vllm:defended", "--out-root", str(root)]) == 0
    cells, metadata, _judgments, audit = judge._read_view(root)
    rows, population = judge.load_candidates(root, include_match_identity=True)
    assert {row["exact_model"] for row in rows} == {"vllm:base", "vllm:defended"}
    assert len(cells) == 9  # All original provenance survives, including retired input origins.
    assert len(metadata) == 4 and not any(key.startswith("retired/") for key in metadata)
    assert audit["excluded_model_joined_rows"] == 2
    assert population == {"validated_joined_rows": 4, "eligible_usable_outputs": 2,
                          "excluded_missing_outputs": 2, "excluded_source_authoritative_rows": 2}
    assert judge.load_retained_metadata(root) == metadata
    assert views == before


def test_composed_source_change_refuses_before_judging(tmp_path, monkeypatch):
    sources, views = _views(tmp_path, monkeypatch)
    root = tmp_path / "scope"
    subject.compose(sources=sources, models=["vllm:base", "vllm:defended"], out_root=root)
    views[sources[0]][1]["base/sample-0"]["prepared_response"] = "Changed answer"
    with pytest.raises(ValueError, match="source view content changed"):
        judge.load_retained_metadata(root)


@pytest.mark.parametrize("defect", ["duplicate-run", "absent-model", "nested"])
def test_invalid_response_scope_cannot_create_output(tmp_path, monkeypatch, defect):
    sources, views = _views(tmp_path, monkeypatch)
    if defect == "duplicate-run":
        views[sources[1]][0][0]["run_id"] = views[sources[0]][0][0]["run_id"]
    elif defect == "nested":
        (sources[0] / "retained-view.json").write_text(json.dumps({"schema": subject.SCHEMA}))
    models = ["absent"] if defect == "absent-model" else ["vllm:base", "vllm:defended"]
    root = tmp_path / "scope"
    with pytest.raises(ValueError):
        subject.compose(sources=sources, models=models, out_root=root)
    assert not root.exists()
