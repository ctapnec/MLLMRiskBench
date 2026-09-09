from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from experiments import retained_response_judge as judge
from experiments import retained_scoring_view as subject


@pytest.mark.parametrize("mutation", [None, "missing", "extra", "response"])
def test_separate_scoring_restores_only_exact_retained_answers(tmp_path, monkeypatch, mutation):
    original = {"one": {"response": {"answer": "Retained answer."}}}
    saved = copy.deepcopy(original)
    if mutation == "missing":
        saved.clear()
    elif mutation == "extra":
        saved["two"] = copy.deepcopy(saved["one"])
    elif mutation == "response":
        saved["one"]["response"]["answer"] = "Replacement answer."
    restored = []
    source = SimpleNamespace(
        manifest=SimpleNamespace(run_id="original-generation"), responses=original,
        inputs={"one": ("original-point", "original-attempt")},
        runner=SimpleNamespace(_restore_record=lambda *args: restored.append(args)),
    )
    monkeypatch.setattr(subject.Runner, "load_checkpoint", lambda *args, **kwargs: saved)
    if mutation:
        with pytest.raises(ValueError, match="retained answer"):
            subject._records(source, tmp_path / "judgments.jsonl")
        assert restored == []
    else:
        assert subject._records(source, tmp_path / "judgments.jsonl") == original
        assert restored == [("original-point", "original-attempt", saved["one"], "original-generation")]


def test_native_reader_dispatches_separate_scoring_without_promoting_a_grid(tmp_path, monkeypatch):
    (tmp_path / subject.FILE).write_text("{}")
    expected = ([{"run_id": "old"}], {}, {}, {"policy_evaluable_samples": 0})
    calls = []
    def read(root):
        calls.append(root)
        return expected
    monkeypatch.setattr(subject, "read_view", read)
    def forbidden(*args, **kwargs):
        raise AssertionError("separate scoring must not be interpreted as a completed generation grid")
    monkeypatch.setattr(judge, "_joined_artifacts", forbidden)
    assert judge._read_native_view(tmp_path) is expected
    assert calls == [tmp_path]


def test_source_descriptor_binds_empty_files_without_ignoring_their_content(tmp_path):
    path = tmp_path / "judgments.jsonl"
    path.touch()
    item = subject._descriptor(path)
    source = SimpleNamespace(source={"files": [item]})
    subject._Source.validate_unchanged(source)
    path.write_text(json.dumps({"invented": "verdict"}))
    with pytest.raises(ValueError, match="original scoring source changed"):
        subject._Source.validate_unchanged(source)


def test_read_view_rejects_unknown_contract_before_loading_any_source(tmp_path):
    (tmp_path / subject.FILE).write_text(json.dumps({"schema": "unrecognized"}))
    with pytest.raises(ValueError, match="view fields changed"):
        subject.read_view(tmp_path)


@pytest.mark.parametrize("mutation", [None, "usable", "changed_response", "missing_response", "missing_input"])
def test_separate_scoring_preserves_only_exact_completed_nonresponses(mutation):
    response = {"raw": {"model_stability_status": "failed_output"}, "output_turns": []}
    completed = {"failed": {"response": copy.deepcopy(response)}}
    responses = {"failed": {"response": copy.deepcopy(response)}}
    inputs = {"failed": ("point", "attempt")}
    if mutation == "usable":
        completed["failed"]["response"]["raw"]["model_stability_status"] = "usable_output"
        responses = copy.deepcopy(completed)
    elif mutation == "changed_response":
        completed["failed"]["response"]["raw"]["invented"] = True
    elif mutation == "missing_response":
        responses.clear()
    elif mutation == "missing_input":
        inputs.clear()
    calls = []
    reader = SimpleNamespace(_restore_record=lambda *args: calls.append(args) or "strictly-restored")
    if mutation:
        with pytest.raises(ValueError, match="original completed answer judgments"):
            subject._restore_nonresponse_prefix(reader, inputs, responses, completed, "run")
        assert calls == []
    else:
        assert subject._restore_nonresponse_prefix(reader, inputs, responses, completed, "run") == {"failed": "strictly-restored"}
        assert calls == [("point", "attempt", completed["failed"], "run")]


def test_explicit_readjudging_preserves_and_strictly_restores_existing_answer_verdict():
    records = {"answer": {"response": {"raw": {}, "output_turns": [{"content": "Saved answer"}]}}}
    inputs = {"answer": ("point", "attempt")}
    calls = []
    reader = SimpleNamespace(_restore_record=lambda *args: calls.append(args) or "original-verdict")
    assert subject._restore_nonresponse_prefix(reader, inputs, records, records, "run", allow_readjudging=True) == {
        "answer": "original-verdict"}
    assert calls == [("point", "attempt", records["answer"], "run")]
    changed = copy.deepcopy(records)
    changed["answer"]["response"]["output_turns"][0]["content"] = "Changed answer"
    with pytest.raises(ValueError, match="original completed answer judgments"):
        subject._restore_nonresponse_prefix(reader, inputs, records, changed, "run", allow_readjudging=True)


def test_judging_revision_rechecks_both_paths_in_retained_checkout(tmp_path, monkeypatch):
    project = tmp_path / "retained-scoring-checkout"
    receipt = {"path": str(tmp_path / "receipt.json"), "sha256": "a" * 64}
    calls = []
    def load(path, digest, driver, **kwargs):
        calls.append((path, digest, driver, kwargs))
        return {"receipt": "retained"}, {"descriptor": "verified"}
    monkeypatch.setattr(subject, "load_project_revision_file", load)
    monkeypatch.setattr(subject, "project_revision_binding", lambda value, descriptor: (value, descriptor))
    assert subject._judging_revision(receipt, project) == (
        {"receipt": "retained"}, {"descriptor": "verified"},
    )
    assert calls == [(tmp_path / "receipt.json", "a" * 64, project / "experiments/run_matrix.py", {
        "recheck_checkout": True, "harness_module_path": project / "src/ura/runner.py",
    })]


@pytest.mark.parametrize("realized", [None, {"judges": []}, {
    "judges": [{"stage": 1, "judge": "rules", "snapshot": {"judge": "rules"}}],
}])
def test_separate_scoring_cannot_fall_back_to_original_judge_identity(realized):
    from experiments import human_audit

    cell = {"integrity_mode": "source_validated_generation_separate_completed_scoring",
            "realized_identities": realized,
            "manifest": {"judges": ["rules"], "config": {
                "components": {"judge_cascade": {}}, "realized_identities": {
                    "judges": [{"stage": 0, "judge": "rules", "snapshot": {"judge": "rules"}}],
                },
            }}}
    with pytest.raises(ValueError, match="judge configuration|judge identity"):
        human_audit._judge_configuration_binding([cell])
