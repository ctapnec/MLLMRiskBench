"""Source selection is independent of thesis controllers and response quality."""
import copy
import hashlib
import json

import pytest

from experiments import retained_local_sources as subject, hosted_retained_inputs as inputs
from experiments.rig_web_app.catalog import build_argv


@pytest.fixture
def source(tmp_path, monkeypatch):
    # Shape exported by the original retained grid reader, including input
    # metadata for a completed run whose response and scoring both failed.
    root = tmp_path / "ordinary-job"
    root.mkdir()
    artifact = root / "run.attempts.jsonl"
    artifact.write_text('{"id":"attempt-1"}\n')
    cell = dict(source_identity_validated=True, run_id="run-1", model="ollama:model",
        manifest=dict(dataset_hashes={"corpus": "b"*64}, config={"run": {
            "corpus": "ordinary-arm", "project_revision": {"sha256": "c"*64}}}),
        artifacts={"attempts": artifact}, artifact_descriptors={"attempts": {
            "file": artifact.name, "bytes": artifact.stat().st_size,
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}},
        attempts={"attempt-1": dict(id="attempt-1", run_id="run-1", target="ollama:model",
            datapoint_id="input-1", attacker="replay", seed=0, turn_index=0,
            rendered_input=[dict(role="user", content="Original task", media=[])],
            params=dict(source_cluster_id="cluster-1", planning_source="source",
                planning_expected_behavior="refuse", planning_source_policy=None))},
        input_metadata={"attempt-1": dict(source="source", risk_category="risk", expected_behavior="refuse")},
        responses={"attempt-1": dict(output_turns=[], outcome="failed_output")}, judgments=[])
    cells = [cell]
    monkeypatch.setattr(subject, "load_cells", lambda path: cells)
    return root, cells


def test_source_population_includes_failed_outputs_and_ignores_judge_labels(source):
    root, cells = source
    first = subject.prepare_sources([root])
    assert first["unique_inputs"] == first["model_input_assignments"] == 1
    assert first["target_calls"] == first["judge_calls"] == first["model_loads"] == 0
    assert first["source_roots"] == [str(root)]
    cells[0]["responses"] = {"attempt-1": {"text": "Now a usable answer"}}
    cells[0]["judgments"] = [dict(attempt_id="attempt-1", label="violation",
        raw=cells[0]["input_metadata"]["attempt-1"])]
    assert subject.prepare_sources([root]) == first
    assert subject.load_sources(first) == cells
    assert "Now a usable answer" not in json.dumps(first)
    assert "violation" not in json.dumps(first)


def test_saved_selection_does_not_include_new_runs(source):
    root, cells = source
    inventory = subject.prepare_sources([root])
    extra = copy.deepcopy(cells[0])
    extra["run_id"] = "run-2"
    cells.append(extra)
    assert [cell["run_id"] for cell in subject.load_sources(inventory)] == ["run-1"]


def test_changed_input_is_not_silently_selected(source):
    root, cells = source
    inventory = subject.prepare_sources([root])
    cells[0]["attempts"]["attempt-1"]["rendered_input"][0]["content"] = "Different task"
    with pytest.raises(ValueError, match="input population differs"):
        subject.load_sources(inventory)


def test_explicit_run_selection_and_missing_run(source):
    root, cells = source
    assert subject.read_sources([root], ["run-1"]) == cells
    with pytest.raises(ValueError, match="absent"):
        subject.prepare_sources([root], ["not-a-run"])
    with pytest.raises(ValueError, match="only once"):
        subject.prepare_sources([root], ["run-1", "run-1"])


def test_overlapping_roots_and_repeated_runs_are_rejected(source, tmp_path):
    root, _cells = source
    other = tmp_path / "other-job"
    other.mkdir()
    with pytest.raises(ValueError, match="overlap"):
        subject.prepare_sources([root, root])
    with pytest.raises(ValueError, match="overlap"):
        subject.prepare_sources([root, tmp_path])
    with pytest.raises(ValueError, match="several source"):
        subject.prepare_sources([root, other])


@pytest.mark.parametrize("change", ["hosted", "not-admitted", "wrong-seed"])
def test_existing_source_requirements_are_unchanged(source, change):
    root, cells = source
    if change == "hosted":
        cells[0]["model"] = "openai:model"
    elif change == "not-admitted":
        cells[0]["source_identity_validated"] = False
    else:
        cells[0]["attempts"]["attempt-1"]["seed"] = 1
    with pytest.raises(ValueError):
        subject.prepare_sources([root])


def test_typed_form_runs_same_source_selection_without_hash_opt_in(source, tmp_path):
    root, _cells = source
    out = tmp_path / "sources.json"
    argv = build_argv("retained_local_sources", {"--source-root": str(root), "--run-id": "run-1", "--out": str(out)})
    assert "--verify-artifact-sha256" not in argv
    assert subject.main(argv[argv.index("experiments.retained_local_sources")+1:]) == 0
    assert json.loads(out.read_text()) == subject.prepare_sources([root])


def test_hosted_selector_consumes_selected_sources_without_historical_view(source, tmp_path, monkeypatch):
    root, cells = source
    inventory = subject.prepare_sources([root])
    descriptor = dict(file="inventory.json", sha256="d"*64, bytes=123)
    monkeypatch.setattr(inputs, "load_bound_json", lambda *a: (inventory, descriptor))
    observed = []
    monkeypatch.setattr(inputs, "build_plan", lambda **kw: observed.append(kw) or
        dict(plan_id="no-call-plan", status="prepared", selected=kw["candidates"]))
    monkeypatch.setattr(inputs, "load_cells", lambda *a: pytest.fail("Historical view was unexpectedly used"))
    values = {"--local-inventory": str(tmp_path/"inventory.json"), "--local-inventory-sha256": "d"*64,
        "--budget": str(tmp_path/"budget.json"), "--budget-sha256": "d"*64,
        "--api-config": str(tmp_path/"api.json"), "--api-config-sha256": "d"*64,
        "--target": "provider:target", "--out": str(tmp_path/"plan.json")}
    argv = build_argv("hosted_retained_inputs", values)
    assert inputs.main(argv[argv.index("experiments.hosted_retained_inputs")+1:]) == 0
    assert observed[0]["candidates"] == inputs.candidates_from_cells(cells)
    assert observed[0]["local_inventory_descriptor"] == descriptor
    with pytest.raises(SystemExit):
        inputs.main(argv[argv.index("experiments.hosted_retained_inputs")+1:] + ["--runner-view", str(root)])
