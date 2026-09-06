"""Recovery keeps target calls impossible and preserves the selected cascade."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_retained_judging as recovery
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import DataPoint, DialogTurn, Response, RiskCategory
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.runner import Runner, _component_config
from ura.targets.base import BaseTarget


def manifest():
    cascade = JudgeCascade([RuleJudge(), GuardrailJudge(
        model="meta-llama/Llama-Guard-3-8B", revision="b" * 40,
        device="cuda:0", max_new_tokens=20,
    )])
    return SimpleNamespace(
        judges=["rules", "guardrail"], models=["retained-rr"],
        config={"components": {
            "judge_cascade": _component_config(cascade),
            "target": {"modality_support": ["text", "image"]},
        }},
    )


def test_target_execution_is_impossible_even_if_called_by_mistake():
    target = recovery._NoTarget(manifest())
    assert target.name == "retained-rr"
    assert target.modality_support == ("text", "image")
    with pytest.raises(RuntimeError, match="cannot execute a target"):
        target.generate([])


def test_recovery_preserves_every_saved_judge_setting_without_loading_models():
    original = manifest()
    runtime = object()
    cascade = recovery.source_cascade(original, model_runtime=runtime)
    assert _component_config(cascade) == original.config["components"]["judge_cascade"]
    assert cascade.stages[1]._model_runtime is runtime
    assert cascade.stages[1]._model is None
    assert cascade.stages[1]._tokenizer is None


@pytest.mark.parametrize("changed", ["class", "extra", "roster"])
def test_recovery_does_not_silently_replace_a_different_judge_configuration(changed):
    original = manifest()
    if changed == "roster":
        original.judges = ["rules", "llm"]
    elif changed == "class":
        original.config["components"]["judge_cascade"]["stages"][1]["class"] = "AnotherGuard"
    else:
        original.config["components"]["judge_cascade"]["unrecognized_setting"] = True
    with pytest.raises(ValueError, match="cascade|configuration"):
        recovery.source_cascade(original)


def test_pending_selection_excludes_every_existing_judgment():
    source = recovery.RetainedUnit(
        manifest(), {}, {}, None, {"a": None, "b": None, "c": None},
        {"a": {}, "b": {}, "c": {}}, {"b": {}},
    )
    assert source.pending_ids == ["a", "c"]


def test_source_files_must_remain_exactly_bound(tmp_path):
    path = tmp_path / "responses.jsonl"
    path.write_text("original\n")
    source = recovery.RetainedUnit(
        manifest(), {}, {"files": [recovery._descriptor(path, label="source")]},
        None, {}, {}, {},
    )
    source.validate_unchanged()
    path.write_text("modified\n")
    with pytest.raises(ValueError):
        source.validate_unchanged()


def _fixture_cascade():
    cascade = recovery.source_cascade(manifest())
    calls = []
    guard = cascade.stages[1]
    guard._ensure_loaded = lambda: None

    def classify(conversation):
        calls.append(conversation)
        return "unsafe\nS1"

    guard._run_guard = classify
    return cascade, calls


@pytest.fixture
def retained_source(tmp_path):
    class FixtureTarget(BaseTarget):
        name = "retained-rr"
        modality_support = ("text", "image")

        def generate(self, dialog, *, seed=None):
            return Response(attempt_id="pending", target=self.name,
                            output_turns=[DialogTurn(role="assistant", content="fixture answer")],
                            raw={"sampling_control": "seeded"})

    points = [DataPoint(id=key, source="unit", modalities=["text"], payload_text="fixture prompt",
                        risk_category=RiskCategory.INFORMATION_SECURITY, expected_behavior="refuse")
              for key in ("a", "b")]
    cascade, _calls = _fixture_cascade()
    original = Runner(ReplayAttacker(), FixtureTarget(), cascade,
                      AttackBudget(max_queries=1, max_turns=1, seed=0), [0])
    responses, records = [], []
    _judgments, saved_manifest = original.run(
        points, on_response=responses.append, on_record=records.append,
        run_config={"expected_target_identity": None, "approximate_common_metrics": False},
    )
    root = tmp_path / "original"
    root.mkdir()
    path = root / "source.json"
    path.write_text(json.dumps({"responses": responses, "judgments": records[:1]}))
    prepared, _media = original._prepare_corpus(points)
    by_id = {point.id: point for point in prepared}
    return recovery.RetainedUnit(
        saved_manifest, {"result_root": str(root), "selected_records": 2},
        {"files": [recovery._descriptor(path, label="source")]}, original,
        {attempt.id: (by_id[attempt.datapoint_id], attempt) for attempt in original.attempts},
        {record["attempt"]["id"]: record for record in responses},
        {record["attempt"]["id"]: record for record in records[:1]},
    )


def test_writer_scores_only_missing_rows_and_resumes_without_any_call(retained_source, tmp_path):
    source = retained_source
    cascade, calls = _fixture_cascade()
    checkpoint = tmp_path / "new-judgments.jsonl"
    result = recovery.score_pending(source, cascade, checkpoint=checkpoint)
    assert len(calls) == 1 and len(result.judgments) == 2
    saved = Runner.load_checkpoint(checkpoint, expected_run_id=source.manifest.run_id)
    assert set(saved) == set(source.pending_ids)
    assert [response.model_dump(mode="json") for response in result.responses] == [
        row["response"] for row in source.responses.values()
    ]
    first = checkpoint.read_bytes()
    cascade, calls = _fixture_cascade()
    resumed = recovery.score_pending(source, cascade, checkpoint=checkpoint)
    assert calls == [] and len(resumed.judgments) == 2
    assert checkpoint.read_bytes() == first
    source.validate_unchanged()


def test_saved_scoring_cannot_substitute_an_internally_valid_different_response(retained_source, tmp_path):
    source = retained_source
    key = source.pending_ids[0]
    point, attempt = source.inputs[key]
    modified = copy.deepcopy(source.responses[key])
    modified["response"]["output_turns"][0]["content"] = "different fixture answer"
    cascade, _calls = _fixture_cascade()
    forging_fixture = recovery._reader_runner(source.manifest, cascade)
    records = []
    forging_fixture._execute_or_restore(point, attempt, source.manifest.run_id, None,
                                       records.append, response_record=modified)
    # This is a valid standalone record, but it is not the retained output.
    forging_fixture._restore_record(point, attempt, records[0], source.manifest.run_id)
    checkpoint = tmp_path / "substituted.jsonl"
    Runner.append_checkpoint(checkpoint, records[0])
    cascade, calls = _fixture_cascade()
    with pytest.raises(ValueError, match="original target response"):
        recovery.score_pending(source, cascade, checkpoint=checkpoint)
    assert calls == []


def test_checkpoint_cannot_repeat_an_original_judgment(retained_source, tmp_path):
    checkpoint = tmp_path / "repeated.jsonl"
    Runner.append_checkpoint(checkpoint, next(iter(retained_source.judgments.values())))
    cascade, calls = _fixture_cascade()
    with pytest.raises(ValueError, match="original completed judgment"):
        recovery.score_pending(retained_source, cascade, checkpoint=checkpoint)
    assert calls == []


def test_writer_cannot_write_into_original_generation_directory(retained_source):
    cascade, calls = _fixture_cascade()
    checkpoint = recovery.Path(retained_source.state["result_root"]) / "new.jsonl"
    with pytest.raises(ValueError, match="original generation root"):
        recovery.score_pending(retained_source, cascade, checkpoint=checkpoint)
    assert calls == [] and not checkpoint.exists()
