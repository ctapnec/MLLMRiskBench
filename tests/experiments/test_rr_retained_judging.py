"""Recovery keeps target calls impossible and preserves the selected cascade."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from experiments.local_campaign import rr_retained_judging as recovery
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.runner import _component_config


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
