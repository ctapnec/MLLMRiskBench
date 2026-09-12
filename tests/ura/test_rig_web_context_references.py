from copy import deepcopy

import pytest

from experiments.rig_web_app.workspace_contexts import native_context_reference, response_identity


@pytest.fixture
def native():
    response = dict(run_id="run", attempt_id="attempt", target="api:model", output_turns=[dict(content="One exact saved answer")])
    context = dict(context="source-context", input_id="primary-input", alias_input_ids=["source-alias"],
        same_native_judge_input=True, response_id="run:attempt", target="api:model",
        response_identity=response_identity(response), criterion_source="criteria.json")
    verdict = dict(response_id="run:attempt", judge_id="actual-native-judge", status="valid", label="safe", source_ref="judgments.jsonl:7")
    return context, response, verdict


def test_equivalent_context_is_a_reference_not_a_new_verdict(native):
    context, response, verdict = native
    result = native_context_reference(context, response, [verdict], expected_judge_ids={verdict["judge_id"]})
    assert result["status"] == "referenced" and result["judgments"] == [verdict]
    assert result["independent_generation"] is False and result["additional_judge_calls"] == 0
    pending = native_context_reference(context, response, [], expected_judge_ids={verdict["judge_id"]})
    assert pending["status"] == "pending_primary_judgment" and pending["judgments"] == []


@pytest.mark.parametrize("change", ["output", "model", "criteria"])
def test_native_reference_never_moves_a_verdict_to_another_output(native, change):
    context, response, verdict = native
    if change == "output": response["output_turns"][0]["content"] += " changed"
    elif change == "model": response["target"] = "api:different-model"
    else: context["same_native_judge_input"] = False
    with pytest.raises(ValueError, match="criteria or model output"):
        native_context_reference(context, response, [verdict], expected_judge_ids={verdict["judge_id"]})


def test_native_reference_retains_differing_assessments_without_picking_a_label(native):
    context, response, verdict = native
    other = {**verdict, "judge_id":"other-version", "label":"violation"}
    result = native_context_reference(context, response, [verdict, other], expected_judge_ids={verdict["judge_id"],other["judge_id"]})
    assert [v["label"] for v in result["judgments"]] == ["safe","violation"]
    with pytest.raises(ValueError, match="owner or condition"):
        native_context_reference(context, response, [other], expected_judge_ids={verdict["judge_id"]})
    invalid = deepcopy(verdict)
    invalid["status"] = "invalid"
    with pytest.raises(ValueError, match="unscored context"):
        native_context_reference(context, response, [invalid], expected_judge_ids={verdict["judge_id"]})
