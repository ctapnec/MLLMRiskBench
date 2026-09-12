from copy import deepcopy

import pytest

from experiments.rig_web_app.workspace_judgments import native_invalid_rows
from ura.runner import _sha256_json


def example():
    response = dict(run_id="run",attempt_id="a",target="api:model",output_turns=[dict(content="Retained answer")])
    unit = dict(run_id="run",invalid_judgments=1,judging_revision="revision",
        source=dict(target="api:model",judge_cascade=dict(stages=[dict(name="rules"),dict(name="guardrail",model_id="local-guard")])))
    trail = [dict(run_id="run",attempt_id="a",judge="rules",raw={}),
        dict(run_id="run",attempt_id="a",judge="guardrail",raw=dict(parsed=False,guardrail_queried=True))]
    failure = dict(schema="ura-rr-retained-judge-failure/1",attempt_id="a",generation_run_id="run",
        response_sha256=_sha256_json(response),trail=trail)
    return unit,response,failure


def test_native_invalid_assessment_is_unscored_not_pending_or_a_target_failure():
    unit,response,failure=example()
    result=native_invalid_rows(unit,[("failure.json",failure)],responses={"a":response},output_assignments={"run:a":"assigned"})
    assert result["judgments"][0]["status"]=="invalid" and result["judgments"][0]["label"] is None
    assert result["judgments"][0]["response_id"]=="run:a"
    assert len(result["costs"])==1 and result["costs"][0]["state"]=="not_billed"
    assert result["costs"][0]["provider"]=="local" and result["costs"][0]["role"]=="judge"


@pytest.mark.parametrize("change",["response","owner","parsed","count"])
def test_invalid_native_record_cannot_change_output_or_become_a_valid_label(change):
    unit,response,failure=example();owners={"run:a":"assigned"}
    if change=="response":
        response["output_turns"][0]["content"]="Different answer"
    elif change=="owner":
        owners={}
    elif change=="parsed":
        failure["trail"][-1]["raw"]["parsed"]=True
    else:
        unit["invalid_judgments"]=2
    with pytest.raises(ValueError):
        native_invalid_rows(unit,[("failure.json",failure)],responses={"a":response},output_assignments=owners)


def test_duplicate_failed_assessment_is_not_two_calls():
    unit,response,failure=example();unit["invalid_judgments"]=2
    with pytest.raises(ValueError,match="output owner"):
        native_invalid_rows(unit,[("first.json",failure),("second.json",deepcopy(failure))],
            responses={"a":response},output_assignments={"run:a":"assigned"})
