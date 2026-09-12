from copy import deepcopy
import json

import pytest

from experiments.retained_outcomes import legacy_provider_policy_basis
from experiments.rig_web_app.storage import ConsoleDB


def saved_response():
    return dict(run_id="run", attempt_id="a", target="openai:gpt-5.6-terra", output_turns=[], tokens=None,
        raw=dict(model_stability_status="failed_output", model_stability_category="transport_failure",
            call_audit=dict(provider="openai", operation="generate", status_code=400, provider_error_code="bio_policy")))


@pytest.mark.parametrize("code", ["cyber_policy", "bio_policy"])
def test_explicit_legacy_policy_is_a_provider_outcome_not_an_answer_or_new_judgment(code):
    response = saved_response()
    response["raw"]["call_audit"]["provider_error_code"] = code
    original = deepcopy(response)
    assert legacy_provider_policy_basis(response) == "openai_http400_"+code
    assert response == original


@pytest.mark.parametrize("change", ["unknown_400", "wrong_status", "wrong_provider", "visible", "partial_filter"])
def test_generic_error_or_discarded_partial_answer_cannot_become_a_refusal(change):
    response = saved_response()
    audit = response["raw"]["call_audit"]
    if change == "unknown_400":
        audit["provider_error_code"] = "invalid_parameter"
    elif change == "wrong_status":
        audit["status_code"] = 500
    elif change == "wrong_provider":
        response["target"] = "deepseek:example"
    elif change == "visible":
        response["output_turns"] = [dict(content="A visible partial answer")]
    else:
        response["target"] = "google:gemini-3.8-flash"
        response["raw"].update(model_stability_reason="Gemini filtered candidate contained visible partial output",
            finish_reason="PROHIBITED_CONTENT")
        audit.update(provider="google", status_code=None)
    assert legacy_provider_policy_basis(response) is None


def test_policy_index_correction_preserves_every_other_field_and_original_verdict(tmp_path):
    db = ConsoleDB(tmp_path/"console.db")
    campaign = db.create_workspace("API", "api")
    assignment = dict(assignment_id="a", model="openai:gpt-5.6-terra", input_id="input", condition_id="condition",
        modality="text", framework="replay", corpus="source", response_id="run:a", evidence_class="measured")
    row = dict(response_id="run:a", assignment_id="a", condition_id="condition", outcome="missing",
        truncated=None, source_ref="cell.responses.checkpoint.jsonl:1", missing_category="transport_failure")
    verdict = dict(response_id="run:a", judge_id="old-judge", status="missing", label=None, source_ref="old-judge.json")
    db.publish_workspace_results(campaign, assignments=[assignment], responses=[row], judgments=[verdict])
    corrected = {**row, "outcome":"policy", "missing_category":None,
        "outcome_basis":legacy_provider_policy_basis(saved_response())}
    for _ in range(2):
        db.publish_workspace_results(campaign, assignments=[], responses=[corrected], judgments=[])
    totals = db.workspace_model_totals(campaign)[0]
    assert (totals["assigned"], totals["missing"], totals["policy"]) == (1, 0, 1)
    assert len(db._query("SELECT * FROM campaign_responses")) == 1
    assert db._query("SELECT status,label FROM campaign_judgments")[0]["status"] == "missing"
    assert db.workspace_cost_totals(campaign) == []
    details = json.loads(db._query("SELECT details FROM campaign_responses")[0]["details"])
    assert details["outcome_basis"] == "openai_http400_bio_policy" and details["output_tokens"] is None
    with pytest.raises(ValueError, match="metadata changed"):
        db.publish_workspace_results(campaign, assignments=[], responses=[{**corrected, "output_tokens":0}], judgments=[])
    db.close()
