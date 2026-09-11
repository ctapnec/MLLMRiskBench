"""Logical outcome accounting and output-specific judging in the UI index."""
import pytest
from experiments.rig_web import RigWebApp


def assignment(model="local-model", key="a", response="r1"):
    return dict(assignment_id=key, model=model, input_id="same-input", condition_id="initial",
                modality="text", framework="replay", corpus="corpus", response_id=response, evidence_class="measured")


def response(key="r1", assigned="a", **extra):
    return dict(response_id=key, assignment_id=assigned, condition_id="initial", outcome="usable",
                truncated=True, source_ref="responses.jsonl:1", output_allowance=4096,
                input_tokens=100, output_tokens=4096, **extra)


@pytest.fixture
def app(tmp_path):
    app = RigWebApp(results_root=tmp_path / "runs", state_dir=tmp_path / "state", repo_root=tmp_path)
    yield app
    app.close()


def test_republication_and_recovery_do_not_duplicate_assignments_or_choose_newest(app):
    owner = app.db.create_workspace("Local", "local")
    initial = dict(assignments=[assignment()], responses=[response()], judgments=[])
    app.db.publish_workspace_results(owner, **initial)
    first_update = app.db.workspace_model_totals(owner)[0]["updated_at"]
    app.db.publish_workspace_results(owner, **initial)
    assert app.db.workspace_model_totals(owner)[0]["updated_at"] == first_update
    corrected = {**response("r2"), "condition_id": "larger-output", "truncated": False, "output_allowance": 8192}
    app.db.publish_workspace_results(owner, assignments=[], responses=[corrected], judgments=[])
    assert app.db.workspace_model_totals(owner)[0]["truncated"] == 1  # no newest-wins
    app.db.publish_workspace_results(owner, assignments=[assignment(response="r2")], responses=[], judgments=[])
    model = app.db.workspace_model_totals(owner)[0]
    assert (model["assigned"], model["usable"], model["truncated"]) == (1, 1, 0)
    assert app.db.workspace_result_rows(owner)[0]["response_condition"] == "larger-output"
    assert len(app.db._query("SELECT * FROM campaign_responses")) == 2
    assert app.db.reindex([], [])
    assert app.db.workspace_model_totals(owner)[0]["assigned"] == 1


def test_equal_inputs_different_outputs_do_not_share_verdicts(app):
    owner = app.db.create_workspace("Comparison", "mixed")
    app.db.publish_workspace_results(owner,
        assignments=[assignment(), assignment("api-model", "b", "r2")],
        responses=[response(), response("r2", "b")],
        judgments=[dict(response_id="r1", judge_id="haiku-condition", status="valid", label="safe", source_ref="judge.jsonl:1")])
    assert app.db.workspace_judging_totals(owner)[0]["count"] == 1
    with pytest.raises(ValueError, match="no matching retained output"):
        app.db.publish_workspace_results(owner, assignments=[], responses=[],
            judgments=[dict(response_id="same-input", judge_id="haiku-condition", status="valid", label="safe", source_ref="judge.jsonl:1")])


def test_invalid_cross_assignment_selection_rolls_back_whole_publication(app):
    owner = app.db.create_workspace("API", "api")
    with pytest.raises(ValueError, match="Selected response"):
        app.db.publish_workspace_results(owner,
            assignments=[assignment(), assignment("api", "b", "r1")], responses=[response()], judgments=[])
    assert app.db.workspace_model_totals(owner) == []


def test_missing_and_pending_remain_in_denominator_and_truncation_is_separate(app):
    owner = app.db.create_workspace("Local", "local")
    missing = {**response("bad", "b"), "outcome": "missing", "truncated": None,
               "input_tokens": None, "output_tokens": None, "missing_category": "empty_answer"}
    app.db.publish_workspace_results(owner,
        assignments=[assignment(), assignment(key="b", response="bad"), assignment(key="c", response=None)],
        responses=[response(), missing], judgments=[])
    model = app.db.workspace_model_totals(owner)[0]
    assert (model["assigned"], model["usable"], model["missing"], model["pending"], model["truncated"]) == (3, 1, 1, 1, 1)
    overview = app.handle("GET", "/campaigns/" + owner)[2].decode()
    assert "<svg" in overview and "local-model" in overview
    results = app.handle("GET", "/campaigns/" + owner + "?section=results")[2].decode()
    assert "Effective context</dt><dd>unknown" in results
    assert "Reported output tokens</dt><dd>4096" in results
    assert "empty_answer" in results
    assert "/artifacts?path=responses.jsonl" in results
    assert "not zero" in app.handle("GET", "/campaigns/" + owner + "?section=costs")[2].decode()


def test_retained_response_and_assignment_identity_cannot_be_overwritten(app):
    owner = app.db.create_workspace("API", "api")
    app.db.publish_workspace_results(owner, assignments=[assignment()], responses=[response()], judgments=[])
    with pytest.raises(ValueError, match="metadata changed"):
        app.db.publish_workspace_results(owner, assignments=[], responses=[{**response(), "truncated": False}], judgments=[])
    with pytest.raises(ValueError, match="assignment identity changed"):
        app.db.publish_workspace_results(owner, assignments=[{**assignment(), "model": "another-model"}], responses=[], judgments=[])


def test_diagnostics_do_not_pool_with_measured_assignments(app):
    owner = app.db.create_workspace("API", "api")
    app.db.publish_workspace_results(owner,
        assignments=[assignment(), {**assignment(key="b", response="r2"), "evidence_class": "diagnostic"}],
        responses=[response(), response("r2", "b")], judgments=[])
    rows = app.db.workspace_model_totals(owner)
    assert len(rows) == 2
    assert {row["evidence_class"] for row in rows} == {"measured", "diagnostic"}
    assert [row["assigned"] for row in rows] == [1, 1]
