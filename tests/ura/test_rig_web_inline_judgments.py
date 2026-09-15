import json

import pytest

from experiments.rig_web_app.workspace_judgments import native_inline_rows


@pytest.fixture
def original(tmp_path):
    revision = dict(expected_commit="a"*40)
    cascade = dict(stages=[dict(name="rules"), dict(name="guardrail", model_id="local-guard")])
    source = dict(target="api:example", run_id="run-1", out=str(tmp_path), runner_argv=["--out",str(tmp_path)],
        judge_cascade=cascade, generation_project_revision=revision)
    manifest = dict(run_id="run-1", config=dict(components=dict(judge_cascade=cascade),run=dict(project_revision=revision)))
    (tmp_path/"cell-run-1.manifest.json").write_text(json.dumps(manifest))
    record = dict(attempt=dict(id="a",run_id="run-1"), response=dict(attempt_id="a",run_id="run-1",target="api:example",
        output_turns=[dict(content="Saved output")]))
    (tmp_path/"cell-run-1.responses.checkpoint.jsonl").write_text(json.dumps(record)+"\n")
    judgment = dict(attempt_id="a",run_id="run-1",label="safe",raw={})
    (tmp_path/"cell-run-1.jsonl").write_text(json.dumps(judgment)+"\n")
    return source, record, judgment


def test_saved_inline_verdict_is_output_owned_and_not_rejudged(original):
    source, _, _ = original
    rows = native_inline_rows(source, output_assignments={"run-1:a":"assignment"})
    assert len(rows)==1 and rows[0]["response_id"]=="run-1:a" and rows[0]["label"]=="safe"
    assert rows[0]["source_ref"].endswith("cell-run-1.jsonl:1")
    assert rows[0]['judge_settings']['stages'][1]['model_id']=='local-guard'
    assert native_inline_rows(source, output_assignments={"run-1:a":"assignment"})==rows
    with pytest.raises(ValueError,match="matching campaign output"):
        native_inline_rows(source, output_assignments={"different-output":"assignment"})


def test_inline_condition_cannot_be_relabelled_as_a_new_judge(original):
    source, _, _ = original
    source["generation_project_revision"] = dict(expected_commit="b"*40)
    with pytest.raises(ValueError,match="judging condition differs"):
        native_inline_rows(source, output_assignments={"run-1:a":"assignment"})


def test_inline_checkpoint_output_and_final_label_must_match(original):
    from pathlib import Path
    source, record, judgment = original
    path=Path(source["out"])/"cell-run-1.checkpoint.jsonl"
    path.write_text(json.dumps(dict(record,judgment=judgment))+"\n")
    assert len(native_inline_rows(source,output_assignments={"run-1:a":"assignment"}))==1
    changed={**judgment,"label":"violation"}
    path.write_text(json.dumps(dict(record,judgment=changed))+"\n")
    with pytest.raises(ValueError,match="Final native judgment differs"):
        native_inline_rows(source,output_assignments={"run-1:a":"assignment"})
    record["response"]["output_turns"][0]["content"]="Changed answer"
    path.write_text(json.dumps(dict(record,judgment=judgment))+"\n")
    with pytest.raises(ValueError,match="changed its saved response"):
        native_inline_rows(source,output_assignments={"run-1:a":"assignment"})
