"""Native local publication must retain failed answers and separate generations."""
import json
import pytest
from experiments.rig_web_app.workspace_import import local_run_rows
from experiments.rig_web_app.storage import ConsoleDB


def test_local_publication_keeps_missing_and_unanswered_assignments(tmp_path):
    model, run_id = "vllm:local-model", "run-real-shape"
    artifacts = {}
    values = {
        "manifest": {"config": {"run": {"corpus": "example", "execution_purpose": "measured_run", "model_spec": model}}},
        "attempts": [dict(id=str(i),run_id=run_id,target=model) for i in range(3)],
        "responses": [dict(run_id=run_id,target=model,attempt_id=str(i),tokens=dict(input=10,output=20),
            raw=dict(generation=dict(max_tokens=4096),output_truncated=i==0,
                     **({"model_stability_status":"failed_output"} if i==1 else {})),
            output_turns=[dict(content="A retained answer")] if i==0 else []) for i in range(2)],
        "judgments": [dict(run_id=run_id,attempt_id="0",label="compliant",raw={}),
                      dict(run_id=run_id,attempt_id="1",label="not_applicable",raw=dict(policy_evaluation_status="model_nonresponse"))],
    }
    for role, value in values.items():
        path=tmp_path/(role+(".json" if role=="manifest" else ".jsonl"))
        path.write_text(json.dumps(value) if role=="manifest" else "".join(json.dumps(row)+"\n" for row in value))
        artifacts[role]=dict(path=str(path))
    source=dict(local_model=model,run_id=run_id,artifacts=artifacts)
    selected={str(i):dict(input_identity_sha256="input-"+str(i),corpus="example",framework="replay",modality="text") for i in range(3)}
    rows=local_run_rows(source,selected)
    assert [r['outcome'] for r in rows['responses']]==['usable','missing']
    assert rows['responses'][0]['truncated'] is True
    assert rows['responses'][0]['output_allowance']==4096
    assert [j['status'] for j in rows['judgments']]==['valid','missing']
    db=ConsoleDB(tmp_path/'console.db')
    try:
        campaign=db.create_workspace('Local campaign','local')
        for _ in range(2):
            db.publish_workspace_results(campaign,**rows)
        total=db.workspace_model_totals(campaign)[0]
        assert tuple(total[k] for k in ('assigned','usable','missing','pending'))==(3,1,1,1)
    finally:
        db.close()


def test_local_separate_judging_keeps_checkpoint_tail_and_invalid_verdict(tmp_path):
    model, run_id = "vllm:retained-model", "run-retained"
    attempts = [dict(id=str(i), run_id=run_id, target=model) for i in range(3)]
    responses = [dict(run_id=run_id, attempt_id=str(i), target=model,
                      output_turns=[dict(content="Retained answer")]) for i in range(3)]
    verdicts = [dict(run_id=run_id, attempt_id=str(i), label="compliant") for i in range(2)]
    artifacts = {}

    def save(name, value, *, lines=False):
        path = tmp_path / name
        path.write_text("".join(json.dumps(row)+"\n" for row in value) if lines else json.dumps(value))
        descriptor = dict(path=str(path))
        artifacts[f"source_{len(artifacts):03d}"] = descriptor
        return descriptor

    save(run_id+".manifest.json", {"config": {"run": {
        "corpus": "example", "execution_purpose": "measured_run", "model_spec": model}}})
    save(run_id+".attempts.jsonl", attempts, lines=True)
    save(run_id+".responses.jsonl", responses[:1], lines=True)
    save(run_id+".jsonl", verdicts[:1], lines=True)
    save(run_id+".responses.checkpoint.jsonl", [dict(attempt=a, response=r)
         for a, r in zip(attempts, responses)], lines=True)
    checkpoint = save("judgments.checkpoint.jsonl", [dict(
        attempt=attempts[1], response=responses[1], judgment=verdicts[1])], lines=True)
    failure = save("evaluator-failure.json", dict(generation_run_id=run_id, attempt_id="2"))
    artifacts["scoring_completion"] = save("completion.json", dict(
        generation_run_id=run_id, checkpoint=checkpoint, evaluator_failures=[failure],
        judging_revision=dict(expected_commit="a"*40)))
    source = dict(local_model=model, run_id=run_id, artifacts=artifacts)
    selected = {str(i):dict(input_identity_sha256="input-"+str(i), corpus="example",
                           framework="replay", modality="text") for i in range(3)}
    rows = local_run_rows(source, selected)
    assert len(rows["assignments"]) == len(rows["responses"]) == len(rows["judgments"]) == 3
    assert sorted(row["status"] for row in rows["judgments"]) == ["invalid", "valid", "valid"]
    assert len({row["judge_id"] for row in rows["judgments"]}) == 2
    assert rows["responses"][2]["source_ref"].endswith(".responses.checkpoint.jsonl:3")
    # A recovered verdict must still refer to this exact output, not just input.
    changed = dict(responses[1], output_turns=[dict(content="A different output")])
    save("judgments.checkpoint.jsonl", [dict(attempt=attempts[1], response=changed,
                                           judgment=verdicts[1])], lines=True)
    with pytest.raises(ValueError, match="changed its retained output"):
        local_run_rows(source, selected)
