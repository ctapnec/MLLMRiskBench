"""Native local publication must retain failed answers and separate generations."""
import json
import pytest
from experiments.rig_web_app.workspace_import import local_run_rows
from experiments.rig_web_app.storage import ConsoleDB


@pytest.mark.parametrize("backend,generation,tokens,reason", [
    ("ollama", dict(num_ctx=8192,num_predict=512), dict(prompt=24,completion=512), dict(done_reason="length")),
    ("vllm", dict(max_model_len=32768,max_tokens=4096), dict(input=24,output=512), dict(finish_reason="length")),
    ("ollama", dict(num_ctx=65536,num_predict=-1), dict(prompt=24,completion=512), dict(done_reason="length")),
])
def test_local_provider_native_token_metadata_is_not_lost(tmp_path, backend, generation, tokens, reason):
    model=backend+":local-model"
    run_id="run-native"
    artifacts={}
    response=dict(run_id=run_id,target=model,attempt_id="a",output_turns=[],tokens=tokens,
                  raw=dict(backend=backend,generation=generation,empty_completion_observed=True,**reason))
    values=dict(manifest={"config":{"run":{"model_spec":model,"corpus":"example","execution_purpose":"measured_run"}}},
        attempts=[dict(id="a",run_id=run_id,target=model)],responses=[response],
        judgments=[dict(run_id=run_id,attempt_id="a",label="not_applicable",raw=dict(policy_evaluation_status="model_nonresponse"))])
    for role,value in values.items():
        path=tmp_path/(role+".json")
        path.write_text(json.dumps(value) if role=="manifest" else "".join(json.dumps(r)+"\n" for r in value))
        artifacts[role]=dict(path=str(path))
    rows=local_run_rows(dict(local_model=model,run_id=run_id,artifacts=artifacts),
        {"a":dict(input_identity_sha256="input-a",corpus="example",framework="replay",modality="text")})
    r=rows['responses'][0]
    assert (r['input_tokens'],r['output_tokens'],r['finish_reason'],r['truncated'],r['outcome'])==(24,512,'length',True,'missing')
    assert r['context_tokens']==generation.get('num_ctx',generation.get('max_model_len'))
    assert r['output_allowance']==generation.get('num_predict',generation.get('max_tokens'))
    assert r['missing_category']=='empty_output'
    db=ConsoleDB(tmp_path/'console.db')
    try:
        db.publish_workspace_results(db.create_workspace('Local','local'),**rows)
    finally:
        db.close()


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
    save(run_id+".attempts.jsonl", attempts[:1], lines=True)
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
