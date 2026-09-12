import json
from copy import deepcopy
from types import SimpleNamespace

import pytest

from experiments.hosted_retained_inputs import _sha, retained_input_identity
from experiments.rig_web_app import workspace_local as subject
from experiments.rig_web_app.storage import ConsoleDB


def example(tmp_path, model):
    db = ConsoleDB(tmp_path / "console.db")
    campaign = db.create_workspace("Local collection", "local")
    run = dict(model_spec=model, corpus="sample", execution_purpose="measured_run", target_answer_retries=1,
        judge_names=["rules", "guardrail"], guardrail_model="local-guard")
    manifest = dict(run_id="run-sample", config=dict(run=run), dataset_hashes=dict(corpus="a"*64))
    dp = SimpleNamespace(id="question-1", source="sample-source", risk_category="violence", expected_behavior="refuse")
    attempt = dict(id="attempt-1", run_id=manifest["run_id"], target=model, datapoint_id=dp.id,
        attacker="replay", seed=0, turn_index=0, rendered_input=[dict(role="user", content="A question", media=[])],
        params=dict(source_cluster_id=dp.id, planning_source=dp.source, planning_expected_behavior=dp.expected_behavior))
    response = dict(run_id=manifest["run_id"], attempt_id=attempt["id"], target=model,
        output_turns=[dict(role="assistant", content="A retained answer")],
        tokens=dict(prompt=17, completion=4096), raw=dict(finish_reason="length", output_truncated=True,
            generation=dict(num_ctx=32768, num_predict=4096)))
    record = dict(attempt=attempt, response=response)
    paths = dict(checkpoint=tmp_path / "cell.checkpoint.jsonl", response_checkpoint=tmp_path / "cell.responses.checkpoint.jsonl")
    return db, campaign, manifest, dp, record, paths


def append(path, record):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record)+"\n")


@pytest.mark.parametrize("model", ["ollama:example", "vllm:example"])
def test_native_publication_uses_durable_output_and_retains_input_identity(tmp_path, model):
    db, campaign, manifest, dp, record, paths = example(tmp_path, model)
    kwargs = dict(run_config=manifest["config"]["run"], manifest=SimpleNamespace(model_dump=lambda **k: manifest),
        on_response=lambda row: append(paths["response_checkpoint"], row),
        on_record=lambda row: append(paths["checkpoint"], row))

    class Runner:
        def run(self, corpus, **options):
            options["on_response"](record)
            # Publication must be visible before judging, not only after run().
            assert paths["response_checkpoint"].is_file()
            assert db.workspace_model_totals(campaign)[0]["truncated"] == 1
            assert db.workspace_judging_totals(campaign) == []
            options["on_record"]({**record, "judgment":dict(run_id=manifest["run_id"], attempt_id="attempt-1", label="safe", raw={})})
            return "unchanged-return"

    assert subject.run_with_workspace_publication(Runner(), [dp], campaign_id=campaign,
        database=db.path, **paths, **kwargs) == "unchanged-return"
    assignment = db._query("SELECT * FROM campaign_assignments")[0]
    assert assignment["input_id"] == _sha(retained_input_identity(manifest["config"]["run"], "a"*64, record["attempt"], vars(dp)))
    details = json.loads(db._query("SELECT details FROM campaign_responses")[0]["details"])
    assert (details["context_tokens"], details["output_allowance"], details["input_tokens"], details["output_tokens"]) == (32768,4096,17,4096)
    assert len(db._query("SELECT * FROM campaign_judgments")) == 1
    assert db.workspace_cost_totals(campaign) == []
    before = paths["response_checkpoint"].read_bytes()
    restored = subject.LocalCheckpointPublication(campaign_id=campaign, database=db.path, manifest=manifest, corpus=[dp], **paths)
    restored.accept(record, "response", restored=True)
    restored.close()
    assert paths["response_checkpoint"].read_bytes() == before
    assert db.workspace_model_totals(campaign)[0]["assigned"] == 1
    db.close()


def test_failed_publication_does_not_cancel_generation_and_retries_saved_records(tmp_path, monkeypatch):
    db, campaign, manifest, dp, record, paths = example(tmp_path, "ollama:example")
    publisher = subject.LocalCheckpointPublication(campaign_id=campaign, database=db.path, manifest=manifest, corpus=[dp], **paths)
    original = ConsoleDB.publish_workspace_results
    monkeypatch.setattr(ConsoleDB, "publish_workspace_results", lambda *a, **k: (_ for _ in ()).throw(ValueError("private data")))
    append(paths["response_checkpoint"], record)
    publisher.accept(record, "response")
    status = publisher.status_path.read_text()
    assert "publication_pending" in status and "private data" not in status
    assert db.workspace_model_totals(campaign) == []
    monkeypatch.setattr(ConsoleDB, "publish_workspace_results", original)
    publisher.flush()
    assert db.workspace_model_totals(campaign)[0]["usable"] == 1
    publisher.close()
    db.close()


def test_local_missing_output_is_published_without_a_fabricated_judgment(tmp_path):
    db, campaign, manifest, dp, record, paths = example(tmp_path, "vllm:example")
    record["response"]["output_turns"] = []
    record["response"]["raw"].update(model_stability_status="failed_output", model_stability_category="empty_output")
    append(paths["response_checkpoint"], record)
    publisher = subject.LocalCheckpointPublication(campaign_id=campaign, database=db.path, manifest=manifest, corpus=[dp], **paths)
    publisher.accept(record, "response", restored=True)
    assert db.workspace_model_totals(campaign)[0]["missing"] == 1
    assert db.workspace_model_totals(campaign)[0]["truncated"] == 1
    assert db.workspace_judging_totals(campaign) == []
    publisher.close()
    db.close()


def test_failed_durable_callback_prevents_publication(tmp_path):
    db, campaign, manifest, dp, record, paths = example(tmp_path, "ollama:example")
    class Runner:
        def run(self, corpus, **options):
            options["on_response"](record)
    with pytest.raises(OSError, match="disk"):
        subject.run_with_workspace_publication(Runner(), [dp], campaign_id=campaign, database=db.path,
            **paths, run_config=manifest["config"]["run"], manifest=SimpleNamespace(model_dump=lambda **k: manifest),
            on_response=lambda row: (_ for _ in ()).throw(OSError("disk")))
    assert db.workspace_model_totals(campaign) == []
    db.close()


def test_seed_and_media_changes_keep_different_input_identity(tmp_path):
    db, _, manifest, dp, record, _ = example(tmp_path, "ollama:example")
    baseline = retained_input_identity(manifest["config"]["run"], "a"*64, record["attempt"], vars(dp))
    changed = deepcopy(record["attempt"])
    changed["seed"] = 12
    assert retained_input_identity(manifest["config"]["run"], "a"*64, changed, vars(dp)) != baseline
    changed = deepcopy(record["attempt"])
    changed["rendered_input"][0]["media"] = [dict(modality="image", mime="image/png", sha256="b"*64, path="sha256:"+"b"*64)]
    image = retained_input_identity(manifest["config"]["run"], "a"*64, changed, vars(dp))
    assert image["modality"] == "image" and image["rendered_input_sha256"] != baseline["rendered_input_sha256"]
    db.close()


def test_judgment_checkpoint_promotes_to_final_without_changing_verdict(tmp_path):
    db, campaign, manifest, dp, record, paths = example(tmp_path, "ollama:example")
    record["judgment"] = dict(run_id=manifest["run_id"], attempt_id="attempt-1", label="safe", raw={})
    append(paths["checkpoint"], record)
    publisher = subject.LocalCheckpointPublication(campaign_id=campaign, database=db.path, manifest=manifest, corpus=[dp], **paths)
    publisher.accept(record, "judgment", restored=True)
    row = dict(db._query("SELECT * FROM campaign_judgments")[0])
    row["source_ref"] = str(tmp_path / "cell.jsonl")+":2"
    db.publish_workspace_results(campaign, assignments=[], responses=[], judgments=[row])
    row["label"] = "violation"
    with pytest.raises(ValueError, match="Retained judgment changed"):
        db.publish_workspace_results(campaign, assignments=[], responses=[], judgments=[row])
    publisher.close()
    db.close()
