"""Use real Runner records to exercise local judging, recovery and publication."""
import copy
import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from experiments import retained_native_judge_execute as subject
from experiments.retained_native_judge_prepare import NoCalls
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.data_models import DataPoint, DialogTurn, Response, RiskCategory
from ura.judges.base import JudgeCascade
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.runner import Runner, _component_config
from ura.targets.base import BaseTarget


def cascade(outputs=None):
    guard = GuardrailJudge(model="meta-llama/Llama-Guard-3-8B", revision="b"*40,
        device="cuda:0", max_new_tokens=20)
    calls = []
    guard._ensure_loaded = lambda: None
    def classify(conversation):
        calls.append(conversation)
        value = outputs[len(calls)-1] if outputs is not None else "unsafe\nS1"
        if isinstance(value, BaseException):
            raise value
        return value
    guard._run_guard = classify
    return JudgeCascade([RuleJudge(), guard]), calls


@pytest.fixture
def retained(tmp_path):
    class Target(BaseTarget):
        name = "openai:saved"
        modality_support = ("text", "image")
        def generate(self, dialog, *, seed=None):
            return Response(attempt_id="pending", target=self.name,
                output_turns=[DialogTurn(role="assistant", content="fixture answer")], raw={"sampling_control":"seeded"})
    points = [DataPoint(id=key, source="unit", modalities=["text"], payload_text="fixture prompt",
        risk_category=RiskCategory.INFORMATION_SECURITY, expected_behavior="refuse") for key in ("a", "b")]
    judges, _ = cascade()
    runner = Runner(ReplayAttacker(), Target(), judges, AttackBudget(max_queries=1, max_turns=1, seed=0), [0])
    responses, judgments = [], []
    _, manifest = runner.run(points, on_response=responses.append, on_record=judgments.append)
    original = tmp_path/"original"
    original.mkdir()
    source = dict(out=str(original), run_id=manifest.run_id, assigned=2, target=Target.name,
        judge_cascade=_component_config(judges), generation_project_revision=dict(expected_commit="a"*40),
        files=[], program=str(tmp_path/"program.json"), job="unit")
    inputs = {a.id:(next(p for p in points if p.id == a.datapoint_id),a) for a in runner.attempts}
    def reader():
        result = Runner(ReplayAttacker(), NoCalls(Target()), cascade()[0],
            AttackBudget(max_queries=1, max_turns=1, seed=0), [0], execution_stage="judgments")
        return result
    return SimpleNamespace(source=source, inputs=inputs, responses={r["attempt"]["id"]:r for r in responses},
        judgments=judgments, reader=reader)


def score(retained, tmp_path, monkeypatch, outputs=None, publication=None):
    judges, calls = cascade(outputs)
    monkeypatch.setattr(subject, "source_cascade", lambda condition,runtime: judges)
    runtime_calls = []
    result = subject.score_unit(retained.source, retained.reader(), retained.inputs, retained.responses,
        out=tmp_path/"scoring", revision="c"*40, publication=publication,
        runtime_factory=lambda *a,**k: runtime_calls.append(k) or object())
    return result, calls, runtime_calls


def test_only_pending_outputs_are_judged_and_resume_needs_no_model(retained, tmp_path, monkeypatch):
    from pathlib import Path
    original = Path(retained.source["out"])/"original.checkpoint.jsonl"
    Runner.append_checkpoint(original, retained.judgments[0])
    before = original.read_bytes()
    result, calls, runtimes = score(retained, tmp_path, monkeypatch)
    assert result["existing_judgments"] == result["completed_judgments"] == len(calls) == 1
    assert runtimes == [dict(verify_model_sha256=False)]
    checkpoint = (tmp_path/"scoring/judgments.checkpoint.jsonl").read_bytes()
    resumed, calls, runtimes = score(retained, tmp_path, monkeypatch)
    assert resumed["newly_scored_this_execution"] == 0 and calls == runtimes == []
    assert (tmp_path/"scoring/judgments.checkpoint.jsonl").read_bytes() == checkpoint
    assert original.read_bytes() == before
    assert result["target_calls"] == result["hosted_calls"] == 0


def test_unparsed_judge_output_is_retained_and_next_output_still_scored(retained, tmp_path, monkeypatch):
    result, calls, _ = score(retained, tmp_path, monkeypatch, outputs=["gibberish", "unsafe\nS1"])
    assert result["invalid_judgments"] == result["completed_judgments"] == 1 and len(calls) == 2
    failure = json.loads(next((tmp_path/"scoring/evaluator-failures").glob("*.json")).read_text())
    assert failure["trail"][-1]["raw"]["parsed"] is False
    result, calls, runtimes = score(retained, tmp_path, monkeypatch)
    assert result["invalid_judgments"] == 1 and calls == runtimes == []


def test_infrastructure_failure_preserves_prefix_for_continuation(retained, tmp_path, monkeypatch):
    with pytest.raises(subject.ExternalCallFailure):
        score(retained, tmp_path, monkeypatch, outputs=["unsafe\nS1", RuntimeError("fixture infrastructure")])
    assert len((tmp_path/"scoring/judgments.checkpoint.jsonl").read_text().splitlines()) == 1
    result, calls, _ = score(retained, tmp_path, monkeypatch)
    assert result["completed_judgments"] == 2 and len(calls) == 1


def test_changed_checkpoint_is_rejected_before_any_new_judge(retained, tmp_path, monkeypatch):
    score(retained, tmp_path, monkeypatch)
    path = tmp_path/"scoring/judgments.checkpoint.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[0]["response"]["output_turns"][0]["content"] = "Changed output"
    path.write_text("\n".join(json.dumps(row) for row in rows)+"\n")
    monkeypatch.setattr(subject, "source_cascade", lambda *a: pytest.fail("model constructed before checkpoint read"))
    with pytest.raises(ValueError, match="changed its saved answer"):
        subject.score_unit(retained.source, retained.reader(), retained.inputs, retained.responses,
            out=tmp_path/"scoring", revision="c"*40,
            runtime_factory=lambda *a,**k: pytest.fail("runtime admitted before checkpoint read"))


def test_execution_preserves_identity_and_refuses_source_writes(retained, tmp_path, monkeypatch):
    monkeypatch.setattr(subject.sources, "load_program_job", lambda *a,**k:
        (retained.source, retained.reader(), retained.inputs, retained.responses))
    judges, calls = cascade()
    monkeypatch.setattr(subject, "source_cascade", lambda *a: judges)
    monkeypatch.setattr(subject, "source_runtime", lambda *a,**k: object())
    value = dict(status="prepared", units=[retained.source], failed=[])
    path = tmp_path/"preparation.json"
    path.write_text(json.dumps(value))
    kwargs = dict(preparation=path, preparation_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        out=tmp_path/"execution", revision="c"*40)
    assert subject.execute(**kwargs)["status"] == "complete"
    assert subject.execute(**kwargs)["status"] == "complete" and len(calls) == 2
    with pytest.raises(ValueError, match="scoring revision"):
        subject.execute(**{**kwargs, "revision":"d"*40})
    with pytest.raises(ValueError, match="overlaps original"):
        subject.execute(**{**kwargs, "out":tmp_path/"original/new"})


def test_same_judge_is_kept_resident_across_jobs(retained, monkeypatch):
    calls, closed = [], []
    judges, _ = cascade()
    judges.stages[1].close = lambda: closed.append(True)
    monkeypatch.setattr(subject, "source_runtime", lambda *a,**k: calls.append(True) or object())
    monkeypatch.setattr(subject, "source_cascade", lambda *a: judges)
    cache = subject.CascadeCache()
    assert cache.get(retained.source) is cache.get(copy.deepcopy(retained.source))
    assert calls == [True] and closed == []
    cache.close()
    assert closed == [True]


def test_partial_execution_keeps_original_pending_coverage_on_resume(retained,tmp_path,monkeypatch):
    retained.source.update(incomplete_generation=True,generation_assigned=3,unsaved_input_ids=['not-saved'])
    seen=[]
    def load(*a,**kwargs):
        seen.append(kwargs)
        assert kwargs['include_incomplete'] is True
        return retained.source,retained.reader(),retained.inputs,retained.responses
    monkeypatch.setattr(subject.sources,'load_program_job',load)
    judges,calls=cascade()
    monkeypatch.setattr(subject,'source_cascade',lambda *a:judges)
    monkeypatch.setattr(subject,'source_runtime',lambda *a,**k:object())
    artifact=tmp_path/'source.json'
    artifact.write_text('{}')
    retained.source['files']=[subject.sources.metadata(artifact)]
    path=tmp_path/'prepared.json'
    path.write_text(json.dumps(dict(status='prepared',units=[retained.source],failed=[])))
    kwargs=dict(preparation=path,preparation_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        out=tmp_path/'judging',revision='c'*40)
    for _ in range(2):
        result=subject.execute(**kwargs)
        assert result['status']=='complete' and result['units'][0]['source']['unsaved_input_ids']==['not-saved']
        assert result['target_calls']==0
    assert len(calls)==2 and len(seen)==2
    artifact.write_text('appended response')
    assert subject.execute(**kwargs)['status']=='continuation_required'
    assert len(calls)==2 and len(seen)==2


@pytest.mark.parametrize("index_failure", [False, True])
def test_durable_judgments_publish_by_output_and_resume_repairs_index(retained, tmp_path, monkeypatch, index_failure):
    from experiments.rig_web_app.storage import ConsoleDB
    from experiments.rig_web_app.workspace_native_judging import NativeJudgmentPublication
    db = ConsoleDB(tmp_path/"console.db")
    campaign = db.create_workspace("Saved API outputs", "api")
    for key in retained.inputs:
        identity = retained.source["run_id"]+":"+key
        db.publish_workspace_results(campaign, assignments=[dict(assignment_id=identity, model=retained.source["target"],
            input_id="same-question", condition_id="generation", modality="text", framework="replay", corpus="unit",
            response_id=identity, evidence_class="measured")], responses=[dict(response_id=identity, assignment_id=identity,
                condition_id="generation", outcome="usable", truncated=False, source_ref="original")], judgments=[])
    original = ConsoleDB.publish_workspace_costs
    if index_failure:
        monkeypatch.setattr(ConsoleDB, "publish_workspace_costs", lambda *a,**k: (_ for _ in ()).throw(ValueError("private fixture")))
    publisher = NativeJudgmentPublication(database=db.path, campaign_id=campaign, root=tmp_path/"scoring")
    result, calls, _ = score(retained, tmp_path, monkeypatch, outputs=["gibberish", "unsafe\nS1"], publication=publisher)
    publisher.close()
    assert result["status"] == "complete" and len(calls) == 2
    if not index_failure:
        assert len(db._query("SELECT * FROM campaign_judgments")) == 2
    status = tmp_path/"scoring/publication.json"
    assert "private fixture" not in status.read_text()
    if index_failure:
        assert json.loads(status.read_text())["status"] == "publication_pending"
        monkeypatch.setattr(ConsoleDB, "publish_workspace_costs", original)
    publisher = NativeJudgmentPublication(database=db.path, campaign_id=campaign, root=tmp_path/"scoring")
    _, calls, runtimes = score(retained, tmp_path, monkeypatch, publication=publisher)
    publisher.close()
    assert calls == runtimes == []
    assert json.loads(status.read_text())["status"] == "published"
    assert {row["status"] for row in db._query("SELECT status FROM campaign_judgments")} == {"valid", "invalid"}
    assert len(db._query("SELECT * FROM campaign_cost_attempts")) == 2
    db.close()


def test_publication_never_copies_a_verdict_to_another_models_answer(tmp_path):
    from experiments.rig_web_app.storage import ConsoleDB
    from experiments.rig_web_app.workspace_native_judging import NativeJudgmentPublication
    db = ConsoleDB(tmp_path/"console.db")
    campaign = db.create_workspace("Other model", "api")
    db.publish_workspace_results(campaign, assignments=[dict(assignment_id="assignment", model="openai:other",
        input_id="same-question", condition_id="generation", modality="text", framework="replay", corpus="unit",
        response_id="run:answer", evidence_class="measured")], responses=[dict(response_id="run:answer", assignment_id="assignment",
        condition_id="generation", outcome="usable", truncated=False, source_ref="original")], judgments=[])
    source = dict(target="openai:saved", run_id="run", judge_cascade=_component_config(cascade()[0]))
    record = dict(response=dict(target="openai:saved", run_id="run", attempt_id="answer"),
        judgment=dict(run_id="run", attempt_id="answer", label="safe"))
    publisher = NativeJudgmentPublication(database=db.path, campaign_id=campaign, root=tmp_path)
    publisher.accept(source, record, "retained.jsonl:1", "a"*40)
    publisher.close()
    assert not db._query("SELECT * FROM campaign_judgments")
    assert json.loads((tmp_path/"publication.json").read_text())["status"] == "publication_pending"
    db.close()


def test_unrecognized_original_cascade_setting_is_not_silently_ignored():
    condition = _component_config(cascade()[0])
    condition["unrecognized_setting"] = True
    with pytest.raises(ValueError, match="changed the selected cascade"):
        subject.source_cascade(condition, object())


def test_ui_cli_and_environment_have_judging_role_without_provider_keys(tmp_path, monkeypatch):
    from experiments.rig_web_app.catalog import build_argv
    from experiments.rig_web_app.lifecycle import LifecycleMixin
    from experiments.rig_web_app.workspace_store import activity_role
    values = {"--preparation":str(tmp_path/"prepared.json"), "--preparation-sha256":"a"*64, "--out":str(tmp_path/"out")}
    argv = build_argv("retained_native_judge_execute", values)
    assert "--verify-model-sha256" not in argv and "--verify-artifact-sha256" not in argv
    seen = []
    monkeypatch.setattr(subject, "execute", lambda **k: seen.append(k) or dict(status="complete"))
    monkeypatch.setenv("URA_CAMPAIGN_WORKSPACE_ID", "selected")
    monkeypatch.setenv("URA_CAMPAIGN_CONSOLE_DB", str(tmp_path/"console.db"))
    assert subject.main(argv[argv.index("experiments.retained_native_judge_execute")+1:]) == 0
    assert seen[0]["workspace_id"] == "selected" and seen[0]["console_db"] == tmp_path/"console.db"
    assert activity_role("retained_native_judge_execute") == "judging"
    fake = SimpleNamespace(repo_root=tmp_path,_MATRIX_BASE_ENV={"PATH"}, _MATRIX_OPTIONAL_ENV={"URA_MEDIA_ROOTS"}, _MATRIX_RECEIPT_ENV=set(),
        _strict_config_document=lambda *a:dict(units=[dict(runner_argv=["--api", "openai:example", "--source-config", "source.json", "--corpora", "sample"])]),
        _declared_matrix_environment=lambda values: {"SOURCE_ROOT"} if set(values) == {"--source-config", "--corpora"} else pytest.fail("unneeded environment"),
        _selected_child_environment=lambda names:dict.fromkeys(names,'test-value'))
    child=LifecycleMixin._generic_child_environment(fake, "retained_native_judge_execute", values)
    assert set(child) == {"PATH", "URA_MEDIA_ROOTS", "SOURCE_ROOT","PYTHONPATH"}
    assert child['PYTHONPATH']==os.pathsep.join((str(tmp_path),str(tmp_path/'src')))
