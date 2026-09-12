"""Native assessment preparation keeps exact outputs without model calls."""
import hashlib
import json
from types import SimpleNamespace

import pytest

from experiments import retained_native_judge_prepare as subject
from experiments.rig_web_app.catalog import build_argv


def program(tmp_path, name="route"):
    path = tmp_path / (name+".json")
    value = dict(target="openai:"+name, jobs=[dict(name=name, input_ids=["input-1"])])
    raw = json.dumps(value).encode()
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def test_preparation_retains_exact_membership_and_never_calls_a_model(tmp_path, monkeypatch):
    sources = [program(tmp_path, name) for name in ("first", "second")]
    calls = []
    def load(path, name, *, program):
        calls.append((path, name, program["target"]))
        return dict(run_id=name, target=program["target"], assigned=1), object(), {"answer": object()}, {}
    monkeypatch.setattr(subject, "load_program_job", load)
    out = tmp_path / "out"
    result = subject.prepare(programs=sources, out=out)
    assert result["status"] == "prepared" and result["outputs"] == 2
    assert result["target_calls"] == result["judge_calls"] == result["model_loads"] == 0
    assert [row[1] for row in calls] == ["first", "second"]
    assert result["judgments"] == "not_executed"
    assert json.loads((out/"result.json").read_text()) == result
    with pytest.raises(ValueError, match="fresh"):
        subject.prepare(programs=sources, out=out)


def test_incomplete_source_is_not_promoted_or_cancelled_across_other_jobs(tmp_path, monkeypatch):
    sources = [program(tmp_path, name) for name in ("first", "second")]
    def load(path, name, *, program):
        if name == "first":
            raise ValueError("Retained target population is incomplete")
        return dict(run_id=name), object(), {"answer": object()}, {}
    monkeypatch.setattr(subject, "load_program_job", load)
    result = subject.prepare(programs=sources, out=tmp_path/"out")
    assert result["status"] == "preparation_incomplete" and result["outputs"] == 1
    assert len(result["failed"]) == 1
    assert "incomplete" in json.loads((tmp_path/"out/source-error-1.json").read_text())["message"]


def test_duplicate_outputs_are_not_independent_judging_requests(tmp_path, monkeypatch):
    monkeypatch.setattr(subject, "load_program_job", lambda *a, **k: (
        dict(run_id="same-run"), object(), {"same-answer": object()}, {}))
    result = subject.prepare(programs=[program(tmp_path, "first"), program(tmp_path, "second")], out=tmp_path/"out")
    assert result["outputs"] == 1 and result["status"] == "preparation_incomplete"


def test_selection_and_cli_form_preserve_programs_and_exact_job_names(tmp_path, monkeypatch):
    first, second = program(tmp_path, "first"), program(tmp_path, "second")
    values = {"--program": str(first[0]), "--program-sha256": first[1],
        "--program#1": str(second[0]), "--program-sha256#1": second[1],
        "--job": "second", "--out": str(tmp_path/"out")}
    argv = build_argv("retained_native_judge_prepare", values)
    called = []
    monkeypatch.setattr(subject, "load_program_job", lambda path,name,**k: called.append(name) or (
        dict(run_id=name), object(), {"answer": object()}, {}))
    assert subject.main(argv[argv.index("experiments.retained_native_judge_prepare")+1:]) == 0
    assert called == ["second"]
    assert "--verify-artifact-sha256" not in argv
    with pytest.raises(ValueError, match="not in"):
        subject.prepare(programs=[first], out=tmp_path/"bad", jobs=["unknown"])
    assert not (tmp_path/"bad").exists()


@pytest.mark.parametrize("mutation", ["wrong-model", "missing-input"])
def test_reader_rejects_wrong_or_incomplete_outputs_before_target_construction(tmp_path, monkeypatch, mutation):
    root = tmp_path/"source"
    root.mkdir()
    (root/"original.grid.json").write_text('{}')
    argv = ["--out", str(root), "--api", "openai:expected", "--corpora", "synth",
        "--judges", "rules,guardrail", "--attackers", "replay", "--target-answer-retries", "0"]
    value = dict(target="openai:expected", jobs=[dict(name="unit", argv=argv, input_ids=["input"])])
    attempt = dict(id="answer", run_id="run", target="openai:expected",
        params=dict(retained_origin=dict(selection=dict(input_identity_sha256="input"))))
    response = dict(run_id="run", target="openai:wrong")
    monkeypatch.setattr(subject, "_responses", lambda job: [] if mutation == "missing-input" else
        [(attempt,response,str(root/"responses.jsonl")+":1")])
    monkeypatch.setattr(subject.run_matrix, "build_target", lambda *a, **k: pytest.fail("constructed target before membership check"))
    with pytest.raises(ValueError, match="requested model differs|population is incomplete"):
        subject.load_program_job(tmp_path/"program.json", "unit", program=value)


def test_reader_target_is_not_capable_of_generation():
    reader = subject.NoCalls(SimpleNamespace(name="openai:retained", modality_support=("text",)))
    with pytest.raises(RuntimeError, match="cannot make a target call"):
        reader.generate([])


def test_preparation_environment_forwards_source_locators_not_provider_credentials():
    from experiments.rig_web_app.catalog import COMMANDS
    from experiments.rig_web_app.lifecycle import LifecycleMixin
    seen = []
    def source_environment(values):
        seen.append(values)
        assert set(values) == {"--source-config", "--corpora"}
        return {"SOURCE_DATA_ROOT"}
    fake = SimpleNamespace(commands=COMMANDS, _MATRIX_BASE_ENV={"PATH"},
        _MATRIX_OPTIONAL_ENV={"URA_MEDIA_ROOTS"}, _MATRIX_RECEIPT_ENV=set(),
        _strict_config_document=lambda *a: dict(jobs=[dict(argv=["--api", "openai:example",
            "--api-config", "private-api.json", "--source-config", "source.json", "--corpora", "sample",
            "--attacker-config", "attacker.json", "--out", "out"])]),
        _declared_matrix_environment=source_environment,
        _selected_matrix_environment_names=lambda *a: pytest.fail("preparation requested provider credentials"),
        _selected_child_environment=lambda values: values)
    result = LifecycleMixin._generic_child_environment(fake, "retained_native_judge_prepare",
        {"--program": "program.json", "--program-sha256": "a"*64})
    assert result == {"PATH", "URA_MEDIA_ROOTS", "SOURCE_DATA_ROOT"}
    assert len(seen) == 1
