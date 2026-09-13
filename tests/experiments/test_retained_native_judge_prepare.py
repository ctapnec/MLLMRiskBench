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


@pytest.fixture
def partial_source(tmp_path, monkeypatch):
    """Exercise selection reconstruction with a missing middle response."""
    root = tmp_path/'original'
    root.mkdir()
    for name in ('responses.jsonl', 'api.json', 'attacker.json', 'source.json'):
        (root/name).write_text('{}')
    grid = dict(grid_id='original', cells=[dict(run_id='run')], status='partial',
        request=dict(project_revision='original-revision'))
    (root/'original.grid.json').write_text(json.dumps(grid))
    points = [SimpleNamespace(id=key) for key in ('a', 'b', 'c')]
    attempts = {p.id:SimpleNamespace(id=p.id) for p in points}
    rows = {key:dict(attempt=dict(id=key,run_id='run',target='openai:saved',
        params=dict(retained_origin=dict(selection=dict(input_identity_sha256=key)))),
        response=dict(run_id='run',target='openai:saved',text='saved '+key)) for key in ('a','c')}
    dumps = {key:json.loads(json.dumps(row['attempt'])) for key,row in rows.items()}
    monkeypatch.setattr(subject, '_responses', lambda job:[
        (row['attempt'],row['response'],str(root/'responses.jsonl')+':1') for row in rows.values()])
    argv=['--api','openai:saved','--corpora','synth','--judges','rules,guardrail',
        '--attackers','replay','--target-answer-retries','0','--out',str(root)]
    for flag,name in (('--api-config','api.json'),('--source-config','source.json'),('--attacker-config','attacker.json')):
        argv.extend([flag,str(root/name)])
    value=dict(target='openai:saved',jobs=[dict(name='unit',argv=argv,input_ids=['a','b','c'])])
    monkeypatch.setattr(subject.run_matrix,'_load_api_config',lambda *a:({},{}))
    monkeypatch.setattr(subject.run_matrix,'build_target',lambda *a,**k:
        SimpleNamespace(name='openai:saved',modality_support=('text',)))
    monkeypatch.setattr(subject.run_matrix,'build_judges',lambda *a,**k:object())
    monkeypatch.setattr(subject.run_matrix,'_load_attacker_config',lambda *a:({'replay':{}},{}))
    monkeypatch.setattr(subject.run_matrix,'_load_source_config',lambda *a:({'synth':{}},{}))
    monkeypatch.setattr(subject.run_matrix,'load_corpus_with_audit',lambda *a,**k:(points,{}))
    monkeypatch.setattr(subject,'ReplayAttacker',lambda **k:SimpleNamespace(
        select_corpus=lambda name,corpus:corpus,generate=lambda point,budget:[attempts[point.id]]))
    reconstructed=[]
    def hashes(corpus, media):
        assert corpus==points  # Never hash the shortened retained subset.
        return {'corpus':'full-original-corpus'}
    def make_reader(attacker,target,*a,**k):
        return SimpleNamespace(target=target,
            _plan_attacker_input_contracts=lambda corpus:{(p.id,0):{} for p in corpus},
            _prepare_corpus=lambda corpus:(corpus,{}),_dataset_hashes=hashes,
            _prepare_attempt=lambda proposed,**kwargs:reconstructed.append(kwargs) or proposed,
            _restore_response=lambda attempt,record,run:None)
    monkeypatch.setattr(subject,'Runner',make_reader)
    monkeypatch.setattr(subject,'_portable_attempt_dump',lambda attempt:dumps[attempt.id])
    monkeypatch.setattr(subject,'_component_config',lambda component:{})
    return SimpleNamespace(path=tmp_path/'program.json',value=value,rows=rows,root=root,reconstructed=reconstructed)


def test_partial_reader_requires_opt_in_and_preserves_full_generation_condition(partial_source):
    f=partial_source
    original=(f.root/'original.grid.json').read_bytes()
    with pytest.raises(ValueError,match='population is incomplete'):
        subject.load_program_job(f.path,'unit',program=f.value)
    assert f.reconstructed==[]
    source,reader,inputs,records=subject.load_program_job(f.path,'unit',program=f.value,include_incomplete=True)
    assert set(inputs)==set(records)=={'a','c'}
    assert source['assigned']==2 and source['generation_assigned']==3
    assert source['unsaved_input_ids']==['b'] and source['incomplete_generation'] is True
    assert source['dataset_hashes']=={'corpus':'full-original-corpus'}
    assert source['runner_argv']==f.value['jobs'][0]['argv'] and len(f.reconstructed)==3
    assert (f.root/'original.grid.json').read_bytes()==original
    with pytest.raises(RuntimeError,match='cannot make a target call'):
        reader.target.generate([])


@pytest.mark.parametrize('mutation',['empty','foreign','duplicate','wrong-model','changed-attempt'])
def test_partial_opt_in_does_not_accept_invalid_saved_outputs(partial_source,mutation):
    f=partial_source
    if mutation=='empty':f.rows.clear()
    elif mutation=='foreign':
        f.rows['a']['attempt']['params']['retained_origin']['selection']['input_identity_sha256']='foreign'
    elif mutation=='duplicate':f.rows['duplicate']=f.rows['a']
    elif mutation=='wrong-model':f.rows['a']['response']['target']='openai:other'
    else:f.rows['a']['attempt']['extra']='changed'
    with pytest.raises(ValueError):
        subject.load_program_job(f.path,'unit',program=f.value,include_incomplete=True)


def test_tools_partial_option_reaches_preparation(tmp_path,monkeypatch):
    path,digest=program(tmp_path)
    argv=build_argv('retained_native_judge_prepare',{'--program':str(path),'--program-sha256':digest,
        '--out':str(tmp_path/'out'),'--include-incomplete':'on'})
    seen=[]
    monkeypatch.setattr(subject,'load_program_job',lambda *a,**k:seen.append(k) or (
        dict(run_id='run'),object(),{'a':object()},{}))
    assert subject.main(argv[argv.index('experiments.retained_native_judge_prepare')+1:])==0
    assert seen[0]['include_incomplete'] is True


def test_generation_artifacts_select_actual_run_among_failed_retries(tmp_path):
    # Real recovery directories retain both the responding run and a later
    # zero-response failure. Neither directory order nor latest timestamp owns
    # the earlier response's generation condition.
    for grid, run in [('grid-c907', 'run-bfa1'), ('grid-c50f', 'run-cecf')]:
        (tmp_path/(grid+'.grid.json')).write_text(json.dumps(dict(grid_id=grid,
            cells=[dict(run_id=run, status='error')], request=dict(project_revision=run))))
        (tmp_path/(run+'.manifest.json')).write_text(json.dumps(dict(run_id=run,
            config=dict(run=dict(grid_id=grid)))))
    path, grid, manifest_path, manifest = subject.generation_artifacts(tmp_path, 'run-bfa1')
    assert path.name == 'grid-c907.grid.json'
    assert grid['request']['project_revision'] == 'run-bfa1'
    assert manifest_path.name == 'run-bfa1.manifest.json' and manifest['run_id'] == 'run-bfa1'


@pytest.mark.parametrize('mutation', ['unrelated', 'duplicate-grid', 'wrong-manifest-grid', 'duplicate-manifest'])
def test_generation_artifacts_never_guess_an_ambiguous_binding(tmp_path, mutation):
    grid = dict(grid_id='original', cells=[dict(run_id='run')])
    manifest = dict(run_id='run', config=dict(run=dict(grid_id='original')))
    if mutation == 'unrelated':grid['cells'][0]['run_id'] = 'other'
    if mutation == 'wrong-manifest-grid':manifest['config']['run']['grid_id'] = 'other'
    (tmp_path/'original.grid.json').write_text(json.dumps(grid))
    (tmp_path/'original.manifest.json').write_text(json.dumps(manifest))
    if mutation == 'duplicate-grid':(tmp_path/'duplicate.grid.json').write_text(json.dumps(grid))
    if mutation == 'duplicate-manifest':(tmp_path/'duplicate.manifest.json').write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match='original grid|several native manifests|different original grid'):
        subject.generation_artifacts(tmp_path, 'run')


def test_response_only_source_keeps_its_single_unfinished_grid(tmp_path):
    grid = dict(grid_id='unfinished', cells=[], status='running')
    (tmp_path/'unfinished.grid.json').write_text(json.dumps(grid))
    path, selected, manifest_path, manifest = subject.generation_artifacts(tmp_path, 'saved-run')
    assert selected == grid and path.name == 'unfinished.grid.json'
    assert manifest_path is manifest is None
    (tmp_path/'ambiguous.grid.json').write_text(json.dumps(grid))
    with pytest.raises(ValueError, match='one original grid'):
        subject.generation_artifacts(tmp_path, 'saved-run')


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
