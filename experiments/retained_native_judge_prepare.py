"""Prepare native local judging of retained hosted outputs, without model calls.

This reusable reader accepts ordinary prepared program references. It does not
depend on campaign phases, a particular rig, a controller state or an RR run.
Preparation records original generation provenance; it does not manufacture a
missing manifest or promote a partial generation run into completed evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from experiments import run_matrix
from experiments.hosted_campaign_budget import load_bound_json
from experiments.retained_judge_media import reader_media_roots
from experiments.retained_response_judge_execute import _write_atomic, _write_new
from experiments.rig_web_app.workspace_import import _responses
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.artifact_checks import artifact_verification_cli
from ura.data_models import RunManifest
from ura.runner import Runner, _component_config, _portable_attempt_dump
from ura.targets.base import BaseTarget


class NoCalls(BaseTarget):
    """The existing retained-scoring pattern: no live target exists in Reader."""
    def __init__(self, target, *, program=None):
        self.name = target.name
        self.modality_support = target.modality_support
        self.media_roots = reader_media_roots(program or {}, getattr(target, 'media_roots', ()))

    def generate(self, *args, **kwargs):
        raise RuntimeError('Retained judging cannot make a target call')


def read(path):
    return json.loads(Path(path).read_text())


def metadata(path):
    stat = path.stat()
    return dict(path=str(path), bytes=stat.st_size, inode=stat.st_ino,
                mtime_ns=stat.st_mtime_ns, ctime_ns=stat.st_ctime_ns)


def load_program_job(program_path: Path, job_name: str, *, program: dict | None = None):
    program = read(program_path) if program is None else program
    job = next(item for item in program['jobs'] if item['name'] == job_name)
    args = run_matrix.build_parser().parse_args(job['argv'])
    if args.judges != 'rules,guardrail':
        raise ValueError('Original scoring cascade differs')
    if args.target_answer_retries != 0 or args.attackers != 'replay':
        raise ValueError('Retained hosted source must preserve replay and its no-answer-retry policy')
    if (args.api != program['target'] or args.local or not job['input_ids']
            or len(set(job['input_ids'])) != len(job['input_ids'])):
        raise ValueError('Retained program target or exact input selection differs')
    out = Path(args.out)
    grids = list(out.glob('*.grid.json'))
    if len(grids) != 1:
        raise ValueError('Expected one original grid')
    grid = read(grids[0])
    records = {}
    files = {str(grids[0]): metadata(grids[0])}
    observed_ids = set()
    for attempt, response, locator in _responses(job):
        key = attempt['params']['retained_origin']['selection']['input_identity_sha256']
        if key not in job['input_ids'] or key in observed_ids:
            raise ValueError('Checkpoint input identity differs')
        observed_ids.add(key)
        if response['run_id'] != attempt['run_id']:
            raise ValueError('Checkpoint run identity differs')
        if response['target'] != attempt['target'] or attempt['target'] != program['target']:
            raise ValueError('Checkpoint requested model differs')
        records[attempt['id']] = dict(attempt=attempt, response=response)
        path = Path(locator.rsplit(':', 1)[0])
        files[str(path)] = metadata(path)
    if observed_ids != set(job['input_ids']):
        raise ValueError('Retained target population is incomplete')
    run_ids = {record['response']['run_id'] for record in records.values()}
    if len(run_ids) != 1:
        raise ValueError('Retained responses do not belong to one generation run')
    run_id = next(iter(run_ids))
    configs, _ = run_matrix._load_api_config(args.api_config, [program['target']], args.api_config_sha256)
    target = run_matrix.build_target(program['target'], api_config=configs.get(program['target']))
    def no_generation(*args, **kwargs):
        raise RuntimeError('Retained judging cannot make a target call')
    target.generate = no_generation
    cascade = run_matrix.build_judges(['rules', 'guardrail'], 'mock',
        guardrail_model=args.guardrail_model, guardrail_revision=args.guardrail_revision,
        guardrail_device=args.guardrail_device)
    config, _ = run_matrix._load_attacker_config(args.attacker_config, ['replay'], args.attacker_config_sha256)
    attacker = ReplayAttacker(**config['replay'])
    instances, _ = run_matrix._load_source_config(args.source_config, [args.corpora], args.source_config_sha256)
    corpus, _ = run_matrix.load_corpus_with_audit(args.corpora, 0, 0, source_instance=instances[args.corpora])
    corpus = attacker.select_corpus(args.corpora, corpus)
    budget = AttackBudget(max_queries=args.max_queries, max_turns=args.max_turns, seed=0)
    reader = Runner(ReplayAttacker(), NoCalls(target, program=program), cascade, budget, [0], target_answer_retries=0,
                    execution_stage='judgments', stop_on_failed_output=False,
                    approximate_common_metrics=bool(args.approximate_common_metrics))
    reader.attacker = attacker
    contracts = reader._plan_attacker_input_contracts(corpus)
    corpus, media = reader._prepare_corpus(corpus)
    hashes = reader._dataset_hashes(corpus, media)
    inputs = {}
    for point in corpus:
        for index, proposed in enumerate(attacker.generate(point, budget)):
            attempt = reader._prepare_attempt(proposed, dp=point, seed=0, logical_turn=index,
                run_id=run_id, corpus_hash=hashes['corpus'], stateful=False, input_contract=contracts[(point.id, 0)])
            if _portable_attempt_dump(attempt) != records[attempt.id]['attempt']:
                raise ValueError('Reconstructed attempt differs')
            reader._restore_response(attempt, records[attempt.id], run_id)
            inputs[attempt.id] = (point, attempt)
    if set(inputs) != set(records):
        raise ValueError('Reconstructed input population differs from its saved responses')
    manifests = list(out.glob('*.manifest.json'))
    if len(manifests) > 1:
        raise ValueError('Retained source has several native manifests')
    if manifests:
        manifest = RunManifest.model_validate(read(manifests[0]), strict=True)
        if manifest.run_id != run_id or manifest.dataset_hashes != hashes:
            raise ValueError('Manifest dataset identity differs')
        if manifest.config['components']['attacker'] != _component_config(attacker):
            raise ValueError('Manifest attacker condition differs')
        if manifest.config['components']['target'] != _component_config(target):
            raise ValueError('Manifest target condition differs')
        if manifest.config['components']['judge_cascade'] != _component_config(cascade):
            raise ValueError('Manifest judge condition differs')
        files[str(manifests[0])] = metadata(manifests[0])
    for path in (Path(args.attacker_config), Path(args.source_config), Path(args.api_config)):
        files[str(path)] = metadata(path)
    source = dict(program=str(program_path), job=job_name, out=str(out), run_id=run_id,
        assigned=len(inputs), target=program['target'], has_native_manifest=bool(manifests),
        generation_project_revision=grid['request']['project_revision'],
        approximate_common_metrics=bool(args.approximate_common_metrics),
        target_component=_component_config(target), judge_cascade=_component_config(cascade),
        dataset_hashes=hashes, files=list(files.values()), runner_argv=list(job['argv']),
        generation_start_reconstructed=False, target_calls=0, judge_calls=0)
    return source, reader, inputs, records


def prepare(*, programs: Sequence[tuple[Path, str]], out: Path, jobs: Sequence[str] = ()) -> dict:
    """Retain an exact source inventory for the separate local scoring stage."""
    if not programs or len({str(path.resolve()) for path, _ in programs}) != len(programs):
        raise ValueError("Select each retained program exactly once")
    if out.exists() or out.is_symlink() or not out.is_absolute() or out.parent.resolve(strict=True) != out.parent:
        raise ValueError("Judging preparation needs a fresh resolved output directory")
    documents = [(path, *load_bound_json(path, digest)) for path, digest in programs]
    requested = set(jobs)
    known = {job["name"] for _, program, _ in documents for job in program["jobs"]}
    if requested - known:
        raise ValueError("Selected judging job is not in the supplied programs")
    out.mkdir(mode=0o700)
    units, failed, seen = [], [], set()
    for path, program, _descriptor in documents:
        for job in program["jobs"]:
            if requested and job["name"] not in requested:
                continue
            try:
                source, _reader, inputs, _records = load_program_job(path, job["name"], program=program)
                identities = {source["run_id"]+":"+key for key in inputs}
                if seen & identities:
                    raise ValueError("One output was selected through several jobs")
                seen.update(identities)
                units.append(source)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
                error_path = out / ("source-error-" + str(len(failed) + 1) + ".json")
                _write_new(error_path, dict(program=str(path), job=job["name"],
                    error_type=type(exc).__name__, message=str(exc)[:2000]))
                failed.append(dict(program=str(path), job=job["name"], error_type=type(exc).__name__,
                    assigned=len(job["input_ids"]), error_ref=str(error_path)))
            _write_atomic(out/"progress.json", dict(stage="preparing_local_judging",
                prepared_outputs=len(seen), prepared_jobs=len(units), failed=failed,
                target_calls=0, judge_calls=0, model_loads=0))
    result = dict(status="preparation_incomplete" if failed else "prepared",
        programs=[dict(path=str(path.resolve()), **descriptor) for path, _, descriptor in documents],
        units=units, failed=failed, outputs=len(seen), target_calls=0, judge_calls=0, model_loads=0,
        judgments="not_executed", original_artifacts_changed=False)
    _write_new(out/"result.json", result)
    return result


@artifact_verification_cli
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, action="append", required=True)
    parser.add_argument("--program-sha256", action="append", required=True)
    parser.add_argument("--job", action="append", default=[], help="Optional exact job names; defaults to all supplied jobs")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verify-artifact-sha256", action="store_true")
    args = parser.parse_args(argv)
    if len(args.program) != len(args.program_sha256):
        parser.error("Supply one matching program digest for each program")
    result = prepare(programs=list(zip(args.program, args.program_sha256)), out=args.out, jobs=args.job)
    print(json.dumps({key:value for key,value in result.items() if key not in {"units", "programs"}}))
    return 0 if result["status"] == "prepared" else 1


if __name__ == "__main__":
    raise SystemExit(main())
