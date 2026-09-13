"""Collect the selected funded hosted programs in parallel, then hand off judging.

Pass the exact prepared/attested program files, not a new random selection.
The shared budget, Runner retry policy and response checkpoints remain
authoritative. Run this detached command on the rig, including from Rig Web.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
from typing import Sequence

from experiments import hosted_retained_execute as retained
from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_campaign_budget import load_bound_json
from experiments.hosted_dispatch import dispatch_admitted
from experiments.retained_response_judge_execute import _write_atomic, _write_new
from ura.artifact_checks import artifact_verification_cli


@contextmanager
def _collection_lock(root):
    import fcntl

    with (root / 'collection.lock').open('a+b') as handle:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError('This collection or its continuation is already active') from exc
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _saved_job_complete(admission):
    """A terminal UI status alone cannot exclude paid work from continuation."""
    from experiments.rig_web_app.workspace_import import _responses
    from ura.adapters.replay import retained_dialog, retained_dialog_sha256

    seen = set()
    for attempt, response, _locator in _responses(admission.job):
        origin = attempt.get('params', {}).get('retained_origin', {})
        identity = origin.get('selection', {}).get('input_identity_sha256')
        entry = admission.entries.get(identity)
        if (entry is None or identity in seen or origin != entry['origin']
                or response['target'] != attempt['target'] or response['target'] != admission.program['target']
                or response['attempt_id'] != attempt['id'] or response['run_id'] != attempt['run_id']
                or retained_dialog_sha256(retained_dialog(attempt['rendered_input'])) != origin['delivered_input_sha256']):
            raise ValueError('Saved collection output differs from its admitted input/model')
        seen.add(identity)
    starts = admission.budget.reserved_attempt_counts([item['call_id'] for item in admission.requests.values()])
    if any(starts[admission.requests[key]['call_id']] < 1 for key in seen):
        raise ValueError('Saved collection output lacks its recorded physical attempt')
    return seen == set(admission.entries)


def _previous_selection(root, selection):
    if root.is_symlink() or not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ValueError('Previous collection must be one resolved directory')
    previous = json.loads((root / 'selection.json').read_text())
    for key in ('programs', 'assigned_target_inputs', 'budget_root', 'budget_plan_sha256',
                'project_root', 'expected_commit', 'workspace_id', 'console_db'):
        if previous.get(key) != selection[key]:
            raise ValueError('Continuation changed the selected programs, budget, revision or campaign owner')
    if (previous.get('prepare_runtime', False) != selection.get('prepare_runtime', False)
            or previous.get('model_store') != selection.get('model_store')):
        raise ValueError('Continuation changed its installed-runtime setting')
    return previous


def _completed_continuation_jobs(root, selection, admitted):
    _previous_selection(root, selection)
    path = root / 'result.json' if (root / 'result.json').is_file() else root / 'progress.json'
    rows = json.loads(path.read_text()).get('jobs', []) if path.is_file() else []
    completed = set()
    for row in rows:
        if row.get('status') != 'collected':
            continue
        p, j = row.get('program'), row.get('job')
        if type(p) is not int or type(j) is not int or not 0 <= p < len(admitted) or not 0 <= j < len(admitted[p]):
            raise ValueError('Previous collection job identity differs')
        admission = admitted[p][j]
        if row.get('name') != admission.job['name'] or row.get('target') != admission.program['target']:
            raise ValueError('Previous collection job identity differs')
        if _saved_job_complete(admission):
            completed.add((p, j))
    return frozenset(completed)


def collect_campaign(*, programs: Sequence[tuple[Path, str]], budget_root: Path,
                     budget_plan_sha256: str, project_root: Path, expected_commit: str,
                     out: Path, workers_per_provider: int = 2,
                     workspace_id: str = "", console_db: Path | None = None,
                     resume_from: Path | None = None, prepare_runtime: bool = False,
                     model_store: Path | None = None) -> dict:
    """Validate shared sources once, then collect without co-resident judges."""
    retained._validated_checkout(project_root, expected_commit)
    if not programs or len({str(path.resolve()) for path, _sha256 in programs}) != len(programs):
        raise ValueError("Select each funded program exactly once")
    if out.exists() or out.is_symlink() or not out.is_absolute() or out.parent.resolve(strict=True) != out.parent:
        raise ValueError("Campaign collection needs a fresh resolved output directory")
    if type(workers_per_provider) is not int or not 1 <= workers_per_provider <= 8:
        raise ValueError("Workers per provider must be an integer from 1 to 8")
    if bool(workspace_id) != (console_db is not None):
        raise ValueError("Campaign publication requires both workspace ID and console database")
    if type(prepare_runtime) is not bool:
        raise ValueError('Choose explicitly whether installed runtime preparation is required')
    if prepare_runtime and (model_store is None or not model_store.is_absolute()
            or model_store.resolve(strict=True) != model_store or not model_store.is_dir()):
        raise ValueError('Installed runtime preparation requires the existing resolved model store')
    budget = AttemptBudget(budget_root, budget_plan_sha256)
    contexts, admitted, references, call_ids = {}, [], [], set()
    prepared_programs = []
    for path, sha256 in programs:
        program, descriptor = load_bound_json(path, sha256)
        key = retained._local_context_key(program)
        if key not in contexts:
            contexts[key] = retained._validated_local_cells(program)
        jobs = retained._validated_jobs(program, budget, local_context=contexts[key])
        ids = {request["call_id"] for admission in jobs for request in admission.requests.values()}
        if call_ids & ids:
            raise ValueError("Selected programs overlap the same funded target calls")
        call_ids.update(ids)
        admitted.append(jobs)
        prepared_programs.append(program)
        references.append({"path": str(path.resolve()), **descriptor, "target": program["target"]})
    selection = dict(programs=references, assigned_target_inputs=len(call_ids),
        workers_per_provider=workers_per_provider, budget_root=str(budget_root),
        budget_plan_sha256=budget_plan_sha256, stage="target_collection", judgments="deferred",
        project_root=str(project_root), expected_commit=expected_commit,
        workspace_id=workspace_id, console_db=str(console_db) if console_db is not None else None)
    if prepare_runtime:
        selection.update(prepare_runtime=True, model_store=str(model_store), runtime_root=str(out/'runtime'))
    completed = frozenset()
    if resume_from is not None:
        if (resume_from.is_symlink() or not resume_from.is_absolute()
                or resume_from.resolve(strict=True) != resume_from or not resume_from.is_dir()):
            raise ValueError('Previous collection must be one resolved directory')
    with ExitStack() as owners:
        if resume_from is not None:
            owners.enter_context(_collection_lock(resume_from))
            previous = _previous_selection(resume_from, selection)
            if prepare_runtime:
                selection['runtime_root'] = previous['runtime_root']
            else:
                completed = _completed_continuation_jobs(resume_from, selection, admitted)
            selection['resume_from'] = str(resume_from)
        out.mkdir(mode=0o700)
        owners.enter_context(_collection_lock(out))
        _write_new(out / 'selection.json', selection)
        worker = None
        if prepare_runtime:
            from experiments.hosted_runtime_collection import (
                completed_runtime_jobs, run_runtime_admission, runtime_programs,
            )
            _write_atomic(out/'progress.json', dict(stage='binding_installed_runtime',
                assigned_target_inputs=len(call_ids), target_calls=0, downloaded_bytes=0))
            runtime_root = Path(selection['runtime_root'])
            if runtime_root.is_symlink() or runtime_root.resolve() != runtime_root:
                raise ValueError('Runtime continuation must use its resolved preparation directory')
            runtime_root.mkdir(mode=0o700, exist_ok=True)
            owners.enter_context(_collection_lock(runtime_root))
            prepared_programs, admitted = runtime_programs(originals=prepared_programs, references=references,
                contexts=[contexts[retained._local_context_key(program)] for program in prepared_programs],
                admitted=admitted, budget=budget, project_root=project_root, expected_commit=expected_commit,
                store=model_store, root=runtime_root)
            if resume_from is not None:
                completed = completed_runtime_jobs(
                    _completed_continuation_jobs(resume_from, selection, admitted), admitted)
            worker = run_runtime_admission
        return _collect_admitted(admitted=admitted, prepared_programs=prepared_programs,
            budget_root=budget_root, project_root=project_root, out=out, workspace_id=workspace_id,
            console_db=console_db, workers_per_provider=workers_per_provider, completed=completed,
            assigned=len(call_ids), worker=worker, runtime_root=selection.get('runtime_root'))


def _collect_admitted(*, admitted, prepared_programs, budget_root, project_root, out,
                      workspace_id, console_db, workers_per_provider, completed, assigned,
                      worker=None, runtime_root=None):
    database, publisher, publication = None, None, None
    try:
        if workspace_id:
            from experiments.rig_web_app.storage import ConsoleDB
            from experiments.rig_web_app.workspace_import import HostedWorkspacePublication
            database = ConsoleDB(console_db, repo_root=project_root)
            publisher = HostedWorkspacePublication(database, workspace_id, programs=prepared_programs,
                selections=[jobs[0].attacker._retained["plan"]["selected"] for jobs in admitted],
                budget_root=budget_root)

        def progress_changed(progress):
            nonlocal publication
            if publisher is not None:
                publication = publisher.refresh(progress)
                progress = dict(progress, publication=publication)
            _write_atomic(out / "progress.json", progress)

        if publisher is not None:
            progress_changed(dict(jobs=[dict(program=p, job=j, status="collected" if (p, j) in completed else "pending")
                for p, jobs in enumerate(admitted) for j in range(len(jobs))]))
        rows = dispatch_admitted(admitted, workers_per_provider=workers_per_provider, responses_only=True,
            on_progress=progress_changed, completed_jobs=completed,
            **({'_worker': worker} if worker is not None else {}))
        if publisher is not None:
            progress_changed(dict(jobs=rows))
    finally:
        if database is not None:
            database.close()
    complete = all(row["status"] == "collected" for row in rows)
    result = dict(status="responses_collected_awaiting_judging" if complete else "collection_needs_continuation",
        jobs=rows, assigned_target_inputs=assigned, judgments="not_executed_by_collection",
        selection_changed=False, automatic_answer_retries_added=0, completed_jobs_restored=len(completed))
    if publication is not None:
        result["publication"] = publication
    if runtime_root is not None:
        from experiments.hosted_runtime_collection import effective_program_descriptors
        result.update(runtime_root=runtime_root, execution_programs=effective_program_descriptors(Path(runtime_root)),
            diagnostic_probe_judging='included_in_funded_transport_checks',
            measured_judging='deferred')
    _write_new(out / "result.json", result)
    return result


@artifact_verification_cli
def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, required=True, action="append")
    parser.add_argument("--program-sha256", required=True, action="append")
    parser.add_argument("--budget-root", type=Path, required=True)
    parser.add_argument("--budget-plan-sha256", required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument('--prepare-runtime', action='store_true',
        help='Bind installed models and run already-funded transport probes before measured collection')
    parser.add_argument('--model-store', type=Path, default=os.environ.get('URA_MODEL_STORE'))
    parser.add_argument('--resume-from', type=Path,
        help='Continue this previous collection with the same programs/budget; --out is a fresh successor directory')
    parser.add_argument("--workers-per-provider", type=int, default=2, choices=range(1, 9))
    parser.add_argument("--workspace-id", default=os.environ.get("URA_CAMPAIGN_WORKSPACE_ID", ""),
        help="Publish the admitted collection into this existing campaign workspace")
    parser.add_argument("--console-db", type=Path, default=os.environ.get("URA_CAMPAIGN_CONSOLE_DB"),
        help="Rig Web SQLite index; paired with --workspace-id")
    parser.add_argument("--verify-artifact-sha256", action="store_true",
        help="Opt in to full retained-file checksum revalidation")
    args = parser.parse_args(argv)
    if len(args.program) != len(args.program_sha256):
        parser.error("Supply one matching digest for each program, in the same order")
    result = collect_campaign(programs=list(zip(args.program, args.program_sha256)),
        budget_root=args.budget_root, budget_plan_sha256=args.budget_plan_sha256,
        project_root=args.project_root, expected_commit=args.expected_commit,
        out=args.out, workers_per_provider=args.workers_per_provider,
        workspace_id=args.workspace_id, console_db=args.console_db, resume_from=args.resume_from,
        prepare_runtime=args.prepare_runtime, model_store=args.model_store)
    print(json.dumps({key: value for key, value in result.items() if key != "jobs"}, sort_keys=True))
    return 0 if result["status"] == "responses_collected_awaiting_judging" else 1


if __name__ == "__main__":
    raise SystemExit(main())
