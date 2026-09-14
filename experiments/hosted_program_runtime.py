"""Bind an untouched hosted program to installed runtimes, without model calls.

The returned program still needs its selected transport observations. Its exact
funded inputs, requests and spending plan are not replaced by this preparation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import copy
import json
import os
from pathlib import Path

from experiments import hosted_retained_execute as retained
from experiments.hosted_retained_inputs import _descriptor
from experiments.retained_response_judge_execute import _write_atomic, _write_new
from ura.artifact_checks import artifact_verification_cli


def set_argument(argv, flag, value):
    if argv.count(flag) > 1:
        raise ValueError('Runtime preparation cannot choose between repeated '+flag)
    if flag in argv:
        argv[argv.index(flag)+1] = str(value)
    else:
        argv.extend([flag, str(value)])


def select_transport_jobs(program, entries_by_name):
    """Use whole already-funded jobs, selected only from fixed input metadata."""
    required, candidates = set(), []
    for job in program['jobs']:
        entries = entries_by_name[job['name']]
        combos = {tuple(sorted(entry['origin']['selection']['required_modalities'])) for entry in entries}
        required.update(combos)
        points = Counter(entry['origin']['selection']['datapoint_id'] for entry in entries)
        clusters = {(entry['origin']['selection']['corpus'], entry['origin']['selection']['source'],
                     entry['origin']['selection']['source_cluster_id']) for entry in entries}
        evaluable = any(entry['origin']['original_attempt']['params']['policy_evaluable_turn'] for entry in entries)
        if len(combos) != 1 or not 1 <= len(clusters) <= 2 or max(points.values(), default=0) != 1 or not evaluable:
            continue
        benign = all(entry['origin']['selection']['corpus']=='jailbreakbench_benign' for entry in entries)
        candidates.append((not benign, job['purpose']!='diagnostic_canary', job['name'],
                           next(iter(combos)), len(clusters)))
    selected, covered = {}, set()
    for _, _, name, combo, clusters in sorted(candidates):
        if combo not in covered:
            selected[name] = clusters
            covered.add(combo)
    if not required or not required <= covered:
        raise ValueError('A selected modality has no complete funded transport-probe job')
    return selected


def prospective_program(original, entries, *, root, project_revision, max_age_hours=24):
    """Preserve all funded jobs while assigning their prospective probe roles."""
    if isinstance(max_age_hours, bool) or not 0 < float(max_age_hours) <= 8760:
        raise ValueError('Transport observation age must be in (0, 8760] hours')
    program = copy.deepcopy(original)
    probes = select_transport_jobs(program, entries)
    remove = {'--execution-scope-id', '--live-attestation-max-age-hours', '--live-attestation',
        '--live-attestation-sha256', '--model-acquisition-plan', '--model-acquisition-plan-sha256',
        '--model-acquisition-receipt', '--model-acquisition-receipt-sha256', '--model-acquisition-store'}
    scope = 'hosted-'+root.name
    for number, job in enumerate(program['jobs']):
        argv, clean, index = job['argv'], [], 0
        while index < len(argv):
            if argv[index] in remove:
                if index+1 >= len(argv):
                    raise ValueError('Runtime argument has no value')
                index += 2
            else:
                clean.append(argv[index])
                index += 1
        job['argv'] = argv = clean
        set_argument(argv, '--project-revision', project_revision['path'])
        set_argument(argv, '--project-revision-sha256', project_revision['sha256'])
        set_argument(argv, '--out', root/'outputs'/f'job-{number:04d}')
        set_argument(argv, '--execution-scope-id', scope)
        if job['name'] in probes:
            job['purpose'] = 'attestation_probe'
            if '--diagnostic-canary' in argv:
                argv.remove('--diagnostic-canary')
            if '--attestation-probe' not in argv:
                argv.append('--attestation-probe')
            for flag, value in (('--limit', probes[job['name']]), ('--max-queries', 1), ('--max-turns', 1)):
                set_argument(argv, flag, value)
        else:
            set_argument(argv, '--live-attestation-max-age-hours', max_age_hours)
    if not any(job['purpose']=='measured_run' for job in program['jobs']):
        choices = [job for job in program['jobs'] if job['purpose']=='diagnostic_canary' and any(
            entry['origin']['original_attempt']['params']['policy_evaluable_turn'] for entry in entries[job['name']])]
        if not choices:
            raise ValueError('Transport preparation must leave a separate scoring-capable measured job')
        chosen = min(choices, key=lambda job: job['name'])
        chosen['purpose'] = 'measured_run'
        chosen['argv'].remove('--diagnostic-canary')
        set_argument(chosen['argv'], '--limit', 0)
    program['jobs'].sort(key=lambda job: {'attestation_probe':0, 'diagnostic_canary':1, 'measured_run':2}[job['purpose']])
    return program


class InstalledOnly:
    """Missing resources require the explicit model installer, never a download here."""
    def fetch_manifest(self, *args, **kwargs):
        raise ValueError('A required managed model is not installed; use model acquisition first')
    cached_file = fetch_manifest
    download_file = fetch_manifest


def bind_installed_program(*, original, budget, project_root, expected_commit, store, out,
                           max_age_hours=24, verify_model_sha256=False, local_context=None,
                           original_admissions=None):
    from experiments import model_acquire, run_matrix
    from ura.model_acquisition import load_plan, load_receipt, verify_receipt_snapshots
    from ura.project_revision import create_project_revision, write_project_revision
    from ura.runner import retained_execution_admission

    retained._validated_checkout(project_root, expected_commit)
    if type(verify_model_sha256) is not bool:
        raise ValueError('Model checksum verification must be explicitly boolean')
    if not store.is_absolute() or store.resolve(strict=True)!=store or not store.is_dir():
        raise ValueError('Select the existing resolved managed-model store')
    if (not out.is_absolute() or out.is_symlink() or out.parent.resolve(strict=True)!=out.parent
            or out.exists() and not out.is_dir()):
        raise ValueError('Runtime preparation requires a resolved output directory')
    starts = budget.reserved_attempt_counts([row['call_id'] for row in original['requests'].values()])
    if any(starts.values()):
        raise ValueError('This program has started; continue its checkpoints instead of preparing new runtime arguments')
    context = retained._validated_local_cells(original) if local_context is None else local_context
    admissions = (retained._validated_jobs(original, budget, local_context=context)
                  if original_admissions is None else original_admissions)
    entries = {admission.job['name']: admission.attacker._selected_entries for admission in admissions}
    selection = dict(original=original, project_root=str(project_root), expected_commit=expected_commit,
        store=str(store), max_age_hours=max_age_hours, verify_model_sha256=verify_model_sha256)
    out.mkdir(mode=0o700, exist_ok=True)
    binding = out/'selection.json'
    if binding.exists():
        if json.loads(binding.read_text()) != selection:
            raise ValueError('Runtime continuation changed its program, project, store or options')
    else:
        if any(out.iterdir()):
            raise ValueError('Runtime directory has no matching preparation')
        _write_new(binding, selection)
    revision_path = out/'revision-reference.json'
    if revision_path.exists():
        revision = json.loads(revision_path.read_text())
    else:
        document = create_project_revision(expected_commit, project_root/'experiments/run_matrix.py')
        # The existing writer supplies the complete document; retain its original name.
        directory = out/'revision'
        directory.mkdir(mode=0o700, exist_ok=True)
        revision = _descriptor(write_project_revision(directory, document))
        _write_new(revision_path, revision)
    program = prospective_program(original, entries, root=out, project_revision=revision,
                                  max_age_hours=max_age_hours)
    planning = copy.deepcopy(program)
    for number, job in enumerate(planning['jobs']):
        unit = out/f'unit-{number:04d}'
        (unit/'plans').mkdir(parents=True, mode=0o700, exist_ok=True)
        (unit/'receipts').mkdir(mode=0o700, exist_ok=True)
        job['argv'] += ['--model-acquisition-plan-only', '--model-acquisition-plan-dir', str(unit/'plans')]
    planned = retained._validated_jobs(planning, budget, local_context=context)
    for number, admission in enumerate(planned):
        unit = out/f'unit-{number:04d}'
        _write_atomic(out/'progress.json', dict(stage='binding_installed_runtime', job=admission.job['name'],
            completed=number, assigned=len(planned), target_calls=0, judge_calls=0, downloaded_bytes=0))
        plans = list((unit/'plans').glob('*.plan.json'))
        if not plans:
            log = unit/'planning.log'
            try:
                with log.open('a') as stream, redirect_stdout(stream), redirect_stderr(stream):
                    with retained_execution_admission(admission):
                        code = run_matrix.main(admission.job['argv'])
            except SystemExit as exc:
                # argparse exits from nested Runner validation. Do not let it
                # terminate the parent silently while its error is redirected.
                raise RuntimeError('Runtime planning failed for '+admission.job['name']+
                    '; '+_log_tail(log)+'\nPlanner log: '+str(log)) from exc
            if code:
                raise RuntimeError('Runtime planning failed for '+admission.job['name']+
                    '; '+_log_tail(log)+'\nPlanner log: '+str(log))
            plans = list((unit/'plans').glob('*.plan.json'))
        if len(plans)!=1:
            raise ValueError('Runtime job needs one exact acquisition plan')
        descriptor = _descriptor(plans[0])
        plan = load_plan(plans[0], expected_sha256=descriptor['sha256'])
        receipts = list((unit/'receipts').glob('*.receipt.json'))
        if receipts:
            if len(receipts)!=1:
                raise ValueError('Runtime job has ambiguous installed-model receipts')
            receipt = _descriptor(receipts[0])
            value = load_receipt(receipts[0], expected_sha256=receipt['sha256'], plan=plan)
            verify_receipt_snapshots(plan, value, managed_store=store, verify_sha256=verify_model_sha256)
        else:
            acquired = model_acquire.acquire(plan, store=store, receipts_dir=unit/'receipts',
                max_download_bytes=0, min_free_bytes=0, deadline_seconds=1800, backend=InstalledOnly(),
                verify_model_sha256=verify_model_sha256)
            if acquired.downloaded_bytes:
                raise RuntimeError('Installed-only preparation downloaded model bytes')
            receipt = _descriptor(acquired.receipt_path)
        argv = program['jobs'][number]['argv']
        for flag, value in (('--model-acquisition-plan', descriptor['path']),
            ('--model-acquisition-plan-sha256', descriptor['sha256']), ('--model-acquisition-receipt', receipt['path']),
            ('--model-acquisition-receipt-sha256', receipt['sha256']), ('--model-acquisition-store', store)):
            set_argument(argv, flag, value)
    retained._validated_jobs(program, budget, local_context=context)
    destination = out/'runtime-program.json'
    if destination.exists():
        if json.loads(destination.read_text())!=program:
            raise ValueError('Prepared runtime program changed')
    else:
        _write_new(destination, program)
    result = dict(status='installed_runtime_bound_transport_pending', program=_descriptor(destination),
        assigned_inputs=len(program['requests']), probe_inputs=sum(len(job['input_ids']) for job in program['jobs']
            if job['purpose']=='attestation_probe'), target_calls=0, judge_calls=0, downloaded_bytes=0,
        verify_model_sha256=verify_model_sha256, original_requests_unchanged=program['requests']==original['requests'])
    _write_atomic(out/'result.json', result)
    return result


def _log_tail(path: Path) -> str:
    with path.open('rb') as stream:
        stream.seek(0, 2)
        stream.seek(max(0,stream.tell()-6000))
        return stream.read().decode('utf-8',errors='replace').strip()


def retained_planning_failure(root: Path, allowed_root: Path) -> str:
    """Expose the active nested planner log, including older silent failures."""
    try:
        root = root.resolve(strict=True)
        if not root.is_relative_to(allowed_root.resolve(strict=True)):
            return ''
        selection = json.loads((root/'selection.json').read_text())
        runtime = Path(selection['runtime_root']).resolve(strict=True)
        if not runtime.is_relative_to(allowed_root.resolve(strict=True)):
            return ''
        if (runtime/'programs.json').is_file():
            return ''  # A later collection failure is not a planning failure.
        for number, _ in enumerate(selection['programs']):
            program = runtime/f'program-{number:04d}'
            if (program/'result.json').is_file():
                continue
            progress = json.loads((program/'progress.json').read_text())
            unit = progress.get('completed')
            if progress.get('stage')!='binding_installed_runtime' or type(unit) is not int or unit<0:
                continue
            log = (program/f'unit-{unit:04d}'/'planning.log').resolve(strict=True)
            if log.is_relative_to(runtime):
                content = _log_tail(log)
                if content:
                    return 'Installed-runtime preparation: '+str(progress.get('job',''))+'\n'+content
    except (OSError,ValueError,KeyError,TypeError):
        return ''
    return ''


@artifact_verification_cli
def main(argv=None):
    from experiments.hosted_attempt_budget import AttemptBudget
    from experiments.hosted_campaign_budget import load_bound_json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--program', type=Path, required=True)
    parser.add_argument('--program-sha256', required=True)
    parser.add_argument('--budget-root', type=Path, required=True)
    parser.add_argument('--budget-plan-sha256', required=True)
    parser.add_argument('--project-root', type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--store', type=Path, default=os.environ.get('URA_MODEL_STORE'))
    parser.add_argument('--out', type=Path, required=True,
        help='New or matching interrupted no-call runtime preparation directory')
    parser.add_argument('--max-age-hours', type=float, default=24)
    parser.add_argument('--verify-model-sha256', action='store_true')
    parser.add_argument('--verify-artifact-sha256', action='store_true')
    args = parser.parse_args(argv)
    if args.store is None:
        parser.error('Select the existing managed-model --store or URA_MODEL_STORE')
    original, _ = load_bound_json(args.program, args.program_sha256)
    result = bind_installed_program(original=original,
        budget=AttemptBudget(args.budget_root, args.budget_plan_sha256),
        project_root=args.project_root, expected_commit=args.expected_commit,
        store=args.store, out=args.out, max_age_hours=args.max_age_hours,
        verify_model_sha256=args.verify_model_sha256)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
