"""Use installed runtime bindings in the existing provider-parallel collector."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from experiments.hosted_campaign_budget import load_bound_json
from experiments.hosted_program_runtime import bind_installed_program
from experiments.hosted_retained_inputs import _descriptor
from experiments.retained_response_judge_execute import _write_new


def _argument(job, flag):
    return job['argv'][job['argv'].index(flag)+1]


def runtime_programs(*, originals, references, contexts, admitted, budget,
                     project_root, expected_commit, store, root):
    """Resume no-call preparation or reuse its exact saved execution programs."""
    root.mkdir(mode=0o700, exist_ok=True)
    manifest = root/'programs.json'
    binding = dict(original_programs=references, project_root=str(project_root),
        expected_commit=expected_commit, store=str(store), budget_root=str(budget.root),
        budget_plan_sha256=budget.expected_plan_sha256)
    if manifest.exists():
        saved = json.loads(manifest.read_text())
        if any(saved.get(key) != value for key, value in binding.items()):
            raise ValueError('Runtime continuation changed its selected programs, store or spending plan')
        descriptors = saved['programs']
        if len(descriptors) != len(originals):
            raise ValueError('Runtime continuation changed its program count')
    else:
        descriptors = []
        for number, (original, context, jobs) in enumerate(zip(originals, contexts, admitted, strict=True)):
            result = bind_installed_program(original=original, budget=budget, project_root=project_root,
                expected_commit=expected_commit, store=store, out=root/f'program-{number:04d}',
                local_context=context, original_admissions=jobs)
            descriptors.append(result['program'])
        _write_new(manifest, dict(binding, programs=descriptors))
    programs, jobs_by_program = [], []
    for original, descriptor, jobs in zip(originals, descriptors, admitted, strict=True):
        program, _ = load_bound_json(Path(descriptor['path']), descriptor['sha256'])
        if (program['requests'] != original['requests'] or program['target'] != original['target']
                or program['sources'] != original['sources']):
            raise ValueError('Runtime continuation changed funded requests or their sources')
        by_name = {admission.job['name']: admission for admission in jobs}
        if set(by_name) != {job['name'] for job in program['jobs']}:
            raise ValueError('Runtime continuation changed its assigned jobs')
        rebound = []
        for job in program['jobs']:
            admission = copy.copy(by_name[job['name']])
            if admission.job['input_ids'] != job['input_ids']:
                raise ValueError('Runtime continuation changed a job input selection')
            admission.job = copy.deepcopy(job)
            admission.runtime_program = descriptor
            rebound.append(admission)
        programs.append(program)
        jobs_by_program.append(rebound)
    return programs, jobs_by_program


def transport_path(program_path, number):
    return Path(program_path).parent/f'transport-{number:04d}.json'


def observed_program(descriptor):
    """Attach completed observations without changing any source or request."""
    program, _ = load_bound_json(Path(descriptor['path']), descriptor['sha256'])
    receipts = [_descriptor(transport_path(descriptor['path'], number))
        for number, job in enumerate(program['jobs']) if job['purpose'] == 'attestation_probe']
    if not receipts:
        raise ValueError('Prepared runtime has no transport observations')
    for job in program['jobs']:
        if job['purpose'] != 'attestation_probe':
            for receipt in receipts:
                job['argv'] += ['--live-attestation', receipt['path'], '--live-attestation-sha256', receipt['sha256']]
    destination = Path(descriptor['path']).parent/'attested-program.json'
    import fcntl
    # Two first measured workers can arrive together after the final probe.
    # Only this small local publication is serialized, never provider calls.
    with (destination.parent/'observation.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if destination.exists():
            if json.loads(destination.read_text()) != program:
                raise ValueError('Saved observed program differs from its transport evidence')
        else:
            _write_new(destination, program)
    return program


def run_runtime_admission(admission, *, responses_only):
    """Finish funded probes first, then collect with their saved observations."""
    from experiments import live_attestation
    from experiments.hosted_dispatch import run_admission

    descriptor = admission.runtime_program
    if admission.job['purpose'] == 'attestation_probe':
        # A transport receipt needs the existing completed diagnostic grid.
        # These few funded probe calls are not measured campaign judgments.
        output = run_admission(admission, responses_only=False)
        program, _ = load_bound_json(Path(descriptor['path']), descriptor['sha256'])
        number = next(i for i, job in enumerate(program['jobs']) if job['name'] == admission.job['name'])
        path = transport_path(descriptor['path'], number)
        if not path.exists():
            code = live_attestation.main(['--probe-root', output, '--execution-scope-id',
                _argument(admission.job, '--execution-scope-id'), '--out', str(path)])
            if code:
                raise RuntimeError('Transport observation is unfinished; continue its saved probe')
        return output
    program = observed_program(descriptor)
    ready = copy.copy(admission)
    ready.job = next(job for job in program['jobs'] if job['name'] == admission.job['name'])
    return run_admission(ready, responses_only=responses_only)


def effective_program_descriptors(root):
    """Supply the same execution output paths to both post-hoc judging stages."""
    saved = json.loads((root/'programs.json').read_text())
    result = []
    for descriptor in saved['programs']:
        observed = Path(descriptor['path']).parent/'attested-program.json'
        result.append(_descriptor(observed) if observed.exists() else descriptor)
    return result


def completed_runtime_jobs(completed, admitted):
    """A retained probe answer alone does not prove its observation finished."""
    return frozenset((p, j) for p, j in completed
        if admitted[p][j].job['purpose'] != 'attestation_probe'
        or transport_path(admitted[p][j].runtime_program['path'], j).is_file())
