"""Read Build's existing source selections as judging candidates, without calls.

The hosted source is the saved native preparation, not a completed-generation
manifest manufactured from its later local verdicts. Candidate identity records
carry no safety labels. Missing or invalid local judgments do not select answers.
"""
from __future__ import annotations

import json
from pathlib import Path

from experiments import retained_native_judge_prepare as sources, run_matrix
from experiments.human_audit import _csv_safe, _dialog_text, _portable_media_references, _record_key
from ura.runner import _dialog_modalities, _effective_modality


def read_local_inventory(value):
    from experiments.retained_local_sources import describe_sources
    from experiments.retained_response_judge import _read_native_view

    roots=[Path(path) for path in value['source_roots']]
    requested=set(value['run_ids'])
    cells,metadata,records=[],{},{}
    seen=set()
    for root in roots:
        part,part_meta,part_records,_audit=_read_native_view(root)
        selected=[cell for cell in part if cell['run_id'] in requested]
        runs={cell['run_id'] for cell in selected}
        if seen & runs or len(runs)!=len(selected):
            raise ValueError('Selected local judging runs overlap')
        seen.update(runs)
        cells.extend(selected)
        for key,meta in part_meta.items():
            if meta['run_id'] in runs:
                if key in metadata:
                    raise ValueError('Selected local judging outputs overlap')
                metadata[key],records[key]=meta,part_records[key]
    if seen!=requested or describe_sources(roots,sorted(cells,key=lambda cell:cell['run_id']))!=value:
        raise ValueError('Selected local judging source inventory changed')
    return cells,metadata,records,dict(policy_evaluable_samples=len(metadata),
        common_ineligible_evaluable_rows_excluded=sum(
            row['raw'].get('common_metrics_eligible') is False and row['raw'].get('policy_evaluable_turn') is True
            for cell in cells for row in cell['judgments']))


def read_hosted_preparation(value):
    if (value.get('status') not in {'prepared','preparation_incomplete'}
        or value.get('judgments')!='not_executed' or not value.get('units')
        or any(value.get(key)!=0 for key in ('target_calls','judge_calls','model_loads'))):
        raise ValueError('Select a saved no-call native judging preparation')
    programs={p['path']:p for p in value['programs']}
    if len(programs)!=len(value['programs']):
        raise ValueError('Native judging preparation repeats a program')
    cells,metadata,identities=[],{},{}
    seen=set()
    excluded_source=excluded_diagnostic=0
    assigned=0
    for expected in value['units']:
        if expected['program'] not in programs:
            raise ValueError('Native judging source has no prepared program')
        for entry in expected['files']:
            if sources.metadata(Path(entry['path']))!=entry:
                raise ValueError('Prepared judging source changed')
        path=Path(expected['program'])
        program,_=sources.load_bound_json(path,programs[str(path)]['sha256'])
        source,reader,inputs,responses=sources.load_program_job(path,expected['job'],program=program)
        if source!=expected or source['run_id'] in seen:
            raise ValueError('Prepared judging source differs or repeats a run')
        seen.add(source['run_id'])
        assigned+=len(inputs)
        job=next(job for job in program['jobs'] if job['name']==source['job'])
        # Readiness probes and canaries cannot enter the measured Haiku cohort.
        if job['purpose']!='measured_run':
            excluded_diagnostic+=len(inputs)
            continue
        args=run_matrix.build_parser().parse_args(source['runner_argv'])
        cells.append(dict(run_id=source['run_id'],model=source['target'],
            generation_context=dict(run=dict(attacker=args.attackers,corpus=args.corpora,
                project_revision=source['generation_project_revision']),components=dict(target=source['target_component'])),
            attempts={key:record['attempt'] for key,record in responses.items()},
            responses={key:record['response'] for key,record in responses.items()},judgments=[],
            source_identity_validated=True,scope='retained_response_candidates_only'))
        for key,(point,attempt) in inputs.items():
            if not attempt.params['policy_evaluable_turn']:
                continue
            if point.meta.get('common_metrics_eligible',True) is not True:
                excluded_source+=1
                continue
            response=responses[key]['response']
            identity=_record_key(response)
            if identity in metadata:
                raise ValueError('Prepared judging outputs overlap')
            metadata[identity]=dict(run_id=source['run_id'],model=source['target'],attempt_id=key,
                datapoint_id=point.id,source_cluster_id=str(point.meta.get('source_cluster_id') or point.id),
                requested_seed=attempt.seed,source=point.source,risk_category=point.risk_category.value,
                expected_behavior=point.expected_behavior,
                source_policy_id=point.source_policy.policy_id if point.source_policy else 'unversioned',
                source_policy_version=point.source_policy.version if point.source_policy else 'unversioned',
                common_metrics_eligible=True,policy_evaluable_turn=True,
                effective_modality=_effective_modality(_dialog_modalities(attempt.rendered_input),reader.target.modality_support),
                prepared_prompt=str(_csv_safe(_dialog_text(responses[key]['attempt']['rendered_input']))),
                prepared_response=str(_csv_safe(_dialog_text(response['output_turns']))),
                prepared_media_references=_portable_media_references(responses[key]['attempt']['rendered_input']))
            # This is an output identity, deliberately not an invented judgment.
            identities[identity]=dict(attempt_id=key)
    if assigned!=value['outputs']:
        raise ValueError('Prepared judging output count changed')
    return cells,metadata,identities,dict(policy_evaluable_samples=len(metadata),
        common_ineligible_evaluable_rows_excluded=excluded_source,
        excluded_diagnostic_outputs=excluded_diagnostic,
        unprepared_outputs=sum(source['assigned'] for source in value.get('failed',[])))


def read_prepared_view(path):
    value=json.loads(Path(path).read_text())
    if value.get('schema')=='ura-retained-local-sources/1':
        return read_local_inventory(value)
    return read_hosted_preparation(value)
