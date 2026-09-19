"""Publish finished direct hosted runs from their exact saved output directory.

Compatibility for Runner revisions that published only native local targets.
No source-corpus reconstruction, model checksums or generation is performed.
"""
import json
from pathlib import Path

from experiments.hosted_retained_inputs import retained_input_identity, _sha
from .workspace_import import _jsonl, _responses, local_generation_condition, local_judge_condition, local_response_row


def publish(db,owner,directory,models):
    directory=Path(directory)
    assignments=[];responses=[];judgments=[];costs=[]
    observed=list(_responses(dict(argv=['--out',str(directory)])))
    for path in sorted(directory.glob('*.manifest.json')):
        manifest=json.loads(path.read_text());run=manifest['config']['run']
        model=run['model_spec'];run_id=manifest['run_id']
        if model.startswith(('ollama:','vllm:')):continue
        if model not in models:raise ValueError('Direct publication target differs from its job')
        condition=local_generation_condition(run);judge=local_judge_condition(run)
        stem=path.name.removesuffix('.manifest.json')
        records={}
        for suffix in ('.checkpoint.jsonl','.jsonl'):
            target=directory/(stem+suffix)
            if not target.exists():continue
            for number,record in _jsonl(target):
                verdict=record.get('judgment',record);key=verdict['attempt_id']
                if verdict['run_id']!=run_id:raise ValueError('Direct judgment belongs to another run')
                if key in records and records[key][0]!=verdict:raise ValueError('Conflicting direct judgments')
                records[key]=(verdict,str(target)+':'+str(number))
        evidence={'measured_run':'measured','attestation_probe':'diagnostic','diagnostic_canary':'diagnostic'}.get(run.get('execution_purpose'),'unknown')
        for attempt,response,reference in observed:
            if response['run_id']!=run_id:continue
            if response['target']!=model or attempt['target']!=model:raise ValueError('Direct response ownership differs')
            verdict,verdict_ref=records.get(attempt['id'],(None,None))
            metadata=(verdict or {}).get('raw') or {}
            # Older attempts retain risk in their saved judgment, not in their
            # planning fields. Never invent it or reconstruct a corpus here.
            if not metadata.get('risk_category'):raise ValueError('Saved source context is not yet available for direct publication')
            choice=retained_input_identity(run,manifest['dataset_hashes']['corpus'],attempt,metadata)
            output=local_response_row(response,condition,reference)
            assignments.append(dict(assignment_id=output['assignment_id'],model=model,input_id=_sha(choice),
                condition_id=condition,modality=choice['modality'],framework=choice['framework'],corpus=choice['corpus'],
                response_id=output['response_id'],evidence_class=evidence))
            responses.append(output)
            if verdict:
                missing=metadata.get('policy_evaluation_status') in {'model_nonresponse','target_input_incompatible'}
                judgments.append(dict(response_id=output['response_id'],judge_id=judge,status='missing' if missing else 'valid',
                    label=None if missing else verdict['label'],source_ref=verdict_ref))
            raw=response.get('raw') or {};attempts=raw.get('transport_attempts') or []
            for physical in attempts:
                number=physical.get('attempt')
                if type(number) is not int or number<1:raise ValueError('Invalid recorded HTTP attempt')
                final=physical.get('outcome')=='success' and number==len(attempts)
                costs.append(dict(call_id='direct-'+output['response_id'],attempt_number=number,assignment_id=output['assignment_id'],
                    response_id=output['response_id'] if final else None,provider=raw.get('provider') or model.split(':')[0],
                    model=raw.get('resolved_model') or model.split(':',1)[-1],role='target',state='unknown',
                    cost_microusd=None,exposure_microusd=None,source_ref=reference,
                    input_tokens=output['input_tokens'] if final else None,output_tokens=output['output_tokens'] if final else None,
                    reasoning_tokens=output['reasoning_tokens'] if final else None))
    db.publish_workspace_results(owner,assignments=assignments,responses=responses,judgments=judgments)
    db.publish_workspace_costs(owner,costs)
    return dict(assignments=len(assignments),responses=len(responses),judgments=len(judgments),physical_attempts=len(costs))
