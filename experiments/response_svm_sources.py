"""Analysis metadata from indexed saved attempts, without re-admitting campaigns."""
from collections import Counter, defaultdict
import json
from pathlib import Path
import sqlite3


def indexed_candidates(database, campaign):
    with sqlite3.connect(Path(database).resolve().as_uri()+'?mode=ro',uri=True) as connection:
        connection.row_factory=sqlite3.Row
        rows=[dict(r) for r in connection.execute('''SELECT a.input_id,a.model,a.modality,a.framework,a.corpus,
            r.response_id,r.details FROM campaign_assignments a JOIN campaign_responses r
            ON a.campaign_id=r.campaign_id AND a.assignment_id=r.assignment_id
            WHERE a.campaign_id=? AND a.evidence_class='measured'
            AND (a.model LIKE 'ollama:%' OR a.model LIKE 'vllm:%')
            AND a.modality='text' AND a.framework='replay' ORDER BY a.input_id,r.response_id''',(campaign,))]
    files=defaultdict(list)
    for row in rows:
        location,_,number=json.loads(row['details'])['source_ref'].rpartition(':')
        if not number.isdigit() or int(number)<1 or not Path(location).is_absolute():
            raise ValueError('Indexed source has no resolved retained row location')
        files[Path(location)].append((int(number),row))
    candidates={};dispositions=Counter();files_read=0
    for path,selected in files.items():
        wanted={number for number,_ in selected};records={};last=max(wanted)
        moved_checkpoint=not path.exists() and path.name.endswith('.responses.checkpoint.jsonl')
        if moved_checkpoint:
            path=path.with_name(path.name.replace('.responses.checkpoint.jsonl','.responses.jsonl'))
            # Final files can have a different order. Match durable identity,
            # never reuse a checkpoint line number in its finalized file.
            by_identity=defaultdict(list)
            for number,row in selected:by_identity[row['response_id']].append(number)
        with path.open(encoding='utf-8') as stream:
            files_read+=1
            for number,line in enumerate(stream,1):
                if moved_checkpoint:
                    record=json.loads(line)
                    identity=str(record.get('run_id'))+':'+str(record.get('attempt_id'))
                    for original_number in by_identity.get(identity,[]):records[original_number]=record
                else:
                    if number in wanted:records[number]=json.loads(line)
                    if number>=last:break
        attempts={};metadata={}
        if path.name.endswith('.responses.jsonl'):
            prefix=path.name.removesuffix('.responses.jsonl')
            wanted_ids={r['response_id'].partition(':')[2] for _,r in selected}
            for suffix,table,identifier in [('.attempts.jsonl',attempts,'id'),('.judgments.jsonl',metadata,'attempt_id')]:
                companion=path.with_name(prefix+suffix)
                if companion.is_file():
                    with companion.open(encoding='utf-8') as stream:
                        files_read+=1
                        for line in stream:
                            record=json.loads(line)
                            if record.get(identifier) in wanted_ids:table[record[identifier]]=record
        for number,row in selected:
            record=records.get(number)
            if record is None:raise ValueError('Indexed saved source row is absent')
            response=record.get('response',record)
            run_id,_,attempt_id=row['response_id'].partition(':')
            if (response.get('run_id'),response.get('attempt_id'),response.get('target'))!=(run_id,attempt_id,row['model']):
                raise ValueError('Indexed source ownership differs from retained response')
            attempt=record.get('attempt',attempts.get(attempt_id))
            if attempt is None:dispositions['missing_saved_attempt']+=1;continue
            if (attempt.get('run_id'),attempt.get('id'),attempt.get('target'),attempt.get('attacker'))!=(run_id,attempt_id,row['model'],row['framework']):
                raise ValueError('Indexed source ownership differs from retained attempt')
            params=attempt.get('params') or {}
            raw=(record.get('judgment',metadata.get(attempt_id)) or {}).get('raw') or {}
            source=params.get('planning_source',raw.get('source'))
            expected=params.get('planning_expected_behavior',raw.get('expected_behavior'))
            cluster=params.get('source_cluster_id');turns=attempt.get('rendered_input')
            if not source or not expected or not cluster or not isinstance(turns,list) or not turns:
                dispositions['missing_source_metadata']+=1;continue
            if any(turn.get('media') for turn in turns):raise ValueError('Indexed text source contains media')
            item=dict(input_identity_sha256=row['input_id'],modality=row['modality'],framework=row['framework'],
                corpus=row['corpus'],source=source,source_cluster_id=cluster,expected_behavior=expected,
                source_policy=params.get('planning_source_policy',params.get('source_policy')),
                rendered_input=turns,risk=raw.get('risk_category',raw.get('risk')))
            prior=candidates.get(row['input_id'])
            if prior is not None:
                if any(prior[key]!=item[key] for key in item if key!='risk'):
                    raise ValueError('One indexed input has conflicting saved source metadata')
                if prior['risk'] is None:prior['risk']=item['risk']
                elif item['risk'] is not None and prior['risk']!=item['risk']:
                    raise ValueError('One indexed input has conflicting risk metadata')
            else:candidates[row['input_id']]=item
    return list(candidates.values()),dict(source_campaign=campaign,indexed_rows=len(rows),
        unique_inputs=len(candidates),files_read=files_read,dispositions=dict(dispositions),
        corpus_reconstructions=0,model_file_reads=0,checksum_revalidation=False)
