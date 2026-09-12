"""Inventory every saved local/hosted answer on the same selected input entries.

Selection depends on inputs, not answer availability. Missing answers remain
in coverage but are never eligible for a paid text judgment. No model is called.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
from typing import Sequence

from experiments import retained_response_judge as retained

SCHEMA='ura-retained-matched-output-inventory/1'
EMPTY_RESPONSE_SHA256=hashlib.sha256(b'').hexdigest()


def read_sources(paths: Sequence[Path]):
    """Combine explicit, disjoint saved preparations without rereading a path."""
    if not paths:
        raise ValueError('Select at least one saved source view')
    cells,metadata,records=[],{},{}
    runs,seen_paths=set(),set()
    prepared_jobs,pending_jobs=set(),{}
    audit=Counter()
    for path in paths:
        path=Path(path).resolve(strict=True)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        part,part_meta,part_records,part_audit=retained._read_view(path)
        ids={cell['run_id'] for cell in part}
        if len(ids)!=len(part) or runs & ids or metadata.keys() & part_meta.keys():
            raise ValueError('Selected preparations overlap saved runs or answers')
        if part_meta.keys()!=part_records.keys() or len(part_meta)!=part_audit['policy_evaluable_samples']:
            raise ValueError('Prepared output inventory lost input coverage')
        runs.update(ids)
        cells.extend(part)
        metadata.update(part_meta)
        records.update(part_records)
        for name in ('policy_evaluable_samples','common_ineligible_evaluable_rows_excluded',
                     'excluded_diagnostic_outputs'):
            audit[name]+=part_audit.get(name,0)
        prepared_jobs.update(tuple(key) for key in part_audit.get('prepared_source_jobs',[]))
        for pending in part_audit.get('unprepared_source_jobs',[]):
            key=(pending['program'],pending['job'])
            if key in pending_jobs and pending_jobs[key]!=pending['assigned']:
                raise ValueError('One unprepared source job has inconsistent input counts')
            pending_jobs[key]=pending['assigned']
        if 'unprepared_source_jobs' not in part_audit:
            audit['unprepared_outputs']+=part_audit.get('unprepared_outputs',0)
    audit['unprepared_outputs']+=sum(count for key,count in pending_jobs.items() if key not in prepared_jobs)
    return cells,metadata,records,dict(audit)


def matched_population(local_views: Sequence[Path],hosted_views: Sequence[Path]):
    local,hosted=read_sources(local_views),read_sources(hosted_views)
    return (retained._candidates_from_view(*local,include_match_identity=True,include_missing=True,allow_empty=True),
        retained._candidates_from_view(*hosted,include_match_identity=True,include_missing=True,
            allow_empty=True,original_cells=local[0]))


def build_inventory(local_rows,hosted_rows,*,local_audit,hosted_audit,input_limit=0,seed=0):
    if type(input_limit) is not int or input_limit<0 or type(seed) is not int:
        raise ValueError('Input limit must be a nonnegative integer; seed must be an integer')
    groups=defaultdict(lambda:{'local':[],'hosted':[]})
    seen=set()
    for cohort,rows in (('local',local_rows),('hosted',hosted_rows)):
        for original in rows:
            row=dict(original)
            key=(row['run_id'],row['attempt_id'])
            if key in seen:
                raise ValueError('One retained answer appears more than once in the comparison')
            seen.add(key)
            identity=retained._sha({field:row[field] for field in retained._MATCH_IDENTITY_FIELDS})
            if identity!=row['input_identity_sha256']:
                raise ValueError('Comparison input identity differs from its recorded dimensions')
            row['cohort']=cohort
            row['judgeable_text']=row['response_sha256']!=EMPTY_RESPONSE_SHA256
            groups[identity][cohort].append(row)
    hosted_inputs=[key for key,value in groups.items() if value['hosted']]
    order=sorted(hosted_inputs,key=lambda key:retained._sha({'seed':seed,'input':key}))
    selected=order[:input_limit] if input_limit else order
    outputs,inputs=[],[]
    by_model=defaultdict(Counter)
    for identity in selected:
        group=groups[identity]
        counts={}
        for cohort in ('local','hosted'):
            rows=sorted(group[cohort],key=lambda row:(row['exact_model'],row['run_id'],row['attempt_id']))
            counts[cohort]={'retained_outputs':len(rows),'judgeable_text':sum(row['judgeable_text'] for row in rows)}
            for row in rows:
                by_model[(cohort,row['exact_model'])]['retained_outputs']+=1
                by_model[(cohort,row['exact_model'])]['judgeable_text' if row['judgeable_text'] else 'missing_text']+=1
            outputs.extend(rows)
        inputs.append(dict(input_identity_sha256=identity,**counts))
    missing=sum(not row['judgeable_text'] for row in outputs)
    value=dict(schema=SCHEMA,status='inventory_only_no_calls',
        selection=dict(policy='seeded_input_prefix_all_retained_outputs_v1',seed=seed,input_limit=input_limit,
            available_hosted_inputs=len(order),selected_inputs=len(selected),
            all_local_counterparts=True,availability_used_for_input_selection=False),
        population=dict(local=dict(local_audit),hosted=dict(hosted_audit)),
        coverage=dict(retained_outputs=len(outputs),judgeable_text=len(outputs)-missing,missing_text=missing,
            hosted_inputs_without_local_records=sum(not row['local']['retained_outputs'] for row in inputs)),
        by_model=[dict(cohort=cohort,model=model,**dict(counts)) for (cohort,model),counts in sorted(by_model.items())],
        inputs=inputs,outputs=outputs,target_calls=0,judge_calls=0,
        existing_judgments_reused=False,budget_created=False)
    value['inventory_id']='retained-matched-inventory-'+retained._sha(value)[:24]
    return value


def prepare_inventory(*,local_views,hosted_views,out,input_limit=0,seed=0):
    (local,local_audit),(hosted,hosted_audit)=matched_population(local_views,hosted_views)
    value=build_inventory(local,hosted,local_audit=local_audit,hosted_audit=hosted_audit,
        input_limit=input_limit,seed=seed)
    retained._write_new(out,value)
    return value


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-view',type=Path,action='append',required=True)
    parser.add_argument('--hosted-view',type=Path,action='append',required=True)
    parser.add_argument('--input-limit',type=int,default=0,help='Zero keeps every hosted input entry')
    parser.add_argument('--sample-seed',type=int,default=0)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    value=prepare_inventory(local_views=args.local_view,hosted_views=args.hosted_view,
        out=args.out,input_limit=args.input_limit,seed=args.sample_seed)
    print(value['inventory_id'])
    return 0


if __name__=='__main__':
    raise SystemExit(main())
