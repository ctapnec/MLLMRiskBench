"""Prepare and resume output-specific assessment from the campaign index.

Uses the existing retained Haiku executor and local judge cascade. It never
constructs a target-under-test, reconstructs a corpus or changes saved answers.
"""
import argparse
from collections import Counter
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from experiments import retained_response_judge as retained
from experiments import retained_response_judge_execute as executor
from experiments.rig_web_app.human_review_inventory import read_campaign


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def pending(output, mode, judge):
    for identity, result in output['judgments'].items():
        if result['status'] != 'valid':
            continue
        if mode == 'local' and identity.startswith('local'):
            return False
        if mode == 'haiku' and (identity == judge or identity.startswith(judge+':')):
            return False
    return True


def candidates(snapshot, mode, judge, limit):
    selected=[];dispositions=Counter()
    for output in snapshot['outputs']:
        if not pending(output,mode,judge):
            dispositions['already_judged']+=1;continue
        meta=output['metadata']
        if not meta['common_metrics_eligible']:
            dispositions['source_specific_metric']+=1;continue
        if limit and len(selected)>=limit:
            dispositions['outside_requested_limit']+=1;continue
        try:
            cell=dict(run_id=meta['run_id'],model=meta['model'],manifest=output['manifest'])
            rows,_=retained._candidates_from_view([cell],{output['sample_key']:meta},
                {output['sample_key']:dict(attempt_id=meta['attempt_id'])},
                dict(policy_evaluable_samples=1,common_ineligible_evaluable_rows_excluded=0))
            if mode=='local':
                stages=output['manifest']['config']['components']['judge_cascade']['stages']
                if len(stages)!=2 or stages[0].get('name')!='rules' or stages[1].get('name')!='guardrail':
                    dispositions['original_local_cascade_unavailable']+=1;continue
            selected.append(dict(row=rows[0],prompt=meta['prepared_prompt'],text=meta['prepared_response'].strip(),source=output))
        except (ValueError,KeyError,TypeError):
            dispositions['generation_context_unavailable']+=1
    return selected,dict(dispositions)


def prepare(args):
    root=args.out.resolve()
    if not root.is_relative_to(args.results_root.resolve()):
        raise ValueError('Choose an assessment output inside the campaign results store')
    root.mkdir(parents=True,exist_ok=True)
    request={key:str(getattr(args,key)) for key in ('database','campaign','results_root','kind','judge_model','limit','model_store','max_cost_microusd')}
    for key in ('api_config','pricing_config'):
        path=getattr(args,key)
        request[key]=hashlib.sha256(path.read_bytes()).hexdigest() if path else None
    if (root/'result.json').exists():
        if read(root/'request.json')!=request:
            raise ValueError('This assessment belongs to a different selection; choose a new output directory')
        return read(root/'result.json')
    executor._write_atomic(root/'request.json',request)
    snapshot=read_campaign(args.database,args.campaign,args.results_root,include_records=True)
    items,dispositions=candidates(snapshot,args.kind,args.judge_model,args.limit)
    executor._write_atomic(root/'items.json',items)
    source=dict(campaign=args.campaign,items_sha256=hashlib.sha256((root/'items.json').read_bytes()).hexdigest(),
        indexed_assignments=snapshot['measured_assignments'],scope='Saved measured outputs; common-metric evaluable turns; image judgments use text proxies')
    executor._write_atomic(root/'source.json',source)
    result=dict(status='prepared',kind=args.kind,campaign=args.campaign,selected_outputs=len(items),
        dispositions=dispositions,assignment_outcomes=snapshot['assignment_outcomes'],unavailable=snapshot['unavailable'],
        target_calls=0,judge_calls=0,plans=[],model_store=args.model_store)
    if args.kind=='haiku' and items:
        if args.max_cost_microusd<=0:
            raise ValueError('Choose a positive Haiku spending ceiling')
        normalized,api=executor._load_api_config(args.api_config,judge_model=args.judge_model,
            expected_sha256=hashlib.sha256(args.api_config.read_bytes()).hexdigest())
        if normalized['max_tokens']!=512:
            raise ValueError('Saved-output Haiku assessment requires its separate 512-token judge configuration')
        # Freeze non-secret endpoint settings and prices with this assessment.
        # UI inputs already live at these destinations. Do not rewrite their
        # serialization after binding it in request.json: an unchanged resume
        # must retain the exact originally selected settings.
        if args.api_config.resolve() != root/'api.json':
            executor._write_atomic(root/'api.json',read(args.api_config))
        if args.pricing_config.resolve() != root/'pricing.json':
            executor._write_atomic(root/'pricing.json',read(args.pricing_config))
        condition=retained.load_pricing_condition(root/'pricing.json',expected_sha256=hashlib.sha256((root/'pricing.json').read_bytes()).hexdigest(),
            judge_model=args.judge_model,as_of=date.today().isoformat())
        target=executor._build_haiku_judge(args.judge_model,normalized)
        from ura.judges.llm import LLMJudge
        bounds=executor._cost_bounds(LLMJudge(target),[(i['row'],i['prompt'],i['text']) for i in items],max_output_tokens=512)
        # Existing executor uses the same conservative byte-based input bound.
        # Keep room for its three eligible HTTP retries; no answer retries.
        required=sum(bounds.values())*4
        result.update(max_cost_microusd=args.max_cost_microusd,first_attempt_bound_microusd=sum(bounds.values()),
                      retry_inclusive_bound_microusd=required,judge_model=args.judge_model)
        if required>args.max_cost_microusd:
            result['status']='over_budget'
        else:
            descriptor=retained._regular_descriptor(root/'source.json',hashlib.sha256((root/'source.json').read_bytes()).hexdigest())
            api_sha=hashlib.sha256((root/'api.json').read_bytes()).hexdigest()
            for start in range(0,len(items),2000):
                group=items[start:start+2000]
                plan=retained.build_plan([i['row'] for i in group],population_audit=dict(validated_joined_rows=len(group),
                    eligible_usable_outputs=len(group),excluded_missing_outputs=0,excluded_source_authoritative_rows=0),
                    source_descriptor=descriptor,judge_model=args.judge_model,api_config_sha256=api_sha,
                    pricing_condition=condition,limit=len(group),seed=0,
                    max_cost_microusd=sum(bounds[i['row']['retained_row_sha256']] for i in group)*4)
                filename='plan-'+str(start//2000)+'.json'
                executor._write_atomic(root/filename,plan);result['plans'].append(filename)
    executor._write_atomic(root/'result.json',result)
    return result


def local_execute(root,prepared,items,database):
    from experiments.retained_native_judge_execute import source_runtime,source_cascade
    from experiments.rig_web_app.storage import ConsoleDB
    from experiments.rig_web_app.workspace_judge_settings import local_settings
    from ura.judges.base import JudgeCascadeDecisionError
    from ura.data_models import Response
    db=ConsoleDB(database);cache={};done=0
    destination=root/'local-verdicts';destination.mkdir(exist_ok=True)
    try:
        for item in items:
            row=item['row'];source=item['source'];manifest=source['manifest'];condition=manifest['config']['components']['judge_cascade']
            identity='local-cascade-indexed-'+retained._sha(dict(cascade=condition,scope='common-text-proxy',revision=manifest['config']['run']['project_revision']))[:24]
            path=destination/(row['retained_row_sha256']+'.json')
            if path.exists():
                artifact=read(path)
                if artifact['response']!=source['response'] or artifact['judge_id']!=identity:
                    raise ValueError('Saved local assessment no longer matches its answer or judge')
            else:
                key=retained._sha(condition)
                if key not in cache:
                    # Reuse the original admitted model store and its metadata checks.
                    runtime=source_runtime(dict(out=source['out'],run_id=row['run_id'],runner_argv=['--model-acquisition-store',prepared['model_store']]))
                    cache[key]=source_cascade(condition,runtime)
                point,_=executor._judge_inputs(row,item['prompt'],item['text'])
                response=Response.model_validate(source['response'])
                try:
                    judgment,trail=cache[key].judge(point,response)
                    judgment=judgment.model_copy(update={'run_id':row['run_id'],'raw':dict(judgment.raw,
                        source=row['source'],risk_category=row['risk'],expected_behavior=row['expected_behavior'],
                        common_metrics_eligible=True,policy_evaluable_turn=True)})
                    artifact=dict(status='valid',judge_id=identity,response=source['response'],judgment=judgment.model_dump(mode='json'),
                                  trail=[j.model_dump(mode='json') for j in trail])
                except JudgeCascadeDecisionError as exc:
                    artifact=dict(status='invalid',judge_id=identity,response=source['response'],
                        judgment=dict(run_id=row['run_id'],attempt_id=row['attempt_id'],label=None),
                        trail=[j.model_dump(mode='json') for j in exc.trail],reason='Judge abstained')
                executor._write_new(path,artifact)
            db.publish_workspace_results(prepared['campaign'],assignments=[],responses=[],judgments=[dict(
                response_id=source['response_id'],judge_id=identity,status=artifact['status'],
                label=artifact['judgment']['label'],source_ref=str(path),
                judge_settings=local_settings(source=dict(judge_cascade=condition,approximate_common_metrics=False)))])
            done+=1
            print(json.dumps(dict(assessed=done,selected=len(items))),flush=True)
    finally:
        for cascade in cache.values():
            for judge in cascade.stages:
                close=getattr(judge,'close',None)
                if close:close()
        db.close()


def execute(args):
    root=args.out.resolve(strict=True);prepared=read(root/'result.json')
    if prepared['status']!='prepared':
        raise ValueError('Resolve the assessment budget before starting')
    items=read(root/'items.json');source=read(root/'source.json')
    if source['items_sha256']!=hashlib.sha256((root/'items.json').read_bytes()).hexdigest():
        raise ValueError('Prepared response selection changed')
    if prepared['kind']=='local':
        with executor._exclusive_lock(root/'execution'):
            local_execute(root,prepared,items,args.database)
    else:
        mapping={i['row']['retained_row_sha256']:i for i in items}
        def reconcile(_view,plan,_source):
            from experiments.retained_inventory_judging import _selected_items
            return _selected_items(plan,mapping)
        for filename in prepared['plans']:
            executor.execute(plan_path=root/filename,runner_view=root,source_receipt=root/'source.json',
                api_config=root/'api.json',pricing_config=root/'pricing.json',out=root/(Path(filename).stem+'-judgments'),
                selection_reconciler=reconcile,retain_invalid_verdicts=True,
                workspace_ids=[prepared['campaign']],console_db=args.database)
    executor._write_atomic(root/'completion.json',dict(status='complete',selected_outputs=len(items),target_calls=0))


def main(argv=None):
    parser=argparse.ArgumentParser(__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--database',type=Path,required=True)
    parser.add_argument('--campaign')
    parser.add_argument('--results-root',type=Path)
    parser.add_argument('--kind',choices=['local','haiku'],default='local')
    parser.add_argument('--judge-model',default='')
    parser.add_argument('--api-config',type=Path)
    parser.add_argument('--pricing-config',type=Path)
    parser.add_argument('--max-cost-microusd',type=int,default=0)
    parser.add_argument('--model-store',default=os.environ.get('URA_MODEL_STORE',''))
    parser.add_argument('--limit',type=int,default=0)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    if args.limit<0:parser.error('limit must be nonnegative')
    if args.execute:
        (args.out/'execution').mkdir(exist_ok=True)
        execute(args)
    else:
        print(json.dumps(prepare(args)),flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
