"""Prepare saved hosted answers for their existing funded Haiku slots.

No target, judge or provider is called. Missing answers stay in coverage;
already-started paid slots remain owned by their original execution.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from experiments import retained_response_judge as retained
from experiments.hosted_attempt_budget import AttemptBudget, _budget_lock
from experiments.hosted_campaign_budget import load_bound_json
from experiments.retained_response_judge_execute import _write_new


def current_budget_snapshot(budget, call_ids=None):
    """Follow recorded funding transfers, preserving slots and physical history."""
    seen=set()
    with _budget_lock(budget.root):
        _plan,ledger,slots=budget._load()
    if call_ids is None:
        call_ids=[key for key,slot in slots.items() if slot['provider']=='anthropic' and slot['pool']=='judge']
    while True:
        identity=(str(budget.root.resolve()),budget.expected_plan_sha256)
        if identity in seen:
            raise ValueError('Judging funding successor chain repeats a budget')
        seen.add(identity)
        marker=budget.root/'paid-circuit.json'
        if not marker.exists():
            return budget,ledger,slots
        value=json.loads(marker.read_text())
        if value.get('schema')!='ura-hosted-budget-superseded/1':
            return budget,ledger,slots  # Real provider/funding stops remain active.
        predecessor_matches=(value.get('status')=='superseded_not_a_target_failure'
            and value.get('predecessor_plan_sha256')==budget.expected_plan_sha256)
        if set(value)=={'schema','successor'}:
            # The original transfer marker kept its predecessor in the adjacent
            # handoff record, rather than repeating it in the closed budget.
            successor_path=Path(value['successor']['path'])
            handoff_path=successor_path.parent.parent/'budget-handoff.json'
            if handoff_path.is_file():
                handoff=json.loads(handoff_path.read_text())
                predecessor=handoff.get('predecessor_plan',{})
                predecessor_matches=(handoff.get('status')=='complete'
                    and all(handoff.get(key) is True for key in (
                        'all_paid_history_preserved','all_started_slots_unchanged','old_spending_closed'))
                    and predecessor.get('sha256')==budget.expected_plan_sha256
                    and Path(predecessor.get('path','')).resolve()==(budget.root/'plan.json').resolve()
                    and handoff.get('successor')==value['successor'])
        if not predecessor_matches:
            raise ValueError('Judging funding transfer names another predecessor')
        descriptor=value['successor'];path=Path(descriptor['path'])
        if path.name!='plan.json':
            raise ValueError('Judging funding transfer needs its recorded successor plan')
        load_bound_json(path,descriptor['sha256'])
        successor=AttemptBudget(path.parent,descriptor['sha256'])
        with _budget_lock(successor.root):
            _next_plan,next_ledger,next_slots=successor._load()
        for key in call_ids:
            if next_slots.get(key)!=slots.get(key) or key not in slots:
                raise ValueError('Judging funding transfer changed an original slot')
            if not set(ledger['attempts'].get(key,{})) <= set(next_ledger['attempts'].get(key,{})):
                raise ValueError('Judging funding transfer lost physical attempt history')
        budget,ledger,slots=successor,next_ledger,next_slots


def collect_items(preparation: Path, budget: AttemptBudget):
    value=json.loads(preparation.read_text())
    view=retained._read_view(preparation)
    rows,audit=retained._candidates_from_view(*view,allow_empty=True)
    programs={}
    for descriptor in value['programs']:
        program,_=load_bound_json(Path(descriptor['path']),descriptor['sha256'])
        if program['budget_plan_sha256']!=budget.expected_plan_sha256:
            raise ValueError('Hosted judging preparation belongs to another budget')
        programs[descriptor['path']]=program
    by_run={cell['run_id']:cell for cell in view[0]}
    sources={unit['run_id']:unit for unit in value['units']}
    mapped=[]
    seen=set()
    for row in rows:
        unit=sources[row['run_id']]
        program=programs[unit['program']]
        cell=by_run[row['run_id']]
        if row['exact_model']!=program['target']:
            raise ValueError('Saved output differs from its funded target')
        attempt=cell['attempts'][row['attempt_id']]
        identity=attempt['params']['retained_origin']['selection']['input_identity_sha256']
        job=next(job for job in program['jobs'] if job['name']==unit['job'])
        if identity not in job['input_ids']:
            raise ValueError('Saved output is outside its original funded job')
        call_id=program['requests'][identity]['judge_call_ids']['hosted']
        if call_id in seen:
            raise ValueError('Different outputs cannot spend the same hosted judging slot')
        seen.add(call_id)
        meta=view[1][row['sample_key']]
        prompt,text=meta['prepared_prompt'],meta['prepared_response'].strip()
        if (hashlib.sha256(prompt.encode()).hexdigest()!=row['prompt_sha256']
            or hashlib.sha256(text.encode()).hexdigest()!=row['response_sha256']):
            raise ValueError('Saved judging text changed')
        mapped.append(dict(row=row,prompt=prompt,text=text,call_id=call_id,
            budget=dict(root=str(budget.root),plan_sha256=budget.expected_plan_sha256),
            input_identity=identity,source_unit=unit['job'],source_program=unit['program']))
    # One snapshot per preparation, not a full ledger reread per answer.
    budget,ledger,slots=current_budget_snapshot(budget,[item['call_id'] for item in mapped])
    items,owned=[],[]
    for item in mapped:
        item['budget']=dict(root=str(budget.root),plan_sha256=budget.expected_plan_sha256)
        slot=slots[item['call_id']]
        if slot['provider']!='anthropic' or slot['pool']!='judge':
            raise ValueError('Saved output needs its existing Anthropic judging slot')
        if ledger['attempts'].get(item['call_id']):
            owned.append(dict(run_id=item['row']['run_id'],attempt_id=item['row']['attempt_id'],
                call_id=item['call_id'],reason='paid_slot_owned_by_existing_execution'))
        else:
            items.append(item)
    return items,owned,audit


def prepare(*,preparation: Path,budget: AttemptBudget,out: Path):
    if out.exists() or not out.is_absolute() or out.parent.resolve(strict=True)!=out.parent:
        raise ValueError('Judging items need a new resolved output directory')
    items,owned,audit=collect_items(preparation,budget)
    out.mkdir(mode=0o700)
    _write_new(out/'validated-items.json',items)
    _write_new(out/'existing-execution-owned.json',owned)
    _write_new(out/'sources.json',dict(preparation=str(preparation.resolve()),budget=dict(
        root=str(budget.root),plan_sha256=budget.expected_plan_sha256)))
    result=dict(status='prepared_no_calls',selected_outputs=len(items),existing_execution_owned=len(owned),
        population=audit,by_model=dict(Counter(item['row']['exact_model'] for item in items)),
        scope='measured_common_evaluable_saved_hosted_answers',
        target_calls=0,judge_calls=0,provider_http_calls=0,model_loads=0,
        existing_judgments_reused=False,additional_context_assessments_included=False)
    _write_new(out/'result.json',result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preparation',type=Path,required=True)
    parser.add_argument('--budget-root',type=Path,required=True)
    parser.add_argument('--budget-plan-sha256',required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args(argv)
    result=prepare(preparation=args.preparation,
        budget=AttemptBudget(args.budget_root,args.budget_plan_sha256),out=args.out)
    print(json.dumps(result))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
