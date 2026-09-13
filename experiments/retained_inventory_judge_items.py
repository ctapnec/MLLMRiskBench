"""Prepare every matching saved answer under its existing judging funding.

This is a no-call handoff. Missing text, absent funding and previously started
executions remain separate; none is silently replaced with another answer.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from experiments import retained_judge_inventory as inventory
from experiments import retained_response_judge as retained
from experiments import retained_hosted_judge_items as funding
from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_campaign_budget import load_bound_json
from experiments.retained_response_judge_execute import _write_new


def source_population(local_views, hosted_views):
    local = inventory.read_sources(local_views)
    hosted = inventory.read_sources(hosted_views)
    local_rows, local_audit = retained._candidates_from_view(
        *local, include_match_identity=True, include_missing=True, allow_empty=True)
    hosted_rows, hosted_audit = retained._candidates_from_view(
        *hosted, include_match_identity=True, include_missing=True, allow_empty=True,
        original_cells=local[0])
    return local_rows, hosted_rows, local_audit, hosted_audit, {
        'local': local[1], 'hosted': hosted[1]}, {cell['run_id']: cell for cell in hosted[0]}


def hosted_sources(hosted_views):
    programs, owners = {}, {}
    for path in dict.fromkeys(Path(path).resolve(strict=True) for path in hosted_views):
        source = json.loads(path.read_text())
        for descriptor in source['programs']:
            name = descriptor['path']
            if name not in programs:
                programs[name] = load_bound_json(Path(name), descriptor['sha256'])[0]
        for unit in source['units']:
            if unit['run_id'] in owners:
                raise ValueError('A hosted output has overlapping source preparations')
            program = programs[unit['program']]
            job = next(job for job in program['jobs'] if job['name'] == unit['job'])
            owners[unit['run_id']] = (program, job)
    return owners


def budget_snapshots(budgets):
    snapshots = []
    seen = set()
    for budget in budgets:
        key = (str(budget.root), budget.expected_plan_sha256)
        if key in seen:
            continue
        seen.add(key)
        current, ledger, slots = funding.current_budget_snapshot(budget)
        snapshots.append((dict(root=str(current.root), plan_sha256=current.expected_plan_sha256),
            ledger, slots, key[1]))
    return snapshots


def collect_items(*, saved_inventory, local_views, hosted_views, budgets):
    local, hosted, local_audit, hosted_audit, metadata, cells = source_population(local_views, hosted_views)
    selection = saved_inventory['selection']
    rebuilt = inventory.build_inventory(local, hosted, local_audit=local_audit, hosted_audit=hosted_audit,
        input_limit=selection['input_limit'], seed=selection['seed'])
    if rebuilt != saved_inventory:
        raise ValueError('All-output coverage changed; refresh the source inventory')
    owners = hosted_sources(hosted_views)
    snapshots = budget_snapshots(budgets)
    pending, owned, unfunded, missing = [], [], [], []
    for row in rebuilt['outputs']:
        identity = dict(cohort=row['cohort'], run_id=row['run_id'], attempt_id=row['attempt_id'],
            retained_row_sha256=row['retained_row_sha256'])
        if not row['judgeable_text']:
            missing.append(dict(identity, reason='missing_text'))
            continue
        meta = metadata[row['cohort']][row['sample_key']]
        prompt, text = meta['prepared_prompt'], meta['prepared_response'].strip()
        if (hashlib.sha256(prompt.encode()).hexdigest() != row['prompt_sha256']
            or hashlib.sha256(text.encode()).hexdigest() != row['response_sha256']):
            raise ValueError('Saved judging text differs from the selected output')
        expected_budget = None
        if row['cohort'] == 'hosted':
            program, job = owners[row['run_id']]
            if program['target'] != row['exact_model']:
                raise ValueError('Hosted output differs from its funded model')
            origin = cells[row['run_id']]['attempts'][row['attempt_id']]['params']['retained_origin']
            key = origin['selection']['input_identity_sha256']
            if key not in job['input_ids']:
                raise ValueError('Hosted output is outside its original funded input selection')
            call_id = program['requests'][key]['judge_call_ids']['hosted']
            expected_budget = program['budget_plan_sha256']
        else:
            call_id = 'judge-local-' + row['retained_row_sha256']
        candidates = [(descriptor, ledger, slots[call_id]) for descriptor, ledger, slots, original_plan in snapshots
            if call_id in slots and (expected_budget is None or expected_budget in {original_plan,descriptor['plan_sha256']})]
        if any(slot['provider'] != 'anthropic' or slot['pool'] != 'judge' for _, _, slot in candidates):
            raise ValueError('An output needs its existing Anthropic judging slot')
        started = [descriptor for descriptor, ledger, _ in candidates if ledger['attempts'].get(call_id)]
        if started:
            owned.append(dict(identity, call_id=call_id, budgets=started,
                reason='paid_slot_owned_by_existing_execution'))
        elif not candidates:
            unfunded.append(dict(identity, call_id=call_id, reason='no_matching_slot_in_selected_budgets'))
        else:
            # Explicit CLI budget order resolves duplicate unstarted local slots.
            # Only one physical assessment is selected for this saved answer.
            descriptor = candidates[0][0]
            pending.append(dict(row=row, prompt=prompt, text=text, call_id=call_id, budget=descriptor,
                input_identity=row['input_identity_sha256']))
    calls = [(item['budget']['root'], item['call_id']) for item in pending]
    if len(set(calls)) != len(calls):
        raise ValueError('Distinct saved answers cannot spend the same judging slot')
    if len(pending) + len(owned) + len(unfunded) + len(missing) != rebuilt['coverage']['retained_outputs']:
        raise ValueError('All-output judging handoff lost coverage')
    return pending, owned, unfunded, missing


def prepare(*, inventory_path, local_views, hosted_views, budgets, out):
    if out.exists() or not out.is_absolute() or out.parent.resolve(strict=True) != out.parent:
        raise ValueError('Judging items need a new resolved output directory')
    saved = json.loads(inventory_path.read_text())
    pending, owned, unfunded, missing = collect_items(saved_inventory=saved, local_views=local_views,
        hosted_views=hosted_views, budgets=budgets)
    out.mkdir(mode=0o700)
    for name, value in (('validated-items', pending), ('existing-execution-owned', owned),
                        ('unfunded-outputs', unfunded), ('missing-outputs', missing)):
        _write_new(out / (name + '.json'), value)
    _write_new(out / 'sources.json', dict(inventory=str(inventory_path),
        local_views=[str(path) for path in local_views], hosted_views=[str(path) for path in hosted_views],
        budgets=[dict(root=str(b.root), plan_sha256=b.expected_plan_sha256) for b in budgets]))
    result = dict(status='prepared_no_calls', scope='all_saved_outputs_on_selected_inputs',
        input_entries=saved['selection']['selected_inputs'], retained_outputs=saved['coverage']['retained_outputs'],
        selected_outputs=len(pending), existing_execution_owned=len(owned), unfunded_outputs=len(unfunded),
        missing_outputs=len(missing), by_model=dict(Counter(item['row']['exact_model'] for item in pending)),
        inventory_id=saved['inventory_id'], target_calls=0, judge_calls=0, provider_http_calls=0, model_loads=0,
        existing_verdicts_not_inferred=True, new_budget_created=False)
    _write_new(out / 'result.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--local-view', type=Path, action='append', required=True)
    parser.add_argument('--hosted-view', type=Path, action='append', required=True)
    parser.add_argument('--budget-root', type=Path, action='append', required=True)
    parser.add_argument('--budget-plan-sha256', action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if len(args.budget_root) != len(args.budget_plan_sha256):
        parser.error('Each selected budget needs its matching plan digest')
    result = prepare(inventory_path=args.inventory, local_views=args.local_view, hosted_views=args.hosted_view,
        budgets=[AttemptBudget(path, digest) for path, digest in zip(args.budget_root, args.budget_plan_sha256)],
        out=args.out)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
