"""Plan and resume funded judging of all selected saved outputs.

Uses the existing retained-response executor and original campaign funding.
Internal plan groups are a storage bound, not sequential collection phases.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import time

from experiments import retained_inventory_judge_items as handoff
from experiments import retained_response_judge as retained
from experiments import retained_response_judge_execute as execution
from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_request_tokens import cached_count_request
from experiments.hosted_retained_inputs import _descriptor
from ura.judges.llm import LLMJudge
from ura.targets.api import _retryable_transport_error, _transport_retry_delay
from ura.artifact_checks import artifact_verification_cli


def read(path):
    return json.loads(Path(path).read_text())


def read_items(descriptor):
    # The whole response selection can exceed the small budget document limit.
    # Its saved byte length owns the read bound; do not impose an unrelated cap.
    value, observed = execution._read_regular(Path(descriptor['path']), label='saved judging outputs',
        max_bytes=descriptor['bytes'])
    if observed['sha256'] != descriptor['sha256'] or not isinstance(value, list):
        raise ValueError('Saved judging output list changed')
    return value


def _selected_items(plan, items):
    result = []
    for row in plan['selected']:
        item = items[row['retained_row_sha256']]
        if any(item['row'][key] != value for key, value in row.items() if key != 'same_model_judge'):
            raise ValueError('Judging plan differs from its saved output')
        if (hashlib.sha256(item['prompt'].encode()).hexdigest() != row['prompt_sha256']
                or hashlib.sha256(item['text'].encode()).hexdigest() != row['response_sha256']):
            raise ValueError('Judging text differs from its saved output')
        result.append((row, item['prompt'], item['text']))
    return result


def _original_items(items_root):
    """Reconcile source content once, independently of later paid-slot state."""
    result = read(items_root / 'result.json')
    if result.get('status') != 'prepared_no_calls' or result.get('scope') != 'all_saved_outputs_on_selected_inputs':
        raise ValueError('Select a completed all-output funding preparation')
    sources = read(items_root / 'sources.json')
    saved = read(sources['inventory'])
    local, hosted, la, ha, metadata, _ = handoff.source_population(
        [Path(p) for p in sources['local_views']], [Path(p) for p in sources['hosted_views']])
    rebuilt = handoff.inventory.build_inventory(local, hosted, local_audit=la, hosted_audit=ha,
        input_limit=saved['selection']['input_limit'], seed=saved['selection']['seed'])
    if rebuilt != saved:
        raise ValueError('Saved output inventory changed')
    actual = {row['retained_row_sha256']: row for row in rebuilt['outputs']}
    items = read(items_root / 'validated-items.json')
    for item in items:
        row = item['row']
        meta = metadata[row['cohort']][row['sample_key']]
        if (actual.get(row['retained_row_sha256']) != row
                or item['prompt'] != meta['prepared_prompt'] or item['text'] != meta['prepared_response'].strip()):
            raise ValueError('Funded item differs from its original saved answer')
    if len(items) != result['selected_outputs'] or len({i['row']['retained_row_sha256'] for i in items}) != len(items):
        raise ValueError('Funded output population changed')
    return items, result


def _count_oversized(items, requests, bounds, *, model, normalized, cache, allow_network):
    oversized = {key for key, request in requests.items()
        if request['input_tokens_estimate'] + 5 * request['max_output_tokens'] > bounds[request['call_id']]}
    if not oversized or not allow_network:
        return requests, 0
    target = execution._build_haiku_judge(model, normalized)
    judge = LLMJudge(target)
    counts, audit = {}, {}
    cache.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        for row, prompt, text in items:
            key = row['retained_row_sha256']
            point, response = execution._judge_inputs(row, prompt, text)
            request = target.build_request(judge.build_judge_dialog(point, response), seed=judge._judge_seed(response))
            for retry in range(4):
                try:
                    counts[key] = cached_count_request(target, request, cache_root=cache,
                        allow_network=key in oversized, audit=audit)
                    break
                except Exception as exc:
                    if retry == 3 or not _retryable_transport_error(exc, provider='anthropic'):
                        raise
                    time.sleep(_transport_retry_delay(exc, retry + 1))
    finally:
        if target._client is not None:
            target._client.close()
    # Ordinary requests get local estimate receipts; only oversized requests
    # may contact the count endpoint. The executor expects one receipt format
    # throughout a group. Keep that cache if a later count fails.
    counted = execution.build_shared_request_receipts(
        [item for item in items if item[0]['retained_row_sha256'] in counts], judge_model=model,
        normalized_api=normalized, call_ids={key: requests[key]['call_id'] for key in counts}, token_counts=counts)
    return dict(requests, **counted), audit.get('http_attempts', 0)


def prepare(*, items_root, judge_model, api_config, pricing_config, pricing_as_of, out, allow_token_counts=False):
    items_root, out = items_root.resolve(strict=True), out.resolve()
    api = _descriptor(api_config)
    pricing = _descriptor(pricing_config)
    request = dict(items=_descriptor(items_root / 'validated-items.json'), sources=_descriptor(items_root / 'sources.json'),
        items_root=str(items_root), judge_model=judge_model, api=api, pricing=pricing,
        pricing_as_of=pricing_as_of, allow_token_counts=allow_token_counts)
    out.mkdir(parents=True, mode=0o700, exist_ok=True)
    with execution._exclusive_lock(out):
        if (out / 'request.json').exists():
            if read(out / 'request.json') != request:
                raise ValueError('Resume the original all-output judging preparation')
            if (out / 'result.json').exists():
                return read(out / 'result.json')
        else:
            execution._write_new(out / 'request.json', request)
        items, coverage = _original_items(items_root)
        normalized, _ = execution._load_api_config(api_config, judge_model=judge_model, expected_sha256=api['sha256'])
        if normalized['max_tokens'] != 512:
            raise ValueError('Saved-output Haiku judging uses 512 output tokens')
        condition = retained.load_pricing_condition(pricing_config, expected_sha256=pricing['sha256'],
            judge_model=judge_model, as_of=pricing_as_of)
        groups = defaultdict(list)
        for item in items:
            groups[(item['budget']['root'], item['budget']['plan_sha256'])].append(item)
        budgets = [AttemptBudget(Path(root), digest) for root, digest in groups]
        snapshots = {(d['root'], d['plan_sha256']): (ledger, slots)
            for d, ledger, slots, _original_plan in handoff.budget_snapshots(budgets)}
        plans, pending, count_http = [], [], 0
        for key, group in sorted(groups.items()):
            ledger, slots = snapshots[key]
            adjusted = {row['call_id']: row['bound_microusd'] for row in ledger.get('allowance_adjustments', [])}
            bounds = {call: adjusted.get(call, slot['bound_microusd']) for call, slot in slots.items()}
            group.sort(key=lambda item: item['row']['retained_row_sha256'])
            for start in range(0, len(group), 2000):
                selected = group[start:start + 2000]
                if any(ledger['attempts'].get(item['call_id']) for item in selected):
                    raise ValueError('An output is now owned by another judging execution; refresh its funding review')
                unit = out / f'plan-{len(plans) + 1:03d}'
                unit.mkdir(mode=0o700, exist_ok=True)
                source = dict(items=request['items'], selected_output_ids=[i['row']['retained_row_sha256'] for i in selected])
                _save_same(unit / 'sources.json', source)
                descriptor = _descriptor(unit / 'sources.json')
                rows = [{field: item['row'][field] for field in retained._SELECTED_FIELDS - {'same_model_judge'}}
                    for item in selected]
                plan = retained.build_plan(rows, population_audit=dict(validated_joined_rows=len(rows),
                    eligible_usable_outputs=len(rows), excluded_missing_outputs=0, excluded_source_authoritative_rows=0),
                    source_descriptor={k: descriptor[k] for k in ('sha256', 'bytes')} | {'file': 'sources.json'},
                    judge_model=judge_model, api_config_sha256=api['sha256'], pricing_condition=condition,
                    limit=len(rows), seed=0, max_cost_microusd=4 * sum(bounds[item['call_id']] for item in selected))
                by_id = {item['row']['retained_row_sha256']: item for item in selected}
                ordered = _selected_items(plan, by_id)
                receipts = execution.build_shared_request_receipts(ordered, judge_model=judge_model,
                    normalized_api=normalized, call_ids={k: item['call_id'] for k, item in by_id.items()})
                receipts, calls = _count_oversized(ordered, receipts, bounds, model=judge_model, normalized=normalized,
                    cache=out / 'count-cache', allow_network=allow_token_counts)
                count_http += calls
                pending.extend(dict(output=key, call_id=value['call_id'], required_microusd=
                    value['input_tokens_estimate'] + 5 * value['max_output_tokens'], funded_microusd=bounds[value['call_id']])
                    for key, value in receipts.items()
                    if value['input_tokens_estimate'] + 5 * value['max_output_tokens'] > bounds[value['call_id']])
                _save_same(unit / 'plan.json', plan)
                _save_same(unit / 'shared-requests.json', receipts)
                plans.append(dict(root=str(unit), budget=dict(root=key[0], plan_sha256=key[1]), selected=len(selected),
                    first_attempt_estimate_microusd=sum(r['input_tokens_estimate'] + 5 * r['max_output_tokens'] for r in receipts.values())))
        result = dict(status='needs_funding_review' if pending else 'ready_for_funded_judging',
            coverage=coverage, selected_outputs=len(items), plans=plans, funding_review=pending,
            target_calls=0, judge_calls=0, token_count_http_attempts=count_http, request=request,
            first_attempt_estimate_microusd=sum(p['first_attempt_estimate_microusd'] for p in plans))
        execution._write_new(out / 'result.json', result)
        return result


def _save_same(path, value):
    if path.exists():
        if read(path) != value:
            raise ValueError('Retained judging preparation changed; keep its original artifacts')
    else:
        execution._write_new(path, value)


def execute(*, preparation, out, workspace_ids=(), console_db=None, workers=2):
    if workers not in (1, 2):
        raise ValueError('Use one or two Haiku network workers')
    ready = read(preparation / 'result.json')
    if ready['status'] != 'ready_for_funded_judging':
        raise ValueError('Resolve the saved funding review before paid execution')
    request = ready['request']
    raw = read_items(request['items'])
    originals = {item['row']['retained_row_sha256']: item for item in raw}
    # Source content is reconciled once per launch, not once per plan or call.
    observed, _ = _original_items(Path(request['items_root']))
    if raw != observed or len(raw) != ready['selected_outputs']:
        raise ValueError('Saved all-output judging selection changed')
    assigned = [row['retained_row_sha256'] for entry in ready['plans']
        for row in read(Path(entry['root']) / 'plan.json')['selected']]
    if len(assigned) != len(originals) or set(assigned) != set(originals):
        raise ValueError('Prepared groups must judge every funded output exactly once')
    out.mkdir(parents=True, mode=0o700, exist_ok=True)
    with execution._exclusive_lock(out):
        _save_same(out / 'preparation.json', _descriptor(preparation / 'result.json'))
        def work(entry):
            unit = Path(entry['root'])
            plan = read(unit / 'plan.json')
            source = read(unit / 'sources.json')
            items = _selected_items(plan, originals)
            selected_ids = sorted(row['retained_row_sha256'] for row, _, _ in items)
            if (source['items'] != request['items'] or source['selected_output_ids'] != selected_ids
                    or entry['selected'] != len(items)):
                raise ValueError('Prepared judging group lost its exact output ownership')
            def reconcile(view, actual_plan, source_descriptor):
                if (Path(view) != Path(request['items_root']) or actual_plan != plan
                        or source_descriptor != plan['source']):
                    raise ValueError('Judging execution differs from its prepared group')
                return items
            completed = execution.execute(plan_path=unit / 'plan.json', runner_view=Path(request['items_root']),
                source_receipt=unit / 'sources.json', api_config=Path(request['api']['path']),
                pricing_config=Path(request['pricing']['path']), out=out / unit.name,
                shared_budget=AttemptBudget(Path(entry['budget']['root']), entry['budget']['plan_sha256']),
                shared_requests=read(unit / 'shared-requests.json'), selection_reconciler=reconcile,
                retain_invalid_verdicts=True, workspace_ids=workspace_ids, console_db=console_db)
            return dict(root=str(unit), completion=str(completed), **read(completed))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            completed = list(pool.map(work, ready['plans']))
        result = dict(status='selected_judging_complete', selected_outputs=ready['selected_outputs'], plans=completed,
            coverage=ready['coverage'], target_calls=0, whole_campaign_complete=False)
        execution._write_atomic(out / 'result.json', result)
        return result


@artifact_verification_cli
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preparation', type=Path)
    parser.add_argument('--items-root', type=Path)
    parser.add_argument('--judge-model')
    parser.add_argument('--api-config', type=Path)
    parser.add_argument('--pricing-config', type=Path)
    parser.add_argument('--pricing-as-of')
    parser.add_argument('--allow-token-counts', action='store_true')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--ack-paid-execution', action='store_true')
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--workspace-id', default=os.environ.get('URA_CAMPAIGN_WORKSPACE_ID', ''))
    parser.add_argument('--matching-workspace-id', default='')
    parser.add_argument('--console-db', type=Path, default=os.environ.get('URA_CAMPAIGN_CONSOLE_DB'))
    parser.add_argument('--verify-artifact-sha256', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.execute:
        if not args.preparation or not args.ack_paid_execution:
            parser.error('Execution needs its original preparation and --ack-paid-execution')
        result = execute(preparation=args.preparation, out=args.out, workers=args.workers,
            workspace_ids=[v for v in (args.workspace_id, args.matching_workspace_id) if v], console_db=args.console_db)
    else:
        if not all((args.items_root, args.judge_model, args.api_config, args.pricing_config, args.pricing_as_of)):
            parser.error('Preparation needs saved items, judge, API configuration, pricing and pricing date')
        result = prepare(items_root=args.items_root, judge_model=args.judge_model, api_config=args.api_config,
            pricing_config=args.pricing_config, pricing_as_of=args.pricing_as_of, out=args.out,
            allow_token_counts=args.allow_token_counts)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
