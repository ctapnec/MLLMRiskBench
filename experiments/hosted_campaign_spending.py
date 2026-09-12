"""One precomputed campaign ceiling across retained execution ledgers.

Historical allocations are not spending limits in precalculated mode. Only
reported charges and complete reported-token upper bounds count toward the
original campaign ceiling. Unknown charges remain visible, never settled here.
"""
from __future__ import annotations

import json
from pathlib import Path


SCHEMA = 'ura-hosted-campaign-spending/1'


def _read(path):
    with Path(path).open('r', encoding='utf-8') as stream:
        return json.load(stream)


def validate_scope(document, root, plan_sha256, pools):
    """An explicit operator configuration, not an inferred budget increase."""
    from experiments.hosted_attempt_budget import BudgetError, _integer

    if (not isinstance(document, dict) or set(document) != {'schema', 'pool_caps_microusd', 'budgets'}
            or document['schema'] != SCHEMA or not isinstance(document['pool_caps_microusd'], dict)
            or not set(pools) <= set(document['pool_caps_microusd'])
            or not isinstance(document['budgets'], list) or not document['budgets']):
        raise BudgetError('campaign spending configuration fields differ')
    # A judge-only continuation has fewer pools than the whole campaign. It
    # must retain the full campaign totals, including other providers' ledgers,
    # while every pool it can actually spend from remains explicitly covered.
    for cap in document['pool_caps_microusd'].values():
        _integer(cap, 'precomputed campaign pool ceiling', zero=True)
    seen = set()
    for row in document['budgets']:
        if not isinstance(row, dict) or set(row) != {'root', 'plan_sha256'}:
            raise BudgetError('campaign spending needs exact budget references')
        path = Path(row['root'])
        digest = row['plan_sha256']
        if (not path.is_absolute() or path.resolve(strict=True) != path or not path.is_dir()
                or path in seen or not isinstance(digest, str) or len(digest) != 64
                or any(char not in '0123456789abcdef' for char in digest)):
            raise BudgetError('campaign spending budget reference is invalid or duplicated')
        if path == root and digest != plan_sha256:
            raise BudgetError('campaign spending current plan differs')
        seen.add(path)
    if root not in seen:
        raise BudgetError('campaign spending must include its current ledger')
    return document


def _ledger_totals(plan, ledger, digest):
    from experiments.hosted_attempt_budget import BudgetError, _integer, _reported_usage_bound

    if ledger.get('plan_sha256') != digest:
        raise BudgetError('campaign spending ledger plan differs')
    calls = {row['call_id']: row for row in plan['planned_calls']}
    totals = {key: {'tracked_spend_microusd': 0, 'unknown_usage_attempts': 0,
                    'unresolved_attempts': 0} for key in plan['pool_caps_microusd']}
    for key, attempts in ledger['attempts'].items():
        if key not in calls:
            raise BudgetError('campaign spending attempt has no planned call')
        call = calls[key]
        pool = totals[call['provider'] + ':' + call['pool']]
        for attempt in attempts.values():
            state = attempt['state']
            if state == 'settled':
                pool['tracked_spend_microusd'] += _integer(attempt['actual_cost_microusd'], 'reported cost', zero=True)
            elif state == 'bounded_unknown':
                pool['tracked_spend_microusd'] += _reported_usage_bound(attempt['usage_bound'])
                pool['unknown_usage_attempts'] += 1
            elif state in {'unknown', 'reserved'} and attempt['actual_cost_microusd'] is None:
                pool['unknown_usage_attempts' if state == 'unknown' else 'unresolved_attempts'] += 1
            else:
                raise BudgetError('campaign spending attempt state is invalid')
    return totals


def campaign_totals(money, plan, ledger, *, document=None):
    """Read current spending; recompute historical subtotals only when changed.

    All ledger writes are atomic. Inode/size/nanosecond timestamps invalidate
    cached subtotals. This performs no corpus scan or checksum validation.
    Concurrent in-flight settlement may exceed a reported-spend stop threshold.
    """
    from experiments.hosted_attempt_budget import BudgetError

    path = money.root / 'campaign-spending.json'
    if document is None and not path.exists():
        return None
    document = validate_scope(document if document is not None else _read(path), money.root,
                              money.expected_plan_sha256, plan['pool_caps_microusd'])
    cache = money.__dict__.setdefault('_campaign_history_totals', {})
    pools = {key: {'cap_microusd': cap, 'tracked_spend_microusd': 0,
                   'unknown_usage_attempts': 0, 'unresolved_attempts': 0}
             for key, cap in document['pool_caps_microusd'].items()}

    def stamp(paths):
        return tuple((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                     for s in (item.stat() for item in paths))

    for row in document['budgets']:
        directory = Path(row['root'])
        if directory == money.root:
            subtotal = _ledger_totals(plan, ledger, row['plan_sha256'])
        else:
            paths = (directory / 'plan.json', directory / 'ledger.json')
            before = stamp(paths)
            key = (row['root'], row['plan_sha256'])
            previous = cache.get(key)
            if previous and previous[0] == before:
                subtotal = previous[1]
            else:
                subtotal = _ledger_totals(_read(paths[0]), _read(paths[1]), row['plan_sha256'])
                if before == stamp(paths):
                    cache[key] = (before, subtotal)
        for key, values in subtotal.items():
            if key not in pools:
                raise BudgetError('campaign spending predecessor has an unconfigured pool')
            for name, value in values.items():
                pools[key][name] += value
    for pool in pools.values():
        pool['remaining_tracked_microusd'] = max(0, pool['cap_microusd'] - pool['tracked_spend_microusd'])
    return {'scope': 'whole_campaign', 'budget_ledgers': len(document['budgets']), 'pools': pools,
            'maximum_cost_holds': False}
