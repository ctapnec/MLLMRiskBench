"""Apply a reviewed monetary allowance to an unchanged Runner invocation.

The existing provider hook checks every physical HTTP attempt, including retries.
Counted-request allowances are conservative accounting, not a provider invoice.
The shared SQLite counter covers diagnostics, measured calls and inline judges.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from decimal import Decimal, ROUND_CEILING
import hashlib
import json
import os
from pathlib import Path
import runpy
import sqlite3
import sys
import time


def reserve(path, policy, *, provider, model, amount, input_tokens, output_tokens):
    if type(amount) is not int or amount < 0:
        raise ValueError('Invalid request spending allowance')
    identity = hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()
    with sqlite3.connect(path, timeout=30) as db:
        db.execute('CREATE TABLE IF NOT EXISTS allowance (id INTEGER PRIMARY KEY, policy TEXT NOT NULL, used INTEGER NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS attempts (time REAL, provider TEXT, model TEXT, allowance INTEGER, input_tokens INTEGER, output_tokens INTEGER)')
        db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT OR IGNORE INTO allowance VALUES (1,?,0)', (identity,))
        held, used = db.execute('SELECT policy,used FROM allowance WHERE id=1').fetchone()
        if held != identity:
            raise ValueError('Campaign spending settings changed; retain the original allowance for continuation')
        if used + amount > policy['max_microusd']:
            raise ValueError('Campaign spending ceiling reached before the next API attempt. Saved answers remain available.')
        db.execute('UPDATE allowance SET used=? WHERE id=1', (used+amount,))
        db.execute('INSERT INTO attempts VALUES (?,?,?,?,?,?)', (time.time(),provider,model,amount,input_tokens,output_tokens))


@contextmanager
def spending(policy_path):
    from ura.targets.api import build_api_target, provider_attempt_admission
    from experiments.hosted_request_tokens import cached_count_request
    policy_path = Path(policy_path).resolve(strict=True)
    policy = json.loads(policy_path.read_text())
    if type(policy.get('max_microusd')) is not int or policy['max_microusd'] <= 0:
        raise ValueError('Campaign spending ceiling must be positive')
    targets = {}
    for route in policy['routes']:
        key = (route['provider'], route['model'])
        if key in targets:
            raise ValueError('The spending policy has ambiguous provider/model settings')
        targets[key] = (build_api_target(route['spec'], config=route['config']), route)
    cache = policy_path.parent/'token-counts'
    cache.mkdir(exist_ok=True)

    def admit(provider, request, number):
        key = (provider, request.get('model'))
        if key not in targets:
            raise ValueError('This API route is outside the reviewed campaign spending policy')
        target, route = targets[key]
        count = cached_count_request(target, request, cache_root=cache, allow_network=True)
        # Gemini carries generation settings in config; other supported adapters
        # carry one explicit maximum in the top-level provider request.
        allowance = next((request[name] for name in ('max_tokens','max_completion_tokens','max_output_tokens') if name in request), None)
        if allowance is None:
            allowance = request.get('config', {}).get('max_output_tokens')
        if type(allowance) is not int or allowance <= 0:
            raise ValueError('The API request lacks its reviewed output allowance')
        amount = int((Decimal(count['input_tokens'])*Decimal(str(route['input_price'])) +
                      Decimal(allowance)*Decimal(str(route['output_price']))).to_integral_value(rounding=ROUND_CEILING))
        reserve(policy_path.parent/'spending.sqlite', policy, provider=provider, model=key[1], amount=amount,
                input_tokens=count['input_tokens'], output_tokens=allowance)

    with provider_attempt_admission(admit):
        yield


def main(argv=None):
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--runner-root', type=Path, required=True)
    parser.add_argument('runner_args', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    root = args.runner_root.resolve(strict=True)
    os.chdir(root)
    # Import the original pinned Runner and adapters, not the console release.
    sys.path[:0] = [str(root),str(root/'src')]
    raw = args.runner_args
    if raw[:1] == ['--']:
        raw = raw[1:]
    sys.argv = ['experiments.run_matrix', *raw]
    with spending(args.policy):
        runpy.run_module('experiments.run_matrix', run_name='__main__')


if __name__ == '__main__':
    main()
