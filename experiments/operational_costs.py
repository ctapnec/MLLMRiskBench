"""Read-only operational costs from explicitly registered hosted attempt ledgers.

This view neither funds calls nor reports a provider credit balance. Registration
avoids recursive result scans; unchanged files reuse their metadata-keyed parse.
"""
from __future__ import annotations

import argparse
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import tempfile

from ura.strict_json import strict_json_loads


_REGISTRY = "operational-cost-sources"
_SCHEMA = "ura-operational-cost-source/1"
_MAX_BYTES = 64 * 1024 * 1024


@lru_cache(maxsize=256)
def _read_cached(path: Path, identity: tuple) -> dict:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise ValueError("cost source exceeds the supported file size")
    value = strict_json_loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("cost source is not an object")
    if _identity(path) != identity:
        raise ValueError("cost source changed while being read; refresh the view")
    return value


def _identity(path: Path) -> tuple:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _read(path: Path) -> dict:
    return _read_cached(path, _identity(path))


def _within(root: Path, path: Path) -> Path:
    resolved = path.resolve(strict=True)
    resolved.relative_to(root)
    return resolved


def register_budget(results_root: Path, budget_root: Path, *, label: str = "") -> Path:
    """Register a real budget once; aliases to that directory share one entry."""
    root = Path(results_root).resolve(strict=True)
    budget = _within(root, Path(budget_root))
    if not (budget / "plan.json").is_file() or not (budget / "ledger.json").is_file():
        raise ValueError("operational cost registration needs a plan and ledger")
    relative = budget.relative_to(root).as_posix()
    registry = root / _REGISTRY
    registry.mkdir(exist_ok=True)
    # A locator key, not content checksum verification.
    path = registry / (hashlib.sha256(relative.encode()).hexdigest()[:24] + ".json")
    value = {"schema": _SCHEMA, "budget": relative, "label": label or budget.parent.name}
    if path.exists() and _read(path) == value:
        return path
    descriptor, temporary = tempfile.mkstemp(dir=registry, prefix=".register-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return path


def _amount(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("invalid operational cost or count")
    return value


def campaign_costs(results_root: Path) -> dict:
    """Merge physical attempt identities, never sum resumed/copied budget caps."""
    root = Path(results_root).resolve(strict=True)
    registry = root / _REGISTRY
    if not registry.exists():
        return {"registered": False, "rows": [], "sources": [], "errors": []}
    paths = sorted(registry.glob("*.json"))
    if len(paths) > 512:
        return {"registered": True, "rows": [], "sources": [], "errors": ["too many cost sources"]}
    calls, sources, errors, seen_roots = {}, [], [], set()
    for path in paths:
        try:
            source = _read(path)
            if source.get("schema") != _SCHEMA:
                raise ValueError("unsupported cost registration")
            budget = _within(root, root / source["budget"])
            if budget in seen_roots:
                continue
            seen_roots.add(budget)
            plan, ledger = _read(budget / "plan.json"), _read(budget / "ledger.json")
            if (plan.get("schema") not in {"ura-hosted-attempt-budget-plan/1", "ura-hosted-attempt-budget-plan/2"}
                    or ledger.get("schema") not in {"ura-hosted-attempt-budget-ledger/1",
                        "ura-hosted-attempt-budget-ledger/2", "ura-hosted-attempt-budget-ledger/3"}):
                raise ValueError("unsupported operational budget format")
            if plan.get('schema') == 'ura-hosted-attempt-budget-plan/2' and plan.get('reservation_policy') != 'per_attempt':
                raise ValueError('unsupported continuous budget policy')
            policy_path = budget / 'spending-policy.json'
            spending_policy = 'reserved_maximum'
            if policy_path.exists():
                policy = _read(policy_path)
                if policy != {'budget_plan_sha256': ledger['plan_sha256'], 'mode': 'precalculated'}:
                    raise ValueError('cost source spending policy differs from its plan')
                spending_policy = 'precalculated'
            if (not isinstance(plan.get("planned_calls"), list)
                    or not isinstance(ledger.get("attempts"), dict)
                    or any(not isinstance(attempts, dict) for attempts in ledger["attempts"].values())):
                raise ValueError("invalid planned calls or attempt inventory")
            allowances = {row["call_id"]: _amount(row["bound_microusd"])
                          for row in ledger.get("allowance_adjustments", [])}
            planned = {slot["call_id"] for slot in plan["planned_calls"]}
            if not ledger["attempts"].keys() <= planned:
                raise ValueError("ledger contains attempts outside its plan")
            stop_path = budget / "paid-circuit.json"
            closure = _read(stop_path) if stop_path.exists() else {}
            released = set(closure.get("unstarted_judge_call_ids", [])) if (
                closure.get("schema") == "ura-hosted-budget-close/1"
                and closure.get("category") == "completed_budget_closed") else set()
            for slot in plan["planned_calls"]:
                key = slot["call_id"]
                provider, role = slot["provider"], slot["pool"]
                if not isinstance(provider, str) or role not in {"target", "judge"}:
                    raise ValueError("invalid cost provider or role")
                bound = allowances.get(key, _amount(slot["bound_microusd"]))
                held = 0 if key in released and role == "judge" else bound
                entry = calls.setdefault(key, {"provider": provider, "role": role,
                    "bound": bound, "held": held, "attempts": {}})
                if (entry["provider"], entry["role"]) != (provider, role):
                    raise ValueError("copied call identity has a different provider or role")
                entry["bound"] = max(entry["bound"], bound)
                entry["held"] = max(entry["held"], held)
                for number, attempt in ledger["attempts"].get(key, {}).items():
                    prior = entry["attempts"].get(number)
                    if prior is not None and prior != attempt:
                        raise ValueError("copied physical attempt has conflicting settlements")
                    entry["attempts"][number] = attempt
            sources.append({"label": str(source["label"]), "budget": source["budget"],
                            "spending_policy": spending_policy,
                            "closed": bool(released) or closure.get("category") == "completed_budget_closed"})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(f"{path.name}: {exc}")
    rows = {}
    try:
        for call in calls.values():
            row = rows.setdefault((call["provider"], call["role"]), {
                "provider": call["provider"], "role": call["role"], "http_attempts": 0,
                "settled_attempts": 0, "unknown_attempts": 0, "unsettled_attempts": 0,
                "reported_cost_microusd": 0, "unknown_exposure_microusd": 0,
                "unsettled_exposure_microusd": 0, "unstarted_commitments_microusd": 0})
            if not call["attempts"]:
                row["unstarted_commitments_microusd"] += call["held"]
            for attempt in call["attempts"].values():
                row["http_attempts"] += 1
                state = attempt["state"]
                if state == "settled":
                    row["settled_attempts"] += 1
                    row["reported_cost_microusd"] += _amount(attempt["actual_cost_microusd"])
                elif state in {"unknown", "bounded_unknown", "reserved"}:
                    kind = "unsettled" if state == "reserved" else "unknown"
                    row[kind + "_attempts"] += 1
                    exposure = (_amount(attempt["usage_bound"]["bound_microusd"])
                                if state == "bounded_unknown" else call["bound"])
                    row[kind + "_exposure_microusd"] += exposure
                else:
                    raise ValueError("unknown physical attempt state")
    except (ValueError, KeyError, TypeError) as exc:
        errors.append(str(exc))
    # Inconsistent sources must not produce a plausible but incomplete total.
    return {"registered": bool(paths), "rows": [] if errors else [rows[k] for k in sorted(rows)],
            "sources": sources, "errors": errors}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--register-budget", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    for budget in args.register_budget:
        register_budget(args.results_root, budget)
    result = campaign_costs(args.results_root)
    print(json.dumps(result, sort_keys=True))
    return int(bool(result["errors"]))


if __name__ == "__main__":
    raise SystemExit(main())
