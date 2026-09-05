"""Durable money reservations, not hosted-call or semantic admission.

The controller supplies immutable logical slots and conservative integer USD
bounds. Each SDK attempt needs a fresh reservation. Unknown usage is never free.
"""
from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path

from experiments.retained_response_judge_execute import (
    _exclusive_lock, _read_regular, _write_atomic, _write_new,
)


PLAN_SCHEMA = "ura-hosted-attempt-budget-plan/1"
LEDGER_SCHEMA = "ura-hosted-attempt-budget-ledger/1"
MAX_HAIKU_MICROUSD = 33_000_000
MAX_ATTEMPTS = 4
_MAX_BYTES = 64 * 1024 * 1024


class BudgetError(ValueError):
    """No paid attempt may follow this failed monetary admission."""


def _integer(value: object, label: str, *, zero: bool = False) -> int:
    if type(value) is not int or value < (0 if zero else 1):
        raise BudgetError(f"{label} must be a {'nonnegative' if zero else 'positive'} integer microUSD/count")
    return value


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise BudgetError(f"{label} must be a nonempty identifier")
    return value


def _plan(provider_budgets: Mapping[str, int], calls: Sequence[Mapping], protected: int) -> dict:
    protected = _integer(protected, "protected Haiku allocation")
    if protected > MAX_HAIKU_MICROUSD or not isinstance(provider_budgets, Mapping) or not provider_budgets:
        raise BudgetError("protected Haiku allocation or provider budget inventory is invalid")
    budgets = {}
    for provider, available in provider_budgets.items():
        provider = _name(provider, "provider")
        if ":" in provider:
            raise BudgetError("provider identifier cannot contain a pool separator")
        budgets[provider] = _integer(available, "available provider budget")
    ceilings = {provider: available * 4 // 5 for provider, available in budgets.items()}
    if ceilings.get("anthropic", 0) < protected:
        raise BudgetError("Anthropic 80 percent ceiling cannot protect the Haiku allocation")
    caps = {f"{provider}:target": cap - (protected if provider == "anthropic" else 0)
            for provider, cap in ceilings.items()}
    caps["anthropic:judge"] = protected
    if not isinstance(calls, Sequence) or isinstance(calls, (str, bytes)) or not calls:
        raise BudgetError("planned calls must be a nonempty sequence of immutable logical slots")
    selected, commitments = {}, dict.fromkeys(caps, 0)
    for call in calls:
        if not isinstance(call, Mapping) or set(call) != {"call_id", "provider", "pool", "bound_microusd"}:
            raise BudgetError("planned call fields differ")
        call_id = _name(call["call_id"], "call ID")
        provider, pool = _name(call["provider"], "call provider"), _name(call["pool"], "call pool")
        if call_id in selected:
            raise BudgetError("duplicate planned call ID")
        if (provider not in budgets or pool not in {"target", "judge"}
                or (pool == "judge" and provider != "anthropic")):
            raise BudgetError("planned call provider/pool differs from funded inventory")
        bound = _integer(call["bound_microusd"], "per-attempt bound")
        selected[call_id] = {"call_id": call_id, "provider": provider, "pool": pool, "bound_microusd": bound}
        commitments[f"{provider}:{pool}"] += bound
    if any(commitments[key] > cap for key, cap in caps.items()):
        raise BudgetError("planned first attempts exceed their dedicated pool cap")
    return {"schema": PLAN_SCHEMA, "provider_budgets_microusd": dict(sorted(budgets.items())),
            "provider_ceilings_microusd": dict(sorted(ceilings.items())),
            "protected_haiku_microusd": protected, "pool_caps_microusd": dict(sorted(caps.items())),
            "planned_calls": [selected[key] for key in sorted(selected)]}


def create_budget(root: Path, *, provider_budgets_microusd: Mapping[str, int],
                  planned_calls: Sequence[Mapping],
                  protected_haiku_microusd: int = MAX_HAIKU_MICROUSD) -> dict:
    """Create one dedicated budget directory. No first call is sent or inferred."""
    plan = _plan(provider_budgets_microusd, planned_calls, protected_haiku_microusd)
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or root.exists() or root.is_symlink():
        raise BudgetError("budget needs a fresh canonical absolute directory")
    root.mkdir(mode=0o700)
    with _exclusive_lock(root):
        path = root / "plan.json"
        _write_new(path, plan)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        _write_atomic(root / "ledger.json", {"schema": LEDGER_SCHEMA, "plan_sha256": digest, "attempts": {}})
    return {"path": str(path), "sha256": digest, "bytes": path.stat().st_size}


class AttemptBudget:
    def __init__(self, root: Path, expected_plan_sha256: str):
        self.root = Path(root)
        if (not self.root.is_absolute() or self.root.is_symlink() or self.root.resolve(strict=True) != self.root
                or not self.root.is_dir()):
            raise BudgetError("budget is not one canonical directory")
        if (not isinstance(expected_plan_sha256, str) or len(expected_plan_sha256) != 64
                or any(char not in "0123456789abcdef" for char in expected_plan_sha256)):
            raise BudgetError("budget requires its exact immutable plan SHA256")
        self.expected_plan_sha256 = expected_plan_sha256
        self.snapshot()  # Refuse missing/partial or incompatible retained state.

    def _load(self) -> tuple[dict, dict, dict]:
        plan, descriptor = _read_regular(self.root / "plan.json", label="attempt budget plan", max_bytes=_MAX_BYTES)
        if descriptor["sha256"] != self.expected_plan_sha256 or not isinstance(plan, dict):
            raise BudgetError("attempt budget plan bytes changed")
        expected = _plan(plan.get("provider_budgets_microusd"), plan.get("planned_calls"),
                         plan.get("protected_haiku_microusd"))
        if plan != expected:
            raise BudgetError("attempt budget derived caps or commitments changed")
        ledger, _ = _read_regular(self.root / "ledger.json", label="attempt budget ledger", max_bytes=_MAX_BYTES)
        if (not isinstance(ledger, dict) or set(ledger) != {"schema", "plan_sha256", "attempts"}
                or ledger["schema"] != LEDGER_SCHEMA or ledger["plan_sha256"] != self.expected_plan_sha256
                or not isinstance(ledger["attempts"], dict)):
            raise BudgetError("attempt budget ledger binding differs")
        calls = {call["call_id"]: call for call in plan["planned_calls"]}
        for call_id, attempts in ledger["attempts"].items():
            if (call_id not in calls or not isinstance(attempts, dict) or not attempts
                    or len(attempts) > MAX_ATTEMPTS or set(attempts) != {str(n) for n in range(1, len(attempts) + 1)}):
                raise BudgetError("attempt reservations are not a bounded sequential prefix")
            for number, attempt in attempts.items():
                if (not isinstance(attempt, dict) or set(attempt) != {"state", "actual_cost_microusd"}
                        or attempt["state"] not in {"reserved", "unknown", "settled"}):
                    raise BudgetError("attempt settlement fields differ")
                if attempt["state"] == "settled":
                    _integer(attempt["actual_cost_microusd"], "settled cost", zero=True)
                elif attempt["actual_cost_microusd"] is not None:
                    raise BudgetError("unresolved attempt cannot report a settled cost")
                if attempt["state"] == "reserved" and int(number) != len(attempts):
                    raise BudgetError("an unresolved attempt was automatically reissued")
        totals = self._totals(plan, ledger)
        if any(pool["over_cap_microusd"] for pool in totals["pools"].values()) and not totals["bound_exceeded_attempts"]:
            raise BudgetError("retained reservations exceed their funded pool")
        return plan, ledger, calls

    @staticmethod
    def _totals(plan: dict, ledger: dict) -> dict:
        pools = {key: {"cap_microusd": cap, "unstarted_first_commitments_microusd": 0,
                       "reserved_exposure_microusd": 0, "settled_cost_microusd": 0,
                       "unresolved_attempts": 0, "unknown_usage_attempts": 0, "settled_attempts": 0}
                 for key, cap in plan["pool_caps_microusd"].items()}
        overruns = []
        for call in plan["planned_calls"]:
            pool = pools[f"{call['provider']}:{call['pool']}"]
            attempts = ledger["attempts"].get(call["call_id"], {})
            if not attempts:
                pool["unstarted_first_commitments_microusd"] += call["bound_microusd"]
            for number, attempt in attempts.items():
                if attempt["state"] == "settled":
                    actual = attempt["actual_cost_microusd"]
                    pool["settled_cost_microusd"] += actual
                    pool["settled_attempts"] += 1
                    if actual > call["bound_microusd"]:
                        overruns.append({"call_id": call["call_id"], "attempt_number": int(number),
                                         "bound_microusd": call["bound_microusd"], "actual_cost_microusd": actual})
                else:
                    pool["reserved_exposure_microusd"] += call["bound_microusd"]
                    pool["unknown_usage_attempts" if attempt["state"] == "unknown" else "unresolved_attempts"] += 1
        for pool in pools.values():
            liability = sum(pool[key] for key in ("unstarted_first_commitments_microusd",
                                                  "reserved_exposure_microusd", "settled_cost_microusd"))
            pool.update(liability_microusd=liability,
                        available_retry_margin_microusd=max(0, pool["cap_microusd"] - liability),
                        over_cap_microusd=max(0, liability - pool["cap_microusd"]))
        return {"state": "blocked_known_bound_exceeded" if overruns else "active",
                "pools": pools, "provider_ceilings_microusd": plan["provider_ceilings_microusd"],
                "bound_exceeded_attempts": overruns, "planned_calls": len(plan["planned_calls"])}

    def snapshot(self) -> dict:
        """Return exposure and commitments without changing any retained state."""
        with _exclusive_lock(self.root):
            plan, ledger, _calls = self._load()
            return self._totals(plan, ledger)

    def call(self, call_id: str) -> dict:
        """The callback checks the provider/request allowance against this slot."""
        call_id = _name(call_id, "call ID")
        with _exclusive_lock(self.root):
            _plan_value, _ledger, calls = self._load()
            if call_id not in calls:
                raise BudgetError("call ID is outside the immutable funded plan")
            return copy.deepcopy(calls[call_id])

    def liability(self, call_ids: Sequence[str]) -> int:
        """Read a caller's sub-plan exposure, including its unfired first calls."""
        if not isinstance(call_ids, Sequence) or isinstance(call_ids, (str, bytes)):
            raise BudgetError("liability needs a sequence of funded call IDs")
        selected = [_name(value, "call ID") for value in call_ids]
        if not selected or len(set(selected)) != len(selected):
            raise BudgetError("liability call IDs must be nonempty and unique")
        with _exclusive_lock(self.root):
            plan, ledger, calls = self._load()
            if any(value not in calls for value in selected):
                raise BudgetError("liability call ID is outside the funded plan")
            partial = dict(plan, planned_calls=[calls[value] for value in selected])
            return sum(pool["liability_microusd"] for pool in self._totals(partial, ledger)["pools"].values())

    def reserved_attempt_count(self, call_id: str) -> int:
        """Read actual admitted ordinals, not a Runner's conservative exposure."""
        call_id = _name(call_id, "call ID")
        with _exclusive_lock(self.root):
            _plan_value, ledger, calls = self._load()
            if call_id not in calls:
                raise BudgetError("call ID is outside the immutable funded plan")
            return len(ledger["attempts"].get(call_id, {}))

    def reserve(self, call_id: str, attempt_number: int, *, provider: str) -> dict:
        """Fsync money before one SDK attempt. Repeated callbacks always refuse."""
        call_id, provider = _name(call_id, "call ID"), _name(provider, "provider")
        number = _integer(attempt_number, "physical attempt number")
        with _exclusive_lock(self.root):
            if (self.root / "paid-circuit.json").exists() or (self.root / "paid-circuit.json").is_symlink():
                raise BudgetError("shared paid-provider circuit is open")
            plan, ledger, calls = self._load()
            if call_id not in calls or calls[call_id]["provider"] != provider:
                raise BudgetError("attempt provider or call ID differs from its funded slot")
            current = self._totals(plan, ledger)
            if current["state"] != "active":
                raise BudgetError("known above-bound usage blocks all new spending")
            attempts = ledger["attempts"].get(call_id, {})
            if number > MAX_ATTEMPTS or number != len(attempts) + 1:
                raise BudgetError("physical attempt is duplicated, out of order, or above the four-attempt cap")
            if attempts and attempts[str(number - 1)]["state"] == "reserved":
                raise BudgetError("unresolved previous attempt cannot be automatically reissued")
            call = calls[call_id]
            pool = current["pools"][f"{provider}:{call['pool']}"]
            if number > 1 and pool["available_retry_margin_microusd"] < call["bound_microusd"]:
                raise BudgetError("retry cannot consume other planned first attempts or another pool")
            ledger["attempts"].setdefault(call_id, {})[str(number)] = {"state": "reserved", "actual_cost_microusd": None}
            _write_atomic(self.root / "ledger.json", ledger)
            return {"call_id": call_id, "attempt_number": number, "provider": provider,
                    "pool": call["pool"], "bound_microusd": call["bound_microusd"]}

    def settle(self, call_id: str, attempt_number: int, actual_cost_microusd: int | None) -> dict:
        """Unknown stays fully held; reported overage is retained and stops spend."""
        call_id = _name(call_id, "call ID")
        number = str(_integer(attempt_number, "physical attempt number"))
        if actual_cost_microusd is not None:
            _integer(actual_cost_microusd, "actual attempt cost", zero=True)
        with _exclusive_lock(self.root):
            plan, ledger, _calls = self._load()
            attempt = ledger["attempts"].get(call_id, {}).get(number)
            if attempt is None:
                raise BudgetError("cannot settle an attempt that was never reserved")
            state = "unknown" if actual_cost_microusd is None else "settled"
            changed = attempt != {"state": state, "actual_cost_microusd": actual_cost_microusd}
            if changed and attempt["state"] == "settled":
                raise BudgetError("conflicting settlement cannot rewrite known billed usage")
            if changed:
                attempt.update(state=state, actual_cost_microusd=actual_cost_microusd)
                _write_atomic(self.root / "ledger.json", ledger)
            result = self._totals(plan, ledger)
            if result["state"] != "active":
                raise BudgetError("known above-bound usage was durably retained; all new spending is blocked")
            return result
