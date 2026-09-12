"""Durable hosted-attempt accounting and selectable spending enforcement.

The controller supplies immutable logical slots and conservative integer USD
bounds. Precalculated execution records attempts without maximum-cost holds;
reported spending and provider exhaustion govern continuation. Unknown is not free.
"""
from __future__ import annotations

import copy
import hashlib
import time
from collections.abc import Mapping, Sequence
from contextlib import ExitStack, contextmanager
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path
from ura.validation_cache import ValidationCache

from experiments.retained_response_judge_execute import (
    _exclusive_lock, _read_regular, _write_atomic, _write_new,
)


PLAN_SCHEMA = "ura-hosted-attempt-budget-plan/1"
PER_ATTEMPT_PLAN_SCHEMA = "ura-hosted-attempt-budget-plan/2"
LEDGER_SCHEMA = "ura-hosted-attempt-budget-ledger/1"
ADJUSTED_LEDGER_SCHEMA = "ura-hosted-attempt-budget-ledger/2"
USAGE_BOUNDED_LEDGER_SCHEMA = "ura-hosted-attempt-budget-ledger/3"
MAX_HAIKU_MICROUSD = 33_000_000
MAX_ATTEMPTS = 4
_MAX_BYTES = 64 * 1024 * 1024
_LOCK_WAIT_SECONDS = 30.0
_LOCK_RETRY_SECONDS = 0.05


class BudgetError(ValueError):
    """No paid attempt may follow this failed monetary admission."""


class BudgetCapacityUnavailable(BudgetError):
    """Valid request waiting for capacity, not a provider or model failure."""

    def __init__(self, *, unresolved_attempts: int,
                 message: str = 'attempt maximum exceeds available provider pool capacity'):
        super().__init__(message)
        self.unresolved_attempts = unresolved_attempts


@contextmanager
def _budget_lock(root: Path):
    """Serialize brief shared-ledger transactions, not whole model executions."""
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    with ExitStack() as stack:
        while True:
            try:
                stack.enter_context(_exclusive_lock(root))
            except RuntimeError as exc:
                if not isinstance(exc.__cause__, BlockingIOError):
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise BudgetError("shared budget transaction lock wait expired") from exc
                time.sleep(min(_LOCK_RETRY_SECONDS, remaining))
            else:
                break
        # Body failures must propagate once, never replay a money transaction.
        yield


def _integer(value: object, label: str, *, zero: bool = False) -> int:
    if type(value) is not int or value < (0 if zero else 1):
        raise BudgetError(f"{label} must be a {'nonnegative' if zero else 'positive'} integer microUSD/count")
    return value


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\0" in value:
        raise BudgetError(f"{label} must be a nonempty identifier")
    return value


def _reported_usage_bound(value: object) -> int:
    """A reported-token upper bound is not an exact cache-discounted bill."""
    fields = {"input_tokens", "output_tokens", "input_unit_price", "output_unit_price",
              "response_sha256", "pricing_sha256", "bound_microusd"}
    if not isinstance(value, dict) or set(value) != fields:
        raise BudgetError("reported usage bound fields differ")
    for key in ("response_sha256", "pricing_sha256"):
        digest = value[key]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise BudgetError("reported usage bound needs response and pricing identities")
    total = Decimal(0)
    for kind in ("input", "output"):
        count = _integer(value[kind + "_tokens"], "reported token count", zero=True)
        rate = value[kind + "_unit_price"]
        if not isinstance(rate, str):
            raise BudgetError("reported usage price must be a finite decimal string")
        try:
            rate = Decimal(rate)
        except InvalidOperation as exc:
            raise BudgetError("reported usage price must be a finite decimal string") from exc
        if not rate.is_finite() or rate < 0:
            raise BudgetError("reported usage price must be finite and nonnegative")
        total += count * rate
    bound = _integer(value["bound_microusd"], "reported usage bound", zero=True)
    if bound != int(total.to_integral_value(rounding=ROUND_CEILING)):
        raise BudgetError("reported usage bound differs from its token and price evidence")
    return bound


def _plan(provider_budgets: Mapping[str, int], calls: Sequence[Mapping], protected: int,
          reservation_policy: str = "first_attempts_upfront") -> dict:
    if not isinstance(reservation_policy, str) or reservation_policy not in {"first_attempts_upfront", "per_attempt"}:
        raise BudgetError("unknown paid reservation policy")
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
    if reservation_policy == "first_attempts_upfront" and any(commitments[key] > cap for key, cap in caps.items()):
        raise BudgetError("planned first attempts exceed their dedicated pool cap")
    return {"schema": PLAN_SCHEMA if reservation_policy == "first_attempts_upfront" else PER_ATTEMPT_PLAN_SCHEMA,
            **({"reservation_policy": reservation_policy} if reservation_policy == "per_attempt" else {}),
            "provider_budgets_microusd": dict(sorted(budgets.items())),
            "provider_ceilings_microusd": dict(sorted(ceilings.items())),
            "protected_haiku_microusd": protected, "pool_caps_microusd": dict(sorted(caps.items())),
            "planned_calls": [selected[key] for key in sorted(selected)]}


def create_budget(root: Path, *, provider_budgets_microusd: Mapping[str, int],
                  planned_calls: Sequence[Mapping],
                  protected_haiku_microusd: int = MAX_HAIKU_MICROUSD,
                  reservation_policy: str = "first_attempts_upfront") -> dict:
    """Create one dedicated budget directory. No first call is sent or inferred."""
    plan = _plan(provider_budgets_microusd, planned_calls, protected_haiku_microusd, reservation_policy)
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or root.exists() or root.is_symlink():
        raise BudgetError("budget needs a fresh canonical absolute directory")
    root.mkdir(mode=0o700)
    with _budget_lock(root):
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
        self._immutable_plan_cache = ValidationCache(entries=1, copy_results=False)
        self.snapshot()  # Refuse missing/partial or incompatible retained state.

    def __getstate__(self):
        # The cache owns a thread lock. Spawned workers reconstruct it locally.
        return {key: value for key, value in vars(self).items() if key != '_immutable_plan_cache'}

    def __setstate__(self, state):
        vars(self).update(state)
        self._immutable_plan_cache = ValidationCache(entries=1, copy_results=False)
        self.snapshot()

    def _load_plan(self) -> tuple[dict, dict]:
        return self._immutable_plan_cache.get(self.expected_plan_sha256, self._read_plan,
                                             paths=(self.root / "plan.json",))

    def _read_plan(self) -> tuple[dict, dict]:
        plan, descriptor = _read_regular(self.root / "plan.json", label="attempt budget plan", max_bytes=_MAX_BYTES)
        if descriptor["sha256"] != self.expected_plan_sha256 or not isinstance(plan, dict):
            raise BudgetError("attempt budget plan bytes changed")
        policy = ("first_attempts_upfront" if plan.get("schema") == PLAN_SCHEMA
                  else plan.get("reservation_policy"))
        expected = _plan(plan.get("provider_budgets_microusd"), plan.get("planned_calls"),
                         plan.get("protected_haiku_microusd"), policy)
        if plan != expected:
            raise BudgetError("attempt budget derived caps or commitments changed")
        return plan, {call["call_id"]: call for call in plan["planned_calls"]}

    def _load(self) -> tuple[dict, dict, dict]:
        plan, calls = self._load_plan()
        ledger, _ = _read_regular(self.root / "ledger.json", label="attempt budget ledger", max_bytes=_MAX_BYTES)
        usage_bounded = isinstance(ledger, dict) and ledger.get("schema") == USAGE_BOUNDED_LEDGER_SCHEMA
        adjusted = isinstance(ledger, dict) and ledger.get("schema") in {ADJUSTED_LEDGER_SCHEMA, USAGE_BOUNDED_LEDGER_SCHEMA}
        fields = {"schema", "plan_sha256", "attempts"} | ({"allowance_adjustments"} if adjusted else set())
        if (not isinstance(ledger, dict) or set(ledger) != fields
                or ledger["schema"] not in {LEDGER_SCHEMA, ADJUSTED_LEDGER_SCHEMA, USAGE_BOUNDED_LEDGER_SCHEMA}
                or ledger["plan_sha256"] != self.expected_plan_sha256
                or not isinstance(ledger["attempts"], dict)):
            raise BudgetError("attempt budget ledger binding differs")
        if adjusted:
            changes = ledger["allowance_adjustments"]
            if not isinstance(changes, list) or (not changes and not usage_bounded):
                raise BudgetError("adjusted ledger needs its allocation history")
            effective = {key: call["bound_microusd"] for key, call in calls.items()}
            for change in changes:
                if (not isinstance(change, dict)
                        or set(change) != {"call_id", "previous_bound_microusd", "bound_microusd", "reason"}
                        or not isinstance(change["call_id"], str) or change["call_id"] not in calls):
                    raise BudgetError("allowance adjustment fields or funded call differ")
                key = change["call_id"]
                previous = _integer(change["previous_bound_microusd"], "previous allowance")
                bound = _integer(change["bound_microusd"], "adjusted allowance")
                _name(change["reason"], "allowance adjustment reason")
                if previous != effective[key] or bound <= previous:
                    raise BudgetError("allowance history must preserve a strictly increasing bound")
                effective[key] = bound
        for call_id, attempts in ledger["attempts"].items():
            if (call_id not in calls or not isinstance(attempts, dict) or not attempts
                    or len(attempts) > MAX_ATTEMPTS or set(attempts) != {str(n) for n in range(1, len(attempts) + 1)}):
                raise BudgetError("attempt reservations are not a bounded sequential prefix")
            for number, attempt in attempts.items():
                bounded = isinstance(attempt, dict) and attempt.get("state") == "bounded_unknown"
                attempt_fields = {"state", "actual_cost_microusd"} | ({"usage_bound"} if bounded else set())
                if (not isinstance(attempt, dict) or set(attempt) != attempt_fields
                        or attempt["state"] not in {"reserved", "unknown", "settled", "bounded_unknown"}
                        or (bounded and not usage_bounded)):
                    raise BudgetError("attempt settlement fields differ")
                if attempt["state"] == "settled":
                    _integer(attempt["actual_cost_microusd"], "settled cost", zero=True)
                elif attempt["actual_cost_microusd"] is not None:
                    raise BudgetError("unresolved attempt cannot report a settled cost")
                if bounded and _reported_usage_bound(attempt["usage_bound"]) > effective[call_id]:
                    raise BudgetError("reported usage bound exceeds its funded attempt allowance")
                if attempt["state"] == "reserved" and int(number) != len(attempts):
                    raise BudgetError("an unresolved attempt was automatically reissued")
        totals = self._totals(plan, ledger)
        if (totals.get("spending_policy") != "precalculated"
                and any(pool["over_cap_microusd"] for pool in totals["pools"].values())
                and not totals["bound_exceeded_attempts"]):
            raise BudgetError("retained reservations exceed their funded pool")
        return plan, ledger, calls

    def spending_policy(self) -> str:
        path = self.root / 'spending-policy.json'
        if not path.exists():
            return 'reserved_maximum'
        value, _ = _read_regular(path, label='spending policy', max_bytes=4096)
        if value != {'budget_plan_sha256': self.expected_plan_sha256, 'mode': 'precalculated'}:
            raise BudgetError('spending policy does not match its campaign plan')
        return value['mode']

    def use_precalculated_spending(self) -> dict:
        """Keep the plan/ledger; replace maximum holds with reported-spend stops.

        Unknown amounts remain unknown, and in-flight calls may finish after
        a cap is reached. This mode does not guarantee a worst-case spend cap.
        """
        with _budget_lock(self.root):
            self._load()
            value = {'budget_plan_sha256': self.expected_plan_sha256, 'mode': 'precalculated'}
            if self.spending_policy() != 'precalculated':
                _write_new(self.root / 'spending-policy.json', value)
            return value

    def use_campaign_spending(self, document: dict) -> dict:
        """Use one precomputed campaign ceiling, preserving all old allocations."""
        from experiments.hosted_campaign_spending import validate_scope, campaign_totals
        with _budget_lock(self.root):
            plan, ledger, _ = self._load()
            validate_scope(document, self.root, self.expected_plan_sha256, plan['pool_caps_microusd'])
            if self.spending_policy() != 'precalculated':
                raise BudgetError('campaign spending requires precalculated mode')
            result = campaign_totals(self, plan, ledger, document=document)
            path = self.root / 'campaign-spending.json'
            if path.exists():
                value, _ = _read_regular(path, label='campaign spending', max_bytes=_MAX_BYTES)
                if value != document:
                    before = {(row['root'], row['plan_sha256']) for row in value['budgets']}
                    after = {(row['root'], row['plan_sha256']) for row in document['budgets']}
                    if (value['pool_caps_microusd'] != document['pool_caps_microusd']
                            or not before < after):
                        raise BudgetError('campaign extension must retain all ledgers and unchanged ceilings')
                    history = self.root / f'campaign-spending-before-extension-{len(before)}.json'
                    if history.exists():
                        retained, _ = _read_regular(history, label='campaign spending history', max_bytes=_MAX_BYTES)
                        if retained != value:
                            raise BudgetError('campaign spending extension history differs')
                    else:
                        _write_new(history, value)
                    _write_atomic(path, document)
            else:
                _write_new(path, document)
            return result

    def _totals(self, plan: dict, ledger: dict) -> dict:
        precalculated = self.spending_policy() == 'precalculated'
        pools = {key: {"cap_microusd": cap, "unstarted_first_commitments_microusd": 0,
                       "reserved_exposure_microusd": 0, "settled_cost_microusd": 0,
                       "unresolved_attempts": 0, "unknown_usage_attempts": 0, "settled_attempts": 0,
                       "bounded_usage_attempts": 0, "reported_usage_upper_bound_microusd": 0}
                 for key, cap in plan["pool_caps_microusd"].items()}
        overruns, unfunded = [], []
        allowances = {change["call_id"]: change["bound_microusd"]
                      for change in ledger.get("allowance_adjustments", [])}
        for call in plan["planned_calls"]:
            bound = allowances.get(call["call_id"], call["bound_microusd"])
            pool = pools[f"{call['provider']}:{call['pool']}"]
            attempts = ledger["attempts"].get(call["call_id"], {})
            if not attempts and plan.get("reservation_policy") != "per_attempt":
                pool["unstarted_first_commitments_microusd"] += bound
            for number, attempt in attempts.items():
                if attempt["state"] == "settled":
                    actual = attempt["actual_cost_microusd"]
                    pool["settled_cost_microusd"] += actual
                    pool["settled_attempts"] += 1
                    if actual > call["bound_microusd"]:
                        overruns.append({"call_id": call["call_id"], "attempt_number": int(number),
                                         "bound_microusd": call["bound_microusd"], "actual_cost_microusd": actual})
                    if actual > bound:
                        unfunded.append({"call_id": call["call_id"], "attempt_number": int(number),
                                         "bound_microusd": bound, "actual_cost_microusd": actual})
                else:
                    bounded = attempt["state"] == "bounded_unknown"
                    if bounded:
                        pool['reported_usage_upper_bound_microusd'] += _reported_usage_bound(attempt['usage_bound'])
                    pool["reserved_exposure_microusd"] += _reported_usage_bound(attempt["usage_bound"]) if bounded else bound
                    pool["bounded_usage_attempts"] += int(bounded)
                    pool["unknown_usage_attempts" if attempt["state"] in {"unknown", "bounded_unknown"} else "unresolved_attempts"] += 1
        for pool in pools.values():
            liability = sum(pool[key] for key in ("unstarted_first_commitments_microusd",
                                                  "reserved_exposure_microusd", "settled_cost_microusd"))
            pool.update(liability_microusd=liability,
                        available_retry_margin_microusd=max(0, pool["cap_microusd"] - liability),
                        over_cap_microusd=max(0, liability - pool["cap_microusd"]))
            if precalculated:
                tracked = pool['settled_cost_microusd'] + pool['reported_usage_upper_bound_microusd']
                pool.update(tracked_spend_microusd=tracked,
                            available_tracked_spend_microusd=max(0, pool['cap_microusd'] - tracked),
                            tracked_spend_over_cap_microusd=max(0, tracked - pool['cap_microusd']),
                            maximum_exposure_is_reserved=False)
        over_cap = any(pool["over_cap_microusd"] for pool in pools.values())
        return {"state": "blocked_known_bound_exceeded" if not precalculated and (unfunded or over_cap) else "active",
                **({'spending_policy': 'precalculated'} if precalculated else {}),
                "pools": pools, "provider_ceilings_microusd": plan["provider_ceilings_microusd"],
                "bound_exceeded_attempts": overruns, "planned_calls": len(plan["planned_calls"]),
                "unfunded_bound_exceeded_attempts": unfunded,
                "allowance_adjustments": copy.deepcopy(ledger.get("allowance_adjustments", []))}

    def increase_allowances(self, bounds: Mapping[str, int], *, reason: str,
                            expected_ledger_sha256: str) -> dict:
        """Explicitly allocate existing pool margin; never revise a request or bill.

        This is an operator transaction, not automatic forgiveness on settlement.
        Earlier versions refuse the new ledger rather than overlook allocations.
        """
        reason = _name(reason, "allowance adjustment reason")
        if not isinstance(bounds, Mapping) or not bounds:
            raise BudgetError("allowance adjustment needs funded call bounds")
        with _budget_lock(self.root):
            plan, ledger, calls = self._load()
            if hashlib.sha256((self.root / "ledger.json").read_bytes()).hexdigest() != expected_ledger_sha256:
                raise BudgetError("allowance review paid history is stale")
            changes = ledger.setdefault("allowance_adjustments", [])
            effective = {key: call["bound_microusd"] for key, call in calls.items()}
            effective.update({change["call_id"]: change["bound_microusd"] for change in changes})
            for key, value in bounds.items():
                key = _name(key, "allowance call ID")
                bound = _integer(value, "adjusted allowance")
                if key not in calls or bound <= effective[key]:
                    raise BudgetError("allowance must increase an existing funded call")
                changes.append({"call_id": key, "previous_bound_microusd": effective[key],
                                "bound_microusd": bound, "reason": reason})
            result = self._totals(plan, ledger)
            if (self.spending_policy() != 'precalculated'
                    and any(pool["over_cap_microusd"] for pool in result["pools"].values())):
                raise BudgetError("allowance adjustment exceeds its existing dedicated pool cap")
            if ledger["schema"] != USAGE_BOUNDED_LEDGER_SCHEMA:
                ledger["schema"] = ADJUSTED_LEDGER_SCHEMA
            _write_atomic(self.root / "ledger.json", ledger)
            return result

    def attempt_bound(self, call_id: str) -> int:
        """Effective funded exposure, separate from the immutable request estimate."""
        call_id = _name(call_id, "call ID")
        with _budget_lock(self.root):
            _plan_value, ledger, calls = self._load()
            if call_id not in calls:
                raise BudgetError("call ID is outside the immutable funded plan")
            allowances = {change["call_id"]: change["bound_microusd"]
                          for change in ledger.get("allowance_adjustments", [])}
            return allowances.get(call_id, calls[call_id]["bound_microusd"])

    def snapshot(self) -> dict:
        """Return exposure and commitments without changing any retained state."""
        with _budget_lock(self.root):
            plan, ledger, calls = self._load()
            result = self._closed_snapshot(plan, ledger, calls)
            if self.spending_policy() == 'precalculated':
                from experiments.hosted_campaign_spending import campaign_totals
                campaign = campaign_totals(self, plan, ledger)
                if campaign is not None:
                    result['campaign_spending'] = campaign
            return result

    def continuation_liability(self, completed_call_ids: Sequence[str]) -> dict:
        """Reserve every remaining physical attempt for an unfinished cohort.

        The caller must establish completion from retained outputs, not merely
        a settlement. It must not replay those completed calls. This read-only
        bound permits independent work to be funded without treating the older
        cohort's unused transport-retry allowance as free money. Recheck it
        before concurrent paid attempts; an allowance change can raise it.
        """
        with _budget_lock(self.root):
            return self._continuation_liability_locked(completed_call_ids)

    @contextmanager
    def hold_continuation_ceiling(self, completed_call_ids: Sequence[str], ceilings: Mapping[str, int]):
        """Hold a prior cohort's ledger stable through a new money reservation.

        Only the brief child-budget reservation belongs inside this context,
        never its network call. Lock older budgets before newer budgets.
        """
        with _budget_lock(self.root):
            forecast = self._continuation_liability_locked(completed_call_ids)
            current = forecast["continuation_liability_microusd"]
            if (not isinstance(ceilings, Mapping) or set(ceilings) != set(current)
                    or any(type(value) is not int or value < 0 for value in ceilings.values())
                    or any(current[key] > ceilings[key] for key in current)):
                raise BudgetError("preceding cohort exceeds its reserved continuation ceiling")
            yield forecast

    def _continuation_liability_locked(self, completed_call_ids: Sequence[str]) -> dict:
        if isinstance(completed_call_ids, (str, bytes)) or not isinstance(completed_call_ids, Sequence):
            raise BudgetError("completed calls must be an explicit identity sequence")
        finished = {_name(key, "completed call ID") for key in completed_call_ids}
        if len(finished) != len(completed_call_ids):
            raise BudgetError("completed call identities are duplicated")
        plan, ledger, calls = self._load()
        if not finished <= calls.keys():
            raise BudgetError("completed call is outside the funded inventory")
        for key in finished:
            attempts = ledger["attempts"].get(key, {})
            if not attempts or any(row["state"] == "reserved" for row in attempts.values()):
                raise BudgetError("unissued or unsettled call cannot be declared complete")
        snapshot = self._closed_snapshot(plan, ledger, calls)
        if snapshot["state"] not in {"active", "closed"}:
            raise BudgetError("above-bound usage prevents a continuation allocation")
        extra = dict.fromkeys(snapshot["pools"], 0)
        allowances = {row["call_id"]: row["bound_microusd"]
                      for row in ledger.get("allowance_adjustments", [])}
        if snapshot["state"] != "closed":
            for key, call in calls.items():
                if key in finished:
                    continue
                attempts = ledger["attempts"].get(key, {})
                # Snapshot liability already holds each recorded attempt
                # and the first attempt of a completely unissued call.
                first_held = not attempts and plan.get("reservation_policy") != "per_attempt"
                remaining = MAX_ATTEMPTS - len(attempts) - int(first_held)
                extra[f"{call['provider']}:{call['pool']}"] += (
                    remaining * allowances.get(key, call["bound_microusd"]))
        ceilings = {key: min(pool["cap_microusd"], pool["liability_microusd"] + extra[key])
                    for key, pool in snapshot["pools"].items()}
        return {"budget_plan_sha256": self.expected_plan_sha256,
                "completed_call_ids": sorted(finished), "snapshot": snapshot,
                "extra_transport_reserve_microusd": extra,
                "continuation_liability_microusd": ceilings}

    def _closed_snapshot(self, plan: dict, ledger: dict, calls: dict) -> dict:
        totals = self._totals(plan, ledger)
        marker = self.root / "paid-circuit.json"
        if not marker.exists() and not marker.is_symlink():
            return totals
        closure, _ = _read_regular(marker, label="paid dispatch stop", max_bytes=_MAX_BYTES)
        if not isinstance(closure, dict) or closure.get("category") != "completed_budget_closed":
            return totals
        unstarted = sorted(key for key in calls if key not in ledger["attempts"])
        if (set(closure) != {"schema", "category", "budget_plan_sha256", "reason", "unstarted_judge_call_ids"}
                or closure["schema"] != "ura-hosted-budget-close/1"
                or closure["budget_plan_sha256"] != self.expected_plan_sha256
                or closure["unstarted_judge_call_ids"] != unstarted
                or any(calls[key]["pool"] != "judge" for key in unstarted)
                or any(pool["unresolved_attempts"] for pool in totals["pools"].values())):
            raise BudgetError("completed budget closure differs from retained attempts")
        _name(closure["reason"], "budget closure reason")
        for pool in totals["pools"].values():
            released = pool["unstarted_first_commitments_microusd"]
            pool["released_unstarted_commitments_microusd"] = released
            pool["unstarted_first_commitments_microusd"] = 0
            pool["liability_microusd"] -= released
            pool["available_retry_margin_microusd"] = max(0, pool["cap_microusd"] - pool["liability_microusd"])
        if totals["state"] == "active":
            totals["state"] = "closed"
        totals["closure"] = closure
        return totals

    def close(self, *, reason: str) -> dict:
        """Retire a completed cohort, releasing only never-issued judge slots.

        The caller must finish the intended judging population first. Target
        attempts and outstanding charges remain untouched. The existing stop
        filename also prevents older executors from spending this budget again.
        """
        reason = _name(reason, "budget closure reason")
        with _budget_lock(self.root):
            plan, ledger, calls = self._load()
            totals = self._closed_snapshot(plan, ledger, calls)
            if totals["state"] == "closed":
                return totals
            marker = self.root / "paid-circuit.json"
            if marker.exists() or marker.is_symlink():
                raise BudgetError("an existing paid stop must be resolved before budget closure")
            if totals["state"] != "active" or any(pool["unresolved_attempts"] for pool in totals["pools"].values()):
                raise BudgetError("cannot close in-flight or over-budget attempts")
            unstarted = sorted(key for key in calls if key not in ledger["attempts"])
            if any(calls[key]["pool"] != "judge" for key in unstarted):
                raise BudgetError("cannot close a cohort with unstarted target inputs")
            _write_new(marker, {"schema": "ura-hosted-budget-close/1", "category": "completed_budget_closed",
                "budget_plan_sha256": self.expected_plan_sha256, "reason": reason,
                "unstarted_judge_call_ids": unstarted})
            return self._closed_snapshot(plan, ledger, calls)

    def call(self, call_id: str) -> dict:
        """The callback checks the provider/request allowance against this slot."""
        call_id = _name(call_id, "call ID")
        with _budget_lock(self.root):
            _plan_value, calls = self._load_plan()
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
        with _budget_lock(self.root):
            plan, ledger, calls = self._load()
            if any(value not in calls for value in selected):
                raise BudgetError("liability call ID is outside the funded plan")
            partial = dict(plan, planned_calls=[calls[value] for value in selected])
            return sum(pool["liability_microusd"] for pool in self._totals(partial, ledger)["pools"].values())

    def reserved_attempt_count(self, call_id: str) -> int:
        """Read actual admitted ordinals, not a Runner's conservative exposure."""
        call_id = _name(call_id, "call ID")
        with _budget_lock(self.root):
            _plan_value, ledger, calls = self._load()
            if call_id not in calls:
                raise BudgetError("call ID is outside the immutable funded plan")
            return len(ledger["attempts"].get(call_id, {}))

    def _provider_stop_path(self, provider: str) -> Path:
        return self.root / ("provider-funding-stop-" + hashlib.sha256(provider.encode()).hexdigest()[:24] + ".json")

    def stop_provider_funding(self, provider: str, call_id: str) -> None:
        """Stop one exhausted billing account without releasing any reservation."""
        with _budget_lock(self.root):
            _plan_value, ledger, calls = self._load()
            if (call_id not in calls or calls[call_id]["provider"] != provider
                    or not ledger["attempts"].get(call_id)):
                raise BudgetError("provider funding stop needs its actual admitted attempt")
            path = self._provider_stop_path(provider)
            if not path.exists() and not path.is_symlink():
                _write_new(path, {"schema": "ura-hosted-provider-funding-stop/1",
                    "provider": provider, "call_id": call_id, "category": "provider_funding_unavailable",
                    "budget_plan_sha256": self.expected_plan_sha256})

    def provider_funding_stops(self) -> list[dict]:
        """Read provider stops for controller scheduling and status reporting."""
        with _budget_lock(self.root):
            plan, _ledger, calls = self._load()
            stopped = []
            for provider in plan["provider_budgets_microusd"]:
                path = self._provider_stop_path(provider)
                if path.exists() or path.is_symlink():
                    value, _ = _read_regular(path, label="provider funding stop", max_bytes=8192)
                    if (value.get("schema") != "ura-hosted-provider-funding-stop/1"
                            or value.get("provider") != provider
                            or value.get("budget_plan_sha256") != self.expected_plan_sha256
                            or value.get("category") != "provider_funding_unavailable"
                            or value.get("call_id") not in calls
                            or calls[value["call_id"]]["provider"] != provider):
                        raise BudgetError("provider funding stop binding differs")
                    stopped.append(value)
            return stopped

    def reserve(self, call_id: str, attempt_number: int, *, provider: str) -> dict:
        """Record one SDK attempt, enforcing the selected spending policy."""
        call_id, provider = _name(call_id, "call ID"), _name(provider, "provider")
        number = _integer(attempt_number, "physical attempt number")
        with _budget_lock(self.root):
            if (self.root / "paid-circuit.json").exists() or (self.root / "paid-circuit.json").is_symlink():
                raise BudgetError("shared paid-provider circuit is open")
            plan, ledger, calls = self._load()
            if call_id not in calls or calls[call_id]["provider"] != provider:
                raise BudgetError("attempt provider or call ID differs from its funded slot")
            required = {provider}
            precalculated = self.spending_policy() == 'precalculated'
            if (not precalculated and calls[call_id]["pool"] == "target"
                    and any(call["pool"] == "judge" for call in calls.values())):
                required.add("anthropic")
            if any(self._provider_stop_path(name).exists() or self._provider_stop_path(name).is_symlink()
                   for name in required):
                raise BudgetError("target or required judge provider funding is unavailable")
            current = self._totals(plan, ledger)
            if current["state"] != "active":
                raise BudgetError("known above-bound usage blocks all new spending")
            attempts = ledger["attempts"].get(call_id, {})
            if number > MAX_ATTEMPTS or number != len(attempts) + 1:
                raise BudgetError("physical attempt is duplicated, out of order, or above the four-attempt cap")
            if attempts and attempts[str(number - 1)]["state"] == "reserved":
                raise BudgetError("unresolved previous attempt cannot be automatically reissued")
            call = calls[call_id]
            bound = next((change["bound_microusd"] for change in reversed(ledger.get("allowance_adjustments", []))
                          if change["call_id"] == call_id), call["bound_microusd"])
            pool = current["pools"][f"{provider}:{call['pool']}"]
            if precalculated:
                from experiments.hosted_campaign_spending import campaign_totals
                campaign = campaign_totals(self, plan, ledger)
                if campaign is not None:
                    pool = campaign['pools'][f"{provider}:{call['pool']}"]
            if precalculated and pool['tracked_spend_microusd'] >= pool['cap_microusd']:
                raise BudgetCapacityUnavailable(unresolved_attempts=0,
                    message='reported spending reached the approved provider pool limit')
            if (not precalculated and (number > 1 or plan.get("reservation_policy") == "per_attempt")
                    and pool["available_retry_margin_microusd"] < bound):
                if plan.get("reservation_policy") == "per_attempt":
                    raise BudgetCapacityUnavailable(unresolved_attempts=pool['unresolved_attempts'])
                raise BudgetError("retry cannot consume other planned first attempts or another pool")
            ledger["attempts"].setdefault(call_id, {})[str(number)] = {"state": "reserved", "actual_cost_microusd": None}
            _write_atomic(self.root / "ledger.json", ledger)
            return {"call_id": call_id, "attempt_number": number, "provider": provider,
                    "pool": call["pool"], "bound_microusd": bound}

    def settle(self, call_id: str, attempt_number: int, actual_cost_microusd: int | None) -> dict:
        """Unknown stays fully held; reported overage is retained and stops spend."""
        call_id = _name(call_id, "call ID")
        number = str(_integer(attempt_number, "physical attempt number"))
        if actual_cost_microusd is not None:
            _integer(actual_cost_microusd, "actual attempt cost", zero=True)
        with _budget_lock(self.root):
            plan, ledger, _calls = self._load()
            attempt = ledger["attempts"].get(call_id, {}).get(number)
            if attempt is None:
                raise BudgetError("cannot settle an attempt that was never reserved")
            if attempt["state"] == "bounded_unknown" and actual_cost_microusd is None:
                return self._totals(plan, ledger)
            state = "unknown" if actual_cost_microusd is None else "settled"
            changed = attempt != {"state": state, "actual_cost_microusd": actual_cost_microusd}
            if changed and attempt["state"] == "settled":
                raise BudgetError("conflicting settlement cannot rewrite known billed usage")
            if changed:
                attempt.pop("usage_bound", None)
                attempt.update(state=state, actual_cost_microusd=actual_cost_microusd)
                _write_atomic(self.root / "ledger.json", ledger)
            result = self._totals(plan, ledger)
            if result["state"] != "active":
                raise BudgetError("known above-bound usage was durably retained; all new spending is blocked")
            return result

    def bound_reported_usage(self, call_id: str, attempt_number: int, evidence: dict) -> dict:
        """Refine an unknown bill using complete token totals and maximum tariffs.

        The caller validates the durable response against its funded request.
        Missing token usage, network errors and unstarted calls remain fully held.
        """
        call_id = _name(call_id, "call ID")
        number = str(_integer(attempt_number, "physical attempt number"))
        amount = _reported_usage_bound(evidence)
        with _budget_lock(self.root):
            plan, ledger, calls = self._load()
            attempt = ledger["attempts"].get(call_id, {}).get(number)
            if attempt is None or attempt["state"] not in {"unknown", "bounded_unknown"}:
                raise BudgetError("reported usage needs a completed unknown-cost attempt")
            allowance = next((change["bound_microusd"] for change in reversed(ledger.get("allowance_adjustments", []))
                              if change["call_id"] == call_id), calls[call_id]["bound_microusd"])
            if amount > allowance:
                if self.spending_policy() != 'precalculated':
                    raise BudgetError("reported usage bound exceeds its funded attempt allowance")
                # This policy limits cumulative reported spending, not each
                # forecast. Preserve its correction in the existing history.
                ledger.setdefault("allowance_adjustments", []).append({
                    "call_id": call_id, "previous_bound_microusd": allowance,
                    "bound_microusd": amount,
                    "reason": "Complete reported usage exceeds the pre-call forecast; campaign ceilings unchanged",
                })
            if attempt["state"] == "bounded_unknown":
                if attempt["usage_bound"] != evidence:
                    raise BudgetError("conflicting reported usage cannot rewrite the retained bound")
                return self._totals(plan, ledger)
            attempt.update(state="bounded_unknown", usage_bound=copy.deepcopy(evidence))
            ledger["schema"] = USAGE_BOUNDED_LEDGER_SCHEMA
            ledger.setdefault("allowance_adjustments", [])
            _write_atomic(self.root / "ledger.json", ledger)
            return self._totals(plan, ledger)


def main(argv=None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--budget-root', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--spending-policy', choices=('precalculated',))
    parser.add_argument('--campaign-spending', type=Path,
                        help='One precomputed campaign ceiling and all contributing budget ledgers')
    args = parser.parse_args(argv)
    money = AttemptBudget(args.budget_root, args.plan_sha256)
    if args.spending_policy:
        money.use_precalculated_spending()
    if args.campaign_spending:
        money.use_campaign_spending(json.loads(args.campaign_spending.read_text()))
    print(json.dumps(money.snapshot(), sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
