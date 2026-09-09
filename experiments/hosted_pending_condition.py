"""Admit a new output setting for unstarted hosted assignments only.

The predecessor selection, generated answers and paid ledger remain immutable.
This condition runs the exact unstarted complement as a separate result stratum.
"""
from __future__ import annotations

from pathlib import Path

from experiments import hosted_campaign_budget as projection
from experiments import hosted_retained_execute as retained
from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_request_tokens import validate_receipt
from ura.adapters.replay import ReplayAttacker, retained_dialog

SCHEMA = "ura-hosted-pending-condition/1"
CONTINUATION_SCHEMA = "ura-hosted-pending-condition/2"


def _portable(descriptor):
    return {"file": Path(descriptor["path"]).name,
            **{key: descriptor[key] for key in ("sha256", "bytes")}}


def validated_jobs(program: dict, budget: AttemptBudget, *, local_context=None):
    """Revalidate old admission, closed old spending and the exact unpaid complement."""
    from experiments import run_matrix

    if (program.get("schema") not in {SCHEMA, CONTINUATION_SCHEMA}
        or program.get("budget_plan_sha256") != budget.expected_plan_sha256
        or program.get("token_count_policy") != retained.TOKEN_COUNT_POLICY
        or program.get("input_budget_policy") != retained.COUNTED_INPUT_POLICY):
        raise ValueError("pending condition lacks its exact funded execution binding")
    predecessor = program.get("predecessor", {})
    if set(predecessor) != {"program", "budget_plan", "budget_ledger"}:
        raise ValueError("pending condition requires its complete predecessor evidence")
    old, _ = retained._bound(predecessor["program"])
    if old.get("schema") != retained.DISTINCT_INPUT_SCHEMA:
        raise ValueError("pending configuration requires an admitted distinct-input predecessor")
    old_plan, _ = retained._bound(predecessor["budget_plan"])
    old_ledger, _ = retained._bound(predecessor["budget_ledger"])
    old_root = Path(predecessor["budget_plan"]["path"]).parent
    if Path(predecessor["budget_ledger"]["path"]) != old_root / "ledger.json":
        raise ValueError("pending predecessor ledger is outside its budget")
    old_budget = AttemptBudget(old_root, predecessor["budget_plan"]["sha256"])
    if old_ledger["plan_sha256"] != old_budget.expected_plan_sha256:
        raise ValueError("pending predecessor paid history changed")
    marker, _ = retained._read_regular(old_root / "paid-circuit.json", label="closed predecessor budget", max_bytes=1024 * 1024)
    if (marker.get("schema") != "ura-hosted-budget-superseded/1"
        or marker.get("successor", {}).get("sha256") != budget.expected_plan_sha256):
        raise ValueError("predecessor spending is not closed to this exact successor")
    old_admissions = retained._validated_jobs(old, old_budget, local_context=local_context)
    new_plan, _ = retained._read_regular(budget.root / "plan.json", label="pending budget plan", max_bytes=64 * 1024 * 1024)
    new_ledger, _ = retained._read_regular(budget.root / "ledger.json", label="pending paid history", max_bytes=64 * 1024 * 1024)
    old_slots = {r["call_id"]: r for r in old_plan["planned_calls"]}
    new_slots = {r["call_id"]: r for r in new_plan["planned_calls"]}
    if (not set(old_slots) <= set(new_slots)
        or any(new_ledger["attempts"].get(key) != value or new_slots.get(key) != old_slots[key]
               for key, value in old_ledger["attempts"].items())
        or any(attempt["state"] == "reserved" for attempts in old_ledger["attempts"].values() for attempt in attempts.values())):
        raise ValueError("pending handoff discarded or changed paid history")
    pending = {key for key, receipt in old["requests"].items() if receipt["call_id"] not in old_ledger["attempts"]}
    if set(program.get("requests", {})) != pending or len(pending) < 2:
        raise ValueError("pending condition must contain every unstarted input and no paid input")
    if any(program.get(key) != old.get(key) for key in ("target", "provider", "results_root", "runner_view", "rr_analysis_root", "pricing_as_of")):
        raise ValueError("pending condition changed target identity or original local sources")
    sources = program["sources"]
    if any(sources.get(key) != old["sources"].get(key) for key in ("pricing", "budgets", "media_index", "historical_result")):
        raise ValueError("pending condition changed source or pricing evidence")
    values = {key: retained._bound(sources[key])[0] for key in ("api_config", "pricing", "budgets", "budget_projection")}
    old_api, _ = retained._bound(old["sources"]["api_config"])
    config = values["api_config"][program["target"]]
    original_config = old_api[old["target"]]
    allowed = {"max_tokens", "reasoning_effort"}
    if ({k: v for k, v in config.items() if k not in allowed}
        != {k: v for k, v in original_config.items() if k not in allowed}
        or (program["schema"] == SCHEMA and config == original_config)):
        raise ValueError("pending condition must change only the declared output settings")
    expected = projection.build_projection(api_config=values["api_config"], pricing=values["pricing"], budgets=values["budgets"],
        descriptors={"api_config": _portable(sources["api_config"]), "pricing_config": _portable(sources["pricing"]),
                     "budgets": _portable(sources["budgets"])}, pricing_as_of=program["pricing_as_of"],
        route_configuration=values["budget_projection"].get("route_configuration"))
    if expected != values["budget_projection"] or expected["status"] != "budget_fit":
        raise ValueError("pending output condition has no unchanged fitting projection")
    retained._additional_funding(sources["additional_funding"], projection._provider_budgets(values["budgets"]), budget_plan=new_plan)
    routes = [r for r in expected["routes"] if r["target_spec"] == program["target"]]
    if len(routes) != 1 or routes[0]["maximum_output_tokens_per_call"] != program["max_output_tokens"]:
        raise ValueError("pending output allowance differs from its funded route")
    normalized, _ = run_matrix._load_api_config(sources["api_config"]["path"], [program["target"]], sources["api_config"]["sha256"])
    target = run_matrix.build_target(program["target"], api_config=normalized[program["target"]])
    originals = {key: (entry, admission.prices) for admission in old_admissions for key, entry in admission.entries.items()}
    old_outputs = [Path(run_matrix.build_parser().parse_args(j["argv"]).out) for j in old["jobs"]]
    observed, outputs, names, admissions, purposes = [], set(), set(), [], []
    for job in program.get("jobs", []):
        args = run_matrix.build_parser().parse_args(job["argv"])
        output = Path(args.out)
        if (not output.is_absolute() or output.resolve() != output or output in outputs
            or any(output == prior or output.is_relative_to(prior) for prior in old_outputs)
            or job["name"] in names):
            raise ValueError("pending jobs need separate canonical output locations and names")
        if args.api_config != sources["api_config"]["path"] or args.api_config_sha256 != sources["api_config"]["sha256"]:
            raise ValueError("pending job changed its declared API configuration")
        cfg, _ = run_matrix._load_attacker_config(args.attacker_config, ["replay"], args.attacker_config_sha256)
        attacker = ReplayAttacker(**cfg["replay"])
        if attacker.retained_input_ids != job["input_ids"] or not set(job["input_ids"]) <= pending:
            raise ValueError("pending job changed its exact source selection")
        for entry in attacker._selected_entries:
            key = entry["origin"]["selection"]["input_identity_sha256"]
            if entry != originals[key][0]:
                raise ValueError("pending job changed the original delivered input")
            receipt = program["requests"][key]
            original = old["requests"][key]
            body = target.build_request(retained_dialog(entry["rendered_input"]), seed=0)
            validate_receipt(target, body, receipt["token_count"])
            if (receipt["call_id"] != original["call_id"] or receipt["judge_call_ids"] != original["judge_call_ids"]
                or receipt["request_sha256"] != retained._sha(body) or receipt["input_tokens"] != receipt["token_count"]["input_tokens"]):
                raise ValueError("pending request or future judge slots changed identity")
            for call_id in receipt["judge_call_ids"].values():
                slot = budget.call(call_id)
                if slot["provider"] != "anthropic" or slot["pool"] != "judge" or slot["bound_microusd"] < old_slots[call_id]["bound_microusd"]:
                    raise ValueError("pending output lost its future judge funding")
        prices = originals[job["input_ids"][0]][1]
        admission = retained._Admission(program=program, job=job, budget=budget, attacker=attacker,
            requests={key: program["requests"][key] for key in job["input_ids"]}, prices=prices)
        admission.validate_cli(job["argv"], args)
        observed.extend(job["input_ids"])
        purposes.append(job["purpose"])
        outputs.add(output)
        names.add(job["name"])
        admissions.append(admission)
    if (len(observed) != len(set(observed)) or set(observed) != pending or "measured_run" not in purposes
        or not any(p in {"attestation_probe", "diagnostic_canary"} for p in purposes)
        or any(p != "measured_run" for p in purposes[purposes.index("measured_run"):])):
        raise ValueError("pending pilot and measured jobs must partition the exact unpaid population")
    retained._validate_input_budget({**program, "schema": retained.COUNTED_INPUT_SCHEMA}, routes[0])
    return admissions
