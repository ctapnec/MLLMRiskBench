"""Budgeted retained-input execution through the existing Runner lifecycle.

Original framework provenance belongs to the retained input, not this replay
transport. This module does not introduce another response or completion format.
"""
from __future__ import annotations

import argparse
import copy
from contextlib import contextmanager
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_campaign_budget import _sha, load_bound_json
from experiments.retained_response_judge_execute import _exclusive_lock, _write_new
from ura.adapters.replay import ReplayAttacker, retained_dialog_sha256
from ura.runner import retained_execution_admission
from ura.model_identity import canonical_provider_name
from ura.targets.api import provider_attempt_admission


SCHEMA = "ura-hosted-retained-execution-plan/1"


def _billing_provider(surface: str) -> str:
    return canonical_provider_name({"anthropic-fable": "anthropic", "openai-responses": "openai"}.get(surface, surface))


def _integer(value: object, label: str, *, zero: bool = False) -> int:
    if type(value) is not int or value < (0 if zero else 1):
        raise ValueError(f"{label} requires a {'nonnegative' if zero else 'positive'} integer")
    return value


def _cost(input_tokens: int, output_tokens: int, prices: Mapping[str, Any]) -> int:
    value = Decimal(input_tokens) * Decimal(prices["input"]) + Decimal(output_tokens) * Decimal(prices["output"])
    return int(value.to_integral_value(rounding=ROUND_CEILING))


class _Admission:
    """One already-validated, immutable job inside the shared funded population."""

    def __init__(self, *, program: dict, job: dict, budget: AttemptBudget,
                 attacker: ReplayAttacker, requests: Mapping[str, dict], prices: dict):
        self.program = copy.deepcopy(program)
        self.job = copy.deepcopy(job)
        self.budget = budget
        self.attacker = attacker
        self.requests = copy.deepcopy(dict(requests))
        self.prices = copy.deepcopy(prices)
        self.entries = {entry["origin"]["selection"]["input_identity_sha256"]: entry
                        for entry in attacker._selected_entries}
        if set(self.entries) != set(job["input_ids"]) or set(self.requests) != set(self.entries):
            raise ValueError("funded job requests differ from its exact retained input partition")
        call_ids = [receipt["call_id"] for receipt in self.requests.values()]
        if len(set(call_ids)) != len(call_ids):
            raise ValueError("retained inputs cannot share one funded target call")
        for receipt in self.requests.values():
            slot = budget.call(receipt["call_id"])
            if (slot["provider"] != program["provider"] or slot["pool"] != "target"
                or slot["bound_microusd"] != receipt["bound_microusd"]
                or slot["bound_microusd"] < _cost(
                    _integer(receipt["input_tokens"], "request input estimate", zero=True),
                    _integer(receipt["max_output_tokens"], "request output allowance"), prices)):
                raise ValueError("request allowance is not funded by its exact target slot")
            if receipt["max_output_tokens"] != program["max_output_tokens"]:
                raise ValueError("funded request changed the configured output allowance")

    def validate_cli(self, argv: list[str], args: argparse.Namespace) -> None:
        if argv != self.job["argv"]:
            raise ValueError("retained execution argv differs from its admitted job")
        purpose = ("attestation_probe" if args.attestation_probe else
                   "diagnostic_canary" if args.diagnostic_canary else "measured_run")
        if (purpose != self.job["purpose"] or args.dry_run or args.preflight_only
            or args.api != self.program["target"] or args.local or args.models
            or args.attackers != "replay" or args.corpora != self.attacker._retained["corpus"]
            or args.seeds != "0" or args.sample_seed != 0 or args.target_answer_retries != 0
            or args.defense != "none" or args.exclude_tool_conditioned
            or args.judges != "rules,guardrail"
            or args.max_total_target_calls != len(self.entries)
            or args.max_total_http_attempts != 4 * len(self.entries)
            or args.max_total_judge_calls < len(self.entries)):
            raise ValueError("retained execution target, scope, retries or call caps differ")

    def validate_runner(self, runner: Any) -> None:
        if (runner.attacker.retained_replay_id != self.attacker.retained_replay_id
            or getattr(runner.attacker, "retained_input_ids", None) != self.attacker.retained_input_ids
            or runner.target.name != self.program["target"]
            or runner.seeds != [0] or runner.target_answer_retries != 0
            or runner.target.max_retries != 3
            or runner.target.max_tokens != self.program["max_output_tokens"]):
            raise ValueError("Runner differs from its funded retained target condition")
        if not callable(getattr(runner.target, "build_request", None)):
            raise ValueError("funded target lacks the shared exact request preview")

    def _receipt(self, attempt: Any) -> dict:
        origin = attempt.params.get("retained_origin", {})
        identity = origin.get("selection", {}).get("input_identity_sha256")
        entry = self.entries.get(identity)
        if (entry is None or origin != entry["origin"]
            or retained_dialog_sha256(attempt.rendered_input) != origin["delivered_input_sha256"]):
            raise ValueError("target call is outside its original retained input partition")
        return self.requests[identity]

    def _circuit(self, category: str, call_id: str) -> None:
        with _exclusive_lock(self.budget.root):
            path = self.budget.root / "paid-circuit.json"
            if not path.exists():
                _write_new(path, {"schema": "ura-hosted-paid-circuit/1", "stage": "target",
                                  "category": category, "call_id": call_id,
                                  "budget_plan_sha256": self.budget.expected_plan_sha256})

    @contextmanager
    def attempt(self, runner: Any, attempt: Any):
        receipt = self._receipt(attempt)
        call_id = receipt["call_id"]
        ordinal = 0

        def reserve(provider: str, request: Mapping[str, Any], number: int) -> None:
            nonlocal ordinal
            if (_billing_provider(provider) != self.program["provider"] or _sha(request) != receipt["request_sha256"]
                or number != ordinal + 1):
                raise ValueError("physical request identity or retry ordinal differs from its funded slot")
            if ordinal:
                # A subsequent SDK callback proves a status-bearing HTTP retry.
                # The unsuccessful attempt's unknown bill remains fully held.
                self.budget.settle(call_id, ordinal, None)
            self.budget.reserve(call_id, number, provider=self.program["provider"])
            ordinal = number

        try:
            if _sha(runner.target.build_request(attempt.rendered_input, seed=attempt.seed)) != receipt["request_sha256"]:
                raise ValueError("target request changed since full-request counting")
            with provider_attempt_admission(reserve):
                yield
            if not ordinal:
                raise ValueError("target bypassed its physical-attempt monetary reservation")
        except BaseException:
            if ordinal:
                self.budget.settle(call_id, ordinal, None)
            self._circuit("terminal_target_call_failure", call_id)
            raise

    def response_checkpointed(self, runner: Any, attempt: Any, response: Any) -> None:
        receipt = self._receipt(attempt)
        call_id = receipt["call_id"]
        count = response.raw.get("transport_attempt_count")
        if type(count) is not int or not 1 <= count <= 4:
            self._circuit("target_usage_or_transport_unavailable", call_id)
            raise ValueError("durable target response lacks bounded physical-attempt accounting")
        missing = (response.raw.get("model_stability_status") == "failed_output"
                   or response.raw.get("target_input_status") == "incompatible"
                   or not any((turn.content or "").strip() for turn in response.output_turns))
        cost = None
        if not missing and all(type(response.tokens.get(key)) is int and response.tokens[key] >= 0
                               for key in ("input", "output")):
            # Without a complete cache billing breakdown, do not invent an
            # exact discounted bill: the already-funded exposure stays held.
            if self.prices.get("cache_read") is None and self.prices.get("cache_write") is None:
                cost = _cost(response.tokens["input"], response.tokens["output"], self.prices)
            elif "cached_input" in response.tokens and "cache_write_input" in response.tokens:
                cached, written = response.tokens["cached_input"], response.tokens["cache_write_input"]
                if (type(cached) is int and type(written) is int and min(cached, written) >= 0
                    and cached + written <= response.tokens["input"]):
                    total = (Decimal(response.tokens["input"] - cached - written) * Decimal(self.prices["input"])
                             + Decimal(cached) * Decimal(self.prices["cache_read"])
                             + Decimal(written) * Decimal(self.prices["cache_write"])
                             + Decimal(response.tokens["output"]) * Decimal(self.prices["output"]))
                    cost = int(total.to_integral_value(rounding=ROUND_CEILING))
        self.budget.settle(call_id, count, cost)
        if missing or (self.job["purpose"] != "measured_run" and response.raw.get("output_truncated") is True):
            self._circuit("missing_target_output" if missing else "pilot_output_truncated", call_id)
            raise RuntimeError("paid target circuit opened after retaining its durable response")


def execute(*, program_path: Path, program_sha256: str, budget_root: Path,
            budget_plan_sha256: str) -> list[Path]:
    """Run only a fully admitted program using run_matrix's own sealed outputs."""
    program, _descriptor = load_bound_json(program_path, program_sha256)
    budget = AttemptBudget(budget_root, budget_plan_sha256)
    jobs = _validated_jobs(program, budget)
    from experiments import run_matrix

    outputs = []
    for admission in jobs:
        with retained_execution_admission(admission):
            result = run_matrix.main(admission.job["argv"])
        if result != 0:
            raise RuntimeError("retained Runner job is unfinished; saved responses must be resumed, not repeated")
        outputs.append(Path(run_matrix.build_parser().parse_args(admission.job["argv"]).out))
    return outputs


def _validated_jobs(program: dict, budget: AttemptBudget) -> list[_Admission]:
    # Completed local/RR source, fixed pilot/measurement union, pricing and
    # full-request validation are supplied here before any target factory.
    raise ValueError("hosted execution remains unavailable until complete local-source program admission is implemented")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--program-sha256", required=True)
    parser.add_argument("--budget-root", type=Path, required=True)
    parser.add_argument("--budget-plan-sha256", required=True)
    args = parser.parse_args(argv)
    for path in execute(program_path=args.program, program_sha256=args.program_sha256,
                        budget_root=args.budget_root, budget_plan_sha256=args.budget_plan_sha256):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
