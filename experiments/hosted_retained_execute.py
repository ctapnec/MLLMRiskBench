"""Budgeted retained-input execution through the existing Runner lifecycle.

Original framework provenance belongs to the retained input, not this replay
transport. This module does not introduce another response or completion format.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import re
import stat
import subprocess
from contextlib import contextmanager
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments.hosted_attempt_budget import AttemptBudget, _budget_lock
from experiments.hosted_campaign_budget import _sha, load_bound_json
from experiments.retained_response_judge_execute import _write_new, _read_regular
from ura.adapters.replay import ReplayAttacker, retained_dialog, retained_dialog_sha256
from ura.runner import retained_execution_admission
from ura.model_identity import canonical_provider_name
from ura.targets.api import provider_attempt_admission


SCHEMA = "ura-hosted-retained-execution-plan/1"
COUNTED_INPUT_SCHEMA = "ura-hosted-retained-execution-plan/2"
TRANSPORT_RECOVERY_SCHEMA = "ura-hosted-retained-execution-plan/3"
ADAPTER_RECOVERY_SCHEMA = "ura-hosted-retained-execution-plan/4"
ADAPTER_PREFIX_RECOVERY_SCHEMA = "ura-hosted-retained-execution-plan/5"
DISTINCT_INPUT_SCHEMA = "ura-hosted-retained-execution-plan/6"
COUNTED_INPUT_POLICY = "counted_requests_within_route_reservation_v1"
TOKEN_COUNT_POLICY = "surface_specific_counts_with_declared_estimates_v1"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _billing_provider(surface: str) -> str:
    return canonical_provider_name({"anthropic-fable": "anthropic", "openai-responses": "openai"}.get(surface, surface))


def _integer(value: object, label: str, *, zero: bool = False) -> int:
    if type(value) is not int or value < (0 if zero else 1):
        raise ValueError(f"{label} requires a {'nonnegative' if zero else 'positive'} integer")
    return value


def _cost(input_tokens: int, output_tokens: int, prices: Mapping[str, Any]) -> int:
    value = Decimal(input_tokens) * Decimal(prices["input"]) + Decimal(output_tokens) * Decimal(prices["output"])
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _validate_input_budget(program: Mapping[str, Any], route: Mapping[str, Any]) -> None:
    """Keep the original per-call contract or fund the explicit counted successor."""
    counted = program.get("schema") in {
        COUNTED_INPUT_SCHEMA, TRANSPORT_RECOVERY_SCHEMA, ADAPTER_RECOVERY_SCHEMA, ADAPTER_PREFIX_RECOVERY_SCHEMA,
        DISTINCT_INPUT_SCHEMA,
    }
    if counted:
        if program.get("input_budget_policy") != COUNTED_INPUT_POLICY:
            raise ValueError("counted input allocation policy differs")
    elif program.get("schema") != SCHEMA or "input_budget_policy" in program:
        raise ValueError("hosted input allocation schema differs")
    requests = program["requests"].values()
    if "maximum_priced_input_tokens" in route and any(
        row["input_tokens"] > route["maximum_priced_input_tokens"] for row in requests
    ):
        raise ValueError("selected request exceeds the bound pricing tier")
    if not counted and any(
        row["input_tokens"] > route["maximum_input_tokens_per_call"] for row in requests
    ):
        raise ValueError("selected hosted request exceeds the projected input-token ceiling")
    if sum(row["bound_microusd"] for row in requests) > route["maximum_cost_microusd"]:
        raise ValueError("exact selected target requests exceed the route's funded projection")


def _typed_provider_refusal(response: Any) -> bool:
    """A validated provider refusal is an observed outcome, not a missing reply."""
    if response.raw.get("provider_refusal") is not True:
        return False
    from ura.runner import validate_response_refusal_state

    validate_response_refusal_state(response)
    return True


class _Admission:
    """One already-validated, immutable job inside the shared funded population."""

    def __init__(self, *, program: dict, job: dict, budget: AttemptBudget,
                 attacker: ReplayAttacker, requests: Mapping[str, dict], prices: dict):
        self.program = {key: program[key] for key in ("target", "provider", "max_output_tokens")}
        self.job = copy.deepcopy(job)
        self.budget = budget
        self.attacker = attacker
        self.requests = copy.deepcopy(dict(requests))
        self.prices = copy.deepcopy(prices)
        self.transport_recoveries = {}
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
                    _integer(receipt["max_output_tokens"], "request output allowance"),
                    {**prices,
                     "input": prices.get("reservation_input", prices["input"]),
                     "output": prices.get("reservation_output", prices["output"])})):
                raise ValueError("request allowance is not funded by its exact target slot")
            if receipt["max_output_tokens"] != program["max_output_tokens"]:
                raise ValueError("funded request changed the configured output allowance")
        recovery = program.get("transport_recoveries", {})
        if recovery and program.get("schema") != TRANSPORT_RECOVERY_SCHEMA:
            raise ValueError("transport recovery requires its explicit execution contract")
        if not isinstance(recovery, dict) or not set(recovery) <= set(program.get("requests", self.requests)):
            raise ValueError("transport recovery names an unfunded input")
        for key in set(recovery) & set(self.requests):
            self.transport_recoveries[key] = _validate_transport_recovery(
                recovery[key], program=program, entry=self.entries[key],
                receipt=self.requests[key], budget=budget,
            )
        repairs = program.get("adapter_recoveries", {})
        if repairs and program.get("schema") not in {ADAPTER_RECOVERY_SCHEMA, ADAPTER_PREFIX_RECOVERY_SCHEMA}:
            raise ValueError("reviewed adapter recovery requires its explicit execution contract")
        if not isinstance(repairs, dict) or not set(repairs) <= set(program.get("requests", self.requests)):
            raise ValueError("reviewed adapter recovery names an unfunded input")
        for key in set(repairs) & set(self.requests):
            self.transport_recoveries[key] = _validate_adapter_recovery(
                repairs[key], program=program, entry=self.entries[key],
                receipt=self.requests[key], budget=budget,
            )

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
        with _budget_lock(self.budget.root):
            path = self.budget.root / "paid-circuit.json"
            if not path.exists():
                _write_new(path, {"schema": "ura-hosted-paid-circuit/1", "stage": "target",
                                  "category": category, "call_id": call_id,
                                  "budget_plan_sha256": self.budget.expected_plan_sha256})

    @contextmanager
    def attempt(self, runner: Any, attempt: Any):
        receipt = self._receipt(attempt)
        call_id = receipt["call_id"]
        key = attempt.params["retained_origin"]["selection"]["input_identity_sha256"]
        prior = self.transport_recoveries.get(key, 0)
        if self.budget.reserved_attempt_count(call_id) != prior:
            raise ValueError("transport continuation no longer matches its reviewed attempt prefix")
        ordinal = prior

        def reserve(provider: str, request: Mapping[str, Any], number: int) -> None:
            nonlocal ordinal
            if (_billing_provider(provider) != self.program["provider"] or _sha(request) != receipt["request_sha256"]
                or number != ordinal + 1):
                raise ValueError("physical request identity or retry ordinal differs from its funded slot")
            if ordinal:
                # A subsequent SDK callback proves an admitted HTTP/network retry.
                # The unsuccessful attempt's unknown bill remains fully held.
                self.budget.settle(call_id, ordinal, None)
            self.budget.reserve(call_id, number, provider=self.program["provider"])
            ordinal = number

        try:
            if _sha(runner.target.build_request(attempt.rendered_input, seed=attempt.seed)) != receipt["request_sha256"]:
                raise ValueError("target request changed since full-request counting")
            with provider_attempt_admission(reserve, attempts_used=prior):
                yield
            if ordinal == prior:
                raise ValueError("target bypassed its physical-attempt monetary reservation")
        except BaseException:
            if ordinal:
                self.budget.settle(call_id, ordinal, None)
            self._circuit("terminal_target_call_failure", call_id)
            raise

    def response_checkpointed(self, runner: Any, attempt: Any, response: Any) -> None:
        receipt = self._receipt(attempt)
        call_id = receipt["call_id"]
        count = self.budget.reserved_attempt_count(call_id)
        if type(count) is not int or not 1 <= count <= 4:
            self._circuit("target_usage_or_transport_unavailable", call_id)
            raise ValueError("durable target response lacks its actual funded physical-attempt prefix")
        provider_refusal = _typed_provider_refusal(response)
        missing = (response.raw.get("model_stability_status") == "failed_output"
                   or response.raw.get("target_input_status") == "incompatible"
                   or (not provider_refusal
                       and not any((turn.content or "").strip() for turn in response.output_turns)))
        tokens = response.tokens if isinstance(response.tokens, Mapping) else {}
        cost = None
        if not missing and all(type(tokens.get(key)) is int and tokens[key] >= 0
                               for key in ("input", "output")):
            # Without a complete cache billing breakdown, do not invent an
            # exact discounted bill: the already-funded exposure stays held.
            if "settlement_input" in self.prices and "settlement_output" in self.prices:
                cost = _cost(tokens["input"], tokens["output"], {
                    **self.prices,
                    "input": self.prices["settlement_input"],
                    "output": self.prices["settlement_output"],
                })
            elif self.prices.get("cache_read") is None and self.prices.get("cache_write") is None:
                cost = _cost(tokens["input"], tokens["output"], self.prices)
            elif "cached_input" in tokens and "cache_write_input" in tokens:
                cached, written = tokens["cached_input"], tokens["cache_write_input"]
                if (type(cached) is int and type(written) is int and min(cached, written) >= 0
                    and cached + written <= tokens["input"]
                    and (cached == 0 or self.prices.get("cache_read") is not None)
                    and (written == 0 or self.prices.get("cache_write") is not None)):
                    # Providers may omit a price for an unused cache operation.
                    # Zero tokens need no rate; positive usage still does.
                    total = (Decimal(tokens["input"] - cached - written) * Decimal(self.prices["input"])
                             + (Decimal(cached) * Decimal(self.prices["cache_read"]) if cached else Decimal(0))
                             + (Decimal(written) * Decimal(self.prices["cache_write"]) if written else Decimal(0))
                             + Decimal(tokens["output"]) * Decimal(self.prices["output"]))
                    cost = int(total.to_integral_value(rounding=ROUND_CEILING))
        self.budget.settle(call_id, count, cost)
        if (cost is None and all(type(tokens.get(key)) is int and tokens[key] >= 0
                                 for key in ("input", "output"))
            and _cost(tokens["input"], tokens["output"], {
                **self.prices,
                "input": self.prices.get("reservation_input", self.prices["input"]),
                "output": self.prices.get("reservation_output", self.prices["output"]),
            })
            > receipt["bound_microusd"]):
            self._circuit("reported_usage_requires_above_reservation_billing_review", call_id)
            raise RuntimeError("durable target usage may exceed its funded exposure; billing review is required")
        if missing or (self.job["purpose"] != "measured_run" and response.raw.get("output_truncated") is True):
            transport = response.raw.get("model_stability_category") == "transport_failure"
            category = (("transport_retry_pending" if response.raw.get("transport_retry_status") == "pending"
                         else "terminal_transport_failure") if transport
                        else "missing_target_output" if missing else "pilot_output_truncated")
            self._circuit(category, call_id)
            raise RuntimeError("paid target circuit opened after retaining its durable response")


def _validate_transport_recovery(
    value: object, *, program: Mapping[str, Any], entry: Mapping[str, Any],
    receipt: Mapping[str, Any], budget: AttemptBudget,
) -> int:
    """Admit only a retained retryable transport failure, never an answer retry."""
    from ura.data_models import Attempt, Response
    from ura.runner import Runner

    fields = {"checkpoint", "attempt_id", "prior_attempts", "request_sha256"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("transport recovery fields differ")
    prior = _integer(value["prior_attempts"], "prior transport attempts")
    if prior >= 4 or value["request_sha256"] != receipt["request_sha256"]:
        raise ValueError("transport recovery is exhausted or changed its exact request")
    descriptor = value["checkpoint"]
    if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256", "bytes"}:
        raise ValueError("transport recovery checkpoint descriptor differs")
    path = Path(descriptor["path"])
    if (not path.is_absolute() or path.resolve(strict=True) != path
        or not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 64 * 1024 * 1024):
        raise ValueError("transport recovery checkpoint must be one bounded regular file")
    data = path.read_bytes()
    if len(data) != descriptor["bytes"] or hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
        raise ValueError("transport recovery checkpoint bytes changed")
    records = Runner.load_response_checkpoint(path)
    record = records.get(value["attempt_id"])
    if record is None:
        raise ValueError("transport recovery attempt is absent from its checkpoint")
    attempt = Attempt.model_validate(record["attempt"])
    response = Response.model_validate(record["response"])
    origin = entry["origin"]
    raw = response.raw
    audit = raw.get("call_audit", {})
    if (attempt.params.get("retained_origin") != origin
        or retained_dialog_sha256(attempt.rendered_input) != origin["delivered_input_sha256"]
        or response.attempt_id != attempt.id or response.target != program["target"]
        or raw.get("model_stability_status") != "failed_output"
        or raw.get("model_stability_category") != "transport_failure"
        or response.output_turns or response.tokens is not None
        or not isinstance(audit, dict) or audit.get("operation") != "generate"
        or _billing_provider(str(audit.get("provider", ""))) != program["provider"]
        or audit.get("logical_call_count") != 1
        or raw.get("transport_attempt_count") != prior
        or audit.get("transport_attempt_count") != prior):
        raise ValueError("transport recovery is not the exact retained failed request")
    status = audit.get("status_code")
    retryable = (type(status) is int and (status in {408, 409, 425, 429} or 500 <= status <= 599))
    if status is None:
        retryable = audit.get("error_type") in {
            "APIConnectionError", "APITimeoutError", "ConnectionError", "TimeoutError",
            "ConnectError", "ReadError", "WriteError", "RemoteProtocolError",
            "ConnectTimeout", "ReadTimeout", "WriteTimeout", "PoolTimeout",
        }
    if not retryable or budget.reserved_attempt_count(receipt["call_id"]) < prior:
        raise ValueError("transport recovery lacks a retryable funded failure prefix")
    return prior


def _validate_adapter_recovery(
    value: object, *, program: Mapping[str, Any], entry: Mapping[str, Any],
    receipt: Mapping[str, Any], budget: AttemptBudget,
) -> int:
    """Explicit post-fix replay of one parser failure, not an automatic answer retry."""
    from ura.data_models import Attempt, Response
    from ura.runner import Runner
    from ura.targets import api

    fields = {"checkpoint", "attempt_id", "prior_attempts", "request_sha256",
              "repair_commit", "error_type", "error_reason"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("reviewed adapter recovery fields differ")
    prior = _integer(value["prior_attempts"], "prior adapter attempts")
    if prior >= 4 or value["request_sha256"] != receipt["request_sha256"]:
        raise ValueError("reviewed adapter recovery is exhausted or changed its request")
    # The repaired target implementation itself must be the named clean revision,
    # not merely an accounting module imported alongside an older adapter.
    _validated_checkout(Path(api.__file__).resolve().parents[3], value["repair_commit"])
    descriptor = value["checkpoint"]
    if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256", "bytes"}:
        raise ValueError("reviewed adapter recovery checkpoint descriptor differs")
    path = Path(descriptor["path"])
    if (not path.is_absolute() or path.resolve(strict=True) != path
        or not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 64 * 1024 * 1024):
        raise ValueError("reviewed adapter recovery checkpoint must be one bounded regular file")
    data = path.read_bytes()
    if len(data) != descriptor["bytes"] or hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
        raise ValueError("reviewed adapter recovery checkpoint bytes changed")
    record = Runner.load_response_checkpoint(path).get(value["attempt_id"])
    if record is None:
        raise ValueError("reviewed adapter recovery attempt is absent from its checkpoint")
    attempt = Attempt.model_validate(record["attempt"])
    response = Response.model_validate(record["response"])
    raw = response.raw
    origin = entry["origin"]
    error_types = {"openai-responses": "OpenAIResponsesOutputError",
                   "anthropic-fable": "AnthropicFableOutputError"}
    expected_error = error_types.get(program["target"].split(":", 1)[0])
    if (attempt.params.get("retained_origin") != origin
        or retained_dialog_sha256(attempt.rendered_input) != origin["delivered_input_sha256"]
        or response.attempt_id != attempt.id or response.target != program["target"]
        or raw.get("model_stability_status") != "failed_output"
        or raw.get("model_stability_category") != "unusable_output"
        or expected_error is None or raw.get("model_stability_error_type") != expected_error
        or value["error_type"] != expected_error
        or not isinstance(value["error_reason"], str) or not value["error_reason"].strip()
        or raw.get("model_stability_reason") != value["error_reason"]
        or raw.get("logical_call_count") != 1 or raw.get("model_stability_retry_count") != 0
        or response.output_turns or response.tokens is not None or raw.get("provider_refusal") is True):
        raise ValueError("reviewed adapter recovery is not the exact retained parser failure")
    # Older adapters retained a conservative upper bound here. Only the durable
    # monetary ledger establishes how many physical calls have actually occurred.
    if budget.reserved_attempt_count(receipt["call_id"]) < prior:
        raise ValueError("reviewed adapter recovery lacks its funded attempt prefix")
    return prior


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


def _validated_checkout(project_root: Path, expected_commit: str) -> Path:
    """Bind the controller process to one clean deployed project revision."""
    project = Path(project_root)
    if (not _HEX40.fullmatch(expected_commit) or project.is_symlink()
            or project.resolve(strict=True) != project):
        raise ValueError("hosted controller requires a canonical project root and exact commit")
    head = subprocess.run(
        ["git", "-C", str(project), "rev-parse", "HEAD"], capture_output=True,
        text=True, check=True,
    ).stdout.strip()
    changed = subprocess.run(
        ["git", "-C", str(project), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True, text=True, check=True,
    ).stdout
    if head != expected_commit or changed:
        raise ValueError("hosted controller project checkout is not the clean expected commit")
    return project


def _fresh_control_root(work_root: Path, control_root: Path) -> Path:
    work = Path(work_root)
    control = Path(control_root)
    if work.is_symlink() or work.resolve(strict=True) != work:
        raise ValueError("hosted controller work root must be one canonical directory")
    engineering = (work / "runs" / "engineering").resolve(strict=True)
    if (control.is_symlink() or control.exists() or not control.is_absolute()
            or control.parent.resolve(strict=True) != engineering):
        raise ValueError("hosted controller requires a fresh direct engineering root")
    control.mkdir(mode=0o700)
    return control


def _reviewed_completed_responses(program: Mapping[str, Any], budget: AttemptBudget) -> dict[str, dict]:
    """Retain usable native prefix records without regenerating or relabelling them."""
    if program.get("schema") != ADAPTER_PREFIX_RECOVERY_SCHEMA:
        return {}
    from experiments import run_matrix
    from ura.data_models import Attempt, Response
    from ura.runner import Runner

    completed = {}
    for key, recovery in program.get("adapter_recoveries", {}).items():
        descriptor = recovery["checkpoint"]
        path = Path(descriptor["path"])
        if (not path.is_absolute() or path.resolve(strict=True) != path
                or not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size > 64 * 1024 * 1024):
            raise ValueError("reviewed response prefix requires a bounded regular checkpoint")
        data = path.read_bytes()
        if descriptor["sha256"] != hashlib.sha256(data).hexdigest() or descriptor["bytes"] != len(data):
            raise ValueError("reviewed response prefix checkpoint bytes changed")
        owners = [job for job in program["jobs"] if key in job["input_ids"]]
        if len(owners) != 1:
            raise ValueError("reviewed response prefix lacks its exact recovery job")
        args = run_matrix.build_parser().parse_args(owners[0]["argv"])
        config, _artifact = run_matrix._load_attacker_config(args.attacker_config, ["replay"], args.attacker_config_sha256)
        attacker = ReplayAttacker(**config["replay"])
        entries = {entry["origin"]["selection"]["input_identity_sha256"]: entry
                   for entry in attacker._retained["entries"]}
        for record in Runner.load_response_checkpoint(path).values():
            response = Response.model_validate(record["response"])
            if (response.raw.get("model_stability_status") == "failed_output"
                    or response.raw.get("target_input_status") == "incompatible"):
                continue
            attempt = Attempt.model_validate(record["attempt"])
            origin = attempt.params.get("retained_origin", {})
            identity = origin.get("selection", {}).get("input_identity_sha256")
            entry = entries.get(identity)
            if (entry is None or origin != entry["origin"] or identity not in program["requests"]
                or retained_dialog_sha256(attempt.rendered_input) != origin["delivered_input_sha256"]
                or response.attempt_id != attempt.id or response.target != program["target"]
                or budget.reserved_attempt_count(program["requests"][identity]["call_id"]) < 1
                or not (_typed_provider_refusal(response) or any((turn.content or "").strip() for turn in response.output_turns))):
                raise ValueError("reviewed response prefix differs from its funded input")
            if identity in completed and completed[identity] != record:
                raise ValueError("reviewed response prefixes contain conflicting native records")
            completed[identity] = record
    return completed


def _retained_execution_counts(program: Mapping[str, Any], budget: AttemptBudget) -> tuple[int, int]:
    """Count logical target starts and durable usable responses for Jobs only."""
    from experiments import run_matrix
    from ura.data_models import Response
    from ura.runner import Runner

    requests = program["requests"]
    attempted = sum(
        budget.reserved_attempt_count(receipt["call_id"]) > 0
        for receipt in requests.values()
    )
    responses = {}

    def register(payload: object) -> None:
        response = Response.model_validate(payload)
        if response.target != program["target"]:
            raise ValueError("hosted controller response target changed")
        _typed_provider_refusal(response)
        previous = responses.get(response.attempt_id)
        dumped = response.model_dump(mode="json")
        if previous is not None and previous != dumped:
            raise ValueError("hosted controller found conflicting durable responses")
        responses[response.attempt_id] = dumped

    for job in program["jobs"]:
        out = Path(run_matrix.build_parser().parse_args(job["argv"]).out)
        finals = sorted(out.glob("*.responses.jsonl")) if out.is_dir() else []
        for path in finals:
            if path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("hosted controller response file is unsafe or oversized")
            for row in run_matrix._read_jsonl(path):  # noqa: SLF001
                register(row)
        for path in sorted(out.glob("*.responses.checkpoint.jsonl")) if out.is_dir() else []:
            # A failed cell can leave an empty or partial final writer beside
            # its paid checkpoint. Merge exact duplicates; never hide its tail.
            for record in Runner.load_response_checkpoint(path).values():
                register(record["response"])
    for record in _reviewed_completed_responses(program, budget).values():
        register(record["response"])
    successful = sum(
        row.get("raw", {}).get("model_stability_status") != "failed_output"
        and row.get("raw", {}).get("target_input_status") != "incompatible"
        and (row.get("raw", {}).get("provider_refusal") is True
             or any((turn.get("content") or "").strip() for turn in row.get("output_turns", [])))
        for row in responses.values()
    )
    if len(responses) > attempted or successful > attempted:
        raise ValueError("hosted controller retained-response accounting exceeds funded starts")
    return attempted, successful


def execute_registered(
    *, program_path: Path, program_sha256: str, budget_root: Path,
    budget_plan_sha256: str, project_root: Path, expected_commit: str,
    work_root: Path, control_root: Path, tmux_socket: str, tmux_session: str,
    hard_stop_hours: int = 168,
) -> list[Path]:
    """Run one funded target program as one visible tmux-owned campaign Job."""
    from experiments.local_campaign.console_events import (
        finish_child_controller, publish_target_execution, start_child_controller,
    )

    _validated_checkout(project_root, expected_commit)
    program, _descriptor = load_bound_json(program_path, program_sha256)
    budget = AttemptBudget(budget_root, budget_plan_sha256)
    _validated_jobs(program, budget)  # Final local seal and all no-call bindings first.
    call_cap = len(program["requests"])
    control = _fresh_control_root(work_root, control_root)
    start_child_controller(
        work_root=work_root, control_root=control, campaign_id=control.name,
        release_commit=expected_commit, evidence_class="measured_hosted_api",
        hard_stop_hours=hard_stop_hours, tmux_socket=tmux_socket,
        tmux_session=tmux_session, target_execution=True,
        hosted_calls_allowed=True, target_call_cap=call_cap,
    )
    try:
        outputs = execute(
            program_path=program_path, program_sha256=program_sha256,
            budget_root=budget_root, budget_plan_sha256=budget_plan_sha256,
        )
        attempted, successful = _retained_execution_counts(program, budget)
        if attempted != call_cap or successful != call_cap:
            raise RuntimeError("completed hosted program lacks its complete durable target population")
    except BaseException:
        try:
            attempted, successful = _retained_execution_counts(program, budget)
            publish_target_execution(
                work_root=work_root, control_root=control,
                target_attempts=attempted,
                successful_target_generations=successful,
            )
        finally:
            finish_child_controller(work_root=work_root, control_root=control, exit_code=1)
        raise
    publish_target_execution(
        work_root=work_root, control_root=control, target_attempts=attempted,
        successful_target_generations=successful,
    )
    finish_child_controller(work_root=work_root, control_root=control, exit_code=0)
    return outputs


def build_matched_judge_requests(*, programs: Sequence[dict], budget: AttemptBudget,
                                plan_path: Path, plan_sha256: str, local_runner_view: Path,
                                hosted_runner_view: Path, source_receipt: Path, api_config: Path,
                                token_counts: Mapping[str, dict] | None = None) -> dict:
    """Bind actual unique A4 outputs to their already funded input-derived slots.

    The existing pair plan retains missing/setup coverage; this does not change
    target selection or create replacement queries for unjudgeable outputs.
    """
    from experiments import retained_response_judge as retained
    from experiments import retained_response_judge_execute as judge
    from experiments.retained_response_judge_pair import SHARED_SCHEMA, validate_pair_plan
    from experiments.retained_response_judge_pair_execute import _reconcile_pair_selection

    funded = {}
    for program in programs:
        for admission in _validated_jobs(program, budget):
            for key, entry in admission.entries.items():
                identity = (program["target"], key)
                if identity in funded:
                    raise ValueError("matched judging cannot duplicate a funded hosted input")
                funded[identity] = (entry["origin"], admission.requests[key]["judge_call_ids"])
        for key, record in _reviewed_completed_responses(program, budget).items():
            identity = (program["target"], key)
            if identity in funded:
                raise ValueError("matched judging cannot duplicate a carried hosted input")
            funded[identity] = (record["attempt"]["params"]["retained_origin"],
                                program["requests"][key]["judge_call_ids"])
    if not funded:
        raise ValueError("matched judging requires its fully admitted target programs")
    plan = validate_pair_plan(load_bound_json(plan_path, plan_sha256)[0])
    if plan["schema"] != SHARED_SCHEMA:
        raise ValueError("prospective shared funding requires the unique-output paired plan")
    source = retained._regular_descriptor(source_receipt, plan["source"]["sha256"])
    if source != plan["source"]:
        raise ValueError("matched judge source receipt changed")
    items = _reconcile_pair_selection(local_runner_view, hosted_runner_view, plan, source)
    # Reuse the exact-source reader, not a new guessed origin-to-output join.
    cells = retained._read_view(Path(hosted_runner_view).resolve(strict=True))[0]
    by_run = {cell["run_id"]: cell for cell in cells}
    call_ids, local_slots = {}, {}
    for row, _prompt, _response in items:
        if row["cohort"] != "hosted":
            continue
        origin = by_run[row["run_id"]]["attempts"][row["attempt_id"]]["params"].get("retained_origin")
        key = origin.get("selection", {}).get("input_identity_sha256") if isinstance(origin, dict) else None
        binding = funded.get((row["exact_model"], key))
        if binding is None or origin != binding[0]:
            raise ValueError("matched hosted output differs from its exact funded original input")
        digest = row["retained_row_sha256"]
        call_ids[digest] = binding[1]["hosted"]
        local_slots[digest] = binding[1]["local"]
    # Each hosted output occurs in exactly one validated /2 edge. A reused
    # local counterpart takes the first such slot once, leaving others unused.
    for pair in plan["pairs"]:
        call_ids.setdefault(pair["local_retained_row_sha256"], local_slots[pair["hosted_retained_row_sha256"]])
    if (set(call_ids) != {row["retained_row_sha256"] for row, _, _ in items}
        or len(set(call_ids.values())) != len(call_ids)):
        raise ValueError("unique matched outputs do not have distinct funded judge slots")
    condition = plan["judge_condition"]
    normalized, _descriptor = judge._load_api_config(api_config, judge_model=condition["model"],
                                                    expected_sha256=condition["api_config_sha256"])
    requests = judge.build_shared_request_receipts(items, judge_model=condition["model"],
        normalized_api=normalized, call_ids=call_ids, token_counts=token_counts)
    for receipt in requests.values():
        slot = budget.call(receipt["call_id"])
        cost = (receipt["input_tokens_estimate"] * condition["input_microusd_per_token"]
                + receipt["max_output_tokens"] * condition["output_microusd_per_token"])
        if slot["provider"] != "anthropic" or slot["pool"] != "judge" or cost > slot["bound_microusd"]:
            raise ValueError("full matched judge request exceeds its existing funded slot")
    return requests


def _additional_funding(descriptor: Mapping, configured: Mapping, *, budget_plan: dict | None = None) -> dict:
    """Keep new allocation below reported remaining credits and original reserves.

    The predecessor accounting remains immutable, including unknown charges.
    This is a separately bounded allocation after the reported balance snapshot,
    never a reset or settlement of the predecessor ledger.
    """
    value, _ = _bound(descriptor)
    fields = {"schema", "previous_budget_plan", "previous_budget_ledger", "balances_microusd",
              "known_new_charges_microusd", "minimum_reserves_microusd", "provider_budgets_microusd",
              "unposted_margin_microusd", "protected_haiku_microusd", "judging_inventory"}
    if set(value) != fields or value["schema"] != "ura-hosted-additional-funding/1":
        raise ValueError("additional funding fields differ")
    old_plan, _ = _bound(value["previous_budget_plan"])
    old_ledger, _ = _bound(value["previous_budget_ledger"])
    if old_ledger.get("plan_sha256") != value["previous_budget_plan"]["sha256"]:
        raise ValueError("additional funding predecessor ledger differs")
    old = AttemptBudget(Path(value["previous_budget_plan"]["path"]).parent, old_ledger["plan_sha256"])
    if any(pool["unresolved_attempts"] for pool in old.snapshot()["pools"].values()):
        raise ValueError("additional funding cannot overlap an unresolved predecessor attempt")
    providers = value["provider_budgets_microusd"]
    if (not isinstance(providers, dict) or not providers or not set(providers) <= set(configured)
        or old_plan["provider_budgets_microusd"] != {
            key: row["configured_budget_microusd"] for key, row in configured.items()}):
        raise ValueError("additional funding provider inventory differs")
    for field in ("balances_microusd", "known_new_charges_microusd", "minimum_reserves_microusd",
                  "provider_budgets_microusd", "unposted_margin_microusd"):
        if not isinstance(value[field], dict) or set(value[field]) != set(providers):
            raise ValueError("additional funding provider inventory differs")
    for provider in providers:
        original = configured[provider]
        balance = _integer(value["balances_microusd"][provider], "reported remaining balance")
        charges = _integer(value["known_new_charges_microusd"][provider], "known later charges", zero=True)
        reserve = _integer(value["minimum_reserves_microusd"][provider], "protected original reserve", zero=True)
        margin = _integer(value["unposted_margin_microusd"][provider], "unposted charge margin", zero=True)
        allocation = _integer(value["provider_budgets_microusd"][provider], "additional provider allocation")
        original_budget = original["configured_budget_microusd"]
        if (old_plan["provider_budgets_microusd"][provider] != original_budget
            or reserve < original_budget - original_budget * 4 // 5
            or allocation > balance - charges
            or allocation * 4 // 5 > balance - charges - reserve - margin):
            raise ValueError("additional funding would consume protected or unavailable credits")
    inventory, _ = _bound(value["judging_inventory"])
    rows = inventory.get("unjudged_rows")
    if not isinstance(rows, list):
        raise ValueError("additional funding needs its exact existing local judge population")
    if not rows:
        # A new target still needs fresh hosted judgments. Only unchanged local
        # answers may already have been adjudicated in a previous comparison.
        matching = inventory.get("all_matching_rows")
        if not isinstance(matching, list) or not matching:
            raise ValueError("empty new local judging needs its existing answer inventory")
        reused, _ = _bound(inventory.get("reused_judgments", {}))
        records = reused.get("records")
        if not isinstance(records, list):
            raise ValueError("reused local judgment records are missing")
        by_output = {row["retained_row_sha256"]: row for row in records
                     if isinstance(row, dict) and row.get("cohort") == "local"}
        seen = set()
        for row in matching:
            key = row.get("retained_row_sha256") if isinstance(row, dict) else None
            prior = by_output.get(key)
            if (key in seen or prior is None
                or any(prior.get(field) != row.get(field) for field in
                       ("exact_model", "run_id", "attempt_id", "input_identity_sha256"))):
                raise ValueError("reused local verdict is not for the exact selected model output")
            artifact, _ = _bound(prior.get("judgment_artifact", {}))
            if artifact.get("retained_row_sha256") != key:
                raise ValueError("reused judgment artifact names a different output")
            seen.add(key)
    keys = [row.get("retained_row_sha256") for row in rows if isinstance(row, dict)]
    if (len(keys) != len(rows) or len(set(keys)) != len(keys)
        or any(not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key) for key in keys)):
        raise ValueError("additional local judge population has invalid or duplicate identities")
    if budget_plan is not None:
        if (budget_plan["provider_budgets_microusd"] != value["provider_budgets_microusd"]
            or budget_plan["protected_haiku_microusd"] != value["protected_haiku_microusd"]
            or {row["call_id"] for row in budget_plan["planned_calls"]}
                & {row["call_id"] for row in old_plan["planned_calls"]}):
            raise ValueError("additional budget differs or repeats predecessor slots")
    return value


def _distinct_judge_ids(plan: dict, key: str, candidates: Sequence[dict]) -> dict[str, str]:
    """One funded future slot per grading context, independent of source aliases."""
    group = next(row for row in plan["selection"]["request_groups"]
                 if row["representative_input_sha256"] == key)
    by_id = {row["input_identity_sha256"]: row for row in candidates}
    def context(identity):
        return _sha({field: value for field, value in by_id[identity].items()
                     if field not in {"input_identity_sha256", "converted_corpus_sha256", "local_sources", "rendered_input"}})
    target = plan["target_condition"]["target_spec"]
    result = {"hosted": "judge-hosted-" + _sha({"target": target, "input_id": key})}
    for identity in sorted({context(identity) for identity in group["source_input_ids"]} - {context(key)}):
        result["hosted-context-" + identity] = "judge-hosted-context-" + _sha({
            "target": target, "request_sha256": group["request_sha256"], "grading_context": identity})
    return result


def _validated_jobs(program: dict, budget: AttemptBudget, *, local_context: tuple | None = None) -> list[_Admission]:
    """Rebuild fixed input selection from complete historical and RR evidence."""
    from experiments import hosted_pending_condition
    if isinstance(program, dict) and program.get("schema") == hosted_pending_condition.SCHEMA:
        return hosted_pending_condition.validated_jobs(program, budget, local_context=local_context)
    if (not isinstance(program, dict) or program.get("schema") not in {
        SCHEMA, COUNTED_INPUT_SCHEMA, TRANSPORT_RECOVERY_SCHEMA, ADAPTER_RECOVERY_SCHEMA, ADAPTER_PREFIX_RECOVERY_SCHEMA,
        DISTINCT_INPUT_SCHEMA,
    }
        or program.get("budget_plan_sha256") != budget.expected_plan_sha256
        or program.get("token_count_policy") != TOKEN_COUNT_POLICY
        or program.get("replaced_descriptive_prerequisite") != "authority.requires_exact_provider_token_counts"):
        raise ValueError("complete local-source program admission requires its exact funded plan")
    recovery = program.get("transport_recoveries")
    if program["schema"] == TRANSPORT_RECOVERY_SCHEMA:
        if not isinstance(recovery, dict) or not recovery:
            raise ValueError("transport recovery contract requires its retained failures")
    elif recovery is not None:
        raise ValueError("historical execution contracts cannot add transport recovery")
    repairs = program.get("adapter_recoveries")
    if program["schema"] in {ADAPTER_RECOVERY_SCHEMA, ADAPTER_PREFIX_RECOVERY_SCHEMA}:
        if not isinstance(repairs, dict) or not repairs:
            raise ValueError("reviewed adapter recovery contract requires its retained failures")
    elif repairs is not None:
        raise ValueError("historical execution contracts cannot add reviewed adapter recovery")
    from experiments import hosted_campaign_budget as projection, hosted_retained_inputs as inputs
    from experiments.hosted_request_tokens import validate_receipt
    from experiments import run_matrix

    cells, historical_inventory = (_validated_local_cells(program) if local_context is None else local_context)
    sources = program["sources"]
    values = {key: _bound(sources[key])[0] for key in
              ("api_config", "pricing", "budgets", "budget_projection", "media_index")}
    descriptors = {key: {"file": Path(sources[key]["path"]).name,
                          "sha256": sources[key]["sha256"], "bytes": sources[key]["bytes"]}
                   for key in ("api_config", "pricing", "budgets")}
    expected_projection = projection.build_projection(
        api_config=values["api_config"], pricing=values["pricing"], budgets=values["budgets"],
        descriptors={"api_config": descriptors["api_config"], "pricing_config": descriptors["pricing"],
                     "budgets": descriptors["budgets"]}, pricing_as_of=program["pricing_as_of"],
        route_configuration=values["budget_projection"].get("route_configuration"),
    )
    if values["budget_projection"] != expected_projection or expected_projection["status"] != "budget_fit":
        raise ValueError("hosted program budget or effective-dated pricing projection changed")
    budget_plan, _descriptor = _read_regular(budget.root / "plan.json", label="funded program budget", max_bytes=64 * 1024 * 1024)
    configured = projection._provider_budgets(values["budgets"])
    distinct = program["schema"] == DISTINCT_INPUT_SCHEMA
    if distinct:
        funding = _additional_funding(sources["additional_funding"], configured, budget_plan=budget_plan)
        inventory, _ = _bound(funding["judging_inventory"])
        judge = expected_projection["judge"]
        local_bound = _cost(judge["maximum_input_tokens_per_call"], judge["maximum_output_tokens_per_call"],
                            {"input": judge["input_usd_per_million_tokens"], "output": judge["output_usd_per_million_tokens"]})
        for row in inventory["unjudged_rows"]:
            slot = budget.call("judge-local-" + row["retained_row_sha256"])
            if slot["provider"] != "anthropic" or slot["pool"] != "judge" or slot["bound_microusd"] < local_bound:
                raise ValueError("complete matching local judge population is not funded upfront")
    elif "additional_funding" in sources:
        raise ValueError("historical execution cannot add supplemental funding")
    elif budget_plan["provider_budgets_microusd"] != {
        key: row["configured_budget_microusd"] for key, row in configured.items()
    }:
        raise ValueError("shared funding differs from the bound current provider budgets")
    if sum(row["pool"] == "judge" for row in budget_plan["planned_calls"]) > projection.JUDGE_CALL_CAP:
        raise ValueError("funded Haiku population exceeds its complete campaign call cap")
    routes = [row for row in expected_projection["routes"] if row["target_spec"] == program["target"]]
    if (len(routes) != 1 or routes[0]["provider"] != program["provider"]
        or routes[0]["maximum_output_tokens_per_call"] != program["max_output_tokens"]):
        raise ValueError("retained program target condition differs from its funded route")
    route = routes[0]
    normalized, _api_artifact = run_matrix._load_api_config(
        sources["api_config"]["path"], [program["target"]], sources["api_config"]["sha256"],
    )
    # The constructors are lazy. No SDK/client is constructed while previewing.
    target = run_matrix.build_target(program["target"], api_config=normalized.get(program["target"]))
    candidates = inputs.candidates_from_cells(cells)  # Never filter by observed answers.
    bindings = {"budget": expected_projection,
                "budget_descriptor": {"file": Path(sources["budget_projection"]["path"]).name,
                                      **{key: sources["budget_projection"][key] for key in ("sha256", "bytes")}},
                "api_config": values["api_config"], "api_descriptor": descriptors["api_config"],
                "media_index": values["media_index"],
                "local_inventory_descriptor": {"file": Path(historical_inventory["path"]).name,
                    **{key: historical_inventory[key] for key in ("sha256", "bytes")}}}
    jobs = program.get("jobs")
    if not isinstance(jobs, list) or not jobs:
        raise ValueError("retained program has no fixed pilot/measured partition")
    prices, _why = projection.rate_for(values["pricing"], route["provider"], route["model"],
        on_date=program["pricing_as_of"])
    prices = {
        **prices["per_million_tokens"],
        "reservation_input": route["reserved_input_usd_per_million_tokens"],
        "reservation_output": route["reserved_output_usd_per_million_tokens"],
    }
    if route["reservation_price_condition"] == "published_peak":
        # Retain the funded peak-rate estimate after each call. Provider billing
        # reconciliation may later establish a lower off-peak charge, but an
        # assumed discount cannot release money for another selected call.
        prices.update(settlement_input=prices["reservation_input"],
                      settlement_output=prices["reservation_output"])
    requests = program["requests"]
    carried = _reviewed_completed_responses(program, budget)
    planned_ids, observed_ids, outputs, names = None, [], set(), set()
    checked_plan = None
    admitted = []
    pilot_ids = []
    measured_started = False
    for job in jobs:
        if (job.get("purpose") not in {"attestation_probe", "diagnostic_canary", "measured_run"}
            or not isinstance(job.get("name"), str) or job["name"] in names):
            raise ValueError("retained program purpose or job identity differs")
        names.add(job["name"])
        if job["purpose"] == "measured_run":
            measured_started = True
        elif measured_started:
            raise ValueError("funded readiness/canary jobs must finish before any measured job")
        args = run_matrix.build_parser().parse_args(job["argv"])
        if not Path(args.out).is_absolute() or Path(args.out).resolve() != Path(args.out):
            raise ValueError("retained job output must be one canonical absolute Runner directory")
        if Path(args.out).resolve() in outputs:
            raise ValueError("pilot and measured Runner output roots must remain separate")
        outputs.add(Path(args.out).resolve())
        if (str(Path(args.api_config).resolve()) != sources["api_config"]["path"]
            or args.api_config_sha256 != sources["api_config"]["sha256"]):
            raise ValueError("job API registry differs from its full-request and pricing binding")
        attacker_config, _artifact = run_matrix._load_attacker_config(
            args.attacker_config, ["replay"], args.attacker_config_sha256,
        )
        attacker = ReplayAttacker(**attacker_config["replay"])
        if getattr(attacker, "retained_input_ids", None) != job["input_ids"]:
            raise ValueError("job changed its exact funded pilot/measured input IDs")
        plan = attacker._retained["plan"]
        if (plan["schema"] == inputs.DISTINCT_SCHEMA) != distinct:
            raise ValueError("distinct retained inputs require their explicit execution contract")
        # Selection /1 was never paid admission. Its original descriptive
        # exact-count prerequisite is retained verbatim; only this prospective
        # execution condition adopts explicitly named provider estimates.
        if program.get("predecessor_selection") != {"schema": plan["schema"], "plan_id": plan["plan_id"], "sha256": _sha(plan)}:
            raise ValueError("prospective count policy changed its exact predecessor input selection")
        if checked_plan is None:
            resolved = inputs.resolve_inputs(plan, candidates=candidates,
                **({"request_builder": inputs.provider_request_builder(target, values["media_index"])} if distinct else {}),
                **bindings)
            checked_plan = (copy.deepcopy(plan), [row["input_identity_sha256"] for row in resolved])
        if plan != checked_plan[0]:
            raise ValueError("retained jobs changed their common input selection plan")
        ids = checked_plan[1]
        if planned_ids is not None and ids != planned_ids:
            raise ValueError("jobs do not share one outcome-independent hosted input selection")
        planned_ids = ids
        if plan["target_condition"]["target_spec"] != program["target"]:
            raise ValueError("retained input selection names a different hosted target")
        by_source = {cell["run_id"]: cell for cell in cells}
        carried_entries = [entry for entry in attacker._retained["entries"]
                           if entry["origin"]["selection"]["input_identity_sha256"] in carried]
        for entry in [*attacker._selected_entries, *carried_entries]:
            origin = entry["origin"]
            source = origin["source_membership"]
            if by_source[source["run_id"]]["attempts"][source["attempt_id"]] != origin["original_attempt"]:
                raise ValueError("materialized replay differs from its actual original Attempt")
            key = origin["selection"]["input_identity_sha256"]
            receipt = requests[key]
            request = target.build_request(retained_dialog(entry["rendered_input"]), seed=0)
            validate_receipt(target, request, receipt["token_count"])
            if (receipt["request_sha256"] != _sha(request)
                or receipt["input_tokens"] != receipt["token_count"]["input_tokens"]
                or receipt["call_id"] != "target-" + _sha({"target": program["target"], "input_id": key})):
                raise ValueError("counted request differs from its funded retained target input")
            expected_judges = {cohort: "judge-" + cohort + "-" + _sha({"target": program["target"], "input_id": key})
                               for cohort in ("local", "hosted")}
            if distinct:
                expected_judges = _distinct_judge_ids(plan, key, candidates)
            if receipt.get("judge_call_ids") != expected_judges:
                raise ValueError("future matched judgments need exact input-derived funded slots, not invented output hashes")
            judge = expected_projection["judge"]
            judge_bound = _cost(
                judge["maximum_input_tokens_per_call"],
                judge["maximum_output_tokens_per_call"],
                {
                    "input": judge["input_usd_per_million_tokens"],
                    "output": judge["output_usd_per_million_tokens"],
                },
            )
            for call_id in expected_judges.values():
                slot = budget.call(call_id)
                if slot["provider"] != "anthropic" or slot["pool"] != "judge" or slot["bound_microusd"] < judge_bound:
                    raise ValueError("selected input's prospective Haiku judgments are not funded upfront")
        observed_ids += job["input_ids"]
        if job["purpose"] != "measured_run":
            pilot_ids += job["input_ids"]
        admission = _Admission(program=program, job=job, budget=budget, attacker=attacker,
                               requests={key: requests[key] for key in job["input_ids"]}, prices=prices)
        admission.validate_cli(job["argv"], args)
        admitted.append(admission)
    if (len(observed_ids) != len(set(observed_ids)) or set(observed_ids) & set(carried)
        or set(observed_ids) | set(carried) != set(planned_ids or [])
        or set(requests) != set(observed_ids) | set(carried) or len(requests) > route["paid_call_cap"]
        or not pilot_ids or not any(job["purpose"] == "measured_run" for job in jobs)):
        raise ValueError("fixed pilot and measured calls must partition the complete selected population once")
    # Pilot membership is fixed from inputs, never picked/replaced after output.
    # The bounded main cohort and all first attempts remain funded upfront.
    _validate_input_budget(program, route)
    return admitted


def _bound(raw: Mapping[str, Any]) -> tuple[dict, dict]:
    path = Path(raw["path"])
    value, descriptor = _read_regular(path, label="hosted source binding", max_bytes=64 * 1024 * 1024)
    observed = {"path": str(path.resolve(strict=True)), **{key: descriptor[key] for key in ("sha256", "bytes")}}
    if observed != dict(raw):
        raise ValueError("hosted source descriptor changed")
    return value, observed


def _validated_local_cells(program: dict) -> tuple[list[dict], dict]:
    from experiments.local_campaign.continuation_stats import retained_continuation_reports
    from experiments.local_campaign.execution_accounting import build_execution_accounting
    from experiments.local_campaign.rr_parallel_analysis import load_judge_view
    from experiments.retained_artifact_reader import load_cells

    reports = retained_continuation_reports(Path(program["results_root"]), program["sources"]["historical_result"])
    inventories = [raw for kind, _label, raw in reports if kind == "terminal_inventory"]
    accountings = [raw for kind, _label, raw in reports if kind == "execution_accounting"]
    if len(inventories) != 1 or len(accountings) != 1:
        raise ValueError("historical 144-unit completion lacks its exact accounting/inventory pair")
    accounting, _descriptor = _bound(accountings[0])
    generated = accounting["generated_from"]
    view, view_descriptor = _bound(generated["human_audit_runner_input_view"])
    index, _index_descriptor = _bound(generated["human_audit_sampling_index"])
    root = Path(program["runner_view"]).resolve(strict=True)
    if (view.get("schema") != "ura-phase7-human-audit-sampling-view/9" or view.get("status") != "complete"
        or view.get("view_root") != str(root) or view.get("source_files_modified") is not False
        or view.get("permitted_view_outputs") != [] or index.get("view_receipt") != view_descriptor
        or view.get("file_inventory_sha256") != _sha(view.get("file_inventory"))):
        raise ValueError("historical selector view differs from the complete accounting source")
    paths, total_bytes = set(), 0
    for row in view["file_inventory"]:
        source_path, path = Path(row["source"]["path"]), Path(row["view"]["path"])
        from experiments.hosted_retained_inputs import _descriptor as descriptor_file
        source, copied = descriptor_file(source_path), descriptor_file(path)
        st, original_st = path.stat(), source_path.stat()
        relative = path.relative_to(root).as_posix()
        if (source != row["source"] or copied != row["view"]
            or any(source[key] != copied[key] for key in ("sha256", "bytes"))
            or relative != row["relative_path"] or relative in paths
            or row["source_file_identity"] != {"device": original_st.st_dev, "inode": original_st.st_ino}
            or row["view_file_identity"] != {"device": st.st_dev, "inode": st.st_ino}
            or source_path.samefile(path) or row["independent_copy"] is not True
            or row["source_view_samefile"] is not False or st.st_nlink != 1
            or row["view_link_count"] != 1 or row["view_mode"] != stat.S_IMODE(st.st_mode)
            or stat.S_IMODE(st.st_mode) & 0o222):
            raise ValueError("historical retained input copy identity changed")
        paths.add(relative)
        total_bytes += copied["bytes"]
    observed = set()
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("historical retained view contains an unsafe entry")
        if path.is_file():
            observed.add(path.relative_to(root).as_posix())
    if (paths != observed or len(paths) != view["regular_files_copied"] or total_bytes != view["logical_bytes"]):
        raise ValueError("historical retained view has a different complete file inventory")
    historical = load_cells(root)
    if build_execution_accounting(historical, generated_from=generated) != accounting:
        raise ValueError("historical selected cells do not reproduce their complete accounting")
    rr = load_judge_view(Path(program["rr_analysis_root"]))[0]
    cells = [*historical, *rr]
    if len({cell["run_id"] for cell in cells}) != len(cells):
        raise ValueError("historical and complete RR source cells overlap")
    return cells, inventories[0]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--program-sha256", required=True)
    parser.add_argument("--budget-root", type=Path, required=True)
    parser.add_argument("--budget-plan-sha256", required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--tmux-socket", required=True)
    parser.add_argument("--tmux-session", required=True)
    parser.add_argument("--hard-stop-hours", type=int, default=168)
    args = parser.parse_args(argv)
    for path in execute_registered(
        program_path=args.program, program_sha256=args.program_sha256,
        budget_root=args.budget_root, budget_plan_sha256=args.budget_plan_sha256,
        project_root=args.project_root, expected_commit=args.expected_commit,
        work_root=args.work_root, control_root=args.control_root,
        tmux_socket=args.tmux_socket, tmux_session=args.tmux_session,
        hard_stop_hours=args.hard_stop_hours,
    ):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
