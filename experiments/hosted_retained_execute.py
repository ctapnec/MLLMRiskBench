"""Budgeted retained-input execution through the existing Runner lifecycle.

Original framework provenance belongs to the retained input, not this replay
transport. This module does not introduce another response or completion format.
"""
from __future__ import annotations

import argparse
import copy
import re
import stat
import subprocess
from contextlib import contextmanager
from decimal import Decimal, ROUND_CEILING
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments.hosted_attempt_budget import AttemptBudget
from experiments.hosted_campaign_budget import _sha, load_bound_json
from experiments.retained_response_judge_execute import _exclusive_lock, _write_new, _read_regular
from ura.adapters.replay import ReplayAttacker, retained_dialog, retained_dialog_sha256
from ura.runner import retained_execution_admission
from ura.model_identity import canonical_provider_name
from ura.targets.api import provider_attempt_admission


SCHEMA = "ura-hosted-retained-execution-plan/1"
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
        count = self.budget.reserved_attempt_count(call_id)
        if type(count) is not int or not 1 <= count <= 4:
            self._circuit("target_usage_or_transport_unavailable", call_id)
            raise ValueError("durable target response lacks its actual funded physical-attempt prefix")
        missing = (response.raw.get("model_stability_status") == "failed_output"
                   or response.raw.get("target_input_status") == "incompatible"
                   or not any((turn.content or "").strip() for turn in response.output_turns))
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
                    and cached + written <= tokens["input"]):
                    total = (Decimal(tokens["input"] - cached - written) * Decimal(self.prices["input"])
                             + Decimal(cached) * Decimal(self.prices["cache_read"])
                             + Decimal(written) * Decimal(self.prices["cache_write"])
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
        previous = responses.get(response.attempt_id)
        dumped = response.model_dump(mode="json")
        if previous is not None and previous != dumped:
            raise ValueError("hosted controller found conflicting durable responses")
        responses[response.attempt_id] = dumped

    for job in program["jobs"]:
        out = Path(run_matrix.build_parser().parse_args(job["argv"]).out)
        finals = sorted(out.glob("*.responses.jsonl")) if out.is_dir() else []
        final_names = {path.name for path in finals}
        for path in finals:
            if path.is_symlink() or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("hosted controller response file is unsafe or oversized")
            for row in run_matrix._read_jsonl(path):  # noqa: SLF001
                register(row)
        for path in sorted(out.glob("*.responses.checkpoint.jsonl")) if out.is_dir() else []:
            final_name = path.name.replace(".responses.checkpoint.jsonl", ".responses.jsonl")
            if final_name in final_names:
                continue
            for record in Runner.load_response_checkpoint(path).values():
                register(record["response"])
    successful = sum(
        row.get("raw", {}).get("model_stability_status") != "failed_output"
        and row.get("raw", {}).get("target_input_status") != "incompatible"
        and any((turn.get("content") or "").strip() for turn in row.get("output_turns", []))
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


def _validated_jobs(program: dict, budget: AttemptBudget) -> list[_Admission]:
    """Rebuild fixed input selection from complete historical and RR evidence."""
    if (not isinstance(program, dict) or program.get("schema") != SCHEMA
        or program.get("budget_plan_sha256") != budget.expected_plan_sha256
        or program.get("token_count_policy") != TOKEN_COUNT_POLICY
        or program.get("replaced_descriptive_prerequisite") != "authority.requires_exact_provider_token_counts"):
        raise ValueError("complete local-source program admission requires its exact funded plan")
    from experiments import hosted_campaign_budget as projection, hosted_retained_inputs as inputs
    from experiments.hosted_request_tokens import validate_receipt
    from experiments import run_matrix

    cells, historical_inventory = _validated_local_cells(program)
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
    )
    if values["budget_projection"] != expected_projection or expected_projection["status"] != "budget_fit":
        raise ValueError("hosted program budget or effective-dated pricing projection changed")
    budget_plan, _descriptor = _read_regular(budget.root / "plan.json", label="funded program budget", max_bytes=64 * 1024 * 1024)
    configured = projection._provider_budgets(values["budgets"])
    if budget_plan["provider_budgets_microusd"] != {
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
        # Selection /1 was never paid admission. Its original descriptive
        # exact-count prerequisite is retained verbatim; only this prospective
        # execution condition adopts explicitly named provider estimates.
        if program.get("predecessor_selection") != {"schema": plan["schema"], "plan_id": plan["plan_id"], "sha256": _sha(plan)}:
            raise ValueError("prospective count policy changed its exact predecessor input selection")
        if checked_plan is None:
            resolved = inputs.resolve_inputs(plan, candidates=candidates, **bindings)
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
        for entry in attacker._selected_entries:
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
            if receipt.get("judge_call_ids") != expected_judges:
                raise ValueError("future matched judgments need exact input-derived funded slots, not invented output hashes")
            judge_bound = (projection.JUDGE_MAX_INPUT_TOKENS + projection.JUDGE_MAX_OUTPUT_TOKENS * 5)
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
    if (len(observed_ids) != len(set(observed_ids)) or set(observed_ids) != set(planned_ids or [])
        or set(requests) != set(observed_ids) or len(observed_ids) > route["paid_call_cap"]
        or not pilot_ids or not any(job["purpose"] == "measured_run" for job in jobs)):
        raise ValueError("fixed pilot and measured calls must partition the complete selected population once")
    # Pilot membership is fixed from inputs, never picked/replaced after output.
    # The bounded main cohort and all first attempts remain funded upfront.
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
