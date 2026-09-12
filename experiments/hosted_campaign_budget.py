"""Create a no-call budget projection for the fixed hosted follow-on cohort.

The projection reads the exact API target, effective-dated pricing, and budget
registries. It distinguishes an explicitly uncalibrated quarter-cap output
scenario from the reservation when every response consumes its maximum.
It never constructs a target or judge and never reads credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path
from typing import Any

from experiments.rig_web_app.reports import rate_for
from ura.targets.api import (
    AnthropicFableTarget,
    DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
    OpenAIResponsesTarget,
)


SCHEMA = "ura-hosted-campaign-budget-projection/4"
CONFIGURED_SCHEMA = "ura-hosted-campaign-budget-projection/5"
CONTINUOUS_SCHEMA = "ura-hosted-campaign-budget-projection/6"
EXPECTED_INPUT_TOKENS = 4_000
MAX_INPUT_TOKENS = 4_000
JUDGE_EXPECTED_INPUT_TOKENS = 8_192
JUDGE_MAX_INPUT_TOKENS = 12_288
JUDGE_EXPECTED_OUTPUT_TOKENS = 256
JUDGE_MAX_OUTPUT_TOKENS = 512
JUDGE_MODEL = "claude-haiku-4-5-20251001"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MONEY = re.compile(r"\$(0|[1-9][0-9]*)(?:\.([0-9]{1,2}))?")

ROUTES: tuple[dict[str, Any], ...] = (
    {
        "label": "GPT-6 Astra",
        "spec": "openai:gpt-6-astra",
        "provider": "openai",
        "model": "gpt-6-astra",
        "call_cap": 30,
        "max_output_tokens": 8_192,
    },
    {
        "label": "Claude Fable 5.1",
        "spec": AnthropicFableTarget.FABLE_51_SPEC,
        "provider": "anthropic",
        "model": "claude-fable-5-1",
        "call_cap": 30,
        "max_output_tokens": 8_192,
        "inherent_config": True,
    },
    {
        "label": "Claude Opus 5",
        "spec": "anthropic:claude-opus-5",
        "provider": "anthropic",
        "model": "claude-opus-5",
        "call_cap": 80,
        "max_output_tokens": 6_144,
    },
    {
        "label": "Claude Sonnet 5",
        "spec": "anthropic:claude-sonnet-5",
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "call_cap": 150,
        "max_output_tokens": 4_096,
    },
    {
        "label": "Claude Haiku 4.5",
        "spec": "anthropic:claude-haiku-4-5-20251001",
        "provider": "anthropic",
        "model": JUDGE_MODEL,
        "call_cap": 200,
        "max_output_tokens": 2_048,
    },
    {
        "label": "GPT-5.6 Sol",
        "spec": OpenAIResponsesTarget.OUTPUT_8192_SPEC,
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "call_cap": 30,
        "max_output_tokens": 8_192,
        "inherent_config": True,
    },
    {
        "label": "GPT-5.6 Terra",
        "spec": "openai:gpt-5.6-terra",
        "provider": "openai",
        "model": "gpt-5.6-terra",
        "call_cap": 30,
        "max_output_tokens": 6_144,
    },
    {
        "label": "GPT-5.6 Luna",
        "spec": "openai:gpt-5.6-luna",
        "provider": "openai",
        "model": "gpt-5.6-luna",
        "call_cap": 150,
        "max_output_tokens": 4_096,
    },
    {
        "label": "GPT-5.5",
        "spec": "openai:gpt-5.5",
        "provider": "openai",
        "model": "gpt-5.5",
        "call_cap": 30,
        "max_output_tokens": 8_192,
    },
    {
        "label": "Kimi K3",
        "spec": "kimi:kimi-k3",
        "provider": "kimi",
        "model": "kimi-k3",
        "call_cap": 80,
        "max_output_tokens": 8_192,
        "reasoning_effort": "low",
    },
    {
        "label": "DeepSeek V4-Pro",
        "spec": "deepseek:deepseek-v4-pro",
        "provider": "deepseek",
        "model": "deepseek-v4-pro",
        "call_cap": 200,
        "max_output_tokens": 8_192,
        # The registry price is the published off-peak rate. Reserve every
        # selected call at the published 2x peak tariff instead of depending
        # on a dispatch-time clock window.
        "reservation_rate_multiplier": 2,
        "reservation_price_condition": "published_peak",
    },
)
HOSTED_TARGET_CALL_CAP = sum(int(route["call_cap"]) for route in ROUTES)
JUDGE_PAIR_CAP = HOSTED_TARGET_CALL_CAP
JUDGE_CALL_CAP = 2 * JUDGE_PAIR_CAP


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in items:
        if key in value:
            raise ValueError(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def load_bound_json(path_value: Path, expected_sha256: str, *, expect_list: bool = False) -> tuple[Any, dict]:
    if _HEX64.fullmatch(expected_sha256) is None:
        raise ValueError("input SHA-256 must be 64 lowercase hex")
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError("budget input must be a regular non-symlink file")
    path = unresolved.resolve(strict=True)
    before = path.stat()
    if not path.is_file() or not 0 < before.st_size <= 16 * 1024 * 1024:
        raise ValueError("budget input must be a regular file of at most 16 MiB")
    payload = path.read_bytes()
    after = path.stat()
    observed = hashlib.sha256(payload).hexdigest()
    if (
        (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or len(payload) != before.st_size
        or observed != expected_sha256
    ):
        raise ValueError("budget input identity or bytes changed")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("budget input is not strict UTF-8 JSON") from exc
    if not isinstance(value, list if expect_list else dict):
        raise ValueError("budget input must be a JSON " + ("list" if expect_list else "object"))
    return value, {"file": path.name, "sha256": observed, "bytes": len(payload)}


def _decimal(value: object, *, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a finite nonnegative number")
    try:
        result = Decimal(str(value))
    except InvalidOperation as exc:
        raise ValueError(f"{label} must be a finite nonnegative number") from exc
    if not result.is_finite() or result < 0:
        raise ValueError(f"{label} must be a finite nonnegative number")
    return result


def _cost_microusd(
    *, calls: int, input_tokens: int, output_tokens: int,
    input_rate: Decimal, output_rate: Decimal,
) -> int:
    value = Decimal(calls) * (
        Decimal(input_tokens) * input_rate
        + Decimal(output_tokens) * output_rate
    )
    # Valid tariffs and odd-sized subsets can produce fractional microdollars.
    # Reserve upward; projections that were already integral stay unchanged.
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _budget_microusd(value: object) -> int:
    if not isinstance(value, str):
        raise ValueError("provider prepaid budget must use '$N' notation")
    match = _MONEY.fullmatch(value)
    if match is None:
        raise ValueError("provider prepaid budget must use '$N' notation")
    cents = (match.group(2) or "").ljust(2, "0")
    return int(match.group(1)) * 1_000_000 + int(cents) * 10_000


def _provider_budgets(value: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    rows = value.get("providers")
    if not isinstance(rows, list):
        raise ValueError("budget registry providers must be a list")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("budget provider entry must be an object")
        provider = row.get("match")
        if not isinstance(provider, str) or not provider.strip() or provider in result:
            raise ValueError("budget provider matches must be unique non-blank strings")
        configured = _budget_microusd(row.get("prepaid"))
        result[provider] = {
            "display_name": row.get("name"),
            "configured_budget_microusd": configured,
            "campaign_cap_microusd": configured * 4 // 5,
        }
    return result


def _route_config(route: Mapping[str, Any], api_config: Mapping[str, Any]) -> None:
    config = api_config.get(route["spec"])
    if not isinstance(config, Mapping):
        raise ValueError(f"API target config lacks {route['spec']!r}")
    modalities = config.get("modalities")
    if not isinstance(modalities, list) or not modalities or any(
        not isinstance(item, str) or not item for item in modalities
    ):
        raise ValueError(f"API target config has invalid modalities for {route['spec']!r}")
    if not route.get("inherent_config") and (
        config.get("max_tokens") != route["max_output_tokens"]
    ):
        raise ValueError(f"API target max_tokens changed for {route['spec']!r}")
    if "reasoning_effort" in route and config.get("reasoning_effort") != route["reasoning_effort"]:
        raise ValueError(f"API target reasoning_effort changed for {route['spec']!r}")


def _priced_row(
    route: Mapping[str, Any], *, pricing: Mapping[str, Any], as_of: str
) -> dict[str, Any]:
    rate, why = rate_for(
        pricing, str(route["provider"]), str(route["model"]), on_date=as_of
    )
    if rate is None:
        raise ValueError(f"price unavailable for {route['label']}: {why}")
    per_million = rate.get("per_million_tokens")
    if rate.get("currency") != "USD" or not isinstance(per_million, Mapping):
        raise ValueError(f"price for {route['label']} must be in USD")
    input_rate = _decimal(per_million.get("input"), label="input price")
    output_rate = _decimal(per_million.get("output"), label="output price")
    # Reserve a cold cache write for OpenAI even when the average estimate
    # assumes ordinary uncached input. Published new-model writes cost 1.25x;
    # using that bound for older OpenAI routes leaves additional headroom.
    multiplier = _decimal(route.get("reservation_rate_multiplier", 1),
                          label="reservation rate multiplier")
    if multiplier < 1:
        raise ValueError(f"reservation rate multiplier is invalid for {route['label']}")
    reserved_input_rate = input_rate * multiplier
    reserved_output_rate = output_rate * multiplier
    if route["provider"] == "openai":
        reserved_input_rate *= Decimal("1.25")
    if route["provider"] == "openai" and per_million.get("cache_write") is not None:
        reserved_input_rate = max(
            reserved_input_rate,
            _decimal(per_million["cache_write"], label="cache-write price"),
        )
    calls = int(route["call_cap"])
    maximum_output = int(route["max_output_tokens"])
    expected_output = maximum_output // 4
    return {
        "label": route["label"],
        "target_spec": route["spec"],
        "provider": route["provider"],
        "model": route["model"],
        **({"reasoning_effort": route["reasoning_effort"]}
           if "reasoning_effort" in route else {}),
        "paid_call_cap": calls,
        "paid_call_cap_includes_readiness_and_canaries": True,
        "answer_retries": 0,
        "transport_retries": DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        "maximum_http_attempts": calls * (DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1),
        "expected_input_tokens_per_call": EXPECTED_INPUT_TOKENS,
        "maximum_input_tokens_per_call": MAX_INPUT_TOKENS,
        **({"maximum_priced_input_tokens": route["maximum_priced_input_tokens"]}
           if "maximum_priced_input_tokens" in route else {}),
        "expected_output_tokens_per_call": expected_output,
        "maximum_output_tokens_per_call": maximum_output,
        "expected_total_input_tokens": calls * EXPECTED_INPUT_TOKENS,
        "maximum_total_input_tokens": calls * MAX_INPUT_TOKENS,
        "expected_total_output_tokens": calls * expected_output,
        "maximum_total_output_tokens": calls * maximum_output,
        "input_usd_per_million_tokens": str(input_rate),
        "reserved_input_usd_per_million_tokens": str(reserved_input_rate),
        "reserved_output_usd_per_million_tokens": str(reserved_output_rate),
        "reservation_price_condition": route.get("reservation_price_condition", "listed_rate"),
        "output_usd_per_million_tokens": str(output_rate),
        "pricing_effective_date": rate["effective_date"],
        "expected_cost_microusd": _cost_microusd(
            calls=calls,
            input_tokens=EXPECTED_INPUT_TOKENS,
            output_tokens=expected_output,
            input_rate=input_rate,
            output_rate=output_rate,
        ),
        "maximum_cost_microusd": _cost_microusd(
            calls=calls,
            input_tokens=MAX_INPUT_TOKENS,
            output_tokens=maximum_output,
            input_rate=reserved_input_rate,
            output_rate=reserved_output_rate,
        ),
    }


def build_projection(
    *,
    api_config: Mapping[str, Any],
    pricing: Mapping[str, Any],
    budgets: Mapping[str, Any],
    descriptors: Mapping[str, Mapping[str, Any]],
    pricing_as_of: str,
    route_configuration: Sequence[Mapping[str, Any]] | None = None,
    reservation_policy: str = "first_attempts_upfront",
) -> dict[str, Any]:
    if reservation_policy not in {"first_attempts_upfront", "per_attempt"}:
        raise ValueError("unknown hosted reservation policy")
    routes = ROUTES if route_configuration is None else route_configuration
    if route_configuration is not None:
        required = {"label", "spec", "provider", "model", "call_cap", "max_output_tokens"}
        optional = {"reasoning_effort", "maximum_priced_input_tokens",
                    "reservation_rate_multiplier", "reservation_price_condition", "inherent_config"}
        if not isinstance(routes, (list, tuple)) or not routes:
            raise ValueError("configured routes must be a nonempty list")
        seen = set()
        for route in routes:
            inherent = isinstance(route, Mapping) and route.get("inherent_config") is True
            fixed = next((row for row in ROUTES if row.get("inherent_config") is True
                          and isinstance(route, Mapping) and row["spec"] == route.get("spec")), None)
            fixed_identity = inherent and fixed is not None and all(
                route.get(key) == fixed[key] for key in ("spec", "provider", "model", "max_output_tokens"))
            if (not isinstance(route, Mapping) or not required <= set(route) <= required | optional
                or any(not isinstance(route[k], str) or not route[k].strip()
                       for k in ("label", "spec", "provider", "model"))
                or (not fixed_identity and route["spec"] != route["provider"] + ":" + route["model"])
                or ("inherent_config" in route and not fixed_identity)
                or route["spec"] in seen
                or any(type(route[k]) is not int or route[k] <= 0 for k in
                       ("call_cap", "max_output_tokens"))
                or ("maximum_priced_input_tokens" in route and
                    (type(route["maximum_priced_input_tokens"]) is not int or route["maximum_priced_input_tokens"] <= 0))
                or ("reservation_price_condition" in route and
                    route["reservation_price_condition"] not in {"published_peak", "configured_effective_date"})):
                raise ValueError("configured route identity, limits or fields differ")
            seen.add(route["spec"])
    judge_call_cap = JUDGE_CALL_CAP if route_configuration is None else 2 * sum(route["call_cap"] for route in routes)
    if pricing.get("schema") != "ura-console-pricing/1":
        raise ValueError("pricing config schema changed")
    try:
        __import__("datetime").date.fromisoformat(pricing_as_of)
    except (TypeError, ValueError) as exc:
        raise ValueError("pricing as-of date must be ISO YYYY-MM-DD") from exc
    for route in routes:
        _route_config(route, api_config)
    rows = [
        _priced_row(route, pricing=pricing, as_of=pricing_as_of) for route in routes
    ]
    budget_rows = _provider_budgets(budgets)
    haiku = next((row for row in rows if row["model"] == JUDGE_MODEL), None)
    if haiku is None:
        haiku = _priced_row({"label": "Haiku judge", "spec": "anthropic:" + JUDGE_MODEL,
                            "provider": "anthropic", "model": JUDGE_MODEL,
                            "call_cap": judge_call_cap, "max_output_tokens": JUDGE_MAX_OUTPUT_TOKENS},
                           pricing=pricing, as_of=pricing_as_of)
    judge_input_rate = Decimal(haiku["input_usd_per_million_tokens"])
    judge_output_rate = Decimal(haiku["output_usd_per_million_tokens"])
    judge = {
        "provider": "anthropic",
        "model": JUDGE_MODEL,
        "paid_call_cap": judge_call_cap,
        "selected_pair_cap": judge_call_cap // 2,
        "target_calls": 0,
        "answer_retries": 0,
        "transport_retries": DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
        "maximum_http_attempts": judge_call_cap
        * (DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1),
        "expected_input_tokens_per_call": JUDGE_EXPECTED_INPUT_TOKENS,
        "maximum_input_tokens_per_call": JUDGE_MAX_INPUT_TOKENS,
        "expected_output_tokens_per_call": JUDGE_EXPECTED_OUTPUT_TOKENS,
        "maximum_output_tokens_per_call": JUDGE_MAX_OUTPUT_TOKENS,
        "expected_total_input_tokens": judge_call_cap * JUDGE_EXPECTED_INPUT_TOKENS,
        "maximum_total_input_tokens": judge_call_cap * JUDGE_MAX_INPUT_TOKENS,
        "expected_total_output_tokens": judge_call_cap * JUDGE_EXPECTED_OUTPUT_TOKENS,
        "maximum_total_output_tokens": judge_call_cap * JUDGE_MAX_OUTPUT_TOKENS,
        "input_usd_per_million_tokens": str(judge_input_rate),
        "output_usd_per_million_tokens": str(judge_output_rate),
        "expected_cost_microusd": _cost_microusd(
            calls=judge_call_cap,
            input_tokens=JUDGE_EXPECTED_INPUT_TOKENS,
            output_tokens=JUDGE_EXPECTED_OUTPUT_TOKENS,
            input_rate=judge_input_rate,
            output_rate=judge_output_rate,
        ),
        "maximum_cost_microusd": _cost_microusd(
            calls=judge_call_cap,
            input_tokens=JUDGE_MAX_INPUT_TOKENS,
            output_tokens=JUDGE_MAX_OUTPUT_TOKENS,
            input_rate=judge_input_rate,
            output_rate=judge_output_rate,
        ),
    }
    providers: list[dict[str, Any]] = []
    for provider in sorted({str(row["provider"]) for row in rows} | {"anthropic"}):
        budget = budget_rows.get(provider)
        if budget is None:
            raise ValueError(f"configured budget is unavailable for {provider!r}")
        selected = [row for row in rows if row["provider"] == provider]
        target_expected = sum(int(row["expected_cost_microusd"]) for row in selected)
        target_maximum = sum(int(row["maximum_cost_microusd"]) for row in selected)
        judge_expected = int(judge["expected_cost_microusd"]) if provider == "anthropic" else 0
        judge_maximum = int(judge["maximum_cost_microusd"]) if provider == "anthropic" else 0
        combined_maximum = target_maximum + judge_maximum
        cap = int(budget["campaign_cap_microusd"])
        providers.append(
            {
                "provider": provider,
                **budget,
                "target_expected_cost_microusd": target_expected,
                "target_maximum_cost_microusd": target_maximum,
                "judge_expected_cost_microusd": judge_expected,
                "judge_maximum_cost_microusd": judge_maximum,
                "combined_maximum_cost_microusd": combined_maximum,
                "remaining_margin_microusd": cap - combined_maximum,
                "fits_campaign_cap": combined_maximum <= cap,
            }
        )
    target_expected = sum(int(row["expected_cost_microusd"]) for row in rows)
    target_maximum = sum(int(row["maximum_cost_microusd"]) for row in rows)
    target_expected_input = sum(
        int(row["expected_total_input_tokens"]) for row in rows
    )
    target_maximum_input = sum(
        int(row["maximum_total_input_tokens"]) for row in rows
    )
    target_expected_output = sum(
        int(row["expected_total_output_tokens"]) for row in rows
    )
    target_maximum_output = sum(
        int(row["maximum_total_output_tokens"]) for row in rows
    )
    value: dict[str, Any] = {
        "schema": (CONTINUOUS_SCHEMA if reservation_policy == "per_attempt" else
                   SCHEMA if route_configuration is None else CONFIGURED_SCHEMA),
        **({"reservation_policy": "per_attempt"} if reservation_policy == "per_attempt" else {}),
        **({"route_configuration": [dict(route) for route in routes]} if route_configuration is not None else {}),
        "status": (
            "per_attempt_budgeted" if reservation_policy == "per_attempt" else
            "budget_fit" if all(row["fits_campaign_cap"] for row in providers)
            else "blocked_budget"
        ),
        "authority": {
            "provider_calls_made": 0,
            "target_answer_retries": 0,
            "provider_transport_retries": DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
            "transport_retry_trigger": "retryable_http_status_only",
            "paid_target_call_cap_includes_readiness_and_canaries": True,
            "pricing_as_of": pricing_as_of,
            "budget_fraction_numerator": 4,
            "budget_fraction_denominator": 5,
            "expected_cost_basis": "uncalibrated_quarter_cap_output_scenario",
            "judge_input_includes_prompt_answer_and_rubric": True,
            "physical_media_sent_to_judge": False,
            "exact_provider_input_token_counts_required_before_spend": True,
        },
        "sources": {key: dict(value) for key, value in sorted(descriptors.items())},
        "routes": rows,
        "judge": judge,
        "providers": providers,
        "totals": {
            "target_paid_call_cap": sum(int(row["paid_call_cap"]) for row in rows),
            "judge_paid_call_cap": judge_call_cap,
            "target_expected_input_tokens": target_expected_input,
            "target_maximum_input_tokens": target_maximum_input,
            "target_expected_output_tokens": target_expected_output,
            "target_maximum_output_tokens": target_maximum_output,
            "judge_expected_input_tokens": judge["expected_total_input_tokens"],
            "judge_maximum_input_tokens": judge["maximum_total_input_tokens"],
            "judge_expected_output_tokens": judge["expected_total_output_tokens"],
            "judge_maximum_output_tokens": judge["maximum_total_output_tokens"],
            "combined_expected_input_tokens": (
                target_expected_input + int(judge["expected_total_input_tokens"])
            ),
            "combined_maximum_input_tokens": (
                target_maximum_input + int(judge["maximum_total_input_tokens"])
            ),
            "combined_expected_output_tokens": (
                target_expected_output + int(judge["expected_total_output_tokens"])
            ),
            "combined_maximum_output_tokens": (
                target_maximum_output + int(judge["maximum_total_output_tokens"])
            ),
            "target_expected_cost_microusd": target_expected,
            "target_maximum_cost_microusd": target_maximum,
            "judge_expected_cost_microusd": judge["expected_cost_microusd"],
            "judge_maximum_cost_microusd": judge["maximum_cost_microusd"],
            "combined_expected_cost_microusd": (
                target_expected + int(judge["expected_cost_microusd"])
            ),
            "combined_maximum_cost_microusd": (
                target_maximum + int(judge["maximum_cost_microusd"])
            ),
        },
    }
    value["projection_id"] = "hosted-budget-" + _sha(value)[:24]
    return value


def admissible_projection(value: Mapping[str, Any]) -> bool:
    """A queued inventory is not a promise that every maximum fits upfront."""
    if value.get("schema") == CONTINUOUS_SCHEMA:
        return (value.get("reservation_policy") == "per_attempt"
                and value.get("status") == "per_attempt_budgeted")
    return (value.get("schema") in {SCHEMA, CONFIGURED_SCHEMA}
            and "reservation_policy" not in value and value.get("status") == "budget_fit")


def _write_new(path_value: Path, value: object) -> Path:
    path = Path(path_value)
    if path.exists() or path.is_symlink():
        raise ValueError("hosted budget projection output must be create-only")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_canonical(value))
        handle.flush()
        os.fsync(handle.fileno())
    return path.resolve(strict=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-config", type=Path, required=True)
    parser.add_argument("--api-config-sha256", required=True)
    parser.add_argument("--pricing-config", type=Path, required=True)
    parser.add_argument("--pricing-config-sha256", required=True)
    parser.add_argument("--budgets", type=Path, required=True)
    parser.add_argument("--budgets-sha256", required=True)
    parser.add_argument("--pricing-as-of", required=True)
    parser.add_argument("--route-configuration", type=Path)
    parser.add_argument("--route-configuration-sha256")
    parser.add_argument("--reservation-policy", choices=("first_attempts_upfront", "per_attempt"),
                        default="first_attempts_upfront",
                        help="Queue the full inventory and reserve money before each attempt, or reserve all first attempts upfront")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    api_config, api_descriptor = load_bound_json(
        args.api_config, args.api_config_sha256
    )
    pricing, pricing_descriptor = load_bound_json(
        args.pricing_config, args.pricing_config_sha256
    )
    budgets, budget_descriptor = load_bound_json(args.budgets, args.budgets_sha256)
    routes = None
    if bool(args.route_configuration) != bool(args.route_configuration_sha256):
        parser.error("route configuration requires its SHA-256")
    if args.route_configuration:
        routes, _ = load_bound_json(args.route_configuration, args.route_configuration_sha256, expect_list=True)
    projection = build_projection(
        api_config=api_config,
        pricing=pricing,
        budgets=budgets,
        descriptors={
            "api_config": api_descriptor,
            "pricing_config": pricing_descriptor,
            "budgets": budget_descriptor,
        },
        pricing_as_of=args.pricing_as_of,
        route_configuration=routes,
        reservation_policy=args.reservation_policy,
    )
    print(_write_new(args.out, projection))
    return 0 if admissible_projection(projection) else 2


if __name__ == "__main__":
    raise SystemExit(main())
