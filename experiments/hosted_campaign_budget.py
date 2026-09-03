"""Create a no-call budget projection for the fixed hosted follow-on cohort.

The projection reads the exact API target, effective-dated pricing, and budget
registries. It distinguishes the 4,000-input/500-output planning average from
the reservation obtained when every response consumes its configured maximum.
It never constructs a target or judge and never reads credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from experiments.rig_web_app.reports import rate_for
from ura.targets.api import AnthropicFableTarget, OpenAIResponsesTarget


SCHEMA = "ura-hosted-campaign-budget-projection/1"
EXPECTED_INPUT_TOKENS = 4_000
MAX_INPUT_TOKENS = 4_000
EXPECTED_OUTPUT_TOKENS = 500
JUDGE_MAX_OUTPUT_TOKENS = 512
JUDGE_CALL_CAP = 4_000
JUDGE_MODEL = "claude-haiku-4-5-20251001"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MONEY = re.compile(r"\$(0|[1-9][0-9]*)(?:\.([0-9]{1,2}))?")

ROUTES: tuple[dict[str, Any], ...] = (
    {
        "label": "Claude Fable 5",
        "spec": AnthropicFableTarget.name,
        "provider": "anthropic",
        "model": "claude-fable-5",
        "call_cap": 5,
        "max_output_tokens": AnthropicFableTarget.MAX_TOKENS,
        "inherent_config": True,
    },
    {
        "label": "Claude Opus 5",
        "spec": "anthropic:claude-opus-5",
        "provider": "anthropic",
        "model": "claude-opus-5",
        "call_cap": 10,
        "max_output_tokens": 4_096,
    },
    {
        "label": "Claude Sonnet 5",
        "spec": "anthropic:claude-sonnet-5",
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "call_cap": 50,
        "max_output_tokens": 4_096,
    },
    {
        "label": "Claude Haiku 4.5",
        "spec": "anthropic:claude-haiku-4-5-20251001",
        "provider": "anthropic",
        "model": JUDGE_MODEL,
        "call_cap": 100,
        "max_output_tokens": 2_048,
    },
    {
        "label": "GPT-5.6 Sol",
        "spec": OpenAIResponsesTarget.name,
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "call_cap": 5,
        "max_output_tokens": OpenAIResponsesTarget.MAX_OUTPUT_TOKENS,
        "inherent_config": True,
    },
    {
        "label": "GPT-5.6 Terra",
        "spec": "openai:gpt-5.6-terra",
        "provider": "openai",
        "model": "gpt-5.6-terra",
        "call_cap": 20,
        "max_output_tokens": 4_096,
    },
    {
        "label": "GPT-5.6 Luna",
        "spec": "openai:gpt-5.6-luna",
        "provider": "openai",
        "model": "gpt-5.6-luna",
        "call_cap": 100,
        "max_output_tokens": 4_096,
    },
    {
        "label": "GPT-5.5",
        "spec": "openai:gpt-5.5",
        "provider": "openai",
        "model": "gpt-5.5",
        "call_cap": 100,
        "max_output_tokens": 4_096,
    },
    {
        "label": "Kimi K3",
        "spec": "kimi:kimi-k3",
        "provider": "kimi",
        "model": "kimi-k3",
        "call_cap": 100,
        "max_output_tokens": 4_096,
    },
    {
        "label": "DeepSeek V4-Pro",
        "spec": "deepseek:deepseek-v4-pro",
        "provider": "deepseek",
        "model": "deepseek-v4-pro",
        "call_cap": 100,
        "max_output_tokens": 4_096,
    },
)


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


def load_bound_json(path_value: Path, expected_sha256: str) -> tuple[dict, dict]:
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
    if not isinstance(value, dict):
        raise ValueError("budget input must be a JSON object")
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
    if value != value.to_integral_value():
        raise ValueError("projection cost is not an integral number of micro-USD")
    return int(value)


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
            "campaign_cap_microusd": configured // 2,
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
    calls = int(route["call_cap"])
    maximum_output = int(route["max_output_tokens"])
    return {
        "label": route["label"],
        "target_spec": route["spec"],
        "provider": route["provider"],
        "model": route["model"],
        "paid_call_cap": calls,
        "paid_call_cap_includes_readiness_and_canaries": True,
        "answer_retries": 0,
        "transport_retries": 0,
        "expected_input_tokens_per_call": EXPECTED_INPUT_TOKENS,
        "maximum_input_tokens_per_call": MAX_INPUT_TOKENS,
        "expected_output_tokens_per_call": EXPECTED_OUTPUT_TOKENS,
        "maximum_output_tokens_per_call": maximum_output,
        "expected_total_input_tokens": calls * EXPECTED_INPUT_TOKENS,
        "maximum_total_input_tokens": calls * MAX_INPUT_TOKENS,
        "expected_total_output_tokens": calls * EXPECTED_OUTPUT_TOKENS,
        "maximum_total_output_tokens": calls * maximum_output,
        "input_usd_per_million_tokens": str(input_rate),
        "output_usd_per_million_tokens": str(output_rate),
        "pricing_effective_date": rate["effective_date"],
        "expected_cost_microusd": _cost_microusd(
            calls=calls,
            input_tokens=EXPECTED_INPUT_TOKENS,
            output_tokens=EXPECTED_OUTPUT_TOKENS,
            input_rate=input_rate,
            output_rate=output_rate,
        ),
        "maximum_cost_microusd": _cost_microusd(
            calls=calls,
            input_tokens=MAX_INPUT_TOKENS,
            output_tokens=maximum_output,
            input_rate=input_rate,
            output_rate=output_rate,
        ),
    }


def build_projection(
    *,
    api_config: Mapping[str, Any],
    pricing: Mapping[str, Any],
    budgets: Mapping[str, Any],
    descriptors: Mapping[str, Mapping[str, Any]],
    pricing_as_of: str,
) -> dict[str, Any]:
    if pricing.get("schema") != "ura-console-pricing/1":
        raise ValueError("pricing config schema changed")
    try:
        __import__("datetime").date.fromisoformat(pricing_as_of)
    except (TypeError, ValueError) as exc:
        raise ValueError("pricing as-of date must be ISO YYYY-MM-DD") from exc
    for route in ROUTES:
        _route_config(route, api_config)
    rows = [
        _priced_row(route, pricing=pricing, as_of=pricing_as_of) for route in ROUTES
    ]
    budget_rows = _provider_budgets(budgets)
    haiku = next(row for row in rows if row["model"] == JUDGE_MODEL)
    judge_input_rate = Decimal(haiku["input_usd_per_million_tokens"])
    judge_output_rate = Decimal(haiku["output_usd_per_million_tokens"])
    judge = {
        "provider": "anthropic",
        "model": JUDGE_MODEL,
        "paid_call_cap": JUDGE_CALL_CAP,
        "selected_pair_cap": JUDGE_CALL_CAP // 2,
        "target_calls": 0,
        "answer_retries": 0,
        "transport_retries": 0,
        "expected_input_tokens_per_call": EXPECTED_INPUT_TOKENS,
        "maximum_input_tokens_per_call": MAX_INPUT_TOKENS,
        "expected_output_tokens_per_call": EXPECTED_OUTPUT_TOKENS,
        "maximum_output_tokens_per_call": JUDGE_MAX_OUTPUT_TOKENS,
        "expected_total_input_tokens": JUDGE_CALL_CAP * EXPECTED_INPUT_TOKENS,
        "maximum_total_input_tokens": JUDGE_CALL_CAP * MAX_INPUT_TOKENS,
        "expected_total_output_tokens": JUDGE_CALL_CAP * EXPECTED_OUTPUT_TOKENS,
        "maximum_total_output_tokens": JUDGE_CALL_CAP * JUDGE_MAX_OUTPUT_TOKENS,
        "input_usd_per_million_tokens": str(judge_input_rate),
        "output_usd_per_million_tokens": str(judge_output_rate),
        "expected_cost_microusd": _cost_microusd(
            calls=JUDGE_CALL_CAP,
            input_tokens=EXPECTED_INPUT_TOKENS,
            output_tokens=EXPECTED_OUTPUT_TOKENS,
            input_rate=judge_input_rate,
            output_rate=judge_output_rate,
        ),
        "maximum_cost_microusd": _cost_microusd(
            calls=JUDGE_CALL_CAP,
            input_tokens=MAX_INPUT_TOKENS,
            output_tokens=JUDGE_MAX_OUTPUT_TOKENS,
            input_rate=judge_input_rate,
            output_rate=judge_output_rate,
        ),
    }
    providers: list[dict[str, Any]] = []
    for provider in sorted({str(row["provider"]) for row in rows}):
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
        "schema": SCHEMA,
        "status": (
            "budget_fit" if all(row["fits_campaign_cap"] for row in providers)
            else "blocked_budget"
        ),
        "authority": {
            "provider_calls_made": 0,
            "target_answer_retries": 0,
            "provider_transport_retries": 0,
            "paid_target_call_cap_includes_readiness_and_canaries": True,
            "pricing_as_of": pricing_as_of,
            "budget_fraction_numerator": 1,
            "budget_fraction_denominator": 2,
        },
        "sources": {key: dict(value) for key, value in sorted(descriptors.items())},
        "routes": rows,
        "judge": judge,
        "providers": providers,
        "totals": {
            "target_paid_call_cap": sum(int(row["paid_call_cap"]) for row in rows),
            "judge_paid_call_cap": JUDGE_CALL_CAP,
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
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    api_config, api_descriptor = load_bound_json(
        args.api_config, args.api_config_sha256
    )
    pricing, pricing_descriptor = load_bound_json(
        args.pricing_config, args.pricing_config_sha256
    )
    budgets, budget_descriptor = load_bound_json(args.budgets, args.budgets_sha256)
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
    )
    print(_write_new(args.out, projection))
    return 0 if projection["status"] == "budget_fit" else 2


if __name__ == "__main__":
    raise SystemExit(main())
