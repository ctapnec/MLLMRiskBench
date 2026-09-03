from __future__ import annotations

import copy

import pytest

from experiments import hosted_campaign_budget as subject


def _api_config() -> dict:
    result: dict = {}
    for route in subject.ROUTES:
        result[route["spec"]] = {"modalities": ["text"]}
        if not route.get("inherent_config"):
            result[route["spec"]]["max_tokens"] = route["max_output_tokens"]
    return result


def _pricing() -> dict:
    rates = {
        ("anthropic", "claude-fable-5"): (10, 50),
        ("anthropic", "claude-opus-5"): (5, 25),
        ("anthropic", "claude-sonnet-5"): (2, 10),
        ("anthropic", subject.JUDGE_MODEL): (1, 5),
        ("openai", "gpt-5.6-sol"): (4, 20),
        ("openai", "gpt-5.6-terra"): (2, 12),
        ("openai", "gpt-5.6-luna"): (0.2, 1.2),
        ("openai", "gpt-5.5"): (5, 30),
        ("kimi", "kimi-k3"): (3, 15),
        ("deepseek", "deepseek-v4-pro"): (0.66, 1.98),
    }
    providers: dict = {}
    for (provider, model), (input_rate, output_rate) in rates.items():
        providers.setdefault(provider, {"models": {}})["models"][model] = {
            "rates": [
                {
                    "currency": "USD",
                    "effective_date": "2026-09-03",
                    "per_million_tokens": {
                        "input": input_rate,
                        "output": output_rate,
                    },
                }
            ]
        }
    return {"schema": "ura-console-pricing/1", "providers": providers}


def _budgets() -> dict:
    return {
        "providers": [
            {"name": "Anthropic", "match": "anthropic", "prepaid": "$100"},
            {"name": "OpenAI", "match": "openai", "prepaid": "$40"},
            {"name": "Moonshot", "match": "kimi", "prepaid": "$15"},
            {"name": "DeepSeek", "match": "deepseek", "prepaid": "$10"},
        ]
    }


def _projection(**changes) -> dict:
    values = {
        "api_config": _api_config(),
        "pricing": _pricing(),
        "budgets": _budgets(),
        "descriptors": {
            "api_config": {"file": "api.json", "sha256": "a" * 64, "bytes": 1},
            "pricing_config": {
                "file": "pricing.json", "sha256": "b" * 64, "bytes": 1,
            },
            "budgets": {"file": "budgets.json", "sha256": "c" * 64, "bytes": 1},
        },
        "pricing_as_of": "2026-09-03",
    }
    values.update(changes)
    return subject.build_projection(**values)


def test_projection_binds_expected_and_maximum_token_costs() -> None:
    value = _projection()

    assert value["status"] == "budget_fit"
    assert value["totals"] == {
        "target_paid_call_cap": 590,
        "judge_paid_call_cap": 1_180,
        "target_expected_input_tokens": 2_360_000,
        "target_maximum_input_tokens": 2_360_000,
        "target_expected_output_tokens": 295_000,
        "target_maximum_output_tokens": 2_420_880,
        "judge_expected_input_tokens": 4_720_000,
        "judge_maximum_input_tokens": 4_720_000,
        "judge_expected_output_tokens": 590_000,
        "judge_maximum_output_tokens": 604_160,
        "combined_expected_input_tokens": 7_080_000,
        "combined_maximum_input_tokens": 7_080_000,
        "combined_expected_output_tokens": 885_000,
        "combined_maximum_output_tokens": 3_025_040,
        "target_expected_cost_microusd": 8_313_000,
        "target_maximum_cost_microusd": 38_547_568,
        "judge_expected_cost_microusd": 7_670_000,
        "judge_maximum_cost_microusd": 7_740_800,
        "combined_expected_cost_microusd": 15_983_000,
        "combined_maximum_cost_microusd": 46_288_368,
    }
    sonnet = next(row for row in value["routes"] if row["label"] == "Claude Sonnet 5")
    assert sonnet["expected_cost_microusd"] == 650_000
    assert sonnet["maximum_cost_microusd"] == 2_448_000
    assert all(row["paid_call_cap_includes_readiness_and_canaries"] for row in value["routes"])
    assert value["judge"]["maximum_output_tokens_per_call"] == 512
    assert value["judge"]["selected_pair_cap"] == 590
    assert all(row["fits_campaign_cap"] for row in value["providers"])


def test_api_config_maximum_is_not_a_prose_only_assumption() -> None:
    config = _api_config()
    config["openai:gpt-5.5"]["max_tokens"] = 25_000

    with pytest.raises(ValueError, match="max_tokens changed"):
        _projection(api_config=config)


def test_missing_or_non_usd_price_blocks_projection() -> None:
    pricing = _pricing()
    pricing["providers"]["kimi"]["models"]["kimi-k3"]["rates"][0][
        "currency"
    ] = "EUR"

    with pytest.raises(ValueError, match="must be in USD"):
        _projection(pricing=pricing)


def test_half_budget_failure_is_explicit() -> None:
    budgets = copy.deepcopy(_budgets())
    next(row for row in budgets["providers"] if row["match"] == "openai")[
        "prepaid"
    ] = "$20"

    value = _projection(budgets=budgets)

    assert value["status"] == "blocked_budget"
    openai = next(row for row in value["providers"] if row["provider"] == "openai")
    assert openai["fits_campaign_cap"] is False
    assert openai["remaining_margin_microusd"] < 0


def test_projection_is_deterministic_and_signed() -> None:
    first = _projection()
    second = _projection()

    assert first == second
    material = dict(first)
    projection_id = material.pop("projection_id")
    assert projection_id == "hosted-budget-" + subject._sha(material)[:24]
