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
        ("openai", "gpt-6-astra"): (10, 50),
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
            {"name": "Anthropic", "match": "anthropic", "prepaid": "$90"},
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
        "target_paid_call_cap": 1_350,
        "judge_paid_call_cap": 2_700,
        "target_expected_input_tokens": 5_400_000,
        "target_maximum_input_tokens": 5_400_000,
        "target_expected_output_tokens": 675_000,
        "target_maximum_output_tokens": 5_120_000,
        "judge_expected_input_tokens": 10_800_000,
        "judge_maximum_input_tokens": 10_800_000,
        "judge_expected_output_tokens": 1_350_000,
        "judge_maximum_output_tokens": 1_382_400,
        "combined_expected_input_tokens": 16_200_000,
        "combined_maximum_input_tokens": 16_200_000,
        "combined_expected_output_tokens": 2_025_000,
        "combined_maximum_output_tokens": 6_502_400,
        "target_expected_cost_microusd": 21_624_000,
        "target_maximum_cost_microusd": 80_435_904,
        "judge_expected_cost_microusd": 17_550_000,
        "judge_maximum_cost_microusd": 17_712_000,
        "combined_expected_cost_microusd": 39_174_000,
        "combined_maximum_cost_microusd": 98_147_904,
    }
    sonnet = next(row for row in value["routes"] if row["label"] == "Claude Sonnet 5")
    assert sonnet["expected_cost_microusd"] == 2_600_000
    assert sonnet["maximum_cost_microusd"] == 9_792_000
    assert sonnet["transport_retries"] == 3
    assert sonnet["maximum_http_attempts"] == 800
    assert all(row["paid_call_cap_includes_readiness_and_canaries"] for row in value["routes"])
    assert value["judge"]["maximum_output_tokens_per_call"] == 512
    assert value["judge"]["transport_retries"] == 3
    assert value["judge"]["maximum_http_attempts"] == 10_800
    assert value["judge"]["selected_pair_cap"] == 1_350
    assert all(row["fits_campaign_cap"] for row in value["providers"])
    astra = next(row for row in value["routes"] if row["model"] == "gpt-6-astra")
    assert astra["maximum_cost_microusd"] == 12_740_000
    assert astra["reserved_input_usd_per_million_tokens"] == "12.50"
    anthropic = next(row for row in value["providers"] if row["provider"] == "anthropic")
    assert anthropic["campaign_cap_microusd"] == 72_000_000


def test_api_config_maximum_is_not_a_prose_only_assumption() -> None:
    config = _api_config()
    config["openai:gpt-5.5"]["max_tokens"] = 25_000

    with pytest.raises(ValueError, match="max_tokens changed"):
        _projection(api_config=config)


def test_new_pair_defaults_match_budget_and_admit_historical_smaller_limits() -> None:
    from experiments import retained_response_judge_pair as pairs

    assert pairs.DEFAULT_PAIR_LIMIT == subject.JUDGE_PAIR_CAP == 1_350
    assert pairs.DEFAULT_COST_MICROUSD == 18_000_000
    assert pairs.MAX_PAIR_LIMIT >= 590
    assert pairs.MAX_COST_MICROUSD >= 7_750_000


def test_higher_published_astra_cache_write_rate_is_reserved() -> None:
    pricing = _pricing()
    pricing["providers"]["openai"]["models"]["gpt-6-astra"]["rates"][0][
        "per_million_tokens"
    ]["cache_write"] = 20
    astra = next(row for row in _projection(pricing=pricing)["routes"]
                 if row["model"] == "gpt-6-astra")
    assert astra["maximum_cost_microusd"] == 14_240_000


def test_missing_or_non_usd_price_blocks_projection() -> None:
    pricing = _pricing()
    pricing["providers"]["kimi"]["models"]["kimi-k3"]["rates"][0][
        "currency"
    ] = "EUR"

    with pytest.raises(ValueError, match="must be in USD"):
        _projection(pricing=pricing)


def test_eighty_percent_budget_failure_is_explicit() -> None:
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
