from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from experiments import hosted_campaign_budget as subject


def _api_config() -> dict:
    result: dict = {}
    for route in subject.ROUTES:
        result[route["spec"]] = {"modalities": ["text"]}
        if not route.get("inherent_config"):
            result[route["spec"]]["max_tokens"] = route["max_output_tokens"]
        if "reasoning_effort" in route:
            result[route["spec"]]["reasoning_effort"] = route["reasoning_effort"]
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
        "target_paid_call_cap": 1_110,
        "judge_paid_call_cap": 2_220,
        "target_expected_input_tokens": 4_440_000,
        "target_maximum_input_tokens": 4_440_000,
        "target_expected_output_tokens": 1_602_560,
        "target_maximum_output_tokens": 6_410_240,
        "judge_expected_input_tokens": 18_186_240,
        "judge_maximum_input_tokens": 27_279_360,
        "judge_expected_output_tokens": 568_320,
        "judge_maximum_output_tokens": 1_136_640,
        "combined_expected_input_tokens": 22_626_240,
        "combined_maximum_input_tokens": 31_719_360,
        "combined_expected_output_tokens": 2_170_880,
        "combined_maximum_output_tokens": 7_546_880,
        "target_expected_cost_microusd": 27_939_392,
        "target_maximum_cost_microusd": 84_841_568,
        "judge_expected_cost_microusd": 21_027_840,
        "judge_maximum_cost_microusd": 32_962_560,
        "combined_expected_cost_microusd": 48_967_232,
        "combined_maximum_cost_microusd": 117_804_128,
    }
    sonnet = next(row for row in value["routes"] if row["label"] == "Claude Sonnet 5")
    assert sonnet["expected_cost_microusd"] == 2_736_000
    assert sonnet["maximum_cost_microusd"] == 7_344_000
    assert sonnet["transport_retries"] == 3
    assert sonnet["maximum_http_attempts"] == 600
    assert all(row["paid_call_cap_includes_readiness_and_canaries"] for row in value["routes"])
    assert value["judge"]["maximum_output_tokens_per_call"] == 512
    assert value["judge"]["transport_retries"] == 3
    assert value["judge"]["maximum_http_attempts"] == 8_880
    assert value["judge"]["selected_pair_cap"] == 1_110
    assert value["judge"]["maximum_input_tokens_per_call"] == 12_288
    assert all(row["fits_campaign_cap"] for row in value["providers"])
    astra = next(row for row in value["routes"] if row["model"] == "gpt-6-astra")
    assert astra["maximum_cost_microusd"] == 13_788_000
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

    assert pairs.DEFAULT_PAIR_LIMIT == subject.JUDGE_PAIR_CAP == 1_110
    assert pairs.DEFAULT_COST_MICROUSD == 33_000_000
    assert pairs.MAX_PAIR_LIMIT >= 1_350
    assert pairs.MAX_COST_MICROUSD >= 7_750_000


def test_higher_published_astra_cache_write_rate_is_reserved() -> None:
    pricing = _pricing()
    pricing["providers"]["openai"]["models"]["gpt-6-astra"]["rates"][0][
        "per_million_tokens"
    ]["cache_write"] = 20
    astra = next(row for row in _projection(pricing=pricing)["routes"]
                 if row["model"] == "gpt-6-astra")
    assert astra["maximum_cost_microusd"] == 14_688_000


def test_real_roster_uses_model_specific_allowances_and_no_uniform_average() -> None:
    path = Path(__file__).resolve().parents[2] / "experiments/rig/api-targets.example.json"
    value = _projection(api_config=json.loads(path.read_text(encoding="utf-8")))
    expected = {
        "gpt-6-astra": (30, 8192), "claude-fable-5": (30, 8192),
        "claude-opus-5": (80, 6144), "claude-sonnet-5": (150, 4096),
        subject.JUDGE_MODEL: (200, 2048), "gpt-5.6-sol": (30, 8192),
        "gpt-5.6-terra": (30, 6144), "gpt-5.6-luna": (150, 4096),
        "gpt-5.5": (30, 8192), "kimi-k3": (80, 8192),
        "deepseek-v4-pro": (300, 8192),
    }
    assert {r["model"]: (r["paid_call_cap"], r["maximum_output_tokens_per_call"])
            for r in value["routes"]} == expected
    assert all(r["expected_output_tokens_per_call"] == expected[r["model"]][1] // 4
               for r in value["routes"])
    assert value["authority"]["expected_cost_basis"] == (
        "uncalibrated_quarter_cap_output_scenario"
    )


def test_long_judge_inputs_are_reserved_inside_anthropic_ceiling() -> None:
    value = _projection()
    anthropic = next(r for r in value["providers"] if r["provider"] == "anthropic")
    assert anthropic["target_maximum_cost_microusd"] == 37_568_000
    assert anthropic["judge_maximum_cost_microusd"] == 32_962_560
    assert anthropic["combined_maximum_cost_microusd"] == 70_530_560
    assert anthropic["remaining_margin_microusd"] == 1_469_440


def test_missing_or_non_usd_price_blocks_projection() -> None:
    pricing = _pricing()
    pricing["providers"]["kimi"]["models"]["kimi-k3"]["rates"][0][
        "currency"
    ] = "EUR"

    with pytest.raises(ValueError, match="must be in USD"):
        _projection(pricing=pricing)


def test_kimi_implicit_max_reasoning_is_not_the_budgeted_condition() -> None:
    config = _api_config()
    del config["kimi:kimi-k3"]["reasoning_effort"]
    with pytest.raises(ValueError, match="reasoning_effort changed"):
        _projection(api_config=config)


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
