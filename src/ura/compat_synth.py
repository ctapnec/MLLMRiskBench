"""Synthetic comparison-case generator for the compatibility oracle (SYN-001).

Templates are scenario-times-mutation constructions.  Each template builds a
base compatible pair for one scenario and optionally applies one mutation that
injects exactly one incompatibility (or an abstention condition).  Perturbation
randomness (support sizes, rates, id suffixes) is drawn from a seeded RNG so
generation is deterministic; template identity, family tags and seeds live
only in the sidecar split metadata, never in the case payload a model may see.

The generated corpus proves rule fidelity and template coverage only.  It is
not evidence about real benchmarks, models, judges or humans.
"""

from __future__ import annotations

import random
from typing import Any, Callable

from .compat_bundles import (
    ALL_REASONS,
    COMPAT_BUNDLE_SCHEMA,
    COMPAT_CASE_SCHEMA,
    REASON_HORIZON,
    REASON_IDENTITY,
    REASON_IMPOSSIBLE,
    REASON_JUDGE,
    REASON_MEDIA_EVALUATOR,
    REASON_NATIVE_PROXY,
    REASON_POLARITY,
    REASON_POLICY,
    REASON_POPULATION,
    REASON_PROVENANCE,
    REASON_STRUCTURAL_NA,
    REASON_UNIT,
    ComparisonCase,
    evaluate_comparison,
)

_MODEL_POOL = (
    ("fable-x", "provider-a"), ("sol-y", "provider-b"),
    ("nimbus-z", "provider-c"), ("quartz-q", "provider-d"),
)
_SOURCE_POOL = ("alpha_bench", "beta_bench", "gamma_bench", "delta_bench")


def _hex(rng: random.Random) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(64))


def _bundle(rng: random.Random, *, model_index: int, source_index: int,
            run_suffix: str, **overrides: Any) -> dict[str, Any]:
    model, provider = _MODEL_POOL[model_index % len(_MODEL_POOL)]
    source = _SOURCE_POOL[source_index % len(_SOURCE_POOL)]
    support = rng.randrange(40, 400)
    numerator = rng.randrange(0, support + 1)
    estimate = numerator / support
    half = min(estimate, 1 - estimate, 0.08 + rng.random() * 0.05)
    policy_hash = _hex(rng)
    value: dict[str, Any] = {
        "schema": COMPAT_BUNDLE_SCHEMA,
        "bundle_id": f"bundle-{_hex(rng)[:16]}",
        "requested_model": model,
        "resolved_model": f"{model}-resolved",
        "provider": provider,
        "source": source,
        "source_policy_id": f"{source}-policy",
        "source_policy_version": "1.2",
        "source_policy_sha256": policy_hash,
        "modality": "text",
        "delivery_mode": "text_only",
        "evaluator_mode": "text_judges_over_text_response",
        "attacker": "replay",
        "defense": "none",
        "judge_order": ("rules", "llm-judge"),
        "execution_type": "static_replay",
        "run_id": f"run-{run_suffix}",
        "budget_horizon_turns": None,
        "metric_family": "unsafe_response_rate",
        "metric_name": "ASR",
        "endpoint_status": "proxy",
        "population": "harmful_expected_refusal",
        "unit": "source_prompt_cluster",
        "denominator": "eligible_harmful_clusters",
        "polarity": "higher_adverse",
        "scale": "unit_interval_rate",
        "numerator": numerator,
        "support": support,
        "decided": support,
        "abstained": 0,
        "estimate": estimate,
        "ci_low": max(0.0, estimate - half),
        "ci_high": min(1.0, estimate + half),
        "ci_method": "cluster_bootstrap_percentile",
        "status": "measured",
        "na_reason": None,
        "artifact_sha256": _hex(rng),
        "config_sha256": _hex(rng),
        "source_corpus_sha256": _hex(rng),
    }
    value.update(overrides)
    return value


def _shared(rng: random.Random, left: dict[str, Any], right: dict[str, Any]) -> None:
    """Make the identity axes a compatible pair must share actually shared."""

    for field in (
        "source", "source_policy_id", "source_policy_version",
        "source_policy_sha256", "unit", "denominator", "polarity", "scale",
        "metric_family", "metric_name", "population", "judge_order",
        "delivery_mode", "evaluator_mode", "execution_type",
        "budget_horizon_turns", "attacker", "defense", "endpoint_status",
        "modality", "source_corpus_sha256",
    ):
        right[field] = left[field]


# -- scenarios ---------------------------------------------------------------

def _static_paired(rng: random.Random, model_index: int = 0,
                   source_index: int = 0) -> dict[str, Any]:
    left = _bundle(rng, model_index=model_index, source_index=source_index,
                   run_suffix=_hex(rng)[:10])
    right = _bundle(rng, model_index=model_index + 1,
                    source_index=source_index, run_suffix=_hex(rng)[:10])
    _shared(rng, left, right)
    return {"proposed": "paired_difference", "left": left, "right": right}


def _static_pooled(rng: random.Random, model_index: int = 0,
                   source_index: int = 1) -> dict[str, Any]:
    left = _bundle(rng, model_index=model_index, source_index=source_index,
                   run_suffix="shared")
    right = _bundle(rng, model_index=model_index, source_index=source_index,
                    run_suffix="shared")
    _shared(rng, left, right)
    right["resolved_model"] = left["resolved_model"]
    right["run_id"] = left["run_id"]
    return {"proposed": "pooled_rate", "left": left, "right": right}


def _adaptive_paired(rng: random.Random, model_index: int = 0,
                     source_index: int = 0) -> dict[str, Any]:
    case = _static_paired(rng, model_index, source_index)
    for side in ("left", "right"):
        case[side].update({
            "execution_type": "live_conversation",
            "attacker": "crescendo",
            "budget_horizon_turns": 4,
            "metric_family": "adaptive_compromise",
            "metric_name": "conversation_ASR",
            "unit": "conversation_cluster",
            "denominator": "eligible_conversations",
        })
    return case


def _classification_paired(rng: random.Random, model_index: int = 0,
                           source_index: int = 0) -> dict[str, Any]:
    case = _static_paired(rng, model_index, source_index)
    for side in ("left", "right"):
        case[side].update({
            "execution_type": "classification_replay",
            "evaluator_mode": "source_specific_parser",
            "judge_order": ("source_metric_only",),
            "metric_family": "classification_quality",
            "metric_name": "rjudge_accuracy",
            "population": "source_items",
            "unit": "source_item",
            "denominator": "valid_parsed_outputs",
            "polarity": "higher_favorable",
        })
    return case


def _native_side_by_side(rng: random.Random, model_index: int = 2,
                         source_index: int = 2) -> dict[str, Any]:
    left = _bundle(
        rng, model_index=model_index, source_index=source_index,
        run_suffix=_hex(rng)[:10],
        execution_type="native_campaign",
        evaluator_mode="source_native_evaluator",
        endpoint_status="native",
        metric_family="attack_or_injection_goal_success",
        metric_name="native_goal_success",
        population="native_episodes",
        unit="native_task_episode",
        denominator="native_scored_episodes",
        polarity="source_defined",
        scale="native_percent",
    )
    right = _bundle(rng, model_index=model_index + 1,
                    source_index=source_index + 1, run_suffix=_hex(rng)[:10])
    return {"proposed": "side_by_side_row", "left": left, "right": right}


_SCENARIOS: dict[str, Callable[[random.Random], dict[str, Any]]] = {
    "static_paired": _static_paired,
    "static_pooled": _static_pooled,
    "adaptive_paired": _adaptive_paired,
    "classification_paired": _classification_paired,
}


# -- mutations (each injects exactly one axis of incompatibility) ------------

def _mutate_policy(case, rng):
    case["right"]["source_policy_version"] = "2.0"
    case["right"]["source_policy_sha256"] = _hex(rng)
    return [REASON_POLICY]


def _mutate_population(case, rng):
    case["right"].update({
        "population": "benign_expected_answer",
        "denominator": case["left"]["denominator"],
    })
    return [REASON_POPULATION]


def _mutate_unit(case, rng):
    case["right"].update({
        "execution_type": "live_conversation",
        "budget_horizon_turns": 4,
    })
    return [REASON_UNIT]


def _mutate_horizon(case, rng):
    for side in ("left", "right"):
        case[side].update({
            "execution_type": "live_conversation",
            "metric_family": "adaptive_compromise",
            "metric_name": "conversation_ASR",
            "unit": "conversation_cluster",
        })
    case["left"]["budget_horizon_turns"] = 4
    case["right"]["budget_horizon_turns"] = 8
    return [REASON_HORIZON]


def _mutate_proxy(case, rng):
    case["right"]["endpoint_status"] = "official"
    return [REASON_NATIVE_PROXY]


def _mutate_identity(case, rng):
    case["right"]["source"] = _SOURCE_POOL[
        (_SOURCE_POOL.index(case["left"]["source"]) + 1) % len(_SOURCE_POOL)
    ]
    case["right"]["source_policy_id"] = f"{case['right']['source']}-policy"
    case["right"]["source_policy_sha256"] = _hex(rng)
    return [REASON_IDENTITY, REASON_POLICY]


def _mutate_run_pool(case, rng):
    case["proposed"] = "pooled_rate"
    case["right"]["run_id"] = f"run-{_hex(rng)[:10]}"
    return [REASON_IDENTITY]


def _mutate_judge(case, rng):
    case["right"]["judge_order"] = ("llm-judge", "rules")
    return [REASON_JUDGE]


def _mutate_na(case, rng):
    case["right"].update({
        "status": "structural_na",
        "na_reason": "modality_unsupported_by_route",
        "estimate": None, "numerator": None,
        "ci_low": None, "ci_high": None, "ci_method": None,
    })
    return [REASON_STRUCTURAL_NA]


def _mutate_provenance(case, rng):
    case["right"]["artifact_sha256"] = None
    return [REASON_PROVENANCE]


def _mutate_polarity(case, rng):
    case["right"].update({
        "metric_name": "refusal_rate",
        "polarity": "higher_favorable",
    })
    return [REASON_POLARITY]


def _mutate_support(case, rng):
    case["right"]["numerator"] = case["right"]["support"] + 5
    return [REASON_IMPOSSIBLE]


def _mutate_evaluator(case, rng):
    case["right"].update({
        "modality": "image",
        "delivery_mode": "physical_bytes",
        "evaluator_mode": "text_judges_with_source_reference_proxy",
    })
    case["left"]["modality"] = "image"
    case["left"]["delivery_mode"] = "physical_bytes"
    case["left"]["evaluator_mode"] = "response_only_text_judge_proxy"
    return [REASON_MEDIA_EVALUATOR]


def _mutate_modality(case, rng):
    for side, modality in (("left", "image"), ("right", "video")):
        case[side].update({
            "modality": modality,
            "delivery_mode": "physical_bytes",
            "evaluator_mode": "text_judges_with_source_reference_proxy",
        })
    return [REASON_MEDIA_EVALUATOR]


def _mutate_hash_absent(case, rng):
    case["left"]["source_policy_sha256"] = None
    case["right"]["source_policy_sha256"] = None
    return []  # abstain: identity looks equal but cannot be confirmed


_MUTATIONS: dict[str, tuple[Callable[..., list[str]], str]] = {
    # mutation name -> (function, intended label)
    "policy": (_mutate_policy, "incompatible"),
    "population": (_mutate_population, "incompatible"),
    "unit": (_mutate_unit, "incompatible"),
    "horizon": (_mutate_horizon, "incompatible"),
    "proxy": (_mutate_proxy, "incompatible"),
    "identity": (_mutate_identity, "incompatible"),
    "run_pool": (_mutate_run_pool, "incompatible"),
    "judge": (_mutate_judge, "incompatible"),
    "na_pooled": (_mutate_na, "incompatible"),
    "provenance": (_mutate_provenance, "incompatible"),
    "polarity": (_mutate_polarity, "incompatible"),
    "support": (_mutate_support, "incompatible"),
    "evaluator": (_mutate_evaluator, "incompatible"),
    "modality": (_mutate_modality, "incompatible"),
    "hash_absent": (_mutate_hash_absent, "abstain"),
}


def templates() -> list[dict[str, Any]]:
    """The template inventory: scenarios, mutations, and special cases."""

    entries: list[dict[str, Any]] = []
    for scenario in _SCENARIOS:
        entries.append({
            "template": f"{scenario}::compatible",
            "scenario": scenario,
            "mutation": None,
            "intended_label": "compatible",
        })
    for scenario in ("static_paired", "static_pooled"):
        for mutation, (_, intended) in _MUTATIONS.items():
            if scenario == "static_pooled" and mutation in {"run_pool"}:
                continue
            entries.append({
                "template": f"{scenario}::{mutation}",
                "scenario": scenario,
                "mutation": mutation,
                "intended_label": intended,
            })
    entries.append({
        "template": "native_side_by_side::compatible",
        "scenario": "native_side_by_side",
        "mutation": None,
        "intended_label": "compatible",
    })
    return entries


def template_families(template_name: str) -> tuple[int, int]:
    """Deterministic per-template family assignment (spreads families)."""

    import hashlib

    digest = hashlib.sha256(template_name.encode("utf-8")).digest()
    return digest[0] % len(_SOURCE_POOL), digest[1] % len(_MODEL_POOL)


def build_case(template: dict[str, Any], rng: random.Random,
               case_index: int) -> tuple[ComparisonCase, dict[str, Any]]:
    scenario = template["scenario"]
    builder = _SCENARIOS.get(scenario, _native_side_by_side)
    source_index, model_index = template_families(template["template"])
    raw = builder(rng, model_index, source_index)
    intended_reasons: list[str] = []
    if template["mutation"] is not None:
        mutate, _ = _MUTATIONS[template["mutation"]]
        intended_reasons = mutate(raw, rng)
    case = ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA,
        "case_id": f"case-{_hex(rng)[:16]}",
        **raw,
    })
    left_model = case.left.requested_model
    metadata = {
        "template": template["template"],
        "intended_label": template["intended_label"],
        "intended_reasons": sorted(intended_reasons),
        "benchmark_family": case.left.source,
        "model_family": left_model,
        "case_index": case_index,
    }
    return case, metadata


def generate_corpus(
    *, seed: int, perturbations_per_template: int,
) -> tuple[list[ComparisonCase], dict[str, dict[str, Any]]]:
    if perturbations_per_template < 1:
        raise ValueError("perturbations_per_template must be positive")
    rng = random.Random(seed)
    cases: list[ComparisonCase] = []
    metadata: dict[str, dict[str, Any]] = {}
    for template in templates():
        for index in range(perturbations_per_template):
            case, meta = build_case(template, rng, index)
            if case.case_id in metadata:
                raise ValueError("duplicate generated case id")
            cases.append(case)
            metadata[case.case_id] = meta
    return cases, metadata


def coverage_report(cases: list[ComparisonCase]) -> dict[str, Any]:
    """Oracle the corpus and verify every critical reason code appears."""

    labels: dict[str, int] = {"compatible": 0, "incompatible": 0, "abstain": 0}
    reason_counts: dict[str, int] = {reason: 0 for reason in ALL_REASONS}
    for case in cases:
        verdict = evaluate_comparison(case)
        labels[verdict["label"]] += 1
        for reason in verdict["reasons"]:
            reason_counts[reason] += 1
    missing = sorted(
        reason for reason, count in reason_counts.items() if count == 0
    )
    return {
        "n_cases": len(cases),
        "labels": labels,
        "reason_counts": dict(sorted(reason_counts.items())),
        "missing_critical_reasons": missing,
        "all_critical_reasons_covered": not missing,
    }


#: Hand-authored adversarial near-valid cases (not generated; deterministic).
def hand_authored_adversarial() -> list[tuple[ComparisonCase, str]]:
    rng = random.Random(4242)
    entries: list[tuple[ComparisonCase, str]] = []

    # Same policy id, near-identical version string ("1.2" vs "1.2.0").
    raw = _static_paired(rng)
    raw["right"]["source_policy_version"] = "1.2.0"
    raw["right"]["source_policy_sha256"] = _hex(rng)
    entries.append((ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA, "case_id": "adv-policy-patch", **raw,
    }), "incompatible"))

    # Metric renamed but identical family/unit; polarity silently flipped.
    raw = _static_pooled(rng)
    raw["right"]["metric_name"] = "attack_success_rate"
    entries.append((ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA, "case_id": "adv-metric-rename", **raw,
    }), "incompatible"))

    # Judge cascade equal as a set, different order.
    raw = _static_paired(rng)
    raw["right"]["judge_order"] = tuple(reversed(raw["left"]["judge_order"]))
    entries.append((ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA, "case_id": "adv-judge-order", **raw,
    }), "incompatible"))

    # Interval that only just excludes its estimate.
    raw = _static_paired(rng)
    left = raw["left"]
    left["ci_low"] = min(0.9, left["estimate"] + 1e-6)
    left["ci_high"] = min(1.0, left["ci_low"] + 0.01)
    entries.append((ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA, "case_id": "adv-interval-edge", **raw,
    }), "incompatible"))

    # Decided+abstained exceeding support by exactly one.
    raw = _static_paired(rng)
    raw["right"]["decided"] = raw["right"]["support"]
    raw["right"]["abstained"] = 1
    entries.append((ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA, "case_id": "adv-support-off-by-one", **raw,
    }), "incompatible"))

    # Fully valid pair; proposal is the always-allowed side-by-side row.
    raw = _static_paired(rng)
    raw["proposed"] = "side_by_side_row"
    entries.append((ComparisonCase.model_validate({
        "schema": COMPAT_CASE_SCHEMA, "case_id": "adv-side-by-side-ok", **raw,
    }), "compatible"))
    return entries
