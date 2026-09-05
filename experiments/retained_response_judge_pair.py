"""Seal matched local/hosted retained outputs for one Haiku comparison cohort.

The selector consumes two already validated Phase 7 Runner views. It admits
only pairs whose rendered input identity is byte-equivalent after canonical
normalization, then selects without reusing either retained output. No target
or judge is constructed here.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.retained_response_judge import (
    _HEX64,
    _MATCH_IDENTITY_FIELDS,
    _regular_descriptor,
    _sha,
    _text,
    _write_new,
    load_candidates,
    load_pricing_condition,
)
from ura.targets.api import DEFAULT_HOSTED_HTTP_ERROR_RETRIES


SCHEMA = "ura-retained-response-judge-pair-plan/1"
ALGORITHM = "seeded_balanced_round_robin_matched_retained_output_pairs_v1"
# The operator's 80-percent allocation includes both members of every pair.
# Historical /1 plans retain their own smaller content-bound quantity and spend.
MAX_PAIR_LIMIT = 1_350
MAX_COST_MICROUSD = 33_000_000
DEFAULT_PAIR_LIMIT = 1_110
DEFAULT_COST_MICROUSD = MAX_COST_MICROUSD
_PAIR_DIMENSIONS = (
    "local_exact_model",
    "hosted_exact_model",
    "framework",
    "corpus",
    "source",
    "modality",
    "risk",
    "expected_behavior",
    "source_policy_id",
    "source_policy_version",
)
_BASE_ROW_FIELDS = frozenset(
    {
        "sample_key",
        "run_id",
        "attempt_id",
        "datapoint_id",
        "source_cluster_id",
        "requested_seed",
        "exact_model",
        "framework",
        "corpus",
        "source",
        "modality",
        "risk",
        "expected_behavior",
        "project_revision_sha256",
        "output_policy_sha256",
        "prompt_sha256",
        "response_sha256",
        "retained_row_sha256",
        "stratum_id",
        "source_policy_id",
        "source_policy_version",
        "media_references_sha256",
        "input_identity_sha256",
    }
)
_SELECTED_ROW_FIELDS = _BASE_ROW_FIELDS | {
    "cohort",
    "pair_id",
    "pair_stratum_id",
    "same_model_judge",
}
_CONDITION_FIELDS = frozenset(
    {
        "model",
        "api_config_sha256",
        "hosted_data_transfer_acknowledged",
        "target_calls",
        "answer_retries",
        "transport_retries",
        "max_judge_calls",
        "max_http_attempts",
        "max_cost_microusd",
        "judge_max_output_tokens",
        "pricing_config_sha256",
        "pricing_as_of",
        "pricing_effective_date",
        "pricing_currency",
        "input_microusd_per_token",
        "output_microusd_per_token",
        "independent_judge_rows",
        "same_model_judge_rows",
    }
)


def _candidate_groups(
    candidates: Sequence[Mapping[str, Any]], *, cohort: str
) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[str] = set()
    for raw in candidates:
        row = dict(raw)
        if set(row) != _BASE_ROW_FIELDS:
            raise ValueError(f"{cohort} matched candidate fields changed")
        retained = _text(row.get("retained_row_sha256"), label="retained row digest")
        identity = _text(row.get("input_identity_sha256"), label="input identity")
        if (
            _HEX64.fullmatch(retained) is None
            or _HEX64.fullmatch(identity) is None
            or retained in seen
        ):
            raise ValueError(f"{cohort} matched candidate identity is invalid")
        expected_identity = _sha(
            {field: row[field] for field in _MATCH_IDENTITY_FIELDS}
        )
        if identity != expected_identity:
            raise ValueError(f"{cohort} input identity changed")
        seen.add(retained)
        groups[identity].append(row)
    return groups


def _pair_edges(
    local_candidates: Sequence[Mapping[str, Any]],
    hosted_candidates: Sequence[Mapping[str, Any]],
    *,
    seed: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if isinstance(seed, bool) or not isinstance(seed, int) or seed != 0:
        raise ValueError("current matched Haiku campaign requires sample seed 0")
    local = _candidate_groups(local_candidates, cohort="local")
    hosted = _candidate_groups(hosted_candidates, cohort="hosted")
    common = sorted(set(local) & set(hosted))
    edges: list[dict[str, Any]] = []
    for identity in common:
        for local_row in local[identity]:
            for hosted_row in hosted[identity]:
                stratum_material = {
                    "local_exact_model": local_row["exact_model"],
                    "hosted_exact_model": hosted_row["exact_model"],
                    **{
                        field: local_row[field]
                        for field in _PAIR_DIMENSIONS
                        if field not in {"local_exact_model", "hosted_exact_model"}
                    },
                }
                if any(
                    local_row[field] != hosted_row[field]
                    for field in (
                        "framework",
                        "corpus",
                        "source",
                        "modality",
                        "risk",
                        "expected_behavior",
                        "source_policy_id",
                        "source_policy_version",
                        "prompt_sha256",
                        "media_references_sha256",
                        "datapoint_id",
                        "source_cluster_id",
                        "requested_seed",
                    )
                ):
                    raise ValueError("equal input digest has conflicting input fields")
                pair_stratum_id = _sha(stratum_material)
                pair_id = "retained-judge-pair-" + _sha(
                    {
                        "input_identity_sha256": identity,
                        "local_retained_row_sha256": local_row["retained_row_sha256"],
                        "hosted_retained_row_sha256": hosted_row["retained_row_sha256"],
                    }
                )[:24]
                edges.append(
                    {
                        "pair_id": pair_id,
                        "input_identity_sha256": identity,
                        "pair_stratum_id": pair_stratum_id,
                        "local": local_row,
                        "hosted": hosted_row,
                    }
                )
    return edges, {
        "local_matched_input_identities": sum(len(local[key]) for key in common),
        "hosted_matched_input_identities": sum(len(hosted[key]) for key in common),
        "matched_distinct_input_identities": len(common),
        "unmatched_local_distinct_input_identities": len(set(local) - set(hosted)),
        "unmatched_hosted_distinct_input_identities": len(set(hosted) - set(local)),
        "eligible_pair_edges": len(edges),
    }


def _select_pairs(
    edges: Sequence[Mapping[str, Any]], *, limit: int, seed: int
) -> list[dict[str, Any]]:
    if (
        isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_PAIR_LIMIT
    ):
        raise ValueError(
            f"matched retained judge pair limit must be in [1,{MAX_PAIR_LIMIT}]"
        )
    if not edges:
        raise ValueError("local and hosted Runner views have no matched usable outputs")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in edges:
        edge = dict(raw)
        groups[edge["pair_stratum_id"]].append(edge)
    for stratum, rows in groups.items():
        rows.sort(
            key=lambda row: _sha(
                {"seed": seed, "pair_stratum_id": stratum, "edge": row}
            )
        )
    order = sorted(groups, key=lambda value: _sha({"seed": seed, "stratum": value}))
    queues = {key: deque(groups[key]) for key in order}
    selected: list[dict[str, Any]] = []
    used_local: set[str] = set()
    used_hosted: set[str] = set()
    while len(selected) < limit:
        progressed = False
        for key in order:
            while queues[key]:
                edge = queues[key].popleft()
                local_digest = edge["local"]["retained_row_sha256"]
                hosted_digest = edge["hosted"]["retained_row_sha256"]
                if local_digest in used_local or hosted_digest in used_hosted:
                    continue
                selected.append(edge)
                used_local.add(local_digest)
                used_hosted.add(hosted_digest)
                progressed = True
                break
            if len(selected) >= limit:
                break
        if not progressed:
            break
    if not selected:
        raise ValueError("matched retained-output selection is empty")
    return selected


def build_pair_plan(
    local_candidates: Sequence[Mapping[str, Any]],
    hosted_candidates: Sequence[Mapping[str, Any]],
    *,
    local_population_audit: Mapping[str, int],
    hosted_population_audit: Mapping[str, int],
    source_descriptor: Mapping[str, object],
    judge_model: str,
    api_config_sha256: str,
    pricing_condition: Mapping[str, object],
    limit: int = DEFAULT_PAIR_LIMIT,
    seed: int = 0,
    max_cost_microusd: int = DEFAULT_COST_MICROUSD,
) -> dict[str, Any]:
    judge_model = _text(judge_model, label="judge model")
    if not judge_model.startswith("anthropic:claude-haiku-"):
        raise ValueError("funded matched retained-response judge must be Haiku")
    if _HEX64.fullmatch(api_config_sha256) is None:
        raise ValueError("API configuration SHA-256 must be 64 lowercase hex")
    if (
        isinstance(max_cost_microusd, bool)
        or not isinstance(max_cost_microusd, int)
        or not 1 <= max_cost_microusd <= MAX_COST_MICROUSD
    ):
        raise ValueError(
            "matched Haiku cost ceiling must be positive and at most USD 18"
        )
    edges, match_audit = _pair_edges(
        local_candidates, hosted_candidates, seed=seed
    )
    pairs = _select_pairs(edges, limit=limit, seed=seed)
    selected: list[dict[str, Any]] = []
    pair_rows: list[dict[str, str]] = []
    for pair in pairs:
        pair_rows.append(
            {
                field: pair[field]
                for field in ("pair_id", "input_identity_sha256", "pair_stratum_id")
            }
        )
        for cohort in ("local", "hosted"):
            row = dict(pair[cohort])
            row.update(
                {
                    "cohort": cohort,
                    "pair_id": pair["pair_id"],
                    "pair_stratum_id": pair["pair_stratum_id"],
                    "same_model_judge": row["exact_model"] == judge_model,
                }
            )
            selected.append(row)
    same_model_rows = sum(row["same_model_judge"] is True for row in selected)
    selected_strata = Counter(pair["pair_stratum_id"] for pair in pairs)
    eligible_strata = Counter(edge["pair_stratum_id"] for edge in edges)
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "planned_no_calls",
        "authority": "matched_selected_followon_not_full_corpus",
        "source": dict(source_descriptor),
        "judge_condition": {
            "model": judge_model,
            "api_config_sha256": api_config_sha256,
            "hosted_data_transfer_acknowledged": True,
            "target_calls": 0,
            "answer_retries": 0,
            "transport_retries": DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
            "max_judge_calls": len(selected),
            "max_http_attempts": len(selected)
            * (DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1),
            "max_cost_microusd": max_cost_microusd,
            "judge_max_output_tokens": 512,
            **dict(pricing_condition),
            "independent_judge_rows": len(selected) - same_model_rows,
            "same_model_judge_rows": same_model_rows,
        },
        "selection": {
            "algorithm": ALGORITHM,
            "sample_seed": seed,
            "requested_pair_limit": limit,
            "selected_pairs": len(pairs),
            "selected_outputs": len(selected),
            "pair_dimensions": list(_PAIR_DIMENSIONS),
            "input_identity_dimensions": list(_MATCH_IDENTITY_FIELDS),
            "retained_output_reuse_permitted": False,
            "outcome_dependent_extension_permitted": False,
        },
        "population": {
            "local": dict(local_population_audit),
            "hosted": dict(hosted_population_audit),
            **match_audit,
        },
        "stratum_population": {
            key: {"eligible_edges": count, "selected_pairs": selected_strata.get(key, 0)}
            for key, count in sorted(eligible_strata.items())
        },
        "pairs": pair_rows,
        "selected": selected,
    }
    value["plan_id"] = "retained-judge-pair-plan-" + _sha(value)[:24]
    return validate_pair_plan(value)


def validate_pair_plan(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "authority",
        "source",
        "judge_condition",
        "selection",
        "population",
        "stratum_population",
        "pairs",
        "selected",
        "plan_id",
    }:
        raise ValueError("matched retained-response plan fields changed")
    condition = value.get("judge_condition")
    selection = value.get("selection")
    pairs = value.get("pairs")
    selected = value.get("selected")
    if (
        value.get("schema") != SCHEMA
        or value.get("status") != "planned_no_calls"
        or value.get("authority") != "matched_selected_followon_not_full_corpus"
        or not isinstance(condition, dict)
        or set(condition) != _CONDITION_FIELDS
        or not isinstance(selection, dict)
        or not isinstance(pairs, list)
        or not isinstance(selected, list)
        or not pairs
        or len(selected) != 2 * len(pairs)
    ):
        raise ValueError("matched retained-response plan contract changed")
    if (
        condition.get("target_calls") != 0
        or condition.get("answer_retries") != 0
        or condition.get("transport_retries") != DEFAULT_HOSTED_HTTP_ERROR_RETRIES
        or condition.get("max_judge_calls") != len(selected)
        or condition.get("max_http_attempts")
        != len(selected) * (DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1)
        or condition.get("hosted_data_transfer_acknowledged") is not True
        or condition.get("input_microusd_per_token") != 1
        or condition.get("output_microusd_per_token") != 5
        or not str(condition.get("model", "")).startswith("anthropic:claude-haiku-")
        or _HEX64.fullmatch(str(condition.get("api_config_sha256", ""))) is None
        or _HEX64.fullmatch(str(condition.get("pricing_config_sha256", ""))) is None
        or not isinstance(condition.get("max_cost_microusd"), int)
        or not 1 <= condition["max_cost_microusd"] <= MAX_COST_MICROUSD
        or condition.get("judge_max_output_tokens") != 512
    ):
        raise ValueError("matched retained-response call contract changed")
    same_model = sum(
        isinstance(row, dict) and row.get("same_model_judge") is True
        for row in selected
    )
    requested_pair_limit = selection.get("requested_pair_limit")
    if (
        condition.get("same_model_judge_rows") != same_model
        or condition.get("independent_judge_rows") != len(selected) - same_model
        or selection.get("algorithm") != ALGORITHM
        or selection.get("sample_seed") != 0
        or selection.get("selected_pairs") != len(pairs)
        or selection.get("selected_outputs") != len(selected)
        or isinstance(requested_pair_limit, bool)
        or not isinstance(requested_pair_limit, int)
        or not 1 <= len(pairs) <= requested_pair_limit <= MAX_PAIR_LIMIT
        or selection.get("pair_dimensions") != list(_PAIR_DIMENSIONS)
        or selection.get("input_identity_dimensions") != list(_MATCH_IDENTITY_FIELDS)
        or selection.get("retained_output_reuse_permitted") is not False
        or selection.get("outcome_dependent_extension_permitted") is not False
    ):
        raise ValueError("matched retained-response selection contract changed")
    pair_by_id: dict[str, dict[str, str]] = {}
    for pair in pairs:
        if (
            not isinstance(pair, dict)
            or set(pair) != {"pair_id", "input_identity_sha256", "pair_stratum_id"}
            or not str(pair.get("pair_id", "")).startswith("retained-judge-pair-")
            or _HEX64.fullmatch(str(pair.get("input_identity_sha256", ""))) is None
            or _HEX64.fullmatch(str(pair.get("pair_stratum_id", ""))) is None
            or pair["pair_id"] in pair_by_id
        ):
            raise ValueError("matched retained-response pair identity is invalid")
        pair_by_id[pair["pair_id"]] = pair
    seen_rows: set[str] = set()
    cohorts: Counter[tuple[str, str]] = Counter()
    for row in selected:
        if not isinstance(row, dict) or set(row) != _SELECTED_ROW_FIELDS:
            raise ValueError("matched retained-response selected-row fields changed")
        pair = pair_by_id.get(row["pair_id"])
        if (
            pair is None
            or row["cohort"] not in {"local", "hosted"}
            or row["input_identity_sha256"] != pair["input_identity_sha256"]
            or row["pair_stratum_id"] != pair["pair_stratum_id"]
            or row["same_model_judge"]
            is not (row["exact_model"] == condition["model"])
            or row["retained_row_sha256"] in seen_rows
        ):
            raise ValueError("matched retained-response pair membership changed")
        for field in (
            "input_identity_sha256",
            "retained_row_sha256",
            "prompt_sha256",
            "response_sha256",
            "media_references_sha256",
            "project_revision_sha256",
            "output_policy_sha256",
        ):
            if _HEX64.fullmatch(str(row.get(field, ""))) is None:
                raise ValueError("matched retained-response selected digest is invalid")
        if row["input_identity_sha256"] != _sha(
            {field: row[field] for field in _MATCH_IDENTITY_FIELDS}
        ):
            raise ValueError("matched retained-response input identity changed")
        seen_rows.add(row["retained_row_sha256"])
        cohorts[(row["pair_id"], row["cohort"])] += 1
    if any(
        cohorts[(pair_id, cohort)] != 1
        for pair_id in pair_by_id
        for cohort in ("local", "hosted")
    ):
        raise ValueError("each matched pair must contain one local and one hosted output")
    source = value.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"file", "sha256", "bytes"}
        or _HEX64.fullmatch(str(source.get("sha256", ""))) is None
    ):
        raise ValueError("matched retained-response source descriptor changed")
    population = value.get("population")
    strata = value.get("stratum_population")
    if not isinstance(population, dict) or not isinstance(strata, dict):
        raise ValueError("matched retained-response population changed")
    counted = Counter(pair["pair_stratum_id"] for pair in pairs)
    if any(
        _HEX64.fullmatch(key) is None
        or not isinstance(item, dict)
        or set(item) != {"eligible_edges", "selected_pairs"}
        or item["selected_pairs"] != counted.get(key, 0)
        or item["eligible_edges"] < item["selected_pairs"]
        for key, item in strata.items()
    ):
        raise ValueError("matched retained-response stratum population changed")
    material = dict(value)
    claimed = material.pop("plan_id")
    if claimed != "retained-judge-pair-plan-" + _sha(material)[:24]:
        raise ValueError("matched retained-response plan identity changed")
    return dict(value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-runner-view", type=Path, required=True)
    parser.add_argument("--hosted-runner-view", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--source-receipt-sha256", required=True)
    parser.add_argument("--judge-model", required=True)
    parser.add_argument("--api-config-sha256", required=True)
    parser.add_argument("--pricing-config", type=Path, required=True)
    parser.add_argument("--pricing-config-sha256", required=True)
    parser.add_argument("--pricing-as-of", required=True)
    parser.add_argument("--pair-limit", type=int, default=DEFAULT_PAIR_LIMIT)
    parser.add_argument("--sample-seed", type=int, default=0)
    parser.add_argument("--max-cost-microusd", type=int, default=DEFAULT_COST_MICROUSD)
    parser.add_argument("--ack-hosted-judge-data-transfer", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.ack_hosted_judge_data_transfer:
        parser.error("--ack-hosted-judge-data-transfer is required")
    local, local_audit = load_candidates(
        args.local_runner_view, include_match_identity=True
    )
    hosted, hosted_audit = load_candidates(
        args.hosted_runner_view, include_match_identity=True
    )
    value = build_pair_plan(
        local,
        hosted,
        local_population_audit=local_audit,
        hosted_population_audit=hosted_audit,
        source_descriptor=_regular_descriptor(
            args.source_receipt, args.source_receipt_sha256
        ),
        judge_model=args.judge_model,
        api_config_sha256=args.api_config_sha256,
        pricing_condition=load_pricing_condition(
            args.pricing_config,
            expected_sha256=args.pricing_config_sha256,
            judge_model=args.judge_model,
            as_of=args.pricing_as_of,
        ),
        limit=args.pair_limit,
        seed=args.sample_seed,
        max_cost_microusd=args.max_cost_microusd,
    )
    print(_write_new(args.out, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
