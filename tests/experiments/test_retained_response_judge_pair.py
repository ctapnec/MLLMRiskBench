from __future__ import annotations

import copy

import pytest

from experiments import retained_response_judge_pair as subject


JUDGE = "anthropic:claude-haiku-4-5-20251001"
HEX_A = "a" * 64
HEX_B = "b" * 64
PRICING = {
    "pricing_config_sha256": HEX_A,
    "pricing_as_of": "2026-09-03",
    "pricing_effective_date": "2026-09-01",
    "pricing_currency": "USD",
    "input_microusd_per_token": 1,
    "output_microusd_per_token": 5,
}


def _candidate(
    index: int,
    *,
    cohort: str,
    input_index: int | None = None,
    model: str | None = None,
) -> dict:
    input_index = index if input_index is None else input_index
    dimensions = {
        "exact_model": model or f"{cohort}:model-{index % 3}",
        "framework": f"framework-{input_index % 2}",
        "corpus": f"corpus-{input_index % 3}",
        "source": f"source-{input_index % 3}",
        "modality": "image" if input_index % 2 else "text",
        "risk": f"risk-{input_index % 2}",
        "expected_behavior": "refuse",
        "project_revision_sha256": HEX_A if cohort == "local" else HEX_B,
        "output_policy_sha256": HEX_B if cohort == "local" else HEX_A,
    }
    row = {
        "sample_key": f"{cohort}-sample-{index}",
        "run_id": f"{cohort}-run-{index}",
        "attempt_id": f"{cohort}-attempt-{index}",
        "datapoint_id": f"datapoint-{input_index}",
        "source_cluster_id": f"cluster-{input_index}",
        "requested_seed": 0,
        **dimensions,
        "prompt_sha256": subject._sha({"prompt": input_index}),
        "response_sha256": subject._sha({"response": cohort, "index": index}),
        "source_policy_id": f"policy-{input_index % 2}",
        "source_policy_version": "1",
        "media_references_sha256": subject._sha({"media": input_index}),
    }
    row["retained_row_sha256"] = subject._sha({"row": row})
    row["stratum_id"] = subject._sha(dimensions)
    row["input_identity_sha256"] = subject._sha(
        {field: row[field] for field in subject._MATCH_IDENTITY_FIELDS}
    )
    return row


def _population(count: int) -> dict[str, int]:
    return {
        "validated_joined_rows": count,
        "eligible_usable_outputs": count,
        "excluded_missing_outputs": 0,
        "excluded_source_authoritative_rows": 0,
    }


def _build(local: list[dict], hosted: list[dict], *, limit: int = 2) -> dict:
    return subject.build_pair_plan(
        local,
        hosted,
        local_population_audit=_population(len(local)),
        hosted_population_audit=_population(len(hosted)),
        source_descriptor={"file": "source.json", "sha256": HEX_A, "bytes": 123},
        judge_model=JUDGE,
        api_config_sha256=HEX_B,
        pricing_condition=PRICING,
        limit=limit,
    )


def _resign(plan: dict) -> None:
    material = copy.deepcopy(plan)
    material.pop("plan_id")
    plan["plan_id"] = "retained-judge-pair-plan-" + subject._sha(material)[:24]


def test_pair_selector_is_deterministic_and_uses_identical_inputs() -> None:
    local = [_candidate(index, cohort="local") for index in range(4)]
    hosted = [_candidate(index, cohort="hosted") for index in range(4)]

    first = _build(local, hosted, limit=3)
    second = _build(list(reversed(local)), list(reversed(hosted)), limit=3)

    assert first == second
    assert first["selection"]["selected_pairs"] == 3
    assert first["selection"]["selected_outputs"] == 6
    assert first["judge_condition"]["max_judge_calls"] == 6
    by_pair: dict[str, list[dict]] = {}
    for row in first["selected"]:
        by_pair.setdefault(row["pair_id"], []).append(row)
    assert all(
        {row["cohort"] for row in rows} == {"local", "hosted"}
        for rows in by_pair.values()
    )
    assert all(
        len({row["input_identity_sha256"] for row in rows}) == 1
        for rows in by_pair.values()
    )


def test_pair_selector_never_reuses_an_output() -> None:
    local = [
        _candidate(0, cohort="local", input_index=0),
        _candidate(1, cohort="local", input_index=0),
    ]
    hosted = [
        _candidate(0, cohort="hosted", input_index=0),
        _candidate(1, cohort="hosted", input_index=0),
        _candidate(2, cohort="hosted", input_index=0),
    ]

    plan = _build(local, hosted, limit=3)

    assert plan["selection"]["selected_pairs"] == 2
    assert len({row["retained_row_sha256"] for row in plan["selected"]}) == 4
    assert plan["population"]["eligible_pair_edges"] == 6


def test_prompt_or_policy_difference_is_not_a_match() -> None:
    local = [_candidate(0, cohort="local")]
    hosted = [_candidate(0, cohort="hosted")]
    hosted[0]["source_policy_version"] = "2"
    hosted[0]["input_identity_sha256"] = subject._sha(
        {field: hosted[0][field] for field in subject._MATCH_IDENTITY_FIELDS}
    )

    with pytest.raises(ValueError, match="no matched usable outputs"):
        _build(local, hosted, limit=1)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda plan: plan["selected"][0].__setitem__(
            "input_identity_sha256", "f" * 64
        ),
        lambda plan: plan["selected"][0].__setitem__(
            "cohort", plan["selected"][1]["cohort"]
        ),
        lambda plan: plan["judge_condition"].__setitem__("answer_retries", 1),
        lambda plan: plan["selection"].__setitem__(
            "retained_output_reuse_permitted", True
        ),
    ],
)
def test_validator_rejects_resigned_pair_contract_mutations(mutation) -> None:
    plan = _build(
        [_candidate(0, cohort="local")],
        [_candidate(0, cohort="hosted")],
        limit=1,
    )
    mutation(plan)
    _resign(plan)

    with pytest.raises(ValueError):
        subject.validate_pair_plan(plan)
