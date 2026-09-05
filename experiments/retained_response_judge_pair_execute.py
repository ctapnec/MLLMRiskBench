"""Execute one sealed matched local/hosted Haiku comparison plan."""

from __future__ import annotations

import argparse
import hashlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.human_audit import _joined_artifacts
from experiments.retained_response_judge import load_candidates
from experiments.retained_response_judge_execute import (
    _build_haiku_judge,
    execute as execute_retained,
)
from experiments.retained_response_judge_pair import (
    SHARED_SCHEMA,
    build_pair_plan,
    validate_pair_plan,
)


def _reconcile_pair_selection(
    local_runner_view: Path,
    hosted_runner_view: Path,
    plan: dict[str, Any],
    source_descriptor: Mapping[str, object],
) -> list[tuple[dict[str, Any], str, str]]:
    local_candidates, local_audit = load_candidates(
        local_runner_view, include_match_identity=True
    )
    hosted_candidates, hosted_audit = load_candidates(
        hosted_runner_view, include_match_identity=True
    )
    condition = plan["judge_condition"]
    rebuilt = build_pair_plan(
        local_candidates,
        hosted_candidates,
        local_population_audit=local_audit,
        hosted_population_audit=hosted_audit,
        source_descriptor=source_descriptor,
        judge_model=condition["model"],
        api_config_sha256=condition["api_config_sha256"],
        pricing_condition={
            field: condition[field]
            for field in (
                "pricing_config_sha256",
                "pricing_as_of",
                "pricing_effective_date",
                "pricing_currency",
                "input_microusd_per_token",
                "output_microusd_per_token",
            )
        },
        limit=plan["selection"]["requested_pair_limit"],
        seed=plan["selection"]["sample_seed"],
        max_cost_microusd=condition["max_cost_microusd"],
        share_local_judgments=plan["schema"] == SHARED_SCHEMA,
    )
    if rebuilt != plan:
        raise ValueError("matched Haiku plan no longer matches its Runner views")
    metadata_by_cohort: dict[str, Mapping[str, dict[str, Any]]] = {}
    for cohort, runner_view in (
        ("local", local_runner_view),
        ("hosted", hosted_runner_view),
    ):
        _per_judge, metadata, _judgments, _audit = _joined_artifacts(
            Path(runner_view).resolve(strict=True), frame="common"
        )
        metadata_by_cohort[cohort] = metadata
    items: list[tuple[dict[str, Any], str, str]] = []
    for row in plan["selected"]:
        meta = metadata_by_cohort[row["cohort"]].get(row["sample_key"])
        if not isinstance(meta, dict):
            raise ValueError("matched retained response disappeared from its Runner view")
        prompt_value = meta.get("prepared_prompt")
        response_value = meta.get("prepared_response")
        if not isinstance(prompt_value, str) or not isinstance(response_value, str):
            raise ValueError("matched retained-response content is not text")
        prompt = prompt_value
        response = response_value.strip()
        if (
            not prompt
            or not response
            or hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            != row["prompt_sha256"]
            or hashlib.sha256(response.encode("utf-8")).hexdigest()
            != row["response_sha256"]
        ):
            raise ValueError("matched retained-response content identity changed")
        items.append((row, prompt, response))
    return items


def execute(
    *,
    plan_path: Path,
    local_runner_view: Path,
    hosted_runner_view: Path,
    source_receipt: Path,
    api_config: Path,
    pricing_config: Path,
    out: Path,
    judge_factory: Any = _build_haiku_judge,
) -> Path:
    def build_judge(spec: str, config: Mapping[str, object]) -> Any:
        if config.get("max_tokens") != 512:
            raise ValueError("matched Haiku judge API config must fix max_tokens=512")
        return judge_factory(spec, config)

    def reconcile(
        runner_view: Path,
        plan: dict[str, Any],
        source_descriptor: Mapping[str, object],
    ) -> list[tuple[dict[str, Any], str, str]]:
        if Path(runner_view) != Path(local_runner_view):
            raise ValueError("matched Haiku local Runner view changed")
        return _reconcile_pair_selection(
            local_runner_view,
            hosted_runner_view,
            plan,
            source_descriptor,
        )

    return execute_retained(
        plan_path=plan_path,
        runner_view=local_runner_view,
        source_receipt=source_receipt,
        api_config=api_config,
        pricing_config=pricing_config,
        out=out,
        judge_factory=build_judge,
        plan_validator=validate_pair_plan,
        selection_reconciler=reconcile,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--local-runner-view", type=Path, required=True)
    parser.add_argument("--hosted-runner-view", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--api-config", type=Path, required=True)
    parser.add_argument("--pricing-config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ack-paid-execution", action="store_true")
    args = parser.parse_args(argv)
    if not args.ack_paid_execution:
        parser.error("--ack-paid-execution is required")
    print(
        execute(
            plan_path=args.plan,
            local_runner_view=args.local_runner_view,
            hosted_runner_view=args.hosted_runner_view,
            source_receipt=args.source_receipt,
            api_config=args.api_config,
            pricing_config=args.pricing_config,
            out=args.out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
