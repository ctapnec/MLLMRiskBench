"""Seal local judging for the hosted members of one matched Haiku pair plan.

The pair plan remains immutable. This follow-on plan selects exactly its hosted
members and binds the existing rules plus sealed Llama Guard cascade. Planning
constructs neither a target nor a judge and makes no network request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.retained_response_judge import _HEX64, _sha, _write_new
from experiments.retained_response_judge_execute import _read_regular
from experiments.retained_response_judge_pair import validate_pair_plan
from ura.model_acquisition import write_document_create_only
from ura.model_acquisition_runtime import (
    build_runtime_plan,
    build_runtime_selection,
    collect_run_requirements,
    public_selection_descriptor,
    validate_public_selection_descriptor,
)


SCHEMA = "ura-retained-response-local-judge-plan/1"
ALGORITHM = "hosted_members_of_exact_matched_pair_plan_v1"
DEFAULT_GUARDRAIL_MODEL = "meta-llama/Llama-Guard-3-8B"
DEFAULT_GUARDRAIL_REVISION = "7327bd9f6efbbe6101dc6cc4736302b3cbb6e425"
_CONDITION_FIELDS = frozenset(
    {
        "stages",
        "guardrail_model",
        "guardrail_revision",
        "guardrail_device",
        "guardrail_max_new_tokens",
        "target_calls",
        "provider_calls",
        "http_attempts",
        "answer_retries",
        "transport_retries",
        "rules_evaluations",
        "max_local_guardrail_calls",
        "physical_media_directly_evaluated",
        "benign_guardrail_label_scope",
    }
)


def _descriptor(path: Path, expected_sha256: str, *, label: str) -> tuple[dict, dict]:
    value, descriptor = _read_regular(
        path,
        label=label,
        max_bytes=32 * 1024 * 1024,
    )
    if descriptor["sha256"] != expected_sha256:
        raise ValueError(f"{label} SHA-256 differs from the declared digest")
    return value, descriptor


def _hosted_rows(pair_plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = [dict(row) for row in pair_plan["selected"] if row["cohort"] == "hosted"]
    if len(rows) != pair_plan["selection"]["selected_pairs"] or not rows:
        raise ValueError("matched pair plan does not contain one hosted row per pair")
    pair_order = [pair["pair_id"] for pair in pair_plan["pairs"]]
    if [row["pair_id"] for row in rows] != pair_order:
        raise ValueError("hosted pair-plan members are not in canonical pair order")
    return rows


def _runtime_selection(
    *,
    pair_descriptor: Mapping[str, object],
    source_descriptor: Mapping[str, object],
    selected: Sequence[Mapping[str, Any]],
    guardrail_model: str,
    guardrail_revision: str,
):
    requirements = collect_run_requirements(
        target_specs=(),
        local_configs={},
        judge_names=("guardrail",),
        judge_model="mock",
        attacker_names=(),
        attacker_configs={},
        guardrail_model=guardrail_model,
        guardrail_revision=guardrail_revision,
    )
    return build_runtime_selection(
        requirements,
        input_bindings={
            "pair_plan_sha256": str(pair_descriptor["sha256"]),
            "selected_outputs_sha256": _sha(list(selected)),
            "source_receipt_sha256": str(source_descriptor["sha256"]),
        },
    )


def build_plan(
    pair_plan: Mapping[str, Any],
    *,
    pair_descriptor: Mapping[str, object],
    guardrail_model: str = DEFAULT_GUARDRAIL_MODEL,
    guardrail_revision: str = DEFAULT_GUARDRAIL_REVISION,
    guardrail_device: str = "cuda:1",
) -> tuple[dict[str, Any], Any]:
    pair = validate_pair_plan(dict(pair_plan))
    if pair_descriptor.get("sha256") is None:
        raise ValueError("matched pair-plan descriptor lacks a digest")
    selected = _hosted_rows(pair)
    selection = _runtime_selection(
        pair_descriptor=pair_descriptor,
        source_descriptor=pair["source"],
        selected=selected,
        guardrail_model=guardrail_model,
        guardrail_revision=guardrail_revision,
    )
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "planned_no_calls",
        "authority": "matched_hosted_outputs_local_post_factum_judging",
        "pair_plan": {
            **dict(pair_descriptor),
            "plan_id": pair["plan_id"],
        },
        "source": dict(pair["source"]),
        "judge_condition": {
            "stages": ["rules", "guardrail"],
            "guardrail_model": guardrail_model,
            "guardrail_revision": guardrail_revision,
            "guardrail_device": guardrail_device,
            "guardrail_max_new_tokens": 20,
            "target_calls": 0,
            "provider_calls": 0,
            "http_attempts": 0,
            "answer_retries": 0,
            "transport_retries": 0,
            "rules_evaluations": len(selected),
            "max_local_guardrail_calls": len(selected),
            "physical_media_directly_evaluated": False,
            "benign_guardrail_label_scope": (
                "safe_violation_only_over_refusal_abstains_when_rules_undecided"
            ),
        },
        "selection": {
            "algorithm": ALGORITHM,
            "cohort": "hosted",
            "selected_pairs": len(selected),
            "selected_outputs": len(selected),
            "same_rows_as_haiku": True,
            "outcome_dependent_extension_permitted": False,
        },
        "model_acquisition": public_selection_descriptor(selection),
        "selected": selected,
    }
    value["plan_id"] = "retained-local-judge-plan-" + _sha(value)[:24]
    return validate_plan(value), selection


def validate_plan(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "authority",
        "pair_plan",
        "source",
        "judge_condition",
        "selection",
        "model_acquisition",
        "selected",
        "plan_id",
    }:
        raise ValueError("local retained-response judge plan fields changed")
    condition = value.get("judge_condition")
    selection = value.get("selection")
    selected = value.get("selected")
    pair_descriptor = value.get("pair_plan")
    source = value.get("source")
    if (
        value.get("schema") != SCHEMA
        or value.get("status") != "planned_no_calls"
        or value.get("authority")
        != "matched_hosted_outputs_local_post_factum_judging"
        or not isinstance(condition, dict)
        or set(condition) != _CONDITION_FIELDS
        or not isinstance(selection, dict)
        or not isinstance(selected, list)
        or not selected
        or not isinstance(pair_descriptor, dict)
        or set(pair_descriptor) != {"file", "sha256", "bytes", "plan_id"}
        or not isinstance(source, dict)
        or set(source) != {"file", "sha256", "bytes"}
    ):
        raise ValueError("local retained-response judge plan contract changed")
    if any(
        _HEX64.fullmatch(str(item.get("sha256", ""))) is None
        for item in (pair_descriptor, source)
    ):
        raise ValueError("local judge input descriptor digest is invalid")
    count = len(selected)
    if (
        condition.get("stages") != ["rules", "guardrail"]
        or condition.get("guardrail_model") != DEFAULT_GUARDRAIL_MODEL
        or condition.get("guardrail_revision") != DEFAULT_GUARDRAIL_REVISION
        or not isinstance(condition.get("guardrail_device"), str)
        or not condition["guardrail_device"].strip()
        or condition.get("guardrail_max_new_tokens") != 20
        or any(condition.get(field) != 0 for field in (
            "target_calls", "provider_calls", "http_attempts",
            "answer_retries", "transport_retries",
        ))
        or condition.get("rules_evaluations") != count
        or condition.get("max_local_guardrail_calls") != count
        or condition.get("physical_media_directly_evaluated") is not False
        or condition.get("benign_guardrail_label_scope")
        != "safe_violation_only_over_refusal_abstains_when_rules_undecided"
        or selection != {
            "algorithm": ALGORITHM,
            "cohort": "hosted",
            "selected_pairs": count,
            "selected_outputs": count,
            "same_rows_as_haiku": True,
            "outcome_dependent_extension_permitted": False,
        }
        or any(row.get("cohort") != "hosted" for row in selected)
        or len({row.get("pair_id") for row in selected}) != count
        or len({row.get("retained_row_sha256") for row in selected}) != count
    ):
        raise ValueError("local retained-response judge call or selection contract changed")
    acquisition = validate_public_selection_descriptor(value.get("model_acquisition"))
    rebuilt = _runtime_selection(
        pair_descriptor=pair_descriptor,
        source_descriptor=source,
        selected=selected,
        guardrail_model=condition["guardrail_model"],
        guardrail_revision=condition["guardrail_revision"],
    )
    if acquisition != public_selection_descriptor(rebuilt):
        raise ValueError("local judge model-acquisition selection changed")
    material = dict(value)
    claimed = material.pop("plan_id")
    if claimed != "retained-local-judge-plan-" + _sha(material)[:24]:
        raise ValueError("local retained-response judge plan identity changed")
    return dict(value)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair-plan", type=Path, required=True)
    parser.add_argument("--pair-plan-sha256", required=True)
    parser.add_argument("--guardrail-model", default=DEFAULT_GUARDRAIL_MODEL)
    parser.add_argument("--guardrail-revision", default=DEFAULT_GUARDRAIL_REVISION)
    parser.add_argument("--guardrail-device", default="cuda:1")
    parser.add_argument("--acquisition-plan-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    raw_pair, pair_descriptor = _descriptor(
        args.pair_plan,
        args.pair_plan_sha256,
        label="matched pair plan",
    )
    pair = validate_pair_plan(raw_pair)
    value, runtime_selection = build_plan(
        pair,
        pair_descriptor=pair_descriptor,
        guardrail_model=args.guardrail_model,
        guardrail_revision=args.guardrail_revision,
        guardrail_device=args.guardrail_device,
    )
    plan_path = _write_new(args.out, value)
    acquisition = build_runtime_plan(runtime_selection)
    acquisition_path, acquisition_sha256 = write_document_create_only(
        args.acquisition_plan_dir,
        acquisition,
        identifier=acquisition["plan_id"],
        suffix="plan.json",
    )
    print(json.dumps({
        "local_judge_plan": str(plan_path),
        "acquisition_plan": str(acquisition_path),
        "acquisition_plan_sha256": acquisition_sha256,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
