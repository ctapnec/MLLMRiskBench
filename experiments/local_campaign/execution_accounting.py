"""Exact execution accounting for the retained all-local campaign view.

This module consumes cells that have already passed ``figure_results._load_cells``.
It does not discover artifacts, reinterpret judgments, or pool experiment strata.
The result is a presentation artifact: logical inputs, physical target starts,
answer retries, final outputs, and judge paths remain separate counts.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA = "ura-local-campaign-execution-accounting/1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_SOURCE_AUTHORITATIVE_ARMS = frozenset({"rjudge_release", "gptgeochat_release"})
_COUNT_FIELDS = (
    "selected_inputs",
    "initial_target_calls",
    "answer_retry_calls",
    "successful_output_generations",
    "retained_missing_outputs",
    "local_rules_decisions",
    "local_guardrail_calls",
    "source_authoritative_decisions",
    "common_local_judgments",
    "haiku_judge_calls",
)
_DIMENSION_FIELDS = (
    "target_locality",
    "target_provider",
    "exact_model",
    "framework",
    "corpus_family",
    "logical_arm",
    "modality",
    "risk",
    "expected_behavior",
    "seed",
    "project_revision_sha256",
    "output_policy_sha256",
)
_ROW_FIELDS = frozenset((*_DIMENSION_FIELDS, *_COUNT_FIELDS))
_TOP_FIELDS = frozenset(
    {
        "schema",
        "status",
        "scope",
        "generated_from",
        "population_plan",
        "policies",
        "row_order",
        "rows",
        "totals",
        "accounting_id",
    }
)
POPULATION_PLAN = {
    "intended_target_calls_before_optional_defense": 42_882,
    "source_authoritative_rows": 8_680,
    "common_judge_eligible_rows": 34_202,
    "optional_defense_target_calls": 3_854,
    "one_retry_attempt_ceiling_before_optional_defense": 85_764,
    "planned_local_haiku_selection_ceiling": 2_000,
}


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


def _object(value: object, *, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} is not an object")
    return value


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is not a non-blank string")
    return value


def _provider(model: str) -> str:
    lowered = model.lower()
    if lowered.startswith("ollama:"):
        return "ollama"
    if lowered.startswith("vllm:"):
        return "vllm"
    return "local_other"


def _project_revision(run: Mapping[str, Any]) -> str:
    binding = _object(run.get("project_revision"), label="run project revision")
    digest = binding.get("sha256")
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError("run project revision SHA-256 is invalid")
    return digest


def _output_policy_sha256(config: Mapping[str, Any]) -> str:
    components = _object(config.get("components"), label="manifest components")
    target = _object(components.get("target"), label="target component")
    return hashlib.sha256(_canonical(dict(target))).hexdigest()


def _stability_retry_count(response: Mapping[str, Any]) -> int:
    raw = _object(response.get("raw"), label="response raw")
    value = raw.get("model_stability_retry_count", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("response retry count is invalid")
    return value


def _missing_output(response: Mapping[str, Any]) -> bool:
    raw = _object(response.get("raw"), label="response raw")
    status = raw.get("model_stability_status")
    if status is None:
        return False
    if status not in {"recovered_after_retry", "failed_output"}:
        raise ValueError("response model-stability status is invalid")
    return status == "failed_output"


def _row_key(row: Mapping[str, Any]) -> str:
    dimensions = {field: row[field] for field in _DIMENSION_FIELDS}
    return hashlib.sha256(_canonical(dimensions)).hexdigest()


def build_execution_accounting(
    cells: Sequence[Mapping[str, Any]],
    *,
    generated_from: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one non-pooling table from validated, success-view Runner cells."""

    if not cells:
        raise ValueError("execution accounting requires validated Runner cells")
    if not isinstance(generated_from, Mapping) or not generated_from:
        raise ValueError("execution accounting source descriptors are absent")

    grouped: dict[tuple[object, ...], dict[str, Any]] = {}
    selected: dict[tuple[object, ...], set[tuple[str, int]]] = {}
    for cell in cells:
        manifest = _object(cell.get("manifest"), label="cell manifest")
        config = _object(manifest.get("config"), label="manifest config")
        run = _object(config.get("run"), label="manifest run")
        model = _text(cell.get("model"), label="resolved model")
        logical_arm = _text(run.get("corpus"), label="logical source arm")
        framework = _text(run.get("attacker"), label="framework")
        revision = _project_revision(run)
        output_policy = _output_policy_sha256(config)
        attempts = _object(cell.get("attempts"), label="cell attempts")
        responses = _object(cell.get("responses"), label="cell responses")
        judgments = cell.get("judgments")
        if not isinstance(judgments, list) or not judgments:
            raise ValueError("cell judgments are absent")
        judgment_by_attempt: dict[str, Mapping[str, Any]] = {}
        for judgment_value in judgments:
            judgment = _object(judgment_value, label="judgment")
            attempt_id = _text(judgment.get("attempt_id"), label="judgment attempt ID")
            if attempt_id in judgment_by_attempt:
                raise ValueError("duplicate judgment attempt ID")
            judgment_by_attempt[attempt_id] = judgment
        if set(attempts) != set(responses) or set(attempts) != set(judgment_by_attempt):
            raise ValueError("cell attempt/response/judgment identities differ")

        for attempt_id, attempt_value in attempts.items():
            attempt = _object(attempt_value, label="attempt")
            response = _object(responses[attempt_id], label="response")
            judgment = judgment_by_attempt[attempt_id]
            raw = _object(judgment.get("raw"), label="judgment raw")
            datapoint_id = _text(attempt.get("datapoint_id"), label="datapoint ID")
            seed = attempt.get("seed")
            if isinstance(seed, bool) or not isinstance(seed, int):
                raise ValueError("attempt seed is invalid")
            dimensions: tuple[object, ...] = (
                "local",
                _provider(model),
                model,
                framework,
                _text(raw.get("source"), label="corpus family"),
                logical_arm,
                _text(raw.get("effective_modality"), label="effective modality"),
                _text(raw.get("risk_category"), label="risk category"),
                _text(raw.get("expected_behavior"), label="expected behavior"),
                seed,
                revision,
                output_policy,
            )
            if dimensions not in grouped:
                row = dict(zip(_DIMENSION_FIELDS, dimensions, strict=True))
                row.update({field: 0 for field in _COUNT_FIELDS})
                grouped[dimensions] = row
                selected[dimensions] = set()
            row = grouped[dimensions]
            selected[dimensions].add((datapoint_id, seed))
            row["initial_target_calls"] += 1
            row["answer_retry_calls"] += _stability_retry_count(response)
            missing = _missing_output(response)
            row[
                "retained_missing_outputs" if missing else "successful_output_generations"
            ] += 1
            source_authoritative = logical_arm in _SOURCE_AUTHORITATIVE_ARMS
            decided = judgment.get("label") != "not_applicable"
            judge = _text(judgment.get("judge"), label="final judge")
            if source_authoritative:
                row["source_authoritative_decisions"] += int(decided)
            else:
                row["common_local_judgments"] += 1
                row["local_rules_decisions"] += int(judge == "rules" and decided)
                row["local_guardrail_calls"] += int(
                    raw.get("guardrail_queried") is True
                )

    rows: list[dict[str, Any]] = []
    for dimensions in sorted(grouped, key=lambda item: tuple(str(value) for value in item)):
        row = grouped[dimensions]
        row["selected_inputs"] = len(selected[dimensions])
        rows.append(row)
    totals = {
        field: sum(int(row[field]) for row in rows) for field in _COUNT_FIELDS
    }
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": (
            "complete_with_missing_outputs"
            if totals["retained_missing_outputs"]
            else "complete"
        ),
        "scope": "validated_success_view_without_cross_stratum_pooling",
        "generated_from": dict(generated_from),
        "population_plan": dict(POPULATION_PLAN),
        "policies": {
            "cross_revision_pooling_permitted": False,
            "cross_output_policy_pooling_permitted": False,
            "retry_calls_inflate_selected_inputs": False,
            "multiple_judge_stages_inflate_target_calls": False,
            "hosted_target_calls": 0,
            "haiku_judge_calls": 0,
        },
        "row_order": [_row_key(row) for row in rows],
        "rows": rows,
        "totals": totals,
    }
    value["accounting_id"] = "execution-accounting-" + hashlib.sha256(
        _canonical(value)
    ).hexdigest()[:24]
    return validate_execution_accounting(value)


def validate_execution_accounting(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _TOP_FIELDS:
        raise ValueError("execution accounting field set changed")
    rows = value.get("rows")
    order = value.get("row_order")
    totals = value.get("totals")
    policies = value.get("policies")
    if (
        value.get("schema") != SCHEMA
        or value.get("status") not in {"complete", "complete_with_missing_outputs"}
        or value.get("scope")
        != "validated_success_view_without_cross_stratum_pooling"
        or not isinstance(value.get("generated_from"), dict)
        or not value["generated_from"]
        or value.get("population_plan") != POPULATION_PLAN
        or not isinstance(rows, list)
        or not rows
        or not isinstance(order, list)
        or len(order) != len(rows)
        or not isinstance(totals, dict)
        or set(totals) != set(_COUNT_FIELDS)
        or not isinstance(policies, dict)
        or policies
        != {
            "cross_revision_pooling_permitted": False,
            "cross_output_policy_pooling_permitted": False,
            "retry_calls_inflate_selected_inputs": False,
            "multiple_judge_stages_inflate_target_calls": False,
            "hosted_target_calls": 0,
            "haiku_judge_calls": 0,
        }
    ):
        raise ValueError("execution accounting contract changed")
    observed_order: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != _ROW_FIELDS:
            raise ValueError("execution accounting row field set changed")
        for field in _DIMENSION_FIELDS:
            item = row[field]
            if field == "seed":
                if isinstance(item, bool) or not isinstance(item, int):
                    raise ValueError("execution accounting seed is invalid")
            elif not isinstance(item, str) or not item:
                raise ValueError("execution accounting dimension is invalid")
        if row["target_locality"] != "local" or row["target_provider"] not in {
            "ollama",
            "vllm",
            "local_other",
        }:
            raise ValueError("execution accounting target route is invalid")
        if (
            _HEX64.fullmatch(row["project_revision_sha256"]) is None
            or _HEX64.fullmatch(row["output_policy_sha256"]) is None
        ):
            raise ValueError("execution accounting content identity is invalid")
        for field in _COUNT_FIELDS:
            count = row[field]
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("execution accounting count is invalid")
        if (
            row["initial_target_calls"]
            != row["successful_output_generations"]
            + row["retained_missing_outputs"]
            or row["selected_inputs"] > row["initial_target_calls"]
            or row["source_authoritative_decisions"]
            and row["common_local_judgments"]
            or row["haiku_judge_calls"] != 0
        ):
            raise ValueError("execution accounting row counts do not reconcile")
        observed_order.append(_row_key(row))
    if len(set(observed_order)) != len(rows) or order != observed_order:
        raise ValueError("execution accounting row order changed")
    expected_totals = {
        field: sum(row[field] for row in rows) for field in _COUNT_FIELDS
    }
    if totals != expected_totals:
        raise ValueError("execution accounting totals do not reconcile")
    expected_status = (
        "complete_with_missing_outputs"
        if totals["retained_missing_outputs"]
        else "complete"
    )
    if value["status"] != expected_status:
        raise ValueError("execution accounting status does not reconcile")
    material = dict(value)
    claimed = material.pop("accounting_id")
    expected_id = "execution-accounting-" + hashlib.sha256(
        _canonical(material)
    ).hexdigest()[:24]
    if claimed != expected_id:
        raise ValueError("execution accounting content identity changed")
    return dict(value)
