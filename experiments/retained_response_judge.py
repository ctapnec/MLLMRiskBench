"""Content-bound zero-target selection for retained-response LLM judging.

This module deliberately imports no Runner, attacker, corpus converter, or
target-under-test factory.  It consumes the already validated Phase 7 Runner
view through the human-audit join, selects immutable retained outputs, and
writes a no-call judge plan.  Paid execution is a separate step and cannot
change this selection after outcomes are observed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
from collections import Counter, defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.figure_results import _load_cells
from experiments.human_audit import _joined_artifacts
from experiments.rig_web_app.reports import rate_for


SCHEMA = "ura-retained-response-judge-plan/1"
ALGORITHM = "seeded_balanced_round_robin_retained_outputs_v1"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PHYSICAL = frozenset({"image", "audio", "video"})
_MATCH_IDENTITY_FIELDS = (
    "framework",
    "corpus",
    "source",
    "datapoint_id",
    "source_cluster_id",
    "requested_seed",
    "modality",
    "risk",
    "expected_behavior",
    "source_policy_id",
    "source_policy_version",
    "prompt_sha256",
    "media_references_sha256",
)
_DIMENSIONS = (
    "exact_model",
    "framework",
    "corpus",
    "source",
    "modality",
    "risk",
    "expected_behavior",
    "project_revision_sha256",
    "output_policy_sha256",
)
_SELECTED_FIELDS = frozenset(
    {
        "sample_key",
        "run_id",
        "attempt_id",
        "datapoint_id",
        "source_cluster_id",
        "requested_seed",
        *_DIMENSIONS,
        "prompt_sha256",
        "response_sha256",
        "retained_row_sha256",
        "stratum_id",
        "same_model_judge",
    }
)
_TOP_FIELDS = frozenset(
    {
        "schema",
        "status",
        "authority",
        "source",
        "judge_condition",
        "selection",
        "population",
        "stratum_population",
        "selected",
        "plan_id",
    }
)
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


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-blank string")
    return value


def _regular_descriptor(path_value: Path, expected_sha256: str) -> dict[str, object]:
    if _HEX64.fullmatch(expected_sha256) is None:
        raise ValueError("source receipt SHA-256 must be 64 lowercase hex")
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError("source receipt must be a regular non-symlink file")
    path = unresolved.resolve(strict=True)
    before = path.stat()
    if not path.is_file() or before.st_size <= 0 or before.st_size > 16 * 1024 * 1024:
        raise ValueError("source receipt must be a regular file of at most 16 MiB")
    payload = path.read_bytes()
    after = path.stat()
    observed = hashlib.sha256(payload).hexdigest()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or len(payload) != before.st_size
        or observed != expected_sha256
    ):
        raise ValueError("source receipt identity or bytes changed")
    return {"file": path.name, "sha256": observed, "bytes": len(payload)}


def load_pricing_condition(
    path_value: Path,
    *,
    expected_sha256: str,
    judge_model: str,
    as_of: str,
) -> dict[str, object]:
    if _HEX64.fullmatch(expected_sha256) is None:
        raise ValueError("pricing SHA-256 must be 64 lowercase hex")
    try:
        dt.date.fromisoformat(as_of)
    except (TypeError, ValueError) as exc:
        raise ValueError("pricing as-of date must be ISO YYYY-MM-DD") from exc
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError("pricing config must be a regular non-symlink file")
    path = unresolved.resolve(strict=True)
    before = path.stat()
    if not path.is_file() or before.st_size <= 0 or before.st_size > 1024 * 1024:
        raise ValueError("pricing config must be a regular file of at most 1 MiB")
    payload = path.read_bytes()
    after = path.stat()
    observed = hashlib.sha256(payload).hexdigest()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or len(payload) != before.st_size
        or observed != expected_sha256
    ):
        raise ValueError("pricing config identity or bytes changed")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"pricing config contains duplicate key {key!r}")
            value[key] = item
        return value

    try:
        pricing = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("pricing config is not strict UTF-8 JSON") from exc
    if not isinstance(pricing, dict) or pricing.get("schema") != "ura-console-pricing/1":
        raise ValueError("pricing config schema changed")
    if not judge_model.startswith("anthropic:claude-haiku-"):
        raise ValueError("pricing condition requires an exact Anthropic Haiku route")
    provider, model = judge_model.split(":", 1)
    rate, why = rate_for(pricing, provider, model, on_date=as_of)
    if rate is None:
        raise ValueError(f"Haiku price is unavailable: {why}")
    per_million = rate.get("per_million_tokens")
    if (
        rate.get("currency") != "USD"
        or not isinstance(per_million, Mapping)
        or per_million.get("input") != 1
        or per_million.get("output") != 5
    ):
        raise ValueError("Haiku standard price differs from the funded USD 1/5 plan")
    return {
        "pricing_config_sha256": observed,
        "pricing_as_of": as_of,
        "pricing_effective_date": rate["effective_date"],
        "pricing_currency": "USD",
        "input_microusd_per_token": 1,
        "output_microusd_per_token": 5,
    }


def _output_policy_sha256(cell: Mapping[str, Any]) -> str:
    manifest = cell.get("manifest")
    config = manifest.get("config") if isinstance(manifest, Mapping) else None
    components = config.get("components") if isinstance(config, Mapping) else None
    target = components.get("target") if isinstance(components, Mapping) else None
    if not isinstance(target, Mapping) or not target:
        raise ValueError("validated cell lacks its target output policy")
    return _sha(dict(target))


def _project_revision_sha256(cell: Mapping[str, Any]) -> str:
    manifest = cell.get("manifest")
    config = manifest.get("config") if isinstance(manifest, Mapping) else None
    run = config.get("run") if isinstance(config, Mapping) else None
    revision = run.get("project_revision") if isinstance(run, Mapping) else None
    digest = revision.get("sha256") if isinstance(revision, Mapping) else None
    if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
        raise ValueError("validated cell lacks a project-revision SHA-256")
    return digest


def load_candidates(
    runner_view: Path, *, include_match_identity: bool = False
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return common, evaluable, usable retained outputs from one validated view."""

    root = Path(runner_view).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Runner view must be a resolved directory")
    _per_judge, metadata, judgments, audit = _joined_artifacts(root, frame="common")
    cells = _load_cells(root)
    contexts: dict[str, dict[str, str]] = {}
    for cell in cells:
        run_id = _text(cell.get("run_id"), label="validated run ID")
        manifest = cell["manifest"]
        run = manifest["config"]["run"]
        context = {
            "exact_model": _text(cell.get("model"), label="validated model"),
            "framework": _text(run.get("attacker"), label="validated framework"),
            "corpus": _text(run.get("corpus"), label="validated corpus"),
            "project_revision_sha256": _project_revision_sha256(cell),
            "output_policy_sha256": _output_policy_sha256(cell),
        }
        if run_id in contexts and contexts[run_id] != context:
            raise ValueError("one validated run ID has conflicting execution context")
        contexts[run_id] = context

    candidates: list[dict[str, Any]] = []
    excluded_missing = 0
    for sample_key, judgment in sorted(judgments.items()):
        meta = metadata[sample_key]
        response_text = str(meta.get("prepared_response") or "").strip()
        if not response_text:
            excluded_missing += 1
            continue
        run_id = _text(meta.get("run_id"), label="candidate run ID")
        context = contexts.get(run_id)
        if context is None:
            raise ValueError("retained response has no validated cell context")
        if (
            meta.get("common_metrics_eligible") is not True
            or meta.get("policy_evaluable_turn") is not True
        ):
            raise ValueError("common retained-response join admitted an ineligible row")
        prompt = _text(meta.get("prepared_prompt"), label="retained prompt")
        modality = _text(meta.get("effective_modality"), label="effective modality")
        row: dict[str, Any] = {
            "sample_key": _text(sample_key, label="sample key"),
            "run_id": run_id,
            "attempt_id": _text(judgment.get("attempt_id"), label="attempt ID"),
            "datapoint_id": _text(meta.get("datapoint_id"), label="datapoint ID"),
            "source_cluster_id": _text(
                meta.get("source_cluster_id"), label="source cluster ID"
            ),
            "requested_seed": meta.get("requested_seed"),
            **context,
            "source": _text(meta.get("source"), label="source"),
            "modality": modality,
            "risk": _text(meta.get("risk_category"), label="risk"),
            "expected_behavior": _text(
                meta.get("expected_behavior"), label="expected behavior"
            ),
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "response_sha256": hashlib.sha256(
                response_text.encode("utf-8")
            ).hexdigest(),
        }
        if include_match_identity:
            row.update(
                {
                    "source_policy_id": _text(
                        meta.get("source_policy_id"), label="source policy ID"
                    ),
                    "source_policy_version": _text(
                        meta.get("source_policy_version"),
                        label="source policy version",
                    ),
                    "media_references_sha256": hashlib.sha256(
                        _text(
                            meta.get("prepared_media_references"),
                            label="prepared media references",
                        ).encode("utf-8")
                    ).hexdigest(),
                }
            )
            row["input_identity_sha256"] = _sha(
                {field: row[field] for field in _MATCH_IDENTITY_FIELDS}
            )
        if isinstance(row["requested_seed"], bool) or not isinstance(
            row["requested_seed"], int
        ):
            raise ValueError("retained response lacks its requested seed")
        material = {
            **row,
            "physical_media_sent_to_judge": False,
            "judge_input_scope": (
                "rendered_text_proxy_plus_target_output"
                if modality in _PHYSICAL
                else "rendered_text_prompt_plus_target_output"
            ),
        }
        row["retained_row_sha256"] = _sha(material)
        row["stratum_id"] = _sha({field: row[field] for field in _DIMENSIONS})
        candidates.append(row)
    if not candidates:
        raise ValueError("validated Runner view has no usable common retained outputs")
    return candidates, {
        "validated_joined_rows": int(audit["policy_evaluable_samples"]),
        "eligible_usable_outputs": len(candidates),
        "excluded_missing_outputs": excluded_missing,
        "excluded_source_authoritative_rows": int(
            audit["common_ineligible_evaluable_rows_excluded"]
        ),
    }


def _select(candidates: Sequence[Mapping[str, Any]], limit: int, seed: int) -> list[dict]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 2_000:
        raise ValueError("retained judge limit must be in [1,2000]")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed != 0:
        raise ValueError("current retained judge campaign requires sample seed 0")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen: set[str] = set()
    for raw in candidates:
        row = dict(raw)
        digest = _text(row.get("retained_row_sha256"), label="retained row digest")
        if _HEX64.fullmatch(digest) is None or digest in seen:
            raise ValueError("candidate retained-row identities are invalid or duplicate")
        seen.add(digest)
        stratum = _text(row.get("stratum_id"), label="stratum ID")
        if _HEX64.fullmatch(stratum) is None:
            raise ValueError("candidate stratum identity is invalid")
        groups[stratum].append(row)
    for stratum, rows in groups.items():
        rows.sort(key=lambda row: _sha({"seed": seed, "stratum": stratum, "row": row}))
    order = sorted(groups, key=lambda value: _sha({"seed": seed, "stratum": value}))
    queues = {key: deque(groups[key]) for key in order}
    selected: list[dict] = []
    while len(selected) < min(limit, len(candidates)):
        progressed = False
        for key in order:
            if queues[key] and len(selected) < limit:
                selected.append(queues[key].popleft())
                progressed = True
        if not progressed:
            break
    return selected


def build_plan(
    candidates: Sequence[Mapping[str, Any]],
    *,
    population_audit: Mapping[str, int],
    source_descriptor: Mapping[str, object],
    judge_model: str,
    api_config_sha256: str,
    pricing_condition: Mapping[str, object],
    limit: int = 2_000,
    seed: int = 0,
    max_cost_microusd: int = 7_000_000,
) -> dict[str, Any]:
    """Build the immutable no-call selector and its exact judge-call ceiling."""

    judge_model = _text(judge_model, label="judge model")
    if not judge_model.startswith("anthropic:claude-haiku-"):
        raise ValueError("funded retained-response judge must be an exact Haiku route")
    if _HEX64.fullmatch(api_config_sha256) is None:
        raise ValueError("API configuration SHA-256 must be 64 lowercase hex")
    if (
        isinstance(max_cost_microusd, bool)
        or not isinstance(max_cost_microusd, int)
        or not 1 <= max_cost_microusd <= 7_000_000
    ):
        raise ValueError("one Haiku cohort cost ceiling must be positive and at most USD 7")
    selected = _select(candidates, limit, seed)
    for row in selected:
        row["same_model_judge"] = row["exact_model"] == judge_model
    same_model_rows = sum(row["same_model_judge"] is True for row in selected)
    stratum_population = dict(sorted(Counter(row["stratum_id"] for row in candidates).items()))
    selected_strata = Counter(row["stratum_id"] for row in selected)
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": "planned_no_calls",
        "authority": "selected_followon_not_full_corpus",
        "source": dict(source_descriptor),
        "judge_condition": {
            "model": judge_model,
            "api_config_sha256": api_config_sha256,
            "hosted_data_transfer_acknowledged": True,
            "target_calls": 0,
            "answer_retries": 0,
            "transport_retries": 0,
            "max_judge_calls": len(selected),
            "max_http_attempts": len(selected),
            "max_cost_microusd": max_cost_microusd,
            **dict(pricing_condition),
            "independent_judge_rows": len(selected) - same_model_rows,
            "same_model_judge_rows": same_model_rows,
        },
        "selection": {
            "algorithm": ALGORITHM,
            "sample_seed": seed,
            "requested_limit": limit,
            "selected_outputs": len(selected),
            "dimensions": list(_DIMENSIONS),
            "outcome_dependent_extension_permitted": False,
        },
        "population": dict(population_audit),
        "stratum_population": {
            key: {"eligible": count, "selected": selected_strata.get(key, 0)}
            for key, count in stratum_population.items()
        },
        "selected": selected,
    }
    value["plan_id"] = "retained-judge-plan-" + _sha(value)[:24]
    return validate_plan(value)


def validate_plan(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _TOP_FIELDS:
        raise ValueError("retained-response judge plan fields changed")
    condition = value.get("judge_condition")
    selection = value.get("selection")
    population = value.get("population")
    strata = value.get("stratum_population")
    selected = value.get("selected")
    if (
        value.get("schema") != SCHEMA
        or value.get("status") != "planned_no_calls"
        or value.get("authority") != "selected_followon_not_full_corpus"
        or not isinstance(value.get("source"), dict)
        or not isinstance(condition, dict)
        or set(condition) != _CONDITION_FIELDS
        or not isinstance(selection, dict)
        or not isinstance(population, dict)
        or not isinstance(strata, dict)
        or not isinstance(selected, list)
        or not selected
    ):
        raise ValueError("retained-response judge plan contract changed")
    selected_count = len(selected)
    source = value["source"]
    if (
        set(source) != {"file", "sha256", "bytes"}
        or not isinstance(source["file"], str)
        or not source["file"]
        or _HEX64.fullmatch(str(source["sha256"])) is None
        or isinstance(source["bytes"], bool)
        or not isinstance(source["bytes"], int)
        or source["bytes"] <= 0
        or source["bytes"] > 16 * 1024 * 1024
    ):
        raise ValueError("retained-response judge source descriptor changed")
    if (
        condition.get("target_calls") != 0
        or condition.get("answer_retries") != 0
        or condition.get("transport_retries") != 0
        or condition.get("max_judge_calls") != selected_count
        or condition.get("max_http_attempts") != selected_count
        or condition.get("hosted_data_transfer_acknowledged") is not True
        or isinstance(condition.get("independent_judge_rows"), bool)
        or not isinstance(condition.get("independent_judge_rows"), int)
        or isinstance(condition.get("same_model_judge_rows"), bool)
        or not isinstance(condition.get("same_model_judge_rows"), int)
        or condition["independent_judge_rows"]
        + condition["same_model_judge_rows"]
        != selected_count
        or condition.get("input_microusd_per_token") != 1
        or condition.get("output_microusd_per_token") != 5
        or _HEX64.fullmatch(str(condition.get("pricing_config_sha256", ""))) is None
        or condition.get("pricing_currency") != "USD"
        or not isinstance(condition.get("max_cost_microusd"), int)
        or not 1 <= condition["max_cost_microusd"] <= 7_000_000
        or not str(condition.get("model", "")).startswith(
            "anthropic:claude-haiku-"
        )
        or _HEX64.fullmatch(str(condition.get("api_config_sha256", ""))) is None
    ):
        raise ValueError("retained-response judge call or cost contract changed")
    try:
        pricing_as_of = dt.date.fromisoformat(condition["pricing_as_of"])
        pricing_effective = dt.date.fromisoformat(condition["pricing_effective_date"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("retained-response judge pricing date is invalid") from exc
    if pricing_effective > pricing_as_of:
        raise ValueError("retained-response judge price is not yet effective")
    if (
        selection.get("algorithm") != ALGORITHM
        or selection.get("sample_seed") != 0
        or selection.get("selected_outputs") != selected_count
        or not 1 <= selected_count <= int(selection.get("requested_limit", 0)) <= 2_000
        or selection.get("dimensions") != list(_DIMENSIONS)
        or selection.get("outcome_dependent_extension_permitted") is not False
    ):
        raise ValueError("retained-response judge selection contract changed")
    order: list[str] = []
    counted = Counter()
    same_model_count = 0
    for row in selected:
        if not isinstance(row, dict) or set(row) != _SELECTED_FIELDS:
            raise ValueError("retained-response judge selected-row fields changed")
        for field in _SELECTED_FIELDS - {"requested_seed", "same_model_judge"}:
            item = row[field]
            if not isinstance(item, str) or not item:
                raise ValueError("retained-response judge selected-row value is invalid")
        if not isinstance(row["same_model_judge"], bool):
            raise ValueError("retained-response judge relationship is invalid")
        if isinstance(row["requested_seed"], bool) or not isinstance(
            row["requested_seed"], int
        ):
            raise ValueError("retained-response judge selected seed is invalid")
        expected_same_model = row["exact_model"] == condition["model"]
        if row["same_model_judge"] is not expected_same_model:
            raise ValueError("retained-response judge relationship changed")
        same_model_count += int(expected_same_model)
        for field in (
            "prompt_sha256",
            "response_sha256",
            "retained_row_sha256",
            "stratum_id",
            "project_revision_sha256",
            "output_policy_sha256",
        ):
            if _HEX64.fullmatch(row[field]) is None:
                raise ValueError("retained-response judge digest is invalid")
        order.append(row["retained_row_sha256"])
        counted[row["stratum_id"]] += 1
    if len(set(order)) != selected_count:
        raise ValueError("retained-response judge selection has duplicate rows")
    if (
        condition["same_model_judge_rows"] != same_model_count
        or condition["independent_judge_rows"] != selected_count - same_model_count
    ):
        raise ValueError("retained-response judge relationship counts changed")
    if set(counted) - set(strata):
        raise ValueError("selected retained-response stratum is absent")
    for key, item in strata.items():
        if (
            _HEX64.fullmatch(key) is None
            or not isinstance(item, dict)
            or set(item) != {"eligible", "selected"}
            or not isinstance(item["eligible"], int)
            or not isinstance(item["selected"], int)
            or item["eligible"] < item["selected"]
            or item["selected"] != counted.get(key, 0)
        ):
            raise ValueError("retained-response judge stratum counts are invalid")
    if sum(item["eligible"] for item in strata.values()) < selected_count:
        raise ValueError("retained-response judge population is smaller than selection")
    required_population = {
        "validated_joined_rows",
        "eligible_usable_outputs",
        "excluded_missing_outputs",
        "excluded_source_authoritative_rows",
    }
    if set(population) != required_population:
        raise ValueError("retained-response judge population fields changed")
    for count in population.values():
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("retained-response judge population count is invalid")
    if (
        population["eligible_usable_outputs"] != sum(
            item["eligible"] for item in strata.values()
        )
        or population["eligible_usable_outputs"] < selected_count
    ):
        raise ValueError("retained-response judge eligible population changed")
    material = dict(value)
    claimed = material.pop("plan_id")
    expected = "retained-judge-plan-" + _sha(material)[:24]
    if claimed != expected:
        raise ValueError("retained-response judge plan identity changed")
    return dict(value)


def _write_new(path_value: Path, value: object) -> Path:
    path = Path(path_value)
    if path.exists() or path.is_symlink():
        raise ValueError("retained-response judge plan output must be create-only")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_canonical(value))
        handle.flush()
        os.fsync(handle.fileno())
    return path.resolve(strict=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner-view", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--source-receipt-sha256", required=True)
    parser.add_argument("--judge-model", required=True)
    parser.add_argument("--api-config-sha256", required=True)
    parser.add_argument("--pricing-config", type=Path, required=True)
    parser.add_argument("--pricing-config-sha256", required=True)
    parser.add_argument("--pricing-as-of", required=True)
    parser.add_argument("--limit", type=int, default=2_000)
    parser.add_argument("--sample-seed", type=int, default=0)
    parser.add_argument("--max-cost-microusd", type=int, default=7_000_000)
    parser.add_argument("--ack-hosted-judge-data-transfer", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.ack_hosted_judge_data_transfer:
        parser.error("--ack-hosted-judge-data-transfer is required")
    candidates, audit = load_candidates(args.runner_view)
    value = build_plan(
        candidates,
        population_audit=audit,
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
        limit=args.limit,
        seed=args.sample_seed,
        max_cost_microusd=args.max_cost_microusd,
    )
    print(_write_new(args.out, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
