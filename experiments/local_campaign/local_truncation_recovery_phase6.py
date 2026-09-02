"""Inventory exact local rows that require native-maximum regeneration.

This module never reads response text into its output. It validates retained
attempt/response identities, selects only unfinished, typed failed-output, and
provider-declared length-ended rows, and emits completed-ID selectors for a
separate correction stratum. Historical artifacts remain immutable.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from experiments import run_matrix
from experiments.local_campaign.current_ollama import CURRENT_OLLAMA_BY_SPEC
from experiments.local_campaign.current_ollama_gate5 import _descriptor, _stable_file
from experiments.local_campaign.failed_output_recovery_phase6 import (
    _active_jsonl,
    _durable_outcomes,
    _jsonl,
    _selected_rows,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    _create_json,
    _load_json,
    _option,
    _sha256_json,
)
from ura.data_models import Response
from ura.runner import Runner


SCHEMA = "ura-local-truncation-recovery-inventory/1"
CURRENT_VLLM_SPECS = frozenset({
    "vllm:Qwen/Qwen3-VL-8B-Instruct",
    "vllm:llava-hf/llava-v1.6-mistral-7b-hf",
    "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR",
})
CURRENT_LOCAL_SPECS = CURRENT_VLLM_SPECS | frozenset(CURRENT_OLLAMA_BY_SPEC)

_VALUE_FLAGS = frozenset({
    "--deadline-seconds",
    "--execution-scope-id",
    "--live-attestation",
    "--live-attestation-max-age-hours",
    "--live-attestation-sha256",
    "--max-total-http-attempts",
    "--max-total-judge-calls",
    "--max-total-target-calls",
    "--model-acquisition-plan",
    "--model-acquisition-plan-sha256",
    "--model-acquisition-receipt",
    "--model-acquisition-receipt-sha256",
    "--model-acquisition-store",
    "--out",
    "--recovery-completed-prefix",
    "--recovery-completed-prefix-sha256",
})
_BOOLEAN_FLAGS = frozenset({
    "--diagnostic-canary",
    "--model-acquisition-plan-only",
    "--preflight-only",
})


def _without_runtime_bindings(argv: Sequence[str]) -> list[str]:
    """Return the immutable selection/semantics vector without run bindings."""

    result: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in _BOOLEAN_FLAGS:
            index += 1
            continue
        if item in _VALUE_FLAGS:
            if index + 1 >= len(argv):
                raise ValueError(f"runtime flag lacks a value: {item}")
            index += 2
            continue
        result.append(item)
        index += 1
    return result


def native_max_local_config(
    config: Mapping[str, Any], *, expected_spec: str
) -> dict[str, Any]:
    """Change only local context/output policy to provider-native maximums."""

    if set(config) != {expected_spec} or not isinstance(config[expected_spec], dict):
        raise ValueError("local truncation config must contain the exact selected model")
    entry = dict(config[expected_spec])
    if expected_spec.startswith("vllm:"):
        entry.pop("max_model_len", None)
        entry.pop("max_tokens", None)
    elif expected_spec.startswith("ollama:"):
        entry["num_ctx"] = "max"
        entry["num_predict"] = -1
    else:
        raise ValueError("local truncation config has an unsupported backend")
    return {expected_spec: entry}


def length_ended_datapoint_ids(
    *, attempts: Mapping[str, str], responses: Sequence[Response]
) -> set[str]:
    """Return exact datapoint IDs whose provider declared output truncation."""

    selected: set[str] = set()
    seen_attempts: set[str] = set()
    for response in responses:
        attempt_id = response.attempt_id
        if attempt_id not in attempts or attempt_id in seen_attempts:
            raise ValueError("truncation response identity inventory changed")
        seen_attempts.add(attempt_id)
        raw = response.raw
        backend = raw.get("backend")
        if backend == "vllm":
            is_length = raw.get("finish_reason") == "length"
        elif backend == "ollama":
            is_length = raw.get("done_reason") == "length"
        else:
            raise ValueError("truncation inventory contains a non-local backend")
        if is_length:
            selected.add(attempts[attempt_id])
    if seen_attempts != set(attempts):
        raise ValueError("truncation attempt/response inventory is incomplete")
    return selected


def build_truncation_selection(
    *,
    selected_ids: Mapping[str, Sequence[str]],
    eligible_ids: Mapping[str, Sequence[str]],
    outcomes: Mapping[str, str],
    length_ended_ids: set[str],
) -> tuple[dict[str, object], dict[str, object]]:
    """Select only unfinished, failed-output, and length-ended local rows."""

    all_selected = [item for rows in selected_ids.values() for item in rows]
    all_eligible = {item for rows in eligible_ids.values() for item in rows}
    if (
        set(selected_ids) != set(eligible_ids)
        or len(all_selected) != len(set(all_selected))
        or any(len(rows) != len(set(rows)) for rows in eligible_ids.values())
        or not all_eligible.issubset(all_selected)
        or not set(outcomes).issubset(all_eligible)
        or not length_ended_ids.issubset(set(outcomes))
    ):
        raise ValueError("truncation recovery identity inventory changed")
    allowed = {
        "usable_first_response",
        "recovered_after_retry",
        "failed_output",
        "input_incompatible",
    }
    if any(value not in allowed for value in outcomes.values()):
        raise ValueError("truncation recovery outcome is unsupported")
    retry_ids = (
        all_eligible - set(outcomes)
        | {item for item, status in outcomes.items() if status == "failed_output"}
        | length_ended_ids
    )
    if any(outcomes.get(item) == "input_incompatible" for item in retry_ids):
        raise ValueError("typed input incompatibility requires its dedicated recovery")

    corpora: dict[str, dict[str, object]] = {}
    remaining_all: list[str] = []
    for corpus, ordered_value in selected_ids.items():
        ordered = list(ordered_value)
        eligible = set(eligible_ids[corpus])
        remaining = [item for item in ordered if item in eligible & retry_ids]
        if not remaining:
            continue
        completed = sorted(set(ordered) - set(remaining))
        if not completed or len(completed) >= len(ordered):
            raise ValueError(f"{corpus}: completed selection is not a strict subset")
        corpora[corpus] = {
            "completed_record_count": len(completed),
            "selected_datapoint_ids_sha256": _sha256_json(ordered),
            "completed_datapoint_ids": completed,
            "completed_datapoint_ids_sha256": _sha256_json(completed),
            "remaining_datapoint_ids_sha256": _sha256_json(remaining),
        }
        remaining_all.extend(remaining)
    if not corpora or set(remaining_all) != retry_ids:
        raise ValueError("truncation recovery selector lost an eligible identity")
    summary: dict[str, object] = {
        "selected_records": len(all_selected),
        "prior_eligible_records": len(all_eligible),
        "durable_outcomes": len(outcomes),
        "never_attempted_records": len(all_eligible - set(outcomes)),
        "failed_output_records": sum(
            status == "failed_output" for status in outcomes.values()
        ),
        "length_ended_records": len(length_ended_ids),
        "recovery_records": len(retry_ids),
        "completed_records_excluded": len(all_selected) - len(retry_ids),
        "outcome_counts": dict(sorted(Counter(outcomes.values()).items())),
    }
    return {"schema": "ura-recovery-completed-selection/1", "corpora": corpora}, summary


def _response_rows(result_root: Path) -> list[Response]:
    rows: list[Response] = []
    for path in _active_jsonl(result_root, "responses"):
        if path.name.endswith(".responses.checkpoint.jsonl"):
            rows.extend(
                Response.model_validate(record.get("response"))
                for record in Runner.load_response_checkpoint(path).values()
            )
        else:
            rows.extend(
                Response.model_validate(row)
                for row in _jsonl(path, label="local truncation responses")
            )
    return rows


def _source_modality(selected_rows: Mapping[str, Sequence[Any]]) -> str:
    modalities = {
        modality
        for rows in selected_rows.values()
        for row in rows
        for modality in row.modalities
    }
    physical = modalities & {"image", "audio", "video"}
    if physical == {"image"}:
        return "image"
    if not physical:
        return "text"
    raise ValueError("local truncation source has an unsupported modality mixture")


def derive_state_inventory(state_path: Path) -> dict[str, Any]:
    """Derive one exact structure-only recovery unit from retained state."""

    state_path = state_path.resolve(strict=True)
    state = _load_json(state_path, label="local truncation source state")
    argv = state.get("runner_argv")
    if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
        raise ValueError("local truncation state argv changed")
    spec = _option(argv, "--local")
    if "," in spec or spec not in CURRENT_LOCAL_SPECS:
        raise ValueError("local truncation state is not one current-roster model")
    selected_rows, audits = _selected_rows(argv)
    source_unit_id = state.get("unit_id")
    source_lane = state.get("source_lane")
    source_corpus = state.get("corpus")
    if (
        not isinstance(source_unit_id, str)
        or not source_unit_id
        or not isinstance(source_lane, str)
        or not source_lane
        or (source_corpus is not None and not isinstance(source_corpus, str))
    ):
        raise ValueError("local truncation source unit identity changed")
    eligible_rows = dict(selected_rows)
    if "--recovery-completed-prefix" in argv:
        old_recovery, _binding = run_matrix.load_recovery_completed_prefix(
            _option(argv, "--recovery-completed-prefix"),
            _option(argv, "--recovery-completed-prefix-sha256"),
        )
        if old_recovery is None:
            raise ValueError("local truncation source selector changed")
        eligible_rows = {}
        for corpus, rows in selected_rows.items():
            eligible, _audit = run_matrix.apply_recovery_completed_prefix(
                corpus, rows, audits[corpus], old_recovery
            )
            eligible_rows[corpus] = eligible
    result_root = Path(str(state.get("result_root", "")))
    if (
        not result_root.is_absolute()
        or result_root.is_symlink()
        or result_root.resolve(strict=True) != result_root
    ):
        raise ValueError("local truncation result root changed")
    attempts, outcomes, attempt_files, response_files = _durable_outcomes(result_root)
    responses = _response_rows(result_root)
    length_ids = length_ended_datapoint_ids(attempts=attempts, responses=responses)
    selected_ids = {
        corpus: [row.id for row in rows] for corpus, rows in selected_rows.items()
    }
    eligible_ids = {
        corpus: [row.id for row in rows] for corpus, rows in eligible_rows.items()
    }
    selector, summary = build_truncation_selection(
        selected_ids=selected_ids,
        eligible_ids=eligible_ids,
        outcomes=outcomes,
        length_ended_ids=length_ids,
    )
    config_path = Path(_option(argv, "--local-config")).resolve(strict=True)
    config_payload = _stable_file(config_path, label="local truncation source config")
    if hashlib.sha256(config_payload).hexdigest() != _option(
        argv, "--local-config-sha256"
    ):
        raise ValueError("local truncation source config digest changed")
    config = json.loads(config_payload.decode("utf-8"))
    corrected_config = native_max_local_config(config, expected_spec=spec)
    return {
        "source_state": _descriptor(state_path, label="local truncation source state"),
        "source_result_root": str(result_root),
        "source_attempt_files": [
            _descriptor(path, label="local truncation attempts") for path in attempt_files
        ],
        "source_response_files": [
            _descriptor(path, label="local truncation responses") for path in response_files
        ],
        "source_local_config": _descriptor(
            config_path, label="local truncation source config"
        ),
        "source_unit_id": source_unit_id,
        "source_lane": source_lane,
        "source_corpus": source_corpus,
        "modality": _source_modality(selected_rows),
        "local_spec": spec,
        "base_argv": _without_runtime_bindings(argv),
        "recovery_selection": selector,
        "native_max_local_config": corrected_config,
        "summary": summary,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", action="append", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    units = [derive_state_inventory(path) for path in args.state]
    identities = [str(unit["source_result_root"]) for unit in units]
    if len(identities) != len(set(identities)):
        raise ValueError("local truncation source result root is duplicated")
    _create_json(
        args.out,
        {
            "schema": SCHEMA,
            "unit_order": identities,
            "units": units,
            "totals": {
                "source_units": len(units),
                "recovery_records": sum(
                    int(unit["summary"]["recovery_records"]) for unit in units
                ),
                "length_ended_records": sum(
                    int(unit["summary"]["length_ended_records"]) for unit in units
                ),
                "never_attempted_records": sum(
                    int(unit["summary"]["never_attempted_records"]) for unit in units
                ),
                "failed_output_records": sum(
                    int(unit["summary"]["failed_output_records"]) for unit in units
                ),
            },
            "response_text_retained": False,
            "historical_rows_mutated": False,
            "retired_rwkv_rescheduled": False,
            "paid_provider_calls": 0,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
