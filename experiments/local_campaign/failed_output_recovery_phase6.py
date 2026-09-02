"""Replay only failed or never-attempted local rows under Runner 2.27.

The controller binds the terminal Runner 2.25 vLLM campaign, the terminal
Runner 2.26 Ollama alignment, and the durably interrupted DeepSeek continuation.
It derives completed-ID selectors from persisted attempt/response pairs. Usable
rows and deterministic input-incompatibility rows are excluded; exhausted model
outputs and never-attempted rows remain selected.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from experiments import run_matrix
from experiments.local_campaign.console_events import (
    finish_child_controller,
    publish_target_execution,
    start_child_controller,
)
from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_BY_SPEC,
    CURRENT_OLLAMA_NUM_CTX,
    CURRENT_OLLAMA_NUM_PREDICT,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _descriptor,
    _stable_file,
)
from experiments.local_campaign.current_ollama_population_alignment_phase6 import (
    hub_acquisition_required,
)
from experiments.local_campaign.current_ollama_population_alignment_recovery_phase6 import (
    _base_inputs as _ollama_base_inputs,
)
from experiments.local_campaign.vllm_input_recovery_phase6 import (
    validate_failed_completion as validate_vllm_failed_completion,
)
from experiments.local_campaign.vllm_stability_phase6 import (
    Unit,
    _create_json,
    _framework_lock_id,
    _historical_specs,
    _load_json,
    _option,
    _project_python,
    _replace_option,
    _run_unit,
    _sha256_json,
    _validate_descriptor,
    build_units as build_vllm_units,
)
from ura.data_models import Attempt, Response
from ura.runner import CODE_VERSION, Runner


SCHEMA = "ura-failed-output-recovery-phase6/1"
LAUNCH_SCHEMA = "ura-failed-output-recovery-phase6-launch/1"
SNAPSHOT_SCHEMA = "ura-failed-output-recovery-input-snapshot/1"
UNIT_STATE_SCHEMA = "ura-failed-output-recovery-phase6-unit-state/1"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DEEPSEEK_UNIT = "ollama-deepseek-r1-distill-32b-text-primary-100-extension"
LLAVA_UNIT = "vllm-stability-llava-base-airbench-suffix"
ORIGINAL_UNIT_ORDER = (
    "ollama-gemma4-12b-text-primary-100-extension",
    "ollama-gemma4-12b-image-primary-100-extension",
    "ollama-gpt-oss-20b-text-primary-100-extension",
    "ollama-ministral3-14b-image-primary-100-extension",
    DEEPSEEK_UNIT,
    LLAVA_UNIT,
)
EXPECTED_RECOVERY_COUNTS = (1223, 555, 323, 18, 1674, 20)
EXPECTED_UNIT_ORDER = tuple(
    f"failed-output-recovery-{index:02d}-{original[:52]}"
    for index, original in enumerate(ORIGINAL_UNIT_ORDER, 1)
)
EXPECTED_RECOVERY_ROWS = sum(EXPECTED_RECOVERY_COUNTS)
RESULT_FIELDS = {
    "status",
    "unit_id",
    "source_lane",
    "corpus",
    "selected_records",
    "target_answer_retries",
    "target_call_cap",
    "target_attempts",
    "successful_target_generations",
    "missing_responses",
    "result_root",
    "state",
    "level1",
    "original_unit_id",
}
STATE_FIELDS = {
    "schema",
    "unit_id",
    "source_lane",
    "corpus",
    "selected_records",
    "target_answer_retries",
    "target_call_cap",
    "attestation",
    "projection",
    "result_root",
    "runner_argv",
}


def physical_unit_id(original_unit: str) -> str:
    """Keep a filtered recovery unit at its original six-unit position."""

    try:
        index = ORIGINAL_UNIT_ORDER.index(original_unit) + 1
    except ValueError as exc:
        raise ValueError("unknown failed-output recovery unit") from exc
    return f"failed-output-recovery-{index:02d}-{original_unit[:52]}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _optional_option(argv: Sequence[str], flag: str) -> str | None:
    if flag not in argv:
        return None
    return _option(argv, flag)


def _active_jsonl(result_root: Path, role: str) -> list[Path]:
    finals = sorted(result_root.glob(f"*.{role}.jsonl"))
    selected = list(finals)
    for checkpoint in sorted(result_root.glob(f"*.{role}.checkpoint.jsonl")):
        final = checkpoint.with_name(
            checkpoint.name.replace(
                f".{role}.checkpoint.jsonl", f".{role}.jsonl"
            )
        )
        if not final.exists():
            selected.append(checkpoint)
    if not selected:
        raise ValueError(f"result root has no durable {role} JSONL")
    return selected


def _jsonl(path: Path, *, label: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    payload = _stable_file(path, label=label)
    for raw in payload.splitlines():
        if not raw:
            continue
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"{label} contains invalid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError(f"{label} contains a non-object row")
        result.append(value)
    return result


def _file_descriptor(path: Path, *, label: str) -> dict[str, object]:
    payload = _stable_file(path, label=label)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _canonical_result_root(value: object, *, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError(f"{label} is not an absolute result root")
    path = Path(value)
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(f"{label} is not one canonical directory")
    return path


def _selected_rows(
    argv: Sequence[str],
) -> tuple[dict[str, list[Any]], dict[str, dict[str, object]]]:
    corpora = _option(argv, "--corpora").split(",")
    if not corpora or any(not item for item in corpora) or len(set(corpora)) != len(corpora):
        raise ValueError("selected corpus inventory changed")
    limit = int(_option(argv, "--limit"))
    sample_seed = int(_option(argv, "--sample-seed"))
    source_path = _option(argv, "--source-config")
    source_sha = _option(argv, "--source-config-sha256")
    instances, _artifact = run_matrix._load_source_config(  # noqa: SLF001
        source_path, corpora, source_sha
    )
    policy = _optional_option(argv, "--sampling-policy")
    rows: dict[str, list[Any]] = {}
    audits: dict[str, dict[str, object]] = {}
    for corpus in corpora:
        selected, audit = run_matrix.load_corpus_with_audit(
            corpus,
            limit,
            sample_seed,
            sampling_policy=policy,
            source_instance=instances[corpus],
        )
        rows[corpus] = selected
        audits[corpus] = audit
    return rows, audits


def build_completed_selection(
    *,
    selected_ids: Mapping[str, Sequence[str]],
    eligible_ids: Mapping[str, Sequence[str]],
    outcomes: Mapping[str, str],
) -> tuple[dict[str, object], dict[str, object]]:
    """Return a selector that leaves failed and never-attempted rows runnable."""

    all_ids = [item for rows in selected_ids.values() for item in rows]
    if len(set(all_ids)) != len(all_ids):
        raise ValueError("selected datapoint identities are not globally unique")
    eligible_all = {item for rows in eligible_ids.values() for item in rows}
    if not set(outcomes).issubset(eligible_all):
        raise ValueError("durable outcome lies outside the prior unfinished selection")
    allowed = {
        "usable_first_response",
        "recovered_after_retry",
        "failed_output",
        "input_incompatible",
    }
    if any(status not in allowed for status in outcomes.values()):
        raise ValueError("durable outcome has an unsupported terminal status")

    corpora: dict[str, dict[str, object]] = {}
    summary: dict[str, object] = {
        "selected_records": len(all_ids),
        "prior_eligible_records": len(eligible_all),
        "durable_outcomes": len(outcomes),
        "failed_output_records": sum(
            value == "failed_output" for value in outcomes.values()
        ),
        "input_incompatible_records": sum(
            value == "input_incompatible" for value in outcomes.values()
        ),
        "never_attempted_records": len(eligible_all - set(outcomes)),
    }
    recovery_records = 0
    for corpus, ordered_value in selected_ids.items():
        ordered = list(ordered_value)
        eligible = set(eligible_ids[corpus])
        replay = {
            item
            for item in eligible
            if item not in outcomes or outcomes[item] == "failed_output"
        }
        remaining = [item for item in ordered if item in replay]
        if not remaining:
            continue
        completed = sorted(item for item in ordered if item not in replay)
        if not completed or len(completed) >= len(ordered):
            raise ValueError(f"{corpus}: completed selection is not a strict subset")
        corpora[corpus] = {
            "completed_record_count": len(completed),
            "selected_datapoint_ids_sha256": _sha256_json(ordered),
            "completed_datapoint_ids": completed,
            "completed_datapoint_ids_sha256": _sha256_json(completed),
            "remaining_datapoint_ids_sha256": _sha256_json(remaining),
        }
        recovery_records += len(remaining)
    if not corpora or recovery_records < 1:
        raise ValueError("recovery selection contains no failed or unfinished row")
    summary.update(
        {
            "recovery_records": recovery_records,
            "completed_records_excluded": len(all_ids) - recovery_records,
            "recovery_corpora": list(corpora),
        }
    )
    return {"schema": "ura-recovery-completed-selection/1", "corpora": corpora}, summary


def _derive_selector(
    state_path: Path,
) -> tuple[dict[str, object], dict[str, object]]:
    state = _load_json(state_path, label="failed-output source state")
    argv = state.get("runner_argv")
    if (
        not isinstance(argv, list)
        or any(not isinstance(item, str) for item in argv)
        or _option(argv, "--target-answer-retries") != "1"
    ):
        raise ValueError("failed-output source Runner argv changed")
    selected_rows, audits = _selected_rows(argv)
    old_path = _option(argv, "--recovery-completed-prefix")
    old_sha = _option(argv, "--recovery-completed-prefix-sha256")
    old_recovery, _binding = run_matrix.load_recovery_completed_prefix(
        old_path, old_sha
    )
    if old_recovery is None:
        raise ValueError("failed-output source lacks its prior recovery selection")
    eligible_rows: dict[str, list[Any]] = {}
    for corpus, rows in selected_rows.items():
        eligible, _audit = run_matrix.apply_recovery_completed_prefix(
            corpus, rows, audits[corpus], old_recovery
        )
        eligible_rows[corpus] = eligible

    result_root = _canonical_result_root(
        state.get("result_root"), label="failed-output source result root"
    )
    attempts, outcomes, attempt_files, response_files = _durable_outcomes(
        result_root
    )

    selected_ids = {
        corpus: [row.id for row in rows] for corpus, rows in selected_rows.items()
    }
    eligible_ids = {
        corpus: [row.id for row in rows] for corpus, rows in eligible_rows.items()
    }
    selector, summary = build_completed_selection(
        selected_ids=selected_ids,
        eligible_ids=eligible_ids,
        outcomes=outcomes,
    )
    snapshot = {
        "state": _file_descriptor(state_path, label="failed-output source state"),
        "result_root": str(result_root),
        "prior_recovery": _file_descriptor(
            Path(old_path), label="prior recovery selection"
        ),
        "attempt_files": [
            _file_descriptor(path, label="failed-output attempts")
            for path in attempt_files
        ],
        "response_files": [
            _file_descriptor(path, label="failed-output responses")
            for path in response_files
        ],
        "summary": summary,
    }
    return selector, snapshot


def _durable_outcomes(
    result_root: Path,
) -> tuple[dict[str, str], dict[str, str], list[Path], list[Path]]:
    """Load terminal outcomes from final rows and pre-judging checkpoints."""

    attempt_files = _active_jsonl(result_root, "attempts")
    response_files = _active_jsonl(result_root, "responses")
    attempts: dict[str, str] = {}
    attempt_payloads: dict[str, dict[str, Any]] = {}

    def register_attempt(payload: object) -> None:
        attempt = Attempt.model_validate(payload)
        dumped = attempt.model_dump(mode="json")
        previous = attempt_payloads.get(attempt.id)
        if previous is not None:
            if previous != dumped:
                raise ValueError("failed-output attempt identity inventory changed")
            return
        if attempt.datapoint_id in attempts.values():
            raise ValueError("failed-output attempt identity inventory changed")
        attempts[attempt.id] = attempt.datapoint_id
        attempt_payloads[attempt.id] = dumped

    for path in attempt_files:
        for row in _jsonl(path, label="failed-output attempts"):
            register_attempt(row)

    checkpoint_records: dict[Path, dict[str, dict[str, Any]]] = {}
    for path in response_files:
        if not path.name.endswith(".responses.checkpoint.jsonl"):
            continue
        records = Runner.load_response_checkpoint(path)
        checkpoint_records[path] = records
        for record in records.values():
            register_attempt(record.get("attempt"))

    outcomes: dict[str, str] = {}

    def register_response(payload: object) -> None:
        response = Response.model_validate(payload)
        attempt_id = response.attempt_id
        if attempt_id not in attempts:
            raise ValueError("failed-output response identity inventory changed")
        datapoint_id = attempts[attempt_id]
        if datapoint_id in outcomes:
            raise ValueError("failed-output response datapoint is duplicated")
        raw = response.raw
        if raw.get("target_input_status") == "incompatible":
            status = "input_incompatible"
        else:
            status_value = raw.get(
                "model_stability_status", "usable_first_response"
            )
            if not isinstance(status_value, str):
                raise ValueError("model-stability status is malformed")
            status = status_value
        outcomes[datapoint_id] = status

    for path in response_files:
        if path in checkpoint_records:
            for record in checkpoint_records[path].values():
                register_response(record.get("response"))
        else:
            for row in _jsonl(path, label="failed-output responses"):
                register_response(row)
    if set(attempts.values()) != set(outcomes):
        raise ValueError("durable attempts and responses do not match exactly")
    return attempts, outcomes, attempt_files, response_files


def _ollama_config(control_root: Path, spec: str) -> tuple[Path, str]:
    model = CURRENT_OLLAMA_BY_SPEC.get(spec)
    if model is None:
        raise ValueError(f"current Ollama recovery model changed: {spec!r}")
    path = control_root / "configs" / f"{model.label}.json"
    if not path.exists():
        _create_json(
            path,
            {
                model.spec: {
                    "digest": model.digest,
                    "modalities": list(model.modalities),
                    "num_ctx": CURRENT_OLLAMA_NUM_CTX,
                    "num_predict": CURRENT_OLLAMA_NUM_PREDICT,
                    "think": model.think,
                }
            },
        )
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _recovery_unit(
    template: Unit,
    *,
    state_path: Path,
    control_root: Path,
    unit_id: str,
) -> tuple[Unit, Path, str, dict[str, object]]:
    selector, snapshot = _derive_selector(state_path)
    selector_path = control_root / "inputs" / f"{unit_id}.json"
    _create_json(selector_path, selector)
    selector_sha = hashlib.sha256(selector_path.read_bytes()).hexdigest()
    corpora = list(selector["corpora"])
    base = list(template.spec["base_argv"])
    base = _replace_option(base, "--corpora", ",".join(corpora))
    if _option(base, "--local").startswith("ollama:"):
        config_path, config_sha = _ollama_config(
            control_root, _option(base, "--local")
        )
        base = _replace_option(base, "--local-config", str(config_path))
        base = _replace_option(base, "--local-config-sha256", config_sha)
    spec = dict(template.spec)
    spec["base_argv"] = base
    spec["lane_id"] = unit_id
    if isinstance(spec.get("selection"), dict):
        spec["selection"] = {**spec["selection"], "corpora": corpora}
    selected_records = int(snapshot["summary"]["recovery_records"])
    spec["selected_records"] = selected_records
    unit = replace(
        template,
        unit_id=unit_id,
        spec=spec,
        selected_records=selected_records,
        recovery=selector,
    )
    return unit, selector_path, selector_sha, snapshot


def _prepare_units(
    args: argparse.Namespace,
    *,
    work_root: Path,
    control_root: Path,
    only_original_units: Sequence[str] | None = None,
) -> list[tuple[Unit, Path, str, dict[str, object], bool, str]]:
    runner_root = work_root / "runs/thesis/runner"
    base_completion = args.ollama_base_completion.resolve(strict=True)
    if hashlib.sha256(_stable_file(base_completion, label="Ollama base completion")).hexdigest() != args.ollama_base_completion_sha256:
        raise ValueError("Ollama base completion digest changed")
    _snapshot, base, _launch, alignment = _ollama_base_inputs(
        base_completion, runner_root=runner_root
    )
    templates = {item.unit.unit_id: item for item in alignment}
    results = base.get("unit_results")
    if not isinstance(results, dict):
        raise ValueError("Ollama base result inventory changed")

    sources: list[tuple[Unit, Path, bool, str]] = []
    for original in ORIGINAL_UNIT_ORDER[:4]:
        state_path = _validate_descriptor(
            results[original]["state"], label=f"{original} source state"
        )
        item = templates[original]
        sources.append(
            (
                item.unit,
                state_path,
                hub_acquisition_required(item.unit),
                original,
            )
        )
    interrupted = args.ollama_interrupted_root.resolve(strict=True)
    if interrupted.parent != work_root / "runs/engineering":
        raise ValueError("interrupted Ollama root is outside runs/engineering")
    deepseek_state = interrupted / "units" / DEEPSEEK_UNIT / "state.json"
    sources.append(
        (
            templates[DEEPSEEK_UNIT].unit,
            deepseek_state.resolve(strict=True),
            hub_acquisition_required(templates[DEEPSEEK_UNIT].unit),
            DEEPSEEK_UNIT,
        )
    )

    vllm_completion = args.vllm_failed_completion.resolve(strict=True)
    failed, _failed_root = validate_vllm_failed_completion(
        vllm_completion, args.vllm_failed_completion_sha256
    )
    historical_path = _validate_descriptor(
        failed["historical_completion"], label="vLLM historical completion"
    )
    historical = _load_json(historical_path, label="vLLM historical completion")
    vllm_units, _old_root = build_vllm_units(
        historical, _historical_specs(historical)
    )
    vllm_template = next(unit for unit in vllm_units if unit.unit_id == LLAVA_UNIT)
    vllm_state = _validate_descriptor(
        failed["unit_results"][LLAVA_UNIT]["state"],
        label="LLaVA failed-output state",
    )
    sources.append((vllm_template, vllm_state, True, LLAVA_UNIT))

    if only_original_units is not None:
        requested = tuple(only_original_units)
        if len(set(requested)) != len(requested) or any(
            unit not in ORIGINAL_UNIT_ORDER for unit in requested
        ):
            raise ValueError("failed-output recovery unit filter changed")
        sources = [row for row in sources if row[3] in set(requested)]
        if [row[3] for row in sources] != list(requested):
            raise ValueError("failed-output recovery unit filter order changed")

    prepared: list[tuple[Unit, Path, str, dict[str, object], bool, str]] = []
    for template, state, hub_required, original in sources:
        physical = physical_unit_id(original)
        unit, selector, digest, snapshot = _recovery_unit(
            template,
            state_path=state,
            control_root=control_root,
            unit_id=physical,
        )
        prepared.append(
            (unit, selector, digest, snapshot, hub_required, original)
        )
    return prepared


def _validate_metric_result(
    result: object,
    *,
    physical_unit: str,
    original_unit: str,
    selected_records: int,
    runner_root: Path,
    control_root: Path,
    completion: Mapping[str, object],
) -> dict[str, Any]:
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
        raise ValueError(f"{physical_unit} recovery result contract changed")
    successful = result.get("successful_target_generations")
    missing = result.get("missing_responses")
    source_lane = result.get("source_lane")
    corpus = result.get("corpus")
    if (
        result.get("status") != "complete"
        or result.get("unit_id") != physical_unit
        or result.get("original_unit_id") != original_unit
        or not isinstance(source_lane, str)
        or not source_lane
        or (corpus is not None and not isinstance(corpus, str))
        or result.get("selected_records") != selected_records
        or result.get("target_answer_retries") != 1
        or result.get("target_call_cap") != selected_records * 2
        or result.get("target_attempts") != selected_records
        or isinstance(successful, bool)
        or not isinstance(successful, int)
        or successful < 0
        or isinstance(missing, bool)
        or not isinstance(missing, int)
        or missing < 0
        or successful + missing != selected_records
    ):
        raise ValueError(f"{physical_unit} recovery accounting changed")

    result_root = Path(str(result.get("result_root", "")))
    expected_root = runner_root / physical_unit / control_root.name
    if (
        not result_root.is_absolute()
        or result_root.is_symlink()
        or result_root.resolve(strict=True) != expected_root
    ):
        raise ValueError(f"{physical_unit} recovery result root changed")
    state_path = _validate_descriptor(
        result.get("state"), label=f"{physical_unit} state"
    )
    level1_path = _validate_descriptor(
        result.get("level1"), label=f"{physical_unit} Level 1 evidence"
    )
    expected_unit_root = control_root / "units" / physical_unit
    if (
        state_path != expected_unit_root / "state.json"
        or level1_path != expected_unit_root / "level1.json"
    ):
        raise ValueError(f"{physical_unit} recovery artifact placement changed")

    grids = sorted(result_root.glob("*.grid.json"))
    envelopes = sorted(result_root.glob("*.request-envelope.json"))
    eligibility = sorted(result_root.glob("eligibility-*.eligibility.json"))
    markers = sorted(result_root.glob("*.complete.json"))
    if (
        len(grids) != 1
        or len(envelopes) != 1
        or len(eligibility) != 1
        or not markers
    ):
        raise ValueError(f"{physical_unit} completed Runner artifacts changed")

    state = _load_json(state_path, label=f"{physical_unit} state")
    argv = state.get("runner_argv")
    if (
        set(state) != STATE_FIELDS
        or state.get("schema") != UNIT_STATE_SCHEMA
        or state.get("unit_id") != physical_unit
        or state.get("source_lane") != source_lane
        or state.get("corpus") != corpus
        or state.get("selected_records") != selected_records
        or state.get("target_answer_retries") != 1
        or state.get("target_call_cap") != selected_records * 2
        or state.get("result_root") != str(result_root)
        or not isinstance(argv, list)
        or any(not isinstance(item, str) for item in argv)
        or _option(argv, "--target-answer-retries") != "1"
    ):
        raise ValueError(f"{physical_unit} measured state changed")
    selector_path = Path(_option(argv, "--recovery-completed-prefix"))
    selector_sha = _option(argv, "--recovery-completed-prefix-sha256")
    expected_selector = control_root / "inputs" / f"{physical_unit}.json"
    if (
        selector_path != expected_selector
        or hashlib.sha256(
            _stable_file(selector_path, label=f"{physical_unit} recovery selector")
        ).hexdigest()
        != selector_sha
    ):
        raise ValueError(f"{physical_unit} recovery selector binding changed")
    selector = _load_json(selector_path, label=f"{physical_unit} recovery selector")
    corpora = selector.get("corpora") if isinstance(selector, dict) else None
    if (
        selector.get("schema") != "ura-recovery-completed-selection/1"
        or not isinstance(corpora, dict)
        or not corpora
    ):
        raise ValueError(f"{physical_unit} recovery selector contract changed")
    revision = _option(argv, "--project-revision-sha256")
    source = _option(argv, "--source-conformance-sha256")
    if HEX64.fullmatch(revision) is None or HEX64.fullmatch(source) is None:
        raise ValueError(f"{physical_unit} project/source stratum changed")
    evidence = {
        "completion": dict(completion),
        "physical_unit_id": physical_unit,
        "original_unit_id": original_unit,
        "grid": _descriptor(grids[0], label=f"{physical_unit} measured grid"),
        "request_envelope": _descriptor(
            envelopes[0], label=f"{physical_unit} request envelope"
        ),
        "eligibility_plan": _descriptor(
            eligibility[0], label=f"{physical_unit} eligibility plan"
        ),
        "completion_markers": [
            _descriptor(marker, label=f"{physical_unit} completion marker")
            for marker in markers
        ],
        "state": dict(result["state"]),
        "level1": dict(result["level1"]),
    }
    return {
        "revision": revision,
        "source": source,
        "root": str(result_root),
        "evidence": evidence,
        "grid": evidence["grid"],
        "eligibility_plan": evidence["eligibility_plan"],
        "completion_markers": evidence["completion_markers"],
        "successful": successful,
        "missing": missing,
    }


def validate_phase7_completion(
    completion_path: Path,
    *,
    runner_root: Path,
) -> dict[str, Any]:
    """Validate the exact six Runner 2.27 recovery strata for Phase 7."""

    resolved = completion_path.resolve(strict=True)
    runner_root = runner_root.resolve(strict=True)
    completion = _load_json(resolved, label="failed-output recovery completion")
    if completion.get("schema") == "ura-failed-output-recovery-phase6/2":
        from experiments.local_campaign.failed_output_recovery_continuation_phase6 import (
            validate_phase7_completion as validate_continuation_completion,
        )

        return validate_continuation_completion(resolved, runner_root=runner_root)
    fields = {
        "schema",
        "status",
        "controller_exit_code",
        "completed_at_utc",
        "expected_commit",
        "runner_code_version",
        "target_answer_retries",
        "launch",
        "input_snapshot",
        "unit_order",
        "unit_results",
        "unit_failures",
        "target_execution",
        "successful_rows_repeated",
        "input_incompatible_rows_retried",
        "cross_revision_pooling_permitted",
        "paid_provider_calls",
    }
    if (
        set(completion) != fields
        or completion.get("schema") != SCHEMA
        or completion.get("status") != "complete"
        or completion.get("controller_exit_code") != 0
        or HEX40.fullmatch(str(completion.get("expected_commit", ""))) is None
        or completion.get("runner_code_version") != "ura-runner/2.27"
        or completion.get("target_answer_retries") != 1
        or completion.get("unit_order") != list(EXPECTED_UNIT_ORDER)
        or completion.get("unit_failures") != {}
        or completion.get("successful_rows_repeated") != 0
        or completion.get("input_incompatible_rows_retried") != 0
        or completion.get("cross_revision_pooling_permitted") is not False
        or completion.get("paid_provider_calls") != 0
    ):
        raise ValueError("failed-output recovery completion contract changed")
    control_root = resolved.parent
    if (
        control_root.is_symlink()
        or control_root.resolve(strict=True) != control_root
        or control_root.parent.name != "engineering"
    ):
        raise ValueError("failed-output recovery control root is not canonical")
    launch_path = _validate_descriptor(
        completion.get("launch"), label="failed-output recovery launch"
    )
    snapshot_path = _validate_descriptor(
        completion.get("input_snapshot"), label="failed-output recovery snapshot"
    )
    launch = _load_json(launch_path, label="failed-output recovery launch")
    snapshot = _load_json(snapshot_path, label="failed-output recovery snapshot")
    if (
        launch_path != control_root / "launch.json"
        or snapshot_path != control_root / "input-snapshot.json"
        or launch.get("schema") != LAUNCH_SCHEMA
        or launch.get("runner_code_version") != "ura-runner/2.27"
        or launch.get("target_answer_retries") != 1
        or launch.get("unit_order") != list(EXPECTED_UNIT_ORDER)
        or launch.get("recovery_records") != EXPECTED_RECOVERY_ROWS
        or launch.get("successful_rows_repeated") != 0
        or launch.get("input_incompatible_rows_retried") != 0
        or launch.get("paid_provider_calls") != 0
        or snapshot.get("schema") != SNAPSHOT_SCHEMA
        or snapshot.get("recovery_records") != EXPECTED_RECOVERY_ROWS
        or snapshot.get("successful_rows_repeated") != 0
        or snapshot.get("input_incompatible_rows_retried") != 0
        or not isinstance(snapshot.get("units"), dict)
        or set(snapshot["units"]) != set(EXPECTED_UNIT_ORDER)
    ):
        raise ValueError("failed-output recovery launch or snapshot changed")

    results = completion.get("unit_results")
    if not isinstance(results, dict) or set(results) != set(EXPECTED_UNIT_ORDER):
        raise ValueError("failed-output recovery result inventory changed")
    completion_descriptor = _descriptor(
        resolved, label="failed-output recovery completion"
    )
    metric_roots: dict[str, str] = {}
    metric_evidence: dict[str, dict[str, object]] = {}
    metric_grids: list[dict[str, object]] = []
    metric_eligibility_plans: list[dict[str, object]] = []
    metric_completion_markers: list[dict[str, object]] = []
    revisions: set[str] = set()
    sources: set[str] = set()
    successful = 0
    missing = 0
    for physical, original, selected in zip(
        EXPECTED_UNIT_ORDER,
        ORIGINAL_UNIT_ORDER,
        EXPECTED_RECOVERY_COUNTS,
        strict=True,
    ):
        snapshot_unit = snapshot["units"].get(physical)
        summary = snapshot_unit.get("summary") if isinstance(snapshot_unit, dict) else None
        if (
            not isinstance(snapshot_unit, dict)
            or snapshot_unit.get("original_unit_id") != original
            or not isinstance(summary, dict)
            or summary.get("recovery_records") != selected
        ):
            raise ValueError(f"{physical} input snapshot changed")
        validated = _validate_metric_result(
            results.get(physical),
            physical_unit=physical,
            original_unit=original,
            selected_records=selected,
            runner_root=runner_root,
            control_root=control_root,
            completion=completion_descriptor,
        )
        revisions.add(str(validated["revision"]))
        sources.add(str(validated["source"]))
        metric_roots[physical] = str(validated["root"])
        metric_evidence[physical] = dict(validated["evidence"])
        metric_grids.append(dict(validated["grid"]))
        metric_eligibility_plans.append(dict(validated["eligibility_plan"]))
        metric_completion_markers.extend(validated["completion_markers"])
        successful += int(validated["successful"])
        missing += int(validated["missing"])
    target_execution = completion.get("target_execution")
    if (
        target_execution
        != {
            "target_attempts": EXPECTED_RECOVERY_ROWS,
            "successful_target_generations": successful,
            "missing_responses": missing,
        }
        or successful + missing != EXPECTED_RECOVERY_ROWS
        or len(revisions) != 1
        or len(sources) != 1
    ):
        raise ValueError("failed-output recovery aggregate accounting changed")
    revision = next(iter(revisions))
    return {
        "completion": completion_descriptor,
        "runner_code_version": "ura-runner/2.27",
        "output_policy_stratum": "runner_227_failed_output_recovery",
        "unit_order": list(EXPECTED_UNIT_ORDER),
        "original_unit_order": list(ORIGINAL_UNIT_ORDER),
        "terminal_states": {
            unit: "measured_complete" for unit in EXPECTED_UNIT_ORDER
        },
        "metric_lane_order": list(EXPECTED_UNIT_ORDER),
        "metric_roots": metric_roots,
        "metric_evidence": metric_evidence,
        "metric_grids": metric_grids,
        "metric_eligibility_plans": metric_eligibility_plans,
        "metric_completion_markers": metric_completion_markers,
        "revision_strata": {revision: list(EXPECTED_UNIT_ORDER)},
        "project_revision_receipt_sha256": revision,
        "source_conformance_sha256": next(iter(sources)),
        "target_execution": dict(target_execution),
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
        "cross_revision_pooling_permitted": False,
    }


def run(args: argparse.Namespace) -> int:
    if CODE_VERSION != "ura-runner/2.27":
        raise ValueError("failed-output recovery requires Runner 2.27")
    if HEX40.fullmatch(args.expected_commit) is None:
        raise ValueError("expected commit must be one lowercase Git object ID")
    project_root = args.project_root.resolve(strict=True)
    python = _project_python(project_root, args.python)
    work_root = args.work_root.resolve(strict=True)
    control_root = args.control_root
    if control_root.exists() or control_root.is_symlink():
        raise FileExistsError("fresh failed-output recovery root already exists")
    if (
        not control_root.is_absolute()
        or control_root.parent.resolve(strict=True) != work_root / "runs/engineering"
    ):
        raise ValueError("failed-output recovery root must be one direct campaign")
    project_revision = args.project_revision.resolve(strict=True)
    if hashlib.sha256(_stable_file(project_revision, label="project revision")).hexdigest() != args.project_revision_sha256:
        raise ValueError("project revision digest changed")

    control_root.mkdir(mode=0o700)
    for name in ("units", "inputs", "configs"):
        (control_root / name).mkdir(mode=0o700)
    prepared = _prepare_units(
        args, work_root=work_root, control_root=control_root
    )
    snapshot = {
        "schema": SNAPSHOT_SCHEMA,
        "created_at_utc": _utc_now(),
        "units": {
            unit.unit_id: {
                "original_unit_id": original,
                **source_snapshot,
            }
            for unit, _path, _sha, source_snapshot, _hub, original in prepared
        },
        "recovery_records": sum(unit.selected_records for unit, *_rest in prepared),
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
    }
    snapshot_path = control_root / "input-snapshot.json"
    _create_json(snapshot_path, snapshot)
    launch = {
        "schema": LAUNCH_SCHEMA,
        "started_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "execution_scope_id": args.execution_scope_id,
        "target_answer_retries": 1,
        "input_snapshot": _descriptor(snapshot_path, label="recovery input snapshot"),
        "unit_order": [unit.unit_id for unit, *_rest in prepared],
        "recovery_records": snapshot["recovery_records"],
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
        "paid_provider_calls": 0,
    }
    launch_path = control_root / "launch.json"
    _create_json(launch_path, launch)
    start_child_controller(
        work_root=work_root,
        control_root=control_root,
        campaign_id=control_root.name,
        release_commit=args.expected_commit,
        evidence_class="measured_local_failed_output_recovery",
        hard_stop_hours=336,
        tmux_socket=args.tmux_socket,
        tmux_session=args.tmux_session,
        target_execution=True,
    )

    results: dict[str, Any] = {}
    failures: dict[str, Any] = {}
    for unit, selector, selector_sha, _source, hub_required, original in prepared:
        try:
            result = _run_unit(
                unit,
                python=python,
                work_root=work_root,
                control_root=control_root,
                project_revision=project_revision,
                project_revision_sha256=args.project_revision_sha256,
                scope=args.execution_scope_id,
                recovery_path=selector,
                recovery_sha256=selector_sha,
                expected_commit=args.expected_commit,
                framework_lock_id=_framework_lock_id(),
                admission_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                tmux_socket=args.tmux_socket,
                tmux_session=args.tmux_session,
                state_schema=UNIT_STATE_SCHEMA,
                hub_acquisition_required=hub_required,
            )
            results[unit.unit_id] = {**result, "original_unit_id": original}
        except (
            KeyError,
            OSError,
            RuntimeError,
            subprocess.SubprocessError,
            TypeError,
            ValueError,
        ) as exc:
            failures[unit.unit_id] = {
                "status": "failed",
                "unit_id": unit.unit_id,
                "original_unit_id": original,
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
            }
    attempts = sum(int(row["target_attempts"]) for row in results.values())
    successful = sum(
        int(row["successful_target_generations"]) for row in results.values()
    )
    missing = sum(int(row["missing_responses"]) for row in results.values())
    status = "complete" if not failures else "complete_with_failures"
    completion = {
        "schema": SCHEMA,
        "status": status,
        "controller_exit_code": 0 if not failures else 1,
        "completed_at_utc": _utc_now(),
        "expected_commit": args.expected_commit,
        "runner_code_version": CODE_VERSION,
        "target_answer_retries": 1,
        "launch": _descriptor(launch_path, label="failed-output recovery launch"),
        "input_snapshot": _descriptor(
            snapshot_path, label="failed-output recovery snapshot"
        ),
        "unit_order": launch["unit_order"],
        "unit_results": results,
        "unit_failures": failures,
        "target_execution": {
            "target_attempts": attempts,
            "successful_target_generations": successful,
            "missing_responses": missing,
        },
        "successful_rows_repeated": 0,
        "input_incompatible_rows_retried": 0,
        "cross_revision_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    completion_path = control_root / "completion.json"
    _create_json(completion_path, completion)
    exit_code = int(completion["controller_exit_code"])
    with (control_root / ".exit").open("xb") as handle:
        handle.write(f"{exit_code}\n".encode("ascii"))
    publish_target_execution(
        work_root=work_root,
        control_root=control_root,
        target_attempts=attempts,
        successful_target_generations=successful,
    )
    finish_child_controller(
        work_root=work_root,
        control_root=control_root,
        exit_code=exit_code,
    )
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ollama-base-completion", type=Path, required=True)
    parser.add_argument("--ollama-base-completion-sha256", required=True)
    parser.add_argument("--ollama-interrupted-root", type=Path, required=True)
    parser.add_argument("--vllm-failed-completion", type=Path, required=True)
    parser.add_argument("--vllm-failed-completion-sha256", required=True)
    parser.add_argument("--control-root", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--project-revision", type=Path, required=True)
    parser.add_argument("--project-revision-sha256", required=True)
    parser.add_argument("--execution-scope-id", required=True)
    parser.add_argument("--tmux-socket", default="default")
    parser.add_argument("--tmux-session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as exc:
        print(f"failed-output recovery failed: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
