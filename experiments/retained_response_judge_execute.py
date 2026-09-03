"""Execute one sealed retained-response Haiku plan without target-model calls."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.human_audit import _joined_artifacts
from experiments.retained_response_judge import (
    _canonical,
    _regular_descriptor,
    build_plan,
    load_candidates,
    load_pricing_condition,
    validate_plan,
)
from ura.data_models import DataPoint, DialogTurn, Judgment, Response
from ura.judges.llm import LLMJudge
from ura.targets.api import AnthropicTarget, normalize_api_target_config


EXECUTION_SCHEMA = "ura-retained-response-judge-execution/1"
JUDGMENT_SCHEMA = "ura-retained-response-judge-artifact/1"
CIRCUIT_SCHEMA = "ura-retained-response-judge-circuit/1"
COMPLETION_SCHEMA = "ura-retained-response-judge-completion/1"
_LEDGER_FIELDS = frozenset(
    {
        "schema",
        "plan_id",
        "plan_sha256",
        "selected_outputs",
        "target_calls",
        "judge_calls_reserved",
        "http_attempts_reserved",
        "completed_judgments",
        "input_tokens",
        "output_tokens",
        "actual_cost_microusd",
        "conservative_cost_microusd",
        "state",
        "current_reservation",
    }
)


def _strict_json(payload: bytes, *, label: str) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"{label} contains duplicate JSON key {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(payload.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc


def _read_regular(path_value: Path, *, label: str, max_bytes: int) -> tuple[object, dict]:
    unresolved = Path(path_value)
    if unresolved.is_symlink():
        raise ValueError(f"{label} must be a regular non-symlink file")
    path = unresolved.resolve(strict=True)
    before = path.stat()
    if not path.is_file() or before.st_size <= 0 or before.st_size > max_bytes:
        raise ValueError(f"{label} is outside its file-size bound")
    payload = path.read_bytes()
    after = path.stat()
    digest = hashlib.sha256(payload).hexdigest()
    if (
        before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or len(payload) != before.st_size
    ):
        raise ValueError(f"{label} changed while it was read")
    return _strict_json(payload, label=label), {
        "file": path.name,
        "sha256": digest,
        "bytes": len(payload),
    }


def _write_new(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"create-only artifact already exists: {path.name}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(_canonical(value))
        handle.flush()
        os.fsync(handle.fileno())


def _write_atomic(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("stale execution-ledger temporary file requires review")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(_canonical(value))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


@contextlib.contextmanager
def _exclusive_lock(root: Path):
    import fcntl

    lock_path = root / "execution.lock"
    handle = lock_path.open("a+b")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another retained-response judge executor is active") from exc
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _load_api_config(
    path: Path,
    *,
    judge_model: str,
    expected_sha256: str,
) -> tuple[dict[str, object], dict[str, object]]:
    raw, descriptor = _read_regular(
        path,
        label="judge API config",
        max_bytes=1024 * 1024,
    )
    if descriptor["sha256"] != expected_sha256:
        raise ValueError("judge API config SHA-256 does not match the sealed plan")
    if not isinstance(raw, dict) or judge_model not in raw:
        raise ValueError("judge API config lacks the exact selected Haiku route")
    config = raw[judge_model]
    if not isinstance(config, dict):
        raise ValueError("selected Haiku API config must be a JSON object")
    normalized = normalize_api_target_config(judge_model, config)
    return normalized, descriptor


def _build_haiku_judge(spec: str, config: Mapping[str, object]) -> AnthropicTarget:
    provider, model = spec.split(":", 1)
    if provider != "anthropic" or not model.startswith("claude-haiku-"):
        raise ValueError("retained-response executor accepts only exact Anthropic Haiku")
    return AnthropicTarget(
        model,
        requested_spec=spec,
        max_tokens=int(config["max_tokens"]),
        temperature=(
            None if config["temperature"] is None else float(config["temperature"])
        ),
        modality_support=config["modalities"],
        max_retries=0,
    )


def _reconcile_selection(
    runner_view: Path,
    plan: dict[str, Any],
    source_descriptor: Mapping[str, object],
) -> list[tuple[dict[str, Any], str, str]]:
    candidates, audit = load_candidates(runner_view)
    rebuilt = build_plan(
        candidates,
        population_audit=audit,
        source_descriptor=source_descriptor,
        judge_model=plan["judge_condition"]["model"],
        api_config_sha256=plan["judge_condition"]["api_config_sha256"],
        pricing_condition={
            field: plan["judge_condition"][field]
            for field in (
                "pricing_config_sha256",
                "pricing_as_of",
                "pricing_effective_date",
                "pricing_currency",
                "input_microusd_per_token",
                "output_microusd_per_token",
            )
        },
        limit=plan["selection"]["requested_limit"],
        seed=plan["selection"]["sample_seed"],
        max_cost_microusd=plan["judge_condition"]["max_cost_microusd"],
    )
    if rebuilt != plan:
        raise ValueError("retained-response plan no longer matches the validated Runner view")
    _per_judge, metadata, _judgments, _audit = _joined_artifacts(
        Path(runner_view).resolve(strict=True),
        frame="common",
    )
    reconciled: list[tuple[dict[str, Any], str, str]] = []
    for row in plan["selected"]:
        meta = metadata.get(row["sample_key"])
        if not isinstance(meta, dict):
            raise ValueError("selected retained response disappeared from the Runner view")
        prompt_value = meta.get("prepared_prompt")
        response_value = meta.get("prepared_response")
        if not isinstance(prompt_value, str) or not isinstance(response_value, str):
            raise ValueError("selected retained-response content is not text")
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
            raise ValueError("selected retained-response content identity changed")
        reconciled.append((row, prompt, response))
    return reconciled


def _judge_inputs(
    row: Mapping[str, Any], prompt: str, response_text: str
) -> tuple[DataPoint, Response]:
    physical = row["modality"] in {"image", "audio", "video"}
    datapoint = DataPoint(
        id=row["datapoint_id"],
        source=row["source"],
        modalities=[row["modality"]],
        payload_text=None if physical else prompt,
        risk_category=row["risk"],
        expected_behavior=row["expected_behavior"],
        meta=(
            {
                "judge_reference_text": prompt,
                "automated_metric_scope": "source_text_reference_plus_target_output_proxy",
                "physical_media_directly_available": False,
            }
            if physical
            else {}
        ),
    )
    response = Response(
        attempt_id=row["attempt_id"],
        target=row["exact_model"],
        output_turns=[DialogTurn(role="assistant", content=response_text)],
        raw={
            "requested_seed": row["requested_seed"],
            "retained_response": True,
            "retained_row_sha256": row["retained_row_sha256"],
        },
        run_id=row["run_id"],
    )
    return datapoint, response


def _cost_bounds(
    judge: LLMJudge,
    items: Sequence[tuple[dict[str, Any], str, str]],
    *,
    max_output_tokens: int,
) -> dict[str, int]:
    result: dict[str, int] = {}
    for row, prompt, response_text in items:
        datapoint, response = _judge_inputs(row, prompt, response_text)
        rubric = judge.rubric.format(
            forbidden_prompt=judge._forbidden_prompt(datapoint),
            response=judge._response_text(response),
        )
        # A byte-level upper bound is deliberately conservative for the text
        # tokenizer. The fixed allowance covers the system message and provider
        # message framing without requiring an unbudgeted token-count API call.
        input_bound = len(rubric.encode("utf-8")) + 256
        result[row["retained_row_sha256"]] = input_bound + max_output_tokens * 5
    return result


def _validate_ledger(value: object, plan: Mapping[str, Any], plan_sha256: str) -> dict:
    if not isinstance(value, dict) or set(value) != _LEDGER_FIELDS:
        raise ValueError("retained-response execution ledger fields changed")
    selected = len(plan["selected"])
    integers = (
        "selected_outputs",
        "target_calls",
        "judge_calls_reserved",
        "http_attempts_reserved",
        "completed_judgments",
        "input_tokens",
        "output_tokens",
        "actual_cost_microusd",
        "conservative_cost_microusd",
    )
    if any(
        isinstance(value.get(field), bool)
        or not isinstance(value.get(field), int)
        or value[field] < 0
        for field in integers
    ):
        raise ValueError("retained-response execution ledger count is invalid")
    if (
        value["schema"] != EXECUTION_SCHEMA
        or value["plan_id"] != plan["plan_id"]
        or value["plan_sha256"] != plan_sha256
        or value["selected_outputs"] != selected
        or value["target_calls"] != 0
        or value["judge_calls_reserved"] != value["http_attempts_reserved"]
        or value["completed_judgments"] > value["judge_calls_reserved"]
        or value["judge_calls_reserved"] > selected
        or value["actual_cost_microusd"] != value["input_tokens"]
        + value["output_tokens"] * 5
        or value["actual_cost_microusd"]
        > plan["judge_condition"]["max_cost_microusd"]
        or value["state"] not in {"active", "reserved", "circuit_open", "complete"}
        or (
            value["state"] == "reserved"
            and not isinstance(value["current_reservation"], dict)
        )
        or (
            value["state"] != "reserved"
            and value["current_reservation"] is not None
        )
        or (
            value["state"] == "active"
            and value["judge_calls_reserved"] != value["completed_judgments"]
        )
        or (
            value["state"] == "reserved"
            and value["judge_calls_reserved"] != value["completed_judgments"] + 1
        )
        or (
            value["state"] == "complete"
            and (
                value["completed_judgments"] != selected
                or value["judge_calls_reserved"] != selected
            )
        )
        or value["state"] == "circuit_open"
    ):
        raise ValueError("retained-response execution ledger contract changed")
    return value


def _judgment_path(root: Path, index: int, row: Mapping[str, Any]) -> Path:
    return root / "judgments" / (
        f"{index + 1:04d}-{row['retained_row_sha256'][:24]}.json"
    )


def _validate_artifact(
    value: object,
    *,
    plan: Mapping[str, Any],
    index: int,
    row: Mapping[str, Any],
) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "plan_id",
        "selection_index",
        "retained_row_sha256",
        "sample_key",
        "same_model_judge",
        "judgment",
        "input_tokens",
        "output_tokens",
        "cost_microusd",
    }:
        raise ValueError("retained-response judgment artifact fields changed")
    judgment = Judgment.model_validate(value.get("judgment"))
    call = judgment.raw.get("judge_call")
    if (
        value["schema"] != JUDGMENT_SCHEMA
        or value["plan_id"] != plan["plan_id"]
        or value["selection_index"] != index
        or value["retained_row_sha256"] != row["retained_row_sha256"]
        or value["sample_key"] != row["sample_key"]
        or value["same_model_judge"] is not row["same_model_judge"]
        or judgment.attempt_id != row["attempt_id"]
        or judgment.raw.get("judge_model") != plan["judge_condition"]["model"]
        or judgment.raw.get("judge_model_queried") is not True
        or not isinstance(call, dict)
        or call.get("transport_attempt_count") != 1
    ):
        raise ValueError("retained-response judgment artifact contract changed")
    input_tokens = value.get("input_tokens")
    output_tokens = value.get("output_tokens")
    cost = value.get("cost_microusd")
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in (input_tokens, output_tokens, cost)
    ) or cost != input_tokens + output_tokens * 5:
        raise ValueError("retained-response judgment usage is invalid")
    return value


def _artifact_usage(value: Mapping[str, Any]) -> tuple[int, int, int]:
    return value["input_tokens"], value["output_tokens"], value["cost_microusd"]


def _validate_completion(
    value: object,
    *,
    plan: Mapping[str, Any],
    ledger: Mapping[str, Any],
    plan_sha256: str,
) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "plan_id",
        "plan_sha256",
        "selected_outputs",
        "target_calls",
        "judge_calls",
        "http_attempts",
        "input_tokens",
        "output_tokens",
        "actual_cost_microusd",
        "max_cost_microusd",
        "independent_judge_rows",
        "same_model_judge_rows",
        "physical_media_sent_to_judge",
    }:
        raise ValueError("retained-response completion fields changed")
    condition = plan["judge_condition"]
    if (
        value["schema"] != COMPLETION_SCHEMA
        or value["status"] != "complete"
        or value["plan_id"] != plan["plan_id"]
        or value["plan_sha256"] != plan_sha256
        or value["selected_outputs"] != len(plan["selected"])
        or value["target_calls"] != 0
        or value["judge_calls"] != ledger["completed_judgments"]
        or value["http_attempts"] != ledger["http_attempts_reserved"]
        or value["input_tokens"] != ledger["input_tokens"]
        or value["output_tokens"] != ledger["output_tokens"]
        or value["actual_cost_microusd"] != ledger["actual_cost_microusd"]
        or value["max_cost_microusd"] != condition["max_cost_microusd"]
        or value["independent_judge_rows"] != condition["independent_judge_rows"]
        or value["same_model_judge_rows"] != condition["same_model_judge_rows"]
        or value["physical_media_sent_to_judge"] is not False
    ):
        raise ValueError("retained-response completion contract changed")
    return value


def execute(
    *,
    plan_path: Path,
    runner_view: Path,
    source_receipt: Path,
    api_config: Path,
    pricing_config: Path,
    out: Path,
    judge_factory: Callable[[str, Mapping[str, object]], Any] = _build_haiku_judge,
    plan_validator: Callable[[object], dict[str, Any]] = validate_plan,
    selection_reconciler: Callable[
        [Path, dict[str, Any], Mapping[str, object]],
        list[tuple[dict[str, Any], str, str]],
    ] = _reconcile_selection,
) -> Path:
    raw_plan, plan_descriptor = _read_regular(
        plan_path,
        label="retained-response judge plan",
        max_bytes=32 * 1024 * 1024,
    )
    plan = plan_validator(raw_plan)
    source_descriptor = _regular_descriptor(
        source_receipt,
        str(plan["source"]["sha256"]),
    )
    if source_descriptor != plan["source"]:
        raise ValueError("source receipt descriptor differs from the sealed plan")
    condition = plan["judge_condition"]
    observed_pricing = load_pricing_condition(
        pricing_config,
        expected_sha256=condition["pricing_config_sha256"],
        judge_model=condition["model"],
        as_of=condition["pricing_as_of"],
    )
    if any(condition[field] != item for field, item in observed_pricing.items()):
        raise ValueError("pricing condition differs from the sealed plan")
    normalized_api, _api_descriptor = _load_api_config(
        api_config,
        judge_model=condition["model"],
        expected_sha256=condition["api_config_sha256"],
    )
    items = selection_reconciler(runner_view, plan, source_descriptor)

    root = Path(out)
    if root.is_symlink():
        raise ValueError("retained-response execution root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = root.resolve(strict=True)
    judgments_dir = root / "judgments"
    if judgments_dir.is_symlink():
        raise ValueError("retained-response judgments directory must not be a symlink")
    judgments_dir.mkdir(mode=0o700, exist_ok=True)
    ledger_path = root / "execution.json"
    circuit_path = root / "circuit.json"
    completion_path = root / "completion.json"

    with _exclusive_lock(root):
        if circuit_path.exists() or circuit_path.is_symlink():
            raise RuntimeError("paid_provider circuit is open; investigate before new work")
        judge_target = judge_factory(condition["model"], normalized_api)
        if (
            getattr(judge_target, "max_retries", None) != 0
            or getattr(judge_target, "sdk_max_retries", None) != 0
            or getattr(judge_target, "max_transport_attempts_per_call", None) != 1
        ):
            raise ValueError("Haiku judge transport is not fixed to one attempt")
        judge = LLMJudge(judge_target)
        bounds = _cost_bounds(
            judge,
            items,
            max_output_tokens=int(normalized_api["max_tokens"]),
        )
        conservative_total = sum(bounds.values())
        if bounds[items[0][0]["retained_row_sha256"]] > condition["max_cost_microusd"]:
            raise ValueError("the first Haiku call could exceed the sealed USD ceiling")

        if ledger_path.exists() or ledger_path.is_symlink():
            raw_ledger, _descriptor = _read_regular(
                ledger_path,
                label="retained-response execution ledger",
                max_bytes=1024 * 1024,
            )
            ledger = _validate_ledger(raw_ledger, plan, plan_descriptor["sha256"])
            if ledger["conservative_cost_microusd"] != conservative_total:
                raise ValueError("retained-response conservative cost bound changed")
        else:
            ledger = {
                "schema": EXECUTION_SCHEMA,
                "plan_id": plan["plan_id"],
                "plan_sha256": plan_descriptor["sha256"],
                "selected_outputs": len(items),
                "target_calls": 0,
                "judge_calls_reserved": 0,
                "http_attempts_reserved": 0,
                "completed_judgments": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "actual_cost_microusd": 0,
                "conservative_cost_microusd": conservative_total,
                "state": "active",
                "current_reservation": None,
            }
            _write_atomic(ledger_path, ledger)

        expected_names = {
            _judgment_path(root, index, row).name
            for index, (row, _prompt, _response) in enumerate(items)
        }
        actual_names = {path.name for path in judgments_dir.glob("*.json")}
        if actual_names - expected_names:
            raise ValueError("unexpected retained-response judgment artifact exists")

        if ledger["state"] == "reserved":
            reservation = ledger["current_reservation"]
            index = reservation.get("selection_index")
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or index != ledger["completed_judgments"]
                or not 0 <= index < len(items)
            ):
                raise ValueError("current paid judge reservation is invalid")
            row = items[index][0]
            artifact_path = _judgment_path(root, index, row)
            if not artifact_path.exists():
                raise RuntimeError(
                    "paid judge call has an unresolved durable reservation; manual audit required"
                )
            artifact_raw, _descriptor = _read_regular(
                artifact_path,
                label="retained-response judgment artifact",
                max_bytes=1024 * 1024,
            )
            artifact = _validate_artifact(
                artifact_raw,
                plan=plan,
                index=index,
                row=row,
            )
            input_tokens, output_tokens, cost = _artifact_usage(artifact)
            ledger["completed_judgments"] += 1
            ledger["input_tokens"] += input_tokens
            ledger["output_tokens"] += output_tokens
            ledger["actual_cost_microusd"] += cost
            ledger["state"] = "active"
            ledger["current_reservation"] = None
            _write_atomic(ledger_path, ledger)

        completed = ledger["completed_judgments"]
        for index, (row, _prompt, _response) in enumerate(items):
            artifact_path = _judgment_path(root, index, row)
            if index < completed:
                artifact_raw, _descriptor = _read_regular(
                    artifact_path,
                    label="retained-response judgment artifact",
                    max_bytes=1024 * 1024,
                )
                _validate_artifact(artifact_raw, plan=plan, index=index, row=row)
            elif artifact_path.exists() or artifact_path.is_symlink():
                raise ValueError("judgment artifact is ahead of the durable ledger")

        if completion_path.exists() or completion_path.is_symlink():
            if completed != len(items) or ledger["state"] != "complete":
                raise ValueError("completion exists before the execution ledger is complete")
            completion_raw, _descriptor = _read_regular(
                completion_path,
                label="retained-response completion",
                max_bytes=1024 * 1024,
            )
            _validate_completion(
                completion_raw,
                plan=plan,
                ledger=ledger,
                plan_sha256=plan_descriptor["sha256"],
            )
            return completion_path.resolve(strict=True)

        for index in range(completed, len(items)):
            row, prompt, response_text = items[index]
            bound = bounds[row["retained_row_sha256"]]
            if ledger["actual_cost_microusd"] + bound > condition["max_cost_microusd"]:
                budget_circuit = {
                    "schema": CIRCUIT_SCHEMA,
                    "status": "open",
                    "dependency": "budget",
                    "plan_id": plan["plan_id"],
                    "selection_index": index,
                    "retained_row_sha256": row["retained_row_sha256"],
                    "error_type": "HaikuCostCeiling",
                    "error_category": "budget_ceiling",
                    "call_audit": None,
                    "target_calls": 0,
                    "judge_calls_reserved": ledger["judge_calls_reserved"],
                    "http_attempts_reserved": ledger["http_attempts_reserved"],
                    "cost_status": "known_before_call",
                }
                _write_new(circuit_path, budget_circuit)
                ledger["state"] = "circuit_open"
                ledger["current_reservation"] = None
                _write_atomic(ledger_path, ledger)
                raise RuntimeError(
                    "Haiku cost ceiling blocks the next call; no HTTP attempt was made"
                )
            if ledger["judge_calls_reserved"] != index:
                raise ValueError("paid judge reservation count is not a strict prefix")
            ledger["judge_calls_reserved"] += 1
            ledger["http_attempts_reserved"] += 1
            ledger["state"] = "reserved"
            ledger["current_reservation"] = {
                "selection_index": index,
                "retained_row_sha256": row["retained_row_sha256"],
                "conservative_cost_microusd": bound,
            }
            _write_atomic(ledger_path, ledger)

            datapoint, response = _judge_inputs(row, prompt, response_text)
            try:
                judgment = judge.judge(datapoint, response)
                call = judgment.raw.get("judge_call")
                tokens = call.get("tokens") if isinstance(call, dict) else None
                if (
                    not isinstance(tokens, dict)
                    or isinstance(tokens.get("input"), bool)
                    or not isinstance(tokens.get("input"), int)
                    or tokens["input"] < 0
                    or isinstance(tokens.get("output"), bool)
                    or not isinstance(tokens.get("output"), int)
                    or tokens["output"] < 0
                ):
                    raise ValueError("Haiku judgment lacks exact input/output token usage")
                cost = tokens["input"] + tokens["output"] * 5
                if cost > bound:
                    raise ValueError("actual Haiku usage exceeded its conservative bound")
                artifact = {
                    "schema": JUDGMENT_SCHEMA,
                    "plan_id": plan["plan_id"],
                    "selection_index": index,
                    "retained_row_sha256": row["retained_row_sha256"],
                    "sample_key": row["sample_key"],
                    "same_model_judge": row["same_model_judge"],
                    "judgment": judgment.model_dump(mode="json"),
                    "input_tokens": tokens["input"],
                    "output_tokens": tokens["output"],
                    "cost_microusd": cost,
                }
                _validate_artifact(artifact, plan=plan, index=index, row=row)
                _write_new(_judgment_path(root, index, row), artifact)
            except Exception as exc:
                call_audit = getattr(exc, "call_audit", None)
                circuit = {
                    "schema": CIRCUIT_SCHEMA,
                    "status": "open",
                    "dependency": "paid_provider",
                    "plan_id": plan["plan_id"],
                    "selection_index": index,
                    "retained_row_sha256": row["retained_row_sha256"],
                    "error_type": type(exc).__name__,
                    "error_category": getattr(exc, "category", None),
                    "call_audit": call_audit if isinstance(call_audit, dict) else None,
                    "target_calls": 0,
                    "judge_calls_reserved": ledger["judge_calls_reserved"],
                    "http_attempts_reserved": ledger["http_attempts_reserved"],
                    "cost_status": "unknown_within_conservative_reservation",
                }
                _write_new(circuit_path, circuit)
                ledger["state"] = "circuit_open"
                ledger["current_reservation"] = None
                _write_atomic(ledger_path, ledger)
                raise RuntimeError(
                    "paid_provider circuit opened on the first judge failure"
                ) from exc

            input_tokens, output_tokens, cost = _artifact_usage(artifact)
            ledger["completed_judgments"] += 1
            ledger["input_tokens"] += input_tokens
            ledger["output_tokens"] += output_tokens
            ledger["actual_cost_microusd"] += cost
            ledger["state"] = "active"
            ledger["current_reservation"] = None
            if ledger["actual_cost_microusd"] > condition["max_cost_microusd"]:
                raise AssertionError("sealed Haiku cost ceiling was exceeded")
            _write_atomic(ledger_path, ledger)

        ledger["state"] = "complete"
        _write_atomic(ledger_path, ledger)
        completion = {
            "schema": COMPLETION_SCHEMA,
            "status": "complete",
            "plan_id": plan["plan_id"],
            "plan_sha256": plan_descriptor["sha256"],
            "selected_outputs": len(items),
            "target_calls": 0,
            "judge_calls": ledger["completed_judgments"],
            "http_attempts": ledger["http_attempts_reserved"],
            "input_tokens": ledger["input_tokens"],
            "output_tokens": ledger["output_tokens"],
            "actual_cost_microusd": ledger["actual_cost_microusd"],
            "max_cost_microusd": condition["max_cost_microusd"],
            "independent_judge_rows": condition["independent_judge_rows"],
            "same_model_judge_rows": condition["same_model_judge_rows"],
            "physical_media_sent_to_judge": False,
        }
        _validate_completion(
            completion,
            plan=plan,
            ledger=ledger,
            plan_sha256=plan_descriptor["sha256"],
        )
        _write_new(completion_path, completion)
        return completion_path.resolve(strict=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--runner-view", type=Path, required=True)
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
            runner_view=args.runner_view,
            source_receipt=args.source_receipt,
            api_config=args.api_config,
            pricing_config=args.pricing_config,
            out=args.out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
