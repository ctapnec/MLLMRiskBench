"""Execute one sealed retained-response Haiku plan without target-model calls."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.retained_response_judge import (
    _canonical,
    _regular_descriptor,
    build_plan,
    load_candidates,
    load_pricing_condition,
    load_retained_metadata,
    validate_plan,
)
from ura.data_models import DataPoint, DialogTurn, Judgment, Response
from ura.judges.llm import LLMJudge, LLMJudgeOutputError
from ura.targets.api import (
    AnthropicTarget,
    DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
    normalize_api_target_config,
    provider_attempt_admission,
)


EXECUTION_SCHEMA = "ura-retained-response-judge-execution/2"
JUDGMENT_SCHEMA = "ura-retained-response-judge-artifact/2"
CIRCUIT_SCHEMA = "ura-retained-response-judge-circuit/2"
COMPLETION_SCHEMA = "ura-retained-response-judge-completion/2"
OUTCOME_EXECUTION_SCHEMA = "ura-retained-response-judge-execution/3"
INVALID_JUDGMENT_SCHEMA = "ura-retained-response-judge-artifact/3"
OUTCOME_COMPLETION_SCHEMA = "ura-retained-response-judge-completion/3"
SHARED_ESTIMATE_METHOD = "canonical_request_utf8_bytes_plus_256_conservative_estimate_v1"
_LEDGER_FIELDS = frozenset(
    {
        "schema",
        "plan_id",
        "plan_sha256",
        "selected_outputs",
        "target_calls",
        "judge_calls_reserved",
        "http_attempts_reserved",
        "http_attempts_observed",
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
    from ura.validation_cache import observe_validation_path
    observe_validation_path(path_value)
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
    # Different threads in one provider share a PID. Each publication needs
    # its own temporary file; the final replacement remains atomic.
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(temporary_name)
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
        max_retries=DEFAULT_HOSTED_HTTP_ERROR_RETRIES,
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
    root = Path(runner_view).resolve(strict=True)
    metadata = load_retained_metadata(root)
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


def build_shared_request_receipts(
    items: Sequence[tuple[dict[str, Any], str, str]], *, judge_model: str,
    normalized_api: Mapping[str, object], call_ids: Mapping[str, str],
    token_counts: Mapping[str, dict] | None = None,
) -> dict[str, dict]:
    """No-client full-rubric previews with conservative token estimates.

    UTF8 bytes plus framing are neither a provider count nor a proved billing
    bound. The exact request hash and separately funded microUSD reservation
    remain distinct; above-reservation actual usage is retained and stops spend.
    """
    target = _build_haiku_judge(judge_model, normalized_api)
    judge = LLMJudge(target)
    if set(call_ids) != {row["retained_row_sha256"] for row, _, _ in items}:
        raise ValueError("shared judge call IDs differ from the exact retained selection")
    if token_counts is not None and (not isinstance(token_counts, Mapping) or set(token_counts) != set(call_ids)):
        raise ValueError("shared token counts differ from the complete retained selection")
    result = {}
    for row, prompt, text in items:
        datapoint, response = _judge_inputs(row, prompt, text)
        request = target.build_request(judge.build_judge_dialog(datapoint, response), seed=judge._judge_seed(response))
        payload = _canonical(request)
        key = row["retained_row_sha256"]
        result[key] = {"call_id": call_ids[key], "request_sha256": hashlib.sha256(payload).hexdigest(),
                       "input_tokens_estimate": len(payload) + 256,
                       "max_output_tokens": int(normalized_api["max_tokens"])}
        if token_counts is not None:
            from experiments.hosted_request_tokens import validate_receipt
            count = validate_receipt(target, request, token_counts[key])
            result[key].update(input_tokens_estimate=count["input_tokens"], token_count_receipt=count)
    return result


def _shared_binding(budget, requests, items, condition, normalized_api, plan_sha256):
    # Lazy import: the money primitive reuses this module's persistence helpers.
    from experiments.hosted_attempt_budget import AttemptBudget
    if not isinstance(budget, AttemptBudget) or not isinstance(requests, Mapping):
        raise ValueError("shared judge execution requires its budget and full request receipts")
    if any(not isinstance(value, dict) for value in requests.values()):
        raise ValueError("shared judge request receipt is not an object")
    counts = {key: value["token_count_receipt"] for key, value in requests.items()
              if "token_count_receipt" in value}
    expected = build_shared_request_receipts(items, judge_model=condition["model"], normalized_api=normalized_api,
                                           call_ids={key: value.get("call_id") for key, value in requests.items()},
                                           token_counts=counts if counts else None)
    if requests != expected:
        raise ValueError("shared full-rubric request or token estimate changed")
    call_ids = [value["call_id"] for value in expected.values()]
    if any(not isinstance(value, str) or not value for value in call_ids) or len(set(call_ids)) != len(call_ids):
        raise ValueError("shared retained judge call IDs are not distinct funded slots")
    if budget.liability(call_ids) > condition["max_cost_microusd"]:
        raise ValueError("shared judge first commitments or retained exposure exceed this plan's ceiling")
    bounds = {}
    for key, receipt in expected.items():
        slot = budget.call(receipt["call_id"])
        bound = (receipt["input_tokens_estimate"] * condition["input_microusd_per_token"]
                 + receipt["max_output_tokens"] * condition["output_microusd_per_token"])
        if slot["provider"] != "anthropic" or slot["pool"] != "judge" or slot["bound_microusd"] < bound:
            raise ValueError("full Haiku request is not covered by its dedicated funded judge slot")
        bounds[key] = slot["bound_microusd"]
    return {"schema": "ura-retained-response-shared-budget/1", "plan_sha256": plan_sha256,
            "budget_root": str(budget.root), "budget_plan_sha256": budget.expected_plan_sha256,
            "input_token_estimate_method": ("per_request_token_count_receipt_v1" if counts else SHARED_ESTIMATE_METHOD),
            "requests": expected}, bounds


def _open_shared_circuit(budget, row, exc):
    from experiments.hosted_attempt_budget import _budget_lock

    with _budget_lock(budget.root):
        path = budget.root / "paid-circuit.json"
        if not path.exists() and not path.is_symlink():
            _write_atomic(path, {"schema": "ura-hosted-paid-circuit/1", "status": "open",
                             "budget_plan_sha256": budget.expected_plan_sha256,
                             "retained_row_sha256": row["retained_row_sha256"], "error_type": type(exc).__name__})


def _settle_shared_artifact(budget, requests, row, artifact):
    receipt = requests[row["retained_row_sha256"]]
    # Only the last physical attempt produced this checkpoint. Every earlier
    # HTTP-error attempt stays unknown at its full independently held bound.
    budget.settle(receipt["call_id"], _artifact_http_attempts(artifact), artifact["cost_microusd"])


def _validate_ledger(value: object, plan: Mapping[str, Any], plan_sha256: str) -> dict:
    if not isinstance(value, dict) or set(value) != _LEDGER_FIELDS:
        raise ValueError("retained-response execution ledger fields changed")
    selected = len(plan["selected"])
    integers = (
        "selected_outputs",
        "target_calls",
        "judge_calls_reserved",
        "http_attempts_reserved",
        "http_attempts_observed",
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
        value["schema"] not in {EXECUTION_SCHEMA, OUTCOME_EXECUTION_SCHEMA}
        or value["plan_id"] != plan["plan_id"]
        or value["plan_sha256"] != plan_sha256
        or value["selected_outputs"] != selected
        or value["target_calls"] != 0
        or value["http_attempts_reserved"]
        != value["judge_calls_reserved"] * (DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1)
        or value["http_attempts_observed"] > value["http_attempts_reserved"]
        or value["http_attempts_observed"] < value["completed_judgments"]
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


def invalid_verdict_artifact(*, plan: Mapping[str, Any], index: int, row: Mapping[str, Any],
                             verdict: Response | None, reviewed_failure: Mapping[str, Any] | None = None) -> dict:
    """Retain an undecidable judge outcome, never a replacement safety label.

    The historical missing-reply case is operator-only: its immutable failure
    evidence is mandatory, usage stays unknown, and the money hold is not zeroed.
    """
    if verdict is None:
        if not isinstance(reviewed_failure, Mapping):
            raise ValueError("unretained judge verdict requires reviewed failure evidence")
        circuit = reviewed_failure.get("circuit")
        if (not isinstance(circuit, Mapping) or circuit.get("error_type") != "LLMJudgeOutputError"
            or circuit.get("plan_id") != plan["plan_id"] or circuit.get("selection_index") != index
            or circuit.get("retained_row_sha256") != row["retained_row_sha256"]
            or reviewed_failure.get("physical_attempts") != 1
            or not isinstance(reviewed_failure.get("sources"), list) or not reviewed_failure["sources"]):
            raise ValueError("reviewed invalid judge failure differs from its exact reserved input")
        for source in reviewed_failure["sources"]:
            if (not isinstance(source, Mapping) or set(source) != {"file", "sha256", "bytes"}
                or Path(str(source["file"])).name != source["file"]
                or type(source["bytes"]) is not int or source["bytes"] <= 0
                or not isinstance(source["sha256"], str) or len(source["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in source["sha256"])):
                raise ValueError("reviewed invalid judge failure evidence descriptor is invalid")
        input_tokens = output_tokens = cost = None
        call = {"tokens": {"input": None, "output": None}, "transport_attempt_count": 1,
                "provider_response_id": reviewed_failure.get("provider_response_id"),
                "usage_status": "unknown_retained_failure"}
    else:
        if reviewed_failure is not None or not LLMJudge._response_text(verdict):
            raise ValueError("empty judge output still requires investigation before continuation")
        if verdict.target != plan["judge_condition"]["model"]:
            raise ValueError("invalid verdict came from a different judge")
        try:
            LLMJudge._parse(LLMJudge.__new__(LLMJudge), LLMJudge._response_text(verdict))
        except LLMJudgeOutputError:
            pass
        else:
            raise ValueError("a valid rubric verdict cannot be relabelled as an abstention")
        tokens = verdict.tokens or {}
        input_tokens, output_tokens = tokens.get("input"), tokens.get("output")
        if any(type(value) is not int or value < 0 for value in (input_tokens, output_tokens)):
            raise ValueError("invalid judge verdict lacks exact usage")
        cost = input_tokens + output_tokens * 5
        call = {"tokens": dict(tokens), "transport_attempt_count": verdict.raw.get("transport_attempt_count"),
                "transport_attempts": verdict.raw.get("transport_attempts", []),
                "provider_response_id": verdict.raw.get("response_id") or verdict.raw.get("id"),
                "usage_status": "reported"}
    judgment = Judgment(attempt_id=row["attempt_id"], judge="llm-judge", label="not_applicable", score=0,
        rationale="The judge did not supply a complete unambiguous rubric verdict; no safety label is assigned.",
        raw={"parsed": False, "confidence": 0.0, "judge_model": plan["judge_condition"]["model"],
             "judge_model_queried": True, "judge_call": call, "judge_status": "invalid_verdict"})
    value = {"schema": INVALID_JUDGMENT_SCHEMA, "plan_id": plan["plan_id"], "selection_index": index,
        "retained_row_sha256": row["retained_row_sha256"], "sample_key": row["sample_key"],
        "same_model_judge": row["same_model_judge"], "judgment": judgment.model_dump(mode="json"),
        "input_tokens": input_tokens, "output_tokens": output_tokens, "cost_microusd": cost,
        "invalid_verdict": {"verdict": verdict.model_dump(mode="json") if verdict is not None else None,
                            "reviewed_failure": dict(reviewed_failure) if reviewed_failure is not None else None}}
    return value


def _validate_artifact(
    value: object,
    *,
    plan: Mapping[str, Any],
    index: int,
    row: Mapping[str, Any],
) -> dict:
    invalid = isinstance(value, dict) and value.get("schema") == INVALID_JUDGMENT_SCHEMA
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
    } | ({"invalid_verdict"} if invalid else set()):
        raise ValueError("retained-response judgment artifact fields changed")
    judgment = Judgment.model_validate(value.get("judgment"))
    call = judgment.raw.get("judge_call")
    if (
        value["schema"] not in {JUDGMENT_SCHEMA, INVALID_JUDGMENT_SCHEMA}
        or value["plan_id"] != plan["plan_id"]
        or value["selection_index"] != index
        or value["retained_row_sha256"] != row["retained_row_sha256"]
        or value["sample_key"] != row["sample_key"]
        or value["same_model_judge"] is not row["same_model_judge"]
        or judgment.attempt_id != row["attempt_id"]
        or judgment.raw.get("judge_model") != plan["judge_condition"]["model"]
        or judgment.raw.get("judge_model_queried") is not True
        or not isinstance(call, dict)
        or isinstance(call.get("transport_attempt_count"), bool)
        or not isinstance(call.get("transport_attempt_count"), int)
        or not 1
        <= call["transport_attempt_count"]
        <= DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1
    ):
        raise ValueError("retained-response judgment artifact contract changed")
    input_tokens = value.get("input_tokens")
    output_tokens = value.get("output_tokens")
    cost = value.get("cost_microusd")
    if invalid:
        failure = value["invalid_verdict"]
        if not isinstance(failure, dict) or set(failure) != {"verdict", "reviewed_failure"}:
            raise ValueError("invalid judge outcome lost its retained failure evidence")
        rebuilt = invalid_verdict_artifact(plan=plan, index=index, row=row,
            verdict=Response.model_validate(failure["verdict"]) if failure["verdict"] is not None else None,
            reviewed_failure=failure["reviewed_failure"])
        if value != rebuilt:
            raise ValueError("invalid judge outcome or reported usage differs from its evidence")
        if cost is None:
            return value
    if any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in (input_tokens, output_tokens, cost)
    ) or cost != input_tokens + output_tokens * 5:
        raise ValueError("retained-response judgment usage is invalid")
    return value


def _artifact_usage(value: Mapping[str, Any]) -> tuple[int, int, int]:
    # Arithmetic is a known-usage subtotal. Unknown remains null in the
    # artifact and fully reserved in the shared money ledger, never a free call.
    return tuple(value[key] if value[key] is not None else 0
                 for key in ("input_tokens", "output_tokens", "cost_microusd"))


def _artifact_http_attempts(value: Mapping[str, Any]) -> int:
    judgment = Judgment.model_validate(value["judgment"])
    return int(judgment.raw["judge_call"]["transport_attempt_count"])


def _validate_completion(
    value: object,
    *,
    plan: Mapping[str, Any],
    ledger: Mapping[str, Any],
    plan_sha256: str,
) -> dict:
    outcomes = ledger["schema"] == OUTCOME_EXECUTION_SCHEMA
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "plan_id",
        "plan_sha256",
        "selected_outputs",
        "target_calls",
        "judge_calls",
        "http_attempts",
        "http_attempts_reserved",
        "input_tokens",
        "output_tokens",
        "actual_cost_microusd",
        "max_cost_microusd",
        "independent_judge_rows",
        "same_model_judge_rows",
        "physical_media_sent_to_judge",
    } | ({"invalid_verdicts", "unknown_usage_judgments"} if outcomes else set()):
        raise ValueError("retained-response completion fields changed")
    condition = plan["judge_condition"]
    if (
        value["schema"] != (OUTCOME_COMPLETION_SCHEMA if outcomes else COMPLETION_SCHEMA)
        or value["status"] != "complete"
        or value["plan_id"] != plan["plan_id"]
        or value["plan_sha256"] != plan_sha256
        or value["selected_outputs"] != len(plan["selected"])
        or value["target_calls"] != 0
        or value["judge_calls"] != ledger["completed_judgments"]
        or value["http_attempts"] != ledger["http_attempts_observed"]
        or value["http_attempts_reserved"] != ledger["http_attempts_reserved"]
        or value["input_tokens"] != ledger["input_tokens"]
        or value["output_tokens"] != ledger["output_tokens"]
        or value["actual_cost_microusd"] != ledger["actual_cost_microusd"]
        or value["max_cost_microusd"] != condition["max_cost_microusd"]
        or value["independent_judge_rows"] != condition["independent_judge_rows"]
        or value["same_model_judge_rows"] != condition["same_model_judge_rows"]
        or value["physical_media_sent_to_judge"] is not False
    ):
        raise ValueError("retained-response completion contract changed")
    if outcomes and (any(type(value[key]) is not int for key in ("invalid_verdicts", "unknown_usage_judgments"))
        or not 0 <= value["unknown_usage_judgments"] <= value["invalid_verdicts"] <= len(plan["selected"])):
        raise ValueError("retained-response invalid-verdict coverage differs")
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
    shared_budget: Any = None,
    shared_requests: Mapping[str, dict] | None = None,
    retain_invalid_verdicts: bool = False,
) -> Path:
    if type(retain_invalid_verdicts) is not bool:
        raise ValueError("invalid-verdict retention policy must be explicit boolean")
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
    shared_binding = None
    shared_bounds = None
    if shared_budget is not None or shared_requests is not None:
        shared_binding, shared_bounds = _shared_binding(
            shared_budget, shared_requests, items, condition, normalized_api, plan_descriptor["sha256"]
        )
        shared_requests = shared_binding["requests"]

    root = Path(out)
    if root.is_symlink():
        raise ValueError("retained-response execution root must not be a symlink")
    if shared_binding is not None and root.resolve() == shared_budget.root:
        raise ValueError("shared budget and judgment execution require separate directories")
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
        shared_path = root / "shared-budget.json"
        if shared_binding is None:
            if shared_path.exists() or shared_path.is_symlink():
                raise ValueError("shared funded execution cannot resume without its original budget binding")
        else:
            if (shared_budget.root / "paid-circuit.json").exists() or (shared_budget.root / "paid-circuit.json").is_symlink():
                raise RuntimeError("shared paid-provider circuit is open; investigate before new work")
            if shared_path.exists() or shared_path.is_symlink():
                retained, _descriptor = _read_regular(shared_path, label="shared judge budget binding", max_bytes=32 * 1024 * 1024)
                if retained != shared_binding:
                    raise ValueError("shared judge request or budget continuation binding changed")
            else:
                if ledger_path.exists() or ledger_path.is_symlink():
                    raise ValueError("an existing unshared execution cannot acquire a new money binding")
                _write_new(shared_path, shared_binding)
        if circuit_path.exists() or circuit_path.is_symlink():
            raise RuntimeError("paid_provider circuit is open; investigate before new work")
        judge_target = judge_factory(condition["model"], normalized_api)
        if (
            getattr(judge_target, "max_retries", None)
            != DEFAULT_HOSTED_HTTP_ERROR_RETRIES
            or getattr(judge_target, "sdk_max_retries", None) != 0
            or getattr(judge_target, "max_transport_attempts_per_call", None)
            != DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1
        ):
            raise ValueError("Haiku judge HTTP-error retry policy changed")
        judge = LLMJudge(judge_target)
        bounds = _cost_bounds(
            judge,
            items,
            max_output_tokens=int(normalized_api["max_tokens"]),
        )
        if shared_binding is not None:
            bounds = shared_bounds
            # The actual target must use the same no-client preview as the
            # canonical Haiku route, including the full rubric and system text.
            for row, prompt, text in items:
                point, response = _judge_inputs(row, prompt, text)
                request = judge_target.build_request(judge.build_judge_dialog(point, response), seed=judge._judge_seed(response))
                if hashlib.sha256(_canonical(request)).hexdigest() != shared_requests[row["retained_row_sha256"]]["request_sha256"]:
                    raise ValueError("actual judge target request differs before client construction")
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
            if (ledger["schema"] == OUTCOME_EXECUTION_SCHEMA) != retain_invalid_verdicts:
                raise ValueError("invalid-verdict continuation policy differs from its execution")
            if ledger["conservative_cost_microusd"] != conservative_total:
                raise ValueError("retained-response conservative cost bound changed")
        else:
            ledger = {
                "schema": OUTCOME_EXECUTION_SCHEMA if retain_invalid_verdicts else EXECUTION_SCHEMA,
                "plan_id": plan["plan_id"],
                "plan_sha256": plan_descriptor["sha256"],
                "selected_outputs": len(items),
                "target_calls": 0,
                "judge_calls_reserved": 0,
                "http_attempts_reserved": 0,
                "http_attempts_observed": 0,
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
            if shared_binding is not None:
                _settle_shared_artifact(shared_budget, shared_requests, row, artifact)
            input_tokens, output_tokens, cost = _artifact_usage(artifact)
            ledger["completed_judgments"] += 1
            ledger["http_attempts_observed"] += _artifact_http_attempts(artifact)
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
                artifact = _validate_artifact(artifact_raw, plan=plan, index=index, row=row)
                if shared_binding is not None:
                    _settle_shared_artifact(shared_budget, shared_requests, row, artifact)
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
            ledger["http_attempts_reserved"] += DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1
            ledger["state"] = "reserved"
            ledger["current_reservation"] = {
                "selection_index": index,
                "retained_row_sha256": row["retained_row_sha256"],
                "conservative_cost_microusd": bound,
            }
            _write_atomic(ledger_path, ledger)

            datapoint, response = _judge_inputs(row, prompt, response_text)
            physical = {"last_reserved": 0}

            def reserve_physical(provider, request, number):
                receipt = shared_requests[row["retained_row_sha256"]]
                if (provider != "anthropic" or hashlib.sha256(_canonical(request)).hexdigest() != receipt["request_sha256"]
                        or number != physical["last_reserved"] + 1):
                    raise ValueError("physical Haiku request differs from its frozen funded receipt")
                if number > 1:
                    # The existing HTTP-only retry loop invoked this callback;
                    # this is not permission to reissue a crash-ambiguous call.
                    shared_budget.settle(receipt["call_id"], number - 1, None)
                increment = shared_budget.call(receipt["call_id"])["bound_microusd"] if number > 1 else 0
                if (shared_budget.liability([value["call_id"] for value in shared_requests.values()]) + increment
                        > condition["max_cost_microusd"]):
                    raise ValueError("physical retry exceeds this retained judge plan's own ceiling")
                shared_budget.reserve(receipt["call_id"], number, provider=provider)
                physical["last_reserved"] = number

            try:
                invalid_artifact = None
                try:
                    with provider_attempt_admission(reserve_physical) if shared_binding is not None else contextlib.nullcontext():
                        judgment = judge.judge(datapoint, response)
                except LLMJudgeOutputError as exc:
                    if not retain_invalid_verdicts or not isinstance(getattr(exc, "verdict", None), Response):
                        raise
                    invalid_artifact = invalid_verdict_artifact(plan=plan, index=index, row=row, verdict=exc.verdict)
                    judgment = Judgment.model_validate(invalid_artifact["judgment"])
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
                if cost > bound and shared_binding is None:
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
                if invalid_artifact is not None:
                    artifact = invalid_artifact
                _validate_artifact(artifact, plan=plan, index=index, row=row)
                if shared_binding is not None and _artifact_http_attempts(artifact) != physical["last_reserved"]:
                    raise ValueError("judgment checkpoint disagrees with its physical paid reservations")
                _write_new(_judgment_path(root, index, row), artifact)
                if shared_binding is not None:
                    directory_fd = os.open(judgments_dir, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            except Exception as exc:
                from experiments.hosted_attempt_budget import BudgetError
                if (shared_binding is not None and isinstance(exc, BudgetError)
                    and str(exc) == "shared paid-provider circuit is open"
                    and physical["last_reserved"] == 0
                    and shared_budget.reserved_attempt_count(
                        shared_requests[row["retained_row_sha256"]]["call_id"]) == 0):
                    # Another worker paused the shared campaign before this
                    # request reached HTTP. Keep its input pending, not billed
                    # or misclassified as an ambiguous failed judge response.
                    _write_atomic(root / f"shared-pause-{index:06d}.json", {
                        "status": "waiting_on_shared_budget", "plan_id": plan["plan_id"],
                        "selection_index": index, "retained_row_sha256": row["retained_row_sha256"],
                        "physical_http_attempts": 0, "completed_judgments": ledger["completed_judgments"],
                    })
                    ledger["judge_calls_reserved"] -= 1
                    ledger["http_attempts_reserved"] -= DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1
                    ledger["state"] = "active"
                    ledger["current_reservation"] = None
                    _write_atomic(ledger_path, ledger)
                    raise RuntimeError("shared campaign paused before judge HTTP; input remains unstarted") from exc
                if shared_binding is not None:
                    _open_shared_circuit(shared_budget, row, exc)
                    if physical["last_reserved"]:
                        shared_budget.settle(shared_requests[row["retained_row_sha256"]]["call_id"], physical["last_reserved"], None)
                call_audit = getattr(exc, "call_audit", None)
                observed_attempts = (
                    call_audit.get("transport_attempt_count")
                    if isinstance(call_audit, dict)
                    else None
                )
                if (
                    isinstance(observed_attempts, int)
                    and not isinstance(observed_attempts, bool)
                    and 1
                    <= observed_attempts
                    <= DEFAULT_HOSTED_HTTP_ERROR_RETRIES + 1
                ):
                    ledger["http_attempts_observed"] += observed_attempts
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

            if shared_binding is not None:
                # This follows the create-only judgment checkpoint. A disk
                # interruption here is reconciled from that checkpoint on resume.
                _settle_shared_artifact(shared_budget, shared_requests, row, artifact)
            input_tokens, output_tokens, cost = _artifact_usage(artifact)
            ledger["completed_judgments"] += 1
            ledger["http_attempts_observed"] += _artifact_http_attempts(artifact)
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
            "schema": OUTCOME_COMPLETION_SCHEMA if retain_invalid_verdicts else COMPLETION_SCHEMA,
            "status": "complete",
            "plan_id": plan["plan_id"],
            "plan_sha256": plan_descriptor["sha256"],
            "selected_outputs": len(items),
            "target_calls": 0,
            "judge_calls": ledger["completed_judgments"],
            "http_attempts": ledger["http_attempts_observed"],
            "http_attempts_reserved": ledger["http_attempts_reserved"],
            "input_tokens": ledger["input_tokens"],
            "output_tokens": ledger["output_tokens"],
            "actual_cost_microusd": ledger["actual_cost_microusd"],
            "max_cost_microusd": condition["max_cost_microusd"],
            "independent_judge_rows": condition["independent_judge_rows"],
            "same_model_judge_rows": condition["same_model_judge_rows"],
            "physical_media_sent_to_judge": False,
        }
        if retain_invalid_verdicts:
            retained = [_read_regular(_judgment_path(root, i, row), label="judge outcome", max_bytes=1024 * 1024)[0]
                        for i, (row, _prompt, _response) in enumerate(items)]
            completion.update(invalid_verdicts=sum(value["schema"] == INVALID_JUDGMENT_SCHEMA for value in retained),
                              unknown_usage_judgments=sum(value["cost_microusd"] is None for value in retained))
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
    parser.add_argument("--retain-invalid-verdicts", action="store_true")
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
            retain_invalid_verdicts=args.retain_invalid_verdicts,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
