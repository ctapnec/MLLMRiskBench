"""Provider-independent generation conditions from validated response artifacts.

Context, output allowance, observed usage and stop reason are distinct facts.
No token-equality heuristic classifies truncation and no text is copied here.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

from experiments.figure_results import _base_target_component


SCHEMA = "ura-generation-conditions/1"
_COUNTS = ("rows", "normal_stop", "truncated", "other_stop", "unknown_stop",
           "missing_output", "input_context_error")
_IDENTITY = ("run_id", "model_spec", "corpus_arm", "attacker", "modality",
             "context_tokens", "context_source", "context_policy",
             "output_allowance", "output_source")


def _map(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _allowance(value: object) -> bool:
    return type(value) is int and (value == -1 or value > 0)


def _first(source: Mapping[str, Any], keys: tuple[str, ...]) -> Any:
    return next((source[key] for key in keys if key in source), None)


def _usage(tokens: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    values = [tokens[key] for key in keys if tokens.get(key) is not None]
    if not values:
        return None
    if any(type(v) is not int or v < 0 for v in values) or len(set(values)) != 1:
        raise ValueError("generation token usage aliases disagree or are invalid")
    return values[0]


def _stop(raw: Mapping[str, Any]) -> str:
    reasons = [raw[key] for key in ("finish_reason", "done_reason", "stop_reason")
               if isinstance(raw.get(key), str) and raw[key]]
    if raw.get("status") == "incomplete":
        reason = raw.get("incomplete_reason") or _map(raw.get("incomplete_details")).get("reason")
        if reason:
            reasons.append(reason)
    if any(reason in {"length", "max_tokens", "max_output_tokens", "MAX_TOKENS"}
           for reason in reasons):
        return "truncated"
    if any(reason in {"stop", "end_turn", "STOP"} for reason in reasons):
        return "normal_stop"
    if reasons:
        return "other_stop"
    if raw.get("status") == "completed":
        return "normal_stop"
    return "unknown_stop"


def build_generation_conditions(cells: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[str, dict[str, Any]] = {}
    for cell in cells:
        config = cell["manifest"]["config"]
        run = config["run"]
        target = _map(_base_target_component(_map(config.get("components")).get("target")))
        judgments = {j["attempt_id"]: _map(j.get("raw")) for j in cell["judgments"]}
        for attempt_id, response in cell["responses"].items():
            raw = _map(response.get("raw"))
            generation = _map(raw.get("generation"))
            context = _first(generation, ("max_model_len", "num_ctx"))
            if not (type(context) is int and context > 0):
                context = raw.get("max_model_len")
            context_source = "response_runtime"
            if not (type(context) is int and context > 0):
                context = _first(target, ("max_model_len", "num_ctx"))
                context_source = "configured_not_observed"
            if not (type(context) is int and context > 0):
                context, context_source = None, "not_recorded"
            output = _first(generation, ("max_output_tokens", "max_tokens", "num_predict"))
            output_source = "response_request"
            if raw.get("backend") == "vllm" and "max_tokens" in generation and output is None:
                output = -1
            if not _allowance(output):
                output = _first(target, ("max_output_tokens", "max_tokens", "num_predict"))
                output_source = "manifest_config"
                if (str(target.get("class", "")).endswith(".VLLMTarget")
                    and "max_tokens" in target and output is None):
                    output = -1
            if not _allowance(output):
                output, output_source = None, "not_recorded"
            policy = generation.get("num_ctx_policy") or raw.get("max_model_len_policy")
            if policy is None:
                requested = _first(target, ("max_model_len", "num_ctx"))
                policy = "hardware_fit" if requested in (-1, "fit") else None
            identity = {
                "run_id": cell["run_id"], "model_spec": run["model_spec"],
                "corpus_arm": run["corpus"], "attacker": run["attacker"],
                "modality": judgments.get(attempt_id, {}).get("effective_modality", "unknown"),
                "context_tokens": context, "context_source": context_source,
                "context_policy": str(policy) if policy is not None else None,
                "output_allowance": output, "output_source": output_source,
            }
            key = json.dumps(identity, sort_keys=True)
            group = groups.setdefault(key, {
                **identity, **dict.fromkeys(_COUNTS, 0),
                "input_tokens": {"reported_rows": 0, "sum": 0, "minimum": None, "maximum": None},
                "output_tokens": {"reported_rows": 0, "sum": 0, "minimum": None, "maximum": None},
            })
            group["rows"] += 1
            group[_stop(raw)] += 1
            missing = (raw.get("model_stability_status") == "failed_output"
                       or judgments.get(attempt_id, {}).get("policy_evaluation_status") == "model_nonresponse")
            group["missing_output"] += int(missing)
            group["input_context_error"] += int(raw.get("model_stability_category") == "context_limit_exceeded")
            tokens = _map(response.get("tokens"))
            for name, aliases in (("input_tokens", ("input", "prompt")),
                                  ("output_tokens", ("output", "completion"))):
                count = _usage(tokens, aliases)
                if count is None:
                    continue
                aggregate = group[name]
                aggregate["reported_rows"] += 1
                aggregate["sum"] += count
                aggregate["minimum"] = count if aggregate["minimum"] is None else min(count, aggregate["minimum"])
                aggregate["maximum"] = count if aggregate["maximum"] is None else max(count, aggregate["maximum"])
    result = {"schema": SCHEMA, "cross_condition_pooling_permitted": False,
              "conditions": [groups[k] for k in sorted(groups)]}
    validate_generation_conditions(result, {cell["run_id"] for cell in cells})
    return result


def validate_generation_conditions(value: object, run_ids: set[str]) -> None:
    document = _map(value)
    if (set(document) != {"schema", "cross_condition_pooling_permitted", "conditions"}
        or document.get("schema") != SCHEMA
        or document.get("cross_condition_pooling_permitted") is not False
        or not isinstance(document.get("conditions"), list)):
        raise ValueError("invalid generation-condition report")
    seen = set()
    for row in document["conditions"]:
        if not isinstance(row, dict) or set(row) != set(_IDENTITY + _COUNTS) | {"input_tokens", "output_tokens"}:
            raise ValueError("invalid generation-condition fields")
        key = json.dumps({k: row[k] for k in _IDENTITY}, sort_keys=True)
        if key in seen or row["run_id"] not in run_ids:
            raise ValueError("duplicate or unbound generation condition")
        seen.add(key)
        if any(type(row[k]) is not int or row[k] < 0 for k in _COUNTS):
            raise ValueError("invalid generation-condition count")
        if (row["rows"] < 1 or sum(row[k] for k in _COUNTS[1:5]) != row["rows"]
            or row["missing_output"] > row["rows"] or row["input_context_error"] > row["missing_output"]):
            raise ValueError("generation-condition counts do not reconcile")
        for key, sources in (("context", {"response_runtime", "configured_not_observed", "not_recorded"}),
                             ("output", {"response_request", "manifest_config", "not_recorded"})):
            count = row["context_tokens" if key == "context" else "output_allowance"]
            source = row[key + "_source"]
            if source not in sources or (count is None) != (source == "not_recorded"):
                raise ValueError("generation allowance provenance does not reconcile")
            if count is not None and (not _allowance(count) or (key == "context" and count < 1)):
                raise ValueError("invalid generation allowance")
        for key in ("input_tokens", "output_tokens"):
            usage = row[key]
            if not isinstance(usage, dict) or set(usage) != {"reported_rows", "sum", "minimum", "maximum"}:
                raise ValueError("invalid generation usage fields")
            n, total, low, high = (usage[k] for k in ("reported_rows", "sum", "minimum", "maximum"))
            if type(n) is not int or not 0 <= n <= row["rows"] or type(total) is not int or total < 0:
                raise ValueError("invalid generation usage count")
            if n == 0:
                if (total, low, high) != (0, None, None):
                    raise ValueError("unreported generation usage is not unknown")
            elif (type(low) is not int or type(high) is not int
                  or not 0 <= low <= high or not n * low <= total <= n * high):
                raise ValueError("generation usage range does not reconcile")
