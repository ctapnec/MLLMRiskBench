"""Index retained Haiku verdicts against their actual generated outputs."""
from __future__ import annotations

import hashlib
import json

from .workspace_costs import budget_attempt_rows


def retained_judge_rows(plan: dict, artifacts: list[tuple[str, dict]], *,
                        output_assignments: dict[str, str], campaign_id: str,
                        shared_requests: dict, budget_plan: dict, ledger: dict,
                        ledger_path: str) -> dict:
    """Translate saved verdicts and physical costs, without another judging call.

    The caller explicitly selects source plans and outputs. Matching inputs
    alone never authorize copying a verdict to another model's answer.
    Incomplete plans publish only their already durable judgment artifacts.
    """
    from experiments.retained_response_judge_execute import (
        INVALID_JUDGMENT_SCHEMA, _validate_artifact,
    )

    condition = plan["judge_condition"]
    identity = {key: value for key, value in condition.items()
                if not key.startswith("pricing_") and key not in {
                    "max_cost_microusd", "input_microusd_per_token", "output_microusd_per_token",
                    "independent_judge_rows", "same_model_judge_rows", "max_judge_calls", "max_http_attempts"}}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    judge_id = condition["model"] + ":" + digest
    judgments, bindings, seen = [], {}, set()
    for reference, value in artifacts:
        index = value["selection_index"]
        if type(index) is not int or not 0 <= index < len(plan["selected"]) or index in seen:
            raise ValueError("Repeated or out-of-range retained judgment")
        seen.add(index)
        selected = plan["selected"][index]
        _validate_artifact(value, plan=plan, index=index, row=selected)
        response_id = selected["run_id"] + ":" + selected["attempt_id"]
        if response_id not in output_assignments:
            raise ValueError("Judgment has no indexed matching output")
        key = selected["retained_row_sha256"]
        invalid = value["schema"] == INVALID_JUDGMENT_SCHEMA
        judgments.append(dict(response_id=response_id, judge_id=judge_id,
            status="invalid" if invalid else "valid",
            label=None if invalid else value["judgment"]["label"], source_ref=reference))
        call_id = shared_requests[key]["call_id"]
        if call_id in bindings:
            raise ValueError("Judgments cannot share one physical paid call")
        attempts = ledger["attempts"].get(call_id, {})
        call = value["judgment"]["raw"]["judge_call"]
        number = str(call["transport_attempt_count"])
        if number not in attempts:
            raise ValueError("Retained verdict has no corresponding paid attempt")
        usage = {name: value[field] for name, field in
                 (("input_tokens", "input_tokens"), ("output_tokens", "output_tokens"))
                 if value[field] is not None}
        bindings[call_id] = dict(campaign_id=campaign_id,
            assignment_id=output_assignments[response_id], response_id=response_id,
            model=condition["model"], attempt_usage={number: usage})
    costs = budget_attempt_rows(budget_plan, ledger, bindings=bindings, source_ref=ledger_path)
    return dict(judgments=judgments, costs=costs.get(campaign_id, []))
