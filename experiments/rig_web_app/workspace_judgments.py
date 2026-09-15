"""Index retained Haiku verdicts against their actual generated outputs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .workspace_costs import budget_attempt_rows
from .workspace_judge_settings import local_settings


def native_inline_rows(source: dict, *, output_assignments: dict[str, str]) -> list[dict]:
    """Publish original inline verdicts, not only later post-hoc checkpoints.

    The source is an explicitly selected native run. Read its exact local
    files once; do not reconstruct the corpus, query a judge or hash artifacts.
    """
    from .workspace_import import _jsonl, _responses
    model, run_id = source["target"], source["run_id"]
    directory = Path(source["out"])
    responses = {response["attempt_id"]: response for _attempt, response, _ref in _responses(
        dict(argv=source["runner_argv"])) if response["run_id"] == run_id}
    manifests = list(directory.glob("*"+run_id+".manifest.json"))
    if len(manifests) != 1:
        raise ValueError("Original inline judging needs its retained generation manifest")
    manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
    if (manifest["run_id"] != run_id or manifest["config"]["components"]["judge_cascade"] != source["judge_cascade"]
            or manifest["config"]["run"]["project_revision"] != source["generation_project_revision"]):
        raise ValueError("Original native judging condition differs from its source")
    condition = dict(config=source["judge_cascade"],
        scoring_revision=source["generation_project_revision"]["expected_commit"])
    judge = "local-cascade-" + hashlib.sha256(json.dumps(condition, sort_keys=True).encode()).hexdigest()[:24]
    stem = manifests[0].name.removesuffix(".manifest.json")
    observed = {}
    checkpoint = directory / (stem+".checkpoint.jsonl")
    if checkpoint.is_file():
        for number, record in _jsonl(checkpoint):
            value = record["judgment"]
            if responses.get(value["attempt_id"]) != record["response"]:
                raise ValueError("Inline judgment checkpoint changed its saved response")
            observed[value["attempt_id"]] = (value, f"{checkpoint}:{number}")
    final = directory / (stem+".jsonl")
    if final.is_file():
        for number, value in _jsonl(final):
            prior = observed.get(value["attempt_id"])
            if prior is not None and prior[0] != value:
                raise ValueError("Final native judgment differs from its checkpoint")
            observed[value["attempt_id"]] = (value, f"{final}:{number}")
    rows = []
    for aid, (value, reference) in observed.items():
        identity = run_id+":"+aid
        response = responses.get(aid)
        if (value["run_id"] != run_id or response is None or response["target"] != model
                or identity not in output_assignments):
            raise ValueError("Original inline judgment has no matching campaign output")
        missing = (value.get("raw") or {}).get("policy_evaluation_status") in {"model_nonresponse", "target_input_incompatible"}
        rows.append(dict(response_id=identity, judge_id=judge, status="missing" if missing else "valid",
            label=None if missing else value["label"], source_ref=reference,
            judge_settings=local_settings(source=dict(judge_cascade=source['judge_cascade'],
                approximate_common_metrics=manifest['config']['run'].get('approximate_common_metrics')),
                revision=condition['scoring_revision'])))
    return rows


def native_invalid_rows(unit: dict, artifacts: list[tuple[str, dict]], *,
                        responses: dict[str, dict], output_assignments: dict[str, str]) -> dict:
    """Retain completed-but-unscored native assessments, not perpetual pending rows."""
    from ura.runner import _sha256_json
    condition = dict(config=unit["source"]["judge_cascade"], scoring_revision=unit["judging_revision"])
    judge = "local-cascade-" + hashlib.sha256(json.dumps(condition, sort_keys=True).encode()).hexdigest()[:24]
    if len(artifacts) != unit["invalid_judgments"]:
        raise ValueError("Native invalid-assessment count differs from its terminal")
    rows, costs, seen = [], [], set()
    for reference, value in artifacts:
        aid = value["attempt_id"]
        response = responses.get(aid)
        identity = unit["run_id"]+":"+aid
        if (value.get("schema") != "ura-rr-retained-judge-failure/1" or aid in seen or response is None
                or value["generation_run_id"] != unit["run_id"] or response["run_id"] != unit["run_id"]
                or response["attempt_id"] != aid or response["target"] != unit["source"]["target"]
                or value["response_sha256"] != _sha256_json(response) or identity not in output_assignments):
            raise ValueError("Invalid native assessment changed its output owner")
        seen.add(aid)
        trail = value["trail"]
        if (not trail or trail[-1]["judge"] != "guardrail" or trail[-1].get("raw", {}).get("parsed") is not False
                or trail[-1].get("raw", {}).get("guardrail_queried") is not True
                or any(stage.get("run_id") not in {None, unit["run_id"]} or stage["attempt_id"] != aid for stage in trail)):
            raise ValueError("Native failure is not an observed unparsed guard assessment")
        rows.append(dict(response_id=identity, judge_id=judge, status="invalid", label=None, source_ref=reference,
            judge_settings=local_settings(source=unit['source'], revision=unit['judging_revision'])))
        costs.append(dict(call_id="local-scoring:"+judge+":"+identity, attempt_number=1,
            assignment_id=output_assignments[identity], response_id=identity, provider="local",
            model=unit["source"]["judge_cascade"]["stages"][-1]["model_id"], role="judge",
            state="not_billed", cost_microusd=0, exposure_microusd=0, source_ref=reference))
    return dict(judgments=rows, costs=costs)


def retained_judge_identity(condition: dict) -> str:
    # Execution takes the output allowance from the bound API configuration.
    # Paired plans repeat that allowance as explanatory metadata; ordinary
    # retained-output plans do not. It is not a second judging condition.
    identity = {key: value for key, value in condition.items()
                if not key.startswith("pricing_") and key not in {
                    "max_cost_microusd", "input_microusd_per_token", "output_microusd_per_token",
                    "independent_judge_rows", "same_model_judge_rows", "max_judge_calls", "max_http_attempts"}
                and not (key == "judge_max_output_tokens" and condition.get("api_config_sha256"))}
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:24]
    return condition["model"] + ":" + digest


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
    judge_id = retained_judge_identity(condition)
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
