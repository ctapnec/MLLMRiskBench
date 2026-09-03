"""Execute sealed local judging for hosted outputs already selected for Haiku."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from experiments.retained_response_judge_execute import (
    _exclusive_lock,
    _judge_inputs,
    _read_regular,
    _write_atomic,
    _write_new,
)
from experiments.retained_response_judge_pair import validate_pair_plan
from experiments.retained_response_judge_pair_execute import (
    _reconcile_pair_selection,
)
from experiments.retained_response_local_judge import (
    _hosted_rows,
    _runtime_selection,
    validate_plan,
)
from ura.data_models import Judgment
from ura.judges.base import JudgeCascade, JudgeCascadeDecisionError
from ura.judges.guardrail import GuardrailJudge
from ura.judges.rules import RuleJudge
from ura.model_acquisition_runtime import admit_managed_model_runtime


EXECUTION_SCHEMA = "ura-retained-response-local-judge-execution/1"
JUDGMENT_SCHEMA = "ura-retained-response-local-judge-artifact/1"
COMPLETION_SCHEMA = "ura-retained-response-local-judge-completion/1"


def _build_cascade(condition: Mapping[str, Any], runtime: Any) -> JudgeCascade:
    return JudgeCascade(
        [
            RuleJudge(),
            GuardrailJudge(
                model=condition["guardrail_model"],
                revision=condition["guardrail_revision"],
                device=condition["guardrail_device"],
                max_new_tokens=condition["guardrail_max_new_tokens"],
                model_runtime=runtime,
                managed_model_role="guardrail_judge",
            ),
        ]
    )


def _judgment_path(root: Path, index: int, row: Mapping[str, Any]) -> Path:
    return root / "judgments" / (
        f"{index + 1:04d}-{row['retained_row_sha256'][:24]}.json"
    )


def _validate_judgment(
    value: object,
    *,
    plan: Mapping[str, Any],
    row: Mapping[str, Any],
    index: int,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "plan_id",
        "selection_index",
        "pair_id",
        "sample_key",
        "retained_row_sha256",
        "decision_status",
        "judgment",
        "trail",
    }:
        raise ValueError("local retained-response judgment fields changed")
    trail_raw = value.get("trail")
    if not isinstance(trail_raw, list) or len(trail_raw) != 2:
        raise ValueError("local judge must retain its complete two-stage trail")
    trail = [Judgment.model_validate(item) for item in trail_raw]
    final_raw = value.get("judgment")
    final = None if final_raw is None else Judgment.model_validate(final_raw)
    decision_status = value.get("decision_status")
    if (
        value.get("schema") != JUDGMENT_SCHEMA
        or value.get("plan_id") != plan["plan_id"]
        or value.get("selection_index") != index
        or value.get("pair_id") != row["pair_id"]
        or value.get("sample_key") != row["sample_key"]
        or value.get("retained_row_sha256") != row["retained_row_sha256"]
        or [item.judge for item in trail] != ["rules", "guardrail"]
        or any(item.attempt_id != row["attempt_id"] for item in trail)
        or trail[1].raw.get("guardrail_queried") is not True
        or decision_status not in {"decided", "abstained"}
        or (decision_status == "decided" and final is None)
        or (decision_status == "decided" and final.label == "not_applicable")
        or (
            decision_status == "abstained"
            and final is not None
            and final.label != "not_applicable"
        )
        or (final is not None and final.attempt_id != row["attempt_id"])
    ):
        raise ValueError("local retained-response judgment contract changed")
    return dict(value)


def _new_ledger(plan: Mapping[str, Any], plan_sha256: str) -> dict[str, Any]:
    return {
        "schema": EXECUTION_SCHEMA,
        "plan_id": plan["plan_id"],
        "plan_sha256": plan_sha256,
        "selected_outputs": len(plan["selected"]),
        "completed_judgments": 0,
        "rules_evaluations": 0,
        "local_guardrail_calls": 0,
        "decided": 0,
        "abstained": 0,
        "target_calls": 0,
        "provider_calls": 0,
        "http_attempts": 0,
        "state": "active",
    }


def _validate_ledger(
    value: object, plan: Mapping[str, Any], plan_sha256: str
) -> dict[str, Any]:
    expected = set(_new_ledger(plan, plan_sha256))
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("local retained-response execution ledger fields changed")
    count = value.get("completed_judgments")
    integers = (
        "selected_outputs",
        "completed_judgments",
        "rules_evaluations",
        "local_guardrail_calls",
        "decided",
        "abstained",
        "target_calls",
        "provider_calls",
        "http_attempts",
    )
    if any(
        isinstance(value.get(field), bool)
        or not isinstance(value.get(field), int)
        or value[field] < 0
        for field in integers
    ):
        raise ValueError("local retained-response execution count is invalid")
    if (
        value["schema"] != EXECUTION_SCHEMA
        or value["plan_id"] != plan["plan_id"]
        or value["plan_sha256"] != plan_sha256
        or value["selected_outputs"] != len(plan["selected"])
        or count > value["selected_outputs"]
        or value["rules_evaluations"] != count
        or value["local_guardrail_calls"] != count
        or value["decided"] + value["abstained"] != count
        or any(value[field] != 0 for field in (
            "target_calls", "provider_calls", "http_attempts",
        ))
        or value["state"] not in {"active", "complete"}
        or (value["state"] == "complete" and count != value["selected_outputs"])
    ):
        raise ValueError("local retained-response execution ledger contract changed")
    return dict(value)


def _apply_artifact(ledger: dict[str, Any], artifact: Mapping[str, Any]) -> None:
    ledger["completed_judgments"] += 1
    ledger["rules_evaluations"] += 1
    ledger["local_guardrail_calls"] += 1
    ledger[str(artifact["decision_status"])] += 1


def _validate_completion(
    value: object,
    *,
    plan: Mapping[str, Any],
    ledger: Mapping[str, Any],
    plan_sha256: str,
    runtime_descriptor: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "plan_id",
        "plan_sha256",
        "selected_outputs",
        "rules_evaluations",
        "local_guardrail_calls",
        "decided",
        "abstained",
        "target_calls",
        "provider_calls",
        "http_attempts",
        "same_rows_as_haiku",
        "physical_media_directly_evaluated",
        "model_acquisition",
    }:
        raise ValueError("local retained-response completion fields changed")
    if (
        value.get("schema") != COMPLETION_SCHEMA
        or value.get("status") != "complete"
        or value.get("plan_id") != plan["plan_id"]
        or value.get("plan_sha256") != plan_sha256
        or value.get("selected_outputs") != len(plan["selected"])
        or any(value.get(field) != ledger[field] for field in (
            "rules_evaluations", "local_guardrail_calls", "decided", "abstained",
            "target_calls", "provider_calls", "http_attempts",
        ))
        or value.get("same_rows_as_haiku") is not True
        or value.get("physical_media_directly_evaluated") is not False
        or value.get("model_acquisition") != dict(runtime_descriptor)
    ):
        raise ValueError("local retained-response completion contract changed")
    return dict(value)


def execute(
    *,
    plan_path: Path,
    pair_plan_path: Path,
    local_runner_view: Path,
    hosted_runner_view: Path,
    source_receipt: Path,
    model_acquisition_plan: Path,
    model_acquisition_plan_sha256: str,
    model_acquisition_receipt: Path,
    model_acquisition_receipt_sha256: str,
    model_acquisition_store: Path,
    out: Path,
    runtime_admitter: Callable[..., tuple[Any, dict[str, Any]]] = (
        admit_managed_model_runtime
    ),
    cascade_factory: Callable[[Mapping[str, Any], Any], Any] = _build_cascade,
    selection_reconciler: Callable[..., list[tuple[dict[str, Any], str, str]]] = (
        _reconcile_pair_selection
    ),
) -> Path:
    raw_plan, plan_descriptor = _read_regular(
        plan_path,
        label="local retained-response judge plan",
        max_bytes=32 * 1024 * 1024,
    )
    plan = validate_plan(raw_plan)
    raw_pair, pair_descriptor = _read_regular(
        pair_plan_path,
        label="matched pair plan",
        max_bytes=32 * 1024 * 1024,
    )
    if {
        **pair_descriptor,
        "plan_id": raw_pair.get("plan_id") if isinstance(raw_pair, dict) else None,
    } != plan["pair_plan"]:
        raise ValueError("matched pair plan differs from the local judge plan")
    pair = validate_pair_plan(raw_pair)
    source_raw, source_descriptor = _read_regular(
        source_receipt,
        label="source receipt",
        max_bytes=32 * 1024 * 1024,
    )
    del source_raw
    if source_descriptor != plan["source"] or pair["source"] != plan["source"]:
        raise ValueError("source receipt differs from the matched judging plans")
    reconciled = selection_reconciler(
        local_runner_view,
        hosted_runner_view,
        pair,
        source_descriptor,
    )
    items = [item for item in reconciled if item[0]["cohort"] == "hosted"]
    if [item[0] for item in items] != plan["selected"]:
        raise ValueError("hosted retained outputs differ from the local judge plan")
    condition = plan["judge_condition"]
    runtime_selection = _runtime_selection(
        pair_descriptor=pair_descriptor,
        source_descriptor=source_descriptor,
        selected=plan["selected"],
        guardrail_model=condition["guardrail_model"],
        guardrail_revision=condition["guardrail_revision"],
    )
    runtime, runtime_descriptor = runtime_admitter(
        selection=runtime_selection,
        plan_path=model_acquisition_plan,
        plan_sha256=model_acquisition_plan_sha256,
        receipt_path=model_acquisition_receipt,
        receipt_sha256=model_acquisition_receipt_sha256,
        managed_store=model_acquisition_store,
    )
    if runtime_descriptor.get("selection_sha256") != plan["model_acquisition"][
        "selection_sha256"
    ]:
        raise ValueError("admitted local judge model selection differs from its plan")

    root = Path(out)
    if root.is_symlink():
        raise ValueError("local judge execution root must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root = root.resolve(strict=True)
    judgments = root / "judgments"
    if judgments.is_symlink():
        raise ValueError("local judge judgments directory must not be a symlink")
    judgments.mkdir(mode=0o700, exist_ok=True)
    ledger_path = root / "execution.json"
    completion_path = root / "completion.json"

    with _exclusive_lock(root):
        if ledger_path.exists() or ledger_path.is_symlink():
            raw_ledger, _ = _read_regular(
                ledger_path,
                label="local retained-response execution ledger",
                max_bytes=1024 * 1024,
            )
            ledger = _validate_ledger(raw_ledger, plan, plan_descriptor["sha256"])
        else:
            ledger = _new_ledger(plan, plan_descriptor["sha256"])
            _write_atomic(ledger_path, ledger)
        expected_names = {
            _judgment_path(root, index, row).name
            for index, row in enumerate(plan["selected"])
        }
        actual_names = {path.name for path in judgments.glob("*.json")}
        if actual_names - expected_names:
            raise ValueError("unexpected local retained-response judgment exists")

        completed = ledger["completed_judgments"]
        for index in range(completed):
            raw_artifact, _ = _read_regular(
                _judgment_path(root, index, plan["selected"][index]),
                label="local retained-response judgment",
                max_bytes=1024 * 1024,
            )
            _validate_judgment(
                raw_artifact,
                plan=plan,
                row=plan["selected"][index],
                index=index,
            )
        while completed < len(items):
            artifact_path = _judgment_path(root, completed, items[completed][0])
            if not artifact_path.exists() and not artifact_path.is_symlink():
                break
            raw_artifact, _ = _read_regular(
                artifact_path,
                label="recoverable local retained-response judgment",
                max_bytes=1024 * 1024,
            )
            artifact = _validate_judgment(
                raw_artifact,
                plan=plan,
                row=items[completed][0],
                index=completed,
            )
            _apply_artifact(ledger, artifact)
            completed += 1
            _write_atomic(ledger_path, ledger)
        if any(
            _judgment_path(root, index, items[index][0]).exists()
            for index in range(completed + 1, len(items))
        ):
            raise ValueError("local judgment artifacts are not a strict prefix")

        if completion_path.exists() or completion_path.is_symlink():
            if completed != len(items) or ledger["state"] != "complete":
                raise ValueError("local judge completion precedes its durable ledger")
            raw_completion, _ = _read_regular(
                completion_path,
                label="local retained-response completion",
                max_bytes=1024 * 1024,
            )
            _validate_completion(
                raw_completion,
                plan=plan,
                ledger=ledger,
                plan_sha256=plan_descriptor["sha256"],
                runtime_descriptor=runtime_descriptor,
            )
            return completion_path.resolve(strict=True)

        cascade = cascade_factory(condition, runtime)
        try:
            for index in range(completed, len(items)):
                row, prompt, response_text = items[index]
                datapoint, response = _judge_inputs(row, prompt, response_text)
                final: Judgment | None
                try:
                    final, trail = cascade.judge(datapoint, response)
                except JudgeCascadeDecisionError as exc:
                    final = None
                    trail = exc.trail
                status = (
                    "decided"
                    if final is not None and final.label != "not_applicable"
                    else "abstained"
                )
                artifact = {
                    "schema": JUDGMENT_SCHEMA,
                    "plan_id": plan["plan_id"],
                    "selection_index": index,
                    "pair_id": row["pair_id"],
                    "sample_key": row["sample_key"],
                    "retained_row_sha256": row["retained_row_sha256"],
                    "decision_status": status,
                    "judgment": (
                        None if final is None else final.model_dump(mode="json")
                    ),
                    "trail": [item.model_dump(mode="json") for item in trail],
                }
                _validate_judgment(artifact, plan=plan, row=row, index=index)
                _write_new(_judgment_path(root, index, row), artifact)
                _apply_artifact(ledger, artifact)
                completed += 1
                _write_atomic(ledger_path, ledger)
        finally:
            for stage in reversed(getattr(cascade, "stages", [])):
                close = getattr(stage, "close", None)
                if callable(close):
                    close()

        ledger["state"] = "complete"
        _validate_ledger(ledger, plan, plan_descriptor["sha256"])
        _write_atomic(ledger_path, ledger)
        completion = {
            "schema": COMPLETION_SCHEMA,
            "status": "complete",
            "plan_id": plan["plan_id"],
            "plan_sha256": plan_descriptor["sha256"],
            "selected_outputs": len(items),
            "rules_evaluations": ledger["rules_evaluations"],
            "local_guardrail_calls": ledger["local_guardrail_calls"],
            "decided": ledger["decided"],
            "abstained": ledger["abstained"],
            "target_calls": 0,
            "provider_calls": 0,
            "http_attempts": 0,
            "same_rows_as_haiku": True,
            "physical_media_directly_evaluated": False,
            "model_acquisition": dict(runtime_descriptor),
        }
        _validate_completion(
            completion,
            plan=plan,
            ledger=ledger,
            plan_sha256=plan_descriptor["sha256"],
            runtime_descriptor=runtime_descriptor,
        )
        _write_new(completion_path, completion)
        return completion_path.resolve(strict=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--pair-plan", type=Path, required=True)
    parser.add_argument("--local-runner-view", type=Path, required=True)
    parser.add_argument("--hosted-runner-view", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--model-acquisition-plan", type=Path, required=True)
    parser.add_argument("--model-acquisition-plan-sha256", required=True)
    parser.add_argument("--model-acquisition-receipt", type=Path, required=True)
    parser.add_argument("--model-acquisition-receipt-sha256", required=True)
    parser.add_argument("--model-acquisition-store", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    print(
        execute(
            plan_path=args.plan,
            pair_plan_path=args.pair_plan,
            local_runner_view=args.local_runner_view,
            hosted_runner_view=args.hosted_runner_view,
            source_receipt=args.source_receipt,
            model_acquisition_plan=args.model_acquisition_plan,
            model_acquisition_plan_sha256=args.model_acquisition_plan_sha256,
            model_acquisition_receipt=args.model_acquisition_receipt,
            model_acquisition_receipt_sha256=(
                args.model_acquisition_receipt_sha256
            ),
            model_acquisition_store=args.model_acquisition_store,
            out=args.out,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
