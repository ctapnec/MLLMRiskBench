from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments import retained_response_judge as subject


JUDGE = "anthropic:claude-haiku-4-5-20251001"
HEX_A = "a" * 64
HEX_B = "b" * 64


def _sha(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256((payload + "\n").encode()).hexdigest()


def _candidate(index: int, *, model: str = "ollama:ministral-3:14b") -> dict:
    dimensions = {
        "exact_model": model,
        "framework": f"framework-{index % 2}",
        "corpus": f"corpus-{index % 3}",
        "source": f"source-{index % 3}",
        "modality": "image" if index % 2 else "text",
        "risk": f"risk-{index % 2}",
        "expected_behavior": "refuse",
        "project_revision_sha256": HEX_A,
        "output_policy_sha256": HEX_B,
    }
    row = {
        "sample_key": f"sample-{index}",
        "run_id": f"run-{index}",
        "attempt_id": f"attempt-{index}",
        "datapoint_id": f"datapoint-{index}",
        "source_cluster_id": f"cluster-{index}",
        "requested_seed": 0,
        **dimensions,
        "prompt_sha256": _sha({"prompt": index}),
        "response_sha256": _sha({"response": index}),
    }
    row["retained_row_sha256"] = _sha({"row": row})
    row["stratum_id"] = _sha(dimensions)
    return row


def _population(count: int) -> dict[str, int]:
    return {
        "validated_joined_rows": count + 9,
        "eligible_usable_outputs": count,
        "excluded_missing_outputs": 4,
        "excluded_source_authoritative_rows": 5,
    }


def _build(candidates: list[dict], *, limit: int = 4) -> dict:
    return subject.build_plan(
        candidates,
        population_audit=_population(len(candidates)),
        source_descriptor={"file": "source.json", "sha256": HEX_A, "bytes": 123},
        judge_model=JUDGE,
        api_config_sha256=HEX_B,
        limit=limit,
    )


def _resign(plan: dict) -> dict:
    material = copy.deepcopy(plan)
    material.pop("plan_id")
    plan["plan_id"] = "retained-judge-plan-" + _sha(material)[:24]
    return plan


def test_selector_is_deterministic_balanced_and_does_not_copy_content() -> None:
    candidates = [_candidate(index) for index in range(6)]
    first = _build(candidates, limit=3)
    second = _build(list(reversed(candidates)), limit=3)

    assert first == second
    assert len({row["stratum_id"] for row in first["selected"]}) == 3
    serialized = json.dumps(first)
    assert "prepared_prompt" not in serialized
    assert "prepared_response" not in serialized
    assert first["judge_condition"] == {
        "model": JUDGE,
        "api_config_sha256": HEX_B,
        "hosted_data_transfer_acknowledged": True,
        "target_calls": 0,
        "answer_retries": 0,
        "transport_retries": 0,
        "max_judge_calls": 3,
        "max_http_attempts": 3,
        "max_cost_microusd": 14_000_000,
        "input_microusd_per_token": 1,
        "output_microusd_per_token": 5,
        "independent_judge_rows": 3,
        "same_model_judge_rows": 0,
    }


def test_same_model_haiku_rows_are_annotated_per_row() -> None:
    candidates = [_candidate(0, model=JUDGE), _candidate(1)]
    plan = _build(candidates, limit=2)

    by_model = {row["exact_model"]: row for row in plan["selected"]}
    assert by_model[JUDGE]["same_model_judge"] is True
    assert by_model["ollama:ministral-3:14b"]["same_model_judge"] is False
    assert plan["judge_condition"]["same_model_judge_rows"] == 1
    assert plan["judge_condition"]["independent_judge_rows"] == 1


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda plan: plan["judge_condition"].__setitem__("target_calls", 1),
            "call or cost contract",
        ),
        (
            lambda plan: plan["judge_condition"].__setitem__("answer_retries", 1),
            "call or cost contract",
        ),
        (
            lambda plan: plan["judge_condition"].__setitem__(
                "max_cost_microusd", 14_000_001
            ),
            "call or cost contract",
        ),
        (
            lambda plan: plan["selected"][0].__setitem__(
                "same_model_judge", not plan["selected"][0]["same_model_judge"]
            ),
            "relationship changed",
        ),
        (
            lambda plan: plan["source"].__setitem__("bytes", 0),
            "source descriptor changed",
        ),
        (
            lambda plan: plan["population"].__setitem__(
                "eligible_usable_outputs",
                plan["population"]["eligible_usable_outputs"] + 1,
            ),
            "eligible population changed",
        ),
    ],
)
def test_validator_rejects_resigned_contract_mutations(mutation, message: str) -> None:
    plan = _build([_candidate(index) for index in range(4)])
    mutation(plan)
    _resign(plan)

    with pytest.raises(ValueError, match=message):
        subject.validate_plan(plan)


def test_validator_rejects_resigned_duplicate_selection() -> None:
    plan = _build([_candidate(index) for index in range(4)])
    plan["selected"][1] = copy.deepcopy(plan["selected"][0])
    for item in plan["stratum_population"].values():
        item["selected"] = 0
    for row in plan["selected"]:
        plan["stratum_population"][row["stratum_id"]]["selected"] += 1
    _resign(plan)

    with pytest.raises(ValueError, match="duplicate rows"):
        subject.validate_plan(plan)


def test_cli_requires_transfer_ack_and_writes_create_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidates = [_candidate(index) for index in range(2)]
    monkeypatch.setattr(
        subject,
        "load_candidates",
        lambda _path: (candidates, _population(len(candidates))),
    )
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}\n", encoding="utf-8")
    receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
    out = tmp_path / "plan.json"
    args = [
        "--runner-view",
        str(tmp_path),
        "--source-receipt",
        str(receipt),
        "--source-receipt-sha256",
        receipt_sha,
        "--judge-model",
        JUDGE,
        "--api-config-sha256",
        HEX_B,
        "--limit",
        "2",
        "--out",
        str(out),
    ]

    with pytest.raises(SystemExit, match="2"):
        subject.main(args)
    assert not out.exists()

    args.insert(-2, "--ack-hosted-judge-data-transfer")
    assert subject.main(args) == 0
    assert subject.validate_plan(json.loads(out.read_text(encoding="utf-8")))
    with pytest.raises(ValueError, match="create-only"):
        subject.main(args)


def test_module_has_no_target_or_runner_factory_import() -> None:
    tree = ast.parse(Path(subject.__file__).read_text(encoding="utf-8"))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }

    assert "experiments.run_matrix" not in imports
    assert "ura.runner" not in imports
    assert "ura.targets" not in imports
