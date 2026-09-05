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
PRICING = {
    "pricing_config_sha256": HEX_A,
    "pricing_as_of": "2026-09-03",
    "pricing_effective_date": "2026-09-01",
    "pricing_currency": "USD",
    "input_microusd_per_token": 1,
    "output_microusd_per_token": 5,
}


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
        pricing_condition=PRICING,
        limit=limit,
    )


@pytest.mark.parametrize("matched", [False, True])
def test_rr_handoff_shares_source_view_for_candidates_and_execution_metadata(tmp_path, monkeypatch, matched):
    from experiments.local_campaign import rr_parallel_analysis
    from experiments import retained_artifact_reader

    (tmp_path / "completion.json").write_text(json.dumps({"schema": rr_parallel_analysis.SCHEMA}))
    cells = [{"run_id": "old", "model": "vllm:GraySwanAI/LLaVA-RR",
              "manifest": {"config": {"run": {
                  "attacker": "replay", "corpus": "strongreject", "project_revision": {"sha256": HEX_A}},
                  "components": {"target": {"max_tokens": 4096}}}}}]
    metadata = {"sample": {"run_id": "old", "prepared_response": "Retained answer.",
        "prepared_prompt": "Original prompt", "common_metrics_eligible": True,
        "policy_evaluable_turn": True, "effective_modality": "text", "datapoint_id": "input1",
        "source_cluster_id": "cluster1", "requested_seed": 0, "source": "strongreject",
        "risk_category": "violence", "expected_behavior": "refuse", "source_policy_id": "policy1",
        "source_policy_version": "1", "prepared_media_references": "[]"}}
    labels = {"sample": {"attempt_id": "attempt1"}}
    audit = {"policy_evaluable_samples": 1, "common_ineligible_evaluable_rows_excluded": 0}
    calls = []
    def validated(root):
        assert root == tmp_path
        calls.append("source_validated")
        return cells, metadata, labels, audit
    monkeypatch.setattr(rr_parallel_analysis, "load_judge_view", validated)
    def forbidden(*a, **kw):
        raise AssertionError("completed RR handoff must not fall back to an interrupted raw grid")
    monkeypatch.setattr(retained_artifact_reader, "grid_partitions", forbidden)
    monkeypatch.setattr(subject, "_joined_artifacts", forbidden)
    rows, population = subject.load_candidates(tmp_path, include_match_identity=matched)
    assert subject.load_retained_metadata(tmp_path) is metadata
    assert calls == ["source_validated", "source_validated"]
    assert population == {"validated_joined_rows": 1, "eligible_usable_outputs": 1,
                          "excluded_missing_outputs": 0, "excluded_source_authoritative_rows": 0}
    row = rows[0]
    assert row["framework"] == "replay" and row["corpus"] == "strongreject"
    assert row["source_cluster_id"] == "cluster1" and row["requested_seed"] == 0
    assert row["response_sha256"] == hashlib.sha256(b"Retained answer.").hexdigest()
    assert ("input_identity_sha256" in row) is matched
    if matched:
        assert row["input_identity_sha256"] == subject._sha({
            field: row[field] for field in subject._MATCH_IDENTITY_FIELDS})


def test_rr_handoff_rejection_is_not_reinterpreted_as_a_current_grid(tmp_path, monkeypatch):
    from experiments.local_campaign import rr_parallel_analysis
    (tmp_path / "completion.json").write_text(json.dumps({"schema": rr_parallel_analysis.SCHEMA}))
    def reject(root):
        raise ValueError("RR judging requires a fully complete parallel analysis handoff")
    monkeypatch.setattr(rr_parallel_analysis, "load_judge_view", reject)
    with pytest.raises(ValueError, match="fully complete"):
        subject.load_candidates(tmp_path)
    with pytest.raises(ValueError, match="fully complete"):
        subject.load_retained_metadata(tmp_path)


def _mixed_configuration_partition() -> dict:
    metadata, judgments, cells = {}, {}, []
    for index, answer in enumerate(("Retained answer.", "")):
        key, run_id = f"sample-{index}", f"run-{index}"
        metadata[key] = {
            "run_id": run_id, "prepared_response": answer,
            "prepared_prompt": "Original prompt", "common_metrics_eligible": True,
            "policy_evaluable_turn": True, "effective_modality": "text",
            "datapoint_id": "input1", "source_cluster_id": "cluster1", "requested_seed": 0,
            "source": "strongreject", "risk_category": "violence", "expected_behavior": "refuse",
            "source_policy_id": "policy1", "source_policy_version": "1", "prepared_media_references": "[]",
        }
        judgments[key] = {"attempt_id": f"attempt-{index}"}
        cells.append({
            "run_id": run_id, "model": "ollama:gemma4:12b",
            "manifest": {"config": {"run": {
                "attacker": "replay", "corpus": "strongreject", "project_revision": {"sha256": HEX_A}},
                "components": {"target": {"max_tokens": 4096}}}},
            "judgments": [{"raw": {"common_metrics_eligible": True, "policy_evaluable_turn": True}}],
        })
    # No joined common group represents this source-only cell. Its non-evaluable
    # row is not part of the source-authoritative evaluable denominator.
    source_only = copy.deepcopy(cells[0])
    source_only["run_id"] = "source-only"
    source_only["judgments"] = [
        {"raw": {"common_metrics_eligible": False, "policy_evaluable_turn": value}}
        for value in (True, False)
    ]
    cells.append(source_only)
    groups = {}
    for index, fingerprint in enumerate((HEX_A, HEX_B)):
        key = f"sample-{index}"
        groups[fingerprint] = [
            {"guardrail": {key: "violation"}} if index == 0 else {},
            {key: metadata[key]}, {key: judgments[key]},
            {"frame": "common", "policy_evaluable_samples": 1,
             "judge_configuration_binding": {"sha256": fingerprint,
                 "realized_guardrail_identity": "exact-guard" if index == 0 else None}},
        ]
    return {"cells": cells, "validator_commit": "c" * 40,
            "joined_by_configuration": groups,
            "audit_join_compatibility": {"unchanged_original_transfer_validator_claimed": False}}


@pytest.mark.parametrize("matched", [False, True])
def test_ordinary_view_separates_configurations_before_missing_output_selection(
    tmp_path, monkeypatch, matched,
):
    from experiments import retained_artifact_reader as reader
    from experiments import retained_response_judge_pair as paired

    partition = _mixed_configuration_partition()
    original = copy.deepcopy(partition)
    monkeypatch.setattr(reader, "grid_partitions", lambda root: [(root, "c" * 40, "d" * 40)])
    calls = []
    def read(root, **kwargs):
        assert root == tmp_path
        assert kwargs == {"joined": True, "frame": "common", "separate_judge_configurations": True}
        calls.append("source_validated")
        return [partition]
    def forbidden(*args, **kwargs):
        raise AssertionError("ordinary retained judging must not pool original judge configurations")
    monkeypatch.setattr(reader, "read_partitions", read)
    monkeypatch.setattr(reader, "load_joined", forbidden)
    monkeypatch.setattr(subject, "_joined_artifacts", forbidden)

    cells, metadata, judgments, audit = subject._read_view(tmp_path)
    assert len(cells) == 3 and metadata.keys() == judgments.keys() == {"sample-0", "sample-1"}
    source = audit["source_configuration_audits"][0]
    assert source["validator_commit"] == partition["validator_commit"]
    assert source["run_ids"] == [cell["run_id"] for cell in cells]
    assert source["configuration_audits"] == {
        key: joined[3] for key, joined in partition["joined_by_configuration"].items()}
    assert source["audit_join_compatibility"] == partition["audit_join_compatibility"]
    assert partition["joined_by_configuration"][HEX_B][0] == {}  # No invented prediction.
    rows, population = subject.load_candidates(tmp_path, include_match_identity=matched)
    assert len(rows) == 1 and rows[0]["sample_key"] == "sample-0"
    assert population == {"validated_joined_rows": 2, "eligible_usable_outputs": 1,
                          "excluded_missing_outputs": 1, "excluded_source_authoritative_rows": 1}
    assert subject.load_retained_metadata(tmp_path) == metadata  # Keeps missing output for coverage.
    assert ("input_identity_sha256" in rows[0]) is matched
    if matched:
        hosted = copy.deepcopy(rows[0])
        hosted.update(exact_model="anthropic:example", run_id="hosted-run", sample_key="hosted-sample",
                      retained_row_sha256=HEX_B)
        plan = paired.build_pair_plan(
            rows, [hosted], local_population_audit=population,
            hosted_population_audit={"validated_joined_rows": 1, "eligible_usable_outputs": 1,
                                     "excluded_missing_outputs": 0, "excluded_source_authoritative_rows": 0},
            source_descriptor={"file": "source.json", "sha256": HEX_A, "bytes": 123},
            judge_model=JUDGE, api_config_sha256=HEX_B, pricing_condition=PRICING,
            limit=1, share_local_judgments=True,
        )
        assert plan["population"]["local"] == population
        assert plan["selection"]["selected_pairs"] == 1
        assert plan["judge_condition"]["max_judge_calls"] == 2
        assert plan["judge_condition"]["answer_retries"] == 0
    assert calls == ["source_validated"] * 3
    assert partition == original


@pytest.mark.parametrize("mutation,message", [
    ("duplicate_run", "duplicate completed run"),
    ("duplicate_key", "lossy or duplicate join"),
    ("missing_judgment", "lossy or duplicate join"),
    ("wrong_count", "lossy or duplicate join"),
    ("wrong_frame", "source frame or configuration"),
    ("wrong_configuration", "source frame or configuration"),
])
def test_ordinary_candidate_join_rejects_identity_loss_or_configuration_changes(mutation, message):
    partition = _mixed_configuration_partition()
    joined = partition["joined_by_configuration"][HEX_B]
    if mutation == "duplicate_run":
        partition["cells"].append(copy.deepcopy(partition["cells"][0]))
    elif mutation == "duplicate_key":
        joined[1] = {"sample-0": joined[1]["sample-1"]}
        joined[2] = {"sample-0": joined[2]["sample-1"]}
    elif mutation == "missing_judgment":
        joined[2].clear()
    elif mutation == "wrong_count":
        joined[3]["policy_evaluable_samples"] = 0
    elif mutation == "wrong_frame":
        joined[3]["frame"] = "source_task"
    else:
        joined[3]["judge_configuration_binding"]["sha256"] = HEX_A
    with pytest.raises(ValueError, match=message):
        subject._joined_candidate_partitions([partition])


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
        "transport_retries": 3,
        "max_judge_calls": 3,
        "max_http_attempts": 12,
        "max_cost_microusd": 7_000_000,
        **PRICING,
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
                "max_cost_microusd", 7_000_001
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
        (
            lambda plan: plan["judge_condition"].__setitem__(
                "pricing_effective_date", "2026-09-04"
            ),
            "price is not yet effective",
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
    pricing = tmp_path / "pricing.json"
    pricing.write_text(
        json.dumps(
            {
                "schema": "ura-console-pricing/1",
                "providers": {
                    "anthropic": {
                        "models": {
                            "claude-haiku-4-5-20251001": {
                                "rates": [
                                    {
                                        "currency": "USD",
                                        "effective_date": "2026-09-01",
                                        "per_million_tokens": {
                                            "input": 1,
                                            "output": 5,
                                        },
                                    }
                                ]
                            }
                        }
                    }
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    pricing_sha = hashlib.sha256(pricing.read_bytes()).hexdigest()
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
        "--pricing-config",
        str(pricing),
        "--pricing-config-sha256",
        pricing_sha,
        "--pricing-as-of",
        "2026-09-03",
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
