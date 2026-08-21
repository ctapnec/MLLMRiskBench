from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import ura.model_acquisition_runtime as runtime_module
from ura.adapters.base import AttackBudget
from ura.adapters.replay import ReplayAttacker
from ura.converters.synth import synth_corpus
from ura.judges.base import JudgeCascade
from ura.judges.rules import RuleJudge
from ura.model_acquisition import (
    ModelAcquisitionError,
    build_receipt,
    build_upstream_manifest,
    hub_requirement,
    write_document_create_only,
)
from ura.model_acquisition_runtime import (
    ManagedModelLoadError,
    ManagedModelRuntime,
    admit_managed_model_runtime,
    build_runtime_plan,
    build_runtime_selection,
    collect_run_requirements,
    hf_offline_environment_overrides,
    model_acquisition_cell_role_projection,
    model_acquisition_execution_descriptor,
    model_acquisition_shared_from_cell_projection,
    model_acquisition_shared_role_projection,
    public_selection_descriptor,
    transformers_local_only_kwargs,
    transformers_managed_snapshot_args,
    validate_runtime_plan,
    validate_runtime_selection,
    validate_model_acquisition_execution_descriptor,
    validate_model_acquisition_grid_binding,
    validate_model_acquisition_role_projection,
    validate_model_acquisition_role_projection_binding,
    validate_model_acquisition_run_binding,
    vllm_managed_snapshot_kwargs,
)
from ura.runner import Runner
from ura.targets.api import MockTarget


REVISIONS = {
    "target": "a" * 40,
    "judge": "b" * 40,
    "guard": "c" * 40,
    "defense": "d" * 40,
    "surrogate": "e" * 40,
}
BINDINGS = {
    "attacker_config_sha256": "1" * 64,
    "builder_ticket_sha256": "2" * 64,
    "local_config_sha256": "3" * 64,
    "request_envelope_sha256": "4" * 64,
}


def _target_roles_selection():
    requirement_set = collect_run_requirements(
        target_specs=["vllm:Org/Target"],
        local_configs={"vllm:Org/Target": {"revision": REVISIONS["target"]}},
        judge_names=["rules", "guardrail"],
        judge_model="mock",
        attacker_names=["replay", "nanogcg"],
        attacker_configs={
            "nanogcg": {
                "model_id": "Org/Surrogate",
                "model_revision": REVISIONS["surrogate"],
            }
        },
        guardrail_model="Org/Guard",
        guardrail_revision=REVISIONS["guard"],
        defense_guardrail_model="Org/Defense",
        defense_guardrail_revision=REVISIONS["defense"],
    )
    return build_runtime_selection(requirement_set, input_bindings=BINDINGS)


def _judge_roles_selection():
    requirement_set = collect_run_requirements(
        target_specs=["anthropic:HostedTarget"],
        local_configs={
            "vllm:Org/Judge": {"revision": REVISIONS["judge"]},
        },
        judge_names=["rules", "guardrail", "llm"],
        judge_model="vllm:Org/Judge",
        attacker_names=["replay", "nanogcg"],
        attacker_configs={
            "nanogcg": {
                "model_id": "Org/Surrogate",
                "model_revision": REVISIONS["surrogate"],
            }
        },
        guardrail_model="Org/Guard",
        guardrail_revision=REVISIONS["guard"],
        defense_guardrail_model="Org/Defense",
        defense_guardrail_revision=REVISIONS["defense"],
    )
    return build_runtime_selection(requirement_set, input_bindings=BINDINGS)


def _git_blob_id(content: bytes) -> str:
    return hashlib.sha1(  # noqa: S324 - Git blob identity is SHA-1 by protocol
        f"blob {len(content)}\0".encode("ascii") + content
    ).hexdigest()


def _sealed_runtime_fixture(
    tmp_path: Path,
    *,
    selection=None,
) -> tuple[ManagedModelRuntime, dict, dict, Path, Path, Path]:
    selected = selection or _target_roles_selection()
    plan = build_runtime_plan(selected)
    store = (tmp_path / "private-managed-store").resolve()
    store.mkdir(parents=True)
    snapshots: dict[str, Path] = {}
    manifests: dict[str, dict] = {}
    for index, resource in enumerate(plan["resources"]):
        resource_root = store / resource["resource_id"]
        snapshot = resource_root / "snapshot"
        snapshot.mkdir(parents=True)
        content = (
            json.dumps(
                {
                    "fixture": index,
                    "repo": resource["repo_id"],
                    "revision": resource["revision"],
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        (snapshot / "config.json").write_bytes(content)
        manifest = build_upstream_manifest(
            resource["repo_id"],
            resource["revision"],
            [
                {
                    "path": "config.json",
                    "size": len(content),
                    "blob_id": _git_blob_id(content),
                    "lfs_sha256": None,
                }
            ],
        )
        write_document_create_only(
            resource_root.resolve(),
            manifest,
            identifier=manifest["manifest_id"],
            suffix="upstream-manifest.json",
        )
        snapshots[resource["resource_id"]] = snapshot
        manifests[resource["resource_id"]] = manifest
    receipt = build_receipt(plan, snapshots=snapshots, manifests=manifests)
    documents = (tmp_path / "private-documents").resolve()
    plan_path, plan_sha = write_document_create_only(
        documents,
        plan,
        identifier=plan["plan_id"],
        suffix="plan.json",
    )
    receipt_path, receipt_sha = write_document_create_only(
        documents,
        receipt,
        identifier=receipt["receipt_id"],
        suffix="receipt.json",
    )
    runtime = ManagedModelRuntime(
        selection=selected,
        plan_path=plan_path,
        plan_sha256=plan_sha,
        receipt_path=receipt_path,
        receipt_sha256=receipt_sha,
        managed_store=store,
    )
    return runtime, plan, receipt, store, plan_path, receipt_path


def _evidence_descriptor(path: Path, *, root: Path) -> dict[str, object]:
    return {
        "bytes": path.stat().st_size,
        "file": path.relative_to(root).as_posix(),
        "records": 1,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def _full_runtime_descriptor(
    runtime: ManagedModelRuntime,
    *,
    root: Path,
    plan_path: Path,
    receipt_path: Path,
) -> dict[str, object]:
    return {
        **runtime.admit(),
        "evidence": {
            "plan": _evidence_descriptor(plan_path, root=root),
            "receipt": _evidence_descriptor(receipt_path, root=root),
        },
        "selection": public_selection_descriptor(runtime._selection),
    }


def test_requirement_projection_covers_all_five_roles_across_legal_processes() -> None:
    target_selection = _target_roles_selection()
    judge_selection = _judge_roles_selection()
    projected = {
        (item.role, item.repo_id, item.revision)
        for selection in (target_selection, judge_selection)
        for item in selection.requirements
    }
    assert projected == {
        ("vllm_target", "Org/Target", REVISIONS["target"]),
        ("llm_judge", "Org/Judge", REVISIONS["judge"]),
        ("guardrail_judge", "Org/Guard", REVISIONS["guard"]),
        ("defense_guardrail", "Org/Defense", REVISIONS["defense"]),
        ("nanogcg_surrogate", "Org/Surrogate", REVISIONS["surrogate"]),
    }
    for selection in (target_selection, judge_selection):
        plan = build_runtime_plan(selection)
        assert plan["bindings"] == selection.plan_bindings
        assert validate_runtime_plan(plan, selection=selection) == plan


def test_explicit_local_checkpoints_and_suffix_replay_never_become_hub_resources() -> None:
    requirement_set = collect_run_requirements(
        target_specs=["vllm:/private/target"],
        local_configs={"vllm:/private/target": {"digest": "5" * 64}},
        judge_names=["rules"],
        judge_model="mock",
        attacker_names=["nanogcg"],
        attacker_configs={"nanogcg": {"suffix": "fixture suffix"}},
    )
    assert requirement_set.requirements == ()
    assert {row["kind"] for row in requirement_set.exceptions} == {
        "explicit_local_checkpoint",
        "precomputed_suffix_replay",
    }
    rendered = json.dumps([dict(row) for row in requirement_set.exceptions])
    assert "/private" not in rendered
    assert "fixture suffix" not in rendered
    with pytest.raises(ModelAcquisitionError, match="no Hub resources"):
        build_runtime_plan(
            build_runtime_selection(requirement_set, input_bindings=BINDINGS)
        )


@pytest.mark.parametrize(
    ("spec", "config", "message"),
    [
        (
            "vllm:Org/HubModel",
            {"digest": "5" * 64},
            "Hub vLLM selection requires an immutable revision",
        ),
        (
            "vllm:/private/checkpoint",
            {"revision": "a" * 40},
            "explicit local vLLM selection requires a digest",
        ),
    ],
)
def test_vllm_path_classification_rejects_digest_revision_mismatch(
    spec: str,
    config: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(ModelAcquisitionError, match=message):
        collect_run_requirements(
            target_specs=[spec],
            local_configs={spec: config},
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        )


def test_nanogcg_default_matches_adapter_and_requires_full_commit() -> None:
    requirements = collect_run_requirements(
        target_specs=[],
        local_configs={},
        judge_names=["rules"],
        judge_model="mock",
        attacker_names=["nanogcg"],
        attacker_configs={"nanogcg": {"model_revision": "f" * 40}},
    ).requirements
    assert [(item.repo_id, item.revision, item.role) for item in requirements] == [
        (
            "meta-llama/Llama-2-7b-chat-hf",
            "f" * 40,
            "nanogcg_surrogate",
        )
    ]
    with pytest.raises(ModelAcquisitionError, match="40-64 lowercase hex"):
        collect_run_requirements(
            target_specs=[],
            local_configs={},
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["nanogcg"],
            attacker_configs={"nanogcg": {"model_revision": "abc1234"}},
        )


def test_nanogcg_surrogate_cannot_share_the_evaluated_target_resource() -> None:
    with pytest.raises(ModelAcquisitionError, match="surrogate must differ"):
        collect_run_requirements(
            target_specs=["vllm:Org/SameModel"],
            local_configs={
                "vllm:Org/SameModel": {"revision": REVISIONS["target"]},
            },
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["nanogcg"],
            attacker_configs={
                "nanogcg": {
                    "model_id": "Org/SameModel",
                    "model_revision": REVISIONS["target"],
                }
            },
        )


@pytest.mark.parametrize("consumer", ["llm", "guardrail", "defense"])
def test_target_cannot_share_a_hub_resource_with_a_judge_or_guard(
    consumer: str,
) -> None:
    kwargs: dict[str, object] = {
        "target_specs": ["vllm:Org/SameModel"],
        "local_configs": {
            "vllm:Org/SameModel": {"revision": REVISIONS["target"]},
        },
        "judge_names": ["rules"],
        "judge_model": "mock",
        "attacker_names": ["replay"],
        "attacker_configs": {},
    }
    if consumer == "llm":
        kwargs["judge_names"] = ["llm"]
        kwargs["judge_model"] = "vllm:Org/SameModel"
    elif consumer == "guardrail":
        kwargs["judge_names"] = ["guardrail"]
        kwargs["guardrail_model"] = "Org/SameModel"
        kwargs["guardrail_revision"] = REVISIONS["target"]
    else:
        kwargs["defense_guardrail_model"] = "Org/SameModel"
        kwargs["defense_guardrail_revision"] = REVISIONS["target"]
    with pytest.raises(ModelAcquisitionError, match="cannot"):
        collect_run_requirements(**kwargs)


def test_explicit_local_target_and_judge_cannot_share_one_process() -> None:
    digest = "9" * 64
    with pytest.raises(ModelAcquisitionError, match="cannot share one process"):
        collect_run_requirements(
            target_specs=["vllm:/private/target"],
            local_configs={
                "vllm:/private/target": {"digest": digest},
                "vllm:/private/judge": {"digest": digest},
            },
            judge_names=["llm"],
            judge_model="vllm:/private/judge",
            attacker_names=["replay"],
            attacker_configs={},
        )


def test_public_selection_digest_is_strictly_bound_to_config_and_ticket() -> None:
    first = _target_roles_selection()
    changed_set = collect_run_requirements(
        target_specs=["vllm:Org/Target"],
        local_configs={"vllm:Org/Target": {"revision": REVISIONS["target"]}},
        judge_names=["rules"],
        judge_model="mock",
        attacker_names=["replay"],
        attacker_configs={},
    )
    changed = build_runtime_selection(
        changed_set,
        input_bindings={**BINDINGS, "builder_ticket_sha256": "9" * 64},
    )
    assert first.selection_sha256 != changed.selection_sha256
    with pytest.raises(ModelAcquisitionError, match="resources or immutable"):
        validate_runtime_plan(build_runtime_plan(first), selection=changed)


def test_manually_staled_selection_digest_is_rejected() -> None:
    selected = _target_roles_selection()
    stale = runtime_module.RuntimeSelection(
        requirements=selected.requirements,
        exceptions=selected.exceptions,
        input_bindings=selected.input_bindings,
        selection_sha256="f" * 64,
    )
    with pytest.raises(ModelAcquisitionError, match="non-canonical or stale"):
        validate_runtime_selection(stale)
    with pytest.raises(ModelAcquisitionError, match="non-canonical or stale"):
        build_runtime_plan(stale)


def test_admission_full_hashes_every_resource_and_descriptor_has_no_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _plan, _receipt, store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    calls = 0
    original = runtime_module.verify_receipt_snapshots

    def observe(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_module, "verify_receipt_snapshots", observe)
    descriptor = runtime.admit()
    assert calls == 1
    serialized = json.dumps(descriptor, sort_keys=True)
    for private in (store, plan_path, receipt_path):
        assert str(private) not in serialized
    assert descriptor["schema"] == "ura-model-acquisition-runtime/1"
    assert len(descriptor["resources"]) == 4


def test_receipt_event_time_and_file_mtime_do_not_change_scientific_identity(
    tmp_path: Path,
) -> None:
    runtime_a, plan, receipt_a, store, plan_path, receipt_path_a = (
        _sealed_runtime_fixture(tmp_path)
    )
    full_a = _full_runtime_descriptor(
        runtime_a,
        root=tmp_path,
        plan_path=plan_path,
        receipt_path=receipt_path_a,
    )
    snapshots = {
        resource["resource_id"]: store / resource["resource_id"] / "snapshot"
        for resource in receipt_a["resources"]
    }
    # Reproduce a fresh-store/stat difference without changing one byte. The
    # full receipt must keep detecting the mtime-bearing inventory difference,
    # while scientific identity remains content-stable.
    for snapshot in snapshots.values():
        config = snapshot / "config.json"
        info = config.stat()
        os.utime(
            config,
            ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000),
        )
    manifests = {
        resource["resource_id"]: json.loads(
            (
                store
                / resource["resource_id"]
                / (
                    resource["upstream_manifest_id"]
                    + ".upstream-manifest.json"
                )
            ).read_text(encoding="utf-8")
        )
        for resource in receipt_a["resources"]
    }
    receipt_b = build_receipt(
        plan,
        snapshots=snapshots,
        manifests=manifests,
        completed_at=datetime(2026, 8, 18, 10, 1, tzinfo=timezone.utc),
    )
    documents = receipt_path_a.parent
    receipt_path_b, receipt_sha_b = write_document_create_only(
        documents,
        receipt_b,
        identifier=receipt_b["receipt_id"],
        suffix="receipt.json",
    )
    runtime_b = ManagedModelRuntime(
        selection=runtime_a._selection,
        plan_path=plan_path,
        plan_sha256=runtime_a._plan_sha256,
        receipt_path=receipt_path_b,
        receipt_sha256=receipt_sha_b,
        managed_store=store,
    )
    full_b = _full_runtime_descriptor(
        runtime_b,
        root=tmp_path,
        plan_path=plan_path,
        receipt_path=receipt_path_b,
    )

    assert full_a["receipt_id"] != full_b["receipt_id"]
    assert full_a["receipt_sha256"] != full_b["receipt_sha256"]
    assert all(
        first["tree_sha256"] == second["tree_sha256"]
        and first["inventory_sha256"] != second["inventory_sha256"]
        for first, second in zip(
            receipt_a["resources"], receipt_b["resources"], strict=True
        )
    )
    stable_a = model_acquisition_execution_descriptor(
        full_a, evidence_root=tmp_path
    )
    stable_b = model_acquisition_execution_descriptor(
        full_b, evidence_root=tmp_path
    )
    assert stable_a == stable_b
    assert all("inventory_sha256" not in row for row in stable_a["resources"])
    assert validate_model_acquisition_execution_descriptor(stable_a) == stable_a

    changed_seal = json.loads(json.dumps(stable_a))
    changed_seal["resources"][0]["tree_sha256"] = "f" * 64
    identity_body = {
        key: value
        for key, value in changed_seal.items()
        if key != "execution_sha256"
    }
    changed_seal["execution_sha256"] = hashlib.sha256(
        json.dumps(
            identity_body,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    assert (
        validate_model_acquisition_execution_descriptor(changed_seal)[
            "execution_sha256"
        ]
        != stable_a["execution_sha256"]
    )


def test_execution_descriptors_bind_all_five_roles_across_legal_run_configs(
    tmp_path: Path,
) -> None:
    runtime, _plan, _receipt, _store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path / "target")
    )
    full = _full_runtime_descriptor(
        runtime,
        root=tmp_path / "target",
        plan_path=plan_path,
        receipt_path=receipt_path,
    )
    stable = model_acquisition_execution_descriptor(
        full,
        evidence_root=tmp_path / "target",
    )
    run = {
        "attacker": "nanogcg",
        "attacker_config": {
            "model_id": "Org/Surrogate",
            "model_revision": REVISIONS["surrogate"],
        },
        "defense_guardrail_model": "Org/Defense",
        "defense_guardrail_revision": REVISIONS["defense"],
        "guardrail_model": "Org/Guard",
        "guardrail_revision": REVISIONS["guard"],
        "judge_model": "mock",
        "judge_names": ["rules", "guardrail"],
        "local_identity": {"revision": REVISIONS["target"]},
        "model_spec": "vllm:Org/Target",
    }
    assert validate_model_acquisition_run_binding(stable, run) == stable

    suffixed = dict(run)
    suffixed["model_spec"] = (
        "vllm:Org/Target@" + REVISIONS["target"]
    )
    assert validate_model_acquisition_run_binding(stable, suffixed) == stable

    drifted_suffix = dict(run)
    drifted_suffix["model_spec"] = "vllm:Org/Target@" + ("f" * 40)
    with pytest.raises(ModelAcquisitionError, match="revision suffix differs"):
        validate_model_acquisition_run_binding(stable, drifted_suffix)

    changed = dict(run)
    changed["guardrail_model"] = "Org/OtherGuard"
    with pytest.raises(ModelAcquisitionError, match="differ from run config"):
        validate_model_acquisition_run_binding(stable, changed)

    judge_runtime, _plan, _receipt, _store, judge_plan_path, judge_receipt_path = (
        _sealed_runtime_fixture(
            tmp_path / "judge",
            selection=_judge_roles_selection(),
        )
    )
    judge_full = _full_runtime_descriptor(
        judge_runtime,
        root=tmp_path / "judge",
        plan_path=judge_plan_path,
        receipt_path=judge_receipt_path,
    )
    judge_stable = model_acquisition_execution_descriptor(
        judge_full,
        evidence_root=tmp_path / "judge",
    )
    judge_run = {
        **{key: value for key, value in run.items() if key != "local_identity"},
        "judge_local_identity": {"revision": REVISIONS["judge"]},
        "judge_model": "vllm:Org/Judge",
        "judge_names": ["rules", "guardrail", "llm"],
        "model_spec": "anthropic:HostedTarget",
    }
    assert validate_model_acquisition_run_binding(judge_stable, judge_run) == judge_stable
    judge_suffixed = dict(judge_run)
    judge_suffixed["judge_model"] = (
        "vllm:Org/Judge@" + REVISIONS["judge"]
    )
    assert (
        validate_model_acquisition_run_binding(judge_stable, judge_suffixed)
        == judge_stable
    )


def _stable_descriptor_for_selection(tmp_path: Path, selection) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    runtime, _plan, _receipt, _store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path, selection=selection)
    )
    return model_acquisition_execution_descriptor(
        _full_runtime_descriptor(
            runtime,
            root=tmp_path,
            plan_path=plan_path,
            receipt_path=receipt_path,
        ),
        evidence_root=tmp_path,
    )


def _not_required_descriptor_for_selection(selection) -> dict:
    return model_acquisition_execution_descriptor({
        "selection": public_selection_descriptor(selection),
        "status": "not_required",
    })


def test_hosted_targets_and_one_hub_vllm_target_share_exact_grid_descriptor(
    tmp_path: Path,
) -> None:
    revision = "6" * 40
    selection = build_runtime_selection(
        collect_run_requirements(
            target_specs=[
                "anthropic:hosted-a",
                "openai:hosted-b",
                "vllm:Org/LocalTarget",
            ],
            local_configs={"vllm:Org/LocalTarget": {"revision": revision}},
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings=BINDINGS,
    )
    stable = _stable_descriptor_for_selection(tmp_path / "legal-grid", selection)
    local_model = f"vllm:Org/LocalTarget@{revision}"
    grid = {
        "models": ["anthropic:hosted-a", "openai:hosted-b", local_model],
        "local_configs": {local_model: {"revision": revision}},
        "judges": ["rules"],
        "judge_model": None,
        "attackers": ["replay"],
        "attacker_configs": {},
    }
    assert validate_model_acquisition_grid_binding(stable, grid) == stable
    for cell in (
        {
            "model_spec": "anthropic:hosted-a",
            "local_identity": None,
            "judge_names": ["rules"],
            "attacker": "replay",
            "attacker_config": {},
        },
        {
            "model_spec": local_model,
            "local_identity": {"revision": revision},
            "judge_names": ["rules"],
            "attacker": "replay",
            "attacker_config": {},
        },
    ):
        assert validate_model_acquisition_run_binding(stable, cell) == stable
    for changed in (
        {**grid, "models": grid["models"][:2], "local_configs": {}},
        {
            **grid,
            "models": [*grid["models"], f"vllm:Org/Extra@{'7' * 40}"],
            "local_configs": {
                **grid["local_configs"],
                f"vllm:Org/Extra@{'7' * 40}": {"revision": "7" * 40},
            },
        },
        {
            **grid,
            "models": [*grid["models"][:2], f"vllm:Org/Other@{'8' * 40}"],
            "local_configs": {
                f"vllm:Org/Other@{'8' * 40}": {"revision": "8" * 40},
            },
        },
    ):
        with pytest.raises(ModelAcquisitionError, match="grid|inventory"):
            validate_model_acquisition_grid_binding(stable, changed)


def test_role_projections_prevent_unrelated_grid_targets_fragmenting_hosted_cells(
    tmp_path: Path,
) -> None:
    revision = "6" * 40
    hosted_selection = build_runtime_selection(
        collect_run_requirements(
            target_specs=["anthropic:hosted-a"],
            local_configs={},
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings={**BINDINGS, "local_config_sha256": "7" * 64},
    )
    mixed_selection = build_runtime_selection(
        collect_run_requirements(
            target_specs=["anthropic:hosted-a", "vllm:Org/LocalTarget"],
            local_configs={
                "vllm:Org/LocalTarget": {"revision": revision},
            },
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings=BINDINGS,
    )
    hosted_only = _not_required_descriptor_for_selection(hosted_selection)
    mixed = _stable_descriptor_for_selection(tmp_path / "mixed", mixed_selection)
    hosted_run = {
        "attacker": "replay",
        "attacker_config": {},
        "judge_names": ["rules"],
        "local_identity": None,
        "model_spec": "anthropic:hosted-a",
    }
    local_run = {
        **hosted_run,
        "local_identity": {"revision": revision},
        "model_spec": f"vllm:Org/LocalTarget@{revision}",
    }

    hosted_alone_projection = model_acquisition_cell_role_projection(
        hosted_only,
        hosted_run,
    )
    hosted_mixed_projection = model_acquisition_cell_role_projection(
        mixed,
        hosted_run,
    )
    assert hosted_alone_projection == hosted_mixed_projection
    runner = Runner(
        ReplayAttacker(),
        MockTarget(),
        JudgeCascade([RuleJudge()]),
        AttackBudget(max_queries=1, max_turns=1, seed=0),
        [0],
    )
    corpus = [
        item for item in synth_corpus(4)
        if set(item.modalities).issubset({"text"})
    ][:1]
    assert corpus
    hosted_alone_run = {
        **hosted_run,
        "model_acquisition": hosted_alone_projection,
    }
    hosted_mixed_run = {
        **hosted_run,
        "model_acquisition": hosted_mixed_projection,
    }
    assert runner.plan_manifest(
        corpus,
        run_config=hosted_alone_run,
    ).run_id == runner.plan_manifest(
        corpus,
        run_config=hosted_mixed_run,
    ).run_id
    assert model_acquisition_shared_role_projection(hosted_only) == (
        model_acquisition_shared_role_projection(mixed)
    )
    assert not any(
        field in hosted_mixed_projection
        for field in ("plan_id", "plan_sha256", "selection")
    )
    local_projection = model_acquisition_cell_role_projection(mixed, local_run)
    assert local_projection != hosted_mixed_projection
    assert local_projection["resources"][0]["roles"] == ["vllm_target"]
    assert (
        model_acquisition_shared_from_cell_projection(local_projection)
        == model_acquisition_shared_role_projection(mixed)
    )
    assert validate_model_acquisition_role_projection_binding(
        hosted_mixed_projection,
        mixed,
        run_config=hosted_run,
    ) == hosted_mixed_projection
    assert validate_model_acquisition_role_projection_binding(
        local_projection,
        mixed,
        run_config=local_run,
    ) == local_projection

    with pytest.raises(ModelAcquisitionError, match="differs from full grid"):
        validate_model_acquisition_role_projection_binding(
            local_projection,
            mixed,
            run_config=hosted_run,
        )
    with pytest.raises(ModelAcquisitionError, match="differs from full grid"):
        validate_model_acquisition_role_projection_binding(
            hosted_mixed_projection,
            mixed,
            run_config=local_run,
        )

    forged = json.loads(json.dumps(local_projection))
    forged["resources"][0]["tree_sha256"] = "f" * 64
    projection_body = {
        key: value for key, value in forged.items()
        if key != "projection_sha256"
    }
    forged["projection_sha256"] = hashlib.sha256(
        json.dumps(
            projection_body,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    assert validate_model_acquisition_role_projection(forged) == forged
    with pytest.raises(ModelAcquisitionError, match="differs from full grid"):
        validate_model_acquisition_role_projection_binding(
            forged,
            mixed,
            run_config=local_run,
        )


def test_shared_role_projection_changes_when_shared_model_evidence_changes(
    tmp_path: Path,
) -> None:
    revision = "6" * 40
    without_guard = build_runtime_selection(
        collect_run_requirements(
            target_specs=["vllm:Org/LocalTarget"],
            local_configs={
                "vllm:Org/LocalTarget": {"revision": revision},
            },
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings=BINDINGS,
    )
    with_guard = build_runtime_selection(
        collect_run_requirements(
            target_specs=["vllm:Org/LocalTarget"],
            local_configs={
                "vllm:Org/LocalTarget": {"revision": revision},
            },
            judge_names=["rules", "guardrail"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
            guardrail_model="Org/Guard",
            guardrail_revision=REVISIONS["guard"],
        ),
        input_bindings=BINDINGS,
    )
    first = _stable_descriptor_for_selection(tmp_path / "plain", without_guard)
    second = _stable_descriptor_for_selection(tmp_path / "guard", with_guard)
    first_shared = model_acquisition_shared_role_projection(first)
    second_shared = model_acquisition_shared_role_projection(second)
    assert first_shared != second_shared
    assert second_shared["resources"][0]["roles"] == ["guardrail_judge"]
    assert validate_model_acquisition_role_projection_binding(
        second_shared,
        second,
    ) == second_shared


@pytest.mark.parametrize(
    "target_specs",
    [
        ["vllm:Org/First", "vllm:Org/Second"],
        ["vllm:Org/First", "vllm:C:/operator/second"],
        ["vllm:C:/operator/first", "vllm:C:/operator/second"],
    ],
)
def test_requirement_projection_rejects_more_than_one_local_target(
    target_specs: list[str],
) -> None:
    with pytest.raises(ModelAcquisitionError, match="one local target"):
        collect_run_requirements(
            target_specs=target_specs,
            local_configs={},
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        )


@pytest.mark.parametrize("failure", ["missing_receipt", "tampered_receipt", "tampered_tree"])
def test_absent_or_tampered_receipt_fails_before_any_constructor(
    tmp_path: Path,
    failure: str,
) -> None:
    runtime, plan, _receipt, store, _plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    if failure == "missing_receipt":
        receipt_path.unlink()
    elif failure == "tampered_receipt":
        receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    else:
        resource_id = plan["resources"][0]["resource_id"]
        (store / resource_id / "snapshot" / "config.json").write_bytes(b"same-size-no")
    constructors: list[str] = []
    requirement = runtime._selection.requirements[0]  # private fixture assertion only
    with pytest.raises(ModelAcquisitionError):
        runtime.construct(requirement, lambda _path: constructors.append("called"))
    assert constructors == []


def test_every_consumer_constructs_only_after_preverify_and_postverify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _plan, _receipt, _store, _plan_path, _receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    verification_count = 0
    original = runtime_module.verify_receipt_snapshots

    def observe(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal verification_count
        verification_count += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime_module, "verify_receipt_snapshots", observe)
    loaded = []
    for requirement in runtime._selection.requirements:  # private fixture assertion only
        before = verification_count

        def construct(path: Path, *, role=requirement.role):
            assert verification_count == before + 1
            assert path.is_absolute() and path.name == "snapshot"
            loaded.append(role)
            return {"role": role}

        result = runtime.construct(requirement, construct)
        assert result == {"role": requirement.role}
        assert verification_count == before + 2
    assert set(loaded) == {
        "vllm_target",
        "guardrail_judge",
        "defense_guardrail",
        "nanogcg_surrogate",
    }


def test_post_load_tamper_discards_engine_and_never_returns_it(tmp_path: Path) -> None:
    selection = build_runtime_selection(
        collect_run_requirements(
            target_specs=["vllm:Org/Target"],
            local_configs={
                "vllm:Org/Target": {"revision": REVISIONS["target"]},
            },
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings=BINDINGS,
    )
    runtime, _plan, _receipt, _store, _plan_path, _receipt_path = (
        _sealed_runtime_fixture(tmp_path, selection=selection)
    )
    calls: list[str] = []

    class Engine:
        pass

    def construct(path: Path) -> Engine:
        calls.append("constructed")
        target = path / "config.json"
        raw = target.read_bytes()
        target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        return Engine()

    def cleanup(_engine: Engine) -> None:
        calls.append("cleaned")

    with pytest.raises(ModelAcquisitionError, match="changed after acquisition"):
        runtime.construct(selection.requirements[0], construct, cleanup=cleanup)
    assert calls == ["constructed", "cleaned"]
    assert "inference" not in calls


def test_runtime_shared_lock_blocks_controller_exclusive_lock_during_load(
    tmp_path: Path,
) -> None:
    selection = build_runtime_selection(
        collect_run_requirements(
            target_specs=["vllm:Org/Target"],
            local_configs={
                "vllm:Org/Target": {"revision": REVISIONS["target"]},
            },
            judge_names=["rules"],
            judge_model="mock",
            attacker_names=["replay"],
            attacker_configs={},
        ),
        input_bindings=BINDINGS,
    )
    runtime, _plan, _receipt, store, _plan_path, _receipt_path = (
        _sealed_runtime_fixture(tmp_path, selection=selection)
    )
    script = "\n".join(
        (
            "import sys",
            "from pathlib import Path",
            "from experiments.model_acquire import _ResourceLock",
            "from ura.model_acquisition import ModelAcquisitionError",
            "try:",
            "    with _ResourceLock(Path(sys.argv[1])):",
            "        raise SystemExit(2)",
            "except ModelAcquisitionError:",
            "    raise SystemExit(0)",
        )
    )

    def construct(path: Path) -> object:
        lock_path = store / f".{path.parent.name}.lock"
        attempted = subprocess.run(
            [sys.executable, "-c", script, str(lock_path)],
            cwd=Path(__file__).resolve().parents[2],
            check=False,
        )
        assert attempted.returncode == 0
        return object()

    runtime.construct(selection.requirements[0], construct)


def test_runtime_shared_lock_rejects_multiply_linked_external_file(
    tmp_path: Path,
) -> None:
    store = (tmp_path / "store").resolve()
    store.mkdir()
    resource_id = "hf-" + "a" * 32
    external = tmp_path / "external-shared-lock"
    external.write_bytes(b"sentinel")
    os.link(external, store / f".{resource_id}.lock")

    with pytest.raises(ModelAcquisitionError, match="busy|unsafe"):
        with runtime_module._SharedResourceLock(store, resource_id):
            raise AssertionError("unsafe shared lock unexpectedly acquired")

    assert external.read_bytes() == b"sentinel"


def test_constructor_failure_scrubs_every_private_locator(tmp_path: Path) -> None:
    runtime, _plan, _receipt, store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )

    def fail(path: Path):  # noqa: ANN202
        raise RuntimeError(
            f"loader exposed {path} {store} {plan_path} {receipt_path}"
        )

    with pytest.raises(ManagedModelLoadError) as caught:
        runtime.construct(runtime._selection.requirements[0], fail)
    message = str(caught.value)
    for private in (store, plan_path, receipt_path):
        assert str(private) not in message
    assert "[managed-model-private]" in message


def test_private_path_sanitizer_covers_case_separator_json_and_uri_spellings(
    tmp_path: Path,
) -> None:
    private = (tmp_path / "Private Model Store" / "Receipt.JSON").resolve()
    spellings = [
        str(private).swapcase(),
        str(private).replace("\\", "/").swapcase(),
        json.dumps(str(private), ensure_ascii=False)[1:-1].swapcase(),
        private.as_uri().swapcase(),
    ]
    rendered = runtime_module.sanitize_private_paths(
        " | ".join(spellings),
        [private],
    )
    assert rendered.count("[managed-model-private]") == len(spellings)
    for spelling in spellings:
        assert spelling.casefold() not in rendered.casefold()


def test_constructor_and_inference_output_scrub_private_locators(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime, _plan, _receipt, store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    requirement = runtime._selection.requirements[0]

    def construct(snapshot: Path) -> object:
        print(f"loader snapshot={snapshot}")
        print(f"loader store={store}", file=sys.stderr)
        return object()

    runtime.construct(requirement, construct)
    captured = capsys.readouterr()
    assert "[managed-model-private]" in captured.out + captured.err
    for private in (store, plan_path, receipt_path):
        assert str(private) not in captured.out + captured.err

    def fail_inference() -> None:
        print(f"inference snapshot={store / 'secret'}")
        raise RuntimeError(f"inference failure at {store / 'secret'}")

    with pytest.raises(ManagedModelLoadError) as caught:
        runtime.private_execution(requirement.role, fail_inference)
    captured = capsys.readouterr()
    assert "[managed-model-private]" in captured.out
    assert str(store) not in captured.out
    assert str(store) not in str(caught.value)


def test_prebound_logger_native_fd_and_child_stderr_are_redacted(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    runtime, _plan, _receipt, store, _plan_path, _receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    requirement = runtime._selection.requirements[0]
    logger = logging.getLogger("ura-test-prebound-model-handler")
    logger.handlers.clear()
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(sys.stderr))

    def construct(_snapshot: Path) -> object:
        logger.info("logger store=%s", store)
        os.write(2, f"native store={store}\n".encode())
        subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write(sys.stdin.read())",
            ],
            input=f"child store={store}\n",
            text=True,
            check=True,
        )
        return object()

    try:
        runtime.construct(requirement, construct)
    finally:
        logger.handlers.clear()
    captured = capfd.readouterr()
    rendered = captured.out + captured.err
    assert rendered.count("[managed-model-private]") >= 3
    assert str(store) not in rendered


def test_cancellation_still_performs_post_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, _plan, _receipt, _store, _plan_path, _receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    verifications = 0
    original = runtime_module.verify_receipt_snapshots

    def observe(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        nonlocal verifications
        verifications += 1
        return original(*args, **kwargs)

    class Cancelled(BaseException):
        pass

    def cancel(_path: Path):  # noqa: ANN202
        raise Cancelled

    monkeypatch.setattr(runtime_module, "verify_receipt_snapshots", observe)
    with pytest.raises(Cancelled):
        runtime.construct(runtime._selection.requirements[0], cancel)
    assert verifications == 2


def test_ticket_drift_rejects_before_store_verification_or_constructor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _target_roles_selection()
    runtime, _plan, _receipt, store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path, selection=first)
    )
    drifted = build_runtime_selection(
        collect_run_requirements(
            target_specs=["vllm:Org/Target"],
            local_configs={
                "vllm:Org/Target": {"revision": REVISIONS["target"]},
            },
            judge_names=["rules", "guardrail"],
            judge_model="mock",
            attacker_names=["replay", "nanogcg"],
            attacker_configs={
                "nanogcg": {
                    "model_id": "Org/Surrogate",
                    "model_revision": REVISIONS["surrogate"],
                }
            },
            guardrail_model="Org/Guard",
            guardrail_revision=REVISIONS["guard"],
            defense_guardrail_model="Org/Defense",
            defense_guardrail_revision=REVISIONS["defense"],
        ),
        input_bindings={**BINDINGS, "builder_ticket_sha256": "f" * 64},
    )
    verifications: list[str] = []
    monkeypatch.setattr(
        runtime_module,
        "verify_receipt_snapshots",
        lambda *_a, **_k: verifications.append("verified"),
    )
    drifted_runtime = ManagedModelRuntime(
        selection=drifted,
        plan_path=plan_path,
        plan_sha256=runtime._plan_sha256,
        receipt_path=receipt_path,
        receipt_sha256=runtime._receipt_sha256,
        managed_store=store,
    )
    with pytest.raises(ModelAcquisitionError, match="resources or immutable"):
        drifted_runtime.admit()
    assert verifications == []


def test_unplanned_consumer_is_rejected_without_constructor(tmp_path: Path) -> None:
    runtime, _plan, _receipt, _store, _plan_path, _receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    called: list[str] = []
    with pytest.raises(ModelAcquisitionError, match="unplanned"):
        runtime.construct(
            hub_requirement("vllm_target", "Org/Other", "f" * 40),
            lambda _path: called.append("called"),
        )
    assert called == []


def test_offline_loader_policy_is_explicit_and_private_path_is_in_memory_only(
    tmp_path: Path,
) -> None:
    snapshot = (tmp_path / "snapshot").resolve()
    snapshot.mkdir()
    assert hf_offline_environment_overrides() == {
        "DO_NOT_TRACK": "1",
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "VLLM_NO_USAGE_STATS": "1",
    }
    assert transformers_local_only_kwargs() == {"local_files_only": True}
    transformer_path, transformer_kwargs = transformers_managed_snapshot_args(snapshot)
    assert transformer_path == str(snapshot)
    assert transformer_kwargs == {"local_files_only": True}
    assert vllm_managed_snapshot_kwargs(snapshot) == {
        "model": str(snapshot),
        "tokenizer": str(snapshot),
    }


def test_one_call_helper_admits_before_returning_runtime(tmp_path: Path) -> None:
    original, _plan, _receipt, store, plan_path, receipt_path = (
        _sealed_runtime_fixture(tmp_path)
    )
    admitted, descriptor = admit_managed_model_runtime(
        selection=original._selection,
        plan_path=plan_path,
        plan_sha256=original._plan_sha256,
        receipt_path=receipt_path,
        receipt_sha256=original._receipt_sha256,
        managed_store=store,
    )
    assert isinstance(admitted, ManagedModelRuntime)
    assert descriptor == admitted.public_descriptor()


def test_interpreter_scripts_directory_is_prepended_to_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A local engine must be able to find the build tools shipped beside it.

    vLLM's sampler JIT-builds a FlashInfer kernel on first use and shells out to
    ninja; Torch's C++ extension loader does the same. ninja is installed into
    the running interpreter's own scripts directory, but invoking that
    interpreter by absolute path - which is what the documented commands and the
    console both do - leaves that directory off PATH, and the failure surfaces
    only as an engine that would not initialize.
    """

    from ura import model_acquisition_runtime as runtime

    # A virtual environment's interpreter is a LINK to a base interpreter that
    # lives somewhere else entirely. Resolving it lands in the base
    # installation's scripts directory, which is precisely where the
    # environment's own tools are not; the venv's own bin is what must win.
    scripts = tmp_path / "venv" / "bin"
    scripts.mkdir(parents=True)
    base = tmp_path / "base" / "bin"
    base.mkdir(parents=True)
    (base / "python").write_text("", encoding="utf-8")
    interpreter = scripts / "python"
    try:
        interpreter.symlink_to(base / "python")
    except (OSError, NotImplementedError):  # pragma: no cover - unprivileged Windows
        interpreter.write_text("", encoding="utf-8")
    monkeypatch.setattr(runtime.sys, "executable", str(interpreter))
    monkeypatch.setattr(
        runtime.sysconfig, "get_path", lambda name: str(scripts) if name == "scripts" else ""
    )

    existing = str(tmp_path / "usr" / "bin")
    monkeypatch.setenv("PATH", existing)
    runtime.ensure_interpreter_scripts_on_path()
    entries = os.environ["PATH"].split(os.pathsep)
    assert entries[0] == str(scripts), "the environment's own scripts directory must win"
    assert existing in entries, "the operator's PATH must be preserved, not replaced"
    assert str(base) not in entries, (
        "resolving the interpreter link would add the base installation's bin, "
        "which does not contain the environment's tools"
    )

    # Idempotent: repeated engine construction must not grow PATH without bound.
    runtime.ensure_interpreter_scripts_on_path()
    runtime.ensure_interpreter_scripts_on_path()
    assert os.environ["PATH"].split(os.pathsep).count(str(scripts)) == 1

    # An empty PATH yields exactly the scripts directory, with no stray separator
    # that would put the current working directory on PATH.
    monkeypatch.setenv("PATH", "")
    runtime.ensure_interpreter_scripts_on_path()
    assert os.environ["PATH"] == str(scripts)


def test_local_engines_put_their_scripts_directory_on_path() -> None:
    """Both local engine construction paths must apply the fix, not just one."""

    from pathlib import Path as _Path

    for module in ("src/ura/targets/local.py", "src/ura/judges/guardrail.py"):
        text = _Path(module).read_text(encoding="utf-8")
        assert "ensure_interpreter_scripts_on_path" in text, module
        # It must run before the engine/model is constructed, not after.
        call = text.index("ensure_interpreter_scripts_on_path()")
        construction = min(
            (text.index(marker) for marker in ("from vllm import LLM", "def construct(") if marker in text),
            default=len(text),
        )
        assert call < construction, f"{module}: PATH must be set before construction"


def test_private_capture_supports_the_file_protocol_loaders_actually_use() -> None:
    """Third-party model code asks the stream for its descriptor.

    The sealed wrapper replaces sys.stdout/sys.stderr with a bounded capture so
    that private model locators cannot reach a log. But a loader does not treat
    those streams as bare writers: it asks for the underlying descriptor to hand
    to a child process or to native code. Without fileno() the capture raised
    AttributeError inside vLLM's engine-core subprocess, where the exception
    died, so the only symptom was a generic "Engine core initialization failed"
    and no sealed local model could load at all.
    """

    import io as _io

    from ura import model_acquisition_runtime as runtime

    capture = runtime._BoundedPrivateOutput(descriptor=2)
    # The descriptor is the one _capture_file_descriptor has already redirected,
    # so handing it onward still lands in this capture rather than the console.
    assert capture.fileno() == 2
    assert capture.writable() is True
    assert capture.readable() is False
    assert capture.seekable() is False
    assert capture.isatty() is False
    capture.flush()

    # Still a capture: writing through the object is retained and bounded.
    capture.write("sealed output\n")
    assert "sealed output" in capture.text()

    # With no descriptor it must raise the io-protocol error, which well-behaved
    # callers handle, rather than AttributeError, which they do not.
    detached = runtime._BoundedPrivateOutput()
    with pytest.raises(_io.UnsupportedOperation):
        detached.fileno()


def test_sealed_execution_gives_its_captures_real_descriptors() -> None:
    """The wrapper must wire the descriptors, not just support them."""

    import inspect

    from ura import model_acquisition_runtime as runtime

    source = inspect.getsource(runtime.private_model_execution)
    assert "_BoundedPrivateOutput(descriptor=1)" in source
    assert "_BoundedPrivateOutput(descriptor=2)" in source
