from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Sequence

import pytest

from experiments.local_campaign import current_ollama_phase6 as phase6
from experiments.local_campaign import (
    current_ollama_population_alignment_phase6 as phase6_alignment,
)
from experiments.local_campaign import current_ollama_stability_phase6 as phase6_stability
from experiments.local_campaign import resume_current_ollama_phase6 as phase6_recovery

from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_IMAGE_MODELS,
    CURRENT_OLLAMA_MODELS,
    CURRENT_OLLAMA_NATIVE_ROLES,
    CURRENT_OLLAMA_NUM_CTX,
    CURRENT_OLLAMA_NUM_PREDICT,
    CURRENT_OLLAMA_RUNNABLE_LANES,
    CURRENT_OLLAMA_TEXT_ONLY_MODELS,
    CURRENT_OLLAMA_TYPED_TERMINAL_LANES,
    CurrentOllamaModel,
    gptgeochat_lane,
    image_lane,
    rjudge_lane,
    text_lane,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _base_argv,
    _descriptor_file as _gate5_descriptor_file,
    _expected_dispositions,
    _has_exact_lane_inventory,
    _lane_contract,
    _validate_evidence_provenance,
    _validate_local_config,
    validate_amendment,
    validate_static_canary_stage_support,
)
from experiments.local_campaign.current_ollama_phase6 import (
    FAILURE_SCHEMA,
    PHASE7_INPUT_SCHEMA,
    _canonical,
    _counts_from_level1,
    _create_json,
    _descriptor,
    _probe_args,
    _retain_failure,
    validate_completion,
)


def _assert_exact_current_roster(models: Sequence[CurrentOllamaModel]) -> None:
    assert [model.tag for model in models] == [
        "gemma4:12b-it-q4_K_M",
        "ministral-3:14b-instruct-2512-q4_K_M",
        "deepseek-r1:32b-qwen-distill-q4_K_M",
        "gpt-oss:20b",
    ]
    assert len({model.label for model in models}) == 4
    assert len({model.tag for model in models}) == 4
    assert [model.digest for model in models] == [
        "4eb23ef187e2c5462566d6a1d3bbbc2f1346d0b4327cbb66d58fffbcc9b2b05c",
        "4760c35aeb9d9e9c6174c2492562c0b999e80a222804fd96b1915ab72bbcdcf7",
        "edba8017331d15236e57480eb45406c0d721db77a4cdcf234df500fc2ad3960c",
        "17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7",
    ]
    assert [model.quantization for model in models] == [
        "Q4_K_M",
        "Q4_K_M",
        "Q4_K_M",
        "MXFP4",
    ]
    assert all(re.fullmatch(r"[0-9a-f]{64}", model.digest) for model in models)
    assert all(
        "rwkv" not in model.tag.lower() and "mollysama" not in model.tag.lower() for model in models
    )


def test_current_ollama_roster_is_exact_recent_thesis_cohort() -> None:
    _assert_exact_current_roster(CURRENT_OLLAMA_MODELS)
    assert CURRENT_OLLAMA_NUM_CTX == 8192
    assert CURRENT_OLLAMA_NUM_PREDICT == 512


def test_current_ollama_gate5_binds_bounded_context_and_output_caps(
    tmp_path: Path,
) -> None:
    model = CURRENT_OLLAMA_MODELS[2]
    path = tmp_path / "deepseek.json"
    config = {
        model.spec: {
            "digest": model.digest,
            "modalities": list(model.modalities),
            "num_ctx": CURRENT_OLLAMA_NUM_CTX,
            "num_predict": CURRENT_OLLAMA_NUM_PREDICT,
        }
    }
    path.write_text(json.dumps(config), encoding="utf-8")
    _validate_local_config(path, model_label=model.label)

    config[model.spec]["num_ctx"] = 131072
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="exact local configuration changed"):
        _validate_local_config(path, model_label=model.label)


def test_current_ollama_gate5_accepts_only_the_content_identical_archived_project_receipt(
    tmp_path: Path,
) -> None:
    receipt_root = tmp_path / "project-revision"
    archived = receipt_root / "superseded" / "project-revision-old.json"
    archived.parent.mkdir(parents=True)
    payload = b'{"schema":"ura-project-revision/1"}\n'
    archived.write_bytes(payload)
    original = receipt_root / archived.name
    descriptor = {
        "path": str(original),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }

    assert _gate5_descriptor_file(
        descriptor,
        label="project_revision",
        allow_superseded_project_revision=True,
    ) == original
    with pytest.raises(ValueError, match="canonical regular file"):
        _gate5_descriptor_file(descriptor, label="project_revision")

    archived.write_bytes(payload + b" ")
    with pytest.raises(ValueError, match="descriptor content changed"):
        _gate5_descriptor_file(
            descriptor,
            label="project_revision",
            allow_superseded_project_revision=True,
        )

    source = inspect.getsource(validate_amendment)
    assert "allow_superseded_project_revision=True" in source


@pytest.mark.parametrize(
    ("index", "changes"),
    (
        (0, {"tag": "mollysama/rwkv-7-g1f:2.9b"}),
        (2, {"quantization": "F16"}),
        (3, {"digest": "0" * 64}),
    ),
)
def test_current_ollama_roster_regression_detects_identity_mutations(
    index: int, changes: dict[str, str]
) -> None:
    mutant = list(CURRENT_OLLAMA_MODELS)
    mutant[index] = replace(mutant[index], **changes)
    with pytest.raises(AssertionError):
        _assert_exact_current_roster(mutant)


def test_current_ollama_modalities_roles_and_lanes_are_not_conflated() -> None:
    assert [model.label for model in CURRENT_OLLAMA_IMAGE_MODELS] == [
        "gemma4-12b",
        "ministral3-14b",
    ]
    assert [model.label for model in CURRENT_OLLAMA_TEXT_ONLY_MODELS] == [
        "deepseek-r1-distill-32b",
        "gpt-oss-20b",
    ]
    native_roles = {role: model.label for role, model in CURRENT_OLLAMA_NATIVE_ROLES.items()}
    assert native_roles == {
        "primary": "gemma4-12b",
        "secondary": "ministral3-14b",
        "auditor": "deepseek-r1-distill-32b",
        "judge": "gpt-oss-20b",
    }
    assert len(CURRENT_OLLAMA_RUNNABLE_LANES) == 12
    assert set(CURRENT_OLLAMA_TYPED_TERMINAL_LANES) == {
        "gptgeochat-ollama-deepseek-r1-distill-32b",
        "gptgeochat-ollama-gpt-oss-20b",
    }
    assert not set(CURRENT_OLLAMA_RUNNABLE_LANES) & set(CURRENT_OLLAMA_TYPED_TERMINAL_LANES)


def test_image_lane_rejects_text_only_model() -> None:
    with pytest.raises(ValueError, match="not image-capable"):
        image_lane(CURRENT_OLLAMA_TEXT_ONLY_MODELS[0])


def test_prospective_controllers_use_only_the_current_ollama_roster() -> None:
    templates = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    for name in (
        "phase5_ollama_workflow.sh.in",
        "phase6_native_diagnostics.sh.in",
    ):
        source = (templates / name).read_text(encoding="utf-8")
        assert "mollysama/" not in source
        assert "CURRENT_OLLAMA_NATIVE_ROLES" in source or name.startswith("phase5_")
    # The analysis controllers retain exact historical evidence identities,
    # including superseded RWKV rows, but use the separate current roster.
    for name in ("phase7_analysis.py.in", "phase8_human_audit.py.in"):
        source = (templates / name).read_text(encoding="utf-8")
        assert "CURRENT_OLLAMA_NATIVE_ROLES" in source
    native = (templates / "phase6_native_diagnostics.sh.in").read_text(encoding="utf-8")
    assert "the exact local Ollama roster has no tool-call capability" not in native
    assert "set(expected_models) != set(EXPECTED_MODELS)" in native
    assert 'get("quantization_level")' in native

    rr_amendment = (templates / "phase6_seven_output_policy.py.in").read_text(encoding="utf-8")
    prospective_specs = rr_amendment.split("SPEC_SOURCES = (", 1)[1].split("\n)\nLANE_ORDER", 1)[0]
    assert "rwkv" not in prospective_specs.lower()
    assert "mollysama" not in prospective_specs.lower()


def test_current_rr_amendment_excludes_retired_rwkv_rows_from_analysis() -> None:
    templates = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    expected = [
        "local-llava-rr-text-primary-100",
        "local-llava-rr-image-primary-100",
        "rjudge-llava-rr",
        "gptgeochat-llava-rr",
    ]
    for name in ("phase7_analysis.py.in", "phase8_human_audit.py.in"):
        source = (templates / name).read_text(encoding="utf-8")
        amendment = source.split("SEVEN_AMENDMENT_LANES = (", 1)[1].split(
            "\n)\nSEVEN_TERMINAL_STATES", 1
        )[0]
        assert re.findall(r'"([a-z0-9-]+)"', amendment) == expected
        assert "rwkv" not in amendment.lower()
    phase7 = (templates / "phase7_analysis.py.in").read_text(encoding="utf-8")
    assert '"output_policy_amendment": 4' in phase7


def test_current_ollama_phase5_emits_a_consumable_gate5_amendment() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_ollama_workflow.sh.in"
    ).read_text(encoding="utf-8")
    build = (
        "experiments.local_campaign.current_ollama_gate5 --build \\\n"
        '    --control-root "$CONTROL_ROOT"'
    )
    validate = 'experiments.local_campaign.current_ollama_gate5 --validate "$GATE5_AMENDMENT"'
    assert build in template
    assert validate in template
    assert template.index(build) < template.index(
        "-m experiments.local_campaign.console_events \\\n    target-execution"
    )
    assert 'GATE5_AMENDMENT="$CONTROL_ROOT/gate5-current-ollama-amendment.json"' in template


def test_current_ollama_phase5_recovery_reuses_only_completed_evidence() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments"
        / "local_campaign"
        / "templates"
        / "phase5_ollama_workflow.sh.in"
    ).read_text(encoding="utf-8")
    assert 'RECOVERY_SOURCE_ROOT="${URA_PHASE5_OLLAMA_RECOVERY_SOURCE_ROOT:-}"' in template
    assert "reuse_projection_lane" in template
    assert "reuse_attestation" in template
    assert 'local label="$1" modality="$2"\n  local key="${label}/${modality}"' in template
    assert "revalidate_canary_lane" in template
    assert "record_revalidated" in template
    assert "recovery_source_all_completed()" in template
    assert "RECOVERY_REUSE=all_completed_exact_config" in template
    assert "static text airbench_full completed" in template
    assert "gptgeochat image gptgeochat_release completed" in template
    assert 'observed_id="$(validate_attestation_receipt' in template
    assert 'test "$observed_id" = "$attestation_id"' in template
    completed_start = template.index("  if recovery_source_all_completed; then")
    completed_end = template.index(
        "  else\n  # Only DeepSeek's text attestation failed", completed_start
    )
    completed_branch = template[completed_start:completed_end]
    assert "run_isolated" not in completed_branch
    assert completed_branch.count("reuse_attestation") == 2
    assert completed_branch.count("revalidate_canary_lane") == 4
    assert "recovery_configs_match()" in template
    assert 'source_config="$RECOVERY_SOURCE_ROOT/local-configs/${label}.json"' in template
    assert '! cmp -s -- "$source_config" "${MODEL_CONFIGS[$label]}"' in template
    assert (
        'if [[ -n "$RECOVERY_SOURCE_ROOT" ]] && recovery_configs_match; then'
        in template
    )
    assert "RECOVERY_REUSE=disabled_exact_local_config_changed" in template
    assert "if [[ \"$label\" == 'deepseek-r1-distill-32b' ]]; then" in template
    assert "if [[ \"$label\" == 'gemma4-12b' ]]; then" in template
    assert 'run_canary_lane "$image_lane" "$label" static image mmsafety_official' in template
    assert "evidence-provenance.tsv" in template


def test_current_ollama_gate5_accepts_exact_interleaved_controller_rows() -> None:
    observed = [
        lane
        for model in CURRENT_OLLAMA_MODELS
        for lane in (text_lane(model), rjudge_lane(model))
    ] + [
        lane
        for model in CURRENT_OLLAMA_IMAGE_MODELS
        for lane in (image_lane(model), gptgeochat_lane(model))
    ]
    assert observed != list(CURRENT_OLLAMA_RUNNABLE_LANES)
    rows = [{"lane": lane} for lane in observed]
    assert _has_exact_lane_inventory(rows, CURRENT_OLLAMA_RUNNABLE_LANES)

    rows[-1] = {"lane": rows[0]["lane"]}
    assert not _has_exact_lane_inventory(rows, CURRENT_OLLAMA_RUNNABLE_LANES)


def test_current_ollama_gate5_validator_accepts_exact_interleaved_status_rows() -> None:
    source = inspect.getsource(validate_amendment)

    assert source.count("not _has_exact_lane_inventory(") == 2
    assert "list(by_projection)" not in source
    assert "list(by_canary)" not in source


def test_current_ollama_gate5_binds_execution_and_validation_cohorts(
    tmp_path: Path,
) -> None:
    current_commit = "1" * 40
    historical_commit = "2" * 40
    current = tmp_path / "phase5-ollama-current"
    historical = tmp_path / "phase5-ollama-historical"
    for root, commit in ((current, current_commit), (historical, historical_commit)):
        root.mkdir()
        (root / "ENGINEERING_ONLY.json").write_text(
            json.dumps({
                "schema": "ura-engineering-campaign/1",
                "release_commit": commit,
                "hosted_calls_allowed": False,
            }),
            encoding="utf-8",
        )

    pairs = sorted(_expected_dispositions())
    dispositions = [
        {"phase": phase, "unit": unit, "disposition": "completed", "reason": "validated"}
        for phase, unit in pairs
    ]
    rows = [
        {
            "phase": phase,
            "unit": unit,
            "execution_commit": historical_commit if index == 0 else current_commit,
            "validation_commit": current_commit,
            "evidence_mode": "revalidated" if index == 0 else "executed",
            "source_control_root": str(historical if index == 0 else current),
        }
        for index, (phase, unit) in enumerate(pairs)
    ]

    result = _validate_evidence_provenance(
        rows,
        dispositions=dispositions,
        expected_commit=current_commit,
        control_root=current,
    )
    assert set(result) == set(pairs)
    rows[0]["validation_commit"] = historical_commit
    with pytest.raises(ValueError, match="provenance is malformed"):
        _validate_evidence_provenance(
            rows,
            dispositions=dispositions,
            expected_commit=current_commit,
            control_root=current,
        )


def test_static_canary_stage_support_aggregates_authority_role_partitions() -> None:
    rows = [
        {
            "stage": 0,
            "judge": "rules",
            "role": "authoritative",
            "trail_records": 6,
            "queried_records": 6,
            "not_queried_records": 0,
            "reached": True,
        },
        {
            "stage": 0,
            "judge": "rules",
            "role": "shadow",
            "trail_records": 9,
            "queried_records": 9,
            "not_queried_records": 0,
            "reached": True,
        },
        {
            "stage": 1,
            "judge": "guardrail",
            "role": "authoritative",
            "trail_records": 9,
            "queried_records": 9,
            "not_queried_records": 0,
            "reached": True,
        },
        {
            "stage": 1,
            "judge": "guardrail",
            "role": "shadow",
            "trail_records": 6,
            "queried_records": 6,
            "not_queried_records": 0,
            "reached": True,
        },
    ]
    validate_static_canary_stage_support(rows, completed=15, nonresponses=0)
    rows[1]["queried_records"] = 8
    with pytest.raises(ValueError, match="typed nonresponses"):
        validate_static_canary_stage_support(rows, completed=15, nonresponses=0)


def test_current_ollama_gate5_lane_contract_keeps_caps_sampling_and_judges_exact() -> None:
    modes: list[str] = []
    for lane in CURRENT_OLLAMA_RUNNABLE_LANES:
        label = next(model.label for model in CURRENT_OLLAMA_MODELS if model.label in lane)
        mode, _modality, arms, judges = _lane_contract(lane, label)
        modes.append(mode)
        argv = _base_argv(
            model_label=label,
            mode=mode,
            arms=arms,
            judges=judges,
            project_revision=Path("/evidence/project-revision.json"),
            project_sha256="1" * 64,
            source_config=Path("/source/source-instances.json"),
            source_sha256="2" * 64,
            source_conformance=Path("/evidence/source-conformance.json"),
            conformance_sha256="3" * 64,
            local_config=Path(f"/control/local-configs/{label}.json"),
            local_config_sha256="4" * 64,
        )
        assert argv[argv.index("--limit") + 1] == "50"
        assert argv[argv.index("--sample-seed") + 1] == "0"
        assert argv[argv.index("--judges") + 1] == judges
        assert ("--approximate-common-metrics" in argv) is (mode == "static")
        assert ("--guardrail-model" in argv) is (mode == "static")
    assert modes.count("static") == 6
    assert modes.count("rjudge") == 4
    assert modes.count("gptgeochat") == 2


def _phase6_row(*, modality: str) -> dict[str, object]:
    model = CURRENT_OLLAMA_MODELS[0]
    arms = ("mmsafety_official",) if modality == "image" else ("airbench_full",)
    return {
        "lane_id": f"test-{modality}",
        "modality": modality,
        "model": {
            "spec": model.spec,
            "digest": model.digest,
        },
        "base_argv": _base_argv(
            model_label=model.label,
            mode="static",
            arms=arms,
            judges="rules,guardrail",
            project_revision=Path("/evidence/project-revision.json"),
            project_sha256="1" * 64,
            source_config=Path("/source/source-instances.json"),
            source_sha256="2" * 64,
            source_conformance=Path("/evidence/source-conformance.json"),
            conformance_sha256="3" * 64,
            local_config=Path(f"/control/local-configs/{model.label}.json"),
            local_config_sha256="4" * 64,
        ),
    }


def test_current_ollama_phase6_uses_fresh_modality_specific_transport_probes() -> None:
    text = _probe_args(_phase6_row(modality="text"), scope="scope", out=Path("/text"))
    image = _probe_args(_phase6_row(modality="image"), scope="scope", out=Path("/image"))
    assert text[text.index("--corpora") + 1] == "synth"
    assert "--source-config" not in text
    assert image[image.index("--corpora") + 1] == "harmbench_multimodal"
    assert image[image.index("--source-config") + 1] == "/source/source-instances.json"
    assert text[text.index("--max-total-target-calls") + 1] == "1"
    assert image[image.index("--max-total-target-calls") + 1] == "1"


def test_current_ollama_phase6_retains_nonresponses_in_measured_counts() -> None:
    level1 = {
        "counts": {
            "judgment_records": {
                "completed": 10,
                "missing_responses": 3,
            }
        }
    }
    assert _counts_from_level1(level1) == (10, 7, 3)
    level1["counts"]["judgment_records"]["missing_responses"] = 11
    with pytest.raises(ValueError, match="target/missing-response"):
        _counts_from_level1(level1)


def test_current_ollama_recovery_does_not_double_count_mirrored_checkpoints(
    tmp_path: Path,
) -> None:
    result_root = tmp_path / "lane"
    result_root.mkdir()
    for index, count in enumerate((50, 20)):
        (result_root / f"cell-{index}.complete.json").write_text(
            json.dumps({"n_responses": count}), encoding="utf-8"
        )
    rows = "".join(json.dumps({"row": index}) + "\n" for index in range(3))
    (result_root / "partial.checkpoint.jsonl").write_text(rows, encoding="utf-8")
    (result_root / "partial.responses.checkpoint.jsonl").write_text(
        rows, encoding="utf-8"
    )

    assert phase6_recovery._completed_records(result_root) == 70
    assert phase6_recovery._checkpoint_records(result_root) == 3


def test_current_ollama_recovery_reuses_exact_state_argv_and_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "1" * 40
    lane = "ollama-fixture-text-primary-50"
    project = tmp_path / "project"
    runner_root = tmp_path / "runner"
    result_root = runner_root / lane
    base_control = tmp_path / "phase6-current-ollama-fixture"
    state_root = base_control / "lanes" / lane
    control = tmp_path / "phase6-current-ollama-recovery-fixture"
    for path in (project, result_root, state_root):
        path.mkdir(parents=True)
    gate5 = tmp_path / "gate5.json"
    gate5.write_text("{}\n", encoding="ascii")
    base_completion = base_control / "completion.json"
    base_completion.write_text("{}\n", encoding="ascii")
    python_target = tmp_path / "python-real"
    python_target.write_text("fixture\n", encoding="ascii")
    python_target.chmod(0o700)
    python = tmp_path / "venv" / "bin" / "python"
    python.parent.mkdir(parents=True)
    python.symlink_to(python_target)
    (result_root / "sealed.complete.json").write_text(
        json.dumps({"n_responses": 2}), encoding="utf-8"
    )
    checkpoint = result_root / "partial.checkpoint.jsonl"
    checkpoint.write_text(
        "".join(json.dumps({"row": index}) + "\n" for index in range(3)),
        encoding="utf-8",
    )
    exact_argv = [
        "--deadline-seconds", "60", "--out", str(result_root), "--fixed", "value"
    ]
    state = {
        "argv": exact_argv,
        "result_root": str(result_root),
        "attestation": {"path": str(tmp_path / "attestation"), "sha256": "2" * 64},
    }
    monkeypatch.setattr(
        phase6_recovery,
        "validate_completion",
        lambda **_kwargs: {"terminal_states": {lane: "failed"}},
    )
    monkeypatch.setattr(
        phase6_recovery,
        "validate_amendment",
        lambda *_args, **_kwargs: {"project_commit": commit},
    )
    monkeypatch.setattr(
        phase6_recovery, "_tracked_checkout_commit", lambda _path: commit
    )
    monkeypatch.setattr(
        phase6_recovery, "_load_state", lambda *_args, **_kwargs: state
    )
    observed: list[list[str]] = []

    def complete_exact(*, python: Path, argv: Sequence[str], log: Path, timeout: int) -> int:
        del python, timeout
        observed.append(list(argv))
        log.write_text("resumed\n", encoding="ascii")
        checkpoint.unlink()
        (result_root / "recovered.complete.json").write_text(
            json.dumps({"n_responses": 3}), encoding="utf-8"
        )
        return 0

    def level1(**kwargs) -> tuple[int, int, int]:
        lane_root = kwargs["lane_root"]
        (lane_root / "level1.json").write_text("{}\n", encoding="ascii")
        return 5, 4, 1

    monkeypatch.setattr(phase6_recovery, "_run_exact", complete_exact)
    monkeypatch.setattr(phase6_recovery, "_level1_counts", level1)
    lifecycle: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        phase6_recovery,
        "start_child_controller",
        lambda **kwargs: lifecycle.append(("start", kwargs)),
    )
    monkeypatch.setattr(
        phase6_recovery,
        "publish_target_execution",
        lambda **kwargs: lifecycle.append(("target", kwargs)),
    )
    monkeypatch.setattr(
        phase6_recovery,
        "finish_child_controller",
        lambda **kwargs: lifecycle.append(("finish", kwargs)),
    )

    assert phase6_recovery.run(
        gate5_path=gate5,
        base_completion=base_completion,
        runner_root=runner_root,
        control_root=control,
        project_root=project,
        python=python,
        work_root=tmp_path,
        tmux_socket="default",
        tmux_session="ura-recovery-fixture",
        wait_seconds=1,
        poll_seconds=1,
        max_lane_launches=1,
    ) == 0
    assert observed == [exact_argv]
    completion = json.loads((control / "completion.json").read_text(encoding="utf-8"))
    row = completion["rows"][0]
    assert row["initial_completed_responses"] == 2
    assert row["initial_checkpointed_responses"] == 3
    assert row["final_completed_responses"] == 5
    assert row["final_checkpointed_responses"] == 0
    assert row["missing_responses"] == 1
    assert [event for event, _ in lifecycle] == ["start", "target", "finish"]
    assert lifecycle[0][1]["target_execution"] is True
    assert lifecycle[1][1]["target_attempts"] == 5
    assert lifecycle[1][1]["successful_target_generations"] == 4
    assert lifecycle[2][1]["exit_code"] == 0


def test_current_ollama_recovery_is_required_and_overlaid_for_phase7(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    lane = "ollama-fixture-text-primary-50"
    commit = "1" * 40
    gate5 = tmp_path / "gate5-current-ollama-amendment.json"
    gate5.write_text("{}\n", encoding="ascii")
    base_root = tmp_path / "phase6-current-ollama-fixture"
    base_root.mkdir()
    base_completion = base_root / "completion.json"
    base_completion.write_text("{}\n", encoding="ascii")
    runner_root = tmp_path / "runner"
    result_root = runner_root / lane
    result_root.mkdir(parents=True)
    _create_json(result_root / "fixture.grid.json", {})
    _create_json(result_root / "fixture.request-envelope.json", {})
    _create_json(result_root / "eligibility-fixture.eligibility.json", {})
    _create_json(result_root / "fixture.complete.json", {"n_responses": 5})

    base = {
        "schema": PHASE7_INPUT_SCHEMA,
        "status": "validated",
        "lane_order": [lane],
        "terminal_states": {lane: "failed"},
        "lifecycle": {
            lane: {
                "state": "failed",
                "result_root": str(result_root),
                "runner_lifecycle_present": True,
                "evidence": {"failure": {"sha256": "2" * 64}},
            }
        },
        "metric_lane_order": [],
        "metric_roots": {},
        "metric_evidence": {},
        "metric_grids": [],
        "metric_completion_markers": [],
        "metric_eligibility_plans": [],
        "excluded_from_metrics": {
            lane: {"reason_code": "measured_lane_failed", "reason": "fixture"}
        },
        "revision_strata": {},
        "project_revision_receipt_sha256": "3" * 64,
        "source_conformance_sha256": "4" * 64,
        "gate5": _descriptor(gate5, label="fixture Gate 5"),
        "completion": _descriptor(base_completion, label="fixture base completion"),
        "target_execution": {
            "target_attempts": 0,
            "successful_target_generations": 0,
            "missing_responses": 0,
            "accounting_scope": "completion_bound_level1_records",
        },
        "paid_provider_calls": 0,
        "cross_revision_pooling_permitted": False,
        "cross_source_pooling_permitted": False,
    }
    monkeypatch.setattr(
        phase6_recovery, "validate_completion", lambda **_kwargs: base
    )
    monkeypatch.setattr(
        phase6_recovery,
        "validate_amendment",
        lambda *_args, **_kwargs: {"project_commit": commit},
    )

    recovery_root = tmp_path / "phase6-current-ollama-recovery-fixture"
    lane_root = recovery_root / "lanes" / lane
    lane_root.mkdir(parents=True)
    launch_log = lane_root / "resume-1.log"
    launch_log.write_text("complete\n", encoding="ascii")
    level1 = lane_root / "level1.json"
    _create_json(
        level1,
        {"counts": {"judgment_records": {"completed": 5, "missing_responses": 1}}},
    )
    controller_source = Path(phase6_recovery.__file__).resolve()
    body = {
        "schema": phase6_recovery.SCHEMA,
        "status": "complete",
        "base_phase6": _descriptor(base_completion, label="fixture base completion"),
        "gate5": _descriptor(gate5, label="fixture Gate 5"),
        "controller_source": _descriptor(
            controller_source, label="fixture recovery controller"
        ),
        "project_commit": commit,
        "failed_lanes_selected": [lane],
        "recovered_lanes": 1,
        "remaining_failed_lanes": 0,
        "rows": [
            {
                "lane_id": lane,
                "status": "complete",
                "initial_completed_responses": 2,
                "initial_checkpointed_responses": 3,
                "launches": [
                    {
                        "number": 1,
                        "returncode": 0,
                        "log": _descriptor(launch_log, label="fixture recovery log"),
                    }
                ],
                "result_root": str(result_root),
                "target_attempts": 5,
                "successful_target_generations": 4,
                "missing_responses": 1,
                "final_completed_responses": 5,
                "final_checkpointed_responses": 0,
                "level1": _descriptor(level1, label="fixture recovery Level 1"),
            }
        ],
        "paid_provider_calls": 0,
    }
    body["recovery_id"] = "current-ollama-recovery-" + hashlib.sha256(
        _canonical(body)
    ).hexdigest()[:24]
    recovery_completion = recovery_root / "completion.json"
    _create_json(recovery_completion, body)
    (recovery_root / ".exit").write_text("0\n", encoding="ascii")

    value = phase6_recovery.validate_recovery_completion(
        gate5_path=gate5,
        base_completion=base_completion,
        recovery_completion=recovery_completion,
        runner_root=runner_root,
    )
    assert value["schema"] == phase6_recovery.PHASE7_INPUT_SCHEMA
    assert value["terminal_states"] == {lane: "measured_complete"}
    assert value["metric_lane_order"] == [lane]
    assert value["target_execution"]["missing_responses"] == 1
    assert value["excluded_from_metrics"] == {}

    body["rows"][0]["missing_responses"] = 2
    body.pop("recovery_id")
    body["recovery_id"] = "current-ollama-recovery-" + hashlib.sha256(
        _canonical(body)
    ).hexdigest()[:24]
    recovery_completion.unlink()
    _create_json(recovery_completion, body)
    with pytest.raises(ValueError, match="recovered response accounting"):
        phase6_recovery.validate_recovery_completion(
            gate5_path=gate5,
            base_completion=base_completion,
            recovery_completion=recovery_completion,
            runner_root=runner_root,
        )


def test_current_ollama_recovery_metric_evidence_is_lane_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    roots = {
        lane: tmp_path / lane
        for lane in ("ollama-fixture-a", "ollama-fixture-b")
    }
    observed: list[tuple[str, Path]] = []

    def artifacts(*, lane: str, result_root: Path) -> tuple[
        dict[str, str], dict[str, str], dict[str, str], list[dict[str, str]]
    ]:
        observed.append((lane, result_root))
        return (
            {"path": f"/{lane}.grid.json"},
            {"path": f"/{lane}.request-envelope.json"},
            {"path": f"/{lane}.eligibility.json"},
            [{"path": f"/{lane}.complete.json"}],
        )

    monkeypatch.setattr(phase6_recovery, "_metric_artifacts", artifacts)
    evidence = {
        lane: phase6_recovery._recovered_metric_evidence(
            lane=lane,
            result_root=root,
            base_failure={"lane": lane},
            recovery_descriptor={"sha256": lane},
            level1={"path": f"/{lane}.level1.json"},
        )
        for lane, root in roots.items()
    }

    assert observed == list(roots.items())
    for lane in roots:
        assert evidence[lane]["grid"]["path"] == f"/{lane}.grid.json"
        assert evidence[lane]["request_envelope"]["path"] == (
            f"/{lane}.request-envelope.json"
        )
        assert evidence[lane]["base_failure"] == {"lane": lane}

    source = Path(phase6_recovery.__file__).read_text(encoding="utf-8")
    overlay = source.split(
        "for lane, row in recovered_rows.items():", 1
    )[1].split("metric_lane_order =", 1)[0]
    assert "evidence = _recovered_metric_evidence(" in overlay
    assert "lane=lane" in overlay
    assert 'Path(row["result_root"])' in overlay


def test_current_ollama_stability_selects_only_exact_missing_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    by_lane: dict[str, list[tuple[str, int, int]]] = {
        lane: [] for lane in phase6_stability.FAILED_LANES
    }
    for _unit, lane, corpus, remaining, prefix in phase6_stability.EXPECTED_LAYOUT:
        by_lane[lane].append((corpus, remaining, prefix))

    gate5_rows = []
    lifecycle = {}
    counts_by_lane: dict[str, dict[str, int]] = {}
    for lane in phase6_stability.FAILED_LANES:
        result_root = tmp_path / lane
        result_root.mkdir()
        lifecycle[lane] = {"result_root": str(result_root)}
        completed, _checkpointed = phase6_stability.EXPECTED_DURABLE_COUNTS[lane]
        counts = {"already_complete": completed}
        counts.update({
            corpus: remaining + prefix
            for corpus, remaining, prefix in by_lane[lane]
        })
        counts_by_lane[lane] = counts
        gate5_rows.append({
            "lane_id": lane,
            "selection": {"corpora": list(counts)},
            "base_argv": ["--corpora", ",".join(counts)],
            "modality": "text" if "text" in lane else "image",
        })

    monkeypatch.setattr(
        phase6_stability,
        "_projection_counts",
        lambda spec: counts_by_lane[str(spec["lane_id"])],
    )

    def corpus_state(
        *, corpus: str, selected_records: int, result_root: Path
    ) -> tuple[int, dict[str, object] | None, bool]:
        lane = result_root.name
        if corpus == "already_complete":
            return selected_records, None, True
        _name, remaining, prefix = next(
            row for row in by_lane[lane] if row[0] == corpus
        )
        assert selected_records == remaining + prefix
        recovery = (
            {
                "schema": phase6_stability.PREFIX_SCHEMA,
                "corpus": corpus,
                "completed_prefix_count": prefix,
            }
            if prefix
            else None
        )
        return prefix, recovery, False

    monkeypatch.setattr(phase6_stability, "_corpus_state", corpus_state)
    units, durable = phase6_stability.build_units(
        gate5={"lanes": gate5_rows},
        base={"lifecycle": lifecycle},
    )

    assert [
        (
            unit.unit_id,
            unit.source_lane,
            unit.corpus,
            unit.selected_records,
            int(unit.recovery["completed_prefix_count"])
            if unit.recovery is not None
            else 0,
        )
        for unit in units
    ] == list(phase6_stability.EXPECTED_LAYOUT)
    assert sum(unit.selected_records for unit in units) == 1684
    assert durable == {
        "ollama-gemma4-12b-text-primary-50": 880,
        "ollama-gemma4-12b-image-primary-50": 503,
        "ollama-ministral3-14b-image-primary-50": 528,
    }
    assert all(unit.corpus != "already_complete" for unit in units)


def test_current_ollama_stability_publishes_tmux_job_lifecycle() -> None:
    source = Path(phase6_stability.__file__).read_text(encoding="utf-8")
    assert source.count("start_child_controller(") == 1
    assert source.count("publish_target_execution(") == 1
    assert source.count("finish_child_controller(") == 1
    assert 'evidence_class="measured_local_current_ollama_stability"' in source
    assert 'parser.add_argument("--tmux-session", required=True)' in source
    assert '"target_answer_retries": 1' in source
    assert '"no_completed_rows_repeated": True' in source
    assert "state_schema=UNIT_STATE_SCHEMA" in source


def test_current_ollama_alignment_uses_the_common_limit_100_population(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate5_rows: list[dict[str, object]] = []
    selected_100: dict[str, tuple[list[object], dict[str, object]]] = {}
    selected_50: dict[str, tuple[list[object], dict[str, object]]] = {}
    old_selected: dict[str, dict[str, dict[str, object]]] = {}
    expected_delta = 0
    for index, lane in enumerate(CURRENT_OLLAMA_RUNNABLE_LANES):
        if lane.startswith("rjudge-"):
            mode, modality = "rjudge", "text"
        elif lane.startswith("gptgeochat-"):
            mode, modality = "gptgeochat", "image"
        elif "-image-" in lane:
            mode, modality = "static", "image"
        else:
            mode, modality = "static", "text"
        full = phase6_alignment.EXPECTED_FULL_BY_MODE[(mode, modality)]
        prefix = phase6_alignment.EXPECTED_PREFIX_BY_MODE[(mode, modality)]
        corpus = f"fixture_arm_{index}"
        ids = [f"{corpus}-{row}" for row in range(full)]
        ids_50 = ids[full - prefix:]
        selected_100[corpus] = (
            [SimpleNamespace(id=item) for item in ids],
            {"full_converted_corpus_sha256": "f" * 64},
        )
        selected_50[corpus] = (
            [SimpleNamespace(id=item) for item in ids_50],
            {"full_converted_corpus_sha256": "f" * 64},
        )
        old_selected[lane] = {
            corpus: {
                "selected_records": prefix,
                "selected_datapoint_ids_sha256": phase6_alignment._sha256_json(
                    sorted(ids_50)
                ),
                "limit": 50,
                "sample_seed": 0,
                "full_converted_corpus_sha256": "f" * 64,
            }
        }
        gate5_rows.append({
            "lane_id": lane,
            "metric_mode": mode,
            "modality": modality,
            "selection": {"corpora": [corpus], "limit": 50, "sample_seed": 0},
            "base_argv": [
                "--corpora",
                corpus,
                "--limit",
                "50",
                "--sample-seed",
                "0",
                "--target-answer-retries",
                "1",
            ],
        })
        expected_delta += full - prefix

    monkeypatch.setattr(
        phase6_alignment,
        "_selected_100",
        lambda _gate5, _specs: selected_100,
    )
    monkeypatch.setattr(
        phase6_alignment,
        "_selected_50",
        lambda _gate5, _specs: selected_50,
    )
    monkeypatch.setattr(
        phase6_alignment,
        "_old_selected_corpora",
        lambda spec: old_selected[str(spec["lane_id"])],
    )
    units = phase6_alignment.build_alignment_units({"lanes": gate5_rows})

    assert len(units) == 12
    assert expected_delta == phase6_alignment.EXPECTED_EXTENSION_ROWS == 11_600
    assert sum(item.unit.selected_records for item in units) == 11_600
    assert all(
        phase6_alignment._option(item.unit.spec["base_argv"], "--limit") == "100"
        and phase6_alignment._option(
            item.unit.spec["base_argv"], "--sample-seed"
        ) == "0"
        and phase6_alignment._option(
            item.unit.spec["base_argv"], "--target-answer-retries"
        ) == "1"
        and item.recovery["schema"] == "ura-recovery-completed-selection/1"
        for item in units
    )
    first = units[0]
    first_corpus = next(iter(first.recovery["corpora"]))
    assert first.recovery["corpora"][first_corpus][
        "completed_datapoint_ids"
    ] == sorted(row.id for row in selected_50[first_corpus][0])

    first_lane = str(gate5_rows[0]["lane_id"])
    first_corpus = next(iter(old_selected[first_lane]))
    old_selected[first_lane][first_corpus][
        "selected_datapoint_ids_sha256"
    ] = "0" * 64
    with pytest.raises(ValueError, match="limit-50 prefix changed"):
        phase6_alignment.build_alignment_units({"lanes": gate5_rows})

    source = Path(phase6_alignment.__file__).read_text(encoding="utf-8")

    def assert_result_membership(candidate: str) -> None:
        assert "set(results) != set(ALIGNMENT_LANES)" in candidate

    assert_result_membership(source)
    changed = source.replace(
        "set(results) != set(ALIGNMENT_LANES)",
        "list(results) != list(ALIGNMENT_LANES)",
        1,
    )
    assert changed != source
    with pytest.raises(AssertionError):
        assert_result_membership(changed)


def test_current_ollama_stability_completion_is_a_separate_runner_226_stratum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner_root = tmp_path / "runs" / "thesis" / "runner"
    control_root = (
        tmp_path / "runs" / "engineering" / "phase6-ollama-stability-fixture"
    )
    runner_root.mkdir(parents=True)
    (control_root / "units").mkdir(parents=True)
    inputs = {}
    for name in ("gate5", "base", "recovery"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}\n", encoding="utf-8")
        inputs[name] = path
    units = [
        phase6_stability.Unit(
            unit_id=unit_id,
            source_lane=lane,
            corpus=corpus,
            spec={},
            selected_records=remaining,
            recovery=None,
        )
        for unit_id, lane, corpus, remaining, _prefix
        in phase6_stability.EXPECTED_LAYOUT
    ]
    durable = {
        "ollama-gemma4-12b-text-primary-50": 880,
        "ollama-gemma4-12b-image-primary-50": 503,
        "ollama-ministral3-14b-image-primary-50": 528,
    }
    monkeypatch.setattr(
        phase6_stability,
        "validate_failed_recovery",
        lambda **_kwargs: {"gate5": {}, "base": {}},
    )
    monkeypatch.setattr(
        phase6_stability,
        "build_units",
        lambda **_kwargs: (units, durable),
    )
    revision_sha = "e" * 64
    source_sha = "f" * 64
    results: dict[str, object] = {}
    for unit in units:
        unit_root = control_root / "units" / unit.unit_id
        result_root = runner_root / unit.unit_id / control_root.name
        unit_root.mkdir()
        result_root.mkdir(parents=True)
        for name in (
            f"{unit.unit_id}.grid.json",
            f"{unit.unit_id}.request-envelope.json",
            f"eligibility-{unit.unit_id}.eligibility.json",
            f"{unit.unit_id}.complete.json",
        ):
            (result_root / name).write_text("{}\n", encoding="utf-8")
        state = {
            "schema": phase6_stability.UNIT_STATE_SCHEMA,
            "unit_id": unit.unit_id,
            "source_lane": unit.source_lane,
            "corpus": unit.corpus,
            "selected_records": unit.selected_records,
            "target_answer_retries": 1,
            "target_call_cap": unit.selected_records * 2,
            "attestation": {},
            "projection": {},
            "result_root": str(result_root),
            "runner_argv": [
                "--project-revision-sha256",
                revision_sha,
                "--source-conformance-sha256",
                source_sha,
                "--target-answer-retries",
                "1",
                "--corpora",
                unit.corpus,
            ],
        }
        state_path = unit_root / "state.json"
        state_path.write_text(json.dumps(state) + "\n", encoding="utf-8")
        level1 = unit_root / "level1.json"
        level1.write_text("{}\n", encoding="utf-8")
        results[unit.unit_id] = {
            "status": "complete",
            "unit_id": unit.unit_id,
            "source_lane": unit.source_lane,
            "corpus": unit.corpus,
            "selected_records": unit.selected_records,
            "target_answer_retries": 1,
            "target_call_cap": unit.selected_records * 2,
            "target_attempts": unit.selected_records,
            "successful_target_generations": unit.selected_records,
            "missing_responses": 0,
            "result_root": str(result_root),
            "state": phase6_stability._descriptor(
                state_path, label=f"{unit.unit_id} state"
            ),
            "level1": phase6_stability._descriptor(
                level1, label=f"{unit.unit_id} Level 1"
            ),
        }
    order = [unit.unit_id for unit in units]
    selected_total = sum(unit.selected_records for unit in units)
    launch = {
        "schema": "ura-current-ollama-stability-phase6-launch/1",
        "started_at_utc": "2026-08-31T00:00:00Z",
        "expected_commit": "a" * 40,
        "execution_scope_id": "fixture-local-ollama",
        "target_answer_retries": 1,
        "gate5": phase6_stability._descriptor(inputs["gate5"], label="gate5"),
        "base_completion": phase6_stability._descriptor(
            inputs["base"], label="base"
        ),
        "failed_recovery_completion": phase6_stability._descriptor(
            inputs["recovery"], label="recovery"
        ),
        "historical_durable_rows": durable,
        "unit_order": order,
        "selected_missing_rows": selected_total,
        "no_completed_rows_repeated": True,
        "paid_provider_calls": 0,
    }
    launch_path = control_root / "launch.json"
    launch_path.write_text(json.dumps(launch) + "\n", encoding="utf-8")
    completion = {
        "schema": phase6_stability.SCHEMA,
        "status": "complete",
        "controller_exit_code": 0,
        "completed_at_utc": "2026-08-31T00:01:00Z",
        "expected_commit": "a" * 40,
        "runner_code_version": phase6_stability.RUNNER_CODE_VERSION,
        "target_answer_retries": 1,
        "launch": phase6_stability._descriptor(launch_path, label="launch"),
        "unit_order": order,
        "unit_results": results,
        "unit_failures": {},
        "historical_durable_rows": durable,
        "selected_missing_rows": selected_total,
        "target_execution": {
            "target_attempts": selected_total,
            "successful_target_generations": selected_total,
            "missing_responses": 0,
        },
        "model_stability_accounting": (
            "provider_neutral_retry_then_retain_failed_output_as_missing_response"
        ),
        "no_completed_rows_repeated": True,
        "cross_output_policy_pooling_permitted": False,
        "paid_provider_calls": 0,
    }
    completion_path = control_root / "completion.json"
    completion_path.write_text(json.dumps(completion) + "\n", encoding="utf-8")

    view = phase6_stability.validate_completion(
        completion_path, runner_root=runner_root
    )

    assert view["metric_lane_order"] == order
    assert view["target_execution"]["target_attempts"] == 1684
    assert view["historical_durable_rows"] == durable
    assert view["cross_output_policy_pooling_permitted"] is False

    completion["cross_output_policy_pooling_permitted"] = True
    completion_path.write_text(json.dumps(completion) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="completion contract changed"):
        phase6_stability.validate_completion(
            completion_path, runner_root=runner_root
        )


def test_current_ollama_stability_binds_exact_durable_prefix(tmp_path: Path) -> None:
    corpus = "airbench_full"
    selected = ["row-a", "row-b", "row-c"]
    manifest = tmp_path / f"{corpus}--fixture.manifest.json"
    manifest.write_text(
        json.dumps({
            "config": {"run": {"sampling_audit": {"selected_ids": selected}}}
        }),
        encoding="utf-8",
    )
    attempts = tmp_path / f"{corpus}--fixture.attempts.jsonl"
    attempts.write_text(
        "".join(json.dumps({"datapoint_id": item}) + "\n" for item in selected[:2]),
        encoding="utf-8",
    )

    completed, recovery, complete = phase6_stability._corpus_state(
        corpus=corpus,
        selected_records=3,
        result_root=tmp_path,
    )
    assert completed == 2
    assert complete is False
    assert recovery is not None
    assert recovery["completed_prefix_count"] == 2
    assert recovery["corpus"] == corpus

    marker = tmp_path / f"{corpus}--fixture.complete.json"
    marker.write_text(json.dumps({"n_responses": 3}), encoding="utf-8")
    with pytest.raises(ValueError, match="historical completion count changed"):
        phase6_stability._corpus_state(
            corpus=corpus,
            selected_records=3,
            result_root=tmp_path,
        )

    attempts.write_text(
        "".join(json.dumps({"datapoint_id": item}) + "\n" for item in selected),
        encoding="utf-8",
    )
    assert phase6_stability._corpus_state(
        corpus=corpus,
        selected_records=3,
        result_root=tmp_path,
    ) == (3, None, True)


def test_current_ollama_phase6_retains_typed_pre_runner_failure(tmp_path: Path) -> None:
    lane = "ollama-fixture-text-primary-50"
    result_root = tmp_path / "runs" / "thesis" / "runner" / lane
    result_root.parent.mkdir(parents=True)
    lane_root = tmp_path / "runs" / "engineering" / "phase6" / "lanes" / lane
    gate5 = tmp_path / "gate5-current-ollama-amendment.json"
    gate5.write_text("{}\n", encoding="ascii")
    gate5_sha = hashlib.sha256(gate5.read_bytes()).hexdigest()

    descriptor = _retain_failure(
        lane=lane,
        lane_root=lane_root,
        result_root=result_root,
        gate5_path=gate5,
        gate5_sha256=gate5_sha,
        expected_commit="1" * 40,
        stage="preflight",
        error=ValueError("fixture transport failure"),
    )

    failure = result_root / "current-ollama.failure.json"
    value = json.loads(failure.read_text(encoding="utf-8"))
    assert descriptor == {
        "path": str(failure),
        "sha256": hashlib.sha256(failure.read_bytes()).hexdigest(),
        "bytes": failure.stat().st_size,
    }
    assert value["schema"] == FAILURE_SCHEMA
    assert value["status"] == "failed"
    assert value["result_root_created_for_failure"] is True
    assert value["runner_lifecycle_present"] is False
    assert value["state"] is None
    assert value["target_attempts"] is None
    assert value["successful_target_generations"] is None
    assert value["missing_responses"] is None
    assert value["paid_provider_calls"] == 0


def test_current_ollama_phase7_input_retains_missing_and_failed_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = "1" * 40
    gate5_root = tmp_path / "phase5-ollama-fixture"
    gate5_root.mkdir()
    gate5_path = gate5_root / "gate5-current-ollama-amendment.json"
    gate5_path.write_text("{}\n", encoding="ascii")
    (gate5_root / ".exit").write_text("0\n", encoding="ascii")
    gate5_sha = hashlib.sha256(gate5_path.read_bytes()).hexdigest()
    typed = {
        lane: {
            "disposition": "unavailable",
            "reason_code": "target_transport_text_only_for_image_source",
            "reason": (
                "GPTGeoChat requires image-bearing source inputs, while this exact "
                "Ollama target is text-only."
            ),
        }
        for lane in CURRENT_OLLAMA_TYPED_TERMINAL_LANES
    }
    gate5 = {
        "project_commit": commit,
        "project_revision": {"sha256": "2" * 64},
        "source_conformance": {"sha256": "3" * 64},
        "typed_terminal_lanes": typed,
    }
    monkeypatch.setattr(phase6, "validate_amendment", lambda *_args, **_kwargs: gate5)

    runner_root = tmp_path / "runs" / "thesis" / "runner"
    runner_root.mkdir(parents=True)
    control = tmp_path / "phase6-current-ollama-20260829T000000Z"
    (control / "lanes").mkdir(parents=True)
    status_rows: list[dict[str, object]] = []
    for lane in CURRENT_OLLAMA_TYPED_TERMINAL_LANES:
        status_rows.append(
            {
                "lane_id": lane,
                "status": "unavailable",
                "reason_code": typed[lane]["reason_code"],
                "reason": typed[lane]["reason"],
                "target_attempts": 0,
                "successful_target_generations": 0,
                "missing_responses": 0,
            }
        )
    complete_lane = CURRENT_OLLAMA_RUNNABLE_LANES[0]
    for lane in CURRENT_OLLAMA_RUNNABLE_LANES:
        result_root = runner_root / lane
        lane_root = control / "lanes" / lane
        lane_root.mkdir()
        if lane == complete_lane:
            result_root.mkdir()
            _create_json(result_root / "fixture.grid.json", {})
            _create_json(result_root / "fixture.request-envelope.json", {})
            _create_json(result_root / "eligibility-fixture.eligibility.json", {})
            _create_json(result_root / "fixture.complete.json", {})
            level1 = lane_root / "level1.json"
            _create_json(
                level1,
                {"counts": {"judgment_records": {"completed": 10, "missing_responses": 3}}},
            )
            status_rows.append(
                {
                    "lane_id": lane,
                    "status": "complete",
                    "result_root": str(result_root),
                    "level1": _descriptor(level1, label="fixture Level 1"),
                    "target_attempts": 10,
                    "successful_target_generations": 7,
                    "missing_responses": 3,
                }
            )
            continue
        failure = _retain_failure(
            lane=lane,
            lane_root=lane_root,
            result_root=result_root,
            gate5_path=gate5_path,
            gate5_sha256=gate5_sha,
            expected_commit=commit,
            stage="preflight",
            error=ValueError("fixture lane failure"),
        )
        status_rows.append(
            {
                "lane_id": lane,
                "status": "failed",
                "stage": "preflight",
                "error": "fixture lane failure",
                "result_root": str(result_root),
                "failure": failure,
                "target_attempts": None,
                "successful_target_generations": None,
                "missing_responses": None,
            }
        )
    status_path = control / "lanes.jsonl"
    status_path.write_bytes(b"".join(_canonical(row) for row in status_rows))
    completion_path = control / "completion.json"
    _create_json(
        completion_path,
        {
            "schema": phase6.SCHEMA,
            "status": "complete_with_failures",
            "project_commit": commit,
            "gate5": {"path": str(gate5_path), "sha256": gate5_sha},
            "runnable_lanes": len(CURRENT_OLLAMA_RUNNABLE_LANES),
            "typed_terminal_lanes": len(CURRENT_OLLAMA_TYPED_TERMINAL_LANES),
            "completed_lanes": 1,
            "failed_lanes": len(CURRENT_OLLAMA_RUNNABLE_LANES) - 1,
            "target_execution": {
                "target_attempts": 10,
                "successful_target_generations": 7,
                "missing_responses": 3,
                "accounting_scope": "completion_bound_level1_records",
            },
            "paid_provider_calls": 0,
            "status_rows": _descriptor(status_path, label="fixture status rows"),
        },
    )
    (control / ".exit").write_text("1\n", encoding="ascii")

    value = validate_completion(
        gate5_path=gate5_path,
        completion_path=completion_path,
        runner_root=runner_root,
    )
    assert value["schema"] == PHASE7_INPUT_SCHEMA
    assert value["metric_lane_order"] == [complete_lane]
    assert len(value["metric_grids"]) == 1
    assert len(value["metric_completion_markers"]) == 1
    assert len(value["metric_eligibility_plans"]) == 1
    assert value["target_execution"]["missing_responses"] == 3
    assert value["terminal_states"][complete_lane] == "measured_complete"
    assert len(value["excluded_from_metrics"]) == 13
    assert set(value["lane_order"]) == {
        *CURRENT_OLLAMA_RUNNABLE_LANES,
        *CURRENT_OLLAMA_TYPED_TERMINAL_LANES,
    }


def test_current_ollama_phase6_is_generated_and_rechecks_each_lane() -> None:
    root = Path(__file__).parents[2]
    generator = (root / "experiments" / "local_campaign" / "generate.py").read_text(
        encoding="utf-8"
    )
    verifier = (
        root / "experiments" / "local_campaign" / "templates" / "verify_controller_set.sh.in"
    ).read_text(encoding="utf-8")
    template = (
        root / "experiments" / "local_campaign" / "templates" / "phase6_current_ollama.sh.in"
    ).read_text(encoding="utf-8")
    runner = (root / "experiments" / "local_campaign" / "current_ollama_phase6.py").read_text(
        encoding="utf-8"
    )
    assert 'Controller("phase6_current_ollama.sh.in", "phase6_current_ollama.sh")' in generator
    assert '("phase6_current_ollama.sh", "none")' in verifier
    assert '--gate5-amendment "$GATE5_AMENDMENT"' in template
    assert "tmux new-session -d" in template
    assert "--hard-stop-hours 336" in template
    assert "--evidence-class measured_local_current_ollama" in template
    assert "--evidence-class measured-local-current-ollama" not in template
    loop = runner.split("    for row in rows:", 1)[1]
    assert "validate_amendment(gate5_path, expected_commit=expected_commit)" in loop
    assert "_validate_live_roster(project)" in loop
    assert "failure = _retain_failure(" in loop
    assert '"failure": failure' in loop
    assert loop.index("validate_amendment(") < loop.index("_build_state(")
