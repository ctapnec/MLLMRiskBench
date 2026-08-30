from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import re
from pathlib import Path
from typing import Sequence

import pytest

from experiments.local_campaign import current_ollama_phase6 as phase6

from experiments.local_campaign.current_ollama import (
    CURRENT_OLLAMA_IMAGE_MODELS,
    CURRENT_OLLAMA_MODELS,
    CURRENT_OLLAMA_NATIVE_ROLES,
    CURRENT_OLLAMA_RUNNABLE_LANES,
    CURRENT_OLLAMA_TEXT_ONLY_MODELS,
    CURRENT_OLLAMA_TYPED_TERMINAL_LANES,
    CurrentOllamaModel,
    image_lane,
)
from experiments.local_campaign.current_ollama_gate5 import (
    _base_argv,
    _expected_dispositions,
    _lane_contract,
    _validate_evidence_provenance,
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
        "phase7_analysis.py.in",
        "phase8_human_audit.py.in",
    ):
        source = (templates / name).read_text(encoding="utf-8")
        assert "mollysama/" not in source
        assert "CURRENT_OLLAMA_NATIVE_ROLES" in source or name.startswith("phase5_")
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
    assert "if [[ \"$label\" == 'deepseek-r1-distill-32b' ]]; then" in template
    assert "if [[ \"$label\" == 'gemma4-12b' ]]; then" in template
    assert 'run_canary_lane "$image_lane" "$label" static image mmsafety_official' in template
    assert "evidence-provenance.tsv" in template


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
    loop = runner.split("    for row in rows:", 1)[1]
    assert "validate_amendment(gate5_path, expected_commit=expected_commit)" in loop
    assert "_validate_live_roster(project)" in loop
    assert "failure = _retain_failure(" in loop
    assert '"failure": failure' in loop
    assert loop.index("validate_amendment(") < loop.index("_build_state(")
