from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import ModuleType, SimpleNamespace

import pytest

from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    CONTROLLERS,
    DERIVED_BINDINGS,
    render_controller_set,
)


def _template_tokens() -> set[str]:
    root = Path(__file__).parents[2] / "experiments" / "local_campaign" / "templates"
    token = re.compile(r"@@([A-Z][A-Z0-9_]*)@@")
    return {
        match
        for controller in CONTROLLERS
        for match in token.findall(
            (root / controller.template).read_text(encoding="utf-8")
        )
    } - DERIVED_BINDINGS


def _bindings(path: Path) -> Path:
    values = {name: f"value-{name.lower()}" for name in _template_tokens()}
    values["EXPECTED_COMMIT"] = "1" * 40
    for name in tuple(values):
        if name.endswith("SHA256"):
            values[name] = "2" * 64
        elif name == "PHASE3_DOWNLOADED_BYTES":
            values[name] = "0"
        elif name.endswith("_BYTES"):
            values[name] = "1"
        elif name.endswith("_TAG"):
            values[name] = "20260822T120000Z"
        elif name == "CONTROLLER_INSTALL_ROOT":
            values[name] = "/bound/.ura-controller-active"
        elif name.endswith(("_PATH", "_ROOT")):
            values[name] = f"/bound/{name.lower()}"
    path.write_text(
        json.dumps({"schema": BINDINGS_SCHEMA, "values": values}),
        encoding="utf-8",
    )
    return path


@pytest.fixture(scope="module")
def phase8(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    root = tmp_path_factory.mktemp("phase8-lifecycle")
    output = root / "rendered"
    render_controller_set(_bindings(root / "bindings.json"), output)
    path = output / "phase8_human_audit.py"
    spec = importlib.util.spec_from_file_location("phase8_lifecycle_test_module", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_phase8_embedded_self_test_keeps_success_and_conditional_profiles_distinct(
    phase8: ModuleType,
) -> None:
    assert phase8.main(["--self-test"]) == 0


def _descriptor(kind: str, index: int) -> dict[str, object]:
    return {
        "path": f"/runner/lane/{kind}-{index}.json",
        "sha256": f"{index + 1:064x}",
        "bytes": index + 1,
    }


def _ethics_record(phase8: ModuleType, runner_root: Path) -> dict[str, object]:
    return {
        "schema": phase8.ETHICS_SCHEMA,
        "status": "authorized",
        "determination_id": "operator-record-001",
        "decided_at_utc": "2026-08-28T12:00:00Z",
        "responsible_party": "accountable operator",
        "scope": {
            "expected_commit": phase8.EXPECTED_COMMIT,
            "framework_lock_id": phase8.EXPECTED_FRAMEWORK_LOCK,
            "runner_root": str(runner_root),
            "common_frame": True,
            "source_task_frame": True,
        },
        "sensitive_content_acknowledged": True,
        "preparation_authorized": True,
        "human_labeling_authorized": False,
        "consent_controls": {
            "document_version": "consent-v1",
            "informed_consent_before_exposure": True,
            "minors_excluded": True,
        },
        "compensation_controls": {
            "basis": "hourly at the recorded operator rate",
            "agreement_contingent": False,
        },
        "withdrawal_controls": {
            "process": "contact the accountable operator",
            "without_penalty": True,
        },
        "harmful_content_welfare_controls": {
            "advance_category_warnings": True,
            "category_opt_out_without_penalty": True,
            "continuous_exposure_limit": "30 minutes",
            "scheduled_breaks": True,
        },
        "escalation_controls": {
            "stop_contact": "named operator contact in the retained record",
            "adverse_event_process": "stop exposure and record escalation",
        },
    }


def test_phase8_ethics_contract_binds_exact_structured_record(
    phase8: ModuleType, tmp_path: Path
) -> None:
    runner_root = tmp_path / "runner"
    runner_root.mkdir()
    ethics_path = tmp_path / "ethics.json"
    ethics_path.write_bytes(phase8.canonical(_ethics_record(phase8, runner_root)))
    authorized_sha = phase8.sha256_file(ethics_path)

    observed = phase8.validate_ethics(
        ethics_path,
        authorized_sha,
        runner_root=runner_root,
    )
    assert observed["consent_controls"]["document_version"] == "consent-v1"
    assert observed["compensation_controls"]["agreement_contingent"] is False
    assert observed["withdrawal_controls"]["without_penalty"] is True
    assert observed["harmful_content_welfare_controls"]["scheduled_breaks"] is True
    assert observed["escalation_controls"]["adverse_event_process"]

    ethics_path.write_bytes(ethics_path.read_bytes() + b" ")
    with pytest.raises(phase8.Phase8Error, match="does not match exact bytes"):
        phase8.validate_ethics(
            ethics_path,
            authorized_sha,
            runner_root=runner_root,
        )


def test_phase8_input_manifest_binds_the_validated_ethics_snapshot(
    phase8: ModuleType,
) -> None:
    source = Path(phase8.__file__).read_text(encoding="utf-8")
    block = source[
        source.index("    ethics_path = checked_file(") :
        source.index("    audit_runner_root =", source.index("    ethics_path = checked_file("))
    ]
    manifest_block = source[
        source.index('        "ethics_determination": {') :
        source.index('        "sampling": {', source.index('        "ethics_determination": {'))
    ]
    assert "ethics_path, ethics_payload = _stable_regular_bytes(" in block
    assert "payload=ethics_payload" in block
    assert (
        '"artifact": descriptor_from_bytes(ethics_path, ethics_payload)'
        in manifest_block
    )


def test_phase8_ethics_contract_rejects_missing_or_weakened_controls(
    phase8: ModuleType, tmp_path: Path
) -> None:
    runner_root = tmp_path / "runner"
    runner_root.mkdir()
    mutations = {
        "consent": ("consent_controls", "informed_consent_before_exposure", False),
        "compensation": ("compensation_controls", "agreement_contingent", True),
        "withdrawal": ("withdrawal_controls", "without_penalty", False),
        "welfare": (
            "harmful_content_welfare_controls",
            "continuous_exposure_limit",
            "",
        ),
        "escalation": ("escalation_controls", "stop_contact", ""),
    }
    for name, (group, field, replacement) in mutations.items():
        candidate = _ethics_record(phase8, runner_root)
        candidate[group][field] = replacement
        path = tmp_path / f"ethics-{name}.json"
        path.write_bytes(phase8.canonical(candidate))
        with pytest.raises(
            phase8.Phase8Error,
            match="rater-protection controls differ",
        ):
            phase8.validate_ethics(
                path,
                phase8.sha256_file(path),
                runner_root=runner_root,
            )

    missing = _ethics_record(phase8, runner_root)
    del missing["escalation_controls"]
    path = tmp_path / "ethics-missing-escalation.json"
    path.write_bytes(phase8.canonical(missing))
    with pytest.raises(phase8.Phase8Error, match="required template"):
        phase8.validate_ethics(
            path,
            phase8.sha256_file(path),
            runner_root=runner_root,
        )

    free_form = _ethics_record(phase8, runner_root)
    free_form["details"] = {}
    path = tmp_path / "ethics-free-form-details.json"
    path.write_bytes(phase8.canonical(free_form))
    with pytest.raises(phase8.Phase8Error, match="required template"):
        phase8.validate_ethics(
            path,
            phase8.sha256_file(path),
            runner_root=runner_root,
        )


def test_phase8_machine_preparation_remains_human_only_blocked(
    phase8: ModuleType, tmp_path: Path
) -> None:
    ethics_path = tmp_path / "ethics.json"
    ethics_path.write_bytes(b"{}\n")
    ethics_binding = {
        "artifact": phase8.descriptor(ethics_path),
        "authorized_sha256": phase8.sha256_file(ethics_path),
        "determination_id": "operator-record-001",
        "status": "authorized",
        "preparation_authorized": True,
        "human_labeling_authorized": False,
    }
    blocker = {
        "schema": phase8.BLOCKER_SCHEMA,
        "status": "human_only_blocked",
        "machine_preparation_complete": True,
        "gate8_met": False,
        "ethics_determination_supplied_not_created": ethics_binding,
        "human_labeling_authorized_by_determination": False,
        "required_operator_inputs": phase8.required_human_operator_inputs(
            human_labeling_authorized=False
        ),
        "prohibited_inferences": list(phase8.PROHIBITED_HUMAN_INFERENCES),
        "human_raters": [],
        "qualification_complete": False,
        "labels_complete": False,
        "adjudication_complete": False,
        "kappa_computed": False,
        "judge_validity_claimed": False,
    }
    phase8.validate_human_only_blocker(
        blocker,
        authorized_input_sha="a" * 64,
        authorized_ethics=ethics_binding,
    )

    for field, fabricated in (("status", "complete"), ("gate8_met", True)):
        changed = copy.deepcopy(blocker)
        changed[field] = fabricated
        with pytest.raises(phase8.Phase8Error, match="makes a human claim"):
            phase8.validate_human_only_blocker(
                changed,
                authorized_input_sha="a" * 64,
                authorized_ethics=ethics_binding,
            )


def _groups(
    *, grids: int = 0, envelopes: int = 0, eligibility: int = 0, errors: int = 0
) -> dict[str, list[dict[str, object]]]:
    counts = {
        "runner_grid_artifacts": grids,
        "runner_request_envelopes": envelopes,
        "runner_eligibility_artifacts": eligibility,
        "runner_error_artifacts": errors,
    }
    return {
        field: [_descriptor(field, index) for index in range(count)]
        for field, count in counts.items()
    }


def _status(
    phase8: ModuleType,
    *,
    terminal: str,
    lifecycle: str,
    grid_statuses: list[str],
    groups: dict[str, list[dict[str, object]]],
) -> str:
    kinds = phase8.lifecycle_artifact_kinds(
        grid_statuses=grid_statuses, artifact_groups=groups
    )
    return phase8.lifecycle_authorization_status(
        terminal_state=terminal,
        lifecycle_state=lifecycle,
        artifact_kinds=kinds,
    )


def _analysis_boundary(
    phase8: ModuleType,
    *,
    purplellama_complete: bool,
) -> tuple[dict[str, object], dict[str, str], list[str], list[dict[str, str]]]:
    lanes = tuple(
        lane
        for lane in phase8.RUNNABLE_LANES
        if lane not in phase8.RR_RUNTIME_TERMINAL_LANE_SET
        and lane not in phase8.OLLAMA_STATIC_TERMINAL_LANES
        and lane != phase8.DEFENSE_LOCAL_LANE
    )
    states = {lane: "failed" for lane in lanes}
    states["local-qwen3-vl-image-primary-100"] = "measured_complete"
    if purplellama_complete:
        states["bridge-purplellama"] = "measured_complete"
    cascade = sorted(
        lane for lane, state in states.items() if state == "measured_complete"
    )
    conditions = (
        [
            {
                "lane_id": "bridge-purplellama",
                "model_spec": "vllm:fixture/model",
                "corpus_arm": "cyberseceval_prompt_injection",
                "attacker": "purplellama",
                "required_metric": "cyberseceval_prompt_injection_judge_question",
            }
        ]
        if purplellama_complete
        else []
    )
    boundary: dict[str, object] = {
        "schema": "ura-phase7-analysis-boundaries/2",
        "status": "validated",
        "evaluator_compatibility_modes": {"rules,guardrail": 2},
        "evaluator_modes_pooled": False,
        "cascade_expected_lanes": cascade,
        "classification": {
            "source_parser_only": True,
            "common_metric_rows": 0,
            "estimate_rows": 0,
        },
        "approximate_common_metrics": {
            "supplementary_non_authoritative": True,
            "expected_from_ineligible_opted_in_strata": bool(conditions),
            "expected_conditions": conditions,
            "estimated_conditions": [],
            "all_abstained_conditions": [
                {
                    "condition": condition,
                    "estimate_rows": 0,
                    "completed_records": 1,
                    "typed_abstentions": 1,
                }
                for condition in conditions
            ],
            "estimate_rows": 0,
            "selected_judges": [],
            "judge_models": [],
            "selected_guardrail": phase8.EXPECTED_GUARDRAIL,
            "queried_rows_bind_selected_guardrail": True,
        },
        "cluster_semantics": {
            "paired_inference_unit": "source_cluster_id (fallback datapoint_id)",
            "equal_cluster_weighting_preserved_by_tool": True,
            "missingness_sensitivity_retained": True,
        },
        "paired_status": {
            "llava_base_vs_rr": {
                corpus: {
                    "status": "unavailable",
                    "analysis_ready_real_run": False,
                    "estimate_available": False,
                    "planned_contrast_missing": True,
                    "reason_code": "left_base_and_right_rr_lanes_failed",
                    "missing_roles": ["left_base", "right_rr"],
                    "prerequisite_roles": {
                        "left_base": {},
                        "right_rr": {},
                    },
                    "modality": "image",
                    "facet": corpus,
                    "paired_compare_invoked": False,
                }
                for corpus in phase8.IMAGE_ARMS
            },
            "qwen_replay_vs_crescendo": {
                corpus: {
                    "analysis_ready_real_run": False,
                    "inference_cluster": "source_cluster_id (fallback datapoint_id)",
                }
                for corpus in phase8.ADAPTIVE_ARMS
            },
        },
        "transfer": {
            "attacker": "replay",
            "unexplained_exclusions": 0,
            "not_applicable_facets": [],
        },
        "native_outcomes": {},
        "runner_outcomes": states,
        "conditional_na_lanes": [phase8.DEFENSE_LOCAL_LANE],
        "defense_local_evidence": {
            "status": "N/A",
            "value": None,
            "disposition": "conditional_na",
            "reason_code": phase8.DEFENSE_LOCAL_CONDITIONAL_REASON_CODE,
            "reason": phase8.DEFENSE_LOCAL_CONDITIONAL_REASON,
            "measured_evidence_admitted": False,
        },
        "lifecycle_registry_states": {
            lane: "complete" if state == "measured_complete" else "failed"
            for lane, state in states.items()
        },
        "runner_lifecycle_authorizations": {lane: {} for lane in states},
        "failed_phase6_lanes_excluded_from_metric_and_level2_views": True,
        "native_scales_pooled": False,
        "suite_missingness": {},
        "human_labels_consumed": False,
        "human_validity_claimed": False,
    }
    return boundary, states, cascade, conditions


def test_phase8_human_row_filter_accepts_current_rr_and_rejects_history(
    phase8: ModuleType,
) -> None:
    current = {
        "run_id": "local-llava-rr-image-primary-100",
        "model_spec": phase8.RR_TARGET_SPEC,
    }
    phase8._reject_historical_rr_terminal_human_row(
        current, label="current RR fixture"
    )

    historical = {"run_id": phase8.HISTORICAL_RR_RUNTIME_TERMINAL_LANES[0]}
    with pytest.raises(phase8.Phase8Error, match="obsolete RR runtime-terminal"):
        phase8._reject_historical_rr_terminal_human_row(
            historical, label="historical RR fixture"
        )


def test_phase8_accepts_measured_current_rr_pair_summary(phase8: ModuleType) -> None:
    boundary, states, _cascade, conditions = _analysis_boundary(
        phase8, purplellama_complete=False
    )
    assert conditions == []
    base_lane = "local-llava-base-image-primary-100"
    rr_lane = "local-llava-rr-image-primary-100"
    states[base_lane] = "measured_complete"
    boundary["runner_outcomes"][base_lane] = "measured_complete"
    boundary["lifecycle_registry_states"][base_lane] = "complete"
    pair_states = {base_lane: "measured_complete", rr_lane: "measured_complete"}
    assert rr_lane not in states
    assert rr_lane not in boundary["runner_outcomes"]
    assert rr_lane not in boundary["runner_lifecycle_authorizations"]
    cascade = sorted(
        lane for lane, state in states.items() if state == "measured_complete"
    )
    boundary["cascade_expected_lanes"] = cascade
    for row in boundary["paired_status"]["llava_base_vs_rr"].values():
        row.update(
            {
                "status": "complete",
                "analysis_ready_real_run": True,
                "estimate_available": True,
                "planned_contrast_missing": False,
                "reason_code": None,
                "missing_roles": [],
                "prerequisite_roles": {},
                "paired_compare_invoked": True,
            }
        )

    phase8.validate_analysis_boundaries(
        boundary,
        expected_runner_states=states,
        expected_llava_pair_states=pair_states,
        expected_cascade_lanes=cascade,
        expected_proxy_conditions=conditions,
    )

    failed_rr = dict(pair_states)
    failed_rr[rr_lane] = "measured_failed"
    with pytest.raises(
        phase8.Phase8Error,
        match="LLaVA pair availability differs from Runner state",
    ):
        phase8.validate_analysis_boundaries(
            boundary,
            expected_runner_states=states,
            expected_llava_pair_states=failed_rr,
            expected_cascade_lanes=cascade,
            expected_proxy_conditions=conditions,
        )


def test_phase8_accepts_completed_but_non_estimable_rr_pair_summary(
    phase8: ModuleType,
) -> None:
    boundary, states, _cascade, conditions = _analysis_boundary(
        phase8, purplellama_complete=False
    )
    base_lane = "local-llava-base-image-primary-100"
    rr_lane = "local-llava-rr-image-primary-100"
    states[base_lane] = "measured_complete"
    boundary["runner_outcomes"][base_lane] = "measured_complete"
    boundary["lifecycle_registry_states"][base_lane] = "complete"
    pair_states = {base_lane: "measured_complete", rr_lane: "measured_complete"}
    cascade = sorted(
        lane for lane, state in states.items() if state == "measured_complete"
    )
    boundary["cascade_expected_lanes"] = cascade
    for row in boundary["paired_status"]["llava_base_vs_rr"].values():
        row.update(
            {
                "reason_code": "paired_compare_validation_failed",
                "missing_roles": [],
                "prerequisite_roles": {
                    "left_base": {},
                    "right_rr": {},
                },
                "paired_compare_invoked": True,
            }
        )

    phase8.validate_analysis_boundaries(
        boundary,
        expected_runner_states=states,
        expected_llava_pair_states=pair_states,
        expected_cascade_lanes=cascade,
        expected_proxy_conditions=conditions,
    )

    fabricated = copy.deepcopy(boundary)
    fabricated["paired_status"]["llava_base_vs_rr"][phase8.IMAGE_ARMS[0]][
        "estimate_available"
    ] = True
    with pytest.raises(phase8.Phase8Error, match="completed non-estimable"):
        phase8.validate_analysis_boundaries(
            fabricated,
            expected_runner_states=states,
            expected_llava_pair_states=pair_states,
            expected_cascade_lanes=cascade,
            expected_proxy_conditions=conditions,
        )


def test_phase8_revalidates_completed_non_estimable_rr_pair_artifact(
    phase8: ModuleType, tmp_path: Path
) -> None:
    corpus = phase8.IMAGE_ARMS[0]
    log = tmp_path / "paired-validation.log"
    log.write_text(
        "paired comparison validation failed: requested corpus lacks one exact arm\n",
        encoding="utf-8",
    )
    prerequisite_roles = {"left_base": {}, "right_rr": {}}
    value = {
        "schema": phase8.RR_NON_ESTIMABLE_CONTRAST_SCHEMA,
        "status": "unavailable",
        "contrast_id": "llava-base-vs-rr",
        "modality": "image",
        "facet": corpus,
        "comparison_type": "cross_target_endpoint_noncausal",
        "planned_estimand": (
            "paired static-image endpoint by datapoint_id x requested_seed"
        ),
        "planned_contrast_missing": True,
        "reason_code": "paired_compare_validation_failed",
        "reason": (
            "The completed base and RR lanes did not satisfy the exact paired "
            "comparison validation contract for this facet."
        ),
        "missing_roles": [],
        "prerequisite_roles": prerequisite_roles,
        "analysis_ready_real_run": False,
        "estimate": None,
        "paired_compare_invoked": True,
        "failed_lane_metric_evidence_admitted": False,
        "human_audit_eligible": False,
        "facets": {
            corpus: {
                "analysis_ready_real_run": False,
                "inference_cluster": "source_cluster_id (fallback datapoint_id)",
                "paired_compare_evidence": {
                    "kind": "validation_failure",
                    "artifact": phase8.descriptor(log),
                },
            }
        },
        "target_calls": 0,
        "judge_calls": 0,
        "provider_http_attempts": 0,
        "human_labels_consumed": False,
    }
    artifact = tmp_path / "strict-non-estimable.json"
    artifact.write_text(json.dumps(value) + "\n", encoding="utf-8")
    phase8.validate_llava_pair_artifact(
        artifact,
        corpus=corpus,
        paired_invoked=True,
        prerequisite_roles=prerequisite_roles,
        left_model="vllm:fixture/llava-base",
        right_model="vllm:fixture/llava-rr",
    )

    fabricated = copy.deepcopy(value)
    fabricated["estimate"] = 0.0
    fabricated_path = tmp_path / "fabricated-estimate.json"
    fabricated_path.write_text(json.dumps(fabricated) + "\n", encoding="utf-8")
    with pytest.raises(phase8.Phase8Error, match="not failure-bound"):
        phase8.validate_llava_pair_artifact(
            fabricated_path,
            corpus=corpus,
            paired_invoked=True,
            prerequisite_roles=prerequisite_roles,
            left_model="vllm:fixture/llava-base",
            right_model="vllm:fixture/llava-rr",
        )


def test_phase8_excludes_conditional_defense_from_success_view(
    phase8: ModuleType,
) -> None:
    boundary, states, _cascade, conditions = _analysis_boundary(
        phase8, purplellama_complete=False
    )
    cascade = sorted(
        lane for lane, state in states.items() if state == "measured_complete"
    )
    boundary["cascade_expected_lanes"] = cascade

    phase8.validate_analysis_boundaries(
        boundary,
        expected_runner_states=states,
        expected_cascade_lanes=cascade,
        expected_proxy_conditions=conditions,
    )
    assert phase8.DEFENSE_LOCAL_LANE not in states
    assert phase8.DEFENSE_LOCAL_LANE not in cascade

    fabricated = copy.deepcopy(boundary)
    fabricated["defense_local_evidence"]["measured_evidence_admitted"] = True
    with pytest.raises(phase8.Phase8Error, match="defense evidence/N/A boundary"):
        phase8.validate_analysis_boundaries(
            fabricated,
            expected_runner_states=states,
            expected_cascade_lanes=cascade,
            expected_proxy_conditions=conditions,
        )


def test_phase8_reconstructs_lifecycle_from_exact_artifact_kinds(
    phase8: ModuleType,
) -> None:
    assert _status(
        phase8,
        terminal="measured_complete",
        lifecycle="complete",
        grid_statuses=["complete"],
        groups=_groups(grids=1, envelopes=1, eligibility=1),
    ) == "complete_runner_grid"
    assert _status(
        phase8,
        terminal="failed",
        lifecycle="partial",
        grid_statuses=["partial"],
        groups=_groups(grids=1, envelopes=1, eligibility=1, errors=1),
    ) == "partial_runner_grid"
    assert _status(
        phase8,
        terminal="failed",
        lifecycle="failed",
        grid_statuses=[],
        groups=_groups(envelopes=1, errors=1),
    ) == "failed_after_runner_request"
    assert _status(
        phase8,
        terminal="failed",
        lifecycle="failed",
        grid_statuses=["running"],
        groups=_groups(grids=1, errors=1),
    ) == "failed_after_runner_request"


def test_phase8_does_not_promote_non_request_files_by_generic_count(
    phase8: ModuleType,
) -> None:
    for groups in (_groups(errors=1), _groups(eligibility=1)):
        assert sum(len(rows) for rows in groups.values()) == 1
        assert _status(
            phase8,
            terminal="failed",
            lifecycle="failed",
            grid_statuses=[],
            groups=groups,
        ) == "pre_runner_failure_no_request_artifact"

    with pytest.raises(phase8.Phase8Error, match="status/artifact inventory differs"):
        phase8.lifecycle_artifact_kinds(
            grid_statuses=[], artifact_groups=_groups(grids=1)
        )
    with pytest.raises(phase8.Phase8Error, match="exact artifact kinds"):
        _status(
            phase8,
            terminal="failed",
            lifecycle="partial",
            grid_statuses=["partial"],
            groups=_groups(grids=1, eligibility=1, errors=1),
        )

    source = Path(phase8.__file__).read_text(encoding="utf-8")
    assert "runner_artifact_count" not in source


def test_phase8_accepts_failed_proxy_bridge_without_inventing_approximation(
    phase8: ModuleType,
) -> None:
    boundary, states, cascade, conditions = _analysis_boundary(
        phase8, purplellama_complete=False
    )
    assert conditions == []
    phase8.validate_analysis_boundaries(
        boundary,
        expected_runner_states=states,
        expected_cascade_lanes=cascade,
        expected_proxy_conditions=conditions,
    )

    invented = copy.deepcopy(boundary)
    approximate = invented["approximate_common_metrics"]
    approximate["estimate_rows"] = 1
    approximate["selected_judges"] = ["rules"]
    with pytest.raises(phase8.Phase8Error, match="proxy realization"):
        phase8.validate_analysis_boundaries(
            invented,
            expected_runner_states=states,
            expected_cascade_lanes=cascade,
            expected_proxy_conditions=conditions,
        )


def test_phase8_accepts_expected_proxy_with_zero_all_abstained_estimates(
    phase8: ModuleType,
) -> None:
    boundary, states, cascade, conditions = _analysis_boundary(
        phase8, purplellama_complete=True
    )
    assert len(conditions) == 1
    phase8.validate_analysis_boundaries(
        boundary,
        expected_runner_states=states,
        expected_cascade_lanes=cascade,
        expected_proxy_conditions=conditions,
    )

    detached = copy.deepcopy(boundary)
    detached["approximate_common_metrics"][
        "expected_from_ineligible_opted_in_strata"
    ] = False
    with pytest.raises(phase8.Phase8Error, match="proxy realization"):
        phase8.validate_analysis_boundaries(
            detached,
            expected_runner_states=states,
            expected_cascade_lanes=cascade,
            expected_proxy_conditions=conditions,
        )


def test_phase8_rejects_structural_mixed_proxy_partition_defects(
    phase8: ModuleType,
) -> None:
    boundary, _states, _cascade, conditions = _analysis_boundary(
        phase8, purplellama_complete=True
    )
    all_abstained_condition = conditions[0]
    estimated_condition = {
        **all_abstained_condition,
        "corpus_arm": "fixture_second_benign_proxy",
        "required_metric": "fixture_second_benign_judge_question",
    }
    conditions = sorted(
        [all_abstained_condition, estimated_condition],
        key=lambda row: (
            row["model_spec"],
            row["corpus_arm"],
            row["attacker"],
            row["required_metric"],
        ),
    )
    approximate = boundary["approximate_common_metrics"]
    estimated_realization = {
        "condition": estimated_condition,
        "estimate_rows": 1,
        "completed_records": 1,
        "typed_abstentions": 0,
    }
    all_abstained_realization = {
        "condition": all_abstained_condition,
        "estimate_rows": 0,
        "completed_records": 1,
        "typed_abstentions": 1,
    }
    approximate.update(
        {
            "expected_conditions": conditions,
            "estimated_conditions": [estimated_realization],
            "all_abstained_conditions": [all_abstained_realization],
            "estimate_rows": 1,
            "selected_judges": ["guardrail"],
            "judge_models": [phase8.EXPECTED_GUARDRAIL["model"]],
        }
    )
    phase8.validate_analysis_boundaries(
        boundary,
        expected_proxy_conditions=conditions,
    )
    reordered = copy.deepcopy(boundary)
    reordered["approximate_common_metrics"]["expected_conditions"].reverse()
    with pytest.raises(phase8.Phase8Error, match="not canonical"):
        phase8.validate_analysis_boundaries(
            reordered,
            expected_proxy_conditions=conditions,
        )

    swapped = copy.deepcopy(boundary)
    swapped["approximate_common_metrics"].update(
        {
            "estimated_conditions": [all_abstained_realization],
            "all_abstained_conditions": [estimated_realization],
        }
    )
    with pytest.raises(phase8.Phase8Error, match="realization disposition"):
        phase8.validate_analysis_boundaries(
            swapped,
            expected_proxy_conditions=conditions,
        )

    mutations = {
        "missing": lambda value: value["approximate_common_metrics"][
            "all_abstained_conditions"
        ].clear(),
        "duplicate": lambda value: value["approximate_common_metrics"][
            "all_abstained_conditions"
        ].append(copy.deepcopy(all_abstained_realization)),
        "overlapping": lambda value: value["approximate_common_metrics"][
            "all_abstained_conditions"
        ].append(
            {
                **all_abstained_realization,
                "condition": estimated_condition,
            }
        ),
        "detached": lambda value: value["approximate_common_metrics"][
            "estimated_conditions"
        ].__setitem__(
            0,
            {
                **estimated_realization,
                "condition": {**estimated_condition, "lane_id": "detached-lane"},
            },
        ),
    }
    for mutate in mutations.values():
        changed = copy.deepcopy(boundary)
        mutate(changed)
        with pytest.raises(
            phase8.Phase8Error,
            match="proxy[- ]condition|proxy realization",
        ):
            phase8.validate_analysis_boundaries(
                changed,
                expected_proxy_conditions=conditions,
            )


def test_phase8_capacity_reserves_exact_twenty_disjoint_clusters(
    phase8: ModuleType,
) -> None:
    assert phase8.INPUT_SCHEMA == "ura-phase8-human-audit-inputs/5"
    exact = phase8.plan_phase8_capacity(
        common_available_unique_clusters=21,
        source_task_available_unique_clusters=1,
        common_requested_unique_clusters=1,
        source_task_requested_unique_clusters=1,
    )
    assert exact == {
        "schema": "ura-phase8-human-audit-capacity/1",
        "status": "cardinality_sufficient_for_requests_and_qualification_reserve",
        "common_available_unique_clusters": 21,
        "common_requested_unique_clusters": 1,
        "common_remaining_disjoint_unique_clusters": 20,
        "source_task_available_unique_clusters": 1,
        "source_task_requested_unique_clusters": 1,
        "qualification_required_unique_clusters": 20,
    }

    with pytest.raises(
        phase8.Phase8Error,
        match=r"leaves 19 disjoint qualification clusters; exactly 20 are required",
    ):
        phase8.plan_phase8_capacity(
            common_available_unique_clusters=20,
            source_task_available_unique_clusters=1,
            common_requested_unique_clusters=1,
            source_task_requested_unique_clusters=1,
        )


def test_phase8_capacity_requires_the_exact_source_task_sample(
    phase8: ModuleType,
) -> None:
    with pytest.raises(
        phase8.Phase8Error,
        match=r"source-task frame cannot supply the exact requested sample",
    ):
        phase8.plan_phase8_capacity(
            common_available_unique_clusters=21,
            source_task_available_unique_clusters=1,
            common_requested_unique_clusters=1,
            source_task_requested_unique_clusters=2,
        )
    with pytest.raises(phase8.Phase8Error, match="exact integer"):
        phase8.plan_phase8_capacity(
            common_available_unique_clusters=True,
            source_task_available_unique_clusters=1,
            common_requested_unique_clusters=1,
            source_task_requested_unique_clusters=1,
        )


def test_phase8_revalidates_capacity_against_phase7_success_view(
    phase8: ModuleType,
) -> None:
    source = Path(phase8.__file__).read_text(encoding="utf-8")
    builder = source[
        source.index("def build_input_manifest(") : source.index(
            "def prepare_input_manifest("
        )
    ]
    semantic = source[
        source.index("def semantic_revalidate(") : source.index(
            "def sanitized_environment("
        )
    ]
    execution = source[
        source.index("def execute_preparation(") : source.index(
            "def execute_entry("
        )
    ]
    assert 'audit_runner_root = phase7_support["runner_view"]' in builder
    assert "observed_audit_frame_cluster_counts(" in builder
    assert "revalidate_bound_audit_runner_view(" in builder
    assert '"capacity": capacity' in builder
    assert 'audit_runner_root = support["runner_view"]' in semantic
    assert "observed_audit_frame_cluster_counts(" in semantic
    assert "revalidate_bound_audit_runner_view(" in semantic
    assert "authorized Phase 8 capacity differs" in semantic
    assert 'runner_root = support["audit_runner_root"]' in execution
    assert execution.count("\n    revalidate_execution_view()\n") == 5


def test_phase8_rejects_count_preserving_independent_view_substitution(
    phase8: ModuleType,
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "runner"
    lane_root = source_root / "lane-a"
    lane_root.mkdir(parents=True)
    source = lane_root / "cell.jsonl"
    source.write_bytes(b'{"bound":true}\n')
    view_root = tmp_path / "read-only-runner-view"
    target = view_root / "lane-a" / "cell.jsonl"
    target.parent.mkdir(parents=True)
    target.write_bytes(source.read_bytes())
    os.chmod(target, 0o400)
    source_stat = source.stat()
    target_stat = target.stat()
    inventory = [
        {
            "relative_path": "lane-a/cell.jsonl",
            "source": phase8.descriptor(source),
            "view": phase8.descriptor(target),
            "source_file_identity": {
                "device": source_stat.st_dev,
                "inode": source_stat.st_ino,
            },
            "view_file_identity": {
                "device": target_stat.st_dev,
                "inode": target_stat.st_ino,
            },
            "independent_copy": True,
            "source_view_samefile": False,
            "view_mode": target_stat.st_mode & 0o777,
            "view_link_count": target_stat.st_nlink,
        }
    ]
    receipt = {
        "schema": "ura-phase7-runner-input-view/4",
        "status": "complete",
        "source_runner_root": str(source_root.resolve()),
        "view_root": str(view_root.resolve()),
        "included_measured_lanes": ["lane-a"],
        "regular_files_copied": 1,
        "logical_bytes": source.stat().st_size,
        "source_files_modified": False,
        "permitted_view_outputs": [],
        "file_inventory": inventory,
        "file_inventory_sha256": phase8.sha256_bytes(phase8.canonical(inventory)),
    }
    assert (
        phase8.validate_phase7_runner_view(
            receipt,
            expected_source_root=source_root,
            expected_view_root=view_root,
            expected_measured_lanes=["lane-a"],
        )
        == view_root.resolve()
    )
    assert not source.samefile(target)

    payload = target.read_bytes()
    os.chmod(target, 0o600)
    target.unlink()
    substitution = view_root / "transfer_matrix-shadow.jsonl"
    substitution.write_bytes(payload)
    assert len([path for path in view_root.rglob("*") if path.is_file()]) == 1
    assert substitution.stat().st_size == receipt["logical_bytes"]
    with pytest.raises(phase8.Phase8Error):
        phase8.validate_phase7_runner_view(
            receipt,
            expected_source_root=source_root,
            expected_view_root=view_root,
            expected_measured_lanes=["lane-a"],
        )

    rendered_source = Path(phase8.__file__).read_text(encoding="utf-8")
    completion_validator = rendered_source[
        rendered_source.index("def validate_phase7_completion(") :
        rendered_source.index("def required_env(")
    ]
    assert "runner_view_root = validate_phase7_runner_view(" in completion_validator


def test_phase8_frozen_phase7_api_requires_recovery_and_campaign_union(
    phase8: ModuleType, tmp_path: Path
) -> None:
    oracle = phase8.load_frozen_phase7_oracle(tmp_path)
    phase8.validate_frozen_phase7_oracle_api(oracle)
    names = (
        "gate5_inventory_profile",
        "validate_gate5",
        "validate_project_and_source",
        "validate_core_controller",
        "validate_extended_controller",
        "validate_native_controller",
        "validate_runner_inventory",
        "validate_followon_inventory",
        "validate_seven_output_policy_inventory",
        "validate_phase6_recovery_completions",
        "validate_phase6_campaign_terminal_inventory",
        "build_phase6_campaign_terminal_inventory",
    )
    changed = SimpleNamespace(**{name: getattr(oracle, name) for name in names})
    changed.validate_phase6_recovery_completions = lambda paths: None
    with pytest.raises(phase8.Phase8Error, match="API signature differs"):
        phase8.validate_frozen_phase7_oracle_api(changed)

    changed = SimpleNamespace(**{name: getattr(oracle, name) for name in names})

    def stale_campaign_builder(
        *, gate5_rows, gate5_manifest, project_and_source, runner, native, seven,
        followon
    ):
        return {}

    changed.build_phase6_campaign_terminal_inventory = stale_campaign_builder
    with pytest.raises(phase8.Phase8Error, match="API signature differs"):
        phase8.validate_frozen_phase7_oracle_api(changed)


def test_phase8_frozen_replay_uses_current_identity_for_native_only(
    phase8: ModuleType, tmp_path: Path
) -> None:
    def artifact(name: str, value: object) -> dict[str, object]:
        path = tmp_path / name
        path.write_text(json.dumps(value) + "\n", encoding="ascii")
        return phase8.descriptor(path)

    historical = {
        "expected_commit": "1" * 40,
        "framework_lock_id": "a" * 64,
    }
    current = {
        "expected_commit": "2" * 40,
        "framework_lock_id": "b" * 64,
    }
    manifest_value = {"lanes": []}
    gate5 = {
        "manifest": artifact("gate5.json", manifest_value),
        "canonical_runnote": artifact("runnote.json", {}),
        "promotion_receipt": artifact("promotion.json", {}),
        "code_identity": historical,
    }
    core = {"completion": artifact("core.json", {})}
    extended = {"completion": artifact("extended.json", {})}
    native = {"completion": artifact("native.json", {})}
    runner = {"fixture": "runner"}
    project_and_source = {"fixture": "project"}
    recovery_completion = artifact("recovery.json", {})
    followon = {
        "amendment": artifact("followon-amendment.json", {}),
        "completion": artifact("followon-completion.json", {}),
    }
    seven = {
        "amendment": artifact("seven-amendment.json", {}),
        "completion": artifact("seven-completion.json", {}),
    }
    current_ollama = {
        "gate5": artifact("current-ollama-gate5.json", {}),
        "completion": artifact("current-ollama-completion.json", {}),
    }
    current_ollama_stability = {
        "completion": artifact("current-ollama-stability.json", {})
    }
    current_ollama_alignment = {
        "completion": artifact("current-ollama-alignment.json", {})
    }
    vllm_stability = {
        "input_recovery_completion": artifact("vllm-stability.json", {})
    }
    recoveries = {"completion_order": [recovery_completion]}
    campaign = {"fixture": "campaign"}
    inputs = {
        "code_identity": current,
        "canonical_recoveries": recoveries,
        "followon": followon,
        "seven_output_policy_amendment": seven,
        "current_ollama": current_ollama,
        "current_ollama_stability": current_ollama_stability,
        "current_ollama_population_alignment": current_ollama_alignment,
        "vllm_stability": vllm_stability,
        "campaign_terminal_inventory": campaign,
    }
    observed: dict[str, object] = {}
    observed_provenance: dict[str, dict[str, object]] = {}
    expected_provenance = {
        "gate5_manifest": (tmp_path / "gate5.json").resolve(),
        "gate5_runnote": (tmp_path / "runnote.json").resolve(),
        "gate5_promotion": (tmp_path / "promotion.json").resolve(),
        "project_and_source": project_and_source,
    }

    def validate_gate5(*_args, **_kwargs):
        return manifest_value, {}, {}, historical

    def validate_core_controller(**kwargs):
        observed["core"] = kwargs["code_identity"]
        return core

    def validate_extended_controller(**kwargs):
        observed["extended"] = kwargs["code_identity"]
        return extended

    def validate_native_controller(**kwargs):
        observed["native"] = kwargs["code_identity"]
        if kwargs["code_identity"] != current:
            raise AssertionError("native replay used the historical Gate5 identity")
        return native

    def validate_runner_inventory(**kwargs):
        observed["runner"] = kwargs["code_identity"]
        return runner

    def validate_followon_inventory(**kwargs):
        observed["followon"] = tuple(sorted(kwargs))
        return followon

    def validate_recoveries(_paths, **kwargs):
        observed_provenance["recoveries"] = dict(kwargs)
        if kwargs != expected_provenance:
            raise ValueError("recovery canonical provenance mismatch")
        return recoveries

    def validate_seven(**kwargs):
        provenance = {key: kwargs[key] for key in expected_provenance}
        observed_provenance["seven"] = provenance
        if provenance != expected_provenance:
            raise ValueError("seven-row canonical provenance mismatch")
        return seven

    oracle = SimpleNamespace(
        validate_gate5=validate_gate5,
        gate5_inventory_profile=lambda *_args, **_kwargs: {},
        validate_project_and_source=lambda **_kwargs: project_and_source,
        validate_core_controller=validate_core_controller,
        validate_extended_controller=validate_extended_controller,
        validate_native_controller=validate_native_controller,
        validate_runner_inventory=validate_runner_inventory,
        validate_phase6_recovery_completions=validate_recoveries,
        validate_followon_inventory=validate_followon_inventory,
        validate_seven_output_policy_inventory=validate_seven,
        validate_current_ollama_completion=(
            lambda **_kwargs: current_ollama
        ),
        validate_current_ollama_stability_completion=(
            lambda *_args, **_kwargs: current_ollama_stability
        ),
        validate_current_ollama_alignment_completion=(
            lambda *_args, **_kwargs: current_ollama_alignment
        ),
        validate_vllm_stability_completion=(
            lambda *_args, **_kwargs: vllm_stability
        ),
        build_phase6_campaign_terminal_inventory=lambda **_kwargs: campaign,
    )
    phase8.replay_frozen_phase7_oracle(
        oracle,
        gate5=gate5,
        inputs=inputs,
        project_and_source=project_and_source,
        core=core,
        extended=extended,
        native=native,
        runner=runner,
        project_root=tmp_path,
        work_root=tmp_path,
        runner_root=tmp_path,
    )
    assert observed == {
        "core": historical,
        "extended": historical,
        "native": current,
        "runner": historical,
        "followon": ("amendment_path", "completion_path", "gate5_promotion"),
    }
    assert observed_provenance == {
        "recoveries": expected_provenance,
        "seven": expected_provenance,
    }

    forged_gate5 = copy.deepcopy(gate5)
    forged_gate5["canonical_runnote"] = artifact("forged-runnote.json", {})
    with pytest.raises(
        phase8.Phase8Error, match="frozen Phase 7 semantic replay failed"
    ):
        phase8.replay_frozen_phase7_oracle(
            oracle,
            gate5=forged_gate5,
            inputs=inputs,
            project_and_source=project_and_source,
            core=core,
            extended=extended,
            native=native,
            runner=runner,
            project_root=tmp_path,
            work_root=tmp_path,
            runner_root=tmp_path,
        )

    with pytest.raises(
        phase8.Phase8Error, match="frozen semantic replay differs"
    ):
        phase8.replay_frozen_phase7_oracle(
            oracle,
            gate5=gate5,
            inputs=inputs,
            project_and_source={"fixture": "forged-project"},
            core=core,
            extended=extended,
            native=native,
            runner=runner,
            project_root=tmp_path,
            work_root=tmp_path,
            runner_root=tmp_path,
        )


def test_phase8_native_snapshot_binds_its_retained_project_receipt(
    phase8: ModuleType,
) -> None:
    source = Path(phase8.__file__).read_text(encoding="utf-8")
    block = source[
        source.index("    native = phase6.get(\"native\")") :
        source.index("    native_outcomes = inputs.get(\"native_outcomes\")")
    ]

    def assert_retained_contract(candidate: str) -> None:
        assert '"project_revision",' in candidate
        assert 'native["project_revision"], label="Phase 7 native project-revision receipt"' in candidate
        assert 'native_plan_code.get("project_revision") != native["project_revision"]' in candidate
        assert 'native_commit = authoritative_native.get("expected_commit")' in candidate
        assert 'expected_commit=str(native_commit)' in candidate
        assert 'native_plan_code.get("expected_commit")\n        != native_commit' in candidate
        assert 'native_repository.get("observed_commit")' in candidate
        assert '!= inputs["code_identity"]["expected_commit"]' not in candidate
        assert "EXPECTED_PROJECT_REVISION_SHA256" not in candidate

    assert_retained_contract(block)
    for old in (
        '        "project_revision",\n',
        '    native_commit = authoritative_native.get("expected_commit")\n',
        '        or native_repository.get("observed_commit")\n'
        '        != native_commit\n',
    ):
        changed = block.replace(old, "", 1)
        assert changed != block
        with pytest.raises(AssertionError):
            assert_retained_contract(changed)


def test_phase8_mixed_revision_validators_separate_historical_and_current(
    phase8: ModuleType,
) -> None:
    source = Path(phase8.__file__).read_text(encoding="utf-8")

    def block(start: str, end: str) -> str:
        return source[source.index(start) : source.index(end, source.index(start))]

    gate5 = block("def validate_gate5(", "def validate_ethics(")
    core = block("def validate_core_completion(", "def validate_extended_completion(")
    extended = block("def validate_extended_completion(", "def validate_native_completion(")
    native = block("def validate_native_completion(", "def validate_analysis_boundaries(")
    rr = block(
        "def _validate_rr_runtime_terminal_rows(", "def exact_json_contract("
    )
    conditional = block(
        "def _validate_conditional_defense_row(", "def _exact_inventory("
    )

    def assert_mixed_revision_contract() -> None:
        assert "EXPECTED_COMMIT" not in gate5
        assert "EXPECTED_FRAMEWORK_LOCK" not in gate5
        assert 'plan.get("code_identity") != code_identity' in gate5
        for historical in (core, extended):
            assert "EXPECTED_COMMIT" not in historical
            assert "EXPECTED_FRAMEWORK_LOCK" not in historical
            assert 'historical_identity["expected_commit"]' in historical
            assert 'historical_identity["framework_lock_id"]' in historical
        assert "EXPECTED_COMMIT" not in rr
        assert 'project_repository.get("expected_commit")' in rr
        assert 'artifact_code_identity["expected_commit"]' in rr
        assert "EXPECTED_PROJECT_REVISION_SHA256" not in conditional
        assert "EXPECTED_SOURCE_CONFORMANCE_SHA256" not in conditional
        assert 'project_repository.get("observed_commit")' in conditional
        assert 'set(plan_code)\n        != {' in native
        assert '"project_revision",' in native
        assert "EXPECTED_PROJECT_REVISION_SHA256" not in native
        assert 'native_commit = value.get("expected_commit")' in native
        assert 'expected_commit=str(native_commit)' in native
        assert "RETAINED_NATIVE_OLLAMA_MODELS_BY_COMMIT.get" in native
        assert "recheck_checkout=False" in native
        assert 'native_repository.get("expected_commit") != native_commit' in native
        assert (
            "per-engine literal-loopback proxy under one production exclusive "
            "inference lease with protected pre/post exact-roster checks"
        ) in native
        assert 'contract_test.get("mutations_rejected") != 13' in native
        for case in (
            '"rr-current-runnable"',
            '"defense-na-v2-cross-mix"',
            '"defense-na-shape"',
        ):
            assert case in native

    assert_mixed_revision_contract()

    reverted_gate5 = gate5.replace(
        'plan.get("code_identity") != code_identity',
        'plan.get("code_identity") != {"expected_commit": EXPECTED_COMMIT}',
        1,
    )
    assert reverted_gate5 != gate5
    with pytest.raises(AssertionError):
        assert "EXPECTED_COMMIT" not in reverted_gate5

    reverted_core = core.replace(
        'historical_identity["expected_commit"]', "EXPECTED_COMMIT", 1
    )
    assert reverted_core != core
    with pytest.raises(AssertionError):
        assert "EXPECTED_COMMIT" not in reverted_core

    reverted_native = native.replace('            "project_revision",\n', "", 1)
    assert reverted_native != native
    with pytest.raises(AssertionError):
        assert '"project_revision",' in reverted_native


def test_phase8_full_current_sampling_view_is_revision_and_source_stratified(
    phase8: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner_root = tmp_path / "runner"
    runner_root.mkdir()
    canonical = [
        lane
        for lane in phase8.RUNNABLE_LANES
        if lane not in phase8.RR_RUNTIME_TERMINAL_LANE_SET
        and lane not in phase8.OLLAMA_STATIC_TERMINAL_LANES
        and lane != phase8.DEFENSE_LOCAL_LANE
    ]
    assert len(canonical) == phase8.HISTORICAL_GATE5_RUNNABLE == 18
    original_lane, recovered_lane = canonical[:2]
    runner_states = {lane: "failed" for lane in canonical}
    runner_states[original_lane] = "measured_complete"

    revisions = {"canonical": "a" * 64, "recovery": "b" * 64,
                 "seven": "c" * 64, "followon": "d" * 64}
    sources = {"canonical": "1" * 64, "recovery": "2" * 64,
               "seven": "3" * 64, "followon": "4" * 64}
    actual_strata: dict[str, tuple[str, str]] = {}

    def lane_root(group: str, lane: str) -> str:
        root = runner_root / group / lane
        root.mkdir(parents=True)
        (root / "result.jsonl").write_bytes(
            json.dumps({"lane": lane, "group": group}).encode("ascii") + b"\n"
        )
        return str(root.resolve())

    original_root = lane_root("canonical", original_lane)
    recovered_root = lane_root("recovery", recovered_lane)
    actual_strata[original_lane] = (revisions["canonical"], sources["canonical"])
    actual_strata[recovered_lane] = (revisions["recovery"], sources["recovery"])

    seven_states = {
        lane: ("measured_complete" if index < 2 else (
            "gate5_failed" if index == 2 else "measured_failed"
        ))
        for index, lane in enumerate(phase8.SEVEN_AMENDMENT_LANES)
    }
    seven_metric = [
        lane for lane in phase8.SEVEN_AMENDMENT_LANES
        if seven_states[lane] == "measured_complete"
    ]
    seven_roots = {lane: lane_root("seven", lane) for lane in seven_metric}
    for lane in seven_metric:
        actual_strata[lane] = (revisions["seven"], sources["seven"])

    followon_states = {
        phase8.FOLLOWON_LANES[0]: "measured_complete",
        phase8.FOLLOWON_LANES[1]: "partial",
        phase8.FOLLOWON_LANES[2]: "failed",
    }
    followon_metric = [phase8.FOLLOWON_LANES[0]]
    followon_roots = {
        lane: lane_root("followon", lane) for lane in followon_metric
    }
    actual_strata[followon_metric[0]] = (
        revisions["followon"], sources["followon"]
    )
    excluded = runner_root / "excluded"
    excluded.mkdir()
    (excluded / "failed-and-partial-must-not-be-copied.jsonl").write_bytes(b"x\n")

    calls: list[tuple[str, str | None, str | None]] = []

    def fake_binding(
        *, lane: str, root: Path, evidence: object,
        expected_revision: str | None, expected_source: str | None
    ) -> tuple[str, str]:
        del root, evidence
        actual_revision, actual_source = actual_strata[lane]
        calls.append((lane, expected_revision, expected_source))
        if expected_revision is not None and expected_revision != actual_revision:
            raise phase8.Phase8Error(f"{lane}: project-revision stratum changed")
        if expected_source is not None and expected_source != actual_source:
            raise phase8.Phase8Error(f"{lane}: source-conformance stratum changed")
        return actual_revision, actual_source

    monkeypatch.setattr(phase8, "_sampling_lane_binding", fake_binding)
    runner = {
        "lifecycle_lane_order": canonical,
        "terminal_states": runner_states,
        "lifecycle_lane_roots": {original_lane: original_root},
        "lifecycle_authorizations": {lane: {"lane": lane} for lane in canonical},
    }
    recoveries = {
        "latest": {
            recovered_lane: {
                "state": "measured_complete",
                "result_root": recovered_root,
                "evidence": {"recovery": recovered_lane},
                "project_revision_stratum": revisions["recovery"],
                "source_conformance_stratum": sources["recovery"],
            }
        }
    }
    seven = {
        "terminal_states": seven_states,
        "metric_lane_order": seven_metric,
        "metric_roots": seven_roots,
        "metric_evidence": {lane: {"lane": lane} for lane in seven_metric},
        "project_revision_receipt_sha256": revisions["seven"],
        "source_conformance_sha256": sources["seven"],
    }
    followon = {
        "terminal_states": followon_states,
        "metric_lane_order": followon_metric,
        "metric_roots": followon_roots,
        "metric_evidence": {lane: {"lane": lane} for lane in followon_metric},
        "project_revision_receipt_sha256": revisions["followon"],
        "source_conformance_sha256": sources["followon"],
    }
    contract = phase8.phase7_sampling_lane_contract(
        runner_root=runner_root,
        runner=runner,
        recoveries=recoveries,
        seven=seven,
        followon=followon,
    )
    assert contract["lane_order"] == [
        original_lane, recovered_lane, *seven_metric, *followon_metric
    ]
    assert set(contract["lane_order"]).isdisjoint(
        {phase8.SEVEN_AMENDMENT_LANES[2], *phase8.FOLLOWON_LANES[1:]}
    )
    assert contract["revision_strata"] == {
        revisions["canonical"]: [original_lane],
        revisions["recovery"]: [recovered_lane],
        revisions["seven"]: seven_metric,
        revisions["followon"]: followon_metric,
    }
    assert contract["source_conformance_strata"] == {
        sources["canonical"]: [original_lane],
        sources["recovery"]: [recovered_lane],
        sources["seven"]: seven_metric,
        sources["followon"]: followon_metric,
    }
    assert calls[0] == (original_lane, None, None)
    assert calls[1] == (
        recovered_lane, revisions["recovery"], sources["recovery"]
    )

    view_root = tmp_path / "human-view"
    view_root.mkdir()
    inventory: list[dict[str, object]] = []
    logical_bytes = 0
    for lane in contract["lane_order"]:
        root = Path(contract["lane_roots"][lane])
        source = root / "result.jsonl"
        relative = source.relative_to(runner_root).as_posix()
        target = view_root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        os.chmod(target, 0o400)
        source_stat = source.stat()
        target_stat = target.stat()
        inventory.append({
            "relative_path": relative,
            "source": phase8.descriptor(source),
            "view": phase8.descriptor(target),
            "source_file_identity": {
                "device": source_stat.st_dev, "inode": source_stat.st_ino,
            },
            "view_file_identity": {
                "device": target_stat.st_dev, "inode": target_stat.st_ino,
            },
            "independent_copy": True,
            "source_view_samefile": False,
            "view_mode": target_stat.st_mode & 0o777,
            "view_link_count": target_stat.st_nlink,
        })
        logical_bytes += source_stat.st_size
    inventory.sort(key=lambda row: str(row["relative_path"]))
    core_view_receipt = {"schema": "fixture-core-view"}
    receipt = {
        "schema": "ura-phase7-human-audit-sampling-view/2",
        "status": "complete",
        "core_view_receipt": core_view_receipt,
        "source_runner_root": str(runner_root.resolve()),
        "view_root": str(view_root.resolve()),
        "included_core_lanes": contract["canonical_lanes"],
        "included_amendment_lanes": contract["seven_lanes"],
        "amendment_result_roots": contract["seven_roots"],
        "included_followon_lanes": contract["followon_lanes"],
        "followon_result_roots": contract["followon_roots"],
        "regular_files_copied": len(inventory),
        "logical_bytes": logical_bytes,
        "source_files_modified": False,
        "permitted_view_outputs": [],
        "file_inventory": inventory,
        "file_inventory_sha256": phase8.sha256_bytes(phase8.canonical(inventory)),
    }
    observed_root, observed_contract = phase8.validate_phase7_human_sampling_view(
        receipt,
        core_view_receipt=core_view_receipt,
        runner_root=runner_root,
        expected_view_root=view_root,
        runner=runner,
        recoveries=recoveries,
        seven=seven,
        followon=followon,
    )
    assert observed_root == view_root.resolve()
    assert observed_contract == contract
    assert not any("failed-and-partial" in row["relative_path"] for row in inventory)

    stale_schema = copy.deepcopy(receipt)
    stale_schema["schema"] = "ura-phase7-human-audit-sampling-view/1"
    with pytest.raises(phase8.Phase8Error, match="sampling view contract"):
        phase8.validate_phase7_human_sampling_view(
            stale_schema,
            core_view_receipt=core_view_receipt,
            runner_root=runner_root,
            expected_view_root=view_root,
            runner=runner,
            recoveries=recoveries,
            seven=seven,
            followon=followon,
        )

    stale_seven = copy.deepcopy(seven)
    stale_seven["terminal_states"][seven_metric[0]] = "measured_failed"
    with pytest.raises(phase8.Phase8Error, match="sampling partition changed"):
        phase8.phase7_sampling_lane_contract(
            runner_root=runner_root, runner=runner, recoveries=recoveries,
            seven=stale_seven, followon=followon,
        )
    wrong_revision = copy.deepcopy(seven)
    wrong_revision["project_revision_receipt_sha256"] = "e" * 64
    with pytest.raises(phase8.Phase8Error, match="project-revision stratum changed"):
        phase8.phase7_sampling_lane_contract(
            runner_root=runner_root, runner=runner, recoveries=recoveries,
            seven=wrong_revision, followon=followon,
        )
    wrong_source = copy.deepcopy(followon)
    wrong_source["source_conformance_sha256"] = "5" * 64
    with pytest.raises(phase8.Phase8Error, match="source-conformance stratum changed"):
        phase8.phase7_sampling_lane_contract(
            runner_root=runner_root, runner=runner, recoveries=recoveries,
            seven=seven, followon=wrong_source,
        )
    failed_recovery = copy.deepcopy(recoveries)
    failed_recovery["latest"][recovered_lane]["state"] = "failed"
    without_recovery = phase8.phase7_sampling_lane_contract(
        runner_root=runner_root, runner=runner, recoveries=failed_recovery,
        seven=seven, followon=followon,
    )
    assert recovered_lane not in without_recovery["lane_order"]
