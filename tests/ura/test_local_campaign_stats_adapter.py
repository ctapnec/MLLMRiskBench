"""Local campaign analysis adapter and generic Stats registration."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from experiments.rig_web import (
    RigWebApp,
    _LEVEL2_ROW_FIELDS,
    _validate_report_document,
)
from experiments.local_campaign import stats_adapter as phase7_module
from experiments.local_campaign.stats_adapter import (
    load_local_campaign_stats_bundle,
    publish_local_campaign_stats_registration,
)
from experiments.rig_web_app import external_measured as external_measured_module
from experiments.rig_web_app.campaigns import EngineeringCampaign
from experiments.rig_web_app.external_analysis import (
    ExternalAnalysisReportSpec,
    load_external_analysis_registration,
    publish_external_analysis_registration,
)


COMMIT = "a" * 40
PHASE6_COMMIT = "e" * 40
LOCK = "b" * 64


@pytest.fixture(autouse=True)
def _serve_from_a_different_release(monkeypatch: pytest.MonkeyPatch) -> None:
    """Historical sealed reports remain visible after a console repin."""

    monkeypatch.setenv("REF_URA", "c" * 40)
    monkeypatch.setenv("URA_FRAMEWORK_LOCK_ID", "d" * 64)


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return path


def _descriptor(path: Path) -> dict[str, object]:
    payload = path.read_bytes()
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _level1(
    path: Path,
    *,
    revision: str = "1" * 64,
    source: str = "a" * 64,
) -> None:
    counts = {
        name: {"unit": name.replace("_", " "), "completed": 0}
        for name in (
            "planning_strata",
            "execution_units",
            "judgment_records",
            "request_level_errors",
        )
    }
    body: dict[str, object] = {
        "schema_version": "ura-level1-evidence/3",
        "status": "validated_unit_qualified_lifecycle_inventory",
        "scope": {
            "evidence_kind": "measured_run",
            "empirical_validity_established": False,
            "contains_diagnostic_dry_run": False,
        },
        "counts": counts,
        "requests": [
            {
                "bindings": {
                    "project_revision": {"sha256": revision},
                    "selected_config_identities": {
                        "source_conformance": {"bytes": 1, "sha256": source}
                    },
                }
            }
        ],
        "request_envelopes": [],
    }
    material = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    body["evidence_id"] = "level1-" + hashlib.sha256(material).hexdigest()[:24]
    _write(path, body)


def _level2(
    path: Path,
    *,
    revision: str = "1" * 64,
    empty: bool = False,
) -> None:
    row = {field: None for field in _LEVEL2_ROW_FIELDS}
    row.update(
        {
            "run_id": "phase7-run",
            "corpus_arm": "strongreject_official",
            "model_spec": "local-model",
            "resolved_model": "local-model",
            "source": "strongreject",
            "risk_category": "harm",
            "effective_modality": "text",
            "expected_behavior": "refuse",
            "attacker": "deepteam",
            "defense": "none",
            "semantic_family": "safety",
            "metric": "refusal_rate",
            "metric_authority": "authoritative_or_source_native",
            "value": 0.5,
            "ci_low": 0.25,
            "ci_high": 0.75,
            "n_records": 1,
            "n_clusters": 1,
            "judgments_completed": 1,
            "judgments_evaluable": 1,
            "judgments_decided": 1,
            "judgments_abstained": 0,
            "judgments_non_evaluable": 0,
            "cross_stratum_pooling_permitted": False,
        }
    )
    body: dict[str, object] = {
        "schema_version": "ura-level2-report/1",
        "status": "deterministic_compatible_stratum_export",
        "empirical_validity_established": False,
        "pooling_policy": {
            "universal_safety_score_defined": False,
            "cross_stratum_pooling_permitted": False,
            "native_scale_pooling_permitted": False,
        },
        "inputs": {
            "n_completed_cells": 0 if empty else 1,
            "cells": [] if empty else [{"project_revision": {"sha256": revision}}],
        },
        "common": {
            "n_estimate_rows": 0 if empty else 1,
            "estimates": [] if empty else [row],
        },
        "native": {"n_native_runs": 1 if empty else 0},
    }
    material = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    body["report_id"] = "level2-" + hashlib.sha256(material).hexdigest()[:24]
    _write(path, body)


def _terminal_inventory() -> dict[str, object]:
    cohorts = (
        ("canonical", 46, "measured_complete", "1" * 64, "a" * 64),
        (
            "output_policy_amendment",
            4,
            "measured_complete",
            "2" * 64,
            "b" * 64,
        ),
        ("followon_prepared", 3, "measured_complete", "3" * 64, "c" * 64),
        ("current_ollama", 14, "measured_complete", "5" * 64, "d" * 64),
        (
            "current_ollama_stability",
            14,
            "measured_complete",
            "7" * 64,
            "f" * 64,
        ),
        (
            "current_ollama_population_alignment",
            12,
            "measured_complete",
            "7" * 64,
            "f" * 64,
        ),
        (
            "failed_output_recovery",
            6,
            "measured_complete",
            "8" * 64,
            "9" * 64,
        ),
        ("vllm_stability", 7, "measured_complete", "6" * 64, "e" * 64),
        ("native", 9, "run", "4" * 64, "not_applicable"),
    )
    rows: list[dict[str, object]] = []
    project_strata: dict[str, list[str]] = {}
    source_strata: dict[str, list[str]] = {}
    for cohort, count, state, revision, source in cohorts:
        for index in range(count):
            logical_id = f"{cohort}-{index:02d}"
            key = f"{cohort}:{logical_id}"
            rows.append(
                {
                    "key": key,
                    "cohort": cohort,
                    "logical_id": logical_id,
                    "terminal_state": state,
                    "failure": False,
                    "project_revision_stratum": revision,
                    "source_conformance_stratum": source,
                    "evidence": {"fixture": True},
                }
            )
            project_strata.setdefault(revision, []).append(key)
            source_strata.setdefault(source, []).append(key)
    return {
        "schema": "ura-phase6-campaign-terminal-inventory/5",
        "status": "complete",
        "cohort_order": [row[0] for row in cohorts],
        "cohort_counts": {row[0]: row[1] for row in cohorts},
        "row_order": [str(row["key"]) for row in rows],
        "rows": rows,
        "failure_rows": [],
        "project_revision_strata": project_strata,
        "source_conformance_strata": source_strata,
        "all_rows_terminal": True,
        "cross_revision_pooling_permitted": False,
        "cross_source_pooling_permitted": False,
        "accounting": {
            "hosted_target_calls": 0,
            "hosted_judge_calls": 0,
            "provider_http_attempts": 0,
            "paid_provider_calls": 0,
            "model_downloads": 0,
        },
    }


@pytest.mark.parametrize(
    "mutation",
    (
        "schema",
        "terminal_state",
        "nonzero_accounting",
        "cross_revision_pooling",
        "revision_label",
        "native_source_label",
    ),
)
def test_local_terminal_inventory_policy_stays_in_the_plan_adapter(
    mutation: str,
) -> None:
    document = json.loads(json.dumps(_terminal_inventory()))
    rows = document["rows"]
    assert isinstance(rows, list)
    if mutation == "schema":
        document["schema"] = "example-campaign-terminal-inventory/3"
    elif mutation == "terminal_state":
        rows[0]["terminal_state"] = "finished"
    elif mutation == "nonzero_accounting":
        document["accounting"]["target_calls"] = 1
    elif mutation == "cross_revision_pooling":
        document["cross_revision_pooling_permitted"] = True
    elif mutation == "revision_label":
        rows[0]["project_revision_stratum"] = "release-a"
        project_strata: dict[str, list[str]] = {}
        for row in rows:
            project_strata.setdefault(row["project_revision_stratum"], []).append(
                row["key"]
            )
        document["project_revision_strata"] = project_strata
    else:
        native = next(row for row in rows if row["cohort"] == "native")
        native["source_conformance_stratum"] = "source-free"
        source_strata: dict[str, list[str]] = {}
        for row in rows:
            source_strata.setdefault(row["source_conformance_stratum"], []).append(
                row["key"]
            )
        document["source_conformance_strata"] = source_strata

    # Rig Web accepts the self-reconciling generic report. Only the plan-owned
    # adapter knows this campaign's schema, states, identities, and zero-call cap.
    _validate_report_document("terminal_inventory", document)
    with pytest.raises(ValueError, match="local campaign terminal"):
        phase7_module._validate_local_campaign_terminal_inventory(document)


def _campaign(watcher: Path) -> EngineeringCampaign:
    now = time.time()
    return EngineeringCampaign(
        route_id=watcher.name,
        campaign_id=watcher.name,
        directory=watcher,
        state="complete",
        display_state="passed",
        status_tag="passed",
        state_detail="local_campaign_controller_exit_0",
        started_at=now - 10,
        ended_at=now,
        progress="sealed Phase 7 watcher complete",
        completed_tasks=1,
        succeeded_tasks=1,
        failed_tasks=0,
        skipped_tasks=0,
        active_tasks=(),
        download_tasks=(),
        pending_tasks=0,
        unplanned_tasks=(),
        task_outcomes=(("validate-analysis", "passed", "support"),),
        model_tasks=(),
        model_declaration_error="",
        model_succeeded_tasks=0,
        model_failed_tasks=0,
        model_skipped_tasks=0,
        model_active_tasks=0,
        model_pending_tasks=0,
        model_attempted_calls=0,
        model_successful_generations=0,
        model_execution_covered_tasks=0,
        model_execution_error="",
        last_detail="",
        release_commit=COMMIT,
        evidence_class="local_campaign_control",
        thesis_empirical_evidence=False,
        hosted_calls_allowed=False,
        target_call_cap=None,
        reserved_calls=0,
        hard_stop_hours=720,
        named_session_liveness_verified=False,
        logs=(),
    )


def _sealed_chain(
    tmp_path: Path,
    *,
    mutation: str = "",
    limited: bool = False,
) -> tuple[Path, EngineeringCampaign, Path]:
    results = tmp_path / "runs"
    watcher = results / "engineering" / "phase7-after-phase6-test"
    control = results / "engineering" / "phase7-analysis-test"
    analysis = results / "thesis" / "analysis" / "phase7-test"
    sealed = watcher / "sealed"
    sealed.mkdir(parents=True)
    control.mkdir()
    analysis.mkdir(parents=True)
    watcher_script = sealed / "phase7_after_phase6_sequence.sh"
    watcher_script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="ascii")
    wrapper = sealed / "phase7_analysis.sh"
    wrapper.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="ascii")
    sealed_payload = sealed / "phase7_analysis.py"
    sealed_payload.write_text("# sealed phase 7 payload\n", encoding="ascii")

    input_lock = "c" * 64 if mutation == "framework_lock_input" else LOCK
    gate5_lock = "d" * 64 if mutation == "gate5_code_identity" else input_lock
    gate5 = _write(
        results / "thesis" / "gate5" / "covered.json",
        {
            "schema": "ura-gate5-covered-manifest/1",
            "inventory_complete": True,
            "code_identity": {
                "expected_commit": PHASE6_COMMIT,
                "framework_lock_id": gate5_lock,
            },
        },
    )
    phase6 = results / "engineering" / "phase6-sequence-test"
    phase6_sealed = phase6 / "sealed"
    phase6_sealed.mkdir(parents=True)
    phase6_validator = phase6_sealed / "phase7_analysis.py"
    phase6_validator.write_bytes(sealed_payload.read_bytes())
    launch_validator = phase6_validator
    if mutation == "phase6_launch_validator":
        launch_validator = phase6_sealed / "phase7_analysis_other.py"
        launch_validator.write_text("# wrong historical validator\n", encoding="ascii")
    phase6_sequence = phase6_sealed / "phase6_sequence.sh"
    phase6_sequence.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="ascii")
    phase6_wrappers = {}
    for name in ("core", "extended", "native"):
        path = phase6_sealed / f"phase6_{name}.sh"
        path.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="ascii")
        phase6_wrappers[name] = _descriptor(path)
    phase6_self_test = _write(
        phase6 / "phase7-contract-self-test.json",
        {"schema": "ura-phase7-contract-self-test/1", "status": "passed"},
    )
    phase6_claimed_commit = (
        "f" * 40 if mutation == "phase6_gate5_identity" else PHASE6_COMMIT
    )
    phase6_launch = _write(
        phase6 / "sequence-launch.json",
        {
            "schema": "ura-phase6-sequence-launch/1",
            "status": "running",
            "started_at_utc": "2026-08-22T00:00:00Z",
            "expected_commit": phase6_claimed_commit,
            "framework_lock_id": LOCK,
            "control_root": str(phase6.resolve()),
            "authorized_sequence_sha256": _descriptor(phase6_sequence)["sha256"],
            "sequence_script": _descriptor(phase6_sequence),
            "phase7_validator": _descriptor(launch_validator),
            "phase7_contract_self_test": _descriptor(phase6_self_test),
            "controller_wrappers": phase6_wrappers,
            "gate5_wait": {
                "control_root": str(gate5.parent.resolve()),
                "session": "ura-gate5-sequence-historical",
                "socket": "ura-gate5-sequence-historical",
            },
            "controller_order": ["core", "extended", "native"],
            "long_running_children_use_tmux": True,
            "local_only": True,
        },
    )
    phase6_gate5 = {field: None for field in phase7_module._PHASE6_GATE5_FIELDS}
    phase6_gate5.update(
        {
            "covered_manifest": _descriptor(gate5),
            "runnable_lanes": ["core-lane", "extended-lane"],
            "typed_terminal_lanes": [],
            "target_runtime_terminal": {},
            "conditional_na_lanes": [],
        }
    )
    phase6_doc = {field: None for field in phase7_module._PHASE6_COMPLETION_FIELDS}
    phase6_doc.update(
        {
            "schema": "ura-phase6-sequence-completion/2",
            "status": "complete",
            "expected_commit": phase6_claimed_commit,
            "framework_lock_id": LOCK,
            "control_root": str(phase6.resolve()),
            "controller_order": ["core", "extended", "native"],
            "all_controllers_attempted": True,
            "terminal_states": {
                "core": "complete",
                "extended": "complete",
                "native": "complete",
            },
            "failed_controller_receipts_are_evidence": False,
            "conditional_na_lanes": [],
            "sequence_launch": _descriptor(phase6_launch),
            "sequence_script": _descriptor(phase6_sequence),
            "phase7_validator": _descriptor(phase6_validator),
            "phase7_contract_self_test": _descriptor(phase6_self_test),
            "controller_wrappers": phase6_wrappers,
            "gate5": phase6_gate5,
            "hosted_target_calls": 0,
            "hosted_judge_calls": 0,
            "provider_http_attempts": 0,
            "downloads_observed_bytes": 0,
        }
    )
    if mutation == "phase6_completion_schema":
        phase6_doc["schema"] = "ura-phase6-sequence-completion/0"
    phase6_completion = _write(phase6 / "completion.json", phase6_doc)
    phase6_exit = phase6 / ".exit"
    phase6_exit.write_bytes(b"1\n" if mutation == "phase6_exit" else b"0\n")

    followon_lanes = (
        "followon-nanogcg-qwen3-vl",
        "followon-ideator-v2-qwen3-vl",
        "followon-t3mp3st-qwen3-vl",
    )
    followon_states = {lane: "measured_complete" for lane in followon_lanes}
    followon_strata = {"3" * 64: list(followon_lanes)}
    input_followon_states = (
        None if mutation == "followon_terminal_states_null" else followon_states
    )
    input_followon_strata = (
        None if mutation == "followon_revision_strata_null" else followon_strata
    )
    campaign_inventory_value = _terminal_inventory()
    inputs = {
        "schema": "ura-phase7-analysis-inputs/5",
        "inventory_complete": True,
        "scope": "all_local_phase7_read_only_analysis_over_phase6_lifecycle",
        "code_identity": {"expected_commit": COMMIT, "framework_lock_id": input_lock},
        "gate5": {
            "manifest": _descriptor(gate5),
            "code_identity": {
                "expected_commit": PHASE6_COMMIT,
                "framework_lock_id": gate5_lock,
            },
        },
        "project_and_source": {
            "project_revision": {
                "artifact": {"sha256": "1" * 64},
                "experiment_binding": {
                    "sha256": "1" * 64,
                    "expected_commit": PHASE6_COMMIT,
                    "observed_commit": PHASE6_COMMIT,
                },
            }
        },
        "phase6": {
            "core": {"lane_terminal_states": {"core-lane": "measured_complete"}},
            "extended": {"lane_terminal_states": {"extended-lane": "measured_complete"}},
        },
        "native_outcomes": {"states": {"native-lane": "run"}},
        "followon": {
            "terminal_states": input_followon_states,
            "revision_strata": input_followon_strata,
            "source_conformance_sha256": "c" * 64,
        },
        "seven_output_policy_amendment": {
            "terminal_states": {"seven-lane": "measured_complete"},
            "revision_strata": {"2" * 64: ["seven-lane"]},
            "source_conformance_sha256": "b" * 64,
        },
        "current_ollama": {
            "terminal_states": {"current-lane": "measured_complete"},
            "revision_strata": {"5" * 64: ["current-lane"]},
            "target_execution": {
                "target_attempts": 1,
                "successful_target_generations": 1,
                "missing_responses": 0,
            },
        },
        "current_ollama_stability": {
            "terminal_states": {
                "current-stability-lane": "measured_complete"
            },
            "revision_strata": {
                "7" * 64: ["current-stability-lane"]
            },
            "target_execution": {
                "target_attempts": 1,
                "successful_target_generations": 1,
                "missing_responses": 0,
            },
        },
        "current_ollama_population_alignment": {
            "terminal_states": {
                "current-alignment-lane": "measured_complete"
            },
            "revision_strata": {
                "7" * 64: ["current-alignment-lane"]
            },
            "target_execution": {
                "target_attempts": 1,
                "successful_target_generations": 1,
                "missing_responses": 0,
            },
            "population_alignment": {
                "limit_50_prefix_rows": 11520,
                "limit_100_total_rows": 23120,
                "extension_rows": 11600,
            },
        },
        "failed_output_recovery": {
            "terminal_states": {
                "failed-output-recovery-lane": "measured_complete"
            },
            "revision_strata": {
                "8" * 64: ["failed-output-recovery-lane"]
            },
            "target_execution": {
                "target_attempts": 1,
                "successful_target_generations": 1,
                "missing_responses": 0,
            },
        },
        "vllm_stability": {
            "terminal_states": {"vllm-lane": "measured_complete"},
            "revision_strata": {"6" * 64: ["vllm-lane"]},
            "target_execution": {
                "target_attempts": 1,
                "successful_target_generations": 1,
                "missing_responses": 0,
            },
        },
        "campaign_terminal_inventory": campaign_inventory_value,
        "runner": {
            "lifecycle_lane_order": ["core-lane", "extended-lane"],
            "metric_lane_order": ["core-lane", "extended-lane"],
            "terminal_states": {
                "core-lane": "measured_complete",
                "extended-lane": "measured_complete",
            },
        },
    }
    watcher_input = _write(watcher / "phase7-inputs.json", inputs)
    control_input = _write(control / "phase7-inputs.json", inputs)
    input_sha = hashlib.sha256(control_input.read_bytes()).hexdigest()
    assert watcher_input.read_bytes() == control_input.read_bytes()
    payload = control / "payload.py"
    payload.write_bytes(sealed_payload.read_bytes())
    analysis_launch = {
        "schema": "ura-phase7-analysis-launch/1",
        "authorized_input_manifest_sha256": (
            "d" * 64 if mutation == "control_launch_authorization" else input_sha
        ),
        "input_manifest": _descriptor(control_input),
        "payload": _descriptor(payload),
        "control_root": str(control.resolve()),
        "analysis_root": str(analysis.resolve()),
    }
    _write(control / "launch.json", analysis_launch)

    prepare_result = {
        "status": "prepared",
        "schema": "ura-phase7-analysis-inputs/5",
        "output": (
            str(watcher / "wrong-input.json")
            if mutation == "prepare_result_output"
            else str(watcher_input.resolve())
        ),
        "sha256": input_sha,
        "bytes": len(watcher_input.read_bytes()),
        "bound_artifacts": 4,
        "runner_lanes": 2,
        "metric_runner_lanes": 2,
        "native_outcomes": {"native-lane": "run"},
        "campaign_terminal_rows": 115,
        "campaign_terminal_status": "complete",
        "authorization_required_before_launch": True,
    }
    prepare_path = _write(watcher / "prepare-result.json", prepare_result)

    phase7_session = (
        "ura-phase7-wrong" if mutation == "phase7_launch_output_session" else "ura-phase7-test"
    )
    phase7_launch = watcher / "phase7-launch.txt"
    phase7_launch.write_bytes(
        (
            "\n".join(
                (
                    f"SESSION={phase7_session}",
                    "SOCKET=ura-phase7-test",
                    "ATTACH=tmux -L ura-phase7-test attach -t ura-phase7-test",
                    f"CONTROL_ROOT={control.resolve()}",
                    f"ANALYSIS_ROOT={analysis.resolve()}",
                    f"LOG={control.resolve() / 'controller.log'}",
                    f"EXIT_MARKER={control.resolve() / '.exit'}",
                    f"COMPLETION={control.resolve() / 'completion.json'}",
                )
            )
            + "\n"
        ).encode("ascii")
    )

    phase6_wait_session = (
        "ura-phase6-sequence-substituted"
        if mutation == "watcher_phase6_wait_identity"
        else f"ura-phase6-sequence-{COMMIT[:7]}"
    )
    watcher_launch = {
        "schema": (
            "ura-phase7-after-phase6-launch/0"
            if mutation == "watcher_launch_schema"
            else "ura-phase7-after-phase6-launch/1"
        ),
        "status": "waiting_for_phase6",
        "started_at_utc": "2026-08-23T00:00:00Z",
        "expected_commit": COMMIT,
        "framework_lock_id": LOCK,
        "control_root": str(watcher.resolve()),
        "authorized_watcher_sha256": _descriptor(watcher_script)["sha256"],
        "watcher": _descriptor(watcher_script),
        "phase7_wrapper": _descriptor(wrapper),
        "phase7_payload": _descriptor(sealed_payload),
        "phase6_wait": {
            "control_root": str(phase6.resolve()),
            "session": phase6_wait_session,
            "socket": phase6_wait_session,
        },
        "target_calls_permitted": 0,
        "judge_calls_permitted": 0,
        "provider_http_attempts_permitted": 0,
    }
    watcher_launch_path = _write(watcher / "watcher-launch.json", watcher_launch)
    runner_view = _write(
        control / "read-only-runner-view.json", {"schema": "runner-view"}
    )
    human_view = _write(
        control / "read-only-human-audit-runner-view.json", {"schema": "human-view"}
    )
    human_index = _write(
        control / "read-only-human-audit-runner-view.index.json",
        {"schema": "human-index"},
    )
    campaign_rows = campaign_inventory_value["rows"]
    assert isinstance(campaign_rows, list)
    if mutation == "campaign_inventory_terminal_state":
        campaign_rows[0]["terminal_state"] = "running"
    if mutation == "campaign_inventory_revision_stratum":
        campaign_rows[0]["project_revision_stratum"] = "short"
    campaign_inventory = _write(
        analysis / "campaign-terminal-inventory.json",
        campaign_inventory_value,
    )
    first_stratum_id = f"{'1' * 12}-{'a' * 12}"
    if mutation == "report_stratum_directory":
        first_stratum_id = f"{'9' * 12}-{'a' * 12}"
    if mutation == "report_stratum_source_directory":
        first_stratum_id = f"{'1' * 12}-{'9' * 12}"
    level1 = analysis / "lifecycle-strata" / first_stratum_id / "level1-evidence.json"
    level1_second = (
        analysis / "lifecycle-strata" / f"{'2' * 12}-{'b' * 12}" / "level1-evidence.json"
    )
    level1_third = (
        analysis / "lifecycle-strata" / f"{'3' * 12}-{'c' * 12}" / "level1-evidence.json"
    )
    level1_fourth = (
        analysis / "lifecycle-strata" / f"{'5' * 12}-{'d' * 12}" / "level1-evidence.json"
    )
    level1_fifth = (
        analysis / "lifecycle-strata" / f"{'6' * 12}-{'e' * 12}" / "level1-evidence.json"
    )
    level1_sixth = (
        analysis / "lifecycle-strata" / f"{'7' * 12}-{'f' * 12}" / "level1-evidence.json"
    )
    level1_failed_output_recovery = (
        analysis / "lifecycle-strata" / f"{'8' * 12}-{'9' * 12}" / "level1-evidence.json"
    )
    level2 = analysis / "metric-strata" / f"{'1' * 12}-{'a' * 12}" / "level2-report.json"
    level2_second = (
        analysis / "metric-strata" / f"{'2' * 12}-{'b' * 12}" / "level2-report.json"
    )
    level2_third = (
        analysis / "metric-strata" / f"{'3' * 12}-{'c' * 12}" / "level2-report.json"
    )
    level2_fourth = (
        analysis / "metric-strata" / f"{'5' * 12}-{'d' * 12}" / "level2-report.json"
    )
    level2_fifth = (
        analysis / "metric-strata" / f"{'6' * 12}-{'e' * 12}" / "level2-report.json"
    )
    level2_sixth = (
        analysis / "metric-strata" / f"{'7' * 12}-{'f' * 12}" / "level2-report.json"
    )
    level2_failed_output_recovery = (
        analysis / "metric-strata" / f"{'8' * 12}-{'9' * 12}" / "level2-report.json"
    )
    _level1(
        level1,
        revision="9" * 64 if mutation == "report_scope_revision" else "1" * 64,
        source="9" * 64 if mutation == "report_scope_source" else "a" * 64,
    )
    _level1(level1_second, revision="2" * 64, source="b" * 64)
    _level1(level1_third, revision="3" * 64, source="c" * 64)
    _level1(level1_fourth, revision="5" * 64, source="d" * 64)
    _level1(level1_fifth, revision="6" * 64, source="e" * 64)
    _level1(level1_sixth, revision="7" * 64, source="f" * 64)
    _level1(level1_failed_output_recovery, revision="8" * 64, source="9" * 64)
    _level2(
        level2,
        revision="9" * 64 if mutation == "level2_scope_revision" else "1" * 64,
    )
    _level2(level2_second, revision="2" * 64)
    _level2(level2_third, revision="3" * 64)
    _level2(level2_fourth, revision="5" * 64)
    _level2(level2_fifth, revision="6" * 64)
    _level2(level2_sixth, revision="7" * 64)
    _level2(level2_failed_output_recovery, revision="8" * 64)
    statuses = {
        "level1-evidence": "complete",
        "level2-report": "complete_with_limitations" if limited else "complete",
    }
    explicit_limitations = {
        name: status for name, status in statuses.items() if status != "complete"
    }
    completion_status = "complete_with_explicit_limitations" if explicit_limitations else "complete"
    artifacts = [
        _descriptor(path)
        for path in (
            level1,
            level1_second,
            level1_third,
            level1_fourth,
            level1_fifth,
            level1_sixth,
            level1_failed_output_recovery,
            level2,
            level2_second,
            level2_third,
            level2_fourth,
            level2_fifth,
            level2_sixth,
            level2_failed_output_recovery,
            campaign_inventory,
        )
    ]
    inventory = _write(
        analysis / "artifact-inventory.json",
        {
            "schema": "ura-phase7-analysis-artifact-inventory/1",
            "status": "complete",
            "analysis_root": str(analysis.resolve()),
            "artifacts": artifacts,
            "artifact_count": len(artifacts),
            "status_inventory": statuses,
            "input_manifest_sha256": (
                "e" * 64 if mutation == "inventory_input_digest" else input_sha
            ),
            "payload_sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            "runner_input_view": _descriptor(runner_view),
            "campaign_terminal_inventory": _descriptor(campaign_inventory),
            "human_audit_runner_input_view": _descriptor(human_view),
            "human_audit_sampling_index": _descriptor(human_index),
            "target_calls": 0,
            "judge_calls": 0,
            "provider_http_attempts": 0,
            "human_labels_consumed": False,
        },
    )
    exit_path = control / ".exit"
    exit_path.write_bytes(b"0\n")
    controller = {field: None for field in phase7_module._CONTROLLER_FIELDS}
    boundary_fields = (
        "human_labels_consumed",
        "human_validity_claimed",
        "universal_safety_score_defined",
        "native_scales_pooled",
        "evaluator_modes_pooled",
    )
    controller.update(
        {
            "schema": "ura-phase7-analysis-completion/5",
            "status": completion_status,
            "inventory_complete": True,
            "input_manifest": _descriptor(control_input),
            "authorized_input_manifest_sha256": (
                "f" * 64 if mutation == "controller_input_digest" else input_sha
            ),
            "payload": _descriptor(payload),
            "analysis_root": str(analysis.resolve()),
            "artifact_inventory": _descriptor(inventory),
            "runner_input_view": _descriptor(runner_view),
            "campaign_terminal_inventory": _descriptor(campaign_inventory),
            "human_audit_runner_input_view": _descriptor(human_view),
            "human_audit_sampling_index": _descriptor(human_index),
            "analysis_statuses": statuses,
            "explicit_limitations": explicit_limitations,
            "phase6_terminal_states": {
                "core": {"core-lane": "measured_complete"},
                "extended": {"extended-lane": "measured_complete"},
                "native": {"native-lane": "run"},
            },
            "followon_terminal_states": input_followon_states,
            "followon_metric_revision_strata": input_followon_strata,
            "seven_output_policy_terminal_states": (
                {"seven-lane": "failed"}
                if mutation == "controller_seven_states"
                else {"seven-lane": "measured_complete"}
            ),
            "seven_output_policy_metric_revision_strata": {"2" * 64: ["seven-lane"]},
            "current_ollama_terminal_states": inputs["current_ollama"][
                "terminal_states"
            ],
            "current_ollama_metric_revision_strata": inputs["current_ollama"][
                "revision_strata"
            ],
            "current_ollama_target_execution": inputs["current_ollama"][
                "target_execution"
            ],
            "current_ollama_stability_terminal_states": inputs[
                "current_ollama_stability"
            ]["terminal_states"],
            "current_ollama_stability_metric_revision_strata": inputs[
                "current_ollama_stability"
            ]["revision_strata"],
            "current_ollama_stability_target_execution": inputs[
                "current_ollama_stability"
            ]["target_execution"],
            "current_ollama_population_alignment_terminal_states": inputs[
                "current_ollama_population_alignment"
            ]["terminal_states"],
            "current_ollama_population_alignment_metric_revision_strata": inputs[
                "current_ollama_population_alignment"
            ]["revision_strata"],
            "current_ollama_population_alignment_target_execution": inputs[
                "current_ollama_population_alignment"
            ]["target_execution"],
            "current_ollama_population_alignment": (
                {"changed": True}
                if mutation == "controller_ollama_alignment"
                else inputs["current_ollama_population_alignment"][
                    "population_alignment"
                ]
            ),
            "failed_output_recovery_terminal_states": inputs[
                "failed_output_recovery"
            ]["terminal_states"],
            "failed_output_recovery_metric_revision_strata": inputs[
                "failed_output_recovery"
            ]["revision_strata"],
            "failed_output_recovery_target_execution": inputs[
                "failed_output_recovery"
            ]["target_execution"],
            "vllm_stability_terminal_states": inputs["vllm_stability"][
                "terminal_states"
            ],
            "vllm_stability_metric_revision_strata": inputs["vllm_stability"][
                "revision_strata"
            ],
            "vllm_stability_target_execution": inputs["vllm_stability"][
                "target_execution"
            ],
            "target_calls": 0,
            "judge_calls": 0,
            "provider_http_attempts": 0,
            "downloads_observed_bytes": 0,
            **{field: mutation == f"controller_boundary_{field}" for field in boundary_fields},
        }
    )
    controller_path = _write(control / "completion.json", controller)
    watcher_descriptor_path = watcher_script
    wrapper_descriptor_path = wrapper
    payload_descriptor_path = sealed_payload
    if mutation == "watcher_descriptor_path":
        watcher_descriptor_path = sealed / "alternate-watcher.sh"
        watcher_descriptor_path.write_bytes(watcher_script.read_bytes())
    if mutation == "wrapper_descriptor_path":
        wrapper_descriptor_path = sealed / "alternate-wrapper.sh"
        wrapper_descriptor_path.write_bytes(wrapper.read_bytes())
    if mutation == "payload_descriptor_path":
        payload_descriptor_path = sealed / "alternate-payload.py"
        payload_descriptor_path.write_bytes(sealed_payload.read_bytes())
    watcher_doc = {field: None for field in phase7_module._WATCHER_FIELDS}
    watcher_doc.update(
        {
            "schema": "ura-phase7-after-phase6-completion/1",
            "status": (
                "complete_with_explicit_limitations"
                if mutation == "watcher_controller_status"
                else completion_status
            ),
            "expected_commit": "c" * 40 if mutation == "watcher_commit" else COMMIT,
            "framework_lock_id": LOCK,
            "watcher_launch": _descriptor(watcher_launch_path),
            "watcher": _descriptor(watcher_descriptor_path),
            "phase7_wrapper": _descriptor(wrapper_descriptor_path),
            "phase7_payload": _descriptor(payload_descriptor_path),
            "phase6_sequence_completion": _descriptor(phase6_completion),
            "phase6_sequence_exit": _descriptor(phase6_exit),
            "prepare_result": _descriptor(prepare_path),
            "authorized_input_manifest": _descriptor(watcher_input),
            "authorized_input_manifest_sha256": input_sha,
            "phase7_launch_output": _descriptor(phase7_launch),
            "phase7_control_root": str(control.resolve()),
            "analysis_root": str(analysis.resolve()),
            "phase7_completion": _descriptor(controller_path),
            "phase7_exit": _descriptor(exit_path),
            "artifact_inventory": _descriptor(inventory),
            "campaign_terminal_inventory": _descriptor(campaign_inventory),
            "runner_input_view": _descriptor(runner_view),
            "human_audit_runner_input_view": _descriptor(human_view),
            "human_audit_sampling_index": _descriptor(human_index),
            "analysis_statuses": statuses,
            "explicit_limitations": explicit_limitations,
            "target_calls": 0,
            "judge_calls": 0,
            "provider_http_attempts": 0,
            "downloads_observed_bytes": 0,
            "human_labels_consumed": False,
        }
    )
    if mutation == "inventory_descriptor_mismatch":
        alternate = analysis / "alternate-inventory.json"
        alternate.write_bytes(inventory.read_bytes())
        watcher_doc["artifact_inventory"] = _descriptor(alternate)
    _write(watcher / "completion.json", watcher_doc)
    return results, _campaign(watcher), level2


def test_phase7_watcher_chain_binds_reports_and_rejects_mutated_output(
    tmp_path: Path,
) -> None:
    results, campaign, level2 = _sealed_chain(tmp_path)
    bundle = load_local_campaign_stats_bundle(results, campaign)
    assert bundle is not None
    assert [report.kind for report in bundle.reports] == [
        "terminal_inventory",
        "level1", "level1", "level1", "level1", "level1", "level1",
        "level1",
        "level2", "level2", "level2", "level2", "level2", "level2",
        "level2",
    ]
    assert [report.display_name for report in bundle.reports] == [
        "campaign-terminal-inventory.json",
        "lifecycle-strata/111111111111-aaaaaaaaaaaa/level1-evidence.json",
        "lifecycle-strata/222222222222-bbbbbbbbbbbb/level1-evidence.json",
        "lifecycle-strata/333333333333-cccccccccccc/level1-evidence.json",
        "lifecycle-strata/555555555555-dddddddddddd/level1-evidence.json",
        "lifecycle-strata/666666666666-eeeeeeeeeeee/level1-evidence.json",
        "lifecycle-strata/777777777777-ffffffffffff/level1-evidence.json",
        "lifecycle-strata/888888888888-999999999999/level1-evidence.json",
        "metric-strata/111111111111-aaaaaaaaaaaa/level2-report.json",
        "metric-strata/222222222222-bbbbbbbbbbbb/level2-report.json",
        "metric-strata/333333333333-cccccccccccc/level2-report.json",
        "metric-strata/555555555555-dddddddddddd/level2-report.json",
        "metric-strata/666666666666-eeeeeeeeeeee/level2-report.json",
        "metric-strata/777777777777-ffffffffffff/level2-report.json",
        "metric-strata/888888888888-999999999999/level2-report.json",
    ]
    assert bundle.expected_commit == COMMIT
    phase6_completion = json.loads(
        (results / "engineering" / "phase6-sequence-test" / "completion.json").read_text(
            encoding="utf-8"
        )
    )
    assert phase6_completion["expected_commit"] == PHASE6_COMMIT != bundle.expected_commit
    assert bundle.framework_lock_id == LOCK
    assert (
        bundle.gate5_sha256
        == hashlib.sha256((results / "thesis" / "gate5" / "covered.json").read_bytes()).hexdigest()
    )

    # Mutation proof: inventory membership without matching report bytes never
    # authorizes a chart or detail binding.
    level2.write_text("{}\n", encoding="utf-8")
    assert load_local_campaign_stats_bundle(results, campaign) is None


@pytest.mark.parametrize(
    "mutation",
    (
        "watcher_commit",
        "framework_lock_input",
        "gate5_code_identity",
        "controller_input_digest",
        "controller_seven_states",
        "controller_ollama_alignment",
        "inventory_input_digest",
        "watcher_controller_status",
        "inventory_descriptor_mismatch",
        "watcher_launch_schema",
        "watcher_descriptor_path",
        "wrapper_descriptor_path",
        "payload_descriptor_path",
        "phase6_completion_schema",
        "phase6_gate5_identity",
        "phase6_launch_validator",
        "phase6_exit",
        "prepare_result_output",
        "phase7_launch_output_session",
        "watcher_phase6_wait_identity",
        "control_launch_authorization",
        "controller_boundary_human_labels_consumed",
        "controller_boundary_human_validity_claimed",
        "controller_boundary_universal_safety_score_defined",
        "controller_boundary_native_scales_pooled",
        "controller_boundary_evaluator_modes_pooled",
        "followon_terminal_states_null",
        "followon_revision_strata_null",
        "report_stratum_directory",
        "report_stratum_source_directory",
        "report_scope_revision",
        "report_scope_source",
        "level2_scope_revision",
        "campaign_inventory_terminal_state",
        "campaign_inventory_revision_stratum",
    ),
)
def test_phase7_chain_identity_and_boundary_mutations_never_link_stats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path, mutation=mutation)
    assert load_local_campaign_stats_bundle(results, campaign) is None
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    monkeypatch.setattr(app, "_engineering_campaign_scan", lambda **_kwargs: ([campaign], ""))
    try:
        index = app.handle("GET", "/stats")[2].decode("utf-8")
    finally:
        app.close()
    assert f"href='/stats/job/{campaign.route_id}'" not in index


def test_stats_links_sealed_phase7_reports_to_watcher_campaign(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path)
    publish_local_campaign_stats_registration(results, campaign)
    registration = load_external_analysis_registration(results, campaign.route_id)
    assert registration is not None
    assert [report.kind for report in registration.reports] == [
        "terminal_inventory",
        "level1", "level1", "level1", "level1", "level1", "level1",
        "level2", "level2", "level2", "level2", "level2", "level2",
    ]
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    monkeypatch.setattr(app, "_engineering_campaign_scan", lambda **_kwargs: ([campaign], ""))
    monkeypatch.setattr(
        app,
        "_engineering_campaign",
        lambda route: campaign if route == campaign.route_id else None,
    )
    try:
        index = app.handle("GET", "/stats")[2].decode("utf-8")
        status, _headers, detail = app.handle("GET", f"/stats/job/{campaign.route_id}?fragment=1")
    finally:
        app.close()

    assert f"href='/stats/job/{campaign.route_id}'" in index
    assert "Statistics &amp; diagrams" in index
    assert status == 200
    detail_text = detail.decode("utf-8")
    assert "Registered external analysis" in detail_text
    assert "does not grant thesis-evidence authority" in detail_text
    assert "Campaign terminal rows" in detail_text
    assert "115 terminal campaign rows; 0 failure rows" in detail_text
    assert "Rows by cohort" in detail_text
    assert "Rows by terminal state" in detail_text
    assert "Failure accounting" in detail_text
    assert "canonical" in detail_text and ">46<" in detail_text
    assert "output policy amendment" in detail_text and ">4<" in detail_text
    assert "followon prepared" in detail_text and ">3<" in detail_text
    assert "current ollama" in detail_text and ">14<" in detail_text
    assert "current ollama stability" in detail_text and ">14<" in detail_text
    assert "current ollama population alignment" in detail_text and ">12<" in detail_text
    assert "failed output recovery" in detail_text and ">6<" in detail_text
    assert "vllm stability" in detail_text and ">7<" in detail_text
    assert "native" in detail_text and ">9<" in detail_text
    assert "1" * 64 in detail_text
    assert "a" * 64 in detail_text
    assert "0 complete cells" not in detail_text
    assert "lifecycle-strata/111111111111-aaaaaaaaaaaa/level1-evidence.json" in detail_text
    assert "lifecycle-strata/333333333333-cccccccccccc/level1-evidence.json" in detail_text
    assert "lifecycle-strata/666666666666-eeeeeeeeeeee/level1-evidence.json" in detail_text
    assert "metric-strata/111111111111-aaaaaaaaaaaa/level2-report.json" in detail_text
    assert "metric-strata/333333333333-cccccccccccc/level2-report.json" in detail_text
    assert "metric-strata/666666666666-eeeeeeeeeeee/level2-report.json" in detail_text
    assert "refusal_rate" in detail_text
    assert "class='barchart'" in detail_text
    assert "Open full job record" in detail_text


def test_stats_preserves_phase7_explicit_limitations_in_status_and_detail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path, limited=True)
    bundle = load_local_campaign_stats_bundle(results, campaign)
    assert bundle is not None
    assert bundle.completion_status == "complete_with_explicit_limitations"
    assert bundle.explicit_limitations == (("level2-report", "complete_with_limitations"),)
    publish_local_campaign_stats_registration(results, campaign)
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    monkeypatch.setattr(app, "_engineering_campaign_scan", lambda **_kwargs: ([campaign], ""))
    monkeypatch.setattr(
        app,
        "_engineering_campaign",
        lambda route: campaign if route == campaign.route_id else None,
    )
    try:
        index = app.handle("GET", "/stats")[2].decode("utf-8")
        status, _headers, detail = app.handle("GET", f"/stats/job/{campaign.route_id}?fragment=1")
    finally:
        app.close()

    assert "complete with explicit limitations" in index
    assert status == 200
    detail_text = detail.decode("utf-8")
    assert "Analysis completed with explicit limitations" in detail_text
    assert "level2-report" in detail_text
    assert "complete_with_limitations" in detail_text


def test_generic_registration_fails_closed_after_report_byte_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, campaign, level2_path = _sealed_chain(tmp_path)
    publish_local_campaign_stats_registration(results, campaign)
    assert load_external_analysis_registration(results, campaign.route_id) is not None

    # The document remains valid JSON, but its exact registered bytes changed.
    level2_document = json.loads(level2_path.read_text(encoding="utf-8"))
    level2_path.write_text(
        json.dumps(level2_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    assert load_external_analysis_registration(results, campaign.route_id) is None

    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    monkeypatch.setattr(app, "_engineering_campaign_scan", lambda **_kwargs: ([campaign], ""))
    try:
        index = app.handle("GET", "/stats")[2].decode("utf-8")
    finally:
        app.close()
    assert f"href='/stats/job/{campaign.route_id}'" not in index


def test_render_revalidates_registered_report_bytes(
    tmp_path: Path,
) -> None:
    results, campaign, level2_path = _sealed_chain(tmp_path)
    publish_local_campaign_stats_registration(results, campaign)
    registration = load_external_analysis_registration(results, campaign.route_id)
    assert registration is not None

    level2_document = json.loads(level2_path.read_text(encoding="utf-8"))
    level2_path.write_text(
        json.dumps(level2_document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    try:
        detail = app._stats_campaign_detail(
            app._stats_external_analysis_campaign(campaign, registration)
        )
    finally:
        app.close()
    assert "The exact report output is missing or malformed" in detail


def test_valid_empty_level2_retains_artifact_link(tmp_path: Path) -> None:
    results = tmp_path / "runs"
    report = results / "analysis" / "native-only-level2.json"
    _level2(report, empty=True)
    app = RigWebApp(
        results_root=results,
        state_dir=tmp_path / "state",
        repo_root=tmp_path,
        gpu_hardware={"devices": []},
        system_hardware={},
    )
    try:
        card = app._stats_report_card(
            {
                "path": "analysis/native-only-level2.json",
                "source_path": report,
                "display_name": "native-only-level2.json",
                "kind": "level2",
            }
        )
    finally:
        app.close()

    assert "no common estimate rows (native-only or empty)" in card
    assert "href='/artifacts?path=analysis/native-only-level2.json'" in card


def test_generic_registration_rejects_duplicate_report_path(tmp_path: Path) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path)
    registration_path = publish_local_campaign_stats_registration(results, campaign)
    registration = json.loads(registration_path.read_text(encoding="utf-8"))
    registration["reports"][1] = dict(registration["reports"][0])
    _write(registration_path, registration)
    assert load_external_analysis_registration(results, campaign.route_id) is None


def test_generic_registration_rejects_invalid_terminal_inventory(tmp_path: Path) -> None:
    results, _campaign, level2 = _sealed_chain(tmp_path)
    analysis = level2.parents[2]
    inventory = analysis / "campaign-terminal-inventory.json"
    document = json.loads(inventory.read_text(encoding="utf-8"))
    document["cohort_counts"]["canonical"] = 45
    _write(inventory, document)

    with pytest.raises(ValueError, match="cohort counts"):
        publish_external_analysis_registration(
            results,
            job_id="phase7-invalid-terminal-inventory",
            analysis_root=analysis,
            work_label="invalid terminal inventory fixture",
            completion_status="complete",
            explicit_limitations={},
            reports=(
                ExternalAnalysisReportSpec(
                    path=inventory,
                    kind="terminal_inventory",
                    display_name="campaign-terminal-inventory.json",
                ),
            ),
        )


def test_generic_registration_retains_more_than_eight_analysis_strata(
    tmp_path: Path,
) -> None:
    results, _campaign, level2 = _sealed_chain(tmp_path)
    analysis = level2.parents[2]
    level1 = next((analysis / "lifecycle-strata").glob("*/level1-evidence.json"))
    reports: list[ExternalAnalysisReportSpec] = []
    for index in range(9):
        for kind, source in (("level1", level1), ("level2", level2)):
            destination = analysis / "registration-scale" / f"{index:02d}-{kind}.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
            reports.append(
                ExternalAnalysisReportSpec(
                    path=destination,
                    kind=kind,
                    display_name=f"registration-scale/{destination.name}",
                )
            )
    registration_path = publish_external_analysis_registration(
        results,
        job_id="phase7-many-strata",
        analysis_root=analysis,
        work_label="Phase 7 many-stratum fixture",
        completion_status="complete",
        explicit_limitations={},
        reports=reports,
    )
    assert registration_path.is_file()
    registration = load_external_analysis_registration(results, "phase7-many-strata")
    assert registration is not None
    assert len(registration.reports) == 18

    with pytest.raises(ValueError, match="report count"):
        publish_external_analysis_registration(
            results,
            job_id="phase7-over-report-cap",
            analysis_root=analysis,
            work_label="Phase 7 over-cap fixture",
            completion_status="complete",
            explicit_limitations={},
            reports=[reports[0]] * 129,
        )


def test_generic_registration_rejects_symlinked_registry_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path)
    publish_local_campaign_stats_registration(results, campaign)
    registry = results / "external-analysis-jobs"
    original = Path.is_symlink

    def appears_symlinked(path: Path) -> bool:
        return path == registry or original(path)

    monkeypatch.setattr(Path, "is_symlink", appears_symlinked)
    assert load_external_analysis_registration(results, campaign.route_id) is None


def test_local_adapter_cli_publishes_generic_registration(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path)
    assert (
        phase7_module.main(
            [
                "--results-root",
                str(results),
                "--campaign-root",
                str(campaign.directory),
                "--release-commit",
                COMMIT,
            ]
        )
        == 0
    )
    registration = load_external_analysis_registration(results, campaign.route_id)
    assert registration is not None
    assert Path(capsys.readouterr().out.strip()).name == "registration.json"


def test_local_adapter_cli_fails_before_publication_for_mutated_terminal_chain(
    tmp_path: Path,
) -> None:
    results, campaign, _level2_path = _sealed_chain(
        tmp_path,
        mutation="watcher_commit",
    )
    with pytest.raises(ValueError, match="chain is not publishable"):
        phase7_module.main(
            [
                "--results-root",
                str(results),
                "--campaign-root",
                str(campaign.directory),
                "--release-commit",
                COMMIT,
            ]
        )
    assert not (results / "external-analysis-jobs").exists()


def test_interrupted_generic_registration_is_retryable_without_partial_final(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path)
    real_publish = external_measured_module._publish_create_only

    def interrupt_publish(_temporary: Path, _final: Path) -> None:
        raise OSError("simulated publication interruption")

    monkeypatch.setattr(
        external_measured_module,
        "_publish_create_only",
        interrupt_publish,
    )
    with pytest.raises(OSError, match="simulated publication interruption"):
        publish_local_campaign_stats_registration(results, campaign)
    job_directory = results / "external-analysis-jobs" / campaign.route_id
    assert not job_directory.exists()

    monkeypatch.setattr(
        external_measured_module,
        "_publish_create_only",
        real_publish,
    )
    registration_path = publish_local_campaign_stats_registration(results, campaign)
    assert registration_path.is_file()
    assert load_external_analysis_registration(results, campaign.route_id) is not None


def test_interrupted_generic_registration_preserves_foreign_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results, campaign, _level2_path = _sealed_chain(tmp_path)
    foreign: Path | None = None

    def interrupt_after_foreign_file(_temporary: Path, final: Path) -> None:
        nonlocal foreign
        foreign = final.with_name("foreign.keep")
        foreign.write_text("operator-owned\n", encoding="utf-8")
        raise OSError("simulated foreign collision")

    monkeypatch.setattr(
        external_measured_module,
        "_publish_create_only",
        interrupt_after_foreign_file,
    )
    with pytest.raises(OSError, match="simulated foreign collision"):
        publish_local_campaign_stats_registration(results, campaign)

    assert foreign is not None and foreign.read_text(encoding="utf-8") == "operator-owned\n"
    assert not foreign.with_name("registration.json").exists()
