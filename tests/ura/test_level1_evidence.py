from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments import run_matrix
from experiments.level1_evidence import (
    _condition_from_plan,
    _bind_live_attestations,
    _decision_state,
    _load_live_attestation_artifact,
    _load_results,
    _plan_artifact,
    _validate_grid_plan_bindings,
    build_level1_evidence,
    main,
    write_csv,
)
from ura.converters.synth import synth_corpus
from ura.eligibility import build_eligibility_plan, canonical_json_sha256
from ura.live_attestation import (
    build_live_attestation_manifest,
    route_config_sha256,
)
from ura.targets.api import MockTarget


class _Target:
    def __init__(self, name: str, modalities: tuple[str, ...]) -> None:
        self.name = name
        self.modality_support = modalities


def _project_revision(*, dry_run: bool) -> dict[str, object]:
    identity: dict[str, object] = {
        "mode": "not_required_diagnostic_dry_run" if dry_run else "verified",
        "revision_id": None,
        "file": None,
        "sha256": None,
        "bytes": None,
        "expected_commit": None,
        "observed_commit": None,
        "head_tree": None,
        "harness_source_sha256": "1" * 64,
        "driver_source_sha256": "2" * 64,
    }
    if not dry_run:
        identity.update({
            "revision_id": "project-revision-" + "a" * 24,
            "file": "project-revision-" + "a" * 24 + ".project-revision.json",
            "sha256": "b" * 64,
            "bytes": 100,
            "expected_commit": "c" * 40,
            "observed_commit": "c" * 40,
            "head_tree": "d" * 40,
        })
    return identity


def _conditions(
    *,
    defense: str = "none",
    dry_run: bool = True,
    live_attestation: dict | None = None,
) -> tuple[dict, dict]:
    selected = {
        "source_config": None,
        "source_conformance": None,
        "attacker_config": None,
        "api_config": None,
        "local_config": None,
    }
    values = {
        "execution_purpose": "diagnostic_dry_run" if dry_run else "measured_run",
        "project_revision": _project_revision(dry_run=dry_run),
        "defense": defense,
        "defense_guard": "rules",
        "judges": ["rules"],
        "judge_model": None,
        "guardrail_model": None,
        "guardrail_revision": None,
        "guardrail_device": None,
        "defense_guardrail_model": None,
        "defense_guardrail_revision": None,
        "defense_guardrail_device": None,
        "seeds": [0],
        "sample_seed": 0,
        "limit": 2,
        "max_queries": 1,
        "max_turns": 1,
        "call_caps": {
            "target": None,
            "judge": None,
            "http_attempts": None,
            "deadline_seconds": None,
        },
        "group_keys": [
            "model",
            "source",
            "risk",
            "effective_modality",
            "expected_behavior",
            "attacker",
            "source_policy_id",
            "source_policy_version",
        ],
        "quantization": "",
        "dtype": "auto",
        "dry_run": dry_run,
        "selected_config_identities": selected,
        "live_attestation": live_attestation or {
            "mode": "not_required",
            "execution_scope_id": None,
            "max_age_hours": None,
            "artifacts": [],
        },
    }
    condition = {
        "condition_id": "condition-" + canonical_json_sha256(values)[:24],
        "values": values,
    }
    bindings = {
        "driver_source": {"module": "run_matrix.py", "sha256": "2" * 64},
        "project_revision": _project_revision(dry_run=dry_run),
        "source_instances_sha256": "1" * 64,
        "attacker_configs_sha256": "2" * 64,
        "api_configs_sha256": "3" * 64,
        "local_configs_sha256": "4" * 64,
        "selected_config_identities": selected,
        "experiment_conditions": condition,
        "selected_corpora": {},
    }
    return condition, bindings


def _write_plan(
    path: Path,
    *,
    defense: str = "none",
    modalities: tuple[str, ...] = ("text",),
    whole_request_preflight_complete: bool = False,
    dry_run: bool = True,
    live_attestation: dict | None = None,
    corpus_size: int = 2,
) -> dict:
    _condition, bindings = _conditions(
        defense=defense,
        dry_run=dry_run,
        live_attestation=live_attestation,
    )
    plan = build_eligibility_plan(
        requested_targets=["text-target"],
        targets={"text-target": _Target("resolved-text", modalities)},
        corpora={"synth-arm": synth_corpus(corpus_size)},
        attackers=["replay"],
        bindings=bindings,
        dry_run=dry_run,
        whole_request_preflight_complete=whole_request_preflight_complete,
    )
    path.write_text(
        json.dumps(plan, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return plan


def _write_live_attestation(
    path: Path, *, route_kind: str = "hosted_api"
) -> tuple[dict, dict]:
    route_digest = route_config_sha256(
        route_kind=route_kind,
        requested_target_spec="text-target",
        resolved_target="resolved-text",
        route_config=None,
    )
    realized_identity = {
        "target": "resolved-text",
        "provider": "openai",
        "resolved_model": "fixture-model-2026-08-01",
    }
    if route_kind == "local_runtime":
        realized_identity["model_digest"] = "a" * 64
    manifest = build_live_attestation_manifest([{
        "execution_scope_id": "openai-account:test-project",
        "requested_target_spec": "text-target",
        "resolved_target": "resolved-text",
        "route_kind": route_kind,
        "route_config_sha256": route_digest,
        "exact_input_modalities": ["text"],
        "realized_target_identity": realized_identity,
        "observed_at_utc": "2026-08-12T10:00:00Z",
        "probe": {
            "evidence_kind": "synthetic_live_transport_probe",
            "grid_id": "grid-probe",
            "run_id": "run-probe",
            "grid_artifact": {
                "file": "grid-probe.grid.json",
                "sha256": "b" * 64,
                "bytes": 100,
            },
            "completion_artifact": {
                "file": "run-probe.complete.json",
                "sha256": "c" * 64,
                "bytes": 200,
            },
            "realized_identities_sha256": "d" * 64,
            "attempt_media_hashes_sha256": "e" * 64,
            "harness_source_sha256": "1" * 64,
            "driver_source_sha256": "2" * 64,
            "project_revision": _project_revision(dry_run=False),
        },
    }])
    payload = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    artifact = _load_live_attestation_artifact(path, digest)
    projection = {
        "mode": "measured",
        "execution_scope_id": "openai-account:test-project",
        "max_age_hours": 4,
        "artifacts": [dict(artifact["descriptor"])],
    }
    return artifact, projection


def test_planning_only_keeps_structural_na_separate_from_missing(tmp_path: Path) -> None:
    path = tmp_path / "plan.eligibility.json"
    plan = _write_plan(path)
    artifact = _plan_artifact(path)

    report = build_level1_evidence([artifact], {}, [])

    assert report["schema_version"] == "ura-level1-evidence/1"
    counts = report["counts"]["planning_strata"]
    assert counts["requested"] == 2
    assert counts["scientifically_compatible"] == 1
    assert counts["structural_not_applicable"] == 1
    assert counts["execution_eligible"] == 0
    assert counts["attested"] is None
    assert counts["included"] is None
    by_status = {row["planning_status"]: row for row in report["planning_strata"]}
    assert by_status["N/A"]["final_disposition"] == "not_applicable_structural"
    assert by_status["compatible_if_isolated"]["final_disposition"] == (
        "compatible_stratum_blocked_by_sibling"
    )
    assert report["availability"]["live_attestation"]["status"] == "not_supplied"
    assert report["requests"][0]["plan_id"] == plan["plan_id"]


def test_condition_projection_rejects_malformed_types() -> None:
    _condition, bindings = _conditions()
    plan = build_eligibility_plan(
        requested_targets=["text-target"],
        targets={"text-target": _Target("resolved-text", ("text",))},
        corpora={"synth-arm": synth_corpus(1)},
        attackers=["replay"],
        bindings=bindings,
        dry_run=True,
    )
    values = plan["bindings"]["experiment_conditions"]["values"]
    values["judges"] = "rules"
    plan["bindings"]["experiment_conditions"]["condition_id"] = (
        "condition-" + canonical_json_sha256(values)[:24]
    )

    with pytest.raises(ValueError, match="judges"):
        _condition_from_plan(plan)


def test_condition_projection_rejects_project_revision_drift() -> None:
    _condition, bindings = _conditions()
    plan = build_eligibility_plan(
        requested_targets=["text-target"],
        targets={"text-target": _Target("resolved-text", ("text",))},
        corpora={"synth-arm": synth_corpus(1)},
        attackers=["replay"],
        bindings=bindings,
        dry_run=True,
    )
    plan["bindings"]["project_revision"] = {
        **plan["bindings"]["project_revision"],
        "driver_source_sha256": "9" * 64,
    }
    with pytest.raises(ValueError, match="project-revision condition mismatch"):
        _condition_from_plan(plan)

    request = {
        "driver_source": bindings["driver_source"],
        "project_revision": {
            **bindings["project_revision"],
            "driver_source_sha256": "8" * 64,
        },
    }
    with pytest.raises(ValueError, match="project-revision binding mismatch"):
        _validate_grid_plan_bindings(request, {"bindings": bindings})


def test_planning_only_retains_unresolved_target_setup_as_blocked(
    tmp_path: Path,
) -> None:
    _condition, bindings = _conditions()
    plan = build_eligibility_plan(
        requested_targets=["unresolved-target"],
        targets={},
        target_failures={
            "unresolved-target": {
                "gate": "target_construction",
                "reason": "offline fixture setup failure",
            }
        },
        corpora={"synth-arm": synth_corpus(1)},
        attackers=["replay"],
        bindings=bindings,
        dry_run=True,
    )
    path = tmp_path / "blocked.json"
    path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")

    report = build_level1_evidence([_plan_artifact(path)], {}, [])

    assert report["counts"]["execution_units"]["attempted"] == 0
    assert report["counts"]["execution_units"]["missing"] == 0
    assert report["execution_units"][0]["resolved_target"] is None
    assert report["execution_units"][0]["final_disposition"] == "blocked_preflight"


def test_measured_level1_binds_exact_typed_attestation_at_grid_start(
    tmp_path: Path,
) -> None:
    live_artifact, projection = _write_live_attestation(
        tmp_path / "live-attestation.json"
    )
    projection["artifacts"][0]["file"] = (
        "live-attestation-retained-content-addressed.json"
    )
    plan_path = tmp_path / "measured-plan.json"
    plan = _write_plan(
        plan_path,
        dry_run=False,
        live_attestation=projection,
        corpus_size=1,
        whole_request_preflight_complete=True,
    )
    plan_artifact = _plan_artifact(plan_path)
    grid = {
        "grid_id": "grid-measured",
        "grid_status": "complete",
        "started_at": "2026-08-12T12:00:00+00:00",
        "grid_artifact": {
            "locator": "grid-measured.grid.json",
            "sha256": "f" * 64,
            "bytes": 100,
        },
        "request": {
            "dry_run": False,
            "attestation_probe": False,
            "live_attestation": projection,
            "harness_source": {"sha256": "1" * 64},
            "driver_source": {"sha256": "2" * 64},
            "project_revision": _project_revision(dry_run=False),
        },
        "cells": {},
        "n_errors": 0,
    }
    grids = {plan["plan_id"]: grid}
    availability = _bind_live_attestations(
        grids,
        {plan["plan_id"]: plan_artifact},
        [live_artifact],
    )

    report = build_level1_evidence(
        [plan_artifact], grids, [], availability
    )

    row = report["planning_strata"][0]
    unit = report["execution_units"][0]
    assert row["attestation_status"] == "attested"
    assert row["attestation_reference"]["record_id"].startswith(
        "live-attestation-record-"
    )
    assert row["attestation_reference"]["artifact"] == {
        "attestation_id": live_artifact["descriptor"]["attestation_id"],
        "sha256": live_artifact["descriptor"]["sha256"],
        "bytes": live_artifact["descriptor"]["bytes"],
        "supplied_file": "live-attestation.json",
        "retained_grid_file": "live-attestation-retained-content-addressed.json",
    }
    assert unit["attestation_status"] == "attested"
    assert report["counts"]["planning_strata"]["attested"] == 1
    assert report["counts"]["execution_units"]["attested"] == 1
    assert report["availability"]["live_attestation"]["status"] == "validated"
    assert report["scope"]["empirical_validity_established"] is False


def test_level1_attestation_rejects_stale_or_descriptor_substitution(
    tmp_path: Path,
) -> None:
    live_artifact, projection = _write_live_attestation(
        tmp_path / "live-attestation.json"
    )
    plan_path = tmp_path / "measured-plan.json"
    plan = _write_plan(
        plan_path,
        dry_run=False,
        live_attestation=projection,
        corpus_size=1,
        whole_request_preflight_complete=True,
    )
    plan_artifact = _plan_artifact(plan_path)

    def grid(started_at: str, bound: dict = projection) -> dict:
        return {
            "grid_id": "grid-measured",
            "grid_status": "complete",
            "started_at": started_at,
            "grid_artifact": {},
            "request": {
                "dry_run": False,
                "attestation_probe": False,
                "live_attestation": bound,
                "harness_source": {"sha256": "1" * 64},
                "driver_source": {"sha256": "2" * 64},
                "project_revision": _project_revision(dry_run=False),
            },
            "cells": {},
            "n_errors": 0,
        }

    with pytest.raises(ValueError, match="is stale"):
        _bind_live_attestations(
            {plan["plan_id"]: grid("2026-08-12T15:00:01+00:00")},
            {plan["plan_id"]: plan_artifact},
            [live_artifact],
        )

    substituted = json.loads(json.dumps(projection))
    substituted["artifacts"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="was not supplied exactly"):
        _bind_live_attestations(
            {plan["plan_id"]: grid("2026-08-12T12:00:00+00:00", substituted)},
            {plan["plan_id"]: plan_artifact},
            [live_artifact],
        )


def test_level1_attestation_rejects_route_kind_or_mode_flag_substitution(
    tmp_path: Path,
) -> None:
    live_artifact, projection = _write_live_attestation(
        tmp_path / "wrong-route.json", route_kind="local_runtime"
    )
    plan_path = tmp_path / "measured-plan.json"
    plan = _write_plan(
        plan_path,
        dry_run=False,
        live_attestation=projection,
        corpus_size=1,
        whole_request_preflight_complete=True,
    )
    plan_artifact = _plan_artifact(plan_path)
    grid = {
        "grid_id": "grid-measured",
        "grid_status": "complete",
        "started_at": "2026-08-12T12:00:00+00:00",
        "grid_artifact": {},
        "request": {
            "dry_run": False,
            "attestation_probe": False,
            "live_attestation": projection,
            "harness_source": {"sha256": "1" * 64},
            "driver_source": {"sha256": "2" * 64},
            "project_revision": _project_revision(dry_run=False),
        },
        "cells": {},
        "n_errors": 0,
    }
    with pytest.raises(ValueError, match="route kind differs"):
        _bind_live_attestations(
            {plan["plan_id"]: grid},
            {plan["plan_id"]: plan_artifact},
            [live_artifact],
        )

    grid["request"]["attestation_probe"] = None
    with pytest.raises(ValueError, match="boolean attestation_probe"):
        _bind_live_attestations(
            {plan["plan_id"]: grid},
            {plan["plan_id"]: plan_artifact},
            [live_artifact],
        )


def test_plan_only_receipt_is_supplied_but_not_time_evaluated(
    tmp_path: Path,
) -> None:
    live_artifact, projection = _write_live_attestation(
        tmp_path / "live-attestation.json"
    )
    plan_path = tmp_path / "measured-plan.json"
    _write_plan(
        plan_path,
        dry_run=False,
        live_attestation=projection,
        corpus_size=1,
        whole_request_preflight_complete=True,
    )
    out_json = tmp_path / "level1.json"
    out_csv = tmp_path / "level1.csv"

    assert main([
        "--eligibility", str(plan_path),
        "--live-attestation", str(tmp_path / "live-attestation.json"),
        "--live-attestation-sha256", live_artifact["descriptor"]["sha256"],
        "--out-json", str(out_json),
        "--out-csv", str(out_csv),
    ]) == 0

    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["availability"]["live_attestation"]["status"] == (
        "not_evaluated_no_realized_measured_grid"
    )
    assert report["availability"]["live_attestation"]["counts"] is None
    assert report["counts"]["planning_strata"]["attested"] is None
    assert report["planning_strata"][0]["attestation_status"] == "not_evaluated"


def test_completed_synthetic_grid_joins_exact_strata_and_decisions(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run"
    assert run_matrix.main([
        "--dry-run",
        "--corpora", "synth",
        "--limit", "2",
        "--seeds", "0",
        "--attackers", "replay",
        "--judges", "rules,llm",
        "--judge-model", "mock",
        "--max-queries", "1",
        "--max-turns", "1",
        "--max-total-target-calls", "2",
        "--max-total-judge-calls", "2",
        "--max-total-http-attempts", "2",
        "--out", str(root),
    ]) == 0
    artifact = _plan_artifact(next(root.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([root], {artifact[0]["plan_id"]: artifact})

    report = build_level1_evidence([artifact], grids, errors)

    assert report["scope"]["contains_diagnostic_dry_run"] is True
    assert report["scope"]["empirical_validity_established"] is False
    assert report["counts"]["execution_units"]["completed"] == 1
    assert report["counts"]["planning_strata"]["completed"] == 2
    judgments = report["counts"]["judgment_records"]
    assert judgments["completed"] == 2
    assert judgments["decided"] == 2
    assert judgments["abstained"] == 0
    assert report["requests"][0]["grid_artifact"]["sha256"]
    assert report["execution_units"][0]["execution_evidence_artifact"]["sha256"]
    assert all(row["final_disposition"] == "completed" for row in report[
        "planning_strata"
    ])


def test_completed_cell_must_cover_the_exact_planned_datapoint_ids(
    tmp_path: Path,
) -> None:
    root = tmp_path / "run"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(root),
    ]) == 0
    artifact = _plan_artifact(next(root.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([root], {artifact[0]["plan_id"]: artifact})
    cell = next(iter(grids[artifact[0]["plan_id"]]["cells"].values()))
    attempts = cell["validated_cell"]["attempts"]
    next(iter(attempts.values()))["datapoint_id"] = "different-synthetic-id"

    with pytest.raises(ValueError, match="wrong planning-stratum datapoint IDs"):
        build_level1_evidence([artifact], grids, errors)


def test_defended_grid_joins_requested_to_guarded_resolved_target(
    tmp_path: Path,
) -> None:
    root = tmp_path / "guarded"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--defense", "input", "--defense-guard", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(root),
    ]) == 0
    artifact = _plan_artifact(next(root.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([root], {artifact[0]["plan_id"]: artifact})

    report = build_level1_evidence([artifact], grids, errors)

    assert report["counts"]["execution_units"]["completed"] == 1
    assert report["execution_units"][0]["requested_target_spec"] == "mock"
    assert report["execution_units"][0]["resolved_target"] == "mock+guard"


def test_adaptive_setup_and_challenge_join_one_planning_stratum(
    tmp_path: Path,
) -> None:
    root = tmp_path / "crescendo"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "crescendo", "--judges", "rules",
        "--max-queries", "2", "--max-turns", "2", "--out", str(root),
    ]) == 0
    artifact = _plan_artifact(next(root.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([root], {artifact[0]["plan_id"]: artifact})

    report = build_level1_evidence([artifact], grids, errors)

    counts = report["counts"]["judgment_records"]
    assert report["counts"]["planning_strata"]["completed"] == 1
    assert counts["completed"] == 2
    assert counts["decided"] == 1
    assert counts["non_evaluable"] == 1
    assert counts["abstained"] == 0


def test_planning_identity_must_match_between_attempt_and_judgment(
    tmp_path: Path,
) -> None:
    root = tmp_path / "planning-lineage"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(root),
    ]) == 0
    artifact = _plan_artifact(next(root.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([root], {artifact[0]["plan_id"]: artifact})
    cell = next(iter(grids[artifact[0]["plan_id"]]["cells"].values()))
    cell["validated_cell"]["judgments"][0]["raw"][
        "planning_expected_behavior"
    ] = "safe_answer"

    with pytest.raises(ValueError, match="Attempt/Judgment planning identity mismatch"):
        build_level1_evidence([artifact], grids, errors)


def test_partial_grid_error_is_exactly_bound_and_unit_qualified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingMock(MockTarget):
        def generate(self, dialog, *, seed=None):
            raise RuntimeError("synthetic target failure")

    monkeypatch.setattr(
        run_matrix, "build_target", lambda *_args, **_kwargs: FailingMock("failed")
    )
    root = tmp_path / "partial"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "2",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(root),
    ]) == 1
    artifact = _plan_artifact(next(root.glob("eligibility-*.eligibility.json")))
    grids, errors = _load_results([root], {artifact[0]["plan_id"]: artifact})
    report = build_level1_evidence([artifact], grids, errors)

    assert report["counts"]["execution_units"]["attempted"] == 1
    assert report["counts"]["execution_units"]["error"] == 1
    assert all(
        row["execution_unit_started"] is True
        for row in report["planning_strata"]
    )
    assert report["counts"]["planning_strata"]["attempted"] is None
    assert {
        row["final_disposition"] for row in report["planning_strata"]
    } == {"execution_unit_error_after_start_stratum_attempt_unknown"}
    assert report["counts"]["planning_strata"][
        "associated_execution_unit_error"
    ] == 2
    error_path = next(root.glob("*.error.json"))
    error = json.loads(error_path.read_text(encoding="utf-8"))
    error["grid_id"] = "grid-other-condition"
    error_path.write_text(json.dumps(error), encoding="utf-8")
    grid_path = next(root.glob("*.grid.json"))
    grid = json.loads(grid_path.read_text(encoding="utf-8"))
    grid["cells"][0]["error_artifact"] = run_matrix._artifact_descriptor(error_path)
    run_matrix._write_json(grid_path, grid)

    with pytest.raises(ValueError, match="grid/error grid_id identity mismatch"):
        _load_results([root], {artifact[0]["plan_id"]: artifact})


def test_distinct_conditions_have_distinct_lifecycle_rows_and_csv_is_stable(
    tmp_path: Path,
) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    _write_plan(first_path, defense="none")
    _write_plan(second_path, defense="input")
    artifacts = [_plan_artifact(first_path), _plan_artifact(second_path)]

    report = build_level1_evidence(artifacts, {}, [])
    reversed_report = build_level1_evidence(list(reversed(artifacts)), {}, [])
    identities = [row["lifecycle_stratum_id"] for row in report["planning_strata"]]
    assert len(identities) == len(set(identities)) == 4
    first_csv = tmp_path / "first.csv"
    second_csv = tmp_path / "second.csv"
    write_csv(first_csv, report["planning_strata"])
    write_csv(second_csv, reversed_report["planning_strata"])
    assert first_csv.read_bytes() == second_csv.read_bytes()
    assert report["evidence_id"] == reversed_report["evidence_id"]


def test_level1_rejects_mixed_diagnostic_and_measured_requests(
    tmp_path: Path,
) -> None:
    dry_path = tmp_path / "dry.json"
    measured_path = tmp_path / "measured.json"
    _write_plan(dry_path, dry_run=True)
    _write_plan(measured_path, dry_run=False)

    with pytest.raises(ValueError, match="must not mix"):
        build_level1_evidence(
            [_plan_artifact(dry_path), _plan_artifact(measured_path)], {}, []
        )


def test_eligibility_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    _write_plan(plan_path)
    link = tmp_path / "plan-link.json"
    try:
        link.symlink_to(plan_path)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")

    with pytest.raises(ValueError, match="must not be a symlink"):
        _plan_artifact(link)


def test_cli_fails_closed_on_tampered_grid_plan_descriptor(tmp_path: Path) -> None:
    root = tmp_path / "run"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(root),
    ]) == 0
    eligibility = next(root.glob("eligibility-*.eligibility.json"))
    grid_path = next(root.glob("*.grid.json"))
    grid = json.loads(grid_path.read_text(encoding="utf-8"))
    grid["request"]["eligibility_plan"]["sha256"] = "f" * 64
    grid_path.write_text(json.dumps(grid), encoding="utf-8")

    assert main([
        "--eligibility", str(eligibility),
        "--results", str(root),
        "--out-json", str(tmp_path / "out.json"),
        "--out-csv", str(tmp_path / "out.csv"),
    ]) == 1
    assert not (tmp_path / "out.json").exists()
    assert not (tmp_path / "out.csv").exists()


def test_cli_writes_zero_human_synthetic_json_and_csv(tmp_path: Path) -> None:
    root = tmp_path / "run"
    assert run_matrix.main([
        "--dry-run", "--corpora", "synth", "--limit", "1",
        "--seeds", "0", "--attackers", "replay", "--judges", "rules",
        "--max-queries", "1", "--max-turns", "1", "--out", str(root),
    ]) == 0
    eligibility = next(root.glob("eligibility-*.eligibility.json"))
    out_json = tmp_path / "level1.json"
    out_csv = tmp_path / "level1.csv"

    assert main([
        "--eligibility", str(eligibility),
        "--results", str(root),
        "--out-json", str(out_json),
        "--out-csv", str(out_csv),
    ]) == 0
    report = json.loads(out_json.read_text(encoding="utf-8"))
    assert report["scope"]["evidence_kind"] == "diagnostic_dry_run"
    assert report["scope"]["empirical_validity_established"] is False
    assert report["availability"]["live_attestation"]["status"] == "not_supplied"
    assert report["availability"]["analysis_inclusion"]["status"] == "not_supplied"
    assert out_csv.read_text(encoding="utf-8").splitlines()[0].startswith(
        "lifecycle_stratum_id,"
    )


def test_decision_state_keeps_common_source_metric_and_setup_units_distinct() -> None:
    assert _decision_state({
        "label": "violation",
        "raw": {
            "policy_evaluable_turn": True,
            "common_metrics_eligible": True,
            "cascade_confident": True,
            "parsed": True,
        },
    }) == "decided"
    assert _decision_state({
        "label": "not_applicable",
        "raw": {
            "policy_evaluable_turn": True,
            "common_metrics_eligible": False,
            "source_evaluation": {"valid": True},
        },
    }) == "decided"
    assert _decision_state({
        "label": "not_applicable",
        "raw": {"policy_evaluable_turn": False},
    }) == "non_evaluable"
