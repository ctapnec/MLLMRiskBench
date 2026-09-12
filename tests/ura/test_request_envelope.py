from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments import run_matrix
from ura.eligibility import canonical_json_sha256
from ura.project_revision import diagnostic_project_revision_binding
from ura.request_envelope import (
    REQUEST_ENVELOPE_SCHEMA,
    REQUEST_ERROR_SCHEMA,
    build_request_envelope,
    build_request_error,
    load_request_envelope_file,
    load_request_error_file,
    request_envelope_bytes,
    request_envelope_descriptor,
    request_envelope_id,
    request_error_id,
    validate_request_envelope,
    validate_request_error,
    write_request_envelope,
    write_request_error,
)
from ura.sampling import (
    DEFAULT_SAMPLING_POLICY,
    SOURCE_ORDER_CLUSTER_PREFIX,
)


def _source_bindings() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    harness = {
        "algorithm": "sha256_relative_path_size_file_digest_v1",
        "sha256": "a" * 64,
        "file_count": 2,
        "bytes": 100,
    }
    driver = {
        "module": "run_matrix.py",
        "sha256": "b" * 64,
        "file_count": 1,
    }
    project = diagnostic_project_revision_binding(
        str(harness["sha256"]), str(driver["sha256"])
    )
    return project, harness, driver


def _request() -> dict[str, object]:
    return {
        "execution_purpose": "diagnostic_dry_run",
        "requested_target_keys": ["target-a", "target-b"],
        "logical_source_arms": ["source-b", "source-a"],
        "selected_attackers": ["replay", "crescendo"],
        "judges": ["rules"],
        "judge_model": None,
        "seeds": [0, 1],
        "sample_seed": 7,
        "limit": 3,
        "max_queries": 2,
        "max_turns": 2,
        "target_answer_retries": 1,
        "defense": "none",
        "defense_guard": "rules",
        "group_keys": ["model", "source"],
        "quantization": "",
        "dtype": "auto",
        "dry_run": True,
        "approximate_common_metrics": False,
        "hosted_judge_data_transfer_acknowledged": False,
        "call_caps": {
            "target": None,
            "judge": None,
            "http_attempts": None,
            "deadline_seconds": None,
        },
    }


def _envelope() -> dict[str, object]:
    project, harness, driver = _source_bindings()
    return build_request_envelope(
        request=_request(),
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )


def _refresh_envelope_id(value: dict[str, object]) -> None:
    body = {key: item for key, item in value.items() if key != "envelope_id"}
    value["envelope_id"] = request_envelope_id(body)


def _refresh_error_id(value: dict[str, object]) -> None:
    body = {key: item for key, item in value.items() if key != "error_id"}
    value["error_id"] = request_error_id(body)


def test_envelope_fixes_only_exact_requested_whole_arm_cross_product() -> None:
    envelope = _envelope()

    assert envelope["schema"] == REQUEST_ENVELOPE_SCHEMA
    units = envelope["execution_units"]
    assert len(units) == 8
    assert {
        (
            unit["requested_target_key"],
            unit["logical_source_arm"],
            unit["attacker"],
        )
        for unit in units
    } == {
        (target, arm, attacker)
        for target in ("target-a", "target-b")
        for arm in ("source-a", "source-b")
        for attacker in ("replay", "crescendo")
    }
    serialized = json.dumps(envelope, sort_keys=True)
    for forbidden in (
        "exact_modality_combination",
        "source_policy",
        "metric_mode",
        "selected_datapoint",
    ):
        assert forbidden not in serialized
    assert envelope["limitations"]["source_strata_materialized"] is False
    assert envelope["limitations"]["compatibility_evaluated"] is False
    assert envelope["request"]["target_answer_retries"] == 1
    assert envelope["request"]["recovery_selection"] is None


def test_envelope_defaults_retry_once_and_rejects_out_of_range_values() -> None:
    project, harness, driver = _source_bindings()
    request = _request()
    del request["target_answer_retries"]

    envelope = build_request_envelope(
        request=request,
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )
    assert envelope["request"]["target_answer_retries"] == 1

    for invalid in (-1, 11, True):
        with pytest.raises(ValueError, match="target_answer_retries"):
            build_request_envelope(
                request={**_request(), "target_answer_retries": invalid},
                project_revision=project,
                harness_source=harness,
                driver_source=driver,
            )


def test_recovery_selection_is_bound_and_requires_its_one_source_arm() -> None:
    project, harness, driver = _source_bindings()
    recovery = {
        "schema": "ura-recovery-completed-prefix/1",
        "sha256": "c" * 64,
        "bytes": 321,
        "corpus": "airbench_full",
        "completed_prefix_count": 1039,
        "selected_datapoint_ids_sha256": "d" * 64,
        "completed_prefix_ids_sha256": "e" * 64,
        "remaining_datapoint_ids_sha256": "f" * 64,
    }
    request = {
        **_request(),
        "logical_source_arms": ["airbench_full"],
        "recovery_selection": recovery,
    }

    envelope = build_request_envelope(
        request=request,
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )

    assert envelope["request"]["recovery_selection"] == recovery
    with pytest.raises(ValueError, match="one logical source arm"):
        build_request_envelope(
            request={**request, "logical_source_arms": ["airbench_full", "xstest_full"]},
            project_revision=project,
            harness_source=harness,
            driver_source=driver,
        )


def test_v6_multi_arm_recovery_keeps_required_retry_policy() -> None:
    project, harness, driver = _source_bindings()
    entry = {
        "completed_prefix_count": 50,
        "selected_datapoint_ids_sha256": "d" * 64,
        "completed_prefix_ids_sha256": "e" * 64,
        "remaining_datapoint_ids_sha256": "f" * 64,
    }
    recovery = {
        "schema": "ura-recovery-completed-prefix/2",
        "sha256": "c" * 64,
        "bytes": 654,
        "corpora": {
            "airbench_full": dict(entry),
            "xstest_full": dict(entry),
        },
    }
    request = {
        **_request(),
        "requested_target_keys": ["ollama:model"],
        "logical_source_arms": ["airbench_full", "xstest_full"],
        "selected_attackers": ["replay"],
        "recovery_selection": recovery,
    }

    envelope = build_request_envelope(
        request=request,
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )

    assert envelope["schema"] == "ura-request-envelope/6"
    assert envelope["request"]["target_answer_retries"] == 1
    assert envelope["request"]["recovery_selection"] == recovery

    missing_retry = copy.deepcopy(envelope)
    del missing_retry["request"]["target_answer_retries"]
    _refresh_envelope_id(missing_retry)
    with pytest.raises(ValueError, match="invalid field inventory"):
        validate_request_envelope(missing_retry)

    retained_v5 = copy.deepcopy(envelope)
    retained_v5["schema"] = "ura-request-envelope/5"
    _refresh_envelope_id(retained_v5)
    assert validate_request_envelope(retained_v5)["schema"] == (
        "ura-request-envelope/5"
    )

    retained_v4 = copy.deepcopy(envelope)
    retained_v4["schema"] = "ura-request-envelope/4"
    _refresh_envelope_id(retained_v4)
    with pytest.raises(ValueError, match="schema is unsupported"):
        validate_request_envelope(retained_v4)


def test_v6_binds_noncontiguous_completed_selection_and_v5_rejects_it() -> None:
    project, harness, driver = _source_bindings()
    completed = ["row-1", "row-3"]
    recovery = {
        "schema": "ura-recovery-completed-selection/1",
        "sha256": "c" * 64,
        "bytes": 654,
        "corpora": {
            "airbench_full": {
                "completed_record_count": len(completed),
                "selected_datapoint_ids_sha256": "d" * 64,
                "completed_datapoint_ids": completed,
                "completed_datapoint_ids_sha256": canonical_json_sha256(completed),
                "remaining_datapoint_ids_sha256": "f" * 64,
            }
        },
    }
    envelope = build_request_envelope(
        request={
            **_request(),
            "logical_source_arms": ["airbench_full"],
            "recovery_selection": recovery,
        },
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )

    assert envelope["schema"] == "ura-request-envelope/6"
    assert envelope["request"]["target_answer_retries"] == 1
    assert envelope["request"]["recovery_selection"] == recovery

    retained_v5 = copy.deepcopy(envelope)
    retained_v5["schema"] = "ura-request-envelope/5"
    _refresh_envelope_id(retained_v5)
    with pytest.raises(ValueError, match="schema is unsupported"):
        validate_request_envelope(retained_v5)


def test_recovery_completed_prefix_keeps_only_exact_unfinished_suffix(
    tmp_path: Path,
) -> None:
    corpus = run_matrix.synth_corpus(5)
    selected_ids = [row.id for row in corpus]

    def digest(value: object) -> str:
        return hashlib.sha256(json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")).hexdigest()

    value = {
        "schema": "ura-recovery-completed-prefix/1",
        "corpus": "synth",
        "completed_prefix_count": 3,
        "selected_datapoint_ids_sha256": digest(selected_ids),
        "completed_prefix_ids_sha256": digest(selected_ids[:3]),
        "remaining_datapoint_ids_sha256": digest(selected_ids[3:]),
    }
    path = tmp_path / "recovery-prefix.json"
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(raw, encoding="utf-8")
    loaded, binding = run_matrix.load_recovery_completed_prefix(
        str(path), hashlib.sha256(raw.encode("utf-8")).hexdigest()
    )
    audit = {
        "selected_indices": list(range(5)),
        "selected_ids": selected_ids,
        "selected_records": 5,
        "selected_cluster_ids": selected_ids,
        "selected_clusters": 5,
        "selected_converted_corpus_sha256": "historical",
    }

    remaining, recovered_audit = run_matrix.apply_recovery_completed_prefix(
        "synth", corpus, audit, loaded
    )

    assert [row.id for row in remaining] == selected_ids[3:]
    assert recovered_audit["selected_indices"] == [3, 4]
    assert recovered_audit["selected_records"] == 2
    assert recovered_audit["pre_recovery_converted_corpus_sha256"] == "historical"
    assert recovered_audit["selection_method"] == (
        "content_bound_never_completed_suffix_v1"
    )
    assert binding == {
        **value,
        "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "bytes": len(raw.encode("utf-8")),
    }

    changed = list(corpus)
    changed[3], changed[4] = changed[4], changed[3]
    with pytest.raises(ValueError, match="selected datapoint identity changed"):
        run_matrix.apply_recovery_completed_prefix("synth", changed, audit, loaded)


def test_multi_corpus_recovery_keeps_each_exact_unfinished_suffix(
    tmp_path: Path,
) -> None:
    corpus = run_matrix.synth_corpus(5)
    selected_ids = [row.id for row in corpus]

    def digest(value: object) -> str:
        return hashlib.sha256(json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")).hexdigest()

    entry = {
        "completed_prefix_count": 3,
        "selected_datapoint_ids_sha256": digest(selected_ids),
        "completed_prefix_ids_sha256": digest(selected_ids[:3]),
        "remaining_datapoint_ids_sha256": digest(selected_ids[3:]),
    }
    value = {
        "schema": "ura-recovery-completed-prefix/2",
        "corpora": {"source-a": dict(entry), "source-b": dict(entry)},
    }
    path = tmp_path / "recovery-prefixes.json"
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(raw, encoding="utf-8")
    loaded, binding = run_matrix.load_recovery_completed_prefix(
        str(path), hashlib.sha256(raw.encode("utf-8")).hexdigest()
    )
    audit = {
        "selected_indices": list(range(5)),
        "selected_ids": selected_ids,
        "selected_records": 5,
        "selected_cluster_ids": selected_ids,
        "selected_clusters": 5,
        "selected_converted_corpus_sha256": "historical",
    }

    for name in ("source-a", "source-b"):
        remaining, recovered_audit = run_matrix.apply_recovery_completed_prefix(
            name, corpus, audit, loaded
        )
        assert [row.id for row in remaining] == selected_ids[3:]
        assert recovered_audit["pre_recovery_converted_corpus_sha256"] == "historical"
        assert recovered_audit["recovery_completed_prefix"] == {
            "schema": "ura-recovery-completed-prefix/2",
            "corpus": name,
            **entry,
        }
    assert binding == {
        "schema": "ura-recovery-completed-prefix/2",
        "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "bytes": len(raw.encode("utf-8")),
        "corpora": value["corpora"],
    }

    changed = copy.deepcopy(loaded)
    changed["corpora"]["source-b"]["completed_prefix_ids_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="completed-prefix identity changed"):
        run_matrix.apply_recovery_completed_prefix(
            "source-b", corpus, audit, changed
        )


def test_completed_selection_keeps_only_noncontiguous_unfinished_rows(
    tmp_path: Path,
) -> None:
    corpus = run_matrix.synth_corpus(5)
    selected_ids = [row.id for row in corpus]

    def digest(value: object) -> str:
        return hashlib.sha256(json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")).hexdigest()

    completed_ids = [selected_ids[1], selected_ids[3]]
    remaining_ids = [selected_ids[0], selected_ids[2], selected_ids[4]]
    entry = {
        "completed_record_count": 2,
        "selected_datapoint_ids_sha256": digest(selected_ids),
        "completed_datapoint_ids": completed_ids,
        "completed_datapoint_ids_sha256": digest(completed_ids),
        "remaining_datapoint_ids_sha256": digest(remaining_ids),
    }
    value = {
        "schema": "ura-recovery-completed-selection/1",
        "corpora": {"synth": entry},
    }
    path = tmp_path / "recovery-selection.json"
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    path.write_text(raw, encoding="utf-8")
    loaded, binding = run_matrix.load_recovery_completed_prefix(
        str(path), hashlib.sha256(raw.encode("utf-8")).hexdigest()
    )
    audit = {
        "selected_indices": list(range(5)),
        "selected_ids": selected_ids,
        "selected_records": 5,
        "selected_cluster_ids": selected_ids,
        "selected_clusters": 5,
        "selected_converted_corpus_sha256": "historical",
    }

    remaining, recovered_audit = run_matrix.apply_recovery_completed_prefix(
        "synth", corpus, audit, loaded
    )

    assert [row.id for row in remaining] == remaining_ids
    assert recovered_audit["selected_indices"] == [0, 2, 4]
    assert recovered_audit["selected_records"] == 3
    assert recovered_audit["pre_recovery_converted_corpus_sha256"] == "historical"
    assert recovered_audit["selection_method"] == (
        "content_bound_never_completed_selection_v1"
    )
    assert recovered_audit["recovery_completed_selection"] == {
        "schema": "ura-recovery-completed-selection/1",
        "corpus": "synth",
        **entry,
    }
    assert binding == {
        "schema": "ura-recovery-completed-selection/1",
        "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "bytes": len(raw.encode("utf-8")),
        "corpora": value["corpora"],
    }

    changed = copy.deepcopy(loaded)
    changed["corpora"]["synth"]["completed_datapoint_ids"][0] = "unknown"
    with pytest.raises(ValueError, match="exact unfinished set"):
        run_matrix.apply_recovery_completed_prefix(
            "synth", corpus, audit, changed
        )


def test_request_envelope_rejects_unbound_row_exclusion_switch() -> None:
    project, harness, driver = _source_bindings()
    request = {**_request(), "exclude_tool_conditioned": True}

    with pytest.raises(ValueError, match="invalid field inventory"):
        build_request_envelope(
            request=request,
            project_revision=project,
            harness_source=harness,
            driver_source=driver,
        )


def test_explicit_sampling_policy_is_validated_and_changes_request_identity() -> None:
    project, harness, driver = _source_bindings()
    legacy = _envelope()
    seeded = build_request_envelope(
        request={**_request(), "sampling_policy": DEFAULT_SAMPLING_POLICY},
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )
    source_order = build_request_envelope(
        request={**_request(), "sampling_policy": SOURCE_ORDER_CLUSTER_PREFIX},
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )

    assert "sampling_policy" not in legacy["request"]
    assert len({
        legacy["envelope_id"], seeded["envelope_id"], source_order["envelope_id"]
    }) == 3
    # run_matrix binds this exact byte digest into model-acquisition selection.
    assert len({
        hashlib.sha256(request_envelope_bytes(item)).hexdigest()
        for item in (legacy, seeded, source_order)
    }) == 3
    with pytest.raises(ValueError, match="sampling policy is unsupported"):
        build_request_envelope(
            request={**_request(), "sampling_policy": "ignored-policy-mutant"},
            project_revision=project,
            harness_source=harness,
            driver_source=driver,
        )


def test_envelope_loader_is_canonical_strict_and_content_addressed(
    tmp_path: Path,
) -> None:
    envelope = _envelope()
    path = write_request_envelope(tmp_path, envelope)

    loaded, descriptor = load_request_envelope_file(path)

    assert loaded == envelope
    assert descriptor == request_envelope_descriptor(path, envelope)
    assert path.name == f"{envelope['envelope_id']}.request-envelope.json"

    tampered = copy.deepcopy(envelope)
    tampered["request"]["limit"] = 4
    path.write_text(json.dumps(tampered, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ID/content mismatch"):
        load_request_envelope_file(path)

    path.write_bytes(request_envelope_bytes(envelope))
    raw = path.read_text(encoding="utf-8")
    path.write_text(
        raw.replace(
            "{\n  \"bindings\"",
            "{\n  \"schema\": \"ura-request-envelope/1\",\n  \"bindings\"",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_request_envelope_file(path)


def test_legacy_v1_envelope_remains_readable_without_relabeling() -> None:
    envelope = copy.deepcopy(_envelope())
    envelope["schema"] = "ura-request-envelope/1"
    del envelope["request"]["approximate_common_metrics"]
    del envelope["request"]["hosted_judge_data_transfer_acknowledged"]
    del envelope["request"]["target_answer_retries"]
    del envelope["request"]["recovery_selection"]
    _refresh_envelope_id(envelope)

    validated = validate_request_envelope(envelope)

    assert validated == envelope
    assert validated["schema"] == "ura-request-envelope/1"
    assert "approximate_common_metrics" not in validated["request"]


def test_legacy_v2_envelope_remains_readable_without_retry_relabeling() -> None:
    envelope = copy.deepcopy(_envelope())
    envelope["schema"] = "ura-request-envelope/2"
    del envelope["request"]["target_answer_retries"]
    del envelope["request"]["recovery_selection"]
    _refresh_envelope_id(envelope)

    validated = validate_request_envelope(envelope)

    assert validated == envelope
    assert validated["schema"] == "ura-request-envelope/2"
    assert "target_answer_retries" not in validated["request"]


def test_legacy_v3_envelope_remains_readable_without_recovery_relabeling() -> None:
    envelope = copy.deepcopy(_envelope())
    envelope["schema"] = "ura-request-envelope/3"
    del envelope["request"]["recovery_selection"]
    _refresh_envelope_id(envelope)

    validated = validate_request_envelope(envelope)

    assert validated == envelope
    assert validated["schema"] == "ura-request-envelope/3"
    assert validated["request"]["target_answer_retries"] == 1


def test_legacy_v4_envelope_keeps_single_arm_recovery_and_retry() -> None:
    project, harness, driver = _source_bindings()
    request = {
        **_request(),
        "logical_source_arms": ["airbench_full"],
        "recovery_selection": {
            "schema": "ura-recovery-completed-prefix/1",
            "sha256": "c" * 64,
            "bytes": 321,
            "corpus": "airbench_full",
            "completed_prefix_count": 1039,
            "selected_datapoint_ids_sha256": "d" * 64,
            "completed_prefix_ids_sha256": "e" * 64,
            "remaining_datapoint_ids_sha256": "f" * 64,
        },
    }
    envelope = build_request_envelope(
        request=request,
        project_revision=project,
        harness_source=harness,
        driver_source=driver,
    )
    envelope["schema"] = "ura-request-envelope/4"
    _refresh_envelope_id(envelope)

    validated = validate_request_envelope(envelope)

    assert validated == envelope
    assert validated["request"]["target_answer_retries"] == 1


def test_envelope_rejects_missing_units_and_source_binding_substitution() -> None:
    envelope = copy.deepcopy(_envelope())
    envelope["execution_units"].pop()
    _refresh_envelope_id(envelope)
    with pytest.raises(ValueError, match="omits a requested whole-arm"):
        validate_request_envelope(envelope)

    envelope = copy.deepcopy(_envelope())
    envelope["bindings"]["driver_source"]["sha256"] = "c" * 64
    _refresh_envelope_id(envelope)
    with pytest.raises(ValueError, match="project/driver source mismatch"):
        validate_request_envelope(envelope)


def test_bound_request_error_is_strict_scoped_and_never_claims_strata_or_calls(
    tmp_path: Path,
) -> None:
    envelope = _envelope()
    envelope_path = write_request_envelope(tmp_path, envelope)
    descriptor = request_envelope_descriptor(envelope_path, envelope)
    error = build_request_error(
        envelope=envelope,
        envelope_descriptor=descriptor,
        phase="corpus_preflight",
        category="conversion_failed",
        exception_type="ValueError",
        message=" converter\nfailed ",
        logical_source_arm="source-a",
    )
    path = write_request_error(tmp_path, error)

    assert error["schema"] == REQUEST_ERROR_SCHEMA
    assert error["scope"] == {
        "level": "logical_source_arm",
        "requested_target_key": None,
        "logical_source_arm": "source-a",
        "attacker": None,
    }
    assert error["failure"]["message"] == "converter failed"
    assert error["execution"] == {
        "execution_started": False,
        "provider_calls_started": False,
    }
    assert error["limitations"]["planning_strata_attributed"] is False
    assert load_request_error_file(path, envelope=envelope) == error

    tampered = copy.deepcopy(error)
    tampered["scope"]["logical_source_arm"] = "not-requested"
    _refresh_error_id(tampered)
    with pytest.raises(ValueError, match="outside the requested universe"):
        validate_request_error(tampered, envelope=envelope)


def test_run_matrix_persists_envelope_and_bound_config_error_before_conversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    conversions = 0

    def forbidden_conversion(*_args, **_kwargs):
        nonlocal conversions
        conversions += 1
        raise AssertionError("conversion must not start")

    monkeypatch.setattr(run_matrix, "load_corpus_with_audit", forbidden_conversion)
    out = tmp_path / "early"
    private = tmp_path / "private-config" / "missing.json"

    assert run_matrix.main([
        "--dry-run", "--attackers", "replay", "--attacker-config", str(private),
        "--judges", "rules", "--corpora", "synth", "--limit", "1",
        "--max-queries", "1", "--max-turns", "1", "--out", str(out),
    ]) == 1
    assert conversions == 0
    envelope_path = next(out.glob("*.request-envelope.json"))
    envelope, descriptor = load_request_envelope_file(envelope_path)
    error_path = next(out.glob("*.request.error.json"))
    error = load_request_error_file(error_path, envelope=envelope)
    assert error["request_envelope"] == descriptor
    assert error["failure"]["phase"] == "configuration_preflight"
    assert error["failure"]["category"] == "configuration_invalid"
    assert error["scope"]["level"] == "whole_request"
    assert str(tmp_path) not in json.dumps(error)
    assert not list(out.glob("*.eligibility.json"))
    assert not list(out.glob("*.grid.json"))


def test_run_matrix_binds_descriptor_everywhere_and_clears_resolved_early_error(
    tmp_path: Path,
) -> None:
    out = tmp_path / "retry"
    missing = tmp_path / "missing.json"
    common = [
        "--dry-run", "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--max-queries", "1",
        "--max-turns", "1", "--out", str(out),
    ]
    assert run_matrix.main([
        *common, "--attacker-config", str(missing),
    ]) == 1
    assert list(out.glob("*.request.error.json"))

    assert run_matrix.main(common) == 0
    assert not list(out.glob("*.request.error.json"))
    envelope_path = next(out.glob("*.request-envelope.json"))
    envelope, descriptor = load_request_envelope_file(envelope_path)
    assert envelope["request"]["dry_run"] is True
    plan = json.loads(next(out.glob("*.eligibility.json")).read_text(encoding="utf-8"))
    grid = json.loads(next(out.glob("*.grid.json")).read_text(encoding="utf-8"))
    manifest = json.loads(next(out.glob("*.manifest.json")).read_text(encoding="utf-8"))
    assert plan["bindings"]["request_envelope"] == descriptor
    assert grid["request"]["request_envelope"] == descriptor
    assert manifest["config"]["run"]["request_envelope"] == descriptor
    assert plan["request"]["requested_target_specs"] == envelope["request"][
        "requested_target_keys"
    ]


def test_run_matrix_new_error_supersedes_same_envelope_error(tmp_path: Path) -> None:
    out = tmp_path / "retry-errors"
    common = [
        "--dry-run", "--attackers", "replay", "--judges", "rules",
        "--corpora", "synth", "--limit", "1", "--max-queries", "1",
        "--max-turns", "1", "--out", str(out),
    ]

    first_missing = tmp_path / "first-missing.json"
    assert run_matrix.main([
        *common, "--attacker-config", str(first_missing),
    ]) == 1
    first_path = next(out.glob("*.request.error.json"))
    first_error_id = first_path.name

    second_missing = tmp_path / "second-missing.json"
    assert run_matrix.main([
        *common, "--attacker-config", str(second_missing),
    ]) == 1

    error_paths = list(out.glob("*.request.error.json"))
    assert len(error_paths) == 1
    assert error_paths[0].name != first_error_id
    envelope, _descriptor = load_request_envelope_file(
        next(out.glob("*.request-envelope.json"))
    )
    error = load_request_error_file(error_paths[0], envelope=envelope)
    assert "second-missing.json" in error["failure"]["message"]
    assert "first-missing.json" not in error["failure"]["message"]


def test_scrubber_removes_ancestor_directories_of_configured_inputs() -> None:
    # Platform-independent regression for the Linux-observed leak: the OS
    # error may name a missing PARENT directory of the configured input, not
    # the configured file itself; both must be scrubbed from retained errors.
    from experiments.run_matrix import _scrub_operator_paths

    configured = "/tmp/pytest-of-ura/pytest-0/case0/private-config/missing.json"
    parent_message = (
        "[Errno 2] No such file or directory: "
        "'/tmp/pytest-of-ura/pytest-0/case0/private-config'"
    )
    scrubbed = _scrub_operator_paths(parent_message, [configured])
    assert "/tmp/pytest-of-ura" not in scrubbed
    assert "<operator-input-dir:private-config>" in scrubbed

    exact_message = f"cannot read {configured}"
    scrubbed = _scrub_operator_paths(exact_message, [configured])
    assert configured not in scrubbed
    assert "<operator-input:missing.json>" in scrubbed

    # Windows-style separators scrub the same way.
    win = r"C:\Users\op\data\registry.json"
    scrubbed = _scrub_operator_paths(r"missing dir C:\Users\op\data", [win])
    assert r"C:\Users\op\data" not in scrubbed
    # A filesystem root is never scrubbed away.
    assert _scrub_operator_paths("error at /", ["/x"]) == "error at /"
