from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import textwrap
from types import SimpleNamespace
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
TEMPLATES = ROOT / "experiments" / "local_campaign" / "templates"


def _python_payload(name: str) -> str:
    text = (TEMPLATES / name).read_text(encoding="utf-8")
    marker = "<<'PY'\n"
    assert text.count(marker) == 1
    payload = text.split(marker, 1)[1]
    assert payload.endswith("\nPY\n")
    return payload[: -len("\nPY\n")]


def _prelude(name: str, stop: str) -> dict[str, Any]:
    payload = _python_payload(name)
    assert payload.count(stop) == 1
    namespace: dict[str, Any] = {}
    exec(compile(payload.split(stop, 1)[0], name, "exec"), namespace)  # noqa: S102
    return namespace


def _phase7_method(name: str, namespace: dict[str, Any]) -> Any:
    text = (TEMPLATES / "phase7_analysis.py.in").read_text(encoding="utf-8")
    start = text.index(f"    def {name}(")
    next_method = text.find("\n    def ", start + 8)
    source = textwrap.dedent(text[start:] if next_method < 0 else text[start:next_method])
    exec(compile(source, f"phase7:{name}", "exec"), namespace)  # noqa: S102
    return namespace[name]


def _phase8_function(name: str, namespace: dict[str, Any]) -> Any:
    text = (TEMPLATES / "phase8_human_audit.py.in").read_text(encoding="utf-8")
    start = text.index(f"def {name}(")
    next_function = text.find("\ndef ", start + 4)
    source = text[start:] if next_function < 0 else text[start:next_function]
    exec(compile(source, f"phase8:{name}", "exec"), namespace)  # noqa: S102
    return namespace[name]


def _exact_argv(namespace: dict[str, Any], lane: str) -> list[str]:
    spec = namespace["LANES"][lane]
    values = {option: "fixture" for option in namespace["PAIR_OPTIONS"]}
    values.update(
        {
            "--local": namespace["QWEN"],
            "--attackers": spec["attacker"],
            "--judges": "rules,guardrail",
            "--guardrail-model": namespace["GUARD"],
            "--guardrail-revision": namespace["GUARD_REVISION"],
            "--guardrail-device": "cuda:1",
            "--corpora": spec["corpus"],
            "--limit": str(spec["limit"]),
            "--sample-seed": str(spec["sample_seed"]),
            "--seeds": "0",
            "--max-queries": str(spec["max_queries"]),
            "--max-turns": str(spec["max_turns"]),
            "--group": namespace["GROUP"],
            "--max-total-target-calls": str(spec["target_calls"]),
            "--max-total-judge-calls": "0",
            "--max-total-http-attempts": "0",
            "--deadline-seconds": str(namespace["DEADLINE_SECONDS"]),
            "--live-attestation-max-age-hours": "24",
        }
    )
    argv = [item for option in sorted(values) for item in (option, values[option])]
    return [*argv, "--approximate-common-metrics"]


def _replace_option(argv: list[str], option: str, value: str) -> list[str]:
    mutated = list(argv)
    mutated[mutated.index(option) + 1] = value
    return mutated


def test_followon_payloads_compile_and_ideator_cap_is_eight() -> None:
    for name in (
        "phase5_followon_prepared.sh.in",
        "phase6_followon_prepared.sh.in",
    ):
        compile(_python_payload(name), name, "exec")
    phase5 = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    assert tuple(phase5["LANES"]) == phase5["LANE_ORDER"]
    ideator = phase5["LANES"]["followon-ideator-v2-qwen3-vl"]
    assert (ideator["limit"], ideator["max_queries"], ideator["target_calls"]) == (
        1,
        8,
        8,
    )
    assert ideator["preparations"] == {"attacker_config", "seed_pair_manifest"}


@pytest.mark.parametrize(
    ("option", "bad_value"),
    (
        ("--local", "api:hosted-model"),
        ("--attackers", "replay"),
        ("--corpora", "strongreject_official"),
        ("--limit", "2"),
        ("--max-queries", "1"),
        ("--max-turns", "1"),
        ("--judges", "rules"),
        ("--max-total-target-calls", "1"),
        ("--max-total-judge-calls", "1"),
        ("--max-total-http-attempts", "1"),
        ("--deadline-seconds", "1"),
    ),
)
def test_phase5_argument_policy_rejects_reverse_mutations(
    option: str, bad_value: str
) -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    lane = "followon-ideator-v2-qwen3-vl"
    spec = namespace["LANES"][lane]
    argv = _exact_argv(namespace, lane)
    namespace["validate_argv_policy"](argv, spec, lane)
    with pytest.raises(SystemExit):
        namespace["validate_argv_policy"](
            _replace_option(argv, option, bad_value), spec, lane
        )


def test_phase5_rejects_missing_approximation_and_hosted_option() -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    lane = "followon-nanogcg-qwen3-vl"
    spec = namespace["LANES"][lane]
    argv = _exact_argv(namespace, lane)
    with pytest.raises(SystemExit):
        namespace["validate_argv_policy"](
            [item for item in argv if item != "--approximate-common-metrics"], spec, lane
        )
    with pytest.raises(SystemExit):
        namespace["validate_argv_policy"]([*argv, "--api", "hosted"], spec, lane)


def test_phase5_measured_root_requires_existing_canonical_parent_and_absent_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    lane = "followon-nanogcg-qwen3-vl"
    work = tmp_path / "work"
    parent = work / "runs" / "thesis" / "runner" / lane
    parent.mkdir(parents=True)
    monkeypatch.setenv("URA_WORK", str(work))
    output = parent / "fresh-measured-root"
    namespace["validate_result_root"](output, lane)
    output.mkdir()
    with pytest.raises(SystemExit):
        namespace["validate_result_root"](output, lane)
    with pytest.raises(SystemExit):
        namespace["validate_result_root"](
            work / "runs" / "thesis" / "runner" / "missing-lane" / "fresh",
            "missing-lane",
        )


def test_phase5_nanogcg_reuses_strict_capture_and_binds_exact_config(
    tmp_path: Path,
) -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    lane = "followon-nanogcg-qwen3-vl"
    spec = namespace["LANES"][lane]
    descriptors = {
        "config": {"path": str(tmp_path / "config.json"), "sha256": "b" * 64, "bytes": 10},
        "capture": {"path": str(tmp_path / "capture.json"), "sha256": "c" * 64, "bytes": 20},
    }
    capture = {
        "result": {"best_string": "sealed suffix"},
        "source": {"source_row": {
            "datapoint_id": "advbench:245", "target": "target continuation"
        }},
    }
    expected_config = {
        "suffix": "sealed suffix", "suffix_source": "capture",
    }
    calls: list[str] = []

    def fake_checked(raw: object, label: str) -> tuple[Path, dict[str, Any]]:
        assert isinstance(raw, dict)
        return Path(str(raw["path"])), capture if "capture" in label else {"nanogcg": expected_config}

    namespace["checked"] = fake_checked
    namespace["load_runner_attacker_config"] = lambda *_, **__: (
        tmp_path / "config.json", dict(expected_config), "d" * 64
    )
    namespace["nanogcg_capture"] = SimpleNamespace(
        validate_capture=lambda value: calls.append("capture") or value,
        _replay_config=lambda *_, **__: {"nanogcg": dict(expected_config)},
    )
    validated = namespace["validate_preparations"](
        {"attacker_config": descriptors["config"], "capture": descriptors["capture"]},
        spec,
        lane,
    )
    assert calls == ["capture"]
    assert validated["config_sha256"] == {"canary": "d" * 64, "measured": "d" * 64}

    namespace["load_runner_attacker_config"] = lambda *_, **__: (
        tmp_path / "config.json", {**expected_config, "suffix": "mutated"}, "d" * 64
    )
    with pytest.raises(SystemExit):
        namespace["validate_preparations"](
            {"attacker_config": descriptors["config"], "capture": descriptors["capture"]},
            spec,
            lane,
        )


def test_phase5_ideator_reuses_campaign_manifest_and_binds_exact_config(
    tmp_path: Path,
) -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    lane = "followon-ideator-v2-qwen3-vl"
    spec = namespace["LANES"][lane]
    config_descriptor = {
        "path": str(tmp_path / "config.json"), "sha256": "a" * 64, "bytes": 10,
    }
    manifest_descriptor = {
        "path": str(tmp_path / "manifest.json"), "sha256": "b" * 64, "bytes": 20,
    }
    manifest = {"seed_pairs": [{"source_id": "advbench:245"} for _ in range(8)]}
    expected_config = {"pair_limit": 0, "seed_pairs": [["text", "image"]]}
    calls: list[str] = []

    def fake_checked(raw: object, label: str) -> tuple[Path, dict[str, Any]]:
        assert isinstance(raw, dict)
        value = manifest if "manifest" in label else {"ideator": expected_config}
        return Path(str(raw["path"])), value

    namespace["checked"] = fake_checked
    namespace["load_runner_attacker_config"] = lambda *_, **__: (
        tmp_path / "config.json", dict(expected_config), "c" * 64
    )
    namespace["validate_campaign_ideator_manifest"] = (
        lambda value: calls.append("manifest") or value
    )
    namespace["materialize_runner_attacker_config"] = lambda *_, **__: {
        "ideator": dict(expected_config)
    }
    validated = namespace["validate_preparations"](
        {
            "attacker_config": config_descriptor,
            "seed_pair_manifest": manifest_descriptor,
        },
        spec,
        lane,
    )
    assert calls == ["manifest"]
    assert validated["selection"]["measured"]["selected_datapoint_ids_sha256"]

    namespace["load_runner_attacker_config"] = lambda *_, **__: (
        tmp_path / "config.json", {**expected_config, "pair_limit": 1}, "c" * 64
    )
    with pytest.raises(SystemExit):
        namespace["validate_preparations"](
            {
                "attacker_config": config_descriptor,
                "seed_pair_manifest": manifest_descriptor,
            },
            spec,
            lane,
        )


def test_phase5_t3mp3st_reuses_strict_bundle_validator_and_record_cap(
    tmp_path: Path,
) -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    bundle = tmp_path / "bundle.json"
    descriptor = {"path": str(bundle), "sha256": "a" * 64, "bytes": 100}
    config = {
        "upstream_revision": "b" * 40,
        "source_provider": "provider",
        "source_model": "model",
        "response_artifact": str(bundle),
        "response_artifact_sha256": "a" * 64,
    }
    calls: list[str] = []

    class FakeAttacker:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs == config

        @staticmethod
        def _pin() -> str:
            return "b" * 40

        @staticmethod
        def _load_artifact(_pin: str) -> tuple[dict[str, Any], dict[str, Any]]:
            calls.append("bundle")
            return {}, {
                "format_version": "ura-t3mp3st-plan-bundle/1",
                "sha256": "a" * 64,
                "bytes": 100,
                "records": 50,
                "corpus_sha256": "c" * 64,
                "capture_runtime": {"verified": True},
            }

    namespace["T3MP3STAttacker"] = FakeAttacker
    validated = namespace["validate_t3mp3st_bundle"](
        config, bundle, descriptor, expected_records=50, label="fixture"
    )
    assert calls == ["bundle"]
    assert validated["corpus_sha256"] == "c" * 64
    with pytest.raises(SystemExit):
        namespace["validate_t3mp3st_bundle"](
            config, bundle, descriptor, expected_records=1, label="fixture"
        )
    with pytest.raises(SystemExit):
        namespace["validate_t3mp3st_bundle"](
            {**config, "response_artifact_sha256": "d" * 64},
            bundle,
            descriptor,
            expected_records=50,
            label="fixture",
        )


def test_phase5_canary_binds_purpose_artifacts_config_seed_and_attempt_count(
    tmp_path: Path,
) -> None:
    namespace = _prelude("phase5_followon_prepared.sh.in", "src_arg = Path(sys.argv[1])")
    lane = "followon-ideator-v2-qwen3-vl"
    spec = namespace["LANES"][lane]
    root = tmp_path / "canary"
    root.mkdir()

    def artifact(name: str, value: dict[str, Any]) -> dict[str, Any]:
        path = root / name
        raw = json.dumps(value, sort_keys=True).encode()
        path.write_bytes(raw)
        return {
            "file": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
            "records": 1,
        }

    eligibility_id = "eligibility-" + "1" * 24
    request_id = "eligibility-request-" + "2" * 24
    condition_id = "condition-" + "3" * 24
    projection_id = "lane-projection-" + "4" * 24
    grid_id = "grid-" + "5" * 24
    config_sha256 = "a" * 64
    config_identity = {"normalized_selected_sha256": config_sha256}
    condition_values = {
        "execution_purpose": "diagnostic_canary",
        "seeds": [0],
        "sample_seed": spec["sample_seed"],
        "limit": 1,
        "max_queries": spec["max_queries"],
        "max_turns": spec["max_turns"],
        "dry_run": False,
        "selected_config_identities": {"attacker_config": config_identity},
    }
    eligibility = {
        "plan_id": eligibility_id,
        "request_id": request_id,
        "bindings": {
            "attacker_configs_sha256": config_sha256,
            "selected_config_identities": {"attacker_config": config_identity},
            "experiment_conditions": {
                "condition_id": condition_id,
                "values": condition_values,
            },
        },
    }
    selected_sha256 = "b" * 64
    projection = {
        "projection_id": projection_id,
        "selection": {"arms": [{
            "logical_source_arm": spec["corpus"],
            "limit": 1,
            "sample_seed": spec["sample_seed"],
            "selected_records": 1,
            "selected_clusters": 1,
            "selected_datapoint_ids_sha256": selected_sha256,
        }]},
        "call_projection": {
            "target_calls": spec["canary_target_calls"],
            "judge_calls": 0,
            "http_attempts": 0,
        },
    }
    eligibility_descriptor = artifact("fixture.eligibility.json", {})
    projection_descriptor = artifact("fixture.lane-projection.json", {})
    completion_descriptor = artifact("fixture.complete.json", {})
    grid = {
        "grid_id": grid_id,
        "request": {
            "execution_purpose": "diagnostic_canary",
            "dry_run": False,
            "models": [namespace["QWEN_RUNTIME"]],
            "corpora": [spec["corpus"]],
            "attackers": [spec["attacker"]],
            "seeds": [0],
            "sample_seed": spec["sample_seed"],
            "limit": 1,
            "max_queries": spec["max_queries"],
            "max_turns": spec["max_turns"],
            "attacker_config_artifact": {
                "file": "canary-attacker.json",
                "sha256": "c" * 64,
                "bytes": 123,
                "normalized_selected_sha256": config_sha256,
            },
            "eligibility_plan": {"plan_id": eligibility_id, **eligibility_descriptor},
            "lane_projection": {"projection_id": projection_id, **projection_descriptor},
        },
    }
    grid_descriptor = artifact("fixture.grid.json", grid)
    canary_id = "lane-canary-" + "6" * 24
    canary_path = root / f"{canary_id}.lane-canary.json"
    canary_path.write_text("{}", encoding="utf-8")
    canary = {
        "canary_id": canary_id,
        "bindings": {
            "grid_id": grid_id,
            "grid_artifact": grid_descriptor,
            "completion_artifact": completion_descriptor,
            "eligibility_plan_id": eligibility_id,
            "eligibility_request_id": request_id,
            "eligibility_condition_id": condition_id,
            "eligibility_artifact": eligibility_descriptor,
            "lane_projection_id": projection_id,
            "lane_projection_artifact": projection_descriptor,
        },
        "condition": {
            "execution_purpose": "diagnostic_canary",
            "dry_run": False,
            "requested_model_spec": namespace["QWEN_RUNTIME"],
            "resolved_target": namespace["QWEN_RUNTIME"],
            "logical_source_arm": spec["corpus"],
            "attacker": spec["attacker"],
            "defense": "none",
            "judges": ["rules", "guardrail"],
            "seeds": [0],
        },
        "workload": {
            "selected_clusters": 1,
            "selected_rows": 1,
            "completed_attempts": spec["canary_target_calls"],
            "completed_responses": spec["canary_target_calls"],
            "completed_judgments": spec["canary_target_calls"],
        },
    }
    namespace["validate_eligibility_plan"] = lambda _value: eligibility
    namespace["validate_lane_projection_binding"] = lambda *_args, **_kwargs: projection
    preparation = {"selected_datapoint_ids_sha256": selected_sha256}
    config_descriptor = {
        "path": str(root / "canary-attacker.json"),
        "sha256": "c" * 64,
        "bytes": 123,
    }
    namespace["validate_canary_chain"](
        canary_path,
        canary,
        spec=spec,
        preparation=preparation,
        config_sha256=config_sha256,
        config_descriptor=config_descriptor,
        lane=lane,
    )

    canary["condition"]["seeds"] = [1]
    with pytest.raises(SystemExit):
        namespace["validate_canary_chain"](
            canary_path, canary, spec=spec, preparation=preparation,
            config_sha256=config_sha256, config_descriptor=config_descriptor, lane=lane,
        )
    canary["condition"]["seeds"] = [0]
    canary["workload"]["completed_attempts"] = 1
    with pytest.raises(SystemExit):
        namespace["validate_canary_chain"](
            canary_path, canary, spec=spec, preparation=preparation,
            config_sha256=config_sha256, config_descriptor=config_descriptor, lane=lane,
        )
    canary["workload"]["completed_attempts"] = spec["canary_target_calls"]
    eligibility["bindings"]["attacker_configs_sha256"] = "c" * 64
    with pytest.raises(SystemExit):
        namespace["validate_canary_chain"](
            canary_path, canary, spec=spec, preparation=preparation,
            config_sha256=config_sha256, config_descriptor=config_descriptor, lane=lane,
        )
    eligibility["bindings"]["attacker_configs_sha256"] = config_sha256
    projection["selection"]["arms"][0]["selected_datapoint_ids_sha256"] = "d" * 64
    with pytest.raises(SystemExit):
        namespace["validate_canary_chain"](
            canary_path, canary, spec=spec, preparation=preparation,
            config_sha256=config_sha256, config_descriptor=config_descriptor, lane=lane,
        )
    projection["selection"]["arms"][0]["selected_datapoint_ids_sha256"] = selected_sha256
    grid["request"]["attacker_config_artifact"]["sha256"] = "d" * 64
    with pytest.raises(SystemExit):
        namespace["validate_canary_chain"](
            canary_path, canary, spec=spec, preparation=preparation,
            config_sha256=config_sha256, config_descriptor=config_descriptor, lane=lane,
        )
    grid["request"]["attacker_config_artifact"]["sha256"] = "c" * 64
    canary["bindings"]["eligibility_condition_id"] = "condition-" + "9" * 24
    with pytest.raises(SystemExit):
        namespace["validate_canary_chain"](
            canary_path, canary, spec=spec, preparation=preparation,
            config_sha256=config_sha256, config_descriptor=config_descriptor, lane=lane,
        )


def _grid(namespace: dict[str, Any], lane: str, status: str, errors: int) -> dict[str, Any]:
    spec = namespace["LANES"][lane]
    return {
        "status": status,
        "grid_id": "fixture-grid",
        "n_errors": errors,
        "requested_cells": 1,
        "accounted_cells": 1,
        "request": {
            "execution_purpose": "measured_run",
            "dry_run": False,
            "attestation_probe": False,
            "models": [namespace["QWEN_RUNTIME"]],
            "corpora": [spec["corpus"]],
            "attackers": [spec["attacker"]],
            "judges": ["rules", "guardrail"],
            "judge_model": None,
            "guardrail_model": namespace["GUARD"],
            "guardrail_revision": namespace["GUARD_REVISION"],
            "guardrail_device": "cuda:1",
            "limit": spec["limit"],
            "sample_seed": spec["sample_seed"],
            "seeds": [0],
            "max_queries": spec["max_queries"],
            "max_turns": spec["max_turns"],
            "group_keys": namespace["GROUP_KEYS"],
            "defense": "none",
            "defense_guard": "rules",
            "approximate_common_metrics": True,
            "global_call_budget": {
                "max_target_calls": spec["target_calls"],
                "max_judge_calls": None,
                "max_http_attempts": None,
                "call_start_deadline_seconds_from_first_invocation": 86_400,
                "accounting_semantics": "durable_pre_call_logical_reservation_v1",
            },
            "live_attestation": {"mode": "measured"},
            "project_revision": {"commit": "f" * 40},
            "source_conformance_artifact": {"sha256": "a" * 64},
        },
    }


def test_phase6_derives_terminal_state_and_rejects_fabricated_success(
    tmp_path: Path,
) -> None:
    namespace = _prelude(
        "phase6_followon_prepared.sh.in", "amendment_arg = Path(sys.argv[1])"
    )
    lane = "followon-nanogcg-qwen3-vl"
    spec = namespace["LANES"][lane]
    empty = tmp_path / "empty"
    empty.mkdir()
    assert namespace["observed_terminal_state"](empty, spec, lane) == ("failed", None)

    partial = tmp_path / "partial"
    partial.mkdir()
    (partial / "fixture-grid.grid.json").write_text(
        json.dumps(_grid(namespace, lane, "partial", 1)), encoding="utf-8"
    )
    (partial / "cell.error.json").write_text(
        json.dumps({"status": "error", "message": "typed failure"}), encoding="utf-8"
    )
    assert namespace["observed_terminal_state"](partial, spec, lane) == (
        "partial",
        None,
    )

    fabricated = tmp_path / "fabricated"
    fabricated.mkdir()
    (fabricated / "fixture-grid.grid.json").write_text(
        json.dumps(_grid(namespace, lane, "complete", 0)), encoding="utf-8"
    )
    with pytest.raises(SystemExit):
        namespace["observed_terminal_state"](fabricated, spec, lane)
    (fabricated / "active.grid.lock").write_text("locked", encoding="utf-8")
    with pytest.raises(SystemExit):
        namespace["observed_terminal_state"](fabricated, spec, lane)


def test_phase6_binds_existing_external_terminal_and_exact_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = _prelude(
        "phase6_followon_prepared.sh.in", "amendment_arg = Path(sys.argv[1])"
    )
    work = tmp_path / "work"
    results = work / "runs"
    result_root = results / "thesis" / "runner" / "lane" / "attempt"
    result_root.mkdir(parents=True)
    registration_dir = results / "external-measured-jobs-v2" / "external-fixture"
    registration_dir.mkdir(parents=True)
    (registration_dir / "registration.json").write_text(
        json.dumps({"schema": "ura-external-measured-job/2"}), encoding="utf-8"
    )
    (registration_dir / "terminal.json").write_text(
        json.dumps({"schema": "ura-external-measured-job-terminal/1"}),
        encoding="utf-8",
    )
    argv = ["--local", "fixture", "--out", str(result_root)]
    job = SimpleNamespace(
        job_id="external-fixture",
        state="failed",
        exit_code=7,
        command="run_matrix",
        run_kind="measured",
        argv=tuple(argv),
        out_dir=result_root,
        expected_commit="f" * 40,
        framework_lock_id="a" * 64,
        admission_sha256="b" * 64,
        registration_dir=registration_dir,
    )
    monkeypatch.setenv("URA_WORK", str(work))
    namespace["load_external_measured_job"] = lambda *_args, **_kwargs: job
    raw = {"external_job_id": job.job_id, "controller_exit_code": 7}
    bound = namespace["validate_external_terminal"](
        raw,
        result_root=result_root,
        expected_argv=argv,
        expected_commit="f" * 40,
        expected_lock="a" * 64,
        admission_sha256="b" * 64,
        lane="fixture",
    )
    assert bound["state"] == "failed"
    assert bound["terminal"]["sha256"] == hashlib.sha256(
        (registration_dir / "terminal.json").read_bytes()
    ).hexdigest()
    with pytest.raises(SystemExit):
        namespace["validate_external_terminal"](
            raw,
            result_root=result_root,
            expected_argv=[*argv, "--limit", "2"],
            expected_commit="f" * 40,
            expected_lock="a" * 64,
            admission_sha256="b" * 64,
            lane="fixture",
        )


def test_phase6_terminal_must_agree_with_failed_partial_or_complete_lifecycle() -> None:
    namespace = _prelude(
        "phase6_followon_prepared.sh.in", "amendment_arg = Path(sys.argv[1])"
    )
    validate = namespace["validate_terminal_state_agreement"]
    validate("failed", {"state": "failed", "exit_code": 7}, [], lane="fixture")
    validate(
        "partial",
        {"state": "failed", "exit_code": 124},
        [{"path": "partial.grid.json"}],
        lane="fixture",
    )
    validate(
        "measured_complete",
        {"state": "complete", "exit_code": 0},
        [{"path": "complete.grid.json"}],
        lane="fixture",
    )
    for declared, external, inventory in (
        ("failed", {"state": "complete", "exit_code": 0}, []),
        ("partial", {"state": "complete", "exit_code": 0}, [{}]),
        ("measured_complete", {"state": "failed", "exit_code": 9}, [{}]),
    ):
        with pytest.raises(SystemExit):
            validate(declared, external, inventory, lane="fixture")


def test_phase7_sampling_sources_exclude_failed_followon_sibling(tmp_path: Path) -> None:
    runner = tmp_path / "runner"
    core_view = tmp_path / "core-view"
    success = runner / "followon-nanogcg-qwen3-vl" / "success"
    failed = runner / "followon-nanogcg-qwen3-vl" / "failed-recovery"
    (core_view / "core-lane").mkdir(parents=True)
    success.mkdir(parents=True)
    failed.mkdir(parents=True)
    (core_view / "core-lane" / "core.complete.json").write_text("{}", encoding="utf-8")
    (success / "success.complete.json").write_text("{}", encoding="utf-8")
    (failed / "failure.error.json").write_text("{}", encoding="utf-8")

    def regular_files(root: Path, *, label: str) -> dict[str, Path]:
        del label
        return {
            path.relative_to(root).as_posix(): path
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    method = _phase7_method(
        "_human_audit_view_sources",
        {"Path": Path, "checked_dir": lambda path, **_: Path(path), "_regular_tree_files": regular_files},
    )

    class Fixture:
        runner_root = runner
        inputs = {
            "followon": {
                "metric_roots": {"followon-nanogcg-qwen3-vl": str(success)}
            }
        }

        @staticmethod
        def analysis_runner_view() -> Path:
            return core_view

        @staticmethod
        def _followon_metric_lanes() -> list[str]:
            return ["followon-nanogcg-qwen3-vl"]

    sources = method(Fixture())
    assert set(sources) == {
        "core-lane/core.complete.json",
        "followon-nanogcg-qwen3-vl/success/success.complete.json",
    }
    assert all("failed-recovery" not in relative for relative in sources)


def test_phase7_revision_strata_retain_mixed_current_revisions(tmp_path: Path) -> None:
    lanes = ["core-a", "core-b", "followon-nanogcg-qwen3-vl"]
    grids: list[dict[str, Any]] = []
    for lane, commit in (("core-a", "9560270"), ("core-b", "b6241be")):
        path = tmp_path / lane / f"{lane}.grid.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"request": {"project_revision": {"commit": commit}}}), encoding="utf-8")
        grids.append({"path": str(path)})

    def canonical(value: object) -> bytes:
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    method = _phase7_method(
        "_human_audit_revision_strata",
        {
            "descriptor_file": lambda item, **_: Path(item["path"]),
            "strict_object": lambda path: json.loads(Path(path).read_text(encoding="utf-8")),
            "checked_dir": lambda path, **_: Path(path),
            "sha256_bytes": lambda data: hashlib.sha256(data).hexdigest(),
            "canonical": canonical,
            "Phase7Error": ValueError,
        },
    )
    followon_revision = hashlib.sha256(canonical({"commit": "73c5331"})).hexdigest()

    class Fixture:
        inputs = {
            "runner": {
                "metric_grids": grids,
                "metric_lane_order": lanes[:2],
                "lifecycle_lane_roots": {
                    lane: str(tmp_path / lane) for lane in lanes[:2]
                },
            },
            "followon": {
                "revision_strata": {
                    followon_revision: ["followon-nanogcg-qwen3-vl"]
                }
            },
        }

        @staticmethod
        def _human_audit_lane_order() -> list[str]:
            return lanes

    strata = method(Fixture())
    assert len(strata) == 3
    assert {lane for rows in strata.values() for lane in rows} == set(lanes)


def test_phase8_sampling_keeps_four_current_revision_strata() -> None:
    def canonical(value: object) -> bytes:
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    helper = _phase8_function(
        "phase8_sampling_revision_strata",
        {
            "Sequence": list,
            "Mapping": dict,
            "Any": Any,
            "canonical": canonical,
            "sha256_bytes": lambda data: hashlib.sha256(data).hexdigest(),
            "HEX64": re.compile(r"[0-9a-f]{64}"),
            "Phase8Error": ValueError,
        },
    )
    core = ["core-956", "core-b62", "core-c62"]
    followon = "followon-nanogcg-qwen3-vl"
    grid_values = {
        lane: {"request": {"project_revision": {"commit": commit}}}
        for lane, commit in zip(core, ("9560270", "b6241be", "c62e027"), strict=True)
    }
    followon_revision = hashlib.sha256(canonical({"commit": "73c5331"})).hexdigest()
    lane_order = [*core, followon]
    strata = helper(
        core_lanes=core,
        grid_values=grid_values,
        followon_strata={followon_revision: [followon]},
        audit_lanes=lane_order,
    )
    assert len(strata) == 4
    assert {lane for lanes in strata.values() for lane in lanes} == set(lane_order)
    with pytest.raises(ValueError):
        helper(
            core_lanes=core,
            grid_values=grid_values,
            followon_strata={followon_revision: [core[0]]},
            audit_lanes=core,
        )


def test_phase7_zero_success_followons_are_a_typed_limitation(tmp_path: Path) -> None:
    lanes = (
        "followon-nanogcg-qwen3-vl",
        "followon-ideator-v2-qwen3-vl",
        "followon-t3mp3st-qwen3-vl",
    )

    def canonical(value: object) -> bytes:
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def write_new(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    method = _phase7_method(
        "record_followon_outcomes",
        {
            "FOLLOWON_VIEW_SCHEMA": "ura-phase7-followon-input-view/1",
            "FOLLOWON_LANES": lanes,
            "canonical": canonical,
            "write_new": write_new,
        },
    )

    class Fixture:
        analysis = tmp_path
        inputs = {
            "followon": {
                "terminal_states": {lane: "failed" for lane in lanes},
                "lifecycle": {lane: {"state": "failed"} for lane in lanes},
                "metric_lane_order": [],
                "excluded_from_metrics": {lane: "failed" for lane in lanes},
                "revision_strata": {},
                "metric_roots": {},
                "metric_evidence": {},
            }
        }
        recorded: list[tuple[str, str, object]] = []

        def status(self, name: str, status: str, **kwargs: object) -> None:
            self.recorded.append((name, status, kwargs.get("limitations")))

    fixture = Fixture()
    method(fixture)
    assert fixture.recorded == [
        ("followon-lifecycle", "complete_with_limitations", {"excluded_from_metrics": fixture.inputs["followon"]["excluded_from_metrics"]})
    ]
    assert (tmp_path / "followon" / "lifecycle.json").is_file()


def test_followon_controllers_and_phase7_wrapper_are_packaged() -> None:
    generator = (ROOT / "experiments" / "local_campaign" / "generate.py").read_text(encoding="utf-8")
    verifier = (TEMPLATES / "verify_controller_set.sh.in").read_text(encoding="utf-8")
    wrapper = (TEMPLATES / "phase7_analysis.sh.in").read_text(encoding="utf-8")
    for name in ("phase5_followon_prepared.sh", "phase6_followon_prepared.sh"):
        assert f'"{name}.in", "{name}"' in generator
        assert f'("{name}", "none")' in verifier
    assert "--followon-gate5-amendment" in wrapper
    assert "--phase6-followon-completion" in wrapper
