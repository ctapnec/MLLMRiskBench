from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import ura.adapters.harmbench as harmbench_module
from experiments import harmbench_capture
from ura.adapters._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineError,
    ExternalEngineOutputError,
)
from ura.adapters.base import AttackBudget
from ura.adapters.harmbench import HarmBenchAttacker
from ura.converters.harmbench import HarmBenchConverter
from ura.data_models import DataPoint, RiskCategory

_REVISION = "1" * 40


def _datapoint() -> DataPoint:
    return DataPoint(
        id="hb-case",
        source="unit",
        modalities=["text"],
        payload_text="harmful behavior",
        risk_category=RiskCategory.JAILBREAK,
        expected_behavior="refuse",
    )


def _checkout(tmp_path: Path) -> None:
    (tmp_path / "generate_test_cases.py").write_text("# fixture", encoding="utf-8")
    (tmp_path / "merge_test_cases.py").write_text("# fixture", encoding="utf-8")


def _source_csv(path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "Behavior",
            "FunctionalCategory",
            "SemanticCategory",
            "Tags",
            "ContextString",
            "BehaviorID",
        ])
        writer.writeheader()
        writer.writerow({
            "Behavior": "harmful behavior",
            "FunctionalCategory": "standard",
            "SemanticCategory": "harmful",
            "Tags": "fixture",
            "ContextString": "",
            "BehaviorID": "case-a",
        })


def _capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    cases_per_method: int = 2,
    engine_runner=None,
    limit: int = 1,
    converted_datapoints: list[DataPoint] | None = None,
) -> tuple[Path, Path, DataPoint]:
    repo = tmp_path / "HarmBench"
    repo.mkdir(parents=True)
    _checkout(repo)
    source = tmp_path / "behaviors.csv"
    _source_csv(source)
    artifact = tmp_path / "harmbench.replay.json"
    config = tmp_path / "harmbench.attackers.json"
    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(
        harmbench_module,
        "run_engine_command",
        engine_runner or _fake_runner(),
    )
    if converted_datapoints is not None:
        monkeypatch.setattr(
            harmbench_capture.HarmBenchConverter,
            "parse",
            lambda _self, _path: list(converted_datapoints),
        )
    assert harmbench_capture.main([
        "--repo", str(repo),
        "--revision", _REVISION,
        "--source", str(source),
        "--corpus-name", "harmbench_text",
        "--method", "PEZ",
        "--method", "PAP-top5",
        "--experiment", "fixture-model",
        "--limit", str(limit),
        "--sample-seed", "7",
        "--cases-per-method", str(cases_per_method),
        "--artifact-out", str(artifact),
        "--attacker-config-out", str(config),
    ]) == 0
    point = HarmBenchConverter().parse(source)[0]
    return artifact, config, point


def _attacker_from_config(path: Path) -> HarmBenchAttacker:
    config = json.loads(path.read_text(encoding="utf-8"))
    return HarmBenchAttacker(**config["harmbench"])


def _repin_bundle(path: Path, bundle: dict) -> str:
    unsigned = {
        key: value for key, value in bundle.items() if key != "content_sha256"
    }
    bundle["content_sha256"] = harmbench_module._canonical_sha256(unsigned)
    raw = (
        json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _fake_runner(*, fail_method: str | None = None, dirty: bool = False):
    behavior_ids: dict[str, str] = {}

    def run(command, **_kwargs):
        if "rev-parse" in command:
            return subprocess.CompletedProcess(
                command, returncode=0, stdout=_REVISION, stderr=""
            )
        if "status" in command:
            return subprocess.CompletedProcess(
                command,
                returncode=0,
                stdout=" M generate_test_cases.py" if dirty else "",
                stderr="",
            )
        args = [str(item) for item in command]
        method = args[args.index("--method_name") + 1]
        if fail_method == method:
            raise ExternalEngineError(f"{method} failed")
        save_dir = Path(args[args.index("--save_dir") + 1])
        if any(item.endswith("generate_test_cases.py") for item in args):
            behaviors = Path(args[args.index("--behaviors_path") + 1])
            with behaviors.open(encoding="utf-8", newline="") as handle:
                row = next(csv.DictReader(handle))
            behavior_ids[str(save_dir)] = row["BehaviorID"]
        if any(item.endswith("merge_test_cases.py") for item in args):
            save_dir.mkdir(parents=True, exist_ok=True)
            (save_dir / "test_cases.json").write_text(
                json.dumps(
                    {
                        behavior_ids[str(save_dir)]: [
                            f"{method} generated attack 1",
                            f"{method} generated attack 2",
                        ]
                    }
                ),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(
            command, returncode=0, stdout="", stderr=""
        )

    return run


def test_harmbench_runs_every_method_and_round_robins_outputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _checkout(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(harmbench_module, "run_engine_command", _fake_runner())

    attempts = list(
        HarmBenchAttacker(
            methods=["PEZ", "PAP-top5"],
            repo=str(tmp_path),
            upstream_revision=_REVISION,
        ).generate(
            _datapoint(), AttackBudget(max_queries=4, max_turns=4, seed=3)
        )
    )

    assert [attempt.params["method"] for attempt in attempts] == [
        "PEZ",
        "PAP-top5",
        "PEZ",
        "PAP-top5",
    ]
    assert all(
        attempt.params["attack_semantics"]
        == "harmbench_generated_case_transfer"
        for attempt in attempts
    )
    assert all(attempt.params["native_harmbench_classifier_executed"] is False
               for attempt in attempts)
    assert all(attempt.params["method_output_artifacts"] for attempt in attempts)


def test_harmbench_capture_replays_every_bound_case_without_native_overclaim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    artifact, config, point = _capture(monkeypatch, tmp_path)
    attacker = _attacker_from_config(config)
    attacker.validate_measured_run([point])

    with pytest.raises(ExternalEngineConformanceError, match="every captured"):
        list(
            attacker.generate(
                point, AttackBudget(max_queries=3, max_turns=3, seed=7)
            )
        )
    attempts = list(
        attacker.generate(point, AttackBudget(max_queries=4, max_turns=4, seed=7))
    )

    assert [attempt.params["method"] for attempt in attempts] == [
        "PEZ", "PAP-top5", "PEZ", "PAP-top5",
    ]
    assert [attempt.params["upstream_method"] for attempt in attempts] == [
        "PEZ", "PAP", "PEZ", "PAP",
    ]
    assert [attempt.params["upstream_experiment"] for attempt in attempts] == [
        "fixture-model", "top_5", "fixture-model", "top_5",
    ]
    assert all(
        attempt.params["native_harmbench_classifier_executed"] is False
        for attempt in attempts
    )
    assert all(
        attempt.params["common_judge_is_not_native_harmbench_classifier"] is True
        for attempt in attempts
    )
    identity = attempts[0].params["replay_artifact_identity"]
    assert identity["sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert identity["source_requests"] == 1
    assert identity["generated_cases"] == 4
    output = capsys.readouterr().out
    assert "captured 4 HarmBench cases for 1 behaviors" in output
    assert "attacker config ->" in output

    from ura.runner import _component_config

    persisted = _component_config(attacker)
    assert str(artifact) not in json.dumps(persisted, sort_keys=True)
    assert persisted["replay_artifact_sha256"] == identity["sha256"]
    assert persisted["replay_artifact_identity"] == identity

    from ura.judges.base import JudgeCascade
    from ura.judges.rules import RuleJudge
    from ura.runner import Runner
    from ura.targets.api import MockTarget

    smoke_judge = RuleJudge()
    smoke_judge.escalate_below = 0.0
    judgments, manifest = Runner(
        _attacker_from_config(config),
        MockTarget(),
        JudgeCascade([smoke_judge]),
        AttackBudget(max_queries=4, max_turns=4, seed=7),
        [7],
    ).run([point])
    assert len(judgments) == 4
    assert manifest.adapters == ["harmbench"]
    assert manifest.config["components"]["attacker"][
        "replay_artifact_identity"
    ] == identity


def test_harmbench_replay_rejects_missing_and_tampered_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    artifact, config, point = _capture(
        monkeypatch, tmp_path, cases_per_method=1
    )
    raw = artifact.read_text(encoding="utf-8")
    artifact.write_text(raw.replace("PEZ generated", "PEZ altered", 1), encoding="utf-8")
    with pytest.raises(ExternalEngineConformanceError, match="replay_artifact_sha256"):
        _attacker_from_config(config).validate_measured_run([point])

    config_value = json.loads(config.read_text(encoding="utf-8"))["harmbench"]
    config_value["replay_artifact"] = str(tmp_path / "missing.json")
    config_value["replay_artifact_sha256"] = "0" * 64
    with pytest.raises(ExternalEngineConformanceError, match="cannot read"):
        HarmBenchAttacker(**config_value).validate_measured_run([point])


def test_harmbench_replay_rejects_partial_capture_before_target_or_judge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    artifact, config, point = _capture(monkeypatch, tmp_path)
    bundle = json.loads(artifact.read_text(encoding="utf-8"))
    bundle["cases"].pop()
    digest = _repin_bundle(artifact, bundle)
    config_value = json.loads(config.read_text(encoding="utf-8"))["harmbench"]
    config_value["replay_artifact_sha256"] = digest
    attacker = HarmBenchAttacker(**config_value)

    from ura.judges.base import JudgeCascade
    from ura.judges.rules import RuleJudge
    from ura.runner import Runner
    from ura.targets.api import MockTarget

    target = MockTarget()
    judge = RuleJudge()
    monkeypatch.setattr(
        target,
        "generate",
        lambda *_args, **_kwargs: pytest.fail("partial capture reached target"),
    )
    monkeypatch.setattr(
        judge,
        "judge",
        lambda *_args, **_kwargs: pytest.fail("partial capture reached judge"),
    )
    runner = Runner(
        attacker,
        target,
        JudgeCascade([judge]),
        AttackBudget(max_queries=4, max_turns=4, seed=7),
        [7],
    )
    with pytest.raises(ExternalEngineOutputError, match="partial"):
        runner.run([point])


def test_harmbench_replay_rejects_corpus_mismatch_and_duplicate_json_keys(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    artifact, config, point = _capture(
        monkeypatch, tmp_path, cases_per_method=1
    )
    mismatch = point.model_copy(update={"payload_text": "different behavior"})
    with pytest.raises(ExternalEngineConformanceError, match="measured corpus"):
        _attacker_from_config(config).validate_measured_run([mismatch])

    duplicate = (
        '{"format_version":"ura-harmbench-transfer-replay/1",'
        '"format_version":"duplicate"}'
    ).encode("utf-8")
    artifact.write_bytes(duplicate)
    config_value = json.loads(config.read_text(encoding="utf-8"))["harmbench"]
    config_value["replay_artifact_sha256"] = hashlib.sha256(duplicate).hexdigest()
    with pytest.raises(ExternalEngineOutputError, match="valid UTF-8 JSON"):
        HarmBenchAttacker(**config_value).validate_measured_run([point])


def test_harmbench_capture_does_not_publish_partial_final_on_write_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = tmp_path / "capture.json"
    real_fdopen = harmbench_capture.os.fdopen

    class FailingWriter:
        def __init__(self, descriptor: int, mode: str) -> None:
            self.handle = real_fdopen(descriptor, mode)

        def __enter__(self):
            return self

        def write(self, payload: bytes) -> None:
            self.handle.write(payload[:1])
            raise OSError("injected staging write failure")

        def __exit__(self, *_args) -> None:
            self.handle.close()

    monkeypatch.setattr(harmbench_capture.os, "fdopen", FailingWriter)
    with pytest.raises(OSError, match="injected"):
        harmbench_capture._atomic_exclusive_write(output, b"complete artifact")

    assert not output.exists()
    assert not list(tmp_path.glob(".capture.json.*.tmp"))


def test_harmbench_capture_prevents_child_bytecode_from_dirtying_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base_runner = _fake_runner()
    checkout = tmp_path / "HarmBench"
    cache_file = checkout / "__pycache__" / "upstream.cpython-312.pyc"
    observed_overrides: list[dict[str, str]] = []

    def runner(command, **kwargs):
        if "status" in command and cache_file.exists():
            return subprocess.CompletedProcess(
                command,
                returncode=0,
                stdout="!! __pycache__/upstream.cpython-312.pyc",
                stderr="",
            )
        parts = [str(part) for part in command]
        if any(
            item.endswith(("generate_test_cases.py", "merge_test_cases.py"))
            for item in parts
        ):
            overrides = kwargs.get("env_overrides", {})
            observed_overrides.append(dict(overrides))
            if overrides.get("PYTHONDONTWRITEBYTECODE") != "1":
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_bytes(b"child bytecode")
        return base_runner(command, **kwargs)

    _capture(
        monkeypatch,
        tmp_path,
        cases_per_method=1,
        engine_runner=runner,
    )

    assert len(observed_overrides) == 4
    assert all(
        value == {"PYTHONDONTWRITEBYTECODE": "1"}
        for value in observed_overrides
    )
    assert not cache_file.exists()


def test_harmbench_capture_rejects_duplicate_ids_before_engine_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    point = _datapoint()

    def no_engine(*_args, **_kwargs):
        pytest.fail("duplicate selection reached HarmBench")

    with pytest.raises(ValueError, match="duplicate DataPoint ids"):
        _capture(
            monkeypatch,
            tmp_path,
            cases_per_method=1,
            engine_runner=no_engine,
            limit=0,
            converted_datapoints=[point, point.model_copy()],
        )


def test_harmbench_capture_rejects_request_and_case_limits_before_engine_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    points = [
        _datapoint(),
        _datapoint().model_copy(update={"id": "hb-case-2"}),
    ]

    def no_engine(*_args, **_kwargs):
        pytest.fail("oversized selection reached HarmBench")

    monkeypatch.setattr(harmbench_capture, "_MAX_REPLAY_REQUESTS", 1)
    with pytest.raises(ValueError, match="request limit"):
        _capture(
            monkeypatch,
            tmp_path / "requests",
            cases_per_method=1,
            engine_runner=no_engine,
            limit=0,
            converted_datapoints=points,
        )

    monkeypatch.setattr(harmbench_capture, "_MAX_REPLAY_REQUESTS", 2)
    monkeypatch.setattr(harmbench_capture, "_MAX_REPLAY_CASES", 3)
    with pytest.raises(ValueError, match="case limit"):
        _capture(
            monkeypatch,
            tmp_path / "cases",
            cases_per_method=1,
            engine_runner=no_engine,
            limit=0,
            converted_datapoints=points,
        )


def test_harmbench_capture_rejects_oversized_artifact_before_publish(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(harmbench_capture, "_MAX_REPLAY_BYTES", 1)
    monkeypatch.setattr(
        harmbench_capture,
        "_atomic_exclusive_write",
        lambda *_args, **_kwargs: pytest.fail("oversized artifact was published"),
    )

    with pytest.raises(ValueError, match="artifact exceeds"):
        _capture(monkeypatch, tmp_path, cases_per_method=1)

    assert not (tmp_path / "harmbench.replay.json").exists()
    assert not (tmp_path / "harmbench.attackers.json").exists()


def test_harmbench_does_not_admit_surviving_methods_after_one_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _checkout(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(
        harmbench_module,
        "run_engine_command",
        _fake_runner(fail_method="PAP"),
    )

    with pytest.raises(ExternalEngineError, match="PAP failed"):
        list(
            HarmBenchAttacker(
                methods=["PEZ", "PAP-top5"],
                repo=str(tmp_path),
                upstream_revision=_REVISION,
            ).generate(
                _datapoint(), AttackBudget(max_queries=2, max_turns=2, seed=0)
            )
        )


def test_harmbench_rejects_budget_that_silently_drops_a_method(tmp_path: Path) -> None:
    _checkout(tmp_path)
    attacker = HarmBenchAttacker(
        methods=["PEZ", "PAP-top5"],
        repo=str(tmp_path),
        upstream_revision=_REVISION,
    )
    with pytest.raises(ExternalEngineConformanceError, match="one case per"):
        list(
            attacker.generate(
                _datapoint(), AttackBudget(max_queries=1, max_turns=1, seed=0)
            )
        )


def test_measured_harmbench_requires_capture(tmp_path: Path) -> None:
    _checkout(tmp_path)
    attacker = HarmBenchAttacker(
        methods=["PEZ"],
        repo=str(tmp_path),
        upstream_revision=_REVISION,
    )

    with pytest.raises(ExternalEngineConformanceError, match="harmbench_capture"):
        attacker.validate_measured_run()


def test_harmbench_rejects_modified_pinned_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _checkout(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(
        harmbench_module, "run_engine_command", _fake_runner(dirty=True)
    )
    with pytest.raises(ExternalEngineConformanceError, match="tracked modifications"):
        list(
            HarmBenchAttacker(
                methods=["PEZ"],
                repo=str(tmp_path),
                upstream_revision=_REVISION,
            ).generate(
                _datapoint(), AttackBudget(max_queries=1, max_turns=1, seed=0)
            )
        )


def test_harmbench_rejects_ignored_files_in_pinned_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _checkout(tmp_path)
    observed_status_command: list[str] = []

    def runner(command, **_kwargs):
        nonlocal observed_status_command
        if "rev-parse" in command:
            return subprocess.CompletedProcess(
                command, returncode=0, stdout=_REVISION, stderr=""
            )
        if "status" in command:
            observed_status_command = [str(part) for part in command]
            return subprocess.CompletedProcess(
                command, returncode=0, stdout="!! ignored-config.json", stderr=""
            )
        raise AssertionError("generation must not start for a dirty checkout")

    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(harmbench_module, "run_engine_command", runner)
    with pytest.raises(ExternalEngineConformanceError, match="ignored files"):
        list(
            HarmBenchAttacker(
                methods=["PEZ"],
                repo=str(tmp_path),
                upstream_revision=_REVISION,
            ).generate(
                _datapoint(), AttackBudget(max_queries=1, max_turns=1, seed=0)
            )
        )
    assert "--ignored=matching" in observed_status_command
