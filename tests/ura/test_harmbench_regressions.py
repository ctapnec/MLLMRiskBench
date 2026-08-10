from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import ura.adapters.harmbench as harmbench_module
from ura.adapters._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineError,
)
from ura.adapters.base import AttackBudget
from ura.adapters.harmbench import HarmBenchAttacker
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


def _fake_runner(*, fail_method: str | None = None, dirty: bool = False):
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
        if any(item.endswith("merge_test_cases.py") for item in args):
            save_dir = Path(args[args.index("--save_dir") + 1])
            save_dir.mkdir(parents=True, exist_ok=True)
            (save_dir / "test_cases.json").write_text(
                json.dumps(
                    {
                        "hb_case": [
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
            _datapoint(), AttackBudget(max_queries=4, max_turns=1, seed=3)
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


def test_harmbench_does_not_admit_surviving_methods_after_one_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _checkout(tmp_path)
    monkeypatch.setattr(shutil, "which", lambda _name: "git")
    monkeypatch.setattr(
        harmbench_module,
        "run_engine_command",
        _fake_runner(fail_method="PAP-top5"),
    )

    with pytest.raises(ExternalEngineError, match="PAP-top5 failed"):
        list(
            HarmBenchAttacker(
                methods=["PEZ", "PAP-top5"],
                repo=str(tmp_path),
                upstream_revision=_REVISION,
            ).generate(
                _datapoint(), AttackBudget(max_queries=2, max_turns=1, seed=0)
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
