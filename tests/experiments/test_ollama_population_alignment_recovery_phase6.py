from __future__ import annotations

from pathlib import Path
from typing import Sequence

import pytest

from experiments.local_campaign import (
    current_ollama_population_alignment_phase6 as alignment,
)
from experiments.local_campaign import vllm_stability_phase6 as unit_runner


@pytest.mark.parametrize(
    ("metric_mode", "expected"),
    (("static", True), ("rjudge", False), ("gptgeochat", False)),
)
def test_population_alignment_hub_acquisition_matches_exact_metric_mode(
    metric_mode: str,
    expected: bool,
) -> None:
    unit = unit_runner.Unit(
        unit_id=f"fixture-{metric_mode}",
        source_lane=f"fixture-{metric_mode}",
        corpus=None,
        spec={"metric_mode": metric_mode},
        selected_records=1,
    )

    assert alignment.hub_acquisition_required(unit) is expected


def test_run_unit_omits_hub_plan_for_local_only_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work_root = tmp_path / "work"
    control_root = work_root / "runs/engineering/alignment-recovery"
    (control_root / "units").mkdir(parents=True)
    (work_root / "runs/thesis/runner").mkdir(parents=True)
    unit = unit_runner.Unit(
        unit_id="rjudge-local-only-fixture",
        source_lane="rjudge-local-only-fixture",
        corpus=None,
        spec={"metric_mode": "rjudge"},
        selected_records=1,
    )
    monkeypatch.setattr(unit_runner, "_base_argv", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        unit_runner,
        "_derive_attestation",
        lambda *args, **kwargs: {"path": "/attestation", "sha256": "a" * 64},
    )
    monkeypatch.setattr(
        unit_runner,
        "_runtime_args",
        lambda base, *, out, **kwargs: ["--out", str(out)],
    )

    def reject_acquisition(*_args: object, **_kwargs: object) -> list[str]:
        raise AssertionError("local-only lane must not derive a Hub plan")

    monkeypatch.setattr(unit_runner, "_acquisition_args", reject_acquisition)

    def fake_run(
        argv: Sequence[str],
        *,
        log: Path,
        timeout: int,
        allow_failure: bool = False,
    ) -> int:
        del argv, timeout, allow_failure
        log.write_text("ok\n", encoding="utf-8")
        if log.name == "canary.run.log":
            root = log.parent / "canary"
            root.mkdir()
            (root / "eligibility-fixture.eligibility.json").write_text(
                "{}\n", encoding="utf-8"
            )
        elif log.name == "preflight.run.log":
            root = log.parent / "preflight"
            root.mkdir()
            (root / "lane-projection-fixture.lane-projection.json").write_text(
                "{}\n", encoding="utf-8"
            )
        return 0

    monkeypatch.setattr(unit_runner, "_run", fake_run)
    monkeypatch.setattr(
        unit_runner,
        "register_external_measured_start",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        unit_runner,
        "register_external_measured_terminal",
        lambda *args, **kwargs: None,
    )

    def fake_level1_counts(
        *, lane_root: Path, **_kwargs: object
    ) -> tuple[int, int, int]:
        (lane_root / "level1.json").write_text("{}\n", encoding="utf-8")
        return 1, 1, 0

    monkeypatch.setattr(unit_runner, "_level1_counts", fake_level1_counts)

    result = unit_runner._run_unit(
        unit,
        python=Path("/fixture/python"),
        work_root=work_root,
        control_root=control_root,
        project_revision=Path("/fixture/revision.json"),
        project_revision_sha256="b" * 64,
        scope="scope-fixture",
        recovery_path=None,
        recovery_sha256=None,
        expected_commit="c" * 40,
        framework_lock_id="d" * 64,
        admission_sha256="e" * 64,
        tmux_socket="ura-fixture",
        tmux_session="ura-fixture",
        hub_acquisition_required=False,
    )

    assert result["status"] == "complete"
    assert result["target_attempts"] == 1


def test_phase7_uses_alignment_recovery_dispatcher() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments/local_campaign/templates/phase7_analysis.py.in"
    ).read_text(encoding="utf-8")
    required = (
        "current_ollama_population_alignment_recovery_phase6 import (",
        "validate_phase7_completion as validate_current_ollama_alignment_completion",
    )
    for token in required:
        assert token in template

    mutant = template.replace(
        "current_ollama_population_alignment_recovery_phase6 import (",
        "current_ollama_population_alignment_phase6 import (",
        1,
    )
    assert mutant != template
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant
