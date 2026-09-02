from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Sequence

import pytest

from experiments.local_campaign import (
    current_ollama_population_alignment_phase6 as alignment,
)
from experiments.local_campaign import (
    current_ollama_population_alignment_recovery_phase6 as recovery,
)
from experiments.local_campaign import vllm_stability_phase6 as unit_runner


def test_alignment_continuation_selects_only_six_never_started_units() -> None:
    failed = {
        recovery.FAILED_OUTPUT_COVERED_LANE,
        *recovery.CONTINUATION_LANES,
    }
    snapshot = {
        "terminal_states": {
            lane: "failed" if lane in failed else "measured_complete"
            for lane in alignment.ALIGNMENT_LANES
        }
    }

    selected = recovery._selected_failed_lanes(  # noqa: SLF001
        snapshot,
        covered_lanes=(recovery.FAILED_OUTPUT_COVERED_LANE,),
    )

    assert selected == list(recovery.CONTINUATION_LANES)
    assert len(selected) == 6
    assert recovery.FAILED_OUTPUT_COVERED_LANE not in selected
    assert all(
        lane.startswith(("rjudge-ollama-", "gptgeochat-ollama-"))
        for lane in selected
    )
    expected_rows = sum(
        50 if lane.startswith("rjudge-ollama-") else 1_075
        for lane in selected
    )
    assert expected_rows == recovery.EXPECTED_CONTINUATION_ROWS == 2_350

    mutant = recovery._selected_failed_lanes(snapshot)  # noqa: SLF001
    assert mutant != selected
    assert recovery.FAILED_OUTPUT_COVERED_LANE in mutant


def test_alignment_continuation_contract_binds_hardware_fit_successor() -> None:
    destinations = {action.dest for action in recovery.build_parser()._actions}  # noqa: SLF001

    assert recovery.SCHEMA.endswith("/4")
    assert {
        "failed_output_recovery_completion",
        "failed_output_recovery_completion_sha256",
        "hardware_fit_completion",
        "hardware_fit_completion_sha256",
    } <= destinations


def test_alignment_continuation_separates_actual_replays_from_unique_rows() -> None:
    execution = recovery._combined_target_execution(  # noqa: SLF001
        base_execution={
            "target_attempts": 7_341,
            "successful_target_generations": 5_222,
            "missing_responses": 2_119,
        },
        coverage={
            "prior_usable_records": 235,
            "alignment_recovery_successful_target_generations": 3_747,
            "alignment_recovery_missing_responses": 46,
            "partial_deepseek_successful_target_generations": 771,
            "retained_partial_deepseek_successful_target_generations": 743,
            "partial_deepseek_missing_responses": 14,
            "hardware_fit_replayed_partial_rows": 42,
        },
        continuation_successful=2_350,
        continuation_missing=0,
    )

    assert execution == {
        "target_attempts": 14_414,
        "successful_target_generations": 11_582,
        "missing_responses": 2_832,
        "unique_population_rows": 11_600,
        "retained_population_successful_target_generations": 11_554,
        "retained_population_missing_responses": 46,
        "replayed_failed_output_rows": 2_772,
        "replayed_partial_recovery_rows": 42,
        "never_attempted_rows_completed": 1_021,
        "alignment_never_started_rows_completed": 2_350,
    }
    with pytest.raises(ValueError):
        recovery._combined_target_execution(  # noqa: SLF001
            base_execution={
                "target_attempts": 7_340,
                "successful_target_generations": 5_222,
                "missing_responses": 2_118,
            },
            coverage={
                "prior_usable_records": 235,
                "alignment_recovery_successful_target_generations": 3_747,
                "alignment_recovery_missing_responses": 46,
                "partial_deepseek_successful_target_generations": 771,
                "retained_partial_deepseek_successful_target_generations": 743,
                "partial_deepseek_missing_responses": 14,
                "hardware_fit_replayed_partial_rows": 42,
            },
            continuation_successful=2_350,
            continuation_missing=0,
        )
    with pytest.raises(ValueError):
        recovery._combined_target_execution(  # noqa: SLF001
            base_execution={
                "target_attempts": 7_341,
                "successful_target_generations": 5_222,
                "missing_responses": 2_119,
            },
            coverage={
                "prior_usable_records": 235,
                "alignment_recovery_successful_target_generations": 3_747,
                "alignment_recovery_missing_responses": 46,
                "partial_deepseek_successful_target_generations": 771,
                "retained_partial_deepseek_successful_target_generations": 743,
                "partial_deepseek_missing_responses": 14,
                "hardware_fit_replayed_partial_rows": 41,
            },
            continuation_successful=2_350,
            continuation_missing=0,
        )


@pytest.mark.parametrize(
    ("model_spec", "expected_think"),
    (
        ("ollama:gemma4:12b-it-q4_K_M", False),
        ("ollama:ministral-3:14b-instruct-2512-q4_K_M", False),
        ("ollama:deepseek-r1:32b-qwen-distill-q4_K_M", True),
        ("ollama:gpt-oss:20b", "low"),
    ),
)
def test_alignment_continuation_rebinds_explicit_thinking_policy(
    tmp_path: Path,
    model_spec: str,
    expected_think: bool | str,
) -> None:
    control_root = tmp_path / "alignment-continuation"
    (control_root / "configs").mkdir(parents=True)
    unit = unit_runner.Unit(
        unit_id="fixture",
        source_lane="fixture",
        corpus=None,
        spec={
            "metric_mode": "rjudge",
            "base_argv": [
                "--local",
                model_spec,
                "--local-config",
                "/old/config.json",
                "--local-config-sha256",
                "a" * 64,
            ],
        },
        selected_records=1,
    )
    item = alignment.AlignmentUnit(
        unit=unit,
        old_lane="fixture",
        full_records=1,
        prefix_records=0,
        by_corpus={},
        recovery={},
    )

    configured = recovery._configured_unit(  # noqa: SLF001
        item, control_root=control_root
    )
    argv = configured.unit.spec["base_argv"]
    config_path = Path(unit_runner._option(argv, "--local-config"))  # noqa: SLF001
    payload = json.loads(config_path.read_text(encoding="utf-8"))

    assert payload[model_spec]["think"] == expected_think
    assert payload[model_spec]["num_ctx"] == "fit"
    assert payload[model_spec]["num_predict"] == -1
    assert (
        unit_runner._option(  # noqa: SLF001
            argv, "--local-config-sha256"
        )
        == hashlib.sha256(config_path.read_bytes()).hexdigest()
    )


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
        "FAILED_OUTPUT_COVERED_LANE as CURRENT_OLLAMA_ALIGNMENT_SPLIT_LANE",
        "validate_phase7_completion as validate_current_ollama_alignment_completion",
        'current_ollama_alignment["metric_roots"].get(lane)',
        "if lane != CURRENT_OLLAMA_ALIGNMENT_SPLIT_LANE",
        '"population_segments": current.get("population_segments", {})',
    )
    for token in required:
        assert token in template
    current_method = template.split(
        "def record_current_ollama_outcomes", 1
    )[1].split("def record_current_ollama_stability_outcomes", 1)[0]
    alignment_method = template.split(
        "def record_current_ollama_alignment_outcomes", 1
    )[1].split("def record_vllm_stability_outcomes", 1)[0]
    assert '"population_segments"' not in current_method
    assert '"population_segments"' in alignment_method

    mutant = template.replace(
        "current_ollama_population_alignment_recovery_phase6 import (",
        "current_ollama_population_alignment_phase6 import (",
        1,
    )
    assert mutant != template
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant


def test_phase8_excludes_split_alignment_lane_from_metric_sampling() -> None:
    template = (
        Path(__file__).parents[2]
        / "experiments/local_campaign/templates/phase8_human_audit.py.in"
    ).read_text(encoding="utf-8")
    required = (
        "FAILED_OUTPUT_COVERED_LANE as CURRENT_OLLAMA_ALIGNMENT_SPLIT_LANE",
        "expected_metric_lanes: Sequence[str] | None = None",
        "if lane != CURRENT_OLLAMA_ALIGNMENT_SPLIT_LANE",
        'metric_revisions = value.get("metric_project_revision_receipt_sha256")',
        "!= expected_current_ollama_alignment_metric_lanes",
    )
    for token in required:
        assert token in template

    mutant = template.replace(
        "if lane != CURRENT_OLLAMA_ALIGNMENT_SPLIT_LANE",
        "if True",
    )
    assert mutant != template
    with pytest.raises(AssertionError):
        for token in required:
            assert token in mutant
