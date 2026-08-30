"""Current Runner version declarations must match the executable contract."""

from __future__ import annotations

from pathlib import Path

from ura.runner import CODE_VERSION


_ROOT = Path(__file__).resolve().parents[2]


def test_current_runner_contract_docs_match_code_version() -> None:
    expected = f"Runner `{CODE_VERSION}`"
    documents = (
        _ROOT / "README.md",
        _ROOT / "experiments" / "README.md",
        _ROOT / "experiments" / "RUN_AND_RETURN.md",
    )

    assert CODE_VERSION == "ura-runner/2.25"
    for path in documents:
        text = path.read_text(encoding="utf-8")
        assert text.count(expected) == 1, path


def test_campaign_plan_keeps_checkpoint_recovery_on_original_runner() -> None:
    plan = (_ROOT / "experiments" / "LOCAL_CAMPAIGN_PLAN.md").read_text(
        encoding="utf-8"
    )

    assert (
        "Exact checkpoint recovery retains the\n"
        "originally bound Runner and argv and executes only never-completed rows."
        in plan
    )
    assert (
        "A\nseparately projected fresh Runner 2.25 cohort reserves the answer-retry "
        "attempts"
        in plan
    )
    assert (
        "recovery projects only their never-completed\nrows under Runner 2.25"
        not in plan
    )
