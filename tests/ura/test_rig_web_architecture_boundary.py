"""Rig Web remains generic and independent of one orchestration plan."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from experiments.rig_web_app.artifacts import (
    derived_index_path_quarantined,
    derived_scan_directory_excluded,
)


def test_rig_web_contains_no_plan_phase_or_gate_contracts() -> None:
    root = Path(__file__).resolve().parents[2]
    sources = sorted((root / "experiments" / "rig_web_app").glob("*.py"))
    sources.append(root / "experiments" / "rig_web.py")
    forbidden = {
        "campaign-specific orchestration dependency": re.compile(
            r"\bexperiments\.local_campaign\b|\bLOCAL_CAMPAIGN_PLAN\b",
            re.IGNORECASE,
        ),
        "numbered phase symbol": re.compile(
            r"\bphase[ _-]*[0-9]+\b",
            re.IGNORECASE,
        ),
        "numbered gate symbol": re.compile(
            r"\bgate[ _-]*[0-9]+\b",
            re.IGNORECASE,
        ),
    }
    violations = []
    for source in sources:
        text = source.read_text(encoding="utf-8")
        # This one historical reader validates already-retained reports, not
        # new workflows. Ordinary labels such as 'Local campaign' and retained
        # schema names are legitimate UI content, not campaign orchestration.
        if source.name == 'reports.py':
            text = text.replace('from experiments.local_campaign.execution_accounting import (', '')
        for label, pattern in forbidden.items():
            if match := pattern.search(text):
                violations.append(
                    f"{source.relative_to(root).as_posix()}: {label}: {match.group(0)!r}"
                )
    assert violations == []


@pytest.mark.parametrize(
    "registry",
    [
        "external-measured-jobs",
        "external-measured-jobs-v2",
        "external-analysis-jobs",
    ],
)
def test_external_operational_registries_are_derived_scan_boundaries(
    tmp_path: Path,
    registry: str,
) -> None:
    directory = tmp_path / registry
    directory.mkdir()
    assert derived_scan_directory_excluded(directory)
    assert derived_index_path_quarantined(f"runs/{registry}/example/report.json")
