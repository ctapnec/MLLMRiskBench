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
        "local campaign vocabulary": re.compile(
            r"\blocal[ _-]+campaign\b",
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
