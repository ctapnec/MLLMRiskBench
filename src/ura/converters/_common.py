"""Shared helpers for the per-framework converters (thesis IV.1.6).

Each converter lives in its own module (rjudge.py, mmsafety.py, harmbench.py, ...)
and uses these helpers to read source files and build unified DataPoints. Only the
standard library + pydantic are imported here.
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any, Optional

from ..data_models import DataPoint, DialogTurn, ExpectedBehavior, MediaRef, RiskCategory

from ..taxonomy import refs_for

logger = logging.getLogger("ura.converters")

Rc = RiskCategory


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def image(path: str, root: Optional[Path] = None) -> MediaRef:
    """Build an image MediaRef, resolving a relative path against a data root."""
    p = Path(path)
    if root is not None and not p.is_absolute():
        p = root / p
    return MediaRef(modality="image", path=str(p))


def dp(
    *,
    id: str,
    source: str,
    modalities: list[str],
    risk: RiskCategory,
    expected: ExpectedBehavior,
    dialog: list[DialogTurn],
    payload_text: Optional[str] = None,
    payload_code: Optional[str] = None,
    media: Optional[list[MediaRef]] = None,
    risk_subtype: Optional[str] = None,
    attack_family: Optional[str] = None,
    turns: int = 1,
    is_agentic: bool = False,
    meta: Optional[dict] = None,
) -> DataPoint:
    """Construct a DataPoint with taxonomy_refs filled from the risk category."""
    return DataPoint(
        id=id,
        source=source,
        modalities=modalities,
        dialog_history=dialog,
        payload_text=payload_text,
        payload_code=payload_code,
        media=media or [],
        risk_category=risk,
        risk_subtype=risk_subtype,
        expected_behavior=expected,
        taxonomy_refs=refs_for(risk),
        attack_family=attack_family,
        turns=turns,
        is_agentic=is_agentic,
        meta=meta or {},
    )


def missing(name: str, path: Path) -> list[DataPoint]:
    logger.warning("%s: path not found: %s (returning [])", name, path)
    return []
