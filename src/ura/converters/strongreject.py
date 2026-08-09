"""StrongREJECT converter: 313 forbidden text prompts CSV.

Columns: category, source, forbidden_prompt. Category is a harm bucket that does
not map 1:1 to the unified taxonomy, so the original label is preserved in
risk_subtype.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, missing, read_csv

CATEGORY_MAP = {
    "Illegal goods and services": Rc.LEGALITY,
    "Non-violent crimes": Rc.LEGALITY,
    "Violence": Rc.LEGALITY,
    "Hate/harassment/discrimination": Rc.TOXICITY,
    "Sexual content": Rc.TOXICITY,
    "Disinformation and deception": Rc.HALLUCINATION,
}


class StrongRejectConverter(BaseConverter):
    name = "strongreject"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        out: list[DataPoint] = []
        for i, row in enumerate(read_csv(path)):
            cat = row.get("category") or ""
            out.append(dp(
                id=f"strongreject:{i}",
                source="strongreject",
                modalities=["text"],
                risk=CATEGORY_MAP.get(cat, Rc.LEGALITY),
                expected="refuse",
                dialog=[DialogTurn(role="user", content=row.get("forbidden_prompt") or "")],
                payload_text=row.get("forbidden_prompt"),
                risk_subtype=cat,
                meta={"source": row.get("source")},
            ))
        return out
