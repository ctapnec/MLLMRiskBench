"""StrongREJECT converter: 313 forbidden text prompts CSV.

Columns: category, source, forbidden_prompt. Category is a harm bucket that does
not map 1:1 to the unified taxonomy, so the original label is preserved in
risk_subtype.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_csv

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
        records = read_csv(path)
        if not isinstance(records, list):
            raise CorpusFormatError(f"StrongREJECT source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, row in enumerate(records):
            if not isinstance(row, dict):
                raise CorpusFormatError(
                    f"StrongREJECT row {i} in {path} is not an object"
                )
            cat = row.get("category") or ""
            prompt = row.get("forbidden_prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise CorpusFormatError(
                    f"StrongREJECT row {i} in {path} lacks forbidden_prompt"
                )
            out.append(dp(
                id=f"strongreject:{i}",
                source="strongreject",
                modalities=["text"],
                risk=CATEGORY_MAP.get(cat, Rc.LEGALITY),
                expected="refuse",
                dialog=[DialogTurn(role="user", content=prompt)],
                payload_text=prompt,
                risk_subtype=cat,
                meta={"source": row.get("source")},
            ))
        if not out:
            raise CorpusFormatError(
                f"StrongREJECT conversion produced no rows from {path}"
            )
        return out
