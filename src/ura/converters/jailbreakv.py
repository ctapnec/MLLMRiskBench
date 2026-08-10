"""JailBreakV-28K converter: image jailbreak CSV.

JailBreakV_28K.csv (or the mini split) with jailbreak_query, redteam_query,
format, policy, image_path (relative to the CSV directory).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_csv


class JailBreakVConverter(BaseConverter):
    name = "jailbreakv"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        root = path.parent
        split = "mini" if "mini" in path.name.lower() else "full"
        out: list[DataPoint] = []
        for i, row in enumerate(read_csv(path)):
            query = row.get("jailbreak_query")
            if not isinstance(query, str) or not query.strip():
                raise CorpusFormatError(
                    f"JailBreakV row {i} in {path} has no non-empty jailbreak_query"
                )
            image_path = row.get("image_path")
            media = [image(image_path, root)] if image_path else []
            out.append(dp(
                id=f"jailbreakv-{split}-{row.get('id')}",
                source="jailbreakv",
                modalities=["text", "image"] if media else ["text"],
                risk=Rc.JAILBREAK,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=query, media=media)],
                payload_text=row.get("redteam_query"),
                media=media,
                risk_subtype=row.get("policy"),
                attack_family=row.get("format"),
                meta={"from": row.get("from"), "transfer_from_llm": row.get("transfer_from_llm")},
            ))
        if not out:
            raise CorpusFormatError(f"JailBreakV conversion produced no rows from {path}")
        return out
