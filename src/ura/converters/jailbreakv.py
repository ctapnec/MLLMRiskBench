"""JailBreakV-28K converter: image jailbreak CSV.

JailBreakV_28K.csv (or the mini split) with jailbreak_query, redteam_query,
format, policy, image_path (relative to the CSV directory).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
import hashlib

from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, image, missing, read_csv


def _intent_cluster_id(intent: object, *, fallback: str) -> str:
    """Cluster key for one released red-team intent, shared by its variants."""

    if not isinstance(intent, str) or not intent.strip():
        return fallback
    normalized = " ".join(intent.split()).casefold().encode("utf-8")
    return f"jailbreakv:{hashlib.sha256(normalized).hexdigest()[:16]}"


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
            if not isinstance(image_path, str) or not image_path.strip():
                raise CorpusFormatError(
                    f"JailBreakV row {i} in {path} lacks its required image_path"
                )
            media = [image(image_path, root)]
            out.append(dp(
                id=f"jailbreakv-{split}-{row.get('id')}",
                source="jailbreakv",
                modalities=["text", "image"],
                risk=Rc.JAILBREAK,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=query, media=media)],
                payload_text=row.get("redteam_query"),
                media=media,
                risk_subtype=row.get("policy"),
                attack_family=row.get("format"),
                meta={
                    "from": row.get("from"),
                    "transfer_from_llm": row.get("transfer_from_llm"),
                    # The release applies several jailbreak templates and images
                    # to one underlying red-team intent, so the row id is not the
                    # independent unit: on the pinned image-backed split, 360 rows
                    # carry only 190 distinct intents. Without this the Runner
                    # falls back to the datapoint id and counts every variant as
                    # its own cluster, which inflates the nominal independent
                    # count and narrows the interval. The release ships no intent
                    # identifier, only the text, so the key is a digest of the
                    # whitespace- and case-normalized intent: deterministic,
                    # order-independent, and stable across runs.
                    "source_cluster_id": _intent_cluster_id(
                        row.get("redteam_query"), fallback=f"jailbreakv-{split}-{row.get('id')}"
                    ),
                    # The released red-team query is grading-only context.  It
                    # is not sent through the target text channel; the carrier
                    # remains the source jailbreak query plus physical image.
                    "judge_reference_text": (
                        row.get("redteam_query").strip()
                        if isinstance(row.get("redteam_query"), str)
                        and row.get("redteam_query").strip()
                        else None
                    ),
                    "judge_reference_kind": (
                        "source_redteam_query_not_sent_to_target"
                        if isinstance(row.get("redteam_query"), str)
                        and row.get("redteam_query").strip()
                        else None
                    ),
                },
            ))
        if not out:
            raise CorpusFormatError(f"JailBreakV conversion produced no rows from {path}")
        return out
