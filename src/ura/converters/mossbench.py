"""MOSSBench converter: MLLM over-refusal (~300 BENIGN image+text queries).

All items are safe -> expected_behavior=safe_answer (a refusal is the failure).
MOSSBench is inherently multimodal: every item pairs a benign image with a
question, so a record without a resolvable image fails closed rather than being
silently converted into a text-only datapoint (which would change the construct).

Accepted layouts:
  * the released metadata table as ``information.csv``/``metadata.csv`` (or a
    JSON/JSONL export) whose rows carry a question column, an image reference,
    and optional pid / oversensitivity-type / short-description columns; or
  * a directory containing one of those tables with the images beside it.
Column names are matched against documented aliases below; a required column
that is absent fails closed, so confirm the exact header against the release.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import (
    CorpusFormatError,
    Rc,
    dp,
    image,
    missing,
    read_csv,
    read_json,
    read_jsonl,
)

# Column names follow the official release: GitHub information.csv has
# pid, question, image_path, short description, description, meta_data_over, ...;
# the Hugging Face release uses metadata_over for the oversensitivity type.
_QUESTION_KEYS = ("question", "prompt", "instruction", "query")
_IMAGE_KEYS = ("image_path", "image", "img", "file_name", "image_file")
_PID_KEYS = ("pid", "id", "pair_id", "index")
_OVER_KEYS = ("meta_data_over", "metadata_over", "over", "type", "category")
_DESC_KEYS = ("short description", "short_description", "description")
_TABLE_FILES = (
    "information.csv", "metadata.csv", "data.csv",
    "information.json", "metadata.json", "mossbench.json",
)


def _first(rec: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = rec.get(key)
        if value not in (None, ""):
            return value
    return None


class MOSSBenchConverter(BaseConverter):
    name = "mossbench"

    def _load(self, path: Path) -> tuple[Any, Path]:
        """Return ``(records, media_root)`` for a file or a release directory."""
        if path.is_dir():
            for candidate in _TABLE_FILES:
                table = path / candidate
                if table.is_file():
                    return self._read_table(table), path
            jsonl = sorted(path.glob("*.jsonl"))
            if jsonl:
                return read_jsonl(jsonl[0]), path
            raise CorpusFormatError(
                f"MOSSBench directory has no information.csv/metadata.csv or "
                f"JSON/JSONL table: {path}"
            )
        if not path.is_file():
            return missing(self.name, path), path  # missing() raises
        return self._read_table(path), path.parent

    @staticmethod
    def _read_table(path: Path) -> Any:
        if path.suffix == ".csv":
            return read_csv(path)
        if path.suffix == ".jsonl":
            return read_jsonl(path)
        records = read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", []))
        return records

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        records, root = self._load(path)
        if not isinstance(records, list):
            raise CorpusFormatError(f"MOSSBench source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"MOSSBench row {i} in {path} is not an object")
            question = _first(rec, _QUESTION_KEYS)
            if not isinstance(question, str) or not question.strip():
                raise CorpusFormatError(
                    f"MOSSBench row {i} in {path} has no non-empty question"
                )
            nested = rec.get("metadata") if isinstance(rec.get("metadata"), dict) else {}
            img_ref = _first(rec, _IMAGE_KEYS) or _first(nested, _IMAGE_KEYS)
            if not isinstance(img_ref, str) or not img_ref.strip():
                raise CorpusFormatError(
                    f"MOSSBench row {i} in {path} has no image reference; MOSSBench is a "
                    "multimodal over-refusal benchmark and must not become text-only"
                )
            media = [image(img_ref.strip(), root)]
            over = _first(rec, _OVER_KEYS) or _first(nested, _OVER_KEYS)
            pid = _first(rec, _PID_KEYS)
            desc = _first(rec, _DESC_KEYS) or _first(nested, _DESC_KEYS)
            out.append(dp(
                id=f"mossbench:{pid if pid is not None else i}",
                source="mossbench",
                modalities=["text", "image"],
                risk=Rc.TOXICITY,                 # the safety domain the benign query brushes against
                expected="safe_answer",           # benign: the model SHOULD answer
                dialog=[DialogTurn(role="user", content=question, media=media)],
                payload_text=question,
                media=media,
                risk_subtype=str(over) if over is not None else None,
                attack_family="oversensitivity",
                meta={"short_description": desc},
            ))
        if not out:
            raise CorpusFormatError(f"MOSSBench conversion produced no rows from {path}")
        return out
