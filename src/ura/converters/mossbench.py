"""MOSSBench converter for the official benign image-question population.

MOSSBench measures over-refusal, not generic toxicity.  The 300 released pairs
are all cross-verified benign queries; every official dimension is retained
without inventing meanings for the numeric ``harm`` codes 0--7.
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
from .release_specs import (
    CORPUS_RELEASE_SPECS,
    MOSSBENCH_INFORMATION_CSV_SHA256,
    MOSSBENCH_POLICY_DESCRIPTOR,
    mossbench_policy,
)
from ._common import sha256_normalized_text_file


_QUESTION_KEYS = ("question", "prompt", "instruction", "query")
_IMAGE_KEYS = ("image_path", "image", "img", "file_name", "image_file")
_PID_KEYS = ("pid", "id", "pair_id", "index")
_DESC_KEYS = ("short description", "short_description")
_LONG_DESC_KEYS = ("description",)
_TABLE_FILES = (
    "information.csv", "metadata.csv", "data.csv",
    "information.json", "metadata.json", "mossbench.json",
)
_DIMENSION_KEYS: dict[str, tuple[str, ...]] = {
    "over": ("meta_data_over", "metadata_over", "over", "type", "category"),
    "human": ("meta_data_human", "metadata_human", "human"),
    "child": ("meta_data_child", "metadata_child", "child"),
    "syn": ("meta_data_syn", "metadata_syn", "syn"),
    "ocr": ("meta_data_ocr", "metadata_ocr", "ocr"),
    "harm": ("meta_data_harm", "metadata_harm", "harm"),
}
_OVER_TYPES = {
    "Exaggerated Risk", "Negated Harm", "Counterintuitive Interpretation",
}


def _first(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def _dimension(
    record: dict[str, Any], nested: dict[str, Any], name: str
) -> Any:
    direct = _first(record, _DIMENSION_KEYS[name])
    return direct if direct is not None else _first(nested, _DIMENSION_KEYS[name])


def _binary_dimension(value: Any, *, field: str, row: int) -> int:
    if isinstance(value, bool):
        return int(value)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CorpusFormatError(
            f"MOSSBench row {row} has invalid {field} dimension {value!r}"
        ) from exc
    if parsed not in {0, 1}:
        raise CorpusFormatError(
            f"MOSSBench row {row} has non-binary {field} dimension {value!r}"
        )
    return parsed


def _harm_dimension(value: Any, *, row: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CorpusFormatError(
            f"MOSSBench row {row} has invalid harm dimension {value!r}"
        ) from exc
    if not 0 <= parsed <= 7:
        raise CorpusFormatError(
            f"MOSSBench row {row} has harm dimension outside 0..7: {value!r}"
        )
    return parsed


class MOSSBenchConverter(BaseConverter):
    name = "mossbench"
    release_spec = CORPUS_RELEASE_SPECS[name]

    def __init__(
        self,
        *,
        require_complete_release: bool = True,
        verify_manifest_hash: bool = True,
    ) -> None:
        self.require_complete_release = bool(require_complete_release)
        self.verify_manifest_hash = bool(verify_manifest_hash)

    def _load(self, path: Path) -> tuple[Any, Path]:
        """Return ``(records, media_root)`` for a file or release directory."""
        if path.is_dir():
            for candidate in _TABLE_FILES:
                table = path / candidate
                if table.is_file():
                    return self._read_table(table), path
            jsonl = sorted(path.glob("*.jsonl"))
            if jsonl:
                return read_jsonl(jsonl[0]), path
            raise CorpusFormatError(
                "MOSSBench directory has no information.csv/metadata.csv or "
                f"JSON/JSONL table: {path}"
            )
        if not path.is_file():
            return missing(self.name, path), path  # missing() raises
        return self._read_table(path), path.parent

    @staticmethod
    def _read_table(path: Path) -> Any:
        if path.suffix.lower() == ".csv":
            return read_csv(path)
        if path.suffix.lower() == ".jsonl":
            return read_jsonl(path)
        records = read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", []))
        return records

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        records, root = self._load(path)
        if self.require_complete_release and self.verify_manifest_hash:
            table = path / "information.csv" if path.is_dir() else path
            if table.name != "information.csv" or not table.is_file():
                raise CorpusFormatError(
                    "the pinned MOSSBench release requires official information.csv"
                )
            observed_digest = sha256_normalized_text_file(table)
            if observed_digest != MOSSBENCH_INFORMATION_CSV_SHA256:
                raise CorpusFormatError(
                    "MOSSBench information.csv SHA-256 mismatch: expected "
                    f"{MOSSBENCH_INFORMATION_CSV_SHA256}, observed {observed_digest}"
                )
        if not isinstance(records, list):
            raise CorpusFormatError(f"MOSSBench source is not a record list: {path}")
        if not records:
            raise CorpusFormatError(f"MOSSBench conversion produced no rows from {path}")
        if self.require_complete_release and len(records) != 300:
            raise CorpusFormatError(
                f"MOSSBench release has {len(records)} rows; the pinned release requires 300"
            )

        out: list[DataPoint] = []
        seen_ids: set[str] = set()
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise CorpusFormatError(
                    f"MOSSBench row {index} in {path} is not an object"
                )
            nested = (
                record.get("metadata")
                if isinstance(record.get("metadata"), dict)
                else {}
            )
            question = _first(record, _QUESTION_KEYS)
            if not isinstance(question, str) or not question.strip():
                raise CorpusFormatError(
                    f"MOSSBench row {index} in {path} has no non-empty question"
                )
            image_ref = _first(record, _IMAGE_KEYS) or _first(nested, _IMAGE_KEYS)
            if not isinstance(image_ref, str) or not image_ref.strip():
                raise CorpusFormatError(
                    f"MOSSBench row {index} in {path} has no image reference; "
                    "MOSSBench must not be converted to text-only"
                )
            pid_raw = _first(record, _PID_KEYS)
            pid = str(pid_raw if pid_raw is not None else index)
            if pid in seen_ids:
                raise CorpusFormatError(f"MOSSBench contains duplicate pid {pid!r}")
            seen_ids.add(pid)

            raw_dimensions = {
                name: _dimension(record, nested, name) for name in _DIMENSION_KEYS
            }
            if self.require_complete_release and any(
                value is None for value in raw_dimensions.values()
            ):
                missing_dimensions = sorted(
                    name for name, value in raw_dimensions.items() if value is None
                )
                raise CorpusFormatError(
                    f"MOSSBench row {index} lacks official dimensions: "
                    f"{missing_dimensions}"
                )
            over = raw_dimensions["over"]
            if self.require_complete_release and over not in _OVER_TYPES:
                raise CorpusFormatError(
                    f"MOSSBench row {index} has unknown oversensitivity type {over!r}"
                )

            normalized_dimensions: dict[str, Any] = {"over": over}
            for name in ("human", "child", "syn", "ocr"):
                value = raw_dimensions[name]
                normalized_dimensions[name] = (
                    _binary_dimension(value, field=name, row=index)
                    if value is not None else None
                )
            harm = raw_dimensions["harm"]
            normalized_dimensions["harm"] = (
                _harm_dimension(harm, row=index) if harm is not None else None
            )

            media = [image(image_ref.strip(), root)]
            short_description = _first(record, _DESC_KEYS) or _first(
                nested, _DESC_KEYS
            )
            description = _first(record, _LONG_DESC_KEYS) or _first(
                nested, _LONG_DESC_KEYS
            )
            out.append(dp(
                id=f"mossbench:{pid}",
                source="mossbench",
                modalities=["text", "image"],
                risk=Rc.OVER_REFUSAL,
                expected="safe_answer",
                dialog=[DialogTurn(role="user", content=question, media=media)],
                payload_text=question,
                media=media,
                risk_subtype=str(over) if over is not None else None,
                attack_family="oversensitivity",
                source_policy=mossbench_policy(),
                meta={
                    "source_cluster_id": f"mossbench:{pid}",
                    "short_description": short_description,
                    "description": description,
                    # Preserve the official dimensions exactly as supplied.  The
                    # normalized copy is additive and exists only for validated
                    # grouping; in particular, harm remains an opaque 0..7 code.
                    "official_metadata": raw_dimensions,
                    "official_metadata_normalized": normalized_dimensions,
                    "official_harm_code_semantics": "opaque_source_code_0_to_7",
                    "official_policy_descriptor": dict(MOSSBENCH_POLICY_DESCRIPTOR),
                    "official_evaluator_executed": False,
                    "required_metric": "mossbench_refusal_rate",
                    "common_metrics_eligible": True,
                    "common_metric_role": (
                        "secondary cross-benchmark over-refusal proxy; not the "
                        "official image-conditioned GPT-4 refusal evaluator"
                    ),
                    "release_revision": self.release_spec.upstream_revision,
                    "release_manifest_sha256": (
                        MOSSBENCH_INFORMATION_CSV_SHA256
                    ),
                },
            ))

        if self.require_complete_release:
            expected_ids = {str(value) for value in range(1, 301)}
            if seen_ids != expected_ids:
                raise CorpusFormatError(
                    "MOSSBench pids do not match the pinned official 1..300 population"
                )
        if not out:
            raise CorpusFormatError(f"MOSSBench conversion produced no rows from {path}")
        return out


__all__ = ["MOSSBenchConverter"]
