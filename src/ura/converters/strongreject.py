"""StrongREJECT converter for the pinned 313-prompt official release.

Columns: category, source, forbidden_prompt. Category is a harm bucket that does
not map 1:1 to the unified taxonomy, so the original label is preserved in
risk_subtype.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import (
    CorpusFormatError,
    Rc,
    dp,
    missing,
    read_csv,
    sha256_normalized_text_file,
)
from .release_specs import (
    CORPUS_RELEASE_SPECS,
    STRONGREJECT_CATEGORIES,
    STRONGREJECT_DATASET_SHA256,
)

CATEGORY_MAP = {
    "Illegal goods and services": Rc.LEGALITY,
    "Non-violent crimes": Rc.LEGALITY,
    "Violence": Rc.LEGALITY,
    "Hate, harassment and discrimination": Rc.TOXICITY,
    "Sexual content": Rc.TOXICITY,
    "Disinformation and deception": Rc.HALLUCINATION,
}
_FIELDS = {"category", "source", "forbidden_prompt"}


class StrongRejectConverter(BaseConverter):
    name = "strongreject"
    release_spec = CORPUS_RELEASE_SPECS[name]

    def __init__(
        self,
        *,
        require_complete_release: bool = True,
        verify_manifest_hash: bool = True,
    ) -> None:
        self.require_complete_release = bool(require_complete_release)
        self.verify_manifest_hash = bool(verify_manifest_hash)

    @staticmethod
    def _dataset_path(path: Path) -> Path:
        if path.is_file():
            return path
        candidate = path / "strongreject_dataset" / "strongreject_dataset.csv"
        if candidate.is_file():
            return candidate
        missing("strongreject", path)
        raise AssertionError("unreachable")  # pragma: no cover

    def parse(self, path: Path) -> list[DataPoint]:
        path = self._dataset_path(Path(path))
        records = read_csv(path)
        if not isinstance(records, list):
            raise CorpusFormatError(f"StrongREJECT source is not a record list: {path}")
        if not records:
            raise CorpusFormatError(
                f"StrongREJECT conversion produced no rows from {path}"
            )
        if any(set(row) != _FIELDS for row in records):
            raise CorpusFormatError(
                "StrongREJECT CSV must contain exactly category, source, and "
                "forbidden_prompt columns"
            )
        if self.require_complete_release and (
            len(records) != self.release_spec.expected_source_records
        ):
            raise CorpusFormatError(
                f"StrongREJECT release has {len(records)} rows; the pinned release "
                f"requires {self.release_spec.expected_source_records}"
            )

        out: list[DataPoint] = []
        prompts: set[str] = set()
        observed_categories: set[str] = set()
        for i, row in enumerate(records):
            if not isinstance(row, dict):
                raise CorpusFormatError(
                    f"StrongREJECT row {i} in {path} is not an object"
                )
            cat = row.get("category")
            source = row.get("source")
            prompt = row.get("forbidden_prompt")
            if not isinstance(cat, str) or not cat.strip():
                raise CorpusFormatError(
                    f"StrongREJECT row {i} in {path} lacks non-empty category"
                )
            if cat not in STRONGREJECT_CATEGORIES:
                raise CorpusFormatError(
                    f"StrongREJECT row {i} has unknown official category {cat!r}"
                )
            if not isinstance(source, str) or not source.strip():
                raise CorpusFormatError(
                    f"StrongREJECT row {i} in {path} lacks non-empty source"
                )
            if not isinstance(prompt, str) or not prompt.strip():
                raise CorpusFormatError(
                    f"StrongREJECT row {i} in {path} lacks forbidden_prompt"
                )
            if prompt in prompts:
                raise CorpusFormatError(
                    f"StrongREJECT release contains duplicate forbidden_prompt at row {i}"
                )
            prompts.add(prompt)
            observed_categories.add(cat)
            out.append(dp(
                id=f"strongreject:{i}",
                source="strongreject",
                modalities=["text"],
                risk=CATEGORY_MAP[cat],
                expected="refuse",
                dialog=[DialogTurn(role="user", content=prompt)],
                payload_text=prompt,
                risk_subtype=cat,
                meta={
                    "source": source,
                    "release_revision": self.release_spec.upstream_revision,
                    "release_manifest_sha256": STRONGREJECT_DATASET_SHA256,
                    "official_evaluator_executed": False,
                    "evaluator_scope": "strongreject_style_not_official_runtime",
                },
            ))

        if self.require_complete_release and observed_categories != set(
            STRONGREJECT_CATEGORIES
        ):
            raise CorpusFormatError(
                "StrongREJECT release does not contain the exact six-category inventory"
            )
        if self.require_complete_release and self.verify_manifest_hash:
            observed_digest = sha256_normalized_text_file(path)
            if observed_digest != STRONGREJECT_DATASET_SHA256:
                raise CorpusFormatError(
                    "StrongREJECT dataset SHA-256 mismatch: expected "
                    f"{STRONGREJECT_DATASET_SHA256}, observed {observed_digest}"
                )
        return out
