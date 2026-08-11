"""MM-SafetyBench converter for all three official image-pair variants.

The released population contains 1,680 questions in thirteen scenario files.
Each question has SD, TYPO and SD_TYPO image conditions, yielding 5,040 real
text-image pairs.  The converter fails closed on a partial official release by
default and retains the scenario-specific upstream answer-evaluation policy.
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
    read_json,
    sha256_normalized_text_file,
)
from .release_specs import (
    CORPUS_RELEASE_SPECS,
    MM_SAFETYBENCH_POLICY_DESCRIPTORS,
    MM_SAFETYBENCH_MANIFEST_SHA256,
    MM_SAFETYBENCH_SCENARIO_COUNTS,
    MM_SAFETYBENCH_VARIANTS,
    mm_safetybench_policy,
)


def _policy_name(scenario_prefix: str) -> str:
    if scenario_prefix == "08":
        return "political_lobbying_refusal"
    if scenario_prefix == "10":
        return "legal_advice_caution"
    if scenario_prefix == "11":
        return "financial_advice_caution"
    if scenario_prefix == "12":
        return "health_advice_caution"
    if scenario_prefix == "13":
        return "government_decision_refusal"
    return "content_safety"


class MMSafetyConverter(BaseConverter):
    name = "mmsafety"
    variant = "all_official_variants"
    release_spec = CORPUS_RELEASE_SPECS[name]

    def __init__(
        self,
        *,
        require_complete_release: bool = True,
        verify_manifest_hashes: bool = True,
    ) -> None:
        self.require_complete_release = bool(require_complete_release)
        self.verify_manifest_hashes = bool(verify_manifest_hashes)

    @staticmethod
    def _question_dir(path: Path) -> Path:
        if path.is_dir() and path.name == "processed_questions":
            return path
        if (path / "data" / "processed_questions").is_dir():
            return path / "data" / "processed_questions"
        if (path / "processed_questions").is_dir():
            return path / "processed_questions"
        if path.is_dir():
            return path
        missing("mmsafety", path)
        raise AssertionError("unreachable")  # pragma: no cover

    def _scenario_files(self, qdir: Path) -> list[Path]:
        files = sorted(qdir.glob("*.json"))
        if not files:
            raise CorpusFormatError(
                f"MM-SafetyBench conversion produced no rows from {qdir}"
            )
        if self.require_complete_release:
            observed = {file.stem for file in files}
            expected = set(MM_SAFETYBENCH_SCENARIO_COUNTS)
            missing_names = sorted(expected - observed)
            extra_names = sorted(observed - expected)
            if missing_names or extra_names:
                raise CorpusFormatError(
                    "MM-SafetyBench release must contain exactly the 13 official "
                    f"scenario manifests; missing={missing_names}, extra={extra_names}"
                )
        return files

    @staticmethod
    def _variant_question(rec: dict[str, Any], variant: str, *, row: str) -> str:
        field = "Rephrased Question(SD)" if variant == "SD" else "Rephrased Question"
        value = rec.get(field)
        if not isinstance(value, str) or not value.strip():
            raise CorpusFormatError(
                f"MM-SafetyBench row {row} lacks a non-empty question in "
                f"{field!r} for {variant}"
            )
        return value

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        qdir = self._question_dir(path)
        # Official layout keeps imgs beside processed_questions:
        # <root>/data/{processed_questions,imgs}/...
        imgroot = qdir.parent / "imgs"

        out: list[DataPoint] = []
        source_records = 0
        for file in self._scenario_files(qdir):
            scenario = file.stem
            records = read_json(file)
            if self.require_complete_release and self.verify_manifest_hashes:
                observed_digest = sha256_normalized_text_file(file)
                expected_digest = MM_SAFETYBENCH_MANIFEST_SHA256[scenario]
                if observed_digest != expected_digest:
                    raise CorpusFormatError(
                        f"MM-SafetyBench manifest SHA-256 mismatch for {scenario}: "
                        f"expected {expected_digest}, observed {observed_digest}"
                    )
            prefix = scenario.split("-", 1)[0]
            if not isinstance(records, dict):
                raise CorpusFormatError(
                    f"MM-SafetyBench scenario is not an object: {file}"
                )
            if not records:
                raise CorpusFormatError(f"MM-SafetyBench scenario is empty: {file}")
            if self.require_complete_release:
                expected_count = MM_SAFETYBENCH_SCENARIO_COUNTS[scenario]
                if len(records) != expected_count:
                    raise CorpusFormatError(
                        f"MM-SafetyBench {scenario} has {len(records)} source records; "
                        f"the pinned release requires {expected_count}"
                    )
            source_records += len(records)

            policy_name = _policy_name(prefix)
            policy_descriptor = dict(MM_SAFETYBENCH_POLICY_DESCRIPTORS[policy_name])
            source_policy = mm_safetybench_policy(policy_name)
            for qid, record in records.items():
                if not isinstance(record, dict):
                    raise CorpusFormatError(
                        f"MM-SafetyBench row {qid!r} in {file} is not an object"
                    )
                cluster_id = f"mmsafety/{scenario}/{qid}"
                for variant in MM_SAFETYBENCH_VARIANTS:
                    content = self._variant_question(
                        record, variant, row=f"{scenario}/{qid}"
                    )
                    media_ref = image(
                        f"{scenario}/{variant}/{qid}.jpg", imgroot
                    )
                    out.append(dp(
                        id=f"{cluster_id}/{variant}",
                        source="mmsafety",
                        modalities=["text", "image"],
                        risk=Rc.JAILBREAK,
                        # These are adversarial/harmful probes, never benign
                        # utility items, so they belong in the common harmful
                        # denominator and cannot contaminate FRR. The distinct
                        # source policy above remains authoritative: scenarios
                        # 01--07/09 accept any non-unsafe answer, while 08/10--13
                        # impose their narrower refusal/disclaimer conditions.
                        expected="refuse",
                        dialog=[DialogTurn(
                            role="user", content=content, media=[media_ref]
                        )],
                        payload_text=record.get("Key Phrase"),
                        media=[media_ref],
                        risk_subtype=scenario,
                        attack_family=f"image_jailbreak:{variant}",
                        source_policy=source_policy,
                        meta={
                            "source_cluster_id": cluster_id,
                            "official_scenario": scenario,
                            "official_variant": variant,
                            "official_original_question": record.get("Question"),
                            "official_changed_question": record.get("Changed Question"),
                            "official_key_phrase": record.get("Key Phrase"),
                            "official_phrase_type": record.get("Phrase Type"),
                            "official_evaluator_policy": policy_name,
                            "official_evaluator_policy_descriptor": policy_descriptor,
                            "official_evaluator_executed": False,
                            "required_metric": "mmsafety_official_attack_rate",
                            "common_metrics_eligible": True,
                            "common_metric_role": (
                                "secondary cross-benchmark safety proxy; not the "
                                "official scenario-conditioned attack rate"
                            ),
                            "release_revision": self.release_spec.upstream_revision,
                            "release_manifest_sha256": (
                                MM_SAFETYBENCH_MANIFEST_SHA256.get(scenario)
                            ),
                        },
                    ))

        if self.require_complete_release:
            if source_records != self.release_spec.expected_source_records:
                raise CorpusFormatError(
                    f"MM-SafetyBench has {source_records} source records; expected "
                    f"{self.release_spec.expected_source_records}"
                )
            if len(out) != self.release_spec.expected_emitted_points:
                raise CorpusFormatError(
                    f"MM-SafetyBench emitted {len(out)} pairs; expected "
                    f"{self.release_spec.expected_emitted_points}"
                )
        if not out:
            raise CorpusFormatError(
                f"MM-SafetyBench conversion produced no rows from {path}"
            )
        return out


__all__ = ["MMSafetyConverter"]
