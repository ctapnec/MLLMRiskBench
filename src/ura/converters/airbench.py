"""AIR-Bench 2024 converter: a regulation-grounded aggregator (thesis II.4).

AIR-Bench 2024 (Zeng et al., Stanford CRFM; arXiv:2407.17436) decomposes 8
government regulations and 16 company policies into a four-tier AIR taxonomy
(4 -> 16 -> 45 -> 314 nodes) and ships 5,694 harmful prompts, ~18 framing/
paraphrase variants per L4 leaf. It is the only regulation/policy-derived source
in URA and densely covers societal, political, economic, and rights-related risk
areas the existing jailbreak/cyber/multimodal families under-serve.

Released layout (Hugging Face ``stanford-crfm/air-bench-2024``, config
``default`` split ``test``, exported to JSON/JSONL/parquet-derived): each record
has ``cate-idx`` (the ``L2.L3.L4`` index string), ``l2-name``, ``l3-name``,
``l4-name`` and ``prompt``. There is no answer key - AIR's own metric is a graded
GPT-4o refusal score, an optional source extra; URA re-scores every prompt with
its own judge cascade (common harmful-ASR/refusal).

The unified ``RiskCategory`` is assigned from the exact 16-member ``l2-name``
(fail-closed; unknown/blank raises), refined at ``l3-name`` for the six
heterogeneous L2 categories. Each L4 leaf (``cate-idx``) is one source cluster.
The full ``cate-idx | l4-name`` path is preserved in ``risk_subtype``. Point
``URA_AIRBENCH_PATH`` at the export.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_json, read_jsonl

# Exact 16 AIR L2 categories -> unified RiskCategory (fail-closed on l2-name).
L2_MAP: dict[str, Rc] = {
    "Security Risks": Rc.INFORMATION_SECURITY,
    "Operational Misuses": Rc.LEGALITY,
    "Violence & Extremism": Rc.TOXICITY,
    "Hate/Toxicity": Rc.TOXICITY,
    "Sexual Content": Rc.TOXICITY,
    "Child Harm": Rc.CATASTROPHIC,
    "Self-harm": Rc.CATASTROPHIC,
    "Political Usage": Rc.LEGALITY,
    "Economic Harm": Rc.LEGALITY,
    "Deception": Rc.LEGALITY,
    "Manipulation": Rc.HALLUCINATION,
    "Defamation": Rc.TOXICITY,
    "Fundamental Rights": Rc.LEGALITY,
    "Discrimination/Bias": Rc.BIAS,
    "Privacy": Rc.PRIVACY,
    "Criminal Activities": Rc.LEGALITY,
}

# L3 refinements for the heterogeneous L2 categories, keyed on (l2-name, l3-name).
# Weapons/warfare/extremist-orgs and unsafe autonomous operation of critical
# systems escalate to CATASTROPHIC; mis/disinformation routes to HALLUCINATION.
L3_OVERRIDE: dict[tuple[str, str], Rc] = {
    ("Violence & Extremism", "Military and Warfare"): Rc.CATASTROPHIC,
    ("Violence & Extremism", "Supporting Malicious Organized Groups"): Rc.CATASTROPHIC,
    ("Violence & Extremism", "Weapon Usage & Development"): Rc.CATASTROPHIC,
    ("Operational Misuses", "Autonomous Unsafe Operation of Systems"): Rc.CATASTROPHIC,
    ("Deception", "Mis/disinformation"): Rc.HALLUCINATION,
}


class AirBenchConverter(BaseConverter):
    name = "airbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("rows", records.get("test", records)))
        if not isinstance(records, list) or not records:
            raise CorpusFormatError(
                f"AIR-Bench source is not a non-empty record list: {path}"
            )

        out: list[DataPoint] = []
        seen: set[str] = set()
        leaf_counter: dict[str, int] = {}
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                raise CorpusFormatError(f"AIR-Bench row {i} in {path} is not an object")
            prompt = rec.get("prompt")
            if not isinstance(prompt, str) or not prompt.strip():
                raise CorpusFormatError(
                    f"AIR-Bench row {i} in {path} lacks a non-empty prompt"
                )
            l2 = str(rec.get("l2-name") or "").strip()
            l3 = str(rec.get("l3-name") or "").strip()
            l4 = str(rec.get("l4-name") or "").strip()
            cate_idx = str(rec.get("cate-idx") or "").strip()
            if not l2:
                raise CorpusFormatError(
                    f"AIR-Bench row {i} in {path} lacks a non-empty l2-name"
                )
            if l2 not in L2_MAP:
                raise CorpusFormatError(
                    f"AIR-Bench row {i} in {path} has unknown l2-name {l2!r}; "
                    "extend L2_MAP to admit it"
                )
            if not cate_idx:
                raise CorpusFormatError(
                    f"AIR-Bench row {i} in {path} lacks a non-empty cate-idx"
                )
            risk = L3_OVERRIDE.get((l2, l3), L2_MAP[l2])

            n = leaf_counter.get(cate_idx, 0)
            leaf_counter[cate_idx] = n + 1
            point_id = f"airbench:{cate_idx}#{n}"
            if point_id in seen:
                raise CorpusFormatError(
                    f"AIR-Bench duplicate id {point_id!r} at row {i}"
                )
            seen.add(point_id)

            out.append(dp(
                id=point_id,
                source="airbench",
                modalities=["text"],
                risk=risk,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=prompt)],
                payload_text=prompt,
                risk_subtype=f"{cate_idx} | {l4}" if l4 else cate_idx,
                attack_family="direct_request",
                meta={
                    "source_cluster_id": f"airbench:{cate_idx}",
                    "air_cate_idx": cate_idx,
                    "air_l2": l2,
                    "air_l3": l3 or None,
                    "air_l4": l4 or None,
                    "official_evaluator_executed": False,
                    "evaluator_scope": "air_graded_gpt4o_rubric_not_run_common_metrics_only",
                },
            ))
        return out
