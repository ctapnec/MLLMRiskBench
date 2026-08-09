"""JailbreakBench converter: JBB-Behaviors robustness set (100 harmful + 100 benign).

JailbreakBench (github.com/JailbreakBench/jailbreakbench, Chao et al. 2024,
``jailbreakbench-2024``) ships JBB-Behaviors, the target set of its open robustness
benchmark: 100 distinct misuse behaviors spread over ten categories drawn from
OpenAI's usage policies, each paired with a thematically matched benign twin
(100 benign behaviors) so that over-refusal can be measured against the same
topics.

Real released layout (HF ``JailbreakBench/JBB-Behaviors``): two CSVs under
``data/`` - ``harmful-behaviors.csv`` and ``benign-behaviors.csv`` (parquet mirror
auto-generated) - each with the header ``Index, Goal, Target, Behavior, Category,
Source``. ``Goal`` is the request, ``Target`` an affirmative "Sure, here is ..."
prefix (preserved in ``meta`` for GCG-style replay), ``Behavior`` a unique slug,
``Category`` one of the ten OpenAI-policy buckets (-> risk), and ``Source`` the
origin (Original / TDC-HarmBench / AdvBench).

Point ``URA_JAILBREAKBENCH_PATH`` at either CSV; the benign subset is detected
from the file name (``"benign"`` in the stem) and its rows carry
``expected="safe_answer"`` (over-refusal probes), while harmful rows carry
``expected="refuse"``. A JSON/JSONL export is also tolerated. Robust to a missing
path (returns []). Mirrors advbench.py / strongreject.py CSV reading.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, missing, read_csv, read_json, read_jsonl

# JBB categories (OpenAI usage policies) -> internal taxonomy. Default LEGALITY
# when unmapped, matching the other harmful-behavior CSV converters.
CATEGORY_MAP = {
    "harassment/discrimination": Rc.TOXICITY,
    "malware/hacking": Rc.CYBERSEC,
    "physical harm": Rc.CATASTROPHIC,
    "economic harm": Rc.LEGALITY,
    "fraud/deception": Rc.LEGALITY,
    "disinformation": Rc.HALLUCINATION,
    "sexual/adult content": Rc.TOXICITY,
    "privacy": Rc.PRIVACY,
    "expert advice": Rc.LEGALITY,
    "government decision-making": Rc.LEGALITY,
}


class JailbreakBenchConverter(BaseConverter):
    name = "jailbreakbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        if path.suffix == ".jsonl":
            records = read_jsonl(path)
        elif path.suffix == ".json":
            records = read_json(path)
        else:
            records = read_csv(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("behaviors", []))
        # Harmful vs benign is a subset (separate file), not a per-row column.
        benign = "benign" in path.stem.lower()
        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            goal = rec.get("Goal") or rec.get("goal") or rec.get("prompt") or ""
            target = rec.get("Target") or rec.get("target")
            behavior = rec.get("Behavior") or rec.get("behavior")
            cat = str(rec.get("Category") or rec.get("category") or "").strip()
            origin = rec.get("Source") or rec.get("source")
            # per-row override in case a combined export tags the subset
            row_kind = str(rec.get("type") or rec.get("behavior_type") or "").strip().lower()
            is_benign = benign or row_kind == "benign"
            risk = CATEGORY_MAP.get(cat.lower(), Rc.LEGALITY)
            rid = rec.get("Index", rec.get("index", behavior if behavior else i))
            kind = "benign" if is_benign else "harmful"
            out.append(dp(
                id=f"jailbreakbench:{kind}:{rid}",
                source="jailbreakbench",
                modalities=["text"],
                risk=risk,
                expected="safe_answer" if is_benign else "refuse",
                dialog=[DialogTurn(role="user", content=goal)],
                payload_text=goal,
                risk_subtype=cat or None,
                attack_family=None if is_benign else "direct_request",
                meta={
                    "target": target,
                    "behavior": behavior,
                    "origin": origin,
                    "subset": kind,
                    "citation": "jailbreakbench-2024",
                },
            ))
        return out
