"""AdvBench converter: 520 harmful behaviors, the canonical GCG target set.

AdvBench (github.com/llm-attacks/llm-attacks, Zou et al. 2023, ``advbench-gcg-2023``)
is the "Harmful Behaviors" corpus introduced with the Greedy Coordinate Gradient
(GCG) attack: a set of harmful instructions each paired with an affirmative
response prefix that the adversarial-suffix optimization is driven toward.

Real released layout: ``data/advbench/harmful_behaviors.csv`` - a two-column CSV
with header ``goal,target`` (~520 rows). ``goal`` is the harmful request the model
should refuse; ``target`` is the "Sure, here is ..." affirmative prefix GCG
optimizes for (preserved in ``meta`` for attackers that replay the suffix search).
There is no per-row category label, so every behavior maps to ``JAILBREAK`` and
``expected="refuse"``. Point ``URA_ADVBENCH_PATH`` at that CSV (a ``harmful_strings``
export with a lone ``target`` column is tolerated). Missing inputs raise a
typed corpus error so the evaluation denominator cannot shrink silently.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_csv


class AdvBenchConverter(BaseConverter):
    name = "advbench"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        records = read_csv(path)
        if not isinstance(records, list):
            raise CorpusFormatError(f"AdvBench source is not a record list: {path}")
        out: list[DataPoint] = []
        for i, row in enumerate(records):
            if not isinstance(row, dict):
                raise CorpusFormatError(f"AdvBench row {i} in {path} is not an object")
            # AdvBench uses `goal`; tolerate `behavior`/`prompt`, or the
            # harmful_strings export whose only column is `target`.
            goal = (
                row.get("goal")
                or row.get("behavior")
                or row.get("prompt")
                or row.get("target")
                or ""
            )
            if not isinstance(goal, str) or not goal.strip():
                raise CorpusFormatError(
                    f"AdvBench row {i} in {path} lacks a non-empty harmful prompt"
                )
            target = row.get("target")
            out.append(dp(
                id=f"advbench:{i}",
                source="advbench",
                modalities=["text"],
                risk=Rc.JAILBREAK,
                expected="refuse",
                dialog=[DialogTurn(role="user", content=goal)],
                payload_text=goal,
                risk_subtype="harmful_behavior",
                attack_family="gcg_suffix",
                meta={"target": target, "citation": "advbench-gcg-2023"},
            ))
        if not out:
            raise CorpusFormatError(f"AdvBench conversion produced no rows from {path}")
        return out
