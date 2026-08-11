"""MM-SafetyBench converter: image jailbreak.

data/processed_questions/<Scenario>.json maps id -> question record; images live
at imgs/<Scenario>/{SD,TYPO,SD_TYPO}/<id>.jpg (basename == json key).
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn, ExpectedBehavior
from ._common import CorpusFormatError, Rc, dp, image, missing, read_json

# scenarios 10-13 (legal/financial/health/gov) expect a cautious answer, not refusal
SAFE_ANSWER_SCENARIOS = {"10", "11", "12", "13"}


class MMSafetyConverter(BaseConverter):
    name = "mmsafety"
    variant = "SD_TYPO"  # canonical image variant

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if path.is_dir() and path.name == "processed_questions":
            qdir = path
        elif (path / "data" / "processed_questions").is_dir():
            qdir = path / "data" / "processed_questions"
        elif (path / "processed_questions").is_dir():
            qdir = path / "processed_questions"
        elif path.is_dir():
            qdir = path
        else:
            return missing(self.name, path)
        # Official layout keeps images beside the questions directory:
        # <root>/data/processed_questions/<Scenario>.json and
        # <root>/data/imgs/<Scenario>/<variant>/<id>.jpg. imgs is therefore the
        # sibling of processed_questions, not one level higher.
        imgroot = qdir.parent / "imgs"

        out: list[DataPoint] = []
        for f in sorted(qdir.glob("*.json")):
            scenario = f.stem                       # e.g. 01-Illegal_Activitiy
            prefix = scenario.split("-", 1)[0]
            expected: ExpectedBehavior = "comply_safely" if prefix in SAFE_ANSWER_SCENARIOS else "refuse"
            records = read_json(f)
            if not isinstance(records, dict):
                raise CorpusFormatError(
                    f"MM-SafetyBench scenario is not an object: {f}"
                )
            if not records:
                raise CorpusFormatError(f"MM-SafetyBench scenario is empty: {f}")
            for qid, rec in records.items():
                if not isinstance(rec, dict):
                    raise CorpusFormatError(
                        f"MM-SafetyBench row {qid!r} in {f} is not an object"
                    )
                # SD pairs with "Rephrased Question(SD)"; TYPO/SD_TYPO with "Rephrased Question"
                content = (rec.get("Rephrased Question(SD)") if self.variant == "SD"
                           else rec.get("Rephrased Question")) or rec.get("Question") or ""
                if not isinstance(content, str) or not content.strip():
                    raise CorpusFormatError(
                        f"MM-SafetyBench row {qid!r} in {f} lacks a non-empty question"
                    )
                img = image(f"{scenario}/{self.variant}/{qid}.jpg", imgroot)
                out.append(dp(
                    id=f"mmsafety/{scenario}/{qid}/{self.variant}",
                    source="mmsafety",
                    modalities=["text", "image"],
                    risk=Rc.JAILBREAK,
                    expected=expected,
                    dialog=[DialogTurn(role="user", content=content, media=[img])],
                    payload_text=rec.get("Key Phrase"),
                    media=[img],
                    risk_subtype=scenario,
                    attack_family=f"image_jailbreak:{self.variant}",
                ))
        if not out:
            raise CorpusFormatError(
                f"MM-SafetyBench conversion produced no rows from {path}"
            )
        return out
