"""R-Judge converter: agentic judgment over recorded tool-use trajectories.

data/<Category>/*.json; ``contents`` is a list of turn-groups (a list of lists of
message dicts); agent text lives in ``action`` (plus optional ``thought``);
label 1 = unsafe.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, missing, read_json


class RJudgeConverter(BaseConverter):
    name = "rjudge"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        files: Iterable[Path]
        if path.is_dir():
            files = sorted(path.rglob("*.json"))
        elif path.is_file():
            files = [path]
        else:
            return missing(self.name, path)

        out: list[DataPoint] = []
        for f in files:
            try:
                records = read_json(f)
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(records, list):
                continue
            stem = f.stem
            for rec in records:
                dialog: list[DialogTurn] = []
                for group in rec.get("contents", []):
                    for msg in group:
                        role = msg.get("role")
                        if role == "user":
                            dialog.append(DialogTurn(role="user", content=msg.get("content") or ""))
                        elif role == "agent":
                            thought = msg.get("thought")
                            action = msg.get("action") or ""
                            content = (f"Thought: {thought}\n" if thought else "") + action
                            dialog.append(DialogTurn(role="assistant", content=content))
                        elif role == "environment":
                            if msg.get("content"):
                                dialog.append(DialogTurn(role="tool", content=msg["content"]))
                attack_type = rec.get("attack_type")
                risk = Rc.PROMPT_INJECTION_INDIRECT if attack_type == "injection" else Rc.AGENTIC_MISUSE
                unsafe = rec.get("label") == 1
                out.append(dp(
                    id=f"rjudge:{stem}:{rec.get('id')}",
                    source="rjudge",
                    modalities=["text"],
                    risk=risk,
                    expected="refuse" if unsafe else "comply_safely",
                    dialog=dialog,
                    payload_text=rec.get("risk_description"),
                    risk_subtype=rec.get("scenario") or attack_type,
                    attack_family=attack_type,
                    turns=len(rec.get("contents", [])) or 1,
                    is_agentic=True,
                    meta={"label": rec.get("label"), "profile": rec.get("profile")},
                ))
        return out
