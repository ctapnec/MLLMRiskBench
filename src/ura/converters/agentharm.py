"""AgentHarm converter: agentic misuse.

benchmark/*_behaviors_*.json with {canary_guid, behaviors:[...]}; each behavior
has prompt, category, target_functions, grading_function. Benign files are the
safe counterparts.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, missing, read_json


class AgentHarmConverter(BaseConverter):
    name = "agentharm"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        files: Iterable[Path]
        if path.is_dir():
            files = sorted(path.glob("*behaviors*.json"))
        elif path.is_file():
            files = [path]
        else:
            return missing(self.name, path)

        out: list[DataPoint] = []
        for f in files:
            benign = "benign" in f.name.lower()
            try:
                data = read_json(f)
            except (json.JSONDecodeError, OSError):
                continue
            for rec in data.get("behaviors", []):
                tools = rec.get("target_functions") or []
                out.append(dp(
                    id=f"agentharm:{f.stem}:{rec.get('id')}",
                    source="agentharm",
                    modalities=["text"],
                    risk=Rc.AGENTIC_MISUSE,
                    expected="comply_safely" if benign else "refuse",
                    dialog=[DialogTurn(role="user", content=rec.get("prompt") or "")],
                    payload_text=rec.get("prompt"),
                    risk_subtype=rec.get("category"),
                    attack_family="tool_hint" if rec.get("hint_included") else None,
                    is_agentic=bool(tools),
                    meta={"target_functions": tools, "grading_function": rec.get("grading_function"),
                          "name": rec.get("name"), "benign": benign},
                ))
        return out
