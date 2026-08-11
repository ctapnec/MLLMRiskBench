"""AgentHarm source converter.

AgentHarm's official score requires an interactive tool environment and its
grading function.  The unified schema can preserve the behavior prompt, target
function names, and grading-function identifier, but this converter does not
pretend that merely sending the prompt to a chat target executes that construct.
Rows are explicitly marked as a prompt-only representation/proxy.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import CorpusFormatError, Rc, dp, missing, read_json


class AgentHarmConverter(BaseConverter):
    name = "agentharm"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        files: Iterable[Path]
        if path.is_dir():
            files = sorted(path.glob("*behaviors*.json"))
            if not files:
                raise CorpusFormatError(
                    f"agentharm: no '*behaviors*.json' files under {path}"
                )
        elif path.is_file():
            files = [path]
        else:
            return missing(self.name, path)

        out: list[DataPoint] = []
        for source_file in files:
            benign_file = "benign" in source_file.name.lower()
            data = read_json(source_file)
            if isinstance(data, dict):
                records = data.get("behaviors")
                canary_guid = data.get("canary_guid")
            elif isinstance(data, list):
                records = data
                canary_guid = None
            else:
                records = None
                canary_guid = None
            if not isinstance(records, list):
                raise CorpusFormatError(
                    f"AgentHarm file lacks a behaviors list: {source_file}"
                )
            for row_index, rec in enumerate(records):
                if not isinstance(rec, dict):
                    raise CorpusFormatError(
                        f"AgentHarm row {row_index} in {source_file} is not an object"
                    )
                prompt = rec.get("prompt")
                if not isinstance(prompt, str) or not prompt.strip():
                    raise CorpusFormatError(
                        f"AgentHarm row {row_index} in {source_file} lacks prompt"
                    )
                tools = rec.get("target_functions") or []
                if not isinstance(tools, list) or not all(isinstance(x, str) for x in tools):
                    raise CorpusFormatError(
                        f"AgentHarm row {row_index} has invalid target_functions"
                    )
                grading_function = rec.get("grading_function")
                benign = benign_file or bool(rec.get("benign", False))
                row_id = rec.get("id", row_index)
                out.append(dp(
                    id=f"agentharm:{source_file.stem}:{row_id}",
                    source="agentharm",
                    modalities=["text", "tool"] if tools else ["text"],
                    risk=Rc.AGENTIC_MISUSE,
                    expected="comply_safely" if benign else "refuse",
                    dialog=[DialogTurn(role="user", content=prompt)],
                    payload_text=prompt,
                    risk_subtype=rec.get("category"),
                    attack_family=(
                        "agentharm_prompt_augmentation"
                        if rec.get("hint_included") or rec.get("detailed_prompt")
                        else None
                    ),
                    is_agentic=bool(tools),
                    extra_refs=["OWASP_ASI:ASI02"] if tools and not benign else None,
                    meta={
                        "target_functions": tools,
                        "grading_function": grading_function,
                        "name": rec.get("name"),
                        "benign": benign,
                        "id_original": rec.get("id_original"),
                        "detailed_prompt": rec.get("detailed_prompt"),
                        "hint_included": rec.get("hint_included"),
                        "canary_guid": canary_guid,
                        "source_construct": "interactive_tool_agent",
                        "execution_mode": "prompt_and_tool_requirements_only",
                        "tools_executed": False,
                        "official_grading_executed": False,
                        "evaluation_scope": "prompt_only_proxy",
                        "common_metrics_eligible": False,
                        "required_metric": "official_agentharm_tool_grading",
                        "source_metric_attackers": ["replay"],
                    },
                ))
        if not out:
            raise CorpusFormatError(f"AgentHarm conversion produced no rows from {path}")
        return out
