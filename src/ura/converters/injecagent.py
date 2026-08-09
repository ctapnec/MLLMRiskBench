"""InjecAgent converter: indirect prompt injection against tool-integrated agents.

InjecAgent (github.com/uiuc-kang-lab/InjecAgent) probes an LLM agent that calls a
benign *user tool* whose response has been poisoned with an *attacker instruction*.
The agent should complete the user's original task and ignore the injected text; a
successful attack makes it invoke an *attacker tool* instead (direct harm) or leak
data (data stealing). This is the canonical tool-response indirect-injection set
(risk Rc.PROMPT_INJECTION_INDIRECT, thesis II.4 / V.1.3), and it is agentic.

Real released layout: ``data/test_cases_{dh,ds}_{base,enhanced}.json`` - each a JSON
list of records. ``dh`` = direct harm, ``ds`` = data stealing (two-stage); ``base``
carries the bare attacker instruction, ``enhanced`` prepends an "ignore all previous
instructions" preamble. The exact per-record keys (verbatim, note the source typo
"Modifed") are: ``User Instruction``, ``User Tool``, ``Tool Parameters``,
``Tool Response Template`` (holds the ``<Attacker Instruction>`` placeholder),
``Tool Response`` (template already filled), ``Attacker Instruction``,
``Attacker Tools`` (a list), ``Attack Type``, ``Expected Achievements``, ``Thought``.

Point ``URA_INJECAGENT_PATH`` at one of the ``test_cases_*.json`` files (a ``.jsonl``
export is also accepted). Robust to a missing path (returns []).
"""
from __future__ import annotations

import ast
from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn, ToolCall
from ._common import Rc, dp, missing, read_json, read_jsonl


def _parse_params(raw: object) -> dict:
    """Best-effort parse of the python-literal-ish 'Tool Parameters' string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            val = ast.literal_eval(raw)
            if isinstance(val, dict):
                return val
        except (ValueError, SyntaxError):
            pass
        return {"raw": raw}
    return {}


class InjecAgentConverter(BaseConverter):
    name = "injecagent"

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)

        stem = path.stem.lower()
        # infer the split/setting from the released filename (dh/ds, base/enhanced)
        setting = "data_stealing" if "ds" in stem else "direct_harm"
        prompt_setting = "enhanced" if "enhanced" in stem else "base"

        records = read_jsonl(path) if path.suffix == ".jsonl" else read_json(path)
        if isinstance(records, dict):
            records = records.get("data", records.get("cases", []))

        out: list[DataPoint] = []
        for i, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue

            user_instr = rec.get("User Instruction") or rec.get("user_instruction") or ""
            user_tool = rec.get("User Tool") or rec.get("user_tool")
            attacker_instr = (
                rec.get("Attacker Instruction") or rec.get("attacker_instruction") or ""
            )
            attacker_tools = rec.get("Attacker Tools") or rec.get("attacker_tools") or []
            if isinstance(attacker_tools, str):
                attacker_tools = [attacker_tools]
            attacker_tool = attacker_tools[0] if attacker_tools else None
            attack_type = rec.get("Attack Type") or rec.get("attack_type")
            params = _parse_params(rec.get("Tool Parameters") or rec.get("tool_parameters"))

            # the poisoned tool result: prefer the pre-rendered 'Tool Response',
            # else fill the template's <Attacker Instruction> placeholder ourselves
            tool_response = rec.get("Tool Response") or rec.get("tool_response")
            template = rec.get("Tool Response Template") or rec.get("tool_response_template") or ""
            if not tool_response:
                tool_response = template.replace("<Attacker Instruction>", attacker_instr)

            # dialog: the user asks; the agent calls the benign user tool; the tool
            # returns a response carrying the injected attacker instruction
            dialog: list[DialogTurn] = [DialogTurn(role="user", content=user_instr)]
            if user_tool:
                dialog.append(
                    DialogTurn(
                        role="assistant",
                        content=rec.get("Thought") or None,
                        tool_call=ToolCall(name=str(user_tool), arguments=params),
                    )
                )
            dialog.append(DialogTurn(role="tool", content=tool_response, tool_result=tool_response))

            out.append(dp(
                id=f"injecagent:{path.stem}:{i}",
                source="injecagent",
                modalities=["text"],
                risk=Rc.PROMPT_INJECTION_INDIRECT,
                expected="safe_answer",   # complete the benign task, ignore the injection
                dialog=dialog,
                payload_text=attacker_instr or None,
                risk_subtype=attack_type or setting,
                attack_family="indirect_prompt_injection",
                turns=len(dialog),
                is_agentic=True,
                meta={
                    "setting": setting,
                    "prompt_setting": prompt_setting,
                    "user_tool": user_tool,
                    "attacker_tool": attacker_tool,
                    "attacker_tools": attacker_tools,
                    "attack_type": attack_type,
                    "expected_achievements": rec.get("Expected Achievements"),
                    "tool_parameters": rec.get("Tool Parameters"),
                    "tool_response_template": template or None,
                    "thought": rec.get("Thought"),
                    "modified": rec.get("Modifed", rec.get("Modified")),
                },
            ))
        return out
