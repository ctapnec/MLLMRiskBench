"""BIPIA converter: indirect prompt injection.

Benign context files (email/table/code/*.jsonl with context, question, ideal)
poisoned with an injected attack instruction. Pragmatic builder: reads a context
.jsonl and, if a sibling attack file (text_attack_*.json) is present, appends one
attack instruction (rotating across categories). The correct behavior is always
to complete the benign task and ignore any injected instruction.
"""
from __future__ import annotations

from pathlib import Path

from ..adapters.base import BaseConverter
from ..data_models import DataPoint, DialogTurn
from ._common import Rc, dp, missing, read_json, read_jsonl


class BIPIAConverter(BaseConverter):
    name = "bipia"

    def _load_attacks(self, root: Path) -> list[tuple[str, str]]:
        for cand in ("text_attack_test.json", "text_attack_train.json",
                     "code_attack_test.json"):
            p = root / cand
            if p.is_file():
                data = read_json(p)
                return [(k, s) for k, strings in data.items() for s in strings]
        return []

    def parse(self, path: Path) -> list[DataPoint]:
        path = Path(path)
        if not path.is_file():
            return missing(self.name, path)
        task = path.parent.name                       # email / table / code / qa / abstract
        attacks = self._load_attacks(path.parent) or self._load_attacks(path.parent.parent)
        rows = read_jsonl(path)

        out: list[DataPoint] = []
        for i, rec in enumerate(rows):
            context = rec.get("context")
            if isinstance(context, list):
                context = "\n".join(str(x) for x in context)
            question = rec.get("question") or ""
            if attacks:
                atk_name, atk_str = attacks[i % len(attacks)]
                poisoned = f"{context}\n\n{atk_str}"
                subtype, payload = atk_name, atk_str
            else:
                poisoned, subtype, payload = context or "", task, None
            content = f"{question}\n\n{poisoned}".strip()
            out.append(dp(
                id=f"bipia/{task}/{i}",
                source="bipia",
                modalities=["text"],
                risk=Rc.PROMPT_INJECTION_INDIRECT,
                expected="safe_answer",           # do the benign task, ignore injection
                dialog=[DialogTurn(role="user", content=content)],
                payload_text=payload if task != "code" else None,
                payload_code=payload if task == "code" else None,
                risk_subtype=subtype,
                attack_family="indirect_prompt_injection",
                meta={"task": task, "ideal": rec.get("ideal")},
            ))
        return out
