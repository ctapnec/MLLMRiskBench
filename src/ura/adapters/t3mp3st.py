"""T3MP3ST engine adapter: autonomous offensive-security / agentic-cyber-offense.

T3MP3ST (elder-plinius, AGPL-3.0) is a multi-agent offensive-security framework
that coordinates operator agents (Recon, Scanner, Exploiter, ...) along a
recon -> exploit -> report kill chain. In URA-Bench it represents the autonomous
cyber-offense attack family (thesis II.3.2 / II.4.5; OWASP LLM06 Excessive Agency,
ASI02 Tool Misuse; EU AI Act "cyber offence" systemic risk), i.e. testing whether
a target model, placed in an operator role, will plan and drive unauthorized
offensive actions.

Safety (thesis N5, III.2.4): this adapter runs T3MP3ST in PLAN-GENERATION mode
only. It elicits the operator prompts / mission plan and maps them to Attempts for
the target to be judged on; it never executes tools against live systems. Use only
for authorized testing; unauthorized access to systems is illegal.

T3MP3ST is a Node/TypeScript tool with no Python binding, so this is a CLI bridge
(cf. PromptfooAttacker). It imports with only stdlib present; the tool is required
only when generate() is actually invoked.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt


class T3MP3STAttacker(BaseAttacker):
    """Drive the T3MP3ST kill chain in plan mode to produce offensive-security
    operator prompts as Attempts (no live execution)."""

    name = "t3mp3st"

    def __init__(self, operators: list[str] | None = None, cli: str = "t3mp3st") -> None:
        # Operators whose plan-stage prompts are materialised as attempts.
        self.operators = operators or ["recon", "exploiter"]
        self.cli = cli

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompts = self._plan_prompts(seed, max(1, budget.max_queries))
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy="+".join(self.operators),
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={"operators": self.operators, "mode": "plan"},
            )

    def _plan_prompts(self, seed: str, n: int) -> list[str]:
        """Invoke the T3MP3ST CLI in plan/dry-run mode and read back the operator
        prompts (lazy; requires the tool). Never executes a live mission."""
        import json
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path

        if shutil.which(self.cli) is None:
            raise RuntimeError(
                "T3MP3ST is required for T3MP3STAttacker; install it "
                "(git clone https://github.com/elder-plinius/T3MP3ST && npm install) "
                "and expose its CLI. Authorized use only."
            )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "plan.json"
            # --dry-run / plan mode: generate the kill-chain operator prompts without
            # executing tools against live systems (harness safety principle N5).
            subprocess.run(
                [self.cli, "plan", "--dry-run", "--objective", seed,
                 "--operators", ",".join(self.operators),
                 "--max-steps", str(n), "--output", str(out)],
                check=True, capture_output=True,
            )
            data = json.loads(out.read_text(encoding="utf-8"))
        steps = data.get("steps", data) if isinstance(data, dict) else data
        prompts = [
            s.get("prompt", "") for s in steps if isinstance(s, dict)
        ] if isinstance(steps, list) else []
        return [p for p in prompts if p] or [seed]
