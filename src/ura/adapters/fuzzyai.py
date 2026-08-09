"""FuzzyAI engine adapter: mutation-based LLM jailbreak fuzzing.

CyberArk FuzzyAI (Apache-2.0, https://github.com/cyberark/FuzzyAI) is a fuzzing
framework for LLMs that mutates a seed payload into adversarial prompt variants
across 18+ attack modes -- e.g. ascii-smuggling (``asc``), best-of-n (``bon``),
ActorAttack (``act``), WordGame (``wrd``), genetic (``gen``), DAN (``dan``) and
many-shot (``man``). In URA-Bench it represents the automated jailbreak /
prompt-mutation attack family (thesis II.4.x; OWASP LLM01 Prompt Injection).

Safety (thesis N5, III.2.4): this adapter drives FuzzyAI in prompt-GENERATION
mode only. It runs the ``fuzzyai fuzz`` CLI to materialise the mutated attack
prompts for the seed and reads them back as Attempts; the harness's own
evaluation loop is what later judges a target model on those prompts. The
adapter never uses FuzzyAI to autonomously execute or score a live exploit chain
against a production system. Authorized testing only.

FuzzyAI ships a Python CLI (``fuzzyai``) but no stable in-process API for
one-shot mutation, so this is a CLI bridge (cf. :class:`T3MP3STAttacker` /
:class:`PromptfooAttacker`). The module imports with only stdlib + pydantic
present; the tool is required only when :meth:`generate` is actually invoked,
guarded via ``shutil.which("fuzzyai")``.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt


class FuzzyAIAttacker(BaseAttacker):
    """Drive the FuzzyAI fuzzer in generation mode to produce mutated jailbreak
    prompts for the seed as Attempts (no live exploit execution)."""

    name = "fuzzyai"

    def __init__(
        self,
        attacks: list[str] | None = None,
        model: str = "ollama/llama3",
        cli: str = "fuzzyai",
    ) -> None:
        # FuzzyAI attack-mode short codes (repeatable ``-a``); the mutated prompts
        # they emit for the seed are what we harvest as attempts.
        self.attacks = attacks or ["asc", "bon"]
        # FuzzyAI's CLI requires a ``-m`` target; a local model keeps generation
        # offline. We only read back the mutated prompts, never a live verdict.
        self.model = model
        self.cli = cli

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompts = self._mutated_prompts(seed, max(1, budget.max_queries))
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy="+".join(self.attacks),
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={"attacks": self.attacks, "model": self.model, "mode": "generate"},
            )

    def _mutated_prompts(self, seed: str, n: int) -> list[str]:
        """Invoke the FuzzyAI CLI to mutate ``seed`` and read back the generated
        adversarial prompts (lazy; requires the tool). Never executes a live
        exploit chain against a production system (harness safety principle N5)."""
        import json
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path

        if shutil.which(self.cli) is None:
            raise RuntimeError(
                "FuzzyAI is required for FuzzyAIAttacker; install it "
                "(pip install fuzzyai, or git clone "
                "https://github.com/cyberark/FuzzyAI) and expose its CLI on PATH. "
                "Authorized use only."
            )
        cmd = [self.cli, "fuzz", "-m", self.model]
        for attack in self.attacks:
            cmd += ["-a", attack]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fuzz.json"
            # Generation mode: mutate the seed into adversarial variants and write
            # them to ``out``; we do not point FuzzyAI at a live production target.
            cmd += ["-t", seed, "-o", str(out)]
            subprocess.run(cmd, check=True, capture_output=True)
            data = json.loads(out.read_text(encoding="utf-8"))
        prompts = self._extract_prompts(data)
        return prompts[:n] or [seed]

    @staticmethod
    def _extract_prompts(data: object) -> list[str]:
        """Pull the mutated-prompt strings out of FuzzyAI's JSON output, tolerating
        either a bare list or a dict wrapping the runs under a common key."""
        if isinstance(data, dict):
            for key in ("prompts", "results", "attempts", "runs"):
                if key in data:
                    data = data[key]
                    break
        if not isinstance(data, list):
            return []
        out: list[str] = []
        for item in data:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                for field in ("prompt", "attack_prompt", "mutated_prompt", "text"):
                    value = item.get(field)
                    if isinstance(value, str) and value:
                        out.append(value)
                        break
        return [p for p in out if p]
