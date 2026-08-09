"""AutoDAN-Turbo engine adapter: lifelong self-evolving jailbreak strategy library.

AutoDAN-Turbo (SaFoLab-WISC, MIT) is an automated red-team method that
autonomously discovers, summarizes and reuses jailbreak strategies in a
*lifelong self-evolving* Strategy Library, then composes new attack prompts by
retrieving the strategies most relevant to a target request; it supports a
black-box API attack mode [autodan-turbo-2025]. In URA-Bench it represents the
automated strategy-optimization jailbreak family (thesis II.3.1 / II.4.1,
III.2.2; OWASP LLM01 Prompt Injection / jailbreak).

Interface (github.com/SaFoLab-WISC/AutoDAN-Turbo): the framework ships as a cloned
repo (no PyPI package). It exposes a ``framework`` package -- ``framework.attacker``
(``Attacker.warm_up_attack`` / ``use_strategy`` / ``find_new_strategy``),
``framework.library`` (``Library``) and ``framework.retrival`` (retrieval over
strategy embeddings) -- wired together by ``pipeline.AutoDANTurbo``, plus
``main.py`` / ``test.py`` entry scripts. The evolved Strategy Library is persisted
to disk (e.g. ``./logs`` / ``./logs_r``) and can be reused directly. Because there
is no Python binding to install and the tool is driven through its own interpreter
entry point, this is a CLI bridge in the same shape as PromptfooAttacker /
T3MP3STAttacker / PetriAttacker: it imports with only stdlib present, and the
cloned repo is required only when :meth:`generate` is actually invoked.

Safety (thesis N5, III.2.4): this adapter runs AutoDAN-Turbo in attack-GENERATION
mode only. It retrieves strategies from the (pre-evolved) library and reads back
the strategy-composed jailbreak prompts as Attempts for the harness to judge; it
never drives the harness's own live-exploit / scoring-optimization loop against a
real evaluation target (that live attacker-vs-target loop belongs to Chapter V,
against real models with keys present). Authorized red-team use only.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt


class AutoDANTurboAttacker(BaseAttacker):
    """Drive AutoDAN-Turbo's self-evolving Strategy Library in generation mode to
    produce strategy-composed jailbreak prompts as Attempts (no live exploit loop).

    ``strategy_library`` points at the persisted lifelong library (e.g. ``./logs_r``);
    ``attacker_model`` is the LLM AutoDAN-Turbo composes with in black-box API mode;
    ``repo`` is the cloned checkout (else ``$AUTODAN_TURBO_HOME``); ``script`` is its
    generation entry point.
    """

    name = "autodan"

    def __init__(
        self,
        strategy_library: str | None = None,
        attacker_model: str = "gpt-4o",
        repo: str | None = None,
        script: str = "test.py",
    ) -> None:
        # Persisted evolved Strategy Library, the attacker LLM, the cloned repo dir
        # and the generation entry script that emits the composed prompts.
        self.strategy_library = strategy_library
        self.attacker_model = attacker_model
        self.repo = repo
        self.script = script

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompts = self._compose_prompts(seed, max(1, budget.max_queries))
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy="autodan-turbo:lifelong-library",
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={
                    "attacker_model": self.attacker_model,
                    "strategy_library": self.strategy_library,
                    "mode": "compose",
                },
            )

    def _compose_prompts(self, seed: str, n: int) -> list[str]:
        """Run AutoDAN-Turbo's generation entry over the seed request and read back
        the strategy-composed jailbreak prompts (lazy; requires the cloned repo).

        The repo is located via ``repo`` / ``$AUTODAN_TURBO_HOME`` and driven through
        its own interpreter; a clear RuntimeError is raised if it is absent. Only the
        retrieval + prompt-composition path is exercised, never the harness's own
        live-exploit / scoring loop against a real target (harness safety N5).
        """
        import json
        import os
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        repo = self.repo or os.environ.get("AUTODAN_TURBO_HOME")
        entry = Path(repo, self.script) if repo else None
        if entry is None or not entry.exists():
            raise RuntimeError(
                "AutoDAN-Turbo is required for AutoDANTurboAttacker; clone it "
                "(git clone https://github.com/SaFoLab-WISC/AutoDAN-Turbo) and set "
                "$AUTODAN_TURBO_HOME (or pass repo=...) to the checkout. "
                "Authorized red-team use only."
            )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "prompts.json"
            # Generation/compose mode: retrieve strategies and emit the composed
            # jailbreak prompts to JSON without the harness driving a live target
            # loop (harness safety principle N5).
            cmd = [
                sys.executable, str(entry),
                "--request", seed,
                "--max_prompts", str(n),
                "--attacker_model", self.attacker_model,
                "--output", str(out),
            ]
            if self.strategy_library:
                cmd += ["--strategy_library", self.strategy_library]
            subprocess.run(
                cmd, check=True, capture_output=True, cwd=str(entry.parent)
            )
            data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        items = data.get("prompts", data) if isinstance(data, dict) else data
        prompts = [
            it.get("prompt", "") if isinstance(it, dict) else str(it)
            for it in items
        ] if isinstance(items, list) else []
        return [p for p in prompts if p] or [seed]
