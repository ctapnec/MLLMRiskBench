"""Promptfoo engine adapter (Node CLI bridge; thesis II.4.1, III.2.2)."""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt


class PromptfooAttacker(BaseAttacker):
    """Wrap Promptfoo's red-team plugin generation (Node CLI bridge).

    Promptfoo is a Node.js tool; there is no Python binding. We shell out to the
    ``promptfoo`` CLI to synthesise adversarial test cases and read them back.
    """

    name = "promptfoo"

    def __init__(self, plugin: str = "harmful", num_tests: int = 1) -> None:
        self.plugin = plugin
        self.num_tests = num_tests

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompts = self._redteam_prompts(seed, max(1, budget.max_queries))
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy=self.plugin,
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={"plugin": self.plugin},
            )

    def _redteam_prompts(self, seed: str, n: int) -> list[str]:
        """Invoke the promptfoo CLI to generate red-team prompts (lazy)."""
        import json
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path

        if shutil.which("promptfoo") is None:
            raise RuntimeError(
                "promptfoo is required for PromptfooAttacker; "
                "npm install -g promptfoo"
            )
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "redteam.json"
            subprocess.run(
                [
                    "promptfoo",
                    "redteam",
                    "generate",
                    "--plugins",
                    self.plugin,
                    "--purpose",
                    seed,
                    "--max-tests",
                    str(min(n, self.num_tests)),
                    "--output",
                    str(out),
                ],
                check=True,
                capture_output=True,
            )
            data = json.loads(out.read_text(encoding="utf-8"))
        tests = data.get("tests", data) if isinstance(data, dict) else data
        prompts = [
            t.get("vars", {}).get("prompt", "")
            for t in tests
            if isinstance(t, dict)
        ]
        return [p for p in prompts if p] or [seed]
