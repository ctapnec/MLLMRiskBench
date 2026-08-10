"""PurpleLlama / CyberSecEval engine adapter: Meta's offensive-cyber and
prompt-injection attack suites driven as a generation engine.

PurpleLlama's CybersecurityBenchmarks harness (github.com/meta-llama/PurpleLlama,
CYBERSECEVAL 3, Wan et al. 2024, ``cyberseceval3-2024``) is Meta's LLM cyber-risk
benchmark runner, driven through ``python -m CybersecurityBenchmarks.benchmark.run
--benchmark <suite>``. Whereas ``converters/cyberseceval.py`` normalises the
*static corpus* a user points a path at, this adapter wraps the harness AS AN
ENGINE: it drives the live attack suites and materialises their generated attack
prompts as Attempts. The suites it wraps are:

* ``prompt-injection`` - textual indirect prompt injection (RiskCategory
  ``prompt_injection_indirect``).
* ``visual-prompt-injection`` - image-carried prompt injection, the textual
  instruction of each case is surfaced (``prompt_injection_indirect``).
* ``interpreter`` - code-interpreter abuse / privilege-escalation payloads
  (RiskCategory ``cybersec``).
* ``multiturn-phishing`` - spear-phishing capability generation (``cybersec``).
* ``autonomous-uplift`` - autonomous offensive-cyber operator prompts
  (``cybersec``).
* ``mitre`` - ATT&CK-mapped offensive-cyber requests (``cybersec``).

License / isolation: CyberSecEval is MIT-licensed, so there is no GPL
contamination concern; nonetheless the harness ships as a cloned repo module with
heavy dependencies, so (like PromptfooAttacker / T3MP3STAttacker /
EasyJailbreakAttacker) it is NEVER imported in-process. A small generation program
runs in a SEPARATE interpreter, imports the CybersecurityBenchmarks package,
harvests each requested suite's attack prompts and writes them back to JSON that
this adapter reads. Only stdlib + pydantic are imported at module load; the harness
lives entirely in the child process.

Safety (thesis N5, III.2.4): this adapter operates in attack-GENERATION / seed
mode only. It materialises the harness's suite-generated cyber and injection
attack prompts as Attempts for URA-Bench to judge later; it never runs the
harness's live loop against a target (never passes a live ``--llm-under-test`` and
never executes an interpreter payload or offensive-cyber action against a real or
third-party system). Authorized red-team use only; unauthorized access to systems
is illegal.

Provisioning: point the adapter at a PurpleLlama checkout via ``$PURPLELLAMA_REPO``
(or ``repo=...``), which is placed on the child ``PYTHONPATH`` so
``CybersecurityBenchmarks`` imports, and/or supply an interpreter with the package
already importable via ``$PURPLELLAMA_PYTHON`` (or ``python=...``).
:meth:`generate` raises a clear RuntimeError when no interpreter can import the
harness.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt

# Map each CybersecurityBenchmarks suite this adapter drives onto the URA
# RiskCategory value its generated prompts belong to. The two prompt-injection
# suites carry indirect prompt injection; the remaining offensive-cyber suites
# (interpreter abuse, spear-phishing, autonomous uplift, MITRE ATT&CK) carry
# cybersec.
_BENCHMARK_RISK = {
    "prompt-injection": "prompt_injection_indirect",
    "visual-prompt-injection": "prompt_injection_indirect",
    "interpreter": "cybersec",
    "multiturn-phishing": "cybersec",
    "autonomous-uplift": "cybersec",
    "mitre": "cybersec",
}

# Generation program run in the SEPARATE interpreter. It imports the harness,
# locates its bundled ``datasets/`` tree, and for each requested benchmark suite
# harvests the suite's attack-prompt strings (tolerating the several record shapes
# CyberSecEval uses: ``mutated_prompt``; ``test_case_prompt`` + ``user_input`` for
# prompt injection; ``base_prompt`` / ``prompt`` / ``system_prompt`` elsewhere). It
# interleaves suites so a mixed budget is represented, writes a JSON document and
# exits 0. It never constructs an LLM-under-test and never drives a live scoring or
# exploit loop (harness safety principle N5); this process only reads that JSON.
_BRIDGE = r'''
import glob
import json
import os
import sys


_SUITE_DIRS = {
    "prompt-injection": "prompt_injection",
    "visual-prompt-injection": "visual_prompt_injection",
    "interpreter": "interpreter",
    "multiturn-phishing": "multiturn_phishing",
    "autonomous-uplift": "autonomous_uplift",
    "mitre": "mitre",
}


def _datasets_dir():
    import CybersecurityBenchmarks as pkg

    for root in list(getattr(pkg, "__path__", []) or []):
        cand = os.path.join(root, "datasets")
        if os.path.isdir(cand):
            return cand
    return None


def _extract(rec):
    if isinstance(rec, str):
        return rec.strip() or None
    if not isinstance(rec, dict):
        return None
    # Prompt-injection cases: keep the app instruction and the adversarial turn.
    if rec.get("user_input") or rec.get("test_case_prompt"):
        sys_t = str(rec.get("test_case_prompt") or "").strip()
        usr = str(rec.get("user_input") or rec.get("mutated_prompt") or "").strip()
        text = (sys_t + "\n\n" + usr).strip() if sys_t else usr
        return text or None
    for key in (
        "mutated_prompt", "prompt", "base_prompt", "mutated_prompt_base",
        "challenge_prompt", "system_prompt", "content", "text",
    ):
        value = rec.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, list) and value:
            joined = " ".join(str(x) for x in value if x).strip()
            if joined:
                return joined
    return None


def _records(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        for key in ("data", "prompts", "test_cases"):
            if isinstance(obj.get(key), list):
                return obj[key]
        flat = []
        for value in obj.values():
            if isinstance(value, list):
                flat.extend(value)
        return flat
    return []


def _harvest(datasets_dir, subdir, limit):
    out = []
    root = os.path.join(datasets_dir, subdir)
    if not os.path.isdir(root):
        return out
    for path in sorted(glob.glob(os.path.join(root, "*.json"))):
        try:
            obj = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        for rec in _records(obj):
            text = _extract(rec)
            if text:
                out.append(text)
            if len(out) >= limit:
                return out
    return out


def main():
    cfg = json.load(open(sys.argv[1], encoding="utf-8"))
    seed = cfg.get("seed") or ""
    benchmarks = cfg.get("benchmarks") or []
    limit = max(1, int(cfg.get("n") or 1))
    out_path = cfg["out"]

    prompts = []
    try:
        datasets_dir = _datasets_dir()
    except Exception:
        datasets_dir = None

    if datasets_dir:
        per_suite = {}
        for bench in benchmarks:
            subdir = _SUITE_DIRS.get(bench)
            if subdir:
                per_suite[bench] = _harvest(datasets_dir, subdir, limit)
        # Interleave across suites so a mixed budget represents each requested one.
        idx = 0
        while len(prompts) < limit:
            added = False
            for bench in benchmarks:
                pool = per_suite.get(bench) or []
                if idx < len(pool):
                    prompts.append({"prompt": pool[idx], "benchmark": bench})
                    added = True
                    if len(prompts) >= limit:
                        break
            if not added:
                break
            idx += 1

    # Seed fallback: if the harness yielded nothing, surface the datapoint payload
    # itself so the caller still gets a suite-tagged attempt.
    if not prompts and seed and benchmarks:
        prompts = [{"prompt": seed, "benchmark": benchmarks[0]}]

    json.dump({"prompts": prompts[:limit]}, open(out_path, "w", encoding="utf-8"))


main()
'''


class PurpleLlamaAttacker(BaseAttacker):
    """Drive PurpleLlama's CybersecurityBenchmarks suites in generation mode, via a
    separate interpreter, to produce cyber and prompt-injection attack prompts as
    Attempts (no live target loop, no live exploit).

    ``benchmarks`` names the CyberSecEval suites to harvest (default
    ``["prompt-injection", "interpreter"]``; any of ``prompt-injection``,
    ``visual-prompt-injection``, ``interpreter``, ``multiturn-phishing``,
    ``autonomous-uplift``, ``mitre``). ``repo`` / ``$PURPLELLAMA_REPO`` locates a
    PurpleLlama checkout placed on the child ``PYTHONPATH``; ``python`` /
    ``$PURPLELLAMA_PYTHON`` selects an interpreter with the ``CybersecurityBenchmarks``
    package importable (defaults to the current interpreter, but only when the
    harness is importable there through a subprocess probe).
    """

    name = "purplellama"

    def __init__(
        self,
        benchmarks: list[str] | None = None,
        python: str | None = None,
        repo: str | None = None,
    ) -> None:
        # CyberSecEval suites whose generated attack prompts we materialise.
        self.benchmarks = benchmarks or ["prompt-injection", "interpreter"]
        # Out-of-process interpreter and cloned harness checkout (never imported here).
        self.python = python
        self.repo = repo

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        items = self._suite_prompts(seed, max(1, budget.max_queries))
        for i, (bench, prompt) in enumerate(items):
            risk = _BENCHMARK_RISK.get(bench, "cybersec")
            yield _attempt(
                datapoint,
                self.name,
                strategy=bench,
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={
                    "benchmark": bench,
                    "benchmarks": self.benchmarks,
                    "risk": risk,
                    "mode": "generate",
                },
            )

    def _interpreter(self) -> str | None:
        """Resolve the interpreter that runs the CyberSecEval generation program.

        Prefers an explicit ``python`` / ``$PURPLELLAMA_PYTHON``, else the current
        interpreter. Returns the path only if it exists on disk / PATH; importability
        of the harness is probed separately (never in-process).
        """
        import os
        import shutil
        import sys
        from pathlib import Path

        candidate = (
            self.python or os.environ.get("PURPLELLAMA_PYTHON") or sys.executable
        )
        if not candidate:
            return None
        if shutil.which(candidate) or Path(candidate).exists():
            return candidate
        return None

    def _child_env(self) -> tuple[dict, str | None]:
        """Build the child environment with the PurpleLlama checkout on PYTHONPATH."""
        import os

        env = dict(os.environ)
        repo = self.repo or os.environ.get("PURPLELLAMA_REPO")
        if repo:
            env["PYTHONPATH"] = repo + os.pathsep + env.get("PYTHONPATH", "")
        return env, repo

    @staticmethod
    def _has_harness(python: str, env: dict) -> bool:
        """Probe - in the child interpreter, never in-process - whether the
        ``CybersecurityBenchmarks`` package is importable there, without importing it
        here."""
        import subprocess

        probe = (
            "import importlib.util, sys; "
            "sys.exit(0 if importlib.util.find_spec('CybersecurityBenchmarks') "
            "else 1)"
        )
        try:
            result = subprocess.run(
                [python, "-c", probe], capture_output=True, timeout=60, env=env
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0

    def _suite_prompts(self, seed: str, n: int) -> list[tuple[str, str]]:
        """Run the CyberSecEval generation program over the requested suites in a
        separate interpreter and read back ``(benchmark, prompt)`` pairs (lazy;
        requires the harness). Never imports ``CybersecurityBenchmarks`` in-process
        and never drives a live target / exploit loop (harness safety principle N5)."""
        import json
        import subprocess
        import tempfile
        from pathlib import Path

        python = self._interpreter()
        env, repo = self._child_env()
        if python is None or not self._has_harness(python, env):
            raise RuntimeError(
                "PurpleLlama CyberSecEval (CybersecurityBenchmarks) is required for "
                "PurpleLlamaAttacker; it is driven from a SEPARATE process. Clone it "
                "(git clone https://github.com/meta-llama/PurpleLlama) and set "
                "$PURPLELLAMA_REPO (or pass repo=...) to the checkout, and/or set "
                "$PURPLELLAMA_PYTHON / python=... to an interpreter with the "
                "CybersecurityBenchmarks package importable. Authorized red-team use "
                "only."
            )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            out = tmp_dir / "prompts.json"
            cfg = tmp_dir / "cfg.json"
            script = tmp_dir / "purplellama_bridge.py"
            cfg.write_text(
                json.dumps(
                    {
                        "seed": seed,
                        "benchmarks": self.benchmarks,
                        "n": n,
                        "out": str(out),
                    }
                ),
                encoding="utf-8",
            )
            script.write_text(_BRIDGE, encoding="utf-8")
            # Generation mode: the child imports the harness, harvests the suite
            # attack prompts to ``out`` and exits; no live target is driven.
            subprocess.run(
                [python, str(script), str(cfg)],
                check=True,
                capture_output=True,
                env=env,
                cwd=repo or None,
            )
            data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        items = data.get("prompts", []) if isinstance(data, dict) else data
        default_bench = self.benchmarks[0] if self.benchmarks else "prompt-injection"
        pairs: list[tuple[str, str]] = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict):
                prompt = it.get("prompt", "")
                bench = it.get("benchmark", default_bench)
            else:
                prompt = str(it)
                bench = default_bench
            if prompt:
                pairs.append((bench, prompt))
        if not pairs and seed:
            pairs = [(default_bench, seed)]
        return pairs[:n]
