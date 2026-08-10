"""HarmBench engine adapter: standardized red-team algorithm suite.

HarmBench (centerforaisafety/HarmBench, MIT) is a standardized evaluation
framework that packages ~18 published red-team ALGORITHMS behind one
``RedTeamingMethod`` abstraction and a common test-case generation pipeline
[harmbench-2024]. Each method turns a HarmBench *behavior* into one or more
concrete adversarial *test cases*. In URA-Bench this adapter represents the
optimization / automated red-team algorithm family (thesis II.3.1 / II.4.1,
III.2.2; OWASP LLM01 Prompt Injection / jailbreak; RiskCategory.JAILBREAK),
and specifically brings in the algorithms URA otherwise lacks:

  - PEZ        -- hard-prompt optimization via soft-prompt projection
  - GBDA       -- Gradient-Based Distributional Attack
  - UAT         -- Universal Adversarial Triggers
  - AutoPrompt  -- gradient-guided discrete trigger search
  - PAP-top5    -- Persuasive Adversarial Prompts (persuasion taxonomy)
  - MultiModal* -- image optimizers (e.g. MultiModalPGD / MultiModalRenderText)
    that craft adversarial / typographic images for vision-language targets

(it also exposes GCG / GCG-Multi / GCG-Transfer, AutoDAN, PAIR, TAP,
DirectRequest, HumanJailbreaks and ZeroShot, which overlap with existing URA
engines). The gradient / white-box optimizers (PEZ, GBDA, UAT, AutoPrompt, GCG)
and the multimodal image optimizers run a search against a local open-weight
target and need a GPU; the persuasion / model-driven methods (PAP, PAIR, TAP)
call an attacker LLM.

Dual role (NOT the corpus converter): this attacker wraps HarmBench AS AN ATTACK
FRAMEWORK and is distinct from :mod:`ura.converters.harmbench`, which merely
ingests the HarmBench behaviors CSV into DataPoints. The two share the
registered name "harmbench" only because ``get_attacker`` and ``get_converter``
are separate registries.

Interface (github.com/centerforaisafety/HarmBench): HarmBench ships as a cloned
repo (no PyPI package) driven through its own entry scripts -- ``generate_test_cases.py``
(step 1) followed by ``merge_test_cases.py`` (step 1.5), or the ``scripts/run_pipeline.py``
orchestrator. ``generate_test_cases.py`` takes ``--method_name``, ``--experiment_name``
(the target model / experiment config key), ``--behaviors_path`` (a HarmBench-format
behaviors CSV), ``--save_dir`` and ``--behavior_start_idx`` / ``--behavior_end_idx``;
``merge_test_cases.py`` collapses the per-behavior outputs into a single
``{save_dir}/test_cases.json`` -- a dict mapping ``BehaviorID`` to a list of test
cases (a string for text methods, or an ``[image_path, text]`` pair for the
multimodal image optimizers). Because there is no Python binding to install and the
tool is run through its own interpreter entry point, this is a CLI / subprocess
bridge in the same shape as :class:`AutoDANTurboAttacker` / :class:`T3MP3STAttacker`:
it imports with only stdlib + pydantic present, and the cloned repo is required only
when :meth:`generate` is actually invoked.

Safety (thesis N5, III.2.4): this adapter runs HarmBench in attack-GENERATION mode
only. It writes a one-behavior seed CSV, runs the requested methods' test-case
generation, and reads the produced adversarial test cases back as Attempts for the
harness to judge later; it never lets HarmBench drive a live attacker-vs-target
completion / scoring loop against a deployed or third-party system (that live loop
belongs to Chapter V, against real models with keys present). Authorized red-team
use only.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt


class HarmBenchAttacker(BaseAttacker):
    """Drive HarmBench's standardized red-team methods in test-case generation mode
    to produce adversarial test cases as Attempts (no live attacker-vs-target loop).

    ``methods`` names the HarmBench methods to run (default ``["PEZ", "PAP-top5"]``,
    the algorithms URA otherwise lacks; any of PEZ, GBDA, UAT, AutoPrompt, PAP-top5,
    GCG, GCG-Multi, GCG-Transfer, AutoDAN, PAIR, TAP, DirectRequest, HumanJailbreaks,
    ZeroShot, or the MultiModal* image optimizers). ``experiment`` is the HarmBench
    experiment / target-model config key the white-box optimizers search against
    (needs a GPU). ``repo`` is the cloned checkout (else ``$HARMBENCH_HOME``);
    ``script`` / ``merge_script`` are its generation and merge entry points;
    ``python`` selects the interpreter HarmBench runs under (else the current one).
    """

    name = "harmbench"

    def __init__(
        self,
        methods: list[str] | None = None,
        experiment: str = "llama2_7b",
        repo: str | None = None,
        script: str = "generate_test_cases.py",
        merge_script: str = "merge_test_cases.py",
        python: str | None = None,
    ) -> None:
        # HarmBench methods whose generated test cases we harvest -- default to the
        # optimizers / persuasion attacks URA lacks (PEZ, PAP); GPU-bound for the
        # gradient and multimodal optimizers, generation-only (no live loop).
        self.methods = methods or ["PEZ", "PAP-top5"]
        # HarmBench experiment / target-model config key the optimizers search against.
        self.experiment = experiment
        # Cloned repo dir, its generation + merge entry scripts, and the interpreter.
        self.repo = repo
        self.script = script
        self.merge_script = merge_script
        self.python = python

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompts = self._generate_test_cases(datapoint, seed, max(1, budget.max_queries))
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy="+".join(self.methods),
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={
                    "methods": self.methods,
                    "experiment": self.experiment,
                    "mode": "generate",
                },
            )

    def _entry(self, name: str):
        """Resolve a HarmBench entry script inside the cloned repo, or None.

        The repo is located via ``repo`` / ``$HARMBENCH_HOME``; returns the script
        path only if it exists on disk, so :meth:`_generate_test_cases` can raise a
        single clear RuntimeError when the checkout is absent.
        """
        import os
        from pathlib import Path

        repo = self.repo or os.environ.get("HARMBENCH_HOME")
        if not repo:
            return None
        entry = Path(repo, name)
        return entry if entry.exists() else None

    def _generate_test_cases(self, datapoint: DataPoint, seed: str, n: int) -> list[str]:
        """Run the requested HarmBench methods' test-case generation over a
        one-behavior seed CSV and read back the produced adversarial test cases
        (lazy; requires the cloned repo, and a GPU for the optimizers).

        The repo is located via ``repo`` / ``$HARMBENCH_HOME`` and driven through its
        own interpreter; a clear RuntimeError is raised if it is absent. Only the
        test-case *generation* + *merge* path is exercised, never HarmBench's own
        live completion / scoring loop against a real target (harness safety N5).
        """
        import subprocess
        import sys
        import tempfile
        from pathlib import Path

        entry = self._entry(self.script)
        merge = self._entry(self.merge_script)
        if entry is None:
            raise RuntimeError(
                "HarmBench is required for HarmBenchAttacker; clone it "
                "(git clone https://github.com/centerforaisafety/HarmBench) and set "
                "$HARMBENCH_HOME (or pass repo=...) to the checkout. The gradient / "
                "multimodal optimizers (PEZ, GBDA, UAT, AutoPrompt, GCG, MultiModal*) "
                "additionally need a GPU. Authorized red-team use only."
            )
        python = self.python or sys.executable
        repo_dir = str(entry.parent)

        prompts: list[str] = []
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            behaviors_csv = tmp_dir / "behaviors.csv"
            behavior_id = self._write_behaviors_csv(datapoint, seed, behaviors_csv)
            for method in self.methods:
                save_dir = tmp_dir / method
                # Step 1: generate per-behavior test cases for the single seed behavior.
                gen_cmd = [
                    python, str(entry),
                    "--method_name", method,
                    "--experiment_name", self.experiment,
                    "--behaviors_path", str(behaviors_csv),
                    "--save_dir", str(save_dir),
                    "--behavior_start_idx", "0",
                    "--behavior_end_idx", "1",
                    "--overwrite",
                ]
                # Step 1.5: merge into {save_dir}/test_cases.json (generation only;
                # no completion / scoring loop is driven against a live target -- N5).
                merge_cmd = (
                    [python, str(merge), "--method_name", method,
                     "--save_dir", str(save_dir)]
                    if merge is not None else None
                )
                try:
                    subprocess.run(
                        gen_cmd, check=True, capture_output=True, cwd=repo_dir
                    )
                    if merge_cmd is not None:
                        subprocess.run(
                            merge_cmd, check=True, capture_output=True, cwd=repo_dir
                        )
                except (OSError, subprocess.SubprocessError):
                    continue
                prompts.extend(
                    self._read_test_cases(save_dir / "test_cases.json", behavior_id)
                )
                if len(prompts) >= n:
                    break
        return prompts[:n] or [seed]

    def _write_behaviors_csv(self, datapoint: DataPoint, seed: str, path) -> str:
        """Write a one-row HarmBench-format behaviors CSV for the seed and return its
        BehaviorID. Adds the multimodal ``ImageFileName`` column when the DataPoint
        carries image media, so the MultiModal* image optimizers have an input."""
        import csv

        behavior_id = "".join(
            ch if ch.isalnum() else "_" for ch in (datapoint.id or "seed")
        )[:64] or "seed"
        image_name = ""
        for ref in datapoint.media:
            candidate = ref.path or ref.uri
            if getattr(ref, "modality", None) == "image" and candidate:
                image_name = candidate
                break
        fields = [
            "Behavior", "FunctionalCategory", "SemanticCategory",
            "Tags", "ContextString", "BehaviorID",
        ]
        row = {
            "Behavior": seed,
            "FunctionalCategory": "standard",
            "SemanticCategory": datapoint.risk_subtype or "",
            "Tags": "",
            "ContextString": "",
            "BehaviorID": behavior_id,
        }
        if image_name:
            fields.append("ImageFileName")
            row["ImageFileName"] = image_name
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerow(row)
        return behavior_id

    @staticmethod
    def _read_test_cases(path, behavior_id: str) -> list[str]:
        """Read back HarmBench's merged ``test_cases.json`` (a dict mapping BehaviorID
        to a list of test cases) and flatten it to prompt strings. A multimodal test
        case is an ``[image_path, text]`` pair; the text component is taken as the
        prompt. Returns [] when the file is absent (generation produced nothing)."""
        import json
        from pathlib import Path

        path = Path(path)
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        if isinstance(data, dict):
            cases = data.get(behavior_id)
            items = cases if cases is not None else [
                c for group in data.values()
                if isinstance(group, list) for c in group
            ]
        else:
            items = data if isinstance(data, list) else []
        prompts: list[str] = []
        for case in items or []:
            if isinstance(case, str):
                text = case
            elif isinstance(case, (list, tuple)) and case:
                # Multimodal [image_path, text]: take the last string element as text.
                strings = [str(el) for el in case if isinstance(el, str)]
                text = strings[-1] if strings else str(case[-1])
            elif isinstance(case, dict):
                text = str(case.get("prompt") or case.get("test_case") or "")
            else:
                text = str(case)
            if text:
                prompts.append(text)
        return prompts
