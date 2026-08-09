"""EasyJailbreak engine adapter: recipe-zoo LLM jailbreak generation.

EasyJailbreak (EasyJailbreak/EasyJailbreak, ``pip install easyjailbreak``) is a
unified framework that packages a *zoo* of published jailbreak recipes behind one
attacker/mutation/dataset abstraction -- ReNeLLM, GPTFuzz, Cipher, CodeChameleon,
DeepInception, MultiLingual, ICA, Jailbroken, PAIR, TAP and GCG. Each recipe turns
a harmful ``query`` into one or more transformed ``jailbreak_prompt`` strings. In
URA-Bench it represents the reproducible published-recipe jailbreak family (thesis
II.3.1 / II.4.1, III.2.2; OWASP LLM01 Prompt Injection / jailbreak;
RiskCategory.JAILBREAK).

License isolation (GPL-3.0): EasyJailbreak is distributed under GPL-3.0. To keep
the harness (and anything that imports it) free of GPL contamination, this adapter
NEVER imports ``easyjailbreak`` in-process. Instead it drives the library from a
*separate* Python interpreter as a subprocess bridge (cf. :class:`PromptfooAttacker`
/ :class:`T3MP3STAttacker` / :class:`AutoDANTurboAttacker`, which shell out to
external tools): a small generation program -- kept out of this process -- imports
the recipes, applies them to the seed and writes the resulting prompts back to a
JSON file that this adapter reads. Only stdlib + pydantic are imported at module
load; ``easyjailbreak`` lives entirely in the child interpreter.

Safety (thesis N5, III.2.4): this adapter operates in attack-GENERATION mode only.
It materialises each recipe's transformed jailbreak prompts as Attempts for the
harness to judge later; it never lets EasyJailbreak drive a live attacker-vs-target
scoring loop against a deployed/third-party system (that live loop belongs to
Chapter V, against real models with keys present). Authorized red-team use only.

Provisioning: because the GPL dependency must stay out of the harness environment,
the EasyJailbreak-equipped interpreter is supplied out-of-band -- a dedicated venv
(``$EASYJAILBREAK_VENV`` or ``venv=...``) or an explicit interpreter
(``$EASYJAILBREAK_PYTHON`` or ``python=...``). :meth:`generate` raises a clear
RuntimeError when no such interpreter with ``easyjailbreak`` importable is found.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt

# Generation program run in the SEPARATE (GPL) interpreter. It is deliberately
# self-contained and best-effort: it resolves each requested recipe by
# name-prefix (tolerating EasyJailbreak's ``<Recipe>_<author>_<year>`` module
# suffixes), applies it to the one-instance seed dataset in generation mode and
# harvests the transformed ``jailbreak_prompt`` strings. Any per-recipe failure
# (missing keys, model, etc.) is swallowed so the bridge always emits a JSON
# document and exits 0; this process only ever reads that JSON back.
_BRIDGE = r'''
import importlib
import json
import pkgutil
import sys


def _load_recipe(name):
    import easyjailbreak.attacker as attacker_pkg

    target = name.lower()
    for mod_info in pkgutil.iter_modules(attacker_pkg.__path__):
        if mod_info.name.lower().split("_", 1)[0] != target:
            continue
        module = importlib.import_module("easyjailbreak.attacker." + mod_info.name)
        for attr in (name, mod_info.name, mod_info.name.split("_", 1)[0]):
            obj = getattr(module, attr, None)
            if isinstance(obj, type):
                return obj
    raise ImportError("EasyJailbreak recipe not found: " + name)


def _build_model(model_name):
    # A model handle for recipes that require one. Kept generation-only; no live
    # scoring loop is driven from here (harness safety N5).
    import os

    from easyjailbreak.models.openai_model import OpenaiModel

    return OpenaiModel(
        model_name=model_name, api_keys=os.environ.get("OPENAI_API_KEY", "")
    )


def _instantiate(recipe_cls, dataset, model):
    # Recipe constructors vary; try the richest signature first and fall back.
    for kwargs in (
        {"attack_model": model, "target_model": model, "eval_model": model},
        {"attack_model": model, "target_model": model},
        {"target_model": model},
        {},
    ):
        try:
            return recipe_cls(jailbreak_datasets=dataset, **kwargs)
        except TypeError:
            continue
    return None


def _harvest(attacker, dataset):
    prompts = []
    pools = [getattr(attacker, "attack_results", None), dataset]
    for pool in pools:
        if not pool:
            continue
        for inst in pool:
            value = getattr(inst, "jailbreak_prompt", None) or getattr(
                inst, "query", None
            )
            if value:
                prompts.append(str(value))
    return prompts


def main():
    cfg = json.load(open(sys.argv[1], encoding="utf-8"))
    seed = cfg["seed"]
    recipes = cfg["recipes"]
    limit = int(cfg["n"])
    out_path = cfg["out"]
    model_name = cfg.get("model") or "gpt-4o-mini"

    prompts = []
    try:
        from easyjailbreak.datasets import Instance, JailbreakDataset

        model = None
        for recipe in recipes:
            try:
                recipe_cls = _load_recipe(recipe)
            except Exception:
                continue
            dataset = JailbreakDataset([Instance(query=seed)])
            if model is None:
                try:
                    model = _build_model(model_name)
                except Exception:
                    model = None
            attacker = _instantiate(recipe_cls, dataset, model)
            if attacker is None:
                continue
            try:
                attacker.attack()
            except Exception:
                pass
            prompts.extend(_harvest(attacker, dataset))
            if len(prompts) >= limit:
                break
    except Exception:
        prompts = []

    json.dump({"prompts": prompts[:limit]}, open(out_path, "w", encoding="utf-8"))


main()
'''


class EasyJailbreakAttacker(BaseAttacker):
    """Drive EasyJailbreak's recipe zoo in generation mode -- via a separate
    (GPL-isolated) interpreter -- to produce transformed jailbreak prompts as
    Attempts (no live attacker-vs-target loop).

    ``recipes`` names the recipes to apply (default ``["ReNeLLM", "Cipher"]``;
    any of ReNeLLM, GPTFuzz, Cipher, CodeChameleon, DeepInception, MultiLingual,
    ICA, Jailbroken, PAIR, TAP, GCG). ``model`` is the model handle recipes that
    need one construct with. ``python`` / ``venv`` (or ``$EASYJAILBREAK_PYTHON`` /
    ``$EASYJAILBREAK_VENV``) locate the EasyJailbreak-equipped interpreter that
    keeps the GPL dependency out of the harness environment.
    """

    name = "easyjailbreak"

    def __init__(
        self,
        recipes: list[str] | None = None,
        model: str = "gpt-4o-mini",
        python: str | None = None,
        venv: str | None = None,
    ) -> None:
        # Recipes from the EasyJailbreak zoo whose transformed prompts we harvest.
        self.recipes = recipes or ["ReNeLLM", "Cipher"]
        # Model handle for recipes that require one; generation-only, no live loop.
        self.model = model
        # Out-of-band, GPL-isolated interpreter: an explicit python or a venv dir.
        self.python = python
        self.venv = venv

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompts = self._recipe_prompts(seed, max(1, budget.max_queries))
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy="+".join(self.recipes),
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={"recipes": self.recipes, "model": self.model, "mode": "generate"},
            )

    def _interpreter(self) -> str | None:
        """Resolve the GPL-isolated interpreter that has ``easyjailbreak`` installed.

        Prefers an explicit ``python`` / ``$EASYJAILBREAK_PYTHON``, else derives the
        interpreter inside a ``venv`` / ``$EASYJAILBREAK_VENV`` checkout. Returns the
        path only if it exists on disk / PATH; never falls back to the harness's own
        interpreter, so the GPL dependency stays out of this environment.
        """
        import os
        import shutil
        from pathlib import Path

        candidate = self.python or os.environ.get("EASYJAILBREAK_PYTHON")
        if not candidate:
            venv = self.venv or os.environ.get("EASYJAILBREAK_VENV")
            if venv:
                base = Path(venv)
                for rel in ("Scripts/python.exe", "bin/python", "bin/python3"):
                    exe = base / rel
                    if exe.exists():
                        candidate = str(exe)
                        break
        if not candidate:
            return None
        if shutil.which(candidate) or Path(candidate).exists():
            return candidate
        return None

    def _recipe_prompts(self, seed: str, n: int) -> list[str]:
        """Run the EasyJailbreak recipes over ``seed`` in a separate interpreter and
        read back the transformed jailbreak prompts (lazy; requires the GPL-isolated
        interpreter). Never imports ``easyjailbreak`` in-process and never drives a
        live attacker-vs-target scoring loop (harness safety principle N5)."""
        import json
        import subprocess
        import tempfile
        from pathlib import Path

        python = self._interpreter()
        if python is None or not self._has_easyjailbreak(python):
            raise RuntimeError(
                "EasyJailbreak is required for EasyJailbreakAttacker; because it is "
                "GPL-3.0 it is run from a SEPARATE interpreter to avoid contaminating "
                "the harness. Create a venv (python -m venv ejb && ejb/bin/pip install "
                "easyjailbreak) and set $EASYJAILBREAK_VENV (or pass venv=...), or set "
                "$EASYJAILBREAK_PYTHON / python=... to an interpreter with easyjailbreak "
                "installed. Authorized red-team use only."
            )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            out = tmp_dir / "prompts.json"
            cfg = tmp_dir / "cfg.json"
            script = tmp_dir / "ejb_bridge.py"
            cfg.write_text(
                json.dumps(
                    {
                        "seed": seed,
                        "recipes": self.recipes,
                        "n": n,
                        "out": str(out),
                        "model": self.model,
                    }
                ),
                encoding="utf-8",
            )
            script.write_text(_BRIDGE, encoding="utf-8")
            # Generation mode: the child interpreter imports the GPL recipes, emits
            # the transformed prompts to ``out`` and exits; no live target is driven.
            subprocess.run(
                [python, str(script), str(cfg)],
                check=True,
                capture_output=True,
            )
            data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        items = data.get("prompts", data) if isinstance(data, dict) else data
        prompts = [
            it.get("prompt", "") if isinstance(it, dict) else str(it)
            for it in items
        ] if isinstance(items, list) else []
        return [p for p in prompts if p] or [seed]

    @staticmethod
    def _has_easyjailbreak(python: str) -> bool:
        """Probe -- in the child interpreter, never in-process -- whether
        ``easyjailbreak`` is importable there, without importing it here."""
        import subprocess

        probe = (
            "import importlib.util, sys; "
            "sys.exit(0 if importlib.util.find_spec('easyjailbreak') else 1)"
        )
        try:
            result = subprocess.run(
                [python, "-c", probe], capture_output=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return result.returncode == 0
