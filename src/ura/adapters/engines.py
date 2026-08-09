"""External red-team engine wrappers (thesis III.2.2).

Thin adapters that drive third-party attack frameworks — PyRIT, Garak, DeepTeam,
Promptfoo — and map their output back onto the unified :class:`Attempt` schema.

Every engine dependency is imported *lazily* inside :meth:`generate`, so this
module (and the whole harness) imports with only ``pydantic`` + the standard
library present. A missing engine surfaces as a clear ``RuntimeError`` only when
that engine is actually invoked. ``get_attacker`` also resolves the pure-python
``replay`` and ``crescendo`` adapters, which have no heavy dependencies.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DialogTurn
from ..data_models import DataPoint
from .base import AttackBudget, BaseAttacker


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _require(module: str, feature: str, pip_name: str | None = None):
    """Lazily import ``module`` or raise a uniform install hint.

    Kept in one place so every engine reports missing deps identically. The
    install hint names the distributable ``pip_name`` (defaults to the module's
    top-level package).
    """
    import importlib

    pkg = pip_name or module.split(".", 1)[0]
    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            f"{pkg} is required for {feature}; pip install {pkg}"
        ) from exc


def _seed_dialog(datapoint: DataPoint, prompt: str) -> list[DialogTurn]:
    """Render an engine-produced prompt as a dialog, preserving prior history."""
    history = list(datapoint.dialog_history)
    history.append(DialogTurn(role="user", content=prompt))
    return history


def _attempt(
    datapoint: DataPoint,
    attacker: str,
    strategy: str,
    turn_index: int,
    prompt: str,
    seed: int,
    params: dict | None = None,
) -> Attempt:
    """Build a schema-valid :class:`Attempt` for a single engine turn."""
    return Attempt(
        id=f"{datapoint.id}:{attacker}:{turn_index}",
        datapoint_id=datapoint.id,
        attacker=attacker,
        strategy=strategy,
        turn_index=turn_index,
        rendered_input=_seed_dialog(datapoint, prompt),
        seed=seed,
        params=params or {},
    )


# --------------------------------------------------------------------------- #
# PyRIT
# --------------------------------------------------------------------------- #

class PyRITAttacker(BaseAttacker):
    """Wrap Microsoft PyRIT prompt-conversion / orchestration.

    Uses PyRIT's ``PromptConverter`` chain to mutate the seed payload into
    concrete attack prompts. Orchestrator-driven online scoring is out of scope
    for a single generate() call; we materialise deterministic converter output.
    """

    name = "pyrit"

    def __init__(self, converters: list[str] | None = None) -> None:
        # Names of pyrit.prompt_converter classes to apply in order.
        self.converters = converters or ["Base64Converter"]

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        prompt = self._render(self._seed(datapoint))
        yield _attempt(
            datapoint,
            self.name,
            strategy="+".join(self.converters),
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={"converters": self.converters},
        )

    @staticmethod
    def _seed(datapoint: DataPoint) -> str:
        return datapoint.payload_text or datapoint.payload_code or ""

    def _render(self, seed: str) -> str:
        """Apply the configured PyRIT converter chain (lazy import)."""
        mod = _require("pyrit.prompt_converter", "PyRITAttacker")
        text = seed
        for name in self.converters:
            converter_cls = getattr(mod, name)
            result = converter_cls().convert_sync(prompt=text, input_type="text")
            text = getattr(result, "output_text", str(result))
        return text


# --------------------------------------------------------------------------- #
# Garak
# --------------------------------------------------------------------------- #

class GarakAttacker(BaseAttacker):
    """Wrap NVIDIA Garak probes as seed-prompt generators.

    Garak probes expose a ``prompts`` list; each becomes one Attempt. We only
    read the probe's static prompts (no live target harnessing here).
    """

    name = "garak"

    def __init__(self, probe: str = "dan.Dan_11_0") -> None:
        self.probe = probe

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        prompts = self._probe_prompts()[: max(1, budget.max_queries)]
        for i, prompt in enumerate(prompts):
            yield _attempt(
                datapoint,
                self.name,
                strategy=self.probe,
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={"probe": self.probe},
            )

    def _probe_prompts(self) -> list[str]:
        """Instantiate the Garak probe and pull its static prompts (lazy)."""
        garak = _require("garak._plugins", "GarakAttacker")
        probe = garak.load_plugin(f"probes.{self.probe}")
        return [str(p) for p in getattr(probe, "prompts", [])] or [""]


# --------------------------------------------------------------------------- #
# DeepTeam
# --------------------------------------------------------------------------- #

class DeepTeamAttacker(BaseAttacker):
    """Wrap Confident-AI DeepTeam attack enhancements.

    DeepTeam exposes single-turn attack transforms (e.g. ``PromptInjection``,
    ``Roleplay``). We apply one transform to the seed to produce an Attempt.
    """

    name = "deepteam"

    def __init__(self, attack: str = "PromptInjection") -> None:
        self.attack = attack

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        prompt = self._enhance(seed)
        yield _attempt(
            datapoint,
            self.name,
            strategy=self.attack,
            turn_index=0,
            prompt=prompt,
            seed=budget.seed,
            params={"attack": self.attack},
        )

    def _enhance(self, seed: str) -> str:
        """Apply a DeepTeam attack transform to the seed (lazy import)."""
        mod = _require("deepteam.attacks.single_turn", "DeepTeamAttacker")
        attack_cls = getattr(mod, self.attack)
        return attack_cls().enhance(seed)


# --------------------------------------------------------------------------- #
# Promptfoo
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #

def get_attacker(name: str) -> BaseAttacker:
    """Resolve an attacker adapter by name.

    Handles the pure-python ``replay`` / ``crescendo`` adapters (imported lazily
    from sibling modules so this module stays import-light) and the four engine
    wrappers defined here.
    """
    key = name.strip().lower()
    if key == "replay":
        from .replay import ReplayAttacker

        return ReplayAttacker()
    if key == "crescendo":
        from .crescendo import CrescendoAttacker

        return CrescendoAttacker()
    engines: dict[str, type[BaseAttacker]] = {
        "pyrit": PyRITAttacker,
        "garak": GarakAttacker,
        "deepteam": DeepTeamAttacker,
        "promptfoo": PromptfooAttacker,
    }
    if key in engines:
        return engines[key]()
    raise ValueError(
        f"unknown attacker {name!r}; "
        f"choose from replay, crescendo, {', '.join(engines)}"
    )


__all__ = [
    "PyRITAttacker",
    "GarakAttacker",
    "DeepTeamAttacker",
    "PromptfooAttacker",
    "get_attacker",
]
