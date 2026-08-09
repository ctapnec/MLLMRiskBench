"""Giskard engine adapter: autonomous multi-turn OWASP-LLM-Top-10 red-teaming.

Giskard-OSS (Giskard-AI, Apache-2.0) v3 ships ``giskard-scan``, an agent
vulnerability scanner that autonomously synthesises and drives multi-turn
red-team probes across the OWASP LLM Top-10 threat families - prompt injection,
harmful content, stereotypes/bias, misinformation/hallucination, and jailbreaks
[giskard-2024]. Its public entry point is the async
``giskard.scan.vulnerability_scan(target=..., description=..., languages=...)``,
and the scenario space is extensible via ``ScenarioGenerator`` instances passed to
``generate_suite`` (or registered on ``vulnerability_suite_generator_registry``).

In URA-Bench, Giskard is wrapped as a *scanner-style attacker* (thesis II.4.1 /
III.2.2; OWASP LLM01 Prompt Injection, LLM02 Insecure Output, LLM09
Misinformation): the adapter expands a DataPoint into a Giskard scenario suite and
materialises each scenario's seed probe as an Attempt, so the probes flow through
the same attacker/target/judge pipeline as the other engines.

Safety (thesis N5, III.2.4): this adapter runs Giskard in SCAN-SEED / plan mode
only. It calls the suite-*generation* surface to elicit the red-team scenario
prompts and never invokes ``vulnerability_scan(target=...)``, which would drive a
live multi-turn attack loop against a target model; the live scan runs only in
Chapter V against real models with keys present. Authorized testing only.

Giskard is a Python package, so this is a lazy ``_require`` wrapper (cf.
PyRITAttacker / GarakAttacker): the module imports with only stdlib + pydantic
present, and ``giskard[scan]`` is required only when :meth:`generate` runs.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt, _require


class GiskardAttacker(BaseAttacker):
    """Wrap Giskard-scan's OWASP-LLM suite generation to emit seed probes as
    Attempts (no live scan loop).

    ``categories`` names the OWASP-LLM threat families whose scenario generators
    seed the suite (e.g. prompt_injection, harmful_content, jailbreak);
    ``languages`` is the probe language set. The target/judge models are supplied
    by the run (Chapter V), not by this adapter.
    """

    name = "giskard"

    def __init__(
        self,
        categories: list[str] | None = None,
        languages: list[str] | None = None,
    ) -> None:
        # OWASP-LLM threat families the seed scenarios probe for.
        self.categories = categories or [
            "prompt_injection",
            "harmful_content",
            "jailbreak",
        ]
        self.languages = languages or ["en"]

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        probes = self._scan_probes(datapoint, max(1, budget.max_queries))
        for i, prompt in enumerate(probes):
            yield _attempt(
                datapoint,
                self.name,
                strategy="+".join(self.categories),
                turn_index=i,
                prompt=prompt,
                seed=budget.seed,
                params={
                    "categories": self.categories,
                    "languages": self.languages,
                    "mode": "scan-seed",
                },
            )

    def _scan_probes(self, datapoint: DataPoint, n: int) -> list[str]:
        """Synthesise the Giskard scenario suite for ``datapoint`` and read back
        its seed probes (lazy; requires ``giskard[scan]``).

        Offline / plan mode: this drives Giskard's suite-*generation* surface
        (``generate_suite`` over the OWASP-LLM ``vulnerability_suite_generator_registry``)
        and NEVER calls ``giskard.scan.vulnerability_scan(target=...)``, which
        would run a live multi-turn attack loop against a target model (harness
        safety principle N5). ``giskard.scan`` is imported lazily so this module
        stays stdlib + pydantic only until a scan is actually generated.
        """
        import asyncio
        import inspect

        scan = _require("giskard.scan", "GiskardAttacker", "giskard[scan]")

        generate_suite = getattr(scan, "generate_suite", None)
        registry = getattr(scan, "vulnerability_suite_generator_registry", None)
        if generate_suite is None or registry is None:
            raise RuntimeError(
                "installed giskard build lacks the scan suite-generation API "
                "(giskard.scan.generate_suite / "
                "vulnerability_suite_generator_registry); install a compatible "
                "version: pip install 'giskard[scan]'"
            )

        generators = self._select_generators(registry)
        suite = generate_suite(
            description=self._describe(datapoint),
            generators=generators or None,
            languages=self.languages,
        )
        # giskard-scan v3 is async-first; resolve a coroutine if one is returned.
        if inspect.iscoroutine(suite):
            suite = asyncio.run(suite)

        prompts = self._extract_prompts(suite)[:n]
        return prompts or [self._describe(datapoint)]

    def _select_generators(self, registry) -> list:
        """Resolve the configured OWASP-LLM categories to ScenarioGenerator
        instances from the registry; unknown categories are skipped so an empty
        result falls back to Giskard's default generator set."""
        gens: list = []
        for category in self.categories:
            gen = None
            if hasattr(registry, "get"):
                gen = registry.get(category)
            elif category in registry:
                gen = registry[category]
            if gen is not None:
                # The registry may hold generator classes or ready instances.
                gens.append(gen() if isinstance(gen, type) else gen)
        return gens

    def _describe(self, datapoint: DataPoint) -> str:
        """Render the target description that seeds scenario synthesis, carrying
        the datapoint's risk focus and payload into the suite."""
        seed = datapoint.payload_text or datapoint.payload_code or ""
        return (
            "System under test for OWASP-LLM red-teaming. "
            f"Risk focus: {datapoint.risk_category.value}. "
            f"Seed scenario: {seed}"
        ).strip()

    @staticmethod
    def _extract_prompts(suite) -> list[str]:
        """Walk a generated suite and pull each scenario's seed probe text,
        defensively across the object/dict/list shapes giskard may return."""
        scenarios = getattr(suite, "scenarios", suite)
        if isinstance(scenarios, dict):
            scenarios = scenarios.get("scenarios", list(scenarios.values()))
        if not isinstance(scenarios, (list, tuple)):
            scenarios = [scenarios]

        def _text(obj, keys) -> str | None:
            for key in keys:
                val = obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)
                if isinstance(val, str) and val.strip():
                    return val
            return None

        prompts: list[str] = []
        for scenario in scenarios:
            direct = _text(scenario, ("prompt", "user_prompt", "seed_prompt", "input"))
            if direct is not None:
                prompts.append(direct)
                continue
            probes = (
                scenario.get("probes")
                if isinstance(scenario, dict)
                else getattr(scenario, "probes", None)
            )
            if isinstance(probes, (list, tuple)):
                for probe in probes:
                    text = probe if isinstance(probe, str) else _text(probe, ("prompt",))
                    if isinstance(text, str) and text.strip():
                        prompts.append(text)
        return [p for p in prompts if p and p.strip()]
