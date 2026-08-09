"""AgentDojo engine adapter: indirect prompt injection against LLM tool-agents.

AgentDojo (ETH Zurich SPY Lab, MIT; ``pip install agentdojo``) is a dynamic
agentic tool-use environment for evaluating direct and indirect prompt-injection
attacks and defenses on LLM agents [agentdojo-2024]. A task suite (workspace,
slack, travel, banking, ...) pairs benign *user tasks* with adversarial
*injection tasks*; an attack renders each injection task's ``GOAL`` into a
payload string that AgentDojo splices into a tool's return value (an email body,
a document, a calendar entry), so the payload reaches the agent indirectly - as
untrusted tool output rather than as a user turn. In URA-Bench this represents
the indirect prompt-injection family (thesis II.4.1 / III.2.2; OWASP LLM01
Prompt Injection, ASI01/ASI02 agentic tool misuse; ``prompt_injection_indirect``
risk category).

Adapter behaviour: :meth:`generate` loads a suite, iterates its injection task
cases, uses AgentDojo's own attack registry to build the indirect-injection
payloads, and materialises each payload as an :class:`Attempt` (``channel =
tool_result``, ``mode = indirect-injection`` recorded in ``params``). The library
is imported lazily via :func:`_require`, so this module imports with only stdlib +
pydantic present and raises a clean install hint offline (cf. PyRITAttacker /
DeepTeamAttacker).

Safety (thesis N5, III.2.4): this adapter runs AgentDojo in offline
plan/seed-generation mode. It only *builds* the injection payload strings for the
target to be judged on; it never runs the live agent loop against real tools or
systems. The target "pipeline" AgentDojo requires is a local stub whose model
query is hard-disabled, so any attack that would need to call a live model (e.g.
``tool_knowledge``) raises instead of executing. Authorized testing only.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..data_models import Attempt, DataPoint
from .base import AttackBudget, BaseAttacker
from ._engine_common import _attempt, _require


class _OfflinePipeline:
    """Duck-typed AgentDojo target-pipeline stub that disables live model calls.

    AgentDojo attacks take a target pipeline; template attacks only read its
    ``name`` while formatting the injection payload. Any attack that actually
    tries to *query* the target hits :meth:`query` and raises, keeping this
    adapter in offline plan/seed mode (harness safety principle N5).
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def query(self, *args, **kwargs):  # noqa: D401,ANN002,ANN003 - stub only
        raise RuntimeError(
            "AgentDojoAttacker runs offline (plan/seed mode, thesis N5): the "
            f"{self.name!r} target pipeline is a stub and never queries a live "
            "model. Choose an attack that only templates the injection goal "
            "(e.g. 'important_instructions')."
        )


class AgentDojoAttacker(BaseAttacker):
    """Wrap AgentDojo injection-task cases as indirect prompt-injection Attempts.

    ``suite`` selects the task suite (``workspace`` / ``slack`` / ``travel`` /
    ``banking``); ``attack`` names a registered AgentDojo attack that renders each
    injection task's ``GOAL`` into a tool-result payload; ``benchmark_version``
    pins the suite version; ``target_name`` is the stub pipeline's model name used
    only for offline templating (never queried). The live agent/target/judge loop
    is driven elsewhere (Chapter V), not by this adapter.
    """

    name = "agentdojo"

    def __init__(
        self,
        suite: str = "workspace",
        attack: str = "important_instructions",
        benchmark_version: str = "v1.2.2",
        target_name: str = "gpt-4o-2024-05-13",
    ) -> None:
        self.suite = suite
        self.attack = attack
        self.benchmark_version = benchmark_version
        self.target_name = target_name

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        cases = self._injections(max(1, budget.max_queries))
        for i, case in enumerate(cases):
            yield _attempt(
                datapoint,
                self.name,
                strategy=f"{self.suite}:{self.attack}",
                turn_index=i,
                prompt=case["payload"],
                seed=budget.seed,
                params={
                    "suite": self.suite,
                    "attack": self.attack,
                    "benchmark_version": self.benchmark_version,
                    "injection_task": case["injection_task"],
                    "vector": case["vector"],
                    "goal": case["goal"],
                    "channel": "tool_result",
                    "mode": "indirect-injection",
                },
            )

    def _injections(self, n: int) -> list[dict]:
        """Build AgentDojo indirect-injection payloads for the suite (lazy import).

        Loads the suite from AgentDojo's bundled data (no network, no model),
        instantiates the registered attack against an offline stub pipeline, and
        returns up to ``n`` injection cases as ``{injection_task, vector, payload,
        goal}`` dicts. The stub pipeline is never queried, so this stays in
        offline plan/seed mode (harness safety principle N5).
        """
        _require("agentdojo", "AgentDojoAttacker")
        from agentdojo.attacks.attack_registry import load_attack
        from agentdojo.task_suite.load_suites import get_suite

        suite = get_suite(self.benchmark_version, self.suite)
        pipeline = _OfflinePipeline(self.target_name)  # never queried (N5)
        attack = load_attack(self.attack, suite, pipeline)

        user_tasks = list(suite.user_tasks.values())
        user_task = user_tasks[0] if user_tasks else None
        out: list[dict] = []
        for task_id, injection_task in suite.injection_tasks.items():
            # {injection_vector_id: payload_string} spliced into a tool result.
            injections = attack.attack(user_task, injection_task)
            for vector, payload in injections.items():
                if not payload:
                    continue
                out.append(
                    {
                        "injection_task": task_id,
                        "vector": vector,
                        "payload": payload,
                        "goal": getattr(injection_task, "GOAL", ""),
                    }
                )
                if len(out) >= n:
                    return out
        return out
