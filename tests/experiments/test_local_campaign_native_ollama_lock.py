from __future__ import annotations

import ast
from pathlib import Path
import re
import time
from typing import Any, Mapping

import pytest


_TEMPLATE = (
    Path(__file__).parents[2]
    / "experiments"
    / "local_campaign"
    / "templates"
    / "phase6_native_diagnostics.sh.in"
)


def _payload(source: str | None = None) -> str:
    template = _TEMPLATE.read_text(encoding="utf-8") if source is None else source
    marker = "<<'PHASE6_NATIVE_PAYLOAD'\n"
    return template.split(marker, 1)[1].split("\nPHASE6_NATIVE_PAYLOAD\n", 1)[0]


def _planner_payload(source: str | None = None) -> str:
    template = _TEMPLATE.read_text(encoding="utf-8") if source is None else source
    blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", template, re.DOTALL)
    matches = [block for block in blocks if "raw_roster" in block]
    assert len(matches) == 1
    return matches[0]


def _tree_node(
    tree: ast.Module, kind: type[ast.AST], name: str
) -> ast.AST:
    return next(
        row
        for row in tree.body
        if isinstance(row, kind) and getattr(row, "name", None) == name
    )


def _node(payload: str, kind: type[ast.AST], name: str) -> ast.AST:
    return _tree_node(ast.parse(payload), kind, name)


def _exercise_lease(
    payload: str,
    *,
    drift_on_validation: int | None = None,
    event_sink: list[object] | None = None,
) -> tuple[list[object], dict[str, object]]:
    events = [] if event_sink is None else event_sink
    lock_arguments: dict[str, object] = {}
    validation_count = 0

    class FakeLock:
        def __init__(self, **kwargs: object) -> None:
            if lock_arguments:
                raise AssertionError("native call gate acquired more than one process lock")
            lock_arguments.update(kwargs)
            events.append("lock-created")

        def __enter__(self) -> "FakeLock":
            events.append("lock-enter")
            return self

        def __exit__(self, *_args: object) -> None:
            events.append("lock-exit")

    plan = {"fixture": "exact-roster"}

    def validate_roster(observed: Mapping[str, Any]) -> None:
        nonlocal validation_count
        assert observed is plan
        validation_count += 1
        events.append(f"roster-{validation_count}")
        if validation_count == drift_on_validation:
            raise ValueError("exact Ollama roster drift")

    lease_node = _node(payload, ast.ClassDef, "NativeOllamaInferenceLease")
    module = ast.fix_missing_locations(
        ast.Module(body=[lease_node], type_ignores=[])
    )
    namespace: dict[str, object] = {
        "Any": Any,
        "Mapping": Mapping,
        "DEFAULT_OLLAMA_URL": "http://127.0.0.1:11434",
        "OllamaProcessLock": FakeLock,
        "sys": __import__("sys"),
        "time": time,
        "validate_roster": validate_roster,
    }
    exec(compile(module, str(_TEMPLATE), "exec"), namespace)
    lease_type = namespace["NativeOllamaInferenceLease"]
    assert isinstance(lease_type, type)
    with lease_type(plan, deadline_epoch=int(time.time()) + 3600):
        events.extend(("gate-start", "native-call", "gate-stop"))
    return events, lock_arguments


def _named_calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [
        row
        for row in ast.walk(node)
        if isinstance(row, ast.Call)
        and isinstance(row.func, ast.Name)
        and row.func.id == name
    ]


def _assignment_value(payload: str, name: str) -> object:
    tree = ast.parse(payload)
    node = next(
        row
        for row in tree.body
        if isinstance(row, ast.Assign)
        and len(row.targets) == 1
        and isinstance(row.targets[0], ast.Name)
        and row.targets[0].id == name
    )
    return ast.literal_eval(node.value)


def _function_literals(payload: str, name: str) -> set[object]:
    node = _node(payload, ast.FunctionDef, name)
    return {
        row.value
        for row in ast.walk(node)
        if isinstance(row, ast.Constant)
    }


def _assert_bounded_agent_framework_contract(template: str) -> None:
    planner = _planner_payload(template)
    planned = _assignment_value(planner, "PLANNED")
    assert planned["asb"][:2] == ("run", 32)
    assert planned["agentdojo"][:2] == ("run", 32)

    payload = _payload(template)
    assert set(_assignment_value(payload, "RUNNABLE")) >= {"asb", "agentdojo"}
    assert set(_assignment_value(payload, "TYPED")) == {"autodan_turbo"}
    caps = _assignment_value(payload, "EXPECTED_CALL_CAPS")
    assert caps["asb"] == 32
    assert caps["agentdojo"] == 32
    assert 'EXPECTED_NATIVE_CASES["agentdojo"] = 2' in payload

    asb_literals = _function_literals(payload, "run_asb")
    assert {
        "main_attacker.py", "--task_num", "--direct_prompt_injection",
        "attack_tools_test.jsonl", "agent_task.jsonl", "OLLAMA_HOST",
    } <= asb_literals
    agentdojo_literals = _function_literals(payload, "run_agentdojo")
    assert {
        "agentdojo.scripts.benchmark", "--model-id", "local", "user_task_16",
        "injection_task_0", "important_instructions", "--force-rerun",
    } <= agentdojo_literals

    for name, cases in (("run_asb", 1), ("run_agentdojo", 2)):
        calls = _named_calls(_node(payload, ast.FunctionDef, name), "import_native")
        assert len(calls) == 1
        assert isinstance(calls[0].args[3], ast.Constant)
        assert calls[0].args[3].value == cases

    tree = ast.parse(payload)
    runner_assignment = next(
        row
        for row in tree.body
        if isinstance(row, ast.Assign)
        and len(row.targets) == 1
        and isinstance(row.targets[0], ast.Name)
        and row.targets[0].id == "ENGINE_RUNNERS"
    )
    assert isinstance(runner_assignment.value, ast.Dict)
    runners = {
        key.value: value.id
        for key, value in zip(
            runner_assignment.value.keys, runner_assignment.value.values
        )
        if isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and isinstance(value, ast.Name)
    }
    assert runners["asb"] == "run_asb"
    assert runners["agentdojo"] == "run_agentdojo"
    validator = ast.get_source_segment(
        payload, _node(payload, ast.FunctionDef, "validate_import_config")
    )
    assert validator is not None
    assert 'engine == "asb"' in validator
    assert 'engine == "agentdojo"' in validator


def _assert_execution_roster_call_graph(payload: str) -> None:
    tree = ast.parse(payload)
    lease = _tree_node(tree, ast.ClassDef, "NativeOllamaInferenceLease")
    lease_methods = {
        row.name: row
        for row in lease.body
        if isinstance(row, ast.FunctionDef)
    }
    protected_calls = [
        *_named_calls(lease_methods["__enter__"], "validate_roster"),
        *_named_calls(lease_methods["__exit__"], "validate_roster"),
    ]
    all_live_calls = _named_calls(tree, "validate_roster")
    assert len(protected_calls) == 2
    assert {id(row) for row in all_live_calls} == {
        id(row) for row in protected_calls
    }, "live roster validation escaped the production inference lease"

    validate_plan = _tree_node(tree, ast.FunctionDef, "validate_plan")
    assert not _named_calls(validate_plan, "validate_roster")
    assert len(
        _named_calls(validate_plan, "validate_planned_ollama_models")
    ) == 1
    controller_main = _tree_node(tree, ast.FunctionDef, "controller_main")
    assert not _named_calls(controller_main, "validate_roster")

    validate_live = _tree_node(tree, ast.FunctionDef, "validate_roster")
    assert len(_named_calls(validate_live, "fetch_roster")) == 1
    assert len(_named_calls(tree, "fetch_roster")) == 1


def _assert_exact_lease_contract(payload: str) -> None:
    events, arguments = _exercise_lease(payload)
    assert events == [
        "lock-created",
        "lock-enter",
        "roster-1",
        "gate-start",
        "native-call",
        "gate-stop",
        "roster-2",
        "lock-exit",
    ], "native lease lifecycle events changed"
    assert arguments["base_url"] == "http://127.0.0.1:11434"
    assert arguments["exclusive"] is True
    assert arguments["namespace"] == "inference"
    assert isinstance(arguments["deadline"], float)


def test_native_call_gate_holds_one_production_inference_lease() -> None:
    template = _TEMPLATE.read_text(encoding="utf-8")
    assert template.count(
        "one production exclusive inference lease with protected pre/post "
        "exact-roster checks"
    ) == 2
    payload = _payload()
    _assert_exact_lease_contract(payload)

    tree = ast.parse(payload)
    imports = [row for row in tree.body if isinstance(row, ast.ImportFrom)]
    production_import = next(
        row for row in imports if row.module == "ura.ollama_security"
    )
    assert {alias.name for alias in production_import.names} >= {
        "DEFAULT_OLLAMA_URL",
        "OllamaProcessLock",
    }

    engine_main = _node(payload, ast.FunctionDef, "engine_main")
    lease_blocks = [
        row
        for row in ast.walk(engine_main)
        if isinstance(row, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id == "NativeOllamaInferenceLease"
            for item in row.items
        )
    ]
    assert len(lease_blocks) == 1
    calls = list(ast.walk(lease_blocks[0]))
    assert any(
        isinstance(row, ast.Call)
        and isinstance(row.func, ast.Name)
        and row.func.id == "CallGate"
        for row in calls
    )
    assert any(
        isinstance(row, ast.Call)
        and isinstance(row.func, ast.Attribute)
        and row.func.attr == "start"
        for row in calls
    )
    assert any(
        isinstance(row, ast.Call)
        and isinstance(row.func, ast.Attribute)
        and row.func.attr == "stop"
        for row in calls
    )
    assert any(
        isinstance(row, ast.Call)
        and isinstance(row.func, ast.Subscript)
        and isinstance(row.func.value, ast.Name)
        and row.func.value.id == "ENGINE_RUNNERS"
        for row in calls
    )


def test_plan_only_roster_snapshot_uses_shared_production_endpoint_lock() -> None:
    planner = _planner_payload()
    tree = ast.parse(planner)
    imports = [row for row in tree.body if isinstance(row, ast.ImportFrom)]
    production_import = next(
        row for row in imports if row.module == "ura.ollama_security"
    )
    assert {alias.name for alias in production_import.names} >= {
        "DEFAULT_OLLAMA_URL",
        "OllamaProcessLock",
    }

    roster_opens = [
        row
        for row in ast.walk(tree)
        if isinstance(row, ast.Call)
        and isinstance(row.func, ast.Attribute)
        and row.func.attr == "urlopen"
    ]
    assert len(roster_opens) == 1
    lock_blocks = [
        row
        for row in ast.walk(tree)
        if isinstance(row, ast.With)
        and roster_opens[0] in list(ast.walk(row))
        and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id == "OllamaProcessLock"
            for item in row.items
        )
    ]
    assert len(lock_blocks) == 1
    lock_call = next(
        item.context_expr
        for item in lock_blocks[0].items
        if isinstance(item.context_expr, ast.Call)
        and isinstance(item.context_expr.func, ast.Name)
        and item.context_expr.func.id == "OllamaProcessLock"
    )
    keywords = {row.arg: row.value for row in lock_call.keywords}
    assert isinstance(keywords["base_url"], ast.Name)
    assert keywords["base_url"].id == "DEFAULT_OLLAMA_URL"
    assert isinstance(keywords["exclusive"], ast.Constant)
    assert keywords["exclusive"].value is False
    assert isinstance(keywords["namespace"], ast.Constant)
    assert keywords["namespace"].value == "endpoint"
    assert "deadline" in keywords


def test_execution_roster_reads_have_no_pre_lease_call_path() -> None:
    payload = _payload()
    _assert_execution_roster_call_graph(payload)

    needle = "    validate_planned_ollama_models(plan)\n    return plan\n"
    assert payload.count(needle) == 1
    mutation = payload.replace(
        needle,
        "    validate_roster(plan)\n    return plan\n",
        1,
    )
    with pytest.raises(AssertionError, match="escaped"):
        _assert_execution_roster_call_graph(mutation)


def test_native_call_gate_fails_closed_on_post_call_roster_drift() -> None:
    events: list[object] = []
    with pytest.raises(ValueError, match="exact Ollama roster drift"):
        _exercise_lease(
            _payload(), drift_on_validation=2, event_sink=events
        )
    assert events == [
        "lock-created",
        "lock-enter",
        "roster-1",
        "gate-start",
        "native-call",
        "gate-stop",
        "roster-2",
        "lock-exit",
    ]

    payload = _payload()
    lease_node = _node(payload, ast.ClassDef, "NativeOllamaInferenceLease")
    exits = [
        row
        for row in lease_node.body
        if isinstance(row, ast.FunctionDef) and row.name == "__exit__"
    ]
    assert len(exits) == 1
    exit_source = ast.get_source_segment(payload, exits[0])
    assert exit_source is not None
    assert exit_source.index("validate_roster(self.plan)") < exit_source.index(
        "lease.__exit__"
    )


def test_native_inference_lease_removal_mutation_is_rejected() -> None:
    payload = _payload()
    needle = "        lease.__enter__()\n"
    assert payload.count(needle) == 1
    mutation = payload.replace(needle, "", 1)
    with pytest.raises(AssertionError, match="events"):
        _assert_exact_lease_contract(mutation)


def _assert_promptfoo_local_generation_env(payload: str) -> None:
    clean_env = _node(payload, ast.FunctionDef, "clean_env")
    returns = [
        row for row in ast.walk(clean_env)
        if isinstance(row, ast.Return) and isinstance(row.value, ast.Dict)
    ]
    assert len(returns) == 1
    values = {
        key.value: value.value
        for key, value in zip(returns[0].value.keys, returns[0].value.values)
        if isinstance(key, ast.Constant)
        and isinstance(key.value, str)
        and isinstance(value, ast.Constant)
        and isinstance(value.value, str)
    }
    assert values["PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION"] == "1"


def test_promptfoo_native_generation_is_forced_local_and_noninteractive() -> None:
    payload = _payload()
    _assert_promptfoo_local_generation_env(payload)

    mutation = payload.replace(
        '"PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "1"',
        '"PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "0"',
        1,
    )
    assert mutation != payload
    with pytest.raises(AssertionError):
        _assert_promptfoo_local_generation_env(mutation)


def test_asb_and_agentdojo_have_bounded_native_execution_contracts() -> None:
    _assert_bounded_agent_framework_contract(
        _TEMPLATE.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            '    "asb": 32, "agentdojo": 32,',
            '    "asb": 0, "agentdojo": 0,',
        ),
        (
            'EXPECTED_NATIVE_CASES["agentdojo"] = 2',
            'EXPECTED_NATIVE_CASES["agentdojo"] = 1',
        ),
        ('    "asb": run_asb,\n', ''),
        ('    "agentdojo": run_agentdojo,\n', ''),
    ],
)
def test_bounded_agent_framework_mutations_are_rejected(
    needle: str, replacement: str
) -> None:
    template = _TEMPLATE.read_text(encoding="utf-8")
    assert template.count(needle) == 1
    mutation = template.replace(needle, replacement, 1)
    with pytest.raises(AssertionError):
        _assert_bounded_agent_framework_contract(mutation)
