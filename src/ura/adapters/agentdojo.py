"""AgentDojo native suite/environment integration.

AgentDojo attacks do not append an injection to the user's chat.  The official
benchmark calls ``attack.attack(...)`` to modify suite injection vectors, then
executes ``suite.run_task_with_pipeline(...)`` against the suite environment.
Its ``TraceLogger`` records the exact injections, complete user/assistant/tool
trajectory, and the suite's native utility and security booleans.

This adapter builds that documented benchmark command and imports its completed
trace family.  It deliberately does not expose the old payload-as-user-turn
approximation: replaying an injection string through ``Runner`` would remove the
environment and tool-result placement and would not be an AgentDojo run.
"""

from __future__ import annotations

import math
import os
import re
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from ..data_models import Attempt, DataPoint
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
)
from ._native_artifacts import (
    DEFAULT_MAX_RUN_ARTIFACT_BYTES,
    DEFAULT_MAX_RUN_ARTIFACT_FILES,
    NativeArtifactFile,
    NativeEngineCase,
    NativeEngineRun,
    canonical_json_bytes,
    json_sha256,
    read_utf8_artifact,
    require_expected_sha256,
    strict_json_loads,
)
from .base import AttackBudget, BaseAttacker


AGENTDOJO_REPOSITORY = "https://github.com/ethz-spylab/agentdojo"
AGENTDOJO_NATIVE_SCHEMA = "agentdojo-trace-logger/0.1.35"
AGENTDOJO_PINNED_VERSION = "0.1.35"
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_DEFENSES = {
    "tool_filter",
    "transformers_pi_detector",
    "spotlighting_with_delimiting",
    "repeat_user_prompt",
}
_TRACE_FIELDS = {
    "suite_name",
    "pipeline_name",
    "user_task_id",
    "injection_task_id",
    "attack_type",
    "injections",
    "messages",
    "error",
    "benchmark_version",
    "evaluation_timestamp",
    "agentdojo_package_version",
    "duration",
    "utility",
    "security",
}
_MAX_AGENTDOJO_TRACE_BYTES = 32 * 1024 * 1024
_MAX_AGENTDOJO_TOTAL_BYTES = 256 * 1024 * 1024
_MAX_AGENTDOJO_TRACES = DEFAULT_MAX_RUN_ARTIFACT_FILES


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(callable(is_junction) and is_junction())


def _without_link_components(path: Path) -> Path:
    candidate = Path(path).expanduser().absolute()
    current = Path(candidate.anchor)
    try:
        for part in candidate.parts[1:]:
            current /= part
            if _is_link_or_junction(current):
                raise ExternalEngineOutputError(
                    f"AgentDojo trace path contains a symbolic link or junction: {current}"
                )
        return candidate.resolve(strict=True)
    except ExternalEngineOutputError:
        raise
    except OSError as exc:
        raise ExternalEngineOutputError(
            f"AgentDojo trace root cannot be resolved safely: {path}"
        ) from exc


def _enumerate_trace_files(
    trace_root: Path,
    *,
    max_traces: int,
    max_artifact_bytes: int,
    max_total_bytes: int,
) -> tuple[Path, list[Path]]:
    """Enumerate regular JSON traces without following mutable indirections."""

    root = _without_link_components(trace_root)
    if root.is_file():
        paths = [root]
        root_for_names = root.parent
    elif root.is_dir():
        paths = []
        for directory, dirnames, filenames in os.walk(
            root, topdown=True, followlinks=False
        ):
            here = Path(directory)
            for name in sorted((*dirnames, *filenames)):
                child = here / name
                if _is_link_or_junction(child):
                    raise ExternalEngineOutputError(
                        "AgentDojo trace subtree contains a symbolic link or "
                        f"junction: {child}"
                    )
            for name in sorted(filenames):
                child = here / name
                if child.suffix.lower() == ".json":
                    if not child.is_file():
                        raise ExternalEngineOutputError(
                            f"AgentDojo trace is not a regular file: {child}"
                        )
                    paths.append(child)
                    if len(paths) > max_traces:
                        raise ExternalEngineOutputError(
                            "AgentDojo trace count exceeds the "
                            f"{max_traces}-file import limit"
                        )
        root_for_names = root
    else:
        raise ExternalEngineOutputError(
            f"AgentDojo trace root is not a regular file or directory: {root}"
        )
    if not paths:
        raise ExternalEngineOutputError(
            "AgentDojo trace root contains no JSON traces"
        )

    declared_total = 0
    for path in paths:
        try:
            size = path.stat(follow_symlinks=False).st_size
        except OSError as exc:
            raise ExternalEngineOutputError(
                f"AgentDojo trace metadata cannot be read: {path}"
            ) from exc
        if size < 1 or size > max_artifact_bytes:
            raise ExternalEngineOutputError(
                f"AgentDojo trace exceeds the {max_artifact_bytes}-byte "
                f"per-file limit: {path}"
            )
        declared_total += size
        if declared_total > max_total_bytes:
            raise ExternalEngineOutputError(
                "AgentDojo trace family exceeds the "
                f"{max_total_bytes}-byte aggregate limit"
            )
    return root_for_names, sorted(paths)


def _nonblank(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExternalEngineOutputError(
            f"AgentDojo trace field {field} must be a nonblank string"
        )
    return value


def _selection(values: Sequence[str], *, field: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"AgentDojo {field} must be a sequence of task IDs")
    selected = tuple(values)
    if any(not isinstance(value, str) or not value.strip() for value in selected):
        raise ValueError(f"AgentDojo {field} must contain nonblank task IDs")
    if len(set(selected)) != len(selected):
        raise ValueError(f"AgentDojo {field} must not contain duplicates")
    return selected


def _function_call(value: object, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ExternalEngineOutputError(f"AgentDojo {field} must be an object")
    allowed = {"function", "args", "id", "placeholder_args"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ExternalEngineOutputError(
            f"AgentDojo {field} has unknown FunctionCall fields: {', '.join(unknown)}"
        )
    _nonblank(value.get("function"), field=f"{field}.function")
    args = value.get("args")
    if not isinstance(args, dict) or any(not isinstance(key, str) for key in args):
        raise ExternalEngineOutputError(
            f"AgentDojo {field}.args must be a string-keyed object"
        )
    identifier = value.get("id")
    if identifier is not None and not isinstance(identifier, str):
        raise ExternalEngineOutputError(
            f"AgentDojo {field}.id must be string or null"
        )
    placeholders = value.get("placeholder_args")
    if placeholders is not None and (
        not isinstance(placeholders, dict)
        or any(not isinstance(key, str) for key in placeholders)
    ):
        raise ExternalEngineOutputError(
            f"AgentDojo {field}.placeholder_args must be an object or null"
        )
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ExternalEngineOutputError(
            f"AgentDojo {field} is not JSON-compatible"
        ) from exc
    return value


def _content_blocks(value: object, *, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ExternalEngineOutputError(f"AgentDojo {field} must be a list")
    blocks: list[dict[str, Any]] = []
    for index, block in enumerate(value):
        block_field = f"{field}[{index}]"
        if not isinstance(block, dict) or any(
            not isinstance(key, str) for key in block
        ):
            raise ExternalEngineOutputError(
                f"AgentDojo {block_field} must be an object"
            )
        kind = block.get("type")
        required = (
            {"type", "content", "id"}
            if kind == "thinking"
            else {"type", "content"}
        )
        if kind not in {"text", "thinking", "redacted_thinking"}:
            raise ExternalEngineOutputError(
                f"AgentDojo {block_field}.type is unsupported: {kind!r}"
            )
        if set(block) != required:
            raise ExternalEngineOutputError(
                f"AgentDojo {block_field} fields do not match the v0.1.35 content-block schema"
            )
        if not isinstance(block.get("content"), str):
            raise ExternalEngineOutputError(
                f"AgentDojo {block_field}.content must be a string"
            )
        if kind == "thinking" and block.get("id") is not None and not isinstance(
            block.get("id"), str
        ):
            raise ExternalEngineOutputError(
                f"AgentDojo {block_field}.id must be string or null"
            )
        blocks.append(block)
    return blocks


def _messages(value: object, *, pipeline_name: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ExternalEngineOutputError("AgentDojo messages must be a list")
    if len(value) < 2 and "claude-3-opus" not in pipeline_name:
        raise ExternalEngineOutputError(
            "AgentDojo completed TaskResults must contain at least two messages"
        )
    messages: list[dict[str, Any]] = []
    for index, message in enumerate(value):
        field = f"messages[{index}]"
        if not isinstance(message, dict) or any(
            not isinstance(key, str) for key in message
        ):
            raise ExternalEngineOutputError(f"AgentDojo {field} must be an object")
        role = message.get("role")
        if role in {"user", "system"}:
            if set(message) != {"role", "content"}:
                raise ExternalEngineOutputError(
                    f"AgentDojo {field} fields do not match the {role} schema"
                )
            _content_blocks(message.get("content"), field=f"{field}.content")
        elif role == "assistant":
            if set(message) != {"role", "content", "tool_calls"}:
                raise ExternalEngineOutputError(
                    f"AgentDojo {field} fields do not match the assistant schema"
                )
            content = message.get("content")
            if content is not None:
                _content_blocks(content, field=f"{field}.content")
            calls = message.get("tool_calls")
            if calls is not None:
                if not isinstance(calls, list):
                    raise ExternalEngineOutputError(
                        f"AgentDojo {field}.tool_calls must be a list or null"
                    )
                for call_index, call in enumerate(calls):
                    _function_call(call, field=f"{field}.tool_calls[{call_index}]")
            if content is None and not calls:
                raise ExternalEngineOutputError(
                    f"AgentDojo {field} must contain content or a tool call"
                )
        elif role == "tool":
            required = {"role", "tool_call", "content", "tool_call_id", "error"}
            if set(message) != required:
                raise ExternalEngineOutputError(
                    f"AgentDojo {field} fields do not match the tool-result schema"
                )
            _function_call(message.get("tool_call"), field=f"{field}.tool_call")
            _content_blocks(message.get("content"), field=f"{field}.content")
            if message.get("tool_call_id") is not None and not isinstance(
                message.get("tool_call_id"), str
            ):
                raise ExternalEngineOutputError(
                    f"AgentDojo {field}.tool_call_id must be string or null"
                )
            if message.get("error") is not None and not isinstance(
                message.get("error"), str
            ):
                raise ExternalEngineOutputError(
                    f"AgentDojo {field}.error must be string or null"
                )
        else:
            raise ExternalEngineOutputError(
                f"AgentDojo {field}.role is unsupported: {role!r}"
            )
        messages.append(message)
    return messages


def _assistant_outputs(messages: Sequence[Mapping[str, Any]]) -> list[str]:
    outputs: list[str] = []
    for message in messages:
        if message.get("role") != "assistant" or not isinstance(
            message.get("content"), list
        ):
            continue
        text = "\n".join(
            block["content"]
            for block in message["content"]
            if block.get("type") == "text" and isinstance(block.get("content"), str)
        )
        if text:
            outputs.append(text)
    return outputs


class AgentDojoAttacker(BaseAttacker):
    """Build and import a pinned AgentDojo native benchmark trace family."""

    name = "agentdojo"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        suite: str = "workspace",
        attack: str = "important_instructions",
        benchmark_version: str = "v1.2.2",
        model: str = "gpt-4o-2024-05-13",
        *,
        defense: str | None = None,
        model_id: str | None = None,
        upstream_version: str = AGENTDOJO_PINNED_VERSION,
        upstream_revision: str | None = None,
        python: str = sys.executable,
    ) -> None:
        for field, value in (
            ("suite", suite),
            ("attack", attack),
            ("benchmark_version", benchmark_version),
            ("model", model),
            ("upstream_version", upstream_version),
            ("python", python),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"AgentDojo {field} must be nonblank")
        if defense is not None and defense not in _DEFENSES:
            raise ValueError(
                "AgentDojo defense must be one of the v0.1.35 registered defenses"
            )
        if model_id is not None and (
            not isinstance(model_id, str) or not model_id.strip()
        ):
            raise ValueError("AgentDojo model_id must be nonblank when supplied")
        if upstream_revision is not None and not _COMMIT_RE.fullmatch(
            upstream_revision
        ):
            raise ValueError(
                "AgentDojo upstream_revision must be a full 40-hex Git commit"
            )
        self.suite = suite
        self.attack = attack
        self.benchmark_version = benchmark_version
        self.model = model
        self.defense = defense
        self.model_id = model_id
        self.upstream_version = upstream_version
        self.upstream_revision = (
            upstream_revision.lower() if upstream_revision is not None else None
        )
        self.python = python

    @property
    def pipeline_name(self) -> str:
        name = self.model if self.defense is None else f"{self.model}-{self.defense}"
        return name.replace("/", "_")

    def build_native_command(
        self,
        logdir: str | Path,
        *,
        user_tasks: Sequence[str] = (),
        injection_tasks: Sequence[str] = (),
        force_rerun: bool = False,
    ) -> list[str]:
        """Build the official ``agentdojo.scripts.benchmark`` invocation."""

        users = _selection(user_tasks, field="user_tasks")
        injections = _selection(injection_tasks, field="injection_tasks")
        if not isinstance(force_rerun, bool):
            raise TypeError("AgentDojo force_rerun must be boolean")
        command = [
            self.python,
            "-m",
            "agentdojo.scripts.benchmark",
            "--model",
            self.model,
            "--benchmark-version",
            self.benchmark_version,
            "--logdir",
            str(Path(logdir).resolve()),
            "--attack",
            self.attack,
            "--max-workers",
            "1",
            "-s",
            self.suite,
        ]
        if self.model_id is not None:
            command.extend(["--model-id", self.model_id])
        if self.defense is not None:
            command.extend(["--defense", self.defense])
        for task in users:
            command.extend(["-ut", task])
        for task in injections:
            command.extend(["-it", task])
        if force_rerun:
            command.append("--force-rerun")
        return command

    def import_run(
        self,
        trace_root: str | Path,
        *,
        expected_trace_sha256: Mapping[str, str] | None = None,
        max_artifact_bytes: int = _MAX_AGENTDOJO_TRACE_BYTES,
        max_traces: int = _MAX_AGENTDOJO_TRACES,
        max_total_bytes: int = _MAX_AGENTDOJO_TOTAL_BYTES,
    ) -> NativeEngineRun:
        """Import a fresh official trace subtree and reconstruct SuiteResults.

        The subtree must contain attacked user-task traces and exactly one
        no-attack trace for every injection task, as produced by
        ``benchmark_suite_with_injections``.  This preserves all three native
        result maps: utility, security, and injection-task utility.
        """

        for label, value, ceiling in (
            ("max_artifact_bytes", max_artifact_bytes, _MAX_AGENTDOJO_TRACE_BYTES),
            ("max_traces", max_traces, _MAX_AGENTDOJO_TRACES),
            ("max_total_bytes", max_total_bytes, _MAX_AGENTDOJO_TOTAL_BYTES),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
                or value > ceiling
            ):
                raise ValueError(
                    f"AgentDojo {label} must be in 1..{ceiling}"
                )
        if max_traces > DEFAULT_MAX_RUN_ARTIFACT_FILES:
            raise ValueError("AgentDojo trace count exceeds native-run file ceiling")
        if max_total_bytes > DEFAULT_MAX_RUN_ARTIFACT_BYTES:
            raise ValueError("AgentDojo aggregate bytes exceed native-run ceiling")
        root, paths = _enumerate_trace_files(
            Path(trace_root),
            max_traces=max_traces,
            max_artifact_bytes=max_artifact_bytes,
            max_total_bytes=max_total_bytes,
        )
        relative_names = {
            path: (
                path.name if root == path.parent and len(paths) == 1
                else path.relative_to(root).as_posix()
            )
            for path in paths
        }
        if expected_trace_sha256 is not None:
            expected_keys = set(expected_trace_sha256)
            observed_keys = set(relative_names.values())
            if expected_keys != observed_keys:
                raise ExternalEngineOutputError(
                    "AgentDojo preregistered trace-hash keys do not exactly match the imported files"
                )

        loaded: list[dict[str, Any]] = []
        total_bytes = 0
        for path in paths:
            resolved, data, text = read_utf8_artifact(
                path, max_bytes=max_artifact_bytes
            )
            expected = (
                expected_trace_sha256[relative_names[path]]
                if expected_trace_sha256 is not None
                else None
            )
            digest = require_expected_sha256(
                data, expected, role=f"AgentDojo trace {relative_names[path]}"
            )
            total_bytes += len(data)
            if total_bytes > max_total_bytes:
                raise ExternalEngineOutputError(
                    "AgentDojo trace family changed or exceeds the "
                    f"{max_total_bytes}-byte aggregate limit"
                )
            try:
                raw = strict_json_loads(text)
            except Exception as exc:  # noqa: BLE001 - normalize JSON errors
                raise ExternalEngineOutputError(
                    f"invalid AgentDojo trace {relative_names[path]}: {exc}"
                ) from exc
            trace = self._validate_trace(raw, path=resolved)
            trace["_path"] = resolved
            trace["_bytes"] = data
            trace["_sha256"] = digest
            trace["_relative"] = relative_names[path]
            loaded.append(trace)

        attacked = [trace for trace in loaded if trace["attack_type"] is not None]
        baselines = [trace for trace in loaded if trace["attack_type"] is None]
        if not attacked:
            raise ExternalEngineOutputError(
                "AgentDojo import contains no attacked suite/environment traces"
            )
        attack_keys: set[tuple[str, str]] = set()
        injection_ids: set[str] = set()
        for trace in attacked:
            injection_id = trace["injection_task_id"]
            key = (trace["user_task_id"], injection_id)
            if key in attack_keys:
                raise ExternalEngineOutputError(
                    f"duplicate AgentDojo attacked task pair {key!r}"
                )
            attack_keys.add(key)
            injection_ids.add(injection_id)

        baseline_by_task: dict[str, dict[str, Any]] = {}
        for trace in baselines:
            task = trace["user_task_id"]
            if task not in injection_ids:
                raise ExternalEngineOutputError(
                    f"extraneous AgentDojo no-attack trace for {task!r}; import a fresh run subtree"
                )
            if task in baseline_by_task:
                raise ExternalEngineOutputError(
                    f"duplicate AgentDojo injection-task utility trace for {task!r}"
                )
            baseline_by_task[task] = trace
        missing_baselines = sorted(injection_ids - set(baseline_by_task))
        if missing_baselines:
            raise ExternalEngineOutputError(
                "AgentDojo run is incomplete; missing injection-task utility traces: "
                + ", ".join(missing_baselines)
            )

        ordered = sorted(
            loaded,
            key=lambda trace: (
                trace["attack_type"] is None,
                trace["user_task_id"],
                trace["injection_task_id"] or "",
            ),
        )
        identity = {
            "suite": self.suite,
            "attack": self.attack,
            "benchmark_version": self.benchmark_version,
            "pipeline_name": self.pipeline_name,
            "package_version": self.upstream_version,
            "artifacts": [trace["_sha256"] for trace in ordered],
        }
        native_run_id = f"agentdojo:{json_sha256(identity)[:24]}"
        cases: list[NativeEngineCase] = []
        artifacts: list[NativeArtifactFile] = []
        for trace in ordered:
            is_attacked = trace["attack_type"] is not None
            role = "attacked_task_trace" if is_attacked else "injection_task_utility_trace"
            artifacts.append(
                NativeArtifactFile(
                    role=role,
                    path=str(trace["_path"]),
                    sha256=trace["_sha256"],
                    bytes=len(trace["_bytes"]),
                    records=1,
                )
            )
            first_user = next(
                (message for message in trace["messages"] if message.get("role") == "user"),
                trace["messages"][0] if trace["messages"] else None,
            )
            if is_attacked:
                outcome = (
                    f"utility_{str(trace['utility']).lower()}_"
                    f"security_{str(trace['security']).lower()}"
                )
                method = f"agentdojo:{self.attack}"
                scores = {
                    "utility": int(trace["utility"]),
                    "security": int(trace["security"]),
                }
            else:
                outcome = (
                    "injection_task_utility_pass"
                    if trace["utility"]
                    else "injection_task_utility_fail"
                )
                method = "agentdojo:injection-task-utility"
                scores = {"utility": int(trace["utility"])}
            cases.append(
                NativeEngineCase(
                    id=(
                        f"{native_run_id}:{trace['user_task_id']}:"
                        f"{trace['injection_task_id'] or 'none'}:{method}"
                    ),
                    source_run_id=native_run_id,
                    target_model=self.model,
                    attack_method=method,
                    original_input=first_user,
                    adversarial_input=None,
                    target_outputs=_assistant_outputs(trace["messages"]),
                    native_outcome=outcome,
                    native_scores=scores,
                    native_details={
                        "suite_name": trace["suite_name"],
                        "pipeline_name": trace["pipeline_name"],
                        "user_task_id": trace["user_task_id"],
                        "injection_task_id": trace["injection_task_id"],
                        "attack_type": trace["attack_type"],
                        "injections": trace["injections"],
                        "messages": trace["messages"],
                        "duration": trace["duration"],
                        "evaluation_timestamp": trace["evaluation_timestamp"],
                        "native_environment_executed": True,
                        "injection_appended_as_user_turn": False,
                    },
                    source_artifact_role=role,
                    source_record=trace["_relative"],
                    source_record_sha256=json_sha256(
                        {key: trace[key] for key in _TRACE_FIELDS}
                    ),
                )
            )

        utility_results = [
            {
                "user_task_id": trace["user_task_id"],
                "injection_task_id": trace["injection_task_id"],
                "value": trace["utility"],
            }
            for trace in attacked
        ]
        security_results = [
            {
                "user_task_id": trace["user_task_id"],
                "injection_task_id": trace["injection_task_id"],
                "value": trace["security"],
            }
            for trace in attacked
        ]
        injection_utility_results = [
            {"injection_task_id": task, "value": baseline_by_task[task]["utility"]}
            for task in sorted(baseline_by_task)
        ]
        return NativeEngineRun(
            engine="agentdojo",
            native_schema=AGENTDOJO_NATIVE_SCHEMA,
            native_run_id=native_run_id,
            upstream_repository=AGENTDOJO_REPOSITORY,
            upstream_version=self.upstream_version,
            upstream_revision=self.upstream_revision,
            source_artifacts=artifacts,
            target_models=[self.model],
            model_roles={"target": self.model},
            cases=cases,
            native_aggregates={
                "suite": self.suite,
                "attack": self.attack,
                "defense": self.defense,
                "benchmark_version": self.benchmark_version,
                "pipeline_name": self.pipeline_name,
                "utility_results": utility_results,
                "security_results": security_results,
                "injection_tasks_utility_results": injection_utility_results,
                "average_utility": sum(item["value"] for item in utility_results)
                / len(utility_results),
                "average_security": sum(item["value"] for item in security_results)
                / len(security_results),
                "average_injection_task_utility": sum(
                    item["value"] for item in injection_utility_results
                )
                / len(injection_utility_results),
            },
            import_accounting={
                "attacked_task_traces": len(attacked),
                "injection_task_utility_traces": len(baselines),
                "total_traces": len(loaded),
            },
            measurement_semantics=(
                "AgentDojo source-native suite/environment execution: utility is "
                "the user-task check under injection; the field named security is "
                "the upstream injection-goal execution check (True means that goal "
                "was executed), and injection-task utility is measured by executing each "
                "injection task as a no-injection user task; exact environment "
                "injections and tool trajectories are retained without conversion to "
                "a user-turn prompt"
            ),
        )

    def _validate_trace(self, raw: object, *, path: Path) -> dict[str, Any]:
        if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
            raise ExternalEngineOutputError(
                f"AgentDojo trace root must be a string-keyed object: {path}"
            )
        if set(raw) != _TRACE_FIELDS:
            missing = sorted(_TRACE_FIELDS - set(raw))
            extra = sorted(set(raw) - _TRACE_FIELDS)
            raise ExternalEngineOutputError(
                f"AgentDojo trace fields do not match v0.1.35 at {path}; "
                f"missing={missing!r}, extra={extra!r}"
            )
        trace = dict(raw)
        suite = _nonblank(trace["suite_name"], field="suite_name")
        pipeline = _nonblank(trace["pipeline_name"], field="pipeline_name")
        user_task = _nonblank(trace["user_task_id"], field="user_task_id")
        if suite != self.suite:
            raise ExternalEngineOutputError(
                f"AgentDojo suite mismatch: configured={self.suite!r}, trace={suite!r}"
            )
        if pipeline != self.pipeline_name:
            raise ExternalEngineOutputError(
                "AgentDojo pipeline mismatch: "
                f"configured={self.pipeline_name!r}, trace={pipeline!r}"
            )
        if trace["benchmark_version"] != self.benchmark_version:
            raise ExternalEngineOutputError(
                "AgentDojo benchmark-version mismatch: "
                f"configured={self.benchmark_version!r}, trace={trace['benchmark_version']!r}"
            )
        if trace["agentdojo_package_version"] != self.upstream_version:
            raise ExternalEngineOutputError(
                "AgentDojo package-version mismatch: "
                f"expected={self.upstream_version!r}, "
                f"observed={trace['agentdojo_package_version']!r}"
            )
        _nonblank(trace["evaluation_timestamp"], field="evaluation_timestamp")
        duration = trace["duration"]
        if (
            isinstance(duration, bool)
            or not isinstance(duration, (int, float))
            or not math.isfinite(float(duration))
            or duration < 0
        ):
            raise ExternalEngineOutputError(
                "AgentDojo completed trace duration must be a finite nonnegative number"
            )
        for field in ("utility", "security"):
            if not isinstance(trace[field], bool):
                raise ExternalEngineOutputError(
                    f"AgentDojo trace {field} must be boolean"
                )
        if trace["error"] is not None:
            raise ExternalEngineOutputError(
                f"AgentDojo trace contains an execution error: {trace['error']!r}"
            )
        injections = trace["injections"]
        if not isinstance(injections, dict) or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            for key, value in injections.items()
        ):
            raise ExternalEngineOutputError(
                "AgentDojo injections must be a string-to-string object"
            )
        attack_type = trace["attack_type"]
        injection_task = trace["injection_task_id"]
        if attack_type is None:
            if injection_task is not None or injections:
                raise ExternalEngineOutputError(
                    "AgentDojo no-attack trace must have null injection_task_id and empty injections"
                )
            attack_dir = "none"
            filename = "none.json"
        else:
            if attack_type != self.attack:
                raise ExternalEngineOutputError(
                    f"AgentDojo attack mismatch: configured={self.attack!r}, trace={attack_type!r}"
                )
            injection_task = _nonblank(
                injection_task, field="injection_task_id"
            )
            if not injections or not any(value.strip() for value in injections.values()):
                raise ExternalEngineOutputError(
                    "AgentDojo attacked trace must contain a nonblank environment injection"
                )
            attack_dir = self.attack
            filename = f"{injection_task}.json"
        trace["messages"] = _messages(trace["messages"], pipeline_name=pipeline)

        # TraceLogger's documented path is
        # logdir/pipeline/suite/user_task/attack/injection_task.json.
        if (
            path.name != filename
            or path.parent.name != attack_dir
            or path.parent.parent.name != user_task
            or path.parent.parent.parent.name != suite
            or path.parent.parent.parent.parent.name != pipeline
        ):
            raise ExternalEngineOutputError(
                f"AgentDojo trace path does not match TraceLogger metadata: {path}"
            )
        return trace

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "AgentDojo is supported through build_native_command() plus import_run(). "
            "BaseAttacker.generate is inapplicable: AgentDojo places injections in "
            "suite environment/tool outputs and computes native utility/security by "
            "running suite.run_task_with_pipeline; appending a payload as a user turn "
            "is explicitly not supported."
        )


__all__ = [
    "AGENTDOJO_NATIVE_SCHEMA",
    "AGENTDOJO_PINNED_VERSION",
    "AGENTDOJO_REPOSITORY",
    "AgentDojoAttacker",
]
