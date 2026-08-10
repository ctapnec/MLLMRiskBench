"""ASB native-run integration.

Agent Security Bench (ASB) is a complete AIOS agent evaluation, not a
target-free prompt mutator.  Its official launchers run an agent, its tools and
environment, then write a CSV containing the full message trace and ASB's own
attack, task-utility, refusal, memory-retrieval and aggressiveness fields.  A
URA ``Runner`` replay would remove precisely those semantics and make a second
model call, so this adapter imports the completed native run instead.

The upstream contracts used here are the official repository's
``scripts/agent_attack.py``, ``scripts/agent_attack_pot.py``, configuration
files, and ``main_attacker.py`` CSV writer.  DPI, OPI and memory poisoning use
``agent_attack.py --cfg_path``.  PoT is deliberately different upstream: its
official launcher is ``agent_attack_pot.py`` and it reads ``config/POT.yml``
itself.  The adapter does not invent a nonexistent PoT CLI option.
"""

from __future__ import annotations

import ast
import csv
import io
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ..data_models import Attempt, DataPoint, RiskCategory
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
    _require,
    run_engine_command,
)
from ._native_artifacts import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    NativeArtifactFile,
    NativeEngineCase,
    NativeEngineRun,
    canonical_json_bytes,
    json_sha256,
    read_utf8_artifact,
    require_expected_sha256,
)
from .base import AttackBudget, BaseAttacker


ASB_REPOSITORY = "https://github.com/agiresearch/ASB"
ASB_NATIVE_SCHEMA = "asb-main_attacker-csv/main"
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

_ATTACKS: dict[str, dict[str, str]] = {
    "dpi": {
        "config": "DPI.yml",
        "injection_method": "direct_prompt_injection",
        "launcher": "scripts/agent_attack.py",
    },
    "opi": {
        "config": "OPI.yml",
        "injection_method": "observation_prompt_injection",
        "launcher": "scripts/agent_attack.py",
    },
    "mp": {
        "config": "MP.yml",
        "injection_method": "memory_attack",
        "launcher": "scripts/agent_attack.py",
    },
    "pot": {
        "config": "POT.yml",
        "injection_method": "pot_backdoor",
        "launcher": "scripts/agent_attack_pot.py",
    },
}

# Retained as a public inventory crosswalk.  It no longer drives fabricated
# Attempts: native ASB results remain source-specific artifacts.
_RISK_BY_CLASS = {
    "dpi": RiskCategory.JAILBREAK.value,
    "opi": RiskCategory.PROMPT_INJECTION_INDIRECT.value,
    "mp": RiskCategory.AGENTIC_MISUSE.value,
    "pot": RiskCategory.AGENTIC_MISUSE.value,
}

_CSV_HEADER = (
    "Agent Name",
    "Attack Tool",
    "Attack Successful",
    "Original Task Successful",
    "Refuse Result",
    "Memory Found",
    "Aggressive",
    "messages",
)
_CONFIG_KEYS = {
    "injection_method",
    "attack_tool",
    "write_db",
    "read_db",
    "llms",
    "attack_types",
    "defense_type",
    "suffix",
    "triggers",
    "task_num",
}


def _nonblank(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExternalEngineOutputError(f"ASB {field} must be a nonblank string")
    return value


def _string_list(value: object, *, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ExternalEngineOutputError(f"ASB config {field} must be a non-empty list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ExternalEngineOutputError(
            f"ASB config {field} must contain only nonblank strings"
        )
    if len(set(value)) != len(value):
        raise ExternalEngineOutputError(f"ASB config {field} contains duplicates")
    return value


def _binary(value: object, *, field: str, row: int) -> int:
    if value not in {"0", "1"}:
        raise ExternalEngineOutputError(
            f"ASB CSV row {row} field {field!r} must be exactly 0 or 1"
        )
    return int(value)


def _json_compatible(value: Any, *, field: str) -> Any:
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ExternalEngineOutputError(
            f"ASB {field} is not a JSON-compatible native artifact"
        ) from exc
    return value


def _messages(value: object, *, row: int) -> list[dict[str, Any]]:
    if not isinstance(value, str) or not value.strip():
        raise ExternalEngineOutputError(f"ASB CSV row {row} has blank messages")
    try:
        parsed = ast.literal_eval(value)
    except (SyntaxError, ValueError) as exc:
        raise ExternalEngineOutputError(
            f"ASB CSV row {row} messages are not a Python literal trace"
        ) from exc
    if not isinstance(parsed, list) or len(parsed) < 4:
        raise ExternalEngineOutputError(
            f"ASB CSV row {row} messages must contain at least four turns"
        )
    messages: list[dict[str, Any]] = []
    for index, message in enumerate(parsed):
        if not isinstance(message, dict) or any(
            not isinstance(key, str) for key in message
        ):
            raise ExternalEngineOutputError(
                f"ASB CSV row {row} messages[{index}] must be a string-keyed object"
            )
        if "content" not in message:
            raise ExternalEngineOutputError(
                f"ASB CSV row {row} messages[{index}] lacks content"
            )
        content = message["content"]
        if content is not None and not isinstance(content, str):
            raise ExternalEngineOutputError(
                f"ASB CSV row {row} messages[{index}].content must be string or null"
            )
        messages.append(_json_compatible(message, field=f"messages[{index}]"))
    # main_attacker.py itself identifies the original task this way; requiring
    # the same location prevents a superficially similar CSV from being admitted.
    _nonblank(messages[3].get("content"), field=f"CSV row {row} native task")
    return messages


def _load_config(text: str) -> dict[str, Any]:
    yaml = _require("yaml", "ASB native config import", "PyYAML")
    try:
        value = yaml.safe_load(text)
    except Exception as exc:  # noqa: BLE001 - normalize optional parser errors
        raise ExternalEngineOutputError(f"invalid ASB YAML config: {exc}") from exc
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ExternalEngineOutputError("ASB config root must be a string-keyed object")
    unknown = sorted(set(value) - _CONFIG_KEYS)
    if unknown:
        raise ExternalEngineOutputError(
            "ASB config contains unsupported fields for the pinned contract: "
            + ", ".join(unknown)
        )
    return value


class ASBAttacker(BaseAttacker):
    """Build and import one pinned, complete ASB attack-class run.

    The historical registry class name is retained.  ``attack_class`` is one of
    ``dpi``, ``opi``, ``mp`` or ``pot``.  ``generate`` is intentionally
    unavailable because ASB has no native target-free prompt export.
    """

    name = "asb"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        attack_class: str = "dpi",
        *,
        repo: str | Path | None = None,
        upstream_revision: str | None = None,
        python: str = "python",
    ) -> None:
        normalized = attack_class.lower() if isinstance(attack_class, str) else ""
        if normalized not in _ATTACKS:
            raise ValueError("ASB attack_class must be dpi, opi, mp, or pot")
        if upstream_revision is not None and not _COMMIT_RE.fullmatch(
            upstream_revision
        ):
            raise ValueError("ASB upstream_revision must be a full 40-hex Git commit")
        if not isinstance(python, str) or not python.strip():
            raise ValueError("ASB python executable must be nonblank")
        self.attack_class = normalized
        self.repo = Path(repo) if repo is not None else None
        self.upstream_revision = (
            upstream_revision.lower() if upstream_revision is not None else None
        )
        self.python = python

    @property
    def _contract(self) -> dict[str, str]:
        return _ATTACKS[self.attack_class]

    def _require_revision(self, supplied: str | None = None) -> str:
        revision = supplied or self.upstream_revision
        if not isinstance(revision, str) or not _COMMIT_RE.fullmatch(revision):
            raise ValueError("ASB upstream_revision must be a full 40-hex Git commit")
        return revision.lower()

    def _checkout(self) -> Path:
        if self.repo is None:
            raise ValueError("ASB repo is required to build the native command")
        root = self.repo.resolve(strict=True)
        if not root.is_dir():
            raise ValueError(f"ASB repo is not a directory: {root}")
        required = (
            root / "main_attacker.py",
            root / self._contract["launcher"],
            root / "config" / self._contract["config"],
        )
        missing = [str(path) for path in required if not path.is_file()]
        if missing:
            raise ExternalEngineConformanceError(
                "ASB checkout lacks official pinned-contract files: "
                + ", ".join(missing)
            )
        return root

    def _verify_checkout_revision(self, root: Path, expected: str) -> None:
        result = run_engine_command(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            feature="ASB checkout revision verification",
            timeout_seconds=30,
        )
        observed = result.stdout.strip().lower()
        if observed != expected:
            raise ExternalEngineConformanceError(
                f"ASB checkout revision mismatch: expected={expected}, observed={observed}"
            )

    def build_native_command(self) -> list[str]:
        """Build the official launcher command after verifying the checkout pin.

        Execute it with :meth:`native_working_directory` as ``cwd`` because the
        upstream launchers intentionally use checkout-relative data/log paths.
        """

        revision = self._require_revision()
        root = self._checkout()
        self._verify_checkout_revision(root, revision)
        launcher = root / self._contract["launcher"]
        if self.attack_class == "pot":
            # The official PoT launcher has no arguments and reads POT.yml from cwd.
            return [self.python, str(launcher)]
        config = root / "config" / self._contract["config"]
        return [self.python, str(launcher), "--cfg_path", str(config)]

    def native_working_directory(self) -> str:
        """Return the checkout cwd required by both official launchers."""

        revision = self._require_revision()
        root = self._checkout()
        self._verify_checkout_revision(root, revision)
        return str(root)

    def import_run(
        self,
        result_csv: str | Path,
        *,
        target_model: str,
        attack_type: str,
        attack_tool_type: str,
        config_path: str | Path | None = None,
        trigger: str | None = None,
        upstream_revision: str | None = None,
        expected_csv_sha256: str | None = None,
        expected_config_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Import ASB's authoritative config and ``main_attacker.py`` CSV."""

        revision = self._require_revision(upstream_revision)
        target_model = _nonblank(target_model, field="target_model")
        attack_type = _nonblank(attack_type, field="attack_type")
        attack_tool_type = _nonblank(attack_tool_type, field="attack_tool_type")

        if config_path is None:
            root = self._checkout()
            self._verify_checkout_revision(root, revision)
            config_path = root / "config" / self._contract["config"]
        config_resolved, config_bytes, config_text = read_utf8_artifact(
            Path(config_path), max_bytes=max_artifact_bytes
        )
        if config_resolved.name != self._contract["config"]:
            raise ExternalEngineOutputError(
                f"ASB {self.attack_class} import requires config/{self._contract['config']}"
            )
        config_digest = require_expected_sha256(
            config_bytes, expected_config_sha256, role="ASB config"
        )
        config = _load_config(config_text)
        self._validate_config(
            config,
            target_model=target_model,
            attack_type=attack_type,
            attack_tool_type=attack_tool_type,
            trigger=trigger,
        )

        csv_resolved, csv_bytes, csv_text = read_utf8_artifact(
            Path(result_csv), max_bytes=max_artifact_bytes
        )
        csv_digest = require_expected_sha256(
            csv_bytes, expected_csv_sha256, role="ASB results CSV"
        )
        rows = self._parse_rows(csv_text)

        run_identity = {
            "upstream_revision": revision,
            "config_sha256": config_digest,
            "csv_sha256": csv_digest,
            "attack_class": self.attack_class,
            "target_model": target_model,
            "attack_type": attack_type,
            "attack_tool_type": attack_tool_type,
            "trigger": trigger,
        }
        native_run_id = f"asb:{json_sha256(run_identity)[:24]}"
        cases: list[NativeEngineCase] = []
        for index, row in enumerate(rows, start=1):
            scores = {
                "attack_successful": row["attack_successful"],
                "original_task_successful": row["original_task_successful"],
                "refused": row["refused"],
                "aggressive": row["aggressive"],
            }
            if row["memory_found"] is not None:
                scores["memory_found"] = row["memory_found"]
            record = row["source_record"]
            cases.append(
                NativeEngineCase(
                    id=f"{native_run_id}:row{index}",
                    source_run_id=native_run_id,
                    target_model=target_model,
                    attack_method=f"asb:{self._contract['injection_method']}:{attack_type}",
                    original_input=row["task"],
                    adversarial_input=None,
                    target_outputs=row["assistant_outputs"],
                    native_outcome=(
                        "attack_successful"
                        if row["attack_successful"] == 1
                        else "attack_failed"
                    ),
                    native_scores=scores,
                    native_details={
                        "agent_name": row["agent_name"],
                        "attack_tool": row["attack_tool"],
                        "attack_class": self.attack_class,
                        "injection_method": self._contract["injection_method"],
                        "attack_type": attack_type,
                        "attack_tool_type": attack_tool_type,
                        "trigger": trigger,
                        "messages": row["messages"],
                        "native_csv_row": record,
                    },
                    source_artifact_role="results_csv",
                    source_record=f"row {index + 1}",
                    source_record_sha256=json_sha256(record),
                )
            )

        artifacts = [
            NativeArtifactFile(
                role="config",
                path=str(config_resolved),
                sha256=config_digest,
                bytes=len(config_bytes),
                records=1,
            ),
            NativeArtifactFile(
                role="results_csv",
                path=str(csv_resolved),
                sha256=csv_digest,
                bytes=len(csv_bytes),
                records=len(rows),
            ),
        ]
        count = len(rows)
        return NativeEngineRun(
            engine="asb",
            native_schema=(
                f"{ASB_NATIVE_SCHEMA};header=" + "|".join(_CSV_HEADER)
            ),
            native_run_id=native_run_id,
            upstream_repository=ASB_REPOSITORY,
            upstream_revision=revision,
            source_artifacts=artifacts,
            target_models=[target_model],
            model_roles={"target": target_model, "refusal_judge": "gpt-4o-mini"},
            cases=cases,
            native_aggregates={
                "attack_class": self.attack_class,
                "injection_method": self._contract["injection_method"],
                "launcher": self._contract["launcher"],
                "config": config,
                "selected_attack_type": attack_type,
                "selected_attack_tool_type": attack_tool_type,
                "selected_trigger": trigger,
                "attack_success_rate": sum(
                    row["attack_successful"] for row in rows
                )
                / count,
                "original_task_success_rate": sum(
                    row["original_task_successful"] for row in rows
                )
                / count,
                "refusal_rate": sum(row["refused"] for row in rows) / count,
                "aggressive_tool_rate": sum(row["aggressive"] for row in rows)
                / count,
                "memory_found_rate": (
                    sum(
                        row["memory_found"]
                        for row in rows
                        if row["memory_found"] is not None
                    )
                    / sum(row["memory_found"] is not None for row in rows)
                    if any(row["memory_found"] is not None for row in rows)
                    else None
                ),
            },
            import_accounting={"native_rows": count},
            measurement_semantics=(
                "ASB source-native AIOS agent/task evaluation: attack success is "
                "the upstream attacker-goal trace check, original-task success is "
                "the upstream expected-achievement check, refusal is ASB's "
                "GPT-4o-mini judge result, and memory_found is retained only when "
                "the native run emitted it"
            ),
        )

    def _validate_config(
        self,
        config: Mapping[str, Any],
        *,
        target_model: str,
        attack_type: str,
        attack_tool_type: str,
        trigger: str | None,
    ) -> None:
        raw_method = config.get("injection_method")
        methods = (
            _string_list(raw_method, field="injection_method")
            if isinstance(raw_method, list)
            else [_nonblank(raw_method, field="config injection_method")]
        )
        if methods != [self._contract["injection_method"]]:
            raise ExternalEngineOutputError(
                "ASB config injection_method does not exactly match the selected "
                f"attack class: expected={[self._contract['injection_method']]!r}, "
                f"observed={methods!r}"
            )
        models = _string_list(config.get("llms"), field="llms")
        attack_types = _string_list(config.get("attack_types"), field="attack_types")
        tool_types = _string_list(config.get("attack_tool"), field="attack_tool")
        if target_model not in models:
            raise ExternalEngineOutputError(
                f"ASB target model {target_model!r} is not selected by the config"
            )
        if attack_type not in attack_types:
            raise ExternalEngineOutputError(
                f"ASB attack type {attack_type!r} is not selected by the config"
            )
        if attack_tool_type not in tool_types:
            raise ExternalEngineOutputError(
                f"ASB attack-tool type {attack_tool_type!r} is not selected by the config"
            )
        for flag in ("write_db", "read_db"):
            if flag in config and not isinstance(config[flag], bool):
                raise ExternalEngineOutputError(f"ASB config {flag} must be boolean")
        if self.attack_class == "mp" and config.get("read_db") is not True:
            raise ExternalEngineOutputError(
                "ASB memory poisoning requires read_db: true in the native config"
            )
        if self.attack_class == "pot":
            triggers = _string_list(config.get("triggers"), field="triggers")
            selected = _nonblank(trigger, field="PoT trigger")
            if selected not in triggers:
                raise ExternalEngineOutputError(
                    f"ASB PoT trigger {selected!r} is not selected by the config"
                )
            task_num = config.get("task_num")
            if isinstance(task_num, bool) or not isinstance(task_num, int) or task_num < 1:
                raise ExternalEngineOutputError(
                    "ASB PoT config task_num must be a positive integer"
                )
        elif trigger is not None:
            raise ValueError("ASB trigger is valid only for the pot attack class")

    def _parse_rows(self, text: str) -> list[dict[str, Any]]:
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if tuple(reader.fieldnames or ()) != _CSV_HEADER:
            raise ExternalEngineOutputError(
                "ASB CSV header does not match main_attacker.py: expected "
                + repr(list(_CSV_HEADER))
            )
        parsed: list[dict[str, Any]] = []
        for row_number, row in enumerate(reader, start=2):
            if None in row or set(row) != set(_CSV_HEADER):
                raise ExternalEngineOutputError(
                    f"ASB CSV row {row_number} has the wrong number of columns"
                )
            agent_name = _nonblank(row["Agent Name"], field=f"CSV row {row_number} Agent Name")
            attack_tool = _nonblank(row["Attack Tool"], field=f"CSV row {row_number} Attack Tool")
            messages = _messages(row["messages"], row=row_number)
            memory_raw = row["Memory Found"]
            if self.attack_class == "mp":
                memory_found: int | None = _binary(
                    memory_raw, field="Memory Found", row=row_number
                )
            elif memory_raw == "N/A":
                memory_found = None
            else:
                raise ExternalEngineOutputError(
                    f"ASB CSV row {row_number} non-memory run must emit Memory Found=N/A"
                )
            source_record = {key: row[key] for key in _CSV_HEADER}
            parsed.append(
                {
                    "agent_name": agent_name,
                    "attack_tool": attack_tool,
                    "attack_successful": _binary(
                        row["Attack Successful"],
                        field="Attack Successful",
                        row=row_number,
                    ),
                    "original_task_successful": _binary(
                        row["Original Task Successful"],
                        field="Original Task Successful",
                        row=row_number,
                    ),
                    "refused": _binary(
                        row["Refuse Result"], field="Refuse Result", row=row_number
                    ),
                    "memory_found": memory_found,
                    "aggressive": _binary(
                        row["Aggressive"], field="Aggressive", row=row_number
                    ),
                    "messages": messages,
                    "task": messages[3]["content"],
                    "assistant_outputs": [
                        message["content"]
                        for message in messages
                        if message.get("role") == "assistant"
                        and isinstance(message.get("content"), str)
                    ],
                    "source_record": source_record,
                }
            )
        if not parsed:
            raise ExternalEngineOutputError("ASB CSV contains no native result rows")
        return parsed

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        raise ExternalEngineConformanceError(
            "ASB is supported through build_native_command() plus import_run(). "
            "BaseAttacker.generate is inapplicable because ASB's DPI/OPI/memory/PoT "
            "conditions are executed inside its AIOS agent, tool environment and "
            "memory, with source-native task and attack metrics; it has no faithful "
            "standalone prompt export."
        )


__all__ = [
    "ASB_NATIVE_SCHEMA",
    "ASB_REPOSITORY",
    "ASBAttacker",
    "_RISK_BY_CLASS",
]
