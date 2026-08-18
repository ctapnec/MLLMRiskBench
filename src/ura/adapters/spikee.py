"""Spikee engine adapter: indirect prompt-injection dataset generation.

Spikee (ReversecLabs/spikee, formerly WithSecureLabs/spikee; Apache-2.0,
``pip install spikee``) is a "Simple Prompt Injection Kit for Evaluation and
Exploitation". Its ``spikee generate`` CLI builds injection datasets by splicing
malicious payloads (``instructions.jsonl``) into benign document / tool contexts
(``base_user_inputs.jsonl``) through jailbreak framing templates
(``jailbreaks.jsonl``), optionally passing each spliced payload through
transformation plugins (``1337`` leetspeak, ``base64``, ``splat``, ...) and
dynamic attacks (``best_of_n``, ``prompt_decomposition``, ``crescendo``,
``goat``). In URA-Bench it represents the indirect prompt-injection attack family
(thesis II.3.1 / II.4.1, III.2.2; OWASP LLM01 Prompt Injection / indirect
injection; RiskCategory.PROMPT_INJECTION_INDIRECT).

URA invokes Spikee's exact console entry point only inside its own explicitly
admitted virtual environment.  The fixed worker synthesises the seed folder in a
private workspace and returns one content-addressed dataset artifact; neither a
PATH executable nor a user-supplied seed-folder path is accepted.

Safety (thesis N5, III.2.4): this adapter operates in attack-GENERATION / seed
mode only. It materialises the spliced injection prompts as Attempts for the
harness to judge later via ``spikee generate``; it never invokes ``spikee test``
or any dynamic attack loop against a live / third-party target. Authorized
red-team use only.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable

from ..attacker_input_contract import AttackerInputContract, text_only_transfer_contract
from ..data_models import Attempt, DataPoint, DialogTurn
from ..strict_json import strict_json_loads
from ._engine_common import ExternalEngineOutputError, _attempt
from ._engine_runtime import (
    EngineExecution,
    require_admitted_engine_runtime,
)
from .base import AttackBudget, BaseAttacker

_MAX_DATASET_BYTES = 256 * 1024 * 1024
_MAX_DATASET_RECORDS = 1_000_000
SPIKEE_VERSION = "0.9.1"


class SpikeeAttacker(BaseAttacker):
    """Drive ``spikee generate`` to splice the DataPoint payload into a document
    context and materialise the resulting indirect prompt-injection prompts as
    Attempts (no live ``spikee test`` / dynamic-attack loop).

    ``plugins`` names the generation-time transformation plugins applied to the
    spliced payload (default ``["base64", "1337"]``; any of ``1337``, ``base64``,
    ``splat``, ``best_of_n``, ``google_translate``). ``out_format`` selects the
    spikee output format (``full-prompt`` renders the complete injected prompt;
    ``user-input`` renders only the injected user turn). ``positions`` are the
    injection positions inside the document (``start`` / ``middle`` / ``end``).
    Seed material is always synthesised from the DataPoint inside the private
    worker workspace.  Path-based seed folders, PATH CLI overrides and credential
    forwarding are rejected.
    """

    name = "spikee"

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        return text_only_transfer_contract(
            self.name,
            datapoint,
            budget,
            planned_turns=min(budget.max_queries, budget.max_turns),
            turn_count_semantics="upper_bound",
        )

    def __init__(
        self,
        plugins: list[str] | None = None,
        out_format: str = "full-prompt",
        positions: list[str] | None = None,
        include_system_message: bool = False,
        seed_folder: str | None = None,
        cli: str = "spikee",
        credential_env: list[str] | tuple[str, ...] | None = None,
        timeout_seconds: float | None = None,
        engine_version: str = SPIKEE_VERSION,
        engine_runtime: object = None,
    ) -> None:
        # Generation-time transformation plugins applied to the spliced payload.
        self.plugins = ["base64", "1337"] if plugins is None else list(plugins)
        # spikee output format: full-prompt (complete injected prompt) or user-input.
        self.out_format = out_format
        # Injection positions inside the benign document context.
        self.positions = ["end"] if positions is None else list(positions)
        # Whether spikee prepends the seed folder's system message to each prompt.
        self.include_system_message = include_system_message
        if seed_folder is not None:
            raise ValueError(
                "Spikee path-based seed_folder is disabled; use DataPoint content"
            )
        if cli != "spikee":
            raise ValueError("Spikee PATH/CLI overrides are disabled")
        if credential_env:
            raise ValueError("Spikee isolated generation does not forward credentials")
        self.timeout_seconds = timeout_seconds
        if out_format not in {"full-prompt", "user-input"}:
            raise ValueError("Spikee format must be full-prompt or user-input")
        if not self.positions or any(
            position not in {"start", "middle", "end"} for position in self.positions
        ):
            raise ValueError("Spikee positions must contain start, middle, or end")
        if any(not isinstance(plugin, str) or not plugin.strip() for plugin in self.plugins):
            raise ValueError("Spikee plugin names must be non-blank strings")
        if engine_version != SPIKEE_VERSION:
            raise ValueError(f"Spikee must be pinned to {SPIKEE_VERSION}")
        self.engine_version = engine_version
        self._engine_runtime = engine_runtime

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        seed = datapoint.payload_text or datapoint.payload_code or ""
        entries = self._inject_entries(datapoint, seed, max(1, budget.max_queries))
        for i, entry in enumerate(entries):
            plugin = entry["plugin"] or "untransformed"
            strategy = f"spikee:generated-dataset-transfer:{plugin}"
            attempt = _attempt(
                datapoint,
                self.name,
                strategy=strategy,
                turn_index=i,
                prompt=entry["content"],
                seed=budget.seed,
                params={
                    "requested_plugins": self.plugins,
                    "realized_plugin": entry["plugin"],
                    "plugin_semantics": (
                        "piped" if entry["plugin"] and "~" in entry["plugin"]
                        else "alternative_variant"
                    ),
                    "format": self.out_format,
                    "positions": self.positions,
                    "include_system_message": self.include_system_message,
                    "mode": "generate_dataset",
                    "attack_semantics": "generated_dataset_transfer",
                    "native_test_executed": False,
                    "native_judge_executed": False,
                    "spikee_version": self.engine_version,
                    "dataset_file": entry["_dataset_file"],
                    "dataset_sha256": entry["_dataset_sha256"],
                    "dataset_bytes": entry["_dataset_bytes"],
                    "engine_request_sha256": entry["_engine_request_sha256"],
                    "engine_runtime": entry["_engine_runtime"],
                    "spikee_entry": {
                        key: value for key, value in entry.items()
                        if not key.startswith("_")
                    },
                    "risk": "prompt_injection_indirect",
                },
            )
            system_message = entry.get("system_message")
            if system_message:
                # ``_attempt`` has already replaced the source objective with the
                # generated indirect-injection prompt. Rebuilding from the raw
                # DataPoint here used to send both objectives whenever Spikee
                # supplied a system message. Preserve the transformed dialog and
                # replace/prepend only its system instruction.
                rendered = list(attempt.rendered_input)
                if rendered and rendered[0].role == "system":
                    rendered[0] = DialogTurn(role="system", content=system_message)
                else:
                    rendered.insert(
                        0, DialogTurn(role="system", content=system_message)
                    )
                attempt = attempt.model_copy(update={"rendered_input": rendered})
            yield attempt

    def _document_context(self, datapoint: DataPoint) -> str:
        """Render the benign document / tool context the payload is spliced into.

        Uses the DataPoint's prior dialog as the surrounding context when present,
        else a generic document container. Spikee applies each configured
        injection position to this untrusted document.
        """
        history = list(datapoint.dialog_history)
        source_index = next(
            (
                index for index in range(len(history) - 1, -1, -1)
                if history[index].role == "user"
            ),
            None,
        )
        conditioning = (
            history[:source_index] if source_index is not None else history
        )
        parts: list[str] = []
        for turn in conditioning:
            if turn.content:
                parts.append(f"{turn.role}: {turn.content}")
            if turn.tool_result:
                parts.append(f"tool_result: {turn.tool_result}")
        context = "\n".join(parts) or "Untrusted document retrieved for the task."
        return context

    def _inject_entries(
        self, datapoint: DataPoint, seed: str, n: int
    ) -> list[dict]:
        """Generate and parse one fixed dataset artifact in the admitted venv."""

        runtime = require_admitted_engine_runtime(self._engine_runtime, self.name)
        execution = runtime.execute(
            "spikee.generate",
            {
                "plugins": list(self.plugins),
                "format": self.out_format,
                "positions": list(self.positions),
                "include_system_message": self.include_system_message,
                "seed": seed if seed.strip() else "Follow the injected instruction.",
                "document_context": self._document_context(datapoint),
            },
            timeout_seconds=self.timeout_seconds,
        )
        if not isinstance(execution, EngineExecution):
            raise ExternalEngineOutputError("Spikee bridge returned no execution receipt")
        if execution.result != {} or set(execution.artifacts) != {
            "spikee-dataset.jsonl"
        }:
            raise ExternalEngineOutputError("Spikee bridge artifact envelope is invalid")
        dataset_bytes = execution.artifacts["spikee-dataset.jsonl"]
        if not 0 < len(dataset_bytes) <= _MAX_DATASET_BYTES:
            raise ExternalEngineOutputError("Spikee dataset is empty or oversized")
        try:
            dataset_text = dataset_bytes.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ExternalEngineOutputError("Spikee dataset is not UTF-8") from exc
        dataset_sha256 = hashlib.sha256(dataset_bytes).hexdigest()
        entries: list[dict] = []
        for line_no, line in enumerate(dataset_text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                raw = strict_json_loads(line, max_nodes=10_000, max_depth=16)
            except ValueError as exc:
                raise ExternalEngineOutputError(
                    f"Spikee dataset has invalid JSON at line {line_no}"
                ) from exc
            entry = self._validate_entry(raw, line_no)
            entry["_dataset_file"] = "spikee-dataset.jsonl"
            entry["_dataset_sha256"] = dataset_sha256
            entry["_dataset_bytes"] = len(dataset_bytes)
            entry["_engine_request_sha256"] = execution.request_sha256
            entry["_engine_runtime"] = dict(execution.runtime)
            entries.append(entry)
            if len(entries) > _MAX_DATASET_RECORDS:
                raise ExternalEngineOutputError(
                    "Spikee dataset exceeds the 1000000-record parser limit"
                )

        if not entries:
            raise ExternalEngineOutputError(
                "Spikee prompt generation produced no valid generated prompts"
            )
        realized_plugins = {
            entry["plugin"] for entry in entries if entry["plugin"] is not None
        }
        expected_plugins = {plugin.replace("|", "~") for plugin in self.plugins}
        missing = sorted(expected_plugins - realized_plugins)
        if missing:
            raise ExternalEngineOutputError(
                "Spikee omitted configured plugin variants: " + ", ".join(missing)
            )
        realized_positions = {
            entry["position"] for entry in entries if entry["position"] is not None
        }
        missing_positions = sorted(set(self.positions) - realized_positions)
        if missing_positions:
            raise ExternalEngineOutputError(
                "Spikee omitted configured injection positions: "
                + ", ".join(missing_positions)
            )
        return entries[:n]

    def _validate_entry(self, raw: object, line_no: int) -> dict:
        if not isinstance(raw, dict):
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} is not an object"
            )
        required = {
            "id", "long_id", "content", "content_type", "judge_name",
            "judge_args", "injected", "task_type", "document_id", "position",
            "system_message", "plugin", "payload",
        }
        missing = sorted(required - raw.keys())
        if missing:
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} lacks fields: {', '.join(missing)}"
            )
        if not isinstance(raw["long_id"], str) or not raw["long_id"].strip():
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} has invalid long_id"
            )
        if raw["content_type"] != "text":
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} uses unsupported content_type"
            )
        if not isinstance(raw["content"], str) or not raw["content"].strip():
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} has blank content"
            )
        if raw["injected"] not in {True, "true"}:
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} is not marked injected"
            )
        for key in ("judge_name", "payload"):
            if not isinstance(raw[key], str) or not raw[key].strip():
                raise ExternalEngineOutputError(
                    f"Spikee dataset line {line_no} has invalid {key}"
                )
        for key in ("system_message", "plugin"):
            if raw[key] is not None and (
                not isinstance(raw[key], str) or not raw[key].strip()
            ):
                raise ExternalEngineOutputError(
                    f"Spikee dataset line {line_no} has invalid {key}"
                )
        if self.include_system_message and not raw["system_message"]:
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} omitted requested system message"
            )
        if raw["position"] not in {"start", "middle", "end"}:
            raise ExternalEngineOutputError(
                f"Spikee dataset line {line_no} has invalid injection position"
            )
        return dict(raw)
