"""Garak 0.15.1 native report integration.

Garak is a target-running scanner: its harness invokes the configured target,
runs detectors over every response, and writes detector/evaluator results to a
JSONL report.  Reading ``Probe.prompts`` and replaying those prompts through URA
is not a Garak scan and loses the native target response and detector result.

The supported boundary is therefore the complete ``*.report.jsonl`` produced by
the exact audited release.  The importer cross-validates paired attempt rows and
the evaluator totals, retains the full conversations and detector arrays, and
keeps the resulting metrics source-native and Runner-ineligible.

Primary upstream contracts:

* https://github.com/NVIDIA/garak/tree/v0.15.1
* https://reference.garak.ai/en/stable/reporting.html
* https://reference.garak.ai/en/stable/cliref.html
* ``garak/attempt.py`` and ``garak/evaluators/base.py`` at ``GARAK_REVISION``
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from ..data_models import Attempt, DataPoint
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
)
from ._native_artifacts import (
    DEFAULT_MAX_ARTIFACT_BYTES,
    NativeArtifactFile,
    NativeEngineCase,
    NativeEngineRun,
    json_sha256,
    read_utf8_artifact,
    require_expected_sha256,
    strict_json_loads,
)
from .base import AttackBudget, BaseAttacker


GARAK_REPOSITORY = "https://github.com/NVIDIA/garak"
GARAK_VERSION = "0.15.1"
GARAK_REVISION = "c43aed7d3e2b97e3b62c12a2eb5d171860bf8909"
GARAK_NATIVE_SCHEMA = "garak-report-jsonl/0.15.1"

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_ENTRY_TYPES = {
    "start_run setup",
    "init",
    "plugin_cache",
    "payload_init",
    "attempt",
    "tree_data",
    "eval",
    "completion",
    "digest",
}
_ATTEMPT_KEYS = {
    "entry_type",
    "uuid",
    "seq",
    "status",
    "probe_classname",
    "probe_params",
    "targets",
    "prompt",
    "outputs",
    "detector_results",
    "notes",
    "goal",
    "conversations",
    "reverse_translation_outputs",
}
_EVAL_REQUIRED_KEYS = {
    "entry_type",
    "probe",
    "detector",
    "passed",
    "fails",
    "nones",
    "total_evaluated",
    "total_processed",
}
_EVAL_CI_KEYS = {
    "confidence_method",
    "confidence",
    "confidence_upper",
    "confidence_lower",
}
_MESSAGE_KEYS = {
    "text",
    "lang",
    "data_path",
    "data_type",
    "data_checksum",
    "notes",
}


def _object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExternalEngineOutputError(f"Garak report {field} must be an object")
    return value


def _nonblank(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExternalEngineOutputError(
            f"Garak report {field} must be a nonblank string"
        )
    return value


def _integer(value: Any, *, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ExternalEngineOutputError(
            f"Garak report {field} must be an integer >= {minimum}"
        )
    return value


def _score(value: Any, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExternalEngineOutputError(f"Garak report {field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0.0 or result > 1.0:
        raise ExternalEngineOutputError(
            f"Garak report {field} must be finite and in [0, 1]"
        )
    return result


def _strict_keys(
    value: Mapping[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
    field: str,
) -> None:
    keys = set(value)
    missing = sorted(required - keys)
    extra = sorted(keys - required - (optional or set()))
    if missing or extra:
        parts = []
        if missing:
            parts.append("missing=" + ",".join(missing))
        if extra:
            parts.append("unknown=" + ",".join(extra))
        raise ExternalEngineOutputError(
            f"Garak report {field} schema mismatch ({'; '.join(parts)})"
        )


def _message_has_evidence(value: Any, *, field: str) -> bool:
    if value is None:
        return False
    message = _object(value, field=field)
    _strict_keys(message, required=_MESSAGE_KEYS, field=field)
    text = message.get("text")
    if text is not None and not isinstance(text, str):
        raise ExternalEngineOutputError(f"Garak report {field}.text must be a string/null")
    for scalar in ("lang", "data_path"):
        if message.get(scalar) is not None and not isinstance(message.get(scalar), str):
            raise ExternalEngineOutputError(
                f"Garak report {field}.{scalar} must be a string/null"
            )
    data_type = message.get("data_type")
    if data_type is not None and not (
        isinstance(data_type, list)
        and len(data_type) == 2
        and all(item is None or isinstance(item, str) for item in data_type)
    ):
        raise ExternalEngineOutputError(
            f"Garak report {field}.data_type must be a two-item string/null array"
        )
    data_checksum = message.get("data_checksum")
    if data_checksum is not None and not (
        isinstance(data_checksum, str)
        and bool(re.fullmatch(r"[0-9a-fA-F]{64}", data_checksum))
    ):
        raise ExternalEngineOutputError(
            f"Garak report {field}.data_checksum must be a full SHA-256/null"
        )
    notes = message.get("notes")
    if notes is not None and not isinstance(notes, dict):
        raise ExternalEngineOutputError(f"Garak report {field}.notes must be an object/null")
    if isinstance(text, str) and text.strip():
        return True

    data_path = message.get("data_path")
    has_media = (
        isinstance(data_path, str)
        and bool(data_path.strip())
        and isinstance(data_checksum, str)
        and bool(re.fullmatch(r"[0-9a-fA-F]{64}", data_checksum))
        and isinstance(data_type, list)
        and len(data_type) == 2
    )
    return has_media


def _validate_conversation(value: Any, *, field: str) -> list[dict[str, Any]]:
    conversation = _object(value, field=field)
    _strict_keys(conversation, required={"turns", "notes"}, field=field)
    notes = conversation.get("notes")
    if notes is not None and not isinstance(notes, dict):
        raise ExternalEngineOutputError(f"Garak report {field}.notes must be an object/null")
    turns = conversation.get("turns")
    if not isinstance(turns, list):
        raise ExternalEngineOutputError(f"Garak report {field}.turns must be an array")
    for index, raw_turn in enumerate(turns):
        turn = _object(raw_turn, field=f"{field}.turns[{index}]")
        _strict_keys(
            turn,
            required={"role", "content"},
            field=f"{field}.turns[{index}]",
        )
        if turn.get("role") not in {"system", "user", "assistant", "tool", "function"}:
            raise ExternalEngineOutputError(
                f"Garak report {field}.turns[{index}].role is unknown"
            )
        _message_has_evidence(
            turn.get("content"), field=f"{field}.turns[{index}].content"
        )
    return turns


def _text_outputs(outputs: list[Any]) -> list[str]:
    retained: list[str] = []
    for output in outputs:
        if isinstance(output, dict):
            text = output.get("text")
            if isinstance(text, str) and text.strip():
                retained.append(text)
    return retained


def _prompt_text(prompt: Any) -> str | None:
    if not isinstance(prompt, dict):
        return None
    turns = prompt.get("turns")
    if not isinstance(turns, list):
        return None
    for turn in reversed(turns):
        if not isinstance(turn, dict) or turn.get("role") != "user":
            continue
        content = turn.get("content")
        if isinstance(content, dict):
            text = content.get("text")
            if isinstance(text, str) and text.strip():
                return text
    return None


def _load_report(
    path: Path,
    *,
    expected_records: int,
    max_artifact_bytes: int,
) -> tuple[Path, bytes, list[dict[str, Any]]]:
    resolved, data, text = read_utf8_artifact(path, max_bytes=max_artifact_bytes)
    lines = text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise ExternalEngineOutputError(
            "Garak report JSONL must contain only nonblank JSON records"
        )
    if len(lines) != expected_records:
        raise ExternalEngineOutputError(
            "Garak report record-count mismatch: "
            f"expected={expected_records}, observed={len(lines)}"
        )
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, start=1):
        try:
            value = strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ExternalEngineOutputError(
                f"invalid Garak JSONL at line {line_no}: {exc}"
            ) from exc
        record = _object(value, field=f"line {line_no}")
        entry_type = _nonblank(record.get("entry_type"), field=f"line {line_no}.entry_type")
        if entry_type not in _ENTRY_TYPES:
            raise ExternalEngineOutputError(
                f"Garak report line {line_no} has unknown entry_type {entry_type!r}"
            )
        records.append(record)
    return resolved, data, records


class GarakAttacker(BaseAttacker):
    """Import complete Garak 0.15.1 reports without changing the estimand.

    The historical class name remains for registry compatibility.  This class
    builds an official Garak scan command and imports its authoritative report;
    it is deliberately not a URA prompt generator.
    """

    name = "garak"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        *,
        target_type: str = "openai.OpenAICompatible",
        target_name: str = "gpt-5-nano",
        probe_spec: str = "dan.Dan_11_0",
        detector_spec: str = "auto",
        generations: int = 1,
        seed: int = 0,
        eval_threshold: float = 0.5,
        python: str = "python",
        upstream_version: str = GARAK_VERSION,
    ) -> None:
        for field, value in (
            ("target_type", target_type),
            ("target_name", target_name),
            ("probe_spec", probe_spec),
            ("detector_spec", detector_spec),
            ("python", python),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Garak {field} must be a nonblank string")
        if isinstance(generations, bool) or not isinstance(generations, int) or generations < 1:
            raise ValueError("Garak generations must be a positive integer")
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("Garak seed must be an integer")
        if isinstance(eval_threshold, bool) or not isinstance(
            eval_threshold, (int, float)
        ):
            raise ValueError("Garak eval_threshold must be numeric")
        threshold = float(eval_threshold)
        if not math.isfinite(threshold) or threshold < 0.0 or threshold > 1.0:
            raise ValueError("Garak eval_threshold must be finite and in [0, 1]")
        if upstream_version != GARAK_VERSION:
            raise ValueError(f"Garak must be pinned to audited version {GARAK_VERSION}")

        self.target_type = target_type
        self.target_name = target_name
        self.probe_spec = probe_spec
        self.detector_spec = detector_spec
        self.generations = generations
        self.seed = seed
        self.eval_threshold = threshold
        self.python = python
        self.upstream_version = upstream_version

    def build_native_command(self, report_prefix: str | Path) -> list[str]:
        """Build, but do not execute, the documented full-scan CLI."""

        prefix = Path(report_prefix).resolve()
        return [
            self.python,
            "-m",
            "garak",
            "--target_type",
            self.target_type,
            "--target_name",
            self.target_name,
            "--probes",
            self.probe_spec,
            "--detectors",
            self.detector_spec,
            "--generations",
            str(self.generations),
            "--seed",
            str(self.seed),
            "--eval_threshold",
            str(self.eval_threshold),
            "--report_prefix",
            str(prefix),
        ]

    def import_run(
        self,
        report_path: str | Path,
        *,
        upstream_revision: str,
        expected_records: int,
        expected_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Validate and import one complete, pinned Garak report."""

        if not isinstance(upstream_revision, str) or not _COMMIT_RE.fullmatch(
            upstream_revision
        ):
            raise ValueError("Garak upstream_revision must be a full 40-hex commit")
        if upstream_revision.lower() != GARAK_REVISION:
            raise ExternalEngineOutputError(
                "Garak revision mismatch: "
                f"expected audited {GARAK_REVISION}, observed {upstream_revision.lower()}"
            )
        if (
            isinstance(expected_records, bool)
            or not isinstance(expected_records, int)
            or expected_records < 1
        ):
            raise ValueError("Garak expected_records must be a positive integer")

        resolved, report_bytes, records = _load_report(
            Path(report_path),
            expected_records=expected_records,
            max_artifact_bytes=max_artifact_bytes,
        )
        report_digest = require_expected_sha256(
            report_bytes, expected_sha256, role="Garak report"
        )

        if records[0].get("entry_type") != "start_run setup":
            raise ExternalEngineOutputError("Garak report must start with start_run setup")
        if len(records) < 3 or records[1].get("entry_type") != "init":
            raise ExternalEngineOutputError("Garak report second record must be init")
        if records[-1].get("entry_type") != "digest":
            raise ExternalEngineOutputError("Garak report must end with its native digest")

        by_type: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
        for line_no, record in enumerate(records, start=1):
            by_type[record["entry_type"]].append((line_no, record))
        for singleton in ("start_run setup", "init", "completion", "digest"):
            if len(by_type[singleton]) != 1:
                raise ExternalEngineOutputError(
                    f"Garak report must contain exactly one {singleton!r} record"
                )
        if not by_type["plugin_cache"]:
            raise ExternalEngineOutputError(
                "Garak report lacks the native plugin-cache provenance record"
            )
        if not by_type["attempt"] or not by_type["eval"]:
            raise ExternalEngineOutputError(
                "Garak report must contain nonempty attempt and eval records"
            )

        setup = records[0]
        expected_setup: dict[str, Any] = {
            "plugins.target_type": self.target_type,
            "plugins.target_name": self.target_name,
            "plugins.probe_spec": self.probe_spec,
            "plugins.detector_spec": self.detector_spec,
            "run.generations": self.generations,
            "run.seed": self.seed,
            "run.eval_threshold": self.eval_threshold,
            "system.skip_unknown": False,
        }
        for key, expected in expected_setup.items():
            if setup.get(key) != expected:
                raise ExternalEngineOutputError(
                    f"Garak setup mismatch for {key}: expected={expected!r}, "
                    f"observed={setup.get(key)!r}"
                )

        init = records[1]
        _strict_keys(
            init,
            required={"entry_type", "garak_version", "start_time", "run"},
            field="init",
        )
        if init.get("garak_version") != GARAK_VERSION:
            raise ExternalEngineOutputError(
                f"Garak report version must be {GARAK_VERSION!r}"
            )
        run_id = _nonblank(init.get("run"), field="init.run")
        _nonblank(init.get("start_time"), field="init.start_time")

        completion_line, completion = by_type["completion"][0]
        if completion_line >= len(records):
            raise ExternalEngineOutputError("Garak completion must precede the digest")
        _strict_keys(
            completion,
            required={"entry_type", "end_time", "run"},
            field="completion",
        )
        if completion.get("run") != run_id:
            raise ExternalEngineOutputError("Garak completion run UUID does not match init")
        _nonblank(completion.get("end_time"), field="completion.end_time")

        for line_no, cache_record in by_type["plugin_cache"]:
            _strict_keys(
                cache_record,
                required={"entry_type", "run", "plugin_cache"},
                field=f"line {line_no} plugin_cache",
            )
            if cache_record.get("run") != run_id:
                raise ExternalEngineOutputError(
                    f"Garak plugin_cache line {line_no} has a different run UUID"
                )
            cache = _object(
                cache_record.get("plugin_cache"), field=f"line {line_no}.plugin_cache"
            )
            if cache.get("version") != GARAK_VERSION:
                raise ExternalEngineOutputError(
                    f"Garak plugin_cache line {line_no} has the wrong version"
                )

        digest_record = records[-1]
        _strict_keys(
            digest_record,
            required={"entry_type", "meta", "eval"},
            field="digest",
        )
        digest_meta = _object(digest_record.get("meta"), field="digest.meta")
        if digest_meta.get("garak_version") != GARAK_VERSION:
            raise ExternalEngineOutputError("Garak digest version does not match init")
        if digest_meta.get("run_uuid") != run_id:
            raise ExternalEngineOutputError("Garak digest run UUID does not match init")
        if digest_meta.get("target_type") != self.target_type or digest_meta.get(
            "target_name"
        ) != self.target_name:
            raise ExternalEngineOutputError("Garak digest target identity mismatch")
        if digest_meta.get("probespec") != self.probe_spec:
            raise ExternalEngineOutputError("Garak digest probe specification mismatch")
        digest_setup = _object(digest_meta.get("setup"), field="digest.meta.setup")
        for key, expected in expected_setup.items():
            if digest_setup.get(key) != expected:
                raise ExternalEngineOutputError(
                    f"Garak digest setup diverges from the report for {key}"
                )
        digest_eval = _object(digest_record.get("eval"), field="digest.eval")
        if not digest_eval:
            raise ExternalEngineOutputError("Garak digest contains no evaluator summary")
        if digest_meta.get("plugin_cache_source") not in (None, GARAK_VERSION):
            raise ExternalEngineOutputError(
                "Garak digest plugin-cache version does not match the audited release"
            )

        for line_no, payload in by_type["payload_init"]:
            _strict_keys(
                payload,
                required={
                    "entry_type",
                    "loading_complete",
                    "payload_name",
                    "payload_path",
                    "entries",
                    "filesize",
                    "mtime",
                },
                field=f"payload_init line {line_no}",
            )
            if payload.get("loading_complete") != "payload":
                raise ExternalEngineOutputError(
                    f"Garak payload_init line {line_no} has invalid completion marker"
                )
            for field in ("payload_name", "payload_path", "mtime"):
                _nonblank(payload.get(field), field=f"line {line_no}.{field}")
            _integer(payload.get("entries"), field=f"line {line_no}.entries")
            _integer(payload.get("filesize"), field=f"line {line_no}.filesize")
        for line_no, tree in by_type["tree_data"]:
            _strict_keys(
                tree,
                required={
                    "entry_type",
                    "probe",
                    "detector",
                    "node_id",
                    "node_parent",
                    "node_score",
                    "surface_forms",
                },
                field=f"tree_data line {line_no}",
            )
            for field in ("probe", "detector", "node_id"):
                _nonblank(tree.get(field), field=f"line {line_no}.{field}")
            if tree.get("node_parent") is not None:
                _nonblank(tree.get("node_parent"), field=f"line {line_no}.node_parent")
            _score(tree.get("node_score"), field=f"line {line_no}.node_score")
            if not isinstance(tree.get("surface_forms"), list):
                raise ExternalEngineOutputError(
                    f"Garak tree_data line {line_no}.surface_forms must be an array"
                )

        started: dict[str, tuple[int, dict[str, Any]]] = {}
        completed: dict[str, tuple[int, dict[str, Any]]] = {}
        for line_no, attempt in by_type["attempt"]:
            _strict_keys(
                attempt,
                required=_ATTEMPT_KEYS,
                field=f"attempt line {line_no}",
            )
            attempt_id = _nonblank(attempt.get("uuid"), field=f"line {line_no}.uuid")
            _integer(attempt.get("seq"), field=f"line {line_no}.seq")
            _nonblank(
                attempt.get("probe_classname"), field=f"line {line_no}.probe_classname"
            )
            if not isinstance(attempt.get("probe_params"), dict):
                raise ExternalEngineOutputError(
                    f"Garak attempt line {line_no}.probe_params must be an object"
                )
            for field in ("targets", "outputs", "conversations", "reverse_translation_outputs"):
                if not isinstance(attempt.get(field), list):
                    raise ExternalEngineOutputError(
                        f"Garak attempt line {line_no}.{field} must be an array"
                    )
            if not isinstance(attempt.get("notes"), dict):
                raise ExternalEngineOutputError(
                    f"Garak attempt line {line_no}.notes must be an object"
                )
            if not isinstance(attempt.get("detector_results"), dict):
                raise ExternalEngineOutputError(
                    f"Garak attempt line {line_no}.detector_results must be an object"
                )
            status = attempt.get("status")
            destination = started if status == 1 else completed if status == 2 else None
            if destination is None:
                raise ExternalEngineOutputError(
                    f"Garak attempt line {line_no} must have status 1 or 2"
                )
            if attempt_id in destination:
                raise ExternalEngineOutputError(
                    f"duplicate Garak attempt status {status} for UUID {attempt_id}"
                )
            destination[attempt_id] = (line_no, attempt)

        if set(started) != set(completed):
            raise ExternalEngineOutputError(
                "Garak report has unpaired status-1/status-2 attempt UUIDs"
            )

        pair_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "fails": 0, "nones": 0}
        )
        cases: list[NativeEngineCase] = []
        total_output_slots = 0
        scored_output_slots = 0
        for attempt_id in sorted(completed):
            started_line, started_attempt = started[attempt_id]
            completed_line, completed_attempt = completed[attempt_id]
            if completed_line <= started_line:
                raise ExternalEngineOutputError(
                    f"Garak completed attempt {attempt_id} precedes its started row"
                )
            started_content = dict(started_attempt)
            completed_content = dict(completed_attempt)
            started_content.pop("status")
            completed_content.pop("status")
            started_detectors = started_content.pop("detector_results")
            completed_detectors = completed_content.pop("detector_results")
            started_notes = started_content.pop("notes")
            completed_notes = completed_content.pop("notes")
            if started_content != completed_content:
                raise ExternalEngineOutputError(
                    f"Garak paired attempt {attempt_id} changed outside detector results"
                )
            if any(completed_notes.get(key) != value for key, value in started_notes.items()):
                raise ExternalEngineOutputError(
                    f"Garak paired attempt {attempt_id} changed or dropped pre-detector notes"
                )
            detectors = _object(
                completed_detectors, field=f"attempt {attempt_id}.detector_results"
            )
            if not detectors:
                raise ExternalEngineOutputError(
                    f"Garak completed attempt {attempt_id} has no detector results"
                )
            # TreeSearchProbe runs its primary detector while expanding the tree,
            # before the harness writes the status-1 row.  Those source-native
            # scores are legitimate, but the later status-2 row must retain them
            # unchanged rather than silently replacing or dropping them.
            for detector, early_scores in started_detectors.items():
                if detector not in detectors or detectors[detector] != early_scores:
                    raise ExternalEngineOutputError(
                        f"Garak paired attempt {attempt_id} changed an early detector result"
                    )
            outputs = completed_attempt["outputs"]
            if len(outputs) != self.generations:
                raise ExternalEngineOutputError(
                    f"Garak attempt {attempt_id} output count does not match generations"
                )
            for output_index, output in enumerate(outputs):
                if output is not None:
                    _message_has_evidence(
                        output,
                        field=f"attempt {attempt_id}.outputs[{output_index}]",
                    )
            _validate_conversation(
                completed_attempt["prompt"], field=f"attempt {attempt_id}.prompt"
            )
            conversations = completed_attempt["conversations"]
            if len(conversations) != self.generations:
                raise ExternalEngineOutputError(
                    f"Garak attempt {attempt_id} conversation count does not match generations"
                )
            for conversation_index, conversation in enumerate(conversations):
                turns = _validate_conversation(
                    conversation,
                    field=(
                        f"attempt {attempt_id}.conversations[{conversation_index}]"
                    ),
                )
                assistant_messages = [
                    turn["content"]
                    for turn in turns
                    if turn.get("role") == "assistant"
                ]
                if not assistant_messages or assistant_messages[-1] != outputs[
                    conversation_index
                ]:
                    raise ExternalEngineOutputError(
                        f"Garak attempt {attempt_id} output/conversation alignment failed"
                    )
            total_output_slots += len(outputs)
            any_hit = False
            any_pass = False
            numeric_scores: list[float] = []
            normalized_detectors: dict[str, list[float | None]] = {}
            for detector, raw_scores in detectors.items():
                detector_name = _nonblank(
                    detector, field=f"attempt {attempt_id}.detector name"
                )
                if not isinstance(raw_scores, list) or len(raw_scores) != len(outputs):
                    raise ExternalEngineOutputError(
                        f"Garak detector {detector_name!r} for attempt {attempt_id} "
                        "must align exactly with outputs"
                    )
                normalized: list[float | None] = []
                pair = (completed_attempt["probe_classname"], detector_name)
                for index, raw_score in enumerate(raw_scores):
                    if raw_score is None:
                        normalized.append(None)
                        pair_counts[pair]["nones"] += 1
                        continue
                    value = _score(
                        raw_score,
                        field=f"attempt {attempt_id}.{detector_name}[{index}]",
                    )
                    if not _message_has_evidence(
                        outputs[index], field=f"attempt {attempt_id}.outputs[{index}]"
                    ):
                        raise ExternalEngineOutputError(
                            f"Garak scored an empty output for attempt {attempt_id}, "
                            f"detector {detector_name!r}, generation {index}"
                        )
                    scored_output_slots += 1
                    normalized.append(value)
                    numeric_scores.append(value)
                    if value >= self.eval_threshold:
                        pair_counts[pair]["fails"] += 1
                        any_hit = True
                    else:
                        pair_counts[pair]["passed"] += 1
                        any_pass = True
                normalized_detectors[detector_name] = normalized

            if any_hit and any_pass:
                outcome = "mixed_detector_outcomes"
            elif any_hit:
                outcome = "detector_hit"
            elif any_pass:
                outcome = "detector_pass"
            else:
                outcome = "detectors_unscored"
            case_digest = json_sha256(completed_attempt)
            cases.append(
                NativeEngineCase(
                    id=f"garak:{attempt_id}",
                    source_run_id=run_id,
                    target_model=f"{self.target_type}:{self.target_name}",
                    attack_method=f"garak:{completed_attempt['probe_classname']}",
                    original_input=completed_attempt["prompt"],
                    adversarial_input=_prompt_text(completed_attempt["prompt"]),
                    target_outputs=_text_outputs(outputs),
                    native_outcome=outcome,
                    native_scores=(
                        {
                            "maximum_detector_score": max(numeric_scores),
                            "minimum_detector_score": min(numeric_scores),
                        }
                        if numeric_scores
                        else {}
                    ),
                    native_details={
                        "sequence": completed_attempt["seq"],
                        "goal": completed_attempt["goal"],
                        "targets": completed_attempt["targets"],
                        "probe_parameters": completed_attempt["probe_params"],
                        "notes": completed_attempt["notes"],
                        "pre_detector_notes": started_notes,
                        "outputs": outputs,
                        "conversations": completed_attempt["conversations"],
                        "reverse_translation_outputs": completed_attempt[
                            "reverse_translation_outputs"
                        ],
                        "detector_results": normalized_detectors,
                        "eval_threshold": self.eval_threshold,
                        "full_completed_attempt_record": completed_attempt,
                        "paired_started_record_line": started_line,
                    },
                    source_artifact_role="report_jsonl",
                    source_record=f"jsonl:line={completed_line}",
                    source_record_sha256=case_digest,
                )
            )

        observed_evals: dict[tuple[str, str], dict[str, int]] = {}
        eval_rows: list[dict[str, Any]] = []
        for line_no, eval_record in by_type["eval"]:
            _strict_keys(
                eval_record,
                required=_EVAL_REQUIRED_KEYS,
                optional=_EVAL_CI_KEYS,
                field=f"eval line {line_no}",
            )
            probe = _nonblank(eval_record.get("probe"), field=f"line {line_no}.probe")
            detector = _nonblank(
                eval_record.get("detector"), field=f"line {line_no}.detector"
            )
            key = (probe, detector)
            if key in observed_evals:
                raise ExternalEngineOutputError(
                    f"duplicate Garak eval row for probe/detector {key!r}"
                )
            counts = {
                name: _integer(eval_record.get(name), field=f"line {line_no}.{name}")
                for name in ("passed", "fails", "nones")
            }
            if eval_record.get("total_evaluated") != counts["passed"] + counts["fails"]:
                raise ExternalEngineOutputError(
                    f"Garak eval line {line_no} has inconsistent total_evaluated"
                )
            if eval_record.get("total_processed") != sum(counts.values()):
                raise ExternalEngineOutputError(
                    f"Garak eval line {line_no} has inconsistent total_processed"
                )
            ci_present = _EVAL_CI_KEYS & set(eval_record)
            if ci_present and ci_present != _EVAL_CI_KEYS:
                raise ExternalEngineOutputError(
                    f"Garak eval line {line_no} has a partial confidence interval"
                )
            if ci_present:
                if eval_record.get("confidence_method") != "bootstrap":
                    raise ExternalEngineOutputError(
                        f"Garak eval line {line_no} has an unknown CI method"
                    )
                confidence = _score(
                    eval_record.get("confidence"), field=f"line {line_no}.confidence"
                )
                lower = _score(
                    eval_record.get("confidence_lower"),
                    field=f"line {line_no}.confidence_lower",
                )
                upper = _score(
                    eval_record.get("confidence_upper"),
                    field=f"line {line_no}.confidence_upper",
                )
                if confidence <= 0.0 or lower > upper:
                    raise ExternalEngineOutputError(
                        f"Garak eval line {line_no} has invalid confidence bounds"
                    )
            observed_evals[key] = counts
            eval_rows.append(eval_record)

        if set(observed_evals) != set(pair_counts):
            raise ExternalEngineOutputError(
                "Garak eval probe/detector pairs do not match completed attempts"
            )
        for key, reconstructed in pair_counts.items():
            if observed_evals[key] != reconstructed:
                raise ExternalEngineOutputError(
                    f"Garak eval counts do not reconstruct for {key!r}: "
                    f"reported={observed_evals[key]!r}, observed={reconstructed!r}"
                )

        pair_aggregates: list[dict[str, Any]] = []
        for (probe, detector), counts in sorted(pair_counts.items()):
            denominator = counts["passed"] + counts["fails"]
            pair_aggregates.append(
                {
                    "probe": probe,
                    "detector": detector,
                    **counts,
                    "native_attack_success_rate": (
                        counts["fails"] / denominator if denominator else None
                    ),
                }
            )

        artifact = NativeArtifactFile(
            role="report_jsonl",
            path=str(resolved),
            sha256=report_digest,
            bytes=len(report_bytes),
            records=len(records),
        )
        return NativeEngineRun(
            engine="garak",
            native_schema=GARAK_NATIVE_SCHEMA,
            native_run_id=run_id,
            upstream_repository=GARAK_REPOSITORY,
            upstream_version=GARAK_VERSION,
            upstream_revision=GARAK_REVISION,
            source_artifacts=[artifact],
            target_models=[f"{self.target_type}:{self.target_name}"],
            model_roles={"target": f"{self.target_type}:{self.target_name}"},
            cases=cases,
            native_aggregates={
                "eval_threshold": self.eval_threshold,
                "probe_detector_results": pair_aggregates,
                "native_eval_records": eval_rows,
                "digest": digest_record,
                "global_asr_not_reported": (
                    "Detector outputs overlap and remain separate probe/detector estimands."
                ),
            },
            import_accounting={
                "report_records": len(records),
                "attempts": len(cases),
                "target_output_slots": total_output_slots,
                "detector_score_slots": scored_output_slots,
                "probe_detector_pairs": len(pair_counts),
            },
            measurement_semantics=(
                "Garak detector scores at or above the configured threshold are native "
                "hits/failures; lower scores are native passes and null scores are excluded. "
                "Rates remain per probe/detector because overlapping detectors must not be "
                "collapsed into URA common ASR/FRR."
            ),
        )

    def generate(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> Iterable[Attempt]:
        del datapoint, budget
        raise ExternalEngineConformanceError(
            "Garak is supported through build_native_command()/import_run(); its full "
            "target/detector report cannot be represented as Runner seed generation"
        )


__all__ = [
    "GARAK_NATIVE_SCHEMA",
    "GARAK_REPOSITORY",
    "GARAK_REVISION",
    "GARAK_VERSION",
    "GarakAttacker",
]
