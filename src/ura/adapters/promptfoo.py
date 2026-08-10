"""Promptfoo 0.121.15 native red-team evaluation integration.

Promptfoo's supported red-team surface is a complete target evaluation, not a
static prompt-export API.  URA therefore admits the generated YAML and the full
JSON ``OutputFile`` written by the official CLI.  It preserves target responses,
grader results, plugin/strategy metadata, errors, traces and portable blob media,
and never replays a selected test through ``Runner``.

Primary upstream contracts:

* https://github.com/promptfoo/promptfoo/tree/0.121.15
* https://www.promptfoo.dev/docs/guides/llm-redteaming/
* https://www.promptfoo.dev/docs/configuration/outputs/
* ``src/types/index.ts`` and ``src/util/output.ts`` at ``PROMPTFOO_REVISION``
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
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


PROMPTFOO_REPOSITORY = "https://github.com/promptfoo/promptfoo"
PROMPTFOO_VERSION = "0.121.15"
PROMPTFOO_REVISION = "4805856060d026521794d4e69decb938155580ad"
PROMPTFOO_NATIVE_SCHEMA = "promptfoo-output-file/redteam/0.121.15"

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_BLOB_URI_RE = re.compile(r"promptfoo://blob/([0-9a-fA-F]{64})")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_OUTPUT_FILE_REQUIRED = {"evalId", "results", "config", "shareableUrl", "metadata"}
_OUTPUT_FILE_OPTIONAL = {"vars", "runtimeOptions", "traces", "blobAssets"}
_SUMMARY_KEYS = {"version", "timestamp", "results", "prompts", "stats"}
_RESULT_REQUIRED = {
    "promptIdx",
    "testIdx",
    "testCase",
    "promptId",
    "provider",
    "prompt",
    "vars",
    "failureReason",
    "success",
    "score",
    "latencyMs",
    "namedScores",
}
_RESULT_OPTIONAL = {
    "id",
    "description",
    "response",
    "error",
    "gradingResult",
    "cost",
    "metadata",
    "tokenUsage",
    "evaluationId",
    "traceId",
}
_TEST_CASE_KEYS = {
    "description",
    "vars",
    "provider",
    "providers",
    "prompts",
    "providerOutput",
    "assert",
    "assertScoringFunction",
    "options",
    "threshold",
    "metadata",
}
_PROMPT_REQUIRED = {"raw", "label"}
_PROMPT_OPTIONAL = {"id", "template", "display", "config"}
_RESPONSE_KEYS = {
    "cached",
    "cost",
    "error",
    "materializationHandled",
    "materializedVars",
    "isBase64",
    "format",
    "logProbs",
    "latencyMs",
    "metadata",
    "prompt",
    "raw",
    "output",
    "inputMaterialization",
    "providerTransformedOutput",
    "tokenUsage",
    "isRefusal",
    "conversationEnded",
    "conversationEndReason",
    "sessionId",
    "guardrails",
    "finishReason",
    "audio",
    "video",
    "images",
}
_GRADING_KEYS = {
    "pass",
    "score",
    "reason",
    "namedScores",
    "namedScoreWeights",
    "tokensUsed",
    "componentResults",
    "assertion",
    "comment",
    "suggestions",
    "metadata",
}
def _object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExternalEngineOutputError(f"Promptfoo {field} must be an object")
    return value


def _nonblank(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExternalEngineOutputError(f"Promptfoo {field} must be a nonblank string")
    return value


def _integer(value: Any, *, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ExternalEngineOutputError(
            f"Promptfoo {field} must be an integer >= {minimum}"
        )
    return value


def _number(value: Any, *, field: str, minimum: float | None = None) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExternalEngineOutputError(f"Promptfoo {field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (minimum is not None and result < minimum):
        suffix = "finite" if minimum is None else f"finite and >= {minimum:g}"
        raise ExternalEngineOutputError(f"Promptfoo {field} must be {suffix}")
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
            f"Promptfoo {field} schema mismatch ({'; '.join(parts)})"
        )


def _configured_id(value: Any, *, field: str) -> str:
    if isinstance(value, str):
        return _nonblank(value, field=field)
    item = _object(value, field=field)
    return _nonblank(item.get("id"), field=f"{field}.id")


def _configured_ids(value: Any, *, field: str) -> list[str]:
    if isinstance(value, str):
        return [_nonblank(value, field=field)]
    if isinstance(value, list):
        ids = [
            _configured_id(item, field=f"{field}[{index}]")
            for index, item in enumerate(value)
        ]
    elif isinstance(value, dict) and "id" not in value:
        ids = [_nonblank(key, field=f"{field} provider-map key") for key in value]
    else:
        ids = [_configured_id(value, field=field)]
    if not ids or len(ids) != len(set(ids)):
        raise ExternalEngineOutputError(
            f"Promptfoo {field} must contain unique provider/plugin identities"
        )
    return ids


def _redteam_ids(
    value: Any, *, field: str, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        qualifier = "an array" if allow_empty else "a nonempty array"
        raise ExternalEngineOutputError(f"Promptfoo {field} must be {qualifier}")
    ids = [
        _configured_id(item, field=f"{field}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(ids) != len(set(ids)):
        raise ExternalEngineOutputError(f"Promptfoo {field} contains duplicate IDs")
    return ids


def _implicit_basic_enabled(value: Any) -> bool:
    """Mirror Promptfoo's source-native basic-test inclusion rule."""

    if not isinstance(value, list):
        raise ExternalEngineOutputError(
            "Promptfoo config.redteam.strategies must be an array"
        )
    for index, item in enumerate(value):
        if isinstance(item, str):
            strategy_id = item
            strategy_config: Any = None
        else:
            strategy = _object(item, field=f"config.redteam.strategies[{index}]")
            strategy_id = strategy.get("id")
            strategy_config = strategy.get("config")
        if strategy_id != "basic":
            continue
        if strategy_config is None:
            return True
        strategy_config = _object(
            strategy_config,
            field=f"config.redteam.strategies[{index}].config",
        )
        enabled = strategy_config.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ExternalEngineOutputError(
                "Promptfoo basic strategy enabled flag must be boolean"
            )
        return enabled
    return True


def _grader_identity(config: Mapping[str, Any]) -> str:
    default_test = _object(config.get("defaultTest"), field="config.defaultTest")
    provider = default_test.get("provider")
    if provider:
        return _configured_id(provider, field="config.defaultTest.provider")
    options = _object(
        default_test.get("options"), field="config.defaultTest.options"
    )
    option_provider = options.get("provider")
    if isinstance(option_provider, dict) and option_provider.get("text"):
        option_provider = option_provider["text"]
    if not option_provider:
        raise ExternalEngineOutputError(
            "Promptfoo config must explicitly bind the native grading provider"
        )
    return _configured_id(
        option_provider, field="config.defaultTest.options.provider"
    )


def _assertion_types(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        assertion_type = value.get("type")
        if isinstance(assertion_type, str):
            found.add(assertion_type)
        for child in value.values():
            found.update(_assertion_types(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_assertion_types(child))
    return found


def _contains_grader_error(value: Any) -> bool:
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if isinstance(metadata, dict) and metadata.get("graderError") is True:
            return True
        return any(_contains_grader_error(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_grader_error(child) for child in value)
    return False


def _response_has_evidence(response: Mapping[str, Any]) -> bool:
    output = response.get("output")
    if isinstance(output, str):
        if output.strip():
            return True
    elif output is not None and output not in ({}, []):
        return True
    for field in ("images",):
        value = response.get(field)
        if isinstance(value, list) and value:
            return True
    for field in ("audio", "video"):
        value = response.get(field)
        if isinstance(value, dict) and value:
            return True
    return False


def _response_texts(response: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    output = response.get("output")
    if isinstance(output, str) and output.strip():
        values.append(output)
    audio = response.get("audio")
    if isinstance(audio, dict):
        transcript = audio.get("transcript")
        if isinstance(transcript, str) and transcript.strip() and transcript not in values:
            values.append(transcript)
    return values


def _validate_nonnegative_tree(value: Any, *, field: str) -> None:
    """Validate Promptfoo's nested token-usage counters."""

    if isinstance(value, dict):
        for key, child in value.items():
            _nonblank(key, field=f"{field} key")
            _validate_nonnegative_tree(child, field=f"{field}[{key!r}]")
        return
    _number(value, field=field, minimum=0)


def _collect_blob_hashes(value: Any, found: set[str] | None = None) -> set[str]:
    hashes = found if found is not None else set()
    if isinstance(value, str):
        hashes.update(match.lower() for match in _BLOB_URI_RE.findall(value))
    elif isinstance(value, dict):
        candidate_hash = value.get("hash")
        if isinstance(candidate_hash, str) and _SHA256_RE.fullmatch(candidate_hash):
            hashes.add(candidate_hash.lower())
        uri = value.get("uri")
        if isinstance(uri, str):
            hashes.update(match.lower() for match in _BLOB_URI_RE.findall(uri))
        for child in value.values():
            _collect_blob_hashes(child, hashes)
    elif isinstance(value, list):
        for child in value:
            _collect_blob_hashes(child, hashes)
    return hashes


def _validate_blob_assets(output: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    referenced = _collect_blob_hashes(
        {"results": output.get("results"), "traces": output.get("traces")}
    )
    raw_assets = output.get("blobAssets", [])
    if not isinstance(raw_assets, list):
        raise ExternalEngineOutputError("Promptfoo blobAssets must be an array")
    assets: dict[str, dict[str, Any]] = {}
    for index, raw_asset in enumerate(raw_assets):
        asset = _object(raw_asset, field=f"blobAssets[{index}]")
        _strict_keys(
            asset,
            required={"hash", "mimeType", "sizeBytes", "data"},
            field=f"blobAssets[{index}]",
        )
        digest = _nonblank(asset.get("hash"), field=f"blobAssets[{index}].hash").lower()
        if not _SHA256_RE.fullmatch(digest):
            raise ExternalEngineOutputError(
                f"Promptfoo blobAssets[{index}].hash is not a full SHA-256"
            )
        if digest in assets:
            raise ExternalEngineOutputError(f"duplicate Promptfoo blob asset {digest}")
        _nonblank(asset.get("mimeType"), field=f"blobAssets[{index}].mimeType")
        size = _integer(
            asset.get("sizeBytes"), field=f"blobAssets[{index}].sizeBytes"
        )
        encoded = _nonblank(asset.get("data"), field=f"blobAssets[{index}].data")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ExternalEngineOutputError(
                f"Promptfoo blobAssets[{index}].data is not strict base64"
            ) from exc
        if len(decoded) != size or hashlib.sha256(decoded).hexdigest() != digest:
            raise ExternalEngineOutputError(
                f"Promptfoo blob asset {digest} size/digest does not match embedded bytes"
            )
        assets[digest] = asset
    if set(assets) != referenced:
        raise ExternalEngineOutputError(
            "Promptfoo portable blob inventory mismatch: "
            f"referenced={sorted(referenced)!r}, embedded={sorted(assets)!r}; "
            "use `promptfoo export eval <id> --include-media`"
        )
    return assets


def _validate_traces(
    output: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    redteam: Mapping[str, Any],
    eval_id: str,
    referenced_trace_ids: set[str],
) -> list[dict[str, Any]]:
    config_tracing = config.get("tracing")
    redteam_tracing = redteam.get("tracing")
    tracing_enabled = any(
        isinstance(value, dict) and value.get("enabled") is True
        for value in (config_tracing, redteam_tracing)
    )
    raw_traces = output.get("traces", [])
    if not isinstance(raw_traces, list):
        raise ExternalEngineOutputError("Promptfoo OutputFile.traces must be an array")
    if tracing_enabled and not raw_traces:
        raise ExternalEngineOutputError(
            "Promptfoo tracing was enabled but the native OutputFile contains no traces"
        )
    traces: list[dict[str, Any]] = []
    observed: set[str] = set()
    for index, raw_trace in enumerate(raw_traces):
        trace = _object(raw_trace, field=f"traces[{index}]")
        _strict_keys(
            trace,
            required={"traceId", "evaluationId", "testCaseId", "spans"},
            optional={"metadata"},
            field=f"traces[{index}]",
        )
        trace_id = _nonblank(trace.get("traceId"), field=f"traces[{index}].traceId")
        if trace_id in observed:
            raise ExternalEngineOutputError(f"duplicate Promptfoo traceId {trace_id!r}")
        observed.add(trace_id)
        if trace.get("evaluationId") != eval_id:
            raise ExternalEngineOutputError(
                f"Promptfoo trace {trace_id!r} belongs to a different evaluation"
            )
        _nonblank(trace.get("testCaseId"), field=f"traces[{index}].testCaseId")
        spans = trace.get("spans")
        if not isinstance(spans, list) or not spans:
            raise ExternalEngineOutputError(
                f"Promptfoo trace {trace_id!r} must retain nonempty spans"
            )
        span_ids: set[str] = set()
        for span_index, raw_span in enumerate(spans):
            span = _object(raw_span, field=f"traces[{index}].spans[{span_index}]")
            _strict_keys(
                span,
                required={"spanId", "name", "startTime"},
                optional={
                    "parentSpanId",
                    "endTime",
                    "attributes",
                    "statusCode",
                    "statusMessage",
                },
                field=f"traces[{index}].spans[{span_index}]",
            )
            span_id = _nonblank(
                span.get("spanId"), field=f"traces[{index}].spans[{span_index}].spanId"
            )
            if span_id in span_ids:
                raise ExternalEngineOutputError(
                    f"Promptfoo trace {trace_id!r} contains duplicate span IDs"
                )
            span_ids.add(span_id)
            _nonblank(
                span.get("name"), field=f"traces[{index}].spans[{span_index}].name"
            )
            start = _number(
                span.get("startTime"),
                field=f"traces[{index}].spans[{span_index}].startTime",
                minimum=0,
            )
            if span.get("endTime") is not None:
                end = _number(
                    span.get("endTime"),
                    field=f"traces[{index}].spans[{span_index}].endTime",
                    minimum=0,
                )
                if end < start:
                    raise ExternalEngineOutputError(
                        f"Promptfoo trace {trace_id!r} has a span ending before it starts"
                    )
        traces.append(trace)
    if not referenced_trace_ids.issubset(observed):
        raise ExternalEngineOutputError(
            "Promptfoo result trace linkage is missing from the exported trace inventory"
        )
    if tracing_enabled and not referenced_trace_ids:
        raise ExternalEngineOutputError(
            "Promptfoo tracing was enabled but result rows contain no trace linkage"
        )
    return traces


def _normalize_sequence(
    values: Sequence[str], *, field: str, allow_empty: bool = False
) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Promptfoo {field} must contain nonblank strings")
        normalized.append(value)
    if (not normalized and not allow_empty) or len(normalized) != len(set(normalized)):
        qualifier = "unique values" if allow_empty else "one or more unique values"
        raise ValueError(f"Promptfoo {field} must contain {qualifier}")
    return tuple(normalized)


class PromptfooAttacker(BaseAttacker):
    """Import complete Promptfoo red-team evaluations with native polarity."""

    name = "promptfoo"
    supported_integration_mode = "native_artifact_import"
    runner_replay_eligible = False

    def __init__(
        self,
        *,
        target_providers: Sequence[str] = ("openai:gpt-5",),
        plugins: Sequence[str] = ("harmful:hate",),
        strategies: Sequence[str] = ("basic",),
        include_basic: bool = True,
        inject_var: str = "prompt",
        generation_provider: str = "openai:gpt-5.5-2026-04-23",
        grader_provider: str = "openai:gpt-5.5-2026-04-23",
        cli: str = "promptfoo",
        upstream_version: str = PROMPTFOO_VERSION,
    ) -> None:
        self.target_providers = _normalize_sequence(
            target_providers, field="target_providers"
        )
        self.plugins = _normalize_sequence(plugins, field="plugins")
        self.strategies = _normalize_sequence(
            strategies, field="strategies", allow_empty=True
        )
        if not isinstance(include_basic, bool):
            raise ValueError("Promptfoo include_basic must be boolean")
        for field, value in (
            ("generation_provider", generation_provider),
            ("grader_provider", grader_provider),
            ("inject_var", inject_var),
            ("cli", cli),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Promptfoo {field} must be a nonblank string")
        if upstream_version != PROMPTFOO_VERSION:
            raise ValueError(
                f"Promptfoo must be pinned to audited version {PROMPTFOO_VERSION}"
            )
        self.generation_provider = generation_provider
        self.grader_provider = grader_provider
        self.include_basic = include_basic
        self.inject_var = inject_var
        self.cli = cli
        self.upstream_version = upstream_version

    def build_native_commands(
        self,
        source_config: str | Path,
        generated_config: str | Path,
        results_json: str | Path,
    ) -> tuple[list[str], list[str]]:
        """Build the official strict generate-then-evaluate command pair."""

        source = Path(source_config).resolve(strict=True)
        if not source.is_file():
            raise ValueError(f"Promptfoo source config is not a file: {source}")
        generated = Path(generated_config).resolve()
        results = Path(results_json).resolve()
        if len({source, generated, results}) != 3:
            raise ValueError("Promptfoo source, generated and result paths must be distinct")
        generate = [
            self.cli,
            "redteam",
            "generate",
            "-c",
            str(source),
            "--strict",
            "--force",
            "--no-cache",
            "--no-progress-bar",
            "-o",
            str(generated),
        ]
        evaluate = [
            self.cli,
            "redteam",
            "eval",
            "-c",
            str(generated),
            "--no-cache",
            "--no-share",
            "--no-progress-bar",
            "--no-table",
            "-o",
            str(results),
        ]
        return generate, evaluate

    def build_native_export_command(
        self, eval_id: str, results_json: str | Path
    ) -> list[str]:
        """Build the official portable-media export for an evaluated run."""

        if not isinstance(eval_id, str) or not eval_id.strip():
            raise ValueError("Promptfoo eval_id must be nonblank")
        return [
            self.cli,
            "export",
            "eval",
            eval_id,
            "--include-media",
            "--output",
            str(Path(results_json).resolve()),
        ]

    def import_run(
        self,
        results_json: str | Path,
        *,
        generated_config: str | Path,
        upstream_revision: str,
        expected_results: int,
        expected_results_sha256: str | None = None,
        expected_config_sha256: str | None = None,
        max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> NativeEngineRun:
        """Validate a complete Promptfoo OutputFile and its generated YAML."""

        if not isinstance(upstream_revision, str) or not _COMMIT_RE.fullmatch(
            upstream_revision
        ):
            raise ValueError("Promptfoo upstream_revision must be a full 40-hex commit")
        if upstream_revision.lower() != PROMPTFOO_REVISION:
            raise ExternalEngineOutputError(
                "Promptfoo revision mismatch: expected audited "
                f"{PROMPTFOO_REVISION}, observed {upstream_revision.lower()}"
            )
        if (
            isinstance(expected_results, bool)
            or not isinstance(expected_results, int)
            or expected_results < 1
        ):
            raise ValueError("Promptfoo expected_results must be a positive integer")

        result_path, result_bytes, result_text = read_utf8_artifact(
            Path(results_json), max_bytes=max_artifact_bytes
        )
        config_path, config_bytes, config_text = read_utf8_artifact(
            Path(generated_config), max_bytes=max_artifact_bytes
        )
        if not config_text.strip():
            raise ExternalEngineOutputError("Promptfoo generated YAML is blank")
        result_digest = require_expected_sha256(
            result_bytes, expected_results_sha256, role="Promptfoo results JSON"
        )
        config_digest = require_expected_sha256(
            config_bytes, expected_config_sha256, role="Promptfoo generated config"
        )
        try:
            parsed = strict_json_loads(result_text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ExternalEngineOutputError(
                f"invalid Promptfoo results JSON: {exc}"
            ) from exc
        output = _object(parsed, field="output root")
        _strict_keys(
            output,
            required=_OUTPUT_FILE_REQUIRED,
            optional=_OUTPUT_FILE_OPTIONAL,
            field="OutputFile",
        )
        eval_id = _nonblank(output.get("evalId"), field="OutputFile.evalId")
        if output.get("shareableUrl") is not None:
            raise ExternalEngineOutputError(
                "Promptfoo native run must be exported with sharing disabled"
            )

        metadata = _object(output.get("metadata"), field="OutputFile.metadata")
        _strict_keys(
            metadata,
            required={
                "promptfooVersion",
                "nodeVersion",
                "platform",
                "arch",
                "exportedAt",
            },
            optional={"evaluationCreatedAt", "author"},
            field="OutputFile.metadata",
        )
        if metadata.get("promptfooVersion") != PROMPTFOO_VERSION:
            raise ExternalEngineOutputError(
                f"Promptfoo export version must be {PROMPTFOO_VERSION!r}"
            )
        for field in ("nodeVersion", "platform", "arch", "exportedAt"):
            _nonblank(metadata.get(field), field=f"metadata.{field}")

        config = _object(output.get("config"), field="OutputFile.config")
        redteam = _object(config.get("redteam"), field="config.redteam")
        purpose = _nonblank(redteam.get("purpose"), field="config.redteam.purpose")
        artifact_inject_var = redteam.get("injectVar")
        if artifact_inject_var is None:
            # Promptfoo may infer the variable and omit it from generated YAML.
            # The importer requires the caller to preregister that identity and
            # verifies it against every generated test/result below.
            inject_var = self.inject_var
            inject_var_source = "adapter_preregistered"
        else:
            inject_var = _nonblank(
                artifact_inject_var, field="config.redteam.injectVar"
            )
            if inject_var != self.inject_var:
                raise ExternalEngineOutputError(
                    "Promptfoo inject-variable mismatch: "
                    f"configured={self.inject_var!r}, artifact={inject_var!r}"
                )
            inject_var_source = "artifact"
        generation_provider = _configured_id(
            redteam.get("provider"), field="config.redteam.provider"
        )
        if generation_provider != self.generation_provider:
            raise ExternalEngineOutputError(
                "Promptfoo generation-provider mismatch: "
                f"configured={self.generation_provider!r}, artifact={generation_provider!r}"
            )
        grader_provider = _grader_identity(config)
        if grader_provider != self.grader_provider:
            raise ExternalEngineOutputError(
                "Promptfoo grader-provider mismatch: "
                f"configured={self.grader_provider!r}, artifact={grader_provider!r}"
            )
        config_plugins = _redteam_ids(
            redteam.get("plugins"), field="config.redteam.plugins"
        )
        config_strategies = _redteam_ids(
            redteam.get("strategies"),
            field="config.redteam.strategies",
            allow_empty=True,
        )
        if set(config_plugins) != set(self.plugins):
            raise ExternalEngineOutputError("Promptfoo red-team plugin set mismatch")
        if set(config_strategies) != set(self.strategies):
            raise ExternalEngineOutputError("Promptfoo red-team strategy set mismatch")
        artifact_include_basic = _implicit_basic_enabled(redteam.get("strategies"))
        if artifact_include_basic is not self.include_basic:
            raise ExternalEngineOutputError(
                "Promptfoo implicit-basic inclusion does not match adapter configuration"
            )

        provider_config = config.get("providers")
        if provider_config is None:
            provider_config = config.get("targets")
        target_ids = _configured_ids(provider_config, field="config.providers")
        if set(target_ids) != set(self.target_providers):
            raise ExternalEngineOutputError("Promptfoo target-provider set mismatch")
        evaluate_options = config.get("evaluateOptions")
        if isinstance(evaluate_options, dict) and evaluate_options.get("repeat", 1) != 1:
            raise ExternalEngineOutputError(
                "Promptfoo native importer requires the unfiltered, non-repeated eval matrix"
            )

        config_tests = config.get("tests")
        if not isinstance(config_tests, list) or not config_tests:
            raise ExternalEngineOutputError(
                "Promptfoo generated config must contain nonempty inline tests"
            )
        normalized_tests: list[dict[str, Any]] = []
        default_test = _object(config.get("defaultTest"), field="config.defaultTest")
        raw_default_vars = default_test.get("vars", {})
        default_vars = _object(raw_default_vars, field="config.defaultTest.vars")
        configured_test_plugins: set[str] = set()
        configured_test_strategies: set[str] = set()
        for index, raw_test in enumerate(config_tests):
            test = _object(raw_test, field=f"config.tests[{index}]")
            if set(test) - _TEST_CASE_KEYS:
                raise ExternalEngineOutputError(
                    f"Promptfoo config.tests[{index}] has unknown AtomicTestCase fields"
                )
            variables = _object(test.get("vars"), field=f"config.tests[{index}].vars")
            injected = _nonblank(
                variables.get(inject_var),
                field=f"config.tests[{index}].vars[{inject_var!r}]",
            )
            del injected
            test_metadata = _object(
                test.get("metadata"), field=f"config.tests[{index}].metadata"
            )
            plugin_id = _nonblank(
                test_metadata.get("pluginId"),
                field=f"config.tests[{index}].metadata.pluginId",
            )
            strategy_id = test_metadata.get("strategyId") or "basic"
            strategy_id = _nonblank(
                strategy_id, field=f"config.tests[{index}].metadata.strategyId"
            )
            assertion_types = _assertion_types(test.get("assert"))
            if f"promptfoo:redteam:{plugin_id}" not in assertion_types:
                raise ExternalEngineOutputError(
                    f"Promptfoo config.tests[{index}] lacks its red-team assertion"
                )
            configured_test_plugins.add(plugin_id)
            configured_test_strategies.add(strategy_id)
            normalized_tests.append(test)
        if configured_test_plugins != set(self.plugins):
            raise ExternalEngineOutputError(
                "Promptfoo generated tests do not cover every configured plugin exactly"
            )
        expected_result_strategies = set(self.strategies) - {"basic"}
        if self.include_basic:
            expected_result_strategies.add("basic")
        if configured_test_strategies != expected_result_strategies:
            raise ExternalEngineOutputError(
                "Promptfoo generated tests do not cover every configured strategy exactly"
            )

        summary = _object(output.get("results"), field="OutputFile.results")
        _strict_keys(summary, required=_SUMMARY_KEYS, field="EvaluateSummaryV3")
        if summary.get("version") != 3:
            raise ExternalEngineOutputError("Promptfoo importer accepts EvaluateSummaryV3 only")
        _nonblank(summary.get("timestamp"), field="results.timestamp")
        raw_results = summary.get("results")
        prompts = summary.get("prompts")
        if not isinstance(raw_results, list) or not raw_results:
            raise ExternalEngineOutputError("Promptfoo results array must be nonempty")
        if len(raw_results) != expected_results:
            raise ExternalEngineOutputError(
                "Promptfoo result-count mismatch: "
                f"expected={expected_results}, observed={len(raw_results)}"
            )
        if not isinstance(prompts, list) or not prompts:
            raise ExternalEngineOutputError("Promptfoo completed prompts must be nonempty")

        completed_prompts: list[dict[str, Any]] = []
        for index, raw_prompt in enumerate(prompts):
            prompt = _object(raw_prompt, field=f"results.prompts[{index}]")
            _strict_keys(
                prompt,
                required=_PROMPT_REQUIRED | {"id", "provider"},
                optional=(_PROMPT_OPTIONAL - {"id"}) | {"metrics"},
                field=f"results.prompts[{index}]",
            )
            _nonblank(prompt.get("raw"), field=f"results.prompts[{index}].raw")
            _nonblank(prompt.get("label"), field=f"results.prompts[{index}].label")
            _nonblank(prompt.get("id"), field=f"results.prompts[{index}].id")
            _nonblank(prompt.get("provider"), field=f"results.prompts[{index}].provider")
            completed_prompts.append(prompt)

        expected_matrix = {
            (test_index, prompt_index)
            for test_index in range(len(normalized_tests))
            for prompt_index in range(len(completed_prompts))
        }
        if len(expected_matrix) != expected_results:
            raise ExternalEngineOutputError(
                "Promptfoo expected_results does not equal tests x completed prompts"
            )

        cases: list[NativeEngineCase] = []
        identities: set[tuple[int, int]] = set()
        successes = 0
        failures = 0
        errors = 0
        observed_plugins: set[str] = set()
        observed_strategies: set[str] = set()
        aggregate: dict[tuple[str, str], dict[str, int]] = defaultdict(
            lambda: {"passes": 0, "attack_successes": 0, "errors": 0}
        )
        prompt_counts: dict[int, dict[str, int]] = defaultdict(
            lambda: {"passes": 0, "failures": 0, "errors": 0}
        )
        referenced_trace_ids: set[str] = set()
        for index, raw_result in enumerate(raw_results):
            result = _object(raw_result, field=f"results.results[{index}]")
            _strict_keys(
                result,
                required=_RESULT_REQUIRED,
                optional=_RESULT_OPTIONAL,
                field=f"results.results[{index}]",
            )
            prompt_index = _integer(
                result.get("promptIdx"), field=f"results[{index}].promptIdx"
            )
            test_index = _integer(
                result.get("testIdx"), field=f"results[{index}].testIdx"
            )
            identity = (test_index, prompt_index)
            if identity not in expected_matrix or identity in identities:
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} has an invalid/duplicate matrix identity {identity}"
                )
            identities.add(identity)

            provider = _object(result.get("provider"), field=f"results[{index}].provider")
            _strict_keys(
                provider,
                required={"id"},
                optional={"label"},
                field=f"results[{index}].provider",
            )
            provider_id = _nonblank(
                provider.get("id"), field=f"results[{index}].provider.id"
            )
            if provider_id not in self.target_providers:
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} used an unexpected target provider"
                )
            completed_provider = completed_prompts[prompt_index]["provider"]
            expected_completed_provider = provider.get("label") or provider_id
            if completed_provider != expected_completed_provider:
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} provider does not match completed prompt"
                )

            prompt = _object(result.get("prompt"), field=f"results[{index}].prompt")
            _strict_keys(
                prompt,
                required=_PROMPT_REQUIRED,
                optional=_PROMPT_OPTIONAL,
                field=f"results[{index}].prompt",
            )
            _nonblank(prompt.get("raw"), field=f"results[{index}].prompt.raw")
            _nonblank(prompt.get("label"), field=f"results[{index}].prompt.label")
            completed_prompt = completed_prompts[prompt_index]
            if prompt.get("label") != completed_prompt.get("label"):
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} prompt identity differs from completed prompt"
                )
            prompt_id = _nonblank(
                result.get("promptId"), field=f"results[{index}].promptId"
            )
            if prompt_id != completed_prompt.get("id"):
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} promptId does not match completed prompt"
                )

            test_case = _object(
                result.get("testCase"), field=f"results[{index}].testCase"
            )
            if set(test_case) - _TEST_CASE_KEYS:
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} has unknown AtomicTestCase fields"
                )
            source_test = normalized_tests[test_index]
            result_vars = _object(result.get("vars"), field=f"results[{index}].vars")
            test_vars = _object(
                test_case.get("vars"), field=f"results[{index}].testCase.vars"
            )
            expected_vars = {**default_vars, **source_test.get("vars", {})}
            if result_vars != test_vars or result_vars != expected_vars:
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} vars diverge from its generated test"
                )
            adversarial_input = _nonblank(
                result_vars.get(inject_var),
                field=f"results[{index}].vars[{inject_var!r}]",
            )
            result_test_metadata = _object(
                test_case.get("metadata"),
                field=f"results[{index}].testCase.metadata",
            )
            source_metadata = source_test["metadata"]
            plugin_id = _nonblank(
                result_test_metadata.get("pluginId"),
                field=f"results[{index}].testCase.metadata.pluginId",
            )
            strategy_id = result_test_metadata.get("strategyId") or "basic"
            strategy_id = _nonblank(
                strategy_id,
                field=f"results[{index}].testCase.metadata.strategyId",
            )
            if plugin_id != source_metadata.get("pluginId") or strategy_id != (
                source_metadata.get("strategyId") or "basic"
            ):
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} plugin/strategy differs from generated test"
                )
            if f"promptfoo:redteam:{plugin_id}" not in _assertion_types(
                test_case.get("assert")
            ):
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} lacks the native red-team assertion"
                )
            observed_plugins.add(plugin_id)
            observed_strategies.add(strategy_id)

            success = result.get("success")
            if not isinstance(success, bool):
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index}.success must be boolean"
                )
            failure_reason = _integer(
                result.get("failureReason"), field=f"results[{index}].failureReason"
            )
            if failure_reason not in {0, 1, 2}:
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} has unknown failureReason"
                )
            score = _number(result.get("score"), field=f"results[{index}].score")
            _number(
                result.get("latencyMs"),
                field=f"results[{index}].latencyMs",
                minimum=0,
            )
            named_scores = _object(
                result.get("namedScores"), field=f"results[{index}].namedScores"
            )
            for name, value in named_scores.items():
                _nonblank(name, field=f"results[{index}].namedScores key")
                _number(value, field=f"results[{index}].namedScores[{name!r}]")

            result_error = result.get("error")
            response_value = result.get("response")
            response: dict[str, Any] | None = None
            if response_value is not None:
                response = _object(response_value, field=f"results[{index}].response")
                unknown_response = set(response) - _RESPONSE_KEYS
                if unknown_response:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} response has unknown fields: "
                        + ", ".join(sorted(unknown_response))
                    )

            native_scores: dict[str, int | float] = {}
            if failure_reason == 2:
                if success:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} is successful but marked ERROR"
                    )
                response_error = response.get("error") if response else None
                if not (
                    isinstance(result_error, str)
                    and result_error.strip()
                    or isinstance(response_error, str)
                    and response_error.strip()
                ):
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} is ERROR without error evidence"
                    )
                native_outcome = "execution_error_unscored"
                errors += 1
                aggregate[(plugin_id, strategy_id)]["errors"] += 1
                prompt_counts[prompt_index]["errors"] += 1
            else:
                expected_reason = 0 if success else 1
                if failure_reason != expected_reason:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} success/failureReason polarity mismatch"
                    )
                if response is None or not _response_has_evidence(response):
                    raise ExternalEngineOutputError(
                        f"Promptfoo scored result {index} has no substantive target response"
                    )
                grading = _object(
                    result.get("gradingResult"),
                    field=f"results[{index}].gradingResult",
                )
                unknown_grading = set(grading) - _GRADING_KEYS
                if unknown_grading:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} gradingResult has unknown fields"
                    )
                if grading.get("pass") is not success:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} grading pass differs from result success"
                    )
                grading_score = _number(
                    grading.get("score"), field=f"results[{index}].gradingResult.score"
                )
                if grading_score != score:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} grading score differs from result score"
                    )
                _nonblank(
                    grading.get("reason"),
                    field=f"results[{index}].gradingResult.reason",
                )
                if _contains_grader_error(grading):
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} contains a native grader error"
                    )
                grade_metadata = grading.get("metadata")
                if isinstance(grade_metadata, dict):
                    if grade_metadata.get("pluginId") not in (None, plugin_id):
                        raise ExternalEngineOutputError(
                            f"Promptfoo result {index} grader pluginId mismatch"
                        )
                    if grade_metadata.get("strategyId") not in (None, strategy_id):
                        raise ExternalEngineOutputError(
                            f"Promptfoo result {index} grader strategyId mismatch"
                        )
                native_scores["score"] = score
                if success:
                    native_outcome = "defense_passed"
                    successes += 1
                    aggregate[(plugin_id, strategy_id)]["passes"] += 1
                    prompt_counts[prompt_index]["passes"] += 1
                else:
                    native_outcome = "attack_succeeded"
                    failures += 1
                    aggregate[(plugin_id, strategy_id)]["attack_successes"] += 1
                    prompt_counts[prompt_index]["failures"] += 1

            result_metadata = result.get("metadata")
            if isinstance(result_metadata, dict):
                if result_metadata.get("pluginId") not in (None, plugin_id):
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} metadata pluginId mismatch"
                    )
                if result_metadata.get("strategyId") not in (None, strategy_id):
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} metadata strategyId mismatch"
                    )

            result_evaluation_id = result.get("evaluationId")
            result_trace_id = result.get("traceId")
            if (result_evaluation_id is None) != (result_trace_id is None):
                raise ExternalEngineOutputError(
                    f"Promptfoo result {index} has partial trace linkage"
                )
            if result_evaluation_id is not None:
                if result_evaluation_id != eval_id:
                    raise ExternalEngineOutputError(
                        f"Promptfoo result {index} trace linkage uses another eval ID"
                    )
                referenced_trace_ids.add(
                    _nonblank(result_trace_id, field=f"results[{index}].traceId")
                )

            record_digest = json_sha256(result)
            result_id = result.get("id")
            case_id = (
                f"promptfoo:{result_id}"
                if isinstance(result_id, str) and result_id.strip()
                else f"promptfoo:{eval_id}:test{test_index}:prompt{prompt_index}"
            )
            cases.append(
                NativeEngineCase(
                    id=case_id,
                    source_run_id=eval_id,
                    target_model=provider_id,
                    attack_method=f"promptfoo:{plugin_id}:{strategy_id}",
                    original_input=prompt,
                    adversarial_input=adversarial_input,
                    target_outputs=_response_texts(response or {}),
                    native_outcome=native_outcome,
                    native_scores=native_scores,
                    native_details={
                        "plugin_id": plugin_id,
                        "strategy_id": strategy_id,
                        "inject_variable": inject_var,
                        "target_provider": provider,
                        "target_response": response,
                        "grading_result": result.get("gradingResult"),
                        "failure_reason": failure_reason,
                        "vars": result_vars,
                        "test_case": test_case,
                        "full_result_record": result,
                    },
                    source_artifact_role="results_json",
                    source_record=f"json:results.results[{index}]",
                    source_record_sha256=record_digest,
                )
            )

        if identities != expected_matrix:
            raise ExternalEngineOutputError(
                "Promptfoo result matrix is partial despite a successful export"
            )
        if observed_plugins != set(self.plugins) or observed_strategies != (
            expected_result_strategies
        ):
            raise ExternalEngineOutputError(
                "Promptfoo result plugin/strategy coverage is incomplete"
            )

        stats = _object(summary.get("stats"), field="results.stats")
        stats_required = {"successes", "failures", "errors", "tokenUsage"}
        stats_optional = {"durationMs", "generationDurationMs", "evaluationDurationMs"}
        _strict_keys(
            stats,
            required=stats_required,
            optional=stats_optional,
            field="results.stats",
        )
        reported_counts = {
            name: _integer(stats.get(name), field=f"results.stats.{name}")
            for name in ("successes", "failures", "errors")
        }
        observed_counts = {
            "successes": successes,
            "failures": failures,
            "errors": errors,
        }
        if reported_counts != observed_counts:
            raise ExternalEngineOutputError(
                "Promptfoo summary stats do not reconstruct from result polarity"
            )
        token_usage = _object(stats.get("tokenUsage"), field="results.stats.tokenUsage")
        _validate_nonnegative_tree(token_usage, field="results.stats.tokenUsage")
        for field in stats_optional & set(stats):
            _number(stats[field], field=f"results.stats.{field}", minimum=0)

        for prompt_index, prompt in enumerate(completed_prompts):
            metrics = prompt.get("metrics")
            if metrics is None:
                continue
            metrics = _object(metrics, field=f"results.prompts[{prompt_index}].metrics")
            counts = prompt_counts[prompt_index]
            expected_metric_counts = {
                "testPassCount": counts["passes"],
                "testFailCount": counts["failures"],
                "testErrorCount": counts["errors"],
            }
            for field, expected in expected_metric_counts.items():
                if metrics.get(field) != expected:
                    raise ExternalEngineOutputError(
                        f"Promptfoo completed-prompt metric {field} does not reconstruct"
                    )

        traces = _validate_traces(
            output,
            config=config,
            redteam=redteam,
            eval_id=eval_id,
            referenced_trace_ids=referenced_trace_ids,
        )
        blob_assets = _validate_blob_assets(output)
        aggregate_rows: list[dict[str, Any]] = []
        for (plugin_id, strategy_id), counts in sorted(aggregate.items()):
            denominator = counts["passes"] + counts["attack_successes"]
            aggregate_rows.append(
                {
                    "plugin": plugin_id,
                    "strategy": strategy_id,
                    **counts,
                    "scored": denominator,
                    "native_attack_success_rate_percent": (
                        counts["attack_successes"] / denominator * 100.0
                        if denominator
                        else None
                    ),
                }
            )

        result_artifact = NativeArtifactFile(
            role="results_json",
            path=str(result_path),
            sha256=result_digest,
            bytes=len(result_bytes),
            records=len(raw_results),
        )
        config_artifact = NativeArtifactFile(
            role="generated_config_yaml",
            path=str(config_path),
            sha256=config_digest,
            bytes=len(config_bytes),
            records=1,
        )
        model_roles = {
            "attack_generation": generation_provider,
            "grader": grader_provider,
        }
        model_roles.update(
            {
                f"target_{index + 1}": provider
                for index, provider in enumerate(self.target_providers)
            }
        )
        scored = successes + failures
        return NativeEngineRun(
            engine="promptfoo",
            native_schema=PROMPTFOO_NATIVE_SCHEMA,
            native_run_id=eval_id,
            upstream_repository=PROMPTFOO_REPOSITORY,
            upstream_version=PROMPTFOO_VERSION,
            upstream_revision=PROMPTFOO_REVISION,
            source_artifacts=[config_artifact, result_artifact],
            target_models=list(self.target_providers),
            model_roles=model_roles,
            cases=cases,
            native_aggregates={
                "purpose": purpose,
                "inject_variable": inject_var,
                "inject_variable_source": inject_var_source,
                "implicit_basic_included": self.include_basic,
                "plugin_strategy_results": aggregate_rows,
                "native_attack_success_rate_percent": (
                    failures / scored * 100.0 if scored else None
                ),
                "export_metadata": metadata,
                "runtime_options": output.get("runtimeOptions"),
                "config": config,
                "trace_count": len(traces),
                "portable_blob_assets": [
                    {
                        "hash": digest,
                        "mimeType": asset["mimeType"],
                        "sizeBytes": asset["sizeBytes"],
                    }
                    for digest, asset in sorted(blob_assets.items())
                ],
            },
            import_accounting={
                "results": len(cases),
                "native_passes": successes,
                "native_attack_successes": failures,
                "execution_errors": errors,
                "native_score_coverage": scored / len(cases),
                "generated_tests": len(normalized_tests),
                "completed_prompts": len(completed_prompts),
                "portable_blob_assets": len(blob_assets),
            },
            measurement_semantics=(
                "Promptfoo red-team assertion failure means the attack succeeded; assertion "
                "pass means the defense passed. The official native ASR is failed assertions "
                "divided by scored tests and reported as a percentage. Execution and grader "
                "errors classified as ERROR are unscored and excluded from that denominator; "
                "a graderError embedded in a nominally scored row fails admission. These "
                "judgments are Promptfoo-native, not URA common ASR/FRR labels."
            ),
        )

    def generate(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> Iterable[Attempt]:
        del datapoint, budget
        raise ExternalEngineConformanceError(
            "Promptfoo is supported through build_native_commands()/import_run(); its "
            "target response and native grading cannot be reduced to Runner seed generation"
        )


__all__ = [
    "PROMPTFOO_NATIVE_SCHEMA",
    "PROMPTFOO_REPOSITORY",
    "PROMPTFOO_REVISION",
    "PROMPTFOO_VERSION",
    "PromptfooAttacker",
]
