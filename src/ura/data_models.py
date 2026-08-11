"""URA-Bench unified schema - version 1.0.

Typed data contract shared by every layer of the harness (see thesis III.3).
Extends the pre-2025 prototype schema (v0.3: DataPoint / DialogTurn / EvalResult)
with multi-turn dialog, agentic tool traces, content-addressed media, an explicit
Attempt / Response / Judgment lineage, and standard-taxonomy mapping.

Pure Python + Pydantic v2 (no framework lock-in). Every artifact validates here.
"""
from __future__ import annotations

import math
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

SCHEMA_VERSION = "1.1"

_HEX = frozenset("0123456789abcdef")


def _nonblank(value: str, label: str) -> str:
    """Fail-closed identifier check: a required string must not be blank."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-blank string")
    return value

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

Modality = Literal["text", "image", "audio", "video", "tool", "multi"]
Role = Literal["system", "user", "assistant", "tool", "env"]
ExpectedBehavior = Literal["refuse", "safe_answer", "comply_safely"]
JudgeLabel = Literal["safe", "violation", "refusal", "over_refusal"]


class RiskCategory(str, Enum):
    """Internal risk taxonomy (superset of the prototype's 8 tags).

    Cross-references to external standards live in ``ura.taxonomy`` so that
    adding a standard is a data change, not a code change (thesis F7/N4).
    """

    JAILBREAK = "jailbreak"
    PROMPT_INJECTION_INDIRECT = "prompt_injection_indirect"
    TOXICITY = "toxicity"
    PRIVACY = "privacy"
    BIAS = "bias"
    HALLUCINATION = "hallucination"
    LEGALITY = "legality"
    CYBERSEC = "cybersec"
    GEO = "geo"
    AGENTIC_MISUSE = "agentic_misuse"
    CATASTROPHIC = "catastrophic"  # CBRN / weapons / self-harm / CSEM


# --------------------------------------------------------------------------- #
# Media & dialog
# --------------------------------------------------------------------------- #

class MediaRef(BaseModel):
    """Content-addressed reference to a media asset (reproducible, de-duplicated)."""

    modality: Modality
    uri: Optional[str] = None          # remote URL
    path: Optional[str] = None         # local path
    sha256: Optional[str] = Field(default=None, description="content hash for reproducibility")
    mime: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("modality")
    @classmethod
    def _media_is_not_text(cls, v: str) -> str:
        if v == "text":
            raise ValueError("MediaRef.modality must be a non-text modality")
        return v

    @field_validator("sha256")
    @classmethod
    def _valid_sha256(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        normalized = v.lower()
        # Preserve schema-level compatibility with legacy abbreviated fixture
        # digests; Runner preflight requires the full 64 characters before an
        # artifact can enter an executable run.
        if not normalized or any(c not in "0123456789abcdef" for c in normalized):
            raise ValueError("MediaRef.sha256 must be hexadecimal")
        return normalized

    @model_validator(mode="after")
    def _exactly_one_source(self) -> "MediaRef":
        if bool(self.path) == bool(self.uri):
            raise ValueError("MediaRef must contain exactly one of path or uri")
        return self


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class DialogTurn(BaseModel):
    """One turn of a (possibly agentic) conversation."""

    role: Role
    content: Optional[str] = None
    media: list[MediaRef] = Field(default_factory=list)
    tool_call: Optional[ToolCall] = None
    tool_result: Optional[str] = None
    # Verbatim provider-native reasoning blocks (e.g. Anthropic ``thinking`` /
    # ``redacted_thinking``, with their signatures) captured on an assistant
    # turn so a multi-turn continuation can return them to the provider
    # unchanged, as the extended-thinking contract requires. Optional and
    # additive: empty for text-only providers and all pre-existing artifacts.
    provider_thinking: list[dict[str, Any]] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# The evaluation unit
# --------------------------------------------------------------------------- #

class DataPoint(BaseModel):
    """The atomic unit of evaluation (one probe/scenario in unified form)."""

    id: str
    source: str                                   # originating framework
    modalities: list[Modality]
    dialog_history: list[DialogTurn] = Field(default_factory=list)
    payload_text: Optional[str] = None
    payload_code: Optional[str] = None
    media: list[MediaRef] = Field(default_factory=list)
    risk_category: RiskCategory
    risk_subtype: Optional[str] = None
    expected_behavior: ExpectedBehavior
    taxonomy_refs: list[str] = Field(
        default_factory=list,
        description="external standard IDs, e.g. ['OWASP:LLM01', 'NIST:InformationSecurity']",
    )
    attack_family: Optional[str] = None           # e.g. 'crescendo', 'typographic'
    turns: int = Field(default=1, ge=1)
    is_agentic: bool = False
    schema_version: str = SCHEMA_VERSION
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", "source")
    @classmethod
    def _dp_ids_nonblank(cls, v: str, info) -> str:
        return _nonblank(v, f"DataPoint.{info.field_name}")

    @field_validator("modalities")
    @classmethod
    def _non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("DataPoint.modalities must not be empty")
        if len(set(v)) != len(v):
            raise ValueError("DataPoint.modalities must not contain duplicates")
        return v


# --------------------------------------------------------------------------- #
# Execution lineage: Attempt -> Response -> Judgment
# --------------------------------------------------------------------------- #

class Attempt(BaseModel):
    """A concrete execution derived from a DataPoint by an attacker adapter."""

    id: str
    datapoint_id: str
    attacker: str                                 # adapter name
    strategy: Optional[str] = None                # e.g. 'TAP', 'replay'
    target: Optional[str] = None                  # execution target, stamped by Runner
    turn_index: int = Field(default=0, ge=0)
    rendered_input: list[DialogTurn]
    seed: Optional[int] = None
    params: dict[str, Any] = Field(default_factory=dict)
    run_id: Optional[str] = None

    @field_validator("id", "datapoint_id", "attacker")
    @classmethod
    def _attempt_ids_nonblank(cls, v: str, info) -> str:
        return _nonblank(v, f"Attempt.{info.field_name}")


class Response(BaseModel):
    """A target model's reply to an Attempt (with full trace)."""

    attempt_id: str
    target: str                                   # target model id
    output_turns: list[DialogTurn]                # may be empty for a typed provider refusal
    tool_trace: list[DialogTurn] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    tokens: Optional[dict[str, int]] = None
    raw: dict[str, Any] = Field(default_factory=dict)
    run_id: Optional[str] = None

    # Note: output_turns is intentionally allowed to be empty. A typed provider
    # refusal / empty / truncation is a valid terminal state that carries no
    # assistant turn; the Runner validates that state centrally via
    # raw.provider_refusal, so it must not be rejected at the schema boundary.

    @field_validator("attempt_id", "target")
    @classmethod
    def _response_ids_nonblank(cls, v: str, info) -> str:
        return _nonblank(v, f"Response.{info.field_name}")


class Judgment(BaseModel):
    """A single judge's verdict on a Response."""

    attempt_id: str
    judge: str                                    # judge name (rule/guardrail/llm/human)
    label: JudgeLabel
    score: float = Field(ge=0.0, le=1.0, description="graded severity in [0,1]")
    rationale: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)
    run_id: Optional[str] = None

    @field_validator("attempt_id", "judge")
    @classmethod
    def _judgment_ids_nonblank(cls, v: str, info) -> str:
        return _nonblank(v, f"Judgment.{info.field_name}")


# --------------------------------------------------------------------------- #
# Aggregated results & provenance
# --------------------------------------------------------------------------- #

class EvalResult(BaseModel):
    """An aggregated metric with uncertainty and grouping."""

    id: str
    metric: str                                   # e.g. 'ASR', 'strongreject', 'FRR'
    value: float
    ci_low: Optional[float] = None
    ci_high: Optional[float] = None
    n: int = Field(default=0, ge=0)
    group_by: dict[str, str] = Field(default_factory=dict)  # {'model':..., 'risk':...}
    provenance: dict[str, Any] = Field(default_factory=dict)
    run_id: Optional[str] = None

    @field_validator("id", "metric")
    @classmethod
    def _result_ids_nonblank(cls, v: str, info) -> str:
        return _nonblank(v, f"EvalResult.{info.field_name}")

    @field_validator("value", "ci_low", "ci_high")
    @classmethod
    def _finite(cls, v: Optional[float], info) -> Optional[float]:
        if v is not None and not math.isfinite(v):
            raise ValueError(f"EvalResult.{info.field_name} must be a finite number")
        return v

    @model_validator(mode="after")
    def _coherent_ci(self) -> "EvalResult":
        if self.ci_low is not None and self.ci_high is not None:
            if self.ci_low > self.ci_high:
                raise ValueError("EvalResult.ci_low must be <= ci_high")
            tol = 1e-9
            if not (self.ci_low - tol <= self.value <= self.ci_high + tol):
                raise ValueError("EvalResult.value must lie within [ci_low, ci_high]")
        return self


class RunManifest(BaseModel):
    """The single object that makes a run re-derivable (thesis N1/N6)."""

    run_id: str
    code_version: str
    config: dict[str, Any] = Field(default_factory=dict)
    seeds: list[int] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    adapters: list[str] = Field(default_factory=list)
    judges: list[str] = Field(default_factory=list)
    dataset_hashes: dict[str, str] = Field(default_factory=dict)
    started_at: str = ""                          # ISO-8601, injected by the runner
    env: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    @field_validator("run_id", "code_version")
    @classmethod
    def _manifest_ids_nonblank(cls, v: str, info) -> str:
        return _nonblank(v, f"RunManifest.{info.field_name}")

    @field_validator("seeds", "models", "adapters", "judges")
    @classmethod
    def _no_duplicate_lists(cls, v: list, info) -> list:
        if len(set(v)) != len(v):
            raise ValueError(f"RunManifest.{info.field_name} must not contain duplicates")
        return v

    @field_validator("dataset_hashes")
    @classmethod
    def _hex_dataset_hashes(cls, v: dict[str, str]) -> dict[str, str]:
        for key, digest in v.items():
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(c not in _HEX for c in digest.lower())
            ):
                raise ValueError(
                    f"RunManifest.dataset_hashes[{key!r}] must be a 64-char SHA-256 hex digest"
                )
        return v


__all__ = [
    "SCHEMA_VERSION",
    "Modality", "Role", "ExpectedBehavior", "JudgeLabel", "RiskCategory",
    "MediaRef", "ToolCall", "DialogTurn",
    "DataPoint", "Attempt", "Response", "Judgment",
    "EvalResult", "RunManifest",
]
