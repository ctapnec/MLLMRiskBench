"""URA-Bench unified schema — version 1.0.

Typed data contract shared by every layer of the harness (see thesis III.3).
Extends the pre-2025 prototype schema (v0.3: DataPoint / DialogTurn / EvalResult)
with multi-turn dialog, agentic tool traces, content-addressed media, an explicit
Attempt / Response / Judgment lineage, and standard-taxonomy mapping.

Pure Python + Pydantic v2 (no framework lock-in). Every artifact validates here.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"

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
    turns: int = 1
    is_agentic: bool = False
    schema_version: str = SCHEMA_VERSION
    meta: dict[str, Any] = Field(default_factory=dict)

    @field_validator("modalities")
    @classmethod
    def _non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("DataPoint.modalities must not be empty")
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
    turn_index: int = 0
    rendered_input: list[DialogTurn]
    seed: Optional[int] = None
    params: dict[str, Any] = Field(default_factory=dict)


class Response(BaseModel):
    """A target model's reply to an Attempt (with full trace)."""

    attempt_id: str
    target: str                                   # target model id
    output_turns: list[DialogTurn]
    tool_trace: list[DialogTurn] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    tokens: Optional[dict[str, int]] = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Judgment(BaseModel):
    """A single judge's verdict on a Response."""

    attempt_id: str
    judge: str                                    # judge name (rule/guardrail/llm/human)
    label: JudgeLabel
    score: float = Field(ge=0.0, le=1.0, description="graded severity in [0,1]")
    rationale: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)


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
    n: int = 0
    group_by: dict[str, str] = Field(default_factory=dict)  # {'model':..., 'risk':...}
    provenance: dict[str, Any] = Field(default_factory=dict)


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


__all__ = [
    "SCHEMA_VERSION",
    "Modality", "Role", "ExpectedBehavior", "JudgeLabel", "RiskCategory",
    "MediaRef", "ToolCall", "DialogTurn",
    "DataPoint", "Attempt", "Response", "Judgment",
    "EvalResult", "RunManifest",
]
