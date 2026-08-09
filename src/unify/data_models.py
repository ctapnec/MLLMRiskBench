"""Pydantic data classes defining the unified schema (v0.3)."""
from __future__ import annotations
from typing import List, Optional, Literal
from pydantic import BaseModel, HttpUrl

Modalities = Literal["text", "image", "audio", "video", "multi"]
AttackTag   = Literal[
    "jailbreak", "toxicity", "privacy", "bias", "hallucination",
    "legality", "geo", "cybersec"
]

class DialogTurn(BaseModel):
    role: Literal["user", "assistant", "system", "env"]
    content: Optional[str] = None
    uri: Optional[HttpUrl] = None  # link to media

class DataPoint(BaseModel):
    id: str
    modalities: List[Modalities]
    dialog_history: Optional[List[DialogTurn]] = None
    payload_text: Optional[str] = None
    payload_code: Optional[str] = None
    payload_image_uri: Optional[HttpUrl] = None
    attack_tag: AttackTag
    risk_type: Optional[str] = None
    expected_behavior: str  # e.g. "refuse", "safe-answer"
    meta_source: str

class EvalResult(BaseModel):
    id: str
    metric: str  # e.g. "ASR", "risk_score"
    value: float | bool
    raw: dict