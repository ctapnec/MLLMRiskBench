"""Adapter for Confident‑AI DeepTeam red‑teaming framework."""
from __future__ import annotations
from typing import Any

try:
    # pip install deepteam
    from deepteam import attack as dt_attack
except ImportError:  # graceful degradation for CI without GPU ↴
    dt_attack = None  # type: ignore

from ..data_models import DataPoint, EvalResult
from .base import BaseAdapter

class DeepTeamAdapter(BaseAdapter):
    """Runs selected DeepTeam attack modes and maps result → ASR."""

    ATTACK_MODES = [
        "jailbreak", "bias", "toxicity", "privacy", "hallucination"
    ]

    def run(self, sample: DataPoint) -> EvalResult:  # noqa: D401
        if dt_attack is None:
            # fallback logic when deepteam is not installed
            success = sample.attack_tag == "jailbreak"
            raw: dict[str, Any] = {"note": "deepteam package missing"}
            return EvalResult(id=sample.id, metric="ASR", value=success, raw=raw)

        # Build prompt from payload/dialog depending on sample structure
        prompt = sample.payload_text or (sample.dialog_history or [])[0].content
        # DeepTeam API call
        result = dt_attack(
            prompt,
            modes=[sample.attack_tag] if sample.attack_tag in self.ATTACK_MODES else None,
        )
        success = bool(result.success)
        return EvalResult(
            id=sample.id,
            metric="ASR",
            value=success,
            raw={"deepteam": result.model_dump()},
        )