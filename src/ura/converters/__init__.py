"""Per-framework source converters (thesis IV.1.6).

Each benchmark framework has its own module (rjudge, mmsafety, jailbreakv,
gptgeochat, agentharm, strongreject, bipia, harmbench, vlsbench, mossbench, siuo),
and each converter loads that framework's REAL released layout into unified
DataPoints. ``get_converter(name)`` returns a fresh instance; ``synth_corpus``
builds an offline mixed-modality corpus. Adding a framework is a new module plus
one line in the registry below (open/closed; thesis N4).
"""
from __future__ import annotations

from ..adapters.base import BaseConverter
from .agentharm import AgentHarmConverter
from .bipia import BIPIAConverter
from .gptgeochat import GPTGeoChatConverter
from .harmbench import HarmBenchConverter
from .jailbreakv import JailBreakVConverter
from .mmsafety import MMSafetyConverter
from .mossbench import MOSSBenchConverter
from .rjudge import RJudgeConverter
from .siuo import SIUOConverter
from .strongreject import StrongRejectConverter
from .synth import synth_corpus
from .vlsbench import VLSBenchConverter

_CONVERTERS: dict[str, type[BaseConverter]] = {
    c.name: c for c in (
        RJudgeConverter, MMSafetyConverter, JailBreakVConverter, GPTGeoChatConverter,
        AgentHarmConverter, StrongRejectConverter, BIPIAConverter, HarmBenchConverter,
        VLSBenchConverter, MOSSBenchConverter, SIUOConverter,
    )
}


def get_converter(name: str) -> BaseConverter:
    """Return a fresh converter instance for a source name."""
    if name not in _CONVERTERS:
        raise KeyError(f"unknown converter '{name}'; known: {sorted(_CONVERTERS)}")
    return _CONVERTERS[name]()


__all__ = [
    "RJudgeConverter", "MMSafetyConverter", "JailBreakVConverter", "GPTGeoChatConverter",
    "AgentHarmConverter", "StrongRejectConverter", "BIPIAConverter", "HarmBenchConverter",
    "VLSBenchConverter", "MOSSBenchConverter", "SIUOConverter",
    "get_converter", "synth_corpus",
]
