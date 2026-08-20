"""Per-framework source converters (thesis IV.1.6).

Each benchmark framework has its own module (rjudge, mmsafety, jailbreakv,
gptgeochat, agentharm, strongreject, bipia, harmbench, vlsbench, mossbench, siuo,
advbench, jailbreakbench, figstep, cyberseceval, injecagent, mllmguard, jalmbench,
videosafetybench, saladbench), and each converter loads that framework's REAL released layout into unified
DataPoints. ``get_converter(name)`` returns a fresh instance; ``synth_corpus``
builds an offline mixed-modality corpus. Adding a framework is a new module plus
one line in the registry below (open/closed; thesis N4).
"""
from __future__ import annotations

from ..adapters.base import BaseConverter
from .advbench import AdvBenchConverter
from .agentharm import AgentHarmConverter
from .airbench import AirBenchConverter
from .bipia import BIPIAConverter
from .cyberseceval import CyberSecEvalConverter
from .figstep import FigStepConverter
from .gptgeochat import GPTGeoChatConverter
from .harmbench import HarmBenchConverter
from .injecagent import InjecAgentConverter
from .jailbreakbench import JailbreakBenchConverter
from .jailbreakv import JailBreakVConverter
from .jalmbench import JALMBenchConverter
from .mllmguard import MLLMGuardConverter
from .mmsafety import MMSafetyConverter
from .mossbench import MOSSBenchConverter
from .release_specs import CORPUS_RELEASE_SPECS
from .rjudge import RJudgeConverter
from .saladbench import SaladBenchConverter
from .simplesafetytests import SimpleSafetyTestsConverter
from .siuo import SIUOConverter
from .strongreject import StrongRejectConverter
from .xstest import XSTestConverter
from .synth import synth_corpus
from .videosafetybench import VideoSafetyBenchConverter
from .vlsbench import VLSBenchConverter
from ._common import ConverterError, CorpusFormatError, CorpusNotFoundError, MediaAssetError

_CONVERTERS: dict[str, type[BaseConverter]] = {
    c.name: c for c in (
        RJudgeConverter, MMSafetyConverter, JailBreakVConverter, GPTGeoChatConverter,
        AgentHarmConverter, StrongRejectConverter, BIPIAConverter, HarmBenchConverter,
        VLSBenchConverter, MOSSBenchConverter, SIUOConverter,
        AdvBenchConverter, JailbreakBenchConverter, FigStepConverter,
        CyberSecEvalConverter, InjecAgentConverter, MLLMGuardConverter,
        JALMBenchConverter, VideoSafetyBenchConverter, SaladBenchConverter,
        AirBenchConverter, XSTestConverter, SimpleSafetyTestsConverter,
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
    "AdvBenchConverter", "JailbreakBenchConverter", "FigStepConverter",
    "CyberSecEvalConverter", "InjecAgentConverter", "MLLMGuardConverter",
    "JALMBenchConverter", "VideoSafetyBenchConverter", "SaladBenchConverter",
    "AirBenchConverter", "XSTestConverter", "SimpleSafetyTestsConverter",
    "get_converter", "synth_corpus",
    "ConverterError", "CorpusFormatError", "CorpusNotFoundError", "MediaAssetError",
    "CORPUS_RELEASE_SPECS",
]
