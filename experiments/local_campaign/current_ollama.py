"""Exact prospective Ollama cohort for the local thesis campaign.

The superseded RWKV identities live only in ``ollama_static_terminal`` so old
artifacts remain verifiable.  No prospective controller may select them.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

# These constants describe the already-retained Gate 5 and initial Phase 6
# condition.  They intentionally do not follow later product defaults.
CURRENT_OLLAMA_NUM_CTX = 8_192
CURRENT_OLLAMA_NUM_PREDICT = 512

# Never-started continuation units use the product's automatic GPU-fit context
# policy. A changed context/output profile receives fresh attestation, canary,
# projection, acquisition, and measured artifacts before it can contribute
# evidence.
PROSPECTIVE_OLLAMA_NUM_CTX = "fit"
PROSPECTIVE_OLLAMA_NUM_PREDICT = -1


@dataclass(frozen=True)
class CurrentOllamaModel:
    """One exact acquired Ollama identity and its admitted campaign roles."""

    label: str
    tag: str
    digest: str
    quantization: str
    modalities: tuple[str, ...]
    think: bool | str
    roles: tuple[str, ...]

    @property
    def spec(self) -> str:
        return f"ollama:{self.tag}"


CURRENT_OLLAMA_MODELS = (
    CurrentOllamaModel(
        label="gemma4-12b",
        tag="gemma4:12b-it-q4_K_M",
        digest="4eb23ef187e2c5462566d6a1d3bbbc2f1346d0b4327cbb66d58fffbcc9b2b05c",
        quantization="Q4_K_M",
        modalities=("text", "image"),
        think=False,
        roles=("target", "native_primary"),
    ),
    CurrentOllamaModel(
        label="ministral3-14b",
        tag="ministral-3:14b-instruct-2512-q4_K_M",
        digest="4760c35aeb9d9e9c6174c2492562c0b999e80a222804fd96b1915ab72bbcdcf7",
        quantization="Q4_K_M",
        modalities=("text", "image"),
        think=False,
        roles=("target", "native_secondary"),
    ),
    CurrentOllamaModel(
        label="deepseek-r1-distill-32b",
        tag="deepseek-r1:32b-qwen-distill-q4_K_M",
        digest="edba8017331d15236e57480eb45406c0d721db77a4cdcf234df500fc2ad3960c",
        quantization="Q4_K_M",
        modalities=("text",),
        think=True,
        roles=("target", "native_auditor"),
    ),
    CurrentOllamaModel(
        label="gpt-oss-20b",
        tag="gpt-oss:20b",
        digest="17052f91a42e97930aa6e28a6c6c06a983e6a58dbb00434885a0cf5313e376f7",
        quantization="MXFP4",
        modalities=("text",),
        think="low",
        roles=("target", "native_judge"),
    ),
)

CURRENT_OLLAMA_BY_LABEL: Mapping[str, CurrentOllamaModel] = MappingProxyType(
    {model.label: model for model in CURRENT_OLLAMA_MODELS}
)
CURRENT_OLLAMA_BY_TAG: Mapping[str, CurrentOllamaModel] = MappingProxyType(
    {model.tag: model for model in CURRENT_OLLAMA_MODELS}
)
CURRENT_OLLAMA_BY_SPEC: Mapping[str, CurrentOllamaModel] = MappingProxyType(
    {model.spec: model for model in CURRENT_OLLAMA_MODELS}
)
CURRENT_OLLAMA_TEXT_MODELS = CURRENT_OLLAMA_MODELS
CURRENT_OLLAMA_IMAGE_MODELS = tuple(
    model for model in CURRENT_OLLAMA_MODELS if "image" in model.modalities
)
CURRENT_OLLAMA_TEXT_ONLY_MODELS = tuple(
    model for model in CURRENT_OLLAMA_MODELS if model.modalities == ("text",)
)

CURRENT_OLLAMA_NATIVE_ROLES: Mapping[str, CurrentOllamaModel] = MappingProxyType(
    {
        role.removeprefix("native_"): model
        for model in CURRENT_OLLAMA_MODELS
        for role in model.roles
        if role.startswith("native_")
    }
)


def text_lane(model: CurrentOllamaModel) -> str:
    return f"ollama-{model.label}-text-primary-50"


def image_lane(model: CurrentOllamaModel) -> str:
    if "image" not in model.modalities:
        raise ValueError(f"{model.label} is not image-capable")
    return f"ollama-{model.label}-image-primary-50"


def rjudge_lane(model: CurrentOllamaModel) -> str:
    return f"rjudge-ollama-{model.label}"


def gptgeochat_lane(model: CurrentOllamaModel) -> str:
    return f"gptgeochat-ollama-{model.label}"


CURRENT_OLLAMA_RUNNABLE_LANES = tuple(
    [text_lane(model) for model in CURRENT_OLLAMA_TEXT_MODELS]
    + [image_lane(model) for model in CURRENT_OLLAMA_IMAGE_MODELS]
    + [rjudge_lane(model) for model in CURRENT_OLLAMA_TEXT_MODELS]
    + [gptgeochat_lane(model) for model in CURRENT_OLLAMA_IMAGE_MODELS]
)
CURRENT_OLLAMA_TYPED_TERMINAL_LANES = tuple(
    gptgeochat_lane(model) for model in CURRENT_OLLAMA_TEXT_ONLY_MODELS
)
