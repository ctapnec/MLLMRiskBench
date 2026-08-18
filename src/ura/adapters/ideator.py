"""IDEATOR engine adapter: VLM-driven multimodal (image+text) jailbreak generation.

IDEATOR (roywang021/IDEATOR, ICCV 2025, research licence [ideator-2025]) is an
automated black-box red-teaming method for Vision-Language Models. It uses a VLM
as the red-teamer to invent a malicious idea and the accompanying jailbreak text,
then drives a text-to-image diffusion model (Stable Diffusion 3.5 Large) to
synthesize the paired adversarial image, yielding malicious image+text pairs that
transfer across target VLMs without any gradient access to them. In URA-Bench it
represents the automated multimodal attack-generation family (thesis II.4.x,
III.2.2; OWASP LLM01 Prompt Injection / jailbreak; RiskCategory.JAILBREAK). It is
distinct from the multimodal safety corpora (converters): those replay fixed
image/audio/video probes, whereas IDEATOR generates fresh malicious media here.

Scope: the official repository exposes research scripts, not the
``ideator.IDEATOR`` Python package/class assumed by an older local prototype; its
README also says the full Gemini implementation is withheld. This adapter therefore
supports only explicit precomputed ``seed_pairs``. The unverified generation path
fails closed until a pinned upstream script/export contract is implemented.

Safety (thesis N5, III.2.4): this adapter operates in attack-GENERATION / seed mode
only. It materialises each red-teamer-produced image+text pair as an Attempt whose
rendered dialog carries the jailbreak text plus the generated image as an image
MediaRef, for the harness to judge later; it never drives a live attacker-vs-target
scoring loop against a deployed / third-party system (that live loop belongs to
Chapter V, against real models with keys present). When precomputed pairs are
supplied it runs fully offline (no model load, no synthesis). Authorized red-team
use only.

The heavy dependencies (the ideator package plus its diffusion / torch backend) are
imported lazily via ``_require`` inside the call path, so this module imports with
only stdlib + pydantic present and raises a clear RuntimeError when they are absent.
"""
from __future__ import annotations

from collections.abc import Iterable

from ..attacker_input_contract import (
    AttackerInputContract,
    generated_image_input_contract,
)
from ..data_models import Attempt, DataPoint, MediaRef
from .base import AttackBudget, BaseAttacker
from ._engine_common import (
    ExternalEngineConformanceError,
    ExternalEngineOutputError,
    _attempt,
)


class IDEATORAttacker(BaseAttacker):
    """Drive IDEATOR's VLM red-teamer + diffusion synthesizer in generation mode to
    produce malicious image+text pairs as Attempts (no live attacker-vs-target loop).

    Each Attempt's rendered dialog carries the jailbreak ``text`` and the generated
    image as an image :class:`~ura.data_models.MediaRef` (``modality="image"``,
    ``path=...``), so the target VLM is probed multimodally.

    ``vlm`` names the red-teamer VLM backend (default ``"minigpt4"``; ``"gemini"`` in
    the repo's demo). ``diffusion_model`` is the text-to-image synthesizer weights.
    ``device`` selects the GPU. ``out_dir`` is where synthesized images are written
    (a persistent temp dir when unset, so the MediaRef paths stay valid). Pass
    ``seed_pairs`` (a list of ``(text, image_path)``) to run fully offline in seed
    mode; otherwise the VLM + diffusion pipeline runs via a lazy import of the
    ideator package. No live exploit is ever executed against a deployed system
    (thesis N5).
    """

    name = "ideator"
    # Raw host paths are execution locators, not portable scientific identity.
    # Runner binds the ordered text/image pair content through input contracts.
    portable_config_exclude = ("seed_pairs", "out_dir")

    def plan_target_inputs(
        self, datapoint: DataPoint, budget: AttackBudget
    ) -> AttackerInputContract:
        return generated_image_input_contract(
            self.name,
            datapoint,
            budget,
            seed_pairs=tuple(self.seed_pairs or ()),
        )

    def __init__(
        self,
        vlm: str = "minigpt4",
        diffusion_model: str = "stabilityai/stable-diffusion-3.5-large",
        device: str = "cuda:0",
        out_dir: str | None = None,
        seed_pairs: list[tuple[str, str]] | None = None,
    ) -> None:
        # Red-teamer VLM backend and the diffusion synthesizer that paints the image.
        self.vlm = vlm
        self.diffusion_model = diffusion_model
        # GPU device for both models; the pipeline is generation-only (no live loop).
        self.device = device
        # Where synthesized images land; kept persistent so MediaRef paths resolve.
        self.out_dir = out_dir
        # Precomputed (text, image_path) pairs; when set, generate() is fully offline.
        self.seed_pairs = seed_pairs

    def generate(self, datapoint: DataPoint, budget: AttackBudget) -> Iterable[Attempt]:
        objective = datapoint.payload_text or datapoint.payload_code or ""
        pairs, mode = self._pairs(
            objective,
            min(budget.max_queries, budget.max_turns),
            budget,
        )
        # Preserve the adapter's established conformance/output exceptions from
        # ``_pairs`` while still binding every accepted image before yielding an
        # Attempt. Runner admission calls ``plan_target_inputs`` on the original
        # configuration, where ignored/malformed configured pairs fail closed.
        input_contract = generated_image_input_contract(
            self.name,
            datapoint,
            budget,
            seed_pairs=tuple(pairs),
        )
        generated_by_id = {
            item.media_id: item for item in input_contract.generated_media
        }
        for i, (text, image_path) in enumerate(pairs):
            media_id = input_contract.turns[i].media_ids[0]
            identity = generated_by_id[media_id]
            attempt = _attempt(
                datapoint,
                self.name,
                strategy=f"ideator:{self.vlm}+diffusion",
                turn_index=i,
                prompt=text,
                seed=budget.seed,
                params={
                    "vlm": self.vlm,
                    "diffusion_model": self.diffusion_model,
                    "image_identity": {
                        "media_id": media_id,
                        "modality": identity.modality,
                        "mime": identity.mime,
                        "sha256": identity.sha256,
                        "bytes": identity.bytes,
                    },
                    "modalities": ["image", "text"],
                    "mode": mode,
                },
            )
            # Attach the synthesized image so the rendered dialog is truly multimodal:
            # the last (user) turn now carries both the jailbreak text and the image.
            if image_path:
                attempt.rendered_input[-1].media.append(
                    MediaRef(
                        modality="image",
                        path=image_path,
                        sha256=identity.sha256,
                        mime="image/png",
                    )
                )
            yield attempt

    def _pairs(
        self, objective: str, n: int, budget: AttackBudget
    ) -> tuple[list[tuple[str, str]], str]:
        """Return ``(pairs, mode)`` where each pair is ``(jailbreak_text, image_path)``.

        Uses the precomputed ``seed_pairs`` fully offline (mode ``"seed"``), or runs
        explicit precomputed pairs (mode ``"seed"``). The repository does not
        expose the package API previously assumed by this bridge, so an absent
        ``seed_pairs`` value is a conformance error rather than an invented live
        generation path."""
        if self.seed_pairs is not None:
            pairs = [
                (text, image)
                for text, image in self.seed_pairs
                if isinstance(text, str)
                and text.strip()
                and isinstance(image, str)
                and image.strip()
            ][:n]
            if not pairs:
                raise ExternalEngineOutputError(
                    "IDEATOR seed-pair input contains no valid image+text pairs"
                )
            return pairs, "seed"

        raise ExternalEngineConformanceError(
            "IDEATOR live generation is disabled: the official repository does "
            "not expose the ideator.IDEATOR package API assumed by the former "
            "bridge. Supply verified precomputed seed_pairs instead."
        )
