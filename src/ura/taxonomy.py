"""Informational standards crosswalk (thesis III.3.1, F7/N4).

Maps the internal RiskCategory to external governance taxonomies so the
reporting layer can show nearby OWASP / NIST / MLCommons concepts without new
code. The mapping is interpretive and is not a certification, official
AILuminate score, conformity assessment, or legal-compliance determination.

The category-level defaults are deliberately CONSERVATIVE: a standard id is
attached to a whole RiskCategory only when it holds for every member of that
category. Narrower ids that depend on a specific construct are attached per
DataPoint by the converter via ``dp(extra_refs=...)`` rather than forced onto
the whole category. In particular:

* OWASP LLM05 is Improper Output Handling (validating/sanitizing model *output*
  before a downstream sink); it is not generic toxic content or cyber capability,
  so TOXICITY and CYBERSEC carry no LLM05 default.
* OWASP LLM01 Prompt Injection already covers both direct and indirect injection,
  so PROMPT_INJECTION_INDIRECT needs no additional agentic id by default. ASI05
  (Unexpected Code Execution) and ASI06 (Memory/Context Poisoning) are attached
  only to the exact subtypes that establish them.
* CATASTROPHIC is an umbrella (CBRN, weapons, self-harm, CSEM). No single hazard
  applies to every member, so its category default is empty and the specific
  hazard is attached per DataPoint.
* AGENTIC_MISUSE is likewise broader than either goal hijack or tool misuse.
  ASI01/ASI02 attach only when a source record establishes the corresponding
  construct; benign utility and post-hoc monitoring rows must not inherit both.
"""
from __future__ import annotations

from .data_models import RiskCategory

# RiskCategory -> {standard: [ids]}
TAXONOMY_MAP: dict[RiskCategory, dict[str, list[str]]] = {
    RiskCategory.JAILBREAK: {
        "OWASP_LLM": ["LLM01"], "NIST_GENAI": ["Information Security"], "MLCOMMONS": []},
    RiskCategory.PROMPT_INJECTION_INDIRECT: {
        "OWASP_LLM": ["LLM01"],
        "NIST_GENAI": ["Information Integrity"], "MLCOMMONS": []},
    RiskCategory.TOXICITY: {
        "OWASP_LLM": [], "NIST_GENAI": ["Dangerous, Violent, or Hateful Content"],
        "MLCOMMONS": ["Hate"]},
    RiskCategory.PRIVACY: {
        "OWASP_LLM": ["LLM02"], "NIST_GENAI": ["Data Privacy"], "MLCOMMONS": ["Privacy"]},
    RiskCategory.BIAS: {
        "OWASP_LLM": [], "NIST_GENAI": ["Harmful Bias or Homogenization"], "MLCOMMONS": []},
    RiskCategory.HALLUCINATION: {
        "OWASP_LLM": ["LLM09"], "NIST_GENAI": ["Confabulation"], "MLCOMMONS": []},
    RiskCategory.LEGALITY: {
        "OWASP_LLM": [], "MLCOMMONS": ["Non-Violent Crimes"]},
    RiskCategory.CYBERSEC: {
        "OWASP_LLM": [],
        "NIST_GENAI": ["Information Security"], "MLCOMMONS": []},
    RiskCategory.GEO: {
        "OWASP_LLM": ["LLM02"], "NIST_GENAI": ["Data Privacy"], "MLCOMMONS": ["Privacy"]},
    RiskCategory.AGENTIC_MISUSE: {
        "OWASP_ASI": [], "NIST_GENAI": ["Human-AI Configuration"],
        "MLCOMMONS": []},
    # Umbrella: the specific hazard (CBRN / weapons / self-harm / CSEM) is attached
    # per DataPoint by the converter via dp(extra_refs=...), not forced here.
    RiskCategory.CATASTROPHIC: {},
    # Utility/safety calibration construct, not itself an external harm class.
    RiskCategory.OVER_REFUSAL: {},
}

# Umbrella categories whose specific standard hazard is established per DataPoint
# rather than at the category level (see TAXONOMY_MAP note above).
UMBRELLA_CATEGORIES = frozenset({
    RiskCategory.CATASTROPHIC,
    # Explicitly exempt from category-level harm mappings: excessive refusal is
    # a benchmark utility construct, not an external safety-harm category.
    RiskCategory.OVER_REFUSAL,
})

# EU AI Act GPAI systemic-risk names attach at report level for frontier runs.
EU_AI_ACT_SYSTEMIC_RISKS = [
    "CBRN", "loss of control", "cyber offence", "harmful manipulation",
]


def refs_for(category: RiskCategory) -> list[str]:
    """Flatten the mapping into 'STANDARD:ID' strings for DataPoint.taxonomy_refs."""
    out: list[str] = []
    for standard, ids in TAXONOMY_MAP.get(category, {}).items():
        out.extend(f"{standard}:{i}" for i in ids)
    return out


__all__ = [
    "TAXONOMY_MAP", "UMBRELLA_CATEGORIES", "EU_AI_ACT_SYSTEMIC_RISKS", "refs_for",
]
