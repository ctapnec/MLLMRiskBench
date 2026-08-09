"""Standards taxonomy mapping — data, not code (thesis III.3.1, F7/N4).

Maps the internal RiskCategory to external governance taxonomies so the
reporting layer can emit OWASP / NIST / MLCommons roll-ups without new code.
All identifiers are verified in the thesis bibliography (T4 sweep).
"""
from __future__ import annotations

from .data_models import RiskCategory

# RiskCategory -> {standard: [ids]}
TAXONOMY_MAP: dict[RiskCategory, dict[str, list[str]]] = {
    RiskCategory.JAILBREAK: {
        "OWASP_LLM": ["LLM01"], "NIST_GENAI": ["Information Security"], "MLCOMMONS": []},
    RiskCategory.PROMPT_INJECTION_INDIRECT: {
        "OWASP_LLM": ["LLM01"], "OWASP_ASI": ["ASI06"],
        "NIST_GENAI": ["Information Integrity"], "MLCOMMONS": []},
    RiskCategory.TOXICITY: {
        "OWASP_LLM": ["LLM05"], "NIST_GENAI": ["Dangerous, Violent, or Hateful Content"],
        "MLCOMMONS": ["Hate"]},
    RiskCategory.PRIVACY: {
        "OWASP_LLM": ["LLM02"], "NIST_GENAI": ["Data Privacy"], "MLCOMMONS": ["Privacy"]},
    RiskCategory.BIAS: {
        "OWASP_LLM": [], "NIST_GENAI": ["Harmful Bias or Homogenization"], "MLCOMMONS": []},
    RiskCategory.HALLUCINATION: {
        "OWASP_LLM": ["LLM09"], "NIST_GENAI": ["Confabulation"], "MLCOMMONS": []},
    RiskCategory.LEGALITY: {
        "OWASP_LLM": [], "NIST_GENAI": ["Dangerous, Violent, or Hateful Content"],
        "MLCOMMONS": ["Non-Violent Crimes", "Violent Crimes"]},
    RiskCategory.CYBERSEC: {
        "OWASP_LLM": ["LLM05"], "OWASP_ASI": ["ASI05"],
        "NIST_GENAI": ["Information Security"], "MLCOMMONS": []},
    RiskCategory.GEO: {
        "OWASP_LLM": ["LLM02"], "NIST_GENAI": ["Data Privacy"], "MLCOMMONS": ["Privacy"]},
    RiskCategory.AGENTIC_MISUSE: {
        "OWASP_ASI": ["ASI01", "ASI02"], "NIST_GENAI": ["Human-AI Configuration"],
        "MLCOMMONS": []},
    RiskCategory.CATASTROPHIC: {
        "NIST_GENAI": ["CBRN Information or Capabilities"],
        "MLCOMMONS": ["Indiscriminate Weapons", "Suicide and Self-Harm",
                      "Child Sexual Exploitation"]},
}

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


__all__ = ["TAXONOMY_MAP", "EU_AI_ACT_SYSTEMIC_RISKS", "refs_for"]
