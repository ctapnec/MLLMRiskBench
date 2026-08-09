# Risk taxonomy & standards mapping (v1.0)

The internal `RiskCategory` enum (`ura.data_models`) is a superset of the prototype's 8 tags, extended for the 2025–2026 landscape. It stores **no** external identifiers itself; the mapping to governance taxonomies lives in `ura.taxonomy.TAXONOMY_MAP` as **data**, so adding a standard is a one-line change and every result rolls up to OWASP / NIST / MLCommons automatically (`refs_for(category)` → `["OWASP_LLM:LLM02", …]`).

## Categories → external standards

| `RiskCategory` | OWASP LLM / Agentic | NIST GenAI (AI 600-1) | MLCommons AILuminate |
|---|---|---|---|
| `jailbreak` | LLM01 Prompt Injection | Information Security | — |
| `prompt_injection_indirect` | LLM01 · ASI06 Memory/Context Poisoning | Information Integrity | — |
| `toxicity` | LLM05 Improper Output | Dangerous/Violent/Hateful Content | Hate |
| `privacy` | LLM02 Sensitive Info Disclosure | Data Privacy | Privacy |
| `bias` | — | Harmful Bias/Homogenization | — |
| `hallucination` | LLM09 Misinformation | Confabulation | — |
| `legality` | — | Dangerous/Violent Content | Non-Violent/Violent Crimes |
| `cybersec` | LLM05 · ASI05 Unexpected Code Execution | Information Security | — |
| `geo` | LLM02 | Data Privacy | Privacy |
| `agentic_misuse` | ASI01 Goal Hijack · ASI02 Tool Misuse | Human-AI Configuration | — |
| `catastrophic` (CBRN/weapons/self-harm/CSEM) | — | CBRN Information | Indiscriminate Weapons · Suicide & Self-Harm · Child Sexual Exploitation |

For frontier-model runs, the **EU AI Act GPAI** systemic-risk names attach at report level: `ura.taxonomy.EU_AI_ACT_SYSTEMIC_RISKS = ["CBRN", "loss of control", "cyber offence", "harmful manipulation"]`.

## Attack-technique families (by mechanism)

Orthogonal to the risk *category* above (what harm), the attack *family* records *how* a violation was induced. The harness tags each `DataPoint.attack_family`; the taxonomy follows thesis II.3.1:

- **Text single-turn** — DAN/role-play, GCG optimization suffixes, encoding/obfuscation, persuasion/overload.
- **Multi-turn / adaptive** — crescendo escalation, PAIR/TAP, chain-of-utterances, many-shot.
- **Indirect / environmental** — indirect prompt injection, GUI environmental injection.
- **Vision-channel** — adversarial pixels, typographic (FigStep), query-relevant generated imagery (MM-SafetyBench/HADES), steganographic, visual chain-of-reasoning lures.
- **Cross-modal / temporal** — safe-inputs-unsafe-output (SIUO), multi-image/multi-clip, audio.
- **Agentic** — goal hijack, tool misuse.

Both axes are queryable, so a result can be sliced by *what* harm (category → standard) and by *how* it was reached (family).
