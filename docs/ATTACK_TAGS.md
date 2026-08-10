# Risk categories and informational crosswalk

`RiskCategory` is URA-Bench's internal analysis taxonomy. `ura.taxonomy` maps
each category to nearby entries in external frameworks so results can be
navigated alongside those documents. The mapping is interpretive: it is not an
official OWASP, NIST, MLCommons, or EU assessment and does not establish legal
compliance or certification.

Protocol baselines:

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [NIST AI 600-1, Generative AI Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [MLCommons AILuminate safety information](https://mlcommons.org/ailuminate/safety-faq/)

## Internal category crosswalk

The category-level defaults below are deliberately conservative: a standard id is
listed for a whole category only when it holds for every member. Narrower ids that
depend on a specific construct are attached per DataPoint by the converter through
`dp(extra_refs=...)`, not forced onto the category.

| Internal category | OWASP vicinity | NIST AI 600-1 risk vicinity | MLCommons hazard vicinity |
| --- | --- | --- | --- |
| `jailbreak` | LLM01 Prompt Injection | Information Security | - |
| `prompt_injection_indirect` | LLM01 Prompt Injection (covers direct and indirect) | Information Integrity | - |
| `toxicity` | - | Dangerous, Violent, or Hateful Content | Hate |
| `privacy` | LLM02 Sensitive Information Disclosure | Data Privacy | Privacy |
| `bias` | - | Harmful Bias or Homogenization | - |
| `hallucination` | LLM09 Misinformation | Confabulation | - |
| `legality` | - | - | Non-Violent Crimes |
| `cybersec` | - | Information Security | - |
| `geo` | LLM02 | Data Privacy | Privacy |
| `agentic_misuse` | ASI01 Goal Hijack; ASI02 Tool Misuse | Human-AI Configuration | - |
| `catastrophic` | - | - (umbrella) | - (umbrella) |

Notes on the conservative defaults:

- OWASP **LLM05 Improper Output Handling** concerns validating/sanitizing model
  *output* before a downstream sink (XSS/SQLi/SSRF/code-execution consumers). It is
  not generic toxic content and not offensive-cyber capability, so `toxicity` and
  `cybersec` carry no LLM05 default.
- OWASP **LLM01 Prompt Injection** already covers both direct and indirect
  injection, so `prompt_injection_indirect` needs no additional agentic id by
  default. **ASI05 Unexpected Code Execution** and **ASI06 Memory/Context
  Poisoning** are attached only to the exact subtypes that establish them (a
  tool-enabled agent that executes attacker code; persistent corruption of agent
  memory/context), via `extra_refs`.
- `catastrophic` is an umbrella (CBRN, weapons, self-harm, CSEM). No single hazard
  applies to every member, so its category default is empty and the specific
  hazard (NIST CBRN, MLCommons Indiscriminate Weapons / Suicide and Self-Harm /
  Child Sexual Exploitation) is attached per DataPoint.

AILuminate's official test has its own controlled prompts, grading, scoring,
and validation process. URA-Bench does not call its outputs “AILuminate scores”;
the labels above are crosswalk annotations only.

## Attack mechanism

Risk category answers “what harm?” `attack_family` separately records “how was
the probe delivered?” Relevant families include:

- single-turn text jailbreak or adversarial suffix;
- stateful multi-turn escalation;
- indirect/environmental prompt injection;
- vision-channel typography or adversarial imagery;
- cross-modal/audio/video interaction;
- represented agentic goal or tool misuse.

These axes must not be collapsed. For example, a privacy probe and a cyber probe
may both use indirect injection, while a single catastrophic objective may be
tested by replay and by a response-conditioned conversation.
