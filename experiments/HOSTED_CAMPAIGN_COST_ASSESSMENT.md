# Prospective hosted campaign cost assessment

Status: planning only, 1 September 2026. This document authorizes no provider
call and reports no hosted-model result.

The proposed hosted breadth cohort uses the same seed-0 whole-cluster
selection, source instances, rendered inputs, attacks and source-policy strata
as the compatible local campaign. Its positive per-arm limits are fixed in
`PROTOCOL.md`. A target receives only modalities declared by its exact route;
an incompatible media lane is typed `N/A`, not captioned or silently assigned
to a different model.

## Projected populations

These are no-call planning counts, not observations of model behavior.

| Per-arm limit | Static text | Static image | R-Judge | GPTGeoChat | Attack/framework calls | Total target calls |
|---:|---:|---:|---:|---:|---:|---:|
| 5 | 178 | 86 | 5 | 65 | 329 | 663 |
| 10 | 380 | 170 | 10 | 145 | 649 | 1,354 |
| 20 | 766 | 327 | 20 | 340 | 1,289 | 2,742 |
| 50 | 1,945 | 825 | 50 | 945 | 3,209 | 6,974 |
| 100 | 3,854 | 1,632 | 100 | 2,020 | 4,609 | 12,215 |

The attack/framework column includes four-turn Crescendo, the admitted bridge
and HarmBench replay routes, and the prepared T3MP3ST, NanoGCG and IDEATOR
follow-on calls. DeepSeek V4-Pro is configured text-only, so its compatible
limit-100 population is 8,563 calls: 3,854 static-text, 100 R-Judge and 4,609
attack/framework calls. The rig registry declares Kimi K3 text and image, but a
bounded live image canary is still required before measured media calls.

R-Judge and GPTGeoChat use their source-authoritative parsers. They are excluded
from the common Haiku-judge population. The resulting common-judge counts are
593, 1,199, 2,382, 5,979 and 10,095 at limits 5, 10, 20, 50 and 100. The
DeepSeek text-only limit-100 condition has 8,463 common-judge-eligible calls.

## Cost model

The central planning scenario assumes, per target call:

- 2,000 billed input tokens;
- 512 billed output tokens;
- no cache hit; and
- one successful retained output per intended call.

Each Haiku judgment assumes 2,000 input and 256 output tokens. The configured
answer policy permits one retry after an unusable output. The retry-reserved
target ceiling is therefore twice the first-pass target estimate if every
initial answer consumes the same tokens and fails. Judging does not double:
only one retained usable output per intended row is judged, and an exhausted
missing response receives no policy-judge call.

This is not a monetary hard ceiling. Images have provider-specific tokenization,
reasoning models may bill more output than the 512-token planning value, and
most configured routes permit up to 4,096 output tokens. Exact caps must be
derived from provider-token canaries and the no-call population projection
before authorization.

## Per-condition estimate

| Target condition | Limit | Target calls | First-pass target USD | Retry-reserved target USD | Haiku-eligible calls | Haiku judge USD | Haiku Batch judge USD |
|---|---:|---:|---:|---:|---:|---:|---:|
| Claude Fable 5 | 5 | 663 | 30.2328 | 60.4656 | 593 | 1.9450 | 0.9725 |
| Claude Opus 5 | 10 | 1,354 | 30.8712 | 61.7424 | 1,199 | 3.9327 | 1.9664 |
| Claude Sonnet 5 | 50 | 6,974 | 95.4043 | 190.8086 | 5,979 | 19.6111 | 9.8056 |
| Claude Haiku 4.5 | 100 | 12,215 | 55.7004 | 111.4008 | 10,095 | 33.1116 raw | 16.5558 raw |
| GPT-5.6 Sol | 5 | 663 | 12.0931 | 24.1862 | 593 | 1.9450 | 0.9725 |
| GPT-5.6 Terra | 20 | 2,742 | 27.8148 | 55.6297 | 2,382 | 7.8130 | 3.9065 |
| GPT-5.6 Luna | 100 | 12,215 | 12.3909 | 24.7818 | 10,095 | 33.1116 | 16.5558 |
| GPT-5.5 | 100 | 12,215 | 309.7724 | 619.5448 | 10,095 | 33.1116 | 16.5558 |
| Kimi K3 | 100 | 12,215 | 167.1012 | 334.2024 | 10,095 | 33.1116 | 16.5558 |
| DeepSeek V4-Pro, text-compatible | 100 | 8,563 | 19.9840 off-peak | 39.9680 off-peak | 8,463 | 27.7586 | 13.8793 |

Claude Haiku judging its own target outputs is a same-model dependency and is
not an admissible judge-comparison condition. The raw arithmetic is retained
only to make the requested total reproducible. That target row requires an
independent judge or exclusion from the Haiku-judged comparison.

Excluding invalid Haiku self-judgment:

- first-pass target total: USD 761.3652;
- retry-reserved target total: USD 1,522.7304;
- standard Haiku judge total: USD 162.3403;
- Batch Haiku judge total: USD 81.1702;
- first-pass targets plus standard valid judging: USD 923.7055; and
- first-pass targets plus Batch valid judging: USD 842.5353.

## Configured budget fit

The rig budget registry records Anthropic USD 100, OpenAI USD 40, Moonshot USD
15 and DeepSeek USD 10 for the requested providers. Those entries support
reporting only; Runner admission is enforced by the exact sampling, target,
judge, HTTP and deadline caps.

Under the central first-pass scenario, target costs alone are USD 212.2087 for
the four Anthropic targets, USD 362.0712 for the four OpenAI targets, USD
167.1012 for Kimi K3 and USD 19.9840 off-peak for DeepSeek V4-Pro. The requested
matrix therefore does not fit the configured prepaid balances. Even a Batch
judge does not close that gap. A measured hosted plan must either add funds or
prospectively reduce limits/arms before its projections and acquisition/request
envelopes are sealed. A cap is never raised or a subset changed after outcomes
are observed.

Anthropic Batch gives a 50 percent input/output discount and is appropriate for
post-hoc judging of immutable retained responses. Adaptive target trajectories
such as Crescendo cannot be flattened into independent target batches. Kimi's
published Batch support must not be assumed for K3 unless its exact model is
listed by the provider at launch time.

## Haiku re-adjudication of local outputs

The planned local population has 42,882 intended target calls before optional
local defense work. Removing 8,680 source-authoritative R-Judge/GPTGeoChat rows
leaves at most 34,202 common-judge-eligible outputs; including the 59 retained
follow-on outputs gives an upper planning inventory of 34,261. At the stated
judge-token assumption this is USD 112.3761 standard or USD 56.1880 through
Anthropic Batch. The exact cost is determined only after Phase 7 reports usable
retained outputs and missing responses.

Re-adjudication must use a new immutable output root, bind the source response
and former completion by content identity, make zero target calls, preserve the
original judgments, and record the new judge/model identity and transfer
acknowledgement. The current Runner does not yet expose that general post-hoc
path; a naive rerun would risk regenerating targets and is not authorized.

## Pricing sources

- Anthropic: <https://platform.claude.com/docs/en/about-claude/pricing>
- OpenAI Sol: <https://developers.openai.com/api/docs/models/gpt-5.6-sol>
- OpenAI Terra: <https://developers.openai.com/api/docs/models/gpt-5.6-terra>
- OpenAI Luna/model family: <https://developers.openai.com/api/docs/models>
- OpenAI GPT-5.5: <https://developers.openai.com/api/docs/models/gpt-5.5>
- Kimi: <https://platform.kimi.ai/>
- DeepSeek: <https://api-docs.deepseek.com/quick_start/pricing/>

All rates are effective-dated planning inputs and must be fetched and reviewed
again immediately before a paid campaign.
