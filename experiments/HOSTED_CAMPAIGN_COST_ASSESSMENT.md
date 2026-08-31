# Prospective hosted campaign cost assessment

Status: planning only, 1 September 2026. This document authorizes no provider
call and reports no hosted-model result.

The executable gate sequence and exact local-input subset rule are in
[`HOSTED_CAMPAIGN_PLAN.md`](HOSTED_CAMPAIGN_PLAN.md).

The proposed hosted breadth cohort uses the same seed-0 whole-cluster
selection, source instances, rendered inputs, attacks and source-policy strata
as the compatible local campaign. Its budget-fitted positive per-arm limits are
fixed in `PROTOCOL.md`. The larger limits below are retained only as the
superseded requested-cost baseline. A target receives only modalities declared
by its exact route;
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

Each Haiku judgment assumes 2,000 input and 256 output tokens. The original
requested-cost table retains a doubled retry sensitivity column so the earlier
question remains reproducible. The budget-fitted execution plan does not use
that reserve: paid targets and Haiku judging make exactly one application
attempt, target answer retries and harness transport retries are 0, and
provider SDK retries are disabled. An
exhausted missing response receives no policy-judge call.

This is not a monetary hard ceiling. Images have provider-specific tokenization,
reasoning models may bill more output than the 512-token planning value, and
most configured routes permit up to 4,096 output tokens. Exact caps must be
derived from provider-token canaries and the no-call population projection
before authorization.

## Original requested per-condition estimate, superseded

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

Claude Haiku judging its own target outputs is a same-model dependency. It is
allowed in the prospective selected cohort by explicit operator decision, but
must be labelled non-independent and may not support an independent-judge
claim. The raw arithmetic is retained to make both totals reproducible.

Excluding invalid Haiku self-judgment:

- first-pass target total: USD 761.3652;
- retry-reserved target total: USD 1,522.7304;
- standard Haiku judge total: USD 162.3403;
- Batch Haiku judge total: USD 81.1702;
- first-pass targets plus standard valid judging: USD 923.7055; and
- first-pass targets plus Batch valid judging: USD 842.5353.

Including the explicitly allowed but non-independent Haiku self-judgment, the
original requested scenario has USD 195.4519 standard or USD 97.7261 Batch
judge cost, and USD 956.8171 or USD 859.0913 respectively including first-pass
targets.

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

### Budget-fitted execution plan

The retained execution plan therefore replaces the larger requested breadth
scenario with per-target nested-prefix limits. It keeps the same seed, arms and
compatible modalities while reducing only the prospective cluster prefix:

| Provider | Target | Limit | One-attempt planning allocation |
|---|---|---:|---:|
| Anthropic | Claude Fable 5 | 1 | within shared USD 32 target ceiling |
| Anthropic | Claude Opus 5 | 3 | within shared USD 32 target ceiling |
| Anthropic | Claude Sonnet 5 | 5 | within shared USD 32 target ceiling |
| Anthropic | Claude Haiku 4.5 | 10 | within shared USD 32 target ceiling |
| OpenAI | GPT-5.6 Sol | 2 | within shared USD 19 target ceiling |
| OpenAI | GPT-5.6 Terra | 5 | within shared USD 19 target ceiling |
| OpenAI | GPT-5.6 Luna | 20 | within shared USD 19 target ceiling |
| OpenAI | GPT-5.5 | 1 | within shared USD 19 target ceiling |
| Moonshot | Kimi K3 | 3 | USD 7 ceiling |
| DeepSeek | DeepSeek V4-Pro | 20 | USD 5 off-peak ceiling |

Each provider may use at most 50 percent of its configured budget: Anthropic
USD 50, OpenAI USD 20, Moonshot USD 7.50 and DeepSeek USD 5. The Anthropic share
reserves at most USD 32 for one-attempt targets and USD 14 for Haiku
judging, leaving at least USD 4 planning margin. OpenAI keeps USD 19 for
one-attempt execution and at least USD 1 margin; Moonshot keeps USD 7 plus
USD 0.50 margin; DeepSeek keeps USD 5 and may run only in the
reviewed off-peak window. These are monetary ceilings, not permission to spend.
Exact no-call population projections and provider-token canaries must fit
beneath them before acquisition. If they do not, the affected limit or judging
population is reduced and resealed before any output is observed.

Paid targets and Haiku judging use exactly one application attempt; target
answer retries and harness transport retries are 0, and provider SDK retries
are disabled. Counts for limits 1, 2 and 3 are deliberately not
interpolated into evidence.
The rig must derive their exact whole-cluster populations with the normal
no-call projector. The central token assumptions indicate that this schedule
fits the stated one-attempt allocations, but only those exact projections
and provider-token canaries can authorize execution.

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

The budget-fitted cohort selects at most 2,000 eligible local outputs and at
most 2,000 eligible hosted outputs. Seed-0 balanced round-robin
sampling spans target, modality, source arm, attacker, risk, expected behavior
and output-policy/revision strata. Missing responses remain in coverage
statistics but require no judge call. Source-authoritative R-Judge and
GPTGeoChat decisions are excluded. Haiku's own target outputs are included by
explicit operator decision and labelled same-model, non-independent evidence.
Under the central 2,000-input/256-output assumption, 4,000 judgments use 8.0
million input and 1.024 million output tokens and cost USD 13.12 standard or
USD 6.56 with Batch pricing, within the USD 14 judging allocation. Exact
retained-output token counts may reduce the selected population before its
immutable selector is sealed; they may not change it after judgments are
observed.

The later comparison is a selected-cohort analysis, not a full-corpus estimate.
It publishes separate API-selected and local-selected tables plus a matched-
input intersection wherever the same rendered input identity exists in both.
Its diagrams cover judgment outcomes with uncertainty, response/missingness,
model stability, modality/source/attack composition, and billed token/cost
usage. Same-model Haiku judging is visually and textually distinguished; no
unmatched or different-revision rate is silently pooled.

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
