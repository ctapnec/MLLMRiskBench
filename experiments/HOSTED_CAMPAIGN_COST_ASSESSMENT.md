# Prospective hosted campaign cost assessment

Status: planning only, 1 September 2026. This document authorizes no provider
call and reports no hosted-model result.

The executable gate sequence and exact local-input subset rule are in
[`HOSTED_CAMPAIGN_PLAN.md`](HOSTED_CAMPAIGN_PLAN.md).

The proposed hosted breadth cohort uses the same seed-0 source instances,
rendered inputs, attacks and source-policy strata as the compatible local
campaign. Its budget-fitted quantities are global retained-input caps, not
Runner per-arm limits. The per-arm projections below are retained only as the
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

Each revised Haiku judgment assumes 4,000 input and 500 output tokens. Paid targets and
Haiku judging make exactly one application attempt: target answer retries and
harness transport retries are 0, and provider SDK retries are disabled.
There is no retry reserve in either the cost estimate or the executable
campaign. A missing response receives no policy-judge call.

This is not a monetary hard ceiling. Images have provider-specific tokenization,
reasoning models may bill more output than the 512-token planning value, and
most configured routes permit up to 4,096 output tokens. Exact caps must be
derived from provider-token canaries and the no-call population projection
before authorization.

## Original requested per-condition estimate, superseded

| Target condition | Limit | Target calls | One-attempt target USD | Haiku-eligible calls | Haiku judge USD | Haiku Batch judge USD |
|---|---:|---:|---:|---:|---:|---:|
| Claude Fable 5 | 5 | 663 | 30.2328 | 593 | 1.9450 | 0.9725 |
| Claude Opus 5 | 10 | 1,354 | 30.8712 | 1,199 | 3.9327 | 1.9664 |
| Claude Sonnet 5 | 50 | 6,974 | 63.6029 | 5,979 | 19.6111 | 9.8056 |
| Claude Haiku 4.5 | 100 | 12,215 | 55.7004 | 10,095 | 33.1116 raw | 16.5558 raw |
| GPT-5.6 Sol | 5 | 663 | 12.0931 | 593 | 1.9450 | 0.9725 |
| GPT-5.6 Terra | 20 | 2,742 | 27.8148 | 2,382 | 7.8130 | 3.9065 |
| GPT-5.6 Luna | 100 | 12,215 | 12.3909 | 10,095 | 33.1116 | 16.5558 |
| GPT-5.5 | 100 | 12,215 | 309.7724 | 10,095 | 33.1116 | 16.5558 |
| Kimi K3 | 100 | 12,215 | 167.1012 | 10,095 | 33.1116 | 16.5558 |
| DeepSeek V4-Pro, text-compatible | 100 | 8,563 | 19.9840 off-peak | 8,463 | 27.7586 | 13.8793 |

Claude Haiku judging its own target outputs is a same-model dependency. It is
allowed in the prospective selected cohort by explicit operator decision, but
must be labelled non-independent and may not support an independent-judge
claim. The raw arithmetic is retained to make both totals reproducible.

Excluding invalid Haiku self-judgment:

- one-attempt target total: USD 729.5638;
- standard Haiku judge total: USD 162.3403;
- Batch Haiku judge total: USD 81.1702;
- one-attempt targets plus standard valid judging: USD 891.9041; and
- one-attempt targets plus Batch valid judging: USD 810.7340.

Including the explicitly allowed but non-independent Haiku self-judgment, the
original requested scenario has USD 195.4519 standard or USD 97.7261 Batch
judge cost, and USD 925.0157 or USD 827.2899 respectively including one-attempt
targets.

## Configured budget fit

The rig budget registry records Anthropic USD 100, OpenAI USD 40, Moonshot USD
15 and DeepSeek USD 10 for the requested providers. Those entries support
reporting only; Runner admission is enforced by the exact sampling, target,
judge, HTTP and deadline caps.

Under the central one-attempt scenario, target costs alone are USD 180.4073 for
the four Anthropic targets, USD 362.0712 for the four OpenAI targets, USD
167.1012 for Kimi K3 and USD 19.9840 off-peak for DeepSeek V4-Pro. The requested
matrix therefore does not fit the configured prepaid balances. Even a Batch
judge does not close that gap. A measured hosted plan must either add funds or
prospectively reduce limits/arms before its projections and acquisition/request
envelopes are sealed. A cap is never raised or a subset changed after outcomes
are observed.

### Budget-fitted execution plan

The funded plan uses the operator-requested quantities as global retained-input
caps. It draws an exact balanced subset from the local Phase 7 inputs, and each
selected entry permits one paid target call. This avoids the unintended
per-arm multiplication in the superseded 8,734-call forecast. Adaptive local
framework prompts are retained test inputs; the paid campaign does not create
additional adaptive turns.

The central estimate uses 4,000 billed input and 500 billed output tokens per
target call. The maximum column instead uses the route's configured
`max_tokens`; it is a budget reservation, not predicted output length. Both
columns assume at most 4,000 input tokens per selected entry. Exact provider
tokenization must enforce that input bound or reduce and reseal the selection.

| Provider | Target | Global calls | USD/M input | USD/M output | Max output tokens | Expected USD | Max-token USD |
|---|---|---:|---:|---:|---:|---:|---:|
| Anthropic | Claude Fable 5 | 5 | 10.00 | 50.00 | 25,000 | 0.3250 | 6.4500 |
| Anthropic | Claude Opus 5 | 10 | 5.00 | 25.00 | 4,096 | 0.3250 | 1.2240 |
| Anthropic | Claude Sonnet 5 | 50 | 2.00 | 10.00 | 4,096 | 0.6500 | 2.4480 |
| Anthropic | Claude Haiku 4.5 | 100 | 1.00 | 5.00 | 2,048 | 0.6500 | 1.4240 |
| OpenAI | GPT-5.6 Sol | 5 | 4.00 | 20.00 | 25,000 | 0.1300 | 2.5800 |
| OpenAI | GPT-5.6 Terra | 20 | 2.00 | 12.00 | 4,096 | 0.2800 | 1.1430 |
| OpenAI | GPT-5.6 Luna | 100 | 0.20 | 1.20 | 4,096 | 0.1400 | 0.5715 |
| OpenAI | GPT-5.5 | 100 | 5.00 | 30.00 | 4,096 | 3.5000 | 14.2880 |
| Moonshot | Kimi K3 | 100 | 3.00 | 15.00 | 4,096 | 1.9500 | 7.3440 |
| DeepSeek | DeepSeek V4-Pro off-peak | 100 | 0.66 | 1.98 | 4,096 | 0.3630 | 1.0750 |
| **Total targets** | | **590** | | | | **8.3130** | **38.5476** |

Expected target cost is USD 8.3130 under the stated average-token model.
The 590-call target projection contains 2.36 million input and 295,000 expected
output tokens. Its configured maxima retain the same 2.36 million input bound
and permit at most 2,420,880 output tokens.
The matched Haiku plan adds at most 2,000 pairs or 4,000 judge calls. At 4,000
input and 500 output tokens it costs USD 26.00. A dedicated judge config fixes
`max_tokens=512`; if every judge input is at most 4,000 tokens, the maximum is
USD 26.24. Thus the expected combined campaign is USD 34.3130 and the
max-token reservation is USD 64.7876.
Across targets and judging, that is 18.36 million input plus 2.295 million
expected output tokens, or at most 4,468,880 output tokens under the configured
route maxima.

Provider reconciliation remains inside the 50 percent rule: Anthropic target
maximum USD 11.546 plus judge maximum USD 26.24 is USD 37.786 of USD 50; OpenAI
is USD 18.5826 of USD 20; Moonshot is USD 7.3440 of USD 7.50; and DeepSeek is
USD 1.0750 of USD 5. These are monetary ceilings, not permission to spend.
Exact no-call selection, provider token counting and one-call canaries must
fit before authorization. If they do not, only the affected prospective count
is reduced and resealed before any output is observed.

The 590 target-call cap includes every paid readiness and diagnostic canary.
Those calls consume their target's global cap rather than adding an unbudgeted
request. The create-only `hosted_campaign_budget` projection reads and binds the
exact API config, effective-dated pricing and budget registries, reproduces the
expected and maximum-token columns, and reports a blocked status if any
provider exceeds half its configured balance. It constructs no target or judge.

Paid targets and Haiku judging use exactly one application attempt; target
answer retries and harness transport retries are 0, and provider SDK retries
are disabled.

Anthropic Batch gives a 50 percent input/output discount and is appropriate for
post-hoc judging of immutable retained responses. Adaptive target trajectories
such as Crescendo cannot be flattened into independent target batches. Kimi's
published Batch support must not be assumed for K3 unless its exact model is
listed by the provider at launch time.

## Matched Haiku and local re-adjudication

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
acknowledgement. The dedicated `retained_response_judge_pair` selector and
`retained_response_judge_pair_execute` executor implement that zero-target path;
they remain pending deployment and must not be replaced by a naive Runner rerun
that could regenerate targets.

The budget-fitted cohort selects at most 2,000 eligible local/hosted pairs, so
the local and hosted judged populations contain the same input entries. Exact
identity binds the rendered prompt, media-reference digest, datapoint, source
cluster, seed, arm/framework, modality, risk, expected behavior and source
policy. Seed-0 balanced round-robin sampling spans both target models and those
input strata, and no retained output is reused. Missing responses remain in
coverage statistics but require no judge call and cannot form a judged pair.
Source-authoritative R-Judge and GPTGeoChat decisions are excluded. Haiku's own
target outputs are included by explicit operator decision and labelled
same-model, non-independent evidence.
Under the central 4,000-input/500-output assumption, 4,000 judgments use 16.0
million input and 2.0 million output tokens and cost USD 26.00 standard or USD
13.00 with Batch pricing, within the USD 27 judging allocation. With the
dedicated 512-token output cap, the corresponding maximum is USD 26.24. Exact
retained-output token counts may reduce the selected population before its
immutable selector is sealed; they may not change it after judgments are
observed.

The later comparison is a matched selected-cohort analysis, not a full-corpus
estimate. It publishes separate hosted/local member tables from the identical
pair inventory plus unpaired coverage counts.
The same hosted member of every pair is also passed through the sealed local
`rules,guardrail` cascade. This adds at most 2,000 rule evaluations and 2,000
Llama Guard calls, but zero target, provider or HTTP calls and USD 0 in provider
spend. It is a GPU-time allocation, not a token-billed budget item. Local versus
Haiku agreement is reported only on comparable decided labels, with the local
decision denominator and abstentions displayed because Llama Guard cannot
express benign over-refusal when the rules stage is undecided.
Its diagrams cover judgment outcomes with uncertainty, response/missingness,
model stability, modality/source/attack composition, local-versus-Haiku
agreement and billed token/cost usage. Same-model Haiku judging is visually and
textually distinguished; no
unmatched or different-revision rate is silently pooled.

## Pricing sources

- Anthropic: <https://platform.claude.com/docs/en/about-claude/pricing>
- OpenAI Sol: <https://developers.openai.com/api/docs/models/gpt-5.6-sol>
- OpenAI Terra: <https://developers.openai.com/api/docs/models/gpt-5.6-terra>
- OpenAI Luna/model family: <https://developers.openai.com/api/docs/models>
- OpenAI GPT-5.5: <https://developers.openai.com/api/docs/models/gpt-5.5>
- Kimi: <https://platform.kimi.ai/docs/pricing/chat-k3>
- DeepSeek: <https://api-docs.deepseek.com/quick_start/pricing/>

All rates are effective-dated planning inputs and must be fetched and reviewed
again immediately before a paid campaign.
