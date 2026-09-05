# Prospective hosted campaign cost assessment

Status: planning only, revised 5 September 2026. This document authorizes no
provider call and reports no hosted-model result. The earlier per-arm scenario
is historical; the later global-cap allocation is the current proposal.

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

## Historical per-arm cost model

The central planning scenario assumes, per target call:

- 2,000 billed input tokens;
- 512 billed output tokens;
- no cache hit; and
- one successful retained output per intended call.

Each revised Haiku judgment assumes 4,000 input and 500 output tokens. Paid
targets and Haiku judging use zero answer-quality retries. The harness permits
three retries only for status-bearing HTTP 408, 409, 425, 429, and 5xx errors;
provider SDK retries remain disabled. The HTTP-attempt ceiling therefore
reserves four attempts per logical call, while the token-cost ceiling remains
bound to the successful logical calls that return usage. A missing or unusable
response receives no content retry and no policy-judge call.

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

Revised 5 September 2026: the operator authorizes 80 percent provider ceilings
and shorter output allowances in exchange for more inputs. Anthropic available
funds are USD 90, giving a USD 72 cap including all Haiku judging. OpenAI's
ceiling is USD 32. The earlier per-arm forecast above remains historical.

The funded plan uses budget-fitted quantities as global retained-input
caps. It draws an exact balanced subset from the local Phase 7 inputs, and each
selected entry permits one paid target call. This avoids the unintended
per-arm multiplication in the superseded 8,734-call forecast. Adaptive local
framework prompts are retained test inputs; the paid campaign does not create
additional adaptive turns.

The scenario column uses 4,000 billed input tokens and one quarter of the
route's output ceiling per target call, including reasoning. It is explicitly
uncalibrated, not an empirical average or finish-cost prediction. The maximum
column uses the full configured output ceiling. Both assume at most 4,000
provider-counted input tokens per selected entry. Exact tokenization must
confirm that bound or the prospective allocation must be reduced and resealed.
The model-specific ceilings and pilot procedure are in HOSTED_CAMPAIGN_PLAN.md
A2; a 4,096-token ceiling is no longer imposed on nearly every model.
Kimi K3 uses explicit low reasoning effort instead of its default max effort;
its larger output ceiling remains available for complete final answers. This
is a budget-conditioned comparison, not an equal-compute model ranking.
[Kimi reasoning controls](https://platform.kimi.ai/docs/guide/use-reasoning-effort).

OpenAI maximum reservations additionally reserve 1.25 times the ordinary input
rate, or a higher published cache-write rate. Astra lists USD 10 input, USD 50
output and USD 12.50 cache writes per million tokens. The same 25 percent
allowance is conservatively reserved on the other OpenAI routes; it is not a
claim that they always incur that premium. Expected costs use ordinary input
rates. [OpenAI Astra model documentation](https://developers.openai.com/api/docs/models/gpt-6-astra).

| Provider | Target | Global calls | USD/M input | USD/M output | Max output tokens | Scenario USD | Max-token USD |
|---|---|---:|---:|---:|---:|---:|---:|
| Anthropic | Claude Fable 5.1 | 30 | 10.00 | 50.00 | 8,192 | 4.2720 | 13.4880 |
| Anthropic | Claude Opus 5 | 80 | 5.00 | 25.00 | 6,144 | 4.6720 | 13.8880 |
| Anthropic | Claude Sonnet 5 | 150 | 2.00 | 10.00 | 4,096 | 2.7360 | 7.3440 |
| Anthropic | Claude Haiku 4.5 | 200 | 1.00 | 5.00 | 2,048 | 1.3120 | 2.8480 |
| OpenAI | GPT-6 Astra | 30 | 10.00 | 50.00 | 8,192 | 4.2720 | 13.7880 |
| OpenAI | GPT-5.6 Sol | 30 | 4.00 | 20.00 | 8,192 | 1.7088 | 5.5152 |
| OpenAI | GPT-5.6 Terra | 30 | 2.00 | 12.00 | 6,144 | 0.7930 | 2.5118 |
| OpenAI | GPT-5.6 Luna | 150 | 0.20 | 1.20 | 4,096 | 0.3043 | 0.8873 |
| OpenAI | GPT-5.5 | 30 | 5.00 | 30.00 | 8,192 | 2.4432 | 8.1228 |
| Moonshot | Kimi K3 | 80 | 3.00 | 15.00 | 8,192 | 3.4176 | 10.7904 |
| DeepSeek | DeepSeek V4-Pro off-peak | 300 | 0.66 | 1.98 | 8,192 | 2.0085 | 5.6580 |
| **Total targets** | | **1,110** | | | | **27.9394** | **84.8416** |

This allocation replaces Fable 5 with exact `claude-fable-5-1`, released
1 September 2026; the earlier per-arm assessment above remains historical.
Fable 5.1 keeps USD 10/50 per million input/output tokens, so its USD 13.488
target reservation and the combined campaign totals are unchanged. Its lower
USD 0.25 cache-read price is not assumed as a saving in this reservation.
[Anthropic Fable 5.1 pricing](https://platform.claude.com/docs/en/models/fable-5-1/overview).

The target scenario costs USD 27.939392: 4,440,000 input and 1,602,560 output
tokens. Its maximum is USD 84.841568 with the same input bound and 6,410,240
output tokens. The matched Haiku plan adds at most 1,110 pairs or 2,220 judge
calls. Its 8,192-input/256-output scenario costs USD 21.02784, and its
12,288-input/512-output reservation costs USD 32.96256. Thus the combined
scenario is USD 48.967232 and the maximum is USD 117.804128. Across targets
and judging, this is 22,626,240 scenario input and 2,170,880 scenario output
tokens; maximum totals are 31,719,360 input and 7,546,880 output tokens.
Every judging input includes prompt, answer and rubric. The retained-response
judge sends text context, not the original physical image; it is not an
independent visual reinspection. The
former 4,000-token grading assumption did not reserve enough room for long
retained answers. Exact Haiku token counts must replace these planning bounds
before paid execution; no truncation of the answer is permitted to force a fit.

Provider reconciliation remains inside the 80 percent rule: Anthropic target
maximum USD 37.568 plus judge maximum USD 32.96256 is USD 70.53056 of USD 72;
OpenAI is USD 30.82512 of USD 32; Moonshot is USD 10.7904 of USD 12; and
DeepSeek is USD 5.658048 of USD 8. The rounded USD 33 judge allocation leaves
USD 1.432 inside Anthropic's ceiling. These reservations are not permission to spend.
Exact no-call selection, provider token counting and one-call canaries must
fit before authorization. If they do not, only the affected prospective count
is reduced and resealed before any output is observed.

The 1,110 target-call cap includes every paid readiness and diagnostic canary.
Those calls consume their target's global cap rather than adding an unbudgeted
request. The create-only `hosted_campaign_budget` projection reads and binds the
exact API config, effective-dated pricing and budget registries, reproduces the
expected and maximum-token columns, and reports a blocked status if any
provider exceeds 80 percent of its configured balance. It constructs no target or judge.

Paid targets and Haiku judging use zero answer-quality retries and three
harness retries only for the fixed status-bearing retryable HTTP errors.
Provider SDK retries are disabled, so every HTTP attempt remains visible.
The current monetary controller must reserve each physical attempt's complete
input bound and maximum output cost before sending it. The table is the funded
first-attempt population, not an assumption that retries are free. Retry
exposure uses available contingency or already settled savings while keeping
remaining selected calls and the Haiku allocation funded. Unknown usage keeps
its conservative reservation. If another attempt cannot fit, it is not sent;
the configured retry count does not override the provider or judge dollar cap.

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

The budget-fitted cohort selects at most 1,110 eligible local/hosted pairs, so
the local and hosted judged populations contain the same input entries. Exact
identity binds the rendered prompt, media-reference digest, datapoint, source
cluster, seed, arm/framework, modality, risk, expected behavior and source
policy. Seed-0 balanced round-robin sampling spans both target models and those
input strata. A local judgment may support multiple same-input comparisons;
each unique local or hosted output incurs at most one Haiku call. Missing responses remain in
coverage statistics but require no judge call and cannot form a judged pair.
The pair limit equals the hosted campaign's 1,110-target ceiling and therefore
includes every eligible answered hosted output exactly once rather than drawing
a smaller outcome-selected sample.
Source-authoritative R-Judge and GPTGeoChat decisions are excluded. Haiku's own
target outputs are included by explicit operator decision and labelled
same-model, non-independent evidence.
The conservative 2,220-judgment scenario costs USD 21.02784; its maximum reservation is
USD 32.96256 inside a USD 33 allocation. Full grading requests, including local
answers, must be counted with the judge provider before fixing affordable
hosted quantities. Long answers are not silently truncated or discarded based
on their security outcome. Pilot answers remain a separate diagnostic stratum.
The all-model matched core is reported separately from larger model-specific
extensions; a 30-call premium lane cannot support precise per-arm conclusions.

Shared local judgments reduce actual unique-call counts, not the prospective
reserve. Their repeated comparison links are correlated evidence, not new
independent local samples. Historical `/1` disjoint-pair plans are unchanged.

The later comparison is a matched selected-cohort analysis, not a full-corpus
estimate. It publishes separate hosted/local member tables from the identical
pair inventory plus unpaired coverage counts.
Every hosted target lane already applies the sealed local `rules,guardrail`
cascade, adding at most 1,110 rule evaluations and 1,110 Llama Guard calls but no
hosted-provider cost. The Haiku selector reuses those unchanged local trails on
the exact hosted pair members. Local versus Haiku agreement is reported only on
comparable decided labels, with the local decision denominator and abstentions
displayed because Llama Guard cannot express benign over-refusal when the rules
stage is undecided.
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
- Kimi published rate confirmation: <https://forum.moonshot.ai/t/kimi-k3-is-here-our-most-capable-model/480>
- DeepSeek: <https://api-docs.deepseek.com/quick_start/pricing/>

All rates are effective-dated planning inputs and must be fetched and reviewed
again immediately before a paid campaign.
