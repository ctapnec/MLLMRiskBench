# Third hosted campaign: provider-scaled expansion

Status, 10 September 2026: requested quantities and a full-pool input
availability preview and a shared-input preview are verified on the rig.
Shared-cohort preparation and credit-stop handling have passed focused rig tests.
The first 128-input batch is complete, with local judging, output-specific
Haiku judging of its 21 eligible measured answers and thirteen per-model Stats
publications. Its twenty matching local answers also have valid Haiku verdicts.
The next 224-input slice is funded; all 63 additional matching local answers
have valid Haiku verdicts. Its target controllers stopped before any target
call because their probe selector considered only the original canary jobs.
The corrected selector passed all thirteen actual funded-route validations
on the rig, while restoring the former selection fails on those same inputs.
Both target queues and their analysis successor restarted at 12:38 UTC using
suitable already-funded whole jobs. The complete input selection and failed
controller history are preserved. Most of the requested expansion
remains unexecuted. This is a separate cohort
after [the original campaign](HOSTED_CAMPAIGN_PLAN.md) and
[the supplement, including Google](HOSTED_SUPPLEMENT_PLAN.md).

## Required quantities

The new campaign alone requests five times the combined earlier Kimi and
DeepSeek input counts and three times the combined earlier Google, OpenAI and
Anthropic counts. These are additional evaluations, not cumulative totals,
token multipliers, retries or judge-call multipliers.

| Provider | Original campaign | Supplement and Google extension | Earlier total | Multiplier | New evaluations |
| --- | ---: | ---: | ---: | ---: | ---: |
| Anthropic | 455 | 296 | 751 | 3 | 2,253 |
| OpenAI | 264 | 243 | 507 | 3 | 1,521 |
| Google | 0 | 324 | 324 | 3 | 972 |
| Kimi | 79 | 34 | 113 | 5 | 565 |
| DeepSeek | 143 | 103 | 246 | 5 | 1,230 |
| Total | 941 | 1,000 | 1,941 | - | 6,541 |

One evaluation is one assigned model-input condition with a target attempt.
Policy outcomes and missing responses remain in attempted-input accounting;
they are not replaced to inflate successful-answer counts. HTTP retries are
separate physical attempts. The resulting cumulative assignment count would
be 8,482, not 8,482 independent questions or guaranteed answers.

The historical baseline deliberately retains the original campaign's source
aliases because the operator specified its queried quantities. This does not
permit duplicate source aliases to inflate the new selection. New requests
must exclude already attempted model/input conditions, including failures.

## Per-model reference allocation

The following proportional allocation preserves the existing roster and its
relative coverage. It is the first allocation to assess, not a funded promise.
The operator specified provider totals, not mandatory per-model multipliers.
Any budget-driven redistribution within a provider must be recorded explicitly
before selection and execution; do not silently remove frontier coverage,
substitute another model or lower the provider target.

| Model | Earlier total | Proportional new allocation |
| --- | ---: | ---: |
| Fable 5.1 | 47 | 141 |
| Opus 5 | 132 | 396 |
| Sonnet 5 | 249 | 747 |
| Haiku 4.5 | 323 | 969 |
| GPT-6 Astra | 47 | 141 |
| GPT-5.6 Sol | 58 | 174 |
| GPT-5.6 Terra | 58 | 174 |
| GPT-5.6 Luna | 297 | 891 |
| GPT-5.5 | 47 | 141 |
| Gemini 3.8 Flash | 162 | 486 |
| Gemini 3.1 Pro Preview | 162 | 486 |
| Kimi K3 | 113 | 565 |
| DeepSeek V4 Pro | 246 | 1,230 |

### Full-pool availability preview

At 09:04 UTC the rig finished reading all 372 validated source cells and
27,847 retained input candidates. Applying the proportional reference above
to the existing whole-cluster prefixes selected 6,495 new input payloads:

| Provider | Requested | Whole-cluster prefix preview | Unfilled allocation |
| --- | ---: | ---: | ---: |
| Anthropic | 2,253 | 2,242 | 11 |
| OpenAI | 1,521 | 1,503 | 18 |
| Google | 972 | 966 | 6 |
| Kimi | 565 | 556 | 9 |
| DeepSeek | 1,230 | 1,228 | 2 |
| Total | 6,541 | 6,495 | 46 |

This is a cluster-boundary effect, not exhaustion of the local input pool.
For example, Kimi has nine slots left before a fifteen-request cluster and
DeepSeek has two slots left before a four-request cluster. Do not silently
replace the requested total with 6,495 or split those groups. Finalize and
report any per-model reallocation and unavoidable provider-level shortfall
before funding. The provider targets above remain the requested quantities.

The preview excludes previous retained input payloads, uses no answer or
verdict to select inputs and sends no API requests. Its 4,315 selected source
memberships are not 4,315 independent questions or local Haiku calls. Exact
provider-wire requests, expanded media resolution and matching output-specific
judging counts remain to be validated. Evidence:
`engineering/hosted-expansion-20260910/result.json` on the rig.

## Budget and generation conditions

The latest operator-reported balances total USD 151.06. Preserve the earlier
absolute buffers as well as the 80 percent spending limit. A working envelope
is below; it is a prospective allocation, not a cost estimate or funded ledger.

| Provider | Reported balance | Working ceiling | Credit left at that ceiling |
| --- | ---: | ---: | ---: |
| Anthropic, targets and Haiku judging together | $78.43 | $60.00 | $18.43 |
| OpenAI | $32.17 | $24.00 | $8.17 |
| Google | $22.12 | $17.00 | $5.12 |
| Kimi | $9.10 | $6.00 | $3.10 |
| DeepSeek | $9.24 | $7.00 | $2.24 |
| Total | $151.06 | $114.00 | $37.06 |

Within Anthropic's working ceiling, protect USD 33 for Haiku assessments and
at most USD 27 for target generation. This replaces the earlier informal
USD 35 judging suggestion: the existing budget tool supports a maximum
USD 33 protected judge pool. Do not change that tool merely to publish a plan.
The exact split still needs the selected-output count and token quote.

Retain validated generation settings while estimating costs, including
DeepSeek's corrected 16,384 output-token allowance. A short-answer average
is not a maximum-cost reservation. Do not reinstate a known reasoning-starved
limit simply to make the requested quantity appear affordable. Any changed
output allowance or reasoning setting is a separately recorded condition.

Count complete provider requests, including images and billed reasoning or
Pro-mode amplification where applicable. Price standard execution, not a
Batch discount for synchronous calls. Reserve each physical HTTP attempt,
retain unknown charges and fund both judging obligations before dispatch.
User-reported account credit is not per-attempt billing reconciliation.

Assess the full fixed selection first. If all maximum allowances do not fit
at once, assess bounded successive batches using the existing accounting
mechanisms, with one cumulative provider ceiling and reserved judging funds.
Never reset the spending allowance for each batch, lower a reservation to an
average, or call an unfunded remainder complete. Full-count affordability
remains unverified until this assessment is complete.

Current pricing references, checked 10 September 2026:
[OpenAI](https://developers.openai.com/api/docs/pricing),
[Anthropic](https://platform.claude.com/docs/en/about-claude/pricing),
[Google](https://ai.google.dev/gemini-api/docs/pricing),
[DeepSeek](https://api-docs.deepseek.com/quick_start/pricing/) and
[Kimi](https://platform.kimi.ai/docs/pricing/chat-k3).
Kimi's official page stores its numeric table in the rendered page component.
Its source was checked directly: USD 3 input, USD 0.30 cache-hit input and
USD 15 output per million tokens. Do not assume a cache-hit discount before
the provider reports it.

DeepSeek currently publishes peak/off-peak prices and announces that the
V4 Pro alias will route to V4.1 Flash from 14 September 2026 at 04:00 UTC.
Do not pool outputs across that identity change. Complete the retained Pro
condition before that boundary or record the replacement as a separate model
condition. Off-peak savings are conditional, not guaranteed funding.

## Selection, judging and comparison

Select the common input cohort before assigning it to models. Every provider
uses that same fixed cohort, not independently sampled questions. Smaller
allocations use a nested common core; larger allocations extend it in the same
deterministic order. Compare all models only on their common text inputs and
compare multimodal models on identical images and prompts. Show extra-input
results separately and report the exact intersection for each comparison.

The 09:22 UTC shared preview excludes every source cluster containing a
previously queried input payload. It contains 6,474 prospective model-input
evaluations, with 114 text inputs common to all thirteen routes and 141 inputs
common to the twelve multimodal routes. These are input-only selection counts,
not funded generation counts. The 67 whole-cluster boundary gaps do not replace
the requested 6,541. Per-route preview counts are Fable 141, Opus 395, Sonnet 747,
Haiku 956, Astra 141, Sol 171, Terra 171, Luna 889, GPT-5.5 141, Flash 480,
Pro 480, Kimi 549 and DeepSeek 1,213. This shared preview supersedes the earlier
independently extended route preview for prospective selection only.

Funding batches are slices of this fixed input prefix. A batch cannot split
a source cluster or select inputs according to previous answers. Completed
input slices are not replayed when the next batch is funded. Financial limits
remain cumulative across batches; a fresh ledger is not a fresh spending
allowance. The original plans and results remain immutable.

The completed source assessment found 5,358 eligible existing local answers
on 1,401 matching input identities. None has a reusable earlier Haiku verdict
for this newly selected cohort. All 31 additional media files have been
located and hash-verified without downloads. The first prepared batch contains
ten inputs for each multimodal route and eight for DeepSeek: 128 target inputs,
plus twenty matching local answers needing Haiku assessment. Counting produced
128 request receipts using 120 count-endpoint requests, and this batch is now
funded. By 10:28 UTC, Sonnet's ten assignments and DeepSeek's eight assignments
were complete. Their three eligible measured outputs have separate Haiku
assessments; diagnostic and source-ineligible outcomes remain outside that
measured judging population. All twenty matching saved local answers have
valid Haiku verdicts, costing USD 0.026716 from reported token usage. These are
first-batch results, not completion of the expansion.

Later disjoint input slices may be prepared without allocating more spending.
They cannot dispatch while an earlier allocation can still consume the same
provider or judge funds. Count-only preparation may proceed in parallel;
funding follows reconciliation of the closed preceding work against the
cumulative ceilings. The 224-input second slice was funded after the first
slice closed. Its 63 new judgments of exact existing local answers are complete
and valid. The recovered target queues are executing under their existing
allocation; no completed local judgment was repeated.
Unknown charges and unused earlier judge commitments remain reserved, not
reported as spent. Future batches use the cache-usage preservation correction
documented in RA-446. Where complete cache-inclusive token totals exist but
the exact cache split is missing, RA-449 permits a conservative maximum-tariff
bound on the reported tokens, separately from an exact bill. Unreported token
usage, HTTP failures and unpriced positive cache writes remain fully held.
Closed historical responses can be reconciled without repeating any answer;
active shared-ledger users must finish before the accounting upgrade.

The third prospective financial slice increases throughput for the lower-cost
routes while preserving the fixed shared prefixes and final per-model limits.
Its no-call selection contains 612 additional target inputs and 624 new saved
local answers requiring Haiku assessment. The selected route counts are Fable
15, Opus 30, Sonnet 51, Haiku 150, Astra 15, Sol 15, Terra 17, Luna 98, GPT-5.5
15, Kimi 30, DeepSeek 74, Flash 51 and Pro 51. These are batch sizes, not revised
campaign totals. Whole-cluster boundaries explain the unused nominal capacity.
Materialization and exact request counting are complete; this
slice has not been funded or executed. Token limits and reasoning settings
are unchanged. Financial allocation must still leave both judging obligations
covered and must not consume the earlier batches' retained exposure.

The fourth no-call selection extends the same shared prefixes by 655 target
inputs and identifies 492 new existing local answers for Haiku assessment.
Its selected counts are Fable 15, Opus 21, Sonnet 74, Haiku 149, Astra 15,
Sol 15, Terra 17, Luna 96, GPT-5.5 15, Kimi 21, DeepSeek 69, Flash 74 and
Pro 74. Materialization, prospective probe checks and counting are complete.
One oversized Haiku image required verified lossless PNG packing. Its source
file, format, dimensions and every pixel remain unchanged. The corrected
unstarted-request binding changes exactly one provider request hash while
the other twelve route artifacts remain identical. Counting reused 249 saved
receipts and required 337 additional count-endpoint requests. The slice is not
yet funded. Its continuation
must verify suitable transport probes within the unchanged inputs and wait
for the preceding batches' target and judging costs to close. These figures
do not change the requested provider totals or authorize new spending caps.

At the 14:17 UTC execution snapshot, 352 inputs are funded in the first two
batches, with 267 started and 266 usable outcomes. Another 1,267 inputs are
selected and counted in batches three and four. These staged quantities do
not reduce the requested 6,541 evaluations. The remaining 4,922 assignments
include the 67 unresolved whole-cluster boundary gaps. The fifth slice is
being prepared from the same fixed cohort. It prospectively appends the two
verified VLBreakBench image directories to the campaign media roots; the
existing root order, request contents and selected input identities stay fixed.

The fifth slice subsequently completed input preparation with 607 target
evaluations and 317 additional existing local answers selected for Haiku
assessment. Its materialization is in progress, not paid execution. Thus
2,226 target evaluations are funded or prepared across the first five slices:
352 funded, 1,267 further counted, and 607 prepared. The other 4,315 requested
evaluations, including the 67 boundary gaps, remain pending. Judging calls are
additional to these target-evaluation counts. Sixth-slice input preparation
has started from the fifth slice's exact ending prefixes, without new funding.

Use only inputs already executed by the local campaign. Preserve prompt,
conversation, media bytes, seed, framework, arm, corpus and source-policy
identity. These are retained-conversation transfers; adaptive attacks are not
newly generated against hosted models. Existing local generations are not
restarted by this plan.

Use the existing deterministic, modality-compatible, whole-cluster ordering.
Exclude prior paid requests and collapse source aliases before applying new
limits. Preserve complete conversations and shared-media groups. Report any
whole-cluster shortfall explicitly; do not split a cluster, exceed a provider
quota or invent an extra unique input to fill an exact number. Verify the full
available input pool, not only the previous supplement's cached prefix.

Every eligible new hosted output requires its own local-cascade judgment and
its own Haiku assessment. Match every existing eligible local output on those
same inputs for Haiku assessment. Reuse a local verdict only when both its
actual output and judging condition are identical. Never reuse a verdict for
another model's new output just because its input matches. Local and hosted
judgment totals can differ because models cover different subsets and share
local counterparts; input identity, not equal row counts, defines matching.

Before outcomes, report 6,541 requested target evaluations separately from
the still-unknown eligible hosted judgments, distinct local counterparts and
new versus exactly reusable local Haiku assessments. Do not advertise an
invented fixed judging total. Preserve source-native or unscored tasks and
missing outputs in coverage even when they have no common-security verdict.

Keep zero answer retries and up to three retries for qualifying HTTP or
network errors. Explicit provider-policy refusals, including HTTP 400 with
`cyber_policy`, are legitimate terminal outcomes and do not stop the campaign.
Usable length-ended text is retained with truncation marked. Unexplained empty
answers require investigation before further paid execution, not automatic
answer retries. Invalid judge verdicts remain unscored.

Monitor explicit exhausted-credit and account-spending-limit responses.
These are not transient rate limits and must not consume the HTTP retry
allowance. Retain the failed attempt, its machine-readable funding reason and
any unknown charge. Stop further target dispatch to that provider and report
the unstarted remainder; continue other independently funded providers. If
Anthropic funding becomes unavailable, preserve outstanding Haiku obligations
and stop any dispatch whose promised judging is no longer funded. Do not
top up an account, clear a stopped paid circuit or infer zero cost automatically.
Ordinary rate limits remain retryable under the existing bounded policy.

Publish this third cohort separately in Stats, with local/Haiku comparisons,
coverage, model stability, output allowance, actual token usage, truncation,
framework/arm/corpus composition and spending. Show independent input support
separately from source aliases and matched comparison links.

## Execution order and reporting

### Hosted-only parallel execution

The user requested independent provider queues on 10 September. Use up to
eight active hosted model routes, with at most two routes per provider.
Installed model reuse uses metadata checks by default, not full weight-file
SHA reads. A full recheck requires `--verify-model-sha256`, also available as an
unchecked Build option. Do not launch nested checksum pools during routine
execution. Existing acquisition receipts may seed the installed verification
record without downloading or reading all model weights again.
OpenAI, Anthropic, Google, Kimi and DeepSeek need not wait for each other's
responses. This does not change local-target scheduling. Each retained
conversation, input partition, generation setting and paid slot stays fixed;
adaptive conversation steps are never dispatched out of dependency order.

Local judging remains post-generation and output-specific. Concurrent hosted
workers acquire one shared scoring slot for their assigned GPU before loading
the local judge and release it after Runner teardown. Thus network waits do
not occupy a GPU slot, and no more than two local judges run at once. Haiku
judging shares Anthropic's account limits and its protected monetary pool.

Honor valid `Retry-After` delays, including HTTP-date values. Otherwise use
exponential backoff with jitter; preserve the three-retry transport maximum,
per-attempt reservation and timeout evidence. Slow or rate-limited workers
must not block other independently funded providers. Exhausted-credit errors
remain provider funding stops, not ordinary HTTP 429 retries. When a paid
circuit opens, stop new dispatch and retain responses already in flight.

Published limits permit concurrency but are not proof of this account's
current quota. Check provider/model limits and account response headers;
lower dispatch concurrency when rate limiting persists. In particular,
[OpenAI](https://developers.openai.com/api/docs/guides/rate-limits) can share
limits across models; [Anthropic](https://platform.claude.com/docs/en/api/rate-limits)
uses request, input-token and output-token rates;
[Google](https://ai.google.dev/gemini-api/docs/rate-limits) applies project quotas;
[Kimi](https://platform.kimi.ai/docs/introduction) shares account limits across
models and accounts for the requested output allowance when rate limiting;
[DeepSeek](https://api-docs.deepseek.com/quick_start/rate_limit/) documents
account-level concurrency limits.

The 332 saved early responses contained 4,449 seconds of summed generation
latency. That is not total campaign duration: source validation, local model
verification, judging and recovery also consume wall time. Do not simply
divide the earlier full-campaign ETA by the worker count. Establish the new
throughput from an actual funded parallel batch, without new benchmark-only
calls or changed inputs.

Carry the reviewed Sol Pro aggregate-work contingency into each future
funding slice: USD 0.30 per unstarted Sol input, in addition to its counted
request reservation, within the unchanged OpenAI ceiling. Allocate this
contingency before the Sol route is dispatched. Other already-funded OpenAI
routes may run first and release unused exposure through their retained usage
records; a pending Sol allocation must not idle the other providers. Do not
dispatch Sol if its contingency still cannot fit, release an unknown charge,
or enlarge the provider ceiling. This is not a
guaranteed bound on provider model work. Preserve unknown exact charges and
the original paid outputs; do not retry an answer to repair accounting.

### Campaign sequence

1. Verify the completed-family baseline - done, 10 September at 08:54 UTC.
2. Finalize new retained inputs and count all matching local judging obligations;
   the full-pool availability preview completed at 09:04 UTC.
3. Quote actual requests, reconcile outstanding liabilities and fund the work.
4. Execute target collection on the rig in tmux, preserving checkpoints.
5. Complete local and Haiku judging, then publish the separate Stats report.

Reuse installed runtimes and the tested deployed adapters. Do not repeat
Windows tests, framework installations or completed readiness work. Register
new preparation and execution jobs in the console. While a worker is active,
provide aggregate reports at 30-minute intervals: target/answer/judging counts,
progress since the last report, remaining funded work, budgets and an ETA
based on observed throughput. No generation ETA is established before launch.

Audit evidence is retained on the rig and in the ignored thesis verification
directory. Operational scripts and campaign data must not be committed to Git.
