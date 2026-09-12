# Third hosted campaign: provider-scaled expansion

UI publication requirement, 11 September 2026: original, supplemental, Google
and expansion work will appear in one API campaign workspace, not as separate
top-level campaigns or a long job list. Local/Haiku judging and costs belong to
the outputs they assess. The [workspace specification](../docs/CAMPAIGN_WORKSPACES.md)
also defines the future manual UI execution flow and its common-input comparison
with the Local campaign. This is pending UI integration, not new target work;
collection continues while it is prepared.

## Current account balances

Operator-reported sixth update, retained on 12 September 2026 at 17:17 UTC.
This observation does not increase campaign allowances or launch an extension.

| Provider | Previous credit (USD) | Latest credit (USD) | Net decrease (USD) |
| --- | ---: | ---: | ---: |
| Anthropic | 48.01 | 20.22 | 27.79 |
| OpenAI | 14.36 | 4.59 | 9.77 |
| Google | 17.14 | 11.22 | 5.92 |
| Kimi | 4.11 | 1.45 | 2.66 |
| DeepSeek | 3.43 | 2.68 | 0.75 |
| Total | 87.05 | 40.16 | 46.89 |

The decreases are account-level observations, not campaign-attributed bills.
Historical balances and uncertain individual charges remain unchanged. Anthropic
target generations and Haiku judging share the same USD 20.22 credit.

The proposed next extension prioritizes a full Gemini Pro daily cohort on
existing comparison inputs. A retained provider response reports 250 requests
per day for Gemini 3.1 Pro. Subject to unchanged quota, other project usage and
transport retries, the 20 pending inputs would leave at most 230 new inputs in
a fresh daily allowance. This is a proposal, not an already-funded selection.
Do not repeat completed Pro model-input conditions to fill the quota.

Across 650 historical Pro attempts with reported token usage, mean input and
output usage were 562 and 753 tokens. At standard prices of USD 2 and USD 12 per
million tokens, respectively, 250 similar attempts would cost approximately
USD 2.54; the 230 additional attempts account for approximately USD 2.34.
These are token-priced estimates, not provider-confirmed charges or guarantees.
At the retained 4,096-token output allowance, 250 maximum-length answers would
instead cost approximately USD 12.57 at the same mean input length, before any
transport retries. Consequently the cohort must remain subject to the actual
spending limit; the mean-cost estimate cannot authorize an overrun.
[Google pricing](https://ai.google.dev/gemini-api/docs/pricing).

Every new generated answer requires its own local and Haiku assessment. Existing
local answers on the same inputs can reuse only judgments of those exact saved
answers, never judgments of a different model's response. Protect the remaining
judging allocation before selecting further Anthropic target work. The current
tracked Haiku allowance is USD 11.229735, not an additional account balance or
a claim that this entire amount will be spent.

Google documents the next daily reset as 13 September at 07:00 UTC, or 10:00
Europe/Kyiv. A controller's earlier scheduled retry is not proof of a quota
reset. Actual project quota and retry responses remain authoritative.
[Google rate-limit documentation](https://ai.google.dev/gemini-api/docs/rate-limits).

### Approved Pro daily extension (12 September, 21:50 UTC)

The operator's continuation request has now been prepared and queued on the
rig. The new selection contains 230 inputs: 189 text and 41 image inputs across
25 logical arms. It uses the existing fourth-cohort prefix already delivered
to Flash and local models. All existing Pro request slots, including unfinished
ones, were excluded. Whole source clusters, sampling seeds, rendered prompts
and media are retained; output quality was not used for selection.

Google counted 105,817 input tokens across these exact requests. With a
4,096-token output allowance, the first-attempt maximum is USD 11.516594;
using the historical mean of 753 output tokens gives USD 2.289914. Neither is
a provider-confirmed bill. The combined Google continuation has a USD 10
further-spending stop, including the existing 20 pending inputs, leaving
USD 1.22 of the reported credit outside it. This is a reduction in the shared
campaign stop, not another copy of the account balance. Reported-spend stopping
does not guarantee a worst-case final bill when usage is unknown or calls are
already in flight. Transport retries remain three; automatic answer retries
remain zero. Budget exhaustion must remain a separate stopping reason.

The detached `google-pro-daily-extension` worker on
`ura-hosted-expansion-20260910` is scheduled no earlier than 13 September at
07:00 UTC. It uses one Google worker, allowing at most two alongside the
existing remainder. Fresh transport probes use untouched inputs within the
230 selected requests, not extra requests, and are not replayed by subsequent
collection. Quota responses remain authoritative. This queue is attached to
the existing API campaign workspace; paid target generation has not started.

Each eligible new Pro output requires its own native local and Haiku
assessment. The selection also maps to 1,030 existing local outputs with
already assigned Haiku slots. Reuse applies only to their exact saved answers,
never to the new Pro response. Native/source-specific assessment and common
comparison eligibility remain distinct. The half-hour aggregate now includes
this 230-input extension separately and in its overall assignment count.
Preparation, counting and funding evidence is retained under
`runs/engineering/google-pro-daily-extension-20260912`; execution is under
`runs/engineering/google-pro-daily-extension-execute-20260912`.

At 23:18 UTC the separate `google-pro-daily-judging` tmux controller was
registered in the same API workspace and began waiting for collection. It
prepares the exact saved Pro outputs, uses their existing funded Haiku slots,
retains missing/invalid assessment coverage, and publishes primary Haiku and
native verdicts with their physical costs. Native model work waits for the
local recovery's device owners; this does not delay independent API collection.
Only the paid/counting children source provider credentials. No model bytes
are downloaded or fully hashed. This is a queued follow-up, not completed
judging. Additional source-grading contexts remain separately pending and
must not be conflated with primary output assessments or independent target
generations. The worker records that remaining scope explicitly.

The older remainder has a separate observation-age issue: fourteen untouched
inputs sit behind an already-started job with six pending inputs. Its 24-hour
transport observations expire before this quota reset. The transport-tail
controller therefore waits for the old worker to end and the new Pro queue's
fresh observations before dispatching only wholly untouched jobs. The target
configurations were compared and are identical. Completed jobs and paid slots
are preserved; the observation-age policy is not extended, and no extra probe
input is purchased. Any partially started remainder stays with its existing
checkpoint recovery. Tail collection, its judging and publication must still
be verified after execution, not inferred from the queued controller.

### Previous account observation: fifth update

Operator-reported fifth update, recorded on 11 September 2026 at 23:11
UTC (12 September locally). Earlier observations are retained below.

| Provider | Previous credit (USD) | Latest credit (USD) | Net decrease (USD) |
| --- | ---: | ---: | ---: |
| Anthropic | 49.01 | 48.01 | 1.00 |
| OpenAI | 14.50 | 14.36 | 0.14 |
| Google | 17.46 | 17.14 | 0.32 |
| Kimi | 4.23 | 4.11 | 0.12 |
| DeepSeek | 3.51 | 3.43 | 0.08 |
| Total | 88.71 | 87.05 | 1.66 |

These account observations include posted consumption, not necessarily only
this campaign's calls. They neither erase earlier snapshots nor settle unknown
individual charges. Haiku judging and Anthropic target generations share the
same USD 48.01 account credit; do not allocate it twice.

Google daily request quotas reset at midnight Pacific time, not local midnight.
For 12 September this is 07:00 UTC, or 10:00 Europe/Kyiv. Minute quotas and
provider-supplied retry delays are separate. Keep the pending Pro selection
and retry state, and confirm its actual quota response before resuming; credit
availability alone does not establish request availability.
[Google rate-limit documentation](https://ai.google.dev/gemini-api/docs/rate-limits)
was checked on 12 September 2026.

### Previous account observation

Operator-reported fourth update on 11 September 2026, received around 15:09 UTC:

| Provider | Previous credit (USD) | Latest credit (USD) | Net decrease (USD) |
| --- | ---: | ---: | ---: |
| Anthropic | 49.08 | 49.01 | 0.07 |
| OpenAI | 14.74 | 14.50 | 0.24 |
| Google | 17.74 | 17.46 | 0.28 |
| Kimi | 4.23 | 4.23 | 0.00 |
| DeepSeek | 4.42 | 3.51 | 0.91 |
| Total | 90.21 | 88.71 | 1.50 |

This is a new account observation, not a replacement of earlier balances or
settlement of unknown per-call charges. The subsequent request for another
balanced campaign is documented in [the balanced campaign plan](HOSTED_BALANCED_CAMPAIGN_PLAN.md).
It shares these account credits with all unfinished target and judging work;
USD 88.71 must not be allocated independently to both campaigns.

### Previous allowance update

Operator-reported third update on 11 September 2026, received at 13:33 UTC.
These are account credits. The preceding snapshots remain unchanged below.

| Provider | Previous credit (USD) | Latest credit (USD) | Net decrease (USD) |
| --- | ---: | ---: | ---: |
| Anthropic | 49.52 | 49.08 | 0.44 |
| OpenAI | 14.83 | 14.74 | 0.09 |
| Google | 17.79 | 17.74 | 0.05 |
| Kimi | 4.23 | 4.23 | 0.00 |
| DeepSeek | 4.88 | 4.42 | 0.46 |
| Total | 91.25 | 90.21 | 1.04 |

The balance update itself does not settle uncertain charges. After this report,
the operator explicitly authorized continuing DeepSeek against its remaining
USD 4.42 rather than stopping at the older USD 7 campaign ceiling. At that stop,
tracked campaign spending was USD 7.024506; the revised stopping threshold is
USD 11.444506, adding the reported available credit without resetting spending.
At that initial DeepSeek-only update, other provider ceilings and the protected
Haiku allocation were unchanged. The continuation selects only the 295 untouched inputs in seven partial jobs,
preserving 265 saved responses and the separate interrupted HTTP pilot. An actual
insufficient-credit response stops that provider. Retain the previous scope and
the new authorization beside the unchanged plans and billing records.

The operator subsequently authorized raising all five provider allowances.
The applied configuration uses the 13:34 tracked-spending observation and the
13:33 account balances, preserving the remaining Haiku allocation inside the
Anthropic balance. These figures are planning headroom, not live account reads;
later charges and in-flight requests reduce the available amounts.

| Provider / purpose | Additional tracked headroom (USD) | Revised cumulative threshold (USD) |
| --- | ---: | ---: |
| Anthropic targets | 21.388997 | 46.263894 |
| Anthropic Haiku judging | 27.691003 | 33.000000 |
| OpenAI targets | 14.740000 | 32.429681 |
| Google targets | 17.740000 | 21.475466 |
| Kimi targets | 4.230000 | 9.084431 |
| DeepSeek targets | 4.420000 | 11.444506 |
| Total additional headroom | 90.210000 | - |

This explicit authorization supersedes the former target thresholds without
resetting any previously tracked spending, erasing uncertain charges or raising
the Haiku threshold. Both active shared-spending owners received the revision.
Continue the fixed selected inputs, retain provider-directed quota waits and
stop a provider on an actual exhausted-credit response. Do not infer that a
higher allowance has itself selected, generated or judged additional inputs.

### Previous same-day snapshot

Operator-reported second update on 11 September 2026, received after the
12:34 UTC observation. These are account credits, not campaign-only costs.

| Provider | Previous credit (USD) | Latest credit (USD) | Net decrease (USD) |
| --- | ---: | ---: | ---: |
| Anthropic | 59.61 | 49.52 | 10.09 |
| OpenAI | 25.06 | 14.83 | 10.23 |
| Google | 18.47 | 17.79 | 0.68 |
| Kimi | 7.19 | 4.23 | 2.96 |
| DeepSeek | 6.53 | 4.88 | 1.65 |
| Total | 116.86 | 91.25 | 25.61 |

The earlier snapshots below remain unchanged. The update neither increases
campaign ceilings nor settles unknown per-call charges. Both target work and
output-specific local/Haiku judging remain within their existing allocations.
Google account credit does not override a model's request quota.

### Earlier balance updates

Operator-reported update on 11 September 2026. Retain every earlier dated
snapshot; this update adds to the balance history rather than replacing it.

| Provider | Remaining account credit (USD) |
| --- | ---: |
| Anthropic | 59.61 |
| OpenAI | 25.06 |
| Google | 18.47 |
| Kimi | 7.19 |
| DeepSeek | 6.53 |
| Total | 116.86 |

Change since the balances used to plan this expansion on 10 September:

| Provider | Earlier credit (USD) | Updated credit (USD) | Net decrease (USD) |
| --- | ---: | ---: | ---: |
| Anthropic | 78.43 | 59.61 | 18.82 |
| OpenAI | 32.17 | 25.06 | 7.11 |
| Google | 22.12 | 18.47 | 3.65 |
| Kimi | 9.10 | 7.19 | 1.91 |
| DeepSeek | 9.24 | 6.53 | 2.71 |
| Total | 151.06 | 116.86 | 34.20 |

The net decrease estimates account consumption when there were no intervening
top-ups, refunds or credit adjustments. It is not automatically campaign-only
spending: other projects and delayed billing can affect the same accounts.
Retain the per-call campaign accounting alongside this independent comparison.

These are account credits, not new campaign allocations or measured campaign
costs. The existing cumulative provider ceilings and protected Haiku allocation
remain unchanged. Preserve the historical accounting and uncertain charges;
do not subtract already-posted historical charges twice from these balances.
Reconcile spending after this snapshot and unposted liabilities before using
the balances to fund further requests. Both local and Haiku judging remain
required after target collection.

## Continuous execution

### Additional Flash inputs, 11 September

The operator's account-panel screenshot confirms Gemini 3.8 Flash limits of
1,000 requests/minute, 2,000,000 tokens/minute and 10,000 requests/day. The
displayed 259 requests/day is peak usage over the selected 28-day interval,
not remaining daily capacity. Gemini 3.1 Pro is separately limited to 250/day.
Evidence: [operator-supplied quota panel](https://gyazo.com/f1b2b82020b809ec21e9d0b40bcc89aa).

The authorized additional Flash selection extends the existing deterministic
shared input prefix from 480 to 747 inputs: 267 additional inputs, matching
Sonnet's prefix. Preserve the existing 4,096-token output allowance, seed,
prompt/media bytes, whole source clusters and zero answer retries. Qualifying
HTTP failures retain up to three retries with provider-directed backoff. No
already completed Flash answer is repeated, and Pro inputs are not replaced.
Exact counting and preparation precede dispatch; this paragraph is not evidence
that the additional generations have completed.

At this extension's initial preparation, the Google ceiling was USD 17 and the
Haiku ceiling USD 33. The later explicit all-provider update above raises the
Google threshold; Haiku remains USD 33.
Additional inventory is included in the same cumulative spending calculation,
not a fresh spending allowance. Both local and Haiku judges assess every
eligible new hosted output. Existing local answers on the identical inputs
remain in the Haiku comparison; a saved verdict is reused only for the same
actual output and judge condition. The original 67-input allocation gap remains
separate from this explicitly added work.

12:34 UTC observation: 5,519 of 6,669 assignments attempted, with 5,503 usable
outcomes, up 277 in thirty minutes. There are 1,150 unstarted assignments and
the separate 67-input allocation gap. Haiku totals remain 2,217 local and
1,508 hosted; these include 18 and seven invalid verdicts, respectively.
Console HTTP is 200, with no provider credit-exhaustion marker. Luna has a
new terminal-transport pause requiring inspection; its pending rows are not
declared complete. The half-hour recorder saved this snapshot on schedule;
delivery to the operator was late. The next saved observation is due at
13:04 UTC.

Google Pro's retained HTTP 429 identifies a per-project, per-model quota of
250 requests per day, not exhausted account credit. At 12:33 UTC its existing
worker was alive and sleeping until 00:00 UTC on 12 September. This is an
observed controller timer, not a verified provider reset time: Google's
[rate-limit documentation](https://ai.google.dev/gemini-api/docs/rate-limits)
states midnight Pacific for daily quotas. The original error's short RetryInfo
and the later long timer are distinct observations; the current in-flight
error is not yet durably available. Do not claim guaranteed resumption at
midnight UTC or restart the request merely to inspect it. Flash independently
completed its 259 queued inputs. Remaining Pro inputs and their judging remain
pending, so throughput alone cannot establish the full campaign finish time.

12:04 UTC observation: 5,240 of 6,669 assignments attempted, retaining 5,226
usable outcomes, up 458 in thirty minutes. There are 1,429 unstarted assignments
and the separate 67-input allocation gap. Haiku totals remain 2,217 local and
1,508 hosted. Console HTTP is 200; no credit-exhaustion response was observed.
Luna's new missing answer is a reported 4,096-token reasoning-only completion,
not an HTTP error or discarded visible text. Its exact failed row and costs
remain retained. The reviewed continuation covers 570 untouched inputs and
preserves 47 saved responses without changing the 4,096-token request condition
or adding an automatic answer retry. Opus recovery preparation and final
local/Haiku judging remain unfinished.

11:04 UTC observation: 4,572 of 6,669 selected assignments attempted, with
4,560 usable outcomes. The thirty-minute increase is 258 attempts and 257 usable
outcomes. There are 2,097 unstarted assignments and the separate 67-input
selection gap. Local/hosted Haiku totals remain 2,217/1,508; recorded Haiku
cost remains USD 5.308997. No provider credit-exhaustion response was observed.

The operator reaffirmed one precomputed campaign budget, without partial batch
allowances. The old continuation cap still reflected predecessor maximum-cost
holds and stopped OpenAI before HTTP despite remaining campaign capacity.
The corrected execution uses the original pool ceilings across all thirteen
existing ledgers. It counts reported charges and complete reported-token upper
bounds; unknown bills remain unknown. It changes no input selection, old plan,
physical-attempt ordinal or settlement. It does not allocate new money or create
another financial slice. At the handoff, tracked OpenAI usage was USD 11.367865
against the original USD 24 ceiling. This is not an account-credit balance.

The scoped continuation reviewed 101 pre-HTTP-stopped jobs: 945 inputs had not
been sent, while 50 saved responses remain reusable. Two OpenAI workers resumed
under the unchanged target implementation. Collection remains incomplete.
Source 8c46c93/020ef86 passed twelve focused campaign/precalculated budget checks
and a removed-fix regression on the rig. Explicit output-forecast updates also
no longer reintroduce maximum-cost holds (419ef06, one focused and removed-fix
check). Budget exhaustion and tracked campaign ceilings still govern spending.

DeepSeek input `bec4426a3a7bf0f20e948a63150f3936ff89a6273892b27b91bc580701bf56b2`
returned no visible answer after 16,384 reported reasoning tokens. The operator
explicitly requested one rerun. That rerun uses 32,768 output tokens, with the
same delivered input and unchanged reasoning setting. Its original failed row
and charge remain retained; the new generation is a separate condition requiring
its own local and Haiku judgments. It is not an automatic answer-retry policy
or a reason to repeat successful responses. The conservative per-physical-call
forecast is USD 0.132565, within the original DeepSeek ceiling. The rerun completed
with a visible answer, reporting 402 input and 30,045 output tokens. It is retained
as a separate direct adapter capture, not silently promoted into the predecessor
Runner grid. Its local/Haiku judgments and analysis publication remain pending.

Preparation exposed a generic 25,000-token configuration restriction. Source
cab59c4 permits the documented DeepSeek V4 output range while preserving all
explicit campaign defaults. Four focused configuration/request tests and the
removed-fix check passed. The [provider reference](https://api-docs.deepseek.com/api/create-chat-completion/)
defines a maximum of 393,216 tokens; this is a supported configuration ceiling,
not the requested campaign allowance. No model default was raised to that value.
Source 3e80fca removes the arbitrary fallback for other generic API routes as
well. All 23 focused rig checks passed, including CLI and Build configuration
paths; restoring the fallback produced eleven targeted failures. The production
console is deployed at that revision with existing SQLite records preserved.
Configured output allowances and campaign spending ceilings remain unchanged.

09:34 UTC observation: 3,286 of 6,669 selected assignments started, with 3,277
usable outcomes. Thirty-minute gains are 342 starts and 343 usable outcomes.
The 3,383 unstarted assignments and separate 67-input allocation gap remain.
Haiku counts and cost are unchanged at 2,217 local, 1,508 hosted and USD 5.308997.
No provider credit-exhaustion response was reported; console HTTP is 200.
Next aggregate: 10:04 UTC.

An Opus parser error at 09:29 rejected thinking after visible text and opened
the shared stop. Source 383ba71 scopes output/transport investigation pauses to
the affected target rather than unrelated models. All 124 affected rig tests,
lint and the reversed-fix check passed. The successor launched at 09:41:47 UTC,
retaining completed work and all paid history. Opus remains separately paused
for the parser/data-retention investigation and exact recovery. Its saved error
lacks the original block sequence, stop reason and usage, so it is not called
an intrinsic model failure. Further judging still follows target collection.

Instruction update at approximately 08:52 UTC: execute the pre-calculated
inventory without per-request maximum-cost money holds. Track reported spending
and provider credit-exhaustion responses; retain unknown billing data without
calling it zero. The input selection, output limits and spending ceilings are
unchanged. In-flight calls can settle after a spending stop, so the tracking
policy is not a worst-case hard spending guarantee.

The implementation at ff9cb53 passed 185 focused rig tests in 14.12 seconds,
lint and a reversed-fix check. The handoff stopped at the next saved response,
not at the end of each long corpus. In-flight workers were not signaled.
Precalculated spending was enabled at 09:10:55 UTC. The successor reuses
responses and continues the full prepared queue, with judging afterwards.
The descriptions of maximum-cost reservation below record the earlier policy.

Current instruction, 11 September 2026: collect all remaining targets through
one continuous provider-parallel queue, then perform local and Haiku judging.
The financial slices below are historical. No new slice may wait for preceding
judgments. Preserve the full 6,736 requested evaluations, existing provider
ceilings, protected Haiku allocation, unknown charges and completed answers.
Use bounded concurrency per provider, not thousands of simultaneous HTTP calls.
Quota or exhausted credits on one provider must not idle independent providers.
Likewise, missing output or terminal transport investigation pauses its target
route, not other models sharing the program or billing provider.

At 06:54:36 UTC the unstarted fund-013, prepare-flow-014 and deferred-posthoc-006/007
controllers were retired without interrupting an in-flight call. Existing
Google target continuations retain their ownership and accounting.

The 09:04 aggregate records 6,669 selected assignments, 2,944 starts and 2,934
usable outcomes, gaining 141 starts and 139 usable outcomes in thirty minutes.
Haiku totals remain 2,217 local and 1,508 hosted assessments, with USD 5.308997
reported cost. Console HTTP is 200. Next aggregate: 09:34 UTC. A revised ETA
requires sustained continuous-dispatch throughput; the serial-batch estimate
is obsolete. No account credit-exhaustion outcome was reported in this snapshot.

Per-attempt money reservation and its preparation/execution integration passed
96 and 162 focused rig tests respectively, plus targeted reversed-fix checks.
The complete queued inventory does not commit every maximum output upfront;
each physical request still reserves its maximum cost immediately before HTTP.
The separate hosted response-collection scope pauses before local judge load.
Materialization of all 3,830 remaining fixed inputs completed at approximately
07:43 UTC. It retained 79 already completed replay files through the handoff.
Counting resumed at 07:55 UTC across all five providers, with two workers per
provider and reuse of saved count receipts. All sixteen programs are prepared.
Continuous collection issued 42 requests and saved 41 usable outcomes before
a temporary OpenAI reservation shortage incorrectly opened a shared stop.
The provider-scoped correction and checkpoint reuse passed focused rig checks.
The controller restarted in tmux at 08:50 UTC, retaining nine complete jobs and
all saved responses. One interrupted DeepSeek transport prefix remains separate
pending recovery; it does not block independent jobs. Local and Haiku judging
follow target collection. The older 67-input whole-cluster
allocation shortfall remains open, not silently discarded or counted complete.

The full-inventory path now resolves a selection once across its corpora and
reuses immutable budget-slot mappings. Mutable spending reservations remain
current on each paid request. Token-count cache locks are per request: distinct
requests can count concurrently, while identical requests share one saved
result. These changes passed focused rig tests and reversed-fix checks
(RA-490). They do not alter selected inputs, response limits or provider costs.

## Historical execution snapshots

Status update, 11 September 2026 at 06:34 UTC: the requested program is
expanded from 6,541 to 6,736 target evaluations by the additional frontier
selection below. The added 195 evaluations have counted requests and validated
replay files. Twenty Fable evaluations and their judging are complete;
another 27 additional assignments are funded, and 148 remain unfunded.
The operator's latest reported balances and the
existing USD 114 cumulative ceiling are unchanged. Frontier coverage takes
priority over adding further lower-cost groups.

The 06:34 aggregate records 2,734 started assignments and 2,727 usable
outcomes from its 2,812-input funded snapshot, gaining 23 starts and 24 usable
outcomes in thirty minutes. Six failures, one unsettled Google request and
78 unstarted Google inputs remain in that snapshot. Haiku totals are 2,198
local and 1,492 hosted assessments, including eighteen and seven invalid
verdicts respectively, with USD 5.272464 reported cost. Console availability
is HTTP 200; no shared stop or provider credit-exhaustion marker is present.
The next aggregate is due at 07:04 UTC. The ninth slice is complete: 95 usable outcomes
and one exhausted Opus overload outcome, with 73 eligible hosted Haiku
assessments and 201 new matching-local assessments. The tenth slice's twenty
additional Fable targets and judging completed by 05:42, including 55 new
local assessments with one invalid verdict. The eleventh slice's 78 targets
and both judging stages are complete, including 153 new matching-local Haiku
assessments. Twelfth funding completed at 06:34:01 UTC, just after the aggregate
selected its sources, adding 27 frontier inputs for 2,839 funded assignments.
The full requested expansion still depends on quota and subsequent
funding; the unfunded remainder is not claimed complete.

The ninth interruption was an Opus HTTP 529 `overloaded_error` after four
transport attempts, not HTTP 400 or `cyber_policy`. Its missing output and
uncertain charge remain retained without a fifth attempt. The continuation
preserves eleven Opus, nineteen Kimi and twenty-two DeepSeek outcomes and
resumes the 44 unissued inputs. Opus has issued new requests. DeepSeek's first
continuation found a local stop record left by the shared outage before its
next monetary reservation. The corrected checkpoint reuses that held logical
slot, still requires the ordinary paid reservation, and leaves historical
counters unchanged. Its focused real-slot and reversed-fix checks passed on
the rig; the separate DeepSeek continuation was launched at 04:53 UTC.
The ninth judging workers subsequently completed by 05:18 UTC.
No completed answer or exhausted transport request is scheduled for repetition.

Fable, Opus and Kimi completed all 18, 29 and 19 eighth-slice inputs.
DeepSeek retained 35 of 59 outcomes before one request exhausted its 16,384
output tokens entirely on reasoning, leaving no visible answer. This is not
HTTP 400, a transport failure or an explicit provider policy refusal. Its
failed output, token usage and unknown-charge reservation remain retained.
The reviewed continuation starts only the 24 unissued inputs, preserving the
same generation condition and giving the failed answer no paid answer retry.
It also resumes the interrupted output-specific and matching-local Haiku
judging. New failures still use the ordinary investigation stop. The recovery
completed at approximately 04:02 UTC, retaining all 59 DeepSeek outcomes:
58 usable answers and the original missing output. No completed target was
repeated. All four target routes and both judging stages of this slice are
now complete, including 273 new matching-local Haiku assessments and 56
eligible new hosted-output assessments.
Explicit OpenAI HTTP 400 `cyber_policy` remains an observed refusal that does
not stop subsequent inputs. Other HTTP 400 causes are not inferred from it.

The ninth slice was funded at 04:13:07 UTC for 96 unchanged non-Google requests:
Opus 27, Kimi 19 and DeepSeek 50. Its 47 Google requests are deferred, not
discarded or skipped by the next input prefix. The partition reused exact
request counts without HTTP. Funding waits for eighth-slice target and both
judging terminals, then checks actual remaining capacity while still reserving
the sixth and seventh pending work. It does not wait for Google's quota before
considering independent providers. Earlier post-hoc judges now remain queued
until their own Google outputs are ready and run one at a time. Ninth-slice
hosted and matching-local judging run sequentially, maintaining at most two
Anthropic requests including the older judge. Focused scheduling and reversed
dependency checks passed on the rig. No paid process was stopped by this
queue handoff. The initial 56-request DeepSeek reservation exceeded remaining
capacity by USD 0.216182. A no-call partition deferred six requests and their
eighteen newly matching local judgments, preserving whole input clusters and
the exact request contents. Its protected plan reserves 96 target attempts,
96 prospective hosted Haiku assessments and 201 new matching-local Haiku
assessments. At that funding snapshot, dispatch and both judging controllers
were live; funded starts must remain distinct from actual responses. Total
funded inputs then stood at 2,714.

The tenth slice has prepared the first twenty extra Fable inputs:
eleven text and nine image inputs, with USD 8.263490 maximum target exposure.
It reuses already counted requests and keeps the other nineteen extra Fable
inputs pending. Its inputs match 91 existing local answers, of which 55 need
new Haiku assessments. Funding completed at 05:22:54 UTC after the ninth target
and judging terminals; targets and both judging stages subsequently completed.
Every new hosted output receives its own eligible local and Haiku assessment.
Only judgments of the identical retained local answers may be reused.

The following original-input slice is queued behind the tenth funded
selection, with prospective caps of Opus 30, Kimi 19 and DeepSeek 40.
Whole-cluster selection, request counting and cumulative funding still apply;
those caps are not executed quantities. At 05:46:35 UTC the resulting eleventh
slice was funded for Opus 23, Kimi 16 and DeepSeek 39, with 153 new matching-local
Haiku assignments. Its targets and both judging stages subsequently completed.
The independent additional
Fable prefix must not move the original model-input prefixes. The queue uses
the existing preparation, materialization, counting and funding commands,
including local and Haiku judging, without altering requests already issued.

The next extra-frontier preparation waits for that eleventh selection to be
funded before binding its predecessor. It selects Fable's remaining nineteen
inputs plus the same first four extra image inputs for Astra and Sol. Those
four inputs already have Fable outputs and retained local counterparts. Exact
whole-cluster cuts and separate measured jobs are available in this extra
block; this does not skip or replace the unfunded original Astra prefix.
The cached maximum quotes are USD 7.867030 for Fable and USD 2.359491 for the
combined OpenAI targets, plus Sol's USD 1.20 execution allowance. All 27 request
counts are reusable without HTTP. Preparation must verify no repeated
model-input pair and preserve the independent original prefixes. Funding
still waits for all preceding target and judging terminals and protects both
pending Google slices. Each new hosted output needs its own local and Haiku
judgment; only judgments of identical retained local answers can be reused.
The twelfth preparation completed by 05:49 UTC for all 27 unchanged requests.
They match sixty retained local answers, of which nineteen need new Haiku
assessments. Its funding completed at 06:34:01 UTC after the eleventh targets
and both judging stages. The dispatcher and judging controllers are live;
funding alone is not a generation count. The original program's unfunded
inputs remain pending.

At 06:09 UTC a thirteenth preparation was queued for 39 extra Opus inputs,
using the same 26 text and thirteen image inputs as the extra Fable block.
Its unchanged cached maximum target quote is USD 6.068070. Preparation waits
for twelfth funding before binding the exact preceding selection; thirteenth
funding then requires the twelfth target and both judging stages to finish.
No thirteenth call is funded or issued by this queue. Local-answer reuse must
be verified from that preceding selection, while every new eligible Opus
output requires its own local and Haiku assessment. This queue changes neither
the 6,736 requested assignments nor the cumulative provider ceilings.
Preparation completed at 06:34 for all 39 unchanged requests, matching 125
existing local answers with zero newly assigned local Haiku slots. Their
completed judgments must still be verified at funding after the twelfth
judging stage. The thirteenth funding controller is live and waiting.

A following original-input preparation is queued as slice fourteen, behind
thirteenth funding, with prospective caps of Opus 30, Kimi 19 and DeepSeek 40.
It uses the existing whole-cluster selection, materialization, request counting
and cumulative funding workflow. These are preparation caps, not promised
executed counts. The original prefixes remain independent of additional
frontier inputs; matching local and new hosted-output judging are included.
Paid execution still waits for preceding target and judging terminals and
available capacity. No completed input is selected again.

The historical RR prefix reader now forwards the optional artifact-checking
mode to its original-source subprocess. Ninety-three focused rig tests, a
reversed-fix test and a real two-cell, 200-response prefix check passed.
The checked runtime handoff changes no generation revision or retained data.

The completed-route comparison through slice eight is published at
`/stats/job/hosted-expansion-comparison-through-008-65ac4d6-20260910-completed-routes`.
It contains 1,370 hosted and 1,547 matching local outputs on 418 distinct inputs,
with 4,566 comparison links. The two unfinished Google routes remain explicitly
excluded. No target or judge was called by publication. HTTP 200 and chart markup
were verified; the browser connector has no available browser, so visual QA is
not claimed. The actual page is 7.4 MB with 12,698 table rows. The bounded
presentation correction at a833b50 passed thirty focused rig tests, a
reversed-fix check and actual-report rendering. The comparison fragment falls
from 7,385,885 to 147,085 bytes, with all outcome, contrast and token details
available through separate paged links. Full-population aggregates and the
retained report are unchanged. This correction is queued with operational costs
for post-collection deployment; the currently served page remains unchanged.

The completed-route comparison through slice ten is now published at
`/stats/job/hosted-expansion-comparison-through-010-65ac4d6-20260910-completed-routes`.
It joins 1,450 hosted and 1,768 matching local outputs across 468 distinct
inputs, retaining 4,907 comparison links rather than treating those links as
independent questions. The sixth and seventh unfinished Google routes remain
explicitly excluded. HTTP 200 and chart markup were verified; no target or
judge was called and browser visual QA is not claimed. This is a completed
snapshot, not completion of the full expansion. The earlier publications
remain retained.

Earlier 03:12 observations follow.

The 03:04 aggregate records 2,459 started assignments and 2,453 usable
outcomes from 2,618 funded inputs. The eighth Kimi route is complete for all
nineteen inputs. DeepSeek has twenty-four durable outcomes, one unsettled
request and thirty-four unstarted inputs. Four terminal failures remain across
the expansion; the other unsettled request is Google. Haiku totals remain
1,516 local and 1,314 hosted assessments, with USD 3.905620 reported cost.
Judging is queued, not actively issuing requests. Console availability is
HTTP 200; GPUs are idle and no provider credit-exhaustion stop is recorded.
The next aggregate is due at 03:34 UTC.

The two earlier Haiku controllers were waiting solely for Google results but
still consumed both Anthropic scheduler slots. Their five and four completed
route analyses were verified, together with zero in-flight judge requests and
their actual idle process owners. At 03:11 UTC they were replaced by visible
queued successors that consume no HTTP slot and resume automatically after
the eighth targets and both judging stages finish. The successors skip all
completed analyses. Eight focused dependency cases and an omitted-dependency
mutation passed on the rig. No paid request was stopped or repeated. The
eighth Fable and Opus workers are now active alongside DeepSeek, with at most
two Anthropic requests. Existing Google owners and every monetary hold remain
unchanged. This supersedes the earlier conservative idle-slot wait below.

Earlier 02:38 observations follow.

The eighth slice was funded at 02:37:50 UTC for 125 non-Google inputs:
Fable 18, Opus 29, Kimi 19 and DeepSeek 59. Funded assignments now total
2,618. The slice reserves 125 prospective hosted Haiku assessments and 273
new matching local assessments, within USD 8.025068 of protected judging
capacity after both earlier unfinished slices' worst-case continuation.
All 125 exact request-count receipts were reused with no new HTTP request.
Shared dispatch is live; this funding result alone is not a generation count.

The same eighth selection's 100 Google inputs remain deferred. The ninth
prospective slice has been rebased to start at the correct unchanged prefixes,
so those inputs cannot be skipped. Its 149 exact count receipts were reused
offline, and its funding successor waits for all three preceding slices'
targets and judgments. It remains unfunded. The older 152-input ninth preview
is superseded, not silently counted as completed work.

Two-parent monetary reservations acquire locks in chronological order and
release them before HTTP. Focused rig checks covered both holds, changed
forecasts, unrelated budgets, duplicate/reversed parents, closed-parent
reporting and actual reversed-fix cases. Only the unfunded eighth and ninth
waiters were stopped. Existing Google workers and paid responses were not
touched. Earlier Haiku workers retain their provider slots; the eighth local
judge is queued until those judges and the eighth Anthropic targets finish,
preserving the two-request Anthropic ceiling.

The 02:34 aggregate recorded 2,415 started assignments and 2,410 usable
outcomes out of the then-funded 2,493 inputs: fifteen newly started inputs
and sixteen newly durable outcomes in thirty minutes. Four terminal failures,
one unsettled Google request and 78 unstarted Google inputs remain. Haiku
assessments total 1,516 local and 1,314 hosted outputs, with USD 3.905620
reported judging cost. Console availability is HTTP 200; GPUs are idle.
There is no recorded credit-exhaustion stop. The next aggregate is due at
03:04 UTC. The full-program finish time remains dependent on Google's daily
quota and subsequent cumulative funding, not on GPU inference.

The completed-route comparison through slice seven is now published at
`/stats/job/hosted-expansion-comparison-through-007-65ac4d6-20260910-completed-routes`.
It contains 1,314 hosted and 1,351 matching local outputs, 378 distinct inputs
and 4,324 comparison links. The sixth and seventh Google routes are explicitly
unfinished and excluded. All thirteen observed hosted models still share only
three eligible judged inputs; pairwise support is reported separately, and
links are not independent observations. HTTP and comparison/chart markup
checks passed. Browser visual QA remains unavailable. Publication made no new
target or judge call.

Earlier 02:17 observations follow.

All 120 non-Google seventh-slice inputs are now complete, with their required
local and Haiku judgments: Fable 15, Opus 23, Kimi 15 and DeepSeek 67. Its
72 Google inputs remain queued behind the sixth Google route's daily quota
wait. Explicit OpenAI HTTP 400 `cyber_policy` responses are retained provider
policy outcomes and do not stop subsequent inputs or receive answer retries.
The present Google wait is HTTP 429, not that HTTP 400 condition.

The 02:04 aggregate recorded 2,400 started assignments and 2,394 usable
outcomes from 2,493 funded assignments, with four terminal failures and two
then-unsettled requests. It gained 105 started inputs and 104 usable outcomes
in thirty minutes. DeepSeek subsequently completed its remaining sixteen
inputs. The snapshot retained 1,516 local and 1,261 hosted Haiku assessments,
with USD 3.839137 reported judging cost. Console availability was HTTP 200;
both GPUs were idle, as expected for the active hosted collection. The next
aggregate is due at 02:34 UTC. These snapshot counts are not later completion
counts and are not live provider credit balances.

The eighth slice has 225 counted inputs; the ninth has another 152 counted
inputs. Neither is funded. A read-only review protecting every remaining
attempt in both unfinished slices six and seven found that the eighth slice's
non-Google target quotes fit, but essentially no additional Google capacity
is available while reserving the worst-case Google continuation. This is
reserved exposure, not spent credit. Additional allocation still requires
complete judging reservations and cumulative provider ownership; no money was
allocated by the review. A comparison of completed routes through slice seven
is building, explicitly excluding the unfinished Google routes. It makes no
target or judge calls and does not declare the full expansion complete.

Earlier 01:34 preparation and recovery observations follow.

The seventh slice's funding successor completed for 192 inputs. Its
120 non-Google inputs can advance independently; its 72 Google inputs wait
for the preceding Google route to finish. Only the unfunded waiting process
was replaced. The active Google request, its retry counter, retained answers
and existing ceilings were untouched. The pending sixth-slice liability now
reserves every remaining permitted attempt, including unfinished judging;
new reservations hold that preceding budget stable while checking the bound.
Eleven focused rig tests, reversed-fix checks and an actual retained-budget
integration check passed. The actual forecast leaves USD 18.682230 protected
for new Haiku judging. All seventh-slice target quotes fit. The dispatcher
started at 01:24:57 UTC and is preparing its shared source context; new target
responses are not yet claimed. The slice's 510 exact local answers already
have retained Haiku assessments, so its local assessment handoff is complete
with zero new judge calls. New hosted outputs still need their own judgments.

The first seventh-slice dispatch stopped its four non-Google workers before
any paid reservation: the launcher compared the whole runtime-utility file
with an older engineering checksum after unrelated helpers were added. The
unchanged acquisition function was isolated, passed focused no-download and
concurrency regressions, and the zero-call dispatcher was replaced at 01:34:20
UTC. Existing model verification was not repeated. At the 01:34 aggregate,
2,295 of 2,493 funded assignments had started, retaining 2,290 usable outcomes,
four terminal failures and one unsettled Google request. There were 198 funded
inputs still unstarted and no new response in the preceding half hour. After
the new allocation and explicit pending-work holds, uncommitted target
capacity is USD 5.326100 Anthropic, 5.232875 OpenAI, 7.173291 Google,
2.301066 Kimi and 0.302763 DeepSeek; protected uncommitted Haiku capacity is
USD 15.742326. These are conservative campaign allocations, not live credits.
New paid execution remains to be confirmed after the corrected preparation.

The first five funded slices have all 2,107 assigned target inputs
attempted and all required local and Haiku judging complete. They retain
2,106 usable answers or explicit policy outcomes and one unclassified HTTP
400. Its seven neighboring usable answers are included through separately
attributed scoring; the native partial grid remains partial. The sixth slice
needs no new local Haiku calls because its exact matching local answers were
already assessed; the funding handoff binds those existing verdicts. New
hosted outputs still require their own local and Haiku judgments.

At the earlier 23:34 UTC snapshot, the sixth slice had attempted 124 of 194 assignments. Gemini exhausted its
three transport retries on HTTP 429; the shared paid stop then interrupted
three unrelated provider routes. Its failed response and four physical
attempts remain retained, with unknown charges still reserved. Recovery
continues the 70 unissued inputs from native checkpoints, without repeating
saved responses or granting a fifth attempt to that exhausted request.
An explicit policy-rejection HTTP 400 remains a different, legitimate outcome.

Later quota diagnosis identified Gemini Pro's 250-request daily project limit.
The provider supplied a 781-second retry delay in its RPC error body; the old
adapter ignored that delay. The correction passed twenty focused rig tests,
an actual retained-error check and a reversed-fix check. Three exhausted Google
requests remain missing responses, with their charges still unknown. Only
unissued inputs continue after the reported retry window. This is not a credit
top-up or a retry of an exhausted request. The remaining non-Google routes run
independently. A checkpoint-reader bookkeeping error after successful Opus,
Kimi and DeepSeek jobs was also repaired from their finalized files, without
repeating their calls. A further 225-input prospective slice is selected from
the unchanged prefixes; all 225 requests are now counted, but it is not funded.

At 00:34 UTC, the six funded slices retain 2,295 started assignments from
2,301 planned inputs, with 2,290 usable outcomes, four terminal failures and
one unsettled Google request. Six Google inputs remain unstarted. All five
non-Google routes in the sixth slice are complete with their required judging;
DeepSeek completed all seventy inputs successfully. Google alone is waiting
on request quota. The next 192-input and 225-input slices have counted requests
and queued funding controllers. That snapshot used whole-slice closure;
the seventh-slice pending-liability correction above supersedes that wait
without releasing money needed by the unfinished sixth slice. The eighth
slice still waits for predecessor completion and fresh capacity checks. The full
6,736-input scope has not been replaced by these funded slices. The earlier
15-30 minute estimate for closing the sixth slice no longer holds, and the
whole-program completion time remains uncertain while Google is quota-limited.

The current expansion retains 1,516 local-output Haiku assessments and 1,234
hosted-output Haiku assessments, including fourteen and seven invalid verdicts.
Their reported cost is USD 3.820234. Uncommitted target capacity within the
existing campaign ceilings is USD 15.083930 Anthropic, 5.232875 OpenAI,
11.847553 Google, 4.163529 Kimi and 4.874205 DeepSeek; protected uncommitted
judging capacity is USD 27.323766. These are operational allocations, not live
provider balances. The cost-view repair has passed focused rig, actual-ledger
and reversed-fix checks at c4221e4/4bda20c. Production publication remains
scheduled after collection. The matched comparison through the five fully closed
slices is published at
`/stats/job/hosted-expansion-comparison-through-005-65ac4d6-20260910`:
1,165 hosted outputs and 1,346 matching local outputs on 375 distinct inputs,
with 3,908 comparison links. Links are not independent questions. All thirteen
observed hosted models share only three eligible judged inputs in this snapshot;
pairwise input support is retained, and unmatched model averages must not be
ranked as though every model answered the same complete corpus. Publication
made no target or judge call. HTTP and server-rendered comparison/chart checks
passed; browser visual QA remains pending because no browser connection was
available.

Thirty-seven completed OpenAI responses released USD 3.457155 in excess
maximum-output reservations using reported token totals and the already-funded
cache-write tariff. These remain conservative bounds, not known provider bills.
Actual charges, unknown HTTP-error exposure and all ceilings are unchanged.
The fractional-price correction is verified, and its final reconciliation
completed after the sixth funding handoff finished reading predecessor ledgers.

Historical fifth-slice status: the first four funded slices
have completed target collection and all eligible local and Haiku judging,
covering 1,551 assigned inputs. The fifth slice contains 556 funded inputs;
its controller correction preserves the original diagnostic/measured roles
and repeats no completed target call. Current transport receipts are reused
at the unchanged target runtime, while funding and reporting use their
separately verified maintained readers. Four Astra inputs were deferred from
this fifth slice, not removed from the campaign.

The earlier 586-input, lower-cost-first sixth slice was paused before funding
when the operator specified frontier-first execution. Its underlying 671-input
selection and all request counts remain available. Its replacement is counted
with 194 inputs: Fable 32, Opus 10, GPT-5.5 17, Gemini Pro 37, Kimi 28 and
DeepSeek 70. Maximum target reservations are USD 14.955195 Anthropic,
4.200633 OpenAI, 1.830200 Google, 3.470652 Kimi and 4.801825 DeepSeek.
No new token-count requests or generations were used to make this partition. Neither the
paused partition nor its 85 deferred inputs represents a reduced campaign
target. This replacement was funded at 23:13 UTC after the fifth slice's target
and judging work finished, and its independent provider routes are executing.
Its 689 matching local answers reuse their exact retained Haiku assessments;
new hosted answers receive new judgments. The next rebased slice has 211
counted, materialized inputs. A subsequent financial partition retains 192:
Fable 15, Opus 23, Gemini Pro 72, Kimi 15 and DeepSeek 67. Its funding controller
is queued, not yet allocated. Astra's 19 inputs remain pending: the 15-input
cluster exceeds current uncommitted OpenAI capacity, while its four-input
predecessor alone cannot satisfy the preparation helper's separate pilot and
measurement groups. This preparation limitation must not split a cluster or
silently remove either group. The queued allocation must fit all sixth-slice
liabilities, including the full reserved continuation of unfinished work.

Completed-budget closure released USD 10.868736 of never-issued Haiku
reservations from the first four slices. Actual charges and unknown-usage
holds remain unchanged. This is available judging capacity, not an increase
to any provider ceiling or a transfer into target-generation funds.

The added selection is genuinely outside the original allocations of its
five target models; it does not rename or repeat existing assignments. Every
new eligible output requires its own local and Haiku verdict. An existing
local answer's unchanged verdict can be reused, but a verdict cannot be
reused for a newly generated answer. Account credit is not automatically
uncommitted campaign funding, and counted requests are not funded calls.

Historical status, 10 September 2026 at 20:34 UTC: the first three funded slices have
finished target collection, local and Haiku judging and per-model analysis,
covering 964 assigned inputs. Across those slices, Haiku assessed 707 selected
existing local answers and 548 eligible hosted answers. The fourth slice is
funded and executing; the aggregate snapshot retains 1,180 attempted inputs
out of 1,551 funded inputs, with 1,178 usable outcomes. The recovered
target and local-judge controllers preserved completed checkpoints instead of
repeating their paid calls. Slices after the fourth remain unfunded; their simultaneous
worst-case reservations must fit the unchanged cumulative provider and judge
ceilings. Smaller financial slices may defer inputs to later prefixes, but do
not remove them from the requested campaign or change generation settings.
Historical preparation snapshots below are not current completion claims.
At 19:55 UTC the fourth unfunded slice was partitioned into 587 current inputs
and 68 deferred OpenAI inputs. It reuses the same questions, media, model
settings and 587 exact token-count receipts, without network calls. The
OpenAI maximum reservation falls from USD 14.152121 to USD 9.245201; deferred
inputs retain their place in the final shared prefixes. Local Haiku inputs
are restricted to matching answers for this slice. The fifth slice has since
been rebased and its 560 request counts reused without network calls.
Previously prepared sixth and seventh slices still require rebasing before
funding so that no deferred input is skipped. This is scheduling within the
original ceilings, not a
reduction of the requested campaign.
The Operational costs integration is scheduled after the interrupted hosted
campaign finishes, as specified in the execution order below.
This is a separate cohort
after [the original campaign](HOSTED_CAMPAIGN_PLAN.md) and
[the supplement, including Google](HOSTED_SUPPLEMENT_PLAN.md).

## Required quantities

### Completing the retained allocation gap

Following the 11 September all-provider allowance increase, fill the remaining
67-input rounding gap through the next complete source clusters: at least
14 Opus inputs, 8 Astra inputs, 12 Flash inputs, 16 Kimi inputs and 17 DeepSeek
inputs. Use the existing shared input order and generation settings. Opus and
Astra take their next original-prefix inputs, excluding the separate frontier
block; Flash continues after its completed 747-input prefix. Kimi and DeepSeek
continue their existing prefixes. The smallest necessary whole-cluster
overshoot is permitted and must be recorded before execution. This allocation
prioritizes frontier coverage within Anthropic/OpenAI and uses available Flash
capacity rather than adding to Pro's quota wait. It does not replace any
previous assignment or treat a failed output as an unissued input.

Every eligible new output requires local and Haiku judging. Reuse a local
verdict only for the same retained local answer; newly covered local inputs
need their own Haiku assessment. Publish exact shared-input intersections and
coverage, not an implication that unequal model prefixes are identical samples.
The 67-input gap remains pending until the actual selection and execution are
retained. Current spending thresholds are the all-provider update recorded
above, not the superseded per-slice reservations described in historical notes.

The actual 11 September selection requires 79 assignments: Opus 18, Astra 11,
Flash 14, Kimi 18 and DeepSeek 18. Its 12-input excess preserves complete
source clusters. Materialization reused 61 existing inputs and prepared the
remaining 18 from retained local source records. There are 381 matching local
answers, including 156 without an existing Haiku slot. Target collection and
both judging obligations remain pending. Evidence: hosted-gap-67-20260911.

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

## Additional frontier coverage

The operator requested more frontier data without increasing any provider
ceiling. Add the following identical block of 39 inputs to each of five
models. The block contains 26 text and 13 image inputs, selected in the
existing deterministic whole-cluster order without consulting answers or
verdicts. It follows the original prefixes of all five routes, so these are
195 new model-input assignments. Existing local collection supplies 125
matching answers; no new local target generation is required for this block.

| Model | Additional inputs | Retained output allowance | Maximum target reservation |
| --- | ---: | ---: | ---: |
| GPT-6 Astra | 39 | 8,192 | $16.148246 |
| Fable 5.1 | 39 | 8,192 | $16.130520 |
| Opus 5 | 39 | 6,144 | $6.068070 |
| GPT-5.6 Sol | 39 | 8,192 | $6.459295 |
| Gemini 3.1 Pro Preview | 39 | 4,096 | $1.949590 |
| Total | 195 | - | $46.755721 |

These are complete-request, maximum-output reservations, not expected bills.
The separate Sol execution allowance adds USD 0.30 per input before its
dispatch, from the same OpenAI pool. It is not included in the table.
All output settings remain unchanged; no token reduction is assumed.

Reserve up to USD 4.751360 for 320 Haiku assessments: one for each of the 195
new hosted outputs and each of the 125 matching retained local answers.
The final callable count excludes explicit outcomes with no answer text and
reuses only an already-judged, identical local answer. Those exclusions must
remain visible, not be reported as new verdicts. Each eligible hosted output
also receives its own local judgment. The matched comparison reports this
selection separately from the wider local population and includes per-model
coverage and the exact common-input intersection.

The revised requested provider totals are Anthropic 2,331, OpenAI 1,599,
Google 1,011, Kimi 565 and DeepSeek 1,230: 6,736 in this expansion and 8,677
assignments across all three hosted cohorts. These are assignments, not
independent questions or guaranteed successful answers. The original 67
whole-cluster allocation gaps remain unresolved and are not hidden by this
addition.

Execute affordable whole groups successively, prioritizing frontier routes
within each provider. The added target and judge maxima total USD 51.507081
before the Sol allowance; that amount cannot be reserved simultaneously
alongside all unfinished work. Reconcile completed usage between slices,
retain unknown exposure, and leave both judging obligations funded before
dispatch. The requested quantity is now part of the plan, while complete
funding remains conditional on actual cumulative capacity. Do not increase
ceilings or claim an unfunded remainder complete.

Rig evidence: `engineering/hosted-frontier-extension-quote-b04f997-20260910-r-inputs/`.
It retains the shared selection, 195 counted provider requests and their
quotes, with zero target generations and zero judge calls during preparation.
The matching replay files are prepared under
`engineering/hosted-frontier-extension-materialized-6425380-20260910-r-cap/`.
This step reused retained source records, not model outputs or verdicts, and
made no network calls. Final funding must recheck which of the 125 identical
local answers already has a Haiku judgment before reserving additional calls.

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

The 10 September planning balances totaled USD 151.06; retain them as the
baseline for the dated updates above. Preserve the earlier
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
At that historical snapshot, unknown charges and unused earlier judge commitments remained reserved, not
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
OpenAI's `cyber_policy` or `bio_policy`, are legitimate terminal outcomes and do
not stop the campaign. A previously successful parameter set does not establish
that every later HTTP 400 is a refusal: input size, media validity and other
request-specific causes must remain distinguishable by the retained error.
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

Earlier preparations included a USD 0.30 Sol Pro aggregate-work contingency per
unstarted input. Those recorded forecasts remain historical accounting; they
are not new funding slices or maximum-cost holds. The remaining fixed inventory
uses the one precomputed campaign ceiling and cumulative reported spending,
including complete token-based cost bounds. Preserve unknown exact charges and
the original paid outputs; do not retry an answer to repair accounting or enlarge
the provider ceiling. A forecast is not a guaranteed bound on provider model work.

Quota or output investigation on one model must not idle a distinct model with
available capacity. In the current Google continuation, the existing Pro work
occupies at most one provider worker; Flash may use the other. Once that Pro work
is terminal, both worker slots may serve the remaining queue. This changes only
scheduling, not inputs, generation settings, retry counts or the shared Google
spending ceiling. Check actual live ownership before replacing an idle dispatcher and
never terminate a paid request merely to hand off its queue.

A reviewed parser recovery keeps the original failed output and cost. It must
use the repaired adapter, the identical delivered input and request controls,
and the next actual physical-attempt ordinal. Completed responses are not
repeated. The recovery preserves the shared input population and output-specific
local/Haiku judging obligations; old cohort records are not rewritten. The
explicit DeepSeek 32,768-token rerun is a separate output condition, not a parser
repair or an automatic answer retry.

### Campaign sequence

1. Verify the completed-family baseline - done, 10 September at 08:54 UTC.
2. Finalize new retained inputs and count all matching local judging obligations;
   the full-pool availability preview completed at 09:04 UTC.
3. Quote actual requests, reconcile outstanding attempt charges and precompute
   the complete campaign spending forecast against the shared provider limits.
4. Execute target collection on the rig in tmux, preserving checkpoints.
5. Complete local and Haiku judging, then publish the separate Stats report.
6. After the interrupted hosted collection finishes, reconcile the console's
   Operational costs tab with the retained target and judging ledgers. Show
   reported spending, unknown charges, uncertain charge exposure and remaining budget
   separately. Missing cost integration must not appear as zero spending.
   Include all campaign cohorts without double-counting resumed jobs or source
   aliases; verify the UI totals against the same billing records, with no new
   paid calls.

Reuse installed runtimes and the tested deployed adapters. Do not repeat
Windows tests, framework installations or completed readiness work. Register
new preparation and execution jobs in the console. While a worker is active,
provide aggregate reports at 30-minute intervals: target/answer/judging counts,
progress since the last report, remaining funded work, budgets and an ETA
based on observed throughput. No generation ETA is established before launch.

Audit evidence is retained on the rig and in the ignored thesis verification
directory. Operational scripts and campaign data must not be committed to Git.

Operational continuation must reuse unchanged source validation and retained
answers. Full model/artifact checksum revalidation is optional and disabled by
default. Source-context reuse is invalidated by changes to its observed inputs;
paid budgets are never reused from a cached authorization. Validate the shared
source population once before dispatching compatible API workers, and keep
their paid reservations independent. The active dispatcher validates one
shared source context before forking Linux workers, which inherit its
read-only cache. Independent routes retain their own error records; a failed
transport-probe derivation must not discard a saved provider-policy outcome
or prevent unrelated funded routes from completing. A replacement transport
probe must use an unissued assigned input, preserve the original outcome and
retain the same cumulative spending checks.

The initial 79-input gap selection stopped before generation because the Kimi
and DeepSeek selections each contained only one source cluster. Extending each
by one retained input fixed that allocation without relaxing the measurement
requirement. The corrected 81-input addition completed target collection at
approximately 16:36 UTC on 11 September, with 81 usable answers or policy
outcomes and no repeated completed response. It reused previous request counts
and completed transport observations across independent providers. It includes
Opus 18, Astra 11, Flash 14, Kimi 19 and DeepSeek 19 inputs. Both local and
output-specific Haiku judging remain required.
The fourth-campaign allocation is in HOSTED_BALANCED_CAMPAIGN_PLAN.md and uses
the same remaining account credit, not independent new funds.

### UI execution and publication

The whole-flow contract is in [Campaign workspaces](../docs/CAMPAIGN_WORKSPACES.md).
Build defines a campaign or standalone run; local/API/mixed follows from the
selected models. The running campaign must become configurable and manageable
through those same controls, including input selection, model settings,
provider-parallel collection, retries, budgets and both judging stages. Import
current and historical retained work without new generations. Publish progress,
outcomes, costs and output-specific judgments as durable data changes, keeping
historical and corrected conditions available. The current scoped index refresh
is not the full combined campaign import or a completed automatic UI workflow.
