# Third hosted campaign: provider-scaled expansion

Status, 10 September 2026: requested quantities and a full-pool input
availability preview are verified on the rig. Final selection, pricing and funding are pending;
no third-campaign target or judge call has started. This is a separate cohort
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
Kimi's numeric rate table was not exposed in the retrieved page; the final
quote must verify it rather than silently treating an older rate as current.

DeepSeek currently publishes peak/off-peak prices and announces that the
V4 Pro alias will route to V4.1 Flash from 14 September 2026 at 04:00 UTC.
Do not pool outputs across that identity change. Complete the retained Pro
condition before that boundary or record the replacement as a separate model
condition. Off-peak savings are conditional, not guaranteed funding.

## Selection, judging and comparison

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

Publish this third cohort separately in Stats, with local/Haiku comparisons,
coverage, model stability, output allowance, actual token usage, truncation,
framework/arm/corpus composition and spending. Show independent input support
separately from source aliases and matched comparison links.

## Execution order and reporting

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
