# Fourth hosted campaign: balanced matched coverage

Status: requested on 11 September 2026; allocation and exact request quotes in
preparation. No fourth-campaign target call is claimed. The third campaign,
its remaining Google work, its 79-input completion and all outstanding judging
continue independently.

## Available credit and obligations

The latest operator balances are Anthropic USD 49.01, OpenAI 14.50, Google
17.46, Kimi 4.23 and DeepSeek 3.51: USD 88.71 total. These are shared remaining
account credits, not fresh money on top of the previous campaign's allowances.
Preserve the full dated balance history in HOSTED_EXPANSION_PLAN.md. Deduct
post-snapshot reported spending and outstanding target/judging obligations
once when quoting this campaign. Unknown costs remain explicitly unknown.

Haiku judges both eligible hosted outputs and the corresponding selected
local answers. Its cost comes from the same Anthropic account as Fable, Opus,
Sonnet and Haiku target generations. Every eligible hosted output also receives
local judging. Reuse a verdict only for the exact unchanged output and judging
condition. Equal inputs from different models require different verdicts.

## Balanced selection

Count distinct assigned model-input conditions, separately reporting attempts,
usable answers, provider-policy outcomes and missing responses. Source aliases,
HTTP retries and comparison links cannot inflate input support. The coverage
baseline is fixed before looking at new outcomes. Include earlier cohorts only
through their deduplicated input records; raw legacy assignment counts are not
an independent-sample baseline.

Prioritize models with the smallest completed distinct-input coverage. Choose
a common set of retained local inputs for the cross-model comparison, followed
by nested extensions for models whose measured cost permits more coverage.
Fill each model's missing coverage within that common set before widening its
sample. Preserve the existing seeded whole-cluster order and modality support;
do not choose questions according to observed answers or security verdicts.
Text-only models enter the text comparison. Multimodal comparisons use the
same retained images and questions among compatible models.

The intended result is proportionate coverage, not equal expenditure and not
an assertion that unequal sample sizes are identical. Publish the common-set
comparison separately from the larger nested sets, including exact per-model
input support and missingness. Budget-limited and quota-limited remainders
must stay visible. A full campaign means the complete chosen assignment and
its judging, not every available corpus row regardless of cost.

## Allocation before execution

1. Reconcile the finished and already-assigned distinct inputs for all thirteen
   existing API model routes. Keep the 267 pending Google Pro assignments and
   the 79-input third-campaign completion separate from genuinely new work.
2. Use actual retained input/output usage and configured effective-dated prices
   to estimate cost by model. Report mean usage, a conservative usage scenario
   and maximum output allowance separately. Do not quote a short average answer
   as a guaranteed maximum bill or assume a refusal is unbilled.
3. Allocate common coverage to the least-tested routes first, then proportionate
   nested extensions. Quote the exact chosen requests and both Haiku populations
   before publishing the executable allocation. Keep tested generation settings;
   changing output allowance creates a declared separate condition.
4. Run independent providers concurrently, with at most two network workers per
   provider. Local and Haiku judging may run alongside independent target queues
   or afterwards; judging must not serialize otherwise independent providers.
5. Use the existing three HTTP retries, valid Retry-After delays and provider
   funding stops. There are no automatic paid answer retries. Retain explicit
   provider-policy refusals; investigate other HTTP 400 errors rather than
   assuming all are security outcomes.
6. Publish this cohort under the same API campaign workspace, with cohort filters,
   costs, token usage, truncation, stability, local/Haiku agreement and matched
   figures. Retain originals and earlier cohorts. No synthetic output or human
   judgment is permitted to stand in for missing evidence.

## Reporting

Keep the thirty-minute aggregate cadence. Report planned, issued and completed
counts separately; account credits separately from campaign-attributed costs;
remaining judging work; and an ETA based on observed throughput and actual
quota waits. Do not wait for the next report to recover a genuine interruption.

The first allocation table is pending the retained-usage calculation. No new
amount has yet been assigned from the USD 88.71 account snapshot.
