# Hosted subset and Haiku re-adjudication campaign plan

Status: prospective follow-on, 1 September 2026. This document authorizes no
paid call. Start only after the all-local campaign seals its Phase 7 inventory.
Run every controller on the rig in a named tmux session.

This is a separate campaign, not a local-campaign phase and not product
semantics. It compares bounded hosted-model conditions on content-bound subsets
of inputs already used by the local campaign, then applies one selected Haiku
judge condition to hosted and local retained outputs.

## Fixed design

- Sampling policy: seeded_pseudorandom_whole_cluster_prefix_v1.
- Sample seed and attack seeds: 0.
- Source, converter, policy, prepared-attack, rendered-media and framework
  identities: the exact Phase 7-validated local identities.
- A hosted row is eligible only if its rendered input identity occurs in the
  sealed local campaign and its hosted route declares that modality.
- Incompatible modalities are N/A. They are never captioned or transformed.
- Paid targets and Haiku judging use exactly one application attempt.
  target_answer_retries is 0 and provider SDK retries are disabled.
- Missing responses remain selected-population and stability evidence but
  receive no Haiku call.

For local arm a, let L_local(a) be its sealed limit and L_t the hosted target
limit. Hosted selection uses the first min(L_t, L_local(a)) clusters from the
same seed-0 permutation and retains every sibling row. Its create-only selector
binds the local selection artifact, converted-corpus digest, ordered clusters,
rendered-input digests and hosted subset digest. Set inclusion must validate
before any provider call.

| Hosted target condition | Per-arm limit | Modalities |
|---|---:|---|
| Claude Fable 5 | 1 | registry/canary intersection |
| Claude Opus 5 | 3 | registry/canary intersection |
| Claude Sonnet 5 | 5 | registry/canary intersection |
| Claude Haiku 4.5 | 10 | registry/canary intersection |
| GPT-5.6 Sol | 2 | registry/canary intersection |
| GPT-5.6 Terra | 5 | registry/canary intersection |
| GPT-5.6 Luna | 20 | registry/canary intersection |
| GPT-5.5 | 1 | registry/canary intersection |
| Kimi K3 | 3 | text; image only after an exact image canary |
| DeepSeek V4-Pro | 20 | text only, reviewed off-peak window |

Limits were fixed before hosted outputs. Exact no-call projections or token
canaries may reduce a limit before execution to satisfy the monetary gate.
Observed answers or judgments may never change a selection.

## Budget contract

The complete follow-on, including readiness probes, diagnostic canaries,
targets and Haiku judging, may use at most 50 percent of each configured budget.

| Provider | Configured | Follow-on maximum | Planning partition |
|---|---:|---:|---|
| Anthropic | USD 100 | USD 50 | targets/probes at most USD 32; Haiku at most USD 14; margin at least USD 4 |
| OpenAI | USD 40 | USD 20 | targets/probes at most USD 19; margin at least USD 1 |
| Moonshot | USD 15 | USD 7.50 | targets/probes at most USD 7; margin at least USD 0.50 |
| DeepSeek | USD 10 | USD 5 | off-peak targets/probes at most USD 5 |

Haiku receives at most 2,000 selected local outputs and 2,000 selected hosted
outputs. At the planning assumption of 2,000 input and 256 output tokens per
judgment, 4,000 calls use 8.0 million input and 1.024 million output tokens and
cost USD 13.12 standard or USD 6.56 Batch. Exact token canaries and retained
output sizes replace the estimate. The selector shrinks before calls if the
standard-price upper bound exceeds USD 14. Batch never authorizes an
outcome-dependent expansion.

## A0 - Bind the retained local population

Validate the sealed local Phase 7 inventory, its project/source receipts,
selection and rendering evidence, prepared attacks, and current provider
registry/prices/budgets. Every prospective hosted row must prove membership in
one exact local input selection without printing prompt or response text.

Gate A0: all subset proofs validate and current provider terms and prices have
an effective timestamp. Failure affects only the hosted condition.

## A1 - Project immutable hosted subsets

Create one selector and no-call projection per target. Record exact counts by
modality, source arm, attacker/framework, risk and expected behavior. Bind
target, judge, HTTP, deadline and monetary caps to the request. Prepared
T3MP3ST, NanoGCG, IDEATOR and HarmBench rows retain their exact locally admitted
artifacts. Native-only evidence is not converted into common Runner rows.

Gate A1: every hosted row is a local-input subset, projected total spend
including probes/canaries is within its partition, and target/judge calls are 0.

## A2 - Paid readiness and canaries

Run bounded text and declared-media readiness probes for each exact route, then
one purpose-bound diagnostic canary per admitted target/modality. Record exact
served identity, billed tokens, effective price and spend.

Gate A2: identity and modality pass, accounting reconciles, and actual plus
remaining projected spend stays inside the 50 percent provider ceiling. Failed
routes are typed failed or N/A and are never silently substituted.

## A3 - Measured hosted subset

Execute only the A1 selectors with zero answer retries. Each row checkpoints
independently. Empty, malformed, binary/control-like or symbol-only output is a
model-stability missing response and does not stop the remaining population.
Identity, budget, request-binding or artifact drift still fails closed.

Gate A3: every intended row is complete or typed missing, no non-subset input
was called, and the provider ledgers reconcile within all monetary ceilings.

## A4 - Zero-target Haiku re-adjudication

Create two content-bound selectors:

1. up to 2,000 eligible local outputs; and
2. up to 2,000 eligible hosted outputs.

Use deterministic seed-0 balanced round-robin selection across target,
modality, source arm, attacker, risk, expected behavior and output-policy/
revision strata. Preserve original judgments. Exclude missing responses and
source-authoritative R-Judge/GPTGeoChat rows from judge calls while retaining
their coverage counts. Haiku target outputs are allowed by operator decision;
mark them same_model_judge=true and never call them independent judge evidence.

The re-adjudicator reads only content-bound retained responses and minimum
grading context. It cannot import a target factory, construct a target or
reserve a target call. Its new judgment stratum records the hosted-transfer
acknowledgement and exactly one judge attempt.

Gate A4: target calls 0, original mutations 0, Haiku calls at most 4,000,
Haiku spend at most USD 14, and complete selected/missing/excluded accounting.

## A5 - Selected comparison and diagrams

Publish separate, non-pooled views for:

- the API-selected cohort;
- the local-selected cohort; and
- the matched-input intersection with identical rendered-input identities.

Each reports population and decision coverage before rates. Required tables and
diagrams cover:

1. selected, answered, missing and judged counts by target/modality;
2. Haiku outcome rates with cluster-aware uncertainty;
3. failed-output and retry-use model-stability rates;
4. source-arm, attack/framework, risk and behavior composition;
5. matched-input model contrasts where support exists; and
6. billed input/output tokens and cost against each 50 percent provider cap.

Self-Haiku rows have a visible same-model annotation in every applicable table,
tooltip and figure. These are selected-cohort results, never full-corpus
estimates. Different revision/output-policy strata remain separate.

Gate A5: the comparison package, figure inputs, figures and Stats campaign
detail validate from the same sealed inventories. UI state and job-log prose
are not analysis sources.

## Stop conditions

Stop only the affected hosted condition for identity drift, provider-budget
exhaustion, invalid transfer acknowledgement, deterministic route
incompatibility or irreconcilable artifacts. Refusals, vague or length-capped
answers, and typed missing responses are results. No paid call starts until the
operator separately launches this follow-on after the local campaign.
