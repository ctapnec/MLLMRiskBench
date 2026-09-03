# Hosted subset and Haiku re-adjudication campaign plan

Status: prospective follow-on, 1 September 2026. This document authorizes no
paid call. Start only after the all-local campaign seals its Phase 7 inventory.
Run every controller on the rig in a named tmux session.

This is a separate campaign, not a local-campaign phase and not product
semantics. It compares bounded hosted-model conditions on content-bound subsets
of inputs already used by the local campaign, then applies one selected Haiku
judge condition to hosted and local retained outputs. Every hosted lane uses
the sealed local `rules,guardrail` cascade during its measured Runner execution,
so the hosted member of every later Haiku pair already has its local judgment.

## Fixed design

- Sampling policy: seeded_pseudorandom_whole_cluster_prefix_v1.
- Sample seed and attack seeds: 0.
- Source, converter, policy, prepared-attack, rendered-media and framework
  identities: the exact Phase 7-validated local identities.
- A hosted row is eligible only if its rendered input identity occurs in the
  sealed local campaign and its hosted route declares that modality.
- Incompatible modalities are N/A. They are never captioned or transformed.
- Paid targets and Haiku judging use exactly one application attempt.
  target_answer_retries is 0, harness transport max_retries is 0, and provider
  SDK retries are disabled.
- Missing responses remain selected-population and stability evidence but
  receive no Haiku call.
- The first retained failed target output opens the global `paid_provider`
  circuit before another paid call can start. A transport or network failure
  opens the same circuit. The retained row is diagnostic evidence, not
  permission to continue spending.
- Every hosted target lane fixes `--judges rules,guardrail`, the admitted
  Llama Guard identity and a local judge-call ceiling covering its selected
  answered rows. This local scoring adds no hosted call or monetary spend.

The hosted quantity is a global retained-input cap per target, not Runner's
per-arm `--limit`. One deterministic balanced selector draws that many exact
rendered inputs from the validated local population across arm, framework,
modality, risk and behavior strata. Each selected entry permits exactly one
hosted target call. Framework/attacker labels record how the retained input was
produced locally; the paid campaign does not regenerate adaptive trajectories.
Its create-only selector binds the local selection artifact, converted-corpus
digest, source cluster, seed, rendered-input and media digests, and hosted
subset digest. Set inclusion must validate before any provider call.

| Hosted target condition | Global input/call cap | Modalities | Max output tokens |
|---|---:|---|---:|
| Claude Fable 5 | 5 | registry/canary intersection | 25,000 |
| Claude Opus 5 | 10 | registry/canary intersection | 4,096 |
| Claude Sonnet 5 | 50 | registry/canary intersection | 4,096 |
| Claude Haiku 4.5 | 100 | registry/canary intersection | 2,048 |
| GPT-5.6 Sol | 5 | registry/canary intersection | 25,000 |
| GPT-5.6 Terra | 20 | registry/canary intersection | 4,096 |
| GPT-5.6 Luna | 100 | registry/canary intersection | 4,096 |
| GPT-5.5 | 100 | registry/canary intersection | 4,096 |
| Kimi K3 | 100 | text; image only after an exact image canary | 4,096 |
| DeepSeek V4-Pro | 100 | text only, reviewed off-peak window | 4,096 |

Limits were fixed before hosted outputs. Exact no-call projections or token
canaries may reduce a limit before execution to satisfy the monetary gate.
Observed answers or judgments may never change a selection.

The table authorizes at most 590 hosted target calls, including every paid
readiness and diagnostic canary. A canary consumes its target's global cap and
does not add another paid request. With 4,000 input and 500
output tokens per call, current effective-dated rates predict USD 8.3130. With
the same input bound and every route consuming its configured maximum output,
the target reservation is USD 38.5476. The exact per-model arithmetic is in
`HOSTED_CAMPAIGN_COST_ASSESSMENT.md` and must be regenerated from the retained
pricing bytes before execution.
The target projection records 2.36 million input and 295,000 expected output
tokens, with 2,420,880 output tokens at the configured maxima. Including 4,000
Haiku calls gives 18.36 million input, 2.295 million expected output and
4,468,880 maximum output tokens.

## Budget contract

The complete follow-on, including readiness probes, diagnostic canaries,
targets and Haiku judging, may use at most 50 percent of each configured budget.

| Provider | Configured | Follow-on maximum | Planning partition |
|---|---:|---:|---|
| Anthropic | USD 100 | USD 50 | targets/probes at most USD 13; Haiku at most USD 27; margin at least USD 10 |
| OpenAI | USD 40 | USD 20 | targets/probes at most USD 19; margin at least USD 1 |
| Moonshot | USD 15 | USD 7.50 | targets/probes at most USD 7.50 |
| DeepSeek | USD 10 | USD 5 | off-peak targets/probes at most USD 5 |

Haiku receives one matched cohort of at most 2,000 local/hosted output pairs.
That is at most 2,000 selected local outputs and 2,000 selected hosted outputs
from their matched-input intersection.
The local and hosted member of every pair has the same rendered-input identity,
source cluster, seed, arm/framework, modality and source-policy stratum. Neither
retained output may be reused in another pair. At the planning assumption of
4,000 input and 500 output tokens per judgment, the resulting maximum 4,000
calls use 16.0 million input and 2.0 million output tokens and cost USD 26.00
standard or USD 13.00 Batch. The dedicated judge route fixes `max_tokens=512`,
making USD 26.24 the planning maximum when every selected judge input is at
most 4,000 tokens. Exact provider token counts replace the estimate. The
selector shrinks before calls if that bound exceeds USD 27. Batch never
authorizes an outcome-dependent expansion.

Across the full hosted population, local scoring performs at most 590 rule
evaluations and 590 sealed Llama Guard calls, with no hosted-provider cost.
The guardrail's safe/violation label space cannot decide benign over-refusal
where the rules stage is also undecided, so local decision coverage and
abstentions must accompany every local-versus-Haiku agreement result.

## A0 - Bind the retained local population

Validate the sealed local Phase 7 inventory, its project/source receipts,
selection and rendering evidence, prepared attacks, and current provider
registry/prices/budgets. Every prospective hosted row must prove membership in
one exact local input selection without printing prompt or response text.
Before projection, use the pricing fetch action to add any missing models from
the current checked-in null roster and fetch supported rates. It must preserve
all existing operator-entered models, rates and fields. Models whose current
price cannot be fetched remain explicitly unpriced and block their own lane.
Run `python -m experiments.hosted_campaign_budget` with the exact API config,
pricing and budget files plus their SHA-256 values. Its create-only no-call
artifact must reproduce the selected call counts, the 4,000-input/500-output
expected cost, every route's configured maximum-output reservation, the
4,000-call Haiku expected and 512-output maximum, and the 50 percent provider
reconciliation. A `blocked_budget` status does not admit a paid call.

Gate A0: all subset proofs validate and current provider terms and prices have
an effective timestamp. Failure affects only the hosted condition.

## A1 - Project immutable hosted subsets

Create one selector and no-call projection per target. Record exact counts by
modality, source arm, attacker/framework, risk and expected behavior. Bind
target, local judge, HTTP, deadline and monetary caps to the request. Every
projected lane fixes `--judges rules,guardrail`, Llama Guard revision
`7327bd9f6efbbe6101dc6cc4736302b3cbb6e425`, and its sealed acquisition
identity. Prepared
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

Execute only the A1 selectors with zero answer retries. Each completed row
checkpoints independently and retains its `rules,guardrail` trail. Empty,
malformed, binary/control-like or symbol-only
output is durably retained as a model-stability missing response, then the
global `paid_provider` circuit stops the grid before another paid call. A
transport or network exception opens the same circuit without inventing a
completed response. The operator must classify provider-completed empty output
separately from interrupted transport, resolve the route, derive a fresh bound
plan, and explicitly reset the circuit. There is no automatic paid resumption.
Identity, budget, request-binding or artifact drift still fails closed.

Gate A3: every intended row is complete or typed missing, every answered row
has its validated local cascade trail, no non-subset input was called, and the
provider ledgers reconcile within all monetary ceilings.

## A4 - Zero-target matched Haiku re-adjudication

Create one content-bound selector for at most 2,000 local/hosted pairs. A pair
is eligible only when both retained outputs bind the same rendered prompt,
media-reference digest, datapoint, source cluster, seed, arm/framework,
modality, risk, expected behavior and source-policy identity. Use deterministic
seed-0 balanced round-robin selection across local target, hosted target and
those input strata, without reusing an output. Preserve original judgments.
Missing responses and source-authoritative R-Judge/GPTGeoChat rows remain in
coverage accounting but receive no judge call and cannot form a judged pair.
Haiku target outputs are allowed by operator decision; mark them
same_model_judge=true and never call them independent judge evidence.

The re-adjudicator reads only content-bound retained responses and minimum
grading context. Its planner cannot import a target-under-test or Runner
factory. Its executor may construct only the exact Haiku judge; it cannot
construct a model under test or reserve a target call. The paired plan receives
one USD 27 ceiling. Its judgment strata record the hosted-transfer
acknowledgement and exactly one judge attempt per output.

Gate A4: target calls 0, original mutations 0, Haiku calls at most 4,000,
Haiku spend at most USD 27, and complete selected/missing/excluded accounting.
Every selected hosted member must bind the unchanged local cascade trail from
its A3 result by retained-row digest.

## A5 - Selected comparison and diagrams

Publish separate, non-pooled views for the hosted and local members of the one
matched-input cohort. Also publish the unpaired hosted/local input and response
coverage that was excluded before judging.

Each reports population and decision coverage before rates. Required tables and
diagrams cover:

1. selected, answered, missing and judged counts by target/modality;
2. Haiku and local-cascade outcome rates with cluster-aware uncertainty;
3. failed-output model-stability rates and one-attempt response coverage;
4. source-arm, attack/framework, risk and behavior composition;
5. matched-input model contrasts where support exists; and
6. billed input/output tokens and cost against each 50 percent provider cap;
   and
7. local-versus-Haiku agreement on the same hosted outputs, with comparable
   label support, decision coverage and abstentions shown separately.

Self-Haiku rows have a visible same-model annotation in every applicable table,
tooltip and figure. These are selected-cohort results, never full-corpus
estimates. Different revision/output-policy strata remain separate.

Gate A5: the comparison package, figure inputs, figures and Stats campaign
detail validate from the same sealed inventories. UI state and job-log prose
are not analysis sources.

## Stop conditions

Stop the paid grid on the first target transport/network failure or first
durably retained failed target output, and stop the affected hosted condition
for identity drift, provider-budget exhaustion, invalid transfer
acknowledgement, deterministic route incompatibility or irreconcilable
artifacts. Refusals, vague answers and length-capped answers with substantive
text are results. A typed missing response is retained, but it opens the global
`paid_provider` circuit for investigation. No paid call starts until the
operator separately launches this follow-on after the local campaign.
