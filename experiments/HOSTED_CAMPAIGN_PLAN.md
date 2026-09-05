# Hosted subset and Haiku re-adjudication campaign plan

Status: prospective follow-on, revised 5 September 2026. This document authorizes no
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
- Paid targets and Haiku judging use zero answer-quality retries. The harness
  permits three retries, for at most four HTTP attempts per logical call, only
  when the provider exception carries status 408, 409, 425, 429, or 5xx.
  Connection failures without an HTTP status and valid HTTP responses with
  unusable content are not retried. Provider SDK retries are disabled.
- Hosted output-token limits are the explicit budget-derived values in this
  plan. They never inherit the vLLM/Ollama readiness profile, local 4,096-token
  fallback, or local request deadline.
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
| Claude Fable 5 | 30 | registry/canary intersection | 8,192 |
| Claude Opus 5 | 80 | registry/canary intersection | 6,144 |
| Claude Sonnet 5 | 150 | registry/canary intersection | 4,096 |
| Claude Haiku 4.5 | 200 | registry/canary intersection | 2,048 |
| GPT-6 Astra | 30 | text/image registry/canary intersection | 8,192 |
| GPT-5.6 Sol | 30 | registry/canary intersection | 8,192 |
| GPT-5.6 Terra | 30 | registry/canary intersection | 6,144 |
| GPT-5.6 Luna | 150 | registry/canary intersection | 4,096 |
| GPT-5.5 | 30 | registry/canary intersection | 8,192 |
| Kimi K3 | 80 | text; image only after an exact image canary | 8,192 |
| DeepSeek V4-Pro | 300 | text only, reviewed off-peak window | 8,192 |

OpenAI's published identifier for the requested Astra model is `gpt-6-astra`,
not GPT-5.6 Astra. The operator raised provider ceilings to 80 percent and
requested more inputs with shorter output allowances. Fable and Sol use their
explicit 8,192-token condition identities, preserving the earlier 4,096- and
25,000-token variants unchanged; Astra's exact config also fixes 8,192. Account access
must be confirmed before its included canary. Unavailable access is reported,
not silently substituted or charged to another route.

Limits were fixed before hosted outputs. Exact no-call projections or token
canaries may reduce a limit before execution to satisfy the monetary gate.
Observed answers or judgments may never change a selection.

The table budgets at most 1,110 hosted target calls, including every paid
readiness and diagnostic canary. A canary consumes its target's global cap and
does not add another paid request. The uncalibrated planning scenario uses
4,000 input tokens and one quarter of each route's output ceiling, including
reasoning tokens. It costs USD 27.939392, not an empirical prediction. With
the same input bound and every route consuming its configured maximum output,
the target reservation is USD 84.841568. The exact per-model arithmetic is in
`HOSTED_CAMPAIGN_COST_ASSESSMENT.md` and must be regenerated from the retained
pricing bytes before execution.
The target projection records 4,440,000 input and 1,602,560 scenario output
tokens, with 6,410,240 output tokens at the configured maxima. Including at
most 2,220 Haiku calls gives 22,626,240 scenario input and 2,170,880 scenario
output tokens; the maximum reservation is 31,719,360 input and 7,546,880 output.

These are budget-feasible starting ceilings, not proven optimal token settings.
Haiku has a non-thinking 2,048-token target allowance; Sonnet/Luna start at
4,096; Opus/Terra get 6,144; the six 8,192-token conditions reserve more room
for reasoning. Fable remains high-effort adaptive and Sol remains Pro/medium.
Kimi K3 explicitly uses `reasoning_effort=low`, not its provider-default `max`;
it still reasons. This budget-conditioned setting is reported separately from
any default/max-effort result. [Kimi reasoning controls](https://platform.kimi.ai/docs/guide/use-reasoning-effort).
Other selected reasoning controls remain those in the exact registry. No
reasoning mode is silently disabled to increase the apparent response rate.
The allowance is a ceiling, never a request to fill it. Token and effort
settings define reported experimental conditions, not a model ranking at
equal compute. See A2 for the empirical check before freezing the main cohort.

## Budget contract

The complete follow-on, including readiness probes, diagnostic canaries,
targets and Haiku judging, may use at most 80 percent of each configured budget.

| Provider | Configured | Follow-on maximum | Planning partition |
|---|---:|---:|---|
| Anthropic | USD 90 | USD 72 | targets USD 37.568; Haiku cap USD 33; margin USD 1.432 |
| OpenAI | USD 40 | USD 32 | targets USD 30.82512; margin USD 1.17488 |
| Moonshot | USD 15 | USD 12 | targets USD 10.7904; margin USD 1.2096 |
| DeepSeek | USD 10 | USD 8 | off-peak targets USD 5.658048; margin USD 2.341952 |

The Anthropic balance is the operator's 5 September update after unrelated
project spending. OpenAI maximum reservations include a conservative 25 percent
input-price allowance for cache writes, or a higher published cache-write rate
when present. This is a reserve, not an assumed charge on every request. The
combined target and Haiku maximum is USD 117.804128 across providers; OpenAI
uses USD 30.82512 of its USD 32 cap and Anthropic USD 70.53056 of USD 72.
The additional USD 0.03744 between calculated Haiku reservation and its USD 33
cap is retained headroom, not permission for extra judgments or content retries.

Haiku receives one matched cohort of at most 1,110 local/hosted output pairs.
That is at most 1,110 selected local outputs and 1,110 selected hosted outputs
from their matched-input intersection. The pair limit equals the entire hosted
target cap, so it selects every eligible answered hosted output exactly once;
it is not a second sample of the hosted results. Each receives one deterministic
unused local counterpart.
The local and hosted member of every pair has the same rendered-input identity,
source cluster, seed, arm/framework, modality and source-policy stratum. Neither
retained output may be reused in another pair. The judging scenario is 8,192
input and 256 output tokens per call: at most 2,220 calls cost USD 21.02784.
The dedicated judge route fixes `max_tokens=512`; reserving 12,288 input
tokens per complete judgment gives USD 32.96256, inside the USD 33 cap.
Judge input includes the prompt, retained answer, rubric and any rendered
media, not just the original target prompt. Different providers tokenize
differently: no target token count proves a Haiku input bound. Before spending,
count the complete local grading requests with Haiku's tokenizer/count API and
reserve hosted grading headroom. Oversized inputs are not silently truncated;
rebalance the prospective subset or its token allocation before A3 if the
exact reservation does not fit. Do not drop long answers after observing the
security result. Batch discounts are not needed for this funded plan and
never authorize an outcome-dependent expansion.

Across the full hosted population, local scoring performs at most 1,110 rule
evaluations and 1,110 sealed Llama Guard calls, with no hosted-provider cost.
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
artifact must reproduce the selected call counts, the explicitly uncalibrated
quarter-output-cap scenario, every route's configured maximum reservation,
the 2,220-call Haiku scenario and 12,288-input/512-output maximum, and the 80 percent provider
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

Use a small fixed technical pilot, normally three selected text inputs and up
to two selected images where supported, all charged inside the table's caps.
Include a short task, a reasoning-demanding task and a longer-input task; no
extra prompt rewriting, target answer retry or security-outcome tuning is
allowed. Record visible-answer presence, finish reason, total output tokens,
reasoning tokens where exposed and latency. If any pilot exhausts its ceiling
or has no usable final text, do not launch the remaining lane unchanged.
Investigate the cause, then change the exact token/effort condition and reduce
its remaining call count as necessary while preserving the provider and judge
reserves. Never automatically reissue the failed paid input. If the pilot
condition changes, retain it as diagnostic evidence and exclude it from the
new measured condition; it still consumes the original cap. A few passes are
screening evidence, not proof that truncation cannot occur later.

Freeze a common deterministic ordered input list within compatible modalities:
smaller model cohorts are prefixes of larger ones. Keep pilot and measured
strata separate and report their counts. Premium 30-call lanes therefore have
at most 25-27 non-pilot calls and support exploratory contrasts, not precise
per-arm claims. Report all-model matched-core comparisons separately from
larger route-specific extensions. Do not pool DeepSeek's larger text-only
cohort into an apparently better-supported all-model comparison.

Gate A2: identity and modality pass, accounting reconciles, and actual plus
remaining projected spend stays inside the 80 percent provider ceiling. Failed
routes are typed failed or N/A and are never silently substituted.

## A3 - Measured hosted subset

Execute only the A1 selectors with zero answer retries and the fixed
three-retry status-bearing HTTP policy. Each completed row
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

Create one content-bound selector for at most 1,110 local/hosted pairs. A pair
is eligible only when both retained outputs bind the same rendered prompt,
media-reference digest, datapoint, source cluster, seed, arm/framework,
modality, risk, expected behavior and source-policy identity. Use deterministic
seed-0 balanced round-robin selection across local target, hosted target and
those input strata, without reusing an output. Preserve original judgments.
When the eligible hosted population remains at or below 1,110, selection must
include every eligible hosted output rather than downsample it.
Missing responses and source-authoritative R-Judge/GPTGeoChat rows remain in
coverage accounting but receive no judge call and cannot form a judged pair.
Haiku target outputs are allowed by operator decision; mark them
same_model_judge=true and never call them independent judge evidence.

The re-adjudicator reads only content-bound retained responses and minimum
grading context. Its planner cannot import a target-under-test or Runner
factory. Its executor may construct only the exact Haiku judge; it cannot
construct a model under test or reserve a target call. The paired plan receives
one USD 33 ceiling. Its judgment strata record the hosted-transfer
acknowledgement, one logical judge call per output, and at most four HTTP
attempts under the status-only retry rule.

Gate A4: target calls 0, original mutations 0, Haiku calls at most 2,220,
Haiku spend at most USD 33, and complete selected/missing/excluded accounting.
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
6. billed input/output tokens and cost against each 80 percent provider cap;
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
