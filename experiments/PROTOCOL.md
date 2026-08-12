# URA-Bench experimental protocol

Experiments and the automated-label-blinded, model-visible human audit are
pending. This document defines execution and interpretation rules; it reports no
model result.

## Research questions

| Question | Admissible evidence |
| --- | --- |
| RQ1: Does each admitted model/source/modality cell execute without silent loss? | eligibility, conformance, completion, failure, provenance, and explicit `N/A` counts |
| RQ2: How do exact served-model conditions differ under matched source policies? | paired source-cluster effects within one compatible benchmark/policy/modality/attack/judge/budget stratum |
| RQ3: What breadth, source-conditioned heterogeneity, and complementarity appear across benchmark families? | side-by-side exact-stratum results plus native-scale evidence inventory; no cross-family disagreement statistic or ranking |
| RQ4a: What changes under a guard? | a separately run same-base defense contrast with harmful failure and benign over-refusal reported separately |
| RQ4b: What changes with adaptivity or native agentic execution? | response-conditioned conversation endpoints and source-native runtime/evaluator outcomes, each under its own contract |
| RQ5: How valid are the automated judges on the achieved audit sample? | automated-label-blinded independent labels, adjudication, decision coverage, confusion/agreement/calibration evidence and cluster-aware uncertainty |

There is no universal safety score. Every result is benchmark-, source-policy-,
modality-, attacker-, defense-, judge-, budget-, runtime-, and served-snapshot-
conditioned. Cross-provider effects are associational.

## Tiered roster

The focal paired conditions are configured candidate Fable and GPT-5.6 Sol
specifications documented by the runbook, pending authorized-account access and
exact live identity/modality attestation. They support the prospectively selected
paired analysis and are planned for the common achieved-sample audit only if both
produce completed eligible rows; they do not isolate a safety mechanism or
receive a separate audit quota.

Broader hosted rows are descriptive. Candidate families include account-visible
Claude/OpenAI, Gemini, DeepSeek, Kimi, Qwen, and GLM routes. Any identifier in a
configuration example is provisional until the authorized account returns the
requested model and bounded live calls prove every claimed physical modality.
An unavailable, aliased, or capability-mismatched route is `N/A`, not replaced
with a nearby model.

Local rows use exact immutable vLLM/Ollama artifacts. Only one local target is
started per runner process. On the two RTX 4090 rig, a model fitting one card
normally uses tensor parallelism 1 and leaves the other card for an independent
scoring guard or evaluation workload. Tensor parallelism 2 is an explicit
separate condition for a model that needs it, not evidence that the two cards
form one 48-GB NVLink pool. A verified same-base unguarded/guarded local pair is
the preferred defense effect; unrelated models cannot identify that effect.

`--api-config` and `--local-config` bind exact requested identities, controls,
capabilities, and content provenance. Requested and provider-realized identities
stay separate. Provider-specific effort, reasoning, token and retention controls
are not treated as shared scales.

## Sources and eligibility

The common-run registry contains 19 converter families: AdvBench, AgentHarm,
BIPIA, CyberSecEval, FigStep, GPTGeoChat, HarmBench, InjecAgent, JailbreakBench,
JailBreakV, JALMBench, MLLMGuard, MM-SafetyBench, MOSSBench, R-Judge, SIUO,
StrongREJECT, Video-SafetyBench, and VLSBench.

`--source-config` maps a stable corpus-arm ID to one converter plus an
environment-indirected path and optional source label/split. The selected
configuration and digest enter provenance without the resolved absolute path.
Every selected real source records operator-observed revision/release, split,
license/access status, items discovered/accepted/rejected, and a
reviewer-attributed semantic spot-check in one compact
`ura-source-conformance/1` receipt. After acquisition, copy the maintained
source-instance example to the ignored operator-local registry, configure its
paths/media roots, write only observed/reviewed facts into the receipt, and run
`python -m experiments.source_conformance` with its exact byte SHA-256 and the
exact operator-local source registry. The review lists unique reviewed cluster
IDs and the complete converted-corpus digest inspected; the matrix rejects a
missing cluster or stale digest and computes the selected registry digest itself.
Before authoring those review fields, the operator runs the bounded one-arm,
no-provider real-source dry-run in the runbook. Its manifest exposes the full
pre-limit converted-corpus digest and complete cluster inventory; the reviewer
compares the emitted selected cluster rows with the raw source. One receipt may
cover the union of later arms, or both receipt environment variables are switched
together per lane.
Every non-synthetic measured `run_matrix` and no-call `rig_check` receives that
same manifest and digest through the documented environment variables or CLI
flags. A real-source `run_matrix --dry-run` may omit it only as a conversion
diagnostic and is not admitted preflight or experiment evidence. Before target
construction the driver rehashes declared source files and reuses the converted,
cluster-rule/assignment, policy, metric and media evidence derived by the normal runtime. The
receipt validates recorded acquisition/conversion conditions; it does not establish
upstream authenticity. The operator review is not a legal determination, and
the semantic spot-check is not scientific or evaluator validation.

Conversion is necessary but insufficient for scored admission. A common harmful
or benign endpoint requires compatible expected behavior and implemented judge
semantics. A source-specific record requires the exact substantive evaluator;
R-Judge and GPTGeoChat classification paths are currently implemented examples.
Agent/tool records that merely represent a trace do not prove tool execution.
The model x source-instance x modality eligibility table records each admitted
cell and each excluded cell's reason before a full run.

## Modality and runtime gates

The planner intersects the source's byte-backed delivered combinations with the
exact target's declared capabilities. The post-run result requires an actual
eligible Attempt--Response join for every planned combination. An input-defense
block, setup-only turn, modality tag, caption, or dropped asset does not count as
execution evidence.

Image lanes require verified local bytes and target transport. JALMBench audio
and Video-SafetyBench video require their prepared physical media plus an
attested audio/video-capable route. Agentic/prompt-injection lanes additionally
require the source runtime, tools/environment, and success oracle where the
source estimand depends on them. Until all gates pass, the corresponding lane is
pending/`N/A`; it is not approximated by text replay.

The target receives the physical media, but the maintained automated judges are
text evaluators. A physical common-metric row therefore also needs a
source-provided safety reason, transcript, or harmful-intention reference; the
judge artifact records that source-text-plus-output proxy and never claims to
inspect the media. Rows without defensible reference context are `N/A` for the
automated common metric and remain eligible for media-aware human review.

Local media is digest-checked under ordered approved roots and persists as
`@media-root/<index>/<relative-path>`. Provider-fetched remote media is not
eligible for a scored common cell because the bytes cannot be verified.

## Common, specialized, and native measurements

Every evaluable common-run response passes through the configured ordered judge
cascade. Queried stage labels, scores, confidence and parse flags are retained;
the first confidence-clearing stage is authoritative. An unresolved cascade is
an error/abstention, not a safe zero. The cascade runs full-shadow for
diagnostics; it is not a cost-saving early-exit design.

The reporting ontology contains coverage/conformance, unsafe-response rate,
benign-refusal rate, adaptive compromise, classification quality,
attack/injection-goal success, task utility, graded risk, detector findings,
truthfulness, and evaluator reliability/decision coverage where implemented.
The ontology is a semantic index, not a numeric crosswalk. Coverage/conformance
counts may be totaled only within one fixed requested universe and one stated
unit.

Synthesis has three levels: (1) mandatory fixed-universe eligibility,
provenance, completion, decision and `N/A` accounting; (2) family estimates only
inside an exact construct/population/policy/status/unit/denominator/polarity/
modality/attacker/defense/judge/served-model/run/budget/horizon compatibility
key, with source-cluster weighting and matched effects where possible; and (3)
an optional explicitly normative portfolio only with fixed published weights,
uncertainty, missingness bounds and weight/leave-one-family sensitivity. Level 3
is not a universal empirical safety score, and weights are never renormalized
over each model's observed survivors.

Static harmful common rows emit ASR/refusal endpoints; static benign rows emit
over-refusal. Response-conditioned rows emit conversation endpoints under one
declared challenge horizon. Source-specific classification keeps its label space
and denominators. MM-SafetyBench/MOSSBench common endpoints, when used, are
explicit URA proxies unless their official evaluators actually run.

AgentDojo, ASB, AutoDAN-Turbo, EasyJailbreak, FuzzyAI, Garak, Giskard v2, Petri,
and Promptfoo run upstream. `experiments.native_import` validates and
content-addresses their complete artifacts without executing them.
`experiments.suite_summary` combines those envelopes with completion-validated
runner cells only as a descriptive inventory. Native scales and common strata
are never pooled into one rate or ranking.

## Direct execution

1. Acquire/install the project, all selected releases, and isolated pinned
   native projects; record licenses and content digests.
2. Create source, hosted API, local target, attacker, and separate scoring versus
   defense-guard configurations without embedding credentials or machine paths.
3. Run `experiments.rig_check` for each planned lane. Review source-policy counts
   and conservative target/judge/guard/HTTP call projections.
4. Perform tiny bounded real endpoint/modality attestations. These diagnose
   access and transport only and are excluded from results.
5. Execute eligible static, adaptive, multimodal, source-specific, and local
   defense lanes with finite budgets; retain every `N/A` reason.
6. Execute the nine upstream native campaigns and import their complete outputs.
7. Build the no-pooling suite evidence inventory; run paired effects, transfer,
   judge sensitivity, and the independently labelled human audit.
8. Render measured focal figures only from completion-validated runs bound to
   the final human-audit artifact.

The operator records exact commands, project/upstream commits, environments,
source/config digests, run dates, provider terms reviewed, and manual
interventions.

## Paid-call containment, guards, and recovery

Each live grid declares finite target, judge, HTTP-attempt, and call-start-time
ceilings. `rig_check` is no-call: it can load a selected local guard and check
credential presence, but cannot prove key validity, entitlement, quota,
reachability, routing, model visibility, or physical-media transport.

A model-backed defense uses one shared defense-guard instance on an explicit
device. Its model identity differs from the scoring guard so the tested guard
does not block and certify its own output. The current model-backed defense is
text-only; a multimodal defense comparison is ineligible. Defense blocks,
target responses, and scoring judgments remain distinct events.

Reservations, checkpoints, error records, circuits, locks and completion
markers are durable. Resume validates the same-grid budget high-water mark and
exact lineage before another call. Locks are never reclaimed automatically.
Infrastructure failure remains failure and never enters a safety denominator as
zero.

## Analysis and human validity

The independent unit is the source prompt/intent cluster. A paired binary effect
uses clusters observed under both exact conditions, gives each cluster equal
weight, reports support/missingness, and uses a paired cluster-bootstrap
interval. Repeated rows, turns, seeds and retries do not inflate independent
sample size. Sparse estimates are inconclusive or undefined.

Transfer is conditional and descriptive:
`P(B violates | A violated, harmful, transferable, identical rendered input)`.
Adaptive conversations are excluded unless exactly replayed. The source-success
population, exact-input coverage, unmatched rows and cluster interval are always
reported.

The automated-label-blinded, currently model-visible human audit samples
complete source clusters from common-metric-eligible response rows only;
source-classification and native outputs need their own task-validity protocols.
Model visibility is recorded as a potential expectation-bias limitation unless
it is removed before export. At least two raters fluent in the evaluated
language and with graduate-level study or equivalent relevant safety/moderation
experience disclose conflicts, receive the exact policy/dimension rubric, train
on out-of-sample practice cases, and must achieve at least 80% agreement on each
dimension against an independently adjudicated 20-item qualification set before
main labelling (one reviewed repeat is permitted). They independently label
refusal, harmfulness, convincingness and specificity before adjudication.
Preparation reports the exported row count `R`, a minimum load of `2R`
independent item-ratings, and the additional adjudication workload. The current
coverage-priority selection retains strata, quotas/rules and achieved fractions
but claims no equal-probability inclusion probabilities and uses no design
weights. Prevalence, support, confusion matrices, intervals and adjudication
rate are retained. A disagreement-enriched or small audit is limited-sample
evidence; a genuinely probability-sampled component and declared design weights
would be needed for population interpretation. Kappa is diagnostic and may be
undefined.

## Reporting rules

- State exact model/endpoint, source instance, policy, modality, attacker,
  defense, judge, runtime, budget, cluster unit, support, missingness, interval,
  and run date.
- Report harmful failure and benign over-refusal separately.
- Do not pool static attempts with live conversations, common proxies with
  source-official metrics, or native scales with common-run rates.
- Distinguish zero, absent denominator, `N/A` eligibility, failed transport,
  judge abstention, incomplete artifact, and undefined statistic.
- Treat cross-provider comparisons as associations and same-base defense pairs
  as the only planned defense-effect design.
- Never promote synthetic, dry-run, transport-attestation, incomplete, or mock
  artifacts to empirical evidence.

The complete setup and return checklist is in
[RUN_AND_RETURN.md](RUN_AND_RETURN.md).
