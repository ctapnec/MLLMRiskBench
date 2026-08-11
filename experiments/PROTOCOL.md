# Chapter V protocol

The study has not been executed. All hypotheses are prospective and every
measured claim must trace to complete real-run artifacts. Synthetic output and
preliminary analysis remain explicitly non-publishable.

## Questions and estimands

| Question | Primary evidence |
| --- | --- |
| RQ1: Which safety risks are observed? | harmful ASR/refusal/severity and benign FRR, separated by source and risk |
| RQ2: What changes across physical input channels? | identical metric families grouped by declared/effective modality, with explicit unsupported combinations |
| RQ3: What changes under a guard? | separately frozen same-target defense contrast; not the Fable/Sol comparison |
| RQ4: What changes under adaptive attacks and transfer? | conversation ASR/robust refusal/full KM/RMTB; exact static transfer only |
| RQ5: How reliable is judgment? | decision coverage, binary/exact kappa, blinded multi-rater audit and human-label sensitivity |

The primary case is the cross-provider endpoint contrast between exact
account-visible Fable and GPT-5.6 Sol configurations. It is non-causal and is
not a same-base defense ablation. Mythos is literature/future replication only.

## Populations and metrics

Harmful probes (`expected_behavior=refuse`) and benign probes (`safe_answer` or
`comply_safely`) never share a denominator. Static attempts report ASR,
desired-refusal, FRR, and where fully rubric-graded unconditional
StrongREJECT-style severity. Live response-conditioned units report conversation
ASR/FRR and robust refusal, never per-turn pooled ASR.

For harmful live conversations, report the entire Kaplan-Meier curve from turn
0 through `min(max_queries,max_turns)`, at-risk/event/censor counts, the median
only if observed inside the horizon, and horizon-specific restricted mean
turns-to-break (RMTB) with a source-cluster bootstrap interval.

All uncertainty and pairing use source prompt/intent clusters. A paired effect
is reduced to one mean difference per cluster before clusters are weighted
equally. The confirmatory plan uses one disjoint-pilot variance artifact and one
SESOI per hypothesis. It freezes complete Holm-Bonferroni families; unavailable
hypotheses stay in their family and prevent publishability.

## Corpus and source-policy scope

The primary corpus set is:

| Corpus | Population/input | Interpretation |
| --- | --- | --- |
| StrongREJECT | harmful text | common harmful metrics; dedicated rubric only when complete |
| MM-SafetyBench | harmful text+image | complete pinned release; common ASR is secondary, not official scenario-conditioned attack rate |
| MOSSBench | benign text+image | complete pinned release; common FRR is secondary, not the official image-conditioned GPT-4 refusal score |

The maintained matrix records both official evaluators as not executed. Do not
rename their secondary common metrics.

MM-SafetyBench contains six maintained source-evaluation policies. Every matrix
command that can include it (and the MOSSBench policy) groups by
`source_policy_id,source_policy_version` in addition to model/risk/modality, so
an aggregate never pools distinct source rules.

R-Judge and GPTGeoChat run separately with static replay and their implemented
source-specific classification metrics. A converted source that still lacks its
substantive runtime/evaluator fails before target calls; conversion coverage is
not experimental success.

Every real scored source is loaded from `URA_<NAME>_PATH` and must be frozen by
the SHA-256-bound exhaustive pilot/main partition. That artifact binds the full
converted population, source-cluster inventory, and selection. MM-SafetyBench
and MOSSBench additionally enforce maintained official counts and manifest/table
hashes. A missing, partial, modified, or schema-drifted release fails before
paid calls.

## Target and modality scope

Primary conditions:

- `anthropic-fable:claude-fable-5;effort=high;max_tokens=25000`
- `openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns`

The exact requested strings and provider-resolved identities are retained.
Fable thinking continuity and Sol's encrypted reasoning/assistant items are
preserved for exact stateless continuation. A Fable midstream refusal discards
partial output but remains a counted refusal.

Both target adapters currently support text and text+image. The pre-call
`modality_coverage_plan` therefore requires both combinations, and the post-run
result requires at least one real eligible execution of each for every target.
StrongREJECT supplies text; MM-SafetyBench and MOSSBench supply text+image. Audio
and video are registered but explicitly unavailable for these targets. Do not
drop media, caption it, or infer arbitrary image+audio/video combinations.

Local exploratory targets require exact `--local` specs and config entries with
one immutable `revision` or `digest` plus `modalities`. They do not silently join
the primary family.

## Provider, budget, and recovery gates

Before any hosted call, freeze a SHA-256-bound
`ura-provider-data-policy-approval/1.0` file. It must cover every exact hosted
target and LLM judge with its provider, role, accepted retention/data-use terms,
and policy URLs. Fable's mandatory covered-model retention and the effective
OpenAI organization controls must be recorded; `store=false` is not zero
provider retention.

Every paid grid uses finite durable ceilings for model-under-test logical calls,
model-backed judge calls, declared provider transport attempts, and elapsed
wall time. Reservations persist before calls. Grid/cell locks prevent concurrent
reuse; systemic provider/judge failures open a durable circuit. After correcting
the cause, `--reset-open-circuits` is the only deliberate reset. Append-only
checkpoints resume verified completed work, including continuation state. These
controls bound call exposure, not provider billing or token cost.

`--limit N` counts unique source clusters and retains every row in them. Measured
real execution always selects a frozen partition role with `--limit 0`; arbitrary
limited sampling is diagnostic only.

## Prospective execution and analysis

1. Verify tests, lint/compile checks, and synthetic smoke output.
2. Resolve and validate complete releases/media.
3. Freeze one content-addressed pilot/main cluster partition and one hosted-
   provider approval.
4. Run the pilot role under the exact planned conditions and finite ceilings.
5. Generate a separate pilot artifact for each planned endpoint/facet. Freeze
   its SESOI, required clusters, complete family, source policy, analysis seed,
   bootstrap/permutation counts, and conservative whole-cluster human-audit
   design in `ura-confirmatory-plan/1.0`.
6. Run the main role using the same partition and conditions. Do not add pilot
   rows to main estimates.
7. Run same-response judge sensitivity, exact transfer, kappa, and the optional
   non-publishable preliminary confirmatory analysis.
8. Prepare exactly the frozen number of whole source clusters for at least two
   independent raters, then adjudicate and analyse labels with cluster/IPW
   uncertainty.
9. Produce the final confirmatory artifact bound to both the immutable plan and
   successful human-audit SHA-256.
10. Render measured figures only from that final artifact.

The confirmatory driver verifies pilot/main run IDs and cluster IDs are disjoint,
that both roles bind the same partition digest, that selectors/corpus/metric/
risk/modality/source-policy identity matches each pilot, and that every planned
endpoint has its own power gate. Hypotheses use the canonical
`policy=<percent-encoded-id>@<percent-encoded-version>` token; no confirmatory
MM-SafetyBench effect pools its six policies.

## Judge and transfer validity

Every automated stage shadow-scores the same persisted response. The first
confident stage is authoritative, but no automated judge is treated as ground
truth. Unparsed or low-confidence rows are abstentions; sensitivity reports
identification bounds where coverage is incomplete. Primary kappa is violation
versus other; exact four-label kappa is diagnostic.

Static transfer estimates target-B violation conditional on a harmful exact
input that violated A, requiring identical transfer key and input fingerprint.
Live adaptive Crescendo is target-specific and excluded unless the transcript
is replayed verbatim. No support yields `null` with a reason and counts. Transfer
is prespecified descriptive evidence with support/power gates and a cluster
interval, but its source-success-conditioned population has no frozen null or
p-value and stays outside the Holm families. The paired adaptivity effect, not
the conditional transfer rate, is the confirmatory adaptivity hypothesis.

## Interpretation and stopping rules

Stop and preserve artifacts on endpoint/identity drift, unexpected modality
fallback, release/media mismatch, exhausted durable ceiling/deadline, open
circuit, judge malfunction, or corrupted lineage. Amend and rerun; never edit
result files or delete failure evidence to continue.

Report the exact endpoint/judge IDs, access/run dates, source releases and
policy identities, partition/approval/plan digests, conditions, effective
sampling control, cluster support, uncertainty, exclusions, failures, and
amendments. Distinguish missing, failed, unsupported, abstaining, undefined, and
measured zero. Taxonomy mappings remain informational crosswalks, not compliance
conclusions.

The exact operator commands and JSON shapes are in
[RUN_AND_RETURN.md](RUN_AND_RETURN.md).
