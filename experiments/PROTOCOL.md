# URA-Bench experimental protocol

Experiments and the automated-label-blinded, model-visible human audit are pending. This document defines the
current execution and interpretation rules; it reports no result.

## Research questions

| Question | Admissible evidence |
| --- | --- |
| RQ1: Does each admitted cell execute without silent loss? | conformance, completion, failure, and provenance counts |
| RQ2: Do exact served-model conditions differ under one benchmark policy? | paired source-cluster effects within matching policy, modality, attack, judge, and budget |
| RQ3: What changes under a guard? | separately run same-target defense contrast with harmful ASR and benign false-refusal reported separately |
| RQ4: What changes with adaptivity, and what transfers? | within-target replay-versus-Crescendo effects; separately qualified exact-input conditional transfer |

There is no universal safety score. Results are benchmark-, policy-, modality-,
judge-, attack-, budget-, and endpoint-snapshot-conditioned. Cross-provider
effects are associational.

## Study conditions

The named executable comparison is:

- `anthropic-fable:claude-fable-5;effort=high;max_tokens=25000`
- `openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns`

The driver records the requested specification and every provider-returned
identity field. A changed non-null model, provider fingerprint, reasoning mode,
effort, or context within a cell fails closed. Unsupported or inaccessible
targets are reported rather than replaced with aliases. Mythos is literature
and possible future authorized replication only.

Fable uses adaptive thinking, explicit high effort, a 25,000-token maximum, no
temperature, no seed, no fallback, and no native tools. Sol uses Responses Pro,
medium effort, all-turns reasoning context, a 25,000-token maximum,
`store=false`, and disabled truncation. Their effort labels and token accounting
are provider-specific and are not treated as a common scale. Provider-native
continuation state is retained only within the originating conversation and in
bounded access-controlled artifacts.

## Corpora and modalities

The main grid loads the complete pinned releases through:

- `URA_STRONGREJECT_PATH`: harmful text;
- `URA_MMSAFETY_PATH`: harmful text+image across six source policies; and
- `URA_MOSSBENCH_PATH`: benign text+image.

The runbook gives the exact download, checkout, image-placement, and environment
commands. Converters validate the official release identity, expected layout,
counts, policies, and media bytes before target calls. The StrongREJECT anchor is
the 313-row official CSV at commit
`f7cad6c17e624e21d8df2278e918ae1dddb4cb56` with normalized SHA-256
`4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`.

Sampling and inference use unique source prompt/intent clusters. Every model,
repeat, attack, turn, response, and judgment derived from one cluster stays with
that cluster. The complete thesis run uses `--limit 0`; smaller cluster limits
are diagnostics and must be labelled as such.

Fable and Sol currently support text and image. The selected corpus set exposes
text and text+image, and both exact targets must execute both available
combinations. `modality_coverage_plan` checks this before calls;
`modality_coverage_result` requires actual eligible Attempt--Response evidence
afterward. Audio and video are unavailable in the study adapters. The harness
never fabricates modality support, silently removes media, or substitutes a
caption.

Local media is digest-checked beneath ordered approved roots and persisted as
`@media-root/<index>/<relative-path>`. Provider-fetched remote media is not
eligible for scored cells because its bytes cannot be verified.

## Judgment and endpoint rules

Every evaluated response passes through the ordered rule, guardrail, and LLM
judge stages. All queried stage outputs and parse/confidence fields are retained
as a shadow trail. The first confidence-clearing stage is authoritative. A
failed or unparseable required judge path is not a safe zero.

Static harmful probes emit `ASR`. Static benign probes emit false-refusal rate.
Response-conditioned Crescendo uses `conversation_ASR`, robust refusal, and
survival on contiguous policy-challenge indices. Benign setup turns remain in
the transcript as typed `not_applicable` provenance, invoke no judge, and enter
no metric. A harmful authoritative violation terminates the conversation.

Common MM-SafetyBench ASR and MOSSBench false-refusal are secondary URA proxies,
not source-official metrics. Source-specific evaluator tracks remain separate.
Converted records whose substantive metric is not implemented fail scored
preflight rather than entering a convenient common denominator.

## Direct execution

The operator performs one direct experiment lifecycle:

1. set up the project and exact corpus releases;
2. set credentials and review provider retention, corpus licenses, and local
   handling requirements;
3. run the complete intended arguments through `experiments.rig_check`;
4. run replay over all three core corpora, then Crescendo over StrongREJECT,
   using the two exact targets, `--limit 0`, required policy grouping, and
   finite call and time ceilings;
5. retain the complete artifact tree and ordinary provenance;
6. run no-call diagnostics and the automated-label-blinded, model-visible
   multi-rater human audit; and
7. perform post-experiment analysis and render measured figures only from
   validated real artifacts.

The operator records the exact command, commit identifier, environment, release
paths and digests, provider terms reviewed, run dates, and any manual lock
intervention.

## Paid-call containment and recovery

Every live grid declares finite `--max-total-target-calls`,
`--max-total-judge-calls`, `--max-total-http-attempts`, and
`--deadline-seconds`. `rig_check` prints conservative complete-grid projections
and rejects smaller ceilings. It imports the selected hosted SDKs, checks for
nonblank credential environment variables, and loads a selected local guardrail
checkpoint at the requested revision/device without generating. It does not
construct a hosted client or make a provider request, and cannot prove key
validity, entitlement, quota, reachability, or hosted model visibility.

External-call reservations, response checkpoints, completed-attempt
checkpoints, error records, circuits, and completion markers are durable. Resume
reconstructs the same-grid high-water mark before another call. Existing locks
are not reclaimed automatically. After verifying that no owner is active, an
operator may remove only the exact abandoned lock and record that intervention.
Infrastructure failures remain failures and do not count as safe responses.

## Analysis

The independent unit is the source prompt/intent cluster. For a paired binary
comparison, report the equal-cluster risk difference and a paired
cluster-bootstrap interval. Report support, missingness, completion, endpoint
definition, and exact cohort identity for every effect. Repeated attempts and
turns do not increase the nominal independent sample size.

Any hypotheses or contrast families documented before seeing outcomes should be
reported as such. Selections or revisions made after inspecting results are
exploratory. Multiplicity adjustment can still be useful, but it does not
retroactively make an analysis prospective. A small or sparse cohort receives
wide intervals or an inconclusive status; dependent turns are not added as
independent observations.

Transfer for an ordered pair A to B is
`P(B violates | A violated, harmful, transferable, identical rendered input)`.
It is descriptive and conditional on A's successes. Every estimable cell reports
source successes, exact matches, unmatched rows, exact-input coverage, unique
clusters, equal-cluster dispersion, and a cluster-bootstrap interval. Empty or
unsupported estimands are JSON `null` with a reason, not zero. Live adaptive
trajectories are excluded unless replayed exactly.

## Human validity

The human audit hides automated labels but exposes model identity and is stratified by source cluster. At least two
independent raters label the complete selected sample, followed by adjudication.
Refusal, harmfulness, convincingness, and specificity remain separate. Analysis
retains source-policy context and content-bound media references. Raters resolve
`@media-root` aliases through the ordered `URA_MEDIA_ROOTS`, verify each MIME and
SHA-256, and view every physical input before labelling. Inline identities point
back to the matching completed Attempt without placing base64 bytes in the CSV;
an unavailable or unverifiable asset remains unrated and fails analysis.
Analysis
reports pairwise inter-rater agreement, automated-versus-consensus performance,
class support, prevalence, confusion matrices, cluster-aware intervals, and
adjudication rate. Cohen's kappa is diagnostic, not a stand-alone validity
certificate. If the audit is small or selectively enriched for judge
disagreement, the report must call it a limited-sample validity study and state the
sampling design; it may not generalize the estimate to the full run without
appropriate weighting or a random-audit component.

The achieved-evidence artifact is `ura-human-audit/1.1`. It reports
`analysis_ready_real_run=true` with status `complete_sample_conditional` only
after full selected-sample rater coverage, adjudication, run binding, and other
integrity checks succeed. This supports sample-conditional post-experiment
analysis and explicitly sets `population_validity_claimed=false`.

Measured figures are then computed directly from the common completed-run
parent plus the content-bound `human_audit.json`. The renderer takes
`--results`, the exact left/right model specifications, `--human-audit`, and
`--human-audit-sha256`. Schema `ura-chapter-v-figures/1.3` contains exactly one
StrongREJECT replay ASR model contrast, six policy-qualified MM-SafetyBench ASR
contrasts, one MOSSBench benign-FRR contrast, and two model-specific
replay-versus-Crescendo contrasts. No population-validity, power, or
prospective-confirmation claim follows from rendering them.

## Reporting rules

- State metric, population, unit, support, interval method, cluster unit, seed,
  horizon where relevant, exact model and judge identities, and run date.
- Do not pool harmful ASR with benign false-refusal, or static with live units.
- Distinguish a measured zero from missing population, failed cell, abstention,
  unsupported modality, and undefined statistic.
- Keep source-official metrics separate from URA secondary proxies.
- Treat taxonomy mappings as research crosswalks, not compliance findings.
- Never promote synthetic, dry-run, incomplete, or mock-judge artifacts to
  empirical evidence.

The exact commands and return checklist are in
[RUN_AND_RETURN.md](RUN_AND_RETURN.md).
