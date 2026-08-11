# URA-Bench

URA-Bench is the research software for the master's thesis *A Risk-Assessment
System for Question Answering by Multimodal Language Models*. It converts safety
corpora to one typed schema, runs static or response-conditioned attacks against
hosted or local targets, shadow-scores every response, and retains auditable
lineage for later analysis.

Experiments are pending. The repository establishes no model ranking, defense
effect, compliance finding, or other empirical result yet.

## What is measured

- Harmful ASR/refusal and benign false-refusal rate use disjoint denominators.
- Live trajectories report conversation ASR, robust refusal, a Kaplan--Meier
  curve, observed median turns-to-break when estimable, and challenge-horizon
  restricted mean turns-to-break. Setup turns remain provenance only.
- Repeated seeds, turns, and source variants are clustered by their originating
  prompt or intent; paired effects give source clusters equal weight.
- Static transfer requires the same harmful rendered input. Live adaptive
  conversations are not transferable unless replayed exactly.
- MM-SafetyBench common ASR and MOSSBench common false-refusal rate are secondary
  URA proxies. They are not the sources' official metrics unless those official
  evaluators run.
- MM-SafetyBench's six source-policy strata remain separate. A pooled number is
  descriptive only and must publish its weights.

The absence of a universal safety score is deliberate: every estimate is
conditioned on a benchmark, policy, modality, judge, attack budget, and served
model snapshot. Cross-provider differences are associations, not causal effects
of one training or safety mechanism.

See [metrics](docs/METRICS.md), [schema](docs/SCHEMA.md),
[architecture](docs/ARCHITECTURE.md), and the complete
[operator runbook](experiments/RUN_AND_RETURN.md).

## Offline smoke test

Python 3.12 is the supported baseline.

```bash
python -m pip install -e ".[dev,analysis]"
python -m pytest
python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
python -m experiments.figures --synth --out runs/_figcheck
```

Dry-run and synthetic output are plumbing evidence only and cannot enter the
thesis results.

## Planned comparison

The executable case study is the exact account-visible Claude Fable endpoint
versus GPT-5.6 Sol through the Responses API:

- `anthropic-fable:claude-fable-5;effort=high;max_tokens=25000`
- `openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns`

It is a cross-provider endpoint comparison, not a same-base ablation or a causal
estimate of a safety mechanism. Fable thinking and Sol encrypted reasoning or
assistant-output state are retained only as needed for provider-faithful
stateless continuation and checkpoint resume.

Mythos remains relevant frontier-security literature and a possible future
replication target, but the researcher has no access. It is not an executable
target, roster row, or measured effect in this study.

## Multimodality

The canonical Fable and Sol adapters currently declare text and image support.
The all-corpus replay grid therefore runs every supported modality combination
present in its selected releases on both targets:

- StrongREJECT: text;
- MM-SafetyBench: harmful text+image;
- MOSSBench: benign text+image.

Before calls, `modality_coverage_plan` verifies the selected combinations. After
execution, `modality_coverage_result` requires real eligible Attempt--Response
evidence for each exact delivered combination. An input-defense block or a
setup-only turn is not execution evidence; an output-defense block after a real
target call is. Audio and video are unavailable on both study adapters and are
reported unavailable rather than fabricated, silently dropped, or replaced by
captions.

## Direct real-run lifecycle

The runbook is the canonical from-zero procedure:

1. download the project and create its Python environment;
2. download the exact corpus releases, place their image assets, and set
   `URA_<CORPUS>_PATH` plus ordered `URA_MEDIA_ROOTS`;
3. set the target and judge credentials and review provider retention and
   corpus-license constraints;
4. run `python -m experiments.rig_check` with the intended matrix arguments;
5. run the complete all-corpus replay grid and the StrongREJECT-only Crescendo
   grid with finite target-call, judge-call, HTTP-attempt, and time ceilings;
6. run diagnostics and the automated-label-blinded, model-visible multi-rater
   human audit; and
7. retain the complete artifact tree, command line, commit identifier,
   environment inventory, and run note for post-experiment analysis.

## Real-run gates

- Real corpora resolve through `URA_<CORPUS>_PATH`. Local media also needs an
  approved, ordered `URA_MEDIA_ROOTS` list. Persisted media paths are portable
  `@media-root/<index>/<relative-path>` aliases; resume must rebind the same
  ordered roots and relative layouts.
- StrongREJECT, MM-SafetyBench, and MOSSBench enforce pinned official release
  identities. The StrongREJECT gate is the official CSV at commit
  `f7cad6c17e624e21d8df2278e918ae1dddb4cb56`, normalized SHA-256
  `4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`,
  313 rows, all six categories, and 313 unique nonblank prompts. URA reports a
  StrongREJECT-style judge; it does not claim to execute the official evaluator.
- Before each paid grid, `python -m experiments.rig_check` repeats corpus,
  release, policy, component, modality, source-metric, credential-presence, and
  budget checks without constructing a hosted client or making a generation
  call. A selected local guardrail is loaded at its exact revision and device
  before any paid call. The check prints selected source-policy counts and
  conservative target, local-guardrail, judge, and HTTP-attempt upper bounds. It cannot prove account access,
  entitlement, quota, reachability, or model visibility.
- Every live grid sets finite matrix-wide target-call, judge-call, HTTP-attempt,
  and wall-clock ceilings. Resume validates the durable ledger, checkpoints,
  completion records, errors, and circuit state before another external call.
- A real LLM judge needs an exact non-mock `--judge-model`. A model guard needs
  an immutable `--guardrail-revision`.
- Optional local targets use `--local-config` keyed by the exact local spec,
  with exactly one immutable `revision` or `digest` and an explicit
  `modalities` list.
- Missing media, unsupported modality, source-policy drift, provider/model
  identity drift, a failed cell, an abstention, and an undefined statistic stay
  distinct. None is rewritten as zero.

`--limit N` means at most N unique source prompt/intent clusters while retaining
all rows in each selected cluster. The complete thesis run uses `--limit 0`.

## Artifacts and recovery

Each cell can produce exact attempts, responses, authoritative judgments,
full-shadow trails, aggregate results, a manifest, an append-only checkpoint,
and either a validated completion marker or an error record. A matching
completion marker makes a rerun call-free. A matching checkpoint restores
completed attempts and provider continuation state without querying them again.
Partial artifact families, unresolved locks, exhausted ceilings, or provenance
drift fail explicitly.

Runner `ura-runner/2.4` writes unified schema `1.4`. In a Crescendo trajectory,
benign setup turns receive typed `not_applicable` judgments and no judge call or
metric contribution. Policy challenges are numbered contiguously from zero,
share one declared challenge horizon, and a harmful authoritative violation is
terminal.

## Human validity and post-experiment analysis

The automated-label-blinded, model-visible human audit samples complete source
clusters, uses at least two independent raters plus adjudication, keeps refusal,
harmfulness, convincingness, and specificity separate, and reports inter-rater
as well as automated-versus-consensus agreement with cluster-aware uncertainty.
The resulting `ura-human-audit/1.1` artifact becomes
`complete_sample_conditional` and `analysis_ready_real_run=true` only when the
achieved labels and run binding pass every integrity check. This permits
sample-conditional analysis; it does not claim population-wide judge validity.
Cohen's kappa is diagnostic and must be accompanied by support and intervals.

Paired effects, judge sensitivity, kappa, transfer, and figures are computed
only from completion-validated recorded artifacts and make no new target calls.
Until the real matrix and human audit exist, these tools demonstrate analysis
capability rather than empirical findings.

Measured figures are built directly from the common completed-run parent and
the content-bound `human_audit.json` using `--results`, the two exact model
specifications, `--human-audit`, and `--human-audit-sha256`. Their
`ura-chapter-v-figures/1.3` provenance contains exactly one StrongREJECT replay
ASR contrast, six policy-specific MM-SafetyBench ASR contrasts, one MOSSBench
benign-FRR contrast, and two model-specific replay-versus-Crescendo contrasts.

## Source-specific tracks

R-Judge and GPTGeoChat use their own classification metrics rather than common
ASR/FRR. Other convertible agent/runtime sources may fail scored preflight until
their substantive runtime or evaluator exists; conversion support is not
scoring support. See the protocol for the current inventory.

## Layout

```text
src/ura/       schema, converters, adapters, targets, judges, runtime
tests/ura/     offline regression and integration tests
experiments/   matrix execution, diagnostics, human audit, analysis, figures
docs/          architecture, schema, metrics, taxonomy and native imports
datasets/      local dataset area; released corpora are not redistributed
```

Model inputs, outputs, provider state, and human-audit exports can be harmful or
sensitive. Keep them access-controlled and follow [SECURITY.md](SECURITY.md).
Taxonomy mappings are informational crosswalks, not certifications.

Apache-2.0; see [LICENSE](LICENSE).
