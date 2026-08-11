# Chapter V experiments

Experiments are pending. Use [PROTOCOL.md](PROTOCOL.md) for the estimands and
validity rules, then execute [RUN_AND_RETURN.md](RUN_AND_RETURN.md). A dry run,
partial artifact family, placeholder model ID, or synthetic figure is not a
measured thesis result.

The maintained execution contract is Runner `ura-runner/2.4` with unified
schema `1.4`; older artifacts are not mixed into the thesis run.

## Direct lifecycle

1. Clone the project, create the Python environment, install
   `.[dev,analysis,api,guardrail]`, accept and download the exact pinned
   Llama-Guard checkpoint, and run the offline suite and synthetic smoke test.
2. Download the exact StrongREJECT, MM-SafetyBench, and MOSSBench releases and
   image assets as described in the runbook. Set `URA_<CORPUS>_PATH` and the
   ordered `URA_MEDIA_ROOTS`.
3. Set the target and judge credentials. Review corpus licenses, provider
   retention, and institutional data-handling requirements before upload.
4. Run the intended matrix arguments through
   `python -m experiments.rig_check`. Review the printed source-policy cluster
   counts and conservative target-call, local-guardrail, hosted-judge, and
   HTTP-attempt totals. The check also loads the pinned local guardrail without
   generating.
5. Run the complete replay grid over all three corpora, then the smaller
   StrongREJECT-only Crescendo grid. Both use the exact study targets,
   `--limit 0`, the full rule/guardrail/LLM trail, and finite grid-wide call and
   time ceilings.
6. Preserve the complete run artifacts, command line, project commit,
   environment inventory, and operator note.
7. Run no-call diagnostics (`paired_compare`, `judge_sensitivity`, `kappa`, and
   `transfer_matrix`) and prepare the automated-label-blinded, model-visible
   multi-rater human audit.
8. After labels and adjudication are complete, run the human-audit analysis and
   then produce appropriately qualified tables and figures.

Core CLIs:

```bash
python -m experiments.rig_check --help
python experiments/run_matrix.py --help
python -m experiments.paired_compare --help
python -m experiments.judge_sensitivity --help
python -m experiments.kappa --help
python -m experiments.transfer_matrix --help
python -m experiments.human_audit --help
python -m experiments.figures --help
```

## Planned target and modality scope

The primary target strings are:

```text
anthropic-fable:claude-fable-5;effort=high;max_tokens=25000
openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns
```

Both adapters currently declare text and image only. The replay grid executes
StrongREJECT text, complete MM-SafetyBench harmful text+image, and complete
MOSSBench benign text+image data on both targets; the Crescendo grid is
StrongREJECT text only. Coverage binds the exact
delivered combination; input-blocked and setup-only attempts do not count.
Audio and video are unavailable on both study targets and are reported as such,
not replaced with text fallbacks.

MM-SafetyBench common ASR is a secondary URA proxy; its official scenario-aware
evaluator is not executed. MOSSBench common false-refusal rate is also
secondary; its official image-conditioned evaluator is not executed. Keep both
distinctions in every table and claim. Because MM-SafetyBench spans six source
policies, matrix commands containing it group by
`source_policy_id,source_policy_version`.

StrongREJECT is the official 313-row, six-category, 313-unique-prompt CSV at
commit `f7cad6c17e624e21d8df2278e918ae1dddb4cb56`, normalized SHA-256
`4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`.
The maintained score is explicitly StrongREJECT-style; it is not a claim that
the upstream official evaluator ran.

## Real-run invariants

- Real corpora resolve through `URA_<CORPUS>_PATH` and must pass their pinned
  release contracts. `--limit N` counts source prompt/intent clusters and keeps
  every row in each selected cluster; the complete thesis grid uses `--limit 0`.
- Local media artifacts use `@media-root/<index>/<relative-path>`. Preserve the
  configured media-root order and relative layout on resume or another machine.
- Every paid grid declares finite target-call, judge-call, HTTP-attempt, and
  time ceilings. `rig_check` rejects ceilings below its conservative grid
  projection, imports selected hosted SDKs, loads the exact local guardrail,
  and requires nonblank credential environment variables without making a
  provider request. It
  cannot establish credential validity, account access, model visibility, or
  quota.
- Preserve durable budget, circuit, lock, checkpoint, completion, and error
  artifacts and resume from the same directory. Recovery validates the
  same-grid high-water mark before another call. Existing locks are never
  reclaimed automatically.
- Optional local configuration is keyed by each exact target specification and
  declares exactly one immutable revision or digest plus supported modalities.
- Missing, failed, unsupported, abstained, and mathematically undefined states
  remain distinct and are never rewritten as zero.

## Analysis and reporting

The primary comparison is paired by source cluster within exact benchmark,
source policy, modality, target condition, attack, judge, and budget. Direct
paired intervals are reported on risk differences. If multiple comparisons are
selected after seeing the data, they are explicitly exploratory and any
multiplicity adjustment is described as post-experiment analysis, not
prospective confirmation.

Transfer is conditional and descriptive:
`P(B violates | A violated, harmful, transferable, identical rendered input)`.
It reports exact-input coverage, equal-cluster support, dispersion, and a
cluster-bootstrap interval. No source successes or no exact matches yields
`null` with a reason rather than zero. Live Crescendo is excluded unless
replayed exactly.

Judge sensitivity reuses completion-validated shadow trails and makes no target
calls. Unparsed or low-confidence stages are abstentions. The automated-label-blinded, model-visible human
audit samples complete source clusters, requires at least two independent
raters plus adjudication, and separates refusal, harmfulness, convincingness,
and specificity. Its CSV preserves the source-policy ID, version, intended
metric, and short rater instruction. Physical inputs are content-bound in
`media_references`: local assets use `@media-root/<index>/<relative-path>` and
inline assets use `@inline-sha256/<digest>` without embedding bytes. Raters must
resolve `URA_MEDIA_ROOTS` in order, verify MIME and SHA-256, and view every asset
before labelling; unresolved media stays unrated and analysis fails closed.
Agreement results must state the population, support,
interval, endpoint definition, and cluster weighting. With a small audit, all
validity conclusions are limited-sample evidence with intervals. The achieved
audit artifact uses schema `ura-human-audit/1.1`; only an integrity-complete
real-run artifact reports `analysis_ready_real_run=true` and status
`complete_sample_conditional`. That status does not assert population validity.

Measured figures may be produced only after the real grid and human audit are
complete. Until then, tracked images are visibly watermarked synthetic layout
previews with neutral condition labels.

After `human_audit.json` is complete, measured mode reads the completed runs
directly rather than an intermediate analysis artifact:

```bash
python -m experiments.figures \
  --results runs/main \
  --left-model "$FABLE" --right-model "$SOL" \
  --human-audit runs/main/human_audit.json \
  --human-audit-sha256 "$HUMAN_AUDIT_SHA256" \
  --out runs/main/figures
```

Its `ura-chapter-v-figures/1.3` sidecar records one StrongREJECT model point,
six MM-SafetyBench policy points, one MOSSBench benign-FRR point, and two
model-specific adaptivity points. These are sample-conditional post-experiment
estimates, without a population-validity, power, or prospective-confirmation
claim.

## Return package

Return the complete artifact directory, including attempts, responses, shadow
trails, judgments, manifests, completion and error records, budgets, circuits,
locks or intervention notes, modality plans/results, diagnostics, human-audit
files, figures and provenance, logs, environment inventory, commit identifier,
and run note. Do not return only aggregates.
