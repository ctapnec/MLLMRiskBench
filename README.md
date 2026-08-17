# URA-Bench

URA-Bench is the research software for the master's thesis *A Risk-Assessment
System for Question Answering by Multimodal Language Models*. It converts safety
corpora to one typed schema, runs static or response-conditioned attacks against
hosted or local targets, shadow-scores every response, and retains auditable
lineage for later analysis.

Experiments are pending. The repository establishes no model ranking, defense
effect, compliance finding, or other empirical result yet.

The development tree implements the RUN-001 prospective-request and MET-001
exact-selection interfaces described below, with offline contract tests. The
latest exact tested software revision, raw local/rig logs, rendered dashboard
and Build pages, project-revision receipt and source bundle are retained under
`../../Thesis-EN/verification/2026-08-17-campaign-status-harmbench/`; that
record is the authority for its exact commit and verification results. The
earlier quantization and dashboard/filter records remain historical evidence
for their own snapshots. A retained
26-arm receipt is historical acquisition/conversion
traceability, not current admission or a result: the current audit found no new
issue in 19 entries; the SIUO, VLSBench, MLLMGuard position-swapping and
noise-injection, and both Video-SafetyBench mapping reviews are superseded; and
VLSBench/JALMBench upstream export accounting needs refreshed retained
summaries. No provider, human-audit, or real-input MET-001 result exists.

## What is measured

- Harmful ASR/refusal and benign false-refusal rate use disjoint denominators.
- Live trajectories report conversation ASR, robust refusal, a Kaplan-Meier
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
env -u URA_PROJECT_REVISION_MANIFEST -u URA_PROJECT_REVISION_SHA256 \
  python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
python -m experiments.figures --synth --out runs/_figcheck
```

The rig's local-vLLM environment is installed from the checked-in extra rather
than from separate version variables:

```bash
python -m pip install -e ".[dev,analysis,api,guardrail,local-vllm,harmbench]"
python -c "import bitsandbytes, datasketch, en_core_web_sm, psutil, ray, spacy, torch, vllm; print(vllm.__version__, bitsandbytes.__version__, psutil.__version__, torch.__version__, datasketch.__version__, ray.__version__, spacy.__version__)"
```

`local-vllm` pins the tested `vllm==0.27.1` and `bitsandbytes==0.49.2` pair;
`psutil>=7.2,<8` is a normal project dependency used for the startup CPU/core/RAM
snapshot. The `harmbench` extra pins the tested prepared-workflow dependencies,
including `datasketch` and the SHA-256-bound `en_core_web_sm` model required by
the pinned HarmBench checkout.

Dry-run and synthetic output are plumbing evidence only and cannot enter the
thesis results. This explicit offline form records
`project_revision.mode=not_required_diagnostic_dry_run`; every non-dry Runner
invocation instead requires the exact project-revision receipt described below.

## Planned experimental programme

The experiment is a **tiered suite**, not a two-model leaderboard. The focal
paired comparison is specified as the following exact Claude Fable and GPT-5.6
Sol routes, subject to authorized-account live attestation:

- `anthropic-fable:claude-fable-5;effort=high;max_tokens=25000`
- `openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns`

It is supplemented by descriptive hosted and local breadth. Hosted candidates
include configured Claude, Gemini, DeepSeek, Kimi, Qwen and GLM routes whose
account visibility has not yet been established;
local candidates include an open multimodal instruction model and, where the
exact artifacts remain obtainable, a same-base unguarded/guarded pair. Those
names are candidate families, not guaranteed endpoint identifiers. Every
generic hosted route is bound by `--api-config`, every local route by
`--local-config`, and each exact model/modality pair must pass a bounded live
transport attestation before entering a measured cell. An inaccessible,
silently aliased or stale route is blocked with a reason; structural capability
incompatibility remains `N/A` rather than being counted as a failed experiment.

Local startup uses `psutil`/platform probes for OS, CPU, physical/logical cores
and RAM, and `nvidia-smi` for each GPU model, VRAM, PCI id, compute capability
and driver. The dashboard and Build tab show this snapshot. Build filters hosted
targets by provider (`All` by default). Local vLLM filters combine an immediate
case-insensitive name substring, a synchronized 10M-3T maximum-parameter
slider/numeric input, and a separate `Automatic 16/8/4-bit fit` card (on by
default). A separate `Include unknown fit` checkbox is off by default. Hardware
auto-selection chooses the highest precision that fits:
unquantized 16-bit BF16/FP16, then FP8 8-bit on SM 7.5+, then BitsAndBytes 4-bit
on SM 7.0+. Known recommendations are badged green for 16-bit, blue for 8-bit,
or amber for 4-bit; unknown fit is neutral gray. Per-model quantization
overrides the command override, which overrides hardware auto-selection; the
dropdown labels the 16-, 8-, and 4-bit choices explicitly. Compatible local rows
use a single-choice radio and remain selectable when their roster revision is
still `OPERATOR_TODO`, but every non-dry submission requires an exact immutable
revision or digest before any subprocess starts. Expert/MoE-ambiguous names do
not infer a dense total: fit stays unknown, so no download/fit is implied. These
rows stay hidden until `Include unknown fit` is selected or
`parameter_count_b` is declared. Hardware-auto remains blocked for
a live unknown-fit row; an explicit per-model choice (`none`, `fp8`,
`bitsandbytes`, `awq`, or `gptq`) writes the narrow
`allow_unknown_fit: true` opt-in and permits an operator-owned load attempt.
Known incompatibility, invalid topology, or missing hardware stays blocked, and
dependency/runtime allocation failures fail during local preflight before
target/judge calls. On
the actual two-24,564-MiB rig, FP8 does not fit a 70B profile, so it is rostered
only as an in-flight 4-bit BitsAndBytes, tensor-parallel-2 candidate rather than
an unquantized model.
The optional vLLM-only `max_model_len` field is an engine-context and KV-cache
admission cap, not the response-generation `max_tokens` bound. Omission leaves
the checkpoint's native context unchanged; an explicit integer in 1..1,000,000
is passed to vLLM at engine construction, and `max_tokens` may not exceed it.
Rig Web preserves the field in its selected local config, and the normalized
value enters grid/run provenance. Each Build row labels either the explicit
context cap or native model context.

The dependency check on that rig used Python 3.12.13, vLLM 0.27.1,
BitsAndBytes 0.49.2, psutil 7.2.2 and torch 2.13.0+cu130/CUDA 13.0. The
BitsAndBytes import/self-diagnostic succeeded; CUDA exposed two GPUs with
maximum compute capability 8.9; the system probe reported 24 logical CPUs and
134,974,398,464 bytes of RAM; and `pip check` was clean after removing an
unused orphaned `datasets 2.14.7` installation. This verifies the environment
and UI/admission prerequisites, not model inference; no provider/model call was
made.

Runner 2.16 makes that prerequisite machine-checked. A bounded non-dry
`--attestation-probe` grid is converted by `experiments.live_attestation` into a
content-addressed `ura-live-attestation/2` receipt. An ordinary measured grid
must supply the exact receipt bytes and digest, the same operator-declared
execution scope, and a maximum permitted age. Requested/base-resolved target,
secret-free route configuration, exact delivered modality combination,
observation time, harness/driver source digests, and realized provider/runtime
identity are matched before
target calls; a newly returned or restored response must still match the stable
attested identity. This is historical route/access/byte-backed-transport
evidence only. It proves no safety, evaluator, benchmark, human-validity,
account-equivalence, or future-availability claim.
The recorded observation is the probe Runner manifest's content-bound UTC
`started_at`, deliberately used as a conservative lower bound rather than the
outer grid's mutable `finished_at` packaging field.

The focal contrast is cross-provider and associational, not a same-base
ablation or a causal estimate of a safety mechanism. Broader roster rows are
descriptive replication/coverage evidence. A verified local same-base defense
pair is the appropriate design for a defense effect. Fable thinking and Sol
encrypted reasoning or assistant-output state are retained only as needed for
provider-faithful stateless continuation and checkpoint resume.

Mythos remains relevant frontier-security literature and a possible future
replication target, but the researcher has no access. It is not an executable
target, roster row, or measured effect in this study.

## Sources, modalities, and native engines

The common runner exposes 19 converter families: AdvBench, AgentHarm, BIPIA,
CyberSecEval, FigStep, GPTGeoChat, HarmBench, InjecAgent, JailbreakBench,
JailBreakV, JALMBench, MLLMGuard, MM-SafetyBench, MOSSBench, R-Judge, SIUO,
StrongREJECT, Video-SafetyBench, and VLSBench. A `--source-config` inventory can
bind multiple independently labelled source instances to those converters
without persisting operator-specific absolute paths. Conversion is not an
automatic claim of scored-run eligibility: a source-specific evaluator that is
not implemented fails pre-call rather than being squeezed into common ASR.
The current 39-arm disposition is 22 common-metric arms, two implemented
source-classification arms, and 15 conversion-only arms pending their exact
source scorer or runtime.

Nine end-to-end projects - AgentDojo, ASB, AutoDAN-Turbo, EasyJailbreak, FuzzyAI,
Garak, Giskard v2, Petri, and Promptfoo - run upstream under their own contracts.
Their complete outputs are normalized by `experiments.native_import`; they are
not reduced to generated prompts and replayed as if that reproduced the native
experiment.

Before configuration loading or corpus conversion, `run_matrix` writes a strict,
content-addressed `ura-request-envelope/1`. It fixes the operator-selected
requested-target x logical-source-arm x attacker universe as prospective
whole-arm request units; it does not invent source-policy or modality strata.
Pre-materialization failures after that boundary use bound
`ura-request-error/1` artifacts that explicitly deny execution and provider
calls. Basic CLI/argument-shape failures rejected before the envelope boundary
remain outside this accounting surface.

For each source instance and model, the planner admits only the exact
source-present modality combination declared by the target. Before calls,
the content-addressed `ura-eligibility-plan/1` ledger retains each requested
selected-source stratum as `compatible_if_isolated` or `N/A`, together with its
whole-arm execution-unit status and failed gate, and
`modality_coverage_plan` verifies the admitted intersection; afterward,
`modality_coverage_result` requires real eligible Attempt-Response evidence for
each delivered combination. The eligibility ledger is planning evidence, not
live attestation or completed execution. An input-defense block or setup-only turn is not
execution evidence; an output-defense block after a real target call is. Image,
audio, video, and agent/tool lanes remain pending until their byte-level source,
transport, target capability, runtime, and evaluator gates pass. Media is never
silently removed, caption-substituted, or counted merely from a tag.

`python -m experiments.level1_evidence` performs the bounded lifecycle join.
The operator supplies the existing eligibility files and result roots; the
command automatically discovers their request envelopes and bound early
errors. It writes `ura-level1-evidence/2` JSON plus the existing deterministic
materialized-planning-stratum CSV. Prospective whole-arm request units remain a
separate, unit-labelled JSON collection rather than being mixed into that CSV.
Bound early errors can mark applicable prospective units blocked, but never
fabricate strata, attempts, or provider calls.

Repeatable typed live-attestation inputs are validated against every measured
grid's content-bound receipt projection. Analysis inclusion is deliberately
left `status=not_supplied` with null counts; it is never guessed from directory
placement. Probe, preflight, and diagnostic-canary artifacts are rejected from
Level-1, and dry-run and measured requests cannot be mixed. Every Level-1
artifact records `empirical_validity_established=false`.

## Direct real-run lifecycle

The runbook is the canonical from-zero procedure:

1. select a prospectively reviewed full 40-hex project commit, check it out
   detached, create and validate one content-addressed
   `ura-project-revision/1` receipt from that clean checkout, export its path and
   SHA-256, and create the Python environment;
2. download the selected releases from the 19-converter inventory, copy the
   checked-in source-instance example to the ignored operator-local registry,
   configure its independently labelled instances, bind ordered media roots,
   and validate one compact content-addressed `ura-source-conformance/1`
   receipt; for VLSBench/JALMBench prepared manifests, retain each exporter
   summary as a hashed receipt component and count the upstream exporter input,
   not only JSONL lines;
3. set the target and judge credentials and review provider retention and
   corpus-license constraints;
4. run `python -m experiments.rig_check` with the intended matrix arguments,
   retain its content-addressed lane projection, and approve complete-grid
   provider and operator caps;
5. run bounded exact target/modality probes, derive and hash their typed
   receipts, then pass the receipts and the same non-secret execution-scope ID
   to every measured `run_matrix` lane;
6. run the eligibility-scoped static, adaptive, multimodal, local-defense,
   source-specific, and native-engine lanes with finite call/time ceilings;
7. import native outputs, build the unit-qualified Level-1 lifecycle artifact and separate
   no-pooling suite evidence inventory, run diagnostics, and
   perform the automated-label-blinded, model-visible
   multi-rater human audit across the achieved common-eligible arms; the declared
   focal conditions follow the same achieved-sample rule, not a reserved quota;
  and
8. revalidate the same local checkout and retain the complete artifact tree,
   including the VLSBench/JALMBench exporter summaries when those arms are used,
   project-revision receipt and digest, separately self-recorded checkout status,
   command line, upstream commits, environment inventory, and run note for
   post-experiment analysis.

## Real-run gates

- `URA_PROJECT_REVISION_MANIFEST` and `URA_PROJECT_REVISION_SHA256` bind one
  digest-approved `ura-project-revision/1` receipt. Every non-dry `rig_check`,
  target probe, diagnostic canary, and measured Runner request requires it.
  Expected and observed full commits, HEAD tree, common driver/harness Git root,
  clean tracked state, and actual driver/harness source digests are checked and
  carried through eligibility, grid, manifest, completion, and postprocessing
  identities. A revision change starts a prospectively recorded new cohort; it
  cannot resume or pool under an old identity. This is local source provenance,
  not remote authenticity, dependency/upstream identity, or empirical evidence.
- Real corpora resolve through `URA_<CORPUS>_PATH`. Local media also needs an
  approved, ordered `URA_MEDIA_ROOTS` list. Persisted media paths are portable
  `@media-root/<index>/<relative-path>` aliases; resume must rebind the same
  ordered roots and relative layouts.
- Every non-synthetic measured run and every no-call `rig_check` preflight
  requires the exact compact
  `URA_SOURCE_CONFORMANCE_MANIFEST` and
  `URA_SOURCE_CONFORMANCE_SHA256`. The selected arms must be admitted, their
  operator reviews complete, and their declared source files unchanged. The
  driver separately reuses its runtime converter, cluster, policy, metric, and
  media evidence rather than asking the operator to duplicate those inventories
  by hand. See
  [`docs/SOURCE_CONFORMANCE.md`](docs/SOURCE_CONFORMANCE.md).
  A real-source `run_matrix --dry-run` may omit the receipt only as a conversion
  diagnostic; it is not admitted experiment or preflight evidence.
- Release-pinned converters enforce their implemented official contracts. The
  StrongREJECT gate, for example, is the official CSV at commit
  `f7cad6c17e624e21d8df2278e918ae1dddb4cb56`, normalized SHA-256
  `4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`,
  313 rows, all six categories, and 313 unique nonblank prompts. URA reports a
  StrongREJECT-style judge; it does not claim to execute the official evaluator.
- Before each paid grid, `python -m experiments.rig_check` repeats corpus,
  release, policy, component, modality, source-metric, credential-presence, and
  budget checks without constructing a hosted client or making a generation
  call. A selected local guardrail is loaded at its exact revision and device
  before any paid call. The check prints selected source-policy counts and
  conservative target, local-guardrail, judge, and HTTP-attempt upper bounds. It
  retains the exact `ura-lane-projection/1` artifact alongside the eligibility
  plan. The projection records selected input-media bytes when physical media
  are present, while token use, price/cost, runtime/throughput, and expected
  output storage remain `CANNOT-VERIFY`. It cannot prove account access,
  entitlement, quota, reachability, or model visibility.
- `rig_check` and `--dry-run` neither require nor accept live-attestation
  arguments. A probe requires one real target, one source arm, replay, one seed,
  one query/turn, no defense, `--limit 1` or `2`, and a non-secret
  `--execution-scope-id`. A fully synthetic probe can attest text or the supplied
  text+one-pixel-image transport without a source receipt or human work; it still
  makes a real target call and is never benchmark evidence. There is currently
  no synthetic audio/video probe.
- Every ordinary non-dry `run_matrix` grid requires repeatable paired
  `--live-attestation`/`--live-attestation-sha256` inputs, the same
  `--execution-scope-id`, and a positive
  `--live-attestation-max-age-hours`. Exact combinations are not substitutable:
  text+image does not attest text alone. Missing, stale, future-dated,
  scope/route/config/resolved-target-mismatched, ambiguous, or identity-drifting
  evidence fails closed before a measured target call. The scope label is an
  operator assertion, not a credential or independently verified proof that two
  accounts/environments are equivalent.
- Every live grid sets finite matrix-wide target-call, judge-call, HTTP-attempt,
  and wall-clock ceilings. Every non-dry provider-backed ceiling must cover the
  complete conservative projection; a deliberately undersized cap is rejected
  before a provider call rather than producing a paid partial grid. The exact
  measured grid binds its own projection artifact. Provider-side project quota
  and explicit operator approval remain separate prerequisites. Resume validates the durable ledger, checkpoints,
  completion records, errors, and circuit state before another external call.
  Durable ledger replacement retries only a few bounded times for transient
  Windows sharing violations, then still fails closed.
- A real LLM judge needs an exact non-mock `--judge-model`. A model guard needs
  an immutable `--guardrail-revision`. A model-backed defense uses a separately
  identified guard and explicit device; it must not certify its own output via
  the same guard instance used as the scoring judge.
- Generic hosted targets are selected through `--api-config`; corpus-arm
  instances are selected through `--source-config`. Those reusable-file hashes
  are **configuration-registry** provenance, not acquisition evidence. The
  separate compact source-conformance receipt records operator-observed
  release/file/review evidence. For an exporter-prepared manifest it also binds
  the export summary and reconciles upstream discovered/accepted/excluded counts;
  only its normalized selected subset enters grid/run identity. Secrets and
  literal local paths are excluded.
- Optional local targets use `--local-config` keyed by the exact local spec,
  with exactly one immutable `revision` or `digest` and an explicit
  `modalities` list.
- Missing media, unsupported modality, source-policy drift, provider/model
  identity drift, a failed cell, an abstention, and an undefined statistic stay
  distinct. None is rewritten as zero.

`--limit N` means at most N unique source prompt/intent clusters while retaining
all rows in each selected cluster. For the same converted-corpus digest and
sample seed, real-source limits are deterministic nested prefixes, so the
one-cluster canary is contained in a later `N`-cluster sample. The complete
thesis run uses `--limit 0`.

## Artifacts and recovery

Each cell can produce exact attempts, responses, authoritative judgments,
full-shadow common-response trails or explicit unqueried source-metric
placeholders, aggregate results, a manifest, an append-only checkpoint,
and either a validated completion marker or an error record. A matching
completion marker makes a rerun call-free. A matching checkpoint restores
completed attempts and provider continuation state without querying them again.
Partial artifact families, unresolved locks, exhausted ceilings, or provenance
drift fail explicitly.

A separately typed `--diagnostic-canary` executes exactly one target, logical
source arm, attacker, seed, and whole source cluster. Its strict offline
`ura-lane-canary/1` summary is labelled `synthetic_offline` for
`--dry-run --corpora synth` or `live_diagnostic` for a live-attested route. It
separates conservatively reserved logical calls/HTTP-attempt exposure from
client-reported observed transport attempts and records which target, defense,
source evaluator, and judge stages were actually exercised. One cluster cannot
establish population latency, throughput, cost, expected storage, safety, or
human validity. Diagnostic canaries are rejected from Level-1, suite summary,
paired/transfer analysis, human-audit preparation, and measured figures. Native
framework canaries remain external to the Runner and outside native imports.
Canonical native envelopes retain their upstream project revision and have no
Runner `RunManifest`; the URA revision that performed their import is retained
in the return-package/importer context rather than relabelled as an upstream
native field.

Runner `ura-runner/2.16` writes unified schema `1.4`. Immutable planning/source
stratum identity is stored separately from adaptive per-turn evaluation
identity. Thus a Crescendo setup turn remains joined to its original planning
stratum while receiving a typed `not_applicable` judgment and no judge call or
metric contribution. Policy challenges are numbered contiguously from zero,
share one declared challenge horizon, and a harmful authoritative violation is
terminal.

## Human validity and post-experiment analysis

The automated-label-blinded, model-visible human audit samples complete source
clusters, uses at least two independently qualified raters under the declared
language/experience, conflict, training, and out-of-sample pilot criteria,
requires adjudication for every
non-unanimous composite or dimension, keeps refusal, harmfulness,
convincingness, and specificity separate, and reports inter-rater as well as
automated-versus-consensus agreement with cluster-aware uncertainty.
Its deterministic selector derives non-vacuous coverage requirements from every
observed common-eligible run/model/defense/attacker/source-policy/population arm
at overall and exact risk/modality scope; an undersized requested sample fails.
Judge-validity reports are primary within exact run, response-producing arm,
logical corpus, source policy, modality, expected population, and
common-eligibility strata. They report decision coverage, treat violation as the
harmful adverse event and over-refusal as the benign adverse event, and label
their intervals as conditional on defined bootstrap replicates. Cross-stratum
pooled values are explicitly composition-dependent diagnostics.
The resulting `ura-human-audit/1.1` artifact becomes
`complete_sample_conditional` and `analysis_ready_real_run=true` only when the
achieved labels and run binding pass every integrity check. This permits
sample-conditional analysis; it does not claim population-wide judge validity.
Cohen's kappa is diagnostic and must be accompanied by support and intervals.

Paired effects, judge sensitivity, kappa, transfer, and figures are computed
only from completion-validated recorded artifacts and make no new target calls.
Until the real matrix and human audit exist, these tools demonstrate analysis
capability rather than empirical findings.

The existing figure renderer remains a focal-analysis surface: measured figures
are built directly from completion-validated runs and the content-bound
`human_audit.json`. Logical corpus-arm aliases avoid duplicate focal calls. When
the audit covers a broader run tree, each focal run must occur in the labelled
cohort and its exact logical-corpus/source-policy/arm effect must exist in the human sensitivity
analysis. It does not summarize the whole broad suite. Cross-source
coverage and results are inventoried separately by `experiments.suite_summary`,
which keeps every rate in its exact model/source/policy/modality/attacker/defense
stratum and every native aggregate on its upstream scale.

## Source-specific tracks

R-Judge and GPTGeoChat use their own classification metrics rather than common
ASR/FRR. Other convertible agent/runtime sources may fail scored preflight until
their substantive runtime or evaluator exists; conversion support is not
scoring support. See the protocol for the current inventory.

## Rig console and campaign builder

`python -m experiments.rig_web` serves a single-operator, localhost-only
campaign builder and console over the same maintained CLIs: mode-aware lane
composition (an ordinary offline dry run over the synthetic corpus, attestation
probe, diagnostic canary, measured execution) with complete server-side
fail-closed admission - exact-modality compatibility of every target/attacker
with each arm, agentic/native-only attackers shown disabled rather than as
common lanes, and scoring-vs-defense guardrail separation - before any
subprocess. Source arms lacking an integrated evaluator remain selectable so the
programme stays visible, but carry one concise `no evaluator` badge with one
custom hover/focus tooltip containing the exact reason; submitting one is
rejected server-side before a subprocess and never presented as runnable.
Dry-run composition drops selected
real API/local targets and their configs because `run_matrix --dry-run` always
uses `MockTarget`. Local roster modalities are limited to Runner-supported text
and image, so an audio arm/target mismatch is rejected by UI parity. The
builder covers all 39 maintained source arms. T3MP3ST and HarmBench are
selectable attacker lanes after their prepared artifact is supplied. The same
Build page exposes the separate preparation commands: T3MP3ST captures an exact
planning bundle, while HarmBench captures generated text cases and writes the
matching attacker config. These preparation jobs can use source-model or GPU
compute; the measured Runner only validates and replays their content-addressed
outputs. The Build preparation workflow resolves a symlinked configured results
root before invoking either producer and emits canonical absolute artifact paths
for runtime use. The native artifact readers still reject paths containing a
symlink component. `run_matrix` removes those host-only paths before persistence
and retains only the verified content identity.
Before a paid mode, it shows the exact argv and offers a no-call preflight
whose lane-projection gives the
required target/judge/HTTP call upper bounds; Start is blocked until the entered
ceilings cover that projection (a call bound, not a price estimate). It also
offers job monitoring with a verified whole-process-tree stop (an unconfirmed
stop is surfaced, never reported as success), an allowlisted JSON editor for the
operator-local registries, rendering of retained Level-1/Level-2 artifacts (one
diagram per compatible metric stratum, measured badged only for the exact
measured evidence kind), and recorded-token usage with calculated cost. Cost
multiplies recorded tokens by the rate effective on each run's completion date
(an old run is never repriced by a later reindex) from an operator-controlled
pricing registry containing manual or provenance-labelled fetched rates; mixed
currencies are never summed, a missing count or price renders N/A never zero,
and local serving is not billable. Its state (jobs, campaign runs, recorded
usage, report index) lives in a stdlib-sqlite `console.db` under the console
state directory - operational state only; the validated filesystem artifacts
remain the scientific authority. Every experiment operation the console launches
runs the same maintained `experiments.*` command available on the CLI
(`--models` resolves names via the hosted/local target registries on
`run_matrix`/`rig_check`; `live_attestation --validate` revalidates a receipt),
and the console's own bookkeeping is reachable headlessly too (`rig_web
--reindex`, `rig_web --usage-report`).

`experiments/rig_web.py` is the stable, thin import and `python -m` facade.
The implementation lives in `experiments/rig_web_app/`: command/catalog and
shared UI helpers, artifact/report/database services, the job/request lifecycle,
builder workflows, pages/settings, application composition, and the localhost
HTTP adapter. This is an internal code split only; the CLI, imported facade
symbols, admission behavior, database, and artifacts are unchanged.

## Layout

```text
src/ura/       schema, converters, adapters, targets, judges, runtime
tests/ura/     offline regression and integration tests
experiments/   matrix execution, diagnostics, human audit, analysis, figures
  rig_web.py   stable rig-console CLI/import facade
  rig_web_app/ modular rig-console implementation
docs/          architecture, schema, metrics, taxonomy and native imports
datasets/      local dataset area; released corpora are not redistributed
```

Model inputs, outputs, provider state, and human-audit exports can be harmful or
sensitive. Keep them access-controlled and follow [SECURITY.md](SECURITY.md).
Taxonomy mappings are informational crosswalks, not certifications.

Apache-2.0; see [LICENSE](LICENSE).
