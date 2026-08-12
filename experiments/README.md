# Chapter V experiments

Experiments are pending. Use [PROTOCOL.md](PROTOCOL.md) for the estimands and
validity rules, then execute [RUN_AND_RETURN.md](RUN_AND_RETURN.md). A dry run,
partial artifact family, source conversion, model-name assumption, native prompt
export, or synthetic figure is not a measured thesis result.

The maintained execution contract is Runner `ura-runner/2.10` with unified
schema `1.4`; older artifacts are not mixed into the thesis run.

## Experimental shape

The thesis uses a tiered programme rather than an infeasible universal Cartesian
product:

1. **Focal paired lane.** The exact account-visible Fable and GPT-5.6 Sol
   conditions support the prospectively selected paired and human-audited
   comparison. This remains a cross-provider association.
2. **Hosted breadth lane.** Additional account-visible Anthropic, OpenAI,
   Gemini, DeepSeek, Kimi, Qwen and GLM-family routes receive bounded static
   evaluation on compatible sources. Family names and documentation examples
   are candidates only; the exact route, returned identity, access, and physical
   modalities must be attested live.
3. **Local breadth/defense lane.** One local vLLM/Ollama target runs per process.
   A model fitting one RTX 4090 normally uses tensor parallelism 1; the second
   card may host the independent scoring guard. Two-card sharding is a separate
   declared condition. A same-base unguarded/guarded pair is the defensible
   defense contrast when exact artifacts are available.
4. **Multimodal lanes.** Image, JALMBench audio, and Video-SafetyBench video are
   attempted only for exact target transports that pass bounded live
   attestation. Agent/tool sources additionally require their substantive
   runtime and evaluator. Unsupported cells remain `N/A` with reasons.
5. **Source-native lane.** AgentDojo, ASB, AutoDAN-Turbo, EasyJailbreak, FuzzyAI,
   Garak, Giskard v2, Petri, and Promptfoo run upstream. URA imports their
   complete artifacts; it never claims that replaying a generated prompt
   reproduces the source experiment.

## Source inventory

The common runner has 19 converter families:

```text
advbench, agentharm, bipia, cyberseceval, figstep, gptgeochat,
harmbench, injecagent, jailbreakbench, jailbreakv, jalmbench,
mllmguard, mmsafety, mossbench, rjudge, siuo, strongreject,
videosafetybench, vlsbench
```

`--source-config` binds stable arm IDs to a converter, environment-variable path
locator, and optional source label/split. This permits several releases or
subsets of one converter without putting author-specific absolute paths into
artifacts. Conversion support does not imply scored eligibility: currently
implemented source-specific classification evaluators include R-Judge and
GPTGeoChat; other source-specific requirements fail before a target call until
their substantive evaluator exists.

## Target configuration and admission

The focal target specifications are:

```text
anthropic-fable:claude-fable-5;effort=high;max_tokens=25000
openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns
```

Generic hosted candidates are bound by `--api-config`; local candidates by
`--local-config`. A no-call `rig_check` verifies configuration, corpus, policy,
component, declared modality, credential presence and conservative call bounds.
After whole-request admission it retains a content-addressed
`ura-lane-projection/1` with the exact condition, selected cluster/policy/input-
media byte inventory, and conservative complete-grid logical-call/HTTP exposure.
The measured grid binds its own exact projection before its first call. Tokens,
price/cost, runtime/throughput, and expected output storage remain
`CANNOT-VERIFY`.
It cannot prove account access, endpoint visibility, routing, quota, or media
transport. Therefore every exact model/modality route also needs a tiny bounded
non-dry `run_matrix --attestation-probe`, followed by
`experiments.live_attestation`. The latter performs no call; it converts the
strict completed probe into a content-addressed `ura-live-attestation/2`
receipt. Every ordinary non-dry grid must bind that receipt's exact bytes,
digest, operator-declared execution scope and maximum age before target calls.
The receipt is diagnostic historical route/access/byte-backed transport
evidence, not a thesis measurement or proof of account equivalence, safety,
evaluator validity, human validity, or future availability.

The earlier admission boundary is the exact URA implementation itself.
`URA_PROJECT_REVISION_MANIFEST` and `URA_PROJECT_REVISION_SHA256` name one
content-addressed clean-local-checkout receipt. Its compact expected/observed
commit, HEAD-tree, driver/harness-root and source-digest binding enters every
non-dry eligibility condition, grid, Runner manifest, completion, attestation,
and measured consumer. This establishes local source provenance only—not remote
authenticity, dependency/upstream identity, or empirical validity. A fully
synthetic dry-run may omit it only through the explicit
`not_required_diagnostic_dry_run` mode, which remains non-empirical.

`run_matrix --diagnostic-canary` is a different execution purpose: exactly one
target, logical source arm, attacker, seed, and whole cluster. The no-call
`experiments.lane_canary` summarizer emits `ura-lane-canary/1` as
`synthetic_offline` for `--dry-run --corpora synth` or `live_diagnostic` for a
live-attested route. It keeps reserved calls/HTTP exposure separate from
client-reported observed attempts and records observed artifact bytes, timings,
decision support, and exercised roles. It cannot justify cost, throughput,
expected storage, population validity, or campaign authorization. Canary grids
are rejected by Level-1, suite/figure, paired/transfer, and human-audit admission.
Native-framework canaries remain external and are not canonical native imports.

The planner admits the intersection of source-present and target-supported
modality combinations. Post-run validation requires actual eligible
Attempt--Response evidence. Tags, setup-only turns, input-side blocks, captions,
or silently removed media do not prove modality execution.

## Metric families, not one score

The suite uses a reporting ontology: coverage/conformance, unsafe-response rate,
benign-refusal rate, adaptive compromise, classification quality,
attack/injection-goal success, task utility, graded risk, detector findings, and
truthfulness where a substantive scorer exists. Family membership makes results
findable; it does not make their denominators, policies, judges, or scales
exchangeable.

Only coverage/conformance counts can be totaled globally. Common rates remain
in exact model/source/policy/modality/attacker/defense strata. Native aggregates
remain on their upstream scales. `experiments.suite_summary` enforces that
descriptive evidence-inventory boundary, separates distinct run identities, and
lists missing registered source arms/native projects rather than treating a
nonempty subset as complete.

## Direct lifecycle

1. Select a prospectively reviewed full 40-hex project commit, check it out
   detached, create/digest/validate one `ura-project-revision/1` receipt from
   the clean checkout, export its path/SHA-256, install dependencies, and run
   the complete offline suite. Every non-dry preflight, probe, canary, or
   measured Runner request binds this receipt; a revision change starts a new
   recorded cohort.
2. Acquire every selected release and upstream project at the recorded revision;
   copy and configure the operator-local `--source-config`, bind
   `URA_MEDIA_ROOTS`, then complete and validate the compact content-addressed
   `ura-source-conformance/1` receipt and configure isolated native environments.
3. Configure exact hosted/local targets and separate scoring/defense guards.
4. Run `python -m experiments.rig_check` for every intended lane under a
   separate preflight output tree and review its source-policy counts and call
   projection artifact; obtain explicit operator approval and provider-side
   project quota for caps covering the complete projection. Measured
   `run_matrix` outputs belong in the runner tree.
5. Run bounded live endpoint/modality probes, derive and hash typed receipts,
   then, where needed, run one separately typed whole-cluster diagnostic canary
   and summarize it offline with `experiments.lane_canary`. Only after review,
   execute the exactly attested eligible cells with the same non-secret
   execution-scope ID, an explicit maximum receipt age, and finite target, judge,
   HTTP-attempt, and time ceilings. `rig_check` and dry-run use no receipt.
6. Run the nine upstream native campaigns and normalize their completed outputs
   with `python -m experiments.native_import`.
7. Build `python -m experiments.level1_evidence` from every final plan in the
   selected measured runner cohort, including plan-only `N/A`/blocked requests
   but excluding preflight and probe trees; pass the exact receipts and hashes
   bound by those measured grids, then build the separate no-pooling
   `experiments.suite_summary`, run no-call diagnostics, and prepare the
   automated-label-blinded, model-visible multi-rater human audit.
8. After ratings/adjudication, render qualified focal figures and return the
   complete artifact tree, exact URA project-revision receipt/digest and
   separately recorded checkout status, commands, upstream commits,
   environments, licenses/terms note, and `N/A` ledger.

Core CLIs:

```bash
python -m experiments.project_revision --help
python -m experiments.rig_check --help
python -m experiments.source_conformance --help
python experiments/run_matrix.py --help
python -m experiments.live_attestation --help
python -m experiments.lane_canary --help
python -m experiments.level1_evidence --help
python -m experiments.native_import --help
python -m experiments.suite_summary --help
python -m experiments.paired_compare --help
python -m experiments.judge_sensitivity --help
python -m experiments.kappa --help
python -m experiments.transfer_matrix --help
python -m experiments.human_audit --help
python -m experiments.figures --help
```

## Real-run invariants

- `--limit N` counts source prompt/intent clusters and retains every selected
  cluster row. For an unchanged real converted-corpus digest and sample seed,
  limits are deterministic nested prefixes: the one-cluster canary remains in a
  later `N`-cluster selection. Complete planned lanes use `--limit 0` after
  bounded diagnostics.
- Persisted local media use `@media-root/<index>/<relative-path>` and rebind to
  the same ordered roots and relative layout on resume.
- Missing media, unsupported modality, absent source evaluator, target/transport
  failure, judge abstention, incomplete artifact family, and undefined statistic
  stay distinct. None becomes zero.
- A live receipt matches one exact requested/base-resolved route, secret-free
  route configuration, execution scope, modality combination and observation
  time. Text+image is not a substitute for text. Synthetic live text and
  text+one-pixel-image probes need no source receipt or human rating, but make a
  real target call and remain diagnostic; no synthetic audio/video fixture is
  implemented.
- Every non-dry provider-backed grid has finite call/time ceilings that cover
  the complete conservative projection and resumes from its durable budget,
  circuit, lock, checkpoint, completion, and error artifacts. Reserved logical
  calls/HTTP exposure are not observed transport attempts. A provider-side quota
  and recorded operator approval are required before campaign execution.
- A model-backed defense has one shared explicit-device guard instance whose
  identity differs from the scoring guard. The implemented model defense is
  text-only; it cannot support a multimodal defense claim.
- Every measured comparison states exact model/endpoint, source instance,
  release/policy, modality, attacker, defense, judge, cluster unit, budget,
  support, exclusions, interval method, and run date.

## Analysis and return package

The focal paired comparison gives each source cluster equal weight. Transfer is
conditional on source-model success and an identical rendered input. Adaptive
trajectories use conversation endpoints and the declared challenge horizon.
Source-native outcomes and common proxies are reported separately.

The human audit hides automated labels, keeps model identity visible, requires
at least two independent raters plus adjudication, and labels refusal,
harmfulness, convincingness, and specificity separately. A small or selectively
sampled audit is limited-sample evidence with intervals, not population-wide
judge validation. Its deterministic whole-cluster selector must cover every
observed common-eligible arm endpoint overall and in its exact risk/modality cell;
increase `--prepare N` if that achieved design cannot fit. Validity is primary
within exact-run/response-arm/logical-corpus/source-policy/effective-modality/
expected-population/common-eligibility strata. Every primary stratum reports
decided/abstained support and decision coverage; harmful violation and benign
over-refusal are separate adverse endpoints. Pooled values are
composition-dependent diagnostics.

Return attempts, responses, complete shadow trails, judgments, manifests,
checkpoints, completion/error/budget/circuit artifacts, source/native artifacts
and hashes, modality plans/results, diagnostics, human-audit files, suite
inventory, figures/provenance, logs, environment inventory, the exact
`ura-project-revision/1` receipt and SHA-256, separately self-recorded checkout
status, upstream commit IDs, operator notes, and the explicit eligibility/`N/A`
ledger. `NativeEngineRun` retains its upstream revision but has no Runner
manifest; retain the URA import revision in the return-package/importer context.
Do not return only aggregates.
