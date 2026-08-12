# Chapter V experiments

Experiments are pending. Use [PROTOCOL.md](PROTOCOL.md) for the estimands and
validity rules, then execute [RUN_AND_RETURN.md](RUN_AND_RETURN.md). A dry run,
partial artifact family, source conversion, model-name assumption, native prompt
export, or synthetic figure is not a measured thesis result.

The maintained execution contract is Runner `ura-runner/2.5` with unified
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
It cannot prove account access, endpoint visibility, routing, quota, or media
transport. Therefore every exact model/modality route also needs a tiny bounded
real attestation whose output is diagnostic transport evidence, not a thesis
measurement.

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

1. Install the project and offline dependencies; run the complete offline suite.
2. Acquire every selected release and upstream project at the recorded revision;
   copy and configure the operator-local `--source-config`, bind
   `URA_MEDIA_ROOTS`, then complete and validate the compact content-addressed
   `ura-source-conformance/1` receipt and configure isolated native environments.
3. Configure exact hosted/local targets and separate scoring/defense guards.
4. Run `python -m experiments.rig_check` for every intended lane and review its
   source-policy counts and call projections.
5. Run bounded live endpoint/modality attestations, then execute only the
   attested eligible cells with finite target, judge, HTTP-attempt, and time
   ceilings.
6. Run the nine upstream native campaigns and normalize their completed outputs
   with `python -m experiments.native_import`.
7. Build `python -m experiments.suite_summary`, run no-call diagnostics, and
   prepare the automated-label-blinded, model-visible multi-rater human audit.
8. After ratings/adjudication, render qualified focal figures and return the
   complete artifact tree, commands, commits, environments, licenses/terms note,
   and `N/A` ledger.

Core CLIs:

```bash
python -m experiments.rig_check --help
python -m experiments.source_conformance --help
python experiments/run_matrix.py --help
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
  cluster row; complete planned lanes use `--limit 0` after bounded diagnostics.
- Persisted local media use `@media-root/<index>/<relative-path>` and rebind to
  the same ordered roots and relative layout on resume.
- Missing media, unsupported modality, absent source evaluator, target/transport
  failure, judge abstention, incomplete artifact family, and undefined statistic
  stay distinct. None becomes zero.
- Every paid grid has finite call/time ceilings and resumes from its durable
  budget, circuit, lock, checkpoint, completion, and error artifacts.
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
inventory, figures/provenance, logs, environment inventory, exact commit IDs,
operator notes, and the explicit eligibility/`N/A` ledger. Do not return only
aggregates.
