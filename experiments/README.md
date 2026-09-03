# Chapter V experiments

Experiments are pending. Use [PROTOCOL.md](PROTOCOL.md) for the estimands and
validity rules, then execute [RUN_AND_RETURN.md](RUN_AND_RETURN.md). A dry run,
partial artifact family, source conversion, model-name assumption, native prompt
export, or synthetic figure is not a measured thesis result.

The maintained execution contract is Runner `ura-runner/2.30` with unified
schema `1.5`. Runner 2.19/schema 1.4 artifacts remain runtime-free legacy
compatibility only and are not mixed into the current measured cohort.
Ignored local/rig engineering logs are operational diagnostics, not committed
or usable thesis evidence and not authority for a software revision.

All managed third-party framework dependencies and exact source/runtime
provenance live only in
[`framework_runtime_lock.json`](framework_runtime_lock.json). Install, resume,
or verify one isolated runtime through
`python -m experiments.framework_runtime_installer`; the same typed actions are
available in Build → Runtimes and appear as non-thesis engineering campaigns in
Jobs/Stats. Do not install a framework package in the main URA environment.

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
   Different local target models run as separate rig jobs/grids; a legal grid may
   combine multiple hosted targets with at most one of those local targets.
   A model fitting one RTX 4090 normally uses tensor parallelism 1; the second
   card may host the independent scoring guard. Two-card sharding is a separate
   declared condition. A same-base unguarded/guarded pair is the defensible
   defense contrast when exact artifacts are available. The Build tab shows the
   startup OS/CPU/core/RAM and per-GPU inventory. A shared role-aware modal
   chooses either target models or the LLM-judge model through hosted/local and
   then provider/local-filter steps. Judge rows with the highest comparable
   configured rate per currency carry a cost warning, not a quality score.
   Hosted, Local vLLM, and Local Ollama choices are separate groups. Hosted
   provider filtering and vLLM name,
   maximum-parameter (10M-3T), and rig-compatibility filters combine;
   the separate compatibility card is on by default and applies automatic
   highest-fitting 16-bit, FP8 8-bit, then BitsAndBytes 4-bit selection.
   Known 16/8/4-bit recommendations are green/blue/amber; unknown fit is gray
   and appears only when the separate unchecked `Include unknown fit` control is
   selected. That checkbox admits an unknown-size row at every parameter cap;
   known-size rows always obey the selected cap. Compatible local rows are
   single-choice radios even before their immutable revision is
   filled, but non-dry submission still rejects `OPERATOR_TODO` before launch.
   MoE/expert-ambiguous names remain unknown/hidden until exact
   `parameter_count_b` is supplied; no fit or download is inferred. Auto
   precision cannot launch an unknown-fit row. An explicit per-model precision
   creates the bound `allow_unknown_fit: true` operator opt-in, while a known
   incompatibility remains blocked. The vLLM-only `max_model_len` field controls
   engine context and KV-cache admission; it is not generation `max_tokens`.
   Omission binds vLLM's `-1` automatic fit policy, while an explicit integer in
   1..1,000,000 must be at least `max_tokens`; the Build row labels the explicit
   cap or automatic maximum GPU-fit context.
   Every Hub-backed vLLM target, local LLM judge, scoring/defense Guardrail, and
   NanoGCG surrogate first passes the sealed model workflow. An exact public
   repo plus immutable 40-64-hex commit is planned without constructing a
   model, the dedicated acquisition controller verifies/downloads and seals it,
   and only the exact receipt/store can enter an offline preflight or measured
   child. There is no implicit first-load network fallback. Rig Web exposes the
   three stages explicitly; cache hits have no download badge, while confirmed
   missing-byte transfer alone shows `model_download`. The write-only
   `HF_TOKEN` remains process-memory only (never in the operator secrets file),
   reaches only acquisition, and result artifacts retain safe path-free
   plan/receipt evidence rather than private store locators. The full grid keeps
   the complete acquisition roster; scientific conditions keep shared roles and
   each cell adds only its own local target, so unrelated grid targets do not
   split hosted conditions or transfer cohorts.
   An Ollama choice instead names a tag present in the live loopback daemon after
   a successful pull or discovery transaction. Rig Web may Start, Stop, and Pull
   only through its proven current-console-owned child; an external daemon is
   available for bounded discovery and inference but not UI Stop or Pull. Its
   config requires the exact 64-hex `/api/tags` digest and a
   unique explicit modality list containing `text` and optionally `image`. It
   forbids vLLM-only revision, parameter, topology, memory, output, context,
   quantization, and unknown-fit fields, so the UI provides no fit or precision
   control. Omission binds Ollama `num_ctx="fit"`: Runner tests the native
   ceiling and successively smaller native fractions with load-only requests,
   and admits the largest tested context reported by `/api/ps` as fully
   GPU-resident. The Runner uses the daemon HTTP API directly;
   no Ollama Python SDK is required.
   Generative vLLM and Ollama models share an identity-bound local readiness
   profile. The seeded 10-text/5-image survey runs at 4,096 and 25,000 output
   tokens with a 120-second request deadline, stores the highest passing
   allowance only when no request reaches the deadline, and is required by CLI
   and Build. Hosted target and judge output caps are instead
   fixed only by their paid campaign budget and never consume this registry.
   Response-independent local attestation, diagnostic-canary, and measured cells
   collect and durably checkpoint target responses first, release the target,
   and only then load their model-backed scoring judge. Crescendo remains inline
   because its judgment controls the next turn. Defense guardrails remain in the target
   phase as part of the evaluated treatment.
4. **Multimodal lanes.** Image, JALMBench audio, and Video-SafetyBench video are
   attempted only for exact target transports that pass bounded live
   attestation. Agent/tool sources additionally require their substantive
   runtime and evaluator. Unsupported cells remain `N/A` with reasons.
5. **Source-native lane.** AgentDojo, ASB, AutoDAN-Turbo, EasyJailbreak, FuzzyAI,
   Garak, Giskard v2, Petri, and Promptfoo run upstream. URA imports their
   complete artifacts; it never claims that replaying a generated prompt
   reproduces the source experiment.

The Build page keeps source arms with unavailable source-specific evaluators
visible and selectable for planning; one custom hover/focus tooltip carries the
full reason and server-side submission rejects them by default. Eligible
non-tool rows show `⚠ approximate opt-in`. The explicit opt-in admits only
separate warning-tagged, non-authoritative `approximate_*` proxy results with
separate coverage and an uncalibrated reliability indicator; it never upgrades
source-native evaluator status. Tool-conditioned rows show `tool runtime
required` and remain fail-closed.
Visibility is not a runnable or empirical claim.
Dry mode removes selected real API/local targets and configs because the runner
uses `MockTarget`; local roster modalities are text/image only, so audio
target/arm mismatches remain rejected in UI parity.

T3MP3ST and HarmBench use one simple two-step path. First, run the prepared
attack capture from the Build page or CLI. T3MP3ST writes an exact
`ura-t3mp3st-plan-bundle/1`; HarmBench writes an exact
`ura-harmbench-transfer-replay/1` plus its attacker config. T3MP3ST capture must
use the exact installer-managed source revision from the framework lock; the
capture helper rejects any different revision before HTTP, and only the
resulting attributable bundle may be replayed. Second, select the
attacker in Build or pass that config to `run_matrix`. Preparation may use a
source model or GPU and is outside the Runner's target/judge ceilings. The
measured run makes no attacker-generation call: it verifies the artifact hash
and exact converted selection before any target call, then replays the prepared
attempts. Rig Web resolves a symlinked configured results root before capture and
puts canonical absolute, runtime-only artifact paths in the generated attacker
config. The hardened artifact reader still rejects symlink path components, and
`run_matrix` persists content identity rather than those host paths.

NanoGCG and IDEATOR use separate prepared-input paths. NanoGCG first derives and
acquires its sealed Qwen2.5-0.5B surrogate, then
`experiments.nanogcg_capture` invokes the verified NanoGCG runtime once and
writes both `ura-nanogcg-suffix-capture/1` provenance and the replay config.
The later Runner replay does not invoke NanoGCG. IDEATOR does not run the
unverified generator path:
`experiments.ideator_vlbreakbench_prepare` maps the exact pinned VLBreakBench
release to `advbench:245` and writes an
`ura-ideator-seed-pairs/2` manifest for the Build panel plus, when requested,
a create-only ordinary Runner attacker config for CLI replay. The config carries
the path-free manifest SHA-256, one declared digest per image, the exact source
bindings, and an explicit `pair_limit` (`0` means all verified pairs). Runner
checks those image bytes before planning, and no live IDEATOR generation runs.
Its exact outer
selection is `--corpora advbench_harmful --limit 1 --sample-seed 105`;
`pair_limit=0` selects all eight verified mapped pairs, not the complete
AdvBench arm. Both belong to a separately admitted follow-on cohort with their
own projection, canary, Gate 5 record and measured schedule.

## Source inventory

The common runner has 25 converter families:

```text
advbench, agentharm, airbench, bipia, cyberseceval, decodingtrust,
figstep, gptgeochat, harmbench, holisafe, injecagent, jailbreakbench,
jailbreakv, jalmbench, mllmguard, mmsafety, mossbench, rjudge,
saladbench, simplesafetytests, siuo, strongreject, videosafetybench,
vlsbench, xstest
```

The six aggregator arms (`saladbench_base`, `airbench_full`, `xstest_full`,
`simplesafetytests_full`, `decodingtrust_stereotype`, `holisafe_full`) are
acquired through `experiments.export_aggregators` (runbook section 3.4) and
bound like every other arm through their `URA_*_PATH` locators.

`--source-config` binds stable arm IDs to a converter, environment-variable path
locator, and optional source label/split. This permits several releases or
subsets of one converter without putting author-specific absolute paths into
artifacts. Conversion support does not imply scored eligibility: currently
implemented source-specific classification evaluators include R-Judge and
GPTGeoChat; other source-specific requirements fail before a target call until
their substantive evaluator exists.
The 45 logical arms therefore comprise 28 common-metric arms, two implemented
source-classification arms, and 15 conversion-only arms. MLLMGuard
hallucination, position-swapping, and noise-injection are in the last group
until their truthfulness scorers exist. `holisafe_full` is a common image arm
whose release ships no source-authored safety rationale: its benign all-safe
(`SSS`) combination is scored response-only in the way MOSSBench's benign probes
are, while the unsafe combinations bind a judge reference built deterministically
from the released category, subcategory and safeness-combination labels and
recorded as label-derived rather than source-authored.

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
`ura-lane-projection/2` with the exact condition, selected cluster/policy/input-
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
and measured consumer. This establishes local source provenance only - not remote
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
Attempt-Response evidence. Tags, setup-only turns, input-side blocks, captions,
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
   recorded cohort. On the local-vLLM rig, install
   `.[dev,analysis,api,guardrail,local-vllm]`; that extra pins
   `vllm==0.27.1` and `bitsandbytes==0.49.2`, while the base dependency supplies
   `psutil>=7.2,<8`. Install every attack/native framework in its dedicated
   hash-locked runtime with `experiments.framework_runtime_installer`; never add
   those packages to the main URA environment. Run `pip check` before local
   preflight.
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
   `experiments.suite_summary` and the deterministic
   `experiments.level2_report` broad tables, run no-call diagnostics, and
   prepare the automated-label-blinded, model-visible multi-rater human audit.
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
python -m experiments.level2_report --help
python -m experiments.rig_web --help          # console + campaign builder (sqlite operational state)
python -m experiments.local_targets --help    # vLLM local-target roster (version-matched refresh)
python -m experiments.syn_compat --help
python -m experiments.paired_compare --help
python -m experiments.judge_sensitivity --help
python -m experiments.kappa --help
python -m experiments.transfer_matrix --help
python -m experiments.human_audit --help
python -m experiments.figures --help
```

The rig-console command remains `python -m experiments.rig_web` and its stable
imports remain in `experiments/rig_web.py`. That file is a thin facade over the
focused `experiments/rig_web_app/` modules for catalog/UI, artifacts/reports,
sqlite state, job/request lifecycle, Build workflows, pages/settings, app
composition, and the localhost server. The split changes no CLI, admission
gate, database, or artifact contract.

Jobs show the full start date and time in the browser's local time zone. Their
state, text, From, and To filters combine and default to the previous seven days
through now, with inclusive bounds at the selected input precision. Date changes
query persisted jobs and campaign markers before their bounded display caps;
truncation is explicit rather than silently inherited from the restart cache.
Short tags
use blue `running` plus `partial`, `blocked`, `stopped`, `orphaned`, and `unknown`;
detail text distinguishes an external task-log marker from a console-owned
process. Task-process
succeeded/failed/skipped/active/pending counts are separate from model work.
Optional strict `planned_tasks` and `model_tasks` declarations plus a bounded
`model-execution.jsonl` self-report make that distinction visible; a terminal
campaign report, when present, has exactly one row per declared model task.
Reserved calls and the self-report are not execution evidence. Validated
response artifacts remain authoritative.

## Real-run invariants

- `--limit N` counts source prompt/intent clusters and retains every selected
  cluster row. For an unchanged real converted-corpus digest and sample seed,
  limits are deterministic nested prefixes: the one-cluster canary remains in a
  later `N`-cluster selection. Unique clusters are inventoried in first source
  order; SHA-256 over
  `ura-corpus-cluster-order-v1\0<arm>\0<sample_seed>` supplies an unsigned
  big-endian seed from its first eight bytes for one shuffle without
  replacement. The first N positions are selected and all sibling rows return
  to source order. Prefixes overlap and are nested, not disjoint partitions.
  The current measured local campaign uses its pre-registered positive per-arm
  tier limit. Explicit local or hosted `--limit 0` is supported only as a
  separately projected full-corpus cohort with caps covering the complete grid;
  the current hosted campaign lanes retain their positive prospective limits
  (runbook section 5.2). The source-mapped IDEATOR v2 artifact is not a
  full-corpus configuration: it is fixed to the one-cluster selection above.
  The optional `--sampling-policy` choice is either
  `seeded_pseudorandom_whole_cluster_prefix_v1` (the unchanged omitted-argument
  default) or `source_order_whole_cluster_prefix_v1` (the first N cluster keys
  in source-appearance order). An explicit value is identity-bound; both
  policies retain sibling rows and make `--limit 0` the complete arm.
- `--exclude-tool-conditioned` is not a sampling mode. It is admitted only for
  the standalone offline dry-run smoke and records its diagnostic row
  exclusions. Preflight, acquisition, attestation, canary, and measured routes
  reject it, so every evidence-bearing selected cluster retains all siblings.
- Persisted local media use `@media-root/<index>/<relative-path>` and rebind to
  the same ordered roots and relative layout on resume.
- Missing media, unsupported modality, absent source evaluator, target/transport
  failure, judge abstention, incomplete artifact family, and undefined statistic
  stay distinct. None becomes zero.
- An admitted local generative target defaults to one additional call after a
  deterministically unusable answer (`--target-answer-retries 1`). Exhausting
  that retry checkpoints the row as a model-stability failed output and
  continues the assigned population. It is missing-response coverage, not a
  decided safety label. Projections and caps cover all allowed attempts;
  identity/seal drift remains terminal. If the adapter verified a strong
  runtime/model identity before answer validation failed, the retained missing
  response preserves only that normalized identity and rejects retry drift, so
  transport attestation does not depend on a usable answer. The policy is
  implemented once in Runner and applies identically to vLLM and Ollama
  targets. The budget-fitted
  hosted campaign instead pins answer-quality and provider SDK retries to 0.
  Build sets and locks the answer-retry field to 0 whenever a hosted target is
  selected; server validation rejects a nonzero submitted value. The harness
  permits three retries only after HTTP 408, 409, 425, 429 or 5xx status
  responses, for at most four visible HTTP attempts per logical call. A valid
  but unusable answer and a connection failure without an HTTP status are not
  retried. The first retained failed output or exhausted/non-retryable transport
  failure opens the global `paid_provider` circuit before another paid call. An
  operator must classify and resolve it before a fresh bound plan and explicit
  circuit reset; paid execution never resumes automatically.
- Local context fit and response allowance are independent. vLLM
  `max_model_len=-1` and Ollama `num_ctx="fit"` retain maximum hardware-fitting
  context. A local response allowance and 120-second request deadline must come
  from the exact revision/digest readiness profile; an unprofiled model is not
  admitted to a security campaign. Hosted
  routes use explicit budget-derived token limits and their existing paid-call
  stop circuit instead.
- Post-hoc Haiku re-adjudication does not use `run_matrix` and cannot regenerate
  a target response. `retained_response_judge_pair` admits at most 590 pairs
  from the exact local/hosted input-identity intersection, without reusing an
  output; `retained_response_judge_pair_execute` reconciles both validated
  Runner views and constructs only the named Haiku judge. It reserves zero
  target calls, uses one judge/HTTP attempt per selected output, checkpoints
  every paid decision, binds and revalidates the effective-dated pricing bytes,
  and opens its global `paid_provider` circuit on the first judge or transport
  failure. Its one USD 7.75 ceiling covers at most 1,180 calls: USD 7.67 at the
  4,000-input/500-output planning average and USD 7.7408 at the fixed 512-token
  output maximum.
- The hosted follow-on uses ten global target caps totaling 590 calls, including
  readiness and diagnostic canaries. `hosted_campaign_budget` creates a
  zero-call projection from the exact API-config, effective-dated pricing and
  budget bytes. It reports both the 4,000-input/500-output expectation and each
  route's configured-maximum-output reservation, and blocks any provider above
  half its configured balance. The current planning values are USD 8.3130 and
  USD 38.5476 for targets, or USD 15.9830 and USD 46.288368 including Haiku.
  Every hosted Runner lane uses the sealed local `rules,guardrail` cascade, so
  its retained response already has the local judgment later compared with
  Haiku on the exact paired row. The local cascade has no provider cost.
- Hub acquisition is conditional on the selected resources, not on the mere
  existence of a local target. Static lanes with Hub-backed assets retain the
  exact plan/receipt/store chain. Ollama R-Judge and GPTGeoChat lanes over
  already-local inputs omit that chain and must not invent an empty plan. A
  terminal population-alignment recovery selects only units that failed before
  measured state, retains every completed row, and exposes old and recovered
  revisions as separate Phase 7 strata. It snapshots and applies the same
  identity-bound local readiness profiles as the preceding bounded-output
  recovery; it does not restore a campaign-wide fixed response allowance.
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

The human audit hides automated labels, keeps model identity visible, assigns
exactly two distinct independent raters per row plus adjudication, and labels refusal,
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

The sealed local controller uses Phase 7's validated success-only Runner view.
Before it writes any sample, the exact common population must cover the
requested common sample plus 20 disjoint qualification clusters and the
source-task population must cover its exact request. This is a cardinality
check; both coverage-priority selectors independently reject an undersized
request for the achieved cells. A successful preparation terminal remains
`human_only_blocked` with `gate8_met: false`; prepared blank forms and
assignments are not human evidence.

Return attempts, responses, complete shadow trails, judgments, manifests,
checkpoints, completion/error/budget/circuit artifacts, source/native artifacts
and hashes, modality plans/results, diagnostics, human-audit files, suite
inventory, figures/provenance, logs, environment inventory, the exact
`ura-project-revision/1` receipt and SHA-256, separately self-recorded checkout
status, upstream commit IDs, operator notes, and the explicit eligibility/`N/A`
ledger. `NativeEngineRun` retains its upstream revision but has no Runner
manifest; retain the URA import revision in the return-package/importer context.
Do not return only aggregates.
