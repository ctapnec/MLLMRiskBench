# URA-Bench

URA-Bench is the research software for the master's thesis *A Risk-Assessment
System for Question Answering by Multimodal Language Models*. It converts safety
corpora to one typed schema, runs static or response-conditioned attacks against
hosted or local targets, shadow-scores every response, and retains auditable
lineage for later analysis.

Experiments are pending. The repository establishes no model ranking, defense
effect, compliance finding, or other empirical result yet.

The development tree implements the RUN-001 prospective-request and MET-001
exact-selection interfaces described below, with offline contract tests.
Generated local/rig logs and engineering-campaign records stay under ignored
operator state; they are diagnostics, are not committed, and are not usable
thesis evidence or authority for a software revision. Exact revision identity
comes from the tracked checkout and the typed receipts described below. A retained
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

For a complete Linux rig installation, use the repository-wide installer:

```bash
export URA_PYTHON=$(uv python find 3.12.13)
distro/install.sh all
```

That single entry point installs the main URA environment, corpora and pinned
Ollama runtime, builds BIPIA through its own fully hashed support venv, and
manages all 16 locked third-party framework runtimes in separate
content-addressed stores (14 private Python virtual environments and two private
Node runtimes, Promptfoo and T3MP3ST) from
`experiments/framework_runtime_lock.json`. It verifies every runtime before any
mutation, leaves a passing installation untouched, and resumes only a missing,
interrupted, new, or changed row. Each runtime gets its own sequential `--only`
named session, so one failure is recorded without hiding later runtime results;
the aggregate phase still fails honestly. The installer writes the campaign
locators, seeds only missing aggregator source-registry entries, and never
rewrites receipt-bound operator choices. It starts the console in tmux, or
screen when tmux is unavailable. The phase-by-phase form and recovery rules are in
[`distro/README.md`](distro/README.md) and use the same roots and lock as the
[operator runbook](experiments/RUN_AND_RETURN.md).

```bash
python -m pip install -e ".[dev,analysis]"
python -m pytest
env -u URA_PROJECT_REVISION_MANIFEST -u URA_PROJECT_REVISION_SHA256 \
  python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm \
    --corpora synth --limit 12 --exclude-tool-conditioned --out runs/dry
python -m experiments.figures --synth --out runs/_figcheck
```

The `synth` fixture ships two tool-conditioned rows (`synth-4`, `synth-10`) that
no Runner attacker can execute yet; `--exclude-tool-conditioned` drops them with
a recorded exclusion count so the offline smoke completes. Without that flag the
same command fails closed on the tool contract by design.
The switch is admitted only on a standalone diagnostic `--dry-run`. Preflight,
acquisition, attestation, canary, and measured routes reject it so no
evidence-bearing sample can drop a sibling row from a selected source cluster.

The rig's local-vLLM environment is installed from the checked-in extra rather
than from separate version variables:

```bash
python -m pip install -e ".[dev,analysis,api,guardrail,local-vllm]"
python -c "import bitsandbytes, psutil, torch, vllm; print(vllm.__version__, bitsandbytes.__version__, psutil.__version__, torch.__version__)"
```

`local-vllm` pins the tested `vllm==0.27.1` and `bitsandbytes==0.49.2` pair;
`psutil>=7.2,<8` is a normal project dependency used for the startup CPU/core/RAM
snapshot. HarmBench and every other third-party attack/native framework are
installed only through the strict isolated-runtime lock described in the
operator runbook; they are not main-environment extras.
The installer removes legacy top-level PyRIT, Spikee, `datasets`, and
`jsonlines` copies from the main venv after installing URA, without removing
their isolated stores. It then derives every installed framework root from the
strict lock and fails if a reused main venv still contains one; it never prunes
shared transitive dependencies. BIPIA's retained `datasets==2.14.7` builder
instead uses `distro/bipia-build-requirements.lock` in
`$URA_WORK/support-venvs`.

### Isolated framework runtimes

[`experiments/framework_runtime_lock.json`](experiments/framework_runtime_lock.json)
is the sole dependency/source/runtime manifest for all 16 managed attack,
preparation, and native-framework runtimes. Use
`python -m experiments.framework_runtime_installer plan|install|resume|verify|adopt`
with an exact CPython 3.12.13 base interpreter; never install those packages in
the main URA venv. Each long mutating/verification action automatically runs in
a credential-free named tmux session (screen is the only fallback), publishes
one stable alias to a content-addressed store, and writes only path-free
receipts/summaries plus a non-thesis engineering campaign. Build -> Runtimes
exposes the same fixed per-row actions, while Jobs/Stats shows their bounded
campaign events. The full CLI, state-root convention, canonical `.store`
runtime-config handoff, and 20-attacker coverage dispositions are in the
[operator runbook](experiments/RUN_AND_RETURN.md#122-runner-safe-external-attack-bridges).
Clean per-runtime homes bind explicit persistent package caches at
`$URA_WORK/framework-venvs/.cache/{pip,npm}`. Cache bytes are download
optimizations only; hashed locks, exact inventories, smoke checks, and content
seals remain authoritative.

An aggregate lock identity can change when one runtime is added even though the
other complete framework rows are byte-identical. Retain the exact prior lock at
an operator-private, already-resolved absolute path and opt in explicitly:

```bash
export URA_FRAMEWORK_ADOPT_FROM_LOCK=/absolute/operator/path/framework_runtime_lock.previous.json
distro/install.sh runtimes
unset URA_FRAMEWORK_ADOPT_FROM_LOCK
```

Adoption is never inferred. For each selected row, it requires identical lock
schema, platform, policy and runtime pins plus an identical complete framework
entry. It then checks the retained content seal, exact inventory and offline
smoke before rebinding the receipt. A new or changed row is resumed normally;
an already-current row is only verified.

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
and driver. The dashboard and Build tab show this snapshot. One large, accessible
model-picker wizard serves both the target and LLM-judge controls: first choose
hosted or local, then apply the relevant hosted-provider (`All` by default) or
local filters. Target mode binds one or more hosted targets and at most one
local target. Judge mode binds exactly one model, distinct from every target; a
local target and a distinct local judge cannot share one process. Different
local target models are scheduled as separate rig jobs/grids; one
legal grid may still combine multiple hosted targets with its single local target.
A judge-only
warning marks the highest configured comparable input/output rate in each
currency; it is a pricing warning, not a quality ranking. The local
step presents separate Local vLLM and Local Ollama groups. Local vLLM filters
combine an immediate
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
`parameter_count_b` is declared. Selecting `Include unknown fit` makes an
unknown-size row visible at any maximum-parameter setting; every known size
still obeys the selected cap. Hardware-auto remains blocked for
a live unknown-fit row; an explicit per-model choice (`none`, `fp8`,
`bitsandbytes`, `awq`, or `gptq`) writes the narrow
`allow_unknown_fit: true` opt-in and permits an operator-owned load attempt.
Known incompatibility, invalid topology, or missing hardware stays blocked, and
dependency/runtime allocation failures fail during local preflight before
target/judge calls. On
the actual two-24,564-MiB rig, FP8 does not fit a 70B profile, so it is rostered
only as an in-flight 4-bit BitsAndBytes, tensor-parallel-2 candidate rather than
an unquantized model.

Two disabled precision profiles retain exact diagnostic reasons. LLaVA-v1.6 FP8
loaded its weights under vLLM 0.27.1, then the multimodal encoder's scaled-matrix
kernel attempted `.view()` on a non-contiguous tensor. GraySwan RR BitsAndBytes
4-bit was rejected because its `LlavaNext` implementation exposes no
`packed_modules_mapping`. Both are architecture/runtime incompatibilities, not
VRAM-fit failures, and both stopped before target inference.
The optional vLLM-only `max_model_len` field is an engine-context and KV-cache
admission cap, not the response-generation `max_tokens` bound. Omission leaves
the checkpoint's native context unchanged; an explicit integer in 1..1,000,000
is passed to vLLM at engine construction, and `max_tokens` may not exceed it.
Rig Web preserves the field in its selected local config, and the normalized
value enters grid/run provenance. Each Build row labels either the explicit
context cap or native model context.

Ollama uses its native request fields instead: optional `num_ctx` and
`num_predict` integers in the selected local config. Runner and Build default
them to 8,192 context tokens and 512 generated tokens, pass both in every
`/api/chat` request, and retain them in config, grid, condition, and response
provenance. This avoids allocating a model's full advertised long context for
short benchmark prompts while keeping a different bounded value available as a
separately reviewed execution condition. Reaching `num_predict` remains a valid
length-capped response and the observed text is still evaluated.
Recovery reuses prior Ollama projections, attestations and canaries only when
every exact per-model config is unchanged. A context/output-cap change retains
the older artifacts as diagnostics and creates a fresh projected cohort.
If every exact-config unit completed and only aggregate validation failed, the
recovery revalidates that complete inventory without another model call.

The exact campaign GraySwan RR checkpoint remains sealed and installed. Its
text and physical-image probes reached the declared 4,096-token generation cap
without a stop; an independent Transformers control reproduced its two-token
repetition while the exact LLaVA base emitted EOS. The original Gate 5 record
classified the four affected lanes as target-runtime terminals under the older
Runner policy. Runner 2.22 and later instead retain every nonempty length-capped
completion, preserve `finish_reason='length'`, and send the observed text to the
selected evaluator. The historical terminal artifact remains immutable
diagnostic provenance, but a targeted Gate 5 amendment must re-attest and canary
those four lane identities before they enter measured execution. URA does not
inject stop strings, change decoding configuration, substitute a checkpoint,
or hide truncation provenance.

Hub-backed local execution is a sealed three-stage workflow, never an implicit
first-load download. It covers all five model roles: vLLM target, local vLLM
LLM judge, scoring Guardrail judge, defense Guardrail, and NanoGCG surrogate.
Every Hub selection requires its public repository ID and an exact 40-64
lowercase-hex commit. `run_matrix --model-acquisition-plan-only` derives a
path-free plan and stops before constructing an attacker, target, judge, guard,
or surrogate without changing the intended execution purpose. A preflight plan
includes `--preflight-only`; a diagnostic-canary plan includes
`--diagnostic-canary` without `--preflight-only`; a measured plan includes
neither. Those purpose-specific request envelopes require separate plans. The
dedicated `experiments.model_acquire` controller verifies or transfers the
planned bytes and writes a sealed receipt. The subsequent preflight, canary or
measured process accepts only that exact plan, receipt, and private managed-store
locator, rehashes every snapshot immediately around model construction,
and forces Hugging Face/Transformers/vLLM local-only offline policy. Explicit
digest-sealed workstation checkpoints are the path-local exception and receive
the same pre/post-load content check.

Rig Web presents those stages as `acquisition plan` (no model call), `model
acquisition`, then the reviewed offline preflight/run. Its `model_download`
activity appears only while the authenticated acquisition worker confirms that
missing bytes are being transferred; a cache hit/import never gets the badge,
and terminal or cancelled work clears it. `HF_TOKEN` is write-only and
presence-only in Config, is held only in the console process (never its
operator secrets file), reaches only the acquisition children (the sealed
model-acquisition worker and the `export_aggregators` corpus export), and is removed
before normal model processes import third-party runtimes. Private tokens,
plan/receipt/store locators, and resolved snapshot paths never enter durable
argv, Jobs logs, reports, or UI artifacts. Result roots instead retain safe,
path-free canonical plan and receipt copies plus a timestamp- and mtime-
independent sealed execution descriptor. Grid provenance keeps that complete
roster. Scientific conditions use a plan-free shared judge/guard/defense/
surrogate role projection, while each Runner cell adds only its own local target
seal. Thus adding an unrelated local target to a hosted grid cannot change the
hosted cell's condition or run identity, while changed relevant bytes still do.
Identical bytes remain one
scientific condition while the exact receipt event and its admission-only stat
inventory stay auditable.

Runner-safe PyRIT 0.14.0, DeepTeam 1.0.7, h4rm3l 0.2.4, and Spikee 0.9.1
execute only in four separate, explicitly selected virtual environments. A
private content-addressed config admits one fixed isolated worker per selected
framework, verifies the interpreter and complete package tree including
executable bytecode under `ura-framework-runtime-content-seal/2`
before any component construction, reuses that worker across attempts, and
requires a second full-tree closing seal before completed evidence is
published. Durable artifacts contain only the path-free receipt/bridge identity.
Direct live NanoGCG construction inside Runner remains disabled. The separate
`experiments.nanogcg_capture` command runs the verified NanoGCG 0.3.0
interpreter with a sealed Qwen2.5-0.5B surrogate, performs one bounded
optimization, and emits an attributable suffix plus replay config. Replaying
that config performs no further NanoGCG/model call and therefore records
`framework_execution=not_invoked` for the replay stage only.

The Local Ollama group is a live inventory from the fixed loopback daemon
(`http://127.0.0.1:11434` by default). Rig Web provides Status, Start, Stop,
and Pull controls. It classifies a daemon already on that endpoint as external
and never stops it; a listener whose ownership cannot be proved is explicitly
ambiguous. Stop and clean shutdown address only the dedicated process group
started by the current console process, and retain an error/owned state if
descendant cleanup cannot be confirmed so Stop can retry. After a console
crash/restart, a surviving daemon is external because the new process has no
ownership handle. Cleanup sends no terminating signal unless the original live
process-group leader still has the exact captured start identity; if that proof
disappears, ownership stays in an explicit retryable error state. Pull runs as a normal console job with explicit
`model_download` progress, but only for a current-console-owned daemon. Its
worker re-proves the frozen PID/start identity and exact loopback listener while
holding the cross-process mutation lock, uses the model-storage path bound at
daemon start, and rejects external or replaced daemons. Before admission it
requires five GiB of model-volume headroom; the worker rechecks that reserve
plus each reported remaining download before continuing.

Discovery combines bounded `/api/tags`, `/api/ps`, and `/api/show` requests. It
accepts at most 64 installed rows within one five-second aggregate capability
budget, verifies a second tag/digest snapshot to close mutable-tag races, and
derives text/image modalities only from explicit show capabilities. Invalid or
ambiguous rows are reported but never fabricated as selectable models. Exact
bounded family evidence from tags/show details and
`model_info.general.architecture` must be present and mutually compatible; the
architecture is retained as capability evidence. The vLLM catalog never
suppresses an installed Ollama tag: the backends are separate execution routes,
whether or not model families or names resemble one another.
Every `ollama:<model-tag>`
entry must carry the exact lowercase 64-hex digest reported by `/api/tags` and
an explicit unique modality list containing `text` and optionally `image`.
Ollama entries reject vLLM-only revision, parameter, topology, memory,
`max_tokens`, `max_model_len`, quantization, and unknown-fit fields; they accept
only their bounded `num_ctx` and `num_predict` execution controls in addition to
digest and modalities. The pulled artifact fixes precision, so the Build page
shows no automatic fit or precision control for it. Runner admission
independently refreshes the live show-backed roster. Each inference
holds the shared endpoint lock and binds pre-chat `/api/tags`, the returned
model, post-chat `/api/tags`, and exact post-chat `/api/ps` tag/digest evidence
in one hard-deadline transaction. The Runner talks to the daemon over its HTTP
API using the Python standard library, so no Ollama Python SDK is required. A
running daemon and the matching pulled tag remain live-run prerequisites.

The dependency check on that rig used Python 3.12.13, vLLM 0.27.1,
BitsAndBytes 0.49.2, psutil 7.2.2 and torch 2.13.0+cu130/CUDA 13.0. The
BitsAndBytes import/self-diagnostic succeeded; CUDA exposed two GPUs with
maximum compute capability 8.9; the system probe reported 24 logical CPUs and
134,974,398,464 bytes of RAM; and `pip check` was clean after removing an
unused orphaned `datasets 2.14.7` installation. This verifies the environment
and UI/admission prerequisites, not model inference; no provider/model call was
made.

Runner 2.20 makes that prerequisite machine-checked. A bounded non-dry
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
pair is the appropriate design for a defense effect. The current LLaVA/GraySwan
pair remains non-estimable until its affected identities pass the targeted
current-policy amendment; that pending estimate is not a zero effect. Fable thinking
and Sol encrypted reasoning or assistant-output state are retained only as needed for
provider-faithful stateless continuation and checkpoint resume.

## Sources, modalities, and native engines

The common runner exposes 25 converter families: AdvBench, AgentHarm,
AIR-Bench 2024, BIPIA, CyberSecEval, DecodingTrust (stereotype perspective),
FigStep, GPTGeoChat, HarmBench, HoliSafe, InjecAgent, JailbreakBench,
JailBreakV, JALMBench, MLLMGuard, MM-SafetyBench, MOSSBench, R-Judge,
SALAD-Bench, SimpleSafetyTests, SIUO, StrongREJECT, Video-SafetyBench,
VLSBench, and XSTest. The six aggregator arms (SALAD-Bench, AIR-Bench 2024,
XSTest, SimpleSafetyTests, DecodingTrust, HoliSafe) are acquired through
`experiments.export_aggregators` and bound like every other arm. A
`--source-config` inventory can
bind multiple independently labelled source instances to those converters
without persisting operator-specific absolute paths. Conversion is not an
automatic claim of scored-run eligibility: a source-specific evaluator that is
not implemented fails pre-call rather than being squeezed into common ASR.
The current 45-arm disposition is 28 common-metric arms, two implemented
source-classification arms, and 15 conversion-only arms pending their exact
source scorer or runtime.

Nine end-to-end projects - AgentDojo, ASB, AutoDAN-Turbo, EasyJailbreak, FuzzyAI,
Garak, Giskard v2, Petri, and Promptfoo - run upstream under their own contracts.
Their complete outputs are normalized by `experiments.native_import`; they are
not reduced to generated prompts and replayed as if that reproduced the native
experiment.

Before configuration loading or corpus conversion, `run_matrix` writes a strict,
content-addressed `ura-request-envelope/4`. It fixes the operator-selected
requested-target x logical-source-arm x attacker universe as prospective
whole-arm request units; it does not invent source-policy or modality strata.
Pre-materialization failures after that boundary use bound
`ura-request-error/1` artifacts that explicitly deny execution and provider
calls. Basic CLI/argument-shape failures rejected before the envelope boundary
remain outside this accounting surface.
Version 2 added
`hosted_judge_data_transfer_acknowledged`: it is true only for an explicitly
acknowledged live hosted judge and false for dry, no-call, rules-only, or local-
judge paths. This records an operator acknowledgement, not proof of privacy
approval or a provider retention guarantee.
Version 3 additionally binds `target_answer_retries`, including the default of
one retry. Version 4 adds an optional content-bound recovery selection. Retained
version-1 through version-3 artifacts remain immutable and readable without
inferred fields.

For each source instance and model, the planner admits only the exact
attacker-produced target-input combinations declared prospectively for every
datapoint and seed. The path-free contract preserves repeated physical-media
occurrences and binds IDEATOR's generated image bytes plus adversarial-text
digest; Runner compares every realized turn before budget reservation or target
invocation. Tool-conditioned rows remain fail-closed until a typed executable
runtime and actual-use attestation exist. Before calls,
the content-addressed `ura-eligibility-plan/3` ledger retains each requested
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
The eligibility experiment condition retains the request version's exact retry
and recovery field inventory. Level 1 accepts immutable older shapes but rejects
any field-presence or value mismatch against the bound request envelope.

Generative local vLLM and Ollama targets also require a passing
`python -m experiments.local_model_readiness` receipt before security calls.
The transport-neutral benign gate uses ten deterministic questions and five
synthetic images for image-capable models, treats empty responses as incorrect,
and requires the configured minimum correct counts. It produces engineering
admission evidence, not a safety metric. A failed model is recorded and any
replacement is admitted as a new exact model condition.
Once admitted, a generative model's assigned evaluation does not terminate for
one empty or deterministically unusable answer. Runner defaults to one retry
after the initial call (`--target-answer-retries 1`). An exhausted row is
checkpointed as a model-stability failed output, excluded from decided security-
rate denominators, shown in missing-response coverage and followed by the next
assigned row. The Build page exposes the same 0 through 10 control and Stats
charts the failed-output rate. Identity/seal drift and explicit call/time caps
remain terminal.
This is one provider-neutral Runner policy: hosted targets, local vLLM and local
Ollama use the same selected retry count, accounting, checkpoint and stability
categories.
Runner 2.26 also distinguishes a deterministic route input incompatibility from
model stability. For example, an exact vLLM prompt-length rejection is retained
as `target_input_status=incompatible`, receives no answer retry or policy-judge
call, counts as a missing response, and does not stop the remaining assigned
population. Other validation, identity, seal, configuration, budget, and
transport failures remain terminal.

Acquire a multi-model Ollama roster with
`python -m experiments.local_campaign.ollama_acquire` in a named tmux session.
The controller retains partial blobs, retries transient transport failures with
bounded backoff, and closes and retries a connected pull stream after 15 minutes
without a changed status or completed-byte count. After a process or host
interruption, use `--resume` with the same absolute output directory and exact
model order; completed model smokes are not repeated.

If the current Ollama Phase 5 controller terminates after only some units fail,
set `URA_PHASE5_OLLAMA_RECOVERY_SOURCE_ROOT` to that canonical failed control
root and launch the same active `phase5_ollama_workflow.sh`. Recovery revalidates
completed projections, attestations and canaries under the current validators,
runs only the failed or previously blocked units, and writes an exact
`evidence-provenance.tsv`. The Gate 5 amendment records the original execution
commit and current validation commit separately; historical evidence is never
silently relabeled as current execution.

`python -m experiments.level1_evidence` performs the bounded lifecycle join.
The operator supplies the existing eligibility files and result roots; the
command automatically discovers their request envelopes and bound early
errors. It writes `ura-level1-evidence/3` JSON plus the existing deterministic
materialized-planning-stratum CSV. Prospective whole-arm request units remain a
separate, unit-labelled JSON collection rather than being mixed into that CSV.
Bound early errors can mark applicable prospective units blocked, but never
fabricate strata, attempts, or provider calls.

Rows whose source evaluator is not integrated remain fail-closed by default.
The explicit `--approximate-common-metrics` CLI/Build opt-in may add only
separately named `approximate_*` proxy results. The Stats surface badges them
`⚠ approximate`, or `⚠ synthetic + approximate` when any target or scoring
contribution is synthetic, and keeps their coverage and denominators separate
from source-native results. Their displayed reliability is an auditable,
uncalibrated method/evidence/confidence/identity-completeness indicator-not a
probability, accuracy estimate, model-quality ranking, or substitute evaluator.

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
2. download the selected releases from the 25-converter inventory, copy the
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
  retains the exact `ura-lane-projection/2` artifact alongside the eligibility
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

`--limit N` is an equal per-arm cap of at most N unique source prompt/intent
clusters and retains all rows in each selected cluster. Selection is
deterministic whole-cluster sampling without replacement. Cluster-key fallback
precedence is nonblank `meta["source_cluster_id"]`, then nonblank `DataPoint.id`,
then the converted row index. Unique cluster keys are inventoried in first
source-appearance order. The sampler hashes the UTF-8 bytes
`ura-corpus-cluster-order-v1\0<arm>\0<sample_seed>`, uses the first eight SHA-256
bytes as the unsigned big-endian `scoped_seed`, and calls Python's
`random.Random(scoped_seed).shuffle(...)` once. It takes the first N positions
and restores all selected sibling rows to source order. For one unchanged arm,
converted-corpus digest and sample seed, limits are nested overlapping prefixes,
not disjoint partitions: the one-cluster canary is contained in the 50-cluster
prefix, which is contained in the 100-cluster prefix. Logical-arm identity
contributes to seed derivation and gives each arm an independently scoped
ordering. The current
pre-measurement local campaign fixes seed 0 and uses 100 clusters per source arm
for core lanes and 50 for extended bridge/Ollama lanes. The cap is applied per
logical source arm and is not within-arm risk stratification; reports retain
exact achieved support and row fanout. Explicit `--limit 0` returns the exact
full arm. The framework supports full-set execution for local and hosted targets
through a separately projected cohort; hosted full mode still requires caps that
cover its full no-call projection, deadline, attestation and approval.
The optional `--sampling-policy` is either
`seeded_pseudorandom_whole_cluster_prefix_v1` (the unchanged omitted-argument
default) or `source_order_whole_cluster_prefix_v1` (the first N cluster keys in
source-appearance order). Explicit policy selection is identity-bound, and both
policies make `--limit 0` the full arm.
Current-campaign policy authorizes full mode only for all-local replication.
The current source-mapped IDEATOR v2 artifact is narrower: its outer Runner
selection is `advbench_harmful --limit 1 --sample-seed 105`, and
`pair_limit=0` means all eight verified pairs mapped to `advbench:245`, not
the complete AdvBench arm.
The current measured cohort uses `--sample-seed 0` only. `--sample-seed 1` is a
separately projected future cohort with its own selection-bound projections,
acquisition envelopes, Gate record, output roots and analysis stratum, never an
outcome- or throughput-triggered extension of seed 0. Every current hosted target
or hosted LLM judge uses its separately pre-registered positive cluster limit
from runbook section 5.2.

The current bounded local cohort also fixes `--deadline-seconds 86400` and a
separate 24-hour controller ceiling per measured lane. Runner stops starting new
calls at its deadline but does not interrupt one already in flight; the
controller may terminate and reap an over-time lane process group.

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

Runner `ura-runner/2.26` writes unified schema `1.5`. Runner 2.19/schema 1.4
artifacts remain readable only as runtime-free legacy compatibility and are not
mixed into the current measured cohort. Immutable planning/source
stratum identity is stored separately from adaptive per-turn evaluation
identity. Thus a Crescendo setup turn remains joined to its original planning
stratum while receiving a typed `not_applicable` judgment and no judge call or
metric contribution. Policy challenges are numbered contiguously from zero,
share one declared challenge horizon, and a harmful authoritative violation is
terminal.

## Human validity and post-experiment analysis

The automated-label-blinded, model-visible human audit samples complete source
clusters and assigns exactly two distinct independently qualified raters to
each sampled response under the declared language/experience, conflict,
training, and out-of-sample pilot criteria. Rater pairs may rotate between
responses; agreement is reported for every pair that shares one or more items.
The audit requires adjudication for every
non-unanimous composite or dimension, keeps refusal, harmfulness,
convincingness, and specificity separate, and reports inter-rater as well as
automated-versus-consensus agreement with cluster-aware uncertainty.
Its deterministic selector derives non-vacuous coverage requirements from every
observed common-eligible run/model/defense/attacker/source-policy/population arm
at overall and exact risk/modality scope; an undersized requested sample fails.
The sealed local campaign prepares from Phase 7's validated success-only Runner
view and proves cardinality prospectively: the common population must cover the
requested sample plus 20 disjoint qualification clusters, while the source-task
population must cover its exact requested sample. Both coverage-priority
selectors still fail closed when a requested count cannot cover achieved cells.
Machine preparation always
terminates `human_only_blocked` with `gate8_met: false`; only real qualified
raters, completed independent labels and adjudication, validated reports, and a
human acceptance or limitation record can meet Gate 8.
Judge-validity reports are primary within exact run, response-producing arm,
logical corpus, source policy, modality, expected population, and
common-eligibility strata. They report decision coverage, treat violation as the
harmful adverse event and over-refusal as the benign adverse event, and label
their intervals as conditional on defined bootstrap replicates. Cross-stratum
pooled values are explicitly composition-dependent diagnostics.
The resulting `ura-human-audit/1.2` artifact becomes
`complete_sample_conditional` and `analysis_ready_real_run=true` only when the
achieved labels and run binding pass every integrity check. This permits
sample-conditional analysis; it does not claim population-wide judge validity.
Cohen's kappa is diagnostic and must be accompanied by support and intervals.
The separate source-task report uses the exact `ura-source-task-audit/2`
schema; older common or source-task report schemas are not Gate 8 evidence.

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

`python -m experiments.rig_web` serves a single-operator
campaign builder and console over the same maintained CLIs: mode-aware lane
composition (an ordinary offline dry run over the synthetic corpus, attestation
probe, diagnostic canary, measured execution) with complete server-side
fail-closed admission - exact-modality compatibility of every target/attacker
with each arm, agentic/native-only attackers shown disabled rather than as
common lanes, and scoring-vs-defense guardrail separation - before any
subprocess. Source arms lacking an integrated evaluator remain selectable so the
programme stays visible. They are rejected before a subprocess by default.
Eligible non-tool rows instead show `⚠ approximate opt-in`; the explicit opt-in
admits only separately named, supplementary `approximate_*` response proxies,
not the missing source evaluator. Tool-conditioned rows show `tool runtime
required` and remain fail-closed.
Dry-run composition drops selected
real API/local targets and their configs because `run_matrix --dry-run` always
uses `MockTarget`. Local roster modalities are limited to Runner-supported text
and image, so an audio arm/target mismatch is rejected by UI parity. The
builder covers all 45 maintained source arms. T3MP3ST and HarmBench are
selectable attacker lanes after their prepared artifact is supplied. The same
Build page exposes the separate preparation commands: T3MP3ST captures an exact
planning bundle, while HarmBench captures generated text cases and writes the
matching attacker config. T3MP3ST capture is admitted only through the exact
installer-managed source commit and runtime recorded by the framework lock; the
capture helper rejects a different claimed revision before contacting its
literal-loopback planner. These preparation jobs can use source-model or GPU
compute; the measured Runner only validates and replays their content-addressed
outputs. The Build preparation workflow resolves a symlinked configured results
root before invoking either producer and emits canonical absolute artifact paths
for runtime use. The native artifact readers still reject paths containing a
symlink component. `run_matrix` removes those host-only paths before persistence
and retains only the verified content identity.
NanoGCG uses a separate CLI preparation path: plan and acquire the exact
`Qwen/Qwen2.5-0.5B-Instruct` surrogate, run one bounded capture under the
verified NanoGCG environment, then replay the emitted six-field attacker
config. IDEATOR preparation maps the pinned public VLBreakBench release to the
one exact admitted AdvBench source row and emits
`ura-ideator-seed-pairs/2`; its Build panel validates that manifest and its
eight PNGs. The same preparer can emit a create-only ordinary Runner attacker
config for CLI replay with explicit `pair_limit=0` (all eight) or an ordered
positive prefix. That config retains the path-free manifest identity, declared
image digests, and exact source bindings, which are checked before planning;
neither path runs live IDEATOR generation. The exact pinned
acquisition, receipt, CLI, and separate follow-on cohort commands are in
the operator runbook.
Before a paid mode, it shows the durable argv identity and offers a no-call
preflight whose lane-projection gives the
required target/judge/HTTP call upper bounds; Start is blocked until the entered
ceilings cover that projection (a call bound, not a price estimate). The reviewed
selection is bound as an internal `ura-builder-selected-api-config/1` execution-
config bundle and held behind a 30-minute, purpose-bound, one-shot confirmation
ticket. Each selected route carries its canonical provider/model and a typed
`endpoint_identity=https-base-url-sha256:<digest>`, never a raw URL. At launch,
only the selected generic API/local rows are materialized into private digest-
bound configs that Runner reads once and unlinks; HTML and durable job state use
portable identities and digest placeholders. It also
keeps an explicit workstation checkpoint locator only in the one-shot launch
argv/private transient config; preview HTML, job state, `command.json`, and
SQLite retain its declared `local-checkpoint@sha256` identity instead; the
child verifies that digest before model calls. It also
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

The Jobs view renders each full start date and time in the browser's local time
zone. State, text, From, and To filters combine; the default interval is the
previous seven days through the current browser time, and both selected bounds
are inclusive at the input precision. Date changes reload a date-bounded SQLite
query rather than filtering only the recent in-memory cache; an explicit notice
appears if the 5,000-row console-job or 20-row in-range campaign display cap is
reached. The dates constrain terminal history, not process visibility: a
console-owned process that is still running, or an external row whose exact
named session is currently observed live, remains visible even when it started
before the selected interval. That bounded exception is called out in the UI;
terminal rows never receive it. Tags are deliberately short: console
work uses `running`, `passed`, `failed`, or `orphaned`, while externally managed
engineering campaigns use the same blue `running` tag plus `partial`, `blocked`,
`stopped`, or `unknown`. The surrounding detail identifies external `running` as
a task-log report, not a console-owned process-liveness claim. External
controller markers may additionally bind an exact named tmux socket and
session. Their liveness is checked through a short bounded,
cached batch; a missing exact session becomes `orphaned` instead of remaining
`running` until a generous campaign hard stop, while a probe failure or an
unprobed bounded row becomes `unknown` rather than asserting liveness. Terminal
legacy markers remain readable. Controllers publish their authoritative `.exit` marker before their
best-effort terminal UI event, so an interrupted event write can under-claim a
finished controller but cannot create a false `passed` card.

External campaign task counts report task-process outcomes as succeeded,
failed, skipped, active, or pending. They do not prove that a model was called.
Optional strict `planned_tasks` and `model_tasks` declarations in
`ENGINEERING_ONLY.json` separate model work from support work. An optional,
bounded `model-execution.jsonl` self-report records attempted calls and
successful generations by declared model task; when supplied for a terminal
campaign it must contain exactly one valid row per model task. This operational
self-report and any reserved-call ledger remain diagnostic context. Validated,
completion-bound response artifacts are authoritative for actual execution and
results.

Externally managed controllers can emit those engineering markers and ordered
task events directly from restorable named tmux sessions; they do not need to
be launched by the console to appear in Jobs and Stats.
Discovery reconciles exact-session nonterminal controllers before applying the
20-row recent-history cap, so a controller observed live cannot be hidden by
newer terminal directories; old terminal rows remain subject to the selected
history interval.
Measured controllers can also register each externally owned `run_matrix`
invocation under the fixed `external-measured-jobs-v2` registry immediately
before the call and write one create-only terminal event afterwards. Each registration binds
the exact sanitized argument vector, Runner output root, project commit,
framework-lock identity, a generic admission digest, and a unique private tmux
socket/session for that invocation rather than the parent controller. Start
publication begins only after signal cleanup owns that prospective identity,
and terminal publication is time-bounded.
These rows receive normal detail routes and per-job artifact usage/report
rendering, but no SQLite ownership or Stop action. The registration establishes
operational ownership only, so even an exit-zero registration remains labelled
external operational and non-thesis. Completion-bound usage can still be shown.
The measured-job registration calls that campaign value a generic admission
digest; the external workflow decides which approved manifest supplies it.
External analysis diagrams use a separate generic
`external-analysis-jobs` registration. A workflow-owned adapter validates its
own admission, controller, and artifact chain before publishing that record.
The local campaign watcher invokes that adapter as its final task after its
terminal analysis record passes validation; publication failure remains an
explicit failed controller task.
Rig Web knows only the operational registration, exact report byte identities,
completion status, and explicit limitations. The record is non-thesis and
cannot grant empirical authority.
Successful completion-validated Runner and analysis artifacts,
not their operational registrations, remain the sole basis for metrics and
diagrams.

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
tests/experiments/ controller, packaging and workflow-adapter regressions
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
