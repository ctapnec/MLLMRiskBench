# Architecture

```mermaid
flowchart LR
    O[Operator-selected targets,<br/>logical arms and attackers] --> E[Content-addressed<br/>request envelope]
    E --> S[Verified source instances<br/>25 converter families]
    S --> C[Converters]
    C --> U[Unified schema]
    U --> P[Release, policy, metric and modality preflight]
    P --> Q[Content-addressed no-call lane projection]
    Q --> L[Typed live route/transport receipt gate]
    L --> A[Replay or response-conditioned attacker]
    A --> T[Hosted, local or guarded target]
    T --> J[Rule, guardrail and LLM judge cascade]
    J --> R[Artifacts, checkpoints, budgets and completion]
    N[Upstream native evaluators] --> I[Content-addressed native import]
    R --> D[Diagnostics, exact analysis selection and<br/>automated-label-blinded human audit]
    I --> X
    D --> X[Post-experiment analysis and figures]
```

Experiments are pending. This architecture describes implemented control flow,
not model performance or judge validity.

## Boundaries

| Layer | Location | Responsibility |
| --- | --- | --- |
| Data | `src/ura/data_models.py`, `src/ura/converters/` | typed records, source identity, media and policy provenance |
| Attacks | `src/ura/adapters/` | replay, transforms, response-conditioned escalation, native-result bridges |
| Targets | `src/ura/targets/` | exact hosted/local invocation and provider continuation state |
| Judgment | `src/ura/judges/`, `src/ura/source_metrics.py` | ordered full-shadow cascade for common responses; source evaluator and unqueried placeholders for source-metric-only records |
| Runtime | `src/ura/runner.py`, `src/ura/request_envelope.py`, `src/ura/project_revision.py`, `src/ura/live_attestation.py`, `src/ura/lane_projection.py`, `src/ura/lane_canary.py`, `experiments/run_matrix.py`, `experiments/project_revision.py`, `experiments/live_attestation.py`, `experiments/lane_canary.py` | prospective whole-arm request identity, bound early failures, immutable local-project admission, preflight, no-call projection, typed route/transport receipt production and admission, diagnostic canary summary, execution, budgets, checkpoints, recovery and manifests |
| Analysis | `experiments/level1_evidence.py`, other `experiments/` modules | unit-qualified lifecycle accounting, paired effects, transfer, judge sensitivity, human audit and figures |

## Direct operator flow

The complete run is intentionally linear:

1. select and detach at one prospectively reviewed full project commit, create
   and digest a `ura-project-revision/1` receipt from the clean checkout, export
   its path/hash, install the project, and retain that identity for the cohort;
2. acquire the selected converter-backed releases and upstream native projects,
   then bind labelled source instances and local media roots;
3. set hosted credentials and review provider/data terms;
4. execute the intended arguments with `experiments.rig_check`, retain the
   prospective lane projection, and obtain operator approval for complete-grid
   caps and provider-side quota;
5. prepare any selected T3MP3ST or HarmBench attacker artifact under its own
   cap, outside the Runner, then bind the exact output hash to the measured
   attacker config;
6. run bounded live target/modality probes, derive and hash their typed receipts,
   and bind the same operator-declared execution scope to each measured grid;
7. execute a separately typed one-cluster diagnostic canary where required,
   then execute the eligibility-scoped common-run lanes and source-native
   campaigns with finite target, judge, transport-attempt, and time ceilings;
8. import complete native artifacts and build the no-pooling suite evidence
   inventory;
9. preserve all artifacts and ordinary provenance; and
10. perform diagnostics, the automated-label-blinded/model-visible human audit,
   post-experiment analysis, and measured rendering.

Every non-dry preflight, transport probe, diagnostic canary, and measured Runner
request consumes that same digest-approved receipt. It verifies local expected
and observed commit equality, HEAD tree, common driver/imported-harness Git root,
clean tracked state, and current driver/harness source digests. Its compact
binding travels through eligibility, grid, `RunManifest.config.run`, completion,
live-attestation, and postprocessing identities. A revision change is a
prospective protocol amendment and new cohort, not a resumable old run. A fully
synthetic dry-run is the sole explicit exemption and records
`mode=not_required_diagnostic_dry_run` together with actual source digests.
Neither mode authenticates a remote repository or proves empirical validity.

Prepared attacker paths cross an explicit runtime boundary. The console resolves
its configured results root before invoking T3MP3ST capture or HarmBench prepare,
so a symlinked root yields canonical absolute operational artifact paths. Native
artifact readers still reject any supplied path with a symlink component.
`run_matrix` verifies the bounded file and declared digest, then persists only
its content hash and byte size rather than the host path.

## Schema and source boundaries

Converters preserve source item identifiers, policies, expected behavior,
modalities, cluster identity, and source-specific metric metadata. A unified
record does not imply a unified estimand. Common ASR/FRR admission requires a
substantive implemented evaluator for the exact source/metric pair; conversion
alone is insufficient.

The registry contains 25 converter families spanning harmful and benign text,
image, audio, video, classification, prompt-injection and represented-agent
sources. Release-pinned converters enforce their implemented official contracts
before target calls. `--source-config` maps a stable corpus-arm identifier to a
converter, an environment-variable path locator, and optional split/source
label. This supports multiple instances of one converter without persisting a
machine path. Real corpora resolve through environment paths.
For one unchanged converted-corpus digest and `sample_seed`, bounded real-source
cluster selection uses a deterministic shuffled ordering and nested prefixes;
`--limit 1` is therefore contained in a later `--limit N` selection. Every row
belonging to a selected cluster is retained.
An explicit `--sampling-policy` may retain that seeded pseudorandom ordering or
select the first N whole clusters in source-appearance order. Omission preserves
the historical seeded behavior and artifact shape. Explicit policy choice is
bound into request, acquisition, eligibility, projection and run identity;
`--limit 0` remains the complete arm under either choice.
Local media is digest-checked beneath ordered approved roots and persisted as
`@media-root/<index>/<relative-path>` so artifacts do not retain an author's
absolute path.

The registry is configuration provenance, not acquisition evidence. Every
selected non-synthetic measured run and every no-call `rig_check` preflight also
consumes one exact, compact
`ura-source-conformance/1` receipt. Before target construction the driver
rehashes its declared source files and derives the converted-corpus, cluster,
policy, metric-mode, and media evidence already needed by the runtime. A
selected arm that is not operator-admitted with an observed revision,
approved access/license review, reconciled source counts, and a passed bounded
semantic mapping check fails closed. These checks validate the supplied receipt
and current conversion only; they do not establish upstream authenticity, automate
a legal determination, or establish benchmark/evaluator validity.
A real-source `run_matrix --dry-run` can inspect conversion without a receipt,
but that diagnostic is not admitted preflight or experiment evidence.

## Multimodal admission

For each grid, the planner intersects that grid's selected-corpus modality
combinations with each target's declared capabilities. It requires those
selected supported combinations, not an invented Cartesian product. Post-run validation
requires real eligible Attempt-Response evidence for each delivered
combination. Tags without byte-backed delivery, setup-only turns, and input-side
defense blocks do not count.

Runner 2.26 plans a path-free attacker-input contract for every selected
attacker x datapoint x seed before constructing target or model-backed defense
engines. Eligibility, modality coverage, attestation keys, and lane identity use
the attacker-produced target-call combinations. Immediately before each budget
reservation and call, Runner compares the rendered request's exact channel
combination, ordered/repeated physical-media identities, policy-evaluation
scope, and any bound adversarial-text identity with that prospective turn.
Tool-conditioned input is rejected unless a typed executable runtime and
actual-use attestation exist. This closes the former source-only planning gap in
which an attacker could add media (IDEATOR), lose repeated media, or serialize a
tool trace without changing admission evidence.

Eligibility is represented as a requested-target x selected-source-stratum x
exact-modality x attacker relation, not an invented complete Cartesian product.
After the selected corpora materialize, `run_matrix` writes a content-addressed
`ura-eligibility-plan/3` artifact before any model call. It retains every
requested planning stratum as `compatible_if_isolated` or `N/A`, with its failed
gates, whole-arm execution-unit status, and bound configuration/corpus digests.
Its experiment-condition projection preserves the version-specific request
shape. Current requests bind answer retries and nullable completed-prefix
recovery selection, while retained older projections remain byte-compatible;
Level 1 rejects any request/condition presence or value mismatch.
This is planning evidence only: it is not a live
attestation, attempted/completed-cell record, or scientific result.

At the earlier boundary, after basic argument/axis validation but before config
or source materialization, `run_matrix` writes `ura-request-envelope/6`. Its
units are exactly requested target x logical source arm x attacker. A bound
`ura-request-error/1` may then record a configuration, source-integrity,
conversion, empty-corpus, or diagnostic-admission failure at whole-request,
target, arm, or exact-request-unit scope. Such an error states that execution and
provider calls did not start. It never reconstructs source-policy/modality
strata or claims attempted execution. Argument parsing and basic request-shape
rejections before this boundary are not retroactively represented. The envelope
is the operator-selection universe, not normalized config/receipt identity;
config-only variants sharing it belong in separate Level-1 cohorts.
Version 2 also binds the Boolean
`request.hosted_judge_data_transfer_acknowledged`: true records the explicit CLI
acknowledgement for a live hosted judge, while preflight, dry, rules-only, and
local-judge requests retain false. It does not certify privacy review or
provider retention behavior.
Version 3 also binds `request.target_answer_retries`; the default is one
additional answer attempt. Version 4 binds an optional content-addressed exact
completed-prefix recovery selection for one source arm. Version 5 permits the
same prefix contract across multiple arms. Version 6 additionally binds an
exact completed-ID selection across multiple arms, allowing Runner to execute
only the set difference when the nested sampler restores selected rows to source
order. Retained version-1 through version-5 envelopes validate without
relabeling or inferred fields.

After the whole request passes admission and before the first generation call,
Runner 2.26 writes a content-addressed `ura-lane-projection/2`. The artifact
binds the exact experiment condition and eligibility descriptor, selected
record/cluster/source-policy counts, deterministic sampling identities,
selected physical input-media bytes, and the conservative complete-grid target,
model-judge, local-guardrail, and declared HTTP-attempt exposure. A measured
grid binds its exact projection descriptor; `rig_check` validates and copies the
same artifact class into the separate preflight tree. Input bytes are observed
from selected local media, not an expected-output estimate. Token use,
price/cost, runtime/throughput, and expected output storage remain
`CANNOT-VERIFY` until independently observed and are never extrapolated by the
projection.

The read-only `experiments.level1_evidence` boundary automatically discovers
request envelopes from supplied result roots and eligibility siblings, then
joins any final plan in one selected `run_matrix` cohort, including plan-only
structural-`N/A` or blocked requests, to complete or partial grids under the
same content-derived condition. Its `ura-level1-evidence/3` output retains four non-interchangeable units:
prospective whole-arm request units, materialized planning strata, whole-arm
execution units, and completed Judgment records. Prospective units stay in the
JSON and are not planning rows. Whole-arm execution is projected onto a
planning stratum only after the completed artifacts cover that stratum's exact
selected-datapoint count and identity digest. Grid, completion, and error
evidence remains bound through locator/SHA-256/byte descriptors; a mismatched
embedded plan or artifact descriptor fails closed. The cohort's
`evidence_kind` is either `diagnostic_dry_run` or `measured_run`, and those modes
cannot be mixed in one artifact. For measured grids, the current boundary also
consumes each grid-bound `ura-live-attestation/2` artifact by exact byte digest,
reconstructs its route/config/scope/age and exact-modality prerequisite, checks
the completed cell's stable realized identity, and reports matched record-level
attestation support. Probe grids are diagnostic and cannot enter a measured
Level-1 cohort. Analysis inclusion remains `not_supplied` with null counts; the
system does not infer it from a folder or post-hoc output. Pre-materialization failures are
bound to prospective request units only; the join never fabricates
source/modality rows or calls for them. It identifies
diagnostic dry-run input but explicitly sets empirical validity to false.
No-call `rig_check` plans and live transport-probe artifacts remain in separate
preflight/attestation trees and are not supplied as measured Level-1 requests.

Physical media reaches the target as verified bytes. The maintained automated
judges are not pixel/audio/video evaluators: where a release provides a safety
reason, transcript, or harmful-intention reference, they grade target output
against that source text and record the proxy mode. Without such a defensible
reference, a media-conditioned row is `N/A` for common automated metrics. A
separately typed `response_only` endpoint may grade literal response behavior
without a reference, but cannot support a claim about media understanding.
Media-aware human review is the validity path. Target modality coverage is never
renamed as direct multimodal judging.

## Target and judge identity

Hosted and local targets implement one message-level contract but retain
provider-specific authentication, sampling controls, media encoding, refusal
semantics, and continuation state. The runtime records requested and realized
target identities and rejects non-null identity drift within a cell or across
resume.

Generic account-visible routes are described by `--api-config`; fixed
provider-specific routes retain their dedicated adapters. Exact identifiers and
capabilities are provisional until a bounded non-dry probe yields a strict
`ura-live-attestation/2` receipt. The receipt binds its producer grid/completion
digests, operator-declared non-secret execution scope, requested and base-resolved
target, hosted/local route kind, secret-free route-config digest, exact delivered
combination, UTC observation, harness/driver source digests, and realized
identity. Ordinary non-dry grids fail
closed on a missing, stale, future-dated, ambiguous, or mismatched receipt before
target calls; a returned or restored response must also match the attested stable
provider/runtime identity. Exact combinations are not widened: text+image is not
evidence for text alone. `rig_check` and dry-run remain no-attestation paths.
The UTC observation is the probe Runner manifest's content-bound `started_at`,
used as a conservative lower bound instead of mutable outer-grid `finished_at`
metadata.
Local vLLM and Ollama configuration entries are content-bound, but they have
separate runtime contracts. The two-4090 vLLM topology admits one local
model server per process. A model that fits one card normally uses tensor
parallelism 1; the other card can host the scoring guard or independent
evaluation, and a larger
profile-fit model may resolve to two-card tensor parallelism. Hardware auto
chooses the highest fitting precision: unquantized 16-bit, FP8 8-bit on SM 7.5+,
then BitsAndBytes 4-bit on SM 7.0+. The exact quantization and card count remain
a recorded execution condition; the estimate never substitutes for local-engine
preflight. Expert/MoE-ambiguous names stay parameter/fit-unknown until an exact
`parameter_count_b` is declared; their names never authorize a download or fit.
The vLLM-only `max_model_len` sets the engine context and KV-cache allocation
policy independently of generation `max_tokens`. Omission binds vLLM's `-1`
automatic fit mode, which derives the model ceiling and reduces the allocation
to current GPU capacity. An explicit integer in 1..1,000,000 must be at least
`max_tokens`, is passed at engine construction, and is retained in normalized
execution provenance.

Runner 2.32 uses one provider-independent execution-profile boundary for local
generative models. `local_model_readiness` starts at the 25,000-token local
ceiling and descends until a forced generation reaches its cap below 120
seconds in the text-throughput stress. An image-capable target must additionally
return a nonempty physical-image response below the deadline; a valid early stop
does not negate the throughput measurement. It then applies the seeded 10-text
and 5-image responsiveness thresholds at that cap.
Each stress child publishes a transient generation-start marker. Its parent
enforces the deadline by terminating the isolated process, so setup time stays
outside request latency and an uninterruptible CUDA call cannot overshoot the
selection threshold. Before and after each isolated Ollama child, the parent
holds the cross-process inference lock and clears only residency whose exact tag
and digest match that target. It refuses foreign or co-resident models instead
of adopting or unloading them.
A machine-local registry binds the recommendation to the exact revision or
digest and modalities. Both CLI and Build use its hardware-fit context, vLLM
tensor-parallel size and GPU memory utilization, vLLM `max_tokens`, Ollama
`num_predict` and thinking mode, and request deadline; an explicit local config
value cannot replace the approved profile. Each text/image stress observation runs in a
fresh child process. That process exits before the next lower candidate, so an
interrupted vLLM request cannot retain CUDA state or contaminate later
measurements.
Hosted targets and judges never read this registry: their explicit output caps
remain paid-budget inputs and their answer-quality retry count remains zero.
Transport attempts have a separate configured allowance.

The target boundary keeps output stability separate from input compatibility.
Runner 2.26 retains an exact deterministic target-input rejection, such as a
vLLM prompt exceeding the admitted context cap, as a typed missing response. It
does not retry that unchanged input, does not query policy judges, and continues
the admitted population. The sealed private-execution boundary exposes only the
safe typed disposition and bounded reason; unrelated third-party exceptions,
identity drift, seal failures, and mutable configuration remain terminal.

Runner 2.27 binds an explicit Ollama thinking policy in every local route:
boolean disabled/enabled where supported, or low/medium/high for models with a
graded control. Separate daemon `message.thinking` output is never used as the
final answer and is not persisted as reasoning text. The adapter records only
whether it was observed and rejects thinking output when the bound policy is
disabled. Local vLLM and Ollama exhausted-answer handling remains one shared
Runner policy. A hosted target instead requires zero answer retries; its first
retained failed output or target transport/network failure opens the global
`paid_provider` circuit before another paid call.

Network and HTTP failures retain a transport-retry state separate from unusable
model-generated content: `pending`, `not_retryable`, `exhausted`, or
`needs_review` when eligibility cannot be established. HTTP 400 is not
automatically retried; inspect its retained error code before attributing its
cause. Retry exhaustion uses the lifetime physical-attempt ordinal, including
attempts from earlier invocations. The common response boundary
validates that this state belongs only to a typed transport failure. It does
not assert that the provider generated an empty answer, that a retry worker
is running, or that a retry is already authorized by the monetary ledger.
Unknown charges remain reserved, and any continuation must preserve the
original input and count every physical attempt within its remaining cap.
The shared hosted transport loop retries typed transient connection/timeout
failures as well as HTTP 408, 409, 425, 429 and 5xx. Its default remains three
retries, or four physical attempts total; no provider SDK retries are hidden
under that count. Statusless network attempts with unknown provider acceptance
retain their complete monetary reservation before another attempt is admitted.
Authentication, request-validation and arbitrary programming errors are not
automatically retried. Exhausted transport stays pending for reviewed recovery.

Explicit recovery after a verified adapter correction is separate from that
transport loop. It binds the precise retained parser failure and repaired
target revision, preserves the original failed record and unknown charge,
and continues the same funded physical-attempt sequence. It cannot select a
usable answer for regeneration or enable automatic answer-quality retries.

Every Hugging Face model is admitted through one sealed acquisition boundary.
`collect_run_requirements` projects the five supported roles (vLLM target,
local vLLM LLM judge, scoring Guardrail, defense Guardrail, and NanoGCG
surrogate) into unique public repository plus immutable 40-64-hex commit
resources. It rejects target/judge/guard and target/surrogate identity
collisions before plan generation. Path-free explicit-checkpoint digest and
precomputed-NanoGCG-suffix exceptions remain in the same selection. The
selection digest covers the portable API/local/source/attacker/project/request
bindings; controller ticket nonces and receipt timestamps do not become
scientific identity.

Plan-only execution writes one strict `ura-model-acquisition-plan/1` document
and returns before any model-bearing component is constructed. Only the
dedicated `experiments.model_acquire` controller may contact the fixed Hugging
Face endpoint or receive `HF_TOKEN`. It resolves the complete upstream file
inventory, transfers only missing bytes under cross-process locks and bounded
byte/free-space/deadline limits, seals each immutable snapshot, and writes a
path/token-free receipt. A cache hit is fully reverified and emits no download
activity. Normal and preflight processes require the exact plan/receipt/store
triple, remove Hub tokens, set Hugging Face/Transformers/vLLM offline and
telemetry-disabled variables before optional imports, and pass only private
managed snapshot locators to constructors. One shared resource lease spans the
full pre-load hash, construction, and full post-load hash; post-load drift
drops the object and no target, judge, guard, or surrogate call may occur.
Explicit local checkpoint directories use the same pre/post content seal.

The result tree retains create-only canonical plan and receipt copies and a
strict `ura-model-acquisition-runtime/1` provenance descriptor. Scientific
grid provenance uses `ura-model-acquisition-execution/1`, which retains the
selection, plan, upstream-manifest, size, and content-tree facts while excluding
receipt-event fields and the mtime-bearing stat inventory. Scientific common
conditions use a plan-free `ura-model-acquisition-role-projection/1` containing
only shared judge/guard/defense/surrogate facts. Each Runner cell uses the same
projection plus its own local target, if any. This prevents an unrelated target
elsewhere in a mixed grid from fragmenting a hosted cell or transfer cohort.
Figure, transfer, Level-1, and Level-2 ingestion revalidate the complete grid
documents and require each role projection to be their exact subset.

Historical reporting can explicitly select a trusted Git repository to run
the exact producing revision's validators. Current exporters compute their
reports only after source identity and retained artifact validation succeed.
The multi-artifact validator IPC is bounded separately from a single persisted
JSON artifact (512 MiB UTF-8 and 32 million nodes); strict parsing and all
original per-artifact limits remain unchanged. Level-1 attestation references
follow each attacker's physical target-call modalities, not a source-only
modality shortcut. Neither historical reading nor reporting finalizes an
interrupted grid or promotes an unreferenced completion marker.

PyRIT 0.14.0, DeepTeam 1.0.7, h4rm3l 0.2.4, and Spikee 0.9.1 use a separate
engine-runtime boundary. Each framework lives in its own explicit venv; no
adapter imports it in the Runner process and there is no PATH or in-process
fallback. A private `ura-engine-runtime-config/1` pairs each selected interpreter
with a previously observed path-free receipt and is itself accepted only with
its exact file SHA-256. Before targets, judges, or attacker objects are built,
the Runner starts one fixed standard-library worker with `-I -S -B`, no
credential-bearing environment, a private HOME/cache, a PATH limited to that
venv, and a dedicated process group/job. The worker derives its venv and exact
site-packages root from its executable and `pyvenv.cfg` without importing
`site`, hashes the interpreter, installed inventory, primary RECORD tree, and
the complete site tree including executable bytecode, then adds only that
verified directory via a source/extension-only top-level finder. `.pth`,
`sitecustomize`, ambient import roots, and top-level sourceless bytecode cannot
run before or substitute for this admission. Any nested legacy sourceless
bytecode Python may execute is bound by both the opening and closing tree seals.
Installer receipts express that complete retained-tree algorithm as
`ura-framework-runtime-content-seal/2`; the outer receipt remains
`ura-framework-runtime-receipt/1`. An older nested seal cannot verify under the
current installer, and each seal migration receives a new lock identity/store
without rewriting its predecessor.

The admitted worker persists for all operations in the matrix. Requests and
results cross a fixed strict-JSON/create-only artifact protocol with bounded
depth, nodes, sizes, names, counts, regular-file identity, and no-follow reads;
Spikee's generated dataset is the sole file result. This avoids a full
multi-gigabyte environment hash per attempt. Close performs a second full
content verification, terminates the complete descendant tree, and produces an
exact closing seal. Runtime-backed completion markers remain pending until that
seal succeeds. Stable run/grid/eligibility identity contains only the receipt
and bridge hash, never the private interpreter or mutable lifecycle status;
the grid retains opening and `closed_verified` selections for audit. Figure,
transfer, and Level-1 consumers bind manifest identity, per-cell close, selected
attacker set, and grid close before accepting evidence. This boundary limits
dependency collision and evidence ambiguity but is not a network, filesystem,
or account sandbox.

The process boundary is parent-death-bound as well as explicitly stoppable: a
POSIX watchdog owns a liveness pipe from the Runner, while the Windows worker
tree lives in a dedicated `KILL_ON_JOB_CLOSE` Job Object. If the Runner exits
without reaching its close path, loss of that parent-owned capability tears
down the worker and descendants; no completion seal is published.

NanoGCG live optimization needs a stronger cross-process managed-snapshot
load/post-load verification handshake. Until that Stage-2 protocol exists it
fails before framework, snapshot, model, or target construction. Stage 1 admits
only attributable precomputed-suffix replay and explicitly records
`framework_execution=not_invoked`.

This material evidence change advances the current contracts to Runner 2.26,
unified schema 1.5, `ura-eligibility-plan/3`, and
`ura-level1-evidence/3`. Exact Runner 2.19/schema 1.4 non-runtime artifacts stay
readable through an explicit empty-runtime normalization; no legacy artifact is
allowed to attest runtime-backed framework execution.

The later output-policy and paid-spend stop changes advance executable code to
Runner 2.27 without changing unified schema 1.5 or the byte contracts of retained
Runner 2.19 through 2.26 artifacts.

Runner 2.29 adds hardware-fit context admission without changing unified schema
1.5. vLLM uses its `-1` auto-fit mode. Ollama begins at the pinned model-native
ceiling and halves that value with load-only probes until `/api/ps` proves the
entire loaded runtime is GPU-resident. Only the accepted value reaches a real
prompt; the requested policy, probes, and resolved allocation are retained.

Runner 2.29 also separates GPU phases for response-independent local
attestation, diagnostic-canary, and measured cells. It completes the
target-response checkpoint first,
closes the target, then loads the model-backed scoring cascade and adjudicates
those durable responses. The grid and run condition bind
`judge_execution_schedule=post_factum_after_target_release`. This is same-run
sequencing, not an unbound later re-adjudication. Crescendo remains inline
because the verdict changes the following turn. A defense guard remains in the
target phase because it changes the treatment being measured.

Retained-output re-adjudication is a separate workflow. Its read-only comparison
report validates a completed paired-judge execution against both original
source views and retains the original cascade's decision or abstention. Unique
judged outputs and comparison links are separate counts, so reusing a local
answer across hosted comparisons neither repeats its paid judgment nor creates
independent observations. Stats renders this as `judge_comparison`, with
revision/output-policy/cascade strata, same-model annotations, cluster-weighted
uncertainty and the selected outputs' generation conditions. Neither the report
nor its UI registration constructs a target or judge or establishes human
calibration. Source campaign reports retain missing-input and target-cost
accounting outside the answered matched cohort.

Current comparisons average repeated outputs within each exact input before
averaging inputs within a source cluster and applying equal cluster weights.
Contrasts first count each distinct retained answer once on each side of an
input comparison; repeated links to a shared answer do not multiply its weight.
Stats exposes output, distinct-input and source-cluster counts separately.
The report-only upgrade preserves every original response, judgment, usage
record and selected execution condition. Historical reports remain readable
with their original weighting, while a newly written report identifies the
input-balanced method explicitly. This correction does not enlarge the
selected cohort or turn repeated requests into independent experimental units.

After verified target teardown, the judge performs its own hardware-fit
selection and may use one or both GPUs. The target phase does not reserve a
fraction of another device for later scoring, so target utilization and memory
observations describe the target condition rather than target-judge
co-residency.

Eligible response-independent vLLM work without runtime-backed attackers uses
process exit, not just an in-process close, between target generation and local
scoring. An optional once-only Runner lifecycle callback loads the target only
when a response is genuinely missing. A fresh judge child restores exact
checkpoints without loading that target. The parent permits only bounded,
durable progress and keeps the same request and budget across children. A
retained planned manifest preserves the original target start time for probe
freshness. The later completion-marker handoff releases judge allocations
before the next cell. No response is regenerated merely to change process
ownership, and no framework closing seal is bypassed.

Runner 2.32 leaves unified schema 1.5 and retained Runner artifacts unchanged.
Its current pre-execution gate writes `ura-local-model-readiness/4` and the
machine-local `ura-local-model-execution-profiles/3` registry. Readiness schemas
`/1` through `/3` and registry schemas `/1` and `/2` remain historical records
but cannot supply a current execution profile. Runner 2.32 also preserves typed answer and input failures
across the sealed vLLM execution boundary, so the provider-independent retry,
missing-response, and continuation policy applies to vLLM as well as Ollama.

An Ollama entry instead identifies a tag present in the live loopback daemon
after a successful pull or discovery transaction. Rig Web may Start, Stop, and
Pull only through its proven current-console-owned child; an external daemon is
available for bounded discovery and inference but not UI Stop or Pull. Each tag
requires the exact 64-hex `/api/tags` digest and a
unique modality declaration containing `text` and optionally `image`, and it
forbids every vLLM-only fit, quantization, topology, parameter, output, and
context field. The pulled artifact fixes precision. The adapter uses the
daemon's HTTP API through the Python standard library, with no Ollama Python SDK
dependency.
Runner 2.26 local vLLM/Ollama adapters use the shared deterministic rendered-
dialog fingerprint as the non-blank `Response.attempt_id` placeholder required
at target-return validation. Runner replaces that transport-local value with the
canonical Attempt ID and run ID before judgment, checkpointing, or persistence.
It is linkage scaffolding, not scientific identity or empirical evidence.

This receipt is deliberately not a cryptographic identity or account credential.
`execution_scope_id` is an operator assertion, so equivalence of accounts,
regions, projects, or runtime environments is CANNOT-VERIFY from the receipt.
It establishes only historical route/access and byte-backed delivery for the
recorded target/combination. It does not establish safety, source fidelity,
evaluator validity, benchmark validity, human validity, or future availability.
A synthetic live text or text+one-pixel-image probe needs no source receipt or
human rating and can exercise this transport boundary, but it remains diagnostic;
audio/video currently require prepared real-source media because no synthetic
audio/video fixture exists.

The judge cascade retains every queried stage's label, score, confidence, parse
status, rationale, role, and exact response binding. The first
confidence-clearing stage is authoritative; later stages are shadows. Crescendo
setup turns are typed `not_applicable`, query no judge, and enter no metric.
Judge sensitivity and human validation reuse stored artifacts and make no target
calls.

## Durability and paid-call containment

The grid declares finite matrix-wide target-call, model-judge-call,
HTTP-attempt, and call-start deadline ceilings. Reservations, response
checkpoints, completed-attempt checkpoints, circuits, errors, and completion
markers are durable. Before another external call, recovery validates the
same-grid budget high-water mark and exact run/component lineage. Malformed,
oversized, symlinked, partial, or mismatched recovery artifacts fail closed.

Every non-dry provider-backed invocation requires all logical-call and declared
HTTP-attempt ceilings to cover its complete conservative projection. This is a
fixed-universe admission rule: a smaller cap is rejected before provider calls,
not used to manufacture a paid partial result. The durable ledger records
conservative logical reservations and HTTP-attempt exposure; those values are
not realized network attempts. Provider-side project quota and an operator's
recorded cap approval remain external admission controls.

A `--diagnostic-canary` is a distinct execution purpose restricted to one
target, source arm, attacker, seed, and whole source cluster. The offline
`experiments.lane_canary` reader strictly validates the completed grid and emits
`ura-lane-canary/1`, labelled `synthetic_offline` for the mock synthetic path or
`live_diagnostic` for a live-attested path. It reports observed artifact bytes,
persisted timing observations, decision support, client-reported transport
attempts, and exercised/not-exercised roles separately from reserved exposure.
It permits no throughput, cost, storage, population, safety, or campaign
extrapolation. Default analysis admission rejects canaries from Level-1,
figures, suite summary, paired and transfer analyses, and human-audit
preparation. Native-project canaries execute under each upstream runtime and do
not enter this Runner summary.

Grid and cell locks are created exclusively and are never reclaimed
automatically. A human may remove only an exact abandoned lock after verifying
that no owner is active and recording the intervention. Infrastructure errors
remain errors and never become safe responses.

## Artifact boundary

The earliest durable success artifact is
`<envelope_id>.request-envelope.json`. A pre-materialization terminal failure is
`<error_id>.request.error.json` and is descriptor-bound to that envelope. A
later failure for the same envelope supersedes an earlier one; successful
eligibility removes the same-envelope stale error. Envelope descriptors are
bound under the exact key `request_envelope` in eligibility, grid, cell run, and
completion-validated manifest lineage.

An admitted cell persists attempts, responses, authoritative judgments,
full-shadow common trails or explicit source-metric-only placeholders, aggregate results, manifest, checkpoint, and completion
marker. A failed cell persists a typed error artifact. A complete matching
marker makes rerun call-free; a matching checkpoint resumes without repeating
completed attempts.

Postprocessing accepts only coherent completion-validated cohorts. It preserves
benchmark, source policy, modality, model, defense, attacker, judge, cluster,
seed, turn, and code/schema identity. Partial or mixed artifact families are not
silently aggregated.

## Console and operational state

The rig console (`experiments/rig_web.py`) is the approved campaign builder
over the maintained CLIs: a single-operator HTTP application
that launches every experiment as one allowlisted `python -m experiments.*`
argument vector (`shell=False`, typed parameters, interface-parity-tested
against the real module parsers). Its mode-aware builder enforces the
probe/canary/measured admission shapes before any subprocess exists and shows
the exact argument vector plus call ceilings for confirmation before a paid
mode starts. Jobs run in their own process group so a stop terminates the
complete child tree. The console's own operational actions (saving a
registry, reindexing, stopping a job, computing the recorded-usage cost
report) run in-process against the state database and retained artifacts
rather than as `experiments.*` commands; the reindex and usage report are
also exposed headlessly (`rig_web --reindex` / `--usage-report`).

`experiments/rig_web.py` is intentionally only the stable CLI/import facade.
The sibling `experiments/rig_web_app/` package keeps the implementation in
small, acyclic responsibility modules:

- `catalog.py` and `ui.py` hold the typed command/catalog surface and shared
  presentation assets/helpers;
- `artifacts.py`, `reports.py`, and `storage.py` handle retained-artifact usage,
  validated reports/pricing, and sqlite operational state;
- `lifecycle.py`, `dashboard.py`, `settings.py`, and `pages.py` handle jobs,
  routing, dashboard/report views, configuration, and general pages;
- `ollama_service.py` owns the bounded loopback Ollama API, exact live roster,
  and current-process-only daemon lifecycle;
- `builder_models.py`, `builder_capture.py`, `builder_validation.py`, and
  `builder_page.py` implement the Build workflow without changing its gates;
- `app.py` composes those focused mixins and `server.py` provides the configured
  HTTP/headless adapter.

The HTTP adapter binds the operator-configured `--host` and `--port`. It does
not use `Host`, `Origin`, Fetch Metadata, or a centrally injected CSRF field as
request-admission controls. POST framing remains bounded and unambiguous:
Content-Length must be singular and within the byte cap, transfer framing is
rejected, and URL-encoded form names must be valid and unique. Application
capabilities such as paid-launch tickets and model/evidence bindings remain
authoritative. All control responses continue to deny framing through CSP
`frame-ancestors 'none'` and `X-Frame-Options: DENY`.

The facade continues to expose the established imports and
`python -m experiments.rig_web` entry point. This is an implementation boundary,
not a second interface or evidence path.

At process startup the console snapshots platform, CPU model, physical/logical
cores and total RAM through `psutil`/platform fallbacks, and NVIDIA card/model,
VRAM, PCI, compute capability and driver data through `nvidia-smi`. The
dashboard and Build tab render that one snapshot. A single role-aware modal
picker serves target and LLM-judge selection. Its first step chooses hosted or
local; the second applies hosted-provider (`All` initially) or local filters.
Target mode binds one or more hosted targets and at most one local target. Judge
mode binds exactly one model, distinct from every target. A local target and a
distinct local judge may share one response-independent probe, live canary, or
measured run because Runner releases the target before loading the judge;
adaptive Crescendo cannot use this pairing. Different local targets are
scheduled as separate rig jobs/grids, while each grid may also contain multiple
hosted targets. The judge role alone marks the
highest comparable configured rate per currency as expensive; this is a cost
signal, never a capability score. Build presents separate hosted API, Local vLLM,
and Local Ollama groups. Filters compose Local vLLM name substring, 10M-3T maximum
parameter count and a separate automatic 16/8/4-bit fit control
(initially on), plus a separate unchecked unknown-fit control. Known 16/8/4-bit
recommendations use green/blue/amber badges; unknown fit is neutral gray. The
unknown-fit control exposes an unknown-size row at every parameter maximum,
while every known size obeys the cap. The per-model control names its precision.
Compatible local vLLM
rows are selectable single-choice radios even when still unpinned; non-dry
server admission requires the exact revision/digest before launch. Unknown fit
is blocked under auto; an explicit per-model precision binds
`allow_unknown_fit: true` and permits only that operator-owned load attempt.
Known non-fit remains blocked. Ollama rows follow only modality and expose no
vLLM fit or precision controls. The live roster is assembled from bounded
loopback `/api/tags`, `/api/ps`, and `/api/show` calls: at most 64 installed
models, a five-second aggregate capability deadline, explicit completion/vision
capabilities, exact lowercase digests, and matching before/after tag snapshots.
No row is invented when discovery is absent, malformed, slow, or races a tag
change. Bounded tags/show family fields and
`model_info.general.architecture` are cross-checked; missing or conflicting
identity evidence fails closed, and architecture feeds the overlap index.
Normalized upstream/name/family overlaps are unavailable for Ollama
execution; a stale/manual overlap is visibly disabled with the exact reason and
cannot bypass the distinct-model requirement. These are presentation controls
only. Source arms lacking an integrated evaluator remain visible with a concise
badge and hover/focus explanation. They fail closed by default. The explicit
approximate-common-metrics opt-in admits only a separately named, supplementary,
non-authoritative proxy with warning, strict provenance, separate coverage, and
an uncalibrated reliability indicator; visibility never asserts authoritative
evaluator support.
Dry composition discards real API/local selections because the runner uses
`MockTarget`, and local roster modality metadata is narrowed to its supported
text/image path so audio mismatches fail UI/CLI parity.

Build composes every `run_matrix` flag the documented lanes use except the
`--models` shorthand (CLI/`rig_check`-only; Build emits the explicit
`--api`/`--local` split). The generic `rig_check` form forwards the matrix
surface except `--exclude-tool-conditioned`, because `rig_check` always adds
`--preflight-only` and the exclusion is standalone-dry-run-only. `ideator` is
available only through its verified
precomputed replay panel: the operator supplies an exact
`ura-ideator-seed-pairs/1` manifest and its digest, and every declared PNG path
and digest is validated under the results root. The reviewed manifest and image
bytes are captured in the execution ticket and materialized as private launch
copies; the live generation path remains disabled. `purplellama` admits only
`cyberseceval_*` arms and is rejected server-side for every other arm, not only
in the page. Build also exposes
`--group` (default: the CLI default
`model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version`,
the grouping the Level-2 export requires), `--exclude-tool-conditioned`
(available and on by default only for a standalone dry run), the measured-only
`--reset-open-circuits`, and
`--lock-stale-seconds`. Non-dry `run_matrix`/`rig_check` children inherit the
console process's exported `URA_PROJECT_REVISION_*`/`URA_SOURCE_CONFORMANCE_*`
receipt locators; dry lanes launch with them scrubbed.

Once at least one source arm is selected, Build exposes one synchronized range
and numeric `--limit` control plus the sampling seed. The limit is applied
independently to every selected arm: `0` selects the complete release for each
arm, while a positive value caps whole source clusters per arm. The same panel
has one sampling-policy selector for the seeded pseudorandom or source-order
whole-cluster prefix. A measured bounded selection requires an explicit
`--sample-seed`. The optional local
budget in hours is only a human-scale spelling of the exact Runner
`--deadline-seconds` call-start window for a measured local-target lane. Expiry
blocks new model acquisition and model calls; it neither interrupts an admitted
call nor bounds process completion.

For a reviewed paid launch, Builder first derives exact selected API, local,
source, source-conformance, and prepared-attacker snapshots, then binds their
digests in the internal `ura-builder-selected-execution-config/1` bundle. The
API component remains `ura-builder-selected-api-config/1`; it retains the full
registry digest and each selected target/judge
route's canonical provider/model, selected-entry digest, portable controls, and
`endpoint_identity=https-base-url-sha256:<64 lowercase hex>`. Source and
attacker components retain the canonical selected entries and exact referenced
artifact/content digests, so replacing a real source with synthetic conversion
or swapping a prepared replay after review cannot launch. Compatible raw base
URLs and filesystem locators are used only to construct private runtime configs;
no raw URL enters the bundle or durable job/evidence surfaces. Native routes
use the same typed endpoint-identity form, so aliases share one route identity
without exposing its authority.

The reviewed parameters and bundle digest live behind an opaque, purpose-bound
confirmation ticket in bounded process memory. It expires after 30 minutes and
is atomically burned by success, replay, tampering, purpose mismatch, or
selected-registry/artifact drift. Immediately before `Popen`, Builder
revalidates the bundle and materializes selected generic API, local, source, and
prepared-attacker configs plus source-conformance evidence as private mode-600
files with exact SHA-256 arguments. Runner reads each once, verifies the bound
bytes, and unlinks it before model work. The launch argv may therefore
contain a raw compatible endpoint or explicit checkpoint locator only through a
private config; preview HTML, retained argv, `Job`, `command.json`, and SQLite
use typed digest placeholders and portable identities. This boundary is an
operational TOCTOU/privacy control, not an evidence or access claim.

When that reviewed lane contains a Hub role, Rig Web replaces the ordinary
launch with a purpose-bound plan -> acquisition -> offline preflight/measured
workflow. The visible plan Job is explicitly `acquisition plan / no model
call`; the generic Commands route cannot launch `model_acquire`. The acquisition
child receives a minimal runtime environment, the optional canonical
write-only `HF_TOKEN`, and a job-bound activity secret, but no hosted-provider,
AWS, proxy, or debug credentials. An authenticated event toggles
`model_download` only during confirmed missing-byte transfer; absent events and
cache hits show no badge, and reconcile/Stop/cancel always clear it. The final
one-shot stage rechecks the exact execution-config bundle, plan, receipt,
preflight/call caps, live attestation, and deadline before launching offline.

Private plan/receipt/store/config/snapshot values exist only in process memory
and transient child argv. The controller persists typed digest placeholders,
captures the whole child stdout/stderr pipe (including native writes and
descendant processes), performs bounded streaming redaction of every private
locator/token spelling, and writes only the sanitized stream to Job logs. The
safe canonical plan/receipt evidence copied into the result tree contains no
locator or credential.

Ollama lifecycle actions dispatch directly to the state-gated service. The API
origin is literal loopback HTTP, request/response sizes and timeouts are bounded,
redirects and proxies are disabled, response opens and reads obey hard monotonic
deadlines, and `ollama serve` is launched with a fixed argument vector and a
dedicated process group. Status distinguishes absent, external, starting,
ambiguous, cleanup-error, busy, and proven current-console-owned daemons.
Listener ownership and a PID-reuse-resistant process-start identity must both be
proved before the console claims ownership for pulls. Stop and clean shutdown
terminate only that recorded owned group, including descendants; unconfirmed
residue remains owned/error so Stop can retry, while a pre-existing or
post-restart daemon is external and is never killed. POSIX cleanup re-proves the
live leader's captured process-start identity immediately before each group
signal; leader exit or PID/PGID reuse prevents escalation and retains the
retryable owned/error state. A model pull is a typed
console job, not a generic command form, and carries explicit
`activity=model_download` while running so Jobs can render downloading without
guessing from its name. The daemon child receives an explicit local-runtime,
GPU, Ollama, certificate, and safe unauthenticated-proxy allowlist; unrelated
environment values and hosted credentials are never copied. Pull admission is
available only for the owned daemon and exact storage path frozen at Start. The
worker re-proves PID/start/listener identity while holding the exclusive
cross-process endpoint lock, verifies five GiB of model-volume headroom, and
rechecks that reserve plus each API-reported remaining byte count. Inference and
discovery take the corresponding shared lock, preventing pull/stop/model-mutation
races. Ollama inference also verifies one exact tag/digest before chat, again
after chat, and as exactly one matching loaded `/api/ps` row; Runner admission
independently repeats live show-backed overlap and digest/modality validation.

The Jobs view converts stored epoch timestamps to full browser-local start dates
and times. Its state, text, From, and To filters combine, defaulting to the
previous seven days through the current browser time with inclusive selected
precision. Browser-derived epoch bounds drive a date-aware SQLite query, so the
view is not restricted to the 500-row restart cache. Campaign markers are also
date-filtered before their 20-row display cap; both bounded paths disclose
truncation. The date interval constrains terminal history, while currently
running console-owned processes and exact-session external rows remain visible
through a bounded, disclosed live exception even when their start time is older.
Compact tags use blue `running` for both console-owned work and an
external task-log marker, plus `passed`, `failed`, `orphaned`, `partial`,
`blocked`, `stopped`, and `unknown`. The surrounding detail labels an external
running marker as reported state because the console does not own that process.
An external marker may also bind one exact named tmux socket/session. A bounded concurrent probe with a
short result cache reconciles that explicit identity; after its launch grace, a
missing session is `unknown`, an exact session observed absent is `orphaned`, and unavailable or deliberately capped probing
is `unknown` rather than an unverified `running` claim. Generic external markers without an exact
identity remain task-log-only observations. Terminal legacy markers remain
readable. A controller may publish its authoritative `.exit` before appending its
terminal UI event, so a failure in the operational display path cannot publish a
false successful terminal.

External engineering campaign discovery is read-only and restricted to a
bounded `ura-engineering-campaign/1` `ENGINEERING_ONLY.json` marker whose
`thesis_empirical_evidence` is false. Optional strict `planned_tasks` and
`model_tasks` fields distinguish model tasks, support tasks, pending work, and
unplanned events. Task-event success means a task process ended successfully,
not that inference occurred. An optional bounded `model-execution.jsonl`
self-report provides attempted and successful counts per declared model task;
for a terminal campaign, a supplied report must cover every model task exactly
once. The report and any reserved-call ledger are operational diagnostics, not
execution proof. Completion-validated response artifacts remain the measurement
authority.

Long-running external controllers publish that marker and ordered task-event
contract from their own restorable named tmux sessions. Measured Runner
children use a separate fixed-child `ura-external-measured-job/2`
registry. A create-only start record binds one exact sanitized `run_matrix`
argument vector, canonical descendant of `runs/thesis/runner`, project commit,
framework-lock identity, a generic admission digest and a unique private tmux
socket/session for the actual invocation rather than the parent controller; one
bounded create-only terminal publication binds the child exit. Rig Web never recursively
infers ownership, inserts these rows into sqlite, or offers Stop. Jobs and Stats
can nevertheless resolve the exact child and pass only its explicitly owned
artifact root to the existing digest-validating usage/report readers. This is
an operational visibility boundary, not a second execution or evidence path.
An external registration remains explicitly non-thesis even after exit zero;
completion-bound usage may be displayed, but authority is not inferred from the
registration or terminal record. Exact-session nonterminal discovery precedes
the recent-history cap, so newer terminal directories cannot hide an older
controller that is positively observed live. External analysis uses a separate
generic `ura-external-analysis-registration/1` boundary. A producer-owned
adapter validates any workflow-specific chain before publication. Rig Web then
validates only the direct registry path, operational-only authority, status,
limitations, report ownership, exact bytes, and Level-1/Level-2 report
contracts. The registration is published from a private fsynced temporary file
with atomic no-replace semantics, and failed publication removes only its own
empty staging directory. No workflow phase or gate schema is part of Rig Web.

Console state persists in a stdlib-sqlite database (`console.db` under the
state directory): jobs with their durable argv identities and builder
parameters, the
campaign-run registry, per-artifact recorded token usage, and a report
index; it carries a schema version, a startup integrity check, transactional
terminal-state commits, and a Reindex action that rebuilds every derived row
from retained artifacts with digest verification. This database is
operational state, never scientific evidence: usage rows are read only from
completion-marker-bound artifacts, cost is calculated only from the
operator-edited effective-dated pricing registry (missing data renders N/A,
never zero), and the validated filesystem artifacts remain the sole
measurement authority.

For an explicit workstation vLLM checkpoint, the raw filesystem locator is a
launch-only input. The confirmation capability and raw builder selection are
short-lived process memory, the selected config is a private one-shot file
removed after the child reads it, and all rendered/persisted job surfaces use
`vllm:local-checkpoint@sha256:<digest>`.

The pricing registry can be populated by hand or by the pricing fetcher
(`experiments/pricing_fetch.py`), which does read-only HTTPS GETs of each
provider's published pricing page (URLs in `experiments/pricing-sources.json`),
matches model ids exactly, and merges the rates it can read with
`auto_fetched`/`source_url`/`fetched_at` provenance. It never fabricates a
price (client-side-rendered pages stay manual) and never overwrites an
operator-entered rate; the merge is atomic with a prior-file backup and refuses
a corrupt table rather than resetting it. Provider API keys are managed
write-only from the console's Config section (`/config/secrets`): presence and
a masked last-four hint only, written to the operator secrets file (mode 600),
never displayed, logged, or stored in the database. `HF_TOKEN` is the stricter
exception: it exposes presence only without a suffix, remains process-memory
only (legacy file entries are scrubbed), and is forwarded only to the
acquisition children (`model_acquire` and the `export_aggregators` corpus
export).

## Defense and judge separation

A model-backed `GuardedTarget` intervention has one shared defense-guard
instance, an explicit device, and an identity distinct from the scoring guard.
This prevents a tested guard from blocking and grading its own output. The
implemented model-backed defense is text-only; physical-media defense cells are
`N/A` until a substantive multimodal guard path exists. The scoring cascade may
still receive media sentinels under its separately documented judge semantics,
which is not equivalent to visual/audio/video understanding.

## Native-engine boundary

AgentDojo, ASB, AutoDAN-Turbo, EasyJailbreak, FuzzyAI, Garak, Giskard v2, Petri,
and Promptfoo are imported at their complete result-artifact boundary
when their attack, target, and evaluator jointly define the source result.
Replaying only a generated prompt through URA would change the estimand. Such
imports retain source-native rates and are common-metric-ineligible unless a
separate explicitly matched design supports comparison.

`experiments.native_import` dispatches the audited importer and writes an
`ura-native-import-envelope/2` with a relative, hashed import-config locator. On
validation it re-runs the importer over the authoritative returned files and
requires all substantive cases, scores, aggregates, hashes, and joins to match;
it never executes the upstream project. A `NativeEngineRun` retains the native
repository/revision and has no Runner `RunManifest`. Consequently the URA
revision used for import is retained in the enclosing return-package/importer
context, not inserted as though it were an upstream-native field.
The combined
`experiments.suite_summary` accepts completion-validated common-run roots and
canonical native envelopes. Its output is an evidence inventory, not a
leaderboard: only coverage/conformance counts may be totaled globally, while
rates and graded scores remain on exact common or source-native strata. Passing
the complete source-instance registry makes absent runner arms and the nine
expected native projects visible; a partial collection is never labelled a
complete program. The presence flag is explicitly narrower than full
model-by-source lane coverage. Distinct run IDs are separate strata because each binds the
target, judge, source, sampling, budget, and code identities.

Third-party engine subprocesses are not security sandboxes. Execute untrusted
engines in an isolated container, VM, or low-privilege account with minimal
mounts, explicit network and credential policy, process-tree termination, and
resource quotas.

### Generation condition reporting

The provider adapters preserve usable output stopped at the output-token limit,
the original provider reason and `output_truncated`; empty final text remains a
distinct output failure. This applies to Ollama, vLLM, Anthropic, OpenAI Chat and
Responses, OpenAI-compatible routes and Gemini. No answer retry follows from a
truncation marker. OpenAI Responses admits only token-limit `incomplete` output
with usable visible text and otherwise valid identity, usage and continuation
state; arbitrary incomplete or failed requests are not promoted.

The generic generation-condition exporter reads completion-validated cells.
Level-2 `/2` and Stats expose runtime-observed context, configured output allowance,
reported token usage with coverage, and completion-reason diagrams alongside
missing-output counts. Model/run/arm/modality and different token settings remain
distinct. The exporter never derives historical settings from today's model
roster and never interprets a cap-sized token count as evidence of truncation.
New generation-condition reports additionally separate transport failures and
explicit pending retries. Older reports remain readable without invented retry
metadata. The all-cause missing-output diagram is labelled response availability,
not intrinsic model stability; transport loss is not a model-quality observation.
Historical Level-2 `/1` remains readable. Campaign-specific recovery orchestration
stays outside this product reporting layer.

### Retained judge failures

A judge's malformed rubric is an evaluator failure, not a target safety label.
The LLM judge attaches the actual provider reply and usage to its parse error
so a caller can persist them. Retained-response execution can explicitly retain
non-empty invalid verdicts as unscored outcomes without an answer retry; its
default remains stop-for-investigation. Empty output and infrastructure,
identity and monetary failures still stop. Valid verdicts cannot be converted
to failure records. The failure-aware report separates invalid-verdict
abstentions from valid decisions and keeps unknown historical usage null,
with its original monetary reservation held. Reported usage totals are known
subtotals, never inferred zero charges. Original execution records and their
versioned interpretation remain immutable.
