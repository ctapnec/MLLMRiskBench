# Unified schema v1.5

`ura.data_models` is the typed Pydantic v2 contract shared by converters,
attackers, targets, judges, persistence, and analysis. `SCHEMA_VERSION = "1.5"`
is stamped on datapoints, checkpoints, and manifests. Runner 2.32 rejects mixed
schema versions and duplicate datapoint IDs before a target call.

The 1.5 transition introduces isolated-engine identities and verified closing
seals. Readers retain a narrow compatibility path for exact Runner 2.19/schema
1.4 non-runtime evidence, `ura-eligibility-plan/2`, and
`ura-level1-evidence/2`: missing runtime fields normalize to the explicit
not-required/empty selection. Legacy evidence that selects PyRIT, DeepTeam,
h4rm3l, or Spikee is rejected because those artifacts predate the closing seal;
current artifacts may not omit or downgrade the new runtime fields.

## Records

| Type | Important fields | Purpose |
| --- | --- | --- |
| `MediaRef` | `modality`, exactly one of `uri`/`path`, `sha256`, `mime`, `meta` | content-addressed physical input |
| `ToolCall` | `name`, `arguments` | represented, inert tool invocation |
| `ProviderContinuationState` | provider/API identity and bounded typed output items | exact stateless OpenAI Responses continuation state |
| `SourceEvaluationPolicy` | policy ID, version, SHA-256, source URI, intended metric | immutable source-benchmark evaluation-policy identity |
| `DialogTurn` | role, content, media, tool fields, provider thinking/state | one conversation or represented agent-trace turn |
| `DataPoint` | source, modalities, history/payload/media, risk, expected behavior, source policy, taxonomy and attack metadata | atomic converted corpus item |
| `Attempt` | datapoint, attacker, target, turn, exact rendered input, seed, immutable planning/source-stratum identity, per-turn evaluation identity, params, run ID | one submitted input |
| `Response` | attempt, target, output/tool turns, latency/tokens, raw provenance, run ID | one target outcome, including a typed provider refusal |
| `Judgment` | attempt, judge, label, score, rationale, raw provenance, run ID | one automated/human verdict, or typed non-evaluable setup record |
| `EvalResult` | metric, value/CI, support, grouping, provenance, run ID | one aggregate estimand |
| `RunManifest` | run/code/config identity including `config.run.project_revision`, seeds, components, data hashes, time and environment | re-derivation and audit record |

Enumerations are defined in code. In particular, expected behavior separates
harmful `refuse` probes from benign `safe_answer` and `comply_safely` probes;
that split controls ASR and FRR denominators.

## Prospective attacker-input contracts

Runner 2.26 requires every Runner-eligible adapter to produce one
`ura-attacker-input-contract/1` for each selected datapoint and seed. The
contract binds the source channel combination, every prospective target-call
combination, policy-evaluation scope, and turn-count semantics before an engine
is loaded or a target call is charged. Native-only adapters retain their
canonical upstream execution/import path and are not admitted through this
Runner contract.

Physical inputs use a path-free, content-addressed asset inventory
(`origin`, modality, MIME, SHA-256, and byte count) plus explicit ordered
occurrence sequences. Repeated references therefore remain repeated even when
their bytes are identical, and runtime delivery must equal the planned tuple.
IDEATOR additionally binds each ordered seed pair's adversarial-text SHA-256
and UTF-8 byte length; its image and output-directory paths are runtime-only and
are absent from component, request, eligibility, run, checkpoint, and grid
identity. A path alias with the same bytes and text yields the same contract/run
identity, while changed text or media bytes changes it.

Runner validates the realized rendered input against the corresponding planned
turn before reserving the call budget or invoking the target. Channel changes,
media loss/reordering, or bound-text drift fail closed. Tool-conditioned rows
also fail before planning until a typed executable tool runtime and actual-use
attestation exist; a serialized tool transcript is not execution. Crescendo
retains an exact planned horizon and may execute only a content-bound prefix
terminated by an authoritative harmful violation; an arbitrary short session
is invalid. The `ura-eligibility-plan/3`, modality-coverage `/2`, lane, run, and
completion evidence bind these contracts rather than inferring target inputs
from source modalities alone.

Completion reuse and Level-1 ingestion apply the same four-way
contract/`Attempt`/`Response`/`Judgment` validator. It recomputes the policy
scope, challenge index and horizon, turn behavior, source/delivered/effective
modality, input-delivery state, and target modality capability projection from
the immutable plan, rendered request, response state, and manifest component.
Changing a Judgment and refreshing only its artifact descriptor therefore
cannot change an execution's estimand or evaluability.

## Prepared attacker artifacts

T3MP3ST and HarmBench keep source-model or optimizer work outside a measured
Runner grid, then replay an exact prepared artifact.

`ura-t3mp3st-plan-bundle/1` binds one deterministic converted-corpus selection
to the exact T3MP3ST upstream revision, source provider/model, canonical request
and validated planning response for every selected datapoint. Each entry carries
datapoint, request and response hashes, and the bundle carries the converted
corpus hash and record count. The measured attacker config supplies exactly
`upstream_revision`, `source_provider`, `source_model`, `response_artifact` and
`response_artifact_sha256`.

`ura-harmbench-transfer-replay/1` is text-only. It binds the pinned HarmBench
revision, experiment, ordered methods, cases per method, corpus name, limit,
sample seed, exact converted source requests and every generated case. It also
binds the source CSV and method-output artifact identities. The generated
attacker config supplies exactly `methods`, `experiment`, `upstream_revision`,
`replay_artifact` and `replay_artifact_sha256`.

Both loaders reject missing, extra, duplicate, mismatched or tampered entries
before any target call. Persisted run identity retains content hashes and sizes,
not an operator-specific absolute artifact path. These formats prove prepared
input integrity only; they do not prove upstream evaluator validity, target
safety or an empirical thesis result.

The `response_artifact` and `replay_artifact` values are operational paths, not
portable schema identity. Rig Web resolves its configured results root and emits
canonical absolute runtime-only values, including when the configured root is a
symlink. Native artifact readers still reject every symlink path component.
After validating the declared digest and bounded regular file, `run_matrix`
removes the path and persists `response_artifact_identity` or
`replay_artifact_identity` with the observed SHA-256 and byte count.

## Prospective request envelope and early failures

Before planning exists, `run_matrix` emits strict
`ura-request-envelope/6` as
`<envelope_id>.request-envelope.json`. Its exact top-level
fields are `schema`, `status`, `envelope_id`, `request`, `bindings`,
`execution_units`, and `limitations`. `request` fixes execution purpose,
requested target keys, logical source arms, attackers, judges, seeds, sampling
and call/turn limits, defense, grouping, runtime controls, dry-run state, and
call caps. `bindings` fixes project-revision, harness-source, and driver-source
identity. Every execution unit has exactly `request_unit_id`,
`requested_target_key`, `logical_source_arm`, and `attacker`; the list is the
complete exact cross-product of those three selected axes.

Sampling-policy omission keeps the seeded pseudorandom behavior. When the
operator supplies `--sampling-policy`, the request has exactly one additional
`sampling_policy` field whose value is
`seeded_pseudorandom_whole_cluster_prefix_v1` or
`source_order_whole_cluster_prefix_v1`. That field contributes to envelope
content identity and, through the envelope digest, model-acquisition identity.

In version 2, `request.hosted_judge_data_transfer_acknowledged` is a required
Boolean. It is `true` only when the operator supplied
`--ack-hosted-judge-data-transfer` for a live non-local LLM judge. The flag
records acknowledgement that target output and source/reference grading context
will leave the rig under the selected judge provider's retention and data-use
terms; it is not proof of institutional approval, a retention guarantee, or
provider deletion. It remains `false` for dry runs, no-call `rig_check`, rules-
only judging, and a local LLM judge.

Version 3 requires integer `request.target_answer_retries` in 0 through 10 and
records the CLI default `1`. It is the number of additional target calls allowed
after a deterministically unusable answer. Version 4 adds nullable
`request.recovery_selection`. A non-null value binds one exact
`ura-recovery-completed-prefix/1` artifact, its byte identity, its single source
arm, the completed-prefix count, and selected/prefix/remaining datapoint-ID
digests. Version 5 retains the required retry count and recovery field and also
accepts `ura-recovery-completed-prefix/2`, which binds the same three digests and
positive completed-prefix count independently for every source arm in one
multi-arm request. Version 6 also accepts
`ura-recovery-completed-selection/1`. Each arm binds the full selected-ID digest,
the exact retained ID list and digest, its positive record count, and the
remaining-ID digest. This represents nested samples whose selected sets are
monotone but whose emitted rows return to source order, so the retained set need
not be a contiguous list prefix. Version-1 through version-5 envelopes remain readable with
their exact historical field inventories; validators do not add or infer newer
fields, accept the multi-arm prefix selector under version 4, or accept the
completed-selection selector before version 6.

The envelope is created after basic CLI/axis validation but before selected
config loading, source-conformance input loading, or conversion. It is a
prospective whole-arm request universe, not evidence that source-policy or
modality strata exist, a config was valid, execution started, a provider was
called, or a result was observed. Its exact descriptor is
`{envelope_id,file,sha256,bytes}` and is retained under `request_envelope` in
the later eligibility binding, grid request, cell run config, and completion-
validated manifest lineage. Local target paths are represented by sanitized
pre-materialization request keys. Selected configuration and receipt identities
are bound later by the existing eligibility and grid artifacts; the early
envelope does not duplicate them.

A terminal failure after that boundary but before planning uses strict
`ura-request-error/1` as
`<error_id>.request.error.json`. Its exact top-level fields are
`schema`, `status`, `error_id`, `request_envelope`, `scope`, `failure`,
`execution`, and `limitations`. Scope is one of `whole_request`,
`requested_target`, `logical_source_arm`, or a complete `execution_unit` tuple;
unsupported partial scopes are rejected. Typed phases are
`configuration_preflight`, `source_conformance_input_preflight`,
`corpus_preflight`, `diagnostic_canary_cluster_admission`, and
`source_conformance_preflight`. Categories are `configuration_invalid`,
`source_input_unavailable`, `source_integrity_failed`, `conversion_failed`,
`empty_converted_corpus`, and `diagnostic_admission_failed`. `execution_started` and
`provider_calls_started` are both false. The error cannot attribute planning
strata, infer a failed execution unit beyond its declared scope, or establish
empirical evidence. A newer validated same-envelope early error supersedes an
older one, and successful eligibility removes a stale same-envelope error.

Both artifact loaders require bounded, canonical UTF-8 JSON in a non-symlink
regular file, reject duplicate keys and non-finite values, and match filename,
content ID, digest, and bytes. Argument parsing, malformed selected-axis, and
other basic request-shape failures rejected before envelope creation are outside
this boundary rather than being reconstructed afterward.

## Planning eligibility artifact

`run_matrix` and `rig_check` emit `ura-eligibility-plan/3` as
`eligibility-<content-id>.eligibility.json` after corpus conversion and before
model calls. Each item binds the requested and resolved target identities,
logical source arm, selected source stratum and item digest, exact modality,
attacker, execution/metric mode, evaluator/reference mode, disposition, and
failed gates. The artifact self-validates its content-derived `plan_id`.
Its `bindings.experiment_conditions.values` preserves the exact condition shape
from the request-envelope generation that produced it. Current version-5
requests therefore carry both `target_answer_retries` and nullable
`recovery_selection`; retained version-2 through version-4 condition shapes
remain readable without inferred fields. Level 1 validates the exact field inventory,
types and content ID, then requires retry/recovery field presence and values to
match the bound request envelope before accepting the plan or grid.

Validation strictly reconstructs the embedded grid attacker-input plan and
recomputes every media ID, contract ID, and plan digest. Each eligibility cell
must then equal its exact arm/attacker/datapoint/seed partition: contract IDs
and horizons, all-turn and evaluable modality unions, generated-media
inventory, tool requirement, source combination, and datapoint accounting must
match, with no omitted or extra contracts. A completed manifest repeats only
its relevant Runner-plan subset. Completion, Level-1, and figure loaders rejoin
every persisted Attempt to that subset and verify the exact planned turn,
ordered media occurrences, MIME/digest tuple, bound text, and valid horizon
termination even when outer artifact descriptors were refreshed.

Its stratum statuses are only `compatible_if_isolated` and structural `N/A`;
separate execution-unit accounting says whether the whole logical arm can pass
the actual Runner boundary. Neither status means attested, attempted, completed,
decided, or empirically valid. Failures before a corpus can materialize bind to
the earlier prospective request envelope/error pair because their exact
modality/source strata are not yet knowable. The Level-1 lifecycle artifact
below joins only the evidence presently available rather than reinterpreting
either the request or the plan as realized coverage.

## Prospective lane projection

After successful whole-request admission and before the first generation call,
`run_matrix` emits strict `ura-lane-projection/2` as
`lane-projection-<content-id>.lane-projection.json`. `projection_id` is derived
from the canonical artifact body. The projection binds the exact eligibility
plan/request/condition and artifact descriptor, then records per logical source
arm:

- converter and selected-corpus/datapoint/cluster digests;
- pre-limit and selected row/cluster counts, sample seed, limit, optional
  explicit sampling policy, and exact source-policy cluster counts;
- verified selected physical input-media references and unique bytes by
  modality, or an explicit no-physical-media state; and
- reconciled selected-arm totals.

Its `call_projection` uses `conservative_complete_grid_upper_bound_v2` for
trajectory, retry-reserved target-call, model-judge-call, local-guardrail-
evaluation, and declared HTTP-attempt exposure,
including per-attacker subtotals, and records `target_answer_retries` in the
range 0 through 10. Retained version-1 projections remain readable with their
exact field inventory and version-1 semantics; validators do not infer a retry
field. `unavailable_estimates` fixes token use,
monetary price/cost, runtime/throughput, and expected output storage to
`status=CANNOT-VERIFY` and `value=null`; consumers may not fill those fields by
extrapolation. Selected input-media bytes are observed content bytes, not
expected output storage.

The exact measured grid request contains the projection ID and its file/SHA-256/
byte/record descriptor. `rig_check` validates and retains the projection next to
the eligibility plan in the separate preflight tree. These two instances may
bind different execution purposes and must not be substituted merely because
their call totals match.

## Funded hosted transport continuation

Funded hosted transport continuation uses
`ura-hosted-retained-execution-plan/3`. It retains version 2's counted-input
and monetary bindings and adds a nonempty `transport_recoveries` map keyed by
selected input identity. Each entry binds a regular response-checkpoint file
by path, SHA-256 and byte length, its exact attempt ID, the previous physical
attempt count and unchanged counted request digest. Versions 1 and 2 cannot
acquire this field retrospectively.

Admission checks the original rendered dialogue and source identity, target,
typed retryable HTTP/network failure, absent output and absent token usage.
An exhausted allowance, usable answer, parser error or changed request cannot
be resumed through this path. The same funded call retains prior unknown
charges. New transport records continue their physical ordinals, while their
reported call count includes only calls made by the new invocation; the old
checkpoint remains separately bound evidence. Unrelated inputs start at
attempt one. This contract does not increase any target, judge or retry budget.

Reviewed post-fix parser recovery uses `ura-hosted-retained-execution-plan/4`
with a nonempty `adapter_recoveries` map, not a reinterpretation of version 3.
Each entry has `checkpoint`, `attempt_id`, `prior_attempts`, `request_sha256`,
`repair_commit`, `error_type` and `error_reason`. Checkpoint descriptors retain
the same path, SHA-256 and byte-length fields. Admission requires the exact
typed unusable-output error, no generated turns or token usage, unchanged
source/request identity and the clean repaired target implementation. The
monetary ledger, not an old conservative transport-count estimate, supplies
the used physical-attempt prefix. Ordinary paid answer retries remain zero.

For a checkpoint containing both usable responses and the reviewed parser
failure, `ura-hosted-retained-execution-plan/5` preserves the usable native
records as completed inputs. Jobs select only remaining retained input IDs,
including the failed input. Admission verifies that those jobs and the exact
checkpoint-backed completed inputs form the original funded selection once,
without overlap or omissions. Counter reconciliation reads the unchanged old
records; it does not rewrite their run IDs or claim new generations. Earlier
contracts do not acquire this mixed-checkpoint completion behavior.

## Live route and transport attestation

`python -m experiments.live_attestation` strictly revalidates one completed,
single-cell, non-dry `run_matrix --attestation-probe` root and emits a create-only
`ura-live-attestation/2` JSON receipt. The top-level object is strict and
content-addressed by `attestation_id`; every record is likewise content-addressed
by `record_id`. A record binds:

- the operator-declared non-secret `execution_scope_id`;
- exact requested target, unwrapped base-resolved target, hosted/local route
  kind, and a SHA-256 over the secret-free selected route configuration;
- one canonical exact delivered input combination, such as `['text']` or
  `['text', 'image']`;
- the probe Runner manifest's content-bound UTC `started_at` as a conservative
  lower bound on successful transport, plus normalized realized target identity;
- the exact verified `ura-project-revision/1` binding shared by the probe grid,
  manifest, harness digest, and experiment-driver digest;
- SHA-256/byte descriptors for the probe grid and completion marker, plus the
  probe run, realized-identity, attempt-media-hash, harness-source, and
  experiment-driver-source digests.

Only `synthetic_live_transport_probe` and `real_source_live_transport_probe`
are valid evidence kinds. Dry-run/mock transport cannot produce this schema.
The manifest fixes its purpose as
`target_route_and_byte_backed_transport_only` and carries explicit false flags
for safety, evaluator, benchmark, human-validity, and future-route-availability
claims. `execution_scope_id` is an operator assertion rather than a secret,
credential, signature, or independently verified account-equivalence claim;
that equivalence is CANNOT-VERIFY.

An ordinary non-dry grid retains the selected receipt descriptors in its
`live_attestation` request condition. Admission requires the exact receipt
bytes/SHA-256, matching scope, requested/base-resolved route, route-config
digest, route kind, exact modality combination, and age within the explicit
`max_age_hours`. A future-dated, stale, missing, duplicate, ambiguous, or
mismatched prerequisite fails before target calls. A changed harness or
experiment-driver source digest requires a new probe. Stable provider/runtime
identity fields from returned and restored responses must continue to match;
display/wrapper target and provider-volatile fingerprint remain provenance but
are not treated as stable equality fields. Exact combinations are not widened.
`rig_check` and dry-run instead record `mode=not_required`, while a probe records
`mode=probe`; neither is measured evidence.

## URA project revision identity

`python -m experiments.project_revision` creates a strict, content-addressed
`ura-project-revision/1` receipt from one operator-selected full 40-hex commit.
It records expected/observed commit equality, the HEAD tree, clean tracked state,
the required common Git root for `experiments/run_matrix.py` and the imported
`src/ura/runner.py`, and separate actual-byte identities for the experiment
driver and complete `src/ura` Python tree. Its limitation flags deny remote
repository authenticity, dependency/upstream binding, source-archive inclusion,
and empirical evidence.

Every non-dry request requires a receipt path and exact SHA-256, normally through
`URA_PROJECT_REVISION_MANIFEST` and `URA_PROJECT_REVISION_SHA256`. The compact
verified binding contains receipt ID/file/hash/bytes, expected and observed
commit, HEAD tree, and both source digests. It enters the experiment condition,
eligibility bindings, grid request, `RunManifest.config.run`, completion/recovery
checks, live-attestation version 2, lane-canary validation, Level-1 and measured
postprocessing. Checkout/source drift is rechecked before execution boundaries
and final publication. A revision change therefore requires a new request/cohort
rather than checkpoint or completion reuse.

A fully synthetic dry-run may omit the receipt only by recording the strict
`mode=not_required_diagnostic_dry_run`: all repository identity fields are null,
while current driver/harness source digests remain bound. It is diagnostic-only
and is rejected wherever a verified revision is required. `code_version` is a
Runner protocol label, the two SHA-256 values identify executed source bytes,
and the Git commit identifies repository history; none substitutes for another.

## Diagnostic lane-canary summary

`run_matrix --diagnostic-canary` fixes `execution_purpose=diagnostic_canary` and
admits exactly one target, logical source arm, attacker, seed, and whole source
cluster. For an unchanged real converted-corpus digest and sample seed,
selection is `seeded_nested_source_cluster_prefix_v1`: a `--limit 1` cluster is
contained in a later `--limit N` sample, with all sibling rows retained. The
fully offline form additionally requires `--dry-run --corpora synth`.
An explicit source-order policy instead uses the first source cluster; the
policy remains part of request and projection identity. `--limit 0` is the full
arm for either policy.

`python -m experiments.lane_canary` makes no external call. It accepts exactly
one strictly completion-validated canary cell plus its eligibility plan and
bound lane projection, and writes create-only content-addressed
`ura-lane-canary/1`. `evidence_class` is `synthetic_offline` for mock dry-run or
`live_diagnostic` for a live-attested canary. Bindings retain grid, run,
completion, eligibility, condition, and projection identities/descriptors. The
artifact also records the exact selected cluster/rows, core and supporting
artifact bytes, a byte-bound but driver-self-reported wall-clock window
(including preflight and finalization), available target/model-judge latency
observations, local decision support, and actual role/stage reachability. The
wall-clock field is not a monotonic runtime measurement and cannot establish
throughput.

`call_accounting.reserved` contains durable logical target/model-judge calls and
declared HTTP-attempt exposure. It is not observed traffic.
`observed_transport_attempts` separately sums client-reported target/judge
transport attempts and exposes incomplete reporting; any unavailable difference
stays `CANNOT-VERIFY`. Network payload bytes and end-to-end throughput are also
`CANNOT-VERIFY`. Fixed limitation fields forbid campaign authorization,
empirical benchmark evidence, human-validity, model-ranking, throughput, and
storage extrapolation. Default Level-1, figures, suite, paired, transfer, and
human-audit loaders reject this execution purpose. Upstream-native canaries do
not use this schema.

## Level-1 lifecycle evidence

`python -m experiments.level1_evidence` emits `ura-level1-evidence/3` JSON and
the existing deterministic CSV view of materialized planning strata. The
operator supplies eligibility files and result roots; request envelopes and
bound early errors are discovered automatically from those locations. A result
root containing only an envelope and error can therefore account for a request
that never produced a plan. Each plan, grid, completion, manifest, and error is
content-checked. In particular, the plan, grid, cell run config, and
completion-validated `RunManifest` must carry the exact same request-envelope
descriptor. Partial grids retain their explicit errors, duplicate/orphan or
success-plus-early-error evidence fails closed, and the output receives a
content-derived `evidence_id`. Both outputs are create-only and partial files
opened by the command are removed on failure.

The schema deliberately does not total unlike units:

| Collection/count block | Unit | Meaning |
|---|---|---|
| `prospective_request_units` / `counts.prospective_request_units` | pre-materialization requested target key x logical source arm x attacker | exact operator-selected whole-arm universe and whether each unit materialized, was bound to an early error, or lacks evidence; no stratum/call inference |
| `planning_strata` / `counts.planning_strata` | requested target x materialized selected-source stratum x exact modality x attacker under one request condition | planning compatibility, whole-arm-derived execution eligibility, structural `N/A`, completed evidence, and unit-qualified judgment support; attempted is null because a failed unit does not reveal which strata it reached |
| `execution_units` / `counts.execution_units` | requested target x complete logical source arm x attacker | whether the indivisible Runner cell was eligible, started, failed, or completed |
| `counts.judgment_records` | completed `Judgment` record | completed, evaluable, decided, abstained, and non-evaluable support; analysis inclusion remains unavailable; these are record counts, not cell dispositions |
| `request_level_errors` | error artifact | a typed pre-materialization error is bound only to applicable prospective units; legacy/untyped errors remain unstratified; neither form invents source/modality strata or calls |

A lifecycle stratum is keyed by its `request_id` and planning `cell_id`; the
request identity binds run-wide conditions that the bare cell identity does not.
Judgment-to-stratum attribution uses `planning_stratum_sha256`, the canonical
content hash of the datapoint-level planning-stratum descriptor that Runner
2.11 stamps into every `Attempt` and mirrors into each `Judgment`'s raw
provenance. The planner groups selected rows by exactly that descriptor, so
attribution is unique by construction; the coarser human-readable planning
fields cross-check the matched stratum but never select it, and artifacts
without the token are rejected rather than guessed.
`execution_unit_started` on a planning row is contextual whole-arm state, not a
claim that the stratum was attempted. Exact attempted counts exist only for
whole-arm execution units; `availability.planning_stratum_attempts` and the
planning-stratum attempted count are null because an error unit need not have
reached every stratum. `completed` requires a completion-validated cell plus the
exact selected-datapoint count and identity digest for that stratum. `missing`
means an execution-eligible stratum or unit has no supplied grid; blocked and
error dispositions are reported separately. Structural `N/A` remains distinct.
Decision support reconciles as completed = decided + abstained + non-evaluable.
Conditioning/setup judgments whose turn is not policy-evaluable are
non-evaluable, not abstentions; unqueried source-metric-only trail placeholders
do not enter these authoritative-judgment counts. Adaptive setup and challenge
turns retain the same immutable planning/source-stratum identity even when their
per-turn expected behavior and policy-evaluation status differ.

When supplementary approximate decisions are present, Level-1 also validates
their exact manifest policy and authoritative response bindings. Its selected
and rubric stage projections are strict typed records and must equal the
completion-hashed trail members field for field; self-asserted judgment caller
metadata cannot replace those retained artifacts. Raw optional stage markers
for synthetic/mock evidence, model queries, provider refusal, and source
reference use are strict Booleans. Direct Runner aggregation also requires the
same projection to equal its retained in-memory trail.

For a measured cohort, the current schema consumes repeatable typed
live-attestation artifacts paired with their approved byte SHA-256 values. It
matches each grid's exact bound descriptor, reruns the scope/route/config/age/
modality checks, verifies completed-cell stable target identity, and records
attestation artifact and record references on qualified planning strata and
execution units. Its availability status is `validated` only for this exact
supplied cohort; it is `not_supplied` for a diagnostic dry-run and may be
`not_evaluated_no_realized_measured_grid` for a supplied plan-only cohort.
Probe grids are rejected as measured Level-1 input, and a supplied receipt not
used by the selected measured grid cohort is rejected.

`availability.analysis_inclusion.status` is `not_supplied`, and its counts are
null rather than zero. No consumer may infer inclusion from folder placement.
`scope.evidence_kind` is exactly `diagnostic_dry_run` or
`measured_run`, is repeated on request/execution-unit/planning-stratum records
and CSV rows, and a mixed dry-run/measured cohort is rejected.
`scope.contains_diagnostic_dry_run` is its boolean diagnostic projection and
`scope.empirical_validity_established` is always false. The artifact is
lifecycle accounting, not a safety score or evidence of source fidelity,
endpoint access, human validity, or empirical performance.

## Level-2 compatible-family export

`python -m experiments.level2_report` emits `ura-level2-report/1` JSON plus
deterministic CSV and Markdown broad tables from completion-validated measured
cells (admitted through the measured-figure grid validator, so dry runs,
diagnostic canaries, and attestation probes are rejected) and optional
canonical native envelopes. Each `common.estimates` row is one exact
compatibility stratum and metric: run, served target, source arm,
source-policy identity and digest, risk category, effective modality,
expected-behavior population, attacker, defense and guard revision, ordered
judge identity, seeds/sampling/limit condition, semantic family,
official/proxy endpoint status, declared polarity, value with cluster-aware
interval and support, and completed/evaluable/decided/abstained/non-evaluable
judgment-record decision coverage for the exact bucket. Rows with distinct
keys are never merged; duplicate run IDs and non-default aggregation groupings
fail closed; native runs stay in the separate `native` section on their
original scales. Outputs are create-only, contain a content-derived
`report_id`, and declare `empirical_validity_established=false`: the export is
descriptive and is never a ranking or a universal score.

Approximate Level-2 rows retain proxy decision coverage separately from
source-native coverage. For a static proxy, aggregate `EvalResult.n` equals the
metric-specific supporting-decision count. Only an explicitly typed
response-conditioned trajectory metric may use its distinct trajectory-unit
count, and every selected/rubric stage must still reconcile with the exact
completion-hashed trail and authoritative response.

## Lineage and continuation state

Each cell persists attempts, responses, authoritative judgments, full-shadow
judge trails for common responses (or typed unqueried placeholders for
source-metric-only records), aggregate results, a manifest, an append-only checkpoint, and
only after validation a completion marker. Records join on `(run_id,
model/target, attempt_id)`; an attempt ID alone is not globally unique.
Every completed-attempt checkpoint row includes `budget_after_attempt` when a
durable grid budget is active. Full checkpoint files are bounded regular
non-symlink JSONL, with bounded rows, and their same-grid snapshots participate
in budget high-water recovery before another external call.

Judgment provenance includes source/risk/expectation, declared and effective
modality, source-cluster identity, attacker/strategy/seed/turn, target, exact
input fingerprint and transfer key, source-policy identity, and effective
sampling control. Stateful attempts also carry a Boolean
`policy_evaluable_turn`, nullable zero-based `policy_challenge_index`, positive
`policy_challenge_horizon`, and `turn_expected_behavior`. Policy challenges are
contiguous from zero. Crescendo setup turns use `comply_safely`, have no
challenge index, receive `Judgment.label="not_applicable"`, and record
`stage_queried=false` for every shadow stage; no judge is called and the row is
ineligible for common or source metrics. Trail rows additionally bind every
queried judge stage to the exact persisted response SHA-256 and record
confidence, parse status, cascade role, and provider identity. For a
multi-stage cascade, the final authoritative `Judgment.raw` also carries the
complete ordered `judge_stage_bindings` projection. Completion and every
postprocessor require field-present, type-strict equality with all retained
trail rows, including non-authoritative, non-rubric shadows. The immutable
`Attempt.params.planning_common_metrics_eligible` flag must be present; missing
eligibility state is never inferred as eligible.

Provider-native continuation data is explicit rather than hidden:

- Anthropic thinking/redacted-thinking blocks are retained on assistant turns
  so the next Fable request can return them unchanged.
  A signed thinking block may contain an empty `thinking` string when the
  provider omits its reasoning summary. This is valid continuation data, not
  a missing final answer. The signature remains required; only visible answer
  text is evaluated. The same rule applies to adaptive Opus and Sonnet routes.
- OpenAI Responses with `store=false` retains only bounded `reasoning` and
  assistant `message` items in `ProviderContinuationState`. Encrypted reasoning
  is required for the stateless `all_turns` continuation used by the study.
- Provider state is assistant-only, JSON-only, size bounded, and rejects
  credential-bearing fields.

Response-conditioned attempts are non-transferable unless an exact transcript
is deliberately replayed.

## Media and source-policy trust boundaries

Converters resolve media under their declared corpus root and compute SHA-256.
Runner and target encoders then restrict reads to approved media roots and
recheck the digest, MIME, URI form, and size. Scored cells reject provider-fetched
remote media because the bytes cannot be verified; materialize it locally or use
a bounded hashed data URI.

Before persistence, an approved local path becomes
`@media-root/<index>/<relative-path>`. The index refers to the explicit order in
`URA_MEDIA_ROOTS` (or the target's equivalent root list), so a resumed or moved
run must configure roots in the same order and preserve each relative layout.
Artifacts thereby bind content and logical location without retaining an
author-specific absolute path.

Where a source has a distinct official evaluator, `SourceEvaluationPolicy`
keeps that policy's identity separate from URA's common-metric judge. A common
ASR/FRR result must not be renamed as an official source metric unless the
official evaluator actually ran and its provenance says so.

## Model and source-instance configuration provenance

The matrix accepts reusable inventories without treating an inventory entry as
an executed cell:

- `--project-revision`/`--project-revision-sha256`, or their environment
  equivalents, bind the prospective local URA revision before every non-dry
  preflight, probe, canary, or measured request. They do not bind the independent
  upstream source/native revisions.

- `--source-config` maps a stable corpus-arm ID to a converter plus an
  environment-variable path locator and optional source label/split. The full
  file hash is provenance; the normalized selected subset digest enters
  execution identity. The environment's resolved absolute path is not retained.
- `ura-source-conformance/1` is a separate, compact content-addressed source
  receipt. For each admitted real arm it records operator-observed upstream
  revision, declared source-file hashes, license/access decision, split,
  reconciled raw counts, and a reviewer-attributed bounded
  semantic spot-check listing unique reviewed cluster IDs and the full converted
  corpus digest reviewed. `run_matrix` rehashes the declared files, validates
  those review bindings, computes the normalized selected source-config digest,
  and reuses its runtime converted-corpus, cluster-rule/assignment, policy, metric, and media
  evidence; the operator does not duplicate those inventories in the receipt.
  For an exporter-prepared JSONL, the consumed JSONL hash stays separate while
  the exact exporter summary is a hashed component and supplies reconciled
  upstream discovered/accepted/excluded counts.
  Blocked, mismatched, stale, or tampered selected evidence is rejected before
  target construction. The full receipt digest is package provenance; only its
  selected-arm identity enters execution identity. See
  `docs/SOURCE_CONFORMANCE.md`.
  Measured non-synthetic runs and no-call `rig_check` preflights require this
  receipt. A real-source `run_matrix --dry-run` without one is a conversion
  diagnostic only, not admitted experiment or preflight evidence.
- `--api-config` maps an exact generic hosted model specification to declared
  modalities and request controls, with a compatibility base URL only where
  required. The full file byte count/SHA-256 and normalized selected-subset
  digest are retained, but only the selected subset enters execution identity.
  Capability declarations are planning inputs and require live attestation
  before measured use. Durable route records use
  `endpoint_identity=https-base-url-sha256:<64 lowercase hex>`; they never
  retain the raw URL. The identity is computed from the credential-free
  canonical HTTPS base URL and is paired with the canonical provider/model.
  This proves only configuration equality, not endpoint ownership or access.
- `--local-config` binds an exact local specification to one immutable model
  revision or digest, declared modalities, parameter count, multi-GPU support,
  per-model quantization, tensor-parallel size, memory utilization, and output
  bound. `max_tokens` is the generation bound. The vLLM-only `max_model_len` is
  a distinct engine-context/KV-cache policy: omission normalizes to vLLM's `-1`
  automatic fit mode, while an explicit non-boolean integer in 1..1,000,000 is
  passed to vLLM engine construction and must be at least `max_tokens`. It is
  forbidden for Ollama. A per-model quantization overrides
  the command default, which overrides
  hardware-auto selection. Auto chooses the highest fitting supported precision:
  unquantized 16-bit, FP8 8-bit (minimum SM 7.5), then BitsAndBytes 4-bit
  (minimum SM 7.0). The resolved quantization, precision, tensor-parallel size
  and NVIDIA hardware profile enter run/grid provenance. One local target is
  admitted per runner process so server lifetime and GPU ownership stay explicit.
  Expert/MoE-ambiguous names do not supply an inferred `parameter_count_b`;
  fit remains unknown until the operator declares the exact total.
  `allow_unknown_fit` is an optional vLLM-only boolean (default `false`). It may
  be `true` only with an explicit per-model `quantization` value of `none`,
  `fp8`, `bitsandbytes`, `awq`, or `gptq`. It permits an operator-owned load
  attempt only when estimated fit is unknown; hardware auto and known non-fit
  remain blocked. The normalized selected config retains the resolved precision
  and this opt-in. It also retains the resolved `max_model_len` policy, so its selected
  subset hash and grid/run provenance bind the context/KV admission setting.
  Runner 2.26 records a deterministic rejected input with empty
  `output_turns`, `empty_completion_observed=true`,
  `target_input_status=incompatible`, a typed input category/error, and
  `target_identity_observed=false`. This is missing-response coverage rather
  than `model_stability_status=failed_output`: no model output existed. The
  associated policy stages are unqueried `model_nonresponse` rows. An unchanged
  deterministic incompatible input is not answer-retried, while the remaining
  selected population continues.
  Ollama uses a narrower shape: an `ollama:<model-tag>` entry requires the exact
  64-hex digest returned by the daemon's `/api/tags` inventory and a unique
  explicit modality list containing `text` and optionally `image`. It forbids
  vLLM-only revision, parameter, multi-GPU, tensor-parallel, memory-utilization,
  output/context-limit, quantization, and unknown-fit fields. It additionally
  binds `think` as a boolean or one of `low`, `medium`, and `high`; omission
  normalizes to `false`. Its pulled
  artifact fixes precision. The adapter uses the daemon HTTP API via the Python
  standard library and does not require an Ollama Python SDK.
  Runner 2.27 also derives a hosted-only `stop_on_failed_output` execution
  policy from the already-bound API target type. Runner 2.29 additionally binds
  automatic GPU-fit context admission for local targets. Ollama `num_ctx="fit"`
  uses load-only descending native-fraction probes and accepts only an exact
  `/api/ps` row with `size_vram >= size`; vLLM uses its `-1` auto-fit mode. The
  requested policy, resolved context, and Ollama probe trace are retained. This
  is recorded in the grid run configuration rather than changing
  request-envelope schemas `/1` through
  `/6`: hosted targets require zero answer retries, and their first retained
  failed output or transport/network failure opens the global `paid_provider`
  circuit before another paid call.
  Runner 2.32 also accepts `timeout` on vLLM and Ollama entries as a numeric
  per-request wall-clock bound in 1..3,600 seconds. Omitted local generation
  and timeout values are filled from the exact model's validated machine-local
  profile. An unprofiled local generative model is rejected rather than given a
  campaign fallback. vLLM
  `max_model_len=-1` and Ollama `num_ctx="fit"` remain independent maximum
  hardware-fit context policies. Hosted API configuration never reads or
  inherits these local defaults; hosted maximum output is an explicit
  budget-derived route field.
  Response-independent local attestation, diagnostic-canary, and measured runs
  with a model-backed scoring stage additionally bind
  `judge_execution_schedule=post_factum_after_target_release`. The response
  checkpoint is completed while the target owns GPU capacity; the target is
  then closed before the scoring model is loaded. Crescendo binds `inline`
  because a verdict controls its trajectory. Defense guardrails also execute in
  the target phase because they are part of the treatment.

- `ura-local-model-readiness/4` retains the immutable target identity and
  modalities, a descending 25,000 through 256-token text-throughput stress
  prefix, every failed larger candidate, the 120-second per-request deadline,
  and the first condition that reached at least 95 percent of its cap below
  that deadline. An image-capable target must also return a nonempty
  physical-image response below the deadline, but a valid voluntary stop does
  not fail throughput already proven by the text stress. It also retains the exact
  seeded 10-text/5-image survey at the selected cap. The thresholds remain 5 of
  10 text and 2 of 5 image, with empty or timed-out responses counted as
  incorrect. Readiness schemas `/1` through `/3` remain readable historical
  evidence. Schema `/3` required the image response itself to exhaust the cap
  and cannot supply a current execution profile.
  `ura-local-model-execution-profiles/3` is a machine-local operational
  registry, not empirical evidence. Each row binds one vLLM revision or Ollama
  digest, modalities, hardware-fit context, selected generation tokens, exact
  vLLM tensor-parallel size and GPU memory utilization, Ollama thinking mode
  where applicable, request deadline, and the exact `/4` readiness receipt
  path, ID, and digest. Registry schemas `/1` and `/2` are historical only;
  `/2` did not bind the vLLM topology that determines its resolved context.
  Identity or modality drift fails rather than transferring a recommendation
  to another model.

- Hugging Face model bytes are a separate immutable evidence family, not part
  of `--local-config`. `ura-model-acquisition-selection/1` retains path-free
  `input_bindings`, public `resources` (`repo_id`, exact 40-64-hex `revision`,
  sorted roles), explicit-local/precomputed-suffix exceptions, and a
  recomputable `selection_sha256`. The five Hub roles are `vllm_target`,
  `llm_judge`, `guardrail_judge`, `defense_guardrail`, and
  `nanogcg_surrogate`; one immutable resource may serve compatible roles, but a
  target may not also be its judge, guard, or NanoGCG surrogate.
- Plan-only mode emits the strict, path/token-free
  `ura-model-acquisition-plan/1`; the dedicated acquisition controller emits
  its paired `ura-model-acquisition-receipt/1` after complete upstream-manifest
  and snapshot sealing.
  Verified run evidence uses `ura-model-acquisition-runtime/1` with exact
  plan/receipt IDs and SHA-256s, public resources/selection, and bounded
  create-only plan/receipt file descriptors relative to the result root.
  `status=not_required` is valid only when the selection has no Hub resource.
  Missing, oversized, linked, tampered, internally inconsistent, or
  role-mismatched evidence is rejected at completion, Figure, transfer,
  Level-1, and Level-2 boundaries.
- `ura-model-acquisition-execution/1` is the stable scientific/grid projection.
  It retains selection, plan identity, and every immutable resource seal
  (`resource_id`, repo/revision/roles, upstream-manifest ID/SHA-256, file/byte
  counts, inventory SHA-256, and tree SHA-256), then computes
  `execution_sha256`. It deliberately omits only receipt-event timestamp,
  receipt ID/document hash, and evidence filename. Reacquiring identical bytes
  therefore preserves the condition/grid identity; any changed content seal or
  selected binding changes or invalidates it. Private plan, receipt, store,
  transport-cache, snapshot, and token values are never schema fields.

### Isolated third-party engine runtime evidence

Installer-owned retained environments use the outer
`ura-framework-runtime-receipt/1` schema with a required nested
`ura-framework-runtime-content-seal/2`. Version 2 binds every retained regular
file, including executable bytecode. Receipts with an older nested seal schema
are incompatible; a seal migration uses a new lock identity and store while
preserving the old content-addressed store.

- `ura-engine-runtime-config/1` is private operational input. Its exact root
  fields are `schema` and `runtimes`; each PyRIT, DeepTeam, h4rm3l, or Spikee
  entry contains exactly `interpreter` and `receipt`. The path is accepted only
  with the paired `--engine-runtime-config-sha256`; neither the path nor the
  interpreter is copied into run evidence. A selected framework must have an
  entry, may not reuse the Runner venv or another selected framework venv, and
  its live environment may not contain another registered framework package.
- `ura-engine-runtime-receipt/1` is the path-free content identity observed by
  the selected interpreter. It binds `engine`, fixed distribution/version,
  Python implementation/version/cache tag plus executable hash/size,
  `pyvenv.cfg` hash, installed inventory hash, primary package tree hash/count/
  bytes, full `site-packages` tree hash/count/bytes including executable
  bytecode, and the
  content-derived `runtime_id`. The full tree includes untracked files and all
  dependencies, so a same-version dependency or shadow-module mutation changes
  the receipt. Relative inventory names make unchanged relocated venv content
  retain the same identity.
- `ura-engine-runtime-execution/1` contains exactly `schema`, lifecycle
  `status` (`configured`, `verified`, or `closed_verified`), fixed worker
  `bridge_sha256`, and the receipt. `ura-engine-runtime-identity/1` contains only
  `schema`, `bridge_sha256`, and the receipt. The status-free identity, not
  mutable lifecycle status, enters run IDs, grid IDs, eligibility conditions,
  and scientific cohorts.
- `ura-engine-runtime-selection/1` is the sorted, duplicate-free collection of
  execution descriptors. `ura-engine-runtime-selection-identity/1` is its
  status-free projection. Both retain `selection_sha256`, computed over the
  identity projection, so `configured -> verified -> closed_verified` does not
  change scientific identity.
- A runtime-backed run manifest contains exactly its one status-free
  `engine_runtime` identity. Its completion marker is unpublished until the
  persistent worker has returned an exact per-cell
  `engine_runtime_close` execution descriptor with
  `status=closed_verified`. The completed grid contains the status-free opening
  `request.engine_runtimes` selection and the full closed
  `engine_runtime_close` selection. Completion, Figure, transfer, and Level-1
  readers require manifest identity = marker close identity = matching grid
  opening/close entry and require the grid selection to equal the selected
  runtime-backed attackers. Missing, downgraded, path-bearing, different, or
  extra runtime evidence fails closed. A non-runtime replay cell remains
  independent of another cell's grid runtime seals and may carry only a null or
  absent per-cell close.
- The fixed bridge request/response and session control schemas are private,
  bounded worker protocol artifacts. They accept only the operation registered
  for the selected framework and exact, expected artifact names. They are not
  scientific evidence and their temporary paths never enter durable records.
- Stage-1 NanoGCG precomputed replay uses
  `ura-engine-runtime-not-required/1` with
  `framework_execution=not_invoked`. Live NanoGCG has no execution schema escape:
  it fails before managed-snapshot, framework, model, or target construction
  until the Stage-2 isolated snapshot seal handshake exists.

Unselected inventory entries are neither evidence nor requested cells. Secret
values are environment-indirected and rejected from persisted configuration.
The manifest keeps requested and realized target identities distinct.

Runner's grid, eligibility plan and model-acquisition input bindings use the
same portable API-configuration digest. Compatible endpoints contribute their
`base_url_identity`; the raw launch-time `base_url` must not be hashed in one
artifact while its portable identity is hashed in another. Cross-artifact
validation still requires exact digest agreement. This consistency rule does
not authorize rewriting retained artifacts from an earlier execution.

### Rig Web execution-config bundle and confirmation ticket

Rig Web derives internal selected API, local, source, and prepared-attacker
snapshots, then binds their digests plus source-conformance/project/attestation
digests in `ura-builder-selected-execution-config/1`. These are operational
execution snapshots, not Runner evidence artifacts. The API component remains
`ura-builder-selected-api-config/1` and binds the
complete registry SHA-256 and, for each selected target or hosted judge, the
requested spec, canonical provider/model, selected-entry SHA-256, portable
normalized controls, and typed `endpoint_identity`. A compatible route's raw
`base_url` is removed. Source snapshots bind the immutable selected arm class
and canonical entry; prepared-attacker snapshots bind exact replay/response
artifact digests. A reviewed real arm cannot become synthetic, and an attacker
artifact cannot be swapped, without changing the unified bundle. The fixed
Fable and Sol conditions have inherent execution controls and may advertise
only their exact modality list; they do not create a mutable runtime-config
entry.

Paid confirmation retains the exact builder parameters and selected-bundle
digest behind one opaque, purpose-bound, process-memory ticket. The ticket
expires after 30 minutes and is atomically consumed once; replay, changed form
fields, a changed selected registry entry, or a different purpose fails closed.
Immediately before launch, Rig Web revalidates the unified snapshot and writes
only the selected hosted, local, source, prepared-attacker, and conformance
bytes to private mode-600 files. Each receives its exact paired SHA-256 flag;
Runner performs a bounded read, verifies the digest, and unlinks it before
model work. Raw compatible URLs, explicit local filesystem locators, and
prepared/source paths therefore remain launch-only. HTML, `Job`,
`command.json`, and SQLite retain typed digest placeholders and portable
identities, never those private values. Tickets, private files, and their
snapshots are operational controls, not provider attestation or scientific
evidence.

## Enforced invariants

- every non-dry request has one digest-validated project-revision receipt whose
  expected/observed commit, HEAD tree, source roots and current driver/harness
  bytes remain unchanged through final grid publication;
- modalities and required identifiers are non-empty and non-duplicated;
- executable media uses full 64-character SHA-256 digests;
- scores lie in `[0,1]`, aggregate values are finite, and intervals are coherent;
- checkpoints match schema/run identity, exact field inventory, attempt lineage,
  rendered-input fingerprints, and post-attempt budget lineage before resume;
- non-null target and ordered judge-stage provider/model/fingerprint/revision
  identity stays stable across calls and resume;
- source-policy inventories and realized identity digests reconstruct from the
  hashed artifacts and match the manifest/completion marker;
- modality evidence binds the datapoint ID to its exact delivered modality
  combination; a tag without byte-backed delivery is insufficient;
- missing or unsupported constructs fail explicitly rather than becoming zero.

Grid requests also bind `source_policy_cluster_counts` for every selected corpus
and a `call_projection` using
`conservative_complete_grid_upper_bound_v2`. The latter reports trajectory,
target-call, local-guardrail-evaluation, model-judge-call, and declared
provider-HTTP-attempt upper bounds, including the retry reserve and per-attacker
subtotals. It is an
exposure/budget planning record, not a price, token, latency, or expected-usage
estimate.

Agentic tool fields represent source-benchmark traces. The core harness does not
execute model-produced commands or infer that a represented tool effect occurred.

Complete upstream evaluator outputs use an
`ura-native-import-envelope/2` rather than `EvalResult`. It binds a relative
import-config locator/hash/size and the derived `NativeEngineRun`. Validation
re-runs that exact importer over the returned authoritative files and requires
all case joins, outcomes, scores, aggregates, roles, hashes, byte counts, and
record counts to match; physical paths may relocate with the complete tree.
`experiments.suite_summary` joins completion-validated runner cells and these
revalidated native envelopes only at an evidence-inventory layer; it does not
coerce native outcomes into schema-v1.5 common metrics.
`NativeEngineRun` retains its own upstream repository/revision and does not have
a Runner `RunManifest`; the return-package/importer context records which URA
revision performed import without rewriting the upstream-native schema. The
current native row in `suite_summary` does not itself carry that URA revision.

Human-audit outputs are separately content-addressed after ratings are complete.
The audit artifact records the labels CSV name, byte count, and SHA-256;
complete-rater coverage; completed and directly labelled run inventories;
achieved common-arm endpoint coverage; pairwise policy-endpoint agreement and
support; and automated-versus-consensus performance stratified primarily by
exact run and response-producing arm, logical corpus arm, source policy,
effective modality, expected population, and common-metric eligibility. Each
primary stratum retains total/decided/abstained support and decision coverage;
harmful violation and benign over-refusal remain distinct adverse endpoints.
Cross-stratum pooled values are composition-dependent diagnostics. Static rows are endpoint units directly,
while live challenge rows collapse to conversation endpoints before equal
conversation-within-cluster and equal-cluster weighting. Pair records expose
`n_shared_endpoint_conversations`, `endpoint_unit`, and `weighting` alongside
agreement and unique-cluster support. These are analysis artifacts rather than
additions to schema v1.5's runtime record types.

The exact URA project revision, source-byte identities, target snapshot,
requested and realized judge identities, source and policy digests, code/schema
identity, and analysis inputs remain independently bound in runtime and
postprocessing provenance.

## Console operational database and pricing registry (not evidence)

The console's startup platform/CPU/core/RAM and NVIDIA inventory is an
operator-visible runtime snapshot, not a scientific artifact schema. Likewise,
the Build page separates hosted API, Local vLLM, and Local Ollama choices. Its
hosted-provider and vLLM name/maximum-parameter/profile-fit controls, plus the
separate unchecked unknown-fit control, only filter rendered choices. Known
16/8/4-bit recommendations use green/blue/amber; unknown fit is gray. Compatible
vLLM rows are single-choice
selectors even when the roster pin is unfinished, but non-dry submission still
requires an exact revision/digest. An unknown-fit row remains blocked under auto;
selecting `Include unknown fit` exposes an unknown-size row at every parameter
maximum, while known sizes still obey the cap. An explicit per-model precision
binds `allow_unknown_fit: true`, while known non-fit remains blocked. A vLLM row
labels an explicit `max_model_len` context cap or automatic maximum GPU-fit
context. Source-ineligible rows may also remain visible and
selectable with one custom hover/focus tooltip. Server validation rejects them
before a subprocess by default. Eligible non-tool rows show `⚠ approximate
opt-in`; the explicit opt-in admits only supplementary `approximate_*` response
proxies. Tool-conditioned rows show `tool runtime required` and remain
fail-closed. Neither UI state replaces the local-config, source-evaluator, or
hardware checks described above.
Dry builder state carries no real API/local target/config into the command
because dry execution uses `MockTarget`. Local roster modality metadata is
restricted to the Runner's text/image vLLM path, keeping audio mismatch rejection
consistent between UI and CLI.
Ollama rows follow only selected modality. They expose no fit, parameter,
quantization, topology, or context controls and remain disabled until their
narrow digest/modality config is valid and the tag is present in the live
loopback daemon. Rig Web may Start, Stop, and Pull only through its proven
current-console-owned child; an external daemon is available for bounded
discovery and inference but not UI Stop or Pull.

The Jobs page presents a full start date and time converted from the stored epoch
to browser-local time. State, text, From, and To filters compose. Absent URL
bounds, From defaults to seven days before the current browser time and To to
the current time; both are inclusive at the selected datetime precision. The
browser persists epoch bounds and reloads a date-aware SQLite query rather than
filtering only the 500-row restart cache. Campaign marker start times are
filtered before their 20-row display cap. A 5,000-job or 20-campaign truncation
is disclosed and can be narrowed with From/To. Short
status tags include blue `running`, `passed`, `failed`, `orphaned`, `partial`,
`blocked`, `stopped`, and `unknown`. Detail text distinguishes a console-owned
process from an external task-log `running` marker; the latter never implies
operating-system process liveness.

An external engineering campaign is discovered only through a bounded regular,
non-symlink `ENGINEERING_ONLY.json` object with schema
`ura-engineering-campaign/1`, `thesis_empirical_evidence: false`, and an explicit
boolean `hosted_calls_allowed`. Optional `planned_tasks` is a unique list of
non-empty task names no longer than 256 characters, excluding the phase names
`bootstrap` and `stage2`. Optional `model_tasks` is a unique subset of a valid
`planned_tasks` list. Event logs yield task-process succeeded, failed, skipped,
active, and pending counts; those outcomes do not establish model execution.

An optional regular, non-symlink `model-execution.jsonl` file is bounded to 512
KiB. Each complete JSON line has `event: "model_execution"`, one declared model
task, and nonnegative integer `attempted_calls` and `successful_generations`,
each bounded by 1,000,000 and with successes no greater than attempts. A task
may appear only once. Positive counts contradict a pending or skipped task. If
the file is supplied for a terminal campaign, every declared model task must
have exactly one row; pending or skipped tasks use zero attempts and zero
successes. This is an operational self-report, not confirmed execution or an
evidence schema. Call reservations are also not execution observations.
Completion-validated response artifacts remain authoritative.

The rig console persists its operational state in a stdlib-sqlite database
(`console.db` under the console state directory, schema version 4): `jobs`
(durable argv identity, builder parameters, state, exit code, failure context, pinned
revision), `runs` (the campaign-run registry: kind, output directory, pin),
`usage` (per-completion-marker recorded token amounts keyed by role,
provider, model, and billing category - input, output, cache_read,
cache_write, reasoning, plus `calls` and `missing_tokens` counters), and
`reports` (an index of retained artifacts by their declared
`schema_version`). Rows in `usage` are derived exclusively from artifacts
reachable through a valid `*.complete.json` completion marker and can be
rebuilt at any time from the retained artifacts (dashboard Reindex, with
digest verification). None of these tables is an evidence schema: they index
and mirror the validated artifacts, which remain authoritative.

Explicit local vLLM filesystem locators are never members of this schema. The
console projects them to `vllm:local-checkpoint@sha256:<digest>` before writing
the Job row; storage also rejects an unprojected explicit locator fail-closed.

`experiments/pricing.json` (editable copy of
`experiments/rig/pricing.example.json`, schema tag `ura-console-pricing/1`)
is an operator-maintained registry, not an artifact:
`providers -> models -> rates[]`, each rate carrying `effective_date` (a
zero-padded ISO `YYYY-MM-DD`), `currency`, and `per_million_tokens` for the
billing categories. The console selects the rate whose `effective_date` is the
newest on or before today and multiplies recorded tokens by its per-category
rates. Priced categories are `input`, `output`, `cache_read`, and
`cache_write`; `reasoning` is displayed but not priced separately (providers
bill it as output), and the input count has any reported cache reads netted
out first so no token is billed twice. If the applicable rate leaves a
category with recorded tokens unpriced, or a token count is missing, the whole
row renders N/A naming the missing field - never a fabricated zero. The
example ships every rate as `null`; fill them from the provider's price sheet
before relying on a figure.

A rate may additionally carry provenance - `auto_fetched: true`, `source_url`,
and `fetched_at` - when it was retrieved by the pricing fetcher
(`experiments/pricing_fetch.py`, reachable from the console's Config section as
"Fetch from provider pricing pages" or run as a module). The fetcher performs
read-only HTTPS GETs of each provider's published pricing page listed in
`experiments/pricing-sources.json` (copy of
`experiments/rig/pricing-sources.example.json`, schema tag
`ura-console-pricing-sources/1`, a `providers -> {url}` map) and merges the
per-model rates it can read. Providers and model ids are keyed by the prefix
used in `api-targets` (the prefix attributes recorded usage, e.g.
`google:gemini-3.6-flash` -> provider `google`). It never fabricates a price: a
model or provider it cannot read with confidence is left untouched (Anthropic,
OpenAI, DeepSeek, z.ai/GLM and Google Gemini are machine-readable; Moonshot/Kimi
and Alibaba/Qwen render prices client-side and stay manual). Model ids are
matched exactly, so a base id (`gpt-5`, `claude-opus-4`) never captures a
differently priced longer sibling. Once the operator has priced a model by hand (a rate
without `auto_fetched` whose input or output is non-null) that figure is
authoritative and is never superseded - not on the same date and not by a
later-dated fetch - so a hand-entered correction is always the billed value
until the operator edits it directly; the fetcher only fills a model the
operator has not priced or updates a rate it set itself, appending a
later-dated entry only when the price actually differs. The merge is written atomically
(temp-file + rename) after backing up the prior file to `pricing.json.bak`, and
an existing `pricing.json` that is unreadable or not a JSON object is refused
rather than reset, so operator rates are never lost to a corrupt file.

Provider API keys are managed from the same Config section
(`/config/secrets`). The console records only presence and a last-four masked
hint; it never displays, logs, or stores a key value outside the operator secret
boundary. Hosted-provider keys are written to the operator secrets file (mode
600, `~/.ura_env` by default) as `export NAME=...` lines - rejecting any value
containing a single quote or control character so a stored key can never break
or inject into that sourced file. `HF_TOKEN` is presence-only and process-memory
only; setting or clearing it also removes any legacy `HF_TOKEN` line from the
operator file.
