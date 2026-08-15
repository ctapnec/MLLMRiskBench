# Unified schema v1.4

`ura.data_models` is the typed Pydantic v2 contract shared by converters,
attackers, targets, judges, persistence, and analysis. `SCHEMA_VERSION = "1.4"`
is stamped on datapoints, checkpoints, and manifests. Runner 2.11 rejects mixed
schema versions and duplicate datapoint IDs before a target call.

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

## Prospective request envelope and early failures

Before planning exists, `run_matrix` emits strict
`ura-request-envelope/1` as
`<envelope_id>.request-envelope.json`. Its exact top-level
fields are `schema`, `status`, `envelope_id`, `request`, `bindings`,
`execution_units`, and `limitations`. `request` fixes execution purpose,
requested target keys, logical source arms, attackers, judges, seeds, sampling
and call/turn limits, defense, grouping, runtime controls, dry-run state, and
call caps. `bindings` fixes project-revision, harness-source, and driver-source
identity. Every execution unit has exactly `request_unit_id`,
`requested_target_key`, `logical_source_arm`, and `attacker`; the list is the
complete exact cross-product of those three selected axes.

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

`run_matrix` and `rig_check` emit `ura-eligibility-plan/1` as
`eligibility-<content-id>.eligibility.json` after corpus conversion and before
model calls. Each item binds the requested and resolved target identities,
logical source arm, selected source stratum and item digest, exact modality,
attacker, execution/metric mode, evaluator/reference mode, disposition, and
failed gates. The artifact self-validates its content-derived `plan_id`.

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
`run_matrix` emits strict `ura-lane-projection/1` as
`lane-projection-<content-id>.lane-projection.json`. `projection_id` is derived
from the canonical artifact body. The projection binds the exact eligibility
plan/request/condition and artifact descriptor, then records per logical source
arm:

- converter and selected-corpus/datapoint/cluster digests;
- pre-limit and selected row/cluster counts, sample seed, limit, and exact
  source-policy cluster counts;
- verified selected physical input-media references and unique bytes by
  modality, or an explicit no-physical-media state; and
- reconciled selected-arm totals.

Its `call_projection` uses
`conservative_complete_grid_upper_bound_v1` for trajectory, target-call,
model-judge-call, local-guardrail-evaluation, and declared HTTP-attempt exposure,
including per-attacker subtotals. `unavailable_estimates` fixes token use,
monetary price/cost, runtime/throughput, and expected output storage to
`status=CANNOT-VERIFY` and `value=null`; consumers may not fill those fields by
extrapolation. Selected input-media bytes are observed content bytes, not
expected output storage.

The exact measured grid request contains the projection ID and its file/SHA-256/
byte/record descriptor. `rig_check` validates and retains the projection next to
the eligibility plan in the separate preflight tree. These two instances may
bind different execution purposes and must not be substituted merely because
their call totals match.

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

`python -m experiments.level1_evidence` emits `ura-level1-evidence/2` JSON and
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

## Lineage and continuation state

Each cell persists attempts, responses, authoritative judgments, full-shadow
judge trails for common responses (or typed unqueried placeholders for
source-metric-only classification), aggregate results, a manifest, an append-only checkpoint, and
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
confidence, parse status, cascade role, and provider identity.

Provider-native continuation data is explicit rather than hidden:

- Anthropic thinking/redacted-thinking blocks are retained on assistant turns
  so the next Fable request can return them unchanged.
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
  before measured use.
- `--local-config` binds an exact local specification to one immutable model
  revision or digest, declared modalities, tensor-parallel size, memory
  utilization, and output bound. One local target is admitted per runner
  process so server lifetime and GPU ownership stay explicit.

Unselected inventory entries are neither evidence nor requested cells. Secret
values are environment-indirected and rejected from persisted configuration.
The manifest keeps requested and realized target identities distinct.

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
`conservative_complete_grid_upper_bound_v1`. The latter reports trajectory,
target-call, local-guardrail-evaluation, model-judge-call, and declared
provider-HTTP-attempt upper bounds, including per-attacker subtotals. It is an
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
coerce native outcomes into schema-v1.4 common metrics.
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
additions to schema v1.4's runtime record types.

The exact URA project revision, source-byte identities, target snapshot,
requested and realized judge identities, source and policy digests, code/schema
identity, and analysis inputs remain independently bound in runtime and
postprocessing provenance.

## Console operational database and pricing registry (not evidence)

The rig console persists its operational state in a stdlib-sqlite database
(`console.db` under the console state directory, schema version 2): `jobs`
(exact argv, builder parameters, state, exit code, failure context, pinned
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
