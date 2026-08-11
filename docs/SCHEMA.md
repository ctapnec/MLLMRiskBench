# Unified schema v1.4

`ura.data_models` is the typed Pydantic v2 contract shared by converters,
attackers, targets, judges, persistence, and analysis. `SCHEMA_VERSION = "1.4"`
is stamped on datapoints, checkpoints, and manifests. Runner 2.5 rejects mixed
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
| `Attempt` | datapoint, attacker, target, turn, exact rendered input, seed, params, run ID | one submitted input |
| `Response` | attempt, target, output/tool turns, latency/tokens, raw provenance, run ID | one target outcome, including a typed provider refusal |
| `Judgment` | attempt, judge, label, score, rationale, raw provenance, run ID | one automated/human verdict, or typed non-evaluable setup record |
| `EvalResult` | metric, value/CI, support, grouping, provenance, run ID | one aggregate estimand |
| `RunManifest` | run/code/config identity, seeds, components, data hashes, time and environment | re-derivation and audit record |

Enumerations are defined in code. In particular, expected behavior separates
harmful `refuse` probes from benign `safe_answer` and `comply_safely` probes;
that split controls ASR and FRR denominators.

## Lineage and continuation state

Each cell persists attempts, responses, authoritative judgments, full shadow
judge trails, aggregate results, a manifest, an append-only checkpoint, and
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

- `--source-config` maps a stable corpus-arm ID to a converter plus an
  environment-variable path locator and optional source label/split. The full
  file hash is provenance; the normalized selected subset digest enters
  execution identity. The environment's resolved absolute path is not retained.
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

The exact target snapshot, requested and realized judge identities, source and
policy digests, code/schema identity, and analysis inputs remain independently
bound in runtime and postprocessing provenance.
