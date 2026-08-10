# Unified schema v1.0

`ura.data_models` is the typed Pydantic v2 contract shared by converters,
attackers, targets, judges, persistence, and analysis. `SCHEMA_VERSION = "1.0"`
is stamped on datapoints and manifests. Runner rejects duplicate datapoint IDs
and mixed schema versions before it calls a target.

## Enumerations

- `Modality`: `text`, `image`, `audio`, `video`, `tool`, `multi`
- `Role`: `system`, `user`, `assistant`, `tool`, `env`
- `ExpectedBehavior`: `refuse`, `safe_answer`, `comply_safely`
- `JudgeLabel`: `safe`, `violation`, `refusal`, `over_refusal`
- `RiskCategory`: the categories documented in [ATTACK_TAGS.md](ATTACK_TAGS.md)

## Records

| Type | Important fields | Purpose |
| --- | --- | --- |
| `MediaRef` | `modality`, one of `uri`/`path`, `sha256`, `mime`, `meta` | content reference; local and inline media are verified before upload |
| `ToolCall` | `name`, `arguments` | represented tool invocation |
| `DialogTurn` | `role`, `content`, `media`, `tool_call`, `tool_result` | one conversation or represented agent trace turn |
| `DataPoint` | `id`, `source`, `modalities`, `dialog_history`, payloads, media, risk, expectation, taxonomy refs, attack metadata | atomic corpus item |
| `Attempt` | `id`, `datapoint_id`, `attacker`, `strategy`, `target`, `turn_index`, `rendered_input`, `seed`, `params`, `run_id` | exact input submitted for one target call |
| `Response` | `attempt_id`, `target`, `output_turns`, `tool_trace`, latency, tokens, `raw`, `run_id` | target output and provider provenance |
| `Judgment` | `attempt_id`, `judge`, `label`, `score`, rationale, `raw`, `run_id` | one automated or human verdict |
| `EvalResult` | `id`, `metric`, value and CI, `n`, grouping, provenance, `run_id` | one aggregate estimand |
| `RunManifest` | `run_id`, code/config identity, seeds, models, adapters, judges, dataset hashes, realized target/judge identity inventory and digest, time, environment | re-derivation and audit record |

## Lineage and joins

Runner persists separate `*.attempts.jsonl`, `*.responses.jsonl`, final judgment
JSONL, `*.trails.jsonl`, aggregate `*.results.jsonl`, and a manifest for each
cell. Records join on the composite identity `(run_id, model/target,
attempt_id)`. An attempt ID alone is not assumed globally unique.

Each final judgment additionally carries the fields required by downstream
analysis in `raw`, including:

- datapoint/source/risk/expected behavior;
- declared and effective modalities;
- attacker, strategy, seed, and turn index;
- target model and run ID;
- rendered-input `attack_fingerprint`, stable `transfer_key`, and
  `transferable` flag;
- requested seed and effective target sampling control.

Each `*.trails.jsonl` row carries the same run/model/attempt, datapoint, seed,
turn, construct, fingerprint, transfer, and sampling lineage, plus its manifest
stage index and judge name. It also records numeric stage confidence, optional
parse status (`null` means parsing is not applicable to a structured stage), the
cascade confidence decision and authority role, and `response_sha256`. The last
field is the canonical SHA-256 of the exact persisted `Response`; postprocessors
recompute it before claiming that shadow stages evaluated the same output.

Response-conditioned attempts are marked non-transferable unless they are an
explicit replay. This prevents different live conversations from being paired
as though their inputs were identical.

## Media trust boundary

Converters resolve corpus media under the declared corpus root and compute
SHA-256 digests. Runner preflight and hosted/local image encoders both restrict
local reads to target `media_roots` or `URA_MEDIA_ROOTS` and verify the digest.
Inline data URIs are decoded, size-limited, and hash-verified. Low-level target
clients accept HTTPS references, but scored Runner cells reject them because the
provider-fetched bytes cannot be verified against the manifest; materialize the
asset locally or inline it first. A missing corpus or media file is an error, not
an empty dataset.

## Enforced invariants

- datapoint modalities are non-empty;
- a media modality cannot be `text`;
- a supplied SHA-256 is 64 lowercase hexadecimal characters after normalization;
- judgment scores are in `[0, 1]`;
- run aggregation cannot mix run IDs;
- checkpoints must match run identity and rendered-input fingerprints before
  they can be resumed;
- reported non-null target and ordered judge-stage provider/model/fingerprint,
  revision, and digest identities must remain stable within the cell and resume;
- a completion marker's realized-identity digest must match a reconstruction
  from the hashed Response and trail artifacts.

Agentic `tool_call` and `tool_result` fields represent source-benchmark traces.
The core harness does not execute model-produced commands or claim successful
tool effects merely because a trace contains them.
