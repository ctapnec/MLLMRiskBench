# Unified schema v1.0 (`ura.data_models`)

Typed Pydantic v2 contract shared by every layer. Extends the pre-2025 prototype (v0.3: `DataPoint`/`DialogTurn`/`EvalResult`) with multi-turn dialog, agentic tool traces, content-addressed media, an explicit `Attempt → Response → Judgment` lineage, and standard-taxonomy mapping. `SCHEMA_VERSION = "1.0"` is stamped on every `DataPoint` and `RunManifest`.

## Enumerations

- `Modality = text | image | audio | video | tool | multi`
- `Role = system | user | assistant | tool | env`
- `ExpectedBehavior = refuse | safe_answer | comply_safely`
- `JudgeLabel = safe | violation | refusal | over_refusal`
- `RiskCategory` - 11 members (see [ATTACK_TAGS.md](ATTACK_TAGS.md))

## Types

| Type | Key fields | Purpose |
|---|---|---|
| `MediaRef` | `modality, uri/path, sha256, mime, meta` | content-addressed media (reproducible, de-duplicated; validator rejects `text`) |
| `ToolCall` | `name, arguments` | an agentic tool invocation |
| `DialogTurn` | `role, content?, media[], tool_call?, tool_result?` | one turn of a (possibly agentic) conversation |
| `DataPoint` | `id, source, modalities[], dialog_history[], payload_text?, payload_code?, media[], risk_category, risk_subtype?, expected_behavior, taxonomy_refs[], attack_family?, turns, is_agentic, schema_version, meta` | the atomic unit of evaluation |
| `Attempt` | `id, datapoint_id, attacker, strategy?, turn_index, rendered_input[], seed?, params` | a concrete execution derived from a `DataPoint` by an attacker |
| `Response` | `attempt_id, target, output_turns[], tool_trace[], latency_ms?, tokens?, raw` | a target model's reply |
| `Judgment` | `attempt_id, judge, label, score∈[0,1], rationale?, raw` | a single judge's verdict |
| `EvalResult` | `id, metric, value, ci_low?, ci_high?, n, group_by, provenance` | an aggregated metric with uncertainty |
| `RunManifest` | `run_id, code_version, config, seeds[], models[], adapters[], judges[], dataset_hashes, started_at, env, schema_version` | makes a run re-derivable |

## Invariants (enforced by validators)

- `DataPoint.modalities` is non-empty.
- `MediaRef.modality` is not `text`.
- `Judgment.score ∈ [0, 1]`.

## Why v1.0 over v0.3

v0.3 could express only single-shot text pairs with a stored boolean ground truth. v1.0 adds multi-turn lineage (`turn_index`, escalation trees), agentic traces (`tool_call`/`tool_result`), content-addressed media, the Attacker/Target/Judge split (separate `Attempt`/`Response`/`Judgment` records linked by id), and standards mapping - the capabilities the 2025-2026 threat landscape requires and the prototype lacked. Converters declare the schema version they emit; the metrics engine refuses to mix versions.
