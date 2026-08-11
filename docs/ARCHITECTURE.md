# Architecture

URA-Bench separates corpus meaning, attack generation, model execution,
judgment, and analysis. The shared boundary is schema 1.3 in
`ura.data_models`; targets do not define success, and judges do not generate
attacks.

```mermaid
flowchart LR
    S[Verified local release] --> P[Content-bound pilot/main partition]
    P --> C[Strict converter / DataPoint]
    C --> A[Replay or stateful attacker]
    A --> T[Hosted or local target]
    T --> J[Full-shadow judge cascade]
    J --> R[Runner 2.3 artifacts]
    R --> D[Disjoint pilot + frozen confirmatory plan]
    D --> H[Main analysis + human audit]
    H --> F[Final artifact and measured figures]
```

External engines may instead run natively and be imported as
`NativeEngineRun`. Their upstream target/judge and estimand remain explicit;
they are not silently pooled into common URA ASR/FRR.

## Components

| Layer | Modules | Responsibility |
| --- | --- | --- |
| Schema/taxonomy | `data_models.py`, `taxonomy.py` | typed records and informational standards mapping |
| Ingestion | `converters/` | strict release parsing, source-policy identity, media confinement/hashing |
| Attacks | `adapters/` | static replay, response-conditioned Crescendo, bounded external bridges |
| Targets | `targets/` | mock, hosted API, vLLM, and Ollama transports with declared capabilities |
| Judgment | `judges/` | rules, guard classifier, LLM grader, complete shadow trail |
| Runtime | `runner.py`, `experiments/run_matrix.py` | validation, durable ceilings, locks, circuits, exact resume, manifests |
| Measurement | `metrics.py`, `source_metrics.py` | population-aware common/source metrics, clustered and survival estimates |
| Analysis | `experiments/` | partition, pilot, frozen confirmatory families, human audit, figures |

## Execution and recovery

A static attacker produces complete rendered attempts. A stateful attacker opens
a bounded session: Runner submits one turn, returns the actual response to the
session, and only then requests the next. `max_queries` and `max_turns` are hard
per-datapoint bounds. Crescendo separates conditioning setup from policy
challenges: setup is persisted as typed `not_applicable`, invokes no judge, and
enters no metric; challenge indices are contiguous within one declared horizon,
and a harmful authoritative violation ends the trajectory immediately.

Before external calls, the matrix persists reservations against durable
matrix-wide target-call, judge-call, transport-attempt, and deadline ceilings.
Grid and cell locks prevent concurrent reuse of one artifact namespace. A
systemic provider/judge failure opens a durable circuit so sibling cells do not
repeat it; `--reset-open-circuits` is an explicit operator acknowledgement after
the cause is fixed. Append-only checkpoints resume verified completed attempts,
including provider continuation state, without repeating them. These are call-
exposure controls, not dollar, token, or provider-billing guarantees.

Run identity binds corpus/configuration/source code; provider-resolved identity
is reconstructed separately from responses and trails. Any conflicting non-null
provider/model/fingerprint/revision/digest fails the cell, including across
resume. Completion is atomic and validated before postprocessing.

The Fable transport preserves signed thinking only for successful continuation.
If the provider emits a typed mid-generation refusal, all partial visible,
thinking and redacted-thinking blocks from that generation are discarded and
only the refusal plus bounded discard audit is persisted. The Sol study spec is
`reasoning_context=all_turns`; with `store=false`, bounded encrypted reasoning
and assistant-message items are hash-verified in typed continuation state and
returned on the next request.

## Release, partition, and provider gates

Every real non-synthetic scored run must use the SHA-256-bound
`ura-cluster-partition/1.2` artifact and select exactly `pilot` or `main`. The
partition is exhaustive and disjoint over source prompt/intent clusters and
binds a portable `source_locator`, the full converted-corpus digest and
population, and exact pilot/main counts for every observed source-policy
stratum. The default minimum is two clusters per policy in each role. A child
grid may select only the corpus entries it needs while retaining the identical
full-plan digest; it cannot introduce a corpus absent from the plan.
Loading recomputes the exact SHA-256-scoped-seed assignment from the complete
sorted cluster inventory, corpus name, seed, and pilot count; matching counts
or digests cannot conceal a modified pilot/main membership list.
StrongREJECT enforces official commit
`f7cad6c17e624e21d8df2278e918ae1dddb4cb56`, normalized CSV SHA-256
`4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`,
313 rows, six categories and 313 unique prompts. MM-SafetyBench and MOSSBench
enforce their maintained pinned counts and manifest/table hashes. Measured
execution uses `--limit 0`; ad hoc cluster caps are diagnostics, not a
substitute for the frozen partition.

Every hosted target and hosted LLM judge must also appear exactly once in a
SHA-256-bound provider data-policy approval, including its role and accepted
retention/data-use terms. The normalized approval and artifact digest enter the
grid and every cell.

Pilot reduction admits only real, mock-free, integrity-valid, grid-complete,
source-validated, exclusion-free evidence. It hash-binds a normalized analysis
design whose endpoint construction, selectors, judge identities, repeat seeds,
per-trajectory budget, source policy/metric design, and code/schema identity
must match the main facet exactly. Confirmatory power uses a bounded
rate-difference SESOI, the first Holm threshold, and the discrete two-sided
sign-flip resolution; every confirmatory contrast explicitly asserts paired
exchangeability.

The human-audit plan freezes minimum shared-cluster support and endpoint-event
agreement for every required exact arm. Sampling satisfies the support
constraint before export, and a failed support/agreement cell remains
exploratory and blocks the final publishable artifact. That final artifact feeds
exactly the primary StrongREJECT model, seven policy-qualified MM/MOSS proxy,
and two H4 adaptivity points used by the three measured figures.

## Modality behavior

Coverage is planned from actual adapter capabilities and available converted
data. Evidence is keyed by datapoint and the exact delivered modality
combination, not a declaration alone. The pre-call plan requires text and each
explicitly implemented physical combination; the post-run result requires at
least one real policy-evaluable execution for each planned combination. A
pre-input defense block and a setup-only turn do not count; a target execution
whose output is subsequently blocked does. It never infers arbitrary media
cross-products.

The canonical Fable and Sol adapters currently support text and text+image.
StrongREJECT supplies text; MM-SafetyBench and MOSSBench supply text+image.
Audio and video remain explicit unavailable combinations until a target adapter
implements and declares them. Media is never dropped, captioned, or coerced to
text inside the registered run.

The efficient study layout has two children under each pilot/main parent: one
replay grid over StrongREJECT, MM-SafetyBench and MOSSBench, and one
StrongREJECT-only Crescendo grid. The replay grid emits a content-addressed
`ura-modality-coverage-proof/1.0`; the Crescendo child may use it only when its
target runtime component, defense condition, driver identity and harness source
identity reconstruct exactly. Thus both Fable and Sol execute text and
text+image suite-wide without duplicating replay calls or expanding Crescendo
across the two proxy corpora.

Local media is prepared once, content-hashed, and persisted as
`@media-root/<index>/<relative-path>`. The target resolves the alias against the
same explicitly ordered approved roots on execution or resume. This makes an
artifact portable across machines while keeping path traversal, unapproved
reads, digest drift and MIME spoofing fail-closed.

## Safety and scope

Core tool traces are inert. External subprocess filtering reduces accidental
secret leakage but is not a sandbox; untrusted engines need a disposable,
least-privilege environment with bounded filesystem, network, processes, and
resources. Provider-bound content leaves the machine and is subject to the
content-addressed approval described in [SECURITY.md](../SECURITY.md).

Taxonomy crosswalks are navigation aids, not certification or legal conformity
claims. Experiments remain pending until complete real artifacts pass every
gate above.
