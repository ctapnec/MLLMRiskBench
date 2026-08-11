# URA-Bench

URA-Bench is the research software for the master's thesis *A Risk-Assessment
System for Question Answering by Multimodal Language Models*. It converts safety
corpora to one typed schema, runs static or response-conditioned attacks against
hosted/local targets, shadow-scores every response, and retains auditable
lineage through confirmatory analysis.

Experiments are pending. The repository establishes no model ranking, defense
effect, compliance finding, or other empirical result yet.

## What is measured

- Harmful ASR/refusal and benign FRR use disjoint denominators.
- Live trajectories report conversation ASR, robust refusal, the full
  Kaplan-Meier curve, observed median turns-to-break, and challenge-horizon-bound
  RMTB. Conversation setup turns are retained but are not policy observations.
- Repeated seeds, turns, and source variants are clustered by their originating
  prompt/intent; paired effects give source clusters equal weight.
- Static transfer requires the same harmful rendered input. Live adaptive
  conversations are not transferable unless replayed exactly.
- MM-SafetyBench common ASR and MOSSBench common FRR are secondary URA proxies;
  neither is presented as its official metric unless its official evaluator ran.
- MM-SafetyBench's six source-policy strata are never pooled; executable grids
  include `source_policy_id,source_policy_version` in their grouping.
- Confirmatory results require a disjoint pilot, a frozen complete-family plan,
  a hash-bound whole-cluster human audit, and a final publishable analysis
  artifact. Primary endpoints and secondary cross-benchmark proxies occupy
  separate multiplicity families.

See [metrics](docs/METRICS.md), [schema](docs/SCHEMA.md),
[architecture](docs/ARCHITECTURE.md), and the
[operator runbook](experiments/RUN_AND_RETURN.md).

## Offline smoke test

Python 3.12 is the supported baseline.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python experiments/run_matrix.py --dry-run --attackers replay --judges rules,llm --corpora synth --limit 12 --out runs/dry
python -m experiments.figures --synth --out runs/_figcheck
```

Dry-run output is plumbing evidence only and cannot enter the thesis results.

## Planned comparison

The executable case study is the exact account-visible Claude Fable endpoint
versus GPT-5.6 Sol through the Responses API:

- `anthropic-fable:claude-fable-5;effort=high;max_tokens=25000`
- `openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns`

It is a cross-provider endpoint comparison, not a same-base ablation or a causal
estimate of a safety mechanism. Fable thinking and Sol encrypted reasoning/
assistant output state are retained only as needed for exact stateless
continuation and checkpoint resume.

The real command intentionally is not reduced to an unsafe one-liner here. It
requires three content-addressed inputs: the pilot/main corpus partition, the
hosted-provider data-policy approval, and later the frozen analysis plan. Follow
the [end-to-end runbook](experiments/RUN_AND_RETURN.md), which includes those
schemas and the exact CLI.

Mythos remains important frontier-security literature and a future replication
target, but the researcher has no access. It is not an executable target, roster
row, or measured effect in this study.

## Multimodality

The canonical Fable and Sol adapters currently declare text and image support.
The main corpus set therefore exercises both:

- StrongREJECT: text;
- MM-SafetyBench: harmful text+image;
- MOSSBench: benign text+image.

Before calls, `modality_coverage_plan` verifies that available supported
combinations were selected. After execution, `modality_coverage_result` requires
real eligible evidence for every exact delivered combination. An input-defense
block or a setup-only turn is not execution evidence; an output-defense block
after a real target call is. A content-addressed completed companion grid may
supply the image evidence for the separate StrongREJECT-only Crescendo child,
but only for the same target runtime and defense condition. Audio and video are
unavailable on both study targets; URA never fabricates support, drops media, or
substitutes a caption inside the registered run.

## Real-run gates

- Real corpora resolve through `URA_<CORPUS>_PATH`; local media also needs an
  approved, ordered `URA_MEDIA_ROOTS` list. Persisted media paths are portable
  `@media-root/<index>/<relative-path>` aliases; resume must rebind the same
  ordered roots and relative layouts.
- Every real non-synthetic scored run uses a SHA-256-bound exhaustive
  `ura-cluster-partition/1.2` artifact and selects `pilot` or `main` with
  `--limit 0`. The partition binds a portable source locator, full converted
  release population, disjoint source clusters, and exact per-policy pilot/main
  counts. Both roles default to at least two clusters per observed policy
  stratum. StrongREJECT, MM-SafetyBench, and MOSSBench enforce pinned official
  release identities.
- The StrongREJECT gate is the official CSV at commit
  `f7cad6c17e624e21d8df2278e918ae1dddb4cb56`: normalized SHA-256
  `4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`,
  313 rows, all six categories, and 313 unique non-blank prompts. URA reports a
  StrongREJECT-style judge; it does not claim to execute the official evaluator.
- Every hosted target/judge is covered by a SHA-256-bound provider data-policy
  approval naming its exact model specification and role.
- Finite matrix-wide target-call, judge-call, HTTP-attempt, and wall-clock
  ceilings are persisted before calls. Locks, durable dependency circuits, and
  append-only checkpoints make interruption and resume fail closed.
- A real LLM judge needs an exact non-mock `--judge-model`. A model guard needs
  an immutable `--guardrail-revision`.
- Optional local targets use `--local-config` keyed by the exact local spec,
  with exactly one immutable `revision` or `digest` and an explicit `modalities`
  list; no alternative aliases are accepted.

`--limit N` means at most N unique source prompt/intent clusters, retaining all
rows in each selected cluster. Measured partitioned runs require `--limit 0`;
the cap remains useful for dry-run or unpartitioned diagnostics.

## Artifacts and recovery

Each cell can produce exact attempts, responses, authoritative judgments,
full-shadow trails, aggregate results, a manifest, an append-only checkpoint,
and either a validated completion marker or an error record. A matching
completion marker makes a rerun call-free. A matching checkpoint restores
completed attempts and provider continuation state without querying them again.
Provider/model identity drift, missing media, source-policy drift, partial
artifact families, unsupported modality, or exhausted durable ceilings fail
explicitly; none becomes a zero.

Runner `ura-runner/2.3` writes unified schema `1.3`. In a Crescendo trajectory,
benign setup turns receive typed `not_applicable` judgments and no judge call or
metric contribution. Policy challenges are numbered contiguously from zero,
share one declared challenge horizon, and a harmful authoritative violation is
terminal.

## Source-specific tracks

R-Judge and GPTGeoChat remain first-class but use their own classification
metrics rather than common ASR/FRR. Other convertible agent/runtime sources may
fail scored preflight until their substantive runtime/evaluator exists;
conversion support is not scoring support. See the protocol and runbook for the
current inventory.

## Layout

```text
src/ura/       schema, converters, adapters, targets, judges, runtime
tests/ura/     offline regression and integration tests
experiments/   matrix, partition/pilot/confirmatory analysis, figures
docs/          architecture, schema, metrics, taxonomy and native imports
datasets/      local dataset area; released corpora are not redistributed
```

Model inputs, outputs, provider state, and human-audit exports can be harmful or
sensitive. Keep them access-controlled and follow [SECURITY.md](SECURITY.md).
Taxonomy mappings are informational crosswalks, not certifications.

Apache-2.0; see [LICENSE](LICENSE).
