# Chapter V experiments

Experiments are pending. Use [PROTOCOL.md](PROTOCOL.md) for the estimands and
validity rules, then execute [RUN_AND_RETURN.md](RUN_AND_RETURN.md). A dry run,
partial artifact family, placeholder model ID, or preliminary analysis is not a
measured thesis result.

The maintained execution contract is Runner `ura-runner/2.2` with unified
schema `1.2`; older artifacts are not mixed into this workflow.

## Minimal lifecycle

1. Install `.[dev,analysis,api]`, run the offline suite and synthetic smoke test.
2. Place real releases at `URA_<CORPUS>_PATH`; approve media roots.
3. Create one content-addressed, exhaustive pilot/main cluster partition.
4. Create and SHA-256-bind the provider retention/data-use approval for every
   exact hosted target and LLM judge.
5. Run the `pilot` partition with finite durable call/HTTP/deadline ceilings.
6. Generate one `pilot_analysis` artifact per planned hypothesis; freeze SESOI,
   required cluster count, exact source-policy token, complete Holm family, and
   human-audit design in the confirmatory plan.
7. Run the `main` partition with the same partition and exact conditions.
8. Optionally emit a non-publishable preliminary analysis, prepare/rate/analyse
   the frozen whole-cluster human sample, then emit the final human-bound
   confirmatory artifact.
9. Render measured figures only from that final artifact.

The core CLIs are:

```bash
python -m experiments.cluster_partition --help
python experiments/run_matrix.py --help
python -m experiments.pilot_analysis --help
python -m experiments.confirmatory_analysis --help
python -m experiments.human_audit --help
python -m experiments.figures --help
```

## Planned target and modality scope

The primary target strings are:

```text
anthropic-fable:claude-fable-5;effort=high;max_tokens=25000
openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns
```

Both adapters currently declare text and image only. The main study must execute
StrongREJECT text plus complete MM-SafetyBench harmful text+image and MOSSBench
benign text+image data on both targets. Pre-call and post-run modality coverage
artifacts enforce this. Audio and video are explicit unavailable combinations,
not text fallbacks.

MM-SafetyBench common ASR is a secondary URA proxy; its official scenario-aware
evaluator is not executed. MOSSBench common FRR is also secondary; its official
image-conditioned GPT-4 refusal evaluator is not executed. Keep both distinctions
in every table and claim. Because MM-SafetyBench spans six source policies, all
matrix commands containing MM/MOSS also group by
`source_policy_id,source_policy_version`.

## Real-run invariants

- Real non-synthetic scored runs require
  `--partition-plan/--partition-sha256/--partition-role` together and
  `--limit 0`. A partition binds the full converted release and exact source
  clusters. MM-SafetyBench and MOSSBench also enforce pinned official release
  identities.
- Hosted calls require the content-addressed provider approval. Fable's covered-
  model retention and the effective OpenAI organization controls must be
  explicitly accepted; `store=false` does not mean zero provider retention.
- Set finite matrix-wide call, transport-attempt, and wall-clock ceilings.
  Preserve the durable budget/circuit/lock artifacts and resume from the same
  directory. Reset a circuit only after fixing its cause.
- `--limit N` counts unique prompt/intent clusters and keeps every row in each
  selected cluster. It is for diagnostics when no measured partition is in use;
  it is not a row count.
- Optional local config is keyed by each exact `--local` spec and uses exactly
  one immutable `revision` or `digest`, plus `modalities`.
- Missing/failed/unsupported/undefined is never rewritten as zero.

## Artifacts

Retain the entire run tree: grid, budget, circuit and modality summaries;
attempt/response/judgment/trail/result JSONL; manifests; checkpoints;
completion/error records; partition, provider approval, pilot artifacts,
confirmatory plan, human sample/labels/audit, final analysis, figure provenance,
logs, environment freeze, commit, and run note. Treat provider continuation
state and human-audit exports as sensitive.

Mythos remains literature and a future authorized replication target only; it
must not appear as an executed condition.
