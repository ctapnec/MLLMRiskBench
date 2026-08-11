# Chapter V experiments

Experiments are pending. Use [PROTOCOL.md](PROTOCOL.md) for the estimands and
validity rules, then execute [RUN_AND_RETURN.md](RUN_AND_RETURN.md). A dry run,
partial artifact family, placeholder model ID, or preliminary analysis is not a
measured thesis result.

The maintained execution contract is Runner `ura-runner/2.3` with unified
schema `1.3`; older artifacts are not mixed into this workflow.

## Minimal lifecycle

1. Install `.[dev,analysis,api]`, run the offline suite and synthetic smoke test.
2. Place real releases at `URA_<CORPUS>_PATH`; approve media roots.
3. Create one content-addressed, exhaustive
   `ura-cluster-partition/1.2`. It records portable source locators and exact
   per-policy pilot/main counts; both minimums default to two clusters. Loading
   recomputes the exact scoped-seed assignment from the complete cluster
   inventory.
4. Create and SHA-256-bind the provider retention/data-use approval for every
   exact hosted target and LLM judge.
5. Run each intended grid's exact arguments first through
   `python -m experiments.rig_check`; approve the printed policy-stratum counts
   and conservative target/judge/HTTP upper bounds before calls.
6. Under `runs/pilot/`, run a replay child over StrongREJECT+MM-SafetyBench+
   MOSSBench and a StrongREJECT-only Crescendo child. Feed the replay child's
   content-addressed modality proof to the Crescendo child; do not duplicate
   replay cells.
7. Generate one `pilot_analysis` artifact per planned hypothesis; freeze SESOI,
   required cluster count, endpoint role, exact source-policy token, complete
   Holm family, and human-audit design in the confirmatory plan. StrongREJECT is
   the primary model endpoint; MM/MOSS common proxies occupy a separate
   secondary family. H4 is a primary two-hypothesis family with one replay-
   versus-Crescendo contrast per model. Pilots must be real, mock-free,
   integrity/grid/source-valid and exclusion-free, and their normalized
   analysis design, including the realized target and judge snapshots, must
   match the main facet exactly.
   Use `confirmatory-plan.template.json` as the reviewable three-family,
   ten-hypothesis starting point and replace every `REPLACE_*` sentinel before
   hashing it. The template also byte-binds the checked-in
   `evaluation-policy.json`; its repository-relative path, byte count, SHA-256,
   policy ID and version are verified before any analysis runs.
8. Repeat the two-child layout under `runs/main/` with the same partition and
   exact conditions.
9. Optionally emit a non-publishable preliminary analysis, prepare/rate/analyse
   the frozen whole-cluster human sample, then emit the final human-bound
   confirmatory artifact.
10. Render measured figures only from that final artifact.

The core CLIs are:

```bash
python -m experiments.cluster_partition --help
python -m experiments.rig_check --help
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
benign text+image data on both targets. Coverage binds the exact delivered
combination; input-blocked and setup-only attempts do not count. The completed
replay grid can supply suite-wide image coverage to the exact target/defense-
matched StrongREJECT-only Crescendo child through
`ura-modality-coverage-proof/1.0`. Audio and video are unavailable on both study
targets, not text fallbacks.

MM-SafetyBench common ASR is a secondary URA proxy; its official scenario-aware
evaluator is not executed. MOSSBench common FRR is also secondary; its official
image-conditioned GPT-4 refusal evaluator is not executed. Keep both distinctions
in every table and claim. Because MM-SafetyBench spans six source policies, all
matrix commands containing MM/MOSS also group by
`source_policy_id,source_policy_version`.

StrongREJECT is the official 313-row, six-category, 313-unique-prompt CSV at
commit `f7cad6c17e624e21d8df2278e918ae1dddb4cb56`, normalized SHA-256
`4dd70357e4ff8b5d0ba5ebafecab5d6dd5633ce8046e3dd1c8bd93e64de44381`.
The maintained score is explicitly StrongREJECT-style; it is not a claim that
the upstream official evaluator ran.

## Real-run invariants

- Real non-synthetic scored runs require
  `--partition-plan/--partition-sha256/--partition-role` together and
  `--limit 0`. A partition binds the full converted release and exact source
  clusters. StrongREJECT, MM-SafetyBench and MOSSBench enforce pinned official
  release identities. A child may select a corpus subset from the same complete
  plan; it may not introduce another corpus. The loader recomputes the declared
  SHA-256-scoped-seed role assignment and rejects membership drift.
- Hosted calls require the content-addressed provider approval. Fable's covered-
  model retention and the effective OpenAI organization controls must be
  explicitly accepted; `store=false` does not mean zero provider retention.
- Set finite matrix-wide call, transport-attempt, and wall-clock ceilings.
  Preserve the durable budget/circuit/lock artifacts and resume from the same
  directory. `rig_check` rejects a ceiling below its conservative complete-grid
  projection. Reset a circuit only after fixing its cause.
- `--limit N` counts unique prompt/intent clusters and keeps every row in each
  selected cluster. It is for diagnostics when no measured partition is in use;
  it is not a row count.
- Optional local config is keyed by each exact `--local` spec and uses exactly
  one immutable `revision` or `digest`, plus `modalities`.
- Local media artifacts use `@media-root/<index>/<relative-path>`; preserve the
  configured root order and relative layout on resume or another machine.
- Missing/failed/unsupported/undefined is never rewritten as zero.

Transfer analysis is conditional and descriptive: set a prespecified
`--minimum-unique-clusters`, report equal-cluster rates/dispersion/bootstrap CI,
and keep it outside Holm. It has no pilot, SESOI, power gate or p-value.

For powered rate differences, freeze SESOI in `(0,1]` and calculate required
clusters with the complete frozen `family_size`. Sizing uses
`alpha / family_size` and also enforces the exact two-sided sign-flip resolution
`2 / 2^n <= alpha / family_size`. Every confirmatory contrast must state
`"assume_exchangeable": true`; otherwise it is descriptive, not a confirmatory
p-value.

Freeze `human_audit.validity_gate` with at least two shared clusters per required
cell and a prospective endpoint-agreement threshold (`0.80` is recommended).
The selector guarantees that support before export. Human uncertainty uses the
plan's exact alpha, resample count, and seed, and the audit content-addresses the
completed labels CSV. Failure in any required arm makes the audit/final artifact
non-publishable. Measured rendering then emits
`fig-v-asr-by-model.png` (one StrongREJECT model point),
`fig-v-policy-proxies.png` (six MM ASR plus one MOSS FRR point), and
`fig-v-adaptivity.png` (two H4 points).

## Artifacts

Retain the entire run tree: grid, budget, circuit and modality summaries;
attempt/response/judgment/trail/result JSONL; manifests; checkpoints;
completion/error records; partition, provider approval, pilot artifacts,
confirmatory plan, human sample/labels/audit, final analysis, figure provenance,
logs, environment freeze, commit, and run note. Treat provider continuation
state and human-audit exports as sensitive.

Mythos remains literature and a future authorized replication target only; it
must not appear as an executed condition.
