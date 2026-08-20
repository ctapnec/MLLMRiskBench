# distro/ - rig installer

`install.sh` is the single, reproducible installer that stands up the whole
URA-Bench measured-campaign environment on a fresh rig. It replaces the ad-hoc
pile of operator scripts (`acquire_sources`, `fix_acquire`, `bipia_build`,
`*_export`, `bind_locators`) with one idempotent script.

Everything lands under `$URA_DATA` (default `/data/ura-work`, the big storage),
never the home partition or the tracked tree.

## Quick start

```bash
cp distro/.env.example ~/.ura_secrets     # then fill in HF_TOKEN and provider keys
distro/install.sh all                     # deps + every source + aggregator corpora + locators
distro/install.sh console                 # launch the console in tmux on :8642
```

## Phases

| phase | what it does |
|---|---|
| `deps` | editable install into `.venv` with the `dev,analysis,api,guardrail,local-vllm` extras |
| `clones` | pinned upstream git snapshots (StrongREJECT, HarmBench, BIPIA, ...) |
| `hf` | pinned Hugging Face dataset releases (AgentHarm, JBB, MLLMGuard, VLSBench, Video-SafetyBench, JALMBench, ...) |
| `archives` | separately-distributed media (MM-SafetyBench images, GPTGeoChat, SIUO) + JALMBench/VLSBench parquet exports |
| `bipia` | build the BIPIA qa/abstract sets from their external XSum/NewsQA bases |
| `aggregators` | fetch the aggregator corpora - SALAD-Bench, AIR-Bench 2024, XSTest, SimpleSafetyTests, DecodingTrust (stereotype), HoliSafe (multimodal, gated) - via `experiments.export_aggregators` |
| `locators` | write every `URA_*_PATH` binding into `~/.ura_campaign_env`, register the aggregator arms in `experiments/source-instances.json`, and print an existence report |
| `runtimes` | install the isolated third-party framework runtimes under the strict lock |
| `console` | (re)launch the rig console in a persistent tmux session on `127.0.0.1:8642` |

Run a subset by naming phases: `distro/install.sh clones hf aggregators locators`.

## Secrets

Provider API keys and `HF_TOKEN` live only in `~/.ura_secrets` (sourced by the
installer), never in the repo. `distro/.env.example` is the template.

## Deploy / re-pin

The installer sets up the environment; deploying a specific tracked commit to the
console (project-revision receipt + clean-suite gate + console restart) is still
done by the rig's `repin_web002.sh <commit>` re-pin flow described in
`experiments/RUN_AND_RETURN.md`.
