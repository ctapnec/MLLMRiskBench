# distro/ - rig installer

`install.sh` is the single, reproducible installer that stands up the whole
URA-Bench measured-campaign environment on a fresh rig, start to end. It
replaces the ad-hoc pile of operator scripts (`acquire_sources`, `fix_acquire`,
`fix2_acquire`, `bipia_build`, `*_export`, `bind_locators`, `start_console`).

Everything lands under `$URA_DATA` (default `/data/ura-work`, the big storage),
never the home partition or the tracked tree. Idempotent: re-runs skip every
already-materialized source (skips are recorded OK in the step ledger).

## Quick start

```bash
cp distro/.env.example ~/.ura_secrets     # fill in HF_TOKEN and provider keys
distro/install.sh all                     # EVERYTHING: deps + every corpus +
                                          # ollama + runtimes + locators + console
```

`all` ends with a per-step OK/FAIL summary and a nonzero exit if any step
failed; logs live under `$URA_DATA/acquire-logs/`.

## Phases

| phase | what it does |
|---|---|
| `deps` | editable install into `.venv` with the `dev,analysis,api,guardrail,local-vllm` extras + `hf`/`gdown` CLI tools (verified present) |
| `clones` | pinned upstream git snapshots (StrongREJECT, HarmBench, BIPIA, ...); stale clones are repaired via fetch + re-checkout |
| `hf` | pinned Hugging Face dataset releases (AgentHarm, JBB, JailBreakV-28K, MLLMGuard, VLSBench, Video-SafetyBench, JALMBench) |
| `archives` | separately-distributed media: MM-SafetyBench images (Drive, stall-hardened), GPTGeoChat human split (MediaFire scrape), SIUO images (HF dataset repo), Video-SafetyBench extract, JailBreakV image-backed subset generation, JALMBench/VLSBench exports |
| `bipia` | build the BIPIA qa/abstract sets from their external XSum/NewsQA bases (NewsQA is licensed - obtain `$URA_UPSTREAM/newsqa-data` manually) |
| `aggregators` | fetch the aggregator corpora - SALAD-Bench, AIR-Bench 2024, XSTest, SimpleSafetyTests, DecodingTrust (stereotype), HoliSafe (multimodal, gated) - via `experiments.export_aggregators`, per-source skip when present |
| `ollama` | user-local ollama runtime under `~/.local/ollama` + `~/.local/bin/ollama` symlink (the console-owned daemon needs it on PATH) |
| `runtimes` | install the isolated third-party framework runtimes under the strict lock |
| `locators` | write every `URA_*_PATH` binding (incl. `URA_MEDIA_ROOTS`, `HF_HOME`, `PATH`) into `~/.ura_campaign_env`, register the aggregator arms in `experiments/source-instances.json`, print an existence report |
| `console` | (re)launch the rig console in tmux on `127.0.0.1:8642` with the FULL login env (profile + secrets + campaign env + `~/.local/bin` on PATH) |
| `summary` | per-step OK/FAIL report from the step ledger |

Run a subset by naming phases: `distro/install.sh clones hf aggregators locators`.

`all` = deps clones hf archives bipia aggregators ollama runtimes locators
console summary - the complete start-to-end installation.

## Secrets

Provider API keys and `HF_TOKEN` live only in `~/.ura_secrets` (sourced by the
installer; `~/.ura_env` is honored too for previously provisioned rigs), never
in the repo. `distro/.env.example` is the template and lists the full provider
roster the code reads (Anthropic, OpenAI, Gemini/Google, DeepSeek, Moonshot,
DashScope/Qwen, Zhipu/GLM, Ark/Doubao).

Gated HF datasets (AgentHarm, DecodingTrust, HoliSafe) additionally require the
operator's HF account to have accepted each dataset's terms.

## Deploy / re-pin

The installer sets up the environment; deploying a specific tracked commit to
the console (project-revision receipt + clean-suite gate + console restart) is
still done by the rig's `repin_web002.sh <commit>` re-pin flow described in
`experiments/RUN_AND_RETURN.md`.
