# All-local test campaign plan: every corpus arm, every framework runtime, free models only

Status: plan, written 20 August 2026 after the readiness audit of the big rig
(Debian, 2x RTX 4090 24,564 MiB, 125 GiB RAM, /mnt/stor 7.1 TB free). It is an
operating plan for the rig, not thesis evidence. It complements, and never
replaces, the operator runbook [`RUN_AND_RETURN.md`](RUN_AND_RETURN.md): every
command below is a runbook command (section numbers in brackets) restricted to
local, unpaid resources. Nothing in this plan makes a hosted-provider call.

Goal: exercise and, where the admission gates allow, measure the complete
portfolio without spending provider budget:

- all 45 logical corpus arms of the 25 converter families (28 common-metric,
  2 source-classification, 15 conversion-only);
- all 15 isolated framework runtimes and all 20 attacker dispositions, plus the
  nine source-native engines;
- only free targets and judges: local vLLM checkpoints, locally pulled Ollama
  models, the deterministic rules judge and a locally served guardrail classifier.

Evidence boundary. Lanes that pass the normal measured admission (project
revision receipt, source-conformance receipt, local transport attestation,
no-call projection, canary, caps) produce ordinary measured Level-1/Level-2
evidence for the local tier of Chapter V (RQ1, RQ3, RQ4a, RQ4b local parts).
Everything else (dry runs, installer receipts, engineering campaigns, one-case
native canaries) is engineering diagnostics and stays outside `runs/thesis`.
Hosted-only constructs stay `N/A` here: the focal Fable/Sol pair (RQ2), audio
and video lanes (the local vLLM/Ollama renderers are text and image only), the
hosted LLM-judge stage, and any native engine that cannot be pointed at a local
endpoint.

## 0. Readiness snapshot (20 August 2026) and blockers

| Surface | State found | Consequence |
|---|---|---|
| Code pin | rig and workstation at the same Project commit; clean-env suite green on both | re-pin to the post-fix-wave commit with `distro/repin.sh` before anything else |
| Corpora | 44/45 locators resolve; `bipia_test_qa` missing (licensed NewsQA) | `bipia_test_qa` stays blocked/N/A |
| Source receipt | historical 26-arm receipt bound; 19 arms (6 aggregator + 13 conversion-only) have no entry | a fresh 45-arm receipt is required before any measured lane (Phase 2) |
| Framework runtimes | 1/15 installed under the lock (PyRIT); legacy pre-lock venvs exist but are not installer-managed | install and verify the other 14 (Phase 1, ~65 GiB, 3-6 h) |
| Local models | Qwen3-VL-8B, LLaVA-1.6 base and GraySwan RR only in a legacy HF hub; sealed store absent; no Llama Guard | sealed acquisition for 3 targets + 2 guards (Phase 3, ~80 GB) |
| Ollama | daemon owned by the console; three small rwkv-7 models | usable as free targets only after a local transport attestation |
| Main venv | contains pyrit 0.14.0, spikee 0.9.1, datasets 4.8.4 (isolation policy violation) | remove in Phase 0 |
| Temp | `/tmp/pytest-of-ura` leftovers (~850 MB) | clear before the re-pin gate |

Operator-only gates (cannot be delegated): license/access decisions for the
six aggregator sources in the new receipt; Hugging Face gated-model access and
`HF_TOKEN` for Llama Guard; the ethics/consent determination before any human
audit; any future paid call (none planned here).

## 1. Phase 0: hygiene and pin (about 1 hour)

1. Bundle transport and re-pin [17, 18; `distro/README.md`]: locally
   `git bundle create web002.bundle main`, `scp` it to `ura-rig:~/web002.bundle`
   together with the `distro/repin.sh` of the commit being deployed
   (`scp distro/repin.sh ura-rig:~/repin.sh`; the in-tree copy on the rig is
   the currently pinned commit's version), then on the rig
   `bash ~/repin.sh <40-hex-commit>`. The
   script kills stray `run_matrix`/`rig_web` processes, clears
   `/tmp/pytest-of-ura`, runs the clean-env full suite (admission condition),
   refreshes the vLLM roster, writes and validates the project-revision receipt,
   rebinds `~/.ura_campaign_env`, revalidates the bound source receipt and
   restarts the console on `127.0.0.1:8642`.
2. Main-venv isolation: `~/MLLMRiskBench/.venv/bin/python -m pip uninstall -y
   pyrit spikee datasets jsonlines` (they were one-time build tools), then
   `pip check` and the clean-env suite again. No other package changes.
3. Confirm the console dashboard shows the new pin, and that Build -> Runtimes
   lists the 15 lock entries with their current status.

Gate 0: suite green on the rig at the new pin; receipt valid; console 200.

## 2. Phase 1: all 15 framework runtimes (3-6 hours, mostly unattended)

Runbook 12.2 and 14.1 are the authoritative commands. With the lock's env-root
and state-root conventions (`URA_FRAMEWORK_ENVS=$URA_WORK/framework-venvs`,
`URA_FRAMEWORK_STATE=$URA_WORK/runs/engineering/framework-runtime-<lock-id12>`,
`URA_FRAMEWORK_PYTHON` = the uv CPython 3.12.13 base interpreter):

```bash
python -m experiments.framework_runtime_installer plan    --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE"
python -m experiments.framework_runtime_installer install --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
# wait for the named tmux session (ura_wait_session), resume after any interruption, then:
python -m experiments.framework_runtime_installer verify  --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
```

Run one installer session per framework with `--only <name>`, tolerating a
failure and continuing, rather than a single session for all fifteen. The
installer is fail-closed and sequential, so one framework that cannot build
stops the whole session and hides every later defect: on 20 August a single
failing smoke blocked the twelve frameworks queued behind it, and a second,
unrelated build defect only became visible once the installs were driven one at
a time. Observed per-framework times on the rig range from about a minute
(deepteam, spikee) to roughly half an hour (h4rm3l, nanogcg); the pip cache
under `~/.cache/pip` is persistent, so a later reinstall after a lock change is
substantially faster than the first pass. The console equivalent is Build -> Runtimes (Install / Resume /
Verify per row); use it for at least one batch so that the CLI and UI paths are
both exercised. Disk: about 65 GiB under `$URA_FRAMEWORK_ENVS`. The Node 24.16.0
runtime for Promptfoo is downloaded and signature-verified by the installer.

Then materialize the private engine runtime configuration for the four
persistent-worker bridges [12.2]:

```bash
python -m experiments.engine_runtime_config --runtime pyrit=URA_PYRIT_ENV --runtime deepteam=URA_DEEPTEAM_ENV \
  --runtime h4rm3l=URA_H4RM3L_ENV --runtime spikee=URA_SPIKEE_ENV --out "$URA_WORK/state/engine-runtime-config.json"
# create-only ura-engine-runtime-config/1; each URA_*_ENV names the verified runtime alias from ura_runtime_alias
```

Gate 1: `verify` reports all 15 passed (content seals, smoke) and Build ->
Runtimes shows 15 verified rows; a `run_matrix --dry-run --corpora synth
--exclude-tool-conditioned --attackers pyrit --engine-runtime-config ...` lane
succeeds for each of pyrit, deepteam, h4rm3l, spikee (sealed worker opening and
closing seals present in the manifest).

## 3. Phase 2: source admission for all 45 arms (2-4 hours plus observation runs)

1. Unset the bound historical receipt variables (`URA_SOURCE_CONFORMANCE_MANIFEST`,
   `URA_SOURCE_CONFORMANCE_SHA256`) in the working shell [4.1 note].
2. Scaffold a fresh receipt for all 45 arms:
   `python -m experiments.source_conformance --scaffold --source-config
   experiments/source-instances.json ...` [4.1], then fill every `OPERATOR_TODO`:
   observed release/split, declared file hashes, reconciled discovered/accepted/
   rejected counts, the license/access decision (operator), and a reviewer-
   attributed semantic mapping review per arm. The 19 previously approved sources
   keep their recorded decisions; the six aggregator sources (SALAD-Bench,
   AIR-Bench 2024, XSTest, SimpleSafetyTests, HoliSafe, DecodingTrust stereotype)
   need new operator decisions; `bipia_test_qa` is recorded as blocked.
3. Retain the VLSBench and JALMBench exporter summaries under
   `runs/thesis/source-export-summaries/` and point the receipt component
   variables at them [4, RA-025].
4. Validate, hash and bind the new receipt (`--manifest --sha256`), then run one
   bounded offline observation per arm (MockTarget, no model call):
   `run_matrix --dry-run --corpora <arm> --attackers replay --judges rules,llm
   --limit 2 --sample-seed 0 --out runs/thesis/source-review-observation/<arm>`
   (the dry-run judge is the mock stage, so `rules,llm` is the documented dry
   cascade; a rules-only dry lane fails closed when the rule stage abstains; add
   `--exclude-tool-conditioned` for tool-conditioned arms). Expect 44 clean
   observations; `bipia_test_qa` blocked.

Gate 2: `source_conformance` validates the new receipt with 44 admitted arms
(or 43 plus explicit blocks); the console source catalogue shows the same
dispositions (45 arms, 28/2/15 partition, tool arms fail-closed, approximate
opt-in badges only where expected).

## 4. Phase 3: free models (1-3 hours of downloads)

Sealed acquisition [6.1] through Build -> `Plan & acquire` (preferred) or the
CLI plan -> acquire -> run chain, for:

| Role | Identity | Size | Placement |
|---|---|---|---|
| target | `vllm:Qwen/Qwen3-VL-8B-Instruct` @ exact revision (text+image) | ~17 GB | GPU 0, BF16, TP 1, max_model_len 12288 |
| target | `vllm:llava-hf/llava-v1.6-mistral-7b-hf` @ exact revision (text+image) | ~15 GB | GPU 0 |
| target | `vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR` @ exact revision (same-base defense pair) | ~28 GB | GPU 0 |
| scoring guard | `meta-llama/Llama-Guard-3-8B` (gated; HF_TOKEN) | ~16 GB | GPU 1 (`--guardrail-device cuda:1`) |
| defense guard (optional, hosted lanes only in the runbook; here used for the local text-only defense contrast if VRAM permits) | `meta-llama/Llama-Guard-3-1B` | ~3 GB | GPU 1 |

The legacy hub bytes under `/mnt/stor/data/ura/hf/post-release-.../hub` may be
reused as the transport cache only through the sealed controller; no manual
copies into the store. Ollama rows (the three rwkv-7 models, plus any further
`ollama pull` made from the console) become selectable once the live roster
shows them with exact digests.

Local fit: one local target per process; GPU 0 target, GPU 1 scoring guard; the
two-card 70B profile (4-bit, TP 2) is admitted by the fit calculator but is not
part of this plan.

The CLI chain, verified on the rig, is plan then acquire. Two details are easy
to get wrong and both fail closed with an exact message:

```bash
# 1. Derive the plan. Pair --model-acquisition-plan-only with --preflight-only:
#    plan derivation constructs no target, so it is not measured execution and
#    has no live attestation to consume, but without the pairing the parser
#    applies the measured-execution admission and asks for one. The plan
#    directory must also be an already-resolved absolute path: ~/MLLMRiskBench/runs
#    is a symlink into $URA_WORK, so pass the $URA_WORK path itself.
PLAN_DIR="$URA_WORK/runs/thesis/acquisition/<target-label>"
python -m experiments.run_matrix --model-acquisition-plan-only --preflight-only   --model-acquisition-plan-dir "$PLAN_DIR"   --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG"   --attackers replay --judges rules --corpora xstest_full   --source-config experiments/source-instances.json   --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1   --out "$URA_WORK/runs/thesis/acquisition/<target-label>-run"
# stdout carries plan_id and plan_sha256; the plan file lands in $PLAN_DIR.

# 2. Acquire against that exact plan, bounded by size, free space and a deadline.
python -m experiments.model_acquire --plan "$PLAN_DIR/<plan_id>.plan.json"   --plan-sha256 "$PLAN_SHA256" --store "$URA_MODEL_STORE"   --receipts-dir "$URA_WORK/runs/thesis/acquisition/receipts"   --min-free-bytes $((200 * 1024 ** 3)) --deadline-seconds 14400
```

A gated identity (both Llama Guard sizes) needs `HF_TOKEN` in the environment
for the acquisition step only; source `~/.ura_env` for that call and never log
it.

**The acquisition plan binds the request envelope, not just the model set.** A
plan derived for one set of run arguments will not admit a run with different
ones: changing `--limit`, or adding call caps or a deadline, changes the bound
envelope and admission fails with `acquisition plan resources or immutable
selection bindings differ`. So this is not one acquisition serving every lane.
The working procedure, verified on the rig, is per lane:

1. derive the plan with **the exact arguments that lane will run with**,
2. acquire against that plan, which is a no-op import once the store holds the
   snapshot, and reports `downloaded_bytes: 0`,
3. run the lane with those same arguments plus the plan, receipt and store.

Put **every** run argument in one shell array and reuse it verbatim for all
three steps. That specifically includes `--max-total-target-calls`,
`--max-total-judge-calls` and `--deadline-seconds`: they look like execution
bounds rather than selection, but they are part of the bound envelope, and
adding them at run time after deriving the plan without them fails admission.
This exact mistake was made once while executing this plan, so it is worth
stating plainly rather than leaving to care.

```bash
LANE=(--local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG"
      --attackers replay --judges rules --corpora "$ARM"
      --source-config experiments/source-instances.json
      --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1
      --max-total-target-calls 2 --max-total-judge-calls 2 --deadline-seconds 3600
      --out "$OUT_ROOT")
# derive with "${LANE[@]}", acquire, then run with "${LANE[@]}" plus the
# plan/receipt/store locators. Never add an argument to only one of the steps.
```

The cost of the extra plan and receipt per lane is negligible, because
acquisition re-imports nothing; the benefit is that each receipt states exactly
which models that exact request needed.

Gate 3: acquisition receipts present and bound; `python -m experiments.local_targets`
shows the three vLLM rows as compatible with an exact revision/digest; the
console Build model picker shows the same rows under Local vLLM and the Ollama
rows under Local Ollama.

Status, 21 August 2026: **met for the three targets.** Each was sealed with
`downloaded_bytes: 0`, because the rig already held all three snapshots at
exactly the pinned commits in a legacy Hugging Face hub, which was staged as
the controller's transport cache by hard link. That costs no disk, leaves the
legacy hub intact and is not a manual copy into the managed store: promotion is
gated on `seal_snapshot`, which proves the complete official sibling set and
every Git/LFS content identity against the upstream manifest for the exact
commit before anything is promoted. The three receipts bind 16, 17 and 26 files
respectively, matching the sibling counts verified upstream before acquisition.
The store and each receipt with its digest are bound in `~/.ura_campaign_env`
as `URA_MODEL_STORE` and `URA_ACQ_RECEIPT_*`. Both Llama Guard sizes are gated
and are not in the legacy hub, so they are genuine downloads; their pinned
commits are `7327bd9f6efbbe6101dc6cc4736302b3cbb6e425` (3-8B) and
`acf7aafa60f0410f8f42b1fa35e077d705892029` (3-1B).

## 5. Phase 4: local transport attestations (about 1 hour)

For every local target x modality combination that a lane will use, run the
bounded attestation probe and produce its receipt [8]. The execution scope is
one non-secret label, declared once and reused verbatim by every probe, receipt
and measured grid of this campaign, because admission matches the probe's scope
against the grid's. It is bound in `~/.ura_campaign_env` beside the other
locators so no phase can drift from it:

```bash
export SCOPE="${URA_EXECUTION_SCOPE_ID:?bind it in ~/.ura_campaign_env first}"
# bigrigsys-local-vllm: this rig, on-rig vLLM, no provider account involved.

python -m experiments.run_matrix --attestation-probe --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG" \
  --attackers replay --judges rules --corpora <one text arm> --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 --execution-scope-id "$SCOPE" ... --out runs/thesis/attestation/<target>-text
python -m experiments.live_attestation --probe-root runs/thesis/attestation/<target>-text \
  --execution-scope-id "$SCOPE" --out runs/thesis/attestation/   # derives and hashes the ura-live-attestation/2 receipt
```

Repeat with a text+image arm (for example `mossbench_official`) for the
image combination, and once per Ollama target for text. These are free (local
GPU only). Receipts are content-addressed and expire per the recorded max-age
policy, so schedule them immediately before the measured lanes.

Gate 4: one valid receipt per (target, modality combination) that Phase 6 uses.

## 6. Phase 5: no-call projections and one-cluster canaries (2-4 hours)

For each planned measured lane: `rig_check` with the exact lane arguments
(projection, policy-stratum counts, guard load) [9], then one
`run_matrix --diagnostic-canary` with `--limit 1` on one arm [9.1], then
`lane_canary`. Record approved call/time/storage caps from the projection
before any measured lane. Judges for local-target lanes are `rules,guardrail`
(no hosted LLM judge; a local LLM judge cannot share a process with a local
target). Every lane uses the Level-2-compatible grouping
`--group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version`
(the CLI default; the Build field defaults to it; the Level-2 export rejects
narrower groupings) and `--limit 0` (full corpus; admitted only because every
target and judge is local; the Build field now emits it explicitly).

Gate 5: projections and canaries retained under `runs/thesis/preflight` and
`runs/thesis/diagnostics`; caps recorded in `runs/thesis/RUNNOTE.md`.

## 7. Phase 6: measured local lanes (GPU days; sized by the canaries)

Row inventory (from the 26-arm receipt plus the aggregator exports): common
text arms about 35,900 rows (SALAD-Bench base 21,318; AIR-Bench 5,694;
DecodingTrust 3,456; CyberSecEval 3,416; AdvBench 520; XSTest 450; HarmBench
400; StrongREJECT 313; JailbreakBench 200; SimpleSafetyTests 100), common image
arms about 9,900 rows (HoliSafe 4,031; VLSBench 2,240; MM-SafetyBench 1,680;
MLLMGuard safety dimensions 548; FigStep 500; JailBreakV image-backed 360;
MOSSBench 300; SIUO 167; HarmBench multimodal 110), classification arms 1,071
rows (R-Judge 571; GPTGeoChat 500). With one seed this is roughly 47k target
calls per local model; the canaries (not this paragraph) determine the
throughput, so run seed 0 first and add seed 1 only if the observed rate makes
it affordable.

| Tier | Lane | Targets | Attackers | Judges | Output root |
|---|---|---|---|---|---|
| 1 [10.1] | static text, all common text arms incl. the six aggregator arms | Qwen3-VL-8B; LLaVA base; LLaVA RR; optionally rwkv via Ollama | replay | rules,guardrail | `runs/thesis/runner/local-<model>-text` |
| 1 [10.2] | static image, all common image arms | Qwen3-VL-8B; LLaVA base; LLaVA RR | replay | rules,guardrail | `runs/thesis/runner/local-<model>-image` |
| 1 [10.3] | audio/video | none (no local audio/video renderer) | - | - | structural `N/A` |

Conversion cost, measured on the rig (21 August 2026): the audio arm converts its
complete manifest before any sampling, so a bounded `--limit 2` JALMBench
observation took 1,218 s (20.3 minutes) while it read all 220,240 rows and hashed
the referenced audio. This is the price of binding the full-corpus digest and the
complete cluster inventory into the sampling audit, not a stall; budget it once per
JALMBench invocation. Every other arm observes in under 15 s.
| 2 [11] | R-Judge and GPTGeoChat classification | same local roster | replay | rules (not queried; source parser authoritative) | `runs/thesis/runner/rjudge`, `.../gptgeochat` |
| 3 [12.1] | live Crescendo (response-conditioned) | Qwen3-VL-8B | crescendo | rules,guardrail | `runs/thesis/runner/crescendo-<model>` |
| 3 [12.2] | Runner-safe bridges | Qwen3-VL-8B | pyrit, deepteam, h4rm3l, spikee (sealed workers), nanogcg (verified precomputed suffixes only), purplellama (CyberSecEval arms), ideator (seed pairs) | rules,guardrail | `runs/thesis/runner/bridge-<attacker>` |
| 3 [12.2] | prepared attacks | Qwen3-VL-8B | harmbench prepare (local source model) + replay; t3mp3st stays blocked-unpinned | rules,guardrail | `runs/thesis/runner/harmbench-replay` |
| 4 [13] | same-base defense contrast | LLaVA base vs LLaVA RR (identical clusters, bytes, settings, judges) | replay | rules,guardrail | `runs/thesis/runner/local-llava-{base,rr}-*` |
| 4 [13] | guard defense (text-only) | Qwen3-VL-8B with `--defense both --defense-guard guardrail` (1B guard on GPU 1 alongside the 8B scoring guard only if VRAM allows; otherwise N/A) | replay | rules,guardrail | `runs/thesis/runner/defense-local` |
| 5 [14] | nine native engines | local OpenAI-compatible endpoint (`vllm serve` of Qwen3-VL-8B or the Ollama API) where the engine supports it | engine-native | engine-native | `$URA_WORK/runs/engineering/ura-native-*`, then `native_import` |

Native engines, free configuration (run one-case canaries first [14.2]; each
through `ura_native_run` with `URA_NATIVE_TARGET_CALL_CAP` set):

| Engine | Free route | Expectation |
|---|---|---|
| Garak | `--target_type openai.OpenAICompatible` against the local vLLM server | runs |
| Promptfoo | ollama/openai-compatible providers for target, attacker and grader | runs; grader quality limited |
| FuzzyAI | ollama provider (`-m ollama/<tag>`) | runs |
| Petri | Inspect roles on openai-compatible/vllm providers | runs; auditor quality limited |
| AgentDojo | openai-compatible base URL with a tool-calling local model | only if the local model supports tool calls; otherwise N/A |
| ASB | openai-compatible config | as AgentDojo |
| AutoDAN-Turbo | local HF attacker/target/scorer/summarizer/embedding models | heavy; feasible only with small models on two cards; otherwise N/A |
| EasyJailbreak | local HF models for attack/target/eval | feasible with 7B-8B models |
| Giskard | Python callable around the local endpoint | runs |

Import every complete native artifact family with `experiments.native_import`
[14.3]; record run/failed/unavailable/not-selected for all nine.

Gate 6: every measured lane completes or records an explicit error/partial
state; no lane runs outside `runs/thesis/runner`; caps never raised mid-lane.

## 8. Phase 7: read-only analysis (hours)

`level1_evidence` over `runs/thesis/runner` (every final eligibility plan),
`suite_summary`, `level2_report`, `judge_sensitivity`, `kappa`,
`transfer_matrix --attacker replay`, and the two free paired comparisons
[16]: LLaVA base vs RR on `mmsafety_official` (and each image arm), and
replay vs Crescendo within Qwen3-VL-8B. The Level-2 export keeps rules-only
and cascade (rules+guardrail) evaluator modes as separate compatibility keys.

## 9. Phase 8: human audit (free in money, requires raters and an ethics determination)

`human_audit --prepare` over the completed local cohort [15], rater
qualification set, two raters minimum, adjudication, then `--labels`; the
source-task classification audit separately. This is the only route to RQ5
judge validity for the local tier; it is optional for this plan's
software-coverage goal.

## 10. Console/CLI parity checks embedded in the campaign

Run each phase at least once through the console (Build -> Runtimes; Build
wizard for attestation probe, canary and measured lanes; Jobs for lifecycle;
Stats for per-job usage/coverage; Config editor for registries) and once
through the CLI, and confirm that the composed argument vectors (visible in the
Jobs record) equal the runbook vectors, including `--limit 0`, `--group`,
`--exclude-tool-conditioned` on synth/dry lanes, and the receipt environment
defaults on the Run page.

## 11. Schedule and effort (estimate, to be replaced by observed values)

| Phase | Wall time | Attended effort |
|---|---|---|
| 0 hygiene/pin | 1 h | 1 h |
| 1 runtimes | 3-6 h | 0.5 h |
| 2 receipt + observations | 3-5 h | 2-4 h (operator decisions) |
| 3 models | 1-3 h | 0.5 h |
| 4 attestations | 1 h | 0.5 h |
| 5 projections/canaries | 2-4 h | 2 h |
| 6 measured lanes | several GPU days (seed 0; ~47k calls per model plus guard calls) | periodic |
| 7 analysis | 2-4 h | 2 h |
| 8 human audit | rater-dependent | rater-dependent |

## 12. Records and ledger

Each phase writes its receipts, logs and summaries under `/data/ura-work`
(`runs/thesis/...` for admissible evidence, `runs/engineering/...` for
diagnostics) and appends one dated entry to the convergence ledger
(`Thesis-EN/Codex_Reaudit.md`) with the commit, gate results and any
operator decision. Retain the clean-env suite log and the repin output for the
pinned commit in `Thesis-EN/verification/<date>-local-campaign/RECORD.md`.
