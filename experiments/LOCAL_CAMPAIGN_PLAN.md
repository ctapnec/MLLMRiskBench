# All-local test campaign plan: every corpus arm, every framework runtime, free models only

Status: plan, written 20 August 2026 after the readiness audit of the big rig
(Debian, 2x RTX 4090 24,564 MiB, 125 GiB RAM, /mnt/stor 7.1 TB free). It is an
operating plan for the rig, not thesis evidence. It complements, and never
replaces, the operator runbook [`RUN_AND_RETURN.md`](RUN_AND_RETURN.md): every
command below is a runbook command (section numbers in brackets) restricted to
local, unpaid resources. Nothing in this plan makes a hosted-provider call.
After Phase 7 seals the local inventory, the separate
[`HOSTED_CAMPAIGN_PLAN.md`](HOSTED_CAMPAIGN_PLAN.md) may evaluate API models
only on content-bound compatible subsets of inputs already used here and may
select retained local outputs for bounded Haiku re-adjudication. That follow-on
is not another local phase, cannot change any local selection or result, and
has independent provider-budget and transfer gates.
The forward runtime inventory was amended on 25 August 2026 to admit T3MP3ST
at an exact source commit, increasing the managed inventory from 15 to 16. The
dated readiness snapshot below remains a historical record of what was found on
20 August.

Goal: exercise and, where the admission gates allow, measure the complete
portfolio without spending provider budget:

- all 45 logical corpus arms of the 25 converter families (28 common-metric,
  2 source-classification, 15 conversion-only);
- all 16 isolated framework runtimes and all 20 attacker dispositions, plus the
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

Controller source and binding boundary. Reusable Phase 3-8 controller logic is
versioned under `experiments/local_campaign/templates/`, with its renderer,
verifier and package installer under `experiments/local_campaign/`. A controller
instance cannot be stored as authoritative source because it binds the commit
that contains the templates, deployed-revision receipt hashes, source receipt
hashes, run tags and rig paths. The renderer therefore writes those disposable,
commit-bound instances to the workstation `.campaign` control directory before
they are verified and transferred to the rig. `.campaign` is neither a Git
worktree nor an alternative source authority. Any reusable logic change goes to
the tracked templates first and is tested there; generated instances are never
edited as the implementation.

## 0. Readiness snapshot (20 August 2026) and blockers

| Surface | State found | Consequence |
|---|---|---|
| Code pin | rig and workstation at the same Project commit; clean-env suite green on both | re-pin to the post-fix-wave commit with `distro/repin.sh` before anything else |
| Corpora | 44/45 locators resolve; `bipia_test_qa` missing (licensed NewsQA) | `bipia_test_qa` stays blocked/N/A |
| Source receipt | historical 26-arm receipt bound; 19 arms (6 aggregator + 13 conversion-only) have no entry | a fresh 45-arm receipt is required before any measured lane (Phase 2) |
| Framework runtimes | 1/15 installed under the lock (PyRIT); legacy pre-lock venvs exist but are not installer-managed | install and verify the other 14 (Phase 1, ~65 GiB, 3-6 h) |
| Local models | Qwen3-VL-8B, LLaVA-1.6 base and GraySwan RR only in a legacy HF hub; sealed store absent; no Llama Guard | sealed acquisition for 3 targets + 2 guards (Phase 3, ~80 GB) |
| Ollama | historical snapshot: daemon owned by the console and three small rwkv-7 models | later superseded by the exact current four-model roster; no RWKV model is scheduled prospectively |
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
2. Main-venv isolation: `distro/install.sh deps` removes only legacy duplicate
   `pyrit`, `spikee`, `datasets`, and `jsonlines` top-level installs, then runs
   `pip check`. PyRIT and Spikee remain in their locked framework stores; BIPIA's
   `datasets==2.14.7` builder lives in its own fully hashed, no-system-site-
   packages environment under `$URA_WORK/support-venvs`. No framework is
   discarded because of a main-environment conflict.
3. Confirm the console dashboard shows the new pin, and that Build -> Runtimes
   lists the 16 lock entries with their current status.

Gate 0: suite green on the rig at the new pin; receipt valid; console 200.

## 2. Phase 1: all 16 framework runtimes (3-6 hours, mostly unattended)

Runbook 12.2 and 14.1 are the authoritative commands. With the lock's env-root
and state-root conventions (`URA_FRAMEWORK_ENVS=$URA_WORK/framework-venvs`,
`URA_FRAMEWORK_STATE=$URA_WORK/runs/engineering/framework-runtime-<lock-id12>`,
`URA_FRAMEWORK_PYTHON` = the uv CPython 3.12.13 base interpreter):

```bash
distro/install.sh runtimes

# The equivalent manual unit verifies before any mutation:
python -m experiments.framework_runtime_installer verify --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
# Across an aggregate-lock change, an unchanged row may be adopted only from
# an explicit retained prior lock after exact row/global-pin and seal checks:
python -m experiments.framework_runtime_installer adopt --from-lock "$URA_FRAMEWORK_ADOPT_FROM_LOCK" --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
# Use resume only for a missing, interrupted, new or changed row, then verify:
python -m experiments.framework_runtime_installer resume --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
python -m experiments.framework_runtime_installer verify --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
```

Run one installer session per framework with `--only <name>`, tolerating a
failure and continuing, rather than a single session for all sixteen. Every row
is verified first. A passing current installation is left untouched; strict
adoption is explicit and applies only when the complete prior/current row and
execution-global pins are identical; installation/resume is reserved for a
genuinely missing, interrupted, new or changed row. The
installer is fail-closed and sequential, so one framework that cannot build
stops the whole session and hides every later defect: on 20 August a single
failing smoke blocked the twelve frameworks queued behind it, and a second,
unrelated build defect only became visible once the installs were driven one at
a time. Observed per-framework times on the rig range from about a minute
(deepteam, spikee) to roughly half an hour (h4rm3l, nanogcg); the pip cache
under `$URA_FRAMEWORK_ENVS/.cache/pip` and the npm cache under
`$URA_FRAMEWORK_ENVS/.cache/npm` are explicitly bound outside every sealed
store and persist despite each runtime's clean HOME. They affect transfer time,
not admission. The distro phase derives all 16 names from the validated lock,
continues after an isolated row failure, and returns an honest nonzero aggregate
after attempting the complete inventory. The console equivalent is Build -> Runtimes (Install / Resume /
Verify per row); use it for at least one batch so that the CLI and UI paths are
both exercised. Disk: about 65 GiB under `$URA_FRAMEWORK_ENVS`. The Node 24.16.0
runtime used by the separate Promptfoo and T3MP3ST Node stores is downloaded
and signature-verified by the installer. T3MP3ST is built from its exact source
checkout with `npm ci` against the bound upstream package lock.

Then materialize one private engine runtime configuration for each selected
persistent-worker bridge [12.2]. The campaign controllers create these files
under their private, campaign-tagged state root and bind each file by SHA-256 to
the one lane that consumes it:

```bash
export URA_LANE_ENGINE_CONFIG_ROOT="$URA_WORK/state/bridge-configs/<campaign-tag>"
test ! -e "$URA_LANE_ENGINE_CONFIG_ROOT" || exit 1
mkdir -m 700 -p "$URA_LANE_ENGINE_CONFIG_ROOT"
URA_LANE_ENGINE_STORE="$(ura_runtime_store pyrit)" || exit $?
export URA_LANE_ENGINE_PYTHON="$URA_LANE_ENGINE_STORE/bin/python"
[[ -x "$URA_LANE_ENGINE_PYTHON" ]] || exit 1
python -m experiments.engine_runtime_config \
  --runtime pyrit=URA_LANE_ENGINE_PYTHON \
  --out "$URA_LANE_ENGINE_CONFIG_ROOT/pyrit.json"
# Repeat only for a selected deepteam, h4rm3l or spikee lane.
# Each output is create-only ura-engine-runtime-config/1 and resolves into the
# already verified content-addressed store. No global combined config is needed.
```

Gate 1: `verify` reports all 16 passed (content seals, smoke) and Build ->
Runtimes shows 16 verified rows; a `run_matrix --dry-run --corpora synth
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
| target | `vllm:Qwen/Qwen3-VL-8B-Instruct` @ exact revision (text+image) | 16.34 GiB | GPU 0, BF16, TP 1, max_model_len 12288 |
| target | `vllm:llava-hf/llava-v1.6-mistral-7b-hf` @ exact revision (text+image) | 14.10 GiB | GPU 0 |
| target | `vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR` @ exact revision (same-base defense pair) | 27.59 GiB | GPU 0 |
| scoring guard | `meta-llama/Llama-Guard-3-8B` (gated; HF_TOKEN) | 29.93 GiB | GPU 1 (`--guardrail-device cuda:1`) |
| defense guard (optional, hosted lanes only in the runbook; here used for the local text-only defense contrast if VRAM permits) | `meta-llama/Llama-Guard-3-1B` | 5.59 GiB (6,005,361,738 sealed bytes) | GPU 1 |

The legacy hub bytes under `/mnt/stor/data/ura/hf/post-release-.../hub` may be
reused as the transport cache only through the sealed controller; no manual
copies into the store.

**These are complete-sibling-set sizes, not weight sizes.** The seal proves the
complete official sibling set for the exact commit, so acquisition fetches every
file in the revision, not only the ones the server loads. That is why the two
Llama Guard entries are roughly twice their servable weights: both Meta repos
ship an `original/` PyTorch checkpoint that vLLM never reads, 14.96 GiB of the
3-8B total and 2.79 GiB of the 3-1B total. Budget acquisition time and disk
against the figures above; the earlier "~16 GB" for the 3-8B was the weight size
and understated the transfer by nearly half. The current Ollama cohort is
Gemma 4 12B Instruct Q4_K_M, Ministral 3 14B Instruct 2512 Q4_K_M,
DeepSeek-R1 Distill Qwen 32B Q4_K_M, and GPT-OSS 20B in its native MXFP4
representation. A row becomes selectable only after the live roster
shows its exact digest and a load smoke succeeds. Before any local target enters
security projection, canary or measured execution, it must also pass the
transport-neutral `experiments.local_model_readiness` gate. The gate selects the
same ten benign questions deterministically from a fixed twenty-question bank
with seed 20260829 and requires at least five correct. The other five answers
may be incorrect or empty. For an image-capable target, it adds five
deterministic synthetic split-color images and requires at least two correct;
the other three may be incorrect or empty. This applies to the
three vLLM targets and all four Ollama targets. Guard and classifier checkpoints
instead retain their role-specific classifier smoke because free-form Q&A is not
their served interface. The readiness receipt is engineering admission evidence,
not a safety result. A failing target is retained as failed and receives no new
security calls. A recent, relevant, hardware-fitting replacement may then be
selected as a new exact model condition with its own pin, acquisition,
readiness receipt, projections and Gate amendment; it never inherits the failed
target's identity or artifacts. Multi-model Ollama acquisition uses
`python -m experiments.local_campaign.ollama_acquire` in a named tmux session.
The controller retains one canonical event ledger, skips models whose load smoke
already completed, and retries an interrupted `/api/pull` with 30-to-300-second
bounded backoff under a seven-day controller deadline. Socket, DNS, Ollama
internal-retry and mid-stream HTTP disconnects are retried inside the same tmux
controller. A stream that stays connected but reports no changed status or byte
count for 15 minutes is also closed and retried, and Ollama resumes retained
partial blobs. Relaunch the same command with `--resume` and the same absolute
`--out-dir` and model order only after a controller-process or host interruption;
a changed roster or terminal output root is refused. Non-network failures and
deadline expiry remain typed terminal failures rather than being restarted
blindly. Gemma 4 and Ministral 3 admit
text and image lanes; DeepSeek-R1 Distill and GPT-OSS admit text lanes only.
Every empty survey item remains in the receipt as `model_nonresponse`. Measured
campaign postprocessing likewise retains a typed model nonresponse as missing
response evidence and reports it through missingness and decision coverage; it
is never dropped or counted as a decided safety label. Level-1 judgment and
planning-stratum ledgers retain the count even when no estimate exists. Level-2
rows expose `judgments_missing_responses` when an estimate row exists, and
Stats labels both surfaces as missing responses.
The superseded RWKV tags have been removed from the live roster and from every
prospective task. Their immutable historical artifacts remain readable.

Local fit: one local target per process; GPU 0 target, GPU 1 scoring guard; the
two-card 70B profile (4-bit, TP 2) is admitted by the fit calculator but is not
part of this plan.

The CLI chain, verified on the rig, is plan then acquire. Two details are easy
to get wrong and both fail closed with an exact message:

```bash
# 1. Derive this preflight request's plan. --preflight-only is present because
#    the later consumer is a preflight, not because plan-only requires it.
#    A canary plan instead includes --diagnostic-canary and its exact live-
#    attestation arguments. A measured plan includes neither purpose flag and
#    includes its exact live-attestation arguments. The plan directory must be
#    an already-resolved absolute path: ~/MLLMRiskBench/runs is a symlink into
#    $URA_WORK, so pass the $URA_WORK path itself.
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
ones: changing `--limit`, adding call caps or a deadline, or changing the
execution purpose changes the bound envelope and admission fails with
`acquisition plan resources or immutable selection bindings differ`. A
preflight plan therefore cannot admit a diagnostic canary or measured run, and
a canary plan cannot admit the measured run. The working procedure, verified
on the rig, is per exact purpose-specific request:

1. derive the plan with **the exact arguments that lane will run with**,
2. acquire against that plan, which is a no-op import once the store holds the
   snapshot, and reports `downloaded_bytes: 0`,
3. run the lane with those same arguments plus the plan, receipt and store.

Put **every** run argument for that one request in one shell array and reuse it
verbatim for all three steps. Use separate arrays and separate plans for the
preflight projection, diagnostic canary and measured run. The preflight array
contains `--preflight-only`; the canary array contains `--diagnostic-canary`
without `--preflight-only`; the measured array contains neither flag. This
specifically includes `--max-total-target-calls`,
`--max-total-judge-calls` and `--deadline-seconds`: they look like execution
bounds rather than selection, but they are part of the bound envelope, and
adding them at run time after deriving the plan without them fails admission.
This exact mistake was made once while executing this plan, so it is worth
stating plainly rather than leaving to care.

```bash
PREFLIGHT_LANE=(--preflight-only
      --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG"
      --attackers replay --judges rules --corpora "$ARM"
      --source-config experiments/source-instances.json
      --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1
      --max-total-target-calls 2 --max-total-judge-calls 2 --deadline-seconds 3600
      --out "$OUT_ROOT")
# Derive with "${PREFLIGHT_LANE[@]}", acquire, then preflight with that same
# array plus the plan/receipt/store locators. Build a separate exact array for
# each canary or measured request. Never add an argument to only one step.
```

The cost of the extra plan and receipt per lane is negligible, because
acquisition re-imports nothing; the benefit is that each receipt states exactly
which models that exact request needed.

Gate 3: acquisition receipts present and bound; every selected generative local
target has a passing `ura-local-model-readiness/1` receipt for its declared
modalities; `python -m experiments.local_targets`
shows the three vLLM rows as compatible with an exact revision/digest; the
console Build model picker shows the same rows under Local vLLM and the Ollama
rows under Local Ollama.

Status, 21 August 2026: **met for the three targets.** By 25 August both guards
were also sealed and the 1B guard's fit check passed, completing all five
snapshots. Each target was sealed with `downloaded_bytes: 0`, because the rig
already held all three target snapshots at exactly the pinned commits in a
legacy Hugging Face hub, which was staged as the controller's transport cache
by hard link. That costs no disk, leaves the legacy hub intact and is not a
manual copy into the managed store: promotion is gated on `seal_snapshot`,
which proves the complete official sibling set and every Git/LFS content
identity against the upstream manifest for the exact commit before anything is
promoted. The three target receipts bind 16, 17 and 26 files respectively,
matching the sibling counts verified upstream before acquisition.
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
  --attackers replay --judges rules,guardrail \
  --guardrail-model meta-llama/Llama-Guard-3-8B \
  --guardrail-revision 7327bd9f6efbbe6101dc6cc4736302b3cbb6e425 \
  --guardrail-device cuda:1 \
  --corpora <one text arm> --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 --execution-scope-id "$SCOPE" ... --out runs/thesis/attestation/<target>-text
# --out is the receipt FILE, opened create-only, not a directory: pointing
# it at a directory fails with File exists, and pointing it at an existing
# receipt fails too, so each derivation names a new path.
python -m experiments.live_attestation --probe-root runs/thesis/attestation/<target>-text \
  --execution-scope-id "$SCOPE" \
  --out runs/thesis/attestation/receipts/<target>-text.json   # ura-live-attestation/2
```

Although the receipt establishes transport identity rather than a benchmark
score, the probe is a complete Runner cell and retains a stage-shaped judgment
record. Local probes therefore use the sealed local guardrail after the rules
stage, so a rules abstention cannot turn a valid transport observation into a
controller failure. The purpose-bound acquisition contains target plus guard
for vLLM targets and the guard alone for an Ollama target. It performs no hosted
judge call.

Repeat with a text+image arm (for example `mossbench_official`) for the
image combination, and once per Ollama target for text. These are free (local
GPU only). Receipts are content-addressed and expire per the recorded max-age
policy, so schedule them immediately before the measured lanes.

Gate 4: one valid receipt per (target, modality combination) that Phase 6 uses.
Because these receipts expire under their recorded maximum-age policy, each
required route must meet Gate 4 immediately before its live canary. Gate 5
finalization then revalidates current receipt coverage against the resulting
runnable inventory before it admits Phase 6.

## 6. Phase 5: no-call projections and one-cluster canaries (2-4 hours)

For each planned measured lane: `rig_check` with the exact lane arguments
(projection, policy-stratum counts, guard load) [9], then one
`run_matrix --diagnostic-canary` with `--limit 1` on one arm [9.1], then
`lane_canary`.

`rig_check` is subject to the same sealed-model admission as a measured run,
verified here rather than discovered mid-phase: without an exact acquisition
plan, plan SHA-256, receipt, receipt SHA-256 and managed store it refuses with
`normal and preflight Hub runs require exact acquisition plan, ...`, persists a
request-error artifact and stops. So each projection needs the per-lane
plan-acquire sequence of Phase 3, derived with that lane's exact arguments, for
the same envelope-binding reason: the caps a projection reports are only
meaningful for the request they were derived from. Build one exact argument
array per purpose, then reuse that array only for its own plan derivation,
acquisition and execution. The projection, diagnostic canary and measured run
have distinct purpose-bound plans and receipts even when their model resources
are already present and acquisition downloads zero bytes. Record approved
call/time/storage caps from the projection before any measured lane. Judges for
local-target lanes are `rules,guardrail` (no hosted LLM judge; a local LLM judge
cannot share a process with a local target).

**Prospective bounded-sampling amendment (24 August 2026).** Before any Phase 6
measured lane started, the local programme replaced its earlier exhaustive-local
assumption with two measured population tiers. Core model-comparison lanes use
`--limit 100 --sample-seed 0 --seeds 0`; extended Runner-safe bridge lanes use
`--limit 50 --sample-seed 0 --seeds 0`. The amendment was fixed from source
inventories, no-call projections and diagnostic feasibility, not from measured
benchmark outcomes. `--limit N` is an equal per-arm cap applied independently
within every logical source arm. It selects a deterministic prefix of whole
prompt/intent clusters without replacement and retains every sibling row, so
this is not a risk-stratified or proportional-probability sample. Cluster-key
fallback precedence is nonblank `meta["source_cluster_id"]`, then nonblank
`DataPoint.id`, then the converted row index. Unique cluster keys are inventoried
in first source-appearance order. SHA-256 hashes the UTF-8 bytes
`ura-corpus-cluster-order-v1\0<logical-arm>\0<sample_seed>`; its first eight
bytes, interpreted as an unsigned big-endian integer, provide `scoped_seed` to
Python's `random.Random(scoped_seed).shuffle(...)`. The first N shuffled
positions are selected, then all selected rows are restored to source order.
These are nested, overlapping prefixes, not disjoint partitions: for one
unchanged arm, converted-corpus digest and sample seed, the one-cluster canary
is contained in the 50-cluster extended sample, which is contained in the
100-cluster core sample. Logical-arm identity contributes to seed derivation and
gives each arm an independently scoped ordering. A source with fewer clusters
is retained in full and reported as precision-limited; `--limit 0` returns the
exact full arm without sampling.

Runner also exposes the explicit policies
`seeded_pseudorandom_whole_cluster_prefix_v1` and
`source_order_whole_cluster_prefix_v1`. The second takes the first N cluster
keys in source-appearance order, still retaining every sibling row. The current
local campaign omits `--sampling-policy`, which deliberately preserves the
deployed seeded pseudorandom behavior and its existing request shapes. Any
future explicit policy is a separate request, acquisition, projection and
analysis identity; changing policy cannot reuse the current cohort's Gate 5
record. Both policies treat `--limit 0` as the exact full arm.

The earlier `--limit 0` projections remain useful as full-universe capacity
records but cannot authorize a bounded measured request. Every bounded lane
therefore receives a new exact no-call projection, acquisition plan and receipt,
request envelope and Gate 5 cap. Existing commit-matched `--limit 1` canaries may
remain as nested diagnostics when every other model, attacker, judge and source
identity is unchanged. HarmBench preparation is selection-bound and must be
regenerated at limit 50. The framework supports full-set execution for local
and hosted targets through explicit `--limit 0` with a complete projection and
sufficient admitted caps. A source-mapped prepared artifact can still bind a
narrower selection; the general full-set capability does not broaden that
manifest. Current-campaign policy authorizes
full mode only for all-local replication, as a separately approved cohort with
its own projection, caps, output roots and analysis stratum; it is not part of
the bounded Phase 6 cohort. The current measured cohort uses
`--sample-seed 0` only.
`--sample-seed 1` is a separately projected future cohort that requires its own
selection-bound projections, acquisition envelopes, Gate 5 caps, output roots
and analysis stratum before any calls; it is never appended to the seed-0 cohort
in response to observed throughput or outcomes.

**What this cascade can and cannot measure.** The guardrail is a content-safety
classifier: its label space is violation/safe, and it cannot express
over-refusal, because a refusal is itself safe content. It therefore adjudicates
harmful-probe violations, and on a benign probe it now defers rather than
returning a confident `safe`, which would otherwise have answered the
over-refusal question it cannot see and biased the benign over-refusal rate
toward zero. Benign rows are consequently decided by the deterministic rules
stage alone, and a benign row that the rules stage cannot classify confidently
fails closed: it is excluded from the over-refusal denominator rather than
silently counted as a non-refusal. Harmful-failure coverage is unaffected.

Two consequences for reading these lanes. First, report benign coverage, the
share of benign rows actually decided, beside every over-refusal rate; a rate
computed over a small decided subset is not comparable with one over the full
benign set. Second, where over-refusal coverage matters more than throughput,
add a local LLM judge stage for the benign arms in a separate process, which
`PROTOCOL.md` already admits as a local scoring stage, at the cost of a third
model resident on the pair of cards. Every lane uses the Level-2-compatible grouping
`--group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version`
(the CLI default; the Build field defaults to it; the Level-2 export rejects
narrower groupings). The bounded local cohort uses the tier-specific positive
limit above. The Build and CLI requests must emit that limit and sample seed
explicitly.

The Gate 5 inventory also records target-source pairs that cannot enter measured
execution as typed terminals. GPTGeoChat carries image-bearing source records.
Its Gemma 4 and Ministral 3 pairs are projected and canaried as multimodal
lanes. Its DeepSeek-R1 Distill and GPT-OSS pairs are `unavailable` with reason
`target_transport_text_only_for_image_source`; those two pairs never enter a
projection, canary, or measured loop.

The core cohort records `bridge-nanogcg`, `bridge-ideator`, and `t3mp3st` as
`unavailable` only because their prepared artifacts are assigned to a separate
follow-on cohort and were not bound when its Gate 5 authorization was sealed.
This is not a current capability disposition. The core controller does not
schedule those three lanes for core-cohort measured execution. The follow-on
cohort binds the newly prepared NanoGCG suffix, IDEATOR source-mapped seed-pair
manifest, and T3MP3ST bundle and uses the ordinary documented Runner commands
with one retained common scientific base and separate exact preflight, canary
and measured argument arrays. Each purpose keeps its own plan and receipt. For
each lane, the retained schedule contains a prepared artifact, no-call
projection, diagnostic canary, Gate 5 record, and measured schedule.
NanoGCG can use a positive corpus limit or a separately projected
`--limit 0` transfer cohort. Current IDEATOR v2 cannot: it is fixed to
`advbench_harmful --limit 1 --sample-seed 105`, while `pair_limit=0` means
all eight verified pairs mapped to `advbench:245`.
Prepare those two inputs with the runbook's named "NanoGCG: sealed suffix
capture, then replay" and "IDEATOR: exact VLBreakBench mapping, then Build or CLI
replay" procedures; do not substitute a manually assembled suffix or manifest.
After NanoGCG and both T3MP3ST captures are terminal, the tracked generated
`followon_prepared_controller.py` owns the remaining follow-on sequence in one
persistent tmux session. It consumes the canonical prepared artifacts, performs
the no-call projection and one-cluster canary for each lane, creates the formal
Gate 5 amendment before measured calls, attempts the three exact authorized
argv arrays independently, and produces the formal Phase 6 outcome/completion
pair. It does not alter the already sealed core Gate 5 artifacts and it does
not make this local campaign phase a product concept.

The corpus limit is the outer population selector, not a universal framework-
operation limit. `--limit 0` selects every source cluster; a positive limit uses
the seeded whole-cluster policy above. `--max-queries` and `--max-turns` must
separately cover the selected attacker's per-datapoint fanout. The bounded
HarmBench preparation is fixed to `DirectRequest`, experiment `llama2_7b`, one
case per method, limit 50, sample seed 0, a 28,800-second preparation timeout,
and query/turn bounds of one. T3MP3ST capture exposes its own corpus limit,
sample seed and per-request timeout and is bound to exact source commit
`f2eec3c48cefe301983b3865811eda89d454e988`; after the active sealed chain, run
a one-record capture/replay before the bounded capture/replay. IDEATOR v2 uses
the exact outer selection `advbench_harmful --limit 1 --sample-seed 105`;
`pair_limit=0` selects all eight source-mapped pairs and a positive value
selects their `exact_source_ordered_prefix_v2`. It is distinct from random
corpus sampling and does not admit `--limit 0` over all 520 AdvBench rows.
For the legacy v1 manifest, `pair_limit` uses 0 for all verified manifest pairs
and a positive value for `ordered_prefix_v1`; this does not change the current
v2 source mapping or outer selector.
At Runner replay time, NanoGCG accepts one attributable precomputed suffix and
has no invented quantity selector. The dedicated capture step generates that
suffix under the verified framework runtime and sealed surrogate identity.

For an R-Judge canary, source-evaluator completeness and source-evaluator
validity are separate observations. A completed prediction that does not obey
the source label format remains an exercised, complete observation with
`valid=0`; it contributes to `rjudge_validity` and the all-output accuracy
denominator. Gate 5 therefore requires the implemented source evaluator to be
queried and to complete the planned observations, but it does not require a
positive valid-prediction count or retry until a parseable answer appears.

Seven rows retain historical Gate 5 terminal records produced under the older
output policy: four exact GraySwan RR identities and three RWKV static
identities. The GraySwan probes reached the declared 4,096-token generation cap
with no stop, and a sealed Transformers control reproduced the checkpoint's
two-token repetition while the exact LLaVA base emitted EOS. The RWKV probes
either reached their generation cap or returned an exact successful empty
completion. Their create-only terminal artifacts remain immutable diagnostic
provenance and continue to bind exact model identity, configuration, diagnostic
roots and call accounting.

They are not the current disposition. Runner 2.22 and later retains every
nonempty length-capped response and its `finish_reason='length'` provenance;
Runner 2.23 retains a successful empty Ollama completion as typed
`model_nonresponse`, and Runner 2.24 applies the same typed outcome to a
successful empty vLLM completion. Runner 2.25 makes one additional answer attempt
by default for empty, malformed, binary/control-like, symbol-only or transport-
failed output. Vague, repetitive or semantically poor natural language is still
sent to the selected evaluator, which may decide or abstain. Exhausting the
answer retry writes `model_stability_status=failed_output`, does not query the
policy judge, checkpoints that row and continues until the complete assigned
population has been attempted. The row remains in the final population as a
missing response, counts in missingness and response coverage, and is excluded
from the decided safety-rate denominator. Projection and Gate caps cover two
target attempts per intended call under the default. Exact model identity,
seals, fixed configuration, durable budgets and operator wall-time limits remain
fail-closed. Neither a length-capped answer nor a failed output authorizes altered
stops, generation caps, decoding configuration or checkpoint identity.
When the adapter verifies a strong runtime/model identity before classifying the
answer as unusable, the failed-output row retains only that normalized identity
and rejects drift between attempts. A live-route attestation may therefore bind
the verified transport even when the diagnostic answer is missing; this does
not admit a safety judgment or change readiness/stability accounting.
Runner 2.26 separately retains a deterministic target-input incompatibility,
including an exact vLLM prompt-length rejection, as a typed missing response.
The unchanged input is not answer-retried, policy judges are not queried, and
the remaining selected population continues. This is input-compatibility
coverage, not model-stability failure; identity, seals, configuration, budget,
and unrelated validation or transport failures remain terminal.

An older Runner may already have stopped a lane before this policy was
available. `experiments.local_campaign.resume_current_ollama_phase6` handles
that historical boundary without redefining the experiment: it waits for the
base Phase 6 completion, selects only lanes retained as failed, and relaunches
each lane with the exact stored argv, run IDs, call-budget ledger and original
checkpoint. Sealed cells are call-free and checkpointed attempts are restored;
the controller counts the judgment checkpoint once and does not also count its
mirrored response checkpoint. It writes a separate source-bound recovery
completion and never edits the immutable base completion. The recovery accepts
the standard `.venv/bin/python` symlink only when it resolves to an executable
regular file, so resumption stays in the original isolated environment. Its
exact tmux-owned lifecycle is published to Jobs without granting evidence
authority or rewriting either completion.

Only the four affected GraySwan identities are re-attested and canaried in their
targeted Gate 5 amendment. The historical GraySwan rows keep their immutable
`-full` terminal identities, but the amendment's current measured identities are
`local-llava-rr-text-primary-100`,
`local-llava-rr-image-primary-100`, `rjudge-llava-rr` and
`gptgeochat-llava-rr`. Their limit-100, sample-seed-0 selections and caps match
the corresponding LLaVA-base rows. A separate additive Ollama amendment replaces
the superseded RWKV tasks with the four exact current models. Its retained first
cohort used limit 50 and sample seed 0 for bounded text and source-classification
lanes, with image and GPTGeoChat lanes only for Gemma 4 and Ministral 3. The
population-alignment amendment completes the same nested seed-0 prefix to limit
100 for every comparable Ollama lane. It does not rewrite the already sealed
46-row historical profile or repeat a completed limit-50 row. Every retained
Ollama request before the DeepSeek continuation binds `num_ctx=8192` and
`num_predict=512`. The first value prevents
the 32B DeepSeek condition from allocating its full 131,072-token native context
and spilling nearly half of a short-prompt canary to CPU while the scoring guard
is resident; the second is an output cap, not a reason to discard observed
length-capped text. A different context or output cap is a separate projected
cohort. After `think=true` exposed a systematic 512-token no-final-answer
condition on difficult security inputs, a separate ten-input, one-attempt,
no-judge diagnostic admitted `num_predict=2048` after all ten inputs returned
visible final text with 719-1,335 completion tokens and normal stop reasons. The
resulting DeepSeek-only continuation binds that
condition in its launch, local-config digest, Runner request and combined `/3`
completion; it cannot be pooled with the stopped 512-token diagnostic condition.
Identity, provenance, residency, seal, budget and wall-time failures
remain hard failures. Exhausted answer-level malformed output or transport
failures use the typed missing-response policy above. Earlier attempts remain
diagnostic observations.

Gate 5: projections and canaries retained under `runs/thesis/preflight` and
`runs/thesis/diagnostics`; the four-row GraySwan RR current-policy amendment and
the separate current four-model Ollama amendment retained without rewriting the
earlier terminal artifacts; caps recorded in
`runs/thesis/RUNNOTE.md`; all 46
planned rows represented exactly once as runnable or typed terminal. Each
runnable row also binds `core_primary_100` or `extended_50`, limit, sample seed,
selected-cluster and converted-row identities, exact no-call projection and
approved call caps. The approved policy records
`measured_lane_wall_time_seconds=86400` as the 24-hour process wall-time ceiling
for one measured lane and binds `--deadline-seconds 86400` as that request's
Runner call-start window. The Runner refuses to begin a later call after its
deadline but does not interrupt an in-flight call. The controller ceiling is
separate: it may terminate and reap the lane process group at 24 hours. Both
values are prospective current-cohort bindings; the software supports other
positive values only in a separately projected and approved cohort.

A failed additive Ollama controller is recovered from its exact canonical
`.exit=1` control root. The recovery revalidates completed artifacts, executes
only never-completed rows or cells, and emits one provenance row per disposition when
every exact per-model local config is byte-identical. If a context or output cap
changes, the old evidence remains immutable diagnostics and the controller
creates a fresh projected cohort instead of relabeling or reusing it.
Gate 5 keeps the historical execution commit and current validation commit as
separate identities; it rejects a missing, duplicate or silently relabeled
mixed cohort. Within an exact-config recovery, successful projections,
attestations and canaries are not rerun. If every unit completed and only the
aggregate validator failed, recovery revalidates the complete inventory with
zero additional model calls.
For a row-local output failure produced by an older Runner, recovery binds the
original checkpoint inventory, selects only attempt identities without a durable
response/judgment record, and publishes an explicit merged coverage inventory.
It never reruns or relabels the already paid completed rows, and same-revision
recovery retains the original argv rather than claiming the later answer-retry
policy. A fresh current Runner cohort instead binds
`--target-answer-retries 1` in its request, projection and caps. Original,
recovered and later-revision strata remain explicit until read-only analysis
validates each population.

If that exact-argv recovery reaches a terminal zero-progress state because the
old result root retains an open circuit, it is not relaunched again. The current
Ollama stability continuation validates the immutable base and failed recovery,
then schedules exactly 14 fresh per-corpus Runner 2.26 units covering only the
1,684 never-completed rows. Content-bound prefix selectors exclude the 430
completed Gemma AirBench rows, two completed Gemma MLLMGuard-privacy rows and
27 completed Ministral MLLMGuard-privacy rows; nine complete Gemma text cells
and seven complete image cells per model are omitted entirely. The 1,911
durable historical rows and the later-revision units remain separate output-
policy strata, with no cross-policy pooling. This continuation may run after a
vLLM continuation has terminalized, but never concurrently with it on the two-
GPU rig.

The first 14-unit invocation is itself immutable if a later aggregate check
fails. When complete recovered answers were final-scored but their persisted
judge-stage projections retained null stability fields, four fully executed
Gemma text units could not publish completion even though all intended calls,
responses, judgments and checkpoints existed. The exact follow-up controller
therefore finalizes those units from their durable artifacts with zero target
and judge calls, inherits the five already complete Ministral image units, and
launches only the five Gemma image units that stopped before measured Runner
execution. It accepts only the exact terminal log causes. Fresh image identity
derivation uses deterministic seeds 0 through 4 so one probe nonresponse cannot
stand in for the 2-of-5 readiness gate; every resulting receipt remains fully
validated. The old failed controller, zero-call finalizations and new image
units remain separately attributable and no completed row is repeated.
Once the exact model has passed that readiness gate, a diagnostic canary whose
entire evaluable population abstains records model-stability evidence but does
not veto its assigned measured population. Both canonical zero-record JSONL
encodings, zero bytes and one terminal newline, are valid; any other byte or
record-accounting mismatch remains terminal.
If the retained continuation terminal contains only the historical newline-
encoding rejection, the canary-recovery controller inherits every completed
unit, revalidates the retained canaries with zero repeated canary target calls,
and schedules only populations that never reached measured Runner. A fresh
revision-bound identity attestation is still required; no completed measured
row is repeated.

**Ollama population-alignment amendment (31 August 2026).** Review of the
planned population sizes, before the current-Ollama stability continuation or
Phase 7 analysis started, found that the retained Ollama limit-50 cohort was not
quantity-matched to the vLLM limit-100 model-comparison cohort. This is a design
defect, not a model-outcome trigger. After the 1,684-row stability continuation
fills the holes inside the first 50-cluster prefix, a separate controller must
project and execute only clusters 51 through 100 for all 12 comparable Ollama
lanes. The nested seed-0 policy adds 1,909 static-text rows per model, 807
static-image rows per vision model, 50 R-Judge rows per model and 1,075
GPTGeoChat rows per vision model: 11,600 intended calls in total. The controller
must prove that each old limit-50 datapoint-ID digest identifies an exact subset
of its limit-100 selection, bind the retained ID set and remaining-row digest,
run the no-call projection
and diagnostic canary before measured calls, and reject any overlap. Historical
prefix and new extension artifacts remain distinct Runner strata; Phase 7 may
report their combined population coverage but must not pool their rates across
revision or output-policy boundaries.
Static alignment lanes retain their Hub acquisition plan because their selected
source inventory contains Hub-backed resources. The Ollama R-Judge and
GPTGeoChat lanes use already-local source data and a local daemon target, so
they omit model-acquisition arguments; an empty acquisition plan is not created.
If the controller seals `complete_with_failures`, continuation must validate the
exact base completion and select only work that has not become terminal in a
later artifact. In this campaign the first recovery started DeepSeek and was
interrupted before the other six failed units began. The separate Runner 2.27
failed-output recovery completes DeepSeek's 1,909-row extension from 235 retained
usable rows plus 1,674 recovered or previously unattempted rows. Only after that
recovery is terminal may the alignment continuation schedule the four 50-row
R-Judge units and two 1,075-row GPTGeoChat units, exactly 2,350 rows. It must not
schedule DeepSeek or any of the five base-complete units. All continuations reuse
the original content-bound limit-50 selectors, derive fresh revision-bound
attestations and retain separate revision/output-policy strata. Phase 7 accepts
the resulting population only when its unique extension accounting is exactly
11,600 rows; actual Runner work is reported separately because 2,772 failed
outputs were deliberately retried once rather than hidden.

Before Gate 6 closes, every retained local vLLM failure is partitioned by the
boundary it reached. A lane that failed before measured Runner execution is run
as a complete first measured Runner 2.25 condition. A lane with a durable
measured prefix receives a content-bound continuation containing only its
never-completed rows. Completed lanes are not repeated. Every such condition
uses the same configured answer retry and model-stability accounting as Ollama,
while its revision and output-policy stratum remains explicit in Phase 7 rather
than being silently pooled with historical Runner evidence.

The retained current vLLM continuation is exactly seven new Runner 2.25 units
and 7,199 selected rows: 1,632 Qwen3-VL image rows, 2,020 GPTGeoChat-Qwen rows,
1,632 LLaVA-base image rows, the exact 815-row unfinished AirBench suffix, 100
XSTest rows, 100 SimpleSafetyTests rows and 900 DecodingTrust stereotype rows.
Completed Qwen3-VL text, completed Crescendo and the 1,039 durable LLaVA
AirBench prefix are not part of this call inventory.

That seven-unit controller later retained 375 complete GPTGeoChat-Qwen rows and
then stopped the unit when one rendered multimodal prompt contained 12,290
tokens against the prospectively bound 12,288-token vLLM context cap. The
controller continued to later units, so neither its completed rows nor sibling
units are restarted. After it terminalizes,
`experiments.local_campaign.vllm_input_recovery_phase6` validates that exact
prefix and schedules only the 1,645 never-completed GPTGeoChat rows under Runner
2.26 with the unchanged model/configuration. Later context-limit rejections are
retained as input-compatibility missing responses. A structure-only audit of
that suffix identified exactly 230 such rows: their rendered prompts contained
12,290 to 16,705 tokens against the 12,288-token admission. Before Gate 6,
`experiments.local_campaign.vllm_context_recovery_phase6` must bind those exact
typed outcomes and run only those rows under a separately projected
24,576-token condition. The completion allowance remains 4,096 tokens and the
campaign-wide local answer-retry count remains one. The Runner 2.25 prefix,
Runner 2.26 suffix and larger-context recovery remain separate, non-poolable
execution-condition strata; their disjoint selected IDs may be joined only for
population coverage.

The continuation controller binds its named tmux session to the existing Jobs
lifecycle and publishes terminal target-attempt and successful-generation
counts. This registration makes the campaign operationally visible; it does not
replace or authorize the measured Runner artifacts.
The already-running `bd2faf4` continuation predates per-child registration and
therefore remains truthfully visible as one parent engineering job whose unit
artifacts are browsable; no retrospective child start record is fabricated.
Every later recovery, current-Ollama stability and population-alignment
controller publishes the generic external-measured start record immediately
before each measured `run_matrix` child and its terminal record immediately
afterward. Those rows bind the child's exact Runner output root and remain
operational metadata rather than scientific admission.

## 7. Phase 6: bounded measured local lanes (sized by projections and canaries)

**Source-record inventory, which is NOT the row count.** The figures below are
released source records and equal the receipt's `raw_records.accepted`, which is
also the cluster count for an arm that emits one row per record. Several
converters fan out, so their emitted rows are a multiple of these, and reading
these as rows understates the campaign: MM-SafetyBench emits three variants per
question, 1,680 records giving 5,040 rows, which
`converters/release_specs.py` pins directly, and GPTGeoChat emits one row per
assistant turn per moderation level, 500 conversations giving 9,820 rows over
500 clusters, measured by converting the pinned release on the rig. Both are
correct as clusters and wrong as rows. Do not size a lane from this paragraph:
the no-call projection in Phase 5 reports the exact per-arm cell count for the
selection actually requested, and it is the only figure that should set a cap.

The seed-0 sampler over the currently admitted conversions gives the following
pre-measurement sizing calculation. These values are not benchmark results and
do not replace the new content-bound Gate 5 projections.

| Measured group | Tier | Selected converted rows | Intended target calls before answer-retry reserve |
|---|---|---:|---:|
| static text, per target | core 100 | 3,854 | 3,854 |
| static image, per target | core 100 | 1,632 | 1,632 |
| R-Judge, per target | core 100 | 100 | 100 |
| GPTGeoChat, per target | core 100 | 2,020 rows from 100 conversations | 2,020 |
| Crescendo, Qwen3-VL | core 100 | 700 conversations across seven arms | 2,800 at four turns |
| local guard defense, if runnable | core 100 | 3,854 | 3,854 |
| five runnable bridge lanes plus HarmBench replay combined | extended 50 | 850 source selections before per-method expansion | 1,750 |
| four admitted Ollama static text lanes combined | aligned core 100 | 15,416 | 15,416 |
| four Ollama R-Judge lanes combined | aligned core 100 | 400 | 400 |
| two admitted Ollama static image lanes combined | aligned core 100 | 3,264 | 3,264 |
| two Ollama GPTGeoChat lanes combined | aligned core 100 | 4,040 | 4,040 |

The total below counts each `per target` core group for the two planned core
targets, then adds the single Qwen3-VL Crescendo lane and the combined bridge
and Ollama groups shown above.

The population-aligned bounded design contains 42,882 intended target calls when
the local defense is typed unavailable, or 46,736 when it is runnable. A new
complete projection under the default one-retry policy therefore reserves at
most 85,764 or 93,472 target attempts respectively. The aligned current-Ollama
population contains 23,120 intended calls across its 12 runnable lanes and
reserves at most 46,240 attempts under the new policy. The retained limit-50
prefix and the non-overlapping extension keep their own exact caps and Runner
strata; the
DeepSeek-R1 Distill and GPT-OSS GPTGeoChat pairs are separate typed-unavailable
rows and contribute no calls. Model-judge and provider HTTP caps remain zero in
this local campaign. Local scoring and defense-guard evaluations are accounted
separately and are fixed by the new projection. Retained older-revision runs
keep their originally bound caps. Exact checkpoint recovery retains the
originally bound Runner and argv and executes only never-completed rows. A
separately projected fresh Runner 2.25 cohort reserves the answer-retry attempts
without retroactively doubling or rerunning completed work. Caps are never
raised mid-lane.

Source records: common text arms about 35,900 (SALAD-Bench base 21,318;
AIR-Bench 5,694; DecodingTrust 3,456; CyberSecEval 3,416; AdvBench 520; XSTest
450; HarmBench 400; StrongREJECT 313; JailbreakBench 200; SimpleSafetyTests
100), common image arms about 9,900 (HoliSafe 4,031; VLSBench 2,240;
MM-SafetyBench 1,680 records = 5,040 rows; MLLMGuard safety dimensions 548;
FigStep 500; JailBreakV image-backed 360 rows over 190 intent clusters;
MOSSBench 300; SIUO 167; HarmBench multimodal 110), classification arms 1,071
records (R-Judge 571; GPTGeoChat 500 conversations = 9,820 rows). The remaining
arms have not been recounted against their converters, so treat every figure
here as a source-record count until Phase 5 replaces it. The earlier "roughly
47k target calls per local model" followed from reading these as rows and is
therefore a floor, not an estimate; the canaries and the projection determine
the throughput. The current measured cohort remains seed 0 only. Any seed-1
population sample is the separately projected future cohort defined above, not
an outcome- or throughput-triggered extension of the current cohort.

| Tier | Lane | Targets | Attackers | Judges | Output root |
|---|---|---|---|---|---|
| 1 [10.1] | static text, all common text arms incl. the six aggregator arms | Qwen3-VL-8B; LLaVA base; GraySwan RR after its exact current-policy Gate 5 amendment; Gemma 4 12B Q4_K_M; Ministral 3 14B Q4_K_M; DeepSeek-R1 Distill 32B Q4_K_M; GPT-OSS 20B MXFP4 after the additive Ollama amendment | replay | rules,guardrail | `runs/thesis/runner/local-<model>-text` |
| 1 [10.2] | static image, all common image arms | Qwen3-VL-8B; LLaVA base; GraySwan RR after its exact current-policy Gate 5 amendment; Gemma 4 12B Q4_K_M and Ministral 3 14B Q4_K_M after physical-image transport attestation | replay | rules,guardrail | `runs/thesis/runner/local-<model>-image` |
| 1 [10.3] | audio/video | none (no local audio/video renderer) | - | - | structural `N/A` |

Conversion cost, measured on the rig (21 August 2026): the audio arm converts its
complete manifest before any sampling, so a bounded `--limit 2` JALMBench
observation took 1,218 s (20.3 minutes) while it read all 220,240 rows and hashed
the referenced audio. This is the price of binding the full-corpus digest and the
complete cluster inventory into the sampling audit, not a stall; budget it once per
JALMBench invocation. Every other arm observes in under 15 s.
| 2 [11] | R-Judge and GPTGeoChat classification | vLLM roster for both; all four current Ollama targets for R-Judge; Gemma 4 and Ministral 3 for GPTGeoChat; the DeepSeek-R1 Distill and GPT-OSS GPTGeoChat pairs typed unavailable | replay | rules (not queried; source parser authoritative) | `runs/thesis/runner/rjudge`, `.../gptgeochat` |
| 3 [12.1] | live Crescendo (response-conditioned) | Qwen3-VL-8B | crescendo | rules,guardrail | `runs/thesis/runner/crescendo-<model>` |
| 3 [12.2] | frozen measured Runner-safe bridges | Qwen3-VL-8B | pyrit, deepteam, h4rm3l, spikee (sealed workers), purplellama (CyberSecEval arms) | rules,guardrail | `runs/thesis/runner/bridge-<attacker>` |
| 3 [12.2] | sealed `bdd8252` prepared attacks | Qwen3-VL-8B | pinned HarmBench DirectRequest preparation + replay; T3MP3ST retained its historical pre-amendment terminal | rules,guardrail | `runs/thesis/runner/harmbench-replay` |
| follow-on prepared cohort | prepared replay capability | Qwen3-VL-8B | pinned T3MP3ST capture/replay; NanoGCG attributable suffixes; IDEATOR source-mapped seed pairs | rules,guardrail | fresh content-bound roots only after new admission |
| 4 [13] | same-base defense contrast | LLaVA base versus exact GraySwan RR, estimable only after all affected RR identities pass the current-policy amendment and complete matching Phase 6 cells | replay | rules,guardrail | paired estimate when matching evidence exists; otherwise a typed Phase 7 unavailable artifact |
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
[14.3]; record run/failed/unavailable/not-selected for all nine. These bounded
one-case runs remain engineering diagnostics under `$URA_WORK/runs/engineering`.
They exercise the native bridge and importer but are not measured Runner lanes
and are not promoted into thesis metrics.

The Phase 6 sequence may adopt an already terminal core, extended or native
launch only from an exact retained sequence path. It copies the launch and, for
native diagnostics, the matching plan and plan-result bytes, then revalidates
the whitelisted controller payload, historical project-revision receipt,
framework lock and complete terminal inventory. Adoption makes no target call
and never invokes the child wrapper again; any changed or unregistered identity
fails instead of being treated as reusable evidence.

### 7.1 Runner 2.27 failed-output recovery amendment

The 1 September current-Ollama population run exposed a serving-condition
confound rather than an intrinsic one-third model failure rate. The adapter did
not send an explicit Ollama `think` control and ignored the daemon's separate
`message.thinking` field. At the controlled durable stop, 2,772 of 8,229 rows
were retained as failed output. Every exhausted empty row from the
thinking-capable Gemma, GPT-OSS and DeepSeek routes consumed the full 512-token
completion allowance; Ministral did not show that pattern. The stopped
DeepSeek unit also has 1,021 selected rows that were never attempted. A separate
structure-only audit found 20 genuine two-token empty LLaVA outputs and 230
Qwen3-VL context-limit incompatibilities. No prompt or response text was printed
by either audit.

Runner 2.27 binds Ollama thinking explicitly. Gemma and Ministral use
`think=false`, DeepSeek-R1 uses `think=true`, and GPT-OSS uses its supported
`think=low` condition. The adapter
reads final content separately, retains no reasoning text, records only whether
thinking output was observed and rejects a daemon that violates a disabled
policy. Local vLLM and Ollama still use one configurable Runner answer-retry
policy, set to one retry in this campaign.

`failed_output_recovery_phase6` derives one completed-ID selector from the exact
durable attempt/response pairs of each affected unit. It schedules 3,793 Ollama
rows: the 2,772 failed outputs plus the 1,021 never-attempted DeepSeek rows. It
also schedules the 20 genuine LLaVA failed outputs, for 3,813 measured recovery
rows in six fresh Runner 2.27 units. It excludes every usable first response,
every response recovered after retry, and all 230 deterministic Qwen3-VL input
incompatibilities because they require a different context condition rather
than an answer retry. The dedicated vLLM context-recovery controller verifies
and selects that exact 230-row set, derives a fresh route attestation, canary
and no-call projection, then runs it with `max_model_len=24576`. Old rows stay
immutable lifecycle evidence. Only the old
successful rows and their fresh recovery rows form the eventual complete
selected population, and their Runner/output-policy/revision strata remain
separate until an explicitly justified sensitivity view combines estimates.
Diagnostic attestation/canary calls remain diagnostic and cannot be counted as
population rows.

The first six-unit recovery retained five terminal units (2,139 rows) but made
no DeepSeek population call: all five admission probes were rejected because
the controller had bound that reasoning model with `think=false`. The
`failed_output_recovery_continuation_phase6` controller accepts only that exact
terminal partition, retains the five completed results byte-for-byte, reuses
the exact 1,674-row selector, and runs only DeepSeek with `think=true` under the
separately calibrated 2,048-token completion allowance. Its combined `/3`
completion keeps old and continuation project revisions and generation
conditions in separate metric strata. This is correction of a pre-execution
configuration error followed by a separately named cap sensitivity, not an
extra response retry. Filtering to DeepSeek must preserve its
physical position 05 from the original six-unit order; renumbering the filtered
list from one changes the immutable selector identity and is rejected before a
target call.

The alignment continuation is a dependent Phase 6 step, not another replay of
the seven failed base units. It requires the terminal failed-output recovery and
then runs only the six never-started R-Judge/GPTGeoChat units, for 2,350 rows.
Its explicit Ollama configuration binds `think=false` for Gemma and Ministral
and `think=low` for GPT-OSS. Because none of those six population rows has run,
their fresh condition uses `num_ctx=32768` and `num_predict=4096`, with a fresh
attestation, one-cluster canary, no-call projection and acquisition before the
measured run. This is the maximum common high-context candidate admitted for
live hardware verification on the two-card rig, not a claim that the models'
advertised 131K or 262K windows fit beside the evaluator. A failed allocation
stops that model's unit before population calls and is replaced by its highest
passing bound. No local-only classification unit may gain a Hub
acquisition plan. Reintroducing DeepSeek into this selection or changing the
2,350-row count is a contract failure.

The general local serving default is provider-independent at the response
boundary: an omitted vLLM `max_tokens` and an omitted Ollama `num_predict` both
resolve to 4,096. vLLM uses each checkpoint's native context unless an explicit
hardware-fit `max_model_len` is bound; Ollama uses the 32,768-token high-context
candidate because its request API otherwise falls back to a short interactive
allocation. Every resolved value is visible in Build and retained in the run
condition.

Interactive shutdown owns SIGINT as well as SIGTERM. Runner records the signal,
finishes model and framework teardown, restores both prior handlers and then
returns the conventional signal status. Gate 6 requires an empty Ollama `/api/ps`
inventory and idle baseline GPU memory after any interrupted local lane.

If repinning has moved that exact historical project-revision receipt into the
fixed sibling `project-revision/superseded/` directory, the current-Ollama
campaign validator may read only the same filename with the descriptor's exact
byte count and digest while retaining the original logical locator for argv
comparison. An existing, symlinked, missing or content-different candidate does
not fall through to another receipt.

Every core and extended measured lane runs in its own process group under the
Gate 5 24-hour lane wall-time ceiling. Core lanes are terminated and reaped on
that ceiling before the controller continues to the next lane; the extended
controller applies the same ceiling cumulatively across each lane's preparation,
resume and measured stages. A setup failure or timeout that occurs before Runner
can publish its own request/error lifecycle writes one create-only,
non-empirical `ura-phase6-pre-runner-failure/1` marker inside that exact planned
Runner root. Core uses `runs/thesis/runner/<lane>`; the retryable extended
controller uses `runs/thesis/runner/<lane>/<phase6-extended-control>` so a later
controller can preserve earlier job evidence instead of deleting or reusing it.
The marker is not a Runner artifact and cannot enter metrics. It exists so Gate
6 never represents a planned measured lane by an absent directory or by an
engineering log outside the Runner inventory.

Immediately before each real measured `run_matrix` child, the controller also
creates one fixed-child operational registration binding the exact sanitized
argument vector, Runner root, project revision, framework lock, approved Gate 5
digest and the exact owning tmux socket/session. A sequential controller may
name its own session while it synchronously owns the child; a separately
launched child names its child-specific session. The controller creates the
matching terminal record after the child returns. Jobs and Stats use that
explicit ownership to display the
lane and completion-bound usage from its validated artifacts. The console
neither launches nor stops these external children, and the registration and
its terminal record remain explicitly external operational and non-thesis even
after exit zero. The selected Jobs history window never hides an exact-session
row that is currently observed live; unavailable or bounded-away liveness is
shown as `unknown`, not asserted as `running`.

The Phase 6 sequence wait for Gate 5 is bounded by its declared 720-hour
controller hard stop, not by a Runner lane's 86,400-second call-start window.
When a later sequence finalizes an interrupted campaign, it adopts core or
extended work only through an exact prior sequence launch whose child already
has a validated terminal completion and exit marker. The adopted measured
children retain the Gate 5 project identity under which they ran; native
diagnostics, if not yet completed, run once under the finalizer's current
analysis revision. This avoids repeating successful measured work while keeping
the revision strata explicit.
The Phase 5 and Gate 5 orchestration controllers enforce a 24-hour global
controller deadline, and the Phase 7 watcher enforces 720 hours. At expiry, a
controller records exit 124 and the exact wait/hours reason in task and campaign
events. It terminates and confirms absence of only an exact tmux session it
launched and owns; a controller that times out while awaiting upstream Phase 5
or Phase 6 never terminates that upstream session.
Cleanup owns a
prospective external id and exact session before start publication, and terminal
publication is bounded to 30 seconds, so a signal or stuck publisher cannot
leave a row borrowing the liveness of the parent controller.

Gate 6: every planned measured Runner lane is attempted independently and
either completes or records an explicit error/partial state under
`runs/thesis/runner`, through Runner's own lifecycle artifacts or the exact
typed pre-Runner marker above. The aggregate is `complete` or
`complete_with_failures` according to that exact terminal partition; a typed
failure never becomes `measured_complete` and never prevents later independent
lanes from being attempted. Native engineering diagnostics retain their
separate typed dispositions under `runs/engineering`; caps are never raised
mid-lane.

## 8. Phase 7: read-only analysis (hours)

`level1_evidence` over `runs/thesis/runner` authorizes the complete measured
lifecycle, including complete, partial and failed Runner artifacts and their
final eligibility or request-error records. The metric grid is deliberately
narrower: `suite_summary`, `level2_report`, `judge_sensitivity --attacker replay
--defense none`, `kappa --attacker replay --defense none`, `transfer_matrix
--attacker replay --defense none`, and the free replay-vs-Crescendo paired
comparison within Qwen3-VL-8B [16]. The planned LLaVA base-vs-RR comparison is
estimated only when the GraySwan RR amendment admits all four bounded RR rows and
both base and RR measured cells match on source clusters, input bytes, sampling,
inference settings and judge condition. Otherwise Phase 7 writes one strict
`ura-phase7-non-estimable-contrast/1` artifact for every unavailable planned
facet, binds the failed or retained-terminal prerequisite and carries no
estimate. It must not construct RR metric input from projections, canaries or
partial measured roots. The current Ollama Gate 5 amendment and Phase 6
completion are independent, required Phase 7 inputs alongside the retained
core, recovery, GraySwan RR and follow-on inputs. When that Phase 6 completion
contains a failed readiness-admitted lane, Phase 7 additionally requires the
exact checkpoint-recovery completion, validates every originally failed lane as
its immutable terminal outcome, and then requires the separate 14-unit Runner
2.26 current-Ollama stability completion for the remaining 1,684 rows. The
historical 1,911 durable rows and fresh stability units retain separate
retry/output-policy strata and are never pooled. The Level-2 export keeps
rules-only and cascade (rules+guardrail) evaluator modes as separate
compatibility keys.
The exact terminal seven-unit Runner 2.25 vLLM stability completion and the
one-unit Runner 2.26 GPTGeoChat input recovery are required together. Phase 7
uses the six completed Runner 2.25 units and the 1,645-row Runner 2.26 suffix as
separate metric strata, retains the 375-row failed-unit prefix as lifecycle
evidence, and forbids pooling across either boundary or with completed Runner
2.24 Qwen text and Crescendo evidence.
The exact Phase 6 campaign terminal inventory before population alignment
contains 97 logical rows: 46 canonical, four output-policy amendment, three
follow-on, 14 historical current-Ollama, 14 current-Ollama stability, seven
vLLM stability and nine native. The population-alignment amendment adds 12
current-Ollama population-alignment logical extension rows, giving 109. The six
failed-output recovery units use Runner 2.27 and give a final terminal inventory
of 115.
The 12 population-alignment rows remain logical model/framework conditions, not
12 necessarily single-root files. Eleven have one terminal metric root. The
DeepSeek condition is population-complete across its retained Runner 2.26 usable
segment and Runner 2.27 recovery segment; Phase 7 reports their exact coverage
and model-stability accounting but forbids a pooled security rate across those
output-policy/revision strata.
The
contract self-test rejects any
other count or cohort partition.
Only successful measured lanes enter those metric and Level-2 views; failed and
partial lanes remain visible in Level-1 lifecycle evidence rather than being
silently dropped or replaced by Gate 5 preflight eligibility.
Phase 7 accepts a planned lane root only when it contains Runner lifecycle
artifacts or the exact `ura-phase6-pre-runner-failure/1` marker. A missing root
or an untyped controller-log explanation is rejected rather than normalized to
an invented pre-Runner disposition. After terminal analysis validation, the
watcher runs a plan-owned `publish-stats` task. Stats links the resulting
Level-1/Level-2 JSON only after the adapter validates the existing sealed Phase
7 watcher launch and frozen watcher/wrapper/payload, the Phase 6 completion/exit,
preparation result, actual Phase 7 and analysis launches, analysis completion,
artifact inventory, and authorized input manifest, including their project
revision, framework lock, and approved Gate 5 identity. Adapter or registration
failure makes the watcher fail; no numbered phase or gate interpretation enters
Rig Web.
Neither an external registration nor an inventory by itself grants evidence
authority.

Gate 7: the complete Phase 6 terminal inventory validates as `complete` or
`complete_with_failures`, at least one scheduled Runner lane is
`measured_complete`, the validated lifecycle registry retains every typed lane
state, Level-1 retains every representable Runner/request lifecycle, success-
only metric and Level-2 outputs validate, and the Stats publication registration
succeeds. If no measured Runner lane completes, the typed Phase 6 inventory
remains retained but Gate 7 is not met and no metric analysis is published.

## 9. Phase 8: human audit (free in money, requires raters and an ethics determination)

Run the sealed Phase 8 machine-preparation controller over Phase 7's validated
success-only Runner view [15]. Before it writes a sample, its exact cardinality
plan requires `C >= N + 20` for common-frame population `C` and requested
sample `N`, and `S >= M` for source-task population `S` and requested sample
`M`. The additional 20 common clusters are reserved for the independently
adjudicated qualification set and must remain disjoint from the final common
sample. The authorized manifest records those populations and requests, and
execution recomputes them from the same content-bound view. This proves
cardinality, not coverage feasibility: both deterministic selectors separately
fail closed unless the requested counts cover all achieved cells.

The controller prepares automated-label-blinded, model-visible samples, blank
two-rater forms, a qualification set and gold template, assignment and workload
records, and operator guidance. It makes no model, judge, provider HTTP, or
download call. Its only successful machine terminal is `human_only_blocked`
with `gate8_met: false`. A successful process exit is machine preparation, not
human evidence and not Gate 8.

Preparation is deterministic, seedless, and without replacement. The common
and source-task frames use whole-cluster selectors
`coverage_priority_then_stratum_round_robin_sha256_v1` and
`coverage_priority_then_sha256_fill_v1`, respectively. The disjoint
qualification set uses
`disjoint_risk_modality_behavior_coverage_then_sha256_lexicographic_representative_fill_v1`:
it emits one row per selected cluster, specifically that cluster's
lexicographic-minimum `sample_key` representative, and terminal validation
replays the exact selection against the bound Phase 7 Runner view.
`--bootstrap-resamples`, `--alpha`, and `--seed` apply only to later label
analysis and are invalid during preparation.

Gate 8 is met only after all of the following exist and validate:

- an applicable operator-supplied ethics/consent determination explicitly
  authorizes human exposure and records consent, compensation, withdrawal,
  harmful-content welfare, and escalation controls;
- an independent adjudicator establishes gold labels for all 20 qualification
  items, whose clusters are disjoint from the final common sample;
- at least two pseudonymous raters independently achieve at least 80 percent
  agreement on every qualification dimension;
- exactly two distinct qualified raters independently label each common and
  source-task row, after verifying every referenced media asset; pairs may
  rotate between rows, and agreement is reported for every pair with shared
  assignments;
- every non-unanimous composite or dimension is adjudicated after independent
  ratings are locked;
- `human_audit --labels` and `human_audit --source-task-labels` both validate
  the complete labelled files against the same success-only Runner view, bind
  each one by path and SHA-256 to its exact controller-prepared blank rating
  form, require identical headers and immutable row multisets with exactly two
  distinct rater IDs per sample, and write create-only reports containing the
  prepared-form descriptors into a separate Phase 8 analysis root, never into
  the sealed Phase 7 view; and
- a human operator reviews agreement, prevalence, support, confusion,
  uncertainty, and decision coverage, then authors an acceptance or limitation
  record binding the exact preparation, labels, adjudication, and report
  digests.

The accepted report schemas are exactly `ura-human-audit/1.2` for the common
frame and `ura-source-task-audit/2` for the separate source-task frame. Older
report schemas are not Gate 8 evidence.

Until that human-only record exists, Gate 8 remains open. This is the only route
to RQ5 judge validity for the local tier; machine preparation alone satisfies
only the software-coverage objective.

## 10. Console/CLI parity checks embedded in the campaign

Run each phase at least once through the console (Build -> Runtimes; Build
wizard for attestation probe, canary and measured lanes; Jobs for lifecycle;
Stats for per-job usage/coverage; Config editor for registries) and once
through the CLI, and confirm that the composed argument vectors (visible in the
Jobs record) equal the runbook vectors, including tier-specific `--limit 100`
or `--limit 50`, `--sample-seed 0`, `--group`,
`--exclude-tool-conditioned` on standalone synth dry runs, and the receipt
environment defaults on the Run page. The exclusion is standalone-dry-run-only;
every preflight, acquisition, attestation, canary, or measured route must reject
it.
Direct Phase 5 through Phase 7 controllers must appear
through their exact engineering marker/task-event records. Every Phase 6
measured child started after per-child registration became active must have a
resolvable external Job/Stats detail route whose artifact root equals that
child's one declared `--out` directory. The already-running `bd2faf4`
continuation remains the explicit pre-registration exception described above:
one truthful parent route with separately browsable unit artifacts and no
retrospectively fabricated child starts.

## 11. Schedule and effort (estimate, to be replaced by observed values)

| Phase | Wall time | Attended effort |
|---|---|---|
| 0 hygiene/pin | 1 h | 1 h |
| 1 runtimes | 3-6 h | 0.5 h |
| 2 receipt + observations | 3-5 h | 2-4 h (operator decisions) |
| 3 models | 1-3 h | 0.5 h |
| 4 attestations | 1 h | 0.5 h |
| 5 projections/canaries | 2-4 h | 2 h |
| 6 measured lanes | bounded inference; observed wall time to be reported, with 42,882 intended calls in the population-aligned design and a retry-1 conservative ceiling of 85,764 transport attempts | periodic |
| 7 analysis | 2-4 h | 2 h |
| 8 human audit | rater-dependent | rater-dependent |

## 12. Records and ledger

Each phase writes its receipts, logs and summaries under `/data/ura-work`
(`runs/thesis/...` for admissible evidence, `runs/engineering/...` for
diagnostics) and appends one dated entry to the convergence ledger
(`Thesis-EN/Codex_Reaudit.md`) with the commit, gate results and any
operator decision. Retain the clean-env suite log and the repin output for the
pinned commit in `Thesis-EN/verification/<date>-local-campaign/RECORD.md`.
