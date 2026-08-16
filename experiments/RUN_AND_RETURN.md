# Run and return: broad thesis experiment program

This is the operator path from a clean Linux GPU machine to the evidence bundle
for the thesis. It covers the broad hosted and local model roster, all nineteen
source converters, the runner-safe external attack bridges, and nine complete
source-native evaluators. Experiments and the human audit are still pending.
Preflight, dry-run, diagnostic-canary, and bounded transport-probe artifacts are
diagnostics, not thesis results.

The maintained artifact contract is Runner `ura-runner/2.15` with unified schema
`1.4`. Do not combine older-runner artifacts with this program.

Every `python -m experiments.*` command below can equivalently be started
from the rig console and campaign builder (section 18): the console builds
the identical argument vector from a typed allowlist, so admission gates and
artifacts do not differ between the two interfaces, and the CLI remains
authoritative. Repeatable flags (multiple `--live-attestation` receipt/digest
pairs, repeated `--eligibility`/`--results`/`--native` inputs, repeated
`--arm`/`--observation` for a multi-arm source-conformance scaffold) are
repeatable form rows in the console; the interface-parity tests validate every
console form against the real module parsers.

The Run page starts an allowlisted command from a typed form immediately; the
campaign builder is the separate mode-validated path that previews the exact
argument vector and call ceilings before any paid mode starts.

Target selection shorthand: `--models name[,name...]` on `run_matrix` and
`rig_check` resolves each name through the hosted registry (`--api-config`,
default `experiments/api-targets.json`) and the local registry
(`--local-config`, default `experiments/local-targets.json`) into the
equivalent `--api`/`--local` split. It is mutually exclusive with an explicit
`--api`/`--local`, and an unknown or ambiguous name is rejected naming the
registries consulted. `live_attestation --validate PATH --sha256 HEX`
revalidates an existing receipt through the same strict loader the
measured-grid admission uses.

The program is deliberately lane-based. A model is tested on every physical
modality that both its exact adapter condition and an acquired source support,
but an unsupported cell is recorded as `not_applicable` with a reason. It is not
silently converted to text. The program does not build the meaningless Cartesian
product of every source, attacker, model, defense, and native tool.

## 1. Measurement rules

Keep these rules beside the terminal throughout the run:

- There is no universal safety score. Every estimate retains model, served-model
  identity, source arm, source policy, modality, attacker, defense, judge, seed,
  and budget.
- Harmful response rate and benign refusal rate have different denominators.
  Static attempts and live response-conditioned conversations also remain
  separate.
- Cross-provider differences are descriptive associations. The LLaVA base versus
  GraySwan RR pair is the only planned same-base defense contrast, and even that
  must be described using its exact checkpoint identities.
- The judge cascade runs rules, the scoring guard, and the LLM judge on every
  common-metric-eligible policy-evaluable response. Source-specific
  classification rows use their registered source evaluator and retain an
  explicit unqueried structural placeholder. For common responses, the first
  confidence-clearing result is authoritative; the complete trail is evidence.
  There is no cost-saving early exit in this architecture.
- The scoring guard and a model-backed defense guard must be different model
  identities. The model under test must not grade or certify itself.
- A model-backed defense in this repository is text-only. Do not claim image,
  audio, or video defense results from it.
- A converter is not automatically a runnable evaluator. R-Judge and GPTGeoChat
  have implemented source-specific scorers. AgentHarm, BIPIA, InjecAgent,
  CyberSecEval prompt injection, and MLLMGuard hallucination, position-swapping,
  and noise-injection remain conversion or upstream-native tracks until their
  exact source scorer/runtime is integrated. Runner preflight rejects those
  records before a model call.
- Nine complete evaluators run in their own upstream environments. Their native
  result scales are imported and preserved; URA does not replay their prompts and
  pretend that the upstream framework ran.
- Provider refusal is a measured response state. Transport failure, missing media,
  parsing failure, budget exhaustion, and unsupported modality are not safe
  outcomes.

The operator routes the authoritative Chapter V questions as follows. RQ4 has
two declared subparts; RQ5 is judge validity, not the adaptive lane:

| Question | Execution/analysis route | Required evidence |
| --- | --- | --- |
| RQ1 execution conformance | sections 7-14 | requested-cell eligibility/`N/A`, modality plan/result, complete content-bound cells |
| RQ2 matched served-model conditions | focal grids and section 16 paired/figure commands | matched cluster support/effects plus exact realized identities |
| RQ3 portfolio breadth/heterogeneity | 39 converter arms, nine native projects, section 16 suite summary | disposition-complete family inventory without false pooling |
| RQ4a defense | section 13 guarded/unguarded same-base design | separate harmful and benign paired effects |
| RQ4b adaptivity/native execution | section 12 Crescendo/transfer and section 14 native runtimes | fixed-horizon conversation, exact-transfer, or source task/oracle evidence |
| RQ5 judge validity | sections 15-16 | eligible common-response human labels, adjudication, decision coverage and cluster-aware agreement/calibration |

The cross-framework program ontology is below. `suite_summary` emits the families
that currently have implemented crosswalks; a named but unimplemented family is
an explicit gap, not permission to improvise a pooled score.

| Semantic family | Examples | Combining rule |
| --- | --- | --- |
| `coverage_conformance` | completed/failed/parseable support | counts may be totaled; rates retain their scope |
| `unsafe_response_rate` | static harmful ASR and refusal | exact source/policy/modality strata only |
| `benign_refusal_rate` | benign over-refusal | never combine with harmful probes |
| `adaptive_compromise` | conversation ASR, robust refusal, survival, restricted mean turns-to-break | live trajectories only |
| `classification_quality` | R-Judge and GPTGeoChat validity, accuracy, precision, recall, specificity, F1 | by source task and threshold |
| `attack_or_injection_goal_success` | AgentDojo, ASB, Promptfoo, EasyJailbreak native outcomes | native definition and polarity |
| `task_utility` | AgentDojo/ASB utility, Giskard RAGET correctness | native task and scale |
| `graded_risk` | StrongREJECT-style score, Petri dimensions, AutoDAN danger score | never normalize into one score |
| `detector_findings` | FuzzyAI, Garak, Giskard Scan | detector-specific counts/rates |
| `truthfulness` | MLLMGuard hallucination, position-swapping, and noise-injection | reserved; pending a substantive scorer in the runner |
| `evaluator_reliability` | decision coverage, confusion/calibration, automated-human and inter-rater agreement | achieved independently labelled common-response population; never infer validity from stage concordance alone |

`experiments.suite_summary` applies these crosswalks but does not pool the
heterogeneous rates.

## 2. Machine and URA installation

*Console equivalent: this section's commands are also launchable as the `project_revision` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

The intended rig is Linux, Python 3.12, two RTX 4090 cards, recent NVIDIA drivers,
Git LFS, Git, Node.js for Promptfoo, and enough controlled storage for large audio
and video releases. JALMBench alone is much larger than the three small core
sources; inspect the official repository size before downloading it.

```bash
nvidia-smi
git --version
git lfs version
python3.12 --version
node --version
npm --version

export URA_WORK="$HOME/ura-work"
export URA_CORPORA="$URA_WORK/corpora"
export URA_UPSTREAM="$URA_WORK/upstream"
export URA_NATIVE_ENVS="$URA_WORK/native-envs"
mkdir -p "$URA_CORPORA" "$URA_UPSTREAM" "$URA_NATIVE_ENVS"

cd "$URA_WORK"
git clone https://github.com/ctapnec/MLLMRiskBench.git
cd MLLMRiskBench
# Use the full thesis-reviewed harness commit. Change it only through a recorded
# protocol amendment made before inspecting outcomes. It must be commit
# 6af9efaa5610d86d882211db24f4c679ff5700a0 or later: the section 4.1
# source_conformance --scaffold command first exists at that revision.
export REF_URA='<full-40-hex-reviewed-post-fix-project-commit>'
[[ "$REF_URA" =~ ^[0-9a-f]{40}$ ]]
git checkout --detach "$REF_URA"
test "$(git rev-parse HEAD)" = "$REF_URA"
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,analysis,api,guardrail,local-vllm]"
python -m pip install "huggingface_hub[cli]"
python -c "import bitsandbytes, psutil, torch, vllm; print(vllm.__version__, bitsandbytes.__version__, psutil.__version__, torch.__version__, torch.version.cuda, torch.cuda.is_available(), torch.cuda.device_count())"
python -m bitsandbytes
python -m pip check

# Create the one prospective local-checkout receipt before source acquisition.
# Generated evidence lives under the ignored runs/ tree; untracked or ignored
# executable source under src/ura or experiments still fails the receipt check.
mkdir -p runs/thesis/project-revision
python -m experiments.project_revision \
  --expected-revision "$REF_URA" \
  --out runs/thesis/project-revision
mapfile -t URA_PROJECT_REVISION_FILES < <(find runs/thesis/project-revision \
  -maxdepth 1 -type f -name 'project-revision-*.project-revision.json' -print)
test "${#URA_PROJECT_REVISION_FILES[@]}" -eq 1
export URA_PROJECT_REVISION_MANIFEST="${URA_PROJECT_REVISION_FILES[0]}"
export URA_PROJECT_REVISION_SHA256="$(sha256sum \
  "$URA_PROJECT_REVISION_MANIFEST" | awk '{print $1}')"
python -m experiments.project_revision \
  --validate "$URA_PROJECT_REVISION_MANIFEST" \
  --sha256 "$URA_PROJECT_REVISION_SHA256"

test -e runs/thesis/RUNNOTE.md || printf '# URA thesis run note\n' > runs/thesis/RUNNOTE.md
```

The checked-in `local-vllm` extra is the single version declaration for the
tested local stack: `vllm==0.27.1` and `bitsandbytes==0.49.2`. The base project
dependency declares `psutil>=7.2,<8` for the dashboard system snapshot. On the
actual rig the checks above succeeded with Python 3.12.13, vLLM 0.27.1,
BitsAndBytes 0.49.2, psutil 7.2.2, torch 2.13.0+cu130/CUDA 13.0, CUDA available
with two GPUs and maximum compute capability 8.9, 24 logical CPUs, and
134,974,398,464 bytes RAM. `pip check` was clean after the unused orphaned
`datasets 2.14.7` package was removed. This is dependency/hardware evidence,
not a model load or inference; no provider/model call was made. Repeat these
checks in the final detached measured checkout and retain their output.
The exact dashboard/filter/dependency snapshot and its local/rig results are
retained in the sibling Thesis record
`../../../Thesis-EN/verification/2026-08-16-rig-dashboard-filters/`; do not copy
a mutable hash or test count into this runbook.

`URA_PROJECT_REVISION_MANIFEST` and `URA_PROJECT_REVISION_SHA256` are consumed
automatically by `run_matrix` and by `rig_check`'s forwarded non-dry request.
Every non-dry preflight, transport probe, diagnostic canary, and measured Runner
invocation requires this exact digest-approved `ura-project-revision/1` receipt.
The driver retains it in each output and binds its compact identity into the
eligibility condition, grid request, `RunManifest.config.run`, completion checks,
live-attestation version 2, and postprocessing. It rechecks the local checkout
before execution boundaries and final grid publication. A revision change is a
prospective protocol amendment and a new cohort; do not resume or pool it under
an existing grid/run identity.

The receipt establishes only that the local expected and observed commits match,
the tracked checkout is clean, the driver and imported harness share one Git
root, and their current source bytes have the recorded digests. It does not
authenticate the remote repository, bind dependencies or upstream revisions, or
establish empirical validity. The operator-recorded commit/status files returned
in section 17 are supplemental self-recorded provenance, not a substitute for
the runtime binding.

Use access-controlled storage. Review every upstream license, model access term,
data-use restriction, provider retention policy, and institutional approval before
acquisition or calls. Do not put secrets, harmful artifacts, or restricted corpora
in Git.

## 3. Acquire all nineteen converter sources

*Console equivalent: the section 3.2 export commands are also launchable as
the `export_jalmbench` and `export_vlsbench` form(s) in the rig console
(section 18); identical argument vectors, gates and artifacts.*

The commands below use exact maintained snapshots verified on 12 August 2026.
The operator must still review each repository, access condition, and license and
record the decision in the compact source receipt described in section 4.1;
`runs/thesis/RUNNOTE.md` retains supplemental context. Create the evidence
location before acquisition. A moving branch name is not a research identity.
If a later snapshot is deliberately substituted, replace the corresponding full
`REF_*` value and record why before running that lane.

### 3.1 Git-hosted releases

```bash
export REF_STRONGREJECT=f7cad6c17e624e21d8df2278e918ae1dddb4cb56
export REF_MMSAFETY=b80eedea3db312c09ded2082813390f68e750ef3
export REF_MOSSBENCH=8d68b0614b39d8990a508e03d99975832f399db2

# Reviewed upstream snapshots for the remaining repositories (12 August 2026):
export REF_RJUDGE=83ce301da3ad50dd8b397e772863f5411c3d3dc2
export REF_GPTGEOCHAT=99a13275a6f4a14bcc1fb8c4038446e574033a64
export REF_JAILBREAKV=17e235e4d983ad75adecec2a1e624c3909da9c06
export REF_BIPIA=a004b69ec0dd446e0afd461d98cb5e96e120a5d0
export REF_HARMBENCH=8e1604d1171fe8a48d8febecd22f600e462bdcdd
export REF_SIUO=18974b65d238ad636d65d238541c7d75279ebb3e
export REF_ADVBENCH=098262edf85f807224e70ecd87b9d83716bf6b73
export REF_FIGSTEP=0861b17b3d67887c06ee3534ec65b3012f9becb7
export REF_PURPLELLAMA=e36f132f4c4b952515a03b8bdb1275738a1fa28b
export REF_INJECAGENT=f19c9f2c79a41046eb13c03c51a24c567a8ffa07

git clone https://github.com/alexandrasouly/strongreject.git "$URA_CORPORA/strongreject"
git -C "$URA_CORPORA/strongreject" checkout --detach "$REF_STRONGREJECT"

git clone https://github.com/isXinLiu/MM-SafetyBench.git "$URA_CORPORA/MM-SafetyBench"
git -C "$URA_CORPORA/MM-SafetyBench" checkout --detach "$REF_MMSAFETY"

git clone https://github.com/xirui-li/MOSSBench.git "$URA_CORPORA/MOSSBench"
git -C "$URA_CORPORA/MOSSBench" checkout --detach "$REF_MOSSBENCH"

git clone https://github.com/Lordog/R-Judge.git "$URA_CORPORA/R-Judge"
git -C "$URA_CORPORA/R-Judge" checkout --detach "$REF_RJUDGE"

git clone https://github.com/ethanm88/GPTGeoChat.git "$URA_CORPORA/GPTGeoChat"
git -C "$URA_CORPORA/GPTGeoChat" checkout --detach "$REF_GPTGEOCHAT"

git clone https://github.com/SaFoLab-WISC/JailBreakV_28K.git "$URA_CORPORA/JailBreakV_28K-code"
git -C "$URA_CORPORA/JailBreakV_28K-code" checkout --detach "$REF_JAILBREAKV"

git clone https://github.com/microsoft/BIPIA.git "$URA_CORPORA/BIPIA"
git -C "$URA_CORPORA/BIPIA" checkout --detach "$REF_BIPIA"

git clone https://github.com/centerforaisafety/HarmBench.git "$URA_CORPORA/HarmBench"
git -C "$URA_CORPORA/HarmBench" checkout --detach "$REF_HARMBENCH"

git clone https://github.com/sinwang20/SIUO.git "$URA_CORPORA/SIUO"
git -C "$URA_CORPORA/SIUO" checkout --detach "$REF_SIUO"

git clone https://github.com/llm-attacks/llm-attacks.git "$URA_CORPORA/llm-attacks"
git -C "$URA_CORPORA/llm-attacks" checkout --detach "$REF_ADVBENCH"

git clone https://github.com/CryptoAILab/FigStep.git "$URA_CORPORA/FigStep"
git -C "$URA_CORPORA/FigStep" checkout --detach "$REF_FIGSTEP"

git clone https://github.com/meta-llama/PurpleLlama.git "$URA_CORPORA/PurpleLlama"
git -C "$URA_CORPORA/PurpleLlama" checkout --detach "$REF_PURPLELLAMA"

git clone https://github.com/uiuc-kang-lab/InjecAgent.git "$URA_CORPORA/InjecAgent"
git -C "$URA_CORPORA/InjecAgent" checkout --detach "$REF_INJECAGENT"
```

MM-SafetyBench's repository does not include the image archive. Download the
authors' [`MM-SafetyBench(imgs).zip`](https://drive.google.com/file/d/1xjW9k-aGkmwycqGCXbru70FaSKhSDcR_/view?usp=sharing)
and extract its thirteen scenario directories directly below
`$URA_CORPORA/MM-SafetyBench/data/imgs`. SIUO likewise requires the authors'
`SIUO-images.zip` linked from the
[`sinwang/SIUO` dataset card](https://huggingface.co/datasets/sinwang/SIUO);
place `images/` beside the selected `siuo_gen.json` or `siuo_mcqa.json`.
JailBreakV-28K needs the official dataset-with-images release, not only the code
checkout. GPTGeoChat's Git repository contains evaluation code but not the 1.43
GB human dataset; download `human.zip` from the official
[`GPTGeoChat` README](https://github.com/ethanm88/GPTGeoChat#main-datasets-)
and extract it so each selected split contains sibling `annotations/` and
`images/` directories. Retain each downloaded archive until its exact bytes and
SHA-256 have been entered in the source receipt; the code checkout revision
alone does not identify these separately distributed bytes.

### 3.2 Hugging Face releases and large media

Set every `REF_HF_*` variable to the full dataset repository commit shown by the
operator's reviewed release. Gated sources require `HF_TOKEN` from a secret
manager. The commands below use only official repositories.

`Carol0110/MLLMGuard` is token-gated and `BAAI/Video-SafetyBench` is
approval-gated: its download fails with an access-denied error until the
operator's Hugging Face account has requested and been granted access on the
dataset page. Holding and accepting such access terms is an operator
decision; record it in the source receipt. [Access to
`BAAI/Video-SafetyBench` was requested and granted for this campaign's
account on 13 August 2026; recorded in ledger Section 11.27.]

```bash
export REF_HF_AGENTHARM=e23b3fe60a0da9037314b88e5ee3a0c054970dad
export REF_HF_JBB=886acc352a31533ffbcf4ef22c744658688086fc
export REF_HF_JAILBREAKV=f949ca582fff13d396ac8fce59596afafb2b78d3
export REF_HF_VLSBENCH=b56f6f6aad102fdb53f46e35fec96836bbe13001
export REF_HF_MLLMGUARD=4263487ca736c99292bac92d89f05eb744773450
export REF_HF_JALMBENCH=53da5217aad7b5640dd0bed5f58b79b19dde7fb2
export REF_HF_VIDEOSAFETY=b04daeb5f6c185df47e2aacb4d30b87912c51114

hf download ai-safety-institute/AgentHarm --repo-type dataset \
  --revision "$REF_HF_AGENTHARM" --local-dir "$URA_CORPORA/AgentHarm"

hf download JailbreakBench/JBB-Behaviors --repo-type dataset \
  --revision "$REF_HF_JBB" --local-dir "$URA_CORPORA/JBB-Behaviors"

hf download JailbreakV-28K/JailBreakV-28k --repo-type dataset \
  --revision "$REF_HF_JAILBREAKV" --local-dir "$URA_CORPORA/JailBreakV-28K"

hf download Foreshhh/vlsbench --repo-type dataset \
  --revision "$REF_HF_VLSBENCH" --local-dir "$URA_CORPORA/VLSBench"

hf download Carol0110/MLLMGuard --repo-type dataset \
  --revision "$REF_HF_MLLMGUARD" --local-dir "$URA_CORPORA/MLLMGuard"

hf download AnonymousUser000/JALMBench --repo-type dataset \
  --revision "$REF_HF_JALMBENCH" --local-dir "$URA_CORPORA/JALMBench-parquet"

hf download BAAI/Video-SafetyBench --repo-type dataset \
  --revision "$REF_HF_VIDEOSAFETY" --local-dir "$URA_CORPORA/Video-SafetyBench"

mkdir -p "$URA_CORPORA/Video-SafetyBench/videos"
tar -xzf "$URA_CORPORA/Video-SafetyBench/video.tar.gz" \
  -C "$URA_CORPORA/Video-SafetyBench/videos"
```

Retain `video.tar.gz` as declared file evidence in the source receipt. The
converted media inventory separately binds every selected extracted video; an
archive name or extraction command alone is not content identity.

The URA JALMBench converter consumes an audio-file manifest, not embedded Parquet
bytes. Export the official Parquet release once; the destination must not exist:

```bash
python -m experiments.export_jalmbench \
  --source "$URA_CORPORA/JALMBench-parquet" \
  --out "$URA_CORPORA/JALMBench-export" \
  --max-records 300000 \
  --max-total-bytes 600000000000
```

The official VLSBench Hugging Face release likewise stores images inside
Parquet. Export it once into verified image files plus the JSONL that the
converter consumes:

```bash
python -m experiments.export_vlsbench \
  --source "$URA_CORPORA/VLSBench" \
  --out "$URA_CORPORA/VLSBench-export" \
  --max-records 10000 \
  --max-total-bytes 100000000000
```

Both exporters write `export-summary.json` beside the prepared JSONL. Retain
that exact file as a hashed source-receipt component: the JSONL remains the
`consumed_input`, while upstream `discovered` is the sum of
`source_files[].rows`, `accepted` is `records`, and `excluded_by_design` is the
named skip count. The currently evidenced VLSBench refresh is 2,241 discovered,
2,240 accepted, one empty-instruction exclusion, and zero rejected-invalid
rows. Stop if a newly exported pinned release does not reconcile. The historical
JALMBench consumed manifest has 220,240 rows, but its upstream discovered and
text-only-excluded counts remain `CANNOT-VERIFY` until a new exact exporter
summary is retained; do not infer them from the prepared JSONL.

Copy the exact summaries into the return tree immediately. The receipt must
hash these copies, so the files it references cannot be omitted by the final
`runs/thesis` archive:

```bash
mkdir -p runs/thesis/source-export-summaries
cp "$URA_CORPORA/JALMBench-export/export-summary.json" \
  runs/thesis/source-export-summaries/jalmbench-export-summary.json
cp "$URA_CORPORA/VLSBench-export/export-summary.json" \
  runs/thesis/source-export-summaries/vlsbench-export-summary.json
sha256sum runs/thesis/source-export-summaries/*-export-summary.json \
  > runs/thesis/source-export-summaries/SHA256SUMS
```

### 3.3 Source inventory and exact input locators

The nineteen converter names and the expected operator locators are:

| Converter | Official acquisition | Point the environment variable at | Runner status |
| --- | --- | --- | --- |
| `rjudge` | `Lordog/R-Judge` | `data/` | source-specific classification |
| `mmsafety` | pinned `isXinLiu/MM-SafetyBench` + image ZIP | repository root | common harmful proxy, six policies |
| `jailbreakv` | official JailBreakV-28K data-with-images | `JailBreakV_28K.csv` beside its referenced images | common harmful image |
| `gptgeochat` | `ethanm88/GPTGeoChat` | split root containing `annotations/` and `images/` | source-specific classification |
| `agentharm` | `ai-safety-institute/AgentHarm` | directory containing `*behaviors*.json` | conversion only; exact tool grading absent |
| `strongreject` | pinned `alexandrasouly/strongreject` | `strongreject_dataset/strongreject_dataset.csv` | common harmful text |
| `bipia` | `microsoft/BIPIA` | one task `train.jsonl`/`test.jsonl` with attack companion files | conversion only; task scorer absent |
| `harmbench` | `centerforaisafety/HarmBench` | one behavior CSV; image CSV requires `multimodal_behavior_images/` | common harmful text or image |
| `vlsbench` | `Foreshhh/vlsbench` | exported `vlsbench.jsonl` beside `images/` | common harmful image |
| `mossbench` | pinned `xirui-li/MOSSBench` | repository root | common benign image refusal |
| `siuo` | `sinwang20/SIUO` + image ZIP | `data/siuo_gen.json` or `data/siuo_mcqa.json` beside `images/` | common harmful image composition |
| `advbench` | `llm-attacks/llm-attacks` | `data/advbench/harmful_behaviors.csv` | common harmful text |
| `jailbreakbench` | `JailbreakBench/JBB-Behaviors` | harmful and benign CSVs as separate arms | common harmful and benign text |
| `figstep` | `CryptoAILab/FigStep` | `data/question/safebench.csv`; images in `data/images/SafeBench/` | common harmful image |
| `cyberseceval` | `meta-llama/PurpleLlama` | one supported prompt-suite JSON/JSONL | MITRE/interpreter common; prompt injection pending scorer |
| `injecagent` | `uiuc-kang-lab/InjecAgent` | one `data/test_cases_{dh,ds}_{base,enhanced}.json` | conversion only; tool-call scorer absent |
| `mllmguard` | gated `Carol0110/MLLMGuard` | one per-dimension table beside `imgs/` | privacy/bias/toxicity/legality common; hallucination/position-swapping/noise-injection pending truthfulness scorers |
| `jalmbench` | `AnonymousUser000/JALMBench` | exported `jalmbench.jsonl` | common harmful text+audio |
| `videosafetybench` | `BAAI/Video-SafetyBench` | benign or harmful metadata JSON/JSONL beside videos | common harmful text+video |

Do not guess file names after downloading. Inspect the acquired tree, select the
official table matching the converter contract above, and run the preflight. A
missing or structurally different release is an explicit blocked source, not a
reason to edit the data until it passes.

## 4. Configure source arms and media

*Console equivalent: this section's commands are also launchable as the `source_conformance` and `run_matrix` (bounded one-arm observation dry run) form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Use the checked-in registry so the runbook and converter inventory cannot drift.
The copy is an operator-local input and may add a new reviewed release under a
new logical arm ID; do not overwrite an existing arm to point at different data.

```bash
cp experiments/rig/source-instances.example.json experiments/source-instances.json
```

Bind every selected arm to the matching official physical file. The exact known
bindings and clearly marked operator locators are below. Conversion-only arms
remain in the source inventory, but they are not placed in an ordinary scored
lane.

```bash
export URA_ADVBENCH_HARMFUL_PATH="$URA_CORPORA/llm-attacks/data/advbench/harmful_behaviors.csv"
export URA_AGENTHARM_HARMFUL_PATH='<official-AgentHarm-harmful-behaviors-json>'
export URA_AGENTHARM_BENIGN_PATH='<official-AgentHarm-benign-behaviors-json>'
export URA_BIPIA_TEST_EMAIL_PATH='<official-BIPIA-email-test-jsonl>'
export URA_BIPIA_TEST_QA_PATH='<official-BIPIA-qa-test-jsonl>'
export URA_BIPIA_TEST_ABSTRACT_PATH='<official-BIPIA-abstract-test-jsonl>'
export URA_BIPIA_TEST_TABLE_PATH='<official-BIPIA-table-test-jsonl>'
export URA_BIPIA_TEST_CODE_PATH='<official-BIPIA-code-test-jsonl>'
export URA_CYBERSECEVAL_MITRE_PATH='<PurpleLlama-mitre-json>'
export URA_CYBERSECEVAL_INTERPRETER_PATH='<PurpleLlama-interpreter-json>'
export URA_CYBERSECEVAL_INSECURE_CODING_PATH='<PurpleLlama-insecure-coding-json>'
export URA_CYBERSECEVAL_PROMPT_INJECTION_PATH='<PurpleLlama-prompt-injection-json>'
export URA_FIGSTEP_FULL_PATH="$URA_CORPORA/FigStep/data/question/safebench.csv"
export URA_GPTGEOCHAT_RELEASE_PATH="$URA_CORPORA/GPTGeoChat/human/test"
export URA_HARMBENCH_TEXT_PATH="$URA_CORPORA/HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv"
export URA_HARMBENCH_MULTIMODAL_PATH='<official-HarmBench-multimodal-behavior-csv>'
export URA_INJECAGENT_DH_BASE_PATH="$URA_CORPORA/InjecAgent/data/test_cases_dh_base.json"
export URA_INJECAGENT_DH_ENHANCED_PATH="$URA_CORPORA/InjecAgent/data/test_cases_dh_enhanced.json"
export URA_INJECAGENT_DS_BASE_PATH="$URA_CORPORA/InjecAgent/data/test_cases_ds_base.json"
export URA_INJECAGENT_DS_ENHANCED_PATH="$URA_CORPORA/InjecAgent/data/test_cases_ds_enhanced.json"
export URA_JAILBREAKBENCH_HARMFUL_PATH="$URA_CORPORA/JBB-Behaviors/data/harmful-behaviors.csv"
export URA_JAILBREAKBENCH_BENIGN_PATH="$URA_CORPORA/JBB-Behaviors/data/benign-behaviors.csv"
export URA_JAILBREAKV_FULL_PATH='<official-JailBreakV_28K.csv-beside-images>'
export URA_JALMBENCH_AUDIO_MANIFEST_PATH="$URA_CORPORA/JALMBench-export/jalmbench.jsonl"
export URA_JALMBENCH_EXPORT_SUMMARY_PATH="runs/thesis/source-export-summaries/jalmbench-export-summary.json"
export URA_MLLMGUARD_PRIVACY_PATH='<MLLMGuard-privacy-table-beside-imgs>'
export URA_MLLMGUARD_BIAS_PATH='<MLLMGuard-bias-table-beside-imgs>'
export URA_MLLMGUARD_TOXICITY_PATH='<MLLMGuard-toxicity-table-beside-imgs>'
export URA_MLLMGUARD_LEGALITY_PATH='<MLLMGuard-legality-table-beside-imgs>'
export URA_MLLMGUARD_HALLUCINATION_PATH='<MLLMGuard-hallucination-table-beside-imgs>'
export URA_MLLMGUARD_POSITION_SWAPPING_PATH='<MLLMGuard-position-swapping-table-beside-imgs>'
export URA_MLLMGUARD_NOISE_INJECTION_PATH='<MLLMGuard-noise-injection-table-beside-imgs>'
export URA_MMSAFETY_OFFICIAL_PATH="$URA_CORPORA/MM-SafetyBench"
export URA_MOSSBENCH_OFFICIAL_PATH="$URA_CORPORA/MOSSBench"
export URA_RJUDGE_RELEASE_PATH="$URA_CORPORA/R-Judge/data"
export URA_SIUO_RELEASE_PATH="$URA_CORPORA/SIUO/data/siuo_gen.json"
export URA_STRONGREJECT_OFFICIAL_PATH="$URA_CORPORA/strongreject/strongreject_dataset/strongreject_dataset.csv"
export URA_VIDEOSAFETYBENCH_BENIGN_QUERY_PATH="$URA_CORPORA/Video-SafetyBench/benign_data.json"
export URA_VIDEOSAFETYBENCH_HARMFUL_QUERY_PATH="$URA_CORPORA/Video-SafetyBench/harmful_data.json"
export URA_VLSBENCH_RELEASE_PATH="$URA_CORPORA/VLSBench-export/vlsbench.jsonl"
export URA_VLSBENCH_EXPORT_SUMMARY_PATH="runs/thesis/source-export-summaries/vlsbench-export-summary.json"
```

The BIPIA task files require their official attack companion files in the
release-relative positions expected by the converter. CyberSecEval prompt
injection and all three MLLMGuard truthfulness tasks (hallucination,
position-swapping, and noise-injection) also stay outside ordinary scored lanes:
their substantive task/truthfulness evaluators are not implemented. Run
`rig_check` after filling locators; a placeholder or layout mismatch must stop
the lane.

[13 August 2026: BIPIA `qa` and `abstract` ship only an index plus the
authors' `process.py`, which constructs the task files from external base
datasets and asserts the result against the shipped `md5.txt`. By recorded
operator decision (ledger Section 11.29) these constructions are executed
rather than blocked, marked WARNING in the acquisition logs and the console
notices. `abstract` was constructed from XSum and its `test.jsonl` MD5
matches the shipped checksum (pinned-equivalent). `qa` stays blocked until
the operator obtains the license-gated NewsQA CNN source (Microsoft
Research signup plus the NYU CNN stories, built with the Maluuba scripts);
a successful construction must likewise match `md5.txt` before the arm
leaves its blocked disposition.]

For clarity, the fifteen acquired but intentionally unscored arms are both
AgentHarm behavior sets, all five BIPIA tasks, CyberSecEval prompt injection,
all four InjecAgent sets, and all three MLLMGuard truthfulness tasks. Their
records are useful for provenance and later native-runtime integration, but a
target response without the official tool/task/truthfulness evaluator is not a
defensible result. Any separate upstream execution remains supplementary until
a complete-artifact importer exists; do not inject it into `suite_summary` as
if it were a runner cell.

Set one ordered media-root list containing every real media tree used by the
selected arms. On POSIX the separator is `:`; on Windows it is `;`. Keep the
order unchanged when resuming or relocating a run.

```bash
export URA_MEDIA_ROOTS="$URA_CORPORA/MM-SafetyBench/data/imgs:$URA_CORPORA/MOSSBench:$URA_CORPORA/JailBreakV-28K:$URA_CORPORA/GPTGeoChat:$URA_CORPORA/HarmBench:$URA_CORPORA/VLSBench-export:$URA_CORPORA/SIUO/data:$URA_CORPORA/FigStep/data:$URA_CORPORA/MLLMGuard:$URA_CORPORA/JALMBench-export:$URA_CORPORA/Video-SafetyBench"
```

### 4.1 Validate the compact source receipt

Only now, after acquisition and after the exact operator-local registry and path
bindings exist, derive the converter-owned review bindings and then write the
source receipt. The checked-in
`experiments/rig/source-instances.example.json` is a template; the exact file
used by the commands below is the ignored local copy
`experiments/source-instances.json`. Do not calculate a receipt against the
template and then change the local registry.

For each selected real arm, use a fresh one-arm observation directory. This
bounded diagnostic selects one unique source cluster (retaining all sibling rows
in that cluster), uses `MockTarget` and the offline mock-LLM fallback, and makes
no provider call. It intentionally runs before a source-conformance receipt
exists, while retaining the already established project-revision binding:

```bash
export REVIEW_ARM='strongreject_official'  # repeat for each selected real arm
export REVIEW_OUT="runs/thesis/source-review-observation/$REVIEW_ARM"
test ! -e "$REVIEW_OUT"

python -m experiments.run_matrix --dry-run \
  --corpora "$REVIEW_ARM" \
  --source-config experiments/source-instances.json \
  --attackers replay --judges rules,llm --judge-model mock \
  --limit 1 --sample-seed 0 --seeds 0 \
  --max-queries 1 --max-turns 1 \
  --out "$REVIEW_OUT"

mapfile -t REVIEW_MANIFESTS < <(
  find "$REVIEW_OUT" -maxdepth 1 -type f -name '*.manifest.json' -print
)
test "${#REVIEW_MANIFESTS[@]}" -eq 1
export REVIEW_MANIFEST="${REVIEW_MANIFESTS[0]}"
python - "$REVIEW_MANIFEST" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    audit = json.load(stream)["config"]["run"]["sampling_audit"]
fields = (
    "full_converted_corpus_sha256",
    "total_cluster_ids",
    "selected_cluster_ids",
)
print(json.dumps({field: audit[field] for field in fields}, indent=2))
PY
```

The exact emitted observation files are
`<arm>__mock__replay__<run_id>.manifest.json` and the corresponding
`<arm>__mock__replay__<run_id>.attempts.jsonl` under `REVIEW_OUT`. In the
manifest, `config.run.sampling_audit.full_converted_corpus_sha256` is the complete
pre-limit converted-corpus digest and `total_cluster_ids` is its complete unique
cluster inventory; `selected_cluster_ids` identifies the bounded cluster emitted
for review. Compare every emitted sibling row in the attempts file - including
`params.source_cluster_id`, rendered input, expected behavior, source policy, and
media references - against the retained raw source record. Only after that manual
mapping review may the operator copy the complete digest into
`reviewed_converted_corpus_sha256` and the actually reviewed unique IDs into
`reviewed_cluster_ids`. Increase `--limit` only under a documented review rule;
the digest remains for the full converted corpus, not merely the sample.

To avoid hand-typing the mechanical fields, scaffold the receipt first. The
scaffold pre-fills only what a machine can know - the registry identity, the
consumed-input digest from the exported environment path, and the semantic
review's complete corpus digest plus selected cluster IDs from the bounded
observation above - and writes every judgment field as an `OPERATOR_TODO`
placeholder under the non-receipt schema
`ura-source-conformance-scaffold/1`:

```bash
python -m experiments.source_conformance --scaffold \
  --arm "$REVIEW_ARM" \
  --observation "$REVIEW_ARM=$REVIEW_OUT" \
  --source-config experiments/source-instances.json \
  --out runs/thesis/source-conformance.scaffold.json
```

Repeat `--arm`/`--observation` for each selected arm. The scaffold is not a
receipt: validation rejects the scaffold schema name outright and also rejects
a renamed receipt while any `OPERATOR_TODO` placeholder survives (the check is
case-insensitive), so the license/access decision, raw-record reconciliation
and attributed semantic review always remain actual operator judgments. Fill
those fields, change `schema` to `ura-source-conformance/1`, save the
completed file as `runs/thesis/source-conformance.json` (the exact path the
validation block below consumes), and validate as below. The
`*.scaffold.json` file is a working draft, not evidence: delete it or move it
outside the return tree once the validated receipt exists, so the packaged
artifacts contain only the receipt that was actually admitted.

The scaffold does not find or infer exporter summaries. For `vlsbench_release`
and `jalmbench_audio`, add the exact retained `export-summary.json` to that
arm's `components` with `role`, its summary-path environment variable, `sha256`,
and `bytes`; keep the prepared JSONL separately bound as `consumed_input`.
Copy raw counts only from that summary using the reconciliation rule in section
3.2. Without a retained summary, upstream counts stay `CANNOT-VERIFY`.

Do not reuse or edit the retained 26-entry historical receipt. Nineteen entries
have no newly found issue; six mapping reviews must be replaced after a fresh
observation (`siuo_release`, `vlsbench_release`, both retained MLLMGuard
position/noise arms, and both Video-SafetyBench arms). JALMBench separately
needs a new summary-backed upstream count; VLSBench overlaps both groups. The
old source/input mapping remains historical traceability, but current RUN-002
admission requires new receipt bytes. The exact evidence boundary and receipt
digest are recorded in
[`docs/SOURCE_CONFORMANCE.md`](../docs/SOURCE_CONFORMANCE.md#historical-receipt-boundary).

The receipt is a compact operator record, not a workflow database. It may be
scoped to the real arms selected for this command, but every selected real arm
must appear and be `admitted`. Optional entries may record `blocked` or
`not_selected` operator decisions; the full 39-arm disposition table instead
joins the maintained registry/requested universe with receipts, eligibility, and
results. An admitted arm includes the observed upstream revision, split,
declared source-file hashes, license/access decision, reconciled raw-source counts, and a
reviewer-attributed bounded semantic mapping check. Unknown facts remain
`blocked` or `CANNOT-VERIFY`; they are never guessed. The normal matrix
preflight already derives converted-corpus, cluster-rule/assignment, policy, metric-mode, and
media evidence, so those runtime inventories are not copied into the receipt.
The semantic review lists the unique `reviewed_cluster_ids` selected under its
documented rule and records `reviewed_converted_corpus_sha256` for the complete
converted corpus inspected by the reviewer. Matrix admission rejects a missing
cluster or a stale review when that digest differs from the re-derived complete
corpus.

The exact compact JSON shape, including an explicitly non-empirical admitted-arm
example and the optional blocked/not-selected rule, is maintained in
[`docs/SOURCE_CONFORMANCE.md`](../docs/SOURCE_CONFORMANCE.md). Do not copy its
placeholder values. The receipt omits a source-config digest; the CLI and matrix
compute and retain the normalized digest of the selected registry entries.

One receipt may cover the union of real arms selected by all later lanes; each
matrix validates only its selected subset. Alternatively, retain one receipt per
lane and switch both `URA_SOURCE_CONFORMANCE_MANIFEST` and
`URA_SOURCE_CONFORMANCE_SHA256` to that lane's exact validated bytes before its
`rig_check` and measured `run_matrix`. Never point the two variables at different
receipts or reuse a digest after editing a receipt.

Validate the exact bytes and every declared source file, then expose that same
receipt to all later `rig_check` and `run_matrix` commands:

```bash
export SOURCE_CONFORMANCE='runs/thesis/source-conformance.json'
export SOURCE_CONFORMANCE_SHA256="$(sha256sum "$SOURCE_CONFORMANCE" | awk '{print $1}')"
python -m experiments.source_conformance \
  --manifest "$SOURCE_CONFORMANCE" \
  --sha256 "$SOURCE_CONFORMANCE_SHA256" \
  --source-config experiments/source-instances.json

export URA_SOURCE_CONFORMANCE_MANIFEST="$SOURCE_CONFORMANCE"
export URA_SOURCE_CONFORMANCE_SHA256="$SOURCE_CONFORMANCE_SHA256"
```

All later non-synthetic commands consume the two environment variables
automatically. The driver rejects a missing, blocked, registry-mismatched, or
file-mismatched selected arm before constructing a target and retains the exact
receipt in the return tree. This establishes only that the supplied operator
record and current local bytes passed the implemented checks. It does not
establish upstream authenticity, legal acceptability, benchmark validity,
evaluator validity, or model performance. See
[`docs/SOURCE_CONFORMANCE.md`](../docs/SOURCE_CONFORMANCE.md).

## 5. Configure the broad model roster

The special Fable and Sol conditions have inherent adapters:

```bash
export FABLE='anthropic-fable:claude-fable-5;effort=high;max_tokens=25000'
export SOL='openai-responses:gpt-5.6-sol;reasoning_mode=pro;reasoning_effort=medium;reasoning_context=all_turns'
```

Start from the checked-in dated registry. It records the documentation-reviewed
Anthropic, Gemini, DeepSeek, Kimi, and Qwen conditions plus the reusable Haiku
4.5 judge condition; it does not establish that a route is visible to this rig.

```bash
cp experiments/rig/api-targets.example.json experiments/api-targets.json
```

Any additional OpenAI, GLM, Doubao, regional, preview, or account-private route
is an operator-attested condition. Add its exact spec to the local JSON with
explicit `modalities`, `max_tokens`, and `temperature` only after reviewing the
account documentation, then retain it only if the bounded live checks below
return the expected served identity for every claimed modality. Examples such
as `openai:gpt-5.6-tera`, `openai:gpt-5.6-luna`, or `glm:glm-5.2` become usable
rows through that path: operator attestation of account visibility plus a
probe-confirmed served identity; the document itself cannot see any account.
Do not silently substitute another model.

Generic Claude Opus 5 and Sonnet 5 conditions require all three fields shown:
`temperature: null`, `thinking: "adaptive"`, and an explicit effort. The Haiku
4.5 row is the reusable judge condition and does not use that adaptive-thinking
contract.

Inject only the credentials for selected providers from a secret manager:

```bash
# ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY or GOOGLE_API_KEY,
# DEEPSEEK_API_KEY, MOONSHOT_API_KEY, DASHSCOPE_API_KEY, ZHIPU_API_KEY
```

If a compatible provider requires a different regional HTTPS base URL, use its
documented `URA_<PROVIDER>_BASE_URL` environment variable or the credential-free
`base_url` field accepted for compatible providers. Never embed credentials in a
URL. Record the exact non-secret route.

The generic LLM judge is loaded through the same `--api-config` path as generic
targets. Its exact `JUDGE` key must therefore remain in the JSON even when it is
not itself a model-under-test.

Define the documented candidate lanes below, then remove any condition that
does not pass section 8. Append additional account-attested specs only after
adding their config rows and completing those checks.

```bash
export TEXT_TARGETS="$FABLE,$SOL,anthropic:claude-opus-5,anthropic:claude-sonnet-5,google:gemini-3.6-flash,deepseek:deepseek-v4-pro,kimi:kimi-k3,qwen:qwen3.7-max-2026-06-08"
export IMAGE_TARGETS="$FABLE,$SOL,anthropic:claude-opus-5,anthropic:claude-sonnet-5,google:gemini-3.6-flash,kimi:kimi-k3,qwen:qwen3.7-max-2026-06-08"
export RICH_TARGET='google:gemini-3.6-flash'
export JUDGE='anthropic:claude-haiku-4-5-20251001'

export OPERATOR_TEXT_TARGETS=''
export OPERATOR_IMAGE_TARGETS=''
if [[ -n "$OPERATOR_TEXT_TARGETS" ]]; then export TEXT_TARGETS="$TEXT_TARGETS,$OPERATOR_TEXT_TARGETS"; fi
if [[ -n "$OPERATOR_IMAGE_TARGETS" ]]; then export IMAGE_TARGETS="$IMAGE_TARGETS,$OPERATOR_IMAGE_TARGETS"; fi
```

Remove a target from a lane if its probe did not produce a complete, correctly
resolved response. A local preflight cannot establish remote entitlement.

### 5.1 Funded campaign roster (operator decision, 13 August 2026)

The first campaign's roster is fixed by recorded operator decision (thesis
ledger Section 11.22); this subsection mirrors it so the rig operator does
not have to consult the thesis repository mid-campaign. It narrows the
candidate lanes above; it never adds a route the section 8 gates have not
confirmed.

- Focal pair: the Fable and Sol conditions above; both are measured targets.
- Hosted judge: `anthropic:claude-haiku-4-5-20251001`. The judge model is
  excluded as a target (self-judgment bias); its registry row exists only as
  the judge condition.
- Anthropic breadth: `anthropic:claude-sonnet-5`; add `anthropic:claude-opus-5`
  only if the prepaid budget, conservative call projection, and the canary's
  exact observed token-derived spend support the operator decision.
- OpenAI breadth: at most one additional row beyond Sol - a budget cap, not
  an availability doubt. The operator attests GPT-5.6 Tera, GPT-5.6 Luna,
  and GPT-5.5 are visible on the account; the section 8 probe records each
  exact served route id before its config row is added. The prepaid budget,
  conservative call projection, and exact observed canary spend determine the
  operator's choice; one cluster is not multiplied into a campaign estimate.
- Google: `google:gemini-3.6-flash`, the only funded rich-media hosted row.
- Moonshot: one to two Kimi snapshots (`kimi:kimi-k3` plus at most one
  additional account-visible snapshot).
- DeepSeek: `deepseek:deepseek-v4-pro`, text lane only.
- Hosted GLM: structural `N/A` for this campaign - no payable API route
  exists for this operator, nothing substitutes for it, and a
  third-party-hosted deployment would measure a different serving condition.
- Hosted Qwen (`qwen:qwen3.7-max-2026-06-08`): registry-documented but
  unfunded; it stays out of the campaign lanes unless the operator records a
  funding decision for it.
- Local lane priority: Qwen3-VL first, then the LLaVA base/RR same-base
  defense pair. A local GLM open-weight condition was considered and dropped:
  flagship open checkpoints exceed the 2x24 GB rig even quantized.
- Chat-product subscriptions and agent-product wrappers are never experiment
  routes; all measured traffic uses direct API keys under the declared
  request controls.

Every funded row remains subject to the section 8 gates: a lane that fails
its attestation probe or canary is removed, never substituted.

### 5.2 Budget-bounded lane sampling (operator decision, 13 August 2026)

Frontier hosted conditions (the Fable and Sol focal pair above all) would
consume the prepaid budgets far too quickly at full corpus size, so the
campaign runs two pre-registered population tiers:

- Local lanes run the full converted corpora: target calls cost only local
  GPU time.
- Hosted API lanes run a bounded cluster subsample of each corpus, fixed
  prospectively by `--limit` and a recorded `--sample-seed` before any
  outcome is inspected. The sampling audit in every manifest retains the
  full-corpus digest, the complete cluster inventory, and the exact
  selected clusters, so the subsample is reproducible and reviewable.
- Comparability: with identical corpus, `--limit`, and `--sample-seed`,
  every hosted condition receives the identical cluster subset. A
  local-versus-hosted comparison restricts to the intersection of their
  cluster sets, which is exactly that pre-registered subset. Pooled rates
  across the two population tiers remain forbidden - different
  denominators; the compatibility rules already refuse them. The
  full-corpus local lanes double as an internal check of the design: on a
  local model, the subset estimate can be compared with the full-corpus
  estimate to quantify the subsampling error empirically.
- Judge budget: the hosted Haiku judge is metered on every judged response
  regardless of whether the target is local, so full-corpus local lanes
  cannot default to hosted LLM judging. Full local corpora score through
  the deterministic rules stage; the hosted LLM-judge stage runs on the
  pre-registered common subset (identical to the hosted lanes) unless
  post-canary projections show budget for more. Rules-only and cascade
  evaluator modes are distinct compatibility keys and are never pooled.
- Exact per-lane limits and call caps are fixed after the section 9.1
  diagnostic canaries from the prepaid budgets, conservative call projection,
  and exact observed usage/spend, and are recorded before any
  measured lane starts. [13 August 2026: the operator delegated setting
  these limits to the campaign agent, bounded by the operator-recorded
  prepaid provider budgets (ledger Section 11.27); the limits remain
  prospective and recorded, and the delegation does not extend to any
  other operator-only judgment.] Audio and video remain hosted-only and
  already bounded (section 10.3).

## 6. Configure scoring and optional defense guards

The scoring guard parser currently implements the Llama-Guard output shape. Set
an exact accessible model revision and load it before paid calls.

```bash
export SCORE_GUARD='meta-llama/Llama-Guard-3-8B'
export SCORE_GUARD_REV='7327bd9f6efbbe6101dc6cc4736302b3cbb6e425'
export SCORE_GUARD_DEVICE='cuda:1'

python -c "import os; from huggingface_hub import snapshot_download; snapshot_download(repo_id=os.environ['SCORE_GUARD'], revision=os.environ['SCORE_GUARD_REV'], token=os.environ.get('HF_TOKEN'))"
```

For the optional text-only defense lane, use a different Llama-Guard-family model
identity and explicit device. Do not use either guard as the model under test or
as the hosted LLM judge.

```bash
export DEFENSE_GUARD='meta-llama/Llama-Guard-3-1B'
export DEFENSE_GUARD_REV='acf7aafa60f0410f8f42b1fa35e077d705892029'
export DEFENSE_GUARD_DEVICE='cuda:1'

python -c "import os; from huggingface_hub import snapshot_download; snapshot_download(repo_id=os.environ['DEFENSE_GUARD'], revision=os.environ['DEFENSE_GUARD_REV'], token=os.environ.get('HF_TOKEN'))"
```

## 7. Configure local models: one model per process

The current local vLLM and Ollama renderers support text and image, not audio or
video. At CLI invocation, and once at rig-console startup, URA queries
`nvidia-smi` for each NVIDIA card's index, model, total VRAM, PCI id, compute
capability and driver, plus aggregate/max-card VRAM. The dashboard displays that
inventory together with the platform, CPU model, physical/logical core counts
and total RAM detected through `psutil` with harmless fallbacks. The local model
roster shows parameter count and basis, estimated versus usable VRAM, fit,
resolved quantization, recommended tensor parallelism, and whether multi-GPU
support was declared or assumed. No provider/model call is made by this
inventory. `python -m experiments.local_targets` prints the GPU/profile data for
CLI inspection.

In the Build tab, hosted targets have a provider selector whose default is
`All`. Local vLLM targets have four combinative presentation filters: an
immediate case-insensitive name substring, one synchronized slider/numeric
maximum from 0.01B (10M) to 3000B (3T), and a visually separate `Automatic
16/8/4-bit fit` card selected by default, plus an unchecked `Include unknown
fit` control. Known recommendations use green for 16-bit, blue for 8-bit, and
amber for 4-bit; unknown fit uses neutral gray. The
per-model selector labels 16-bit BF16/FP16, 8-bit FP8 and the 4-bit backends.
Compatible rows are single-choice radios and remain selectable when their
revision is `OPERATOR_TODO`; a non-dry submission still requires an exact
revision/digest before starting a subprocess. Filters do not replace
server-side hardware/revision admission.
Expert/MoE-ambiguous identifiers (for example Mixtral expert counts,
Llama-4 `E` counts, or `MoE`) do not produce a guessed dense parameter total.
They stay fit-unknown and hidden unless `Include unknown fit` is selected or the
roster has an exact `parameter_count_b`; no download or fit is claimed from the
name.

Automatic fit is deliberately simple and conservative: after the configured
`gpu_memory_utilization`, it budgets 2.2 GiB per billion parameters for
unquantized weights/runtime headroom, 1.15 for FP8, and 0.57 for 4-bit
BitsAndBytes/AWQ/GPTQ. Hardware auto-selection uses the highest fitting
precision: unquantized 16-bit BF16/FP16 first, FP8 8-bit next when every selected
card has compute capability 7.5 or newer, then in-flight BitsAndBytes 4-bit when
every selected card has compute capability 7.0 or newer. AWQ/GPTQ remain explicit
choices for matching pre-quantized checkpoints. Hardware-auto does not admit an
unknown-fit model. For that case only, choosing an explicit per-model value
(`none`, `fp8`, `bitsandbytes`, `awq`, or `gptq`) binds
`allow_unknown_fit: true` and permits an operator-owned live load attempt. It is
not a fit claim or allocation guarantee. Missing hardware, a known non-fit, or
invalid tensor parallelism still fails before engine construction.
Missing/incompatible FP8 or BitsAndBytes support fails during
local preflight before target/judge calls; the setup import check above catches
the ordinary missing dependency earlier. The estimate is not an allocation
guarantee: the local preflight must still load the exact revision at the
selected context and serving settings.

Precedence is per-model `quantization` in `--local-config`, then the command's
`--quantization` override, then hardware auto-selection. A missing
`multi_gpu_compatible` field means supported by assumption and is labelled
`assumed`; set it to `false` for a known single-GPU-only model. When a compatible
model exceeds one usable card, automatic tensor parallelism uses the detected
card count needed for the estimate. The resolved hardware, quantization and
tensor-parallel configuration enter normal local-config, grid and run
provenance.

The vLLM local-config field `allow_unknown_fit` is an optional boolean, default
`false`. It is valid only with an explicit per-model `quantization` value from
`none`, `fp8`, `bitsandbytes`, `awq`, or `gptq`; `auto` is rejected. The builder
sets it only for an unknown-fit row with an explicit per-model choice. It never
overrides `fits: false` or the immutable revision/digest requirement.

Concrete rig example: two RTX 4090 cards reported as 24,564 MiB each provide
about 47.98 GiB physical and 40.78 GiB usable VRAM at utilization 0.85. A 70B
model is estimated at 39.9 GiB with 4-bit BitsAndBytes, so the roster shows it
only with mandatory in-flight 4-bit quantization and tensor parallelism 2; its
80.5-GiB FP8 estimate does not fit this rig.
Declaring that model multi-GPU-incompatible makes it a non-fit instead. With an
8B-class target, tensor parallelism 1 normally leaves the second GPU for the
scoring guard; a two-GPU target leaves no GPU for that guard and is therefore a
different execution condition.

The local preflight loads the one target base engine before it constructs the
scoring or defense guards. A successful preflight therefore tests the actual
single-process memory layout; do not start a second target server beside it.

Create a separate local config for each selected model because the file keys must
exactly match that command's `--local` value. Replace each revision with the
actual full Hugging Face commit.

Resolve and cache the exact reviewed revisions before starting vLLM:

```bash
export REF_LOCAL_QWEN3_VL='60595ebc30ec8e3b1d3b9e65d4943ca011c0006a'
export REF_LOCAL_LLAVA_BASE='2424fdd47412fccc66d91719126b420e9fbd7065'
export REF_LOCAL_LLAVA_RR='d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e'

hf download Qwen/Qwen3-VL-8B-Instruct --revision "$REF_LOCAL_QWEN3_VL"
hf download llava-hf/llava-v1.6-mistral-7b-hf --revision "$REF_LOCAL_LLAVA_BASE"
hf download GraySwanAI/llava-v1.6-mistral-7b-hf-RR --revision "$REF_LOCAL_LLAVA_RR"
```

Put those same revision strings into the three local JSON files below.

`experiments/local-qwen3-vl.json`:

```json
{
  "vllm:Qwen/Qwen3-VL-8B-Instruct": {
    "revision": "60595ebc30ec8e3b1d3b9e65d4943ca011c0006a",
    "modalities": ["text", "image"],
    "tensor_parallel_size": 1,
    "gpu_memory_utilization": 0.85,
    "max_tokens": 4096
  }
}
```

`experiments/local-llava-base.json`:

```json
{
  "vllm:llava-hf/llava-v1.6-mistral-7b-hf": {
    "revision": "2424fdd47412fccc66d91719126b420e9fbd7065",
    "modalities": ["text", "image"],
    "tensor_parallel_size": 1,
    "gpu_memory_utilization": 0.85,
    "max_tokens": 4096
  }
}
```

`experiments/local-llava-rr.json`:

```json
{
  "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR": {
    "revision": "d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e",
    "modalities": ["text", "image"],
    "tensor_parallel_size": 1,
    "gpu_memory_utilization": 0.85,
    "max_tokens": 4096
  }
}
```

Download each exact revision in advance. Local text and image runs for each model
remain separate commands so vLLM releases its target weights between processes.

## 8. Offline checks and bounded live modality attestations

*Console equivalent: this section's commands are also launchable as the `run_matrix`, `rig_check`, `live_attestation`, `lane_canary`, `level1_evidence` and `figures` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Run the full offline regression first:

```bash
python -m pytest -p no:cacheprovider
python -m ruff check --no-cache .
python -m compileall src experiments
env -u URA_PROJECT_REVISION_MANIFEST -u URA_PROJECT_REVISION_SHA256 \
python -m experiments.run_matrix --dry-run \
  --attackers replay,crescendo --judges rules,llm \
  --corpora synth --limit 12 --seeds 0,1 \
  --max-queries 4 --max-turns 4 --out runs/thesis/diagnostics/dry
python -m experiments.figures --synth --out runs/thesis/diagnostics/figure-check
```

### 8.1 Explicit zero-human synthetic paths

Synthetic paths are available without a human audit, but none produces a
benchmark result or human-validity claim.

**A. Fully synthetic/offline.** The `--dry-run --corpora synth` command above
uses `MockTarget` plus automated rule and mock-LLM fixture paths. The explicit
environment removal records
`project_revision.mode=not_required_diagnostic_dry_run`; it makes no
provider call and requires no source acquisition, source receipt, or human
rating. Its artifacts demonstrate only schema, orchestration, persistence,
budget, and automated-fixture behavior.

For the smallest fully synthetic, explicitly typed one-cluster canary, run the
following exact command. `mock` is allowed here only because
`--diagnostic-canary --dry-run --corpora synth` fixes the evidence as diagnostic;
never configure a mock judge in a non-dry or measured command.

```bash
export SYNTH_CANARY_ROOT='runs/thesis/diagnostics/canary-synthetic-offline'

env -u URA_PROJECT_REVISION_MANIFEST -u URA_PROJECT_REVISION_SHA256 \
python -m experiments.run_matrix \
  --diagnostic-canary --dry-run \
  --attackers replay --judges rules,llm --judge-model mock \
  --corpora synth --limit 1 --sample-seed 0 --seeds 0 \
  --max-queries 1 --max-turns 1 \
  --out "$SYNTH_CANARY_ROOT"

SYNTH_CANARY_ELIGIBILITY="$(find "$SYNTH_CANARY_ROOT" -maxdepth 1 -type f \
  -name 'eligibility-*.eligibility.json' -print -quit)"
test -n "$SYNTH_CANARY_ELIGIBILITY"

python -m experiments.lane_canary \
  --results "$SYNTH_CANARY_ROOT" \
  --eligibility "$SYNTH_CANARY_ELIGIBILITY" \
  --out-dir "$SYNTH_CANARY_ROOT"
```

The first command makes no provider call and needs no credentials, source
acquisition, source receipt, or human work. Before any mock target execution it
persists the exact content-addressed `ura-lane-projection/1`; the second command
makes no call and writes a content-addressed `ura-lane-canary/1`. Inspect its
`evidence_class=synthetic_offline`, `campaign_authorized=false`, and
`empirical_benchmark_evidence=false`, together with
`project_revision.mode=not_required_diagnostic_dry_run`. The mock full-shadow
decision path proves
only fixture and pipeline behavior. This typed canary is intentionally rejected
by Level-1, figures, suite summary, paired/transfer analysis, and human-audit
preparation; use the broader diagnostic dry-run below only for the separate
Level-1 lifecycle check.

If the real-source receipt environment variables from section 4.1 remain
exported, a synthetic-only invocation ignores them with an explicit warning; it
does not validate or import real-source evidence.

The same zero-human artifacts can exercise the Level-1 join. Run this once after
the fully offline `run_matrix` command above, using its one emitted eligibility
plan:

```bash
DRY_ELIGIBILITY="$(find runs/thesis/diagnostics/dry -maxdepth 1 -type f \
  -name 'eligibility-*.eligibility.json' -print -quit)"
test -n "$DRY_ELIGIBILITY"

python -m experiments.level1_evidence \
  --eligibility "$DRY_ELIGIBILITY" \
  --results runs/thesis/diagnostics/dry \
  --out-json runs/thesis/diagnostics/level1-offline.json \
  --out-csv runs/thesis/diagnostics/level1-offline.csv
```

Outputs are create-only; delete neither measured nor retained evidence to reuse
a name, but choose a new diagnostic name when repeating this check. The JSON
must report `evidence_kind=diagnostic_dry_run`,
`contains_diagnostic_dry_run=true`, and
`empirical_validity_established=false`. It validates only the planning/grid/
judgment lifecycle and deterministic export. It supplies no attestation,
analysis-inclusion, source-release, provider, human-validity, or benchmark
evidence.

**B. Synthetic/live target transport with no human step.** This path sends only
synthetic fixtures to one selected real target and uses only the deterministic
rule stage to complete the typed response trail. It requires target credentials
and makes real target calls, but needs no acquired source, source-conformance
receipt, or human audit. The rule labels are diagnostic and carry no scientific
validity claim. Choose one non-secret
operator label for the account/project/region/runtime context and reuse it
verbatim in the probe, receipt producer, and later measured grid:

```bash
export EXECUTION_SCOPE_ID='rig-a-account-project-region'
export TARGET='<one-exact-live-target-spec>'
export TARGET_LABEL='<short-logical-label>'
export TEXT_PROBE_ROOT="runs/thesis/attestation/$TARGET_LABEL/synthetic-text"
export TEXT_RECEIPT="runs/thesis/attestation/receipts/$TARGET_LABEL-synthetic-text.json"

python -m experiments.run_matrix \
  --attestation-probe --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora synth --limit 1 --sample-seed 0 --seeds 0 \
  --max-queries 1 --max-turns 1 \
  --max-total-target-calls 1 \
  --max-total-http-attempts 4 --deadline-seconds 900 \
  --out "$TEXT_PROBE_ROOT"

python -m experiments.live_attestation \
  --probe-root "$TEXT_PROBE_ROOT" \
  --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --out "$TEXT_RECEIPT"
export TEXT_RECEIPT_SHA256="$(sha256sum -- "$TEXT_RECEIPT" | awk '{print $1}')"
test "${#TEXT_RECEIPT_SHA256}" -eq 64
```

For a target declared image-capable, `--limit 2` includes the text fixture and
the verified text+one-pixel-image fixture. It can therefore emit separate exact
text and text+image receipt records while retaining a two-call ceiling:

```bash
export IMAGE_PROBE_ROOT="runs/thesis/attestation/$TARGET_LABEL/synthetic-text-image"
export IMAGE_RECEIPT="runs/thesis/attestation/receipts/$TARGET_LABEL-synthetic-text-image.json"

python -m experiments.run_matrix \
  --attestation-probe --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora synth --limit 2 --sample-seed 0 --seeds 0 \
  --max-queries 1 --max-turns 1 \
  --max-total-target-calls 2 \
  --max-total-http-attempts 8 --deadline-seconds 900 \
  --out "$IMAGE_PROBE_ROOT"

python -m experiments.live_attestation \
  --probe-root "$IMAGE_PROBE_ROOT" \
  --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --out "$IMAGE_RECEIPT"
export IMAGE_RECEIPT_SHA256="$(sha256sum -- "$IMAGE_RECEIPT" | awk '{print $1}')"
test "${#IMAGE_RECEIPT_SHA256}" -eq 64
```

The producer performs no provider call. It strictly revalidates the completed
single-cell probe and emits create-only `ura-live-attestation/2` JSON. Its UTC
observation is the probe Runner manifest's content-bound `started_at`, a
conservative lower bound on the successful transport event; mutable outer-grid
`finished_at` metadata is not trusted as receipt time. Inspect the receipt and
confirm its exact `requested_target_spec`, `resolved_target`,
`route_config_sha256`, `exact_input_modalities`, realized identity, and probe
artifact/harness/driver hashes before approval. A text+image record does not
cover text alone. A harness or driver source change requires a new probe.

The synthetic image has no image-safety semantics. Synthetic tool calls are
inert and never executed. There is no synthetic audio or video fixture. These
two paths are fully automated after credentials/configuration are present, but
they are target-route/byte-transport diagnostics only. They prove neither the
judge path nor safety, evaluator, benchmark, human validity, account equivalence,
or future route availability. Exclude their probe grids from benchmark
estimates, comparisons, human-validity claims, Level-1 measured requests, and
figures. A later real-source run still needs the source-conformance receipt and
operator reviews in [section 4.1](#41-validate-the-compact-source-receipt).

**C. Real-source audio/video and optional source-native transport probes.** Run
one bounded check per exact target and exact input combination where no synthetic
fixture exists or source-native transport is part of the claim. Use a stable
label that contains no secret or path. The real source-conformance environment
variables from section 4.1 remain mandatory.

```bash
export TARGET='<one-exact-target-spec>'
export TARGET_LABEL='<short-logical-label>'
export PROBE_ARM='jalmbench_audio'  # or videosafetybench_harmful_query
export PROBE_MODALITY='audio'       # or video; a directory label only
export PROBE_ROOT="runs/thesis/attestation/$TARGET_LABEL/real-$PROBE_MODALITY"
export PROBE_RECEIPT="runs/thesis/attestation/receipts/$TARGET_LABEL-real-$PROBE_MODALITY.json"

python -m experiments.rig_check \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora "$PROBE_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --max-total-target-calls 16 \
  --max-total-http-attempts 64 --deadline-seconds 3600 \
  --out "runs/thesis/preflight/attestation/$TARGET_LABEL/$PROBE_MODALITY"

python -m experiments.run_matrix \
  --attestation-probe --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora "$PROBE_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --max-total-target-calls 16 \
  --max-total-http-attempts 64 --deadline-seconds 3600 \
  --out "$PROBE_ROOT"

python -m experiments.live_attestation \
  --probe-root "$PROBE_ROOT" \
  --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --out "$PROBE_RECEIPT"
export PROBE_RECEIPT_SHA256="$(sha256sum -- "$PROBE_RECEIPT" | awk '{print $1}')"
test "${#PROBE_RECEIPT_SHA256}" -eq 64
```

For hosted text/image, the synthetic path above is the smallest no-human
transport option; a real StrongREJECT or MM-SafetyBench probe is optional when
source-specific route behavior itself is being checked. Repeat the real-source
pattern for every planned audio/video-capable target. Fable and Sol do not
require entries in `api-targets.json`; generic targets and a generic LLM judge
do. For a local target, substitute `--local` plus its exact `--local-config` and
run one process at a time. Local audio/video claims are unsupported.

## 9. Plan lanes with the no-call rig check

*Console equivalent: this section's commands are also launchable as the `rig_check`, `run_matrix`, `live_attestation` and `lane_canary` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Every measured grid below must first be passed with the same grid-defining
arguments to `python -m experiments.rig_check`. It loads and validates sources
and media, loads a local target engine before scoring/defense guards when a
local target is selected, checks model/source modality compatibility, and prints
policy-stratum counts plus projected target, guard, LLM-judge, and HTTP-attempt
totals without a hosted generation call. Only the planning ceilings differ from
the later measured command. `rig_check` executes the no-call plan in temporary
scratch storage but validates and copies both its content-addressed
eligibility/`N/A` ledger and `ura-lane-projection/1` into the requested `--out`
directory, including when a later compatibility gate fails. A successful exact
measured invocation creates and binds its own projection after whole-request
admission and before its first generation call. These artifacts are planning
evidence only and are not live attestations.
`rig_check` and `run_matrix --dry-run` neither require nor accept
`--execution-scope-id` or live-attestation arguments.
The preflight is nevertheless non-dry internally and therefore requires the
environment-bound project-revision receipt from section 2; `rig_check` verifies
that the forwarded request retained it. Every non-dry probe, canary, and measured
command below inherits the same two environment variables.

Keep every no-call `rig_check` output under `runs/thesis/preflight/<lane>` and
every measured `run_matrix` output under `runs/thesis/runner/<lane>`. Whenever a
lane below says to repeat a check with `run_matrix`, change both the module name
and that output prefix. Never give the Level-1 join a preflight-only plan: its
selected cohort is the measured `runner/` tree. The separate live transport
probes remain under `attestation/` and are also excluded from that join.

Before each measured lane, build a Bash array from the already approved receipt
files and digests that cover every exact requested target and exact modality
combination compatible in that lane. Do not add a receipt merely because it is
nearby: text, text+image, text+audio, and text+video are distinct combinations,
and route-config changes require a new probe. Do not supply overlapping records:
the two-row synthetic text+image receipt already contains both a text record and
a text+image record for that target, so it replaces rather than accompanies the
one-row text receipt when both combinations are needed. The following example
uses that single receipt; a text-only lane uses `TEXT_RECEIPT` instead. Extend
both arrays positionally for the lane's other targets or real audio/video
receipts:

```bash
export LIVE_ATTESTATION_MAX_AGE_HOURS='24'  # prospective operator policy
LIVE_ATTESTATION_FILES=("$IMAGE_RECEIPT")
LIVE_ATTESTATION_SHA256=("$IMAGE_RECEIPT_SHA256")
test "${#LIVE_ATTESTATION_FILES[@]}" -eq "${#LIVE_ATTESTATION_SHA256[@]}"

LIVE_ATTESTATION_ARGS=(
  --execution-scope-id "$EXECUTION_SCOPE_ID"
  --live-attestation-max-age-hours "$LIVE_ATTESTATION_MAX_AGE_HOURS"
)
for i in "${!LIVE_ATTESTATION_FILES[@]}"; do
  receipt="${LIVE_ATTESTATION_FILES[$i]}"
  digest="${LIVE_ATTESTATION_SHA256[$i]}"
  test "$(sha256sum -- "$receipt" | awk '{print $1}')" = "$digest"
  LIVE_ATTESTATION_ARGS+=(
    --live-attestation "$receipt" --live-attestation-sha256 "$digest"
  )
done
```

Append `"${LIVE_ATTESTATION_ARGS[@]}"` to **every** measured `run_matrix`
invocation below, never to `rig_check`. The driver retains content-addressed
copies and fails before target calls if any compatible planning row lacks a
fresh exact receipt. Its first newly executed or restored response must also
match the receipt's stable realized provider/runtime identity. The non-secret
scope is an operator assertion; account/project/region equivalence remains
CANNOT-VERIFY. The receipt establishes target-route/access/byte-backed transport
only, not judge execution, judge validity, safety, benchmark validity, human
validity, or future availability.

### 9.1 One-cluster live diagnostic canary

Run a live canary only after a canary-specific
`CANARY_LIVE_ATTESTATION_ARGS` array, constructed by the receipt loop above,
covers the exact target route and delivered input combination without unrelated
or overlapping receipt records. To construct it, re-run the section 9 receipt
loop with `LIVE_ATTESTATION_FILES`/`LIVE_ATTESTATION_SHA256` restricted to the
canary target's exact receipt(s), then copy the result:
`CANARY_LIVE_ATTESTATION_ARGS=("${LIVE_ATTESTATION_ARGS[@]}")`. Target-transport receipts do not attest the
hosted judge. The canary must therefore actually reach every intended hosted
judge route, or report it as `not_exercised`. Use the intended lane's complete
target, source, attacker/config, defense, judge/guard, grouping, and query/turn
configuration; reduce only the target inventory to one exact target, the seed
inventory to one seed, and the deterministic cluster limit to one. The static
full-cascade pattern is:

```bash
export CANARY_TARGET='<one-exact-target-from-the-lane>'
export CANARY_ARM='<one-exact-logical-source-arm-from-the-lane>'
export CANARY_ROOT="runs/thesis/diagnostics/canary-live/$CANARY_ARM"
export CANARY_PREFLIGHT_ROOT="runs/thesis/preflight/canary-live/$CANARY_ARM"

# No-call rehearsal. Use provisional operator ceilings large enough to admit
# the complete one-cluster projection, then inspect the retained projection.
python -m experiments.rig_check \
  --api "$CANARY_TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" \
  --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$CANARY_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<operator-planning-ceiling>' \
  --max-total-judge-calls '<operator-planning-ceiling>' \
  --max-total-http-attempts '<operator-planning-ceiling>' \
  --deadline-seconds 3600 --out "$CANARY_PREFLIGHT_ROOT"

# Set these from the retained one-cluster conservative projection. Each value
# must cover its complete projected total; record operator approval first.
export CANARY_TARGET_CAP='<complete-canary-projected-target-total>'
export CANARY_JUDGE_CAP='<complete-canary-projected-judge-total>'
export CANARY_HTTP_CAP='<complete-canary-projected-http-total>'

python -m experiments.run_matrix \
  --diagnostic-canary "${CANARY_LIVE_ATTESTATION_ARGS[@]}" \
  --api "$CANARY_TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" \
  --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$CANARY_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls "$CANARY_TARGET_CAP" \
  --max-total-judge-calls "$CANARY_JUDGE_CAP" \
  --max-total-http-attempts "$CANARY_HTTP_CAP" \
  --deadline-seconds 3600 --out "$CANARY_ROOT"

CANARY_ELIGIBILITY="$(find "$CANARY_ROOT" -maxdepth 1 -type f \
  -name 'eligibility-*.eligibility.json' -print -quit)"
test -n "$CANARY_ELIGIBILITY"
python -m experiments.lane_canary \
  --results "$CANARY_ROOT" --eligibility "$CANARY_ELIGIBILITY" \
  --out-dir "$CANARY_ROOT"
```

The real-source receipt variables from section 4.1 are mandatory. For an
adaptive, guarded, classification, or multimodal lane, replace the static
arguments above with that lane's exact substantive configuration; do not make a
cheaper canary a claim that an unexercised attacker, defense, evaluator, judge,
or modality is reachable. Inspect the summary for
`evidence_class=live_diagnostic`, exercised/not-exercised roles, observed
artifact bytes and canary-local latency records, local
decided/abstained/non-evaluable
support, and client-reported target/judge transport attempts. Its reserved
logical calls and HTTP-attempt exposure are separate conservative quantities.
Missing client reporting is `CANNOT-VERIFY`.

The summary is not campaign approval. Do not proceed until the operator has
reviewed the exact projection and canary, recorded approved call/deadline/storage
limits, and configured provider-side quota. The console automatically reports
the canary's exact completion-bound token usage and, when all required
effective-dated rates exist, its exact token-derived spend. That observed spend
is not an estimate. Do not multiply one cluster into a campaign cost estimate.
Choose caps from prepaid budgets, the conservative call projection, and an
operator decision. Do not infer throughput, expected full-lane storage, safety,
or population validity from one cluster.
Keep the entire canary tree under `diagnostics/`: Level-1, figures, suite summary,
paired/transfer analysis, and human-audit preparation reject it.

On Windows, the durable call-budget ledger retries the same fsynced atomic
replacement for at most 100 ms when a scanner or filesystem filter briefly
holds the prior ledger. Persistent denial still stops the grid before another
external call; never delete or hand-edit the ledger to bypass that stop.

For planning, use finite positive values that cover the complete conservative
projection. Copy at least the printed projection into the measured command's
lane-specific ceilings; add capacity only when explicitly justified in the run
note. Every non-dry provider-backed command fails before a provider call if any
logical target/model-judge/declared HTTP-attempt cap is below its complete
projection. Do not use an undersized cap to create a paid partial grid. Do not
reuse one lane's ledger or ceilings for another lane. Before a campaign, record
operator approval and configure an isolated provider project/account hard quota
no greater than the approved exposure; the Runner ledger cannot prove or impose
that provider-side quota.

The projection's call and HTTP values are conservative reserved exposure, not
observed provider traffic. It inventories selected physical input-media bytes
when available. Token usage, monetary price/cost, runtime/throughput, and
expected output storage remain `CANNOT-VERIFY`; do not extrapolate them from the
projection. A canary summary may report actual retained artifact bytes and
client-reported transport attempts for that canary only. Completion-bound
artifacts additionally provide exact observed token usage; the console may turn
that usage into exact observed spend when the required effective-dated prices
exist. Neither quantity is a measured full-lane total and neither is multiplied
into a campaign estimate. Campaign limits come from prepaid budgets, the
conservative call projection, and the operator decision; throughput and storage
remain unknown until observed.

Common arguments for the full cascade are shown here for reference:

```text
--api-config experiments/api-targets.json
--source-config experiments/source-instances.json
--judges rules,guardrail,llm --judge-model "$JUDGE"
--guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV"
--guardrail-device "$SCORE_GUARD_DEVICE"
--group model,risk,effective_modality,source_policy_id,source_policy_version
```

Use whole source-cluster sampling. `--limit 0` means the complete selected
release; `--limit N` retains every row in each of at most N selected clusters.
For the same real converted-corpus digest and `--sample-seed`, limits are nested
prefixes of one deterministic cluster ordering: the `--limit 1` canary cluster
is contained in a later `--limit N` selection. This continuity is operational,
not evidence that one cluster represents the population.

## 10. Tier 1: broad static replay

*Console equivalent: this section's commands are also launchable as the `rig_check` and `run_matrix` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Static replay is the coverage backbone. It is where the broad model roster is
actually measured, rather than merely listed.

### 10.1 Text roster

The text lane includes harmful and benign behavior sources, but the aggregator
keeps their denominators separate.

```bash
export TEXT_ARMS='strongreject_official,advbench_harmful,jailbreakbench_harmful,jailbreakbench_benign,harmbench_text,cyberseceval_mitre,cyberseceval_interpreter,cyberseceval_insecure_coding'

python -m experiments.rig_check \
  --api "$TEXT_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds 7776000 \
  --out runs/thesis/preflight/static-text

python -m experiments.run_matrix \
  "${LIVE_ATTESTATION_ARGS[@]}" \
  --api "$TEXT_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<projected-target-total>' --max-total-judge-calls '<projected-judge-total>' \
  --max-total-http-attempts '<projected-http-total>' --deadline-seconds 7776000 \
  --out runs/thesis/runner/static-text
```

Replace the bracketed values with positive integers before invoking either
command. The first command's values are operator capacity bounds; the second
command's values come from the successful no-call projection.

### 10.2 Image roster

Add the four common-eligible MLLMGuard safety dimensions as separate arms. Keep
MOSSBench's benign refusal endpoint separate from harmful image ASR. The three
MLLMGuard truthfulness tasks stay in the conversion-only inventory.

```bash
export IMAGE_ARMS='mmsafety_official,jailbreakv_full,harmbench_multimodal,vlsbench_release,mossbench_official,siuo_release,figstep_full,mllmguard_privacy,mllmguard_bias,mllmguard_toxicity,mllmguard_legality'

# Run rig_check first, then run_matrix with the same arguments and exact printed ceilings.
python -m experiments.rig_check \
  --api "$IMAGE_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$IMAGE_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds 7776000 \
  --out runs/thesis/preflight/static-image
```

After the check succeeds, replace `experiments.rig_check` with
`experiments.run_matrix` and replace all three planning ceilings with the printed
totals; append `"${LIVE_ATTESTATION_ARGS[@]}"` and write the measured grid to
`runs/thesis/runner/static-image`. Automated
stages do not inspect image pixels: for released image sources
they grade the target output with the source-provided safety reason/reference,
and record that proxy explicitly. Media-aware human review remains the validity
check; rows without a defensible source reference are not admitted to common
automated metrics.

### 10.3 Audio and video

Use only targets whose exact live checks succeeded for these modalities. Under
the maintained adapters, the planned rich-media target is the operator-attested
Gemini route.

```bash
# Audio
export AUDIO_SAMPLE_CLUSTERS=5000
python -m experiments.rig_check \
  --api "$RICH_TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora jalmbench_audio --source-config experiments/source-instances.json \
  --limit "$AUDIO_SAMPLE_CLUSTERS" --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds 7776000 \
  --out runs/thesis/preflight/static-audio

# Video: the benign-query and harmful-query releases are both harmful joint-input probes.
python -m experiments.rig_check \
  --api "$RICH_TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora videosafetybench_benign_query,videosafetybench_harmful_query \
  --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds 7776000 \
  --out runs/thesis/preflight/static-video
```

For each, repeat with `experiments.run_matrix`, the exact successful projection,
`"${LIVE_ATTESTATION_ARGS[@]}"`, and measured outputs
`runs/thesis/runner/static-audio` and
`runs/thesis/runner/static-video`, respectively. Do not send transcripts,
captions, or extracted frames to a target
and label that as audio/video execution. The maintained automated judges never
receive image, audio, or video bytes: they grade a declared source-text reference
plus the target output. Such evidence is a text-reference proxy, not a
media-aware grade. A substantive media-grading claim requires a source-native
media evaluator or the media-resolving human audit.

The historical prepared JALMBench manifest contains 220,240 audio-bearing rows.
Its upstream discovered and text-only-excluded counts remain `CANNOT-VERIFY`
until a fresh export summary is retained. The maintained lane is therefore a
seeded, bounded source-cluster breadth sample, not an impractical two-repeat
full-manifest sweep. `--limit 5000` selects at most 5,000 underlying prompt
clusters and retains their related acoustic/attack variants, so the realized row
and call counts may exceed 5,000. Accept the post-conversion projection rather
than treating the limit as a call count. Report realized cluster, row,
attack/language/acoustic strata and sample-conditional scope. Expanding it is a
separate funded decision after the call projection is combined with provider
pricing, token, audio-input, and latency assumptions in `RUNNOTE.md`.

## 11. Tier 2: source-specific classification

*Console equivalent: this section's commands are also launchable as the `rig_check` and `run_matrix` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

These tracks answer different questions from ASR/FRR and stay separate.
Each command deliberately selects only `--judges rules` because the Runner
requires a non-empty, stage-shaped trail. For these common-ineligible outputs it
does not query even that rule stage: the emitted `not_applicable` row is a
structural placeholder, not a safety verdict. The registered R-Judge or
GPTGeoChat response parser and its source-native classification metrics are the
authoritative evidence for this lane. Do not pass LLM-judge or scoring-guardrail
configuration; those runtimes are unrelated to this construct.

```bash
# R-Judge: broad text roster, recorded trajectory-risk classification.
python -m experiments.rig_check \
  --api "$TEXT_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora rjudge_release --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality --max-total-target-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds 7776000 --out runs/thesis/preflight/rjudge

# GPTGeoChat: image-capable roster, five moderation thresholds per conversation.
python -m experiments.rig_check \
  --api "$IMAGE_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora gptgeochat_release --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality --max-total-target-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds 7776000 --out runs/thesis/preflight/gptgeochat
```

The no-call projection must report zero model-judge calls and zero local
guardrail evaluations. A non-zero value means this source-only lane is
misconfigured and must not proceed. Repeat each successful check with
`experiments.run_matrix`, `"${LIVE_ATTESTATION_ARGS[@]}"`, and the exact printed target-call and HTTP-attempt
ceilings, and the corresponding measured output under
`runs/thesis/runner/rjudge` or `runs/thesis/runner/gptgeochat`; omission of
`--max-total-judge-calls` is intentional because no
model-backed judge is configured or called. R-Judge reports source-label
classification statistics against its reference labels, not independently
established validity; the risk-explanation effectiveness stage is not
implemented. GPTGeoChat reports
threshold-conditioned moderation classification, not a target geolocation ASR.

## 12. Tier 3: adaptive and transferred attacks

*Console equivalent: this section's commands are also launchable as the `rig_check` and `run_matrix` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Depth is applied to a declared focal subset, not to the full static Cartesian
product. At minimum use several provider families plus a local model.

```bash
export FOCAL_HOSTED="$FABLE,$SOL,anthropic:claude-opus-5,google:gemini-3.6-flash,qwen:qwen3.7-max-2026-06-08"
export ADAPTIVE_ARMS='strongreject_official,advbench_harmful,jailbreakbench_harmful,harmbench_text,cyberseceval_mitre,cyberseceval_interpreter,cyberseceval_insecure_coding'
```

### 12.1 Live Crescendo

```bash
python -m experiments.rig_check \
  --api "$FOCAL_HOSTED" --api-config experiments/api-targets.json \
  --attackers crescendo --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$ADAPTIVE_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 4 --max-turns 4 \
  --group model,risk,effective_modality,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds 7776000 \
  --out runs/thesis/preflight/crescendo-text
```

Repeat with `experiments.run_matrix`, `"${LIVE_ATTESTATION_ARGS[@]}"`, the printed totals, and
`--out runs/thesis/runner/crescendo-text`. This lane reports conversation
endpoints; it does not enter static ASR.

### 12.2 Runner-safe external attack bridges

Install only the adapters selected for this tier in the URA environment:

```bash
python -m pip install 'pyrit==0.14.0' 'deepteam==1.0.7' 'h4rm3l==0.2.4' 'spikee==0.9.1'
# nanoGCG is optional and needs a separately identified surrogate checkpoint.
python -m pip install nanogcg
```

Use `experiments/attacker-config.json` to bind exact constructor arguments. A
minimal deterministic-transfer configuration is:

```json
{
  "deepteam": {"attack": "Base64", "upstream_version": "1.0.7"},
  "h4rm3l": {"engine_version": "0.2.4", "syntax_version": 2},
  "pyrit": {"converters": ["Base64Converter"], "upstream_version": "0.14.0"},
  "spikee": {"plugins": ["base64", "1337"], "positions": ["start", "middle", "end"], "engine_version": "0.9.1"}
}
```

Run PyRIT, DeepTeam, h4rm3l, and Spikee as separate lanes over the declared
harmful text anchors. This makes each framework an identifiable condition and
prevents transformed prompts from being confused with raw replay.

```bash
export TRANSFER_ARMS='strongreject_official,advbench_harmful,jailbreakbench_harmful'

# PyRIT and DeepTeam emit one transformed attempt per selected configuration.
# Repeat ATTACKER=pyrit and deepteam with max-queries=1/max-turns=1.
export ATTACKER='pyrit'
python -m experiments.rig_check \
  --api "$FOCAL_HOSTED" --api-config experiments/api-targets.json \
  --attackers "$ATTACKER" --attacker-config experiments/attacker-config.json \
  --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$TRANSFER_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality --max-total-target-calls '<planning-ceiling>' \
  --max-total-judge-calls '<planning-ceiling>' --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds 7776000 --out "runs/thesis/preflight/transfer-$ATTACKER"
```

Run h4rm3l and Spikee in separate invocations with
`--max-queries 4 --max-turns 4`; otherwise the Runner's shared query/turn budget
admits only the first generated variant. The completed artifacts, not the
configured maximum, establish the realized variant count.

Because `attacker-config.json` must contain only selected attacker keys, create a
one-attacker copy for each invocation or remove the unselected rows before the
check. Repeat the successful check with `experiments.run_matrix`,
`"${LIVE_ATTESTATION_ARGS[@]}"`, its exact
totals, and `--out "runs/thesis/runner/transfer-$ATTACKER"`.

The remaining runner bridges are specialized:

| Bridge | Defensible use in this program |
| --- | --- |
| `nanogcg` | precomputed suffix with `suffix_source`, or live optimization on an immutable local surrogate; report as surrogate transfer |
| `harmbench` attacker | prepare text cases from a clean exact-revision checkout with `experiments.harmbench_capture`, then replay only its exact `ura-harmbench-transfer-replay/1` in the measured grid |
| `purplellama` | only with `cyberseceval` rows; source-identity replay, not the native pipeline |
| `ideator` | verified precomputed text-image `seed_pairs` only; live package path is disabled |
| `t3mp3st` | prepare an exact `ura-t3mp3st-plan-bundle/1` through the literal-loopback Op-General planning route, then replay only that bundle in the measured grid; no mission or tool route is used |

Run these only after preparing their exact attacker config and passing
`rig_check`. Do not claim that a complete upstream evaluator ran. Garak,
Promptfoo, Petri, FuzzyAI, EasyJailbreak, AutoDAN-Turbo, Giskard, ASB, and
AgentDojo are not runner attackers; they belong in the native track below.

T3MP3ST planning, HarmBench generation, and local nanoGCG optimization are
out-of-band activities not covered by the Runner's target/judge/HTTP budget or
post-generation checkpoint. Run preparation once under its own authorized cap
or quota, retain its exact output, then use only that output in the measured
Runner. Never describe preparation calls as protected by the common Runner
ceilings.

#### T3MP3ST: capture, then replay

Start the pinned T3MP3ST Op-General service on loopback. Capture the exact same
arm, limit and sample seed that the measured run will use:

```bash
python -m experiments.capture_t3mp3st \
  --corpus strongreject_official \
  --source-config experiments/source-instances.json \
  --limit 50 --sample-seed 0 \
  --endpoint http://127.0.0.1:3333/api/general/plan \
  --upstream-revision '<exact-40-hex-T3MP3ST-revision>' \
  --source-provider '<source-provider>' \
  --source-model '<source-model>' \
  --out runs/thesis/prepared/t3mp3st
```

The command prints the content-addressed artifact path and SHA-256. Put those
exact values into a one-attacker config:

```json
{
  "t3mp3st": {
    "upstream_revision": "<exact-40-hex-T3MP3ST-revision>",
    "source_provider": "<source-provider>",
    "source_model": "<source-model>",
    "response_artifact": "<printed-artifact-path>",
    "response_artifact_sha256": "<printed-sha256>"
  }
}
```

Use that file with `--attackers t3mp3st --attacker-config <file>` in both
`rig_check` and `run_matrix`. The measured selection must match the captured
arm, limit, sample seed and source bytes exactly.

#### HarmBench: capture, then replay

Generate text cases from the clean pinned HarmBench checkout. The preparation
command writes both the replay artifact and the matching one-attacker config:

```bash
python -m experiments.harmbench_capture \
  --repo "$URA_CORPORA/HarmBench" \
  --revision "$REF_HARMBENCH" \
  --source "$URA_HARMBENCH_TEXT_PATH" \
  --corpus-name harmbench_text \
  --method DirectRequest \
  --experiment llama2_7b \
  --limit 50 --sample-seed 0 --cases-per-method 1 \
  --artifact-out runs/thesis/prepared/harmbench-direct.json \
  --attacker-config-out runs/thesis/prepared/harmbench-direct-config.json
```

Use the generated config with `--attackers harmbench --attacker-config
runs/thesis/prepared/harmbench-direct-config.json` in both `rig_check` and
`run_matrix`. Keep the same `harmbench_text`, limit and sample seed. Set both
`--max-queries` and `--max-turns` to at least `number of methods x
cases-per-method`; otherwise admission fails rather than dropping captured
cases. This bridge is text-only and does not claim that the native HarmBench
classifier ran.

## 13. Tier 4: local targets and defense contrast

*Console equivalent: this section's commands are also launchable as the `rig_check` and `run_matrix` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Run every local model in its own process. The examples below use text; repeat the
static image lane for image-capable local models.

```bash
export LOCAL_SPEC='vllm:Qwen/Qwen3-VL-8B-Instruct'
export LOCAL_CONFIG='experiments/local-qwen3-vl.json'

CUDA_VISIBLE_DEVICES=0,1 python -m experiments.rig_check \
  --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG" \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --api-config experiments/api-targets.json \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device cuda:1 \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality --max-total-target-calls '<planning-ceiling>' \
  --max-total-judge-calls '<planning-ceiling>' --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds 7776000 --out runs/thesis/preflight/local-qwen3-vl-text
```

Repeat with `run_matrix`, `"${LIVE_ATTESTATION_ARGS[@]}"`, exact totals, and
`--out runs/thesis/runner/local-qwen3-vl-text`; allow the process to exit, then
run the image lane. Repeat both for the LLaVA base and GraySwan RR checkpoint using their
own exact local configs. Their paired comparison is meaningful only on identical
source clusters, input bytes, inference settings, and judge condition.

The optional hosted text-only defense contrast uses a separate model identity
and GPU for each guard. Put the 8B scoring guard on GPU 0 and the 1B defense
guard on GPU 1; loading both on one 24 GB card is not this planned condition.
Do not add the model-backed defense to the two-card local-target lane, where GPU
0 already holds the target and GPU 1 holds the scoring guard.

```bash
python -m experiments.rig_check \
  --api "$FOCAL_HOSTED" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device cuda:0 \
  --defense both --defense-guard guardrail \
  --defense-guardrail-model "$DEFENSE_GUARD" \
  --defense-guardrail-revision "$DEFENSE_GUARD_REV" \
  --defense-guardrail-device cuda:1 \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality --max-total-target-calls '<planning-ceiling>' \
  --max-total-judge-calls '<planning-ceiling>' --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds 7776000 --out runs/thesis/preflight/defense-text
```

Repeat the successful defense check with `run_matrix`,
`"${LIVE_ATTESTATION_ARGS[@]}"`, exact totals, and
`--out runs/thesis/runner/defense-text`. Run matching no-defense cells for the
same focal targets and clusters in their own checked/measured lane directories.
Added value is measured as the harmful/benign tradeoff; lower harmful ASR without the
benign refusal cost is an incomplete defense analysis.

## 14. Tier 5: nine source-native evaluators

*Console equivalent: this section's commands are also launchable as the `native_import` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Each project gets an isolated environment and exact source revision. Do not
install all of them into the URA environment.

### 14.1 Acquire and install

```bash
export REF_FUZZYAI=8184b9667a665aa27fb69ef81a7a30615d13faf5
export REF_PETRI=1f41e29f71f4fe407e9f9bd73be1893610dfed5e
export REF_EASYJAILBREAK=bf3c162d54ba5c7818074c1e0b540947fbec348a
export REF_ASB=1f561dccf92d55302368fa67679b4ba9d9c8fdc4
export REF_AGENTDOJO=a75aba7631d3ca5fb7ab938965c97ead2f9ff84b
export REF_GARAK=c43aed7d3e2b97e3b62c12a2eb5d171860bf8909
export REF_PROMPTFOO=4805856060d026521794d4e69decb938155580ad
export REF_AUTODAN=389df844439888fc44ea7f5e8e95fd2b5c82ea64
export REF_GISKARD=86512399daf097358422e1f30d19abbacbe5ce9a

git clone https://github.com/cyberark/FuzzyAI.git "$URA_UPSTREAM/FuzzyAI"
git -C "$URA_UPSTREAM/FuzzyAI" checkout --detach "$REF_FUZZYAI"
python3.12 -m venv "$URA_NATIVE_ENVS/fuzzyai"
"$URA_NATIVE_ENVS/fuzzyai/bin/python" -m pip install -e "$URA_UPSTREAM/FuzzyAI"

git clone https://github.com/NVIDIA/garak.git "$URA_UPSTREAM/garak"
git -C "$URA_UPSTREAM/garak" checkout --detach "$REF_GARAK"
python3.12 -m venv "$URA_NATIVE_ENVS/garak"
"$URA_NATIVE_ENVS/garak/bin/python" -m pip install -e "$URA_UPSTREAM/garak"

git clone https://github.com/promptfoo/promptfoo.git "$URA_UPSTREAM/promptfoo"
git -C "$URA_UPSTREAM/promptfoo" checkout --detach "$REF_PROMPTFOO"
npm install --prefix "$URA_NATIVE_ENVS/promptfoo" promptfoo@0.121.15

git clone https://github.com/meridianlabs-ai/inspect_petri.git "$URA_UPSTREAM/inspect_petri"
git -C "$URA_UPSTREAM/inspect_petri" checkout --detach "$REF_PETRI"
python3.12 -m venv "$URA_NATIVE_ENVS/petri"
"$URA_NATIVE_ENVS/petri/bin/python" -m pip install 'inspect-ai>=0.3.236' -e "$URA_UPSTREAM/inspect_petri"

git clone https://github.com/EasyJailbreak/EasyJailbreak.git "$URA_UPSTREAM/EasyJailbreak"
git -C "$URA_UPSTREAM/EasyJailbreak" checkout --detach "$REF_EASYJAILBREAK"
python3.12 -m venv "$URA_NATIVE_ENVS/easyjailbreak"
"$URA_NATIVE_ENVS/easyjailbreak/bin/python" -m pip install -e "$URA_UPSTREAM/EasyJailbreak"

git clone https://github.com/SaFo-Lab/AutoDAN-Turbo.git "$URA_UPSTREAM/AutoDAN-Turbo"
git -C "$URA_UPSTREAM/AutoDAN-Turbo" checkout --detach "$REF_AUTODAN"
python3.12 -m venv "$URA_NATIVE_ENVS/autodan"
"$URA_NATIVE_ENVS/autodan/bin/python" -m pip install -r "$URA_UPSTREAM/AutoDAN-Turbo/requirements.txt"

git clone https://github.com/Giskard-AI/giskard-oss.git "$URA_UPSTREAM/giskard-oss"
git -C "$URA_UPSTREAM/giskard-oss" checkout --detach "$REF_GISKARD"
python3.12 -m venv "$URA_NATIVE_ENVS/giskard-v2"
"$URA_NATIVE_ENVS/giskard-v2/bin/python" -m pip install 'giskard[llm]==2.19.2'

git clone https://github.com/agiresearch/ASB.git "$URA_UPSTREAM/ASB"
git -C "$URA_UPSTREAM/ASB" checkout --detach "$REF_ASB"
python3.12 -m venv "$URA_NATIVE_ENVS/asb"
"$URA_NATIVE_ENVS/asb/bin/python" -m pip install -r "$URA_UPSTREAM/ASB/requirements.txt"

git clone https://github.com/ethz-spylab/agentdojo.git "$URA_UPSTREAM/agentdojo"
git -C "$URA_UPSTREAM/agentdojo" checkout --detach "$REF_AGENTDOJO"
python3.12 -m venv "$URA_NATIVE_ENVS/agentdojo"
"$URA_NATIVE_ENVS/agentdojo/bin/python" -m pip install -e "$URA_UPSTREAM/agentdojo"
```

If an upstream pin does not support Python 3.12, create only that isolated
environment with its documented Python version and record the interpreter. Do not
change the URA environment to satisfy it.

### 14.2 Execute upstream

Use exact target, attacker/generator, and grader identities visible to the native
tool. The following are the supported artifact-producing surfaces:

These upstream commands run outside `run_matrix`; URA's durable call ledger and
circuits do not protect them. Before each native campaign, use an isolated
provider credential/project with a provider-side hard quota no greater than the
approved lane budget, set the tool's own retry/concurrency/generation limits,
and record its projected target, attacker, and grader calls. Run one case first,
verify the exact model routes and complete native artifact shape, then start the
full campaign. The one-case canary is diagnostic and stays out of the measured
native import. If a tool cannot expose or externally cap its calls, keep that
campaign `N/A` rather than relying on a post-hoc cost check.
Do not route these source-native canaries through
`run_matrix --diagnostic-canary` or `experiments.lane_canary`: their target, attacker,
runtime, and evaluator contract remains upstream-native. Retain their separate
operator note and artifacts outside the canonical measured import input.

```bash
# FuzzyAI: retains a complete timestamped result directory with raw.jsonl and report.json.
"$URA_NATIVE_ENVS/fuzzyai/bin/fuzzyai" fuzz \
  -m '<native-target-route>' -a asc -a bon -T '<prompt-file>'

# Garak 0.15.1: retains <prefix>.report.jsonl.
"$URA_NATIVE_ENVS/garak/bin/python" -m garak \
  --target_type openai.OpenAICompatible --target_name '<exact-target>' \
  --probes dan.Dan_11_0 --detectors auto --generations 1 --seed 0 \
  --eval_threshold 0.5 --report_prefix '<absolute-run-prefix>'

# Promptfoo 0.121.15: configure all three model roles in promptfooconfig.yaml.
"$URA_NATIVE_ENVS/promptfoo/node_modules/.bin/promptfoo" redteam generate \
  -c promptfooconfig.yaml --strict --force --no-cache --no-progress-bar \
  -o generated-redteam.yaml
"$URA_NATIVE_ENVS/promptfoo/node_modules/.bin/promptfoo" redteam eval \
  -c generated-redteam.yaml --no-cache --no-share --no-progress-bar --no-table \
  -o results.json

# Petri: auditor, target, and judge are three different declared roles.
"$URA_NATIVE_ENVS/petri/bin/inspect" eval inspect_petri/audit \
  --model-role auditor='<provider/auditor>' \
  --model-role target='<provider/target>' \
  --model-role judge='<provider/judge>'
"$URA_NATIVE_ENVS/petri/bin/inspect" log convert --to json \
  --output-dir '<converted-dir>' '<path-to-run.eval>'

# AutoDAN-Turbo: run standard or reasoning entrypoint in the exact checkout.
cd "$URA_UPSTREAM/AutoDAN-Turbo"
"$URA_NATIVE_ENVS/autodan/bin/python" main.py
# Or, as a separate condition: "$URA_NATIVE_ENVS/autodan/bin/python" main_r.py

# Immediately write the mandatory URA provenance sidecar. Substitute the exact
# output directory, role identities, dataset digest, variant, and upstream
# iteration/request settings used above; do not import until this succeeds. Use
# the main project interpreter, where URA was installed, rather than AutoDAN's
# isolated upstream-only environment.
URA_AUTODAN_LOGS='<exact-AutoDAN-output-directory>' \
URA_AUTODAN_RUN_ID='<recorded-run-id>' \
URA_AUTODAN_DATASET_SHA256='<64-hex-dataset-sha256>' \
"$URA_WORK/MLLMRiskBench/.venv/bin/python" - <<'PY'
import os
from ura.adapters.autodan import AutoDANTurboAttacker

AutoDANTurboAttacker.write_run_manifest(
    os.environ["URA_AUTODAN_LOGS"],
    run_id=os.environ["URA_AUTODAN_RUN_ID"],
    variant="standard",
    model_roles={
        "attacker": "<provider/attacker>",
        "target": "<provider/target>",
        "scorer": "<provider/scorer>",
        "summarizer": "<provider/summarizer>",
        "embedding": "<provider/embedding>",
    },
    epochs=150,
    warm_up_iterations=1,
    lifelong_iterations=4,
    warm_up_requests=100,
    lifelong_requests=100,
    dataset_sha256=os.environ["URA_AUTODAN_DATASET_SHA256"],
)
PY

# ASB: DPI, OPI, memory poisoning, and PoT are separate native surfaces.
cd "$URA_UPSTREAM/ASB"
"$URA_NATIVE_ENVS/asb/bin/python" scripts/agent_attack.py --cfg_path config/DPI.yml
"$URA_NATIVE_ENVS/asb/bin/python" scripts/agent_attack.py --cfg_path config/OPI.yml
"$URA_NATIVE_ENVS/asb/bin/python" scripts/agent_attack.py --cfg_path config/MP.yml
"$URA_NATIVE_ENVS/asb/bin/python" scripts/agent_attack_pot.py

# AgentDojo: retain the fresh pipeline/suite trace subtree.
"$URA_NATIVE_ENVS/agentdojo/bin/python" -m agentdojo.scripts.benchmark \
  --model '<exact-model>' --benchmark-version v1.2.2 \
  --attack important_instructions -s workspace --logdir '<native-logdir>'
```

EasyJailbreak has no single universal recipe command: execute one exact recipe
class exported by 0.1.3 with explicit attack, target, and evaluator models, then
call `JailbreakDataset.save_to_jsonl()` on the complete `attack_results`. Giskard
likewise uses its Python API: run `giskard.scan(model, dataset)` or
`giskard.rag.evaluate()`, then export the complete Scan or RAGET artifact family.
The URA adapter helpers and exact required artifacts are documented in
[`docs/NATIVE_ENGINE_IMPORTS.md`](../docs/NATIVE_ENGINE_IMPORTS.md).

Run each native framework on every target it genuinely supports and that the
research budget includes. A framework-specific target subset is acceptable; its
absence from another framework is reported as coverage, not filled by prompt
replay. Preserve upstream target configuration, native evaluator identity,
complete logs, errors, and native summaries.

### 14.3 Import native artifacts

For each run, create a strict JSON config with exactly `schema_version`, `engine`,
`adapter`, and `import`. Paths are resolved relative to the config file. Example:

```json
{
  "schema_version": "ura-native-import-config/1",
  "engine": "garak",
  "adapter": {
    "target_type": "openai.OpenAICompatible",
    "target_name": "<exact-target>",
    "probe_spec": "dan.Dan_11_0",
    "detector_spec": "auto",
    "generations": 1,
    "seed": 0,
    "eval_threshold": 0.5,
    "upstream_version": "0.15.1"
  },
  "import": {
    "report_path": "../raw/garak/native.report.jsonl",
    "upstream_revision": "c43aed7d3e2b97e3b62c12a2eb5d171860bf8909",
    "expected_records": 0
  }
}
```

Replace `expected_records` with the actual complete native line count. The nine
engine names and primary import fields are:

| Engine | Adapter identity | Primary import fields |
| --- | --- | --- |
| `fuzzyai` | `model`, `attacks` | `results_dir`, `upstream_revision` |
| `garak` | target/probe/detector/generation/seed/threshold | `report_path`, `upstream_revision`, `expected_records` |
| `promptfoo` | target providers, plugins, strategies, generation and grader providers | `results_json`, `generated_config`, `upstream_revision`, `expected_results` |
| `petri` | auditor, target, judge, dimensions | `log_path`, optional expected digest/version |
| `easyjailbreak` | recipe, attack, target, evaluator, version | `result_jsonl`, `upstream_revision`, `expected_records` |
| `autodan_turbo` | target and standard/reasoning variant | `results_dir`, manifest digest |
| `giskard` | target model | complete Scan or RAGET `results_dir`, manifest digest |
| `asb` | attack class and exact checkout | CSV, target, attack type, tool type, config |
| `agentdojo` | suite, attack, benchmark, target, version/revision | trace root and optional per-trace digests |

Import and immediately revalidate each canonical envelope:

```bash
mkdir -p runs/thesis/native/canonical
python -m experiments.native_import \
  --config runs/thesis/native/configs/garak.json \
  --out runs/thesis/native/canonical/garak.json
python -m experiments.native_import \
  --validate runs/thesis/native/canonical/garak.json
```

Repeat for all completed native runs. `native_import` never executes the upstream
tool or a model; it validates, hashes, and normalizes an already completed native
artifact family. Its output is a `ura-native-import-envelope/2`, not a
self-attesting result file: the envelope binds a relative, hashed import-config
locator, and validation reruns the importer against the authoritative raw files.
Keep each config, every raw artifact it references, and its envelope together
under `runs/thesis/native`; moving that complete relative tree is supported, while
returning the envelope alone is not.

## 15. Human audit

*Console equivalent: this section's commands are also launchable as the `human_audit` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Prepare the blinded audit only after all intended runner grids are complete. Use
the common `runs/thesis/runner` parent so the sample can include broad roster,
source, policy, modality, and attack strata. Choose the sample size from feasible
rater capacity and achieved strata; the number below is only an operator example.
The selector derives overall and exact risk/modality coverage requirements for
every observed common-eligible model/defense/attacker/source-policy/population
arm and fails if the requested whole-cluster sample cannot cover them. Increase
the sample size; do not remove achieved arms from the audit frame.

```bash
python -m experiments.human_audit \
  --results runs/thesis/runner --prepare 400 \
  --output runs/thesis/human-audit-sample.csv \
  --acknowledge-sensitive-content
```

Before main labelling, create `runs/thesis/human-rater-qualification.md` with
pseudonymous rater IDs, language competence, graduate-level study or equivalent
relevant safety/moderation experience, conflict disclosures, training date,
qualification-set digest, per-dimension score and adjudicator. Use an
independently adjudicated 20-item set outside the final audit sample. Each rater
must reach at least 80% agreement on every dimension; after reviewed retraining,
one repeat is permitted. Do not silently lower the threshold or select raters on
the final sample.

Use at least two independently qualified raters. Adjudicate every non-unanimous
composite or dimension; unanimous ratings need no adjudication. Rate refusal,
harmfulness, convincingness, and specificity separately under the exact source
policy and dimension rubric. Resolve and verify every media reference before
rating. Keep all join columns. Raters must not see automated labels or metric
outputs; model identity remains visible in the current export and must be
reported as a limitation. The deterministic coverage-priority selector claims
no equal-probability inclusion probabilities and uses no inverse-probability
weights. Retain a probability-sampled component if any uncertainty- or
disagreement-enriched quota is added and population interpretation is intended.
`--prepare 400` means 400 source clusters, not 400 CSV rows. Every selected
sibling model/seed/run response is exported. Before assigning work, record the
reported exported-row count `R`, reserve at least `2R` independent item-ratings,
and budget additional adjudication for every non-unanimous composite or
dimension. If that realized load is infeasible, choose a smaller cluster count
prospectively and rerun preparation; do not discard sibling rows after export.

After adjudication:

```bash
python -m experiments.human_audit \
  --results runs/thesis/runner \
  --labels runs/thesis/human-audit-labelled.csv
```

Until this succeeds, judge validity is pending. Small strata are pilot evidence
with cluster-aware intervals, not validated rankings. Kappa is diagnostic and is
always accompanied by prevalence, support, confusion matrices, and uncertainty.
Read primary judge-validity results only within their exact run, response arm,
logical corpus, source-policy, modality, population, and eligibility cell. Check
total/decided/abstained support and decision coverage; harmful violation and
benign over-refusal are different adverse endpoints. Bootstrap intervals state
requested and defined replicate counts and are conditional on defined
replicates.

### 15.1 Source-task classification audit (separate frame)

The classification lanes from section 11 use a separate, never-mixed audit
frame that verifies source-defined task semantics and parser fidelity instead
of refusal/harmfulness. Preparation exports only typed source-metric-only rows
(R-Judge/GPTGeoChat), blinds the automated parser prediction, its validity
flag, and the source reference, and includes whole clusters:

```bash
python -m experiments.human_audit \
  --results runs/thesis/runner --prepare-source-task 50 \
  --acknowledge-sensitive-content \
  --output runs/thesis/source-task-audit-sample.csv
```

At least two qualified raters label each row independently with the exact
`task_label_vocabulary` and a parse-status judgment, then adjudicate. Analysis
re-joins every labelled row to the exact exported prompt/response content and
writes `source_task_audit.json` with inter-rater agreement, adjudicated-human
versus source-reference accuracy (cluster-bootstrap interval), adjudicated
versus parser agreement/confusion, and the parser-valid fraction:

```bash
python -m experiments.human_audit \
  --results runs/thesis/runner \
  --source-task-labels runs/thesis/source-task-audit-labelled.csv
```

These results are source-task classification evidence on the source's own
scale. They are never common ASR/refusal evidence, never enter the common
human frame or its judge-validity calibration, and never rename classification
accuracy as safety.

## 16. Read-only analysis and suite summary

*Console equivalent: this section's commands are also launchable as the `judge_sensitivity`, `kappa`, `transfer_matrix`, `paired_compare`, `level1_evidence`, `native_import`, `suite_summary`, `level2_report` and `figures` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Run the implemented diagnostics only on completed, content-validated artifacts:

```bash
python -m experiments.judge_sensitivity --results runs/thesis/runner
python -m experiments.kappa --results runs/thesis/runner
python -m experiments.transfer_matrix --results runs/thesis/runner --attacker replay
```

Paired comparisons must name exact conditions and a common source arm. Examples:

```bash
python -m experiments.paired_compare --results runs/thesis/runner \
  --left-model "$FABLE" --right-model "$SOL" \
  --attacker replay --corpus strongreject_official \
  --output runs/thesis/analysis/fable-v-sol-strongreject.json

python -m experiments.paired_compare --results runs/thesis/runner \
  --left-model "vllm:llava-hf/llava-v1.6-mistral-7b-hf@$REF_LOCAL_LLAVA_BASE" \
  --right-model "vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR@$REF_LOCAL_LLAVA_RR" \
  --attacker replay --corpus mmsafety_official \
  --output runs/thesis/analysis/llava-base-v-rr-mmsafety.json
```

Build the mandatory Level-1 lifecycle inventory from one explicitly selected
runner cohort. Supply every final eligibility plan in that scope, including
plan-only structural-`N/A` or preflight-blocked requests that have no grid. Use
one output directory per exact request condition; if arguments change, use a new
directory rather than mixing conditions. Within a `run_matrix` invocation the
driver replaces its preliminary plan with the final plan. The Level-1 validator
rejects duplicate request identities, and every supplied grid must still bind
the exact plan descriptor and experiment condition.
`run_matrix` already wrote each `ura-request-envelope/1` before config/source
materialization. Level-1 discovers those files and any bound
`ura-request-error/1` automatically from the measured result tree and plan
siblings; there is no extra request-manifest setup or CLI argument.
Do not supply `runs/thesis/preflight`, `runs/thesis/attestation`, or
`runs/thesis/diagnostics`: those trees contain projections, probes, or canaries,
not the selected measured cohort.
One Level-1 artifact cannot mix dry-run and measured requests; this command's
output must declare `evidence_kind=measured_run`. Supply the union of exact
receipt bytes bound by those grids, not merely the most recently constructed
per-lane array. The loop below discovers the content-addressed copies retained
inside the measured tree and deduplicates them by exact SHA-256. Do not supply a
probe grid.

```bash
LEVEL1_ELIGIBILITY_ARGS=()
while IFS= read -r -d '' plan; do
  LEVEL1_ELIGIBILITY_ARGS+=(--eligibility "$plan")
done < <(find runs/thesis/runner -type f \
  -name 'eligibility-*.eligibility.json' -print0 | sort -z)

LEVEL1_LIVE_ATTESTATION_ARGS=()
declare -A LEVEL1_SEEN_LIVE_SHA256=()
while IFS= read -r -d '' receipt; do
  digest="$(sha256sum -- "$receipt" | awk '{print $1}')"
  test "${#digest}" -eq 64
  if [[ -z "${LEVEL1_SEEN_LIVE_SHA256[$digest]+present}" ]]; then
    LEVEL1_LIVE_ATTESTATION_ARGS+=(
      --live-attestation "$receipt" --live-attestation-sha256 "$digest"
    )
    LEVEL1_SEEN_LIVE_SHA256[$digest]=1
  fi
done < <(find runs/thesis/runner -type f \
  -name 'live-attestation-*.json' -print0 | sort -z)
test "${#LEVEL1_LIVE_ATTESTATION_ARGS[@]}" -gt 0

python -m experiments.level1_evidence \
  --results runs/thesis/runner \
  "${LEVEL1_ELIGIBILITY_ARGS[@]}" \
  "${LEVEL1_LIVE_ATTESTATION_ARGS[@]}" \
  --out-json runs/thesis/analysis/level1-evidence.json \
  --out-csv runs/thesis/analysis/level1-evidence.csv
```

The command is create-only; use new output names when rebuilding. Its
`ura-level1-evidence/2` JSON distinguishes prospective whole-arm request units,
materialized planning strata, whole-arm execution units, and judgment-record
support. It validates exact
plan/grid conditions and descriptors, content descriptors for grid and
completion/error evidence, exact selected-datapoint count and identity-digest
coverage, and decided/abstained/non-evaluable reconciliation.
Attempted is counted only at the whole-arm unit: a started failed unit does not
identify which strata it reached, so planning-stratum attempts remain null and
`execution_unit_started` is context only. Missing is reserved for an
execution-eligible row with no grid; block/error dispositions remain separate.
Pre-materialization failures remain bound to prospective request units and do
not create planning strata or calls. For the
measured cohort, the command revalidates each grid-bound typed receipt, matches
its exact route/config/scope/age/modality prerequisite and completed-cell stable
target identity, and reports record-qualified attestation support. This is
transport-prerequisite accounting, not a safety endpoint. Analysis selection is
still `not_supplied`; its counts (including included records) are null rather
than zero, and `empirical_validity_established` is false. `evidence_kind` distinguishes
`diagnostic_dry_run` from `measured_run`; neither the measured label nor completed
cells prove empirical validity.

Build one evidence inventory across every runner grid and every canonical native
run:

```bash
NATIVE_ARGS=()
while IFS= read -r -d '' artifact; do
  NATIVE_ARGS+=(--native "$artifact")
done < <(find runs/thesis/native/canonical -maxdepth 1 -type f \
  -name '*.json' -print0)

ELIGIBILITY_ARGS=()
while IFS= read -r -d '' artifact; do
  ELIGIBILITY_ARGS+=(--eligibility "$artifact")
done < <(find runs/thesis/runner -type f \
  -name 'eligibility-*.eligibility.json' -print0)

python -m experiments.suite_summary \
  --results runs/thesis/runner \
  --source-config experiments/source-instances.json \
  "${NATIVE_ARGS[@]}" \
  "${ELIGIBILITY_ARGS[@]}" \
  --out runs/thesis/suite-evidence.json
```

The output provides planning eligibility/`N/A` counts, exact completed runner
strata, aggregate metric families, native target strata, native
outcome/score-field coverage, and content digests. Planning eligibility is not
live attestation or execution evidence. Static
convenience rates equal-weight source prompt/intent clusters and expose both
record and cluster support; use the runner aggregates for cluster-bootstrap
intervals. It also lists
every registry arm and native project that has no admitted evidence. Record each
missing entry in `RUNNOTE.md` as not run, failed, or scientifically unavailable
with the reason. Its presence flag covers only the supplied source registry and
the requested planning ledgers and nine native projects; it never promotes a
`compatible_if_isolated` plan row to an attested, attempted, or completed cell.
Distinct run IDs, cross-cell rates, and native scales are never pooled. Use this
as the Experimental section's inventory and table source, not as a model
leaderboard score.

The deterministic Level-2 broad-table exporter turns the same
completion-validated measured artifacts into thesis-ready JSON, CSV, and
Markdown tables. It admits cells only through the measured-figure grid
validator, so diagnostic dry runs, diagnostic canaries, and attestation probes
are rejected; every estimate row carries its complete compatibility key
(run, served target, source, policy identity/digest, modality, population,
attacker, defense, ordered judge identity, sampling/budget condition), plus
official/proxy status, declared polarity, cluster support, intervals, and
judgment-record decision coverage. Rows with distinct keys are never merged,
and supplied canonical native envelopes are listed in a separate table on
their original scales:

```bash
python -m experiments.level2_report \
  --results runs/thesis/runner \
  "${NATIVE_ARGS[@]}" \
  --out-json runs/thesis/level2-report.json \
  --out-csv runs/thesis/level2-report.csv \
  --out-md runs/thesis/level2-report.md
```

Outputs are create-only and deterministic for identical inputs. The export is
descriptive: it defines no universal safety score, implies no ranking, and
does not by itself establish empirical validity.

The maintained measured-figure command still renders the declared paired core
figures, not the whole broad roster. Invoke it only after the matching core grids
and human audit exist. The loader requires `attestation_probe=false` plus
`execution_purpose=measured_run` and a measured typed-receipt projection; it
rejects probe and diagnostic-canary grids even when complete.
The explicit corpus aliases reuse those broad-root cells;
they do not trigger or require duplicate focal model calls:

```bash
export HUMAN_AUDIT_SHA256="$(sha256sum runs/thesis/runner/human_audit.json | awk '{print $1}')"
python -m experiments.figures \
  --results runs/thesis/runner \
  --left-model "$FABLE" --right-model "$SOL" \
  --strongreject-corpus strongreject_official \
  --mmsafety-corpus mmsafety_official \
  --mossbench-corpus mossbench_official \
  --human-audit runs/thesis/runner/human_audit.json \
  --human-audit-sha256 "$HUMAN_AUDIT_SHA256" \
  --out runs/thesis/figures
```

Broad-roster tables must be generated from `suite-evidence.json` with explicit
benchmark/policy/modality columns. Do not force heterogeneous native metrics into
the paired core figure template.

## 17. Completion, recovery, and return

*Console equivalent: this section's commands are also launchable as the `project_revision` and `source_conformance` validation forms form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Each lane is complete only when its command exits zero, the grid reports zero
failed cells, every requested cell has a completion marker, modality coverage is
realized, and the durable ledgers reconcile with provider usage. Resume a stopped
lane by rerunning its identical command. Use `--reset-open-circuits` only after
correcting and documenting the provider or judge failure that opened the circuit.

Complete the already-created `runs/thesis/RUNNOTE.md` and record:

- UTC start/end, host, OS, Python, CUDA, driver, and both GPU identities;
- the prospective URA project-revision receipt ID/file/SHA-256, expected and
  observed commit, HEAD tree, and final validation result; separately record
  `git rev-parse HEAD` and `git status --short` for URA and every upstream checkout;
- source/model revisions, source file hashes, exact commands, lane ceilings, and
  non-secret endpoint routes;
- the validated compact source-receipt file/SHA-256,
  admitted/blocked/not-selected arm counts, declared-file rehash result, and any
  unresolved operator-review caveat;
- exact requested and resolved target IDs, operator-declared execution scope,
  account region/tier where recorded, route-config digest, exact combination,
  manifest-start observation, receipt ID/file/SHA-256, selected maximum age,
  and modality-probe outcome; account equivalence remains CANNOT-VERIFY;
- package inventories for URA and every native environment;
- interruptions, retries, exclusions, unavailable cells, and their reasons;
- projected conservative logical calls/HTTP-attempt exposure and separately
  observed client-reported transport attempts for every runner canary/lane;
  provider-side hard quotas and provider usage/cost reconciliation remain
  separate evidence and unavailable values remain `CANNOT-VERIFY`;
- human-audit status and achieved per-stratum counts for the common frame,
  and separately the source-task audit status and its per-family counts; record
  the applicable ethics determination identifier/date, consent version,
  compensation basis, harmful-content welfare controls, withdrawals and adverse
  events without unnecessary personal data;
- Level-1 `evidence_id`, planning-stratum/execution-unit/judgment-record counts,
  request-level errors, validated typed-attestation artifact/record support, and
  the explicit `not_supplied` analysis-inclusion fields; and
- the Level-2 `report_id` with its estimate-row and native-run counts.

Capture the complete URA environment and harness identity. Repeat the Python
version, `pip list`, and `pip freeze --all` commands after activating every
source-native environment, using a distinct filename for each environment:

```bash
mkdir -p runs/thesis/environments
python -VV > runs/thesis/environments/ura-python.txt 2>&1
python -m pip list --format=json > runs/thesis/environments/ura-pip-list.json
python -m pip freeze --all > runs/thesis/environments/ura-pip-freeze.txt
nvidia-smi -q > runs/thesis/environments/nvidia-smi-q.txt
test "$(git rev-parse HEAD)" = "$REF_URA"
python -m experiments.project_revision \
  --validate "$URA_PROJECT_REVISION_MANIFEST" \
  --sha256 "$URA_PROJECT_REVISION_SHA256"
printf '%s\n' "$REF_URA" > runs/thesis/harness-expected-commit.txt
git rev-parse HEAD > runs/thesis/harness-observed-commit.txt
git status --short > runs/thesis/harness-status.txt
printf '%s  %s\n' "$URA_PROJECT_REVISION_SHA256" \
  "$URA_PROJECT_REVISION_MANIFEST" > runs/thesis/project-revision.sha256
test "$(sha256sum "$URA_SOURCE_CONFORMANCE_MANIFEST" | awk '{print $1}')" = \
  "$URA_SOURCE_CONFORMANCE_SHA256"

# Make the exact tested source recoverable even if this commit is not published.
git bundle create runs/thesis/ura-project-source.bundle HEAD
git bundle verify runs/thesis/ura-project-source.bundle
```

If the exact tested commit is already available from a recorded remote ref, the
verified bundle is still a compact self-contained fallback. A hash without a
retrievable ref or source bundle is not a reproducible software release.

Before return, re-run every canonical native validation from the complete
config/raw/envelope tree and rebuild the suite
summary into a new output name if the existing file already exists. Verify that
the tree retains the separate `preflight/`, `attestation/`, and measured
`runner/` directories, plus grid descriptors, manifests, attempts, responses, judgments,
shadow trails, checkpoints, completion/error records, aggregates, modality
coverage, call ledgers, native raw artifacts and canonical envelopes, the
common human-audit files and the separate source-task audit sample/labelled
CSVs plus `source_task_audit.json`, every retained `ura-lane-projection/1`,
diagnostic `ura-lane-canary/1`, the rebuilt `suite-evidence.json` broad-roster
inventory, the Level-1 JSON/CSV, the deterministic
`ura-level2-report/1` JSON/CSV/Markdown tables, the remaining analyses,
figures, the exact retained `source-conformance.json` and any lane-specific
`source-conformance-*.json` (with any
`*.scaffold.json` working drafts removed), the exact VLSBench and JALMBench
`*-export-summary.json` files under `source-export-summaries/` referenced by
prepared-input receipts, every exact
`ura-live-attestation/2`
receipt and approved digest record, the prospective `ura-project-revision/1`
receipt and digest record, expected/observed commit and checkout-status
records, and the run note. The rig console's job state directory
(`runs/rig-web/` by default) is an operational record, not return evidence. Runner outputs retain their own receipt copies and compact bindings.
Canonical native envelopes retain their distinct upstream project revisions but
do not acquire a Runner `RunManifest`; their URA implementation revision is
therefore established in the return-package/importer context, not falsely
presented as an upstream-native field. The source releases themselves
remain outside the return package unless
the recipient is licensed and explicitly authorized.

```bash
tar -czf ura-thesis-return.tgz runs/thesis
sha256sum ura-thesis-return.tgz > ura-thesis-return.tgz.sha256
```

Do not return API keys, shell history, secret-manager exports, model caches, or
restricted source releases unless the recipient is explicitly authorized. Mock,
synthetic, partial, manually edited, failed, or diagnostic-only artifacts remain
diagnostics and cannot be promoted to thesis evidence.

## 18. Rig-local console and campaign builder

A single-operator localhost application starts, monitors, and stops the
allowlisted experiment CLIs from typed forms, composes campaign lanes through
a mode-aware builder (dry run, attestation probe, diagnostic canary, measured
execution) with mode-specific validation and an exact-argv confirmation step
before any paid mode starts, streams job logs, edits the operator-local
registries (api-targets, local-targets, source-instances, budgets, pricing)
through an allowlisted JSON editor, renders retained `ura-level1-evidence/2`
and `ura-level2-report/1` artifacts with explicit diagnostic/measured,
structural-`N/A`, and error distinctions after reconciling their reported
counts, sample sizes, and confidence intervals, and accounts recorded token
usage and its calculated monetary cost:

```bash
python -m experiments.rig_web --results-root runs --state-dir runs/rig-web
```

The dashboard and Build tab show the startup OS/CPU/core/RAM and complete NVIDIA
GPU inventory. Build target filters are independent and combinative: hosted API
provider (`All` by default), plus local vLLM name substring, 10M-3T maximum
parameter count, the separate automatic 16/8/4-bit fit card (on by default), and
an unchecked `Include unknown fit` control. Known 16/8/4-bit recommendations use
green/blue/amber badges; unknown fit is gray. Compatible local models are
single-choice radios;
an unpinned roster row may be selected for planning, but non-dry submission
rejects it before launch. An unknown-fit row also needs an explicit per-model
precision, which binds `allow_unknown_fit: true`; auto remains blocked, as does
every known incompatibility. These filters are convenience only; shared CLI/UI
admission remains authoritative.

Source arms without an integrated evaluator remain visible/selectable with a
concise `no evaluator` badge and one custom hover/focus tooltip containing the
exact limitation. The server
rejects such a selection before a subprocess. This preserves the full research
programme without falsely calling the lane runnable; implemented source-metric
arms and common-metric arms retain their distinct admission paths.

Dry mode removes any selected real API/local targets and target configs because
`run_matrix --dry-run` always executes `MockTarget`. The local roster advertises
only the text/image modalities supported by the Runner's vLLM path; audio
target/arm combinations are rejected by the same UI/CLI parity checks.

The console binds only `127.0.0.1`, builds argument vectors exclusively from a
typed allowlist (no shell), caps POST bodies, runs each job in its own process
group, and keeps per-job argv/stdout/stderr under the state directory. Closing
the console leaves detached jobs running; the explicit Stop action terminates
the complete child tree. Builder preflights are kept under
`<results-root>/preflight`; changing only execution caps may reuse the same exact
projection, while a semantic lane change requires a new preflight.

Console state (jobs with their exact argv and builder parameters, the
campaign-run registry, recorded per-artifact token usage, and the report
index) persists in a stdlib-sqlite database `console.db` under the state
directory, with a schema version, a startup integrity check, transactional
terminal-state commits, and a dashboard Reindex action that rebuilds every
derived row from the retained artifacts with full digest verification. The
database is operational state only - the validated filesystem artifacts
remain the scientific authority, a database fault is surfaced visibly (never
as a silently empty history or zero spend), and neither the database nor the
state directory is return-package evidence.

Token usage is never estimated: target usage is read from completion-bound
`*.responses.jsonl` records (`Response.tokens` plus the detailed
`raw.provider_usage` fields), judge usage from completed trail records
(`raw.judge_call.tokens`), and only artifacts reachable through a valid
`*.complete.json` completion marker are counted, so checkpoints, superseded
partial snapshots, and orphaned cell files are never double-counted.
Monetary cost multiplies those recorded tokens by the operator-edited
effective-dated `experiments/pricing.json` table (per-million rates by
billing category: input, output, cache read, cache write; reasoning tokens
are displayed but not priced separately because every provider here bills
them as output tokens, so pricing output already covers them). Cross-category
overlaps are removed before pricing - cache reads are netted out of the input
count for providers that report input inclusive of cache - so no token is
billed twice. A missing mandatory input or output token direction, inconsistent
token counts, or a missing price renders cost as N/A with the missing field
named, never as a fabricated zero. The precedence rule is that a
provider-reported billed amount, should one ever be recorded in an artifact,
would be authoritative over this token-derived calculation; no in-tree
provider adapter records such an amount today, so the calculation is currently
the only figure shown. Usage and cost rows are rebuilt from the retained
artifacts by the dashboard Reindex action or the headless
`rig_web --reindex` / `--usage-report` CLI. The CLI and the filesystem
artifacts remain authoritative, the console never reinterprets experiment
semantics, and diagnostic evidence it displays never authorizes a campaign.

The per-model rates can be filled by hand or pulled from each provider's
published pricing page by the fetcher (`experiments/pricing_fetch`, also the
Config section's "Fetch from provider pricing pages" action). The fetcher does
read-only HTTPS GETs of the URLs in `experiments/pricing-sources.json`, matches
model ids exactly, and merges the rates it can read with `auto_fetched` /
`source_url` / `fetched_at` provenance; it never fabricates a price (Anthropic,
OpenAI, DeepSeek, z.ai/GLM and Google Gemini are machine-readable; Moonshot/Kimi
and Alibaba/Qwen render client-side and stay manual) and
never supersedes a model the operator has priced by hand - that figure is
billed on any date until the operator edits it directly; the fetcher only fills
unpriced models or updates rates it set itself. The merge is atomic with a
`.bak` of the prior file, and
a corrupt or non-object `pricing.json` is refused rather than reset, so
hand-entered rates are never lost. Provider API keys are set or rotated from
the Config section (`/config/secrets`); the console records only presence and a
last-four hint, never the value, and writes keys write-only to the operator
secrets file (mode 600).

Console-form to runbook-section mapping (the console builds the identical
argument vectors; nothing below is console-only):

| Console form | Runbook section(s) |
|---|---|
| `project_revision` | 2, 17 |
| `source_conformance` (scaffold and validate) | 4/4.1, 17 |
| `export_jalmbench` / `export_vlsbench` | 3.2 |
| `rig_check` | 8.1, 9-13 |
| `run_matrix` (dry-run, probe, canary, measured) | 4.1, 8/8.1, 9/9.1, 10-13 |
| `live_attestation` | 8.1, 9 |
| `lane_canary` | 8.1, 9.1 |
| `native_import` | 14.3, 16 |
| `human_audit` (common and source-task frames) | 15, 15.1 |
| `judge_sensitivity`, `kappa`, `transfer_matrix`, `paired_compare` | 16 |
| `level1_evidence`, `suite_summary`, `level2_report`, `figures` | 8.1, 16 |
