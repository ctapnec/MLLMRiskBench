# Run and return: broad thesis experiment program

This is the operator path from a clean Linux GPU machine to the evidence bundle
for the thesis. It covers the broad hosted and local model roster, all nineteen
source converters, the runner-safe external attack bridges, and nine complete
source-native evaluators. Experiments and the human audit are still pending.
Preflight, dry-run, and one-record transport probes are diagnostics, not thesis
results.

The maintained artifact contract is Runner `ura-runner/2.5` with unified schema
`1.4`. Do not combine older-runner artifacts with this program.

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
  CyberSecEval prompt injection, and MLLMGuard hallucination remain conversion
  or upstream-native tracks until their exact source scorer/runtime is integrated.
  Runner preflight rejects those records before a model call.
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
| RQ1 execution conformance | §§7--14 | requested-cell eligibility/`N/A`, modality plan/result, complete content-bound cells |
| RQ2 matched served-model conditions | focal grids and §16 paired/figure commands | matched cluster support/effects plus exact realized identities |
| RQ3 portfolio breadth/heterogeneity | 39 converter arms, nine native projects, §16 suite summary | disposition-complete family inventory without false pooling |
| RQ4a defense | §13 guarded/unguarded same-base design | separate harmful and benign paired effects |
| RQ4b adaptivity/native execution | §12 Crescendo/transfer and §14 native runtimes | fixed-horizon conversation, exact-transfer, or source task/oracle evidence |
| RQ5 judge validity | §§15--16 | eligible common-response human labels, adjudication, decision coverage and cluster-aware agreement/calibration |

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
| `truthfulness` | MLLMGuard hallucination | reserved; pending a substantive scorer in the runner |
| `evaluator_reliability` | decision coverage, confusion/calibration, automated-human and inter-rater agreement | achieved independently labelled common-response population; never infer validity from stage concordance alone |

`experiments.suite_summary` applies these crosswalks but does not pool the
heterogeneous rates.

## 2. Machine and URA installation

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
# protocol amendment made before inspecting outcomes.
export REF_URA='<full-40-hex-reviewed-post-fix-project-commit>'
test "${#REF_URA}" -eq 40
git checkout --detach "$REF_URA"
test "$(git rev-parse HEAD)" = "$REF_URA"
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,analysis,api,guardrail]"
python -m pip install "huggingface_hub[cli]"

# Required only for the local vLLM lanes in section 13. Pin the version that the
# operator has verified against this machine's CUDA, PyTorch, and driver stack.
export VLLM_VERSION='<operator-reviewed-compatible-version>'
python -m pip install "vllm==$VLLM_VERSION"
```

Use access-controlled storage. Review every upstream license, model access term,
data-use restriction, provider retention policy, and institutional approval before
acquisition or calls. Do not put secrets, harmful artifacts, or restricted corpora
in Git.

## 3. Acquire all nineteen converter sources

The commands below use exact maintained snapshots verified on 12 August 2026.
The operator must still review each repository, access condition, and license and
record the accepted commits in `runs/thesis/RUNNOTE.md`. A moving branch name is
not a research identity. If a later snapshot is deliberately substituted, replace
the corresponding full `REF_*` value and record why before running that lane.

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
`images/` directories.

### 3.2 Hugging Face releases and large media

Set every `REF_HF_*` variable to the full dataset repository commit shown by the
operator's reviewed release. Gated sources require `HF_TOKEN` from a secret
manager. The commands below use only official repositories.

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
| `mllmguard` | gated `Carol0110/MLLMGuard` | one per-dimension table beside `imgs/` | non-hallucination common; hallucination pending truthfulness scorer |
| `jalmbench` | `AnonymousUser000/JALMBench` | exported `jalmbench.jsonl` | common harmful text+audio |
| `videosafetybench` | `BAAI/Video-SafetyBench` | benign or harmful metadata JSON/JSONL beside videos | common harmful text+video |

Do not guess file names after downloading. Inspect the acquired tree, select the
official table matching the converter contract above, and run the preflight. A
missing or structurally different release is an explicit blocked source, not a
reason to edit the data until it passes.

## 4. Configure source arms and media

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
```

The BIPIA task files require their official attack companion files in the
release-relative positions expected by the converter. CyberSecEval prompt
injection and MLLMGuard hallucination also stay outside ordinary scored lanes:
their substantive task/truthfulness evaluators are not implemented. Run
`rig_check` after filling locators; a placeholder or layout mismatch must stop
the lane.

For clarity, the acquired but intentionally unscored arms are both AgentHarm
behavior sets, all five BIPIA tasks, CyberSecEval prompt injection, all four
InjecAgent sets, and MLLMGuard hallucination. Their records are useful for
provenance and later native-runtime integration, but a target response without
the official tool/task/truthfulness evaluator is not a defensible result. Any
separate upstream execution remains supplementary until a complete-artifact
importer exists; do not inject it into `suite_summary` as if it were a runner
cell.

Set one ordered media-root list containing every real media tree used by the
selected arms. On POSIX the separator is `:`; on Windows it is `;`. Keep the
order unchanged when resuming or relocating a run.

```bash
export URA_MEDIA_ROOTS="$URA_CORPORA/MM-SafetyBench/data/imgs:$URA_CORPORA/MOSSBench:$URA_CORPORA/JailBreakV-28K:$URA_CORPORA/GPTGeoChat:$URA_CORPORA/HarmBench:$URA_CORPORA/VLSBench-export:$URA_CORPORA/SIUO/data:$URA_CORPORA/FigStep/data:$URA_CORPORA/MLLMGuard:$URA_CORPORA/JALMBench-export:$URA_CORPORA/Video-SafetyBench"
```

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
as `openai:gpt-5.6-terra`, `openai:gpt-5.6-luna`, or `glm:glm-5.2` are not
asserted available by this runbook. Do not silently substitute another model.

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
video. Use one local target per `run_matrix` process. With an 8B-class target,
`tensor_parallel_size: 1` leaves the second GPU for the scoring guard. A two-GPU
target leaves no GPU for that guard on this rig and is therefore a different,
explicit execution condition.

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

Run the full offline regression first:

```bash
python -m pytest -p no:cacheprovider
python -m ruff check --no-cache .
python -m compileall src experiments
python -m experiments.run_matrix --dry-run \
  --attackers replay,crescendo --judges rules,llm \
  --corpora synth --limit 12 --seeds 0,1 \
  --max-queries 4 --max-turns 4 --out runs/thesis/diagnostics/dry
python -m experiments.figures --synth --out runs/thesis/diagnostics/figure-check
```

Then run one real bounded transport check per claimed physical modality for each
exact hosted model. This is the only way to catch account visibility and request
serialization failures before the large grids. Use a stable `TARGET_LABEL` that
contains no secret or local path.

```bash
export TARGET='<one-exact-target-spec>'
export TARGET_LABEL='<short-logical-label>'
export PROBE_ARM='strongreject_official'  # image=mmsafety_official, audio=jalmbench_audio, video=videosafetybench_harmful_query
export PROBE_MODALITY='text'     # text, image, audio, or video

python -m experiments.rig_check \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$PROBE_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --max-total-target-calls 16 --max-total-judge-calls 1 \
  --max-total-http-attempts 64 --deadline-seconds 3600 \
  --out "runs/thesis/attestation/$TARGET_LABEL/$PROBE_MODALITY"

python -m experiments.run_matrix \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$PROBE_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --max-total-target-calls 16 --max-total-judge-calls 1 \
  --max-total-http-attempts 64 --deadline-seconds 3600 \
  --out "runs/thesis/attestation/$TARGET_LABEL/$PROBE_MODALITY"
```

Repeat as follows:

- every hosted target: StrongREJECT text;
- every target that declares image: MM-SafetyBench image;
- every target that declares audio: JALMBench audio;
- every target that declares video: Video-SafetyBench video.

Fable and Sol do not require entries in `api-targets.json`; a generic target and
the generic LLM judge do. The config may contain a reusable roster superset.
Keep these probe artifacts under `attestation/`; do not include them in measured
aggregates or present them as safety estimates.

For a local target, use the same pattern with `--local` and its exact
`--local-config`, and run one process at a time. Local audio/video claims are not
supported by this code.

## 9. Plan lanes with the no-call rig check

Every measured grid below must first be passed with the same grid-defining
arguments to `python -m experiments.rig_check`. It loads and validates sources
and media, loads a local target engine before scoring/defense guards when a
local target is selected, checks model/source modality compatibility, and prints
policy-stratum counts plus projected target, guard, LLM-judge, and HTTP-attempt
totals without a hosted generation call. Only the planning ceilings differ from
the later measured command. `rig_check` executes the no-call plan in temporary
scratch storage but copies its content-addressed eligibility/`N/A` ledger into
the requested `--out` directory, including when a later compatibility gate
fails. That ledger is planning evidence only and is not a live attestation.

For planning, use finite values larger than the projection. Copy the printed
projection into the measured command's lane-specific ceilings; add capacity only
when explicitly justified in the run note. Do not reuse one lane's ledger or
ceilings for another lane.

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

## 10. Tier 1: broad static replay

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
  --out runs/thesis/runner/static-text

python -m experiments.run_matrix \
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

Add every acquired non-hallucination MLLMGuard dimension as its own arm. Keep
MOSSBench's benign refusal endpoint separate from harmful image ASR.

```bash
export IMAGE_ARMS='mmsafety_official,jailbreakv_full,harmbench_multimodal,vlsbench_release,mossbench_official,siuo_release,figstep_full,mllmguard_privacy,mllmguard_bias,mllmguard_toxicity,mllmguard_legality,mllmguard_position_swapping,mllmguard_noise_injection'

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
  --out runs/thesis/runner/static-image
```

After the check succeeds, replace `experiments.rig_check` with
`experiments.run_matrix` and replace all three planning ceilings with the printed
totals. Automated stages do not inspect image pixels: for released image sources
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
  --out runs/thesis/runner/static-audio

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
  --out runs/thesis/runner/static-video
```

For each, repeat with `experiments.run_matrix` and the exact successful
projection. Do not send transcripts, captions, or extracted frames to a target
and label that as audio/video execution. The maintained automated judges never
receive image, audio, or video bytes: they grade a declared source-text reference
plus the target output. Such evidence is a text-reference proxy, not a
media-aware grade. A substantive media-grading claim requires a source-native
media evaluator or the media-resolving human audit.

JALMBench contains 245,355 audio rows. The maintained lane is therefore a
seeded, bounded source-cluster breadth sample, not an impractical two-repeat
full-release sweep. `--limit 5000` selects at most 5,000 underlying prompt
clusters and retains their related acoustic/attack variants, so the realized row
and call counts may exceed 5,000. Accept the post-conversion projection rather
than treating the limit as a call count. Report realized cluster, row,
attack/language/acoustic strata and sample-conditional scope. Expanding it is a
separate funded decision after the call projection is combined with provider
pricing, token, audio-input, and latency assumptions in `RUNNOTE.md`.

## 11. Tier 2: source-specific classification

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
  --deadline-seconds 7776000 --out runs/thesis/runner/rjudge

# GPTGeoChat: image-capable roster, five moderation thresholds per conversation.
python -m experiments.rig_check \
  --api "$IMAGE_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora gptgeochat_release --source-config experiments/source-instances.json \
  --limit 0 --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,risk,effective_modality --max-total-target-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds 7776000 --out runs/thesis/runner/gptgeochat
```

The no-call projection must report zero model-judge calls and zero local
guardrail evaluations. A non-zero value means this source-only lane is
misconfigured and must not proceed. Repeat each successful check with
`experiments.run_matrix` and the exact printed target-call and HTTP-attempt
ceilings; omission of `--max-total-judge-calls` is intentional because no
model-backed judge is configured or called. R-Judge reports source-label
classification statistics against its reference labels, not independently
established validity; the risk-explanation effectiveness stage is not
implemented. GPTGeoChat reports
threshold-conditioned moderation classification, not a target geolocation ASR.

## 12. Tier 3: adaptive and transferred attacks

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
  --out runs/thesis/runner/crescendo-text
```

Repeat with `experiments.run_matrix` and the printed totals. This lane reports
conversation endpoints; it does not enter static ASR.

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
  --deadline-seconds 7776000 --out "runs/thesis/runner/transfer-$ATTACKER"
```

Run h4rm3l and Spikee in separate invocations with
`--max-queries 4 --max-turns 4`; otherwise the Runner's shared query/turn budget
admits only the first generated variant. The completed artifacts, not the
configured maximum, establish the realized variant count.

Because `attacker-config.json` must contain only selected attacker keys, create a
one-attacker copy for each invocation or remove the unselected rows before the
check. Repeat the successful check with `experiments.run_matrix` and its exact
totals.

The remaining runner bridges are specialized:

| Bridge | Defensible use in this program |
| --- | --- |
| `nanogcg` | precomputed suffix with `suffix_source`, or live optimization on an immutable local surrogate; report as surrogate transfer |
| `harmbench` attacker | run pinned upstream text test-case generation and replay the complete generated artifact family; not native HarmBench scoring |
| `purplellama` | only with `cyberseceval` rows; source-identity replay, not the native pipeline |
| `ideator` | verified precomputed text-image `seed_pairs` only; live package path is disabled |
| `t3mp3st` | request-bound planning response artifact or loopback planning endpoint only; never an execute/tool route |

Run these only after preparing their exact attacker config and passing
`rig_check`. Do not claim that a complete upstream evaluator ran. Garak,
Promptfoo, Petri, FuzzyAI, EasyJailbreak, AutoDAN-Turbo, Giskard, ASB, and
AgentDojo are not runner attackers; they belong in the native track below.

Live/source-model HarmBench generation, a T3MP3ST loopback planner, and local
nanoGCG optimization are not covered by the Runner's target/judge/HTTP budget or
its post-generation checkpoint. They can repeat work on resume. Do not place a
paid or source-model-conditioned generator inside a measured Runner grid.
Execute it first as a separately capped canary/campaign with its own hard
provider quota, retain the complete immutable output plus generator/model/config
identity and SHA-256, then use only that content-addressed precomputed artifact
for the measured transfer lane. If such precomputation is unavailable, mark the
specialized lane pending/`N/A` or omit it as optional; do not describe it as
protected by the common call ceilings.

## 13. Tier 4: local targets and defense contrast

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
  --deadline-seconds 7776000 --out runs/thesis/runner/local-qwen3-vl-text
```

Repeat with `run_matrix` and exact totals, allow the process to exit, then run the
image lane. Repeat both for the LLaVA base and GraySwan RR checkpoint using their
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
  --deadline-seconds 7776000 --out runs/thesis/runner/defense-text
```

Run matching no-defense cells for the same focal targets and clusters. Added
value is measured as the harmful/benign tradeoff; lower harmful ASR without the
benign refusal cost is an incomplete defense analysis.

## 14. Tier 5: nine source-native evaluators

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

## 16. Read-only analysis and suite summary

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

The maintained measured-figure command still renders the declared paired core
figures, not the whole broad roster. Invoke it only after the matching core grids
and human audit exist. The explicit corpus aliases reuse those broad-root cells;
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

Each lane is complete only when its command exits zero, the grid reports zero
failed cells, every requested cell has a completion marker, modality coverage is
realized, and the durable ledgers reconcile with provider usage. Resume a stopped
lane by rerunning its identical command. Use `--reset-open-circuits` only after
correcting and documenting the provider or judge failure that opened the circuit.

Create `runs/thesis/RUNNOTE.md` and record:

- UTC start/end, host, OS, Python, CUDA, driver, and both GPU identities;
- `git rev-parse HEAD` and `git status --short` for URA and every upstream checkout;
- source/model revisions, source file hashes, exact commands, lane ceilings, and
  non-secret endpoint routes;
- exact requested and resolved model IDs, account region/tier, and modality probe
  outcomes;
- package inventories for URA and every native environment;
- interruptions, retries, exclusions, unavailable cells, and their reasons;
- projected and realized provider calls for every runner and native lane,
  provider-side native hard quotas, and provider usage/cost reconciliation; and
- human-audit status and achieved per-stratum counts.

Capture the URA environment and harness identity:

```bash
python -m pip list --format=json > runs/thesis/environment-packages.json
git rev-parse HEAD > runs/thesis/harness-commit.txt
git status --short > runs/thesis/harness-status.txt
```

Before return, re-run every canonical native validation from the complete
config/raw/envelope tree and rebuild the suite
summary into a new output name if the existing file already exists. Verify that
the tree contains grid descriptors, manifests, attempts, responses, judgments,
shadow trails, checkpoints, completion/error records, aggregates, modality
coverage, call ledgers, native raw artifacts and canonical envelopes, human-audit
files, analyses, figures, and the run note.

```bash
tar -czf ura-thesis-return.tgz runs/thesis
sha256sum ura-thesis-return.tgz > ura-thesis-return.tgz.sha256
```

Do not return API keys, shell history, secret-manager exports, model caches, or
restricted source releases unless the recipient is explicitly authorized. Mock,
synthetic, partial, manually edited, failed, or diagnostic-only artifacts remain
diagnostics and cannot be promoted to thesis evidence.
