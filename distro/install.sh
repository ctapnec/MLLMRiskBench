#!/usr/bin/env bash
# URA-Bench rig distro installer - one reproducible script that stands up the
# whole measured-campaign environment on a fresh rig, replacing the ad-hoc pile
# of operator scripts (acquire_sources / fix_acquire / bipia_build / *_export /
# bind_locators). Idempotent: safe to re-run; each source is skipped if already
# materialized. Everything lands under $URA_DATA (the big /data storage), never
# the home partition or the tracked tree.
#
# Secrets (provider API keys, HF_TOKEN) are NOT in this repo. Copy
# distro/.env.example to ~/.ura_secrets, fill it in, and this script sources it.
#
# Usage:
#   distro/install.sh all                 # full setup (deps + every source + locators)
#   distro/install.sh deps                # editable install into the venv only
#   distro/install.sh clones hf archives  # run selected acquisition phases
#   distro/install.sh aggregators         # (re)fetch SALAD/AIR-Bench/XSTest/SST only
#   distro/install.sh locators            # (re)write the URA_*_PATH env bindings
#   distro/install.sh console             # launch the rig console in tmux
#
# Env overrides: URA_DATA (default /data/ura-work), URA_ROOT (repo, autodetected),
# URA_PY_EXTRAS (default "dev,analysis,api,guardrail,local-vllm").
set -uo pipefail

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
URA_ROOT="${URA_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
URA_DATA="${URA_DATA:-/data/ura-work}"
export URA_CORPORA="${URA_CORPORA:-$URA_DATA/corpora}"
export URA_UPSTREAM="${URA_UPSTREAM:-$URA_DATA/upstream}"
LOG="$URA_DATA/acquire-logs"
VENV="$URA_ROOT/.venv"
PY="$VENV/bin/python"
HF="$VENV/bin/hf"
GDOWN="$VENV/bin/gdown"
URA_PY_EXTRAS="${URA_PY_EXTRAS:-dev,analysis,api,guardrail,local-vllm}"
CAMPAIGN_ENV="$HOME/.ura_campaign_env"
SECRETS="$HOME/.ura_secrets"

mkdir -p "$LOG" "$URA_CORPORA" "$URA_UPSTREAM"
[ -f "$SECRETS" ] && source "$SECRETS"
: "${HF_TOKEN:=}"

# Pinned upstream snapshots (verified 12 August 2026; keep in lockstep with the
# retained source-conformance receipt).
REF_STRONGREJECT=f7cad6c17e624e21d8df2278e918ae1dddb4cb56
REF_MMSAFETY=b80eedea3db312c09ded2082813390f68e750ef3
REF_MOSSBENCH=8d68b0614b39d8990a508e03d99975832f399db2
REF_RJUDGE=83ce301da3ad50dd8b397e772863f5411c3d3dc2
REF_GPTGEOCHAT=99a13275a6f4a14bcc1fb8c4038446e574033a64
REF_JAILBREAKV=17e235e4d983ad75adecec2a1e624c3909da9c06
REF_BIPIA=a004b69ec0dd446e0afd461d98cb5e96e120a5d0
REF_HARMBENCH=8e1604d1171fe8a48d8febecd22f600e462bdcdd
REF_SIUO=18974b65d238ad636d65d238541c7d75279ebb3e
REF_ADVBENCH=098262edf85f807224e70ecd87b9d83716bf6b73
REF_FIGSTEP=0861b17b3d67887c06ee3534ec65b3012f9becb7
REF_PURPLELLAMA=e36f132f4c4b952515a03b8bdb1275738a1fa28b
REF_INJECAGENT=f19c9f2c79a41046eb13c03c51a24c567a8ffa07
REF_HF_AGENTHARM=e23b3fe60a0da9037314b88e5ee3a0c054970dad
REF_HF_JBB=886acc352a31533ffbcf4ef22c744658688086fc
REF_HF_JAILBREAKV=f949ca582fff13d396ac8fce59596afafb2b78d3
REF_HF_VLSBENCH=b56f6f6aad102fdb53f46e35fec96836bbe13001
REF_HF_MLLMGUARD=4263487ca736c99292bac92d89f05eb744773450
REF_HF_JALMBENCH=53da5217aad7b5640dd0bed5f58b79b19dde7fb2
REF_HF_VIDEOSAFETY=b04daeb5f6c185df47e2aacb4d30b87912c51114

run_step() { # name cmd...
  local name=$1; shift
  echo "=== $name: $(date -u +%FT%TZ) ===" >> "$LOG/$name.log"
  if "$@" >> "$LOG/$name.log" 2>&1; then
    echo OK > "$LOG/$name.status"; echo "  [ok]   $name"
  else
    echo "FAIL:$?" > "$LOG/$name.status"; echo "  [FAIL] $name (see $LOG/$name.log)"
  fi
}

clone_pin() { # url dir ref
  local url=$1 dir=$2 ref=$3
  if [ -d "$dir/.git" ]; then git -C "$dir" checkout --detach "$ref" && return 0; fi
  git clone "$url" "$dir" && git -C "$dir" checkout --detach "$ref" \
    && test "$(git -C "$dir" rev-parse HEAD)" = "$ref"
}

# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
phase_deps() {
  echo "[deps] editable install into $VENV [$URA_PY_EXTRAS]"
  [ -d "$VENV" ] || python3 -m venv "$VENV"
  "$PY" -m pip install --upgrade pip >/dev/null
  "$PY" -m pip install -e "$URA_ROOT[$URA_PY_EXTRAS]"
  "$PY" -m pip install "huggingface_hub[cli]>=0.24" gdown >/dev/null || true
}

phase_clones() {
  echo "[clones] pinned upstream git snapshots"
  run_step strongreject   clone_pin https://github.com/alexandrasouly/strongreject.git   "$URA_CORPORA/strongreject" "$REF_STRONGREJECT"
  run_step mmsafety-code  clone_pin https://github.com/isXinLiu/MM-SafetyBench.git        "$URA_CORPORA/MM-SafetyBench" "$REF_MMSAFETY"
  run_step mossbench      clone_pin https://github.com/xirui-li/MOSSBench.git             "$URA_CORPORA/MOSSBench" "$REF_MOSSBENCH"
  run_step rjudge         clone_pin https://github.com/Lordog/R-Judge.git                 "$URA_CORPORA/R-Judge" "$REF_RJUDGE"
  run_step gptgeochat-code clone_pin https://github.com/ethanm88/GPTGeoChat.git           "$URA_CORPORA/GPTGeoChat" "$REF_GPTGEOCHAT"
  run_step jailbreakv-code clone_pin https://github.com/SaFoLab-WISC/JailBreakV_28K.git   "$URA_CORPORA/JailBreakV_28K-code" "$REF_JAILBREAKV"
  run_step bipia          clone_pin https://github.com/microsoft/BIPIA.git                "$URA_CORPORA/BIPIA" "$REF_BIPIA"
  run_step harmbench      clone_pin https://github.com/centerforaisafety/HarmBench.git    "$URA_CORPORA/HarmBench" "$REF_HARMBENCH"
  run_step siuo-code      clone_pin https://github.com/sinwang20/SIUO.git                 "$URA_CORPORA/SIUO" "$REF_SIUO"
  run_step advbench       clone_pin https://github.com/llm-attacks/llm-attacks.git        "$URA_CORPORA/llm-attacks" "$REF_ADVBENCH"
  run_step figstep        clone_pin https://github.com/CryptoAILab/FigStep.git            "$URA_CORPORA/FigStep" "$REF_FIGSTEP"
  run_step purplellama    clone_pin https://github.com/meta-llama/PurpleLlama.git         "$URA_CORPORA/PurpleLlama" "$REF_PURPLELLAMA"
  run_step injecagent     clone_pin https://github.com/uiuc-kang-lab/InjecAgent.git       "$URA_CORPORA/InjecAgent" "$REF_INJECAGENT"
}

phase_hf() {
  echo "[hf] pinned Hugging Face dataset releases"
  run_step hf-agentharm   "$HF" download ai-safety-institute/AgentHarm --repo-type dataset --revision "$REF_HF_AGENTHARM" --local-dir "$URA_CORPORA/AgentHarm"
  run_step hf-jbb         "$HF" download JailbreakBench/JBB-Behaviors  --repo-type dataset --revision "$REF_HF_JBB"       --local-dir "$URA_CORPORA/JBB-Behaviors"
  run_step hf-jailbreakv  "$HF" download JailbreakV-28K/JailBreakV-28k --repo-type dataset --revision "$REF_HF_JAILBREAKV" --local-dir "$URA_CORPORA/JailBreakV-28K"
  run_step hf-mllmguard   "$HF" download Carol0110/MLLMGuard           --repo-type dataset --revision "$REF_HF_MLLMGUARD"  --local-dir "$URA_CORPORA/MLLMGuard"
  run_step hf-vlsbench    "$HF" download Foreshhh/vlsbench             --repo-type dataset --revision "$REF_HF_VLSBENCH"   --local-dir "$URA_CORPORA/VLSBench"
  run_step hf-videosafety "$HF" download BAAI/Video-SafetyBench       --repo-type dataset --revision "$REF_HF_VIDEOSAFETY" --local-dir "$URA_CORPORA/Video-SafetyBench"
  run_step hf-jalmbench   "$HF" download AnonymousUser000/JALMBench   --repo-type dataset --revision "$REF_HF_JALMBENCH"  --local-dir "$URA_CORPORA/JALMBench-parquet"
}

phase_archives() {
  echo "[archives] separately-distributed media + one-time exports"
  # MM-SafetyBench images (Google Drive), GPTGeoChat human split, SIUO images,
  # Video-SafetyBench extract, JALMBench/VLSBench parquet exports. These mirror
  # acquire_sources.sh Phases 3-5; see that file's history for the flaky-mirror
  # fallbacks (gdown --continue, MediaFire scrape) if a step FAILs.
  run_step mmsafety-imgs bash -c '
    zip="'"$URA_UPSTREAM"'/MM-SafetyBench-imgs.zip"
    test -s "$zip" || "'"$GDOWN"'" --continue 1xjW9k-aGkmwycqGCXbru70FaSKhSDcR_ -O "$zip"
    "'"$PY"'" -m zipfile -t "$zip"
    tmp="'"$URA_UPSTREAM"'/mmsafety-extract"; rm -rf "$tmp"; mkdir -p "$tmp"
    "'"$PY"'" -m zipfile -e "$zip" "$tmp"
    mkdir -p "'"$URA_CORPORA"'/MM-SafetyBench/data/imgs"
    e=("$tmp"/*); if [ ${#e[@]} -eq 1 ] && [ -d "${e[0]}" ]; then mv "${e[0]}"/* "'"$URA_CORPORA"'/MM-SafetyBench/data/imgs/"; else mv "$tmp"/* "'"$URA_CORPORA"'/MM-SafetyBench/data/imgs/"; fi
    rm -rf "$tmp"'
  run_step video-extract bash -c '
    test -s "'"$URA_CORPORA"'/Video-SafetyBench/video.tar.gz" || exit 1
    mkdir -p "'"$URA_CORPORA"'/Video-SafetyBench/videos"
    tar -xzf "'"$URA_CORPORA"'/Video-SafetyBench/video.tar.gz" -C "'"$URA_CORPORA"'/Video-SafetyBench/videos"'
  ( cd "$URA_ROOT" && run_step export-jalmbench "$PY" -m experiments.export_jalmbench \
      --source "$URA_CORPORA/JALMBench-parquet" --out "$URA_CORPORA/JALMBench-export" \
      --max-records 300000 --max-total-bytes 600000000000 )
  ( cd "$URA_ROOT" && run_step export-vlsbench "$PY" -m experiments.export_vlsbench \
      --source "$URA_CORPORA/VLSBench" --out "$URA_CORPORA/VLSBench-export" \
      --max-records 10000 --max-total-bytes 100000000000 )
}

phase_bipia() {
  echo "[bipia] build qa (NewsQA) + abstract (XSum) sets from external bases"
  export HF_HOME="$URA_DATA/hf-cache" HF_DATASETS_TRUST_REMOTE_CODE=1
  "$PY" -m pip install "datasets==2.14.7" "jsonlines>=4,<5" >> "$LOG/bipia-build.log" 2>&1 || true
  ( cd "$URA_CORPORA/BIPIA/benchmark/abstract" && yes Y | "$PY" process.py ) >> "$LOG/bipia-abstract.log" 2>&1 || echo "  [warn] bipia abstract build failed (external XSum base)"
  ( cd "$URA_CORPORA/BIPIA/benchmark/qa" && "$PY" process.py --data_dir "$URA_UPSTREAM/newsqa-data" ) >> "$LOG/bipia-qa.log" 2>&1 || echo "  [warn] bipia qa build failed (needs licensed NewsQA base)"
}

phase_aggregators() {
  echo "[aggregators] SALAD-Bench + AIR-Bench + XSTest + SimpleSafetyTests + DecodingTrust + HoliSafe"
  ( cd "$URA_ROOT" && run_step export-aggregators "$PY" -m experiments.export_aggregators \
      --source all --out-root "$URA_CORPORA" )
}

phase_locators() {
  echo "[locators] writing URA_*_PATH bindings into $CAMPAIGN_ENV"
  if ! grep -q '# --- URA source locators' "$CAMPAIGN_ENV" 2>/dev/null; then
    cat >> "$CAMPAIGN_ENV" <<ENV
# --- URA source locators (distro/install.sh) ---
export URA_CORPORA=$URA_CORPORA
export URA_UPSTREAM=$URA_UPSTREAM
export URA_ADVBENCH_HARMFUL_PATH=\$URA_CORPORA/llm-attacks/data/advbench/harmful_behaviors.csv
export URA_AGENTHARM_HARMFUL_PATH=\$URA_CORPORA/AgentHarm/benchmark/harmful_behaviors_test_public.json
export URA_AGENTHARM_BENIGN_PATH=\$URA_CORPORA/AgentHarm/benchmark/benign_behaviors_test_public.json
export URA_BIPIA_TEST_EMAIL_PATH=\$URA_CORPORA/BIPIA/benchmark/email/test.jsonl
export URA_BIPIA_TEST_QA_PATH=\$URA_CORPORA/BIPIA/benchmark/qa/test.jsonl
export URA_BIPIA_TEST_ABSTRACT_PATH=\$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl
export URA_BIPIA_TEST_TABLE_PATH=\$URA_CORPORA/BIPIA/benchmark/table/test.jsonl
export URA_BIPIA_TEST_CODE_PATH=\$URA_CORPORA/BIPIA/benchmark/code/test.jsonl
export URA_CYBERSECEVAL_MITRE_PATH=\$URA_CORPORA/PurpleLlama/CybersecurityBenchmarks/datasets/mitre/mitre_benchmark_100_per_category_with_augmentation.json
export URA_CYBERSECEVAL_INTERPRETER_PATH=\$URA_CORPORA/PurpleLlama/CybersecurityBenchmarks/datasets/interpreter/interpreter.json
export URA_CYBERSECEVAL_INSECURE_CODING_PATH=\$URA_CORPORA/PurpleLlama/CybersecurityBenchmarks/datasets/instruct/instruct.json
export URA_CYBERSECEVAL_PROMPT_INJECTION_PATH=\$URA_CORPORA/PurpleLlama/CybersecurityBenchmarks/datasets/prompt_injection/prompt_injection.json
export URA_FIGSTEP_FULL_PATH=\$URA_CORPORA/FigStep/data/question/safebench.csv
export URA_GPTGEOCHAT_RELEASE_PATH=\$URA_CORPORA/GPTGeoChat/human/test
export URA_HARMBENCH_TEXT_PATH=\$URA_CORPORA/HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv
export URA_HARMBENCH_MULTIMODAL_PATH=\$URA_CORPORA/HarmBench/data/behavior_datasets/harmbench_behaviors_multimodal_all.csv
export URA_INJECAGENT_DH_BASE_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_dh_base.json
export URA_INJECAGENT_DH_ENHANCED_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_dh_enhanced.json
export URA_INJECAGENT_DS_BASE_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_ds_base.json
export URA_INJECAGENT_DS_ENHANCED_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_ds_enhanced.json
export URA_JAILBREAKBENCH_HARMFUL_PATH=\$URA_CORPORA/JBB-Behaviors/data/harmful-behaviors.csv
export URA_JAILBREAKBENCH_BENIGN_PATH=\$URA_CORPORA/JBB-Behaviors/data/benign-behaviors.csv
export URA_JAILBREAKV_FULL_PATH=\$URA_CORPORA/JailBreakV-28K/JailBreakV_28K/JailBreakV_28K.csv
export URA_JALMBENCH_AUDIO_MANIFEST_PATH=\$URA_CORPORA/JALMBench-export/jalmbench.jsonl
export URA_MLLMGUARD_PRIVACY_PATH=\$URA_CORPORA/MLLMGuard/desensitize/privacy/en.csv
export URA_MLLMGUARD_BIAS_PATH=\$URA_CORPORA/MLLMGuard/desensitize/bias/en.csv
export URA_MLLMGUARD_TOXICITY_PATH=\$URA_CORPORA/MLLMGuard/desensitize/toxicity/en.csv
export URA_MLLMGUARD_LEGALITY_PATH=\$URA_CORPORA/MLLMGuard/desensitize/legality/en.csv
export URA_MLLMGUARD_HALLUCINATION_PATH=\$URA_CORPORA/MLLMGuard/desensitize/hallucination/en.csv
export URA_MLLMGUARD_POSITION_SWAPPING_PATH=\$URA_CORPORA/MLLMGuard/desensitize/position-swapping/en.csv
export URA_MLLMGUARD_NOISE_INJECTION_PATH=\$URA_CORPORA/MLLMGuard/desensitize/noise-injection/en.csv
export URA_MMSAFETY_OFFICIAL_PATH=\$URA_CORPORA/MM-SafetyBench
export URA_MOSSBENCH_OFFICIAL_PATH=\$URA_CORPORA/MOSSBench
export URA_RJUDGE_RELEASE_PATH=\$URA_CORPORA/R-Judge/data
export URA_SIUO_RELEASE_PATH=\$URA_CORPORA/SIUO/data/siuo_gen.json
export URA_STRONGREJECT_OFFICIAL_PATH=\$URA_CORPORA/strongreject/strongreject_dataset/strongreject_dataset.csv
export URA_VIDEOSAFETYBENCH_BENIGN_QUERY_PATH=\$URA_CORPORA/Video-SafetyBench/benign_data.json
export URA_VIDEOSAFETYBENCH_HARMFUL_QUERY_PATH=\$URA_CORPORA/Video-SafetyBench/harmful_data.json
export URA_VLSBENCH_RELEASE_PATH=\$URA_CORPORA/VLSBench-export/vlsbench.jsonl
# aggregator corpora
export URA_SALADBENCH_PATH=\$URA_CORPORA/SALAD-Data/base_set.json
export URA_AIRBENCH_PATH=\$URA_CORPORA/AIR-Bench-2024/air_bench_default.json
export URA_XSTEST_PATH=\$URA_CORPORA/XSTest/xstest_prompts.csv
export URA_SIMPLESAFETYTESTS_PATH=\$URA_CORPORA/SimpleSafetyTests/simplesafetytests.json
export URA_DECODINGTRUST_STEREOTYPE_PATH=\$URA_CORPORA/DecodingTrust/stereotype.json
export URA_HOLISAFE_PATH=\$URA_CORPORA/HoliSafe/holisafe_bench.json
export URA_MEDIA_ROOTS=\$URA_CORPORA/MM-SafetyBench/data/imgs:\$URA_CORPORA/MOSSBench:\$URA_CORPORA/JailBreakV-28K:\$URA_CORPORA/GPTGeoChat:\$URA_CORPORA/HarmBench:\$URA_CORPORA/VLSBench-export:\$URA_CORPORA/SIUO/data:\$URA_CORPORA/FigStep/data:\$URA_CORPORA/MLLMGuard:\$URA_CORPORA/JALMBench-export:\$URA_CORPORA/Video-SafetyBench
# --- end URA source locators ---
ENV
  fi
  # Register the aggregator arms in the operator source registry (idempotent).
  ( cd "$URA_ROOT" && "$PY" - <<'PY'
import json, collections, pathlib
p = pathlib.Path("experiments/source-instances.json")
d = json.loads(p.read_text()) if p.exists() else {}
adds = {
  "saladbench_base": {"converter":"saladbench","path_env":"URA_SALADBENCH_PATH","source_label":"SALAD-Bench base harmful set (aggregator)","split":"base_set"},
  "airbench_full": {"converter":"airbench","path_env":"URA_AIRBENCH_PATH","source_label":"AIR-Bench 2024 (aggregator)","split":"default-test"},
  "xstest_full": {"converter":"xstest","path_env":"URA_XSTEST_PATH","source_label":"XSTest exaggerated-safety (aggregator)","split":"prompts"},
  "simplesafetytests_full": {"converter":"simplesafetytests","path_env":"URA_SIMPLESAFETYTESTS_PATH","source_label":"SimpleSafetyTests (aggregator)","split":"test"},
  "decodingtrust_stereotype": {"converter":"decodingtrust","path_env":"URA_DECODINGTRUST_STEREOTYPE_PATH","source_label":"DecodingTrust stereotype-bias (aggregator)","split":"stereotype"},
  "holisafe_full": {"converter":"holisafe","path_env":"URA_HOLISAFE_PATH","source_label":"HoliSafe multimodal (aggregator; image carries harm)","split":"bench"},
}
changed = False
for k, v in adds.items():
    if k not in d:
        d[k] = v; changed = True
if changed or not p.exists():
    p.write_text(json.dumps(d, indent=2) + "\n")
print("source-instances.json arms:", len(d))
PY
  )
  echo "  wrote locators; run 'source $CAMPAIGN_ENV' then check with the existence report below"
  source "$CAMPAIGN_ENV" 2>/dev/null || true
  local missing=0
  while IFS= read -r line; do
    case "$line" in
      "export URA_"*PATH=*)
        var=${line#export }; var=${var%%=*}
        value=$(eval "printf '%s' \"\$$var\"")
        if [ -e "$value" ]; then echo "  OK      $var"; else echo "  MISSING $var -> $value"; missing=$((missing+1)); fi ;;
    esac
  done < "$CAMPAIGN_ENV"
  echo "  missing locators: $missing"
}

phase_runtimes() {
  echo "[runtimes] isolated third-party framework environments (strict lock)"
  ( cd "$URA_ROOT" && "$PY" -m experiments.framework_runtime_installer install \
      --python "$(command -v python3.12 || echo python3)" ) || \
      echo "  [warn] framework runtimes need an exact CPython 3.12.13 base; see the runbook"
}

phase_console() {
  echo "[console] launching the rig console in tmux session 'console' on :8642"
  pkill -f 'experiments.rig_web' 2>/dev/null || true; sleep 1
  tmux kill-session -t console 2>/dev/null || true
  tmux new-session -d -s console \
    "source $CAMPAIGN_ENV 2>/dev/null; cd $URA_ROOT && exec $PY -m experiments.rig_web --results-root runs --state-dir runs/rig-web"
  sleep 3
  curl -s -o /dev/null -w "  console http %{http_code}\n" http://127.0.0.1:8642/ || true
}

# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
PHASES=("$@"); [ ${#PHASES[@]} -eq 0 ] && PHASES=(all)
for phase in "${PHASES[@]}"; do
  case "$phase" in
    all)          phase_deps; phase_clones; phase_hf; phase_archives; phase_bipia; phase_aggregators; phase_locators ;;
    deps)         phase_deps ;;
    clones)       phase_clones ;;
    hf)           phase_hf ;;
    archives)     phase_archives ;;
    bipia)        phase_bipia ;;
    aggregators)  phase_aggregators ;;
    locators)     phase_locators ;;
    runtimes)     phase_runtimes ;;
    console)      phase_console ;;
    *) echo "unknown phase: $phase" >&2; exit 2 ;;
  esac
done
echo "distro/install.sh: done (phases: ${PHASES[*]})"
