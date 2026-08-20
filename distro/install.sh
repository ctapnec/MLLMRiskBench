#!/usr/bin/env bash
# URA-Bench rig distro installer - one reproducible script that stands up the
# whole measured-campaign environment on a fresh rig, start to end, replacing
# the ad-hoc pile of operator scripts (acquire_sources / fix_acquire /
# fix2_acquire / bipia_build / *_export / bind_locators / start_console).
# Idempotent: safe to re-run; each source is skipped if already materialized.
# Everything lands under $URA_DATA (the big /data storage), never the home
# partition or the tracked tree.
#
# Secrets (provider API keys, HF_TOKEN) are NOT in this repo. Copy
# distro/.env.example to ~/.ura_secrets, fill it in, and this script sources it
# (~/.ura_env is honored too for rigs provisioned before this installer).
#
# Usage:
#   distro/install.sh all                 # FULL setup: deps + every corpus +
#                                         # ollama + runtimes + locators + console
#   distro/install.sh deps                # editable install into the venv only
#   distro/install.sh clones hf archives  # run selected acquisition phases
#   distro/install.sh aggregators         # (re)fetch SALAD/AIR-Bench/XSTest/SST/
#                                         # DecodingTrust/HoliSafe only
#   distro/install.sh ollama              # user-local ollama runtime
#   distro/install.sh locators            # (re)write the URA_*_PATH env bindings
#   distro/install.sh console             # launch the rig console in tmux
#   distro/install.sh summary             # per-step OK/FAIL report from the logs
#
# Env overrides: URA_DATA (default /data/ura-work), URA_ROOT (repo, autodetected),
# URA_PY_EXTRAS (default "dev,analysis,api,guardrail,local-vllm").
set -uo pipefail

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
URA_ROOT="${URA_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
URA_DATA="${URA_DATA:-/data/ura-work}"
export URA_WORK="$URA_DATA"
export URA_CORPORA="${URA_CORPORA:-$URA_DATA/corpora}"
export URA_UPSTREAM="${URA_UPSTREAM:-$URA_DATA/upstream}"
export URA_NATIVE_ENVS="${URA_NATIVE_ENVS:-$URA_DATA/native-envs}"
export HF_HOME="${HF_HOME:-$URA_DATA/hf-cache}"
LOG="$URA_DATA/acquire-logs"
VENV="$URA_ROOT/.venv"
PY="$VENV/bin/python"
HF="$VENV/bin/hf"
GDOWN="$VENV/bin/gdown"
URA_PY_EXTRAS="${URA_PY_EXTRAS:-dev,analysis,api,guardrail,local-vllm}"
CAMPAIGN_ENV="$HOME/.ura_campaign_env"
SECRETS="$HOME/.ura_secrets"

mkdir -p "$LOG" "$URA_CORPORA" "$URA_UPSTREAM" "$URA_NATIVE_ENVS" "$HF_HOME" || {
  echo "cannot create the data tree under $URA_DATA - check the mount and permissions" >&2
  exit 3
}
[ -w "$LOG" ] || { echo "$LOG is not writable - check the mount and permissions" >&2; exit 3; }
# set -a exports everything the secrets files define (HF_TOKEN included), so
# child processes ($HF, $PY exporters) actually see them. ~/.ura_env is the
# legacy file and is sourced FIRST so ~/.ura_secrets (the documented primary)
# wins on any key present in both - the same precedence the console launcher uses.
set -a
[ -f "$HOME/.ura_env" ] && source "$HOME/.ura_env"
[ -f "$SECRETS" ] && source "$SECRETS"
set +a
export HF_TOKEN="${HF_TOKEN:-}"

# Per-invocation ledger: run_step/skip_step append here (append survives the
# subshells some phases use), so the exit status reflects THIS run only.
SESSION_LEDGER="$LOG/.session-$$"
: > "$SESSION_LEDGER"
trap 'rm -f "$SESSION_LEDGER"' EXIT

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
MMSAFETY_DRIVE_ID=1xjW9k-aGkmwycqGCXbru70FaSKhSDcR_
GPTGEOCHAT_MEDIAFIRE='https://www.mediafire.com/file/luwlv2p9ofgxdb5/human.zip/file'

run_step() { # name cmd...
  local name=$1; shift
  echo "=== $name: $(date -u +%FT%TZ) ===" >> "$LOG/$name.log"
  # .running marks an in-flight step: if the installer is killed mid-step the
  # marker survives, so the next run must NOT adopt the half-written output.
  : > "$LOG/$name.running"
  if "$@" >> "$LOG/$name.log" 2>&1; then
    echo OK > "$LOG/$name.status"; : > "$LOG/$name.done"
    echo "OK $name" >> "$SESSION_LEDGER"; echo "  [ok]   $name"
  else
    echo "FAIL:$?" > "$LOG/$name.status"; rm -f "$LOG/$name.done"
    echo "FAIL $name" >> "$SESSION_LEDGER"; echo "  [FAIL] $name (see $LOG/$name.log)"
  fi
  rm -f "$LOG/$name.running"
}

skip_step() { # name reason -- records OK so the ledger stays truthful on re-runs
  local name=$1 reason=$2
  echo OK > "$LOG/$name.status"; : > "$LOG/$name.done"
  echo "SKIP $name" >> "$SESSION_LEDGER"
  echo "  [skip] $name ($reason)"
}

# A step may be skipped only when its own completion sentinel exists, or when
# pre-existing output can be safely adopted: the content guard passes AND the
# step was never recorded FAIL AND it was not interrupted mid-flight. This is
# what keeps a truncated corpus from being reported OK on a re-run.
step_settled() { # name -- true when the completion sentinel is present
  [ -f "$LOG/$1.done" ]
}

step_adoptable() { # name -- true when pre-existing output may be trusted
  local name=$1
  [ -f "$LOG/$name.running" ] && return 1
  [ -f "$LOG/$name.status" ] && ! grep -q '^OK' "$LOG/$name.status" && return 1
  return 0
}

guard_step() { # name reason content-test... -- skip when settled/adoptable, else run
  local name=$1 reason=$2; shift 2
  if step_settled "$name"; then
    skip_step "$name" "$reason"; return 0
  fi
  if "$@" && step_adoptable "$name"; then
    skip_step "$name" "$reason (adopted pre-existing output)"; return 0
  fi
  return 1
}

clone_pin() { # url dir ref -- clone once, then repair-checkout with a fetch
  local url=$1 dir=$2 ref=$3
  if [ -d "$dir/.git" ]; then
    if git -C "$dir" rev-parse --verify -q "$ref^{commit}" >/dev/null 2>&1; then
      git -C "$dir" checkout --detach "$ref"
    else
      git -C "$dir" fetch origin "$ref" \
        && git -C "$dir" checkout --detach "$ref"
    fi \
      && test "$(git -C "$dir" rev-parse HEAD)" = "$ref"
    return
  fi
  git clone "$url" "$dir" && git -C "$dir" checkout --detach "$ref" \
    && test "$(git -C "$dir" rev-parse HEAD)" = "$ref"
}

nonempty_dir() { [ -d "$1" ] && [ -n "$(ls -A "$1" 2>/dev/null)" ]; }

prereqs() {
  local missing=0 tool
  for tool in git curl tar python3 tmux; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  [FAIL] missing prerequisite: $tool"; missing=1; }
  done
  [ "$missing" -eq 0 ] || { echo "install prerequisites first (apt install git curl tar python3-venv tmux)"; exit 3; }
  if [ -z "$HF_TOKEN" ]; then
    echo "  [warn] HF_TOKEN is empty - gated HF datasets (AgentHarm, DecodingTrust,"
    echo "         HoliSafe) WILL fail. Copy distro/.env.example to ~/.ura_secrets and fill it."
  fi
}

# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
phase_deps() {
  echo "[deps] editable install into $VENV [$URA_PY_EXTRAS]"
  # Everything downstream runs out of this venv, so a deps failure is fatal to
  # the run: record it in the ledger and report it, never continue silently.
  local failed=0
  [ -d "$VENV" ] || python3 -m venv "$VENV" || failed=1
  if [ "$failed" -eq 0 ]; then
    "$PY" -m pip install --upgrade pip >/dev/null || failed=1
    "$PY" -m pip install -e "$URA_ROOT[$URA_PY_EXTRAS]" || failed=1
    "$PY" -m pip install "huggingface_hub[cli]>=0.24" gdown >> "$LOG/deps-tools.log" 2>&1 || failed=1
  fi
  local tool
  for tool in "$PY" "$HF" "$GDOWN"; do
    [ -x "$tool" ] || { echo "  [FAIL] expected tool missing after install: $tool (see $LOG/deps-tools.log)"; failed=1; }
  done
  if [ "$failed" -eq 0 ]; then
    echo OK > "$LOG/deps.status"; : > "$LOG/deps.done"
    echo "OK deps" >> "$SESSION_LEDGER"; echo "  [ok]   deps (venv + hf + gdown present)"
    return 0
  fi
  echo "FAIL:1" > "$LOG/deps.status"; rm -f "$LOG/deps.done"
  echo "FAIL deps" >> "$SESSION_LEDGER"
  echo "  [FAIL] deps - every later phase depends on this venv"
  return 1
}

phase_clones() {
  echo "[clones] pinned upstream git snapshots"
  run_step strongreject    clone_pin https://github.com/alexandrasouly/strongreject.git   "$URA_CORPORA/strongreject" "$REF_STRONGREJECT"
  run_step mmsafety-code   clone_pin https://github.com/isXinLiu/MM-SafetyBench.git        "$URA_CORPORA/MM-SafetyBench" "$REF_MMSAFETY"
  run_step mossbench       clone_pin https://github.com/xirui-li/MOSSBench.git             "$URA_CORPORA/MOSSBench" "$REF_MOSSBENCH"
  run_step rjudge          clone_pin https://github.com/Lordog/R-Judge.git                 "$URA_CORPORA/R-Judge" "$REF_RJUDGE"
  run_step gptgeochat-code clone_pin https://github.com/ethanm88/GPTGeoChat.git            "$URA_CORPORA/GPTGeoChat" "$REF_GPTGEOCHAT"
  run_step jailbreakv-code clone_pin https://github.com/SaFoLab-WISC/JailBreakV_28K.git    "$URA_CORPORA/JailBreakV_28K-code" "$REF_JAILBREAKV"
  run_step bipia           clone_pin https://github.com/microsoft/BIPIA.git                "$URA_CORPORA/BIPIA" "$REF_BIPIA"
  run_step harmbench       clone_pin https://github.com/centerforaisafety/HarmBench.git    "$URA_CORPORA/HarmBench" "$REF_HARMBENCH"
  run_step siuo-code       clone_pin https://github.com/sinwang20/SIUO.git                 "$URA_CORPORA/SIUO" "$REF_SIUO"
  run_step advbench        clone_pin https://github.com/llm-attacks/llm-attacks.git        "$URA_CORPORA/llm-attacks" "$REF_ADVBENCH"
  run_step figstep         clone_pin https://github.com/CryptoAILab/FigStep.git            "$URA_CORPORA/FigStep" "$REF_FIGSTEP"
  run_step purplellama     clone_pin https://github.com/meta-llama/PurpleLlama.git         "$URA_CORPORA/PurpleLlama" "$REF_PURPLELLAMA"
  run_step injecagent      clone_pin https://github.com/uiuc-kang-lab/InjecAgent.git       "$URA_CORPORA/InjecAgent" "$REF_INJECAGENT"
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

# -- archive helpers (ported from the rig's proven fix_acquire/fix2_acquire) -- #
mmsafety_imgs() {
  local zip="$URA_UPSTREAM/MM-SafetyBench-imgs.zip" attempt
  rm -f "$URA_UPSTREAM"/MM-SafetyBench-imgs.zip*.part
  if ! "$PY" -m zipfile -t "$zip" >/dev/null 2>&1; then
    for attempt in 1 2 3; do
      echo "--- gdown attempt $attempt ---"
      timeout 600 "$GDOWN" --continue "$MMSAFETY_DRIVE_ID" -O "$zip" \
        && "$PY" -m zipfile -t "$zip" >/dev/null 2>&1 && break
      sleep 15
    done
  fi
  if ! "$PY" -m zipfile -t "$zip" >/dev/null 2>&1; then
    echo "--- curl fallback (fresh start; a failed seed file is never resumed) ---"
    # Never resume onto the file that just failed the integrity test: Drive
    # serves an HTML quota interstitial that -C - would happily append to.
    rm -f "$zip"
    for attempt in 1 2 3; do
      timeout 900 curl -fL -C - -A "Mozilla/5.0" \
        -o "$zip" "https://drive.google.com/uc?id=$MMSAFETY_DRIVE_ID&confirm=t" \
        && "$PY" -m zipfile -t "$zip" >/dev/null 2>&1 && break
      rm -f "$zip"
      sleep 15
    done
  fi
  "$PY" -m zipfile -t "$zip" || return 1
  local tmp="$URA_UPSTREAM/mmsafety-extract"
  rm -rf "$tmp" && mkdir -p "$tmp"
  "$PY" -m zipfile -e "$zip" "$tmp" || return 1
  mkdir -p "$URA_CORPORA/MM-SafetyBench/data/imgs"
  # Thirteen scenario directories must sit directly below data/imgs. A failed
  # mv must NOT be followed by rm -rf "$tmp" - that would destroy the only copy
  # of whatever did not move.
  local entries=("$tmp"/*)
  if [ ${#entries[@]} -eq 1 ] && [ -d "${entries[0]}" ]; then
    mv "${entries[0]}"/* "$URA_CORPORA/MM-SafetyBench/data/imgs/" || return 1
  else
    mv "$tmp"/* "$URA_CORPORA/MM-SafetyBench/data/imgs/" || return 1
  fi
  rm -rf "$tmp"
  local scenarios
  scenarios=$(find "$URA_CORPORA/MM-SafetyBench/data/imgs" -mindepth 1 -maxdepth 1 -type d | wc -l)
  echo "scenario directories under data/imgs: $scenarios"
  [ "$scenarios" -ge 13 ] || { echo "expected >=13 scenario directories, found $scenarios"; return 1; }
}

gptgeochat_human() {
  local zip="$URA_UPSTREAM/GPTGeoChat-human.zip"
  if ! "$PY" -m zipfile -t "$zip" >/dev/null 2>&1; then
    rm -f "$zip"
    local html direct
    html=$(timeout 120 curl -fsSL -A "Mozilla/5.0" "$GPTGEOCHAT_MEDIAFIRE") || return 1
    direct=$(printf '%s' "$html" | grep -oE 'href="https://download[^"]+"' \
      | head -1 | sed 's/^href="//; s/"$//')
    if [ -z "$direct" ]; then
      direct=$(printf '%s' "$html" \
        | grep -oE 'https://download[A-Za-z0-9.-]*\.mediafire\.com/[^"'"'"' ]+' | head -1)
    fi
    echo "mediafire direct URL: $direct"
    test -n "$direct" || return 1
    timeout 1800 curl -fSL --retry 3 -C - -A "Mozilla/5.0" -o "$zip" "$direct" || return 1
  fi
  "$PY" -m zipfile -t "$zip" || return 1
  "$PY" -m zipfile -e "$zip" "$URA_CORPORA/GPTGeoChat/" || return 1
  # Normalize both released zip layouts to GPTGeoChat/gptgeochat/human/...
  if [ -d "$URA_CORPORA/GPTGeoChat/human" ] && [ ! -d "$URA_CORPORA/GPTGeoChat/gptgeochat/human" ]; then
    mkdir -p "$URA_CORPORA/GPTGeoChat/gptgeochat"
    mv "$URA_CORPORA/GPTGeoChat/human" "$URA_CORPORA/GPTGeoChat/gptgeochat/human"
  fi
  test -d "$URA_CORPORA/GPTGeoChat/gptgeochat/human/test"
}

siuo_images() {
  # The official sinwang/SIUO HF dataset ships images/ directly (no zip).
  if ! nonempty_dir "$URA_CORPORA/SIUO-hf/images"; then
    "$HF" download sinwang/SIUO --repo-type dataset --local-dir "$URA_CORPORA/SIUO-hf" || return 1
  fi
  test -d "$URA_CORPORA/SIUO-hf/images" || return 1
  rm -rf "$URA_CORPORA/SIUO/data/images"
  mkdir -p "$URA_CORPORA/SIUO/data"
  cp -r "$URA_CORPORA/SIUO-hf/images" "$URA_CORPORA/SIUO/data/images" || return 1
  local src dst
  src=$(find "$URA_CORPORA/SIUO-hf/images" -type f | wc -l)
  dst=$(find "$URA_CORPORA/SIUO/data/images" -type f | wc -l)
  echo "SIUO images copied: $dst of $src"
  [ "$dst" -eq "$src" ] && [ "$src" -gt 0 ]
}

video_extract() {
  test -s "$URA_CORPORA/Video-SafetyBench/video.tar.gz" || { echo "video.tar.gz not materialized by the hf phase"; return 1; }
  mkdir -p "$URA_CORPORA/Video-SafetyBench/videos"
  tar -xzf "$URA_CORPORA/Video-SafetyBench/video.tar.gz" -C "$URA_CORPORA/Video-SafetyBench/videos"
}

jailbreakv_image_backed() {
  # The HF release ships images for a subset of rows; the campaign runs on the
  # image-backed subset so every persisted media path resolves.
  "$PY" - "$URA_CORPORA/JailBreakV-28K" <<'PYEOF'
import csv, os, sys
root = sys.argv[1]
d = os.path.join(root, "JailBreakV_28K")
src = os.path.join(d, "JailBreakV_28K.csv")
dst = os.path.join(d, "JailBreakV_28K_image_backed.csv")
with open(src, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    fields = reader.fieldnames
    rows = [r for r in reader
            if (r.get("image_path") or "").strip()
            and (os.path.isfile(os.path.join(root, r["image_path"]))
                 or os.path.isfile(os.path.join(d, r["image_path"])))]
if not rows:
    raise SystemExit("no image-backed rows found; JailBreakV images missing?")
with open(dst, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)
print(f"image-backed rows: {len(rows)} -> {dst}")
PYEOF
}

phase_archives() {
  echo "[archives] separately-distributed media + one-time exports"
  guard_step mmsafety-imgs "data/imgs already populated" \
    nonempty_dir "$URA_CORPORA/MM-SafetyBench/data/imgs" \
    || run_step mmsafety-imgs mmsafety_imgs
  guard_step gptgeochat-human "human split already extracted" \
    test -d "$URA_CORPORA/GPTGeoChat/gptgeochat/human/test" \
    || run_step gptgeochat-human gptgeochat_human
  guard_step siuo-images "images already in place" \
    nonempty_dir "$URA_CORPORA/SIUO/data/images" \
    || run_step siuo-images siuo_images
  guard_step video-extract "videos already extracted" \
    nonempty_dir "$URA_CORPORA/Video-SafetyBench/videos" \
    || run_step video-extract video_extract
  guard_step jailbreakv-image-backed "image-backed subset already generated" \
    test -s "$URA_CORPORA/JailBreakV-28K/JailBreakV_28K/JailBreakV_28K_image_backed.csv" \
    || run_step jailbreakv-image-backed jailbreakv_image_backed
  guard_step export-jalmbench "manifest already exported" \
    test -s "$URA_CORPORA/JALMBench-export/jalmbench.jsonl" \
    || ( cd "$URA_ROOT" && run_step export-jalmbench "$PY" -m experiments.export_jalmbench \
        --source "$URA_CORPORA/JALMBench-parquet" --out "$URA_CORPORA/JALMBench-export" \
        --max-records 300000 --max-total-bytes 600000000000 )
  guard_step export-vlsbench "manifest already exported" \
    test -s "$URA_CORPORA/VLSBench-export/vlsbench.jsonl" \
    || ( cd "$URA_ROOT" && run_step export-vlsbench "$PY" -m experiments.export_vlsbench \
        --source "$URA_CORPORA/VLSBench" --out "$URA_CORPORA/VLSBench-export" \
        --max-records 10000 --max-total-bytes 100000000000 )
  # Retained archive digests (receipt evidence).
  {
    for f in "$URA_UPSTREAM"/*.zip "$URA_CORPORA/Video-SafetyBench/video.tar.gz"; do
      [ -f "$f" ] && sha256sum "$f"
    done
  } > "$LOG/archives.sha256" 2>&1
}

phase_bipia() {
  echo "[bipia] build qa (NewsQA) + abstract (XSum) sets from external bases"
  bipia_built() {
    [ -s "$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl" ] \
      && [ -s "$URA_CORPORA/BIPIA/benchmark/qa/test.jsonl" ]
  }
  if guard_step bipia-build "abstract + qa test.jsonl already built" bipia_built; then
    return 0
  fi
  export HF_DATASETS_TRUST_REMOTE_CODE=1
  # BIPIA's process.py needs the legacy datasets loader; pin it only when the
  # builds actually have to run (side effect on the shared venv, noted).
  "$PY" - <<'PYEOF' >/dev/null 2>&1 || "$PY" -m pip install "datasets==2.14.7" "jsonlines>=4,<5" >> "$LOG/bipia-build.log" 2>&1
import datasets, sys
sys.exit(0 if datasets.__version__ == "2.14.7" else 1)
PYEOF
  if [ ! -s "$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl" ]; then
    # `yes` dies of SIGPIPE once process.py exits, and pipefail would report
    # that 141 as a build failure - so judge this one on its output, not $?.
    ( cd "$URA_CORPORA/BIPIA/benchmark/abstract" && set +o pipefail \
        && yes Y | "$PY" process.py ) >> "$LOG/bipia-abstract.log" 2>&1
    [ -s "$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl" ] \
      || echo "  [warn] bipia abstract build failed (external XSum base; see $LOG/bipia-abstract.log)"
  fi
  if [ ! -s "$URA_CORPORA/BIPIA/benchmark/qa/test.jsonl" ]; then
    ( cd "$URA_CORPORA/BIPIA/benchmark/qa" && "$PY" process.py --data_dir "$URA_UPSTREAM/newsqa-data" ) >> "$LOG/bipia-qa.log" 2>&1
    [ -s "$URA_CORPORA/BIPIA/benchmark/qa/test.jsonl" ] \
      || echo "  [warn] bipia qa build needs the licensed NewsQA base at $URA_UPSTREAM/newsqa-data (obtain manually; see $LOG/bipia-qa.log)"
  fi
  if bipia_built; then
    echo OK > "$LOG/bipia-build.status"; : > "$LOG/bipia-build.done"
    echo "OK bipia-build" >> "$SESSION_LEDGER"; echo "  [ok]   bipia-build"
  else
    echo "FAIL:1" > "$LOG/bipia-build.status"; rm -f "$LOG/bipia-build.done"
    echo "FAIL bipia-build" >> "$SESSION_LEDGER"
    echo "  [FAIL] bipia-build (external bases unavailable; see the warnings above)"
  fi
}

phase_aggregators() {
  echo "[aggregators] SALAD-Bench + AIR-Bench + XSTest + SimpleSafetyTests + DecodingTrust + HoliSafe"
  local src target
  for src in saladbench airbench xstest simplesafetytests decodingtrust holisafe; do
    case "$src" in
      saladbench)        target="$URA_CORPORA/SALAD-Data/base_set.json" ;;
      airbench)          target="$URA_CORPORA/AIR-Bench-2024/air_bench_default.json" ;;
      xstest)            target="$URA_CORPORA/XSTest/xstest_prompts.csv" ;;
      simplesafetytests) target="$URA_CORPORA/SimpleSafetyTests/simplesafetytests.json" ;;
      decodingtrust)     target="$URA_CORPORA/DecodingTrust/stereotype.json" ;;
      holisafe)          target="$URA_CORPORA/HoliSafe/holisafe_bench.json" ;;
    esac
    guard_step "export-$src" "already exported" test -s "$target" \
      || ( cd "$URA_ROOT" && run_step "export-$src" "$PY" -m experiments.export_aggregators \
          --source "$src" --out-root "$URA_CORPORA" )
  done
}

phase_ollama() {
  echo "[ollama] user-local ollama runtime (console-owned daemon; no root needed)"
  guard_step ollama-install "already at $HOME/.local/ollama/bin/ollama" \
    test -x "$HOME/.local/ollama/bin/ollama" \
    || run_step ollama-install bash -c '
      set -u
      # $1 is URA_UPSTREAM, passed as a parameter - never spliced into this
      # script text, so a data root containing $ or " cannot be re-interpreted.
      tgz="$1/ollama-linux-amd64.tgz"
      # A truncated cache would otherwise brick every later run: validate, drop.
      tar -tzf "$tgz" >/dev/null 2>&1 || rm -f "$tgz"
      test -s "$tgz" || curl -fL --retry 3 -o "$tgz" https://ollama.com/download/ollama-linux-amd64.tgz \
        || { rm -f "$tgz"; exit 1; }
      tar -tzf "$tgz" >/dev/null 2>&1 || { rm -f "$tgz"; echo "downloaded archive is not a valid tarball"; exit 1; }
      mkdir -p "$HOME/.local/ollama"
      tar -xzf "$tgz" -C "$HOME/.local/ollama"
      test -x "$HOME/.local/ollama/bin/ollama"' _ "$URA_UPSTREAM"
  if [ -x "$HOME/.local/ollama/bin/ollama" ]; then
    mkdir -p "$HOME/.local/bin"
    ln -sf "$HOME/.local/ollama/bin/ollama" "$HOME/.local/bin/ollama"
    "$HOME/.local/bin/ollama" --version 2>/dev/null | head -1 || true
  fi
}

phase_locators() {
  echo "[locators] writing URA_*_PATH bindings into $CAMPAIGN_ENV"
  if grep -q '# --- URA source locators' "$CAMPAIGN_ENV" 2>/dev/null; then
    # Compare the RESOLVED root, not the literal line: an existing block may
    # legitimately spell it "$URA_WORK/corpora" and still point where we want.
    local existing_corpora
    existing_corpora=$(bash -c 'source "$1" >/dev/null 2>&1; printf "%s" "${URA_CORPORA:-}"' _ "$CAMPAIGN_ENV")
    if [ "$existing_corpora" != "$URA_CORPORA" ]; then
      echo "  [warn] $CAMPAIGN_ENV already holds a locator block resolving to"
      echo "         '$existing_corpora' but this run targets '$URA_CORPORA';"
      echo "         delete the block between the marker comments and re-run."
    else
      echo "  locator block already present and resolving to $URA_CORPORA"
    fi
  else
    cat >> "$CAMPAIGN_ENV" <<ENV
# --- URA source locators (distro/install.sh) ---
export URA_WORK="$URA_DATA"
export URA_CORPORA="$URA_CORPORA"
export URA_UPSTREAM="$URA_UPSTREAM"
export URA_NATIVE_ENVS="$URA_NATIVE_ENVS"
export HF_HOME="$HF_HOME"
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
export URA_GPTGEOCHAT_RELEASE_PATH=\$URA_CORPORA/GPTGeoChat/gptgeochat/human/test
export URA_HARMBENCH_TEXT_PATH=\$URA_CORPORA/HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv
export URA_HARMBENCH_MULTIMODAL_PATH=\$URA_CORPORA/HarmBench/data/behavior_datasets/harmbench_behaviors_multimodal_all.csv
export URA_INJECAGENT_DH_BASE_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_dh_base.json
export URA_INJECAGENT_DH_ENHANCED_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_dh_enhanced.json
export URA_INJECAGENT_DS_BASE_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_ds_base.json
export URA_INJECAGENT_DS_ENHANCED_PATH=\$URA_CORPORA/InjecAgent/data/test_cases_ds_enhanced.json
export URA_JAILBREAKBENCH_HARMFUL_PATH=\$URA_CORPORA/JBB-Behaviors/data/harmful-behaviors.csv
export URA_JAILBREAKBENCH_BENIGN_PATH=\$URA_CORPORA/JBB-Behaviors/data/benign-behaviors.csv
export URA_JAILBREAKV_FULL_PATH=\$URA_CORPORA/JailBreakV-28K/JailBreakV_28K/JailBreakV_28K_image_backed.csv
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
export URA_MEDIA_ROOTS=\$URA_CORPORA/MM-SafetyBench/data/imgs:\$URA_CORPORA/MOSSBench:\$URA_CORPORA/JailBreakV-28K:\$URA_CORPORA/GPTGeoChat:\$URA_CORPORA/HarmBench:\$URA_CORPORA/VLSBench-export:\$URA_CORPORA/SIUO/data:\$URA_CORPORA/FigStep/data:\$URA_CORPORA/MLLMGuard:\$URA_CORPORA/JALMBench-export:\$URA_CORPORA/Video-SafetyBench:\$URA_CORPORA/HoliSafe
export PATH="\$HOME/.local/bin:\$PATH"
# --- end URA source locators ---
ENV
  fi
  # Register the aggregator arms in the operator source registry (idempotent).
  ( cd "$URA_ROOT" && "$PY" - <<'PYEOF'
import json, pathlib
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
PYEOF
  )
  echo "  wrote locators; existence report:"
  source "$CAMPAIGN_ENV" 2>/dev/null || true
  local missing=0 var value line
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
  # The launcher carries the FULL login environment (PATH incl ~/.local/bin for
  # ollama, CUDA/library paths, provider keys, campaign locators) - the same
  # contract as the rig's proven start_console.sh.
  cat > "$URA_DATA/console-launch.sh" <<LAUNCH
#!/bin/bash
set -a
[ -f /etc/profile ] && source /etc/profile 2>/dev/null
[ -f "\$HOME/.profile" ] && source "\$HOME/.profile" 2>/dev/null
[ -f "\$HOME/.ura_env" ] && source "\$HOME/.ura_env" 2>/dev/null
[ -f "$SECRETS" ] && source "$SECRETS" 2>/dev/null
[ -f "$CAMPAIGN_ENV" ] && source "$CAMPAIGN_ENV" 2>/dev/null
set +a
export PATH="\$HOME/.local/bin:\$PATH"
command -v ollama >/dev/null || echo "WARN: ollama not on console PATH" >&2
cd "$URA_ROOT"
exec "$PY" -m experiments.rig_web --results-root runs --state-dir runs/rig-web
LAUNCH
  chmod +x "$URA_DATA/console-launch.sh"
  pkill -f 'experiments.rig_web' 2>/dev/null || true; sleep 1
  tmux kill-session -t console 2>/dev/null || true
  tmux new-session -d -s console "$(printf '%q' "$URA_DATA/console-launch.sh")"
  sleep 3
  curl -s -o /dev/null -w "  console http %{http_code}\n" http://127.0.0.1:8642/ || true
}

summary() { # historical: every step ever recorded under $LOG
  echo "[summary] per-step status from $LOG"
  local fails=0 seen=0 f name
  for f in "$LOG"/*.status; do
    [ -f "$f" ] || continue
    seen=$((seen+1))
    name=$(basename "${f%.status}")
    if grep -q '^OK' "$f"; then
      echo "  OK    $name"
    else
      echo "  FAIL  $name (see $LOG/$name.log)"
      fails=$((fails+1))
    fi
  done
  if [ "$seen" -eq 0 ]; then
    echo "install.sh: no step status recorded under $LOG - nothing has run yet"
    return 1
  fi
  if [ "$fails" -gt 0 ]; then
    echo "install.sh: $fails step(s) FAILED - inspect the logs above"
    return 1
  fi
  echo "install.sh: all recorded steps OK"
}

session_summary() { # this invocation only, from the ledger
  local fails ran
  [ -f "$SESSION_LEDGER" ] || return 0
  # grep -c prints 0 and exits 1 when nothing matches: capture the count and
  # default it, never `|| echo 0` (that appends a second line and breaks -gt).
  ran=$(wc -l < "$SESSION_LEDGER" 2>/dev/null); ran=${ran:-0}
  fails=$(grep -c '^FAIL ' "$SESSION_LEDGER" 2>/dev/null); fails=${fails:-0}
  if [ "$fails" -gt 0 ]; then
    echo "[session] $fails of $ran step(s) FAILED this run:"
    sed -n 's/^FAIL /  FAIL  /p' "$SESSION_LEDGER"
    return 1
  fi
  [ "$ran" -gt 0 ] && echo "[session] $ran step(s) recorded this run, all OK"
  return 0
}

# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #
PHASES=("$@"); [ ${#PHASES[@]} -eq 0 ] && PHASES=(all)
RC=0
prereqs
for phase in "${PHASES[@]}"; do
  case "$phase" in
    all)          phase_deps || RC=1
                  phase_clones; phase_hf; phase_archives; phase_bipia
                  phase_aggregators; phase_ollama; phase_runtimes; phase_locators
                  phase_console; summary || RC=1 ;;
    deps)         phase_deps || RC=1 ;;
    clones)       phase_clones ;;
    hf)           phase_hf ;;
    archives)     phase_archives ;;
    bipia)        phase_bipia ;;
    aggregators)  phase_aggregators ;;
    ollama)       phase_ollama ;;
    locators)     phase_locators ;;
    runtimes)     phase_runtimes ;;
    console)      phase_console ;;
    summary)      summary || RC=1 ;;
    *) echo "unknown phase: $phase" >&2; exit 2 ;;
  esac
done
# Any step this invocation recorded FAIL makes the whole run fail, so a caller
# chaining `install.sh hf && <next>` cannot proceed over a broken corpus.
session_summary || RC=1
echo "distro/install.sh: done (phases: ${PHASES[*]})"
exit "$RC"
