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
# distro/.env.example to ~/.ura_env (mode 600) and fill it in. The installer
# sources secrets only inside HF-backed commands and the generated console
# launcher, never process-wide. ~/.ura_env is canonical and sourced after the
# optional legacy ~/.ura_secrets in those narrow scopes, so rotated keys win.
#
# Python: the venv needs CPython >=3.12,<3.14 (the isolated framework runtimes
# additionally need the venv's base interpreter to be exact CPython 3.12.13).
# Set URA_PYTHON=/path/to/python3.12 to choose the interpreter explicitly;
# otherwise python3.12, python3.13 and python3 are tried in that order. An
# existing .venv is adopted (never rebuilt here); a URA_PYTHON that is not its
# base interpreter is reported as ignored.
#
# Usage:
#   distro/install.sh all                 # FULL setup: deps + every corpus +
#                                         # ollama + runtimes + locators + console
#   distro/install.sh deps                # editable install into the venv only
#   distro/install.sh clones hf archives  # run selected acquisition phases
#   distro/install.sh aggregators         # (re)fetch SALAD/AIR-Bench/XSTest/SST/
#                                         # DecodingTrust/HoliSafe only
#   distro/install.sh ollama              # user-local ollama runtime (pinned)
#   distro/install.sh runtimes            # framework runtimes under the strict lock
#   distro/install.sh locators            # (re)write the URA_*_PATH env bindings
#   distro/install.sh console             # launch the rig console in tmux/screen
#   distro/install.sh summary             # per-step OK/FAIL report from the logs
#
# Env overrides: URA_DATA (default /data/ura-work), URA_ROOT (repo, autodetected),
# URA_PYTHON (interpreter used to create the venv), URA_PY_EXTRAS (default
# "dev,analysis,api,guardrail,local-vllm").
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
export URA_PACKAGE_CACHE="${URA_PACKAGE_CACHE:-$URA_DATA/package-cache}"
LOG="$URA_DATA/acquire-logs"
VENV="$URA_ROOT/.venv"
PY="$VENV/bin/python"
HF="$VENV/bin/hf"
GDOWN="$VENV/bin/gdown"
BIPIA_BUILD_LOCK="$URA_ROOT/distro/bipia-build-requirements.lock"
BIPIA_ENV_ROOT="$URA_DATA/support-venvs"
BIPIA_ENV_STORE="$BIPIA_ENV_ROOT/.store"
BIPIA_BUILD_PY=""
URA_PY_EXTRAS="${URA_PY_EXTRAS:-dev,analysis,api,guardrail,local-vllm}"
CAMPAIGN_ENV="$HOME/.ura_campaign_env"
SECRETS_ENV="$HOME/.ura_env"            # canonical (the console writes rotated keys here)
SECRETS_LEGACY="$HOME/.ura_secrets"     # optional legacy file, overridden by ~/.ura_env
# Pinned user-local ollama release (verified against the release's published
# sha256sum.txt at install time; the rig runs this exact version).
OLLAMA_VERSION=0.32.13
OLLAMA_ARCHIVE=ollama-linux-amd64.tar.zst
OLLAMA_SHA256=0fd1dece38a1c6242e8013ce20b597345c5de072ae6b320160edb0e729ef1de1

mkdir -p "$LOG" "$URA_CORPORA" "$URA_UPSTREAM" "$URA_NATIVE_ENVS" "$HF_HOME" \
  "$URA_PACKAGE_CACHE/pip" "$BIPIA_ENV_STORE" || {
  echo "cannot create the data tree under $URA_DATA - check the mount and permissions" >&2
  exit 3
}
[ -w "$LOG" ] || { echo "$LOG is not writable - check the mount and permissions" >&2; exit 3; }
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

with_hf_token() ( # command... -- secrets exist only for this HF-backed process
  # Never enable tracing in this subshell. The legacy file is sourced first and
  # the canonical console-managed file last, but neither is read for unrelated
  # phases and no value is printed or copied into an argv.
  set +x
  set -a
  [ -f "$SECRETS_LEGACY" ] && source "$SECRETS_LEGACY"
  [ -f "$SECRETS_ENV" ] && source "$SECRETS_ENV"
  set +a
  export HF_TOKEN="${HF_TOKEN:-}"
  if [ -z "$HF_TOKEN" ]; then
    echo "HF_TOKEN is empty; a gated Hugging Face source may refuse this request" >&2
  fi
  exec "$@"
)

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

python_ok() { # exe-or-name -- true when it is CPython >=3.12,<3.14
  local exe
  exe=$(command -v "$1" 2>/dev/null) || return 1
  "$exe" -c 'import sys
v = sys.version_info
ok = sys.implementation.name == "cpython" and (3, 12) <= (v.major, v.minor) < (3, 14)
raise SystemExit(0 if ok else 1)' >/dev/null 2>&1
}

same_interpreter() { # a b -- true when both name the same interpreter file
  "$PY" - "$1" "$2" <<'PYEOF'
import os, shutil, sys
requested, base = sys.argv[1], sys.argv[2]
found = shutil.which(requested) or requested
raise SystemExit(0 if os.path.realpath(found) == os.path.realpath(base) else 1)
PYEOF
}

resolve_python() { # prints the interpreter to build the venv with; fails closed (diagnostics on stderr)
  local candidate
  if [ -n "${URA_PYTHON:-}" ]; then
    if python_ok "$URA_PYTHON"; then command -v "$URA_PYTHON"; return 0; fi
    echo "  [FAIL] URA_PYTHON=$URA_PYTHON is not a CPython >=3.12,<3.14 interpreter" >&2
    return 1
  fi
  for candidate in python3.12 python3.13 python3; do
    python_ok "$candidate" || continue
    command -v "$candidate"; return 0
  done
  echo "  [FAIL] no CPython >=3.12,<3.14 interpreter found (tried python3.12, python3.13, python3)" >&2
  return 1
}

prereqs() {
  local missing=0 tool requested
  for tool in git curl tar; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  [FAIL] missing prerequisite: $tool"; missing=1; }
  done
  if ! command -v tmux >/dev/null 2>&1 && ! command -v screen >/dev/null 2>&1; then
    echo "  [FAIL] missing prerequisite: tmux or screen"
    missing=1
  fi
  [ "$missing" -eq 0 ] || {
    echo "install prerequisites first (apt install git curl tar zstd and either tmux or screen)"
    exit 3
  }
  # The package declares requires-python >=3.12,<3.14 and the framework runtime
  # lock binds exact CPython 3.12.13, so a system python3 (3.11 on Debian 12)
  # must never silently become the venv base. Resolve the interpreter here,
  # fail closed when none qualifies, and reuse it for the venv.
  if [ -x "$PY" ]; then
    if ! python_ok "$PY"; then
      echo "  [FAIL] existing venv $VENV is not CPython >=3.12,<3.14 - remove it and re-run"
      exit 3
    fi
    requested="${URA_PYTHON:-}"
    URA_PYTHON=$("$PY" -c 'import sys; print(sys._base_executable)')
    # The venv is adopted, never rebuilt here: an explicit URA_PYTHON that is
    # not its base interpreter is reported as ignored rather than replaced
    # silently (rebuild: remove $VENV and re-run deps).
    if [ -n "$requested" ] && ! same_interpreter "$requested" "$URA_PYTHON"; then
      echo "  [warn] URA_PYTHON=$requested ignored: existing $VENV (base $URA_PYTHON) is adopted"
    fi
    if [ -n "${URA_PYTHON:-}" ] && ! python_ok "$URA_PYTHON"; then
      echo "  [FAIL] the base interpreter of $VENV ($URA_PYTHON) is not CPython >=3.12,<3.14"
      exit 3
    fi
  else
    URA_PYTHON=$(resolve_python) || {
      echo "         set URA_PYTHON=/path/to/python3.12 (e.g. 'uv python install 3.12.13' ->"
      echo "         ~/.local/share/uv/python/cpython-3.12.13-*/bin/python3.12) and re-run"
      exit 3
    }
  fi
  export URA_PYTHON
  echo "  python: $URA_PYTHON ($("$URA_PYTHON" -c 'import platform; print(platform.python_version())'))"
}

# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
phase_deps() {
  echo "[deps] editable install into $VENV [$URA_PY_EXTRAS]"
  # Everything downstream runs out of this venv, so a deps failure is fatal to
  # the run: record it in the ledger and report it, never continue silently.
  local failed=0
  [ -d "$VENV" ] || "$URA_PYTHON" -m venv "$VENV" || failed=1
  if [ "$failed" -eq 0 ]; then
    "$PY" -m pip install --upgrade pip >/dev/null || failed=1
    "$PY" -m pip install -e "$URA_ROOT[$URA_PY_EXTRAS]" || failed=1
    "$PY" -m pip install "huggingface_hub[cli]>=0.24" gdown >> "$LOG/deps-tools.log" 2>&1 || failed=1
    # Remove only legacy duplicate top-level installs from the Runner venv.
    # Their retained implementations live in the isolated runtime/support
    # stores built below; shared dependencies required by URA are untouched.
    "$PY" -m pip uninstall -y pyrit spikee datasets jsonlines >> "$LOG/deps-tools.log" 2>&1 || failed=1
    "$PY" -m pip check >> "$LOG/deps-tools.log" 2>&1 || failed=1
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
  run_step hf-agentharm   with_hf_token "$HF" download ai-safety-institute/AgentHarm --repo-type dataset --revision "$REF_HF_AGENTHARM" --local-dir "$URA_CORPORA/AgentHarm"
  run_step hf-jbb         with_hf_token "$HF" download JailbreakBench/JBB-Behaviors  --repo-type dataset --revision "$REF_HF_JBB"       --local-dir "$URA_CORPORA/JBB-Behaviors"
  run_step hf-jailbreakv  with_hf_token "$HF" download JailbreakV-28K/JailBreakV-28k --repo-type dataset --revision "$REF_HF_JAILBREAKV" --local-dir "$URA_CORPORA/JailBreakV-28K"
  run_step hf-mllmguard   with_hf_token "$HF" download Carol0110/MLLMGuard           --repo-type dataset --revision "$REF_HF_MLLMGUARD"  --local-dir "$URA_CORPORA/MLLMGuard"
  run_step hf-vlsbench    with_hf_token "$HF" download Foreshhh/vlsbench             --repo-type dataset --revision "$REF_HF_VLSBENCH"   --local-dir "$URA_CORPORA/VLSBench"
  run_step hf-videosafety with_hf_token "$HF" download BAAI/Video-SafetyBench       --repo-type dataset --revision "$REF_HF_VIDEOSAFETY" --local-dir "$URA_CORPORA/Video-SafetyBench"
  run_step hf-jalmbench   with_hf_token "$HF" download AnonymousUser000/JALMBench   --repo-type dataset --revision "$REF_HF_JALMBENCH"  --local-dir "$URA_CORPORA/JALMBench-parquet"
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
    with_hf_token "$HF" download sinwang/SIUO --repo-type dataset \
      --local-dir "$URA_CORPORA/SIUO-hf" || return 1
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

discard_bipia_stage() { # exact mktemp path below, never an operator-supplied tree
  case "$1" in
    "$BIPIA_ENV_STORE"/.bipia-*.stage.*) rm -rf -- "$1" ;;
    *) echo "refusing to remove unexpected BIPIA stage path: $1" >&2; return 1 ;;
  esac
}

bipia_env_valid() { # environment lock-sha runtime-sha runtime-version
  local environment=$1 lock_sha=$2 runtime_sha=$3 runtime_version=$4
  [ -x "$environment/bin/python" ] || return 1
  [ -f "$environment/pyvenv.cfg" ] \
    && grep -qi '^include-system-site-packages = false$' "$environment/pyvenv.cfg" \
    || return 1
  [ "$(sed -n '1p' "$environment/.ura-bipia-identity" 2>/dev/null)" = "$lock_sha" ] \
    || return 1
  [ "$(sed -n '2p' "$environment/.ura-bipia-identity" 2>/dev/null)" = "$runtime_sha" ] \
    || return 1
  "$environment/bin/python" -I - "$BIPIA_BUILD_LOCK" "$runtime_sha" "$runtime_version" <<'PYEOF'
import hashlib
import importlib.metadata
import pathlib
import platform
import re
import sys

lock = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
expected_sha, expected_python = sys.argv[2:]
if platform.python_version() != expected_python:
    raise SystemExit("BIPIA support Python version differs from the runtime lock")
if hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest() != expected_sha:
    raise SystemExit("BIPIA support Python binary differs from the runtime lock")
if sys.prefix == sys.base_prefix:
    raise SystemExit("BIPIA support interpreter is not a virtual environment")

normalize = lambda value: re.sub(r"[-_.]+", "-", value).lower()
expected = {
    normalize(name): version
    for name, version in re.findall(
        r"(?m)^([A-Za-z0-9_.-]+)==([^ \\\r\n;]+)", lock
    )
}
if not expected:
    raise SystemExit("BIPIA dependency lock has no exact requirements")
actual = {
    normalize(dist.metadata["Name"]): dist.version
    for dist in importlib.metadata.distributions()
    if dist.metadata.get("Name")
}
wrong = {
    name: (version, actual.get(name))
    for name, version in expected.items()
    if actual.get(name) != version
}
unexpected = set(actual) - set(expected) - {"pip", "setuptools"}
if wrong or unexpected:
    raise SystemExit(
        f"BIPIA support inventory mismatch: wrong={wrong}, unexpected={sorted(unexpected)}"
    )
import datasets
import jsonlines  # noqa: F401

if datasets.__version__ != "2.14.7":
    raise SystemExit("BIPIA support environment has the wrong datasets release")
PYEOF
}

prepare_bipia_build_env() {
  local framework_lock="$URA_ROOT/experiments/framework_runtime_lock.json"
  local base_python runtime_identity runtime_version runtime_sha lock_sha final alias stage
  [ -s "$BIPIA_BUILD_LOCK" ] || {
    echo "BIPIA support dependency lock missing: $BIPIA_BUILD_LOCK" >&2
    return 1
  }
  [ -s "$framework_lock" ] || {
    echo "framework runtime lock missing: $framework_lock" >&2
    return 1
  }
  base_python=$("$PY" -c 'import sys; print(sys._base_executable)') || return 1
  runtime_identity=$("$PY" - "$framework_lock" "$base_python" <<'PYEOF'
import hashlib
import json
import pathlib
import platform
import re
import subprocess
import sys

lock = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
runtime = lock.get("runtimes", {}).get("python", {})
version = runtime.get("version")
digest = runtime.get("binary_sha256")
if not isinstance(version, str) or not re.fullmatch(r"3\.12\.[0-9]+", version):
    raise SystemExit("framework lock has no exact CPython 3.12 runtime")
if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
    raise SystemExit("framework lock has no exact Python binary digest")
base = pathlib.Path(sys.argv[2])
if not base.is_file() or hashlib.sha256(base.read_bytes()).hexdigest() != digest:
    raise SystemExit("venv base Python binary differs from the framework lock")
probe = subprocess.run(
    [str(base), "-c", "import platform; print(platform.python_version())"],
    capture_output=True,
    text=True,
    check=False,
)
if probe.returncode or probe.stdout.strip() != version:
    raise SystemExit("venv base Python version differs from the framework lock")
print(version, digest)
PYEOF
  ) || return 1
  read -r runtime_version runtime_sha <<<"$runtime_identity"
  lock_sha=$(sha256sum "$BIPIA_BUILD_LOCK" | awk '{print $1}') || return 1
  [[ "$lock_sha" =~ ^[0-9a-f]{64}$ ]] || return 1
  final="$BIPIA_ENV_STORE/bipia-${lock_sha:0:16}-py${runtime_version//./}-${runtime_sha:0:12}"
  alias="$BIPIA_ENV_ROOT/bipia"

  if [ -e "$final" ] || [ -L "$final" ]; then
    bipia_env_valid "$final" "$lock_sha" "$runtime_sha" "$runtime_version" || {
      echo "existing BIPIA support store failed exact identity verification: $final" >&2
      return 1
    }
  else
    stage=$(mktemp -d "$BIPIA_ENV_STORE/.bipia-${lock_sha:0:16}.stage.XXXXXX") \
      || return 1
    mkdir -p "$BIPIA_ENV_ROOT/.home" "$URA_PACKAGE_CACHE/pip"
    if ! "$base_python" -m venv --copies "$stage" \
      || ! env -i \
          HOME="$BIPIA_ENV_ROOT/.home" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
          PATH=/usr/bin:/bin PIP_CONFIG_FILE=/dev/null \
          PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 \
          PIP_CACHE_DIR="$URA_PACKAGE_CACHE/pip" \
          "$stage/bin/python" -m pip install --require-hashes \
            --index-url https://pypi.org/simple -r "$BIPIA_BUILD_LOCK" \
      || ! "$stage/bin/python" -m pip check; then
      discard_bipia_stage "$stage"
      return 1
    fi
    printf '%s\n%s\n' "$lock_sha" "$runtime_sha" > "$stage/.ura-bipia-identity"
    if ! bipia_env_valid "$stage" "$lock_sha" "$runtime_sha" "$runtime_version"; then
      discard_bipia_stage "$stage"
      return 1
    fi
    if ! mv "$stage" "$final"; then
      discard_bipia_stage "$stage"
      return 1
    fi
  fi

  if [ -e "$alias" ] && [ ! -L "$alias" ]; then
    echo "refusing to replace non-symlink BIPIA support alias: $alias" >&2
    return 1
  fi
  ln -sfn ".store/$(basename "$final")" "$alias" || return 1
  [ "$(readlink -f "$alias")" = "$(readlink -f "$final")" ] || return 1
  BIPIA_BUILD_PY="$alias/bin/python"
  echo "BIPIA support environment: $final"
}

phase_bipia() {
  echo "[bipia] build qa (NewsQA) + abstract (XSum) sets from external bases"
  bipia_built() {
    [ -s "$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl" ] \
      && [ -s "$URA_CORPORA/BIPIA/benchmark/qa/test.jsonl" ]
  }
  if ! prepare_bipia_build_env >> "$LOG/bipia-build.log" 2>&1; then
    echo "FAIL:1" > "$LOG/bipia-build.status"; rm -f "$LOG/bipia-build.done"
    echo "FAIL bipia-build" >> "$SESSION_LEDGER"
    echo "  [FAIL] bipia-build (isolated support environment failed; see $LOG/bipia-build.log)"
    return 1
  fi
  if guard_step bipia-build "abstract + qa test.jsonl already built" bipia_built; then
    return 0
  fi
  export HF_DATASETS_TRUST_REMOTE_CODE=1
  if [ ! -s "$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl" ]; then
    # `yes` dies of SIGPIPE once process.py exits, and pipefail would report
    # that 141 as a build failure - so judge this one on its output, not $?.
    ( cd "$URA_CORPORA/BIPIA/benchmark/abstract" && set +o pipefail \
        && yes Y | "$BIPIA_BUILD_PY" process.py ) >> "$LOG/bipia-abstract.log" 2>&1
    [ -s "$URA_CORPORA/BIPIA/benchmark/abstract/test.jsonl" ] \
      || echo "  [warn] bipia abstract build failed (external XSum base; see $LOG/bipia-abstract.log)"
  fi
  if [ ! -s "$URA_CORPORA/BIPIA/benchmark/qa/test.jsonl" ]; then
    ( cd "$URA_CORPORA/BIPIA/benchmark/qa" && "$BIPIA_BUILD_PY" process.py --data_dir "$URA_UPSTREAM/newsqa-data" ) >> "$LOG/bipia-qa.log" 2>&1
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
      || ( cd "$URA_ROOT" && run_step "export-$src" with_hf_token "$PY" -m experiments.export_aggregators \
          --source "$src" --out-root "$URA_CORPORA" )
  done
}

phase_ollama() {
  echo "[ollama] user-local ollama runtime v$OLLAMA_VERSION (console-owned daemon; no root needed)"
  guard_step ollama-install "already at $HOME/.local/ollama/bin/ollama" \
    test -x "$HOME/.local/ollama/bin/ollama" \
    || run_step ollama-install bash -c '
      set -u
      # $1 URA_UPSTREAM, $2 version, $3 archive name, $4 pinned sha256 - passed as
      # parameters, never spliced into this script text, so a data root
      # containing $ or " cannot be re-interpreted.
      upstream="$1" version="$2" archive_name="$3" pinned="$4"
      base="https://github.com/ollama/ollama/releases/download/v$version"
      archive="$upstream/$archive_name"
      sums="$upstream/ollama-v$version.sha256sum.txt"
      command -v zstd >/dev/null 2>&1 || { echo "zstd is required to extract $archive_name (apt install zstd)"; exit 1; }
      # The published checksum list of the SAME release must agree with the
      # pinned digest: a re-published or substituted asset fails closed here.
      curl -fL --retry 3 -o "$sums" "$base/sha256sum.txt" || { rm -f "$sums"; echo "cannot fetch $base/sha256sum.txt"; exit 1; }
      published=$(awk -v name="./$archive_name" '"'"'$2 == name {print $1}'"'"' "$sums")
      [ "$published" = "$pinned" ] || {
        echo "published sha256 for $archive_name in v$version ($published) does not match the pinned $pinned"; exit 1; }
      # A cached archive is reused only when it matches the pin (a truncated or
      # foreign cache would otherwise brick every later run): verify, else drop.
      if [ -s "$archive" ] && [ "$(sha256sum "$archive" | awk '"'"'{print $1}'"'"')" = "$pinned" ]; then
        echo "reusing verified $archive"
      else
        rm -f "$archive"
        curl -fL --retry 3 -o "$archive" "$base/$archive_name" || { rm -f "$archive"; exit 1; }
        actual=$(sha256sum "$archive" | awk '"'"'{print $1}'"'"')
        [ "$actual" = "$pinned" ] || { rm -f "$archive"; echo "downloaded $archive_name sha256 $actual != pinned $pinned"; exit 1; }
      fi
      echo "ollama v$version $archive_name sha256 $pinned verified"
      mkdir -p "$HOME/.local/ollama"
      zstd -dc "$archive" | tar -x -C "$HOME/.local/ollama" || exit 1
      test -x "$HOME/.local/ollama/bin/ollama"' _ "$URA_UPSTREAM" "$OLLAMA_VERSION" "$OLLAMA_ARCHIVE" "$OLLAMA_SHA256"
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
  # The checkout and its interpreter, for the runbook's ura_native_session /
  # ura_native_run wrapper ($URA_PY is the main venv interpreter, $URA_REPO the
  # tracked checkout). Appended once; an existing different binding is reported.
  ensure_env_line URA_REPO "$URA_ROOT"
  ensure_env_line URA_PY "\$URA_REPO/.venv/bin/python"
  # Operator source registry: seed it from the checked-in example when absent
  # (section 4 of the runbook) and take the six aggregator entries - including
  # their source_label strings, which source_conformance matches against the
  # retained receipt - from that same example, never from literals here.
  ( cd "$URA_ROOT" && "$PY" - <<'PYEOF'
import json, pathlib
example_path = pathlib.Path("experiments/rig/source-instances.example.json")
example = json.loads(example_path.read_text(encoding="utf-8"))
AGGREGATORS = ("saladbench_base", "airbench_full", "xstest_full",
               "simplesafetytests_full", "decodingtrust_stereotype", "holisafe_full")
missing = [k for k in AGGREGATORS if k not in example]
if missing:
    raise SystemExit(f"{example_path} lacks aggregator entries {missing}")
p = pathlib.Path("experiments/source-instances.json")
if p.exists():
    d = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(d, dict):
        raise SystemExit(f"{p} is not a JSON object")
    seeded = False
else:
    d = dict(example)
    seeded = True
changed = seeded
for k in AGGREGATORS:
    if k not in d:
        d[k] = example[k]; changed = True
        print(f"  added {k} from {example_path}")
    elif d[k] != example[k]:
        d[k] = example[k]; changed = True
        print(f"  reconciled {k} to the {example_path} entry")
if changed:
    p.write_text(json.dumps(d, indent=2) + "\n", encoding="utf-8")
print("source-instances.json arms:", len(d), "(seeded from the example)" if seeded else "")
PYEOF
  ) || { echo "  [FAIL] could not write experiments/source-instances.json"; echo "FAIL locators-registry" >> "$SESSION_LEDGER"; }
  echo "  wrote locators; existence report:"
  source "$CAMPAIGN_ENV" 2>/dev/null || true
  local missing=0 var value line note
  while IFS= read -r line; do
    case "$line" in
      "export URA_"*PATH=*)
        var=${line#export }; var=${var%%=*}
        value=$(eval "printf '%s' \"\$$var\"")
        note=""
        [ "$var" = URA_BIPIA_TEST_QA_PATH ] && note=" (blocked: licensed NewsQA base; see the bipia phase)"
        if [ -e "$value" ]; then echo "  OK      $var"; else echo "  MISSING $var -> $value$note"; missing=$((missing+1)); fi ;;
    esac
  done < "$CAMPAIGN_ENV"
  echo "  missing locators: $missing"
}

ensure_env_line() { # VAR value -- append 'export VAR="value"' to the campaign env once
  local var=$1 value=$2 existing
  if existing=$(grep -m1 "^export $var=" "$CAMPAIGN_ENV" 2>/dev/null); then
    [ "$existing" = "export $var=\"$value\"" ] \
      || echo "  [warn] $CAMPAIGN_ENV already binds $var ($existing); leaving it as is"
    return 0
  fi
  printf 'export %s="%s"\n' "$var" "$value" >> "$CAMPAIGN_ENV"
}

runtimes_session() { # command lock env-root state-root python framework -- launch and wait
  # The installer runs inside its own named tmux/screen session and returns a
  # session JSON immediately; this waits for the session's terminal exit marker
  # exactly as the runbook's ura_wait_session does (168 h deadline, liveness
  # probe) and returns the inner exit code, so run_step ledgers the real result.
  local command=$1 lock=$2 env_root=$3 state_root=$4 python=$5 framework=$6 session_json
  session_json=$( cd "$URA_ROOT" && "$PY" -m experiments.framework_runtime_installer "$command" \
      --lock "$lock" --env-root "$env_root" --state-root "$state_root" --python "$python" \
      --only "$framework" ) || return 1
  printf '%s\n' "$session_json"
  "$PY" - "$session_json" "$state_root" <<'PYEOF'
import hashlib, json, re, shutil, subprocess, sys, time
from pathlib import Path

row = json.loads(sys.argv[1])
state_root = Path(sys.argv[2])
required = {"schema", "launcher", "session_name", "attach_command", "log", "exit_marker", "status"}
if not isinstance(row, dict) or set(row) != required or row["schema"] != "ura-framework-runtime-session/1":
    raise SystemExit("installer returned an invalid session payload")
name = row["session_name"]
if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
    raise SystemExit("installer returned an invalid session name")
launcher = row["launcher"]
if launcher not in ("tmux", "screen") or row["status"] != "running":
    raise SystemExit("installer session is not a running tmux/screen session")
if row["log"] != f"sessions/{name}.log" or row["exit_marker"] != f"sessions/{name}.exit":
    raise SystemExit("installer session log/exit marker are not the expected paths")
marker = state_root / row["exit_marker"]
log = state_root / row["log"]
socket = "ura-fw-" + hashlib.sha256(name.encode("ascii")).hexdigest()[:16]
print(f"attach with: {row['attach_command']}")
print(f"tail with: tail -f -- {log}")
deadline = time.monotonic() + 168 * 60 * 60
misses = 0
while not marker.is_file():
    if time.monotonic() > deadline:
        raise SystemExit("framework runtime session exceeded the 168 h deadline")
    alive = True
    if launcher == "tmux" and shutil.which("tmux"):
        alive = subprocess.run(["tmux", "-L", socket, "has-session", "-t", name],
                               capture_output=True, check=False).returncode == 0
    elif launcher == "screen" and shutil.which("screen"):
        listing = subprocess.run(["screen", "-ls"], capture_output=True, text=True, check=False).stdout
        alive = re.search(rf"(?m)^\s*\d+\.{re.escape(name)}\s+\((?:Attached|Detached|Multi(?:,\s*attached)?)\)", listing) is not None
    if not alive:
        misses += 1
        time.sleep(1)
        if misses >= 2 and not marker.is_file():
            raise SystemExit(f"framework runtime session {name} ended without an exit marker")
        continue
    misses = 0
    time.sleep(5)
rc = marker.read_text(encoding="utf-8").strip()
if not re.fullmatch(r"0|[1-9][0-9]{0,2}", rc) or int(rc) > 255:
    raise SystemExit(f"framework runtime session {name} wrote an invalid exit marker {rc!r}")
print(f"session {name} exit {rc}")
if log.is_file():
    tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
    print("--- session log tail ---")
    print("\n".join(tail))
raise SystemExit(int(rc))
PYEOF
}

phase_runtimes() {
  echo "[runtimes] isolated third-party framework environments (strict lock)"
  # Same locators the runbook (12.2) and the console's Build -> Runtimes use:
  # env-root $URA_WORK/framework-venvs, state-root
  # $URA_WORK/runs/engineering/framework-runtime-<lock_id[:12]>, and the venv's
  # base interpreter (exact CPython 3.12.13; the installer fails closed otherwise).
  local lock="$URA_ROOT/experiments/framework_runtime_lock.json" lock_id base_python base_version
  local -a lock_rows frameworks
  # The lock is read with the venv interpreter: without the venv the real
  # cause is the missing deps phase, not an unreadable lock - say so.
  [ -x "$PY" ] || { echo "  [FAIL] runtimes-plan (venv missing: $PY - run distro/install.sh deps first)"; echo "FAIL runtimes-plan" >> "$SESSION_LEDGER"; return 1; }
  mapfile -t lock_rows < <("$PY" - "$lock" <<'PYEOF'
import json, re, sys
row = json.load(open(sys.argv[1], encoding="utf-8"))
lock_id = row.get("lock_id")
if not isinstance(lock_id, str) or not re.fullmatch(r"[0-9a-f]{64}", lock_id):
    raise SystemExit("framework_runtime_lock.json has no 64-hex lock_id")
frameworks = row.get("frameworks")
if not isinstance(frameworks, list) or len(frameworks) != 15:
    raise SystemExit("framework_runtime_lock.json must contain exactly 15 frameworks")
names = [entry.get("name") for entry in frameworks if isinstance(entry, dict)]
if len(names) != 15 or len(set(names)) != 15:
    raise SystemExit("framework runtime names must be 15 unique strings")
if any(not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) for name in names):
    raise SystemExit("framework runtime name is unsafe")
print(lock_id)
print(*names, sep="\n")
PYEOF
  ) || { echo "  [FAIL] runtimes-plan (cannot read $lock)"; echo "FAIL runtimes-plan" >> "$SESSION_LEDGER"; return 1; }
  # A Windows-hosted regression shell receives CRLF from the helper Python;
  # normalize the record boundary without changing any lock-derived name.
  local row_index
  for row_index in "${!lock_rows[@]}"; do
    lock_rows[$row_index]=${lock_rows[$row_index]%$'\r'}
  done
  [ "${#lock_rows[@]}" -eq 16 ] \
    || { echo "  [FAIL] runtimes-plan (lock did not yield 15 framework names)"; echo "FAIL runtimes-plan" >> "$SESSION_LEDGER"; return 1; }
  lock_id=${lock_rows[0]}
  frameworks=("${lock_rows[@]:1}")
  base_python=$("$PY" -c 'import sys; print(sys._base_executable)') \
    || { echo "  [FAIL] runtimes-plan (cannot derive the venv base interpreter)"; echo "FAIL runtimes-plan" >> "$SESSION_LEDGER"; return 1; }
  base_version=$("$base_python" -c 'import platform; print(platform.python_version())' 2>/dev/null || echo unknown)
  [ "$base_version" = "3.12.13" ] \
    || echo "  [warn] the lock binds exact CPython 3.12.13 but the venv base is $base_version; the installer will refuse it"
  local env_root="$URA_DATA/framework-venvs" state_root="$URA_DATA/runs/engineering/framework-runtime-${lock_id:0:12}"
  echo "  lock $lock_id"
  echo "  env-root $env_root"
  echo "  state-root $state_root"
  echo "  python $base_python ($base_version)"
  run_step runtimes-plan bash -c \
    'cd "$1" && exec "$2" -m experiments.framework_runtime_installer plan --lock "$3" --env-root "$4" --state-root "$5"' \
    _ "$URA_ROOT" "$PY" "$lock" "$env_root" "$state_root"
  if ! grep -q '^OK' "$LOG/runtimes-plan.status" 2>/dev/null; then
    echo "  runtimes not started because strict lock planning failed"
    return 1
  fi
  # `resume` is the safe universal entry point: it builds an absent store, repairs
  # an interrupted stage phase-by-phase, and re-verifies an already published
  # runtime. Fresh-only `install` would strand a staged store after an SSH or
  # host interruption even though the plan above correctly reports `resume`.
  # One framework per named session prevents one incompatible package set from
  # terminating the global pass before the other independent stores are tried.
  # Every successful resume is immediately verified; failures are retained per
  # framework and the loop continues through the complete locked inventory.
  local framework install_step verify_step install_failed=0 verify_failed=0
  for framework in "${frameworks[@]}"; do
    install_step="runtime-${framework}-install"
    verify_step="runtime-${framework}-verify"
    run_step "$install_step" runtimes_session resume "$lock" "$env_root" \
      "$state_root" "$base_python" "$framework"
    if grep -q '^OK' "$LOG/$install_step.status" 2>/dev/null; then
      run_step "$verify_step" runtimes_session verify "$lock" "$env_root" \
        "$state_root" "$base_python" "$framework"
      grep -q '^OK' "$LOG/$verify_step.status" 2>/dev/null || verify_failed=1
    else
      install_failed=1
      verify_failed=1
      echo "FAIL:install" > "$LOG/$verify_step.status"
      rm -f "$LOG/$verify_step.done"
      echo "  [skip] $verify_step (that framework's resume failed; later frameworks continue)"
    fi
  done

  {
    for framework in "${frameworks[@]}"; do
      printf '%s %s\n' "$framework" "$(sed -n '1p' "$LOG/runtime-${framework}-install.status")"
    done
  } > "$LOG/runtimes-install.log"
  if [ "$install_failed" -eq 0 ]; then
    echo OK > "$LOG/runtimes-install.status"; : > "$LOG/runtimes-install.done"
    echo "  [ok]   runtimes-install (15/15 isolated rows)"
  else
    echo FAIL:1 > "$LOG/runtimes-install.status"; rm -f "$LOG/runtimes-install.done"
    echo "  [FAIL] runtimes-install aggregate (all 15 rows were attempted)"
  fi
  {
    for framework in "${frameworks[@]}"; do
      printf '%s %s\n' "$framework" "$(sed -n '1p' "$LOG/runtime-${framework}-verify.status")"
    done
  } > "$LOG/runtimes-verify.log"
  if [ "$verify_failed" -eq 0 ]; then
    echo OK > "$LOG/runtimes-verify.status"; : > "$LOG/runtimes-verify.done"
    echo "  [ok]   runtimes-verify (15/15 isolated rows)"
  else
    echo FAIL:1 > "$LOG/runtimes-verify.status"; rm -f "$LOG/runtimes-verify.done"
    echo "  [FAIL] runtimes-verify aggregate (see per-row statuses)"
  fi
  [ "$install_failed" -eq 0 ] && [ "$verify_failed" -eq 0 ]
}

phase_console() {
  local launcher
  if command -v tmux >/dev/null 2>&1; then launcher=tmux; else launcher=screen; fi
  echo "[console] launching the rig console in $launcher session 'console' on :8642"
  # The launcher carries the FULL login environment (PATH incl ~/.local/bin for
  # ollama, CUDA/library paths, provider keys, campaign locators) - the same
  # contract as the rig's proven start_console.sh. Secrets precedence is the
  # installer's: legacy ~/.ura_secrets first, canonical ~/.ura_env last (wins).
  cat > "$URA_DATA/console-launch.sh" <<LAUNCH
#!/bin/bash
set -a
[ -f /etc/profile ] && source /etc/profile 2>/dev/null
[ -f "\$HOME/.profile" ] && source "\$HOME/.profile" 2>/dev/null
[ -f "$SECRETS_LEGACY" ] && source "$SECRETS_LEGACY" 2>/dev/null
[ -f "$SECRETS_ENV" ] && source "$SECRETS_ENV" 2>/dev/null
[ -f "$CAMPAIGN_ENV" ] && source "$CAMPAIGN_ENV" 2>/dev/null
set +a
export PATH="\$HOME/.local/bin:\$PATH"
command -v ollama >/dev/null || echo "WARN: ollama not on console PATH" >&2
cd "$URA_ROOT"
exec "$PY" -m experiments.rig_web --results-root runs --state-dir runs/rig-web
LAUNCH
  chmod +x "$URA_DATA/console-launch.sh"
  # Anchored '-m experiments.rig_web' invocation only (pkill -f patterns are
  # EREs; an unescaped '.' would also match experiments/rig_web_app/... paths).
  pkill -f -- '-m experiments\.rig_web( |$)' 2>/dev/null || true; sleep 1
  if [ "$launcher" = tmux ]; then
    tmux kill-session -t console 2>/dev/null || true
    tmux new-session -d -s console "$(printf '%q' "$URA_DATA/console-launch.sh")"
  else
    screen -S console -X quit 2>/dev/null || true
    screen -DmS console "$URA_DATA/console-launch.sh"
  fi
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
                  phase_aggregators; phase_ollama; phase_runtimes || RC=1
                  phase_locators; phase_console; summary || RC=1 ;;
    deps)         phase_deps || RC=1 ;;
    clones)       phase_clones ;;
    hf)           phase_hf ;;
    archives)     phase_archives ;;
    bipia)        phase_bipia ;;
    aggregators)  phase_aggregators ;;
    ollama)       phase_ollama ;;
    locators)     phase_locators ;;
    runtimes)     phase_runtimes || RC=1 ;;
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
