#!/usr/bin/env bash
# URA-Bench rig re-pin: deploy ONE tracked commit to the rig console.
#
# The rig has no GitHub credentials, so code arrives as a git bundle. Run the
# repin.sh OF THE COMMIT BEING DEPLOYED (copied to ~/repin.sh), never the
# in-tree copy: ~/MLLMRiskBench/distro/repin.sh is the version at the
# CURRENTLY pinned commit (possibly absent or lacking fixes), because the
# checkout only advances inside this script.
#   local:  git bundle create web002.bundle main
#           scp web002.bundle rig:~/web002.bundle
#           scp distro/repin.sh rig:~/repin.sh        # from the deployed commit
#   rig:    bash ~/repin.sh <40-hex-commit> [--focused-campaign-handoff|--profile-recovery-handoff]
#
# Run ON the rig with $1 = the expected 40-hex commit (the bundle head must
# match it exactly). Steps, all fail-closed (a failure leaves the rig on the
# new checkout WITHOUT a console; fix the cause and re-run, or start the
# console with distro/install.sh console):
#   1. fetch the bundle, check its head against $1, detach-checkout it
#      (warns when this script differs from distro/repin.sh at that commit)
#   2. hygiene: kill stray '-m experiments.run_matrix' / '-m experiments.rig_web'
#      processes, clear /tmp/pytest-of-<user>
#   3. clean-env full-suite gate by default, or the fixed campaign-handoff
#      regression set only when the explicit second argument is present
#   4. local-target roster refresh, then refuse if any TRACKED file changed
#   5. project-revision receipt: retain every content-addressed historical
#      receipt, create + validate the new one (an invalid receipt aborts)
#   6. rebind REF_URA / URA_PROJECT_REVISION_MANIFEST / _SHA256 in ~/.ura_campaign_env
#   7. re-validate the retained source-conformance receipt against the
#      registry (bound but invalid aborts; unbound is reported only)
#   8. restart the console detached (setsid; full login env like
#      distro/install.sh console; log under $URA_DATA/acquire-logs)
#
# Env: REPO (default ~/MLLMRiskBench), BUNDLE (default ~/web002.bundle),
#      URA_DATA (default /data/ura-work; console log location),
#      URA_CONSOLE_HOST/URA_CONSOLE_PORT (default 127.0.0.1/8642).
set -euo pipefail

REF_EXPECTED="${1:-}"
MODE="${2:-full}"
[[ "$REF_EXPECTED" =~ ^[0-9a-f]{40}$ ]] || { echo "usage: $0 <40-hex-commit> [--focused-campaign-handoff|--profile-recovery-handoff]" >&2; exit 2; }
[[ "$MODE" = "full" || "$MODE" = "--focused-campaign-handoff" || "$MODE" = "--profile-recovery-handoff" ]] \
  || { echo "unsupported re-pin verification mode: $MODE" >&2; exit 2; }
REPO="${REPO:-$HOME/MLLMRiskBench}"
BUNDLE="${BUNDLE:-$HOME/web002.bundle}"
URA_DATA="${URA_DATA:-/data/ura-work}"
CONSOLE_HOST="${URA_CONSOLE_HOST:-127.0.0.1}"
CONSOLE_PORT="${URA_CONSOLE_PORT:-8642}"
PY="$REPO/.venv/bin/python"
CAMPAIGN_ENV="$HOME/.ura_campaign_env"
[ -x "$PY" ] || { echo "venv interpreter missing: $PY (run distro/install.sh deps first)" >&2; exit 1; }
[ -s "$BUNDLE" ] || { echo "bundle missing or empty: $BUNDLE" >&2; exit 1; }
[ -f "$CAMPAIGN_ENV" ] || { echo "campaign env missing: $CAMPAIGN_ENV (run distro/install.sh locators first)" >&2; exit 1; }

cd "$REPO"
git fetch "$BUNDLE" main --quiet
REF=$(git rev-parse FETCH_HEAD)
test "$REF" = "$REF_EXPECTED" || { echo "bundle head $REF != expected $REF_EXPECTED" >&2; exit 1; }
# Advisory: the executing script should be the one shipped in the deployed
# commit (the README copies it to ~/repin.sh first); a stale copy is reported.
if [ -f "$0" ] && git cat-file -e "$REF:distro/repin.sh" 2>/dev/null; then
  git show "$REF:distro/repin.sh" | cmp -s - "$0" \
    || echo "warning: $0 differs from distro/repin.sh at $REF (stale repin.sh; scp the deployed commit's copy to ~/repin.sh next time)" >&2
fi
git checkout --detach "$REF" --quiet

# Hygiene before the gate: a stray run_matrix/rig_web process or a stale pytest
# temp root makes the suite fail spuriously (and a stray console would be the
# OLD code). Processes are matched on the anchored '-m experiments.<module>'
# invocation only (pkill -f patterns are EREs: an unescaped '.' would also
# match a path like experiments/rig_web_app/... open in an editor or tail).
pkill -f -- '-m experiments\.run_matrix( |$)' 2>/dev/null || true
pkill -f -- '-m experiments\.rig_web( |$)' 2>/dev/null || true
sleep 1

# Atomic controller-install tests deliberately make generated controller trees
# immutable. pytest can retain those trees beneath its per-user temp root, so a
# later re-pin makes only that exact, owned directory user-cleanable before
# removing it. The Python helper opens every directory by descriptor with
# O_NOFOLLOW and uses shutil's fd-safe rmtree implementation; it never applies
# a path-based chmod that a same-UID process could replace with a symlink.
PYTEST_TMP_ROOT="/tmp/pytest-of-$(id -un)"
"$PY" -m experiments.pytest_tmp_cleanup --root "$PYTEST_TMP_ROOT"

# Clean-environment verification gate: no URA_* variable may leak into the run
# (digits included: URA_PROJECT_REVISION_SHA256 and friends). The explicit
# campaign handoff runs only files changed since the deployed aa71bcd campaign
# boundary plus the stable hosted-plan and deployment-contract regressions.
DEPLOY_TESTS=()
if [ "$MODE" = "--focused-campaign-handoff" ]; then
  DEPLOY_TESTS=(
    tests/experiments/test_local_campaign_controllers.py
    tests/experiments/test_local_campaign_execution_accounting.py
    tests/experiments/test_local_campaign_phase8_lifecycle_semantics.py
    tests/experiments/test_local_bounded_output_continuation_phase6.py
    tests/experiments/test_local_model_readiness.py
    tests/experiments/test_current_ollama_campaign.py
    tests/experiments/test_local_truncation_recovery_phase6.py
    tests/experiments/test_ollama_population_alignment_recovery_phase6.py
    tests/experiments/test_hosted_campaign_budget.py
    tests/experiments/test_retained_response_judge.py
    tests/experiments/test_retained_response_judge_execute.py
    tests/experiments/test_retained_response_judge_pair.py
    tests/ura/test_runner_regressions.py::test_hosted_guardrail_judging_remains_inline_with_the_paid_response
    tests/ura/test_runner_regressions.py::test_response_checkpoint_resumes_judging_without_rebilling_target
    tests/ura/test_current_contract_docs.py
    tests/ura/test_local_context_limit_regressions.py
    tests/ura/test_hosted_roster_docs.py
    tests/ura/test_local_campaign_stats_adapter.py
    tests/ura/test_pricing_fetch.py
    tests/ura/test_target_regressions.py::test_frontier_targets_disable_hidden_retries_and_audit_failure
    tests/ura/test_target_regressions.py::test_hosted_transport_retries_status_bearing_http_failures_more_than_once
    tests/ura/test_rig_web.py::test_pricing_fetch_banner_reports_added_roster_models
    tests/ura/test_rig_web.py::test_command_construction_is_typed_and_allowlisted
    tests/ura/test_rig_web.py::test_builder_model_filters_and_quantization_warning_are_rendered
    tests/ura/test_rig_web.py::test_builder_rejects_malformed_local_runtime_config_before_job
    tests/ura/test_rig_web.py::test_command_groups_partition_the_allowlist_exactly
    tests/ura/test_rig_web.py::test_every_ui_command_parses_with_its_real_module_parser
    tests/ura/test_rig_web_model_picker.py
    tests/ura/test_rig_web_page_tabs.py
    tests/ura/test_project_metadata.py
    tests/ura/test_framework_runtime_installer.py::test_distro_repin_script_is_fail_closed_and_sources_canonical_ura_env_last
  )
  echo "verification mode: focused campaign handoff (${#DEPLOY_TESTS[@]} selectors)"
elif [ "$MODE" = "--profile-recovery-handoff" ]; then
  DEPLOY_TESTS=(
    tests/ura/test_local_context_limit_regressions.py
    tests/ura/test_hosted_roster_docs.py::test_hosted_follow_on_is_a_no_retry_local_input_subset
    tests/ura/test_rig_web.py::test_builder_model_filters_and_quantization_warning_are_rendered
    tests/ura/test_rig_web.py::test_builder_rejects_malformed_local_runtime_config_before_job
    tests/ura/test_rig_web.py::test_every_ui_command_parses_with_its_real_module_parser
    tests/ura/test_rig_web_model_picker.py::test_server_validates_explicit_judge_and_local_engine_conflicts
    tests/ura/test_rig_web_model_picker.py::test_paid_ticket_burns_when_selected_local_registry_changes
    tests/ura/test_rig_web_model_picker.py::test_web_compose_materializes_local_judge_but_dry_mode_stays_mock
    tests/ura/test_framework_runtime_installer.py::test_distro_repin_script_is_fail_closed_and_sources_canonical_ura_env_last
  )
  echo "verification mode: profile recovery handoff (${#DEPLOY_TESTS[@]} selectors)"
else
  echo "verification mode: full suite"
fi
( for v in $(env | grep -oE '^URA_[A-Za-z0-9_]+' || true); do unset "$v"; done
  set -o pipefail
  "$PY" -m pytest -q -p no:cacheprovider "${DEPLOY_TESTS[@]}" 2>&1 | tail -1 )

# Secrets + campaign env: legacy ~/.ura_secrets first, canonical ~/.ura_env
# last (wins), then the locators (same precedence as distro/install.sh).
set -a
[ -f "$HOME/.ura_secrets" ] && source "$HOME/.ura_secrets"
[ -f "$HOME/.ura_env" ] && source "$HOME/.ura_env"
source "$CAMPAIGN_ENV"
set +a

( set -o pipefail; "$PY" -m experiments.local_targets --refresh 2>&1 | tail -1 )
git diff --quiet || { echo "TRACKED files modified after refresh:" >&2; git diff --stat >&2; exit 1; }

mkdir -p runs/thesis/project-revision
RECEIPT_ROOT="$(readlink -e -- runs/thesis/project-revision)"
RECEIPT_STAGE="$RECEIPT_ROOT/.repin-$REF-$$"
test ! -e "$RECEIPT_STAGE" && test ! -L "$RECEIPT_STAGE"
mkdir -m 700 "$RECEIPT_STAGE"
CREATE_RESULT="$(
  "$PY" -m experiments.project_revision \
    --expected-revision "$REF" --out "$RECEIPT_STAGE"
)"
mapfile -t CREATED < <(
  printf '%s' "$CREATE_RESULT" | "$PY" -c \
    'import json,sys; v=json.load(sys.stdin); print(v["artifact"]); print(v["sha256"])'
)
[ "${#CREATED[@]}" -eq 2 ] || { echo "invalid project-revision creation result" >&2; exit 1; }
STAGED_MANIFEST="${CREATED[0]}"
REPORTED_SHA="${CREATED[1]}"
test -f "$STAGED_MANIFEST" && test ! -L "$STAGED_MANIFEST"
test "${STAGED_MANIFEST%/*}" = "$RECEIPT_STAGE"
case "${STAGED_MANIFEST##*/}" in
  project-revision-*.project-revision.json) ;;
  *) echo "invalid project-revision receipt name" >&2; exit 1 ;;
esac
MANIFEST="$RECEIPT_ROOT/${STAGED_MANIFEST##*/}"
if [ -e "$MANIFEST" ] || [ -L "$MANIFEST" ]; then
  test -f "$MANIFEST" && test ! -L "$MANIFEST"
  cmp -s -- "$STAGED_MANIFEST" "$MANIFEST" \
    || { echo "content-addressed project-revision receipt collision" >&2; exit 1; }
  rm -f -- "$STAGED_MANIFEST"
else
  mv -- "$STAGED_MANIFEST" "$MANIFEST"
fi
rmdir -- "$RECEIPT_STAGE"
SHA=$(sha256sum "$MANIFEST" | awk '{print $1}')
test "$SHA" = "$REPORTED_SHA" \
  || { echo "project-revision creation SHA changed" >&2; exit 1; }
# Explicit abort: under set -e a failure on the left of '&&' would NOT stop
# the script, and the campaign env must never be rebound to an invalid receipt.
"$PY" -m experiments.project_revision --validate "$MANIFEST" --sha256 "$SHA" >/dev/null \
  || { echo "revision receipt INVALID: $MANIFEST (sha256 $SHA)" >&2; exit 1; }
echo "revision receipt valid"

# Rebind the campaign env (replace the line when present, append when absent).
# The manifest path is written relative to $HOME when the repo lives under it.
MANIFEST_ENV="${MANIFEST/#"$HOME"/\$HOME}"
rebind() { # VAR value
  if grep -q "^export $1=" "$CAMPAIGN_ENV"; then
    sed -i "s|^export $1=.*|export $1=$2|" "$CAMPAIGN_ENV"
  else
    printf 'export %s=%s\n' "$1" "$2" >> "$CAMPAIGN_ENV"
  fi
}
rebind REF_URA "$REF"
rebind URA_PROJECT_REVISION_MANIFEST "$MANIFEST_ENV"
rebind URA_PROJECT_REVISION_SHA256 "$SHA"
set -a; source "$CAMPAIGN_ENV"; set +a

# Source-conformance receipt revalidation against the operator registry. The
# bound receipt must stay valid across every re-pin (the registry is tracked
# and the receipt is content-addressed), so a bound-but-invalid receipt aborts
# before the console restart; an unbound receipt is only reported.
if [ -n "${URA_SOURCE_CONFORMANCE_MANIFEST:-}" ] && [ -n "${URA_SOURCE_CONFORMANCE_SHA256:-}" ]; then
  "$PY" -m experiments.source_conformance --manifest "$URA_SOURCE_CONFORMANCE_MANIFEST" \
      --sha256 "$URA_SOURCE_CONFORMANCE_SHA256" --source-config experiments/source-instances.json \
    | "$PY" -c "import sys,json;raw=sys.stdin.read();d=json.loads(raw) if raw.strip() else {};print('source receipt:',d.get('status'),'arms:',len(d.get('verified_admitted_arms',[])))" \
    || { echo "source receipt: NOT VALID - re-run experiments.source_conformance by hand, rebind URA_SOURCE_CONFORMANCE_MANIFEST/_SHA256 in $CAMPAIGN_ENV, then start the console (distro/install.sh console or re-run this script)" >&2; exit 1; }
else
  echo "source receipt: not bound (URA_SOURCE_CONFORMANCE_MANIFEST/_SHA256 unset in $CAMPAIGN_ENV)" >&2
fi

# Detached console restart: exactly one console, the new code. A tmux
# 'console' session from distro/install.sh is replaced too. The child carries
# the same FULL login environment as the install.sh console launcher: profiles
# (PATH, CUDA/library paths) first, then the secrets (legacy ~/.ura_secrets,
# canonical ~/.ura_env last), then the campaign env.
pkill -f -- '-m experiments\.rig_web( |$)' 2>/dev/null || true
tmux kill-session -t console 2>/dev/null || true
sleep 1
mkdir -p "$URA_DATA/acquire-logs"
setsid bash -c 'set -a
[ -f /etc/profile ] && source /etc/profile 2>/dev/null
[ -f "$HOME/.profile" ] && source "$HOME/.profile" 2>/dev/null
[ -f "$HOME/.ura_secrets" ] && source "$HOME/.ura_secrets"
[ -f "$HOME/.ura_env" ] && source "$HOME/.ura_env"
source "$1"; set +a
export PATH="$HOME/.local/bin:$PATH"
cd "$2" && exec "$3" -m experiments.rig_web --results-root runs --state-dir runs/rig-web --host "$4" --port "$5"' \
  _ "$CAMPAIGN_ENV" "$REPO" "$PY" "$CONSOLE_HOST" "$CONSOLE_PORT" \
  > "$URA_DATA/acquire-logs/console.log" 2>&1 < /dev/null &
sleep 2
curl -s -o /dev/null -w "console %{http_code}\n" "http://$CONSOLE_HOST:$CONSOLE_PORT/" || echo "console not answering yet (see $URA_DATA/acquire-logs/console.log)"
rm -f "$BUNDLE"
echo "REF=$REF PROJREV_SHA=$SHA"
