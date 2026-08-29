# distro/ - rig installer and re-pin

`install.sh` is the single, reproducible installer that stands up the whole
URA-Bench measured-campaign environment on a fresh rig, start to end. It
replaces the ad-hoc pile of operator scripts (`acquire_sources`, `fix_acquire`,
`fix2_acquire`, `bipia_build`, `*_export`, `bind_locators`, `start_console`).
`repin.sh` deploys one tracked commit to the rig console afterwards.

Everything lands under `$URA_DATA` (default `/data/ura-work`, the big storage),
never the home partition or the tracked tree. Idempotent: re-runs skip every
already-materialized source (skips are recorded OK in the step ledger).

## Prerequisites

- `git curl tar` and at least one persistent launcher, with tmux preferred and
  screen supported (plus `zstd` for the `ollama` phase; Debian:
  `apt install git curl tar tmux zstd` or substitute `screen` for `tmux`).
- A CPython `>=3.12,<3.14` interpreter for the venv (the package declares
  `requires-python = ">=3.12,<3.14"`). The framework runtime lock additionally
  binds exact **CPython 3.12.13** as the venv's base interpreter, so use that:
  `uv python install 3.12.13` and `export URA_PYTHON=$(uv python find 3.12.13)`.
  Without `URA_PYTHON`, `python3.12`, `python3.13` and `python3` are tried in
  that order and the installer fails closed (exit 3) when none qualifies - the
  Debian 12 system `python3` (3.11) is never silently adopted. An existing
  `.venv` is adopted only if it passes the same check; its base interpreter is
  then the one used (a `URA_PYTHON` that differs from it is reported as
  `[warn] URA_PYTHON=... ignored`, not applied - remove `.venv` and re-run
  `deps` to rebuild).

## Quick start

```bash
cp distro/.env.example ~/.ura_env && chmod 600 ~/.ura_env   # fill in HF_TOKEN and provider keys
export URA_PYTHON=$(uv python find 3.12.13)                   # exact version required by `all`
distro/install.sh all                     # EVERYTHING: deps + every corpus +
                                          # ollama + runtimes + locators + console
```

`all` ends with a per-step OK/FAIL summary and a nonzero exit if any step
failed; logs live under `$URA_DATA/acquire-logs/`.

## Phases

| phase | what it does |
|---|---|
| `deps` | create `.venv` with `$URA_PYTHON` (resolved as above) and editable-install with the `dev,analysis,api,guardrail,local-vllm` extras + `hf`/`gdown` CLI tools (verified present); remove legacy duplicate top-level PyRIT, Spikee, `datasets`, and `jsonlines` installs, fail if any other lock-derived framework root remains in a reused main venv without pruning shared transitive dependencies, then run `pip check` (their isolated runtimes/support environment are retained) |
| `clones` | pinned upstream git snapshots (StrongREJECT, HarmBench, BIPIA, ...); stale clones are repaired via fetch + re-checkout |
| `hf` | pinned Hugging Face dataset releases (AgentHarm, JBB, JailBreakV-28K, MLLMGuard, VLSBench, Video-SafetyBench, JALMBench) |
| `archives` | separately-distributed media: MM-SafetyBench images (Drive, stall-hardened), GPTGeoChat human split (MediaFire scrape), SIUO images (HF dataset repo), Video-SafetyBench extract, JailBreakV image-backed subset generation, JALMBench/VLSBench exports |
| `bipia` | create or verify a content-addressed, no-system-site-packages support venv under `$URA_DATA/support-venvs` from the fully hashed `distro/bipia-build-requirements.lock`, then build the BIPIA qa/abstract sets without installing its legacy `datasets` stack into the main URA venv (NewsQA is licensed - obtain `$URA_UPSTREAM/newsqa-data` manually; until then `URA_BIPIA_TEST_QA_PATH` is reported `MISSING ... (blocked: licensed NewsQA base)`) |
| `aggregators` | fetch the aggregator corpora - SALAD-Bench, AIR-Bench 2024, XSTest, SimpleSafetyTests, DecodingTrust (stereotype), HoliSafe (multimodal, gated) - via `experiments.export_aggregators` (the HoliSafe export resolves the `hf` CLI next to the venv interpreter, so the venv need not be activated), per-source skip when present |
| `ollama` | user-local ollama runtime **v0.32.13** pinned: `ollama-linux-amd64.tar.zst` from the GitHub release, its sha256 checked against the release's published `sha256sum.txt` AND the pin in the script (fail-closed on any mismatch), extracted under `~/.local/ollama` + `~/.local/bin/ollama` symlink (the console-owned daemon needs it on PATH) |
| `runtimes` | plan the strict lock, then issue a separate sequential `verify --only NAME` named tmux/screen session for each of all 16 isolated third-party framework runtimes: 14 private Python venvs plus separate Promptfoo and T3MP3ST Node runtimes under `$URA_DATA/framework-venvs`. A passing row is left untouched. A missing, interrupted, new, or changed row alone proceeds through `resume --only NAME` and final verification. When `URA_FRAMEWORK_ADOPT_FROM_LOCK` explicitly names an exact retained prior lock, an aggregate-lock mismatch first attempts strict per-row adoption; only a byte-identical row with unchanged execution-global pins can be rebound without reinstalling. A failed row is retained, but every later row is still attempted; per-row statuses and honest `runtimes-install`/`runtimes-verify` aggregates make this phase and `all` exit nonzero when any row fails. The clean per-runtime homes use persistent caches at `$URA_DATA/framework-venvs/.cache/pip` and `.cache/npm`; caches never decide admission. Uses the same lock/roots as runbook 12.2 and Build -> Runtimes and requires the `deps` venv with exact CPython 3.12.13 as its base. |
| `locators` | write every `URA_*_PATH` binding (incl. `URA_MEDIA_ROOTS`, `HF_HOME`, `PATH`) plus `URA_REPO` (the checkout) and `URA_PY` (`$URA_REPO/.venv/bin/python`, the interpreter the runbook's `ura_native_run` wrapper uses) into `~/.ura_campaign_env`; seed `experiments/source-instances.json` from `experiments/rig/source-instances.example.json` when absent and add only missing aggregator arms from that example. Existing operator-reviewed entries are never rewritten because `source_conformance` binds their converter, path, label, and split to the retained receipt; print an existence report |
| `console` | (re)launch the rig console in persistent session `console` on `127.0.0.1:8642`, preferring tmux and falling back to screen, with the FULL login env (profile + secrets + campaign env + `~/.local/bin` on PATH) |
| `summary` | per-step OK/FAIL report from the step ledger |

Run a subset by naming phases: `distro/install.sh clones hf aggregators locators`.

`all` = deps clones hf archives bipia aggregators ollama runtimes locators
console summary - the complete start-to-end installation.

For an aggregate framework-lock transition, retain the exact old lock outside
the checkout and opt into adoption explicitly:

```bash
export URA_FRAMEWORK_ADOPT_FROM_LOCK=/absolute/operator/path/framework_runtime_lock.previous.json
distro/install.sh runtimes
unset URA_FRAMEWORK_ADOPT_FROM_LOCK
```

The path must be an already-resolved absolute regular file. The installer never
discovers a prior lock automatically. Adoption requires equal lock schema,
platform, policy and runtime pins and an equal complete framework row, then
rechecks its retained seal, exact inventory and offline smoke. Rows that do not
qualify follow the ordinary resume/install path.

## Secrets

Provider API keys and `HF_TOKEN` live only in `~/.ura_env` (mode 600), never in
the repo. `~/.ura_env` is the canonical operator secrets file and is where the
console's Config page writes rotated keys. `install.sh` does not source either
secret file at process scope: it sources them only inside the subshell of an
HF-backed download/export and inside the generated console launcher, never
prints a value, and keeps every unrelated install/runtime command free of those
bindings. `repin.sh` and the console launcher retain their documented narrow
use. `~/.ura_secrets` is an optional legacy file; whenever both are needed it is
sourced first and overridden by `~/.ura_env`, so a rotated canonical key wins.

Download caches are explicit and outside sealed environments. BIPIA uses
`$URA_DATA/package-cache/pip`; managed frameworks use
`$URA_DATA/framework-venvs/.cache/{pip,npm}` even though each subprocess has a
clean HOME. Deleting a cache affects transfer time only, never lock, inventory,
smoke, receipt, or content-seal verification.
`distro/.env.example` is the template and lists the full provider roster the
code reads (Anthropic, OpenAI, Gemini/Google, DeepSeek, Moonshot, DashScope/Qwen,
Zhipu/GLM, Ark/Doubao).

Gated HF datasets (AgentHarm, DecodingTrust, HoliSafe) additionally require the
operator's HF account to have accepted each dataset's terms.

## Deploy / re-pin

The installer sets up the environment; deploying a specific tracked commit to
the console is `distro/repin.sh`. The rig has no GitHub credentials, so code
travels as a git bundle, and the script that runs is the `repin.sh` OF THE
COMMIT BEING DEPLOYED, copied to `~/repin.sh` (bootstrap + canonical form):

```bash
# local workstation, checked out at the commit being deployed
git bundle create web002.bundle main
scp web002.bundle rig:~/web002.bundle
scp distro/repin.sh rig:~/repin.sh
# rig (REPO defaults to ~/MLLMRiskBench, BUNDLE to ~/web002.bundle)
ssh rig 'bash ~/repin.sh <40-hex-commit>'
```

Never run the in-tree copy (`bash ~/MLLMRiskBench/distro/repin.sh`): that file
is the one at the CURRENTLY pinned commit - it may not exist yet (a rig pinned
at 33a2c65 has no `distro/repin.sh` at all) or may lack later fixes, because the
checkout only advances inside the script. `repin.sh` has no dependency on its
own location (`REPO`/`BUNDLE` are env parameters) and, after fetching the
bundle, prints `warning: ... differs from distro/repin.sh at <commit>` when the
executing copy is not the deployed commit's version.

`repin.sh <commit>` (run ON the rig, `$REPO/.venv/bin/python` as interpreter)
fetches the bundle and refuses unless its head is exactly `<commit>`, detach-
checks it out, then:

1. hygiene: kills stray processes matched on the anchored
   `-m experiments.run_matrix` / `-m experiments.rig_web` invocation only (a path
   such as `experiments/rig_web_app/...` in an editor or `tail` is not matched)
   and clears `/tmp/pytest-of-<user>` before the gate (either makes the suite
   fail spuriously);
2. clean-environment full-suite gate (every `URA_*` variable unset, names with
   digits such as `URA_PROJECT_REVISION_SHA256` included);
3. `experiments.local_targets --refresh`, then refuses if any TRACKED file
   changed (`git diff --quiet`);
4. project-revision receipt: preserves every prior content-addressed receipt at
   its stable path, creates or byte-identically adopts the receipt for
   `--expected-revision <commit>`, and validates it by sha256 - an invalid
   receipt aborts (`revision receipt INVALID`) before anything is rebound;
5. rebinds `REF_URA`, `URA_PROJECT_REVISION_MANIFEST`,
   `URA_PROJECT_REVISION_SHA256` in `~/.ura_campaign_env` and re-sources it;
6. re-validates the retained source-conformance receipt against
   `experiments/source-instances.json` (prints status + admitted arm count); the
   bound receipt is expected to stay valid across every re-pin, so a bound but
   invalid receipt aborts (`source receipt: NOT VALID`) before the console
   restart, while an unbound receipt is only reported;
7. restarts the console detached (`setsid`, log at
   `$URA_DATA/acquire-logs/console.log`, host/port from
   `URA_CONSOLE_HOST`/`URA_CONSOLE_PORT`, default `127.0.0.1:8642`) with the
   same FULL login environment as `install.sh console` (`/etc/profile` and
   `~/.profile` first, then `~/.ura_secrets`, `~/.ura_env` last, then the
   campaign env, `~/.local/bin` on PATH), replacing any previous console
   including the tmux `console` session `install.sh` started - exactly one
   console runs either way;
8. removes the bundle and prints `REF=<commit> PROJREV_SHA=<sha256>`.

Every step is fail-closed (`set -euo pipefail`, with the receipt validation and
the source-receipt revalidation aborting explicitly rather than relying on
`errexit`); a failed step leaves the rig on the new checkout without a console,
which is visible in the output - fix the cause and re-run `repin.sh`, or start
the console with `distro/install.sh console`.
