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

- `git curl tar tmux` (plus `zstd` for the `ollama` phase; Debian: `apt install
  git curl tar tmux zstd`).
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
| `deps` | create `.venv` with `$URA_PYTHON` (resolved as above) and editable-install with the `dev,analysis,api,guardrail,local-vllm` extras + `hf`/`gdown` CLI tools (verified present) |
| `clones` | pinned upstream git snapshots (StrongREJECT, HarmBench, BIPIA, ...); stale clones are repaired via fetch + re-checkout |
| `hf` | pinned Hugging Face dataset releases (AgentHarm, JBB, JailBreakV-28K, MLLMGuard, VLSBench, Video-SafetyBench, JALMBench) |
| `archives` | separately-distributed media: MM-SafetyBench images (Drive, stall-hardened), GPTGeoChat human split (MediaFire scrape), SIUO images (HF dataset repo), Video-SafetyBench extract, JailBreakV image-backed subset generation, JALMBench/VLSBench exports |
| `bipia` | build the BIPIA qa/abstract sets from their external XSum/NewsQA bases (NewsQA is licensed - obtain `$URA_UPSTREAM/newsqa-data` manually; until then `URA_BIPIA_TEST_QA_PATH` is reported `MISSING ... (blocked: licensed NewsQA base)`) |
| `aggregators` | fetch the aggregator corpora - SALAD-Bench, AIR-Bench 2024, XSTest, SimpleSafetyTests, DecodingTrust (stereotype), HoliSafe (multimodal, gated) - via `experiments.export_aggregators` (the HoliSafe export resolves the `hf` CLI next to the venv interpreter, so the venv need not be activated), per-source skip when present |
| `ollama` | user-local ollama runtime **v0.32.13** pinned: `ollama-linux-amd64.tar.zst` from the GitHub release, its sha256 checked against the release's published `sha256sum.txt` AND the pin in the script (fail-closed on any mismatch), extracted under `~/.local/ollama` + `~/.local/bin/ollama` symlink (the console-owned daemon needs it on PATH) |
| `runtimes` | resume or create, then separately verify, all 15 isolated third-party framework runtimes under the strict lock: `framework_runtime_installer resume/verify --lock experiments/framework_runtime_lock.json --env-root $URA_DATA/framework-venvs --state-root $URA_DATA/runs/engineering/framework-runtime-<lock_id[:12]> --python <venv base = CPython 3.12.13>` - 14 private Python venvs plus Promptfoo's private Node runtime, using the same roots as runbook 12.2 and Build -> Runtimes. Each command runs in the installer's named tmux/screen session; the phase waits for its exit marker (168 h deadline, liveness probe) and ledgers the real exit code as `runtimes-install` / `runtimes-verify`. `resume` is safe for a fresh store and resumes a phase-checked staged store after interruption; any install/resume or verify failure makes this phase and `all` exit nonzero. Requires the `deps` venv: without it the phase fails closed as `runtimes-plan (venv missing ...)` |
| `locators` | write every `URA_*_PATH` binding (incl. `URA_MEDIA_ROOTS`, `HF_HOME`, `PATH`) plus `URA_REPO` (the checkout) and `URA_PY` (`$URA_REPO/.venv/bin/python`, the interpreter the runbook's `ura_native_run` wrapper uses) into `~/.ura_campaign_env`; seed `experiments/source-instances.json` from `experiments/rig/source-instances.example.json` when absent and set the six aggregator arms from that example (labels included - `source_conformance` matches them against the retained receipt); print an existence report |
| `console` | (re)launch the rig console in tmux session `console` on `127.0.0.1:8642` with the FULL login env (profile + secrets + campaign env + `~/.local/bin` on PATH) |
| `summary` | per-step OK/FAIL report from the step ledger |

Run a subset by naming phases: `distro/install.sh clones hf aggregators locators`.

`all` = deps clones hf archives bipia aggregators ollama runtimes locators
console summary - the complete start-to-end installation.

## Secrets

Provider API keys and `HF_TOKEN` live only in `~/.ura_env` (mode 600), never in
the repo. `~/.ura_env` is the canonical operator secrets file: it is the file the
console's Config page writes rotated keys into, and the installer, the console
launcher it generates and `repin.sh` all source it LAST, so it wins over any
other file. `~/.ura_secrets` is an optional legacy file (rigs provisioned by an
earlier installer); it is sourced first and overridden by `~/.ura_env`, so a key
rotated in the console is never shadowed by a stale legacy value.
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
4. project-revision receipt: supersedes the previous receipt, creates the new one
   with `--expected-revision <commit>`, validates it by sha256 - an invalid
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
