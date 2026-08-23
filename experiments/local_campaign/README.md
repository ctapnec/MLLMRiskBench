# Local campaign controller sources

This directory is the source authority for the Phase 3 through Phase 8 local
campaign controllers. The large shell and Python programs under `templates/`
are reviewed project source. They use `@@NAME@@` binding markers instead of a
project commit, receipt locator, evidence locator, or tmux schedule.

The workspace `.campaign` directory is not source authority. It holds one
operator binding JSON and the disposable byte-for-byte render produced from
these templates. A render can be copied to the rig after the project revision
it names has been deployed. Run evidence, receipts, verification logs, bundles,
and human-audit material remain outside Git.

The controllers consume, but never install into, the main URA venv. Before a
rendered chain uses a third-party bridge, `distro/install.sh runtimes` must have
attempted all 15 lock-derived frameworks as separate sequential `--only` named
tmux/screen sessions and published only verified stable aliases. Every Python
framework has its own venv, Promptfoo has its own Node environment, and BIPIA's
legacy builder has a separate fully hashed support venv. Clean runtime homes use
the explicit persistent caches under `$URA_WORK/framework-venvs/.cache`; cache
contents are never campaign admission evidence.

Start the next binding from the last validated one. The binding key set is the
exact reviewed placeholder inventory across the controller, verifier, and
installer templates. Every value has a field-specific validator: hashes,
canonical absolute POSIX paths, safe basenames, real UTC datetimes, and byte
counts cannot become shell or Python fragments. Rebind output is create-only.

Rebinding the immediately preceding pre-RR key shape is a controlled migration.
It accepts only that exact prior inventory and requires explicit values for all
four RR evidence roots. The older legacy a05 migration also discards its
obsolete shared GPU hash and requires an explicit `--set` for every new or
changed Phase 3 and installer binding below.
Use the validated prior Phase 3 artifact identities for this provisional render,
except that the project-receipt byte count describes the new receipt. Do not run
the launch chain from this provisional binding; run only the generated Phase 3
producer:

```text
python -m experiments.local_campaign.rebind \
  --base ../../.campaign/controller_bindings_<old-commit7>.json \
  --out ../../.campaign/controller_bindings_<new-commit7>-phase3.json \
  --expected-commit <new-40-hex> \
  --project-receipt-path <new-absolute-receipt> \
  --project-receipt-sha256 <new-64-hex> \
  --phase3-guard-tag <new-tag> \
  --set CONTROLLER_INSTALL_ROOT=/home/ura/.ura-controller-active \
  --set RR_TEXT_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/phase5-core-canaries-20260822T173216Z \
  --set RR_IMAGE_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/rr-image-probe-20260822T182300Z \
  --set RR_VLLM_TAIL_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/rr-token-tail-probe-5719b \
  --set RR_TRANSFORMERS_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/rr-transformers-reference-probe-5719 \
  --set PROJECT_RECEIPT_BYTES=<positive-wc-c> \
  --set PHASE3_REQUEST_BYTES=<prior-positive-wc-c> \
  --set PHASE3_ACQUISITION_BYTES=<prior-positive-wc-c> \
  --set PHASE3_FIT_LOG_BYTES=<prior-positive-wc-c> \
  --set PHASE3_GPU_BEFORE_SHA256=<prior-pre-fit-sha256> \
  --set PHASE3_GPU_BEFORE_BYTES=<prior-positive-wc-c> \
  --set PHASE3_GPU_AFTER_SHA256=<prior-post-fit-sha256> \
  --set PHASE3_GPU_AFTER_BYTES=<prior-positive-wc-c> \
  --set PHASE3_PLAN_BYTES=<prior-positive-wc-c> \
  --set PHASE3_ACQUISITION_RECEIPT_BYTES=<prior-positive-wc-c> \
  --set PHASE3_FIT_RESULT_BYTES=<prior-positive-wc-c> \
  --set PHASE3_ENVELOPE_BYTES=<prior-positive-wc-c> \
  --set PHASE3_PROJECTION_BYTES=<prior-positive-wc-c> \
  --set PHASE3_ELIGIBILITY_BYTES=<prior-positive-wc-c> \
  --set PHASE3_DOWNLOADED_BYTES=<prior-canonical-0-to-8589934592>
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new-commit7>-phase3.json \
  --output-dir ../../.campaign
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new-commit7>-phase3.json \
  --output-dir ../../.campaign --check
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new-commit7>-phase3.json \
  --output-dir ../../.campaign --package
```

Transfer that provisional `controller-set-<new-commit7>.tar` and its generated
installer to the rig, install it atomically, verify through the active pointer,
and invoke only the Phase 3 producer. The producer creates and returns its own
tmux session; do not start the launch chain:

```text
bash ~/install_controller_set_<new-commit7>.sh
bash ~/.ura-controller-active/verify_controllers_<new-commit7>.sh
bash ~/.ura-controller-active/phase3_guard1b_acquire_fit.sh
```

`--phase3-guard-tag` is not a suggested prefix. The rendered Phase 3 controller
uses that exact UTC tag for its tmux identity, engineering root, acquisition
root, and fit root. It never substitutes a launch-time clock value, and all
generated filesystem roots are create-only. Keep the same tag when deriving
the final binding; only bind artifacts produced under that exact tag.

After Phase 3 succeeds, derive the final binding from the provisional file.
Rebind every fresh file's SHA-256 and positive byte count independently:

- request, acquisition evidence, and fit log;
- pre-fit and post-fit GPU snapshots, each with its own SHA-256 and byte count;
- acquisition plan and receipt, including their names;
- fit result, request envelope, projection, and eligibility, including names
  where the producer generates them;
- `PHASE3_CANONICAL_ARGV_SHA256` and the canonical nonnegative
  `PHASE3_DOWNLOADED_BYTES` value, which must not exceed 8589934592.

Use repeatable `--set NAME=VALUE` arguments. A current binding cannot omit a
key, retain the legacy shared GPU key, or contain an extra key. Then render:

```text
python -m experiments.local_campaign.rebind \
  --base ../../.campaign/controller_bindings_<new-commit7>-phase3.json \
  --out ../../.campaign/controller_bindings_<new-commit7>.json \
  --phase5-sequence-tag <fresh-UTC-tag> \
  --gate5-sequence-tag <fresh-UTC-tag> \
  --phase6-sequence-tag <fresh-UTC-tag> \
  --phase7-watcher-tag <fresh-UTC-tag> \
  --set PHASE3_REQUEST_SHA256=<sha256> \
  --set PHASE3_REQUEST_BYTES=<positive-wc-c> \
  --set PHASE3_ACQUISITION_SHA256=<sha256> \
  --set PHASE3_ACQUISITION_BYTES=<positive-wc-c> \
  --set PHASE3_FIT_LOG_SHA256=<sha256> \
  --set PHASE3_FIT_LOG_BYTES=<positive-wc-c> \
  --set PHASE3_GPU_BEFORE_SHA256=<sha256> \
  --set PHASE3_GPU_BEFORE_BYTES=<positive-wc-c> \
  --set PHASE3_GPU_AFTER_SHA256=<sha256> \
  --set PHASE3_GPU_AFTER_BYTES=<positive-wc-c> \
  --set PHASE3_PLAN_NAME=<name> \
  --set PHASE3_PLAN_SHA256=<sha256> \
  --set PHASE3_PLAN_BYTES=<positive-wc-c> \
  --set PHASE3_ACQUISITION_RECEIPT_NAME=<name> \
  --set PHASE3_ACQUISITION_RECEIPT_SHA256=<sha256> \
  --set PHASE3_ACQUISITION_RECEIPT_BYTES=<positive-wc-c> \
  --set PHASE3_FIT_RESULT_SHA256=<sha256> \
  --set PHASE3_FIT_RESULT_BYTES=<positive-wc-c> \
  --set PHASE3_ENVELOPE_NAME=<name> \
  --set PHASE3_ENVELOPE_SHA256=<sha256> \
  --set PHASE3_ENVELOPE_BYTES=<positive-wc-c> \
  --set PHASE3_PROJECTION_NAME=<name> \
  --set PHASE3_PROJECTION_SHA256=<sha256> \
  --set PHASE3_PROJECTION_BYTES=<positive-wc-c> \
  --set PHASE3_ELIGIBILITY_NAME=<name> \
  --set PHASE3_ELIGIBILITY_SHA256=<sha256> \
  --set PHASE3_ELIGIBILITY_BYTES=<positive-wc-c> \
  --set PHASE3_CANONICAL_ARGV_SHA256=<sha256> \
  --set PHASE3_DOWNLOADED_BYTES=<canonical-0-to-8589934592>
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new-commit7>.json \
  --output-dir ../../.campaign
```

Before packaging or transfer, prove that no workspace edit diverged from the
versioned source plus its explicit bindings:

```text
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new-commit7>.json \
  --output-dir ../../.campaign --check
```

Then generate the version-bound verifier, deterministic archive, and installer
from the same source and binding file:

```text
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new-commit7>.json \
  --output-dir ../../.campaign --package
```

Transfer this final archive and installer even though the commit short is the
same as the provisional generation. Its archive digest is different. Re-run the
installer to atomically activate the final generation, verify the active set,
and only then start the commit-specific launch chain:

```text
bash ~/install_controller_set_<new-commit7>.sh
bash ~/.ura-controller-active/verify_controllers_<new-commit7>.sh
bash ~/.ura-controller-active/launch_chain_<new-commit7>.sh
```

The archive contains 24 executable generated controllers, the generated
read-only Phase 8 operator guide, their generated inventory, and the generated
verifier. The installer remains outside the archive. Both
support programs come from the tracked `verify_controller_set.sh.in` and
`install_controller_set.sh.in` sources; only their hashes and locators are
workspace bindings.

`CONTROLLER_INSTALL_ROOT` is the active pointer, normally
`/home/ura/.ura-controller-active`, rather than the transfer directory. The
installer derives the transfer directory from its parent, validates every
archive, inventory, verifier, and controller byte in a private stage, and then
publishes an immutable
`.ura-controller-generations/<commit7>-<archive-sha256>` directory. It changes
the live set with one atomic active-symlink rename only after the generation is
complete. Re-running the exact installer validates and reuses that generation.
An interrupted private stage is never resumed or activated, and an existing
foreign generation or active target fails closed. Invoke the verifier and
commit-specific launch chain through the active pointer; legacy controller
files directly under `/home/ura` are not part of the active generation.
At chain entry, the opened script resolves its own Linux process descriptor to
one physical immutable generation, validates that generation's marker, and
exports that exact root to descendants. All sibling hashing, sealing, tmux
launches, and deferred calls use the pinned physical root. A later provisional
or final active-pointer switch therefore affects only a future chain, never one
already running.

`phase6_native_diagnostics.sh.in` renders `phase6_native_diagnostics.sh`.
Its one-case native canaries/imports are engineering diagnostics outside
`runs/thesis`; they are not Runner/common-metric measured evidence.

The Gate 5 inventory contains 46 rows: 22 runnable rows and 24 typed terminal
rows, or 21 runnable and 25 terminal rows when `defense-local` takes its exact
conditional N/A disposition. The three GPTGeoChat x RWKV Ollama cross-products
are unavailable because that exact target transport is text-only; the Ollama
projection and canary controller self-test proves they cannot enter a runnable
loop. Four further rows share one exact
`ura-phase5-target-runtime-terminal/1` descriptor because the sealed GraySwan RR
checkpoint reached its generation cap without a stop in both text and physical-
image probes. The controller retains its completed no-call projections but
excludes those four identities from canary, measured, metric, paired-analysis,
and human-audit inputs. The checkpoint and runtime remain installed.

Phase 7 binds two distinct Runner views. Its authoritative lifecycle registry
covers every scheduled Runner lane and binds each controller failure, optional
exact measured argv, and retained grid, request-envelope, eligibility, and
error artifacts. The Level 1 tool receives every retained Runner/request
artifact it can represent. A genuine pre-Runner failure with no request
artifact remains explicit in the registry and is not fabricated into Level 1
input. Suite metrics and Level 2 receive only successful measured Runner lanes.
A failed lifecycle is never promoted into metric evidence.

Phase 8 consumes Phase 7's validated success-only read-only Runner copy. This
keeps an honestly failed or partial Runner lifecycle in the canonical lifecycle
tree without letting `human_audit` mistake it for a completed sample input. The
view receipt content-binds every relative source/copy file, distinct identity,
digest, byte count, and read-only mode; the completed view permits no analysis
output or other extra file. Phase 7's separate lifecycle copy uses the same
source-preserving boundary for Level 1. The
create-only Phase 8 input manifest records an exact cardinality plan: the common
population must cover the requested common sample plus 20 disjoint
qualification clusters, and the source-task population must cover its exact
requested sample. Cardinality is recomputed from the same view before any
sample write, while both selectors retain their independent achieved-cell
coverage checks. A successful machine controller remains `human_only_blocked` with
`gate8_met: false`; only real qualified raters, independent labels,
adjudication, validated reports, and a human acceptance or limitation record
can satisfy the later Gate 8 conditions. The generated
`phase8_human_audit.README.md` in the active controller generation is the
commit-bound operator guide.
