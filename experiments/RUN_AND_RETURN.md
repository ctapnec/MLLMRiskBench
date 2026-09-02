# Run and return: broad thesis experiment program

This is the operator path from a clean Linux GPU machine to the evidence bundle
for the thesis. It covers the broad hosted and local model roster, all twenty-five source converters, the runner-safe external attack bridges, and nine complete
source-native evaluators. Experiments and the human audit are still pending.
Preflight, dry-run, diagnostic-canary, and bounded transport-probe artifacts are
diagnostics, not thesis results.

The maintained artifact contract is Runner `ura-runner/2.27` with unified schema
`1.5`. Runner 2.27 is the current executable contract used by this runbook.
Runner 2.19/schema 1.4 artifacts remain runtime-free legacy
compatibility only; do not combine them with the current measured cohort.

Every `python -m experiments.*` command below can equivalently be started
from the rig console and campaign builder (section 18): the console builds
the identical argument vector from a typed allowlist, so admission gates and
artifacts do not differ between the two interfaces, and the CLI remains
authoritative. Repeatable flags (multiple `--live-attestation` receipt/digest
pairs, repeated `--eligibility`/`--results`/`--native` inputs, repeated
`--arm`/`--observation` for a multi-arm source-conformance scaffold) are
repeatable form rows in the console; the interface-parity tests validate every
console form against the real module parsers.

The stable entry point and import facade is `experiments/rig_web.py`; its
implementation is separated under `experiments/rig_web_app/` by command/UI,
artifact/report/database, lifecycle, builder/page, application, and localhost
server responsibilities. This layout does not change any operator command or
artifact contract.

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
| RQ3 portfolio breadth/heterogeneity | 45 converter arms, nine native projects, section 16 suite summary | disposition-complete family inventory without false pooling |
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

The intended rig is Linux, exact CPython 3.12.13, two RTX 4090 cards, recent
NVIDIA drivers, Git, tmux or screen (tmux is preferred), and enough controlled
storage for large audio and video releases. Promptfoo receives its own official
Node runtime, and a pinned user-local Git-LFS runtime is provisioned only when a
locked source actually needs it; neither system Node nor system Git LFS is a
prerequisite. JALMBench alone is much larger than the three small core sources;
inspect the official repository size before downloading it.

```bash
nvidia-smi
git --version
python3.12 --version
if command -v tmux >/dev/null 2>&1; then
  tmux -V
elif command -v screen >/dev/null 2>&1; then
  screen --version
else
  echo 'tmux or screen is required' >&2
  exit 1
fi

# URA_WORK is the data/evidence root (corpora, upstream snapshots, framework
# environments, engineering campaigns, model store). URA_REPO is the URA
# checkout and URA_PY its interpreter: every wrapper below resolves the URA
# interpreter through URA_PY, never through a path under URA_WORK.
# distro/install.sh roots URA_WORK at /data/ura-work instead and writes the same
# names into ~/.ura_campaign_env; persist them there on the rig so new shells
# and the section 14.2 native wrappers see one layout.
export URA_WORK="$HOME/ura-work"
export URA_CORPORA="$URA_WORK/corpora"
export URA_UPSTREAM="$URA_WORK/upstream"
export URA_FRAMEWORK_ENVS="$URA_WORK/framework-venvs"
export URA_REPO="$HOME/MLLMRiskBench"
export URA_PY="$URA_REPO/.venv/bin/python"
mkdir -p "$URA_CORPORA" "$URA_UPSTREAM" "$URA_FRAMEWORK_ENVS"

git clone https://github.com/ctapnec/MLLMRiskBench.git "$URA_REPO"
# A rig without GitHub access clones the verified source bundle instead:
# git clone /path/to/ura-project-source.bundle "$URA_REPO"
cd "$URA_REPO"
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
Generated dashboard captures, installer logs, and local/rig engineering
campaigns stay in ignored operator state. They are operational diagnostics, are
not committed, and are not usable thesis evidence or authority for a revision;
do not copy a mutable hash or test count into this runbook.

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

### 2.1 Versioned local-campaign controllers

Phase 3-8 controller logic is tracked under
`experiments/local_campaign/templates/`. Do not repair a substantive controller
only in the workspace or on the rig. For this controller workflow, the sibling
`.campaign` directory holds disposable renders, one explicit binding JSON,
inventories, packages, and transfer files; none of those files or any run
evidence is committed.

A tracked template cannot contain the hash of the commit that will contain it.
The generator accepts exactly the reviewed external placeholder inventory and
applies semantic validators before substitution: hashes, safe basenames,
canonical absolute POSIX paths, real UTC datetimes, and canonical byte counts
cannot become shell or Python fragments.

After repin has deployed the new commit and created its project-revision receipt,
derive a create-only provisional binding from the last validated binding. The
exact migration from the immediately preceding pre-recovery-controller key
inventory requires both recovery input manifests, their byte identities, and
two fresh UTC tags below. A still older pre-RR inventory also requires the four
RR evidence roots. The legacy a05 migration additionally requires every Phase 3
and installer binding shown below; any other prior subset or extra key is
rejected. Use validated prior Phase 3 values for the provisional
artifact fields, but bind the new project receipt's exact byte count. Render the set and
run only the generated `phase3_guard1b_acquire_fit.sh` at this stage:

```bash
python -m experiments.local_campaign.rebind \
  --base ../../.campaign/controller_bindings_<old7>.json \
  --out ../../.campaign/controller_bindings_<new7>-phase3.json \
  --expected-commit <new-40-hex> \
  --project-receipt-path <absolute-new-project-receipt> \
  --project-receipt-sha256 <new-project-receipt-sha256> \
  --phase3-guard-tag <fresh-UTC-tag> \
  --set CONTROLLER_INSTALL_ROOT=/home/ura/.ura-controller-active \
  --set RR_TEXT_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/phase5-core-canaries-20260824T053641Z \
  --set RR_IMAGE_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/rr-image-probe-20260824T053641Z \
  --set RR_VLLM_TAIL_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/rr-token-tail-probe-5719b \
  --set RR_TRANSFORMERS_EVIDENCE_ROOT=/mnt/stor/data/ura-work/runs/engineering/rr-transformers-reference-probe-5719 \
  --set PHASE6_RECOVERY_TAG=<fresh-UTC-tag> \
  --set PHASE6_RECOVERY_INPUTS_PATH=<resolved-absolute-input-manifest> \
  --set PHASE6_RECOVERY_INPUTS_SHA256=<sha256> \
  --set PHASE6_RECOVERY_INPUTS_BYTES=<positive-wc-c> \
  --set SEVEN_POLICY_TAG=<later-fresh-UTC-tag> \
  --set SEVEN_POLICY_INPUTS_PATH=<resolved-absolute-input-manifest> \
  --set SEVEN_POLICY_INPUTS_SHA256=<sha256> \
  --set SEVEN_POLICY_INPUTS_BYTES=<positive-wc-c> \
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
  --bindings ../../.campaign/controller_bindings_<new7>-phase3.json \
  --output-dir ../../.campaign
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new7>-phase3.json \
  --output-dir ../../.campaign --check
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new7>-phase3.json \
  --output-dir ../../.campaign --package
```

Transfer that provisional `controller-set-<new7>.tar` to the exact remote
filename `~/controller-set-<new7>.tar` together with its generated installer.
Install and verify the immutable generation through the active pointer, then
invoke only the Phase 3 producer. It creates and returns its own tmux session:

```bash
bash ~/install_controller_set_<new7>.sh
bash ~/.ura-controller-active/verify_controllers_<new7>.sh
bash ~/.ura-controller-active/phase3_guard1b_acquire_fit.sh
```

Do not invoke the provisional launch chain. Its Phase 3 evidence identities are
the prior validated values used only to make the migration binding complete.

The generated controller uses the exact `--phase3-guard-tag` binding for its
tmux identity and all engineering, acquisition, and fit roots. It does not
derive a timestamp when launched. Those roots are create-only, so choose the
tag once, render once, and do not change it in the final binding.

After that Phase 3 controller succeeds, derive the final create-only binding
from the provisional file. Replace every fresh Phase 3 file's SHA-256 and
positive byte count, both independent GPU snapshots, generated names, the
canonical argv digest, the actual nonnegative downloaded-byte count, and the
four sequence tags. `PHASE3_DOWNLOADED_BYTES` must be canonical and no greater
than the 8589934592-byte acquisition cap. Then render, check for workspace
drift, and build the deterministic verifier/archive/installer set:

```bash
python -m experiments.local_campaign.rebind \
  --base ../../.campaign/controller_bindings_<new7>-phase3.json \
  --out ../../.campaign/controller_bindings_<new7>.json \
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
  --bindings ../../.campaign/controller_bindings_<new7>.json \
  --output-dir ../../.campaign
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new7>.json \
  --output-dir ../../.campaign --check
python -m experiments.local_campaign.generate \
  --bindings ../../.campaign/controller_bindings_<new7>.json \
  --output-dir ../../.campaign --package
```

Transfer the newly packaged final `controller-set-<new7>.tar` to the exact
remote filename `~/controller-set-<new7>.tar` together with
`install_controller_set_<new7>.sh`, then run:

```bash
bash ~/install_controller_set_<new7>.sh
bash ~/.ura-controller-active/verify_controllers_<new7>.sh
bash ~/.ura-controller-active/launch_chain_<new7>.sh
```

The final archive has a different digest from the provisional archive even
though both names use the same commit short. The second installer run publishes
and activates that final immutable generation before the launch chain starts.
The archive contains every allow-listed executable controller plus the read-only
rendered `phase8_human_audit.README.md`. Read that guide through
`~/.ura-controller-active` before preparing Phase 8 input; a sibling
`.campaign` copy is disposable and must not be treated as source authority.

The installer validates every archive, inventory, verifier, and controller
byte before publishing one immutable
`~/.ura-controller-generations/<commit7>-<archive-sha256>` directory. Its only
live-set change is an atomic rename of the `.ura-controller-active` symlink.
Re-run the exact installer after an interruption: an unpublished stage cannot
become active, a complete matching generation is reused, and a foreign existing
generation or active target is rejected. Always invoke the verifier and launch
chain through the active pointer; old direct controller files under `~/` are
stale and are not launch paths. One-case native framework executions remain
engineering diagnostics outside `runs/thesis` and run only through the active
generation's `phase6_native_diagnostics.sh`; they are not Runner or
common-metric measured evidence.

Each launch-chain root pins the physical immutable generation from its already
opened Linux script descriptor before it hashes or opens any sibling. That
exact root is inherited and revalidated by descendants, and every deferred
tmux launch, hash check, and Phase 6/7 seal reads from it. Do not rewrite
`URA_CONTROLLER_GENERATION_ROOT` in an operator environment. Switching
`.ura-controller-active` while an older chain is running changes only the next
chain; the running chain stays entirely on its pinned generation.

The Phase 5 and Gate 5 orchestration controllers enforce a 24-hour global
controller deadline, and the Phase 7 watcher enforces 720 hours. At expiry, a
controller records exit 124 and the exact wait/hours reason in task and campaign
events. It terminates and confirms absence of only an exact tmux session it
launched and owns; a controller that times out while awaiting upstream Phase 5
or Phase 6 never terminates that upstream session.

The rendered historical Gate 5-8 chain enforces an exact 46-row partition. Its
retained baseline is 18 runnable and 28 typed-terminal rows, including seven
target-runtime-terminal rows; `defense-local` remains conditional N/A. Its
three GPTGeoChat x RWKV rows remain typed unavailable historical records. The
RWKV tags are no longer installed and no prospective controller selects them.
The core cohort records `bridge-nanogcg`, `bridge-ideator`, and
`t3mp3st` as `unavailable` only because their prepared artifacts are assigned
to a separate follow-on cohort and were not bound when its Gate 5 authorization
was sealed. This is not a current capability disposition. The core controller
does not schedule those three lanes for core-cohort measured execution. The
follow-on cohort binds the NanoGCG capture config, IDEATOR v2 source-mapped
manifest, and T3MP3ST bundle and uses the ordinary documented Runner commands
with one retained common scientific base and separate exact preflight, canary
and measured argument arrays. Each purpose keeps its own plan and receipt. For
each lane, the retained schedule contains a prepared artifact, no-call projection,
diagnostic canary, Gate 5 record, and measured schedule.
NanoGCG may use a positive outer limit or a separately projected `--limit 0`
transfer cohort. IDEATOR v2 is fixed to
`advbench_harmful --limit 1 --sample-seed 105`; `pair_limit=0` means
all eight verified pairs mapped to `advbench:245`, not all 520 AdvBench
rows. Four GraySwan RR rows and three RWKV static rows retain immutable
historical Gate 5 terminal records produced before Runner accepted nonempty
length-capped output and typed successful empty completions. Those artifacts
still bind the exact checkpoint or Ollama digest, configuration, diagnostic
calls and complete accounting, but they are not the current output policy.
Runner 2.22 and later retains nonempty `finish_reason='length'` text and its
truncation provenance; Runner 2.23 retains a successful empty Ollama completion
as typed `model_nonresponse`, and Runner 2.24 applies the same typed outcome to
a successful empty vLLM completion. Runner 2.25 defaults to one additional
answer attempt (`--target-answer-retries 1`) after empty, malformed,
binary/control-like, symbol-only or exhausted-transport output. Nonempty vague,
repetitive or semantically poor natural language is sent to the selected
evaluator. If the retry also fails, the row is checkpointed as
`model_stability_status=failed_output`, the policy judge is not queried, and the
remaining assigned population continues. Stats reports this missing-response
coverage separately from decided security rates. Projections reserve the target
and transport upper bounds for both attempts. Exact identity, seals, fixed
configuration, durable caps and operator wall-time limits remain terminal; none
permits altered stops, generation caps, checkpoint identity or decoding. The
failed-output mechanism is provider-neutral. When a backend has already
verified a strong runtime/model identity before answer validation fails, the
missing-response artifact retains that normalized identity and compares it
across the retry. This can satisfy route attestation without turning the absent
answer into policy evidence. The current local campaign pins
one answer retry for vLLM and Ollama. The budget-fitted hosted campaign pins
answer, harness transport and provider SDK retries to 0, so paid targets and
Haiku judgments receive exactly one application attempt. Build sets and locks
the answer-retry field to 0 whenever a hosted target is selected, and server
validation rejects a nonzero submitted value. The first durably retained failed
hosted-target output, or any hosted target transport/network failure, opens the
global `paid_provider` circuit before another paid call can start. Classify a
provider-completed empty response separately from interrupted transport, resolve
the cause, derive a fresh bound plan and explicitly reset the circuit. Never
resume paid execution automatically.
Runner 2.26 separately retains an exact deterministic target-input rejection as
`target_input_status=incompatible`. It makes no answer retry for the unchanged
input, does not query the policy judge, records missing-response coverage, and
continues the selected population. Do not relabel this as model instability: no
model output was produced. Other validation, identity, seal, configuration,
budget, and transport failures stay terminal.

The retained local-campaign vLLM gaps are scheduled by
`python -m experiments.local_campaign.vllm_stability_phase6`. The controller
accepts the exact historical completion and current project-revision receipt,
then creates three complete first-measured image/GPTGeoChat conditions plus the
content-bound unfinished LLaVA text units. Its current inventory is seven units
and 7,199 selected rows. It excludes completed Qwen3-VL text, completed
Crescendo and the 1,039-row completed LLaVA AirBench prefix. This controller is
a campaign-specific executable, not a general Runner phase abstraction. Its
required `--tmux-session` and optional `--tmux-socket` bind the controller to
the existing Jobs lifecycle record; terminal target-attempt and successful-
generation counts are published from the completed unit inventory.

If that retained Runner 2.25 controller terminalizes after the observed
GPTGeoChat prompt-length rejection, run
`python -m experiments.local_campaign.vllm_input_recovery_phase6`. It validates
the exact 375-row durable prefix, applies one content-bound completed-prefix
selector, and runs only the 1,645 never-completed GPTGeoChat rows under Runner
2.26. The unchanged 12,288-token route configuration is retained. Any later
context-limit rejection is a typed input-compatibility missing response; the
375-row Runner 2.25 prefix and Runner 2.26 suffix are never pooled.

The retained suffix contains exactly 230 typed context-limit outcomes with
rendered prompt lengths from 12,290 through 16,705 tokens. Do not count them as
successful generations and do not replay the other 1,790 selected rows. Run
`python -m experiments.local_campaign.vllm_context_recovery_phase6` with the
exact input-recovery completion and SHA-256, current project-revision receipt,
fresh control root, scope, work root, project root and project virtual-
environment interpreter. The controller verifies every retained outcome as
`LocalTargetInputError/context_limit_exceeded`, creates a content-bound
completed-ID selector that leaves only those 230 IDs, removes Qwen's explicit
12,288-token `max_model_len` and 4,096-token `max_tokens`, and therefore uses
the pinned runtime's native context and maximum available output. One local
answer retry remains. It derives a fresh attestation, canary,
projection and acquisition binding before measured calls. Treat the result as
a separate context-condition stratum; join disjoint IDs for population
coverage, never pool the old and new condition rates silently.

An exact old-Runner current-Ollama recovery can be terminal yet make no progress
when its retained result root has an open circuit. Do not repeat that argv loop
or clear the historical circuit in place. Run
`python -m experiments.local_campaign.current_ollama_stability_phase6` with the
exact Gate 5 amendment, base completion, failed recovery completion and current
project-revision receipt. It validates all three historical inputs and creates
14 fresh per-corpus Runner 2.26 units for exactly 1,684 missing rows. The three
partial corpora use content-bound completed-prefix selectors; fully completed
cells are not called again. The new controller publishes its named tmux
lifecycle to Jobs and retains the old and new output policies as non-poolable
strata.

If that fresh controller later terminalizes only because recovered-answer
stability fields differ between an otherwise complete final judgment and its
persisted stage trail, do not rerun its target calls. Use
`python -m experiments.local_campaign.current_ollama_stability_continuation_phase6`
with the exact failed completion and digest. The controller binds the real
terminal logs, inherits already complete units, uses the narrow
`finalize_recovered_trails` path for fully executed affected units with zero
target and judge calls, and launches only units that never entered measured
Runner execution. A fresh image identity probe uses deterministic seeds 0
through 4 and retains every failed probe; it does not weaken the resulting
attestation or retry an unchanged measured input. Any unrelated terminal cause
is rejected rather than treated as reusable evidence.

If that continuation terminal retains only the historical zero-record canary
newline rejection, run
`python -m experiments.local_campaign.current_ollama_stability_canary_recovery_phase6`
with its exact completion and digest. The recovery inherits every completed
unit and revalidates each existing canary into a new summary without repeating
the canary target call. It derives the fresh revision-bound identity
attestation, then projects and executes only populations that never entered
measured Runner. Any other failure cause, prior measured state, or changed
canary artifact is rejected.

The retained current-Ollama cohort used limit 50 while comparable vLLM model
lanes used limit 100. Do not treat those populations as quantity-matched. After
the validated stability completion closes the holes within the old prefix,
run the population-alignment controller. It uses the same seed-0 nested sampler,
proves the retained limit-50 IDs are an exact subset of the limit-100
selection, and executes only the content-bound set difference. The sampler's
cluster order is nested, while emitted rows return to source order, so the
retained datapoint list is not assumed to be a contiguous prefix. Across the 12 comparable
Ollama lanes this adds 11,600 intended rows: 1,909 static-text rows per model,
807 static-image rows per vision model, 50 R-Judge rows per model and 1,075
GPTGeoChat rows per vision model. Its no-call projections and canaries must all
pass before the first extension target call. The old prefix and new extension
remain separate Runner strata; completed prefix rows are never called again.

Static alignment units derive and acquire their exact Hub plan. R-Judge and
GPTGeoChat units with an Ollama target and already-local source data pass no
model-acquisition arguments; do not manufacture an empty plan. The retained base
completion is `complete_with_failures`, and its first recovery was interrupted
after DeepSeek started but before the other six units began. Do not rerun that
seven-unit command. If the six-unit failed-output recovery has the retained
five-complete/DeepSeek-pre-execution failure partition, do not rerun its 2,139
completed rows. Run
`python -m experiments.local_campaign.failed_output_recovery_continuation_phase6`
in a named tmux session with the exact prior completion and SHA-256 plus the
same bound source inputs. It reuses the exact 1,674-row selector and runs only
DeepSeek-R1 with `think=true`. The retained bounded ten-input, one-attempt,
no-judge calibration produced ten visible final answers at `num_predict=2048`,
all with normal stop reasons and 719-1,335 completion tokens; the stopped
512-token condition remains diagnostic. The
continuation's combined `/3` completion preserves the prior five results and
separates project-revision and generation-condition strata. Its filtered
execution keeps DeepSeek's original physical unit 05; do not renumber the
one-unit filtered list
to 01. Use that combined
completion as the failed-output recovery input below.

After the combined `failed_output_recovery_phase6` completion is terminal, run
`python -m experiments.local_campaign.current_ollama_population_alignment_recovery_phase6`
in a named tmux session with the exact base completion and SHA-256, the exact
failed-output recovery completion and SHA-256, current project-revision receipt
and SHA-256, fresh control root, scope, work root, project root and project
virtual-environment interpreter. The controller requires these additional flags:

```text
--failed-output-recovery-completion ABSOLUTE_COMPLETION_JSON
--failed-output-recovery-completion-sha256 LOWERCASE_SHA256
```

It validates that DeepSeek's 1,909-row extension is already reconciled by 235
retained usable rows plus 1,674 recovery rows, then schedules only four 50-row
R-Judge units and two 1,075-row GPTGeoChat units. The exact continuation count is
2,350 rows. It rejects DeepSeek, any base-complete unit, a changed count, a Hub
plan on a local-only classification lane, or an implicit Ollama thinking policy.
Give this continuation completion to Phase 7. Population coverage may be joined,
but rates remain separated by Runner, revision and output-policy stratum.

Phase 7 requires that current-Ollama stability completion, the exact terminal
seven-unit vLLM stability completion, its one-unit GPTGeoChat input recovery,
and the exact 230-row GPTGeoChat larger-context recovery.
It also requires the terminal six failed-output recovery units through
`--phase6-failed-output-recovery-completion`.
Its current-Ollama population-alignment input is the six-unit continuation
completion above, not the interrupted seven-unit recovery root. Eleven logical
alignment conditions have one terminal metric root. DeepSeek is complete across
two disjoint Runner strata and is retained for population/model-stability
accounting without a pooled security rate.
The six completed Runner 2.25 units, one Runner 2.26 suffix and its disjoint
larger-context recovery are separate metric strata; the failed 375-row prefix
remains lifecycle evidence.
Pass the terminal controller through `--phase6-vllm-stability-completion` and
the create-only suffix completion through
`--phase6-vllm-input-recovery-completion`; the validator requires the latter to
bind the former byte-for-byte.
Pass the terminal larger-context Qwen correction separately through
`--phase6-vllm-context-recovery-completion`; it is not pooled silently with the
earlier 12,288-token condition.
Its plan-owned terminal inventory has 116 logical rows after population
alignment and failed-output recovery: 46 canonical, four output-policy
amendment, three follow-on, 14
historical current-Ollama, 14 current-Ollama stability, 12 current-Ollama
population-alignment, six failed-output recovery, seven vLLM stability, one
vLLM context-recovery and nine native. The analysis
self-test, Phase 8 frozen replay and Stats adapter
all reject an omitted cohort, a changed terminal state or any cross-policy
pooling. These counts describe this local campaign only; they are not generic
Runner phases or product defaults.

Repinning may archive the older project-revision receipt named by the retained
current-Ollama Gate 5 artifact. Its campaign validator accepts only the exact
same filename under the fixed sibling `project-revision/superseded/` directory
when the original locator is absent, and verifies the descriptor byte count and
digest before use. It retains the original locator for historical argv
comparison and never substitutes the current receipt.

A targeted amendment must re-attest and canary the four affected GraySwan lane
identities under the current Runner before measured execution. Those identities
use the limit-100, sample-seed-0 selections and caps from their matching
LLaVA-base rows. The older GraySwan `-full` terminal names remain only in
immutable historical provenance.

A separate additive Ollama amendment binds the acquired exact digests for
`gemma4:12b-it-q4_K_M`, `ministral-3:14b-instruct-2512-q4_K_M`,
`deepseek-r1:32b-qwen-distill-q4_K_M`, and `gpt-oss:20b`. The first three are
explicitly Q4_K_M; GPT-OSS retains its native MXFP4
representation. All four receive bounded text and R-Judge projections and
canaries. Gemma 4 and Ministral 3 also
receive physical-image and GPTGeoChat projections and canaries. The DeepSeek and
GPT-OSS GPTGeoChat pairs are typed unavailable because those exact models are
text-only. The retained first cohort is the immutable limit-50 prefix. The
population-alignment amendment separately projects the same seed-0 selections
at limit 100 and runs only the content-bound non-overlapping suffix. It derives
its exact inventory counts before approval and does not rewrite the historical
46-row profile. Malformed protocol, transport,
identity, provenance, residency, timeout, and backend failures remain hard
failures.
Acquire that exact multi-model Ollama roster in a named tmux session with
`python -m experiments.local_campaign.ollama_acquire --out-dir ABSOLUTE_DIR
MODEL...`. Network and DNS interruptions produce bounded retry events rather
than terminating the controller. A connected pull stream whose status and
completed-byte count remain unchanged for 15 minutes is also closed and
retried. Retry delays grow from 30 to at most 300 seconds under a seven-day
deadline, and Ollama reuses its retained partial blobs. If the Python process or
host itself stops, rerun the identical command with `--resume`, the same
resolved output directory and the same model order.
Completed load smokes are not repeated, while a changed roster or a terminal
output root is refused.
If the additive Ollama Phase 5 controller ends with a mixed terminal inventory,
do not rerun its successful lanes. Launch the active controller with the exact
canonical failed root:

```bash
export URA_PHASE5_OLLAMA_RECOVERY_SOURCE_ROOT="$URA_WORK/runs/engineering/phase5-ollama-<failed-tag>"
bash ~/.ura-controller-active/phase5_ollama_workflow.sh
```

The recovery source must carry `.exit=1`, canonical
`ura-engineering-campaign/1` metadata and an older exact release commit.
Recovery revalidates every reused artifact with the current validators and
executes only failed or blocked units when every exact per-model local config is
byte-identical. If the context or output cap changed, the old artifacts remain
diagnostics and the controller creates a fresh projected cohort. Its
`evidence-provenance.tsv` has one row
for every Gate 5 disposition and separates `execution_commit`,
`validation_commit`, `evidence_mode` and source control root. Amendment schema
`ura-current-ollama-gate5-amendment/2` rejects missing, duplicate or drifted
provenance and therefore cannot present a mixed cohort as one current execution.
When every unit completed and only aggregate validation failed, recovery
revalidates the exact inventory and performs zero additional model calls.
The tracked, opt-in `launch_phase6_recovery_and_seven.sh` serializes the exact
core recovery and seven-row producers in one named tmux session. It is not part
of `launch_chain`, does not rerun successful lanes, and does not raise caps. Its
two content-bound input-manifest schemas and fresh-tag binding procedure are
specified in `experiments/local_campaign/README.md`.
Phase 7's authoritative lifecycle registry covers complete,
partial, failed-after-request, and genuine pre-Runner-no-request states. Each
lane binds its controller failure, optional exact measured argv, and retained
grid, request-envelope, eligibility, and error artifacts. `level1_evidence`
receives all retained Runner/request artifacts it can represent. A setup error
or 24-hour lane timeout that occurs before Runner can publish a lifecycle writes
one create-only `ura-phase6-pre-runner-failure/1` marker under the exact planned
Runner root. Core uses `runs/thesis/runner/<lane>`; retryable extended attempts
use `runs/thesis/runner/<lane>/<phase6-extended-control>` so retained job output
is never deleted or silently reused. The marker is explicitly non-Runner and
non-empirical: it satisfies the Gate 6 inventory requirement but is never
fabricated as Level-1 metric input. Phase 7 rejects a missing lane root or an
untyped controller-log explanation. Suite metrics and Level 2 use a separate
success-only Runner view.

Gate 5 records `measured_lane_wall_time_seconds=86400` in its approved policy
and `RUNNOTE.md`, and every current bounded measured request carries
`--deadline-seconds 86400`. The first is a 24-hour process wall-time ceiling;
the second is Runner's call-start window. Runner refuses to start a later call
after its deadline but does not interrupt an in-flight call. Core and extended
controllers can terminate and reap a lane process group at the wall-time
ceiling, record the typed pre-Runner marker when Runner has no lifecycle output,
and continue to the next declared lane without raising either cap. Other
positive values remain a generic configurable capability for a separately
projected and approved cohort.

The four top-level Phase 5 through Phase 7 controllers publish
`ura-engineering-campaign/1` markers and ordered task events from their own
named tmux sessions. Each marker binds its exact socket/session; a missing
session is rendered `unknown`, a valid exact session observed absent is
`orphaned`, and an unavailable probe is `unknown`; none remains an unverified
`running` claim. A currently observed-live controller remains visible
in Jobs even when its start time is older than the selected history interval;
terminal history still obeys that interval. The unwindowed live reconciliation
runs before the 20-row recent-history cap, so more than 20 newer engineering
directories cannot hide an older exact-session controller that is still live.
The authoritative `.exit` is published before the best-effort terminal display
event. Therefore a display-write failure may under-claim the terminal but cannot
publish a false success. These operational records stay outside `runs/thesis`.

Each Phase 6 measured Runner child separately creates one
`ura-external-measured-job/2` registration immediately before `run_matrix` and
one create-only terminal record after it returns. The start binds the exact
sanitized argv, one canonical Runner output root, the project commit, framework
lock, generic admission digest and the exact owning tmux socket/session for that
invocation. A sequential controller may name its own session while it
synchronously owns the child; a separately launched child names its
child-specific session. Jobs and Stats can then resolve
the child and validate only its explicitly owned artifact root. Rig Web does not
insert the child into sqlite, own its process or offer Stop; the registration is
operational visibility, not evidence, and stays explicitly external operational
and non-thesis after exit zero. Completion-bound usage may be displayed. The
Phase 7 watcher runs a final `publish-stats` task after terminal analysis
validation. The local campaign adapter validates the sealed watcher,
controller, input, inventory, and report chain before it creates the generic
`external-analysis-jobs` registration. A validation or publication failure is
a failed watcher task, not a published success. Rig Web does not contain or
interpret the campaign's phase or gate schemas; no registration grants report
or metric authority. A pre-automatic controller generation can use the manual
adapter command in `experiments/local_campaign/README.md` when no registration
exists. The measured-job registration field and CLI flag are
named `admission_sha256` and `--admission-sha256`; this local campaign supplies
the approved Gate 5 manifest digest as that value.

If Phase 6 ran under a pre-v2 deployment, repin first and then migrate its
immutable operational rows without editing or deleting them:

```bash
python -m experiments.local_campaign.migrate_external_measured \
  --results-root "$URA_WORK/runs"
```

The migration validates the complete v1 batch and every existing destination
before writing. It is create-only, resumable, refuses any differing v2 row
without changing it, and preserves all v1 bytes.

Start publication is entered only after signal cleanup owns the prospective
external id, terminal log, socket and session. Both core and extended terminal
publication have a 30-second bound and terminate/reap a stuck publisher. Thus a
signal cannot strand a created row without a terminal attempt, a failed terminal
write cannot borrow the live parent session, and the original Runner return code
remains authoritative when Runner and terminal publication both fail.

## 3. Acquire all twenty-five converter sources

*Console equivalent: the section 3.2 and 3.4 export commands are also
launchable as the `export_jalmbench`, `export_vlsbench` and
`export_aggregators` form(s) in the rig console (section 18); identical
argument vectors, gates and artifacts.*

*Scripted equivalent: `distro/install.sh` automates the acquisition and
binding parts of sections 3-4 on a fresh rig: the same pinned `REF_*` snapshots
and separately distributed archives (3.1-3.2), the JALMBench/VLSBench exports
(3.2), the aggregator corpora (3.4), the section 4 `URA_*_PATH` locators plus
`HF_HOME` and `URA_MEDIA_ROOTS` written into `~/.ura_campaign_env` together with
`URA_WORK`, `URA_CORPORA`, `URA_REPO` and `URA_PY`, the six aggregator arms
registered in `experiments/source-instances.json`, the user-local ollama
runtime, BIPIA's fully hashed isolated support venv, the isolated framework
runtimes, and the console launch. It removes legacy duplicate PyRIT, Spikee,
`datasets`, and `jsonlines` top-level installs from the main URA venv, then
fails if any other lock-derived framework root remains in a reused main venv;
it does not prune shared transitive dependencies, and the dedicated
environments remain installed. Each of the 16 locked framework rows runs as a
separate sequential `--only` resume/verify named session and a failure does not
suppress later rows. The console likewise persists under tmux or, when
unavailable, screen. Secret files are sourced only within HF-backed
download/export subprocesses and the console launcher, never for unrelated
installer phases.
`distro/install.sh all` is the one-command path; the per-phase commands below
remain the reference for what it does and for repairing a single source. It
does not perform the rest of sections 2-4: it roots `URA_WORK` at
`/data/ura-work` (the rig's large storage) rather than `$HOME/ura-work`; it
does not check out `REF_URA` or create/validate the section 2 project-revision
receipt (`distro/repin.sh <commit>` deploys one tracked commit and does that);
it seeds `experiments/source-instances.json` from the full example only when
that file is absent and otherwise adds only missing aggregator entries. It
never rewrites an existing operator-reviewed entry because the source receipt
binds its converter, path, label, and split; it does not copy the exporter
summaries into
`runs/thesis/source-export-summaries/` or export
`URA_JALMBENCH_EXPORT_SUMMARY_PATH`/`URA_VLSBENCH_EXPORT_SUMMARY_PATH`; and it
binds GPTGeoChat at `$URA_CORPORA/GPTGeoChat/gptgeochat/human/test` (its
archive phase normalizes `human.zip` to that layout) where the manual path
below uses `$URA_CORPORA/GPTGeoChat/human/test` - either split root is valid
as long as it contains sibling `annotations/` and `images/`. The 4.1 bounded
observation, receipt authoring and validation remain operator steps in every
case.*

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
place `images/` beside `siuo_gen.json` (the free-form generation release; the
`siuo_mcqa.json` multiple-choice track is not convertible and is rejected).
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

The twenty-five converter names and the expected operator locators are:

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
| `siuo` | `sinwang20/SIUO` + image ZIP | `data/siuo_gen.json` beside `images/` (mcqa track not convertible) | common harmful image composition |
| `advbench` | `llm-attacks/llm-attacks` | `data/advbench/harmful_behaviors.csv` | common harmful text |
| `jailbreakbench` | `JailbreakBench/JBB-Behaviors` | harmful and benign CSVs as separate arms | common harmful and benign text |
| `figstep` | `CryptoAILab/FigStep` | `data/question/safebench.csv`; images in `data/images/SafeBench/` | common harmful image |
| `cyberseceval` | `meta-llama/PurpleLlama` | one supported prompt-suite JSON/JSONL | MITRE/interpreter common; prompt injection pending scorer |
| `injecagent` | `uiuc-kang-lab/InjecAgent` | one `data/test_cases_{dh,ds}_{base,enhanced}.json` | conversion only; tool-call scorer absent |
| `mllmguard` | gated `Carol0110/MLLMGuard` | one per-dimension table beside `imgs/` | privacy/bias/toxicity/legality common; hallucination/position-swapping/noise-injection pending truthfulness scorers |
| `jalmbench` | `AnonymousUser000/JALMBench` | exported `jalmbench.jsonl` | common harmful text+audio |
| `videosafetybench` | `BAAI/Video-SafetyBench` | benign or harmful metadata JSON/JSONL beside videos | common harmful text+video |
| `saladbench` | `OpenSafetyLab/Salad-Data` (section 3.4 exporter) | exported `base_set` (or `attack_enhanced_set`) JSON/JSONL | common harmful text; MD-Judge source-native scorer not run |
| `airbench` | `stanford-crfm/air-bench-2024` (section 3.4 exporter) | exported `air_bench_default.json` | common harmful text; graded GPT-4o rubric not run |
| `xstest` | `paul-rottger/xstest` CSV (section 3.4 exporter) | `xstest_prompts.csv` (JSON/JSONL also accepted) | common text: 250 safe prompts are the benign over-refusal population, 200 unsafe contrast prompts are harmful |
| `simplesafetytests` | `Bertievidgen/SimpleSafetyTests` (section 3.4 exporter) | exported `simplesafetytests.json` | common harmful text |
| `decodingtrust` | gated `AI-Secure/DecodingTrust` stereotype config (section 3.4 exporter) | exported `stereotype.json`; other perspectives are rejected | common harmful text (bias endorsement); agreement index not run |
| `holisafe` | gated `etri-vilab/holisafe-bench` (section 3.4 exporter) | `holisafe_bench.json` beside `images/` | common harmful image composition; the all-safe `SSS` combination is a benign-refusal population scored response-only, while the unsafe combinations bind a label-derived judge reference |

Do not guess file names after downloading. Inspect the acquired tree, select the
official table matching the converter contract above, and run the preflight. A
missing or structurally different release is an explicit blocked source, not a
reason to edit the data until it passes.

### 3.4 Aggregator corpora

The six aggregator arms (`saladbench_base`, `airbench_full`, `xstest_full`,
`simplesafetytests_full`, `decodingtrust_stereotype`, `holisafe_full`) are
acquired through the bounded exporter bridge rather than a Git clone. It reads
each source from its authoritative host (the Hugging Face datasets-server
parquet/rows API for SALAD-Bench, AIR-Bench 2024, SimpleSafetyTests and
DecodingTrust; the upstream GitHub CSV for XSTest; an `hf download` of the
gated HoliSafe release) and writes exactly the file each converter reads under
`$URA_CORPORA/<Source>/`. DecodingTrust and HoliSafe are gated: export
`HF_TOKEN` from the secret manager after accepting each dataset's terms and
record that decision in the source receipt. The bridge contacts no provider and
scores nothing. It is the same per-source command that `distro/install.sh
aggregators` runs, and it is also launchable as the `export_aggregators` form
in the rig console (section 18) with the identical argument vector (the console
forwards its process-held `HF_TOKEN` to that child, so the gated sources work
from the form as well):

```bash
python -m experiments.export_aggregators --source all --out-root "$URA_CORPORA"
# or one source at a time, for example:
python -m experiments.export_aggregators --source holisafe --out-root "$URA_CORPORA"
```

The printed target paths are the exact section 4 locators:
`$URA_CORPORA/SALAD-Data/base_set.json`,
`$URA_CORPORA/AIR-Bench-2024/air_bench_default.json`,
`$URA_CORPORA/XSTest/xstest_prompts.csv`,
`$URA_CORPORA/SimpleSafetyTests/simplesafetytests.json`,
`$URA_CORPORA/DecodingTrust/stereotype.json`, and
`$URA_CORPORA/HoliSafe/holisafe_bench.json` beside its `images/` directory. The
bridge pins no upstream revision: record the acquisition date and the exported
file SHA-256 in the source receipt like every other declared source file.

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
export URA_AIRBENCH_PATH="$URA_CORPORA/AIR-Bench-2024/air_bench_default.json"
export URA_BIPIA_TEST_EMAIL_PATH='<official-BIPIA-email-test-jsonl>'
export URA_BIPIA_TEST_QA_PATH='<official-BIPIA-qa-test-jsonl>'
export URA_BIPIA_TEST_ABSTRACT_PATH='<official-BIPIA-abstract-test-jsonl>'
export URA_BIPIA_TEST_TABLE_PATH='<official-BIPIA-table-test-jsonl>'
export URA_BIPIA_TEST_CODE_PATH='<official-BIPIA-code-test-jsonl>'
export URA_CYBERSECEVAL_MITRE_PATH='<PurpleLlama-mitre-json>'
export URA_CYBERSECEVAL_INTERPRETER_PATH='<PurpleLlama-interpreter-json>'
export URA_CYBERSECEVAL_INSECURE_CODING_PATH='<PurpleLlama-insecure-coding-json>'
export URA_CYBERSECEVAL_PROMPT_INJECTION_PATH='<PurpleLlama-prompt-injection-json>'
export URA_DECODINGTRUST_STEREOTYPE_PATH="$URA_CORPORA/DecodingTrust/stereotype.json"
export URA_FIGSTEP_FULL_PATH="$URA_CORPORA/FigStep/data/question/safebench.csv"
export URA_GPTGEOCHAT_RELEASE_PATH="$URA_CORPORA/GPTGeoChat/human/test"  # distro/install.sh binds .../GPTGeoChat/gptgeochat/human/test
export URA_HARMBENCH_TEXT_PATH="$URA_CORPORA/HarmBench/data/behavior_datasets/harmbench_behaviors_text_all.csv"
export URA_HARMBENCH_MULTIMODAL_PATH='<official-HarmBench-multimodal-behavior-csv>'
export URA_HOLISAFE_PATH="$URA_CORPORA/HoliSafe/holisafe_bench.json"
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
export URA_SALADBENCH_PATH="$URA_CORPORA/SALAD-Data/base_set.json"
export URA_SIMPLESAFETYTESTS_PATH="$URA_CORPORA/SimpleSafetyTests/simplesafetytests.json"
export URA_SIUO_RELEASE_PATH="$URA_CORPORA/SIUO/data/siuo_gen.json"
export URA_STRONGREJECT_OFFICIAL_PATH="$URA_CORPORA/strongreject/strongreject_dataset/strongreject_dataset.csv"
export URA_VIDEOSAFETYBENCH_BENIGN_QUERY_PATH="$URA_CORPORA/Video-SafetyBench/benign_data.json"
export URA_VIDEOSAFETYBENCH_HARMFUL_QUERY_PATH="$URA_CORPORA/Video-SafetyBench/harmful_data.json"
export URA_VLSBENCH_RELEASE_PATH="$URA_CORPORA/VLSBench-export/vlsbench.jsonl"
export URA_VLSBENCH_EXPORT_SUMMARY_PATH="runs/thesis/source-export-summaries/vlsbench-export-summary.json"
export URA_XSTEST_PATH="$URA_CORPORA/XSTest/xstest_prompts.csv"
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
export URA_MEDIA_ROOTS="$URA_CORPORA/MM-SafetyBench/data/imgs:$URA_CORPORA/MOSSBench:$URA_CORPORA/JailBreakV-28K:$URA_CORPORA/GPTGeoChat:$URA_CORPORA/HarmBench:$URA_CORPORA/VLSBench-export:$URA_CORPORA/SIUO/data:$URA_CORPORA/FigStep/data:$URA_CORPORA/MLLMGuard:$URA_CORPORA/JALMBench-export:$URA_CORPORA/Video-SafetyBench:$URA_CORPORA/HoliSafe"
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
`not_selected` operator decisions; the full 45-arm disposition table instead
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

Start from the checked-in dated registry
(`experiments/rig/api-targets.example.json`, described key by key in
`experiments/rig/README.md`). It ships twenty rows: the two fixed focal
conditions above as modalities-only rows (their sampling and reasoning
controls live in the spec string, not in the JSON); the seven
documentation-verified conditions of the 2026-08-11 snapshot (Claude Opus 5,
Claude Sonnet 5, the reusable Haiku 4.5 judge condition, Gemini 3.6 Flash,
DeepSeek V4 Pro, Kimi K3, Qwen 3.7 Max); and eleven candidate rows whose exact
account route was not independently verified for that snapshot
(`openai:gpt-5.6-terra`, `openai:gpt-5.6-luna`, `openai:gpt-5.5`,
`openai:o3-mini`, `google:gemini-3.6-pro`, `google:gemini-3.6-flash-lite`,
`google:gemini-2.5-pro`, `google:gemini-2.5-flash`,
`google:gemini-2.5-flash-lite`, `kimi:kimi-k2`, `glm:glm-5.2`). A row is an
execution condition plus a pricing key; it does not establish that a route is
visible to this rig or that a candidate slug still resolves.

```bash
cp experiments/rig/api-targets.example.json experiments/api-targets.json
```

Every row, verified or candidate, becomes a usable lane only through one path:
operator attestation of account visibility plus the bounded section 8 probe
returning the expected served identity for every claimed modality; the
document itself cannot see any account. A route that is not in the file
(Doubao, a regional or preview endpoint, an account-private deployment) is an
operator-attested condition: add its exact spec to the local JSON with explicit
`modalities`, `max_tokens`, and `temperature` only after reviewing the account
documentation, then retain it only if those same checks pass. Do not silently
substitute another model.

Generic Claude Opus 5 and Sonnet 5 conditions require all three fields shown:
`temperature: null`, `thinking: "adaptive"`, and an explicit effort. The Haiku
4.5 row is the reusable judge condition and does not use that adaptive-thinking
contract.

Inject only the credentials for selected providers from a secret manager:

```bash
# ANTHROPIC_API_KEY, OPENAI_API_KEY, GEMINI_API_KEY or GOOGLE_API_KEY,
# DEEPSEEK_API_KEY, MOONSHOT_API_KEY, DASHSCOPE_API_KEY, ZHIPU_API_KEY,
# ARK_API_KEY (Doubao; only when an operator-attested doubao: row is added)
```

If a compatible provider requires a different regional HTTPS base URL, use its
documented `URA_<PROVIDER>_BASE_URL` environment variable
(`URA_DEEPSEEK_BASE_URL`, `URA_KIMI_BASE_URL`, `URA_QWEN_BASE_URL`,
`URA_GLM_BASE_URL`, `URA_DOUBAO_BASE_URL`) or the credential-free `base_url`
field accepted for compatible providers. Never embed credentials in a URL.
Record the exact non-secret route.

The generic LLM judge is loaded through the same `--api-config` path as generic
targets. Its exact `JUDGE` key must therefore remain in the JSON even when it is
not itself a model-under-test.

Rig Web binds reviewed API, local, source, source-conformance, and
prepared-attacker selections in one internal
`ura-builder-selected-execution-config/1` digest bundle. Its API component
remains `ura-builder-selected-api-config/1` and contains the complete registry
digest, canonical provider/model,
selected-entry digest, portable controls, and
`endpoint_identity=https-base-url-sha256:<64 lowercase hex>` for every target
and hosted judge. It never puts a raw URL or filesystem locator in the bundle
or durable job state. The exact selection is held behind a 30-minute,
purpose-bound, one-shot confirmation ticket. Immediately before launch, only
selected bytes are materialized as private digest-bound configs/evidence;
Runner reads each once, verifies its paired API/local/source/attacker SHA-256,
and unlinks it. Changing a source from real to synthetic or swapping prepared
attacker/conformance bytes after review burns/rejects the ticket. These are
operational TOCTOU/privacy controls, not live attestation or scientific
evidence.

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

Before any live hosted-judge command, record the corpus handling decision and
the selected judge provider's current retention, training/data-use, regional
routing, and abuse-monitoring terms in the dated run note, and obtain the
required institutional/operator approval. Only after that review may a live
`run_matrix` command include the explicit
`--ack-hosted-judge-data-transfer` flag shown below. The acknowledgement records
that target output and source/reference grading
context will leave the rig; it does not prove approval or provider deletion.
Never pass it to `rig_check`, `--dry-run`, rules-only judging, or a local LLM
judge because those paths perform no hosted-judge data transfer.
Before configuration loading, `ura-request-envelope/6` copies this decision to
the required Boolean
`request.hosted_judge_data_transfer_acknowledged`; a no-transfer path records
false rather than omitting the field.

Remove a target from a lane if its probe did not produce a complete, correctly
resolved response. A local preflight cannot establish remote entitlement.

### 5.1 Funded campaign roster (operator decision, 13 August 2026)

The first campaign's roster is fixed by recorded operator decision (thesis
ledger Section 11.22); this subsection mirrors it so the rig operator does
not have to consult the thesis repository mid-campaign. It narrows the
candidate lanes above; it never adds a route the section 8 gates have not
confirmed.

- Focal pair: the Fable and Sol conditions above; both are measured targets.
- Funded-campaign judge default: `anthropic:claude-haiku-4-5-20251001`. This is
  the recorded condition for that campaign, not a UI restriction: the shared
  picker can bind any admitted hosted or local model as the LLM judge. The
  selected judge is excluded as a target (self-judgment bias).
- Anthropic breadth: `anthropic:claude-sonnet-5`; add `anthropic:claude-opus-5`
  only if the prepaid budget, conservative call projection, and the canary's
  exact observed token-derived spend support the operator decision.
- OpenAI breadth: at most one additional row beyond Sol - a budget cap, not
  an availability doubt. The operator attests GPT-5.6 Terra, GPT-5.6 Luna,
  and GPT-5.5 are visible on the account; their candidate rows already ship
  in the example registry, and the section 8 probe records each exact served
  route id before any of them enters a lane. The prepaid budget,
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

### 5.1a Budget-fitted hosted and Haiku amendment (1 September 2026)

The campaign run after the all-local plan supersedes the broader 13 August
roster for that future execution only. It may consume no more than 50 percent
of each configured provider budget, including Haiku judging charged to
Anthropic. Paid targets and Haiku judging use one application attempt,
`--target-answer-retries 0`, with harness transport retries and provider SDK
retries disabled. The first retained failed hosted-target output or target transport/network
failure opens the global `paid_provider` circuit before another paid call. The
operator must classify and resolve the failure before a fresh bound plan and
explicit circuit reset; there is no automatic paid resumption. Use seed 0
and the normal nested whole-cluster sampler with these per-target limits:
Fable 1, Opus 3, Sonnet 5, Haiku 10, Sol 2, Terra 5, Luna 20, GPT-5.5 1, Kimi
K3 3 and DeepSeek V4-Pro 20. DeepSeek
may run only in the reviewed off-peak price window. Google and other candidate
routes are outside this funded amendment.

Before any paid call, derive each exact no-call population independently and
measure the provider-token canary. Reserve exactly one attempt per target or
judge call. If a
provider would exceed Anthropic USD 50, OpenAI USD 20, Moonshot USD 7.50 or
DeepSeek USD 5, reduce and reseal only the affected prospective limit before
any target output exists. Never increase or outcome-select a limit later.

After local completion, create a content-bound zero-target Haiku selector for
at most 2,000 eligible local outputs and another for at most 2,000 hosted
outputs. The two selectors use deterministic balanced round-robin sampling
across target, modality, source arm, attacker, risk, expected behavior and
output-policy/revision strata. They preserve original judgments and exclude
missing responses plus source-authoritative R-Judge/GPTGeoChat rows from judge
calls. Haiku target rows may be judged by Haiku under the operator's explicit
decision, but must be labelled same-model and non-independent. Under the
central assumption the combined 4,000 calls use 8.0 million input and 1.024
million output tokens and cost USD 13.12 standard or USD 6.56 Batch.

Do not emulate this re-adjudication with `run_matrix`: that would risk target
regeneration. Use the dedicated immutable zero-target path after it has focused
regression, mutation and rig validation. Its analysis publishes separate API-
selected, local-selected and matched-input-intersection tables and diagrams.
These are selected-cohort results, never full-corpus estimates.

### 5.2 Bounded lane sampling (prospective amendment, 24 August 2026)

The 13 August design bounded paid hosted routes but assumed that every local
lane would exhaust its converted corpus. Full-universe projections later made
the converted-row fanout and repeated inference burden explicit. Before any
Phase 6 measured call or benchmark outcome, the local campaign therefore fixed
two bounded measured tiers:

```bash
export URA_LOCAL_CORE_CLUSTER_LIMIT=100
export URA_LOCAL_EXTENDED_CLUSTER_LIMIT=50
export URA_LOCAL_SAMPLE_SEED=0
```

- Core static text/image, R-Judge, GPTGeoChat, Crescendo and an eligible local
  defense use `--limit 100 --sample-seed 0 --seeds 0`.
- Runner-safe bridge and Ollama lanes use
  `--limit 50 --sample-seed 0 --seeds 0`. Keep each attacker's declared
  query/turn semantics; do not turn a four-operation bridge into a different
  one-operation attack merely to shorten the run.
- Current hosted API lanes remain separately bounded by prepaid budgets and a
  positive pre-registered limit. Audio and video remain hosted-only and retain
  their own prospective limits.
- The framework supports full-set execution for local and hosted targets through
  explicit `--limit 0` in a separately projected and approved full-corpus
  replication. A hosted full cohort must retain attestation and transfer
  acknowledgement where applicable, and its target, judge and HTTP caps must
  cover the complete no-call projection. Current-campaign policy authorizes full
  mode only for all-local replication. It is not the measured bounded cohort and
  cannot reuse its Gate record, caps or output roots. This does not override a
  prepared artifact's narrower source mapping: current IDEATOR v2 admits only
  `advbench:245` through `--limit 1 --sample-seed 105`.

`--limit N` is an equal per-arm cap applied independently to each logical source
arm. Selection is deterministic whole-cluster sampling without replacement and
retains every sibling row. Cluster-key fallback precedence is nonblank
`meta["source_cluster_id"]`, then nonblank `DataPoint.id`, then the converted row
index. Unique cluster keys are inventoried in first source-appearance order.
SHA-256 over the UTF-8 bytes
`ura-corpus-cluster-order-v1\0<logical-arm>\0<sample_seed>` supplies the unsigned
big-endian `scoped_seed` from its first eight bytes. Python's
`random.Random(scoped_seed).shuffle(...)` permutes inventory positions once, the
first N are retained, and all selected sibling rows are restored to source
order. Thus the design is not proportional or risk-stratified. The prefixes are
nested and overlapping, not disjoint partitions: for one unchanged arm,
converted-corpus digest and sample seed, limit 1 is contained in 50, which is
contained in 100. Logical-arm identity contributes to seed derivation and gives
each arm an independently scoped ordering. A source with fewer than N clusters
is complete but precision-limited, and limit 0 returns the exact full arm.
Fanout rows, repeated model conditions and turns do not increase the independent
cluster count.

`run_matrix` and Build also expose two explicit whole-cluster prefix policies:
`seeded_pseudorandom_whole_cluster_prefix_v1` (the unchanged default above) and
`source_order_whole_cluster_prefix_v1` (the first N cluster keys in
source-appearance order). Omit `--sampling-policy` when reproducing an existing
legacy campaign command. Supplying either value records it in request,
acquisition, projection and run identity, so changing it requires a new exact
plan, receipt, projection, caps, output root and analysis stratum. Both policies
retain every sibling row and interpret `--limit 0` as the exact full arm.

The current measured population cohort uses `--sample-seed 0` only.
`--sample-seed 1` is a separately projected future cohort that requires its own
selection-bound projections, acquisition envelopes, Gate 5 caps, output roots
and analysis stratum before any calls. It is never added to the seed-0 cohort in
response to observed throughput or outcomes.

The manifest retains the full-corpus digest, complete cluster inventory, exact
selected cluster identities, converted-row fanout and achieved source-policy
support. Analysis never pools tiers. It reports total selected, completed,
policy-evaluable, decided and abstained clusters, exact risk/policy coverage and
missingness. Core estimates target 100 matched clusters where available;
extended estimates are descriptive and precision-limited. A bounded selection
does not guarantee coverage of every risk stratum inside an arm.

Every changed selection receives a new `rig_check` projection, purpose-bound
acquisition plan/receipt, request envelope and Gate 5 cap. The earlier
full-corpus projections remain capacity records only. Existing exact-revision
limit-1 canaries remain nested diagnostics when all other identities match;
they are not measured evidence. HarmBench capture is selection-bound and must be
regenerated with limit 50. Exact target, local-guard, model-judge, HTTP, time and
storage ceilings are recorded before measurement and are never raised
mid-lane. The selected hosted LLM judge remains metered and runs only in its
separately authorized hosted cohort; the all-local cohort uses local scoring
stages.

## 6. Configure scoring and optional defense guards

The scoring guard parser currently implements the Llama-Guard output shape. Set
an exact accessible model revision and load it before paid calls.

```bash
export SCORE_GUARD='meta-llama/Llama-Guard-3-8B'
export SCORE_GUARD_REV='7327bd9f6efbbe6101dc6cc4736302b3cbb6e425'
export SCORE_GUARD_DEVICE='cuda:1'
```

For the optional text-only defense lane, use a different Llama-Guard-family model
identity and explicit device. Do not use either guard as the model under test or
as the hosted LLM judge.

```bash
export DEFENSE_GUARD='meta-llama/Llama-Guard-3-1B'
export DEFENSE_GUARD_REV='acf7aafa60f0410f8f42b1fa35e077d705892029'
export DEFENSE_GUARD_DEVICE='cuda:1'
```

Do not call `snapshot_download` or let Guardrail/Transformers download these on
first load. The exact selected guards enter the sealed acquisition workflow in
section 6.1 together with every other Hub-backed role.

### 6.1 Sealed Hugging Face model acquisition

This workflow is mandatory for all five Hub-backed roles: vLLM target, local
vLLM LLM judge, scoring Guardrail, defense Guardrail, and NanoGCG surrogate.
Each selection needs a public repository ID plus an immutable 40-64 lowercase
hex commit. A target may not share that identity with its judge, either guard,
or NanoGCG surrogate. An explicit local checkpoint-directory plus full tree
SHA-256, and a sourced precomputed NanoGCG suffix, are the only no-Hub
exceptions.

Rig Web is the recommended controller. Review the exact Builder lane, then use
the visible `Plan & acquire` action. It creates three purpose-bound Jobs:
`acquisition plan / no model call`, `model acquisition`, and finally the exact
offline no-call preflight or measured run. The generic Commands page cannot
launch the acquisition worker. Set `HF_TOKEN` through the write-only Config
entry (presence is shown, never its value or suffix; it remains process-memory
only and is never written to the operator secrets file), or in the console's
secret-manager environment before starting Rig Web. Only the acquisition child
receives it.

For a direct CLI request, keep one exact argument vector in a shell array and
use it for both planning and execution. Purpose is part of that vector and of
the immutable request binding. Include `--preflight-only` only when the later
consumer is that exact preflight. Include `--diagnostic-canary` without
`--preflight-only` when the later consumer is that exact canary. Include neither
flag for a measured run. Plan-only stops before constructors; it does not
change the intended execution purpose. Preflight, canary and measured requests
therefore need separate exact arrays, plans and receipts even when acquisition
finds every model byte already sealed. The template below deliberately uses
placeholders for the content-addressed filenames printed by each preceding
stage; do not choose or edit those values by hand.

```bash
export URA_STATE="$URA_WORK/state"
export URA_MODEL_STORE="$URA_STATE/model-acquisition/store"
export URA_MODEL_PLANS="$URA_STATE/model-acquisition/plans"
export URA_MODEL_RECEIPTS="$URA_STATE/model-acquisition/receipts"
export URA_MODEL_TRANSPORT="$URA_MODEL_STORE/.transport-cache"
mkdir -p "$URA_MODEL_STORE" "$URA_MODEL_PLANS" "$URA_MODEL_RECEIPTS" "$URA_MODEL_TRANSPORT"

# EXACT_LANE_ARGS contains the complete intended run_matrix selection,
# execution-purpose flag, and immutable source/config/project/request inputs.
# Plan-only stops before every attacker, target, judge, guard, surrogate, or
# engine constructor without changing that purpose.
python -m experiments.run_matrix "${EXACT_LANE_ARGS[@]}" \
  --model-acquisition-plan-only \
  --model-acquisition-plan-dir "$URA_MODEL_PLANS" \
  --out "$URA_STATE/model-acquisition/planning-output"

# Plan-only may create the declared --out directory with sealed project,
# source, attestation and request-envelope copies. Check create-only absence
# immediately before the plan call. If the exact measured controller reuses
# that --out value, accept only the directory created by this successful call;
# do not treat controlled plan materialization as a pre-existing measured run.

# Copy plan_id/plan_sha256 and its create-only filename from that output.
export URA_MODEL_PLAN='<absolute acquisition-plan-*.plan.json>'
export URA_MODEL_PLAN_SHA256='<64 lowercase hex printed by plan-only>'

# Only this controller may have HF_TOKEN/network access. Its byte/free-space/
# deadline values are hard admission bounds; choose and record lane-appropriate
# values rather than silently increasing them after failure.
python -m experiments.model_acquire \
  --plan "$URA_MODEL_PLAN" \
  --plan-sha256 "$URA_MODEL_PLAN_SHA256" \
  --store "$URA_MODEL_STORE" \
  --receipts-dir "$URA_MODEL_RECEIPTS" \
  --transport-cache "$URA_MODEL_TRANSPORT" \
  --max-download-bytes 2199023255552 \
  --min-free-bytes 21474836480 \
  --deadline-seconds 86400

# Copy receipt_id/receipt_sha256 and its create-only filename from the
# controller output. The normal process removes Hub tokens and is offline.
export URA_MODEL_RECEIPT='<absolute acquisition-receipt-*.receipt.json>'
export URA_MODEL_RECEIPT_SHA256='<64 lowercase hex printed by acquisition>'
python -m experiments.run_matrix "${EXACT_LANE_ARGS[@]}" \
  --model-acquisition-plan "$URA_MODEL_PLAN" \
  --model-acquisition-plan-sha256 "$URA_MODEL_PLAN_SHA256" \
  --model-acquisition-receipt "$URA_MODEL_RECEIPT" \
  --model-acquisition-receipt-sha256 "$URA_MODEL_RECEIPT_SHA256" \
  --model-acquisition-store "$URA_MODEL_STORE"
```

Each `--model-acquisition-*` flag defaults to the matching environment
variable when the flag is omitted: `URA_MODEL_ACQUISITION_PLAN_DIR`,
`URA_MODEL_ACQUISITION_PLAN`, `URA_MODEL_ACQUISITION_PLAN_SHA256`,
`URA_MODEL_ACQUISITION_RECEIPT`, `URA_MODEL_ACQUISITION_RECEIPT_SHA256`, and
`URA_MODEL_ACQUISITION_STORE`. A lane may export them once instead of
repeating the flags; they are private controller locators like the variables
above and must not be copied into returned logs, reports, or the run note.

The controller revalidates cache hits but reports zero downloaded bytes and no
`model_download` activity for them. Rig Web shows that badge only while an
authenticated worker confirms missing-byte transfer, and clears it on finish,
failure, or cancellation. Normal/preflight construction holds a shared resource
lease across complete pre-load hash, constructor/load, and complete post-load
hash; any drift destroys the object before a model call. Result roots retain
safe, path/token-free canonical plan and receipt copies plus their strict
full-grid descriptor. Shared scientific conditions retain only acquisition for
the judge, guards, defense, and surrogate; each cell additionally retains only
its own local-target seal. Different grid rosters therefore do not fragment the
same hosted condition. Private plan/receipt/store/snapshot locators, activity
secrets, and `HF_TOKEN` remain controller-only and must not be copied into
returned logs or reports.

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

In the Build tab, one large role-aware model-picker modal serves both target and
LLM-judge selection. Choose hosted or local, then use the hosted provider filter
(`All` by default) or the local filtering surface. Target mode binds one or more
hosted targets and at most one local target. Judge mode binds exactly one model,
distinct from every target; a local target and distinct local judge cannot share
one process. Schedule different local target models as separate rig jobs/grids;
each such grid may still include multiple hosted targets. A judge-only warning
marks the highest configured comparable
input/output rate in each currency; it is a cost signal, not a quality claim.
Hosted, Local vLLM, and Local Ollama choices remain separate
groups. Local vLLM choices have four combinative presentation filters: an
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
name. Once `Include unknown fit` is selected, an unknown-size row remains
visible at every maximum-parameter setting. Known parameter counts always obey
the selected maximum. The checkbox controls visibility only and does not make
hardware-auto valid for an unknown fit.

Local Ollama rows do not use those vLLM name, parameter, fit, or precision
controls. Status, Start, Stop, and Pull operate only on the default literal
loopback API. A daemon found there is external and cannot be stopped by Rig Web;
only the dedicated process group started by the current console is owned and
cleaned up. Pull is a typed Jobs entry whose live activity is `model_download`.
The selectable live roster accepts at most 64 installed models under a
five-second aggregate discovery budget, requires exact tag/digest stability
across two `/api/tags` reads, and gets text/image modalities only from explicit
`/api/show` completion/vision capabilities. Missing, malformed, slow, or racing
data produces no fabricated rows. The vLLM supported-model roster is a
capability catalog, not proof that a model was downloaded or selected, so it
does not suppress installed Ollama tags. vLLM availability and selection never
exclude an Ollama tag; exact Ollama tag, digest, capability, and daemon-stability
checks remain authoritative. Each
`ollama:<model-tag>` entry requires the exact lowercase 64-hex digest reported
by `/api/tags` and a unique explicit modality list containing `text` and
optionally `image`. vLLM-only revision, quantization, tensor parallelism, memory
utilization, parameter count, `max_tokens`, `max_model_len`, and unknown-fit
fields are forbidden. Ollama instead accepts `num_ctx` and `num_predict`. A
newly selected config binds `num_ctx="max"`; Runner resolves the exact native
maximum from the pinned model's architecture-specific `context_length` in
`/api/show`, and uses the `num_predict=-1`
maximum-output sentinel. The pulled
artifact fixes precision. Runner
uses the daemon HTTP API through the Python standard library, so no Ollama
Python SDK is required; the daemon and matching pulled tag must exist before a
live run.

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

The disabled LLaVA-v1.6 FP8 profile is evidence from vLLM 0.27.1 loading the
weights and then failing in multimodal encoder profiling when its scaled-matrix
kernel used `.view()` on a non-contiguous tensor. The disabled GraySwan RR
BitsAndBytes profile was rejected because that `LlavaNext` implementation lacks
`packed_modules_mapping`. These are exact architecture/runtime incompatibilities,
not VRAM-fit failures; both occurred before any target inference.

Precedence is per-model `quantization` in `--local-config`, then the command's
`--quantization` override, then hardware auto-selection. A missing
`multi_gpu_compatible` field means supported by assumption and is labelled
`assumed`; set it to `false` for a known single-GPU-only model. When a compatible
model exceeds one usable card, automatic tensor parallelism uses the detected
card count needed for the estimate. The resolved hardware, quantization and
tensor-parallel configuration enter normal local-config, grid and run
provenance.

`max_model_len` is an optional vLLM-only per-model field for engine context and
KV-cache admission. It is separate from `max_tokens`, which remains the maximum
generated response length. Omit `max_model_len` to let the pinned checkpoint
declare its native context. An omitted `max_tokens` lets the pinned runtime
generate until EOS or the remaining context is spent. If `max_model_len` is
present, it must be a non-boolean integer in 1..1,000,000 and an explicit
`max_tokens` must not exceed it; null, strings, floats, and
out-of-range values fail before engine construction. Rig Web preserves the
field when materializing the selected local config. The normalized value enters
the selected-config hash and grid/run provenance, is passed as
`vllm.LLM(max_model_len=...)` before engine/KV admission, and is reported in the
local response metadata. The Build row displays either the explicit context cap
or `native model context`.

For Ollama, `num_ctx` is the request context/KV policy and
`num_predict` is the generated-token policy. Explicit context values must be
`"max"` or positive integers up to 1,000,000; generation accepts the `-1`
maximum-output sentinel or a positive finite cap up to 25,000. Rig Web selects
`num_ctx="max"`, shows `native maximum context`, selects `num_predict=-1`, and
preserves configured overrides in the selected-config hash. Runner resolves
the maximum policy through `/api/show`, passes the exact value to `/api/chat`, and records it in
the effective condition and response provenance. A changed value therefore
requires a new plan, projection, attestation, and canary; it never silently
rewrites an existing cohort.

Before final Phase 7 analysis, derive the exact current-roster truncation set
with `python -m experiments.local_campaign.local_truncation_recovery_phase6`,
passing each retained unit state through repeated `--state` arguments and using
a fresh `--out` file. The inventory is structure-only: it records descriptors,
IDs, counts, corrected configs and completed-ID selectors without retaining
prompt, response or thinking text. Review it before any corrective execution.

Runner 2.26 local adapters construct each vLLM/Ollama `Response` with the same
deterministic dialog-fingerprint placeholder used by hosted adapters: the first
16 lowercase SHA-256 hex characters over ordered rendered roles, content, and
media identities. This only satisfies transport-local response linkage. Runner
replaces it with the canonical Attempt ID and run ID before judgment,
checkpointing, or result persistence; do not analyze the placeholder as an
attempt identity or outcome.

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

Before that target enters any security projection, canary or measured run, run
`python -m experiments.local_model_readiness` against the exact one-model local
config. For a Hub-backed vLLM target, first use
`--model-acquisition-plan-only --model-acquisition-plan-dir`, acquire that exact
plan with section 6.1, and then pass the resulting plan, receipt and managed
store to the readiness command. An Ollama target needs no Hub-acquisition
arguments. The command makes ten deterministic benign question calls and, for
an image-capable target, five deterministic synthetic-image calls. Admission
requires at least five correct text answers and at least two correct image
answers. The other five text responses and three image responses may be
incorrect or empty. Store each passing `ura-local-model-readiness/1`
receipt and its SHA-256 under the operator-bound
`URA_LOCAL_MODEL_READINESS_ROOT`; the local campaign controllers validate the
exact target receipt before security calls. Empty survey observations remain
typed `model_nonresponse` rows. Later campaign statistics likewise retain them
as missing response counts and decision-coverage loss, not decided safety
labels. A failed target remains failed. A
replacement is a newly pinned model condition and repeats acquisition and
readiness rather than inheriting the failed target's artifacts.

Create a separate local config for each selected model because the file keys must
exactly match that command's `--local` value. Replace each revision with the
actual full Hugging Face commit.

Record the exact reviewed revisions before starting vLLM. Do **not** run a
separate `hf download` for these model repositories: put the same revisions in
the selected local configs, include those configs in `EXACT_LANE_ARGS`, and let
section 6.1 derive one complete plan, perform the bounded acquisition, and seal
the resulting bytes before vLLM construction:

```bash
export REF_LOCAL_QWEN3_VL='60595ebc30ec8e3b1d3b9e65d4943ca011c0006a'
export REF_LOCAL_LLAVA_BASE='2424fdd47412fccc66d91719126b420e9fbd7065'
export REF_LOCAL_LLAVA_RR='d11b3d7ae2fb21e984f197a83c15bbb0deb66b7e'
```

Put those same revision strings into the three local JSON files below.

`experiments/local-qwen3-vl.json`:

```json
{
  "vllm:Qwen/Qwen3-VL-8B-Instruct": {
    "revision": "60595ebc30ec8e3b1d3b9e65d4943ca011c0006a",
    "modalities": ["text", "image"],
    "tensor_parallel_size": 1,
    "gpu_memory_utilization": 0.90,
    "max_model_len": 12288,
    "max_tokens": 4096
  }
}
```

Rig-specific boundary: the direct Qwen engine probe at
`gpu_memory_utilization=0.90` measured a maximum admitted context of 13,040
tokens. The tracked example therefore uses the conservative 12,288-token cap
for the ordinary local target. This is local runtime-admission evidence, not an
inference-quality or thesis result, and it must be rechecked for a different
checkpoint, engine version, serving configuration, or hardware profile.

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

Acquire each exact revision through the section 6.1 sealed workflow (plan-only,
then `model_acquire`, then the offline run) before its lane; no separate
`hf download` or shared Hub cache is consulted by the normal process. The
controller imports already-present bytes only from the managed store's own
transport cache (`$URA_MODEL_TRANSPORT`, one direct child of the store on the
same filesystem): a legacy shared `hub/` cache is reused without re-download
only if the operator relocates its contents into that transport cache before
running plan-only and `model_acquire`; otherwise the sealed acquisition
downloads the revisions again. Local text and image runs for each model remain
separate commands so vLLM releases its target weights between processes.

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
  --corpora synth --limit 12 --seeds 0,1 --exclude-tool-conditioned \
  --max-queries 4 --max-turns 4 --out runs/thesis/diagnostics/dry
python -m experiments.figures --synth --out runs/thesis/diagnostics/figure-check
```

`--exclude-tool-conditioned` drops the two tool-conditioned `synth` rows
(`synth-4`, `synth-10`) with a recorded exclusion count so this diagnostic dry
run completes; omitting it fails closed on the tool contract by design, since no
Runner attacker can execute a tool-conditioned row yet.
It is valid only on a standalone `--dry-run`; preflight, acquisition,
attestation, canary, and measured routes reject it so they cannot partially
retain a selected source cluster.

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
persists the exact content-addressed `ura-lane-projection/2`; the second command
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
  --max-total-target-calls 2 \
  --max-total-http-attempts 8 --deadline-seconds 900 \
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
text and text+image receipt records while retaining a four-call ceiling under
the default one-retry answer policy:

```bash
export IMAGE_PROBE_ROOT="runs/thesis/attestation/$TARGET_LABEL/synthetic-text-image"
export IMAGE_RECEIPT="runs/thesis/attestation/receipts/$TARGET_LABEL-synthetic-text-image.json"

python -m experiments.run_matrix \
  --attestation-probe --execution-scope-id "$EXECUTION_SCOPE_ID" \
  --api "$TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora synth --limit 2 --sample-seed 0 --seeds 0 \
  --max-queries 1 --max-turns 1 \
  --max-total-target-calls 4 \
  --max-total-http-attempts 16 --deadline-seconds 900 \
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

Every probe in this section scores through the rules stage only, so its single
cell completes only when the target's reply matches a confident rule template
(a refusal template, the harmful-compliance heuristic on the synthetic harmful
prompts, or a typed provider refusal). A reply the rules cannot classify
confidently fails that cell with `JudgeCascadeDecisionError` (recorded as a
`judge_call` failure that opens the judge circuit in that probe directory), and
the receipt producer then finds no completed cell. This is a scoring
abstention, not a route, transport, or receipt failure: rerun the identical
probe under a new `--out` directory (outputs are create-only; do not reuse or
reset the failed directory), record the failed attempt in the run note, and
keep `--judges rules` - the probe contract is transport-only, and a `mock`
judge is admitted only under `--dry-run`.

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
eligibility/`N/A` ledger and `ura-lane-projection/2` into the requested `--out`
directory, including when a later compatibility gate fails. A successful exact
measured invocation creates and binds its own projection after whole-request
admission and before its first generation call. These artifacts are planning
evidence only and are not live attestations.
`rig_check` and `run_matrix --dry-run` neither require nor accept
`--execution-scope-id` or live-attestation arguments.
They also neither require nor accept
`--ack-hosted-judge-data-transfer`: even when a hosted judge is selected for
projection, the no-call preflight sends it no grading context. Add
`--ack-hosted-judge-data-transfer` only to the corresponding live measured or
diagnostic `run_matrix` invocation.
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
invocation below, never to `rig_check`. When that invocation uses the hosted
`$JUDGE`, also append `--ack-hosted-judge-data-transfer`; omit it for a local
judge or a non-LLM stage. The driver retains content-addressed
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
inventory to one seed, and the deterministic cluster limit to one.

The no-call rehearsal and live canary are separate purpose-bound requests.
Follow section 6.1 once with the rehearsal's exact array containing
`--preflight-only`, and again with the canary's exact array containing
`--diagnostic-canary` and its canary-specific live-attestation arguments. Point
the model-acquisition environment variables at the matching plan and receipt
before each command. Never reuse the rehearsal plan for the canary or append
`--diagnostic-canary` only after plan derivation; exact admission rejects that
purpose mismatch before any model call.

For a target that already passed the applicable text or image readiness gate,
an exact all-abstention canary is retained model-stability diagnostic evidence;
it does not stop the assigned measured population. The validator accepts the
canonical zero-record JSONL writer outputs of either zero bytes or one terminal
newline. It continues to reject malformed files, nonzero unexpected bytes,
binding drift and irreconcilable record or byte counts.

The static full-cascade pattern is:

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
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
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
  --ack-hosted-judge-data-transfer \
  --api "$CANARY_TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" \
  --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$CANARY_ARM" --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
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
--group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version
```

`--group` is written out explicitly but equals the CLI default: the Level-2
export (section 16) requires at least these eight keys and rejects any
narrower grouping, so every preflight and measured lane below passes exactly
this value (or omits `--group` to inherit it).

Use whole source-cluster sampling. The framework supports the complete selected
release for local or hosted targets through explicit `--limit 0` and a separate
complete projection with sufficient admitted caps. Current-campaign policy
admits that full mode only as a separately projected all-local replication.
Current source-mapped IDEATOR v2 is the explicit exception: its manifest binds
only `advbench:245` and therefore requires
`--limit 1 --sample-seed 105`.
`--limit N` retains every row in each of at most N selected clusters under the
equal cap applied independently to every logical source arm.
For the same real converted-corpus digest and `--sample-seed`, limits are nested
prefixes of one deterministic cluster ordering: the `--limit 1` canary cluster
is contained in a later `--limit N` selection. This continuity is operational,
not evidence that one cluster represents the population. The sampler does not
stratify within an arm by risk or policy, so report achieved exact-stratum
support rather than assuming it.

## 10. Tier 1: broad static replay

*Console equivalent: this section's commands are also launchable as the `rig_check` and `run_matrix` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Static replay is the coverage backbone. It is where the broad model roster is
actually measured, rather than merely listed.

### 10.1 Text roster

The text lane includes harmful and benign behavior sources (JailbreakBench
benign and the 250 safe XSTest prompts are benign-refusal populations), but the
aggregator keeps their denominators separate. The five text aggregator arms
(`saladbench_base`, `airbench_full`, `xstest_full`, `simplesafetytests_full`,
`decodingtrust_stereotype`) are ordinary common-metric text arms here; their
source-native scorers (MD-Judge, the AIR-Bench rubric, the DecodingTrust
agreement index) are recorded as not run.

```bash
export TEXT_ARMS='strongreject_official,advbench_harmful,jailbreakbench_harmful,jailbreakbench_benign,harmbench_text,cyberseceval_mitre,cyberseceval_interpreter,cyberseceval_insecure_coding,saladbench_base,airbench_full,xstest_full,simplesafetytests_full,decodingtrust_stereotype'

python -m experiments.rig_check \
  --api "$TEXT_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds '<pre-registered-call-start-window-seconds>' \
  --out runs/thesis/preflight/static-text

python -m experiments.run_matrix \
  "${LIVE_ATTESTATION_ARGS[@]}" \
  --ack-hosted-judge-data-transfer \
  --api "$TEXT_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<projected-target-total>' --max-total-judge-calls '<projected-judge-total>' \
  --max-total-http-attempts '<projected-http-total>' --deadline-seconds '<pre-registered-call-start-window-seconds>' \
  --out runs/thesis/runner/static-text
```

Replace the bracketed values with positive integers before invoking either
command: `<pre-registered-cluster-limit (section 5.2)>` is the lane's
pre-registered positive cluster limit (identical in the preflight and the
measured command, and required in every hosted-target or hosted-judge lane
below, where the same placeholder appears), the first command's ceilings are
operator capacity bounds, and the second command's ceilings come from the
successful no-call projection. The call-start-window placeholder is likewise a
positive cohort-specific value recorded before execution; it is not inherited
from the current bounded local cohort.

### 10.2 Image roster

Add the four common-eligible MLLMGuard safety dimensions as separate arms. Keep
MOSSBench's benign refusal endpoint separate from harmful image ASR. The three
MLLMGuard truthfulness tasks stay in the conversion-only inventory. HoliSafe
(`holisafe_full`) is the text+image aggregator arm: its all-safe `SSS`
image-text combination is a benign-refusal population kept separate from the
harmful image ASR of its unsafe combinations. Because the release ships no
source-authored safety rationale, that benign subset is scored response-only in
the way MOSSBench's benign probes are, while the unsafe combinations bind a
judge reference composed deterministically from the released category,
subcategory and safeness-combination labels and recorded as label-derived rather
than source-authored.

```bash
export IMAGE_ARMS='mmsafety_official,jailbreakv_full,harmbench_multimodal,vlsbench_release,mossbench_official,siuo_release,figstep_full,mllmguard_privacy,mllmguard_bias,mllmguard_toxicity,mllmguard_legality,holisafe_full'

# Run rig_check first, then run_matrix with the same arguments and exact printed ceilings.
python -m experiments.rig_check \
  --api "$IMAGE_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$IMAGE_ARMS" --source-config experiments/source-instances.json \
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds '<pre-registered-call-start-window-seconds>' \
  --out runs/thesis/preflight/static-image
```

After the check succeeds, replace `experiments.rig_check` with
`experiments.run_matrix` and replace all three planning ceilings with the printed
totals; append `"${LIVE_ATTESTATION_ARGS[@]}"` and
`--ack-hosted-judge-data-transfer`, and write the measured grid to
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
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds '<pre-registered-call-start-window-seconds>' \
  --out runs/thesis/preflight/static-audio

# Video: the benign-query and harmful-query releases are both harmful joint-input probes.
python -m experiments.rig_check \
  --api "$RICH_TARGET" --api-config experiments/api-targets.json \
  --attackers replay --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora videosafetybench_benign_query,videosafetybench_harmful_query \
  --source-config experiments/source-instances.json \
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds '<pre-registered-call-start-window-seconds>' \
  --out runs/thesis/preflight/static-video
```

For each, repeat with `experiments.run_matrix`, the exact successful projection,
`"${LIVE_ATTESTATION_ARGS[@]}"`, `--ack-hosted-judge-data-transfer`, and measured outputs
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
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds '<pre-registered-call-start-window-seconds>' --out runs/thesis/preflight/rjudge

# GPTGeoChat: image-capable roster, five moderation thresholds per conversation.
python -m experiments.rig_check \
  --api "$IMAGE_TARGETS" --api-config experiments/api-targets.json \
  --attackers replay --judges rules \
  --corpora gptgeochat_release --source-config experiments/source-instances.json \
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds '<pre-registered-call-start-window-seconds>' --out runs/thesis/preflight/gptgeochat
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
implemented. A completed R-Judge output that does not obey the exact source
label format is retained as an exercised observation with `valid=0`; it remains
in `rjudge_validity` and the all-output accuracy denominator. Do not retry,
discard, or block Gate 5 merely to obtain a parseable prediction. Admission
requires the implemented source evaluator to be exercised and every planned
observation to complete, not a positive count of valid predictions. GPTGeoChat reports
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
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 4 --max-turns 4 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' --max-total-judge-calls '<planning-ceiling>' \
  --max-total-http-attempts '<planning-ceiling>' --deadline-seconds '<pre-registered-call-start-window-seconds>' \
  --out runs/thesis/preflight/crescendo-text
```

Repeat with `experiments.run_matrix`, `"${LIVE_ATTESTATION_ARGS[@]}"`,
`--ack-hosted-judge-data-transfer`, the printed totals, and
`--out runs/thesis/runner/crescendo-text`. This lane reports conversation
endpoints; it does not enter static ASR.

### 12.2 Runner-safe external attack bridges

Each Runner-safe third-party framework has its own explicit virtual environment.
Do not activate these environments and do not install any of their packages in
the Runner environment. Do not put two registered framework packages in one
environment; live admission rejects that layout.

```bash
export URA_FRAMEWORK_ENVS="$URA_WORK/framework-venvs"
export URA_FRAMEWORK_LOCK="$PWD/experiments/framework_runtime_lock.json"
URA_FRAMEWORK_LOCK_ID="$(python -c 'from pathlib import Path; from experiments.framework_runtime_installer import load_lock; import os; print(load_lock(Path(os.environ["URA_FRAMEWORK_LOCK"]))["lock_id"])')" || exit $?
[[ "$URA_FRAMEWORK_LOCK_ID" =~ ^[0-9a-f]{64}$ ]] || exit 1
export URA_FRAMEWORK_LOCK_ID
export URA_FRAMEWORK_STATE="$URA_WORK/runs/engineering/framework-runtime-${URA_FRAMEWORK_LOCK_ID:0:12}"
URA_FRAMEWORK_PYTHON="$(python -c 'import sys; print(sys._base_executable)')" || exit $?
[[ -x "$URA_FRAMEWORK_PYTHON" ]] || exit 1
export URA_FRAMEWORK_PYTHON

ura_runtime_alias() {
  python - "$1" <<'PY'
import os
import sys
from pathlib import Path
from experiments.framework_runtime_installer import load_lock

lock = load_lock(Path(os.environ["URA_FRAMEWORK_LOCK"]))
entry = next(item for item in lock["frameworks"] if item["name"] == sys.argv[1])
print(Path(os.environ["URA_FRAMEWORK_ENVS"]) / entry["env_slug"])
PY
}

ura_runtime_store() {
  python - "$1" <<'PY'
import json
import os
import sys
from pathlib import Path
import re

from experiments.framework_runtime_installer import Layout, load_lock, published_store

lock = load_lock(Path(os.environ["URA_FRAMEWORK_LOCK"]))
name = sys.argv[1]
rows = [item for item in lock["frameworks"] if item.get("name") == name]
if len(rows) != 1:
    raise SystemExit(f"expected one framework lock row for {name}, found {len(rows)}")
entry = rows[0]
env_root = Path(os.environ["URA_FRAMEWORK_ENVS"]).resolve(strict=True)
layout = Layout(env_root, Path(os.environ["URA_FRAMEWORK_STATE"]))
store = published_store(entry, lock, layout)
alias = layout.final(entry["env_slug"])
raw_target = Path(os.readlink(alias))
unresolved_store = env_root / raw_target
if (
    raw_target.is_absolute()
    or len(raw_target.parts) != 2
    or raw_target.parts[0] != ".store"
    or not re.fullmatch(
        rf"{re.escape(entry['env_slug'])}-[0-9a-f]{{16}}", raw_target.parts[1]
    )
    or unresolved_store.is_symlink()
    or unresolved_store.resolve(strict=True) != store
):
    raise SystemExit(f"{name}: stable runtime alias is not a direct managed-store link")
receipt = json.loads((store / ".ura-runtime-receipt.json").read_bytes())
expected = {
    "schema": "ura-framework-runtime-receipt/1",
    "lock_id": lock["lock_id"],
    "framework": name,
    "version": entry["version"],
    "env_slug": entry["env_slug"],
    "runtime": entry["runtime"],
    "status": "passed",
    "smoke": "passed",
    "network_smoke": "denied",
    "provider_calls": 0,
    "model_calls": 0,
}
if any(receipt.get(key) != value for key, value in expected.items()):
    raise SystemExit(f"{name}: current runtime receipt identity is invalid")
print(store)
PY
}

ura_wait_session() {
  local payload="$1" parsed session_name launcher log_rel exit_rel tmux_socket rc listing
  local deadline=$((SECONDS + 168 * 60 * 60))
  parsed="$(python - "$payload" <<'PY'
import json
import hashlib
import re
import sys

row = json.loads(sys.argv[1])
required = {
    "schema", "launcher", "session_name", "attach_command",
    "log", "exit_marker", "status",
}
if set(row) != required or row["schema"] != "ura-framework-runtime-session/1":
    raise SystemExit(2)
name = row["session_name"]
if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
    raise SystemExit(2)
launcher = row["launcher"]
if launcher not in {"tmux", "screen"} or row["status"] != "running":
    raise SystemExit(2)
log = f"sessions/{name}.log"
marker = f"sessions/{name}.exit"
if row["log"] != log or row["exit_marker"] != marker:
    raise SystemExit(2)
tmux_socket = "ura-fw-" + hashlib.sha256(name.encode("ascii")).hexdigest()[:16]
attach = (
    f"tmux -L {tmux_socket} attach -t {name}"
    if launcher == "tmux"
    else f"screen -r {name}"
)
if row["attach_command"] != attach:
    raise SystemExit(2)
print("\t".join((name, launcher, log, marker, tmux_socket)))
PY
)" || return $?
  IFS=$'\t' read -r session_name launcher log_rel exit_rel tmux_socket <<<"$parsed"
  [[ -n "$session_name" && -n "$exit_rel" ]] || return 1
  case "$launcher" in
    tmux) printf 'Attach with: tmux -L %s attach -t %s\n' "$tmux_socket" "$session_name" ;;
    screen) printf 'Attach with: screen -r %s\n' "$session_name" ;;
    *) return 1 ;;
  esac
  printf 'Tail with: tail -f -- %s\n' "$URA_FRAMEWORK_STATE/$log_rel"
  while [[ ! -f "$URA_FRAMEWORK_STATE/$exit_rel" ]]; do
    (( SECONDS < deadline )) || return 124
    case "$launcher" in
      tmux)
        if ! tmux -L "$tmux_socket" has-session -t "$session_name" 2>/dev/null; then
          sleep 1
          [[ -f "$URA_FRAMEWORK_STATE/$exit_rel" ]] || return 1
        fi
        ;;
      screen)
        listing="$(screen -ls 2>/dev/null || true)"
        if [[ ! "$listing" =~ [[:space:]][0-9]+\.${session_name}[[:space:]]+\((Attached|Detached|Multi(,[[:space:]]*attached)?)\) ]]; then
          sleep 1
          [[ -f "$URA_FRAMEWORK_STATE/$exit_rel" ]] || return 1
        fi
        ;;
    esac
    sleep 5
  done
  rc="$(tr -d '\r\n' < "$URA_FRAMEWORK_STATE/$exit_rel")"
  [[ "$rc" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
  (( rc <= 255 )) || return 1
  (( rc == 0 ))
}

ura_framework_action() {
  local action="$1" framework="$2" payload
  shift 2
  payload="$(
    python -m experiments.framework_runtime_installer "$action" \
      --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" \
      --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON" \
      --only "$framework" "$@"
  )" || return $?
  printf '%s\n' "$payload"
  ura_wait_session "$payload"
}

python -m experiments.framework_runtime_installer plan \
  --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" \
  --state-root "$URA_FRAMEWORK_STATE"

# Preferred complete-inventory path. It verifies every row first and does not
# reinstall a row that passes. Set this only for an aggregate-lock transition:
# export URA_FRAMEWORK_ADOPT_FROM_LOCK=/absolute/operator/path/framework_runtime_lock.previous.json
distro/install.sh runtimes

# Direct one-row equivalent, useful for bounded recovery and inspection.
export URA_FRAMEWORK_NAME=pyrit
if ura_framework_action verify "$URA_FRAMEWORK_NAME"; then
  printf '%s\n' "$URA_FRAMEWORK_NAME already verified; no mutation performed"
elif [[ -n "${URA_FRAMEWORK_ADOPT_FROM_LOCK:-}" ]] \
  && ura_framework_action adopt "$URA_FRAMEWORK_NAME" \
    --from-lock "$URA_FRAMEWORK_ADOPT_FROM_LOCK"; then
  ura_framework_action verify "$URA_FRAMEWORK_NAME" || exit $?
else
  ura_framework_action resume "$URA_FRAMEWORK_NAME" || exit $?
  ura_framework_action verify "$URA_FRAMEWORK_NAME" || exit $?
fi
```

The repository has one strict `ura-framework-runtime-lock/1` manifest for 16
managed runtimes: 14 separate CPython virtual environments and separate
Promptfoo and T3MP3ST Node environments. It binds
CPython 3.12.13, the official Node runtime shared by the two isolated Node
stores, every package/source
version and artifact/source SHA-256, fully hashed transitive dependency locks,
the observed installed inventory, and the explicit 20-attacker coverage
disposition. The installer creates one content-addressed store per managed
framework, verifies there, and atomically publishes only a small stable alias;
it never renames a built venv or shares site packages. DeepTeam's locked Sentry
repair and AutoDAN's resolver-compatible repair are data in that same lock.
The global distro path also keeps BIPIA's legacy corpus builder out of the main
URA venv: `distro/bipia-build-requirements.lock` is fully hashed and installs to
its own content-addressed `$URA_WORK/support-venvs` environment.

`install`, `resume`, `verify`, and `adopt` automatically dispatch into a deterministic
named tmux session (screen only when tmux is unavailable), with a credential-free
environment and retained bounded log/exit marker under the engineering campaign.
Wait for the exit marker before the next action. The default block above and
`distro/install.sh runtimes` verify each row before any mutation. A passing row
is left untouched. `resume` safely creates an absent store or resumes an
admitted, phase-checked staged store; fresh-only `install` intentionally refuses
an existing stage. After a successful adoption, install, or resume, run the same
row selection as `verify`. Add repeated `--only NAME` (or a comma-separated
value) for a bounded subset. An existing receipt never skips verification:
`pip check` or npm inventory, offline import/CLI startup, exact installed
inventory, and the deterministic whole-runtime seal including executable
bytecode all run again. Those receipts retain their outer
`ura-framework-runtime-receipt/1` schema, but their nested content identity must
be `ura-framework-runtime-content-seal/2`; older nested seal schemas are not
accepted. A seal-algorithm migration therefore receives a new lock identity and
content-addressed store instead of verifying or rewriting the retained old
store.
A same-version dependency, source shadow, console script, or other retained-file
change therefore invalidates verification.

Cross-lock adoption is explicit, not automatic. Set
`URA_FRAMEWORK_ADOPT_FROM_LOCK` to an already-resolved absolute path containing
the exact retained prior lock, or pass that path to `adopt --from-lock`. Adoption
requires identical lock schema, platform, policy and runtime pins and an
identical complete selected framework entry. It validates the retained seal,
inventory and offline smoke before rebinding the path-free receipt to the new
aggregate lock. A new or changed row cannot be adopted and follows the normal
resume path. No previous lock is searched for or guessed.

Each runtime subprocess receives a clean private HOME plus an explicit package
cache outside the sealed store: `$URA_FRAMEWORK_ENVS/.cache/pip` for Python and
`$URA_FRAMEWORK_ENVS/.cache/npm` for Node. Those caches persist across
interrupted sessions and lock revisions, but are transfer optimizations only;
the hashed dependency lock, exact inventory, offline smoke, receipt, and whole-
runtime content seal still decide admission. `distro/install.sh runtimes`
derives the exact 16 names from the validated lock and runs one sequential
`verify --only NAME` first. It skips mutation on success, otherwise attempts an
explicit strict adoption when the prior-lock variable is set, and calls
`resume --only NAME` only for a missing, interrupted, new, or changed row. Every
mutated row receives a final `verify --only NAME`. The phase continues after an
isolated row failure and returns a nonzero aggregate after all rows have been
attempted.

Rig Web exposes the same fixed interface under **Build → Runtimes**, with one
lock-derived Install/Resume/Verify action per row and no package, path, shell,
model, provider, or credential inputs. Its credential-free named-session work
appears as a non-thesis engineering campaign in Jobs/Stats; it does not create a
duplicate Console Job. With results root `$URA_WORK/runs`, the UI uses the same
sibling `$URA_WORK/framework-venvs` environment root and lock-derived campaign
state used above.

Build one private, content-addressed runtime config for each one-framework lane
from the canonical `.store` venv parent (preserve the final ordinary venv
`bin/python` link; do not resolve it into the base interpreter). The config's engine inventory
must equal the selected attacker inventory exactly; never carry unused runtimes
into another lane's scientific identity. Interpreter locators never appear in
controller argv or the printed build receipt. For the PyRIT lane:

```bash
URA_PYRIT_STORE="$(ura_runtime_store pyrit)" || exit $?
URA_PYRIT_PYTHON="$URA_PYRIT_STORE/bin/python"
[[ -x "$URA_PYRIT_PYTHON" ]] || exit 1
export URA_PYRIT_STORE URA_PYRIT_PYTHON
umask 077
mkdir -p runs/private
export ENGINE_RUNTIME_CONFIG='runs/private/engine-runtime-pyrit.json'
python -m experiments.engine_runtime_config \
  --runtime pyrit=URA_PYRIT_PYTHON \
  --out "$ENGINE_RUNTIME_CONFIG"
# Copy the exact lowercase sha256 from the path-free JSON printed above.
export ENGINE_RUNTIME_CONFIG_SHA256='<printed-64-hex-sha256>'
```

Create separate DeepTeam, h4rm3l, and Spikee configs by resolving
`ura_runtime_store deepteam`, `ura_runtime_store h4rm3l`, or
`ura_runtime_store spikee`, appending `/bin/python`, and supplying only that
lane's engine/environment pair and a distinct output file. The Builder performs
the same exact-membership check through its typed private runtime-config fields;
the private config generator is intentionally not exposed as a generic Console
command.

Both `rig_check` and `run_matrix` require the paired flags for a selected one of
these attackers:

```bash
--engine-runtime-config "$ENGINE_RUNTIME_CONFIG" \
--engine-runtime-config-sha256 "$ENGINE_RUNTIME_CONFIG_SHA256"
```

Admission runs the fixed standard-library worker with `-I -S -B`, an empty
private HOME/cache, no ambient command-search path, and no provider or Hub
credentials. It ignores `.pth`, `sitecustomize`, and pre-existing package
bytecode, verifies the complete environment before making framework imports
available, and starts no target/model component if the receipt differs. One
admitted worker is reused for the matrix rather than rehashing a multi-gigabyte
environment per attempt; completion is published only after a second full-tree
closing seal. These controls establish execution identity and process-tree
lifecycle, not a filesystem/network sandbox. Keep the config and environments
operator-private; result, grid, completion, Figure, transfer, and Level-1
evidence retain only path-free identities and exact closing seals.

Create one operator-private config containing only the selected attacker's exact
constructor arguments. Set `ATTACKER` separately for each lane; this create-only
step refuses to overwrite an earlier condition:

```bash
export ATTACKER='pyrit'
export ATTACKER_CONFIG="runs/private/attacker-config-$ATTACKER.json"
umask 077
mkdir -p runs/private
python - "$ATTACKER" "$ATTACKER_CONFIG" <<'PY'
import json
import sys
from pathlib import Path

configs = {
    "deepteam": {"attack": "Base64", "upstream_version": "1.0.7"},
    "h4rm3l": {"engine_version": "0.2.4", "syntax_version": 2},
    "pyrit": {"converters": ["Base64Converter"], "upstream_version": "0.14.0"},
    "spikee": {
        "plugins": ["base64", "1337"],
        "positions": ["start", "middle", "end"],
        "engine_version": "0.9.1",
    },
}
attacker = sys.argv[1]
if attacker not in configs:
    raise SystemExit(f"unsupported deterministic-transfer attacker: {attacker}")
payload = json.dumps(
    {attacker: configs[attacker]}, sort_keys=True, separators=(",", ":")
) + "\n"
with Path(sys.argv[2]).open("x", encoding="utf-8", newline="\n") as handle:
    handle.write(payload)
PY
```

Run PyRIT, DeepTeam, h4rm3l, and Spikee as separate lanes over the declared
harmful text anchors. This makes each framework an identifiable condition and
prevents transformed prompts from being confused with raw replay.

```bash
export TRANSFER_ARMS='strongreject_official,advbench_harmful,jailbreakbench_harmful'

# PyRIT and DeepTeam emit one transformed attempt per selected configuration.
# Repeat ATTACKER=pyrit and deepteam with max-queries=1/max-turns=1.
python -m experiments.rig_check \
  --api "$FOCAL_HOSTED" --api-config experiments/api-targets.json \
  --attackers "$ATTACKER" --attacker-config "$ATTACKER_CONFIG" \
  --engine-runtime-config "$ENGINE_RUNTIME_CONFIG" \
  --engine-runtime-config-sha256 "$ENGINE_RUNTIME_CONFIG_SHA256" \
  --judges rules,guardrail,llm --judge-model "$JUDGE" \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device "$SCORE_GUARD_DEVICE" \
  --corpora "$TRANSFER_ARMS" --source-config experiments/source-instances.json \
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' \
  --max-total-judge-calls '<planning-ceiling>' --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds '<pre-registered-call-start-window-seconds>' --out "runs/thesis/preflight/transfer-$ATTACKER"
```

Run h4rm3l and Spikee in separate invocations with
`--max-queries 4 --max-turns 4`; otherwise the Runner's shared query/turn budget
admits only the first generated variant. The completed artifacts, not the
configured maximum, establish the realized variant count.

The private config must contain only the selected attacker key. For each later
lane, rerun the create-only block with its new `ATTACKER` and distinct
`ATTACKER_CONFIG`; do not reuse or edit another lane's condition. Repeat the
successful check with `experiments.run_matrix`, the same paired engine-runtime
flags, `"${LIVE_ATTESTATION_ARGS[@]}"`,
`--ack-hosted-judge-data-transfer`, its exact totals, and
`--out "runs/thesis/runner/transfer-$ATTACKER"`.

The remaining runner bridges are specialized:

| Bridge | Defensible use in this program |
| --- | --- |
| `nanogcg` | prepare one attributable suffix with `experiments.nanogcg_capture` under the verified NanoGCG 0.3.0 runtime and sealed Qwen2.5-0.5B surrogate, then replay that suffix without another framework/model call |
| `harmbench` attacker | prepare text cases from a clean exact-revision checkout with `experiments.harmbench_capture`, then replay only its exact `ura-harmbench-transfer-replay/1` in the measured grid |
| `purplellama` | only with `cyberseceval` rows; source-identity replay, not the native pipeline |
| `ideator` | prepare the eight exact VLBreakBench/AdvBench mappings as `ura-ideator-seed-pairs/2` and replay them through Build or the emitted ordinary CLI config; legacy v1 remains accepted only for previously reviewed pairs, while live generation remains disabled |
| `t3mp3st` | capture through the exact installer-managed source commit `f2eec3c48cefe301983b3865811eda89d454e988`, then replay only the resulting attributable bundle |

The core cohort records `bridge-nanogcg`, `bridge-ideator`, and `t3mp3st` as
`unavailable` only because their prepared artifacts are assigned to a separate
follow-on cohort and were not bound when its Gate 5 authorization was sealed.
This is not a current capability disposition. The core controller does not
schedule those three lanes for core-cohort measured execution. The follow-on
cohort binds all three prepared artifacts and uses the ordinary documented
Runner commands with one retained common scientific base and separate exact
preflight, canary and measured argument arrays. Each purpose keeps its own plan
and receipt. For each lane, the retained schedule contains a prepared artifact,
no-call projection, diagnostic canary, Gate 5 record, and measured schedule.
NanoGCG may use a separately projected positive or `--limit 0` transfer
selection. Current IDEATOR v2 may not: its source mapping fixes the outer
selection to `advbench_harmful --limit 1 --sample-seed 105`.

#### NanoGCG: sealed suffix capture, then replay

Direct live NanoGCG configuration inside Runner remains fail-closed. The
dedicated preparation command is the implemented live path: it verifies the
NanoGCG 0.3.0 framework store, admits the exact sealed
`Qwen/Qwen2.5-0.5B-Instruct` surrogate at revision
`7ae557604adf67be50417f59c2c2f167def9a775`, runs one bounded GCG
optimization, rechecks the framework/model/project seals, and writes both the
create-only capture artifact and replay config. Its exact source row is
`advbench:245`, selected by limit 1 and sample seed 105.

Reuse one immutable argument array for plan derivation and capture. The model
paths below are the already-resolved stores initialized in section 6.1; choose a
fresh preparation root because both output files are create-only:

```bash
URA_NANOGCG_ENV="$(ura_runtime_store nanogcg)" || exit $?
[[ -x "$URA_NANOGCG_ENV/bin/python" ]] || exit 1
NANOGCG_PREP_ROOT="$URA_WORK/runs/thesis/prepared/nanogcg-qwen25-05b-row245"
mkdir -p "$NANOGCG_PREP_ROOT" "$URA_MODEL_PLANS" \
  "$URA_MODEL_RECEIPTS" "$URA_MODEL_STORE" "$URA_MODEL_TRANSPORT"

NANOGCG_CAPTURE_ARGS=(
  --source "$URA_ADVBENCH_HARMFUL_PATH"
  --corpus-name advbench_harmful
  --source-row-index 245
  --limit 1
  --sample-seed 105
  --model-id Qwen/Qwen2.5-0.5B-Instruct
  --model-revision 7ae557604adf67be50417f59c2c2f167def9a775
  --framework-lock "$URA_FRAMEWORK_LOCK"
  --framework-env-root "$URA_FRAMEWORK_ENVS"
  --framework-state-root "$URA_FRAMEWORK_STATE"
  --project-revision "$URA_PROJECT_REVISION_MANIFEST"
  --project-revision-sha256 "$URA_PROJECT_REVISION_SHA256"
  --num-steps 20
  --search-width 64
  --topk 64
  --gcg-seed 0
  --device cuda:0
  --torch-dtype float16
)

"$URA_NANOGCG_ENV/bin/python" -m experiments.nanogcg_capture \
  "${NANOGCG_CAPTURE_ARGS[@]}" \
  --model-acquisition-plan-only \
  --model-acquisition-plan-dir "$URA_MODEL_PLANS"
```

Copy the create-only plan path and SHA-256 printed by that command, acquire only
that public snapshot under explicit byte/free-space/time bounds, then copy the
printed receipt path and digest:

```bash
export URA_NANOGCG_PLAN='<absolute acquisition-plan-*.plan.json>'
export URA_NANOGCG_PLAN_SHA256='<printed 64-hex digest>'
python -m experiments.model_acquire \
  --plan "$URA_NANOGCG_PLAN" \
  --plan-sha256 "$URA_NANOGCG_PLAN_SHA256" \
  --store "$URA_MODEL_STORE" \
  --receipts-dir "$URA_MODEL_RECEIPTS" \
  --transport-cache "$URA_MODEL_TRANSPORT" \
  --max-download-bytes 17179869184 \
  --min-free-bytes 21474836480 \
  --deadline-seconds 86400

export URA_NANOGCG_RECEIPT='<absolute acquisition-receipt-*.receipt.json>'
export URA_NANOGCG_RECEIPT_SHA256='<printed 64-hex digest>'
"$URA_NANOGCG_ENV/bin/python" -m experiments.nanogcg_capture \
  "${NANOGCG_CAPTURE_ARGS[@]}" \
  --model-acquisition-plan "$URA_NANOGCG_PLAN" \
  --model-acquisition-plan-sha256 "$URA_NANOGCG_PLAN_SHA256" \
  --model-acquisition-receipt "$URA_NANOGCG_RECEIPT" \
  --model-acquisition-receipt-sha256 "$URA_NANOGCG_RECEIPT_SHA256" \
  --model-acquisition-store "$URA_MODEL_STORE" \
  --artifact-out "$NANOGCG_PREP_ROOT/capture.json" \
  --attacker-config-out "$NANOGCG_PREP_ROOT/attacker-config.json"
```

Run the final GPU command in a named tmux/screen session. Any change to the
source row, GCG controls, framework lock, project receipt, model identity, or
device/dtype requires a new plan and receipt. Use the emitted attacker config
unchanged. Its replay-only shape is:

```json
{
  "nanogcg": {
    "captured_surrogate_id": "Qwen/Qwen2.5-0.5B-Instruct",
    "captured_surrogate_revision": "7ae557604adf67be50417f59c2c2f167def9a775",
    "captured_source_id": "advbench:245",
    "captured_target": "<exact target continuation retained by the capture>",
    "suffix": "<captured exact suffix>",
    "suffix_source": "ura-nanogcg-suffix-capture/1@sha256:<capture-file-sha256>"
  }
}
```

For its first projection/canary/measured sequence, use
`--attackers nanogcg --attacker-config "$NANOGCG_PREP_ROOT/attacker-config.json"`
with `--corpora advbench_harmful --limit 1 --sample-seed 105 --seeds 0`
and query/turn bounds of one, plus the normal target, judge, acquisition,
attestation and cap flags. The later Runner provenance says
`framework_execution=not_invoked` because replay itself performs no
NanoGCG or surrogate call. The separate capture artifact records one bounded
optimization invocation governed by the declared step, search-width and top-k
controls; this is not a claim of one surrogate forward pass.

#### IDEATOR: exact VLBreakBench mapping, then Build or CLI replay

The implemented preparation path does not run IDEATOR generation. It records
the official generator source at commit
`504a9825f97c833fb4c3da1feb5542594024d0bd` and tree
`1e181bca68af2f5fbc4adc6e7bf5c071600e327f`, whose public tree
declares no software licence, and separately consumes the Apache-2.0
`wang021/VLBreakBench` release at revision
`10b1ce5ab4546b5c2ab27c0aed4e171ab8ee98a0`. The preparer verifies
the exact base/challenge JSON bytes, all referenced PNGs, and the exact admitted
AdvBench CSV before writing eight one-to-one source mappings:

```bash
export REF_HF_VLBREAKBENCH=10b1ce5ab4546b5c2ab27c0aed4e171ab8ee98a0
export URA_IDEATOR_DATASET_ROOT="$URA_CORPORA/VLBreakBench-$REF_HF_VLBREAKBENCH"
[[ ! -e "$URA_IDEATOR_DATASET_ROOT" && ! -L "$URA_IDEATOR_DATASET_ROOT" ]] || exit 1
hf download wang021/VLBreakBench --repo-type dataset \
  --revision "$REF_HF_VLBREAKBENCH" \
  --local-dir "$URA_IDEATOR_DATASET_ROOT"
URA_IDEATOR_DATASET_ROOT="$(realpath "$URA_IDEATOR_DATASET_ROOT")" || exit $?
[[ -d "$URA_IDEATOR_DATASET_ROOT" && ! -L "$URA_IDEATOR_DATASET_ROOT" ]] || exit 1
( cd "$URA_IDEATOR_DATASET_ROOT" && printf '%s  %s\n' \
    264f68ac656a6c8880e447821dc9f2858cd26db88fcbd7c4a80941e36945a523 \
      vlbreakbench_base.json \
    c077e482530cf9ec7c403d4022204ff266c2226cd55830439187a67d24404f00 \
      vlbreakbench_challenge.json | sha256sum --check --strict - ) || exit $?
URA_IDEATOR_PREP_ROOT="$URA_WORK/runs/thesis/prepared/ideator-vlbreakbench-v2"
mkdir -p "$URA_IDEATOR_PREP_ROOT/images"
export URA_IDEATOR_MANIFEST="$URA_IDEATOR_PREP_ROOT/ideator-vlbreakbench-v2.json"
export URA_IDEATOR_ATTACKER_CONFIG="$URA_IDEATOR_PREP_ROOT/attacker-config-limit-all.json"
[[ ! -e "$URA_IDEATOR_MANIFEST" && ! -L "$URA_IDEATOR_MANIFEST" \
   && ! -e "$URA_IDEATOR_ATTACKER_CONFIG" \
   && ! -L "$URA_IDEATOR_ATTACKER_CONFIG" ]] || exit 1

"$URA_PY" -m experiments.ideator_vlbreakbench_prepare \
  --base-json "$URA_IDEATOR_DATASET_ROOT/vlbreakbench_base.json" \
  --challenge-json "$URA_IDEATOR_DATASET_ROOT/vlbreakbench_challenge.json" \
  --dataset-root "$URA_IDEATOR_DATASET_ROOT" \
  --advbench "$URA_ADVBENCH_HARMFUL_PATH" \
  --prepared-image-dir "$URA_IDEATOR_PREP_ROOT/images" \
  --out "$URA_IDEATOR_MANIFEST" \
  --attacker-config-out "$URA_IDEATOR_ATTACKER_CONFIG" \
  --pair-limit 0
URA_IDEATOR_MANIFEST_SHA256="$(sha256sum "$URA_IDEATOR_MANIFEST" | awk '{print $1}')" || exit $?
URA_IDEATOR_ATTACKER_CONFIG_SHA256="$(sha256sum "$URA_IDEATOR_ATTACKER_CONFIG" | awk '{print $1}')" || exit $?
export URA_IDEATOR_MANIFEST_SHA256 URA_IDEATOR_ATTACKER_CONFIG_SHA256
export URA_IDEATOR_MEDIA_ROOT="$(realpath "$URA_IDEATOR_PREP_ROOT/images")" || exit $?
export URA_MEDIA_ROOTS="${URA_MEDIA_ROOTS:+$URA_MEDIA_ROOTS:}$URA_IDEATOR_MEDIA_ROOT"
```

The immutable Hub revision, the two checked JSON artifacts, the selected PNG
digests and their one-to-one AdvBench mappings are retained in the create-only
v2 manifest. Retain that manifest and its printed SHA-256 as the preparation
receipt. The second create-only file is an ordinary Runner attacker config. It
retains that path-free manifest SHA-256, one declared digest per image, the
exact source bindings, `seed_pairs`, and the explicit `pair_limit`; it performs
no IDEATOR or other model generation. Runner checks every declared image digest
before planning. A changed image therefore fails before a target call.
The resolved prepared-image directory must remain in the same ordered
`URA_MEDIA_ROOTS` value for the IDEATOR preflight, diagnostic canary and measured
request; otherwise generated-media admission correctly fails before a target
call.

In Build select the `ideator` attacker, the
`advbench_harmful` source arm, limit 1 and sample seed 105. Supply
`$URA_IDEATOR_MANIFEST` and
`$URA_IDEATOR_MANIFEST_SHA256` in the verified seed-pair panel and
use an image-capable target. Pair limit 0 selects all eight verified pairs for
`advbench:245`; a positive value 1 through 8 selects the exact
source-ordered prefix. Set both `--max-queries` and `--max-turns`
to at least that selected pair count. The v2 manifest itself is not a
`run_matrix --attacker-config` file; Build validates it and materializes
the private runtime config. For CLI replay, pass
`--attacker-config "$URA_IDEATOR_ATTACKER_CONFIG"` and
`--attacker-config-sha256 "$URA_IDEATOR_ATTACKER_CONFIG_SHA256"`. A different
positive pair limit needs a new create-only config output and must be projected
as its own immutable selection. Legacy `ura-ideator-seed-pairs/1` remains
accepted only for previously reviewed pairs. After review, the follow-on lane
still requires its own projection, diagnostic canary, Gate 5 record and measured
schedule.

Run all prepared lanes only after passing `rig_check`. Do not claim that
a complete upstream evaluator ran. Garak, Promptfoo, Petri, FuzzyAI,
EasyJailbreak, AutoDAN-Turbo, Giskard, ASB, and AgentDojo are not runner
attackers; they belong in the native track below.

T3MP3ST planning and HarmBench generation are not target/judge/provider-HTTP
calls covered by the Runner's common call ledger. They run once out of band
under their own cap or quota. NanoGCG capture is also an out-of-band bounded
optimization invocation outside those ceilings; IDEATOR v2 preparation performs
only local source/image validation and copying. Retain exact preparation provenance
and never describe any of these operations as protected by the target/judge
ceilings.

#### T3MP3ST: capture, then replay

The framework lock admits the official T3MP3ST source at exact commit
`f2eec3c48cefe301983b3865811eda89d454e988` in its own source-only Node
runtime. Start that verified runtime in tmux against the dedicated
literal-loopback Qwen3-VL vLLM service. The stable runtime alias is resolved to
the content-addressed store before launch. The capture helper independently
verifies that store and its receipt, reads the current lock, rejects a different
claimed revision before HTTP, and re-verifies the runtime before publication.
The upstream planning route does not expose process identity, so the retained
boundary records `process_identity_attested=false`; do not claim that the HTTP
process itself was attested. Bind the plan, receipt, and store from a completed
sealed Qwen acquisition first. The verifier below re-hashes the receipted
snapshot before the standalone server starts; it must resolve exactly one
`Qwen/Qwen3-VL-8B-Instruct` resource at the reviewed revision:

```bash
export URA_T3_QWEN_PLAN='<absolute Qwen acquisition-plan-*.plan.json>'
export URA_T3_QWEN_PLAN_SHA256='<matching 64 lowercase hex>'
export URA_T3_QWEN_RECEIPT='<absolute Qwen acquisition-receipt-*.receipt.json>'
export URA_T3_QWEN_RECEIPT_SHA256='<matching 64 lowercase hex>'
export URA_T3_QWEN_STORE="$URA_MODEL_STORE"
URA_T3_QWEN_SNAPSHOT="$("$URA_PY" - \
  "$URA_T3_QWEN_PLAN" "$URA_T3_QWEN_PLAN_SHA256" \
  "$URA_T3_QWEN_RECEIPT" "$URA_T3_QWEN_RECEIPT_SHA256" \
  "$URA_T3_QWEN_STORE" <<'PY'
import sys
from ura.model_acquisition import load_plan, load_receipt, verify_receipt_snapshots

plan = load_plan(sys.argv[1], expected_sha256=sys.argv[2])
receipt = load_receipt(sys.argv[3], expected_sha256=sys.argv[4], plan=plan)
matches = [
    resource for resource in plan["resources"]
    if resource["repo_id"] == "Qwen/Qwen3-VL-8B-Instruct"
    and resource["revision"] == "60595ebc30ec8e3b1d3b9e65d4943ca011c0006a"
]
if len(matches) != 1:
    raise SystemExit("Qwen acquisition plan does not contain one exact resource")
snapshots = verify_receipt_snapshots(plan, receipt, managed_store=sys.argv[5])
print(snapshots[matches[0]["resource_id"]])
PY
)" || exit $?
export URA_T3_QWEN_SNAPSHOT
[[ -d "$URA_T3_QWEN_SNAPSHOT" && ! -L "$URA_T3_QWEN_SNAPSHOT" ]] || exit 1

export URA_T3_VLLM_SESSION='ura-t3mp3st-qwen3-vllm-60595ebc30ec'
export URA_T3_VLLM_LOG="$URA_WORK/runs/engineering/$URA_T3_VLLM_SESSION.log"
export URA_T3_VLLM_BIN="$URA_REPO/.venv/bin/vllm"
[[ -x "$URA_T3_VLLM_BIN" ]] || exit 1
mkdir -p "$(dirname "$URA_T3_VLLM_LOG")"
if tmux has-session -t "$URA_T3_VLLM_SESSION" 2>/dev/null; then
  printf 'Refusing to reuse existing session %s; inspect or stop it first.\n' \
    "$URA_T3_VLLM_SESSION" >&2
  exit 1
fi
if "$URA_PY" -c 'import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(("127.0.0.1",8000)) == 0 else 1)'; then
  printf 'Refusing to reuse an existing listener on 127.0.0.1:8000.\n' >&2
  exit 1
fi
tmux new-session -d -s "$URA_T3_VLLM_SESSION" -c "$URA_REPO" \
  "exec env CUDA_VISIBLE_DEVICES=0 HF_DATASETS_OFFLINE=1 HF_HUB_OFFLINE=1 \
TRANSFORMERS_OFFLINE=1 VLLM_NO_USAGE_STATS=1 \
'$URA_T3_VLLM_BIN' serve '$URA_T3_QWEN_SNAPSHOT' \
--served-model-name Qwen/Qwen3-VL-8B-Instruct \
--host 127.0.0.1 --port 8000 --tensor-parallel-size 1 \
--gpu-memory-utilization 0.90 --max-model-len 12288 \
>>'$URA_T3_VLLM_LOG' 2>&1"
curl --retry 120 --retry-delay 2 --retry-connrefused \
  --fail --silent --show-error http://127.0.0.1:8000/v1/models | \
  "$URA_PY" -c 'import json,sys; value=json.load(sys.stdin); ids=[item.get("id") for item in value.get("data",[]) if isinstance(item,dict)]; expected=["Qwen/Qwen3-VL-8B-Instruct"]; sys.exit(0 if ids == expected else "served model identity mismatch")' || exit $?
tmux has-session -t "$URA_T3_VLLM_SESSION" 2>/dev/null || exit 1
```

This separate T3MP3ST source-model server is engineering infrastructure, not a
Runner target lane. Give it exclusive GPU 0 ownership for capture and stop its
tmux session before a normal in-process Runner vLLM lane. Start the verified
T3MP3ST service and check its local endpoint:

```bash
export URA_T3_ENV="$(ura_runtime_store t3mp3st)" || exit $?
export URA_T3_SOURCE="$URA_T3_ENV/source/t3mp3st"
export URA_T3_NODE="$URA_T3_ENV/runtime/node-v24.16.0-linux-x64/bin/node"
export URA_T3_SESSION="ura-t3mp3st-${URA_FRAMEWORK_LOCK_ID:0:12}"
export URA_T3_LOG="$URA_WORK/runs/engineering/$URA_T3_SESSION.log"
[[ -x "$URA_T3_NODE" && -f "$URA_T3_SOURCE/dist/server.js" ]] || exit 1
mkdir -p "$(dirname "$URA_T3_LOG")"
if tmux has-session -t "$URA_T3_SESSION" 2>/dev/null; then
  printf 'Refusing to reuse existing session %s; inspect or stop it first.\n' \
    "$URA_T3_SESSION" >&2
  exit 1
fi
if "$URA_PY" -c 'import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(0 if s.connect_ex(("127.0.0.1",3333)) == 0 else 1)'; then
  printf 'Refusing to reuse an existing listener on 127.0.0.1:3333.\n' >&2
  exit 1
fi
tmux new-session -d -s "$URA_T3_SESSION" -c "$URA_T3_SOURCE" \
  "exec env T3MP3ST_HOST=127.0.0.1 T3MP3ST_PORT=3333 \
TEMPEST_DEFAULT_PROVIDER=local \
TEMPEST_LOCAL_BASE_URL=http://127.0.0.1:8000/v1 \
TEMPEST_LOCAL_MODEL=Qwen/Qwen3-VL-8B-Instruct \
TEMPEST_LOCAL_TIMEOUT=600000 \
'$URA_T3_NODE' dist/server.js >>'$URA_T3_LOG' 2>&1"
curl --retry 30 --retry-delay 2 --retry-connrefused \
  --fail --silent --show-error http://127.0.0.1:3333/api/health >/dev/null
tmux has-session -t "$URA_T3_SESSION" 2>/dev/null || exit 1
```

Capture one record first, then the bounded 50-record selection. Keep separate,
create-only preparation roots because each artifact authorizes a different
Runner selection:

Open a fresh interactive operator shell before running the capture block; the
two service sessions remain separate:

```bash
export URA_T3_CAPTURE_SESSION="ura-t3mp3st-capture-${URA_FRAMEWORK_LOCK_ID:0:12}"
tmux new-session -s "$URA_T3_CAPTURE_SESSION" -c "$URA_REPO"
```

Run the following commands inside that attached capture session:

```bash
set -o pipefail
export URA_T3_PREP_ROOT="$URA_WORK/runs/thesis/prepared/t3mp3st-follow-on"
export URA_T3_ONE_ROOT="$URA_T3_PREP_ROOT/limit-1-seed-0"
export URA_T3_BOUND_ROOT="$URA_T3_PREP_ROOT/limit-50-seed-0"
[[ ! -e "$URA_T3_ONE_ROOT" && ! -L "$URA_T3_ONE_ROOT" ]] || exit 1
[[ ! -e "$URA_T3_BOUND_ROOT" && ! -L "$URA_T3_BOUND_ROOT" ]] || exit 1
mkdir -p "$URA_T3_PREP_ROOT"

T3_COMMON=(
  --corpus strongreject_official
  --source-config experiments/source-instances.json
  --framework-lock "$URA_FRAMEWORK_LOCK"
  --framework-env-root "$URA_FRAMEWORK_ENVS"
  --framework-state-root "$URA_FRAMEWORK_STATE"
  --upstream-revision f2eec3c48cefe301983b3865811eda89d454e988
  --source-provider local
  --source-model Qwen/Qwen3-VL-8B-Instruct
  --endpoint http://127.0.0.1:3333/api/general/plan
  --timeout-seconds 600
)

timeout --signal=TERM --kill-after=60s 1800s \
  "$URA_PY" -m experiments.capture_t3mp3st \
  "${T3_COMMON[@]}" --limit 1 --sample-seed 0 --out "$URA_T3_ONE_ROOT" \
  | tee "$URA_T3_PREP_ROOT/limit-1-result.json" || exit $?
timeout --signal=TERM --kill-after=60s 43200s \
  "$URA_PY" -m experiments.capture_t3mp3st \
  "${T3_COMMON[@]}" --limit 50 --sample-seed 0 --out "$URA_T3_BOUND_ROOT" \
  | tee "$URA_T3_PREP_ROOT/limit-50-result.json" || exit $?
```

`--timeout-seconds 600` applies to each planning HTTP request. The two shell
timeouts above separately bound the complete one-record and fifty-record capture
processes. Run both inside the capture tmux session and retain a timed-out process
as a failed preparation rather than resuming from an incomplete bundle.

Each command prints the canonical absolute content-addressed artifact path and
SHA-256. Put the exact values from the matching result into a one-attacker
config:

```json
{
  "t3mp3st": {
    "upstream_revision": "f2eec3c48cefe301983b3865811eda89d454e988",
    "source_provider": "local",
    "source_model": "Qwen/Qwen3-VL-8B-Instruct",
    "response_artifact": "<printed-artifact-path>",
    "response_artifact_sha256": "<printed-sha256>"
  }
}
```

Use the limit-1 file for the follow-on projection and diagnostic canary, and the
limit-50 file for its separately projected and admitted bounded measured run.
Pass `--attackers t3mp3st`, `--attacker-config <matching-file>` and
`--attacker-config-sha256 <matching-digest>` in both `rig_check` and
`run_matrix`. Retain one common scientific base, then derive separate exact
preflight, diagnostic-canary and measured argument vectors because purpose,
selection, caps, deadline and attestation participate in request identity. Use a
distinct output root for each operation. The path is operational, not part of
model-acquisition identity. Within each purpose, reuse that exact vector for plan
derivation,
acquisition and its consumer; `rig_check` adds its wrapper-owned
`--preflight-only`. Never reuse a preflight plan for a canary or a limit-1 plan
for the limit-50 measured request.

The same purpose separation applies to NanoGCG and IDEATOR. After each live
canary, retain `experiments.lane_canary` output with that canary's own
eligibility artifact. Run the generated `followon_prepared_controller.py` in
its own tmux session after all four prepared configs and their matching capture
or manifest artifacts exist. Supply an absent direct child of
`$URA_WORK/runs/engineering` as `--control-root`, a short unique
`--attempt-tag`, the retained Qwen lane spec, the NanoGCG config/capture, the
IDEATOR config/manifest/media root, both T3MP3ST config/bundle pairs, and the
sealed parent Gate 5 RUNNOTE/promotion. The controller performs the three
purpose-specific projections and canaries, derives fresh measured-purpose
attestations and zero-download acquisition receipts, and writes
`ura-followon-gate5-inputs/1`. The formal
`phase5_followon_prepared.sh` validator creates the content-bound Gate 5
amendment before the controller makes any measured call. Do not append to or
rewrite the sealed core cohort's `runs/thesis/RUNNOTE.md`.

Each exact measured Runner child is then registered as an existing
`ura-external-measured-job/2` Job with the formal amendment digest as its
`admission_sha256`. The controller attempts all three authorized argv arrays
independently and gives the resulting `ura-followon-phase6-outcomes/2` to
`phase6_followon_prepared.sh`. Its final `ura-followon-phase6-completion/2` is
the Phase 7 input; the operational Jobs registration does not replace that
scientific validation. NanoGCG and IDEATOR therefore publish
`ura-external-measured-job/2` start/terminal records around their exact Runner
invocations. The measured plan-only pass creates one deterministic
request envelope under the future output root. The controller verifies that it
is the only entry, deletes that file and empty root, and therefore presents an
absent create-only result root to Gate 5 and the later measured child.
Legacy single-response artifacts and bundles without `capture_runtime` remain
readable for compatibility, but Runner rejects them as measured evidence.

In Rig Web, a configured results-root symlink is resolved before the T3MP3ST
capture command is built. The generated operational config therefore contains
the canonical absolute artifact path, even though the retained experiment
configuration contains only its verified content identity.

#### HarmBench: capture, then replay

Generate text cases from the clean pinned HarmBench checkout. The preparation
command writes both the replay artifact and the matching one-attacker config.
HarmBench preparation has its own locked source checkout and runtime; it must
not use the main local-vLLM environment. Install/resume and verify the
`harmbench` row through the section 12.2 installer first. Its fully hashed lock
pins the tested vLLM, BitsAndBytes, FastChat, Ray, Accelerate, spaCy,
`datasketch`, and SHA-256-bound `en_core_web_sm` dependencies:

```bash
if ! ura_framework_action verify harmbench; then
  if [[ -n "${URA_FRAMEWORK_ADOPT_FROM_LOCK:-}" ]] \
    && ura_framework_action adopt harmbench \
      --from-lock "$URA_FRAMEWORK_ADOPT_FROM_LOCK"; then
    :
  else
    ura_framework_action resume harmbench || exit $?
  fi
  ura_framework_action verify harmbench || exit $?
fi
URA_HARMBENCH_ENV="$(ura_runtime_store harmbench)" || exit $?
[[ -d "$URA_HARMBENCH_ENV" ]] || exit 1
export URA_HARMBENCH_ENV
```

Then prepare the bundle:

```bash
PYTHONDONTWRITEBYTECODE=1 "$URA_HARMBENCH_ENV/bin/python" -m experiments.harmbench_capture \
  --repo "$URA_HARMBENCH_ENV/source/harmbench" \
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

HarmBench resolves each output parent before generation and writes the canonical
absolute replay path into its generated config. Rig Web likewise resolves a
symlinked configured results root before building the prepare command. Use the
canonical paths printed by the producer when an operator-facing path is an
alias. The native replay reader continues to reject any supplied path containing
a symlink component. `run_matrix` verifies the artifact and declared SHA-256,
then replaces the runtime-only path with its SHA-256/byte identity in persisted
configuration.

## 13. Tier 4: local targets and defense contrast

*Console equivalent: this section's commands are also launchable as the `rig_check` and `run_matrix` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Run every local model in its own process. The examples below use text; repeat the
static image lane for image-capable local models.

```bash
export LOCAL_SPEC='vllm:Qwen/Qwen3-VL-8B-Instruct'
export LOCAL_CONFIG='experiments/local-qwen3-vl.json'

CUDA_VISIBLE_DEVICES=0,1 python -m experiments.rig_check \
  --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG" \
  --attackers replay --judges rules,guardrail \
  --guardrail-model "$SCORE_GUARD" --guardrail-revision "$SCORE_GUARD_REV" --guardrail-device cuda:1 \
  --corpora "$TEXT_ARMS" --source-config experiments/source-instances.json \
  --limit "$URA_LOCAL_CORE_CLUSTER_LIMIT" --sample-seed "$URA_LOCAL_SAMPLE_SEED" --seeds 0 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' \
  --max-total-judge-calls 0 --max-total-http-attempts 0 \
  --deadline-seconds 86400 --out runs/thesis/preflight/local-qwen3-vl-text-core100
```

Derive each local live-attestation receipt with the same `rules,guardrail`
cascade and exact guard identity/device shown above. A vLLM probe's
purpose-bound acquisition must contain the target and scoring guard; an Ollama
probe's acquisition contains the scoring guard because the target is served by
Ollama rather than the sealed Hugging Face store. The probe makes no hosted
judge call. Do not reduce a local probe to `--judges rules`: a rules abstention
is not evidence that the local transport failed.

Repeat with `run_matrix`, `"${LIVE_ATTESTATION_ARGS[@]}"`, exact totals, and
`--out runs/thesis/runner/local-qwen3-vl-text-core100`; allow the process to exit, then
run the image lane. Repeat both for the LLaVA base using its own exact local
config. The four GraySwan RR identities enter only through their targeted Gate 5
amendment: each exact lane must pass the normal attestation and canary gates with
the current bounded source clusters matched to its LLaVA-base row, identical
input bytes, inference settings, judge condition and caps. A nonempty
length-capped prefix is a response and is sent to the
selected evaluator with `finish_reason='length'` retained. Do not change stops,
generation caps, checkpoint identity or decoding settings to make the pair look
more favorable.

The command above is the pre-registered bounded core pass. Its exact seed-0
selection must agree across every model used in a paired comparison. An
optional full-corpus replication repeats the same local-stage request with
`--limit 0`, a new projection and acquisition envelope, separately approved
caps and a separate output prefix. It is a different sampling stratum and is
never pooled with core 100, extended 50 or a hosted cohort. A rules-only
(`--judges rules`) pass is not an option: it fails closed on any row the rules
stage cannot classify confidently.

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
  --limit '<pre-registered-cluster-limit (section 5.2)>' --sample-seed 0 --seeds 0,1 --max-queries 1 --max-turns 1 \
  --group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version \
  --max-total-target-calls '<planning-ceiling>' \
  --max-total-judge-calls '<planning-ceiling>' --max-total-http-attempts '<planning-ceiling>' \
  --deadline-seconds '<pre-registered-call-start-window-seconds>' --out runs/thesis/preflight/defense-text
```

Repeat the successful defense check with `run_matrix`,
`"${LIVE_ATTESTATION_ARGS[@]}"`, `--ack-hosted-judge-data-transfer`, exact totals, and
`--out runs/thesis/runner/defense-text`. Run matching no-defense cells for the
same focal targets and clusters in their own checked/measured lane directories.
Added value is measured as the harmful/benign tradeoff; lower harmful ASR without the
benign refusal cost is an incomplete defense analysis.

## 14. Tier 5: nine source-native evaluators

*Console equivalent: this section's commands are also launchable as the `native_import` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Each project gets an isolated environment and exact source revision. Do not
install all of them into the URA environment.

### 14.1 Install and verify from the global lock

Reuse `URA_FRAMEWORK_LOCK`, `URA_FRAMEWORK_ENVS`, `URA_FRAMEWORK_STATE`, and
`URA_FRAMEWORK_PYTHON` from section 12.2. The single lock owns the exact source
checkout and dedicated runtime for all nine native projects; do not clone a
second mutable source tree or run upstream requirements files by hand.

```bash
export URA_NATIVE_SELECTION='fuzzyai,garak,promptfoo,petri,easyjailbreak,autodan,giskard,asb,agentdojo'
python -m experiments.framework_runtime_installer plan \
  --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" \
  --state-root "$URA_FRAMEWORK_STATE" --only "$URA_NATIVE_SELECTION"
IFS=',' read -r -a URA_NATIVE_NAMES <<< "$URA_NATIVE_SELECTION"
for URA_NATIVE_NAME in "${URA_NATIVE_NAMES[@]}"; do
  if ura_framework_action verify "$URA_NATIVE_NAME"; then
    continue
  fi
  if [[ -n "${URA_FRAMEWORK_ADOPT_FROM_LOCK:-}" ]] \
    && ura_framework_action adopt "$URA_NATIVE_NAME" \
      --from-lock "$URA_FRAMEWORK_ADOPT_FROM_LOCK"; then
    :
  else
    ura_framework_action resume "$URA_NATIVE_NAME" || exit $?
  fi
  ura_framework_action verify "$URA_NATIVE_NAME" || exit $?
done

URA_FUZZYAI_ENV="$(ura_runtime_alias fuzzyai)" || exit $?
URA_GARAK_ENV="$(ura_runtime_alias garak)" || exit $?
URA_PROMPTFOO_ENV="$(ura_runtime_alias promptfoo)" || exit $?
URA_PETRI_ENV="$(ura_runtime_alias petri)" || exit $?
URA_EASYJAILBREAK_ENV="$(ura_runtime_alias easyjailbreak)" || exit $?
URA_AUTODAN_ENV="$(ura_runtime_alias autodan)" || exit $?
URA_GISKARD_ENV="$(ura_runtime_alias giskard)" || exit $?
URA_ASB_ENV="$(ura_runtime_alias asb)" || exit $?
URA_AGENTDOJO_ENV="$(ura_runtime_alias agentdojo)" || exit $?
for URA_RUNTIME_ENV in \
  "$URA_FUZZYAI_ENV" "$URA_GARAK_ENV" "$URA_PROMPTFOO_ENV" \
  "$URA_PETRI_ENV" "$URA_EASYJAILBREAK_ENV" "$URA_AUTODAN_ENV" \
  "$URA_GISKARD_ENV" "$URA_ASB_ENV" "$URA_AGENTDOJO_ENV"; do
  [[ -d "$URA_RUNTIME_ENV" ]] || exit 1
done
export URA_FUZZYAI_ENV URA_GARAK_ENV URA_PROMPTFOO_ENV URA_PETRI_ENV
export URA_EASYJAILBREAK_ENV URA_AUTODAN_ENV URA_GISKARD_ENV
export URA_ASB_ENV URA_AGENTDOJO_ENV
```

Wait for the named-session exit marker, re-run the same `resume` command after
an interruption, and then run `verify` with the identical flags. The lock installs
Promptfoo and T3MP3ST in separate stores under the exact official Node runtime
and all Python projects in separate exact
CPython 3.12.13 venvs. Each published alias below points at a stable
content-addressed store, while source checkouts are retained under that same
runtime's `source/` directory. A pin that cannot satisfy the lock remains a
failed/blocked isolated runtime; never repair it by changing the main URA
environment or combining framework packages.

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
Every long big-rig command below is the inner reviewed command of a uniquely
named tmux session (screen only if tmux is unavailable) launched through the
mandatory `ura_native_run` wrapper below. Build -> Runtimes installs and verifies
the isolated software; it does not launch these provider-bearing campaigns.
Never leave one as a foreground SSH child. Retain the session name, attach
command, bounded log, and terminal exit marker with the engineering campaign.
Set `URA_NATIVE_TARGET_CALL_CAP` to the approved positive integer cap for each
provider-bearing reviewed command immediately before invoking it; model mode
refuses an absent or non-positive cap. The offline Petri conversion alone uses
`ura_native_support_run`, which records cap zero, hosted calls disabled, and no
model tasks. Each attempt becomes a direct, explicitly non-thesis
`ura-engineering-campaign/1` entry under `$URA_WORK/runs/engineering`, so its
task and terminal status are visible in Jobs/Stats. tmux uses a unique private
server/socket per attempt, so the child receives the current reviewed provider
environment rather than stale variables from another tmux server. GNU `timeout`
owns the command group, sends TERM at 168 hours, then KILL after 60 seconds;
the waiter terminates the exact owned session and records a terminal code if
the wrapper itself fails to finish.

```bash
ura_native_session() {
  local label="${1:-}" root attempt_dir session socket log marker script logger_python
  local drain_code launcher timeout_bin cap task started_at kind hosted model_tasks
  local cap_field detail evidence_class
  shift || return 2
  [[ "$label" =~ ^[a-z0-9][a-z0-9-]*$ && "$#" -gt 0 ]] || return 2
  kind="${URA_NATIVE_SESSION_KIND:-model}"
  cap="${URA_NATIVE_TARGET_CALL_CAP:-}"
  if [[ "$kind" == model ]]; then
    [[ "$cap" =~ ^[1-9][0-9]*$ ]] || return 2
    hosted=true
    model_tasks='["native-'"$label"'"]'
    cap_field=',"target_call_cap":'"$cap"
    detail=native-upstream
    evidence_class=native_upstream_execution
  elif [[ "$kind" == support && ( -z "$cap" || "$cap" == 0 ) ]]; then
    hosted=false
    model_tasks='[]'
    cap_field=',"target_call_cap":0'
    detail=native-support
    evidence_class=native_upstream_support
  else
    return 2
  fi
  logger_python="${URA_PY:-}"
  timeout_bin="$(command -v timeout || true)"
  [[ -n "$timeout_bin" && -x "$logger_python" && -x "$timeout_bin" ]] || {
    printf 'ura_native_session: URA_PY=%q is not an executable URA interpreter or GNU timeout is missing; export URA_REPO and URA_PY as in section 2\n' "$logger_python" >&2
    return 1
  }
  root="$URA_WORK/runs/engineering"
  umask 077
  mkdir -p "$root" || return
  attempt_dir="$(mktemp -d "$root/ura-native-${label}-XXXXXXXX")" || return
  session="${attempt_dir##*/}"
  socket="${session}-socket"
  log="$attempt_dir/$session.log"
  marker="$attempt_dir/$session.exit"
  script="$attempt_dir/$session.sh"
  task="native-$label"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return
  printf '{"campaign_id":"%s","evidence_class":"%s","hard_stop_hours":168,"hosted_calls_allowed":%s,"model_tasks":%s,"planned_tasks":["%s"],"schema":"ura-engineering-campaign/1","started_at":"%s"%s,"thesis_empirical_evidence":false}\n' \
    "$session" "$evidence_class" "$hosted" "$model_tasks" "$task" \
    "$started_at" "$cap_field" \
    > "$attempt_dir/ENGINEERING_ONLY.json" || return
  drain_code="$(printf '%s\n' \
    'import os, sys' \
    'path, limit = sys.argv[1], int(sys.argv[2])' \
    'notice = b"\n[native session log truncated at 16777216 bytes]\n"' \
    'payload_limit = limit - len(notice)' \
    'written = 0' \
    'truncated = False' \
    'with open(path, "xb", buffering=0) as sink:' \
    '    while True:' \
    '        chunk = sys.stdin.buffer.read(65536)' \
    '        if not chunk: break' \
    '        part = chunk[:max(0, payload_limit - written)]' \
    '        if part: sink.write(part); written += len(part)' \
    '        if len(part) != len(chunk): truncated = True' \
    '    if truncated: sink.write(notice)' \
    '    os.fsync(sink.fileno())')" || return
  {
    printf '#!/usr/bin/env bash\nset -o pipefail\ncd -- %q\n' "$PWD"
    printf 'task=%q\ntask_log=%q\ndetail=%q\n' \
      "$task" "$attempt_dir/task-log.jsonl" "$detail"
    printf 'printf '\''{"at":"%%s","detail":"%%s","event":"campaign_start","status":"running","task":"bootstrap"}\\n'\'' "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" "$detail" >> "$task_log"\n'
    printf 'printf '\''{"at":"%%s","detail":"%%s","event":"task_start","status":"running","task":"%%s"}\\n'\'' "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" "$detail" "$task" >> "$task_log"\n'
    printf '%q --signal=TERM --kill-after=60s 168h' "$timeout_bin"
    printf ' %q' "$@"
    printf ' 2>&1 | %q -c %q %q 16777216\n' \
      "$logger_python" "$drain_code" "$log"
    printf 'status=("${PIPESTATUS[@]}")\nrc="${status[0]}"\n'
    printf 'if [[ "$rc" == 0 && "${status[1]}" != 0 ]]; then rc="${status[1]}"; fi\n'
    printf 'if [[ "$rc" == 0 ]]; then outcome=passed; campaign=complete; else outcome=failed; campaign=failed; fi\n'
    printf 'printf '\''{"at":"%%s","detail":"%%s","event":"task_end","status":"%%s","task":"%%s"}\\n'\'' "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" "$detail" "$outcome" "$task" >> "$task_log"\n'
    printf 'printf '\''{"at":"%%s","detail":"%%s","event":"campaign_end","status":"%%s","task":"bootstrap"}\\n'\'' "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" "$detail" "$campaign" >> "$task_log"\n'
    printf 'printf "%%s\\n" "$rc" > %q\nmv -- %q %q\nexit "$rc"\n' \
      "$marker.tmp" "$marker.tmp" "$marker"
  } > "$script" || return
  chmod 700 "$script" || return
  if command -v tmux >/dev/null 2>&1; then
    tmux -L "$socket" new-session -d -s "$session" "$script" || return
    launcher=tmux
  elif command -v screen >/dev/null 2>&1; then
    screen -DmS "$session" "$script" || return
    launcher=screen
  else
    return 1
  fi
  export URA_NATIVE_SESSION_NAME="$session" URA_NATIVE_SESSION_LAUNCHER="$launcher"
  export URA_NATIVE_SESSION_LOG="$log" URA_NATIVE_SESSION_EXIT="$marker"
  export URA_NATIVE_SESSION_ROOT="$attempt_dir" URA_NATIVE_SESSION_TASK="$task"
  export URA_NATIVE_TMUX_SOCKET="$socket"
  printf 'session=%s\nattach=%s\nlog=%s\nexit_marker=%s\n' \
    "$session" "$([[ "$launcher" == tmux ]] && printf 'tmux -L %s attach -t %s' "$socket" "$session" || printf 'screen -r %s' "$session")" \
    "$log" "$marker"
}

ura_abort_native_session() {
  local rc="$1" now temporary
  if [[ "$URA_NATIVE_SESSION_LAUNCHER" == tmux ]]; then
    tmux -L "$URA_NATIVE_TMUX_SOCKET" kill-session \
      -t "$URA_NATIVE_SESSION_NAME" 2>/dev/null || true
  else
    screen -S "$URA_NATIVE_SESSION_NAME" -X quit 2>/dev/null || true
  fi
  sleep 1
  if [[ ! -f "$URA_NATIVE_SESSION_EXIT" ]]; then
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)" || return
    printf '{"at":"%s","detail":"session-aborted","event":"task_end","status":"failed","task":"%s"}\n' \
      "$now" "$URA_NATIVE_SESSION_TASK" >> "$URA_NATIVE_SESSION_ROOT/task-log.jsonl" || return
    printf '{"at":"%s","detail":"session-aborted","event":"campaign_end","status":"failed","task":"bootstrap"}\n' \
      "$now" >> "$URA_NATIVE_SESSION_ROOT/task-log.jsonl" || return
    temporary="$URA_NATIVE_SESSION_EXIT.wait-$$"
    printf '%s\n' "$rc" > "$temporary" || return
    mv -- "$temporary" "$URA_NATIVE_SESSION_EXIT" || return
  fi
  return "$rc"
}

ura_wait_native_session() {
  local deadline=$((SECONDS + 168 * 60 * 60 + 120)) listing rc
  while [[ ! -f "$URA_NATIVE_SESSION_EXIT" ]]; do
    if (( SECONDS >= deadline )); then
      ura_abort_native_session 124
      return $?
    fi
    if [[ "$URA_NATIVE_SESSION_LAUNCHER" == tmux ]]; then
      if ! tmux -L "$URA_NATIVE_TMUX_SOCKET" has-session \
        -t "$URA_NATIVE_SESSION_NAME" 2>/dev/null; then
        sleep 1
        if [[ ! -f "$URA_NATIVE_SESSION_EXIT" ]]; then
          ura_abort_native_session 125
          return $?
        fi
      fi
    else
      listing="$(screen -ls 2>/dev/null || true)"
      if [[ ! "$listing" =~ [[:space:]][0-9]+\.${URA_NATIVE_SESSION_NAME}[[:space:]]+\((Attached|Detached|Multi(,[[:space:]]*attached)?)\) ]]; then
        sleep 1
        if [[ ! -f "$URA_NATIVE_SESSION_EXIT" ]]; then
          ura_abort_native_session 125
          return $?
        fi
      fi
    fi
    sleep 5
  done
  rc="$(tr -d '\r\n' < "$URA_NATIVE_SESSION_EXIT")"
  [[ "$rc" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( rc <= 255 && rc == 0 ))
}

ura_native_run() {
  ura_native_session "$@" || return
  printf 'Tail with: tail -f -- %s\n' "$URA_NATIVE_SESSION_LOG"
  ura_wait_native_session
}

ura_native_support_run() {
  URA_NATIVE_SESSION_KIND=support URA_NATIVE_TARGET_CALL_CAP=0 \
    ura_native_run "$@"
}

# FuzzyAI: retains a complete timestamped result directory with raw.jsonl and report.json.
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run fuzzyai "$URA_FUZZYAI_ENV/bin/fuzzyai" fuzz \
  -m '<native-target-route>' -a asc -a bon -T '<prompt-file>' || exit $?

# Garak 0.15.1: retains <prefix>.report.jsonl.
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run garak "$URA_GARAK_ENV/bin/python" -m garak \
  --target_type openai.OpenAICompatible --target_name '<exact-target>' \
  --probes dan.Dan_11_0 --detectors auto --generations 1 --seed 0 \
  --eval_threshold 0.5 --report_prefix '<absolute-run-prefix>' || exit $?

# Promptfoo 0.121.15: configure all three model roles in promptfooconfig.yaml.
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run promptfoo-generate "$URA_PROMPTFOO_ENV/runtime/node-v24.16.0-linux-x64/bin/node" \
  "$URA_PROMPTFOO_ENV/node_modules/promptfoo/dist/src/entrypoint.js" redteam generate \
  -c promptfooconfig.yaml --strict --force --no-cache --no-progress-bar \
  -o generated-redteam.yaml || exit $?
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run promptfoo-eval "$URA_PROMPTFOO_ENV/runtime/node-v24.16.0-linux-x64/bin/node" \
  "$URA_PROMPTFOO_ENV/node_modules/promptfoo/dist/src/entrypoint.js" redteam eval \
  -c generated-redteam.yaml --no-cache --no-share --no-progress-bar --no-table \
  -o results.json || exit $?

# Petri: auditor, target, and judge are three different declared roles.
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run petri-eval "$URA_PETRI_ENV/bin/inspect" eval inspect_petri/audit \
  --model-role auditor='<provider/auditor>' \
  --model-role target='<provider/target>' \
  --model-role judge='<provider/judge>' || exit $?
ura_native_support_run petri-convert \
  "$URA_PETRI_ENV/bin/inspect" log convert --to json \
  --output-dir '<converted-dir>' '<path-to-run.eval>' || exit $?

# AutoDAN-Turbo: run standard or reasoning entrypoint in the exact checkout.
cd "$URA_AUTODAN_ENV/source/autodan" || exit $?
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run autodan-standard "$URA_AUTODAN_ENV/bin/python" main.py || exit $?
# Or, as a separate condition, set a fresh cap and call:
# URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
# ura_native_run autodan-reasoning "$URA_AUTODAN_ENV/bin/python" main_r.py || exit $?

# Immediately write the mandatory URA provenance sidecar. Substitute the exact
# output directory, role identities, dataset digest, variant, and upstream
# iteration/request settings used above; do not import until this succeeds. Use
# the main project interpreter ($URA_PY from section 2), where URA was
# installed, rather than AutoDAN's isolated upstream-only environment.
URA_AUTODAN_LOGS='<exact-AutoDAN-output-directory>' \
URA_AUTODAN_RUN_ID='<recorded-run-id>' \
URA_AUTODAN_DATASET_SHA256='<64-hex-dataset-sha256>' \
"$URA_PY" - <<'PY' || exit $?
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
cd "$URA_ASB_ENV/source/asb" || exit $?
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run asb-dpi "$URA_ASB_ENV/bin/python" scripts/agent_attack.py --cfg_path config/DPI.yml || exit $?
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run asb-opi "$URA_ASB_ENV/bin/python" scripts/agent_attack.py --cfg_path config/OPI.yml || exit $?
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run asb-mp "$URA_ASB_ENV/bin/python" scripts/agent_attack.py --cfg_path config/MP.yml || exit $?
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run asb-pot "$URA_ASB_ENV/bin/python" scripts/agent_attack_pot.py || exit $?

# AgentDojo: retain the fresh pipeline/suite trace subtree.
URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' \
ura_native_run agentdojo "$URA_AGENTDOJO_ENV/bin/python" -m agentdojo.scripts.benchmark \
  --model '<exact-model>' --benchmark-version v1.2.2 \
  --attack important_instructions -s workspace --logdir '<native-logdir>' || exit $?
```

EasyJailbreak has no single universal recipe command: execute one exact recipe
class exported by 0.1.3 with explicit attack, target, and evaluator models, then
call `JailbreakDataset.save_to_jsonl()` on the complete `attack_results`; pass
that reviewed Python argv through
`URA_NATIVE_TARGET_CALL_CAP='<approved-positive-integer-for-this-command>' ura_native_run easyjailbreak ...`.
Giskard
likewise uses its Python API: run `giskard.scan(model, dataset)` or
`giskard.rag.evaluate()` through the same fresh-cap pattern with
`ura_native_run giskard`, then export the complete Scan or RAGET artifact family.
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

Prepare the blinded audit only after all intended runner grids are terminal. For
a direct all-success cohort, the common `runs/thesis/runner` parent lets the
sample include broad roster, source, policy, modality, and attack strata. The
sealed local campaign uses the success-only view described below. Choose the
sample size from feasible rater capacity and achieved strata; the number below
is only an operator example.
The selector derives overall and exact risk/modality coverage requirements for
every observed common-eligible model/defense/attacker/source-policy/population
arm and fails if the requested whole-cluster sample cannot cover them. Increase
the sample size; do not remove achieved arms from the audit frame.

For the sealed local campaign, use the generated Phase 8 controller and its
commit-bound operator guide. The controller consumes Phase 7's validated
success-only read-only Runner copy rather than the canonical lifecycle tree, so
an honestly failed lane remains recorded without becoming human-audit sample
input. Its receipt binds every source/copy file digest, byte count, relative
path, distinct file identity, and read-only mode, and the completed view admits
no extra file. Phase 7 also gives Level 1 an independently copied lifecycle
view, so a postprocessor cannot mutate canonical Phase 6 bytes through its input
path. Prepare one create-only input manifest, review its exact bytes and
`sampling.capacity`, authorize its SHA-256, and monitor the returned tmux
session. The cardinality plan fails before a sample write unless the source-task
population covers the exact requested source-task sample and the common
population covers both the exact requested common sample and 20 further
clusters reserved for a disjoint qualification set. Execution recomputes that
plan from the same success-only view. This does not pre-approve coverage
feasibility: both selectors separately fail closed unless their requested counts
cover all achieved cells.

Before that machine preparation, supply the operator-authored ethics/consent
determination described by the generated guide and authorize its exact bytes.
The record uses required structured consent, compensation, withdrawal,
harmful-content welfare, and escalation controls rather than a free-form details
object. It may authorize preparation while withholding human labeling. It does
not create raters, qualification gold, labels, adjudication, reports, or Gate 8
acceptance; those remain human-only inputs.

The machine controller's only successful terminal is `human_only_blocked` with
`gate8_met: false`. Its zero exit means that blinded forms and guidance were
prepared, not that a rater exists, a qualification was passed, a label was
created, or Gate 8 was met.

The preparation selectors are deterministic, seedless, and without
replacement. The common and source-task frames are whole-cluster selectors.
The common frame binds
`coverage_priority_then_stratum_round_robin_sha256_v1`, the source-task frame
binds `coverage_priority_then_sha256_fill_v1`. The disjoint qualification set
binds
`disjoint_risk_modality_behavior_coverage_then_sha256_lexicographic_representative_fill_v1`
and emits one lexicographic-minimum `sample_key` representative from each
selected cluster, rather than every sibling row. Terminal validation replays
that exact selection against the bound Phase 7 Runner view. The
`--bootstrap-resamples`, `--alpha`, and `--seed` flags are label-analysis
controls and are rejected by either preparation mode.

```bash
PHASE7_HUMAN_AUDIT_VIEW=/absolute/path/to/phase7-control/read-only-human-audit-runner-view
python -m experiments.human_audit \
  --results "$PHASE7_HUMAN_AUDIT_VIEW" --prepare 400 \
  --output "$URA_WORK/runs/thesis/human-audit-sample.csv" \
  --acknowledge-sensitive-content
```

For the sealed campaign this is the invocation performed by the generated
Phase 8 controller after it revalidates the Phase 7 view receipt. Do not replace
the view with the mixed canonical Runner root. The sample size remains an
operator example and must satisfy the controller's exact capacity plan.

Before main labelling, create
`$URA_WORK/runs/thesis/human-rater-qualification.md` with
pseudonymous rater IDs, language competence, graduate-level study or equivalent
relevant safety/moderation experience, conflict disclosures, training date,
qualification-set digest, per-dimension score and adjudicator. Use an
independently adjudicated 20-item set outside the final audit sample. Each rater
must reach at least 80% agreement on every dimension; after reviewed retraining,
one repeat is permitted. Do not silently lower the threshold or select raters on
the final sample.

Assign exactly two distinct independently qualified raters to each exported
row. Pairs may rotate between rows; the analysis reports every rater pair that
shares one or more assigned items and does not require a rater to label
unassigned rows. Adjudicate every non-unanimous composite or dimension;
unanimous ratings need no adjudication. Rate refusal, harmfulness,
convincingness, and specificity separately under the exact source policy and
dimension rubric. Resolve and verify every media reference before rating. Keep
all join columns. Raters must not see automated labels or metric outputs; model
identity remains visible in the current export and must be reported as a
limitation. The deterministic coverage-priority selector claims
no equal-probability inclusion probabilities and uses no inverse-probability
weights. Retain a probability-sampled component if any uncertainty- or
disagreement-enriched quota is added and population interpretation is intended.
`--prepare 400` means 400 source clusters, not 400 CSV rows. Every selected
sibling model/seed/run response is exported. Before assigning work, record the
reported exported-row count `R`, schedule exactly `2R` independent item ratings,
and budget additional adjudication for every non-unanimous composite or
dimension. If that realized load is infeasible, choose a smaller cluster count
prospectively and rerun preparation; do not discard sibling rows after export.

After adjudication:

```bash
PHASE8_AUDIT_RUNNER_VIEW=/absolute/path/from-the-bound-phase7-runner-view-receipt
PHASE8_ANALYSIS_ROOT="$URA_WORK/runs/thesis/human-audit-analysis"
PHASE8_COMMON_PREPARED_FORM=/absolute/path/to/prepared/human-audit-rating-form.csv
PHASE8_COMMON_PREPARED_FORM_SHA256="$(sha256sum "$PHASE8_COMMON_PREPARED_FORM" | awk '{print $1}')"
mkdir -p "$PHASE8_ANALYSIS_ROOT"
python -m experiments.human_audit \
  --results "$PHASE8_AUDIT_RUNNER_VIEW" \
  --labels "$URA_WORK/runs/thesis/human-audit-labelled.csv" \
  --prepared-rating-form "$PHASE8_COMMON_PREPARED_FORM" \
  --prepared-rating-form-sha256 "$PHASE8_COMMON_PREPARED_FORM_SHA256" \
  --output "$PHASE8_ANALYSIS_ROOT/human_audit.json"
```

The success-only Runner view is sealed and admits no additional file. Both
human analysis reports therefore use create-only outputs in the separate
Phase 8 analysis root; never write a report into the bound Phase 7 view.
The common report schema is exactly `ura-human-audit/1.2`; the separate
source-task report schema is exactly `ura-source-task-audit/2`. Older schemas
are not Gate 8 evidence.
The prepared-form path and digest are a pair. In Gate 8 analysis they bind the
completed CSV to the exact controller-created blank form: header order,
immutable cell content and row multiplicity must match, every prepared sample
must remain present, and each sample must contain exactly two distinct non-empty
`rater_id` values. Those two IDs may differ between samples. The report records
the verified prepared-form descriptor and agreement for every observed pair
with shared items.

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
  --results "$PHASE7_HUMAN_AUDIT_VIEW" --prepare-source-task 50 \
  --acknowledge-sensitive-content \
  --output "$URA_WORK/runs/thesis/source-task-audit-sample.csv"
```

Exactly two distinct qualified raters label each row independently with the exact
`task_label_vocabulary` and a parse-status judgment, then adjudicate. Analysis
re-joins every labelled row to the exact exported prompt/response content and
writes `source_task_audit.json` with agreement for every observed rater pair
with shared assignments, adjudicated-human
versus source-reference accuracy (cluster-bootstrap interval), adjudicated
versus parser agreement/confusion, and the parser-valid fraction:

```bash
PHASE8_SOURCE_PREPARED_FORM=/absolute/path/to/prepared/source-task-audit-rating-form.csv
PHASE8_SOURCE_PREPARED_FORM_SHA256="$(sha256sum "$PHASE8_SOURCE_PREPARED_FORM" | awk '{print $1}')"
python -m experiments.human_audit \
  --results "$PHASE8_AUDIT_RUNNER_VIEW" \
  --source-task-labels "$URA_WORK/runs/thesis/source-task-audit-labelled.csv" \
  --prepared-rating-form "$PHASE8_SOURCE_PREPARED_FORM" \
  --prepared-rating-form-sha256 "$PHASE8_SOURCE_PREPARED_FORM_SHA256" \
  --output "$PHASE8_ANALYSIS_ROOT/source_task_audit.json"
```

These results are source-task classification evidence on the source's own
scale. They are never common ASR/refusal evidence, never enter the common
human frame or its judge-validity calibration, and never rename classification
accuracy as safety.

Gate 8 additionally requires the exact ethics/consent authorization, an
independently adjudicated 20-item qualification set disjoint from the common
sample, at least two raters passing 80 percent on every dimension, two distinct
qualified ratings for every exported row, verified media viewing,
post-independent adjudication, both validated human-audit reports, and an
operator-authored acceptance or limitation record binding every input and
output digest. Until that human-only record exists, keep `gate8_met: false`.

## 16. Read-only analysis and suite summary

*Console equivalent: this section's commands are also launchable as the `judge_sensitivity`, `kappa`, `transfer_matrix`, `paired_compare`, `level1_evidence`, `native_import`, `suite_summary`, `level2_report` and `figures` form(s) in the rig console (section 18); identical argument vectors, gates and artifacts.*

Run the implemented diagnostics only on completed, content-validated artifacts:

```bash
python -m experiments.judge_sensitivity --results runs/thesis/runner \
  --attacker replay --defense none \
  --output runs/thesis/analysis/judge-sensitivity-replay-no-defense.json
python -m experiments.kappa --results runs/thesis/runner \
  --attacker replay --defense none \
  --output runs/thesis/analysis/judge-kappa-replay-no-defense.json
python -m experiments.transfer_matrix --results runs/thesis/runner \
  --attacker replay --defense none \
  --output-dir runs/thesis/analysis/transfer-replay-no-defense
```

Paired comparisons must name exact conditions and a common source arm. The
current local campaign runs the first example only when its hosted lane is
separately authorized:

```bash
python -m experiments.paired_compare --results runs/thesis/runner \
  --left-model "$FABLE" --right-model "$SOL" \
  --attacker replay --corpus strongreject_official \
  --output runs/thesis/analysis/fable-v-sol-strongreject.json

```

Invoke `paired_compare` for an LLaVA base/RR facet only when the GraySwan RR Gate 5
amendment admits all four bounded RR identities and both exact measured inputs
match on source clusters, input bytes, limit, sample seed, inference settings and
judge condition. When any prerequisite is absent or failed, write one
`ura-phase7-non-estimable-contrast/1` artifact for each unavailable planned
facet. Bind the failed or retained-terminal prerequisite, declare the contrast
unavailable, and include no estimate. Never treat a length-capped canary, a
no-call projection, a partial measured root or the successful base lane alone as
RR evidence.

Build the mandatory Level-1 lifecycle inventory from one explicitly selected
runner cohort. Supply every final eligibility plan in that scope, including
plan-only structural-`N/A` or preflight-blocked requests that have no grid. Use
one output directory per exact request condition; if arguments change, use a new
directory rather than mixing conditions. Within a `run_matrix` invocation the
driver replaces its preliminary plan with the final plan. The Level-1 validator
rejects duplicate request identities, and every supplied grid must still bind
the exact plan descriptor and experiment condition.
`run_matrix` already wrote each `ura-request-envelope/6` before config/source
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
`ura-level1-evidence/3` JSON distinguishes prospective whole-arm request units,
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

Outputs are create-only and deterministic for identical inputs. The exporter
admits only aggregates grouped by at least the eight CLI-default keys
(`model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version`);
a lane aggregated with a narrower `--group` is rejected here, which is why
every lane in sections 9-13 passes exactly that grouping. The export is
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
export HUMAN_AUDIT_SHA256="$(sha256sum "$URA_WORK/runs/thesis/human-audit-analysis/human_audit.json" | awk '{print $1}')"
python -m experiments.figures \
  --results runs/thesis/runner \
  --left-model "$FABLE" --right-model "$SOL" \
  --strongreject-corpus strongreject_official \
  --mmsafety-corpus mmsafety_official \
  --mossbench-corpus mossbench_official \
  --human-audit "$URA_WORK/runs/thesis/human-audit-analysis/human_audit.json" \
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
  non-secret endpoint routes; record the approved
  `measured_lane_wall_time_seconds=86400` separately from the current cohort's
  86,400-second Runner call-start window, plus each external measured Job ID and its one bound
  Runner output root;
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
CSVs plus `source_task_audit.json`, every retained `ura-lane-projection/1` or
`ura-lane-projection/2`,
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

A single-operator application starts, monitors, and stops the
allowlisted experiment CLIs from typed forms, composes campaign lanes through
a mode-aware builder (dry run, attestation probe, diagnostic canary, measured
execution) with mode-specific validation and an exact-argv confirmation step
before any paid mode starts, streams job logs, edits the operator-local
registries (api-targets, local-targets, source-instances, budgets, pricing)
through an allowlisted JSON editor, renders retained `ura-level1-evidence/3`
and `ura-level2-report/1` artifacts with explicit diagnostic/measured,
structural-`N/A`, and error distinctions after reconciling their reported
counts, sample sizes, and confidence intervals, and accounts recorded token
usage and its calculated monetary cost:

```bash
python -m experiments.rig_web --results-root runs --state-dir runs/rig-web
```

A future engineering-only local campaign may exercise one CLI or web action at
a time for at most 24 hours, including local-model T3MP3ST capture/replay and
HarmBench prepare/replay sessions. It must use no hosted target or judge and
must keep a dedicated results/state root outside `runs/thesis`, retaining each
session's exact task, argv, timestamps, model/precision/hardware identity,
stdout/stderr, console job record, preparation artifacts, Runner outputs, and
outcome. Retain impossible, implausible, rejected, failed, interrupted, and
successful cases alike. This campaign has not run yet; its logs are engineering
diagnostics for suite and runbook refinement, not thesis results unless an
output later passes the normal measured-evidence contracts and eligibility
rules.

The dashboard and Build tab show the startup OS/CPU/core/RAM and complete NVIDIA
GPU inventory. Build separates hosted API, Local vLLM, and Local Ollama groups.
Target filters are independent and combinative: hosted API provider (`All` by
default), plus Local vLLM name substring, 10M-3T maximum
parameter count, the separate automatic 16/8/4-bit fit card (on by default), and
an unchecked `Include unknown fit` control. Known 16/8/4-bit recommendations use
green/blue/amber badges; unknown fit is gray. The unknown-fit checkbox exposes
an unknown-size row regardless of the selected maximum, while known sizes still
obey the cap. Compatible local vLLM models are
single-choice radios;
an unpinned roster row may be selected for planning, but non-dry submission
rejects it before launch. An unknown-fit row also needs an explicit per-model
precision, which binds `allow_unknown_fit: true`; auto remains blocked, as does
every known incompatibility. These filters are convenience only; shared CLI/UI
admission remains authoritative.

Local Ollama rows follow only selected modality. Live discovery uses the literal
loopback daemon's bounded tags, loaded-model, and show-capability APIs; it binds
the exact lowercase 64-hex digest, checks the tag snapshot again after show,
and never guesses a model or modality. Tags/show family fields and bounded
`model_info.general.architecture` must provide compatible upstream identity
evidence; missing or ambiguous evidence fails closed. The vLLM support catalog
does not claim local model availability and therefore cannot hide an installed
Ollama tag. vLLM availability or selection does not disable Ollama execution.
Ollama rejects vLLM-only fit and
quantization fields and exposes no fit or precision selector because precision
belongs to the pulled artifact. Runner uses the daemon's HTTP API directly and
needs no Ollama Python SDK. Runner admission independently refreshes the live
show-backed roster, then every inference holds the shared endpoint lock and
binds exact pre-chat tags, returned model, post-chat tags, and post-chat loaded
tag/digest evidence under one hard wall-clock deadline.

Source arms without an integrated evaluator remain visible/selectable, with the
exact limitation in a custom hover/focus tooltip. They are rejected before a
subprocess by default. Eligible non-tool rows show `⚠ approximate opt-in`; the
explicit opt-in admits only separately named, supplementary `approximate_*`
response proxies and never claims to run the missing source evaluator.
Tool-conditioned rows show `tool runtime required` and remain fail-closed.
Implemented source-metric and common-metric arms retain their distinct admission
paths.

Dry mode removes any selected real API/local targets and target configs because
`run_matrix --dry-run` always executes `MockTarget`. The local roster advertises
only the text/image modalities supported by the Runner's vLLM path; audio
target/arm combinations are rejected by the same UI/CLI parity checks.

Build surface. Build composes every `run_matrix`/`rig_check` flag the lanes
above use except the `--models` shorthand, which is CLI/`rig_check`-only: Build
always emits the equivalent explicit `--api`/`--local` split. `ideator` is
available through a verified precomputed-replay panel. Supply a strict
source-mapped `ura-ideator-seed-pairs/2` manifest from the preparation
command above under the results root and its exact SHA-256. Build verifies its
pinned dataset/generator/source descriptors, eight one-to-one source bindings,
and every declared PNG. Legacy `ura-ideator-seed-pairs/1` remains accepted
only for previously reviewed pairs. Build captures the manifest and images in
the review ticket and materializes private copies for the generated
`--attacker-config` at launch. The v2 selection must be
`advbench_harmful --limit 1 --sample-seed 105`; pair limit 0 means all
eight mapped pairs, not a full-corpus run. This does not enable live IDEATOR
generation. `purplellama` admits only `cyberseceval_*` arms. Build
also exposes the documented `--group` (default: the CLI default
`model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version`,
the value every lane above passes; narrower groupings are rejected at the
Level-2 export), `--exclude-tool-conditioned` (available and on by default only
for a standalone dry run; rejected otherwise), the measured-only
`--reset-open-circuits` (never a default),
and the optional `--lock-stale-seconds`. Non-dry `run_matrix`/`rig_check`
children inherit the console process's exported `URA_PROJECT_REVISION_*` /
`URA_SOURCE_CONFORMANCE_*` receipt locators exactly as the campaign shell
supplies them; dry lanes launch with them scrubbed.

The generic Run-page `rig_check` form omits `--exclude-tool-conditioned`
because that forwarder always adds `--preflight-only`; use the Build standalone
dry-run mode for the exclusion smoke.

The Acquisition exports
(`export_jalmbench`, `export_vlsbench`, `export_aggregators`) run as ordinary
Run-page forms; `export_aggregators` additionally receives the console's
process-held `HF_TOKEN` (the gated section 3.4 sources), the same exception
as `model_acquire`.

After one or more arms are selected, the Execution tab shows one synchronized
range/numeric sample-size control and the sample seed. Its `--limit` value is
per selected arm: `0` means the complete release for every selected arm and a
positive value is a whole-cluster cap applied independently to each arm. Every
bounded measured lane records `--sample-seed`. The optional local budget in
whole hours is a detached process wall-time ceiling for the final measured
all-local `run_matrix` process. On POSIX, expiry terminates that process tree and
kills it after a bounded grace period. Dry runs, no-call preflights and model
acquisition remain outside this elapsed interval. Set `--deadline-seconds`
independently for Runner's durable call-start window: it prevents later calls
after expiry but does not interrupt a call already admitted.

The console binds the operator-configured `--host` and `--port`, builds argument
vectors exclusively from a typed allowlist (no shell), caps POST bodies, runs
each job in its own process group, and keeps per-job argv/stdout/stderr under the
state directory. Closing
the console leaves detached jobs running; the explicit Stop action terminates
the complete child tree. Builder preflights are kept under
`<results-root>/preflight`; changing only execution caps may reuse the same exact
projection, while a semantic lane change requires a new preflight.

The Ollama service is the intentional exception to detached experiment jobs:
clean console shutdown stops only an `ollama serve` group started by that same
console process. It never stops a daemon that was already present or one merely
rediscovered after restart. Start uses a fixed no-shell argument vector and
loopback `OLLAMA_HOST`. Console API/pull requests ignore proxies and redirects,
and their opens, reads, bodies, and aggregate operations have hard monotonic
bounds. The daemon child receives only an explicit local runtime/GPU/Ollama/
certificate/safe-proxy environment allowlist. Pulls are disabled for external
or ambiguous daemons. Start freezes the owned model-storage path; the worker
re-proves the PID/start identity and exact listener after acquiring the
exclusive cross-process endpoint lock. Pull admission requires five GiB of
model-volume headroom; the worker rechecks that reserve plus each API-reported
remaining byte count. Discovery and inference use shared locks, so they cannot
race a pull, Stop, or model mutation. Unconfirmed descendant cleanup retains
owned/error state for a later Stop retry. POSIX cleanup sends no group signal
without a current exact process-start identity for the original live leader and
does not escalate after that proof disappears. Daemon output is
discarded instead of creating an unbounded log. The Pull form
launches the typed internal `ollama_pull` job and
streams bounded normalized progress to its ordinary job log; it is deliberately
absent from the generic Commands forms.

The Jobs table renders each full start date and time in the browser's local time
zone. State chips, free-text search, From, and To filters compose. Unless the
URL supplies either bound, From defaults to exactly seven days before the
current browser time and To defaults to that current time. Both bounds are
inclusive at the precision selected by the datetime input. The page persists
browser-derived epoch bounds and reloads a date-aware SQLite query, so older jobs
are retrievable beyond the 500-row restart cache. External campaign markers are
also filtered before the 20-row display cap. The page discloses either the
5,000-job or 20-campaign cap so operators can narrow From/To. Compact tags avoid
repeating terminal prose: jobs use blue `running`, plus `passed`, `failed`,
`orphaned`, `partial`, `blocked`, `stopped`, or `unknown`. For an external
engineering campaign, the surrounding detail identifies `running` as a task-log
marker without asserting operating-system process liveness. A terminal
campaign is `partial` when declared work is failed, skipped, pending, or when
unplanned task events exist.

An external campaign's `ENGINEERING_ONLY.json` marker may declare a strict,
unique `planned_tasks` list and a strict, unique `model_tasks` subset. Each task
name is a non-empty string of at most 256 characters; phase names `bootstrap`
and `stage2` are not tasks. Event logs determine task-process counts for
succeeded, failed, skipped, active, and pending work. A successful task process
does not imply that it called a model, and a call reservation records capacity,
not execution.

The optional `model-execution.jsonl` is a bounded operational self-report. Each
complete row has event `model_execution`, references one declared model task,
and gives nonnegative integer `attempted_calls` and `successful_generations`,
with successful generations no greater than attempts. Duplicate, undeclared,
contradictory, oversized, or malformed rows invalidate the report. If the file
is supplied for a terminal campaign, it must contain exactly one valid row for
every declared model task, including a `0`/`0` row for a pending or skipped task.
This report can distinguish a completed support stub from reported generation,
but it is not confirmed execution or scientific evidence. Only validated,
completion-bound response artifacts establish actual calls and results.

Console state (jobs with their durable argv identities and builder parameters, the
campaign-run registry, recorded per-artifact token usage, and the report
index) persists in a stdlib-sqlite database `console.db` under the state
directory, with a schema version, a startup integrity check, transactional
terminal-state commits, and a dashboard Reindex action that rebuilds every
derived row from the retained artifacts with full digest verification. The
database is operational state only - the validated filesystem artifacts
remain the scientific authority, a database fault is surfaced visibly (never
as a silently empty history or zero spend), and neither the database nor the
state directory is return-package evidence.

An explicit vLLM checkpoint path remains only in the launch-time argv and the
private selected-config file that `run_matrix` unlinks immediately after its
bounded startup read. Confirmation HTML, `Job`, `command.json`, and SQLite use
the declared `vllm:local-checkpoint@sha256:<digest>` identity; the child
verifies the digest before any model call.

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
secrets file (mode 600). `HF_TOKEN` is stricter: it displays presence only (no
suffix), remains process-memory only (legacy file entries are scrubbed), and is
forwarded only to the acquisition children (`model_acquire` and
`export_aggregators`); no other child receives it.

Console-form to runbook-section mapping (the console builds the identical
argument vectors; nothing below is console-only):

| Console form | Runbook section(s) |
|---|---|
| `project_revision` | 2, 17 |
| `source_conformance` (scaffold and validate) | 4/4.1, 17 |
| `export_jalmbench` / `export_vlsbench` / `export_aggregators` | 3.2, 3.4 |
| sealed model plan/acquire/offline run (Builder-only workflow) | 6.1, 7-13 |
| `rig_check` | 8.1, 9-13 |
| `run_matrix` (dry-run, probe, canary, measured) | 4.1, 8/8.1, 9/9.1, 10-13 |
| `live_attestation` | 8.1, 9 |
| `lane_canary` | 8.1, 9.1 |
| `native_import` | 14.3, 16 |
| `human_audit` (common and source-task frames) | 15, 15.1 |
| `judge_sensitivity`, `kappa`, `transfer_matrix`, `paired_compare` | 16 |
| `level1_evidence`, `suite_summary`, `level2_report`, `figures` | 8.1, 16 |
