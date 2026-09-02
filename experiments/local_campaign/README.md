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
attempted all 16 lock-derived frameworks as separate sequential `--only` named
tmux/screen sessions and published only verified stable aliases. Every Python
framework has its own venv, Promptfoo and T3MP3ST have separate Node
environments, and BIPIA's
legacy builder has a separate fully hashed support venv. Clean runtime homes use
the explicit persistent caches under `$URA_WORK/framework-venvs/.cache`; cache
contents are never campaign admission evidence.

The current rendered campaign implements the prospective 24 August 2026 local
sampling amendment: comparable vLLM and Ollama model lanes use limit 100 and
extended bridge lanes use limit 50, all with sample seed 0. The retained first
Ollama cohort stopped at limit 50; its population-alignment continuation proves
that exact selection is the limit-100 prefix and runs only clusters 51-100.
These are plan-owned controller and Gate bindings, not generic Runner defaults.
A render must fail if its projection,
base argv, prepared-attack selection, approved caps or Phase 7 validator differs
from the tier bound to that lane. Optional limit-0 execution is a separate
cohort and is not emitted by this bounded chain.

`vllm_stability_phase6.py` is the focused post-campaign continuation for the
retained Runner 2.24 vLLM gaps. It validates the exact historical completion,
keeps completed Qwen text and Crescendo lanes untouched, and creates seven
fresh Runner 2.25 units: the three conditions that failed before measured
Runner execution, the 815-row never-completed AirBench suffix, and the three
later LLaVA text arms that never started. The AirBench exclusion is bound by a
create-only `ura-recovery-completed-prefix/1` artifact and request-envelope
`/4`; it is not a checkpoint import. Every new unit binds
`--target-answer-retries 1`, receives a fresh attestation, one-cluster canary,
no-call projection and zero-download acquisition receipt, and retains exhausted
unusable answers as model-stability missing responses. Phase 7 must keep this
Runner 2.25 output-policy stratum distinct from the historical Runner 2.24
rows.

`vllm_input_recovery_phase6.py` handles the deterministic GPTGeoChat context
rejection found in the retained seven-unit Runner 2.25 continuation. It binds
the exact 375-row durable prefix and schedules only the 1,645 never-completed
rows under Runner 2.26 with the same model and 12,288-token context setting.
Context-limit rejections are input-compatibility missing responses, not model-
stability failures; they receive no unchanged-input retry or policy-judge call.
The old prefix and new suffix remain non-poolable strata.

`current_ollama_stability_phase6.py` handles the corresponding old-Runner
current-Ollama boundary when exact-argv recovery is terminal with unchanged
durable counts because the retained circuit is open. It validates the exact
Gate 5, base and failed-recovery bytes, omits every completed cell, binds the
three partial-corpus prefixes and runs 14 fresh Runner 2.26 per-corpus units for
the remaining 1,684 rows. Its Jobs lifecycle is operational only. Phase 7 must
retain these units separately from the 1,911 durable historical rows and must
not pool their output-policy strata.

`current_ollama_stability_continuation_phase6.py` handles only the narrower
case in which that fresh controller has already made every call for some units
but aggregate validation finds stale recovered-answer fields in their persisted
judge-stage trails. It binds the exact failed completion and terminal logs,
inherits complete units, finalizes fully executed affected units through
`finalize_recovered_trails.py` with zero target and judge calls, and launches
only units that stopped before measured execution. Identity derivation tries
the fixed seed sequence 0 through 4 so one probe nonresponse is not treated as
a failed readiness gate. The completion remains a distinct output-policy and
project-revision stratum for Phase 7.
After readiness, a whole-cluster all-abstention diagnostic canary is retained
as model-stability evidence and does not cancel the assigned measured
population. Its zero-record JSONL is canonical as either zero bytes or the
writer's single terminal newline; any other accounting mismatch still fails.

`current_ollama_stability_canary_recovery_phase6.py` accepts only a terminal
continuation whose remaining failures are that exact historical zero-record
validator mismatch. It inherits every completed unit, revalidates each retained
canary into a new summary with zero repeated canary target calls, obtains the
fresh revision-bound identity attestation, and executes only populations that
never reached measured Runner. Completed measured rows are not repeated.

`current_ollama_population_alignment_phase6.py` runs only after that retained
limit-50 population is complete. It applies the same source arms, limit 100,
sample seed 0, evaluator policy and configurable default of one retry used by
the comparable vLLM lanes. Its content-bound multi-arm selector proves and
excludes every completed limit-50 prefix, leaving exactly 11,600 new rows across
12 Ollama lanes. The combined Ollama population is 23,120 rows. Historical and
continuation Runner strata remain separate even though their coverage forms one
matched population.

Each current measured lane also binds `--deadline-seconds 86400` and
`measured_lane_wall_time_seconds=86400`. The Runner value gates call starts and
does not interrupt an in-flight call; the controller value permits termination
and process-group reaping at 24 hours. A different positive pair belongs to a
new projected and approved controller generation.

Start the next binding from the last validated one. The binding key set is the
exact reviewed placeholder inventory across the controller, verifier, and
installer templates. Every value has a field-specific validator: hashes,
canonical absolute POSIX paths, safe basenames, real UTC datetimes, and byte
counts cannot become shell or Python fragments. Rebind output is create-only.

Rebinding the immediately preceding pre-recovery-controller key shape is a
controlled migration. It requires two fresh UTC tags and exact path, SHA-256,
and byte bindings for the core-recovery and GraySwan RR input manifests. A still
older pre-RR binding additionally requires all four RR evidence roots. The
legacy a05 migration also discards its obsolete shared GPU hash and requires an
explicit `--set` for every new or changed binding below.
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

The launch chain stops after Phase 6. Phase 7 cannot be launched honestly at
the beginning of the campaign because its exact recovery, GraySwan RR amendment,
and follow-on completion artifacts do not exist yet. After those controllers
terminate, launch the read-only watcher with their absolute artifact paths:

```text
bash ~/.ura-controller-active/launch_phase7_watcher.sh \
  --phase6-sequence-completion <absolute-phase6-completion.json> \
  --phase6-recovery-completion <absolute-recovery-completion.json> \
  --seven-output-policy-amendment <absolute-GraySwan-RR-amendment.json> \
  --phase6-seven-output-policy-completion <absolute-GraySwan-RR-completion.json> \
  --followon-gate5-amendment <absolute-follow-on-amendment.json> \
  --phase6-followon-completion <absolute-follow-on-completion.json> \
  --current-ollama-gate5-amendment <absolute-current-Ollama-amendment.json> \
  --phase6-current-ollama-completion <absolute-current-Ollama-completion.json> \
  --phase6-current-ollama-recovery-completion <absolute-current-Ollama-recovery-completion.json> \
  --phase6-current-ollama-stability-completion <absolute-current-Ollama-stability-completion.json> \
  --phase6-current-ollama-population-alignment-completion <absolute-current-Ollama-population-alignment-completion.json> \
  --phase6-failed-output-recovery-completion <absolute-failed-output-recovery-completion.json> \
  --phase6-vllm-stability-completion <absolute-terminal-vLLM-stability-completion.json> \
  --phase6-vllm-input-recovery-completion <absolute-vLLM-input-recovery-completion.json> \
  --phase6-vllm-context-recovery-completion <absolute-vLLM-context-recovery-completion.json> \
  --phase6-local-hardware-fit-completion <absolute-local-hardware-fit-completion.json>
```

The launcher returns after starting the watcher in the exact detached tmux
socket and session named by its Jobs registration. Monitor that printed
identity; do not wrap the launcher in a differently named session.

Repeat `--phase6-recovery-completion` for every retained recovery stratum.
Pass `--phase6-current-ollama-recovery-completion` only when the base current
Ollama completion has failed lanes. The watcher waits for that exact recovery;
Phase 7 rejects an omitted or unrelated recovery and preserves its terminal
partition. The separate current-Ollama stability completion is always required
for this retained campaign. It contributes the 14 fresh Runner 2.26 per-corpus
units without relabeling or pooling the 1,911 durable old-Runner rows.
The terminal vLLM stability completion and its input-recovery completion are
required together. Six completed Runner 2.25 units and the Runner 2.26
GPTGeoChat suffix form seven logical metric lanes in separate revision strata.
The failed unit's 375-row prefix remains lifecycle evidence and is never pooled
with the suffix. Completed Runner 2.24 Qwen text and Crescendo lanes are not
repeated and remain in their historical output-policy stratum.

For this retained campaign,
`--phase6-current-ollama-population-alignment-completion` names the terminal
six-unit continuation completion, not the interrupted seven-unit recovery root.
Launch that continuation only after the failed-output recovery is terminal. Its
module requires the base alignment completion plus
`--failed-output-recovery-completion` and its SHA-256, and schedules exactly four
R-Judge and two GPTGeoChat units (2,350 rows). DeepSeek is excluded because its
235 retained usable rows plus 1,674 Runner 2.27 recovery rows already close its
1,909-row extension. Phase 7 retains that split as population/model-stability
coverage and forbids a pooled security rate across the two Runner strata.

The retained six-unit failed-output recovery completed five units (2,139 rows)
and rejected DeepSeek before measured execution because the reasoning model was
bound with `think=false`. Do not repeat those five units. Run
`failed_output_recovery_continuation_phase6` with the exact terminal completion
and digest; it validates the retained partition, reuses the exact 1,674-row
selector, and runs only DeepSeek with `think=true`. The separately calibrated
condition uses `num_predict=2048` after a ten-input, one-attempt, no-judge
diagnostic produced ten visible final answers with normal stop reasons and
719-1,335 completion tokens; the stopped 512-token condition remains diagnostic.
Its combined `/3` completion preserves DeepSeek's
original physical unit 05 rather than renumbering the filtered one-unit list. It
is the authoritative Phase 7 and alignment-recovery input, with old and new
project revisions and generation conditions kept as separate metric strata.

The 8,192-context/2,048-output continuation was stopped on 2 September 2026
after 784 durable rows because 14 missing outputs and 21 length-ended responses
showed that the finite output condition remained confounded. Preserve that
checkpoint. Its successor must use a completed-ID selector that runs only
never-attempted, missing, and length-ended identities, bind automatic GPU-fit
context and maximum available output, and derive fresh attestation, canary,
projection, acquisition, and result artifacts. It must not repeat a completed
non-truncated response or pool either historical finite-cap condition with the
hardware-fit correction.

All new local work uses automatic maximum GPU-fit context unless an experiment
explicitly binds a finite historical condition. vLLM binds
`max_model_len=-1`, so the installed engine derives the model ceiling and
reduces its KV allocation to live GPU capacity. Ollama binds `num_ctx="fit"`;
Runner starts at the pinned model ceiling, performs load-only probes at
successively smaller native fractions, and accepts only the largest tested
context for which `/api/ps` reports the whole runtime in VRAM. It binds
`num_predict=-1` after fit succeeds. Retained `finish_reason=length` or
`done_reason=length` rows remain immutable and are regenerated by exact
identity in a separately labelled correction stratum.
For response-independent cells, do not co-reside a model-backed scoring judge
with the target. Runner first completes the response checkpoint, releases the
target, then loads the judge and finishes the same bound run. Crescendo remains
inline because its verdict is trajectory input, and a defense guard remains in
the target phase because it is part of the evaluated condition.
Use `python -m experiments.local_campaign.local_truncation_recovery_phase6`
with one repeated `--state` per retained unit and a create-only `--out` path to
produce the structure-only inventory. The artifact contains descriptors,
datapoint IDs, selectors, corrected local configs and counts, but no prompt,
answer or thinking text. Execution consumes that reviewed inventory separately.
Use `local_truncation_recovery_execution_phase6` with the inventory path and
digest. It re-derives every bound source unit, writes create-only selectors and
configs, obtains fresh admission artifacts, and runs only the exact recovery
identities with one answer retry. A retained missing answer remains a row-level
model-stability result and does not terminate the rest of its unit.

Targeted Runner-output recovery is deliberately outside `launch_chain`. It is
available only through the generated
`launch_phase6_recovery_and_seven.sh`. The launcher starts one named tmux
session, executes `phase6_core_length_recovery.py`, and starts
`phase6_seven_output_policy.py` only after the core process is terminal. The
core exit code does not gate the four-row GraySwan RR launch. Both producers
preserve the retained limits, sample seeds, call caps, 24-hour lane deadlines,
zero-download admission, one-arm canaries, and create-only output roots. They do
not repeat already successful lanes.

Every fresh local attestation inside these recovery producers uses
`rules,guardrail` with the pinned Llama Guard identity on `cuda:1`. The
purpose-bound acquisition is `target_and_guard` for vLLM and `guard_only` for
Ollama. This keeps a rules abstention from being misreported as a transport
failure and introduces no hosted judge call.

The core input manifest has schema
`ura-phase6-core-length-recovery-inputs/2`. Its exact file-descriptor fields
are:

```text
retained_executor_payload
historical_gate5_manifest
historical_gate5_runnote
historical_gate5_promotion
focused_tests
mutation_tests
deployment_exit
```

Its directory dependencies are `base_core_control_root`, with one artifact role
for each of the six named retained lane-spec files, and
`prior_recovery_attempt`, with exact `exit_marker` and `completion` artifact
roles. Before any corrective call, the producer requires that prior completion
to be the exact successful three-lane Runner 2.24 R-Judge recovery, validates
its completion, launch, amendment, summary and result descriptor chain, and
cross-links its retained payload and source lane specs to the bound inputs.

The legacy-named GraySwan RR input manifest has schema
`ura-seven-output-policy-amendment-inputs/2`. Its exact file-descriptor fields
are:

```text
retained_executor_payload
historical_gate5_manifest
historical_gate5_runnote
historical_gate5_promotion
focused_tests
mutation_tests
deployment_exit
```

Its directory dependencies are `base_core_control_root`, with the four exact
LLaVA-base lane-spec artifact roles; `base_ollama_control_root`, with the three
exact R-Judge Ollama lane-spec roles; and `prior_ollama_recovery_attempt`, with
exact `exit_marker` and `completion` roles. The prior attempt's control root
must be the same `base_ollama_control_root`, its three generated lane specs must
occupy the exact named paths in that control, and its exact successful
completion chain is validated before any corrective call. Neither corrective
cohort includes a PyRIT lane, so no unrelated PyRIT evidence is an input.

Every file descriptor has the exact field set `{path,sha256,bytes}`. Every
directory dependency has the exact field set `{path,artifacts}`, and each
artifact value is a file descriptor whose resolved path must remain below that
directory. Both the outer manifest and every referenced file are content-
verified before payload import or use. The optional prior-core attempt is
derived from the bound recovery tag, is recorded only as an uninspected path
with null artifact fields, and is never a launch prerequisite. Create the bound
manifests and tags for a fresh cohort, render and install the generation, then
invoke explicitly:

```bash
bash ~/.ura-controller-active/launch_phase6_recovery_and_seven.sh
```

An occupied sequence, recovery, seven-row, RUNNOTE, reservation, or result path
fails closed. The controller is not a mechanism for rerunning a completed
cohort or raising its caps.

The Phase 5 and Gate 5 orchestration controllers enforce a 24-hour global
controller deadline, and the Phase 7 watcher enforces 720 hours. At expiry, a
controller records exit 124 and the exact wait/hours reason in task and campaign
events. It terminates and confirms absence of only an exact tmux session it
launched and owns; a controller that times out while awaiting upstream Phase 5
or Phase 6 never terminates that upstream session.

The archive contains every allow-listed executable generated controller, the
generated read-only Phase 8 operator guide, their generated inventory, and the
generated verifier. The installer remains outside the archive. Both
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

The sealed historical Gate 5 inventory contains 46 rows. Four GraySwan RR and
three RWKV static identities retain immutable target-runtime-terminal artifacts
from the older output policy. The RWKV tags are no longer installed or selected
by prospective tasks. The additive current Ollama cohort instead contains
Gemma 4 12B Instruct Q4_K_M, Ministral 3 14B Instruct 2512 Q4_K_M,
DeepSeek-R1 Distill Qwen 32B Q4_K_M, and GPT-OSS 20B in its native MXFP4
representation, each bound to its acquired digest. Gemma 4 and
Ministral 3 admit text and image lanes; the other two admit text lanes only.
The current Runner 2.26 contract retains nonempty length-capped text with its
terminal reason and makes one additional answer attempt by default for an
empty, structurally malformed, binary/control-like, symbol-only or transport-
failed answer. Exhaustion becomes typed model-stability missing-response
evidence, bypasses the policy judge and does not stop the assigned population.
Vague, repetitive or semantically poor natural language remains ordinary
observed output for the selected evaluator.

A targeted amendment re-attests and canaries the four GraySwan identities. The
older GraySwan `-full` terminal identities are not rewritten; the current
GraySwan rows instead use limit 100 and sample seed 0 matched to the LLaVA-base
rows. The additive Ollama amendment first retained a limit-50, sample-seed-0
cohort. The population-alignment continuation extends each compatible lane to
the same limit-100 population as vLLM without rerunning any completed row. It
covers four text and R-Judge targets, adds static-image and GPTGeoChat lanes for
the two multimodal targets, and records the two text-only GPTGeoChat pairs as
typed unavailable. Exact inventory counts are derived from the retained
projections and content-bound selected IDs rather than modifying the sealed
historical profile. Identity, provenance, residency, seal, budget and wall-time failures
remain hard failures. An older partial current-Ollama lane is resumed by
`resume_current_ollama_phase6` with its exact stored argv, sealed cells and
checkpoint; the separate recovery completion binds the controller source and
does not rewrite the base Phase 6 completion. Its interpreter may be the normal
`.venv/bin/python` symlink when that path resolves to an executable regular
file, preserving the isolated project environment used by the original lane.
The controller publishes its exact tmux-owned running and terminal lifecycle to
Jobs; that operational record does not alter the separate recovery evidence.

The core cohort records `bridge-nanogcg`, `bridge-ideator`, and `t3mp3st` as
`unavailable` only because their prepared artifacts are assigned to a separate
follow-on cohort and were not bound when its Gate 5 authorization was sealed.
This is not a current capability disposition. The core controller does not
schedule those three lanes for core-cohort measured execution. The follow-on
cohort binds the NanoGCG capture config, IDEATOR v2 source-mapped manifest, and
T3MP3ST bundle and uses the ordinary documented Runner commands with its own
retained common scientific base and separate exact preflight, canary and
measured argument arrays. Each purpose keeps its own plan and receipt. For each
lane, the retained schedule contains a prepared artifact, no-call projection,
diagnostic canary, Gate 5 record, and measured schedule. NanoGCG may use a
positive outer limit or a separately projected `--limit 0` transfer cohort.
IDEATOR v2 is instead
fixed to `advbench_harmful --limit 1 --sample-seed 105`;
`pair_limit=0` means all eight verified pairs mapped to `advbench:245`,
not all 520 AdvBench rows. Accordingly, the exact measured target-call caps are
one for NanoGCG, eight for IDEATOR v2, and 50 for T3MP3ST. The generated
`phase5_followon_prepared.sh` converts only a fully validated three-lane input
into the separate Gate 5 amendment, and `phase6_followon_prepared.sh` derives
the typed `measured_complete`, `partial`, or `failed` lifecycle from the exact
Runner roots. The 141-row Phase 7 campaign union requires the amendment,
stability recovery, population-alignment completion, six failed-output
recovery units, one vLLM context-recovery unit, and 25 local hardware-fit
recovery units as exact inputs. Its
exact cohort counts are 46 canonical, four output-policy amendment, three
follow-on, 14 historical current-Ollama, 14 current-Ollama stability, 12
current-Ollama population alignment, six failed-output recovery, seven vLLM
stability, one vLLM context-recovery, 25 local hardware-fit recovery, and nine
native rows.
It retains
all three terminal states, emits
metric inputs only for
independently validated successful Runner roots and partitions those inputs by
project revision. Zero successful follow-on lanes is an explicit limitation,
not a controller failure.
New recovery, current-Ollama stability and population-alignment controllers
also create one generic external-measured Jobs registration immediately before
each measured Runner child and terminalize it immediately afterward. An older
controller that already began without those start records remains one parent
engineering job with browsable unit artifacts; never invent a retrospective
start time to make it look like a separately registered child.
The generated `followon_prepared_controller.py` is the tracked operator path
between those two validators. It accepts only canonical prepared NanoGCG,
IDEATOR v2 and T3MP3ST artifacts plus the retained parent Gate 5 RUNNOTE and
promotion. It performs each no-call projection and diagnostic canary, derives
the exact measured-purpose attestation, plan and zero-download receipt, removes
only the single plan-only request envelope so the authorized Runner root is
still absent, and creates the formal Gate 5 amendment before any measured
call. It then attempts the three exact authorized argv arrays independently,
records their external Jobs terminals, and invokes the formal Phase 6 outcome
validator. Run this generated controller in its own tmux session; its
`--control-root` must be one absent direct child of
`$URA_WORK/runs/engineering`, and its short `--attempt-tag` is also the durable
job identity. This controller is local campaign orchestration, not a
URA-Bench product phase.
The exact NanoGCG plan/acquire/capture/replay and IDEATOR v2 prepare/Build
procedures are the named subsections of `experiments/RUN_AND_RETURN.md`;
this controller README does not redefine them.

Phase 7 binds two distinct Runner views. Its authoritative lifecycle registry
covers every scheduled Runner lane and binds each controller failure, optional
exact measured argv, and retained grid, request-envelope, eligibility, and
error artifacts. The Level 1 tool receives every retained Runner/request
artifact it can represent. A genuine pre-Runner failure with no request
artifact remains explicit in the registry and is not fabricated into Level 1
input. Suite metrics and Level 2 receive only successful measured Runner lanes.
A failed lifecycle is never promoted into metric evidence.

The watcher runs `publish-stats` only after its terminal Phase 7 record and
artifact inventory pass the sealed validation. The plan-owned adapter validates
the complete chain and creates the generic Stats registration. An adapter,
registration, path, or byte-identity failure makes the watcher fail instead of
claiming publication. Rig Web contains no Phase 7 logic.

For a controller generation deployed before automatic publication, or for
explicit recovery when no registration was created, run the same adapter after
the watcher is terminal:

```bash
python -m experiments.local_campaign.stats_adapter \
  --results-root "$URA_WORK/runs" \
  --campaign-root "$URA_WORK/runs/engineering/<watcher-route>" \
  --release-commit "$REF_URA"
```

The create-only destination is
`external-analysis-jobs/<watcher-route>/registration.json`. Rig Web validates
only that operational registration and the exact Level-1/Level-2 report bytes.
The registration cannot grant thesis-evidence authority.

Controllers deployed before the generic measured-job v2 contract retain their
immutable v1 rows. After repinning to the v2 reader, copy them once without
modifying their source bytes:

```bash
python -m experiments.local_campaign.migrate_external_measured \
  --results-root "$URA_WORK/runs"
```

The command validates the complete v1 batch and all existing v2 destinations
before writing. It is resumable, refuses a differing v2 collision without
changing it, and leaves every v1 start and terminal record in place.

Phase 8 consumes Phase 7's validated success-only read-only Runner copy. This
keeps an honestly failed or partial Runner lifecycle in the canonical lifecycle
tree without letting `human_audit` mistake it for a completed sample input. The
view receipt content-binds every relative source/copy file, distinct identity,
digest, byte count, and read-only mode; the completed view permits no analysis
output or other extra file. When the follow-on amendment is present, Phase 8
uses a sampling-only union of that core success view and each exact successful
follow-on result root. Failed, partial, and sibling recovery roots remain
excluded, while every successful lane is retained in an explicit project-
revision stratum and cross-revision metric pooling remains forbidden. Phase 7's separate lifecycle copy uses the same
source-preserving boundary for Level 1. The
create-only Phase 8 input manifest records an exact cardinality plan: the common
population must cover the requested common sample plus 20 disjoint
qualification clusters, and the source-task population must cover its exact
requested sample. Cardinality is recomputed from the same view before any
sample write, while both selectors retain their independent achieved-cell
coverage checks. Before machine preparation, the controller requires an exact
byte-bound operator ethics/consent record with structured consent,
compensation, withdrawal, harmful-content welfare, and escalation controls;
free-form details do not satisfy that contract. This authorization creates no
rater, qualification, label, adjudication, report, or Gate 8 acceptance. A
successful machine controller remains `human_only_blocked` with
`gate8_met: false`; only real qualified raters, independent labels,
adjudication, validated reports, and a human acceptance or limitation record
can satisfy the later Gate 8 conditions. The generated
`phase8_human_audit.README.md` in the active controller generation is the
commit-bound operator guide.
