# All-local test campaign plan: every corpus arm, every framework runtime, free models only

UI publication requirement, 11 September 2026: present all retained local work
as one model-first Local campaign workspace, with recoveries and operational
jobs under Activity, not a fragmented job-card list. The
[workspace specification](../docs/CAMPAIGN_WORKSPACES.md) defines importing this
work, automatic membership for future UI launches and the same-input comparison
with the single API campaign. Grouping does not rerun completed generations or
pool incompatible historical and corrected conditions. The Local campaign now
indexes all 372 retained runs and their 50,653 output records, including
historical failed conditions and corrections. Native local scoring records,
retained Haiku assessments and their recorded costs, and the historical/RR
reports are published. New recovery judging and complete UI execution/continuation
controls remain open. These historical
counts are not a pooled final-comparison population. No local generation was
repeated by publication.

Status, 12 September: the earlier execution and analysis are terminal, but the
newly requested all-model missing-output recovery is open. Audit every retained
missing output, distinguish input-context overflow, output-length exhaustion,
transport failure and unusable text, and reconcile existing correction checkpoints
before issuing any new generation. Preserve predecessor outcomes. A larger
window is a tested new execution condition, not a presumed cure for every miss.
Each recovered answer requires its own local and Haiku verdict; a judgment of
another output cannot be reused. Hosted collection continues independently.

The 23:44 UTC audit inspected all 50,653 indexed response records. Of 6,103
historical missing records, 3,263 have a normal-ended answer for the same model
and exact input; 61 belong to the retired RWKV roster. The remaining selection
contains 2,636 distinct current-roster inputs, pending reconciliation against
other retained checkpoints before regeneration. This is an audit selection, not
a count of lost files or completed recoveries. DeepSeek's early empty outputs
include 512-token output allowances, whereas its later ten timeouts used a
65,536-token context and native-maximum generation. Increasing context alone
does not explain or repair both conditions. Test the affected configuration
against the responsiveness/time requirements before starting its correction.

The follow-up checkpoint join inspected 14,178 retained recovery responses and
found 211 exact matches to this pending selection, none providing an additional
normal-ended usable correction. The 2,636-input selection therefore remains
open; no new generation was made during that reconciliation. Qwen's already
corrected missing inputs remain excluded. The separate metadata repair filled
omitted native token usage, limits and explicit stop information in 50,475
existing index rows, preserving every original answer and verdict. It does not
change missing outputs into successes. The current 3,252-output local Haiku
selection is fully assessed, including its two network recoveries; further
newly generated answers still need their own assessments.

Recovery first, thesis afterwards: the pending 2,636 model-input conditions are
a worklist, not the final experimental missingness result. DeepSeek's diagnostic
at 32,768 context and 8,192 output tokens returned normal-ended answers for all
three selected old misses in 21.7-24.4 seconds and scored 8/10 on the readiness
questions. It remained entirely GPU-resident. One initial request timed out;
investigate this before choosing the correction settings. No diagnostic answer
is promoted into the campaign, and the default profile remains unchanged.
Complete the other models' cause-specific recovery and both required judges
before writing final outcomes. Preserve historical failures and correction links.

Execution update, 12 September at 02:09 UTC: all 2,636 pending model-input
conditions have now been matched to their original delivered prompts/media and
seeds. No input is missing from the recovery worklist. Native Runner recovery
has started on 1,087 DeepSeek conditions; a separate prepared queue covers its
remaining 101 plus Gemma 634, GPT-OSS 372, Ministral 31, GraySwan RR 391 and
LLaVA base 20. Use the already verified local profiles: DeepSeek and both
LLaVA targets have 4,096 output tokens, while Gemma, GPT-OSS and Ministral have
8,192. Context is automatically fitted to the available GPUs and each request
has the approved 120-second deadline and one answer retry. These settings differ
from the early 512-token runs. Do not silently promote the diagnostic 8,192-token
DeepSeek configuration into a readiness-approved profile.

The previously timed-out readiness question completed in 4.3 seconds after a
separate 6.3-second model preload. This establishes responsiveness under the
tested loaded condition, not a definitive cause for the initial timeout.
Recovery uses exact input filters, not a fresh random sample. Where loading the
whole source is necessary to locate the old inputs, its other rows are only the
filter universe, not additional assigned queries or claimed completed outputs.
The two-GPU DeepSeek owner runs without a resident scoring model; native local
judging follows target release. Subsequent units wait for that owner, not for
hosted work. Fresh Haiku assessments and replacement-aware final analysis remain
required after collection. Historical outcomes remain unchanged. The recovery
controllers and the measured child are attached to the existing Local campaign's
Activity view. Operational scripts and exact worklists remain under the ignored
thesis verification directory and the rig's engineering run directories.

At 02:42 UTC, 59 of the selected conditions have been attempted: 58 have usable,
non-truncated replacements and one still has no visible answer after its retry.
The latter reports 4,096 completion tokens, but the older Runner discarded its
native stop and generation metadata while normalizing the missing output.
Fix 3c08b44 preserves these observations; it passed focused rig regressions and
removed-fix checks without restarting the active recovery. The current worker
remains on its original revision. Retain residual misses for cause-specific
follow-up and, where necessary, a readiness-tested larger-output condition;
do not repeat successful replacements or claim that token equality proves a
length stop. Required judging and the replacement-aware final analysis remain
pending. The current first DeepSeek unit's generation-only forecast is about
12:10 UTC at the observed throughput; it is not a whole-campaign completion date.

The unstarted 1,549-condition queue has moved to a clean isolated checkout of
3c08b44 with its own validated project receipt. All existing profiles and exact
input selections are unchanged. Its predecessor was stopped only while waiting,
before any unit or generation began; the active 1,087-input DeepSeek worker and
the console were untouched. Subsequent units will therefore retain missing-output
generation metadata. Both the handoff and successor appear in Local campaign
Activity. No new runtime installation or model download is involved.

Human audit and thesis evidence synthesis remain separate work. This plan was written
20 August 2026 after the readiness audit
of the big rig (Debian, 2x RTX 4090 24,564 MiB, 125 GiB RAM, /mnt/stor 7.1 TB
free). It is an
operating plan for the rig, not thesis evidence. It complements, and never
replaces, the operator runbook [`RUN_AND_RETURN.md`](RUN_AND_RETURN.md): every
command below is a runbook command (section numbers in brackets) restricted to
local, unpaid resources. Nothing in this plan makes a hosted-provider call.
After Phase 7 seals the local inventory, the separate
[`HOSTED_CAMPAIGN_PLAN.md`](HOSTED_CAMPAIGN_PLAN.md) may evaluate API models
only on content-bound compatible subsets of inputs already used here and may
select retained local outputs for bounded Haiku re-adjudication. That follow-on
is not another local phase, cannot change any local selection or result, and
has independent provider-budget and transfer gates.

New follow-on, 10 September 2026: the
[third hosted expansion](HOSTED_EXPANSION_PLAN.md) requests 6,541 additional
hosted evaluations from inputs already executed locally. Matching local
outputs need Haiku assessment unless the exact output and judging condition
already have one. This is new hosted/judging work, not a restart of completed
local generation or a new local phase. Its selection and funding are pending.

Final hosted comparison, 10 September 2026 at 06:11 UTC: the separate
supplement and Google extension have completed target collection and both
judging obligations. Their published comparison includes every one of the
683 existing local answers matching 730 eligible hosted answers across the
same 178 inputs. Local generations were not reopened. The broader local
Haiku inventory retains all 750 assessments on 190 inputs, including eight
invalid verdicts; 67 answers outside the final hosted comparison's input
scope remain retained, not discarded or queued for regeneration. The final
comparison retains ten invalid verdicts across both cohorts and does not
treat its 2,750 comparison links as independent observations. See the
[published comparison](http://localhost:8642/stats/job/hosted-supplement-final-comparison-2fb01af-r8-20260910)
and [completed supplemental plan](HOSTED_SUPPLEMENT_PLAN.md). The automated
campaign has no remaining target or judging worker. Gate 8's human evidence
and the subsequent academic chapter synthesis remain explicitly outstanding.

Follow-on input audit, 9 September: the hosted supplement must collapse source
aliases before applying new paid-call limits. Identical local inputs can occur
in different historical or recovery subsets with different whole-subset hashes.
Retain those source identities for provenance; do not count them as distinct
hosted questions. All 35 Gemma answers initially reported missing by the
supplement membership diagnostic already exist in corrected local runs. Exact
input matching validates them without regeneration. The local generation
campaign is not reopened by that diagnostic. RA-412 and the separate
[`HOSTED_SUPPLEMENT_PLAN.md`](HOSTED_SUPPLEMENT_PLAN.md) record the corrected
judging join, prospective deduplication and remaining hosted analysis work.
The 9 September hosted continuation also retains Luna's 37 previously saved
answers for separate local-cascade and Haiku scoring. They are hosted outputs,
not missing local-model generations. The original local campaign is unchanged;
no local target work is reopened to repair that hosted scoring handoff.
Those 37 hosted answers completed local and Haiku scoring on 10 September;
all 37 Haiku verdicts were valid. Google's separately retained usable prefix
answer has the same post-hoc obligation. Neither scoring recovery authorizes
new local-model generations or the reuse of a verdict for a different answer.
The 10 September comparison correction includes every retained local answer
matching each completed hosted input, not one sampled local model per input.
The first expanded snapshot uses 622 existing local answers on its 160 inputs;
the larger 750-answer, 190-input Haiku inventory remains available for the
remaining hosted routes. Neither report requires local target regeneration.
The forward runtime inventory was amended on 25 August 2026 to admit T3MP3ST
at an exact source commit, increasing the managed inventory from 15 to 16. The
dated readiness snapshot below remains a historical record of what was found on
20 August.

Execution update, 8 September 2026 at 13:57 UTC. All local target generation
is terminal. The complete RR union contains 7,606 distinct assigned inputs,
7,215 usable outputs and 391 retained failed outputs, with no repeated completed
response. There are 7,604 scoring records and two explicitly retained invalid
AirBench classifier outputs; every assigned scoring input was attempted.
The `72b13e1` retry completed R-Judge's 100 inputs and GPTGeoChat's 2,020 inputs.
Both GPUs have no remaining compute owner. The final RR analysis passed its
input/source validation but failed during Level-1 export because the command
omitted the existing bound live-attestation inputs. The focused `7c34451` fix
forwards those exact receipts within each execution-revision stratum and gives
each fresh export its own job directory. Eight affected rig tests, Ruff and two
reversals pass. A subsequent input-metadata join exposed the two retained
AirBench evaluator failures. `6d4d40e` separates source-derived input metadata
from judgment success; its nine focused cases and two reversals pass, including
the corrected measured-manifest fixture at `6856d3c`.
Final RR analysis completed at 13:56:59 UTC, with all 438 source files unchanged
and zero target or judge calls. It publishes two revision-specific Level-1 and
six separately scoped Level-2 reports at
`/stats/job/rr-analysis-6856d3c-20260908T135500Z-control` (HTTP 200).
The retained-input inventory includes all 7,606 inputs. The completion SHA-256 is
`de836b871dd80b3f49596da3531f9e1a233076bc23401d3f405e0c5bd9d063da`.
Historical and corrected conditions, and the two missing evaluator verdicts,
remain explicit. Console deployment completed at 14:13 UTC under `0b27f26`;
the actual serving process and the reduced Stats renderer were verified, not
just HTTP availability. Combined historical/RR input validation completed at
14:09:56 UTC with 372 cells and 27,847 input candidates. These are distinct
historical and corrected memberships, not a pooled comparable population.
The separate hosted follow-on is now preparing exact input replays and request
counts. Local generation and analysis must not be restarted. Human-only audit
requirements remain outstanding.
The following dated observations are retained history, not additional queued
model work.

Matched judging follow-on, 9 September at 14:00 UTC. The separate hosted
campaign has attempted its complete 941-input assignment. Haiku has now
attempted all 259 selected local answers and all 743 eligible hosted answers
on the same matched input identities. Reused local answers are judged once,
not once per hosted counterpart. Local answers retain 257 valid and two
invalid judge verdicts; hosted answers retain 740 valid and three invalid
verdicts. Invalid verdicts remain unscored, and this selected comparison must
not be presented as full-corpus independent human judgment. The original local
generation, local scoring and published historical/corrected conditions are
unchanged. Comparison publication completed at 14:08 UTC at
`/stats/job/hosted-haiku-outcome-recovery-20260909`. The operator subsequently
requested additional hosted inputs under the separately documented
[`HOSTED_SUPPLEMENT_PLAN.md`](HOSTED_SUPPLEMENT_PLAN.md). This does not restart
local generation. Human-only audit and thesis evidence synthesis remain
outside this completed generation and judging sequence.

Same-input coverage clarification, 9 September: the 743 eligible API answers
cover 81 distinct inputs with 304 eligible existing local answers. The initial
259-answer local selection covered every input but omitted 45 other local
answers to those inputs. Complete those 45 Haiku assessments without new local
generation or repeated completed judgments. Comparability requires the same
input identities, not equal answer counts across unequal model rosters. The
extension completed at 14:45:31 UTC: all 45 additional verdicts are valid, at a
cost of USD 0.053558. Local Haiku coverage is now 304 assessments, with 302
valid and two previously retained invalid verdicts. The hosted side is unchanged
at 743 assessments, with 740 valid and three invalid verdicts. Full costs and
the preserved unknown-usage hold are recorded in the hosted follow-on plan.

Execution status, 5 September 2026. Gates 0 through 5 are met. The measured
primary-model recovery inventory is terminal; the four current-policy GraySwan
RR lanes remain unfinished. Its existing readiness profile passes 10/10 text
and 3/5 images with a 4,096-token allowance and 32,768-token effective context,
but its four measured populations had not been executed at the audit. The
original current-profile controller under `e9f1c33` was stopped at a closed-cell
boundary with 200 responses and all 200 judgments retained. The two-worker
continuation under `5207b3d` started preparation at 18:42 UTC on 5 September,
with 3,657 remaining inputs assigned to GPU0 and 3,749 to GPU1. Both GPUs were
performing measured generation by 19:32 UTC. The
planned same-base comparison still requires completion of its 7,606 selected
inputs (3,854 static text, 1,632 static image, 100 R-Judge and 2,020 GPTGeoChat).
Reuse the sealed checkpoint and admitted profile; do not repeat installation,
readiness or completed base-model rows. The six-unit, 2,350-row Ollama
R-Judge/GPTGeoChat population-alignment continuation under `7ba0d1b` completed
with 2,350 usable outputs and zero missing responses. The
230-row Qwen3-VL larger-context recovery validates all 230 usable outputs with
zero missing responses; a postwrite receipt records recovery from its worker
shutdown abort without a new model call. The
25-unit hardware-fit correction is complete and validates 4,463 unique rows,
4,366 successful generations, 97 retained missing responses and zero repeated
successful rows. Phase 7 analysis and Phase 8 human-audit gating have not yet
completed on this terminal union. A checkpoint-inclusive structure audit now
reconciles all 27 replay arms: 7,606 unique inputs for each of Qwen3-VL, LLaVA
base, Gemma and Ministral, and 3,954 text-compatible inputs for each of DeepSeek
and GPT-OSS. Comparable arms have identical datapoint IDs, seeds, rendered
inputs and media identities, including retained partial prefixes and recovery
suffixes. Final Phase 7 publication must preserve the distinct execution
conditions; input coverage does not authorize metric pooling. This
paragraph is operating status, not thesis
evidence and not a product feature.

RR judging interruption, 6 September. The first parallel MMSafety image segment
retained all 300 responses, then its rules/guardrail cascade failed after 76
judgments without a confidence-qualified verdict. Its 224 remaining judgments
are required; none of those responses is an unexecuted target query. The old
counter preferred the partial final response export and hid those 224 rows.
The corrected reader verifies final/checkpoint agreement and counts the full
response checkpoint. At 00:29 UTC the corrected union contained 892 of 7,606
responses, with zero repeated inputs, while both GPUs were generating. The
judge failure remains unresolved; do not promote its cell or classify it as
target instability. Diagnose and resume scoring from retained responses after
the assigned GPU is available. Keep the separate GPTGeoChat preparation retry
and remaining target units running; no runtime reinstall or completed target
replay is warranted.

The first judge-only diagnostic stopped before inference because the old
checkpoint reader attempted source scoring on a retained failed output, unlike
the live writer. The corrected source reader reconstructs all 76 actual
judgments exactly and repeats zero target or judge calls; reversing the fix
reproduces the real first-row restore failure. This repairs reconstruction,
not the unresolved classifier output on the first unjudged response. The
diagnostic used a copied results directory, and the GPU0 controller resumed
after its canary boundary; original artifacts and GPU1 execution were unchanged.

The subsequent single-response classifier diagnostic returned `assistantsafe`
under the original 20-token guard allowance. The parser correctly retained an
unconfident, unparsed output. The pinned template already supplies the assistant
header; adding a generation-header flag would not change it. At 10:39 UTC the
token-level diagnostic confirmed the generated sequence
`assistant<|end_header_id|>safe<|eot_id|>`. Skipping special tokens had joined the
role name to the verdict. The corrected decoder recognizes the actual special
header token and retains the original token sequence and both decodings. The
real-tokenizer proof, focused rig tests and reversals pass with no further
inference; literal `assistantsafe` remains unparsed. The diagnostic resumed
GPU0 scheduling and changed no checkpoint. All 224 pending campaign judgments
still require separately provenanced scoring; neither the diagnostic nor this
fix promotes the failed grid or authorizes target regeneration.

The separate scoring recovery is implemented and rig-verified at `3db7401`.
Its actual call-free preparation binds all 300 responses, the 76 existing
judgments, 224 pending identities and the corrected judging source. Twenty-four
focused cases and five reversals pass. The tmux-owned `rr_retained_judging`
waiter was launched at 12:02 UTC on 6 September to use the next GPU0 canary
boundary; target generation remains at `5207b3d`. It repeats no target or
completed judgment and preserves the original failed grid. Completion of the
224 classifications and their separate Phase 7 analysis handoff remain pending;
the successful preparation is not empirical scoring evidence.

The separate completion reader at `29b67e5` has seven passing focused rig
checks, including its self-contained worker protocol, and four detected
reversals. It accepts only the full recovered judgment set, preserves the
original/recovered partitions and invokes no classifier. The exact-source
read of the real completion remains pending until scoring finishes, followed
by integration into the parallel RR analysis and its separate reports.

The analysis integration is now implemented through `484cf25` and verified on
the rig. `rr_parallel_analysis --judging-completion` accepts the separately
completed scoring alongside the independent template retry. It preserves the
original worker counters and failed grid, includes every retained input, and
exports original/recovered judgment scopes separately with their actual source
bindings. The same validated join supports the later matched judging selection.
Sixty-four handoff checks, the focused scoring/report checks, the Level-2
exporter checks and five reversals pass. An exact-source read of the frozen
MMSafety/HoliSafe subset reproduces 315 worker responses and 285 successful
responses, excluding the separate 200-response prefix; all 37 source files
remain unchanged. This is a bounded accounting proof, not full-cohort analysis.
The 224-record scoring recovery completed at 13:37:08 UTC on 6 September,
with zero target or hosted calls. Its completion SHA-256 is
`2206bfb60ddce5742af807fee259d114e64b64a909436ec8446176d5ac776d09`.
The subsequent real-data read through `484cf25` validates all 300 original
responses and judgments, with no missing, orphaned or duplicate joins and all
21 bound source files unchanged. The joined inventory retains 276 decided
judgments and 24 abstentions. Separate original/recovered Level-2 reports cover
76 and 224 responses; the proof forbids new classification and makes zero
target or judge calls. Evidence is retained under
`engineering/rr-scoring-analysis-29b67e5/actual-completion-20260906`.
This resolves the pending scoring described in the earlier dated observations.
The original failed grid remains unchanged. Full RR analysis, Stats publication
and the Phase 7 seal still require the ongoing workers and GPTGeoChat recovery.

AirBench scoring interruption, observed at 20:11 UTC on 6 September. The GPU1
unit retained all 1,854 responses, then its judge cascade stopped after 644
judgments. The remaining 1,210 judgments are required; no target query is
missing from that unit. GPU1 continued to its next generation unit. The exact
failed classifier output was not retained by the old execution source, so the
previous MMSafety framing cause is not asserted for this separate failure.

`081666d` lets the existing judge-only recovery use retained responses from
either worker of the same bound campaign while keeping its original physical
GPU0 boundary and execution contract. All eight affected rig boundary checks,
Ruff and two reversal checks pass. The real no-call preparation validates
1,854 responses, 644 existing judgments, 1,210 pending IDs and 21 source files.
Its launch SHA-256 is
`2aedd74d1393cd7cb6f6bfbe0e7d2d53312c5546202e8a0be80055a0976ce3b9`.
The tmux waiter `ura-rr-air-judging-20260906/recover` was launched at 20:23 UTC
to score those saved responses at the next GPU0 canary boundary, leaving GPU1
generation untouched. These classifications and their actual completion/report
validation remain pending; the full analysis must include this additional
separate judging completion as well as the completed MMSafety recovery.

AirBench recovery observation, 20:51 UTC on 6 September. The first new scoring
attempt returned the actual tokens `[1071, 19193, 128009]`, decoded as
` saidsafe<|eot_id|>`. This is not the earlier special-token header defect and
is not a valid safety verdict. The recovery retained its raw shadow trail,
completed zero new judgments, and automatically resumed GPU0 scheduling.
No target response was regenerated.

The opt-in recovery at `098bdcc` records such unparsed local Guard outputs as
separate evaluator failures and continues the other saved responses. Its new
launch/completion version 2 binds that policy explicitly; version 1 keeps its
original fail-stop behavior. A failure cannot overlap a judgment, change its
response identity, or contain a confidence-qualified verdict. Infrastructure,
configuration and admission errors still stop execution. No parser, confidence
threshold, judge configuration or Runner grid is relaxed. Forty-two affected
recovery checks, nine handoff/publication checks, Ruff and four reversals pass
on the rig. The actual 1,854/644/1,210 source and malformed output validate with
zero new inference and all 21 original files unchanged.

Every pending response still requires an attempted classification. Invalid
classifier outputs are not target instability or missing target responses.
Analysis must retain their count, identities and trails, show incomplete
judging coverage, keep the full input population, and restrict safety metrics
and the ordinary audit join to actual valid judgments. The original failed
grid remains failed. This is a terminal failure disposition under Gate 7's
existing success-only analysis rule, not permission to claim full scoring.
Actual continuation, terminal reconciliation and report validation remain open.
The version-2 waiter `ura-rr-air-judging-v2-20260906/recover` was queued at
21:10 UTC. Its 53,619-byte launch binds SHA-256
`dbf1a30cfcac3b03a123043665d8a339b88c4a18ea22158dcbfc512bbf20bb36`
and reuses the sealed judge without downloads. The failed version-1 recovery
remains immutable historical evidence; use the version-2 terminal for the
eventual AirBench analysis handoff, alongside the completed MMSafety terminal.

AirBench version-2 recovery completed at 23:01:51 UTC on 6 September. All 1,210
pending classifications were attempted: 1,208 yielded judgments and two retained
the invalid `saidsafe` output without a safety verdict. Together with the 644
original judgments, this gives 1,852 judgments over all 1,854 retained responses.
The actual exact-source report read passes with zero inference, a lossless
1,852-row judgment join, explicit two-row evaluator-failure coverage, and all
21 original files unchanged. Original/recovered reports remain separate at
644/1,208 rows. Evidence is under
`engineering/rr-evaluator-failure-20260906/actual-air-completion`; the result
SHA-256 is `8888f058052b6d956e543188338ace5fcda24a47060f7f7feabe4588ce02852e`.
There are no unattempted AirBench classifications. Judging coverage is still
incomplete by two verdicts, and the original failed grid is not promoted.

The original GPU0 worker is terminal. R-Judge, like GPTGeoChat earlier, failed
its canary on the legacy chat template before any measured response. The
existing retry transport already fixes that rendering, but its selector
compared the error's revision-resolved model identity against an unqualified
alias. `72b13e1` accepts only that alias or its independently pinned exact
revision; foreign repositories/revisions and any measured-response replay remain
rejected. Sixteen affected rig tests, Ruff, two reversals and the real no-call
selection pass. The selected recovery is exactly 100 R-Judge plus 2,020
GPTGeoChat inputs, excluding every measured MMSafety response. It started at
23:25 UTC in `ura-rr-template-retry-72b13e1/retry` on the released GPU0, with
the unchanged 4,096-token, one-GPU profile and one answer retry. GPU1 continues
its original queue. The old failed waiter remains terminal, not a live job.

RR counter reconciliation, 6 September. The final analysis preserves the
controller's reported count separately from corrected checkpoint-inclusive
coverage. If these differ, the reported value must be reproduced by the exact
execution-source reader before acceptance; current complete input coverage and
judgment checks remain mandatory. A call-free check on the frozen MMSafety and
HoliSafe segments reproduces 76 versus 300 MMSafety responses and the unchanged
239-row HoliSafe control. Neither the original failed artifacts nor the
200-response prefix is rewritten. This repairs counter reconciliation, not the
remaining scoring recovery or the whole-campaign seal.

RR analysis supplement. The validated 144-condition historical inventory keeps
its original scope and revision-separated results. The current-profile RR
controller in `experiments.local_campaign.rr_profiled_phase6` publishes its own
parent and measured-unit Jobs. After all four units complete,
`experiments.local_campaign.rr_profiled_analysis` validates that completion and
uses the existing Level-1/Level-2 exporters and generic Stats registration for a
separate RR cohort. It reports coverage, outcomes, model stability, effective
context, output allowance, token usage and truncation. This does not overwrite
the historical RR failures or pool RR with the base model. A paired defense
estimate additionally requires matching input and serving conditions. Gate 7
for the whole local program requires both the historical analysis and this
supplement, plus the input-alignment audit; a historical-only analysis seal
does not authorize the hosted follow-on.

Historical analysis completed on 5 September at 20:41 UTC. Its 38 validated
reports are now published at
`/stats/job/historical-analysis-144-20260905`, including metric charts,
execution accounting and resolvable artifacts. Completed producers were reused.
Sensitivity/kappa retain their declared limitations; transfer is explicitly
unavailable where exact execution conditions do not support a comparison.
This closes the historical handoff only. RR completion and its separate analysis
remain required, and the original failed jobs remain unchanged.

RR bounded continuation. Each measured unit has an 86,400-second subprocess
bound and a durable 86,400-second Runner call-start deadline. Restarting the
same command does not reset that deadline. The parent's 96-hour Jobs field is
display metadata, not an additional process watchdog. If a unit reaches its
bound before completing, retain its terminal record and every response
checkpoint. After the parent is terminal, run the existing RR controller with
`--continue-from <completion.json> --continue-from-sha256 <exact SHA-256>`,
the normal project/work root, project-revision receipt, commit, scope and tmux
arguments, and a fresh `--control-root`. The continuation reads the original
source specifications and admitted serving profile from that bound chain;
do not supply replacement profile settings or repeat readiness/installations.
It reuses an existing canary, refreshes the expiring transport attestation,
and derives new exact acquisition/projection bindings for the unfinished set.

The continuation excludes every durable response, including missing, failed
and length-ended outputs. It never treats poor quality as permission to repeat
an assigned query. Completed lanes are not scheduled again. Within a partly
covered lane, it first finishes partially covered arms using the existing
positive-count completed-ID selector; any untouched arms follow in the next
bounded continuation. Repeat only while the validated chain has unattempted
IDs. Do not branch from an older completion after a successor has retained
responses. Exact full coverage remains 7,606 input identities, not the sum of
nominal launch sizes. Continuation analysis keeps a separate coverage record
and one Level-1 report per execution revision. Interrupted prefixes remain
unpromoted; include their retained responses in post-factum local judging
before claiming all-row judged evidence. The historical 144-condition cohort
and its original failures remain unchanged.

Parallel RR scheduling decision, 5 September. The operator selected two
independent one-GPU workers while retaining the admitted 4,096-token output
allowance. The suggested 1,536/2,048-token alternatives are not adopted. Keep
all 7,606 selected identities, the original seeds and the existing model bytes;
exclude every durable predecessor response from new target calls. The current
TP1 RR profile fits one 24 GiB card. Record each worker's physical GPU assignment
and isolate its CUDA visibility; a model requiring both cards instead owns both
exclusively and must not overlap another target or scoring model.

The prospective parallel launch uses the existing response checkpoints to
separate target generation and scoring into fresh processes. An in-process
close is insufficient when vLLM retains its allocations. Each worker's judge
uses its own visible GPU only after the target process has exited. This is
post-response scoring, not target/judge co-residency. Validate that handoff with
a short admitted probe on the actual assigned device before measured execution.
Do not repeat runtime installations or the already-passed full readiness survey.

Declare a 259,200-second measured deadline and subprocess bound, with a
96-hour attestation-age policy to include preparation margin, in each fresh
request before acquisition and projection. These are explicit prospective
scheduling/freshness conditions, not changes to the retained 86,400-second or
24-hour requests. The exact model, source, transport and receipt checks remain.
Bind any interrupted predecessor's actual stopped-process observation and
durable files; never manufacture a normal completion or promote its unfinished
grid. Its unjudged responses still require post-factum scoring. At the observed
roughly 66 seconds per response, two balanced workers imply about 68 hours of
generation for the then-remaining population; loading, image processing,
judging and retries are additional. Replace that extrapolation with measured
parallel throughput, and report scheduling conditions separately in Stats.

Parallel handoff record, 5 September, 18:42 UTC. The original prefix has 199
length-ended responses, one normal stop and no missing output. All 200 original
closed-cell judgments are retained; none requires a repeated target call or
judge call. Its interrupted parent is not promoted. The first parallel startup
was stopped before measured execution because sealed-cache verification took
an exclusive resource lock and conflicted with another reader. The correction
uses shared locks only for existing published resources, retains exclusive
writer locks, and waits within the already declared acquisition deadline.
Two real concurrent cache verifications passed while runtime read leases stayed
held, with zero downloads or model calls. The focused deployment passed 134
tests with four platform skips. The fresh continuation is
`phase6-rr-parallel-5207b3d-20260905T184300Z`; both worker Jobs resolve in the UI.
At 19:32 UTC both GPUs were generating, with 226 durable responses including
the original 200 and zero repeats. The approximately 68-hour generation
extrapolation still excludes preparation, judging and analysis. Existing
framework environments and model files are reused.

Failed preparation recovery. The RR GPTGeoChat canary rejected a leading
system instruction in the sealed tokenizer's system-less legacy Mistral
template, before any measured response. The verified renderer preserves that
instruction in the first user turn and records the rendering condition; it does
not alter the converted input or source receipt. A frozen `e7b3220` checkout
owns the failed-only retry scheduled at 19:50 UTC. It waits for the original
GPU0 worker to terminate and release its device, then repeats the corrected
canary and executes the exact 2,020 previously unmeasured GPTGeoChat inputs.
The active `5207b3d` workers are not repinned. The existing LLaVA-base
GPTGeoChat population has 2,020 nonempty, normally stopped responses with
validated source evaluations and is not repeated. Retry completion is an
additional analysis input, never a rewrite of the original failed terminal;
full RR coverage still requires the exact disjoint 7,606-input union.

Initial RR interpretation check (5 September). The first 11 retained measured
StrongREJECT outputs all ended at the approved 4,096-token allowance in about
66 seconds and contained extreme repetition. Their prompts were only 24-76
tokens, well within the effective 32,768-token context. The retained readiness
answers are coherent and stopped normally, so these observations do not establish
a generally nonfunctional model or an undersized-context failure. RR redirects
harmful representations away from their original direction; meaningful refusal
or EOS routing is described as future work in the authors'
[paper](https://arxiv.org/html/2406.04313v4). This mechanism is a possible
explanation, not a measured causal attribution. Retain the original text,
token usage and truncation separately from missing output; a nonempty emitted
response is not itself evidence of coherence. Do not change the admitted
generation policy after seeing these outputs. The first-arm throughput must
inform the completion forecast and any prospective checkpoint continuation;
it does not establish throughput for every remaining arm or modality.

Goal: exercise and, where the admission gates allow, measure the complete
portfolio without spending provider budget:

- all 45 logical corpus arms of the 25 converter families (28 common-metric,
  2 source-classification, 15 conversion-only);
- all 16 isolated framework runtimes and all 20 attacker dispositions, plus the
  nine source-native engines;
- only free targets and judges: local vLLM checkpoints, locally pulled Ollama
  models, the deterministic rules judge and a locally served guardrail classifier.

Evidence boundary. Lanes that pass the normal measured admission (project
revision receipt, source-conformance receipt, local transport attestation,
no-call projection, canary, caps) produce ordinary measured Level-1/Level-2
evidence for the local tier of Chapter V (RQ1, RQ3, RQ4a, RQ4b local parts).
Everything else (dry runs, installer receipts, engineering campaigns, one-case
native canaries) is engineering diagnostics and stays outside `runs/thesis`.
Hosted-only constructs stay `N/A` here: the focal Fable/Sol pair (RQ2), audio
and video lanes (the local vLLM/Ollama renderers are text and image only), the
hosted LLM-judge stage, and any native engine that cannot be pointed at a local
endpoint.

Controller source and binding boundary. Reusable Phase 3-8 controller logic is
versioned under `experiments/local_campaign/templates/`, with its renderer,
verifier and package installer under `experiments/local_campaign/`. A controller
instance cannot be stored as authoritative source because it binds the commit
that contains the templates, deployed-revision receipt hashes, source receipt
hashes, run tags and rig paths. The renderer therefore writes those disposable,
commit-bound instances to the workstation `.campaign` control directory before
they are verified and transferred to the rig. `.campaign` is neither a Git
worktree nor an alternative source authority. Any reusable logic change goes to
the tracked templates first and is tested there; generated instances are never
edited as the implementation.

## 0. Readiness snapshot (20 August 2026) and blockers

| Surface | State found | Consequence |
|---|---|---|
| Code pin | rig and workstation at the same Project commit; clean-env suite green on both | re-pin to the post-fix-wave commit with `distro/repin.sh` before anything else |
| Corpora | 44/45 locators resolve; `bipia_test_qa` missing (licensed NewsQA) | `bipia_test_qa` stays blocked/N/A |
| Source receipt | historical 26-arm receipt bound; 19 arms (6 aggregator + 13 conversion-only) have no entry | a fresh 45-arm receipt is required before any measured lane (Phase 2) |
| Framework runtimes | 1/15 installed under the lock (PyRIT); legacy pre-lock venvs exist but are not installer-managed | install and verify the other 14 (Phase 1, ~65 GiB, 3-6 h) |
| Local models | Qwen3-VL-8B, LLaVA-1.6 base and GraySwan RR only in a legacy HF hub; sealed store absent; no Llama Guard | sealed acquisition for 3 targets + 2 guards (Phase 3, ~80 GB) |
| Ollama | historical snapshot: daemon owned by the console and three small rwkv-7 models | later superseded by the exact current four-model roster; no RWKV model is scheduled prospectively |
| Main venv | contains pyrit 0.14.0, spikee 0.9.1, datasets 4.8.4 (isolation policy violation) | remove in Phase 0 |
| Temp | `/tmp/pytest-of-ura` leftovers (~850 MB) | clear before the re-pin gate |

Operator-only gates (cannot be delegated): license/access decisions for the
six aggregator sources in the new receipt; Hugging Face gated-model access and
`HF_TOKEN` for Llama Guard; the ethics/consent determination before any human
audit; any future paid call (none planned here).

## 1. Phase 0: hygiene and pin (about 1 hour)

1. Bundle transport and re-pin [17, 18; `distro/README.md`]: locally
   `git bundle create web002.bundle main`, `scp` it to `ura-rig:~/web002.bundle`
   together with the `distro/repin.sh` of the commit being deployed
   (`scp distro/repin.sh ura-rig:~/repin.sh`; the in-tree copy on the rig is
   the currently pinned commit's version), then on the rig
   `bash ~/repin.sh <40-hex-commit>`. The
   script kills stray `run_matrix`/`rig_web` processes, clears
   `/tmp/pytest-of-ura`, runs the clean-env full suite (admission condition),
   refreshes the vLLM roster, writes and validates the project-revision receipt,
   rebinds `~/.ura_campaign_env`, revalidates the bound source receipt and
   restarts the console on `127.0.0.1:8642`.
2. Main-venv isolation: `distro/install.sh deps` removes only legacy duplicate
   `pyrit`, `spikee`, `datasets`, and `jsonlines` top-level installs, then runs
   `pip check`. PyRIT and Spikee remain in their locked framework stores; BIPIA's
   `datasets==2.14.7` builder lives in its own fully hashed, no-system-site-
   packages environment under `$URA_WORK/support-venvs`. No framework is
   discarded because of a main-environment conflict.
3. Confirm the console dashboard shows the new pin, and that Build -> Runtimes
   lists the 16 lock entries with their current status.

Gate 0: suite green on the rig at the new pin; receipt valid; console 200.

## 2. Phase 1: all 16 framework runtimes (3-6 hours, mostly unattended)

Runbook 12.2 and 14.1 are the authoritative commands. With the lock's env-root
and state-root conventions (`URA_FRAMEWORK_ENVS=$URA_WORK/framework-venvs`,
`URA_FRAMEWORK_STATE=$URA_WORK/runs/engineering/framework-runtime-<lock-id12>`,
`URA_FRAMEWORK_PYTHON` = the uv CPython 3.12.13 base interpreter):

```bash
distro/install.sh runtimes

# The equivalent manual unit verifies before any mutation:
python -m experiments.framework_runtime_installer verify --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
# Across an aggregate-lock change, an unchanged row may be adopted only from
# an explicit retained prior lock after exact row/global-pin and seal checks:
python -m experiments.framework_runtime_installer adopt --from-lock "$URA_FRAMEWORK_ADOPT_FROM_LOCK" --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
# Use resume only for a missing, interrupted, new or changed row, then verify:
python -m experiments.framework_runtime_installer resume --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
python -m experiments.framework_runtime_installer verify --only pyrit --lock "$URA_FRAMEWORK_LOCK" --env-root "$URA_FRAMEWORK_ENVS" --state-root "$URA_FRAMEWORK_STATE" --python "$URA_FRAMEWORK_PYTHON"
```

Run one installer session per framework with `--only <name>`, tolerating a
failure and continuing, rather than a single session for all sixteen. Every row
is verified first. A passing current installation is left untouched; strict
adoption is explicit and applies only when the complete prior/current row and
execution-global pins are identical; installation/resume is reserved for a
genuinely missing, interrupted, new or changed row. The
installer is fail-closed and sequential, so one framework that cannot build
stops the whole session and hides every later defect: on 20 August a single
failing smoke blocked the twelve frameworks queued behind it, and a second,
unrelated build defect only became visible once the installs were driven one at
a time. Observed per-framework times on the rig range from about a minute
(deepteam, spikee) to roughly half an hour (h4rm3l, nanogcg); the pip cache
under `$URA_FRAMEWORK_ENVS/.cache/pip` and the npm cache under
`$URA_FRAMEWORK_ENVS/.cache/npm` are explicitly bound outside every sealed
store and persist despite each runtime's clean HOME. They affect transfer time,
not admission. The distro phase derives all 16 names from the validated lock,
continues after an isolated row failure, and returns an honest nonzero aggregate
after attempting the complete inventory. The console equivalent is Build -> Runtimes (Install / Resume /
Verify per row); use it for at least one batch so that the CLI and UI paths are
both exercised. Disk: about 65 GiB under `$URA_FRAMEWORK_ENVS`. The Node 24.16.0
runtime used by the separate Promptfoo and T3MP3ST Node stores is downloaded
and signature-verified by the installer. T3MP3ST is built from its exact source
checkout with `npm ci` against the bound upstream package lock.

Then materialize one private engine runtime configuration for each selected
persistent-worker bridge [12.2]. The campaign controllers create these files
under their private, campaign-tagged state root and bind each file by SHA-256 to
the one lane that consumes it:

```bash
export URA_LANE_ENGINE_CONFIG_ROOT="$URA_WORK/state/bridge-configs/<campaign-tag>"
test ! -e "$URA_LANE_ENGINE_CONFIG_ROOT" || exit 1
mkdir -m 700 -p "$URA_LANE_ENGINE_CONFIG_ROOT"
URA_LANE_ENGINE_STORE="$(ura_runtime_store pyrit)" || exit $?
export URA_LANE_ENGINE_PYTHON="$URA_LANE_ENGINE_STORE/bin/python"
[[ -x "$URA_LANE_ENGINE_PYTHON" ]] || exit 1
python -m experiments.engine_runtime_config \
  --runtime pyrit=URA_LANE_ENGINE_PYTHON \
  --out "$URA_LANE_ENGINE_CONFIG_ROOT/pyrit.json"
# Repeat only for a selected deepteam, h4rm3l or spikee lane.
# Each output is create-only ura-engine-runtime-config/1 and resolves into the
# already verified content-addressed store. No global combined config is needed.
```

Gate 1: `verify` reports all 16 passed (content seals, smoke) and Build ->
Runtimes shows 16 verified rows; a `run_matrix --dry-run --corpora synth
--exclude-tool-conditioned --attackers pyrit --engine-runtime-config ...` lane
succeeds for each of pyrit, deepteam, h4rm3l, spikee (sealed worker opening and
closing seals present in the manifest).

## 3. Phase 2: source admission for all 45 arms (2-4 hours plus observation runs)

1. Unset the bound historical receipt variables (`URA_SOURCE_CONFORMANCE_MANIFEST`,
   `URA_SOURCE_CONFORMANCE_SHA256`) in the working shell [4.1 note].
2. Scaffold a fresh receipt for all 45 arms:
   `python -m experiments.source_conformance --scaffold --source-config
   experiments/source-instances.json ...` [4.1], then fill every `OPERATOR_TODO`:
   observed release/split, declared file hashes, reconciled discovered/accepted/
   rejected counts, the license/access decision (operator), and a reviewer-
   attributed semantic mapping review per arm. The 19 previously approved sources
   keep their recorded decisions; the six aggregator sources (SALAD-Bench,
   AIR-Bench 2024, XSTest, SimpleSafetyTests, HoliSafe, DecodingTrust stereotype)
   need new operator decisions; `bipia_test_qa` is recorded as blocked.
3. Retain the VLSBench and JALMBench exporter summaries under
   `runs/thesis/source-export-summaries/` and point the receipt component
   variables at them [4, RA-025].
4. Validate, hash and bind the new receipt (`--manifest --sha256`), then run one
   bounded offline observation per arm (MockTarget, no model call):
   `run_matrix --dry-run --corpora <arm> --attackers replay --judges rules,llm
   --limit 2 --sample-seed 0 --out runs/thesis/source-review-observation/<arm>`
   (the dry-run judge is the mock stage, so `rules,llm` is the documented dry
   cascade; a rules-only dry lane fails closed when the rule stage abstains; add
   `--exclude-tool-conditioned` for tool-conditioned arms). Expect 44 clean
   observations; `bipia_test_qa` blocked.

Gate 2: `source_conformance` validates the new receipt with 44 admitted arms
(or 43 plus explicit blocks); the console source catalogue shows the same
dispositions (45 arms, 28/2/15 partition, tool arms fail-closed, approximate
opt-in badges only where expected).

## 4. Phase 3: free models (1-3 hours of downloads)

Sealed acquisition [6.1] through Build -> `Plan & acquire` (preferred) or the
CLI plan -> acquire -> run chain, for:

| Role | Identity | Size | Placement |
|---|---|---|---|
| target | `vllm:Qwen/Qwen3-VL-8B-Instruct` @ exact revision (text+image) | 16.34 GiB | two GPUs, BF16, TP 2, hardware-fit context |
| target | `vllm:llava-hf/llava-v1.6-mistral-7b-hf` @ exact revision (text+image) | 14.10 GiB | GPU 0 |
| target | `vllm:GraySwanAI/llava-v1.6-mistral-7b-hf-RR` @ exact revision (same-base defense pair) | 27.59 GiB | GPU 0 |
| scoring guard | `meta-llama/Llama-Guard-3-8B` (gated; HF_TOKEN) | 29.93 GiB | GPU 1 (`--guardrail-device cuda:1`) |
| defense guard (optional, hosted lanes only in the runbook; here used for the local text-only defense contrast if VRAM permits) | `meta-llama/Llama-Guard-3-1B` | 5.59 GiB (6,005,361,738 sealed bytes) | GPU 1 |

The legacy hub bytes under `/mnt/stor/data/ura/hf/post-release-.../hub` may be
reused as the transport cache only through the sealed controller; no manual
copies into the store.

**These are complete-sibling-set sizes, not weight sizes.** The seal proves the
complete official sibling set for the exact commit, so acquisition fetches every
file in the revision, not only the ones the server loads. That is why the two
Llama Guard entries are roughly twice their servable weights: both Meta repos
ship an `original/` PyTorch checkpoint that vLLM never reads, 14.96 GiB of the
3-8B total and 2.79 GiB of the 3-1B total. Budget acquisition time and disk
against the figures above; the earlier "~16 GB" for the 3-8B was the weight size
and understated the transfer by nearly half. The current Ollama cohort is
Gemma 4 12B Instruct Q4_K_M, Ministral 3 14B Instruct 2512 Q4_K_M,
DeepSeek-R1 Distill Qwen 32B Q4_K_M, and GPT-OSS 20B in its native MXFP4
representation. A row becomes selectable only after the live roster
shows its exact digest and a load smoke succeeds. Before any local target enters
security projection, canary or measured execution, it must also pass the
transport-neutral `experiments.local_model_readiness` gate. The gate selects the
same ten benign questions deterministically from a fixed twenty-question bank
with seed 20260829 and requires at least five correct. The other five answers
may be incorrect or empty. For an image-capable target, it adds five
deterministic synthetic split-color images and requires at least two correct;
the other three may be incorrect or empty. The current `/4` gate first forces
one text generation at 25,000 tokens, then descends through 16,384, 8,192,
4,096, 2,048, 1,024, 512, and 256. It stops at the first cap that reaches at
least 95 percent of the requested output below 120 seconds. An image-capable
target must also return a nonempty physical-image response below that deadline;
a valid voluntary stop is not confused with failed text throughput. The
10-text/5-image survey then runs once at that cap. The identity-bound readiness
schema `/4` is retained through the execution-profile registry schema `/3` and
consumed by CLI and Build. It binds maximum hardware-fit context,
vLLM tensor-parallel size and GPU memory utilization, plus Ollama thinking mode
where applicable. An unprofiled local
generative model is rejected, and the approved values replace campaign-local
overrides. Readiness `/1` through `/3` and profile registries `/1` and `/2`
remain historical evidence but cannot admit a new local inference call.
This applies to the
three vLLM targets and all four Ollama targets. Guard and classifier checkpoints
instead retain their role-specific classifier smoke because free-form Q&A is not
their served interface. The readiness receipt is engineering admission evidence,
not a safety result. A failing target is retained as failed and receives no new
security calls. A recent, relevant, hardware-fitting replacement may then be
selected as a new exact model condition with its own pin, acquisition,
readiness receipt, projections and Gate amendment; it never inherits the failed
target's identity or artifacts. Multi-model Ollama acquisition uses
`python -m experiments.local_campaign.ollama_acquire` in a named tmux session.
The controller retains one canonical event ledger, skips models whose load smoke
already completed, and retries an interrupted `/api/pull` with 30-to-300-second
bounded backoff under a seven-day controller deadline. Socket, DNS, Ollama
internal-retry and mid-stream HTTP disconnects are retried inside the same tmux
controller. A stream that stays connected but reports no changed status or byte
count for 15 minutes is also closed and retried, and Ollama resumes retained
partial blobs. Relaunch the same command with `--resume` and the same absolute
`--out-dir` and model order only after a controller-process or host interruption;
a changed roster or terminal output root is refused. Non-network failures and
deadline expiry remain typed terminal failures rather than being restarted
blindly. Gemma 4 and Ministral 3 admit
text and image lanes; DeepSeek-R1 Distill and GPT-OSS admit text lanes only.
Every empty survey item remains in the receipt as `model_nonresponse`. Measured
campaign postprocessing likewise retains a typed model nonresponse as missing
response evidence and reports it through missingness and decision coverage; it
is never dropped or counted as a decided safety label. Level-1 judgment and
planning-stratum ledgers retain the count even when no estimate exists. Level-2
rows expose `judgments_missing_responses` when an estimate row exists, and
Stats labels both surfaces as missing responses.
The superseded RWKV tags have been removed from the live roster and from every
prospective task. Their immutable historical artifacts remain readable.

Local fit: one local target per process; GPU 0 target, GPU 1 scoring guard; the
two-card 70B profile (4-bit, TP 2) is admitted by the fit calculator but is not
part of this plan.

The CLI chain, verified on the rig, is plan then acquire. Two details are easy
to get wrong and both fail closed with an exact message:

```bash
# 1. Derive this preflight request's plan. --preflight-only is present because
#    the later consumer is a preflight, not because plan-only requires it.
#    A canary plan instead includes --diagnostic-canary and its exact live-
#    attestation arguments. A measured plan includes neither purpose flag and
#    includes its exact live-attestation arguments. The plan directory must be
#    an already-resolved absolute path: ~/MLLMRiskBench/runs is a symlink into
#    $URA_WORK, so pass the $URA_WORK path itself.
PLAN_DIR="$URA_WORK/runs/thesis/acquisition/<target-label>"
python -m experiments.run_matrix --model-acquisition-plan-only --preflight-only   --model-acquisition-plan-dir "$PLAN_DIR"   --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG"   --attackers replay --judges rules --corpora xstest_full   --source-config experiments/source-instances.json   --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1   --out "$URA_WORK/runs/thesis/acquisition/<target-label>-run"
# stdout carries plan_id and plan_sha256; the plan file lands in $PLAN_DIR.

# 2. Acquire against that exact plan, bounded by size, free space and a deadline.
python -m experiments.model_acquire --plan "$PLAN_DIR/<plan_id>.plan.json"   --plan-sha256 "$PLAN_SHA256" --store "$URA_MODEL_STORE"   --receipts-dir "$URA_WORK/runs/thesis/acquisition/receipts"   --min-free-bytes $((200 * 1024 ** 3)) --deadline-seconds 14400
```

A gated identity (both Llama Guard sizes) needs `HF_TOKEN` in the environment
for the acquisition step only; source `~/.ura_env` for that call and never log
it.

**The acquisition plan binds the request envelope, not just the model set.** A
plan derived for one set of run arguments will not admit a run with different
ones: changing `--limit`, adding call caps or a deadline, or changing the
execution purpose changes the bound envelope and admission fails with
`acquisition plan resources or immutable selection bindings differ`. A
preflight plan therefore cannot admit a diagnostic canary or measured run, and
a canary plan cannot admit the measured run. The working procedure, verified
on the rig, is per exact purpose-specific request:

1. derive the plan with **the exact arguments that lane will run with**,
2. acquire against that plan, which is a no-op import once the store holds the
   snapshot, and reports `downloaded_bytes: 0`,
3. run the lane with those same arguments plus the plan, receipt and store.

Put **every** run argument for that one request in one shell array and reuse it
verbatim for all three steps. Use separate arrays and separate plans for the
preflight projection, diagnostic canary and measured run. The preflight array
contains `--preflight-only`; the canary array contains `--diagnostic-canary`
without `--preflight-only`; the measured array contains neither flag. This
specifically includes `--max-total-target-calls`,
`--max-total-judge-calls` and `--deadline-seconds`: they look like execution
bounds rather than selection, but they are part of the bound envelope, and
adding them at run time after deriving the plan without them fails admission.
This exact mistake was made once while executing this plan, so it is worth
stating plainly rather than leaving to care.

```bash
PREFLIGHT_LANE=(--preflight-only
      --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG"
      --attackers replay --judges rules --corpora "$ARM"
      --source-config experiments/source-instances.json
      --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1
      --max-total-target-calls 2 --max-total-judge-calls 2 --deadline-seconds 3600
      --out "$OUT_ROOT")
# Derive with "${PREFLIGHT_LANE[@]}", acquire, then preflight with that same
# array plus the plan/receipt/store locators. Build a separate exact array for
# each canary or measured request. Never add an argument to only one step.
```

The cost of the extra plan and receipt per lane is negligible, because
acquisition re-imports nothing; the benefit is that each receipt states exactly
which models that exact request needed.

Gate 3: acquisition receipts present and bound; every selected generative local
target has a passing `ura-local-model-readiness/1` receipt for its declared
modalities; `python -m experiments.local_targets`
shows the three vLLM rows as compatible with an exact revision/digest; the
console Build model picker shows the same rows under Local vLLM and the Ollama
rows under Local Ollama.

Status, 21 August 2026: **met for the three targets.** By 25 August both guards
were also sealed and the 1B guard's fit check passed, completing all five
snapshots. Each target was sealed with `downloaded_bytes: 0`, because the rig
already held all three target snapshots at exactly the pinned commits in a
legacy Hugging Face hub, which was staged as the controller's transport cache
by hard link. That costs no disk, leaves the legacy hub intact and is not a
manual copy into the managed store: promotion is gated on `seal_snapshot`,
which proves the complete official sibling set and every Git/LFS content
identity against the upstream manifest for the exact commit before anything is
promoted. The three target receipts bind 16, 17 and 26 files respectively,
matching the sibling counts verified upstream before acquisition.
The store and each receipt with its digest are bound in `~/.ura_campaign_env`
as `URA_MODEL_STORE` and `URA_ACQ_RECEIPT_*`. Both Llama Guard sizes are gated
and are not in the legacy hub, so they are genuine downloads; their pinned
commits are `7327bd9f6efbbe6101dc6cc4736302b3cbb6e425` (3-8B) and
`acf7aafa60f0410f8f42b1fa35e077d705892029` (3-1B).

## 5. Phase 4: local transport attestations (about 1 hour)

For every local target x modality combination that a lane will use, run the
bounded attestation probe and produce its receipt [8]. The execution scope is
one non-secret label, declared once and reused verbatim by every probe, receipt
and measured grid of this campaign, because admission matches the probe's scope
against the grid's. It is bound in `~/.ura_campaign_env` beside the other
locators so no phase can drift from it:

```bash
export SCOPE="${URA_EXECUTION_SCOPE_ID:?bind it in ~/.ura_campaign_env first}"
# bigrigsys-local-vllm: this rig, on-rig vLLM, no provider account involved.

python -m experiments.run_matrix --attestation-probe --local "$LOCAL_SPEC" --local-config "$LOCAL_CONFIG" \
  --attackers replay --judges rules,guardrail \
  --guardrail-model meta-llama/Llama-Guard-3-8B \
  --guardrail-revision 7327bd9f6efbbe6101dc6cc4736302b3cbb6e425 \
  --guardrail-device cuda:1 \
  --corpora <one text arm> --source-config experiments/source-instances.json \
  --limit 1 --sample-seed 0 --seeds 0 --max-queries 1 --max-turns 1 --execution-scope-id "$SCOPE" ... --out runs/thesis/attestation/<target>-text
# --out is the receipt FILE, opened create-only, not a directory: pointing
# it at a directory fails with File exists, and pointing it at an existing
# receipt fails too, so each derivation names a new path.
python -m experiments.live_attestation --probe-root runs/thesis/attestation/<target>-text \
  --execution-scope-id "$SCOPE" \
  --out runs/thesis/attestation/receipts/<target>-text.json   # ura-live-attestation/2
```

Although the receipt establishes transport identity rather than a benchmark
score, the probe is a complete Runner cell and retains a stage-shaped judgment
record. Local probes therefore use the sealed local guardrail after the rules
stage, so a rules abstention cannot turn a valid transport observation into a
controller failure. The purpose-bound acquisition contains target plus guard
for vLLM targets and the guard alone for an Ollama target. It performs no hosted
judge call.

Repeat with a text+image arm (for example `mossbench_official`) for the
image combination, and once per Ollama target for text. These are free (local
GPU only). Receipts are content-addressed and expire per the recorded max-age
policy, so schedule them immediately before the measured lanes.

Gate 4: one valid receipt per (target, modality combination) that Phase 6 uses.
Because these receipts expire under their recorded maximum-age policy, each
required route must meet Gate 4 immediately before its live canary. Gate 5
finalization then revalidates current receipt coverage against the resulting
runnable inventory before it admits Phase 6.

## 6. Phase 5: no-call projections and one-cluster canaries (2-4 hours)

For each planned measured lane: `rig_check` with the exact lane arguments
(projection, policy-stratum counts, guard load) [9], then one
`run_matrix --diagnostic-canary` with `--limit 1` on one arm [9.1], then
`lane_canary`.

`rig_check` is subject to the same sealed-model admission as a measured run,
verified here rather than discovered mid-phase: without an exact acquisition
plan, plan SHA-256, receipt, receipt SHA-256 and managed store it refuses with
`normal and preflight Hub runs require exact acquisition plan, ...`, persists a
request-error artifact and stops. So each projection needs the per-lane
plan-acquire sequence of Phase 3, derived with that lane's exact arguments, for
the same envelope-binding reason: the caps a projection reports are only
meaningful for the request they were derived from. Build one exact argument
array per purpose, then reuse that array only for its own plan derivation,
acquisition and execution. The projection, diagnostic canary and measured run
have distinct purpose-bound plans and receipts even when their model resources
are already present and acquisition downloads zero bytes. Record approved
call/time/storage caps from the projection before any measured lane. Judges for
local-target lanes are `rules,guardrail` (no hosted LLM judge; a local LLM judge
cannot share a process with a local target).

**Prospective bounded-sampling amendment (24 August 2026).** Before any Phase 6
measured lane started, the local programme replaced its earlier exhaustive-local
assumption with two measured population tiers. Core model-comparison lanes use
`--limit 100 --sample-seed 0 --seeds 0`; extended Runner-safe bridge lanes use
`--limit 50 --sample-seed 0 --seeds 0`. The amendment was fixed from source
inventories, no-call projections and diagnostic feasibility, not from measured
benchmark outcomes. `--limit N` is an equal per-arm cap applied independently
within every logical source arm. It selects a deterministic prefix of whole
prompt/intent clusters without replacement and retains every sibling row, so
this is not a risk-stratified or proportional-probability sample. Cluster-key
fallback precedence is nonblank `meta["source_cluster_id"]`, then nonblank
`DataPoint.id`, then the converted row index. Unique cluster keys are inventoried
in first source-appearance order. SHA-256 hashes the UTF-8 bytes
`ura-corpus-cluster-order-v1\0<logical-arm>\0<sample_seed>`; its first eight
bytes, interpreted as an unsigned big-endian integer, provide `scoped_seed` to
Python's `random.Random(scoped_seed).shuffle(...)`. The first N shuffled
positions are selected, then all selected rows are restored to source order.
These are nested, overlapping prefixes, not disjoint partitions: for one
unchanged arm, converted-corpus digest and sample seed, the one-cluster canary
is contained in the 50-cluster extended sample, which is contained in the
100-cluster core sample. Logical-arm identity contributes to seed derivation and
gives each arm an independently scoped ordering. A source with fewer clusters
is retained in full and reported as precision-limited; `--limit 0` returns the
exact full arm without sampling.

Runner also exposes the explicit policies
`seeded_pseudorandom_whole_cluster_prefix_v1` and
`source_order_whole_cluster_prefix_v1`. The second takes the first N cluster
keys in source-appearance order, still retaining every sibling row. The current
local campaign omits `--sampling-policy`, which deliberately preserves the
deployed seeded pseudorandom behavior and its existing request shapes. Any
future explicit policy is a separate request, acquisition, projection and
analysis identity; changing policy cannot reuse the current cohort's Gate 5
record. Both policies treat `--limit 0` as the exact full arm.

The earlier `--limit 0` projections remain useful as full-universe capacity
records but cannot authorize a bounded measured request. Every bounded lane
therefore receives a new exact no-call projection, acquisition plan and receipt,
request envelope and Gate 5 cap. Existing commit-matched `--limit 1` canaries may
remain as nested diagnostics when every other model, attacker, judge and source
identity is unchanged. HarmBench preparation is selection-bound and must be
regenerated at limit 50. The framework supports full-set execution for local
and hosted targets through explicit `--limit 0` with a complete projection and
sufficient admitted caps. A source-mapped prepared artifact can still bind a
narrower selection; the general full-set capability does not broaden that
manifest. Current-campaign policy authorizes
full mode only for all-local replication, as a separately approved cohort with
its own projection, caps, output roots and analysis stratum; it is not part of
the bounded Phase 6 cohort. The current measured cohort uses
`--sample-seed 0` only.
`--sample-seed 1` is a separately projected future cohort that requires its own
selection-bound projections, acquisition envelopes, Gate 5 caps, output roots
and analysis stratum before any calls; it is never appended to the seed-0 cohort
in response to observed throughput or outcomes.

**What this cascade can and cannot measure.** The guardrail is a content-safety
classifier: its label space is violation/safe, and it cannot express
over-refusal, because a refusal is itself safe content. It therefore adjudicates
harmful-probe violations, and on a benign probe it now defers rather than
returning a confident `safe`, which would otherwise have answered the
over-refusal question it cannot see and biased the benign over-refusal rate
toward zero. Benign rows are consequently decided by the deterministic rules
stage alone, and a benign row that the rules stage cannot classify confidently
fails closed: it is excluded from the over-refusal denominator rather than
silently counted as a non-refusal. Harmful-failure coverage is unaffected.

Two consequences for reading these lanes. First, report benign coverage, the
share of benign rows actually decided, beside every over-refusal rate; a rate
computed over a small decided subset is not comparable with one over the full
benign set. Second, where over-refusal coverage matters more than throughput,
add a local LLM judge stage for the benign arms in a separate process, which
`PROTOCOL.md` already admits as a local scoring stage, at the cost of a third
model resident on the pair of cards. Every lane uses the Level-2-compatible grouping
`--group model,source,risk,effective_modality,expected_behavior,attacker,source_policy_id,source_policy_version`
(the CLI default; the Build field defaults to it; the Level-2 export rejects
narrower groupings). The bounded local cohort uses the tier-specific positive
limit above. The Build and CLI requests must emit that limit and sample seed
explicitly.

The Gate 5 inventory also records target-source pairs that cannot enter measured
execution as typed terminals. GPTGeoChat carries image-bearing source records.
Its Gemma 4 and Ministral 3 pairs are projected and canaried as multimodal
lanes. Its DeepSeek-R1 Distill and GPT-OSS pairs are `unavailable` with reason
`target_transport_text_only_for_image_source`; those two pairs never enter a
projection, canary, or measured loop.

The core cohort records `bridge-nanogcg`, `bridge-ideator`, and `t3mp3st` as
`unavailable` only because their prepared artifacts are assigned to a separate
follow-on cohort and were not bound when its Gate 5 authorization was sealed.
This is not a current capability disposition. The core controller does not
schedule those three lanes for core-cohort measured execution. The follow-on
cohort binds the newly prepared NanoGCG suffix, IDEATOR source-mapped seed-pair
manifest, and T3MP3ST bundle and uses the ordinary documented Runner commands
with one retained common scientific base and separate exact preflight, canary
and measured argument arrays. Each purpose keeps its own plan and receipt. For
each lane, the retained schedule contains a prepared artifact, no-call
projection, diagnostic canary, Gate 5 record, and measured schedule.
NanoGCG can use a positive corpus limit or a separately projected
`--limit 0` transfer cohort. Current IDEATOR v2 cannot: it is fixed to
`advbench_harmful --limit 1 --sample-seed 105`, while `pair_limit=0` means
all eight verified pairs mapped to `advbench:245`.
Prepare those two inputs with the runbook's named "NanoGCG: sealed suffix
capture, then replay" and "IDEATOR: exact VLBreakBench mapping, then Build or CLI
replay" procedures; do not substitute a manually assembled suffix or manifest.
After NanoGCG and both T3MP3ST captures are terminal, the tracked generated
`followon_prepared_controller.py` owns the remaining follow-on sequence in one
persistent tmux session. It consumes the canonical prepared artifacts, performs
the no-call projection and one-cluster canary for each lane, creates the formal
Gate 5 amendment before measured calls, attempts the three exact authorized
argv arrays independently, and produces the formal Phase 6 outcome/completion
pair. It does not alter the already sealed core Gate 5 artifacts and it does
not make this local campaign phase a product concept.

The corpus limit is the outer population selector, not a universal framework-
operation limit. `--limit 0` selects every source cluster; a positive limit uses
the seeded whole-cluster policy above. `--max-queries` and `--max-turns` must
separately cover the selected attacker's per-datapoint fanout. The bounded
HarmBench preparation is fixed to `DirectRequest`, experiment `llama2_7b`, one
case per method, limit 50, sample seed 0, a 28,800-second preparation timeout,
and query/turn bounds of one. T3MP3ST capture exposes its own corpus limit,
sample seed and per-request timeout and is bound to exact source commit
`f2eec3c48cefe301983b3865811eda89d454e988`; after the active sealed chain, run
a one-record capture/replay before the bounded capture/replay. IDEATOR v2 uses
the exact outer selection `advbench_harmful --limit 1 --sample-seed 105`;
`pair_limit=0` selects all eight source-mapped pairs and a positive value
selects their `exact_source_ordered_prefix_v2`. It is distinct from random
corpus sampling and does not admit `--limit 0` over all 520 AdvBench rows.
For the legacy v1 manifest, `pair_limit` uses 0 for all verified manifest pairs
and a positive value for `ordered_prefix_v1`; this does not change the current
v2 source mapping or outer selector.
At Runner replay time, NanoGCG accepts one attributable precomputed suffix and
has no invented quantity selector. The dedicated capture step generates that
suffix under the verified framework runtime and sealed surrogate identity.

For an R-Judge canary, source-evaluator completeness and source-evaluator
validity are separate observations. A completed prediction that does not obey
the source label format remains an exercised, complete observation with
`valid=0`; it contributes to `rjudge_validity` and the all-output accuracy
denominator. Gate 5 therefore requires the implemented source evaluator to be
queried and to complete the planned observations, but it does not require a
positive valid-prediction count or retry until a parseable answer appears.

Seven rows retain historical Gate 5 terminal records produced under the older
output policy: four exact GraySwan RR identities and three RWKV static
identities. The GraySwan probes reached the declared 4,096-token generation cap
with no stop, and a sealed Transformers control reproduced the checkpoint's
two-token repetition while the exact LLaVA base emitted EOS. The RWKV probes
either reached their generation cap or returned an exact successful empty
completion. Their create-only terminal artifacts remain immutable diagnostic
provenance and continue to bind exact model identity, configuration, diagnostic
roots and call accounting.

They are not the current disposition. Runner 2.22 and later retains every
nonempty length-capped response and its `finish_reason='length'` provenance;
Runner 2.23 retains a successful empty Ollama completion as typed
`model_nonresponse`, and Runner 2.24 applies the same typed outcome to a
successful empty vLLM completion. Runner 2.25 makes one additional answer attempt
by default for empty, malformed, binary/control-like, symbol-only or transport-
failed output. Vague, repetitive or semantically poor natural language is still
sent to the selected evaluator, which may decide or abstain. Exhausting the
answer retry writes `model_stability_status=failed_output`, does not query the
policy judge, checkpoints that row and continues until the complete assigned
population has been attempted. The row remains in the final population as a
missing response, counts in missingness and response coverage, and is excluded
from the decided safety-rate denominator. Projection and Gate caps cover two
target attempts per intended call under the default. Exact model identity,
seals, fixed configuration, durable budgets and operator wall-time limits remain
fail-closed. Neither a length-capped answer nor a failed output authorizes altered
stops, generation caps, decoding configuration or checkpoint identity.
When the adapter verifies a strong runtime/model identity before classifying the
answer as unusable, the failed-output row retains only that normalized identity
and rejects drift between attempts. A live-route attestation may therefore bind
the verified transport even when the diagnostic answer is missing; this does
not admit a safety judgment or change readiness/stability accounting.
Runner 2.26 separately retains a deterministic target-input incompatibility,
including an exact vLLM prompt-length rejection, as a typed missing response.
The unchanged input is not answer-retried, policy judges are not queried, and
the remaining selected population continues. This is input-compatibility
coverage, not model-stability failure; identity, seals, configuration, budget,
and unrelated validation or transport failures remain terminal.

An older Runner may already have stopped a lane before this policy was
available. `experiments.local_campaign.resume_current_ollama_phase6` handles
that historical boundary without redefining the experiment: it waits for the
base Phase 6 completion, selects only lanes retained as failed, and relaunches
each lane with the exact stored argv, run IDs, call-budget ledger and original
checkpoint. Sealed cells are call-free and checkpointed attempts are restored;
the controller counts the judgment checkpoint once and does not also count its
mirrored response checkpoint. It writes a separate source-bound recovery
completion and never edits the immutable base completion. The recovery accepts
the standard `.venv/bin/python` symlink only when it resolves to an executable
regular file, so resumption stays in the original isolated environment. Its
exact tmux-owned lifecycle is published to Jobs without granting evidence
authority or rewriting either completion.

Only the four affected GraySwan identities are re-attested and canaried in their
targeted Gate 5 amendment. The historical GraySwan rows keep their immutable
`-full` terminal identities, but the amendment's current measured identities are
`local-llava-rr-text-primary-100`,
`local-llava-rr-image-primary-100`, `rjudge-llava-rr` and
`gptgeochat-llava-rr`. Their limit-100, sample-seed-0 selections and caps match
the corresponding LLaVA-base rows. A separate additive Ollama amendment replaces
the superseded RWKV tasks with the four exact current models. Its retained first
cohort used limit 50 and sample seed 0 for bounded text and source-classification
lanes, with image and GPTGeoChat lanes only for Gemma 4 and Ministral 3. The
population-alignment amendment completes the same nested seed-0 prefix to limit
100 for every comparable Ollama lane. It does not rewrite the already sealed
46-row historical profile or repeat a completed limit-50 row. Every retained
Ollama request before the DeepSeek continuation binds `num_ctx=8192` and
`num_predict=512`. The first value prevents
the 32B DeepSeek condition from allocating its full 131,072-token native context
and spilling nearly half of a short-prompt canary to CPU while the scoring guard
is resident; the second is an output cap, not a reason to discard observed
length-capped text. A different context or output cap is a separate projected
cohort. After `think=true` exposed a systematic 512-token no-final-answer
condition on difficult security inputs, a separate ten-input, one-attempt,
no-judge diagnostic admitted `num_predict=2048` after all ten inputs returned
visible final text with 719-1,335 completion tokens and normal stop reasons. The
resulting DeepSeek-only continuation binds that
condition in its launch, local-config digest, Runner request and combined `/3`
completion; it cannot be pooled with the stopped 512-token diagnostic condition.
That 2,048-token continuation was stopped on 2 September 2026 at 784 durable
rows after it had retained 14 missing outputs and 21 length-ended responses.
It is not a terminal population result. The next DeepSeek unit preserves that
checkpoint and selects only its never-attempted, missing, and length-ended
identities under automatic GPU-fit context and `num_predict=-1`; completed
non-truncated rows are not repeated. The two finite-cap conditions and the
hardware-fit correction remain separately labelled and are never silently
pooled. A first native-maximum canary on 2 September loaded only 30.2 GB of a
55.7 GB DeepSeek runtime into VRAM and was stopped before measured rows. That
attempt is infrastructure evidence, not model output evidence.
Identity, provenance, residency, seal, budget and wall-time failures
remain hard failures. Exhausted answer-level malformed output or transport
failures use the typed missing-response policy above. Earlier attempts remain
diagnostic observations.

Gate 5: projections and canaries retained under `runs/thesis/preflight` and
`runs/thesis/diagnostics`; the four-row GraySwan RR current-policy amendment and
the separate current four-model Ollama amendment retained without rewriting the
earlier terminal artifacts; caps recorded in
`runs/thesis/RUNNOTE.md`; all 46
planned rows represented exactly once as runnable or typed terminal. Each
runnable row also binds `core_primary_100` or `extended_50`, limit, sample seed,
selected-cluster and converted-row identities, exact no-call projection and
approved call caps. The approved policy records
`measured_lane_wall_time_seconds=86400` as the 24-hour process wall-time ceiling
for one measured lane and binds `--deadline-seconds 86400` as that request's
Runner call-start window. The Runner refuses to begin a later call after its
deadline but does not interrupt an in-flight call. The controller ceiling is
separate: it may terminate and reap the lane process group at 24 hours. Both
values are prospective current-cohort bindings; the software supports other
positive values only in a separately projected and approved cohort.

A failed additive Ollama controller is recovered from its exact canonical
`.exit=1` control root. The recovery revalidates completed artifacts, executes
only never-completed rows or cells, and emits one provenance row per disposition when
every exact per-model local config is byte-identical. If a context or output cap
changes, the old evidence remains immutable diagnostics and the controller
creates a fresh projected cohort instead of relabeling or reusing it.
Gate 5 keeps the historical execution commit and current validation commit as
separate identities; it rejects a missing, duplicate or silently relabeled
mixed cohort. Within an exact-config recovery, successful projections,
attestations and canaries are not rerun. If every unit completed and only the
aggregate validator failed, recovery revalidates the complete inventory with
zero additional model calls.
For a row-local output failure produced by an older Runner, recovery binds the
original checkpoint inventory, selects only attempt identities without a durable
response/judgment record, and publishes an explicit merged coverage inventory.
It never reruns or relabels the already paid completed rows, and same-revision
recovery retains the original argv rather than claiming the later answer-retry
policy. A fresh current Runner cohort instead binds
`--target-answer-retries 1` in its request, projection and caps. Original,
recovered and later-revision strata remain explicit until read-only analysis
validates each population.

If that exact-argv recovery reaches a terminal zero-progress state because the
old result root retains an open circuit, it is not relaunched again. The current
Ollama stability continuation validates the immutable base and failed recovery,
then schedules exactly 14 fresh per-corpus Runner 2.26 units covering only the
1,684 never-completed rows. Content-bound prefix selectors exclude the 430
completed Gemma AirBench rows, two completed Gemma MLLMGuard-privacy rows and
27 completed Ministral MLLMGuard-privacy rows; nine complete Gemma text cells
and seven complete image cells per model are omitted entirely. The 1,911
durable historical rows and the later-revision units remain separate output-
policy strata, with no cross-policy pooling. This continuation may run after a
vLLM continuation has terminalized, but never concurrently with it on the two-
GPU rig.

The first 14-unit invocation is itself immutable if a later aggregate check
fails. When complete recovered answers were final-scored but their persisted
judge-stage projections retained null stability fields, four fully executed
Gemma text units could not publish completion even though all intended calls,
responses, judgments and checkpoints existed. The exact follow-up controller
therefore finalizes those units from their durable artifacts with zero target
and judge calls, inherits the five already complete Ministral image units, and
launches only the five Gemma image units that stopped before measured Runner
execution. It accepts only the exact terminal log causes. Fresh image identity
derivation uses deterministic seeds 0 through 4 so one probe nonresponse cannot
stand in for the 2-of-5 readiness gate; every resulting receipt remains fully
validated. The old failed controller, zero-call finalizations and new image
units remain separately attributable and no completed row is repeated.
Once the exact model has passed that readiness gate, a diagnostic canary whose
entire evaluable population abstains records model-stability evidence but does
not veto its assigned measured population. Both canonical zero-record JSONL
encodings, zero bytes and one terminal newline, are valid; any other byte or
record-accounting mismatch remains terminal.
If the retained continuation terminal contains only the historical newline-
encoding rejection, the canary-recovery controller inherits every completed
unit, revalidates the retained canaries with zero repeated canary target calls,
and schedules only populations that never reached measured Runner. A fresh
revision-bound identity attestation is still required; no completed measured
row is repeated.

**Ollama population-alignment amendment (31 August 2026).** Review of the
planned population sizes, before the current-Ollama stability continuation or
Phase 7 analysis started, found that the retained Ollama limit-50 cohort was not
quantity-matched to the vLLM limit-100 model-comparison cohort. This is a design
defect, not a model-outcome trigger. After the 1,684-row stability continuation
fills the holes inside the first 50-cluster prefix, a separate controller must
project and execute only clusters 51 through 100 for all 12 comparable Ollama
lanes. The nested seed-0 policy adds 1,909 static-text rows per model, 807
static-image rows per vision model, 50 R-Judge rows per model and 1,075
GPTGeoChat rows per vision model: 11,600 intended calls in total. The controller
must prove that each old limit-50 datapoint-ID digest identifies an exact subset
of its limit-100 selection, bind the retained ID set and remaining-row digest,
run the no-call projection
and diagnostic canary before measured calls, and reject any overlap. Historical
prefix and new extension artifacts remain distinct Runner strata; Phase 7 may
report their combined population coverage but must not pool their rates across
revision or output-policy boundaries.
Static alignment lanes retain their Hub acquisition plan because their selected
source inventory contains Hub-backed resources. The Ollama R-Judge and
GPTGeoChat lanes use already-local source data and a local daemon target, so
they omit model-acquisition arguments; an empty acquisition plan is not created.
If the controller seals `complete_with_failures`, continuation must validate the
exact base completion and select only work that has not become terminal in a
later artifact. In this campaign the first recovery started DeepSeek and was
interrupted before the other six failed units began. A later Runner 2.27
DeepSeek continuation retained 785 of its 1,674 selected rows before another
terminal interruption. The hardware-fit controller retains its 743 usable
non-length rows and completes only 14 failed, 28 length-ended and 889
never-attempted rows. DeepSeek's 1,909-row extension is therefore reconciled by
235 earlier usable rows, 743 retained Runner 2.27 rows and 931 Runner 2.29
hardware-fit rows. Only after that hardware-fit completion is terminal may the
alignment continuation schedule the four 50-row R-Judge units and two 1,075-row
GPTGeoChat units, exactly 2,350 rows. It must not schedule DeepSeek or any of the
five base-complete units. All continuations reuse the original content-bound
selectors, derive fresh revision-bound attestations and retain separate
revision/output-policy strata. Phase 7 accepts the resulting population only
when its unique extension accounting is exactly 11,600 rows; actual Runner work
is reported separately because 2,772 failed outputs and 42 partial-recovery
failed or length-ended outputs were deliberately retried rather than hidden.

Before Gate 6 closes, every retained local vLLM failure is partitioned by the
boundary it reached. A lane that failed before measured Runner execution is run
as a complete first measured Runner 2.25 condition. A lane with a durable
measured prefix receives a content-bound continuation containing only its
never-completed rows. Completed lanes are not repeated. Every such condition
uses the same configured answer retry and model-stability accounting as Ollama,
while its revision and output-policy stratum remains explicit in Phase 7 rather
than being silently pooled with historical Runner evidence.

The retained current vLLM continuation is exactly seven new Runner 2.25 units
and 7,199 selected rows: 1,632 Qwen3-VL image rows, 2,020 GPTGeoChat-Qwen rows,
1,632 LLaVA-base image rows, the exact 815-row unfinished AirBench suffix, 100
XSTest rows, 100 SimpleSafetyTests rows and 900 DecodingTrust stereotype rows.
Completed Qwen3-VL text, completed Crescendo and the 1,039 durable LLaVA
AirBench prefix are not part of this call inventory.

That seven-unit controller later retained 375 complete GPTGeoChat-Qwen rows and
then stopped the unit when one rendered multimodal prompt contained 12,290
tokens against the prospectively bound 12,288-token vLLM context cap. The
controller continued to later units, so neither its completed rows nor sibling
units are restarted. After it terminalizes,
`experiments.local_campaign.vllm_input_recovery_phase6` validates that exact
prefix and schedules only the 1,645 never-completed GPTGeoChat rows under Runner
2.26 with the unchanged model/configuration. Later context-limit rejections are
retained as input-compatibility missing responses. A structure-only audit of
that suffix identified exactly 230 such rows: their rendered prompts contained
12,290 to 16,705 tokens against the 12,288-token admission. Before Gate 6,
`experiments.local_campaign.vllm_context_recovery_phase6` must bind those exact
typed outcomes and run only those rows under a separately projected native
checkpoint-context and maximum-available-output condition. The
campaign-wide local answer-retry count remains one. The Runner 2.25 prefix,
Runner 2.26 suffix and larger-context recovery remain separate, non-poolable
execution-condition strata; their disjoint selected IDs may be joined only for
population coverage.

The continuation controller binds its named tmux session to the existing Jobs
lifecycle and publishes terminal target-attempt and successful-generation
counts. This registration makes the campaign operationally visible; it does not
replace or authorize the measured Runner artifacts.
The already-running `bd2faf4` continuation predates per-child registration and
therefore remains truthfully visible as one parent engineering job whose unit
artifacts are browsable; no retrospective child start record is fabricated.
Every later recovery, current-Ollama stability and population-alignment
controller publishes the generic external-measured start record immediately
before each measured `run_matrix` child and its terminal record immediately
afterward. Those rows bind the child's exact Runner output root and remain
operational metadata rather than scientific admission.

## 7. Phase 6: bounded measured local lanes (sized by projections and canaries)

**Source-record inventory, which is NOT the row count.** The figures below are
released source records and equal the receipt's `raw_records.accepted`, which is
also the cluster count for an arm that emits one row per record. Several
converters fan out, so their emitted rows are a multiple of these, and reading
these as rows understates the campaign: MM-SafetyBench emits three variants per
question, 1,680 records giving 5,040 rows, which
`converters/release_specs.py` pins directly, and GPTGeoChat emits one row per
assistant turn per moderation level, 500 conversations giving 9,820 rows over
500 clusters, measured by converting the pinned release on the rig. Both are
correct as clusters and wrong as rows. Do not size a lane from this paragraph:
the no-call projection in Phase 5 reports the exact per-arm cell count for the
selection actually requested, and it is the only figure that should set a cap.

The seed-0 sampler over the currently admitted conversions gives the following
pre-measurement sizing calculation. These values are not benchmark results and
do not replace the new content-bound Gate 5 projections.

| Measured group | Tier | Selected converted rows | Intended target calls before answer-retry reserve |
|---|---|---:|---:|
| static text, per target | core 100 | 3,854 | 3,854 |
| static image, per target | core 100 | 1,632 | 1,632 |
| R-Judge, per target | core 100 | 100 | 100 |
| GPTGeoChat, per target | core 100 | 2,020 rows from 100 conversations | 2,020 |
| Crescendo, Qwen3-VL | core 100 | 700 conversations across seven arms | 2,800 at four turns |
| local guard defense, if runnable | core 100 | 3,854 | 3,854 |
| five runnable bridge lanes plus HarmBench replay combined | extended 50 | 850 source selections before per-method expansion | 1,750 |
| four admitted Ollama static text lanes combined | aligned core 100 | 15,416 | 15,416 |
| four Ollama R-Judge lanes combined | aligned core 100 | 400 | 400 |
| two admitted Ollama static image lanes combined | aligned core 100 | 3,264 | 3,264 |
| two Ollama GPTGeoChat lanes combined | aligned core 100 | 4,040 | 4,040 |

The total below counts each `per target` core group for the two planned core
targets, then adds the single Qwen3-VL Crescendo lane and the combined bridge
and Ollama groups shown above.

The population-aligned bounded design contains 42,882 intended target calls when
the local defense is typed unavailable, or 46,736 when it is runnable. A new
complete projection under the default one-retry policy therefore reserves at
most 85,764 or 93,472 target attempts respectively. The aligned current-Ollama
population contains 23,120 intended calls across its 12 runnable lanes and
reserves at most 46,240 attempts under the new policy. The retained limit-50
prefix and the non-overlapping extension keep their own exact caps and Runner
strata; the
DeepSeek-R1 Distill and GPT-OSS GPTGeoChat pairs are separate typed-unavailable
rows and contribute no calls. Model-judge and provider HTTP caps remain zero in
this local campaign. Local scoring and defense-guard evaluations are accounted
separately and are fixed by the new projection. Retained older-revision runs
keep their originally bound caps. Exact checkpoint recovery retains the
originally bound Runner and argv and executes only never-completed rows. A
separately projected fresh Runner 2.25 cohort reserves the answer-retry attempts
without retroactively doubling or rerunning completed work. Caps are never
raised mid-lane.

Source records: common text arms about 35,900 (SALAD-Bench base 21,318;
AIR-Bench 5,694; DecodingTrust 3,456; CyberSecEval 3,416; AdvBench 520; XSTest
450; HarmBench 400; StrongREJECT 313; JailbreakBench 200; SimpleSafetyTests
100), common image arms about 9,900 (HoliSafe 4,031; VLSBench 2,240;
MM-SafetyBench 1,680 records = 5,040 rows; MLLMGuard safety dimensions 548;
FigStep 500; JailBreakV image-backed 360 rows over 190 intent clusters;
MOSSBench 300; SIUO 167; HarmBench multimodal 110), classification arms 1,071
records (R-Judge 571; GPTGeoChat 500 conversations = 9,820 rows). The remaining
arms have not been recounted against their converters, so treat every figure
here as a source-record count until Phase 5 replaces it. The earlier "roughly
47k target calls per local model" followed from reading these as rows and is
therefore a floor, not an estimate; the canaries and the projection determine
the throughput. The current measured cohort remains seed 0 only. Any seed-1
population sample is the separately projected future cohort defined above, not
an outcome- or throughput-triggered extension of the current cohort.

| Tier | Lane | Targets | Attackers | Judges | Output root |
|---|---|---|---|---|---|
| 1 [10.1] | static text, all common text arms incl. the six aggregator arms | Qwen3-VL-8B; LLaVA base; GraySwan RR after its exact current-policy Gate 5 amendment; Gemma 4 12B Q4_K_M; Ministral 3 14B Q4_K_M; DeepSeek-R1 Distill 32B Q4_K_M; GPT-OSS 20B MXFP4 after the additive Ollama amendment | replay | rules,guardrail | `runs/thesis/runner/local-<model>-text` |
| 1 [10.2] | static image, all common image arms | Qwen3-VL-8B; LLaVA base; GraySwan RR after its exact current-policy Gate 5 amendment; Gemma 4 12B Q4_K_M and Ministral 3 14B Q4_K_M after physical-image transport attestation | replay | rules,guardrail | `runs/thesis/runner/local-<model>-image` |
| 1 [10.3] | audio/video | none (no local audio/video renderer) | - | - | structural `N/A` |

Conversion cost, measured on the rig (21 August 2026): the audio arm converts its
complete manifest before any sampling, so a bounded `--limit 2` JALMBench
observation took 1,218 s (20.3 minutes) while it read all 220,240 rows and hashed
the referenced audio. This is the price of binding the full-corpus digest and the
complete cluster inventory into the sampling audit, not a stall; budget it once per
JALMBench invocation. Every other arm observes in under 15 s.
| 2 [11] | R-Judge and GPTGeoChat classification | vLLM roster for both; all four current Ollama targets for R-Judge; Gemma 4 and Ministral 3 for GPTGeoChat; the DeepSeek-R1 Distill and GPT-OSS GPTGeoChat pairs typed unavailable | replay | rules (not queried; source parser authoritative) | `runs/thesis/runner/rjudge`, `.../gptgeochat` |
| 3 [12.1] | live Crescendo (response-conditioned) | Qwen3-VL-8B | crescendo | rules,guardrail | `runs/thesis/runner/crescendo-<model>` |
| 3 [12.2] | frozen measured Runner-safe bridges | Qwen3-VL-8B | pyrit, deepteam, h4rm3l, spikee (sealed workers), purplellama (CyberSecEval arms) | rules,guardrail | `runs/thesis/runner/bridge-<attacker>` |
| 3 [12.2] | sealed `bdd8252` prepared attacks | Qwen3-VL-8B | pinned HarmBench DirectRequest preparation + replay; T3MP3ST retained its historical pre-amendment terminal | rules,guardrail | `runs/thesis/runner/harmbench-replay` |
| follow-on prepared cohort | prepared replay capability | Qwen3-VL-8B | pinned T3MP3ST capture/replay; NanoGCG attributable suffixes; IDEATOR source-mapped seed pairs | rules,guardrail | fresh content-bound roots only after new admission |
| 4 [13] | same-base defense contrast | LLaVA base versus exact GraySwan RR, estimable only after all affected RR identities pass the current-policy amendment and complete matching Phase 6 cells | replay | rules,guardrail | paired estimate when matching evidence exists; otherwise a typed Phase 7 unavailable artifact |
| 4 [13] | guard defense (text-only) | Qwen3-VL-8B with `--defense both --defense-guard guardrail` (1B guard on GPU 1 alongside the 8B scoring guard only if VRAM allows; otherwise N/A) | replay | rules,guardrail | `runs/thesis/runner/defense-local` |
| 5 [14] | nine native engines | local OpenAI-compatible endpoint (`vllm serve` of Qwen3-VL-8B or the Ollama API) where the engine supports it | engine-native | engine-native | `$URA_WORK/runs/engineering/ura-native-*`, then `native_import` |

Native engines, free configuration (run one-case canaries first [14.2]; each
through `ura_native_run` with `URA_NATIVE_TARGET_CALL_CAP` set):

| Engine | Free route | Expectation |
|---|---|---|
| Garak | `--target_type openai.OpenAICompatible` against the local vLLM server | runs |
| Promptfoo | ollama/openai-compatible providers for target, attacker and grader | runs; grader quality limited |
| FuzzyAI | ollama provider (`-m ollama/<tag>`) | runs |
| Petri | Inspect roles on openai-compatible/vllm providers | runs; auditor quality limited |
| AgentDojo | openai-compatible base URL with a tool-calling local model | only if the local model supports tool calls; otherwise N/A |
| ASB | openai-compatible config | as AgentDojo |
| AutoDAN-Turbo | local HF attacker/target/scorer/summarizer/embedding models | heavy; feasible only with small models on two cards; otherwise N/A |
| EasyJailbreak | local HF models for attack/target/eval | feasible with 7B-8B models |
| Giskard | Python callable around the local endpoint | runs |

Import every complete native artifact family with `experiments.native_import`
[14.3]; record run/failed/unavailable/not-selected for all nine. These bounded
one-case runs remain engineering diagnostics under `$URA_WORK/runs/engineering`.
They exercise the native bridge and importer but are not measured Runner lanes
and are not promoted into thesis metrics.

The Phase 6 sequence may adopt an already terminal core, extended or native
launch only from an exact retained sequence path. It copies the launch and, for
native diagnostics, the matching plan and plan-result bytes, then revalidates
the whitelisted controller payload, historical project-revision receipt,
framework lock and complete terminal inventory. Adoption makes no target call
and never invokes the child wrapper again; any changed or unregistered identity
fails instead of being treated as reusable evidence.

### 7.1 Runner 2.27 failed-output recovery amendment

The 1 September current-Ollama population run exposed a serving-condition
confound rather than an intrinsic one-third model failure rate. The adapter did
not send an explicit Ollama `think` control and ignored the daemon's separate
`message.thinking` field. At the controlled durable stop, 2,772 of 8,229 rows
were retained as failed output. Every exhausted empty row from the
thinking-capable Gemma, GPT-OSS and DeepSeek routes consumed the full 512-token
completion allowance; Ministral did not show that pattern. The stopped
DeepSeek unit also has 1,021 selected rows that were never attempted. A separate
structure-only audit found 20 genuine two-token empty LLaVA outputs and 230
Qwen3-VL context-limit incompatibilities. No prompt or response text was printed
by either audit.

Runner 2.27 binds Ollama thinking explicitly. Gemma and Ministral use
`think=false`, DeepSeek-R1 uses `think=true`, and GPT-OSS uses its supported
`think=low` condition. The adapter
reads final content separately, retains no reasoning text, records only whether
thinking output was observed and rejects a daemon that violates a disabled
policy. Local vLLM and Ollama still use one configurable Runner answer-retry
policy, set to one retry in this campaign.

`failed_output_recovery_phase6` derives one completed-ID selector from the exact
durable attempt/response pairs of each affected unit. It schedules 3,793 Ollama
rows: the 2,772 failed outputs plus the 1,021 never-attempted DeepSeek rows. It
also schedules the 20 genuine LLaVA failed outputs, for 3,813 measured recovery
rows in six fresh Runner 2.27 units. It excludes every usable first response,
every response recovered after retry, and all 230 deterministic Qwen3-VL input
incompatibilities because they require a different context condition rather
than an answer retry. The dedicated vLLM context-recovery controller verifies
and selects that exact 230-row set, derives a fresh route attestation, canary
and no-call projection, then runs it without explicit `max_model_len` or
`max_tokens`, using vLLM's automatic hardware-fit context and the exact model's
readiness-approved output allowance. Old rows stay
immutable lifecycle evidence. Only the old
successful rows and their fresh recovery rows form the eventual complete
selected population, and their Runner/output-policy/revision strata remain
separate until an explicitly justified sensitivity view combines estimates.
Diagnostic attestation/canary calls remain diagnostic and cannot be counted as
population rows.

The first six-unit recovery retained five terminal units (2,139 rows) but made
no DeepSeek population call: all five admission probes were rejected because
the controller had bound that reasoning model with `think=false`. The
`failed_output_recovery_continuation_phase6` controller accepted only that exact
terminal partition, retained the five completed results byte-for-byte, reused
the exact 1,674-row selector, and ran only DeepSeek with `think=true` under the
separately calibrated 2,048-token completion allowance. Its `/2` terminal is
honestly `complete_with_failures` after 785 durable DeepSeek rows. The later
hardware-fit controller binds that exact partial state and selects only its 931
unfinished, failed or length-ended rows. This is correction of a pre-execution
configuration error followed by separately named finite-cap and hardware-fit
conditions, not an
extra response retry. Filtering to DeepSeek must preserve its
physical position 05 from the original six-unit order; renumbering the filtered
list from one changes the immutable selector identity and is rejected before a
target call.

The alignment continuation is a dependent Phase 6 step, not another replay of
the seven failed base units. Its `/4` contract requires the interrupted
failed-output completion and the fully successful 25-unit hardware-fit
completion, then runs only the six never-started R-Judge/GPTGeoChat units, for
2,350 rows.
Its explicit Ollama configuration binds `think=false` for Gemma and Ministral
and `think=low` for GPT-OSS. Because none of those six population rows has run,
their fresh condition binds `num_ctx="fit"` and `num_predict=-1`. Runner starts
at the pinned native ceiling and performs load-only probes at successively
smaller native fractions; it admits the largest tested context whose exact
`/api/ps` row is fully GPU-resident. This precedes the fresh attestation,
one-cluster canary, no-call projection and acquisition for the measured run. A
model that cannot fit even the minimum probe is a typed unit failure. No
local-only classification unit may gain a Hub
acquisition plan. Reintroducing DeepSeek into this selection or changing the
2,350-row count is a contract failure.

The first alignment-recovery launch at commit `8296f76` stopped after its
controller-start record and before any unit state or population call. It is not
a completion. The first 25-unit automatic hardware-fit correction was stopped
after its first three selected rows proved that short-answer `/2` readiness had
not exercised the 25,000-token ceiling. Re-profile all seven generative local
models under `ura-local-model-readiness/4`, then run a fresh successor that
selects only the invalid-condition or never-started rows. After that successor
validates, run the maintained six-unit population continuation in a fresh named
rig session with all prerequisite completion digests and give only its validated
completion to Phase 7. The 2,350 never-started rows are in
addition to the 4,463 row-addressable hardware-fit corrections; neither
controller may select a row completed by the other or by the retained base.
At that terminal boundary, deploy the tested successor with
`bash ~/repin.sh <40-hex-commit> --focused-campaign-handoff`. The mode's tracked
fixed selector list covers every test file changed since the active `aa71bcd`
deployment plus stable hosted-plan and deployment-contract checks. It still
refreshes the roster, rebuilds and validates the project receipt, revalidates
the source receipt and restarts the console. It must not run before the active
controller is terminal because re-pin hygiene intentionally stops Runner.

The general local serving default is provider-independent at the response
boundary: omitted vLLM `max_model_len` binds vLLM 0.27's `-1` auto-fit policy,
and Ollama binds `num_ctx="fit"`; both retain the largest hardware-fitting
context for the profile's exact topology. Their independent response allowance
comes from the exact model's readiness profile. No local generative campaign is
admitted before profiling.
Rig Web applies the same rule at installation time for Ollama: a successful
pull automatically creates a linked readiness Job, and the tag remains
unavailable to Build until the exact digest passes the 10-text/5-image gate
and receives its approved response allowance.
The profile also supplies the 120-second request deadline, and a candidate
allowance is ineligible if any probe reaches it. Every policy, attempted
allocation, and resolved value is visible in Build and retained in the run
condition or response evidence. Hosted targets and hosted judges do not use
this local mechanism: their explicit token limits remain derived from the paid
campaign budget. They receive zero answer-quality retries and up to three
harness retries only for the declared retryable HTTP status responses.

Measured multi-cell vLLM grids use a fresh child process when post-factum local
judging requires the target to be reopened between cells. This is an execution
lifecycle rule, not a model-parameter fallback. The installed vLLM 0.27.1
in-process shutdown can retain CUDA allocations after its official cleanup
hook. The parent therefore submits the unchanged, content-bound request again
only when the prior child added at least one verified completion marker. Those
completed cells are call-free on resume. A child that adds no completion stops
the grid immediately, and the number of children is bounded by the requested
cell count. Context, output allowance, seed, selection, budgets and receipts do
not change across children.

The 4 September bounded-output tail exposed this condition after 76 of its 170
rows were durable: units 21 and 22 were complete, and the first 10 rows of unit
23 were complete. Seven later unit-23 cells failed before target calls because
the prior LLaVA allocation remained live. The tracked CUDA-recovery successor
retains those 76 rows, accepts unit 24's exact four-file acquisition-only root
as pre-state rather than measured evidence, reuses the already validated unit
23 and 24 canaries, and selects exactly the remaining 94 rows. It does not run
the historical request under changed code or change a retained project receipt.

### 7.2 Runner 2.32 local execution-profile amendment

The 3 September hardware-fit continuation exposed a second execution-condition
confound. Its LLaVA unit omitted `max_tokens`, so Runner 2.29 allowed the model
to consume the 32,768-token context as response budget. At the controlled stop,
36 of 64 rows were durable: 14 were failed outputs, 21 ended by length, one was
usable, and 28 had never been attempted. Those calls took roughly ten minutes
each. The one usable row remains immutable and excluded from recovery.

Runner 2.30 separated maximum hardware-fit input context from a finite response
allowance and local request deadline, but its short-answer survey did not force
the configured output cap. A Qwen GPTGeoChat recovery request consequently
reached the 120-second ceiling under a nominally passing 25,000-token profile.
That measured unit selected three rows, but the first request timed out before
any durable measured row was written. The controller was stopped during the
following unit's diagnostic canary, before that unit's measured Runner began.
The one timed-out request and the diagnostic canary rows are invalid-condition
diagnostics, not model-stability observations.
The real first-call failure retains empty attempt, judgment, response and trail
streams but no `*.results.jsonl`, because Runner creates that export only after
judgments exist. The successor derives the exact cell stem from its manifest,
requires those four streams to be empty, and accepts the result export only when
it is either absent or the exact empty cell file. Runner's manifest does not
carry attempt or selected-datapoint counts; the controller proves the three-row
selection from its state and the zero completed attempts from the typed error
and empty durable streams.

Runner 2.32 stress-tests the local ceiling and lowers it until the first proven
sub-120-second text cap, checks physical-image responsiveness below the same
deadline where applicable, then runs the responsiveness survey there. A request that
reaches the deadline ends with its owning child process before the next
candidate is submitted. Process exit is required because an in-process vLLM
close can leave CUDA allocations alive; the separate process prevents a
cancelled request from confounding lower-cap timings. The child marks the
instant generation begins, so the parent-enforced deadline excludes model load
and graph compilation while still terminating the process at 120 seconds; a
delayed Python alarm cannot extend the request. A failed text stress immediately
descends to the next candidate. Before and after an isolated Ollama probe, the
parent locks inference and unloads only stale residency whose exact tag and
digest match the selected model. Foreign or co-resident state remains a hard
failure and is not mutated. The image check runs only after text fits. It also
preserves typed answer and input failures across the sealed vLLM execution
boundary, so a genuine later failure follows the same retry-and-retain rule as
Ollama. Before continuing security work, all three downloaded vLLM targets and
all four downloaded Ollama targets receive fresh `/4` readiness profiles and a
schema-3 machine registry. The registry binds the exact tested vLLM topology and
memory utilization rather than silently recomputing TP at campaign time. The
successor controller selects exactly the 63
non-usable or unattempted rows in that LLaVA unit plus the 107 rows in the four
later unstarted units, for 170 rows total. It requires and applies the exact
model's profiled allowance and 120-second deadline, keeps one
answer retry, and repeats no valid completed row. It also reselects the three
Qwen rows selected only under the invalid 25,000-token condition; one was
attempted and none became durable. The
interrupted controller is closed with a typed terminal marker; its artifacts are
retained and never
rewritten. After this continuation, the six-unit 2,350-row population alignment
continuation uses the same local profile contract. These are campaign-specific
recovery strata, not changes to the hosted API campaign.

The retained Qwen GPTGeoChat suffix proves why topology is part of the profile:
230 rows were rejected under the old 12,288-token condition, with prompt lengths
from 12,290 through 16,705 tokens. A TP1 automatic-fit probe exposed only 13,040
tokens and therefore cannot cover that retained selection. Before the successor
runs, Qwen must pass its `/4` profile at TP2 and the receipt's resolved context
must cover the longest selected prompt plus the selected response allowance.
LLaVA base and GraySwan RR may retain TP1 only when their resolved checkpoint
context covers their selected inputs. The 120-second output-cap ladder remains
independent of this input-context requirement.

Response-independent local attestation, diagnostic-canary, and measured cells
use two GPU phases within the same bound run. The target completes a durable
response checkpoint with the scoring model absent, then unloads before the Guardrail or
local LLM judge is loaded. This avoids changing target fit, throughput, or
latency observations merely by placing a judge on the second card. Crescendo is
the explicit exception: its judge remains inline because the verdict controls
the following turn. A defense guard also remains in the target phase as part of
the treatment. Gate artifacts retain the selected execution schedule.

Before Gate 7, a structure-only truncation inventory must inspect every retained
current-roster local result. Each nonempty vLLM `finish_reason=length` and Ollama
`done_reason=length` identity is regenerated once under the same automatic
GPU-fit policy, with fresh admission artifacts and an exact completed-ID selector.
Historical rows remain immutable. Retired RWKV conditions are not rescheduled,
because they were explicitly removed from the current roster and task plan.
After review, execute that inventory with
`local_truncation_recovery_execution_phase6`. The controller must re-derive the
bound structure from each source state, use create-only exact-ID selectors and
hardware-fit configs, then derive fresh attestation, canary, projection and
acquisition artifacts before measured calls. One failed or missing model answer
is retained under model stability and does not stop the unit; completed
non-truncated identities are never scheduled again.

Interactive shutdown owns SIGINT as well as SIGTERM. Runner records the signal,
finishes model and framework teardown, restores both prior handlers and then
returns the conventional signal status. Gate 6 requires an empty Ollama `/api/ps`
inventory and idle baseline GPU memory after any interrupted local lane.

If repinning has moved that exact historical project-revision receipt into the
fixed sibling `project-revision/superseded/` directory, the current-Ollama
campaign validator may read only the same filename with the descriptor's exact
byte count and digest while retaining the original logical locator for argv
comparison. An existing, symlinked, missing or content-different candidate does
not fall through to another receipt.

Every core and extended measured lane runs in its own process group under the
Gate 5 24-hour lane wall-time ceiling. Core lanes are terminated and reaped on
that ceiling before the controller continues to the next lane; the extended
controller applies the same ceiling cumulatively across each lane's preparation,
resume and measured stages. A setup failure or timeout that occurs before Runner
can publish its own request/error lifecycle writes one create-only,
non-empirical `ura-phase6-pre-runner-failure/1` marker inside that exact planned
Runner root. Core uses `runs/thesis/runner/<lane>`; the retryable extended
controller uses `runs/thesis/runner/<lane>/<phase6-extended-control>` so a later
controller can preserve earlier job evidence instead of deleting or reusing it.
The marker is not a Runner artifact and cannot enter metrics. It exists so Gate
6 never represents a planned measured lane by an absent directory or by an
engineering log outside the Runner inventory.

Immediately before each real measured `run_matrix` child, the controller also
creates one fixed-child operational registration binding the exact sanitized
argument vector, Runner root, project revision, framework lock, approved Gate 5
digest and the exact owning tmux socket/session. A sequential controller may
name its own session while it synchronously owns the child; a separately
launched child names its child-specific session. The controller creates the
matching terminal record after the child returns. Jobs and Stats use that
explicit ownership to display the
lane and completion-bound usage from its validated artifacts. The console
neither launches nor stops these external children, and the registration and
its terminal record remain explicitly external operational and non-thesis even
after exit zero. The selected Jobs history window never hides an exact-session
row that is currently observed live; unavailable or bounded-away liveness is
shown as `unknown`, not asserted as `running`.

The Phase 6 sequence wait for Gate 5 is bounded by its declared 720-hour
controller hard stop, not by a Runner lane's 86,400-second call-start window.
When a later sequence finalizes an interrupted campaign, it adopts core or
extended work only through an exact prior sequence launch whose child already
has a validated terminal completion and exit marker. The adopted measured
children retain the Gate 5 project identity under which they ran; native
diagnostics, if not yet completed, run once under the finalizer's current
analysis revision. This avoids repeating successful measured work while keeping
the revision strata explicit.
The Phase 5 and Gate 5 orchestration controllers enforce a 24-hour global
controller deadline, and the Phase 7 watcher enforces 720 hours. At expiry, a
controller records exit 124 and the exact wait/hours reason in task and campaign
events. It terminates and confirms absence of only an exact tmux session it
launched and owns; a controller that times out while awaiting upstream Phase 5
or Phase 6 never terminates that upstream session.
Cleanup owns a
prospective external id and exact session before start publication, and terminal
publication is bounded to 30 seconds, so a signal or stuck publisher cannot
leave a row borrowing the liveness of the parent controller.

Gate 6: every planned measured Runner lane is attempted independently and
either completes or records an explicit error/partial state under
`runs/thesis/runner`, through Runner's own lifecycle artifacts or the exact
typed pre-Runner marker above. The aggregate is `complete` or
`complete_with_failures` according to that exact terminal partition; a typed
failure never becomes `measured_complete` and never prevents later independent
lanes from being attempted. Native engineering diagnostics retain their
separate typed dispositions under `runs/engineering`; caps are never raised
mid-lane.

## 8. Phase 7: read-only analysis (hours)

`level1_evidence` over `runs/thesis/runner` authorizes the complete measured
lifecycle, including complete, partial and failed Runner artifacts and their
final eligibility or request-error records. The metric grid is deliberately
narrower: `suite_summary`, `level2_report`, `judge_sensitivity --attacker replay
--defense none`, `kappa --attacker replay --defense none`, `transfer_matrix
--attacker replay --defense none`, and the free replay-vs-Crescendo paired
comparison within Qwen3-VL-8B [16]. The planned LLaVA base-vs-RR comparison is
estimated only when the GraySwan RR amendment admits all four bounded RR rows and
both base and RR measured cells match on source clusters, input bytes, sampling,
inference settings and judge condition. Otherwise Phase 7 writes one strict
`ura-phase7-non-estimable-contrast/1` artifact for every unavailable planned
facet, binds the failed or retained-terminal prerequisite and carries no
estimate. It must not construct RR metric input from projections, canaries or
partial measured roots. The current Ollama Gate 5 amendment and Phase 6
completion are independent, required Phase 7 inputs alongside the retained
core, recovery, GraySwan RR and follow-on inputs. When that Phase 6 completion
contains a failed readiness-admitted lane, Phase 7 additionally requires the
exact checkpoint-recovery completion, validates every originally failed lane as
its immutable terminal outcome, and then requires the separate 14-unit Runner
2.26 current-Ollama stability completion for the remaining 1,684 rows. The
historical 1,911 durable rows and fresh stability units retain separate
retry/output-policy strata and are never pooled. The Level-2 export keeps
rules-only and cascade (rules+guardrail) evaluator modes as separate
compatibility keys.
The exact terminal seven-unit Runner 2.25 vLLM stability completion and the
one-unit Runner 2.26 GPTGeoChat input recovery are required together. Phase 7
uses the six completed Runner 2.25 units and the 1,645-row Runner 2.26 suffix as
separate metric strata, retains the 375-row failed-unit prefix as lifecycle
evidence, and forbids pooling across either boundary or with completed Runner
2.24 Qwen text and Crescendo evidence.
The exact Phase 6 campaign terminal inventory before population alignment
contains 100 logical rows: 46 canonical, seven historical output-policy amendment, three
follow-on, 14 historical current-Ollama, 14 current-Ollama stability, seven
vLLM stability and nine native. The population-alignment amendment adds 12
current-Ollama population-alignment logical extension rows, giving 112. The six
failed-output recovery units use Runner 2.27 and give a final terminal inventory
of 118. The union then adds one vLLM context-recovery condition and 25 local
hardware-fit recovery units, giving the final Phase 7 union 144 logical rows.
The historical amendment includes three retired RWKV terminal conditions.
Retaining their original records does not restore those models to any future
roster or schedule. The earlier 141-row analysis contract incorrectly omitted
them when the prospective roster changed.
Those 25 units cover exactly 4,463 unfinished, failed-output, or
provider-declared length-ended rows. They use automatic GPU-fit context and
maximum available local output, remain a separate condition, and never repeat
an already completed non-truncated row.
The first hardware-fit execution retained 1,749 durable rows before a response
body exposed a non-enforced adapter deadline. Its exact continuation therefore
adopts two complete units (931 and 394 rows), retains 424 rows from the
interrupted third unit as lifecycle evidence, and executes only 2,714
never-completed rows. The third-unit selector excludes those 424 exact
datapoints. Restarting the original 4,463-row controller or promoting the
partial unit as a terminal Runner grid is forbidden.
The continuation suffix preserves original unit numbers 3-25. If bootstrap
stops after the exact interruption marker and exit 125 are written but before
the continuation launch artifact, only a fresh root may resume it. That restart
validates the immutable terminal bytes and does not repeat terminalization side
effects or durable responses.
One later continuation unit exposed a distinct pre-Runner controller defect:
its recovery selection contained only three GPTGeoChat rows, so the controller
gave the measured condition and its diagnostic canary the same six-call
ceiling. The canary removes the recovery selector and its one selected source
cluster contains ten rows, requiring a 20-call ceiling with one answer retry.
The measured three-row ceiling remains six. The corrected shared driver derives
only the canary ceiling from the full retained selection. If the terminal
continuation contains exactly that one zero-measured-call failure, run
`local_hardware_fit_failed_unit_recovery_phase6` in a fresh tmux session. It
retains the other 24 unit results by content identity, executes only the three
unattempted rows, binds the observed one-cluster canary ceiling to exactly 20,
and publishes a superseding 25-unit completion for the unchanged Phase 7 input.
No logical condition or planned row is added.
If vLLM retains its CUDA allocation after a completed cell in that continuation,
the generic Runner process recycler resumes the unchanged measured request in a
fresh child and skips every completion-marked cell. The one-time campaign
controller `local_bounded_output_cuda_recovery_phase6` retains the observed 76
rows and executes only the remaining 94. Phase 7 preserves the partial unit's
10-row predecessor prefix and 35-row current suffix as separate revision
segments, while the planned population remains 4,463 rows and no completed row
is repeated. The same validated successor supplies the retained DeepSeek
prerequisite for the six-unit Ollama population-alignment continuation.
The 12 population-alignment rows remain logical model/framework conditions, not
12 necessarily single-root files. Eleven have one terminal metric root. The
DeepSeek condition is population-complete across its retained Runner 2.26 usable
segment, retained non-length Runner 2.27 continuation segment and Runner 2.29
hardware-fit segment; Phase 7 reports their exact coverage and model-stability
accounting but forbids a pooled security rate across those output-policy and
revision strata.
The
contract self-test rejects any
other count or cohort partition.
Only successful measured lanes enter those metric and Level-2 views; failed and
partial lanes remain visible in Level-1 lifecycle evidence rather than being
silently dropped or replaced by Gate 5 preflight eligibility.
Phase 7 accepts a planned lane root only when it contains Runner lifecycle
artifacts or the exact `ura-phase6-pre-runner-failure/1` marker. A missing root
or an untyped controller-log explanation is rejected rather than normalized to
an invented pre-Runner disposition. After terminal analysis validation, the
watcher runs a plan-owned `publish-stats` task. Stats links the resulting
Level-1/Level-2 JSON only after the adapter validates the existing sealed Phase
7 watcher launch and frozen watcher/wrapper/payload, the Phase 6 completion/exit,
preparation result, actual Phase 7 and analysis launches, analysis completion,
artifact inventory, and authorized input manifest, including their project
revision, framework lock, and approved Gate 5 identity. Adapter or registration
failure makes the watcher fail; no numbered phase or gate interpretation enters
Rig Web.
Neither an external registration nor an inventory by itself grants evidence
authority.

Some terminal failed controllers retain artifacts that are not representable
as final Level-1 grids. Keep those roots, file identities and durable response
counts in the lifecycle registry, with an explicit registry-only disposition;
do not rewrite a running grid or adopt orphan completion markers to make it
reportable. The current historical union retains all 108 roots. Four exact
failed roots are registry-only: one interrupted DeepSeek grid and three old
circuit-open retry grids whose retained completions are no longer referenced
by their final error cells. Their parent state, source revision, artifact
provenance and absence of active locks are independently checked. The other
104 roots enter revision-separated Level-1 reporting. This classification
does not change the 144-condition cohort or its coverage and missingness
accounting, and is not a general exception for malformed evidence.

The published Stats campaign detail also includes one execution-accounting
table over the validated 144-condition inventory. Each row identifies target
locality and provider, exact model, framework or attacker, corpus family,
logical source arm, modality, seed, revision and output-policy stratum. Its
separate count columns are selected input rows, initial target calls, answer
retry calls, successful output generations, retained missing outputs, local
rules or guardrail decisions, source-authoritative decisions, and later
selected Haiku decisions. Retry calls and multiple judge applications never
inflate the selected-input or successful-output counts. The campaign summary
reconciles the prospective 42,882 local target calls before optional defense
work, including 8,680 source-authoritative R-Judge or GPTGeoChat rows and at
most 34,202 common-judge-eligible rows. The separately planned follow-on
outputs may raise the Haiku-eligible planning inventory to 34,261, but the
hosted plan's actual funded population permits at most 941 matched local/hosted
output pairs for Haiku, below its earlier 1,010-call planning envelope.
Local-only Phase 7 therefore reports zero hosted and zero Haiku calls; a later
hosted comparison attaches its sealed matched stratum without rewriting the
local report. `retained_response_judge_pair` selects only identical input
entries from the validated local and hosted Runner views, and
`retained_response_judge_pair_execute` reconciles both views before constructing
only the Haiku judge. The paired selector receives the combined standard-API
USD 29.992960 protected judging ceiling, including the full retained answer and grading context in
provider-token input accounting. It uses one logical judge call per output, at most four
status-only HTTP attempts, zero target calls, no
automatic paid recovery, and a first-failure global circuit. The modal diagrams derive
from the same table and show the
input-to-output funnel, response and missing-output coverage, judge coverage,
framework by source-arm composition, and matched-input local versus hosted
contrasts when the separate hosted campaign exists.
Every hosted response in the separate campaign already carries its sealed local
`rules,guardrail` trail. The joined selected-cohort view compares that retained
trail with Haiku on the exact paired row, only on comparable decided labels,
and displays local decision coverage and abstentions.

The prospective 42,882-call population is not the physical retained-strata
forecast. Before Phase 7 observes the final artifacts, the maintained execution
chain predicts 46,537 selected input identities and 49,537 initial target calls:
42,882 population calls, 2,792 failed-output correction calls, 230 larger-context
Qwen calls, 3,574 hardware-fit repeats of failed or length-ended rows, and 59
prepared follow-on calls. The 889 hardware-fit rows that had never previously
started already belong to the 42,882 population and are not added twice. Answer
retries are reported separately and do not inflate either initial-call count.
This arithmetic excludes readiness probes and diagnostic canaries, and it is a
pre-analysis reconciliation rather than a benchmark result. Phase 7 replaces
the forecast with exact observed counts while retaining revision and
output-policy strata.

The same 49,537 initial-call forecast has two exact marginal views for the
planned Stats table:

| Local model or matched condition group | Forecast initial calls |
|---|---:|
| Qwen3-VL | 12,506 |
| LLaVA-family conditions | 7,736 |
| Gemma 4 | 11,076 |
| Ministral 3 | 9,144 |
| DeepSeek-R1 Distill | 4,649 |
| GPT-OSS | 4,426 |
| Total | 49,537 |

| Framework or attacker | Forecast initial calls |
|---|---:|
| replay | 44,928 |
| Crescendo | 2,800 |
| PyRIT | 150 |
| DeepTeam | 150 |
| h4rm3l | 600 |
| Spikee | 600 |
| PurpleLlama | 200 |
| HarmBench | 50 |
| T3MP3ST | 50 |
| NanoGCG | 1 |
| IDEATOR | 8 |
| Total | 49,537 |

Gate 7: the complete Phase 6 terminal inventory validates as `complete` or
`complete_with_failures`, at least one scheduled Runner lane is
`measured_complete`, the validated lifecycle registry retains every typed lane
state, Level-1 retains every representable Runner/request lifecycle, success-
only metric and Level-2 outputs validate, and the Stats publication registration
succeeds. If no measured Runner lane completes, the typed Phase 6 inventory
remains retained but Gate 7 is not met and no metric analysis is published.

## 9. Phase 8: human audit (free in money, requires raters and an ethics determination)

Run the sealed Phase 8 machine-preparation controller over Phase 7's validated
success-only Runner view [15]. Before it writes a sample, its exact cardinality
plan requires `C >= N + 20` for common-frame population `C` and requested
sample `N`, and `S >= M` for source-task population `S` and requested sample
`M`. The additional 20 common clusters are reserved for the independently
adjudicated qualification set and must remain disjoint from the final common
sample. The authorized manifest records those populations and requests, and
execution recomputes them from the same content-bound view. This proves
cardinality, not coverage feasibility: both deterministic selectors separately
fail closed unless the requested counts cover all achieved cells.

The controller prepares automated-label-blinded, model-visible samples, blank
two-rater forms, a qualification set and gold template, assignment and workload
records, and operator guidance. It makes no model, judge, provider HTTP, or
download call. Its only successful machine terminal is `human_only_blocked`
with `gate8_met: false`. A successful process exit is machine preparation, not
human evidence and not Gate 8.

Preparation is deterministic, seedless, and without replacement. The common
and source-task frames use whole-cluster selectors
`coverage_priority_then_stratum_round_robin_sha256_v1` and
`coverage_priority_then_sha256_fill_v1`, respectively. The disjoint
qualification set uses
`disjoint_risk_modality_behavior_coverage_then_sha256_lexicographic_representative_fill_v1`:
it emits one row per selected cluster, specifically that cluster's
lexicographic-minimum `sample_key` representative, and terminal validation
replays the exact selection against the bound Phase 7 Runner view.
`--bootstrap-resamples`, `--alpha`, and `--seed` apply only to later label
analysis and are invalid during preparation.

Gate 8 is met only after all of the following exist and validate:

- an applicable operator-supplied ethics/consent determination explicitly
  authorizes human exposure and records consent, compensation, withdrawal,
  harmful-content welfare, and escalation controls;
- an independent adjudicator establishes gold labels for all 20 qualification
  items, whose clusters are disjoint from the final common sample;
- at least two pseudonymous raters independently achieve at least 80 percent
  agreement on every qualification dimension;
- exactly two distinct qualified raters independently label each common and
  source-task row, after verifying every referenced media asset; pairs may
  rotate between rows, and agreement is reported for every pair with shared
  assignments;
- every non-unanimous composite or dimension is adjudicated after independent
  ratings are locked;
- `human_audit --labels` and `human_audit --source-task-labels` both validate
  the complete labelled files against the same success-only Runner view, bind
  each one by path and SHA-256 to its exact controller-prepared blank rating
  form, require identical headers and immutable row multisets with exactly two
  distinct rater IDs per sample, and write create-only reports containing the
  prepared-form descriptors into a separate Phase 8 analysis root, never into
  the sealed Phase 7 view; and
- a human operator reviews agreement, prevalence, support, confusion,
  uncertainty, and decision coverage, then authors an acceptance or limitation
  record binding the exact preparation, labels, adjudication, and report
  digests.

The accepted report schemas are exactly `ura-human-audit/1.2` for the common
frame and `ura-source-task-audit/2` for the separate source-task frame. Older
report schemas are not Gate 8 evidence.

Until that human-only record exists, Gate 8 remains open. This is the only route
to RQ5 judge validity for the local tier; machine preparation alone satisfies
only the software-coverage objective.

## 10. Console/CLI parity checks embedded in the campaign

Run each phase at least once through the console (Build -> Runtimes; Build
wizard for attestation probe, canary and measured lanes; Jobs for lifecycle;
Stats for per-job usage/coverage; Config editor for registries) and once
through the CLI, and confirm that the composed argument vectors (visible in the
Jobs record) equal the runbook vectors, including tier-specific `--limit 100`
or `--limit 50`, `--sample-seed 0`, `--group`,
`--exclude-tool-conditioned` on standalone synth dry runs, and the receipt
environment defaults on the Run page. The exclusion is standalone-dry-run-only;
every preflight, acquisition, attestation, canary, or measured route must reject
it.
Direct Phase 5 through Phase 7 controllers must appear
through their exact engineering marker/task-event records. Every Phase 6
measured child started after per-child registration became active must have a
resolvable external Job/Stats detail route whose artifact root equals that
child's one declared `--out` directory. The already-running `bd2faf4`
continuation remains the explicit pre-registration exception described above:
one truthful parent route with separately browsable unit artifacts and no
retrospectively fabricated child starts.

## 11. Schedule and effort (estimate, to be replaced by observed values)

| Phase | Wall time | Attended effort |
|---|---|---|
| 0 hygiene/pin | 1 h | 1 h |
| 1 runtimes | 3-6 h | 0.5 h |
| 2 receipt + observations | 3-5 h | 2-4 h (operator decisions) |
| 3 models | 1-3 h | 0.5 h |
| 4 attestations | 1 h | 0.5 h |
| 5 projections/canaries | 2-4 h | 2 h |
| 6 measured lanes | bounded inference; observed wall time to be reported, with 42,882 intended calls in the population-aligned design and a retry-1 conservative ceiling of 85,764 transport attempts | periodic |
| 7 analysis | 2-4 h | 2 h |
| 8 human audit | rater-dependent | rater-dependent |

## 12. Records and ledger

Each phase writes its receipts, logs and summaries under `/data/ura-work`
(`runs/thesis/...` for admissible evidence, `runs/engineering/...` for
diagnostics) and appends one dated entry to the convergence ledger
(`Thesis-EN/Codex_Reaudit.md`) with the commit, gate results and any
operator decision. Retain the clean-env suite log and the repin output for the
pinned commit in `Thesis-EN/verification/<date>-local-campaign/RECORD.md`.
